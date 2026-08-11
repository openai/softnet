use crate::dhcp_snooper::{Lease, message_matches_bootp_client};
use crate::proxy::flows::{FlowDirection, FlowMatch};
use crate::proxy::udp_packet_helper::UdpPacketHelper;
use crate::proxy::{Direction, PolicyDecision, Proxy};
use anyhow::Context;
use anyhow::Result;
use dhcproto::Decodable;
use dhcproto::v4::Opcode;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address,
    Ipv4Packet, Ipv4Repr, UdpPacket,
};

const IPV4_HEADER_LEN_WITHOUT_OPTIONS: u8 = 20;

impl Proxy<'_> {
    pub(crate) fn process_frame_from_vm(&mut self, frame: EthernetFrame<&[u8]>) -> Result<()> {
        if self.allowed_from_vm(&frame).is_none() {
            // Block packet by not forwarding it to the host
            return Ok(());
        }

        self.host
            .write(frame.as_ref())
            .map(|_| ())
            .context("failed to write to the host")
    }

    fn allowed_from_vm(&mut self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        if frame.src_addr() != self.vm_mac_address {
            return None;
        }

        match frame.ethertype() {
            EthernetProtocol::Arp => {
                let arp_pkt = ArpPacket::new_checked(frame.payload()).ok()?;
                self.allowed_from_vm_arp(arp_pkt)
            }
            EthernetProtocol::Ipv4 => {
                let ipv4_pkt = Ipv4Packet::new_unchecked(frame.payload());
                Ipv4Repr::parse(&ipv4_pkt, &ChecksumCapabilities::ignored()).ok()?;

                // Reject IPv4 options because source routing could bypass destination-based policy
                if ipv4_pkt.header_len() != IPV4_HEADER_LEN_WITHOUT_OPTIONS {
                    return None;
                }

                self.allowed_from_vm_ipv4(ipv4_pkt)
            }
            _ => None,
        }
    }

    fn allowed_from_vm_arp(&self, arp_pkt: ArpPacket<&[u8]>) -> Option<()> {
        vm_arp_allowed(arp_pkt, self.vm_mac_address, self.dhcp_snooper.lease())
    }

    pub(crate) fn allowed_from_vm_ipv4(&mut self, ipv4_pkt: Ipv4Packet<&[u8]>) -> Option<()> {
        // Is this packet coming from VM's IP address that we've learned from DHCP snooping?
        if let Some(lease) = &self.dhcp_snooper.lease()
            && lease.is_valid_for(ipv4_pkt.src_addr())
        {
            // Unicast DHCP renewal is required to maintain the VM's lease
            // and must bypass user-specified rules
            if is_allowed_dhcp_request(
                &ipv4_pkt,
                Some(self.host.gateway_ip),
                self.vm_mac_address,
                self.dhcp_snooper.lease(),
            ) {
                return Some(());
            }

            // Consult the flow table before evaluating outbound policy
            // so established flows are not treated as new traffic
            let pending = match self
                .flows
                .as_mut()
                .map(|flows| flows.inspect(&ipv4_pkt, FlowDirection::FromVm))
                .unwrap_or(FlowMatch::Untracked)
            {
                FlowMatch::Allowed => return Some(()),
                FlowMatch::Denied => return None,
                FlowMatch::Candidate(pending) => Some(pending),
                FlowMatch::Untracked => None,
            };

            // The flow is either pending or untracked, evaluate it against outbound policy
            let dst_addr = ipv4_pkt.dst_addr();

            match self.rules.policy_decision(dst_addr, Direction::Out) {
                // Return traffic was handled above; enforce explicit outbound blocks here
                Some(PolicyDecision::Block) => return None,

                // Track statelessly allowed traffic only when needed so its reply is not
                // treated as a new inbound flow
                Some(PolicyDecision::AllowStateless) => {
                    return self.admit_with_tracking_if_stateful(pending, dst_addr, Direction::In);
                }

                // Untracked packets cannot satisfy stateful policy
                Some(PolicyDecision::AllowStateful) => return self.admit_with_tracking(pending?),

                // No outbound rule matched; apply the built-in fallbacks below
                None => {}
            }

            // When no user-specified rules matched, simply allow all global traffic
            if ip_network::IpNetwork::from(dst_addr).is_global() {
                return self.admit_with_tracking_if_trackable(pending);
            }

            // Additionally, allow communication with the host,
            // otherwise things like SSH to a VM won't work
            if dst_addr == self.host.gateway_ip {
                return self.admit_with_tracking_if_trackable(pending);
            }

            // Additionally, allow DNS requests to DNS-servers
            // provided to a VM by the host's DHCP server
            if ipv4_pkt.next_header() == IpProtocol::Udp {
                let udp_pkt = UdpPacket::new_checked(ipv4_pkt.payload()).ok()?;

                if udp_pkt.is_dns_request() && self.dhcp_snooper.valid_dns_target(&dst_addr) {
                    return self.admit_with_tracking_if_trackable(pending);
                }
            }
        }

        // Allow outgoing DHCP requests to the bootpd(8) broadcast address,
        // otherwise DHCP snooper will never be populated
        if is_allowed_dhcp_request(
            &ipv4_pkt,
            None,
            self.vm_mac_address,
            self.dhcp_snooper.lease(),
        ) {
            return Some(());
        }

        None
    }
}

fn is_allowed_dhcp_request(
    ipv4_pkt: &Ipv4Packet<&[u8]>,
    unicast_target: Option<Ipv4Address>,
    vm_mac_address: smoltcp::wire::EthernetAddress,
    lease: &Option<Lease>,
) -> bool {
    // Require the source address to be either:
    // * covered by the VM's current lease
    // * unspecified on the broadcast DHCP path
    let src_addr = ipv4_pkt.src_addr();
    let src_has_valid_lease = lease
        .as_ref()
        .is_some_and(|lease| lease.is_valid_for(src_addr));
    if !src_has_valid_lease && !(unicast_target.is_none() && src_addr.is_unspecified()) {
        return false;
    }

    let dst_addr = ipv4_pkt.dst_addr();

    // Keep the common path cheap and inspect UDP only for a permitted DHCP target
    if !dst_addr.is_broadcast() && unicast_target != Some(dst_addr) {
        return false;
    }

    if ipv4_pkt.next_header() != IpProtocol::Udp {
        return false;
    }

    let Ok(udp_pkt) = UdpPacket::new_checked(ipv4_pkt.payload()) else {
        return false;
    };

    // Require the standard DHCP client and server ports
    if !udp_pkt.is_dhcp_request() {
        return false;
    }

    // Require the BOOTP client hardware address to match this VM
    let mut decoder = dhcproto::v4::Decoder::new(udp_pkt.payload());
    let Ok(message) = dhcproto::v4::Message::decode(&mut decoder) else {
        return false;
    };

    message_matches_bootp_client(&message, Opcode::BootRequest, vm_mac_address.0)
}

fn vm_arp_allowed(
    arp_pkt: ArpPacket<&[u8]>,
    vm_mac_address: smoltcp::wire::EthernetAddress,
    lease: &Option<Lease>,
) -> Option<()> {
    let (operation, source_hardware_addr, source_protocol_addr) =
        match ArpRepr::parse(&arp_pkt).ok()? {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                ..
            } => (operation, source_hardware_addr, source_protocol_addr),
            _ => return None,
        };

    if !matches!(operation, ArpOperation::Request | ArpOperation::Reply) {
        return None;
    }

    if source_hardware_addr != vm_mac_address {
        return None;
    }

    if let Some(lease) = lease {
        if lease.is_valid_for(source_protocol_addr) {
            return Some(());
        }
    } else if source_protocol_addr.is_unspecified() {
        return Some(());
    }

    None
}

#[cfg(test)]
mod tests {
    use crate::dhcp_snooper::Lease;
    use dhcproto::v4::{DhcpOption, Message, MessageType};
    use dhcproto::{Encodable, Encoder};
    use smoltcp::wire::{
        ArpHardware, ArpOperation, ArpPacket, EthernetAddress, EthernetProtocol, IpProtocol,
        Ipv4Address, Ipv4Packet, UdpPacket,
    };
    use std::collections::HashSet;
    use std::time::Duration;

    const VM_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    #[test]
    fn test_allowed_dhcp_request_policy() {
        let gateway = Ipv4Address::new(192, 168, 64, 1);
        let lease_ip = Ipv4Address::new(192, 168, 64, 2);
        let other = Ipv4Address::new(192, 168, 64, 3);
        let no_lease = None;
        let lease = Some(Lease::new(
            lease_ip,
            Duration::from_secs(600),
            HashSet::new(),
        ));
        let initial = |src, chaddr| {
            allowed_dhcp_request(src, Ipv4Address::BROADCAST, None, chaddr, &no_lease)
        };
        let renewal = |src, dst| allowed_dhcp_request(src, dst, Some(gateway), VM_MAC.0, &lease);
        let other_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

        assert!(initial(Ipv4Address::UNSPECIFIED, VM_MAC.0));
        assert!(renewal(lease_ip, gateway));
        assert!(!renewal(other, gateway));
        assert!(!renewal(Ipv4Address::UNSPECIFIED, gateway));
        assert!(!renewal(lease_ip, other));
        assert!(!initial(Ipv4Address::UNSPECIFIED, other_mac));
    }

    #[test]
    fn test_allowed_from_vm_arp_allows_unspecified_request_without_lease() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let buf = arp_packet(vm_mac_address.0, [0, 0, 0, 0], ArpOperation::Request, 6, 4);
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(super::vm_arp_allowed(arp_pkt, vm_mac_address, &None).is_some());
    }

    #[test]
    fn test_allowed_from_vm_arp_allows_reply_for_leased_ip() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let lease_ip = Ipv4Address::new(192, 168, 0, 2);
        let lease = Some(Lease::new(
            lease_ip,
            Duration::from_secs(600),
            HashSet::new(),
        ));
        let buf = arp_packet(
            vm_mac_address.0,
            lease_ip.octets(),
            ArpOperation::Reply,
            6,
            4,
        );
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(super::vm_arp_allowed(arp_pkt, vm_mac_address, &lease).is_some());
    }

    #[test]
    fn test_allowed_from_vm_arp_rejects_unknown_operation() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let buf = arp_packet(
            vm_mac_address.0,
            [0, 0, 0, 0],
            ArpOperation::Unknown(3),
            6,
            4,
        );
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(super::vm_arp_allowed(arp_pkt, vm_mac_address, &None).is_none());
    }

    #[test]
    fn test_allowed_from_vm_arp_rejects_non_ethernet_hardware_type() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let mut buf = arp_packet(vm_mac_address.0, [0, 0, 0, 0], ArpOperation::Request, 6, 4);
        let mut arp_pkt = ArpPacket::new_unchecked(buf.as_mut_slice());
        arp_pkt.set_hardware_type(ArpHardware::Unknown(2));
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(super::vm_arp_allowed(arp_pkt, vm_mac_address, &None).is_none());
    }

    #[test]
    fn test_allowed_from_vm_arp_rejects_non_ipv4_protocol_type() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let mut buf = arp_packet(vm_mac_address.0, [0, 0, 0, 0], ArpOperation::Request, 6, 4);
        let mut arp_pkt = ArpPacket::new_unchecked(buf.as_mut_slice());
        arp_pkt.set_protocol_type(EthernetProtocol::Ipv6);
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(super::vm_arp_allowed(arp_pkt, vm_mac_address, &None).is_none());
    }

    #[test]
    fn test_allowed_from_vm_arp_rejects_non_ipv4_protocol_length() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let buf = arp_packet(vm_mac_address.0, [0, 0, 0], ArpOperation::Request, 6, 3);
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(super::vm_arp_allowed(arp_pkt, vm_mac_address, &None).is_none());
    }

    fn arp_packet(
        source_hardware_addr: [u8; 6],
        source_protocol_addr: impl AsRef<[u8]>,
        operation: ArpOperation,
        hardware_len: u8,
        protocol_len: u8,
    ) -> Vec<u8> {
        let source_protocol_addr = source_protocol_addr.as_ref();
        let payload_len = 8 + 2 * (hardware_len as usize + protocol_len as usize);
        let mut buf = vec![0; payload_len];
        let mut arp_pkt = ArpPacket::new_unchecked(buf.as_mut_slice());
        arp_pkt.set_hardware_type(ArpHardware::Ethernet);
        arp_pkt.set_protocol_type(EthernetProtocol::Ipv4);
        arp_pkt.set_hardware_len(hardware_len);
        arp_pkt.set_protocol_len(protocol_len);
        arp_pkt.set_operation(operation);
        arp_pkt.set_source_hardware_addr(&source_hardware_addr[..hardware_len as usize]);
        arp_pkt.set_source_protocol_addr(source_protocol_addr);
        arp_pkt.set_target_hardware_addr(&[0; 6][..hardware_len as usize]);
        arp_pkt.set_target_protocol_addr(&vec![0; protocol_len as usize]);
        buf
    }

    fn allowed_dhcp_request(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        unicast_target: Option<Ipv4Address>,
        chaddr: [u8; 6],
        lease: &Option<Lease>,
    ) -> bool {
        let mut buf = dhcp_request(chaddr);
        let mut ipv4_pkt = Ipv4Packet::new_unchecked(buf.as_mut_slice());
        ipv4_pkt.set_src_addr(src_addr);
        ipv4_pkt.set_dst_addr(dst_addr);

        let ipv4_pkt = Ipv4Packet::new_checked(buf.as_slice()).unwrap();
        super::is_allowed_dhcp_request(&ipv4_pkt, unicast_target, VM_MAC, lease)
    }

    fn dhcp_request(chaddr: [u8; 6]) -> Vec<u8> {
        let mut message = Message::new(
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::UNSPECIFIED,
            &chaddr,
        );
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));

        let mut dhcp_payload = Vec::new();
        message
            .encode(&mut Encoder::new(&mut dhcp_payload))
            .unwrap();

        let total_len = 20 + 8 + dhcp_payload.len();
        let mut buf = vec![0; total_len];
        let mut ipv4_pkt = Ipv4Packet::new_unchecked(buf.as_mut_slice());
        ipv4_pkt.set_version(4);
        ipv4_pkt.set_header_len(20);
        ipv4_pkt.set_total_len(total_len as u16);
        ipv4_pkt.set_next_header(IpProtocol::Udp);
        ipv4_pkt.set_src_addr(Ipv4Address::UNSPECIFIED);
        ipv4_pkt.set_dst_addr(Ipv4Address::BROADCAST);

        let mut udp_pkt = UdpPacket::new_unchecked(ipv4_pkt.payload_mut());
        udp_pkt.set_src_port(68);
        udp_pkt.set_dst_port(67);
        udp_pkt.set_len((8 + dhcp_payload.len()) as u16);
        udp_pkt.payload_mut().copy_from_slice(&dhcp_payload);
        buf
    }
}
