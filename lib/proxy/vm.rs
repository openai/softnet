use crate::dhcp_snooper::Lease;
use crate::proxy::conntrack::ConntrackResult;
use crate::proxy::udp_packet_helper::UdpPacketHelper;
use crate::proxy::{Action, Direction, Proxy, Rule, select_rules};
use anyhow::Context;
use anyhow::Result;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address,
    Ipv4Packet, UdpPacket,
};

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
                let ipv4_pkt = Ipv4Packet::new_checked(frame.payload()).ok()?;
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
            let dst_addr = ipv4_pkt.dst_addr();

            // Filter traffic based on user-specified rules first
            if let Some(rules) = select_rules(&self.rules, dst_addr, Direction::Out) {
                // DHCP is required to maintain the VM's lease and must bypass user-specified rules
                if is_allowed_dhcp_request(&ipv4_pkt, Some(self.host.gateway_ip)) {
                    return Some(());
                }

                if let Some((action, _)) = rules
                    .iter()
                    .find(|(_, rule)| matches!(rule, Rule::Stateless(_)))
                {
                    return match action {
                        Action::Allow => Some(()),
                        Action::Block => None,
                    };
                }

                return match self.conntrack.inspect_from_vm(&ipv4_pkt) {
                    ConntrackResult::Allowed => Some(()),
                    ConntrackResult::Denied => None,
                    ConntrackResult::New(pending) => {
                        let allow_new = rules.iter().any(|(action, rule)| {
                            *action == Action::Allow
                                && matches!(
                                    rule,
                                    Rule::Stateful {
                                        direction: Direction::Out,
                                        ..
                                    }
                                )
                        });

                        if !allow_new {
                            return None;
                        }

                        self.conntrack.commit(pending).then_some(())
                    }
                };
            }

            // When no user-specified rules matched, simply allow all global traffic
            if ip_network::IpNetwork::from(dst_addr).is_global() {
                return Some(());
            }

            // Additionally, allow communication with the host,
            // otherwise things like SSH to a VM won't work
            if ipv4_pkt.dst_addr() == self.host.gateway_ip {
                return Some(());
            }

            // Additionally, allow DNS requests to DNS-servers
            // provided to a VM by the host's DHCP server
            if ipv4_pkt.next_header() == IpProtocol::Udp {
                let udp_pkt = UdpPacket::new_checked(ipv4_pkt.payload()).ok()?;

                if udp_pkt.is_dns_request()
                    && self.dhcp_snooper.valid_dns_target(&ipv4_pkt.dst_addr())
                {
                    return Some(());
                }
            }
        }

        // Allow outgoing DHCP requests to the bootpd(8) broadcast address,
        // otherwise DHCP snooper will never be populated
        if is_allowed_dhcp_request(&ipv4_pkt, None) {
            return Some(());
        }

        None
    }
}

fn is_allowed_dhcp_request(
    ipv4_pkt: &Ipv4Packet<&[u8]>,
    unicast_target: Option<Ipv4Address>,
) -> bool {
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

    udp_pkt.is_dhcp_request()
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
    use smoltcp::wire::{
        ArpHardware, ArpOperation, ArpPacket, EthernetAddress, EthernetProtocol, IpProtocol,
        Ipv4Address, Ipv4Packet, UdpPacket,
    };
    use std::collections::HashSet;
    use std::time::Duration;

    #[test]
    fn test_allowed_dhcp_request_targets() {
        let gateway = Ipv4Address::new(192, 168, 64, 1);
        let other = Ipv4Address::new(192, 168, 64, 2);

        assert!(allowed_dhcp_request(Ipv4Address::BROADCAST, None));
        assert!(allowed_dhcp_request(gateway, Some(gateway)));
        assert!(!allowed_dhcp_request(gateway, None));
        assert!(!allowed_dhcp_request(other, Some(gateway)));
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

    fn allowed_dhcp_request(dst_addr: Ipv4Address, unicast_target: Option<Ipv4Address>) -> bool {
        let mut buf = vec![0; 28];
        let mut ipv4_pkt = Ipv4Packet::new_unchecked(buf.as_mut_slice());
        ipv4_pkt.set_version(4);
        ipv4_pkt.set_header_len(20);
        ipv4_pkt.set_total_len(28);
        ipv4_pkt.set_next_header(IpProtocol::Udp);
        ipv4_pkt.set_dst_addr(dst_addr);

        let mut udp_pkt = UdpPacket::new_unchecked(ipv4_pkt.payload_mut());
        udp_pkt.set_src_port(68);
        udp_pkt.set_dst_port(67);
        udp_pkt.set_len(8);

        let ipv4_pkt = Ipv4Packet::new_checked(buf.as_slice()).unwrap();
        super::is_allowed_dhcp_request(&ipv4_pkt, unicast_target)
    }
}
