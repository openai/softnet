use crate::dhcp_server::DHCP_SERVER_MAC;
use crate::dns_server::DNS_PORT;
use crate::proxy::flows::{FlowDirection, FlowMatch};
use crate::proxy::{Direction, PolicyDecision, Proxy};
use anyhow::Context;
use anyhow::Result;
use dhcproto::v4::SERVER_PORT;
use etherparse::{Icmpv4Type, PacketBuilder, icmpv4::DestUnreachableHeader};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress,
    IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket,
};

const IPV4_HEADER_LEN_WITHOUT_OPTIONS: u8 = 20;

impl Proxy {
    pub(crate) async fn process_frame_from_vm(
        &mut self,
        frame: EthernetFrame<&[u8]>,
    ) -> Result<()> {
        if self.allowed_from_vm(&frame).await.is_none() {
            // Block packet by not forwarding it to the host
            return Ok(());
        }

        self.host
            .write(frame.as_ref())
            .map(|_| ())
            .context("failed to write to the host")
    }

    async fn allowed_from_vm(&mut self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
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

                self.allowed_from_vm_ipv4(frame.dst_addr(), ipv4_pkt).await
            }
            _ => None,
        }
    }

    fn allowed_from_vm_arp(&self, arp_pkt: ArpPacket<&[u8]>) -> Option<()> {
        vm_arp_allowed(arp_pkt, self.vm_mac_address, self.host.vm_ip)
    }

    pub(crate) async fn allowed_from_vm_ipv4(
        &mut self,
        destination_mac: EthernetAddress,
        ipv4_pkt: Ipv4Packet<&[u8]>,
    ) -> Option<()> {
        // Consume DHCP before enforcing the reserved source address
        if self.consume_dhcp(&ipv4_pkt) {
            return None;
        }

        // Is this packet coming from the VM's reserved IP address?
        if self.host.vm_ip == ipv4_pkt.src_addr() {
            // Answer queries for Softnet's DNS zone locally
            if self.consume_dns(destination_mac, &ipv4_pkt).await {
                return None;
            }

            // Keep WireGuard destinations out of vmnet
            if let Some(wireguard) = &mut self.wireguard
                && wireguard.reserves(ipv4_pkt.dst_addr())
            {
                let mtu_to_advertise = wireguard.send_vm_ipv4(&ipv4_pkt, self.host.vm_ip).await;

                // Packet won't fit into the WireGuard tunnel, reply with ICMP Fragmentation Needed
                // while suppressing ICMP errors for Ethernet broadcasts and multicasts[1]
                //
                // [1]: https://www.rfc-editor.org/info/rfc1812/#section-4.3.2.7
                if let Some(mtu) = mtu_to_advertise
                    && destination_mac.is_unicast()
                {
                    let reply = fragmentation_needed_frame(
                        &ipv4_pkt,
                        mtu,
                        self.host.gateway_ip,
                        self.vm_mac_address,
                    );
                    if let Err(error) = reply.and_then(|frame| self.write_to_vm(&frame)) {
                        log::debug!("failed to send ICMP Fragmentation Needed: {error:#}");
                    }
                }

                return None;
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

            match self.rules.policy_decision(&ipv4_pkt, Direction::Out) {
                // Return traffic was handled above; enforce explicit outbound blocks here
                Some(PolicyDecision::Block) => return None,

                // Track statelessly allowed traffic only when needed so its reply is not
                // treated as a new inbound flow
                Some(PolicyDecision::AllowStateless) => {
                    return self.admit_with_tracking_if_stateful(pending, &ipv4_pkt, Direction::In);
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
        }

        None
    }

    fn consume_dhcp(&mut self, ipv4_pkt: &Ipv4Packet<&[u8]>) -> bool {
        // Only inspect UDP packets that contain the source and destination ports
        if ipv4_pkt.next_header() != IpProtocol::Udp
            || ipv4_pkt.frag_offset() != 0
            || ipv4_pkt.payload().len() < 4
        {
            return false;
        }

        // Only consume packets addressed to the DHCP server port
        let udp = UdpPacket::new_unchecked(ipv4_pkt.payload());
        if udp.dst_port() != SERVER_PORT {
            return false;
        }

        // Pass the request to the DHCP server and send any reply
        let result = match self.dhcp_server.receive_vm(ipv4_pkt, &udp) {
            Ok(Some(reply)) => self.write_to_vm(&reply),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        };

        // Report failures to generate or send the reply
        if let Err(err) = result {
            sentry::capture_message(
                &format!("Failed to reply to DHCP request: {err:#}"),
                sentry::Level::Warning,
            );
        }

        // Consume the packet even if the request was rejected or the reply failed
        true
    }

    async fn consume_dns(
        &mut self,
        destination_mac: EthernetAddress,
        ipv4_pkt: &Ipv4Packet<&[u8]>,
    ) -> bool {
        // Only inspect DNS packets when Softnet's DNS server is configured
        let Some(dns_server) = &self.dns_server else {
            return false;
        };

        // Accept only complete IPv4 UDP datagrams addressed to the gateway
        if ipv4_pkt.dst_addr() != self.host.gateway_ip
            || !ipv4_pkt.verify_checksum()
            || ipv4_pkt.next_header() != IpProtocol::Udp
            || ipv4_pkt.more_frags()
            || ipv4_pkt.frag_offset() != 0
        {
            return false;
        }

        // Check the UDP header before reading its fields
        let Ok(udp) = UdpPacket::new_checked(ipv4_pkt.payload()) else {
            return false;
        };

        // Validate the UDP checksum, length, and DNS server port
        if !udp.verify_checksum(
            &IpAddress::Ipv4(ipv4_pkt.src_addr()),
            &IpAddress::Ipv4(ipv4_pkt.dst_addr()),
        ) || udp.dst_port() != DNS_PORT
            || udp.len() as usize != ipv4_pkt.payload().len()
        {
            return false;
        }

        // Pass the request to Softnet's DNS server and send the reply
        let result = match dns_server
            .respond(
                self.vm_mac_address,
                destination_mac,
                ipv4_pkt,
                &udp,
                self.host.max_packet_size as usize,
            )
            .await
        {
            Ok(Some(reply)) => self.write_to_vm(&reply),
            Ok(None) => {
                // Leave queries outside Softnet's DNS zone to the system DNS resolver
                return false;
            }
            Err(err) => Err(err),
        };

        // Report failures to generate or send the reply
        if let Err(err) = result {
            sentry::capture_message(
                &format!("Failed to reply to DNS request: {err:#}"),
                sentry::Level::Warning,
            );
        }

        // Consume the packet even if the request was rejected or the reply failed
        true
    }
}

fn fragmentation_needed_frame(
    ip: &Ipv4Packet<&[u8]>,
    mtu: u16,
    gateway: Ipv4Address,
    vm_mac: EthernetAddress,
) -> Result<Vec<u8>> {
    // Quote the original IPv4 header and first eight transport bytes
    let mut quote = [0; IPV4_HEADER_LEN_WITHOUT_OPTIONS as usize + 8];
    let original = ip
        .as_ref()
        .get(..quote.len())
        .context("IPv4 packet too short for ICMP quote")?;
    quote.copy_from_slice(original);
    Ipv4Packet::new_unchecked(&mut quote[..]).fill_checksum();

    let builder = PacketBuilder::ethernet2(DHCP_SERVER_MAC.0, vm_mac.0)
        .ipv4(gateway.octets(), ip.src_addr().octets(), 64)
        .icmpv4(Icmpv4Type::DestinationUnreachable(
            DestUnreachableHeader::FragmentationNeeded { next_hop_mtu: mtu },
        ));
    let mut frame = Vec::with_capacity(builder.size(quote.len()));
    builder.write(&mut frame, &quote)?;

    Ok(frame)
}

fn vm_arp_allowed(
    arp_pkt: ArpPacket<&[u8]>,
    vm_mac_address: smoltcp::wire::EthernetAddress,
    address: Ipv4Address,
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

    (source_protocol_addr == address || source_protocol_addr.is_unspecified()).then_some(())
}

#[cfg(test)]
mod tests {
    use smoltcp::wire::{
        ArpHardware, ArpOperation, ArpPacket, EthernetAddress, EthernetProtocol, Ipv4Address,
    };

    #[test]
    fn fragmentation_needed_frame_quotes_original_guest_datagram() {
        use super::{DHCP_SERVER_MAC, EthernetFrame, IpProtocol, Ipv4Packet, PacketBuilder};
        use smoltcp::wire::Icmpv4Packet;

        let vm = Ipv4Address::new(192, 168, 64, 2);
        let gateway = Ipv4Address::new(192, 168, 64, 1);
        let vm_mac = EthernetAddress([2, 0, 0, 0, 0, 2]);
        let mut oversized = Vec::new();
        PacketBuilder::ipv4(vm.octets(), [10, 77, 2, 2], 64)
            .tcp(50_000, 80, 1, 2048)
            .write(&mut oversized, &[0xa5; 1460])
            .unwrap();
        let mut packet = Ipv4Packet::new_unchecked(&mut oversized[..]);
        packet.set_dont_frag(true);
        packet.fill_checksum();
        let expected_quote = oversized[..28].to_vec();
        Ipv4Packet::new_unchecked(&mut oversized[..]).set_checksum(0);

        let packet = Ipv4Packet::new_checked(&oversized[..]).unwrap();
        let frame = super::fragmentation_needed_frame(&packet, 1380, gateway, vm_mac).unwrap();
        let frame = EthernetFrame::new_checked(&frame[..]).unwrap();
        let reply = Ipv4Packet::new_checked(frame.payload()).unwrap();
        let icmp = Icmpv4Packet::new_checked(reply.payload()).unwrap();
        assert_eq!(frame.src_addr(), DHCP_SERVER_MAC);
        assert_eq!(frame.dst_addr(), vm_mac);
        assert_eq!(reply.src_addr(), gateway);
        assert_eq!(reply.dst_addr(), vm);
        assert_eq!(reply.next_header(), IpProtocol::Icmp);
        assert!(reply.verify_checksum() && icmp.verify_checksum());
        assert_eq!(&reply.payload()[..2], &[3, 4]);
        assert_eq!(&reply.payload()[6..8], &1380u16.to_be_bytes());
        assert_eq!(&reply.payload()[8..], expected_quote);
    }

    #[test]
    fn test_allowed_from_vm_arp_allows_unspecified_request() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let buf = arp_packet(vm_mac_address.0, [0, 0, 0, 0], ArpOperation::Request, 6, 4);
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(
            super::vm_arp_allowed(arp_pkt, vm_mac_address, Ipv4Address::new(1, 2, 3, 4)).is_some()
        );
    }

    #[test]
    fn test_allowed_from_vm_arp_allows_reply_for_leased_ip() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let vm_ip = Ipv4Address::new(192, 168, 0, 2);
        let buf = arp_packet(vm_mac_address.0, vm_ip.octets(), ArpOperation::Reply, 6, 4);
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(super::vm_arp_allowed(arp_pkt, vm_mac_address, vm_ip).is_some());
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

        assert!(
            super::vm_arp_allowed(arp_pkt, vm_mac_address, Ipv4Address::new(1, 2, 3, 4)).is_none()
        );
    }

    #[test]
    fn test_allowed_from_vm_arp_rejects_non_ethernet_hardware_type() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let mut buf = arp_packet(vm_mac_address.0, [0, 0, 0, 0], ArpOperation::Request, 6, 4);
        let mut arp_pkt = ArpPacket::new_unchecked(buf.as_mut_slice());
        arp_pkt.set_hardware_type(ArpHardware::Unknown(2));
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(
            super::vm_arp_allowed(arp_pkt, vm_mac_address, Ipv4Address::new(1, 2, 3, 4)).is_none()
        );
    }

    #[test]
    fn test_allowed_from_vm_arp_rejects_non_ipv4_protocol_type() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let mut buf = arp_packet(vm_mac_address.0, [0, 0, 0, 0], ArpOperation::Request, 6, 4);
        let mut arp_pkt = ArpPacket::new_unchecked(buf.as_mut_slice());
        arp_pkt.set_protocol_type(EthernetProtocol::Ipv6);
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(
            super::vm_arp_allowed(arp_pkt, vm_mac_address, Ipv4Address::new(1, 2, 3, 4)).is_none()
        );
    }

    #[test]
    fn test_allowed_from_vm_arp_rejects_non_ipv4_protocol_length() {
        let vm_mac_address = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let buf = arp_packet(vm_mac_address.0, [0, 0, 0], ArpOperation::Request, 6, 3);
        let arp_pkt = ArpPacket::new_checked(buf.as_slice()).unwrap();

        assert!(
            super::vm_arp_allowed(arp_pkt, vm_mac_address, Ipv4Address::new(1, 2, 3, 4)).is_none()
        );
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
}
