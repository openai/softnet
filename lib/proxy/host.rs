use crate::dhcp_snooper::message_matches_bootp_client;
use crate::proxy::flows::{FlowDirection, FlowMatch};
use crate::proxy::udp_packet_helper::UdpPacketHelper;
use crate::proxy::{Direction, PolicyDecision, Proxy};
use anyhow::{Context, Result};
use dhcproto::Decodable;
use dhcproto::v4::Opcode;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket,
};

/// DhcpResponseDisposition distinguishes non-DHCP traffic from allowed and rejected DHCP replies.
#[derive(Debug, PartialEq, Eq)]
enum DhcpResponseDisposition {
    NotDhcp,
    Allow,
    Reject,
}

impl Proxy<'_> {
    pub(crate) fn process_frame_from_host(&mut self, frame: &EthernetFrame<&[u8]>) -> Result<()> {
        if self.allowed_from_host(frame).is_none() {
            // Block packet by not forwarding it to the VM
            return Ok(());
        }

        // Snoop bootpd(8) replies from the host to
        // figure out the IP assigned to the VM
        if frame.dst_addr() == self.vm_mac_address || frame.dst_addr().is_broadcast() {
            self.snoop(frame);
        }

        match self.vm.write(frame.as_ref()) {
            Ok(_) => Ok(()),
            Err(err) => {
                if let Some(libc::ENOBUFS) = err.raw_os_error() {
                    if !self.enobufs_encountered {
                        sentry::capture_message(
                            "No buffer space available in VM's socket",
                            sentry::Level::Warning,
                        );
                        self.enobufs_encountered = true;
                    }

                    return Ok(());
                }

                Err(err).context("failed to write to the VM")
            }
        }
    }

    fn allowed_from_host(&mut self, frame: &EthernetFrame<&[u8]>) -> Option<()> {
        match frame.ethertype() {
            EthernetProtocol::Arp => Some(()),
            EthernetProtocol::Ipv4 => {
                let ipv4_pkt = Ipv4Packet::new_unchecked(frame.payload());
                Ipv4Repr::parse(&ipv4_pkt, &ChecksumCapabilities::ignored()).ok()?;

                self.allowed_from_host_ipv4(&ipv4_pkt)
            }
            _ => None,
        }
    }

    pub(super) fn allowed_from_host_ipv4(&mut self, ipv4_pkt: &Ipv4Packet<&[u8]>) -> Option<()> {
        match self.dhcp_response_disposition(ipv4_pkt) {
            DhcpResponseDisposition::NotDhcp => { /* Fall through to generic policy */ }
            DhcpResponseDisposition::Allow => return Some(()),
            DhcpResponseDisposition::Reject => return None,
        }

        // Backwards compatibility with Softnet consumers that only use stateless rules
        if self.flows.is_none() {
            return Some(());
        }

        // Consult the flow table before evaluating inbound policy
        // so established flows are not treated as new traffic
        let pending = if self
            .dhcp_snooper
            .lease()
            .as_ref()
            .is_some_and(|lease| lease.is_valid_for(ipv4_pkt.dst_addr()))
        {
            match self
                .flows
                .as_mut()?
                .inspect(ipv4_pkt, FlowDirection::FromHost)
            {
                FlowMatch::Allowed => return Some(()),
                FlowMatch::Denied => return None,
                FlowMatch::Candidate(pending) => Some(pending),
                FlowMatch::Untracked => None,
            }
        } else {
            None
        };

        // The flow is either pending or untracked, evaluate it against inbound policy
        match self
            .rules
            .policy_decision(ipv4_pkt.src_addr(), Direction::In)
        {
            // Return traffic was handled above; enforce explicit inbound blocks here
            Some(PolicyDecision::Block) => None,

            // Stateless policy is outbound-only; fail closed if this invariant is violated
            Some(PolicyDecision::AllowStateless) => None,

            // Untracked packets cannot satisfy stateful policy
            Some(PolicyDecision::AllowStateful) => self.admit_with_tracking(pending?),

            // No inbound rule matched, so allow by default. Track the flow when needed
            // so its reply is not treated as a new outbound flow
            None => {
                self.admit_with_tracking_if_stateful(pending, ipv4_pkt.src_addr(), Direction::Out)
            }
        }
    }

    fn snoop(&mut self, frame: &EthernetFrame<&[u8]>) {
        if frame.ethertype() != EthernetProtocol::Ipv4 {
            return;
        }

        let ipv4_pkt = match Ipv4Packet::new_checked(frame.payload()) {
            Ok(ipv4_pkt) => ipv4_pkt,
            _ => return,
        };

        match self.dhcp_response_disposition(&ipv4_pkt) {
            DhcpResponseDisposition::Allow => { /* Continue snooping */ }
            DhcpResponseDisposition::NotDhcp | DhcpResponseDisposition::Reject => return,
        }

        let udp_pkt = match UdpPacket::new_checked(ipv4_pkt.payload()) {
            Ok(udp_pkt) => udp_pkt,
            Err(_) => return,
        };

        let address_and_dns_ips_saved = self.dhcp_snooper.address_and_dns_ips();
        self.dhcp_snooper.register_dhcp_reply(udp_pkt.payload());
        if address_and_dns_ips_saved != self.dhcp_snooper.address_and_dns_ips()
            && let Some(flows) = &mut self.flows
        {
            flows.clear();
        }
    }

    fn dhcp_response_disposition(&self, ipv4_pkt: &Ipv4Packet<&[u8]>) -> DhcpResponseDisposition {
        classify_dhcp_response(ipv4_pkt, self.host.gateway_ip, self.vm_mac_address.0)
    }
}

/// Classify an IPv4 packet coming from the host as a DHCP reply, a rejected DHCP reply,
/// or as traffic that is not DHCP at all.
fn classify_dhcp_response(
    ipv4_pkt: &Ipv4Packet<&[u8]>,
    gateway_ip: Ipv4Address,
    vm_mac_address: [u8; 6],
) -> DhcpResponseDisposition {
    if ipv4_pkt.src_addr() != gateway_ip || ipv4_pkt.next_header() != smoltcp::wire::IpProtocol::Udp
    {
        return DhcpResponseDisposition::NotDhcp;
    }

    // A fragmented gateway datagram cannot be classified here: the first fragment's
    // UDP length covers the complete datagram, so it fails the length check below, and
    // later fragments carry no UDP header at all. Reporting NotDhcp would send every
    // fragment through the generic policy path, which unconditionally permits them
    // when flows are disabled, letting the guest reassemble a foreign DHCP reply and
    // bypass the BOOTP client check. Reject fragments instead.
    if ipv4_pkt.more_frags() || ipv4_pkt.frag_offset() != 0 {
        return DhcpResponseDisposition::Reject;
    }

    let Ok(udp_pkt) = UdpPacket::new_checked(ipv4_pkt.payload()) else {
        return DhcpResponseDisposition::NotDhcp;
    };

    // Require the standard DHCP server and client ports
    if !udp_pkt.is_dhcp_response() {
        return DhcpResponseDisposition::NotDhcp;
    }

    // Require the BOOTP client hardware address to match this VM
    // (symmetric with is_allowed_dhcp_request / #191 on the VM→host path)
    let mut decoder = dhcproto::v4::Decoder::new(udp_pkt.payload());
    let Ok(message) = dhcproto::v4::Message::decode(&mut decoder) else {
        return DhcpResponseDisposition::Reject;
    };

    if message_matches_bootp_client(&message, Opcode::BootReply, vm_mac_address) {
        DhcpResponseDisposition::Allow
    } else {
        DhcpResponseDisposition::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::{DhcpResponseDisposition, classify_dhcp_response};
    use crate::dhcp_snooper::message_matches_bootp_client;
    use dhcproto::Decodable;
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Encodable, Encoder};
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, UdpPacket};

    const GATEWAY: Ipv4Address = Ipv4Address::new(192, 168, 64, 1);
    const VM_IP: Ipv4Address = Ipv4Address::new(192, 168, 64, 2);
    const VM_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const OTHER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

    #[test]
    fn dhcp_boot_reply_chaddr_must_match_vm() {
        let own = encode_boot_reply(VM_MAC);
        let foreign = encode_boot_reply(OTHER_MAC);

        let mut dec = dhcproto::v4::Decoder::new(&own);
        let own_msg = Message::decode(&mut dec).unwrap();
        let mut dec = dhcproto::v4::Decoder::new(&foreign);
        let foreign_msg = Message::decode(&mut dec).unwrap();

        assert!(message_matches_bootp_client(
            &own_msg,
            Opcode::BootReply,
            VM_MAC
        ));
        assert!(!message_matches_bootp_client(
            &foreign_msg,
            Opcode::BootReply,
            VM_MAC
        ));
    }

    fn encode_boot_reply(chaddr: [u8; 6]) -> Vec<u8> {
        let mut message = Message::new(
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::new(192, 168, 64, 2),
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::UNSPECIFIED,
            &chaddr,
        );
        message.set_opcode(Opcode::BootReply);
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));
        message.opts_mut().insert(DhcpOption::AddressLeaseTime(600));

        let mut encoded = Vec::new();
        message.encode(&mut Encoder::new(&mut encoded)).unwrap();
        encoded
    }

    #[test]
    fn fragmented_gateway_dhcp_reply_is_rejected() {
        // Fragmentation must be rejected rather than reported as non-DHCP: the first
        // fragment's UDP length covers the complete datagram, and later fragments carry
        // no UDP header, so the BOOTP client check below can never run on them.
        for (more_fragments, offset) in [(true, 0), (false, 8)] {
            let mut bytes = dhcp_reply_packet(OTHER_MAC);
            {
                let mut packet = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
                packet.set_more_frags(more_fragments);
                packet.set_frag_offset(offset);
            }

            let packet = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();
            assert_eq!(
                classify_dhcp_response(&packet, GATEWAY, VM_MAC),
                DhcpResponseDisposition::Reject,
                "more_fragments={more_fragments} offset={offset}"
            );
        }
    }

    #[test]
    fn unfragmented_gateway_dhcp_reply_is_still_classified_by_chaddr() {
        let own = dhcp_reply_packet(VM_MAC);
        let packet = Ipv4Packet::new_checked(own.as_slice()).unwrap();
        assert_eq!(
            classify_dhcp_response(&packet, GATEWAY, VM_MAC),
            DhcpResponseDisposition::Allow
        );

        let foreign = dhcp_reply_packet(OTHER_MAC);
        let packet = Ipv4Packet::new_checked(foreign.as_slice()).unwrap();
        assert_eq!(
            classify_dhcp_response(&packet, GATEWAY, VM_MAC),
            DhcpResponseDisposition::Reject
        );
    }

    #[test]
    fn fragmented_traffic_from_other_sources_is_not_treated_as_dhcp() {
        let mut bytes = ipv4_udp_packet(
            Ipv4Address::new(192, 168, 64, 3),
            VM_IP,
            67,
            68,
            &encode_boot_reply(OTHER_MAC),
        );
        {
            let mut packet = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
            packet.set_more_frags(true);
        }

        let packet = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();
        assert_eq!(
            classify_dhcp_response(&packet, GATEWAY, VM_MAC),
            DhcpResponseDisposition::NotDhcp
        );
    }

    fn dhcp_reply_packet(chaddr: [u8; 6]) -> Vec<u8> {
        ipv4_udp_packet(GATEWAY, VM_IP, 67, 68, &encode_boot_reply(chaddr))
    }

    fn ipv4_udp_packet(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut bytes = vec![0; 20 + 8 + payload.len()];
        let total_len = bytes.len() as u16;

        {
            let mut ipv4 = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
            ipv4.set_version(4);
            ipv4.set_header_len(20);
            ipv4.set_total_len(total_len);
            ipv4.set_next_header(IpProtocol::Udp);
            ipv4.set_src_addr(src_addr);
            ipv4.set_dst_addr(dst_addr);
        }

        {
            let mut udp = UdpPacket::new_unchecked(&mut bytes[20..]);
            udp.set_src_port(src_port);
            udp.set_dst_port(dst_port);
            udp.set_len((8 + payload.len()) as u16);
        }

        bytes[28..].copy_from_slice(payload);
        bytes
    }
}
