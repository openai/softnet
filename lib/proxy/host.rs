use crate::proxy::flows::{FlowDirection, FlowMatch};
use crate::proxy::udp_packet_helper::UdpPacketHelper;
use crate::proxy::{Direction, PolicyDecision, Proxy};
use anyhow::{Context, Result};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{EthernetFrame, EthernetProtocol, Ipv4Packet, Ipv4Repr, UdpPacket};

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
        // Backwards compatibility with Softnet consumers that only use stateless rules
        if self.flows.is_none() {
            return Some(());
        }

        // DHCP is required to maintain the VM's lease and must bypass user-specified rules
        if self.is_allowed_dhcp_response(ipv4_pkt) {
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

        if !self.is_allowed_dhcp_response(&ipv4_pkt) {
            return;
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

    fn is_allowed_dhcp_response(&self, ipv4_pkt: &Ipv4Packet<&[u8]>) -> bool {
        if ipv4_pkt.src_addr() != self.host.gateway_ip
            || ipv4_pkt.next_header() != smoltcp::wire::IpProtocol::Udp
        {
            return false;
        }

        UdpPacket::new_checked(ipv4_pkt.payload())
            .map(|udp_pkt| udp_pkt.is_dhcp_response())
            .unwrap_or(false)
    }
}
