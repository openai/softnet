use crate::proxy::flows::{FlowDirection, FlowMatch};
use crate::proxy::{Direction, PolicyDecision, Proxy};
use anyhow::{Context, Result};
use dhcproto::v4::{CLIENT_PORT, SERVER_PORT};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket};

impl Proxy<'_> {
    pub(crate) fn process_frame_from_host(&mut self, frame: &EthernetFrame<&[u8]>) -> Result<()> {
        if self.allowed_from_host(frame).is_none() {
            // Block packet by not forwarding it to the VM
            return Ok(());
        }

        self.write_to_vm(frame.as_ref())
    }

    pub(super) fn write_to_vm(&mut self, packet: &[u8]) -> Result<()> {
        match self.vm.write(packet) {
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
        // Drop external DHCP replies, including malformed and fragmented replies
        if ipv4_pkt.next_header() == IpProtocol::Udp
            && ipv4_pkt.frag_offset() == 0
            && ipv4_pkt.payload().len() >= 4
        {
            let udp = UdpPacket::new_unchecked(ipv4_pkt.payload());
            if udp.src_port() == SERVER_PORT && udp.dst_port() == CLIENT_PORT {
                return None;
            }
        }

        // Backwards compatibility with Softnet consumers that only use stateless rules
        if self.flows.is_none() {
            return Some(());
        }

        // Consult the flow table before evaluating inbound policy
        // so established flows are not treated as new traffic
        let pending = if self.host.vm_ip == ipv4_pkt.dst_addr() {
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
}
