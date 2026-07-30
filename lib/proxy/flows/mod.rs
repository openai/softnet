mod icmp;
mod tcp;
mod udp;

use coarsetime::{Duration, Instant};
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet};
use std::collections::HashMap;

const MAX_FLOWS: usize = 32_768;
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// A bounded cache of exact-tuple permissions for return traffic.
///
/// The table establishes only the direction in which a flow was authorized.
/// This is deliberately not a TCP state machine. Endpoint transport stacks remain
/// responsible for TCP handshakes, teardown, sequence numbers, and receive windows,
/// as well as ICMP echo sequences.
///
/// Capacity is intentionally enforced with one fail-closed limit per VM.
/// Exhaustion may deny further networking for that VM; this availability
/// tradeoff is accepted to avoid fairness quotas, admission scans, and eviction.
#[derive(Debug)]
pub(crate) struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    next_sweep: Instant,
}

/// A proposed flow-table entry awaiting policy authorization.
pub(crate) struct PendingFlow {
    key: FlowKey,
    flow: Flow,
}

/// Metadata stored for an admitted flow.
#[derive(Clone, Copy, Debug)]
struct Flow {
    initiating_direction: FlowDirection,
    expires_at: Instant,
}

/// The result of classifying a packet against the flow table.
pub(crate) enum FlowMatch {
    /// The packet is exact-tuple return traffic for an admitted flow.
    Allowed,

    /// Policy must authorize this initiator-side packet before committing it.
    Candidate(PendingFlow),

    /// The packet is malformed or violates a transport invariant that we deliberately enforce.
    Denied,

    /// The flow table has no stateful interpretation for this packet.
    Untracked,
}

impl FlowMatch {
    fn candidate(
        key: FlowKey,
        initiating_direction: FlowDirection,
        now: Instant,
        timeout: Duration,
    ) -> Self {
        Self::Candidate(PendingFlow {
            key,
            flow: Flow {
                initiating_direction,
                expires_at: now + timeout,
            },
        })
    }
}

/// The canonical identity used to index a flow-table entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum FlowKey {
    IcmpEcho {
        host_addr: Ipv4Address,
        vm_addr: Ipv4Address,
        ident: u16,
        initiating_direction: FlowDirection,
    },
    Tcp {
        host_addr: Ipv4Address,
        host_port: u16,
        vm_addr: Ipv4Address,
        vm_port: u16,
    },
    Udp {
        host_addr: Ipv4Address,
        host_port: u16,
        vm_addr: Ipv4Address,
        vm_port: u16,
    },
}

/// A packet direction across the host–VM boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum FlowDirection {
    FromHost,
    FromVm,
}

impl FlowTable {
    pub(crate) fn new() -> Self {
        Self {
            flows: HashMap::new(),
            next_sweep: Instant::recent() + SWEEP_INTERVAL,
        }
    }

    pub(super) fn inspect(
        &mut self,
        ipv4_pkt: &Ipv4Packet<&[u8]>,
        direction: FlowDirection,
    ) -> FlowMatch {
        self.inspect_at(ipv4_pkt, direction, Instant::recent())
    }

    fn inspect_at(
        &mut self,
        ipv4_pkt: &Ipv4Packet<&[u8]>,
        direction: FlowDirection,
        now: Instant,
    ) -> FlowMatch {
        // Perform lazy garbage collection of expired flow entries
        self.sweep_if_due(now);

        // Later fragments do not contain enough transport information to bind
        // them to an exact flow, so packet policy must decide
        if ipv4_pkt.more_frags() || ipv4_pkt.frag_offset() != 0 {
            return FlowMatch::Untracked;
        }

        match ipv4_pkt.next_header() {
            IpProtocol::Icmp => self.inspect_icmp(ipv4_pkt, direction, now),
            IpProtocol::Tcp => self.inspect_tcp(ipv4_pkt, direction, now),
            IpProtocol::Udp => self.inspect_udp(ipv4_pkt, direction, now),
            _ => FlowMatch::Untracked,
        }
    }

    pub(crate) fn commit(&mut self, pending: PendingFlow) -> bool {
        let PendingFlow { key, flow } = pending;

        // Reject new entries when full while allowing existing entries to be updated
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            return false;
        }

        self.flows.insert(key, flow);

        true
    }

    pub(crate) fn clear(&mut self) {
        self.flows.clear();
    }

    fn sweep_if_due(&mut self, now: Instant) {
        if now < self.next_sweep {
            return;
        }

        self.flows.retain(|_, flow| now < flow.expires_at);

        self.next_sweep = now + SWEEP_INTERVAL;
    }

    fn match_existing_flow(
        &self,
        key: FlowKey,
        direction: FlowDirection,
        now: Instant,
        timeout: Duration,
    ) -> Option<FlowMatch> {
        let existing = self.flows.get(&key).copied()?;

        // Treat expired entries as missing even before the next sweep
        if now >= existing.expires_at {
            return None;
        }

        if direction == existing.initiating_direction {
            Some(FlowMatch::candidate(
                key,
                existing.initiating_direction,
                now,
                timeout,
            ))
        } else {
            Some(FlowMatch::Allowed)
        }
    }
}

impl FlowDirection {
    fn host_vm_pair<T>(self, src: T, dst: T) -> (T, T) {
        match self {
            Self::FromHost => (src, dst),
            Self::FromVm => (dst, src),
        }
    }

    fn opposite(self) -> Self {
        match self {
            Self::FromHost => Self::FromVm,
            Self::FromVm => Self::FromHost,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{HOST, VM, inspect_from_host, ipv4_packet, udp_packet};
    use super::{
        Duration, FlowDirection, FlowMatch, FlowTable, Instant, MAX_FLOWS, SWEEP_INTERVAL,
    };
    use smoltcp::wire::{IpProtocol, Ipv4Packet};

    #[test]
    fn all_ipv4_fragments_are_untracked() {
        for (more_fragments, offset) in [(true, 0), (false, 8)] {
            let mut bytes = udp_packet(HOST, 50_000, VM, 53);
            let mut packet = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
            packet.set_frag_offset(offset);
            packet.set_more_frags(more_fragments);

            let mut tracker = FlowTable::new();
            assert!(matches!(
                inspect_from_host(&mut tracker, &bytes),
                FlowMatch::Untracked
            ));
        }
    }

    #[test]
    fn expired_tuple_is_not_matched_before_the_next_sweep() {
        let mut tracker = FlowTable::new();
        let datagram = udp_packet(HOST, 50_000, VM, 53);
        let FlowMatch::Candidate(pending) = inspect_from_host(&mut tracker, &datagram) else {
            panic!("expected a candidate");
        };
        assert!(tracker.commit(pending));

        let now = Instant::recent();
        let flow = tracker.flows.values_mut().next().unwrap();
        flow.expires_at = now - Duration::from_secs(1);
        tracker.next_sweep = now + SWEEP_INTERVAL;

        let reply = udp_packet(VM, 53, HOST, 50_000);
        assert!(matches!(
            tracker.inspect_at(
                &Ipv4Packet::new_checked(reply.as_slice()).unwrap(),
                FlowDirection::FromVm,
                now,
            ),
            FlowMatch::Candidate(_)
        ));
    }

    #[test]
    fn global_limit_rejects_new_tuple_but_allows_replacement() {
        let mut tracker = FlowTable::new();
        for port in 10_000..10_000 + MAX_FLOWS as u16 {
            let datagram = udp_packet(HOST, port, VM, 53);
            let FlowMatch::Candidate(pending) = inspect_from_host(&mut tracker, &datagram) else {
                panic!("expected a candidate");
            };
            assert!(tracker.commit(pending));
        }

        let over_limit = udp_packet(HOST, 50_000, VM, 53);
        let FlowMatch::Candidate(pending) = inspect_from_host(&mut tracker, &over_limit) else {
            panic!("expected a candidate");
        };
        assert!(!tracker.commit(pending));

        let replacement = udp_packet(HOST, 10_000, VM, 53);
        let FlowMatch::Candidate(pending) = inspect_from_host(&mut tracker, &replacement) else {
            panic!("expected a candidate");
        };
        assert!(tracker.commit(pending));
    }

    #[test]
    fn unsupported_protocol_is_untracked() {
        let bytes = ipv4_packet(HOST, VM, IpProtocol::Unknown(253), 0);
        let mut tracker = FlowTable::new();
        assert!(matches!(
            inspect_from_host(&mut tracker, &bytes),
            FlowMatch::Untracked
        ));
    }
}

#[cfg(test)]
mod test_support {
    use super::{FlowDirection, FlowMatch, FlowTable};
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};

    pub(super) const HOST: Ipv4Address = Ipv4Address::new(192, 168, 64, 1);
    pub(super) const VM: Ipv4Address = Ipv4Address::new(192, 168, 64, 2);

    pub(super) fn inspect_from_host(tracker: &mut FlowTable, bytes: &[u8]) -> FlowMatch {
        let packet = Ipv4Packet::new_checked(bytes).unwrap();
        tracker.inspect(&packet, FlowDirection::FromHost)
    }

    pub(super) fn inspect_from_vm(tracker: &mut FlowTable, bytes: &[u8]) -> FlowMatch {
        let packet = Ipv4Packet::new_checked(bytes).unwrap();
        tracker.inspect(&packet, FlowDirection::FromVm)
    }

    #[derive(Clone, Copy)]
    pub(super) struct TcpFlags {
        syn: bool,
        ack: bool,
        rst: bool,
        fin: bool,
    }

    impl TcpFlags {
        pub(super) const SYN: Self = Self {
            syn: true,
            ack: false,
            rst: false,
            fin: false,
        };
        pub(super) const SYN_ACK: Self = Self {
            syn: true,
            ack: true,
            rst: false,
            fin: false,
        };
        pub(super) const ACK: Self = Self {
            syn: false,
            ack: true,
            rst: false,
            fin: false,
        };
    }

    pub(super) fn tcp_packet(
        src_addr: Ipv4Address,
        src_port: u16,
        dst_addr: Ipv4Address,
        dst_port: u16,
        flags: TcpFlags,
    ) -> Vec<u8> {
        let mut bytes = ipv4_packet(src_addr, dst_addr, IpProtocol::Tcp, 20);
        let mut tcp = TcpPacket::new_unchecked(&mut bytes[20..]);
        tcp.set_src_port(src_port);
        tcp.set_dst_port(dst_port);
        tcp.set_header_len(20);
        tcp.set_syn(flags.syn);
        tcp.set_ack(flags.ack);
        tcp.set_rst(flags.rst);
        tcp.set_fin(flags.fin);
        tcp.set_window_len(u16::MAX);
        bytes
    }

    pub(super) fn udp_packet(
        src_addr: Ipv4Address,
        src_port: u16,
        dst_addr: Ipv4Address,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut bytes = ipv4_packet(src_addr, dst_addr, IpProtocol::Udp, 8);
        let mut udp = UdpPacket::new_unchecked(&mut bytes[20..]);
        udp.set_src_port(src_port);
        udp.set_dst_port(dst_port);
        udp.set_len(8);
        bytes
    }

    pub(super) fn ipv4_packet(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        protocol: IpProtocol,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut bytes = vec![0; 20 + payload_len];
        let total_len = bytes.len() as u16;
        let mut ipv4 = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
        ipv4.set_version(4);
        ipv4.set_header_len(20);
        ipv4.set_total_len(total_len);
        ipv4.set_next_header(protocol);
        ipv4.set_src_addr(src_addr);
        ipv4.set_dst_addr(dst_addr);
        bytes
    }
}
