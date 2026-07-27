#[path = "conntrack_tcp.rs"]
mod tcp;
#[path = "conntrack_udp.rs"]
mod udp;

use coarsetime::{Duration, Instant};
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet};
use std::collections::HashMap;

const MAX_FLOWS: usize = 4096;
const MAX_VM_INITIATED_FLOWS: usize = 1024;
const MAX_EMBRYONIC_FLOWS_PER_SOURCE: usize = 256;
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Tracks permission to use an exact host/VM flow tuple.
///
/// This deliberately does not replace either endpoint's transport stack:
/// TCP sequence/window validation remains the host's and VM's responsibility.
/// Its security boundary is flow initiation: only an authorized first packet
/// can create an entry, and VM traffic to the host must match the reverse.
#[derive(Debug)]
pub(crate) struct Conntrack {
    flows: HashMap<FlowKey, Flow>,
    next_sweep: Instant,
}

pub(crate) enum ConntrackResult {
    Allowed,
    New(PendingFlow),
    Denied,
}

pub(crate) struct PendingFlow {
    key: FlowKey,
    flow: Flow,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum FlowKey {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Initiator {
    Host,
    Vm,
}

#[derive(Clone, Copy, Debug)]
struct Flow {
    initiator: Initiator,
    state: FlowState,
    last_seen: Instant,
}

#[derive(Clone, Copy, Debug)]
enum FlowState {
    Tcp(tcp::State),
    Udp(udp::State),
}

#[derive(Clone, Copy)]
enum Direction {
    FromHost,
    FromVm,
}

impl Conntrack {
    pub(crate) fn new() -> Self {
        let now = Instant::recent();
        Self {
            flows: HashMap::new(),
            next_sweep: now + SWEEP_INTERVAL,
        }
    }

    pub(crate) fn inspect_from_host(&mut self, packet: &Ipv4Packet<&[u8]>) -> ConntrackResult {
        self.inspect(packet, Direction::FromHost, Instant::recent())
    }

    pub(crate) fn inspect_from_vm(&mut self, packet: &Ipv4Packet<&[u8]>) -> ConntrackResult {
        self.inspect(packet, Direction::FromVm, Instant::recent())
    }

    pub(crate) fn commit(&mut self, mut pending: PendingFlow) -> bool {
        let now = Instant::recent();
        pending.flow.last_seen = now;
        self.insert(pending.key, pending.flow, now)
    }

    pub(crate) fn tick(&mut self) {
        let now = Instant::recent();
        if now >= self.next_sweep {
            self.expire(now);
            self.next_sweep = now + SWEEP_INTERVAL;
        }
    }

    pub(crate) fn clear(&mut self) {
        self.flows.clear();
    }

    fn inspect(
        &mut self,
        packet: &Ipv4Packet<&[u8]>,
        direction: Direction,
        now: Instant,
    ) -> ConntrackResult {
        // Later fragments do not contain the transport header needed to bind them
        // to a permitted flow. Fail closed instead of admitting them by IP alone.
        if packet.more_frags() || packet.frag_offset() != 0 {
            return ConntrackResult::Denied;
        }

        match packet.next_header() {
            IpProtocol::Tcp => self.inspect_tcp(packet, direction, now),
            IpProtocol::Udp => self.inspect_udp(packet, direction, now),
            _ => ConntrackResult::Denied,
        }
    }

    fn insert(&mut self, key: FlowKey, flow: Flow, now: Instant) -> bool {
        self.expire(now);
        if self.flows.len() >= MAX_FLOWS {
            return false;
        }
        if flow.initiator == Initiator::Vm
            && self
                .flows
                .values()
                .filter(|flow| flow.initiator == Initiator::Vm)
                .count()
                >= MAX_VM_INITIATED_FLOWS
        {
            return false;
        }
        if let Some(initiator_addr) = embryonic_source(key, flow)
            && self
                .flows
                .iter()
                .filter(|(key, flow)| embryonic_source(**key, **flow) == Some(initiator_addr))
                .count()
                >= MAX_EMBRYONIC_FLOWS_PER_SOURCE
        {
            return false;
        }
        self.flows.insert(key, flow);
        true
    }

    fn expire(&mut self, now: Instant) {
        self.flows
            .retain(|_, flow| now.duration_since(flow.last_seen) < flow.timeout());
    }
}

impl Flow {
    fn timeout(&self) -> Duration {
        match self.state {
            FlowState::Tcp(state) => state.timeout(),
            FlowState::Udp(state) => state.timeout(),
        }
    }
}

fn embryonic_source(key: FlowKey, flow: Flow) -> Option<Ipv4Address> {
    match (key, flow.initiator, flow.state) {
        (
            FlowKey::Tcp { host_addr, .. },
            Initiator::Host,
            FlowState::Tcp(tcp::State::SynSent | tcp::State::SynReceived),
        ) => Some(host_addr),
        (
            FlowKey::Tcp { vm_addr, .. },
            Initiator::Vm,
            FlowState::Tcp(tcp::State::SynSent | tcp::State::SynReceived),
        ) => Some(vm_addr),
        _ => None,
    }
}

fn oriented_transport_key(
    packet: &Ipv4Packet<&[u8]>,
    direction: Direction,
    make_key: impl FnOnce(Ipv4Address, u16, Ipv4Address, u16) -> FlowKey,
    src_port: u16,
    dst_port: u16,
) -> FlowKey {
    match direction {
        Direction::FromHost => make_key(packet.src_addr(), src_port, packet.dst_addr(), dst_port),
        Direction::FromVm => make_key(packet.dst_addr(), dst_port, packet.src_addr(), src_port),
    }
}

fn initiator(direction: Direction) -> Initiator {
    match direction {
        Direction::FromHost => Initiator::Host,
        Direction::FromVm => Initiator::Vm,
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{HOST, TcpFlags, VM, inspect_from_host, inspect_from_vm, tcp_packet};
    use super::{Conntrack, ConntrackResult, MAX_EMBRYONIC_FLOWS_PER_SOURCE};
    use smoltcp::wire::{Ipv4Address, Ipv4Packet};

    #[test]
    fn fragments_fail_closed() {
        let mut packet = tcp_packet(HOST, 49152, VM, 22, TcpFlags::SYN);
        Ipv4Packet::new_unchecked(packet.as_mut_slice()).set_more_frags(true);

        let mut tracker = Conntrack::new();
        assert!(matches!(
            inspect_from_host(&mut tracker, &packet),
            ConntrackResult::Denied
        ));
    }

    #[test]
    fn clear_removes_tracked_flows() {
        let packet = tcp_packet(HOST, 49152, VM, 22, TcpFlags::SYN);
        let mut tracker = Conntrack::new();

        let ConntrackResult::New(pending) = inspect_from_host(&mut tracker, &packet) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));
        assert_eq!(tracker.flows.len(), 1);

        tracker.clear();
        assert!(tracker.flows.is_empty());
    }

    #[test]
    fn embryonic_tcp_limit_is_per_source() {
        let mut tracker = Conntrack::new();

        for index in 0..MAX_EMBRYONIC_FLOWS_PER_SOURCE {
            let syn = tcp_packet(HOST, 10000 + index as u16, VM, 22, TcpFlags::SYN);
            let ConntrackResult::New(pending) = inspect_from_host(&mut tracker, &syn) else {
                panic!("expected a new flow");
            };
            assert!(tracker.commit(pending));
        }

        let over_limit = tcp_packet(HOST, 20000, VM, 22, TcpFlags::SYN);
        let ConntrackResult::New(pending) = inspect_from_host(&mut tracker, &over_limit) else {
            panic!("expected a new flow");
        };
        assert!(!tracker.commit(pending));

        let other_host = Ipv4Address::new(192, 168, 64, 3);
        let other_source = tcp_packet(other_host, 20000, VM, 22, TcpFlags::SYN);
        let ConntrackResult::New(pending) = inspect_from_host(&mut tracker, &other_source) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));

        let syn_ack = tcp_packet(VM, 22, HOST, 10000, TcpFlags::SYN_ACK);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &syn_ack),
            ConntrackResult::Allowed
        ));
        let ack = tcp_packet(HOST, 10000, VM, 22, TcpFlags::ACK);
        assert!(matches!(
            inspect_from_host(&mut tracker, &ack),
            ConntrackResult::Allowed
        ));

        let ConntrackResult::New(pending) = inspect_from_host(&mut tracker, &over_limit) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));
    }
}

#[cfg(test)]
mod test_support {
    use super::{Conntrack, ConntrackResult};
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};

    pub(super) const HOST: Ipv4Address = Ipv4Address::new(192, 168, 64, 1);
    pub(super) const VM: Ipv4Address = Ipv4Address::new(192, 168, 64, 2);

    pub(super) fn inspect_from_host(tracker: &mut Conntrack, bytes: &[u8]) -> ConntrackResult {
        let packet = Ipv4Packet::new_checked(bytes).unwrap();
        tracker.inspect_from_host(&packet)
    }

    pub(super) fn inspect_from_vm(tracker: &mut Conntrack, bytes: &[u8]) -> ConntrackResult {
        let packet = Ipv4Packet::new_checked(bytes).unwrap();
        tracker.inspect_from_vm(&packet)
    }

    #[derive(Clone, Copy)]
    pub(super) struct TcpFlags {
        syn: bool,
        ack: bool,
        rst: bool,
    }

    impl TcpFlags {
        pub(super) const SYN: Self = Self {
            syn: true,
            ack: false,
            rst: false,
        };
        pub(super) const SYN_ACK: Self = Self {
            syn: true,
            ack: true,
            rst: false,
        };
        pub(super) const ACK: Self = Self {
            syn: false,
            ack: true,
            rst: false,
        };
        pub(super) const RST: Self = Self {
            syn: false,
            ack: false,
            rst: true,
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

    fn ipv4_packet(
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
