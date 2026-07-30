use super::{FlowDirection, FlowKey, FlowMatch, FlowTable};
use coarsetime::{Duration, Instant};
use smoltcp::wire::{Ipv4Address, Ipv4Packet, TcpPacket};

const SYN_TIMEOUT: Duration = Duration::from_secs(60);
const TCP_TIMEOUT: Duration = Duration::from_secs(5 * 60);

impl FlowTable {
    pub(super) fn inspect_tcp(
        &mut self,
        ipv4_pkt: &Ipv4Packet<&[u8]>,
        direction: FlowDirection,
        now: Instant,
    ) -> FlowMatch {
        let Ok(tcp) = TcpPacket::new_checked(ipv4_pkt.payload()) else {
            return FlowMatch::Denied;
        };
        if tcp.src_port() == 0 || tcp.dst_port() == 0 {
            return FlowMatch::Denied;
        }

        let key = FlowKey::tcp(
            direction,
            (ipv4_pkt.src_addr(), tcp.src_port()),
            (ipv4_pkt.dst_addr(), tcp.dst_port()),
        );

        // A bare SYN may be either a retransmission or a new connection reusing
        // the tuple in either direction. Always return it to policy, and do not
        // replace an existing permission until the candidate is committed.
        let is_initial_syn = tcp.syn() && !tcp.ack() && !tcp.fin() && !tcp.rst();

        if is_initial_syn {
            return FlowMatch::candidate(key, direction, now, SYN_TIMEOUT);
        }

        self.match_existing_flow(key, direction, now, TCP_TIMEOUT)
            .unwrap_or(FlowMatch::Untracked)
    }
}

impl FlowKey {
    fn tcp(direction: FlowDirection, src: (Ipv4Address, u16), dst: (Ipv4Address, u16)) -> Self {
        let ((host_addr, host_port), (vm_addr, vm_port)) = direction.host_vm_pair(src, dst);
        Self::Tcp {
            host_addr,
            host_port,
            vm_addr,
            vm_port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        HOST, TcpFlags, VM, inspect_from_host, inspect_from_vm, tcp_packet,
    };
    use super::super::{FlowMatch, FlowTable};

    fn admit_host_syn(tracker: &mut FlowTable) {
        let syn = tcp_packet(HOST, 49_152, VM, 22, TcpFlags::SYN);
        let FlowMatch::Candidate(pending) = inspect_from_host(tracker, &syn) else {
            panic!("expected a candidate");
        };
        assert!(tracker.commit(pending));
    }

    #[test]
    fn admitted_syn_creates_an_exact_reverse_permission() {
        let mut tracker = FlowTable::new();
        admit_host_syn(&mut tracker);
        let original_expiry = tracker.flows.values().next().unwrap().expires_at;

        let reply = tcp_packet(VM, 22, HOST, 49_152, TcpFlags::ACK);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &reply),
            FlowMatch::Allowed
        ));
        assert_eq!(
            tracker.flows.values().next().unwrap().expires_at,
            original_expiry,
            "return traffic must not refresh a tuple"
        );

        let initiator_data = tcp_packet(HOST, 49_152, VM, 22, TcpFlags::ACK);
        let FlowMatch::Candidate(pending) = inspect_from_host(&mut tracker, &initiator_data) else {
            panic!("expected an initiator candidate");
        };
        assert_eq!(
            tracker.flows.values().next().unwrap().expires_at,
            original_expiry,
            "inspection must not refresh a tuple before policy accepts it"
        );
        assert!(tracker.commit(pending));
        assert!(tracker.flows.values().next().unwrap().expires_at > original_expiry);
    }

    #[test]
    fn new_tuple_requires_a_clean_syn() {
        let mut tracker = FlowTable::new();

        for flags in [TcpFlags::ACK, TcpFlags::SYN_ACK] {
            let packet = tcp_packet(HOST, 49_152, VM, 22, flags);
            assert!(matches!(
                inspect_from_host(&mut tracker, &packet),
                FlowMatch::Untracked
            ));
        }

        let syn = tcp_packet(HOST, 49_152, VM, 22, TcpFlags::SYN);
        assert!(matches!(
            inspect_from_host(&mut tracker, &syn),
            FlowMatch::Candidate(_)
        ));
    }

    #[test]
    fn reply_requires_the_exact_tuple() {
        let mut tracker = FlowTable::new();
        admit_host_syn(&mut tracker);

        let wrong_port = tcp_packet(VM, 22, HOST, 49_153, TcpFlags::ACK);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &wrong_port),
            FlowMatch::Untracked
        ));
    }

    #[test]
    fn reverse_bare_syn_is_a_new_policy_candidate() {
        let mut tracker = FlowTable::new();
        admit_host_syn(&mut tracker);

        let reverse_syn = tcp_packet(VM, 22, HOST, 49_152, TcpFlags::SYN);
        let FlowMatch::Candidate(pending) = inspect_from_vm(&mut tracker, &reverse_syn) else {
            panic!("reverse SYN must return to policy");
        };

        // Inspection is provisional: a policy rejection leaves the admitted
        // flow untouched.
        let old_flow_reply = tcp_packet(VM, 22, HOST, 49_152, TcpFlags::ACK);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &old_flow_reply),
            FlowMatch::Allowed
        ));

        assert!(tracker.commit(pending));

        let reverse_reply = tcp_packet(HOST, 49_152, VM, 22, TcpFlags::SYN_ACK);
        assert!(matches!(
            inspect_from_host(&mut tracker, &reverse_reply),
            FlowMatch::Allowed
        ));
    }
}
