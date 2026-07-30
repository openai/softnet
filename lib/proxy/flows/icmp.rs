use super::{FlowDirection, FlowKey, FlowMatch, FlowTable};
use coarsetime::{Duration, Instant};
use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, Ipv4Address, Ipv4Packet};

const ECHO_TIMEOUT: Duration = Duration::from_secs(30);

impl FlowTable {
    pub(super) fn inspect_icmp(
        &mut self,
        ipv4_pkt: &Ipv4Packet<&[u8]>,
        direction: FlowDirection,
        now: Instant,
    ) -> FlowMatch {
        let Ok(icmp) = Icmpv4Packet::new_checked(ipv4_pkt.payload()) else {
            return FlowMatch::Denied;
        };
        if !icmp.verify_checksum() {
            return FlowMatch::Denied;
        }

        match (icmp.msg_type(), icmp.msg_code()) {
            (Icmpv4Message::EchoRequest, 0) => {
                self.inspect_echo(ipv4_pkt, direction, icmp.echo_ident(), true, now)
            }
            (Icmpv4Message::EchoReply, 0) => {
                self.inspect_echo(ipv4_pkt, direction, icmp.echo_ident(), false, now)
            }
            // Other ICMP messages follow normal source policy: treating errors that quote
            // tracked tuples as RELATED requires validation beyond this exact-tuple table
            //
            // Potential degradation of PMTU discovery and traceroute is an accepted tradeoff.
            _ => FlowMatch::Untracked,
        }
    }

    fn inspect_echo(
        &mut self,
        ipv4_pkt: &Ipv4Packet<&[u8]>,
        direction: FlowDirection,
        ident: u16,
        is_request: bool,
        now: Instant,
    ) -> FlowMatch {
        // We need to preserve the request direction so opposite-direction echo flows remain distinct
        let initiating_direction = if is_request {
            direction
        } else {
            direction.opposite()
        };

        let key = FlowKey::icmp_echo(
            ipv4_pkt.src_addr(),
            ipv4_pkt.dst_addr(),
            direction,
            initiating_direction,
            ident,
        );

        if let Some(matched) = self.match_existing_flow(key, direction, now, ECHO_TIMEOUT) {
            return matched;
        }

        if is_request {
            FlowMatch::candidate(key, initiating_direction, now, ECHO_TIMEOUT)
        } else {
            // Only replies matching an admitted request are tracked
            FlowMatch::Untracked
        }
    }
}

impl FlowKey {
    fn icmp_echo(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        direction: FlowDirection,
        initiating_direction: FlowDirection,
        ident: u16,
    ) -> Self {
        let (host_addr, vm_addr) = direction.host_vm_pair(src_addr, dst_addr);
        Self::IcmpEcho {
            host_addr,
            vm_addr,
            ident,
            initiating_direction,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{HOST, VM, inspect_from_host, inspect_from_vm, ipv4_packet};
    use super::super::{FlowMatch, FlowTable};
    use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Address};

    #[test]
    fn echo_request_and_reply_are_tracked_in_both_directions() {
        let mut tracker = FlowTable::new();
        let vm_request = echo_packet(VM, HOST, Icmpv4Message::EchoRequest, 7, 1);

        let FlowMatch::Candidate(pending) = inspect_from_vm(&mut tracker, &vm_request) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));

        let host_reply = echo_packet(HOST, VM, Icmpv4Message::EchoReply, 7, 1);
        assert!(matches!(
            inspect_from_host(&mut tracker, &host_reply),
            FlowMatch::Allowed
        ));

        let wrong_ident = echo_packet(HOST, VM, Icmpv4Message::EchoReply, 8, 1);
        assert!(matches!(
            inspect_from_host(&mut tracker, &wrong_ident),
            FlowMatch::Untracked
        ));

        // The opposite direction is a distinct flow even with the same identifier.
        let host_request = echo_packet(HOST, VM, Icmpv4Message::EchoRequest, 7, 1);
        let FlowMatch::Candidate(pending) = inspect_from_host(&mut tracker, &host_request) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));

        let vm_reply = echo_packet(VM, HOST, Icmpv4Message::EchoReply, 7, 1);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &vm_reply),
            FlowMatch::Allowed
        ));
    }

    #[test]
    fn invalid_echo_is_denied_and_unsolicited_echo_is_untracked() {
        let mut tracker = FlowTable::new();
        let unsolicited = echo_packet(HOST, VM, Icmpv4Message::EchoReply, 7, 1);
        assert!(matches!(
            inspect_from_host(&mut tracker, &unsolicited),
            FlowMatch::Untracked
        ));

        let mut wrong_code = echo_packet(HOST, VM, Icmpv4Message::EchoRequest, 7, 1);
        wrong_code[21] = 1;
        Icmpv4Packet::new_unchecked(&mut wrong_code[20..]).fill_checksum();
        assert!(matches!(
            inspect_from_host(&mut tracker, &wrong_code),
            FlowMatch::Untracked
        ));

        let mut bad_checksum = echo_packet(HOST, VM, Icmpv4Message::EchoRequest, 7, 1);
        bad_checksum[27] ^= 1;
        assert!(matches!(
            inspect_from_host(&mut tracker, &bad_checksum),
            FlowMatch::Denied
        ));
    }

    fn echo_packet(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        message: Icmpv4Message,
        ident: u16,
        sequence: u16,
    ) -> Vec<u8> {
        let mut bytes = ipv4_packet(src_addr, dst_addr, IpProtocol::Icmp, 8);
        let mut icmp = Icmpv4Packet::new_unchecked(&mut bytes[20..]);
        icmp.set_msg_type(message);
        icmp.set_msg_code(0);
        icmp.set_echo_ident(ident);
        icmp.set_echo_seq_no(sequence);
        icmp.fill_checksum();
        bytes
    }
}
