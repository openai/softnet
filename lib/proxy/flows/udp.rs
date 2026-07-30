use super::{FlowDirection, FlowKey, FlowMatch, FlowTable};
use coarsetime::{Duration, Instant};
use smoltcp::wire::{Ipv4Address, Ipv4Packet, UdpPacket};

const UDP_TIMEOUT: Duration = Duration::from_secs(30);

impl FlowTable {
    pub(super) fn inspect_udp(
        &mut self,
        ipv4_pkt: &Ipv4Packet<&[u8]>,
        direction: FlowDirection,
        now: Instant,
    ) -> FlowMatch {
        let Ok(udp) = UdpPacket::new_checked(ipv4_pkt.payload()) else {
            return FlowMatch::Denied;
        };
        if udp.dst_port() == 0 {
            return FlowMatch::Denied;
        }

        // Deliberate policy, not merely a packet-format validation:
        // RFC 8085, §5.1 says UDP senders SHOULD NOT use source port zero.
        //
        // We enforce this recommendation to retain source-port entropy
        // and protection against off-path packet injection.
        if udp.src_port() == 0 {
            return FlowMatch::Denied;
        }

        let key = FlowKey::udp(
            direction,
            (ipv4_pkt.src_addr(), udp.src_port()),
            (ipv4_pkt.dst_addr(), udp.dst_port()),
        );

        if let Some(matched) = self.match_existing_flow(key, direction, now, UDP_TIMEOUT) {
            return matched;
        }

        FlowMatch::candidate(key, direction, now, UDP_TIMEOUT)
    }
}

impl FlowKey {
    fn udp(direction: FlowDirection, src: (Ipv4Address, u16), dst: (Ipv4Address, u16)) -> Self {
        let ((host_addr, host_port), (vm_addr, vm_port)) = direction.host_vm_pair(src, dst);
        Self::Udp {
            host_addr,
            host_port,
            vm_addr,
            vm_port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{HOST, VM, inspect_from_host, inspect_from_vm, udp_packet};
    use super::super::{FlowMatch, FlowTable};

    #[test]
    fn rejects_zero_source_port_per_rfc_8085() {
        let mut tracker = FlowTable::new();
        let datagram = udp_packet(HOST, 0, VM, 5353);

        assert!(matches!(
            inspect_from_host(&mut tracker, &datagram),
            FlowMatch::Denied
        ));
    }

    #[test]
    fn udp_reply_requires_an_exact_admitted_request() {
        let mut tracker = FlowTable::new();
        let request = udp_packet(HOST, 50_000, VM, 5353);
        let reply = udp_packet(VM, 5353, HOST, 50_000);

        assert!(matches!(
            inspect_from_vm(&mut tracker, &reply),
            FlowMatch::Candidate(_)
        ));

        let FlowMatch::Candidate(pending) = inspect_from_host(&mut tracker, &request) else {
            panic!("expected a candidate");
        };
        assert!(tracker.commit(pending));
        assert!(matches!(
            inspect_from_vm(&mut tracker, &reply),
            FlowMatch::Allowed
        ));
    }
}
