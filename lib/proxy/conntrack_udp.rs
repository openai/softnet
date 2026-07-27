use super::{
    Conntrack, ConntrackResult, Direction, Flow, FlowKey, FlowState, Initiator, PendingFlow,
    initiator, oriented_transport_key,
};
use coarsetime::{Duration, Instant};
use smoltcp::wire::{Ipv4Packet, UdpPacket};

const UNREPLIED_TIMEOUT: Duration = Duration::from_secs(30);
const REPLIED_TIMEOUT: Duration = Duration::from_secs(3 * 60);

#[derive(Clone, Copy, Debug)]
pub(super) struct State {
    replied: bool,
}

impl State {
    pub(super) fn timeout(self) -> Duration {
        if self.replied {
            REPLIED_TIMEOUT
        } else {
            UNREPLIED_TIMEOUT
        }
    }
}

impl Conntrack {
    pub(super) fn inspect_udp(
        &mut self,
        packet: &Ipv4Packet<&[u8]>,
        direction: Direction,
        now: Instant,
    ) -> ConntrackResult {
        let Ok(udp) = UdpPacket::new_checked(packet.payload()) else {
            return ConntrackResult::Denied;
        };
        if udp.src_port() == 0 || udp.dst_port() == 0 {
            return ConntrackResult::Denied;
        }

        let key = oriented_transport_key(
            packet,
            direction,
            |host_addr, host_port, vm_addr, vm_port| FlowKey::Udp {
                host_addr,
                host_port,
                vm_addr,
                vm_port,
            },
            udp.src_port(),
            udp.dst_port(),
        );

        if let Some(flow) = self.flows.get_mut(&key) {
            let FlowState::Udp(state) = &mut flow.state else {
                return ConntrackResult::Denied;
            };

            let is_reply = matches!(
                (flow.initiator, direction),
                (Initiator::Host, Direction::FromVm) | (Initiator::Vm, Direction::FromHost)
            );
            state.replied |= is_reply;
            flow.last_seen = now;
            return ConntrackResult::Allowed;
        }

        ConntrackResult::New(PendingFlow {
            key,
            flow: Flow {
                initiator: initiator(direction),
                state: FlowState::Udp(State { replied: false }),
                last_seen: now,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{HOST, VM, inspect_from_host, inspect_from_vm, udp_packet};
    use super::super::{Conntrack, ConntrackResult};

    #[test]
    fn udp_reply_requires_an_exact_host_request() {
        let mut tracker = Conntrack::new();

        let vm_datagram = udp_packet(VM, 5353, HOST, 50000);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &vm_datagram),
            ConntrackResult::New(_)
        ));

        let host_datagram = udp_packet(HOST, 50000, VM, 5353);
        let ConntrackResult::New(pending) = inspect_from_host(&mut tracker, &host_datagram) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));
        assert!(matches!(
            inspect_from_vm(&mut tracker, &vm_datagram),
            ConntrackResult::Allowed
        ));

        let wrong_vm_datagram = udp_packet(VM, 5353, HOST, 50001);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &wrong_vm_datagram),
            ConntrackResult::New(_)
        ));
    }

    #[test]
    fn explicitly_allowed_vm_udp_gets_only_its_reply() {
        let mut tracker = Conntrack::new();
        let vm_dns = udp_packet(VM, 53000, HOST, 53);
        let host_dns = udp_packet(HOST, 53, VM, 53000);

        let ConntrackResult::New(pending) = inspect_from_vm(&mut tracker, &vm_dns) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));
        assert!(matches!(
            inspect_from_host(&mut tracker, &host_dns),
            ConntrackResult::Allowed
        ));

        let unsolicited_host_udp = udp_packet(HOST, 53, VM, 53001);
        assert!(matches!(
            inspect_from_host(&mut tracker, &unsolicited_host_udp),
            ConntrackResult::New(_)
        ));
    }
}
