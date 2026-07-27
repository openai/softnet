use super::{
    Conntrack, ConntrackResult, Direction, Flow, FlowKey, FlowState, PendingFlow, initiator,
    oriented_transport_key,
};
use coarsetime::{Duration, Instant};
use smoltcp::wire::{Ipv4Packet, TcpPacket};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const ESTABLISHED_TIMEOUT: Duration = Duration::from_secs(5 * 24 * 60 * 60);
const CLOSING_TIMEOUT: Duration = Duration::from_secs(2 * 60);

#[derive(Clone, Copy, Debug)]
pub(super) enum State {
    SynSent,
    SynReceived,
    Established,
    Closing { host_fin: bool, vm_fin: bool },
}

impl State {
    pub(super) fn timeout(self) -> Duration {
        match self {
            Self::SynSent | Self::SynReceived => HANDSHAKE_TIMEOUT,
            Self::Established => ESTABLISHED_TIMEOUT,
            Self::Closing { .. } => CLOSING_TIMEOUT,
        }
    }
}

impl Conntrack {
    pub(super) fn inspect_tcp(
        &mut self,
        packet: &Ipv4Packet<&[u8]>,
        direction: Direction,
        now: Instant,
    ) -> ConntrackResult {
        let Ok(tcp) = TcpPacket::new_checked(packet.payload()) else {
            return ConntrackResult::Denied;
        };
        if tcp.src_port() == 0 || tcp.dst_port() == 0 {
            return ConntrackResult::Denied;
        }

        let key = oriented_transport_key(
            packet,
            direction,
            |host_addr, host_port, vm_addr, vm_port| FlowKey::Tcp {
                host_addr,
                host_port,
                vm_addr,
                vm_port,
            },
            tcp.src_port(),
            tcp.dst_port(),
        );

        if let Some(flow) = self.flows.get_mut(&key) {
            let from_initiator = matches!(
                (flow.initiator, direction),
                (super::Initiator::Host, Direction::FromHost)
                    | (super::Initiator::Vm, Direction::FromVm)
            );
            let FlowState::Tcp(state) = &mut flow.state else {
                return ConntrackResult::Denied;
            };

            if tcp.rst() {
                self.flows.remove(&key);
                return ConntrackResult::Allowed;
            }

            let allowed = match *state {
                State::SynSent if from_initiator => is_initial_syn(&tcp),
                State::SynSent => {
                    if tcp.syn() && tcp.ack() && !tcp.fin() {
                        *state = State::SynReceived;
                        true
                    } else {
                        false
                    }
                }
                State::SynReceived if from_initiator => {
                    if is_initial_syn(&tcp) {
                        true
                    } else if tcp.ack() && !tcp.syn() {
                        *state = if tcp.fin() {
                            State::Closing {
                                host_fin: matches!(direction, Direction::FromHost),
                                vm_fin: matches!(direction, Direction::FromVm),
                            }
                        } else {
                            State::Established
                        };
                        true
                    } else {
                        false
                    }
                }
                State::SynReceived => tcp.syn() && tcp.ack() && !tcp.fin(),
                State::Established | State::Closing { .. }
                    if is_initial_syn(&tcp) && !from_initiator =>
                {
                    false
                }
                State::Established | State::Closing { .. } if is_initial_syn(&tcp) => {
                    *state = State::SynSent;
                    true
                }
                State::Established if tcp.fin() => {
                    *state = State::Closing {
                        host_fin: matches!(direction, Direction::FromHost),
                        vm_fin: matches!(direction, Direction::FromVm),
                    };
                    true
                }
                State::Closing { .. } if tcp.fin() => {
                    if let State::Closing { host_fin, vm_fin } = state {
                        match direction {
                            Direction::FromHost => *host_fin = true,
                            Direction::FromVm => *vm_fin = true,
                        }
                    }
                    true
                }
                _ => true,
            };

            if allowed {
                flow.last_seen = now;
            }
            return if allowed {
                ConntrackResult::Allowed
            } else {
                ConntrackResult::Denied
            };
        }

        if !is_initial_syn(&tcp) {
            return ConntrackResult::Denied;
        }

        ConntrackResult::New(PendingFlow {
            key,
            flow: Flow {
                initiator: initiator(direction),
                state: FlowState::Tcp(State::SynSent),
                last_seen: now,
            },
        })
    }
}

fn is_initial_syn(tcp: &TcpPacket<&[u8]>) -> bool {
    tcp.syn() && !tcp.ack() && !tcp.fin() && !tcp.rst()
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        HOST, TcpFlags, VM, inspect_from_host, inspect_from_vm, tcp_packet,
    };
    use super::super::{Conntrack, ConntrackResult};

    #[test]
    fn tcp_flows_are_oriented() {
        let mut tracker = Conntrack::new();

        let vm_syn = tcp_packet(VM, 22, HOST, 49152, TcpFlags::SYN);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &vm_syn),
            ConntrackResult::New(_)
        ));

        let host_syn = tcp_packet(HOST, 49152, VM, 22, TcpFlags::SYN);
        let ConntrackResult::New(pending) = inspect_from_host(&mut tracker, &host_syn) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));

        let premature_vm_ack = tcp_packet(VM, 22, HOST, 49152, TcpFlags::ACK);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &premature_vm_ack),
            ConntrackResult::Denied
        ));

        let wrong_vm_reply = tcp_packet(VM, 22, HOST, 49153, TcpFlags::SYN_ACK);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &wrong_vm_reply),
            ConntrackResult::Denied
        ));

        let vm_syn_ack = tcp_packet(VM, 22, HOST, 49152, TcpFlags::SYN_ACK);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &vm_syn_ack),
            ConntrackResult::Allowed
        ));

        let premature_vm_ack = tcp_packet(VM, 22, HOST, 49152, TcpFlags::ACK);
        assert!(matches!(
            inspect_from_vm(&mut tracker, &premature_vm_ack),
            ConntrackResult::Denied
        ));

        let host_ack = tcp_packet(HOST, 49152, VM, 22, TcpFlags::ACK);
        assert!(matches!(
            inspect_from_host(&mut tracker, &host_ack),
            ConntrackResult::Allowed
        ));

        assert!(matches!(
            inspect_from_vm(&mut tracker, &premature_vm_ack),
            ConntrackResult::Allowed
        ));
    }

    #[test]
    fn vm_can_initiate_tcp() {
        let mut tracker = Conntrack::new();
        let vm_syn = tcp_packet(VM, 49152, HOST, 22, TcpFlags::SYN);
        let host_syn_ack = tcp_packet(HOST, 22, VM, 49152, TcpFlags::SYN_ACK);
        let vm_ack = tcp_packet(VM, 49152, HOST, 22, TcpFlags::ACK);

        let ConntrackResult::New(pending) = inspect_from_vm(&mut tracker, &vm_syn) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));
        assert!(matches!(
            inspect_from_host(&mut tracker, &host_syn_ack),
            ConntrackResult::Allowed
        ));
        assert!(matches!(
            inspect_from_vm(&mut tracker, &vm_ack),
            ConntrackResult::Allowed
        ));
    }

    #[test]
    fn tcp_rst_removes_permission() {
        let mut tracker = Conntrack::new();
        let host_syn = tcp_packet(HOST, 49152, VM, 22, TcpFlags::SYN);
        let vm_rst = tcp_packet(VM, 22, HOST, 49152, TcpFlags::RST);
        let vm_ack = tcp_packet(VM, 22, HOST, 49152, TcpFlags::ACK);

        let ConntrackResult::New(pending) = inspect_from_host(&mut tracker, &host_syn) else {
            panic!("expected a new flow");
        };
        assert!(tracker.commit(pending));
        assert!(matches!(
            inspect_from_vm(&mut tracker, &vm_rst),
            ConntrackResult::Allowed
        ));
        assert!(matches!(
            inspect_from_vm(&mut tracker, &vm_ack),
            ConntrackResult::Denied
        ));
    }
}
