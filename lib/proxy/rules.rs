use super::{Direction, Filter, Protocol, Rule, Target};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};
use std::cmp::Reverse;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyDecision {
    Block,
    AllowStateless,
    AllowStateful,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Legacy,
    Stateful,
}

// Filters for one prefix, ordered from highest to lowest priority.
type FilterRules = Vec<(Filter, Action)>;

// Temporary map for merging rules with the same prefix, protocol, and port range.
type PendingRules = PrefixMap<Ipv4Net, HashMap<Filter, Action>>;

#[derive(Default)]
pub(crate) struct Rules {
    mode: Mode,
    inbound: PrefixMap<Ipv4Net, FilterRules>,
    outbound: PrefixMap<Ipv4Net, FilterRules>,
}

impl Rules {
    pub(crate) fn new(host_address: Ipv4Address, allow: &[Rule], block: &[Rule]) -> Self {
        // Preserve legacy behavior for bare-only policies. Once a directional rule
        // is present, compile the whole policy using directional semantics.
        let mode = if allow
            .iter()
            .chain(block)
            .any(|rule| matches!(rule, Rule::Stateful { .. }))
        {
            Mode::Stateful
        } else {
            Mode::Legacy
        };

        let mut inbound = PendingRules::new();
        let mut outbound = PendingRules::new();

        // SECURITY: blocking rules must always take precedence
        // over allowing rules when the rules are identical.
        for (rules, action) in [(allow, Action::Allow), (block, Action::Block)] {
            for &rule in rules {
                let (direction, target, filter) = match rule {
                    Rule::Stateless(target) => {
                        let filter = Filter::default();

                        // Bare rules apply in both directions in stateful mode
                        if mode == Mode::Stateful {
                            insert_filter(&mut inbound, target, filter, action, host_address);
                        }

                        (Direction::Out, target, filter)
                    }
                    Rule::Stateful {
                        direction,
                        target,
                        filter,
                    } => (direction, target, filter),
                };
                let entries = match direction {
                    Direction::In => &mut inbound,
                    Direction::Out => &mut outbound,
                };

                insert_filter(entries, target, filter, action, host_address);
            }
        }

        Self {
            mode,
            inbound: compile_rules(inbound),
            outbound: compile_rules(outbound),
        }
    }

    pub(crate) fn policy_decision(
        &self,
        ipv4_pkt: &Ipv4Packet<&[u8]>,
        direction: Direction,
    ) -> Option<PolicyDecision> {
        let address = match direction {
            Direction::In => ipv4_pkt.src_addr(),
            Direction::Out => ipv4_pkt.dst_addr(),
        };
        let action = self.select(
            address,
            direction,
            ipv4_pkt.next_header(),
            packet_ports(ipv4_pkt).map(|(_, destination)| destination),
        )?;

        match (action, self.mode) {
            (Action::Block, _) => Some(PolicyDecision::Block),
            (Action::Allow, Mode::Legacy) => Some(PolicyDecision::AllowStateless),
            (Action::Allow, Mode::Stateful) => Some(PolicyDecision::AllowStateful),
        }
    }

    pub(crate) fn is_stateful(&self, ipv4_pkt: &Ipv4Packet<&[u8]>, direction: Direction) -> bool {
        let address = match direction {
            Direction::In => ipv4_pkt.dst_addr(),
            Direction::Out => ipv4_pkt.src_addr(),
        };

        // A reply's destination port is the initiating packet's source port
        self.mode == Mode::Stateful
            && self
                .select(
                    address,
                    direction,
                    ipv4_pkt.next_header(),
                    packet_ports(ipv4_pkt).map(|(source, _)| source),
                )
                .is_some()
    }

    pub(crate) fn len(&self) -> usize {
        self.inbound
            .values()
            .chain(self.outbound.values())
            .map(Vec::len)
            .sum()
    }

    pub(crate) fn has_stateful(&self) -> bool {
        self.mode == Mode::Stateful
    }

    fn select(
        &self,
        address: Ipv4Address,
        direction: Direction,
        protocol: IpProtocol,
        destination_port: Option<u16>,
    ) -> Option<Action> {
        let entries = match direction {
            Direction::In => &self.inbound,
            Direction::Out => &self.outbound,
        };

        // Consider covering prefixes so a filter mismatch can fall back to a broader rule
        entries
            .cover(&Ipv4Net::from(address))
            .filter_map(|(prefix, filters)| {
                let (filter, action) = filter_action(filters, protocol, destination_port)?;

                Some((rule_priority(prefix.prefix_len(), filter, action), action))
            })
            .max_by_key(|(priority, _)| *priority)
            .map(|(_, action)| action)
    }
}

fn insert_filter(
    entries: &mut PendingRules,
    target: Target,
    filter: Filter,
    action: Action,
    host_address: Ipv4Address,
) {
    let prefix = match target {
        Target::Prefix(prefix) => prefix,
        Target::Host => host_address.into(),
    };

    entries.entry(prefix).or_default().insert(filter, action);
}

fn compile_rules(entries: PendingRules) -> PrefixMap<Ipv4Net, FilterRules> {
    entries
        .into_iter()
        .map(|(prefix, filters)| {
            let mut filters: Vec<_> = filters.into_iter().collect();

            // Sort once so packet matching can stop at the first compatible filter
            filters.sort_unstable_by_key(|(filter, action)| {
                Reverse(rule_priority(prefix.prefix_len(), filter, *action))
            });

            (prefix, filters)
        })
        .collect()
}

/// Returns the rule priority, shared by filter sorting and packet matching.
fn rule_priority(
    prefix_len: u8,
    filter: &Filter,
    action: Action,
) -> (bool, u8, bool, Reverse<u16>, bool) {
    (
        filter.destination_port_range.is_some(),
        prefix_len,
        filter.protocol.is_some(),
        Reverse(
            filter
                .destination_port_range
                .map_or(u16::MAX, |range| range.width()),
        ),
        action == Action::Block,
    )
}

fn filter_action(
    filters: &[(Filter, Action)],
    protocol: IpProtocol,
    destination_port: Option<u16>,
) -> Option<(&Filter, Action)> {
    let protocol = match protocol {
        IpProtocol::Tcp => Some(Protocol::Tcp),
        IpProtocol::Udp => Some(Protocol::Udp),
        IpProtocol::Icmp => Some(Protocol::Icmp),
        _ => None,
    };

    filters
        .iter()
        .find(|(filter, action)| {
            if filter.protocol.is_some() && filter.protocol != protocol {
                return false;
            }

            // Unknown TCP/UDP ports can match service blocks, but never service allows
            match filter.destination_port_range {
                None => true,
                Some(range) => match destination_port {
                    Some(port) => range.contains(port),
                    None => {
                        *action == Action::Block
                            && matches!(protocol, Some(Protocol::Tcp | Protocol::Udp))
                    }
                },
            }
        })
        .map(|(filter, action)| (filter, *action))
}

fn packet_ports(ipv4_pkt: &Ipv4Packet<&[u8]>) -> Option<(u16, u16)> {
    // Fragments cannot establish a complete transport tuple
    if ipv4_pkt.more_frags() || ipv4_pkt.frag_offset() != 0 {
        return None;
    }

    match ipv4_pkt.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(ipv4_pkt.payload()).ok()?;

            Some((tcp.src_port(), tcp.dst_port()))
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(ipv4_pkt.payload()).ok()?;

            Some((udp.src_port(), udp.dst_port()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyDecision, Rules};
    use crate::proxy::Direction;
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};

    const HOST: Ipv4Address = Ipv4Address::new(192, 168, 64, 1);
    const VM: Ipv4Address = Ipv4Address::new(192, 168, 64, 2);

    fn packet(source: Ipv4Address, destination: Ipv4Address) -> [u8; 20] {
        let mut bytes = [0; 20];
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(4);
        packet.set_header_len(20);
        packet.set_total_len(20);
        packet.set_next_header(IpProtocol::Icmp);
        packet.set_src_addr(source);
        packet.set_dst_addr(destination);

        bytes
    }

    fn policy_decision(
        rules: &Rules,
        source: Ipv4Address,
        destination: Ipv4Address,
        direction: Direction,
    ) -> Option<PolicyDecision> {
        let bytes = packet(source, destination);

        rules.policy_decision(&Ipv4Packet::new_unchecked(&bytes[..]), direction)
    }

    fn transport_packet(
        source: Ipv4Address,
        source_port: u16,
        destination: Ipv4Address,
        destination_port: u16,
        protocol: IpProtocol,
    ) -> Vec<u8> {
        let mut bytes = packet(source, destination).to_vec();
        bytes.resize(if protocol == IpProtocol::Tcp { 40 } else { 28 }, 0);
        let length = bytes.len() as u16;
        let mut ipv4 = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
        ipv4.set_total_len(length);
        ipv4.set_next_header(protocol);

        // Build complete transport headers so policy can inspect the destination port
        if protocol == IpProtocol::Tcp {
            let mut tcp = TcpPacket::new_unchecked(&mut bytes[20..]);
            tcp.set_src_port(source_port);
            tcp.set_dst_port(destination_port);
            tcp.set_header_len(20);
            tcp.set_syn(true);
        } else {
            let mut udp = UdpPacket::new_unchecked(&mut bytes[20..]);
            udp.set_src_port(source_port);
            udp.set_dst_port(destination_port);
            udp.set_len(8);
        }

        bytes
    }

    #[test]
    fn test_policy_precedence() {
        let target = Ipv4Address::new(10, 0, 0, 1);
        let block = ["0.0.0.0/0".parse().unwrap()];
        let rules = Rules::new(HOST, &["in 10.0.0.0/8".parse().unwrap()], &block);

        assert_eq!(
            policy_decision(&rules, target, VM, Direction::In),
            Some(PolicyDecision::AllowStateful)
        );
        assert_eq!(
            policy_decision(&rules, VM, target, Direction::Out),
            Some(PolicyDecision::Block)
        );

        let allow = ["in 10.0.0.0/8", "10.0.0.1/32"].map(|input| input.parse().unwrap());
        let rules = Rules::new(HOST, &allow, &block);

        assert_eq!(
            policy_decision(&rules, VM, target, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
    }

    #[test]
    fn test_directional_rules_at_same_prefix_are_independent() {
        let allow = ["in @host", "out @host"].map(|input| input.parse().unwrap());
        let block = ["in @host".parse().unwrap()];
        let rules = Rules::new(HOST, &allow, &block);

        assert_eq!(
            policy_decision(&rules, HOST, VM, Direction::In),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            policy_decision(&rules, VM, HOST, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_stateless_rules_are_outbound_only() {
        let target = Ipv4Address::new(10, 1, 2, 3);
        let rules = Rules::new(HOST, &[], &["10.0.0.0/8".parse().unwrap()]);

        assert!(policy_decision(&rules, target, VM, Direction::In).is_none());
        assert_eq!(
            policy_decision(&rules, VM, target, Direction::Out),
            Some(PolicyDecision::Block)
        );
    }

    #[test]
    fn test_inbound_selection_uses_more_specific_bare_rule() {
        let target = Ipv4Address::new(10, 1, 2, 3);
        let rules = Rules::new(
            HOST,
            &["10.1.0.0/16".parse().unwrap()],
            &["in 10.0.0.0/8".parse().unwrap()],
        );

        assert_eq!(
            policy_decision(&rules, target, VM, Direction::In),
            Some(PolicyDecision::AllowStateful)
        );
    }

    #[test]
    fn test_block_wins_over_allow_at_same_outbound_prefix() {
        let target = Ipv4Address::new(10, 1, 2, 3);

        for (allow, block) in [
            ("10.0.0.0/8", "out 10.0.0.0/8"),
            ("out 10.0.0.0/8", "10.0.0.0/8"),
        ] {
            let rules = Rules::new(HOST, &[allow.parse().unwrap()], &[block.parse().unwrap()]);

            assert_eq!(
                policy_decision(&rules, VM, target, Direction::Out),
                Some(PolicyDecision::Block)
            );
        }
    }

    #[test]
    fn test_directional_rule_makes_bare_rules_stateful() {
        let allow = "out @host".parse().unwrap();
        let block = "0.0.0.0/0".parse().unwrap();
        let rules = Rules::new(HOST, &[allow], &[block]);

        assert_eq!(rules.len(), 3);
        assert!(rules.has_stateful());
        assert_eq!(
            policy_decision(&rules, HOST, VM, Direction::In),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            policy_decision(&rules, VM, HOST, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
    }

    #[test]
    fn port_exception_opens_one_service_through_address_blocks() {
        let allow = [
            "out proto tcp 10.0.0.0/8 port 8443",
            "out proto tcp 10.0.0.0/8 port 53",
            "out proto udp 10.0.0.0/8 port 53",
            "out proto icmp 10.1.2.3/32",
        ]
        .map(|input| input.parse().unwrap());
        let block = ["10.1.2.3/32".parse().unwrap()];
        let rules = Rules::new(HOST, &allow, &block);
        let peer = Ipv4Address::new(10, 1, 2, 3);

        for (protocol, port, expected) in [
            (IpProtocol::Tcp, 8443, PolicyDecision::AllowStateful),
            (IpProtocol::Udp, 8443, PolicyDecision::Block),
            (IpProtocol::Tcp, 22, PolicyDecision::Block),
            (IpProtocol::Tcp, 53, PolicyDecision::AllowStateful),
            (IpProtocol::Udp, 53, PolicyDecision::AllowStateful),
        ] {
            let bytes = transport_packet(VM, 50_000, peer, port, protocol);
            let packet = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();

            assert_eq!(
                rules.policy_decision(&packet, Direction::Out),
                Some(expected),
                "{protocol:?} port {port}"
            );
        }

        assert_eq!(
            policy_decision(&rules, peer, VM, Direction::In),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            policy_decision(&rules, VM, peer, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
    }

    #[test]
    fn port_ranges_match_tcp_and_udp_inclusively() {
        let allow = [
            "out proto tcp @host port 8000:8100",
            "out proto udp @host port 8000:8100",
        ]
        .map(|input| input.parse().unwrap());
        let block = ["out 0.0.0.0/0".parse().unwrap()];
        let rules = Rules::new(HOST, &allow, &block);

        for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
            for (port, expected) in [
                (7999, PolicyDecision::Block),
                (8000, PolicyDecision::AllowStateful),
                (8050, PolicyDecision::AllowStateful),
                (8100, PolicyDecision::AllowStateful),
                (8101, PolicyDecision::Block),
            ] {
                let bytes = transport_packet(VM, 50_000, HOST, port, protocol);
                let packet = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();

                assert_eq!(
                    rules.policy_decision(&packet, Direction::Out),
                    Some(expected),
                    "{protocol:?} port {port}"
                );
            }
        }
    }

    #[test]
    fn full_port_range_does_not_allow_protocols_without_ports() {
        let allow = ["out proto udp @host port 1:65535".parse().unwrap()];
        let block = ["out 0.0.0.0/0".parse().unwrap()];
        let rules = Rules::new(HOST, &allow, &block);

        for port in [1, 65535] {
            let bytes = transport_packet(VM, 50_000, HOST, port, IpProtocol::Udp);
            let packet = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();

            assert_eq!(
                rules.policy_decision(&packet, Direction::Out),
                Some(PolicyDecision::AllowStateful)
            );
        }

        assert_eq!(
            policy_decision(&rules, VM, HOST, Direction::Out),
            Some(PolicyDecision::Block)
        );
    }

    #[test]
    fn overlapping_ranges_preserve_prefix_and_protocol_precedence() {
        let peer = Ipv4Address::new(10, 1, 2, 3);
        let bytes = transport_packet(VM, 50_000, peer, 8080, IpProtocol::Tcp);
        let packet = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();

        // Port, address and protocol specificity take precedence over range width
        for (allow, block, expected) in [
            (
                "out proto tcp 10.0.0.0/8 port 8070:8090",
                "out proto tcp 10.0.0.0/8 port 8000:9000",
                PolicyDecision::AllowStateful,
            ),
            (
                "out proto tcp 10.0.0.0/8 port 8000:8100",
                "out proto tcp 10.0.0.0/8 port 8050:8150",
                PolicyDecision::Block,
            ),
            (
                "out proto tcp 10.0.0.0/8 port 8080",
                "out proto tcp 10.1.0.0/16 port 8000:9000",
                PolicyDecision::Block,
            ),
            (
                "out proto tcp 10.0.0.0/8",
                "out proto tcp 10.0.0.0/8 port 8000:9000",
                PolicyDecision::Block,
            ),
            (
                "out proto tcp 10.0.0.0/8 port 8000:9000",
                "out 10.1.0.0/16",
                PolicyDecision::AllowStateful,
            ),
            (
                "out 10.0.0.0/8",
                "out proto tcp 10.0.0.0/8",
                PolicyDecision::Block,
            ),
        ] {
            let rules = Rules::new(HOST, &[allow.parse().unwrap()], &[block.parse().unwrap()]);

            assert_eq!(
                rules.policy_decision(&packet, Direction::Out),
                Some(expected),
                "allow {allow:?}, block {block:?}"
            );
        }
    }

    #[test]
    fn return_policy_matches_source_ports_within_ranges() {
        for direction in [Direction::In, Direction::Out] {
            let (source, destination) = match direction {
                Direction::In => (VM, HOST),
                Direction::Out => (HOST, VM),
            };
            let block = format!("{direction} proto udp @host port 40000:50000")
                .parse()
                .unwrap();
            let rules = Rules::new(HOST, &[], &[block]);

            // A reply's destination port comes from the initiating packet's source port
            for (source_port, destination_port, expected) in
                [(45_000, 8080, true), (8080, 45_000, false)]
            {
                let bytes = transport_packet(
                    source,
                    source_port,
                    destination,
                    destination_port,
                    IpProtocol::Udp,
                );
                let packet = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();

                assert_eq!(
                    rules.is_stateful(&packet, direction),
                    expected,
                    "{direction}: {source_port} -> {destination_port}"
                );
            }
        }
    }

    #[test]
    fn unknown_ports_cannot_bypass_service_blocks_or_satisfy_service_allows() {
        for (protocol_name, protocol) in [("tcp", IpProtocol::Tcp), ("udp", IpProtocol::Udp)] {
            let rule = format!("in proto {protocol_name} @host port 8000:8100")
                .parse()
                .unwrap();
            let allowing = Rules::new(HOST, &[rule], &[]);
            let blocking = Rules::new(HOST, &[], &[rule]);

            // Build each case explicitly so the missing transport information is apparent
            let bytes = transport_packet(HOST, 50_000, VM, 8080, protocol);
            let mut first_fragment = bytes.clone();
            Ipv4Packet::new_unchecked(first_fragment.as_mut_slice()).set_more_frags(true);

            let mut later_fragment = bytes.clone();
            Ipv4Packet::new_unchecked(later_fragment.as_mut_slice()).set_frag_offset(8);

            let mut truncated_header = bytes;
            truncated_header.truncate(24);
            Ipv4Packet::new_unchecked(truncated_header.as_mut_slice()).set_total_len(24);

            for (case, bytes) in [
                ("first fragment", first_fragment),
                ("later fragment", later_fragment),
                ("truncated header", truncated_header),
            ] {
                let packet = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();

                assert_eq!(
                    allowing.policy_decision(&packet, Direction::In),
                    None,
                    "{protocol_name}: {case}"
                );
                assert_eq!(
                    blocking.policy_decision(&packet, Direction::In),
                    Some(PolicyDecision::Block),
                    "{protocol_name}: {case}"
                );
            }

            // A TCP or UDP block does not restrict unrelated IP protocols
            assert_eq!(policy_decision(&blocking, HOST, VM, Direction::In), None);
        }
    }
}
