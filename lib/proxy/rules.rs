use super::{Direction, Ports, Rule, Target};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use smoltcp::wire::Ipv4Address;

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

/// A rule with ports, matched by a linear scan since policies have few of them.
#[derive(Debug, Clone, Copy)]
struct PortEntry {
    prefix: Ipv4Net,
    ports: Ports,
    action: Action,
}

#[derive(Default)]
pub(crate) struct Rules {
    mode: Mode,
    inbound: PrefixMap<Ipv4Net, Action>,
    outbound: PrefixMap<Ipv4Net, Action>,
    // Rules with ports take precedence over rules without them
    inbound_ports: Vec<PortEntry>,
    outbound_ports: Vec<PortEntry>,
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

        let mut rules = Self {
            mode,
            ..Self::default()
        };

        for &rule in allow {
            rules.insert(rule, Action::Allow, host_address);
        }

        // SECURITY: blocking rules must always take precedence
        // over allowing rules when the rules are identical.
        for &rule in block {
            rules.insert(rule, Action::Block, host_address);
        }

        rules
    }

    /// `port` is the remote side's TCP or UDP port, when the packet has one.
    pub(crate) fn policy_decision(
        &self,
        address: Ipv4Address,
        port: Option<u16>,
        direction: Direction,
    ) -> Option<PolicyDecision> {
        match (self.select(address, port, direction)?, self.mode) {
            (Action::Block, _) => Some(PolicyDecision::Block),
            (Action::Allow, Mode::Legacy) => Some(PolicyDecision::AllowStateless),
            (Action::Allow, Mode::Stateful) => Some(PolicyDecision::AllowStateful),
        }
    }

    pub(crate) fn is_stateful(
        &self,
        address: Ipv4Address,
        port: Option<u16>,
        direction: Direction,
    ) -> bool {
        self.mode == Mode::Stateful && self.select(address, port, direction).is_some()
    }

    pub(crate) fn len(&self) -> usize {
        self.inbound.len()
            + self.outbound.len()
            + self.inbound_ports.len()
            + self.outbound_ports.len()
    }

    pub(crate) fn has_stateful(&self) -> bool {
        self.mode == Mode::Stateful
    }

    fn select(
        &self,
        address: Ipv4Address,
        port: Option<u16>,
        direction: Direction,
    ) -> Option<Action> {
        let (entries, port_entries) = match direction {
            Direction::In => (&self.inbound, &self.inbound_ports),
            Direction::Out => (&self.outbound, &self.outbound_ports),
        };

        if let Some(port) = port {
            // The longest prefix match wins, and blocking wins a tie
            let selected = port_entries
                .iter()
                .filter(|entry| entry.prefix.contains(&address) && entry.ports.contains(port))
                .max_by_key(|entry| (entry.prefix.prefix_len(), entry.action == Action::Block));

            if let Some(entry) = selected {
                return Some(entry.action);
            }
        }

        entries
            .get_lpm(&Ipv4Net::from(address))
            .map(|(_, action)| *action)
    }

    fn insert(&mut self, rule: Rule, action: Action, host_address: Ipv4Address) {
        match rule {
            Rule::Stateless(target, ports) => {
                // Bare rules apply in both directions in stateful mode
                if self.mode == Mode::Stateful {
                    self.insert_direction(Direction::In, target, ports, action, host_address);
                }

                self.insert_direction(Direction::Out, target, ports, action, host_address);
            }
            Rule::Stateful {
                direction,
                target,
                ports,
            } => {
                self.insert_direction(direction, target, ports, action, host_address);
            }
        }
    }

    fn insert_direction(
        &mut self,
        direction: Direction,
        target: Target,
        ports: Option<Ports>,
        action: Action,
        host_address: Ipv4Address,
    ) {
        let prefix = match target {
            Target::Prefix(prefix) => prefix,
            Target::Host => host_address.into(),
        };

        if let Some(ports) = ports {
            let port_entries = match direction {
                Direction::In => &mut self.inbound_ports,
                Direction::Out => &mut self.outbound_ports,
            };

            // Replace identical rules like the prefix map does, so blocking rules inserted last win
            match port_entries
                .iter_mut()
                .find(|entry| entry.prefix == prefix && entry.ports == ports)
            {
                Some(entry) => entry.action = action,
                None => port_entries.push(PortEntry {
                    prefix,
                    ports,
                    action,
                }),
            }

            return;
        }

        let entries = match direction {
            Direction::In => &mut self.inbound,
            Direction::Out => &mut self.outbound,
        };

        entries.insert(prefix, action);
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Mode, PolicyDecision, Rules};
    use crate::proxy::Direction;
    use smoltcp::wire::Ipv4Address;

    const HOST: Ipv4Address = Ipv4Address::new(192, 168, 64, 1);

    fn stateful_rules() -> Rules {
        Rules {
            mode: Mode::Stateful,
            ..Rules::default()
        }
    }

    #[test]
    fn test_policy_precedence() {
        let target = Ipv4Address::new(10, 0, 0, 1);
        let mut rules = stateful_rules();

        rules.insert("0.0.0.0/0".parse().unwrap(), Action::Block, HOST);
        rules.insert("in 10.0.0.0/8".parse().unwrap(), Action::Allow, HOST);

        assert_eq!(
            rules.policy_decision(target, None, Direction::In),
            Some(PolicyDecision::AllowStateful)
        );
        assert_eq!(
            rules.policy_decision(target, None, Direction::Out),
            Some(PolicyDecision::Block)
        );

        rules.insert("10.0.0.1/32".parse().unwrap(), Action::Allow, HOST);
        assert_eq!(
            rules.policy_decision(target, None, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
    }

    #[test]
    fn test_directional_rules_at_same_prefix_are_independent() {
        let mut rules = stateful_rules();

        for (target, action) in [
            ("in @host", Action::Allow),
            ("out @host", Action::Allow),
            ("in @host", Action::Block),
        ] {
            rules.insert(target.parse().unwrap(), action, HOST);
        }

        assert_eq!(
            rules.policy_decision(HOST, None, Direction::In),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            rules.policy_decision(HOST, None, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_stateless_rules_are_outbound_only() {
        let target = Ipv4Address::new(10, 1, 2, 3);
        let mut rules = Rules::default();

        rules.insert("10.0.0.0/8".parse().unwrap(), Action::Block, HOST);

        assert!(rules.policy_decision(target, None, Direction::In).is_none());
        assert_eq!(
            rules.policy_decision(target, None, Direction::Out),
            Some(PolicyDecision::Block)
        );
    }

    #[test]
    fn test_inbound_selection_uses_more_specific_bare_rule() {
        let target = Ipv4Address::new(10, 1, 2, 3);
        let mut rules = stateful_rules();

        rules.insert("10.1.0.0/16".parse().unwrap(), Action::Allow, HOST);
        rules.insert("in 10.0.0.0/8".parse().unwrap(), Action::Block, HOST);

        assert_eq!(
            rules.policy_decision(target, None, Direction::In),
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
            let mut rules = stateful_rules();
            rules.insert(allow.parse().unwrap(), Action::Allow, HOST);
            rules.insert(block.parse().unwrap(), Action::Block, HOST);

            assert_eq!(
                rules.policy_decision(target, None, Direction::Out),
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
            rules.policy_decision(HOST, None, Direction::In),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            rules.policy_decision(HOST, None, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
    }

    #[test]
    fn test_return_tracking_applies_to_all_rules_in_stateful_mode() {
        let stateful_target = Ipv4Address::new(10, 1, 2, 3);
        let stateless_target = Ipv4Address::new(192, 0, 2, 1);
        let mut rules = stateful_rules();

        rules.insert("0.0.0.0/0".parse().unwrap(), Action::Block, HOST);
        rules.insert("out 10.0.0.0/8".parse().unwrap(), Action::Block, HOST);

        assert!(rules.is_stateful(stateful_target, None, Direction::Out));
        assert!(rules.is_stateful(stateless_target, None, Direction::Out));
        assert!(rules.is_stateful(stateful_target, None, Direction::In));

        rules.insert("10.0.0.0/8".parse().unwrap(), Action::Allow, HOST);
        assert!(rules.is_stateful(stateful_target, None, Direction::Out));
    }

    #[test]
    fn test_port_rule_opens_one_port_through_a_private_block() {
        let server = Ipv4Address::new(192, 168, 0, 10);
        let rules = Rules::new(
            HOST,
            &["192.168.0.10/32:8444".parse().unwrap()],
            &["192.168.0.0/16".parse().unwrap()],
        );

        assert_eq!(
            rules.policy_decision(server, Some(8444), Direction::Out),
            Some(PolicyDecision::AllowStateless)
        );
        for port in [Some(22), Some(8443), Some(8445), None] {
            assert_eq!(
                rules.policy_decision(server, port, Direction::Out),
                Some(PolicyDecision::Block),
                "port {port:?}"
            );
        }
        assert_eq!(
            rules.policy_decision(Ipv4Address::new(192, 168, 0, 1), Some(8444), Direction::Out),
            Some(PolicyDecision::Block)
        );
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_port_rule_outranks_a_longer_rule_without_ports() {
        let server = Ipv4Address::new(192, 168, 0, 10);
        let rules = Rules::new(
            HOST,
            &["192.168.0.0/24:8444".parse().unwrap()],
            &["192.168.0.10/32".parse().unwrap()],
        );

        assert_eq!(
            rules.policy_decision(server, Some(8444), Direction::Out),
            Some(PolicyDecision::AllowStateless)
        );
        assert_eq!(
            rules.policy_decision(server, Some(22), Direction::Out),
            Some(PolicyDecision::Block)
        );
    }

    #[test]
    fn test_port_rules_longest_prefix_then_block_wins() {
        let server = Ipv4Address::new(10, 1, 2, 3);
        let rules = Rules::new(
            HOST,
            &[
                "10.0.0.0/8:8000-9000".parse().unwrap(),
                "10.1.2.3/32:8444".parse().unwrap(),
            ],
            &[
                "10.1.0.0/16:8000-9000".parse().unwrap(),
                "10.1.2.3/32:8444".parse().unwrap(),
            ],
        );

        // /32 allow and /32 block on the same port: block
        assert_eq!(
            rules.policy_decision(server, Some(8444), Direction::Out),
            Some(PolicyDecision::Block)
        );
        // /16 block beats /8 allow
        assert_eq!(
            rules.policy_decision(server, Some(8500), Direction::Out),
            Some(PolicyDecision::Block)
        );
        // Only the /8 allow covers this address
        assert_eq!(
            rules.policy_decision(Ipv4Address::new(10, 9, 9, 9), Some(8500), Direction::Out),
            Some(PolicyDecision::AllowStateless)
        );
    }

    #[test]
    fn test_port_rules_follow_direction_in_stateful_mode() {
        let peer = Ipv4Address::new(10, 1, 2, 3);
        let rules = Rules::new(
            HOST,
            &["out 10.1.2.3/32:443".parse().unwrap()],
            &["10.0.0.0/8".parse().unwrap()],
        );

        assert_eq!(
            rules.policy_decision(peer, Some(443), Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
        assert_eq!(
            rules.policy_decision(peer, Some(443), Direction::In),
            Some(PolicyDecision::Block)
        );
        assert!(rules.is_stateful(peer, Some(443), Direction::Out));
    }
}
