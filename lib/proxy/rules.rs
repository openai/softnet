use super::{Direction, Rule, Target};
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

#[derive(Default)]
pub(crate) struct Rules {
    mode: Mode,
    inbound: PrefixMap<Ipv4Net, Action>,
    outbound: PrefixMap<Ipv4Net, Action>,
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

    pub(crate) fn policy_decision(
        &self,
        address: Ipv4Address,
        direction: Direction,
    ) -> Option<PolicyDecision> {
        match (self.select(address, direction)?, self.mode) {
            (Action::Block, _) => Some(PolicyDecision::Block),
            (Action::Allow, Mode::Legacy) => Some(PolicyDecision::AllowStateless),
            (Action::Allow, Mode::Stateful) => Some(PolicyDecision::AllowStateful),
        }
    }

    pub(crate) fn is_stateful(&self, address: Ipv4Address, direction: Direction) -> bool {
        self.mode == Mode::Stateful && self.select(address, direction).is_some()
    }

    pub(crate) fn len(&self) -> usize {
        self.inbound.len() + self.outbound.len()
    }

    pub(crate) fn has_stateful(&self) -> bool {
        self.mode == Mode::Stateful
    }

    fn select(&self, address: Ipv4Address, direction: Direction) -> Option<Action> {
        let entries = match direction {
            Direction::In => &self.inbound,
            Direction::Out => &self.outbound,
        };

        entries
            .get_lpm(&Ipv4Net::from(address))
            .map(|(_, action)| *action)
    }

    fn insert(&mut self, rule: Rule, action: Action, host_address: Ipv4Address) {
        match rule {
            Rule::Stateless(target) => {
                // Bare rules apply in both directions in stateful mode
                if self.mode == Mode::Stateful {
                    self.insert_direction(Direction::In, target, action, host_address);
                }

                self.insert_direction(Direction::Out, target, action, host_address);
            }
            Rule::Stateful { direction, target } => {
                self.insert_direction(direction, target, action, host_address);
            }
        }
    }

    fn insert_direction(
        &mut self,
        direction: Direction,
        target: Target,
        action: Action,
        host_address: Ipv4Address,
    ) {
        let prefix = match target {
            Target::Prefix(prefix) => prefix,
            Target::Host => host_address.into(),
        };
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
            rules.policy_decision(target, Direction::In),
            Some(PolicyDecision::AllowStateful)
        );
        assert_eq!(
            rules.policy_decision(target, Direction::Out),
            Some(PolicyDecision::Block)
        );

        rules.insert("10.0.0.1/32".parse().unwrap(), Action::Allow, HOST);
        assert_eq!(
            rules.policy_decision(target, Direction::Out),
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
            rules.policy_decision(HOST, Direction::In),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            rules.policy_decision(HOST, Direction::Out),
            Some(PolicyDecision::AllowStateful)
        );
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_stateless_rules_are_outbound_only() {
        let target = Ipv4Address::new(10, 1, 2, 3);
        let mut rules = Rules::default();

        rules.insert("10.0.0.0/8".parse().unwrap(), Action::Block, HOST);

        assert!(rules.policy_decision(target, Direction::In).is_none());
        assert_eq!(
            rules.policy_decision(target, Direction::Out),
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
            rules.policy_decision(target, Direction::In),
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
                rules.policy_decision(target, Direction::Out),
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
            rules.policy_decision(HOST, Direction::In),
            Some(PolicyDecision::Block)
        );
        assert_eq!(
            rules.policy_decision(HOST, Direction::Out),
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

        assert!(rules.is_stateful(stateful_target, Direction::Out));
        assert!(rules.is_stateful(stateless_target, Direction::Out));
        assert!(rules.is_stateful(stateful_target, Direction::In));

        rules.insert("10.0.0.0/8".parse().unwrap(), Action::Allow, HOST);
        assert!(rules.is_stateful(stateful_target, Direction::Out));
    }
}
