use super::{Direction, Rule, Target};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use smoltcp::wire::Ipv4Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Block,
    Allow,
}

pub(crate) type Rules = PrefixMap<Ipv4Net, Vec<(Action, Rule)>>;

pub(crate) fn select_rules(
    rules: &Rules,
    address: Ipv4Address,
    direction: Direction,
) -> Option<&[(Action, Rule)]> {
    if rules.is_empty() {
        return None;
    }

    let mut prefix = Ipv4Net::from(address);
    loop {
        let (matched_prefix, matched_rules) = rules.get_lpm(&prefix)?;
        if matched_rules.iter().any(|(_, rule)| match rule {
            Rule::Stateless(_) => true,
            Rule::Stateful {
                direction: rule_direction,
                ..
            } => *rule_direction == direction,
        }) {
            return Some(matched_rules.as_slice());
        }
        prefix = matched_prefix.supernet()?;
    }
}

pub(crate) fn build_rules(host_address: Ipv4Address, allow: &[Rule], block: &[Rule]) -> Rules {
    let mut rules = PrefixMap::new();

    for &rule in allow {
        insert_rule(&mut rules, rule, Action::Allow, host_address);
    }

    for &rule in block {
        insert_rule(&mut rules, rule, Action::Block, host_address);
    }

    rules
}

pub(crate) fn rule_count(rules: &Rules) -> usize {
    rules.into_iter().map(|(_, rules)| rules.len()).sum()
}

pub(crate) fn has_stateful_rules(rules: &Rules) -> bool {
    rules.into_iter().any(|(_, rules)| {
        rules
            .iter()
            .any(|(_, rule)| matches!(rule, Rule::Stateful { .. }))
    })
}

fn insert_rule(rules: &mut Rules, rule: Rule, mut action: Action, host_address: Ipv4Address) {
    let prefix = match rule.target() {
        Target::Prefix(prefix) => prefix,
        Target::Host => host_address.into(),
    };
    let rule = match rule {
        Rule::Stateless(_) => Rule::Stateless(Target::Prefix(prefix)),
        Rule::Stateful { direction, .. } => Rule::Stateful {
            direction,
            target: Target::Prefix(prefix),
        },
    };

    let prefix_rules = rules.entry(prefix).or_default();

    // SECURITY: blocking rules must always take precedence
    // over allowing rules when prefixes are identical
    if let Some(existing) = prefix_rules
        .iter_mut()
        .find(|(_, existing_rule)| *existing_rule == rule)
    {
        if existing.0 == Action::Block {
            action = Action::Block;
        }
        *existing = (action, rule);
    } else {
        prefix_rules.push((action, rule));
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, has_stateful_rules, insert_rule, rule_count, select_rules};
    use crate::proxy::{Direction, Rule, Target};
    use ipnet::Ipv4Net;
    use prefix_trie::PrefixMap;
    use smoltcp::wire::Ipv4Address;
    use std::str::FromStr;

    #[test]
    fn test_policy_precedence() {
        let host = Ipv4Address::new(192, 168, 64, 1);
        let target = Ipv4Address::new(10, 0, 0, 1);
        let mut rules = PrefixMap::new();

        insert_rule(
            &mut rules,
            "0.0.0.0/0".parse().unwrap(),
            Action::Block,
            host,
        );
        assert!(!has_stateful_rules(&rules));

        insert_rule(
            &mut rules,
            "in 10.0.0.0/8".parse().unwrap(),
            Action::Allow,
            host,
        );
        assert!(has_stateful_rules(&rules));

        assert_eq!(
            select_rules(&rules, target, Direction::In),
            Some(
                &[(
                    Action::Allow,
                    Rule::Stateful {
                        direction: Direction::In,
                        target: Target::Prefix(Ipv4Net::from_str("10.0.0.0/8").unwrap()),
                    }
                )][..]
            )
        );
        assert_eq!(
            select_rules(&rules, target, Direction::Out),
            Some(&[(Action::Block, "0.0.0.0/0".parse().unwrap())][..])
        );

        insert_rule(
            &mut rules,
            "10.0.0.1/32".parse().unwrap(),
            Action::Allow,
            host,
        );
        assert_eq!(
            select_rules(&rules, target, Direction::Out).unwrap().len(),
            1
        );

        insert_rule(
            &mut rules,
            "out 10.0.0.1/32".parse().unwrap(),
            Action::Allow,
            host,
        );
        assert_eq!(
            select_rules(&rules, target, Direction::Out).unwrap().len(),
            2
        );
    }

    #[test]
    fn test_directional_rules_share_a_prefix() {
        let host = Ipv4Address::new(192, 168, 64, 1);
        let mut rules = PrefixMap::new();

        for (target, action) in [
            ("in @host", Action::Allow),
            ("out @host", Action::Allow),
            ("in @host", Action::Block),
        ] {
            insert_rule(&mut rules, target.parse().unwrap(), action, host);
        }

        assert_eq!(
            select_rules(&rules, host, Direction::In),
            Some(
                &[
                    (
                        Action::Block,
                        Rule::Stateful {
                            direction: Direction::In,
                            target: Target::Prefix(host.into()),
                        }
                    ),
                    (
                        Action::Allow,
                        Rule::Stateful {
                            direction: Direction::Out,
                            target: Target::Prefix(host.into()),
                        }
                    ),
                ][..]
            )
        );
        assert_eq!(rule_count(&rules), 2);
    }
}
