use ipnet::Ipv4Net;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Stateless(Target),
    Stateful {
        direction: Direction,
        target: Target,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Prefix(Ipv4Net),
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Rule {
    pub(super) fn target(self) -> Target {
        match self {
            Rule::Stateless(target) => target,
            Rule::Stateful { target, .. } => target,
        }
    }

    pub(super) fn normalized(self) -> Self {
        match self {
            Rule::Stateless(target) => Rule::Stateless(target.normalized()),
            Rule::Stateful { direction, target } => Rule::Stateful {
                direction,
                target: target.normalized(),
            },
        }
    }
}

impl FromStr for Rule {
    type Err = ipnet::AddrParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (direction, target) = if let Some(target) = input.strip_prefix("in ") {
            (Direction::In, target)
        } else if let Some(target) = input.strip_prefix("out ") {
            (Direction::Out, target)
        } else {
            return input.parse().map(Rule::Stateless);
        };

        let target = target.trim_start_matches(' ').parse()?;
        Ok(Rule::Stateful { direction, target })
    }
}

impl Display for Rule {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Rule::Stateless(target) => Display::fmt(target, formatter),
            Rule::Stateful { direction, target } => match direction {
                Direction::In => write!(formatter, "in {target}"),
                Direction::Out => write!(formatter, "out {target}"),
            },
        }
    }
}

impl Target {
    fn normalized(self) -> Self {
        match self {
            Target::Prefix(prefix) => Target::Prefix(prefix.trunc()),
            Target::Host => Target::Host,
        }
    }
}

impl FromStr for Target {
    type Err = ipnet::AddrParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input == "@host" {
            Ok(Target::Host)
        } else {
            input.parse().map(Target::Prefix)
        }
    }
}

impl Display for Target {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Target::Prefix(prefix) => Display::fmt(prefix, formatter),
            Target::Host => formatter.write_str("@host"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Direction, Rule, Target};
    use ipnet::Ipv4Net;
    use std::str::FromStr;

    #[test]
    fn parses_stateless_target() {
        assert_eq!(
            "@host".parse::<Rule>().unwrap(),
            Rule::Stateless(Target::Host)
        );
    }

    #[test]
    fn parses_stateful_directions() {
        let private_network = Target::Prefix(Ipv4Net::from_str("10.0.0.0/8").unwrap());

        assert_eq!(
            "in   @host".parse::<Rule>().unwrap(),
            Rule::Stateful {
                direction: Direction::In,
                target: Target::Host,
            }
        );
        assert_eq!(
            "out 10.0.0.0/8".parse::<Rule>().unwrap(),
            Rule::Stateful {
                direction: Direction::Out,
                target: private_network,
            }
        );
    }

    #[test]
    fn displays_normalized_rules() {
        assert_eq!(
            "in 10.1.2.3/8"
                .parse::<Rule>()
                .unwrap()
                .normalized()
                .to_string(),
            "in 10.0.0.0/8"
        );
        assert_eq!(
            "@host".parse::<Rule>().unwrap().normalized().to_string(),
            "@host"
        );
    }

    #[test]
    fn rejects_invalid_rules() {
        for input in [
            "",
            "from @host",
            "in",
            "out",
            "in from @host",
            "out to @host",
            "infrom @host",
            " in @host",
            "in @host ",
            "in\t@host",
        ] {
            assert!(input.parse::<Rule>().is_err(), "{input:?} should fail");
        }
    }
}
