use ipnet::Ipv4Net;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Stateless(Target, Option<Ports>),
    Stateful {
        direction: Direction,
        target: Target,
        ports: Option<Ports>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Prefix(Ipv4Net),
    Host,
}

/// An inclusive range of TCP and UDP ports on the target's side of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    first: u16,
    last: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRuleError;

impl Display for ParseRuleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid rule")
    }
}

impl std::error::Error for ParseRuleError {}

impl From<ipnet::AddrParseError> for ParseRuleError {
    fn from(_: ipnet::AddrParseError) -> Self {
        ParseRuleError
    }
}

impl Rule {
    pub(super) fn normalized(self) -> Self {
        match self {
            Rule::Stateless(target, ports) => Rule::Stateless(target.normalized(), ports),
            Rule::Stateful {
                direction,
                target,
                ports,
            } => Rule::Stateful {
                direction,
                target: target.normalized(),
                ports,
            },
        }
    }
}

impl FromStr for Rule {
    type Err = ParseRuleError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (direction, destination) = if let Some(destination) = input.strip_prefix("in ") {
            (Some(Direction::In), destination.trim_start_matches(' '))
        } else if let Some(destination) = input.strip_prefix("out ") {
            (Some(Direction::Out), destination.trim_start_matches(' '))
        } else {
            (None, input)
        };

        // Neither IPv4 CIDRs nor @host contain a colon
        let (target, ports) = match destination.split_once(':') {
            Some((target, ports)) => (target.parse()?, Some(ports.parse()?)),
            None => (destination.parse()?, None),
        };

        Ok(match direction {
            None => Rule::Stateless(target, ports),
            Some(direction) => Rule::Stateful {
                direction,
                target,
                ports,
            },
        })
    }
}

impl Display for Rule {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let (direction, target, ports) = match self {
            Rule::Stateless(target, ports) => (None, target, ports),
            Rule::Stateful {
                direction,
                target,
                ports,
            } => (Some(direction), target, ports),
        };

        match direction {
            Some(Direction::In) => formatter.write_str("in ")?,
            Some(Direction::Out) => formatter.write_str("out ")?,
            None => {}
        }
        Display::fmt(target, formatter)?;
        if let Some(ports) = ports {
            write!(formatter, ":{ports}")?;
        }

        Ok(())
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

impl Ports {
    pub(crate) fn contains(self, port: u16) -> bool {
        self.first <= port && port <= self.last
    }
}

impl FromStr for Ports {
    type Err = ParseRuleError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        fn port(input: &str) -> Result<u16, ParseRuleError> {
            if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ParseRuleError);
            }
            match input.parse::<u16>() {
                Ok(0) | Err(_) => Err(ParseRuleError),
                Ok(port) => Ok(port),
            }
        }

        let (first, last) = match input.split_once('-') {
            Some((first, last)) => (port(first)?, port(last)?),
            None => {
                let port = port(input)?;
                (port, port)
            }
        };

        if first > last {
            return Err(ParseRuleError);
        }

        Ok(Ports { first, last })
    }
}

impl Display for Ports {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(formatter, "{}", self.first)
        } else {
            write!(formatter, "{}-{}", self.first, self.last)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Direction, Ports, Rule, Target};
    use ipnet::Ipv4Net;
    use std::str::FromStr;

    #[test]
    fn parses_stateless_target() {
        assert_eq!(
            "@host".parse::<Rule>().unwrap(),
            Rule::Stateless(Target::Host, None)
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
                ports: None,
            }
        );
        assert_eq!(
            "out 10.0.0.0/8".parse::<Rule>().unwrap(),
            Rule::Stateful {
                direction: Direction::Out,
                target: private_network,
                ports: None,
            }
        );
    }

    #[test]
    fn displays_normalized_rules() {
        for (input, expected) in [
            ("in 10.1.2.3/8", "in 10.0.0.0/8"),
            ("@host", "@host"),
            ("10.1.2.3/8:8444", "10.0.0.0/8:8444"),
            (
                "out  192.168.0.10/32:8000-8100",
                "out 192.168.0.10/32:8000-8100",
            ),
            ("@host:22-22", "@host:22"),
        ] {
            assert_eq!(
                input.parse::<Rule>().unwrap().normalized().to_string(),
                expected
            );
        }
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
            "10.0.0.0/8:",
            "10.0.0.0/8:0",
            "10.0.0.0/8:65536",
            "10.0.0.0/8:+80",
            "10.0.0.0/8: 80",
            "10.0.0.0/8:80-",
            "10.0.0.0/8:-80",
            "10.0.0.0/8:90-80",
            "10.0.0.0/8:80:90",
            "@host:ssh",
        ] {
            assert!(input.parse::<Rule>().is_err(), "{input:?} should fail");
        }
    }

    #[test]
    fn parses_ports() {
        let server = Target::Prefix(Ipv4Net::from_str("192.168.0.10/32").unwrap());

        assert_eq!(
            "192.168.0.10/32:8444".parse::<Rule>().unwrap(),
            Rule::Stateless(server, Some("8444".parse().unwrap()))
        );
        assert_eq!(
            "out @host:1-65535".parse::<Rule>().unwrap(),
            Rule::Stateful {
                direction: Direction::Out,
                target: Target::Host,
                ports: Some(Ports {
                    first: 1,
                    last: 65535
                }),
            }
        );
    }

    #[test]
    fn port_ranges_are_inclusive() {
        let ports: Ports = "8000-8002".parse().unwrap();

        assert!(!ports.contains(7999));
        assert!(ports.contains(8000));
        assert!(ports.contains(8002));
        assert!(!ports.contains(8003));
    }
}
