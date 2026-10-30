use anyhow::{Context, Result, ensure};
use ipnet::Ipv4Net;
use pest::Parser as _;
use pest::iterators::Pair;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

mod grammar {
    use pest_derive::Parser;

    #[derive(Parser)]
    #[grammar = "lib/proxy/rule.pest"]
    pub(super) struct RuleParser;
}

use grammar::{Rule as SyntaxRule, RuleParser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Stateless(Target),
    Stateful {
        direction: Direction,
        target: Target,
        filter: Filter,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Prefix(Ipv4Net),
    Host,
    Peers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display, strum::EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Filter {
    pub protocol: Option<Protocol>,
    pub destination_port_range: Option<PortRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl Rule {
    pub(super) fn normalized(self) -> Self {
        match self {
            Rule::Stateless(target) => Rule::Stateless(target.normalized()),
            Rule::Stateful {
                direction,
                target,
                filter,
            } => Rule::Stateful {
                direction,
                target: target.normalized(),
                filter,
            },
        }
    }

    fn parse(input: &str) -> Result<Self> {
        let mut parsed =
            RuleParser::parse(SyntaxRule::rule, input).context("invalid rule syntax")?;

        let body = parsed
            .next()
            .expect("successful parsing always produces a rule body");

        match body.as_rule() {
            SyntaxRule::target => Ok(Rule::Stateless(Self::parse_target(&body)?)),
            SyntaxRule::stateful => Self::parse_stateful(body),
            _ => unreachable!("unexpected rule body: {:?}", body.as_rule()),
        }
    }

    fn parse_stateful(pair: Pair<'_, SyntaxRule>) -> Result<Self> {
        let mut fields = pair.into_inner();

        let direction_field = fields
            .next()
            .expect("a stateful rule always has a direction");

        let direction = direction_field.as_str().parse()?;
        let mut target = Target::Prefix(Ipv4Net::default());
        let mut filter = Filter::default();

        // Keep protocol and destination-port conditions independent of packet direction
        for field in fields {
            match field.as_rule() {
                SyntaxRule::protocol_name => {
                    filter.protocol = Some(field.as_str().parse()?);
                }
                SyntaxRule::target => target = Self::parse_target(&field)?,
                SyntaxRule::destination_port => {
                    filter.destination_port_range = Some(field.as_str().parse()?);
                }
                _ => unreachable!("unexpected rule field: {:?}", field.as_rule()),
            }
        }

        // Port filters require an explicit transport protocol
        ensure!(
            filter.destination_port_range.is_none()
                || matches!(filter.protocol, Some(Protocol::Tcp | Protocol::Udp)),
            "port requires proto tcp or proto udp"
        );

        Ok(Rule::Stateful {
            direction,
            target,
            filter,
        })
    }

    fn parse_target(pair: &Pair<'_, SyntaxRule>) -> Result<Target> {
        pair.as_str()
            .parse()
            .with_context(|| format!("invalid target {:?}", pair.as_str()))
    }
}

impl FromStr for Rule {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl Display for Rule {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Rule::Stateless(target) => Display::fmt(target, formatter),
            Rule::Stateful {
                direction,
                target,
                filter,
            } => {
                write!(formatter, "{direction} ")?;

                if let Some(protocol) = filter.protocol {
                    write!(formatter, "proto {protocol} ")?;
                }

                Display::fmt(target, formatter)?;

                if let Some(port) = filter.destination_port_range {
                    write!(formatter, " port {port}")?;
                }

                Ok(())
            }
        }
    }
}

impl Target {
    fn normalized(self) -> Self {
        match self {
            Target::Prefix(prefix) => Target::Prefix(prefix.trunc()),
            Target::Host => Target::Host,
            Target::Peers => Target::Peers,
        }
    }
}

impl FromStr for Target {
    type Err = ipnet::AddrParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "@host" => Ok(Target::Host),
            "@peers" => Ok(Target::Peers),
            _ => input.parse().map(Target::Prefix),
        }
    }
}

impl Display for Target {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Target::Prefix(prefix) => Display::fmt(prefix, formatter),
            Target::Host => formatter.write_str("@host"),
            Target::Peers => formatter.write_str("@peers"),
        }
    }
}

impl PortRange {
    /// Creates an inclusive range of nonzero ports.
    pub fn new(start: u16, end: u16) -> Result<Self> {
        ensure!(start != 0 && end != 0, "port bounds must be in 1..65535");
        ensure!(start <= end, "port range start must not exceed its end");

        Ok(Self { start, end })
    }

    pub(super) fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }

    pub(super) fn width(self) -> u16 {
        self.end - self.start
    }
}

impl FromStr for PortRange {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        ensure!(
            input
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b':'),
            "invalid destination port {input:?}: expected PORT or START:END"
        );

        let (start, end) = input.split_once(':').unwrap_or((input, input));
        let parse_bound = |bound: &str| {
            bound
                .parse::<u16>()
                .with_context(|| format!("invalid port bound {bound:?}: expected 1..65535"))
        };

        Self::new(parse_bound(start)?, parse_bound(end)?)
    }
}

impl Display for PortRange {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(formatter, "{}", self.start)
        } else {
            write!(formatter, "{}:{}", self.start, self.end)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Direction, Filter, PortRange, Protocol, Rule, Target};
    use ipnet::Ipv4Net;
    use std::str::FromStr;

    #[test]
    fn parses_stateless_target() {
        assert_eq!(
            "@host".parse::<Rule>().unwrap(),
            Rule::Stateless(Target::Host)
        );
        assert_eq!(
            "@peers".parse::<Rule>().unwrap(),
            Rule::Stateless(Target::Peers)
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
                filter: Filter::default(),
            }
        );
        assert_eq!(
            "out 10.0.0.0/8".parse::<Rule>().unwrap(),
            Rule::Stateful {
                direction: Direction::Out,
                target: private_network,
                filter: Filter::default(),
            }
        );
    }

    #[test]
    fn parses_protocol_and_destination_port_filters() {
        for (input, direction, protocol, destination_port_range) in [
            (
                "in proto icmp @host",
                Direction::In,
                Some(Protocol::Icmp),
                None,
            ),
            (
                "out proto udp @host port 53",
                Direction::Out,
                Some(Protocol::Udp),
                Some((53, 53)),
            ),
            (
                "in proto tcp @host port 8000:9000",
                Direction::In,
                Some(Protocol::Tcp),
                Some((8000, 9000)),
            ),
        ] {
            let target = Target::Host;
            let filter = Filter {
                protocol,
                destination_port_range: destination_port_range
                    .map(|(start, end)| PortRange::new(start, end).unwrap()),
            };
            let expected = Rule::Stateful {
                direction,
                target,
                filter,
            };

            assert_eq!(input.parse::<Rule>().unwrap(), expected, "{input:?}");
        }
    }

    #[test]
    fn displays_normalized_rules() {
        for (input, expected) in [
            ("in 10.1.2.3/8", "in 10.0.0.0/8"),
            ("@host", "@host"),
            ("@peers", "@peers"),
            ("out proto udp port 53", "out proto udp 0.0.0.0/0 port 53"),
            (
                "out proto tcp 10.1.2.3/8 port 08443",
                "out proto tcp 10.0.0.0/8 port 8443",
            ),
            (
                "out proto tcp port 080:080",
                "out proto tcp 0.0.0.0/0 port 80",
            ),
            (
                "in proto udp @host port 08000:09000",
                "in proto udp @host port 8000:9000",
            ),
            (
                "out proto udp port 1:65535",
                "out proto udp 0.0.0.0/0 port 1:65535",
            ),
        ] {
            let rule = input.parse::<Rule>().unwrap().normalized();

            assert_eq!(rule.to_string(), expected, "{input:?}");
            assert_eq!(expected.parse::<Rule>().unwrap(), rule, "{input:?}");
        }
    }

    #[test]
    fn port_ranges_reject_invalid_input() {
        assert!(PortRange::new(0, 80).is_err());
        assert!(PortRange::new(90, 80).is_err());
        assert!("+80".parse::<PortRange>().is_err());
    }

    #[test]
    fn rejects_invalid_rules() {
        for input in [
            "",                               // Empty input
            "out proto sctp",                 // Unsupported protocol
            "@host port 53",                  // Filters require a direction
            "in port 53",                     // Missing protocol
            "out port 53",                    // Missing protocol
            "in @host port 8000:8100",        // Missing protocol with a target
            "out 0.0.0.0/0 port 8000:8100",   // Missing protocol with a prefix
            "out proto tcp @host port",       // Missing value
            "out proto tcp @host port 0",     // Forbidden zero port
            "out proto tcp @host port 65536", // Port overflow
            "out proto tcp port 0:80",        // Forbidden zero lower bound
            "out proto tcp port 80:0",        // Forbidden zero upper bound
            "out proto tcp port 80:65536",    // Upper bound overflow
            "out proto tcp port 90:80",       // Reversed bounds
            "out proto tcp port :80",         // Missing lower bound
            "out proto tcp port 80:",         // Missing upper bound
            "out proto tcp port 80:90:100",   // Extra bound
            "out proto tcp port 80-90",       // Unsupported separator
            "out proto icmp port 53",         // Incompatible port
            "out proto icmp port 80:90",      // Incompatible range
            "out 10.0.0.0/33",                // Invalid target
            "out @host trailing",             // Unconsumed input
        ] {
            assert!(input.parse::<Rule>().is_err(), "{input:?} should fail");
        }
    }
}
