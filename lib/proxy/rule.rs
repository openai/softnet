use ipnet::Ipv4Net;
use pest::Parser as _;
use pest::iterators::Pair;
use std::error::Error;
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
        source: Option<Target>,
        destination: Option<Target>,
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

#[derive(Debug)]
pub struct ParseRuleError {
    message: String,
}

impl Rule {
    fn parse(input: &str) -> Result<Self, ParseRuleError> {
        let root = RuleParser::parse(SyntaxRule::rule, input)
            .map_err(ParseRuleError::syntax)?
            .next()
            .expect("the grammar always produces a root pair");
        let body = root
            .into_inner()
            .next()
            .expect("the grammar always produces a rule body");

        match body.as_rule() {
            SyntaxRule::stateful => Self::parse_stateful(body),
            SyntaxRule::target => Ok(Rule::Stateless(Self::parse_target(&body)?)),
            _ => unreachable!("unexpected rule body: {:?}", body.as_rule()),
        }
    }

    fn parse_stateful(pair: Pair<'_, SyntaxRule>) -> Result<Self, ParseRuleError> {
        let mut fields = pair.into_inner();
        let direction = match fields
            .next()
            .expect("a stateful rule always has a direction")
            .as_str()
        {
            "in" => Direction::In,
            "out" => Direction::Out,
            direction => unreachable!("unexpected direction: {direction}"),
        };
        let side = fields
            .next()
            .expect("a stateful rule always has a side")
            .as_str();
        let target =
            Self::parse_target(&fields.next().expect("a stateful rule always has a target"))?;
        let (source, destination) = match side {
            "from" => (Some(target), None),
            "to" => (None, Some(target)),
            side => unreachable!("unexpected side: {side}"),
        };

        Ok(Rule::Stateful {
            direction,
            source,
            destination,
        })
    }

    fn parse_target(pair: &Pair<'_, SyntaxRule>) -> Result<Target, ParseRuleError> {
        pair.as_str().parse().map_err(|error| {
            ParseRuleError::new(format!("invalid target \"{}\": {error}", pair.as_str()))
        })
    }
}

impl FromStr for Rule {
    type Err = ParseRuleError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
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

impl ParseRuleError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn syntax(error: pest::error::Error<SyntaxRule>) -> Self {
        Self::new(error.to_string())
    }
}

impl Display for ParseRuleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ParseRuleError {}

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
            "in from   @host".parse::<Rule>().unwrap(),
            Rule::Stateful {
                direction: Direction::In,
                source: Some(Target::Host),
                destination: None,
            }
        );
        assert_eq!(
            "out to 10.0.0.0/8".parse::<Rule>().unwrap(),
            Rule::Stateful {
                direction: Direction::Out,
                source: None,
                destination: Some(private_network),
            }
        );
    }

    #[test]
    fn rejects_invalid_rules() {
        for input in [
            "",
            "from @host",
            "in",
            "out",
            "in @host",
            "out @host",
            "infrom @host",
            " in from @host",
            "in from @host ",
            "in\tfrom @host",
        ] {
            assert!(input.parse::<Rule>().is_err(), "{input:?} should fail");
        }
    }
}
