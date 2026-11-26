//! The rule catalog `--rules` prints: its version, then one line for each
//! violation rule a check of the worker can raise, with the check that
//! raises it.
//!
//! The version line appears once with the version this parser reads. At
//! least one rule line appears, each a scope word, a space and the rule's
//! text, and no two lines name one scope and text. A text appears under
//! two scopes when two checks raise it. A worker whose capability listing
//! is version 3 or later has the form.

use super::Error;
use super::pairs::{Pairs, count, repeated, words};

/// The rule catalog version this parser reads.
pub const RULES: u64 = 1;

words! {
    /// The check that raises a rule.
    Scope {
        /// The stopped-boundary and teardown observer, which judges every
        /// single-owner and cluster run.
        Boundary = "boundary",
        /// The single-owner world's own checks.
        World = "world",
        /// The cluster checker.
        Cluster = "cluster",
        /// A scripted history's own checks.
        History = "history",
        /// The oracle over recorded rows.
        Oracle = "oracle",
    }
}

/// One cataloged rule: its text and the check that raises it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rule {
    pub scope: Scope,
    pub text: String,
}

/// The rule catalog a worker's `--rules` prints; [`Rules::parse`] holds
/// its grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    pub rules: Vec<Rule>,
}

impl std::hash::Hash for Scope {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}

impl Rules {
    /// The catalog `text` prints.
    ///
    /// # Errors
    ///
    /// [`Error::Torn`] for output cut short; [`Error::Unpaired`] for a line
    /// without `": "`; [`Error::Missing`] for an absent version line or a
    /// catalog with no rule; [`Error::Repeated`] for a second version line
    /// or a scope and text printed twice; [`Error::Unknown`] for a line of
    /// another key; and [`Error::Value`] for a version this parser does not
    /// read, a rule with no space after its scope, a scope outside its
    /// words or an empty text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut lines = Pairs::lines(text)?;
        if lines.take("rules", count)? != RULES {
            return Err(Error::Value("rules"));
        }
        let rules = lines
            .every("rule")
            .into_iter()
            .map(|line| {
                let (scope, text) = line.split_once(' ').ok_or(Error::Value("rule"))?;
                if text.is_empty() {
                    return Err(Error::Value("rule"));
                }
                Ok(Rule {
                    scope: Scope::parse(scope, "rule")?,
                    text: text.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        lines.finish()?;
        if rules.is_empty() {
            return Err(Error::Missing("rule"));
        }
        if let Some(rule) = repeated(&rules) {
            return Err(Error::Repeated(format!(
                "rule {} {}",
                rule.scope.name(),
                rule.text
            )));
        }
        Ok(Self { rules })
    }
}
