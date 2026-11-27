use std::fmt;

use crate::json::Integer;
use crate::text::push_repr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    IgnoreExisting,
    BudgetLowered,
    TimeoutRaised,
    AssertionsRemoved,
    IgnoreNew,
    CaseRemoved,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IgnoreExisting => "ignore-existing",
            Self::BudgetLowered => "budget-lowered",
            Self::TimeoutRaised => "timeout-raised",
            Self::AssertionsRemoved => "assertions-removed",
            Self::IgnoreNew => "ignore-new",
            Self::CaseRemoved => "case-removed",
        }
    }

    pub fn blocks(self) -> bool {
        matches!(
            self,
            Self::IgnoreExisting | Self::BudgetLowered | Self::CaseRemoved
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shown {
    Count(Integer),
    Word(String),
}

impl Shown {
    pub fn absent() -> Self {
        Self::Word("absent".to_owned())
    }
}

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count(count) => count.fmt(f),
            Self::Word(word) => f.write_str(word),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub class: Class,
    pub name: String,
    pub old: Shown,
    pub new: Shown,
}

impl Change {
    pub fn new(class: Class, name: String, old: Shown, new: Shown) -> Self {
        Self {
            class,
            name,
            old,
            new,
        }
    }
}

pub struct Finding {
    pub path: String,
    pub change: Change,
}

impl Finding {
    pub fn key(&self) -> String {
        format!("{}:{}", self.change.class.as_str(), self.path)
    }
}

/// `short` is the first twelve code points of a commit name, as the report and the refusals write it.
pub(super) fn short(commit: &str) -> &str {
    commit
        .char_indices()
        .nth(12)
        .map_or(commit, |(at, _)| &commit[..at])
}

/// `escaped` writes each code point U+0000 to U+001F and U+007F to U+009F of `text` as `repr` writes it and
/// every other code point as it is, so a field of a report or refusal line starts no line of its own.
pub(super) fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for code in text.chars() {
        if matches!(code, '\0'..='\x1f' | '\x7f'..='\u{9f}') {
            push_repr(u32::from(code), &mut out);
        } else {
            out.push(code);
        }
    }
    out
}
