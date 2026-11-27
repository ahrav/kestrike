use std::fmt;

use crate::json::Integer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    IgnoreExisting,
    BudgetLowered,
    TimeoutRaised,
    AssertionsRemoved,
    IgnoreNew,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IgnoreExisting => "ignore-existing",
            Self::BudgetLowered => "budget-lowered",
            Self::TimeoutRaised => "timeout-raised",
            Self::AssertionsRemoved => "assertions-removed",
            Self::IgnoreNew => "ignore-new",
        }
    }

    pub fn blocks(self) -> bool {
        matches!(self, Self::IgnoreExisting | Self::BudgetLowered)
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
