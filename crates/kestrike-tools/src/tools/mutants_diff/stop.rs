//! A [`Stop`] ends the run with an exit code and a reason; a [`Fault`] describes an error the run did not
//! expect, as `<Kind>: <text>`.
//!
//! A fault's kind is the [`io::ErrorKind`] name of an operating-system error and the error type's name
//! otherwise. Its text is the standard library's `Display` of the error, then `: ` and the path or program
//! the error concerns, when there is one.

use std::ffi::OsStr;
use std::fmt;
use std::io;

use crate::text::Text;
use crate::text::text;

pub const COMPLETE: u8 = 0;
pub const INCOMPLETE: u8 = 1;
pub const REJECTED: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    code: u8,
    reason: Text,
    /// A fatal stop prints `mutants-diff: <reason>` and exits 1 without a report.
    fatal: bool,
}

impl Stop {
    pub(super) fn incomplete(reason: Text) -> Self {
        Self {
            code: INCOMPLETE,
            reason,
            fatal: false,
        }
    }

    pub(super) fn rejected(reason: Text) -> Self {
        Self {
            code: REJECTED,
            reason,
            fatal: false,
        }
    }

    pub(super) fn fatal(reason: Text) -> Self {
        Self {
            code: INCOMPLETE,
            reason,
            fatal: true,
        }
    }

    /// `failed` is the stop of an unexpected error inside the run's steps.
    pub(super) fn failed(fault: &Fault) -> Self {
        Self::incomplete(text!("the runner failed: ", fault.to_text()))
    }

    pub(super) fn interrupted(signal: i32) -> Self {
        Self::incomplete(text!(format!("interrupted by signal {signal}")))
    }

    pub fn code(&self) -> u8 {
        self.code
    }

    pub fn reason(&self) -> &Text {
        &self.reason
    }

    pub fn is_fatal(&self) -> bool {
        self.fatal
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    kind: String,
    text: Text,
}

impl Fault {
    /// `os` describes an I/O error that concerns `subject`, a path or a program, when one is given.
    pub(super) fn os(error: &io::Error, subject: Option<&OsStr>) -> Self {
        let mut shown = text!(error.to_string());
        if let Some(subject) = subject {
            shown = text!(shown, ": ", subject);
        }
        Self {
            kind: format!("{:?}", error.kind()),
            text: shown,
        }
    }

    pub(super) fn library(name: &str, error: &impl fmt::Display) -> Self {
        Self {
            kind: name.to_owned(),
            text: text!(error.to_string()),
        }
    }

    /// `text` is the fault without its kind.
    pub(super) fn text(&self) -> &Text {
        &self.text
    }

    pub(super) fn to_text(&self) -> Text {
        text!(self.kind.as_str(), ": ", self.text)
    }
}
