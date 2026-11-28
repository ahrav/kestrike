//! How a step of a plant ends without its value: the plant's no verdict, which leaves the run going on
//! to the next plant, or a halt, a recorded signal or a failure outside a plant, which ends the run. A
//! checked Git step that exits nonzero keeps its error output.

use super::git::CallError;
use super::verdict::NoVerdict;
use crate::process::Interrupted;
use crate::text::{Text, text};

/// Why a run ends before its score: a recorded signal, or a failure outside a plant, exit 4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Halt {
    Interrupted(i32),
    Failed(Text),
}

impl Halt {
    /// `code` is the tool's exit: 128 plus the signal, or 4 for a failure or a signal number whose exit
    /// is no byte.
    pub fn code(&self) -> u8 {
        match self {
            Self::Interrupted(signal) => signal
                .checked_add(128)
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(4),
            Self::Failed(_) => 4,
        }
    }
}

impl From<Interrupted> for Halt {
    fn from(Interrupted(signal): Interrupted) -> Self {
        Self::Interrupted(signal)
    }
}

/// A checked Git step that exited nonzero: its subcommand, its exit code and its error output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitFailed {
    pub step: Text,
    pub code: i32,
    pub stderr: Text,
}

impl GitFailed {
    /// `shown` is `` `git STEP` exited CODE ``.
    pub(crate) fn shown(&self) -> Text {
        text!("`git ", self.step, "` exited ", self.code)
    }
}

/// How one plant's step ended without its value: the plant's no verdict, a checked Git step that
/// failed, or the end of the run.
#[derive(Debug)]
pub enum Step {
    NoVerdict(NoVerdict),
    Git(GitFailed),
    Halt(Halt),
}

impl From<NoVerdict> for Step {
    fn from(ending: NoVerdict) -> Self {
        Self::NoVerdict(ending)
    }
}

impl From<Halt> for Step {
    fn from(halt: Halt) -> Self {
        Self::Halt(halt)
    }
}

impl From<Interrupted> for Step {
    fn from(interrupted: Interrupted) -> Self {
        Self::Halt(interrupted.into())
    }
}

/// How a child the run starts ended without its value: the plant's `NoVerdict`, after which the run
/// goes on, or the run's `Halt`, which ends it; `Stopped` converts into `Step`.
#[derive(Debug)]
pub enum Stopped {
    NoVerdict(NoVerdict),
    Halt(Halt),
}

impl From<NoVerdict> for Stopped {
    fn from(ending: NoVerdict) -> Self {
        Self::NoVerdict(ending)
    }
}

impl From<Halt> for Stopped {
    fn from(halt: Halt) -> Self {
        Self::Halt(halt)
    }
}

impl From<Interrupted> for Stopped {
    fn from(interrupted: Interrupted) -> Self {
        Self::Halt(interrupted.into())
    }
}

impl From<Stopped> for Step {
    fn from(stopped: Stopped) -> Self {
        match stopped {
            Stopped::NoVerdict(ending) => Self::NoVerdict(ending),
            Stopped::Halt(halt) => Self::Halt(halt),
        }
    }
}

/// A Git call that started and printed no UTF-8 text, or that could not start or be waited for, is the
/// plant's no verdict, `the run failed: ` and the call's text.
impl From<CallError> for Step {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Failed { step, code, stderr } => Self::Git(GitFailed { step, code, stderr }),
            CallError::Interrupted(interrupted) => interrupted.into(),
            other => Self::NoVerdict(NoVerdict::failed(other.to_string())),
        }
    }
}
