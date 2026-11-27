//! Why the checks stopped: a refusal of the run's input, exit 2 in the tool, or a failure outside a
//! plant, exit 4, each with its reason.

use super::git::CallError;
use crate::text::Text;

#[derive(Debug)]
pub(crate) enum Stop {
    Rejected(Text),
    Failed(Text),
}

impl Stop {
    pub(crate) fn rejected(reason: impl Into<Text>) -> Self {
        Self::Rejected(reason.into())
    }

    pub(crate) fn failed(reason: impl Into<Text>) -> Self {
        Self::Failed(reason.into())
    }

    /// `git` is the failure of a Git call that could not run, printed no UTF-8 text, or exited nonzero
    /// where the call was checked.
    pub(crate) fn git(error: CallError) -> Self {
        Self::failed(error.to_string())
    }
}
