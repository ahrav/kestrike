//! A refusal holds the judge's sentence as Python's `str` holds it, so a lone surrogate of a decoded key
//! stands in the sentence as a code point.

use std::fmt;

use crate::text::Text;

/// `Refusal` is a failed check of evidence or of a catalog, holding the judge's sentence. The caller
/// decides whether to go on, what to write and which exit status to return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    message: Text,
}

impl Refusal {
    pub fn new(message: Text) -> Self {
        Self { message }
    }

    /// The judge's sentence.
    pub fn message(&self) -> &Text {
        &self.message
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for Refusal {}

/// `need` refuses with `message` when `condition` fails; the message is composed only then.
///
/// # Errors
///
/// A [`Refusal`] that holds the message when `condition` is false.
pub fn need(condition: bool, message: impl FnOnce() -> Text) -> Result<(), Refusal> {
    if condition {
        Ok(())
    } else {
        Err(Refusal::new(message()))
    }
}

/// `said!(a, b, ...)` is the [`Text`] of its pieces in order.
pub(crate) use crate::text::text as said;
