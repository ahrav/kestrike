//! The error types of the controller's checks and bounds. A rejection carries the sentence the controller
//! prints as rejected input; its [`Text`] keeps a lone surrogate of a decoded key as a code point.

use std::fmt;

use crate::text::Text;

/// The sentence explains why the controller rejected the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejected(Text);

impl Rejected {
    pub(super) fn new(sentence: Text) -> Self {
        Self(sentence)
    }

    pub fn sentence(&self) -> &Text {
        &self.0
    }
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Rejected {}

/// A failure of a bound or of a check that sums seconds, of the kind a caller tells apart: the controller
/// prints a rejection as rejected input, and ends its run on each other kind as on an error it does not
/// catch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Rejected(Rejected),
    /// A whole number of seconds that a sum converts to a float is past the largest float.
    Overflow,
    /// A lane's whole number or boolean names no item of a list or a string of the hardware manifest.
    OutOfRange,
}

impl From<Rejected> for Error {
    fn from(rejected: Rejected) -> Self {
        Self::Rejected(rejected)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(rejected) => rejected.fmt(f),
            Self::Overflow => f.write_str("a whole number of seconds is too large for a float"),
            Self::OutOfRange => {
                f.write_str("the lane names no item of a list or a string of the hardware manifest")
            }
        }
    }
}

impl std::error::Error for Error {}
