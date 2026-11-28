//! The one error type of the hardware lane's rules. A refusal's sentence is a [`Text`], so a lone
//! surrogate of a decoded key stands in it as a code point.

use std::fmt;
use std::io;

use crate::text::Text;

pub(super) const MALFORMED: &str = "malformed hardware manifest: ";

/// A failure of a rule, of the kind a caller tells apart.
#[derive(Debug)]
pub enum Error {
    /// The read of the manifest failed with this system error.
    System(io::Error),
    /// The seconds text spells no number.
    NoNumber,
    /// The rule refused its input with this sentence.
    Refused(Text),
}

impl Error {
    pub(super) fn malformed(message: &Text) -> Self {
        let mut sentence = Text::from(MALFORMED);
        sentence.push_text(message);
        Self::Refused(sentence)
    }

    /// The sentence of a refusal, and none for the other kinds.
    pub fn sentence(&self) -> Option<&Text> {
        match self {
            Self::Refused(sentence) => Some(sentence),
            Self::System(_) | Self::NoNumber => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System(error) => error.fmt(f),
            Self::NoNumber => f.write_str("the text is no number"),
            Self::Refused(sentence) => sentence.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::System(error) => std::error::Error::source(error),
            Self::NoNumber | Self::Refused(_) => None,
        }
    }
}

/// `need` composes the message only when `condition` fails, and refuses with it after [`MALFORMED`].
pub(super) fn need(condition: bool, message: impl FnOnce() -> Text) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::malformed(&message()))
    }
}
