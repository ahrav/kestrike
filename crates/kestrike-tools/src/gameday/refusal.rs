//! A refusal holds the judge's sentence as Python's `str` holds it, so a lone surrogate of a decoded key
//! stands in the sentence as a code point.

use std::fmt;

use crate::text::Text;

/// `Refusal` is evidence or a catalog the judge cannot read as the layout states: the judge exits 2 and
/// writes no record of the run.
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

/// A part of a sentence: a string, or text that may hold a lone surrogate.
pub(crate) trait Piece {
    fn put(&self, out: &mut Text);
}

impl Piece for str {
    fn put(&self, out: &mut Text) {
        out.push_str(self);
    }
}

impl Piece for String {
    fn put(&self, out: &mut Text) {
        out.push_str(self);
    }
}

impl Piece for Text {
    fn put(&self, out: &mut Text) {
        out.push_text(self);
    }
}

impl<T: Piece + ?Sized> Piece for &T {
    fn put(&self, out: &mut Text) {
        (**self).put(out);
    }
}

/// `said!(a, b, ...)` is the [`Text`] of its pieces in order.
macro_rules! said {
    ($($piece:expr),+ $(,)?) => {{
        let mut said = $crate::text::Text::new();
        $($crate::gameday::refusal::Piece::put(&$piece, &mut said);)+
        said
    }};
}

pub(crate) use said;
