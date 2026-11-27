//! The reasons of a plant's result, built from literal words and values with [`words!`]: each text value
//! keeps its code points, a lone surrogate included, so the score's JSON escapes it as `\udXXX`.

use crate::json::Integer;
use crate::text::Text;

/// A value a reason writes: literal words, a text, an integer's digits or a count.
pub(crate) trait Piece {
    fn put(&self, into: &mut Text);
}

impl<T: Piece + ?Sized> Piece for &T {
    fn put(&self, into: &mut Text) {
        (**self).put(into);
    }
}

impl Piece for str {
    fn put(&self, into: &mut Text) {
        into.push_str(self);
    }
}

impl Piece for String {
    fn put(&self, into: &mut Text) {
        into.push_str(self);
    }
}

impl Piece for Text {
    fn put(&self, into: &mut Text) {
        into.push_text(self);
    }
}

impl Piece for Integer {
    fn put(&self, into: &mut Text) {
        into.push_str(&self.to_string());
    }
}

impl Piece for i32 {
    fn put(&self, into: &mut Text) {
        into.push_str(&self.to_string());
    }
}

impl Piece for usize {
    fn put(&self, into: &mut Text) {
        into.push_str(&self.to_string());
    }
}

/// `words!(a, b, ...)` is the [`Text`] of each [`Piece`] in order.
macro_rules! words {
    ($($piece:expr),* $(,)?) => {{
        let mut text = $crate::text::Text::new();
        $( $crate::plants::words::Piece::put(&$piece, &mut text); )*
        text
    }};
}

pub(crate) use words;
