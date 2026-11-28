//! A sentence of the checks is a [`Text`] composed of pieces in order, so a decoded name that holds a
//! lone surrogate stands in it as that code point; a list stands as Python's `repr` of the sorted list.

use super::number::Number;
use crate::text::Text;

/// A part of a sentence.
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

impl Piece for Number {
    fn put(&self, out: &mut Text) {
        out.push_str(&self.to_string());
    }
}

impl<T: Piece + ?Sized> Piece for &T {
    fn put(&self, out: &mut Text) {
        (**self).put(out);
    }
}

/// `sentence!(a, b, ...)` is the [`Text`] of its pieces in order.
macro_rules! sentence {
    ($($piece:expr),+ $(,)?) => {{
        let mut sentence = $crate::text::Text::new();
        $($crate::host_stop::words::Piece::put(&$piece, &mut sentence);)+
        sentence
    }};
}

pub(crate) use sentence;

/// Python's `repr` of the sorted list of `items`.
pub(crate) fn sorted_texts<'a>(items: impl IntoIterator<Item = &'a Text>) -> String {
    let mut items: Vec<&Text> = items.into_iter().collect();
    items.sort();
    let shown: Vec<String> = items.iter().map(|item| item.repr()).collect();
    format!("[{}]", shown.join(", "))
}

/// Python's `repr` of the sorted list of `numbers`, no two of which are equal.
pub(crate) fn sorted_numbers(numbers: &[Number]) -> String {
    let mut numbers = numbers.to_vec();
    numbers.sort_by(|a, b| a.partial_cmp(b).expect("a finite number orders"));
    let shown: Vec<String> = numbers.iter().map(Number::to_string).collect();
    format!("[{}]", shown.join(", "))
}
