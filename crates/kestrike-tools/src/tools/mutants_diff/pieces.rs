//! A path or an operating-system string enters the [`Text`] that `text!` builds as [`Text::from_os`]
//! decodes it, so a byte outside UTF-8 stays a surrogate until the text is printed.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::text::Text;

pub trait Piece {
    fn push_to(&self, text: &mut Text);
}

impl Piece for str {
    fn push_to(&self, text: &mut Text) {
        text.push_str(self);
    }
}

impl Piece for String {
    fn push_to(&self, text: &mut Text) {
        text.push_str(self);
    }
}

impl Piece for Text {
    fn push_to(&self, text: &mut Text) {
        text.push_text(self);
    }
}

impl Piece for OsStr {
    fn push_to(&self, text: &mut Text) {
        text.push_text(&Text::from_os(self));
    }
}

impl Piece for OsString {
    fn push_to(&self, text: &mut Text) {
        self.as_os_str().push_to(text);
    }
}

impl Piece for Path {
    fn push_to(&self, text: &mut Text) {
        self.as_os_str().push_to(text);
    }
}

impl Piece for PathBuf {
    fn push_to(&self, text: &mut Text) {
        self.as_os_str().push_to(text);
    }
}

impl<T: Piece + ?Sized> Piece for &T {
    fn push_to(&self, text: &mut Text) {
        (**self).push_to(text);
    }
}

macro_rules! text {
    ($($piece:expr),+ $(,)?) => {{
        let mut text = $crate::text::Text::new();
        $( $crate::tools::mutants_diff::pieces::Piece::push_to(&$piece, &mut text); )+
        text
    }};
}

pub(crate) use text;
