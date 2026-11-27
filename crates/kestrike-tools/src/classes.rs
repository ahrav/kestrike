//! Regular-expression classes with the members Python's `re` gives `\s`, `\w` and `\d` in a `str` pattern:
//! white space is Unicode `White_Space` with U+001C to U+001F, a word character is a letter, a number or
//! `_`, and a digit is a code point of category `Nd`.

use std::sync::LazyLock;

use regex_syntax::hir::{Class as HirClass, HirKind};

pub const SPACE: &str = r"[\s\x1c-\x1f]";
pub const WORD: &str = r"[\p{L}\p{N}_]";

static WORD_CLASS: LazyLock<Class> = LazyLock::new(|| Class::new(WORD));
static DIGIT_CLASS: LazyLock<Class> = LazyLock::new(|| Class::new(r"\d"));

/// # Panics
///
/// `compiled` panics with the pattern's text when `pattern` does not compile.
pub fn compiled(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern)
        .unwrap_or_else(|error| panic!("the pattern {pattern} compiles: {error}"))
}

/// # Panics
///
/// `compiled_bytes` panics with the pattern's text when `pattern` does not compile.
pub fn compiled_bytes(pattern: &str) -> regex::bytes::Regex {
    regex::bytes::Regex::new(pattern)
        .unwrap_or_else(|error| panic!("the pattern {pattern} compiles: {error}"))
}

/// A set of code points held as sorted, disjoint ranges.
pub struct Class(Vec<(char, char)>);

impl Class {
    /// # Panics
    ///
    /// `new` panics when `pattern` does not parse to one Unicode class.
    pub fn new(pattern: &str) -> Self {
        let hir = regex_syntax::Parser::new()
            .parse(pattern)
            .unwrap_or_else(|error| panic!("the class {pattern} parses: {error}"));
        let HirKind::Class(HirClass::Unicode(class)) = hir.kind() else {
            panic!("the pattern {pattern} is one Unicode class");
        };
        Self(
            class
                .ranges()
                .iter()
                .map(|range| (range.start(), range.end()))
                .collect(),
        )
    }

    pub fn contains(&self, c: char) -> bool {
        let at = self.0.partition_point(|&(_, high)| high < c);
        self.0.get(at).is_some_and(|&(low, _)| low <= c)
    }
}

pub fn is_word(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric() || c == '_'
    } else {
        WORD_CLASS.contains(c)
    }
}

pub fn is_digit(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_digit()
    } else {
        DIGIT_CLASS.contains(c)
    }
}
