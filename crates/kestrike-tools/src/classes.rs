//! Regular-expression classes with the members Python's `re` gives `\s`, `\w` and `\d` in a `str` pattern:
//! white space is Unicode `White_Space` with U+001C to U+001F, a word character is a letter, a number or
//! `_`, and a digit is a code point of category `Nd`.
//!
//! Python's `\b` holds where a word character meets another character or the text's edge. The `regex`
//! crate's `\b` reads its own set of word characters, which holds combining marks and lacks numbers such as
//! `²`. A pattern written for [`captures_bounded`] therefore leaves out each `\b` at an edge of its match
//! beside a word character, and the search checks those edges with [`is_word`].

use std::sync::LazyLock;

use regex::{Captures, Regex};
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

/// Whether Python's `\b` holds at each edge of `text[start..end]` that is a word character: a match that
/// starts with one has no word character before it, and a match that ends with one has none after it.
pub fn word_edges(text: &str, start: usize, end: usize) -> bool {
    let word = |c: Option<char>| c.is_some_and(is_word);
    let (first, last) = (
        text[start..end].chars().next(),
        text[start..end].chars().next_back(),
    );
    !(word(first) && word(text[..start].chars().next_back()))
        && !(word(last) && word(text[end..].chars().next()))
}

/// The first match of `regex` in `text` at or after `at` whose word edges pass [`word_edges`]. A candidate
/// that fails resumes the search one code point after its start, as Python tries each start in turn.
pub fn captures_bounded<'h>(regex: &Regex, text: &'h str, mut at: usize) -> Option<Captures<'h>> {
    loop {
        let found = regex.captures_at(text, at)?;
        let whole = found.get_match();
        if word_edges(text, whole.start(), whole.end()) {
            return Some(found);
        }
        at = next_code_point(text, whole.start());
    }
}

fn next_code_point(text: &str, at: usize) -> usize {
    at + text[at..].chars().next().map_or(1, char::len_utf8)
}

/// Each match of `regex` in `text` in order, as Python's `finditer` yields them for the pattern with its
/// `\b` at the word edges: [`captures_bounded`] from the end of the previous match, or from one code point
/// after an empty match.
pub fn bounded_iter<'r, 'h>(
    regex: &'r Regex,
    text: &'h str,
) -> impl Iterator<Item = Captures<'h>> + 'r
where
    'h: 'r,
{
    let mut at = 0;
    std::iter::from_fn(move || {
        let found = captures_bounded(regex, text, at)?;
        let whole = found.get_match();
        at = if whole.is_empty() {
            next_code_point(text, whole.end())
        } else {
            whole.end()
        };
        Some(found)
    })
}
