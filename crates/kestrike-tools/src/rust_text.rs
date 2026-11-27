//! The module defines character classes and patterns for scanning Rust source.

use std::sync::LazyLock;

use regex::Regex;
use regex_syntax::hir::{Class as HirClass, HirKind};

pub const SPACE: &str = r"[\s\x1c-\x1f]";
pub const WORD: &str = r"[\p{L}\p{N}_]";

pub static IGNORE: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"#\[ignore\b[^\]]*\]|#\[cfg_attr\([^\]]*\bignore\b[^\]]*\]"));

pub static FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"(?:#\[[^\]]*\]{SPACE}*)*(?:pub(?:\([^)]*\))?{SPACE}+)?(?:async{SPACE}+)?fn{SPACE}+(?:r#)?{WORD}+"
    ))
});

static BLOCK_EDGE: LazyLock<Regex> = LazyLock::new(|| compiled(r"/\*|\*/"));

static WORD_CLASS: LazyLock<Class> = LazyLock::new(|| Class::new(WORD));
static DIGIT_CLASS: LazyLock<Class> = LazyLock::new(|| Class::new(r"\d"));

pub fn compiled(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|error| panic!("the pattern {pattern} compiles: {error}"))
}

pub struct Class(Vec<(char, char)>);

impl Class {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lexeme {
    Comment,
    String,
    Char,
    Unclosed,
}

pub fn lexemes(text: &str) -> Vec<(Lexeme, usize, usize)> {
    let mut found = Vec::new();
    let mut start = 0;
    while let Some((at, end)) = next_lexeme(text, start) {
        let lexeme = &text[at..end];
        start = end;
        let kind = if lexeme == "/*" {
            let mut depth = 1_usize;
            while depth > 0 {
                let Some(edge) = BLOCK_EDGE.find_at(text, start) else {
                    break;
                };
                depth = if edge.as_str() == "/*" {
                    depth + 1
                } else {
                    depth - 1
                };
                start = edge.end();
            }
            if depth == 0 {
                Lexeme::Comment
            } else {
                start = text.len();
                Lexeme::Unclosed
            }
        } else if lexeme.starts_with('/') {
            Lexeme::Comment
        } else if lexeme.ends_with(['"', '#']) {
            Lexeme::String
        } else if lexeme.ends_with('\'') {
            Lexeme::Char
        } else {
            continue;
        };
        found.push((kind, at, start));
    }
    found
}

pub fn blank(text: &str) -> String {
    text.bytes()
        .map(|byte| if byte == b'\n' { '\n' } else { ' ' })
        .collect()
}

pub fn code(text: &str) -> String {
    let mut view = String::with_capacity(text.len());
    let mut index = 0;
    for (_, start, end) in lexemes(text) {
        view.push_str(&text[index..start]);
        view.push_str(&blank(&text[start..end]));
        index = end;
    }
    view.push_str(&text[index..]);
    view
}

fn next_lexeme(text: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut at = start;
    while at < bytes.len() {
        let found = match bytes[at] {
            b'/' => match bytes.get(at + 1) {
                Some(b'/') => Some(
                    text[at..]
                        .find('\n')
                        .map_or(text.len(), |offset| at + offset),
                ),
                Some(b'*') => Some(at + 2),
                _ => None,
            },
            b'r' => raw_string(text, at).or_else(|| raw_identifier(text, at)),
            b'"' => cooked_string(text, at),
            b'\'' => char_literal(text, at).or_else(|| lifetime(text, at)),
            _ => None,
        };
        if let Some(end) = found {
            return Some((at, end));
        }
        at += text[at..].chars().next().map_or(1, char::len_utf8);
    }
    None
}

fn before(text: &str, at: usize) -> Option<char> {
    text[..at].chars().next_back()
}

fn word_run(text: &str, at: usize) -> usize {
    text[at..]
        .char_indices()
        .find(|&(_, c)| !is_word(c))
        .map_or(text.len(), |(offset, _)| at + offset)
}

fn raw_string(text: &str, at: usize) -> Option<usize> {
    let hashes = text[at + 1..]
        .bytes()
        .take_while(|&byte| byte == b'#')
        .count();
    let open = at + 1 + hashes;
    if text.as_bytes().get(open) != Some(&b'"') {
        return None;
    }
    let prev = before(text, at);
    if prev.is_some_and(|c| is_word(c) && c != 'b' && c != 'c') {
        return None;
    }
    if matches!(prev, Some('b' | 'c')) && before(text, at - 1).is_some_and(is_word) {
        return None;
    }
    let mut close = open + 1;
    loop {
        close += text.get(close..)?.find('"')?;
        let end = close + 1 + hashes;
        if text
            .as_bytes()
            .get(close + 1..end)
            .is_some_and(|run| run.iter().all(|&b| b == b'#'))
        {
            return Some(end);
        }
        close += 1;
    }
}

fn raw_identifier(text: &str, at: usize) -> Option<usize> {
    if before(text, at).is_some_and(is_word) || text.as_bytes().get(at + 1) != Some(&b'#') {
        return None;
    }
    let end = word_run(text, at + 2);
    (end > at + 2).then_some(end)
}

fn cooked_string(text: &str, at: usize) -> Option<usize> {
    let mut chars = text[at + 1..].char_indices();
    while let Some((offset, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next()?;
            }
            '"' => return Some(at + 1 + offset + 1),
            _ => {}
        }
    }
    None
}

fn char_literal(text: &str, at: usize) -> Option<usize> {
    let rest = &text[at + 1..];
    let closed = |length: usize| {
        rest[length..]
            .starts_with('\'')
            .then_some(at + 1 + length + 1)
    };
    let hex = |byte: &u8| byte.is_ascii_hexdigit();
    let bytes = rest.as_bytes();
    if bytes.starts_with(b"\\x")
        && bytes.get(2..4).is_some_and(|pair| pair.iter().all(hex))
        && let Some(end) = closed(4)
    {
        return Some(end);
    }
    if bytes.starts_with(b"\\u{") && bytes.get(3).is_some_and(hex) {
        let digits = bytes[4..]
            .iter()
            .take_while(|&&byte| hex(&byte) || byte == b'_')
            .count();
        if bytes.get(4 + digits) == Some(&b'}')
            && let Some(end) = closed(5 + digits)
        {
            return Some(end);
        }
    }
    let mut chars = rest.chars();
    match chars.next()? {
        '\\' => closed(1 + chars.next()?.len_utf8()),
        '\'' | '\n' => None,
        c => closed(c.len_utf8()),
    }
}

fn lifetime(text: &str, at: usize) -> Option<usize> {
    let start = at + 1;
    if text[start..].chars().next().is_none_or(is_digit) {
        return None;
    }
    let open = |from: usize| {
        let end = word_run(text, from);
        (end > from && !text[end..].starts_with('\'')).then_some(end)
    };
    if text[start..].starts_with("r#")
        && let Some(end) = open(start + 2)
    {
        return Some(end);
    }
    open(start)
}
