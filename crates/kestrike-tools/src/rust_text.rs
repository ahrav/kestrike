//! `lexemes` locates the comments, string literals and char literals of Rust source as byte spans, and
//! `code` blanks them with one space for each byte, keeping each newline, so an offset of the view is the
//! same offset of the source.

use std::sync::LazyLock;

use regex::Regex;

use crate::classes::{SPACE, WORD, compiled, is_digit, is_word};

pub static IGNORE: LazyLock<Regex> = LazyLock::new(|| {
    // `edge` matches a Python `\W` separator beside `ignore` within the attribute, a character outside
    // [`WORD`] and other than `]`, which ends the attribute.
    let edge = format!(r"[^\]{WORD}]");
    let after = format!(r"ignore(?:\]|{edge}[^\]]*\])");
    compiled(&format!(
        r"#\[{after}|#\[cfg_attr\((?:[^\]]*{edge})?{after}"
    ))
});

pub static FUNCTION: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"(?:#\[[^\]]*\]{SPACE}*)*(?:pub(?:\([^)]*\))?{SPACE}+)?(?:async{SPACE}+)?fn{SPACE}+(?:r#)?{WORD}+"
    ))
});

static BLOCK_EDGE: LazyLock<Regex> = LazyLock::new(|| compiled(r"/\*|\*/"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lexeme {
    Comment,
    String,
    Char,
    Unclosed,
}

#[derive(Clone, Copy)]
enum Token {
    LineComment,
    BlockOpen,
    String,
    Char,
    Code,
}

/// `lexemes` returns each comment, string literal and char literal of `text` in order. Block comments nest,
/// and one that never closes is [`Lexeme::Unclosed`] and ends at the end of `text`.
pub fn lexemes(text: &str) -> Vec<(Lexeme, usize, usize)> {
    let mut found = Vec::new();
    let mut start = 0;
    while let Some((token, at, end)) = next_token(text, start) {
        start = end;
        let kind = match token {
            Token::BlockOpen => match block_comment_end(text, end) {
                Some(close) => {
                    start = close;
                    Lexeme::Comment
                }
                None => {
                    start = text.len();
                    Lexeme::Unclosed
                }
            },
            Token::LineComment => Lexeme::Comment,
            Token::String => Lexeme::String,
            Token::Char => Lexeme::Char,
            Token::Code => continue,
        };
        found.push((kind, at, start));
    }
    found
}

fn block_comment_end(text: &str, mut at: usize) -> Option<usize> {
    let mut depth = 1_usize;
    while depth > 0 {
        let edge = BLOCK_EDGE.find_at(text, at)?;
        depth = if edge.as_str() == "/*" {
            depth + 1
        } else {
            depth - 1
        };
        at = edge.end();
    }
    Some(at)
}

pub fn blank(text: &str) -> String {
    text.bytes()
        .map(|byte| if byte == b'\n' { '\n' } else { ' ' })
        .collect()
}

/// The offset `count` code points of `source` before `at`, or 0 when fewer stand there. `at` is a code
/// point boundary of `source`.
pub fn back(source: &str, at: usize, count: usize) -> usize {
    match count.checked_sub(1) {
        None => at,
        Some(last) => source[..at]
            .char_indices()
            .rev()
            .nth(last)
            .map_or(0, |(offset, _)| offset),
    }
}

/// The offset `count` code points of `source` after `at`, or the end of `source` when fewer stand there.
/// `at` is a code point boundary of `source`.
pub fn ahead(source: &str, at: usize, count: usize) -> usize {
    source[at..]
        .char_indices()
        .nth(count)
        .map_or(source.len(), |(offset, _)| at + offset)
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

fn next_token(text: &str, start: usize) -> Option<(Token, usize, usize)> {
    let bytes = text.as_bytes();
    let mut at = start;
    while at < bytes.len() {
        let found = match bytes[at] {
            b'/' => match bytes.get(at + 1) {
                Some(b'/') => {
                    let end = text[at..]
                        .find('\n')
                        .map_or(text.len(), |offset| at + offset);
                    Some((Token::LineComment, end))
                }
                Some(b'*') => Some((Token::BlockOpen, at + 2)),
                _ => None,
            },
            b'r' => raw_string(text, at)
                .map(|end| (Token::String, end))
                .or_else(|| raw_identifier(text, at).map(|end| (Token::Code, end))),
            b'"' => cooked_string(text, at).map(|end| (Token::String, end)),
            b'\'' => char_literal(text, at)
                .map(|end| (Token::Char, end))
                .or_else(|| lifetime(text, at).map(|end| (Token::Code, end))),
            _ => None,
        };
        if let Some((token, end)) = found {
            return Some((token, at, end));
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

#[cfg(test)]
#[path = "rust_text_tests.rs"]
mod tests;
