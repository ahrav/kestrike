//! Production text preserves source offsets and blanks each element under a test-only `cfg` attribute,
//! from the first outer attribute of its run. The scanned text is the production text with comments and
//! literal contents also blanked, as [`code`] gives them. The rules find attributes and element ends in
//! the scanned text, so each attribute and each end they find stands in code.
//! `scripts/classify-atomics.py` holds the same rules for its own callers.
//!
//! Window widths (8 code points before a bracket, 80 before a macro's bracket) count code points of the
//! source. Blanking writes one space per source byte to keep offsets; the rules read any run of spaces as
//! white space.
//!
//! Each pattern compiles with Python's classes. The patterns `ITEM` and `PROVEN` decide whether they
//! match at a start, so each lookahead and each `\b` after a keyword is written as a consumed class that
//! holds where the lookahead or the `\b` holds. [`captures_bounded`] checks the `\b` before a
//! `MACRO_DEFINITION` match.

use std::collections::BTreeSet;
use std::iter;
use std::sync::LazyLock;

use regex::Regex;

use crate::classes::{SPACE, WORD, captures_bounded, compiled};
use crate::rust_text::{back, blank, code};
use crate::text::is_space;

/// Python's `\b` after a word character, consuming the next character or matching the end.
const AFTER_WORD: &str = r"(?:[^\p{L}\p{N}_]|\z)";

fn qualifiers() -> String {
    format!(
        r#"(?:pub(?:\([^)]*\))?{SPACE}+)?(?:(?:const|unsafe|async|extern(?:{SPACE}+"[^"]*")?){SPACE}+)*"#
    )
}

/// Tells a union declaration from `union as` and `union if`, where `union` is an identifier.
fn union() -> String {
    format!(r"union{SPACE}+(?:[A-Z_b-hj-z]|a(?:[^s]|\z)|as{WORD}|i(?:[^f]|\z)|if{WORD})")
}

/// Tells a static item from `static move`, a closure.
fn static_item() -> String {
    format!(r"static{SPACE}+(?:[A-Za-ln-z_]|m(?:[^o]|\z)|mo(?:[^v]|\z)|mov(?:[^e]|\z)|move{WORD})")
}

/// A run of outer attributes that ends in `#[cfg(test)]` or `#[cfg(all(test ...))]`. After `all(test`,
/// the optional suffix starts with a character other than `]` and a word character, which keeps Python's
/// `\b` there.
static RUN: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"(?:#{SPACE}*\[(?:[^\[\]]|\[[^\[\]]*\])*\]{SPACE}*)*#\[cfg\((?:test|all\(test(?:[^\]\p{{L}}\p{{N}}_][^\]]*)?)\)\]"
    ))
});

static ITEM: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"\A{SPACE}*(?:#\[[^\]]*\]{SPACE}*)*{}(?:(?:fn|impl|struct|enum|trait|type|mod|const|static|use){AFTER_WORD}|{})",
        qualifiers(),
        union()
    ))
});

static PROVEN: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"\A{SPACE}*(?:#\[[^\[\]]*\]{SPACE}*)*(?:{}(?:fn{SPACE}+{WORD}|{}|{}|(?:impl|struct|enum|trait|type|mod|use){AFTER_WORD})|(?:let|if|match|while|for|loop|return){AFTER_WORD})",
        qualifiers(),
        union(),
        static_item()
    ))
});

static MACRO_DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r"macro_rules{SPACE}*!{SPACE}*(?:r#)?{WORD}+{SPACE}*\z"
    ))
});

static MACRO_BANG: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"{WORD}{SPACE}*!{SPACE}*\z")));

static ATTRIBUTE_HASH: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"#{SPACE}*!?{SPACE}*\z")));

/// What a test-only element is read as: an item or statement, or an element of a list that ends at its
/// `,` (`Comma`), before a generic parameter list's `>` (`Angle`) or before a closure parameter list's `|`
/// (`Pipe`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Closer {
    Item,
    Comma,
    Angle,
    Pipe,
}

/// A source's production text, its scanned text, and the offset of the first attribute of each element
/// whose end the rules read more than one way ([`Analysis::cut`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Analysis {
    production: String,
    scanned: String,
    cut: Vec<usize>,
}

impl Analysis {
    pub fn production(&self) -> &str {
        &self.production
    }

    /// The production text with comments and literal contents blanked; it equals `code(production)`.
    pub fn scanned(&self) -> &str {
        &self.scanned
    }

    /// Each element counted here may end before its true end and leave the rest of it in the production
    /// text: an element among a macro's tokens that `PROVEN` does not match, an element whose readings
    /// end at different offsets, a reading without an end included, and an element that ends at a `,` that
    /// may be a comma among its own generic arguments or closure parameters.
    pub fn cut(&self) -> &[usize] {
        &self.cut
    }
}

/// The offset just past the brace that closes the block opening at `start`, or `None`. Braces are counted
/// from `start`, and a `start` that holds a character other than a brace closes at once, just past that
/// character.
pub fn closing(text: &str, start: usize) -> Option<usize> {
    if let Some(c) = text.get(start..).and_then(|rest| rest.chars().next())
        && c != '{'
        && c != '}'
    {
        return Some(start + c.len_utf8());
    }
    let mut depth = 0_isize;
    for (index, &byte) in text.as_bytes().iter().enumerate().skip(start) {
        match byte {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => continue,
        }
        if depth == 0 {
            return Some(index + 1);
        }
    }
    None
}

/// The end of the item or statement starting at `start`: its block, or its `;` outside brackets, or for a
/// field, variant, argument or arm, its `,` outside brackets. An item keyword after the attributes and
/// visibility, such as `fn` or `impl`, runs past the commas of its generics to its block or `;`. A closing
/// bracket or brace that the item never opened belongs to the enclosing list or block, so a last element
/// without a trailing comma ends before it. Under [`Closer::Angle`] or [`Closer::Pipe`] the element ends at
/// its `,` or before the list's `>` or `|`; under [`Closer::Comma`] it ends at its `,` whatever word starts
/// it. `start` is a code point boundary.
pub fn item_end(text: &str, start: usize, closer: Closer) -> Option<usize> {
    let item = closer == Closer::Item && ITEM.is_match(&text[start..]);
    let tracked = matches!(closer, Closer::Angle | Closer::Pipe);
    let bytes = text.as_bytes();
    let (mut parens, mut angle) = (0_usize, 0_usize);
    for index in start..bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b'(' | b'[') {
            parens += 1;
        } else if (matches!(byte, b')' | b']') && parens == 0) || byte == b'}' {
            return Some(index);
        } else if matches!(byte, b')' | b']') {
            parens -= 1;
        } else if tracked && parens == 0 && byte == b'<' {
            angle += 1;
        } else if tracked
            && parens == 0
            && byte == b'>'
            && !(index > 0 && matches!(bytes[index - 1], b'-' | b'='))
        {
            if angle == 0 && closer == Closer::Angle {
                return Some(index);
            }
            angle = angle.saturating_sub(1);
        } else if closer == Closer::Pipe && parens == 0 && angle == 0 && byte == b'|' {
            return Some(index);
        } else if byte == b'{' {
            return closing(text, index);
        } else if parens == 0 && angle == 0 && (byte == b';' || (byte == b',' && !item)) {
            return Some(index + 1);
        }
    }
    None
}

/// The closers [`item_end`] reads the test-only element at `start` under, from the text before its
/// attributes. `text` is the scanned text of `source`.
///
/// Directly after `{`, `}`, `;` or the start of `text` the element is an item, a statement or the first
/// element of a braced list. No parameter list is open there, so it is read once, as an item or statement.
/// Anywhere else it is an element of a list: it is read to its `,`, as a generic parameter when a `<` lies
/// outside brackets between it and the bracket or `;` its list follows, and as a closure parameter when a
/// `|` lies there, since a parameter list's own opener lies in that stretch.
fn readings(text: &str, source: &str, start: usize) -> Vec<Closer> {
    let (mut depth, mut direct) = (0_usize, true);
    let (mut angle, mut pipe) = (false, false);
    let before = text[..start].char_indices().rev();
    for (index, c) in before.chain(iter::once((0, ';'))) {
        if matches!(c, ')' | ']' | '}') {
            if direct && depth == 0 && c == '}' {
                return vec![Closer::Item];
            }
            depth += 1;
        } else if matches!(c, '(' | '[' | '{') {
            if depth == 0 {
                if direct && c == '{' {
                    return vec![Closer::Item];
                }
                break;
            }
            depth -= 1;
            direct = direct
                && (depth > 0
                    || (c == '[' && ATTRIBUTE_HASH.is_match(&text[back(source, index, 8)..index])));
        } else if depth > 0 || is_space(u32::from(c)) || (direct && matches!(c, '#' | '!')) {
            continue;
        } else if c == ';' {
            if direct {
                return vec![Closer::Item];
            }
            break;
        } else {
            direct = false;
            angle |= c == '<';
            pipe |= c == '|';
        }
    }
    let mut closers = vec![Closer::Comma];
    closers.extend(angle.then_some(Closer::Angle));
    closers.extend(pipe.then_some(Closer::Pipe));
    closers
}

/// The (opening bracket, closing bracket) offsets of the tokens of each macro definition and invocation of
/// `text`, the scanned text of `source`: each bracket pair that follows `name!` or `macro_rules! name`
/// within 80 code points.
fn macro_spans(text: &str, source: &str) -> Vec<(usize, usize)> {
    let (mut spans, mut stack) = (Vec::new(), Vec::new());
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => stack.push(follows_bang(text, source, index).then_some(index)),
            b')' | b']' | b'}' => {
                if let Some(Some(opened)) = stack.pop() {
                    spans.push((opened, index));
                }
            }
            _ => {}
        }
    }
    spans
}

fn follows_bang(text: &str, source: &str, bracket: usize) -> bool {
    let (window, from) = (&text[..bracket], back(source, bracket, 80));
    MACRO_BANG.find_at(window, from).is_some()
        || captures_bounded(&MACRO_DEFINITION, window, from).is_some()
}

/// Whether the element of `text` from `start` to `end` ends at a `,` that may be a comma among its own
/// generic arguments or closure parameters: any `,` that ends a statement `PROVEN` matches, and
/// otherwise one a `<` of the element is still open at, or one after a `|` that follows the element's
/// last `=>`.
fn own_comma(text: &str, start: usize, end: usize, proven: bool) -> bool {
    let tail = text[start..end]
        .rfind("=>")
        .map_or(start.max(1), |found| start + found + 2);
    text.as_bytes()[end - 1] == b','
        && (proven
            || item_end(text, tail, Closer::Angle).unwrap_or(text.len()) > end
            || item_end(text, tail, Closer::Pipe) != Some(end))
}

/// The [`Analysis`] of `text`.
///
/// An element `PROVEN` matches is read once, as an item or statement; `union` followed by `as` or `if`,
/// or by no name, is an identifier. Any other element is read under the closers `readings` selects, or
/// under every closer when it lies among the tokens of a macro, whose expansion decides what the element
/// is. The element ends at the earliest end, so the code after it stays in the production text. An
/// attribute inside an element already blanked adds no cut. Every run ends in a `#[cfg(` attribute, so a
/// text without one blanks nothing.
pub fn analyzed(text: &str) -> Analysis {
    let masked = code(text);
    let (mut spans, mut cut, mut covered) = (Vec::new(), Vec::new(), 0);
    let mut macros = None;
    let runs = masked
        .contains("#[cfg(")
        .then(|| RUN.find_iter(&masked))
        .into_iter()
        .flatten();
    for attribute in runs {
        let start = attribute.end();
        let proven = PROVEN.is_match(&masked[start..]);
        if macros.is_none() && !proven {
            macros = Some(macro_spans(&masked, text));
        }
        let inside = !proven
            && macros
                .iter()
                .flatten()
                .any(|&(low, high)| low < start && start < high);
        let closers = if proven {
            vec![Closer::Item]
        } else if inside {
            vec![Closer::Item, Closer::Comma, Closer::Angle, Closer::Pipe]
        } else {
            readings(&masked, text, start)
        };
        let ends: BTreeSet<Option<usize>> = closers
            .iter()
            .map(|&closer| item_end(&masked, start, closer))
            .collect();
        let end = ends.iter().flatten().min().copied();
        if attribute.start() >= covered {
            covered = end.unwrap_or(covered);
            if inside
                || ends.len() > 1
                || end.is_some_and(|end| own_comma(&masked, start, end, proven))
            {
                cut.push(attribute.start());
            }
        }
        if let Some(end) = end {
            spans.push((attribute.start(), end));
        }
    }
    if spans.is_empty() {
        return Analysis {
            production: text.to_owned(),
            scanned: masked,
            cut,
        };
    }
    Analysis {
        production: spliced(text, &spans),
        scanned: spliced(&masked, &spans),
        cut,
    }
}

/// `text` with every byte other than a newline inside one of the `(start, end)` spans replaced by a space,
/// offsets kept. The spans may nest or overlap, so each run of overlapping spans blanks once. Each span's
/// ends are code point boundaries of `text`.
pub fn spliced(text: &str, spans: &[(usize, usize)]) -> String {
    let mut sorted = spans.to_vec();
    sorted.sort_unstable();
    let (mut pieces, mut at) = (String::with_capacity(text.len()), 0);
    for (start, end) in sorted {
        if end <= at {
            continue;
        }
        let start = start.max(at);
        pieces.push_str(&text[at..start]);
        pieces.push_str(&blank(&text[start..end]));
        at = end;
    }
    pieces.push_str(&text[at..]);
    pieces
}

/// The production text and the scanned text of `text`.
pub fn blanked(text: &str) -> (String, String) {
    let Analysis {
        production,
        scanned,
        ..
    } = analyzed(text);
    (production, scanned)
}

#[cfg(test)]
#[path = "production_text_tests.rs"]
mod tests;
