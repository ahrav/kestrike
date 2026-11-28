//! Text as Python's `str` holds it: a sequence of code points, each a Unicode scalar value or a lone
//! surrogate.
//!
//! A [`Text`] stores Unicode scalar values as UTF-8 and extends the three-byte encoding pattern to the
//! surrogates U+D800 to U+DFFF. Byte order of that encoding is code point order, so texts order and compare by
//! code point as Python's `str` does. Unix arguments, paths and environment variables carry bytes: each byte
//! outside a UTF-8 sequence becomes the surrogate U+DC80 to U+DCFF, as Python's `surrogateescape` decodes
//! it, and [`Text::to_os`] turns that surrogate back into the byte.
//!
//! The whitespace rules are Python's: [`is_space`] holds for the characters `str.isspace()` takes, and
//! [`Text::strip`], [`Text::split`] and [`Text::splitlines`] apply them as `str.strip()`, `str.split()` and
//! `str.splitlines()` do with no argument.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text(Vec<u8>);

/// The assigned code points that Python 3.9.25's `str.isprintable()` classifies as nonprintable under
/// Unicode 13.0: the categories Cc, Cf, Cs, Co, Zl and Zp, and the Zs code points from U+00A0 up.
/// [`Text::repr`] writes unassigned code points verbatim. Python escapes them. The set of unassigned code
/// points varies by Unicode release.
const UNPRINTABLE: [(u32, u32); 27] = [
    (0x0, 0x1f),
    (0x7f, 0xa0),
    (0xad, 0xad),
    (0x600, 0x605),
    (0x61c, 0x61c),
    (0x6dd, 0x6dd),
    (0x70f, 0x70f),
    (0x8e2, 0x8e2),
    (0x1680, 0x1680),
    (0x180e, 0x180e),
    (0x2000, 0x200f),
    (0x2028, 0x202f),
    (0x205f, 0x2064),
    (0x2066, 0x206f),
    (0x3000, 0x3000),
    (0xd800, 0xf8ff),
    (0xfeff, 0xfeff),
    (0xfff9, 0xfffb),
    (0x110bd, 0x110bd),
    (0x110cd, 0x110cd),
    (0x13430, 0x13438),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0001, 0xe0001),
    (0xe0020, 0xe007f),
    (0xf0000, 0xffffd),
    (0x100000, 0x10fffd),
];

/// Whether `str.isspace()` holds for the code point: the Unicode `White_Space` characters and U+001C to
/// U+001F.
pub fn is_space(code: u32) -> bool {
    char::from_u32(code).is_some_and(|c| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// `strip_str` trims leading and trailing whitespace, including U+001C through U+001F.
pub fn strip_str(text: &str) -> &str {
    text.trim_matches(|c: char| is_space(u32::from(c)))
}

pub fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| is_space(u32::from(c)))
        .filter(|word| !word.is_empty())
}

/// Whether `str.splitlines()` ends a line at the code point.
fn is_line_break(code: u32) -> bool {
    matches!(code, 0xa..=0xd | 0x1c..=0x1e | 0x85 | 0x2028 | 0x2029)
}

fn is_surrogate(code: u32) -> bool {
    (0xd800..=0xdfff).contains(&code)
}

fn is_unprintable(code: u32) -> bool {
    let at = UNPRINTABLE.partition_point(|&(_, high)| high < code);
    UNPRINTABLE.get(at).is_some_and(|&(low, _)| low <= code)
}

/// Appends `code`, at most U+10FFFF, to `bytes` in the encoding [`Text`] keeps.
fn encode(code: u32, bytes: &mut Vec<u8>) {
    match char::from_u32(code) {
        Some(scalar) => bytes.extend_from_slice(scalar.encode_utf8(&mut [0; 4]).as_bytes()),
        None => bytes.extend([
            0xe0 | (code >> 12) as u8,
            0x80 | ((code >> 6) & 0x3f) as u8,
            0x80 | (code & 0x3f) as u8,
        ]),
    }
}

/// The first code point of `bytes`, which hold whole code points in the encoding [`Text`] keeps, and its
/// length in bytes.
fn decode(bytes: &[u8]) -> (u32, usize) {
    let tail = |count: usize| {
        bytes[1..count]
            .iter()
            .fold(0, |code, &byte| (code << 6) | u32::from(byte & 0x3f))
    };
    match bytes[0] {
        lead @ 0..0x80 => (u32::from(lead), 1),
        lead @ 0xc0..0xe0 => ((u32::from(lead & 0x1f) << 6) | tail(2), 2),
        lead @ 0xe0..0xf0 => ((u32::from(lead & 0x0f) << 12) | tail(3), 3),
        lead => ((u32::from(lead & 0x07) << 18) | tail(4), 4),
    }
}

/// `push_repr` appends `code` as [`Text::repr`] writes it inside the quotes. The caller escapes the quote
/// character.
pub(crate) fn push_repr(code: u32, out: &mut String) {
    match code {
        0x5c => out.push_str("\\\\"),
        0x9 => out.push_str("\\t"),
        0xa => out.push_str("\\n"),
        0xd => out.push_str("\\r"),
        _ if !is_unprintable(code) => out.extend(char::from_u32(code)),
        0..0x100 => out.push_str(&format!("\\x{code:02x}")),
        0x100..0x1_0000 => out.push_str(&format!("\\u{code:04x}")),
        _ => out.push_str(&format!("\\U{code:08x}")),
    }
}

/// `escaped` keeps a field that holds embedded CR or LF characters on one output line.
pub(crate) fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for code in text.chars() {
        if matches!(code, '\0'..='\x1f' | '\x7f'..='\u{9f}') {
            push_repr(u32::from(code), &mut out);
        } else {
            out.push(code);
        }
    }
    out
}

/// `push_backslashed` matches Python's UTF-8 `backslashreplace` handler: it appends a scalar value as it is
/// and a surrogate as `\udXXX`.
pub(crate) fn push_backslashed(code: u32, out: &mut String) {
    match char::from_u32(code) {
        Some(scalar) => out.push(scalar),
        None => out.push_str(&format!("\\u{code:04x}")),
    }
}

impl Text {
    pub fn new() -> Self {
        Self::default()
    }

    /// `from_code_points` returns `None` if any code point exceeds U+10FFFF.
    pub fn from_code_points(codes: impl IntoIterator<Item = u32>) -> Option<Self> {
        let mut text = Self::new();
        for code in codes {
            text.push_code_point(code)?;
        }
        Some(text)
    }

    /// If `code` exceeds U+10FFFF, `push_code_point` returns `None` and preserves the text.
    #[must_use]
    pub fn push_code_point(&mut self, code: u32) -> Option<()> {
        (code <= 0x10_ffff).then(|| encode(code, &mut self.0))
    }

    pub fn push_str(&mut self, text: &str) {
        self.0.extend_from_slice(text.as_bytes());
    }

    pub fn push_text(&mut self, text: &Text) {
        self.0.extend_from_slice(&text.0);
    }

    /// `from_os` decodes as Python's `os.fsdecode` does under a UTF-8 locale with `surrogateescape`: each
    /// valid UTF-8 sequence becomes its scalar value and each other byte the surrogate U+DC00 plus the byte.
    pub fn from_os(bytes: &OsStr) -> Self {
        let mut text = Self::new();
        for chunk in bytes.as_bytes().utf8_chunks() {
            text.0.extend_from_slice(chunk.valid().as_bytes());
            for &byte in chunk.invalid() {
                encode(0xdc00 | u32::from(byte), &mut text.0);
            }
        }
        text
    }

    /// `to_os` encodes as Python's `os.fsencode` does under a UTF-8 locale with `surrogateescape`: each
    /// scalar value becomes its UTF-8 bytes and each surrogate U+DC80 to U+DCFF its low byte. It returns
    /// `None` for a text that holds another surrogate, which `os.fsencode` refuses.
    pub fn to_os(&self) -> Option<OsString> {
        let mut bytes = Vec::with_capacity(self.0.len());
        for code in self.code_points() {
            match code {
                0xdc80..=0xdcff => bytes.push((code & 0xff) as u8),
                _ if is_surrogate(code) => return None,
                _ => encode(code, &mut bytes),
            }
        }
        Some(OsString::from_vec(bytes))
    }

    /// `to_str` returns `None` when the text holds a surrogate.
    pub fn to_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// `rpartition` returns the text before the last `separator` and the text after it, or an empty text and
    /// the whole text when `separator` is absent.
    ///
    /// # Panics
    ///
    /// `rpartition` panics if `separator` is not ASCII. A byte of 0x80 or more stands inside the encoding of a
    /// code point, and an ASCII byte is a whole code point.
    pub fn rpartition(&self, separator: u8) -> (Self, Self) {
        assert!(separator.is_ascii(), "the separator is one ASCII byte");
        match self.0.iter().rposition(|&byte| byte == separator) {
            Some(at) => (self.slice(0, at), self.slice(at + 1, self.0.len())),
            None => (Self::new(), self.clone()),
        }
    }

    pub fn code_points(&self) -> impl Iterator<Item = u32> + '_ {
        self.spans().map(|(_, _, code)| code)
    }

    /// `spans` yields each code point with its start and end byte offsets.
    fn spans(&self) -> impl Iterator<Item = (usize, usize, u32)> + '_ {
        let mut at = 0;
        std::iter::from_fn(move || {
            let rest = self.0.get(at..).filter(|rest| !rest.is_empty())?;
            let (code, length) = decode(rest);
            at += length;
            Some((at - length, at, code))
        })
    }

    /// `len` counts code points, as Python's `len` does.
    pub fn len(&self) -> usize {
        self.code_points().count()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn slice(&self, start: usize, end: usize) -> Self {
        Self(self.0[start..end].to_vec())
    }

    /// `strip` matches `str.strip()`: it keeps the text from its first to its last code point for which
    /// [`is_space`] is false.
    pub fn strip(&self) -> Self {
        let mut kept = self.spans().filter(|&(_, _, code)| !is_space(code));
        let Some((start, mut end, _)) = kept.next() else {
            return Self::new();
        };
        if let Some((_, last, _)) = kept.last() {
            end = last;
        }
        self.slice(start, end)
    }

    /// `split` matches `str.split()`: it returns the maximal runs of code points for which [`is_space`] is
    /// false, in order.
    pub fn split(&self) -> Vec<Self> {
        let mut words = Vec::new();
        let mut start = None;
        for (at, _, code) in self.spans() {
            match (is_space(code), start) {
                (true, Some(first)) => {
                    words.push(self.slice(first, at));
                    start = None;
                }
                (false, None) => start = Some(at),
                _ => {}
            }
        }
        if let Some(first) = start {
            words.push(self.slice(first, self.0.len()));
        }
        words
    }

    /// `splitlines` follows Python's `str.splitlines()`: `\r\n` counts as one terminator, and
    /// `is_line_break` identifies the single-code-point terminators. Each line excludes its terminator.
    pub fn splitlines(&self) -> Vec<Self> {
        let mut lines = Vec::new();
        let mut start = 0;
        let mut after_cr = false;
        for (at, end, code) in self.spans() {
            if after_cr && code == 0xa {
                start = end;
            } else if is_line_break(code) {
                lines.push(self.slice(start, at));
                start = end;
            }
            after_cr = code == 0xd;
        }
        if start < self.0.len() {
            lines.push(self.slice(start, self.0.len()));
        }
        lines
    }

    /// `join` writes `items` in order with `separator` between each two.
    pub fn join<'a>(separator: &str, items: impl IntoIterator<Item = &'a Text>) -> Self {
        let mut joined = Self::new();
        for (at, item) in items.into_iter().enumerate() {
            if at > 0 {
                joined.push_str(separator);
            }
            joined.push_text(item);
        }
        joined
    }

    /// `repr` writes the text between single quotes, or between double quotes when it holds `'` and no `"`;
    /// it writes a backslash, a tab, a line feed and a carriage return as their backslash escapes, and each
    /// code point that the Unicode 13.0 data marks nonprintable as `\xXX`, `\uXXXX` or `\UXXXXXXXX`. An
    /// unassigned code point, such as U+0378, is written as it is.
    pub fn repr(&self) -> String {
        let quote = if self.0.contains(&b'\'') && !self.0.contains(&b'"') {
            '"'
        } else {
            '\''
        };
        let mut out = String::from(quote);
        for code in self.code_points() {
            if code == u32::from(quote) {
                out.push('\\');
                out.push(quote);
            } else {
                push_repr(code, &mut out);
            }
        }
        out.push(quote);
        out
    }
}

/// `Display` follows Python's UTF-8 `backslashreplace` policy: it writes each scalar value verbatim and each
/// surrogate as `\udXXX`.
impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::with_capacity(self.0.len());
        for code in self.code_points() {
            push_backslashed(code, &mut out);
        }
        f.write_str(&out)
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.repr())
    }
}

impl From<&str> for Text {
    fn from(text: &str) -> Self {
        Self(text.as_bytes().to_vec())
    }
}

impl From<String> for Text {
    fn from(text: String) -> Self {
        Self(text.into_bytes())
    }
}

impl PartialEq<&str> for Text {
    fn eq(&self, other: &&str) -> bool {
        self.0 == other.as_bytes()
    }
}

/// A part of a [`Text`] that [`text!`] builds: a string, a text that may hold a lone surrogate, or a path or an
/// operating-system string, which enters as [`Text::from_os`] decodes it.
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

/// `text!(a, b, ...)` is the [`Text`] of its pieces in order.
#[cfg(target_os = "linux")]
macro_rules! text {
    ($($piece:expr),+ $(,)?) => {{
        let mut text = $crate::text::Text::new();
        $( $crate::text::Piece::push_to(&$piece, &mut text); )+
        text
    }};
}

#[cfg(target_os = "linux")]
pub(crate) use text;

#[cfg(test)]
#[path = "text_tests.rs"]
mod tests;
