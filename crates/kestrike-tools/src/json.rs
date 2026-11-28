//! A JSON reader that preserves document order, and the writers [`text`], [`dump`] and [`indented`].
//!
//! Beyond strict JSON, [`parse`] takes `NaN`, `Infinity` and `-Infinity` as non-finite floats, reads a float
//! that overflows as an infinity, and keeps an unmatched surrogate escape as a lone surrogate while it joins an
//! escaped high and low surrogate pair into one scalar. A repeated key keeps its first position and takes its
//! last value, and `-0` reads as the integer zero; [`parse_unique`] refuses a repeated key instead.
//! [`parse_strict`] also refuses the three constants and a fractional number whose decimal value is not
//! the shortest form of a finite double, so each float it reads stands for the decimal the text spells.
//! The reader refuses nesting past [`MAX_DEPTH`] and an integer
//! token of more than [`MAX_INTEGER_DIGITS`] digits. The compact writers write non-finite floats as `NaN`,
//! `Infinity` and `-Infinity`, which strict JSON readers refuse; [`indented`] refuses them.

use std::cmp::Ordering;
use std::fmt;

use crate::decimal::{nearest_double, spells_shortest};
use crate::python::repr_float;
pub use crate::text::Text;

/// The deepest nesting of arrays and objects the reader takes.
pub const MAX_DEPTH: usize = 1000;

/// The most decimal digits an integer token of [`parse`] and an [`Integer`] hold.
pub const MAX_INTEGER_DIGITS: usize = 4300;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Object(Object),
    Array(Vec<Value>),
    String(Text),
    Integer(Integer),
    Float(f64),
    Bool(bool),
    Null,
}

/// An integer of at most [`MAX_INTEGER_DIGITS`] decimal digits, held as its sign and its digits without
/// leading zeros, so each writer emits only integers that [`parse`] reads back.
///
/// Zero has `negative == false` and `digits == "0"`, so each integer has one representation and [`Ord`]
/// compares integers numerically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Integer {
    negative: bool,
    digits: String,
}

impl Integer {
    /// The integer that `negative` and the ASCII decimal `digits` spell, or `None` when `digits` is empty or
    /// holds a byte other than a digit, or when more than [`MAX_INTEGER_DIGITS`] digits remain after
    /// `from_digits` strips leading zeros. All-zero digits give zero whatever `negative` says.
    pub fn from_digits(negative: bool, digits: &str) -> Option<Self> {
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let digits = digits.trim_start_matches('0');
        if digits.len() > MAX_INTEGER_DIGITS {
            return None;
        }
        Some(if digits.is_empty() {
            Self {
                negative: false,
                digits: "0".to_owned(),
            }
        } else {
            Self {
                negative,
                digits: digits.to_owned(),
            }
        })
    }
}

impl From<u64> for Integer {
    fn from(value: u64) -> Self {
        Self {
            negative: false,
            digits: value.to_string(),
        }
    }
}

impl From<usize> for Integer {
    fn from(value: usize) -> Self {
        Self {
            negative: false,
            digits: value.to_string(),
        }
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        f.write_str(&self.digits)
    }
}

impl Ord for Integer {
    fn cmp(&self, other: &Self) -> Ordering {
        let magnitude = || {
            self.digits
                .len()
                .cmp(&other.digits.len())
                .then_with(|| self.digits.cmp(&other.digits))
        };
        match (self.negative, other.negative) {
            (false, false) => magnitude(),
            (true, true) => magnitude().reverse(),
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
        }
    }
}

impl PartialOrd for Integer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A JSON object: its members in order, each key once.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Object(Vec<(Text, Value)>);

impl Object {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.0
            .iter_mut()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    }

    /// Replaces an existing key's value in place or appends a new member.
    pub fn insert(&mut self, key: impl Into<Text>, value: Value) {
        let key = key.into();
        match self.0.iter_mut().find(|(name, _)| *name == key) {
            Some((_, slot)) => *slot = value,
            None => self.0.push((key, value)),
        }
    }

    /// The remaining members keep their relative order.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let at = self.0.iter().position(|(name, _)| *name == key)?;
        Some(self.0.remove(at).1)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &(Text, Value)> {
        self.0.iter()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    offset: usize,
    reason: &'static str,
}

impl Error {
    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

/// `parse` accepts one value surrounded by optional JSON whitespace.
///
/// # Errors
///
/// `parse` returns an error for text that is no JSON value of the forms the module states, for nesting past
/// [`MAX_DEPTH`], for an integer token of more than [`MAX_INTEGER_DIGITS`] digits, and when a
/// non-whitespace byte follows the value. A successful parse can hold a non-finite float.
pub fn parse(text: &str) -> Result<Value, Error> {
    Reader::new(text, Mode::Keep)
        .document()
        .map_err(|error| match error {
            StrictError::Syntax(error) => error,
            StrictError::Repeated(_) | StrictError::Number(_) => {
                unreachable!("a read that keeps repeated keys and every number refuses neither")
            }
        })
}

/// A refusal of [`parse_unique`]: an error of [`parse`], or an object that repeats the member `name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UniqueError {
    Syntax(Error),
    Repeated(Text),
}

impl fmt::Display for UniqueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => error.fmt(f),
            Self::Repeated(name) => write!(f, "repeated member {name}"),
        }
    }
}

impl std::error::Error for UniqueError {}

/// `parse_unique` reads what [`parse`] reads and refuses an object that holds a key twice.
///
/// Each object is judged when its closing `}` is read, so a syntax error inside an object, and a repeat
/// in an object nested within it, comes first. The name refused is the first key of the object that
/// repeats an earlier one.
///
/// # Errors
///
/// The reader stops at the first object to close that repeats a key and returns
/// [`UniqueError::Repeated`]; a syntax or limit error the reader meets before that close is
/// [`UniqueError::Syntax`]. So a repeat followed by trailing text is [`UniqueError::Repeated`], where
/// [`parse`] refuses the trailing text.
pub fn parse_unique(text: &str) -> Result<Value, UniqueError> {
    Reader::new(text, Mode::Unique)
        .document()
        .map_err(|error| match error {
            StrictError::Syntax(error) => UniqueError::Syntax(error),
            StrictError::Repeated(name) => UniqueError::Repeated(name),
            StrictError::Number(_) => unreachable!("a read that keeps every number refuses none"),
        })
}

/// A number that strict JSON refuses, holding the token as the text spells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unnumber {
    /// `NaN`, `Infinity` or `-Infinity`.
    Constant(&'static str),
    /// A token with a fraction or an exponent whose nearest double is infinite.
    Range(String),
    /// A token with a fraction or an exponent whose decimal value differs from the shortest form of its
    /// nearest double, or whose exponent lies past the range of Python's `decimal` module.
    Digits(String),
}

/// A refusal of [`parse_strict`]: an error of [`parse`], an object that repeats the member `name`, or a
/// number strict JSON refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrictError {
    Syntax(Error),
    Repeated(Text),
    Number(Unnumber),
}

/// The words of a refusal of a repeat and of a number: `an object repeats a key`, `the constant NaN is no
/// number`, `the number 1e999 is beyond a double's range` and `the number 0.10000000000000001 holds more
/// digits than a double carries`.
impl fmt::Display for StrictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => error.fmt(f),
            Self::Repeated(_) => f.write_str("an object repeats a key"),
            Self::Number(Unnumber::Constant(token)) => {
                write!(f, "the constant {token} is no number")
            }
            Self::Number(Unnumber::Range(token)) => {
                write!(f, "the number {token} is beyond a double's range")
            }
            Self::Number(Unnumber::Digits(token)) => {
                write!(
                    f,
                    "the number {token} holds more digits than a double carries"
                )
            }
        }
    }
}

impl std::error::Error for StrictError {}

/// `parse_strict` reads what [`parse_unique`] reads and refuses `NaN`, `Infinity`, `-Infinity`, and a
/// number with a fraction or an exponent unless its decimal value is the shortest form of a finite double.
/// A refused number reads as [`StrictError::Number`]; `1E2`, `0.1` and `-0.0` read as the floats they
/// spell, and `-0` reads as the integer zero.
///
/// # Errors
///
/// The reader stops at the first refusal in document order. A number is judged where it stands and a
/// repeated key when its object closes, so in `[{"k": 1, "k": 2}, NaN]` the repeat comes first and in
/// `{"k": 1, "k": NaN}` the constant does.
pub fn parse_strict(text: &str) -> Result<Value, StrictError> {
    Reader::new(text, Mode::Strict).document()
}

struct Reader<'a> {
    text: &'a [u8],
    at: usize,
    mode: Mode,
}

/// What ends a read beyond a syntax or limit error.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Nothing more: a repeated key takes its last value.
    Keep,
    /// A repeated key.
    Unique,
    /// A repeated key, and a number [`parse_strict`] refuses.
    Strict,
}

impl<'a> Reader<'a> {
    fn new(text: &'a str, mode: Mode) -> Self {
        Self {
            text: text.as_bytes(),
            at: 0,
            mode,
        }
    }

    fn document(&mut self) -> Result<Value, StrictError> {
        self.space();
        let value = self.value(0)?;
        self.space();
        if self.at != self.text.len() {
            return Err(self.error("text after the value"));
        }
        Ok(value)
    }

    fn error(&self, reason: &'static str) -> StrictError {
        StrictError::Syntax(error_at(self.at, reason))
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn rest_starts_with(&self, word: &[u8]) -> bool {
        self.text[self.at..].starts_with(word)
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &[u8]) -> bool {
        let found = self.rest_starts_with(word);
        if found {
            self.at += word.len();
        }
        found
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    fn value(&mut self, depth: usize) -> Result<Value, StrictError> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Value::String(self.string()?)),
            _ if self.literal(b"null") => Ok(Value::Null),
            _ if self.literal(b"true") => Ok(Value::Bool(true)),
            _ if self.literal(b"false") => Ok(Value::Bool(false)),
            _ if self.literal(b"NaN") => self.constant("NaN", f64::NAN),
            _ if self.literal(b"Infinity") => self.constant("Infinity", f64::INFINITY),
            _ if self.literal(b"-Infinity") => self.constant("-Infinity", f64::NEG_INFINITY),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("expected a value")),
        }
    }

    fn constant(&self, token: &'static str, value: f64) -> Result<Value, StrictError> {
        if self.mode == Mode::Strict {
            return Err(StrictError::Number(Unnumber::Constant(token)));
        }
        Ok(Value::Float(value))
    }

    fn nest(&mut self, depth: usize) -> Result<(), StrictError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting deeper than the reader takes"));
        }
        self.at += 1;
        self.space();
        Ok(())
    }

    /// Consumes `,` and the whitespace after it, or `close`, and returns whether `close` ended the list.
    fn separator(&mut self, close: u8, reason: &'static str) -> Result<bool, StrictError> {
        match self.peek() {
            Some(b',') => {
                self.at += 1;
                self.space();
                Ok(false)
            }
            Some(byte) if byte == close => {
                self.at += 1;
                Ok(true)
            }
            _ => Err(self.error(reason)),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, StrictError> {
        self.nest(depth)?;
        let mut object = Object::new();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(object));
        }
        let mut repeated = None;
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a key"));
            }
            let key = self.string()?;
            self.space();
            if self.peek() != Some(b':') {
                return Err(self.error("expected ':'"));
            }
            self.at += 1;
            self.space();
            let value = self.value(depth)?;
            if self.mode != Mode::Keep
                && repeated.is_none()
                && object.iter().any(|(name, _)| *name == key)
            {
                repeated = Some(key.clone());
            }
            object.insert(key, value);
            self.space();
            if self.separator(b'}', "expected ',' or '}'")? {
                if let Some(name) = repeated {
                    return Err(StrictError::Repeated(name));
                }
                return Ok(Value::Object(object));
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, StrictError> {
        self.nest(depth)?;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.space();
            if self.separator(b']', "expected ',' or ']'")? {
                return Ok(Value::Array(items));
            }
        }
    }

    fn number(&mut self) -> Result<Value, StrictError> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        let digits = self.at;
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.error("expected a digit")),
        }
        let integer = self.at;
        if self.peek() == Some(b'.') && self.text.get(self.at + 1).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mark = self.at;
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                self.at = mark;
            }
        }
        let text = std::str::from_utf8(&self.text[start..self.at]).expect("a number is ASCII");
        if self.at > integer {
            if self.mode == Mode::Strict {
                let value = nearest_double(text);
                double(text, value).map_err(StrictError::Number)?;
                return Ok(Value::Float(value));
            }
            let value = text.parse().expect("a JSON number parses as an f64");
            return Ok(Value::Float(value));
        }
        if integer - digits > MAX_INTEGER_DIGITS {
            return Err(StrictError::Syntax(error_at(
                start,
                "an integer of more digits than the reader takes",
            )));
        }
        Ok(Value::Integer(
            Integer::from_digits(negative, &text[digits - start..])
                .expect("the digits are ASCII digits"),
        ))
    }

    fn string(&mut self) -> Result<Text, StrictError> {
        self.at += 1;
        let mut text = Text::new();
        loop {
            let start = self.at;
            while self
                .peek()
                .is_some_and(|byte| byte != b'"' && byte != b'\\' && byte >= 0x20)
            {
                self.at += 1;
            }
            text.push_str(
                std::str::from_utf8(&self.text[start..self.at])
                    .expect("a run of whole UTF-8 sequences"),
            );
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(text);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let code = self.escape()?;
                    text.push_code_point(code)
                        .expect("an escape names at most U+10FFFF");
                }
                Some(_) => return Err(self.error("a control character in a string")),
                None => return Err(self.error("an unterminated string")),
            }
        }
    }

    /// `self.at` must point to the byte after the backslash.
    fn escape(&mut self) -> Result<u32, StrictError> {
        let escaped = match self.peek() {
            Some(b'u') => return self.unicode(),
            Some(b'"') => b'"',
            Some(b'\\') => b'\\',
            Some(b'/') => b'/',
            Some(b'b') => 0x8,
            Some(b'f') => 0xc,
            Some(b'n') => b'\n',
            Some(b'r') => b'\r',
            Some(b't') => b'\t',
            Some(_) => return Err(self.error("an invalid escape")),
            None => return Err(self.error("an unterminated string")),
        };
        self.at += 1;
        Ok(u32::from(escaped))
    }

    /// `self.at` must point to the `u` of the first escape. A high surrogate joins an immediately following
    /// `\u` escape encoding a low surrogate; any other code unit stands alone.
    fn unicode(&mut self) -> Result<u32, StrictError> {
        let first = self.code_unit()?;
        if (0xd800..0xdc00).contains(&first) && self.rest_starts_with(b"\\u") {
            let mark = self.at;
            self.at += 1;
            let second = self.code_unit()?;
            if (0xdc00..0xe000).contains(&second) {
                return Ok(0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00));
            }
            self.at = mark;
        }
        Ok(first)
    }

    fn code_unit(&mut self) -> Result<u32, StrictError> {
        let digits = self
            .text
            .get(self.at + 1..self.at + 5)
            .ok_or(self.error("an invalid \\u escape"))?;
        let mut code = 0;
        for &digit in digits {
            let value = char::from(digit)
                .to_digit(16)
                .ok_or(self.error("an invalid \\u escape"))?;
            code = code * 16 + value;
        }
        self.at += 5;
        Ok(code)
    }
}

/// `double` passes a token with a fraction or an exponent whose nearest double `value` is finite and has the
/// token's decimal value as its shortest form.
fn double(token: &str, value: f64) -> Result<(), Unnumber> {
    if !value.is_finite() {
        return Err(Unnumber::Range(token.to_owned()));
    }
    if spells_shortest(token, value) {
        Ok(())
    } else {
        Err(Unnumber::Digits(token.to_owned()))
    }
}

fn error_at(offset: usize, reason: &'static str) -> Error {
    Error { offset, reason }
}

/// `dump` writes what [`text`] writes, then a newline.
pub fn dump(value: &Value) -> String {
    let mut out = text(value);
    out.push('\n');
    out
}

/// `text` uses the layout of Python's `json.dumps(value, separators=(",", ":"))`: members in document order,
/// `,` between items, `:` after a key, non-ASCII code points as `\uXXXX` escapes, and non-finite floats as
/// `NaN`, `Infinity` and `-Infinity`.
pub fn text(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out, None).expect("the compact layout writes every float");
    out
}

/// `indented` uses the layout of Python's `json.dumps(value, indent=2, sort_keys=True)`: object keys sorted
/// by code point, each member and item on its own line, two spaces per level, `: ` after a key, and `[]` and
/// `{}` for empty containers.
///
/// # Errors
///
/// `indented` refuses a non-finite float.
pub fn indented(value: &Value) -> Result<String, NonFinite> {
    let mut out = String::new();
    write(value, &mut out, Some(0))?;
    Ok(out)
}

/// A float the indented layout refuses: `NaN`, `Infinity` or `-Infinity`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NonFinite(f64);

impl NonFinite {
    pub fn value(self) -> f64 {
        self.0
    }
}

impl fmt::Display for NonFinite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the float {} has no JSON form", repr_float(self.0))
    }
}

impl std::error::Error for NonFinite {}

/// `depth` is `None` in the compact layout and the nesting depth of `value` in the indented layout.
fn write(value: &Value, out: &mut String, depth: Option<usize>) -> Result<(), NonFinite> {
    match value {
        Value::Object(object) if depth.is_some() => {
            let mut members: Vec<&(Text, Value)> = object.iter().collect();
            members.sort_by(|left, right| left.0.cmp(&right.0));
            write_items(&members, ('{', '}'), depth, out, |member, out, inner| {
                write_member(member, out, inner)
            })?;
        }
        Value::Object(object) => write_items(&object.0, ('{', '}'), depth, out, write_member)?,
        Value::Array(items) => {
            write_items(items, ('[', ']'), depth, out, |item, out, inner| {
                write(item, out, inner)
            })?;
        }
        Value::String(text) => write_string(text, out),
        Value::Integer(integer) => out.push_str(&integer.to_string()),
        Value::Float(value) if value.is_finite() => out.push_str(&repr_float(*value)),
        Value::Float(value) if depth.is_some() => return Err(NonFinite(*value)),
        Value::Float(value) if value.is_nan() => out.push_str("NaN"),
        Value::Float(value) if *value > 0.0 => out.push_str("Infinity"),
        Value::Float(_) => out.push_str("-Infinity"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Null => out.push_str("null"),
    }
    Ok(())
}

fn write_member(
    (key, member): &(Text, Value),
    out: &mut String,
    inner: Option<usize>,
) -> Result<(), NonFinite> {
    write_string(key, out);
    out.push_str(if inner.is_some() { ": " } else { ":" });
    write(member, out, inner)
}

fn write_items<T>(
    items: &[T],
    (open, close): (char, char),
    depth: Option<usize>,
    out: &mut String,
    mut each: impl FnMut(&T, &mut String, Option<usize>) -> Result<(), NonFinite>,
) -> Result<(), NonFinite> {
    let line = |out: &mut String, depth: usize| {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    };
    out.push(open);
    let inner = depth.map(|depth| depth + 1);
    for (at, item) in items.iter().enumerate() {
        if at > 0 {
            out.push(',');
        }
        if let Some(inner) = inner {
            line(out, inner);
        }
        each(item, out, inner)?;
    }
    if let (Some(depth), false) = (depth, items.is_empty()) {
        line(out, depth);
    }
    out.push(close);
    Ok(())
}

fn write_string(text: &Text, out: &mut String) {
    out.push('"');
    for code in text.code_points() {
        match code {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0xa => out.push_str("\\n"),
            0xd => out.push_str("\\r"),
            0x9 => out.push_str("\\t"),
            0x8 => out.push_str("\\b"),
            0xc => out.push_str("\\f"),
            0x20..=0x7e => out.extend(char::from_u32(code)),
            0x1_0000.. => {
                let offset = code - 0x1_0000;
                let (high, low) = (0xd800 + (offset >> 10), 0xdc00 + (offset & 0x3ff));
                out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
            }
            _ => out.push_str(&format!("\\u{code:04x}")),
        }
    }
    out.push('"');
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
