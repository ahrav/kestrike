//! A JSON reader that preserves document order, and a writer that emits Python's
//! `json.dumps(data, separators=(",", ":"))` representation followed by one newline.
//!
//! The reader takes objects, arrays, strings, integers of any length, `true` and `false`, with the whitespace
//! JSON allows around them. An object keeps its keys in the order they first appear; a repeated key's last value
//! takes the first one's place. An integer keeps its digits, except that `-0` reads as `0`. A string holds
//! Unicode scalar values: an escape may name any of them, a pair of surrogate escapes included. `null`, a
//! fraction, an exponent, `NaN`, `Infinity`, a lone surrogate escape, a raw control character in a string,
//! nesting deeper than [`MAX_DEPTH`] and text after the value are errors.
//!
//! The writer escapes `"` and `\`, writes `\n`, `\r`, `\t`, `\b` and `\f` by name and every other character
//! outside the printable ASCII range as `\u` and four lowercase hexadecimal digits, a character past U+FFFF as
//! its surrogate pair. The writer uses `,` and `:` as separators.

use std::cmp::Ordering;
use std::fmt;

/// The deepest nesting of arrays and objects the reader takes.
pub const MAX_DEPTH: usize = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Object(Object),
    Array(Vec<Value>),
    String(Text),
    Integer(Integer),
    Bool(bool),
}

/// The value of a JSON string: a sequence of Unicode scalar values.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Text(String);

impl Text {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Text {
    fn from(text: &str) -> Self {
        Self(text.to_owned())
    }
}

impl From<String> for Text {
    fn from(text: String) -> Self {
        Self(text)
    }
}

/// An integer of any length, held as its sign and its decimal digits without leading zeros.
///
/// Zero has `negative == false` and `digits == "0"`, so each integer has one representation and [`Ord`]
/// compares integers numerically.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Integer {
    negative: bool,
    digits: String,
}

impl Integer {
    /// The integer that `negative` and the ASCII decimal `digits` spell, or `None` when `digits` is empty or
    /// holds a byte other than a digit. `from_digits` strips leading zeros and maps all-zero digits to zero
    /// whatever `negative` says.
    pub fn from_digits(negative: bool, digits: &str) -> Option<Self> {
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let digits = digits.trim_start_matches('0');
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Object(Vec<(Text, Value)>);

impl Object {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(name, _)| name.as_str() == key)
            .map(|(_, value)| value)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.0
            .iter_mut()
            .find(|(name, _)| name.as_str() == key)
            .map(|(_, value)| value)
    }

    /// Replaces an existing key's value in place or appends a new member.
    pub fn insert(&mut self, key: impl Into<Text>, value: Value) {
        let key = key.into();
        match self.get_mut(key.as_str()) {
            Some(slot) => *slot = value,
            None => self.0.push((key, value)),
        }
    }

    /// The remaining members keep their relative order.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let at = self.0.iter().position(|(name, _)| name.as_str() == key)?;
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
    pub offset: usize,
    pub reason: &'static str,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

pub fn parse(text: &str) -> Result<Value, Error> {
    let mut reader = Reader {
        text: text.as_bytes(),
        at: 0,
    };
    reader.space();
    let value = reader.value(0)?;
    reader.space();
    if reader.at != reader.text.len() {
        return Err(reader.error("text after the value"));
    }
    Ok(value)
}

struct Reader<'a> {
    text: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn error(&self, reason: &'static str) -> Error {
        Error {
            offset: self.at,
            reason,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &[u8]) -> bool {
        let found = self.text[self.at..].starts_with(word);
        if found {
            self.at += word.len();
        }
        found
    }

    fn expect(&mut self, byte: u8, reason: &'static str) -> Result<(), Error> {
        if self.peek() != Some(byte) {
            return Err(self.error(reason));
        }
        self.at += 1;
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'-' | b'0'..=b'9') => self.integer(),
            _ if self.literal(b"true") => Ok(Value::Bool(true)),
            _ if self.literal(b"false") => Ok(Value::Bool(false)),
            _ if self.text[self.at..].starts_with(b"null") => Err(self.error("null is refused")),
            _ if self.text[self.at..].starts_with(b"NaN")
                || self.text[self.at..].starts_with(b"Infinity") =>
            {
                Err(self.error("a number beyond the integers is refused"))
            }
            _ => Err(self.error("expected a value")),
        }
    }

    fn nest(&mut self, depth: usize) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting deeper than the reader takes"));
        }
        self.at += 1;
        self.space();
        Ok(())
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        self.nest(depth)?;
        let mut object = Object::new();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(object));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a key"));
            }
            let key = self.string()?;
            self.space();
            self.expect(b':', "expected ':'")?;
            self.space();
            let value = self.value(depth)?;
            object.insert(key, value);
            self.space();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.space();
                }
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(object));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        self.nest(depth)?;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.space();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.space();
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn integer(&mut self) -> Result<Value, Error> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
            if self.text[self.at..].starts_with(b"Infinity") {
                return Err(self.error("a number beyond the integers is refused"));
            }
        }
        let digits = self.at;
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(self.error("expected a digit")),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(Error {
                offset: start,
                reason: "a fraction or an exponent is refused",
            });
        }
        let text = std::str::from_utf8(&self.text[digits..self.at]).expect("the digits are ASCII");
        Ok(Value::Integer(
            Integer::from_digits(negative, text).expect("the digits are ASCII digits"),
        ))
    }

    fn string(&mut self) -> Result<Text, Error> {
        self.at += 1;
        let mut text = Vec::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.error("an unterminated string"));
            };
            self.at += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = match self.peek() {
                        Some(b'u') => self.unicode()?,
                        Some(simple) => {
                            self.at += 1;
                            match simple {
                                b'"' => '"',
                                b'\\' => '\\',
                                b'/' => '/',
                                b'b' => '\u{8}',
                                b'f' => '\u{c}',
                                b'n' => '\n',
                                b'r' => '\r',
                                b't' => '\t',
                                _ => {
                                    return Err(Error {
                                        offset: self.at - 1,
                                        reason: "an invalid escape",
                                    });
                                }
                            }
                        }
                        None => return Err(self.error("an unterminated string")),
                    };
                    let mut buffer = [0; 4];
                    text.extend_from_slice(escaped.encode_utf8(&mut buffer).as_bytes());
                }
                0..0x20 => {
                    return Err(Error {
                        offset: self.at - 1,
                        reason: "a control character in a string",
                    });
                }
                _ => text.push(byte),
            }
        }
        Ok(Text(String::from_utf8(text).expect(
            "the text holds whole UTF-8 sequences and scalar values",
        )))
    }

    /// `self.at` must point to the `u` of the first escape. A high surrogate requires an immediately following
    /// `\u` escape encoding a low surrogate.
    fn unicode(&mut self) -> Result<char, Error> {
        let start = self.at - 1;
        let first = self.code_unit()?;
        let code = match first {
            0xd800..0xdc00 if self.text[self.at..].starts_with(b"\\u") => {
                self.at += 1;
                let second = self.code_unit()?;
                if !(0xdc00..0xe000).contains(&second) {
                    return Err(Error {
                        offset: start,
                        reason: "a lone surrogate escape is refused",
                    });
                }
                0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
            }
            _ => first,
        };
        char::from_u32(code).ok_or(Error {
            offset: start,
            reason: "a lone surrogate escape is refused",
        })
    }

    fn code_unit(&mut self) -> Result<u32, Error> {
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

pub fn dump(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out.push('\n');
    out
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Object(object) => {
            out.push('{');
            for (at, (key, member)) in object.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_string(key.as_str(), out);
                out.push(':');
                write(member, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::String(text) => write_string(text.as_str(), out),
        Value::Integer(integer) => out.push_str(&integer.to_string()),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            _ => {
                for unit in character.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}
