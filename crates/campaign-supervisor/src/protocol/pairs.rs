//! The line layout every worker form is built from, and the forms its
//! values take.
//!
//! A form's output is newline-terminated `key: value` lines, split at the
//! first `": "`. [`Pairs`] marks each line a form reads, so
//! [`Pairs::finish`] refuses every line of a key the form never reads. The
//! worker ends each line with `'\n'` alone, so any other line-break
//! character stays inside its value. A value with parts follows a fixed
//! [`fill`] pattern, so its parts appear in the worker's order with
//! nothing else.

use std::collections::HashSet;
use std::hash::Hash;

use crate::record::Digest;

use super::Error;

/// The lines of one form, each marked once a read takes its key.
pub(super) struct Pairs<'a> {
    pairs: Vec<(&'a str, &'a str, bool)>,
}

impl<'a> Pairs<'a> {
    /// The `key: value` lines of `text`. Output that is empty or whose last
    /// line lacks its newline was cut short and is [`Error::Torn`].
    pub(super) fn lines(text: &'a str) -> Result<Self, Error> {
        let body = text.strip_suffix('\n').ok_or(Error::Torn)?;
        let pair = |line: &'a str| match line.split_once(": ") {
            Some((key, value)) => Ok((key, value, false)),
            None => Err(Error::Unpaired(line.to_owned())),
        };
        Ok(Self {
            pairs: body.split('\n').map(pair).collect::<Result<_, _>>()?,
        })
    }

    /// The value of `key`, which must appear exactly once.
    pub(super) fn one(&mut self, key: &'static str) -> Result<&'a str, Error> {
        self.optional(key)?.ok_or(Error::Missing(key))
    }

    /// The value of the once-printed `key`, parsed by `parse`.
    pub(super) fn take<T>(&mut self, key: &'static str, parse: Parse<T>) -> Result<T, Error> {
        parse(self.one(key)?, key)
    }

    /// The value of `key`, which may appear at most once.
    pub(super) fn optional(&mut self, key: &'static str) -> Result<Option<&'a str>, Error> {
        match self.every(key)[..] {
            [] => Ok(None),
            [value] => Ok(Some(value)),
            _ => Err(Error::Repeated(key.to_owned())),
        }
    }

    /// Every value of `key`, in output order, each parsed by `parse`.
    pub(super) fn all<T>(&mut self, key: &'static str, parse: Parse<T>) -> Result<Vec<T>, Error> {
        self.every(key)
            .into_iter()
            .map(|value| parse(value, key))
            .collect()
    }

    /// Every value of `key`, in output order.
    pub(super) fn every(&mut self, key: &str) -> Vec<&'a str> {
        let matching = self.pairs.iter_mut().filter(|(known, _, _)| *known == key);
        matching
            .map(|(_, value, taken)| {
                *taken = true;
                *value
            })
            .collect()
    }

    /// Refuses the first pair no other method took: a key the form never
    /// prints.
    pub(super) fn finish(self) -> Result<(), Error> {
        match self.pairs.into_iter().find(|(_, _, taken)| !taken) {
            Some((key, _, _)) => Err(Error::Unknown(key.to_owned())),
            None => Ok(()),
        }
    }
}

/// A value parser, given the value and its key for the error.
pub(super) type Parse<T> = fn(&str, &'static str) -> Result<T, Error>;

/// A canonical decimal count: digits with no sign and no leading zero.
pub(super) fn count(text: &str, key: &'static str) -> Result<u64, Error> {
    let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    let canonical = digits && (text == "0" || !text.starts_with('0'));
    canonical
        .then(|| text.parse().ok())
        .flatten()
        .ok_or(Error::Value(key))
}

/// `text`, or `None` where the worker prints `unavailable` because the
/// bundle records no value.
pub(super) fn available(text: &str) -> Option<&str> {
    (text != "unavailable").then_some(text)
}

/// A count, or `None` where the worker prints `unavailable`.
pub(super) fn measure(text: &str, key: &'static str) -> Result<Option<u64>, Error> {
    available(text).map(|text| count(text, key)).transpose()
}

pub(super) fn flag(text: &str, key: &'static str) -> Result<bool, Error> {
    match text {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(Error::Value(key)),
    }
}

pub(super) fn digest(text: &str, key: &'static str) -> Result<Digest, Error> {
    Digest::parse(text).ok_or(Error::Value(key))
}

/// A name or text value, which the worker never prints empty.
pub(super) fn owned(text: &str, key: &'static str) -> Result<String, Error> {
    (!text.is_empty())
        .then(|| text.to_owned())
        .ok_or(Error::Value(key))
}

/// Lowercase hexadecimal of `digits` digits, kept as the worker printed it.
pub(super) fn hex(text: &str, digits: usize, key: &'static str) -> Result<String, Error> {
    let lowercase = text
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    (text.len() == digits && lowercase)
        .then(|| text.to_owned())
        .ok_or(Error::Value(key))
}

/// The parts of `text` at each placeholder of `pattern`, or
/// [`Error::Value`] unless the literal text between them matches. A `{}`
/// ends at the first occurrence of the literal after it and a `{*}` at the
/// last, so only a `{*}` part may hold that literal. A placeholder that
/// ends the pattern takes the rest of `text`; a literal that ends the
/// pattern must end `text`.
///
/// # Panics
///
/// When `pattern` holds a `{` that opens neither placeholder, or other
/// than `N` placeholders: each pattern is a literal of this module's
/// callers.
pub(super) fn fill<'a, const N: usize>(
    text: &'a str,
    pattern: &str,
    key: &'static str,
) -> Result<[&'a str; N], Error> {
    let invalid = Error::Value(key);
    let mut parts = pattern.split('{');
    let Some(mut rest) = parts.next().and_then(|head| text.strip_prefix(head)) else {
        return Err(invalid);
    };
    let mut values = Vec::with_capacity(N);
    for part in parts {
        let (greedy, literal) = match (part.strip_prefix("*}"), part.strip_prefix('}')) {
            (Some(literal), _) => (true, literal),
            (None, Some(literal)) => (false, literal),
            (None, None) => {
                panic!("the pattern {pattern:?} opens a placeholder other than {{}} or {{*}}")
            }
        };
        let end = if literal.is_empty() {
            Some(rest.len())
        } else if greedy {
            rest.rfind(literal)
        } else {
            rest.find(literal)
        };
        let Some(end) = end else { return Err(invalid) };
        values.push(&rest[..end]);
        rest = &rest[end + literal.len()..];
    }
    if !rest.is_empty() {
        return Err(invalid);
    }
    // Each placeholder pushes one part, so a pattern of `N` placeholders
    // yields `N` parts.
    Ok(values
        .try_into()
        .unwrap_or_else(|_| panic!("the pattern {pattern:?} must hold {N} placeholders")))
}

/// The counts at each placeholder of `pattern` in `text`.
pub(super) fn counts<const N: usize>(
    text: &str,
    pattern: &str,
    key: &'static str,
) -> Result<[u64; N], Error> {
    let parts: [&str; N] = fill(text, pattern, key)?;
    let mut out = [0; N];
    for (value, part) in out.iter_mut().zip(parts) {
        *value = count(part, key)?;
    }
    Ok(out)
}

/// The first of `items` that an earlier item equals, found in one pass.
pub(super) fn repeated<T: Eq + Hash>(items: &[T]) -> Option<&T> {
    let mut seen = HashSet::with_capacity(items.len());
    items.iter().find(|item| !seen.insert(*item))
}

/// An enumeration of the words a value takes, and `parse`, which reads the
/// word for each variant and refuses any other text.
macro_rules! words {
    ($(#[$doc:meta])* $name:ident {
        $($(#[$variant_doc:meta])* $variant:ident = $word:literal,)+
    }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($(#[$variant_doc])* $variant,)+ }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            pub(super) fn parse(text: &str, key: &'static str) -> Result<Self, Error> {
                match text {
                    $($word => Ok(Self::$variant),)+
                    _ => Err(Error::Value(key)),
                }
            }

            /// The word the worker prints for this value.
            pub fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $word,)+
                }
            }
        }
    };
}

pub(super) use words;
