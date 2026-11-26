//! The protocol parsers' one error type.

use std::fmt;

/// Why worker output is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The output is empty or its last line lacks its newline, as output
    /// cut short leaves it.
    Torn,
    /// A line with no `": "`, or a family or cluster declaration's field
    /// with no `'='`. A fixed-pattern value that lacks its `'='` lies
    /// outside its form and is [`Error::Value`].
    Unpaired(String),
    /// A required key, or a line the rest of the output requires.
    Missing(&'static str),
    /// A key, or a named entry, that appears twice.
    Repeated(String),
    /// A key the form never prints, or one this output's other lines do
    /// not call for.
    Unknown(String),
    /// The named key's value lies outside its form.
    Value(&'static str),
    /// Lines, or fields of one line, that disagree, as the rule names.
    Inconsistent(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Torn => f.write_str("the output is empty or cut short of its last newline"),
            Self::Unpaired(line) => write!(f, "{} pairs no key with a value", Excerpt(line)),
            Self::Missing(key) => write!(f, "the output lacks its {key} line"),
            Self::Repeated(key) => write!(f, "the output names {} twice", Excerpt(key)),
            Self::Unknown(key) => write!(f, "the output calls for no {} line", Excerpt(key)),
            Self::Value(key) => write!(f, "the {key} value lies outside its form"),
            Self::Inconsistent(rule) => write!(f, "the output disagrees with itself: {rule}"),
        }
    }
}

impl std::error::Error for Error {}

/// Worker text in a message: escaped as a Rust string literal and cut to
/// its first [`Excerpt::CHARS`] characters, so a long or control-laden
/// line prints as one bounded line. The error itself keeps the whole text.
struct Excerpt<'a>(&'a str);

impl Excerpt<'_> {
    const CHARS: usize = 80;
}

impl fmt::Display for Excerpt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.char_indices().nth(Self::CHARS) {
            Some((end, _)) => write!(f, "{:?}...", &self.0[..end]),
            None => write!(f, "{:?}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    /// Worker text in a message is escaped and cut to 80 characters, and
    /// text of 80 characters prints whole.
    #[test]
    fn worker_text_prints_escaped_and_bounded() {
        let long = format!("\u{7}{}", "k".repeat(100));
        let printed = Error::Unknown(long).to_string();
        let excerpt = format!("\"\\u{{7}}{}\"...", "k".repeat(79));
        assert_eq!(printed, format!("the output calls for no {excerpt} line"));
        let whole = "k".repeat(80);
        assert_eq!(
            Error::Repeated(whole.clone()).to_string(),
            format!("the output names {whole:?} twice")
        );
    }
}
