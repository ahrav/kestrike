//! The expected text of a red base, searched in a leg's attempt output outside the lines libtest and the
//! panic hook print around a failure.
//!
//! Lines split at LF alone. A line, less one final CR, is framing when it matches one of [`FRAMING`] as a
//! whole, with `TEST` standing for the test ID as literal text, `.` for any byte and `\s` for
//! [`classes::SPACE`]. A backtrace runs from a line that opens with `stack backtrace:` through each next
//! line that opens with a space. Each framing and backtrace line becomes one NUL, which no argument holds,
//! so a match of the expected text lies within one run of adjacent kept lines.
//!
//! Attempt output decodes as UTF-8 with each byte outside it kept as a lone surrogate, the decoding of
//! option values and paths on a host whose filesystem encoding is UTF-8. While one stream is unframed,
//! its bytes, one decoded text for each of its lines and the joined copy stand in memory together, beside
//! the leg's artifact and its other stream.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use regex::bytes::{Regex, RegexBuilder};

use super::evidence::Readings;
use super::options::Options;
use crate::classes;
use crate::text::Text;

/// `unframed` retains libtest's `running N tests (shuffle seed: S)` header under `--shuffle`.
pub const FRAMING: [&str; 13] = [
    r"running \d+ tests?",
    r"test TEST( - should panic)? \.\.\. .*",
    r"FAILED",
    r"test result: .*",
    r"failures:",
    r"successes:",
    r"---- TEST std(out|err) ----",
    r"\s*TEST",
    r"thread '.*' (\(\d+\) )?panicked at .*:\d+:\d+:",
    r"note: (run with .*|Some details .*|panic did not contain expected string|expected panic with string value,)",
    r"\s*panic message: .*",
    r"\s*expected substring: .*",
    r"\s*found non-string value: .*",
];

fn literal(text: &[u8]) -> String {
    text.iter().map(|byte| format!(r"\x{byte:02x}")).collect()
}

/// Every shape runs with `.` as any byte of a [`Text`]'s encoding; `\d` and `\s` keep their Unicode
/// classes. The compiled program grows with the length of `test`. Its size limit is lifted, so a test ID
/// as long as one command-line argument compiles; the count of states the engine can number still bounds
/// the pattern.
fn framing(test: &Text) -> Regex {
    let test = literal(test.as_bytes());
    let shapes: Vec<String> = FRAMING
        .iter()
        .map(|shape| {
            let shape = shape
                .replace(r"\d", r"(?u:\d)")
                .replace(r"\s", &format!("(?u:{})", classes::SPACE));
            format!("(?:{})", shape.replace("TEST", &test))
        })
        .collect();
    RegexBuilder::new(&format!("(?s-u)^(?:{})$", shapes.join("|")))
        .size_limit(usize::MAX)
        .build()
        .unwrap_or_else(|error| panic!("the framing shapes compile: {error}"))
}

fn unframed_by(framing: &Regex, output: &[u8]) -> Text {
    let nul = Text::from("\0");
    let mut kept = Vec::new();
    let mut backtrace = false;
    for line in output.split(|&byte| byte == b'\n') {
        let line = Text::from_os(OsStr::from_bytes(line));
        let bytes = line.as_bytes();
        let body = bytes.strip_suffix(b"\r").unwrap_or(bytes);
        backtrace = body.starts_with(b"stack backtrace:") || (backtrace && body.starts_with(b" "));
        kept.push(if backtrace || framing.is_match(body) {
            nul.clone()
        } else {
            line
        });
    }
    Text::join("\n", &kept)
}

pub fn unframed(output: &[u8], test: &Text) -> Text {
    unframed_by(&framing(test), output)
}

/// The streams read whose output, unframed for `options.test`, holds `options.expect`, in the order of
/// [`STREAMS`](super::evidence::STREAMS).
pub(super) fn expect_streams(readings: &Readings, options: &Options) -> Vec<&'static str> {
    let framing = framing(&options.test);
    readings
        .read()
        .filter(|(_, data)| unframed_by(&framing, data).contains(&options.expect))
        .map(|(stream, _)| stream)
        .collect()
}

#[cfg(test)]
#[path = "expected_tests.rs"]
mod tests;
