//! The expected text of a red base, searched in a leg's attempt output outside the lines libtest and the
//! panic hook print around a failure.
//!
//! Lines split at LF alone. A line, less one final CR, is framing when it matches one of [`FRAMING`] as a
//! whole, with `TEST` standing for the test ID as literal text, `.` for any byte and `\s` for
//! [`classes::SPACE`]. A backtrace runs from a line that opens with `stack backtrace:` through each next
//! line that opens with a space. Each framing and backtrace line becomes one NUL, which no argument holds,
//! so a match of the expected text lies within one run of adjacent kept lines.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use regex::bytes::Regex;

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
/// classes.
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
    classes::compiled_bytes(&format!("(?s-u)^(?:{})$", shapes.join("|")))
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

/// The streams whose unframed output holds `expect`, in the order of `outputs`.
pub fn expect_streams<'a>(
    outputs: &[(&'a str, Vec<u8>)],
    expect: &Text,
    test: &Text,
) -> Vec<&'a str> {
    let framing = framing(test);
    outputs
        .iter()
        .filter(|(_, data)| super::holds(unframed_by(&framing, data).as_bytes(), expect.as_bytes()))
        .map(|(stream, _)| *stream)
        .collect()
}

#[cfg(test)]
#[path = "expected_tests.rs"]
mod tests;
