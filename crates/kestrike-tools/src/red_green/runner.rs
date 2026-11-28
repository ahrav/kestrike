//! The output of `scripts/reproduce-test.py` as a leg reads it: exit codes, verdicts and the announcement
//! of a leg's `artifact.json`.
//!
//! The runner's two streams decode as UTF-8 with each invalid sequence replaced by U+FFFD, and with
//! `\r\n` and `\r` read as `\n`.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use crate::text::{self, Text, text};

pub const NOT_REPRODUCED: i32 = 0;
pub const REPRODUCED: i32 = 1;
pub const REJECTED: i32 = 2;
pub const BUILD_FAILURE: i32 = 3;
pub const CRASH: i32 = 4;
pub const INTERRUPTED: i32 = 5;
pub const WATCHDOG: i32 = 6;

/// Indexed by exit code; a verdict opens with its code's result.
pub const RESULTS: [&str; 7] = [
    "not reproduced",
    "reproduced",
    "rejected input",
    "build failure",
    "crash",
    "interruption",
    "watchdog expiry",
];

pub const ABSENT: &str = "matched 0 listed";

pub const ANNOUNCEMENT: &str = "artifact: ";

pub fn reported(code: i32, verdict: &Text) -> bool {
    matches!(code, NOT_REPRODUCED | REPRODUCED | WATCHDOG)
        && verdict.starts_with(&Text::from(RESULTS[code as usize]))
}

pub fn leg_directory(run: &Text, attempt: &Text, leg: &str) -> Text {
    text!(run, "-", attempt, "-", leg)
}

fn decoded(output: &[u8]) -> Text {
    Text::from(text::newlines(String::from_utf8_lossy(output).into_owned()))
}

pub fn verdict(stdout: &[u8]) -> Text {
    decoded(stdout)
        .strip()
        .splitlines()
        .pop()
        .unwrap_or_default()
}

pub fn announcement(stderr: &[u8]) -> Option<Text> {
    let opening = Text::from(ANNOUNCEMENT);
    let line = decoded(stderr)
        .splitlines()
        .into_iter()
        .rfind(|line| line.starts_with(&opening))?;
    let rest = &line.as_bytes()[ANNOUNCEMENT.len()..];
    Some(Text::from_os(OsStr::from_bytes(rest)))
}

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;
