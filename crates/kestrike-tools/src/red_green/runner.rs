//! The output of `scripts/reproduce-test.py` as a leg reads it: exit codes, verdicts and the announcement
//! of a leg's `artifact.json`.
//!
//! The runner's two streams decode as UTF-8 with each invalid sequence replaced by U+FFFD. A line ends
//! at `\n`, `\r\n`, `\r` and each other terminator of `str.splitlines()`.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use crate::text::{Text, text};

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

/// Whether `code` is an exit of a run that ended in a result, 0, 1 or 6, and `verdict` opens with that
/// code's result. A reported leg may still lack its evidence.
pub fn reported(code: i32, verdict: &Text) -> bool {
    matches!(code, NOT_REPRODUCED | REPRODUCED | WATCHDOG)
        && verdict.starts_with(&Text::from(RESULTS[code as usize]))
}

/// The name of a leg's directory in the receipt before the suffix `.N` the runner adds to a taken name.
/// `attempt` is the workflow run attempt the runner reads from `GITHUB_RUN_ATTEMPT`, `1` where the
/// variable is unset; the caller supplies it. It differs from the test attempt that numbers
/// `attempt-1.stdout`.
pub fn leg_directory(run: &Text, attempt: &Text, leg: &str) -> Text {
    text!(run, "-", attempt, "-", leg)
}

fn decoded(output: &[u8]) -> Text {
    Text::from(String::from_utf8_lossy(output).into_owned())
}

/// The last line of `stdout` once white space is stripped from both ends of the whole stream, or the
/// empty text where no line remains.
pub fn verdict(stdout: &[u8]) -> Text {
    decoded(stdout)
        .strip()
        .splitlines()
        .pop()
        .unwrap_or_default()
}

/// The text after [`ANNOUNCEMENT`] on the last line of `stderr` that opens with it, untrimmed: the empty
/// text for a line of the prefix alone, `None` where no line opens with it.
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
