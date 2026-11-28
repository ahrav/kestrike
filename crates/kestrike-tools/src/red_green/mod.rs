//! The rules by which a red-green run judges a regression test: a red base leg, where the test fails with an
//! expected text, and a green head leg, where it passes.

pub mod evidence;
pub mod expected;
#[cfg(target_os = "linux")]
mod legs;
pub mod options;
pub mod reasons;
pub mod record;
#[cfg(target_os = "linux")]
pub mod run;
pub mod runner;
pub mod tree;

pub const STREAMS: [&str; 2] = ["stdout", "stderr"];

fn short(commit: &str) -> &str {
    commit
        .char_indices()
        .nth(12)
        .map_or(commit, |(at, _)| &commit[..at])
}

/// Python's substring rule treats an empty `needle` as a match in every `haystack`.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
