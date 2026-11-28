//! Readers of the pin lines, of the debug-assertion entry of `additional_cargo_args`, and of the inherited
//! variables the run refuses.
//!
//! Whitespace here is the set [`is_space`] takes. A line ends at a line feed alone; the pin files reach
//! these readers with their line ends read as line feeds, and the worktree configuration as it is.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::text::{Text, is_space};

const PIN: &str = "# Tool pin: cargo-mutants ";
const STABLE: &str = "STABLE: \"";
const KEY: &str = "additional_cargo_args";
const ENTRY: &str = "profile.dev.debug-assertions";
const CONFIG_PREFIX: &str = "--config=";
/// The profile variables the run sets for the tool; [`build_overrides`] refuses every other one.
pub(super) const OWNED: [&str; 2] = ["CARGO_PROFILE_DEV_OPT_LEVEL", "CARGO_PROFILE_DEV_DEBUG"];

fn space(c: char) -> bool {
    is_space(u32::from(c))
}

fn skip_space(text: &str) -> &str {
    text.trim_start_matches(space)
}

/// Each version is one or more code points outside whitespace that end the line.
pub fn pins(text: &str) -> Vec<&str> {
    text.split('\n')
        .filter_map(|line| line.strip_prefix(PIN))
        .filter(|version| !version.is_empty() && !version.contains(space))
        .collect()
}

/// `line_starts` yields the byte offset 0 and each offset that follows a line feed.
fn line_starts(text: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(text.match_indices('\n').map(|(at, _)| at + 1))
}

/// `stables` returns the value of each line that reads `STABLE: "VALUE"` after spaces or tabs alone, in
/// order. `VALUE` is one or more code points up to the first `"` of its line, and text after that quote
/// is allowed.
pub fn stables(text: &str) -> Vec<&str> {
    text.split('\n')
        .filter_map(|line| {
            let after = line.trim_start_matches([' ', '\t']).strip_prefix(STABLE)?;
            let end = after.find('"').filter(|&end| end > 0)?;
            Some(&after[..end])
        })
        .collect()
}

/// `uncommented` removes each `#` and the rest of its line and keeps the line feed.
fn uncommented(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(hash) = rest.find('#') {
        kept.push_str(&rest[..hash]);
        rest = &rest[hash..];
        rest = &rest[rest.find('\n').unwrap_or(rest.len())..];
    }
    kept.push_str(rest);
    kept
}

/// `array_start` returns the text after the `[` of the first line that reads, after whitespace from a line
/// start, `additional_cargo_args` bare or in either TOML quote, whitespace, `=`, whitespace and `[`.
fn array_start(text: &str) -> Option<&str> {
    line_starts(text).find_map(|start| {
        let rest = skip_space(&text[start..]);
        let (quote, rest) = match rest.chars().next() {
            Some(quote @ ('"' | '\'')) => (Some(quote), &rest[1..]),
            _ => (None, rest),
        };
        let mut rest = rest.strip_prefix(KEY)?;
        if let Some(quote) = quote {
            rest = rest.strip_prefix(quote)?;
        }
        let rest = skip_space(rest).strip_prefix('=')?;
        skip_space(rest).strip_prefix('[')
    })
}

/// `array_words` reads strings in either TOML quote and commas up to the first `]`, each after optional
/// whitespace, and returns the strings' contents.
fn array_words(mut rest: &str) -> Result<Vec<&str>, String> {
    let refused = || "additional_cargo_args is not an array of strings".to_owned();
    let mut words = Vec::new();
    loop {
        rest = skip_space(rest);
        let mut chars = rest.chars();
        match chars.next() {
            Some(quote @ ('"' | '\'')) => {
                let body = chars.as_str();
                let end = body.find(quote).ok_or_else(refused)?;
                words.push(&body[..end]);
                rest = &body[end + 1..];
            }
            Some(',') => rest = chars.as_str(),
            Some(']') => return Ok(words),
            _ => return Err(refused()),
        }
    }
}

/// `entry_value` returns `VALUE` when `word` is `profile.dev.debug-assertions=VALUE`, bare or after
/// `--config=`, with whitespace around the name, the `=` and the value, and `VALUE` one or more ASCII
/// letters, digits or underscores.
fn entry_value(word: &str) -> Option<&str> {
    let rest = word.strip_prefix(CONFIG_PREFIX).unwrap_or(word);
    let rest = skip_space(rest).strip_prefix(ENTRY)?;
    let rest = skip_space(skip_space(rest).strip_prefix('=')?);
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    (end > 0 && rest[end..].chars().all(space)).then(|| &rest[..end])
}

/// `names_assertions` holds when `bytes` contain `debug-assertions` or `debug_assertions`.
fn names_assertions(bytes: &[u8]) -> bool {
    bytes
        .windows(b"debug-assertions".len())
        .any(|window| window == b"debug-assertions" || window == b"debug_assertions")
}

/// `debug_assertions` returns the value of the last `profile.dev.debug-assertions=VALUE` entry of the
/// `additional_cargo_args` array in `text`, or `None` when the text has no such array or the array names
/// no such entry.
///
/// Comments are removed first, a `#` inside a string included. An entry is read wherever it stands in the
/// array, bare or attached as `--config=ENTRY`; commas between strings are optional.
///
/// # Errors
///
/// The array holds something other than strings and commas before its `]`, or a string names debug
/// assertions in a form other than the entry.
pub fn debug_assertions(text: &str) -> Result<Option<String>, String> {
    let text = uncommented(text);
    let Some(rest) = array_start(&text) else {
        return Ok(None);
    };
    let mut value = None;
    for word in array_words(rest)? {
        if let Some(found) = entry_value(word) {
            value = Some(found.to_owned());
        } else if names_assertions(word.as_bytes()) {
            return Err(format!(
                "additional_cargo_args entry {} sets debug assertions in a form the runner does not read",
                Text::from(word).repr()
            ));
        }
    }
    Ok(value)
}

/// `build_overrides` returns, sorted by code point, the names of the variables in `environ` that change
/// the tool or the build profile the run sets: each `CARGO_MUTANTS_*` variable, each `CARGO_PROFILE_*`
/// variable other than the two of [`OWNED`], and each `*RUSTFLAGS` variable whose value names debug
/// assertions.
pub(super) fn build_overrides(environ: &[(OsString, OsString)]) -> Vec<Text> {
    let mut names: Vec<Text> = environ
        .iter()
        .filter(|(name, value)| {
            let name = name.as_bytes();
            name.starts_with(b"CARGO_MUTANTS_")
                || (name.starts_with(b"CARGO_PROFILE_")
                    && !OWNED.iter().any(|owned| owned.as_bytes() == name))
                || (name.ends_with(b"RUSTFLAGS") && names_assertions(value.as_bytes()))
        })
        .map(|(name, _)| Text::from_os(OsStr::new(name)))
        .collect();
    names.sort();
    names
}
