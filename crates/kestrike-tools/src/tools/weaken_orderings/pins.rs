//! The toolchain pins of the copy's workflow and the environment of the loom lane.

use std::ffi::OsString;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::halt::Halt;
use crate::classes::{SPACE, compiled, is_word};
use crate::genmc::read_text;

/// The pins a report records, in this order, when the workflow names them.
const PINS: [&str; 7] = [
    "STABLE",
    "NIGHTLY",
    "LOOM",
    "HERDTOOLS7",
    "LLVM",
    "KANI",
    "CARGO_FUZZ",
];
/// The pins a run needs, each nonempty.
const REQUIRED_PINS: [&str; 3] = ["STABLE", "NIGHTLY", "LOOM"];
/// Plain, unsilenced Cargo status lines carry the `Compiling` and `Checking` lines that the rebuild
/// evidence reads.
pub(super) const TERM: [(&str, &str); 2] =
    [("CARGO_TERM_COLOR", "never"), ("CARGO_TERM_QUIET", "false")];

static PIN_LINE: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r#"(?m)^  ([A-Z0-9_]+): (?:"([^"\n]*)"|'([^'\n]*)'|([^"'#{}]+))[ \t]*(?:#.*)?$"#,
        &SPACE[1..SPACE.len() - 1]
    ))
});

/// The ordered pins of a workflow.
pub(super) type Pins = Vec<(String, String)>;

/// `workflow_pins` reads the pins of the workflow's top-level `env` block in `copy`, the text before its
/// first `\njobs:`, bare or in matched quotes, a later line of a name taking its value; it returns those of
/// [`PINS`] in that order.
///
/// # Errors
///
/// A refusal of exit 2 for a missing or empty pin of [`REQUIRED_PINS`], and a failure for a workflow that
/// cannot be read as UTF-8.
pub(super) fn workflow_pins(copy: &Path) -> Result<Pins, Halt> {
    let path = copy.join(".github/workflows/agent-checks.yml");
    let text =
        read_text(&path).map_err(|error| Halt::failed(format!("{}: {error}", path.display())))?;
    let block = text
        .split_once("\njobs:")
        .map_or(text.as_str(), |(block, _)| block);
    let mut pins: Vec<(String, String)> = Vec::new();
    for found in PIN_LINE.captures_iter(block) {
        let value = (2..=4)
            .find_map(|group| found.get(group))
            .map_or("", |value| value.as_str());
        let name = &found[1];
        match pins.iter_mut().find(|(held, _)| held == name) {
            Some(pin) => pin.1 = value.to_owned(),
            None => pins.push((name.to_owned(), value.to_owned())),
        }
    }
    let get = |name: &str| {
        pins.iter()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value)
    };
    let missing: Vec<&str> = REQUIRED_PINS
        .into_iter()
        .filter(|name| get(name).is_none_or(String::is_empty))
        .collect();
    if !missing.is_empty() {
        return Err(Halt::stop(
            2,
            format!(
                "the workflow's env block names no {} pin",
                missing.join(", ")
            ),
        ));
    }
    Ok(PINS
        .into_iter()
        .filter_map(|name| get(name).map(|value| (name.to_owned(), value.clone())))
        .collect())
}

/// `pin` is the value of `name` among `pins`, which hold every pin of [`REQUIRED_PINS`].
pub(super) fn pin<'p>(pins: &'p Pins, name: &str) -> &'p str {
    pins.iter()
        .find(|(held, _)| held == name)
        .map_or("", |(_, value)| value)
}

/// `shaping` holds for the environment form of a compiler, wrapper, target, runner, flag, profile or
/// output-directory override, or a `LOOM_*` variable, which the loom tests build without; a final line
/// feed of the name is passed over, and `CARGO_BUILD_JOBS` stays.
pub(super) fn shaping(name: &OsString) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let name = name.strip_suffix('\n').unwrap_or(name);
    const EXACT: [&str; 8] = [
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "",
    ];
    if EXACT[..7].contains(&name) {
        return true;
    }
    let word = |rest: &str| !rest.is_empty() && rest.chars().all(is_word);
    if let Some(rest) = name.strip_prefix("CARGO_BUILD_") {
        return rest != "JOBS" && word(rest);
    }
    ["CARGO_TARGET_", "CARGO_PROFILE_", "LOOM_"]
        .into_iter()
        .any(|prefix| name.strip_prefix(prefix).is_some_and(word))
}

/// `lane_env` is the loom lane's environment: `environ` without each name [`shaping`] holds, then the
/// pins, [`TERM`], `RUSTFLAGS="--cfg loom"`, and `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR` at
/// `work/target-loom`; a later value of a name takes that name's first place.
pub(super) fn lane_env(
    environ: &[(OsString, OsString)],
    work: &Path,
    pins: &Pins,
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = environ
        .iter()
        .filter(|(name, _)| !shaping(name))
        .cloned()
        .collect();
    let target = work.join("target-loom").into_os_string();
    let added = pins
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .chain(
            TERM.iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value))),
        )
        .chain([
            (OsString::from("RUSTFLAGS"), OsString::from("--cfg loom")),
            (OsString::from("CARGO_TARGET_DIR"), target.clone()),
            (OsString::from("CARGO_BUILD_BUILD_DIR"), target),
        ]);
    for (name, value) in added {
        set(&mut env, name, value);
    }
    env
}

/// `set` gives `name` the value `value` at its first place in `env`, or at the end.
pub(super) fn set(env: &mut Vec<(OsString, OsString)>, name: OsString, value: OsString) {
    match env.iter_mut().find(|(held, _)| *held == name) {
        Some(entry) => entry.1 = value,
        None => env.push((name, value)),
    }
}

#[cfg(test)]
#[path = "pins_tests.rs"]
mod tests;
