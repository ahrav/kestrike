//! The seed check of a confirmed suspect, apart from the `campaign sim run` the caller starts: the sweep's
//! manifest of the suspect's profile, its digest with the suspect's seed as its root, the manifest the
//! check runs, and the ending the run printed.
//!
//! A manifest is read as UTF-8 text with `\r\n` and `\r` read as `\n`, and its lines break at `\n` alone.
//! A line `KEY = VALUE` is rewritten by its key, the text before its first ` = `, or the whole line when it
//! holds none.

use std::fs;
use std::path::Path;

use super::output::{Pins, last_object};
use super::suspects::Suspect;
use crate::json::Value;
use crate::ownership::PathError;
use crate::python::{hexdigest, str_of, truthy};
use crate::text::{Text, newlines, text};

/// The class of a run that passes; crates/campaign-supervisor/src/exit.rs names the same class.
const COUNTS: &str = "counts";

/// The lines of a profile's manifest, as the sweep wrote it; the judgment makes one once its digest is
/// the confirmed job's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    lines: Vec<String>,
    seed: Text,
}

/// `rewrite` gives the line with its value replaced when `values` names its key.
fn rewrite(line: &str, values: &[(&str, &Text)]) -> Text {
    let key = line.split(" = ").next().unwrap_or_default();
    match values.iter().find(|(name, _)| *name == key) {
        Some((_, value)) => text!(key, " = ", value),
        None => Text::from(line),
    }
}

impl Manifest {
    fn rewritten(&self, values: &[(&str, &Text)]) -> Text {
        let mut written = Text::new();
        for line in &self.lines {
            written.push_text(&rewrite(line, values));
            written.push_str("\n");
        }
        written
    }

    /// `pinned` is the manifest the seed check runs: its `root` lines set to the suspect's seed and its pin
    /// lines to the base archive's pins. All other lines retain their original contents.
    pub fn pinned(&self, pins: &Pins) -> Text {
        let mut values: Vec<(&str, &Text)> = pins.named().collect();
        values.push(("root", &self.seed));
        self.rewritten(&values)
    }
}

/// `manifest` reads the sweep's manifest of the suspect's profile under `root` and returns it when, with
/// the suspect's seed as its root, its UTF-8 bytes hash to `digest`, the `manifest_sha256` of the job
/// `campaign confirm` ran, which must be that text.
///
/// # Errors
///
/// The reason the check runs nothing: a profile that names no file, a manifest that cannot be read or is
/// no UTF-8 (its path and the reader's error), or a digest of other text.
pub(crate) fn manifest(
    root: &Path,
    suspect: &Suspect,
    digest: Option<&Value>,
) -> Result<Manifest, Text> {
    let Some(mut name) = suspect.profile().to_os() else {
        return Err(text!(suspect.profile().repr(), " names no manifest file"));
    };
    name.push(".manifest");
    let path = root.join("manifests").join(name);
    let read = fs::read_to_string(&path)
        .map_err(|error| Text::from(PathError::new(&path, error).to_string()))?;
    let mut lines: Vec<String> = newlines(read).split('\n').map(str::to_owned).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    let manifest = Manifest {
        lines,
        seed: Text::from(suspect.seed().to_string()),
    };
    let seeded = manifest.rewritten(&[("root", &manifest.seed)]);
    let hashed = Text::from(hexdigest(seeded.as_bytes()));
    match digest {
        Some(Value::String(digest)) if *digest == hashed => Ok(manifest),
        _ => Err(Text::from(
            "its manifest differs from the job `confirm` ran",
        )),
    }
}

/// `ending` reads what `campaign sim run` of a seed check printed: it exited `code` and printed `out`,
/// whose last line holds the worker's result. The ending is the result's `reason` value as printed, an
/// object or a list included, when its `str` text begins with the class and `: `; else the text
/// `CLASS: REASON`, or the class alone for a false or missing reason; each is read as Python's `str`
/// writes the value.
///
/// # Errors
///
/// A last line without a class, or an exit 0 whose class is other than `counts`.
pub(crate) fn ending(code: i32, out: &str) -> Result<(i32, Value), Text> {
    let printed = last_object(out, "sim run").ok();
    let Some(class) = printed.as_ref().and_then(|printed| printed.get("class")) else {
        return Err(text!("exit ", code, " with no result"));
    };
    let kind = str_of(class);
    let ending = match printed.as_ref().and_then(|printed| printed.get("reason")) {
        Some(reason) if truthy(reason) => {
            if str_of(reason).starts_with(&text!(kind, ": ")) {
                reason.clone()
            } else {
                Value::String(text!(kind, ": ", str_of(reason)))
            }
        }
        _ => Value::String(kind.clone()),
    };
    if code == 0 && kind != COUNTS {
        return Err(text!("exit 0 with the class ", kind));
    }
    Ok((code, ending))
}

#[cfg(test)]
#[path = "seed_tests.rs"]
mod tests;
