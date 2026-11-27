//! The seed check of a confirmed suspect, apart from the `campaign sim run` the caller starts: the sweep's
//! manifest of the suspect's profile, its digest with the suspect's seed as its root, the manifest the
//! check runs, and the ending the run printed.
//!
//! A manifest is read as UTF-8 text with `\r\n` and `\r` read as `\n`, and its lines break at `\n` alone.
//! A line `KEY = VALUE` is rewritten by its key, the text before its first ` = `, or the whole line when it
//! holds none.

use std::fs;
use std::path::Path;

use super::git::newlines;
use super::output::{Pins, last_object};
use super::suspects::Suspect;
use super::words::words;
use crate::json::Value;
use crate::ownership::PathError;
use crate::python::{hexdigest, str_of, truthy};
use crate::text::Text;

/// The class of a run that passes; crates/campaign-supervisor/src/exit.rs names the same class.
const COUNTS: &str = "counts";

/// What a seed check gave: the exit of the seed's run on the unpatched head with its ending, the reason it
/// ran nothing on the head, or the error that kept it from running.
#[derive(Clone, Debug, PartialEq)]
pub enum SeedCheck {
    /// `campaign sim run` exited `code` with the worker's ending: the class, or the reason with the class
    /// before it.
    Ran { code: i32, ending: Value },
    /// The check ran nothing on the head; the text says why.
    Nothing(Text),
    /// The check did not run; the text is the error.
    Failed(Text),
}

/// The lines of a profile's manifest, as the sweep wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest(Vec<String>);

/// `rewrite` gives the line with its value replaced when `values` names its key.
fn rewrite(line: &str, values: &[(&str, &Text)]) -> Text {
    let key = line.split(" = ").next().unwrap_or_default();
    match values.iter().find(|(name, _)| *name == key) {
        Some((_, value)) => words!(key, " = ", value),
        None => Text::from(line),
    }
}

impl Manifest {
    fn rewritten(&self, values: &[(&str, &Text)]) -> Text {
        let mut text = Text::new();
        for line in &self.0 {
            text.push_text(&rewrite(line, values));
            text.push_str("\n");
        }
        text
    }

    /// `pinned` is the manifest the seed check runs: the root set to `seed` and each of the pins to the
    /// base archive's.
    pub fn pinned(&self, pins: &Pins, seed: &crate::json::Integer) -> Text {
        let seed = Text::from(seed.to_string());
        let mut values: Vec<(&str, &Text)> = pins.named().collect();
        values.push(("root", &seed));
        self.rewritten(&values)
    }
}

/// `manifest` reads the sweep's manifest of the suspect's profile under `root` and returns it when, with
/// the suspect's seed as its root, its UTF-8 bytes hash to `digest`, the `manifest_sha256` of the job
/// `campaign confirm` ran, which must be that text.
///
/// # Errors
///
/// [`SeedCheck::Failed`] with the path and the error of a manifest that cannot be read or is no UTF-8, and
/// [`SeedCheck::Nothing`] for a digest of other text.
pub fn manifest(
    root: &Path,
    suspect: &Suspect,
    digest: Option<&Value>,
) -> Result<Manifest, SeedCheck> {
    let mut name = suspect.profile().to_os().expect("a profile name is ASCII");
    name.push(".manifest");
    let path = root.join("manifests").join(name);
    let read = fs::read_to_string(&path)
        .map_err(|error| SeedCheck::Failed(Text::from(PathError::new(&path, error).to_string())))?;
    let mut lines: Vec<String> = newlines(read).split('\n').map(str::to_owned).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    let manifest = Manifest(lines);
    let seed = Text::from(suspect.seed().to_string());
    let seeded = manifest.rewritten(&[("root", &seed)]);
    let hashed = Text::from(hexdigest(seeded.as_bytes()));
    match digest {
        Some(Value::String(digest)) if *digest == hashed => Ok(manifest),
        _ => Err(SeedCheck::Nothing(Text::from(
            "its manifest differs from the job `confirm` ran",
        ))),
    }
}

/// `ending` reads what `campaign sim run` of a seed check printed: it exited `code` and printed `out`,
/// whose last line holds the worker's result. The ending is the result's `reason` when its text begins
/// with the class and `: `, else `CLASS: REASON`, or the class alone for a false or missing reason; each
/// is read as Python's `str` writes the value.
pub fn ending(code: i32, out: &str) -> SeedCheck {
    let printed = match last_object(out, "sim run") {
        Ok(printed) => printed,
        Err(_) => return SeedCheck::Nothing(words!("exit ", code, " with no result")),
    };
    let Some(class) = printed.get("class") else {
        return SeedCheck::Nothing(words!("exit ", code, " with no result"));
    };
    let kind = str_of(class);
    let ending = match printed.get("reason") {
        Some(reason) if truthy(reason) => {
            if str_of(reason).starts_with(&words!(kind, ": ")) {
                reason.clone()
            } else {
                Value::String(words!(kind, ": ", str_of(reason)))
            }
        }
        _ => Value::String(kind.clone()),
    };
    if code == 0 && kind != COUNTS {
        return SeedCheck::Nothing(words!("exit 0 with the class ", kind));
    }
    SeedCheck::Ran { code, ending }
}
