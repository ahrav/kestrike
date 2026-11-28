//! The JSON documents `campaign` prints, read from a finished command's exit code and output text: the
//! object of an output line, the pins `campaign sim archive` prints, and the findings and the backlog hold
//! `campaign confirm` prints.
//!
//! An output is the text a read of the command's output file as text gives, with `\r\n` and `\r` read as
//! `\n` ([`crate::text::newlines`]); it breaks at `\n` alone. Every document is read with
//! [`json::parse_unique`], which refuses a repeated member.

use std::fs;
use std::path::Path;

use super::verdict::NoVerdict;
use crate::json::{self, Object, UniqueError, Value};
use crate::python::repr;
use crate::text::{Text, strip_str, text};

/// The pins of an archive, in the order a manifest names them; crates/campaign-supervisor/src/sim/input.rs
/// holds the same four names.
const PINS: [&str; 4] = ["build", "executable", "platform", "toolchain"];
/// The dispatch of a `confirm` that settled every job; crates/sim-host/src/runner.rs holds the same
/// word.
const QUEUE_EMPTY: &str = "queue_empty";
/// The dispatch of a `confirm` a refusal stopped; crates/campaign-supervisor/src/campaign/dispatch/mod.rs
/// writes the same word for `State::Held`.
const HELD: &str = "held";
/// The prefix of a backlog hold's refusal; crates/sim-host/src/runner.rs holds the same words.
const BACKLOG: &str = "backlog holds ";
/// The suffix of a backlog hold's refusal; crates/sim-host/src/runner.rs holds the same words.
const BACKLOG_END: &str = "; dispose findings or raise backlog";
/// The words a `confirm` writes to its error output when it prints only some of its refusals;
/// crates/sim-host/src/runner.rs holds the same words.
const OMITTED: &str = "omitted refusals:";

/// `object` reads `line` of the output of `campaign WHAT` as one JSON object.
fn object(line: &str, what: &str) -> Result<Object, NoVerdict> {
    let printed = text!("`campaign ", what, "` printed no JSON object");
    match json::parse_unique(line) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(NoVerdict::plain(printed)),
        Err(UniqueError::Syntax(error)) => {
            Err(NoVerdict::plain(text!(printed, ": ", error.to_string())))
        }
        Err(UniqueError::Repeated(name, _)) => {
            Err(NoVerdict::plain(text!(printed, ": repeated member ", name)))
        }
    }
}

/// `first_object` is the JSON object on the first line of `out`, the output of `campaign WHAT`.
///
/// # Errors
///
/// The line is no JSON object, or repeats a member.
pub fn first_object(out: &str, what: &str) -> Result<Object, NoVerdict> {
    object(out.split('\n').next().unwrap_or_default(), what)
}

/// `last_object` is the JSON object on the last line of `out`, the output of `campaign WHAT`, once
/// [`strip_str`] has removed the whitespace at its ends.
///
/// # Errors
///
/// The line is no JSON object, or repeats a member.
pub fn last_object(out: &str, what: &str) -> Result<Object, NoVerdict> {
    object(strip_str(out).rsplit('\n').next().unwrap_or_default(), what)
}

/// The pins an archive's build printed, each text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pins([Text; 4]);

impl Pins {
    /// The build digest.
    pub fn build(&self) -> &Text {
        &self.0[0]
    }

    /// Each of the [`PINS`] with its value, in that order.
    pub fn named(&self) -> impl Iterator<Item = (&'static str, &Text)> {
        PINS.into_iter().zip(self.0.iter())
    }
}

/// `archive_pins` reads the pins from `campaign sim archive` of `what`, which exited `code` and printed
/// `out`; `err` names its error output from the work directory.
///
/// # Errors
///
/// The build failed (exit 3), the command exited otherwise than 0, its last line is no JSON object, or a
/// pin is missing or no text.
pub fn archive_pins(code: i32, out: &str, what: &str, err: &Path) -> Result<Pins, NoVerdict> {
    if code == 3 {
        return Err(NoVerdict::plain(text!(
            what,
            " does not build: `campaign sim archive` exited 3"
        )));
    }
    if code != 0 {
        return Err(NoVerdict::plain(text!(
            "`campaign sim archive` of ",
            what,
            " exited ",
            code,
            "; its error is in ",
            err
        )));
    }
    let printed = last_object(out, "sim archive")?;
    let pin = |key: &str| match printed.get(key) {
        Some(Value::String(pin)) => Some(pin.clone()),
        _ => None,
    };
    match PINS.map(pin) {
        [
            Some(build),
            Some(executable),
            Some(platform),
            Some(toolchain),
        ] => Ok(Pins([build, executable, platform, toolchain])),
        _ => Err(NoVerdict::plain("`campaign sim archive` printed no pins")),
    }
}

/// What a `campaign confirm` printed: its findings, each an object, and the reason
/// `` `campaign confirm` held its queue: REFUSAL `` of the backlog hold that stopped it, if one did.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Confirmed {
    pub(crate) findings: Vec<Object>,
    pub(crate) hold: Option<Text>,
}

/// `backlog` holds for a refusal that is the backlog limit's.
fn backlog(refusal: &Value) -> bool {
    matches!(refusal, Value::String(line)
        if line.starts_with(&Text::from(BACKLOG)) && line.ends_with(&Text::from(BACKLOG_END)))
}

/// `confirmed` reads what `campaign confirm` printed: it exited `code` and printed `out`, and `errors` is
/// the file of its error output, read with each invalid UTF-8 sequence replaced, which `work`, the work
/// directory, names in a refusal. An exit 4 whose every refusal is the backlog limit, with no rejection
/// and no omitted refusal, still printed the findings it made.
///
/// # Errors
///
/// Another exit than 0 or 4; a first line that is no JSON object; an exit 4 of another hold; an exit 0
/// whose dispatch is not `queue_empty`; no list of finding objects; and an error file that cannot be read
/// at an exit 4.
pub(crate) fn confirmed(
    code: i32,
    out: &str,
    errors: &Path,
    work: &Path,
) -> Result<Confirmed, NoVerdict> {
    if code != 0 && code != 4 {
        return Err(NoVerdict::plain(text!("`campaign confirm` exited ", code)));
    }
    let printed = first_object(out, "confirm")?;
    let dispatch = || repr(printed.get("dispatch").unwrap_or(&Value::Null));
    let is = |key: &str, word: &str| matches!(printed.get(key), Some(Value::String(found)) if found == &word);
    let mut hold = None;
    if code == 4 {
        let read = fs::read(errors).map_err(|error| NoVerdict::unreadable(errors, &error, work))?;
        let omitted = String::from_utf8_lossy(&read).contains(OMITTED);
        let refusals = match printed.get("refusals") {
            Some(Value::Array(refusals)) => refusals.as_slice(),
            _ => &[],
        };
        let rejections =
            matches!(printed.get("rejections"), Some(Value::Array(none)) if none.is_empty());
        match refusals.first() {
            Some(Value::String(first))
                if is("dispatch", HELD)
                    && rejections
                    && !omitted
                    && refusals.iter().all(backlog) =>
            {
                hold = Some(text!("`campaign confirm` held its queue: ", first));
            }
            _ => {
                return Err(NoVerdict::plain(text!(
                    "`campaign confirm` exited 4 at dispatch ",
                    dispatch()
                )));
            }
        }
    } else if !is("dispatch", QUEUE_EMPTY) {
        return Err(NoVerdict::plain(text!(
            "`campaign confirm` left its queue at dispatch ",
            dispatch()
        )));
    }
    let listing = match printed.get("findings") {
        Some(Value::Object(listing)) => listing.get("findings"),
        _ => None,
    };
    let findings = match listing {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Object(finding) => Some(finding.clone()),
                _ => None,
            })
            .collect::<Option<Vec<Object>>>(),
        _ => None,
    };
    let findings = findings
        .ok_or_else(|| NoVerdict::plain("`campaign confirm` printed no list of findings"))?;
    Ok(Confirmed { findings, hold })
}
