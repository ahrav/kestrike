//! The command line of the plant run: seven long options read by [`Reader`] with whole names alone, and
//! the help: the usage, the options and the rules of a run, which `help.md` states. `--plant` keeps
//! every occurrence in order; each other option keeps its last value.
//!
//! A count is read as Python's `int` reads a string: surrounding whitespace, a sign and single
//! underscores between digits are taken, the digits are ASCII, at most
//! [`crate::json::MAX_INTEGER_DIGITS`] of them, and the count must be at least 1; `--runs` must be at
//! least [`FLOOR`].

use std::ffi::{OsStr, OsString};

use crate::args::{Kind, Opt, Parsed, Prefixes, Reader, any};
use crate::json::{Integer, Value};
use crate::python;
use crate::text::Text;

const TOOL: &str = "plant-runner";
/// The least `--runs` a profile takes.
pub const FLOOR: u64 = 300;
const USAGE: &str = "usage: plant-runner [-h] [--work DIR] [--campaign PATH] [--workers N] [--runs N] \
                     [--for SECONDS] [--rounds N] [--plant ID]";
const HELP: &str = "Run each stored plant through a sweep.

options:
  -h, --help         show this help and exit
  --work DIR         a new work directory outside the checkout, on xfs or journaled ext4, under
                     ancestors only you or root can write (default: one under $TMPDIR, which must then
                     be such a directory)
  --campaign PATH    the campaign binary, on PATH or a path (default: campaign)
  --workers N        default: 28
  --runs N           the floor of runs a profile, at least 300 (default: 300)
  --for SECONDS      seconds a sweep (default: 60)
  --rounds N         sweeps a plant at most (default: 10)
  --plant ID         run this plant only, and write a score over the selected plants; repeatable
";

/// The options of the command line, with each default filled in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    work: Option<OsString>,
    campaign: OsString,
    workers: Integer,
    runs: Integer,
    seconds: Integer,
    rounds: Integer,
    plants: Vec<Text>,
}

impl Options {
    /// The `--work` value as given, `None` for the default directory.
    pub fn work(&self) -> Option<&OsStr> {
        self.work.as_deref()
    }

    /// The `--campaign` value as given, `campaign` by default.
    pub fn campaign(&self) -> &OsStr {
        &self.campaign
    }

    pub fn workers(&self) -> &Integer {
        &self.workers
    }

    pub fn runs(&self) -> &Integer {
        &self.runs
    }

    /// The `--for` value: seconds a sweep.
    pub fn seconds(&self) -> &Integer {
        &self.seconds
    }

    pub fn rounds(&self) -> &Integer {
        &self.rounds
    }

    /// The `--plant` values in command-line order, repeats kept; empty selects the whole store.
    pub fn plants(&self) -> &[Text] {
        &self.plants
    }
}

const fn value(names: &'static [&'static str], check: fn(&Text) -> Result<(), String>) -> Opt {
    Opt {
        names,
        kind: Kind::Value {
            required: false,
            check,
        },
    }
}

const TABLE: [Opt; 8] = [
    Opt {
        names: &["-h", "--help"],
        kind: Kind::Help,
    },
    value(&["--work"], any),
    value(&["--campaign"], any),
    value(&["--workers"], positive),
    value(&["--runs"], floor),
    value(&["--for"], positive),
    value(&["--rounds"], positive),
    Opt {
        names: &["--plant"],
        kind: Kind::Repeated { check: any },
    },
];

/// `count` reads `value` as Python's `int` reads a string; `kind` names the check in the refusal of a
/// value it does not read.
fn count(value: &Text, kind: &str) -> Result<Integer, String> {
    python::int(&Value::String(value.clone()))
        .map_err(|_| format!("invalid {kind} value: {}", value.repr()))
}

fn positive(value: &Text) -> Result<(), String> {
    if count(value, "positive")? < Integer::from(1u64) {
        return Err(format!("{value} is not a positive integer"));
    }
    Ok(())
}

fn floor(value: &Text) -> Result<(), String> {
    if count(value, "floor")? < Integer::from(FLOOR) {
        return Err(format!(
            "{value} is below the floor of {FLOOR} runs a profile"
        ));
    }
    Ok(())
}

/// `parse` reads `args` with the option table above and whole names alone.
pub(super) fn parse(args: &[OsString]) -> Parsed<Options> {
    let rules = include_str!("help.md")
        .split_once("\n\n")
        .map_or("", |(_, rules)| rules);
    let help = format!("{USAGE}\n\n{HELP}\n{rules}");
    let reader = Reader::new(TOOL, USAGE, &help, Prefixes::Refuse, &TABLE);
    reader.parse(args).map(|values| {
        let number = |name, default: u64| match values.get(name) {
            Some(given) => {
                count(&Text::from_os(given), "").expect("a checked count reads as an integer")
            }
            None => Integer::from(default),
        };
        Options {
            work: values.get("--work").map(OsStr::to_os_string),
            campaign: values
                .get("--campaign")
                .map_or_else(|| OsString::from("campaign"), OsStr::to_os_string),
            workers: number("--workers", 28),
            runs: number("--runs", FLOOR),
            seconds: number("--for", 60),
            rounds: number("--rounds", 10),
            plants: values
                .all("--plant")
                .iter()
                .map(|plant| Text::from_os(plant))
                .collect(),
        }
    })
}
