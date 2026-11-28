//! The root's `suspects.jsonl`, which a sweep appends one suspect a line, and the finding of `campaign
//! confirm` that confirms a suspect.
//!
//! A suspect is its profile, run and seed, with its class and key. A record is one line ended by a newline
//! byte; a last line without its newline is a write a kill cut short, and is neither read nor counted. A
//! missing list holds no suspect. A list that is no regular file, and a complete line that is no suspect,
//! leave no verdict. Each line is read as strict UTF-8 with [`json::parse_unique`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::values::{natural_integer, text};
use super::verdict::NoVerdict;
use crate::json::{self, Integer, Object, Value};
use crate::ownership::{Opened, is_link, open_regular};
use crate::text::{Text, text};

/// The classes of a suspect that can catch a plant;
/// crates/campaign-supervisor/src/campaign/seeds.rs writes the same two words.
pub(crate) const CATCH_CLASSES: [&str; 2] = ["violation", "panic"];
/// The class of a suspect whose replay ran otherwise than its run;
/// crates/campaign-supervisor/src/campaign/seeds.rs writes the same words.
pub(crate) const REPLAY_DIFFERS: &str = "replay differs";

/// A suspect's profile, run and seed.
pub(crate) type Identity = (Text, Integer, Integer);

/// One suspect of `suspects.jsonl`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suspect {
    profile: Text,
    run: Integer,
    seed: Integer,
    class: Text,
    key: Text,
}

impl Suspect {
    pub fn profile(&self) -> &Text {
        &self.profile
    }

    pub fn run(&self) -> &Integer {
        &self.run
    }

    pub fn seed(&self) -> &Integer {
        &self.seed
    }

    /// The suspect as a reason names it: `KEY in run RUN of PROFILE`.
    pub(crate) fn named(&self) -> Text {
        text!(self.key, " in run ", self.run, " of ", self.profile)
    }

    /// The suspect's identity: its profile, run and seed.
    pub(crate) fn identity(&self) -> Identity {
        (self.profile.clone(), self.run.clone(), self.seed.clone())
    }

    /// `members` are the suspect's profile, run, seed and key, in that order.
    pub(crate) fn members(&self) -> Object {
        let mut members = Object::new();
        members.insert("profile", Value::String(self.profile.clone()));
        members.insert("run", Value::Integer(self.run.clone()));
        members.insert("seed", Value::Integer(self.seed.clone()));
        members.insert("key", Value::String(self.key.clone()));
        members
    }

    /// `from_line` reads a line of `suspects.jsonl` as a suspect: strict UTF-8 holding an object whose
    /// `profile`, `class` and `key` are strings and whose `run` and `seed` are integers of at least zero.
    pub fn from_line(line: &[u8]) -> Option<Self> {
        let Ok(Value::Object(object)) = json::parse_unique(std::str::from_utf8(line).ok()?) else {
            return None;
        };
        let string = |name| match object.get(name)? {
            Value::String(text) => Some(text.clone()),
            _ => None,
        };
        let number = |name| object.get(name).and_then(natural_integer).cloned();
        Some(Self {
            profile: string("profile")?,
            run: number("run")?,
            seed: number("seed")?,
            class: string("class")?,
            key: string("key")?,
        })
    }
}

/// What `suspects.jsonl` lists: the suspects of the expected profiles and of a catch class, each once,
/// in file order; the count of complete records of any profile and class; the profile, run and seed of
/// each `replay differs` record; and the count of complete records of each profile and key.
#[derive(Debug, Default)]
pub(crate) struct Listing {
    pub(crate) listed: Vec<Suspect>,
    pub(crate) complete: usize,
    pub(crate) replayed: BTreeSet<Identity>,
    pub(crate) shown: BTreeMap<(Text, Text), usize>,
}

/// `listing` reads `path`, the root's `suspects.jsonl`, for the suspects of `profiles`, through one open
/// whose file it checks as a regular file; `work`, the work directory, names the path in the refusal of a
/// file that cannot be read.
///
/// # Errors
///
/// The path is no regular file, a complete line is no suspect (named by its number from 1), or the file
/// cannot be tested or read.
pub(crate) fn listing(path: &Path, profiles: &[Text], work: &Path) -> Result<Listing, NoVerdict> {
    let unreadable = |error: &std::io::Error| NoVerdict::unreadable(path, error, work);
    let mut listing = Listing::default();
    let opened = open_regular(path).map_err(|error| unreadable(error.error()))?;
    let file = match opened {
        Opened::File(file) => file,
        Opened::Absent if !is_link(path).map_err(|error| unreadable(error.error()))? => {
            return Ok(listing);
        }
        Opened::Absent | Opened::Other => {
            return Err(NoVerdict::plain(
                "the root's suspects.jsonl is no regular file",
            ));
        }
    };
    let mut lines = BufReader::new(file);
    let mut seen = BTreeSet::new();
    let mut line = Vec::new();
    for number in 1usize.. {
        line.clear();
        lines
            .read_until(b'\n', &mut line)
            .map_err(|error| unreadable(&error))?;
        if line.last() != Some(&b'\n') {
            break;
        }
        listing.complete += 1;
        let suspect = Suspect::from_line(&line).ok_or_else(|| {
            NoVerdict::plain(text!("suspects.jsonl line ", number, " is no suspect"))
        })?;
        *listing
            .shown
            .entry((suspect.profile.clone(), suspect.key.clone()))
            .or_default() += 1;
        if suspect.class == REPLAY_DIFFERS {
            listing.replayed.insert(suspect.identity());
        }
        let caught = CATCH_CLASSES.iter().any(|class| suspect.class == *class);
        if profiles.contains(&suspect.profile) && caught && seen.insert(suspect.identity()) {
            listing.listed.push(suspect);
        }
    }
    Ok(listing)
}

/// The finding that confirms a suspect: its id, and the digest of the job's manifest as it printed it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Found {
    pub(crate) id: Text,
    pub(crate) manifest_sha256: Option<Value>,
}

/// `member` is the member `name` of `value` when it is an object.
fn member<'a>(value: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    match value {
        Some(Value::Object(object)) => object.get(name),
        _ => None,
    }
}

/// `finding_of` is the first finding with a nonblank id whose admitted job ran the suspect's profile, run
/// and seed and whose verified kind is the suspect's class; a finding of another shape confirms nothing.
pub(crate) fn finding_of(findings: &[Object], suspect: &Suspect) -> Option<Found> {
    findings.iter().find_map(|finding| {
        let verified = finding.get("verified");
        let job = member(member(verified, "admission"), "job");
        let experiment = member(job, "experiment");
        let id = finding.get("id").filter(|id| text(id));
        let is_text = |value: Option<&Value>, wanted: &Text| matches!(value, Some(Value::String(found)) if found == wanted);
        let is_number = |value: Option<&Value>, wanted: &Integer| matches!(value, Some(Value::Integer(found)) if found == wanted);
        let ran = is_text(member(experiment, "profile"), &suspect.profile)
            && is_number(member(experiment, "run"), &suspect.run)
            && is_number(member(job, "seed"), &suspect.seed)
            && is_text(member(verified, "kind"), &suspect.class);
        match id {
            Some(Value::String(id)) if ran => Some(Found {
                id: id.clone(),
                manifest_sha256: member(job, "manifest_sha256").cloned(),
            }),
            _ => None,
        }
    })
}
