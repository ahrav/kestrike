//! The judgment of a live plant after its sweeps, from the last sweep's exit, its `sweep-status`
//! document and the root's `suspects.jsonl`, with the two children it needs asked of its caller.
//!
//! The checks run in the order of the results: a catch first, then each of the thirteen causes of no
//! verdict in turn, the first present one being the reason, then the miss. A catch is a suspect of a catch
//! class in an expected profile that `campaign confirm` turned into a finding of that class, whose replay
//! the sweep neither lists nor may hide as differing, and whose seed passes on the unpatched head. The seed
//! of every confirmed suspect that passes both replay tests is checked, in the list's order, so the entry
//! lists each one that fails on the head, beside a catch too.

use std::path::Path;

use super::entry::{Entry, Verdict};
use super::output::Confirmed;
use super::seed::SeedCheck;
use super::status::{held_suspects, profile_runs, unlisted_replay};
use super::suspects::{Suspect, finding_of, listing};
use super::values::natural;
use super::verdict::NoVerdict;
use super::words::words;
use crate::json::{Integer, Object, Value};
use crate::python::{repr, str_of};
use crate::text::Text;

/// The verdict keys a root's status can hold, each making its sweep exit 1;
/// crates/campaign-supervisor/src/campaign/seeds.rs reads the same four keys.
const VERDICT_KEYS: [&str; 4] = ["alarm", "no_pass", "unreached", "no_window"];

/// The children the judgment asks of its caller.
pub trait Ask {
    /// `confirm` runs `campaign confirm` for the root and reads it with [`super::confirmed`]. The judgment
    /// asks it once, when `suspects.jsonl` lists a suspect of a catch class in an expected profile.
    ///
    /// # Errors
    ///
    /// The no verdict that `campaign confirm` leaves.
    fn confirm(&mut self) -> Result<Confirmed, NoVerdict>;

    /// `seed` checks the suspect's seed on the unpatched head; `digest` is the `manifest_sha256` of the
    /// job that confirmed it, as `campaign confirm` printed it.
    fn seed(&mut self, suspect: &Suspect, digest: Option<&Value>) -> SeedCheck;
}

/// The plant's sweeps as they ended: the last sweep's exit, 0 or 1, its status, the root, the work
/// directory, and the floor of runs a profile and the sweeps a plant at most of the run's options.
#[derive(Clone, Copy, Debug)]
pub struct Sweep<'a> {
    code: i32,
    status: &'a Object,
    root: &'a Path,
    work: &'a Path,
    floor: &'a Integer,
    rounds: &'a Integer,
}

impl<'a> Sweep<'a> {
    pub fn new(
        code: i32,
        status: &'a Object,
        root: &'a Path,
        work: &'a Path,
        floor: &'a Integer,
        rounds: &'a Integer,
    ) -> Self {
        Self {
            code,
            status,
            root,
            work,
            floor,
            rounds,
        }
    }
}

/// `judge` sets the result of the swept plant of `entry`: caught, missed or no verdict.
pub fn judge(entry: &mut Entry, sweep: &Sweep<'_>, ask: &mut impl Ask) {
    if let Err(ending) = judged(entry, sweep, ask) {
        entry.no_verdict(&ending);
    }
}

fn member(status: &Object, name: &str) -> Value {
    status.get(name).cloned().unwrap_or(Value::Null)
}

/// What the suspect loop found: the catch, and the reasons of the first three causes apart from the head
/// failures, which the entry holds.
#[derive(Default)]
struct Suspects {
    caught: Option<(Text, Object)>,
    unconfirmed: Vec<Text>,
    differing: Vec<Text>,
    unchecked: Vec<Text>,
}

fn judged(entry: &mut Entry, sweep: &Sweep<'_>, ask: &mut impl Ask) -> Result<(), NoVerdict> {
    let status = sweep.status;
    let profiles = entry.profiles();
    entry.set("counts", member(status, "counts"));
    let mut runs = Object::new();
    for profile in &profiles {
        let counted = profile_runs(status, profile)?;
        runs.insert(profile.clone(), Value::Object(counted.members().clone()));
    }
    entry.set("runs", Value::Object(runs.clone()));
    entry.set("controls", member(status, "controls"));
    entry.set("histories", member(status, "histories"));
    let mut keys = Object::new();
    for key in VERDICT_KEYS {
        if let Some(value) = status.get(key) {
            keys.insert(key, value.clone());
        }
    }
    entry.set("keys", Value::Object(keys.clone()));
    let listing = listing(&sweep.root.join("suspects.jsonl"), &profiles, sweep.work)?;
    let confirmed = if listing.listed.is_empty() {
        Confirmed::default()
    } else {
        ask.confirm()?
    };
    let mut hidden: Vec<(&Text, Option<Text>)> = Vec::new();
    for suspect in &listing.listed {
        if !hidden
            .iter()
            .any(|(profile, _)| *profile == suspect.profile())
        {
            let reason = unlisted_replay(status, suspect.profile(), &listing.shown)?;
            hidden.push((suspect.profile(), reason));
        }
    }
    let mut found = Suspects::default();
    for suspect in &listing.listed {
        let named = suspect.named();
        let Some(finding) = finding_of(confirmed.findings(), suspect) else {
            found
                .unconfirmed
                .push(words!("`campaign confirm` made no finding of ", named));
            continue;
        };
        let identity = (
            suspect.profile().clone(),
            suspect.run().clone(),
            suspect.seed().clone(),
        );
        if listing.replayed.contains(&identity) {
            found.differing.push(words!(
                "the sweep's replay of ",
                named,
                " differs, so its seed does not determine the run"
            ));
            continue;
        }
        let hides = hidden
            .iter()
            .find(|(profile, _)| *profile == suspect.profile());
        if let Some((_, Some(why))) = hides {
            found.differing.push(words!(
                why,
                ", so a differing replay of ",
                named,
                " may be unlisted"
            ));
            continue;
        }
        let (code, ending) = match ask.seed(suspect, finding.manifest_sha256.as_ref()) {
            SeedCheck::Failed(why) | SeedCheck::Nothing(why) => {
                found
                    .unchecked
                    .push(words!("the seed check of ", named, " did not run: ", why));
                continue;
            }
            SeedCheck::Ran { code, ending } => (code, ending),
        };
        let mut members = suspect.members();
        members.insert("finding", Value::String(finding.id.clone()));
        members.insert("head", ending.clone());
        if code == 0 && found.caught.is_none() {
            found.caught = Some((named, members));
        } else if code == 1 || code == 4 {
            members.insert(
                "reason",
                Value::String(words!(
                    "the seed of ",
                    named,
                    " does not pass on the unpatched head: ",
                    str_of(&ending)
                )),
            );
            entry.push_head_failure(members);
        } else if code != 0 {
            found.unchecked.push(words!(
                "the seed check of ",
                named,
                " on the unpatched head exited ",
                code,
                " (",
                str_of(&ending),
                ")"
            ));
        }
    }
    if let Some((reason, caught)) = found.caught {
        entry.settle(Verdict::Caught, reason);
        entry.set("suspect", Value::Object(caught));
        return Ok(());
    }
    let reason = cause(
        entry,
        sweep,
        &runs,
        &keys,
        (&found, listing.complete),
        &confirmed,
    )?;
    match reason {
        Some(reason) => Err(NoVerdict::plain(reason)),
        None => {
            let reason = words!(
                "each expected profile reached ",
                sweep.floor,
                " runs and the root holds no suspect"
            );
            entry.settle(Verdict::Missed, reason);
            Ok(())
        }
    }
}

fn counter<'a>(runs: &'a Object, profile: &Text, name: &str) -> &'a Integer {
    match runs.get_text(profile) {
        Some(Value::Object(counted)) => match counted.get(name) {
            Some(Value::Integer(number)) => number,
            _ => panic!("a profile's checked counters hold {name}"),
        },
        _ => panic!("the entry's runs hold each expected profile"),
    }
}

/// `cause` is the reason of the first of the thirteen causes of no verdict that is present, or `None` for
/// a miss.
///
/// # Errors
///
/// The status gives a profile no suspect count.
fn cause(
    entry: &Entry,
    sweep: &Sweep<'_>,
    runs: &Object,
    keys: &Object,
    (found, complete): (&Suspects, usize),
    confirmed: &Confirmed,
) -> Result<Option<Text>, NoVerdict> {
    let status = sweep.status;
    let zero = Integer::from(0u64);
    let mut held: Vec<(Text, Integer)> = held_suspects(status)?
        .into_iter()
        .filter(|(_, number)| *number != zero)
        .collect();
    held.sort_by(|left, right| left.0.cmp(&right.0));
    let profiles = entry.profiles();
    let short: Vec<&Text> = profiles
        .iter()
        .filter(|profile| counter(runs, profile, "next") < sweep.floor)
        .collect();
    let total = member(status, "suspects");
    let failures: Vec<Text> = match entry.members().get("head_failures") {
        Some(Value::Array(failures)) => failures
            .iter()
            .map(|failure| match failure {
                Value::Object(failure) => str_of(failure.get("reason").unwrap_or(&Value::Null)),
                _ => panic!("a head failure is an object"),
            })
            .collect(),
        _ => panic!("an entry holds its head failures"),
    };
    let campaign =
        matches!(status.get("campaign"), Some(Value::String(name)) if name == entry.campaign());
    let counts = matches!(status.get("counts"), Some(Value::Object(counts)) if counts.is_empty());
    let causes: [Option<Text>; 13] = [
        found.differing.first().cloned(),
        failures.first().cloned(),
        found.unchecked.first().cloned(),
        (!keys.is_empty()).then(|| {
            let names: Vec<Text> = keys.iter().map(|(key, _)| key.clone()).collect();
            words!("the root holds ", Text::join(", ", &names))
        }),
        confirmed.hold().cloned(),
        found.unconfirmed.first().cloned(),
        (!held.is_empty()).then(|| {
            let listed: Vec<Text> = held
                .iter()
                .map(|(profile, number)| words!(profile, " (", number, ")"))
                .collect();
            words!("the root holds suspects in ", Text::join(", ", &listed))
        }),
        (!natural(&total, 0) || total != Value::Integer(zero.clone())).then(|| {
            words!(
                "`campaign sweep-status` counts ",
                repr(&total),
                " suspects at the root"
            )
        }),
        (complete > 0).then(|| words!("`suspects.jsonl` lists ", complete, " suspects")),
        (sweep.code == 1 && keys.is_empty()).then(|| {
            words!(
                "the last sweep exited ",
                sweep.code,
                " and the root holds no verdict key"
            )
        }),
        (!(campaign && counts)).then(|| {
            words!(
                "`campaign sweep-status` names campaign ",
                repr(&member(status, "campaign")),
                " and counts ",
                repr(&member(status, "counts"))
            )
        }),
        (!short.is_empty()).then(|| {
            words!(
                Text::join(", ", short.iter().copied()),
                " stayed below ",
                sweep.floor,
                " runs after ",
                sweep.rounds,
                " sweeps"
            )
        }),
        profiles
            .iter()
            .find(|profile| *counter(runs, profile, "runs") == zero)
            .map(|profile| words!(profile, " has no run counted")),
    ];
    Ok(causes.into_iter().flatten().next())
}
