//! The judgment of a live plant after its sweeps, from the last sweep's exit, its `sweep-status`
//! document and the files of the plant's directory, with the two children it needs asked of its caller.
//!
//! The reads come first, and a failed read ends the judgment with no verdict: the expected profiles'
//! counters, `suspects.jsonl`, `campaign confirm` once a suspect is listed, and the status's account of
//! each listed profile's replays. Of the results, a catch outranks every cause. With no catch, each
//! profile of the status, controls and histories included, must give a suspect count; then the first
//! present one of the thirteen causes of no verdict is the reason, and with none the plant is missed.
//!
//! A catch is a suspect of a catch
//! class in an expected profile that `campaign confirm` turned into a finding of that class, whose replay
//! the sweep neither lists nor may hide as differing, and whose seed passes on the unpatched head. The seed
//! of every confirmed suspect that passes both replay tests is checked, in the list's order, once the
//! sweep's manifest hashes to the confirmed job's digest, so the entry lists each seed that fails on the
//! head, beside a catch too.
//!
//! The plant's directory holds `root/` (the sweep's root, with `suspects.jsonl` and `manifests/`) and
//! `confirm.err`, the error output of `campaign confirm`. The judgment trusts the plant's directory and
//! the work directory its caller names, which the run made under ancestors only its user or root can
//! write, and reads their files as they stand.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::entry::Entry;
use super::options::Options;
use super::output::{Confirmed, confirmed};
use super::seed::{Manifest, ending, manifest};
use super::status::{Runs, held_suspects, profile_runs, unlisted_replay};
use super::suspects::{Suspect, finding_of, listing};
use super::values::natural;
use super::verdict::{NoVerdict, Verdict};
use crate::json::{Integer, Object, Value};
use crate::python::{repr, str_of, truthy};
use crate::text::{Text, text};

/// The verdict keys a root's status can hold, each making its sweep exit 1;
/// crates/campaign-supervisor/src/campaign/seeds.rs reads the same four keys.
const VERDICT_KEYS: [&str; 4] = ["alarm", "no_pass", "unreached", "no_window"];

/// The children the judgment asks of its caller. Each returns the child's exit and its output as a text
/// read of its output file gives it. Once the run is interrupted, each later call returns its error with
/// no child started, and the caller scores no entry of that judgment.
pub trait Ask {
    /// `confirm` runs `campaign confirm` for the root, with its error output in the plant directory's
    /// `confirm.err`. The judgment asks it once, when `suspects.jsonl` lists a suspect of a catch class in
    /// an expected profile.
    ///
    /// # Errors
    ///
    /// The no verdict of a `confirm` that did not run.
    fn confirm(&mut self) -> Result<(i32, String), NoVerdict>;

    /// `run_seed` runs the suspect's seed on the unpatched head's archive with `manifest` pinned to that
    /// archive ([`Manifest::pinned`]). The judgment asks it only once the manifest's digest is the
    /// confirmed job's.
    ///
    /// # Errors
    ///
    /// Why the check did not run: the base archive's failure, or a manifest that cannot be written.
    fn run_seed(&mut self, suspect: &Suspect, manifest: &Manifest) -> Result<(i32, String), Text>;
}

/// The plant's sweeps as they ended: the last sweep's exit, 0 or 1, its status, the plant's directory, the
/// work directory, and the run index each profile's `next` must reach (`--runs`) and the most sweeps a
/// plant gets (`--rounds`).
#[derive(Clone, Copy, Debug)]
pub struct Sweep<'a> {
    exited_1: bool,
    status: &'a Object,
    place: &'a Path,
    work: &'a Path,
    options: &'a Options,
}

impl<'a> Sweep<'a> {
    /// `new` returns `None` for an exit other than 0 and 1, which leaves the plant's sweeps no verdict
    /// before any judgment.
    pub fn new(
        code: i32,
        status: &'a Object,
        place: &'a Path,
        work: &'a Path,
        options: &'a Options,
    ) -> Option<Self> {
        let exited_1 = match code {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some(Self {
            exited_1,
            status,
            place,
            work,
            options,
        })
    }

    fn root(&self) -> PathBuf {
        self.place.join("root")
    }
}

/// `judge` sets the result of the swept plant of `entry`: caught, missed or no verdict. The entry's plant
/// expects a profile; [`Entry::archived`] settles a plant without one.
pub fn judge(entry: &mut Entry, sweep: &Sweep<'_>, ask: &mut impl Ask) {
    if let Err(ending) = judged(entry, sweep, ask) {
        entry.no_verdict(&ending);
    }
}

fn member(status: &Object, name: &str) -> Value {
    status.get(name).cloned().unwrap_or(Value::Null)
}

/// What the suspect loop found: the catch, the reasons of the first three causes and of the unconfirmed
/// suspects, with the hold of `confirm` and the count of complete records of `suspects.jsonl`.
struct Suspects {
    caught: Option<(Text, Object)>,
    differing: Option<Text>,
    failures: Option<Text>,
    unchecked: Option<Text>,
    unconfirmed: Option<Text>,
    hold: Option<Text>,
    complete: usize,
}

fn judged(entry: &mut Entry, sweep: &Sweep<'_>, ask: &mut impl Ask) -> Result<(), NoVerdict> {
    let status = sweep.status;
    let profiles = entry.profiles().to_vec();
    entry.set("counts", member(status, "counts"));
    let mut runs = Vec::with_capacity(profiles.len());
    for profile in &profiles {
        runs.push((profile.clone(), profile_runs(status, profile)?));
    }
    let mut members = Object::new();
    for (profile, counted) in &runs {
        members.insert(profile.clone(), Value::Object(counted.members().clone()));
    }
    entry.set("runs", Value::Object(members));
    entry.set("controls", member(status, "controls"));
    entry.set("histories", member(status, "histories"));
    let mut keys = Object::new();
    for key in VERDICT_KEYS {
        if let Some(value) = status.get(key) {
            keys.insert(key, value.clone());
        }
    }
    entry.set("keys", Value::Object(keys.clone()));
    let root = sweep.root();
    let listing = listing(&root.join("suspects.jsonl"), &profiles, sweep.work)?;
    let confirmed = if listing.listed.is_empty() {
        Confirmed::default()
    } else {
        let (code, out) = ask.confirm()?;
        confirmed(code, &out, &sweep.place.join("confirm.err"), sweep.work)?
    };
    let mut hidden: BTreeMap<&Text, Option<Text>> = BTreeMap::new();
    for suspect in &listing.listed {
        if !hidden.contains_key(suspect.profile()) {
            let reason = unlisted_replay(status, suspect.profile(), &listing.shown)?;
            hidden.insert(suspect.profile(), reason);
        }
    }
    let mut found = Suspects {
        caught: None,
        differing: None,
        failures: None,
        unchecked: None,
        unconfirmed: None,
        hold: confirmed.hold.clone(),
        complete: listing.complete,
    };
    for suspect in &listing.listed {
        let named = suspect.named();
        let Some(finding) = finding_of(&confirmed.findings, suspect) else {
            found
                .unconfirmed
                .get_or_insert_with(|| text!("`campaign confirm` made no finding of ", named));
            continue;
        };
        if listing.replayed.contains(&suspect.identity()) {
            found.differing.get_or_insert_with(|| {
                text!(
                    "the sweep's replay of ",
                    named,
                    " differs, so its seed does not determine the run"
                )
            });
            continue;
        }
        if let Some(Some(why)) = hidden.get(suspect.profile()) {
            found.differing.get_or_insert_with(|| {
                text!(
                    why,
                    ", so a differing replay of ",
                    named,
                    " may be unlisted"
                )
            });
            continue;
        }
        let checked = manifest(&root, suspect, finding.manifest_sha256.as_ref())
            .and_then(|manifest| ask.run_seed(suspect, &manifest))
            .and_then(|(code, out)| ending(code, &out));
        let (code, ending) = match checked {
            Err(why) => {
                found.unchecked.get_or_insert_with(|| {
                    text!("the seed check of ", named, " did not run: ", why)
                });
                continue;
            }
            Ok(checked) => checked,
        };
        let mut members = suspect.members();
        members.insert("finding", Value::String(finding.id.clone()));
        members.insert("head", ending.clone());
        match code {
            0 => {
                if found.caught.is_none() {
                    found.caught = Some((named, members));
                }
            }
            1 | 4 => {
                let reason = text!(
                    "the seed of ",
                    named,
                    " does not pass on the unpatched head: ",
                    str_of(&ending)
                );
                members.insert("reason", Value::String(reason.clone()));
                entry.push_head_failure(members);
                found.failures.get_or_insert(reason);
            }
            _ => {
                found.unchecked.get_or_insert_with(|| {
                    text!(
                        "the seed check of ",
                        named,
                        " on the unpatched head exited ",
                        code,
                        " (",
                        str_of(&ending),
                        ")"
                    )
                });
            }
        }
    }
    if let Some((reason, caught)) = found.caught {
        entry.settle(Verdict::Caught, reason);
        entry.set("suspect", Value::Object(caught));
        return Ok(());
    }
    match cause(entry, sweep, &runs, &keys, &found)? {
        Some(reason) => Err(NoVerdict::plain(reason)),
        None => {
            let reason = text!(
                "each expected profile reached ",
                sweep.options.runs(),
                " runs and the root holds no suspect"
            );
            entry.settle(Verdict::Missed, reason);
            Ok(())
        }
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
    runs: &[(Text, Runs)],
    keys: &Object,
    found: &Suspects,
) -> Result<Option<Text>, NoVerdict> {
    let status = sweep.status;
    let (floor, rounds) = (sweep.options.runs(), sweep.options.rounds());
    let zero = Integer::from(0u64);
    let mut held: Vec<(Text, Integer)> = held_suspects(status)?
        .into_iter()
        .filter(|(_, number)| *number != zero)
        .collect();
    held.sort_by(|left, right| left.0.cmp(&right.0));
    let short: Vec<&Text> = runs
        .iter()
        .filter(|(_, counted)| counted.next() < floor)
        .map(|(profile, _)| profile)
        .collect();
    let total = member(status, "suspects");
    let campaign =
        matches!(status.get("campaign"), Some(Value::String(name)) if name == entry.campaign());
    let no_counts =
        matches!(status.get("counts"), Some(Value::Object(counts)) if counts.is_empty());
    let causes: [Option<Text>; 13] = [
        found.differing.clone(),
        found.failures.clone(),
        found.unchecked.clone(),
        (!keys.is_empty()).then(|| {
            let names: Vec<Text> = keys.iter().map(|(key, _)| key.clone()).collect();
            text!("the root holds ", Text::join(", ", &names))
        }),
        found.hold.clone(),
        found.unconfirmed.clone(),
        (!held.is_empty()).then(|| {
            let listed: Vec<Text> = held
                .iter()
                .map(|(profile, number)| text!(profile, " (", number, ")"))
                .collect();
            text!("the root holds suspects in ", Text::join(", ", &listed))
        }),
        (!natural(&total, 0) || truthy(&total)).then(|| {
            text!(
                "`campaign sweep-status` counts ",
                repr(&total),
                " suspects at the root"
            )
        }),
        (found.complete > 0).then(|| text!("`suspects.jsonl` lists ", found.complete, " suspects")),
        (sweep.exited_1 && keys.is_empty())
            .then(|| text!("the last sweep exited 1 and the root holds no verdict key")),
        (!(campaign && no_counts)).then(|| {
            text!(
                "`campaign sweep-status` names campaign ",
                repr(&member(status, "campaign")),
                " and counts ",
                repr(&member(status, "counts"))
            )
        }),
        (!short.is_empty()).then(|| {
            text!(
                Text::join(", ", short.iter().copied()),
                " stayed below ",
                floor,
                " runs after ",
                rounds,
                " sweeps"
            )
        }),
        runs.iter()
            .find(|(_, counted)| *counted.runs() == zero)
            .map(|(profile, _)| text!(profile, " has no run counted")),
    ];
    Ok(causes.into_iter().flatten().next())
}
