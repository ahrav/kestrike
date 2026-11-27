//! The judgment of a live plant after its sweeps, from the last sweep's exit, its `sweep-status`
//! document and the files of the plant's directory, with the two children it needs asked of its caller.
//!
//! The checks run in the order of the results: a catch first, then each of the thirteen causes of no
//! verdict in turn, the first present one being the reason, then the miss. A catch is a suspect of a catch
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

use std::path::{Path, PathBuf};

use super::entry::{Entry, Verdict};
use super::options::Options;
use super::output::{Confirmed, confirmed};
use super::seed::{Manifest, SeedCheck, ending, manifest};
use super::status::{Runs, held_suspects, profile_runs, unlisted_replay};
use super::suspects::{Suspect, finding_of, listing};
use super::values::natural;
use super::verdict::NoVerdict;
use crate::json::{Integer, Object, Value};
use crate::python::{repr, str_of, truthy};
use crate::text::{Text, text};

/// The verdict keys a root's status can hold, each making its sweep exit 1;
/// crates/campaign-supervisor/src/campaign/seeds.rs reads the same four keys.
const VERDICT_KEYS: [&str; 4] = ["alarm", "no_pass", "unreached", "no_window"];

/// The children the judgment asks of its caller. Each returns the child's exit and its output as a text
/// read of its output file gives it.
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
/// work directory, and the runs each profile must reach (`--runs`) and the most sweeps a plant gets
/// (`--rounds`).
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
/// expects a profile; a plant without one is settled by [`Entry::unswept`] once its archive builds.
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
    differing: Vec<Text>,
    failures: Vec<Text>,
    unchecked: Vec<Text>,
    unconfirmed: Vec<Text>,
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
        Confirmed::none()
    } else {
        let (code, out) = ask.confirm()?;
        confirmed(code, &out, &sweep.place.join("confirm.err"), sweep.work)?
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
    let mut found = Suspects {
        caught: None,
        differing: Vec::new(),
        failures: Vec::new(),
        unchecked: Vec::new(),
        unconfirmed: Vec::new(),
        hold: confirmed.hold().cloned(),
        complete: listing.complete,
    };
    for suspect in &listing.listed {
        let named = suspect.named();
        let Some(finding) = finding_of(confirmed.findings(), suspect) else {
            found
                .unconfirmed
                .push(text!("`campaign confirm` made no finding of ", named));
            continue;
        };
        if listing.replayed.contains(&suspect.identity()) {
            found.differing.push(text!(
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
            found.differing.push(text!(
                why,
                ", so a differing replay of ",
                named,
                " may be unlisted"
            ));
            continue;
        }
        let checked = manifest(&root, suspect, finding.manifest_sha256.as_ref())
            .and_then(|manifest| ask.run_seed(suspect, &manifest))
            .map(|(code, out)| ending(code, &out));
        let (code, ending) = match checked {
            Err(why) | Ok(SeedCheck::NotRun(why)) => {
                found
                    .unchecked
                    .push(text!("the seed check of ", named, " did not run: ", why));
                continue;
            }
            Ok(SeedCheck::Ran { code, ending }) => (code, ending),
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
                found.failures.push(reason);
            }
            _ => found.unchecked.push(text!(
                "the seed check of ",
                named,
                " on the unpatched head exited ",
                code,
                " (",
                str_of(&ending),
                ")"
            )),
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
        found.differing.first().cloned(),
        found.failures.first().cloned(),
        found.unchecked.first().cloned(),
        (!keys.is_empty()).then(|| {
            let names: Vec<Text> = keys.iter().map(|(key, _)| key.clone()).collect();
            text!("the root holds ", Text::join(", ", &names))
        }),
        found.hold.clone(),
        found.unconfirmed.first().cloned(),
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
