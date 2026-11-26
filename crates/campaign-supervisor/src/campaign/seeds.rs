//! `campaign sweep`: seed exploration that keeps a record only for a run
//! that needs one.
//!
//! The command claims its root, a directory only this user can write that
//! one sweep holds at a time, verifies the archive before the first run
//! and after the last, reads the worker's listing once, within the ready
//! wait, and freezes one manifest per profile. Each of `workers` threads runs batches: one
//! archived worker process in `--sweep` mode, fed one root at a time for
//! one profile until the batch's time ends. A worker prints a ready line
//! before it reads a root; one that ends before that line, or prints none
//! within the ready wait, ran no root, so it fails the sweep and is
//! charged to no seed. The root of run `n` of a
//! profile is the seed of the job `campaign admit` derives from the same
//! archive for the same campaign, profile, run and counts at its default
//! attempt limit, so a swept run and that supervised job execute one
//! manifest.
//!
//! A run's block is parsed as the run form's output and earns its ending
//! only beside the exit code that form gives it. Counting an initial pass updates only
//! aggregate totals. A pass with cluster lines increments `covered` and
//! reaches each event whose drawn count is positive. A run that ends `unsuccessful`
//! or `inconclusive` adds to the totals under its rule. Every other ending
//! is a suspect: a violation, a panic, a refusal, an infrastructure
//! terminal other than the recorder's cap, a summary the parser refuses,
//! that names another profile than the worker's or whose exit code
//! disagrees with it, a worker that exits during a run, is killed during
//! one or prints more than a block's bound, a control run that passes
//! or whose plant met no check, and a run whose replay differs. The
//! first eight suspects of each profile, class and
//! failure identity are each one line of `suspects.jsonl` naming the
//! campaign, profile, run and counts that `campaign confirm` admits as a
//! supervised job, with the root and the archive's build that check it;
//! later ones are counted. A panic's identity is its location, and a
//! profile keys at most 256 identities plus `other`, so each profile adds
//! at most 257 suspect keys to `sweep.json` and 2,056 lines to
//! `suspects.jsonl`.
//!
//! One batch in [`CONTROL_EVERY`] of a root's batches, which `sweep.json`
//! counts across its sweeps, runs a control: a profile that plants a
//! wrong behavior in the scenario of one of the sweep's profiles and that
//! [`controls::swept`] names for it. A sweep is rejected before its first
//! run and before binding the root when the worker's capability listing omits
//! a scheduled control or the cluster declaration of a selected profile in
//! the [required-event table](required::REQUIRED). A control batch takes the control with the fewest control batches begun
//! in the root's sweeps, the earliest listed among equals, and
//! `sweep.json` keeps each control's count. A control batch that sends
//! its worker no root is not counted: one the sweep's end keeps from its
//! first root, and one whose replay or worker fails the sweep before it. So the sweeps of one profile
//! list take its controls in turn, and a later sweep of the root takes
//! first the controls with the fewest control batches begun, whatever
//! profiles each sweep listed. The count is of control batches alone: a
//! control's runs as one of the sweep's profiles do not raise it, and a
//! sweep that is killed can leave a batch counted whose first run was
//! not. A
//! control run that ends in its declared failure is counted under `caught`
//! and leaves no file. A control run that passes is a suspect of class
//! `control passed`. One whose plant did what a rule forbids while no
//! check failed is a suspect of class `control met no check`, and so is a
//! run that ends unsuccessful or inconclusive when its control's plant
//! precedes the run. Each is counted under `missed` and makes the command
//! exit 1: the checks let a planted defect through, so the sweep's passes
//! earn no trust until it is explained. A control's replay that ends in
//! one of those classes where its run did not is counted under `missed`
//! too. A control run that finished
//! before its plant took effect is counted under its rule, and every
//! other ending of a control run is counted as a live run's is. A control
//! the command line lists among its profiles is judged the same way.
//!
//! One batch in [`CONTROL_EVERY`], from the root's tenth batch, runs a
//! scripted history: a profile of the history class, whose listing line
//! says how it ends. The sweep takes each listed history that expects a
//! pass or declares its failure, as [`histories_of`] names them, the one
//! with the fewest history batches begun in the root's sweeps first and
//! the earliest listed among equals, as it takes its controls. A history
//! that expects a pass is counted as a live profile is. One that expects
//! no pass is judged as a control by the failure its line declares. A run
//! that ends in the declared violation, under its obligation and rule, is
//! counted under `caught`. So is a run that completes unsuccessful and
//! prints the declared witness, when that witness is shorter than the 41
//! bytes a summary prints of a rule: a longer one is cut in the summary
//! and could be another witness with the same start, so it earns no
//! credit. A run that passes, with or without its witnesses, is a suspect
//! of class `control passed`, counted under `missed`. One that ends in
//! another violation is a suspect of class `violation`. One that ends
//! unsuccessful under another rule, at the recorder's cap or inconclusive
//! is counted under that ending, whatever witness its summary holds. A
//! listing below version 4 declares no failure, so a sweep of its worker
//! runs the passing histories alone, and a sweep whose profiles name a
//! history that expects no pass is rejected before its first run. Each
//! history is frozen with the sweep's counts, and its manifest is a file
//! named for it, so a count below a listed history's bound, and a listed
//! history whose name is no single path component or is longer than 242
//! bytes, reject the sweep too.
//!
//! A profile the listing classes as live, recovery or history, with
//! [`NO_PASS_RUNS`] runs or more in the root and none of them counted
//! under `pass` or `caught`, earned nothing: each run was counted under
//! `uncredited` or was a suspect. A history that expects a failure is
//! among them, and its `caught` runs keep it off the list. The root's
//! totals list such a profile under `no_pass`. The covered-pass floor for `unreached` is
//! [`required::REQUIRED_PASSES`]. At or above the floor, the list contains
//! each required event with zero reaching passes. In a root whose counts
//! set `restarts` to [`EVERY_CUT`] or more, the totals list under
//! `no_window` each profile with [`NO_PASS_RUNS`] runs or more and a
//! planned crash window with zero counted cuts or a total that sums
//! distinct planned rows, as [`status`] describes. The sweep exits with
//! status 1 if `no_pass`, `unreached` or `no_window` is nonempty.
//!
//! A batch of one of the sweep's profiles or controls, after that
//! profile's first in the sweep, begins by replaying the last run the
//! profile finished in such a batch of the sweep. A history batch replays its own last
//! finished run once its worker has exited and its pen is empty, while
//! the sweep still runs, so a history is replayed in the batch that ran
//! it. A replay is a fresh worker process that runs, as one recorded run,
//! the manifest admission derives for that campaign, profile and run. A
//! replay that exits with another code or prints another summary than the
//! sweep read for the run makes the run a suspect of class `replay
//! differs`, listed with both observations: the digest and ending the
//! sweep read under `first`, beside the replay's code and summary. A
//! replay that a kill ends, or whose worker ends without an exit code,
//! makes the run a suspect of the class that end has. A replay that
//! SIGINT or SIGTERM ends, as when the sweep's unit is stopped, was
//! interrupted: it lists no suspect. This checks that a swept run is the
//! supervised job of the same campaign, profile and run, which runs that
//! manifest in a new process as the replay did, and that its result is
//! independent of the runs before it in its worker process. A profile or
//! control batch's time for fresh roots starts after its replay.
//!
//! Every worker runs in its thread's [`pen`], a cgroup with one CPU, a
//! memory limit and a process limit. The sweep holds the lock of the
//! pens' root for its lifetime, and a sweep that finds the lock held
//! ends busy before its first run. A run whose pen the sweep killed at
//! the wall limit is a suspect of class `wall limit`. A run whose worker
//! ended after the kernel killed a process of the pen for its memory use
//! is one of class `out of memory`, and a run whose worker ended for
//! another cause one of class `worker ended during the run`. After each
//! worker the thread kills every process left in the pen. A remaining
//! process marks the last finished run as `left a process` when the block
//! stream completed and the monitor left the overdue flag clear. A replay that agrees
//! and leaves a process marks its run with the same class.
//!
//! `sweep.json` holds the archive's build, the sweep's campaign and
//! `--set` counts, and each profile's next run number and totals. The
//! command writes it for a new root once the worker's listing has
//! accepted the sweep's profiles and counts and before the first worker
//! starts, replaces it
//! every few seconds and reads it when it starts, so a later sweep of the
//! same root with the same build, campaign and counts continues at fresh
//! run numbers. A root takes one of each: a sweep with an archive of
//! another build, another campaign or other counts is rejected before it
//! writes a manifest or starts a worker, so every line of `suspects.jsonl`
//! names a run of one archive, and a run number in the totals, with its
//! profile, names one root. A sweep whose archive fails the verification
//! after its last run writes that into `sweep.json`, with its last totals
//! when they can be written and without them otherwise, and every reader
//! then refuses the root, whose runs may be of other bytes than the
//! build's. A sweep that is killed before that verification leaves no
//! such mark and its root continues, and a mark that cannot be written
//! leaves the root unmarked, which the sweep's error says. A replacement
//! that fails stops the
//! workers and fails the sweep. A sweep killed between two replacements
//! leaves the counts of the earlier one: the next sweep of the root takes
//! those run numbers again, runs the same roots and lists their suspects
//! again, past the bounds above, and `confirm` admits a suspect listed
//! twice as one job. A run that was in a worker when the earlier
//! replacement was written has its number in those counts, so when the
//! sweep is killed before that run ends, the next sweep does not run its
//! root again, and the run is in no total and no list. A record of
//! `suspects.jsonl` that a kill left without its newline is not read by
//! `confirm` and is cut when the next sweep claims the root.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::calibration::controls::{self, Control, Ended};
use super::calibration::uncaught;
use super::freeze::ATTEMPTS;
use super::known;
use super::{Error, Request};
use crate::protocol::{
    COVERAGE, Class, FailureIdentity, Infrastructure, Listing, Outcome, RULE_CATALOG, Rule, Rules,
    Run, Summary, Terminal,
};
use crate::record::{Digest, Pins, Text};
use crate::store::cgroup::{CPU_PERIOD_US, FitError, Root};

pub(super) mod fuzz;
mod pen;
#[cfg(test)]
mod pen_tests;
mod required;

use pen::{Limits, Pen};

/// The seconds between two replacements of `sweep.json`.
const FLUSH: Duration = Duration::from_secs(5);

/// One batch in this many runs a control, when the sweep's profiles have
/// any, and one a scripted history, when the worker lists any the sweep
/// judges.
const CONTROL_EVERY: u64 = 16;

/// The first history batch of a root, whose batches are numbered from 0.
/// Every [`CONTROL_EVERY`]th batch after it is one, halfway between two
/// control batches.
const HISTORY_FIRST: u64 = 9;

/// The suspect classes of a control run the checks let through.
const MISSED: [&str; 2] = ["control passed", "control met no check"];

/// The runs after which a profile is reported as one with no pass, when
/// none of them was counted as a pass or as caught. A profile that can
/// pass in a sweep does so within far fewer runs. A profile under
/// `no_window` has at least this many runs too.
const NO_PASS_RUNS: u64 = 64;

/// The fewest `restarts` in a root's counts for its totals to report
/// planned crash windows under `no_window`, as [`status`] describes. The
/// `recovery-torn` table holds 20 cuts, and the other built-in recovery
/// tables fewer.
const EVERY_CUT: u64 = 20;

/// The most workers a sweep takes.
pub(super) const WORKERS: u64 = 1024;

/// The runs kept as examples of one uncredited rule, and the suspects of
/// one class and failure identity written to `suspects.jsonl`.
const EXAMPLES: usize = 8;

/// Per-profile limit on ordinary keys. Window rows use one limit across
/// `windows` and `windows_unplanned`. Excess names accumulate under `other`.
const KEYS: usize = 256;

/// The bytes of `sweep.json` its readers take. A sweep writes no larger
/// one, so the root keeps a checkpoint they read.
pub(super) const CHECKPOINT_BOUND: u64 = 16 << 20;

/// The supervisor measures `KEY_BOUND` in bytes of escaped JSON string contents
/// for window names, uncredited-rule keys, and suspect class-and-identity keys.
const KEY_BOUND: usize = 256;

/// The bytes `character` takes in escaped JSON string contents: a
/// control character takes six, a quote or backslash two.
fn escaped(character: char) -> usize {
    match character {
        '"' | '\\' => 2,
        character if character < ' ' => 6,
        character => character.len_utf8(),
    }
}

/// The most bytes [`escaped`] gives one character.
const WIDEST: usize = 6;

/// `text` cut where its JSON form would pass [`KEY_BOUND`] bytes.
fn key(text: &str) -> &str {
    let mut encoded = 0;
    let end = text
        .char_indices()
        .find(|&(_, character)| {
            encoded += escaped(character);
            encoded > KEY_BOUND
        })
        .map_or(text.len(), |(at, _)| at);
    &text[..end]
}

const OTHER: &str = "other";

/// The line a `--sweep` worker prints once it has accepted its manifest,
/// before it reads a root.
const READY: &str = "sweep: ready\n";

/// The longest a worker may take to print [`READY`]: the time to read its
/// manifest and hash its executable on a host busy with other workers. A
/// shorter wall limit is the wait in its place.
const READY_WAIT: Duration = Duration::from_secs(60);

/// What `campaign sweep` runs and how much of the host it uses.
pub(super) struct Plan {
    pub root: PathBuf,
    pub archive: PathBuf,
    pub campaign: Text,
    /// The batch rotation; a profile listed twice gets twice the batches.
    /// The controls of these profiles run beside it.
    pub profiles: Vec<Text>,
    pub counts: BTreeMap<Text, u64>,
    /// Worker processes, one per thread.
    pub workers: u64,
    /// How long one worker process takes roots before it is replaced.
    pub batch: Duration,
    /// The wall time after which a run's worker is killed.
    pub wall: Duration,
    pub seconds: Option<Duration>,
    /// The delegated cgroup the sweep divides into one pen per thread.
    pub cgroup: PathBuf,
    /// Each pen's memory limit in bytes.
    pub memory: u64,
    /// Each pen's process limit.
    pub processes: u64,
}

/// How many covered passes reached one event and how many times it occurred.
#[derive(Clone, Default, Serialize, Deserialize)]
struct EventReach {
    runs: u64,
    total: u64,
}

/// One profile's work so far.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Totals {
    /// Workers report passing cuts per planned window.
    #[serde(default)]
    windows: BTreeMap<String, u64>,
    /// A worker row with a `None` cut count identifies an unplanned window.
    #[serde(default)]
    windows_unplanned: BTreeSet<String>,
    /// The planned names that hold a counted row stored under a name other
    /// than its own, as [`Folds`] records them.
    #[serde(default = "Folds::unrecorded")]
    windows_folded: Folds,
    /// The next run number.
    next: u64,
    runs: u64,
    pass: u64,
    /// Whether the profile is a control.
    #[serde(default)]
    control: bool,
    /// Whether the profile is a scripted history. `None` means the
    /// checkpoint row has no `history` field, so the profile's class is
    /// unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history: Option<bool>,
    /// Whether the listing declares a failure for this history.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    failing_history: bool,
    /// The runs of a control, or of a history that expects no pass, that
    /// ended in its declared failure.
    #[serde(default)]
    caught: u64,
    /// The runs of a control, or of a history that expects no pass, that
    /// passed or whose plant met no check, and its replays that ended so
    /// where the run did not.
    #[serde(default)]
    missed: u64,
    /// The caught runs by the rule each ended in, as [`rule_name`] names
    /// it.
    #[serde(default)]
    caught_rules: BTreeMap<String, u64>,
    /// The control batches the root's sweeps have begun for a control,
    /// or the history batches for a history, and sent a root in.
    #[serde(default)]
    begun: u64,
    /// Runs that ended `unsuccessful` or `inconclusive`, by rule.
    uncredited: BTreeMap<String, u64>,
    /// The first [`EXAMPLES`] run numbers of each uncredited rule.
    #[serde(default)]
    uncredited_runs: BTreeMap<String, Vec<u64>>,
    suspects: u64,
    /// Suspects by class and failure identity. `suspects.jsonl` holds the
    /// first [`EXAMPLES`] of each key.
    #[serde(default)]
    suspect_keys: BTreeMap<String, u64>,
    /// Runs replayed in a fresh worker process.
    #[serde(default)]
    replays: u64,
    turns: u64,
    operations: u64,
    /// Witnessed actions accumulated alongside operations from the original runs.
    #[serde(default)]
    witnesses: u64,
    /// Passes whose summaries carried cluster lines, including unavailable coverage.
    #[serde(default)]
    covered: u64,
    /// An original pass with drawn coverage records every counter, including zeros.
    #[serde(default)]
    reached: BTreeMap<Cow<'static, str>, EventReach>,
    decisions: u64,
    faults_delivered: u64,
    /// Virtual microseconds the runs spent outside idle skips.
    active_us: u64,
    /// Virtual time the runs skipped while idle: its whole seconds, and
    /// in `skipped_us` the microseconds past them, below 1,000,000. One
    /// run can skip years, which a count of microseconds alone holds for
    /// fewer runs than a sweep makes.
    skipped_s: u64,
    skipped_us: u64,
    /// Microseconds the profile's runs took in their workers.
    busy_us: u64,
}

/// Each stored planned name that holds a counted row stored under a
/// name other than its own, with the digest of that row's full name, or
/// `None` once a second distinct row, an own-named one included, adds to
/// the same total. A `None` total sums distinct planned rows, so its
/// count shows the coverage of none of them. The record of a checkpoint
/// written without it is `None`; such a profile treats each name
/// [`key`] could have cut, and `other`, as one that sums distinct rows.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct Folds(Option<BTreeMap<String, Option<Digest>>>);

impl Default for Folds {
    fn default() -> Self {
        Self(Some(BTreeMap::new()))
    }
}

impl Folds {
    fn unrecorded() -> Self {
        Self(None)
    }

    /// Records the counted row `row` stored under `name`. `held` says
    /// whether `windows` held `name` before this row.
    fn note(&mut self, name: &str, row: &str, held: bool) {
        let Some(folds) = &mut self.0 else {
            return;
        };
        if name == row {
            if let Some(first) = folds.get_mut(name) {
                *first = None;
            }
            return;
        }
        let digest = Digest::of(row.as_bytes());
        if let Some(first) = folds.get_mut(name) {
            if *first != Some(digest) {
                *first = None;
            }
        } else {
            folds.insert(name.to_owned(), (!held).then_some(digest));
        }
    }

    /// Whether the total stored under `name` can sum distinct planned rows.
    fn mixed(&self, name: &str) -> bool {
        match &self.0 {
            Some(folds) => matches!(folds.get(name), Some(None)),
            None => name == OTHER || name.chars().map(escaped).sum::<usize>() > KEY_BOUND - WIDEST,
        }
    }
}

impl Totals {
    fn count_block(
        &mut self,
        profile: &str,
        run: u64,
        block: &Block,
        ending: &Ending,
        busy_us: u64,
    ) {
        self.count_windows(block.windows(profile));
        self.count(run, block.summary(), ending, busy_us);
    }

    /// The sweep carries skipped microseconds into whole seconds and saturates sums
    /// of worker-reported work. A suspect ending increments `missed` only
    /// for a [`MISSED`] class. A pass with cluster lines increments `covered`.
    /// Unavailable coverage leaves the event counts unchanged.
    fn count(&mut self, run: u64, summary: Option<&Summary>, ending: &Ending, busy_us: u64) {
        self.runs += 1;
        if let Some(summary) = summary {
            let add = |total: &mut u64, count: Option<u64>| {
                *total = total.saturating_add(count.unwrap_or(0));
            };
            add(&mut self.turns, summary.turns);
            add(&mut self.operations, summary.operations);
            add(&mut self.witnesses, summary.witnesses);
            add(&mut self.decisions, summary.decisions);
            add(&mut self.faults_delivered, summary.faults_delivered);
            let skipped_us = summary.skipped_us.unwrap_or(0);
            let active = summary.virtual_us.unwrap_or(0).saturating_sub(skipped_us);
            add(&mut self.active_us, Some(active));
            let past = self.skipped_us + skipped_us % 1_000_000;
            add(
                &mut self.skipped_s,
                Some(skipped_us / 1_000_000 + past / 1_000_000),
            );
            self.skipped_us = past % 1_000_000;
        }
        self.busy_us += busy_us;
        match ending {
            Ending::Pass => {
                self.pass += 1;
                if let Some(cluster) = summary.and_then(|s| s.cluster.as_ref()) {
                    self.covered = self.covered.saturating_add(1);
                    if let Some(drawn) = &cluster.drawn {
                        for (name, count) in COVERAGE.into_iter().zip(drawn.coverage) {
                            let event = self.reached.entry(Cow::Borrowed(name)).or_default();
                            event.runs = event.runs.saturating_add(u64::from(count > 0));
                            event.total = event.total.saturating_add(u64::from(count));
                        }
                    }
                }
            }
            Ending::Caught => self.caught += 1,
            ending if ending.missed() => self.missed += 1,
            Ending::Uncredited(rule) => self.uncredit(rule, run),
            Ending::Suspect(_) => {}
        }
    }

    /// Planned and unplanned rows share one budget of distinct shortened
    /// names. Both collections can hold the overflow key.
    fn count_windows(&mut self, rows: &[(String, Option<u64>)]) {
        if rows.is_empty() {
            return;
        }
        let names = self.windows.len()
            + self
                .windows_unplanned
                .iter()
                .filter(|name| !self.windows.contains_key(*name))
                .count();
        let mut room = KEYS.saturating_sub(names);
        for (row, count) in rows {
            let mut name = key(row);
            if !self.windows.contains_key(name) && !self.windows_unplanned.contains(name) {
                if room == 0 {
                    name = OTHER;
                } else {
                    room -= 1;
                }
            }
            if let Some(count) = count {
                let held = self.windows.contains_key(name);
                self.windows_folded.note(name, row, held);
                if let Some(sum) = self.windows.get_mut(name) {
                    *sum = sum.saturating_add(*count);
                } else {
                    self.windows.insert(name.to_owned(), *count);
                }
            } else if !self.windows_unplanned.contains(name) {
                self.windows_unplanned.insert(name.to_owned());
            }
        }
    }

    fn counts_agree(&self) -> bool {
        self.covered <= self.pass
            && self.pass <= self.runs
            && self.reached.values().all(|event| {
                event.runs <= self.covered
                    && event.runs <= event.total
                    && event.total <= event.runs.saturating_mul(u64::from(u32::MAX))
            })
    }

    fn never_reached(&self, name: &str) -> bool {
        self.reached.get(name).is_none_or(|event| event.runs == 0)
    }

    /// Recovery and live profiles are eligible. A history is eligible when
    /// its stored failure marker is false. Eligibility also requires `control` to be false.
    /// An eligible profile with required events reports its covered count even at zero.
    /// Positive coverage supplies the zero-event list. Decided workload GETs
    /// in covered passes supply the unread share.
    fn reach(&self, required: bool) -> Option<Value> {
        if self.control || (self.history == Some(true) && self.failing_history) {
            return None;
        }
        let mut entry = serde_json::Map::new();
        if self.operations > 0 {
            // Integer subtraction preserves small differences between large counts
            // and the sign when the summary reports excess witnesses.
            let unwitnessed = i128::from(self.operations) - i128::from(self.witnesses);
            entry.insert(
                "refused_actions".into(),
                (unwitnessed as f64 / self.operations as f64).into(),
            );
        }
        if required || self.covered > 0 {
            entry.insert("covered".into(), self.covered.into());
        }
        if self.covered > 0 {
            let zero = COVERAGE
                .into_iter()
                .filter(|name| self.never_reached(name))
                .collect();
            entry.insert("zero".into(), zero);
            let total = |name: &str| self.reached.get(name).map_or(0.0, |e| e.total as f64);
            let unread = total("misses") + total("refused");
            let gets = total("hits") + unread;
            if gets > 0.0 {
                entry.insert("unread".into(), (unread / gets).into());
            }
        }
        (!entry.is_empty()).then_some(Value::Object(entry))
    }

    /// Counts run `run` under the uncredited rule `rule`, cut to a key's
    /// length, or under [`OTHER`] once the profile holds [`KEYS`] rules,
    /// and keeps it as one of that key's first [`EXAMPLES`].
    fn uncredit(&mut self, rule: &str, run: u64) {
        let rule = key(rule);
        let rule = if self.uncredited.len() < KEYS || self.uncredited.contains_key(rule) {
            rule
        } else {
            OTHER
        };
        *self.uncredited.entry(rule.to_owned()).or_default() += 1;
        let runs = self.uncredited_runs.entry(rule.to_owned()).or_default();
        if runs.len() < EXAMPLES {
            runs.push(run);
        }
    }
}

/// What the closing verifications of a root's sweeps found. A sweep
/// verifies its archive before its first run and after its last, and its
/// totals are written between the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Closing {
    /// No closing verification of the root has failed.
    Kept,
    /// A sweep's closing verification failed, with its failure. The runs
    /// of that sweep may be of other bytes than the build's, so the root
    /// is refused from then on.
    Changed(String),
}

/// The sweep's persisted position and totals.
#[derive(Serialize, Deserialize)]
struct Progress {
    /// The build digest of the archive whose sweeps wrote the root. A
    /// run's root, its suspect line and its run number in the totals all
    /// belong to that build.
    build: Text,
    /// The campaign and the `--set` counts of the root's sweeps, which
    /// with the build, the profile and the run number give a run its
    /// root. A run number in the totals names a run of these.
    campaign: Text,
    counts: BTreeMap<Text, u64>,
    /// How the sweeps of the root left the archive.
    archive: Closing,
    profiles: BTreeMap<String, Totals>,
    /// Milliseconds the sweeps of this root have run.
    elapsed_ms: u64,
    /// The rule catalog of the root's worker, each rule's scope then its
    /// text; empty for a worker with no catalog form.
    #[serde(default)]
    rules: Vec<(String, String)>,
    /// The batches the sweeps of this root have begun. A sweep numbers its
    /// batches from this count, so the root's control batches and its
    /// turns through the profiles continue across sweeps, and a sweep
    /// that ends inside its first batch leaves the next batch's turn to
    /// the next sweep.
    #[serde(default)]
    batches: u64,
}

impl Progress {
    /// Begins a control batch, or a history batch, and returns the index
    /// of its profile in `listed`, the sweep's controls or its histories,
    /// which holds one: the profile with the fewest such batches begun in
    /// the root's sweeps, the earliest listed among equals. The count is
    /// the profile's own, so a sweep runs a control or a history that
    /// earlier sweeps of the root began less often first, whatever lists
    /// those sweeps had.
    fn next_listed(&mut self, listed: &[Text]) -> usize {
        let begun = |profile: &Text| {
            self.profiles
                .get(profile.as_str())
                .map_or(0, |totals| totals.begun)
        };
        let taken = (0..listed.len())
            .min_by_key(|&index| begun(&listed[index]))
            .expect("a control or history batch has a profile to run");
        self.profiles
            .entry(listed[taken].as_str().to_owned())
            .or_default()
            .begun += 1;
        taken
    }

    /// Takes back the batch [`Self::next_listed`] began for `profile`,
    /// for a batch that sent its worker no root, so the profile is the
    /// next one taken.
    fn unsent(&mut self, profile: &Text) {
        if let Some(totals) = self.profiles.get_mut(profile.as_str()) {
            totals.begun = totals.begun.saturating_sub(1);
        }
    }
}

fn held(error: std::io::Error) -> Error {
    Error::Held(error.to_string())
}

fn invalid(error: crate::archive::Invalid) -> Error {
    if error.exit(false) == crate::exit::Sim::Rejected {
        Error::Rejected(error.to_string())
    } else {
        Error::Held(error.to_string())
    }
}

/// How one run ended, as the sweep treats it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ending {
    Pass,
    /// A control's run that ended in its declared failure.
    Caught,
    /// A harness result, counted under its rule.
    Uncredited(String),
    /// A result a supervised job must reproduce, with its class.
    Suspect(String),
}

impl Ending {
    /// The ending as a replay's suspect line names it: `pass`, `caught`,
    /// the rule of an uncredited run, or the class of a suspect.
    fn text(&self) -> &str {
        match self {
            Self::Pass => "pass",
            Self::Caught => "caught",
            Self::Uncredited(text) | Self::Suspect(text) => text,
        }
    }

    /// Whether this is the ending of a control's run the checks let
    /// through: a suspect of a [`MISSED`] class.
    fn missed(&self) -> bool {
        matches!(self, Self::Suspect(class) if MISSED.contains(&class.as_str()))
    }
}

/// One run's block as the worker printed it.
#[derive(Clone, Default)]
struct Block {
    code: Option<i32>,
    /// The lines between the block's `code` and `end` lines.
    text: String,
    /// The run-form output `text` parses to; `None` for a refusal, a load
    /// error or lines the protocol's parser refuses.
    run: Option<Run>,
}

impl Block {
    fn summary(&self) -> Option<&Summary> {
        match &self.run {
            Some(Run::Summary(summary)) => Some(summary),
            _ => None,
        }
    }

    fn agrees(&self, summary: &Summary) -> bool {
        self.code
            .is_some_and(|code| crate::sim::agrees(summary, code))
    }

    /// Each printed key's first value.
    fn fields(&self) -> BTreeMap<&str, &str> {
        let mut fields = BTreeMap::new();
        for (key, value) in self.text.lines().filter_map(|line| line.split_once(": ")) {
            fields.entry(key).or_insert(value);
        }
        fields
    }

    /// What tells this run's failure from another's of its class: a
    /// violation's identity, or a panic's location without its message,
    /// whose values differ from run to run.
    fn identity(&self) -> &str {
        match &self.run {
            Some(Run::Summary(summary)) => summary
                .identity
                .as_ref()
                .map_or("", FailureIdentity::as_str),
            Some(Run::Panicked(panic)) => panic.split_once(": ").map_or(panic, |(at, _)| at),
            None => "",
        }
    }

    fn mismatch(&self, profile: &str, summary: &Summary) -> Option<&'static str> {
        if summary.profile.as_deref() != Some(profile) {
            Some("summary of another profile")
        } else if !self.agrees(summary) {
            Some("exit code disagrees with the summary")
        } else {
            None
        }
    }

    /// Sums use window rows only when the profile and exit code agree with
    /// the summary and the ledger verdict is credited or inconclusive.
    fn windows(&self, profile: &str) -> &[(String, Option<u64>)] {
        self.summary()
            .filter(|s| {
                self.mismatch(profile, s).is_none()
                    && matches!(
                        s.ledger,
                        Some(
                            crate::protocol::Ledger::Credited
                                | crate::protocol::Ledger::Inconclusive(_)
                        )
                    )
            })
            .and_then(|s| s.recovery.as_ref())
            .map_or(&[], |census| &census.windows)
    }

    /// How the run of `profile` ended. A summary earns its ending only
    /// when it names `profile`, the profile whose manifest the worker
    /// runs, and only beside the exit code the run form gives it, by the
    /// rule of [`crate::sim::agrees`].
    fn ending(&self, profile: &Text) -> Ending {
        let summary = match &self.run {
            Some(Run::Summary(summary)) => summary,
            Some(Run::Panicked(_)) => return Ending::Suspect("panic".into()),
            None if self.fields().contains_key("terminal") => {
                return Ending::Suspect("malformed summary".into());
            }
            None => return Ending::Suspect("no terminal".into()),
        };
        if let Some(reason) = self.mismatch(profile.as_str(), summary) {
            return Ending::Suspect(reason.into());
        }
        let named = |name: Option<&str>| name.unwrap_or("unnamed").to_owned();
        match summary.terminal {
            _ if summary.counts => Ending::Pass,
            Terminal::Complete { outcome, .. } => match outcome {
                Outcome::Unsuccessful => Ending::Uncredited(unsuccessful_key(&named(
                    summary.unsuccessful.as_ref().map(Text::as_str),
                ))),
                Outcome::Inconclusive => {
                    Ending::Uncredited(format!("inconclusive: {}", named(summary.stop.as_deref())))
                }
                Outcome::Pass => Ending::Uncredited(format!(
                    "inconclusive: uncredited pass, {}",
                    named(summary.cause.as_deref())
                )),
                Outcome::Violation => Ending::Suspect("violation".into()),
            },
            Terminal::Infrastructure(Infrastructure::Cap) => {
                Ending::Uncredited("inconclusive: recorder cap".into())
            }
            terminal @ Terminal::Infrastructure(_) => Ending::Suspect(terminal.to_string()),
        }
    }
}

/// A command for `program` whose environment holds exactly what
/// `environment` sets, as the archive's approved command's does: that
/// command clears its environment before it sets these variables, which
/// `Command::get_envs` does not report.
fn archived(
    program: &std::ffi::OsStr,
    environment: &[(std::ffi::OsString, Option<std::ffi::OsString>)],
) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for (key, value) in environment {
        match value {
            Some(value) => command.env(key, value),
            None => command.env_remove(key),
        };
    }
    command
}

/// Kills the worker `child` and every process in its group, which a
/// worker leads from its start, so a process the worker started that
/// holds its output ends with it. The caller has not reaped `child`, so
/// its ID still names the group.
fn end(child: &Child) {
    let _ = crate::sys::kill_group(child.id());
}

/// Reads `errors` to its end and returns its first line, cut at 4096
/// bytes.
fn first_line(mut errors: impl Read) -> String {
    let mut start = Vec::new();
    let _ = errors.by_ref().take(4096).read_to_end(&mut start);
    let _ = std::io::copy(&mut errors, &mut std::io::sink());
    let line = start.split(|byte| *byte == b'\n').next();
    String::from_utf8_lossy(line.unwrap_or_default()).into_owned()
}

/// The key of the uncredited runs that ended unsuccessful under `rule`.
fn unsuccessful_key(rule: &str) -> String {
    format!("unsuccessful: {rule}")
}

/// Returns the failure `block` holds for `ending`. A violation yields its
/// identity. An uncredited run yields its unsuccessful rule only when its
/// terminal is a complete unsuccessful one: a run that ended at the
/// recorder's cap or inconclusive can print a rule it did not end under.
/// A panic yields its claim only when `block.code` is
/// [`crate::sim::INCOMPLETE`].
fn shown<'a>(ending: &Ending, block: &'a Block) -> Option<Ended<'a>> {
    match (ending, &block.run) {
        (Ending::Suspect(class), Some(Run::Summary(summary))) if class == "violation" => summary
            .identity
            .as_ref()
            .map(|identity| Ended::Violation(identity.as_str())),
        (Ending::Uncredited(_), Some(Run::Summary(summary)))
            if matches!(
                summary.terminal,
                Terminal::Complete {
                    outcome: Outcome::Unsuccessful,
                    ..
                }
            ) =>
        {
            summary
                .unsuccessful
                .as_ref()
                .map(|rule| Ended::Unsuccessful(rule.as_str()))
        }
        (Ending::Suspect(class), Some(Run::Panicked(panic)))
            if class == "panic" && block.code == Some(crate::sim::INCOMPLETE) =>
        {
            Some(Ended::Panic(panic))
        }
        _ => None,
    }
}

/// The name of the rule a caught control run `ended` in: the text `rules`
/// holds for a violation's rule digest, or `unlisted rule` and the digest
/// when it holds none; an unsuccessful run's rule as the summary prints
/// it; and `panic:` with a panic's payload.
fn rule_name(ended: &Ended<'_>, rules: &BTreeMap<String, String>) -> String {
    match ended {
        Ended::Violation(identity) => {
            let digest = identity.get(14..78).unwrap_or(identity);
            match rules.get(digest) {
                Some(text) => text.clone(),
                None => format!("unlisted rule {digest}"),
            }
        }
        Ended::Unsuccessful(rule) => (*rule).to_owned(),
        Ended::Panic(claim) => {
            let payload = claim
                .split_once(": ")
                .map_or(*claim, |(_, payload)| payload);
            format!("panic: {payload}")
        }
    }
}

/// The ending of a run of `control` that a live run would end as `ending`:
/// caught when `ending` is the class of the control's failure and the
/// block shows that failure; a suspect when the run passed with or without
/// its witnesses, ended under [`controls::UNSEEN`], or completed
/// unsuccessful or inconclusive while the control's plant takes effect in
/// every run; and `ending` otherwise. A run that ended at the recorder's
/// cap keeps its ending under either kind of control. A summary whose exit
/// code disagrees with it shows no failure, and neither does a panic beside
/// another exit code than a panicked run's.
fn judged(control: &Control, block: &Block, ending: Ending) -> Ending {
    if shown(&ending, block).is_some_and(|ended| control.caught(&ended)) {
        return Ending::Caught;
    }
    match ending {
        Ending::Pass => Ending::Suspect("control passed".into()),
        Ending::Uncredited(rule) if rule.starts_with("inconclusive: uncredited pass") => {
            Ending::Suspect("control passed".into())
        }
        Ending::Uncredited(rule)
            if rule == unsuccessful_key(controls::UNSEEN)
                || (control.certain()
                    && block.summary().is_some_and(|summary| {
                        matches!(summary.terminal, Terminal::Complete { .. })
                    })) =>
        {
            Ending::Suspect("control met no check".into())
        }
        ending => ending,
    }
}

/// The class of a run whose worker a kill ended: the wall limit when the
/// monitor killed the pen, which is `overdue`, and the memory limit when
/// the kernel killed a process of the pen, which is `memory`.
fn killed(overdue: bool, memory: bool) -> Option<&'static str> {
    if overdue {
        Some("wall limit")
    } else if memory {
        Some("out of memory")
    } else {
        None
    }
}

/// How the run of `profile` that printed `block` ended, as the sweep
/// counts it: a control's run as [`judged`] reads it, and any other as
/// [`Block::ending`] does. A control is a profile [`controls::named`]
/// declares a failure for, or a history whose line in `listing` declares
/// one.
fn ended(listing: &Listing, profile: &Text, block: &Block) -> Ending {
    let ending = block.ending(profile);
    let control = controls::named(profile.as_str())
        .copied()
        .or_else(|| listing.profile(profile.as_str()).and_then(Control::history));
    match control {
        Some(control) => judged(&control, block, ending),
        None => ending,
    }
}

/// The suspect class of a replay of the run of `seed` the sweep read as
/// `block`, with the block the replay printed, or `None` when the replay
/// agrees and left no process. `code` is the replay's exit code, `printed`
/// its output, `died` the class of a replay without one, and `left`
/// whether the pen held a process after the replay's worker exited. A
/// replay that exited reports its code; output that does not read as one
/// block differs and is reported under that code with no lines, and
/// output that reads as a block and holds lines after it differs. A run
/// the worker refused, or whose bundle did not load, prints that line in
/// a sweep alone, so its replay agrees by its code and empty output. A
/// replay that agrees and left a process is a suspect of class `left a
/// process`.
fn compared(
    block: &Block,
    seed: u64,
    code: Option<i32>,
    printed: &str,
    died: &'static str,
    left: bool,
    listing: &Listing,
) -> Option<(&'static str, Option<Block>)> {
    let Some(code) = code else {
        return Some((died, None));
    };
    let text = format!("root: {seed}\ncode: {code}\n{printed}end: {seed}\n");
    // The block ends at the first line that closes it, so output that
    // agrees leaves nothing after it.
    let mut rest = text.as_bytes();
    // A sweep worker prints a refusal or a load error in the summary's
    // place. The recorded run prints neither on its standard output.
    let unprinted = block.text.starts_with("refused: ") || block.text.starts_with("load: ");
    match self::block(&mut rest, seed, listing) {
        Some(replayed)
            if rest.is_empty()
                && replayed.code == block.code
                && (replayed.text == block.text || unprinted && replayed.text.is_empty()) =>
        {
            left.then_some(("left a process", None))
        }
        Some(replayed) => Some(("replay differs", Some(replayed))),
        None => Some((
            "replay differs",
            Some(Block {
                code: Some(code),
                ..Block::default()
            }),
        )),
    }
}

/// What one batch runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Turn {
    /// The sweep's profile at this index.
    Profile(u64),
    /// The control [`Progress::next_listed`] takes.
    Control,
    /// The history [`Progress::next_listed`] takes.
    History,
}

/// What batch `batch` runs in a sweep of `profiles` profiles. In a sweep
/// with `controls`, batch 1 and every [`CONTROL_EVERY`]th after it are
/// control batches. In one with `histories`, batch [`HISTORY_FIRST`] and
/// every [`CONTROL_EVERY`]th after it are history batches. The other
/// batches take the profiles in turn.
fn scheduled(batch: u64, profiles: u64, controls: bool, histories: bool) -> Turn {
    let place = batch % CONTROL_EVERY;
    if controls && place == 1 {
        return Turn::Control;
    }
    if histories && place == HISTORY_FIRST {
        return Turn::History;
    }
    // The batches below `batch` at `first`, `first + CONTROL_EVERY`, ...
    let below = |first: u64| (batch + CONTROL_EVERY - 1 - first) / CONTROL_EVERY;
    let earlier = u64::from(controls) * below(1) + u64::from(histories) * below(HISTORY_FIRST);
    Turn::Profile((batch - earlier) % profiles)
}

/// Controls in first-occurrence order across the selected profiles.
///
/// # Errors
///
/// [`Error::Rejected`] when `listing` omits a scheduled control or a cluster
/// declaration for a profile with required events.
fn controls_of(profiles: &[Text], listing: &Listing) -> Result<Vec<Text>, Error> {
    let mut scheduled: Vec<Text> = Vec::new();
    for profile in profiles {
        let name = profile.as_str();
        if required::REQUIRED
            .iter()
            .any(|&(profile, ..)| profile == name)
            && listing.cluster(name).is_none()
        {
            return Err(Error::Rejected(format!(
                "the archive's worker listing lacks the cluster declaration required for {name}"
            )));
        }
        for control in controls::swept(name) {
            if listing.profile(control.profile).is_none() {
                return Err(Error::Rejected(format!(
                    "the archive's worker lists no control {} of the profile {}",
                    control.profile,
                    profile.as_str()
                )));
            }
            if !scheduled
                .iter()
                .any(|listed| listed.as_str() == control.profile)
            {
                scheduled.push(super::text(control.profile)?);
            }
        }
    }
    Ok(scheduled)
}

/// The scripted histories a sweep runs: each profile `listing` holds with
/// the history class that expects a pass or declares its failure, in the
/// listing's order. A listing that declares no failure, as one below
/// version 4 does, yields its passing histories alone.
///
/// # Errors
///
/// [`Error::Rejected`] for a history whose name is no record text, or
/// one [`component`] refuses, with the name: the name comes from the
/// worker's output, and the history's manifest is a file named for it
/// under the root.
fn histories_of(listing: &Listing) -> Result<Vec<Text>, Error> {
    listing
        .profiles
        .iter()
        .filter(|profile| profile.class == Class::History && !profile.undeclared_history())
        .map(|profile| {
            let history = super::text(&profile.name).map_err(|_| {
                Error::Rejected(format!(
                    "the listed history {:?} has a name that is no record text",
                    profile.name
                ))
            })?;
            component(&history)?;
            Ok(history)
        })
        .collect()
}

/// The bytes of one run's block. A summary is a few kilobytes.
const BLOCK_BOUND: u64 = 1 << 20;

/// Reads the block of `root` from `lines` and parses its run against
/// `listing`; `None` when the worker's output ends first, passes
/// [`BLOCK_BOUND`] bytes before the block ends, opens or closes another
/// root, holds a field before its `root` line, a second `code` line, a
/// line without `": "` or a last line without its newline. The read takes
/// at most the bound from `lines`, in one line or in many.
fn block(lines: &mut impl BufRead, root: u64, listing: &Listing) -> Option<Block> {
    let mut block = Block::default();
    let mut line = String::new();
    let (mut opened, mut coded) = (false, false);
    let mut left = BLOCK_BOUND;
    loop {
        line.clear();
        let read = Read::take(&mut *lines, left).read_line(&mut line).ok()?;
        if read == 0 {
            return None;
        }
        left -= read as u64;
        // A line reaches the parser as the worker printed it, without its
        // newline alone.
        let (key, value) = line.strip_suffix('\n')?.split_once(": ")?;
        match key {
            "root" if !opened && value == root.to_string() => opened = true,
            "end" if opened && value == root.to_string() => {
                block.run = Run::parse(&block.text, listing).ok();
                return Some(block);
            }
            "root" | "end" => return None,
            _ if !opened => return None,
            "code" if coded => return None,
            "code" => {
                coded = true;
                block.code = value.parse().ok();
            }
            _ => block.text.push_str(&line),
        }
    }
}

/// One thread's running worker.
struct Running {
    child: Child,
    /// The pen the worker runs in.
    pen: Arc<Pen>,
    /// When the monitor kills the pen: the end of the worker's ready wait,
    /// the end of its current run's wall limit, then the end of its exit
    /// wait. The time is `None` while the worker owes nothing, between its
    /// ready line and its first run and between two runs.
    killed: Option<Instant>,
    /// The monitor killed the pen at that time.
    overdue: bool,
}

/// One thread's slot, which holds its worker from the worker's start to
/// its exit.
type Slot = Mutex<Option<Running>>;

/// The frozen inputs every thread shares.
struct Frozen<'a> {
    plan: &'a Plan,
    listing: Listing,
    pins: Pins,
    /// Each profile's manifest path.
    manifests: BTreeMap<String, PathBuf>,
    /// The controls [`controls::swept`] names for the sweep's profiles.
    /// Each control batch takes the one [`Progress::next_listed`] names.
    controls: Vec<Text>,
    /// The histories [`histories_of`] names for the worker's listing.
    /// Each history batch takes the one [`Progress::next_listed`] names.
    histories: Vec<Text>,
    /// The worker's cataloged rule texts by the digest a failure identity
    /// holds; empty for a worker with no catalog form.
    rules: BTreeMap<String, String>,
    /// This executable, whose `gate` subcommand starts a replay's worker
    /// once the worker's process is in its pen.
    gate: PathBuf,
    /// The archived worker's program and the variables the approved
    /// command sets. A worker's environment is these variables and the
    /// three allocator settings [`Frozen::command`] adds.
    program: std::ffi::OsString,
    environment: Vec<(std::ffi::OsString, Option<std::ffi::OsString>)>,
    progress: Mutex<Progress>,
    /// Each thread's slot.
    running: Vec<Slot>,
    /// The last run each profile finished in a batch of the sweep's
    /// profiles or controls: its run number, root and block, which the
    /// next such batch of that profile replays. A history batch's runs
    /// are not kept here.
    last: Mutex<BTreeMap<String, (u64, u64, Block)>>,
    batches: AtomicU64,
    stop: AtomicBool,
    /// When this sweep began, and the milliseconds earlier sweeps of the
    /// root ran.
    began: Instant,
    before_ms: u64,
    /// The ready wait, which a shorter wall limit replaces.
    ready: Duration,
}

impl Frozen<'_> {
    fn request(&self, profile: &Text, run: u64) -> Request {
        Request {
            profile: profile.clone(),
            campaign: self.plan.campaign.clone(),
            run,
            attempts: ATTEMPTS,
            counts: self.plan.counts.clone(),
        }
    }

    /// The root of run `run` of `profile`: the seed of the job admission
    /// derives for it.
    fn seed(&self, profile: &Text, run: u64) -> Result<u64, Error> {
        let request = self.request(profile, run);
        Ok(
            super::freeze::freeze(&self.listing, self.pins.clone(), &request)?
                .0
                .seed(),
        )
    }

    /// A command for `program` with the archived worker's environment,
    /// which starts it as the leader of its own process group, which
    /// [`end`] kills as one, with the signal mask of the thread that
    /// starts it. The kernel kills the process when that thread exits,
    /// so a worker in a run does not outlive a sweep that a signal to its
    /// own group ended. A thread reaps each process it starts before it
    /// starts the next or returns.
    fn command(&self, program: &std::ffi::OsStr) -> Command {
        let mut command = archived(program, &self.environment);
        // A worker allocates each run's world anew. These settings keep
        // freed memory in the worker's heap, so later runs reuse its pages
        // without a page fault for each one. The mmap threshold is 32 MiB,
        // the largest a glibc before 2.35 accepts on a 64-bit host: such
        // a glibc ignores a larger one and maps each block of 128 KiB or
        // more that the heap's top cannot hold. A block of 32 MiB or more
        // is mapped on its own and unmapped when freed.
        for (key, bytes) in [
            ("MALLOC_MMAP_THRESHOLD_", 32u64 << 20),
            ("MALLOC_TRIM_THRESHOLD_", 16 << 30),
            ("MALLOC_TOP_PAD_", 256 << 20),
        ] {
            command.env(key, bytes.to_string());
        }
        crate::sys::lead(&mut command);
        command
    }

    /// Starts the worker of `profile`.
    fn worker(&self, profile: &str) -> std::io::Result<Child> {
        self.command(&self.program)
            .arg("--sweep")
            .arg(&self.manifests[profile])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
    }

    /// Counts one suspect under its class and failure identity, or under
    /// [`OTHER`] once the profile holds [`KEYS`] keys, and appends it to
    /// `suspects.jsonl` while its key has fewer than [`EXAMPLES`] lines.
    /// The append comes first, so a failed append leaves the totals as
    /// they were. Its error names the run, whose number a later sweep
    /// does not take again.
    fn suspect(
        &self,
        profile: &Text,
        run: u64,
        seed: u64,
        class: &str,
        block: Option<&Block>,
    ) -> Result<(), Error> {
        self.list(profile, run, seed, class, block, None)
    }

    /// Counts and lists a suspect as [`Frozen::suspect`] does. A suspect
    /// whose replay differs is listed with `first`, the digest the sweep
    /// read for the run and the ending it counted the run under, beside
    /// the code and summary of `block`, which the replay printed. Every
    /// line carries `key`, the `suspect_keys` entry that counts it. A
    /// line past [`LINE_BOUND`] is written with a null `summary` and
    /// `first`, so every line names its job within the reader's bound.
    fn list(
        &self,
        profile: &Text,
        run: u64,
        seed: u64,
        class: &str,
        block: Option<&Block>,
        first: Option<&(Option<Digest>, Ending)>,
    ) -> Result<(), Error> {
        let mut line = json!({
            "campaign": self.plan.campaign.as_str(),
            "profile": profile.as_str(),
            "run": run,
            "counts": self.plan.counts,
            "seed": seed,
            "build": self.pins.build.as_str(),
            "class": class,
            "code": block.and_then(|block| block.code),
            "summary": block.map(Block::fields),
        });
        if let Some((digest, ending)) = first {
            line["first"] = json!({"digest": digest, "ending": ending.text()});
        }
        let named = format!("{class}: {}", block.map_or("", Block::identity));
        let key = key(&named).to_owned();
        let mut progress = self
            .progress
            .lock()
            .expect("no thread panics holding totals");
        let totals = progress
            .profiles
            .entry(profile.as_str().to_owned())
            .or_default();
        let key = if totals.suspect_keys.len() < KEYS || totals.suspect_keys.contains_key(&key) {
            key
        } else {
            OTHER.to_owned()
        };
        if totals.suspect_keys.get(&key).copied().unwrap_or(0) < EXAMPLES as u64 {
            line["key"] = Value::from(key.as_str());
            let mut bytes = format!("{line}\n");
            if bytes.len() as u64 > LINE_BOUND {
                // The reader refuses a line past its bound, so such a line
                // is written with the suspect's job and without the run's
                // output, which holds its length.
                line["summary"] = Value::Null;
                line["first"] = Value::Null;
                bytes = format!("{line}\n");
            }
            // The totals lock orders the appends of every thread.
            crate::store::append_host(&self.plan.root.join("suspects.jsonl"), bytes.as_bytes())
                .map_err(|error| {
                    Error::Held(format!(
                        "suspects.jsonl: {error}; run {run} of {} (root {seed}) is a suspect \
                     the list does not hold",
                        profile.as_str()
                    ))
                })?;
        }
        totals.suspects += 1;
        *totals.suspect_keys.entry(key).or_default() += 1;
        Ok(())
    }

    /// Reads the ready line of the worker thread `index` started for
    /// `profile`. A worker that ends first, or that the monitor kills at
    /// the end of its ready wait, never ran a root, so its end fails the
    /// sweep and is charged to no seed.
    ///
    /// # Errors
    ///
    /// The worker's exit status when its output ends before the line, the
    /// wait it outlived, or the start of what it printed in its place.
    fn started(&self, index: usize, profile: &Text, lines: &mut impl BufRead) -> Result<(), Error> {
        let mut line = String::new();
        // The read takes the ready line's length and no more, so a worker
        // that prints without a newline costs that much memory.
        let read = Read::take(&mut *lines, READY.len() as u64).read_line(&mut line);
        if read.is_ok() && line == READY {
            return Ok(());
        }
        let taken = self.running[index]
            .lock()
            .expect("the slot lock is clean")
            .take();
        let outlived = taken.as_ref().is_some_and(|running| running.overdue);
        let ended = taken.and_then(|mut running| {
            end(&running.child);
            running.child.wait().ok()
        });
        let profile = profile.as_str();
        Err(Error::Held(match ended {
            Some(_) if line.is_empty() && outlived => format!(
                "the sweep worker of {profile} printed no ready line within {} ms",
                self.ready.min(self.plan.wall).as_millis()
            ),
            Some(status) if line.is_empty() => {
                format!("the sweep worker of {profile} ended with {status} before its ready line")
            }
            _ => format!(
                "the sweep worker of {profile} printed {:?} in place of its ready line",
                line.trim_end()
            ),
        }))
    }

    /// Sets when the monitor kills thread `index`'s pen.
    fn limit(&self, index: usize, killed: Option<Instant>) {
        if let Some(running) = self.running[index]
            .lock()
            .expect("the slot lock is clean")
            .as_mut()
        {
            running.killed = killed;
        }
    }

    /// Reaps thread `index`'s worker, whose input the thread has closed
    /// and which exits at that. The worker stays in its slot under its
    /// exit wait, the length of the ready wait, so the monitor kills one
    /// that stalls, and the slot lock is held for each poll alone. A
    /// worker that is not `alive`, whose output ended during a run, is
    /// killed at once. Returns the worker's exit status, or `None` for a
    /// slot without a worker or a failed wait, and whether the monitor
    /// marked the worker overdue, as at the end of the exit wait. A batch
    /// does not read the status, since each root its worker was sent was
    /// judged from its block; a replay reads both.
    fn retire(&self, index: usize, alive: bool) -> (Option<std::process::ExitStatus>, bool) {
        const POLL: Duration = Duration::from_millis(1);
        if let Some(running) = self.running[index]
            .lock()
            .expect("the slot lock is clean")
            .as_mut()
        {
            running.killed = Some(Instant::now() + self.ready.min(self.plan.wall));
            if !alive {
                end(&running.child);
            }
        }
        loop {
            let mut slot = self.running[index].lock().expect("the slot lock is clean");
            let Some(running) = slot.as_mut() else {
                return (None, false);
            };
            let exited = running.child.try_wait();
            if !matches!(exited, Ok(None)) {
                let overdue = running.overdue;
                *slot = None;
                return (exited.ok().flatten(), overdue);
            }
            drop(slot);
            std::thread::sleep(POLL);
        }
    }

    /// The class of the suspect a run is when thread `index`'s worker ended
    /// during it: the wall limit when the monitor killed the pen at it,
    /// the memory limit when the kernel killed a process of `pen`, else
    /// the worker's own end.
    fn death(&self, index: usize, pen: &Pen) -> Result<&'static str, Error> {
        let overdue = self.running[index]
            .lock()
            .expect("the slot lock is clean")
            .as_ref()
            .is_some_and(|running| running.overdue);
        // Every worker's end reads the count, so a kill belongs to the
        // worker whose end follows it.
        let memory = pen.out_of_memory().map_err(held)?;
        Ok(killed(overdue, memory).unwrap_or("worker ended during the run"))
    }

    /// Runs run `run` of `profile` again as one recorded run, in a fresh
    /// worker process inside `pen`, of the manifest admission derives for
    /// it. The worker has the wall limit of a run, then the exit wait, and
    /// is ended once it prints more than a block's bound. A
    /// replay that exits with another code or prints another summary than
    /// `block`, which the sweep read for the run, makes the run a suspect
    /// of class `replay differs`, listed with both. One the sweep killed
    /// at the wall limit or the exit wait makes it a suspect of class
    /// `wall limit`, one the kernel killed a process of at the memory
    /// limit one of class `out of memory`, and another whose worker ends
    /// without an exit code one of class `worker ended during the run`.
    /// A replay that SIGINT or SIGTERM ends was interrupted from outside
    /// the sweep: it is no replay of the totals and lists no suspect.
    /// The cause is read once the worker is retired. After the worker the thread kills every
    /// process left in the pen, and a replay that agrees and left one
    /// makes the run a suspect of class `left a process`.
    fn replay(
        &self,
        index: usize,
        pen: &Arc<Pen>,
        profile: &Text,
        run: u64,
        seed: u64,
        block: &Block,
    ) -> Result<(), Error> {
        let (_, manifest) = super::freeze::freeze(
            &self.listing,
            self.pins.clone(),
            &self.request(profile, run),
        )?;
        let (path, bundle) = replay_files(&self.plan.root, index as u64);
        crate::store::replace_host(&path, manifest.as_bytes()).map_err(held)?;
        // The worker creates its bundle, so none may be there.
        crate::store::remove_host(&bundle).map_err(held)?;
        // The gate starts the worker once it reads the go byte, which
        // follows the move into the pen, so the run executes inside it.
        let mut child = self
            .command(self.gate.as_os_str())
            .arg("gate")
            .arg("--")
            .arg(&self.program)
            .arg("--manifest")
            .arg(&path)
            .arg("--bundle")
            .arg(&bundle)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(held)?;
        let errors = child.stderr.take().expect("its stderr is piped");
        // The thread reads standard error to its end while the worker
        // runs, so a worker that fills the pipe keeps running.
        let errors = pen
            .admit(&child)
            .and_then(|()| std::thread::Builder::new().spawn(move || first_line(errors)));
        let errors = match errors {
            Ok(errors) => errors,
            Err(error) => {
                end(&child);
                let _ = child.wait();
                return Err(held(error));
            }
        };
        let mut go = child.stdin.take().expect("the gate's stdin is piped");
        let mut output = child.stdout.take().expect("its stdout is piped");
        *self.running[index].lock().expect("the slot lock is clean") = Some(Running {
            child,
            pen: Arc::clone(pen),
            killed: Some(Instant::now() + self.plan.wall),
            overdue: false,
        });
        let mut printed = String::new();
        // The read takes one byte past a block's bound, so a worker that
        // prints more costs the sweep that much memory and is ended here.
        let read = go
            .write_all(b"G")
            .and_then(|()| Read::take(&mut output, BLOCK_BOUND + 1).read_to_string(&mut printed));
        drop(go);
        let bounded = read.is_ok_and(|read| read as u64 <= BLOCK_BOUND);
        let (status, overdue) = self.retire(index, bounded);
        let left = pen.empty().map_err(held)?;
        // The count is read once the worker is retired, so it holds a
        // kill at any time of the replay.
        let memory = pen.out_of_memory().map_err(held)?;
        crate::store::remove_host(&bundle).map_err(held)?;
        crate::store::remove_host(&path).map_err(held)?;
        // The gate starts the worker with SIGINT and SIGTERM unblocked,
        // and the sweep ends a worker with SIGKILL alone, so either
        // signal came from outside the sweep, as when its unit is
        // stopped. The replay was interrupted and judges nothing.
        if status.is_some_and(crate::sys::interrupted) {
            return Ok(());
        }
        // Joining the reader waits for every writer to close the stderr
        // pipe.
        let exited = status.and_then(|status| status.code());
        if crate::exit::gate_code(exited) {
            let line = errors.join().unwrap_or_default();
            if crate::exit::gate_failed(exited, &line) {
                return Err(Error::Held(format!(
                    "a replay's gate failed before it started the worker: {line}"
                )));
            }
        }
        self.progress
            .lock()
            .expect("no thread panics holding totals")
            .profiles
            .entry(profile.as_str().to_owned())
            .or_default()
            .replays += 1;
        // A kill by the sweep at a limit, or by the kernel at the memory
        // limit, ended the replay whatever its worker exited with: a
        // process the worker left can hold the output open until the
        // wall limit. Output the sweep could not read whole is no
        // output to compare, whatever its worker exited with.
        let killed = killed(overdue, memory);
        let code = status
            .and_then(|status| status.code())
            .filter(|_| bounded && killed.is_none());
        let died = killed.unwrap_or("worker ended during the run");
        let Some((class, replayed)) =
            compared(block, seed, code, &printed, died, left, &self.listing)
        else {
            return Ok(());
        };
        let first = (
            block.summary().map(|summary| summary.digest),
            ended(&self.listing, profile, block),
        );
        // A control's replay that the checks let through where they did
        // not let its run through is a missed control run.
        if !first.1.missed()
            && replayed
                .as_ref()
                .is_some_and(|replayed| ended(&self.listing, profile, replayed).missed())
        {
            self.progress
                .lock()
                .expect("no thread panics holding totals")
                .profiles
                .entry(profile.as_str().to_owned())
                .or_default()
                .missed += 1;
        }
        let first = replayed.is_some().then_some(&first);
        self.list(profile, run, seed, class, replayed.as_ref(), first)
    }

    /// One thread: batches in the thread's pen, a child of `cgroup`, until
    /// the sweep stops.
    fn thread(&self, index: usize, cgroup: &Root) -> Result<(), Error> {
        let limits = Limits {
            memory: self.plan.memory,
            processes: self.plan.processes,
        };
        let pen = Arc::new(Pen::create(cgroup, index, limits).map_err(held)?);
        let swept = self.batches_in(index, &pen);
        // The thread's slot holds the only other reference to the pen. A
        // batch that ended in an error left its worker there. The slot
        // lock is released before the wait, so the monitor keeps its pass
        // over the other slots.
        let left = self.running[index]
            .lock()
            .expect("the slot lock is clean")
            .take();
        if let Some(mut running) = left {
            if running.pen.kill().is_err() {
                end(&running.child);
            }
            let _ = running.child.wait();
        }
        let removed = Arc::into_inner(pen)
            .expect("the thread holds the last reference to its pen")
            .remove()
            .map_err(held);
        swept.and(removed)
    }

    /// The profile batch `batch` runs and the turn it takes. A control or
    /// history turn begins that profile's batch in the root's totals, as
    /// [`Progress::next_listed`] counts it.
    fn next_profile(&self, batch: u64) -> (&Text, Turn) {
        let turn = scheduled(
            batch,
            self.plan.profiles.len() as u64,
            !self.controls.is_empty(),
            !self.histories.is_empty(),
        );
        let profile = match turn {
            Turn::Profile(index) => &self.plan.profiles[index as usize],
            Turn::Control | Turn::History => {
                let listed = if turn == Turn::Control {
                    &self.controls
                } else {
                    &self.histories
                };
                let index = self
                    .progress
                    .lock()
                    .expect("no thread panics holding totals")
                    .next_listed(listed);
                &listed[index]
            }
        };
        (profile, turn)
    }

    /// Thread `index`'s batches, each worker inside `pen`.
    fn batches_in(&self, index: usize, pen: &Arc<Pen>) -> Result<(), Error> {
        while !self.stop.load(Ordering::Relaxed) {
            let batch = self.batches.fetch_add(1, Ordering::Relaxed);
            let (profile, turn) = self.next_profile(batch);
            // A control or history batch that sends no root gives its
            // profile the turn back: one the sweep's end keeps from its
            // first root, and one whose replay or worker fails the sweep
            // before it.
            let unsent = || {
                if !matches!(turn, Turn::Profile(_)) {
                    self.progress
                        .lock()
                        .expect("no thread panics holding totals")
                        .unsent(profile);
                }
            };
            // A history batch replays its own last run once its worker is
            // retired, below, so it takes none from the shared map.
            let last = if turn == Turn::History {
                None
            } else {
                self.last
                    .lock()
                    .expect("the replay lock is clean")
                    .get(profile.as_str())
                    .cloned()
            };
            if let Some((run, seed, block)) = last {
                self.replay(index, pen, profile, run, seed, &block)
                    .inspect_err(|_| unsent())?;
                if self.stop.load(Ordering::Relaxed) {
                    unsent();
                    break;
                }
            }
            let mut child = self
                .worker(profile.as_str())
                .map_err(held)
                .inspect_err(|_| unsent())?;
            // The worker reads its first root after this move, so each of
            // its runs executes inside the pen.
            if let Err(error) = pen.admit(&child) {
                end(&child);
                let _ = child.wait();
                unsent();
                return Err(held(error));
            }
            let mut roots = child.stdin.take().expect("the worker's stdin is piped");
            let mut lines = BufReader::new(child.stdout.take().expect("its stdout is piped"));
            *self.running[index].lock().expect("the slot lock is clean") = Some(Running {
                child,
                pen: Arc::clone(pen),
                killed: Some(Instant::now() + self.ready.min(self.plan.wall)),
                overdue: false,
            });
            self.started(index, profile, &mut lines)
                .inspect_err(|_| unsent())?;
            self.limit(index, None);
            let mut finished = None;
            let mut history_sample = None;
            // The batch's time for fresh roots starts after the replay and
            // the ready line, so a batch whose replay outlasts that time
            // still runs a fresh root.
            let ends = Instant::now() + self.plan.batch;
            let mut alive = true;
            let mut sent = false;
            while alive && !self.stop.load(Ordering::Relaxed) && Instant::now() < ends {
                sent = true;
                let run = {
                    let mut progress = self
                        .progress
                        .lock()
                        .expect("no thread panics holding totals");
                    let totals = progress
                        .profiles
                        .entry(profile.as_str().to_owned())
                        .or_default();
                    totals.next += 1;
                    totals.next - 1
                };
                let seed = self.seed(profile, run)?;
                let began = Instant::now();
                self.limit(index, Some(began + self.plan.wall));
                let read = writeln!(roots, "{seed}")
                    .and_then(|()| roots.flush())
                    .ok()
                    .and_then(|()| block(&mut lines, seed, &self.listing));
                // The run's wall limit ends with its block, so the time
                // the thread takes to count the run kills no worker.
                self.limit(index, None);
                let Some(read) = read else {
                    let class = self.death(index, pen)?;
                    {
                        let mut progress = self
                            .progress
                            .lock()
                            .expect("no thread panics holding totals");
                        let totals = progress
                            .profiles
                            .entry(profile.as_str().to_owned())
                            .or_default();
                        totals.runs += 1;
                        totals.busy_us += began.elapsed().as_micros() as u64;
                    }
                    self.suspect(profile, run, seed, class, None)?;
                    alive = false;
                    continue;
                };
                finished = Some((run, seed));
                let ending = ended(&self.listing, profile, &read);
                let caught_by = (ending == Ending::Caught)
                    .then(|| shown(&read.ending(profile), &read))
                    .flatten()
                    .map(|ended| rule_name(&ended, &self.rules));
                {
                    let mut progress = self
                        .progress
                        .lock()
                        .expect("no thread panics holding totals");
                    let totals = progress
                        .profiles
                        .entry(profile.as_str().to_owned())
                        .or_default();
                    let busy_us = began.elapsed().as_micros() as u64;
                    totals.count_block(profile.as_str(), run, &read, &ending, busy_us);
                    if let Some(rule) = caught_by {
                        *totals.caught_rules.entry(rule).or_default() += 1;
                    }
                }
                if let Ending::Suspect(class) = &ending {
                    self.suspect(profile, run, seed, class, Some(&read))?;
                }
                if turn == Turn::History {
                    history_sample = Some((run, seed, read));
                } else {
                    self.last
                        .lock()
                        .expect("the replay lock is clean")
                        .insert(profile.as_str().to_owned(), (run, seed, read));
                }
            }
            drop(roots);
            if !sent {
                unsent();
            }
            let (_, overdue) = self.retire(index, alive);
            // The monitor marks an overdue worker before attempting the kill.
            // Processes found after that mark can still be exiting.
            let left = pen.empty().map_err(held)?;
            pen.out_of_memory().map_err(held)?;
            if left
                && alive
                && !overdue
                && let Some((run, seed)) = finished
            {
                self.suspect(profile, run, seed, "left a process", None)?;
            }
            // The sample is a run that finished and was judged, so it is
            // replayed also when a later run of the batch lost its worker.
            if !self.stop.load(Ordering::Relaxed)
                && let Some((run, seed, block)) = history_sample
            {
                self.replay(index, pen, profile, run, seed, &block)?;
            }
        }
        Ok(())
    }

    /// Replaces `sweep.json` with the totals at the sweep's end and with
    /// what its closing verification found: `changed`, the failure of a
    /// verification that failed, marks the root, which no later sweep,
    /// status or confirmation then takes. Totals that cannot be written,
    /// as when their file would pass [`CHECKPOINT_BOUND`], cannot carry
    /// the mark, so the mark is then written without them: no reader
    /// takes a marked root's totals.
    fn close(&self, changed: Option<&str>) -> Result<(), Error> {
        let Some(changed) = changed else {
            return self.flush();
        };
        self.progress
            .lock()
            .expect("no thread panics holding totals")
            .archive = Closing::Changed(changed.to_owned());
        self.flush().or_else(|_| {
            let progress = self
                .progress
                .lock()
                .expect("no thread panics holding totals");
            let marked = Progress {
                build: progress.build.clone(),
                campaign: progress.campaign.clone(),
                counts: progress.counts.clone(),
                archive: progress.archive.clone(),
                profiles: BTreeMap::new(),
                elapsed_ms: progress.elapsed_ms,
                // The catalog is the worker's text, which the bound also
                // counts, and no reader takes it from a marked root.
                rules: Vec::new(),
                batches: progress.batches,
            };
            let bytes = serde_json::to_vec(&marked).expect("progress encodes");
            crate::store::replace_host(&self.plan.root.join("sweep.json"), &bytes).map_err(held)
        })
    }

    /// Replaces `sweep.json` with the totals so far. Totals whose file
    /// would pass [`CHECKPOINT_BOUND`] are not written, which fails the
    /// sweep and leaves the root its last checkpoint.
    fn flush(&self) -> Result<(), Error> {
        let mut progress = self
            .progress
            .lock()
            .expect("no thread panics holding totals");
        progress.elapsed_ms = self.before_ms + self.began.elapsed().as_millis() as u64;
        progress.batches = self.batches.load(Ordering::Relaxed);
        let bytes = serde_json::to_vec(&*progress).expect("progress encodes");
        if bytes.len() as u64 > CHECKPOINT_BOUND {
            return Err(Error::Held(format!(
                "sweep.json would hold {} bytes, past the {CHECKPOINT_BOUND} its readers take; \
                 the root keeps its last checkpoint; preserve this root and start a new \
                 root with a new campaign name; every root also holds its automatic histories",
                bytes.len()
            )));
        }
        crate::store::replace_host(&self.plan.root.join("sweep.json"), &bytes).map_err(held)
    }

    /// Runs one thread per worker, each in a pen under `cgroup`, until a
    /// signal, `deadline` or a failure stops them, killing the pen of a
    /// worker that outlives its ready wait or its exit wait or whose run
    /// outlives the wall limit and replacing `sweep.json` each `every`. A
    /// failed replacement or signal wait stops the workers as a failed
    /// thread does, and the monitor keeps these limits until every thread
    /// has ended. A signal that is pending when the call starts, or a
    /// `deadline` that has passed then, stops the threads before any
    /// starts a worker.
    ///
    /// # Errors
    ///
    /// A thread the host does not start, the first failed signal wait or
    /// replacement of `sweep.json`, or else the first thread's failure.
    fn run(&self, cgroup: &Root, deadline: Option<Instant>, every: Duration) -> Result<(), Error> {
        const POLL: Duration = Duration::from_millis(500);
        let mut failed = None;
        let mut signalled = false;
        // A sweep that a signal has already ended, or whose deadline has
        // passed, starts no worker.
        match crate::sys::interruption(Duration::ZERO) {
            Ok(taken) => signalled = taken.is_some(),
            Err(error) => failed = Some(held(error)),
        }
        if signalled
            || failed.is_some()
            || deadline.is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.stop.store(true, Ordering::Relaxed);
        }
        std::thread::scope(|scope| {
            let mut threads = Vec::new();
            for index in 0..self.running.len() {
                let started = std::thread::Builder::new().spawn_scoped(scope, move || {
                    let ended = self.thread(index, cgroup);
                    if ended.is_err() {
                        // One failed thread ends the sweep.
                        self.stop.store(true, Ordering::Relaxed);
                    }
                    ended
                });
                match started {
                    Ok(thread) => threads.push(thread),
                    Err(error) => {
                        // The threads that started are stopped, and the
                        // monitor below runs until they end.
                        failed.get_or_insert(Error::Held(format!(
                            "a sweep thread did not start: {error}"
                        )));
                        self.stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
            let mut flushed = Instant::now();
            while threads.iter().any(|thread| !thread.is_finished()) {
                // Until the workers are told to stop, a wait that would
                // pass the deadline ends at it, so they stop there; one
                // that has passed is not waited for.
                let wait = match deadline {
                    Some(deadline) if !self.stop.load(Ordering::Relaxed) => {
                        POLL.min(deadline.saturating_duration_since(Instant::now()))
                    }
                    _ => POLL,
                };
                match crate::sys::interruption(wait) {
                    Ok(taken) => signalled |= taken.is_some(),
                    Err(error) => {
                        failed.get_or_insert(held(error));
                        // A failed wait returns at once, so the pass sleeps
                        // the wait's length.
                        std::thread::sleep(POLL);
                    }
                }
                if failed.is_none() && flushed.elapsed() >= every {
                    failed = self.flush().err();
                    flushed = Instant::now();
                }
                if signalled
                    || failed.is_some()
                    || deadline.is_some_and(|deadline| Instant::now() >= deadline)
                {
                    self.stop.store(true, Ordering::Relaxed);
                }
                for slot in &self.running {
                    if let Some(running) = slot.lock().expect("the slot lock is clean").as_mut()
                        && running.killed.is_some_and(|killed| Instant::now() > killed)
                    {
                        // Killing the pen ends the worker and every process
                        // its run started, whatever group it is in. The
                        // thread reads the end of the worker's output. It
                        // records a run as a suspect of the wall limit,
                        // fails the sweep for a worker that printed no ready
                        // line, and reaps one past its exit wait. The kill
                        // repeats on each pass until the thread clears the
                        // slot's time, so one that failed is tried again.
                        running.overdue = true;
                        if running.pen.kill().is_err() {
                            end(&running.child);
                        }
                    }
                }
            }
            for thread in threads {
                if let Err(error) = thread.join().expect("a sweep thread returns") {
                    failed.get_or_insert(error);
                }
            }
        });
        failed.map_or(Ok(()), Err)
    }
}

/// The rules the root's control runs and failing histories' runs were
/// caught by, and the cataloged rules by scope: under `caught`, each rule
/// with its caught runs and the profiles that ended in it; under
/// `scopes`, for each scope of the worker's catalog, its rules, how many
/// of them count as caught, and the texts that do not. A catch by a
/// scripted history's profile counts under `history` when the catalog
/// lists the text there, since that scope's checks judge only history
/// runs; every other catch counts in the first scope the catalog lists
/// the text under, and the text stays uncaught in a later one: the
/// single-owner world's scope and the histories' precede the oracle's.
/// The catalog's order picks that scope, which says nothing of which
/// check raised the text. `scopes` is empty for a root whose worker
/// printed no catalog.
fn rules(progress: &Progress, caught: &BTreeMap<&str, (u64, Vec<&str>)>) -> Value {
    let mut scopes: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut histories: BTreeSet<&str> = BTreeSet::new();
    for (scope, text) in &progress.rules {
        scopes.entry(scope).or_default().push(text);
        if scope == "history" {
            histories.insert(text);
        }
    }
    let first: BTreeMap<&str, &str> = uncaught::firsts(&progress.rules)
        .map(|(scope, text)| (text, scope))
        .collect();
    let mut credited: BTreeSet<(&str, &str)> = BTreeSet::new();
    for totals in progress.profiles.values() {
        for rule in totals.caught_rules.keys() {
            let Some(&listed) = first.get(rule.as_str()) else {
                continue;
            };
            let scope = if totals.history == Some(true) && histories.contains(rule.as_str()) {
                "history"
            } else {
                listed
            };
            credited.insert((rule, scope));
        }
    }
    let scopes: serde_json::Map<String, Value> = scopes
        .into_iter()
        .map(|(scope, texts)| {
            let uncaught: Vec<&str> = texts
                .iter()
                .copied()
                .filter(|text| !credited.contains(&(text, scope)))
                .collect();
            let summary = json!({
                "rules": texts.len(),
                "caught": texts.len() - uncaught.len(),
                "uncaught": uncaught,
            });
            (scope.to_owned(), summary)
        })
        .collect();
    let caught: serde_json::Map<String, Value> = caught
        .iter()
        .map(|(rule, (runs, controls))| {
            (
                (*rule).to_owned(),
                json!({"runs": runs, "controls": controls}),
            )
        })
        .collect();
    json!({"caught": caught, "scopes": scopes})
}

/// `catches` maps each rule of the profiles' `caught_rules` to its run
/// count, capped at `u64::MAX`, and the names of the profiles that list
/// the rule.
fn catches(progress: &Progress) -> BTreeMap<&str, (u64, Vec<&str>)> {
    let mut caught: BTreeMap<&str, (u64, Vec<&str>)> = BTreeMap::new();
    for (control, totals) in &progress.profiles {
        for (rule, runs) in &totals.caught_rules {
            let entry = caught.entry(rule).or_default();
            entry.0 = entry.0.saturating_add(*runs);
            entry.1.push(control);
        }
    }
    caught
}

/// Creates the sweep root `root` when it is absent and returns it locked:
/// a directory only this user can write, by the rules of
/// [`crate::store::private_dir`], under an exclusive `flock` the returned
/// handle holds, so one sweep at a time numbers the root's runs and
/// writes its files.
///
/// # Errors
///
/// [`Error::Rejected`] for a root or ancestor those rules refuse,
/// [`Error::Store`] holding [`crate::store::Error::Busy`] while another
/// sweep holds the root, or a failed creation, open or lock.
fn claim(root: &Path) -> Result<crate::store::PrivateDir, Error> {
    let directory = crate::store::private_dir(root).map_err(Error::input_path)?;
    directory.lock()?;
    Ok(directory)
}

/// Refuses a sweep or fuzz root whose creation starts at or under
/// `archive`. The caller must supply an absolute `root`. The deepest
/// ancestor of the root that resolves identifies where creation starts.
/// The host resolves a `..` component with the existing path before it: a
/// root that leaves the archive through existing directories passes, and
/// one whose `..` follows a missing component under the archive is
/// refused. Every root passes when `archive` does not resolve.
///
/// # Errors
///
/// [`Error::Rejected`] for a root whose creation starts at or under the
/// archive.
fn outside_archive(root: &Path, archive: &Path) -> Result<(), Error> {
    let Ok(archive) = crate::store::canonical_host(archive) else {
        return Ok(());
    };
    let start = root
        .ancestors()
        .find_map(|ancestor| crate::store::canonical_host(ancestor).ok());
    if start.is_some_and(|start| start.starts_with(&archive)) {
        return Err(Error::Rejected(format!(
            "the root {} lies inside the archive {}",
            root.display(),
            archive.display()
        )));
    }
    Ok(())
}

/// The progress `sweep.json` holds for the sweep root `root`, or `None`
/// for a root without the file. Every reader of a root goes through
/// here, so a root one of whose sweeps ended with a changed archive is
/// refused by all of them.
///
/// # Errors
///
/// [`Error::Rejected`] for a root marked with a failed closing
/// verification; [`Error::Unreadable`] for a `sweep.json` that cannot be
/// read and [`Error::Held`] for a parse error or inconsistent reach counts.
/// A healthy profile marked as a control also holds the root.
fn read(root: &Path) -> Result<Option<Progress>, Error> {
    let Some(bytes) = crate::store::read_host(&root.join("sweep.json"), CHECKPOINT_BOUND)? else {
        return Ok(None);
    };
    let mut progress: Progress = serde_json::from_slice(&bytes)
        .map_err(|error| Error::Held(format!("sweep.json: {error}")))?;
    if let Closing::Changed(failure) = &progress.archive {
        return Err(Error::Rejected(format!(
            "a sweep of this root ended with its archive changed ({failure}), so its runs \
             may not be the build's; sweep a new root"
        )));
    }
    for (profile, totals) in &mut progress.profiles {
        if !totals.counts_agree() {
            let name = if profile.len() > 242 {
                format!("a profile name of {} bytes", profile.len())
            } else {
                format!("{profile:?}")
            };
            return Err(Error::Held(format!(
                "sweep.json: inconsistent reach counts for {name}"
            )));
        }
        if totals.control && controls::HEALTHY.contains(&profile.as_str()) {
            return Err(Error::Held(format!(
                "sweep.json: healthy profile {profile:?} marked as a control"
            )));
        }
        totals.control |= controls::named(profile).is_some();
    }
    Ok(Some(progress))
}

/// The stored progress of the sweep root of `plan` for an archive of
/// build `build`, or `None` for a root without `sweep.json`. A root is
/// bound to one build, one campaign and one set of `--set` counts, so its
/// suspect list and its run numbers name the runs of one archive, and a
/// run number in its totals names one root. The counts are compared as
/// `--set` gave them. The plan's profiles are free to differ.
///
/// # Errors
///
/// [`Error::Rejected`] for a root whose `sweep.json` names another build,
/// another campaign or other counts, or a root a failed closing
/// verification marked, each left as it was. [`read`] supplies the checkpoint
/// I/O, parse and reach-count errors.
fn stored(plan: &Plan, build: &Text) -> Result<Option<Progress>, Error> {
    let Some(progress) = read(&plan.root)? else {
        return Ok(None);
    };
    if progress.build != *build {
        return Err(Error::Rejected(format!(
            "this root holds the sweeps of an archive of build {}; this archive is build {}, \
             which takes a new root",
            progress.build.as_str(),
            build.as_str()
        )));
    }
    if progress.campaign != plan.campaign || progress.counts != plan.counts {
        let counts = |counts: &BTreeMap<Text, u64>| json!(counts).to_string();
        return Err(Error::Rejected(format!(
            "this root holds the sweeps of campaign {} with the counts {}; campaign {} with \
             the counts {} takes a new root",
            progress.campaign.as_str(),
            counts(&progress.counts),
            plan.campaign.as_str(),
            counts(&plan.counts)
        )));
    }
    Ok(Some(progress))
}

/// The progress of the sweep root of `plan` and the path of the manifest
/// of each of its profiles, of `controls` and of `histories`, frozen
/// against `listing` and written under the root. A root without `stored` progress is bound here to the build of
/// `pins` and the plan's campaign and counts, once every profile's
/// request has frozen: a sweep the listing refuses binds no root, and
/// `sweep.json` is written before a manifest and before the sweep's
/// first worker starts.
///
/// # Errors
///
/// [`Error::Rejected`] for a profile or count `listing` refuses, for a
/// listed control that declares no failure, for a control with a
/// declared failure that `listing` holds with another class and for a
/// listed history that expects no pass and declares no failure, before
/// anything is written;
/// [`Error::Held`] for a failed write under the root.
fn bound(
    plan: &Plan,
    pins: &Pins,
    listing: &Listing,
    (controls, histories): (&[Text], &[Text]),
    stored: Option<Progress>,
) -> Result<(Progress, BTreeMap<String, PathBuf>), Error> {
    let mut frozen = BTreeMap::new();
    for profile in plan.profiles.iter().chain(controls).chain(histories) {
        if frozen.contains_key(profile.as_str()) {
            continue;
        }
        // A failing history needs a declared failure, which tells a catch
        // from a missed control.
        let listed = listing.profile(profile.as_str());
        if listed.is_some_and(|profile| profile.undeclared_history()) {
            return Err(Error::Rejected(format!(
                "the history {} expects no pass and declares no failure",
                profile.as_str()
            )));
        }
        let class = listed.map(|p| &p.class);
        let history = class == Some(&Class::History);
        let failing_history = listed.and_then(Control::history).is_some();
        // A control [`controls::named`] declares is judged by its declared
        // failure and counted as a control by its listed class, so the two
        // agree. A history is counted as a history.
        let control = class == Some(&Class::Control);
        let declared = controls::named(profile.as_str()).is_some();
        if control && !declared {
            return Err(Error::Rejected(format!(
                "the control {} declares no failure",
                profile.as_str()
            )));
        }
        if declared && listed.is_some() && !control {
            return Err(Error::Rejected(format!(
                "the archive's worker lists the control {} with another class",
                profile.as_str()
            )));
        }
        let request = Request {
            profile: profile.clone(),
            campaign: plan.campaign.clone(),
            run: 0,
            attempts: ATTEMPTS,
            counts: plan.counts.clone(),
        };
        let (_, manifest) = super::freeze::freeze(listing, pins.clone(), &request).map_err(
            |error| match error {
                Error::Rejected(reason) if history => {
                    Error::Rejected(format!("history {}: {reason}", profile.as_str()))
                }
                error => error,
            },
        )?;
        frozen.insert(
            profile.as_str().to_owned(),
            (manifest, class, failing_history),
        );
    }
    let mut progress = match stored {
        Some(progress) => progress,
        None => {
            let progress = Progress {
                build: pins.build.clone(),
                campaign: plan.campaign.clone(),
                counts: plan.counts.clone(),
                archive: Closing::Kept,
                profiles: BTreeMap::new(),
                elapsed_ms: 0,
                rules: Vec::new(),
                batches: 0,
            };
            let bytes = serde_json::to_vec(&progress).expect("progress encodes");
            crate::store::replace_host(&plan.root.join("sweep.json"), &bytes).map_err(held)?;
            progress
        }
    };
    let mut manifests = BTreeMap::new();
    for (profile, (manifest, class, failing_history)) in frozen {
        let path = plan
            .root
            .join("manifests")
            .join(format!("{profile}.manifest"));
        crate::store::replace_host(&path, manifest.as_bytes()).map_err(held)?;
        let totals = progress.profiles.entry(profile.clone()).or_default();
        (totals.control, totals.history, totals.failing_history) = (
            class == Some(&Class::Control),
            Some(class == Some(&Class::History)),
            failing_history,
        );
        manifests.insert(profile, path);
    }
    Ok((progress, manifests))
}

/// The manifest and the bundle of the replays of thread `index` under the
/// sweep root `root`.
fn replay_files(root: &Path, index: u64) -> (PathBuf, PathBuf) {
    let stem = root.join("replays").join(format!("{index:04}"));
    (
        stem.with_extension("manifest"),
        stem.with_extension("bundle"),
    )
}

/// Creates the directory of the replays' files under the sweep root
/// `root` and removes the files there, which a killed sweep's replay
/// leaves at its thread's index. The caller holds the root.
///
/// # Errors
///
/// A failed creation or removal.
fn emptied(root: &Path) -> Result<(), Error> {
    crate::store::create_dirs(&root.join("replays")).map_err(held)?;
    for index in 0..WORKERS {
        let (manifest, bundle) = replay_files(root, index);
        crate::store::remove_host(&manifest).map_err(held)?;
        crate::store::remove_host(&bundle).map_err(held)?;
    }
    Ok(())
}

/// The listing the archived worker `command` prints for `--capabilities`.
/// The worker has `wait` to print it and exit and is killed at the end of
/// that time, so a worker that hangs in its listing fails the sweep as
/// one that prints no ready line does. A SIGINT or SIGTERM that arrives
/// meanwhile stays pending for the sweep's monitor.
///
/// # Errors
///
/// [`Error::Held`] for a worker that cannot start, outlives `wait` or
/// prints more than the archive's output bound, and for a listing that
/// does not parse.
fn listed(mut command: Command, wait: Duration) -> Result<Listing, Error> {
    let output = crate::archive::output(command.arg("--capabilities"), wait)
        .map_err(|failure| Error::Held(format!("the worker's listing: {failure}")))?;
    Listing::parse(&String::from_utf8_lossy(&output))
        .map_err(|error| Error::Held(format!("the worker's listing: {error:?}")))
}

/// The rule catalog the archived worker `command` prints for `--rules`,
/// read as [`listed`] reads the listing: the worker has `wait` to print it
/// and exit with success, and is killed at the end of that time.
///
/// # Errors
///
/// [`Error::Held`] for a worker that cannot start, outlives `wait`, prints
/// more than the archive's output bound or ends with another status than
/// success, and for a catalog that does not parse.
fn cataloged(mut command: Command, wait: Duration) -> Result<Vec<Rule>, Error> {
    let output = crate::archive::output(command.arg("--rules"), wait)
        .map_err(|failure| Error::Held(format!("the worker's rule catalog: {failure}")))?;
    Rules::parse(&String::from_utf8_lossy(&output))
        .map(|catalog| catalog.rules)
        .map_err(|error| Error::Held(format!("the worker's rule catalog: {error:?}")))
}

/// Checks that the summed limits of `workers` pens of `limits`, with the
/// command's own tasks, stay below every limit of `cgroup` and its
/// ancestors. A sweep or a fuzz run runs one thread for each worker and
/// one for its monitor, and a process limit counts each thread.
///
/// # Errors
///
/// [`Error::Rejected`] naming the resource and the cgroup whose limit the
/// sum reaches, or [`Error::Held`] for a limit that cannot be read.
fn fit(cgroup: &Root, workers: u64, limits: Limits) -> Result<(), Error> {
    cgroup
        .limits_fit(
            CPU_PERIOD_US,
            limits.memory,
            // A pen's processes and the thread that feeds its worker; the
            // check adds the monitor's thread.
            limits.processes.saturating_add(1),
            u128::from(workers),
        )
        .map_err(|error| match error {
            FitError::Limit { resource, ancestor } => Error::Rejected(format!(
                "{resource} of {workers} workers exceeds the limit of {}",
                ancestor.display()
            )),
            FitError::Io(error) => held(error),
        })
}

/// Checks the campaign, the profile names and the counts of a sweep, which
/// need no archive to check. They pass the check `admit` makes of a
/// request, so `confirm` refuses no suspect for them, and each profile's
/// name is one path component. A profile's class is left to `confirm`,
/// which refuses the suspects of a control profile.
///
/// # Errors
///
/// [`Error::Rejected`] for a campaign name, profile name or count
/// [`Request::validate`] refuses for a campaign job, such as a `root`
/// count, and for a profile name [`component`] refuses.
pub(super) fn accepted(
    campaign: &Text,
    profiles: &[Text],
    counts: &BTreeMap<Text, u64>,
) -> Result<(), Error> {
    for profile in profiles {
        let request = Request {
            profile: profile.clone(),
            campaign: campaign.clone(),
            run: 0,
            attempts: ATTEMPTS,
            counts: counts.clone(),
        };
        request.validate(crate::record::Purpose::Campaign)?;
        component(profile)?;
    }
    Ok(())
}

/// Accepts `profile` as the name of a manifest file under the root. The
/// file is staged as the name with `.manifest.tmp` after it, which a
/// directory entry of 255 bytes holds for a name of at most 242.
///
/// # Errors
///
/// [`Error::Rejected`] for a name longer than 242 bytes or one that is no
/// single path component.
fn component(profile: &Text) -> Result<(), Error> {
    if profile.as_str().len() > 242 {
        return Err(Error::Rejected(format!(
            "the swept profile {:?} exceeds 242 bytes for its staged manifest name",
            profile.as_str()
        )));
    }
    let name = Path::new(profile.as_str());
    if name
        .components()
        .eq([std::path::Component::Normal(name.as_os_str())])
    {
        return Ok(());
    }
    Err(Error::Rejected(format!(
        "the swept profile {:?} is no single path component",
        profile.as_str()
    )))
}

/// Runs until a signal or the deadline and returns the root's totals,
/// which [`carries_verdict`] reads.
///
/// # Errors
///
/// A campaign name, profile name or count [`accepted`] refuses, a root
/// inside the archive according to [`outside_archive`], or a
/// cgroup root path that is relative, holds `..` or is not printable,
/// before the root is claimed; a failed signal block or wait; a root
/// [`claim`] refuses or another sweep holds; a cgroup root that is no
/// delegation with the cpu, memory and pids controllers, that another
/// sweep holds, or whose pens' summed limits reach a limit of the root or
/// an ancestor; an archive that fails verification before the first run
/// or after the last, which marks the root; a root so marked; a listing
/// or a rule catalog that outlives the ready wait or does not
/// parse; a history the listing holds whose name [`histories_of`]
/// refuses, once the root is claimed and the listing read; a profile or
/// count the listing refuses, for one of the plan's profiles, a control
/// or a listed history; a control of one of the
/// profiles that the listing lacks or holds with another class; a profile
/// with required events whose cluster declaration the listing omits; a listed
/// control that declares no failure; a listed history among the profiles
/// that expects no pass and declares no failure; a `sweep.json` that cannot be read,
/// fails to parse, holds inconsistent reach counts or names another build than the archive's, another
/// campaign or other counts than the plan's; a worker or replay that
/// cannot start or enter its pen; a worker that ends before its ready
/// line or outlives the ready wait; a sweep thread the host does not
/// start; a pen that cannot be created, read,
/// emptied or removed; a failed write or removal under the root; or a
/// root that holds no `sweep.json` when the sweep reads its totals at
/// its end, as [`final_totals`] gives it.
pub(super) fn sweep(plan: &Plan) -> Result<Value, Error> {
    accepted(&plan.campaign, &plan.profiles, &plan.counts)?;
    outside_archive(&plan.root, &plan.archive)?;
    // A cgroup root path custody refuses is refused here as an argument,
    // before the sweep writes anything.
    crate::custody::Custody::check_root(&plan.cgroup)?;
    crate::sys::block_interruptions().map_err(held)?;
    let _claimed = claim(&plan.root)?;
    // A sweep killed during an append leaves a record without its newline
    // at the end of the list. It is cut here, under the root's lock, so
    // the next append starts a line; the reader passes it over until then.
    crate::store::trim_host(&plan.root.join("suspects.jsonl")).map_err(held)?;
    // A cgroup root another sweep holds is busy, as a held sweep root is.
    let cgroup = pen::claim(&plan.cgroup)
        .map_err(held)?
        .ok_or(Error::Store(crate::store::Error::Busy))?;
    let limits = Limits {
        memory: plan.memory,
        processes: plan.processes,
    };
    fit(&cgroup, plan.workers, limits)?;
    crate::store::create_dirs(&plan.root.join("manifests")).map_err(held)?;
    emptied(&plan.root)?;
    let gate = crate::store::canonical_host(Path::new("/proc/self/exe")).map_err(held)?;
    let mut archive = crate::archive::Archive::load(&plan.archive).map_err(invalid)?;
    let pins = archive.pins();
    let approved = archive.verify().map_err(invalid)?;
    let stored = stored(plan, &pins.build)?;
    let template = approved.command();
    let wait = READY_WAIT.min(plan.wall);
    let listing = listed(approved.command(), wait)?;
    let catalog = if listing.capabilities >= RULE_CATALOG {
        cataloged(approved.command(), wait)?
    } else {
        Vec::new()
    };
    let scheduled = controls_of(&plan.profiles, &listing)?;
    let histories = histories_of(&listing)?;
    let (mut progress, manifests) = bound(plan, &pins, &listing, (&scheduled, &histories), stored)?;
    progress.rules = catalog
        .iter()
        .map(|rule| (rule.scope.name().to_owned(), rule.text.clone()))
        .collect();
    let (before_ms, batches) = (progress.elapsed_ms, progress.batches);
    let frozen = Frozen {
        plan,
        listing,
        pins,
        manifests,
        controls: scheduled,
        histories,
        rules: catalog
            .into_iter()
            .map(|rule| (Digest::of(rule.text.as_bytes()).to_string(), rule.text))
            .collect(),
        gate,
        program: template.get_program().to_owned(),
        environment: template
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(ToOwned::to_owned)))
            .collect(),
        progress: Mutex::new(progress),
        running: (0..plan.workers).map(|_| Mutex::new(None)).collect(),
        last: Mutex::new(BTreeMap::new()),
        batches: AtomicU64::new(batches),
        stop: AtomicBool::new(false),
        began: Instant::now(),
        before_ms,
        ready: READY_WAIT,
    };
    let ran = frozen.run(
        &cgroup,
        plan.seconds.map(|seconds| frozen.began + seconds),
        FLUSH,
    );
    // The closing verification comes before the last write of
    // `sweep.json`, which carries its result.
    let finished = approved
        .finish()
        .map_err(|error| format!("the archive after the sweep: {}", error.0));
    let closed = frozen.close(finished.as_ref().err().map(String::as_str));
    match (finished, closed) {
        (Err(changed), Ok(())) => return Err(Error::Held(changed)),
        (Err(changed), Err(unwritten)) => {
            return Err(Error::Held(format!(
                "{changed}; the root is left unmarked: {unwritten}"
            )));
        }
        (Ok(()), closed) => {
            ran?;
            closed?;
        }
    }
    final_totals(&plan.root)
}

/// The totals a sweep of `root` ends with.
///
/// # Errors
///
/// [`Error::Held`] for a root with no `sweep.json`, whose sweep has no
/// totals to give a verdict on, and each error of [`status`].
fn final_totals(root: &Path) -> Result<Value, Error> {
    status(root)?.ok_or_else(|| {
        Error::Held(format!(
            "the sweep of {} ended with no sweep.json to read its totals from",
            root.display()
        ))
    })
}

/// The archive build the sweep root `root` is bound to, or `None` for a
/// root no sweep has written.
///
/// # Errors
///
/// Forwards the checkpoint errors from [`read`], including [`Error::Held`]
/// for inconsistent reach counts.
pub(super) fn build(root: &Path) -> Result<Option<Text>, Error> {
    let Some(progress) = read(root)? else {
        return Ok(None);
    };
    Ok(Some(progress.build))
}

/// The summed totals and overall rates of the sweep root `root`, with each
/// profile's totals, or `None` for a root no sweep has written. Every
/// status document includes `reach`, even when empty. `no_pass`
/// lists each profile [`unpassed`] names. A `windows_missing` entry lists
/// the stored planned names with zero cuts. In a root whose counts set
/// `restarts` to [`EVERY_CUT`] or more, `no_window` maps each profile with
/// [`NO_PASS_RUNS`] runs or more to its stored planned names with zero
/// cuts and to those whose total [`Folds`] marks as one that sums distinct
/// planned rows, since such a total can sum a row at zero with a positive one.
/// `no_pass`, `windows_missing` and `no_window` appear only when populated.
///
/// An eligible profile with required events reports `covered: 0` alongside
/// any defined work share until its first covered pass. Positive coverage
/// supplies the `zero` list. At or above [`required::REQUIRED_PASSES`] covered passes,
/// `unreached` lists each non-control profile with a missing required event.
/// Status includes `unreached` only when at least one profile qualifies.
///
/// `known` lists each row of [`known::KNOWN`] with the suspects it
/// explains and appears only when the table holds a row. `new_suspects`
/// counts the root's other suspects and is always present. Both are a
/// view of the checkpoint's suspect counts.
///
/// Once every history of the root has a run counted under `pass` or
/// `caught`, `unlisted_uncaught` maps each scope to the cataloged texts
/// whose first scope it is, that no caught run ended under and that
/// [`uncaught::ALLOWED`] does not cover, and appears only when the map
/// contains at least one text. For a root without a history profile, the
/// first status satisfies the history requirement for the key. A profile
/// whose checkpoint row omits `history` may be an uncredited history, so
/// the status of its root omits `unlisted_uncaught`.
///
/// # Errors
///
/// Forwards the checkpoint errors from [`read`], including [`Error::Held`]
/// for inconsistent reach counts.
pub(super) fn status(root: &Path) -> Result<Option<Value>, Error> {
    status_with(root, known::KNOWN)
}

fn status_with(root: &Path, table: &[known::Row]) -> Result<Option<Value>, Error> {
    let Some(progress) = read(root)? else {
        return Ok(None);
    };
    let seconds = (progress.elapsed_ms as f64 / 1000.0).max(0.001);
    let selected = |class: fn(&Totals) -> bool, read: fn(&Totals) -> u64| {
        progress
            .profiles
            .values()
            .filter(|totals| class(totals))
            .map(read)
            .fold(0u64, u64::saturating_add)
    };
    let sum = |read: fn(&Totals) -> u64| selected(|_| true, read);
    let control_sum = |read: fn(&Totals) -> u64| selected(|totals| totals.control, read);
    let history_sum =
        |read: fn(&Totals) -> u64| selected(|totals| totals.history == Some(true), read);
    let uncredited = |totals: &Totals| {
        totals
            .uncredited
            .values()
            .copied()
            .fold(0u64, u64::saturating_add)
    };
    let runs = sum(|totals| totals.runs);
    let suspects = sum(|totals| totals.suspects);
    let controls = || progress.profiles.values().filter(|totals| totals.control);
    let histories = || {
        progress
            .profiles
            .values()
            .filter(|totals| totals.history == Some(true))
    };
    let missed_controls = control_sum(|totals| totals.missed);
    let missed_histories = history_sum(|totals| totals.missed);
    let no_effect = unsuccessful_key(controls::NO_EFFECT);
    let mut status = json!({
        "controls": {
            "profiles": controls().count(),
            "runs": control_sum(|totals| totals.runs),
            "caught": control_sum(|totals| totals.caught),
            "no_effect": controls()
                .map(|totals| totals.uncredited.get(&no_effect).copied().unwrap_or(0))
                .fold(0u64, u64::saturating_add),
            "missed": missed_controls,
            "other": controls()
                .map(|totals| {
                    totals
                        .uncredited
                        .iter()
                        .filter(|(rule, _)| **rule != no_effect)
                        .map(|(_, count)| *count)
                        .fold(0u64, u64::saturating_add)
                })
                .fold(0u64, u64::saturating_add),
        },
        "histories": {
            "profiles": histories().count(),
            "ran": histories().filter(|totals| totals.runs > 0).count(),
            "runs": history_sum(|totals| totals.runs),
            "pass": history_sum(|totals| totals.pass),
            "caught": history_sum(|totals| totals.caught),
            "missed": missed_histories,
            "uncredited": history_sum(uncredited),
            "suspects": history_sum(|totals| totals.suspects),
        },
        "elapsed_s": seconds,
        "runs": runs,
        "runs_per_s": runs as f64 / seconds,
        "pass": sum(|totals| totals.pass),
        "uncredited": sum(uncredited),
        "suspects": suspects,
        "replays": sum(|totals| totals.replays),
        "operations": sum(|totals| totals.operations),
        "operations_per_s": sum(|totals| totals.operations) as f64 / seconds,
        "turns": sum(|totals| totals.turns),
        "faults_delivered": sum(|totals| totals.faults_delivered),
        "skipped_virtual_years": (sum(|totals| totals.skipped_s) as f64
            + sum(|totals| totals.skipped_us) as f64 / 1e6)
            / 31_536_000.0,
        "campaign": progress.campaign,
        "counts": progress.counts,
        "profiles": progress.profiles,
    });
    let missed = sum(|totals| totals.missed);
    if missed > 0 {
        status["alarm"] = format!("{missed} control runs were missed").into();
    }
    let no_pass: Vec<&str> = progress
        .profiles
        .iter()
        .filter(|(_, totals)| unpassed(totals))
        .map(|(profile, _)| profile.as_str())
        .collect();
    if !no_pass.is_empty() {
        status["no_pass"] = json!(no_pass);
    }
    let mut reach = serde_json::Map::new();
    let mut unreached = BTreeMap::new();
    for (name, totals) in &progress.profiles {
        let row = required::REQUIRED
            .iter()
            .find(|&&(profile, ..)| profile == name);
        if let Some(entry) = totals.reach(row.is_some()) {
            reach.insert(name.clone(), entry);
        }
        if let Some(&(_, _, events, ..)) = row {
            let missing = required::unreached(totals, events);
            if !missing.is_empty() {
                unreached.insert(name, missing);
            }
        }
    }
    status["reach"] = Value::Object(reach);
    if !unreached.is_empty() {
        status["unreached"] = json!(unreached);
    }
    let every_cut = progress
        .counts
        .iter()
        .any(|(key, &count)| key.as_str() == "restarts" && count >= EVERY_CUT);
    let mut missing = BTreeMap::new();
    let mut no_window = BTreeMap::new();
    for (profile, totals) in &progress.profiles {
        let gated = every_cut && totals.runs >= NO_PASS_RUNS;
        let (mut zero, mut uncovered) = (Vec::new(), Vec::new());
        for (name, &count) in &totals.windows {
            if count == 0 {
                zero.push(name);
            }
            if gated && (count == 0 || totals.windows_folded.mixed(name)) {
                uncovered.push(name);
            }
        }
        if !uncovered.is_empty() {
            no_window.insert(profile, uncovered);
        }
        if !zero.is_empty() {
            missing.insert(profile, zero);
        }
    }
    if !missing.is_empty() {
        status["windows_missing"] = json!(missing);
    }
    if !no_window.is_empty() {
        status["no_window"] = json!(no_window);
    }
    let caught = catches(&progress);
    status["rules"] = rules(&progress, &caught);
    let credited = progress
        .profiles
        .values()
        .all(|totals| match totals.history {
            Some(true) => totals.pass > 0 || totals.caught > 0,
            Some(false) => true,
            None => false,
        });
    if credited {
        let unlisted = uncaught::unlisted(&progress.rules, |text| caught.contains_key(text));
        if !unlisted.is_empty() {
            status["unlisted_uncaught"] = json!(unlisted);
        }
    }
    let (rows, explained) = split(table, &progress.profiles);
    if !table.is_empty() {
        status["known"] = Value::Array(rows);
    }
    status["new_suspects"] = suspects.saturating_sub(explained).into();
    Ok(Some(status))
}

/// Each row of `table` as `known` lists it, with the keys of `profiles` it
/// explains under each profile it names and the sum of their counts, and
/// the sum over every row. One walk over the keys gives each key to the
/// row [`known::explains`] names, so a key counts under one row at most,
/// and a profile named twice in a row appears once. The sums saturate.
fn split(table: &[known::Row], profiles: &BTreeMap<String, Totals>) -> (Vec<Value>, u64) {
    let mut explained: Vec<(BTreeMap<&str, Vec<&str>>, u64)> = table
        .iter()
        .map(|row| {
            let keys = row.profiles.iter().map(|&profile| (profile, Vec::new()));
            (keys.collect(), 0)
        })
        .collect();
    for (profile, totals) in profiles {
        for (key, &count) in &totals.suspect_keys {
            if let Some(row) = known::explains(table, profile, key) {
                let (keys, suspects) = &mut explained[row];
                *suspects = suspects.saturating_add(count);
                keys.entry(profile).or_default().push(key);
            }
        }
    }
    let sum = explained
        .iter()
        .map(|(_, suspects)| *suspects)
        .fold(0u64, u64::saturating_add);
    let rows = table
        .iter()
        .zip(explained)
        .map(|(row, (keys, suspects))| {
            json!({
                "issue": row.issue,
                "class": row.class.name(),
                "pin": row.pin,
                "rule": row.rule,
                "suspects": suspects,
                "keys": keys,
            })
        })
        .collect();
    (rows, sum)
}

/// Whether the profile of `totals` earned nothing in the root: the
/// listing gives it a class other than control, it has [`NO_PASS_RUNS`]
/// runs or more, and none of them was counted under `pass` or `caught`.
/// A history that expects a failure is judged here by its `caught` runs.
/// The totals show that the profile earned nothing and leave the cause
/// to be found.
fn unpassed(totals: &Totals) -> bool {
    !totals.control && totals.runs >= NO_PASS_RUNS && totals.pass == 0 && totals.caught == 0
}

/// Whether the totals `status` printed for a root give its sweep the
/// exit 1 verdict: they carry `alarm`, for a missed control or history
/// run, `no_pass`, for a profile listed by [`unpassed`], `unreached`, for
/// required events with zero recorded reaching passes by profile, or
/// `no_window`, for the planned crash windows [`status`] lists for a
/// profile with at least [`NO_PASS_RUNS`] runs in a root whose counts set
/// `restarts` to at least [`EVERY_CUT`].
pub(super) fn carries_verdict(status: &Value) -> bool {
    ["alarm", "no_pass", "unreached", "no_window"]
        .into_iter()
        .any(|key| status.get(key).is_some())
}

/// One line of `suspects.jsonl`.
pub(super) struct Suspect {
    /// The job `campaign confirm` admits for the run.
    pub request: Request,
    /// The root the sweep ran, which is that job's seed.
    pub seed: u64,
    /// The build digest of the archive the sweep ran.
    pub build: Text,
}

/// The bytes of one line of `suspects.jsonl`, which holds as JSON one
/// block's fields and, for a run whose replay differs, the ending the
/// sweep counted the run under, which can carry text of a second block. A byte of a block takes at
/// most six bytes there, as a control character's escape does, so the
/// bound holds a line of two blocks. A line that would pass it is
/// written without the run's output.
const LINE_BOUND: u64 = 16 * BLOCK_BOUND;

/// The suspects of `root` after its first `from` lines, and the number of
/// lines read. The list is read a line at a time, so its length has no
/// bound and each line has [`LINE_BOUND`]. A record at the end of the
/// list without its newline is not read and not counted.
///
/// # Errors
///
/// A `suspects.jsonl` that cannot be read, a line past the bound, or a
/// line after `from` that is no suspect.
pub(super) fn suspects(root: &Path, from: usize) -> Result<(Vec<Suspect>, usize), Error> {
    let file = match crate::store::open_host(&root.join("suspects.jsonl")) {
        Err(crate::store::Unreadable::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok((Vec::new(), 0));
        }
        file => file?,
    };
    let mut file = BufReader::new(file);
    let mut suspects = Vec::new();
    let mut lines = 0;
    let mut bytes = Vec::new();
    loop {
        bytes.clear();
        let read = Read::take(&mut file, LINE_BOUND + 1)
            .read_until(b'\n', &mut bytes)
            .map_err(held)?;
        if read == 0 {
            break;
        }
        if read as u64 <= LINE_BOUND && !bytes.ends_with(b"\n") {
            // A sweep killed during an append leaves a record without its
            // newline at the end of the list. It is not a line yet.
            break;
        }
        lines += 1;
        if read as u64 > LINE_BOUND {
            return Err(Error::Held(format!(
                "suspects.jsonl line {lines} passes {LINE_BOUND} bytes"
            )));
        }
        if lines <= from {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let line = text.lines().next().unwrap_or("");
        let malformed = || Error::Held(format!("suspects.jsonl line {lines} is no suspect"));
        let suspect: Value = serde_json::from_str(line).map_err(|_| malformed())?;
        let word = |key: &str| {
            suspect[key]
                .as_str()
                .ok_or_else(malformed)
                .and_then(super::text)
        };
        let request = Request {
            profile: word("profile")?,
            campaign: word("campaign")?,
            run: suspect["run"].as_u64().ok_or_else(malformed)?,
            attempts: ATTEMPTS,
            counts: suspect["counts"]
                .as_object()
                .ok_or_else(malformed)?
                .iter()
                .map(|(key, value)| Ok((super::text(key)?, value.as_u64().ok_or_else(malformed)?)))
                .collect::<Result<_, Error>>()?,
        };
        suspects.push(Suspect {
            request,
            seed: suspect["seed"].as_u64().ok_or_else(malformed)?,
            build: word("build")?,
        });
    }
    Ok((suspects, lines))
}

#[cfg(test)]
#[path = "seeds_tests.rs"]
mod tests;
