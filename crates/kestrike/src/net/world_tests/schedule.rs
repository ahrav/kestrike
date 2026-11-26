//! Schedule reduction: fewer decisions for a failing mixed-world bundle,
//! its scenario fixed.
//!
//! The tape becomes a fed chooser's input, one draw per decision
//! ([`draws`]), zero-padded to a length fixed for the reduction, the larger
//! of [`PAD`] and its own; a fed run of it must first record the original's
//! semantic records, digest, decisions and terminal. Each pass sweeps
//! three edits: zeroing the draws from a cut bisection searches for,
//! deleting one draw at a time, and lowering each index or bounded-value
//! draw to zero, skipping fills.
//! Passes repeat while a sweep keeps an edit; then one cut of the turn
//! limit to the best run's turns, the one manifest edit, is tried. No
//! result is claimed minimal.
//!
//! A fed run records the run it makes, so each candidate is an ordinary
//! bundle, kept only when it is a complete violation with the original's
//! failure identity and enabling requirement, strictly smaller in
//! (decisions, unpadded input in shortlex order, turn limit), and replays
//! in a fresh process; later edits split the kept run's own tape. A short
//! input or an infrastructure terminal rejects a candidate. The
//! requirement is the plant's premise, the cataloged rule's conditions or
//! a history predicate bound to one profile and failure; a failure with
//! none refuses reduction. Each candidate spends a candidate, and each run
//! or fresh-process check a run, the original's check and the conversion
//! run included, checked before the work starts.

use std::collections::BTreeSet;

use crate::oracle::Obligation;
use crate::sim::choice::{Candidate, ChoiceError, Draw, draws};
use crate::sim::manifest::Manifest;
use crate::sim::trace::{Loaded, RECORD, Tag, Terminal, load};
use crate::sim::turn::End;

use super::super::frame::Kind;
use super::super::observe::Failure;
use super::bundle::{Admitted, RULE, Site, admit, run_into, scenario};
use super::histories::cohorts::MOVED_MORE;
use super::histories::incidents::LOST_SOURCE_RELEASED;
use super::replay::{
    Condition, Edit, FailureIdentity, Identity, Refused, Stop, Verify, conditions,
    first_difference, premise, recorded, violated,
};
use super::{Plan, Plant, WorldKind};

/// The work one reduction may do, or the work it spent; the worker admits
/// only positive limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Budget {
    pub(crate) candidates: u64,
    /// Sweeps of the three input edits.
    pub(crate) passes: u64,
    /// In-process runs and fresh-process checks.
    pub(crate) runs: u64,
}

impl Budget {
    /// The runs cover the original's fresh-process check, the conversion
    /// run, and one run and one check for each candidate.
    pub(crate) const DEFAULT: Self = Self {
        candidates: 512,
        passes: 8,
        runs: 1026,
    };
}

/// The least length every candidate's input is padded to.
pub(crate) const PAD: usize = 65_536;

/// One edit, naming draws of the best run so far by index, as
/// [`Attempt`]'s text names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    ZeroFrom(usize),
    Delete(usize),
    Lower(usize),
    Turns(u64),
}

/// What became of a candidate, as [`Attempt`]'s text names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Kept,
    Refused,
    Short,
    Infrastructure,
    OtherOutcome,
    Unenabled,
    NotSmaller,
    Unreproduced,
    Unbudgeted,
    Unverified,
}

/// One candidate and what became of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub(crate) change: Change,
    pub(crate) verdict: Verdict,
}

impl std::fmt::Display for Attempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let verdict = match self.verdict {
            Verdict::Kept => "kept",
            Verdict::Refused => "rejected, the manifest refuses it:",
            Verdict::Short => "rejected, its input ran short:",
            Verdict::Infrastructure => "rejected, its run ended in infrastructure:",
            Verdict::OtherOutcome => "rejected, another outcome:",
            Verdict::Unenabled => "rejected, an enabling requirement is gone:",
            Verdict::NotSmaller => "rejected, it is no smaller:",
            Verdict::Unreproduced => "rejected, it does not replay in a fresh process:",
            Verdict::Unbudgeted => "rejected, no run is left for its fresh-process check:",
            Verdict::Unverified => "unverified, its fresh-process check failed:",
        };
        match self.change {
            Change::ZeroFrom(at) => write!(f, "{verdict} zero the draws from {at}"),
            Change::Delete(at) => write!(f, "{verdict} delete draw {at}"),
            Change::Lower(at) => write!(f, "{verdict} lower draw {at} to zero"),
            Change::Turns(turns) => write!(f, "{verdict} cut the schedule to {turns} turns"),
        }
    }
}

/// A finished reduction: the best verified regression with its manifest
/// and scenario text, the original's and the regression's counts as
/// [`Best::counts`] names them, every candidate in order, the requirement's
/// names, the budget, what it spent and why it stopped. With no candidate
/// kept the regression is the original's bytes.
#[derive(Debug)]
pub(crate) struct Reduced {
    pub(crate) bundle: Vec<u8>,
    pub(crate) manifest: Manifest,
    pub(crate) scenario: String,
    pub(crate) original: String,
    pub(crate) best: String,
    pub(crate) attempts: Vec<Attempt>,
    pub(crate) requirement: Vec<String>,
    pub(crate) budget: Budget,
    pub(crate) spent: Budget,
    pub(crate) stop: Stop,
}

impl Reduced {
    /// steps.txt and the summary line, or the reason the fresh-process check
    /// failed for an interrupted reduction. steps.txt names the original's
    /// counts, the budget, the requirement, each candidate's verdict, a
    /// checked one with its step-N files (step-1 is the original's), what
    /// was spent, the regression's counts and the stop; the summary line
    /// names the regression's counts, the keeps and the stop.
    pub(crate) fn report(&self) -> (String, Result<String, String>) {
        let spent = |b: Budget| {
            format!(
                "{} candidates, {} passes, {} runs",
                b.candidates, b.passes, b.runs
            )
        };
        let (stopped, line) = match &self.stop {
            Stop::Exhausted => ("exhausted".to_owned(), Ok("exhausted")),
            Stop::Bounded => ("bounded".to_owned(), Ok("bounded")),
            Stop::Interrupted(reason) => (
                format!("interrupted, the fresh-process check failed: {reason:?}"),
                Err(reason.clone()),
            ),
        };
        let requirement = self.requirement.join(", ");
        let (original, budget) = (&self.original, spent(self.budget));
        let mut steps =
            format!("original: {original}\nbudget: {budget}\nrequirement: {requirement}\n");
        let mut checked = 1;
        for attempt in &self.attempts {
            let fresh = matches!(
                attempt.verdict,
                Verdict::Kept | Verdict::Unreproduced | Verdict::Unverified
            );
            checked += usize::from(fresh);
            steps.push_str(&attempt.to_string());
            if fresh {
                steps.push_str(&format!(" (step-{checked})"));
            }
            steps.push('\n');
        }
        let (best, used) = (&self.best, spent(self.spent));
        let kept = self.attempts.iter().filter(|a| a.verdict == Verdict::Kept);
        let kept = kept.count();
        steps.push_str(&format!(
            "spent: {used}\nbest: {best}\nstopped: {stopped}\n"
        ));
        (
            steps,
            line.map(|stop| format!("reduce-schedule: reduced to {best}, {kept} kept, {stop}\n")),
        )
    }
}

/// What a reduction keeps beside the failure identity.
#[derive(Clone, Copy)]
enum Requirement {
    Premise(Plant),
    Conditions(&'static [Condition]),
    History(&'static Enabling, &'static [super::Step]),
}

impl Requirement {
    /// The requirement of a run of `plan` under profile `profile` that
    /// fails as `identity`: the plant's premise, else the cataloged rule's
    /// conditions, else the history predicate bound to the profile and the
    /// failure; `None` for a planted panic or a failure with none.
    fn of(plan: &Plan, profile: &str, identity: &FailureIdentity) -> Option<Self> {
        match plan.plant {
            Plant::Panic | Plant::DebugAssertion => None,
            Plant::None => conditions(identity)
                .map(Self::Conditions)
                .or_else(|| Some(Self::History(Enabling::of(profile, identity)?, plan.script))),
            plant => Some(Self::Premise(plant)),
        }
    }

    fn holds(self, bytes: &[u8], loaded: &Loaded) -> bool {
        match self {
            Self::Premise(plant) => premise(plant, loaded) == Some(true),
            Self::Conditions(found) => found.iter().all(|condition| (condition.holds)(loaded)),
            Self::History(enabling, script) => enabling.holds(bytes, script),
        }
    }

    fn names(self) -> Vec<String> {
        match self {
            Self::Premise(plant) => vec![format!("premise-{plant:?}")],
            Self::Conditions(found) => found.iter().map(|c| c.name.to_owned()).collect(),
            Self::History(enabling, _) => vec![enabling.name.to_owned()],
        }
    }
}

/// An enabling predicate of a history's failure, bound to the profile and
/// the failure it names: the script steps, by name in the profile's own
/// script, whose SCRIPT turns complete before the first violation, the
/// step `raised` whose turn, the last before it, returned 0 as a failing
/// check does, and when `lost_middle` holds, a link rule capture before it
/// that dropped PUT DATA fragment 1 on its way to the owner.
pub(super) struct Enabling {
    pub(super) name: &'static str,
    profile: &'static str,
    failure: (Obligation, &'static str),
    steps: &'static [&'static str],
    raised: &'static str,
    lost_middle: bool,
}

/// The history predicates, each bound to one profile and failure.
pub(super) const HISTORICAL: [Enabling; 3] = [
    Enabling {
        name: "i3-lost-middle-after-single-upload",
        profile: "i3-put-hole",
        failure: (Obligation::Custody, LOST_SOURCE_RELEASED),
        steps: &["arm-drop", "put-begin", "put-prepare", "put-supply"],
        raised: "lost-held",
        lost_middle: true,
    },
    Enabling {
        name: "s3-injected-then-counted",
        profile: "s3-d-19",
        failure: (Obligation::Contain, MOVED_MORE),
        steps: &["setup", "effect"],
        raised: "check",
        lost_middle: false,
    },
    Enabling {
        name: "s3-mutated-premise",
        profile: "s3-d-19-mutated",
        failure: (Obligation::Contain, MOVED_MORE),
        steps: &["setup", "effect"],
        raised: "check-mutated",
        lost_middle: false,
    },
];

impl Enabling {
    fn of(profile: &str, identity: &FailureIdentity) -> Option<&'static Self> {
        let mut found = HISTORICAL
            .iter()
            .map(|enabling| (enabling, enabling.failure));
        let found = found.find(|&(enabling, (obligation, rule))| {
            let failure = Failure::Violation(obligation, rule);
            enabling.profile == profile
                && FailureIdentity::of_failure(&failure, Site::Run) == *identity
        });
        found.map(|(enabling, _)| enabling)
    }

    /// Whether the records of `bytes` before its first violation hold the
    /// predicate, its steps found by name in `script`; a script without one
    /// of them never holds it. A step counts once its SCRIPT turn completes
    /// with a mark count: a step whose guard fails returns 0, and one that
    /// waits returns STAY. A run's failure event follows the Turn record of
    /// the turn that raised it.
    pub(super) fn holds(&self, bytes: &[u8], script: &[super::Step]) -> bool {
        let named = |name: &str| script.iter().position(|step| step.name == name);
        let steps = self.steps.iter().map(|name| named(name));
        let (Some(raised), Some(steps)) = (named(self.raised), steps.collect::<Option<Vec<_>>>())
        else {
            return false;
        };
        let (records, _) = bytes.as_chunks::<RECORD>();
        let (mut completed, mut lost, mut last) = (BTreeSet::new(), false, None);
        for record in records
            .iter()
            .take_while(|record| record[0] != Tag::Violation as u8)
        {
            // A turn's payload holds its event at 8..24 and its outcome at
            // 24..32, after the record's four header bytes.
            let payload = &record[4..];
            if record[0] == Tag::Turn as u8 {
                let event = Candidate(payload[8..24].try_into().expect("sixteen bytes"));
                let outcome = u64::from_le_bytes(payload[24..32].try_into().expect("eight bytes"));
                let step = super::completed_step(&event, outcome);
                last = step.filter(|_| outcome == 0);
                completed.extend(step.filter(|_| outcome != 0));
            }
            lost |= record[..2] == [Tag::Event as u8, RULE] && lost_middle(payload);
        }
        let done = steps.iter().all(|&step| completed.contains(&(step as u32)));
        done && last == Some(raised as u32) && (lost || !self.lost_middle)
    }
}

/// Whether a RULE event's payload, its net then the code
/// [`capture_code`](super::bundle::capture_code) lays out, names PUT DATA
/// fragment 1 that a link rule (drop code 2) dropped toward the owner's
/// end of the link, end 1.
fn lost_middle(payload: &[u8]) -> bool {
    let code = &payload[1..];
    let index = u32::from_le_bytes(code[14..18].try_into().expect("four bytes"));
    (code[4], code[13], index, code[18]) == (1, Kind::PutData as u8, 1, 2)
}

/// Runs an admitted manifest from an input into a bundle: the bundle, and
/// whether the input ran short.
pub(super) type Run<'r> = dyn FnMut(Admitted<'_>, Vec<u8>) -> (Vec<u8>, bool) + 'r;

/// A fed run of `admitted` from `input`, keeping the records written
/// before a panic, which leaves the bundle without its terminal.
fn fed(admitted: Admitted<'_>, input: Vec<u8>) -> (Vec<u8>, bool) {
    let chooser = admitted.fed(input);
    let mut sink = Vec::new();
    let end = crate::sim::unwind::caught(|| run_into(admitted, &mut sink, chooser).1);
    let short =
        matches!(end, Ok(End::Defect(defect)) if defect.choice() == Some(ChoiceError::Short));
    (sink, short)
}

/// A run: its bundle, manifest, draws, decisions and the turns its
/// terminal records. The search's best has passed its fresh-process check;
/// a candidate awaits it.
struct Best {
    bundle: Vec<u8>,
    manifest: Manifest,
    draws: Vec<Draw>,
    decisions: u64,
    turns: u64,
}

impl Best {
    /// `None` for a tape that does not split into draws.
    fn of(bundle: Vec<u8>, loaded: &Loaded, manifest: Manifest) -> Option<Self> {
        Some(Self {
            bundle,
            manifest,
            draws: draws(&loaded.tape)?,
            decisions: loaded.decisions,
            turns: loaded.work.turns,
        })
    }

    /// The bytes of the draws with those in `range` replaced by `with`.
    fn splice(&self, range: std::ops::Range<usize>, with: &[u8]) -> Vec<u8> {
        let (before, after) = (&self.draws[..range.start], &self.draws[range.end..]);
        let input = before.iter().flat_map(|draw| &draw.bytes).chain(with);
        input
            .chain(after.iter().flat_map(|draw| &draw.bytes))
            .copied()
            .collect()
    }

    fn whole(&self) -> Vec<u8> {
        self.splice(0..0, &[])
    }

    /// The draws before the zero tail: the index after the last draw that
    /// holds a nonzero byte.
    fn nonzero(&self) -> usize {
        let last = self
            .draws
            .iter()
            .rposition(|draw| draw.bytes.iter().any(|&byte| byte != 0));
        last.map_or(0, |at| at + 1)
    }

    /// The order a keep must decrease: decisions, the unpadded input in
    /// shortlex order, then the turn limit.
    fn measure(&self) -> (u64, usize, Vec<u8>, u64) {
        let input = self.whole();
        let turns = self.manifest.count("turns");
        (self.decisions, input.len(), input, turns)
    }

    /// Its records, decisions, turns run of the turn limit and input bytes.
    fn counts(&self) -> String {
        let (decisions, input, _, limit) = self.measure();
        let (records, turns) = (self.bundle.len() / RECORD, self.turns);
        format!(
            "{records} records, {decisions} decisions, {turns} of {limit} turns, {input} input bytes"
        )
    }
}

struct Search<'a, 'v, 'r> {
    target: FailureIdentity,
    requirement: Requirement,
    pad: usize,
    budget: Budget,
    spent: Budget,
    attempts: Vec<Attempt>,
    best: Best,
    verify: &'a mut Verify<'v>,
    run: &'a mut Run<'r>,
}

impl Search<'_, '_, '_> {
    fn padded(&self, mut input: Vec<u8>) -> Vec<u8> {
        debug_assert!(input.len() <= self.pad, "an edit never grows the input");
        input.resize(self.pad, 0);
        input
    }

    fn log(&mut self, change: Change, verdict: Verdict) -> bool {
        self.attempts.push(Attempt { change, verdict });
        verdict == Verdict::Kept
    }

    /// Tries `input` under `manifest` as `change` and says whether it was
    /// kept; `Err` when the budget cannot start it or its fresh-process
    /// check, or that check fails. An edit that leaves the padded input and
    /// the manifest as they are is no candidate.
    fn attempt(
        &mut self,
        change: Change,
        input: Vec<u8>,
        manifest: Manifest,
    ) -> Result<bool, Stop> {
        let input = self.padded(input);
        if manifest == self.best.manifest && input == self.padded(self.best.whole()) {
            return Ok(false);
        }
        if self.spent.candidates >= self.budget.candidates || self.spent.runs >= self.budget.runs {
            return Err(Stop::Bounded);
        }
        self.spent.candidates += 1;
        let ran = match admit(&manifest) {
            Err(_) => Err(Verdict::Refused),
            Ok(admitted) => {
                self.spent.runs += 1;
                let (bytes, short) = (self.run)(admitted, input);
                self.judged(bytes, short, manifest.clone())
            }
        };
        let candidate = match ran {
            Ok(candidate) => candidate,
            Err(verdict) => return Ok(self.log(change, verdict)),
        };
        if self.spent.runs >= self.budget.runs {
            self.log(change, Verdict::Unbudgeted);
            return Err(Stop::Bounded);
        }
        self.spent.runs += 1;
        match (self.verify)(&candidate.bundle, &Identity::Violation(self.target)) {
            Err(reason) => {
                self.log(change, Verdict::Unverified);
                Err(Stop::Interrupted(reason))
            }
            Ok(false) => Ok(self.log(change, Verdict::Unreproduced)),
            Ok(true) => {
                self.best = candidate;
                Ok(self.log(change, Verdict::Kept))
            }
        }
    }

    /// The candidate a run recorded, or why it is rejected before its
    /// fresh-process check.
    fn judged(&self, bytes: Vec<u8>, short: bool, manifest: Manifest) -> Result<Best, Verdict> {
        if short {
            return Err(Verdict::Short);
        }
        let loaded = load(&bytes, u64::MAX).map_err(|_| Verdict::OtherOutcome)?;
        if matches!(loaded.terminal, Terminal::Infrastructure(_)) {
            return Err(Verdict::Infrastructure);
        }
        if violated(&loaded) != Some(self.target) {
            return Err(Verdict::OtherOutcome);
        }
        if !self.requirement.holds(&bytes, &loaded) {
            return Err(Verdict::Unenabled);
        }
        let candidate = Best::of(bytes, &loaded, manifest).ok_or(Verdict::OtherOutcome)?;
        if candidate.measure() >= self.best.measure() {
            return Err(Verdict::NotSmaller);
        }
        Ok(candidate)
    }

    /// Sweeps the passes, then tries the turn-limit cut, and says why the
    /// search stopped: exhausted once a sweep keeps nothing and the cut
    /// step completed, bounded when a budget ended it first. A pass counts
    /// once its sweep completes.
    fn search(&mut self) -> Stop {
        let converged = loop {
            if self.spent.passes >= self.budget.passes {
                break false;
            }
            let kept = self.sweep();
            self.spent.passes += u64::from(kept.is_ok());
            match kept {
                Err(stop) => return stop,
                Ok(false) => break true,
                Ok(true) => {}
            }
        };
        match self.cut() {
            Err(stop) => stop,
            Ok(()) if converged => Stop::Exhausted,
            Ok(()) => Stop::Bounded,
        }
    }

    /// One pass, saying whether it kept a candidate: zero a suffix by
    /// bisection over the draws before the zero tail, so every probe changes
    /// the input, delete the draws before the zero tail one at a time from
    /// the first, then lower each index or bounded-value draw. An edit
    /// inside the zero tail leaves the padded input as it is.
    fn sweep(&mut self) -> Result<bool, Stop> {
        let (manifest, mut kept) = (self.best.manifest.clone(), false);
        let (mut low, mut high) = (0, self.best.nonzero());
        while low < high {
            let middle = low + (high - low) / 2;
            let input = self.best.splice(middle..self.best.draws.len(), &[]);
            if self.attempt(Change::ZeroFrom(middle), input, manifest.clone())? {
                (kept, high) = (true, middle.min(self.best.nonzero()));
            } else {
                low = middle + 1;
            }
        }
        let mut at = 0;
        while at < self.best.nonzero() {
            let input = self.best.splice(at..at + 1, &[]);
            match self.attempt(Change::Delete(at), input, manifest.clone())? {
                true => kept = true,
                false => at += 1,
            }
        }
        for at in 0.. {
            let Some(draw) = self.best.draws.get(at) else {
                break;
            };
            if !draw.fill && draw.bytes.iter().any(|&byte| byte != 0) {
                let input = self.best.splice(at..at + 1, &vec![0; draw.bytes.len()]);
                kept |= self.attempt(Change::Lower(at), input, manifest.clone())?;
            }
        }
        Ok(kept)
    }

    /// Cuts the turn limit to the best run's turns, when that is below it.
    fn cut(&mut self) -> Result<(), Stop> {
        let turns = self.best.turns;
        if turns == 0 || turns >= self.best.manifest.count("turns") {
            return Ok(());
        }
        let manifest = self.best.manifest.clone().with("turns", turns);
        let input = self.best.whole();
        self.attempt(Change::Turns(turns), input, manifest)
            .map(drop)
    }
}

/// Reduces the schedule of `original` within `budget`. `verify` replays a
/// bundle in a fresh process and says whether it reproduced the identity
/// it is given; it runs for the original and for every candidate that
/// would be kept. A `verify` that fails after the original's check stops
/// the reduction with the best regression so far, marked interrupted.
///
/// # Errors
///
/// `Input` when the bundle does not load, name a run or split into
/// draws, `Recovery` when its recovery record does not parse,
/// `Unreducible` when it runs another world than the mixed one, is no
/// complete violation with a failure identity, names no enabling
/// requirement or does not hold it, has no run for its fresh-process
/// check, does not replay in a fresh process, or its converted input does
/// not record its run again, `Infrastructure` when `verify` fails for the
/// original.
pub(crate) fn reduce(
    original: &[u8],
    verify: &mut Verify<'_>,
    budget: Budget,
) -> Result<Reduced, Refused> {
    reduce_with(original, verify, &mut fed, budget)
}

/// [`reduce`] with every run, the conversion check's included, made by
/// `run`.
pub(super) fn reduce_with(
    original: &[u8],
    verify: &mut Verify<'_>,
    run: &mut Run<'_>,
    budget: Budget,
) -> Result<Reduced, Refused> {
    let (loaded, manifest) = recorded(original)?;
    let unreducible = |reason: &str| Refused::Unreducible(reason.into());
    let refused = |refusal| Refused::Input(format!("{refusal:?}"));
    let (profile, plan, _) = scenario(&manifest).map_err(refused)?;
    if !matches!(plan.world, WorldKind::Mixed) {
        return Err(unreducible(
            "only a mixed-world bundle reduces its schedule",
        ));
    }
    let target = violated(&loaded).ok_or_else(|| {
        unreducible("the bundle records no complete violation with a failure identity")
    })?;
    let requirement = Requirement::of(&plan, &manifest.profile, &target)
        .ok_or_else(|| unreducible("the failure names no checkable enabling requirement"))?;
    if !requirement.holds(original, &loaded) {
        return Err(unreducible(
            "the bundle does not witness its enabling requirement",
        ));
    }
    let best = Best::of(original.to_vec(), &loaded, manifest.clone())
        .ok_or_else(|| Refused::Input("the tape does not split into decisions".into()))?;
    if budget.runs == 0 {
        return Err(unreducible("no run is left for its fresh-process check"));
    }
    if !verify(original, &Identity::Violation(target)).map_err(Refused::Infrastructure)? {
        return Err(unreducible("the bundle does not replay in a fresh process"));
    }
    let (pad, counts) = (PAD.max(best.whole().len()), best.counts());
    let mut search = Search {
        target,
        requirement,
        pad,
        budget,
        spent: Budget {
            candidates: 0,
            passes: 0,
            runs: 1,
        },
        attempts: Vec::new(),
        best,
        verify,
        run,
    };
    let stop = if search.spent.runs >= budget.runs {
        Stop::Bounded
    } else {
        search.spent.runs += 1;
        let admitted = admit(&manifest).map_err(refused)?;
        let input = search.padded(search.best.whole());
        let (again, short) = (search.run)(admitted, input);
        let same = load(&again, u64::MAX).is_ok_and(|ran| {
            (ran.digest, ran.decisions, ran.terminal)
                == (loaded.digest, loaded.decisions, loaded.terminal)
        });
        if short || !same || first_difference(original, &again).is_some() {
            return Err(unreducible(
                "its tape as an input does not record its run again",
            ));
        }
        search.search()
    };
    Ok(Reduced {
        original: counts,
        best: search.best.counts(),
        bundle: search.best.bundle,
        manifest: search.best.manifest,
        scenario: Edit::of(&profile, &plan).describe(),
        attempts: search.attempts,
        requirement: requirement.names(),
        budget,
        spent: search.spent,
        stop,
    })
}

#[cfg(test)]
pub(crate) mod tests;
