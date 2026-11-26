//! Strict replay of a mixed-world bundle and the reducer that minimizes a
//! failing one.
//!
//! A replay reruns the bundle's recorded scenario with every decision read
//! back from its tape: the chooser checks each draw's identity, candidate
//! set and range before the action that draws it runs, and refuses input
//! left after the last decision. The replay records a fresh bundle; it is
//! `Reproduced` only when that bundle's digest, decision count and terminal
//! equal the original's, and otherwise reports the first semantic record
//! where the two differ. A tape that ends before or inside a decision the
//! run draws is rejected as exhausted, so a missing last decision is
//! rejected while a missing earlier one diverges at the next draw, unless
//! the shifted tape still checks and then ends short.
//!
//! A reduction starts from a mixed-world bundle whose run is a violation,
//! planted or with a cataloged rule, or a panic, that replays in a fresh
//! process; a bundle of any other world refuses reduction. It edits
//! the scenario one step at a time: each round tries deleting a whole
//! declared action kind, then clearing a whole plan flag (a fault,
//! transmit, scheduling or read-target flag), then cutting the turn
//! schedule to the last kept run's executed turns, including the turn a
//! panic interrupted, and only then lowers one budget or halves one link
//! capacity. It keeps an edit only when the edited run fails with the
//! original's identity and its bundle replays that failure in a fresh
//! process: for a complete violation the failure identity, with the
//! plant's premise or the rule's enabling conditions witnessed; for a run
//! that panicked the panic's location and payload ([`unwind`]), its bundle
//! stopping where the panic cut its stream. A run that panics with another
//! identity is unsuccessful, never a kept failure.
//! An edit that removes every prerequisite of a kind it keeps, the budget
//! a kept kind spends, or the deferrals a kept supply waits on, is rejected
//! before it runs.
//!
//! A reduction tries at most [`MAX_STEPS`] steps. At that bound, or when a
//! fresh-process check of a candidate fails, it returns the best regression
//! kept so far, marked bounded or interrupted, which may admit further
//! edits.

use crate::sim::action::{ActionKind, Profile};
use crate::sim::choice::ChoiceError;
use crate::sim::manifest::Manifest;
use crate::sim::trace::{
    Event, Field, Infrastructure, LoadError, Loaded, Outcome, PAYLOAD, RECORD, Terminal,
    is_semantic, load,
};
use crate::sim::turn::End;
use crate::sim::unwind;

use super::super::observe::{Failure, UNCHECKED_RECORD, UNREGISTERED_BYTES};
use super::super::upload::UploadOutcome;
use super::bundle::{
    ACT, Admitted, FRAGMENTS, IDENTITY, PutRecord, SUPPLIED, Site, Unadmitted, UploadState, admit,
    identity_event, run_into, scenario, traced,
};
use super::{Plan, Plant, WorldKind};
use crate::oracle::Obligation;

/// A plan flag a reducer may clear: its name and its field.
type FlagField = (&'static str, fn(&mut Plan) -> &mut bool);

/// A plan budget a reducer may lower: its name and its field.
type CountField = (&'static str, fn(&mut Plan) -> &mut u32);

/// The plan flags a reducer may clear, in encoding order.
const FLAG_FIELDS: [FlagField; 13] = [
    ("link_faults", |plan| &mut plan.link_faults),
    ("lose_upload", |plan| &mut plan.lose_upload),
    ("withheld_tx", |plan| &mut plan.withheld_tx),
    ("drop_result", |plan| &mut plan.drop_result),
    ("read_after_publish", |plan| &mut plan.read_after_publish),
    ("read_during_stall", |plan| &mut plan.read_during_stall),
    ("rekey_during_get", |plan| &mut plan.rekey_during_get),
    ("cancel_after_decision", |plan| {
        &mut plan.cancel_after_decision
    }),
    ("manual_maintenance", |plan| &mut plan.manual_maintenance),
    ("unattributed", |plan| &mut plan.unattributed),
    ("short_link", |plan| &mut plan.short_link),
    ("corrupt_resident", |plan| &mut plan.corrupt_resident),
    ("read_resident", |plan| &mut plan.read_resident),
];

/// The plan budgets a reducer may lower, in encoding order.
const COUNT_FIELDS: [CountField; 8] = [
    ("gets_first", |plan| &mut plan.gets[0]),
    ("gets_second", |plan| &mut plan.gets[1]),
    ("puts", |plan| &mut plan.puts),
    ("retries", |plan| &mut plan.retries),
    ("sessions", |plan| &mut plan.sessions),
    ("rekeys", |plan| &mut plan.rekeys),
    ("invalidations", |plan| &mut plan.invalidations),
    ("withhold", |plan| &mut plan.withhold),
];

const FLAGS: usize = FLAG_FIELDS.len();
const COUNTS: usize = COUNT_FIELDS.len();

/// Bytes of an encoded edit: the kind mask, each budget and the flag mask.
const EDIT_LEN: usize = 4 + 4 * COUNTS + 2;

/// The manifest capacities a reducer may halve.
const CAPACITIES: [&str; 2] = ["link_copy_bytes", "tx_slots"];

const _: () = assert!(FLAGS <= 16, "the flag mask holds one bit per flag");

/// Each kind whose proposals spend a budget, with the budgets of which it
/// needs at least one.
const SPENDS: [(ActionKind, &[&str]); 7] = [
    (ActionKind::Get, &["gets_first", "gets_second"]),
    (ActionKind::Read, &["gets_first", "gets_second"]),
    (ActionKind::PutInvoke, &["puts"]),
    (ActionKind::Retry, &["retries"]),
    (ActionKind::SessionChange, &["sessions"]),
    (ActionKind::Rekey, &["rekeys"]),
    (ActionKind::Invalidate, &["invalidations"]),
];

/// The index of budget `name` among [`COUNT_FIELDS`].
fn budget(name: &str) -> usize {
    COUNT_FIELDS
        .iter()
        .position(|(known, _)| *known == name)
        .unwrap_or_else(|| panic!("{name} is no reducible budget"))
}

fn bit(kind: ActionKind) -> u32 {
    1 << (kind as u8 - 1)
}

// The mask holds one bit per kind, so an appended kind past the 32nd
// fails to compile here, where the mask's capacity is enforced.
const _: () = assert!(ActionKind::ALL.len() <= u32::BITS as usize);

/// The reducible part of a scenario: the declared action kinds it keeps,
/// the plan budgets, and the plan flags a reducer may clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Edit {
    kinds: u32,
    counts: [u32; COUNTS],
    flags: [bool; FLAGS],
}

impl Edit {
    /// The edit that leaves `profile` and `plan` as they are.
    pub(super) fn of(profile: &Profile, plan: &Plan) -> Self {
        let mut plan = *plan;
        Self {
            kinds: profile
                .declared
                .iter()
                .fold(0, |mask, &kind| mask | bit(kind)),
            counts: COUNT_FIELDS.map(|(_, field)| *field(&mut plan)),
            flags: FLAG_FIELDS.map(|(_, field)| *field(&mut plan)),
        }
    }

    /// `profile` and `plan` under this edit, or `None` unless it only
    /// removes: each kind it keeps is declared, each budget is at most the
    /// plan's, and each flag it sets the plan sets. The edit applies when
    /// the plan's `script` is empty.
    pub(super) fn apply(&self, profile: &Profile, plan: Plan) -> Option<(Profile, Plan)> {
        let base = Self::of(profile, &plan);
        let within = plan.script.is_empty()
            && self.kinds & !base.kinds == 0
            && self
                .counts
                .iter()
                .zip(base.counts)
                .all(|(&edited, was)| edited <= was)
            && self
                .flags
                .iter()
                .zip(base.flags)
                .all(|(&edited, was)| was || !edited);
        if !within {
            return None;
        }
        let mut profile = profile.clone();
        profile.declared.retain(|&kind| self.kinds & bit(kind) != 0);
        let mut plan = plan;
        for ((_, field), value) in COUNT_FIELDS.iter().zip(self.counts) {
            *field(&mut plan) = value;
        }
        for ((_, field), value) in FLAG_FIELDS.iter().zip(self.flags) {
            *field(&mut plan) = value;
        }
        Some((profile, plan))
    }

    /// The edit as lowercase hex: the kind mask, each budget and the flag
    /// mask, little-endian.
    pub(crate) fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(EDIT_LEN);
        bytes.extend(self.kinds.to_le_bytes());
        for count in self.counts {
            bytes.extend(count.to_le_bytes());
        }
        let mask = self
            .flags
            .iter()
            .enumerate()
            .fold(0u16, |mask, (at, &on)| mask | (u16::from(on) << at));
        bytes.extend(mask.to_le_bytes());
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// [`encode`](Self::encode) in reverse.
    pub(crate) fn decode(text: &str) -> Option<Self> {
        let hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
        if text.len() != 2 * EDIT_LEN || !text.bytes().all(hex) {
            return None;
        }
        let bytes: Vec<u8> = (0..EDIT_LEN)
            .map(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).ok())
            .collect::<Option<_>>()?;
        let word =
            |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
        let mask = u16::from_le_bytes([bytes[EDIT_LEN - 2], bytes[EDIT_LEN - 1]]);
        if mask >> FLAGS != 0 {
            return None;
        }
        Some(Self {
            kinds: word(0),
            counts: std::array::from_fn(|at| word(4 + 4 * at)),
            flags: std::array::from_fn(|at| mask & (1 << at) != 0),
        })
    }

    fn keeps(&self, kind: ActionKind) -> bool {
        self.kinds & bit(kind) != 0
    }

    /// Whether the edit keeps a kind whose every prerequisite it removed, a
    /// kind whose budgets are all zero, or a supply that waits on deferrals
    /// it removed.
    fn breaks(&self) -> bool {
        let orphan = ActionKind::ALL.iter().any(|&kind| {
            let needs = prerequisites(kind);
            self.keeps(kind) && !needs.is_empty() && !needs.iter().any(|&need| self.keeps(need))
        });
        let unfunded = SPENDS.iter().any(|&(kind, budgets)| {
            self.keeps(kind) && budgets.iter().all(|&name| self.counts[budget(name)] == 0)
        });
        let starved = self.keeps(ActionKind::Supply)
            && !self.keeps(ActionKind::DeferSupply)
            && self.counts[budget("withhold")] > 0;
        orphan || unfunded || starved
    }

    /// The edit as text a regression stores beside its manifest.
    pub(crate) fn describe(&self) -> String {
        let kinds: Vec<String> = ActionKind::ALL
            .iter()
            .filter(|&&kind| self.keeps(kind))
            .map(|kind| format!("{kind:?}"))
            .collect();
        let mut out = format!("kinds = {}\n", kinds.join(", "));
        for ((name, _), count) in COUNT_FIELDS.iter().zip(self.counts) {
            out.push_str(&format!("{name} = {count}\n"));
        }
        for ((name, _), on) in FLAG_FIELDS.iter().zip(self.flags) {
            out.push_str(&format!("{name} = {on}\n"));
        }
        out
    }
}

/// The kinds of which a kind needs at least one, as the world proposes it.
fn prerequisites(kind: ActionKind) -> &'static [ActionKind] {
    use ActionKind::*;
    match kind {
        Read | Cancel => &[Get],
        Release => &[Read, Acquire],
        PutPrepare | PutCancel | PutOutcome => &[PutInvoke],
        Supply | DeferSupply => &[PutPrepare],
        Abandon | Retry | Invalidate => &[PutOutcome],
        Receive => &[Fill],
        Publish => &[Receive],
        Acquire | Expire | Evict => &[Publish],
        _ => &[],
    }
}

/// One step a reducer tries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Delete(ActionKind),
    Clear(&'static str),
    /// Cut the turn limit to this many turns.
    Schedule(u64),
    Lower(&'static str, u32),
    /// Halve a manifest capacity to this value.
    Halve(&'static str, u64),
}

/// What became of a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Kept,
    /// It keeps a kind without its prerequisite, budget or deferrals.
    Breaks,
    /// The manifest refuses the edited scenario or capacity.
    Refused,
    /// Its run panicked with an identity other than the original's, which
    /// is unsuccessful.
    Panicked,
    /// Its run ends without the original's violation.
    OtherOutcome,
    /// Its run violates as the original did without the plant's premise or
    /// the rule's enabling conditions.
    NoPremise,
    /// Its bundle does not replay in a fresh process.
    Unreproduced,
    /// Its fresh-process check failed for a reason other than a replay
    /// result, which stops the reduction.
    Unverified,
}

/// One step and what became of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) change: Change,
    pub(crate) verdict: Verdict,
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let verdict = match self.verdict {
            Verdict::Kept => "kept",
            Verdict::Breaks => "rejected, it breaks a dependency:",
            Verdict::Refused => "rejected, the manifest refuses it:",
            Verdict::Panicked => "rejected, its run panicked unlike the original:",
            Verdict::OtherOutcome => "rejected, another outcome:",
            Verdict::NoPremise => "rejected, the premise or an enabling condition is gone:",
            Verdict::Unreproduced => "rejected, it does not replay in a fresh process:",
            Verdict::Unverified => "unverified, its fresh-process check failed:",
        };
        match self.change {
            Change::Delete(kind) => write!(f, "{verdict} delete {kind:?}"),
            Change::Clear(flag) => write!(f, "{verdict} clear {flag}"),
            Change::Schedule(turns) => write!(f, "{verdict} cut the schedule to {turns} turns"),
            Change::Lower(budget, to) => write!(f, "{verdict} lower {budget} to {to}"),
            Change::Halve(capacity, to) => write!(f, "{verdict} halve {capacity} to {to}"),
        }
    }
}

/// How a replay ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Replayed {
    /// The replay's digest, decision count and terminal equal the original's.
    Reproduced,
    /// The first semantic record, counting `Begin` as 0, where the replay
    /// differs, `None` when every record matches yet the chooser refused or
    /// the result differs, and why.
    Diverged { at: Option<usize>, reason: String },
}

/// Why a bundle cannot be replayed or reduced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The bundle does not load, records no manifest that parses, holds
    /// more records than that manifest allows, or names a run the manifest
    /// cannot hold.
    Input(String),
    /// The tape ends before or inside a decision the run draws.
    Exhausted,
    /// A recovery profile's record fails to parse or differs from the one
    /// this executable derives, or a live profile's Config embeds one,
    /// before the first turn.
    Recovery(Unadmitted),
    /// Reduction requires a mixed-world bundle whose run is a complete
    /// violation with a failure identity, planted or with cataloged
    /// enabling conditions, or a panic a fresh process reproduces.
    Unreducible(String),
    /// The original's fresh-process check failed, for the reason given.
    Infrastructure(String),
}

/// The loaded bundle `bytes` and the manifest it recorded.
///
/// # Errors
///
/// `Recovery` when its recovery record does not parse or a live profile's
/// Config embeds one, `Input` when the bundle otherwise does not load,
/// records no manifest that parses, or holds more records than that
/// manifest allows.
pub(crate) fn recorded(bytes: &[u8]) -> Result<(Loaded, Manifest), Refused> {
    let loaded = load(bytes, u64::MAX).map_err(|error| match error {
        LoadError::Recovery { error, .. } => Refused::Recovery(Unadmitted::Record(error)),
        error => Refused::Input(format!("{error:?}")),
    })?;
    let manifest = manifest_of(&loaded)?;
    let records = (bytes.len() / RECORD) as u64;
    if records > manifest.capacity().records() {
        let reason = format!("{records} records past the manifest's maximum");
        return Err(Refused::Input(reason));
    }
    Ok((loaded, manifest))
}

/// The manifest `loaded` recorded.
///
/// # Errors
///
/// `Input` when `loaded` records no manifest that parses.
pub(crate) fn manifest_of(loaded: &Loaded) -> Result<Manifest, Refused> {
    let text = loaded
        .fields
        .iter()
        .find(|(field, _)| *field == Field::Manifest)
        .and_then(|(_, bytes)| std::str::from_utf8(bytes).ok())
        .ok_or_else(|| Refused::Input("no recorded manifest".into()))?;
    Manifest::parse_canonical(text).map_err(|error| Refused::Input(format!("{error:?}")))
}

/// The index of the first semantic record, counting `Begin` as 0, where
/// `ours` and `theirs` differ, the shorter stream's length when one is a
/// prefix of the other.
pub(super) fn first_difference(ours: &[u8], theirs: &[u8]) -> Option<usize> {
    let semantic = |bytes: &[u8]| -> Vec<[u8; RECORD]> {
        let (records, _) = bytes.as_chunks::<RECORD>();
        records
            .iter()
            .filter(|record| is_semantic(record[0]))
            .copied()
            .collect()
    };
    let (ours, theirs) = (semantic(ours), semantic(theirs));
    let shared = ours
        .iter()
        .zip(&theirs)
        .position(|(left, right)| left != right);
    shared.or((ours.len() != theirs.len()).then(|| ours.len().min(theirs.len())))
}

/// Replays `original` from its tape, returning the verdict and the bundle
/// the replay recorded.
///
/// # Errors
///
/// As [`replay_recording`].
pub(crate) fn replay(original: &[u8]) -> Result<(Replayed, Vec<u8>), Refused> {
    let mut sink = Vec::new();
    let replayed = replay_recording(original, &mut sink)?;
    Ok((replayed, sink))
}

/// Replays `original` from its tape, recording into `sink`, which keeps
/// the records written before a panic, and returns the verdict.
///
/// # Errors
///
/// `Input` when the bundle does not load or name a run, `Recovery` when
/// its recovery record does not parse, a live profile's Config embeds one,
/// or the record differs from the one this executable derives for the
/// bundle's profile, all before the first turn, `Exhausted` when its tape
/// ends before or inside a decision the run draws.
pub(crate) fn replay_recording(original: &[u8], sink: &mut Vec<u8>) -> Result<Replayed, Refused> {
    let (loaded, manifest) = recorded(original)?;
    let admitted = admit(&manifest).map_err(|refusal| Refused::Input(format!("{refusal:?}")))?;
    let chooser = admitted.replayer(&loaded).map_err(Refused::Recovery)?;
    let (closed, end, finished) = run_into(admitted, sink, chooser);
    let at = first_difference(original, closed.sink);
    let refused = match end {
        End::Defect(defect) => defect.choice(),
        _ => None,
    };
    let refusal = match (refused, finished) {
        (Some(ChoiceError::Short), _) => return Err(Refused::Exhausted),
        (Some(error), _) | (None, Err(error)) => Some(format!("{error:?}")),
        (None, Ok(_)) => None,
    };
    let same = closed.digest == loaded.digest
        && closed.work.decisions == loaded.decisions
        && closed.terminal == loaded.terminal;
    let replayed = match refusal {
        Some(reason) => Replayed::Diverged { at, reason },
        None if at.is_none() && same => Replayed::Reproduced,
        None => Replayed::Diverged {
            at,
            reason: "the replayed records or result differ".into(),
        },
    };
    Ok(replayed)
}

/// A minimized regression: its manifest, bundle, the steps the reducer
/// took, its scenario as text and the failure identity every kept step
/// shares with the original.
#[derive(Debug)]
pub(crate) struct Reduced {
    pub(crate) manifest: Manifest,
    pub(crate) bundle: Vec<u8>,
    pub(crate) steps: Vec<Step>,
    pub(crate) scenario: String,
    pub(crate) identity: Identity,
    /// The enabling conditions every kept step of an unplanted violation
    /// holds.
    pub(crate) conditions: Vec<&'static str>,
    /// Why the reduction stopped.
    pub(crate) stop: Stop,
}

/// Why a reduction stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The search completed: the scenario reducer tried every candidate of
    /// its last kept step; the schedule reducer's search states its rule.
    Exhausted,
    /// A bound ended the search first; the regression is the best kept so
    /// far.
    Bounded,
    /// A candidate's fresh-process check failed, for the reason given;
    /// the step log ends with that candidate, the regression is the best
    /// kept before it, and the failure stays unresolved.
    Interrupted(String),
}

/// The most steps one reduction tries.
pub(crate) const MAX_STEPS: usize = 512;

/// Replays a bundle in a fresh process and says whether it reproduced the
/// identity it is given, or why the check failed.
pub(crate) type Verify<'v> = dyn FnMut(&[u8], &Identity) -> Result<bool, String> + 'v;

/// What a failing run's reduction preserves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Identity {
    /// A complete violation's failure identity.
    Violation(FailureIdentity),
    /// A panic's location and payload.
    Panic(String),
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Violation(_) => write!(f, "its original violation"),
            Self::Panic(identity) => write!(f, "the run panicked at {identity}"),
        }
    }
}

/// A complete violation's versioned failure identity: the payload of its
/// [`IDENTITY`] event, compared as an opaque value. It is a type apart
/// from the violation record, which shares the payload's size and keeps
/// only a truncated rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FailureIdentity([u8; PAYLOAD]);

impl FailureIdentity {
    /// The identity an [`IDENTITY`] event carries; `None` for an event of
    /// another kind.
    pub(crate) fn of(event: &Event) -> Option<Self> {
        (event.kind == IDENTITY).then_some(Self(event.payload))
    }

    /// The identity of `failure`, which names a broken obligation as
    /// [`identity_event`] requires, surfacing at `site`.
    pub(crate) fn of_failure(failure: &Failure, site: Site) -> Self {
        Self(identity_event(failure, site).payload)
    }

    /// The identity's payload bytes, laid out as [`IDENTITY`] states.
    pub(crate) fn bytes(&self) -> &[u8; PAYLOAD] {
        &self.0
    }
}

/// Whether `loaded` ends in a complete violation and records its
/// violation record.
fn violating(loaded: &Loaded) -> bool {
    let failed = matches!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Outcome::Violation,
            ..
        }
    );
    failed && loaded.violation.is_some()
}

/// The failure identity of `loaded` when it ends in a complete violation:
/// its last [`IDENTITY`] event's payload, naming the variant, obligation,
/// audit class, site and the digest of the full rule, so a step keeps the
/// same claim and no rule that shares the violation record's truncated
/// prefix stands in for it. `None` for a run without a complete violation
/// or without an identity event.
pub(crate) fn violated(loaded: &Loaded) -> Option<FailureIdentity> {
    if !violating(loaded) {
        return None;
    }
    loaded.events.iter().rev().find_map(FailureIdentity::of)
}

/// A named enabling condition of a failure, checked on a run's bundle
/// independently of the check that failed.
pub(crate) struct Condition {
    pub(crate) name: &'static str,
    pub(super) holds: fn(&Loaded) -> bool,
}

/// How many witnessed actions of `kind` `loaded` records.
fn acted(loaded: &Loaded, kind: ActionKind) -> usize {
    loaded
        .events
        .iter()
        .filter(|event| event.kind == ACT && event.payload[0] == kind as u8)
        .filter_map(|event| event.payload[1..9].try_into().ok())
        .map(u64::from_le_bytes)
        .filter(|&outcome| super::witnessed(kind, outcome))
        .count()
}

/// The run's stop event records at least one checked stopped boundary.
/// The mixed world raises both cataloged rules at [`Site::Run`] only from
/// its stopped-boundary check, which counts the boundary as checked, so a
/// complete run that keeps either identity holds this condition. It
/// witnesses that the stop event recorded that check; a bundle whose stop
/// event names no checked boundary refuses reduction or rejects its step.
const BOUNDARY_CHECKED: Condition = Condition {
    name: "boundary-checked",
    holds: |loaded| {
        super::bundle::observed(&loaded.events)
            .composed
            .is_some_and(|composed| composed.checked > 0)
    },
};

/// The enabling conditions of each cataloged rule, by its obligation, the
/// site it surfaced at and its full text. Each rule here is raised by one
/// check. An unplanted failure whose rule and site are not here has no
/// checkable conditions and refuses reduction.
const CATALOG: &[(Obligation, Site, &str, &[Condition])] = &[
    (
        Obligation::Bytes,
        Site::Run,
        UNREGISTERED_BYTES,
        &[BOUNDARY_CHECKED],
    ),
    (
        Obligation::Bytes,
        Site::Run,
        UNCHECKED_RECORD,
        &[BOUNDARY_CHECKED],
    ),
];

/// The enabling conditions the cataloged rule `identity` names, or `None`
/// for an identity whose rule and site the catalog does not hold.
pub(crate) fn conditions(identity: &FailureIdentity) -> Option<&'static [Condition]> {
    CATALOG
        .iter()
        .find(|(obligation, site, rule, _)| {
            FailureIdentity::of_failure(&Failure::Violation(*obligation, rule), *site) == *identity
        })
        .map(|(.., conditions)| *conditions)
}

/// Whether every enabling condition of the unplanted failure `identity`
/// holds on `loaded`; `None` when the failure names no cataloged
/// conditions.
pub(crate) fn enabled(identity: &FailureIdentity, loaded: &Loaded) -> Option<bool> {
    conditions(identity).map(|found| found.iter().all(|condition| (condition.holds)(loaded)))
}

/// Whether `loaded` witnesses the premise of `plant`, `None` for a run with
/// no plant, one that panics, or the peer owner's uncounted plant. An upload plant needs one upload attempt
/// with a supply accepted for every fragment of the object its recorded
/// scenario uploads, and from that attempt a grant from the owner and the
/// plant's witness: a collected publication for a changed published
/// record and for a leaked unit, every fragment acknowledged while the
/// outcome was undecided for
/// a claim on acknowledgment. A stalled heal needs a delivered rekey, a GET
/// from each client and a witnessed read, so a step keeps the reads the
/// plant withholds from one client. A plant that changes what a decided
/// GET hands its client needs a GET and a witnessed read, and a plant that
/// collects an unknown upload outcome as published needs a witnessed
/// outcome collection. The uncounted plant needs an invoked upload, which
/// makes a BEGIN datagram due toward the owner. A run can witness a premise
/// only if its recorded manifest names a scenario.
pub(super) fn premise(plant: Plant, loaded: &Loaded) -> Option<bool> {
    if plant == Plant::None {
        return None;
    }
    let object = manifest_of(loaded)
        .ok()
        .and_then(|manifest| scenario(&manifest).ok())
        .map(|(_, plan, _)| plan.object_len);
    let Some(object) = object else {
        return Some(false);
    };
    let fragments = object.div_ceil(super::FRAGMENT_LEN);
    let states: Vec<UploadState> = loaded.events.iter().filter_map(UploadState::of).collect();
    let mut attempts: std::collections::BTreeMap<(u64, u16), std::collections::BTreeSet<u32>> =
        std::collections::BTreeMap::new();
    for put in loaded.events.iter().filter_map(PutRecord::of) {
        if put.kind == Some(ActionKind::Supply) && put.outcome == SUPPLIED {
            attempts
                .entry((put.session, put.attempt))
                .or_default()
                .insert(put.fragment);
        }
    }
    // The attempts whose accepted supplies cover every fragment; the grant
    // and the plant's witness must come from one of them.
    let covering: std::collections::BTreeSet<u16> = attempts
        .iter()
        .filter(|(_, supplied)| supplied.iter().copied().eq(0..fragments))
        .map(|((_, attempt), _)| *attempt)
        .collect();
    let witnessed = |test: &dyn Fn(&UploadState) -> bool| {
        let granted = states
            .iter()
            .any(|state| covering.contains(&state.attempt) && state.grant > 0);
        granted
            && states
                .iter()
                .any(|state| covering.contains(&state.attempt) && test(state))
    };
    let published = UploadState::code(UploadOutcome::Published);
    match plant {
        // A panic is its own identity, so it carries no premise.
        Plant::None | Plant::Panic | Plant::DebugAssertion => None,
        Plant::UncountedPeer => None,
        Plant::StalledHeal => Some(
            acted(loaded, ActionKind::Rekey) >= 1
                && acted(loaded, ActionKind::Get) == 2
                && acted(loaded, ActionKind::Read) >= 1,
        ),
        Plant::PublishedByte | Plant::SettledByte | Plant::LeakedUnit => {
            Some(witnessed(&|state| state.outcome == published))
        }
        Plant::AckAsSuccess => Some(witnessed(&|state| {
            state.base == fragments && state.outcome == 0
        })),
        Plant::ChangedRead | Plant::UnpublishedHit | Plant::ExposedMiss | Plant::StagedHit => {
            Some(acted(loaded, ActionKind::Get) >= 1 && acted(loaded, ActionKind::Read) >= 1)
        }
        Plant::UnknownAsSuccess | Plant::ContendedAsSuccess => {
            Some(acted(loaded, ActionKind::PutOutcome) >= 1)
        }
        // An upload invocation makes a BEGIN datagram due toward the owner.
        Plant::Uncounted => Some(acted(loaded, ActionKind::PutInvoke) >= 1),
    }
}

/// Reduces the failing mixed-world bundle `original`, a violation planted
/// or with cataloged enabling conditions or a run that panicked, toward a
/// smaller regression of the same failure, trying at most [`MAX_STEPS`]
/// steps. `verify` replays a bundle in a fresh process and says whether it
/// reproduced the identity it is given; it runs for the original and for
/// every step that would be kept. A `verify` that fails after the
/// original's check stops the reduction with the best regression so far,
/// marked interrupted.
///
/// # Errors
///
/// `Input` when the bundle does not load or name a run or `admit` refuses
/// its manifest, `Recovery` when its recovery record does not parse or a
/// live profile's Config embeds one, `Unreducible` when its scenario names
/// another world than the mixed one, when it is no complete violation with
/// a failure identity and no panic, when an unplanted violation's rule and
/// site name no cataloged enabling conditions, when its plant's premise
/// or its rule's cataloged enabling conditions do not hold, when it stops
/// short of its terminal and its rerun does not panic there with the same
/// bundle, or when it does not replay in a fresh process, `Infrastructure`
/// when `verify` fails for the original.
pub(crate) fn reduce(original: &[u8], verify: &mut Verify<'_>) -> Result<Reduced, Refused> {
    let mut run = |admitted: Admitted<'_>, sink: &mut Vec<u8>| {
        traced(admitted, sink);
    };
    reduce_with(original, verify, &mut run, MAX_STEPS)
}

/// Runs `admitted` through `run` into a fresh bundle, keeping the records
/// written before a panic: the bundle, and the panic's identity when the
/// run panicked.
fn ran(
    run: &mut dyn FnMut(Admitted<'_>, &mut Vec<u8>),
    admitted: Admitted<'_>,
) -> (Vec<u8>, Option<String>) {
    let mut sink = Vec::new();
    let panicked = unwind::caught(|| run(admitted, &mut sink)).err();
    (sink, panicked)
}

/// The turn limit a run needs to fail as `identity` did in `loaded`. A
/// complete violation's terminal records the turns it took. A panic stops
/// inside its turn, before that turn is recorded, so a rerun needs one
/// turn beyond the recorded turns.
fn taken(loaded: &Loaded, identity: &Identity) -> u64 {
    match identity {
        Identity::Violation(_) => loaded.work.turns,
        Identity::Panic(_) => loaded.turns.len() as u64 + 1,
    }
}

/// [`reduce`] with each run, the original's rerun included, recorded by
/// `run` into the sink it is given, trying at most `limit` steps. A
/// panicked run's bundle ends before the choices of the turn the panic
/// cut, so its tape replays to exhaustion: `verify` reproduces a panic by
/// rerunning the bundle's own manifest to the same panic and the same
/// bundle.
pub(super) fn reduce_with(
    original: &[u8],
    verify: &mut Verify<'_>,
    run: &mut dyn FnMut(Admitted<'_>, &mut Vec<u8>),
    limit: usize,
) -> Result<Reduced, Refused> {
    let (loaded, manifest) = recorded(original)?;
    let unreducible = |reason: &str| Refused::Unreducible(reason.into());
    let (profile, plan, _) =
        scenario(&manifest).map_err(|refusal| Refused::Input(format!("{refusal:?}")))?;
    if !matches!(plan.world, WorldKind::Mixed) {
        return Err(unreducible("only a mixed-world bundle reduces"));
    }
    let target = match violated(&loaded) {
        Some(identity) => Identity::Violation(identity),
        None if violating(&loaded) => {
            return Err(unreducible(
                "the bundle's violation records no failure identity",
            ));
        }
        None if loaded.terminal == Terminal::Infrastructure(Infrastructure::Truncated) => {
            let admitted =
                admit(&manifest).map_err(|refusal| Refused::Input(format!("{refusal:?}")))?;
            match ran(run, admitted) {
                (rerun, Some(panic)) if rerun == original => Identity::Panic(panic),
                _ => {
                    return Err(unreducible(
                        "the bundle's run does not panic where it stops",
                    ));
                }
            }
        }
        None => {
            return Err(unreducible(
                "the bundle records no complete violation and no panic",
            ));
        }
    };
    // A planted failure keeps its plant's premise; an unplanted one keeps
    // the cataloged enabling conditions of its rule; a panic keeps only its
    // own identity.
    let required: &[Condition] = match (&target, plan.plant) {
        (Identity::Violation(identity), Plant::None) => conditions(identity).ok_or_else(|| {
            unreducible("the failure's rule names no cataloged enabling conditions")
        })?,
        _ => &[],
    };
    let premised = |ran: &Loaded| match plan.plant {
        Plant::None => required.iter().all(|condition| (condition.holds)(ran)),
        plant => premise(plant, ran) == Some(true),
    };
    if matches!(target, Identity::Violation(_)) && !premised(&loaded) {
        return Err(unreducible(match plan.plant {
            Plant::None => "the bundle does not witness its rule's enabling conditions",
            _ => "the bundle does not witness its plant's premise",
        }));
    }
    if !verify(original, &target).map_err(Refused::Infrastructure)? {
        return Err(unreducible("the bundle does not replay in a fresh process"));
    }
    let mut current = (Edit::of(&profile, &plan), manifest.clone());
    let mut best = original.to_vec();
    let mut steps = Vec::new();
    let mut stop = Stop::Exhausted;
    'reduce: loop {
        let turns = load(&best, u64::MAX).map_or(0, |run| taken(&run, &target));
        for (change, edit, candidate) in candidates(&current, turns) {
            if steps.len() >= limit {
                stop = Stop::Bounded;
                break 'reduce;
            }
            let mut decide = |verdict| steps.push(Step { change, verdict });
            if edit.breaks() {
                decide(Verdict::Breaks);
                continue;
            }
            let Ok(admitted) = admit(&candidate) else {
                decide(Verdict::Refused);
                continue;
            };
            let (bytes, panicked) = ran(run, admitted);
            let loaded = load(&bytes, u64::MAX).ok();
            let failed = match panicked {
                Some(panic) => Some(Identity::Panic(panic)),
                None => loaded.as_ref().and_then(violated).map(Identity::Violation),
            };
            if failed.as_ref() != Some(&target) {
                decide(match failed {
                    Some(Identity::Panic(_)) => Verdict::Panicked,
                    _ => Verdict::OtherOutcome,
                });
                continue;
            }
            if matches!(target, Identity::Violation(_)) && !loaded.as_ref().is_some_and(premised) {
                decide(Verdict::NoPremise);
                continue;
            }
            match verify(&bytes, &target) {
                Err(reason) => {
                    decide(Verdict::Unverified);
                    stop = Stop::Interrupted(reason);
                    break 'reduce;
                }
                Ok(false) => {
                    decide(Verdict::Unreproduced);
                    continue;
                }
                Ok(true) => {}
            }
            decide(Verdict::Kept);
            current = (edit, candidate);
            best = bytes;
            continue 'reduce;
        }
        break;
    }
    Ok(Reduced {
        manifest: current.1,
        bundle: best,
        steps,
        scenario: current.0.describe(),
        identity: target,
        conditions: required.iter().map(|condition| condition.name).collect(),
        stop,
    })
}

/// The one-step reductions of `(edit, manifest)` in group order: each kind
/// deleted, each flag cleared, the turn limit cut to `turns`, then each
/// budget lowered by one and each capacity halved; each with its edit and
/// the manifest that runs it.
fn candidates((edit, manifest): &(Edit, Manifest), turns: u64) -> Vec<(Change, Edit, Manifest)> {
    let scenario = |edit: Edit| manifest.clone().with_scenario(edit.encode());
    let mut out = Vec::new();
    for kind in ActionKind::ALL.into_iter().filter(|&kind| edit.keeps(kind)) {
        let cut = Edit {
            kinds: edit.kinds & !bit(kind),
            ..*edit
        };
        out.push((Change::Delete(kind), cut, scenario(cut)));
    }
    for (at, (name, _)) in FLAG_FIELDS
        .iter()
        .enumerate()
        .filter(|&(at, _)| edit.flags[at])
    {
        let mut cleared = *edit;
        cleared.flags[at] = false;
        out.push((Change::Clear(name), cleared, scenario(cleared)));
    }
    if turns > 0 && turns < manifest.count("turns") {
        let cut = manifest.clone().with("turns", turns);
        out.push((
            Change::Schedule(turns),
            *edit,
            cut.with_scenario(edit.encode()),
        ));
    }
    for (at, (name, _)) in COUNT_FIELDS
        .iter()
        .enumerate()
        .filter(|&(at, _)| edit.counts[at] > 0)
    {
        let mut lowered = *edit;
        lowered.counts[at] -= 1;
        out.push((
            Change::Lower(name, lowered.counts[at]),
            lowered,
            scenario(lowered),
        ));
    }
    for name in CAPACITIES {
        let halved = manifest.count(name) / 2;
        if halved > 0 {
            let cut = manifest
                .clone()
                .with(name, halved)
                .with_scenario(edit.encode());
            out.push((Change::Halve(name, halved), *edit, cut));
        }
    }
    out
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod recovery_tests;
