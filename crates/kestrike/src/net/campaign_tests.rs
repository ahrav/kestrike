//! Campaign profiles: seven named workloads, each declared once per run by
//! the manifest and admitted before any storage exists, then driven over
//! one engine through the choice contract and judged by the history oracle.
//!
//! Admission resolves the manifest's profile, judges the profile's pair-row
//! configuration with the configuration model and requires a non-empty
//! action mask that holds every action the profile's declared obligations
//! need. A profile's weights, key subset, hot-key skew, sizes, fault class,
//! bounds, obligations and witnesses are constants, and its canonical record
//! encodes every field and the root, so two profiles or two roots never
//! share one. Generation draws one candidate per step among
//! the actions valid in the current state, with each action's weight as its
//! count of candidate slots, so the tape records the candidate sets and a
//! replay of the tape repeats the run.
//!
//! Each phase ends in a funded healthy interval: holders return, funded
//! maintenance restores a largest record's units and a slot within the
//! configuration's action bound, and a fresh publication must then serve an
//! exact hit. The history oracle judges that interval; its key and label
//! domain holds two keys of two labels each, so the generated steps are
//! judged by the run's credit table instead: every lookup must agree with
//! the publications the run credited after publish returned, and each later
//! phase must find the previous phase's qualified publication on the same
//! engine. The isolated profile runs two owners of its configuration and
//! qualifies the healthy one's exact read within a turn bound while the
//! other keeps its custody after an unproven stop; the two owners share no
//! storage, arena or link, so the profile's evidence is for owners that
//! share only their clients' receive pool and the turn loop.

use crate::oracle::{
    Checkpoint, Custodian, Inconclusive, KeyId, Label, Obligation, Outcome, Recorder, ReportKind,
    ReportState, ResourceKind, Row, Verdict, check,
};
use crate::sim::choice::{CANDIDATE_LEN, Candidate, Chooser, Domain, Site};
use crate::sim::manifest::Manifest;
use crate::sim::manifest_tests::sample_lines;
use crate::sim::round::{self, Actor, afresh};
use crate::storage::owner_fixture::{
    Device, QuiesceMode, SimControl, TestPlatform, attach_shaped, invalidate,
};
use crate::storage::{
    AllocationId, BufferArena, Decision, EngineBudget, ExtentLease, MaintainStage, Maintained,
    Storage, WorkBudget, WritableFill,
};

use super::adapters::{ID, fills_written, served, share, shares, written_commands};
use super::coverage_tests::{
    CHUNK, CHUNK_16K, Derived, FACTORS, FAULTS, HEADER_SLACK, SPAN, SPAN_8K, arena, owner_config,
    rows, storage,
};
use super::fetch::{Outcome as Fetched, Releases};
use super::link::{Faults, LinkEnd, network};
use super::owner::{Bundle, Keys, Owner};
use super::owner_tests::{
    Mux, PRINCIPALS, TestOwner, client, collect, entries, hold_next_read, key, open, pool,
};

/// One workload action a profile weights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum Act {
    Fill = 1,
    Publish,
    Acquire,
    Read,
    Release,
    Invalidate,
    Maintain,
}

impl Act {
    const ALL: [Self; 7] = [
        Self::Fill,
        Self::Publish,
        Self::Acquire,
        Self::Read,
        Self::Release,
        Self::Invalidate,
        Self::Maintain,
    ];
}

/// A fact a campaign must observe for its run to count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Witness {
    /// A lookup hit a key a publication of this run made visible, and its
    /// read returned that publication's exact bytes.
    PublishedBeforeAcquire = 1,
    /// A publication replaced a credited label of its key.
    Replacement,
    /// A read under a lease taken before its key's invalidation returned
    /// the bytes the lease was taken for.
    HeldAcrossInvalidation,
    /// Maintenance evicted a resident.
    Eviction,
    /// A fill received a refusal at begin, admission or reservation.
    PressureRefusal,
    /// A lookup of the hot key hit while another lease on it was held.
    HotKeyShared,
    /// A second phase ran on the engine the first phase built.
    PhaseAccumulated,
    /// The healthy owner served exact bytes beside the stopped owner.
    IsolatedServe,
}

/// The fault a profile injects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum FaultClass {
    None = 1,
    /// One owner stops with a held read and no proof of quiescence.
    UnprovenStop,
}

/// A campaign profile. Every field is fixed for the run.
#[derive(Debug)]
pub(super) struct Profile {
    name: &'static str,
    /// The pair row whose derived configuration the run builds.
    row: usize,
    /// Each action's weight, in [`Act::ALL`] order; zero leaves it out of
    /// the mask. The isolated profile generates no steps: its weights name
    /// the actions its fixed two-owner scene performs.
    weights: [u8; 7],
    /// Keys the workload draws from.
    keys: u8,
    /// The multiplier on key zero's fill and lookup candidate slots; every
    /// other key's multiplier is one.
    hot: u8,
    /// Inclusive body sizes a fill draws from.
    sizes: (u32, u32),
    /// The fault class the run injects.
    faults: FaultClass,
    /// Generated steps per phase.
    steps: u32,
    /// Retries each lookup may make.
    retries: usize,
    /// The healthy owner's turn bound when isolated.
    turns: u32,
    obligations: &'static [Obligation],
    witnesses: &'static [Witness],
    /// The profiles whose workloads the phases run, in order; empty runs
    /// this profile's own workload as the one phase.
    phases: &'static [&'static str],
}

const STORAGE: &[Obligation] = &[
    Obligation::Progress,
    Obligation::Bytes,
    Obligation::History,
    Obligation::Resources,
];

const PROFILES: [Profile; 7] = [
    Profile {
        name: "all-actions",
        row: 10,
        weights: [2, 2, 3, 2, 2, 1, 1],
        keys: 4,
        hot: 1,
        sizes: (1, 30_000),
        faults: FaultClass::None,
        steps: 300,
        retries: 4,
        turns: 0,
        obligations: STORAGE,
        witnesses: &[
            Witness::PublishedBeforeAcquire,
            Witness::Replacement,
            Witness::HeldAcrossInvalidation,
        ],
        phases: &[],
    },
    Profile {
        name: "healthy",
        row: 9,
        weights: [3, 3, 3, 3, 3, 0, 1],
        keys: 4,
        hot: 1,
        sizes: (1, 200),
        faults: FaultClass::None,
        steps: 200,
        retries: 4,
        turns: 0,
        obligations: STORAGE,
        witnesses: &[Witness::PublishedBeforeAcquire],
        phases: &[],
    },
    Profile {
        name: "hot-key",
        row: 14,
        weights: [2, 2, 6, 1, 1, 1, 1],
        keys: 4,
        hot: 12,
        sizes: (1, 200),
        faults: FaultClass::None,
        steps: 300,
        retries: 4,
        turns: 0,
        obligations: STORAGE,
        witnesses: &[Witness::PublishedBeforeAcquire, Witness::HotKeyShared],
        phases: &[],
    },
    Profile {
        name: "fragmentation",
        row: 13,
        weights: [4, 4, 1, 1, 2, 2, 2],
        keys: 8,
        hot: 1,
        sizes: (1, 200),
        faults: FaultClass::None,
        steps: 300,
        retries: 4,
        turns: 0,
        obligations: STORAGE,
        witnesses: &[Witness::PressureRefusal, Witness::Eviction],
        phases: &[],
    },
    Profile {
        name: "isolated",
        row: 7,
        weights: [1, 1, 1, 1, 1, 0, 0],
        keys: 1,
        hot: 1,
        sizes: (200, 200),
        faults: FaultClass::UnprovenStop,
        steps: 0,
        retries: 4,
        turns: 2_000,
        obligations: &[Obligation::Isolation, Obligation::Resources],
        witnesses: &[Witness::IsolatedServe],
        phases: &[],
    },
    Profile {
        name: "correlated",
        row: 9,
        weights: [2, 2, 4, 1, 1, 3, 0],
        keys: 2,
        hot: 1,
        sizes: (1, 200),
        faults: FaultClass::None,
        steps: 300,
        retries: 4,
        turns: 0,
        obligations: STORAGE,
        witnesses: &[
            Witness::HeldAcrossInvalidation,
            Witness::Replacement,
            Witness::PublishedBeforeAcquire,
        ],
        phases: &[],
    },
    Profile {
        name: "persistent-owner",
        row: 9,
        weights: [3, 3, 3, 3, 3, 1, 1],
        keys: 4,
        hot: 1,
        sizes: (1, 200),
        faults: FaultClass::None,
        steps: 0,
        retries: 4,
        turns: 0,
        obligations: STORAGE,
        witnesses: &[Witness::PhaseAccumulated, Witness::PublishedBeforeAcquire],
        phases: &["healthy", "hot-key", "fragmentation"],
    },
];

fn profile(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|profile| profile.name == name)
}

/// The actions an obligation's judgment needs the workload to run.
fn needs(obligation: Obligation) -> &'static [Act] {
    match obligation {
        Obligation::Progress | Obligation::Bytes => {
            &[Act::Fill, Act::Publish, Act::Acquire, Act::Read]
        }
        Obligation::History => &[Act::Fill, Act::Publish, Act::Acquire],
        Obligation::Resources => &[Act::Acquire, Act::Release],
        Obligation::Isolation => &[Act::Acquire, Act::Read],
        Obligation::Custody | Obligation::Restart | Obligation::Contain => &[],
    }
}

/// Why admission refused a run, before any storage was built.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    UnknownProfile,
    /// A phase names no profile.
    UnknownPhase,
    EmptyMask,
    /// A declared obligation needs an action the mask leaves out.
    MissingAction(Obligation, Act),
    /// The configuration model refuses the profile's configuration.
    Configuration(Vec<&'static str>),
}

/// An admitted run: the profile, its configuration and the root seed, all
/// fixed before construction.
pub(super) struct Admitted {
    profile: &'static Profile,
    derived: Derived,
    root: u64,
}

impl Profile {
    fn mask(&self) -> Vec<Act> {
        Act::ALL
            .into_iter()
            .zip(self.weights)
            .filter_map(|(act, weight)| (weight > 0).then_some(act))
            .collect()
    }

    /// The canonical record: the root, then name, row and row levels,
    /// weights, keys, skew, sizes, fault class, bounds, obligations,
    /// witnesses and each phase profile's workload; the obligation and
    /// witness lists each end in a zero byte. Every phase runs on this
    /// profile's row.
    fn record(&self, root: u64) -> Vec<u8> {
        let mut out = root.to_le_bytes().to_vec();
        out.extend(self.body());
        out
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let text = |out: &mut Vec<u8>, text: &str| {
            out.push(text.len() as u8);
            out.extend(text.as_bytes());
        };
        text(&mut out, self.name);
        out.push(self.row as u8);
        for level in rows()[self.row] {
            out.push(level as u8);
        }
        out.extend(self.weights);
        out.extend([self.keys, self.hot]);
        out.extend(self.sizes.0.to_le_bytes());
        out.extend(self.sizes.1.to_le_bytes());
        out.push(self.faults as u8);
        out.extend(self.steps.to_le_bytes());
        out.extend((self.retries as u32).to_le_bytes());
        out.extend(self.turns.to_le_bytes());
        out.extend(self.obligations.iter().map(|&o| o as u8));
        out.push(0);
        out.extend(self.witnesses.iter().map(|&w| w as u8));
        out.push(0);
        for phase in self.phases {
            out.extend(profile(phase).map_or_else(Vec::new, Profile::workload));
        }
        out
    }

    /// The profiles whose workloads the phases run, or `None` when a phase
    /// names no profile.
    fn workloads(&'static self) -> Option<Vec<&'static Profile>> {
        if self.phases.is_empty() {
            return Some(vec![self]);
        }
        self.phases.iter().map(|name| profile(name)).collect()
    }

    /// The workload fields a phase of another profile runs: name, weights,
    /// keys, skew, sizes, steps and lookup retries.
    fn workload(&self) -> Vec<u8> {
        let mut out = vec![self.name.len() as u8];
        out.extend(self.name.as_bytes());
        out.extend(self.weights);
        out.extend([self.keys, self.hot]);
        out.extend(self.sizes.0.to_le_bytes());
        out.extend(self.sizes.1.to_le_bytes());
        out.extend(self.steps.to_le_bytes());
        out.extend((self.retries as u32).to_le_bytes());
        out
    }
}

/// Admits the run `manifest` declares, judging the configuration and the
/// mask before anything is constructed.
fn admit(manifest: &Manifest) -> Result<Admitted, Refusal> {
    let profile = profile(&manifest.profile).ok_or(Refusal::UnknownProfile)?;
    admit_profile(profile, rows()[profile.row], manifest.root)
}

fn admit_profile(
    profile: &'static Profile,
    row: super::coverage_tests::Assignment,
    root: u64,
) -> Result<Admitted, Refusal> {
    let workloads = profile.workloads().ok_or(Refusal::UnknownPhase)?;
    for workload in std::iter::once(profile).chain(workloads) {
        let mask = workload.mask();
        if mask.is_empty() {
            return Err(Refusal::EmptyMask);
        }
        for &obligation in profile.obligations {
            if let Some(&act) = needs(obligation).iter().find(|act| !mask.contains(act)) {
                return Err(Refusal::MissingAction(obligation, act));
            }
        }
    }
    let derived = Derived::of(&row);
    let violations = derived.violations();
    if !violations.is_empty() {
        return Err(Refusal::Configuration(violations));
    }
    Ok(Admitted {
        profile,
        derived,
        root,
    })
}

fn manifest_for(profile: &str, root: u64) -> Manifest {
    let text: String = sample_lines(profile, &"0".repeat(64), "linux-x86_64")
        .into_iter()
        .map(|(key, value)| {
            let value = if key == "root" {
                root.to_string()
            } else {
                value
            };
            format!("{key} = {value}\n")
        })
        .collect();
    Manifest::parse(&text).expect("a valid manifest")
}

/// A harness plant: a scene variant the run passes, or a defect a named
/// check must fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plant {
    None,
    /// A fill's label is credited as visible when the fill completes, before
    /// its publication.
    CreditUnpublished,
    /// A publication that replaces a credited label leaves the replaced
    /// label credited.
    CreditStale,
    /// Each phase builds a fresh engine.
    RebuildEngine,
    /// The harness skips the reservation of the qualified publication's
    /// first `n` attempts; each skipped attempt still counts against the
    /// action bound and runs maintenance.
    RefuseQualified(u32),
    /// One lease stays held across the qualified checkpoint.
    Retention,
    /// The qualified publication is never looked up.
    SkipLookup,
    /// The harness publishes the qualified bytes under the qualified key a
    /// second time after the qualified publication, so a lookup hits another
    /// allocation holding those bytes.
    RepublishQualified,
    /// Every invalidation runs on an empty budget, so storage refuses each
    /// one and keeps every mapping.
    RefuseInvalidate,
    /// Every credit is marked evictable at its publication, as if maintenance
    /// evicted it at once.
    EvictableCredits,
    /// The healthy client's GET is routed to the stopped owner.
    StarvePeer,
    /// The stopped owner's retained share is recorded returned.
    ReturnStopped,
    /// The healthy owner stores its object with the low bit of its first
    /// byte flipped, so it differs from the bytes the history records for it.
    CorruptServed,
    /// Admission closes before the qualified publication.
    CloseBeforeQualified,
    /// The history ends unsealed.
    Unsealed,
}

/// The class a run's result falls in. Only a pass with every declared
/// obligation activated discharges a gate.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Class {
    Pass,
    Safety(Obligation, &'static str),
    ProgressExhausted(Obligation, &'static str),
    TerminalRefusal(&'static str),
    Incomplete(Inconclusive),
}

#[derive(Debug)]
pub(super) struct Run {
    tape: Vec<u8>,
    verdict: Result<Verdict, &'static str>,
    gate: Result<(), &'static str>,
    fired: Vec<Witness>,
    pub(super) rows: Vec<Row>,
    /// Each generated step's observable result.
    pub(super) trace: Vec<u8>,
}

impl Run {
    pub(super) fn class(&self) -> Class {
        match &self.verdict {
            Err(refusal) => Class::TerminalRefusal(refusal),
            Ok(Verdict::Pass(_)) => Class::Pass,
            Ok(Verdict::Violation(violation)) if EXHAUSTION.contains(&violation.rule) => {
                Class::ProgressExhausted(violation.obligation, violation.rule)
            }
            Ok(Verdict::Violation(violation)) => {
                Class::Safety(violation.obligation, violation.rule)
            }
            Ok(Verdict::Inconclusive(inconclusive)) => Class::Incomplete(*inconclusive),
        }
    }

    /// Whether the run discharges `profile`'s gate: a pass activating every
    /// declared obligation, a clean generation gate and every declared
    /// witness fired.
    fn discharges(&self, profile: &Profile) -> bool {
        self.gate.is_ok()
            && profile.witnesses.iter().all(|w| self.fired.contains(w))
            && matches!(&self.verdict, Ok(verdict) if verdict.satisfies(profile.obligations))
    }
}

/// The progress and isolation rules a run breaks by exhausting a bound or
/// serving nothing. Every other rule, including an unmet premise of a
/// qualified checkpoint and a stopped owner's early return, is safety.
const EXHAUSTION: [&str; 4] = [
    "funded recovery exceeded its action bound",
    "a qualified funded interval produced no exact hit",
    "a healthy owner served no exact bytes",
    "a healthy owner starved past its fixture bound",
];

/// The key every qualified interval publishes; the oracle's key domain
/// stays within its bound across phases.
const QUALIFIED: u8 = 200;

const SITE: Site = Site {
    domain: Domain::Workload,
    actor: 0,
    site: 9,
};

/// Maintenance stages one full cycle visits.
const STAGES: usize = MaintainStage::Headroom as usize + 1;

fn budget() -> WorkBudget {
    WorkBudget::new(1 << 16)
}

fn action_bound(derived: &Derived) -> u32 {
    let slots = derived.slots as usize;
    (slots * slots + 2 * STAGES) as u32
}

/// One generated candidate: the action, its argument and a weight slot.
fn candidate(act: Act, arg: u8, slot: u8) -> Candidate {
    let mut bytes = [0; CANDIDATE_LEN];
    bytes[0] = Domain::Workload as u8;
    bytes[1] = act as u8;
    bytes[2] = arg;
    bytes[3] = slot;
    Candidate(bytes)
}

/// One key's object as this run credits it.
#[derive(Clone, Copy, Debug)]
struct Credit {
    label: Label,
    body: u64,
    /// The allocation the credited publication returned; `None` for a label
    /// credited before its publication.
    publication: Option<AllocationId>,
    /// An eviction since the credit may have removed it.
    evictable: bool,
}

struct Lease<'s> {
    key: u8,
    label: Label,
    body: u64,
    invalidated: bool,
    lease: ExtentLease<'s, TestPlatform>,
}

/// The state one phase's generation reads and changes.
struct Phase<'s, 'a> {
    profile: &'static Profile,
    credited: Vec<Option<Credit>>,
    fills: Vec<(u8, Label, u64, WritableFill<'s, 'a, TestPlatform>)>,
    leases: Vec<Lease<'s>>,
}

/// The engine and the run-wide state every phase shares.
struct Engine<'s, 'a> {
    /// Each step's observable result, compared across replay.
    trace: Vec<u8>,
    /// What the last generated step returned, for the trace.
    outcome: u8,
    storage: &'s Storage<TestPlatform>,
    device: Device<'s, 'a>,
    reader: crate::storage::Registration<'s, TestPlatform>,
    chooser: Chooser,
    incarnation: u32,
    next_label: u32,
    plant: Plant,
    gate: Result<(), &'static str>,
    fired: Vec<Witness>,
    derived: Derived,
}

fn content(key: u8, label: Label, body: u64) -> Vec<u8> {
    Recorder::content(KeyId(key), label, 0, body)
}

impl<'s, 'a> Engine<'s, 'a> {
    fn fire(&mut self, witness: Witness) {
        if !self.fired.contains(&witness) {
            self.fired.push(witness);
        }
    }

    fn fail(&mut self, rule: &'static str) {
        if self.gate.is_ok() {
            self.gate = Err(rule);
        }
    }

    fn resident(&self) -> u64 {
        let units = self.derived.units - self.derived.low_units;
        (units * crate::storage::IO_UNIT as u64).saturating_sub(HEADER_SLACK as u64)
    }

    fn candidates(&self, phase: &Phase<'s, 'a>) -> Vec<(Candidate, Act, u8)> {
        let profile = phase.profile;
        let key_slots = |k: u8| if k == 0 { profile.hot } else { 1 };
        let mut out = Vec::new();
        let mut add = |act: Act, arg: u8, slots: u8| {
            let weight = profile.weights[act as usize - 1];
            for slot in 0..weight * slots {
                out.push((candidate(act, arg, slot), act, arg));
            }
        };
        for k in 0..profile.keys {
            if phase.fills.iter().all(|f| f.0 != k) && phase.fills.len() < 2 {
                add(Act::Fill, k, key_slots(k));
            }
            let held = phase.leases.iter().filter(|l| l.key == k).count();
            if held < 4 && phase.leases.len() < 8 {
                add(Act::Acquire, k, key_slots(k));
            }
            add(Act::Invalidate, k, 1);
        }
        for i in 0..phase.fills.len() {
            add(Act::Publish, i as u8, 1);
        }
        for i in 0..phase.leases.len() {
            add(Act::Read, i as u8, 1);
            add(Act::Release, i as u8, 1);
        }
        add(Act::Maintain, 0, 1);
        out.sort_by_key(|entry| entry.0);
        out
    }

    fn step(&mut self, phase: &mut Phase<'s, 'a>) {
        self.outcome = 0;
        let candidates = self.candidates(phase);
        let set: Vec<Candidate> = candidates.iter().map(|entry| entry.0).collect();
        let at = self
            .chooser
            .index(SITE, self.incarnation, &set)
            .expect("a recorded draw");
        let (_, act, arg) = candidates[at];
        match act {
            Act::Fill => self.fill(phase, arg),
            Act::Publish => self.publish(phase, usize::from(arg)),
            Act::Acquire => self.acquire(phase, arg),
            Act::Read => self.read(phase, usize::from(arg)),
            Act::Release => drop(phase.leases.remove(usize::from(arg))),
            Act::Invalidate => {
                let acknowledged = if self.plant == Plant::RefuseInvalidate {
                    self.storage
                        .invalidate(&key(arg), 2, &mut WorkBudget::new(0))
                } else {
                    invalidate(self.storage, &key(arg))
                };
                if acknowledged.is_ok() {
                    phase.credited[usize::from(arg)] = None;
                    for lease in phase.leases.iter_mut().filter(|l| l.key == arg) {
                        lease.invalidated = true;
                    }
                } else {
                    self.outcome = 3;
                }
            }
            Act::Maintain => {
                if let Ok(Maintained::Open(report)) = self.storage.maintain(&mut budget())
                    && report.evicted > 0
                {
                    self.fire(Witness::Eviction);
                    for credit in phase.credited.iter_mut().flatten() {
                        credit.evictable = true;
                    }
                }
            }
        }
        self.observe(phase, act, arg);
    }

    /// Appends what step `act` on `arg` left to the run's semantic trace:
    /// the held leases and fills, each credited label and the storage's
    /// free units and slots.
    fn observe(&mut self, phase: &Phase<'s, 'a>, act: Act, arg: u8) {
        let domain = self.storage.domain_report().expect("a report");
        self.trace.extend([
            self.outcome,
            act as u8,
            arg,
            phase.leases.len() as u8,
            phase.fills.len() as u8,
        ]);
        self.trace.extend(
            phase
                .credited
                .iter()
                .flat_map(|credit| credit.map_or(0, |c| c.label.0).to_le_bytes()),
        );
        self.trace.extend(domain.free_units.to_le_bytes());
        self.trace.extend((domain.free_slots as u32).to_le_bytes());
    }

    fn fill(&mut self, phase: &mut Phase<'s, 'a>, k: u8) {
        let (low, high) = phase.profile.sizes;
        let span = u64::from(high - low) + 1;
        let drawn = self
            .chooser
            .bounded(SITE, self.incarnation, span)
            .expect("a recorded size");
        let body = (u64::from(low) + drawn).min(self.derived.body_cap);
        let label = Label(u64::from(self.next_label));
        self.next_label += 1;
        match self.reserve(k, body) {
            Some(mut fill) => {
                self.device.fill(&mut fill, &content(k, label, body));
                if self.plant == Plant::CreditUnpublished {
                    phase.credited[usize::from(k)] = Some(Credit {
                        label,
                        body,
                        publication: None,
                        evictable: false,
                    });
                }
                phase.fills.push((k, label, body, fill));
            }
            None => self.fire(Witness::PressureRefusal),
        }
    }

    fn reserve(&mut self, k: u8, body: u64) -> Option<WritableFill<'s, 'a, TestPlatform>> {
        let attempt = self
            .storage
            .begin_fill(&key(k), crate::storage::CacheVersion(0), 2, &mut budget())
            .ok()?;
        let Decision::Admit(admitted) = self.storage.decide_admission(Some(0), Some(body as usize))
        else {
            return None;
        };
        attempt
            .reserve_storage(admitted, Some(0), Some(body as usize), 2, &mut budget())
            .ok()
    }

    fn publish(&mut self, phase: &mut Phase<'s, 'a>, at: usize) {
        let (k, label, body, fill) = phase.fills.remove(at);
        let published = fill.publish(&mut self.device.volume, u64::MAX, 2, &mut budget());
        let _ = self
            .storage
            .service_fills(crate::index::ShardIndex(0), 2, &mut budget());
        if let Ok(lease) = published {
            let publication = Some(lease.id());
            drop(lease);
            let replaced = phase.credited[usize::from(k)].is_some();
            let incumbent = phase.credited[usize::from(k)].is_some_and(|credit| !credit.evictable);
            if incumbent && self.plant != Plant::CreditUnpublished {
                self.fire(Witness::Replacement);
            }
            if replaced && self.plant == Plant::CreditStale {
                return;
            }
            phase.credited[usize::from(k)] = Some(Credit {
                label,
                body,
                publication,
                evictable: self.plant == Plant::EvictableCredits,
            });
        }
    }

    fn acquire(&mut self, phase: &mut Phase<'s, 'a>, k: u8) {
        let found = self
            .reader
            .lookup(&key(k), phase.profile.retries, &mut budget());
        let credit = phase.credited[usize::from(k)];
        self.outcome = match &found {
            Ok(_) => 1,
            Err(crate::storage::LookupError::Missing) => 2,
            Err(_) => 3,
        };
        let visible = credit.is_some_and(|credit| !credit.evictable);
        let lease = match found {
            Ok(lease) => lease,
            Err(crate::storage::LookupError::Missing) => {
                if visible {
                    self.fail("a credited publication was not visible");
                }
                return;
            }
            Err(_) => {
                if visible {
                    self.fail("a credited publication's lookup was refused");
                }
                return;
            }
        };
        let Some(Credit {
            label,
            body,
            publication,
            ..
        }) = credit
        else {
            self.fail("a lookup hit a key with no credited publication");
            return;
        };
        if publication != Some(lease.id()) {
            self.fail("a lookup hit a publication other than its credited one");
            return;
        }
        if k == 0 && phase.leases.iter().any(|l| l.key == 0) {
            self.fire(Witness::HotKeyShared);
        }
        phase.leases.push(Lease {
            key: k,
            label,
            body,
            invalidated: false,
            lease,
        });
    }

    fn read(&mut self, phase: &mut Phase<'s, 'a>, at: usize) {
        let lease = &phase.leases[at];
        let bytes = self.device.read(&lease.lease);
        let exact = bytes == content(lease.key, lease.label, lease.body);
        self.outcome = if exact { 4 } else { 5 };
        if !exact {
            self.fail("a read returned bytes other than its credited label's");
            return;
        }
        if lease.invalidated {
            self.fire(Witness::HeldAcrossInvalidation);
        } else {
            self.fire(Witness::PublishedBeforeAcquire);
        }
    }

    /// Ends `phase` with a funded healthy interval recorded on `rec`, under
    /// key [`QUALIFIED`]: holders return, then funded maintenance and the
    /// qualified publication's attempts count against the configuration's
    /// action bound, and a lookup of the publication must hit and read back
    /// exactly.
    fn qualify(
        &mut self,
        phase: Phase<'s, 'a>,
        rec: &mut Recorder,
    ) -> Result<Vec<Option<Credit>>, &'static str> {
        let Phase {
            profile,
            mut leases,
            fills,
            mut credited,
            ..
        } = phase;
        if self.plant == Plant::Retention && leases.is_empty() {
            for (k, credit) in credited.iter().enumerate() {
                let Some(Credit { label, body, .. }) = *credit else {
                    continue;
                };
                if let Ok(lease) = self
                    .reader
                    .lookup(&key(k as u8), profile.retries, &mut budget())
                {
                    leases.push(Lease {
                        key: k as u8,
                        label,
                        body,
                        invalidated: false,
                        lease,
                    });
                    break;
                }
            }
        }
        for credit in 0..leases.len() {
            rec.take(
                (ResourceKind::Credit, credit as u32, 0),
                Custodian::Reader,
                None,
            );
        }
        let kept = (self.plant == Plant::Retention && !leases.is_empty()).then(|| leases.remove(0));
        for credit in usize::from(kept.is_some())..leases.len() + usize::from(kept.is_some()) {
            rec.release((ResourceKind::Credit, credit as u32, 0), Custodian::Reader);
        }
        drop(leases);
        for (.., fill) in fills {
            fill.abort();
        }
        let credits = self
            .storage
            .lease_report()
            .map_or(ReportState::Absent, |report| {
                ReportState::Value(report.reserved as u64)
            });
        rec.report(ResourceKind::Credit, ReportKind::Ledger, credits);
        let limit = action_bound(&self.derived);
        let mut funded = 0;
        let body = self.qualified_body();
        let need = self.derived.record_units;
        let maintain = |engine: &mut Self, credited: &mut Vec<Option<Credit>>, funded: &mut u32| {
            *funded += 1;
            // The ticks settle the volume's commands before maintenance returns its retirements.
            engine.device.tick_journal(4);
            if let Ok(Maintained::Open(report)) = engine.storage.maintain(&mut budget())
                && report.evicted > 0
            {
                for credit in credited.iter_mut().flatten() {
                    credit.evictable = true;
                }
            }
        };
        while funded < limit {
            let domain = self.storage.domain_report().expect("a report");
            if domain.claimable_units >= need && domain.free_slots > 0 {
                break;
            }
            maintain(self, &mut credited, &mut funded);
        }
        if self.plant == Plant::CloseBeforeQualified {
            self.storage.close();
        }
        let label = Label(u64::from(self.next_label));
        self.next_label += 1;
        let bytes = content(QUALIFIED, label, body);
        let (mut published, mut written) = (None, None);
        let mut attempts = 0;
        while published.is_none() && funded <= limit && !self.storage.is_closed() {
            funded += 1;
            let refused = matches!(self.plant, Plant::RefuseQualified(n) if attempts < n);
            attempts += 1;
            let reserved = (!refused).then(|| self.reserve(QUALIFIED, body)).flatten();
            if let Some(mut fill) = reserved {
                self.device.fill(&mut fill, &bytes);
                let serial = fill.serial();
                if let Ok(lease) = fill.publish(&mut self.device.volume, u64::MAX, 2, &mut budget())
                {
                    published = Some(lease.id());
                    written = Some(written_commands(
                        self.device.volume.bound_tokens(),
                        &self.device.control.capture(),
                        serial,
                    ));
                    break;
                }
            }
            maintain(self, &mut credited, &mut funded);
        }
        rec.checkpoint(Checkpoint::Qualified { funded, limit });
        let qualified = KeyId(QUALIFIED);
        if self.storage.is_closed() && published.is_none() {
            drop(kept);
            return Err("admission closed before the qualified publication");
        }
        if let Some(id) = published {
            if self.plant == Plant::RepublishQualified
                && let Some(mut fill) = self.reserve(QUALIFIED, body)
            {
                self.device.fill(&mut fill, &bytes);
                let _ = fill.publish(&mut self.device.volume, u64::MAX, 2, &mut budget());
            }
            let identity = (self.device.volume.session(), id.record_tag());
            rec.published_written(
                qualified,
                label,
                0,
                &bytes,
                identity,
                Some(written.take().expect("the qualified fill's write evidence")),
            );
            if self.plant == Plant::SkipLookup {
                drop(kept);
                return Ok(credited);
            }
            if let Ok(lease) = self
                .reader
                .lookup(&key(QUALIFIED), profile.retries, &mut budget())
            {
                if lease.id() != id {
                    self.fail("a qualified lookup hit a publication other than the qualified one");
                }
                let read = rec.lookup(qualified, Outcome::Hit, Some(label));
                let delivered = crate::storage::owner_fixture::read_back(
                    &mut self.device.volume,
                    &self.device.control,
                    &lease,
                );
                assert_eq!(delivered.status, crate::storage::ReadStatus::Complete);
                let info = delivered.info.expect("a complete read verified its header");
                rec.delivered(
                    read,
                    (qualified, label),
                    (0, body),
                    (info.identity().session, info.identity().allocation),
                    Outcome::Complete,
                    delivered.bytes,
                );
                drop(kept);
                return Ok(credited);
            }
        }
        rec.lookup(qualified, Outcome::Missing, None);
        drop(kept);
        Ok(credited)
    }

    /// Looks up the previous phase's qualified publication at the start of
    /// a later phase: on the engine that published it, it is still visible.
    fn carried_over(&mut self, label: Label) {
        match self.reader.lookup(&key(QUALIFIED), 4, &mut budget()) {
            Ok(lease)
                if self.device.read(&lease) == content(QUALIFIED, label, self.qualified_body()) =>
            {
                self.fire(Witness::PhaseAccumulated);
            }
            _ => self.fail("a phase ran on an engine without the previous phase's publication"),
        }
    }

    fn qualified_body(&self) -> u64 {
        self.derived.body_cap.min(self.resident()).min(4_000)
    }
}

/// Runs `admitted` from `chooser` with `plant`, phase by phase, on one
/// engine unless the plant rebuilds it. Each phase is its own oracle
/// episode, and the run's verdict is the first phase verdict that is not a
/// pass, or the last pass.
fn run(admitted: &Admitted, chooser: Chooser, plant: Plant) -> Run {
    if admitted.profile.faults == FaultClass::UnprovenStop {
        let tape = chooser.finish().expect("a tape");
        let arena_a = arena(&admitted.derived);
        let run = Run {
            tape,
            ..isolated(admitted, plant, &arena_a)
        };
        assert!(
            arena_a.release().is_err(),
            "the stopped owner's arena stays held"
        );
        return run;
    }
    let phases = admitted
        .profile
        .workloads()
        .expect("an admitted profile's phases");
    let mut chooser = Some(chooser);
    let mut gate = Ok(());
    let mut fired = Vec::new();
    let mut verdict: Result<Verdict, &'static str> = Err("no phase ran");
    let mut rows = Vec::new();
    let mut labels = 1;
    let mut carried: Vec<Option<Credit>> = Vec::new();
    let mut last_qualified: Option<Label> = None;
    let mut trace = Vec::new();
    let rebuild = plant == Plant::RebuildEngine;
    let mut phase_at = 0;
    while phase_at < phases.len() {
        let mut storage = storage(&admitted.derived);
        storage.install_hasher(crate::index::KeyHasher::with_key_pair(
            admitted.root,
            admitted.root.rotate_left(32),
        ));
        let arena = arena(&admitted.derived);
        let (volume, control) = attach_shaped(
            &storage,
            &arena,
            super::coverage_tests::table_depth(&admitted.derived),
            admitted.derived.span as u32,
        )
        .expect("an admitted configuration attaches");
        let reader = storage.register().expect("a registration");
        let mut taken = chooser.take().expect("one chooser");
        let incarnation = taken.launch(0);
        let mut engine = Engine {
            storage: &storage,
            device: Device { volume, control },
            reader,
            chooser: taken,
            incarnation,
            next_label: labels,
            plant,
            gate: Ok(()),
            fired: Vec::new(),
            derived: admitted.derived,
            trace: Vec::new(),
            outcome: 0,
        };
        let phases_here = if rebuild { 1 } else { phases.len() };
        for _ in 0..phases_here {
            let workload = phases[phase_at];
            if let Some(label) = last_qualified {
                engine.carried_over(label);
            }
            carried.resize(carried.len().max(usize::from(workload.keys)), None);
            let mut phase = Phase {
                profile: workload,
                credited: std::mem::take(&mut carried),
                fills: Vec::new(),
                leases: Vec::new(),
            };
            for _ in 0..workload.steps {
                engine.step(&mut phase);
            }
            let mut rec = Recorder::new(phase_at as u16 + 1);
            let qualified = engine.qualify(phase, &mut rec);
            rec.checkpoint(Checkpoint::Stopped);
            rows.extend_from_slice(rec.rows());
            let history = if plant == Plant::Unsealed {
                rec.unsealed()
            } else {
                rec.finish()
            };
            let judged = match qualified {
                Ok(credited) => {
                    carried = credited;
                    Ok(check(&history))
                }
                Err(refusal) => Err(refusal),
            };
            last_qualified = matches!(judged, Ok(Verdict::Pass(_)))
                .then(|| Label(u64::from(engine.next_label - 1)));
            if phase_at == 0 || matches!(verdict, Ok(Verdict::Pass(_))) {
                verdict = judged;
            }
            phase_at += 1;
        }
        labels = engine.next_label;
        if gate.is_ok() {
            gate = engine.gate;
        }
        for witness in engine.fired {
            if !fired.contains(&witness) {
                fired.push(witness);
            }
        }
        trace.extend(engine.trace);
        chooser = Some(engine.chooser);
    }
    let tape = chooser
        .take()
        .expect("the chooser")
        .finish()
        .expect("a tape");
    Run {
        tape,
        verdict,
        gate,
        fired,
        rows,
        trace,
    }
}

/// An owner over `storage` and `arena`, attached at `derived`'s depth and
/// span, serving `object` under key 1 to one peer per link of `ends`.
fn owner_over<'s, 'a, 'm>(
    derived: &Derived,
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    receive: &'m super::packet::PacketPool<'a>,
    object: &[u8],
    ends: Vec<LinkEnd<'a>>,
) -> (TestOwner<'s, 'a, 'm>, SimControl) {
    let (volume, control) = attach_shaped(
        storage,
        arena,
        super::coverage_tests::table_depth(derived),
        derived.span as u32,
    )
    .expect("an admitted configuration attaches");
    let mut device = Device { volume, control };
    crate::storage::owner_fixture::publish(storage, &mut device, &key(1), 0, object);
    let Device { volume, control } = device;
    let cache = storage.issue_cache().expect("a cache");
    let registration = cache.register().expect("a registration");
    let entries = entries();
    let peers = ends.len();
    let keys = Keys {
        principals: &PRINCIPALS[..peers],
        entries: &entries[..peers],
        epoch: 1,
        put: &PRINCIPALS[..1],
    };
    let mut config = owner_config(derived, storage.maintain_minimum());
    config.peer_requests = config.request_slots / peers as u32;
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    let owner = Owner::start(
        config,
        bundle,
        keys,
        Mux::new(ends),
        receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .expect("an admitted configuration starts");
    (owner, control)
}

const HELD: KeyId = KeyId(0);
const SERVED: KeyId = KeyId(1);
const HELD_LABEL: Label = Label(2);
const SERVED_LABEL: Label = Label(1);

/// The isolated profile: owner A holds a read at an unproven stop while
/// owner B, of the same configuration, must serve its exact object within
/// the profile's turn bound. Afterwards A's request and submitted reads
/// keep their pre-stop values, its read buffers keep the custody breakdown
/// the stop left them in, and A's shutdown refuses release while its stop
/// is unproven. A's buffers come from `arena_a`, which the caller finds
/// still held afterwards.
fn isolated(admitted: &Admitted, plant: Plant, arena_a: &BufferArena<TestPlatform>) -> Run {
    let profile = admitted.profile;
    let derived = admitted.derived;
    let body = u64::from(profile.sizes.0).min(derived.body_cap);
    let held_object = Recorder::content(HELD, HELD_LABEL, 0, body);
    let served_object = Recorder::content(SERVED, SERVED_LABEL, 0, body);
    let (client_pool, receive_a, receive_b) = (pool(), pool(), pool());
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).expect("a board"),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).expect("a board"),
    ];
    let storage_a = storage(&derived);
    let (storage_b, arena_b) = (storage(&derived), arena(&derived));
    let seed = |n: u64| admitted.root.wrapping_mul(3).wrapping_add(n);
    let (client_end_a, owner_end_a, net_a) = network(64, 8384, seed(1), [Faults::default(); 2]);
    let (client_end_b, owner_end_b, net_b) = network(64, 8384, seed(2), [Faults::default(); 2]);
    let (_spare_client, spare_end, _spare_net) = network(64, 8384, seed(3), [Faults::default(); 2]);
    let routed = plant == Plant::StarvePeer;
    let (ends_a, ends_b) = if routed {
        (vec![owner_end_a, owner_end_b], vec![spare_end])
    } else {
        (vec![owner_end_a], vec![owner_end_b])
    };
    let (mut owner_a, control_a) = owner_over(
        &derived,
        &storage_a,
        arena_a,
        &receive_a,
        &held_object,
        ends_a,
    );
    let mut stored_b = served_object.clone();
    if plant == Plant::CorruptServed {
        stored_b[0] ^= 1;
    }
    let (mut owner_b, control_b) = owner_over(
        &derived, &storage_b, &arena_b, &receive_b, &stored_b, ends_b,
    );
    let mut client_a = super::owner_tests::sourced_client(
        0,
        &client_pool,
        &releases[0],
        client_end_a,
        Box::default(),
        super::auth::os_entropy,
    );
    let mut client_b = client(
        usize::from(routed),
        &client_pool,
        &releases[1],
        client_end_b,
    );
    let mut turn = open(
        &mut client_a,
        &mut owner_a,
        &control_a,
        std::slice::from_ref(&net_a),
        0,
    );
    turn = if routed {
        let nets = [net_a.clone(), net_b.clone()];
        open(&mut client_b, &mut owner_a, &control_a, &nets, turn)
    } else {
        open(
            &mut client_b,
            &mut owner_b,
            &control_b,
            std::slice::from_ref(&net_b),
            turn,
        )
    };
    let mut rec = Recorder::new(1);
    let held_written = Some(
        fills_written(&owner_a, &control_a)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(HELD, HELD_LABEL, 0, &held_object, ID, held_written);
    let served_written = Some(
        fills_written(&owner_b, &control_b)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(SERVED, SERVED_LABEL, 0, &served_object, ID, served_written);
    let held = client_a
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .expect("an admitted GET");
    let (_token, at) = hold_next_read(&mut client_a, &mut owner_a, &control_a, &net_a, turn);
    turn = at;
    rec.take(share(0), Custodian::Storage, None);
    shares(&mut rec, &[&owner_a, &owner_b]);
    let accounts_a = |owner: &TestOwner<'_, '_, '_>| {
        (
            owner.census().live(),
            arena_a.report(crate::storage::PoolKind::ReadResponse),
            owner.volume_report().reads_submitted,
        )
    };
    let busy =
        |report: &crate::storage::BufferPoolReport| report.count - report.free - report.retired;
    let before = accounts_a(&owner_a);
    control_a.set_quiesce(QuiesceMode::Unproven);
    let _ = owner_a.close(turn * 100);
    let commands = control_a.outstanding();
    // A's post-stop custody breakdown is the baseline while B serves.
    let stopped = accounts_a(&owner_a);
    assert_eq!(
        busy(&stopped.1),
        busy(&before.1),
        "the stop keeps its buffer"
    );
    assert_eq!(stopped.2, before.2, "the stop keeps its submitted reads");
    rec.isolated(share(0));
    if plant == Plant::ReturnStopped {
        rec.release(share(0), Custodian::Storage);
    }
    let id = client_b
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .expect("an admitted GET");
    if !routed {
        rec.take(share(1), Custodian::Storage, None);
    }
    let began = turn;
    let mut bytes = Vec::new();
    while turn < began + u64::from(profile.turns) {
        round::round(&mut [
            round::Act::new(Actor::Link(0), &mut || net_a.borrow_mut().advance(turn)),
            round::Act::new(Actor::Link(1), &mut || net_b.borrow_mut().advance(turn)),
            round::Act::new(Actor::Client(0), &mut || {
                let _ = client_a.poll(turn * 100);
            }),
            round::Act::new(Actor::Client(1), &mut || {
                let _ = client_b.poll(turn * 100);
            }),
            round::Act::new(Actor::Disk(0), &mut || control_a.tick(64)),
            round::Act::new(Actor::Owner(0), &mut || owner_a.poll(turn * 100)),
            round::Act::new(Actor::Disk(1), &mut || control_b.tick(64)),
            round::Act::new(Actor::Owner(1), &mut || owner_b.poll(turn * 100)),
        ]);
        turn += 1;
        collect(&mut client_b, id, &mut bytes);
        assert_eq!(
            accounts_a(&owner_a).0,
            before.0,
            "the stopped owner keeps its request"
        );
        if client_b.outcome(id).is_some() {
            break;
        }
    }
    let turns = (turn - began) as u32;
    rec.checkpoint(Checkpoint::Healthy {
        turns,
        bound: profile.turns,
    });
    let mut trace = turns.to_le_bytes().to_vec();
    for net in [&net_a, &net_b] {
        for side in 0..2 {
            trace.extend(net.borrow().report(side).delayed.to_le_bytes());
        }
    }
    let mut fired = Vec::new();
    if client_b.outcome(id) == Some(Fetched::Complete) {
        if bytes == served_object {
            fired.push(Witness::IsolatedServe);
        }
        served(&mut rec, &storage_b, (SERVED, SERVED_LABEL), bytes);
        for _ in 0..2_000 {
            if owner_b.census().live() == 0 {
                break;
            }
            round::round(&mut [
                round::Act::new(Actor::Link(1), &mut || net_b.borrow_mut().advance(turn)),
                round::Act::new(Actor::Client(1), &mut || {
                    let _ = client_b.poll(turn * 100);
                }),
                round::Act::new(Actor::Disk(1), &mut || control_b.tick(64)),
                round::Act::new(Actor::Owner(1), &mut || owner_b.poll(turn * 100)),
            ]);
            turn += 1;
        }
        rec.release(share(1), Custodian::Storage);
    }
    shares(&mut rec, &[&owner_a, &owner_b]);
    assert_eq!(
        accounts_a(&owner_a),
        stopped,
        "the stopped owner's accounts at their stop"
    );
    assert_eq!(client_a.outcome(held), None, "the held GET still waits");
    assert_eq!(
        control_a.outstanding(),
        commands,
        "the stopped owner keeps its device commands"
    );
    rec.checkpoint(Checkpoint::Stopped);
    let (owner_a, blocked) = *owner_a
        .shutdown()
        .err()
        .expect("an unproven stop blocks the release");
    assert_eq!(blocked.census.live(), before.0);
    drop(owner_a);
    let rows = rec.rows().to_vec();
    Run {
        tape: Vec::new(),
        verdict: Ok(check(&Recorder::rebuilt(rows.clone()))),
        gate: Ok(()),
        fired,
        rows,
        trace,
    }
}

fn sites() -> Vec<Site> {
    vec![SITE]
}

pub(super) fn launched(name: &str, plant: Plant) -> (Admitted, Run) {
    let manifest = manifest_for(name, 0x5EED);
    let admitted = admit(&manifest).expect("an admitted profile");
    let run = run(&admitted, Chooser::record(admitted.root, &sites()), plant);
    (admitted, run)
}

#[test]
fn every_profile_admits_runs_and_discharges_its_declared_obligations() {
    for profile in &PROFILES {
        let (admitted, run) = launched(profile.name, Plant::None);
        assert_eq!(run.gate, Ok(()), "{}", profile.name);
        assert_eq!(
            run.class(),
            Class::Pass,
            "{}: {:?}",
            profile.name,
            run.verdict
        );
        for witness in profile.witnesses {
            assert!(
                run.fired.contains(witness),
                "{}: {witness:?} never fired",
                profile.name
            );
        }
        assert!(run.discharges(admitted.profile), "{}", profile.name);
        let row = rows()[profile.row];
        assert_eq!(
            FACTORS[FAULTS].1[row[FAULTS]], "healthy",
            "{}",
            profile.name
        );
    }
}

#[test]
fn admission_refuses_an_empty_mask_a_missing_action_and_an_invalid_configuration() {
    static EMPTY: Profile = Profile {
        weights: [0; 7],
        ..PROFILES[1]
    };
    static UNREAD: Profile = Profile {
        weights: [3, 3, 3, 0, 3, 0, 1],
        ..PROFILES[1]
    };
    static EMPTY_PHASE: Profile = Profile {
        phases: &["healthy", "unknown-phase"],
        ..PROFILES[6]
    };
    let row = rows()[PROFILES[1].row];
    assert!(matches!(
        admit_profile(&EMPTY, row, 1),
        Err(Refusal::EmptyMask)
    ));
    assert!(matches!(
        admit_profile(&UNREAD, row, 1),
        Err(Refusal::MissingAction(Obligation::Progress, Act::Read))
    ));
    let mut wide_chunk = row;
    wide_chunk[CHUNK] = CHUNK_16K;
    wide_chunk[SPAN] = SPAN_8K;
    let Err(Refusal::Configuration(violations)) = admit_profile(&PROFILES[1], wide_chunk, 1) else {
        panic!("the chunk longer than the span is refused");
    };
    assert!(
        violations.contains(&"span at least a fragment and a chunk"),
        "{violations:?}"
    );
    assert!(matches!(
        admit(&manifest_for("unknown", 1)),
        Err(Refusal::UnknownProfile)
    ));
    assert!(matches!(
        admit_profile(&EMPTY_PHASE, row, 1),
        Err(Refusal::UnknownPhase)
    ));
}

#[test]
fn the_record_and_the_run_are_equal_across_a_replay_of_the_tape() {
    for profile in &PROFILES {
        // Each compared run restarts the fixture sessions, so both attach under the same session.
        let (admitted, first) = afresh(|| {
            let _sessions = crate::storage::restart_sessions();
            launched(profile.name, Plant::None)
        });
        let again = afresh(|| {
            let _sessions = crate::storage::restart_sessions();
            run(
                &admitted,
                Chooser::replay(&sites(), first.tape.clone()),
                Plant::None,
            )
        });
        assert_eq!(again.trace, first.trace, "{}", profile.name);
        assert_eq!(again.rows, first.rows, "{}", profile.name);
        assert_eq!(again.fired, first.fired, "{}", profile.name);
        assert_eq!(again.gate, first.gate, "{}", profile.name);
        assert_eq!(again.class(), first.class(), "{}", profile.name);
        let other = run(
            &admit_profile(admitted.profile, rows()[profile.row], admitted.root + 1)
                .expect("admitted"),
            Chooser::record(admitted.root + 1, &sites()),
            Plant::None,
        );
        if profile.faults != FaultClass::UnprovenStop {
            assert_ne!(
                other.trace, first.trace,
                "{}: the root drives the generated steps",
                profile.name
            );
        }
    }
    let records: Vec<Vec<u8>> = PROFILES.iter().map(|profile| profile.record(1)).collect();
    for (at, record) in records.iter().enumerate() {
        assert!(!records[..at].contains(record), "{}", PROFILES[at].name);
    }
    let healthy = PROFILES[1].record(1);
    assert_ne!(PROFILES[1].record(2), healthy);
    let variants = [
        Profile {
            row: 10,
            ..PROFILES[1]
        },
        Profile {
            weights: [3, 3, 3, 3, 3, 1, 1],
            ..PROFILES[1]
        },
        Profile {
            keys: 5,
            ..PROFILES[1]
        },
        Profile {
            hot: 2,
            ..PROFILES[1]
        },
        Profile {
            sizes: (1, 201),
            ..PROFILES[1]
        },
        Profile {
            faults: FaultClass::UnprovenStop,
            ..PROFILES[1]
        },
        Profile {
            steps: 201,
            ..PROFILES[1]
        },
        Profile {
            retries: 5,
            ..PROFILES[1]
        },
        Profile {
            turns: 1,
            ..PROFILES[1]
        },
        Profile {
            obligations: &[Obligation::Progress],
            ..PROFILES[1]
        },
        Profile {
            witnesses: &[],
            ..PROFILES[1]
        },
        Profile {
            phases: &["hot-key"],
            ..PROFILES[1]
        },
    ];
    let mut seen = vec![healthy];
    for variant in &variants {
        let record = variant.record(1);
        assert!(!seen.contains(&record), "{variant:?}");
        seen.push(record);
    }
}

#[test]
fn crediting_an_unpublished_fill_or_rebuilding_the_engine_fails_the_generation_gate() {
    let (admitted, credited) = launched("correlated", Plant::CreditUnpublished);
    assert_eq!(credited.gate, Err("a credited publication was not visible"));
    assert!(!credited.discharges(admitted.profile));
    let (admitted, rebuilt) = launched("persistent-owner", Plant::RebuildEngine);
    assert_eq!(
        rebuilt.class(),
        Class::Pass,
        "every rebuilt phase still qualifies"
    );
    assert_eq!(
        rebuilt.gate,
        Err("a phase ran on an engine without the previous phase's publication")
    );
    assert!(!rebuilt.fired.contains(&Witness::PhaseAccumulated));
    assert!(!rebuilt.discharges(admitted.profile));
}

#[test]
fn a_stale_credit_fails_at_its_hit_even_when_the_lease_is_never_read() {
    static UNREAD: Profile = Profile {
        name: "correlated-unread",
        weights: [2, 2, 3, 0, 3, 1, 0],
        ..PROFILES[5]
    };
    let row = rows()[UNREAD.row];
    assert!(matches!(
        admit_profile(&UNREAD, row, 0x5EED),
        Err(Refusal::MissingAction(Obligation::Progress, Act::Read))
    ));
    let unread = Admitted {
        profile: &UNREAD,
        derived: Derived::of(&row),
        root: 0x5EED,
    };
    let record = || Chooser::record(unread.root, &sites());
    assert_eq!(run(&unread, record(), Plant::None).gate, Ok(()));
    let stale = run(&unread, record(), Plant::CreditStale);
    assert_eq!(
        stale.gate,
        Err("a lookup hit a publication other than its credited one"),
        "{:?}",
        stale.fired
    );
    let (admitted, read) = launched("correlated", Plant::CreditStale);
    assert_eq!(
        read.gate,
        Err("a lookup hit a publication other than its credited one")
    );
    assert!(!read.discharges(admitted.profile));
}

#[test]
fn a_qualified_hit_on_another_allocation_holding_the_qualified_bytes_fails_the_gate() {
    let (admitted, republished) = launched("healthy", Plant::RepublishQualified);
    // The delivery records the identity the verified header carries, so the oracle sees the other allocation too.
    assert_eq!(
        republished.class(),
        Class::Safety(
            Obligation::Bytes,
            "delivered identity differs from the acquired content"
        ),
        "{:?}",
        republished.verdict
    );
    assert_eq!(
        republished.gate,
        Err("a qualified lookup hit a publication other than the qualified one")
    );
    assert!(!republished.discharges(admitted.profile));
}

#[test]
fn a_refused_invalidation_leaves_the_credits_and_the_held_leases_unchanged() {
    let (admitted, refused) = launched("correlated", Plant::RefuseInvalidate);
    assert_eq!(refused.gate, Ok(()), "{:?}", refused.fired);
    assert!(
        !refused.fired.contains(&Witness::HeldAcrossInvalidation),
        "no invalidation happened: {:?}",
        refused.fired
    );
    assert!(!refused.discharges(admitted.profile));
}

#[test]
fn a_publication_over_an_evictable_credit_fires_no_replacement() {
    let (admitted, evicted) = launched("correlated", Plant::EvictableCredits);
    assert_eq!(evicted.gate, Ok(()), "{:?}", evicted.fired);
    assert!(
        !evicted.fired.contains(&Witness::Replacement),
        "{:?}",
        evicted.fired
    );
    assert!(!evicted.discharges(admitted.profile));
}

#[test]
#[should_panic(expected = "a tape")]
fn an_isolated_replay_refuses_a_tape_with_trailing_input() {
    let admitted = admit(&manifest_for("isolated", 0x5EED)).expect("an admitted profile");
    let _ = run(&admitted, Chooser::replay(&sites(), vec![0]), Plant::None);
}

#[test]
fn always_miss_skip_lookup_and_retention_controls_fail_funded_progress() {
    let (admitted, missed) = launched("healthy", Plant::RefuseQualified(u32::MAX));
    assert_eq!(
        missed.class(),
        Class::ProgressExhausted(
            Obligation::Progress,
            "funded recovery exceeded its action bound"
        )
    );
    assert!(!missed.discharges(admitted.profile));
    let (admitted, retained) = launched("hot-key", Plant::Retention);
    assert_eq!(
        retained.class(),
        Class::Safety(
            Obligation::Progress,
            "a qualified checkpoint began with holders outstanding"
        )
    );
    assert!(!retained.discharges(admitted.profile));
    let (admitted, unread) = launched("healthy", Plant::SkipLookup);
    assert_eq!(
        unread.class(),
        Class::ProgressExhausted(
            Obligation::Progress,
            "a qualified funded interval produced no exact hit"
        )
    );
    assert!(!unread.discharges(admitted.profile));
}

#[test]
fn refused_qualified_attempts_and_their_maintenance_count_against_the_funded_bound() {
    let (admitted, retried) = launched("healthy", Plant::RefuseQualified(1));
    assert_eq!(retried.class(), Class::Pass, "{:?}", retried.verdict);
    assert!(retried.discharges(admitted.profile));
    // A maintenance call follows each refused attempt, so refusing just over
    // half the bound spends more actions than the bound allows.
    let refusals = action_bound(&admitted.derived) / 2 + 1;
    let (admitted, over) = launched("healthy", Plant::RefuseQualified(refusals));
    assert_eq!(
        over.class(),
        Class::ProgressExhausted(
            Obligation::Progress,
            "funded recovery exceeded its action bound"
        )
    );
    assert!(!over.discharges(admitted.profile));
}

#[test]
fn a_peer_routed_to_the_stopped_owner_and_a_returned_stopped_share_fail_isolation() {
    let (admitted, starved) = launched("isolated", Plant::StarvePeer);
    assert_eq!(
        starved.class(),
        Class::ProgressExhausted(
            Obligation::Isolation,
            "a healthy owner served no exact bytes"
        )
    );
    assert!(!starved.discharges(admitted.profile));
    let (admitted, returned) = launched("isolated", Plant::ReturnStopped);
    assert!(!returned.discharges(admitted.profile));
    assert_eq!(
        returned.class(),
        Class::Safety(
            Obligation::Isolation,
            "a failed owner returned custody its unproven stop retained"
        )
    );
}

#[test]
fn safety_progress_terminal_refusal_and_incomplete_verdicts_stay_distinct() {
    let (admitted, closed) = launched("healthy", Plant::CloseBeforeQualified);
    assert_eq!(
        closed.class(),
        Class::TerminalRefusal("admission closed before the qualified publication")
    );
    assert!(!closed.discharges(admitted.profile));
    let (_, unsealed) = launched("healthy", Plant::Unsealed);
    assert_eq!(unsealed.class(), Class::Incomplete(Inconclusive::Truncated));
    assert!(!unsealed.discharges(admitted.profile));
    let (_, passed) = launched("healthy", Plant::None);
    let mut corrupt = passed.rows.clone();
    let delivered = corrupt
        .iter_mut()
        .rfind(|row| row.payload.is_some() && row.kind == crate::oracle::ActionKind::Deliver)
        .expect("the qualified delivery");
    delivered.payload.as_mut().expect("bytes")[0] ^= 1;
    let safety = Run {
        verdict: Ok(check(&Recorder::rebuilt(corrupt))),
        ..passed
    };
    assert!(
        matches!(safety.class(), Class::Safety(Obligation::Bytes, _)),
        "{:?}",
        safety.class()
    );
    assert!(!safety.discharges(admitted.profile));
    let (admitted, corrupt_served) = launched("isolated", Plant::CorruptServed);
    assert!(
        matches!(corrupt_served.class(), Class::Safety(Obligation::Bytes, _)),
        "{:?}",
        corrupt_served.class()
    );
    assert!(!corrupt_served.discharges(admitted.profile));
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    always_miss_skip_lookup_and_retention_controls_fail_funded_progress,
    the_record_and_the_run_are_equal_across_a_replay_of_the_tape,
);
