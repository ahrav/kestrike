//! Four guarded metamorphic relations over settled pairs of mixed-world
//! runs: poll batching, schedule permutation, geometry scaling and
//! drain-suffix idempotence.
//!
//! Each side of a pair runs a named scenario through the bundle path, so
//! its bundle replays strictly, and leaves a [`Settled`] projection taken
//! at its last turn while the scene is alive: every bound record's key,
//! label, metadata and exact payload, the upload's and each read's outcome
//! and exact bytes, the first failure a check observed, the storage census
//! reconciled against the run's own geometry, and the certificate facts a
//! premise needs. A relation checks its premise certificate before it
//! compares: a failed premise is an unsupported comparison, neither a pass
//! nor a failure, so an invalid pair can earn no credit and raise no false
//! failure.
//!
//! - **Poll batching.** The owner's per-poll datagram batch differs and
//!   every other input is fixed: no link fault or withheld transmit, one
//!   writer, and slack that keeps the pair free of pressure outcomes,
//!   refused maintenance and eviction. Outcomes and exact ordered bytes
//!   must be equal.
//! - **Schedule permutation.** Two events enabled together at one time
//!   run in both orders. The certificate requires that both stayed enabled
//!   with the clock unmoved, that at most one client held a request, so no
//!   key order exists between the two, and that the pair's classes
//!   share no state or custody: client polls of distinct
//!   clients, each on its own link, or a client poll and the disk service
//!   call, which touches no link. Logical key, label and content must be
//!   equal.
//! - **Geometry scaling.** The storage's units, slots and chunk length
//!   differ; the work fits both with the same slack premises, which
//!   include no fingerprint collision. Per-key outcomes and bytes must be
//!   equal, and each run's census reconciles against its own geometry.
//! - **Drain-suffix idempotence.** Once the goal holds, mutation and time
//!   stand still: no workload action runs, holders are released, nothing
//!   is pending, paths are healed, and the suffix crosses no deadline, so
//!   no session, key epoch or client state changes and its span stays
//!   below the object lifetime while maintenance polls pass. Both runs
//!   share the prefix to the goal, and repeating the drain-only suffix
//!   leaves contents, outcomes and obligations equal; counters may
//!   advance. The suffix repeats drain events alone, since a recovery
//!   suffix that publishes would mutate the contents it compares.
//!
//! Every comparison also requires each side's checks to pass and its
//! census to reconcile: a failure on either side, shared or not, is a
//! difference.

use std::cell::RefCell;

use sha2::{Digest, Sha256};

use crate::oracle::Label;
use crate::sim::action::{ActionKind, Profile};
use crate::sim::choice::{Candidate, Chooser, Domain};
use crate::sim::manifest::Manifest;
use crate::sim::recovery::Recovery;
use crate::sim::trace::Recorder;
use crate::sim::turn::{End, Limits, Report, Turn};
use crate::storage::IO_UNIT;

use super::super::audit::Verdict;
use super::super::fetch::Outcome;
use super::super::observe::Failure;
use super::super::owner::OwnerReport;
use super::super::upload::UploadOutcome;
use super::bundle::{ACT, PUT, Stops, UploadState, admit, run_settled};
use super::{CLIENT_POLL, Geometry, Mixed, Plan, Plant, SERVICE, TTL_MS};

#[cfg(test)]
mod tests;

/// Turns a settled scenario keeps taking once its goal holds.
pub(super) const DRAIN: u32 = 32;

/// One bound record, or the check that refused it.
pub(super) type Bound = Result<Record, Failure>;

/// A bound record's key, the label the registry knows its content by, its
/// metadata bytes and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) key: [u8; 32],
    pub(super) label: Option<Label>,
    pub(super) metadata: u32,
    pub(super) payload: Vec<u8>,
}

/// What the drain suffix did to time-driven state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Suffix {
    /// Virtual microseconds from the goal's turn to the last turn.
    pub(super) span_us: u64,
    /// A session, key epoch or client state changed.
    pub(super) changed: bool,
}

/// What a run settled to, taken at its last turn.
#[derive(Debug, Clone)]
pub(super) struct Settled {
    pub(super) profile: Profile,
    pub(super) limits: Limits,
    pub(super) plan: Plan,
    pub(super) end: End,
    /// The turns applied before the goal first held, `None` while it never
    /// held.
    pub(super) reached: Option<Vec<Turn>>,
    /// Turns the run took.
    pub(super) turns: usize,
    pub(super) suffix: Option<Suffix>,
    /// Bound records in key order, refusals after them.
    pub(super) contents: Vec<Bound>,
    /// The upload's outcome when it ran, `None` inside while undecided.
    pub(super) put: Option<Option<UploadOutcome>>,
    /// Each read's outcome and the exact bytes it delivered, in order.
    pub(super) gets: [Option<(Option<Outcome>, Vec<u8>)>; 2],
    /// The first failure a stopped boundary or teardown check observed;
    /// the run sets it once the teardown judged.
    pub(super) first: Option<Failure>,
    /// Both links' and the device's audit under the declared outcomes.
    pub(super) audit: Verdict,
    /// The storage census against the run's own geometry.
    pub(super) census: Result<(), String>,
    /// Workload actions that ran once the goal held.
    pub(super) suffix_acts: usize,
    /// The first reason the run had not drained at its end.
    pub(super) undrained: Option<&'static str>,
    /// The first pressure, admission or collision effect the run met.
    pub(super) pressure: Option<&'static str>,
    pub(super) counters: OwnerReport,
}

/// The settled projection of `world` at its last turn.
pub(super) fn settled(
    world: &Mixed<'_, '_, '_>,
    report: &Report,
    audit: Verdict,
    profile: &Profile,
    limits: Limits,
) -> Settled {
    let storage = world.scene.storage;
    let (mut bindings, mut facts, mut buffer) = (Vec::new(), Vec::new(), Vec::new());
    let live =
        storage.bindings_into(&mut bindings).is_ok() && storage.slot_facts_into(&mut facts).is_ok();
    let media = world.scene.media();
    let registry = world.registry.borrow();
    let mut contents: Vec<Bound> = bindings
        .iter()
        .map(|&binding| {
            media
                .bound_record(binding, &facts, &mut buffer)
                .map(|(key, metadata, payload)| Record {
                    key,
                    label: registry.label(&key, metadata, payload),
                    metadata,
                    payload: payload.to_vec(),
                })
        })
        .collect();
    contents.sort_by_key(|bound| match bound {
        Ok(record) => (0, record.key, String::new()),
        Err(failure) => (1, [0; 32], format!("{failure:?}")),
    });
    let reached = world.reached.get();
    let suffix_acts = reached.map_or(0, |(at, _)| {
        world.acts.iter().filter(|act| act.turn >= at).count()
    });
    let suffix = reached.map(|(at, at_us)| {
        let clocked = |seen: &super::Seen| (seen.epoch, seen.states, seen.sessions);
        let goal = world.seen.get(at.saturating_sub(1)).map(clocked);
        Suffix {
            span_us: world.last_us - at_us,
            changed: world.seen[at..]
                .iter()
                .any(|seen| Some(clocked(seen)) != goal),
        }
    });
    let gets = [0, 1].map(|client| {
        world.gets[client]
            .as_ref()
            .map(|get| (get.outcome, get.bytes.clone()))
    });
    let counters = world.scene.owner.report();
    let totals = storage.maintain_totals();
    let pressed = |status| matches!(Outcome::of(status, false), Outcome::Pressure(_));
    let read_pressed = gets.iter().flatten().any(|(outcome, _)| match outcome {
        Some(Outcome::Pressure(_)) => true,
        Some(Outcome::Failed(status) | Outcome::Incomplete(status)) => pressed(*status),
        _ => false,
    });
    let put_pressed = matches!(
        world.put.as_ref().and_then(|put| put.outcome),
        Some(UploadOutcome::Failed(status)) if pressed(status)
    );
    let effects = [
        (read_pressed, "a read ended under pressure"),
        (put_pressed, "the upload failed under pressure"),
        (
            counters.maintenance_refused > 0,
            "the storage refused maintenance",
        ),
        (counters.dropped > 0, "the owner dropped a datagram"),
        (
            counters.failed + counters.defects > 0,
            "the owner failed a frame or a read",
        ),
        (counters.false_positives > 0, "a fingerprint collided"),
        (world.evicted, "an object was evicted"),
        (world.expired, "an object expired"),
        (totals.evicted > 0, "the storage evicted an object"),
        (totals.expired > 0, "the storage expired an object"),
    ];
    let pressure = effects.iter().find(|(met, _)| *met).map(|&(_, why)| why);
    Settled {
        profile: profile.clone(),
        limits,
        plan: world.configured,
        end: report.end,
        reached: reached.map(|(at, _)| report.turns[..at].to_vec()),
        turns: world.seen.len(),
        suffix,
        census: if live {
            census(world, bindings.len())
        } else {
            Err("the storage was not live".into())
        },
        contents,
        put: world.put.as_ref().map(|put| put.outcome),
        gets,
        first: world.first.get(),
        audit,
        suffix_acts,
        undrained: undrained(world),
        pressure,
        counters,
    }
}

/// The first reason `world` has not drained: a holder kept, an update
/// held, a read or upload pending, a request live at the owner, a datagram
/// queued on a link for this turn or a later one, a device reference a
/// link holds for a delivered datagram, or a completion undelivered.
pub(super) fn undrained(world: &Mixed<'_, '_, '_>) -> Option<&'static str> {
    let scene = &world.scene;
    let checks = [
        (!world.held.is_empty(), "a holder was kept"),
        (!world.updates.is_empty(), "an update was held"),
        (
            (0..2).any(|client| world.get_pending(client)),
            "a read was pending",
        ),
        (world.uploading(), "the upload was pending"),
        (
            scene.owner.census().live() > 0,
            "a request was live at the owner",
        ),
        (
            scene
                .nets
                .iter()
                .any(|net| (0..2).any(|side| net.borrow().pending(side) > 0)),
            "a datagram was in flight",
        ),
        (
            scene.nets.iter().any(|net| net.borrow().nic_held() > 0),
            "a link held a transmit's reference",
        ),
        (
            scene.control.deliverable() > 0,
            "a completion was undelivered",
        ),
    ];
    checks.iter().find(|(held, _)| *held).map(|&(_, why)| why)
}

/// Reconciles the storage's ledger against the run's own geometry: its
/// slots and raw bytes as configured, each ledger partition summing to
/// them, and as many resident slots as bindings.
fn census(world: &Mixed<'_, '_, '_>, bound: usize) -> Result<(), String> {
    let (shape, _) = world.configured.geometry.shape();
    let report = world
        .scene
        .storage
        .pool_report()
        .ok_or("the pool reported nothing")?;
    let ledger = report.ledger.ok_or("the pool's gate was poisoned")?;
    let descriptor = report.descriptor;
    // `test_volume`'s metadata prefix.
    let metadata = crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT;
    let raw = shape.units * IO_UNIT + metadata;
    let checks = [
        (descriptor.slot_count, shape.slots, "configured slots"),
        (descriptor.raw_bytes, raw, "configured raw bytes"),
        (ledger.raw.metadata, metadata, "metadata term"),
        (
            ledger.slots.total().map_err(|_| "slot overflow")?,
            shape.slots,
            "slot partition",
        ),
        (
            ledger.raw.total().map_err(|_| "raw overflow")?,
            raw,
            "raw partition",
        ),
        (
            ledger.slots.resident,
            bound,
            "resident slots against bindings",
        ),
    ];
    match checks.iter().find(|(found, wanted, _)| found != wanted) {
        Some((found, wanted, what)) => Err(format!("{what}: {found} against {wanted}")),
        None => Ok(()),
    }
}

/// One side of a pair: its bundle and what it settled to.
#[derive(Debug)]
pub(super) struct Side {
    pub(super) bundle: Vec<u8>,
    pub(super) settled: Settled,
}

/// Runs the scenario `name` through the bundle path under `stops`.
pub(super) fn side<S: Stops<Vec<u8>>>(name: &str, stops: S) -> (Side, S) {
    side_with(name, &[], stops)
}

/// [`side`] with manifest overrides, so paired runs can vary a manifest
/// input such as the root seed.
pub(super) fn side_with<S: Stops<Vec<u8>>>(
    name: &str,
    edits: &[(&str, &str)],
    stops: S,
) -> (Side, S) {
    use crate::sim::manifest_tests::{edited, sample_lines};
    let lines = sample_lines(name, &"a".repeat(64), "x86_64-linux");
    let manifest = Manifest::parse(&edited(lines, edits)).expect("a sample manifest");
    let admitted = admit(&manifest).expect("a named scenario");
    let chooser = admitted.recorder();
    let (closed, _, _, stops, settled) = run_settled(admitted, Vec::new(), chooser, stops);
    let settled = settled.expect("a mixed run settles");
    let side = Side {
        bundle: closed.sink,
        settled,
    };
    (side, stops)
}

/// How a relation judged a pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Judged {
    /// The premise held and the projections are equal.
    Equal,
    /// The premise held and the projections differ.
    Differs(String),
    /// The premise failed; the pair is no comparison.
    Unsupported(String),
}

/// Record equality establishes the shared-input premise after normalizing
/// `plant` and the knobs `varied` resets.
fn fixed(side: &Settled, varied: fn(&mut Plan)) -> Vec<u8> {
    let mut plan = Plan {
        plant: Plant::None,
        ..side.plan
    };
    varied(&mut plan);
    crate::sim::turn::record(
        &side.profile,
        plan.recovery().map(Recovery::record).as_ref(),
        &plan.record(),
        side.limits,
    )
}

/// The premise every relation shares: the pair's inputs equal except the
/// knobs `varied` resets, each side settled with one writer over healed
/// paths and drained, and neither under pressure. A harness defect is
/// reported first and settling last, since a side whose storage evicted its
/// objects may never settle.
fn settled_pair(a: &Settled, b: &Settled, varied: fn(&mut Plan)) -> Result<(), String> {
    if fixed(a, varied) != fixed(b, varied) {
        return Err("the pair's fixed inputs differ".into());
    }
    for side in [a, b] {
        if matches!(side.end, End::Defect(_)) {
            return Err(format!("a side ended in a harness defect: {:?}", side.end));
        }
    }
    for side in [a, b] {
        let plan = &side.plan;
        if plan.puts > 1 {
            return Err("two writers may race one key".into());
        }
        if plan.faulted() {
            return Err("a path was faulted or withheld".into());
        }
        if let Some(why) = side.undrained {
            return Err(format!("a side had not drained: {why}"));
        }
        if let Some(why) = side.pressure {
            return Err(format!("a side met pressure: {why}"));
        }
        if side.end != End::Done {
            return Err(format!("a side never settled: {:?}", side.end));
        }
    }
    Ok(())
}

/// The mismatch of field `what` between `a` and `b`, digested.
fn differs<T: PartialEq + std::fmt::Debug>(what: &str, a: &T, b: &T) -> Option<String> {
    (a != b).then(|| format!("{what}: {} against {}", digest(a), digest(b)))
}

/// A short digest of a projection field, so a mismatch names no payload.
fn digest<T: std::fmt::Debug>(value: &T) -> String {
    let hash = Sha256::digest(format!("{value:?}").as_bytes());
    hash[..6].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A census that failed to reconcile on either side.
fn census_failed(a: &Settled, b: &Settled) -> Option<String> {
    [a, b].iter().find_map(|side| {
        side.census
            .as_ref()
            .err()
            .map(|why| format!("a census failed to reconcile: {why}"))
    })
}

/// The obligations each side's checks judged: a difference, a failure
/// both sides share, or an audit other than a pass, since equal
/// projections of failing runs earn no credit.
fn obligations(a: &Settled, b: &Settled) -> Option<String> {
    let audited = [a, b]
        .iter()
        .find(|side| side.audit != Verdict::Pass)
        .map(|side| format!("an audit judged {:?}", side.audit));
    differs("the obligations", &a.first, &b.first)
        .or_else(|| {
            a.first
                .as_ref()
                .map(|failure| format!("the obligations failed alike: {failure:?}"))
        })
        .or(audited)
}

/// Outcomes and exact bytes: the upload's outcome, each read's outcome and
/// delivered bytes in order, every bound record, the obligations each side
/// observed, and each side's census.
fn outcomes_and_bytes(a: &Settled, b: &Settled) -> Judged {
    let first = differs("the upload", &a.put, &b.put)
        .or_else(|| differs("the reads", &a.gets, &b.gets))
        .or_else(|| differs("the bound records", &a.contents, &b.contents))
        .or_else(|| obligations(a, b))
        .or_else(|| census_failed(a, b));
    first.map_or(Judged::Equal, Judged::Differs)
}

fn varies<K: PartialEq>(
    a: &Settled,
    b: &Settled,
    what: &str,
    effect: fn(&Plan) -> K,
) -> Result<(), String> {
    if effect(&a.plan) == effect(&b.plan) {
        return Err(format!("{what} was not varied"));
    }
    Ok(())
}

/// Poll batching: the owner's batch is the one varied input.
pub(super) fn batching(a: &Settled, b: &Settled) -> Judged {
    let premise = settled_pair(a, b, |plan| plan.batch = None)
        .and_then(|()| varies(a, b, "the owner's batch", Plan::owner_batch));
    if let Err(why) = premise {
        return Judged::Unsupported(why);
    }
    outcomes_and_bytes(a, b)
}

/// Geometry scaling: the storage geometry is the one varied input, and each
/// side's census must reconcile against its own geometry.
pub(super) fn scaling(a: &Settled, b: &Settled) -> Judged {
    let premise = settled_pair(a, b, |plan| plan.geometry = Geometry::Fixture)
        .and_then(|()| varies(a, b, "the geometry", |plan| plan.geometry.shape()));
    if let Err(why) = premise {
        return Judged::Unsupported(why);
    }
    outcomes_and_bytes(a, b)
}

/// Drain-suffix idempotence: the drain length is the one varied input,
/// both runs drain and share the prefix to the goal, the suffix runs no
/// workload action and crosses no deadline, and contents, outcomes and
/// obligations must be equal while the counters may differ.
pub(super) fn idempotence(a: &Settled, b: &Settled) -> Judged {
    if let Err(why) = settled_pair(a, b, |plan| plan.drain = 0) {
        return Judged::Unsupported(why);
    }
    if a.plan.drain == b.plan.drain || a.plan.drain.min(b.plan.drain) == 0 {
        return Judged::Unsupported("the suffix was not repeated".into());
    }
    if a.reached != b.reached {
        return Judged::Unsupported("the runs reached the goal by different prefixes".into());
    }
    if a.suffix_acts + b.suffix_acts > 0 {
        return Judged::Unsupported("a suffix ran a workload action".into());
    }
    for suffix in [a.suffix, b.suffix].into_iter().flatten() {
        if suffix.changed || suffix.span_us >= u64::from(TTL_MS) * 1000 {
            return Judged::Unsupported("a suffix crossed a deadline".into());
        }
    }
    outcomes_and_bytes(a, b)
}

/// Schedule permutation: the pair is one plan whose two runs took
/// `swapped` in opposite orders; the bound records' key, label and content
/// must be equal.
pub(super) fn permutation(a: (&Settled, &Swap), b: (&Settled, &Swap)) -> Judged {
    for swap in [a.1, b.1] {
        if let Err(why) = swap.certificate() {
            return Judged::Unsupported(why.into());
        }
    }
    if let Err(why) = settled_pair(a.0, b.0, |_| ()) {
        return Judged::Unsupported(why);
    }
    if (a.1.first, a.1.second) != (b.1.second, b.1.first) {
        return Judged::Unsupported("the runs did not take one pair in opposite orders".into());
    }
    let logical = |side: &Settled| -> Vec<_> {
        side.contents
            .iter()
            .map(|bound| {
                bound
                    .as_ref()
                    .map(|record| (record.key, record.label, record.payload.clone()))
                    .map_err(Clone::clone)
            })
            .collect()
    };
    differs("the logical contents", &logical(a.0), &logical(b.0))
        .or_else(|| obligations(a.0, b.0))
        .or_else(|| census_failed(a.0, b.0))
        .map_or(Judged::Equal, Judged::Differs)
}

/// Where a scripted swap stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The pair has not been enabled together.
    Waiting,
    /// The first event of the pair was forced.
    First,
    /// Both were forced in order at one time.
    Done,
    Broken(&'static str),
}

/// A script that forces `first` then `second` at the first selection that
/// offers both, and certifies that the second stayed
/// enabled with the clock unmoved and that at most one client held a
/// request at the pair: the reader had issued no read, or the uploader had
/// collected its upload's outcome.
#[derive(Debug, Clone)]
pub(super) struct Swap {
    pub(super) first: Candidate,
    pub(super) second: Candidate,
    /// The reader issued a read before the pair was forced.
    read: bool,
    /// The uploader held an upload it had not collected when the pair was
    /// forced.
    uploading: bool,
    step: Step,
}

impl Swap {
    pub(super) fn new(first: Candidate, second: Candidate) -> Self {
        Self {
            first,
            second,
            read: false,
            uploading: false,
            step: Step::Waiting,
        }
    }

    /// The certificate that the run took an independent pair in order at
    /// one time.
    pub(super) fn certificate(&self) -> Result<(), &'static str> {
        match self.step {
            Step::Waiting => Err("the pair was never enabled together"),
            Step::First => Err("the second event never ran"),
            Step::Broken(why) => Err(why),
            Step::Done if self.read && self.uploading => {
                Err("both clients held requests at the pair")
            }
            Step::Done if !independent(&self.first, &self.second) => {
                Err("the pair shares a link, key, custody or resource order")
            }
            Step::Done => Ok(()),
        }
    }
}

/// Whether two events commute: client polls of distinct clients, each on
/// its own link, or a client poll and the disk service call, which shares
/// no link with it.
fn independent(a: &Candidate, b: &Candidate) -> bool {
    let class = |event: &Candidate| {
        (event.0[0] == Domain::Workload as u8).then_some((event.0[1], event.0[2]))
    };
    match (class(a), class(b)) {
        (Some((CLIENT_POLL, x)), Some((CLIENT_POLL, y))) => x != y,
        (Some((CLIENT_POLL, _)), Some((SERVICE, _)))
        | (Some((SERVICE, _)), Some((CLIENT_POLL, _))) => true,
        _ => false,
    }
}

impl Stops<Vec<u8>> for Swap {
    fn events(&mut self, events: &[crate::sim::trace::Event]) {
        if self.step != Step::Waiting {
            return;
        }
        for event in events {
            self.read |= event.kind == ACT && event.payload[0] == ActionKind::Get as u8;
            if event.kind == PUT {
                self.uploading = true;
            }
            if UploadState::of(event).is_some_and(|state| state.outcome != 0) {
                self.uploading = false;
            }
        }
    }

    fn stopped(&mut self, _recorder: &mut Recorder<Vec<u8>>, _chooser: &RefCell<Chooser>) {
        if self.step == Step::First {
            self.step = Step::Broken("the clock moved between the pair");
        }
    }

    fn select(
        &mut self,
        _recorder: &mut Recorder<Vec<u8>>,
        runnable: &[Candidate],
        chooser: &RefCell<Chooser>,
    ) {
        let at = |event: &Candidate| runnable.iter().position(|offered| offered == event);
        match self.step {
            Step::Waiting => {
                if let (Some(first), Some(_)) = (at(&self.first), at(&self.second)) {
                    chooser.borrow_mut().force(first);
                    self.step = Step::First;
                }
            }
            Step::First => match at(&self.second) {
                Some(second) => {
                    chooser.borrow_mut().force(second);
                    self.step = Step::Done;
                }
                None => self.step = Step::Broken("the first event disabled the second"),
            },
            Step::Done | Step::Broken(_) => {}
        }
    }
}
