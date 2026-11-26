//! Composed custody histories: the held-state families, each a scripted
//! sequence of steps the turn controller interleaves with owner, client,
//! disk and link events, so the interleaving each history's root selects
//! keeps the history's correlated ingredients in one episode.
//!
//! A history arms its holds before its fault: while reads are held, every
//! read command the device accepts stays pending until the history releases
//! it, and while NIC references are held, no transmit reference returns.
//! Each step that sets an ingredient marks it, and the last step ends the
//! history unsuccessful when a declared witness is unmarked. Safety is
//! judged at every stopped boundary by the world's registry against
//! bindings and raw media, and by each step's own check against the exact
//! bytes, outcomes and custody the history expects. In each history that
//! heals, qualified progress is judged after the heal, by an exact read or
//! a published upload read back exactly. A control modifies a passing
//! history to introduce a defect that the named check must detect.

use crate::oracle::{Label, Obligation};
use crate::sim::action::Profile;
use crate::sim::trace::{Loaded, Outcome as Ending, Terminal};
use crate::storage::device::sim::{Event as DiskEvent, QuiesceMode};
use crate::storage::owner_fixture::TestPlatform;
use crate::storage::{CacheVersion, CommandToken, ExtentLease, Operation, WritableFill};

use super::super::datagram::PeerId;
use super::super::fetch::Outcome;
use super::super::frame::Status;
use super::super::geometry::FRAGMENT_LEN;
use super::super::observe::Failure;
use super::super::owner_tests::{collect, key, payload};
use super::super::requests::{PeerCensus, RequestId};
use super::super::upload::UploadOutcome;
use super::{Mixed, Plan, QUIET, Step, budget, fill, ticks};

mod cancelled_reads;
mod cancelled_uploads;
mod closed_references;
pub(crate) mod cohorts;
mod copies;
mod covered_successors;
mod deadline_edges;
mod deferred_deadlines;
mod deferred_outcomes;
mod delayed_results;
mod displaced_charges;
mod expiry_samples;
mod full_shares;
mod handshakes;
mod healed_pools;
mod healed_uploads;
mod held_writes;
pub(crate) mod incidents;
mod isolation;
mod keyops;
mod late_results;
mod lent_commands;
mod lost_completes;
mod lost_results;
mod named_gets;
mod old_rights;
mod peer_charges;
mod pressured_gets;
mod receipts;
mod refused;
mod rekeys;
mod resolved_uploads;
mod restarts;
mod retained;
mod retained_rows;
mod root_slots;
mod saturated_shares;
mod second_gets;
mod share_charges;
mod silent_owners;
mod stalled_uploads;
mod warm_loads;

/// The outcome a step returns when it must run again: the history stays at
/// that step.
pub(super) const STAY: u64 = u64::MAX;

/// Microseconds a history waits for a step's progress before its bound
/// check fails it.
const BOUND_US: u64 = 200_000;

/// Microseconds a history waits for the owner to end a cancelled request.
const CANCEL_BOUND_US: u64 = 20_000;
const _: () = assert!(CANCEL_BOUND_US < super::WAIT_US);

/// What a history's steps keep for later steps and for its judgment.
#[derive(Default)]
pub(super) struct State<'s, 'm> {
    /// Every read command the device accepts is held until released.
    hold_reads: bool,
    /// No transmit reference returns while set.
    pub(super) hold_nic: bool,
    /// A world time a waiting step needs the run to reach.
    pub(super) wake: Option<u64>,
    /// The storage tick every owner-side turn samples while set.
    pub(super) clock: Option<u64>,
    /// Every write command the device accepts is held until released.
    hold_writes: bool,
    /// Write commands the history holds.
    writes: Vec<CommandToken>,
    /// Held writes when the upload's DATA was supplied.
    supplied_at: usize,
    /// Read commands the history holds.
    held: Vec<CommandToken>,
    /// Read commands the hold lets run before it holds the next.
    pass: u32,
    /// Device events the hold has examined, over the device's life.
    seen: u64,
    /// Each ingredient and check, in the order it was set.
    marks: Vec<&'static str>,
    /// GETs the history issued beyond the world's own two.
    ids: Vec<RequestId>,
    /// The history's current upload.
    put: Option<RequestId>,
    /// Client 1's upload beside the current one.
    second: Option<RequestId>,
    /// The other peer's GET beside a saturated share.
    peer: Option<RequestId>,
    fill: Option<WritableFill<'s, 'm, TestPlatform>>,
    /// A fill of several extents whose placement the history keeps across
    /// its steps.
    placing: Option<crate::storage::PlacingFill<'s, TestPlatform>>,
    lease: Option<ExtentLease<'s, TestPlatform>>,
    /// The cancelled request's peer and that peer's active requests when
    /// the cancel began.
    cancelled: Option<(PeerId, u32)>,
    /// The owner's live requests when a cancel or stop began, the volume's
    /// count of reads that waited when SS2's peer GET was issued, or the
    /// table slot of the one PUT the owner held when LW's waiter began.
    kept: u64,
    /// Frames the owner had sent when it closed.
    sent: u64,
    /// Uploads the owner had published when I10's take step ran.
    published: u64,
    /// GETs the owner had admitted when I9's successor was issued.
    admitted: u64,
    /// GET frames the link had carried toward the owner when I9's wire
    /// slot freed.
    carried: u64,
    /// Transmit references the links withheld when a cancel began.
    refs: u64,
    /// The time a bounded wait began.
    since: u64,
    /// The turn a wait bounded in turns began.
    turn: usize,
    /// The time the history released its holds.
    released_at: u64,
    /// The time a waiting incident step compares: I1 GET's expiry as a
    /// storage tick; I2 PUT's client deadline or I3's retention end, in
    /// world microseconds.
    deadline: u64,
    /// The objects a later exact read may return, when an outcome leaves
    /// more than one admissible.
    allowed: Vec<Vec<u8>>,
    /// Fragments of the current upload supplied so far.
    fragment: u32,
    /// A turn saw the lost fragment's source held before its receipt.
    lost_held: bool,
    /// Session frames the owner had refused when the displaced client sent.
    noted_drops: u64,
    /// Session displacements the owner had counted when a replacement opened.
    displacements: u64,
    /// Uploads the owner had begun when a history's GET started.
    begun: u64,
    /// Upload RESULTs the link's rule chain kept, summed each time a step
    /// clears those rules.
    results: usize,
    /// Bytes a GET delivered, in offset order, across the steps that take
    /// its fragments.
    taken: Vec<u8>,
    /// The world time a delayed frame reaches its end.
    arrival: u64,
    /// Each cohort event the history recorded, in order.
    pub(super) events: Vec<Event>,
    forged: Option<cohorts::Counters>,
    /// A frame header a cohort learned from the link, for a forged frame.
    learned: Option<super::super::frame::Header>,
    /// The request ID each judged request's frames carry, by its client
    /// and table handle, kept for the steps that run after its release.
    attempts: Vec<(usize, RequestId, u64)>,
    /// The world time a request judged against one deadline was issued.
    issued: u64,
    /// The world time B's GET beside A's saturated share was issued.
    b_issued: u64,
    /// RESULT frames the uploading client had accepted when its upload went
    /// unknown.
    results_received: u64,
    /// Frames the replacement client had refused as naming another session
    /// when a delayed old-session frame was armed.
    mismatched: u64,
    /// The session epoch the displaced client held.
    old_epoch: Option<u64>,
    /// Read-response buffers a history holds to exhaust the owner's pool.
    pool: Vec<crate::storage::Buffer<'m>>,
    /// Fill reservations a history holds to exhaust the storage's space.
    reserved: Vec<WritableFill<'s, 'm, TestPlatform>>,
    /// Owner polls applied when the history closed or stopped the owner.
    polls_at_close: u64,
    /// The oracle rows a relaunch opened with its Restart row, which the
    /// relaunched owner's recovered lookup is judged against.
    recovered: Option<crate::oracle::Script>,
    /// The GET beside a stopped owner and the client that issued it.
    beside: Option<(RequestId, isolation::Via)>,
    at_stop: Option<isolation::Accounts>,
    at_beside: Option<isolation::Accounts>,
    /// Warm-load state survives an owner relaunch.
    warm: Option<Box<warm_loads::Warm>>,
    /// The root generations the root-slot histories judge.
    roots: Option<root_slots::Roots>,
}

impl State<'_, '_> {
    /// `relaunched` clears every hold, request, fill, lease and counter
    /// snapshot the history kept from the previous incarnation, so each
    /// later step reads only the living incarnation. Marks, cohort events,
    /// recorded times, the owner polls at close, the recovered-lookup rows,
    /// the warm-load state and a GET beside the stopped owner through the
    /// peer's client stay.
    pub(super) fn relaunched(&mut self) {
        *self = Self {
            marks: std::mem::take(&mut self.marks),
            events: std::mem::take(&mut self.events),
            recovered: self.recovered.take(),
            warm: self.warm.take(),
            wake: self.wake,
            since: self.since,
            turn: self.turn,
            released_at: self.released_at,
            deadline: self.deadline,
            arrival: self.arrival,
            issued: self.issued,
            b_issued: self.b_issued,
            polls_at_close: self.polls_at_close,
            beside: self
                .beside
                .filter(|&(_, via)| !matches!(via, isolation::Via::Stopped)),
            ..Self::default()
        };
    }
}

/// The part an event plays in a cohort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Injection,
    Effect,
    Check,
}

/// What a cohort event names: its episode, actor, operation attempt, key
/// label, device token and session incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) episode: &'static str,
    pub(super) actor: usize,
    pub(super) attempt: u64,
    pub(super) label: Label,
    pub(super) token: Option<CommandToken>,
    pub(super) incarnation: Option<u64>,
}

/// One recorded cohort event and its place in the history's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Event {
    pub(super) role: Role,
    pub(super) name: &'static str,
    pub(super) identity: Identity,
    pub(super) at: usize,
}

/// Holds each read command the device accepted since the last call, after
/// the `pass` reads it lets run, when the history holds reads, and each
/// write command, when it holds writes.
/// The device's log is bounded: `seen` counts events over the device's
/// life, so the events the log dropped are skipped by count.
pub(super) fn settle(world: &mut Mixed<'_, '_, '_>) {
    let events = world.scene.control.events();
    let evicted = world.scene.control.evicted();
    let total = evicted + events.len() as u64;
    let start = world.history.seen.saturating_sub(evicted) as usize;
    for event in &events[start.min(events.len())..] {
        match *event {
            DiskEvent::Submitted(token, Operation::Read) if world.history.hold_reads => {
                if world.history.pass > 0 {
                    world.history.pass -= 1;
                } else if world.scene.control.try_hold(token).is_ok() {
                    world.history.held.push(token);
                }
            }
            DiskEvent::Submitted(token, Operation::Write)
                if world.history.hold_writes && world.scene.control.try_hold(token).is_ok() =>
            {
                world.history.writes.push(token);
            }
            _ => {}
        }
    }
    world.history.seen = total;
}

/// The resident object the scene publishes under key 1 before the run.
fn version_a() -> Vec<u8> {
    payload(1000, 1)
}

/// The replacement a history publishes or uploads under key 1.
fn version_b() -> Vec<u8> {
    payload(VERSION_B_LEN, 2)
}

const VERSION_B_LEN: usize = 1200;

/// The successor upload's object in H2: its bytes differ from the
/// cancelled upload's, so a late frame of the cancelled one shows.
fn version_c() -> Vec<u8> {
    payload(1200, 4)
}

/// A replacement of three fragments, the last short.
fn long_b() -> Vec<u8> {
    payload(LONG_B_LEN, 3)
}

const LONG_B_LEN: usize = 3 * FRAGMENT_LEN as usize - 100;

const LABEL_B: Label = Label(21);
const LABEL_C: Label = Label(22);

fn mark(world: &mut Mixed<'_, '_, '_>, name: &'static str) -> u64 {
    world.history.marks.push(name);
    world.history.marks.len() as u64
}

/// Records the violation `rule` of `obligation`, or, when a premise the
/// plan declares is unmarked, the history unsuccessful: a kill counts only
/// with its premise witnessed.
fn fail(world: &mut Mixed<'_, '_, '_>, obligation: Obligation, rule: &'static str) -> u64 {
    let missing = world
        .plan
        .premise
        .iter()
        .find(|witness| !world.history.marks.contains(witness));
    match missing {
        Some(&witness) => world.first.record(Failure::Unsuccessful(witness)),
        None => world.first.record(Failure::Violation(obligation, rule)),
    };
    0
}

fn always(_: &Mixed<'_, '_, '_>, _: u64) -> bool {
    true
}

fn active_get(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.active(1)
}

fn active_put(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.active(0)
}

fn arm(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_reads = true;
    world.history.hold_nic = true;
    mark(world, "holds armed")
}

fn arm_nic(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_nic = true;
    mark(world, "holds armed")
}

/// Holds reads, transmit references and the owner's write commands.
fn arm_writes(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.hold_writes = true;
    arm(world, now)
}

/// Holds transmit references and the owner's write commands.
fn arm_nic_writes(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.hold_writes = true;
    arm_nic(world, now)
}

/// The owner accepted upload DATA: the device holds a write submitted
/// after the supply.
fn write_held(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.history.writes.len() > world.history.supplied_at
}

fn mark_write_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "owner write held")
}

/// Every write the history held is still pending on the device.
fn writes_pending(world: &Mixed<'_, '_, '_>) -> bool {
    let control = &world.scene.control;
    world
        .history
        .writes
        .iter()
        .all(|&token| control.try_hold(token).is_ok())
}

/// Every read and write the history holds is still pending on the device.
fn commands_pending(world: &Mixed<'_, '_, '_>) -> bool {
    let control = &world.scene.control;
    world
        .history
        .held
        .iter()
        .all(|&token| control.try_hold(token).is_ok())
        && writes_pending(world)
}

fn old_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.get(1, now) {
        super::REFUSED => STAY,
        applied => applied,
    }
}

fn read_held_or_done(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    !world.history.held.is_empty() || world.gets[1].is_none() || old_decided(world, now)
}

fn mark_read_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if world.history.held.is_empty() {
        return 1;
    }
    mark(world, "old read held")
}

fn invalidate(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let removed = world
        .scene
        .owner
        .invalidate(&key(1), 3, &mut budget())
        .is_ok_and(|done| done.removed.is_some());
    world.owner_due = now;
    if !removed {
        return fail(
            world,
            Obligation::History,
            "the invalidation removed no mapping",
        );
    }
    mark(world, "invalidation acknowledged")
}

/// A control's step in place of the invalidation: it removes nothing and
/// lets the next read command run, so the fresh GET's read of the mapped
/// version completes beside the held old read.
fn invalidation_skipped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.pass = 1;
    1
}

/// A GET of key 1 from the uploading client, which holds no other GET.
fn fresh_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[0].get(key(1), 0, 1 << 20, now, super::WAIT_US) {
        Ok(id) => {
            world.history.ids.push(id);
            world.history.since = now;
            1
        }
        Err(_) => STAY,
    }
}

/// The falsifier's client cancels the GET on issue, so it ends
/// `Failed(Cancelled)` whatever the owner holds for the key.
fn fresh_get_cancelled(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let issued = fresh_get(world, now);
    if issued != STAY {
        let id = *world.history.ids.last().expect("the fresh GET");
        world.scene.clients[0].cancel(id);
    }
    issued
}

fn fresh_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .ids
        .last()
        .is_some_and(|&id| world.scene.clients[0].outcome(id).is_some())
}

/// Every byte GET `id` delivered to `client` so far, each fragment at its
/// offset.
fn drain<'m>(
    client: &mut super::super::client::Client<'m, super::super::link::LinkEnd<'m>>,
    id: RequestId,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    collect(client, id, &mut bytes);
    bytes
}

/// The fresh GET's outcome and every byte it delivered, after which its
/// request retires.
fn fresh_result(world: &mut Mixed<'_, '_, '_>) -> (Option<Outcome>, Vec<u8>) {
    let id = *world.history.ids.last().expect("a fresh GET");
    let bytes = drain(&mut world.scene.clients[0], id);
    let outcome = world.collect_get(0, id);
    let _ = world.scene.clients[0].retire(id);
    (outcome, bytes)
}

fn fresh_missed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    if outcome != Some(Outcome::Missing) || !bytes.is_empty() {
        return fail(
            world,
            Obligation::History,
            "a GET after the acknowledged invalidation saw a removed version",
        );
    }
    mark(world, "fresh GET missed")
}

/// A `true` result means the storage granted the fill of `version` of key
/// `n`. `world.history.fill` keeps the fill even when the owner accepted
/// only part of `object`.
fn fill_key_with(
    world: &mut Mixed<'_, '_, '_>,
    n: u8,
    version: CacheVersion,
    object: &[u8],
    label: Label,
) -> bool {
    let Some(mut fill) = super::fill_at(world.storage(), &key(n), version, object.len()) else {
        return false;
    };
    world
        .registry
        .borrow_mut()
        .register(key(n), label, 0, object.to_vec());
    let io = &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX);
    let mut taken = 0;
    while taken < object.len() {
        match world
            .scene
            .owner
            .receive_fill(&mut fill, &object[taken..], io)
        {
            Ok(0) | Err(_) => break,
            Ok(count) => taken += count,
        }
    }
    world.history.fill = Some(fill);
    true
}

fn fill_with(world: &mut Mixed<'_, '_, '_>, object: &[u8], label: Label) -> u64 {
    if !fill_key_with(world, 1, CacheVersion(0), object, label) {
        return STAY;
    }
    mark(world, "replacement filled")
}

fn fill_b(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fill_with(world, &version_b(), LABEL_B)
}

fn fill_long(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fill_with(world, &long_b(), LABEL_B)
}

/// A control: the replacement's fill carries the old version's bytes, so
/// the key's visible bytes stay the old generation's.
fn fill_stale(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fill_with(world, &version_a(), Label(1))
}

fn fill_written(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .fill
        .as_ref()
        .is_some_and(|fill| world.scene.owner.fill_progress(fill).is_ready())
}

fn publish_fill(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let fill = world.history.fill.take().expect("a written fill");
    match world
        .scene
        .owner
        .publish_fill(fill, ticks(now + 60 * super::SECOND_US), 2, &mut budget())
    {
        Ok(lease) => {
            world.history.lease = Some(lease);
            world.owner_due = now;
            mark(world, "replacement published")
        }
        Err(_) => fail(
            world,
            Obligation::Progress,
            "the replacement never published",
        ),
    }
}

/// `FILL_REVOKED` requires `Storage::invalidate` to report a revoked
/// attempt.
fn invalidate_then_publish_fill(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    invalidate_key_then_publish_fill(world, now, &key(1))
}

fn invalidate_key_then_publish_fill(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    invalidated: &[u8; 32],
) -> u64 {
    let revoked = world
        .scene
        .owner
        .invalidate(invalidated, 3, &mut budget())
        .is_ok_and(|done| done.revoked.is_some());
    if premised(world, revoked, FILL_REVOKED) == 0 {
        return 0;
    }
    publish_fill(world, now)
}

const FILL_REVOKED: &str = "the fill's attempt was revoked";

fn release_reads(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_reads = false;
    world.history.hold_writes = false;
    let reads = std::mem::take(&mut world.history.held);
    for token in reads
        .into_iter()
        .chain(std::mem::take(&mut world.history.writes))
    {
        world.scene.control.release(token);
    }
    world.history.lease = None;
    mark(world, "old read released")
}

fn old_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.gets[1]
        .as_ref()
        .is_some_and(|get| world.scene.clients[1].outcome(get.id).is_some())
}

/// The old right ends with its own version's exact bytes, or with a
/// failure that delivered no byte outside them.
fn old_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the old GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    judge_old(world, outcome, &bytes)
}

/// A control: the old right delivers the replacement's bytes, as a read
/// of its extent reused early would.
fn old_reused(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    judge_old(world, Some(Outcome::Complete), &version_b())
}

fn judge_old(world: &mut Mixed<'_, '_, '_>, outcome: Option<Outcome>, bytes: &[u8]) -> u64 {
    let version = version_a();
    let exact = match outcome {
        Some(Outcome::Complete) => bytes == version,
        Some(Outcome::Failed(_)) => version.starts_with(bytes),
        _ => false,
    };
    if !exact {
        return fail(
            world,
            Obligation::Bytes,
            "the old right returned bytes other than its own version",
        );
    }
    mark(world, "old right returned its version")
}

fn release_nic(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = withheld(world);
    world.history.hold_nic = false;
    if held == 0 {
        return 1;
    }
    mark(world, "DATA references held past the old GET")
}

/// The healed suffix's GET reads `expected` exactly.
fn fresh_exact_of(world: &mut Mixed<'_, '_, '_>, expected: &[u8]) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    if outcome != Some(Outcome::Complete) || bytes != expected {
        return fail(
            world,
            Obligation::History,
            "a qualified GET missed the visible version's exact bytes",
        );
    }
    mark(world, "qualified exact read")
}

fn fresh_exact_b(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fresh_exact_of(world, &version_b())
}

/// The obligation each check's mark judges.
const CHECKS: [(&str, Obligation); 54] = [
    ("old right returned its version", Obligation::Bytes),
    (INCOMPLETE_OVER_PREFIX, Obligation::Contain),
    ("fresh GET missed", Obligation::History),
    ("qualified exact read", Obligation::History),
    ("upload published", Obligation::History),
    ("cancel kept custody", Obligation::Custody),
    ("close retained DATA and stopped sends", Obligation::Custody),
    ("the stop retained its custody", Obligation::Custody),
    (
        "the cancelled request drained after its terminal",
        Obligation::Resources,
    ),
    (
        "each custody domain released after its proof",
        Obligation::Resources,
    ),
    ("the stop retained its custody", Obligation::Resources),
    ("eligible peer progressed", Obligation::Progress),
    ("upload stalled before its DATA", Obligation::Resources),
    ("charges stayed within the share", Obligation::Resources),
    ("the upload stayed unknown at close", Obligation::History),
    (
        "the proven stop ended its device custody",
        Obligation::Custody,
    ),
    (
        "the cancelled upload's outcome matched its phase",
        Obligation::History,
    ),
    ("a held sample served before its expiry", Obligation::Bytes),
    ("a sample at the deadline missed", Obligation::History),
    (
        "the client deadline passed with the write held",
        Obligation::Custody,
    ),
    ("the upload's actual outcome judged", Obligation::History),
    (
        "the GET agreed with the upload's outcome",
        Obligation::Bytes,
    ),
    (
        "the replacement read the visible version exactly",
        Obligation::Bytes,
    ),
    ("unrelated work progressed", Obligation::Progress),
    ("the GET after the loss ended exactly", Obligation::Bytes),
    (
        "the lost fragment's source stayed held",
        Obligation::Custody,
    ),
    ("upload published", Obligation::Progress),
    (
        "the upload's outcome stayed consistent",
        Obligation::History,
    ),
    ("duplicates granted no extra credit", Obligation::Contain),
    ("duplicates granted no extra credit", Obligation::Resources),
    (
        "the displaced session's frames were refused",
        Obligation::Contain,
    ),
    (
        "the replacement took a new session identity",
        Obligation::Contain,
    ),
    (
        "the displaced session's work drained only after its terminal",
        Obligation::Custody,
    ),
    (
        "the displaced upload kept its sources and write",
        Obligation::Custody,
    ),
    (
        "the GET past the share ended typed within its deadline",
        Obligation::Resources,
    ),
    (
        "the pressured upload was refused typed",
        Obligation::Resources,
    ),
    ("the incumbent stayed exact", Obligation::History),
    ("the known result stayed", Obligation::History),
    (
        "the upload stayed within its granted credit",
        Obligation::Resources,
    ),
    (
        "the deferred upload ended at its one deadline",
        Obligation::Resources,
    ),
    ("charges reconciled by peer", Obligation::Resources),
    ("B progressed beside A's capped share", Obligation::Progress),
    (
        "the GET under the exhausted pool ended typed within its deadline",
        Obligation::Resources,
    ),
    (
        "the upload past its share was refused typed",
        Obligation::Resources,
    ),
    (
        "the upload waited on its source slots",
        Obligation::Resources,
    ),
    ("the healed GET read exactly", Obligation::Progress),
    (
        "the resident's GET completed with the resident's exact bytes",
        Obligation::Progress,
    ),
    ("the fill aborted and returned", Obligation::Contain),
    (
        "the settled upload left no admitted attempt",
        Obligation::Resources,
    ),
    (
        "the settled GET left no admitted request",
        Obligation::Resources,
    ),
    (
        "the refused successor ended unadmitted",
        Obligation::Resources,
    ),
    (
        "the GET on the ended upload's wire slot was admitted",
        Obligation::Progress,
    ),
    ("the owner's next turn returned", Obligation::Contain),
    (
        "the upload whose write unwound ended unpublished",
        Obligation::History,
    ),
];

/// The obligations a history's marks activated.
fn activated(marks: &[&'static str]) -> Vec<Obligation> {
    CHECKS
        .iter()
        .chain(&cohorts::CHECKS)
        .chain(&handshakes::CHECKS)
        .chain(&copies::CHECKS)
        .chain(&restarts::CHECKS)
        .chain(&isolation::CHECKS)
        .chain(&keyops::CHECKS)
        .chain(&resolved_uploads::CHECKS)
        .chain(&lost_results::CHECKS)
        .chain(&receipts::CHECKS)
        .chain(&named_gets::CHECKS)
        .chain(&silent_owners::CHECKS)
        .chain(&pressured_gets::CHECKS)
        .chain(&late_results::CHECKS)
        .chain(&deadline_edges::CHECKS)
        .chain(&cancelled_reads::CHECKS)
        .chain(&expiry_samples::CHECKS)
        .chain(&full_shares::CHECKS)
        .chain(&saturated_shares::CHECKS)
        .chain(&lent_commands::CHECKS)
        .chain(&warm_loads::CHECKS)
        .chain(&root_slots::CHECKS)
        .chain(&deferred_deadlines::CHECKS)
        .chain(&displaced_charges::CHECKS)
        .chain(&healed_pools::CHECKS)
        .chain(&deferred_outcomes::CHECKS)
        .chain(&share_charges::CHECKS)
        .chain(&peer_charges::CHECKS)
        .chain(&rekeys::CHECKS)
        .chain(&refused::CHECKS)
        .filter(|(check, _)| marks.contains(check))
        .map(|&(_, obligation)| obligation)
        .collect()
}

/// Ends the history: every declared witness must be marked.
fn judge(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let missing = world
        .plan
        .witnesses
        .iter()
        .find(|witness| !world.history.marks.contains(witness));
    if let Some(&witness) = missing {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, "judged")
}

/// Starts the uploading client's PUT of `object` under key 1 at `version`,
/// registered under `label`.
fn put_begin_with(
    world: &mut Mixed<'_, '_, '_>,
    version: CacheVersion,
    object: Vec<u8>,
    label: Label,
    now: u64,
) -> u64 {
    let Ok(id) = world.scene.clients[0].put(key(1), version, now, super::WAIT_US) else {
        return STAY;
    };
    world.plan.puts -= 1;
    world
        .registry
        .borrow_mut()
        .register(key(1), label, 0, object);
    world.history.put = Some(id);
    world.history.since = now;
    mark(world, "upload begun")
}

fn put_begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    put_begin_with(world, CacheVersion(0), version_b(), LABEL_B, now)
}

fn put_prepare(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let body = VERSION_B_LEN as u32;
    match world.scene.clients[0].prepare(id, 0, body, super::TTL_MS) {
        Ok(()) => mark(world, "upload prepared"),
        Err(_) => STAY,
    }
}

fn put_supply(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    supply_with(world, &version_b())
}

fn supply_with(world: &mut Mixed<'_, '_, '_>, object: &[u8]) -> u64 {
    world.history.supplied_at = world.history.writes.len();
    let id = world.history.put.expect("a PUT");
    match world.scene.clients[0].supply(id, 0, object) {
        Ok(_) => mark(world, "upload DATA supplied"),
        Err(_) => STAY,
    }
}

fn successor_supply(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    supply_with(world, &version_c())
}

fn successor_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fresh_exact_of(world, &version_c())
}

fn put_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .put
        .is_some_and(|id| world.scene.clients[0].put_outcome(id).is_some())
}

fn put_published(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    let _ = world.scene.clients[0].retire(id);
    if outcome != Some(UploadOutcome::Published) {
        return fail(
            world,
            Obligation::History,
            "the upload's result was other than published",
        );
    }
    mark(world, "upload published")
}

/// A control: the upload supplies bytes other than the object its PUT
/// names, so a success selects bytes the upload never declared.
fn put_supply_wrong(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    supply_with(world, &payload(1200, 9))
}

fn cancel_old(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.gets[1].as_ref().expect("the old GET").id;
    world.scene.clients[1].cancel(id);
    cancel_began(world, PeerId(1), now);
    mark(world, "held read cancelled")
}

fn cancel_unsent(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    cancel_began(world, PeerId(1), now);
    mark(world, "held read cancelled")
}

/// Records what the cancel of `peer`'s request is judged against: that
/// peer's active requests, the owner's live requests, the withheld transmit
/// references and the time the bounded wait began.
fn cancel_began(world: &mut Mixed<'_, '_, '_>, peer: PeerId, now: u64) {
    let active = world.scene.owner.peer_census(peer).active;
    world.history.cancelled = Some((peer, active));
    world.history.kept = u64::from(world.scene.owner.census().live());
    world.history.refs = withheld(world);
    world.history.since = now;
}

/// The owner ended the cancelled request: its peer holds fewer active
/// requests than when the cancel began.
fn cancel_ended(world: &Mixed<'_, '_, '_>) -> bool {
    world
        .history
        .cancelled
        .is_some_and(|(peer, active)| world.scene.owner.peer_census(peer).active < active)
}

fn cancel_received(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    cancel_ended(world) || now > world.history.since + CANCEL_BOUND_US
}

fn cancel_kept(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let live = u64::from(world.scene.owner.census().live());
    judge_cancel(world, live, now)
}

/// A control: the owner's requests are read as released while the device
/// still holds the cancelled read, as an owner releasing custody at the
/// CANCEL would leave them.
fn cancel_released(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_cancel(world, 0, now)
}

/// Judges a cancel the owner ended while the device still holds the
/// history's commands: the owner's live requests, `live`, number at least
/// those it held when the cancel began, every held write stays pending and,
/// while the history holds transmit references, every one stays withheld.
/// A cancel the owner never ended within its bound, or a device that holds
/// no command at the check, leaves the history unsuccessful.
fn judge_cancel(world: &mut Mixed<'_, '_, '_>, live: u64, now: u64) -> u64 {
    let timely = now <= world.history.since + CANCEL_BOUND_US;
    for (formed, premise) in [
        (
            cancel_ended(world) && timely,
            "the owner ended the cancelled request",
        ),
        (
            world.scene.control.outstanding() > 0,
            "the device held the cancelled request's commands at its check",
        ),
    ] {
        if !formed {
            world.first.record(Failure::Unsuccessful(premise));
            return 0;
        }
        mark(world, premise);
    }
    let nic_kept = !world.history.hold_nic || withheld(world) >= world.history.refs;
    if live < world.history.kept || !writes_pending(world) || !nic_kept {
        return fail(
            world,
            Obligation::Custody,
            "a cancel released custody before the read's terminal",
        );
    }
    mark(world, "cancel kept custody")
}

/// Cancels the upload after its DATA was accepted.
fn cancel_put(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    world.scene.clients[0].cancel(id);
    cancel_began(world, PeerId(0), now);
    mark(world, "upload cancelled with its DATA accepted")
}

/// The cancelled upload's outcome names the phase it reached: after its
/// DATA reached the owner's write, it never claims no effect.
fn cancelled_outcome(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_cancelled(world, outcome)
}

/// A control: the cancelled upload's result is reported as no effect.
fn cancelled_no_effect(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_cancelled(world, Some(UploadOutcome::NotStarted))
}

fn judge_cancelled(world: &mut Mixed<'_, '_, '_>, outcome: Option<UploadOutcome>) -> u64 {
    let id = world.history.put.expect("a PUT");
    if outcome == Some(UploadOutcome::NotStarted) {
        return fail(
            world,
            Obligation::History,
            "a cancelled upload whose DATA was accepted claimed no effect",
        );
    }
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    mark(world, "the cancelled upload's outcome matched its phase")
}

/// The successor upload takes a wire identity the cancelled one never had:
/// on the same slot a higher generation, so no late frame of the cancelled
/// upload names it.
fn successor_put(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let old = world.history.put.expect("a PUT");
    if put_begin_with(world, CacheVersion(0), version_c(), LABEL_C, now) == STAY {
        return STAY;
    }
    let id = world.history.put.expect("the successor");
    let fresh = if id.slot() == old.slot() {
        id.generation() > old.generation()
    } else {
        id.wire() != old.wire()
    };
    if !fresh {
        return fail(
            world,
            Obligation::History,
            "a successor took its predecessor's wire identity",
        );
    }
    mark(world, "the successor upload took a fresh wire identity")
}

/// The uploading peer's requests drained: the cancelled upload's request
/// ended after its write's terminal.
fn upload_drained(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    let census = world.scene.owner.peer_census(PeerId(0));
    census.active + census.draining == 0
}

fn drained(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.owner.census().live() == 0
}

fn mark_drained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "the cancelled request drained after its terminal")
}

fn successor_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    successor_get_named(world, now, super::WAIT_US, |id, _| id)
}

/// A control: the successor is judged under its predecessor's wire
/// identity, as a stale successor that late frames of the old GET reach.
fn successor_get_stale(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    successor_get_named(world, now, super::WAIT_US, |_, old| old)
}

/// The request ID `id`'s frames carry: read from `actor`'s client while
/// the request is live, then kept for the steps that run after its
/// release.
fn attempt(world: &mut Mixed<'_, '_, '_>, actor: usize, id: RequestId) -> u64 {
    if let Some(wire) = kept_wire(world, actor, id) {
        return wire;
    }
    let wire = world.scene.clients[actor]
        .get_wire(id)
        .expect("a request's first use names it while it is live");
    world.history.attempts.push((actor, id, wire));
    wire
}

/// The wire ID `attempt` kept, which stays readable after the request's
/// release.
fn kept_wire(world: &Mixed<'_, '_, '_>, actor: usize, id: RequestId) -> Option<u64> {
    world
        .history
        .attempts
        .iter()
        .find(|&&(kept_actor, kept_id, _)| (kept_actor, kept_id) == (actor, id))
        .map(|&(_, _, wire)| wire)
}

/// Starts the successor GET and judges the wire identity `named` gives it
/// against its predecessor's, both as their frames carry them: on the
/// predecessor's wire slot it carries a higher generation. A refused
/// successor leaves the step to run again after the predecessor retired.
fn successor_get_named(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    wait_us: u64,
    named: fn(u64, u64) -> u64,
) -> u64 {
    let old = world.gets[1].as_ref().expect("the old GET").id;
    let old_wire = attempt(world, 1, old);
    let _ = world.scene.clients[1].retire(old);
    let Ok(started) = world.scene.clients[1].get(key(1), 0, 1 << 20, now, wait_us) else {
        return STAY;
    };
    world.history.ids.push(started);
    let wire = attempt(world, 1, started);
    let id = RequestId::from_wire(named(wire, old_wire));
    let old = RequestId::from_wire(old_wire);
    if id.slot() == old.slot() && id.generation() <= old.generation() {
        return fail(
            world,
            Obligation::History,
            "a successor took its predecessor's wire identity",
        );
    }
    if id.slot() == old.slot() {
        mark(world, "successor reused the slot at a higher generation");
    }
    1
}

fn successor_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .ids
        .last()
        .is_some_and(|&id| world.scene.clients[1].outcome(id).is_some())
}

/// The successor reads the resident version exactly: the late terminal of
/// its predecessor changed nothing in it.
fn successor_get_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = *world.history.ids.last().expect("a successor");
    let bytes = drain(&mut world.scene.clients[1], id);
    let outcome = world.collect_get(1, id);
    if outcome != Some(Outcome::Complete) || bytes != version_a() {
        return fail(
            world,
            Obligation::History,
            "a successor's result came from its predecessor",
        );
    }
    mark(world, "qualified exact read")
}

/// The control cancels the successor on issue, so `successor_get_exact`
/// judges a cancelled GET against its requirement of a complete read of
/// `version_a()`.
fn successor_get_cancelled(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let issued = successor_get(world, now);
    if issued == 1 {
        let id = *world.history.ids.last().expect("a successor");
        world.scene.clients[1].cancel(id);
    }
    issued
}

/// A long GET whose first DATA is sent and whose later reads stay held.
fn long_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[0].get(key(1), 0, 1 << 20, now, super::WAIT_US) {
        Ok(id) => {
            world.history.ids.push(id);
            world.history.hold_reads = true;
            world.history.pass = 1;
            1
        }
        Err(_) => STAY,
    }
}

fn data_withheld(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .scene
        .nets
        .iter()
        .any(|net| net.borrow().withheld() > 0)
        && !world.history.held.is_empty()
}

/// The owner polled since the history closed or stopped it, so the poll
/// that releases requests as reads drain and sends has run before the
/// custody check.
fn owner_polled(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.owner_polls > world.history.polls_at_close
}

fn close_owner(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.polls_at_close = world.owner_polls;
    world.history.refs = withheld(world);
    world.history.sent = world.scene.owner.report().sent;
    world.history.kept = u64::from(world.scene.owner.census().live());
    let _ = world.scene.owner.close(now);
    world.closed = true;
    mark(world, "owner closed with DATA in flight")
}

/// A control: the withheld DATA references return at close.
fn close_releasing(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let closed = close_owner(world, now);
    for net in &world.scene.nets {
        net.borrow_mut().release_tx();
    }
    closed
}

/// A control: the device posts the held reads' completions at close, as a
/// close that dropped the reads it still held would leave it.
fn close_dropping_reads(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let closed = close_owner(world, now);
    for &token in &world.history.held {
        world.scene.control.release(token);
        world.scene.control.post(token);
    }
    closed
}

/// After close, every accepted frame's reference is still held, every held
/// read and write stays pending, the owner keeps its requests, and it sends
/// nothing more.
fn close_retained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = withheld(world);
    let live = u64::from(world.scene.owner.census().live());
    if held < world.history.refs || !commands_pending(world) || live < world.history.kept {
        return fail(
            world,
            Obligation::Custody,
            "a close released DATA the device still held",
        );
    }
    if world.scene.owner.report().sent != world.history.sent {
        return fail(world, Obligation::Custody, "a closed owner kept sending");
    }
    mark(world, "close retained DATA and stopped sends")
}

/// When `world.history.sent` is positive, the control lowers the baseline
/// by one to simulate a post-close send.
fn close_retained_sent_after(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.sent = world.history.sent.saturating_sub(1);
    close_retained(world, now)
}

fn release_everything(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.released_at = now;
    release_reads(world, now);
    world.history.hold_nic = false;
    mark(world, "holds released")
}

/// Transmit references every link still holds: those of queued datagrams
/// and of delivered ones no sender has reclaimed, returnable or withheld.
fn nic_held(world: &Mixed<'_, '_, '_>) -> usize {
    world
        .scene
        .nets
        .iter()
        .map(|net| net.borrow().nic_held())
        .sum()
}

/// Every reference reclaimed and every command ended, or the bound since
/// the holds' release passed.
fn released_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    let released = nic_held(world) == 0 && world.scene.control.outstanding() == 0;
    released || now > world.history.released_at + BOUND_US
}

/// Every device-held DATA reference was reclaimed by its sender once its
/// hold ended, and the device holds zero commands.
fn released_in_domain(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if nic_held(world) != 0 || world.scene.control.outstanding() != 0 {
        return fail(
            world,
            Obligation::Resources,
            "a custody domain kept a reference after its proof",
        );
    }
    mark(world, "each custody domain released after its proof")
}

/// Ends the device holds; a transmit hold stays armed.
fn release_device(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.released_at = now;
    release_reads(world, now);
    mark(world, "holds released")
}

fn device_drained(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.control.outstanding() == 0
}

/// The release check runs in the same turn after all withheld references
/// become returnable and before any sender reclaims one.
fn released_unreclaimed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if withheld(world) > 0 {
        mark(world, "transmit references withheld at the release check");
    }
    for net in &world.scene.nets {
        let mut net = net.borrow_mut();
        while net.withheld() > 0 {
            net.return_tx(0);
        }
    }
    world.history.hold_nic = false;
    released_in_domain(world, now)
}

/// The GET client holds two GETs whose reads stay held, filling its share.
fn saturate(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[1].get(key(1), 0, 1 << 20, now, super::WAIT_US) {
        Ok(id) => {
            world.history.ids.push(id);
            if world.history.ids.len() == 2 {
                mark(world, "share saturated")
            } else {
                STAY
            }
        }
        Err(_) => STAY,
    }
}

fn reads_held(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.history.held.len() >= 2
}

/// A third GET past the saturated share: it waits in the client or is
/// refused, and either outcome is marked.
fn over_share(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[1].get(key(1), 0, 1 << 20, now, super::WAIT_US) {
        Ok(id) => {
            world.history.ids.push(id);
            mark(world, "a GET past the share waits in the client")
        }
        Err(_) => mark(world, "a GET past the share was refused"),
    }
}

fn peer_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[0].get(key(1), 0, 1 << 20, now, super::WAIT_US) {
        Ok(id) => {
            world.history.peer = Some(id);
            world.history.since = now;
            world.history.hold_reads = false;
            1
        }
        Err(_) => STAY,
    }
}

/// The peer's GET, issued while reads stay held, so in H4's control it
/// starves behind the saturated share.
fn peer_get_starved(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let issued = peer_get(world, now);
    world.history.hold_reads = true;
    issued
}

fn peer_decided_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    let decided = world
        .history
        .peer
        .is_some_and(|id| world.scene.clients[0].outcome(id).is_some());
    decided || now > world.history.since + BOUND_US
}

/// The other peer's GET completes exactly within the bound while the share
/// stays saturated.
fn peer_exact(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    peer_exact_charged(world, now, |world, peer| {
        world.scene.owner.peer_census(peer)
    })
}

/// A control: each datagram the link duplicated toward the owner is
/// charged to the saturating peer as a further grant.
fn peer_exact_duplicated(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let duplicated = world.scene.nets[1].borrow().report(1).duplicated as u32;
    peer_exact_charged(world, now, move |world, peer| {
        let mut census = world.scene.owner.peer_census(peer);
        census.active += u32::from(peer == PeerId(1)) * duplicated;
        census
    })
}

/// A control: the saturating peer's requests are read from the other
/// peer's share.
fn peer_exact_wrong_peer(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    peer_exact_charged(world, now, |world, peer| {
        world.scene.owner.peer_census(PeerId(1 - peer.0))
    })
}

/// The early return gives the world's read rule precedence over the
/// peer-read check.
fn judge_peer_read(world: &mut Mixed<'_, '_, '_>, outcome: Option<Outcome>, bytes: &[u8]) -> u64 {
    if outcome.is_some_and(|outcome| handout_misread(world, outcome, bytes)) {
        return 0;
    }
    if outcome != Some(Outcome::Complete) || bytes != version_a() {
        return fail(
            world,
            Obligation::Progress,
            "an eligible peer's GET starved behind a saturated share",
        );
    }
    1
}

/// Takes, drains and retires the peer's GET, with its drained bytes as
/// `alter` leaves them, and judges it as observed at `decided_at`: the
/// world's read check first, then a `Complete` with the resident's exact
/// bytes, then `decided_at` within `BOUND_US` of its issue. Each failed
/// check records its violation. Whether all three passed.
fn peer_read_in_bound(
    world: &mut Mixed<'_, '_, '_>,
    decided_at: u64,
    alter: impl FnOnce(&mut Vec<u8>),
) -> bool {
    let id = world.history.peer.take().expect("the peer's GET");
    let mut bytes = drain(&mut world.scene.clients[0], id);
    alter(&mut bytes);
    let outcome = world.collect_get(0, id);
    let _ = world.scene.clients[0].retire(id);
    if judge_peer_read(world, outcome, &bytes) == 0 {
        return false;
    }
    if decided_at > world.history.since + BOUND_US {
        fail(
            world,
            Obligation::Progress,
            "an eligible peer's GET starved behind a saturated share",
        );
        return false;
    }
    true
}

/// The other peer's GET completes exactly within the bound while the share
/// stays saturated, and each peer's charge, read by `charged`, holds only
/// its own live requests within its share: the saturating peer its held
/// GETs, the other peer at most its completed GET while it drains.
/// Judges the peer's GET as observed at `decided_at`: it completed exactly
/// within `BOUND_US` of its issue, and each peer's charge stayed in its share.
fn peer_exact_charged(
    world: &mut Mixed<'_, '_, '_>,
    decided_at: u64,
    charged: impl Fn(&Mixed<'_, '_, '_>, PeerId) -> PeerCensus,
) -> u64 {
    if !peer_read_in_bound(world, decided_at, |_| ()) {
        return 0;
    }
    let saturating = charged(world, PeerId(1));
    let other = charged(world, PeerId(0));
    let held = (saturating.active + saturating.draining) as usize;
    if held > super::OWNER.peer_requests as usize || held < world.history.ids.len().min(2) {
        return fail(
            world,
            Obligation::Resources,
            "a peer's charge left its live requests or its share",
        );
    }
    // The completed GET may still drain while its references return.
    if other.active != 0 || other.draining > 1 {
        return fail(
            world,
            Obligation::Resources,
            "a peer's charge left its live requests or its share",
        );
    }
    mark(world, "eligible peer progressed");
    mark(world, "charges stayed within the share")
}

fn saturated_drained(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .ids
        .iter()
        .all(|&id| world.scene.clients[1].outcome(id).is_some())
}

/// Each saturating GET completes exactly once healed.
fn saturated_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let mut exact = true;
    for (at, id) in world.history.ids.clone().into_iter().enumerate() {
        let bytes = drain(&mut world.scene.clients[1], id);
        let outcome = world.collect_get(1, id);
        let refused = matches!(outcome, Some(Outcome::Pressure(_))) && bytes.is_empty();
        exact &= outcome == Some(Outcome::Complete) && bytes == version_a() || at >= 2 && refused;
        let _ = world.scene.clients[1].retire(id);
    }
    if !exact {
        return fail(
            world,
            Obligation::Resources,
            "a healed saturated GET missed its exact bytes",
        );
    }
    mark(world, "qualified exact read")
}

fn read_held(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    !world.history.held.is_empty()
}

/// Stops the owner without proof: the device never quiesces.
fn unproven_stop(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.scene.control.set_quiesce(QuiesceMode::Unproven);
    stop(world, now)
}

/// The error code a failed stop's device reports.
const FAILED_STOP: i32 = -5;

/// A stop the device reports failed: like an unproven stop, it proves no
/// command ended.
fn failed_stop(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world
        .scene
        .control
        .set_quiesce(QuiesceMode::Failed(Some(FAILED_STOP)));
    stop(world, now)
}

/// A control: the stop treats the frames' delivery as ending NIC custody,
/// so every withheld transmit reference returns at the stop.
fn stop_releasing(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.scene.control.set_quiesce(QuiesceMode::Unproven);
    let stopped = stop(world, now);
    for net in &world.scene.nets {
        net.borrow_mut().release_tx();
    }
    stopped
}

/// A proven stop: the device drops every command and reports it stopped.
fn reset_stop(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.scene.control.set_quiesce(QuiesceMode::Reset);
    stop(world, now)
}

/// A proven stop ends exactly its device custody: no command stays on the
/// device, and every transmit reference the links withheld stays withheld.
fn reset_ended(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if world.scene.control.outstanding() != 0 {
        return fail(
            world,
            Obligation::Custody,
            "a proven stop kept a command on the device",
        );
    }
    if withheld(world) < world.history.refs {
        return fail(
            world,
            Obligation::Custody,
            "a device stop ended the links' custody",
        );
    }
    mark(world, "the proven stop ended its device custody")
}

/// When `withheld(world)` is below its type's maximum, the control sets
/// `world.history.refs` one above that count to simulate a released
/// reference.
fn reset_ended_released(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.refs = withheld(world).saturating_add(1);
    reset_ended(world, now)
}

fn stop(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.polls_at_close = world.owner_polls;
    world.history.refs = withheld(world);
    world.history.kept = u64::from(world.scene.owner.census().live());
    if world.history.refs > 0 {
        mark(world, "transmit references withheld at stop");
    }
    let progress = world.scene.owner.close(now);
    world.closed = true;
    if matches!(
        progress,
        crate::storage::QuiesceProgress::Unproven {
            code: Some(FAILED_STOP),
            ..
        }
    ) {
        mark(world, "the device reported a failed stop");
    }
    if world.history.held.is_empty() {
        return 1;
    }
    mark(world, "owner stopped with a read held")
}

/// Commands the device holds.
fn custody(world: &Mixed<'_, '_, '_>) -> u64 {
    world.scene.control.outstanding() as u64
}

/// Transmit references every link withholds.
fn withheld(world: &Mixed<'_, '_, '_>) -> u64 {
    world
        .scene
        .nets
        .iter()
        .map(|net| net.borrow().withheld() as u64)
        .sum()
}

/// An unproven or failed stop ends no custody: every command the history
/// held stays pending on the device, every transmit reference stays
/// withheld, and the owner keeps its requests. A successful history reaches
/// the stop with a held read or write.
fn stop_retained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let live = world.scene.owner.census().live();
    judge_stop(world, live)
}

/// A control: the owner's requests are read as released at the failed
/// stop, as an owner treating the stop as quiesced would leave them.
fn stop_released(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_stop(world, 0)
}

fn judge_stop(world: &mut Mixed<'_, '_, '_>, live: u32) -> u64 {
    if world.history.held.is_empty() && world.history.writes.is_empty() {
        world.first.record(Failure::Unsuccessful("old read held"));
        return 0;
    }
    let owner_kept = u64::from(live) >= world.history.kept;
    if !commands_pending(world)
        || custody(world) == 0
        || withheld(world) < world.history.refs
        || !owner_kept
    {
        return fail(
            world,
            Obligation::Custody,
            "a stop without proof ended custody",
        );
    }
    mark(world, "the stop retained its custody")
}

fn sources_withheld(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.nets[0].borrow().withheld() > 0
}

/// After close, the upload's DATA references are still held and its result
/// stays undecided or unknown: neither the close nor a receipt publishes it.
fn upload_retained(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    judge_retained(world, now, outcome)
}

/// A control: the upload's receipt ACK is taken as its publication.
fn upload_acked(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_retained(world, now, Some(UploadOutcome::Published))
}

fn judge_retained(world: &mut Mixed<'_, '_, '_>, now: u64, outcome: Option<UploadOutcome>) -> u64 {
    let retained = close_retained(world, now);
    if retained == 0 {
        return 0;
    }
    match outcome {
        None | Some(UploadOutcome::Unknown) => mark(world, "the upload stayed unknown at close"),
        Some(_) => fail(
            world,
            Obligation::History,
            "a closed owner settled an upload from its receipt",
        ),
    }
}

/// The owner acknowledged every fragment of the upload's DATA.
fn receipt_acked(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .put
        .and_then(|id| world.scene.clients[0].put_receipt(id))
        .is_some_and(|(_, base, _)| base >= 1)
}

fn mark_receipt(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "upload receipt acknowledged")
}

fn mark_source_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, "upload DATA held by the device")
}

/// A stalled upload: begun and prepared, its DATA withheld by its
/// supplier, the owner keeps a live request for it.
fn stalled(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if world.scene.owner.census().live() == 0 {
        return fail(
            world,
            Obligation::Resources,
            "a stalled upload's request was not charged",
        );
    }
    mark(world, "upload stalled before its DATA")
}

/// The control begins the upload and judges its stall in the same step,
/// before any turn delivers the upload's BEGIN to the owner.
fn put_begin_judged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if put_begin(world, now) == STAY {
        return STAY;
    }
    stalled(world, now)
}

/// The other peer's GET beside the stalled upload, issued at `since` so
/// its completion is held to the bound.
fn peer_old_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let issued = old_get(world, now);
    if issued != STAY {
        world.history.since = now;
    }
    issued
}

/// A control: the peer's reads stay held, so its GET starves beside the
/// stalled upload.
fn peer_old_get_starved(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let issued = peer_old_get(world, now);
    world.history.hold_reads = true;
    issued
}

fn old_decided_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    old_decided(world, now) || now > world.history.since + BOUND_US
}

/// The other peer's GET completes exactly beside the stalled upload within
/// the bound of its issue.
fn peer_beside_stall(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the peer's GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    judge_beside_stall(world, now, outcome, &bytes)
}

/// The control models starvation beside the stalled upload by treating the
/// peer's GET as timing out before receiving any bytes.
fn peer_beside_stall_timed_out(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.read(1);
    judge_beside_stall(world, now, Some(Outcome::Failed(Status::TimedOut)), &[])
}

/// Judges the peer's read as observed at `decided_at`: exact, and within
/// `BOUND_US` of the GET's issue at `since`.
fn judge_beside_stall(
    world: &mut Mixed<'_, '_, '_>,
    decided_at: u64,
    outcome: Option<Outcome>,
    bytes: &[u8],
) -> u64 {
    if !exact_within(world, decided_at, outcome, bytes) {
        return fail(
            world,
            Obligation::Progress,
            "an eligible peer's GET starved beside a stalled upload",
        );
    }
    mark(world, "eligible peer progressed")
}

fn exact_within(
    world: &Mixed<'_, '_, '_>,
    decided_at: u64,
    outcome: Option<Outcome>,
    bytes: &[u8],
) -> bool {
    decided_at <= world.history.since + BOUND_US
        && outcome == Some(Outcome::Complete)
        && bytes == version_a()
}

const fn step(
    name: &'static str,
    ready: fn(&Mixed<'_, '_, '_>, u64) -> bool,
    run: fn(&mut Mixed<'_, '_, '_>, u64) -> u64,
) -> Step {
    Step { name, ready, run }
}

const JUDGE: Step = step("judge", always, judge);

/// H1 for GET: an old read and its DATA references held across an
/// acknowledged invalidation, a fresh miss and a replacement's publication;
/// the old right returns its own version and a later GET the replacement.
const H1_GET: [Step; 14] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held_or_done, mark_read_held),
    step("invalidate", always, invalidate),
    step("fresh-get", active_put, fresh_get),
    step("fresh-miss", fresh_decided, fresh_missed),
    step("fill-replacement", always, fill_b),
    step("publish-replacement", fill_written, publish_fill),
    step("release-old-read", always, release_reads),
    step("old-right", old_decided, old_exact),
    step("release-nic", always, release_nic),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const fn joined<const P: usize, const S: usize, const N: usize>(
    prefix: [Step; P],
    suffix: [Step; S],
) -> [Step; N] {
    assert!(P + S == N, "the script holds its prefix and suffix");
    let mut out = [JUDGE; N];
    let mut at = 0;
    while at < N {
        out[at] = if at < P { prefix[at] } else { suffix[at - P] };
        at += 1;
    }
    out
}

/// `script` with its step named `name` replaced by `with`; a name the
/// script lacks fails the build.
const fn replaced<const N: usize>(script: [Step; N], name: &str, with: Step) -> [Step; N] {
    let mut out = script;
    let mut at = 0;
    while at < N {
        if same(out[at].name.as_bytes(), name.as_bytes()) {
            out[at] = with;
            return out;
        }
        at += 1;
    }
    panic!("a control replaces a step its script lacks");
}

const fn same(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut at = 0;
    while at < left.len() {
        if left[at] != right[at] {
            return false;
        }
        at += 1;
    }
    true
}

const H1_GET_STALE: [Step; 14] = replaced(
    H1_GET,
    "fill-replacement",
    step("fill-stale", always, fill_stale),
);
const H1_GET_REUSED: [Step; 14] = replaced(
    H1_GET,
    "old-right",
    step("old-right-reused", old_decided, old_reused),
);

/// A step a falsifier removes: it issues nothing, holds nothing and marks
/// nothing.
fn removed_step(_: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    1
}

/// H1 built from one request less: the fresh GET and its miss removed.
const H1_GET_ONE_REQUEST: [Step; 14] = replaced(
    replaced(
        H1_GET,
        "fresh-get",
        step("fresh-get-removed", always, removed_step),
    ),
    "fresh-miss",
    step("fresh-miss-removed", always, removed_step),
);

const H1_GET_UNHELD: [Step; 14] =
    replaced(H1_GET, "arm", step("arm-nothing", always, removed_step));

/// A control: the fresh GET is judged as one after the acknowledged
/// invalidation, which never ran, so the key still maps the old version and
/// the fresh GET reads it.
const H1_GET_UNINVALIDATED: [Step; 14] = replaced(
    H1_GET,
    "invalidate",
    step("invalidate-skipped", always, invalidation_skipped),
);

/// When the second `invalidate` call returns a nonzero value, the history
/// resumes `H1_GET` at `fresh_get`.
const H1_GET_INVALIDATED_TWICE: [Step; 14] = replaced(
    H1_GET,
    "fresh-get",
    step("invalidate-again", active_put, invalidate_then_get),
);

fn invalidate_then_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if invalidate(world, now) == 0 {
        return 0;
    }
    fresh_get(world, now)
}

const H1_GET_PUBLISH_REVOKED: [Step; 14] = replaced(
    H1_GET,
    "publish-replacement",
    step(
        "publish-revoked",
        fill_written,
        invalidate_then_publish_fill,
    ),
);

/// The most fills of other keys the crowded H1 history publishes: twice
/// the fixture storage's eight slots.
const H1_MOST_OTHERS: usize = 16;

/// World time the history gives the owner's maintenance after the
/// invalidation.
const H1_MAINTENANCE_US: u64 = 20_000;

/// Acknowledges the invalidation of key 1 and has the run reach the end of
/// the maintenance time.
fn invalidate_then_wait(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.since = now;
    world.history.wake = Some(now + H1_MAINTENANCE_US);
    invalidate(world, now)
}

fn maintenance_passed(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now >= world.history.since + H1_MAINTENANCE_US
}

/// The maintenance time counts only while the device still holds the old
/// read.
fn maintained(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let held = !world.history.held.is_empty() && !old_decided(world, now);
    premised(world, held, "owner maintenance ran after the invalidation")
}

/// Other keys' fills the history published so far.
fn others_published(world: &Mixed<'_, '_, '_>) -> usize {
    world
        .history
        .marks
        .iter()
        .filter(|&&mark| mark == "another key's fill written and published")
        .count()
}

/// The key, label and bytes of the other key's object number `n`, as long
/// as the old version.
fn other_object(n: usize) -> ([u8; 32], Label, Vec<u8>) {
    let name = 100 + n as u8;
    (
        key(name),
        Label(u64::from(name)),
        payload(version_a().len(), u64::from(name)),
    )
}

/// No fill of the history is in flight, or the device wrote the one that
/// is.
fn fill_settled(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    world.history.fill.is_none() || fill_written(world, now)
}

/// Publishes the written fill of another key, if one is in flight, then
/// begins the next key's fill and hands the owner its bytes. The step
/// repeats until the store grants no fill or [`H1_MOST_OTHERS`] were
/// published. Each object is as long as the old version, so any space the
/// invalidation freed fits one. Under some roots' index keys a publication
/// displaces an earlier one and the store never refuses, so the fills also
/// end at their bound.
fn fill_others(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if let Some(written) = world.history.fill.take() {
        let published = world.scene.owner.publish_fill(
            written,
            ticks(now + 60 * super::SECOND_US),
            2,
            &mut budget(),
        );
        let formed = published.is_ok();
        world.history.lease = published.ok();
        world.owner_due = now;
        if premised(world, formed, "another key's fill written and published") == 0 {
            return 0;
        }
    }
    let published = others_published(world);
    if published == H1_MOST_OTHERS {
        return mark(world, "the store's free space went to other keys");
    }
    let (name, label, object) = other_object(published);
    let Some(mut next) = fill(world.storage(), &name, object.len()) else {
        return premised(
            world,
            published > 0,
            "the store's free space went to other keys",
        );
    };
    world
        .registry
        .borrow_mut()
        .register(name, label, 0, object.clone());
    let io = &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX);
    let mut taken = 0;
    while taken < object.len() {
        match world
            .scene
            .owner
            .receive_fill(&mut next, &object[taken..], io)
        {
            Ok(0) | Err(_) => break,
            Ok(count) => taken += count,
        }
    }
    world.history.fill = Some(next);
    STAY
}

/// Lets the transmit references return once the old GET was judged.
fn free_nic(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_nic = false;
    1
}

/// H1 with the freed space taken: the old read is held across the
/// acknowledged invalidation of its key and 20 ms of world time, so the
/// owner's maintenance runs with the removed mapping's extent no longer
/// reachable from the index. The owner then fills, writes and publishes
/// objects of other keys, one after another, until the store grants no
/// further fill or sixteen were published. The held read is released and
/// the old right must still end with its own version. A premise that does
/// not form ends the run unsuccessful under its name: the read held, the
/// invalidation acknowledged, the maintenance time passed with the read
/// still held, and the store's free space spent on other keys' fills, each
/// written and published.
const H1_GET_CROWDED: [Step; 10] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held_or_done, mark_read_held),
    step("invalidate", always, invalidate_then_wait),
    step("maintenance", maintenance_passed, maintained),
    step("fill-others", fill_settled, fill_others),
    step("release-old-read", always, release_reads),
    step("old-right", old_decided, old_exact),
    step("release-nic", always, free_nic),
    JUDGE,
];

/// The same steps without the other keys' fills.
const H1_GET_MAINTAINED: [Step; 9] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held_or_done, mark_read_held),
    step("invalidate", always, invalidate_then_wait),
    step("maintenance", maintenance_passed, maintained),
    step("release-old-read", always, release_reads),
    step("old-right", old_decided, old_exact),
    step("release-nic", always, free_nic),
    JUDGE,
];

const H1_GET_CROWDED_WITNESSES: &[&str] = &[
    "holds armed",
    "old read held",
    "invalidation acknowledged",
    "owner maintenance ran after the invalidation",
    "another key's fill written and published",
    "the store's free space went to other keys",
    "old read released",
    "old right returned its version",
];

const H1_GET_MAINTAINED_WITNESSES: &[&str] = &[
    "holds armed",
    "old read held",
    "invalidation acknowledged",
    "owner maintenance ran after the invalidation",
    "old read released",
    "old right returned its version",
];

/// The old right's bytes are the one check these two histories witness.
const H1_OLD_RIGHT: &[Obligation] = &[Obligation::Bytes];

/// H1 for PUT: a remote upload of the replacement on the same key beside
/// the acknowledged invalidation, while the old read is held.
const H1_PUT: [Step; 14] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held_or_done, mark_read_held),
    step("invalidate", always, invalidate),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("put-result", put_decided, put_published),
    step("release-old-read", always, release_reads),
    step("old-right", old_decided, old_exact),
    step("release-nic", always, release_nic),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const H1_PUT_WRONG: [Step; 14] = replaced(
    H1_PUT,
    "put-supply",
    step("put-supply-wrong", always, put_supply_wrong),
);

/// A control: the upload's result is judged in place of its DATA supply,
/// once the upload is decided, so the result judged is that of an upload
/// that never had the bytes to publish.
const H1_PUT_JUDGED_UNSUPPLIED: [Step; 14] = replaced(
    H1_PUT,
    "put-supply",
    step("put-result-unsupplied", put_decided, put_published),
);

/// H2 for GET: a held read's GET cancelled, its request kept until the
/// read's late terminal, then a successor on the same wire slot at a higher
/// generation reading the resident version exactly.
const H2_GET: [Step; 10] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("cancel", always, cancel_old),
    step("cancel-kept", cancel_received, cancel_kept),
    step("release-old-read", always, release_reads),
    step("drained", drained, mark_drained),
    step("successor-get", active_get, successor_get),
    step("successor-read", successor_decided, successor_get_exact),
    JUDGE,
];

const H2_GET_STALE: [Step; 10] = replaced(
    H2_GET,
    "successor-get",
    step("successor-get-stale", active_get, successor_get_stale),
);

const H2_GET_UNCANCELLED: [Step; 10] = replaced(
    H2_GET,
    "cancel",
    step("cancel-unsent", always, cancel_unsent),
);

const H2_GET_SUCCESSOR_AS_CANCELLED: [Step; 10] = replaced(
    H2_GET,
    "successor-get",
    step(
        "successor-get-cancelled",
        active_get,
        successor_get_cancelled,
    ),
);

const H2_GET_EARLY: [Step; 10] = replaced(
    H2_GET,
    "cancel-kept",
    step("cancel-released", cancel_received, cancel_released),
);

/// H2 for PUT: an upload abandoned with its DATA accepted while the GET's
/// read is held; the upload's successor uploads again on a higher
/// generation and publishes.
const H2_PUT: [Step; 20] = [
    step("arm", always, arm_writes),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("write-held", write_held, mark_write_held),
    step("cancel-put", always, cancel_put),
    step("cancel-kept", cancel_received, cancel_kept),
    step("release-old-read", always, release_everything),
    step("cancelled-outcome", put_decided, cancelled_outcome),
    step("cancelled-drained", upload_drained, mark_drained),
    step("successor-put", active_put, successor_put),
    step("successor-prepare", always, put_prepare),
    step("successor-supply", always, successor_supply),
    step("successor-result", put_decided, put_published),
    step("returned", released_or_late, released_in_domain),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, successor_exact),
    JUDGE,
];

const H2_PUT_NO_EFFECT: [Step; 20] = replaced(
    H2_PUT,
    "cancelled-outcome",
    step("cancelled-no-effect", put_decided, cancelled_no_effect),
);

/// H3 for GET: a three-fragment GET with its first DATA accepted and its
/// references held, its later reads held, then a close before any suffix
/// retry; the close keeps every reference and sends nothing more, and each
/// reference returns only once its hold ends.
const H3_GET: [Step; 9] = [
    step("arm", always, arm_nic),
    step("fill-long", always, fill_long),
    step("publish-long", fill_written, publish_fill),
    step("long-get", active_put, long_get),
    step("close", data_withheld, close_owner),
    step("close-retained", owner_polled, close_retained),
    step("release", always, release_everything),
    step("returned", released_or_late, released_in_domain),
    JUDGE,
];

/// The premise the close of `H3_GET_READ` marks, and the name an
/// unsuccessful run carries when it fails to form.
const UNSENT: &str = "no transmit reference at the close";

/// Closes the owner while no link holds a transmit reference, so a held
/// read's drain proof alone keeps a request. A reference on a link is a
/// premise that failed to form.
fn close_unsent(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if nic_held(world) != 0 {
        world.first.record(Failure::Unsuccessful(UNSENT));
        return 0;
    }
    mark(world, UNSENT);
    close_owner(world, now)
}

/// H3 for a GET with its read alone held. An ended request leaves the
/// owner's table only when it holds no chunk, the NIC holds no reference to
/// its DATA, and the volume proves its read drained. `H3_GET` closes the
/// owner with a read and a transmit reference held together, so either of
/// the last two guards alone keeps its request. This script holds the GET's
/// first read, so the owner has no byte of the object to send, and the
/// drain proof is the only guard: after the close and one poll the held
/// read is still pending on the device and the owner keeps its requests.
const H3_GET_READ: [Step; 8] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("close", always, close_unsent),
    step("close-retained", owner_polled, close_retained),
    step("release", always, release_everything),
    step("returned", released_or_late, released_in_domain),
    JUDGE,
];

/// The sibling: every hold ends before the close, which waits until the
/// device drained and each link's transmit references returned. The GET's
/// request has left by then, so the two scripts differ at the close only in
/// the read the device holds, and the closed owner has no request to keep.
const H3_GET_READ_DRAINED: [Step; 8] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held, mark_read_held),
    step("release", always, release_everything),
    step("close", released_or_late, close_unsent),
    step("close-retained", owner_polled, close_retained),
    step("returned", released_or_late, released_in_domain),
    JUDGE,
];

const H3_GET_RELEASING: [Step; 9] = replaced(
    H3_GET,
    "close",
    step("close-releasing", data_withheld, close_releasing),
);

const H3_GET_SENT_AFTER_CLOSE: [Step; 9] = replaced(
    H3_GET,
    "close-retained",
    step(
        "close-retained-sent-after",
        owner_polled,
        close_retained_sent_after,
    ),
);

const H3_GET_DROPPING: [Step; 9] = replaced(
    H3_GET,
    "close",
    step("close-dropping", data_withheld, close_dropping_reads),
);

const H3_GET_UNRECLAIMED: [Step; 9] = replaced(
    replaced(
        H3_GET,
        "release",
        step("release-device", always, release_device),
    ),
    "returned",
    step("returned-unreclaimed", device_drained, released_unreclaimed),
);

/// H4 for GET: one peer's share saturated by two GETs whose reads stay
/// held and a third issued past it, while the other peer's GET completes
/// exactly within the bound; healed, the saturating GETs complete exactly.
const H4_GET: [Step; 10] = [
    step("arm", always, arm_duplicates),
    step("saturate", active_get, saturate),
    step("reads-held", reads_held, |world, _| {
        mark(world, "saturating reads held")
    }),
    step("over-share", always, over_share),
    step("peer-get", active_put, peer_get),
    step("peer-read", peer_decided_or_late, peer_exact),
    step("release", always, release_everything),
    step("healed", saturated_drained, saturated_exact),
    step("nic", released_or_late, released_in_domain),
    JUDGE,
];

/// Every frame between the saturating peer and the owner is duplicated,
/// so each request, receipt and ACK arrives twice.
fn arm_duplicates(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let duplicated = super::super::link::Faults {
        duplicate: 100,
        ..Default::default()
    };
    let mut net = world.scene.nets[1].borrow_mut();
    net.set_faults(0, duplicated);
    net.set_faults(1, duplicated);
    drop(net);
    arm(world, now)
}

const H4_GET_DUPLICATED: [Step; 10] = replaced(
    H4_GET,
    "peer-read",
    step(
        "peer-read-duplicated",
        peer_decided_or_late,
        peer_exact_duplicated,
    ),
);

const H4_GET_WRONG_PEER: [Step; 10] = replaced(
    H4_GET,
    "peer-read",
    step(
        "peer-read-wrong-peer",
        peer_decided_or_late,
        peer_exact_wrong_peer,
    ),
);

const H4_GET_STARVED: [Step; 10] = replaced(
    H4_GET,
    "peer-get",
    step("peer-get-starved", active_put, peer_get_starved),
);

/// H5 for GET: a long GET's first DATA sent with its references withheld
/// and a later read held before an unproven stop; the stop retains the
/// read, the DATA references and the request.
const H5_GET: [Step; 8] = [
    step("arm", always, arm_nic),
    step("fill-long", always, fill_long),
    step("publish-long", fill_written, publish_fill),
    step("long-get", active_put, long_get),
    step("old-read-held", data_withheld, mark_read_held),
    step("stop", always, unproven_stop),
    step("stop-retained", owner_polled, stop_retained),
    JUDGE,
];

/// H5 with a proven stop: the reset ends exactly the device custody of the
/// held read and keeps the links' DATA references.
const H5_GET_RESET: [Step; 8] = replaced(
    replaced(H5_GET, "stop", step("stop", always, reset_stop)),
    "stop-retained",
    step("stop-ended", owner_polled, reset_ended),
);

const H5_GET_RESET_RELEASING: [Step; 8] = replaced(
    H5_GET_RESET,
    "stop-ended",
    step("stop-ended-released", owner_polled, reset_ended_released),
);

/// A control: the stop judged as proven is an unproven one, so the device
/// keeps the one held read.
const H5_GET_RESET_UNPROVEN: [Step; 8] = replaced(
    H5_GET_RESET,
    "stop",
    step("stop-unproven", always, unproven_stop),
);

const H5_GET_NO_READ: [Step; 8] = replaced(
    replaced(
        H5_GET,
        "long-get",
        step("long-get-removed", always, removed_step),
    ),
    "old-read-held",
    step("old-read-held-removed", always, removed_step),
);

/// H5 with a failed stop: the stop retains the read's custody as an
/// unproven one does.
const H5_GET_FAILED_STOP: [Step; 8] =
    replaced(H5_GET, "stop", step("failed-stop", always, failed_stop));

const H5_GET_RELEASING: [Step; 8] = replaced(
    H5_GET,
    "stop",
    step("stop-releasing", always, stop_releasing),
);

const H5_GET_FAILED: [Step; 8] = replaced(
    H5_GET_FAILED_STOP,
    "stop-retained",
    step("failed-as-quiesced", owner_polled, stop_released),
);

/// H3 for PUT: an upload's DATA accepted with its device references held
/// when the owner closes; the close keeps them, the upload stays unknown,
/// and each reference returns only once its hold ends.
const H3_PUT: [Step; 12] = [
    step("arm", always, arm_nic_writes),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("source-held", sources_withheld, mark_source_held),
    step("write-held", write_held, mark_write_held),
    step("receipt-acked", receipt_acked, mark_receipt),
    step("close", always, close_owner),
    step("close-retained", owner_polled, upload_retained),
    step("release", always, release_everything),
    step("returned", released_or_late, released_in_domain),
    JUDGE,
];

const H3_PUT_RELEASING: [Step; 12] = replaced(
    H3_PUT,
    "close",
    step("close-releasing", always, close_releasing),
);

const H3_PUT_ACKED: [Step; 12] = replaced(
    H3_PUT,
    "close-retained",
    step("close-acked", owner_polled, upload_acked),
);

/// H4 mixed: a stalled upload keeps its request live while
/// the other peer's GET completes exactly within the bound; healed, the
/// upload publishes and a GET reads it exactly.
const H4_PUT: [Step; 10] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("stalled", always, stalled),
    step("peer-get", active_get, peer_old_get),
    step("peer-read", old_decided_or_late, peer_beside_stall),
    step("put-supply", always, put_supply),
    step("put-result", put_decided, put_published),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

/// The control judges the stall while the upload's BEGIN awaits delivery
/// to the owner.
const H4_PUT_JUDGED_AT_BEGIN: [Step; 10] = replaced(
    H4_PUT,
    "put-begin",
    step("put-begin-judged", active_put, put_begin_judged),
);

const H4_PUT_TIMED_OUT: [Step; 10] = replaced(
    H4_PUT,
    "peer-read",
    step(
        "peer-read-timed-out",
        old_decided_or_late,
        peer_beside_stall_timed_out,
    ),
);

const H4_PUT_STARVED: [Step; 10] = replaced(
    H4_PUT,
    "peer-get",
    step("peer-get-starved", active_get, peer_old_get_starved),
);

/// H5 for PUT: an upload's DATA held by the device and a GET's read held
/// before an unproven stop; the stop retains both.
const H5_PUT: [Step; 12] = [
    step("arm", always, arm_writes),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("source-held", sources_withheld, mark_source_held),
    step("write-held", write_held, mark_write_held),
    step("receipt-acked", receipt_acked, mark_receipt),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held_or_done, mark_read_held),
    step("stop", always, unproven_stop),
    step("stop-retained", owner_polled, stop_retained),
    JUDGE,
];

const H5_PUT_NO_READ: [Step; 12] = replaced(
    H5_PUT,
    "old-get",
    step("old-get-removed", always, removed_step),
);

const H5_PUT_ACKED: [Step; 12] =
    replaced(H5_PUT, "stop", step("stop-acked", always, stop_releasing));

const H5_PUT_FAILED_STOP: [Step; 12] =
    replaced(H5_PUT, "stop", step("failed-stop", always, failed_stop));

const H5_PUT_FAILED: [Step; 12] = replaced(
    H5_PUT_FAILED_STOP,
    "stop-retained",
    step("failed-as-quiesced", owner_polled, stop_released),
);

/// H5 for PUT with a proven stop: the reset ends the device custody of the
/// held read and write while the links keep the upload's DATA references.
const H5_PUT_RESET: [Step; 12] = replaced(
    replaced(H5_PUT, "stop", step("stop", always, reset_stop)),
    "stop-retained",
    step("stop-ended", owner_polled, reset_ended),
);

const HANDED_OUT: &str = "a prefix was handed out with later reads held";
const ENDED_AFTER_HANDOUT: &str = "the GET ended with no further fragment";
const INCOMPLETE_OVER_PREFIX: &str = "the ended GET is Incomplete over its prefix";

/// Marks `witness` when `formed`, and otherwise ends the run unsuccessful
/// under it.
fn premised(world: &mut Mixed<'_, '_, '_>, formed: bool, witness: &'static str) -> u64 {
    if !formed {
        world.first.record(Failure::Unsuccessful(witness));
        return 0;
    }
    mark(world, witness)
}

/// The history's long GET.
fn handout_id(world: &Mixed<'_, '_, '_>) -> RequestId {
    *world.history.ids.last().expect("the long GET")
}

/// The hold caught a later read, which the owner submits once the first
/// read's bytes reached it, or the GET was decided, after which no fragment
/// arrives.
fn prefix_due(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    !world.history.held.is_empty() || fresh_decided(world, now)
}

/// Takes every fragment the client holds for the GET, in order. The step
/// waits while the undecided GET has delivered none. The premise forms when
/// the taken bytes are a nonempty, strict prefix by length of the published
/// object and the GET is still undecided with a later read held.
fn take_prefix(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = handout_id(world);
    collect(&mut world.scene.clients[0], id, &mut world.history.taken);
    let undecided = world.scene.clients[0].outcome(id).is_none();
    let taken = world.history.taken.len();
    if taken == 0 && undecided {
        return STAY;
    }
    let formed = taken > 0 && taken < LONG_B_LEN && undecided && !world.history.held.is_empty();
    premised(world, formed, HANDED_OUT)
}

/// The client cancels the GET; a GET its own deadline decided first ended
/// the same way, with no fragment after the prefix.
fn cancel_after_handout(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = handout_id(world);
    world.scene.clients[0].cancel(id);
    world.history.since = now;
    let decided = world.scene.clients[0].outcome(id).is_some();
    premised(world, decided, ENDED_AFTER_HANDOUT)
}

/// The GET's outcome and every byte it handed out over the history; the
/// request then retires. `None` while the GET is undecided.
fn handout_ended(world: &mut Mixed<'_, '_, '_>) -> Option<(Outcome, Vec<u8>)> {
    let id = handout_id(world);
    collect(&mut world.scene.clients[0], id, &mut world.history.taken);
    let outcome = world.collect_get(0, id)?;
    let _ = world.scene.clients[0].retire(id);
    Some((outcome, std::mem::take(&mut world.history.taken)))
}

/// Records what the world's read check found: a violation through `fail`,
/// which counts it only with the premise witnessed.
fn misread_failed(world: &mut Mixed<'_, '_, '_>, failure: Failure) -> u64 {
    match failure {
        Failure::Violation(obligation, rule) => fail(world, obligation, rule),
        other => {
            world.first.record(other);
            0
        }
    }
}

/// Judges `outcome` and `bytes` as the world judges a decided GET of key 1
/// and records a failure that read check finds. Whether it found one.
fn handout_misread(world: &mut Mixed<'_, '_, '_>, outcome: Outcome, bytes: &[u8]) -> bool {
    let failure = super::misread(&world.registry.borrow(), &key(1), true, outcome, bytes);
    failure.is_some_and(|failure| {
        misread_failed(world, failure);
        true
    })
}

/// The ended GET's outcome and bytes are read and judged.
fn ended_incomplete(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some((outcome, bytes)) = handout_ended(world) else {
        return STAY;
    };
    judge_incomplete(world, outcome, &bytes)
}

/// A control: the judgment is handed the bytes the ended GET handed out
/// under a miss, which the world's read check fails.
fn ended_missing(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some((_, bytes)) = handout_ended(world) else {
        return STAY;
    };
    judge_incomplete(world, Outcome::Missing, &bytes)
}

/// The ended GET handed out bytes, so it is `Incomplete` and its bytes are
/// a prefix of the published object; a miss, a pressure refusal or a
/// failure with those bytes is the read check's violation.
fn judge_incomplete(world: &mut Mixed<'_, '_, '_>, outcome: Outcome, bytes: &[u8]) -> u64 {
    if handout_misread(world, outcome, bytes) {
        return 0;
    }
    let incomplete = matches!(outcome, Outcome::Incomplete(_)) && long_b().starts_with(bytes);
    premised(
        world,
        incomplete && !bytes.is_empty(),
        INCOMPLETE_OVER_PREFIX,
    )
}

/// The released GET's outcome and bytes are read and judged.
fn handout_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some((outcome, bytes)) = handout_ended(world) else {
        return STAY;
    };
    judge_exact(world, outcome, &bytes)
}

/// A control: the judgment is handed the released GET as one that ended
/// `Incomplete` over the first half of the bytes it handed out, an ending
/// the world's read check accepts.
fn handout_short(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some((_, bytes)) = handout_ended(world) else {
        return STAY;
    };
    judge_exact(
        world,
        Outcome::Incomplete(Status::Cancelled),
        &bytes[..bytes.len() / 2],
    )
}

/// With its reads released the GET completes, and the prefix with the
/// bytes taken after it is the published object.
fn judge_exact(world: &mut Mixed<'_, '_, '_>, outcome: Outcome, bytes: &[u8]) -> u64 {
    if handout_misread(world, outcome, bytes) {
        return 0;
    }
    if outcome != Outcome::Complete || bytes != long_b() {
        return fail(
            world,
            Obligation::History,
            "a qualified GET missed the visible version's exact bytes",
        );
    }
    mark(world, "qualified exact read")
}

/// H2 for a GET that handed bytes out: a three-fragment GET whose first
/// read runs while every later one is held, so only a prefix reaches the
/// client, which hands it to the application. The client then cancels the
/// GET, which must end `Incomplete` over a prefix of the published object,
/// never as a miss, a pressure refusal or a failure with bytes. The held
/// reads are released before the history ends, so the owner's request
/// drains.
const H2_GET_HANDOUT: [Step; 8] = [
    step("fill-long", always, fill_long),
    step("publish-long", fill_written, publish_fill),
    step("long-get", active_put, long_get),
    step("take-prefix", prefix_due, take_prefix),
    step("end", always, cancel_after_handout),
    step("outcome", fresh_decided, ended_incomplete),
    step("release", always, release_reads),
    JUDGE,
];

/// The sibling: the held reads are released in place of the cancel, the GET
/// completes, and the bytes taken before and after the release are the
/// published object exactly.
const H2_GET_HANDOUT_RELEASED: [Step; 8] = replaced(
    replaced(
        H2_GET_HANDOUT,
        "end",
        step("release-in-place", always, release_reads),
    ),
    "outcome",
    step("outcome", fresh_decided, handout_exact),
);

const H2_GET_HANDOUT_MISSING: [Step; 8] = replaced(
    H2_GET_HANDOUT,
    "outcome",
    step("outcome-missing", fresh_decided, ended_missing),
);

const H2_GET_HANDOUT_SHORT: [Step; 8] = replaced(
    H2_GET_HANDOUT_RELEASED,
    "outcome",
    step("outcome-short", fresh_decided, handout_short),
);

const H2_HANDOUT_PREMISE: &[&str] = &[HANDED_OUT, ENDED_AFTER_HANDOUT];
const H2_HANDOUT_RELEASED_PREMISE: &[&str] = &[HANDED_OUT];

const H2_HANDOUT_WITNESSES: &[&str] = &[
    "replacement published",
    HANDED_OUT,
    ENDED_AFTER_HANDOUT,
    INCOMPLETE_OVER_PREFIX,
    "old read released",
];

const H2_HANDOUT_RELEASED_WITNESSES: &[&str] = &[
    "replacement published",
    HANDED_OUT,
    "old read released",
    "qualified exact read",
];

/// What a history's run must end in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    Pass,
    /// The named check fails it with this rule.
    Violation(Obligation, &'static str),
    /// This declared witness or premise never fired. The text is printable
    /// ASCII of fewer than 41 bytes: a summary prints at most 41 bytes of
    /// an unsuccessful rule, and a sweep credits the ending only when the
    /// printed text is shorter than that, which shows it was not cut, and
    /// equals the declaration.
    Unsuccessful(&'static str),
}

impl Expect {
    /// The first failure a run ending as declared records.
    fn failure(self) -> Option<Failure> {
        match self {
            Self::Pass => None,
            Self::Violation(obligation, rule) => Some(Failure::Violation(obligation, rule)),
            Self::Unsuccessful(witness) => Some(Failure::Unsuccessful(witness)),
        }
    }
}

/// One composed history: its name, family, script, the witnesses its
/// marks must hold, the obligations it judges and what its run must end in.
pub(crate) struct History {
    pub(crate) name: &'static str,
    pub(super) script: &'static [Step],
    pub(super) witnesses: &'static [&'static str],
    pub(super) obligations: &'static [Obligation],
    pub(crate) expect: Expect,
    /// The marks a run must hold before `fail` records the history's
    /// declared violation, a control's kill or a pin's failure; a run that
    /// lacks one records the history Unsuccessful under it.
    pub(super) premise: &'static [&'static str],
    /// Uploads the script starts: the plan's `puts` budget, which admission
    /// holds against the manifest's `upload_attempts`.
    pub(super) uploads: u32,
    /// Source bytes the clients hold at once, which admission holds against
    /// the manifest's `source_bytes`.
    pub(super) source_bytes: u32,
    /// The plan's GET budget per client.
    pub(super) gets: [u32; 2],
    /// Owner relaunches the script runs. Admission compares them with the
    /// manifest's `restarts`, and compares the one dead bundle a
    /// relaunching script holds with its `bundles`.
    pub(super) relaunches: u32,
    /// A peer owner runs beside the scripted one, whose actors admission
    /// holds against the manifest's `actors`.
    pub(super) peer_owner: bool,
    /// The storage the scripted owner serves from.
    pub(super) geometry: super::Geometry,
    /// Write commands the owner's PUT core may submit in one turn, the
    /// owner's own value when `None`.
    pub(super) put_commands: Option<usize>,
    /// Source slots client 1 holds.
    pub(super) second_sources: u32,
}

const H1_WITNESSES: &[&str] = &[
    "old read held",
    "invalidation acknowledged",
    "fresh GET missed",
    "replacement published",
    "old right returned its version",
    "DATA references held past the old GET",
    "qualified exact read",
];
const H1_PUT_WITNESSES: &[&str] = &[
    "old read held",
    "invalidation acknowledged",
    "upload DATA supplied",
    "upload published",
    "old right returned its version",
    "DATA references held past the old GET",
    "qualified exact read",
];
const H2_WITNESSES: &[&str] = &[
    "old read held",
    "held read cancelled",
    "the owner ended the cancelled request",
    "cancel kept custody",
    "the cancelled request drained after its terminal",
    "successor reused the slot at a higher generation",
    "qualified exact read",
];
const H2_PUT_WITNESSES: &[&str] = &[
    "old read held",
    "upload DATA supplied",
    "owner write held",
    "upload cancelled with its DATA accepted",
    "the owner ended the cancelled request",
    "cancel kept custody",
    "the cancelled upload's outcome matched its phase",
    "the cancelled request drained after its terminal",
    "the successor upload took a fresh wire identity",
    "upload published",
    "each custody domain released after its proof",
    "qualified exact read",
];
const H3_WITNESSES: &[&str] = &[
    "replacement published",
    "owner closed with DATA in flight",
    "close retained DATA and stopped sends",
    "each custody domain released after its proof",
];
const H3_READ_WITNESSES: &[&str] = &[
    "old read held",
    UNSENT,
    "owner closed with DATA in flight",
    "close retained DATA and stopped sends",
    "each custody domain released after its proof",
];
const H3_READ_DRAINED_WITNESSES: &[&str] = &[
    "old read held",
    "old read released",
    UNSENT,
    "owner closed with DATA in flight",
    "close retained DATA and stopped sends",
    "each custody domain released after its proof",
];
const H4_WITNESSES: &[&str] = &[
    "share saturated",
    "saturating reads held",
    "eligible peer progressed",
    "charges stayed within the share",
    "qualified exact read",
];
const H3_PUT_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "upload DATA held by the device",
    "owner write held",
    "upload receipt acknowledged",
    "owner closed with DATA in flight",
    "close retained DATA and stopped sends",
    "the upload stayed unknown at close",
    "each custody domain released after its proof",
];
const H4_PUT_WITNESSES: &[&str] = &[
    "upload stalled before its DATA",
    "eligible peer progressed",
    "upload published",
    "qualified exact read",
];
const H5_PUT_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "upload DATA held by the device",
    "owner write held",
    "upload receipt acknowledged",
    "old read held",
    "owner stopped with a read held",
    "the stop retained its custody",
];
const H5_PUT_RESET_WITNESSES: &[&str] = &[
    "upload DATA held by the device",
    "owner write held",
    "old read held",
    "transmit references withheld at stop",
    "owner stopped with a read held",
    "the proven stop ended its device custody",
];
const H5_PUT_FAILED_WITNESSES: &[&str] = &[
    "upload DATA held by the device",
    "owner write held",
    "upload receipt acknowledged",
    "old read held",
    "the device reported a failed stop",
    "owner stopped with a read held",
    "the stop retained its custody",
];
const H5_FAILED_WITNESSES: &[&str] = &[
    "old read held",
    "transmit references withheld at stop",
    "the device reported a failed stop",
    "owner stopped with a read held",
    "the stop retained its custody",
];
const H5_RESET_WITNESSES: &[&str] = &[
    "old read held",
    "transmit references withheld at stop",
    "owner stopped with a read held",
    "the proven stop ended its device custody",
];
const H5_WITNESSES: &[&str] = &[
    "old read held",
    "transmit references withheld at stop",
    "owner stopped with a read held",
    "the stop retained its custody",
];

const H1: &[Obligation] = &[Obligation::Bytes, Obligation::History];
/// `H1` with `Progress`: the declaration of `h1-get-publish-revoked`, whose
/// violation fails the replacement's publication.
const H1_PROGRESS: &[Obligation] = &[Obligation::Bytes, Obligation::History, Obligation::Progress];
const CUSTODY: &[Obligation] = &[Obligation::Custody];
const CUSTODY_RESOURCES: &[Obligation] = &[Obligation::Custody, Obligation::Resources];
const CUSTODY_HISTORY: &[Obligation] = &[
    Obligation::Custody,
    Obligation::Resources,
    Obligation::History,
];
const H4: &[Obligation] = &[Obligation::Resources, Obligation::Progress];

const fn history(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    obligations: &'static [Obligation],
    expect: Expect,
) -> History {
    History {
        name,
        script,
        witnesses,
        obligations,
        expect,
        premise: &[],
        uploads: 0,
        source_bytes: super::OBJECT_LEN,
        gets: [0, 1],
        relaunches: 0,
        peer_owner: false,
        geometry: super::Geometry::Fixture,
        put_commands: None,
        second_sources: 0,
    }
}

/// `history` over the two-slot storage.
const fn cramped(history: History) -> History {
    History {
        geometry: super::Geometry::Cramped,
        ..history
    }
}

/// `Geometry::Warm` uses the fixture's shape and storage whose recovery limits admit a warm attach.
const fn warm(history: History) -> History {
    History {
        geometry: super::Geometry::Warm,
        ..history
    }
}

/// `history` over the sequence storage.
const fn sequenced(history: History) -> History {
    History {
        geometry: super::Geometry::Sequenced,
        ..history
    }
}

/// `history` over devices whose persistence unit is 16384 bytes.
const fn wide(history: History) -> History {
    History {
        geometry: super::Geometry::WideUnit,
        ..history
    }
}

/// `history` over the storage whose read share is one command.
const fn one_read_command(history: History) -> History {
    History {
        geometry: super::Geometry::OneReadCommand,
        ..history
    }
}

/// `history` whose script starts `uploads` uploads.
const fn uploading(history: History, uploads: u32) -> History {
    History { uploads, ..history }
}

/// `history` whose uploading client holds `source_bytes` at once.
const fn sourcing(history: History, source_bytes: u32) -> History {
    History {
        source_bytes,
        ..history
    }
}

/// `history` whose script relaunches the owner `relaunches` times.
const fn relaunching(history: History, relaunches: u32) -> History {
    History {
        relaunches,
        ..history
    }
}

/// `history` with a peer owner beside its scripted owner.
const fn paired(history: History) -> History {
    History {
        peer_owner: true,
        ..history
    }
}

const fn getting(history: History, gets: [u32; 2]) -> History {
    History { gets, ..history }
}

/// A control: `history` whose kill counts only once `premise` is marked.
const fn control(history: History, premise: &'static [&'static str]) -> History {
    History { premise, ..history }
}

impl History {
    /// `Ok` when `loaded` ended complete with the outcome and violation
    /// code this history declares and, for an unsuccessful ending, its first
    /// unsuccessful check records the whole declared witness. A record holds
    /// at most `PAYLOAD - 3` bytes of a witness, so a declared witness of
    /// that length or more is refused: its record cannot tell it from a
    /// longer text with the same prefix.
    pub(crate) fn ends_as_declared(&self, loaded: &Loaded) -> Result<(), String> {
        let Terminal::Complete { outcome, .. } = loaded.terminal else {
            return Err(format!("{}: {:?}", self.name, loaded.terminal));
        };
        let declared = match self.expect {
            Expect::Pass => (Ending::Pass, None),
            Expect::Violation(obligation, rule) => (
                Ending::Violation,
                Some(super::bundle::failure_code(&Failure::Violation(
                    obligation, rule,
                ))),
            ),
            Expect::Unsuccessful(_) => (Ending::Unsuccessful, None),
        };
        let witnessed = match self.expect {
            Expect::Unsuccessful(witness) => {
                witness.len() < crate::sim::trace::PAYLOAD - 3
                    && super::bundle::unsuccessful_rule(loaded).as_deref() == Some(witness)
            }
            Expect::Pass | Expect::Violation(..) => true,
        };
        if (outcome, loaded.violation) == declared && witnessed {
            return Ok(());
        }
        Err(format!(
            "{}: ended {outcome:?} {:?} {:?}, declared {:?}",
            self.name,
            loaded.violation,
            super::bundle::unsuccessful_rule(loaded),
            self.expect
        ))
    }
}

pub(crate) const HISTORIES: [History; 57] = [
    history("h1-get", &H1_GET, H1_WITNESSES, H1, Expect::Pass),
    control(
        history(
            "h1-get-stale",
            &H1_GET_STALE,
            H1_WITNESSES,
            H1,
            Expect::Violation(
                Obligation::History,
                "a qualified GET missed the visible version's exact bytes",
            ),
        ),
        &[
            "old read held",
            "invalidation acknowledged",
            "fresh GET missed",
            "replacement published",
        ],
    ),
    control(
        history(
            "h1-get-reused",
            &H1_GET_REUSED,
            H1_WITNESSES,
            H1,
            Expect::Violation(
                Obligation::Bytes,
                "the old right returned bytes other than its own version",
            ),
        ),
        &["old read held", "invalidation acknowledged"],
    ),
    history(
        "h1-get-unheld",
        &H1_GET_UNHELD,
        H1_WITNESSES,
        H1,
        Expect::Unsuccessful("old read held"),
    ),
    history(
        "h1-get-one-request",
        &H1_GET_ONE_REQUEST,
        H1_WITNESSES,
        H1,
        Expect::Unsuccessful("fresh GET missed"),
    ),
    control(
        history(
            "h1-get-held-across-other-fills",
            &H1_GET_CROWDED,
            H1_GET_CROWDED_WITNESSES,
            H1_OLD_RIGHT,
            Expect::Pass,
        ),
        &[
            "old read held",
            "invalidation acknowledged",
            "owner maintenance ran after the invalidation",
            "another key's fill written and published",
            "the store's free space went to other keys",
        ],
    ),
    control(
        history(
            "h1-get-held-across-maintenance",
            &H1_GET_MAINTAINED,
            H1_GET_MAINTAINED_WITNESSES,
            H1_OLD_RIGHT,
            Expect::Pass,
        ),
        &[
            "old read held",
            "invalidation acknowledged",
            "owner maintenance ran after the invalidation",
        ],
    ),
    uploading(
        history("h1-put", &H1_PUT, H1_PUT_WITNESSES, H1, Expect::Pass),
        1,
    ),
    control(
        uploading(
            history(
                "h1-put-wrong",
                &H1_PUT_WRONG,
                H1_PUT_WITNESSES,
                H1,
                Expect::Violation(
                    Obligation::History,
                    "a qualified GET missed the visible version's exact bytes",
                ),
            ),
            1,
        ),
        &[
            "old read held",
            "invalidation acknowledged",
            "upload published",
        ],
    ),
    history(
        "h2-get",
        &H2_GET,
        H2_WITNESSES,
        CUSTODY_HISTORY,
        Expect::Pass,
    ),
    control(
        history(
            "h2-get-early",
            &H2_GET_EARLY,
            H2_WITNESSES,
            CUSTODY_HISTORY,
            Expect::Violation(
                Obligation::Custody,
                "a cancel released custody before the read's terminal",
            ),
        ),
        &[
            "old read held",
            "held read cancelled",
            "the device held the cancelled request's commands at its check",
        ],
    ),
    control(
        history(
            "h2-get-stale",
            &H2_GET_STALE,
            H2_WITNESSES,
            CUSTODY_HISTORY,
            Expect::Violation(
                Obligation::History,
                "a successor took its predecessor's wire identity",
            ),
        ),
        &[
            "old read held",
            "held read cancelled",
            "cancel kept custody",
            "the cancelled request drained after its terminal",
        ],
    ),
    history(
        "h2-get-uncancelled",
        &H2_GET_UNCANCELLED,
        H2_WITNESSES,
        CUSTODY_HISTORY,
        Expect::Unsuccessful("the owner ended the cancelled request"),
    ),
    uploading(
        history(
            "h2-put",
            &H2_PUT,
            H2_PUT_WITNESSES,
            CUSTODY_HISTORY,
            Expect::Pass,
        ),
        2,
    ),
    control(
        uploading(
            history(
                "h2-put-no-effect",
                &H2_PUT_NO_EFFECT,
                H2_PUT_WITNESSES,
                CUSTODY_HISTORY,
                Expect::Violation(
                    Obligation::History,
                    "a cancelled upload whose DATA was accepted claimed no effect",
                ),
            ),
            2,
        ),
        &[
            "owner write held",
            "upload cancelled with its DATA accepted",
            "cancel kept custody",
        ],
    ),
    history(
        "h3-get",
        &H3_GET,
        H3_WITNESSES,
        CUSTODY_RESOURCES,
        Expect::Pass,
    ),
    control(
        history(
            "h3-get-releasing",
            &H3_GET_RELEASING,
            H3_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Violation(
                Obligation::Custody,
                "a close released DATA the device still held",
            ),
        ),
        &["replacement published", "owner closed with DATA in flight"],
    ),
    control(
        history(
            "h3-get-dropping",
            &H3_GET_DROPPING,
            H3_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Violation(
                Obligation::Custody,
                "a close released DATA the device still held",
            ),
        ),
        &["replacement published", "owner closed with DATA in flight"],
    ),
    control(
        history(
            "h3-get-unreclaimed",
            &H3_GET_UNRECLAIMED,
            H3_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Violation(
                Obligation::Resources,
                "a custody domain kept a reference after its proof",
            ),
        ),
        &[
            "owner closed with DATA in flight",
            "close retained DATA and stopped sends",
            "transmit references withheld at the release check",
        ],
    ),
    uploading(
        history(
            "h3-put",
            &H3_PUT,
            H3_PUT_WITNESSES,
            CUSTODY_HISTORY,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "h3-put-releasing",
                &H3_PUT_RELEASING,
                H3_PUT_WITNESSES,
                CUSTODY_HISTORY,
                Expect::Violation(
                    Obligation::Custody,
                    "a close released DATA the device still held",
                ),
            ),
            1,
        ),
        &[
            "upload DATA held by the device",
            "owner write held",
            "owner closed with DATA in flight",
        ],
    ),
    control(
        uploading(
            history(
                "h3-put-acked",
                &H3_PUT_ACKED,
                H3_PUT_WITNESSES,
                CUSTODY_HISTORY,
                Expect::Violation(
                    Obligation::History,
                    "a closed owner settled an upload from its receipt",
                ),
            ),
            1,
        ),
        &[
            "upload DATA held by the device",
            "owner write held",
            "upload receipt acknowledged",
            "owner closed with DATA in flight",
        ],
    ),
    history("h4-get", &H4_GET, H4_WITNESSES, H4, Expect::Pass),
    uploading(
        history("h4-put", &H4_PUT, H4_PUT_WITNESSES, H4, Expect::Pass),
        1,
    ),
    control(
        uploading(
            history(
                "h4-put-starved",
                &H4_PUT_STARVED,
                H4_PUT_WITNESSES,
                H4,
                Expect::Violation(
                    Obligation::Progress,
                    "an eligible peer's GET starved beside a stalled upload",
                ),
            ),
            1,
        ),
        &["upload stalled before its DATA"],
    ),
    control(
        uploading(
            history(
                "h4-put-timed-out",
                &H4_PUT_TIMED_OUT,
                H4_PUT_WITNESSES,
                H4,
                Expect::Violation(
                    Obligation::Progress,
                    "an eligible peer's GET starved beside a stalled upload",
                ),
            ),
            1,
        ),
        &["upload stalled before its DATA"],
    ),
    control(
        history(
            "h4-get-starved",
            &H4_GET_STARVED,
            H4_WITNESSES,
            H4,
            Expect::Violation(
                Obligation::Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
        ),
        &["share saturated", "saturating reads held"],
    ),
    control(
        history(
            "h4-get-duplicated",
            &H4_GET_DUPLICATED,
            H4_WITNESSES,
            H4,
            Expect::Violation(
                Obligation::Resources,
                "a peer's charge left its live requests or its share",
            ),
        ),
        &["share saturated", "saturating reads held"],
    ),
    control(
        history(
            "h4-get-wrong-peer",
            &H4_GET_WRONG_PEER,
            H4_WITNESSES,
            H4,
            Expect::Violation(
                Obligation::Resources,
                "a peer's charge left its live requests or its share",
            ),
        ),
        &["share saturated", "saturating reads held"],
    ),
    history(
        "h5-get",
        &H5_GET,
        H5_WITNESSES,
        CUSTODY_RESOURCES,
        Expect::Pass,
    ),
    history(
        "h5-get-no-read",
        &H5_GET_NO_READ,
        H5_WITNESSES,
        CUSTODY_RESOURCES,
        Expect::Unsuccessful("old read held"),
    ),
    history(
        "h5-get-reset",
        &H5_GET_RESET,
        H5_RESET_WITNESSES,
        CUSTODY,
        Expect::Pass,
    ),
    history(
        "h5-get-failed-stop",
        &H5_GET_FAILED_STOP,
        H5_FAILED_WITNESSES,
        CUSTODY_RESOURCES,
        Expect::Pass,
    ),
    control(
        history(
            "h5-get-releasing",
            &H5_GET_RELEASING,
            H5_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Violation(Obligation::Custody, "a stop without proof ended custody"),
        ),
        &[
            "old read held",
            "transmit references withheld at stop",
            "owner stopped with a read held",
        ],
    ),
    control(
        history(
            "h5-get-failed",
            &H5_GET_FAILED,
            H5_FAILED_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Violation(Obligation::Custody, "a stop without proof ended custody"),
        ),
        &[
            "old read held",
            "transmit references withheld at stop",
            "the device reported a failed stop",
            "owner stopped with a read held",
        ],
    ),
    uploading(
        history(
            "h5-put",
            &H5_PUT,
            H5_PUT_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "h5-put-no-read",
            &H5_PUT_NO_READ,
            H5_PUT_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Unsuccessful("old read held"),
        ),
        1,
    ),
    uploading(
        history(
            "h5-put-failed-stop",
            &H5_PUT_FAILED_STOP,
            H5_PUT_FAILED_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "h5-put-acked",
                &H5_PUT_ACKED,
                H5_PUT_WITNESSES,
                CUSTODY_RESOURCES,
                Expect::Violation(Obligation::Custody, "a stop without proof ended custody"),
            ),
            1,
        ),
        &[
            "upload DATA held by the device",
            "owner write held",
            "upload receipt acknowledged",
            "old read held",
            "owner stopped with a read held",
        ],
    ),
    control(
        uploading(
            history(
                "h5-put-failed",
                &H5_PUT_FAILED,
                H5_PUT_FAILED_WITNESSES,
                CUSTODY_RESOURCES,
                Expect::Violation(Obligation::Custody, "a stop without proof ended custody"),
            ),
            1,
        ),
        &[
            "upload DATA held by the device",
            "owner write held",
            "upload receipt acknowledged",
            "old read held",
            "the device reported a failed stop",
            "owner stopped with a read held",
        ],
    ),
    uploading(
        history(
            "h5-put-reset",
            &H5_PUT_RESET,
            H5_PUT_RESET_WITNESSES,
            CUSTODY,
            Expect::Pass,
        ),
        1,
    ),
    control(
        history(
            "h1-get-reused-unpremised",
            &H1_GET_REUSED,
            H1_WITNESSES,
            H1,
            Expect::Unsuccessful("a premise no step marks"),
        ),
        &["a premise no step marks"],
    ),
    history(
        "h2-get-cancelled-after-handout",
        &H2_GET_HANDOUT,
        H2_HANDOUT_WITNESSES,
        &[Obligation::Contain],
        Expect::Pass,
    ),
    history(
        "h2-get-released-after-handout",
        &H2_GET_HANDOUT_RELEASED,
        H2_HANDOUT_RELEASED_WITNESSES,
        &[Obligation::History],
        Expect::Pass,
    ),
    control(
        history(
            "h2-get-handout-judged-missing",
            &H2_GET_HANDOUT_MISSING,
            H2_HANDOUT_WITNESSES,
            &[Obligation::Contain],
            Expect::Violation(Obligation::Contain, "a refused read exposed bytes"),
        ),
        H2_HANDOUT_PREMISE,
    ),
    control(
        history(
            "h2-get-handout-judged-short",
            &H2_GET_HANDOUT_SHORT,
            H2_HANDOUT_RELEASED_WITNESSES,
            &[Obligation::History],
            Expect::Violation(
                Obligation::History,
                "a qualified GET missed the visible version's exact bytes",
            ),
        ),
        H2_HANDOUT_RELEASED_PREMISE,
    ),
    history(
        "h3-get-read-held",
        &H3_GET_READ,
        H3_READ_WITNESSES,
        CUSTODY_RESOURCES,
        Expect::Pass,
    ),
    history(
        "h3-get-read-drained",
        &H3_GET_READ_DRAINED,
        H3_READ_DRAINED_WITNESSES,
        CUSTODY_RESOURCES,
        Expect::Pass,
    ),
    control(
        uploading(
            history(
                "h1-put-judged-unsupplied",
                &H1_PUT_JUDGED_UNSUPPLIED,
                H1_PUT_WITNESSES,
                H1,
                Expect::Violation(
                    Obligation::History,
                    "the upload's result was other than published",
                ),
            ),
            1,
        ),
        &["invalidation acknowledged", "upload prepared"],
    ),
    control(
        history(
            "h1-get-invalidated-twice",
            &H1_GET_INVALIDATED_TWICE,
            H1_WITNESSES,
            H1,
            Expect::Violation(Obligation::History, "the invalidation removed no mapping"),
        ),
        &["invalidation acknowledged"],
    ),
    control(
        history(
            "h1-get-uninvalidated",
            &H1_GET_UNINVALIDATED,
            H1_WITNESSES,
            H1,
            Expect::Violation(
                Obligation::History,
                "a GET after the acknowledged invalidation saw a removed version",
            ),
        ),
        &["holds armed", "old read held"],
    ),
    control(
        history(
            "h1-get-publish-revoked",
            &H1_GET_PUBLISH_REVOKED,
            H1_WITNESSES,
            H1_PROGRESS,
            Expect::Violation(Obligation::Progress, "the replacement never published"),
        ),
        &[
            "invalidation acknowledged",
            "fresh GET missed",
            "replacement filled",
            FILL_REVOKED,
        ],
    ),
    control(
        uploading(
            history(
                "h4-put-judged-at-begin",
                &H4_PUT_JUDGED_AT_BEGIN,
                H4_PUT_WITNESSES,
                H4,
                Expect::Violation(
                    Obligation::Resources,
                    "a stalled upload's request was not charged",
                ),
            ),
            1,
        ),
        &["upload begun"],
    ),
    control(
        history(
            "h5-get-reset-unproven",
            &H5_GET_RESET_UNPROVEN,
            H5_RESET_WITNESSES,
            CUSTODY,
            Expect::Violation(
                Obligation::Custody,
                "a proven stop kept a command on the device",
            ),
        ),
        &["old read held"],
    ),
    control(
        history(
            "h2-get-successor-as-cancelled",
            &H2_GET_SUCCESSOR_AS_CANCELLED,
            H2_WITNESSES,
            CUSTODY_HISTORY,
            Expect::Violation(
                Obligation::History,
                "a successor's result came from its predecessor",
            ),
        ),
        &[
            "held read cancelled",
            "cancel kept custody",
            "the cancelled request drained after its terminal",
            "successor reused the slot at a higher generation",
        ],
    ),
    control(
        history(
            "h3-get-sent-after-close",
            &H3_GET_SENT_AFTER_CLOSE,
            H3_WITNESSES,
            CUSTODY_RESOURCES,
            Expect::Violation(Obligation::Custody, "a closed owner kept sending"),
        ),
        &["replacement published", "owner closed with DATA in flight"],
    ),
    control(
        history(
            "h5-get-reset-releasing",
            &H5_GET_RESET_RELEASING,
            H5_RESET_WITNESSES,
            CUSTODY,
            Expect::Violation(
                Obligation::Custody,
                "a device stop ended the links' custody",
            ),
        ),
        &[
            "old read held",
            "transmit references withheld at stop",
            "owner stopped with a read held",
        ],
    ),
];

/// Whether every step ran.
fn complete(world: &Mixed<'_, '_, '_>) -> bool {
    world.scripted == world.plan.script.len() || world.first.get().is_some()
}

/// Every composed history: the custody histories, the incident histories,
/// the cohorts, the relaunch histories, the isolation histories, the
/// key-operation histories, the sibling families, then the scenario
/// histories.
pub(crate) fn every() -> impl Iterator<Item = &'static History> {
    HISTORIES
        .iter()
        .chain(incidents::descending::DESCENDING.iter())
        .chain(incidents::unknowns::UNKNOWNS.iter())
        .chain(incidents::INCIDENTS.iter())
        .chain(cohorts::COHORTS.iter())
        .chain(handshakes::HANDSHAKES.iter())
        .chain(copies::COPIES.iter())
        .chain(restarts::RESTARTS.iter())
        .chain(isolation::PAIRED.iter())
        .chain(covered_successors::COVERED_SUCCESSORS.iter())
        .chain(keyops::KEYOPS.iter())
        .chain(healed_uploads::HEALED_UPLOADS.iter())
        .chain(stalled_uploads::STALLED_UPLOADS.iter())
        .chain(resolved_uploads::RESOLVED_UPLOADS.iter())
        .chain(delayed_results::DELAYED_RESULTS.iter())
        .chain(lost_results::LOST_RESULTS.iter())
        .chain(lost_completes::LOST_COMPLETES.iter())
        .chain(closed_references::CLOSED_REFERENCES.iter())
        .chain(old_rights::OLD_RIGHTS.iter())
        .chain(held_writes::HELD_WRITES.iter())
        .chain(second_gets::SECOND_GETS.iter())
        .chain(retained_rows::RETAINED_ROWS.iter())
        .chain(warm_loads::WARM_LOADS.iter())
        .chain(root_slots::ROOT_SLOTS.iter())
        .chain(scenarios())
}

fn scenarios() -> impl Iterator<Item = &'static History> {
    receipts::RECEIPTS
        .iter()
        .chain(named_gets::NAMED_GETS.iter())
        .chain(silent_owners::SILENT_OWNERS.iter())
        .chain(pressured_gets::PRESSURED_GETS.iter())
        .chain(late_results::LATE_RESULTS.iter())
        .chain(deadline_edges::DEADLINE_EDGES.iter())
        .chain(cancelled_uploads::CANCELLED_UPLOADS.iter())
        .chain(cancelled_reads::CANCELLED_READS.iter())
        .chain(expiry_samples::EXPIRY_SAMPLES.iter())
        .chain(full_shares::FULL_SHARES.iter())
        .chain(saturated_shares::SATURATED_SHARES.iter())
        .chain(saturated_shares::WAITING_READS.iter())
        .chain(lent_commands::LENT_COMMANDS.iter())
        .chain(retained::RETAINED_GETS.iter())
        .chain(deferred_deadlines::DEFERRED_DEADLINES.iter())
        .chain(displaced_charges::DISPLACED_CHARGES.iter())
        .chain(healed_pools::HEALED_POOLS.iter())
        .chain(deferred_outcomes::DEFERRED_OUTCOMES.iter())
        .chain(share_charges::SHARE_CHARGES.iter())
        .chain(peer_charges::PEER_CHARGES.iter())
        .chain(rekeys::REKEYS.iter())
        .chain(refused::REFUSED_GETS.iter())
}

/// The scenario a history's name selects.
pub(super) fn named(name: &str, root: u64) -> Option<super::bundle::Scenario> {
    every()
        .find(|history| history.name == name)
        .map(|history| scenario_of(history, root))
}

/// The scenario `history` runs under `root`.
fn scenario_of(history: &'static History, root: u64) -> super::bundle::Scenario {
    let profile = Profile {
        name: history.name,
        declared: Vec::new(),
        root,
    };
    let plan = Plan {
        gets: history.gets,
        puts: history.uploads,
        source_bytes: history.source_bytes,
        read_resident: true,
        withheld_tx: true,
        script: history.script,
        witnesses: history.witnesses,
        premise: history.premise,
        relaunches: history.relaunches,
        peer_owner: history.peer_owner,
        geometry: history.geometry,
        put_commands: history.put_commands,
        second_sources: history.second_sources,
        ..QUIET
    };
    (profile, plan, complete)
}

#[cfg(test)]
mod tests {
    use crate::sim::manifest::Manifest;
    use crate::sim::trace::{Outcome, Terminal, load};

    use super::super::bundle::{Refusal, admit, held_by, traced};
    use super::super::replay::{Replayed, replay};
    use super::{Expect, HISTORIES};

    pub(super) fn manifest(name: &str) -> Manifest {
        let text = crate::sim::manifest_tests::sample(name, &"a".repeat(64), "x86_64-linux");
        Manifest::parse(&text).expect("a valid manifest")
    }

    /// Admission compares the manifest's `upload_attempts`, `scripted`,
    /// `source_bytes`, `restarts` and `bundles` with the uploads, steps,
    /// source bytes, owner relaunches and dead bundles each history's
    /// script needs: it admits a manifest at each need and refuses one
    /// below it.
    #[test]
    fn every_history_holds_its_script_against_the_manifest() {
        for history in super::every() {
            let steps = history.script.len() as u64;
            let actors = held_by(history.name)
                .expect("a listed history")
                .into_iter()
                .find(|(key, _)| *key == "actors")
                .expect("an actors bound")
                .1;
            for (key, held) in [
                ("actors", actors),
                ("upload_attempts", u64::from(history.uploads)),
                ("scripted", steps),
                ("source_bytes", u64::from(history.source_bytes)),
                ("restarts", u64::from(history.relaunches)),
                ("bundles", u64::from(history.relaunches > 0)),
            ] {
                let exact = manifest(history.name).with(key, held);
                assert!(admit(&exact).is_ok(), "{}: {key} = {held}", history.name);
                if held > 0 {
                    let short = manifest(history.name).with(key, held - 1);
                    assert_eq!(
                        admit(&short).err(),
                        Some(Refusal::Bound(key)),
                        "{}: {key} = {}",
                        history.name,
                        held - 1
                    );
                }
            }
        }
    }

    /// Each control's and falsifier's run records the exact failure its
    /// declaration names: the named rule, or the witness or premise that
    /// never fired.
    #[test]
    fn every_history_records_its_declared_failure() {
        for history in super::every() {
            assert_eq!(
                first_failure(history.name, 3),
                history.expect.failure(),
                "{}",
                history.name
            );
        }
    }

    /// The first failure the run of history `name` under `root` records.
    pub(super) fn first_failure(name: &str, root: u64) -> Option<super::Failure> {
        let history = super::every().find(|history| history.name == name);
        ended(history.expect(name), root).1
    }

    /// How the run of `history` under `root` ended, and the first failure
    /// it records. The run takes no bundle, so it serves a history outside
    /// the listing too. A run that records an unsuccessful first failure
    /// has an `Unsuccessful` terminal whether it reached its goal or a
    /// limit stopped it; the end separates the two.
    pub(super) fn run_end(
        history: &'static super::History,
        root: u64,
    ) -> (crate::sim::turn::End, Option<super::Failure>) {
        let (profile, plan, goal) = super::scenario_of(history, root);
        let chooser = profile.recorder(&super::super::sites_for(&plan));
        let (ran, first, _) =
            super::super::mixed_run(chooser, &profile, plan, goal, super::super::LIMITS, &mut ());
        (ran.report.end, first)
    }

    /// A passing run and a run that a limit stops before its script ends
    /// both record no first failure. The terminal separates them: the
    /// stopped run ends `Inconclusive`.
    pub(super) fn ended(
        history: &'static super::History,
        root: u64,
    ) -> (Terminal, Option<super::Failure>) {
        ended_of(super::scenario_of(history, root))
    }

    fn ended_of(
        (profile, plan, goal): super::super::bundle::Scenario,
    ) -> (Terminal, Option<super::Failure>) {
        let chooser = profile.recorder(&super::super::sites_for(&plan));
        let declares_put = profile.declares(crate::sim::action::ActionKind::PutInvoke);
        let (ran, first, puts) =
            super::super::mixed_run(chooser, &profile, plan, goal, super::super::LIMITS, &mut ());
        let (terminal, _) = super::super::bundle::judge(
            ran.report.end,
            first.as_ref(),
            ran.audit,
            (declares_put, puts),
            ran.boundaries,
        );
        (terminal, first)
    }

    fn invalidate_key_2_then_publish_fill(world: &mut super::Mixed<'_, '_, '_>, now: u64) -> u64 {
        super::invalidate_key_then_publish_fill(world, now, &super::key(2))
    }

    /// Invalidating key 2 leaves the fill of key 1 eligible to publish, so
    /// the premise `FILL_REVOKED` of `h1-get-publish-revoked` stays
    /// unformed and the run reports `Failure::Unsuccessful(FILL_REVOKED)`.
    #[test]
    fn an_invalidation_that_revokes_no_attempt_ends_unsuccessful_under_the_premise() {
        const UNREVOKED: [super::Step; 14] = super::replaced(
            super::H1_GET_PUBLISH_REVOKED,
            "publish-revoked",
            super::step(
                "publish-unrevoked",
                super::fill_written,
                invalidate_key_2_then_publish_fill,
            ),
        );
        let (profile, mut plan, goal) =
            super::named("h1-get-publish-revoked", 3).expect("the control");
        assert!(plan.premise.contains(&super::FILL_REVOKED));
        plan.script = &UNREVOKED;
        assert_eq!(
            ended_of((profile, plan, goal)).1,
            Some(super::Failure::Unsuccessful(super::FILL_REVOKED))
        );
    }

    /// The roots the sibling families' seeded test pins: a small one and two
    /// drawn from the 64-bit range.
    pub(super) const ROOTS: [u64; 3] = [11, 4_302_617_955_180_736_441, 15_611_090_472_388_207_913];

    /// The families that each hold one property's history, its sibling and
    /// the controls of their checks.
    const SIBLING_FAMILIES: [&[super::History]; 10] = [
        &super::healed_uploads::HEALED_UPLOADS,
        &super::stalled_uploads::STALLED_UPLOADS,
        &super::resolved_uploads::RESOLVED_UPLOADS,
        &super::lost_results::LOST_RESULTS,
        &super::lost_completes::LOST_COMPLETES,
        &super::closed_references::CLOSED_REFERENCES,
        &super::old_rights::OLD_RIGHTS,
        &super::held_writes::HELD_WRITES,
        &super::second_gets::SECOND_GETS,
        &super::retained_rows::RETAINED_ROWS,
    ];

    /// Each sibling family's control declares the rule its family's check
    /// raises and a premise its run marks before that check, and the
    /// families hold no other history that expects a failure. The seeded
    /// test below runs each control under the pinned roots.
    #[test]
    fn every_sibling_family_control_fails_through_its_named_check() {
        use crate::oracle::Obligation::{Bytes, Contain, History};
        let killed = [
            (
                "ru1-put-result-left-unknown",
                History,
                "a delayed matching RESULT left the unknown upload unresolved",
            ),
            (
                "or1-get-ended-over-a-prefix",
                Bytes,
                "the old right ended without its version",
            ),
            (
                "rr1-put-begin-judged-as-no-frame",
                Contain,
                "a PUT frame naming a GET changed more than its counter",
            ),
        ];
        let controls: Vec<_> = SIBLING_FAMILIES
            .into_iter()
            .flatten()
            .filter(|history| history.expect != Expect::Pass)
            .collect();
        assert_eq!(controls.len(), killed.len());
        for (name, obligation, rule) in killed {
            let control = controls.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                control.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            assert!(!control.premise.is_empty(), "{name} declares its premise");
        }
    }

    /// Records `history` under `root` and requires that it ends as it
    /// declares and that its bundle replays to an equal digest.
    pub(super) fn ends_as_declared_at(history: &super::History, root: u64) {
        let (bytes, loaded) = recorded(history.name, root);
        assert_eq!(
            history.ends_as_declared(&loaded),
            Ok(()),
            "{} at {root}",
            history.name
        );
        assert_eq!(
            replay(&bytes).expect("a replay").0,
            Replayed::Reproduced,
            "{} at {root}",
            history.name
        );
    }

    /// The bundle history `name` records under `root`, and its load.
    pub(super) fn recorded(name: &str, root: u64) -> (Vec<u8>, crate::sim::trace::Loaded) {
        let mut manifest = manifest(name);
        manifest.root = root;
        let records = manifest.capacity().records();
        let bytes = traced(admit(&manifest).expect("admitted"), Vec::new()).sink;
        let loaded = load(&bytes, records).expect("a loadable bundle");
        (bytes, loaded)
    }

    /// Each family that holds one property's history and its sibling is
    /// recorded under each pinned root: every history ends as it declares
    /// and its bundle replays to an equal digest, so its ending holds under
    /// each interleaving these roots select.
    #[test]
    fn every_sibling_family_history_ends_as_declared_and_replays_equal_under_pinned_roots() {
        for history in SIBLING_FAMILIES.into_iter().flatten() {
            for root in ROOTS {
                ends_as_declared_at(history, root);
            }
        }
    }

    /// A GET that handed a prefix out ends `Incomplete` over it once
    /// cancelled and completes exactly once its reads are released, under
    /// each pinned root, and each of the two judgments' controls ends in its
    /// violation there.
    #[test]
    fn a_get_that_handed_bytes_out_ends_as_declared_under_pinned_roots() {
        for name in [
            "h2-get-cancelled-after-handout",
            "h2-get-released-after-handout",
            "h2-get-handout-judged-missing",
            "h2-get-handout-judged-short",
        ] {
            let history = HISTORIES.iter().find(|h| h.name == name).expect(name);
            for root in ROOTS {
                ends_as_declared_at(history, root);
            }
        }
    }

    #[test]
    fn each_shared_check_text_control_ends_as_declared_under_a_wide_root() {
        for name in [
            "h1-put-judged-unsupplied",
            "h1-get-invalidated-twice",
            "h1-get-uninvalidated",
            "h1-get-publish-revoked",
            "h4-put-judged-at-begin",
            "h5-get-reset-unproven",
            "h2-get-successor-as-cancelled",
            "h3-get-sent-after-close",
            "h5-get-reset-releasing",
        ] {
            let history = HISTORIES.iter().find(|h| h.name == name).expect(name);
            ends_as_declared_at(history, ROOTS[1]);
            assert_eq!(
                first_failure(name, ROOTS[1]),
                history.expect.failure(),
                "{name}"
            );
        }
    }

    /// Passing requires completion because a run stopped by a limit can
    /// record zero failures.
    #[test]
    fn the_pinned_roots_of_both_histories_pass_and_replay_equal() {
        for name in ["h3-get-read-held", "h3-get-read-drained"] {
            let history = HISTORIES.iter().find(|h| h.name == name).expect(name);
            assert_eq!(history.expect, Expect::Pass, "{name}");
            for root in [1, 2, 3] {
                ends_as_declared_at(history, root);
            }
        }
    }

    /// The duplicated-charge control fails through its rule under roots
    /// whose owner had sent the saturating peer no frame when the other
    /// peer's read was judged: its planted charge counts the datagrams the
    /// link duplicated toward the owner, and the saturating GETs the owner
    /// holds by then are among them.
    #[test]
    fn the_duplicated_charge_control_fails_before_the_owner_answers_the_saturating_peer() {
        let control = super::every()
            .find(|history| history.name == "h4-get-duplicated")
            .expect("a listed control");
        assert!(matches!(control.expect, Expect::Violation(..)));
        for root in [1564, 1654, 1801] {
            assert_eq!(
                first_failure(control.name, root),
                control.expect.failure(),
                "{root}"
            );
        }
    }

    /// Each obligation a passing history declares must appear in the
    /// `CHECKS` entry for at least one of its witnesses, in every family
    /// `every` chains.
    #[test]
    fn every_passing_history_activates_the_obligations_it_declares() {
        let passing = super::every().filter(|h| h.expect == Expect::Pass);
        let (mut restarted, mut isolated) = (false, false);
        let mut unwitnessed = Vec::new();
        for history in passing {
            let activated = super::activated(history.witnesses);
            for obligation in history.obligations {
                if !activated.contains(obligation) {
                    unwitnessed.push(format!("{}: {obligation:?}", history.name));
                }
            }
            restarted |= activated.contains(&crate::oracle::Obligation::Restart);
            isolated |= activated.contains(&crate::oracle::Obligation::Isolation);
        }
        assert!(
            unwitnessed.is_empty(),
            "declared obligations with no witnessed check: {unwitnessed:#?}"
        );
        assert!(restarted, "a passing history witnesses its restart check");
        assert!(isolated, "a passing history witnesses its isolation check");
    }

    /// The obligation a control's violation fails is one its own
    /// declaration lists. A control may declare more than the passing
    /// history its script derives from: `h1-get-publish-revoked` declares
    /// `H1_PROGRESS`, while `h1-get` declares `H1`.
    #[test]
    fn every_control_declares_the_obligation_its_violation_fails() {
        let undeclared: Vec<_> = super::every()
            .filter_map(|history| match history.expect {
                Expect::Violation(obligation, _) if !history.obligations.contains(&obligation) => {
                    Some(format!("{}: {obligation:?}", history.name))
                }
                _ => None,
            })
            .collect();
        assert!(
            undeclared.is_empty(),
            "violations of an undeclared obligation: {undeclared:#?}"
        );
    }

    /// The family record pairs `TEST` with each distinct `Expect::Violation`
    /// rule text in `HISTORIES` exactly once.
    #[test]
    fn the_family_record_lists_each_declared_violation_in_full() {
        const RECORD: &str = "composed-custody-histories-hold-their-witnesses-and-replay";
        const TEST: &str =
            "net::world_tests::histories::tests::every_history_ends_as_declared_and_replays_equal";
        let records = crate::net::terminal_tests::OBLIGATIONS["records"]
            .as_array()
            .expect("the catalog's records");
        let record = records
            .iter()
            .find(|record| record["id"] == RECORD)
            .expect("the family's record");
        let mut listed: Vec<&str> = record["controls"]
            .as_array()
            .expect("the record's controls")
            .iter()
            .map(|control| {
                assert_eq!(control["test"], TEST, "{control}");
                control["violation"].as_str().expect("a control's text")
            })
            .collect();
        let mut declared: Vec<&str> = HISTORIES
            .iter()
            .filter_map(|history| match history.expect {
                Expect::Violation(_, rule) => Some(rule),
                _ => None,
            })
            .collect();
        listed.sort_unstable();
        declared.sort_unstable();
        declared.dedup();
        assert_eq!(listed, declared);
    }

    /// Every history is recorded once under its manifest: it ends as it
    /// declares and replays equal. A control's declared end is its named
    /// rule, under its premise, and a falsifier's is unsuccessful, so the one
    /// recording shows each control fails through its named check and each
    /// falsifier ends unsuccessful;
    /// `every_history_records_its_declared_failure` checks which witness or
    /// premise never fired.
    #[test]
    fn every_history_ends_as_declared_and_replays_equal() {
        use crate::oracle::Obligation::{Bytes, Contain, Custody, History, Progress, Resources};
        let killed = [
            (
                "h1-get-stale",
                History,
                "a qualified GET missed the visible version's exact bytes",
            ),
            (
                "h1-get-reused",
                Bytes,
                "the old right returned bytes other than its own version",
            ),
            (
                "h1-put-wrong",
                History,
                "a qualified GET missed the visible version's exact bytes",
            ),
            (
                "h2-get-early",
                Custody,
                "a cancel released custody before the read's terminal",
            ),
            (
                "h2-get-stale",
                History,
                "a successor took its predecessor's wire identity",
            ),
            (
                "h2-put-no-effect",
                History,
                "a cancelled upload whose DATA was accepted claimed no effect",
            ),
            (
                "h3-get-releasing",
                Custody,
                "a close released DATA the device still held",
            ),
            (
                "h3-get-dropping",
                Custody,
                "a close released DATA the device still held",
            ),
            (
                "h3-get-unreclaimed",
                Resources,
                "a custody domain kept a reference after its proof",
            ),
            (
                "h3-put-releasing",
                Custody,
                "a close released DATA the device still held",
            ),
            (
                "h3-put-acked",
                History,
                "a closed owner settled an upload from its receipt",
            ),
            (
                "h4-get-starved",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "h4-put-starved",
                Progress,
                "an eligible peer's GET starved beside a stalled upload",
            ),
            (
                "h4-put-timed-out",
                Progress,
                "an eligible peer's GET starved beside a stalled upload",
            ),
            (
                "h4-get-duplicated",
                Resources,
                "a peer's charge left its live requests or its share",
            ),
            (
                "h4-get-wrong-peer",
                Resources,
                "a peer's charge left its live requests or its share",
            ),
            (
                "h5-get-releasing",
                Custody,
                "a stop without proof ended custody",
            ),
            (
                "h5-get-failed",
                Custody,
                "a stop without proof ended custody",
            ),
            (
                "h5-put-acked",
                Custody,
                "a stop without proof ended custody",
            ),
            (
                "h5-put-failed",
                Custody,
                "a stop without proof ended custody",
            ),
            (
                "h2-get-handout-judged-missing",
                Contain,
                "a refused read exposed bytes",
            ),
            (
                "h2-get-handout-judged-short",
                History,
                "a qualified GET missed the visible version's exact bytes",
            ),
            (
                "h1-put-judged-unsupplied",
                History,
                "the upload's result was other than published",
            ),
            (
                "h1-get-invalidated-twice",
                History,
                "the invalidation removed no mapping",
            ),
            (
                "h1-get-uninvalidated",
                History,
                "a GET after the acknowledged invalidation saw a removed version",
            ),
            (
                "h1-get-publish-revoked",
                Progress,
                "the replacement never published",
            ),
            (
                "h4-put-judged-at-begin",
                Resources,
                "a stalled upload's request was not charged",
            ),
            (
                "h5-get-reset-unproven",
                Custody,
                "a proven stop kept a command on the device",
            ),
            (
                "h2-get-successor-as-cancelled",
                History,
                "a successor's result came from its predecessor",
            ),
            (
                "h3-get-sent-after-close",
                Custody,
                "a closed owner kept sending",
            ),
            (
                "h5-get-reset-releasing",
                Custody,
                "a device stop ended the links' custody",
            ),
        ];
        for (name, obligation, rule) in killed {
            let declared = HISTORIES.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                declared.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            assert!(!declared.premise.is_empty(), "{name} declares its premise");
        }
        let falsifiers = [
            "h1-get-unheld",
            "h1-get-one-request",
            "h1-get-reused-unpremised",
            "h5-get-no-read",
            "h5-put-no-read",
            "h2-get-uncancelled",
        ];
        for name in falsifiers {
            let declared = HISTORIES.iter().find(|h| h.name == name).expect(name);
            assert!(matches!(declared.expect, Expect::Unsuccessful(_)), "{name}");
        }
        let controls = HISTORIES
            .iter()
            .filter(|h| h.expect != Expect::Pass)
            .count();
        assert_eq!(controls, killed.len() + falsifiers.len());
        for history in &HISTORIES {
            let manifest = manifest(history.name);
            let bytes = traced(admit(&manifest).expect("admitted"), Vec::new()).sink;
            let loaded = load(&bytes, 1_000_000).expect("a loadable bundle");
            assert_eq!(history.ends_as_declared(&loaded), Ok(()));
            let other = HISTORIES
                .iter()
                .find(|h| h.expect != history.expect)
                .expect("a history declaring another end");
            assert!(other.ends_as_declared(&loaded).is_err(), "{}", history.name);
            assert_eq!(
                replay(&bytes).expect("a replay").0,
                Replayed::Reproduced,
                "{}",
                history.name
            );
        }
    }

    #[test]
    fn every_scenario_history_ends_as_declared_and_replays_equal() {
        for history in super::scenarios() {
            ends_as_declared_at(history, manifest(history.name).root);
        }
    }

    #[test]
    fn every_passing_scenario_history_passes_and_replays_under_pinned_roots() {
        for history in super::scenarios().filter(|h| h.expect == Expect::Pass) {
            for root in [1, 250, 500] {
                ends_as_declared_at(history, root);
            }
        }
    }

    /// A pressured GET ends by its one deadline, with its refusals lost and
    /// with one delivered, under two roots drawn from the 64-bit range.
    #[test]
    fn a_pressured_get_ends_by_its_deadline_under_roots_of_the_64_bit_range() {
        for name in ["pg1-get-refusals-dropped", "pg1-get-refusal-delivered"] {
            let history = super::scenarios().find(|h| h.name == name).expect(name);
            assert_eq!(history.expect, Expect::Pass, "{name}");
            for root in [7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                ends_as_declared_at(history, root);
            }
        }
    }

    #[test]
    fn a_scenario_history_a_limit_stops_is_no_pass() {
        let name = "lr1-put-result-late";
        let cut = manifest(name).with("turns", 8);
        let bytes = traced(admit(&cut).expect("admitted"), Vec::new()).sink;
        let loaded = load(&bytes, cut.capacity().records()).expect("a loadable bundle");
        assert_eq!(loaded.violation, None);
        assert!(
            matches!(
                loaded.terminal,
                Terminal::Complete {
                    outcome: Outcome::Inconclusive,
                    ..
                }
            ),
            "{:?}",
            loaded.terminal
        );
        let history = super::scenarios().find(|h| h.name == name).expect(name);
        assert_eq!(history.expect, Expect::Pass);
        assert!(history.ends_as_declared(&loaded).is_err());
    }

    #[test]
    fn every_scenario_control_fails_through_its_named_check() {
        use crate::oracle::Obligation::{Bytes, Contain, Custody, History, Progress, Resources};
        let killed = [
            (
                "rc1-put-receipt-as-publication",
                History,
                "an upload claimed publication without a delivered RESULT",
            ),
            (
                "rc1-put-unknown-as-published",
                History,
                "an upload claimed publication without a delivered RESULT",
            ),
            (
                "rc1-put-counted-result-as-published",
                History,
                "an upload claimed publication without a delivered RESULT",
            ),
            (
                "ng1-put-cancel-moved-the-slot",
                Contain,
                "a PUT frame naming a GET changed more than its counter",
            ),
            (
                "ng1-no-frame-counted",
                Contain,
                "a PUT frame naming a GET changed more than its counter",
            ),
            (
                "so1-put-result-lost-as-not-started",
                History,
                "an attempt that did not publish published",
            ),
            (
                "pg1-get-undecided-past-deadline",
                Resources,
                "a pressured request outlived its one deadline",
            ),
            (
                "lr1-put-late-as-published",
                History,
                "a timed-out upload claimed publication before its RESULT",
            ),
            (
                "lr1-put-late-as-no-effect",
                History,
                "a timed-out upload claimed no effect after its DATA reached the owner",
            ),
            (
                "de1-publish-below-judged-reached",
                History,
                "a publication at or past its deadline",
            ),
            (
                "cr1-get-uncancelled-released",
                Custody,
                "a cancel released custody before the read's terminal",
            ),
            (
                "cr1-get-uncancelled-failed-read",
                Bytes,
                "the old right ended without its version",
            ),
            (
                "ex1-get-below-judged-at-the-expiry",
                History,
                "a GET at its expiry sample served the version",
            ),
            (
                "ex1-get-at-judged-below-the-expiry",
                Bytes,
                "a sample below the deadline missed the live version",
            ),
            (
                "fs1-get-capped-late",
                Resources,
                "a GET past a peer's share outlived its one deadline",
            ),
            (
                "fs1-get-capped-read-complete",
                Resources,
                "a GET past a peer's share ended without a typed pressure outcome",
            ),
            (
                "fs1-b-uncharged",
                Resources,
                "a retained GET left its peer's share before its release",
            ),
            (
                "fs1-b-late",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "fs1-wrong-peer",
                Resources,
                "a peer's share was charged with another peer's work",
            ),
            (
                "ss1-open-share-peer-late",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "ss1-open-share-get-read-as-refused",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "ss2-peer-read-waits-for-one-command",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "ss2-three-commands-peer-late",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "ss2-three-commands-trader-read-as-missing",
                Resources,
                "a healed saturated GET missed its exact bytes",
            ),
            (
                "ss2-three-commands-trader-read-altered",
                Resources,
                "a healed saturated GET missed its exact bytes",
            ),
            (
                "ss2-three-commands-peer-read-altered",
                Bytes,
                "a complete read returned bytes other than the label's content",
            ),
            (
                "ss2-three-commands-peer-late-read-altered",
                Bytes,
                "a complete read returned bytes other than the label's content",
            ),
            (
                "ss2-three-commands-trader-read-corrupted",
                Bytes,
                "a complete read returned bytes other than the label's content",
            ),
            (
                "ss2-one-command-trader-read-corrupted-at-exit",
                Bytes,
                "a complete read returned bytes other than the label's content",
            ),
            (
                "ss1-open-share-get-past-read-as-missing",
                Resources,
                "a healed saturated GET missed its exact bytes",
            ),
            (
                "lw1-waiter-submit-refused-twice",
                Progress,
                "a write command went to a peer at its share while a peer below its share waited",
            ),
            (
                "lw1-accepted-turn-judged-as-bound",
                Progress,
                "a write command went to a peer at its share while a peer below its share waited",
            ),
            (
                "lw2-waiter-receive-finds-no-buffer",
                Progress,
                "a write command went to a peer at its share while a peer below its share waited",
            ),
            (
                "lw3-waiter-submit-refused-inside-fragment",
                Progress,
                "a write command went to a peer at its share while a peer below its share waited",
            ),
            (
                "rt1-get-judged-uncharged",
                Resources,
                "a retained GET left its peer's share before its release",
            ),
            (
                "dc1-get-drained-judged-charged",
                Resources,
                "a peer's charge left its live requests or its share",
            ),
            (
                "dc1-get-held-judged-dropped",
                Custody,
                "a displacement dropped the old session's live charges",
            ),
            (
                "hp1-get-with-the-pool-still-held",
                Progress,
                "unrelated work stalled or read bytes outside the visible versions",
            ),
            (
                "sc1-get-past-share-judged-admitted",
                Resources,
                "a peer's charge left its live requests or its share",
            ),
            (
                "sc1-get-share-judged-uncharged",
                Resources,
                "a peer's charge left its live requests or its share",
            ),
            (
                "sc1-get-past-share-judged-admitted-uncharged",
                Resources,
                "a peer's charge left its live requests or its share",
            ),
            (
                "pc1-get-and-upload-judged-on-the-other-peer",
                Resources,
                "a peer's share was charged with another peer's work",
            ),
            (
                "pc1-get-beside-one-judged-late",
                Progress,
                "an eligible peer's GET starved behind a saturated share",
            ),
            (
                "rk1-get-after-a-rekey-judged-late",
                Progress,
                "a healed request stalled past its bound",
            ),
            (
                "rk1-get-after-a-rekey-judged-past-its-turns",
                Progress,
                "a healed request stalled past its bound",
            ),
            (
                "rk1-get-with-keys-kept-judged-as-rekeyed",
                Progress,
                "a healed request settled without its update",
            ),
            (
                "rk1-get-with-keys-kept-read-altered",
                History,
                "a qualified GET missed the visible version's exact bytes",
            ),
            (
                "rf1-get-refused-judged-as-readmitted",
                Resources,
                "a settled GET's row held an admitted request",
            ),
            (
                "rf1-get-refused-judged-unsettled",
                Resources,
                "a refused GET's wire identity stayed unsettled",
            ),
            (
                "df2-put-unsupplied-judged-past-its-wait",
                Resources,
                "a deferred upload outlived its one deadline",
            ),
            (
                "df1-put-unsupplied-judged-not-started",
                History,
                "a deferred upload ended with an outcome its deadline cannot give",
            ),
        ];
        let unsuccessful = [
            (
                "lr1-put-in-time-unpublished",
                "upload published by an accepted RESULT",
            ),
            (
                "ss1-get-beside-a-drained-share",
                "saturating reads held at the peer's read",
            ),
            (
                "ss2-peer-read-submitted-as-waiting",
                "the peer's read waited for the command",
            ),
            (
                "ss2-three-commands-trader-read-as-refused",
                "a terminal met the next GET at the owner",
            ),
            (
                "ss2-one-command-trade-unsent",
                "a terminal met the next GET at the owner",
            ),
            (
                "ss2-one-command-trader-read-as-refused-at-exit",
                "a terminal met the next GET at the owner",
            ),
            (
                "ss2-one-command-peer-wait-read-as-uncounted",
                "the peer's read waited for the command",
            ),
            (
                "ss2-one-command-peer-read-as-submitted",
                "the peer's read took a free command",
            ),
            (
                "ss2-three-commands-peer-wait-read-as-counted",
                "the peer's read waited for the command",
            ),
            (
                "ss2-one-command-trader-read-as-undecided-at-exit",
                "a trader decided at the exit",
            ),
            (
                "ss2-one-command-trades-stalled",
                "a terminal met the next GET at the owner",
            ),
        ];
        let controls: Vec<_> = super::scenarios()
            .filter(|h| h.expect != Expect::Pass)
            .collect();
        assert_eq!(controls.len(), killed.len() + unsuccessful.len());
        let declared = killed
            .map(|(name, obligation, rule)| (name, Expect::Violation(obligation, rule)))
            .into_iter()
            .chain(unsuccessful.map(|(name, witness)| (name, Expect::Unsuccessful(witness))));
        for (name, expect) in declared {
            let control = controls.iter().find(|h| h.name == name).expect(name);
            assert_eq!(control.expect, expect, "{name}");
            assert!(!control.premise.is_empty(), "{name} declares its premise");
            assert_eq!(first_failure(name, 3), expect.failure(), "{name}");
        }
    }

    mod old_right_beside_other_fills {
        use super::super::super::{End, LIMITS, mixed_run, sites_for};
        use super::super::{Failure, named};

        const NAMES: [&str; 2] = [
            "h1-get-held-across-other-fills",
            "h1-get-held-across-maintenance",
        ];

        /// Whether the run of history `name` under `root` ran to its end,
        /// and the first failure it records.
        fn ending(name: &str, root: u64) -> (bool, Option<Failure>) {
            let (profile, plan, goal) = named(name, root).expect(name);
            let chooser = profile.recorder(&sites_for(&plan));
            let (ran, first, _) = mixed_run(chooser, &profile, plan, goal, LIMITS, &mut ());
            (ran.report.end == End::Done, first)
        }

        /// Both histories run to their end and record no failure at four
        /// pinned roots. At root 21 the store never refuses a fill, so the
        /// fills of other keys end at their bound.
        #[test]
        fn both_histories_pass_at_pinned_roots() {
            let mut endings = Vec::new();
            for name in NAMES {
                for root in [1, 21, 250, 500] {
                    endings.push((name, root, ending(name, root)));
                }
            }
            let failed: Vec<_> = endings
                .iter()
                .filter(|(_, _, ending)| *ending != (true, None))
                .collect();
            assert!(failed.is_empty(), "{failed:?}");
        }
    }
}
