//! The tests judge storage fixture histories with the history oracle.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::attempt_tests::service;
use super::device::sim::{QuiesceMode, SimControl, Unwind};
use super::device::{
    BufferArena, CommandToken, Completion, DeviceStatus, PoolKind, QuiesceProgress, slot_of,
};
use super::evict::Commit;
use super::evict_tests::{drain, generous};
use super::layout::IO_UNIT;
use super::owner_fixture::{Device, arena, invalidate, publish, storage};
use super::publish_tests::{TRIES, budget, key};
use super::register::Registration;
use super::test_platform::TestPlatform;
use super::volume::{ReadEvent, ReadStatus};
use super::volume_fixture::{TestVolume, drive, step};
use super::{AllocationId, ExtentLease, LookupError, Storage};
use crate::index::Key;
use crate::oracle::{
    ActionKind, Checkpoint, ClockSample, Continuation, Custodian, Entry, Geometry, Inconclusive,
    KeyId, LIMITS, Label, NoInformation, Obligation, OpId, Ordinal, Outcome, Owner, Pending,
    Recorder, ReportKind, ReportState, ResourceKind, Row, Verdict, VisibilityCause, WideOp, check,
};
use crate::sim::round::{Act, Actor, round};

const READ: PoolKind = PoolKind::ReadResponse;
const FREE_CLASS: usize = 0;
const RETIRED_CLASS: usize = 6;
const SECOND: u64 = 1_000_000_000;
const K: KeyId = KeyId(0);
const KEEP: KeyId = KeyId(1);
const A: Label = Label(1);
const B: Label = Label(2);
const C: Label = Label(3);
pub(super) const META: usize = 16;

type Instance = (ResourceKind, u32, u64);

/// The test's own custody record of a storage fixture run: a recorder whose
/// rows describe what production took and returned, beside the credits the
/// test's leases hold.
pub(super) struct Watch {
    pub(super) rec: Recorder,
    credits: Vec<u32>,
    next_credit: u32,
}

pub(super) fn generated(key: KeyId, label: Label, len: usize) -> Vec<u8> {
    let (metadata, body) = lengths(len);
    Recorder::content(key, label, metadata, body)
}

/// The metadata and body lengths of a `len`-byte [`generated`] payload.
pub(super) fn lengths(len: usize) -> (u32, u64) {
    (META as u32, (len - META) as u64)
}

pub(super) fn in_use(arena: &BufferArena<TestPlatform>) -> BTreeSet<(u32, u64)> {
    arena
        .pools()
        .snapshot(READ)
        .into_iter()
        .enumerate()
        .filter(|&(_, (class, _))| class != FREE_CLASS && class != RETIRED_CLASS)
        .map(|(index, (_, incarnation))| (index as u32, incarnation))
        .collect()
}

fn outstanding(volume: &TestVolume<'_, '_>) -> CommandToken {
    let pending: Vec<CommandToken> = volume
        .table_tokens()
        .into_iter()
        .filter_map(|(token, pending)| pending.then_some(token))
        .collect();
    assert_eq!(pending.len(), 1, "one outstanding command");
    pending[0]
}

pub(super) fn command(token: CommandToken) -> Instance {
    (
        ResourceKind::Command,
        u32::from(slot_of(token)),
        token.raw(),
    )
}

pub(super) fn buffer((index, incarnation): (u32, u64)) -> Instance {
    (ResourceKind::Buffer, index, incarnation)
}

/// The slot and incarnation a lease names.
pub(super) fn held(lease: &ExtentLease<'_, TestPlatform>) -> (u32, u64) {
    identity(lease.id())
}

pub(super) fn identity(id: AllocationId) -> (u32, u64) {
    (id.slot_index() as u32, u64::from(id.incarnation()))
}

/// The allocation a record's header names for the slot and incarnation
/// `at`: the slot in the high 32 bits and the incarnation in the low 32.
pub(super) fn allocation((slot, incarnation): (u32, u64)) -> u64 {
    (u64::from(slot) << 32) | incarnation
}

fn resident(storage: &Storage<TestPlatform>, object: &Key) -> (u32, u64) {
    let mut reader = storage.register().expect("a registration");
    held(
        &reader
            .lookup(object, TRIES, &mut budget())
            .expect("the object"),
    )
}

fn slot((index, incarnation): (u32, u64)) -> Instance {
    (ResourceKind::Slot, index, incarnation)
}

fn extent((index, incarnation): (u32, u64)) -> Instance {
    (ResourceKind::Extent, index, incarnation)
}

impl Watch {
    fn new(storage: &Storage<TestPlatform>) -> Self {
        Self::in_episode(storage, 1)
    }

    /// A watch whose rows carry episode `episode`.
    pub(super) fn in_episode(storage: &Storage<TestPlatform>, episode: u16) -> Self {
        let mut rec = Recorder::new(episode);
        let charged = storage.engine_used() as u64;
        rec.take(
            (ResourceKind::BudgetCharge, 0, 0),
            Custodian::Owner,
            Some((0, charged)),
        );
        Self {
            rec,
            credits: Vec::new(),
            next_credit: 0,
        }
    }

    fn clock(storage: &Storage<TestPlatform>) -> ClockSample {
        storage
            .platform
            .last_sample()
            .map_or(ClockSample::Unavailable, |now| {
                ClockSample::Seconds(now / SECOND)
            })
    }

    /// Records `object`'s publication through `device`, whose last fill wrote it, with that fill's write evidence.
    pub(super) fn published(
        &mut self,
        (storage, device): (&Storage<TestPlatform>, &Device<'_, '_>),
        object: &Key,
        (key, label): (KeyId, Label),
        payload: &[u8],
    ) -> (u32, u64) {
        let at = resident(storage, object);
        let written = crate::net::fills_written_in(device.volume.bound_tokens(), &device.control)
            .pop()
            .expect("the fill's write evidence");
        self.rec.published_written(
            key,
            label,
            META as u32,
            payload,
            (device.volume.session(), allocation(at)),
            Some(written),
        );
        let locator = storage.live_pool().expect("a live pool").records()[at.0 as usize].locator();
        let span = (locator.start_unit(), u64::from(locator.len_units()));
        self.rec.hold(slot(at), Custodian::Storage, (key, label));
        self.rec.take(extent(at), Custodian::Storage, Some(span));
        at
    }

    /// Looks `object` up and records what production answered: a hit under
    /// `label` with its lease's credit, or the miss, expiry or refusal.
    pub(super) fn lookup<'s>(
        &mut self,
        storage: &'s Storage<TestPlatform>,
        reader: &mut Registration<'s, TestPlatform>,
        object: &Key,
        (key, label): (KeyId, Label),
    ) -> Option<(ExtentLease<'s, TestPlatform>, OpId)> {
        let answer = reader.lookup(object, TRIES, &mut budget());
        let clock = Some(Self::clock(storage));
        let refused = match answer {
            Ok(lease) => {
                let op = self.rec.lookup_at(key, Outcome::Hit, Some(label), clock);
                self.lease_taken(held(&lease));
                return Some((lease, op));
            }
            Err(LookupError::Missing) => Outcome::Missing,
            Err(LookupError::Expired) => {
                self.rec
                    .lookup_at(key, Outcome::Expired, Some(label), clock);
                return None;
            }
            Err(LookupError::Contended) => Outcome::NoInformation(NoInformation::Contended),
            Err(LookupError::LeaseLimit) => Outcome::NoInformation(NoInformation::LeaseLimit),
            Err(LookupError::RetainLimit) => Outcome::NoInformation(NoInformation::RetainLimit),
            Err(LookupError::ClockUnavailable) => {
                self.rec.lookup_at(
                    key,
                    Outcome::NoInformation(NoInformation::ClockUnavailable),
                    Some(label),
                    Some(ClockSample::Unavailable),
                );
                return None;
            }
            Err(LookupError::Closed) => Outcome::NoInformation(NoInformation::Closed),
        };
        self.rec.lookup_at(key, refused, None, None);
        None
    }

    fn lease_taken(&mut self, at: (u32, u64)) {
        self.duplicate_taken(at);
        let credit = self.next_credit;
        self.next_credit += 1;
        self.credits.push(credit);
        self.rec
            .take((ResourceKind::Credit, credit, 0), Custodian::Reader, None);
    }

    /// Drops `lease` and records its credit and extent right returned.
    pub(super) fn returned(&mut self, lease: ExtentLease<'_, TestPlatform>) {
        let at = held(&lease);
        drop(lease);
        self.lease_returned(at);
    }

    pub(super) fn lease_returned(&mut self, at: (u32, u64)) {
        self.duplicate_returned(at);
        let credit = self.credits.pop().expect("a held credit");
        self.rec
            .release((ResourceKind::Credit, credit, 0), Custodian::Reader);
    }

    pub(super) fn duplicate_taken(&mut self, at: (u32, u64)) {
        self.rec.take(extent(at), Custodian::Reader, None);
    }

    pub(super) fn duplicate_returned(&mut self, at: (u32, u64)) {
        self.rec.release(extent(at), Custodian::Reader);
    }

    pub(super) fn retired(&mut self, at: (u32, u64)) {
        self.rec.release(slot(at), Custodian::Storage);
        self.rec.take(slot(at), Custodian::Grace, None);
    }

    pub(super) fn reclaimed(&mut self, at: (u32, u64), owner: (KeyId, Label)) {
        self.rec
            .end_visibility(slot(at), Custodian::Grace, owner, VisibilityCause::GraceEnd);
        self.rec.release(extent(at), Custodian::Storage);
    }

    fn submitted(
        &mut self,
        volume: &TestVolume<'_, '_>,
        arena: &BufferArena<TestPlatform>,
        before: &BTreeSet<(u32, u64)>,
    ) -> (Instance, Instance) {
        let token = command(outstanding(volume));
        let fresh: Vec<_> = in_use(arena).difference(before).copied().collect();
        assert_eq!(fresh.len(), 1, "one response buffer");
        let response = buffer(fresh[0]);
        self.rec.take(token, Custodian::Storage, None);
        self.rec.take(response, Custodian::Storage, None);
        (token, response)
    }

    fn completed(&mut self, (token, response): (Instance, Instance)) {
        self.rec.terminal(token, Outcome::Complete);
        self.rec.release(response, Custodian::Storage);
    }

    fn pool(&mut self, arena: &BufferArena<TestPlatform>) {
        let report = arena.report(READ);
        let held = report.count - report.free - report.retired;
        self.rec.report(
            ResourceKind::Buffer,
            ReportKind::Pool,
            ReportState::Value(u64::from(held)),
        );
        self.rec.report(
            ResourceKind::Buffer,
            ReportKind::Mismatched,
            ReportState::Value(report.mismatched),
        );
    }

    fn ledger(&mut self, storage: &Storage<TestPlatform>) {
        let slots = match storage.pool_report().map(|report| report.ledger) {
            Some(Some(ledger)) => {
                let slots = ledger.slots;
                ReportState::Value((slots.filling + slots.resident + slots.retired) as u64)
            }
            Some(None) => ReportState::Poisoned,
            None => ReportState::Absent,
        };
        self.rec
            .report(ResourceKind::Slot, ReportKind::Ledger, slots);
        let units = match storage.pool_report().map(|report| report.ledger) {
            Some(Some(ledger)) => {
                let raw = ledger.raw;
                ReportState::Value(
                    ((raw.reserved + raw.resident + raw.retired + raw.waste) / IO_UNIT) as u64,
                )
            }
            Some(None) => ReportState::Poisoned,
            None => ReportState::Absent,
        };
        self.rec
            .report(ResourceKind::Extent, ReportKind::Ledger, units);
        self.rec.report(
            ResourceKind::BudgetCharge,
            ReportKind::EngineBudget,
            ReportState::Value(storage.engine_used() as u64),
        );
        let credits = storage
            .lease_report()
            .map_or(ReportState::Absent, |report| {
                ReportState::Value(report.reserved as u64)
            });
        self.rec
            .report(ResourceKind::Credit, ReportKind::Ledger, credits);
    }

    fn table(&mut self, volume: &TestVolume<'_, '_>) {
        let report = volume.table_report();
        self.rec.report(
            ResourceKind::Command,
            ReportKind::Table,
            ReportState::Value(u64::from(report.pending + report.abandoned)),
        );
        self.rec.report(
            ResourceKind::Command,
            ReportKind::Mismatched,
            ReportState::Value(report.stale),
        );
    }

    pub(super) fn reports(
        &mut self,
        storage: &Storage<TestPlatform>,
        arena: &BufferArena<TestPlatform>,
        volume: &TestVolume<'_, '_>,
    ) {
        self.pool(arena);
        self.ledger(storage);
        self.table(volume);
    }
}

fn statuses_at(volume: &mut TestVolume<'_, '_>, control: &SimControl, now: u64) -> Vec<ReadStatus> {
    let mut out = Vec::with_capacity(16);
    let mut done = Vec::new();
    for _ in 0..8 {
        let mut tick = || control.tick(64);
        let mut poll = || {
            let _ = volume.poll_storage(now, &mut out);
        };
        round(&mut [
            Act::new(Actor::Disk(0), &mut tick),
            Act::new(Actor::Volume(0), &mut poll),
        ]);
        done.extend(out.drain(..).filter_map(|event| match event {
            ReadEvent::Done { status, .. } => Some(status),
            ReadEvent::Chunk { .. } => None,
        }));
    }
    done
}

fn judged(rows: Vec<Row>) -> Verdict {
    check(&Recorder::rebuilt(rows))
}

fn is_return(row: &Row, kind: ResourceKind) -> bool {
    matches!(row.kind, ActionKind::Release | ActionKind::Terminal)
        && row.resource().is_some_and(|r| r.kind == kind)
}

fn held_read_across_invalidation() -> Vec<Row> {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::new(&storage);
    let object = key(1);
    let payload = generated(K, A, 3000);
    publish(&storage, &mut device, &object, META, &payload);
    let at = w.published((&storage, &device), &object, (K, A), &payload);
    w.reports(&storage, &arena, &device.volume);
    let mut reader = storage.register().expect("a registration");
    let (lease, read) = w
        .lookup(&storage, &mut reader, &object, (K, A))
        .expect("the object");
    w.reports(&storage, &arena, &device.volume);
    invalidate(&storage, &object).expect("invalidated");
    w.rec.invalidate(K, Outcome::Acknowledged);
    w.retired(at);
    device.persist_journal();
    w.reports(&storage, &arena, &device.volume);
    let mut fresh = storage.register().expect("a registration");
    assert_eq!(
        fresh.lookup(&object, TRIES, &mut budget()).err(),
        Some(LookupError::Missing)
    );
    w.rec.lookup_at(K, Outcome::Missing, None, None);
    let before = in_use(&arena);
    let op = device
        .volume
        .read(lease.duplicate(), u64::MAX)
        .expect("admitted");
    w.duplicate_taken(at);
    let issued = w.submitted(&device.volume, &arena, &before);
    w.reports(&storage, &arena, &device.volume);
    let delivered = drive(&mut device.volume, &device.control, op);
    assert_eq!(delivered.status, ReadStatus::Complete);
    assert_eq!(delivered.bytes, payload);
    let info = delivered.info.expect("a complete read verified its header");
    w.rec.delivered(
        read,
        (K, A),
        (META as u32, (payload.len() - META) as u64),
        (info.identity().session, info.identity().allocation),
        Outcome::Complete,
        delivered.bytes,
    );
    w.completed(issued);
    w.duplicate_returned(at);
    w.reports(&storage, &arena, &device.volume);
    drop(lease);
    w.lease_returned(at);
    drop((reader, fresh));
    w.reports(&storage, &arena, &device.volume);
    drain(&storage);
    w.reclaimed(at, (K, A));
    w.reports(&storage, &arena, &device.volume);
    w.rec.checkpoint(Checkpoint::Released);
    w.rec.rows().to_vec()
}

#[test]
fn a_held_read_across_invalidation_delivers_the_old_bytes_beside_a_fresh_miss() {
    let verdict = judged(held_read_across_invalidation());
    assert!(
        verdict.satisfies(&[
            Obligation::History,
            Obligation::Bytes,
            Obligation::Custody,
            Obligation::Resources,
        ]),
        "{verdict:?}"
    );
}

/// The live history fed to the oracle's continuation in segments of whole
/// rows, cut after each completion ordinal, judges as the whole check judges
/// it.
#[test]
fn the_live_history_judges_alike_through_the_continuation() {
    let rows = held_read_across_invalidation();
    let whole = judged(rows.clone());
    let mut ordered = rows.clone();
    ordered.sort_by_key(|row| row.ordinals().map(|(_, at)| at.0).max());
    let mut continuation = Continuation::new(LIMITS, Geometry::GOLDEN);
    let mut fed = 0;
    while fed < ordered.len() {
        let end = ordered[fed]
            .ordinals()
            .map(|(_, at)| at.0)
            .max()
            .unwrap_or(0);
        let next = ordered[fed..]
            .iter()
            .take_while(|row| row.ordinals().map(|(_, at)| at.0).max().unwrap_or(0) == end)
            .count();
        let segment: Vec<Entry> = ordered[fed..fed + next]
            .iter()
            .map(|row| Entry::new(row.clone(), WideOp(u64::from(row.op.0)), Owner(0)))
            .collect();
        fed += next;
        let cut = Ordinal(end + 1);
        let mut pending: Vec<Pending> = Vec::new();
        for row in &ordered[fed..] {
            let Some(start) = row.ordinals().map(|(_, at)| at).min() else {
                continue;
            };
            let op = WideOp(u64::from(row.op.0));
            match pending.iter_mut().find(|open| open.op == op) {
                Some(open) => open.invoked = open.invoked.min(start),
                None if start < cut => pending.push(Pending { op, invoked: start }),
                None => {}
            }
        }
        pending.retain(|open| open.invoked < cut);
        continuation.segment(segment, cut, &pending);
    }
    let verdict = continuation.finish();
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
    assert_eq!(verdict, whole);
}

#[test]
fn leaked_capacity_control_fails_resources_on_the_live_history() {
    let rows = held_read_across_invalidation();
    for kind in [
        ResourceKind::Buffer,
        ResourceKind::Slot,
        ResourceKind::Extent,
        ResourceKind::Command,
        ResourceKind::Credit,
    ] {
        let mut leaked = rows.clone();
        let returned = leaked
            .iter()
            .rposition(|row| is_return(row, kind))
            .expect("a return");
        leaked.remove(returned);
        assert_eq!(
            judged(leaked.clone()).violated(),
            Some((
                Obligation::Resources,
                "a production report disagreed with the independent count"
            )),
            "{kind:?}"
        );
        leaked.retain(|row| row.kind != ActionKind::Report);
        assert_eq!(
            judged(leaked).violated(),
            Some((
                Obligation::Resources,
                "a released checkpoint kept capacity its obligations no longer justify"
            )),
            "{kind:?}"
        );
    }
}

#[test]
fn a_report_that_disagrees_with_the_live_count_cannot_pass() {
    let mut rows = held_read_across_invalidation();
    let report = rows
        .iter()
        .position(|row| row.report.is_some_and(|r| r.kind == ReportKind::Pool))
        .expect("a pool report");
    let mut incoherent = rows[report].report.expect("a report");
    incoherent.state = ReportState::Value(7);
    rows[report].report = Some(incoherent);
    assert_eq!(
        judged(rows).violated(),
        Some((
            Obligation::Resources,
            "a production report disagreed with the independent count"
        ))
    );
}

fn cancelled_read(stop: QuiesceMode) -> Vec<Row> {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::new(&storage);
    let object = key(1);
    let payload = generated(K, A, 3000);
    publish(&storage, &mut device, &object, META, &payload);
    device.persist_journal();
    let at = w.published((&storage, &device), &object, (K, A), &payload);
    w.reports(&storage, &arena, &device.volume);
    let mut reader = storage.register().expect("a registration");
    let (lease, _) = w
        .lookup(&storage, &mut reader, &object, (K, A))
        .expect("the object");
    for deadline in [None, Some(10)] {
        let before = in_use(&arena);
        let op = device
            .volume
            .read(lease.duplicate(), deadline.unwrap_or(u64::MAX))
            .expect("admitted");
        w.duplicate_taken(at);
        let issued = w.submitted(&device.volume, &arena, &before);
        let token = outstanding(&device.volume);
        device.control.hold(token);
        let ended = match deadline {
            None => {
                device.volume.cancel_read(op).expect("live");
                w.rec.cancel(issued.0);
                ReadStatus::Cancelled
            }
            Some(_) => ReadStatus::TimedOut,
        };
        if deadline.is_some() {
            w.rec.cancel(issued.0);
        }
        let now = deadline.unwrap_or(0);
        assert_eq!(
            statuses_at(&mut device.volume, &device.control, now),
            [ended]
        );
        w.reports(&storage, &arena, &device.volume);
        assert_eq!(
            arena.report(READ).quarantined,
            1,
            "the command kept its buffer"
        );
        device.control.release(token);
        assert!(statuses_at(&mut device.volume, &device.control, now).is_empty());
        w.completed(issued);
        w.duplicate_returned(at);
        w.reports(&storage, &arena, &device.volume);
        assert_eq!(
            arena.report(READ).free,
            4,
            "the late terminal returned it once"
        );
    }
    let before = in_use(&arena);
    let _held = device
        .volume
        .read(lease.duplicate(), u64::MAX)
        .expect("admitted");
    w.duplicate_taken(at);
    w.submitted(&device.volume, &arena, &before);
    let current = outstanding(&device.volume);
    device.control.hold(current);
    let stale = CommandToken::from_raw(current.raw() ^ (1 << 16));
    assert_eq!(slot_of(stale), slot_of(current));
    device.control.inject(
        Completion {
            token: stale,
            status: DeviceStatus::Kernel(4096),
        },
        super::device::sim::Injection::Foreign,
    );
    assert!(statuses_at(&mut device.volume, &device.control, 0).is_empty());
    w.rec.terminal(command(stale), Outcome::Complete);
    w.reports(&storage, &arena, &device.volume);
    assert_eq!(device.volume.table_report().stale, 1);
    drop(lease);
    drop(reader);
    w.lease_returned(at);
    w.reports(&storage, &arena, &device.volume);
    device.control.set_quiesce(stop);
    assert!(matches!(
        device.volume.close(),
        QuiesceProgress::Draining { .. } | QuiesceProgress::Unproven { .. }
    ));
    w.rec.checkpoint(Checkpoint::Unproven);
    w.reports(&storage, &arena, &device.volume);
    drop(device);
    w.pool(&arena);
    w.ledger(&storage);
    assert!(
        arena.release().is_err(),
        "a stop without proof keeps the arena"
    );
    w.rec.rows().to_vec()
}

#[test]
fn a_cancelled_or_timed_out_read_keeps_custody_until_its_late_terminal() {
    for stop in [QuiesceMode::Unproven, QuiesceMode::Failed(Some(7))] {
        let verdict = judged(cancelled_read(stop));
        assert!(
            verdict.satisfies(&[
                Obligation::History,
                Obligation::Custody,
                Obligation::Resources
            ]),
            "{stop:?}: {verdict:?}"
        );
    }
}

#[test]
fn a_buffer_freed_at_the_cancel_fails_the_live_count() {
    let mut rows = cancelled_read(QuiesceMode::Unproven);
    let cancel = rows
        .iter()
        .position(|row| row.kind == ActionKind::Cancel)
        .expect("the cancel");
    let freed = rows
        .iter()
        .position(|row| is_return(row, ResourceKind::Buffer))
        .expect("the late return");
    let early = rows.remove(freed);
    rows.insert(cancel + 1, early);
    Recorder::renumber(&mut rows);
    assert_eq!(
        judged(rows).violated(),
        Some((
            Obligation::Resources,
            "a production report disagreed with the independent count"
        ))
    );
}

struct Returned {
    rows: Vec<Row>,
    buffer: (u32, u64),
    keep: (u64, u64),
}

fn delayed_nic_return() -> Returned {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::new(&storage);
    let (kept, object) = (key(2), key(1));
    let (kept_bytes, payload) = (generated(KEEP, C, 48), generated(K, A, 48));
    publish(&storage, &mut device, &kept, META, &kept_bytes);
    let kept_at = w.published((&storage, &device), &kept, (KEEP, C), &kept_bytes);
    publish(&storage, &mut device, &object, META, &payload);
    let at = w.published((&storage, &device), &object, (K, A), &payload);
    w.reports(&storage, &arena, &device.volume);
    let mut reader = storage.register().expect("a registration");
    let (lease, read) = w
        .lookup(&storage, &mut reader, &object, (K, A))
        .expect("the object");
    let before = in_use(&arena);
    device.volume.read(lease, u64::MAX).expect("admitted");
    let issued = w.submitted(&device.volume, &arena, &before);
    let mut out = Vec::with_capacity(16);
    let mut chunk = None;
    let mut status = None;
    let mut verified = None;
    for _ in 0..64 {
        step(&mut device.volume, &device.control, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { chunk: held, .. } => chunk = Some(held),
                ReadEvent::Done {
                    status: done, info, ..
                } => (status, verified) = (Some(done), info),
            }
        }
    }
    assert_eq!(status, Some(ReadStatus::Complete));
    let chunk = chunk.expect("one chunk");
    assert_eq!(chunk.bytes(), payload);
    let info = verified.expect("a complete read verified its header");
    w.rec.delivered(
        read,
        (K, A),
        (META as u32, (payload.len() - META) as u64),
        (info.identity().session, info.identity().allocation),
        Outcome::Complete,
        chunk.bytes().to_vec(),
    );
    w.rec.terminal(issued.0, Outcome::Complete);
    w.rec.release(issued.1, Custodian::Storage);
    w.rec.take(issued.1, Custodian::Owner, None);
    w.lease_returned(at);
    w.reports(&storage, &arena, &device.volume);
    let (_, index, incarnation) = chunk
        .source(0..payload.len())
        .expect("a source")
        .hold()
        .expect("a reference")
        .into_raw();
    assert_eq!(buffer((index, incarnation)), issued.1);
    w.rec.take(issued.1, Custodian::Nic, None);
    drop(chunk);
    w.rec.release(issued.1, Custodian::Owner);
    drop(reader);
    w.reports(&storage, &arena, &device.volume);
    assert_eq!(arena.report(READ).nic_held, 1);
    invalidate(&storage, &object).expect("invalidated");
    w.rec.invalidate(K, Outcome::Acknowledged);
    w.retired(at);
    w.reports(&storage, &arena, &device.volume);
    device.persist_journal();
    drain(&storage);
    w.reclaimed(at, (K, A));
    w.reports(&storage, &arena, &device.volume);
    let others: Vec<_> = (0..3)
        .map(|_| arena.acquire(READ).expect("a free buffer"))
        .collect();
    assert!(
        arena.acquire(READ).is_err(),
        "the NIC-held buffer stays out of reuse"
    );
    for other in &others {
        w.rec.take(buffer(other.identity()), Custodian::Owner, None);
    }
    w.pool(&arena);
    for other in others {
        let identity = other.identity();
        drop(other);
        w.rec.release(buffer(identity), Custodian::Owner);
    }
    w.pool(&arena);
    for (named, returned) in [
        (incarnation + 1, false),
        (incarnation, true),
        (incarnation, false),
    ] {
        // SAFETY: each live reference named here was detached with `into_raw` and returns once; any other identity names no live reference.
        assert_eq!(unsafe { arena.nic_return(READ, index, named) }, returned);
        w.rec.release(buffer((index, named)), Custodian::Nic);
        w.pool(&arena);
    }
    assert_eq!(arena.report(READ).mismatched, 2);
    let all: Vec<_> = (0..4)
        .map(|_| arena.acquire(READ).expect("a free buffer"))
        .collect();
    for held in &all {
        w.rec.take(buffer(held.identity()), Custodian::Owner, None);
    }
    w.pool(&arena);
    for held in all {
        let identity = held.identity();
        drop(held);
        w.rec.release(buffer(identity), Custodian::Owner);
    }
    w.pool(&arena);
    service(&storage);
    let republished = generated(K, B, 48);
    publish(&storage, &mut device, &object, META, &republished);
    w.published((&storage, &device), &object, (K, B), &republished);
    w.reports(&storage, &arena, &device.volume);
    w.rec.checkpoint(Checkpoint::Stopped);
    let locator = storage.live_pool().expect("a live pool").records()[kept_at.0 as usize].locator();
    Returned {
        rows: w.rec.rows().to_vec(),
        buffer: (index, incarnation),
        keep: (locator.start_unit(), u64::from(locator.len_units())),
    }
}

#[test]
fn a_delayed_nic_return_pins_its_buffer_while_the_disk_extent_returns() {
    let returned = delayed_nic_return();
    assert!(
        returned
            .rows
            .iter()
            .any(|row| row.cause == Some(VisibilityCause::GraceEnd) && row.label == Some(A)),
        "the retired extent's grace ended"
    );
    let verdict = judged(returned.rows);
    assert!(
        verdict.satisfies(&[
            Obligation::History,
            Obligation::Bytes,
            Obligation::Custody,
            Obligation::Resources,
        ]),
        "{verdict:?}"
    );
}

#[test]
fn early_reuse_control_fails_custody_on_the_live_history() {
    let Returned {
        mut rows,
        buffer: (index, incarnation),
        keep,
    } = delayed_nic_return();
    let reuse = rows
        .iter()
        .position(|row| {
            row.kind == ActionKind::Take
                && row
                    .resource()
                    .is_some_and(|r| r.kind == ResourceKind::Buffer && r.index == index)
                && row.incarnation.is_some_and(|i| i.0 > incarnation)
        })
        .expect("the reused incarnation's take");
    let returned = rows
        .iter()
        .position(|row| {
            row.kind == ActionKind::Release
                && row.custodian == Some(Custodian::Nic)
                && row.incarnation.is_some_and(|i| i.0 == incarnation)
        })
        .expect("the NIC return");
    let mut early = rows.clone();
    let take = early.remove(reuse);
    early.insert(returned, take);
    Recorder::renumber(&mut early);
    assert_eq!(
        judged(early).violated(),
        Some((
            Obligation::Custody,
            "a resource was reused while a custodian held an earlier incarnation"
        ))
    );
    let mut accepted = rows.clone();
    let refused = accepted
        .iter()
        .position(|row| {
            row.kind == ActionKind::Release
                && row.custodian == Some(Custodian::Nic)
                && row.incarnation.is_some_and(|i| i.0 > incarnation)
        })
        .expect("the refused NIC return");
    accepted.remove(refused);
    assert_eq!(
        judged(accepted).violated(),
        Some((
            Obligation::Resources,
            "a production report disagreed with the independent count"
        ))
    );
    let republished = rows
        .iter()
        .rposition(|row| row.kind == ActionKind::Take && row.span.is_some())
        .expect("the republication's extent");
    rows[republished].span = Some(keep);
    assert_eq!(
        judged(rows).violated(),
        Some((Obligation::Custody, "writable extents overlapped"))
    );
}

#[test]
fn an_eviction_ends_the_label_and_returns_the_extent_after_grace() {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::new(&storage);
    let object = key(1);
    let payload = generated(K, A, 48);
    publish(&storage, &mut device, &object, META, &payload);
    let at = w.published((&storage, &device), &object, (K, A), &payload);
    w.reports(&storage, &arena, &device.volume);
    let report = storage
        .evict_step(&mut generous(), |_, _| true)
        .expect("an eviction step");
    assert!(matches!(
        report.commit,
        Some(Commit::Evicted { victim, .. }) if victim.slot_index() == at.0 as usize
    ));
    w.rec.end_visibility(
        slot(at),
        Custodian::Storage,
        (K, A),
        VisibilityCause::Eviction,
    );
    w.rec.take(slot(at), Custodian::Grace, None);
    w.reports(&storage, &arena, &device.volume);
    let mut reader = storage.register().expect("a registration");
    assert_eq!(
        reader.lookup(&object, TRIES, &mut budget()).err(),
        Some(LookupError::Missing)
    );
    w.rec.lookup_at(K, Outcome::Missing, None, None);
    device.persist_journal();
    drain(&storage);
    w.rec.release(slot(at), Custodian::Grace);
    w.rec.release(extent(at), Custodian::Storage);
    w.reports(&storage, &arena, &device.volume);
    w.rec.checkpoint(Checkpoint::Released);
    let verdict = check(&w.rec.finish());
    assert!(
        verdict.satisfies(&[
            Obligation::History,
            Obligation::Custody,
            Obligation::Resources
        ]),
        "{verdict:?}"
    );
}

#[test]
fn a_production_panic_before_the_check_leaves_the_stream_truncated() {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::new(&storage);
    let object = key(1);
    let payload = generated(K, A, 48);
    publish(&storage, &mut device, &object, META, &payload);
    let at = w.published((&storage, &device), &object, (K, A), &payload);
    let mut reader = storage.register().expect("a registration");
    let (lease, _) = w
        .lookup(&storage, &mut reader, &object, (K, A))
        .expect("the object");
    let before = in_use(&arena);
    device.volume.read(lease, u64::MAX).expect("admitted");
    w.submitted(&device.volume, &arena, &before);
    w.reports(&storage, &arena, &device.volume);
    device.control.unwind_next(Some(Unwind::Pick));
    let judged_stream = catch_unwind(AssertUnwindSafe(|| {
        let mut out = Vec::with_capacity(16);
        step(&mut device.volume, &device.control, &mut out);
        w.lease_returned(at);
        w.reports(&storage, &arena, &device.volume);
        std::mem::replace(&mut w.rec, Recorder::new(1)).finish()
    }));
    assert!(judged_stream.is_err(), "the driver unwound");
    let verdict = check(&w.rec.unsealed());
    assert_eq!(verdict, Verdict::Inconclusive(Inconclusive::Truncated));
    assert!(!verdict.satisfies(&[Obligation::Custody]));
}

#[test]
fn a_lookup_without_a_clock_sample_records_a_judgeable_refusal() {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::new(&storage);
    let object = key(1);
    let payload = generated(K, A, 48);
    publish(&storage, &mut device, &object, META, &payload);
    w.published((&storage, &device), &object, (K, A), &payload);
    storage.platform.ticks(&[None]);
    let mut reader = storage.register().expect("a registration");
    assert!(w.lookup(&storage, &mut reader, &object, (K, A)).is_none());
    let refusal = w.rec.rows().last().expect("the lookup row");
    assert_eq!(
        refusal.outcome,
        Some(Outcome::NoInformation(NoInformation::ClockUnavailable))
    );
    let verdict = judged(w.rec.rows().to_vec());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
}

#[test]
fn a_poisoned_pool_gate_reports_nothing_that_can_pass() {
    let storage = storage(8);
    let arena = arena(4);
    let mut device = Device::new(&storage, &arena);
    let mut w = Watch::new(&storage);
    let object = key(1);
    let payload = generated(K, A, 48);
    publish(&storage, &mut device, &object, META, &payload);
    w.published((&storage, &device), &object, (K, A), &payload);
    w.reports(&storage, &arena, &device.volume);
    let poisoned = catch_unwind(AssertUnwindSafe(|| {
        let _held = storage.live_pool().expect("a live pool").lock();
        panic!("a holder of the pool gate unwound");
    }));
    assert!(poisoned.is_err());
    w.ledger(&storage);
    w.rec.checkpoint(Checkpoint::Stopped);
    assert!(matches!(
        check(&w.rec.finish()),
        Verdict::Inconclusive(Inconclusive::PoisonedReport { .. })
    ));
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_buffer_freed_at_the_cancel_fails_the_live_count,
    a_cancelled_or_timed_out_read_keeps_custody_until_its_late_terminal,
    a_delayed_nic_return_pins_its_buffer_while_the_disk_extent_returns,
    a_held_read_across_invalidation_delivers_the_old_bytes_beside_a_fresh_miss,
    a_poisoned_pool_gate_reports_nothing_that_can_pass,
    a_production_panic_before_the_check_leaves_the_stream_truncated,
    a_report_that_disagrees_with_the_live_count_cannot_pass,
    an_eviction_ends_the_label_and_returns_the_extent_after_grace,
    early_reuse_control_fails_custody_on_the_live_history,
    leaked_capacity_control_fails_resources_on_the_live_history,
    the_live_history_judges_alike_through_the_continuation,
);
