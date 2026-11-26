//! The planned-exit driver of authenticated requests: the owner's request intake, its one ledger beside the roll,
//! the transfer to the named standby through the store lane, the target's activation through its restart's lineage
//! arm, and the requested same-host restart.

use std::cell::Cell;
use std::num::NonZeroU32;
use std::rc::Rc;

use crate::host::Exit;

use crate::failover::planned::{Binding, Kind, PlannedRequest, RequestKey, Sequence, encode};
use crate::failover::records::ShardRecord;
use crate::failover::report::ExitOperation;

/// A driver defect a control plants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Plant {
    /// The transfer is submitted with the authority still serving and the owner open.
    EmitAfterTransfer,
    /// The withdrawal reopens admission and the transfer follows 40 turns later over the certified read, so FILLs and
    /// INVALIDATEs land after the seal and outside the certified cut.
    MutationsAfterSeal,
}

thread_local! {
    /// The machine state at whose first turn the harness's tenure crashes.
    static CRASH_AT: Cell<Option<crate::failover::planned::State>> = const { Cell::new(None) };
    static BOUND: std::cell::RefCell<Vec<Binding>> = const { std::cell::RefCell::new(Vec::new()) };
    static PLANTED: Cell<Option<Plant>> = const { Cell::new(None) };
    static ENROLLMENT_UNREAD: Cell<bool> = const { Cell::new(false) };
    static BOUNDARY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    /// A test's one-shot step at the withdrawal boundary, run after the emission sample.
    static AT_BOUNDARY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    /// The owner turns the inline lane holds the transfer's completion for; 0 lands it at once.
    static HOLD_TRANSFER: Cell<u32> = const { Cell::new(0) };
    /// The round at which the harness stops a tenure that has not ended.
    static STOP_AT: Cell<Option<u64>> = const { Cell::new(None) };
    /// When set, the harness holds the capture mutex across the first turn that starts in `Sealed` and records the
    /// seal there and after it.
    static BUSY_SEAL: std::cell::RefCell<Option<super::roll_tests::BusySeal>> =
        const { std::cell::RefCell::new(None) };
    /// The cause that withdraws the authority at the transfer's withdrawal, before the planned withdrawal.
    static WITHDRAWN_FIRST: Cell<Option<crate::failover::serving::Cause>> = const { Cell::new(None) };
    /// Whether the lane refuses the transfer's submit, as a lane with `DEPTH` jobs outstanding does.
    static REFUSE_TRANSFER: Cell<bool> = const { Cell::new(false) };
    /// The machine state from whose first turn on the harness feeds the duties one frozen clock reading.
    static FREEZE_AT: Cell<Option<crate::failover::planned::State>> = const { Cell::new(None) };
    /// The volume-read gate of [`Answering`]: 1 fails every volume-record read from the seal to the certify's
    /// write, which then commits a same-content shard rewrite at the next version; 2 once that happened.
    static VOLUME_GATE: Cell<u8> = const { Cell::new(0) };
    /// Whether the harness arms [`VOLUME_GATE`] at the seal.
    static GATED: Cell<bool> = const { Cell::new(false) };
    /// The store outage of a harness tenure: the machine state from whose first turn the store is down until the
    /// tenure resumes, and how the store fails while it is down.
    static OUTAGE: Cell<Option<(crate::failover::planned::State, Outage)>> = const { Cell::new(None) };
    /// Whether [`Answering`] answers no request: a read returns no value and a write is unknown and commits nothing.
    static DOWN: Cell<bool> = const { Cell::new(false) };
    /// Whether [`Answering`] returns no value for a read of a volume record.
    static VOLUME_DOWN: Cell<bool> = const { Cell::new(false) };
    /// Whether [`Answering`] returns no value for a read of a shard record.
    static SHARD_DOWN: Cell<bool> = const { Cell::new(false) };
    /// Whether the harness publishes one fresh FILL in the tenure after a resume, before it stops the tenure.
    static FILL_AFTER_RESUME: Cell<bool> = const { Cell::new(false) };
    /// The reclaim's end write of the target's attach, issued and not yet committed ([`Parking`]).
    static PARKED_END: std::cell::RefCell<Option<(crate::storage::store::Key, crate::storage::store::Write)>> =
        const { std::cell::RefCell::new(None) };
    /// The store's outcome of the parked end write once [`Answer::EndedFirst`] committed it.
    static END_OUTCOME: Cell<Option<crate::storage::store::Outcome>> = const { Cell::new(None) };
}

/// How a store outage answers the requests of a draining tenure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outage {
    /// Every request fails at once: a read returns no value and a write's outcome is unknown with no commit.
    Fails,
    /// Every request fails as under [`Outage::Fails`], and its completion reaches the owner only after the outage.
    Silent,
    /// Every read of a volume record returns no value, at once; every other request is answered.
    VolumeUnread,
}

/// Runs `body` with the thread-local `cell` set to `value`, and clears it after.
fn with_cell<C: Copy + Default + 'static, T>(
    cell: &'static std::thread::LocalKey<Cell<C>>,
    value: C,
    body: impl FnOnce() -> T,
) -> T {
    cell.with(|cell| cell.set(value));
    let out = body();
    cell.with(|cell| cell.set(C::default()));
    out
}

/// Whether the harness holds the transfer's completion on the inline lane.
pub(super) fn holds_transfer() -> bool {
    HOLD_TRANSFER.with(Cell::get) > 0
}

/// The cause that withdraws the authority at the transfer's withdrawal, before the planned withdrawal.
pub(super) fn withdrawn_first() -> Option<crate::failover::serving::Cause> {
    WITHDRAWN_FIRST.with(Cell::get)
}

/// Whether the lane refuses the transfer's submit.
pub(super) fn refuses_transfer() -> bool {
    REFUSE_TRANSFER.with(Cell::get)
}

/// Runs `body` with the transfer's completion held for `turns` owner turns.
fn holding<T>(turns: u32, body: impl FnOnce() -> T) -> T {
    HOLD_TRANSFER.with(|cell| cell.set(turns));
    let out = body();
    HOLD_TRANSFER.with(|cell| cell.set(0));
    out
}

/// Runs the harness's sample of its emission counters once, at the point where the driver withdraws the tenure for
/// its planned exit, before that withdrawal or anything after it in the same turn.
pub(super) fn boundary() {
    if let Some(sample) = BOUNDARY.with(|cell| cell.borrow_mut().take()) {
        sample();
    }
    if let Some(step) = AT_BOUNDARY.with(|cell| cell.borrow_mut().take()) {
        step();
    }
}

/// Whether the planted transfer job skips its read of the target's enrollment.
pub(crate) fn planted_enrollment_unread() -> bool {
    ENROLLMENT_UNREAD.with(Cell::get)
}

pub(super) fn planted(plant: Plant) -> bool {
    PLANTED.with(Cell::get) == Some(plant)
}

fn with_plant<T>(plant: Plant, body: impl FnOnce() -> T) -> T {
    PLANTED.with(|cell| cell.set(Some(plant)));
    let out = body();
    PLANTED.with(|cell| cell.set(None));
    out
}

/// The binding of the last request the intake decoded; the read clears every recorded binding.
fn last_bound() -> Option<Binding> {
    bindings().last().copied()
}

/// The bindings the ledger gave each request the intake decoded, in order; the read clears them.
fn bindings() -> Vec<Binding> {
    BOUND.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

/// Records the binding the ledger gave the last request the intake decoded.
pub(super) fn bound(binding: Binding) {
    BOUND.with(|cell| cell.borrow_mut().push(binding));
}

/// The request key of the test hosts.
pub(crate) fn key() -> RequestKey {
    RequestKey::derive(&[0x42; 32])
}

/// A request of `kind` for the tenure `record` names, sealed for its owner, with operation and sequence `n`.
pub(crate) fn sealed(record: &ShardRecord, kind: Kind, n: u8) -> Vec<u8> {
    sealed_by(record, kind, n, NonZeroU32::new(u32::MAX).unwrap())
}

/// [`sealed`] with the request's own deadline `deadline_us`.
fn sealed_by(record: &ShardRecord, kind: Kind, n: u8, deadline_us: NonZeroU32) -> Vec<u8> {
    let request = PlannedRequest {
        kind,
        operation: ExitOperation::new([n; 16]).unwrap(),
        sequence: Sequence::of(1, u32::from(n)),
        shard: record.shard,
        generation: record.generation,
        attempts: record.attempts,
        owner: record.owner,
        deadline_us,
    };
    encode(&request, &key()).to_vec()
}

/// The record the store holds for the test shard.
fn record_of(store: &crate::storage::store::sim::Shared) -> ShardRecord {
    crate::failover::restart::tests::shard_now(store)
}

/// A reservation table the owner's pair holds alone: the named standby holds no registration until its own
/// activation registers it.
fn own_alone() -> crate::storage::gate_fixture::Control {
    crate::host::fencer_tests::shared_table(vec![crate::failover::fresh::tests::registrant(
        crate::failover::restart::tests::own(),
        1,
        true,
    )])
}

/// One seed's handoff: the owner's tenure serves the warm objects, mutates, accepts a transfer to its named standby
/// and transfers; the standby's tenure then serves exactly the objects the owner held. Returns the records before the
/// owner's tenure, after its transfer and after the standby's tenure.
fn handed_over(seed: u64) -> Result<[ShardRecord; 3], String> {
    use super::roll_tests::Trigger;
    use super::step_tests::{Choices, Reached, run_cycle_as, warm_objects};
    use crate::host::recover_tests::Identity;
    let volume = crate::host::serve::tests::warm_volume_certified(0);
    let before = record_of(&volume.0);
    let registry = own_alone();
    let mut held = warm_objects();
    let (mut choices, mut reached) = (Choices::of(seed), Reached::default());
    crate::host::serve::tests::inline(|| {
        let (volume, _, _) = run_cycle_as(
            (Identity::owner(), registry.clone()),
            volume,
            (&mut held, &mut choices, &mut reached),
            Some(Trigger::Transfer),
        )?;
        let handed = record_of(&volume.0);
        let (volume, _, _) = run_cycle_as(
            (Identity::standby(), registry.clone()),
            volume,
            (&mut held, &mut choices, &mut reached),
            None,
        )?;
        Ok([before, handed, record_of(&volume.0)])
    })
}

/// TransferNamesStandby with HandoffCutIsExact: the owner A drains, publishes, certifies, withdraws and transfers to
/// its named standby C. The committed record names C owner at A's `E + 1` with no standby, on the same generation,
/// volume and checkpoint lineage, and C's restart activates at `E + 2` through its lineage arm and serves exactly the
/// objects A acknowledged, with every FILL and INVALIDATE A acknowledged before its drain.
#[test]
fn a_requested_transfer_hands_the_shard_to_its_standby_which_serves_every_acknowledged_mutation() {
    let [before, handed, after] = handed_over(7).unwrap_or_else(|failure| panic!("{failure}"));
    let c = crate::failover::takeover::tests::c_host();
    assert_eq!(before.standby, Some(c));
    let kept = |record: &ShardRecord| (record.generation, record.active);
    assert_eq!(kept(&handed), kept(&before));
    assert_eq!(
        (handed.owner, handed.standby, handed.attempts),
        (c, None, before.attempts + 2),
        "A's restart bumped once and its transfer consumed the next E"
    );
    assert_eq!(
        (after.owner, after.attempts),
        (c, handed.attempts + 1),
        "C activated through its own bump"
    );
}

/// How the store answers the transfer write, the first write that names the standby owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// The store commits and acknowledges it.
    Commit,
    /// The reply is lost; the write commits when `commit`.
    Unknown { commit: bool },
    /// Another writer moved the record's version first, so the write fails its condition.
    Moved,
    /// The standby's own takeover compare-and-swap committed first, naming it owner at `E + 1`, so the transfer
    /// fails its condition.
    TakenOver,
    /// The class documents that the principal may not make the write, which does not commit.
    Denied,
    /// The write commits and its reply names a version past the next one, which the client reads as a regression
    /// after the commit.
    Skewed,
    /// The reclaim's parked end of the target's attach ([`PARKED_END`]) commits first, after the transfer job's
    /// volume read and before this write, which then commits.
    EndedFirst,
    /// The reply is lost and the store parks the write: it applies, under its version condition, only when the test
    /// releases it.
    Parked,
}

/// A store over `inner` that answers the transfer write as `answer` says and passes every other request through.
struct Answering {
    inner: crate::storage::store::sim::Shared,
    answer: Rc<Cell<Option<Answer>>>,
}

impl crate::storage::store::Store for Answering {
    fn read(
        &mut self,
        key: &crate::storage::store::Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        let gated = VOLUME_GATE.with(Cell::get) == 1 || VOLUME_DOWN.with(Cell::get);
        if gated && matches!(key, crate::storage::store::Key::Volume(_)) {
            return Err(crate::storage::store::Unavailable);
        }
        if DOWN.with(Cell::get)
            || (SHARD_DOWN.with(Cell::get) && matches!(key, crate::storage::store::Key::Shard(_)))
        {
            return Err(crate::storage::store::Unavailable);
        }
        self.inner.read(key)
    }

    fn write(
        &mut self,
        key: &crate::storage::store::Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        use crate::failover::records::Record;
        if DOWN.with(Cell::get) {
            return crate::storage::store::Outcome::Unknown;
        }
        let names_standby = match write {
            crate::storage::store::Write::Exact { value, .. } => ShardRecord::decode(value)
                .is_ok_and(|record| record.owner == crate::failover::takeover::tests::c_host()),
            crate::storage::store::Write::Create(_) => false,
        };
        // The certify keeps the record's checkpoint; a Publish names a new one.
        let certify = VOLUME_GATE.with(Cell::get) == 1
            && matches!(key, crate::storage::store::Key::Shard(_))
            && !names_standby
            && match write {
                crate::storage::store::Write::Exact { value, .. } => {
                    let held = self.inner.0.borrow().current(key).cloned();
                    let checkpoint =
                        |bytes: &[u8]| ShardRecord::decode(bytes).ok().map(|r| r.checkpoint);
                    held.is_some_and(|held| checkpoint(&held.value) == checkpoint(value))
                }
                crate::storage::store::Write::Create(_) => false,
            };
        if certify {
            let outcome = self.inner.write(key, write);
            crate::failover::takeover::tests::rewrite(&self.inner, |record| record);
            VOLUME_GATE.with(|cell| cell.set(2));
            return outcome;
        }
        if names_standby && let Some(answer) = self.answer.take() {
            match answer {
                Answer::Denied => {
                    return crate::storage::store::Outcome::NotCommitted(
                        crate::storage::store::Refusal::Denied,
                    );
                }
                Answer::Skewed => {
                    return match self.inner.write(key, write) {
                        crate::storage::store::Outcome::Committed(version) => {
                            let skipped = version
                                .next()
                                .and_then(crate::storage::store::Version::next);
                            crate::storage::store::Outcome::Committed(skipped.unwrap())
                        }
                        outcome => outcome,
                    };
                }
                Answer::Commit => {}
                Answer::EndedFirst => {
                    let (key, end) = PARKED_END
                        .with(|cell| cell.borrow_mut().take())
                        .expect("the reclaim parked its end write");
                    let committed = self.inner.write(&key, &end);
                    END_OUTCOME.with(|cell| cell.set(Some(committed)));
                }
                Answer::Unknown { commit } => self
                    .inner
                    .schedule(crate::storage::store::sim::Arm::Timeout { commit }),
                Answer::Parked => self.inner.schedule(crate::storage::store::sim::Arm::Hold),
                Answer::Moved => crate::failover::takeover::tests::designate(
                    &self.inner,
                    Some(crate::failover::takeover::tests::c_host()),
                ),
                Answer::TakenOver => {
                    crate::failover::takeover::tests::rewrite(&self.inner, |record| {
                        crate::failover::takeover::tests::taken(&record, record.standby.unwrap())
                    })
                }
            }
        }
        self.inner.write(key, write)
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// What one requested tenure did and left.
struct Requested {
    exit: Exit,
    /// The record the store holds after the tenure.
    record: ShardRecord,
    volume: (
        crate::storage::store::sim::Shared,
        crate::storage::device::sim::Media,
    ),
    registry: crate::storage::gate_fixture::Control,
    /// The reservation commands the tenure issued from its planned withdrawal to the end of its teardown; `None`
    /// when the driver reached no withdrawal.
    commands_after: Option<usize>,
    /// The medium commands the tenure's device took, admitted or refused, from its planned withdrawal to the end of
    /// its teardown; `None` when the driver reached no withdrawal.
    medium_after: Option<usize>,
    /// The frames the owner sent from the turn of that withdrawal on; `None` when the driver reached none.
    sends_after: Option<u64>,
    /// Whether the owner stood closed at the end of the turn of that withdrawal; `None` when the driver reached none.
    closed_after: Option<bool>,
    /// The most client datagrams sent toward the owner from the turn of that withdrawal on, delivered or still in
    /// flight, on any one round.
    delivered_after: Option<usize>,
    /// The owner turns that ran while the inline lane held the transfer's completion, and whether each of them
    /// returned no exit with the owner's handoff outstanding.
    held: (u32, bool),
    /// The Views the duties submitted on turns while the inline lane held the transfer's completion.
    views_while_held: u64,
    /// Whether the owner entered a drain stage on any turn.
    drained: bool,
    /// Whether the owner's admission stood open, with no drain stage, on the tenure's last turn.
    admission_open: bool,
    /// The `(roll_due, roll_active)` of the owner's report entry on a turn while the transfer was outstanding.
    transfer_entry: Option<(Option<bool>, Option<bool>)>,
    /// The tracked exit's status on the tenure's last turn.
    status: Option<crate::failover::report::ExitStatus>,
    /// The kind of exit the machine ran, if one started.
    started: Option<crate::failover::planned::ExitKind>,
    resumed: Option<crate::failover::report::Resume>,
    /// The `(roll_due, roll_active)` of the owner's report entry on a turn while a roll ran.
    rolling_entry: Option<(Option<bool>, Option<bool>)>,
    /// The client's GETs that ended while the store was down: those that completed with the object's bytes, and
    /// those that ended any other way or that the client gave up on.
    gets_down: (u64, u64),
    /// The turn clock at the request's delivery and at the tenure's resume.
    received_at: Option<u64>,
    resumed_at: Option<u64>,
    /// Whether the client's session at the request's delivery was its active session on the tenure's last turn.
    session_kept: bool,
    /// The outcome of the FILL the harness published after the resume: `Some(true)` once it published.
    filled: Option<bool>,
}

/// The request a tenure receives once its open settles, sealed for the tenure the record then names.
type Request = fn(&ShardRecord) -> Vec<u8>;

/// Whether the request goes out on a turn, from whether a roll runs then.
type Deliver = fn(bool) -> bool;

type Volume = (
    crate::storage::store::sim::Shared,
    crate::storage::device::sim::Media,
);

fn warm() -> Volume {
    crate::host::serve::tests::warm_volume_certified(0)
}

fn at_open(_: bool) -> bool {
    true
}

fn transfer_request(record: &ShardRecord) -> Vec<u8> {
    let target = record
        .standby
        .unwrap_or(crate::failover::takeover::tests::c_host());
    sealed(record, Kind::Transfer { target }, 1)
}

fn restart_request(record: &ShardRecord) -> Vec<u8> {
    sealed(record, Kind::Restart, 1)
}

/// A tenure of the warm volume, with the standby holding no registration, whose duties take requests: once its open
/// settles it receives `request` and, from then on, keeps up to two GETs live, and the transfer write meets `answer`. With
/// `setup`, the duties are changed before the first turn.
fn requested(
    (volume, request, deliver): (Volume, Request, Deliver),
    answer: Answer,
    deadline: crate::failover::planned::Deadline,
    setup: impl FnOnce(&mut TestDuties<'_>),
) -> Requested {
    requested_with(
        (volume, request, deliver),
        answer,
        Built::BOTH,
        deadline,
        |duties| setup(duties.as_mut().unwrap()),
        |_| {},
    )
}

/// The duties the harness drives.
type TestDuties<'l> = super::Duties<
    'l,
    Answering,
    crate::storage::store::sim::MemLog,
    crate::storage::test_platform::TestPlatform,
>;

/// Which builders the harness's duties went through, beside [`super::Duties::requesting`].
#[derive(Debug, Clone, Copy)]
struct Built {
    capturing: bool,
    rolling: bool,
}

impl Built {
    const BOTH: Self = Self {
        capturing: true,
        rolling: true,
    };
}

/// [`requested`] over duties `built` lists, with `each` run over the duties before every owner turn.
fn requested_with(
    (volume, request, deliver): (Volume, Request, Deliver),
    answer: Answer,
    built: Built,
    deadline: crate::failover::planned::Deadline,
    setup: impl FnOnce(&mut Option<TestDuties<'_>>),
    mut each: impl FnMut(&mut Option<TestDuties<'_>>),
) -> Requested {
    use super::step_tests::{NEVER, STEP_US, step_duties_on};
    let registry = own_alone();
    crate::host::serve::loop_tests::staged_over_on(
        volume,
        registry.clone(),
        || crate::storage::warm_sim::storage(1),
        |mut stage| {
            let answering = Answering {
                inner: stage.store.clone(),
                answer: Rc::new(Cell::new(Some(answer))),
            };
            let policy = built
                .capturing
                .then(|| super::capture_tests::policy_every(NEVER));
            let duties = step_duties_on(&stage, answering, policy, STEP_US);
            let duties = match built.rolling {
                true => duties.rolling(super::roll_tests::deadline()),
                false => duties,
            };
            let mut slot = Some(duties.requesting(key(), deadline));
            setup(&mut slot);
            let storage = stage.storage;
            super::roll_tests::reset();
            let sent = Cell::new(false);
            let withdrawn_at = Rc::new(Cell::new(None::<usize>));
            let medium_at = Rc::new(Cell::new(None::<usize>));
            let (marked, medium_marked) = (withdrawn_at.clone(), medium_at.clone());
            let marking = registry.clone();
            BOUNDARY.with(|cell| {
                *cell.borrow_mut() = Some(Box::new(move || {
                    marked.set(Some(crate::host::fencer_tests::commands(&marking).len()));
                    medium_marked.set(Some(marking.borrow().medium));
                }));
            });
            let (sent_at, sends_after) = (Cell::new(None::<u64>), Cell::new(None::<u64>));
            let closed_after = Cell::new(None::<bool>);
            let status = Cell::new(None);
            let rolling_entry = Cell::new(None);
            let resumed_for = Cell::new(0);
            let (carried_at, delivered_after) = (Cell::new(None::<u64>), Cell::new(None::<usize>));
            let live = std::cell::RefCell::new(Vec::new());
            let held = Cell::new((0_u32, true));
            let views_while_held = Cell::new(0_u64);
            let (drained, transfer_entry) = (Cell::new(false), Cell::new(None));
            let admission_open = Cell::new(false);
            let frozen = Cell::new(None::<u64>);
            let gets_down = Cell::new((0_u64, 0_u64));
            let (received_at, resumed_at) = (Cell::new(None::<u64>), Cell::new(None::<u64>));
            let sessions = Cell::new((None::<u64>, None::<u64>));
            let filled = Cell::new(None::<bool>);
            let mut filling: super::tests::Filling<'_> = None;
            let (served, _) = stage.serve_until(
                |rounds, turn, stop| {
                    if super::roll_tests::resumed_reason().is_some() {
                        resumed_for.set(resumed_for.get() + 1);
                        let fills = FILL_AFTER_RESUME.with(Cell::get) && filled.get().is_none();
                        if resumed_for.get() > 8 && !fills {
                            stop.store(true, std::sync::atomic::Ordering::Release);
                        }
                    }
                    if STOP_AT.with(Cell::get).is_some_and(|at| turn >= at) {
                        stop.store(true, std::sync::atomic::Ordering::Release);
                    }
                    if withdrawn_at.get().is_some() && carried_at.get().is_none() {
                        carried_at.set(Some(rounds.carried()));
                    }
                    if let Some(from) = carried_at.get() {
                        // A closed owner receives nothing, so a datagram toward it stays in flight.
                        let toward = crate::host::serve::loop_tests::OWNER_END;
                        let offered =
                            rounds.delivered_since(toward, from) + rounds.in_flight(toward);
                        let most = delivered_after.get().unwrap_or(0).max(offered);
                        delivered_after.set(Some(most));
                    }
                    // Up to two GETs stay live; one the owner leaves unanswered for 20 rounds ends and retires, so
                    // the client keeps asking the withdrawn owner.
                    let down = DOWN.with(Cell::get) || VOLUME_DOWN.with(Cell::get);
                    live.borrow_mut().retain(|&(id, at)| {
                        if let Some(outcome) = rounds.fetched(id, &mut Vec::new()) {
                            let hit = outcome == crate::net::Outcome::Complete;
                            let (hits, unserved) = gets_down.get();
                            match (down, hit) {
                                (true, true) => gets_down.set((hits + 1, unserved)),
                                (true, false) => gets_down.set((hits, unserved + 1)),
                                (false, _) => {}
                            }
                            return false;
                        }
                        if turn >= at + 20 {
                            let mut client = rounds.client.borrow_mut();
                            client.cancel(id);
                            if down {
                                let (hits, unserved) = gets_down.get();
                                gets_down.set((hits, unserved + 1));
                            }
                            return !client.retire(id);
                        }
                        true
                    });
                    let active = rounds.client.borrow().state() == crate::net::SessionState::Active;
                    if active && live.borrow().len() < 2 {
                        let n = (turn % 4) as u8 + 1;
                        if let Ok(id) = rounds.try_get(n) {
                            live.borrow_mut().push((id, turn));
                        }
                    }
                },
                |owner, now| {
                    crate::storage::owner_fixture::set_clock(
                        storage,
                        &[Some(super::capture::nanos(now))],
                    );
                    each(&mut slot);
                    let duties = slot.as_mut().expect("the harness keeps its duties");
                    let freeze = FREEZE_AT.with(Cell::get);
                    if freeze.is_some()
                        && duties.planned_state() == freeze
                        && frozen.get().is_none()
                    {
                        frozen.set(Some(now));
                    }
                    let now = frozen.get().unwrap_or(now);
                    drained.set(drained.get() || owner.draining().is_some());
                    if VOLUME_GATE.with(Cell::get) == 0
                        && duties.planned_state().is_some()
                        && GATED.with(Cell::get)
                    {
                        VOLUME_GATE.with(|cell| cell.set(1));
                    }
                    if duties.open() == super::Open::Opened
                        && !sent.get()
                        && deliver(duties.roll_active())
                        && let Some(read) = duties.read.as_ref()
                    {
                        duties.deliver(&request(read.value()));
                        sent.set(true);
                        received_at.set(Some(now));
                        sessions.set((owner.session_epoch(crate::net::PeerId(0)), None));
                    }
                    let resumed = super::roll_tests::resumed_reason().is_some();
                    if let Some((state, outage)) = OUTAGE.with(Cell::get)
                        && !DOWN.with(Cell::get)
                        && !VOLUME_DOWN.with(Cell::get)
                        && !resumed
                        && duties.planned_state() == Some(state)
                    {
                        match outage {
                            // A view is due at once, so a view shows the unreadable volume record before the
                            // certify's acknowledgment arrives.
                            Outage::VolumeUnread => {
                                VOLUME_DOWN.with(|cell| cell.set(true));
                                duties.view_at = 0;
                            }
                            Outage::Fails | Outage::Silent => DOWN.with(|cell| cell.set(true)),
                        }
                        if outage == Outage::Silent {
                            duties.lane.inline_mut().hold();
                        }
                    }
                    let views = duties.views;
                    let busy_turn = BUSY_SEAL.with(|busy| {
                        (busy.borrow().as_ref())
                            .is_some_and(|busy| busy.holds(duties.roll_sealed()))
                    });
                    let exit = match busy_turn {
                        true => storage
                            .with_suffix(|_| duties.turn(owner, now))
                            .expect("the capture mutex"),
                        false => duties.turn(owner, now),
                    };
                    let asked = duties.roll_seal_asked();
                    BUSY_SEAL.with(|busy| {
                        if let Some(busy) = busy.borrow_mut().as_mut() {
                            busy.after(busy_turn, asked);
                        }
                    });
                    sessions.set((sessions.get().0, owner.session_epoch(crate::net::PeerId(0))));
                    if super::roll_tests::resumed_reason().is_some() && resumed_at.get().is_none() {
                        resumed_at.set(Some(now));
                        // The outage ends with the resume: the store answers again, and each held completion lands.
                        VOLUME_DOWN.with(|cell| cell.set(false));
                        if DOWN.with(|cell| cell.replace(false)) {
                            duties.lane.inline_mut().release_all();
                        }
                    }
                    if resumed && FILL_AFTER_RESUME.with(Cell::get) && filled.get().is_none() {
                        let payload = [
                            &crate::storage::warm_sim::object_key(FRESH)[..4],
                            &[0x5a; 40][..],
                        ]
                        .concat();
                        let fill = (FRESH, &payload[..]);
                        if let Some(published) =
                            super::step_tests::fill(owner, storage, &mut filling, fill)
                        {
                            filled.set(Some(published.is_ok()));
                        }
                    }
                    if duties.lane.inline_mut().held() > 0 && !DOWN.with(Cell::get) {
                        views_while_held.set(views_while_held.get() + duties.views - views);
                        let (turns, outstanding) = held.get();
                        let outstanding = outstanding
                            && exit.is_none()
                            && matches!(
                                owner.transfer(),
                                Some(crate::net::Handoff::Outstanding { .. })
                            );
                        held.set((turns + 1, outstanding));
                        if turns + 1 >= HOLD_TRANSFER.with(Cell::get) {
                            duties.lane.inline_mut().release_all();
                        }
                    }
                    if withdrawn_at.get().is_some() && sent_at.get().is_none() {
                        sent_at.set(Some(owner.report().sent));
                        closed_after.set(Some(owner.blockers().is_none_or(|held| !held.open)));
                    }
                    if let Some(at) = sent_at.get() {
                        sends_after.set(Some(owner.report().sent - at));
                    }
                    let crash = CRASH_AT.with(Cell::get);
                    if crash.is_some() && duties.planned_state() == crash {
                        return Some(Exit::Rerun(crate::host::Rerun::Unwound));
                    }
                    admission_open.set(owner.draining().is_none());
                    let entry = owner.report_entry(now, &duties.observed());
                    status.set(entry.and_then(|entry| entry.exit).map(|exit| exit.status));
                    if duties.roll_active() && rolling_entry.get().is_none() {
                        rolling_entry.set(entry.map(|entry| (entry.roll_due, entry.roll_active)));
                    }
                    if owner.transfer().is_some() && transfer_entry.get().is_none() {
                        transfer_entry.set(entry.map(|entry| (entry.roll_due, entry.roll_active)));
                    }
                    exit
                },
            );
            BOUNDARY.with(|cell| cell.borrow_mut().take());
            let commands = crate::host::fencer_tests::commands(&stage.registry).len();
            Requested {
                exit: served.exit,
                record: record_of(&stage.store),
                volume: (stage.store.clone(), stage.media.clone()),
                registry: stage.registry.clone(),
                commands_after: withdrawn_at.get().map(|at| commands - at),
                medium_after: (medium_at.get()).map(|at| stage.registry.borrow().medium - at),
                sends_after: sends_after.get(),
                closed_after: closed_after.get(),
                delivered_after: delivered_after.get(),
                held: held.get(),
                views_while_held: views_while_held.get(),
                drained: drained.get(),
                admission_open: admission_open.get(),
                transfer_entry: transfer_entry.get(),
                status: status.get(),
                started: super::roll_tests::started_kind(),
                resumed: super::roll_tests::resumed_reason(),
                rolling_entry: rolling_entry.get(),
                gets_down: gets_down.get(),
                received_at: received_at.get(),
                resumed_at: resumed_at.get(),
                session_kept: {
                    let (first, last) = sessions.get();
                    first.is_some() && first == last
                },
                filled: filled.get(),
            }
        },
    )
}

/// The object the harness fills after a resume, which no warm object and no cycle key names.
const FRESH: u8 = 77;

/// Runs the standby's tenure over what `requested` left, its restart and its serve of every warm object; `Err` names
/// the first object or step that failed.
fn standby_serves(left: &Requested) -> Result<(), String> {
    use super::step_tests::{Choices, Reached, run_cycle_as, warm_objects};
    let mut held = warm_objects();
    let (mut choices, mut reached) = (Choices::of(1), Reached::default());
    crate::host::serve::tests::inline(|| {
        run_cycle_as(
            (
                crate::host::recover_tests::Identity::standby(),
                left.registry.clone(),
            ),
            left.volume.clone(),
            (&mut held, &mut choices, &mut reached),
            None,
        )
        .map(drop)
    })
}

/// NoEmissionAfterTransfer and TransferNamesStandby: an accepted transfer request withdraws the serving tenure,
/// which issues no reservation command and sends the client no datagram from its withdrawal on, while the client
/// keeps sending GETs. The transfer commits the record naming the standby C owner at `E + 1` with no standby, the
/// incarnation ends `Stopped` with the tracked exit `exited`, and C's restart then serves every warm object.
#[test]
fn an_accepted_transfer_stops_emitting_at_the_withdrawal_and_its_standby_serves_the_cut() {
    let before = record_of(&warm().0);
    let left = holding(HELD_TURNS, || {
        requested(
            (warm(), transfer_request, at_open),
            Answer::Commit,
            super::roll_tests::deadline(),
            |_| {},
        )
    });
    let c = crate::failover::takeover::tests::c_host();
    assert_eq!(left.exit, Exit::Stopped);
    assert_eq!(
        left.started,
        Some(crate::failover::planned::ExitKind::Transfer { target: c })
    );
    assert_eq!(
        (left.record.owner, left.record.standby, left.record.attempts),
        (c, None, before.attempts + 2)
    );
    assert_eq!(
        (left.commands_after, left.medium_after, left.sends_after),
        (Some(0), Some(0), Some(0)),
        "no reservation command, medium command or frame after the withdrawal"
    );
    assert_eq!(
        left.closed_after,
        Some(true),
        "the owner closed in the turn of its withdrawal"
    );
    assert!(
        left.delivered_after.is_some_and(|delivered| delivered > 0),
        "the client sent the withdrawn owner a GET"
    );
    assert_eq!(
        left.held,
        (HELD_TURNS, true),
        "each turn with the transfer's completion held polled on with the handoff outstanding"
    );
    assert_eq!(
        left.views_while_held, 0,
        "no View is submitted ahead of the waiting transfer"
    );
    assert_eq!(
        left.status,
        Some(crate::failover::report::ExitStatus::Exited)
    );
    standby_serves(&left).unwrap_or_else(|failure| panic!("{failure}"));
}

/// The owner turns the no-emission tests hold the transfer's completion for.
const HELD_TURNS: u32 = 12;

/// A transfer whose reply is lost: the withdrawn owner stays withdrawn, submits a view and reads the record from a
/// view sent after the outcome. When the write committed the record names C at `E + 1` and the owner ends `Deposed`
/// with its exit `exited`, and C's restart serves the cut; when it did not, the record still names this tenure and the
/// owner ends in one same-host restart, `restarting` for an unknown transfer, and nothing else moved.
#[test]
fn an_unknown_transfer_ends_in_the_exit_or_one_restart_by_the_record_it_reads() {
    use crate::failover::report::{ExitStatus, Restart};
    let before = record_of(&warm().0);
    let c = crate::failover::takeover::tests::c_host();
    for commit in [true, false] {
        let left = requested(
            (warm(), transfer_request, at_open),
            Answer::Unknown { commit },
            super::roll_tests::deadline(),
            |_| {},
        );
        assert_eq!(
            (left.commands_after, left.medium_after, left.sends_after),
            (Some(0), Some(0), Some(0)),
            "{commit}"
        );
        if commit {
            assert_eq!(left.exit, Exit::Deposed);
            assert_eq!(
                (left.record.owner, left.record.attempts),
                (c, before.attempts + 2)
            );
            assert_eq!(left.status, Some(ExitStatus::Exited));
            standby_serves(&left).unwrap_or_else(|failure| panic!("{failure}"));
        } else {
            assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Planned));
            assert_eq!(
                (left.record.owner, left.record.standby, left.record.attempts),
                (before.owner, before.standby, before.attempts + 1)
            );
            assert_eq!(
                left.status,
                Some(ExitStatus::Restarting(Restart::TransferUnknown))
            );
        }
    }
}

/// A transfer that fails its version condition, because another writer moved the record's version at the same
/// tenure, ends in one same-host restart with the exit `restarting` for a refused transfer; the record keeps this
/// tenure and its standby.
#[test]
fn a_refused_transfer_ends_in_one_same_host_restart() {
    use crate::failover::report::{ExitStatus, Restart};
    let before = record_of(&warm().0);
    let left = requested(
        (warm(), transfer_request, at_open),
        Answer::Moved,
        super::roll_tests::deadline(),
        |_| {},
    );
    assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Planned));
    assert_eq!(
        (left.record.owner, left.record.standby, left.record.attempts),
        (before.owner, before.standby, before.attempts + 1)
    );
    assert_eq!(
        left.status,
        Some(ExitStatus::Restarting(Restart::TransferRefused))
    );
    assert_eq!(
        (left.commands_after, left.medium_after, left.sends_after),
        (Some(0), Some(0), Some(0))
    );
}

/// A transfer whose lane refuses the transfer's submit at the withdrawal, as a lane with `DEPTH` jobs outstanding
/// does: the withdrawn tenure issues no write, keeps its standby gate and ends in its one same-host restart with
/// the exit `restarting` for a refused transfer; the record keeps this owner and its standby.
#[test]
fn a_transfer_whose_lane_refuses_its_submit_issues_no_write_and_restarts_once() {
    use crate::failover::report::{ExitStatus, Restart};
    let before = record_of(&warm().0);
    REFUSE_TRANSFER.with(|cell| cell.set(true));
    let left = requested(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        super::roll_tests::deadline(),
        |_| {},
    );
    REFUSE_TRANSFER.with(|cell| cell.set(false));
    assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Planned));
    assert_eq!(
        (left.record.owner, left.record.standby, left.record.attempts),
        (before.owner, before.standby, before.attempts + 1)
    );
    assert_eq!(
        left.status,
        Some(ExitStatus::Restarting(Restart::TransferRefused))
    );
}

/// A transfer at whose withdrawal another cause has already withdrawn the authority, here a recorded force detach:
/// the planned withdrawal finds the authority withdrawn for that cause, the driver issues no transfer and ends the
/// tenure as the earlier cause decides, with the flip it requests; the record keeps this owner.
#[test]
fn an_earlier_withdrawal_at_the_transfer_s_withdrawal_issues_no_transfer() {
    let before = record_of(&warm().0);
    let cause = crate::failover::serving::Cause::ForceDetach;
    WITHDRAWN_FIRST.with(|cell| cell.set(Some(cause)));
    let left = requested(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        super::roll_tests::deadline(),
        |_| {},
    );
    WITHDRAWN_FIRST.with(|cell| cell.set(None));
    let tenure = crate::failover::retire::Target {
        attempts: before.attempts + 1,
        ..crate::failover::retire::Target::of(&before)
    };
    assert_eq!(left.exit, Exit::Retire(tenure), "the force detach's flip");
    assert_eq!(
        (left.record.owner, left.record.standby, left.record.attempts),
        (before.owner, before.standby, before.attempts + 1),
        "no transfer was written"
    );
}

/// A requested restart at whose withdrawal a force detach already withdrew the authority: the exit
/// is the force detach's flip, and the tracked request reads no `restarting` status, so the status the tracker
/// observed for the earlier cause stands.
#[test]
fn an_earlier_withdrawal_at_a_requested_restart_records_no_restarting_status() {
    use crate::failover::report::ExitStatus;
    let before = record_of(&warm().0);
    let cause = crate::failover::serving::Cause::ForceDetach;
    WITHDRAWN_FIRST.with(|cell| cell.set(Some(cause)));
    let left = requested(
        (warm(), restart_request, at_open),
        Answer::Commit,
        super::roll_tests::deadline(),
        |_| {},
    );
    WITHDRAWN_FIRST.with(|cell| cell.set(None));
    let tenure = crate::failover::retire::Target {
        attempts: before.attempts + 1,
        ..crate::failover::retire::Target::of(&before)
    };
    assert_eq!(left.exit, Exit::Retire(tenure), "the force detach's flip");
    assert!(
        !matches!(left.status, Some(ExitStatus::Restarting(_))),
        "{:?}",
        left.status
    );
}

/// A deploy restart: an accepted request of kind `Restart` drains, publishes, certifies and withdraws for
/// `Cause::Planned`, issues no transfer and ends `Rerun(Planned)` with the exit `restarting` for a planned restart.
/// The record keeps its owner, standby and generation, and the next incarnation's restart runs at `E + 1` and serves
/// every warm object.
#[test]
fn an_accepted_restart_request_restarts_once_with_owner_and_standby_unchanged() {
    use super::step_tests::{Choices, Reached, cycle, warm_objects};
    use crate::failover::report::{ExitStatus, Restart};
    let before = record_of(&warm().0);
    let left = requested(
        (warm(), restart_request, at_open),
        Answer::Commit,
        super::roll_tests::deadline(),
        |_| {},
    );
    assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Planned));
    assert_eq!(
        left.started,
        Some(crate::failover::planned::ExitKind::Restart)
    );
    assert_eq!(left.status, Some(ExitStatus::Restarting(Restart::Planned)));
    let kept = |record: &ShardRecord| (record.generation, record.owner, record.standby);
    assert_eq!(kept(&left.record), kept(&before));
    assert_eq!(left.record.attempts, before.attempts + 1);
    let mut held = warm_objects();
    let (mut choices, mut reached) = (Choices::of(3), Reached::default());
    let (volume, _, _) = crate::host::serve::tests::inline(|| {
        cycle(left.volume.clone(), &mut held, &mut choices, &mut reached)
    })
    .unwrap_or_else(|failure| panic!("{failure}"));
    assert_eq!(kept(&record_of(&volume.0)), kept(&before));
    assert_eq!(record_of(&volume.0).attempts, before.attempts + 2);
}

/// The intake uses the activated session's owner as the addressee when decoding requests.
#[test]
fn a_request_sealed_for_the_session_owner_is_accepted_whatever_host_the_records_name() {
    let before = record_of(&warm().0);
    let other = crate::failover::takeover::tests::c_host();
    assert_ne!(before.owner, other);
    let cases = [
        (transfer_request as Request, Exit::Stopped),
        (restart_request, Exit::Rerun(crate::host::Rerun::Planned)),
    ];
    for (request, ending) in cases {
        bindings();
        let left = requested(
            (warm(), request, at_open),
            Answer::Commit,
            super::roll_tests::deadline(),
            |duties| duties.records.holder.host = other,
        );
        assert_eq!(bindings().first(), Some(&Binding::Accept), "{ending:?}");
        assert_eq!(left.exit, ending);
    }
}

/// Requests that resume before the withdrawal change nothing: a restart request for a record that names no standby
/// starts its machine on its first view and resumes `standby`, and a transfer request whose 1 µs deadline passes
/// before its first view resumes `deadline` with no machine started. Each leaves admission open, keeps `E`, and its
/// exit reads `resumed`.
#[test]
fn a_request_that_fails_before_the_withdrawal_resumes_in_place_with_e_unchanged() {
    use crate::failover::report::{ExitStatus, Resume};
    let unnamed = warm();
    crate::failover::takeover::tests::designate(&unnamed.0, None);
    let before = record_of(&unnamed.0);
    let rows: [(Volume, Request, crate::failover::planned::Deadline, Resume); 2] = [
        (
            unnamed,
            restart_request,
            super::roll_tests::deadline(),
            Resume::Standby,
        ),
        (
            warm(),
            transfer_request,
            crate::failover::planned::Deadline::new(1).unwrap(),
            Resume::Deadline,
        ),
    ];
    for (volume, request, deadline, reason) in rows {
        let left = requested((volume, request, at_open), Answer::Commit, deadline, |_| {});
        assert_eq!(
            left.exit,
            Exit::Stopped,
            "{reason:?}: the tenure kept serving to the stop"
        );
        assert_eq!(left.resumed, Some(reason));
        assert_eq!(left.status, Some(ExitStatus::Resumed(reason)));
        assert!(left.admission_open, "{reason:?}: admission reopened");
        assert_eq!(
            left.started.is_some(),
            reason == Resume::Standby,
            "{reason:?}: only a request past its first view starts a machine"
        );
        assert_eq!(
            left.record.attempts,
            before.attempts + 1,
            "{reason:?}: no E consumed"
        );
        assert_eq!(left.record.owner, before.owner);
    }
}

/// REQUEST-START: an accepted request keeps the cap in force at its acceptance. A later
/// [`super::Duties::requesting`] call between acceptance and submission of the next view sets the cap for later
/// requests: a transfer and a restart accepted under the long cap drain after the cap drops to 1 microsecond, and
/// the same requests accepted under the 1 microsecond cap resume directly with `Resume::Deadline` after the cap rises.
#[test]
fn a_later_requesting_call_leaves_the_cap_of_an_accepted_request() {
    use crate::failover::planned::Deadline;
    use crate::failover::report::{ExitStatus, Resume};
    let (long, short) = (super::roll_tests::deadline(), Deadline::new(1).unwrap());
    let requests: [(Request, &str); 2] =
        [(transfer_request, "transfer"), (restart_request, "restart")];
    for (request, kind) in requests {
        for (accepted, later) in [(long, short), (short, long)] {
            let mut swapped = false;
            let left = requested_with(
                (warm(), request, at_open),
                Answer::Commit,
                Built::BOTH,
                accepted,
                |_| {},
                |slot| {
                    if !swapped && last_bound() == Some(Binding::Accept) {
                        assert_eq!(
                            super::roll_tests::starts(),
                            0,
                            "{kind}: swapped before the start"
                        );
                        let duties = slot.take().unwrap().requesting(key(), later);
                        *slot = Some(duties);
                        swapped = true;
                    }
                },
            );
            assert!(swapped, "{kind}: the request was accepted");
            let label = format!("{kind} accepted under {accepted:?}, later cap {later:?}");
            if accepted == long {
                assert!(left.started.is_some(), "{label}: the machine started");
                assert!(left.drained, "{label}: the exit drained");
                assert_ne!(left.resumed, Some(Resume::Deadline), "{label}");
            } else {
                assert_eq!(left.started, None, "{label}: no machine started");
                assert!(!left.drained, "{label}: no drain stage");
                assert_eq!(
                    left.status,
                    Some(ExitStatus::Resumed(Resume::Deadline)),
                    "{label}"
                );
            }
        }
    }
}

/// ONE-LEDGER: a request that meets a running roll is refused `Busy` and starts nothing; the roll ends the tenure in
/// its restart. The same request delivered to duties with no roll running is accepted and transfers the shard, so
/// the refusal comes from the running roll.
#[test]
fn a_request_during_a_roll_is_refused_busy_and_starts_nothing() {
    let left = requested(
        (warm(), transfer_request, |rolling| rolling),
        Answer::Commit,
        super::roll_tests::deadline(),
        |duties| duties.roll_due = true,
    );
    assert_eq!(last_bound(), Some(Binding::Busy));
    assert!(matches!(
        left.started,
        Some(crate::failover::planned::ExitKind::Roll { .. })
    ));
    assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Planned));
    assert_eq!(left.record.owner, record_of(&warm().0).owner);

    let left = requested(
        (warm(), transfer_request, |_| true),
        Answer::Commit,
        super::roll_tests::deadline(),
        |_| {},
    );
    assert_eq!(last_bound(), Some(Binding::Accept));
    assert_eq!(left.exit, Exit::Stopped);
}

/// Control: a transfer submitted with the authority still serving keeps its device running after the transfer write:
/// its serving Reports reach the reservation, so the no-emission check `commands_after == 0` fails.
#[test]
fn control_an_owner_that_emits_after_its_transfer_fails_the_no_emission_check() {
    let left = with_plant(Plant::EmitAfterTransfer, || {
        holding(HELD_TURNS, || {
            requested(
                (warm(), transfer_request, at_open),
                Answer::Commit,
                super::roll_tests::deadline(),
                |_| {},
            )
        })
    });
    assert!(
        left.commands_after.is_some_and(|commands| commands > 0),
        "the planted owner issued a reservation command after its transfer write"
    );
    assert!(
        left.sends_after.is_some_and(|sends| sends > 0),
        "the planted owner answered a client after its transfer write"
    );
    assert!(
        left.medium_after.is_some_and(|medium| medium > 0),
        "the planted owner read the medium for a client after its transfer write"
    );
}

/// Control: a drain that reopens admission after its certify and transfers 40 turns later acknowledges mutations after
/// the seal, past the end the certify named: seed 1's cycle fails its cut check, which compares the durable end at
/// the withdrawal with the end the certified record names, `over a record certifying`.
#[test]
fn control_a_mutation_acknowledged_after_the_seal_fails_the_cut_check() {
    let failure = with_plant(Plant::MutationsAfterSeal, || handed_over(1))
        .expect_err("a mutation after the seal moved the durable end past the certified one");
    assert!(failure.contains("over a record certifying"), "{failure}");
    handed_over(1).unwrap_or_else(|failure| panic!("the unplanted seed passes: {failure}"));
}

/// The standby's restart over the reservation a committed transfer left, with the predecessor's registration kept
/// or, in the control, removed at its exit as a release would remove it. Kept, the restart returns a tenure; removed,
/// nobody holds at Report #1, the restart refuses `Unheld`, issues no command after that Report, and the incarnation
/// parks.
#[test]
fn control_a_predecessor_that_releases_its_registration_stops_the_standby_at_report_one() {
    use crate::failover::restart::Check;
    use crate::host::recover::Recovery;
    use crate::host::{Refusal, recover_tests::Identity};
    let restart = |released: bool| {
        let left = requested(
            (warm(), transfer_request, at_open),
            Answer::Commit,
            super::roll_tests::deadline(),
            |_| {},
        );
        assert_eq!(left.exit, Exit::Stopped);
        if released {
            left.registry.borrow_mut().entries.clear();
        }
        let before = crate::host::fencer_tests::commands(&left.registry).len();
        let standby = Identity::standby();
        let (disk, _control) =
            crate::host::serve::tests::host_over(&left.registry, &left.volume.1, standby.pair);
        let arena = crate::storage::gate_fixture::arena_with(16, 9);
        let clock = crate::storage::gate_fixture::Ticking::default();
        let recovery = crate::host::recover_tests::restarted_as(
            standby,
            &left.volume.0,
            (disk, &arena, &clock),
            Box::new(crate::storage::gate_fixture::ZeroClock),
        );
        let exit = match recovery {
            Recovery::Tenure(_) => None,
            Recovery::Ended(ended) => Some(ended.exit),
            Recovery::Waits => panic!("the record names the standby owner"),
        };
        let issued = crate::host::fencer_tests::commands(&left.registry)[before..].to_vec();
        (exit, issued)
    };
    let (kept, _) = restart(false);
    assert_eq!(
        kept, None,
        "the kept registration lets the standby activate"
    );
    let (released, issued) = restart(true);
    assert_eq!(
        released,
        Some(Exit::Refused(Refusal::Restart(Check::Unheld)))
    );
    assert_eq!(issued, ["report"], "no command after Report #1");
}

/// While a roll runs, the owner's report entry, which the published status carries, reads `roll_due` and
/// `roll_active`; the next incarnation's entry reads both clear once its first suffix step sampled the signals.
#[test]
fn a_running_roll_reads_roll_due_and_roll_active_and_the_restarted_tenure_clears_both() {
    use super::step_tests::{NEVER, step_duties};
    let left = requested(
        (warm(), transfer_request, |_| false),
        Answer::Commit,
        super::roll_tests::deadline(),
        |duties| {
            duties.roll_due = true;
        },
    );
    assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Planned));
    assert_eq!(left.rolling_entry, Some((Some(true), Some(true))));
    let cleared = crate::host::serve::loop_tests::staged_over_on(
        left.volume,
        left.registry,
        || crate::storage::warm_sim::storage(1),
        |mut stage| {
            let mut duties = step_duties(&stage, Some(super::capture_tests::policy_every(NEVER)))
                .rolling(super::roll_tests::deadline());
            let read = Cell::new(None);
            stage.serve_until(
                |_, _, stop| {
                    if read.get().is_some() {
                        stop.store(true, std::sync::atomic::Ordering::Release);
                    }
                },
                |owner, now| {
                    let exit = duties.turn(owner, now);
                    if duties.due.is_some() && read.get().is_none() {
                        let entry = owner.report_entry(now, &duties.observed());
                        read.set(entry.map(|entry| (entry.roll_due, entry.roll_active)));
                    }
                    exit
                },
            );
            read.get()
        },
    );
    assert_eq!(cleared, Some((Some(false), Some(false))));
}

/// Seeds `seeds`, each `cycles` tenures of the warm volume's shard between its two recorded hosts, A and C, then one
/// plain tenure. Each tenure draws a planned request: a transfer to the record's standby, after which the standby's
/// restart activates through its lineage arm, or a same-host restart. Before each tenure the reconciler's
/// designation names the other host standby when the record names none. Every tenure first serves exactly the
/// objects the earlier tenures acknowledged and answers missing for every other key; a transfer leaves the record
/// naming the target owner at `E + 1` with no standby, and a restart keeps the owner and the standby. Returns one
/// line per seed and a summary line, or the first mismatch with its seed and cycle.
pub(crate) fn handoff_cycles(
    seeds: std::ops::RangeInclusive<u64>,
    cycles: usize,
) -> Result<Vec<String>, String> {
    use super::roll_tests::Trigger;
    use super::step_tests::{Choices, Reached, run_cycle_as, warm_objects};
    use crate::failover::planned::ExitKind;
    use crate::host::recover_tests::Identity;
    let (a, c) = (Identity::owner(), Identity::standby());
    let mut lines = Vec::new();
    let mut totals = [0_u64; 2];
    let (mut fills, mut removals, mut checks) = (0, 0, 0);
    for seed in seeds.clone() {
        let mut choices = Choices::of(seed);
        let mut held = warm_objects();
        let mut reached = Reached::default();
        let mut volume = warm();
        let registry = own_alone();
        let mut drawn = [0_u64; 2];
        for at in 0..=cycles {
            let failed = |failure: String| format!("seed {seed} cycle {at}: {failure}");
            let named = record_of(&volume.0);
            let (owner, other) = if named.owner == c.host {
                (c, a)
            } else {
                (a, c)
            };
            if named.standby.is_none() {
                crate::failover::takeover::tests::designate(&volume.0, Some(other.host));
            }
            let before = record_of(&volume.0);
            let trigger = (at < cycles).then(|| {
                let draw = choices.next(2) as usize;
                drawn[draw] += 1;
                [Trigger::Transfer, Trigger::Requested][draw]
            });
            super::roll_tests::reset();
            let (next, _, _) = run_cycle_as(
                (owner, registry.clone()),
                volume,
                (&mut held, &mut choices, &mut reached),
                trigger,
            )
            .map_err(failed)?;
            let started = super::roll_tests::started_kind();
            let after = record_of(&next.0);
            let kept = |record: &ShardRecord| (record.generation, record.active);
            let expected = match trigger {
                Some(Trigger::Transfer) => (other.host, None, before.attempts + 2),
                _ => (owner.host, before.standby, before.attempts + 1),
            };
            let wanted = match trigger {
                Some(Trigger::Transfer) => Some(ExitKind::Transfer { target: other.host }),
                Some(_) => Some(ExitKind::Restart),
                None => None,
            };
            if started != wanted
                || kept(&after) != kept(&before)
                || (after.owner, after.standby, after.attempts) != expected
            {
                return Err(failed(format!(
                    "{trigger:?} started {started:?} and moved the record from {before:?} to {after:?}"
                )));
            }
            volume = next;
        }
        lines.push(format!(
            "handoff: seed {seed} cycles {cycles}: every tenure after a planned exit held every acknowledged \
             mutation; transfers {}; restarts {}; fills {}; removals {}; checks {}; identity {:016x}",
            drawn[0], drawn[1], reached.fills, reached.removals, reached.checks, reached.identity
        ));
        for (total, count) in totals.iter_mut().zip(drawn) {
            *total += count;
        }
        fills += reached.fills;
        removals += reached.removals;
        checks += reached.checks;
    }
    lines.push(format!(
        "handoff: {} seeds of {cycles} planned exits; transfers {}; restarts {}; fills {fills}; removals {removals}; \
         checks {checks}",
        seeds.count(),
        totals[0],
        totals[1],
    ));
    Ok(lines)
}

#[test]
fn two_seeded_handoff_cycles_hold_every_acknowledged_mutation_across_both_hosts() {
    let lines = crate::host::serve::tests::inline(|| handoff_cycles(1..=2, 3))
        .unwrap_or_else(|failure| panic!("{failure}"));
    assert_eq!(lines, PINNED, "{lines:#?}");
}

const PINNED: [&str; 3] = [
    "handoff: seed 1 cycles 3: every tenure after a planned exit held every acknowledged mutation; transfers 2; \
     restarts 1; fills 16; removals 17; checks 48; identity c1740d5c32be795e",
    "handoff: seed 2 cycles 3: every tenure after a planned exit held every acknowledged mutation; transfers 2; \
     restarts 1; fills 16; removals 15; checks 48; identity ae9e101ecf37e181",
    "handoff: 2 seeds of 3 planned exits; transfers 4; restarts 2; fills 32; removals 32; checks 96",
];

/// A crash of the owner at each step boundary of its transfer. After fills stop and after the Publish, the record
/// still names the owner at its tenure with its standby named, and the owner's own restart serves every warm object
/// at `E + 1`. After the withdrawal, with the transfer written and its reply not yet adopted, the record names the
/// standby, whose restart serves every warm object.
#[test]
fn a_crash_at_each_step_of_the_transfer_leaves_one_restart_serving_the_cut() {
    use super::step_tests::{Choices, Reached, cycle, warm_objects};
    use crate::failover::planned::State;
    let before = record_of(&warm().0);
    CRASH_AT.with(|cell| cell.set(Some(State::Withdrawn)));
    let left = requested(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        super::roll_tests::deadline(),
        |_| {},
    );
    CRASH_AT.with(|cell| cell.set(None));
    assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Unwound));
    let c = crate::failover::takeover::tests::c_host();
    assert_eq!(
        (left.record.owner, left.record.attempts),
        (c, before.attempts + 2)
    );
    assert_eq!(
        (left.commands_after, left.medium_after, left.sends_after),
        (Some(0), Some(0), Some(0))
    );
    standby_serves(&left).unwrap_or_else(|failure| panic!("{failure}"));
    for state in [State::FillsStopped, State::Sealed] {
        CRASH_AT.with(|cell| cell.set(Some(state)));
        let left = requested(
            (warm(), transfer_request, at_open),
            Answer::Commit,
            super::roll_tests::deadline(),
            |_| {},
        );
        CRASH_AT.with(|cell| cell.set(None));
        assert_eq!(
            left.exit,
            Exit::Rerun(crate::host::Rerun::Unwound),
            "{state:?}"
        );
        assert_eq!(
            (left.record.owner, left.record.standby, left.record.attempts),
            (before.owner, before.standby, before.attempts + 1),
            "{state:?}: no transfer committed"
        );
        let mut held = warm_objects();
        let (mut choices, mut reached) = (Choices::of(5), Reached::default());
        let (volume, _, _) = crate::host::serve::tests::inline(|| {
            cycle(left.volume.clone(), &mut held, &mut choices, &mut reached)
        })
        .unwrap_or_else(|failure| panic!("{state:?}: {failure}"));
        assert_eq!(
            record_of(&volume.0).attempts,
            before.attempts + 2,
            "{state:?}"
        );
    }
}

/// The standby's own takeover compare-and-swap commits while the owner drains, before its transfer write: the
/// transfer fails its condition, the reread shows the standby's tenure, and the owner ends `Deposed` with no restart.
/// The standby, the one successor, then activates through its own restart's lineage arm and serves every warm object.
#[test]
fn a_takeover_that_races_the_transfer_leaves_one_successor() {
    let before = record_of(&warm().0);
    let left = requested(
        (warm(), transfer_request, at_open),
        Answer::TakenOver,
        super::roll_tests::deadline(),
        |_| {},
    );
    let c = crate::failover::takeover::tests::c_host();
    assert_eq!(left.exit, Exit::Deposed);
    assert_eq!(
        (left.record.owner, left.record.standby, left.record.attempts),
        (c, None, before.attempts + 2)
    );
    assert_eq!(
        (left.commands_after, left.medium_after, left.sends_after),
        (Some(0), Some(0), Some(0))
    );
    standby_serves(&left).unwrap_or_else(|failure| panic!("{failure}"));
}

/// Ends C's latest attach entry in `store`'s volume record by one exact-version write, keeping its pair recorded.
fn end_c(store: &crate::storage::store::sim::Shared) {
    use crate::failover::records::{EventKind, Record, VolumeRecord};
    let key = crate::storage::store::Key::Volume(crate::failover::restart::tests::volume_id());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let mut record = VolumeRecord::decode(&item.value).unwrap();
    let c = crate::failover::takeover::tests::c_host();
    let at = record
        .events
        .iter()
        .rposition(|event| event.host == c)
        .unwrap();
    record.events[at].kind = EventKind::Ended;
    let write = crate::storage::store::Write::Exact {
        expect: item.version,
        value: record.encode(),
    };
    let mut store = store.clone();
    let _ = crate::storage::store::Store::write(&mut store, &key, &write);
}

/// Where a test ends the transfer target C's attach entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// Before the tenure starts, so every view of the drain shows C unenrolled.
    Before,
    /// After the seal, with a view due, so a view shows C unenrolled before the acknowledged certify withdraws.
    Sealed,
    /// At the withdrawal boundary, after the last view: only the transfer job's own enrollment read sees it.
    AtWithdrawal,
}

/// ENDED-GRANTS-NOTHING at each point it can be observed. A target whose entry a view shows ended keeps the tenure:
/// at the request's first view the request resumes `standby` before any drain stage, and after the seal the drain
/// resumes `standby` before the acknowledged certify withdraws, each with `E` and the owner unchanged. An end after
/// the last view reaches only the transfer job's enrollment read, which issues no write, so the owner ends in one
/// same-host restart with the exit restarting for a refused transfer and the record still naming it. Control: a job
/// that skips that read transfers the shard to C, whose ended entry gives it no tenure to activate.
#[test]
fn a_transfer_to_a_target_whose_entry_ended_writes_nothing_and_restarts_once() {
    use crate::failover::planned::State;
    use crate::failover::report::{ExitStatus, Restart, Resume};
    let before = record_of(&warm().0);
    for (ended, skipped) in [
        (Ended::Before, false),
        (Ended::Sealed, false),
        (Ended::AtWithdrawal, false),
        (Ended::AtWithdrawal, true),
    ] {
        let volume = warm();
        let store = volume.0.clone();
        if ended == Ended::Before {
            end_c(&store);
        }
        if ended == Ended::AtWithdrawal {
            let store = store.clone();
            AT_BOUNDARY.with(|cell| *cell.borrow_mut() = Some(Box::new(move || end_c(&store))));
        }
        ENROLLMENT_UNREAD.with(|cell| cell.set(skipped));
        let mut sealed = false;
        let left = requested_with(
            (volume, transfer_request, at_open),
            Answer::Commit,
            Built::BOTH,
            super::roll_tests::deadline(),
            |_| {},
            |slot| {
                let duties = slot.as_mut().unwrap();
                if ended == Ended::Sealed
                    && !sealed
                    && duties.planned_state() == Some(State::Sealed)
                {
                    end_c(&store);
                    duties.view_at = 0;
                    sealed = true;
                }
            },
        );
        ENROLLMENT_UNREAD.with(|cell| cell.set(false));
        AT_BOUNDARY.with(|cell| cell.borrow_mut().take());
        let label = format!("{ended:?}, skipped {skipped}");
        assert!(
            ended != Ended::Sealed || sealed,
            "{label}: the drain reached the seal"
        );
        if skipped {
            assert_eq!(
                left.record.owner,
                crate::failover::takeover::tests::c_host(),
                "{label}: the planted job transferred"
            );
            continue;
        }
        let unchanged = (before.owner, before.attempts + 1);
        assert_eq!(
            (left.record.owner, left.record.attempts),
            unchanged,
            "{label}: no transfer was written"
        );
        match ended {
            Ended::Before | Ended::Sealed => {
                assert_eq!(left.exit, Exit::Stopped, "{label}: the tenure kept serving");
                assert_eq!(
                    left.status,
                    Some(ExitStatus::Resumed(Resume::Standby)),
                    "{label}"
                );
                assert_eq!(left.drained, ended == Ended::Sealed, "{label}: drain stage");
                assert!(left.admission_open, "{label}: admission reopened");
            }
            Ended::AtWithdrawal => {
                assert_eq!(
                    left.exit,
                    Exit::Rerun(crate::host::Rerun::Planned),
                    "{label}"
                );
                assert_eq!(
                    left.status,
                    Some(ExitStatus::Restarting(Restart::TransferRefused)),
                    "{label}"
                );
            }
        }
    }
}

/// A request whose capped deadline passes while it waits for its first view resumes `deadline` before any drain
/// stage: no machine starts, no drain stage stops a fill, and `E` stays. A second call of [`super::Duties::rolling`]
/// on the live duties keeps the tenure's ledger, so the same request delivered again binds `Repeat`, and a fresh
/// request with a higher sequence is accepted.
#[test]
fn an_expired_pending_request_resumes_before_any_drain_and_a_later_builder_call_keeps_the_ledger() {
    use crate::failover::report::{ExitStatus, Resume};
    let before = record_of(&warm().0);
    let mut phase = 0;
    let left = requested_with(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        Built::BOTH,
        crate::failover::planned::Deadline::new(1).unwrap(),
        |_| {},
        |slot| {
            if phase == 0 && super::roll_tests::resumed_reason().is_some() {
                let duties = slot.take().unwrap().rolling(super::roll_tests::deadline());
                *slot = Some(duties);
                let duties = slot.as_mut().unwrap();
                let record = *duties.read.as_ref().unwrap().value();
                duties.deliver(&transfer_request(&record));
                let target = record.standby.unwrap();
                duties.deliver(&sealed(&record, Kind::Transfer { target }, 2));
                phase = 1;
            }
        },
    );
    let bound = bindings();
    assert_eq!(
        bound,
        [Binding::Accept, Binding::Repeat, Binding::Accept],
        "the repeat kept its operation across the second builder call"
    );
    assert_eq!(super::roll_tests::starts(), 0, "no machine started");
    assert!(!left.drained, "no drain stage");
    assert_eq!(left.status, Some(ExitStatus::Resumed(Resume::Deadline)));
    assert_eq!(left.record.attempts, before.attempts + 1);
}

/// A change the test makes to the duties after the request's acceptance.
type Halt = fn(&mut TestDuties<'_>);

/// REQUEST-START over a capture that cannot publish: a transfer and a restart accepted while the capture refuses
/// every later start, or after the open stopped, resume `cut` at their first view with no drain stage and `E`
/// unchanged.
#[test]
fn a_request_whose_capture_cannot_publish_resumes_cut_before_any_drain() {
    use crate::failover::report::{ExitStatus, Resume};
    let before = record_of(&warm().0);
    let halts: [(Halt, &str); 2] = [
        (
            |duties| duties.capture.as_mut().unwrap().start_at = u64::MAX,
            "every capture start refused",
        ),
        (
            |duties| duties.open = super::Open::Stopped,
            "the open stopped",
        ),
    ];
    let requests: [(Request, &str); 2] =
        [(transfer_request, "transfer"), (restart_request, "restart")];
    for (request, kind) in requests {
        for (halt, how) in halts {
            let mut halted = false;
            let left = requested_with(
                (warm(), request, at_open),
                Answer::Commit,
                Built::BOTH,
                super::roll_tests::deadline(),
                |_| {},
                |slot| {
                    if !halted && last_bound() == Some(Binding::Accept) {
                        halt(slot.as_mut().unwrap());
                        halted = true;
                    }
                },
            );
            assert!(halted, "{kind}, {how}: the request was accepted");
            assert!(!left.drained, "{kind}, {how}: no drain stage");
            assert_eq!(
                left.status,
                Some(ExitStatus::Resumed(Resume::Cut)),
                "{kind}, {how}"
            );
            assert_eq!(
                left.record.attempts,
                before.attempts + 1,
                "{kind}, {how}: no E consumed"
            );
        }
    }
}

/// Duties built through `requesting` alone start no roll at the tenure's bound, in either builder order the roll
/// starts once `rolling` was called, and its cap stays its own: the request cap of 1 µs leaves the roll running to
/// its restart.
#[test]
fn only_duties_built_through_rolling_roll_at_the_bound() {
    let alone = with_cell(&STOP_AT, Some(600), || {
        requested_with(
            (warm(), transfer_request, |_| false),
            Answer::Commit,
            Built {
                capturing: true,
                rolling: false,
            },
            crate::failover::planned::Deadline::new(1).unwrap(),
            |slot| slot.as_mut().unwrap().roll_due = true,
            |_| {},
        )
    });
    assert_eq!(alone.started, None, "requesting alone rolls nothing");
    assert_eq!(alone.exit, Exit::Stopped);
    let after = requested_with(
        (warm(), transfer_request, |_| false),
        Answer::Commit,
        Built {
            capturing: true,
            rolling: false,
        },
        crate::failover::planned::Deadline::new(1).unwrap(),
        |slot| {
            let duties = slot.take().unwrap().rolling(super::roll_tests::deadline());
            *slot = Some(duties);
            slot.as_mut().unwrap().roll_due = true;
        },
        |_| {},
    );
    assert!(matches!(
        after.started,
        Some(crate::failover::planned::ExitKind::Roll { .. })
    ));
    assert_eq!(after.exit, Exit::Rerun(crate::host::Rerun::Planned));
    // The other builder order: `rolling` first, then `requesting` with the 1 µs cap. A roll under the request cap
    // would resume `deadline` on its first clock reading.
    let before = requested_with(
        (warm(), transfer_request, |_| false),
        Answer::Commit,
        Built::BOTH,
        crate::failover::planned::Deadline::new(1).unwrap(),
        |slot| slot.as_mut().unwrap().roll_due = true,
        |_| {},
    );
    assert!(matches!(
        before.started,
        Some(crate::failover::planned::ExitKind::Roll { .. })
    ));
    assert_eq!(before.resumed, None, "the roll kept its own cap");
    assert_eq!(before.exit, Exit::Rerun(crate::host::Rerun::Planned));
}

/// A request on duties with no capture policy resumes `cut` at its start: no drain stage, no `E`, and its exit reads
/// resumed, for a transfer and for a restart alike.
#[test]
fn a_request_with_no_capture_policy_resumes_cut_before_any_drain() {
    use crate::failover::report::{ExitStatus, Resume};
    let before = record_of(&warm().0);
    for request in [transfer_request as Request, restart_request] {
        let left = requested_with(
            (warm(), request, at_open),
            Answer::Commit,
            Built {
                capturing: false,
                rolling: false,
            },
            super::roll_tests::deadline(),
            |_| {},
            |_| {},
        );
        assert_eq!(left.resumed, Some(Resume::Cut));
        assert_eq!(left.status, Some(ExitStatus::Resumed(Resume::Cut)));
        assert!(!left.drained, "no drain stage");
        assert_eq!(left.record.attempts, before.attempts + 1);
        assert_eq!(left.exit, Exit::Stopped);
    }
}

/// The accepted request delivered again while its own drain runs binds `Repeat`: one machine starts, one transfer
/// commits, and the incarnation ends `Stopped`. An authentic request followed in the same delivery by bytes that
/// fail the tag still reaches the ledger.
#[test]
fn a_repeat_during_the_drain_starts_nothing_and_a_bad_tag_beside_it_hides_nothing() {
    use crate::failover::planned::State;
    let before = record_of(&warm().0);
    let mut repeated = false;
    let left = requested_with(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        Built::BOTH,
        super::roll_tests::deadline(),
        |_| {},
        |slot| {
            let duties = slot.as_mut().unwrap();
            if !repeated && duties.planned_state() == Some(State::FillsStopped) {
                let record = *duties.read.as_ref().unwrap().value();
                duties.deliver(&transfer_request(&record));
                repeated = true;
            }
        },
    );
    assert_eq!(bindings(), [Binding::Accept, Binding::Repeat]);
    assert_eq!(super::roll_tests::starts(), 1);
    assert_eq!(left.exit, Exit::Stopped);
    assert_eq!(left.record.attempts, before.attempts + 2);

    let mut delivered = false;
    let left = requested_with(
        (warm(), |_| Vec::new(), |_| false),
        Answer::Commit,
        Built::BOTH,
        super::roll_tests::deadline(),
        |_| {},
        |slot| {
            let duties = slot.as_mut().unwrap();
            if !delivered
                && duties.open() == super::Open::Opened
                && let Some(read) = duties.read.as_ref()
            {
                let valid = transfer_request(read.value());
                let mut forged = valid.clone();
                *forged.last_mut().unwrap() ^= 1;
                duties.deliver(&valid);
                duties.deliver(&forged);
                delivered = true;
            }
        },
    );
    assert_eq!(
        bindings(),
        [Binding::Accept],
        "the forged bytes bind nothing"
    );
    assert_eq!(left.exit, Exit::Stopped);
    assert_eq!(
        left.record.owner,
        crate::failover::takeover::tests::c_host()
    );
}

/// The published entry reads `roll_active` for a same-host restart alone: a transfer's drain and its outstanding
/// write read it clear, and a requested restart reads it set.
#[test]
fn roll_active_reads_a_same_host_restart_and_a_transfer_reads_clear() {
    let transfer = holding(HELD_TURNS, || {
        requested(
            (warm(), transfer_request, at_open),
            Answer::Commit,
            super::roll_tests::deadline(),
            |_| {},
        )
    });
    assert_eq!(
        transfer.rolling_entry.map(|entry| entry.1),
        Some(Some(false))
    );
    assert_eq!(
        transfer.transfer_entry.map(|entry| entry.1),
        Some(Some(false))
    );
    let restart = requested(
        (warm(), restart_request, at_open),
        Answer::Commit,
        super::roll_tests::deadline(),
        |_| {},
    );
    assert_eq!(restart.rolling_entry.map(|entry| entry.1), Some(Some(true)));
}

/// Equal clock readings: with the duties' clock frozen from the seal on and a view due on every turn, a view
/// submitted before the transfer's lost-reply outcome reads the record from before the write. The machine waits for
/// a view submitted after that outcome, which shows the committed transfer, and the owner ends `Deposed` with its
/// exit `exited`.
#[test]
fn a_view_submitted_before_the_outcome_decides_nothing_whatever_the_clock_reads() {
    use crate::failover::planned::State;
    use crate::failover::report::ExitStatus;
    let left = with_cell(&FREEZE_AT, Some(State::Sealed), || {
        requested_with(
            (warm(), transfer_request, at_open),
            Answer::Unknown { commit: true },
            Built::BOTH,
            super::roll_tests::deadline(),
            |_| {},
            |slot| {
                let duties = slot.as_mut().unwrap();
                if duties.planned_state().is_some() || duties.views > 0 {
                    duties.view_at = 0;
                }
            },
        )
    });
    assert_eq!(left.exit, Exit::Deposed);
    assert_eq!(left.status, Some(ExitStatus::Exited));
    assert_eq!(
        left.record.owner,
        crate::failover::takeover::tests::c_host()
    );
}

/// The transfer conditions on the version the acknowledged certify committed. Volume reads fail from the seal to
/// the certify, so the certify waits for a view that read the volume record; meanwhile a same-content rewrite moves
/// the record to the next version and that view adopts it. The transfer's version condition then fails, and the
/// tenure ends in its one same-host restart with the exit restarting for a refused transfer.
#[test]
fn the_transfer_conditions_on_the_certified_version_whatever_later_views_read() {
    use crate::failover::report::{ExitStatus, Restart};
    let before = record_of(&warm().0);
    let left = with_cell(&GATED, true, || {
        requested_with(
            (warm(), transfer_request, at_open),
            Answer::Commit,
            Built::BOTH,
            super::roll_tests::deadline(),
            |_| {},
            |slot| {
                let duties = slot.as_mut().unwrap();
                if duties.planned_state().is_some() {
                    duties.view_at = 0;
                }
            },
        )
    });
    VOLUME_GATE.with(|cell| cell.set(0));
    assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Planned));
    assert_eq!(
        left.status,
        Some(ExitStatus::Restarting(Restart::TransferRefused))
    );
    assert_eq!(
        (left.record.owner, left.record.attempts),
        (before.owner, before.attempts + 1)
    );
}

/// A transfer request whose own deadline, 3 ms from receipt, falls after the harness's withdrawal and before the
/// held transfer's outcome.
fn transfer_by_3_ms(record: &ShardRecord) -> Vec<u8> {
    let target = record.standby.unwrap();
    sealed_by(
        record,
        Kind::Transfer { target },
        1,
        NonZeroU32::new(3_000).unwrap(),
    )
}

/// A request deadline that passes after the withdrawal and before the transfer's outcome restarts nothing: the
/// driver's outcome decides the exit. An acknowledged transfer and a lost reply whose write committed read `exited`,
/// a lost reply whose write did not commit reads restarting for an unknown transfer, and a refused one restarting
/// for a refused transfer.
#[test]
fn a_request_deadline_after_the_withdrawal_leaves_the_exit_to_the_transfer_outcome() {
    use crate::failover::report::{ExitStatus, Restart};
    let rows = [
        (Answer::Commit, ExitStatus::Exited),
        (Answer::Unknown { commit: true }, ExitStatus::Exited),
        (
            Answer::Unknown { commit: false },
            ExitStatus::Restarting(Restart::TransferUnknown),
        ),
        (
            Answer::Moved,
            ExitStatus::Restarting(Restart::TransferRefused),
        ),
    ];
    for (answer, status) in rows {
        let left = holding(HELD_TURNS, || {
            requested(
                (warm(), transfer_by_3_ms, at_open),
                answer,
                super::roll_tests::deadline(),
                |_| {},
            )
        });
        assert!(
            left.commands_after.is_some(),
            "{answer:?}: the owner withdrew"
        );
        assert_eq!(left.status, Some(status), "{answer:?}");
    }
}

/// A transfer the store refuses with `Denied`, a documented noncommit, ends in one same-host restart with the exit
/// restarting for a refused transfer. A transfer whose commit the client then reads as a regression, a client alarm
/// after the store committed, ends the incarnation `Rerun(Withdrawn)` with no emission after the withdrawal; the
/// record names the standby owner, and the standby's restart serves the cut.
#[test]
fn a_denied_transfer_restarts_once_and_an_alarm_after_its_commit_ends_withdrawn() {
    use crate::failover::report::{ExitStatus, Restart};
    let before = record_of(&warm().0);
    let denied = requested(
        (warm(), transfer_request, at_open),
        Answer::Denied,
        super::roll_tests::deadline(),
        |_| {},
    );
    assert_eq!(denied.exit, Exit::Rerun(crate::host::Rerun::Planned));
    assert_eq!(
        denied.status,
        Some(ExitStatus::Restarting(Restart::TransferRefused))
    );
    assert_eq!(
        (denied.record.owner, denied.record.attempts),
        (before.owner, before.attempts + 1)
    );
    let alarmed = requested(
        (warm(), transfer_request, at_open),
        Answer::Skewed,
        super::roll_tests::deadline(),
        |_| {},
    );
    assert_eq!(alarmed.exit, Exit::Rerun(crate::host::Rerun::Withdrawn));
    assert_eq!(
        (
            alarmed.commands_after,
            alarmed.medium_after,
            alarmed.sends_after
        ),
        (Some(0), Some(0), Some(0))
    );
    assert_eq!(
        (alarmed.record.owner, alarmed.record.attempts),
        (
            crate::failover::takeover::tests::c_host(),
            before.attempts + 2
        )
    );
    standby_serves(&alarmed).unwrap_or_else(|failure| panic!("{failure}"));
}

/// A view whose shard read fails beside a volume read that succeeds shows nothing of the target's enrollment. Volume
/// reads fail from the seal until the certify is acknowledged, which holds that certify back; from then to the
/// withdrawal every shard read fails and volume reads succeed. The held certify then withdraws the tenure and the
/// transfer commits, naming the standby owner, with no resume.
#[test]
fn a_failed_shard_read_beside_a_read_volume_record_keeps_the_certified_transfer() {
    let before = record_of(&warm().0);
    super::roll_tests::reset();
    AT_BOUNDARY.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(|| SHARD_DOWN.with(|down| down.set(false))));
    });
    let mut phase = 0;
    let left = requested_with(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        Built::BOTH,
        super::roll_tests::deadline(),
        |_| {},
        |slot| {
            let duties = slot.as_mut().unwrap();
            // Each phase asks for one view at once.
            if phase == 0 && duties.roll_sealed() {
                VOLUME_DOWN.with(|down| down.set(true));
                (phase, duties.view_at) = (1, 0);
            }
            if phase == 1 && duties.roll_certify_held() {
                VOLUME_DOWN.with(|down| down.set(false));
                SHARD_DOWN.with(|down| down.set(true));
                (phase, duties.view_at) = (2, 0);
            }
        },
    );
    SHARD_DOWN.with(|down| down.set(false));
    VOLUME_DOWN.with(|down| down.set(false));
    AT_BOUNDARY.with(|cell| cell.borrow_mut().take());
    assert_eq!(
        phase, 2,
        "the certify was held behind the unread volume record"
    );
    assert_eq!(super::roll_tests::resumed_reason(), None);
    assert_eq!(left.exit, Exit::Stopped);
    assert_eq!(
        (left.record.owner, left.record.attempts),
        (before.standby.unwrap(), before.attempts + 2)
    );
}

/// When the link toward the client admits sends again in a transfer beside a queued PUT RESULT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opens {
    /// After the result waited this many turns of the transfer; a transfer that waits in its stage 1 holds that stage
    /// for all of them.
    InStageOne(u32),
    /// On the turn after the transfer resumed.
    AfterTheResume,
}

/// The deadline of a transfer's stage 1 beside a queued result.
const STAGE_ONE_CAP_US: u64 = 400 * crate::host::serve::loop_tests::ROUND_US;

/// The planned exit a case beside a queued PUT RESULT requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    Transfer,
    Restart,
}

/// The first turn after the request on which the authority left `Serving`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Left {
    /// The turn's clock reading.
    at: u64,
    /// Whether a published fill's first PUT RESULT waited before that turn's duties ran.
    owed: bool,
    cause: Option<crate::failover::serving::Cause>,
}

/// What a case beside a queued PUT RESULT showed.
struct Beside {
    /// Each check that failed.
    failures: Vec<String>,
    /// The request's capped deadline, from its receipt.
    due: Option<u64>,
    left: Option<Left>,
    exit: Exit,
}

/// A planned exit beside a published wire fill whose first PUT RESULT waits behind blocked sends: the client uploads
/// an empty object, sends toward it block once it holds the owner's READY, the fill publishes, and the owner then
/// receives the request `asked` names under a cap of `cap_us`. With `refused` set, the planned capture's Publish is
/// refused (a planted stale epoch). While the planned exit runs and the result waits, the tenure holds an interval
/// INVALIDATE every other turn. The link opens as `opens` says. A transfer whose link opens in stage 1 runs with its
/// completion held for [`HELD_TURNS`] turns, over which the client keeps asking the withdrawn owner for warm objects.
///
/// Checks RESULT-BEFORE-WITHDRAWAL for the exit: the drain holds stage 1 while the result waits and leaves it only
/// after a send took the result; no INVALIDATE is refused `Closed` before the result leaves or the tenure resumes;
/// after a transfer's withdrawal the old owner sends nothing while GETs toward it are delivered or in flight; and an
/// exit whose link stays blocked to the deadline resumes in place, on the first turn at or past the deadline, with
/// `E`, the sessions sampled after the resuming turn, the authority, and the record's owner and standby unchanged,
/// after which the result is sent. A refused Publish resumes the exit `cut` before the deadline, with the result
/// still queued. The client's upload ends `Published`; a transfer that completes names the standby owner at `E + 2`
/// and ends `Stopped`, and a restart ends `Rerun::Planned` with the owner and standby unchanged.
fn exit_beside_a_queued_result(asked: Asked, opens: Opens, cap_us: u64, refused: bool) -> Beside {
    let withdraws = asked == Asked::Transfer && matches!(opens, Opens::InStageOne(_));
    match withdraws {
        true => holding(HELD_TURNS, || {
            beside_a_queued_result(asked, opens, cap_us, refused)
        }),
        false => beside_a_queued_result(asked, opens, cap_us, refused),
    }
}

fn beside_a_queued_result(asked: Asked, opens: Opens, cap_us: u64, refused: bool) -> Beside {
    use super::capture::STALE_EPOCH;
    use super::cover_tests::{entry, key_on, pages};
    use super::step_tests::{NEVER, STEP_US, step_duties_on};
    use crate::failover::planned::{Deadline, ExitKind};
    use crate::failover::report::Resume;
    use crate::failover::serving::State;
    use crate::net::link::Faults;
    use crate::net::{DrainStage, PeerId, SessionState, UploadOutcome};
    use crate::storage::{CacheVersion, InvalidateError, WorkBudget};
    use std::cell::RefCell;
    use std::sync::atomic::Ordering;

    const FILLED: u8 = 200;
    let round = crate::host::serve::loop_tests::ROUND_US;
    super::roll_tests::reset();
    let failures = RefCell::new(Vec::<String>::new());
    let fail = |failure: String| failures.borrow_mut().push(failure);
    let upload = Cell::new(None);
    let (prepared, open, outcome) = (Cell::new(false), Cell::new(false), Cell::new(None));
    let (resumed, done_at) = (Cell::new(false), Cell::new(None::<u64>));
    let (carried_at, offered) = (Cell::new(None::<u64>), Cell::new(0_usize));
    let blocked = Faults {
        would_block: 100,
        ..Faults::default()
    };
    let before = record_of(&warm().0);
    let (mut due, mut left) = (None::<u64>, None::<Left>);
    let (exit, record) = crate::host::serve::loop_tests::staged_over_on(
        warm(),
        own_alone(),
        || crate::storage::warm_sim::storage(1),
        |mut stage| {
            let policy = Some(super::capture_tests::policy_every(NEVER));
            let mut duties = step_duties_on(&stage, stage.store.clone(), policy, STEP_US)
                .requesting(key(), Deadline::new(cap_us).unwrap());
            let storage = stage.storage;
            let (mut requested, mut held, mut stage_left) = (None::<u64>, 0_u32, false);
            let (mut epochs_before, mut withdrawn_sent) = (None, None::<u64>);
            let (mut invalidations, mut admitted, mut waited) = (0_usize, 0_usize, 0_u32);
            let mut held_turns = 0_u32;
            // The driver's withdrawal boundary marks the turn from whose end on the old owner sends nothing.
            let boundary = Rc::new(Cell::new(false));
            let marked = boundary.clone();
            BOUNDARY.with(|cell| {
                *cell.borrow_mut() = Some(Box::new(move || marked.set(true)));
            });
            let (served, _) = stage.serve_until(
                |rounds, turn, stop| {
                    let now = turn * round;
                    let mut client = rounds.client.borrow_mut();
                    if upload.get().is_none() && client.state() == SessionState::Active {
                        let key = crate::storage::warm_sim::object_key(FILLED);
                        upload.set(client.put(key, CacheVersion(0), now, 30_000_000).ok());
                    }
                    if let Some(id) = upload.get() {
                        if !prepared.get() && client.prepare(id, 0, 0, 60_000).is_ok() {
                            prepared.set(true);
                            rounds.fault_toward_client(blocked);
                        }
                        if outcome.get().is_none() {
                            outcome.set(client.put_outcome(id));
                        }
                    }
                    if open.replace(false) {
                        rounds.fault_toward_client(Faults::default());
                    }
                    drop(client);
                    // From the withdrawal boundary on the client keeps asking the old owner for warm objects; a
                    // closed owner receives nothing, so a datagram toward it stays in flight.
                    if boundary.get() {
                        let from = *carried_at.get().get_or_insert(rounds.carried());
                        carried_at.set(Some(from));
                        if turn % 4 == 0 {
                            let _ = rounds.try_get((turn / 4 % 4) as u8 + 1);
                        }
                        let toward = crate::host::serve::loop_tests::OWNER_END;
                        let seen = rounds.delivered_since(toward, from) + rounds.in_flight(toward);
                        offered.set(offered.get().max(seen));
                    }
                    // A resumed exit leaves the tenure serving: the case ends a few turns after the result reached
                    // the client.
                    if resumed.get() && outcome.get().is_some() {
                        let at = *done_at.get().get_or_insert(turn);
                        done_at.set(Some(at));
                        if turn >= at + 8 {
                            stop.store(true, Ordering::Release);
                        }
                    }
                },
                |owner, now| {
                    crate::storage::owner_fixture::set_clock(
                        storage,
                        &[Some(super::capture::nanos(now))],
                    );
                    let epochs = [0, 1].map(|peer| owner.session_epoch(PeerId(peer)));
                    if owner.put_results_queued()
                        && requested.is_none()
                        && duties.open() == super::Open::Opened
                        && let Some(read) = duties.read.as_ref()
                    {
                        let bytes = match asked {
                            Asked::Transfer => transfer_request(read.value()),
                            Asked::Restart => restart_request(read.value()),
                        };
                        duties.deliver(&bytes);
                        requested = Some(now);
                        due = Some(now + cap_us);
                        epochs_before = Some((owner.tenure().target(), epochs));
                        STALE_EPOCH.with(|stale| stale.set(refused));
                    }
                    let owed_before = owner.put_results_queued();
                    let waiting = owed_before && !resumed.get();
                    if requested.is_some() && waiting && now % (2 * round) == 0 {
                        let pages = pages(owner);
                        let page = [0, pages.get() - 1][invalidations % 2];
                        let (key, interval) = entry(key_on(page, pages, invalidations));
                        invalidations += 1;
                        let mut budget = WorkBudget::new(1024);
                        match owner.invalidate_interval(&key, interval, 2, &mut budget) {
                            Ok(_) => admitted += 1,
                            Err(InvalidateError::Closed) => fail(format!(
                                "an INVALIDATE was refused Closed with the result queued, in {:?}",
                                owner.draining()
                            )),
                            Err(_) => {}
                        }
                    }
                    let exit = duties.turn(owner, now);
                    if duties.lane.inline_mut().held() > 0 {
                        held_turns += 1;
                        if held_turns >= HELD_TURNS {
                            duties.lane.inline_mut().release_all();
                        }
                    }
                    let owed = owner.put_results_queued();
                    let stage = owner.draining();
                    let report = owner.authority_report();
                    if requested.is_some() && left.is_none() && report.state != State::Serving {
                        left = Some(Left {
                            at: now,
                            owed: owed_before,
                            cause: report.withdrawal,
                        });
                    }
                    if requested.is_some()
                        && !stage_left
                        && (stage == Some(DrainStage::Mutations) || report.state != State::Serving)
                    {
                        stage_left = true;
                        if owed {
                            fail("RESULT-BEFORE-WITHDRAWAL: the exit left stage 1 beside a queued result".into());
                        }
                    }
                    if boundary.get() && withdrawn_sent.is_none() {
                        withdrawn_sent = Some(owner.report().sent);
                    }
                    if let Some(sent) = withdrawn_sent
                        && owner.report().sent != sent
                    {
                        fail(format!("FP-HAND-04: the old owner sent {} frames after its withdrawal", owner.report().sent - sent));
                        withdrawn_sent = Some(owner.report().sent);
                    }
                    if stage == Some(DrainStage::Fills) && owed {
                        held += 1;
                    }
                    // The link opens after the result waited this many turns of the planned exit, whatever drain
                    // stage they fell in.
                    if requested.is_some() && owed && !resumed.get() {
                        waited += 1;
                        if opens == Opens::InStageOne(waited) {
                            open.set(true);
                        }
                    }
                    if let Some(reason) = super::roll_tests::resumed_reason()
                        && !resumed.get()
                    {
                        resumed.set(true);
                        STALE_EPOCH.with(|stale| stale.set(false));
                        // The sessions are sampled after the turn that resumed.
                        let after = [0, 1].map(|peer| owner.session_epoch(PeerId(peer)));
                        let kept = after[0].is_some()
                            && Some((owner.tenure().target(), after)) == epochs_before;
                        let expected = match refused {
                            true => Resume::Cut,
                            false => Resume::Deadline,
                        };
                        if reason != expected
                            || report.state != State::Serving
                            || report.withdrawal.is_some()
                            || stage.is_some()
                            || !kept
                            || !owed
                        {
                            fail(format!(
                                "the resume: {reason:?}, {:?}, withdrawal {:?}, stage {stage:?}, tenure and sessions \
                                 kept {kept}, result queued {owed}",
                                report.state, report.withdrawal
                            ));
                        }
                        // The request's deadline runs from its receipt; a deadline resume comes on the first turn at
                        // or past it, and a refused Publish resumes before it.
                        let timely = match refused {
                            true => due.is_some_and(|due| now < due),
                            false => due.is_some_and(|due| (due..due + round).contains(&now)),
                        };
                        if !timely {
                            fail(format!("the resume came at {now}; the deadline is {due:?}"));
                        }
                        open.set(opens == Opens::AfterTheResume);
                    }
                    exit
                },
            );
            BOUNDARY.with(|cell| cell.borrow_mut().take());
            STALE_EPOCH.with(|stale| stale.set(false));
            if (opens == Opens::AfterTheResume) != resumed.get() {
                fail(format!(
                    "RESULT-BEFORE-WITHDRAWAL: the exit resumed: {}, after holding stage 1 for {held} turns",
                    resumed.get()
                ));
            }
            if held == 0 {
                fail("the exit never held stage 1 beside the queued result".into());
            }
            if admitted == 0 {
                fail("no INVALIDATE was admitted beside the queued result".into());
            }
            if asked == Asked::Transfer && boundary.get() && offered.get() == 0 {
                fail("no GET was offered to the withdrawn owner".into());
            }
            (served.exit, record_of(&stage.store))
        },
    );
    let c = crate::failover::takeover::tests::c_host();
    let started = super::roll_tests::started_kind();
    let kind = match asked {
        Asked::Transfer => ExitKind::Transfer { target: c },
        Asked::Restart => ExitKind::Restart,
    };
    if started != Some(kind) {
        fail(format!("the exit started as {started:?}"));
    }
    if outcome.get() != Some(UploadOutcome::Published) {
        fail(format!("the client's upload ended {:?}", outcome.get()));
    }
    let (ending, owner, standby, attempts) = match (asked, opens) {
        (Asked::Transfer, Opens::InStageOne(_)) => (Exit::Stopped, c, None, before.attempts + 2),
        (Asked::Restart, Opens::InStageOne(_)) => (
            Exit::Rerun(crate::host::Rerun::Planned),
            before.owner,
            before.standby,
            before.attempts + 1,
        ),
        (_, Opens::AfterTheResume) => (
            Exit::Stopped,
            before.owner,
            before.standby,
            before.attempts + 1,
        ),
    };
    if exit != ending
        || (record.owner, record.standby, record.attempts) != (owner, standby, attempts)
    {
        fail(format!(
            "the tenure ended {exit:?} with the record naming {:?} and standby {:?} at E = {}",
            record.owner, record.standby, record.attempts
        ));
    }
    Beside {
        failures: failures.into_inner(),
        due,
        left,
        exit,
    }
}

/// RESULT-BEFORE-WITHDRAWAL for the transfer and the requested restart: a published fill's first PUT RESULT queued
/// behind blocked egress holds the exit's stage 1, no INVALIDATE is refused `Closed` while it waits, and the exit
/// leaves stage 1 once a send took the result. The transfer then completes, naming the standby owner, and the old owner
/// sends nothing after its withdrawal while GETs toward it are offered; the restart ends `Rerun::Planned` with the
/// owner and standby unchanged.
#[test]
fn a_transfer_holds_stage_one_until_a_queued_put_result_is_sent_and_then_completes() {
    for asked in [Asked::Transfer, Asked::Restart] {
        let beside = exit_beside_a_queued_result(asked, Opens::InStageOne(40), 1 << 50, false);
        assert!(
            beside.failures.is_empty(),
            "{asked:?}: {:#?}",
            beside.failures
        );
    }
}

/// The control: a driver that reads no queued result leaves the exit's stage 1 beside one.
#[test]
fn control_a_transfer_that_reads_no_queued_result_leaves_stage_one_beside_it() {
    use super::roll_tests::{Plant, with_plant};
    for asked in [Asked::Transfer, Asked::Restart] {
        let beside = with_plant(Plant::ResultsUnwaited, || {
            exit_beside_a_queued_result(asked, Opens::InStageOne(40), 1 << 50, false)
        });
        let left = "RESULT-BEFORE-WITHDRAWAL: the exit left stage 1 beside a queued result";
        assert!(
            beside.failures.iter().any(|failure| failure == left),
            "{asked:?}: {:#?}",
            beside.failures
        );
    }
}

/// A transfer whose first turn in `Sealed` runs with the capture mutex held: each check of
/// [`BusySeal`](super::roll_tests::BusySeal) that failed, and a failure when the tenure does not end `Stopped` with
/// the record naming the standby owner.
fn transfer_under_a_busy_seal() -> Vec<String> {
    let before = record_of(&warm().0);
    BUSY_SEAL.with(|busy| *busy.borrow_mut() = Some(Default::default()));
    let left = requested(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        super::roll_tests::deadline(),
        |_| {},
    );
    let busy = BUSY_SEAL.with(|busy| busy.borrow_mut().take());
    let mut failures = busy.expect("the harness kept the record").failures();
    if left.exit != Exit::Stopped || Some(left.record.owner) != before.standby {
        failures.push(format!(
            "the transfer ended {:?} naming {:?}",
            left.exit, left.record.owner
        ));
    }
    failures
}

/// FP-HAND-06 under a busy capture mutex: a transfer whose seal, asked on its first turn in `Sealed`, finds the
/// capture mutex held keeps that seal asked, a later turn admits it, and the transfer commits and stops the tenure.
#[test]
fn a_transfer_s_seal_that_finds_the_capture_mutex_held_is_admitted_on_a_later_turn() {
    let failures = transfer_under_a_busy_seal();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The control: a driver that drops a seal whose try of the capture mutex found it held fails the transfer's check.
#[test]
fn control_a_dropped_seal_under_a_busy_capture_mutex_fails_the_transfer_s_check() {
    use super::roll_tests::{Plant, with_plant};
    let failures = with_plant(Plant::SealDroppedWhenBusy, transfer_under_a_busy_seal);
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("the seal was dropped")),
        "{failures:#?}"
    );
}

/// The control: a driver that reads no queued result in stage 1 and waits in `Sealed` with an acknowledged certify
/// refuses INVALIDATEs `Closed` while the result waits. The Sealed hold alone keeps the transfer from withdrawing
/// beside the result, so the transfer still completes with the client's upload `Published`, which the stage-1 bypass
/// alone does not show.
#[test]
fn control_the_sealed_gate_refuses_invalidates_closed_while_the_result_waits() {
    use super::roll_tests::{Plant, with_plant};
    let failures = with_plant(Plant::SealedGate, || {
        exit_beside_a_queued_result(Asked::Transfer, Opens::InStageOne(40), 1 << 50, false)
    })
    .failures;
    assert!(
        failures.iter().any(|failure| failure
            .starts_with("an INVALIDATE was refused Closed with the result queued")),
        "{failures:#?}"
    );
    assert!(
        !failures
            .iter()
            .any(|failure| failure.starts_with("the client's upload ended")
                || failure.starts_with("the tenure ended")),
        "{failures:#?}"
    );
}

/// Egress blocked to the request's deadline resumes the tenure in place: the reason is `deadline`, admission
/// reopens, the authority stays `Serving` with no withdrawal, and `E`, the sessions and the record's owner and standby
/// are unchanged.
/// The result is sent once egress opens.
#[test]
fn a_transfer_whose_queued_put_result_outlasts_the_deadline_resumes_in_place() {
    for asked in [Asked::Transfer, Asked::Restart] {
        let beside =
            exit_beside_a_queued_result(asked, Opens::AfterTheResume, STAGE_ONE_CAP_US, false);
        assert!(
            beside.failures.is_empty(),
            "{asked:?}: {:#?}",
            beside.failures
        );
        assert_eq!(beside.left, None, "{asked:?}: the authority left Serving");
    }
}

/// The control: a driver whose resume ends the tenure's sessions in the resuming turn fails the sessions-kept check,
/// which samples the sessions after that turn.
#[test]
fn control_a_resume_that_ends_the_sessions_fails_the_sessions_kept_check() {
    use super::roll_tests::{Plant, with_plant};
    let failures = with_plant(Plant::ResumeEndsSessions, || {
        exit_beside_a_queued_result(
            Asked::Transfer,
            Opens::AfterTheResume,
            STAGE_ONE_CAP_US,
            false,
        )
    })
    .failures;
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("the resume: Deadline")
                && failure.contains("tenure and sessions kept false")),
        "{failures:#?}"
    );
}

/// The control: a driver that withdraws where the machine resumes for the deadline ends the tenure with the result
/// unsent and no resume. The authority leaves `Serving` for `Cause::Planned` on the first turn at or past the
/// request's deadline, with the result queued before that turn's duties ran, and the tenure ends `Rerun::Planned`.
#[test]
fn control_a_transfer_that_withdraws_at_the_deadline_abandons_the_queued_result() {
    use super::roll_tests::{Plant, with_plant};
    let round = crate::host::serve::loop_tests::ROUND_US;
    for asked in [Asked::Transfer, Asked::Restart] {
        let beside = with_plant(Plant::DeadlineWithdraws, || {
            exit_beside_a_queued_result(asked, Opens::AfterTheResume, STAGE_ONE_CAP_US, false)
        });
        let failures = &beside.failures;
        let due = beside.due.expect("the request was delivered");
        let left = beside.left.expect("the authority left Serving");
        assert!(
            (due..due + round).contains(&left.at),
            "{asked:?}: withdrew at {} for the deadline {due}",
            left.at
        );
        assert!(left.owed, "{asked:?}: no result waited at the withdrawal");
        assert_eq!(
            left.cause,
            Some(crate::failover::serving::Cause::Planned),
            "{asked:?}"
        );
        assert_eq!(
            beside.exit,
            Exit::Rerun(crate::host::Rerun::Planned),
            "{asked:?}"
        );
        assert!(
            !failures
                .iter()
                .any(|failure| failure.starts_with("the exit never held stage 1")),
            "{asked:?}: {failures:#?}"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure
                    .starts_with("RESULT-BEFORE-WITHDRAWAL: the exit resumed: false")),
            "{asked:?}: {failures:#?}"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.starts_with("the client's upload ended")),
            "{asked:?}: {failures:#?}"
        );
    }
}

/// A Publish the store refuses resumes the exit `cut` before its deadline while a published fill's first PUT RESULT
/// waits, with admission reopened, the authority `Serving` and `E` and the sessions unchanged; the result is sent once
/// egress opens.
#[test]
fn a_refused_publish_beside_a_queued_put_result_resumes_cut_before_the_deadline() {
    for asked in [Asked::Transfer, Asked::Restart] {
        let beside =
            exit_beside_a_queued_result(asked, Opens::AfterTheResume, STAGE_ONE_CAP_US, true);
        assert!(
            beside.failures.is_empty(),
            "{asked:?}: {:#?}",
            beside.failures
        );
    }
}

/// The control: a driver that holds every Publish outcome while a result waits keeps the refused Publish from the
/// machine, so the exit resumes `deadline` at the cap.
#[test]
fn control_a_refused_publish_held_beside_the_queued_result_resumes_deadline() {
    use super::roll_tests::{Plant, with_plant};
    let failures = with_plant(Plant::PublishOutcomesHeld, || {
        exit_beside_a_queued_result(
            Asked::Transfer,
            Opens::AfterTheResume,
            STAGE_ONE_CAP_US,
            true,
        )
    })
    .failures;
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("the resume: Deadline")),
        "{failures:#?}"
    );
}

/// The control: an owner that submits the transfer while still serving keeps sending after the withdrawal boundary,
/// which fails FP-HAND-04's check of the queued-result case.
#[test]
fn control_an_owner_that_emits_after_its_transfer_fails_the_queued_result_case() {
    let failures = with_plant(Plant::EmitAfterTransfer, || {
        exit_beside_a_queued_result(Asked::Transfer, Opens::InStageOne(40), 1 << 50, false)
    })
    .failures;
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("FP-HAND-04: the old owner sent")),
        "{failures:#?}"
    );
}

/// One tenure of the warm volume that accepts a transfer request under a cap of `cap_us` and loses its store from
/// the first turn its drain reads `state`: `outage` says how the store fails, and the outage ends when the tenure
/// resumes. The client keeps up to two GETs of warm objects live throughout, and after the resume the harness
/// publishes one fresh FILL in the same tenure. Returns each check of the store-outage scenario that failed:
/// the tenure resumes in place for `reason`, for a silent store on the first turn at or past the request's
/// deadline, with no withdrawal, `E`, the owner and the client's session unchanged; every GET that ended during
/// the outage completed with its object, and at least one did; and the resumed tenure publishes the FILL.
fn drained_through_a_store_outage(
    state: crate::failover::planned::State,
    outage: Outage,
    reason: crate::failover::report::Resume,
    cap_us: u64,
) -> Vec<String> {
    use crate::failover::planned::Deadline;
    use crate::failover::report::{ExitStatus, Resume};
    let before = record_of(&warm().0);
    OUTAGE.with(|cell| cell.set(Some((state, outage))));
    FILL_AFTER_RESUME.with(|cell| cell.set(true));
    let left = requested(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        Deadline::new(cap_us).unwrap(),
        |_| {},
    );
    OUTAGE.with(|cell| cell.set(None));
    FILL_AFTER_RESUME.with(|cell| cell.set(false));
    DOWN.with(|cell| cell.set(false));
    VOLUME_DOWN.with(|cell| cell.set(false));
    let mut failures = Vec::new();
    if left.resumed != Some(reason) || left.status != Some(ExitStatus::Resumed(reason)) {
        failures.push(format!(
            "the outage resumed: {:?} with the exit {:?}",
            left.resumed, left.status
        ));
    }
    if left.exit != Exit::Stopped || !left.admission_open {
        failures.push(format!(
            "the tenure kept serving: it ended {:?} with admission open {}",
            left.exit, left.admission_open
        ));
    }
    let kept = (before.owner, before.standby, before.attempts + 1);
    if (left.record.owner, left.record.standby, left.record.attempts) != kept {
        failures.push(format!("the record moved: {:?}", left.record));
    }
    if !left.session_kept {
        failures.push("the client's session ended".into());
    }
    let (hits, unserved) = left.gets_down;
    if hits == 0 || unserved != 0 {
        failures.push(format!(
            "hits through the outage: {hits} GETs completed and {unserved} did not"
        ));
    }
    if reason == Resume::Deadline {
        let round = crate::host::serve::loop_tests::ROUND_US;
        let due = left.received_at.map(|at| at + cap_us);
        let on_time =
            (due.zip(left.resumed_at)).is_some_and(|(due, at)| (due..due + round).contains(&at));
        if !on_time {
            failures.push(format!(
                "the resume came at {:?}; the deadline is {due:?}",
                left.resumed_at
            ));
        }
    }
    if left.filled != Some(true) {
        failures.push(format!("the FILL after the resume: {:?}", left.filled));
    }
    failures
}

/// The deadline of the store-outage cases: long enough for a drain to reach its seal, short enough to pass in the
/// tenure's stage.
const OUTAGE_CAP_US: u64 = 400 * crate::host::serve::loop_tests::ROUND_US;

/// RESUME-BEFORE-WITHDRAWAL under a store outage, a store that is unavailable during the drain: a transfer
/// whose store stops answering after fills stop, or after the seal, resumes in place on the first turn at or past
/// its deadline. A store whose requests fail at once resumes the drain `store` at the failed Publish or the failed
/// certify. A store that answers every request but the reads of the volume record, from the seal on, acknowledges
/// the certify; INPUT-ORDER holds that acknowledgment back while no view read the volume record, so the tenure
/// resumes at its deadline and issues no transfer toward a target whose enrollment no view could read. In each row
/// the tenure withdraws nothing, keeps `E`, its owner, its standby and the client's session, completes every GET
/// that ends during the outage, and publishes a fresh FILL after the resume.
#[test]
fn a_store_outage_during_the_drain_resumes_in_place_with_hits_served_throughout() {
    use crate::failover::planned::State;
    use crate::failover::report::Resume;
    for (state, outage, reason) in [
        (State::FillsStopped, Outage::Silent, Resume::Deadline),
        (State::Sealed, Outage::Silent, Resume::Deadline),
        (State::FillsStopped, Outage::Fails, Resume::Store),
        (State::Sealed, Outage::Fails, Resume::Store),
        (State::Sealed, Outage::VolumeUnread, Resume::Deadline),
    ] {
        let failures = drained_through_a_store_outage(state, outage, reason, OUTAGE_CAP_US);
        assert!(failures.is_empty(), "{state:?}, {outage:?}: {failures:#?}");
    }
}

/// The control: a driver that withdraws where the machine resumes for the deadline ends the tenure of the silent
/// outage in a restart, which consumes an `E` and ends the client's session.
#[test]
fn control_a_driver_that_withdraws_at_the_deadline_of_a_store_outage_ends_the_tenure() {
    use crate::failover::planned::State;
    use crate::failover::report::Resume;
    let failures =
        super::roll_tests::with_plant(super::roll_tests::Plant::DeadlineWithdraws, || {
            drained_through_a_store_outage(
                State::FillsStopped,
                Outage::Silent,
                Resume::Deadline,
                OUTAGE_CAP_US,
            )
        });
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("the outage resumed: None")),
        "{failures:#?}"
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.starts_with("the tenure kept serving: it ended Rerun(Planned)")),
        "{failures:#?}"
    );
}

/// Attaches and enrolls B, a third host, on the warm volume's record by one exact-version write, as the standby
/// enrollment of a second standby leaves it.
fn enroll_b(store: &crate::storage::store::sim::Shared) {
    use crate::failover::records::{ERA, EventKind, Record, RecordedPair, VolumeRecord};
    use crate::failover::takeover::tests::{b_host, b_pair};
    let key = crate::storage::store::Key::Volume(crate::failover::restart::tests::volume_id());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let mut record = VolumeRecord::decode(&item.value).unwrap();
    let attach = record.push(EventKind::Attach, b_host(), ERA).unwrap();
    record.pairs.push(RecordedPair {
        host: b_host(),
        pair: b_pair(),
        attach,
    });
    let write = crate::storage::store::Write::Exact {
        expect: item.version,
        value: record.encode(),
    };
    let mut store = store.clone();
    let outcome = crate::storage::store::Store::write(&mut store, &key, &write);
    assert!(
        matches!(outcome, crate::storage::store::Outcome::Committed(_)),
        "B's enrollment commits: {outcome:?}"
    );
}

/// Gives C's live attach on the warm volume the form `Reconciler::end_attach` ends (KEY-PER-ATTACH, BIND-AT-ATTACH),
/// as `record_standby` and `enroll_standby` write it: C's entry takes the record's next number and binds C's
/// instance, and C's recorded pair carries that entry's key. The fixture's other pairs keep their keys.
fn key_c_attach(store: &crate::storage::store::sim::Shared) {
    use crate::failover::attachments::InstanceId;
    use crate::failover::records::{Record, VolumeRecord, attachment_key};
    use crate::failover::takeover::tests::c_host;
    let key = crate::storage::store::Key::Volume(crate::failover::restart::tests::volume_id());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let mut record = VolumeRecord::decode(&item.value).unwrap();
    let old = record.live(c_host()).expect("C holds a live attach");
    let seq = record.next;
    record.next += 1;
    let at = (record.events.iter()).position(|event| event.seq == old);
    let mut entry = record.events.remove(at.expect("C's entry"));
    (entry.seq, entry.instance) = (seq, Some(InstanceId::new("i-0ccccccccccccccc0").unwrap()));
    record.events.push(entry);
    let pair = (record.pairs.iter_mut()).find(|recorded| recorded.host == c_host());
    let pair = pair.expect("C's recorded pair");
    (pair.attach, pair.pair.key) = (seq, attachment_key(seq).unwrap());
    let write = crate::storage::store::Write::Exact {
        expect: item.version,
        value: record.encode(),
    };
    let outcome = crate::storage::store::Store::write(&mut store.clone(), &key, &write);
    assert!(
        matches!(outcome, crate::storage::store::Outcome::Committed(_)),
        "C's keyed attach commits: {outcome:?}"
    );
}

/// Names `host` the standby of the test shard through the reconciler's production steps: a census reservation of the
/// shard's slot for `host`, with every other host shown lost, then `Reconciler::designate` on the active volume.
fn designate_through_the_reconciler(
    store: &crate::storage::store::sim::Shared,
    host: crate::failover::records::Host,
) {
    use crate::failover::reconcile::{Reconciler, StandbyGate};
    use crate::failover::standbys::{Population, Zone, tests::roomy};
    use crate::storage::store::sim::{AsReconciler, MemLog};
    let client =
        crate::storage::store::Client::open(AsReconciler(store.clone()), MemLog::default());
    let mut reconciler = Reconciler::new(client.unwrap());
    let gate = StandbyGate::qualified();
    let bounds = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
    let shard = crate::storage::store_tests::shard();
    let slot = reconciler
        .reserve(
            &gate,
            &Population { cap: 1 },
            &bounds,
            Zone(1),
            shard,
            &roomy(host),
            |_| None,
            |h| h != host,
        )
        .expect("the census reserves the slot");
    let active = record_of(store).active;
    let designated = reconciler.designate(&gate, &slot, active);
    designated.expect("the designation passes serving on the owner's ended entry");
}

/// The volume record the store holds for the warm volume.
fn volume_of(store: &crate::storage::store::sim::Shared) -> crate::failover::records::VolumeRecord {
    use crate::failover::records::Record;
    let key = crate::storage::store::Key::Volume(crate::failover::restart::tests::volume_id());
    let item = store.0.borrow().current(&key).cloned().unwrap();
    crate::failover::records::VolumeRecord::decode(&item.value).unwrap()
}

/// The reclaim's store: its first write of a volume record is issued and parked in [`PARKED_END`] while `during`
/// runs, and returns the outcome the store gave it when [`Answer::EndedFirst`] committed it inside `during`. Every
/// other request passes through.
struct Parking {
    inner: crate::storage::store::sim::Shared,
    during: Option<Box<dyn FnOnce()>>,
}

impl crate::storage::store::Store for Parking {
    fn read(
        &mut self,
        key: &crate::storage::store::Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        self.inner.read(key)
    }

    fn write(
        &mut self,
        key: &crate::storage::store::Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        let volume = matches!(key, crate::storage::store::Key::Volume(_));
        match self.during.take().filter(|_| volume) {
            Some(during) => {
                PARKED_END.with(|cell| *cell.borrow_mut() = Some((*key, write.clone())));
                during();
                END_OUTCOME
                    .with(Cell::take)
                    .expect("the parked end write committed during the transfer")
            }
            None => self.inner.write(key, write),
        }
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// What the history of [`ended_between_the_transfer_s_requests`] left.
struct EndedTarget {
    /// The reclaim's witness of its end write.
    ended: crate::failover::reconcile::AttachEnded,
    /// The outgoing owner's tenure.
    left: Requested,
}

/// The history the transfer's two requests admit, each write through production code but
/// the two designations, which are the fixtures' raw designation write. B is attached and enrolled beside A and C,
/// and the shard record names B standby. The reclaim ([`Reconciler::end_attach`]) reads the shard record, which
/// names B, and the volume record, and issues its end of C's attach. While that write is in flight the shard record
/// comes to name C standby, the owner A accepts a transfer to C, drains, certifies and withdraws, and its transfer
/// job reads the volume record, which still shows C's live, enrolled attach. The end then commits, and the
/// transfer's write commits after it.
///
/// [`Reconciler::end_attach`]: crate::failover::reconcile::Reconciler::end_attach
fn ended_between_the_transfer_s_requests() -> EndedTarget {
    use crate::failover::reconcile::{Reconciler, StandbyGate};
    use crate::failover::takeover::tests::{b_host, c_host, designate};
    let volume = warm();
    let store = volume.0.clone();
    enroll_b(&store);
    key_c_attach(&store);
    designate(&store, Some(b_host()));
    let slot = Rc::new(std::cell::RefCell::new(None));
    let (filled, designated) = (slot.clone(), store.clone());
    let during = move || {
        designate(&designated, Some(c_host()));
        let left = requested(
            (volume, transfer_request, at_open),
            Answer::EndedFirst,
            super::roll_tests::deadline(),
            |_| {},
        );
        *filled.borrow_mut() = Some(left);
    };
    let parking = Parking {
        inner: store.clone(),
        during: Some(Box::new(during)),
    };
    let client =
        crate::storage::store::Client::open(parking, crate::storage::store::sim::MemLog::default())
            .unwrap();
    let active = record_of(&store).active;
    let seq = volume_of(&store)
        .live(c_host())
        .expect("C holds a live attach");
    let ended = Reconciler::new(client)
        .end_attach(
            &StandbyGate::qualified(),
            crate::storage::store_tests::shard(),
            active,
            c_host(),
            seq,
        )
        .expect("the reclaim's end write commits");
    let left = slot.borrow_mut().take().expect("the owner's tenure ran");
    EndedTarget { ended, left }
}

/// The third host B's takeover of the tenure the record names, through a fencer on the reservation table the
/// outgoing owner left: its result, and the reservation commands it issued.
fn third_takes_over(
    left: &Requested,
) -> (
    Result<(), crate::failover::takeover::Refused>,
    Vec<&'static str>,
) {
    third_takes_over_on(&left.volume, &left.registry)
}

/// [`third_takes_over`] over `volume` and the reservation table `registry`.
fn third_takes_over_on(
    volume: &Volume,
    registry: &crate::storage::gate_fixture::Control,
) -> (
    Result<(), crate::failover::takeover::Refused>,
    Vec<&'static str>,
) {
    use crate::failover::takeover::tests::{b_host, b_pair, stored_b, takeover_of};
    let before = crate::host::fencer_tests::commands(registry).len();
    let (disk, _control) = crate::host::serve::tests::host_over(registry, &volume.1, b_pair());
    let arena = crate::storage::gate_fixture::arena_with(16, 9);
    let clock = crate::storage::gate_fixture::Ticking::default();
    let mut fencer = crate::host::fencer_tests::fencer_of(disk, b_pair(), &arena, &clock);
    let taken = takeover_of(&volume.0, b_host())
        .run(
            &mut crate::storage::store_tests::client(&volume.0),
            &stored_b(),
            &mut fencer,
        )
        .map(drop);
    let issued = crate::host::fencer_tests::commands(registry)[before..].to_vec();
    (taken, issued)
}

/// ENDED-GRANTS-NOTHING across the transfer's two requests: an end of the target's attach
/// that commits after the transfer job's volume read and before its shard write is not refused, and the committed
/// record names the ended target C owner at `E + 1` with no standby. C gets no tenure from it: its restart refuses
/// `Local(Ended)` at its record reads, issues no device command, requests no flip and parks. The volume and its
/// generation stay, C's pair stays recorded, and the detach witness refuses while it is. The shard gets an owner
/// again by the ordinary standby path over C's tenure: a designation of the attached, enrolled third host B, and
/// B's takeover, whose step 1 admits C's pair on its ended entry and whose Report #1 admits the reservation the
/// outgoing owner A still holds. B's tenure then serves every object A held.
///
/// Control: with C's pair gone from the record, as an end that dropped the pair it ends would leave it, B's
/// takeover refuses at step 1 with no write and no device command, and the shard keeps no path to an owner.
#[test]
fn an_attach_end_between_the_transfer_s_two_requests_names_the_ended_target_and_a_third_host_takes_over()
 {
    use super::step_tests::{Choices, Reached, run_cycle_as, warm_objects};
    use crate::failover::reconcile::{ReconcileError, Reconciler};
    use crate::failover::records::{EventKind, Record, VolumeState};
    use crate::failover::restart::{Check, Local};
    use crate::failover::takeover::tests::{b_host, c_host, designate};
    use crate::host::recover::Recovery;
    use crate::host::{Refusal, recover_tests::Identity};
    let before = record_of(&warm().0);
    for dropped in [false, true] {
        let EndedTarget { ended, left } = ended_between_the_transfer_s_requests();
        let store = left.volume.0.clone();
        let label = format!("pair dropped {dropped}");

        // The transfer committed over the end, and the reclaim's witness reports the name it read after its write.
        assert_eq!(left.exit, Exit::Stopped, "{label}");
        assert!(ended.named(), "{label}: the reclaim read the target named");
        let kept = |record: &ShardRecord| (record.generation, record.active);
        assert_eq!(kept(&left.record), kept(&before), "{label}");
        assert_eq!(
            (left.record.owner, left.record.standby, left.record.attempts),
            (c_host(), None, before.attempts + 2),
            "{label}: the record names the ended target"
        );
        let volume = volume_of(&store);
        let (_, latest) = volume.latest(c_host()).expect("C's entry");
        assert_eq!(latest.kind, EventKind::Ended, "{label}");
        assert!(volume.live(c_host()).is_none(), "{label}");
        assert!(
            volume
                .pairs
                .iter()
                .any(|recorded| recorded.host == c_host()),
            "{label}: the end keeps C's pair recorded"
        );
        assert_eq!(volume.state, VolumeState::Active, "{label}");

        // C's restart: its own entry is ended, so it refuses at its record reads and parks.
        let commands = crate::host::fencer_tests::commands(&left.registry).len();
        let standby = Identity::standby();
        let (disk, _control) =
            crate::host::serve::tests::host_over(&left.registry, &left.volume.1, standby.pair);
        let arena = crate::storage::gate_fixture::arena_with(16, 9);
        let clock = crate::storage::gate_fixture::Ticking::default();
        let recovery = crate::host::recover_tests::restarted_as(
            standby,
            &store,
            (disk, &arena, &clock),
            Box::new(crate::storage::gate_fixture::ZeroClock),
        );
        let exit = match recovery {
            Recovery::Ended(ended) => ended.exit,
            Recovery::Tenure(_) => panic!("{label}: an ended attach acquired a tenure"),
            Recovery::Waits => panic!("{label}: the record names C owner"),
        };
        assert_eq!(
            exit,
            Exit::Refused(Refusal::Restart(Check::Local(Local::Ended))),
            "{label}"
        );
        assert!(exit.parks(), "{label}");
        assert_eq!(
            crate::host::fencer_tests::commands(&left.registry).len(),
            commands,
            "{label}: C issued no reservation command"
        );
        assert_eq!(record_of(&store), left.record, "{label}: C wrote nothing");

        // DETACH-AFTER-DROP: C's attachment stays attached while its pair is recorded.
        let mut reclaim = Reconciler::new(crate::storage::store_tests::client(&store));
        assert_eq!(
            reclaim.detachable(volume.volume, c_host()).map(drop),
            Err(ReconcileError::Conflict),
            "{label}"
        );

        if dropped {
            // The control: the record as an end that dropped the ended pair would leave it.
            let key = crate::storage::store::Key::Volume(volume.volume);
            let item = store.0.borrow().current(&key).cloned().unwrap();
            let mut record = volume.clone();
            record.pairs.retain(|recorded| recorded.host != c_host());
            let write = crate::storage::store::Write::Exact {
                expect: item.version,
                value: record.encode(),
            };
            let _ = crate::storage::store::Store::write(&mut store.clone(), &key, &write);
        }

        // The reconciler's designation of the attached, enrolled third host over C's tenure, through its census
        // reservation and `Reconciler::designate`, whose `serving` check admits C's pair on its ended entry; then
        // B's takeover. In the control the same check refuses, with C's pair gone, and the fixture's raw write
        // designates B so the takeover's own refusal shows.
        if dropped {
            designate(&store, Some(b_host()));
        } else {
            designate_through_the_reconciler(&store, b_host());
        }
        let (taken, issued) = third_takes_over(&left);
        if dropped {
            let refused = taken.expect_err("control: no pair recorded for the predecessor");
            assert!(issued.is_empty(), "control: {issued:?}");
            assert_eq!(
                record_of(&store).owner,
                c_host(),
                "control: the takeover wrote nothing: {refused:?}"
            );
            continue;
        }
        taken.unwrap_or_else(|refused| panic!("B's takeover refused {refused:?}"));
        assert_eq!(
            issued,
            ["report", "register", "lineage", "report"],
            "B registered and preempted the reservation the outgoing owner still held"
        );
        let taken = record_of(&store);
        assert_eq!(kept(&taken), kept(&before), "no flip and no new generation");
        assert_eq!(
            (taken.owner, taken.standby, taken.attempts),
            (b_host(), None, before.attempts + 3)
        );
        assert_eq!(volume_of(&store).state, VolumeState::Active);
        let mut held = warm_objects();
        let (mut choices, mut reached) = (Choices::of(1), Reached::default());
        crate::host::serve::tests::inline(|| {
            run_cycle_as(
                (Identity::third(), left.registry.clone()),
                left.volume.clone(),
                (&mut held, &mut choices, &mut reached),
                None,
            )
            .map(drop)
        })
        .unwrap_or_else(|failure| panic!("B's tenure: {failure}"));
        assert_eq!(record_of(&store).owner, b_host());
    }
}

/// One seed's handoff to a target whose host is lost after the committed transfer and before its device steps:
/// the owner A serves the warm objects, mutates, accepts a transfer to its named
/// standby C and transfers. C never runs. The reconciler's designation names the attached, enrolled third host B
/// standby over C's tenure, B takes the shard over, and B's next tenure serves exactly the objects A acknowledged.
/// With `released`, A's registration is removed at its exit, as a release by the predecessor would remove it.
/// Returns the records before A's tenure, after its transfer and after B's tenure, or the first step that failed.
fn handed_to_a_lost_target(seed: u64, released: bool) -> Result<[ShardRecord; 3], String> {
    use super::roll_tests::Trigger;
    use super::step_tests::{Choices, Reached, run_cycle_as, warm_objects};
    use crate::failover::takeover::tests::{b_host, designate};
    use crate::host::recover_tests::Identity;
    let volume = crate::host::serve::tests::warm_volume_certified(0);
    enroll_b(&volume.0);
    let before = record_of(&volume.0);
    let registry = own_alone();
    let mut held = warm_objects();
    let (mut choices, mut reached) = (Choices::of(seed), Reached::default());
    crate::host::serve::tests::inline(|| {
        let (volume, _, _) = run_cycle_as(
            (Identity::owner(), registry.clone()),
            volume,
            (&mut held, &mut choices, &mut reached),
            Some(Trigger::Transfer),
        )?;
        let handed = record_of(&volume.0);
        if released {
            registry.borrow_mut().entries.clear();
        }
        designate(&volume.0, Some(b_host()));
        let (taken, issued) = third_takes_over_on(&volume, &registry);
        taken.map_err(|refused| {
            format!("B's takeover refused {refused:?} after the commands {issued:?}")
        })?;
        if issued != ["report", "register", "lineage", "report"] {
            return Err(format!("B's takeover issued {issued:?}"));
        }
        let (volume, _, _) = run_cycle_as(
            (Identity::third(), registry.clone()),
            volume,
            (&mut held, &mut choices, &mut reached),
            None,
        )?;
        Ok([before, handed, record_of(&volume.0)])
    })
}

/// HOST-LOSS-KEEPS-VOLUME and `HandoffCutIsExact` after the target's loss: the transfer leaves the record naming C
/// owner at A's `E + 1` with no standby; with C's host lost before any of its device steps, a designated third
/// host's takeover commits at `E + 2` over C's tenure, preempts the reservation A still holds, and its tenure
/// serves every FILL and INVALIDATE A acknowledged, on the same generation and the same active volume.
///
/// Control (`release-by-predecessor` for the third host): with A's registration removed at its exit, nobody holds
/// at B's Report #1 and its takeover refuses with no Register and no preempt.
#[test]
fn a_target_lost_after_the_committed_transfer_is_succeeded_warm_by_a_designated_third_host() {
    use crate::failover::takeover::tests::{b_host, c_host};
    for seed in [3, 7] {
        let [before, handed, after] =
            handed_to_a_lost_target(seed, false).unwrap_or_else(|failure| panic!("{failure}"));
        let kept = |record: &ShardRecord| (record.generation, record.active);
        assert_eq!(kept(&handed), kept(&before), "seed {seed}");
        assert_eq!(
            (handed.owner, handed.standby, handed.attempts),
            (c_host(), None, before.attempts + 2),
            "seed {seed}: A's restart bumped once and its transfer consumed the next E"
        );
        assert_eq!(kept(&after), kept(&before), "seed {seed}: no flip");
        assert_eq!(
            (after.owner, after.attempts),
            (b_host(), handed.attempts + 2),
            "seed {seed}: B's takeover and its next tenure's bump"
        );
    }
    let failure = handed_to_a_lost_target(3, true)
        .expect_err("control: nobody holds the reservation at B's Report #1");
    assert!(
        failure.contains("Holder(Unresolved)")
            && failure.contains("after the commands [\"report\"]"),
        "{failure}"
    );
}

/// A transfer after a published wire fill whose first PUT RESULT the transport took and the link then lost
/// (the case RESULT-BEFORE-WITHDRAWAL leaves). The client of the owner's stage uploads an empty
/// object over the wire; once it holds the owner's READY the link toward it loses every datagram when `lost`, so the
/// result the owner sends, and each replay the client's resent PREPARE asks for, never arrives. The owner then
/// receives a transfer request, which no queued result holds, and transfers the shard to C. The client's rounds run
/// on after the owner stopped until its upload settles. A second stage runs C's restart and tenure over the same
/// store, media and reservation table, with a second client of the same peer and boot nonce on C's own link: a GET
/// of the uploaded key, then a PUT of the same key and version, the application's retry.
///
/// Returns each check that failed: the transfer completes naming C; the old upload settles `Unknown` when the
/// result was lost and `Published` when the link stayed whole, the sibling; at C the GET hits, C holds no queued
/// result until the retry publishes its own, and the retry's outcome is `Published` in C's session.
fn transfer_after_a_lost_put_result(lost: bool) -> Vec<String> {
    use super::step_tests::{NEVER, STEP_US, step_duties_for, step_duties_on};
    use crate::failover::planned::ExitKind;
    use crate::net::link::Faults;
    use crate::net::{Outcome as Fetched, SessionState, UploadOutcome};
    use crate::storage::CacheVersion;
    use std::cell::RefCell;
    use std::sync::atomic::Ordering;

    const FILLED: u8 = 200;
    let round = crate::host::serve::loop_tests::ROUND_US;
    super::roll_tests::reset();
    let failures = RefCell::new(Vec::<String>::new());
    let fail = |failure: String| failures.borrow_mut().push(failure);
    let losing = Faults {
        loss: 100,
        ..Faults::default()
    };
    let before = record_of(&warm().0);
    let (exit, record, settled, volume, registry) = crate::host::serve::loop_tests::staged_over_on(
        warm(),
        own_alone(),
        || crate::storage::warm_sim::storage(1),
        |mut stage| {
            let policy = Some(super::capture_tests::policy_every(NEVER));
            let mut duties = step_duties_on(&stage, stage.store.clone(), policy, STEP_US)
                .requesting(key(), super::roll_tests::deadline());
            let storage = stage.storage;
            let upload = Cell::new(None);
            let prepared = Cell::new(false);
            let (mut published, mut handed, mut requested) = (false, false, false);
            let mut reader = storage.register().expect("a registration");
            let (served, _) = stage.serve_until(
                |rounds, turn, _| {
                    let now = turn * round;
                    let mut client = rounds.client.borrow_mut();
                    if upload.get().is_none() && client.state() == SessionState::Active {
                        let key = crate::storage::warm_sim::object_key(FILLED);
                        upload.set(client.put(key, CacheVersion(0), now, 30_000_000).ok());
                    }
                    if let Some(id) = upload.get()
                        && !prepared.get()
                        && client.prepare(id, 0, 0, 60_000).is_ok()
                    {
                        prepared.set(true);
                        if lost {
                            rounds.fault_toward_client(losing);
                        }
                    }
                },
                |owner, now| {
                    crate::storage::owner_fixture::set_clock(
                        storage,
                        &[Some(super::capture::nanos(now))],
                    );
                    // The fill published once the index serves its key, and its result was handed to the
                    // transport once no first-time result waits in the reply rings on a later turn.
                    handed |= published && !owner.put_results_queued();
                    let key = crate::storage::warm_sim::object_key(FILLED);
                    let mut budget = crate::storage::WorkBudget::new(1 << 16);
                    published |= reader.lookup(&key, 4, &mut budget).is_ok();
                    if handed
                        && !requested
                        && duties.open() == super::Open::Opened
                        && let Some(read) = duties.read.as_ref()
                    {
                        duties.deliver(&transfer_request(read.value()));
                        requested = true;
                    }
                    duties.turn(owner, now)
                },
            );
            if !handed || !requested {
                fail(format!(
                    "premise: the fill published {published}, its result was handed to the transport \
                         {handed}, and the transfer was requested {requested}"
                ));
            }
            // The owner stopped; the client polls on until its resends run out or the result it holds settles
            // the upload.
            let mut settled = None;
            for _ in 0..4_000 {
                settled =
                    (upload.get()).and_then(|id| stage.rounds.client.borrow().put_outcome(id));
                if settled.is_some() {
                    break;
                }
                stage.rounds.round();
            }
            (
                served.exit,
                record_of(&stage.store),
                settled,
                (stage.store.clone(), stage.media.clone()),
                stage.registry.clone(),
            )
        },
    );
    let c = crate::failover::takeover::tests::c_host();
    let started = super::roll_tests::started_kind();
    if started != Some(ExitKind::Transfer { target: c })
        || exit != Exit::Stopped
        || (record.owner, record.standby, record.attempts) != (c, None, before.attempts + 2)
    {
        fail(format!(
            "the transfer: started {started:?}, ended {exit:?}, the record names {:?} at E = {}",
            record.owner, record.attempts
        ));
    }
    let expected = match lost {
        true => UploadOutcome::Unknown,
        false => UploadOutcome::Published,
    };
    if settled != Some(expected) {
        fail(format!(
            "the upload whose result was lost: {lost} settled {settled:?}"
        ));
    }
    // The target: C's restart through its lineage arm, then its tenure with a client of the same peer.
    let identity = crate::host::recover_tests::Identity::standby();
    crate::host::serve::tests::inline(|| {
        crate::host::serve::loop_tests::staged_restart_as(
            identity,
            (volume, registry),
            |mut stage| {
                let policy = Some(super::capture_tests::policy_every(NEVER));
                let mut duties = step_duties_for(&stage, policy, identity.host);
                let storage = stage.storage;
                let (mut got, mut hit) = (None, None::<Fetched>);
                let (mut retry, mut retried) = (None, None::<UploadOutcome>);
                let (mut prepared, mut early) = (false, false);
                let done = Cell::new(false);
                let begun = Cell::new(false);
                stage.serve_until(
                    |rounds, turn, stop| {
                        let now = turn * round;
                        if rounds.client.borrow().state() != SessionState::Active {
                            return;
                        }
                        if got.is_none() {
                            got = rounds.try_get(FILLED).ok();
                        }
                        if let Some(id) = got
                            && hit.is_none()
                        {
                            hit = rounds.fetched(id, &mut Vec::new());
                        }
                        let mut client = rounds.client.borrow_mut();
                        if hit.is_some() && retry.is_none() {
                            let key = crate::storage::warm_sim::object_key(FILLED);
                            retry = client.put(key, CacheVersion(0), now, 30_000_000).ok();
                            begun.set(retry.is_some());
                        }
                        if let Some(id) = retry {
                            prepared = prepared || client.prepare(id, 0, 0, 60_000).is_ok();
                            retried = client.put_outcome(id);
                        }
                        if retried.is_some() || turn > 6_000 {
                            done.set(true);
                            stop.store(true, Ordering::Release);
                        }
                    },
                    |owner, now| {
                        crate::storage::owner_fixture::set_clock(
                            storage,
                            &[Some(super::capture::nanos(now))],
                        );
                        early |= !begun.get() && owner.put_results_queued();
                        duties.turn(owner, now)
                    },
                );
                if hit != Some(Fetched::Complete) {
                    fail(format!(
                        "the GET of the uploaded key at the target ended {hit:?}"
                    ));
                }
                if early {
                    fail("the target queued a PUT RESULT before any PUT of its own session".into());
                }
                if retried != Some(UploadOutcome::Published) {
                    fail(format!("the retry at the target settled {retried:?}"));
                }
            },
        )
    });
    failures.into_inner()
}

/// The limit of RESULT-BEFORE-WITHDRAWAL, over the wire: a published fill's first PUT RESULT
/// that the transport took and the link lost holds no transfer, and the client's upload settles `Unknown`, never
/// `Published` and never a failure. The object is in the cut: a GET at the target hits. The target holds no result
/// of the old session to replay, so the retry, a PUT of the same key and version in the target's session, settles
/// by its own publication. The sibling with a whole link settles the same upload `Published` before the transfer.
///
/// The layer: one client drives the PUT over the wire at the outgoing owner, and a second client of the same peer
/// and boot nonce drives the GET and the retry over the wire at the target; the staged harness holds one owner and
/// one client for each stage, so no single client object spans both hosts.
#[test]
fn a_put_result_lost_before_the_transfer_leaves_the_upload_unknown_and_the_object_served_by_the_target()
 {
    for lost in [true, false] {
        let failures = transfer_after_a_lost_put_result(lost);
        assert!(failures.is_empty(), "lost {lost}: {failures:#?}");
    }
}

/// ONE-LEDGER at the driver: only a request the ledger accepts starts an exit. A transfer sealed for the tenure's
/// earlier `E` binds `Stale` and starts no machine, enters no drain stage and records no exit, under a cap that
/// would let it drain. After a restart request resumed `standby` over a record naming no standby, the same request
/// delivered again binds `Repeat` and a new operation under an earlier sequence binds `LowSequence`; neither starts
/// a second machine, and `E` stays.
#[test]
fn a_request_the_ledger_refuses_starts_no_exit() {
    use crate::failover::report::{ExitStatus, Resume};
    let before = record_of(&warm().0);
    let stale: Request = |record| {
        let earlier = ShardRecord {
            attempts: record.attempts - 1,
            ..*record
        };
        transfer_request(&earlier)
    };
    let left = with_cell(&STOP_AT, Some(600), || {
        requested(
            (warm(), stale, at_open),
            Answer::Commit,
            super::roll_tests::deadline(),
            |_| {},
        )
    });
    assert_eq!(bindings(), [Binding::Stale]);
    assert_eq!(super::roll_tests::starts(), 0, "no machine started");
    assert_eq!(
        (left.started, left.resumed, left.status),
        (None, None, None)
    );
    assert!(!left.drained && left.exit == Exit::Stopped);
    assert_eq!(
        (left.record.owner, left.record.attempts),
        (before.owner, before.attempts + 1)
    );

    let unnamed = warm();
    crate::failover::takeover::tests::designate(&unnamed.0, None);
    let mut again = false;
    let left = requested_with(
        (unnamed, restart_request, at_open),
        Answer::Commit,
        Built::BOTH,
        super::roll_tests::deadline(),
        |_| {},
        |slot| {
            if !again && super::roll_tests::resumed_reason().is_some() {
                let duties = slot.as_mut().unwrap();
                let record = *duties.read.as_ref().unwrap().value();
                duties.deliver(&restart_request(&record));
                let mut early = PlannedRequest {
                    kind: Kind::Restart,
                    operation: ExitOperation::new([9; 16]).unwrap(),
                    sequence: Sequence::of(1, 0),
                    shard: record.shard,
                    generation: record.generation,
                    attempts: record.attempts,
                    owner: record.owner,
                    deadline_us: NonZeroU32::new(u32::MAX).unwrap(),
                };
                duties.deliver(&encode(&early, &key()));
                early.sequence = Sequence::of(1, 1);
                duties.deliver(&encode(&early, &key()));
                again = true;
            }
        },
    );
    assert!(again, "the first request resumed");
    assert_eq!(
        bindings(),
        [
            Binding::Accept,
            Binding::Repeat,
            Binding::LowSequence,
            Binding::LowSequence
        ]
    );
    assert_eq!(
        super::roll_tests::starts(),
        1,
        "only the accepted request started a machine"
    );
    assert_eq!(left.status, Some(ExitStatus::Resumed(Resume::Standby)));
    assert_eq!(left.record.attempts, before.attempts + 1);
}

/// A control plane that counts its listings and lists the owner's and the standby's attachments.
struct CountedPlane(std::sync::Arc<std::sync::atomic::AtomicU32>);

impl crate::failover::attachments::ControlPlane for CountedPlane {
    fn attachments(
        &mut self,
        _: &crate::failover::records::VolumeId,
    ) -> Result<Vec<String>, crate::failover::attachments::Unlisted> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(super::view_tests::clean_listing())
    }
}

/// TRANSFER-OFF-POLL's wait gate, both halves: while the withdrawn owner's transfer waits on the lane, the duties
/// submit no View and no Listing, though both periods are due on every held turn. The tenure lists while it serves,
/// so the plane is installed, and the transfer then commits and ends the incarnation `Stopped`.
#[test]
fn no_view_and_no_listing_is_submitted_while_the_transfer_waits_on_the_lane() {
    use std::sync::atomic::Ordering;
    let listings = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let (installed, counted) = (listings.clone(), listings.clone());
    let held_listings = Cell::new(None::<(u32, u32)>);
    let left = holding(HELD_TURNS, || {
        requested_with(
            (warm(), transfer_request, at_open),
            Answer::Commit,
            Built::BOTH,
            super::roll_tests::deadline(),
            |slot| {
                let plane = crate::host::lane::Plane(Box::new(CountedPlane(installed)));
                slot.as_mut().unwrap().plane = Some(plane);
            },
            |slot| {
                let duties = slot.as_mut().unwrap();
                if duties.lane.inline_mut().held() > 0 {
                    // Both periods are due on this turn.
                    (duties.view_at, duties.listing_at) = (0, 0);
                    let now = counted.load(Ordering::Relaxed);
                    let (first, _) = held_listings.get().unwrap_or((now, now));
                    held_listings.set(Some((first, now)));
                }
            },
        )
    });
    assert_eq!(left.exit, Exit::Stopped);
    assert_eq!(left.held, (HELD_TURNS, true));
    assert!(
        listings.load(Ordering::Relaxed) > 0,
        "premise: the serving tenure listed its attachments"
    );
    let (first, last) = held_listings
        .get()
        .expect("the transfer's completion was held");
    assert_eq!(
        last, first,
        "no Listing is submitted ahead of the waiting transfer"
    );
    assert_eq!(
        left.views_while_held, 0,
        "no View is submitted ahead of the waiting transfer"
    );
}

/// TRANSFER-OFF-POLL's fallback with no write issued: a tenure that reaches its withdrawal with the standby gate
/// away withdraws for `Cause::Planned`, closes, submits no transfer and records no handoff, and ends in its one
/// same-host restart with the exit restarting for a refused transfer. The record keeps the tenure and its standby,
/// and the owner issues no reservation command from the withdrawal on.
#[test]
fn a_withdrawal_with_no_gate_issues_no_transfer_and_restarts_once() {
    use crate::failover::planned::State;
    use crate::failover::report::{ExitStatus, Restart};
    let before = record_of(&warm().0);
    let mut taken = false;
    let left = requested_with(
        (warm(), transfer_request, at_open),
        Answer::Commit,
        Built::BOTH,
        super::roll_tests::deadline(),
        |_| {},
        |slot| {
            let duties = slot.as_mut().unwrap();
            if !taken && duties.planned_state() == Some(State::Sealed) {
                taken = duties.standby.take().is_some();
            }
        },
    );
    assert!(taken, "the drain reached its seal with the gate home");
    assert_eq!(left.exit, Exit::Rerun(crate::host::Rerun::Planned));
    assert_eq!(
        left.status,
        Some(ExitStatus::Restarting(Restart::TransferRefused))
    );
    assert_eq!(left.transfer_entry, None, "no handoff was recorded");
    assert_eq!(
        (left.record.owner, left.record.standby, left.record.attempts),
        (before.owner, before.standby, before.attempts + 1),
        "no transfer was written"
    );
    assert_eq!(
        (left.commands_after, left.medium_after, left.sends_after),
        (Some(0), Some(0), Some(0))
    );
}

/// The owner's one request intake through the link: duties built with both `linked` and `requesting` take the
/// requests the inbox delivered, in delivery order, at the start of the turn. A forged request, the authentic bytes
/// with one tag bit flipped, delivered ahead of the authentic one hides nothing: the authentic request binds
/// `Accept` and transfers the shard, the forged one binds nothing, and `take_request` holds no request, since the
/// duties took both.
#[test]
fn linked_duties_take_each_request_the_inbox_delivered_and_a_forged_one_hides_nothing() {
    use crate::host::link::{Inbound, Link, Request as Delivered};
    let link: &'static Link = Box::leak(Box::default());
    let mut sent = false;
    let left = requested_with(
        (warm(), transfer_request, |_| false),
        Answer::Commit,
        Built::BOTH,
        super::roll_tests::deadline(),
        |slot| {
            let duties = slot.take().unwrap().linked(super::Linked {
                link,
                pid: 7,
                status_us: super::tests::TEST_VIEW_US,
                recovery: Some(crate::failover::report::RecoveryStatus::NO_ATTEMPT),
            });
            *slot = Some(duties);
        },
        |slot| {
            let duties = slot.as_mut().unwrap();
            if sent || duties.open() != super::Open::Opened {
                return;
            }
            let Some(read) = duties.read.as_ref() else {
                return;
            };
            let authentic = transfer_request(read.value());
            let mut forged = authentic.clone();
            *forged.last_mut().unwrap() ^= 1;
            for bytes in [forged, authentic] {
                let request = Delivered::new(&bytes).expect("a request of the wire length");
                assert!(link.inbox.deliver(Inbound::Request(request)));
            }
            sent = true;
            assert_eq!(duties.take_request(), None);
        },
    );
    assert!(sent, "the tenure opened");
    assert_eq!(bindings(), [Binding::Accept]);
    assert_eq!(left.exit, Exit::Stopped);
    assert_eq!(
        left.record.owner,
        crate::failover::takeover::tests::c_host(),
        "the delivered request transferred the shard"
    );
}

/// When the store applies the transfer write it parked, relative to the outgoing owner's next bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lands {
    /// After the next incarnation's step-1 shard read and before its bump.
    BeforeTheBump,
    /// After the next incarnation's acknowledged bump.
    AfterTheBump,
}

/// The store of the outgoing owner's next incarnation: its first shard-record write is the restart's bump, and the
/// parked transfer write of `inner` is released directly before or directly after it.
struct Releasing {
    inner: crate::storage::store::sim::Shared,
    lands: Option<Lands>,
    released: Rc<std::cell::RefCell<Vec<crate::storage::store::Outcome>>>,
}

impl crate::storage::store::Store for Releasing {
    fn read(
        &mut self,
        key: &crate::storage::store::Key,
    ) -> Result<Option<crate::storage::store::Item>, crate::storage::store::Unavailable> {
        self.inner.read(key)
    }

    fn write(
        &mut self,
        key: &crate::storage::store::Key,
        write: &crate::storage::store::Write,
    ) -> crate::storage::store::Outcome {
        let bump = matches!(key, crate::storage::store::Key::Shard(_));
        match self.lands.take_if(|_| bump) {
            Some(Lands::BeforeTheBump) => {
                *self.released.borrow_mut() = self.inner.release();
                self.inner.write(key, write)
            }
            Some(Lands::AfterTheBump) => {
                let outcome = self.inner.write(key, write);
                *self.released.borrow_mut() = self.inner.release();
                outcome
            }
            None => self.inner.write(key, write),
        }
    }

    fn namespace(&self) -> crate::failover::records::Namespace {
        self.inner.namespace()
    }
}

/// One owner after a parked transfer write (FP-HAND-07 at the hosts): the transfer's reply is lost with its write
/// still parked at the store, so the withdrawn owner reads its own tenure and ends in one same-host restart, the
/// record unchanged. The parked write then lands on one side of that restart's bump, and each host's real recovery
/// runs over the result. Landing before the bump, the transfer commits, the restart's bump fails its version
/// condition and holds with no command after Report #1, the target's restart activates through its lineage arm and
/// serves the cut, and the outgoing owner's next restart reads itself deposed. Landing after the acknowledged bump,
/// the transfer fails its condition, the outgoing owner's restart is the tenure, and the target's restart reads
/// itself deposed with no device command.
#[test]
fn a_parked_transfer_write_leaves_one_serving_host_on_either_side_of_the_owner_s_next_bump() {
    use super::step_tests::{Choices, Reached, cycle, warm_objects};
    use crate::failover::report::{ExitStatus, Restart};
    use crate::host::recover::Recovery;
    use crate::host::recover_tests::{Identity, restarted_as, restarted_over};
    use crate::storage::store::{Outcome, Refusal};
    let before = record_of(&warm().0);
    let c = crate::failover::takeover::tests::c_host();
    for lands in [Lands::BeforeTheBump, Lands::AfterTheBump] {
        let left = requested(
            (warm(), transfer_request, at_open),
            Answer::Parked,
            super::roll_tests::deadline(),
            |_| {},
        );
        let store = left.volume.0.clone();
        assert_eq!(
            left.exit,
            Exit::Rerun(crate::host::Rerun::Planned),
            "{lands:?}"
        );
        assert_eq!(
            left.status,
            Some(ExitStatus::Restarting(Restart::TransferUnknown)),
            "{lands:?}"
        );
        assert_eq!(
            (left.record.owner, left.record.standby, left.record.attempts),
            (before.owner, before.standby, before.attempts + 1),
            "{lands:?}: the transfer is parked"
        );
        assert_eq!(store.0.borrow().parked().len(), 1, "{lands:?}");

        // The outgoing owner's next incarnation, with the parked write landing beside its bump.
        let released = Rc::new(std::cell::RefCell::new(Vec::new()));
        let releasing = Releasing {
            inner: store.clone(),
            lands: Some(lands),
            released: released.clone(),
        };
        let owner = Identity::owner();
        let commands = crate::host::fencer_tests::commands(&left.registry).len();
        let (disk, _control) =
            crate::host::serve::tests::host_over(&left.registry, &left.volume.1, owner.pair);
        let arena = crate::storage::gate_fixture::arena_with(16, 9);
        let clock = crate::storage::gate_fixture::Ticking::default();
        let recovery = restarted_over(
            owner,
            releasing,
            (disk, &arena, &clock),
            Box::new(crate::storage::gate_fixture::ZeroClock),
        );
        let issued = crate::host::fencer_tests::commands(&left.registry)[commands..].to_vec();
        let restart_of = |identity: Identity| {
            let commands = crate::host::fencer_tests::commands(&left.registry).len();
            let (disk, _control) =
                crate::host::serve::tests::host_over(&left.registry, &left.volume.1, identity.pair);
            let arena = crate::storage::gate_fixture::arena_with(16, 9);
            let clock = crate::storage::gate_fixture::Ticking::default();
            let recovery = restarted_as(
                identity,
                &store,
                (disk, &arena, &clock),
                Box::new(crate::storage::gate_fixture::ZeroClock),
            );
            let exit = match recovery {
                Recovery::Ended(ended) => Some(ended.exit),
                Recovery::Tenure(_) => None,
                Recovery::Waits => panic!("a restart role waits"),
            };
            let issued = crate::host::fencer_tests::commands(&left.registry).len() - commands;
            (exit, issued)
        };
        match lands {
            Lands::BeforeTheBump => {
                assert!(
                    matches!(released.borrow()[..], [Outcome::Committed(_)]),
                    "the parked transfer committed: {:?}",
                    released.borrow()
                );
                let Recovery::Ended(ended) = recovery else {
                    panic!("the bump over the transferred record acquired a tenure");
                };
                assert!(
                    matches!(ended.exit, Exit::Held { .. }),
                    "the refused bump holds: {:?}",
                    ended.exit
                );
                assert_eq!(issued, ["report"], "no command after Report #1");
                drop(ended);
                let handed = record_of(&store);
                assert_eq!(
                    (handed.owner, handed.standby, handed.attempts),
                    (c, None, before.attempts + 2)
                );
                standby_serves(&left).unwrap_or_else(|failure| panic!("{failure}"));
                assert_eq!(record_of(&store).owner, c);
                let (exit, issued) = restart_of(owner);
                assert_eq!(
                    (exit, issued),
                    (Some(Exit::Deposed), 0),
                    "the outgoing owner reads itself deposed"
                );
            }
            Lands::AfterTheBump => {
                assert!(
                    matches!(
                        released.borrow()[..],
                        [Outcome::NotCommitted(Refusal::Condition)]
                    ),
                    "the parked transfer lost its condition: {:?}",
                    released.borrow()
                );
                let Recovery::Tenure(tenure) = recovery else {
                    panic!("the outgoing owner's restart acquired no tenure");
                };
                drop(tenure);
                let bumped = record_of(&store);
                assert_eq!(
                    (bumped.owner, bumped.standby, bumped.attempts),
                    (before.owner, before.standby, before.attempts + 2)
                );
                let (exit, issued) = restart_of(Identity::standby());
                assert_eq!(
                    (exit, issued),
                    (Some(Exit::Deposed), 0),
                    "the target reads another owner and issues no command"
                );
                let mut held = warm_objects();
                let (mut choices, mut reached) = (Choices::of(2), Reached::default());
                crate::host::serve::tests::inline(|| {
                    cycle(left.volume.clone(), &mut held, &mut choices, &mut reached)
                })
                .unwrap_or_else(|failure| panic!("the owner's tenure: {failure}"));
                assert_eq!(record_of(&store).owner, before.owner);
            }
        }
    }
}
