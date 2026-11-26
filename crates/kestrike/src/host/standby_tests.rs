use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::fencer::Release;
use super::fencer_tests::{
    commands, fencer_of, host as driver_of, shared_table, stop as stop_table,
};
use super::recover::{Role, Signals, stand_by};
use super::recover_tests::{UnwindsAfterSubmit, own_holds, reads_of, two_reads};
use super::wait_tests::keyed;
use super::{Exit, HostGate, Inputs, Rerun, role};
use crate::failover::admission::AdmissionError;
use crate::failover::assignment_tests::record as local_record;
use crate::failover::detect::host::Revalidated;
use crate::failover::fresh::tests::registrant;
use crate::failover::fresh::tests::store as store_with_spare;
use crate::failover::identity::Key as ReservationKey;
use crate::failover::reconcile::{Binding, Reconciler, StandbyGate};
use crate::failover::record::LocalRecord;
use crate::failover::records::{ERA, Host, ShardRecord, VolumeId};
use crate::failover::report::{RecoveryCheck, RecoveryNext};
use crate::failover::restart;
use crate::failover::restart::tests::{
    Stored, host as owner_host, own, shard_now, store, volume_id,
};
use crate::failover::retire::Target;
use crate::failover::takeover::tests::{
    b_host, bound_record, c_host, c_pair, d_host, designate, fence_page_zero, holder_of, holder_on,
    instance_of, rewrite, shard_record, stored_b, stored_c, successor_record, taken, volume_now,
    with_c, with_c_and_b,
};
use crate::storage::gate_fixture::Ticking;
use crate::storage::gate_fixture::{Control, ZeroClock, arena_with, bounds_of, limits};
use crate::storage::store::sim::{Arm, MemLog, Recorder, Shared};
use crate::storage::store::{Client, Key};
use crate::storage::store_tests::{client, shard};
use crate::storage::{Dropped, ServingClock};

/// A planted fault of the wait's publications, which a control runs a witness under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Plant {
    /// The wait publishes no status.
    Silent,
    /// The wait publishes each role read's status once and never again within a view period.
    Unrepeated,
}

thread_local! {
    static PLANT: Cell<Option<Plant>> = const { Cell::new(None) };
}

/// The plant set on this thread.
pub(super) fn plant() -> Option<Plant> {
    PLANT.with(Cell::get)
}

/// Runs `body` with `plant` set on this thread.
fn planted<R>(plant: Plant, body: impl FnOnce() -> R) -> R {
    PLANT.with(|cell| cell.set(Some(plant)));
    let result = body();
    PLANT.with(|cell| cell.set(None));
    result
}

/// D's local record, the record of a fresh host the reconciler attached: its key is the key of the attach entry
/// [`record_d`] appends to [`with_c`] (KEY-PER-ATTACH).
fn d_record() -> LocalRecord {
    let key = crate::failover::records::attachment_key(with_c().next).unwrap();
    successor_record(d_host(), key.encode(), 0x5d)
}

/// The persist of the unnamed arm, which receives D's attach key and returns D's record under it.
fn persist_d(key: ReservationKey) -> Result<LocalRecord, AdmissionError> {
    assert_eq!(key, d_record().pair().key, "the key of D's live attach");
    Ok(d_record())
}

/// The witness of a nomination of the stored record's `(g, owner, E)`, valid until 1,000.
fn witness_of(store: &Shared) -> Revalidated {
    Revalidated {
        shard: shard(),
        target: Target::of(&shard_now(store)),
        until_us: 1_000,
    }
}

/// What one run of `stand_by` did.
struct Stood {
    exit: Option<Exit>,
    /// The next step a status reads for the class of the takeover refusal the exit carries.
    class: Option<super::recover_tests::Class>,
    /// The target of the tenure the run returned.
    tenure: Option<Target>,
    /// What the fencer released: `driver`, `outstanding` or `unconnected`.
    device: &'static str,
    periods: u32,
    /// Every store request, as `(write, key)`.
    calls: Vec<(bool, Key)>,
    /// The store requests issued when each view period began.
    marks: Vec<usize>,
    /// The store requests issued when each `persist` call ran.
    persists: Vec<usize>,
}

impl Stood {
    /// The store requests of view period `period`, counted from 1.
    fn period(&self, period: usize) -> &[(bool, Key)] {
        let end = self.marks.get(period).copied().unwrap_or(self.calls.len());
        &self.calls[self.marks[period - 1]..end]
    }
}

/// One view period's script: its number, the stop flag, and the nomination to deliver in it.
type Script<'s> = &'s mut dyn FnMut(u32, &AtomicBool) -> Option<Revalidated>;

/// The host one `stand_by` run holds: its own local record, which the takeover reads and whose pair its driver
/// connects as, the reservation table, the clock nominations are read against, and a host the instance lookup
/// leaves unresolved.
struct Standby<'t> {
    host: Host,
    /// The volume the host is attached to.
    volume: VolumeId,
    local: LocalRecord,
    registry: &'t Control,
    now: &'t Cell<u64>,
    unresolved: Option<Host>,
    /// While set, the client's watermark log fails to record a raise.
    log_fails: Rc<Cell<bool>>,
    /// The fencer's clock; a ticking clock when `None`.
    clock: Option<&'t dyn ServingClock>,
    /// The fencer's state when the arm takes the fencer.
    fencer: Held,
    /// The link whose status cell the wait publishes to; a link of the run's own when `None`.
    link: Option<&'t super::Link>,
    /// The calls of the period signal that return before each view period passed, each after it advances `now` by
    /// the bound it was given.
    slices: u32,
    /// Runs at each call of the period signal with the bound it was given.
    on_wait: Option<&'t dyn Fn(u64)>,
    /// The detector window the wait is told; two status periods unless a case sets it.
    window_us: u64,
}

/// What a fencer holds before the arm's first view period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// The connect closure, before its first call.
    Nothing,
    /// The connected driver, before its first command.
    Driver,
    /// A table whose Report the device accepted and left pending.
    Report,
}

fn standby<'t>(
    host: Host,
    local: LocalRecord,
    registry: &'t Control,
    now: &'t Cell<u64>,
) -> Standby<'t> {
    Standby {
        host,
        volume: volume_id(),
        local,
        registry,
        now,
        unresolved: None,
        log_fails: Rc::default(),
        clock: None,
        fencer: Held::Nothing,
        link: None,
        slices: 0,
        on_wait: None,
        window_us: 2 * super::duties::STATUS_US,
    }
}

fn c_record() -> LocalRecord {
    stored_c().0.unwrap()
}

/// `stand_by` for `run`'s host over `store`. `script` runs at each view period and returns that period's
/// nomination. `persist` answers the unnamed arm.
fn stood(
    store: &Shared,
    run: &Standby<'_>,
    script: Script<'_>,
    persist: &dyn Fn(ReservationKey) -> Result<LocalRecord, AdmissionError>,
) -> Stood {
    let recorder = Recorder::new(store);
    let calls = RefCell::new(Vec::new());
    // The requests issued so far: those recorded before this call and those the recorder holds.
    let issued = || {
        calls.borrow_mut().extend(keyed(&recorder));
        calls.borrow().len()
    };
    let log = MemLog::default();
    let log_fails = log.fail.clone();
    let mut traced = Client::open(recorder.clone(), log).unwrap();
    let arena = arena_with(16, 9);
    let ticking = Ticking::default();
    let pair = run.local.pair();
    let (disk, control) = driver_of(run.registry, pair, 2);
    let mut fencer = fencer_of(disk, pair, &arena, run.clock.unwrap_or(&ticking));
    if run.fencer != Held::Nothing {
        restart::Device::start(&mut fencer).unwrap();
    }
    if run.fencer == Held::Report {
        restart::Device::ready(&mut fencer).unwrap();
        assert!(restart::Device::report(&mut fencer).is_err());
    }
    let stop = AtomicBool::new(false);
    let periods = Cell::new(0);
    let pending = Cell::new(None);
    let persists = RefCell::new(Vec::new());
    let marks = RefCell::new(Vec::new());
    let holder = holder_on(run.volume, run.host, instance_of(run.host));
    let own_link = super::Link::default();
    let link = run.link.unwrap_or(&own_link);
    let slice = Cell::new(0);
    let inputs = Inputs::new(shard(), holder, bounds_of(limits()), limits(), 4).unwrap();
    let recovery = stand_by(
        (&HostGate::qualified(), &StandbyGate::qualified()),
        (&inputs, &|peer| {
            (Some(peer) != run.unresolved).then(|| instance_of(peer))
        }),
        &mut traced,
        &Stored(Ok(run.local.clone())),
        |key| {
            persists.borrow_mut().push(issued());
            persist(key)
        },
        fencer,
        Box::new(ZeroClock),
        Signals {
            stop: &stop,
            period: |bound| {
                if let Some(on_wait) = run.on_wait {
                    on_wait(bound);
                }
                let sliced = slice.get();
                if sliced == 0 {
                    periods.set(periods.get() + 1);
                    assert!(periods.get() < 100, "the wait never ended");
                    marks.borrow_mut().push(issued());
                    // The slot keeps an unread witness; a send replaces it.
                    if let Some(witness) = script(periods.get(), &stop) {
                        pending.set(Some(witness));
                    }
                    log_fails.set(run.log_fails.get());
                }
                let passed = sliced == run.slices;
                slice.set(if passed { 0 } else { sliced + 1 });
                if !passed {
                    run.now.set(run.now.get() + bound);
                }
                passed
            },
            nominations: || pending.take(),
            now: || run.now.get(),
            status: &link.status,
            pid: 7,
            window_us: run.window_us,
        },
    );
    let (exit, tenure, device, class) = match recovery {
        Ok(tenure) => (
            None,
            Some(tenure.authority.session().target()),
            "driver",
            None,
        ),
        Err(ended) => (
            Some(ended.exit),
            None,
            match ended.device {
                Release::Unconnected => "unconnected",
                Release::Driver(_) => "driver",
                Release::Outstanding(table) => {
                    stop_table(table, &control);
                    "outstanding"
                }
            },
            super::recover_tests::class_of(ended.refusal),
        ),
    };
    // Only a takeover refusal that ends the incarnation carries a class; every other exit of the wait carries none.
    if exit != Some(Exit::Rerun(Rerun::Takeover)) {
        assert_eq!(class, None, "{exit:?} carries no refusal class");
    }
    Stood {
        exit,
        class,
        tenure,
        device,
        periods: periods.get(),
        calls: {
            issued();
            calls.into_inner()
        },
        marks: marks.into_inner(),
        persists: persists.into_inner(),
    }
}

/// A fault fixture: clears coverage page 0's fence by a raw exact-version write, which no record writer admits, so
/// the enrollment precondition refuses `Tenure` in a period and holds in a later one.
fn unfence_page_zero(store: &Shared) {
    use crate::failover::records::{CoveragePage, Record};
    use crate::storage::store::{Outcome, Store, Write};
    let key = Key::Page(shard(), 0);
    let item = store.0.borrow().current(&key).cloned().unwrap();
    let page = CoveragePage {
        fence: 0,
        ..CoveragePage::decode(&item.value).unwrap()
    };
    let write = Write::Exact {
        expect: item.version,
        value: page.encode(),
    };
    let mut raw = store.clone();
    assert!(matches!(
        Store::write(&mut raw, &key, &write),
        Outcome::Committed(_)
    ));
}

/// Records D's attach as a writer before BIND-AT-ATTACH did: an attach entry at `next` that binds no instance, in a
/// format-2 record, by an exact-version replace the successor check admits, so the judges admit D's live attach
/// only through a peer binding.
fn record_d_unbound(store: &Shared) {
    use crate::failover::records::{EventKind, VolumeRecord};
    let mut client = client(store);
    let read = client
        .read::<VolumeRecord>(Key::Volume(volume_id()))
        .unwrap();
    let mut next = read.value().clone();
    next.push(EventKind::Attach, d_host(), ERA).unwrap();
    client.replace(&read, next).unwrap();
}

fn no_persist(_: ReservationKey) -> Result<LocalRecord, AdmissionError> {
    panic!("the standby arm persists nothing")
}

fn writes(calls: &[(bool, Key)]) -> Vec<Key> {
    (calls.iter().filter(|(write, _)| *write))
        .map(|(_, key)| *key)
        .collect()
}

/// The two requests of a takeover's step 1: the shard read, which the compare-and-swap conditions on, then the
/// volume read. The role read takes the same two records in the other order.
fn step_one_reads() -> Vec<(bool, Key)> {
    vec![
        (false, Key::Shard(shard())),
        (false, Key::Volume(volume_id())),
    ]
}

fn standby_role(store: &Shared) -> Role {
    Role::Standby {
        target: Target::of(&shard_now(store)),
    }
}

/// NAMED-STANDBY: C waits one period with one role read. A witness of a stale target then starts a takeover that
/// refuses at step 1 and returns to the wait. A witness for C's shard and target arrives in a period whose role
/// read fails, stays pending, and starts one takeover through the fencer in the next period: Report, Register is
/// skipped for a registered pair, the lineage preempt and Report. The record then names C owner at `E + 1` with no
/// standby, and the arm returns the tenure and the driver.
#[test]
fn a_valid_witness_starts_one_takeover_that_ends_in_a_tenure() {
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let witness = witness_of(&store);
    let stale = Revalidated {
        target: Target {
            attempts: witness.target.attempts - 1,
            ..witness.target
        },
        ..witness
    };
    let armed = store.clone();
    let now = Cell::new(999);
    let stood = stood(
        &store,
        &standby(c_host(), c_record(), &registry, &now),
        &mut |period, _| match period {
            2 => Some(stale),
            3 => {
                armed.schedule(Arm::Unavailable);
                Some(witness)
            }
            _ => None,
        },
        &no_persist,
    );
    assert_eq!(stood.exit, None);
    assert_eq!(stood.periods, 4);
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
    assert_eq!(stood.tenure, Some(Target::of(&shard_now(&store))));
    assert_eq!(commands(&registry), ["report", "lineage", "report"]);
    assert_eq!(stood.period(1), two_reads());
    assert_eq!(
        stood.period(2),
        [two_reads(), step_one_reads()].concat(),
        "the stale step 1"
    );
    assert_eq!(stood.period(3), &two_reads()[..1], "the failed role read");
    let cas = writes(&stood.calls);
    let shard_writes = cas.iter().filter(|key| **key == Key::Shard(shard()));
    assert_eq!(shard_writes.count(), 1, "the one CAS: {cas:?}");
    assert_eq!(
        cas[0],
        Key::Shard(shard()),
        "the CAS precedes the page fences"
    );
    assert!(stood.persists.is_empty());
}

/// A standby with no nomination, with an expired witness, with a witness for another shard and with a witness of
/// a stale target issues one role read a period and the stale takeover's own step-1 reads, no write, no Register
/// and no device command, and stays in the wait until its stop request. The witness of period 2 expires in that
/// period: the clock reads 499 before it and 500, the witness's `until_us`, from it.
#[test]
fn a_waiting_standby_issues_no_write_and_no_device_command() {
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let fresh = witness_of(&store);
    let expired = Revalidated {
        until_us: 500,
        ..fresh
    };
    let elsewhere = Revalidated {
        shard: crate::net::ownership::Shard::new(shard().get() + 1).unwrap(),
        ..fresh
    };
    let stale = Revalidated {
        target: Target {
            attempts: fresh.target.attempts - 1,
            ..fresh.target
        },
        ..fresh
    };
    let now = Cell::new(499);
    let stood = stood(
        &store,
        &standby(c_host(), c_record(), &registry, &now),
        &mut |period, stop| match period {
            2 => {
                now.set(500);
                Some(expired)
            }
            3 => Some(elsewhere),
            4 => Some(stale),
            6 => {
                stop.store(true, Ordering::Release);
                None
            }
            _ => None,
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert_eq!(stood.device, "unconnected", "no device call");
    assert!(commands(&registry).is_empty());
    assert!(writes(&stood.calls).is_empty(), "{:?}", stood.calls);
    // Five role reads, and the two step-1 reads of the stale takeover in period 4, which refused `Stale`.
    let periods = [two_reads().repeat(4), step_one_reads(), two_reads()].concat();
    assert_eq!(stood.calls, periods);
    assert_eq!(stood.period(4), [two_reads(), step_one_reads()].concat());
    assert_eq!(shard_now(&store), shard_record());
}

/// CAS-BEFORE-DEVICE: a takeover write whose reply is lost ends the incarnation `Rerun(Takeover)` with no device
/// command. When the write did not commit the record still names the predecessor and the next role read is
/// `Standby`, so the nomination repeats; when it committed the next role read is `Restart`.
#[test]
fn an_unknown_takeover_write_reruns_with_no_device_command() {
    for commit in [false, true] {
        let store = store(shard_record(), with_c());
        let registry = own_holds();
        let witness = witness_of(&store);
        let armed = store.clone();
        let now = Cell::new(0);
        let stood = stood(
            &store,
            &standby(c_host(), c_record(), &registry, &now),
            &mut |_, _| {
                // The period's role read and the takeover's step-1 reads pass; its write times out.
                for arm in [Arm::Pass; 4] {
                    armed.schedule(arm);
                }
                armed.schedule(Arm::Timeout { commit });
                Some(witness)
            },
            &no_persist,
        );
        assert_eq!(stood.exit, Some(Exit::Rerun(Rerun::Takeover)), "{commit}");
        let class = Some((RecoveryCheck::TakeOver, RecoveryNext::Restart));
        assert_eq!(stood.class, class, "{commit}: the takeover refusal's class");
        assert_eq!(stood.periods, 1);
        assert!(stood.device == "unconnected" && commands(&registry).is_empty());
        assert_eq!(writes(&stood.calls), [Key::Shard(shard())], "the one CAS");
        let next = role(&mut client(&store), shard(), &holder_of(c_host()));
        let expected = if commit {
            Role::Restart
        } else {
            standby_role(&store)
        };
        assert_eq!(next, Ok(expected), "{commit}");
    }
}

/// A takeover whose compare-and-swap was acknowledged and whose first Report then refuses, on a table where nobody
/// holds the reservation, ends the incarnation `Rerun(Takeover)` in the nomination's period with the connected
/// driver released, one device command, and the record naming C owner at `E + 1`, so the next role read is
/// `Restart`.
#[test]
fn a_refusal_after_the_acknowledged_takeover_write_reruns_with_the_driver() {
    let store = store(shard_record(), with_c());
    let registry = shared_table(vec![
        registrant(own(), 1, false),
        registrant(c_pair(), 2, false),
    ]);
    let witness = witness_of(&store);
    let now = Cell::new(0);
    let stood = stood(
        &store,
        &standby(c_host(), c_record(), &registry, &now),
        &mut |_, _| Some(witness),
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Rerun(Rerun::Takeover)));
    let class = Some((RecoveryCheck::Holder, RecoveryNext::Restart));
    assert_eq!(stood.class, class, "the takeover refusal's class");
    assert_eq!((stood.periods, stood.tenure), (1, None));
    assert_eq!(stood.device, "driver");
    assert_eq!(commands(&registry), ["report"]);
    assert_eq!(writes(&stood.calls), [Key::Shard(shard())], "the one CAS");
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
    let next = role(&mut client(&store), shard(), &holder_of(c_host()));
    assert_eq!(next, Ok(Role::Restart));
}

/// A takeover whose compare-and-swap was acknowledged and whose first Report is accepted and never completes ends
/// the incarnation `Rerun(Takeover)` with the fencer's table, which still owns that Report and which the harness
/// ends through a proven stop.
#[test]
fn a_report_withheld_after_the_acknowledged_takeover_write_reruns_with_the_table() {
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    registry.borrow_mut().budget = Some(0);
    let witness = witness_of(&store);
    let now = Cell::new(0);
    let stood = stood(
        &store,
        &standby(c_host(), c_record(), &registry, &now),
        &mut |_, _| Some(witness),
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Rerun(Rerun::Takeover)));
    let class = Some((RecoveryCheck::FirstReport, RecoveryNext::Restart));
    assert_eq!(stood.class, class, "the takeover refusal's class");
    assert_eq!((stood.periods, stood.tenure), (1, None));
    assert_eq!(stood.device, "outstanding");
    assert_eq!(commands(&registry), ["report"]);
    assert_eq!(writes(&stood.calls), [Key::Shard(shard())], "the one CAS");
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
}

/// A takeover that unwinds after its compare-and-swap was acknowledged and its first Report submitted ends the
/// incarnation `Rerun(Unwound)`. The fencer's table keeps the outstanding Report, also when dropping the unwind's
/// payload panics.
#[test]
fn a_takeover_that_unwinds_reruns_with_the_table_that_owns_its_report() {
    for bomb in [None, Some(Dropped::default())] {
        let store = store(shard_record(), with_c());
        let registry = own_holds();
        registry.borrow_mut().budget = Some(0);
        let witness = witness_of(&store);
        let now = Cell::new(0);
        let clock = UnwindsAfterSubmit::over(&registry, bomb.clone());
        let run = Standby {
            clock: Some(&clock),
            ..standby(c_host(), c_record(), &registry, &now)
        };
        let stood = stood(&store, &run, &mut |_, _| Some(witness), &no_persist);
        assert_eq!(stood.exit, Some(Exit::Rerun(Rerun::Unwound)));
        assert_eq!((stood.periods, stood.tenure), (1, None));
        assert_eq!(stood.device, "outstanding");
        assert_eq!(commands(&registry), ["report"]);
        assert_eq!(writes(&stood.calls), [Key::Shard(shard())], "the one CAS");
        assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
        if let Some(dropped) = bomb {
            assert_eq!(*dropped.lock().unwrap(), ["bomb"]);
        }
    }
}

/// A role read whose raised watermark the log fails to record withdraws the store client, which issues no further
/// request. The arm ends `Rerun(Records)` in that period with no write and no device command.
#[test]
fn a_withdrawn_store_client_ends_the_arm() {
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let now = Cell::new(0);
    let run = standby(c_host(), c_record(), &registry, &now);
    let stood = stood(
        &store,
        &run,
        &mut |period, _| {
            if period == 2 {
                // A write that keeps the record's value raises its version, which the role read must log.
                designate(&store, Some(c_host()));
                run.log_fails.set(true);
            }
            None
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Rerun(Rerun::Records)));
    assert_eq!(stood.periods, 2);
    assert_eq!(stood.calls, two_reads().repeat(2));
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
}

/// A takeover read that withdraws the store client ends the arm at the next view period. The step-1 shard read of
/// period 3 returns a version below the client's watermark, the regression alarm, so the takeover refuses before
/// its compare-and-swap and the arm returns to the wait. Period 4's role read then fails at the withdrawn client
/// with no store request, and the arm ends `Rerun(Records)` with no write and no device command.
#[test]
fn a_takeover_read_that_withdraws_the_client_ends_the_arm_at_the_next_period() {
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let witness = witness_of(&store);
    let now = Cell::new(0);
    let stood = stood(
        &store,
        &standby(c_host(), c_record(), &registry, &now),
        &mut |period, _| match period {
            2 => {
                // A write that keeps the record's value raises its version, which period 2's role read logs.
                designate(&store, Some(c_host()));
                None
            }
            3 => {
                // The role read passes; the step-1 shard read, the takeover's first, returns the earlier version.
                for arm in [Arm::Pass, Arm::Pass, Arm::StaleRead] {
                    store.schedule(arm);
                }
                Some(witness)
            }
            _ => None,
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Rerun(Rerun::Records)));
    assert_eq!(stood.periods, 4);
    let regressed = [two_reads(), step_one_reads()[..1].to_vec()].concat();
    assert_eq!(
        stood.calls,
        [two_reads().repeat(2), regressed.clone()].concat()
    );
    assert_eq!(stood.period(3), regressed, "the regressed step 1");
    assert!(
        stood.period(4).is_empty(),
        "a withdrawn client issues no request"
    );
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
    assert_eq!(shard_now(&store), shard_record());
}

#[test]
fn a_fencer_connected_at_handoff_ends_the_arm_with_its_device() {
    for held in [Held::Driver, Held::Report] {
        let store = store(shard_record(), with_c());
        let registry = own_holds();
        let (device, issued): (_, &[&str]) = if held == Held::Report {
            registry.borrow_mut().budget = Some(0);
            ("outstanding", &["report"])
        } else {
            ("driver", &[])
        };
        let now = Cell::new(0);
        let stood = stood(
            &store,
            &Standby {
                fencer: held,
                ..standby(c_host(), c_record(), &registry, &now)
            },
            &mut |_, stop| {
                stop.store(true, Ordering::Release);
                Some(witness_of(&store))
            },
            &no_persist,
        );
        assert!(
            matches!(stood.exit, Some(Exit::Fault(_))),
            "{held:?}: {:?}",
            stood.exit
        );
        assert_eq!(stood.periods, 0, "{held:?}: no view period");
        assert!(stood.calls.is_empty(), "{held:?}: no store request");
        assert_eq!(stood.device, device, "{held:?}");
        assert_eq!(commands(&registry), issued, "{held:?}: no device command");
        assert_eq!(shard_now(&store), shard_record(), "{held:?}");
    }
}

/// The arm resolves its peers from the volume record of the nomination's period. D's attach is recorded during
/// C's wait and D stays unenrolled; the witness of a later period then starts a takeover that admits D and ends in
/// C's tenure. D's entry binds its instance (BIND-AT-ATTACH), so the takeover admits D with its instance unresolved
/// too. When D's entry binds no instance, as in a format-2 record, the peers bind D, and with D's instance unresolved
/// the same takeover refuses `Volume(Events)` at step 1 and the arm keeps waiting with no write and no device
/// command, which is what a takeover over peers that lack D does.
#[test]
fn an_attach_recorded_during_the_wait_is_bound_by_the_takeover_it_precedes() {
    for (unresolved, bound) in [
        (None, true),
        (Some(d_host()), true),
        (None, false),
        (Some(d_host()), false),
    ] {
        let store = store(shard_record(), with_c());
        fence_page_zero(&store);
        let registry = own_holds();
        let witness = witness_of(&store);
        let attached = store.clone();
        let now = Cell::new(0);
        let stood = stood(
            &store,
            &Standby {
                unresolved,
                ..standby(c_host(), c_record(), &registry, &now)
            },
            &mut |period, stop| {
                match period {
                    2 if bound => record_d(&attached),
                    2 => record_d_unbound(&attached),
                    3 => return Some(witness),
                    4 => stop.store(true, Ordering::Release),
                    _ => {}
                }
                None
            },
            &no_persist,
        );
        assert_eq!(volume_now(&store).enrolled(d_host()), None);
        if bound || unresolved.is_none() {
            assert_eq!(stood.exit, None, "{unresolved:?}, bound {bound}");
            assert_eq!(stood.tenure, Some(Target::of(&shard_now(&store))));
            assert_eq!(shard_now(&store).owner, c_host());
        } else {
            assert_eq!(stood.exit, Some(Exit::Stopped));
            assert_eq!(
                stood.period(3),
                [
                    two_reads(),
                    vec![
                        (false, Key::Shard(shard())),
                        (false, Key::Volume(volume_id()))
                    ]
                ]
                .concat(),
                "the role read and the takeover's step-1 reads, the shard record first"
            );
            assert!(writes(&stood.calls).is_empty(), "{:?}", stood.calls);
            assert!(stood.device == "unconnected" && commands(&registry).is_empty());
            assert_eq!(shard_now(&store), shard_record());
        }
    }
}

/// A role read that names the host owner ends the arm `Rerun(RoleChanged)` in its first period, whatever the
/// caller read before, with no write and no device command.
#[test]
fn an_owner_role_read_ends_the_arm_in_its_first_period() {
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let now = Cell::new(0);
    let link = super::Link::default();
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            ..standby(owner_host(), local_record(), &registry, &now)
        },
        &mut |_, _| Some(witness_of(&store)),
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Rerun(Rerun::RoleChanged)));
    assert_eq!(stood.calls, two_reads());
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
    assert_eq!(link.status.take(), None, "an owner read publishes nothing");
}

/// Records D's attach as the reconciler does, with no enrolled pair.
fn record_d(store: &Shared) {
    // The fixture instance of every attached host, so the write binds each unbound live entry to it.
    let peers = [owner_host(), c_host(), b_host()].map(|host| crate::failover::attachments::Peer {
        host,
        instance: instance_of(host),
    });
    Reconciler::new(client(store))
        .record_standby(
            &StandbyGate::qualified(),
            shard(),
            volume_id(),
            d_host(),
            ERA,
            &bounds_of(limits()),
            &Binding {
                instance: instance_of(d_host()),
                unbound: &peers,
                listing: None,
            },
        )
        .unwrap();
}

/// ENROLL-BEFORE-REGISTER: D is attached with no enrolled pair and named in no role, beside a serving owner. The
/// unnamed arm refuses `Tenure` with no write while the owner's page 0 is unfenced and `Persist` while the local
/// record cannot be written, then makes the local record durable and writes its one enrollment; later periods
/// issue one role read each and no write. No Register or device command is issued. Before its attach is recorded
/// D issues one role read a period and calls neither the enrollment nor the persist.
#[test]
fn an_attached_unnamed_host_persists_then_enrolls_once_and_then_only_waits() {
    let store = store(shard_record(), with_c());
    fence_page_zero(&store);
    let registry = own_holds();
    let now = Cell::new(0);
    let unattached = stood(
        &store,
        &standby(d_host(), d_record(), &registry, &now),
        &mut |period, stop| {
            stop.store(period == 3, Ordering::Release);
            None
        },
        &no_persist,
    );
    assert_eq!(unattached.exit, Some(Exit::Stopped));
    assert_eq!(unattached.calls, two_reads().repeat(2));
    assert!(unattached.device == "unconnected" && commands(&registry).is_empty());

    record_d(&store);
    assert_eq!(volume_now(&store).enrolled(d_host()), None);
    unfence_page_zero(&store);
    let fails = Cell::new(true);
    let fenced = store.clone();
    let stood = stood(
        &store,
        &standby(d_host(), d_record(), &registry, &now),
        &mut |period, stop| {
            match period {
                // Periods 1 and 2 refuse `Tenure`; from 3 the owner's page 0 is fenced.
                3 => fence_page_zero(&fenced),
                // Period 3 refuses `Persist`; from 4 the local record persists.
                4 => fails.set(false),
                8 => stop.store(true, Ordering::Release),
                _ => {}
            }
            None
        },
        &|key| {
            if fails.get() {
                Err(AdmissionError::DurableWrite)
            } else {
                persist_d(key)
            }
        },
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert_eq!(
        volume_now(&store).enrolled(d_host()),
        Some(d_record().pair())
    );
    assert_eq!(
        writes(&stood.calls),
        [Key::Volume(volume_id())],
        "one write"
    );
    let write = stood.calls.iter().position(|(write, _)| *write).unwrap();
    // The enrollment's precondition reads follow the role read in each period that calls it.
    let checked = [two_reads().as_slice(), &precondition()].concat();
    assert_eq!(stood.period(1), checked, "refused `Tenure`");
    assert_eq!(stood.period(2), checked, "refused `Tenure`");
    assert_eq!(stood.period(3), checked, "refused `Persist`");
    assert_eq!(stood.persists, [stood.marks[2] + checked.len(), write]);
    let enrolled = [
        checked.as_slice(),
        &[(true, Key::Volume(volume_id()))],
        &precondition()[1..],
    ]
    .concat();
    assert_eq!(stood.period(4), enrolled, "the write, then its two rereads");
    for period in 5..=7 {
        assert_eq!(stood.period(period), two_reads(), "period {period}");
    }
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
}

/// The reply of D's enrollment write is lost. When the write committed, the next role read shows the pair and the
/// arm issues role reads only, with no second persist or write. When it did not, the next period persists and
/// writes again and enrolls the pair the first persist returned. Neither issues a device command, and the wait
/// ends only on its stop request.
#[test]
fn a_lost_enrollment_reply_is_settled_by_the_next_role_read() {
    for commit in [false, true] {
        let store = store(shard_record(), with_c());
        fence_page_zero(&store);
        record_d(&store);
        let registry = own_holds();
        let armed = store.clone();
        let now = Cell::new(0);
        let stood = stood(
            &store,
            &standby(d_host(), d_record(), &registry, &now),
            &mut |period, stop| {
                if period == 1 {
                    // The role read and the three precondition reads pass; the enrollment write times out.
                    for arm in [Arm::Pass; 5] {
                        armed.schedule(arm);
                    }
                    armed.schedule(Arm::Timeout { commit });
                }
                stop.store(period == 4, Ordering::Release);
                None
            },
            &persist_d,
        );
        assert_eq!(stood.exit, Some(Exit::Stopped), "{commit}");
        assert_eq!(
            volume_now(&store).enrolled(d_host()),
            Some(d_record().pair()),
            "{commit}"
        );
        let attempts = if commit { 1 } else { 2 };
        assert_eq!(stood.persists.len(), attempts, "{commit}");
        assert_eq!(writes(&stood.calls).len(), attempts, "{commit}");
        assert_eq!(
            stood.period(1).last(),
            Some(&(true, Key::Volume(volume_id())))
        );
        assert_eq!(stood.period(2).len() > two_reads().len(), !commit);
        assert_eq!(stood.period(3), two_reads(), "{commit}");
        assert!(stood.device == "unconnected" && commands(&registry).is_empty());
    }
}

/// B is attached with no enrolled pair beside an owner at `E = 0`, where the role read's records fail
/// STANDBY-TENURE: each view period issues one role read and calls neither the enrollment nor the persist. The
/// owner's bump to `E = 1` makes the records pass, and that period's enrollment persists and writes B's pair once.
#[test]
fn an_unnamed_host_calls_no_enrollment_until_the_role_read_passes_its_precondition() {
    let unenrolled = crate::failover::records::VolumeRecord {
        pairs: with_c().pairs,
        ..with_c_and_b()
    };
    let store = store(restart::tests::shard_record(0), unenrolled);
    fence_page_zero(&store);
    let registry = own_holds();
    let now = Cell::new(0);
    // B's record carries the key of its attach entry 2 (KEY-PER-ATTACH).
    let local = successor_record(b_host(), (1 << 32) | 3, 0x5b);
    let stood = stood(
        &store,
        &standby(b_host(), local.clone(), &registry, &now),
        &mut |period, stop| {
            match period {
                3 => rewrite(&store, |record| ShardRecord {
                    attempts: 1,
                    ..record
                }),
                5 => stop.store(true, Ordering::Release),
                _ => {}
            }
            None
        },
        &|_| Ok(local.clone()),
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert_eq!(stood.period(1), two_reads(), "E = 0");
    assert_eq!(stood.period(2), two_reads(), "E = 0");
    assert_eq!(stood.persists.len(), 1);
    assert_eq!(
        stood.persists[0],
        stood.marks[2] + 5,
        "after period 3's reads"
    );
    assert_eq!(writes(&stood.calls), [Key::Volume(volume_id())]);
    assert_eq!(volume_now(&store).enrolled(b_host()), Some(local.pair()));
    assert_eq!(stood.period(4), two_reads(), "enrolled");
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
}

/// The reads `enroll_standby` issues before its persist.
fn precondition() -> [(bool, Key); 3] {
    [
        (false, Key::Volume(volume_id())),
        (false, Key::Shard(shard())),
        (false, Key::Page(shard(), 0)),
    ]
}

/// An attached, unnamed host whose pair is already enrolled writes nothing and calls no persist: one role read a
/// period. A designation moves it to the standby wait in place, where a witness of a stale target starts a takeover
/// that issues its two step-1 reads and refuses.
#[test]
fn an_enrolled_unnamed_host_writes_nothing() {
    let store = store(shard_record(), with_c_and_b());
    let registry = own_holds();
    let designated = store.clone();
    let target = Target::of(&shard_record());
    let stale = Revalidated {
        target: Target {
            attempts: target.attempts - 1,
            ..target
        },
        ..witness_of(&store)
    };
    let now = Cell::new(0);
    let link = super::Link::default();
    let mut named = Vec::new();
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            ..standby(b_host(), stored_b().0.unwrap(), &registry, &now)
        },
        &mut |period, stop| {
            let entry = link.status.take().and_then(|status| status.entry);
            named.extend(entry.map(|entry| (entry.role, entry.named)));
            match period {
                3 => designate(&designated, Some(b_host())),
                4 => return Some(stale),
                5 => stop.store(true, Ordering::Release),
                _ => {}
            }
            None
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    let periods = [two_reads().repeat(4), step_one_reads()].concat();
    assert_eq!(stood.calls, periods);
    assert_eq!(stood.period(3), two_reads());
    assert_eq!(
        stood.period(4),
        [two_reads(), step_one_reads()].concat(),
        "the takeover's step 1"
    );
    assert!(writes(&stood.calls).is_empty());
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
    use crate::failover::report::RecordedRole::Standby as Enrolled;
    assert_eq!(
        named,
        [
            (Some(Enrolled), Some(false)),
            (Some(Enrolled), Some(false)),
            (Some(Enrolled), Some(true)),
            (Some(Enrolled), Some(true)),
        ],
        "B's entry reads standby while enrolled and named once designated"
    );
}

/// The named standby D enrolls its pair in period 1 and retains that period's witness until the role read of
/// period 2 shows the pair. The stale attempt count stops D's takeover after the two step-1 reads.
#[test]
fn a_named_standby_attached_with_no_pair_enrolls_before_it_reads_a_witness() {
    let store = store(shard_record(), with_c());
    fence_page_zero(&store);
    record_d(&store);
    designate(&store, Some(d_host()));
    let target = Target::of(&shard_now(&store));
    let stale = Revalidated {
        target: Target {
            attempts: target.attempts - 1,
            ..target
        },
        ..witness_of(&store)
    };
    let registry = own_holds();
    let now = Cell::new(0);
    let stood = stood(
        &store,
        &standby(d_host(), d_record(), &registry, &now),
        &mut |period, stop| {
            stop.store(period == 4, Ordering::Release);
            (period == 1).then_some(stale)
        },
        &persist_d,
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert_eq!(
        volume_now(&store).enrolled(d_host()),
        Some(d_record().pair())
    );
    assert_eq!(writes(&stood.calls), [Key::Volume(volume_id())]);
    assert_eq!(stood.persists.len(), 1);
    let enrolled = [
        two_reads().as_slice(),
        &precondition(),
        &[(true, Key::Volume(volume_id()))],
        &precondition()[1..],
    ]
    .concat();
    assert_eq!(stood.period(1), enrolled, "the enrollment and no takeover");
    assert_eq!(
        stood.period(2),
        [two_reads(), step_one_reads()].concat(),
        "the takeover's step 1"
    );
    assert_eq!(stood.period(3), two_reads());
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
}

/// The agent of host C over `store`'s shard, owned by A with C named standby, tracking A and the probers 21 and 22
/// in partitions other than A's, with a detector window of 10.
fn c_agent(store: &Shared) -> super::Agent {
    use super::agent::tests::{REPORT_US, keys, reporting};
    use crate::failover::arbiter::Partition;
    use crate::failover::detect::tests::{bounds, clock};
    use crate::failover::sim::host;
    let peers = [owner_host(), host(21), host(22)];
    let mut agent = super::Agent::new(
        &HostGate::qualified(),
        (c_host(), super::agent::tests::boot_of(c_host()), 500),
        bounds(),
        keys(c_host(), &peers),
        reporting(c_host(), REPORT_US),
    )
    .unwrap();
    let placement = [
        (owner_host(), Partition(1)),
        (c_host(), Partition(9)),
        (host(21), Partition(2)),
        (host(22), Partition(3)),
    ];
    let records = [shard_now(store)];
    let out = agent.turn(
        0,
        super::agent::Inputs {
            sync: Some(super::agent::Synced {
                records: &records,
                placement: &placement,
            }),
            clock: clock(0),
            ..super::agent::Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    agent
}

/// One agent window at `now`: C's standby status, DEAD votes from 21 and 22 for every open probe round, and each
/// message the agent addresses to C's process delivered to `link`. Returns the nominations delivered.
fn c_window(agent: &mut super::Agent, link: &super::Link, now: u64) -> usize {
    use crate::failover::report::Phase;
    let statuses = [super::Status::idle(shard(), volume_id(), 7, Phase::Standby)];
    c_window_over(agent, link, now, &statuses)
}

/// [`c_window`] over `statuses` in place of C's fixed standby status.
fn c_window_over(
    agent: &mut super::Agent,
    link: &super::Link,
    now: u64,
    statuses: &[super::Status],
) -> usize {
    use super::agent::tests::{answer, slices};
    use crate::failover::detect::tests::{SILENT, clock};
    let mut delivered = 0;
    for probing in [false, true] {
        let requests: Vec<_> = agent.watch().probes().collect();
        let votes: Vec<_> = (requests.into_iter())
            .filter(|_| probing)
            .flat_map(|r| [21, 22].map(|prober| answer(r, prober, c_host(), SILENT)))
            .collect();
        let out = agent.turn(
            now,
            super::agent::Inputs {
                statuses,
                probes: &slices(&votes),
                clock: clock(now),
                ..super::agent::Inputs::NONE
            },
        );
        for (volume, message) in out.messages {
            assert_eq!(volume, volume_id());
            delivered += usize::from(matches!(message, super::Inbound::Nominate(_)));
            assert!(link.inbox.deliver(message));
        }
    }
    delivered
}

/// The retried takeover of NAMED-STANDBY: C's agent nominates the silent owner A, and C's first takeover refuses at
/// its step-1 record read because the store is unavailable, with no write and no device command. Later windows
/// send the same kept nomination again, revalidated, and the takeover it starts commits. The detector published
/// the target once. Returns the run, the nominations delivered and the detector's nomination count.
fn retried_takeover(registry: &Control) -> (Stood, usize, u64, Option<u32>) {
    let store = store(shard_record(), with_c());
    let mut agent = c_agent(&store);
    let link = super::Link::default();
    let now = Cell::new(0);
    let armed = store.clone();
    let (mut delivered, mut refused) = (0, None);
    let stood = stood(
        &store,
        &standby(c_host(), c_record(), registry, &now),
        &mut |period, stop| {
            let t = u64::from(period) * 10;
            now.set(t);
            let sent = c_window(&mut agent, &link, t);
            delivered += sent;
            if sent > 0 && refused.is_none() {
                refused = Some(period);
                // The period's role read passes; the takeover's step-1 shard read, its first, finds the store
                // unavailable.
                for arm in [Arm::Pass, Arm::Pass, Arm::Unavailable] {
                    armed.schedule(arm);
                }
            }
            if period == 12 {
                stop.store(true, Ordering::Release);
            }
            link.inbox.nomination()
        },
        &no_persist,
    );
    let published = agent.watch().census().nominations;
    (stood, delivered, published, refused)
}

#[test]
fn a_takeover_refused_with_no_write_is_nominated_again_and_commits() {
    let registry = own_holds();
    let (stood, delivered, published, refused) = retried_takeover(&registry);
    let refused = refused.expect("a nomination arrived") as usize;
    let mut step_one = two_reads();
    step_one.push((false, Key::Shard(shard())));
    assert_eq!(
        stood.period(refused),
        step_one,
        "the first takeover refused at its step-1 shard read with no write"
    );
    assert_eq!(
        stood.periods as usize,
        refused + 1,
        "the next window's nomination committed"
    );
    assert_eq!(delivered, 2, "one nomination a window");
    assert_eq!(stood.exit, None, "the second takeover returned a tenure");
    assert_eq!(stood.tenure.map(|t| t.owner), Some(c_host()));
    let cas = writes(&stood.calls);
    assert_eq!(
        cas.iter()
            .filter(|key| **key == Key::Shard(shard()))
            .count(),
        1,
        "one CAS: {cas:?}"
    );
    assert_eq!(
        cas[0],
        Key::Shard(shard()),
        "the CAS precedes the fence writes"
    );
    assert_eq!(
        commands(&registry),
        ["report", "lineage", "report"],
        "one takeover's device commands"
    );
    assert_eq!(published, 1, "the detector published the target once");
}

/// The control that sends only the last tick's published values delivers one nomination, so the takeover never runs
/// again after its refusal.
#[test]
fn the_control_that_sends_only_the_published_values_fails_the_retried_takeover() {
    let registry = own_holds();
    let (stood, delivered, _, _) =
        super::agent::tests::planted("published-only", || retried_takeover(&registry));
    assert_eq!(delivered, 1, "no second nomination arrives");
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert_eq!(stood.tenure, None);
    assert!(writes(&stood.calls).is_empty());
    assert!(commands(&registry).is_empty(), "no device command");
}

/// The reports C's agent seals over what C's own wait publishes: C, the enrolled named standby, waits three view
/// periods with no nomination, and each period's script hands C's agent the status `link`'s cell holds, one report
/// period apart, before the run stops in the fourth. Returns the last report, read under C's report key.
fn reported_while_waiting(
    store: &Shared,
    link: &super::Link,
) -> crate::failover::report::HostReport {
    use super::agent::tests::{REPORT_US, reader_key};
    use crate::failover::detect::tests::clock;
    let registry = own_holds();
    let mut agent = c_agent(store);
    let now = Cell::new(0);
    let mut sealed = None;
    let stood = stood(
        store,
        &Standby {
            link: Some(link),
            ..standby(c_host(), c_record(), &registry, &now)
        },
        &mut |period, stop| {
            let t = u64::from(period) * REPORT_US;
            now.set(t);
            let statuses: Vec<_> = link.status.take().into_iter().collect();
            let out = agent.turn(
                t,
                super::agent::Inputs {
                    statuses: &statuses,
                    clock: clock(t),
                    ..super::agent::Inputs::NONE
                },
            );
            assert_eq!(out.seal_refused, None);
            sealed = out.report.or(sealed.take());
            if period == 4 {
                stop.store(true, Ordering::Release);
            }
            None
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
    let sealed = sealed.expect("C's agent sealed a report");
    crate::failover::report::Reader::default()
        .accept(&sealed, reader_key)
        .unwrap()
}

/// HEADROOM over a production wait: the census lists C's slot for its shard, and C's report, sealed from the
/// statuses C's wait published, lists that shard in the standby role, so a reservation of another shard counts C's
/// slot as filled and charges C no pending attachment.
#[test]
fn the_census_counts_a_waiting_standby_from_the_report_its_wait_feeds() {
    use crate::failover::standbys::tests::listing;
    use crate::failover::standbys::{ActiveVolume, Entry, Zone, lists_standby};
    let store = store(shard_record(), with_c());
    let link = super::Link::default();
    let report = reported_while_waiting(&store, &link);
    let record = shard_now(&store);
    assert!(
        lists_standby(&report, shard().get(), record.active),
        "the report lists the standby: {:?}",
        report.entries
    );
    let census = listing(
        Zone(1),
        shard(),
        Entry {
            target: Target::of(&record),
            host: c_host(),
        },
    );
    let other = crate::net::ownership::Shard::new(shard().get() + 1).unwrap();
    let known = |held| (held == shard()).then(|| ActiveVolume::of(&record));
    assert_eq!(
        census.pending(other, &report, known),
        0,
        "C's slot is filled"
    );
    assert_eq!(
        census.pending(other, &report, |_| None),
        1,
        "a caller with no record of the shard keeps the charge"
    );
}

/// HEADROOM after a flip: C's report still holds the standby entry its wait published for the volume the shard
/// record named active before the flip, and the census lists C's slot at the record's new tenure. That entry fills
/// no slot of the new active volume, so a reservation of another shard counts C's slot as a pending attachment,
/// whether its caller holds the record of after the flip or still the one of before it.
#[test]
fn a_standby_entry_for_a_volume_the_record_no_longer_names_active_fills_no_slot() {
    use crate::failover::standbys::tests::listing;
    use crate::failover::standbys::{ActiveVolume, Entry, Zone};
    let store = store_with_spare(shard_record(), with_c());
    let link = super::Link::default();
    let report = reported_while_waiting(&store, &link);
    flip(&store);
    let record = shard_now(&store);
    assert_ne!(
        record.active,
        volume_id(),
        "the flip named the spare active"
    );
    let target = Target {
        attempts: 1,
        ..Target::of(&record)
    };
    let census = listing(
        Zone(1),
        shard(),
        Entry {
            target,
            host: c_host(),
        },
    );
    let other = crate::net::ownership::Shard::new(shard().get() + 1).unwrap();
    let known = |held| (held == shard()).then(|| ActiveVolume::of(&record));
    assert_eq!(
        census.pending(other, &report, known),
        1,
        "C owes the attach of the new active volume: {:?}",
        report.entries
    );
    // A caller that still holds the record of before the flip reads the entry's volume as the active one, and
    // the census entry's later generation keeps the charge.
    let earlier = shard_record();
    assert_eq!(earlier.active, volume_id());
    assert!(earlier.generation < target.generation);
    let before = |held| (held == shard()).then(|| ActiveVolume::of(&earlier));
    assert_eq!(
        census.pending(other, &report, before),
        1,
        "the census entry is of a later generation than the caller's record"
    );
    let at_the_entry = ActiveVolume {
        generation: target.generation,
        ..ActiveVolume::of(&earlier)
    };
    let credited = |held| (held == shard()).then_some(at_the_entry);
    assert_eq!(
        census.pending(other, &report, credited),
        0,
        "control: the entry fills the slot on the volume it names at the census entry's generation"
    );
}

/// The record names C standby, the active volume record shows C's enrolled pair, and C's report, sealed from the
/// statuses C's wait published, holds an entry for the record's shard and active volume in the standby role.
#[test]
fn a_waiting_standbys_report_holds_a_standby_entry_for_its_shard_and_active_volume() {
    use crate::failover::report::RecordedRole;
    let store = store(shard_record(), with_c());
    let link = super::Link::default();
    let report = reported_while_waiting(&store, &link);
    let record = shard_now(&store);
    assert_eq!(record.standby, Some(c_host()));
    assert!(volume_now(&store).enrolled(c_host()).is_some());
    let listed = (report.entries.iter()).any(|entry| {
        entry.shard == record.shard
            && entry.volume == record.active
            && entry.role == Some(RecordedRole::Standby)
    });
    assert!(listed, "a standby entry: {:?}", report.entries);
}

/// NAMED-STANDBY over a production wait: C's agent turns over the statuses C's own wait published, nominates the
/// silent owner A, and the takeover that nomination starts commits.
#[test]
fn a_silent_owners_standby_is_nominated_through_the_status_its_wait_publishes() {
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let mut agent = c_agent(&store);
    let link = super::Link::default();
    let now = Cell::new(0);
    let mut delivered = 0;
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            ..standby(c_host(), c_record(), &registry, &now)
        },
        &mut |period, stop| {
            let t = u64::from(period) * 10;
            now.set(t);
            let statuses: Vec<_> = link.status.take().into_iter().collect();
            delivered += c_window_over(&mut agent, &link, t, &statuses);
            if period == 12 {
                stop.store(true, Ordering::Release);
            }
            link.inbox.nomination()
        },
        &no_persist,
    );
    assert!(delivered >= 1, "C's agent nominated C's process");
    assert_eq!(stood.exit, None, "the takeover returned a tenure");
    assert_eq!(stood.tenure.map(|t| t.owner), Some(c_host()));
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
}

/// The status C, the enrolled named standby of `store`'s shard, publishes for a role read of `store`'s records:
/// phase `Standby` at the shard record's target with no tenure, and an entry in the standby role, named, with the
/// volume's state and every other field absent or unavailable.
fn c_standing(store: &Shared) -> super::Status {
    use crate::failover::report::tests::bare;
    use crate::failover::report::{Phase, RecordedRole, VolumeEntry};
    let entry = VolumeEntry {
        volume: volume_id(),
        shard: shard(),
        volume_state: Some(crate::failover::records::VolumeState::Active),
        named: Some(true),
        ..bare(volume_id().as_str(), RecordedRole::Standby)
    };
    super::Status {
        target: Some(Target::of(&shard_now(store))),
        entry: Some(entry),
        ..super::Status::idle(shard(), volume_id(), 7, Phase::Standby)
    }
}

/// Whether each call of C's period signal found a status in C's link cell, over four view periods of three status
/// periods each: the period signal returns three times, one `STATUS_US` apart, before each period passes, and
/// period 2's role read fails. Every status found is C's, and every call is bounded by `STATUS_US`.
fn found_over_long_periods() -> Vec<bool> {
    use super::duties::STATUS_US;
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let link = super::Link::default();
    let now = Cell::new(0);
    let seen = RefCell::new(Vec::new());
    let on_wait = |bound: u64| {
        seen.borrow_mut()
            .push((bound, now.get(), link.status.take()));
    };
    let armed = store.clone();
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            slices: 3,
            on_wait: Some(&on_wait),
            ..standby(c_host(), c_record(), &registry, &now)
        },
        &mut |period, stop| {
            if period == 2 {
                armed.schedule(Arm::Unavailable);
            }
            stop.store(period == 4, Ordering::Release);
            None
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert_eq!(stood.period(1), two_reads());
    assert_eq!(stood.period(2), &two_reads()[..1], "the failed role read");
    assert_eq!(stood.period(3), two_reads());
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
    let standing = c_standing(&store);
    let seen = seen.into_inner();
    assert!(seen.iter().all(|(bound, ..)| *bound == STATUS_US));
    (seen.iter())
        .map(|(_, at, status)| {
            if let Some(status) = status {
                assert_eq!(*status, standing, "at {at}");
            }
            status.is_some()
        })
        .collect()
}

/// STANDBY-PUBLISHES over a view period of three status periods: period 1's read publishes C's status; period 2's
/// calls find it and its republications one and two status periods later, and none once the read is `STALE_US`
/// old. Period 2's role read fails, so period 3 finds nothing to republish; period 3's read publishes again, and
/// period 4's first call finds it. The stop flag set at that call ends the wait there. Each period issues only its
/// role read.
#[test]
fn a_long_view_period_republishes_each_status_period_until_its_read_is_stale() {
    let (none, some) = (false, true);
    assert_eq!(
        found_over_long_periods(),
        [
            &[none; 4][..],
            &[some, some, some, none],
            &[none; 4],
            &[some],
        ]
        .concat(),
        "the stop set at period 4's first call ends the period there"
    );
}

/// The control whose wait publishes each read once and never again within a view period fails the long-period case:
/// each read's status is found once, at the first call after it, and the later calls find the cell empty.
#[test]
fn the_control_that_publishes_once_a_period_fails_the_long_period_case() {
    let found = planted(Plant::Unrepeated, found_over_long_periods);
    let found = found.iter().filter(|some| **some).count();
    assert_eq!(
        found, 2,
        "each read's status is found once and then the cell is empty"
    );
}

/// The control whose wait publishes nothing fails the census case: C's report lists no standby.
#[test]
fn the_control_whose_wait_publishes_nothing_fails_the_census_case() {
    let store = store(shard_record(), with_c());
    let link = super::Link::default();
    let report = planted(Plant::Silent, || reported_while_waiting(&store, &link));
    let active = shard_now(&store).active;
    let listed = crate::failover::standbys::lists_standby(&report, shard().get(), active);
    assert!(!listed, "the control's report lists no standby");
}

/// The status a named standby with no enrolled pair publishes reads `Unrecorded`, and the next period's, after its
/// enrollment committed, reads `Standby`; each names the record's target and carries no tenure and no serving state.
#[test]
fn a_standby_entry_reads_standby_only_while_the_volume_read_lists_the_enrolled_pair() {
    use crate::failover::report::RecordedRole;
    let store = store(shard_record(), with_c());
    fence_page_zero(&store);
    record_d(&store);
    designate(&store, Some(d_host()));
    let registry = own_holds();
    let link = super::Link::default();
    let now = Cell::new(0);
    let mut published = Vec::new();
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            ..standby(d_host(), d_record(), &registry, &now)
        },
        &mut |period, stop| {
            published.extend(link.status.take());
            stop.store(period == 3, Ordering::Release);
            None
        },
        &persist_d,
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    let roles: Vec<_> = (published.iter())
        .map(|status| status.entry.and_then(|entry| entry.role))
        .collect();
    assert_eq!(
        roles,
        [Some(RecordedRole::Unrecorded), Some(RecordedRole::Standby)]
    );
    for status in &published {
        let entry = status.entry.unwrap();
        assert_eq!(status.target, Some(Target::of(&shard_now(&store))));
        assert_eq!(
            (status.tenure, entry.tenure, entry.serving),
            (None, None, None)
        );
        assert_eq!(entry.named, Some(true));
    }
}

/// A publication the held cell refuses is retried at the next call of the period signal, and a republication waits
/// one status period after the last accepted one and stops once the read is `STALE_US` old.
#[test]
fn a_refused_publication_is_retried_and_a_stale_read_is_published_no_more() {
    use super::agent::STALE_US;
    use super::duties::STATUS_US;
    use super::recover::Publisher;
    let store = store(shard_record(), with_c());
    let link = super::Link::default();
    let publisher = Publisher {
        cell: &link.status,
        last: Cell::new(None),
    };
    let standing = c_standing(&store);
    let held = link.status.hold();
    publisher.publish(standing, 100);
    drop(held);
    assert_eq!(link.status.take(), None, "the held cell refused");
    publisher.again(150);
    assert_eq!(link.status.take(), Some(standing), "the retry");
    publisher.again(150 + STATUS_US - 1);
    assert_eq!(link.status.take(), None, "within a status period");
    publisher.again(150 + STATUS_US);
    assert_eq!(link.status.take(), Some(standing));
    publisher.again(100 + STALE_US);
    assert_eq!(link.status.take(), None, "the read is STALE_US old");
}

/// A witness that arrives within a long view period ends the period: the role read and the takeover follow at the
/// next call of the period signal, while the witness is live, where the period's end would find it expired.
#[test]
fn a_witness_within_a_long_view_period_starts_its_takeover_while_it_is_live() {
    use super::duties::STATUS_US;
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let now = Cell::new(0);
    let link = super::Link::default();
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            slices: 3,
            ..standby(c_host(), c_record(), &registry, &now)
        },
        &mut |period, _| {
            (period == 2).then(|| Revalidated {
                until_us: now.get() + STATUS_US + STATUS_US / 2,
                ..witness_of(&store)
            })
        },
        &no_persist,
    );
    assert_eq!(stood.exit, None, "the takeover returned a tenure");
    assert_eq!(stood.tenure.map(|t| t.owner), Some(c_host()));
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
}

/// A witness of a detector window shorter than the status period, delivered as a bounded call of a long view
/// period begins, starts its takeover while it is live: the call that holds it returns within the window.
#[test]
fn a_witness_of_a_window_shorter_than_the_status_period_starts_its_takeover_while_it_is_live() {
    const WINDOW_US: u64 = 1_000;
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let now = Cell::new(0);
    let link = super::Link::default();
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            slices: 3,
            window_us: WINDOW_US,
            ..standby(c_host(), c_record(), &registry, &now)
        },
        &mut |period, stop| {
            stop.store(period == 4, Ordering::Release);
            (period == 2).then(|| Revalidated {
                until_us: now.get() + WINDOW_US,
                ..witness_of(&store)
            })
        },
        &no_persist,
    );
    assert_eq!(stood.exit, None, "the takeover returned a tenure");
    assert_eq!(stood.tenure.map(|t| t.owner), Some(c_host()));
    assert_eq!(shard_now(&store), taken(&shard_record(), c_host()));
}

/// A detector window below two status periods bounds each call of the period signal by half the window, and the
/// publications keep the status period's pacing: over a view period of two and a half status periods, period 2's
/// calls find period 1's status and its republications one status period apart, and period 3's first call finds
/// period 2's. Each period issues only its role read.
#[test]
fn a_short_detector_window_bounds_each_call_and_keeps_the_publication_pacing() {
    use super::duties::STATUS_US;
    const WINDOW_US: u64 = 1_000;
    let view_us = 5 * STATUS_US / 2;
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let link = super::Link::default();
    let now = Cell::new(0);
    let seen = RefCell::new(Vec::new());
    let on_wait = |bound: u64| {
        let found = link.status.take().is_some();
        seen.borrow_mut().push((bound, now.get(), found));
    };
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            slices: (view_us / (WINDOW_US / 2)) as u32,
            on_wait: Some(&on_wait),
            window_us: WINDOW_US,
            ..standby(c_host(), c_record(), &registry, &now)
        },
        &mut |period, stop| {
            stop.store(period == 3, Ordering::Release);
            None
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert_eq!(stood.period(1), two_reads());
    assert_eq!(stood.period(2), two_reads());
    let seen = seen.into_inner();
    assert!(seen.iter().all(|(bound, ..)| *bound == WINDOW_US / 2));
    let found: Vec<u64> = (seen.iter())
        .filter_map(|(_, at, found)| found.then_some(*at))
        .collect();
    assert_eq!(
        found,
        [
            view_us,
            view_us + STATUS_US,
            view_us + 2 * STATUS_US,
            2 * view_us
        ],
        "one publication a status period"
    );
}

/// A detector window of zero or one microsecond gives calls of one microsecond, and a window of two status periods
/// or more gives calls of one status period.
#[test]
fn the_bound_of_a_call_is_half_the_window_within_one_microsecond_and_one_status_period() {
    use super::duties::STATUS_US;
    let bound_of = |window_us: u64| {
        let store = store(shard_record(), with_c());
        let registry = own_holds();
        let now = Cell::new(0);
        let seen = Cell::new(None);
        let on_wait = |bound: u64| seen.set(Some(bound));
        let stood = stood(
            &store,
            &Standby {
                slices: 1,
                on_wait: Some(&on_wait),
                window_us,
                ..standby(c_host(), c_record(), &registry, &now)
            },
            &mut |_, stop| {
                stop.store(true, Ordering::Release);
                None
            },
            &no_persist,
        );
        assert_eq!(stood.exit, Some(Exit::Stopped));
        seen.get()
    };
    assert_eq!(bound_of(0), Some(1));
    assert_eq!(bound_of(1), Some(1));
    assert_eq!(bound_of(2 * STATUS_US - 2), Some(STATUS_US - 1));
    assert_eq!(bound_of(2 * STATUS_US), Some(STATUS_US));
    assert_eq!(bound_of(u64::MAX), Some(STATUS_US));
}

/// A role read that fails publishes the last successful read's status again once its publication is `STATUS_US` old,
/// while that read is less than `STALE_US` old.
#[test]
fn a_failed_role_read_republishes_the_last_read_when_due() {
    use super::duties::STATUS_US;
    let store = store(shard_record(), with_c());
    let registry = own_holds();
    let link = super::Link::default();
    let now = Cell::new(0);
    let armed = store.clone();
    let mut found = Vec::new();
    let stood = stood(
        &store,
        &Standby {
            link: Some(&link),
            ..standby(c_host(), c_record(), &registry, &now)
        },
        &mut |period, stop| {
            found.push(link.status.take().is_some());
            if period == 2 {
                now.set(STATUS_US);
                armed.schedule(Arm::Unavailable);
            }
            stop.store(period == 3, Ordering::Release);
            None
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Stopped));
    assert_eq!(stood.period(2), &two_reads()[..1], "the failed role read");
    assert_eq!(
        found,
        [false, true, true],
        "period 2's failed read republished"
    );
}

/// INSTANCE-BOUND: a live attach entry bound to another instance than the holder's gives the waiting entry the role
/// `Unrecorded` though the pair is enrolled, and the holder's own instance gives `Standby`.
#[test]
fn a_standby_entry_reads_unrecorded_for_an_attach_bound_to_another_instance() {
    use crate::failover::report::RecordedRole;
    let (record, mut volume) = (shard_record(), with_c());
    assert!(volume.enrolled(c_host()).is_some());
    let live = volume.live(c_host()).unwrap();
    let attach = (volume.events.iter_mut()).find(|event| event.seq == live);
    attach.unwrap().instance = Some(instance_of(c_host()));
    let role = |instance| {
        let holder = holder_on(volume_id(), c_host(), instance);
        let status = super::recover::standing((&holder, shard(), 7), &volume, &record);
        status.entry.and_then(|entry| entry.role)
    };
    assert_eq!(role(instance_of(c_host())), Some(RecordedRole::Standby));
    assert_eq!(role(instance_of(d_host())), Some(RecordedRole::Unrecorded));
}

/// The flip of the stored shard record, as the reconciler's client writes it: the spare becomes the active volume
/// under its host at the next generation and `E = 0`.
fn flip(store: &Shared) {
    let mut client = client(store);
    let read = client.read::<ShardRecord>(Key::Shard(shard())).unwrap();
    client.flip(&read).unwrap();
}

/// The host of a spare that no flip made active waits as `Unnamed`. Its volume record shows its live attach with
/// no enrolled pair while the shard record names another volume active, so each view period issues one role read
/// and calls neither the enrollment nor the persist. The flip names the spare active under its host at `E = 0`, a
/// fresh role, and the arm ends `Rerun(RoleChanged)` at that period's read with no write and no device command.
#[test]
fn the_spares_host_issues_role_reads_only_until_a_flip_makes_it_fresh() {
    let (spare, spare_host) = shard_record().spare.expect("the fixture names a spare");
    let store = store_with_spare(shard_record(), with_c());
    let unenrolled = client(&store)
        .read::<crate::failover::records::VolumeRecord>(Key::Volume(spare))
        .unwrap()
        .into_value();
    assert!(unenrolled.live(spare_host).is_some() && unenrolled.enrolled(spare_host).is_none());
    let registry = own_holds();
    let now = Cell::new(0);
    let local = bound_record(instance_of(spare_host), spare, (6 << 32) | 4, 0x5e);
    let link = super::Link::default();
    let mut published = Vec::new();
    let stood = stood(
        &store,
        &Standby {
            volume: spare,
            link: Some(&link),
            ..standby(spare_host, local, &registry, &now)
        },
        &mut |period, _| {
            published.push(link.status.take());
            if period == 3 {
                flip(&store);
            }
            None
        },
        &no_persist,
    );
    assert_eq!(stood.exit, Some(Exit::Rerun(Rerun::RoleChanged)));
    assert_eq!(stood.periods, 3);
    assert_eq!(stood.calls, reads_of(spare).repeat(3));
    assert!(stood.device == "unconnected" && commands(&registry).is_empty());
    use crate::failover::report::{Phase, RecordedRole};
    let first = published[1].expect("period 1's read published");
    let entry = first.entry.unwrap();
    assert_eq!((first.phase, first.tenure), (Phase::Standby, None));
    assert_eq!(
        (entry.role, entry.named, entry.volume_state),
        (
            Some(RecordedRole::Unrecorded),
            Some(false),
            Some(unenrolled.state)
        ),
        "the spare's host"
    );
    assert_eq!(link.status.take(), None, "the Fresh read publishes nothing");
}
