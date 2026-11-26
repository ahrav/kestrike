//! Loom model of the warm bootstrap's pool-gate protocol against fill admission and withdrawal: an installer that
//! holds a restored unit, installs its slot with one counted reference and commits `LoadComplete`, each in its own
//! try-locked hold of the production gate that reads the production readiness word through [`admits`], then begins
//! replay; a reserver that claims a free unit under the gate only when [`Word::fill_refusal`] admits it; and a
//! withdrawer that runs `Storage::withdraw`'s two steps, the compare-and-swap to `Withheld` and one pass of the gate,
//! then applies a stale `LoadComplete`, as a terminal of the ended attempt would.
//!
//! Two models run. The stage model runs those three threads at preemption bound 3 with two try-locks a hold; the lane
//! model runs one installer holding the gate over two lane workers, joined inside the hold, against the withdrawer at
//! preemption bound 2. Properties at every step of every execution, within those bounds:
//!
//! - no write to the modelled pool tables starts after the withdrawal returned, so a reservation or install racing
//!   the withdrawal completes inside a hold that ended before the withdrawal's gate pass, or refuses;
//! - a fill never claims a restored unit, and no unit has two owners;
//! - once withdrawn the word stays `Withheld`: the stale `LoadComplete` reopens nothing;
//! - an ended attempt frees no unit whose slot holds a counted reference.
//!
//! Loom explores the interleavings under its C11 model, which does not include the `SeqCst`
//! total order. The model covers the pool-gated stages, the allocator's hold, the install and the commit, in the
//! production order; the marks and the index publication, which write no pool table, lie outside it. Each planted
//! control breaks one rule and fails its assertion.

use loom::cell::UnsafeCell;
use loom::sync::Arc;
use loom::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use loom::thread;

use super::super::gate::Gate;
use super::super::readiness::{Event, State, Word};
use super::warm::admits;

/// The payload units the model's tables hold: the installer restores unit 0, and a fill may claim either.
const UNITS: usize = 2;

/// A planted defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plant {
    None,
    /// The installer reads the readiness word before it takes the gate.
    CheckBeforeGate,
    /// The withdrawal returns after its compare-and-swap without passing the gate.
    SkipGatePass,
    /// The stale terminal stores `Loaded` over the word instead of applying `LoadComplete` through the table.
    StoreLoadComplete,
    /// The installer commits before it holds the restored unit.
    CommitBeforeHold,
    /// An ended attempt returns its installed unit to the free set.
    ReturnOnEnd,
}

/// The tables the pool gate guards: each unit's owner, the counted references of each unit's slot, and the free set.
#[derive(Debug, Default)]
struct Tables {
    owner: [Option<u8>; UNITS],
    refs: [u32; UNITS],
    taken: [bool; UNITS],
}

struct Pool {
    word: Word,
    gate: Gate<AtomicU32>,
    tables: UnsafeCell<Tables>,
    /// The cells two range-split install workers write, one per lane.
    lanes: [UnsafeCell<u32>; 2],
    /// Set once the withdrawal returned.
    returned: AtomicBool,
}

/// Try-locks one hold makes, so every execution is finite.
const TRIES: usize = 2;

const INSTALLER: u8 = 1;
const FILL: u8 = 2;

impl Pool {
    fn new() -> Self {
        let pool = Self {
            word: Word::default(),
            gate: Gate::open_over(AtomicU32::new),
            tables: UnsafeCell::new(Tables::default()),
            lanes: [UnsafeCell::new(0), UnsafeCell::new(0)],
            returned: AtomicBool::new(false),
        };
        pool.word.apply(Event::Attach).unwrap();
        pool
    }

    /// Runs `under` in one hold of the gate, taken by at most [`TRIES`] try-locks, and returns its result; `None`
    /// when every try found the gate held, as a step that leaves its hold to a later tick.
    fn hold<R>(&self, under: impl FnOnce(&mut Tables) -> R) -> Option<R> {
        for _ in 0..TRIES {
            if let Ok(guard) = self.gate.try_lock() {
                // SAFETY: the gate's hold makes this the one access to the tables; loom reports a missing edge.
                let result = self
                    .tables
                    .with_mut(|tables| under(unsafe { &mut *tables }));
                guard.release();
                return Some(result);
            }
            thread::yield_now();
        }
        None
    }

    /// A table write: none starts after the withdrawal returned.
    fn write(&self) {
        assert!(
            !self.returned.load(Ordering::SeqCst),
            "a table write followed the withdrawal's return"
        );
    }
}

/// Holds unit 0 for a restored slot. The assertion requires the unit to have no owner, so it fails when a fill
/// claimed unit 0 before this hold.
fn hold_restored(pool: &Pool, tables: &mut Tables) {
    pool.write();
    assert!(
        tables.owner[0].is_none(),
        "a restored unit already had an owner: {:?}",
        tables.owner[0]
    );
    (tables.taken[0], tables.owner[0]) = (true, Some(INSTALLER));
}

/// Installs unit 0's slot with its counted anchor.
fn install(pool: &Pool, tables: &mut Tables) {
    pool.write();
    tables.refs[0] = 1;
}

/// One warm stage under the gate: `step` writes the tables only when the word read in the same hold admits it, or,
/// under `CheckBeforeGate`, when a read before the hold did, and under `CommitBeforeHold`, whose stages follow the
/// commit, when the word reads `Live`. `false` when the stage refused.
fn stage(pool: &Pool, plant: Plant, step: fn(&Pool, &mut Tables)) -> bool {
    let early = admits(pool.word.state());
    pool.hold(|tables| {
        let admitted = match plant {
            Plant::CheckBeforeGate => early,
            Plant::CommitBeforeHold => pool.word.state() == State::Live,
            _ => admits(pool.word.state()),
        };
        if admitted {
            step(pool, tables);
        }
        admitted
    })
    .unwrap_or(false)
}

/// The commit: `LoadComplete` applied while the gate is held, then `begin_replay` of no rows to `Live`.
fn commit(pool: &Pool) -> bool {
    let committed = pool.hold(|_| {
        admits(pool.word.state()) && pool.word.apply(Event::LoadComplete) == Ok(State::Loaded)
    }) == Some(true);
    let began = Event::BeginReplay {
        matches: true,
        rows: 0,
    };
    committed && pool.word.apply(began).is_ok()
}

/// The end of an attempt that refused a stage: production retires nothing, so every installed slot keeps its unit;
/// `ReturnOnEnd` returns the installer's units to the free set.
fn ended(pool: &Pool, plant: Plant) {
    if plant != Plant::ReturnOnEnd {
        return;
    }
    let _ = pool.hold(|tables| {
        for unit in 0..UNITS {
            if tables.owner[unit] == Some(INSTALLER) {
                tables.taken[unit] = false;
            }
        }
    });
}

/// The installer's stages in the production order: hold, install, commit; `CommitBeforeHold` commits first.
fn installer(pool: &Pool, plant: Plant) {
    if plant == Plant::CommitBeforeHold && !commit(pool) {
        return ended(pool, plant);
    }
    if !stage(pool, plant, hold_restored) || !stage(pool, plant, install) {
        return ended(pool, plant);
    }
    if plant != Plant::CommitBeforeHold && !commit(pool) {
        ended(pool, plant);
    }
}

/// One fill reservation: under the gate, the word's fill refusal, then a claim of the first free unit.
fn reserve(pool: &Pool) {
    let _ = pool.hold(|tables| {
        if pool.word.fill_refusal().is_some() {
            return;
        }
        pool.write();
        let Some(unit) = (0..UNITS).find(|&unit| !tables.taken[unit]) else {
            return;
        };
        (tables.taken[unit], tables.owner[unit]) = (true, Some(FILL));
    });
}

/// `Storage::withdraw`: the compare-and-swap to `Withheld`, then one pass of the gate, after which the call returns;
/// then a stale `LoadComplete`. A pass whose tries all found the gate held leaves the call waiting at the execution's
/// end.
fn withdraw(pool: &Pool, plant: Plant) {
    let _ = pool.word.apply(Event::Withdraw);
    if plant != Plant::SkipGatePass && pool.hold(|_| {}).is_none() {
        return;
    }
    pool.returned.store(true, Ordering::SeqCst);
    match plant {
        Plant::StoreLoadComplete => pool.word.force(State::Loaded),
        _ => drop(pool.word.apply(Event::LoadComplete)),
    }
    assert_eq!(
        pool.word.state(),
        State::Withheld,
        "an ended attempt reopened"
    );
}

fn model(plant: Plant) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let pool = Arc::new(Pool::new());
        let threads = [
            thread::spawn({
                let pool = Arc::clone(&pool);
                move || withdraw(&pool, plant)
            }),
            thread::spawn({
                let pool = Arc::clone(&pool);
                move || reserve(&pool)
            }),
        ];
        installer(&pool, plant);
        for thread in threads {
            thread.join().unwrap();
        }
        let _ = pool.hold(|tables| {
            for unit in 0..UNITS {
                assert!(
                    tables.refs[unit] == 0 || tables.taken[unit],
                    "a unit with refs > 0 entered the free set: unit {unit}, refs {}",
                    tables.refs[unit]
                );
            }
        });
        assert_eq!(
            pool.word.state(),
            State::Withheld,
            "an ended attempt reopened"
        );
    });
}

#[test]
fn a_reservation_or_install_racing_a_withdrawal_completes_before_it_returns_or_refuses() {
    model(Plant::None);
}

#[test]
#[should_panic(expected = "a table write followed the withdrawal's return")]
fn negative_control_an_admission_read_before_the_gate_writes_after_the_withdrawal() {
    model(Plant::CheckBeforeGate);
}

#[test]
#[should_panic(expected = "a table write followed the withdrawal's return")]
fn negative_control_a_withdrawal_without_its_gate_pass_returns_before_a_write() {
    model(Plant::SkipGatePass);
}

#[test]
#[should_panic(expected = "an ended attempt reopened")]
fn negative_control_a_stored_load_complete_reopens_the_withdrawn_attempt() {
    model(Plant::StoreLoadComplete);
}

#[test]
#[should_panic(expected = "a restored unit already had an owner")]
fn negative_control_a_commit_before_the_hold_lets_a_fill_take_a_restored_unit() {
    model(Plant::CommitBeforeHold);
}

#[test]
#[should_panic(expected = "a unit with refs > 0 entered the free set")]
fn negative_control_an_ended_attempt_that_returns_its_units_frees_a_referenced_unit() {
    model(Plant::ReturnOnEnd);
}

/// A planted defect of the range-split install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LanePlant {
    None,
    /// Both workers write the first lane's slots.
    SharedLane,
    /// The holder releases the gate before it joins its workers.
    ReleaseBeforeJoin,
}

/// One worker's install into lane `lane` of `pool`'s lane cells: no write starts after the withdrawal returned.
fn work(pool: &Pool, lane: usize) {
    pool.write();
    // SAFETY: each worker writes only its own lane's cell, and the holder joins it before reading the cells; loom
    // reports the concurrent access the `SharedLane` control plants.
    pool.lanes[lane].with_mut(|slots| unsafe { *slots += 1 });
}

/// The holder's install tick: one try-lock, the word read under the hold, two workers over their lanes joined inside
/// the hold, then the fold of their counts, as `Volume::install` runs them.
fn install_tick(pool: &Arc<Pool>, plant: LanePlant) {
    let Ok(guard) = pool.gate.try_lock() else {
        return;
    };
    if !admits(pool.word.state()) {
        return guard.release();
    }
    let workers: Vec<_> = (0..2)
        .map(|worker| {
            let pool = Arc::clone(pool);
            let lane = if plant == LanePlant::SharedLane {
                0
            } else {
                worker
            };
            thread::spawn(move || work(&pool, lane))
        })
        .collect();
    if plant == LanePlant::ReleaseBeforeJoin {
        guard.release();
        workers
            .into_iter()
            .for_each(|worker| worker.join().unwrap());
        return;
    }
    workers
        .into_iter()
        .for_each(|worker| worker.join().unwrap());
    // SAFETY: the workers were joined, so the holder is the cells' one accessor under its hold.
    let total: u32 = (pool.lanes.iter())
        .map(|lane| lane.with(|slots| unsafe { *slots }))
        .sum();
    // SAFETY: the holder's gate hold makes it the tables' one accessor.
    pool.tables
        .with_mut(|tables| unsafe { (*tables).refs[1] = total });
    guard.release();
}

fn lanes_model(plant: LanePlant) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let pool = Arc::new(Pool::new());
        let withdrawer = thread::spawn({
            let pool = Arc::clone(&pool);
            move || withdraw(&pool, Plant::None)
        });
        install_tick(&pool, plant);
        withdrawer.join().unwrap();
        assert_eq!(
            pool.word.state(),
            State::Withheld,
            "an ended attempt reopened"
        );
    });
}

#[test]
fn range_split_workers_racing_a_withdrawal_write_disjoint_lanes_inside_the_hold() {
    lanes_model(LanePlant::None);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_two_workers_sharing_a_lane_race_on_its_slots() {
    lanes_model(LanePlant::SharedLane);
}

#[test]
#[should_panic(expected = "a table write followed the withdrawal's return")]
fn negative_control_a_hold_released_before_its_workers_join_lets_a_write_follow_the_withdrawal() {
    lanes_model(LanePlant::ReleaseBeforeJoin);
}
