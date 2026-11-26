//! Native litmus loops over three weakly ordered structures: the parked
//! credit against a scan, a pinned reader against a retirement and a pass,
//! and a failed fill's departure against a follower. Each test runs the
//! production generic functions on real threads at production strength and,
//! through the same generic body in the same invocation, a weakened twin
//! that is the live control. The test asserts that production strength
//! shows no forbidden outcome; the twin's count is printed and judged by the
//! `litmus` lane of `scripts/rust-lane.sh`, which runs these ignored tests
//! on aarch64.
//!
//! Each round resets the shared words, releases every participant through a
//! spin start (a `Release` store of the round number that each worker
//! `Acquire`-loads), runs one bounded attempt per participant, and joins
//! through a `Release` count that the judging thread `Acquire`-loads. The
//! start and the join order everything outside the contested accesses, and
//! the harness adds no synchronization between them. Each participant
//! spins 0 to 31 times, by participant and round, before its attempt, so the
//! attempts meet at varying offsets. Zero forbidden outcomes is a finite
//! sample for one build on one CPU.

use std::hint::{black_box, spin_loop};
use std::mem::offset_of;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;

use super::credit;
use super::fill::{self, FillWord, Record};
use super::grace::{self, ERA_FIRST, INACTIVE, PassCursor};
use super::row::{FillFailure, FillRow, Terminal};

/// Rounds per strength, the count the `litmus` lane requires in each line.
const ROUNDS: u64 = 10_000_000;

/// Runs `ROUNDS` rounds over `threads` participants and returns how many
/// rounds `judge` found forbidden. Participant 0 runs on the calling thread.
fn rounds(
    threads: usize,
    reset: &dyn Fn(),
    part: &(dyn Fn(usize) + Sync),
    judge: &dyn Fn() -> bool,
) -> u64 {
    let go = AtomicU64::new(0);
    let done = AtomicU64::new(0);
    let workers = threads as u64 - 1;
    let mut forbidden = 0;
    thread::scope(|scope| {
        for index in 1..threads {
            let (go, done) = (&go, &done);
            scope.spawn(move || {
                for round in 1..=ROUNDS {
                    while go.load(Ordering::Acquire) < round {
                        spin_loop();
                    }
                    stagger(index, round);
                    part(index);
                    done.fetch_add(1, Ordering::Release);
                }
            });
        }
        for round in 1..=ROUNDS {
            reset();
            go.store(round, Ordering::Release);
            stagger(0, round);
            part(0);
            while done.load(Ordering::Acquire) != workers * round {
                spin_loop();
            }
            forbidden += u64::from(judge());
        }
    });
    forbidden
}

/// Spins between 0 and 31 times, by participant and round.
#[inline(always)]
fn stagger(index: usize, round: u64) {
    let spins = (round
        .wrapping_mul(index as u64 * 2 + 1)
        .wrapping_mul(0x9E37_79B9)
        >> 27)
        & 31;
    for _ in 0..spins {
        spin_loop();
    }
}

/// Prints the line the `litmus` lane judges and asserts that production
/// strength showed no forbidden outcome.
fn report(name: &str, forbidden: u64, control: u64) {
    println!(
        "litmus: {name} ran {ROUNDS} rounds; {} forbidden={forbidden} control={control}",
        std::env::consts::ARCH
    );
    assert_eq!(
        forbidden, 0,
        "{name}: production strength reached the forbidden outcome"
    );
}

// Credit: a park of one credit into a word that holds none races a scan's
// clear of the record's bit and its reload of the word. The forbidden
// outcome (record `sweep-credit-return-and-scan-keep-credit-visible`): after
// the join the word holds the credit and its bit is clear. Fixture accesses:
// the reset's stores and the judge's `Relaxed` loads.

const BIT: u64 = 1;

/// The control: every access of the two store-then-load pairs `Relaxed`.
struct RelaxedCredit;

impl credit::Strength for RelaxedCredit {
    const ADD: Ordering = Ordering::Relaxed;
    const BIT_LOAD: Ordering = Ordering::Relaxed;
    const CLEAR: Ordering = Ordering::Relaxed;
    const RELOAD: Ordering = Ordering::Relaxed;
}

fn credit_kernel<S: credit::Strength>() -> u64 {
    let pool = AtomicUsize::new(0);
    let map = AtomicU64::new(BIT);
    rounds(
        2,
        &|| {
            pool.store(0, Ordering::Relaxed);
            map.store(BIT, Ordering::Relaxed);
        },
        &|index| {
            if index == 0 {
                credit::park::<S, _, _>(&pool, &map, BIT, 1);
            } else {
                credit::clear::<S, _>(&map, BIT);
                if credit::credits(&pool, S::RELOAD) > 0 {
                    credit::reset(&map, BIT);
                }
            }
        },
        &|| {
            credit::credits(&pool, Ordering::Relaxed) == 1 && map.load(Ordering::Relaxed) & BIT == 0
        },
    )
}

#[test]
#[ignore = "native litmus loop; the litmus lane runs it on aarch64"]
fn a_parked_credit_keeps_its_record_flagged_against_a_scan() {
    report(
        "credit",
        credit_kernel::<credit::Sequential>(),
        credit_kernel::<RelaxedCredit>(),
    );
}

// Grace: a reader pins the era and then loads an index entry, a writer
// removes the entry and bumps the era, and a maintainer begins a pass and
// visits the reader's record. The forbidden outcome (record
// `grace-sc-points-protect-pinned-reader`, the condition of RC11 test
// `G0-grace-production-seqcst`): the reader saw the entry after its pin, the
// pass started past the bump, and the pass read the reader as inactive. A
// pass that reads the reader's pin at the bumped era also misses it; this
// loop counts the inactive case, the outcome the RC11 condition names.
// Fixture accesses: the index's observation load and removal store of
// `bucket`, both `SeqCst`, as `read_stable` and `Busy::commit` perform them
// and the `grace` module's ordering argument requires; the reset's stores and
// the result words.

/// The control: the reader's pin store `Relaxed`, every other point as
/// [`grace::Sequential`].
struct PinRelaxed;

impl grace::Strength for PinRelaxed {
    const ERA_LOAD: Ordering = <grace::Sequential as grace::Strength>::ERA_LOAD;
    const PIN_STORE: Ordering = Ordering::Relaxed;
    const BUMP: Ordering = <grace::Sequential as grace::Strength>::BUMP;
    const START: Ordering = <grace::Sequential as grace::Strength>::START;
    const VISIT: Ordering = <grace::Sequential as grace::Strength>::VISIT;
    const PUBLISH: Ordering = <grace::Sequential as grace::Strength>::PUBLISH;

    fn fence_pin() {
        <grace::Sequential as grace::Strength>::fence_pin();
    }

    fn fence_retire() {
        <grace::Sequential as grace::Strength>::fence_retire();
    }

    fn fence_certify() {
        <grace::Sequential as grace::Strength>::fence_certify();
    }
}

fn grace_kernel<S: grace::Strength>() -> u64 {
    let era = AtomicU64::new(ERA_FIRST);
    let record = AtomicU64::new(INACTIVE);
    let bucket = AtomicU64::new(1);
    let (seen, start, visited) = (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0));
    rounds(
        3,
        &|| {
            era.store(ERA_FIRST, Ordering::Relaxed);
            record.store(INACTIVE, Ordering::Relaxed);
            bucket.store(1, Ordering::Relaxed);
            seen.store(0, Ordering::Relaxed);
        },
        &|index| match index {
            0 => {
                if grace::pin::<_, S>(&era, &record).is_ok() {
                    seen.store(bucket.load(Ordering::SeqCst), Ordering::Relaxed);
                }
            }
            1 => {
                bucket.store(0, Ordering::SeqCst);
                black_box(grace::bump::<_, S>(&era));
            }
            _ => {
                let mut cursor = PassCursor::begin::<_, S>(&era);
                let pin = cursor.visit::<_, S>(&record);
                start.store(cursor.start_era, Ordering::Relaxed);
                visited.store(pin, Ordering::Relaxed);
            }
        },
        &|| {
            seen.load(Ordering::Relaxed) == 1
                && start.load(Ordering::Relaxed) == ERA_FIRST + 1
                && visited.load(Ordering::Relaxed) == INACTIVE
        },
    )
}

#[test]
#[ignore = "native litmus loop; the litmus lane runs it on aarch64"]
fn a_pinned_reader_is_seen_by_a_pass_that_starts_past_the_bump() {
    report(
        "grace",
        grace_kernel::<grace::Sequential>(),
        grace_kernel::<PinRelaxed>(),
    );
}

// Fill: a producer records a failure and departs while a follower observes
// the departure and reads the terminal. The forbidden outcome (record
// `rc11-fill-terminal-shapes-match-the-declared-matrix`): the follower
// observes the departure and still reads the upload-granted terminal.
// `FillRow::record_failure` and its terminal load use the row's concrete
// atomic at `Relaxed`, outside the `FillWord` seam. Fixture accesses: the
// reset's occupation store and upload grant, and the result words.

const SERIAL: fill::FillSerial = match fill::FillSerial::new(5) {
    Some(serial) => serial,
    None => panic!("5 is an issuable serial"),
};

/// The control: a fill word whose every access is `Relaxed`, with an empty
/// acquire fence.
struct RelaxedFill(AtomicU64);

impl FillWord for RelaxedFill {
    fn load(&self, _: Ordering) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn store(&self, value: u64, _: Ordering) {
        self.0.store(value, Ordering::Relaxed);
    }

    fn fetch_or(&self, value: u64, _: Ordering) -> u64 {
        self.0.fetch_or(value, Ordering::Relaxed)
    }

    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        _: Ordering,
        _: Ordering,
    ) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, new, Ordering::Relaxed, Ordering::Relaxed)
    }

    fn acquire_fence() {}
}

/// A value that starts a 64-byte cache line.
#[repr(align(64))]
struct Line<T>(T);

/// The fill kernel's shared words. The fill word and the row each start a
/// cache line: on an aarch64 Neoverse V1 host the twin shows the forbidden
/// outcome only while the fill word and the row's terminal lie on different
/// lines.
struct Fill<W> {
    state: Line<W>,
    row: Line<FillRow>,
    departed: AtomicBool,
    ready: AtomicBool,
}

// The fill word and the row lie on different cache lines.
const _: () = assert!(
    align_of::<Fill<AtomicU64>>() == 64
        && offset_of!(Fill<AtomicU64>, state) / 64 != offset_of!(Fill<AtomicU64>, row) / 64
);

fn fill_kernel<W: FillWord + Sync>(state: W) -> u64 {
    let f = Fill {
        state: Line(state),
        row: Line(FillRow::new()),
        departed: AtomicBool::new(false),
        ready: AtomicBool::new(false),
    };
    rounds(
        2,
        &|| {
            f.state.0.store(fill::occupied(SERIAL), Ordering::Relaxed);
            f.row.0.mark_ready(1, 0, 1);
        },
        &|index| {
            if index == 0 {
                f.row.0.record_failure(FillFailure::DeviceError);
                black_box(fill::depart(&f.state.0, SERIAL));
            } else {
                let observed = fill::observe(&f.state.0, SERIAL.get() + 1);
                let terminal = f.row.0.terminal();
                f.departed.store(
                    matches!(observed, Ok(Record::Occupied { departed: true, .. })),
                    Ordering::Relaxed,
                );
                f.ready
                    .store(matches!(terminal, Ok(Terminal::Ready)), Ordering::Relaxed);
            }
        },
        &|| f.departed.load(Ordering::Relaxed) && f.ready.load(Ordering::Relaxed),
    )
}

#[test]
#[ignore = "native litmus loop; the litmus lane runs it on aarch64"]
fn a_departed_failure_is_seen_with_its_terminal() {
    report(
        "fill",
        fill_kernel(AtomicU64::new(0)),
        fill_kernel(RelaxedFill(AtomicU64::new(0))),
    );
}
