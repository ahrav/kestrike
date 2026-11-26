//! Loom kernel for the parked-credit protocol of the `credit` module: one
//! record's pool and return line and its bit in one map word, over every
//! schedule of a return, the owner's take and another reader's scan that the
//! search reaches within the preemption bound.
//!
//! Model substitutions: the record's two words and the map word are loom
//! atomics; the owner, the returner and the scanner run the `credit`
//! module's steps unchanged, choosing the orderings through [`Model`]. Loom
//! 0.7.2 does not model the cross-location total order of `SeqCst`
//! accesses, so the model stands in for the production `Sequential` with
//! `Release`/`Acquire` accesses and a `SeqCst` fence between the two
//! accesses of each store-then-load pair; turning one fence off is the
//! model's form of weakening that pair.
//!
//! The scanner runs the `lease` module's scan: a flagged record's return
//! line is tried, then its pool; a record that showed nothing has its bit
//! cleared and both words reloaded, and a record found holding credits after
//! the clear gets its bit back and is tried again. The owner takes from its
//! pool, and when that holds nothing drains its return line into the pool.
//!
//! Properties at the end of every execution: the credits are conserved,
//! as the two words' credits plus every take; no word is left below zero;
//! and a record holding credits has its bit set, so no credit is hidden
//! from the next scan.
//!
//! Negative controls: from a record whose bit is set while it holds nothing,
//! the state an owner's take leaves, dropping both fences, the return's
//! fence alone or the scan's fence alone each produces a counterexample at
//! the hidden-credit assertion. Each control is matched on that assertion's
//! message, so an unrelated panic does not satisfy it.
//!
//! Finite-model findings. Under RC11 the store-buffering execution in which
//! the park's load reads the bit before the clear and the scan's reload
//! reads the words before the add is allowed whenever either fence is
//! missing and forbidden with both, so each single-fence control is a real
//! weakening. Loom's `SeqCst` fence joins the fencing thread's causality
//! into one global clock, so it orders more than RC11's fence rule; for
//! these two weakenings the search still reaches the matched hidden credit
//! within the bound. The GenMC kernel over the production `credit` source
//! checks the RC11 reading: `verification/genmc/expected.json` declares its
//! `nopark` and `noclear` cases violations at the hidden-credit check for
//! the stale, pool1 and two states, and `verification/rc11/expected.json`
//! declares `L2a-park-fence-dropped` and `L2b-scan-fence-dropped`
//! `Sometimes`. These findings are about the model's encoding;
//! the production argument is the `credit` module's: its `Sequential`
//! accesses at both pairs sit in one `SeqCst` total order, which the
//! finite model neither replaces nor checks.
//!
//! A second kernel runs two records
//! in one map word, two scanners and a returner over the same production
//! scan, sweep and refusal: at the end the credits are conserved, no word
//! owes a give-back and every record holding credits is flagged; a scanner
//! never refuses `LeaseLimit` while a record it started after held a credit
//! no scan took; and a scan after every actor joins takes a remaining credit
//! or refuses `LeaseLimit` over none. With the first scanner funded for its
//! sweep and not the take after its reset, some execution has the second
//! scanner refuse `Contended` over the credit that sweep holds under a clear
//! bit, counted outside the model. Its controls substitute a load-and-store
//! credit word, which loses or duplicates a credit, a sweep word that always
//! reads zero, under which a refusal over the hidden credit reports the
//! limit, and one that always reads a sweep in progress, under which the
//! quiescent scan refuses `Contended`. The sweep counts and bits run under
//! loom's treatment of `SeqCst` as acquire and release; production's
//! argument for them is the `SeqCst` total order, which the model leaves
//! unchecked.
//!
//! Bounds: loom `0.7.2`, preemption bound 3; each property holds on every
//! schedule the bounded search reached. Run with
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release credit_model`.

use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicUsize as StdUsize, Ordering};

use loom::sync::Arc;
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, fence};
use loom::thread;

use super::budget::WorkBudget;
use super::credit::{CreditWord, Strength, SweepWord, drain, park, take};
use super::credit_steps::{BIT, Record as Steps};
use super::lease::{CreditError, ParkedCredits, RecordWords, record_credits, scan_parked};

const PREEMPTION_BOUND: usize = 3;

/// `Release`/`Acquire` accesses with a `SeqCst` fence at each pair whose
/// parameter is `true`. Both fences on is the stand-in for production.
struct Model<const PARK: bool, const CLEAR: bool>;

impl<const PARK: bool, const CLEAR: bool> Strength for Model<PARK, CLEAR> {
    const ADD: Ordering = Ordering::Release;
    const BIT_LOAD: Ordering = Ordering::Acquire;
    const CLEAR: Ordering = Ordering::AcqRel;
    const RELOAD: Ordering = Ordering::Acquire;

    #[inline(always)]
    fn fence_park() {
        if PARK {
            fence(Ordering::SeqCst);
        }
    }

    #[inline(always)]
    fn fence_clear() {
        if CLEAR {
            fence(Ordering::SeqCst);
        }
    }
}

type Record = Steps<AtomicUsize, AtomicU64>;

/// A budget that pays every scan here in full.
const FUNDED: usize = 64;

/// The one-record model as the production scan reads it: one record in one
/// map word with its sweep counts.
struct One {
    steps: Record,
    sweeps: AtomicU64,
}

impl RecordWords for One {
    type Credit = AtomicUsize;
    type Bits = AtomicU64;

    fn bits(&self, _: usize) -> &AtomicU64 {
        &self.steps.map
    }

    fn pool(&self, _: usize) -> &AtomicUsize {
        &self.steps.pool
    }

    fn line(&self, _: usize) -> &AtomicUsize {
        &self.steps.line
    }
}

impl ParkedCredits for One {
    type Sweeps = AtomicU64;

    fn records(&self) -> usize {
        1
    }

    fn map_words(&self) -> usize {
        1
    }

    fn sweeps(&self, _: usize) -> &AtomicU64 {
        &self.sweeps
    }

    fn lent(&self, _: usize, _: usize) {}
}

/// A record holding `pool` credits, flagged when it holds any and, when
/// `stale`, flagged while holding none: the state an owner's take leaves
/// when it drains the pool, since a take clears no bit.
fn record(pool: usize, stale: bool) -> Record {
    Steps {
        pool: AtomicUsize::new(pool),
        line: AtomicUsize::new(0),
        map: AtomicU64::new(if pool > 0 || stale { BIT } else { 0 }),
    }
}

fn model<S: Strength + 'static>(initial_pool: usize, stale: bool, returns: usize) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let one = Arc::new(One {
            steps: record(initial_pool, stale),
            sweeps: AtomicU64::new(0),
        });
        let returner = {
            let one = Arc::clone(&one);
            thread::spawn(move || one.steps.give_back::<S>(returns))
        };
        let scanner = {
            let one = Arc::clone(&one);
            thread::spawn(move || {
                usize::from(scan_parked::<S, _>(&*one, None, &mut WorkBudget::new(FUNDED)).is_ok())
            })
        };
        let record = &one.steps;
        let owner_taken = record.owner_take::<S>();
        returner.join().unwrap();
        let scanner_taken = scanner.join().unwrap();
        assert_eq!(
            record.held() + owner_taken + scanner_taken,
            initial_pool + returns,
            "credits conserved"
        );
        assert!(record.owes_nothing(), "no debt left behind");
        assert!(record.discoverable(), "a record holding credits is flagged");
    });
}

/// Two records in one map word as the production scan reads them, with
/// the word's sweep counts. `C` is the records' credit word and `W` the
/// sweep word, so a control substitutes either.
struct Two<C, W> {
    pools: [C; 2],
    lines: [C; 2],
    bits: AtomicU64,
    sweeps: W,
}

impl<C: CreditWord, W> RecordWords for Two<C, W> {
    type Credit = C;
    type Bits = AtomicU64;

    fn bits(&self, _: usize) -> &AtomicU64 {
        &self.bits
    }

    fn pool(&self, index: usize) -> &C {
        &self.pools[index]
    }

    fn line(&self, index: usize) -> &C {
        &self.lines[index]
    }
}

impl<C: CreditWord, W: SweepWord> ParkedCredits for Two<C, W> {
    type Sweeps = W;

    fn records(&self) -> usize {
        2
    }

    fn map_words(&self) -> usize {
        1
    }

    fn sweeps(&self, _: usize) -> &W {
        &self.sweeps
    }

    fn lent(&self, _: usize, _: usize) {}
}

impl<C: CreditWord, W: SweepWord> Two<C, W> {
    /// The credits record `index` holds.
    fn held_by(&self, index: usize) -> usize {
        record_credits(self, index, Ordering::Acquire)
    }

    /// Every credit both records hold.
    fn held(&self) -> usize {
        (0..2).map(|index| self.held_by(index)).sum()
    }

    /// Whether neither record's words owe a give-back.
    fn owes_nothing(&self) -> bool {
        (0..2).all(|index| {
            (self.pools[index].load(Ordering::Acquire) as isize) >= 0
                && (self.lines[index].load(Ordering::Acquire) as isize) >= 0
        })
    }

    /// Whether every record holding credits has its bit set.
    fn discoverable(&self) -> bool {
        let bits = self.bits.load(Ordering::Acquire);
        (0..2).all(|index| self.held_by(index) == 0 || bits & (1 << index) != 0)
    }
}

/// A credit word whose read-modify-writes are a load and a plain store, so a
/// take or a park racing another loses or duplicates a credit: the negative
/// control for conservation.
struct PlainCredit(AtomicUsize);

impl CreditWord for PlainCredit {
    fn load(&self, order: Ordering) -> usize {
        self.0.load(order)
    }

    fn fetch_add(&self, value: usize, _: Ordering) -> usize {
        let current = self.0.load(Ordering::Relaxed);
        self.0.store(current.wrapping_add(value), Ordering::Relaxed);
        current
    }

    fn fetch_sub(&self, value: usize, _: Ordering) -> usize {
        let current = self.0.load(Ordering::Relaxed);
        self.0.store(current.wrapping_sub(value), Ordering::Relaxed);
        current
    }
}

impl From<usize> for PlainCredit {
    fn from(value: usize) -> Self {
        Self(AtomicUsize::new(value))
    }
}

/// A sweep word that always reads zero, so a refusal that made no sweep of
/// its own sees no sweep count change: the negative control for the sweep
/// evidence.
struct NoSweeps;

impl SweepWord for NoSweeps {
    fn load(&self, _: Ordering) -> u64 {
        0
    }

    fn fetch_add(&self, _: u64, _: Ordering) -> u64 {
        0
    }

    fn fetch_sub(&self, _: u64, _: Ordering) -> u64 {
        0
    }
}

/// A sweep word that always reads one sweep in progress, so every refusal
/// is `Contended`: the negative control for the limit's meaning.
struct BusySweeps;

impl SweepWord for BusySweeps {
    fn load(&self, _: Ordering) -> u64 {
        1
    }

    fn fetch_add(&self, _: u64, _: Ordering) -> u64 {
        1
    }

    fn fetch_sub(&self, _: u64, _: Ordering) -> u64 {
        1
    }
}

/// The first scanner's budget under [`Funding::SweepOnly`]: its two visits,
/// the empty record's line and then its pool, and the `lease` module's
/// sweep of one record, which debits the record's clear and reset and the
/// two count updates at once.
const SWEEP_ONLY: usize = 2 + (1 + 3);

/// Which scan funds the first scanner.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Funding {
    /// Both scanners can pay every visit, sweep and take.
    Full,
    /// The first scanner pays its two visits and its sweep, not the take
    /// after its reset, so its sweep can hold a returned credit under a
    /// clear bit and leave it there.
    SweepOnly,
}

/// Executions of the multi-record kernel, counted outside the model: the
/// second scanner refused `Contended` over a returned credit that landed
/// before it started and stayed untaken, the window the first scanner's
/// sweep opens, and the first scanner's take after its reset ran out of
/// budget.
#[derive(Default)]
struct MultiWitnesses {
    hidden_contended: StdUsize,
    budget_refused: StdUsize,
}

/// Two records in one map word, two scanners and a returner over the
/// production scan, sweep and refusal: record 0 starts with `pool0` idle
/// credits and its bit set when it holds any, record 1 empty with a stale
/// bit, and the returner returns one credit to record 1's line. `C` and `W`
/// are the credit and sweep words.
fn model_two<C, W>(pool0: usize, funding: Funding, sweeps: fn() -> W) -> StdArc<MultiWitnesses>
where
    C: CreditWord + From<usize> + Send + Sync + 'static,
    W: SweepWord + Send + Sync + 'static,
{
    type S = Model<true, true>;
    let witnesses = StdArc::new(MultiWitnesses::default());
    let reached = StdArc::clone(&witnesses);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let two = Arc::new(Two {
            pools: [C::from(pool0), C::from(0)],
            lines: [C::from(0), C::from(0)],
            bits: AtomicU64::new(0b10 | u64::from(pool0 > 0)),
            sweeps: sweeps(),
        });
        // Released by the returner once its credit has landed and acquired
        // by each scanner as it starts, so a scanner that reads it set
        // starts after the credit in happens-before.
        let landed = Arc::new(AtomicBool::new(false));
        let returner = {
            let (two, landed) = (Arc::clone(&two), Arc::clone(&landed));
            thread::spawn(move || {
                park::<S, _, _>(&two.lines[1], &two.bits, 0b10, 1);
                landed.store(true, Ordering::Release);
            })
        };
        let first = {
            let (two, landed) = (Arc::clone(&two), Arc::clone(&landed));
            thread::spawn(move || {
                let after = landed.load(Ordering::Acquire);
                let steps = if funding == Funding::SweepOnly {
                    SWEEP_ONLY
                } else {
                    FUNDED
                };
                (
                    after,
                    scan_parked::<S, _>(&*two, None, &mut WorkBudget::new(steps)),
                )
            })
        };
        let second = {
            let (two, landed) = (Arc::clone(&two), Arc::clone(&landed));
            thread::spawn(move || {
                let after = landed.load(Ordering::Acquire);
                (
                    after,
                    scan_parked::<S, _>(&*two, None, &mut WorkBudget::new(FUNDED)),
                )
            })
        };
        returner.join().unwrap();
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        let taken = outcomes
            .iter()
            .filter(|(_, outcome)| outcome.is_ok())
            .count();
        assert_eq!(
            two.held() + taken,
            pool0 + 1,
            "multi-record credits conserved"
        );
        assert!(two.owes_nothing(), "multi-record: no debt left behind");
        assert!(
            two.discoverable(),
            "multi-record: a record holding credits is flagged"
        );
        // A scan takes from a record only for itself, so a record still
        // holding a credit at the end held it through every scan that
        // started after the credit arrived: record 0's from the start, and
        // record 1's once the scanner read the return landed. Such a scan
        // cannot report every credit backing a live lease.
        for (after, outcome) in outcomes {
            if two.held_by(0) > 0 || (after && two.held_by(1) > 0) {
                assert_ne!(
                    outcome,
                    Err(CreditError::LeaseLimit),
                    "a refusal reported the limit while a returned credit sat under a sweep"
                );
            }
        }
        // The second scanner's refusal over the returned credit the first
        // scanner's sweep left under a clear bit.
        if let (true, Err(CreditError::Contended)) = outcomes[1]
            && two.held_by(1) > 0
        {
            reached.hidden_contended.fetch_add(1, Ordering::Relaxed);
        }
        if outcomes[0].1 == Err(CreditError::BudgetExhausted) {
            reached.budget_refused.fetch_add(1, Ordering::Relaxed);
        }
        // With every actor joined, a scan sees no other sweep: it takes a
        // credit that remains, and refuses at the limit over none. The
        // fully funded configuration checks it; the sweep-only one keeps
        // its controls on the hidden credit.
        if funding == Funding::SweepOnly {
            return;
        }
        let remaining = two.held();
        let quiescent = scan_parked::<S, _>(&*two, None, &mut WorkBudget::new(FUNDED));
        assert_eq!(
            quiescent,
            if remaining > 0 {
                Ok(())
            } else {
                Err(CreditError::LeaseLimit)
            },
            "a quiescent scan misjudged the limit"
        );
    });
    witnesses
}

/// The production sweep counter.
fn counted() -> AtomicU64 {
    AtomicU64::new(0)
}

#[test]
fn two_records_two_scanners_and_a_return_conserve_credits_and_flag_them() {
    model_two::<AtomicUsize, _>(1, Funding::Full, counted);
}

#[test]
fn a_refusal_over_a_credit_a_sweep_holds_under_a_clear_bit_is_contended() {
    let witnesses = model_two::<AtomicUsize, _>(0, Funding::SweepOnly, counted);
    assert!(
        witnesses.hidden_contended.load(Ordering::Relaxed) > 0,
        "no explored execution refused over a credit a concurrent sweep hid"
    );
    assert!(
        witnesses.budget_refused.load(Ordering::Relaxed) > 0,
        "no explored execution refused the first scanner's unfunded take"
    );
}

#[test]
#[should_panic(expected = "multi-record credits conserved")]
fn negative_control_a_plain_store_credit_word_loses_or_duplicates_a_credit() {
    model_two::<PlainCredit, _>(1, Funding::Full, counted);
}

#[test]
#[should_panic(expected = "a quiescent scan misjudged the limit")]
fn negative_control_a_refusal_that_always_sees_a_sweep_reports_contention_at_the_limit() {
    model_two::<AtomicUsize, _>(1, Funding::Full, || BusySweeps);
}

#[test]
#[should_panic(expected = "a refusal reported the limit while a returned credit sat under a sweep")]
fn negative_control_a_refusal_without_sweep_evidence_reports_the_limit() {
    model_two::<AtomicUsize, _>(0, Funding::SweepOnly, || NoSweeps);
}

#[test]
fn credits_are_conserved_and_never_hidden_from_an_empty_pool() {
    model::<Model<true, true>>(0, false, 1);
}

#[test]
fn credits_are_conserved_and_never_hidden_from_a_stale_flag() {
    model::<Model<true, true>>(0, true, 1);
}

#[test]
fn credits_are_conserved_and_never_hidden_from_a_pool_of_one() {
    model::<Model<true, true>>(1, false, 1);
}

#[test]
fn two_returns_are_conserved_and_never_hidden() {
    model::<Model<true, true>>(0, true, 2);
}

/// A pool value of -1 represents one outstanding give-back from an
/// unsuccessful take. A drain racing the give-back and another reader's
/// take must treat the give-back as repayment of the outstanding debt.
#[test]
fn a_drain_racing_a_give_back_and_a_take_creates_no_credit() {
    type S = Model<true, true>;
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(|| {
        let record = Arc::new(record(0, true));
        record.pool.store((-1isize) as usize, Ordering::Relaxed);
        let debtor = {
            let record = Arc::clone(&record);
            thread::spawn(move || park::<S, _, _>(&record.pool, &record.map, BIT, 1))
        };
        let taker = {
            let record = Arc::clone(&record);
            thread::spawn(move || take::<S, _, _>(&record.pool, &record.map, BIT, 1))
        };
        let drained = drain::<S, _, _>(&record.pool, &record.map, BIT);
        debtor.join().unwrap();
        let taken = taker.join().unwrap();
        assert_eq!(drained + taken, 0, "credits out of a pool that held none");
        assert_eq!(record.pool.load(Ordering::Acquire), 0, "debt left behind");
    });
}

#[test]
#[should_panic(expected = "a record holding credits is flagged")]
fn dropping_both_fences_hides_a_credit() {
    model::<Model<false, false>>(0, true, 1);
}

#[test]
#[should_panic(expected = "a record holding credits is flagged")]
fn dropping_the_return_fence_hides_a_credit() {
    model::<Model<false, true>>(0, true, 1);
}

#[test]
#[should_panic(expected = "a record holding credits is flagged")]
fn dropping_the_scan_fence_hides_a_credit() {
    model::<Model<true, false>>(0, true, 1);
}
