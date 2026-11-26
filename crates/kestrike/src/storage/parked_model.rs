//! Loom kernel for the parked-slot bitmap over every schedule the search
//! reaches within the recorded preemption bound. Parks set a slot's
//! abandonment flag and then its parked bit without the pool gate. The gate
//! holder sights flagged slots from the bits, clears the stale bits it
//! meets, and returns a serviced slot, clearing its flag and then its bit.
//!
//! The park's exchange is the production transition [`word::parked`],
//! conditioned on the incarnation it was issued for; the retirement sets
//! and the return clears the [`word::FLAGS`] bits each with one
//! read-modify-write, as `abandon` and `return_extent` do. Every write of
//! the parked set runs the production body over loom atomics: the park's
//! bits through `pending`'s [`mark_parked`], the stale clear and its second
//! look through [`parked_flag`], the absorbing and returning clears through
//! [`unmark_parked_slot`], and the summary repair through [`Parked`]'s
//! word read. A negative control substitutes one [`Marking`] constant or
//! wraps the bitmap word in [`PlainBits`], then runs the same bodies.
//! Model substitutions:
//!
//! - The pool gate is a loom mutex; its holder is the only thread that
//!   clears a bit or a flag, as in production.
//! - Two slots share one bitmap word, so a clear of one slot's bit races the
//!   other slot's park on the same word.
//!
//! Stale-bit kernel: slot 0 starts with a stale bit beside its clear word,
//! the state a previous incarnation's park leaves when its bit lands after
//! the slot's return. One parker parks slot 0's current incarnation and
//! another parks slot 1. The gate holder reads the bitmap once and sights
//! each slot whose bit it read set. At the end every flagged slot has its
//! bit set or was sighted, so no park is lost to a concurrent clear.
//! Negative controls: a clear without its second look loses the park whose
//! bit landed before the clear; and with either the park's bit or the clear
//! `Relaxed`, the clear reads the bit without synchronizing with the park,
//! so the second look may miss its flag and the clear loses that park too.
//!
//! Absorb kernel: a parker parks slot 0 while the gate holder retires slot
//! 0's same incarnation, which absorbs the park when it reads the flag and
//! clears the slot's bit; the park's bit may land after that clear. Once the
//! parker ends, the holder returns slot 0 and sights the bitmap, which
//! clears the stale bit. Slot 1 parks into the same bitmap word throughout.
//! At the end slot 1's flag has its bit set, and slot 0's flag and bit are
//! clear. The kernel counts, outside the model, the executions in which the
//! stale bit landed, and asserts the count is nonzero. Negative control: a
//! clear by a load and a plain store overwrites a bit another write set
//! between them, losing slot 1's park or restoring slot 0's stale bit.
//!
//! Summary kernel: two parked bitmap words, one slot each, under one
//! summary word whose bit for word 0 starts stale beside its zero word, the
//! state a gate holder's clear of word 0's last bit leaves. One parker parks
//! the slot of word 0 and another the slot of word 1, each setting the
//! flag, then the bitmap bit, then the summary bit. The gate holder reads
//! the summary once and reads each word whose summary bit it read set
//! through the production [`Parked`] word read, the walk itself being the
//! model's, repairing a zero word's bit: the clear with `Acquire`, a second
//! load of the word, and the bit set again when the word holds a bit. The
//! holder writes only summary bits, so once the parkers join every flagged slot
//! has both its bitmap bit and its summary bit set; while a park is in
//! flight the two may disagree. The kernel counts, outside the model, the
//! executions in which the repair of word 0's stale summary bit found, on
//! its second load, the bit of a concurrent park that the holder's first
//! load did not observe, the stale summary's clear overlapping a current
//! park, and asserts the count is nonzero. Negative controls: a repair
//! without its second load loses the park whose bits landed before the
//! clear; and with either the park's summary set or the repair's clear
//! `Relaxed`, the second load may miss a bit whose summary bit the clear
//! read, so the repair loses that park too.
//!
//! Run with
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release parked_model`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize as StdUsize, Ordering, Ordering as StdOrdering};

use loom::sync::Mutex;
use loom::sync::atomic::AtomicU64;
use loom::thread;

use super::credit::PlainBits;
use super::pending::{
    Levels, Marking, Parked, Published, mark_parked, parked_flag, unmark_parked_slot,
};
use super::word::{self, ABANDONED, FLAGS, REF, RETIRED};

const PREEMPTION_BOUND: usize = 9;

/// Production's strength with the stale clears' second look omitted.
struct NoSecondLook;

impl Marking for NoSecondLook {
    const BIT: Ordering = Published::BIT;
    const SUMMARY: Ordering = Published::SUMMARY;
    const BIT_CLEAR: Ordering = Published::BIT_CLEAR;
    const SUMMARY_CLEAR: Ordering = Published::SUMMARY_CLEAR;
    const SECOND_LOOK: bool = false;
}

/// Production's strength with the park's slot bit `Relaxed`.
struct RelaxedBitSet;

impl Marking for RelaxedBitSet {
    const BIT: Ordering = Ordering::Relaxed;
    const SUMMARY: Ordering = Published::SUMMARY;
    const BIT_CLEAR: Ordering = Published::BIT_CLEAR;
    const SUMMARY_CLEAR: Ordering = Published::SUMMARY_CLEAR;
    const SECOND_LOOK: bool = true;
}

/// Production's strength with the stale slot bit's clear `Relaxed`.
struct RelaxedBitClear;

impl Marking for RelaxedBitClear {
    const BIT: Ordering = Published::BIT;
    const SUMMARY: Ordering = Published::SUMMARY;
    const BIT_CLEAR: Ordering = Ordering::Relaxed;
    const SUMMARY_CLEAR: Ordering = Published::SUMMARY_CLEAR;
    const SECOND_LOOK: bool = true;
}

/// Production's strength with the park's summary bit `Relaxed`.
struct RelaxedSummarySet;

impl Marking for RelaxedSummarySet {
    const BIT: Ordering = Published::BIT;
    const SUMMARY: Ordering = Ordering::Relaxed;
    const BIT_CLEAR: Ordering = Published::BIT_CLEAR;
    const SUMMARY_CLEAR: Ordering = Published::SUMMARY_CLEAR;
    const SECOND_LOOK: bool = true;
}

/// Production's strength with the stale summary bit's clear `Relaxed`.
struct RelaxedSummaryClear;

impl Marking for RelaxedSummaryClear {
    const BIT: Ordering = Published::BIT;
    const SUMMARY: Ordering = Published::SUMMARY;
    const BIT_CLEAR: Ordering = Published::BIT_CLEAR;
    const SUMMARY_CLEAR: Ordering = Ordering::Relaxed;
    const SECOND_LOOK: bool = true;
}

/// The stale and absorb kernels' state: slots 0 and 1 share parked bitmap
/// word 0 under summary word 0.
struct Shared {
    gate: Mutex<()>,
    words: [AtomicU64; 2],
    parked: [AtomicU64; 1],
    summary: [AtomicU64; 1],
}

impl Shared {
    fn new(words: [u64; 2], parked: u64) -> Self {
        Self {
            gate: Mutex::new(()),
            words: words.map(AtomicU64::new),
            parked: [AtomicU64::new(parked)],
            summary: [AtomicU64::new(u64::from(parked != 0))],
        }
    }

    fn flagged(&self, slot: usize) -> bool {
        self.words[slot].load(Ordering::Relaxed) & ABANDONED != 0
    }

    fn bit(&self, slot: usize) -> bool {
        self.parked[0].load(Ordering::Relaxed) & (1 << slot) != 0
    }
}

/// `park_marked`'s exchange for `incarnation` on lifetime word `word`, then,
/// when the exchange set the flag, the production `mark_parked` of `slot`
/// at strength `M`.
fn park<M: Marking>(
    word: &AtomicU64,
    bits: &[AtomicU64],
    summary: &[AtomicU64],
    slot: usize,
    incarnation: u32,
) {
    let mut current = word.load(Ordering::Relaxed);
    let flagged = loop {
        let Some(next) = word::parked(current, incarnation, 0) else {
            break false;
        };
        match word.compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break current & ABANDONED == 0,
            Err(seen) => current = seen,
        }
    };
    if flagged {
        mark_parked::<_, M>(bits, summary, slot);
    }
}

/// The production `unmark_parked_slot`, over the bitmap word itself or, with
/// `plain`, over the negative control's load and plain store.
fn unmark(shared: &Shared, slot: usize, plain: bool) {
    if plain {
        unmark_parked_slot(&[PlainBits(&shared.parked[0])], slot);
    } else {
        unmark_parked_slot(&shared.parked, slot);
    }
}

/// `abandon`'s retirement under the gate: the flags with one
/// read-modify-write, then the bit of a park it absorbed.
fn retire(shared: &Shared, slot: usize, plain: bool) {
    let previous = shared.words[slot].fetch_or(ABANDONED | RETIRED, Ordering::AcqRel);
    if previous & ABANDONED != 0 {
        unmark(shared, slot, plain);
    }
}

/// The return's clears: every flag with one `fetch_and`, then the bit of a
/// park no retirement absorbed.
fn return_slot(shared: &Shared, slot: usize, plain: bool) {
    let previous = shared.words[slot].fetch_and(!FLAGS, Ordering::Relaxed);
    if previous & (ABANDONED | RETIRED) == ABANDONED {
        unmark(shared, slot, plain);
    }
}

/// The stale kernel with the parkers at strength `P` and the gate holder at
/// strength `H`.
fn stale_model<P: Marking, H: Marking>() {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        // Slot 0 holds incarnation 2 with a stale bit; slot 1 incarnation 1.
        let shared = Arc::new(Shared::new([2 | REF, 1 | REF], 0b01));
        let parkers: Vec<_> = [(0, 2), (1, 1)]
            .into_iter()
            .map(|(slot, incarnation)| {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    park::<P>(
                        &shared.words[slot],
                        &shared.parked,
                        &shared.summary,
                        slot,
                        incarnation,
                    );
                })
            })
            .collect();
        let found = {
            let _hold = shared.gate.lock().unwrap();
            let bits = shared.parked[0].load(Ordering::Relaxed);
            [0, 1].map(|slot| {
                bits & (1 << slot) != 0
                    && parked_flag::<_, _, H>(&shared.parked, &shared.words[slot], slot)
            })
        };
        for parker in parkers {
            parker.join().unwrap();
        }
        for (slot, found) in found.into_iter().enumerate() {
            assert!(
                !shared.flagged(slot) || shared.bit(slot) || found,
                "a park lost its bit to a concurrent clear"
            );
        }
        // Every park completed, so every flag is set; a stale bit the holder
        // cleared never stood for one of them.
        assert!(shared.flagged(0) && shared.flagged(1));
    });
}

#[test]
fn a_stale_clear_loses_no_concurrent_park() {
    stale_model::<Published, Published>();
}

#[test]
#[should_panic(expected = "a park lost its bit")]
fn negative_control_a_clear_without_its_second_look_loses_a_park() {
    stale_model::<Published, NoSecondLook>();
}

#[test]
#[should_panic(expected = "a park lost its bit")]
fn negative_control_a_relaxed_stale_bit_clear_loses_a_park() {
    stale_model::<Published, RelaxedBitClear>();
}

#[test]
#[should_panic(expected = "a park lost its bit")]
fn negative_control_a_relaxed_park_bit_loses_a_park() {
    stale_model::<RelaxedBitSet, Published>();
}

fn absorb_model(plain: bool) {
    // Executions in which the absorbed park's bit landed after the
    // retirement's clear, counted outside the model so the search is known
    // to reach the stale bit.
    let stale = Arc::new(StdUsize::new(0));
    let reached = Arc::clone(&stale);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let shared = Arc::new(Shared::new([1 | REF, 1 | REF], 0));
        let parkers: Vec<_> = [0, 1]
            .into_iter()
            .map(|slot| {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    park::<Published>(
                        &shared.words[slot],
                        &shared.parked,
                        &shared.summary,
                        slot,
                        1,
                    );
                })
            })
            .collect();
        let [zero, one]: [_; 2] = parkers.try_into().ok().unwrap();
        thread::yield_now();
        {
            let _hold = shared.gate.lock().unwrap();
            retire(&shared, 0, plain);
        }
        zero.join().unwrap();
        if shared.bit(0) {
            reached.fetch_add(1, StdOrdering::Relaxed);
        }
        {
            let _hold = shared.gate.lock().unwrap();
            return_slot(&shared, 0, plain);
            if shared.bit(0) {
                assert!(
                    !parked_flag::<_, _, Published>(&shared.parked, &shared.words[0], 0),
                    "a returned slot is flagged"
                );
            }
        }
        one.join().unwrap();
        assert!(
            shared.flagged(1) && shared.bit(1),
            "bitmap word: slot 1's park lost its bit"
        );
        assert!(
            !shared.flagged(0) && !shared.bit(0),
            "bitmap word: slot 0's stale bit survived its sighting"
        );
    });
    assert!(
        stale.load(StdOrdering::Relaxed) > 0,
        "no explored execution landed a bit after the absorbing clear"
    );
}

#[test]
fn an_absorbed_park_leaves_no_bit_and_takes_no_other_slots_bit() {
    absorb_model(false);
}

#[test]
#[should_panic(expected = "bitmap word:")]
fn negative_control_a_load_and_store_clear_overwrites_another_write() {
    absorb_model(true);
}

/// The summary kernel's state: lifetime word `i` is the one slot, slot
/// `64 * i`, of parked bitmap word `i`, and bit `i` of the one summary word
/// stands for that bitmap word.
struct Summary {
    gate: Mutex<()>,
    words: [AtomicU64; 2],
    bits: [AtomicU64; 2],
    summary: [AtomicU64; 1],
}

impl Summary {
    fn new() -> Self {
        Self {
            gate: Mutex::new(()),
            words: [1 | REF, 1 | REF].map(AtomicU64::new),
            bits: [0, 0].map(AtomicU64::new),
            // Word 0's summary bit is stale: its word is zero.
            summary: [AtomicU64::new(0b01)],
        }
    }
}

fn summary_model<M: Marking>() {
    // Executions in which the repair of word 0's stale summary bit found,
    // on its second load, a bit the holder's first load did not observe.
    let overlaps = Arc::new(StdUsize::new(0));
    let reached = Arc::clone(&overlaps);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let shared = Arc::new(Summary::new());
        let parkers: Vec<_> = [0, 1]
            .into_iter()
            .map(|word| {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    park::<M>(
                        &shared.words[word],
                        &shared.bits,
                        &shared.summary,
                        64 * word,
                        1,
                    );
                })
            })
            .collect();
        {
            let _hold = shared.gate.lock().unwrap();
            let mut levels = Parked::<_, M>::new(&shared.bits, &shared.summary);
            let summary = levels.summary(0);
            for word in [0, 1] {
                if summary & (1 << word) != 0 {
                    let relit = levels.relit;
                    levels.word(word);
                    if word == 0 && levels.relit > relit {
                        reached.fetch_add(1, StdOrdering::Relaxed);
                    }
                }
            }
        }
        for parker in parkers {
            parker.join().unwrap();
        }
        let summary = shared.summary[0].load(Ordering::Relaxed);
        for word in [0, 1] {
            let flagged = shared.words[word].load(Ordering::Relaxed) & ABANDONED != 0;
            let marked =
                shared.bits[word].load(Ordering::Relaxed) != 0 && summary & (1 << word) != 0;
            assert!(
                !flagged || marked,
                "a park lost its summary bit to a concurrent repair"
            );
        }
        assert!(
            shared
                .words
                .iter()
                .all(|word| word.load(Ordering::Relaxed) & ABANDONED != 0)
        );
    });
    assert!(
        overlaps.load(StdOrdering::Relaxed) > 0,
        "no explored execution relit word 0's stale summary bit for a concurrent park"
    );
}

#[test]
fn a_stale_summary_repair_loses_no_concurrent_park() {
    summary_model::<Published>();
}

#[test]
#[should_panic(expected = "a park lost its summary bit")]
fn negative_control_a_summary_repair_without_a_second_look_loses_a_park() {
    summary_model::<NoSecondLook>();
}

#[test]
#[should_panic(expected = "a park lost its summary bit")]
fn negative_control_a_relaxed_summary_set_loses_a_park() {
    summary_model::<RelaxedSummarySet>();
}

#[test]
#[should_panic(expected = "a park lost its summary bit")]
fn negative_control_a_relaxed_summary_clear_loses_a_park() {
    summary_model::<RelaxedSummaryClear>();
}
