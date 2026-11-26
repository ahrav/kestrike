//! Weak-memory kernels that drive the production sequence bracket, the
//! publication anchor and the parked-credit steps on real threads. They are
//! sized for a Miri many-seed sweep, and the ordinary suite runs them too.
//!
//! Each kernel races one bounded attempt per participant on shared atomics.
//! A start barrier precedes the contested protocol events and the joins
//! follow them; the contested store and load pairs run unsynchronized
//! between the two. Every field a reader copies optimistically is an
//! atomic, so a copy the sequence later rejects is race-free.
//!
//! Under Miri each seed picks one schedule and one set of weak-memory
//! outcomes. The interpreter bounds store buffers and approximates `SeqCst`
//! accesses, allowing fewer behaviors than C++20 in some cases, so the
//! seeds are samples: removing `Busy::begin`'s `Release` fence went
//! undetected over all 64 seeds and rests on the `sequence` module's
//! argument, SC-fence weakening evidence belongs to the RC11 lanes, and the
//! physical clock sample of the publication bracket lies outside these
//! kernels.

use std::sync::Barrier;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;

use super::credit::{Sequential, Strength, clear, credits, park, reset};
use super::extent::ExtentLocator;
use super::slot::Record;
use super::word::{self, REF};
use crate::index::{Busy, read_stable, still};

/// A writer moves two fields from 0 to 1 inside the production bracket
/// while a reader makes one optimistic copy. A copy the reader accepts
/// matches the stable value it started from: (0, 0) at 0, (1, 1) at 2.
#[test]
fn miri_weak_memory_seqlock_accepts_only_coherent_copies() {
    let sequence = AtomicU64::new(0);
    let fields = [AtomicU64::new(0), AtomicU64::new(0)];
    let start = Barrier::new(2);
    thread::scope(|scope| {
        scope.spawn(|| {
            start.wait();
            let busy = Busy::begin(&sequence, 0);
            for field in &fields {
                field.store(1, Ordering::Relaxed);
            }
            busy.commit();
        });
        start.wait();
        if let Ok(stable) = read_stable(&sequence) {
            let copy = fields.each_ref().map(|field| field.load(Ordering::SeqCst));
            if still(&sequence, stable) {
                let expected = if stable == 0 { [0, 0] } else { [1, 1] };
                assert_eq!(
                    copy, expected,
                    "an accepted copy at sequence {stable} is torn"
                );
            }
        }
    });
    assert_eq!(sequence.load(Ordering::Relaxed), 2);
    assert_eq!(
        fields.each_ref().map(|field| field.load(Ordering::Relaxed)),
        [1, 1]
    );
}

const NONE: u64 = 0;
const CANDIDATE: u64 = 7;
const FINGERPRINT: u64 = 0xF1F1;
const LOCATOR: u64 = 0x10C;

/// A publisher initializes a candidate's fingerprint and locator, installs
/// its anchor through the production exchange from a zero count, and
/// stores the pair inside the bracket, while a reader makes one copy. A
/// reader that accepts the candidate sees a counted anchor and both fields
/// initialized.
#[test]
fn miri_weak_memory_publication_keeps_visible_candidate_initialized() {
    let sequence = AtomicU64::new(0);
    let pair = AtomicU64::new(NONE);
    let slot_word = AtomicU64::new(1);
    let record = Record::free();
    let start = Barrier::new(2);
    thread::scope(|scope| {
        scope.spawn(|| {
            start.wait();
            record.set_fingerprint(FINGERPRINT);
            record.set_locator(ExtentLocator::from_bits(LOCATOR));
            assert!(word::install(&slot_word, 1, 1), "an idle unindexed slot");
            let stable = read_stable(&sequence).expect("the publisher holds the only bracket");
            let busy = Busy::begin(&sequence, stable);
            pair.store(CANDIDATE, Ordering::Relaxed);
            busy.commit();
        });
        start.wait();
        if let Ok(stable) = read_stable(&sequence) {
            let seen = pair.load(Ordering::SeqCst);
            let current = slot_word.load(Ordering::Acquire);
            let copied = [record.fingerprint(), record.locator().bits()];
            if still(&sequence, stable) && seen == CANDIDATE {
                assert!(
                    word::refs(current) >= 1,
                    "a visible candidate without its anchor"
                );
                assert_eq!(
                    copied,
                    [FINGERPRINT, LOCATOR],
                    "a visible candidate left uninitialized"
                );
            }
        }
    });
    assert_eq!(read_stable(&sequence), Ok(2));
    assert_eq!(pair.load(Ordering::Relaxed), CANDIDATE);
    assert_eq!(slot_word.load(Ordering::Relaxed), 1 + REF);
}

const BIT: u64 = 1;

/// A record holds no credit while its bit is still set, the state a take
/// leaves. One production `Sequential` park of a credit races one scan's
/// clear, reload and conditional reset. After both, the credit is in the word and the
/// bit is set, so the next scan finds it.
#[test]
fn miri_weak_memory_credit_return_and_scan_keep_credit_visible() {
    let pool = AtomicUsize::new(0);
    let map = AtomicU64::new(BIT);
    let start = Barrier::new(2);
    thread::scope(|scope| {
        scope.spawn(|| {
            start.wait();
            park::<Sequential, _, _>(&pool, &map, BIT, 1);
        });
        start.wait();
        clear::<Sequential, _>(&map, BIT);
        if credits(&pool, Sequential::RELOAD) > 0 {
            reset(&map, BIT);
        }
    });
    assert_eq!(credits(&pool, Ordering::Relaxed), 1);
    assert_eq!(
        map.load(Ordering::Relaxed) & BIT,
        BIT,
        "a record holding a credit is unflagged"
    );
}
