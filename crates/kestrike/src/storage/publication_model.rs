//! Loom model for the publication bracket with one publisher, one reader and one clock-and-cutoff thread, explored within preemption bound 3.
//!
//! `sequence` is the shard sequence, driven by the production `read_stable`, `still` and `Busy`; `pair` is the mapping's identity word and `body` stands for the RAM state a lookup reads after the pair, the candidate slot's locator and fingerprint, written by the claim and the completion before the odd store, and the fingerprint is what the reader compares with the key's; `word` is the candidate slot's lifetime word, on which the fill's write right is installed from a zero count before its writes and released with a release `fetch_sub` at their last terminal, before readiness, and then the publisher installs the anchor and its own right with one release exchange from a zero count before the odd store and refunds both with one release `fetch_sub` on a refusal; the fill's writes, their terminals and the publication all run on the volume's owner thread, the publisher here; `clock` is the monotonic clock, one `SeqCst` word the clock thread advances; `closed` is the cutoff; `phase` and `credit` are the custody phase and the claimed lease credit.
//! A reader that sees the candidate's pair finds the anchor counted beside the candidate's incarnation in one acquire load of the word.
//! The publisher samples the clock after the odd store; the reader copies the pair, then samples, reads the cutoff and makes its final sequence load.
//! A reader whose final load returns the pre-publication even and whose cutoff read found admission open therefore samples no later than the publisher; a reader that read the cutoff closed reports Closed, which needs no sample.
//! Loom orders `SeqCst` operations across locations only through `SeqCst` fences, so the model places one after the odd store and one after the reader's sample; they stand for the two edges of the platform clock's serialization in the `os` module, the odd store performed before the publisher's counter read and the reader's counter read complete before its later loads, not for anything the memory model gives the clock read.
//! The same limit bounds what the model shows: the edge controls show that each modeled edge is needed in loom's semantics, where a `SeqCst` store and a later `SeqCst` load in one thread are unordered across locations, and the fence after `Busy::begin` also stands in for the odd store's place in the total order, so the model does not distinguish a `SeqCst` odd store from a `Relaxed` one; the `sequence` and `publish` modules argue that store.
//! The negative controls are matched on their own assertions: one samples before the odd store, two each drop one of those fences, and one stores the fingerprint after the pair, so a reader that sees the pair can read it unwritten.
//! Run with `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release publication_model`.

use std::sync::atomic::Ordering;

use loom::sync::atomic::{AtomicBool, AtomicU64};
use loom::sync::{Arc, Mutex};
use loom::thread;

use super::publication::phase;
use super::word::{self, REF};
use crate::index::{Busy, Unstable, read_stable, still};

const NONE: u64 = 0;
const CANDIDATE: u64 = 7;
const COMPLETE: u64 = 0xC0;
const DEADLINE: u64 = 2;
const TICKS: u64 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sampling {
    Inhibited,
    Early,
}

/// Which of the two sample-order edges the model keeps. Each stands for one
/// half of the platform clock's serialization.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Edges {
    /// Both: the odd store precedes the publisher's sample, and the
    /// reader's sample precedes its cutoff and sequence loads.
    Serialized,
    /// The negative control without the publisher's edge.
    NoneAfterOdd,
    /// The negative control without the reader's edge.
    NoneBeforeLoads,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    Ordinary,
    UnwindAfterOdd,
    /// The negative control: the completion's fingerprint and locator
    /// store follows the pair install.
    FingerprintAfterPair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Published,
    Closed,
    Expired,
    Unwound,
}

struct Model {
    gate: Mutex<()>,
    sequence: AtomicU64,
    pair: AtomicU64,
    body: AtomicU64,
    word: AtomicU64,
    clock: AtomicU64,
    closed: AtomicBool,
    phase: AtomicU64,
    credit: AtomicU64,
    poisoned: AtomicBool,
}

impl Model {
    fn new() -> Self {
        Self {
            gate: Mutex::new(()),
            sequence: AtomicU64::new(0),
            pair: AtomicU64::new(NONE),
            body: AtomicU64::new(0),
            word: AtomicU64::new(1),
            clock: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            phase: AtomicU64::new(phase::NONE),
            credit: AtomicU64::new(0),
            poisoned: AtomicBool::new(false),
        }
    }
}

fn publisher(model: &Model, sampling: Sampling, ending: Ending, edges: Edges) -> (Verdict, u64) {
    let _gate = model.gate.lock().unwrap();
    // The fill's write right, from the idle count of an unindexed slot, then
    // its release at the last write terminal, before readiness.
    model
        .word
        .compare_exchange(1, 1 + REF, Ordering::Release, Ordering::Relaxed)
        .expect("an unindexed filling slot's idle count");
    if ending != Ending::FingerprintAfterPair {
        model.body.store(COMPLETE, Ordering::Relaxed);
    }
    model.word.fetch_sub(REF, Ordering::Release);
    model.credit.fetch_add(1, Ordering::Relaxed);
    // The anchor and the publisher's right, from a zero count.
    model
        .word
        .compare_exchange(1, 1 + 2 * REF, Ordering::Release, Ordering::Relaxed)
        .expect("an idle count");
    model.phase.store(phase::PREPARED, Ordering::Relaxed);
    let early = model.clock.load(Ordering::SeqCst);
    let stable = read_stable(&model.sequence).unwrap();
    let busy = Busy::begin(&model.sequence, stable);
    if edges != Edges::NoneAfterOdd {
        loom::sync::atomic::fence(Ordering::SeqCst);
    }
    model.phase.store(phase::INHIBITED, Ordering::Relaxed);
    if ending == Ending::UnwindAfterOdd {
        model.poisoned.store(true, Ordering::Relaxed);
        std::mem::forget(busy);
        return (Verdict::Unwound, 0);
    }
    let sample = match sampling {
        Sampling::Inhibited => model.clock.load(Ordering::SeqCst),
        Sampling::Early => early,
    };
    let closed = model.closed.load(Ordering::SeqCst);
    let verdict = if closed {
        Verdict::Closed
    } else if sample >= DEADLINE {
        Verdict::Expired
    } else {
        Verdict::Published
    };
    if verdict == Verdict::Published {
        model.pair.store(CANDIDATE, Ordering::Relaxed);
        model.phase.store(phase::STORED, Ordering::Relaxed);
    }
    if ending == Ending::FingerprintAfterPair {
        model.body.store(COMPLETE, Ordering::Relaxed);
    }
    let committed = busy.commit();
    assert_eq!(committed, stable + 2);
    if verdict != Verdict::Published {
        model.word.fetch_sub(2 * REF, Ordering::Release);
        model.credit.fetch_sub(1, Ordering::Relaxed);
    }
    model.phase.store(phase::NONE, Ordering::Relaxed);
    (verdict, sample)
}

struct Observation {
    sample: u64,
    stable: u64,
    saw_candidate: bool,
    closed: bool,
}

fn reader(model: &Model, edges: Edges) -> Option<Observation> {
    for _ in 0..2 {
        let stable = match read_stable(&model.sequence) {
            Ok(stable) => stable,
            Err(Unstable::Busy) => continue,
            Err(Unstable::Terminal) => return None,
        };
        let pair = model.pair.load(Ordering::Acquire);
        let saw_candidate = pair == CANDIDATE;
        if saw_candidate {
            let current = model.word.load(Ordering::Acquire);
            assert_eq!(word::incarnation(current), 1);
            assert!(
                word::refs(current) >= 1,
                "a visible candidate without its anchor"
            );
            // The fingerprint a hit compares after its validation, with
            // production's `Acquire` load, and the locator it reads.
            assert_eq!(
                model.body.load(Ordering::Acquire),
                COMPLETE,
                "a visible candidate without its fingerprint"
            );
        }
        // The final bracket, as a lookup makes it after its copy: the
        // sample, then the cutoff read and the final sequence load.
        let sample = model.clock.load(Ordering::SeqCst);
        if edges != Edges::NoneBeforeLoads {
            loom::sync::atomic::fence(Ordering::SeqCst);
        }
        let closed = model.closed.load(Ordering::SeqCst);
        if !still(&model.sequence, stable) {
            continue;
        }
        return Some(Observation {
            sample,
            stable,
            saw_candidate,
            closed,
        });
    }
    None
}

fn model(sampling: Sampling, ending: Ending, edges: Edges, bound: usize) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(bound);
    builder.check(move || {
        let model = Arc::new(Model::new());
        let publisher = {
            let model = Arc::clone(&model);
            thread::spawn(move || publisher(&model, sampling, ending, edges))
        };
        let reader = {
            let model = Arc::clone(&model);
            thread::spawn(move || reader(&model, edges))
        };
        for _ in 0..TICKS {
            model.clock.fetch_add(1, Ordering::SeqCst);
        }
        model.closed.store(true, Ordering::SeqCst);
        let (verdict, sample) = publisher.join().unwrap();
        let observation = reader.join().unwrap();
        let sequence = model.sequence.load(Ordering::Relaxed);
        match verdict {
            Verdict::Unwound => {
                assert_eq!(sequence, 1);
                assert_eq!(model.phase.load(Ordering::Relaxed), phase::INHIBITED);
                assert_eq!(model.credit.load(Ordering::Relaxed), 1);
                assert_eq!(model.word.load(Ordering::Relaxed), 1 + 2 * REF);
                assert!(model.poisoned.load(Ordering::Relaxed));
                assert!(observation.as_ref().is_none_or(|seen| !seen.saw_candidate));
            }
            Verdict::Published => {
                assert_eq!(sequence, 2);
                assert_eq!(model.pair.load(Ordering::Relaxed), CANDIDATE);
                assert_eq!(model.credit.load(Ordering::Relaxed), 1);
                assert_eq!(model.word.load(Ordering::Relaxed), 1 + 2 * REF);
            }
            Verdict::Closed | Verdict::Expired => {
                assert_eq!(sequence, 2);
                assert_eq!(model.pair.load(Ordering::Relaxed), NONE);
                assert_eq!(model.credit.load(Ordering::Relaxed), 0);
                assert_eq!(model.word.load(Ordering::Relaxed), 1);
            }
        }
        assert_eq!(
            model.phase.load(Ordering::Relaxed) == phase::NONE,
            verdict != Verdict::Unwound
        );
        // A reader that read the cutoff closed reports Closed, which needs
        // no sample; every other reader that finished on the pre-publication
        // even is a Missing or Expired verdict the sample must witness.
        if let Some(seen) = observation
            && verdict != Verdict::Unwound
            && seen.stable == 0
            && !seen.closed
        {
            assert!(!seen.saw_candidate);
            assert!(
                seen.sample <= sample,
                "a reader that finished before the odd store sampled later than the publisher"
            );
        }
    });
}

#[test]
fn a_reader_finishing_before_the_odd_store_samples_no_later_than_the_publisher() {
    model(Sampling::Inhibited, Ending::Ordinary, Edges::Serialized, 3);
}

#[test]
fn an_unwind_after_the_odd_store_keeps_inhibition_custody_and_the_credit() {
    model(
        Sampling::Inhibited,
        Ending::UnwindAfterOdd,
        Edges::Serialized,
        3,
    );
}

#[test]
#[should_panic(expected = "a visible candidate without its fingerprint")]
fn negative_control_a_fingerprint_stored_after_the_pair_is_read_unwritten() {
    model(
        Sampling::Inhibited,
        Ending::FingerprintAfterPair,
        Edges::Serialized,
        3,
    );
}

#[test]
#[should_panic(expected = "sampled later than the publisher")]
fn negative_control_an_early_sample_can_precede_a_finished_readers_sample() {
    model(Sampling::Early, Ending::Ordinary, Edges::Serialized, 3);
}

#[test]
#[should_panic(expected = "sampled later than the publisher")]
fn negative_control_a_sample_unordered_after_the_odd_store_can_precede_a_finished_readers_sample() {
    model(
        Sampling::Inhibited,
        Ending::Ordinary,
        Edges::NoneAfterOdd,
        3,
    );
}

#[test]
#[should_panic(expected = "sampled later than the publisher")]
fn negative_control_a_reader_sample_unordered_before_its_loads_can_follow_the_publishers() {
    model(
        Sampling::Inhibited,
        Ending::Ordinary,
        Edges::NoneBeforeLoads,
        3,
    );
}
