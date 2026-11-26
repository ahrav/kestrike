//! Loom kernel for the ordering contract between a durable prefix writer and service, over every schedule the search reaches within the recorded preemption bound. A model-local writer records block 0 persisted, advances the prefix through the production [`advance`] and stores it; service loads the prefix once and, when the production [`reusable`] admits the retired slot whose record is entry 0 of block 0, returns the slot's extent and reads the persistence the writer recorded. In production, the volume's delta writer stores the prefix word with release after a suffix block's `Written` terminal, and service makes the acquire load.
//!
//! Model substitutions:
//!
//! - The writer is a model-local thread, and the block's persistence is a plain cell it writes before its store, standing for the `Persisted` evidence a writer applies; the extent's return is a read of that cell, so a return the store does not order after the write is a data race loom reports.
//! - Service is the model's main thread; its load stands for the acquire load `Storage::service` makes, over a loom atomic.
//! - Admission stays open, so the close waiver is out of the kernel.
//!
//! At the end a return happened only after the block persisted. The kernel counts, outside the model, the executions in which service returned the slot, and asserts the count is nonzero. Negative control: with the store or the load `Relaxed`, a return can read the cell with no ordering after its write.
//!
//! Run with
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release durable_prefix_model`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize as StdUsize, Ordering as StdOrdering};

use loom::cell::UnsafeCell;
use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

use super::recovery::{NO_RECORD, advance, journal_position, reusable};

const PREEMPTION_BOUND: usize = 4;

/// The kernel with the writer's store at `publish` and service's load at `observe`, counting the executions that returned the slot.
fn prefix_model(publish: Ordering, observe: Ordering) {
    let returned = Arc::new(StdUsize::new(0));
    let reached = Arc::clone(&returned);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let prefix = Arc::new(AtomicU64::new(0));
        let persisted = Arc::new(UnsafeCell::new(false));
        let writer = {
            let (prefix, persisted) = (Arc::clone(&prefix), Arc::clone(&persisted));
            thread::spawn(move || {
                // SAFETY: loom tracks the cell's accesses; the writer thread is its only writer.
                persisted.with_mut(|block| unsafe { *block = true });
                prefix.store(advance(0, 0), publish);
            })
        };
        let position = journal_position(0, 0);
        assert_ne!(position, NO_RECORD);
        if reusable(0, position, prefix.load(observe), false) {
            // SAFETY: loom tracks the cell's accesses and reports a read unordered after the write.
            let durable = persisted.with(|block| unsafe { *block });
            assert!(durable, "a slot returned before its block persisted");
            returned.fetch_add(1, StdOrdering::Relaxed);
        }
        writer.join().unwrap();
    });
    assert_ne!(
        reached.load(StdOrdering::Relaxed),
        0,
        "no schedule returned the slot"
    );
}

#[test]
fn a_return_on_the_loaded_prefix_follows_the_block_s_persistence() {
    let returned = Arc::new(StdUsize::new(0));
    let reached = Arc::clone(&returned);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let prefix = Arc::new(AtomicU64::new(0));
        let persisted = Arc::new(UnsafeCell::new(false));
        let writer = {
            let (prefix, persisted) = (Arc::clone(&prefix), Arc::clone(&persisted));
            thread::spawn(move || {
                // SAFETY: loom tracks the cell's accesses; the writer thread is its only writer.
                persisted.with_mut(|block| unsafe { *block = true });
                prefix.store(advance(0, 0), Ordering::Release);
            })
        };
        if reusable(
            0,
            journal_position(0, 0),
            prefix.load(Ordering::Acquire),
            false,
        ) {
            // SAFETY: loom tracks the cell's accesses and reports a read unordered after the write.
            let durable = persisted.with(|block| unsafe { *block });
            assert!(durable, "a slot returned before its block persisted");
            returned.fetch_add(1, StdOrdering::Relaxed);
        }
        writer.join().unwrap();
    });
    assert_ne!(
        reached.load(StdOrdering::Relaxed),
        0,
        "no schedule returned the slot"
    );
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_prefix_store_lets_a_return_race_the_persistence() {
    prefix_model(Ordering::Relaxed, Ordering::Acquire);
}

#[test]
#[should_panic(expected = "Causality violation")]
fn negative_control_a_relaxed_prefix_load_lets_a_return_race_the_persistence() {
    prefix_model(Ordering::Release, Ordering::Relaxed);
}
