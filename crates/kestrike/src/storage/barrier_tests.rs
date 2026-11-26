//! Native callers of three production barrier sites, kept in the linked
//! library-test executable for `scripts/scan-barriers.py`: the sequence
//! bracket's begin and the shard's terminal store, each followed by a
//! release fence, and the fill run's acquire fence after an occupied word.
//!
//! Each caller is `inline(never)` and monomorphic over the production atomic
//! type, takes its inputs through [`black_box`], and reaches the fence only
//! through production code. The scan reads each caller's own extent, where
//! the production code inlines. The tests run every caller through its
//! production path. The scan establishes that a sufficient barrier is
//! present in each function; branch placement and the publication clock
//! rest on separate arguments.
//!
//! A removal in a terminal shard, whose release fence replaces the bracket,
//! is checked by behavior: the lane runs [`terminal_removal`] through the
//! terminal path beside the callers. The scan declares no site for it,
//! because `remove_exact` also holds the bracket's fence and a
//! function-level scan of it would pass with the terminal fence deleted.

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use super::AllocationId;
use super::allocation::RetireOutcome;
use super::fill::load_run;
use super::owner::Storage;
use super::publish_tests::{
    TRIES, budget, completed, index_config, install_seam, key, one_chain, report, storage,
};
use super::remove::RemoveError;
use super::test_platform::TestPlatform;
use crate::index::{Busy, Key, TERMINAL, terminate};

/// Opens the sequence bracket from stable `stable` and commits it.
#[inline(never)]
pub(crate) fn sequence_begin(sequence: &AtomicU64, stable: u64) -> u64 {
    Busy::begin(sequence, stable).commit()
}

/// Stores the terminal sequence value.
#[inline(never)]
pub(crate) fn sequence_terminate(sequence: &AtomicU64) {
    terminate(sequence);
}

/// The service pass's observation of an eight-record run.
#[inline(never)]
pub(crate) fn fill_run(states: &[AtomicU64; 8]) -> [u64; 8] {
    load_run(states)
}

/// Removes the mapping of `key` to `id` from `storage`.
#[inline(never)]
pub(crate) fn terminal_removal(
    storage: &Storage<TestPlatform>,
    key: &Key,
    id: AllocationId,
) -> Result<RetireOutcome, RemoveError> {
    storage.remove(key, id, TRIES, &mut budget())
}

#[test]
fn the_sequence_callers_bracket_and_terminate_a_shard() {
    let sequence = AtomicU64::new(black_box(4));
    assert_eq!(sequence_begin(&sequence, black_box(4)), 6);
    sequence_terminate(black_box(&sequence));
    assert_eq!(sequence.load(Ordering::SeqCst), TERMINAL);
}

#[test]
fn the_fill_caller_observes_an_occupied_run_of_eight_words() {
    let words: [u64; 8] = black_box([0, 0, 0, 1 << 3, 0, 0, 0, 0]);
    let states = words.map(AtomicU64::new);
    assert_eq!(fill_run(&states), words);
}

#[test]
fn the_removal_caller_ends_a_mapping_in_a_terminal_shard() {
    let config = index_config(&[4], (1, 1), 1);
    let mut storage = storage(16, &config);
    install_seam(&mut storage, one_chain);
    let index = storage.index.as_ref().unwrap();
    let shard = index.image.shard(crate::index::ShardIndex(0)).unwrap();
    // SAFETY: the index mapping is live.
    let control = unsafe { shard.control(&index.mapping) };
    let id = completed(&storage, key(0x51))
        .publish(TRIES, &mut budget())
        .unwrap();
    control.sequence.store(TERMINAL, Ordering::SeqCst);
    assert!(report(&storage, 0).terminal);
    assert_eq!(
        terminal_removal(&storage, black_box(&key(0x51)), black_box(id)),
        Ok(RetireOutcome::Recorded)
    );
    assert_eq!(report(&storage, 0).visible, 0);
}
