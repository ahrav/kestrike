//! The open volume writes no coverage into its metadata, and the coverage feed's advance, registration and release rules.

use std::sync::atomic::{AtomicU64, Ordering};

use super::super::MetadataOutcome;
use super::super::attempt_tests::invalidate;
use super::super::budget::WorkBudget;
use super::super::coverage::{Advance, COUNT_LIMIT, CoverageError, exhausted, register, release};
use super::super::device::Operation;
use super::super::publication_tests::drain;
use super::super::publish_tests::key;
use super::super::recovery::PARKED_EPOCH;
use super::super::tables::SlotState;
use super::super::volume_fixture::Device;
use super::bootstrap_tests::{arena_maintaining, submitted};
use super::journal_tests::{poll, position, published, state, storage_with};

/// Invalidations, an advance of the feed position and 96 polls leave the open volume with no metadata write to submit,
/// so no metadata write carries the feed position.
#[test]
fn no_coverage_bytes_on_volume() {
    let storage = storage_with(|volume| volume.metadata_commands = 2);
    let buffers = arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    published(&storage, &mut dev, 1..=3);
    for n in 1..=3 {
        invalidate(&storage, &key(n)).unwrap();
    }
    poll(&mut dev);
    storage.advance_coverage(0x5EED_C0DE_C0FE_D00D).unwrap();
    let metadata = super::super::TEST_METADATA_UNITS * super::super::device::IO_UNIT as u64;
    for _ in 0..96 {
        poll(&mut dev);
        dev.control.tick(64);
    }
    let writes: Vec<u64> = submitted(&dev.control, Operation::Write)
        .into_iter()
        .map(|(_, start)| start)
        .filter(|start| *start < metadata)
        .collect();
    assert_eq!(
        writes,
        Vec::<u64>::new(),
        "the open volume submits no metadata write"
    );
    assert_eq!(dev.volume.metadata_outcome(), MetadataOutcome::Open);
    assert!(
        dev.volume.metadata.commands[super::metadata::JOURNAL].is_none(),
        "no journal block is staged"
    );
}

#[test]
fn advance_refusals_leave_the_applied_position() {
    let storage = storage_with(|_| {});
    let applied = || {
        storage
            .pool()
            .journal_words()
            .applied
            .load(Ordering::Acquire)
    };
    assert_eq!(storage.advance_coverage(0), Err(CoverageError::Zero));
    assert_eq!(storage.advance_coverage(5), Ok(Advance::Advanced));
    assert_eq!(storage.advance_coverage(5), Ok(Advance::Unchanged));
    assert_eq!(
        storage.advance_coverage(4),
        Err(CoverageError::Regressed { applied: 5 })
    );
    assert_eq!(applied(), 5);
    storage.close();
    assert_eq!(storage.advance_coverage(6), Err(CoverageError::Closed));
    assert_eq!(applied(), 5);
}

/// The epoch word's counts of epoch 0 and epoch 1, as bits 1 to 31 and 32 to 62 hold them.
fn counts(
    storage: &super::super::owner::Storage<super::super::test_platform::TestPlatform>,
) -> (u64, u64) {
    let word = storage.pool().journal_words().epochs.load(Ordering::SeqCst);
    ((word >> 1) & COUNT_LIMIT, (word >> 32) & COUNT_LIMIT)
}

/// `register` counts a retirement under the current epoch with one compare-and-swap, `release` ends that count
/// with one `fetch_sub`, and a count at `COUNT_LIMIT` latches the closed bit through `fetch_or`, after which
/// `register` refuses and `exhausted` holds.
#[test]
fn the_epoch_word_counts_each_registration_until_its_release() {
    let word = AtomicU64::new(0);
    assert_eq!((register(&word), register(&word)), (Some(0), Some(0)));
    assert_eq!(word.load(Ordering::SeqCst), 4);
    release(&word, 0);
    release(&word, 0);
    assert_eq!(word.load(Ordering::SeqCst), 0);
    let full = AtomicU64::new(COUNT_LIMIT << 1);
    assert_eq!(register(&full), None);
    assert!(exhausted(&full));
    assert_eq!(full.load(Ordering::SeqCst) >> 63, 1, "the latch is set");
}

/// A retirement that finds the pool gate held parks through `abandon`, which stores its epoch in the slot's
/// position word and keeps its registration counted. With a volume attached, service's first gate-held sighting
/// of the park retires the slot, ends the registration in that hold and reports the slot as awaiting; `drain`,
/// which certifies before each service call, then returns it once no right remains.
#[test]
fn a_parked_retirement_keeps_its_registration_until_service_converts_its_park() {
    let storage = storage_with(|_| {});
    let buffers = arena_maintaining(2, 4096);
    let mut dev = Device::new(&storage, &buffers);
    let ids = published(&storage, &mut dev, 1..=2);
    dev.persist_journal();
    let pool = storage.live_pool().unwrap();
    let access = pool.try_lock().unwrap();
    invalidate(&storage, &key(1)).unwrap();
    drop(access);
    let abandoned = position(&storage, ids[0].slot_index());
    assert_eq!(
        abandoned, PARKED_EPOCH[0],
        "`abandon` parked the retirement under epoch 0"
    );
    assert_eq!(
        counts(&storage),
        (1, 0),
        "the parked retirement stays counted"
    );
    let slot = ids[0].slot_index();
    let mut access = pool.lock().unwrap();
    let step = access.tables().step(slot);
    access.release();
    assert_eq!(step, 0, "the attach bit alone retires the parked resident");
    let first = storage.service(&mut WorkBudget::new(1 << 10)).unwrap();
    assert_eq!(
        (state(&storage, ids[0]), first.awaiting_journal),
        (Some(SlotState::Retired), 1),
        "the first sighting retires the park and reports it awaiting"
    );
    assert_eq!(
        counts(&storage),
        (0, 0),
        "the conversion ended the registration"
    );
    drain(&storage);
    assert_eq!(state(&storage, ids[0]), Some(SlotState::Free));
    assert_eq!(counts(&storage), (0, 0), "every registration ended once");
}
