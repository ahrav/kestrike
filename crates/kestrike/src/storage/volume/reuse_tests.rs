//! Reuse of a removed entry's extent: the slot returns at once at `NO_RECORD`, and the reused unit's header fails the identity a checkpoint capture named for it.

use super::super::extent::ExtentLocator;
use super::super::publication_tests::{drain, publish};
use super::super::publish_tests::key;
use super::super::record::{Crc32c, RecordIdentity, admits, claim_header};
use super::super::recovery::NO_RECORD;
use super::super::recovery::capture_tests::drain as captured;
use super::super::tables::SlotState;
use super::super::volume_fixture::{Device, arena_with};
use super::journal_tests::{position, retired, state, storage_with};

#[test]
fn a_reused_extent_fails_the_captured_identity_without_a_retirement_record() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let first = retired(&storage, &mut dev, 1);
    drain(&storage);
    assert_eq!(
        state(&storage, first),
        Some(SlotState::Free),
        "the removed entry's slot returns at once"
    );
    assert_eq!(position(&storage, first.slot_index()), NO_RECORD);

    let lease = publish(&storage, &mut dev, &key(2), &[2; 20]).unwrap();
    drop(lease);
    drain(&storage);
    storage.start_capture(64, true, 4).unwrap();
    let capture = captured(&storage);
    let entry = capture
        .iter()
        .find(|entry| entry.key == key(2))
        .expect("the capture holds the published entry")
        .clone();
    let extent = ExtentLocator::from_bits(entry.extents[0]);
    let metadata = storage.pool().descriptor().geometry.metadata_units();
    let at = (metadata + extent.start_unit()) as usize * super::super::IO_UNIT;
    let named = RecordIdentity {
        key: entry.key,
        allocation: entry.allocation,
        session: entry.session,
        version: entry.version,
    };
    let reader = dev.volume.session();
    let crc = Crc32c::detect();
    let admitted = |dev: &Device<'_, '_>| {
        let bytes = dev.control.device(at, super::super::IO_UNIT);
        let found = claim_header(crc, &storage.record, &bytes)
            .expect("the unit holds a record header")
            .identity;
        (found.key, admits(&found, &named, reader))
    };
    assert_eq!(
        admitted(&dev),
        (entry.key, true),
        "the captured extent holds the entry's header"
    );
    invalidate_and_reuse(&storage, &mut dev);
    assert_eq!(
        admitted(&dev),
        (key(3), false),
        "the removed entry's unit is reused at once, and the capture's candidate check refuses it"
    );
}

fn invalidate_and_reuse<'s>(
    storage: &'s super::super::owner::Storage<super::super::test_platform::TestPlatform>,
    dev: &mut Device<'s, '_>,
) {
    super::super::attempt_tests::invalidate(storage, &key(2)).unwrap();
    drain(storage);
    let lease = publish(storage, dev, &key(3), &[3; 20]).unwrap();
    drop(lease);
    drain(storage);
}
