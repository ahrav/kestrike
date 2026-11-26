//! Retirement over the simulated device, the control tables' naming columns, and the storage, publication and position-word helpers other volume tests share.

use super::super::allocation::AllocationId;
use super::super::attempt_tests::invalidate;
use super::super::config::StorageConfig;
use super::super::owner::Storage;
use super::super::publication_tests::{drain, publish};
use super::super::publish_tests::{PAGE, index_config, key, storage_config, storage_from};

use super::super::VolumeConfig;
use super::super::tables::{SlotIndex, SlotState};
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{Device, arena_with};
use crate::index::IndexConfig;

/// A storage of eight slots with two fill records, its volume edited by `edit`.
pub(super) fn storage_with(edit: impl FnOnce(&mut VolumeConfig)) -> Storage<TestPlatform> {
    let fills = [2];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[8], (1, 1), 1)
    };
    let mut config = StorageConfig {
        lease_limit: 16,
        ..storage_config(8)
    };
    edit(&mut config.volume);
    let storage = storage_from(&config, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    storage
}

/// `slot`'s position word.
pub(super) fn position(storage: &Storage<TestPlatform>, slot: usize) -> u64 {
    let live = storage.live_pool().unwrap();
    let mut access = live.lock().unwrap();
    let position = access.tables().journal().position(slot);
    access.release();
    position
}

pub(super) fn state(storage: &Storage<TestPlatform>, id: AllocationId) -> Option<SlotState> {
    storage
        .slot_state(SlotIndex(id.slot_index()))
        .map(|state| state.0)
}

/// Publishes `n`'s object, drops its lease and invalidates it, so its slot is a retired resident.
pub(super) fn retired<'s>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, '_>,
    n: u8,
) -> AllocationId {
    let lease = publish(storage, dev, &key(n), &[n; 20]).unwrap();
    let id = lease.id();
    drop(lease);
    storage
        .service_fills(
            crate::index::ShardIndex(0),
            4,
            &mut super::super::publish_tests::budget(),
        )
        .unwrap();
    invalidate(storage, &key(n)).unwrap();
    id
}

/// One volume poll with no disk tick, so a command it submits waits on the device.
pub(super) fn poll(dev: &mut Device<'_, '_>) {
    let _ = dev.volume.poll_storage(0, &mut Vec::with_capacity(16));
}

/// Four rounds of six retirements each, past the eight slots, all return: every retired slot's position is `NO_RECORD`, so service frees each once no right remains.
#[test]
fn every_retirement_returns_its_slot() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::new(&storage, &buffers);
    let mut ids = Vec::new();
    for round in 0..4u8 {
        for n in 0..6u8 {
            let lease = publish(&storage, &mut dev, &key(round * 8 + n + 1), &[n; 20]).unwrap();
            ids.push(lease.id());
            drop(lease);
            drain(&storage);
        }
        for n in 0..6u8 {
            invalidate(&storage, &key(round * 8 + n + 1)).unwrap();
        }
        for _ in 0..32 {
            dev.tick_journal(4);
            drain(&storage);
        }
        for id in &ids {
            assert_eq!(state(&storage, *id), Some(SlotState::Free), "round {round}");
        }
    }
}

/// Publishes the objects `names` and drops their leases.
pub(super) fn published<'s>(
    storage: &'s Storage<TestPlatform>,
    dev: &mut Device<'s, '_>,
    names: std::ops::RangeInclusive<u8>,
) -> Vec<AllocationId> {
    names
        .map(|n| {
            let lease = publish(storage, dev, &key(n), &[n; 20]).unwrap();
            let id = lease.id();
            drop(lease);
            storage
                .service_fills(
                    crate::index::ShardIndex(0),
                    4,
                    &mut super::super::publish_tests::budget(),
                )
                .unwrap();
            id
        })
        .collect()
}

/// The control mapping holds one 32-byte full key, deadline, lifetime and record generation per slot, in that order.
#[test]
fn the_control_tables_hold_a_key_per_slot() {
    let storage = storage_with(|_| {});
    let slots = storage.pool().descriptor().slot_count;
    let inventory = storage.table_inventory().unwrap();
    assert_eq!(inventory.keys.1, slots);
    assert_eq!(
        (inventory.deadlines.1, inventory.lifetimes.1),
        (slots, slots)
    );
    assert!(inventory.deadlines.0 >= inventory.keys.0 + 32 * slots);
    assert!(inventory.lifetimes.0 >= inventory.deadlines.0 + 8 * slots);
    assert_eq!(inventory.generations.1, slots);
    assert!(inventory.generations.0 >= inventory.lifetimes.0 + 4 * slots);
}
