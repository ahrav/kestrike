//! Seeding the device with `PATTERN` exposes writes to the metadata prefix and bytes beyond the volume.

use super::FillReserveError;
use super::budget::WorkBudget;
use super::config::StorageConfig;
use super::device::sim::{Captured, SimControl};
use super::device::{CommandToken, IO_UNIT, Operation};
use super::geometry::EXTENT_PAYLOAD;
use super::owner::Storage;
use super::publish_tests::{PAGE, TRIES, budget, index_config, key, storage_config, storage_from};
use super::test_platform::TestPlatform;
use super::volume::Bound;
use super::volume_fixture::{Device, MEDIA, ample_io, arena_with, settle};
use super::writable_tests::{bytes, reserve};
use crate::index::IndexConfig;

const METADATA_UNITS: u64 = 17;
const PATTERN: u8 = 0xA5;

fn prefixed(payload_units: u64, body_cap: usize) -> Storage<TestPlatform> {
    let fill_records = [4];
    let index = IndexConfig {
        fills: &fill_records,
        ..index_config(&[8], (1, 1), 1)
    };
    let storage = storage_from(
        &config(payload_units, body_cap),
        &index,
        TestPlatform::heap(PAGE),
    );
    storage.platform.ticks(&[Some(1)]);
    storage
}

fn config(payload_units: u64, body_cap: usize) -> StorageConfig {
    let mut volume =
        crate::storage::test_volume_with(payload_units as usize * IO_UNIT, METADATA_UNITS, 8);
    volume.block_roots = 1;
    volume.alloc_search_words = super::extent::work_bound(payload_units, 8, 64);
    StorageConfig {
        body_cap,
        metadata_cap: Some(64),
        object_rights: 8,
        volume,
        ..storage_config(8)
    }
}

fn largest_units(body_cap: usize) -> u64 {
    config(1024, body_cap)
        .validate()
        .unwrap()
        .largest_geometry()
        .total_units()
}

fn payload_bytes(payload_units: u64) -> (u64, u64) {
    (
        METADATA_UNITS * IO_UNIT as u64,
        (METADATA_UNITS + payload_units) * IO_UNIT as u64,
    )
}

fn seed(control: &SimControl) {
    control.write_device(0, &vec![PATTERN; MEDIA as usize]);
    control.clear_capture();
}

fn untouched(control: &SimControl, payload_units: u64) {
    let (_, end) = payload_bytes(payload_units);
    let outside = |at: u64, len: u64| control.device(at as usize, len as usize);
    assert!(
        outside(end, MEDIA - end)
            .iter()
            .all(|&byte| byte == PATTERN),
        "a byte past the volume changed"
    );
}

fn accepted(control: &SimControl) -> usize {
    control.accepted(Operation::Read) + control.accepted(Operation::Write)
}

/// The payload commands the device accepted since `accepted_before`, each checked to lie inside the payload; a command the volume bound as metadata is skipped by its token, whatever its address.
fn window(
    dev: &Device<'_, '_>,
    accepted_before: usize,
    payload_units: u64,
) -> Vec<(Operation, u64, u64)> {
    let control = &dev.control;
    let capture = control.capture();
    assert!(!capture.overflow, "the capture overflowed");
    let (bound, overflow) = dev.volume.bound_tokens();
    assert!(!overflow, "the volume's token record overflowed");
    let metadata = |token: &CommandToken| {
        bound
            .iter()
            .any(|(bound, owner)| bound == token && matches!(owner, Bound::Metadata { .. }))
    };
    let mut total = 0;
    let commands: Vec<_> = capture
        .events
        .iter()
        .filter_map(|event| match event {
            Captured::Submitted {
                token,
                operation,
                device,
                ..
            } => {
                total += 1;
                (!metadata(token)).then(|| (*operation, device.start(), device.end()))
            }
            Captured::Delivered { .. } => None,
        })
        .collect();
    assert_eq!(
        total,
        accepted(control) - accepted_before,
        "every accepted command captured"
    );
    let (start, end) = payload_bytes(payload_units);
    for &(operation, at, until) in &commands {
        assert!(
            start <= at && until <= end,
            "{operation:?} [{at}, {until}) leaves [{start}, {end})"
        );
    }
    control.clear_capture();
    commands
}

fn reclaim(storage: &Storage<TestPlatform>) {
    for _ in 0..4 {
        let _ = storage.certify(&mut WorkBudget::new(1 << 12)).unwrap();
        storage.service(&mut WorkBudget::new(1 << 12)).unwrap();
        super::attempt_tests::service(storage);
    }
}

#[test]
fn the_largest_multi_extent_object_fills_an_exact_fit_from_payload_unit_zero() {
    let body_cap = EXTENT_PAYLOAD as usize + 3 * 8192;
    let cmax = largest_units(body_cap);
    let payload_units = cmax + 1;
    let storage = prefixed(payload_units, body_cap);
    let buffers = arena_with(4, 6);
    let mut dev = Device::new(&storage, &buffers);
    seed(&dev.control);
    let (start, end) = payload_bytes(payload_units);
    let before = accepted(&dev.control);
    let payload = bytes(64 + body_cap, 1);
    let mut fill = reserve(&storage, &key(1), 64, body_cap).expect("Cmax fits the exact volume");
    dev.fill(&mut fill, &payload);
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    let writes = window(&dev, before, payload_units);
    assert!(writes.iter().all(|(op, ..)| *op == Operation::Write));
    assert!(
        writes.iter().any(|&(_, at, _)| at == start),
        "payload unit 0 written"
    );
    assert_eq!(
        writes.iter().map(|&(_, _, until)| until).max(),
        Some(end - IO_UNIT as u64),
        "the object's last extent ends at the clean reserve's unit"
    );
    let before = accepted(&dev.control);
    assert_eq!(dev.read(&lease), payload);
    let reads = window(&dev, before, payload_units);
    assert!(reads.len() > 2, "a two-extent read spans several commands");
    assert!(
        writes.len() > 2,
        "the two extents take more than two write commands"
    );
    assert!(
        reads
            .iter()
            .any(|&(_, _, until)| until % 512 == 0 && until % IO_UNIT as u64 != 0),
        "a read ends on a sector boundary inside a unit"
    );
    assert!(
        reads.iter().any(|&(_, at, _)| at == start),
        "a read starts at payload unit 0"
    );
    untouched(&dev.control, payload_units);
    let raw = storage.pool_report().unwrap().ledger.unwrap().raw;
    assert_eq!(raw.metadata, METADATA_UNITS as usize * IO_UNIT);
    assert_eq!(raw.free, IO_UNIT, "only the clean reserve is free");
}

#[test]
fn a_fill_in_the_last_payload_units_ends_at_the_volume_s_last_byte() {
    let payload_units = 8;
    let storage = prefixed(payload_units, 7 * IO_UNIT - 200);
    let buffers = arena_with(4, 6);
    let mut dev = Device::new(&storage, &buffers);
    seed(&dev.control);
    let (start, end) = payload_bytes(payload_units);
    let first = bytes(3000, 2);
    let second = bytes(5 * IO_UNIT - 300, 3);
    let last = bytes(2 * IO_UNIT - 300, 4);
    let mut leases = Vec::new();
    for (n, payload) in [(1, &first), (2, &second)] {
        let before = accepted(&dev.control);
        let mut fill = reserve(&storage, &key(n), 0, payload.len()).unwrap();
        dev.fill(&mut fill, payload);
        leases.push(
            fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .unwrap(),
        );
        window(&dev, before, payload_units);
    }
    drop(leases.remove(0));
    super::attempt_tests::invalidate(&storage, &key(1)).unwrap();
    dev.persist_journal();
    dev.control.clear_capture();
    reclaim(&storage);
    let before = accepted(&dev.control);
    assert_eq!(
        reserve(&storage, &key(9), 0, 3 * IO_UNIT - 300).err(),
        Some(FillReserveError::CleanReserve),
    );
    let mut cancelled = reserve(&storage, &key(8), 0, IO_UNIT - 300).unwrap();
    let mut taken = 0;
    while taken == 0 {
        taken = cancelled
            .receive(&mut dev.volume, &bytes(IO_UNIT - 300, 8), &mut ample_io())
            .unwrap();
    }
    drop(cancelled);
    settle(&mut dev.volume, &dev.control);
    reclaim(&storage);
    window(&dev, before, payload_units);
    let before = accepted(&dev.control);
    let mut fill = reserve(&storage, &key(3), 0, last.len()).unwrap();
    dev.fill(&mut fill, &last);
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    let writes = window(&dev, before, payload_units);
    assert_eq!(
        writes.iter().map(|&(_, _, until)| until).max(),
        Some(end),
        "a write ends at the volume's last byte"
    );
    let before = accepted(&dev.control);
    assert_eq!(dev.read(&lease), last);
    assert_eq!(dev.read(&leases[0]), second);
    let reads = window(&dev, before, payload_units);
    assert!(
        reads
            .iter()
            .any(|&(_, at, _)| at == end - 2 * IO_UNIT as u64),
        "a read starts at the last object's first unit"
    );
    // Every read lies in the payload, past the metadata prefix.
    assert!(
        reads
            .iter()
            .filter(|&&(operation, _, _)| operation == Operation::Read)
            .all(|&(_, at, _)| at >= start)
    );
    untouched(&dev.control, payload_units);
    let raw = storage.pool_report().unwrap().ledger.unwrap().raw;
    assert_eq!(raw.metadata, METADATA_UNITS as usize * IO_UNIT);
    assert_eq!(
        raw.free + raw.reserved + raw.resident + raw.retired + raw.waste,
        payload_units as usize * IO_UNIT
    );
}

#[test]
fn the_largest_object_s_later_extent_ends_at_the_volume_s_last_byte() {
    let body_cap = EXTENT_PAYLOAD as usize + 3 * 8192;
    let cmax = largest_units(body_cap);
    let payload_units = cmax + 2;
    let storage = prefixed(payload_units, body_cap);
    let buffers = arena_with(4, 6);
    let mut dev = Device::new(&storage, &buffers);
    seed(&dev.control);
    let (start, end) = payload_bytes(payload_units);
    let mut leases = Vec::new();
    for n in [1, 2] {
        let before = accepted(&dev.control);
        let mut fill = reserve(&storage, &key(n), 0, 100).unwrap();
        dev.fill(&mut fill, &bytes(100, n.into()));
        leases.push(
            fill.publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
                .unwrap(),
        );
        window(&dev, before, payload_units);
    }
    drop(leases.remove(0));
    super::attempt_tests::invalidate(&storage, &key(1)).unwrap();
    dev.persist_journal();
    dev.control.clear_capture();
    reclaim(&storage);
    let before = accepted(&dev.control);
    let payload = bytes(64 + body_cap, 9);
    let mut fill = reserve(&storage, &key(3), 64, body_cap).expect("Cmax fits the end run");
    dev.fill(&mut fill, &payload);
    let lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    let writes = window(&dev, before, payload_units);
    assert_eq!(
        writes.iter().map(|&(_, _, until)| until).max(),
        Some(end),
        "the largest object's later extent ends at the volume's last byte"
    );
    assert!(
        writes
            .iter()
            .all(|&(_, at, _)| at >= start + 2 * IO_UNIT as u64),
        "the object lands past the two one-unit objects' units"
    );
    let first_extent = config(1024, body_cap)
        .validate()
        .unwrap()
        .largest_geometry()
        .units(0);
    let later = start + (2 + first_extent) * IO_UNIT as u64;
    assert!(
        writes
            .iter()
            .filter(|&&(_, _, until)| until == end)
            .all(|&(_, at, _)| at >= later),
        "the command ending at the volume's last byte belongs to the later extent"
    );
    let before = accepted(&dev.control);
    assert_eq!(dev.read(&lease), payload);
    window(&dev, before, payload_units);
    untouched(&dev.control, payload_units);
}

/// A storage whose payload starts one unit below the test's `M` writes
/// payload unit 0 into the metadata prefix; `window`, judging against the
/// test's own `M` and `V`, must reject that write.
#[test]
#[should_panic(expected = "leaves [")]
fn negative_control_a_payload_one_unit_low_writes_into_the_metadata_prefix() {
    let payload_units = 8;
    let mut low = config(payload_units, 7 * IO_UNIT - 200);
    low.volume.metadata_units = METADATA_UNITS - 1;
    low.volume.raw_bytes -= IO_UNIT;
    let fill_records = [4];
    let index = IndexConfig {
        fills: &fill_records,
        ..index_config(&[8], (1, 1), 1)
    };
    let storage = storage_from(&low, &index, TestPlatform::heap(PAGE));
    storage.platform.ticks(&[Some(1)]);
    let buffers = arena_with(4, 6);
    let mut dev = Device::new(&storage, &buffers);
    seed(&dev.control);
    let before = accepted(&dev.control);
    let payload = bytes(3000, 1);
    let mut fill = reserve(&storage, &key(1), 0, payload.len()).unwrap();
    dev.fill(&mut fill, &payload);
    let _lease = fill
        .publish(&mut dev.volume, u64::MAX, TRIES, &mut budget())
        .unwrap();
    window(&dev, before, payload_units);
}

#[test]
fn the_owner_s_run_work_bound_counts_payload_units() {
    let large = {
        let mut config = config(64, 7 * IO_UNIT - 200);
        config.volume.metadata_units = 4096;
        config.volume.raw_bytes = (4096 + 64) * IO_UNIT;
        let fill_records = [4];
        let index = IndexConfig {
            fills: &fill_records,
            ..index_config(&[8], (1, 1), 1)
        };
        storage_from(&config, &index, TestPlatform::heap(PAGE))
    };
    assert_eq!(
        large.pool().run_work(8),
        super::extent::work_bound(64, 8, 8),
        "the bound follows the payload units"
    );
    assert_ne!(
        super::extent::work_bound(64, 8, 8),
        super::extent::work_bound(4096 + 64, 8, 8),
        "a volume-sized bound would differ"
    );
}
