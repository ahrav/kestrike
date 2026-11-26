//! `CommandTable::new` charges the budget the bytes its metadata allocates:
//! the charge grows by one slot's bytes per slot of depth, and a driver with
//! reservation limits adds its reservation slots to the same charge. A table
//! over such a driver holds the arena's reservation buffers while it is alive
//! and returns them when it drops.

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::TestPlatform;
use super::sim::{Mode, SimConfig, SimDisk, StatusForm, sim};
use super::sim_tests::LEN;
use super::{
    BufferArena, BufferConfig, CommandTable, CommandToken, CompletionSink, DeviceGeometry,
    DeviceRange, Disk, DmaRange, PoolKind, PoolSpec, QuiesceStatus, ReservationLimits,
    SubmitRefusal,
};
use crate::instrument;
use std::cell::Cell;

const QUEUE_DEPTH: u16 = 20;

const POOLS: [PoolSpec; 4] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: 16,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 16,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
    PoolSpec {
        kind: PoolKind::Reservation,
        count: 2,
        buffer_len: 4096,
    },
];

fn arena() -> BufferArena<TestPlatform> {
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &POOLS,
    }
    .validate()
    .unwrap();
    BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap()
}

fn plain_disk() -> SimDisk {
    sim(SimConfig {
        seed: 1,
        capacity: 64 * u64::from(LEN),
        queue_depth: u32::from(QUEUE_DEPTH),
        max_transfer: LEN,
        form: StatusForm::Kernel,
        mode: Mode::Direct,
        script: super::sim::SCRIPT,
    })
    .0
}

/// A driver that declares reservation limits of two commands and is never
/// given a command. With `answered` set, only that many reads of its limits
/// answer them and every later read answers `None`.
#[derive(Default)]
struct Reserving {
    answered: Option<usize>,
    reads: Cell<usize>,
}

// SAFETY: the read and write submits panic before any device access and the default reservation submit refuses; the
// tests construct a table over this driver, read the table's report and read the driver's reservation limits. With
// `answered` unset every read of `reservation_limits` answers the same limits. With `answered` set to `Some(n)`, the
// first `n` reads answer the limits and every later read answers `None`, against the trait's rule that the limits stay
// constant for the driver's life.
unsafe impl Disk for Reserving {
    fn geometry(&self) -> DeviceGeometry {
        DeviceGeometry {
            capacity: 1 << 20,
            max_transfer: LEN,
            block_size: 4096,
            queue_depth: u32::from(QUEUE_DEPTH),
        }
    }
    fn reservation_limits(&self) -> Option<ReservationLimits> {
        let read = self.reads.get();
        self.reads.set(read + 1);
        self.answered
            .is_none_or(|answered| read < answered)
            .then(|| ReservationLimits::new(2, 2, 10, 10).unwrap())
    }
    unsafe fn submit_read(
        &mut self,
        _: CommandToken,
        _: DeviceRange,
        _: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        unreachable!("construction never submits")
    }
    unsafe fn submit_write(
        &mut self,
        _: CommandToken,
        _: DeviceRange,
        _: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        unreachable!("construction never submits")
    }
    fn pick_completions(&mut self, _: &mut CompletionSink<'_>) {}
    fn quiesce(&mut self) -> QuiesceStatus {
        QuiesceStatus::Pending
    }
}

/// What one construction showed.
struct Seen {
    /// The bytes `CommandTable::new` alone charged to a fresh budget.
    charged: usize,
    /// The bytes it allocated on this thread.
    allocated: usize,
    /// The reservation buffers the arena held free while the table was alive.
    free_alive: u32,
    /// The same after the table dropped.
    free_dropped: u32,
}

/// Measures `CommandTable::new` alone at `depth`, over a driver and an arena
/// built before the measurement. The charge, the depth and the reservation
/// pool are read while the table is alive, and the pool again once it dropped.
fn construction<D: Disk>(disk: D, arena: &BufferArena<TestPlatform>, depth: u16) -> Seen {
    let mut budget = EngineBudget::new(usize::MAX);
    let (table, charged, allocated) = instrument::charged(&mut budget, |budget| {
        CommandTable::new(disk, arena, depth, budget).map_err(|(error, _)| error)
    });
    let table = table.unwrap();
    assert_eq!(table.report().depth, depth);
    assert_eq!(budget.used(), charged);
    let free_alive = arena.report(PoolKind::Reservation).free;
    drop(table);
    Seen {
        charged,
        allocated,
        free_alive,
        free_dropped: arena.report(PoolKind::Reservation).free,
    }
}

/// Over a driver without reservation limits the charge is per slot and
/// covers what the table allocates: at depths 1, 2, 4 and 8 the bytes charged
/// equal the bytes the construction allocated on this thread, the depth
/// times the charge of a one-slot table, and `metadata_bytes` of the depth.
/// The allocated bytes are the growth of this thread's allocator byte counter
/// across the construction, which counts the records, the free list and the
/// completion scratch; the equality holds the charge to all three. No
/// reservation buffer leaves the arena, while a table is alive or after it.
#[test]
fn a_table_without_reservations_charges_what_its_slots_allocate_at_each_depth() {
    let arena = arena();
    let slot = construction(plain_disk(), &arena, 1).charged;
    assert!(slot > 0, "one slot has metadata");
    for depth in [1u16, 2, 4, 8] {
        let seen = construction(plain_disk(), &arena, depth);
        assert_eq!(
            seen.charged, seen.allocated,
            "depth {depth}: the charge is the records, free list and completion scratch allocated"
        );
        assert_eq!(
            seen.charged,
            usize::from(depth) * slot,
            "depth {depth}: the charge is per slot"
        );
        assert_eq!(
            seen.charged,
            CommandTable::<SimDisk>::metadata_bytes(depth),
            "depth {depth}: the documented charge is the one made"
        );
        assert_eq!(
            (seen.free_alive, seen.free_dropped),
            (2, 2),
            "depth {depth}: a table without reservations takes no reservation buffer"
        );
    }
}

/// A driver with reservation limits adds its reservation slots to the same
/// charge: at depths 4 and 8 the bytes charged equal the bytes allocated,
/// and they exceed the charge of a table without reservations at that depth
/// by `reservation_metadata_bytes`. The table holds both reservation buffers
/// while it is alive, and a dropped table returns both to the arena.
#[test]
fn a_table_with_reservations_charges_its_slots_and_reservation_slots_together() {
    let arena = arena();
    let reservation = CommandTable::<Reserving>::reservation_metadata_bytes(&Reserving::default());
    assert!(reservation > 0, "two reservation slots have metadata");
    for depth in [4u16, 8] {
        let plain = construction(plain_disk(), &arena, depth).charged;
        let seen = construction(Reserving::default(), &arena, depth);
        one_charge_covers(depth, seen.charged, seen.allocated);
        assert_eq!(
            seen.charged,
            plain + reservation,
            "depth {depth}: the reservation slots add to the per-slot charge"
        );
        assert_eq!(
            seen.free_alive, 0,
            "depth {depth}: a live table holds both reservation buffers"
        );
        assert_eq!(
            seen.free_dropped, 2,
            "depth {depth}: a dropped table returns its reservation buffers"
        );
    }
    assert_eq!(
        arena.report(PoolKind::Reservation).free,
        2,
        "a dropped table returns its reservation buffers"
    );
}

/// Asserts that the bytes `charged` for a table over the reserving driver equal the bytes its construction
/// `allocated`.
fn one_charge_covers(depth: u16, charged: usize, allocated: usize) {
    assert_eq!(
        charged, allocated,
        "depth {depth}: one charge covers the table and its reservation slots"
    );
}

/// The planted driver: the reserving driver answers its limits to the table's first two reads, the reserve check and
/// the reservation share, and answers none to the read behind the charge and every later read, so the table acquires
/// and allocates its two reservation slots while charging the slots alone, as a construction that left out the
/// reservation slots' metadata would, and the allocation check rejects the charge at depth 4.
#[test]
#[should_panic(expected = "depth 4: one charge covers the table and its reservation slots")]
fn negative_control_a_charge_without_the_reservation_slots_misses_their_allocation() {
    let arena = arena();
    let reservation = CommandTable::<Reserving>::reservation_metadata_bytes(&Reserving::default());
    let plain = construction(plain_disk(), &arena, 4).charged;
    let planted = Reserving {
        answered: Some(2),
        ..Reserving::default()
    };
    let seen = construction(planted, &arena, 4);
    if seen.charged != seen.allocated {
        assert_eq!(
            (seen.charged, seen.allocated.checked_sub(seen.charged)),
            (plain, Some(reservation)),
            "the planted table charges a plain table's slots and allocates its reservation slots beyond that charge"
        );
    }
    one_charge_covers(4, seen.charged, seen.allocated);
}
