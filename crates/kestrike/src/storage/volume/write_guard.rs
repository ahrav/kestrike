//! The write guard, compiled only in test builds, records W1, "a payload write overlapped an extent another slot
//! holds". W1 states that owned slots hold disjoint extents: `O-CUSTODY` forbids overlapping writable extents, the
//! obligation record `owned-extents-disjoint-ledger-matches-census` binds the census of the same property, and
//! `ReuseTwoProofs` in `tla/Recovery.tla` models extent reuse.
//!
//! `Volume::write_at` calls [`check`], which records only on an armed thread, once per write that reaches a device
//! range, after the range is computed and before the slot word's install check and the driver call. The check copies
//! the slot table's held direct extents through `Storage::held_extents_into` and keeps the thread's first conflict. It
//! reads the range and returns nothing, so the write's result, the slot words, the charge counts and the driver call
//! are the same armed or unarmed. The guard records and never refuses or panics.
//!
//! W1 checks payload writes against direct extents. The lens skips slots with malformed words or unrecognized
//! states. A held slot qualifies for comparison only when its locator decodes to a direct extent inside the payload
//! region; the lens counts all other held slots as skipped, including those with sequence-block locators. A clean record
//! requires that count to be zero. A slot freed too early falls under the reuse rule of `recovery::durable`.
//!
//! The takeover history tests arm the guard for each serving tenure after its bootstrap ends, and the storage volume
//! unit tests arm it around the writes each test checks. The serving tenures' payload writes are the deposed fill,
//! the allocator control and the seeded cycles' fills. A clean record covers exactly the writes the guard checked in
//! those windows.
//!
//! The check reads each slot's word and locator with atomic loads alone, so the pool gate's word and the tables it
//! guards are the same armed or unarmed, and the check runs whatever the gate's state. `Storage::holdings_into` copies
//! the extents of the same slot states under one pool-gate hold for the conservation census: it expands sequence
//! blocks and refuses the whole snapshot at the first held locator it cannot read, where this lens counts that slot
//! as skipped and compares the write with the rest.
//!
//! Ungated slot-word reads rely on the armed thread performing every slot-word change after a load completes: the
//! warm stages and the recovery helper threads finish their slot-word writes before the load completes, and a claim
//! stores the word and then its locator within a single callout-free gate hold.

use std::cell::Cell;

use super::super::allocation::AllocationId;
use super::super::device::DeviceRange;
use super::super::lenses::HeldExtent;
use super::super::os::Platform;
use super::super::owner::Storage;

pub(crate) const W1: &str = "a payload write overlapped an extent another slot holds";

/// A payload write's whole range and the slot whose held extent it intersects, each slot named by its index and
/// incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Conflict {
    pub(crate) rule: &'static str,
    pub(crate) writer: AllocationId,
    pub(crate) holder: AllocationId,
    /// The range covers the entire payload write.
    pub(crate) range: DeviceRange,
}

/// The guard records the armed thread's first conflict, the maximum number of slots the lens skipped on any one
/// checked write, and the number of writes checked against a live slot table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Guarded {
    pub(crate) first: Option<Conflict>,
    pub(crate) skipped: u64,
    pub(crate) checked: u64,
}

impl Guarded {
    /// `later` must follow `self` in observation order so `first` remains the earliest conflict. `skipped` keeps the
    /// larger per-write maximum and `checked` sums.
    pub(crate) fn merge(&mut self, later: Self) {
        self.first = self.first.or(later.first);
        self.skipped = self.skipped.max(later.skipped);
        self.checked += later.checked;
    }

    /// A clean record has `first == None` and `skipped == 0`.
    pub(crate) fn clean(&self) -> bool {
        self.first.is_none() && self.skipped == 0
    }
}

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static SEEN: Cell<Guarded> = const {
        Cell::new(Guarded {
            first: None,
            skipped: 0,
            checked: 0,
        })
    };
}

/// The first held extent, in `held`'s order, of a slot other than `own`'s that shares at least one device byte with
/// `range`.
pub(crate) fn conflict(
    held: &[HeldExtent],
    own: AllocationId,
    range: DeviceRange,
) -> Option<Conflict> {
    let other = |extent: &&HeldExtent| extent.holder.slot() != own.slot();
    let overlaps = |extent: &&HeldExtent| {
        extent.bytes.start.max(range.start()) < extent.bytes.end.min(range.end())
    };
    let holder = held.iter().filter(other).find(overlaps)?;
    Some(Conflict {
        rule: W1,
        writer: own,
        holder: holder.holder,
        range,
    })
}

/// Sets the thread's armed flag and returns its prior value, which a nested tenure restores.
pub(crate) fn arm(armed: bool) -> bool {
    ARMED.with(|cell| cell.replace(armed))
}

/// Takes what the thread's guard saw, leaving it empty.
pub(crate) fn take() -> Guarded {
    SEEN.with(Cell::take)
}

pub(crate) fn armed() -> bool {
    ARMED.with(Cell::get)
}

/// On an armed thread whose storage is live, compares `writer`'s write of `range` with the slot table's held direct
/// extents. Each comparison increments `checked`, updates `skipped` to the maximum number of slots skipped on any
/// one write, and stores the W1 conflict in `first` when the write overlaps another slot's extent and `first` is
/// empty. The write's outcome is independent of the guard.
pub(crate) fn check<P: Platform>(storage: &Storage<P>, writer: AllocationId, range: DeviceRange) {
    if !ARMED.with(Cell::get) {
        return;
    }
    let mut held = Vec::new();
    let Ok(skipped) = storage.held_extents_into(&mut held) else {
        return;
    };
    let write = Guarded {
        first: conflict(&held, writer, range),
        skipped,
        checked: 1,
    };
    SEEN.with(|cell| {
        let mut seen = cell.get();
        seen.merge(write);
        cell.set(seen);
    });
}
