//! The raw-byte ledger of one volume: every byte is metadata, free, reserved, resident, retired or waste.
//!
//! `metadata` counts the metadata prefix's bytes; `reserved`, `resident` and `retired` count held extents' logical payload bytes by phase; `waste` counts their record headers and tail padding.
//! Each transition is checked, never wrapped, and all-or-nothing: it returns a new partition or refuses and changes nothing.
//! Every transition moves bytes between terms without creating or destroying any, so the terms sum to the volume's raw bytes after each one.

#[cfg(verus_keep_ghost)]
use crate::model::raw_sum;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// A partition sum is not representable.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerOverflow;

/// Where a held extent's payload bytes sit in the [`RawPartition`].
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldPhase {
    /// Reserved and not yet published.
    Reserved,
    Resident,
    Retired,
}

/// Byte partition of one volume's raw capacity.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawPartition {
    pub metadata: usize,
    pub free: usize,
    pub reserved: usize,
    pub resident: usize,
    pub retired: usize,
    pub waste: usize,
}

impl RawPartition {
    pub fn new(metadata: usize, payload: usize) -> Self {
        fresh(metadata, payload)
    }

    /// Sum of all six terms, which equals the volume's raw bytes for a conserved ledger.
    ///
    /// # Errors
    ///
    /// `LedgerOverflow` if the sum exceeds `usize::MAX`.
    pub fn total(&self) -> Result<usize, LedgerOverflow> {
        summed(*self)
    }

    /// Moves an `extent`-byte extent from free to `payload` reserved bytes plus the rest as waste.
    ///
    /// # Errors
    ///
    /// `LedgerOverflow` when `payload > extent`, `extent > free` or a term would overflow.
    pub(crate) fn reserve(self, extent: usize, payload: usize) -> Result<Self, LedgerOverflow> {
        reserved_from_free(self, extent, payload)
    }

    /// Moves `payload` bytes from reserved to resident.
    ///
    /// # Errors
    ///
    /// `LedgerOverflow` when fewer than `payload` bytes are reserved or `resident` would overflow.
    pub(crate) fn publish(self, payload: usize) -> Result<Self, LedgerOverflow> {
        published(self, payload)
    }

    /// Moves `payload` bytes from resident to retired.
    ///
    /// # Errors
    ///
    /// `LedgerOverflow` when fewer than `payload` bytes are resident or `retired` would overflow.
    pub(crate) fn retire(self, payload: usize) -> Result<Self, LedgerOverflow> {
        retired(self, payload)
    }

    /// Moves an `extent`-byte extent whose `payload` bytes sit in `phase` back to free, with its waste.
    ///
    /// # Errors
    ///
    /// `LedgerOverflow` when `payload > extent`, a term holds fewer bytes than it gives up, or `free` would overflow.
    pub(crate) fn release(
        self,
        phase: HeldPhase,
        extent: usize,
        payload: usize,
    ) -> Result<Self, LedgerOverflow> {
        released(self, phase, extent, payload)
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(made =>
    ensures
        made.metadata == metadata,
        made.free == payload,
        made.reserved == 0 && made.resident == 0 && made.retired == 0 && made.waste == 0,
))]
fn fresh(metadata: usize, payload: usize) -> RawPartition {
    RawPartition {
        metadata,
        free: payload,
        reserved: 0,
        resident: 0,
        retired: 0,
        waste: 0,
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(sum =>
    ensures
        sum matches Ok(total) ==> total == raw_sum(p),
        sum is Err ==> raw_sum(p) > usize::MAX,
))]
fn summed(p: RawPartition) -> Result<usize, LedgerOverflow> {
    let Some(sum) = p.metadata.checked_add(p.free) else {
        return Err(LedgerOverflow);
    };
    let Some(sum) = sum.checked_add(p.reserved) else {
        return Err(LedgerOverflow);
    };
    let Some(sum) = sum.checked_add(p.resident) else {
        return Err(LedgerOverflow);
    };
    let Some(sum) = sum.checked_add(p.retired) else {
        return Err(LedgerOverflow);
    };
    match sum.checked_add(p.waste) {
        Some(sum) => Ok(sum),
        None => Err(LedgerOverflow),
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        next matches Ok(n) ==> payload <= extent && n.metadata == p.metadata && raw_sum(n) == raw_sum(p)
            && n.free == p.free - extent && n.reserved == p.reserved + payload
            && n.waste == p.waste + (extent - payload)
            && n.resident == p.resident && n.retired == p.retired,
        next is Err ==> payload > extent || extent > p.free
            || p.reserved + payload > usize::MAX || p.waste + (extent - payload) > usize::MAX,
))]
fn reserved_from_free(
    p: RawPartition,
    extent: usize,
    payload: usize,
) -> Result<RawPartition, LedgerOverflow> {
    let (Some(waste), Some(free)) = (extent.checked_sub(payload), p.free.checked_sub(extent))
    else {
        return Err(LedgerOverflow);
    };
    let (Some(reserved), Some(waste)) =
        (p.reserved.checked_add(payload), p.waste.checked_add(waste))
    else {
        return Err(LedgerOverflow);
    };
    Ok(RawPartition {
        free,
        reserved,
        waste,
        ..p
    })
}

#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        next matches Ok(n) ==> n.metadata == p.metadata && raw_sum(n) == raw_sum(p)
            && n.reserved == p.reserved - payload && n.resident == p.resident + payload
            && n.free == p.free && n.retired == p.retired && n.waste == p.waste,
        next is Err ==> payload > p.reserved || p.resident + payload > usize::MAX,
))]
fn published(p: RawPartition, payload: usize) -> Result<RawPartition, LedgerOverflow> {
    let (Some(reserved), Some(resident)) = (
        p.reserved.checked_sub(payload),
        p.resident.checked_add(payload),
    ) else {
        return Err(LedgerOverflow);
    };
    Ok(RawPartition {
        reserved,
        resident,
        ..p
    })
}

#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        next matches Ok(n) ==> n.metadata == p.metadata && raw_sum(n) == raw_sum(p)
            && n.resident == p.resident - payload && n.retired == p.retired + payload
            && n.free == p.free && n.reserved == p.reserved && n.waste == p.waste,
        next is Err ==> payload > p.resident || p.retired + payload > usize::MAX,
))]
fn retired(p: RawPartition, payload: usize) -> Result<RawPartition, LedgerOverflow> {
    let (Some(resident), Some(retired)) = (
        p.resident.checked_sub(payload),
        p.retired.checked_add(payload),
    ) else {
        return Err(LedgerOverflow);
    };
    Ok(RawPartition {
        resident,
        retired,
        ..p
    })
}

#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        next matches Ok(n) ==> payload <= extent && n.metadata == p.metadata && raw_sum(n) == raw_sum(p)
            && n.free == p.free + extent && n.waste == p.waste - (extent - payload)
            && n.reserved == (if phase == HeldPhase::Reserved { p.reserved - payload } else { p.reserved as int })
            && n.resident == (if phase == HeldPhase::Resident { p.resident - payload } else { p.resident as int })
            && n.retired == (if phase == HeldPhase::Retired { p.retired - payload } else { p.retired as int }),
        next is Err ==> payload > extent || p.free + extent > usize::MAX || p.waste < extent - payload
            || (if phase == HeldPhase::Reserved { p.reserved as int } else if phase == HeldPhase::Resident { p.resident as int } else { p.retired as int }) < payload,
))]
fn released(
    p: RawPartition,
    phase: HeldPhase,
    extent: usize,
    payload: usize,
) -> Result<RawPartition, LedgerOverflow> {
    let Some(waste) = extent.checked_sub(payload) else {
        return Err(LedgerOverflow);
    };
    let (Some(free), Some(waste)) = (p.free.checked_add(extent), p.waste.checked_sub(waste)) else {
        return Err(LedgerOverflow);
    };
    let held = match phase {
        HeldPhase::Reserved => p.reserved,
        HeldPhase::Resident => p.resident,
        HeldPhase::Retired => p.retired,
    };
    let Some(held) = held.checked_sub(payload) else {
        return Err(LedgerOverflow);
    };
    let next = RawPartition { free, waste, ..p };
    Ok(match phase {
        HeldPhase::Reserved => RawPartition {
            reserved: held,
            ..next
        },
        HeldPhase::Resident => RawPartition {
            resident: held,
            ..next
        },
        HeldPhase::Retired => RawPartition {
            retired: held,
            ..next
        },
    })
}
