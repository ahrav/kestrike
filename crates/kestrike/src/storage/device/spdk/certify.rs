//! The SPDK driver's staging decisions: which record a completion callback stages, which staged terminals a poll certifies, how many a pick delivers, and when register reads prove the controller disabled.
//!
//! The verifier checks these value-only decisions; the driver performs the native calls.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Record {
    Free,
    Accepted { token: u64 },
    Staged { token: u64, status: u16 },
}

/// Only a free record takes a newly accepted command; the free list holds the records never taken, refused, delivered, or freed by a proven stop, and the driver's debug assertion checks each take.
#[cfg_attr(verus_keep_ghost, verus_spec(free =>
    ensures free == (record is Free),
))]
#[inline(always)]
pub(super) fn takes(record: Record) -> bool {
    matches!(record, Record::Free)
}

/// A completion callback stages an accepted command's terminal; a callback for a free or already staged record is a stray and changes nothing.
#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        record matches Record::Accepted { token } ==> next == Some(Record::Staged { token, status }),
        !(record is Accepted) ==> next is None,
))]
#[inline(always)]
pub(super) fn stage(record: Record, status: u16) -> Option<Record> {
    match record {
        Record::Accepted { token } => Some(Record::Staged { token, status }),
        _ => None,
    }
}

/// A delivery hands the table a staged record's token and status.
#[cfg_attr(verus_keep_ghost, verus_spec(terminal =>
    ensures
        record matches Record::Staged { token, status } ==> terminal == Some((token, status)),
        !(record is Staged) ==> terminal is None,
))]
#[inline(always)]
pub(super) fn terminal(record: Record) -> Option<(u64, u16)> {
    match record {
        Record::Staged { token, status } => Some((token, status)),
        _ => None,
    }
}

/// A completion poll certifies the terminals staged during it when `rc >= 0` and the controller's failure flag is clear; a terminal staged during any other poll may be a software abort with the device still able to reach the buffer.
#[cfg_attr(verus_keep_ghost, verus_spec(certified =>
    ensures certified == (rc >= 0 && !failed),
))]
#[inline(always)]
pub(super) fn certifies(rc: i32, failed: bool) -> bool {
    rc >= 0 && !failed
}

/// One pick delivers at most the sink's room of certified terminals.
#[cfg_attr(verus_keep_ghost, verus_spec(count =>
    ensures count <= room, count <= certified, count == room || count == certified,
))]
#[inline(always)]
pub(super) fn deliverable(room: usize, certified: usize) -> usize {
    room.min(certified)
}

/// Register reads prove the controller disabled when both reads are valid (a failed access reads all ones), CC.EN is clear and CSTS.RDY is clear; a pending disable stays unproven until they do.
#[cfg_attr(verus_keep_ghost, verus_spec(proven =>
    ensures proven == (cc != u32::MAX && csts != u32::MAX && cc & en_mask == 0 && csts & rdy_mask == 0),
))]
#[inline(always)]
pub(super) fn disable_proven(cc: u32, csts: u32, en_mask: u32, rdy_mask: u32) -> bool {
    cc != u32::MAX && csts != u32::MAX && cc & en_mask == 0 && csts & rdy_mask == 0
}
