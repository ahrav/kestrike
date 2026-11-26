//! A slot's position word, the durable prefix's advance over a persisted block, and the reuse rule service applies before it returns a retired slot's extents.
//!
//! Each function reads plain values; Verus checks each against its `ensures` contract, and the suffix log and service apply them.
//! A position packs a block's LSN into the high 32 bits and the record's index in that block into the low 32. [`NO_RECORD`] marks a slot that waits on no block, and [`UNSTAGED`] is a reserved word that [`reusable`] refuses while admission is open; both lie above every position.
//! The durable prefix is an exclusive LSN frontier that [`advance`] moves over a gapless run of persisted blocks: a tenure's suffix blocks from its start up to `prefix`. The suffix log starts it at the tenure's first LSN, and the volume's delta writer publishes it to the service word, which starts at zero.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The position word of a slot whose retirement waits on no block; [`reusable`] admits its return at zero rights.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const NO_RECORD: u64 = u64::MAX;

/// A reserved position word between every position and [`NO_RECORD`]; [`reusable`] refuses it while admission is open.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UNSTAGED: u64 = u64::MAX - 1;

/// The highest LSN a position names, so every position stays below both sentinels.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const LSN_LIMIT: u64 = 0xFFFF_FFFE;

/// The position of record `index` in block `lsn`.
#[cfg_attr(verus_keep_ghost, verus_spec(packed =>
    requires
        lsn <= LSN_LIMIT,
    ensures
        packed < UNSTAGED,
        packed >> 32u64 == lsn,
))]
pub fn position(lsn: u64, index: u32) -> u64 {
    let packed = (lsn << 32) | index as u64;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(lsn <= 0xFFFF_FFFEu64 ==> ((lsn << 32u64) | (index as u64)) < 0xFFFF_FFFF_FFFF_FFFEu64
            && ((lsn << 32u64) | (index as u64)) >> 32u64 == lsn) by (bit_vector);
    }
    packed
}

/// The durable prefix once block `lsn` is persisted over `prefix`: one more when `lsn` is the block right after the gapless front, and unchanged otherwise.
#[cfg_attr(verus_keep_ghost, verus_spec(advanced =>
    requires
        prefix < u64::MAX,
    ensures
        lsn == prefix ==> advanced == prefix + 1,
        lsn != prefix ==> advanced == prefix,
        advanced >= prefix,
))]
pub fn advance(prefix: u64, lsn: u64) -> u64 {
    if lsn == prefix { prefix + 1 } else { prefix }
}

/// Whether service may return a retired slot whose word counts `refs` rights and whose position word is `position`, against the durable prefix `prefix` this service call loaded, with `closed` when the call observed admission closed under the gate.
///
/// A returned slot holds no right, and while admission is open a slot whose record is needed returns only once the block naming it lies inside the durable prefix.
#[cfg_attr(verus_keep_ghost, verus_spec(admitted =>
    ensures
        admitted ==> refs == 0,
        admitted && !closed && position != NO_RECORD ==> position != UNSTAGED && (position >> 32u64) < prefix,
        refs == 0 && (closed || position == NO_RECORD) ==> admitted,
))]
pub fn reusable(refs: u64, position: u64, prefix: u64, closed: bool) -> bool {
    refs == 0
        && (closed || position == NO_RECORD || (position != UNSTAGED && (position >> 32) < prefix))
}
