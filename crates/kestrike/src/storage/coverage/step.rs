//! The pure integer core of the retirement-epoch word.
//!
//! The word packs the current epoch in bit 0, epoch 0's count of outstanding counted retirements in bits 1 to 31, epoch 1's in bits 32 to 62, and in bit 63 the latch that closes coverage admission once a count would pass [`COUNT_LIMIT`]. Each function reads plain values; Verus checks each against its `ensures` contract, and the storage's atomic operations apply them.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The largest count one epoch holds.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const COUNT_LIMIT: u64 = 0x7FFF_FFFF;

/// The latch bit that closes coverage admission.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const CLOSED: u64 = 1u64 << 63;

/// The amount one registration under epoch `epoch` adds to the word.
#[cfg_attr(verus_keep_ghost, verus_spec(unit =>
    requires
        epoch <= 1,
    ensures
        epoch == 0 ==> unit == 2,
        epoch == 1 ==> unit == 1u64 << 32u64,
))]
pub fn unit(epoch: u64) -> u64 {
    if epoch == 0 { 2 } else { 1u64 << 32 }
}

/// The count epoch `epoch` holds in `word`.
#[cfg_attr(verus_keep_ghost, verus_spec(count =>
    requires
        epoch <= 1,
    ensures
        count <= COUNT_LIMIT,
        epoch == 0 ==> count == (word >> 1u64) & COUNT_LIMIT,
        epoch == 1 ==> count == (word >> 32u64) & COUNT_LIMIT,
))]
pub fn count(word: u64, epoch: u64) -> u64 {
    let count = if epoch == 0 {
        (word >> 1) & COUNT_LIMIT
    } else {
        (word >> 32) & COUNT_LIMIT
    };
    #[cfg(verus_keep_ghost)]
    proof! {
        assert((word >> 1u64) & 0x7FFF_FFFFu64 <= 0x7FFF_FFFFu64) by (bit_vector);
        assert((word >> 32u64) & 0x7FFF_FFFFu64 <= 0x7FFF_FFFFu64) by (bit_vector);
    }
    count
}

/// The word after one registration under the current epoch of `word`, with that epoch; `None` when admission is closed or the epoch's count is at [`COUNT_LIMIT`].
#[cfg_attr(verus_keep_ghost, verus_spec(registered =>
    ensures
        registered matches Some((next, epoch)) ==> epoch == word % 2
            && word & CLOSED == 0
            && (if epoch == 0 { (word >> 1u64) & COUNT_LIMIT } else { (word >> 32u64) & COUNT_LIMIT }) < COUNT_LIMIT
            && next == word + (if epoch == 0 { 2u64 } else { 1u64 << 32u64 }),
        registered is None ==> word & CLOSED != 0
            || (if word % 2 == 0 { (word >> 1u64) & COUNT_LIMIT } else { (word >> 32u64) & COUNT_LIMIT }) == COUNT_LIMIT,
))]
pub fn registered(word: u64) -> Option<(u64, u64)> {
    let epoch = word % 2;
    if word & CLOSED != 0 || count(word, epoch) == COUNT_LIMIT {
        return None;
    }
    let step = unit(epoch);
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(CLOSED == 0x8000_0000_0000_0000u64) by (bit_vector);
        assert(1u64 << 32u64 == 0x1_0000_0000u64) by (bit_vector);
        let low = (word >> 1u64) & 0x7FFF_FFFFu64;
        let high = (word >> 32u64) & 0x7FFF_FFFFu64;
        if epoch == 0 {
            assert(word & 0x8000_0000_0000_0000u64 == 0 && low < 0x7FFF_FFFFu64 ==> word <= u64::MAX - 2) by (bit_vector)
                requires low == (word >> 1u64) & 0x7FFF_FFFFu64;
        } else {
            assert(word & 0x8000_0000_0000_0000u64 == 0 && high < 0x7FFF_FFFFu64 ==> word <= u64::MAX - 0x1_0000_0000u64) by (bit_vector)
                requires high == (word >> 32u64) & 0x7FFF_FFFFu64;
        }
    }
    Some((word + step, epoch))
}
