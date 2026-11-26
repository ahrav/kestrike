//! Block sizes of the sequence arena and the order of the block that holds
//! an object's extent sequence.
//!
//! An object of `N >= 2` extents keeps its sequence in one block of
//! `next_power_of_two(16 + 8N)` bytes: a 16-byte block header, then one
//! 8-byte locator per extent. Blocks run from [`BLOCK_MIN`] bytes at order 0
//! to [`ROOT_BYTES`] at order [`BLOCK_TOP`], so the largest object's
//! sequence, 2,115 extents in 16,936 bytes, fits one root.
//!
//! Verus checks these value-only functions against their contracts;
//! the arena in `blocks` applies them.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use super::geometry::EXTENT_LIMIT;

/// Bytes of the smallest block, order 0.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const BLOCK_MIN: u64 = 32;

/// The largest order, whose block is one whole root.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const BLOCK_TOP: u64 = 10;

/// Bytes of one root, the order-[`BLOCK_TOP`] block: 32 KiB.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const ROOT_BYTES: u64 = 32_768;

/// Bytes of a block's header: owner, extent count and held prefix.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const BLOCK_HEADER: u64 = 16;

/// Bytes of one extent locator in a block.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const LOCATOR_BYTES: u64 = 8;

/// Bytes of a block of `order`: [`BLOCK_MIN`] doubled `order` times.
#[cfg_attr(verus_keep_ghost, verus_spec(bytes =>
    requires order <= BLOCK_TOP,
    ensures
        bytes == BLOCK_MIN << order,
        BLOCK_MIN <= bytes <= ROOT_BYTES,
))]
#[inline(always)]
pub(crate) fn block_bytes(order: u64) -> u64 {
    // The bit-vector literals are BLOCK_MIN, ROOT_BYTES and BLOCK_TOP.
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(32u64 <= (32u64 << order) && (32u64 << order) <= 32768u64) by (bit_vector)
            requires order <= 10u64;
    }
    BLOCK_MIN << order
}

/// The order of the block that holds the sequence of `count` extents: the
/// smallest whose bytes hold the header and `count` locators. Sequence
/// blocks serve objects of two or more extents, so counts start at two.
///
/// The sequence needs 32 to 16,936 bytes. The smallest power of two at or
/// above that need is `1 << bits`, where `bits` is the bit length of
/// `need - 1`, and a block of order `k` spans `1 << (k + 5)` bytes, so
/// the order is `bits - 5`, computed with one `leading_zeros` call.
#[cfg_attr(verus_keep_ghost, verus_spec(order =>
    requires 2 <= count <= EXTENT_LIMIT,
    ensures
        order <= BLOCK_TOP,
        BLOCK_HEADER + LOCATOR_BYTES * count <= BLOCK_MIN << order,
        order == 0 || BLOCK_MIN << ((order - 1) as u64) < BLOCK_HEADER + LOCATOR_BYTES * count,
))]
#[inline(always)]
pub(crate) fn block_order(count: u64) -> u64 {
    let below = BLOCK_HEADER + LOCATOR_BYTES * count - 1;
    let zeros = below.leading_zeros() as u64;
    // The bit-vector literals are the bounds of `below`, 31 to 16,935, the
    // leading zeros of that range, 49 to 59, and BLOCK_MIN and BLOCK_TOP.
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(31u64 <= below && zeros <= 64u64 && (below >> sub(64u64, zeros)) == 0u64
            ==> zeros <= 59u64) by (bit_vector);
        assert(below <= 16935u64 && zeros < 64u64 && (below >> sub(63u64, zeros)) & 1u64 != 0u64
            ==> 49u64 <= zeros) by (bit_vector);
    }
    let order = 59 - zeros;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(order <= 10u64 && (below >> add(order, 5u64)) == 0u64
            ==> below < (32u64 << order)) by (bit_vector);
        assert(1u64 <= order <= 10u64 && (below >> add(order, 4u64)) & 1u64 != 0u64
            ==> (32u64 << sub(order, 1u64)) <= below) by (bit_vector);
    }
    order
}
