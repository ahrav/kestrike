//! The pure decisions of the recovery metadata prefix: how many blocks of one atomic unit tile it and which root slot a RESET writes first.
//!
//! Every decision reads plain values; Verus checks each against its `ensures` contract, and the volume applies it.
//! The prefix of `M` units of [`UNIT_BYTES`] bytes splits into blocks of the persistence profile's atomic unit `U`: block 0 is root slot A, block 1 root slot B.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The device transfer unit in bytes; every metadata block is at least this long.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UNIT_BYTES: u64 = 4096;

/// Blocks every layout holds: the two root slots.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const ROOT_BLOCKS: u64 = 2;

/// Why a metadata prefix cannot be tiled in blocks of the atomic unit, in the order [`tile`] checks.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileRefusal {
    /// The atomic unit is shorter than one [`UNIT_BYTES`] transfer unit.
    UnitBelowIoUnit,
    /// The prefix's bytes do not fit `u64`.
    PrefixOverflow,
    /// The prefix's bytes are not a whole number of atomic units.
    NotUnitMultiple,
    /// The prefix holds fewer than [`ROOT_BLOCKS`] blocks.
    TooFewBlocks,
}

/// A root slot: A is block 0, B is block 1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

/// The blocks of `unit` bytes that tile `metadata_units` units of [`UNIT_BYTES`] bytes, at least [`ROOT_BLOCKS`] of them.
#[cfg_attr(verus_keep_ghost, verus_spec(tiled =>
    ensures
        tiled matches Ok(blocks) ==> unit >= UNIT_BYTES
            && metadata_units * UNIT_BYTES == blocks * unit
            && blocks >= ROOT_BLOCKS,
        tiled is Err ==> unit < UNIT_BYTES
            || metadata_units * UNIT_BYTES > u64::MAX
            || (metadata_units * UNIT_BYTES) % (unit as int) != 0
            || (metadata_units * UNIT_BYTES) / (unit as int) < ROOT_BLOCKS,
))]
pub fn tile(metadata_units: u64, unit: u64) -> Result<u64, TileRefusal> {
    if unit < UNIT_BYTES {
        return Err(TileRefusal::UnitBelowIoUnit);
    }
    if metadata_units > u64::MAX / UNIT_BYTES {
        return Err(TileRefusal::PrefixOverflow);
    }
    let bytes = metadata_units * UNIT_BYTES;
    if !bytes.is_multiple_of(unit) {
        return Err(TileRefusal::NotUnitMultiple);
    }
    let blocks = bytes / unit;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(bytes == blocks * unit + bytes % unit) by (nonlinear_arith)
            requires unit > 0, blocks == bytes / unit;
    }
    if blocks < ROOT_BLOCKS {
        return Err(TileRefusal::TooFewBlocks);
    }
    Ok(blocks)
}

/// The slot a RESET writes first when slots A and B hold valid roots ordered by `(generation, root sequence)` `a` and `b`: the slot that does not hold the higher root, or A when both hold equal ordinals or neither holds a root.
///
/// The slot holding the higher root is written only after the first write is persisted, so a crash between the two leaves that root selectable (RESET-BEFORE-OVERWRITE).
#[cfg_attr(verus_keep_ghost, verus_spec(first =>
    ensures
        first is B <==> (match (a, b) {
            (Some(x), Some(y)) => x.0 > y.0 || (x.0 == y.0 && x.1 > y.1),
            (Some(_), None) => true,
            (None, _) => false,
        }),
))]
pub fn first_slot(a: Option<(u64, u64)>, b: Option<(u64, u64)>) -> Slot {
    match (a, b) {
        (Some(x), Some(y)) if x.0 > y.0 || (x.0 == y.0 && x.1 > y.1) => Slot::B,
        (Some(_), None) => Slot::B,
        _ => Slot::A,
    }
}
