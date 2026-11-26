//! Checks [`tile`] and [`first_slot`] against tables worked out by hand.

use super::layout::{ROOT_BLOCKS, Slot, TileRefusal, UNIT_BYTES, first_slot, tile};

/// Each row: metadata units, unit bytes, then the blocks or refusal worked out by hand from `M * 4096 / U`.
#[test]
fn a_prefix_tiles_into_whole_blocks_of_at_least_the_two_root_slots() {
    let rows: [(u64, u64, Result<u64, TileRefusal>); 10] = [
        (2, 4096, Ok(2)),
        (3, 4096, Ok(3)),
        (4, 8192, Ok(2)),
        (8, 16_384, Ok(2)),
        (12, 16_384, Ok(3)),
        (1, 4096, Err(TileRefusal::TooFewBlocks)),
        (4, 16_384, Err(TileRefusal::TooFewBlocks)),
        (3, 8192, Err(TileRefusal::NotUnitMultiple)),
        (2, 2048, Err(TileRefusal::UnitBelowIoUnit)),
        (u64::MAX / 4096 + 1, 4096, Err(TileRefusal::PrefixOverflow)),
    ];
    for (units, unit, expected) in rows {
        assert_eq!(tile(units, unit), expected, "{units} units of {unit} bytes");
    }
    assert_eq!((ROOT_BLOCKS, UNIT_BYTES), (2, 4096));
    // The largest prefix whose bytes fit u64 still tiles.
    let largest = u64::MAX / 4096;
    assert_eq!(tile(largest, 4096), Ok(largest));
}

/// The RESET keeps the root of the highest `(generation, root sequence)` by writing the other slot first; equal ordinals or two empty slots select slot A.
#[test]
fn a_reset_writes_first_to_the_slot_without_the_highest_root() {
    let rows = [
        (Some((5, 0)), Some((4, 9)), Slot::B),
        (Some((4, 9)), Some((5, 0)), Slot::A),
        (Some((5, 2)), Some((5, 1)), Slot::B),
        (Some((5, 1)), Some((5, 2)), Slot::A),
        (Some((5, 1)), Some((5, 1)), Slot::A),
        (Some((1, 0)), None, Slot::B),
        (None, Some((1, 0)), Slot::A),
        (None, None, Slot::A),
    ];
    for (a, b, first) in rows {
        assert_eq!(first_slot(a, b), first, "{a:?} {b:?}");
    }
}
