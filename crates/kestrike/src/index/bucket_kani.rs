//! Kani proof of the bucket control word's lane rules in `bucket`: over
//! every 64-bit control word, `candidate_lanes`, `is_occupied`, `is_pending`
//! and `first_free` agree with a lane-by-lane reading, `occupied_pairs` and
//! `held_pairs` count at least one pair when a lane is occupied, `held_pairs`
//! counts at least one pair when a lane is pending,
//! a pending lane is neither occupied, a candidate nor free, and each
//! control update changes its own lane alone.
//!
//! Bounds: every loop in the proof has a fixed bound, the three control
//! updates and the fourteen-lane mask the word-parallel compare builds, so
//! Kani's default unwinding finishes. The control word is a symbolic `u64`,
//! reserved bits included, the tag a symbolic `u16`, and the two pair
//! indices are symbolic below `PAIRS`.

#[cfg(kani)]
mod verification {
    use super::super::bucket::{
        PAIRS, candidate_lanes, control_pending, control_with, control_without, first_free,
        held_pairs, is_occupied, is_pending, occupied_pairs,
    };

    /// The lane of a pending pair.
    const PENDING: u64 = 0b1110;
    /// The high bit of each of the fourteen lanes.
    const HIGH_BITS: u64 = 0x0088_8888_8888_8888;
    /// Bits of the fourteen lanes; the control word's reserved bits lie above them.
    const LANES_BITS: u32 = 56;

    /// Lane `pair` of `control`, read by shift and mask.
    fn lane_of(control: u64, pair: usize) -> u64 {
        (control >> (4 * pair)) & 0b1111
    }

    /// Whether a lane is free: unoccupied and not pending.
    fn free(lane: u64) -> bool {
        lane & 1 == 0 && lane != PENDING
    }

    /// Over one symbolic control word, tag and two pairs: `candidate_lanes` sets the high bit of a lane exactly when
    /// the lane is occupied with the tag's low three bits, and no other bit; `is_occupied` and `is_pending` read the
    /// lane; a pending lane is unoccupied, counts in `held_pairs` and is never the free pair; an occupied lane counts in
    /// `occupied_pairs` and `held_pairs`; `first_free` returns the lowest free lane,
    /// or `None` when no lane is free; and `control_with`, `control_without` and `control_pending` give their pair's
    /// lane its value and keep every other lane and the reserved bits.
    #[kani::proof]
    fn every_control_word_reads_and_changes_lane_by_lane() {
        let control: u64 = kani::any();
        let tag: u16 = kani::any();
        let (pair, other): (usize, usize) = (kani::any(), kani::any());
        kani::assume(pair < PAIRS && other < PAIRS);
        let lane = lane_of(control, pair);
        let carried = 1 | (u64::from(tag) & 0b111) << 1;

        let candidates = candidate_lanes(control, tag);
        assert_eq!(candidates & !HIGH_BITS, 0);
        assert_eq!((candidates >> (4 * pair + 3)) & 1 == 1, lane == carried);
        assert_eq!(is_occupied(control, pair), lane & 1 == 1);
        assert_eq!(is_pending(control, pair), lane == PENDING);
        if lane == PENDING {
            assert!(!is_occupied(control, pair));
            assert!(first_free(control) != Some(pair));
            assert!(held_pairs(control) >= 1);
        }
        if lane & 1 == 1 {
            assert!(occupied_pairs(control) >= 1 && held_pairs(control) >= 1);
        }

        let found = first_free(control);
        kani::cover!(lane == PENDING);
        kani::cover!(candidates != 0);
        kani::cover!(found.is_none());
        kani::cover!(lane == PENDING && found.is_some_and(|found| pair < found));
        kani::cover!(control >> LANES_BITS != 0 && found == Some(PAIRS - 1));
        kani::cover!(other != pair);
        match found {
            Some(found) => {
                assert!(found < PAIRS);
                assert!(free(lane_of(control, found)));
                if pair < found {
                    assert!(!free(lane));
                }
            }
            None => {
                assert!(!free(lane));
            }
        }

        let changes = [
            (control_with(control, pair, tag), carried),
            (control_without(control, pair), 0),
            (control_pending(control, pair), PENDING),
        ];
        for (changed, own) in changes {
            assert_eq!(lane_of(changed, pair), own);
            assert_eq!(changed >> LANES_BITS, control >> LANES_BITS);
            if other != pair {
                assert_eq!(lane_of(changed, other), lane_of(control, other));
            }
        }
    }
}
