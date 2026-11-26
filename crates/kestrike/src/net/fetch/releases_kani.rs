//! Kani proof of the release board's credit rule. For board states and
//! leases within the bounds below, [`Releases::release`](super::Releases)
//! credits a count only when the lease's core matches the attached core and
//! its generation matches the slot's recorded generation. A crediting release
//! marks its own slot and preserves every other mark. Every other release
//! inside the board frees one orphan and preserves every count and mark, and
//! a release naming a slot outside the board preserves the whole board.
//!
//! Bounds: a board of two request slots, so one slot stands beside the
//! lease's own. Each slot's recorded generation is a symbolic `u64`, the
//! closed marker included, and its count a symbolic `u32` below `u32::MAX`.
//! Each slot starts marked or unmarked by symbolic choice.
//! The attached core, the lease's core and the lease's wire ID are symbolic
//! `u64`s, and the orphan count is a symbolic nonzero `u32`, the state an
//! unmatched release requires. The constructor's loops over the two slots and
//! the one mark word unwind at most four times. The proof takes one release
//! step and does not cover the fetch core folding the counts into grants.

#[cfg(kani)]
mod verification {
    use super::super::{CLOSED, EngineBudget, GENERATION_LIMIT, Releases, RequestId};

    /// The board's request slots.
    const SLOTS: u32 = 2;

    /// Over one symbolic board state and one symbolic lease: a release whose core and generation match its slot adds one
    /// to that slot's count, marks the slot and preserves the other slot's count and mark and the orphans; a release
    /// inside the board that matches neither preserves both counts and both marks and frees one orphan; a release
    /// outside the board preserves the counts, the marks and the orphans. A closed slot matches no lease, since no wire ID carries the closed marker.
    #[kani::proof]
    #[kani::unwind(4)]
    fn a_release_credits_only_the_live_request_of_its_own_core_and_generation() {
        let mut budget = EngineBudget::new(usize::MAX);
        let Ok(board) = Releases::with_generation_limit(SLOTS, GENERATION_LIMIT - 1, &mut budget)
        else {
            unreachable!("the budget holds a two-slot board");
        };
        let before: [(u64, u32); SLOTS as usize] = kani::any();
        kani::assume(before.iter().all(|(_, count)| *count < u32::MAX));
        for (cell, state) in board.counts.iter().zip(before) {
            cell.set(state);
        }
        let marked: [bool; SLOTS as usize] = kani::any();
        for slot in 0..SLOTS as u16 {
            if marked[usize::from(slot)] {
                board.marks.set(slot);
            }
        }
        let orphans: u32 = kani::any();
        kani::assume(orphans > 0);
        board.orphans.set(orphans);
        let attached: u64 = kani::any();
        board.core.set(attached);

        let core: u64 = kani::any();
        let id = RequestId::from_wire(kani::any());
        let slot = usize::from(id.slot());
        let inside = slot < SLOTS as usize;
        let matched = inside && core == attached && before[slot].0 == id.generation();
        kani::cover!(matched);
        kani::cover!(inside && core == attached && before[slot].0 != id.generation());
        kani::cover!(inside && core != attached && before[slot].0 == id.generation());
        kani::cover!(inside && core == attached && before[slot].0 == CLOSED);
        kani::cover!(!inside);

        board.release(core, id);

        let after = [board.counts[0].get(), board.counts[1].get()];
        for other in 0..SLOTS as u16 {
            assert_eq!(
                board.marks.contains(other),
                marked[usize::from(other)] || (matched && other == id.slot()),
                "a release changes only the mark of the slot it credits"
            );
        }
        assert_eq!(
            board.marks.maybe_marked(),
            marked[0] || marked[1] || matched,
            "the board reports a mark exactly when a slot is marked"
        );
        if matched {
            let (generation, count) = before[slot];
            assert!(generation != CLOSED, "a closed slot matches no lease");
            assert_eq!(
                after[slot],
                (generation, count + 1),
                "a matched release adds one to its own count"
            );
            assert_eq!(
                after[1 - slot],
                before[1 - slot],
                "a matched release leaves the other slot unchanged"
            );
            assert_eq!(
                board.orphans.get(),
                orphans,
                "a matched release frees no orphan"
            );
        } else {
            assert_eq!(
                after, before,
                "an unmatched release leaves every count unchanged"
            );
            assert_eq!(
                board.orphans.get(),
                if inside { orphans - 1 } else { orphans },
                "an unmatched release inside the board frees one orphan"
            );
        }
    }
}
