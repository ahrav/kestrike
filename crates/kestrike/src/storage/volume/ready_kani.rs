//! Kani proof of the read-slot set in `ready`: after any four `set` calls on an empty set of 130 slots,
//! [`SlotSet::next`](super::ready::SlotSet::next) returns the lowest member of its range and
//! [`SlotSet::any`](super::ready::SlotSet::any) reports whether a member exists.
//!
//! Bounds: 130 slots, which is two whole words and a partial third; four symbolic `set` calls from the empty set; a
//! symbolic range `from..end` with `from <= end <= 130`; unwinding 132, above the 130 iterations of the reference scan.

#[cfg(kani)]
mod verification {
    use super::super::ready::SlotSet;

    /// Slots in the set: bits 0 to 63 and 64 to 127 fill two words and bits 128 and 129 start a third.
    const COUNT: u32 = 130;

    /// `set` calls that build the state from the empty set.
    const CALLS: usize = 4;

    /// The set agrees with a shadow array of its members: `next(from, end)` is the lowest shadow member in
    /// `from..end`, or `None` when the range holds none, and `any` is true exactly when the shadow holds a member.
    #[kani::proof]
    #[kani::unwind(132)]
    fn next_is_the_lowest_member_in_its_range_and_any_reports_a_member() {
        let mut set = SlotSet::new(COUNT);
        let mut shadow = [false; COUNT as usize];
        let mut cleared = false;
        for _ in 0..CALLS {
            let slot: u32 = kani::any();
            kani::assume(slot < COUNT);
            let member: bool = kani::any();
            cleared |= shadow[slot as usize] && !member;
            set.set(slot, member);
            shadow[slot as usize] = member;
        }
        let from: u32 = kani::any();
        let end: u32 = kani::any();
        kani::assume(from <= end && end <= COUNT);

        let mut lowest = None;
        let mut first = None;
        let mut members = false;
        for slot in 0..COUNT {
            if shadow[slot as usize] {
                members = true;
                if slot >= from && first.is_none() {
                    first = Some(slot);
                }
                if slot >= from && slot < end && lowest.is_none() {
                    lowest = Some(slot);
                }
            }
        }

        let next = set.next(from, end);
        kani::cover!(next.is_some_and(|slot| slot / 64 > from / 64));
        kani::cover!(next == Some(from));
        kani::cover!(next.is_none() && first.is_some());
        kani::cover!(next.is_none() && !members);
        kani::cover!(next == Some(COUNT - 1));
        kani::cover!(cleared && next.is_some());
        assert_eq!(next, lowest);
        assert_eq!(set.any(), members);
    }
}
