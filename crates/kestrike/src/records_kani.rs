//! Kani proof that the `(slot, generation)` handle counter of
//! [`Records`](super::records::Records) issues each handle once,
//! issues a slot's last generation once and then retires the slot, and
//! reads and removes nothing under a stale handle: the clauses "each
//! counter issues its last value once, then refuses or quarantines exactly,
//! no identity repeats" of the obligation record
//! `terminal-identities-issue-last-and-never-repeat`, the part of its
//! clause "a stale token changes nothing" that the comparisons below
//! observe, and the generation sentences of the module doc of `records.rs`.
//!
//! Bounds: an array of two slots whose generation limit is a symbolic value
//! of at most 1, and [`STEPS`] steps, so the proof runs at an unwinding of
//! `STEPS + 1` and a history at either limit reaches the issue of a slot's
//! last generation and the slot's retirement. Each step is a symbolic
//! insertion, a take, a read and drop, a shared or a mutable read under a
//! symbolic handle (slot 0 through 2, generation 0 through 3), or a removal
//! of a symbolic slot. Every step is checked against a shadow model of each
//! slot's generation, record and retirement, of the high-water mark and of
//! the order the free slots are reused in.
//!
//! A call under a stale handle returns nothing and leaves the live and
//! retired counts, each live record's generation and the high-water mark as
//! the shadow holds them, and an insertion later in the history lands on
//! the slot the shadow's reuse order names, at the shadow's generation. The
//! generation limit, the free list's capacity and a live record's value are
//! outside these comparisons, and so are a free slot's generation and its
//! place in the reuse order until an insertion takes the slot.

#[cfg(kani)]
mod verification {
    use super::super::records::Records;

    /// Steps of one symbolic history.
    const STEPS: usize = 4;

    /// Slots of the array.
    const SLOTS: usize = 2;

    /// One slot as the shadow model holds it.
    #[derive(Clone, Copy)]
    struct Shadow {
        generation: u64,
        value: Option<u8>,
        retired: bool,
    }

    /// The free slots in the order the array reuses them: the next insertion
    /// takes the last of the first `len`.
    struct Free {
        slots: [u32; SLOTS],
        len: usize,
    }

    /// Over every history of [`STEPS`] symbolic steps, the array agrees with
    /// the shadow model after each step: an insertion lands on a free,
    /// unretired slot at its current generation and is refused exactly when
    /// none is free; a handle reads, takes or drops a record exactly when it
    /// names the slot's current generation and the slot holds one; a removal
    /// advances the slot's generation, or retires the slot once the
    /// generation is the limit; and no handle is issued twice. The shadow
    /// also holds the high-water mark and the order the free slots are
    /// reused in: a call that moved the mark fails its own step, and one
    /// that reordered the free slots fails at the next insertion in the
    /// history.
    #[kani::proof]
    #[kani::unwind(5)]
    fn each_handle_is_issued_once_and_a_stale_handle_reads_and_removes_nothing() {
        let limit: u64 = kani::any();
        kani::assume(limit <= 1);
        let mut records = Records::<u8>::with_generation_limit(SLOTS as u32, limit);
        let mut shadow = [Shadow {
            generation: 0,
            value: None,
            retired: false,
        }; SLOTS];
        let mut free = Free {
            slots: core::array::from_fn(|place| (SLOTS - 1 - place) as u32),
            len: SLOTS,
        };
        let mut high_water = 0;
        let mut issued = [(0u32, 0u64); STEPS];
        let mut count = 0;
        let (mut retired, mut stale, mut refused, mut reused) = (false, false, false, false);
        for _ in 0..STEPS {
            let slot: u32 = kani::any();
            kani::assume(slot <= SLOTS as u32);
            let generation: u64 = kani::any();
            kani::assume(generation <= 3);
            let named = shadow
                .get(slot as usize)
                .filter(|at| at.generation == generation && at.value.is_some());
            let expected = named.and_then(|at| at.value);
            match kani::any::<u8>() {
                0 => {
                    let value: u8 = kani::any();
                    match records.insert(value) {
                        Ok((at, generation)) => {
                            let entry = &mut shadow[at as usize];
                            assert!(
                                entry.value.is_none() && !entry.retired,
                                "an insertion lands on a live or retired slot"
                            );
                            assert!(entry.generation == generation && generation <= limit);
                            assert!(
                                free.len > 0 && free.slots[free.len - 1] == at,
                                "an insertion lands off the most recently freed slot"
                            );
                            free.len -= 1;
                            high_water = high_water.max(at + 1);
                            for earlier in &issued[..count] {
                                assert!(*earlier != (at, generation), "a handle issued twice");
                            }
                            reused |= generation > 0;
                            issued[count] = (at, generation);
                            count += 1;
                            entry.value = Some(value);
                        }
                        Err(back) => {
                            assert!(back == value);
                            assert!(
                                shadow.iter().all(|at| at.value.is_some() || at.retired),
                                "an insertion refused beside a free slot"
                            );
                            refused = true;
                        }
                    }
                }
                1 => {
                    assert!(records.get(slot, generation).copied() == expected);
                    stale |= expected.is_none()
                        && shadow
                            .get(slot as usize)
                            .is_some_and(|at| at.value.is_some());
                }
                2 => {
                    assert!(records.get_mut(slot, generation).map(|value| *value) == expected);
                }
                3 => {
                    let taken = records.take(slot, generation);
                    assert!(taken == expected, "a take under a stale handle");
                    if taken.is_some() {
                        vacate(&mut shadow, &mut free, slot, limit);
                    }
                }
                4 => {
                    let read = records.drop_with(slot, generation, |value| *value);
                    assert!(read == expected, "a drop under a stale handle");
                    if read.is_some() {
                        vacate(&mut shadow, &mut free, slot, limit);
                    }
                }
                _ => {
                    if let Some(at) = shadow.get(slot as usize) {
                        records.remove(slot);
                        if at.value.is_some() {
                            vacate(&mut shadow, &mut free, slot, limit);
                        }
                    }
                }
            }
            let live = shadow.iter().filter(|at| at.value.is_some()).count() as u32;
            let gone = shadow.iter().filter(|at| at.retired).count() as u32;
            assert!(records.live() == live && records.retired() == gone);
            assert!(records.high_water() == high_water);
            for (at, entry) in shadow.iter().enumerate() {
                assert!(records.generation_of(at as u32) == entry.value.map(|_| entry.generation));
            }
            retired |= gone > 0;
        }
        kani::cover!(retired, "a slot retires at the limit");
        kani::cover!(retired && limit == 1, "a reused slot retires at the limit");
        kani::cover!(stale, "a stale handle beside a live record");
        kani::cover!(refused, "an insertion refused");
        kani::cover!(reused, "a slot reused at a higher generation");
    }

    /// The shadow of `Records::vacate`: the slot empties, then advances its
    /// generation and becomes the next slot an insertion takes, or retires
    /// at the limit.
    fn vacate(shadow: &mut [Shadow; SLOTS], free: &mut Free, slot: u32, limit: u64) {
        let entry = &mut shadow[slot as usize];
        entry.value = None;
        if entry.generation < limit {
            entry.generation += 1;
            free.slots[free.len] = slot;
            free.len += 1;
        } else {
            entry.retired = true;
        }
    }
}
