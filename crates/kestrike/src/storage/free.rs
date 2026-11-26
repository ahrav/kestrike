//! The free-slot set: one bit per slot, set while the slot is `Free` and
//! unclaimed, under a radix tree of summary words that locates the first
//! free slot at or after any position in a bounded number of word reads.
//!
//! Level 0 holds one bit per slot, bit `s % 64` of word `s / 64`; bits past
//! the slot count stay clear. Each level above holds one bit per word of the
//! level below, set exactly while that word is nonzero, up to a single root
//! word. The levels lie back to back in one `u64` table, level 0 first, as
//! [`words`] sizes it.
//!
//! A claim with a placement takes the lowest free slot of its [`WINDOW`]
//! slots, else the first free slot after the window, wrapping at the slot
//! count; a claim without one takes the first free slot at or after the
//! pool's claim cursor. A cursor search reads at most two words per level
//! on the way up and one per level on the way down; a placement search
//! reads one window word first, then the same bound. So a claim costs a
//! bounded number of word reads whatever the pool's fill, and the slot it
//! finds is the lowest free slot of its window or the nearest free slot
//! after it.
//!
//! The window of a key's slots is derived from its fingerprint by
//! [`window_of`], so every path that knows the key can hint the window's
//! record lines before it touches them: a lookup hints them beside its
//! bucket hint, for the validation and retain that follow the bucket read,
//! and the fill's grant hints them for the claim on targets whose atomic
//! exchange proceeds past outstanding hints.

use super::prefetch::LINE;
use super::slot::Record;

/// Slots in one placement window: the records of [`WINDOW`] consecutive
/// slots fill [`WINDOW_LINES`] whole cache lines, which a hint covers.
pub(crate) const WINDOW: usize = 4;

/// Cache lines one window's records span.
pub(crate) const WINDOW_LINES: usize = WINDOW * size_of::<Record>() / LINE;

const _: () = assert!(
    WINDOW * size_of::<Record>() == WINDOW_LINES * LINE
        && WINDOW_LINES == 2
        && WINDOW.is_power_of_two()
);

/// Bits per word, the tree's fanout.
const FANOUT: usize = 64;

/// Levels of the set for the largest slot count configuration validation
/// admits, below `2^31`: `2^25` level-0 words under five summary levels.
const LEVELS_MAX: usize = 6;

const _: () = assert!(words(1 << 31) == (1 << 25) + (1 << 19) + (1 << 13) + 128 + 2 + 1);

/// Words of every level of the set for `slot_count` slots: level 0 holds
/// `ceil(slot_count / 64)` words, each level above `ceil(below / 64)`, down
/// to one root word. At least one word for any slot count.
pub(crate) const fn words(slot_count: usize) -> usize {
    let mut total = 0;
    let mut level = level0_words(slot_count);
    loop {
        total += level;
        if level == 1 {
            return total;
        }
        level = level.div_ceil(FANOUT);
    }
}

/// Words of level 0 for `slot_count` slots: at least one.
const fn level0_words(slot_count: usize) -> usize {
    let words = slot_count.div_ceil(FANOUT);
    if words == 0 { 1 } else { words }
}

/// The first slot of the window `fingerprint` places a key in: one of the
/// `slot_count / WINDOW` whole windows, `floor(windows * fingerprint /
/// 2^64)`. The high bits weigh `2^32` times the low ones, so fingerprints
/// equal in their high half share a window for every power-of-two window
/// count, and for any other count differ only when the low half carries
/// into the quotient, fewer than `windows / 2^32` of high halves. The
/// bucket and tag come from the low bits, so the window is decorrelated from
/// them. `None` for a pool with fewer slots than one window.
#[inline(always)]
pub(crate) fn window_of(fingerprint: u64, slot_count: usize) -> Option<usize> {
    let windows = (slot_count / WINDOW) as u64;
    if windows == 0 {
        return None;
    }
    let window = ((u128::from(fingerprint) * u128::from(windows)) >> 64) as usize;
    Some(window * WINDOW)
}

/// The set's words, borrowed from the control tables under the pool gate.
pub(crate) struct FreeSlots<'a> {
    words: &'a mut [u64],
    slot_count: usize,
}

impl<'a> FreeSlots<'a> {
    /// Attaches to `words`, laid out by [`words`] for `slot_count`.
    #[inline(always)]
    pub(crate) fn attach(words: &'a mut [u64], slot_count: usize) -> Self {
        debug_assert_eq!(words.len(), self::words(slot_count));
        debug_assert!(
            slot_count < 1 << 31,
            "slot count {slot_count} exceeds the validated limit"
        );
        Self { words, slot_count }
    }

    /// Sets every slot free: every level-0 bit below `slot_count` and the
    /// summary bit of every nonzero word.
    pub(crate) fn fill(&mut self) {
        // Level 0 is `whole` full words, then the low `rest` bits of one
        // more word; that word's other bits and the summary levels start
        // clear.
        let (whole, rest) = (self.slot_count / FANOUT, self.slot_count % FANOUT);
        self.words[..whole].fill(u64::MAX);
        self.words[whole..].fill(0);
        if rest != 0 {
            self.words[whole] = (1 << rest) - 1;
        }
        let mut base = 0;
        let mut len = self.level0_words();
        while len > 1 {
            let above = base + len;
            for word in 0..len {
                if self.words[base + word] != 0 {
                    self.words[above + word / FANOUT] |= 1 << (word % FANOUT);
                }
            }
            base = above;
            len = len.div_ceil(FANOUT);
        }
    }

    /// Whether `slot` is in the set.
    #[inline(always)]
    pub(crate) fn contains(&self, slot: usize) -> bool {
        self.words[slot / FANOUT] >> (slot % FANOUT) & 1 == 1
    }

    /// Removes `slot`, which is in the set, clearing each summary bit whose
    /// word became zero.
    #[inline(always)]
    pub(crate) fn take(&mut self, slot: usize) {
        debug_assert!(self.contains(slot), "slot {slot} is not free");
        let word = &mut self.words[slot / FANOUT];
        *word &= !(1 << (slot % FANOUT));
        if *word == 0 {
            self.emptied(slot / FANOUT);
        }
    }

    /// Clears the summary bits above level-0 word `word`, which became zero, as far as each summary word becomes
    /// zero: a range-split take clears level-0 bits alone and calls this once per word it emptied.
    #[inline(always)]
    pub(crate) fn emptied(&mut self, word: usize) {
        let (mut base, mut len, mut index) = (0, self.level0_words(), word * FANOUT);
        while len > 1 {
            index /= FANOUT;
            base += len;
            len = len.div_ceil(FANOUT);
            let word = &mut self.words[base + index / FANOUT];
            *word &= !(1 << (index % FANOUT));
            if *word != 0 {
                return;
            }
        }
    }

    /// Adds `slot`, which is not in the set, setting each summary bit whose
    /// word was zero.
    #[inline(always)]
    pub(crate) fn give(&mut self, slot: usize) {
        debug_assert!(!self.contains(slot), "slot {slot} is already free");
        let (mut base, mut len, mut index) = (0, self.level0_words(), slot);
        loop {
            let word = &mut self.words[base + index / FANOUT];
            let was_empty = *word == 0;
            *word |= 1 << (index % FANOUT);
            if !was_empty || len == 1 {
                return;
            }
            index /= FANOUT;
            base += len;
            len = len.div_ceil(FANOUT);
        }
    }

    /// The lowest free slot in `start..start + WINDOW`, clipped to the slot
    /// count. `start` is a multiple of [`WINDOW`] below the slot count, so
    /// the window lies in one word.
    #[inline(always)]
    pub(crate) fn first_in_window(&self, start: usize) -> Option<usize> {
        debug_assert!(start.is_multiple_of(WINDOW) && start < self.slot_count);
        let bits = self.words[start / FANOUT] >> (start % FANOUT) & ((1 << WINDOW) - 1);
        (bits != 0).then(|| start + bits.trailing_zeros() as usize)
    }

    /// The first free slot at or after `from`, wrapping past the slot count
    /// to the lowest free slot; `None` when the set is empty. `from` is
    /// below the slot count.
    #[inline(always)]
    pub(crate) fn next_from(&self, from: usize) -> Option<usize> {
        debug_assert!(from < self.slot_count);
        match self.first_at_or_after(from) {
            found @ Some(_) => found,
            None => self.lowest(),
        }
    }

    /// The lowest free slot, or `None` when the set is empty. It is cold and
    /// out of line: [`next_from`](Self::next_from) reaches it only when no
    /// slot is free from its position to the end of the set, so the path of
    /// a search that finds one holds no call.
    #[cold]
    #[inline(never)]
    fn lowest(&self) -> Option<usize> {
        self.first_at_or_after(0)
    }

    fn level0_words(&self) -> usize {
        level0_words(self.slot_count)
    }

    /// The first set bit at or after `from`, or `None` past the last set
    /// bit: climbs from level 0 while the word's bits at or after the
    /// position are clear, then descends through each level's lowest set
    /// bit.
    #[inline(always)]
    fn first_at_or_after(&self, from: usize) -> Option<usize> {
        let (mut base, mut len, mut index) = (0, self.level0_words(), from);
        let mut bases = [0usize; LEVELS_MAX];
        let mut level = 0;
        let found = loop {
            bases[level] = base;
            let word = self.words[base + index / FANOUT] & (u64::MAX << (index % FANOUT));
            if word != 0 {
                break index / FANOUT * FANOUT + word.trailing_zeros() as usize;
            }
            if len == 1 {
                return None;
            }
            // Positions after this word, at the level above.
            index = index / FANOUT + 1;
            base += len;
            len = len.div_ceil(FANOUT);
            level += 1;
            if index >= len * FANOUT {
                return None;
            }
        };
        let mut position = found;
        while level > 0 {
            level -= 1;
            let word = self.words[bases[level] + position];
            position = position * FANOUT + word.trailing_zeros() as usize;
        }
        Some(position)
    }
}

#[cfg(test)]
mod tests {
    use super::super::seeded::SplitMix64;
    use super::*;

    /// A naive model of the set: a vector of flags.
    fn check(slot_count: usize, free: &[bool], set: &FreeSlots<'_>) {
        for (slot, &is_free) in free.iter().enumerate() {
            assert_eq!(set.contains(slot), is_free, "slot {slot}");
        }
        for from in (0..slot_count).step_by((slot_count / 97).max(1)) {
            let naive = (from..slot_count).chain(0..from).find(|&slot| free[slot]);
            assert_eq!(
                set.next_from(from),
                naive,
                "next from {from} of {slot_count}"
            );
        }
        for start in (0..slot_count).step_by(WINDOW) {
            let naive = (start..(start + WINDOW).min(slot_count)).find(|&slot| free[slot]);
            assert_eq!(set.first_in_window(start), naive, "window {start}");
        }
    }

    #[test]
    fn the_levels_cover_every_slot_count() {
        assert_eq!(words(0), 1);
        assert_eq!(words(1), 1);
        assert_eq!(words(64), 1);
        assert_eq!(words(65), 2 + 1);
        assert_eq!(words(4096), 64 + 1);
        assert_eq!(words(4097), 65 + 2 + 1);
        assert_eq!(words(1 << 18), 4096 + 64 + 1);
        assert_eq!(
            words(1 << 31),
            (1 << 25) + (1 << 19) + (1 << 13) + 128 + 2 + 1
        );
    }

    /// Every window starts on a window boundary inside the pool, and the
    /// high half of the fingerprint decides it: with a power-of-two window
    /// count, fingerprints that differ only in their low 32 bits share a
    /// window exactly, with another count they share it or a neighbour, and
    /// ones that differ only in the high half spread over the windows.
    #[test]
    fn a_window_is_whole_inside_the_pool_and_chosen_by_the_high_half() {
        assert_eq!(window_of(7, WINDOW - 1), None);
        for slot_count in [WINDOW, 150, 4096, 4099, 1 << 20] {
            let windows = slot_count / WINDOW;
            let mut rng = SplitMix64::new(slot_count as u64);
            for _ in 0..1000 {
                let fingerprint = rng.next_u64();
                let start = window_of(fingerprint, slot_count).unwrap();
                assert_eq!(start % WINDOW, 0);
                assert!(start + WINDOW <= slot_count, "{start} of {slot_count}");
                let low_differs = fingerprint ^ (rng.next_u64() & 0xFFFF_FFFF);
                let other = window_of(low_differs, slot_count).unwrap();
                if windows.is_power_of_two() {
                    assert_eq!(other, start);
                } else {
                    assert!(other.abs_diff(start) <= WINDOW, "{other} vs {start}");
                }
            }
        }
        let slot_count = 1 << 20;
        let mut rng = SplitMix64::new(9);
        let distinct: std::collections::HashSet<usize> = (0..1000)
            .map(|_| window_of(rng.next_u64() << 32, slot_count).unwrap())
            .collect();
        assert!(distinct.len() > 900, "{} windows", distinct.len());
    }

    #[test]
    fn take_give_and_search_agree_with_a_flag_vector() {
        for &slot_count in &[1usize, 5, 64, 65, 150, 4096, 4097, 9000] {
            let mut table = vec![0u64; words(slot_count)];
            let mut set = FreeSlots::attach(&mut table, slot_count);
            set.fill();
            let mut free = vec![true; slot_count];
            check(slot_count, &free, &set);
            let mut rng = SplitMix64::new(slot_count as u64 ^ 0xC0FFEE);
            for round in 0..6 {
                for _ in 0..slot_count {
                    let slot = (rng.next_u64() % slot_count as u64) as usize;
                    if free[slot] {
                        set.take(slot);
                    } else {
                        set.give(slot);
                    }
                    free[slot] = !free[slot];
                }
                check(slot_count, &free, &set);
                if round % 2 == 1 {
                    for (slot, is_free) in free.iter_mut().enumerate() {
                        if *is_free {
                            set.take(slot);
                            *is_free = false;
                        }
                    }
                    assert_eq!(set.next_from(0), None);
                    check(slot_count, &free, &set);
                }
            }
        }
    }

    #[test]
    fn the_search_wraps_and_the_window_clips() {
        let slot_count = 70;
        let mut table = vec![0u64; words(slot_count)];
        let mut set = FreeSlots::attach(&mut table, slot_count);
        set.fill();
        for slot in 0..slot_count {
            if slot != 3 {
                set.take(slot);
            }
        }
        assert_eq!(set.next_from(0), Some(3));
        assert_eq!(set.next_from(3), Some(3));
        assert_eq!(set.next_from(4), Some(3));
        assert_eq!(set.next_from(69), Some(3));
        assert_eq!(set.first_in_window(0), Some(3));
        assert_eq!(set.first_in_window(4), None);
        assert_eq!(set.first_in_window(68), None);
        set.give(69);
        assert_eq!(set.first_in_window(68), Some(69));
        assert_eq!(set.next_from(4), Some(69));
    }
}
