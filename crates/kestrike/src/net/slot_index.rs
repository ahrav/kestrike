//! Per-request-slot indexes for the client's fetch and upload cores. The cached timer lower bound lets callers rule out due timers in constant time.

use std::cell::Cell;

/// Children per node of the timer index's bound tree; eight `u64` bounds take 64 bytes, one cache line's width.
const FANOUT: usize = 8;

/// Levels a bound tree over `u32` slots can need.
const MOST_LEVELS: usize = 11;

/// Each slot carries a timer or none, its presence kept apart from its value, so every `u64` is a timer. A tree of lower bounds stands over the slots: each node bounds the eight nodes or slots of one group below it, and the top level is a single group. A scan descends only into nodes whose bound is at or before its time and compares one group of eight at each node it visits. A write that raises the least value under a node recomputes the path above it at once when it is the first such write since a read left no node stale; any other such write marks the path stale, and a fold recomputes only stale nodes. Each write takes time proportional to the tree's height and keeps `floor` at or below every timer. [`least`](Self::least) folds when `exact` is false, so writes between reads share at most one fold.
pub(super) struct Timers {
    /// Each slot's timer while `present` holds the slot, and `u64::MAX` while it carries none or lies past the last slot, so for `now_us < u64::MAX` every value at or before `now_us` belongs to a slot that carries a timer.
    slots: Box<[[u64; FANOUT]]>,
    /// One bit per slot, set exactly while the slot carries a timer.
    present: Box<[u64]>,
    /// The tree's levels in groups, lowest first: node `i` of a level bounds group `i` of the level below, or of `slots` for the lowest level. Each bound is at most every timer below it and at most its children's bounds, and equals their least while no stale bit covers it. Nodes past a level's last hold `u64::MAX`.
    bounds: Box<[[Cell<u64>; FANOUT]]>,
    /// Per node of `bounds`, a bit for each child node that may be stale: its bound may be below its children's least, or a node below it is stale. A set bit implies a set bit for the parent above it, up to `top_stale`; nodes of the lowest level use none.
    stale: Box<[Cell<u8>]>,
    /// The stale bits of the top level's nodes.
    top_stale: Cell<u8>,
    /// Set by a read or fold that leaves no node stale and cleared by the next write that raises a lowest-level bound, which recomputes its path at once instead of marking it, so writes between reads recompute at most one path.
    fresh: Cell<bool>,
    /// Where each level starts in `bounds`, in groups; level `top` is the last and holds one group.
    levels: [usize; MOST_LEVELS],
    top: usize,
    /// The number of slots that carry a timer.
    count: u32,
    /// While `count > 0`, `floor` is at most every timer and equals the least one when `exact` is true.
    floor: Cell<u64>,
    exact: Cell<bool>,
}

/// The group count of each level of a bound tree over `slots` slots, lowest first; the top level is the first with one group.
fn widths(slots: u32) -> impl Iterator<Item = usize> {
    let mut below = Some((slots as usize).div_ceil(FANOUT).max(1));
    std::iter::from_fn(move || {
        let groups = below?.div_ceil(FANOUT);
        below = (groups > 1).then_some(groups);
        Some(groups)
    })
}

impl Timers {
    pub(super) fn charge(slots: u32) -> usize {
        let groups: usize = widths(slots).sum();
        (slots as usize).div_ceil(FANOUT).max(1) * size_of::<[u64; FANOUT]>()
            + slots.div_ceil(64) as usize * size_of::<u64>()
            + groups * (size_of::<[Cell<u64>; FANOUT]>() + FANOUT * size_of::<Cell<u8>>())
    }

    pub(super) fn new(slots: u32) -> Self {
        let (mut levels, mut groups, mut top) = ([0; MOST_LEVELS], 0, 0);
        for (level, width) in widths(slots).enumerate() {
            (levels[level], groups, top) = (groups, groups + width, level);
        }
        Self {
            slots: vec![[u64::MAX; FANOUT]; (slots as usize).div_ceil(FANOUT).max(1)]
                .into_boxed_slice(),
            present: vec![0; slots.div_ceil(64) as usize].into_boxed_slice(),
            bounds: (0..groups)
                .map(|_| std::array::from_fn(|_| Cell::new(u64::MAX)))
                .collect(),
            stale: (0..groups * FANOUT).map(|_| Cell::new(0)).collect(),
            top_stale: Cell::new(0),
            fresh: Cell::new(true),
            levels,
            top,
            count: 0,
            floor: Cell::new(u64::MAX),
            exact: Cell::new(true),
        }
    }

    /// Slot `slot`'s timer, if it carries one.
    #[inline]
    pub(super) fn get(&self, slot: usize) -> Option<u64> {
        (self.present[slot / 64] & 1 << (slot % 64) != 0).then(|| self.slots.as_flattened()[slot])
    }

    /// A lower bound on every timer, or `None` while no slot carries one; a timer becomes due only at or after it.
    #[inline]
    pub(super) fn floor(&self) -> Option<u64> {
        (self.count > 0).then(|| self.floor.get())
    }

    #[cfg(test)]
    pub(super) fn exact(&self) -> bool {
        self.exact.get()
    }

    /// Node `index` of level `level`.
    #[inline]
    fn node(&self, level: usize, index: usize) -> &Cell<u64> {
        &self.bounds[self.levels[level] + index / FANOUT][index % FANOUT]
    }

    /// Gives slot `slot` the timer `timer`, or none.
    #[inline(always)]
    pub(super) fn set(&mut self, slot: usize, timer: Option<u64>) {
        let value = timer.unwrap_or(u64::MAX);
        // `before` is `u64::MAX` for a slot without a timer, and no value is above it, so each raise test below holds only for a slot that carried `before` as a timer.
        let before = std::mem::replace(&mut self.slots.as_flattened_mut()[slot], value);
        let (word, bit) = (&mut self.present[slot / 64], 1 << (slot % 64));
        let had = *word & bit != 0;
        if timer.is_some() {
            *word |= bit;
        } else {
            *word &= !bit;
        }
        self.count = self.count - u32::from(had) + u32::from(timer.is_some());
        // The lowest level starts `bounds`.
        let node = &self.bounds.as_flattened()[slot / FANOUT];
        let bound = node.get();
        if value < bound {
            node.set(value);
            if self.top > 0 {
                self.lower(slot / FANOUT / FANOUT, value);
            }
        } else if before == bound && value > bound {
            if self.fresh.get() {
                return self.raise(slot / FANOUT, before);
            }
            self.mark_stale(slot / FANOUT);
        }
        let floor = self.floor.get();
        if timer.is_some() && (self.count == 1 || value < floor) {
            // Every other timer is at least `floor`, so `value` is the least one.
            self.floor.set(value);
            self.exact.set(true);
        } else if before == floor && value > floor {
            self.exact.set(false);
        }
    }

    /// Lowers the bounds of node `index` of level 1 and the nodes above it to `value`, up to the first already at or below it.
    #[cold]
    #[inline(never)]
    fn lower(&self, mut index: usize, value: u64) {
        for level in 1..=self.top {
            let node = self.node(level, index);
            if node.get() <= value {
                return;
            }
            node.set(value);
            index /= FANOUT;
        }
    }

    /// Recomputes lowest-level node `index`, whose bound `old` a write raised, and each node above it whose bound was the value it replaced, and the floor when the top level changes; requires no node to be stale, so every bound and the floor stay exact.
    #[inline(never)]
    fn raise(&self, mut index: usize, old: u64) {
        self.fresh.set(false);
        scanned(FANOUT);
        // A slot without a timer holds `u64::MAX`, the identity of the minimum.
        let mut low = least_of(&self.slots[index], |&at| at);
        let mut level = 0;
        loop {
            self.node(level, index).set(low);
            if low == old {
                return;
            }
            if level == self.top {
                scanned(FANOUT);
                let top = &self.bounds[self.levels[self.top]];
                return self.floor.set(least_of(top, Cell::get));
            }
            // A parent below `old` takes its bound from another child.
            if self.node(level + 1, index / FANOUT).get() != old {
                return;
            }
            scanned(FANOUT);
            low = least_of(&self.bounds[self.levels[level] + index / FANOUT], Cell::get);
            (level, index) = (level + 1, index / FANOUT);
        }
    }

    /// Marks lowest-level node `index` and the nodes above it stale, up to the first already marked.
    #[inline(never)]
    fn mark_stale(&self, mut index: usize) {
        self.fresh.set(false);
        for level in 1..=self.top {
            let parent = &self.stale[self.levels[level] * FANOUT + index / FANOUT];
            let bit = 1 << (index % FANOUT);
            if parent.get() & bit != 0 {
                return;
            }
            parent.set(parent.get() | bit);
            index /= FANOUT;
        }
        self.top_stale.set(self.top_stale.get() | 1 << index);
    }

    /// The least timer, or `None` while no slot carries one; requires every slot in `slots[end..]` to carry none.
    #[inline]
    pub(super) fn least(&self, end: usize) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        if !self.exact.get() {
            self.fold(end);
        }
        self.fresh.set(self.top_stale.get() == 0);
        Some(self.floor.get())
    }

    /// Sets `floor` to the least timer and marks it exact; requires every slot in `slots[end..]` to carry none. An exact floor needs no work; otherwise only stale nodes over `slots[..end]` are recomputed, one group of children each.
    pub(super) fn fold(&self, end: usize) {
        if self.exact.get() {
            return;
        }
        let span = FANOUT.pow(self.top as u32 + 1);
        let used = FANOUT.min(end.div_ceil(span));
        let mut bits = self.top_stale.get() & !u8::MAX.checked_shl(used as u32).unwrap_or(0);
        self.top_stale.set(self.top_stale.get() & !bits);
        while bits != 0 {
            self.refresh(bits.trailing_zeros() as usize);
            bits &= bits - 1;
        }
        scanned(used);
        let top = &self.bounds[self.levels[self.top]];
        self.floor.set(least(&top[..used], Cell::get));
        self.exact.set(true);
        self.fresh.set(self.top_stale.get() == 0);
    }

    /// Recomputes top-level node `index` and every stale node below it, children before their parent.
    fn refresh(&self, index: usize) {
        if self.top == 0 {
            return self.recompute(0, index);
        }
        // Each entry is a level, a node on it and its stale children not yet recomputed.
        let mut path = [(0, 0, 0); MOST_LEVELS];
        let mut depth = 0;
        path[0] = (self.top, index, self.take_stale(self.top, index));
        loop {
            let (level, node, bits) = path[depth];
            if bits != 0 {
                path[depth].2 = bits & (bits - 1);
                let child = node * FANOUT + bits.trailing_zeros() as usize;
                if level == 1 {
                    self.recompute(0, child);
                } else {
                    depth += 1;
                    path[depth] = (level - 1, child, self.take_stale(level - 1, child));
                }
                continue;
            }
            self.recompute(level, node);
            if depth == 0 {
                return;
            }
            depth -= 1;
        }
    }

    /// Clears and returns the stale bits of node `index` of level `level`.
    #[inline]
    fn take_stale(&self, level: usize, index: usize) -> u8 {
        self.stale[self.levels[level] * FANOUT + index].replace(0)
    }

    /// Sets node `index` of level `level` to the least of its children.
    #[inline]
    fn recompute(&self, level: usize, index: usize) {
        scanned(FANOUT);
        let low = if level == 0 {
            // A slot without a timer holds `u64::MAX`, the identity of the minimum.
            least_of(&self.slots[index], |&at| at)
        } else {
            least_of(&self.bounds[self.levels[level - 1] + index], Cell::get)
        };
        self.node(level, index).set(low);
    }

    /// The first slot in `from..end` whose timer is at or before `now_us`.
    #[inline]
    pub(super) fn next_due(&self, from: usize, end: usize, now_us: u64) -> Option<usize> {
        // `floor` is at most every timer.
        if from >= end || self.count == 0 || self.floor.get() > now_us {
            return None;
        }
        if now_us == u64::MAX {
            return self.first_present(from, end);
        }
        // While `now_us < u64::MAX`, every value at or before `now_us` belongs to a slot that carries a timer, and a node bounds a due timer only if its bound is at or before `now_us`. Height 0 is the slots and height `h` is level `h - 1`; the walk tests the rest of the group holding `at`, descends into the first node that admits a due timer and climbs to the next group when none does.
        let (mut height, mut at) = (0, from);
        // When `at` is the first of its group, its parent covers the whole group, so the walk starts at the highest node that starts at `from`.
        while at % FANOUT == 0 && height <= self.top {
            (height, at) = (height + 1, at / FANOUT);
        }
        loop {
            let (group, lane) = (at / FANOUT, at % FANOUT);
            let due = if height == 0 {
                first_due(&self.slots[group], lane, now_us, |&at| at)
            } else {
                first_due(
                    &self.bounds[self.levels[height - 1] + group],
                    lane,
                    now_us,
                    Cell::get,
                )
            };
            if let Some(hit) = due {
                let hit = group * FANOUT + hit;
                if height == 0 {
                    return (hit < end).then_some(hit);
                }
                (height, at) = (height - 1, hit * FANOUT);
            } else if height > self.top {
                return None;
            } else {
                (height, at) = (height + 1, group + 1);
                if at * FANOUT.pow(height as u32) >= end {
                    return None;
                }
            }
        }
    }

    /// The first slot in `from..end` that carries a timer.
    fn first_present(&self, from: usize, end: usize) -> Option<usize> {
        let mut word = from / 64;
        let mut bits = self.present[word] & u64::MAX << (from % 64);
        loop {
            if bits != 0 {
                let slot = word * 64 + bits.trailing_zeros() as usize;
                return (slot < end).then_some(slot);
            }
            word += 1;
            if word * 64 >= end {
                return None;
            }
            bits = self.present[word];
        }
    }
}

/// The least of `values`, or `u64::MAX` when there are none.
#[inline]
fn least<T>(values: &[T], value: impl Fn(&T) -> u64) -> u64 {
    values.iter().map(value).fold(u64::MAX, u64::min)
}

/// The least of `group`, compared as a tree of pairs so the compares overlap.
#[inline]
fn least_of<T>(group: &[T; FANOUT], value: impl Fn(&T) -> u64) -> u64 {
    let v: [u64; FANOUT] = std::array::from_fn(|lane| value(&group[lane]));
    (v[0].min(v[1]).min(v[2].min(v[3]))).min(v[4].min(v[5]).min(v[6].min(v[7])))
}

/// The first lane at or after `lane` whose value in `group` is at or before `now_us`.
#[inline]
fn first_due<T>(
    group: &[T; FANOUT],
    lane: usize,
    now_us: u64,
    value: impl Fn(&T) -> u64,
) -> Option<usize> {
    (lane..FANOUT).find(|&at| value(&group[at]) <= now_us)
}

/// Counts `reads` timer-index entries that a fold or a path recomputation read, so a test can bound the index's work.
#[inline(always)]
fn scanned(reads: usize) {
    #[cfg(test)]
    TIMER_SCANS.with(|total| total.set(total.get() + reads));
    #[cfg(not(test))]
    let _ = reads;
}

#[cfg(test)]
thread_local! {
    /// Bounds and slots that folds and path recomputations read on this thread, so a test can bound the timer index's work.
    static TIMER_SCANS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_timer_scans() -> usize {
    TIMER_SCANS.with(|total| total.replace(0))
}

/// A set of request slots, one bit per slot, with a flag that is clear only while the set is empty.
pub(super) struct Marks {
    words: Box<[Cell<u64>]>,
    /// `any == false` guarantees an empty set; removing the last member leaves `any` true.
    any: Cell<bool>,
}

impl Marks {
    pub(super) fn charge(slots: u32) -> usize {
        slots.div_ceil(64) as usize * size_of::<Cell<u64>>()
    }

    pub(super) fn new(slots: u32) -> Self {
        Self {
            words: (0..slots.div_ceil(64)).map(|_| Cell::new(0)).collect(),
            any: Cell::new(false),
        }
    }

    #[inline]
    pub(super) fn set(&self, slot: u16) {
        let word = &self.words[usize::from(slot) / 64];
        word.set(word.get() | 1 << (slot % 64));
        self.any.set(true);
    }

    #[inline]
    pub(super) fn remove(&self, slot: u16) -> bool {
        let word = &self.words[usize::from(slot) / 64];
        let (bits, bit) = (word.get(), 1 << (slot % 64));
        word.set(bits & !bit);
        bits & bit != 0
    }

    pub(super) fn contains(&self, slot: u16) -> bool {
        self.words[usize::from(slot) / 64].get() & 1 << (slot % 64) != 0
    }

    pub(super) fn clear(&self) {
        self.words.iter().for_each(|word| word.set(0));
        self.any.set(false);
    }

    pub(super) fn any(&self, member: impl FnMut(u32) -> bool) -> bool {
        self.any.get() && Self::any_in(self.words.len(), |word| self.words[word].get(), member)
    }

    /// Whether this set may hold a member; false only while it is empty.
    #[inline]
    pub(super) fn maybe_marked(&self) -> bool {
        self.any.get()
    }

    /// Whether this set or `other` may hold a member; false only while both sets are empty.
    #[inline]
    pub(super) fn maybe_any(&self, other: &Marks) -> bool {
        self.maybe_marked() || other.maybe_marked()
    }

    pub(super) fn any_with(&self, other: &Marks, member: impl FnMut(u32) -> bool) -> bool {
        debug_assert!(other.words.len() >= self.words.len());
        self.maybe_any(other)
            && Self::any_in(
                self.words.len(),
                |word| self.words[word].get() | other.words[word].get(),
                member,
            )
    }

    #[inline]
    pub(super) fn next(&self, from: u32) -> Option<u32> {
        if !self.any.get() {
            return None;
        }
        let found = Self::first(self.words.len(), from, |word| self.words[word].get());
        if found.is_none() {
            self.any.set(false);
        }
        found
    }

    pub(super) fn next_with(&self, other: &Marks, from: u32) -> Option<u32> {
        debug_assert!(other.words.len() >= self.words.len());
        if !self.maybe_any(other) {
            return None;
        }
        let found = Self::first(self.words.len(), from, |word| {
            self.words[word].get() | other.words[word].get()
        });
        if found.is_none() {
            self.any.set(false);
            other.any.set(false);
        }
        found
    }

    fn any_in(
        words: usize,
        marks: impl Fn(usize) -> u64,
        mut member: impl FnMut(u32) -> bool,
    ) -> bool {
        for word in 0..words {
            let mut bits = marks(word);
            while bits != 0 {
                let slot = word as u32 * 64 + bits.trailing_zeros();
                if member(slot) {
                    return true;
                }
                bits &= bits - 1;
            }
        }
        false
    }

    #[inline]
    fn first(words: usize, from: u32, marks: impl Fn(usize) -> u64) -> Option<u32> {
        if words == 0 {
            return None;
        }
        let from = if (from as usize) < words * 64 {
            from
        } else {
            0
        };
        let mut word = from as usize / 64;
        let mut bits = marks(word) & (u64::MAX << (from % 64));
        for _ in 0..words {
            if bits != 0 {
                return Some(word as u32 * 64 + bits.trailing_zeros());
            }
            word = if word + 1 < words { word + 1 } else { 0 };
            bits = marks(word);
        }
        (bits != 0).then(|| word as u32 * 64 + bits.trailing_zeros())
    }
}
