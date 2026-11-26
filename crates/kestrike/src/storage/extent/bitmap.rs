//! The free-unit bitmap and its radix tree of free-run summaries: address-ordered first fit and the two run-end searches.
//!
//! The space is one `u64` table: bitmap words first (bit `u % 64` of word `u / 64` is set while unit `u` is free, and bits past the volume stay clear), then the summary levels.
//! Level 0 holds one summary per chunk of [`CHUNK`] units and each level above one per [`FANOUT`] nodes below, up to one root.
//! A summary is `(start, max, end)`: the free units at the node's start, its longest free run and the free units at its end, over the node's nominal span, with units past the volume taken.
//! Nodes on levels 0 to 4 take one word with 21-bit fields: a level-4 node spans exactly `2^21` units, so bit 63 marks a node entirely free, whose three fields equal its span.
//! Nodes on levels 5 and above take two words with 42-bit fields, enough for any span a volume of at most `2^40` units can fill.
//!
//! A search counts one visit toward the call's work per bitmap word or summary node it reads.
//! A run-end search instead counts one visit per bitmap word or sibling summary that a scan to the run's end reads, including the words and siblings a parent summary's end or start run shows free, which it skips, and counts none for that parent summary.
//! A summary update after a mark counts the reads a full recomputation of the marked chunks and every node above them makes, whatever it reads, and writes count nothing.
//! The update derives each node's summary from its stored summary and the joined or split run, recomputes a node from its words or children when the split run's part inside it was at least as long as its longest run and covered only part of it, and stops above a level whose nodes all keep their stored words.
//! Once a node holds that run strictly inside its span, every ancestor does too and keeps its start and end runs, so the update decides each from its stored longest run: a join raises a shorter one to the run's length, and a split recomputes a node whose longest run was the run's length.
//! A node whose eight bitmap words or eight one-word children are all zero holds no free unit, so its recompute returns the empty summary from a zero test of those words.
//! On each level where a multi-chunk update covers several nodes, the nodes strictly between the first and last lie inside the marked units and take the entirely taken or entirely free summary directly.

use super::super::prefetch::hint_read;
use super::allocator::ExtentAllocator;
use super::summary::{Summary, joined, split};

/// Units under one level-0 summary.
pub(super) const CHUNK: u64 = 512;
/// Bitmap words under one level-0 summary.
pub(super) const CHUNK_WORDS: u64 = CHUNK / 64;
/// Children of one summary node above level 0.
pub(super) const FANOUT: u64 = 8;
/// Summary levels of a volume of `2^40` units, which covers every volume a locator addresses: `2^31` chunks under eleven levels of fanout 8.
pub(super) const LEVEL_LIMIT: usize = 12;
const NARROW_LEVELS: usize = 5;
const NARROW_BITS: u32 = 21;
const WIDE_BITS: u32 = 42;
const ENTIRELY_FREE: u64 = 1 << 63;
/// The size, in words, up to which a level stays in a core's first-level data cache; [`prefetch`](ExtentAllocator::prefetch) hints only the levels below the first level this small.
const HOT_WORDS: u64 = 512;

/// Where one level of a first-fit descent leads.
enum Step {
    /// The fit starts at this unit.
    Fit(u64),
    /// The fit lies inside this child.
    Into(u64),
}

/// How a call changed the free runs around the units it marked.
#[derive(Debug, Clone, Copy)]
pub(super) enum Change {
    /// Units `low..high` form one maximal free run, and each of its units that was taken before lies in the marked range.
    Joined { low: u64, high: u64 },
    /// The marked units `start..end` left the maximal free run `low..high`, so `low..start` and `end..high` stay free.
    Split {
        low: u64,
        start: u64,
        end: u64,
        high: u64,
    },
}

/// Word offsets of the space for a volume of `payload_units` units, and the summary level count.
///
/// Entry `l` is the first word of level `l` and entry `levels` ends the space; the bitmap occupies words `0..base[0]`.
pub(crate) fn space_base(payload_units: u64) -> ([u64; LEVEL_LIMIT + 1], usize) {
    let mut base = [0; LEVEL_LIMIT + 1];
    let (mut offset, mut nodes, mut level) =
        (payload_units.div_ceil(64), payload_units.div_ceil(CHUNK), 0);
    loop {
        base[level] = offset;
        offset += nodes * width(level);
        level += 1;
        if nodes <= 1 {
            break;
        }
        nodes = nodes.div_ceil(FANOUT);
    }
    base[level] = offset;
    (base, level)
}

/// Summary levels of a volume of `payload_units` units: the chunk level and one level per factor of [`FANOUT`] it takes to reach one node, so `levels(v)` equals `space_base(v).1`.
pub(super) fn levels(payload_units: u64) -> usize {
    let chunks = payload_units.div_ceil(CHUNK);
    let bits = if chunks <= 1 {
        0
    } else {
        (chunks - 1).ilog2() + 1
    };
    1 + (bits as usize).div_ceil(FANOUT.ilog2() as usize)
}

/// The lowest chunk of a volume of `payload_units` units with fewer than [`CHUNK_WORDS`] bitmap words or an ancestor below the root with fewer than [`FANOUT`] children, or the chunk count when no chunk has either; a one-level volume, whose only chunk is the root, gives zero.
///
/// A node of level `l` has fewer than [`FANOUT`] children exactly when it is the last on its level and [`FANOUT`] does not divide the node count of level `l - 1`, and a chunk has fewer words exactly when it is the last chunk and [`CHUNK_WORDS`] does not divide the bitmap's word count.
/// The first chunk under node `m` of level `l` is `m << (3 * l)`.
pub(super) fn edge_chunk(payload_units: u64) -> u64 {
    let top = levels(payload_units) - 1;
    if top == 0 {
        return 0;
    }
    let nodes = |level: usize| payload_units.div_ceil(span(level));
    let mut edge = nodes(0) - u64::from(!payload_units.div_ceil(64).is_multiple_of(CHUNK_WORDS));
    for level in 1..top {
        if !nodes(level - 1).is_multiple_of(FANOUT) {
            edge = edge.min((nodes(level) - 1) << (3 * level));
        }
    }
    edge
}

/// Words one node of `level` takes.
fn width(level: usize) -> u64 {
    if level < NARROW_LEVELS { 1 } else { 2 }
}

/// Units under one node of `level`.
pub(super) fn span(level: usize) -> u64 {
    CHUNK << (3 * level)
}

/// The lowest bit `i` with bits `i..i + n` of `x` all set, for `n <= 64`.
pub(super) fn run_in(x: u64, n: u64) -> Option<u64> {
    if n > 64 {
        return None;
    }
    let (mut m, mut have) = (x, 1);
    while have < n {
        let shift = have.min(n - have);
        m &= m >> shift;
        have += shift;
    }
    (m != 0).then(|| u64::from(m.trailing_zeros()))
}

/// A left-to-right fold of consecutive children of one node into the node's summary.
///
/// `run` is the free run ending at the right edge of the children pushed so far; `closed` is set once a child with a taken unit fixes `start`.
#[derive(Default)]
struct Fold {
    start: u64,
    max: u64,
    run: u64,
    closed: bool,
}

impl Fold {
    /// Adds the next child, of `size` units, whose summary is `child`.
    #[inline(always)]
    fn push(&mut self, child: Summary, size: u64) {
        if child.start == size {
            self.run += size;
            return;
        }
        self.max = self.max.max(self.run + child.start).max(child.max);
        if !self.closed {
            (self.start, self.closed) = (self.run + child.start, true);
        }
        self.run = child.end;
    }

    /// The node's summary; `short` marks a node whose last children lie past the volume and hold no free unit.
    #[inline(always)]
    fn finish(mut self, short: bool) -> Summary {
        if short {
            self.push(Summary::default(), 1);
        }
        Summary {
            start: if self.closed { self.start } else { self.run },
            max: self.max.max(self.run),
            end: self.run,
        }
    }
}

/// The summary a level-0 to level-4 node's word stores, for a node of `size` units.
#[inline(always)]
fn narrow(word: u64, size: u64) -> Summary {
    const MASK: u64 = (1 << NARROW_BITS) - 1;
    if word & ENTIRELY_FREE != 0 {
        return Summary {
            start: size,
            max: size,
            end: size,
        };
    }
    Summary {
        start: word & MASK,
        max: word >> NARROW_BITS & MASK,
        end: word >> (2 * NARROW_BITS),
    }
}

/// The word a level-0 to level-4 node of `size` units stores for `sum`; a start run that covers the span stores only the entirely-free bit.
#[inline(always)]
pub(super) fn pack_narrow(sum: Summary, size: u64) -> u64 {
    if sum.start == size {
        ENTIRELY_FREE
    } else {
        sum.start | sum.max << NARROW_BITS | sum.end << (2 * NARROW_BITS)
    }
}

/// Summarizes a node's eight narrow children when each holds a taken unit and returns `None` when any child is entirely free; eight zero words give the empty summary after one test.
///
/// Such a child's start run and end run are shorter than its span, so the node's longest run is either one child's longest run or one run across a child boundary, the left child's end run plus the right child's start run.
#[inline(always)]
fn merge_taken(words: &[u64; FANOUT as usize]) -> Option<Summary> {
    const MASK: u64 = (1 << NARROW_BITS) - 1;
    const MAX_FIELD: u64 = MASK << NARROW_BITS;
    let any = words.iter().fold(0, |any, &word| any | word);
    if any == 0 {
        return Some(Summary::default());
    }
    if any & ENTIRELY_FREE != 0 {
        return None;
    }
    let mut inner = words[0] & MAX_FIELD;
    let mut across = 0;
    for pair in words.windows(2) {
        inner = inner.max(pair[1] & MAX_FIELD);
        across = across.max((pair[0] >> (2 * NARROW_BITS)) + (pair[1] & MASK));
    }
    Some(Summary {
        start: words[0] & MASK,
        max: (inner >> NARROW_BITS).max(across),
        end: words[FANOUT as usize - 1] >> (2 * NARROW_BITS),
    })
}

#[inline(always)]
fn fold_narrow(words: &[u64], size: u64, short: bool) -> Summary {
    let mut fold = Fold::default();
    for &word in words {
        fold.push(narrow(word, size), size);
    }
    fold.finish(short)
}

/// The three `width`-bit fields of `bits`, lowest first.
fn unpack(bits: u128, width: u32) -> Summary {
    let field = |shift: u32| (bits >> shift) as u64 & ((1 << width) - 1);
    Summary {
        start: field(0),
        max: field(width),
        end: field(2 * width),
    }
}

/// The longest run of set bits in `x`.
pub(super) fn longest(mut x: u64) -> u64 {
    let mut best = 0;
    while x != 0 {
        x >>= x.trailing_zeros();
        let ones = x.trailing_ones();
        best = best.max(u64::from(ones));
        x = x.checked_shr(ones).unwrap_or(0);
    }
    best
}

impl ExtentAllocator<'_> {
    pub(super) fn levels(&self) -> usize {
        self.root.levels as usize
    }

    fn bitmap_words(&self) -> u64 {
        self.root.base[0]
    }

    /// Nodes on `level`.
    pub(super) fn nodes(&self, level: usize) -> u64 {
        (self.root.base[level + 1] - self.root.base[level]) / width(level)
    }

    /// The summary of `node` on `level`, counting no visit.
    #[inline(always)]
    pub(super) fn decode(&self, level: usize, node: u64) -> Summary {
        let at = (self.root.base[level] + node * width(level)) as usize;
        if level < NARROW_LEVELS {
            narrow(self.space[at], span(level))
        } else {
            unpack(
                u128::from(self.space[at]) | u128::from(self.space[at + 1]) << 64,
                WIDE_BITS,
            )
        }
    }

    /// Writes `sum` as the summary of `node` on `level` and reports whether the stored words changed; a level-0 to level-4 node whose start run covers its span stores only the entirely-free bit.
    #[inline(always)]
    pub(super) fn store(&mut self, level: usize, node: u64, sum: Summary) -> bool {
        let at = (self.root.base[level] + node * width(level)) as usize;
        if level < NARROW_LEVELS {
            let word = pack_narrow(sum, span(level));
            std::mem::replace(&mut self.space[at], word) != word
        } else {
            let bits = u128::from(sum.start)
                | u128::from(sum.max) << WIDE_BITS
                | u128::from(sum.end) << (2 * WIDE_BITS);
            let low = std::mem::replace(&mut self.space[at], bits as u64);
            let high = std::mem::replace(&mut self.space[at + 1], (bits >> 64) as u64);
            u128::from(low) | u128::from(high) << 64 != bits
        }
    }

    /// The bitmap words that units `start..start + len`, with `len` nonzero, cover: the first word with the mask of its bits from `start` up, then the last word with the mask of its bits up to the range's last unit.
    ///
    /// Every word between is covered whole; when one word holds all the units it is both first and last, and its covered bits are the two masks' intersection.
    #[inline(always)]
    fn cover(start: u64, len: u64) -> (usize, u64, usize, u64) {
        let last = start + len - 1;
        (
            (start / 64) as usize,
            u64::MAX << (start % 64),
            (last / 64) as usize,
            u64::MAX >> (63 - last % 64),
        )
    }

    /// Hints the lines a call over `unit` reads first: its chunk's bitmap words, and on each level larger than [`HOT_WORDS`] the eight siblings that a merge or a run-end search reads, so their misses overlap the call's other reads.
    /// Each group takes a hint at its first and last word, which covers the at most two lines of eight one-word nodes and the outer two lines of eight two-word nodes on levels 5 and above.
    /// A hint reads nothing and never faults, so `unit` may lie past the volume, as a refused return's locator may; the call counts no visit.
    pub(super) fn prefetch(&self, unit: u64) {
        let space = self.space.as_ptr();
        let group = |first: u64, words: u64| {
            hint_read(space.wrapping_add(first as usize).cast());
            hint_read(space.wrapping_add((first + words - 1) as usize).cast());
        };
        group(unit / CHUNK * CHUNK_WORDS, CHUNK_WORDS);
        let mut node = unit / CHUNK;
        for level in 0..self.levels() {
            let (base, size) = (self.root.base[level], width(level));
            if self.root.base[level + 1] - base <= HOT_WORDS {
                break;
            }
            group(base + node / FANOUT * FANOUT * size, FANOUT * size);
            node /= FANOUT;
        }
    }

    /// Whether every unit of `start..start + len` is taken, counting one visit per word read: the words in address order through the first that holds a free unit of the range, or every word the range covers when none does.
    #[inline(always)]
    pub(super) fn taken(&mut self, start: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let (first, head, last, tail) = Self::cover(start, len);
        // Units within at most two words take one read of each, with one word's mask applied twice when they share it.
        let (head, tail) = match first == last {
            true => (head & tail, head & tail),
            false => (head, tail),
        };
        if last <= first + 1 && (self.space[first] & head) | (self.space[last] & tail) == 0 {
            self.work += last - first + 1;
            return true;
        }
        self.work += 1;
        if first == last {
            return false;
        }
        if self.space[first] & head != 0 {
            return false;
        }
        let between = &self.space[first + 1..last];
        if let Some(at) = between.iter().position(|&x| x != 0) {
            self.work += at + 1;
            return false;
        }
        self.work += between.len() + 1;
        self.space[last] & tail == 0
    }

    /// Marks units `start..start + len` free or taken; the caller then brings the summaries up to date, as [`update`](Self::update) and [`summarize_run`](Self::summarize_run) do.
    #[inline(always)]
    pub(super) fn mark(&mut self, start: u64, len: u64, free: bool) {
        if len == 0 {
            return;
        }
        let (first, head, last, tail) = Self::cover(start, len);
        let set =
            |word: &mut u64, mask: u64| *word = if free { *word | mask } else { *word & !mask };
        // One word's mask applies twice when the units lie in it, which sets or clears the same bits.
        let (head, tail) = match first == last {
            true => (head & tail, head & tail),
            false => (head, tail),
        };
        set(&mut self.space[first], head);
        set(&mut self.space[last], tail);
        if last > first + 1 {
            self.space[first + 1..last].fill(if free { u64::MAX } else { 0 });
        }
    }

    /// Recomputes the summaries over chunks `first..=last` and every node above them.
    ///
    /// The call counts the visits of a full recomputation, [`recompute_visits`](Self::recompute_visits), wherever it stops.
    /// A node's summary depends only on its children, so once a level's nodes all keep their stored words every node above them is already current and the pass stops.
    #[cfg(test)]
    pub(super) fn refresh(&mut self, first: u64, last: u64) {
        self.work += self.recompute_visits(first, last);
        self.settle_from(first, last, None, |_, _, _| None);
    }

    /// `summarize_run` marks the run `start..start + len` free on a bitmap whose every unit started taken and whose summaries all started zero, where the runs it receives are nonempty maximal free runs in address order; `open` carries the summary of the last chunk a run reached until a later run passes it, and [`summarize_end`](Self::summarize_end) stores the rest.
    ///
    /// Maximal input runs intersect each chunk in complete free runs. Chunks containing only allocated units retain their initial zero summaries.
    #[inline(always)]
    pub(super) fn summarize_run(
        &mut self,
        open: &mut Option<(u64, Summary)>,
        start: u64,
        len: u64,
    ) {
        self.mark(start, len, true);
        let end = start + len;
        for chunk in start / CHUNK..=(end - 1) / CHUNK {
            let (low, high) = (chunk * CHUNK, (chunk + 1) * CHUNK);
            let part = end.min(high) - start.max(low);
            let mut sum = match *open {
                Some((at, sum)) if at == chunk => sum,
                Some((at, sum)) => {
                    self.store(0, at, sum);
                    Summary::default()
                }
                None => Summary::default(),
            };
            sum.max = sum.max.max(part);
            if start <= low {
                sum.start = part;
            }
            if end >= high {
                sum.end = part;
            }
            *open = Some((chunk, sum));
        }
    }

    /// Stores the summary `open` carries and every node's summary above level 0 from its children.
    pub(super) fn summarize_end(&mut self, open: Option<(u64, Summary)>) {
        if let Some((at, sum)) = open {
            self.store(0, at, sum);
        }
        for level in 1..self.levels() {
            for node in 0..self.nodes(level) {
                let sum = self.merge(level, node);
                self.store(level, node, sum);
            }
        }
    }

    /// Brings the summaries over the marked units `from..to` and every node above them up to date after `change`.
    ///
    /// `from..to` is the nonempty range [`mark`](Self::mark) just wrote, and `change` describes the bitmap after that mark.
    /// Each node over a marked unit takes its new summary from its stored one and `change`, and recomputes from its words or children when `change` leaves its longest run unknown; the pass stops above a level whose nodes all keep their stored words, since every node above them is then current.
    /// The call counts the visits of a full recomputation of the chunks the units touch, [`recompute_visits`](Self::recompute_visits).
    /// A run strictly inside one chunk takes [`join_inside`](Self::join_inside) or [`split_inside`](Self::split_inside), and any other run takes [`settle_join`](Self::settle_join) or [`settle_split`](Self::settle_split); each is out of line, so a caller that names one change kind keeps only the inside test inline.
    #[inline(always)]
    pub(super) fn update(&mut self, from: u64, to: u64, change: Change) {
        debug_assert!(from < to, "an update covers the units a mark wrote");
        let (first, last) = (from / CHUNK, (to - 1) / CHUNK);
        // A run strictly inside one chunk holds the marked units, so `first == last`.
        let inside = |low: u64, high: u64| low > first * CHUNK && high < (first + 1) * CHUNK;
        match change {
            Change::Joined { low, high } if inside(low, high) => {
                self.join_inside(first, high - low);
            }
            Change::Split { low, high, .. } if inside(low, high) => {
                self.split_inside(first, high - low);
            }
            Change::Joined { low, high } => self.settle_join(first, last, low, high),
            Change::Split {
                low,
                start,
                end,
                high,
            } => self.settle_split(first, last, [low, start, end, high]),
        }
    }

    /// [`update`](Self::update) over chunks `first..=last` after a join into the run `low..high`, which reaches or crosses a boundary of chunk `first`.
    #[inline(never)]
    fn settle_join(&mut self, first: u64, last: u64, low: u64, high: u64) {
        self.work += self.recompute_visits(first, last);
        self.settle_run(first, last, (low, high), false, |old, n0, n1| {
            Some(joined(low, high, old, n0, n1))
        });
    }

    /// [`update`](Self::update) over chunks `first..=last` after the marked units `start..end` split the run `low..high`, which reaches or crosses a boundary of chunk `first`; `range` holds `[low, start, end, high]`.
    #[inline(never)]
    fn settle_split(&mut self, first: u64, last: u64, range: [u64; 4]) {
        self.work += self.recompute_visits(first, last);
        let [low, .., high] = range;
        self.settle_run(first, last, (low, high), true, |old, n0, n1| {
            split(range, old, n0, n1)
        });
    }

    /// [`update`](Self::update) after a join into a run of `len` units strictly inside `chunk`.
    #[inline(never)]
    fn join_inside(&mut self, chunk: u64, len: u64) {
        self.work += self.recompute_visits(chunk, chunk);
        self.settle_inside(0, chunk, len, false);
    }

    /// [`update`](Self::update) after a split of a run of `len` units strictly inside `chunk`.
    #[inline(never)]
    fn split_inside(&mut self, chunk: u64, len: u64) {
        self.work += self.recompute_visits(chunk, chunk);
        self.settle_inside(0, chunk, len, true);
    }

    /// [`update`](Self::update)'s pass for the run `low..high` a change joined, or split when `split` holds, with the change's summary rule: one chunk takes its ancestors' path through [`settle_path`](Self::settle_path) at once, and several chunks take [`settle_from`](Self::settle_from), which hands its pass to [`settle_path`](Self::settle_path) at the first level where their ancestors meet in one node.
    #[inline(always)]
    fn settle_run(
        &mut self,
        first: u64,
        last: u64,
        run: (u64, u64),
        split: bool,
        rule: impl Fn(Summary, u64, u64) -> Option<Summary>,
    ) {
        if first == last {
            self.settle_path(0, first, run, split, rule);
        } else {
            self.settle_from(first, last, Some((run, split)), rule);
        }
    }

    /// The pass of [`update`](Self::update) from `node` on `level` up, one node per level, until a node keeps its stored words or the root is written, for the run `low..high` the change joined, or split when `split` holds, with the summary rule `rule(old, n0, n1)` for the node over units `n0..n1`; the pass counts no visit.
    ///
    /// The narrow levels read and write their words in place, and the wide levels go through [`decode`](Self::decode) and [`store`](Self::store); a narrow node the rule leaves to its words or children recomputes through [`repack`](Self::repack), and a wide one through [`restore`](Self::restore).
    /// The first narrow node that holds the run strictly inside its span hands the rest of the pass to [`settle_inside`](Self::settle_inside).
    #[inline(always)]
    fn settle_path(
        &mut self,
        mut level: usize,
        mut node: u64,
        (low, high): (u64, u64),
        split: bool,
        rule: impl Fn(Summary, u64, u64) -> Option<Summary>,
    ) {
        let levels = self.levels();
        let narrow_top = levels.min(NARROW_LEVELS);
        let mut size = span(level);
        while level < narrow_top {
            let at = (self.root.base[level] + node) as usize;
            let word = self.space[at];
            let n0 = node * size;
            if low > n0 && high < n0 + size {
                break;
            }
            let next = match rule(narrow(word, size), n0, n0 + size) {
                Some(sum) => pack_narrow(sum, size),
                None => self.repack(level, node, size),
            };
            if next == word {
                return;
            }
            self.space[at] = next;
            (node, size, level) = (node / FANOUT, size << 3, level + 1);
        }
        if level < narrow_top {
            return self.settle_inside(level, node, high - low, split);
        }
        while level < levels {
            let n0 = node * size;
            let changed = match rule(self.decode(level, node), n0, n0 + size) {
                Some(sum) => self.store(level, node, sum),
                None => self.restore(level, node),
            };
            if !changed {
                return;
            }
            (node, size, level) = (node / FANOUT, size << 3, level + 1);
        }
    }

    /// The pass of [`update`](Self::update) from `node` on `level` up, once the node holds strictly inside its span the run of `len` units that the change joined, or split when `split` holds; the pass counts no visit.
    ///
    /// Each ancestor holds the run strictly inside too, and the change leaves its start and end runs alone: a join raises a longest run shorter than `len` to `len`, and a split leaves a node whose longest run exceeds `len` unchanged and recomputes the rest; the pass stops at the first node that keeps its stored words.
    #[inline(always)]
    fn settle_inside(&mut self, mut level: usize, mut node: u64, len: u64, split: bool) {
        const MAX_FIELD: u64 = ((1 << NARROW_BITS) - 1) << NARROW_BITS;
        let levels = self.levels();
        let narrow_top = levels.min(NARROW_LEVELS);
        let mut size = span(level);
        // A node holding the run strictly inside has a taken unit on each side of it, so its word carries the three fields.
        let field = len << NARROW_BITS;
        while level < narrow_top {
            let at = (self.root.base[level] + node) as usize;
            let word = self.space[at];
            if split {
                if word & MAX_FIELD > field {
                    return;
                }
                let next = self.repack(level, node, size);
                if next == word {
                    return;
                }
                self.space[at] = next;
            } else {
                // A join raises a shorter longest run to the run's length, which changes the word.
                if word & MAX_FIELD >= field {
                    return;
                }
                self.space[at] = word & !MAX_FIELD | field;
            }
            (node, size, level) = (node / FANOUT, size << 3, level + 1);
        }
        while level < levels {
            let sum = self.decode(level, node);
            let changed = match split {
                false if sum.max >= len => false,
                false => self.store(level, node, Summary { max: len, ..sum }),
                true if sum.max > len => false,
                true => self.restore(level, node),
            };
            if !changed {
                return;
            }
            (node, level) = (node / FANOUT, level + 1);
        }
    }

    /// The summary pass of [`update`](Self::update) processes chunks `first..=last` and their ancestors while preserving the visit count. Each node over units `n0..n1` uses `rule(old, n0, n1)` for its summary and recomputes from its words or children when the rule returns `None`.
    ///
    /// The pass stops after a level whose nodes all keep their stored words.
    /// A change's pass passes its run and kind as `path`, and at the first level whose covered nodes reduce to one node the pass continues on [`settle_path`](Self::settle_path).
    /// Below that level a change's nodes strictly between the first and the last lie inside the marked units, so a split leaves them taken and a join leaves them free, and the pass stores the entirely taken or entirely free summary directly.
    #[inline(never)]
    fn settle_from(
        &mut self,
        mut first: u64,
        mut last: u64,
        path: Option<((u64, u64), bool)>,
        rule: impl Fn(Summary, u64, u64) -> Option<Summary>,
    ) {
        let levels = self.levels();
        let (mut level, mut size) = (0, CHUNK);
        while level < levels {
            let mut changed = false;
            match path {
                Some((run, split)) => {
                    if first == last {
                        return self.settle_path(level, first, run, split, rule);
                    }
                    let inner = match split {
                        true => Summary::default(),
                        false => Summary {
                            start: size,
                            max: size,
                            end: size,
                        },
                    };
                    for node in first + 1..last {
                        changed |= self.store(level, node, inner);
                    }
                    changed |= self.settle_node(level, first, &rule);
                    changed |= self.settle_node(level, last, &rule);
                }
                None => {
                    for node in first..last + 1 {
                        changed |= self.settle_node(level, node, &rule);
                    }
                }
            }
            if !changed {
                return;
            }
            (first, last, size, level) = (first / FANOUT, last / FANOUT, size << 3, level + 1);
        }
    }

    /// Stores the summary of `node` on `level` that `rule` derives from its stored one, or recomputes it from its words or children where `rule` leaves it, and reports whether the stored words changed.
    #[inline(always)]
    fn settle_node(
        &mut self,
        level: usize,
        node: u64,
        rule: &impl Fn(Summary, u64, u64) -> Option<Summary>,
    ) -> bool {
        let size = span(level);
        let n0 = node * size;
        if level < NARROW_LEVELS {
            let at = (self.root.base[level] + node) as usize;
            let word = self.space[at];
            let sum = rule(narrow(word, size), n0, n0 + size)
                .unwrap_or_else(|| self.recompute(level, node));
            let next = pack_narrow(sum, size);
            self.space[at] = next;
            next != word
        } else {
            let sum = rule(self.decode(level, node), n0, n0 + size)
                .unwrap_or_else(|| self.recompute(level, node));
            self.store(level, node, sum)
        }
    }

    /// Recomputes the summary of `node` on `level` from its words or children and stores it, reporting whether the stored words changed; the wide levels of [`settle_path`](Self::settle_path) and [`settle_inside`](Self::settle_inside) call it out of line.
    #[inline(never)]
    fn restore(&mut self, level: usize, node: u64) -> bool {
        let sum = self.recompute(level, node);
        self.store(level, node, sum)
    }

    /// Recomputes and encodes the summary of `node` on narrow `level`, where `node` spans `size` units.
    ///
    /// A chunk's [`CHUNK_WORDS`] bitmap words or a node's [`FANOUT`] child words that are all zero cover only taken units and give the zero word; that test runs inline.
    /// Any other full group recomputes out of line in [`repack_leaf`](Self::repack_leaf) or [`repack_merge`](Self::repack_merge), and the last node of a level, with fewer words or children, recomputes through [`leaf`](Self::leaf) or [`merge`](Self::merge).
    #[inline(always)]
    fn repack(&self, level: usize, node: u64, size: u64) -> u64 {
        if level == 0 {
            match self.group::<{ CHUNK_WORDS as usize }>(node * CHUNK_WORDS, self.bitmap_words()) {
                Some(words) if words.iter().all(|&word| word == 0) => 0,
                Some(words) => Self::repack_leaf(words, size),
                None => pack_narrow(self.leaf(node), size),
            }
        } else {
            let first = self.root.base[level - 1] + node * FANOUT;
            match self.group::<{ FANOUT as usize }>(first, self.root.base[level]) {
                Some(words) if words.iter().all(|&word| word == 0) => 0,
                Some(words) => Self::repack_merge(words, size),
                None => pack_narrow(self.merge(level, node), size),
            }
        }
    }

    /// The `N` space words from word `first`, or `None` when they reach past word `end`.
    #[inline(always)]
    fn group<const N: usize>(&self, first: u64, end: u64) -> Option<&[u64; N]> {
        if first + N as u64 > end {
            return None;
        }
        self.space
            .get(first as usize..first as usize + N)?
            .try_into()
            .ok()
    }

    /// [`repack`](Self::repack) for a chunk whose bitmap `words` hold a free unit.
    #[inline(never)]
    fn repack_leaf(words: &[u64; CHUNK_WORDS as usize], size: u64) -> u64 {
        pack_narrow(Self::leaf_words(words), size)
    }

    /// [`repack`](Self::repack) for a node of `size` units whose eight narrow children's `words` hold a free unit.
    #[inline(never)]
    fn repack_merge(words: &[u64; FANOUT as usize], size: u64) -> u64 {
        let sum = merge_taken(words).unwrap_or_else(|| fold_narrow(words, size / FANOUT, false));
        pack_narrow(sum, size)
    }

    /// The summary of `node` on `level` from its bitmap words or its children.
    #[inline(always)]
    fn recompute(&self, level: usize, node: u64) -> Summary {
        if level == 0 {
            self.leaf(node)
        } else {
            self.merge(level, node)
        }
    }

    /// The reads a recomputation of chunks `first..=last` and every node above them makes: each chunk's bitmap words, then each level's children under the covered nodes, fewer where the volume ends.
    ///
    /// A single chunk below [`ExtentRoot::edge`](super::allocator::ExtentRoot::edge) has eight words and every ancestor below the root full, so its count is eight words, eight children on each level from 1 to the level below the root, and the root's children.
    #[inline(always)]
    fn recompute_visits(&self, mut first: u64, mut last: u64) -> usize {
        if first == last && first < self.root.edge {
            let top = self.levels() - 1;
            return (CHUNK_WORDS + FANOUT * (top as u64 - 1) + self.nodes(top - 1)) as usize;
        }
        let mut visits = self.bitmap_words().min((last + 1) * CHUNK_WORDS) - first * CHUNK_WORDS;
        for level in 1..self.levels() {
            (first, last) = (first / FANOUT, last / FANOUT);
            visits += self.nodes(level - 1).min((last + 1) * FANOUT) - first * FANOUT;
        }
        visits as usize
    }

    /// The summary of `chunk` from its bitmap words, each a child of span 64; words past the volume hold no free unit.
    fn leaf(&self, chunk: u64) -> Summary {
        let first = (chunk * CHUNK_WORDS) as usize;
        Self::leaf_words(
            &self.space[first..(first + CHUNK_WORDS as usize).min(self.bitmap_words() as usize)],
        )
    }

    /// The summary of a chunk from its bitmap `words`, lowest first; the volume's last chunk may pass fewer than [`CHUNK_WORDS`] words, and the missing words hold no free unit.
    #[inline(always)]
    fn leaf_words(words: &[u64]) -> Summary {
        let mut held = 0u32;
        for (index, &x) in words.iter().enumerate() {
            held |= u32::from(x != 0) << index;
        }
        if held == 0 {
            return Summary::default();
        }
        // The fold visits only the words holding a free unit; a gap of taken words before one, after the last, or past the volume ends the run so far, as a taken word would.
        let (mut start, mut max, mut run, mut closed) = (0, 0, 0, false);
        let mut close = |run: &mut u64, max: &mut u64| {
            *max = (*max).max(*run);
            if !closed {
                (start, closed) = (*run, true);
            }
            *run = 0;
        };
        let mut next = 0;
        while held != 0 {
            let index = held.trailing_zeros() as usize;
            held &= held - 1;
            if index > next {
                close(&mut run, &mut max);
            }
            next = index + 1;
            let x = words[index];
            if x == u64::MAX {
                run += 64;
                continue;
            }
            let (head, tail) = (u64::from(x.trailing_ones()), u64::from(x.leading_ones()));
            // The runs inside the word, with its head and tail runs cleared; `tail` is below 64 because the word holds a taken unit.
            max = max.max(longest(x & x.wrapping_add(1) & u64::MAX >> tail));
            run += head;
            close(&mut run, &mut max);
            run = tail;
        }
        if next < CHUNK_WORDS as usize {
            close(&mut run, &mut max);
        }
        Summary {
            start: if closed { start } else { run },
            max: max.max(run),
            end: run,
        }
    }

    /// The summary of `node` on `level` from its children; children past the last node hold no free unit.
    fn merge(&self, level: usize, node: u64) -> Summary {
        let below = level - 1;
        let first = node * FANOUT;
        let count = self.nodes(below).min(first + FANOUT) - first;
        let size = span(below);
        if below < NARROW_LEVELS {
            let at = (self.root.base[below] + first) as usize;
            let words = &self.space[at..at + count as usize];
            if let Ok(words) = <&[u64; FANOUT as usize]>::try_from(words)
                && let Some(sum) = merge_taken(words)
            {
                return sum;
            }
            return fold_narrow(words, size, count < FANOUT);
        }
        let mut fold = Fold::default();
        for child in first..first + count {
            fold.push(self.decode(below, child), size);
        }
        fold.finish(count < FANOUT)
    }

    /// The longest free run of the volume, from the root summary.
    #[inline(always)]
    pub(super) fn longest_run(&mut self) -> u64 {
        self.work += 1;
        self.longest_free_run()
    }

    /// `longest_free_run` returns the volume's longest free run in units in constant time and preserves the visit count.
    #[inline(always)]
    pub(crate) fn longest_free_run(&self) -> u64 {
        self.decode(self.levels() - 1, 0).max
    }

    /// The first unit of the lowest run of `n` free units, descending from a root whose longest run the caller found at least `n`.
    ///
    /// Each level scans the node's children in address order, one visit each, until a run that ends in a child's start run reaches `n` units or a child's longest run does; the chunk level scans words the same way.
    pub(super) fn first_fit(&mut self, n: u64) -> Option<u64> {
        let mut visits = 0;
        let found = self.fit_search(n, &mut visits);
        self.work += visits;
        found
    }

    /// [`first_fit`](Self::first_fit) with its visits added to `visits`.
    #[inline(always)]
    fn fit_search(&self, n: u64, visits: &mut usize) -> Option<u64> {
        let top = self.levels() - 1;
        let mut node = 0;
        for below in (NARROW_LEVELS..top).rev() {
            let children = node * FANOUT..self.nodes(below).min((node + 1) * FANOUT);
            match Self::scan(children, span(below), n, visits, |child| {
                self.decode(below, child)
            })? {
                Step::Fit(unit) => return Some(unit),
                Step::Into(child) => node = child,
            }
        }
        // A narrow level's nodes take one word each, so its words run from its base to the next level's.
        for below in (0..top.min(NARROW_LEVELS)).rev() {
            let (base, end) = (self.root.base[below], self.root.base[below + 1]);
            let first = base + node * FANOUT;
            let words = &self.space[first as usize..end.min(first + FANOUT) as usize];
            match Self::scan_narrow(words, node * FANOUT, span(below), n, visits)? {
                Step::Fit(unit) => return Some(unit),
                Step::Into(child) => node = child,
            }
        }
        let mut run = 0;
        for index in node * CHUNK_WORDS..self.bitmap_words().min((node + 1) * CHUNK_WORDS) {
            *visits += 1;
            let (x, base) = (self.space[index as usize], index * 64);
            if x == 0 {
                run = 0;
                continue;
            }
            if run + u64::from(x.trailing_ones()) >= n {
                return Some(base - run);
            }
            if let Some(bit) = run_in(x, n) {
                return Some(base + bit);
            }
            run = if x == u64::MAX {
                run + 64
            } else {
                u64::from(x.leading_ones())
            };
        }
        None
    }

    /// [`scan`](Self::scan) over the stored `words` of narrow children from `first` on, of `size` units each, reading the fields in place: a child's longest run holds `n` units exactly when its word's middle field is at least `n`, and an entirely free child, whose middle field is clear, holds no longer run than its start run.
    #[inline(always)]
    fn scan_narrow(
        words: &[u64],
        first: u64,
        size: u64,
        n: u64,
        visits: &mut usize,
    ) -> Option<Step> {
        // A full group has a fixed length, so its scan unrolls.
        match <&[u64; FANOUT as usize]>::try_from(words) {
            Ok(group) => Self::scan_words(group, first, size, n, visits),
            Err(_) => Self::scan_words(words, first, size, n, visits),
        }
    }

    /// The scan of [`scan_narrow`](Self::scan_narrow), counting its visits once at its exit.
    #[inline(always)]
    fn scan_words(
        words: &[u64],
        first: u64,
        size: u64,
        n: u64,
        visits: &mut usize,
    ) -> Option<Step> {
        const MASK: u64 = (1 << NARROW_BITS) - 1;
        let mut run = 0;
        for (index, &word) in words.iter().enumerate() {
            let child = first + index as u64;
            let free = word & ENTIRELY_FREE != 0;
            let start = if free { size } else { word & MASK };
            if run + start >= n {
                *visits += index + 1;
                return Some(Step::Fit(child * size - run));
            }
            if word & MASK << NARROW_BITS >= n << NARROW_BITS {
                *visits += index + 1;
                return Some(Step::Into(child));
            }
            run = if free {
                run + size
            } else {
                word >> (2 * NARROW_BITS)
            };
        }
        *visits += words.len();
        None
    }

    /// One level of [`fit_search`](Self::fit_search) over `children` of `size` units, whose summaries `summary` reads, adding one visit per child read to `visits`: the first unit of the fit that ends in a child's start run, the first child whose longest run holds `n` units, whichever comes first, or `None` when neither exists.
    #[inline(always)]
    fn scan(
        children: std::ops::Range<u64>,
        size: u64,
        n: u64,
        visits: &mut usize,
        summary: impl Fn(u64) -> Summary,
    ) -> Option<Step> {
        let mut run = 0;
        for child in children {
            *visits += 1;
            let sum = summary(child);
            if run + sum.start >= n {
                return Some(Step::Fit(child * size - run));
            }
            if sum.max >= n {
                return Some(Step::Into(child));
            }
            run = if sum.start == size {
                run + size
            } else {
                sum.end
            };
        }
        None
    }

    /// Free units from `unit` up to the first taken unit or the volume's end, counting the visits of a scan of `unit`'s word, the later words of its chunk, then at most `FANOUT - 1` later sibling summaries per level, while the units so far stay free.
    ///
    /// When the end run of the chunk's level-0 summary covers all the chunk's later words, that run decides them, and on each level the end run of the parent's summary decides the later siblings the same way; each word or sibling so decided counts one visit, and the parent summary counts none.
    /// The decided words and siblings lie wholly after `unit`'s word, so the result and the count match the scan while every unit [`mark`](Self::mark) has written since the last summary update lies below `unit`; [`release`](Self::release) calls this at its extent's end after marking the extent free and before [`update`](Self::update).
    #[inline(always)]
    pub(super) fn free_after(&mut self, unit: u64) -> u64 {
        let index = unit / 64;
        if index >= self.bitmap_words() {
            return 0;
        }
        let bit = unit % 64;
        let total = u64::from((self.space[index as usize] >> bit).trailing_ones());
        if total < 64 - bit {
            self.work += 1;
            return total;
        }
        self.free_after_words(index, total)
    }

    /// [`free_after`](Self::free_after) once the run reaches the end of word `index` with `total` free units so far, out of line.
    #[inline(never)]
    fn free_after_words(&mut self, index: u64, mut total: u64) -> u64 {
        let words = self.bitmap_words();
        let mut reads = 1;
        let mut node = index / CHUNK_WORDS;
        let chunk_end = words.min((node + 1) * CHUNK_WORDS);
        let after = chunk_end - index - 1;
        if self.decode(0, node).end >= 64 * after {
            reads += after as usize;
            total += 64 * after;
        } else {
            for &x in &self.space[index as usize + 1..chunk_end as usize] {
                reads += 1;
                total += u64::from(x.trailing_ones());
                if x != u64::MAX {
                    self.work += reads;
                    return total;
                }
            }
        }
        for level in 0..self.levels() - 1 {
            let (size, end) = (
                span(level),
                self.nodes(level).min((node / FANOUT + 1) * FANOUT),
            );
            let after = end - node - 1;
            if self.decode(level + 1, node / FANOUT).end >= size * after {
                reads += after as usize;
                total += size * after;
                node /= FANOUT;
                continue;
            }
            for sibling in node + 1..end {
                reads += 1;
                let sum = self.decode(level, sibling);
                if sum.start != size {
                    self.work += reads;
                    return total + sum.start;
                }
                total += size;
            }
            node /= FANOUT;
        }
        self.work += reads;
        total
    }

    /// Free units just below `unit` down to the first taken unit or unit zero, searched and counted as [`free_after`](Self::free_after) is, with start runs deciding the earlier words and siblings.
    ///
    /// The result and the count match the scan while every unit [`mark`](Self::mark) has written since the last summary update lies at or above `unit`; [`release`](Self::release) calls this at its extent's start after marking the extent free and before [`update`](Self::update).
    #[inline(always)]
    pub(super) fn free_before(&mut self, unit: u64) -> u64 {
        if unit == 0 {
            return 0;
        }
        let (index, bit) = ((unit - 1) / 64, (unit - 1) % 64);
        let total = u64::from((self.space[index as usize] << (63 - bit)).leading_ones());
        if total <= bit {
            self.work += 1;
            return total;
        }
        self.free_before_words(index, total)
    }

    /// [`free_before`](Self::free_before) once the run reaches the start of word `index` with `total` free units so far, out of line.
    #[inline(never)]
    fn free_before_words(&mut self, index: u64, mut total: u64) -> u64 {
        let mut reads = 1;
        let mut node = index / CHUNK_WORDS;
        let chunk_start = node * CHUNK_WORDS;
        let before = index - chunk_start;
        if self.decode(0, node).start >= 64 * before {
            reads += before as usize;
            total += 64 * before;
        } else {
            for &x in self.space[chunk_start as usize..index as usize]
                .iter()
                .rev()
            {
                reads += 1;
                total += u64::from(x.leading_ones());
                if x != u64::MAX {
                    self.work += reads;
                    return total;
                }
            }
        }
        for level in 0..self.levels() - 1 {
            let (size, first) = (span(level), node / FANOUT * FANOUT);
            let before = node - first;
            if self.decode(level + 1, node / FANOUT).start >= size * before {
                reads += before as usize;
                total += size * before;
                node /= FANOUT;
                continue;
            }
            for sibling in (first..node).rev() {
                reads += 1;
                let sum = self.decode(level, sibling);
                if sum.start != size {
                    self.work += reads;
                    return total + sum.end;
                }
                total += size;
            }
            node /= FANOUT;
        }
        self.work += reads;
        total
    }
}
