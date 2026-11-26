//! Hierarchical membership of the pending cohort: the slots service visits.
//!
//! The cohort has two sets, each a bitmap of one bit per slot under a
//! summary of one bit per bitmap word. The retired set marks the slots
//! whose state is `Retired`; the gate holder writes both of its levels in
//! the hold that moves the state, so its summary bit is set exactly while
//! its bitmap word is nonzero. The parked set marks the slots a park
//! flagged without the gate. A park sets its slot's bit and then the bit's
//! summary bit, each with `Release`; only the gate holder clears either.
//! A clear can leave a summary bit beside a zero bitmap word, so the
//! parked summary may run ahead of its words but never behind a set bit
//! whose park completed: [`Parked`] repairs a stale summary bit by
//! clearing it with `Acquire` and loading the word again, and sets it back
//! when a park's bit landed meanwhile. The argument is the one the parked
//! slot bit makes against its flag: every write to a summary word is a
//! read-modify-write, so the clear reads from the release sequence of
//! every park whose summary bit preceded it, and the second load reads that
//! park's bitmap bit or a later write to its word, which only the hold that
//! absorbs or returns the park clears; a park whose summary bit follows the
//! clear keeps its bit. The gate holder's clears of parked bits, [`parked_flag`]
//! and [`unmark_parked_slot`], live here beside the summary protocol, so
//! this module owns every write to the parked set.
//!
//! A [`walk`] hands the members at or after a position to a [`Cohort`] in
//! order. It reads a summary word as it enters the word's group and a
//! bitmap word when the summary marks it, each read one probe the cohort
//! funds before it is made, and hands on each member of a bitmap word from
//! the bits it read, so it makes at most one probe of each word. After an
//! empty summary word, the walk scans the following summary words in one
//! run bounded by the probes the funds afford, loading them eight at a
//! time, and charges one probe for each word up to and including the first
//! marked one. A summary word covers [`GROUP_SLOTS`] slots, so the probes a
//! walk makes depend on the configured slot count and on where the members
//! lie; a stale parked summary bit costs one bitmap probe, in the walk that
//! reads it and repairs it. A walk the cohort stops short reports the
//! position its funded probes reached, or the member it refused, which is
//! where the next walk resumes.

use std::marker::PhantomData;
use std::ops::Range;
use std::sync::atomic::Ordering;

use super::credit::BitWord;
use super::word::ABANDONED;

/// The orderings of the parked set's writes, and whether a stale clear
/// loads again. [`Published`] carries the protocol the module documentation
/// states; the bodies below run under any strength, so a model substitutes
/// one ordering or the second look to show which property it carries.
pub(crate) trait Marking {
    /// A park's slot bit.
    const BIT: Ordering;
    /// A park's summary bit.
    const SUMMARY: Ordering;
    /// A gate holder's clear of a stale slot bit.
    const BIT_CLEAR: Ordering;
    /// A gate holder's clear of a stale summary bit.
    const SUMMARY_CLEAR: Ordering;
    /// Whether a stale clear loads again and sets the bit back when a
    /// park's write landed meanwhile.
    const SECOND_LOOK: bool;
}

/// The parked set's production strength: `Release` sets, `Acquire` stale
/// clears, and the second look after each clear.
pub(crate) struct Published;

impl Marking for Published {
    const BIT: Ordering = Ordering::Release;
    const SUMMARY: Ordering = Ordering::Release;
    const BIT_CLEAR: Ordering = Ordering::Acquire;
    const SUMMARY_CLEAR: Ordering = Ordering::Acquire;
    const SECOND_LOOK: bool = true;
}

/// Slots one summary word covers: one bit per bitmap word of 64 slots.
pub(crate) const GROUP_SLOTS: usize = 64 * 64;

/// Where a walk of one membership set stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Walked {
    /// Every member from the walk's start to its end was visited.
    Clear,
    /// The funds refused the next probe. Every member from the walk's
    /// start to this position was visited, and the next walk resumes here.
    Short(usize),
    /// The cohort refused this member, which it left unvisited. Every
    /// member before it was visited, and the next walk resumes on it.
    Refused(usize),
}

/// The probes a walk may make. The walk asks before every read, so each
/// read it makes is one the caller funded; a scan of consecutive summary
/// words asks once how many it may read and reports how many it charges:
/// the words up to and including the first marked one.
pub(crate) trait Funds {
    /// Probes the caller would still fund.
    fn affordable(&self) -> usize;
    /// Records `probes` words examined, at most what `affordable` reported.
    fn spend(&mut self, probes: usize);
    /// Funds one probe, or refuses.
    #[inline(always)]
    fn fund(&mut self) -> bool {
        let funded = self.affordable() != 0;
        if funded {
            self.spend(1);
        }
        funded
    }
}

/// The two levels of one membership set as a walk reads them. A read
/// returns the whole word; the walk masks it.
pub(crate) trait Levels {
    /// Summary word `group`: bit `i` stands for bitmap word `64 * group + i`.
    fn summary(&mut self, group: usize) -> u64;
    /// Bitmap word `word`, read because its summary bit was set.
    fn word(&mut self, word: usize) -> u64;
    /// The first summary word in `groups` with a set bit, and its bits.
    /// The walk funds every word of `groups` and charges the words up to
    /// and including the reported one, so an implementation may load later
    /// words of `groups` as long as it reports the first marked word in
    /// index order.
    fn first_marked(&mut self, groups: Range<usize>) -> Option<(usize, u64)>;
}

/// The retired set, read under the pool gate that writes it.
pub(crate) struct Retired<'a> {
    pub bits: &'a [u64],
    pub summary: &'a [u64],
}

impl Levels for Retired<'_> {
    #[inline(always)]
    fn summary(&mut self, group: usize) -> u64 {
        self.summary[group]
    }

    #[inline(always)]
    fn word(&mut self, word: usize) -> u64 {
        self.bits[word]
    }

    #[inline(always)]
    fn first_marked(&mut self, groups: Range<usize>) -> Option<(usize, u64)> {
        let first = groups.start;
        let words = &self.summary[groups];
        let (at, marks) = first_nonzero(words, |word| *word)?;
        Some((first + at, marks))
    }
}

/// The parked set, read by the pool gate's holder while parks set bits
/// without the gate, at strength `M`. `repaired` counts the stale summary
/// bits this view cleared and left clear. `relit` counts the stale summary
/// bits this view cleared and then set back because the second load found
/// a park's bit: the overlap of a stale clear and a concurrent park that
/// the parked model witnesses.
pub(crate) struct Parked<'a, W: BitWord, M: Marking> {
    pub bits: &'a [W],
    pub summary: &'a [W],
    pub repaired: usize,
    pub relit: usize,
    marking: PhantomData<M>,
}

impl<'a, W: BitWord, M: Marking> Parked<'a, W, M> {
    /// A view of `bits` under `summary` that has repaired nothing yet.
    #[inline(always)]
    pub(crate) fn new(bits: &'a [W], summary: &'a [W]) -> Self {
        Self {
            bits,
            summary,
            repaired: 0,
            relit: 0,
            marking: PhantomData,
        }
    }
}

impl<W: BitWord, M: Marking> Levels for Parked<'_, W, M> {
    /// A relaxed load: a set bit only directs the walk to its word, and a
    /// clear bit for a park concurrent with the walk is a park a relaxed
    /// flag load would miss as well. [`first_marked`](Levels::first_marked)
    /// loads summary words the same way.
    #[inline(always)]
    fn summary(&mut self, group: usize) -> u64 {
        self.summary[group].load(Ordering::Relaxed)
    }

    #[inline(always)]
    fn first_marked(&mut self, groups: Range<usize>) -> Option<(usize, u64)> {
        let first = groups.start;
        let words = &self.summary[groups];
        let (at, marks) = first_nonzero(words, |word| word.load(Ordering::Relaxed))?;
        Some((first + at, marks))
    }

    /// A zero word under a set summary bit is stale; the holder clears the
    /// bit with `M::SUMMARY_CLEAR`, `Acquire` in production, and, under
    /// `M::SECOND_LOOK`, loads the word again, setting the bit back when a
    /// park's bit is there.
    #[inline(always)]
    fn word(&mut self, word: usize) -> u64 {
        let bits = self.bits[word].load(Ordering::Relaxed);
        if bits != 0 {
            return bits;
        }
        let (group, bit) = (&self.summary[word / 64], 1u64 << (word % 64));
        group.fetch_and(!bit, M::SUMMARY_CLEAR);
        let bits = if M::SECOND_LOOK {
            self.bits[word].load(Ordering::Relaxed)
        } else {
            0
        };
        if bits != 0 {
            group.fetch_or(bit, Ordering::Relaxed);
            self.relit += 1;
        } else {
            self.repaired += 1;
        }
        bits
    }
}

/// The first index of `words` whose value `read` returns nonzero, with the
/// value. The scan loads eight words at a time and tests them with one OR
/// of the eight values, and reports the first nonzero word of a
/// nonzero eight in index order; the fewer than eight words left after the
/// last full eight are read one at a time.
#[inline(always)]
fn first_nonzero<T>(words: &[T], read: impl Fn(&T) -> u64) -> Option<(usize, u64)> {
    let (eights, rest) = words.as_chunks::<8>();
    for (index, eight) in eights.iter().enumerate() {
        let values = eight.each_ref().map(&read);
        if values.iter().fold(0, |any, value| any | value) != 0 {
            let lane = values.iter().position(|&value| value != 0)?;
            return Some((8 * index + lane, values[lane]));
        }
    }
    rest.iter().enumerate().find_map(|(lane, word)| {
        let value = read(word);
        (value != 0).then_some((8 * eights.len() + lane, value))
    })
}

/// Records `slot` in the parked set: its bit, then its word's summary bit,
/// both with `Release` under [`Published`], so a gate holder whose acquire
/// reads either also reads what the park wrote before it. The caller set
/// the slot's abandonment flag first.
#[inline(always)]
pub(crate) fn mark_parked<W: BitWord, M: Marking>(bits: &[W], summary: &[W], slot: usize) {
    let word = slot / 64;
    bits[word].fetch_or(1 << (slot % 64), M::BIT);
    summary[word / 64].fetch_or(1 << (word % 64), M::SUMMARY);
}

/// Whether `slot`, whose parked bit the caller read set, has a lifetime
/// word, `ident`, that carries [`ABANDONED`]. The caller holds the pool
/// gate, so only the caller clears the bit or the flag. A set bit beside a clear flag is
/// stale: its park's bit landed after the return that cleared the flag, or
/// after the retirement that absorbed the park. The holder clears it, then
/// loads the word again. A park of the slot's current incarnation sets its
/// flag before its `Release` bit, so when the `Acquire` clear reads that
/// bit the second load sees the flag and the holder sets the bit again;
/// when the clear precedes that bit in the word's modification order, the
/// bit lands after the clear and survives. Either way the park keeps its
/// bit. The orderings and the second look are `M`'s.
#[inline(always)]
pub(crate) fn parked_flag<P: BitWord, I: BitWord, M: Marking>(
    parked: &[P],
    ident: &I,
    slot: usize,
) -> bool {
    let set = || ident.load(Ordering::Relaxed) & ABANDONED != 0;
    if set() {
        return true;
    }
    let (word, bit) = (&parked[slot / 64], 1u64 << (slot % 64));
    word.fetch_and(!bit, M::BIT_CLEAR);
    if M::SECOND_LOOK && set() {
        word.fetch_or(bit, Ordering::Relaxed);
        return true;
    }
    false
}

/// Clears `slot`'s parked bit, for the gate holder that absorbs or returns
/// the park that set it. The park's bit may still be in flight; one that
/// lands after this clear is stale, and a later park pass that meets it
/// clears it: beside a clear flag through [`parked_flag`], or beside a
/// retired flag through the park pass's retired check. The clear touches
/// only `slot`'s bit, so a park of another slot in the same bitmap word
/// keeps its bit.
#[inline(always)]
pub(crate) fn unmark_parked_slot<W: BitWord>(parked: &[W], slot: usize) {
    let (word, bit) = (&parked[slot / 64], 1u64 << (slot % 64));
    if word.load(Ordering::Relaxed) & bit != 0 {
        word.fetch_and(!bit, Ordering::Relaxed);
    }
}

/// One pass over a membership set: the set's two levels, the funds its
/// probes draw on, and what it does with each member.
pub(crate) trait Cohort: Levels + Funds {
    /// Visits member `slot` and returns `true`, or returns `false` to
    /// refuse it, leaving it unvisited and stopping the walk in front of
    /// it. `next` is the following member in the bits the walk read from
    /// `slot`'s bitmap word, below the slot count and possibly at or past
    /// the walk's end. The visit writes at most `slot`'s own bit and,
    /// in the retired set, its word's summary bit.
    fn member(&mut self, slot: usize, next: Option<usize>) -> bool;
}

/// Walks `cohort`'s members in `start..end` in order, where `end` is at
/// most the slot count, and reports where it stopped. A summary word is
/// read as the walk enters its group and a bitmap word when the summary
/// marks it; the cohort's funds approve every read before it is made.
/// After an empty summary word, the following words of groups that start
/// below `end` are scanned up to the first marked one or as many as the
/// funds afford, and each word up to and including the first marked one is
/// charged as one probe. The walk hands each member of a bitmap
/// word to the cohort from the bits it read; a member's visit writes at
/// most its own bit and its word's summary bit, so the summary bits the
/// walk holds for later words stay current. In the parked set the walk sees
/// the words as it read them: a park whose bit lands after the read, like
/// one behind the walk's position, is found by a later walk. Bits at or
/// past the slot count stay clear.
#[inline(always)]
pub(crate) fn walk(cohort: &mut impl Cohort, start: usize, end: usize) -> Walked {
    let mut at = start;
    while at < end {
        if !cohort.fund() {
            return Walked::Short(at);
        }
        let mut group = at / GROUP_SLOTS;
        let mut marks = cohort.summary(group) & (u64::MAX << (at / 64 % 64));
        if marks == 0 {
            // The groups that start below `end` after this one, as many as
            // the funds afford.
            let (first, groups) = (group + 1, end.div_ceil(GROUP_SLOTS));
            let limit = groups.min(first.saturating_add(cohort.affordable()));
            match cohort.first_marked(first..limit) {
                Some((found, bits)) => {
                    cohort.spend(found - first + 1);
                    (group, at, marks) = (found, found * GROUP_SLOTS, bits);
                }
                None => {
                    cohort.spend(limit - first);
                    return if limit == groups {
                        Walked::Clear
                    } else {
                        Walked::Short(limit * GROUP_SLOTS)
                    };
                }
            }
        }
        while marks != 0 {
            let word = group * 64 + marks.trailing_zeros() as usize;
            at = at.max(word * 64);
            if at >= end {
                return Walked::Clear;
            }
            if !cohort.fund() {
                return Walked::Short(at);
            }
            marks &= marks - 1;
            let base = word * 64;
            let mut bits = cohort.word(word) & (u64::MAX << (at % 64));
            while bits != 0 {
                let slot = base + bits.trailing_zeros() as usize;
                if slot >= end {
                    return Walked::Clear;
                }
                bits &= bits - 1;
                let next = (bits != 0).then(|| base + bits.trailing_zeros() as usize);
                if !cohort.member(slot, next) {
                    return Walked::Refused(slot);
                }
            }
            at = base + 64;
        }
        at = (group + 1) * GROUP_SLOTS;
    }
    Walked::Clear
}

/// Where a test's search for the first member stopped: on that member, or
/// where the walk stopped without one.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seek {
    Member(usize),
    Clear,
    Short(usize),
}

/// A test cohort over `levels` and `funds` that hands each member to
/// `decide` in order; a member it returns `false` for is refused and stops
/// the walk.
#[cfg(test)]
pub(crate) struct Every<'l, L, F, D> {
    pub levels: &'l mut L,
    pub funds: &'l mut F,
    pub decide: D,
}

#[cfg(test)]
impl<L: Levels, F: Funds, D> Levels for Every<'_, L, F, D> {
    fn summary(&mut self, group: usize) -> u64 {
        self.levels.summary(group)
    }

    fn word(&mut self, word: usize) -> u64 {
        self.levels.word(word)
    }

    fn first_marked(&mut self, groups: Range<usize>) -> Option<(usize, u64)> {
        self.levels.first_marked(groups)
    }
}

#[cfg(test)]
impl<L: Levels, F: Funds, D> Funds for Every<'_, L, F, D> {
    fn affordable(&self) -> usize {
        self.funds.affordable()
    }

    fn spend(&mut self, probes: usize) {
        self.funds.spend(probes);
    }
}

#[cfg(test)]
impl<L: Levels, F: Funds, D: FnMut(usize) -> bool> Cohort for Every<'_, L, F, D> {
    fn member(&mut self, slot: usize, _: Option<usize>) -> bool {
        (self.decide)(slot)
    }
}

/// The first member of `levels` in `start..end`, funded by `funds`: a walk
/// that refuses the first member it meets.
#[cfg(test)]
pub(crate) fn seek(
    levels: &mut impl Levels,
    start: usize,
    end: usize,
    funds: &mut impl Funds,
) -> Seek {
    let mut first = Every {
        levels,
        funds,
        decide: |_| false,
    };
    match walk(&mut first, start, end) {
        Walked::Refused(slot) => Seek::Member(slot),
        Walked::Clear => Seek::Clear,
        Walked::Short(at) => Seek::Short(at),
    }
}

/// Funds that approve `left` more probes and count the probes made.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Counted {
    pub left: usize,
    pub probes: usize,
}

#[cfg(test)]
impl Counted {
    /// Funds that approve every probe.
    pub(crate) fn unbounded() -> Self {
        Self::new(usize::MAX)
    }

    pub(crate) fn new(left: usize) -> Self {
        Self { left, probes: 0 }
    }
}

#[cfg(test)]
impl Funds for Counted {
    fn affordable(&self) -> usize {
        self.left
    }

    fn spend(&mut self, probes: usize) {
        assert!(probes <= self.left, "a search read past its funds");
        self.left -= probes;
        self.probes += probes;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        Counted, Every, GROUP_SLOTS, Levels, Parked, Published, Retired, Seek, Walked, mark_parked,
        seek, walk,
    };

    /// Three summary groups and a partial fourth, so searches cross group
    /// boundaries and end inside a group.
    const SLOTS: usize = 3 * GROUP_SLOTS + 700;

    /// The member a search from `start` finds below `end`, and the probes
    /// it makes: one summary word read as the search enters each group,
    /// then each bitmap word the summary marks, until a member or `end`.
    fn expected(marked: &[usize], start: usize, end: usize) -> (Seek, usize) {
        let mut probes = 0;
        let mut at = start;
        while at < end {
            probes += 1;
            let group_end = (at / GROUP_SLOTS + 1) * GROUP_SLOTS;
            let words = (at / 64..group_end / 64)
                .filter(|word| marked.iter().any(|slot| slot / 64 == *word));
            for word in words {
                at = at.max(word * 64);
                if at >= end {
                    return (Seek::Clear, probes);
                }
                probes += 1;
                let next = marked
                    .iter()
                    .copied()
                    .filter(|&slot| slot / 64 == word && slot >= at)
                    .min();
                match next {
                    Some(slot) if slot < end => return (Seek::Member(slot), probes),
                    Some(_) => return (Seek::Clear, probes),
                    None => at = (word + 1) * 64,
                }
            }
            at = group_end;
        }
        (Seek::Clear, probes)
    }

    fn retired_levels(marked: &[usize]) -> (Vec<u64>, Vec<u64>) {
        retired_levels_of(SLOTS, marked)
    }

    fn retired_levels_of(slots: usize, marked: &[usize]) -> (Vec<u64>, Vec<u64>) {
        let mut bits = vec![0u64; slots.div_ceil(64)];
        let mut summary = vec![0u64; bits.len().div_ceil(64)];
        for &slot in marked {
            bits[slot / 64] |= 1 << (slot % 64);
            summary[slot / 64 / 64] |= 1 << (slot / 64 % 64);
        }
        (bits, summary)
    }

    /// Over sparse members at group, word and table edges, `seek` agrees
    /// with a slot-by-slot scan on the member it finds, and makes exactly
    /// the probes the positions call for, over every start and end pair
    /// drawn from the edges.
    #[test]
    fn seek_matches_a_slot_by_slot_scan_and_its_probe_count() {
        let marked = [
            0,
            63,
            64,
            GROUP_SLOTS - 1,
            GROUP_SLOTS + 100,
            3 * GROUP_SLOTS + 699,
        ];
        let (bits, summary) = retired_levels(&marked);
        let mut edges: Vec<usize> = marked
            .iter()
            .flat_map(|&slot| [slot.saturating_sub(1), slot, slot + 1])
            .chain([0, 65, GROUP_SLOTS, 2 * GROUP_SLOTS + 5, SLOTS])
            .filter(|&slot| slot <= SLOTS)
            .collect();
        edges.sort_unstable();
        edges.dedup();
        for &start in &edges {
            for &end in edges.iter().filter(|&&end| end > start) {
                let mut funds = Counted::unbounded();
                let found = seek(
                    &mut Retired {
                        bits: &bits,
                        summary: &summary,
                    },
                    start,
                    end,
                    &mut funds,
                );
                let probes = funds.probes;
                let scan = (start..end)
                    .find(|slot| marked.contains(slot))
                    .map_or(Seek::Clear, Seek::Member);
                assert_eq!(found, scan, "{start}..{end}");
                assert_eq!(
                    (found, probes),
                    expected(&marked, start, end),
                    "{start}..{end}"
                );
            }
        }
    }

    /// A walk that visits every member reports them in order, as a
    /// slot-by-slot scan does, and reads each summary word of the groups it
    /// enters and each marked bitmap word in its range once: members that
    /// share a word or a group cost no further read.
    #[test]
    fn a_walk_over_every_member_reads_each_word_once() {
        let marked = [
            3,
            4,
            63,
            64,
            200,
            GROUP_SLOTS - 1,
            GROUP_SLOTS,
            GROUP_SLOTS + 64 * 5 + 1,
            3 * GROUP_SLOTS + 699,
        ];
        let (bits, summary) = retired_levels(&marked);
        let ranges = [
            (0, SLOTS),
            (4, SLOTS),
            (5, GROUP_SLOTS + 1),
            (64, 3 * GROUP_SLOTS),
        ];
        for (start, end) in ranges {
            let mut levels = Retired {
                bits: &bits,
                summary: &summary,
            };
            let (mut funds, mut found) = (Counted::unbounded(), Vec::new());
            let walked = walk(
                &mut Every {
                    levels: &mut levels,
                    funds: &mut funds,
                    decide: |slot| {
                        found.push(slot);
                        true
                    },
                },
                start,
                end,
            );
            assert_eq!(walked, Walked::Clear);
            let scan: Vec<usize> = (start..end).filter(|slot| marked.contains(slot)).collect();
            assert_eq!(found, scan, "{start}..{end}");
            let groups = (end - 1) / GROUP_SLOTS - start / GROUP_SLOTS + 1;
            let words = (start / 64..=(end - 1) / 64)
                .filter(|word| marked.iter().any(|slot| slot / 64 == *word))
                .count();
            assert_eq!(funds.probes, groups + words, "{start}..{end}");
        }
    }

    /// A search funded short of the member stops before the unfunded probe
    /// with the position its funded probes reached, and a search resumed
    /// from there finds the member. The resumed search skips every summary
    /// word already read empty; it repeats only the summary read that led
    /// to the unfunded word read, since the position names a slot, not the
    /// level of the next read.
    #[test]
    fn a_short_search_resumes_where_its_funded_probes_reached() {
        let marked = [2 * GROUP_SLOTS + 77];
        let (bits, summary) = retired_levels(&marked);
        let (_, needed) = expected(&marked, 5, SLOTS);
        assert_eq!(needed, 4, "three summary probes and one word probe");
        for funded in 0..needed {
            let mut levels = Retired {
                bits: &bits,
                summary: &summary,
            };
            let mut short = Counted::new(funded);
            let Seek::Short(at) = seek(&mut levels, 5, SLOTS, &mut short) else {
                panic!("{funded} probes reached the member");
            };
            assert_eq!(short.probes, funded);
            let mut resumed_funds = Counted::unbounded();
            let resumed = seek(&mut levels, at, SLOTS, &mut resumed_funds);
            let rest = resumed_funds.probes;
            assert_eq!(resumed, Seek::Member(marked[0]));
            let repeated = usize::from(funded == needed - 1);
            assert_eq!(
                funded + rest,
                needed + repeated,
                "{funded} funded, resumed at {at}"
            );
        }
    }

    /// The parked view repairs a summary bit left beside a zero word, keeps
    /// one whose word holds a bit, and finds the same members the retired
    /// view does over the same marks.
    #[test]
    fn the_parked_view_repairs_stale_summary_bits_and_keeps_live_ones() {
        let words = SLOTS.div_ceil(64);
        let bits: Vec<_> = (0..words).map(|_| AtomicU64::new(0)).collect();
        let summary: Vec<_> = (0..words.div_ceil(64)).map(|_| AtomicU64::new(0)).collect();
        let member = GROUP_SLOTS + 130;
        mark_parked::<_, Published>(&bits, &summary, member);
        // A stale summary bit for word 1, as a clear of its only parked bit
        // leaves it.
        summary[0].fetch_or(1 << 1, Ordering::Relaxed);
        let mut levels = Parked::<_, Published>::new(&bits, &summary);
        assert_eq!(
            seek(&mut levels, 0, SLOTS, &mut Counted::unbounded()),
            Seek::Member(member)
        );
        assert_eq!(levels.repaired, 1);
        assert_eq!(summary[0].load(Ordering::Relaxed), 0);
        assert_eq!(summary[1].load(Ordering::Relaxed), 1 << (member / 64 % 64));
        // A live word's summary bit survives a later search.
        assert_eq!(levels.word(member / 64), 1 << (member % 64));
        assert_eq!(
            seek(&mut levels, 0, SLOTS, &mut Counted::unbounded()),
            Seek::Member(member)
        );
        assert_eq!(levels.repaired, 1);
    }

    /// Forty summary groups and a partial forty-first: a scan of empty
    /// summary words spans several full eight-word chunks and a remainder.
    const LARGE: usize = 40 * GROUP_SLOTS + 700;

    /// The parked set marking `marked`, as parks leave it.
    fn parked_levels_of(slots: usize, marked: &[usize]) -> (Vec<AtomicU64>, Vec<AtomicU64>) {
        let words = slots.div_ceil(64);
        let bits: Vec<_> = (0..words).map(|_| AtomicU64::new(0)).collect();
        let summary: Vec<_> = (0..words.div_ceil(64)).map(|_| AtomicU64::new(0)).collect();
        for &slot in marked {
            mark_parked::<_, Published>(&bits, &summary, slot);
        }
        (bits, summary)
    }

    /// Members in groups 1, 4, 8, 9, 19, 30 and 39, at offset 77, and the
    /// table's last slot. Over starts at every group boundary, a scan meets a
    /// marked word in each lane of a first eight-word chunk, in the first two
    /// lanes of a second chunk, and in the remainder.
    fn chunk_members() -> Vec<usize> {
        [1, 4, 8, 9, 19, 30, 39]
            .iter()
            .map(|group| group * GROUP_SLOTS + 77)
            .chain([LARGE - 1])
            .collect()
    }

    /// Over forty-one summary groups, a walk of either set finds the member
    /// a slot-by-slot scan finds and charges exactly the probes the positions
    /// call for, wherever the scan of empty summary words meets the marked
    /// word: within an eight-word chunk, at its edges, or in the remainder.
    #[test]
    fn the_summary_scan_charges_the_words_it_examines_in_either_set() {
        let marked = chunk_members();
        let (bits, summary) = retired_levels_of(LARGE, &marked);
        let (parked_bits, parked_summary) = parked_levels_of(LARGE, &marked);
        let mut edges: Vec<usize> = (0..=41)
            .map(|group| group * GROUP_SLOTS)
            .chain(marked.iter().flat_map(|&slot| [slot - 1, slot, slot + 1]))
            .chain([5, LARGE])
            .filter(|&slot| slot <= LARGE)
            .collect();
        edges.sort_unstable();
        edges.dedup();
        for &start in &edges {
            for &end in edges.iter().filter(|&&end| end > start) {
                let oracle = expected(&marked, start, end);
                let mut funds = Counted::unbounded();
                let mut retired = Retired {
                    bits: &bits,
                    summary: &summary,
                };
                let found = seek(&mut retired, start, end, &mut funds);
                assert_eq!((found, funds.probes), oracle, "retired {start}..{end}");
                let mut funds = Counted::unbounded();
                let mut parked = Parked::<_, Published>::new(&parked_bits, &parked_summary);
                let found = seek(&mut parked, start, end, &mut funds);
                assert_eq!((found, funds.probes), oracle, "parked {start}..{end}");
            }
        }
    }

    /// A walk over every member of either large set reports them in order
    /// and reads each summary word of the groups it enters and each marked
    /// bitmap word once.
    #[test]
    fn a_walk_over_a_large_set_reads_each_word_once() {
        let marked = chunk_members();
        let (bits, summary) = retired_levels_of(LARGE, &marked);
        let (parked_bits, parked_summary) = parked_levels_of(LARGE, &marked);
        let groups = LARGE.div_ceil(GROUP_SLOTS);
        for parked in [false, true] {
            let (mut funds, mut found) = (Counted::unbounded(), Vec::new());
            let decide = |slot| {
                found.push(slot);
                true
            };
            let walked = if parked {
                let mut levels = Parked::<_, Published>::new(&parked_bits, &parked_summary);
                walk(
                    &mut Every {
                        levels: &mut levels,
                        funds: &mut funds,
                        decide,
                    },
                    0,
                    LARGE,
                )
            } else {
                let mut levels = Retired {
                    bits: &bits,
                    summary: &summary,
                };
                walk(
                    &mut Every {
                        levels: &mut levels,
                        funds: &mut funds,
                        decide,
                    },
                    0,
                    LARGE,
                )
            };
            assert_eq!(walked, Walked::Clear);
            assert_eq!(found, marked, "parked {parked}");
            assert_eq!(funds.probes, groups + marked.len(), "parked {parked}");
        }
    }

    /// Funds short of the member stop the walk where the funded probes
    /// reached, every funded word charged: at the start with none, on the
    /// first unfunded group while the scan of empty summary words runs out,
    /// and on the member's bitmap word when only its read is unfunded. A walk
    /// resumed there reaches the member, repeating only the summary read that
    /// led to an unfunded bitmap read.
    #[test]
    fn funds_that_run_out_inside_the_summary_scan_stop_on_the_first_unfunded_group() {
        let member = 12 * GROUP_SLOTS + 77;
        let (bits, summary) = retired_levels_of(LARGE, &[member]);
        let (_, needed) = expected(&[member], 5, LARGE);
        assert_eq!(needed, 14, "thirteen summary probes and one word probe");
        for funded in 0..needed {
            let mut levels = Retired {
                bits: &bits,
                summary: &summary,
            };
            let mut short = Counted::new(funded);
            let Seek::Short(at) = seek(&mut levels, 5, LARGE, &mut short) else {
                panic!("{funded} probes reached the member");
            };
            assert_eq!(short.probes, funded);
            let stop = match funded {
                0 => 5,
                13 => member / 64 * 64,
                _ => funded * GROUP_SLOTS,
            };
            assert_eq!(at, stop, "{funded} funded");
            let mut rest = Counted::unbounded();
            assert_eq!(
                seek(&mut levels, at, LARGE, &mut rest),
                Seek::Member(member)
            );
            let repeated = usize::from(funded == needed - 1);
            assert_eq!(funded + rest.probes, needed + repeated, "{funded} funded");
        }
    }
}
