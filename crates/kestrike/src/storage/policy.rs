//! The eviction policy domain: one per volume, holding exactly its resident
//! slots, from the pool-gate hold in which `bind` sets the slot `Resident`
//! until the first pool-gate hold that observes its retirement or returns its
//! extent.
//!
//! A domain is a doubly linked list of slots, newest member at the head,
//! plus a hand that the SIEVE selection moves from the tail toward the head
//! (Zhang et al., *SIEVE is Simpler than LRU*, NSDI 2024, Algorithm 1).
//! Each slot's links and state take 8 bytes and three word bits:
//!
//! - `prev`, one step toward the head, is the `u32` at bytes 28 to 31 of the
//!   slot's record (see the `slot` module);
//! - `next`, one step toward the tail, is the slot's entry in the volume's
//!   per-slot `u32` table (see the `tables` module);
//! - [`LINKED`], [`DETACHED`] and [`EVICTED`] are bits 39 to 41 of the
//!   slot's lifetime word (see the `word` module).
//!
//! [`POLICY_NONE`] ends both directions. The links, the bits and the domain
//! record are gate-owned: only a holder of the pool gate writes them or acts
//! on them, or a range-split restore's lane worker the holder runs, which
//! touches only its own lane's links and bits and joins before the holder
//! folds the lanes' sublists or releases the gate; the gate and the join
//! order every access, so the list needs no ordering of its own. `prev` and the bits are atomics because they
//! share the record and the word that readers without the gate load; those
//! readers ignore both, except the eviction step, which reads one `prev`
//! link after its holds end only to form a prefetch address. Every bit write
//! is one read-modify-write that changes only the bits it writes: a
//! `fetch_or` ([`PolicySlot::set_bits`]) sets bits, a `fetch_and`
//! ([`PolicySlot::clear_bits`]) clears them, and a `fetch_xor`
//! ([`PolicySlot::move_bits`]) replaces [`LINKED`] with [`DETACHED`] in
//! `detach`, or with [`DETACHED`] and [`EVICTED`] in `mark_evicted`, so a
//! slot leaves the list and takes its new bits in one write. So a retain, a
//! release or a park racing it on the same word keeps its own bits. The
//! extent's return clears the bits in the `fetch_and` that frees the word
//! and passes the word it replaced to [`Queue::clear`].
//!
//! `bind` and `abandon` fold their policy write into the read-modify-write
//! their hold already makes. [`Queue::link_with`] hands [`LINKED`] to
//! `bind`'s `move_state`. [`Queue::detach_with`] and
//! [`Queue::mark_evicted_with`] pass the XOR mask of the departure or the
//! mark to `abandon`'s `retire` closure, which must apply the mask in one
//! read-modify-write before the list changes.
//!
//! The queue fails closed. Every read of the bits fails closed on a
//! reserved bit: the queue's own loads pass the word through
//! `word::checked`, and `clear` receives the word the return has already
//! asserted well formed. `link_with` asserts that the slot's bits are zero and
//! both links are the end marker, `detach` and `mark_evicted` that a linked
//! slot carries exactly [`LINKED`], and `mark_evicted` that [`EVICTED`] is
//! clear;
//! `release_evicted` clears [`EVICTED`] only when it is set. A failed check
//! panics under the gate and poisons it, and a poisoned gate admits no
//! later holder.
//!
//! Membership rule. A slot links at the head in `bind`'s hold, inside that
//! call's one `Update` debit; an unpublished resident is a member too. A
//! slot leaves at the first hold that finds a retirement describing its
//! current incarnation while the slot is [`LINKED`]: `abandon` with the gate,
//! or service, the eviction hand's walk or the expiry sweep sighting a
//! parked retirement on a resident slot. That hold
//! unlinks it, sets [`DETACHED`] and counts it in the domain's `detached`.
//! `LINKED` is the single authority: a later observer of the same retirement
//! finds it clear and does nothing, so each incarnation unlinks at most once
//! and `detached` equals the number of `DETACHED` slots. The extent's return
//! unlinks a still-linked slot, uncounts a detached one and clears its bits
//! in the read-modify-write that frees the word, so a `Free` slot is never
//! linked and carries no bits. A stale park names an earlier incarnation,
//! so it never unlinks the current occupant. A quarantined slot never
//! reaches `bind` and never links.
//!
//! Hand repair: unlinking the hand's slot moves the hand to its head-side
//! neighbour, or to none when the slot was the head, so the hand always
//! names a member or none.
//!
//! SIEVE's visited bit lives in each slot's lifetime word (see the `word`
//! module), beside the incarnation it describes: the registered retain sets
//! it in the exchange that takes its right, the hand clears it under the
//! pool gate with a `fetch_and`, and the extent's return clears it with the
//! other flags. It holds no gate-owned state and is advisory input to victim
//! selection only.
//!
//! Why a reused slot never inherits a stale hit: a retain sets the bit only
//! in an exchange that finds the word carrying the incarnation it validated
//! and a positive count, and the return's read-modify-write, which clears
//! the bit, follows every such exchange in the word's modification order:
//! service returns an extent only after it observes the count at zero, and
//! no retain lands on zero. The claim then installs `i + 1` from the cleared
//! word, so a reader of incarnation `i + 1` sees the bit clear or set by a
//! retain on `i + 1`.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::credit::BitWord;
use super::slot::Record;
use super::word::{self, DETACHED, EVICTED, LINKED, POLICY};

/// Terminator of every policy list and the hand's "no member" value.
/// Validation refuses a volume with `O >= 2^31 - 1`, so no slot index
/// reaches it.
pub(crate) const POLICY_NONE: u32 = u32::MAX;

/// One slot's policy fields as the queue reaches them: the head-side link
/// and the lifetime word that holds the policy bits. The volume's
/// [`Record`] in production; a Loom model supplies its own, with the word
/// over a loom atomic. Only the pool gate's holder, or a lane worker it joins
/// before it releases the gate, calls these methods for a slot, and the gate
/// and the join order every access, so none needs an ordering of its own.
pub(crate) trait PolicySlot {
    /// The lifetime word.
    fn word(&self) -> u64;
    /// Sets `bits` of the lifetime word with one `fetch_or`, preserving bits
    /// outside `bits`.
    fn set_bits(&self, bits: u64);
    /// Clears `bits` of the lifetime word with one `fetch_and`, which
    /// changes no other bit.
    fn clear_bits(&self, bits: u64);
    /// Replaces policy bits `from` with `to` in one `fetch_xor` of
    /// `from ^ to`. The caller has checked under the gate that the policy
    /// bits equal `from`.
    fn move_bits(&self, from: u64, to: u64);
    /// The neighbour one step toward the head, or [`POLICY_NONE`].
    fn prev(&self) -> u32;
    fn set_prev(&self, prev: u32);
}

/// The [`PolicySlot`] read of lifetime word `word`. The gate orders every
/// gate holder's reads, and each bit write below is a read-modify-write,
/// which keeps every bit outside its operand and extends every release
/// sequence on the word, so `Relaxed` suffices. A record runs these bodies
/// over its std word and a model over its own.
#[inline(always)]
pub(crate) fn policy_word<W: BitWord>(word: &W) -> u64 {
    word.load(Ordering::Relaxed)
}

/// [`PolicySlot::set_bits`] on `word`.
#[inline(always)]
pub(crate) fn set_policy_bits<W: BitWord>(word: &W, bits: u64) {
    word.fetch_or(bits, Ordering::Relaxed);
}

/// [`PolicySlot::clear_bits`] on `word`.
#[inline(always)]
pub(crate) fn clear_policy_bits<W: BitWord>(word: &W, bits: u64) {
    word.fetch_and(!bits, Ordering::Relaxed);
}

/// [`PolicySlot::move_bits`] on `word`.
#[inline(always)]
pub(crate) fn move_policy_bits<W: BitWord>(word: &W, from: u64, to: u64) {
    word.fetch_xor(from ^ to, Ordering::Relaxed);
}

/// The volume domain's list ends, hand and exact counts. Every slot count is
/// bounded by `O` and the unit count by the volume's units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Domain {
    /// Newest member, or [`POLICY_NONE`].
    pub head: u32,
    /// Oldest member, or [`POLICY_NONE`].
    pub tail: u32,
    /// The member the next selection examines, or [`POLICY_NONE`] to start
    /// from the tail.
    pub hand: u32,
    /// Linked members.
    pub members: u32,
    /// Slots with [`DETACHED`] set: retired members whose extent has not
    /// returned. Never usable capacity.
    pub detached: u32,
    /// Slots with [`EVICTED`] set; `check_domain` asserts that `in_flight`
    /// equals the number of slots with [`EVICTED`] set.
    pub in_flight: u32,
    /// Units of the extents of the slots with [`EVICTED`] set: each mark
    /// adds its extents' length, each extent service returns ahead of the
    /// final return subtracts its own, and the bit's clearing subtracts the
    /// rest.
    pub in_flight_units: u64,
    /// Units of every retired slot's extents not yet returned, the retired
    /// charge the allowance `T` bounds: each retirement adds the slot's held
    /// units and each return of a retired extent subtracts its own. It
    /// counts an extent from retirement to return, whatever holds it. An
    /// abandonment that parks, finding the gate busy, and that no retirement
    /// absorbs returns from its owned phase without retiring: its units stay
    /// charged to that phase, outside this count, and its slot counts in the
    /// pending marks.
    pub retired_units: u64,
}

impl Domain {
    pub(crate) const EMPTY: Self = Self {
        head: POLICY_NONE,
        tail: POLICY_NONE,
        hand: POLICY_NONE,
        members: 0,
        detached: 0,
        in_flight: 0,
        in_flight_units: 0,
        retired_units: 0,
    };
}

/// The volume's one pending removal mark: the slot and incarnation of a victim
/// whose removal committed and whose slot is not yet marked [`EVICTED`].
/// Written by the removing call, eviction or expiry, without the pool gate,
/// read and cleared by the next hold that call or the next one takes, which
/// applies it before any selection there. At most one eviction or expiry
/// step runs at a time, ordered by happens-before, so
/// the words have one writer. The slot word is stored with release after
/// the incarnation and taken with acquire, so a reader that takes a slot
/// reads the incarnation written with it.
#[derive(Debug)]
pub(crate) struct PendingMark {
    /// The victim's slot, or [`MARK_NONE`].
    pub slot: AtomicU64,
    pub incarnation: AtomicU32,
}

/// The pending mark's "no mark" slot value.
pub(crate) const MARK_NONE: u64 = u64::MAX;

impl PendingMark {
    pub(crate) fn empty() -> Self {
        Self {
            slot: AtomicU64::new(MARK_NONE),
            incarnation: AtomicU32::new(0),
        }
    }
}

/// One domain's list over the volume's slots and `next` table, borrowed
/// from a gate hold.
pub(crate) struct Queue<'a, S: PolicySlot = Record> {
    slots: &'a [S],
    next: &'a mut [u32],
    domain: &'a mut Domain,
}

impl<'a, S: PolicySlot> Queue<'a, S> {
    pub(crate) fn new(slots: &'a [S], next: &'a mut [u32], domain: &'a mut Domain) -> Self {
        Self {
            slots,
            next,
            domain,
        }
    }

    /// `slot`'s policy bits, from a load of its word that panics on a
    /// reserved bit, which poisons the gate the caller holds.
    #[inline(always)]
    fn bits(&self, slot: usize) -> u64 {
        word::checked(self.slots[slot].word()) & POLICY
    }

    #[cfg(test)]
    pub(crate) fn link(&mut self, slot: usize) {
        let slots = self.slots;
        self.link_with(slot, |linked| slots[slot].set_bits(linked));
    }

    /// Links `slot`, which `bind` just made resident, at the head: a
    /// resident slot links once per incarnation. A range-split restore
    /// links its lanes' sublists by the same rule in `Lane::install` and
    /// `Tables::fold_lanes`.
    /// `write` must set the [`LINKED`] bit it receives in `slot`'s word.
    ///
    /// `slot < O < u32::MAX`, so the narrowing is exact.
    ///
    /// # Panics
    ///
    /// - If `slot`'s word has a reserved bit set.
    /// - If `slot` carries a policy bit, a `prev` link or a `next` link.
    #[inline(always)]
    pub(crate) fn link_with<T>(&mut self, slot: usize, write: impl FnOnce(u64) -> T) -> T {
        assert!(
            self.bits(slot) == 0
                && self.slots[slot].prev() == POLICY_NONE
                && self.next[slot] == POLICY_NONE,
            "a resident slot linked twice or linked with stale state"
        );
        let head = self.domain.head;
        if head == POLICY_NONE {
            self.domain.tail = slot as u32;
        } else {
            self.slots[head as usize].set_prev(slot as u32);
        }
        self.next[slot] = head;
        self.domain.head = slot as u32;
        self.domain.members += 1;
        write(LINKED)
    }

    /// The observer rule: a hold that found a retirement describing the
    /// current incarnation of `slot` unlinks it if it is still linked, marks
    /// it detached and counts it. Returns whether this call detached it; a
    /// later observer of the same retirement does nothing.
    ///
    /// # Panics
    ///
    /// - If `slot`'s word has a reserved bit set.
    /// - If `slot` is [`LINKED`] and carries a second policy bit.
    #[inline(always)]
    pub(crate) fn detach(&mut self, slot: usize) -> bool {
        let slots = self.slots;
        self.detach_with(slot, |mask| {
            let member = mask != 0;
            if member {
                slots[slot].move_bits(LINKED, DETACHED);
            }
            member
        })
    }

    /// [`detach`](Self::detach) with `slot`'s word written by `write`: it
    /// receives the XOR mask of the departure, zero when `slot` is not
    /// linked, and must apply it in one read-modify-write. It runs after the
    /// checks and before the list changes.
    ///
    /// # Panics
    ///
    /// As for [`detach`](Self::detach).
    #[inline(always)]
    pub(crate) fn detach_with<T>(&mut self, slot: usize, write: impl FnOnce(u64) -> T) -> T {
        let member = member(self.bits(slot));
        let written = write(if member { LINKED ^ DETACHED } else { 0 });
        if member {
            self.unlink(slot);
            self.domain.detached += 1;
        }
        written
    }

    /// The extent of `slot`, `units` long, returned, and `previous` is the
    /// word the return's read-modify-write replaced as it cleared the
    /// policy bits: unlinks a still-linked slot and uncounts a detached or
    /// evicted one, so the next incarnation starts clean.
    #[inline(always)]
    pub(crate) fn clear(&mut self, slot: usize, units: u32, previous: u64) {
        let bits = previous & POLICY;
        if bits & LINKED != 0 {
            self.unlink(slot);
        }
        if bits & DETACHED != 0 {
            self.domain.detached -= 1;
        }
        if bits & EVICTED != 0 {
            self.domain.in_flight -= 1;
            self.domain.in_flight_units -= u64::from(units);
        }
    }

    /// Service returned `units` of a slot's extents ahead of its final
    /// return, `current` being the slot's word under the gate: an evicted
    /// slot's in-flight units shrink by them, and its in-flight count stays
    /// until the final return clears it.
    #[inline(always)]
    pub(crate) fn returned_part(&mut self, units: u32, current: u64) {
        if current & EVICTED != 0 {
            self.domain.in_flight_units -= u64::from(units);
        }
    }

    /// Service found evicted `slot`'s anchor released and its journal block
    /// durable or not needed while rights remain: its extent, `units` long,
    /// is held by those rights alone now, no longer in flight. Clears
    /// [`EVICTED`] once.
    ///
    /// # Panics
    ///
    /// If `slot`'s word has a reserved bit set.
    pub(crate) fn release_evicted(&mut self, slot: usize, units: u32) {
        if self.bits(slot) & EVICTED != 0 {
            self.slots[slot].clear_bits(EVICTED);
            self.domain.in_flight -= 1;
            self.domain.in_flight_units -= u64::from(units);
        }
    }

    /// Removes linked `slot` from the list and resets its links, repairing
    /// the hand first when it names `slot`. The caller changes the bits.
    #[inline(always)]
    fn unlink(&mut self, slot: usize) {
        let prev = self.slots[slot].prev();
        let next = self.next[slot];
        if self.domain.hand == slot as u32 {
            self.domain.hand = prev;
        }
        if prev == POLICY_NONE {
            self.domain.head = next;
        } else {
            self.next[prev as usize] = next;
        }
        if next == POLICY_NONE {
            self.domain.tail = prev;
        } else {
            self.slots[next as usize].set_prev(prev);
        }
        self.slots[slot].set_prev(POLICY_NONE);
        self.next[slot] = POLICY_NONE;
        self.domain.members -= 1;
    }

    /// Members from head to tail, for oracles and structural checks.
    #[cfg(test)]
    pub(crate) fn members(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut at = self.domain.head;
        while at != POLICY_NONE {
            out.push(at as usize);
            at = self.next[at as usize];
        }
        out
    }

    /// Every slot's links and policy bits, for oracles and structural
    /// checks.
    #[cfg(test)]
    pub(crate) fn nodes(&self) -> Vec<Node> {
        (0..self.slots.len())
            .map(|slot| Node {
                prev: self.slots[slot].prev(),
                next: self.next[slot],
                state: self.bits(slot),
            })
            .collect()
    }
}

#[inline(always)]
fn member(bits: u64) -> bool {
    if bits & LINKED == 0 {
        return false;
    }
    assert_eq!(bits, LINKED, "a member with a second policy bit");
    true
}

/// One slot's links and policy bits as a test reads them.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Node {
    pub prev: u32,
    pub next: u32,
    pub state: u64,
}

#[cfg(test)]
impl Node {
    /// A slot on no list with no bits: every `Free` slot.
    pub(crate) const CLEAR: Self = Self {
        prev: POLICY_NONE,
        next: POLICY_NONE,
        state: 0,
    };
}

/// Selection's steps over the list and the eviction mark.
impl<S: PolicySlot> Queue<'_, S> {
    /// Applies an eviction mark to `slot`, whose current incarnation the
    /// caller matched against the victim's under the gate: a still-linked
    /// slot leaves the list as the observer rule has it, and the slot is
    /// marked [`EVICTED`] and counted in flight with its extent's `units`.
    /// Returns whether this call detached it.
    ///
    /// # Panics
    ///
    /// - If `slot`'s word has a reserved bit set.
    /// - If `slot` is already marked [`EVICTED`].
    /// - If `slot` is [`LINKED`] and carries a second policy bit.
    #[inline(always)]
    pub(crate) fn mark_evicted(&mut self, slot: usize, units: u32) -> bool {
        let slots = self.slots;
        self.mark_evicted_with(slot, units, |mask| {
            let member = mask & LINKED != 0;
            if member {
                slots[slot].move_bits(LINKED, DETACHED | EVICTED);
            } else {
                slots[slot].set_bits(EVICTED);
            }
            member
        })
    }

    /// [`mark_evicted`](Self::mark_evicted) with `slot`'s word written by
    /// `write`: it receives the XOR mask of the mark and must apply it in
    /// one read-modify-write. It runs after the checks and before the list
    /// changes.
    ///
    /// # Panics
    ///
    /// As for [`mark_evicted`](Self::mark_evicted).
    #[inline(always)]
    pub(crate) fn mark_evicted_with<T>(
        &mut self,
        slot: usize,
        units: u32,
        write: impl FnOnce(u64) -> T,
    ) -> T {
        let bits = self.bits(slot);
        assert_eq!(bits & EVICTED, 0, "evicted twice");
        let member = member(bits);
        let written = write(if member {
            LINKED ^ DETACHED ^ EVICTED
        } else {
            EVICTED
        });
        if member {
            self.unlink(slot);
            self.domain.detached += 1;
        }
        self.domain.in_flight += 1;
        self.domain.in_flight_units += u64::from(units);
        written
    }

    /// The member selection examines first: the hand, or the tail when the
    /// hand names none.
    pub(crate) fn start(&self) -> u32 {
        if self.domain.hand == POLICY_NONE {
            self.domain.tail
        } else {
            self.domain.hand
        }
    }

    pub(crate) fn set_hand(&mut self, hand: u32) {
        self.domain.hand = hand;
    }

    /// The oldest member, or [`POLICY_NONE`].
    #[inline(always)]
    pub(crate) fn tail(&self) -> u32 {
        self.domain.tail
    }

    pub(crate) fn members_len(&self) -> usize {
        self.domain.members as usize
    }
}

/// Checks every structural invariant of one domain over `nodes`, one per
/// slot as [`Queue::nodes`] reads them: the
/// list is doubly linked and consistent with its ends and count, every
/// member has only `LINKED`, the hand names a member or none, and
/// `detached` and `in_flight` equal the `DETACHED` and `EVICTED` counts
/// among the slots `in_domain` names.
#[cfg(test)]
pub(crate) fn check_domain(nodes: &[Node], domain: &Domain, in_domain: impl Fn(usize) -> bool) {
    let mut seen = 0u32;
    let mut prev = POLICY_NONE;
    let mut at = domain.head;
    let mut hand_found = domain.hand == POLICY_NONE;
    while at != POLICY_NONE {
        let node = nodes[at as usize];
        assert_eq!(node.prev, prev, "back link of {at}");
        assert_eq!(node.state, LINKED, "member {at} state");
        hand_found |= domain.hand == at;
        seen += 1;
        assert!(seen <= domain.members, "list longer than its count");
        prev = at;
        at = node.next;
    }
    assert_eq!(domain.tail, prev, "tail");
    assert_eq!(seen, domain.members, "count");
    assert!(hand_found, "hand {} names no member", domain.hand);
    let detached = nodes
        .iter()
        .enumerate()
        .filter(|&(slot, node)| in_domain(slot) && node.state & DETACHED != 0)
        .count();
    assert_eq!(domain.detached as usize, detached, "detached count");
    let evicted = nodes
        .iter()
        .enumerate()
        .filter(|&(slot, node)| in_domain(slot) && node.state & EVICTED != 0)
        .count();
    assert_eq!(domain.in_flight as usize, evicted, "in-flight count");
}

/// Checks that `in_flight_units` equals the extent lengths, from `units_of`,
/// of the slots `in_domain` names that have [`EVICTED`] set; every mark,
/// extent return, clear and return passes the units it moves, and this sum
/// is where a mismatch among them shows.
#[cfg(test)]
pub(crate) fn check_in_flight_units(
    nodes: &[Node],
    domain: &Domain,
    in_domain: impl Fn(usize) -> bool,
    mut units_of: impl FnMut(usize) -> u64,
) {
    let units: u64 = nodes
        .iter()
        .enumerate()
        .filter(|&(slot, node)| in_domain(slot) && node.state & EVICTED != 0)
        .map(|(slot, _)| units_of(slot))
        .sum();
    assert_eq!(domain.in_flight_units, units, "in-flight units");
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::super::slot::Record;
    use super::super::word::{DETACHED, EVICTED, LINKED, POLICY, REF, VISITED};
    use super::{Domain, Node, POLICY_NONE, PolicySlot, Queue, check_domain};

    fn fresh(slots: usize) -> (Vec<Record>, Vec<u32>, Domain) {
        let records = (0..slots).map(|_| Record::free()).collect();
        (records, vec![POLICY_NONE; slots], Domain::EMPTY)
    }

    #[test]
    fn link_pushes_at_the_head_and_unlink_repairs_every_neighbour() {
        let (records, mut next, mut domain) = fresh(4);
        let mut queue = Queue::new(&records, &mut next, &mut domain);
        for slot in 0..4 {
            queue.link(slot);
        }
        assert_eq!(queue.members(), [3, 2, 1, 0]);
        // Middle, head, then tail.
        assert!(queue.detach(2));
        assert_eq!(queue.members(), [3, 1, 0]);
        assert!(queue.detach(3));
        assert_eq!(queue.members(), [1, 0]);
        assert!(queue.detach(0));
        assert_eq!(queue.members(), [1]);
        check_domain(&queue.nodes(), &domain, |_| true);
        assert_eq!((domain.head, domain.tail, domain.members), (1, 1, 1));
        assert_eq!(domain.detached, 3);
    }

    #[test]
    fn detach_is_counted_once_and_clear_uncounts_it() {
        let (records, mut next, mut domain) = fresh(2);
        let mut queue = Queue::new(&records, &mut next, &mut domain);
        queue.link(0);
        queue.link(1);
        assert!(queue.detach(0));
        assert!(!queue.detach(0), "a second observer must not detach again");
        for (slot, (record, bits)) in records.iter().zip([DETACHED, LINKED]).enumerate() {
            let previous = record.ident.fetch_and(0, Ordering::Relaxed);
            assert_eq!(previous & POLICY, bits, "slot {slot}'s policy bits");
            queue.clear(slot, 1, previous);
        }
        let nodes = queue.nodes();
        check_domain(&nodes, &domain, |_| true);
        assert_eq!(domain, Domain::EMPTY);
        assert!(nodes.iter().all(|node| *node == Node::CLEAR));
    }

    /// Unlinking the hand's slot moves the hand one step toward the head, or
    /// to none from the head, at both exits: detach and clear.
    #[test]
    fn unlinking_the_hands_slot_moves_the_hand_head_side() {
        for exit_by_clear in [false, true] {
            let (records, mut next, mut domain) = fresh(3);
            let mut queue = Queue::new(&records, &mut next, &mut domain);
            for slot in 0..3 {
                queue.link(slot);
            }
            // Head to tail: 2, 1, 0.
            let exit = |queue: &mut Queue<'_>, slot: usize| {
                if exit_by_clear {
                    let previous = records[slot].ident.fetch_and(0, Ordering::Relaxed);
                    queue.clear(slot, 1, previous);
                } else {
                    assert!(queue.detach(slot));
                }
            };
            queue.domain.hand = 0;
            exit(&mut queue, 0);
            assert_eq!(queue.domain.hand, 1);
            exit(&mut queue, 1);
            assert_eq!(queue.domain.hand, 2);
            exit(&mut queue, 2);
            assert_eq!(queue.domain.hand, POLICY_NONE);
            check_domain(&queue.nodes(), &domain, |_| true);
        }
    }

    #[test]
    fn a_mark_counts_a_linked_or_a_detached_slot_in_flight_once() {
        let (records, mut next, mut domain) = fresh(2);
        let other = 1 | REF | VISITED;
        for record in &records {
            record.ident.store(other, Ordering::Relaxed);
        }
        let mut queue = Queue::new(&records, &mut next, &mut domain);
        queue.link(0);
        queue.link(1);
        assert!(queue.detach(1));
        assert!(queue.mark_evicted(0, 3), "the mark detaches a linked slot");
        assert!(!queue.mark_evicted(1, 5), "the mark detaches a slot once");
        for record in &records {
            assert_eq!(record.word(), other | DETACHED | EVICTED);
        }
        check_domain(&queue.nodes(), &*queue.domain, |_| true);
        assert_eq!(queue.domain.members, 0);
        assert_eq!(queue.domain.detached, 2);
        assert_eq!(
            (queue.domain.in_flight, queue.domain.in_flight_units),
            (2, 8)
        );
        queue.release_evicted(0, 3);
        queue.release_evicted(1, 5);
        for record in &records {
            assert_eq!(record.word(), other | DETACHED);
        }
        assert_eq!((domain.in_flight, domain.in_flight_units), (0, 0));
    }

    /// A policy read of a word with a reserved bit set panics, so a gate
    /// holder never acts on a corrupt word.
    #[test]
    #[should_panic(expected = "a slot word with a reserved bit set")]
    fn detach_panics_on_a_word_with_a_reserved_bit() {
        let (records, mut next, mut domain) = fresh(1);
        let mut queue = Queue::new(&records, &mut next, &mut domain);
        queue.link(0);
        records[0].ident.fetch_or(1 << 43, Ordering::Relaxed);
        queue.detach(0);
    }
}
