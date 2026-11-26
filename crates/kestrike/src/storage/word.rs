//! The per-slot lifetime word: the state every thread reads without the
//! pool gate, packed into one `AtomicU64` so a registered reader validates
//! and retains with one load and one compare-exchange.
//!
//! Layout, pinned below and by the layout test: the slot's incarnation in
//! bits 0 to 31; [`ABANDONED`], [`RETIRED`] and [`ANCHORED`] in bits 32 to
//! 34; [`VISITED`] in bit 35; the [`SlotState`] in bits 36 to 38
//! ([`STATE`]); the eviction policy's [`LINKED`], [`DETACHED`] and
//! [`EVICTED`] in bits 39 to 41 ([`POLICY`]); the recovered-origin
//! [`MARKER`] in bit 42; bits 43 to 45 zero ([`RESERVED`]); and the
//! reference count, external read rights plus the anchor, in bits 46 to 63.
//!
//! The restored install is the one writer that sets [`MARKER`], on a slot it
//! installs from a `Free` word, and the extent's return clears it.
//!
//! Only the pool gate's holder, or a range-split restore's lane worker it
//! starts and joins within its hold, reads or writes the state and policy
//! bits, each write a read-modify-write; the gate's acquire, the worker's
//! start and its join before the fold and the release order those accesses,
//! and the lanes' slot ranges are disjoint. Readers without the gate ignore
//! them, and every other writer's read-modify-write carries them unchanged. A retain's compare-exchange therefore fails and
//! retries when a gate holder moved the state or a policy bit between its
//! load and its exchange, like any other write it races.
//!
//! A word with a reserved bit set is malformed and fails closed wherever it
//! is read: a reader without the gate refuses it, a park, a retain and an
//! install leave it unchanged, a gate holder that acts on it panics and
//! poisons the gate, and drain and finalization never count it drained. A
//! state encoding past `Quarantined` is malformed for gate holders, which
//! panic on it the same way.
//!
//! Every write is a read-modify-write: the claim's compare-exchange from
//! the `Free` value, made once the slot's extent is reserved; the restored
//! install's `Release` compare-exchange from the `Free` value, which sets
//! the restored incarnation, `Resident`, [`LINKED`], [`MARKER`] and one
//! counted anchor; the
//! publication's `Release` compare-exchange in [`install`], which also
//! installs a fill's write right; the retain's compare-exchange, which a
//! lookup and a volume read make; the `Release` `fetch_sub` of a dropped
//! lease, a refunded reservation, a refused fill publication and a write or
//! read operation's right; the park's
//! compare-exchange; the gate-held retirement's `AcqRel` `try_update` in
//! `abandon`, which also moves the state to `Retired`; the anchor release's
//! compare-exchange; the gate holder's state `fetch_xor` and `fetch_or`
//! and the policy's bit writes; and the `fetch_and` of the
//! return, which also moves the state to `Free` and clears the policy bits
//! and the marker,
//! and of the SIEVE hand. So each writer changes only its own bits, and
//! every release decrement heads a release sequence that every later write
//! of the word extends: a reader whose acquire load reads any later value
//! synchronizes with every such decrement.
//!
//! A flag in the word always describes the incarnation beside it: a park
//! sets its bits only while the low half equals the incarnation it was
//! issued for, and the return clears every flag and policy bit before the
//! claim installs the next incarnation. The claim advances the incarnation with checked
//! arithmetic and quarantines a slot whose counter is exhausted, so a
//! slot's incarnation names at most one object.

use std::sync::atomic::{AtomicU64, Ordering};

/// Mask of the incarnation, the word's low half.
pub(crate) const INCARNATION: u64 = u32::MAX as u64;
/// The owner was dropped or retired and the slot awaits service.
pub(crate) const ABANDONED: u64 = 1 << 32;
/// The abandonment reached the ledger: the slot is `Retired` and only the
/// deferred return remains.
pub(crate) const RETIRED: u64 = 1 << 33;
/// The retired object's anchor is still counted and waits for grace
/// certification of the slot's retirement era. Never set without
/// [`ABANDONED`]: both retirement paths set the two in one write.
pub(crate) const ANCHORED: u64 = 1 << 34;
/// SIEVE's visited bit: set by a retain, cleared by the hand under the pool
/// gate and by the extent's return.
pub(crate) const VISITED: u64 = 1 << 35;
/// Position of the slot state.
pub(crate) const STATE_SHIFT: u32 = 36;
/// The slot state's three bits.
pub(crate) const STATE: u64 = 0b111 << STATE_SHIFT;
/// The three lifetime flags.
pub(crate) const FLAGS: u64 = ABANDONED | RETIRED | ANCHORED;
/// Policy bit: the slot is on its domain's list.
pub(crate) const LINKED: u64 = 1 << 39;
/// Policy bit: the slot left its list because its retirement was observed,
/// and its extent has not returned; counted in the domain's `detached`.
pub(crate) const DETACHED: u64 = 1 << 40;
/// Policy bit: eviction committed this incarnation's removal and its extent
/// is in flight: neither returned nor yet held by rights alone, past grace
/// and past its journal block; counted in the domain's `in_flight` and its
/// units in `in_flight_units`. Cleared once, by the extent's return or by
/// service finding the anchor released and the journal block durable while
/// rights remain.
pub(crate) const EVICTED: u64 = 1 << 41;
/// The three policy bits, zero on a slot that is not a member and whose
/// retirement is not outstanding.
pub(crate) const POLICY: u64 = LINKED | DETACHED | EVICTED;
/// The slot's binding was restored from recovery metadata, not filled by this storage.
pub(crate) const MARKER: u64 = 1 << 42;
/// Position of the reference count.
pub(crate) const REFS_SHIFT: u32 = 46;
/// One reference in the count.
pub(crate) const REF: u64 = 1 << REFS_SHIFT;
/// Bits that are zero in every well-formed word.
pub(crate) const RESERVED: u64 = REF - (1 << 43);
/// The largest count the word holds; validation keeps `object_rights + 1`
/// at or below it, so the anchor and every right always fit.
pub(crate) const REFS_MAX: usize = (1 << (64 - REFS_SHIFT)) - 1;

const _: () = assert!(
    INCARNATION
        | ABANDONED
        | RETIRED
        | ANCHORED
        | VISITED
        | STATE
        | POLICY
        | MARKER
        | RESERVED
        | (REFS_MAX as u64) << REFS_SHIFT
        == u64::MAX
        && INCARNATION
            & (ABANDONED | RETIRED | ANCHORED | VISITED | STATE | POLICY | MARKER | RESERVED)
            == 0
        && (ABANDONED | RETIRED | ANCHORED | VISITED) & (STATE | POLICY | MARKER | RESERVED) == 0
        && STATE & (POLICY | MARKER | RESERVED) == 0
        && POLICY & (MARKER | RESERVED) == 0
        && MARKER & RESERVED == 0
        && REFS_MAX == (1 << 18) - 1
);

/// The lifecycle state of one object slot, held in bits 36 to 38 of its
/// lifetime word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    Free,
    Filling,
    Resident,
    Retired,
    /// Incarnation counter exhausted; never reissued.
    Quarantined,
}

impl SlotState {
    /// The state's encoding in the word. `Free` is zero, so a free slot's
    /// word is its incarnation alone; `Filling` and `Resident` are subsets of
    /// `Retired`, so a retirement sets its state with the one `try_update`
    /// that sets its flags.
    #[inline(always)]
    pub(crate) const fn bits(self) -> u64 {
        (match self {
            Self::Free => 0,
            Self::Filling => 1,
            Self::Resident => 2,
            Self::Retired => 3,
            Self::Quarantined => 4,
        }) << STATE_SHIFT
    }
}

const _: () = assert!(
    SlotState::Filling.bits() & !SlotState::Retired.bits() == 0
        && SlotState::Resident.bits() & !SlotState::Retired.bits() == 0
);

/// The state `word` carries, read by a gate holder.
///
/// # Panics
///
/// If the word is malformed: a reserved bit set or a state encoding past
/// `Quarantined`. The caller holds the gate, so the panic poisons it.
#[inline(always)]
pub(crate) fn state(word: u64) -> SlotState {
    match checked(word) & STATE {
        bits if bits == SlotState::Free.bits() => SlotState::Free,
        bits if bits == SlotState::Filling.bits() => SlotState::Filling,
        bits if bits == SlotState::Resident.bits() => SlotState::Resident,
        bits if bits == SlotState::Retired.bits() => SlotState::Retired,
        bits if bits == SlotState::Quarantined.bits() => SlotState::Quarantined,
        _ => panic!("a slot word with an unknown state"),
    }
}

/// Moves `slot_word`'s state from `from` to `to` and flips the policy bits
/// `policy` in one `fetch_xor` that preserves every other bit, and returns
/// the word it replaced.
/// Only the
/// pool gate's holder calls it, having read `from` under the same hold, and
/// the gate orders every gate holder's reads of the state, so `Relaxed`
/// suffices.
#[inline(always)]
pub(crate) fn move_state(
    slot_word: &AtomicU64,
    from: SlotState,
    to: SlotState,
    policy: u64,
) -> u64 {
    debug_assert_eq!(policy & !POLICY, 0, "a flip outside the policy bits");
    slot_word.fetch_xor(from.bits() ^ to.bits() ^ policy, Ordering::Relaxed)
}

/// The incarnation `word` carries.
#[inline(always)]
pub(crate) const fn incarnation(word: u64) -> u32 {
    word as u32
}

/// The reference count `word` carries.
#[inline(always)]
pub(crate) const fn refs(word: u64) -> usize {
    (word >> REFS_SHIFT) as usize
}

/// Whether every reserved bit of `word` is zero.
#[inline(always)]
pub(crate) const fn well_formed(word: u64) -> bool {
    word & RESERVED == 0
}

/// Whether `word` holds its slot for a drain count: a nonzero count, or a
/// reserved bit set, so a malformed word is never counted drained.
#[inline(always)]
pub(crate) const fn held(word: u64) -> bool {
    refs(word) != 0 || !well_formed(word)
}

/// `word`, read under the pool gate, after the check every gate-held read
/// makes.
///
/// # Panics
///
/// If a reserved bit is set, which only corruption of the control mapping
/// produces; the caller holds the gate, so the panic poisons it.
#[inline(always)]
pub(crate) fn checked(word: u64) -> u64 {
    if !well_formed(word) {
        panic!("a slot word with a reserved bit set");
    }
    word
}

/// The word a park of `incarnation` leaves when it finds `word`: `word` with
/// [`ABANDONED`] and `marks` set, or `None` when the park changes nothing,
/// because the low half names another incarnation, a reserved bit is set,
/// or every bit it would set already is.
#[inline(always)]
pub(crate) const fn parked(word: u64, incarnation: u32, marks: u64) -> Option<u64> {
    let next = word | ABANDONED | marks;
    if word as u32 != incarnation || !well_formed(word) || next == word {
        None
    } else {
        Some(next)
    }
}

/// The word one more right on `incarnation` leaves when a retain finds
/// `word`, with [`VISITED`] set, or `None` when the retain is refused: the
/// low half names another incarnation, a reserved bit is set, or the count
/// is zero. A full count wraps to zero here; the caller refuses a count at
/// its limit before exchanging, so the count never passes [`REFS_MAX`].
#[inline(always)]
pub(crate) const fn retained(word: u64, incarnation: u32) -> Option<u64> {
    match counted(word, incarnation) {
        Some(next) => Some(next | VISITED),
        None => None,
    }
}

/// [`retained`] with [`VISITED`] left as found, for a holder whose hit
/// waits on a verdict that follows the right.
#[inline(always)]
pub(crate) const fn counted(word: u64, incarnation: u32) -> Option<u64> {
    if word as u32 != incarnation || !well_formed(word) || refs(word) == 0 {
        None
    } else {
        Some(word.wrapping_add(REF))
    }
}

/// Sets [`VISITED`] on `slot_word` and changes nothing else. The caller
/// holds a right it took through [`counted`], so the word stays on that
/// right's incarnation with a positive count.
#[inline(always)]
pub(crate) fn visit(slot_word: &AtomicU64) {
    slot_word.fetch_or(VISITED, Ordering::Relaxed);
}

/// The word the anchor's release leaves when it finds `word`: [`ANCHORED`]
/// cleared and the count one lower, in one write.
#[inline(always)]
pub(crate) const fn unanchored(word: u64) -> u64 {
    (word & !ANCHORED) - REF
}

/// Installs `count` references, the anchor and a publisher's rights at
/// publication or a fill's one write right before its first outstanding
/// command, on `slot_word` while its count is zero and its low half is
/// `incarnation`, and returns whether it did. One compare-exchange from the
/// value loaded, retried against the value it found while the count stays
/// zero; a nonzero count, another incarnation or a malformed word refuses
/// with nothing changed. The owner's exclusive claim keeps the low half at
/// its incarnation, so a refusal for another incarnation means a corrupt
/// word: publication reports it as the anchor already present, which fails
/// closed, and the fill's write path panics, since only the fill's own
/// writes count on its `Filling` slot. `Release`: the exchange heads the release sequence the rights and
/// the anchor's release extend, so a reclaimer's acquire of the terminal
/// zero pairs with it.
#[inline(always)]
pub(crate) fn install(slot_word: &AtomicU64, incarnation: u32, count: usize) -> bool {
    let mut current = slot_word.load(Ordering::Relaxed);
    loop {
        if refs(current) != 0 || current as u32 != incarnation || !well_formed(current) {
            return false;
        }
        let next = current + count as u64 * REF;
        match slot_word.compare_exchange(current, next, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(seen) => current = seen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_is_pinned() {
        assert_eq!(size_of::<std::sync::atomic::AtomicU64>(), 8);
        assert_eq!(INCARNATION, 0xFFFF_FFFF);
        assert_eq!(
            [ABANDONED, RETIRED, ANCHORED, VISITED].map(u64::trailing_zeros),
            [32, 33, 34, 35]
        );
        assert_eq!(
            [LINKED, DETACHED, EVICTED].map(u64::trailing_zeros),
            [39, 40, 41]
        );
        assert_eq!(POLICY, 0b111 << 39);
        assert_eq!((MARKER, RESERVED), (1 << 42, 0b111 << 43));
        assert_eq!(STATE, 0b111 << 36);
        assert_eq!(
            [
                SlotState::Free,
                SlotState::Filling,
                SlotState::Resident,
                SlotState::Retired,
                SlotState::Quarantined
            ]
            .map(|state| state.bits() >> 36),
            [0, 1, 2, 3, 4]
        );
        assert_eq!((REFS_SHIFT, REFS_MAX), (46, 262_143));
        let word = 7 | ANCHORED | (3 * REF);
        assert_eq!((incarnation(word), refs(word)), (7, 3));
        assert_eq!(refs(!RESERVED), REFS_MAX);
    }

    #[test]
    fn a_reserved_bit_fails_every_transition() {
        for bit in 43..46 {
            let word = 5 | 1 << bit | (2 * REF);
            assert!(!well_formed(word), "{bit}");
            assert_eq!(parked(word, 5, 0), None, "{bit}");
            assert_eq!(retained(word, 5), None, "{bit}");
            assert!(std::panic::catch_unwind(|| checked(word)).is_err(), "{bit}");
            let idle = AtomicU64::new(5 | 1 << bit);
            assert!(!install(&idle, 5, 2), "{bit}");
            assert_eq!(idle.load(Ordering::Relaxed), 5 | 1 << bit, "{bit}");
        }
        let idle = AtomicU64::new(5);
        assert!(!install(&idle, 4, 2));
        assert!(!install(&idle, 6, 2));
        assert!(install(&idle, 5, 2));
        assert_eq!(idle.load(Ordering::Relaxed), 5 | (2 * REF));
        assert_eq!(checked(5 | (2 * REF)), 5 | (2 * REF));
    }

    /// Every transition a reader without the gate or a park makes carries
    /// the state, policy and marker bits unchanged, a state move changes only the
    /// state, a policy bit is well formed, and a gate holder's decode
    /// refuses every encoding past `Quarantined`.
    #[test]
    fn state_and_policy_bits_pass_through_every_other_transition() {
        let states = [
            SlotState::Free,
            SlotState::Filling,
            SlotState::Resident,
            SlotState::Retired,
            SlotState::Quarantined,
        ];
        for (state, policy) in states.into_iter().flat_map(|state| {
            [0, LINKED, DETACHED | EVICTED, LINKED | MARKER].map(|policy| (state, policy))
        }) {
            let kept = state.bits() | policy;
            let word = 5 | REF | kept;
            assert_eq!(super::state(word), state);
            assert_eq!(checked(word), word);
            let parked = parked(word, 5, ANCHORED).unwrap();
            let retained = retained(word, 5).unwrap();
            let anchored = (word | ABANDONED | ANCHORED) + REF;
            for next in [parked, retained, unanchored(anchored)] {
                assert_eq!(
                    next & (STATE | POLICY | MARKER),
                    kept,
                    "{state:?} {policy:x}"
                );
            }
            let idle = AtomicU64::new(5 | kept);
            assert!(install(&idle, 5, 2));
            assert_eq!(
                idle.load(Ordering::Relaxed) & (STATE | POLICY | MARKER),
                kept
            );
            let moved = AtomicU64::new(word | VISITED);
            let previous = move_state(&moved, state, SlotState::Retired, 0);
            assert_eq!(previous, word | VISITED);
            assert_eq!(
                moved.load(Ordering::Relaxed),
                word & !STATE | VISITED | SlotState::Retired.bits()
            );
        }
        for encoding in 5..8u64 {
            let word = 5 | REF | encoding << STATE_SHIFT;
            assert!(well_formed(word), "{encoding}");
            assert!(std::panic::catch_unwind(|| super::state(word)).is_err());
        }
    }

    #[test]
    fn transitions_hold_their_incarnation() {
        let word = 5 | REF;
        assert_eq!(parked(word, 4, 0), None);
        assert_eq!(parked(word, 5, ANCHORED), Some(word | ABANDONED | ANCHORED));
        assert_eq!(parked(word | ABANDONED, 5, 0), None);
        assert_eq!(retained(word, 4), None);
        assert_eq!(retained(5, 5), None);
        assert_eq!(retained(word, 5), Some(5 | VISITED | (2 * REF)));
        let anchored = (word | ABANDONED | ANCHORED) + REF;
        assert_eq!(unanchored(anchored), 5 | ABANDONED | REF);
    }
}
