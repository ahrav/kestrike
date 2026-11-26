//! The 128-byte index bucket: one atomic control word, one atomic overflow
//! link and fourteen one-word atomic identity pairs.
//!
//! The control word holds one four-bit lane per pair: lane `i` is bits
//! `4 i .. 4 i + 4`, its low bit the pair's occupancy and its upper three
//! bits the low three bits of the pair's tag. The lanes let a reader select
//! the occupied pairs that can carry a tag with one word-parallel compare
//! ([`candidate_lanes`]) before it loads any pair word, so a chain scan
//! loads about one pair per bucket instead of every occupied pair; the full
//! tag in the pair word still decides. Bits 56..64 are reserved and zero.
//!
//! A lane of [`PENDING_LANE`], occupancy clear and every filter bit set,
//! holds a pending pair: its word names an identity whose publication has
//! not committed. Candidate selection, chain scans and removal walks take
//! occupied lanes only, so a reader loads pair words for the occupied
//! lanes its control word shows. [`first_free`] skips a pending lane, so
//! placement leaves it reserved, and [`held_pairs`] counts it, so a removal
//! that clears the bucket's last occupied pair keeps the bucket linked
//! while the pending pair remains. An unoccupied lane with any other filter
//! bits is free. [`Bucket::reserve_pair`] writes a pending pair,
//! [`Bucket::activate_pair`] makes it occupied with one control store,
//! and [`Bucket::cancel_pair`] frees it once.
//!
//! Every shared field is an initialized atomic for the whole life of the
//! index, empty pairs included; nothing reads a bucket through a non-atomic
//! cast or a vector load across live atomics, which is why the fields are
//! private to the index: the writer's store order lives in
//! [`Bucket::publish_pair`], [`Bucket::link`], [`Bucket::clear_pair`] and
//! the pending pair's three methods, and the reader's loads in the scan and
//! in [`Bucket::peek_slot`], whose result only forms a hint's address.
//! Slot records and payload bytes stay outside the bucket: a pair carries
//! only the identity that names them.
//!
//! A pair is one 64-bit word, so every copy of it is whole: bits 0..16 hold
//! the tag, the 16 hash bits directly above the bucket bits; bits 16..32 the
//! low 16 bits of the slot's incarnation; bits 32..64 the slot. The tag and
//! the incarnation bits filter. A lookup accepts a pair only when the slot's
//! current incarnation and the key's fingerprint match; a volume read then
//! compares the full key with the record header before any payload byte.
//!
//! Layout on the assumed 64-bit target: control at offset 0, link at offset
//! 8, pair `i` at offset `16 + 8 i`, 128 bytes at alignment 64 with no
//! padding. Pairs 0 to 5 share the first 64-byte line with the control word
//! and pairs 6 to 13 fill the second; no atomic straddles a line. The
//! contract is [`BucketLayout::EXPECTED`], asserted at compile time and
//! again by [`verify_layout`] at run time so an allocator of bucket arrays
//! can check the target it runs on before allocating.

use std::mem::{align_of, offset_of, size_of};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};

use crate::storage::AllocationId;

/// One identity pair: one atomic word in the layout [`Identity::pack`]
/// writes. A pair whose occupancy bit in the control word is clear is
/// unoccupied and its word is unspecified.
#[repr(transparent)]
#[derive(Debug)]
pub(crate) struct Pair {
    pub(super) word: AtomicU64,
}

/// A pair's contents: the tag it is filtered by, the low 16 bits of the
/// incarnation and the slot it names. Plain data, so a snapshot can hold
/// `14 (1 + D)` of them in fixed scratch; a copied identity names a slot
/// only once the slot's current incarnation carries its low bits. The fields
/// sit in the word's order, so on a little-endian target an identity's bytes
/// equal its pair word.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub tag: u16,
    pub incarnation_low: u16,
    pub slot: u32,
}

/// Bit offset of the incarnation's low bits in a pair word.
const INCARNATION_SHIFT: u32 = 16;
/// Bit offset of the slot in a pair word.
const SLOT_SHIFT: u32 = 32;

impl Identity {
    /// The identity naming `id` under `tag`. Configuration validation keeps
    /// the slot count below `2^31 - 1`, so the slot fits its 32 bits.
    #[inline(always)]
    pub(crate) fn new(tag: u16, id: AllocationId) -> Self {
        debug_assert!(u32::try_from(id.slot().0).is_ok());
        Self {
            tag,
            incarnation_low: id.incarnation() as u16,
            slot: id.slot().0 as u32,
        }
    }

    /// The pair word: tag in bits 0..16, incarnation bits in 16..32, slot
    /// in 32..64.
    #[inline(always)]
    pub const fn pack(self) -> u64 {
        self.tag as u64
            | (self.incarnation_low as u64) << INCARNATION_SHIFT
            | (self.slot as u64) << SLOT_SHIFT
    }

    /// The identity a pair word holds; every word decodes.
    #[inline(always)]
    pub const fn unpack(word: u64) -> Self {
        Self {
            tag: word as u16,
            incarnation_low: (word >> INCARNATION_SHIFT) as u16,
            slot: (word >> SLOT_SHIFT) as u32,
        }
    }
}

/// Pairs per bucket.
pub const PAIRS: usize = 14;

/// Bits of one control lane.
pub const LANE_BITS: u32 = 4;

/// `pattern`, a value below `2^LANE_BITS`, repeated in every lane.
const fn lanes(pattern: u64) -> u64 {
    let mut word = 0;
    let mut pair = 0;
    while pair < PAIRS {
        word |= pattern << (pair as u32 * LANE_BITS);
        pair += 1;
    }
    word
}

/// Bits of the control word that record which pairs are occupied: bit `4 i`
/// is pair `i`.
pub const OCCUPANCY_MASK: u64 = lanes(0b0001);

/// Bits of the control word that hold the pairs' tag filters: bits
/// `4 i + 1 .. 4 i + 4` are the low three bits of pair `i`'s tag.
pub const FILTER_MASK: u64 = lanes(0b1110);

/// Every bit the control word defines. The rest are initialized to zero and
/// reserved.
pub const CONTROL_MASK: u64 = OCCUPANCY_MASK | FILTER_MASK;

/// The high bit of every lane.
const LANE_HIGH: u64 = lanes(0b1000);

/// The low three bits of every lane.
const LANE_LOW: u64 = lanes(0b0111);

/// The lane of a pending pair: unoccupied, every filter bit set.
const PENDING_LANE: u64 = 0b1110;

/// Lane-high bits of the lanes of `control` that equal `pattern`, a value
/// below `2^LANE_BITS`: each lane is xored with the pattern, so a lane is
/// zero exactly when it matches, and a nonzero lane carries into or holds
/// its high bit. Reserved bits above the lanes are ignored.
#[inline(always)]
const fn lanes_equal(control: u64, pattern: u64) -> u64 {
    let lanes = (control & CONTROL_MASK) ^ (pattern * lanes(1));
    let nonzero = ((lanes & LANE_LOW) + LANE_LOW) | lanes;
    !nonzero & LANE_HIGH
}

/// The occupancy bit of `pair`.
#[inline(always)]
const fn occupancy_bit(pair: usize) -> u64 {
    1 << (pair as u32 * LANE_BITS)
}

/// The lane an occupied pair carrying `tag` holds: occupied, and the tag's
/// low three bits.
#[inline(always)]
const fn lane(tag: u16) -> u64 {
    1 | ((tag as u64 & 0b111) << 1)
}

/// `control` with `pair` occupied under `tag`.
#[inline(always)]
pub(crate) const fn control_with(control: u64, pair: usize, tag: u16) -> u64 {
    let shift = pair as u32 * LANE_BITS;
    (control & !(0b1111 << shift)) | (lane(tag) << shift)
}

/// `control` with `pair` unoccupied, its lane cleared.
#[inline(always)]
pub(crate) const fn control_without(control: u64, pair: usize) -> u64 {
    control & !(0b1111 << (pair as u32 * LANE_BITS))
}

/// Whether `control` marks `pair` occupied.
#[inline(always)]
pub(crate) const fn is_occupied(control: u64, pair: usize) -> bool {
    control & occupancy_bit(pair) != 0
}

/// Counts the occupied pairs of a control word.
#[inline(always)]
pub(crate) fn occupied_pairs(control: u64) -> usize {
    (control & OCCUPANCY_MASK).count_ones() as usize
}

/// The lowest free pair of a control word, unoccupied and not pending, or
/// `None` when every pair is occupied or pending.
#[inline(always)]
pub(crate) fn first_free(control: u64) -> Option<usize> {
    // Each pending lane's high bit, moved down to the lane's occupancy bit.
    let pending = lanes_equal(control, PENDING_LANE) >> (LANE_BITS - 1);
    let free = !control & OCCUPANCY_MASK & !pending;
    (free != 0).then(|| (free.trailing_zeros() / LANE_BITS) as usize)
}

/// Whether `control` marks `pair` pending.
#[inline(always)]
pub(crate) const fn is_pending(control: u64, pair: usize) -> bool {
    (control >> (pair as u32 * LANE_BITS)) & 0b1111 == PENDING_LANE
}

/// `control` with `pair` pending.
#[inline(always)]
pub(crate) const fn control_pending(control: u64, pair: usize) -> u64 {
    let shift = pair as u32 * LANE_BITS;
    (control & !(0b1111 << shift)) | (PENDING_LANE << shift)
}

/// Counts the pairs of a control word that hold a lane: occupied or
/// pending. A bucket with any held pair stays linked.
#[inline(always)]
pub(crate) fn held_pairs(control: u64) -> usize {
    occupied_pairs(control) + lanes_equal(control, PENDING_LANE).count_ones() as usize
}

/// Lane-high bits of the occupied pairs of `control` whose filter equals
/// `tag`'s low three bits: every pair that can carry `tag`, from one
/// word-parallel compare. Each lane is xored with the lane an occupied pair
/// carrying `tag` holds, so a lane is zero exactly when it matches. A lane
/// is nonzero when its low three bits are nonzero, which adding `0b0111` to
/// them carries into the lane's high bit, or when its own high bit is set;
/// the sum stays inside the lane. Reserved bits above the lanes are ignored.
#[inline(always)]
pub(crate) fn candidate_lanes(control: u64, tag: u16) -> u64 {
    lanes_equal(control, lane(tag))
}

/// Pair indices of a lane mask, lowest first: one bit anywhere in a lane
/// names its pair.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LanePairs(u64);

impl Iterator for LanePairs {
    type Item = usize;

    #[inline(always)]
    fn next(&mut self) -> Option<usize> {
        if self.0 == 0 {
            return None;
        }
        let pair = (self.0.trailing_zeros() / LANE_BITS) as usize;
        self.0 &= self.0 - 1;
        Some(pair)
    }
}

/// The pairs named by `lanes`, a mask with at most one bit per lane.
#[inline(always)]
pub(crate) fn lane_pairs(lanes: u64) -> LanePairs {
    LanePairs(lanes)
}

/// The occupied pairs of `control`, lowest first.
#[inline(always)]
pub(crate) fn occupied(control: u64) -> LanePairs {
    LanePairs(control & OCCUPANCY_MASK)
}

/// One index bucket. See the module documentation for the layout contract.
#[repr(C, align(64))]
#[derive(Debug)]
pub(crate) struct Bucket {
    /// One four-bit lane per pair, [`CONTROL_MASK`]; the rest are reserved
    /// and zero.
    pub(super) control: AtomicU64,
    /// Encoded [`OverflowLink`]: shard-local overflow index plus one, zero
    /// for no link.
    pub(super) next: AtomicUsize,
    pub(super) pairs: [Pair; PAIRS],
}

impl Pair {
    /// An unoccupied pair, its word zero.
    const fn empty() -> Self {
        Self {
            word: AtomicU64::new(0),
        }
    }
}

impl Bucket {
    /// Each occupied pair's identity, in pair order, for a test lens that
    /// reads the bucket passively.
    #[cfg(test)]
    pub(crate) fn identities(&self) -> impl Iterator<Item = Identity> + '_ {
        let control = self.control.load(Ordering::Relaxed);
        occupied(control)
            .map(|pair| Identity::unpack(self.pairs[pair].word.load(Ordering::Relaxed)))
    }

    /// The slot of the lowest occupied pair that carries `tag`, as one
    /// `Relaxed` load of the control word and one of each candidate pair up
    /// to that one read them. The loads run outside any gate, pin or
    /// sequence check, so the slot may come from a pair a writer is
    /// replacing and may name no slot of the pool: it is fit to form a
    /// hint's address once the caller has bounded it, and for nothing else.
    #[inline(always)]
    pub(crate) fn peek_slot(&self, tag: u16) -> Option<usize> {
        let control = self.control.load(Ordering::Relaxed);
        for pair in lane_pairs(candidate_lanes(control, tag)) {
            let identity = Identity::unpack(self.pairs[pair].word.load(Ordering::Relaxed));
            if identity.tag == tag {
                return Some(identity.slot as usize);
            }
        }
        None
    }

    /// An empty bucket: no pair occupied, no link, every field zero.
    pub(crate) fn empty() -> Self {
        Self {
            control: AtomicU64::new(0),
            next: AtomicUsize::new(OverflowLink::NONE.0),
            pairs: [const { Pair::empty() }; PAIRS],
        }
    }

    /// Publishes `id` under `tag` in unoccupied pair `pair`: the pair word,
    /// then the pair's lane, both stores `Relaxed`. A bucket readers can
    /// reach is written only by the shard gate holder with the sequence
    /// busy. `Busy::begin` stores the odd sequence value and issues a release
    /// fence before these stores, so a reader's copy across them fails its
    /// sequence recheck in either store order. `control` is the word the
    /// caller loaded under the same gate hold, and the holder is the only
    /// writer, so a plain store suffices. Seeding may call this directly
    /// while the bucket is still unreachable to readers.
    #[inline(always)]
    pub(crate) fn publish_pair(&self, pair: usize, control: u64, tag: u16, id: AllocationId) {
        self.pairs[pair]
            .word
            .store(Identity::new(tag, id).pack(), Ordering::Relaxed);
        self.control
            .store(control_with(control, pair, tag), Ordering::Relaxed);
    }

    /// Stores the overflow link, `Relaxed`, under the same gate and busy
    /// sequence as [`publish_pair`](Self::publish_pair).
    #[inline(always)]
    pub(crate) fn link(&self, link: OverflowLink) {
        self.next.store(link.0, Ordering::Relaxed);
    }

    /// The caller holds the gate with the sequence busy or terminal, and
    /// `control` is the control word it loaded under that hold. The holder is
    /// the bucket's one writer, so the word is still current and the cleared
    /// lane is published with a `Relaxed` store. The pair's word becomes
    /// unspecified.
    #[inline(always)]
    pub(crate) fn clear_pair(&self, pair: usize, control: u64) {
        self.control
            .store(control_without(control, pair), Ordering::Relaxed);
    }

    /// Writes raw words into the control word and the link, bypassing every
    /// check, so tests can plant a malformed table.
    #[cfg(test)]
    pub(crate) fn corrupt(&self, control: u64, next: usize) {
        self.control.store(control, Ordering::SeqCst);
        self.next.store(next, Ordering::SeqCst);
    }

    /// The caller writes the bucket alone.
    #[cfg(test)]
    pub(crate) fn plant(&self, identity: Identity) -> Option<usize> {
        let control = self.control.load(Ordering::Relaxed);
        let free = first_free(control)?;
        self.pairs[free]
            .word
            .store(identity.pack(), Ordering::Relaxed);
        self.control
            .store(control_with(control, free, identity.tag), Ordering::Relaxed);
        Some(free)
    }

    /// The caller writes the bucket alone.
    #[cfg(test)]
    pub(crate) fn clear(&self, pair: usize) {
        self.clear_pair(pair, self.control.load(Ordering::Relaxed));
    }
}

/// A pending pair's reservation, activation and cancel.
impl Bucket {
    /// Reserves free pair `pair` for `id` under `tag` as a pending pair: a
    /// release fence, then the pair word, then the pending lane, both
    /// `Relaxed`, by the shard gate holder, the bucket's one writer, which
    /// loads the control word itself. Returns whether the pair was free; an
    /// occupied or pending pair is left unchanged. No candidate selection
    /// takes a pending lane, but a reader holding an older control word in
    /// which the pair was still occupied can load the new word; the fence
    /// makes that reader's acquire load of the word synchronize with it, so
    /// the reader's second sequence load sees the bracket that freed the pair
    /// and rejects the copy, as the `sequence` module requires of every bucket
    /// store outside a bracket.
    #[inline(always)]
    pub(crate) fn reserve_pair(&self, pair: usize, tag: u16, id: AllocationId) -> bool {
        let control = self.control.load(Ordering::Relaxed);
        if is_occupied(control, pair) || is_pending(control, pair) {
            return false;
        }
        fence(Ordering::Release);
        self.pairs[pair]
            .word
            .store(Identity::new(tag, id).pack(), Ordering::Relaxed);
        self.control
            .store(control_pending(control, pair), Ordering::Relaxed);
        true
    }

    /// Makes pending pair `pair` occupied under the tag its reserved word
    /// carries, with one `Relaxed` store of the control word, which the gate
    /// holder loads itself: a reader's copy of the bucket holds the pair
    /// either pending, absent from its candidates, or occupied with the word
    /// reserved before, never between. The caller holds the gate with the
    /// sequence busy, as for [`publish_pair`](Bucket::publish_pair), and
    /// stores the chain summary with the returned tag in the same bracket.
    /// Returns that tag, or `None`, with the pair unchanged, when it was not
    /// pending.
    #[inline(always)]
    pub(crate) fn activate_pair(&self, pair: usize) -> Option<u16> {
        let control = self.control.load(Ordering::Relaxed);
        if !is_pending(control, pair) {
            return None;
        }
        let tag = Identity::unpack(self.pairs[pair].word.load(Ordering::Relaxed)).tag;
        self.control
            .store(control_with(control, pair, tag), Ordering::Relaxed);
        Some(tag)
    }

    /// The word pending pair `pair` was reserved with, read by the gate
    /// holder, or `None` when the pair is not pending.
    #[inline(always)]
    pub(crate) fn pending_word(&self, pair: usize) -> Option<u64> {
        let control = self.control.load(Ordering::Relaxed);
        is_pending(control, pair).then(|| self.pairs[pair].word.load(Ordering::Relaxed))
    }

    /// Frees pending pair `pair` with a release fence and one `Relaxed`
    /// store, by the gate holder, which loads the control word itself; the
    /// fence lets a reader that loads the new control word reject a copy
    /// taken across earlier brackets, as for
    /// [`reserve_pair`](Bucket::reserve_pair). Returns whether the pair was
    /// pending: a second cancel, or a cancel of an occupied or free pair,
    /// changes nothing and returns `false`, so a reservation frees its lane
    /// once. A cancel that leaves an overflow bucket with no held pair
    /// leaves it linked and empty; unlinking it needs the chain's
    /// predecessor, which a caller's chain walk records.
    #[inline(always)]
    pub(crate) fn cancel_pair(&self, pair: usize) -> bool {
        let control = self.control.load(Ordering::Relaxed);
        if !is_pending(control, pair) {
            return false;
        }
        fence(Ordering::Release);
        self.control
            .store(control_without(control, pair), Ordering::Relaxed);
        true
    }
}

/// The encoded value of a bucket's `next` word: a shard-local overflow index
/// plus one, so that zero means no link and the encoding never collides with
/// index zero. Decoding recovers the index only; whether it lies below the
/// shard's overflow count is the chain walk's check, which fails closed on
/// an out-of-range link rather than treating it as absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverflowLink(usize);

/// The overflow index is `usize::MAX`, whose encoding would wrap to zero and
/// read as no link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnencodableLink;

impl OverflowLink {
    /// No link.
    pub const NONE: Self = Self(0);

    /// Encodes a link to overflow bucket `index`.
    ///
    /// # Errors
    ///
    /// `UnencodableLink` if `index + 1` does not fit the word. Geometry
    /// never produces such an index: it refuses a shard whose physical pair
    /// count `14 (B + A)` overflows, so `A <= usize::MAX / 14`, and this
    /// refusal guards the link writer, not validation.
    pub fn encode(index: usize) -> Result<Self, UnencodableLink> {
        index.checked_add(1).map(Self).ok_or(UnencodableLink)
    }

    /// The word as stored in a bucket.
    pub fn raw(self) -> usize {
        self.0
    }

    /// The link a stored word encodes, for carrying it to another bucket
    /// unchanged; whether it is in range is still the chain walk's check.
    pub(crate) fn from_raw(raw: usize) -> Self {
        Self(raw)
    }

    /// Decodes a stored word: `None` for no link, else the overflow index.
    pub fn decode(raw: usize) -> Option<usize> {
        raw.checked_sub(1)
    }
}

/// The layout of a bucket type: size, alignment and field offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketLayout {
    pub size: usize,
    pub align: usize,
    pub control: usize,
    pub next: usize,
    /// Offset of pair 0; pair `i` follows at `pairs + i * pair_size`.
    pub pairs: usize,
    pub pair_size: usize,
}

impl BucketLayout {
    /// The contract every bucket array is laid out against.
    pub const EXPECTED: Self = Self {
        size: 128,
        align: 64,
        control: 0,
        next: 8,
        pairs: 16,
        pair_size: 8,
    };

    /// The layout the compiler gave the bucket type on this target.
    pub const ACTUAL: Self = Self {
        size: size_of::<Bucket>(),
        align: align_of::<Bucket>(),
        control: offset_of!(Bucket, control),
        next: offset_of!(Bucket, next),
        pairs: offset_of!(Bucket, pairs),
        pair_size: size_of::<Pair>(),
    };

    /// Offset of pair `index`.
    pub fn pair(&self, index: usize) -> usize {
        self.pairs + index * self.pair_size
    }
}

/// A bucket layout that differs from the contract. The refused layout is
/// carried; the contract it missed is [`BucketLayout::EXPECTED`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketLayoutMismatch {
    pub actual: BucketLayout,
}

/// Checks `actual` against the layout contract.
///
/// # Errors
///
/// `BucketLayoutMismatch` carrying the refused layout.
pub fn verify_layout(actual: BucketLayout) -> Result<(), BucketLayoutMismatch> {
    if actual == BucketLayout::EXPECTED {
        Ok(())
    } else {
        Err(BucketLayoutMismatch { actual })
    }
}

const _: () = {
    let (actual, expected) = (BucketLayout::ACTUAL, BucketLayout::EXPECTED);
    assert!(actual.size == expected.size);
    assert!(actual.align == expected.align);
    assert!(actual.control == expected.control);
    assert!(actual.next == expected.next);
    assert!(actual.pairs == expected.pairs);
    assert!(actual.pair_size == expected.pair_size);
    assert!(size_of::<Pair>() == 8);
    assert!(offset_of!(Pair, word) == 0);
    assert!(expected.pairs + PAIRS * expected.pair_size == expected.size);
    assert!(size_of::<Identity>() == 8);
    assert!(offset_of!(Identity, tag) == 0);
    assert!(offset_of!(Identity, incarnation_low) == 2);
    assert!(offset_of!(Identity, slot) == 4);
};

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    /// Every occupancy pattern counts as `count_ones` of its occupancy
    /// bits does, whatever the filter bits hold, and the first free pair is
    /// the lowest unoccupied lane.
    #[test]
    fn occupancy_is_counted_and_the_first_free_pair_found_from_the_lanes() {
        assert_eq!(OCCUPANCY_MASK, 0x0011_1111_1111_1111);
        assert_eq!(FILTER_MASK, 0x00EE_EEEE_EEEE_EEEE);
        assert_eq!(CONTROL_MASK, 0x00FF_FFFF_FFFF_FFFF);
        for pattern in 0..=(1u64 << PAIRS) - 1 {
            let mut control = 0;
            for pair in 0..PAIRS {
                if pattern & (1 << pair) != 0 {
                    control = control_with(control, pair, 0xFFFF ^ pair as u16);
                }
            }
            assert_eq!(occupied_pairs(control), pattern.count_ones() as usize);
            assert_eq!(
                control & OCCUPANCY_MASK,
                control & CONTROL_MASK & OCCUPANCY_MASK
            );
            assert_eq!(
                first_free(control),
                (0..PAIRS).find(|pair| pattern & (1 << pair) == 0)
            );
            assert_eq!(
                occupied(control).collect::<Vec<_>>(),
                (0..PAIRS)
                    .filter(|pair| pattern & (1 << pair) != 0)
                    .collect::<Vec<_>>()
            );
            for pair in 0..PAIRS {
                assert_eq!(is_occupied(control, pair), pattern & (1 << pair) != 0);
            }
        }
        assert_eq!(occupied_pairs(CONTROL_MASK), PAIRS);
        assert_eq!(first_free(CONTROL_MASK), None);
    }

    /// The candidate lanes are exactly the occupied pairs whose filter bits
    /// equal the tag's low three bits: every filter value against every
    /// tag residue, with reserved bits and unoccupied lanes ignored.
    #[test]
    fn candidate_lanes_select_exactly_the_occupied_pairs_whose_filter_matches() {
        for tag in [0u16, 1, 5, 7, 8, 0x1234, 0xFFF8, 0xFFFF] {
            // Pairs 0..8 occupied with filters 0..8, pairs 8..14 unoccupied
            // but with stale filter bits equal to the tag's residue.
            let mut control = 0;
            for pair in 0..8 {
                control = control_with(control, pair, pair as u16);
            }
            for pair in 8..PAIRS {
                control |= u64::from(tag & 0b111) << (pair as u32 * LANE_BITS + 1);
            }
            let pairs: Vec<usize> = lane_pairs(candidate_lanes(control, tag)).collect();
            assert_eq!(pairs, vec![(tag & 0b111) as usize], "tag {tag:#x}");
            // Reserved bits do not disturb the compare.
            let pairs: Vec<usize> =
                lane_pairs(candidate_lanes(control | 0xFF << 56, tag)).collect();
            assert_eq!(pairs, vec![(tag & 0b111) as usize]);
        }
        // Every occupied pair with the residue is a candidate, in order.
        let mut control = 0;
        for pair in [1usize, 4, 13] {
            control = control_with(control, pair, 0x0D);
        }
        control = control_with(control, 6, 0x0C);
        assert_eq!(
            lane_pairs(candidate_lanes(control, 0xAD)).collect::<Vec<_>>(),
            vec![1, 4, 13]
        );
        assert_eq!(
            lane_pairs(candidate_lanes(control, 0x04)).collect::<Vec<_>>(),
            vec![6]
        );
        assert_eq!(candidate_lanes(control, 0x02), 0);
        assert_eq!(candidate_lanes(0, 0), 0);
        // Clearing a pair removes it from the candidates.
        assert_eq!(
            lane_pairs(candidate_lanes(control_without(control, 4), 0xAD)).collect::<Vec<_>>(),
            vec![1, 13]
        );
    }

    /// A pair is one 8-byte word; the bucket fits the control word, the
    /// link and fourteen pairs in 128 bytes at the pinned offsets.
    #[test]
    fn layout_matches_the_contract_and_a_wrong_layout_is_refused() {
        assert_eq!(std::mem::size_of::<Pair>(), 8);
        assert_eq!(std::mem::size_of::<Identity>(), 8);
        assert_eq!(verify_layout(BucketLayout::ACTUAL), Ok(()));
        assert_eq!(BucketLayout::ACTUAL, BucketLayout::EXPECTED);
        assert_eq!(BucketLayout::EXPECTED.pair(13), 120);
        // The compiler's numbers, read back independently through pointers.
        let bucket = Bucket::empty();
        let base = &bucket as *const Bucket as usize;
        assert_eq!(base % 64, 0);
        assert_eq!(&bucket.control as *const AtomicU64 as usize - base, 0);
        assert_eq!(&bucket.next as *const AtomicUsize as usize - base, 8);
        assert_eq!(bucket.pairs.len(), 14);
        for (index, pair) in bucket.pairs.iter().enumerate() {
            assert_eq!(pair as *const Pair as usize - base, 16 + 8 * index);
            assert_eq!(
                &pair.word as *const AtomicU64 as usize - base,
                16 + 8 * index
            );
        }
        assert_eq!(std::mem::size_of_val(&bucket), 128);
        assert_eq!(bucket.control.load(Ordering::Relaxed) & OCCUPANCY_MASK, 0);
        assert_eq!(
            OverflowLink::decode(bucket.next.load(Ordering::Relaxed)),
            None
        );

        // Every field that could drift is refused on its own.
        let wrong = [
            BucketLayout {
                size: 64,
                ..BucketLayout::EXPECTED
            },
            BucketLayout {
                align: 8,
                ..BucketLayout::EXPECTED
            },
            BucketLayout {
                control: 8,
                ..BucketLayout::EXPECTED
            },
            BucketLayout {
                next: 16,
                ..BucketLayout::EXPECTED
            },
            BucketLayout {
                pairs: 24,
                ..BucketLayout::EXPECTED
            },
            BucketLayout {
                pair_size: 32,
                ..BucketLayout::EXPECTED
            },
        ];
        for actual in wrong {
            assert_eq!(verify_layout(actual), Err(BucketLayoutMismatch { actual }));
        }
    }

    /// The word holds the tag in bits 0..16, the incarnation's low bits in
    /// 16..32 and the slot in 32..64, and every word decodes to the identity
    /// it was packed from.
    #[test]
    fn a_pair_word_packs_tag_incarnation_bits_and_slot_at_fixed_bits() {
        use crate::storage::SlotIndex;
        let id = AllocationId::new(SlotIndex(0x1234_5678), 0xABCD_9876);
        let identity = Identity::new(0xBEEF, id);
        assert_eq!(
            identity,
            Identity {
                tag: 0xBEEF,
                incarnation_low: 0x9876,
                slot: 0x1234_5678,
            }
        );
        assert_eq!(identity.pack(), 0x1234_5678_9876_BEEF);
        for word in [0, u64::MAX, 0x1234_5678_9876_BEEF, 1 << 63, 1 << 16] {
            assert_eq!(Identity::unpack(word).pack(), word);
        }
        let bucket = Bucket::empty();
        bucket.publish_pair(13, 0, 0xBEEF, id);
        assert_eq!(
            bucket.pairs[13].word.load(Ordering::Relaxed),
            identity.pack()
        );
        assert_eq!(
            bucket.control.load(Ordering::Relaxed),
            control_with(0, 13, 0xBEEF)
        );
        assert_eq!(control_with(0, 13, 0xBEEF), 0b1111 << 52);
    }

    fn old_decoding(control: u64, tag: u16) -> (Vec<usize>, Option<usize>, Vec<usize>) {
        let lane = |pair: usize| (control >> (pair as u32 * LANE_BITS)) & 0b1111;
        let occupied: Vec<usize> = (0..PAIRS).filter(|&pair| lane(pair) & 1 == 1).collect();
        let free = (0..PAIRS).find(|&pair| lane(pair) & 1 == 0);
        let candidates = (0..PAIRS)
            .filter(|&pair| lane(pair) == 1 | (u64::from(tag & 0b111) << 1))
            .collect();
        (occupied, free, candidates)
    }

    /// Every lane value but the pending one matches the occupancy-bit
    /// decoding: occupied, free and candidate pairs agree for every lane
    /// value at every pair beside occupied neighbours, whatever the tag. A
    /// pending lane has a clear occupancy bit and remains held; candidate
    /// selection uses occupied lanes.
    #[test]
    fn existing_lane_values_decode_unchanged_and_a_pending_lane_is_held() {
        for pair in [0, 5, 13] {
            for value in 0..16u64 {
                let mut control = control_with(0, (pair + 1) % PAIRS, 0x3);
                control |= value << (pair as u32 * LANE_BITS);
                for tag in [0u16, 3, 7, 0xFFFF] {
                    let (occupied_then, free_then, candidates_then) = old_decoding(control, tag);
                    assert_eq!(occupied(control).collect::<Vec<_>>(), occupied_then);
                    assert_eq!(
                        lane_pairs(candidate_lanes(control, tag)).collect::<Vec<_>>(),
                        candidates_then
                    );
                    if value == PENDING_LANE {
                        assert!(is_pending(control, pair));
                        assert_ne!(first_free(control), Some(pair));
                        assert_eq!(held_pairs(control), 2);
                    } else {
                        assert!(!is_pending(control, pair));
                        assert_eq!(first_free(control), free_then, "lane {value:#06b}");
                        assert_eq!(held_pairs(control), occupied_pairs(control));
                    }
                }
            }
        }
    }

    /// Over seeded control words of free, occupied and pending lanes, the
    /// lowest free pair skips every occupied and pending lane, the held
    /// count is their sum, and no pending pair is occupied or a candidate.
    #[test]
    fn pending_lanes_are_held_and_never_selected_over_seeded_words() {
        use crate::storage::seeded::SplitMix64;
        let mut rng = SplitMix64::new(7);
        for _ in 0..4096 {
            let mut control = 0;
            let mut states = [0u8; PAIRS];
            for (pair, state) in states.iter_mut().enumerate() {
                *state = (rng.next_u64() % 3) as u8;
                control = match *state {
                    1 => control_with(control, pair, rng.next_u64() as u16),
                    2 => control_pending(control, pair),
                    _ => control,
                };
            }
            let tag = rng.next_u64() as u16;
            assert_eq!(
                first_free(control),
                states.iter().position(|&state| state == 0)
            );
            assert_eq!(
                held_pairs(control),
                states.iter().filter(|&&state| state != 0).count()
            );
            for pair in lane_pairs(candidate_lanes(control, tag)).chain(occupied(control)) {
                assert_eq!(states[pair], 1);
            }
            for (pair, &state) in states.iter().enumerate() {
                assert_eq!(is_pending(control, pair), state == 2);
            }
        }
    }

    /// A reservation takes only a free pair, and the reserved pair is
    /// pending until activated: activation makes it occupied under its
    /// reserved word's tag in one control store and succeeds once; cancel
    /// frees a pending pair once, and neither touches a free or occupied
    /// pair.
    #[test]
    fn a_pending_pair_activates_once_or_cancels_once() {
        use crate::storage::SlotIndex;
        let id = AllocationId::new(SlotIndex(9), 4);
        let bucket = Bucket::empty();
        bucket.publish_pair(0, 0, 0x21, AllocationId::new(SlotIndex(1), 1));
        let control = bucket.control.load(Ordering::Relaxed);
        // An occupied pair refuses a reservation and keeps its word.
        assert!(!bucket.reserve_pair(0, 0x45, id));
        assert_eq!(bucket.control.load(Ordering::Relaxed), control);
        assert_eq!(
            Identity::unpack(bucket.pairs[0].word.load(Ordering::Relaxed)),
            Identity::new(0x21, AllocationId::new(SlotIndex(1), 1))
        );
        assert!(bucket.reserve_pair(1, 0x45, id));
        let reserved = bucket.control.load(Ordering::Relaxed);
        assert!(is_pending(reserved, 1));
        assert!(!bucket.reserve_pair(1, 0x45, id));
        assert_eq!(first_free(reserved), Some(2));
        assert_eq!(occupied(reserved).collect::<Vec<_>>(), vec![0]);
        assert_eq!(candidate_lanes(reserved, 0x45), 0);
        assert!(!bucket.cancel_pair(0));
        assert_eq!(bucket.activate_pair(2), None);
        assert_eq!(bucket.control.load(Ordering::Relaxed), reserved);
        assert_eq!(bucket.activate_pair(1), Some(0x45));
        let active = bucket.control.load(Ordering::Relaxed);
        assert_eq!(active, control_with(control, 1, 0x45));
        assert_eq!(
            lane_pairs(candidate_lanes(active, 0x45)).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            Identity::unpack(bucket.pairs[1].word.load(Ordering::Relaxed)),
            Identity::new(0x45, id)
        );
        assert_eq!(bucket.activate_pair(1), None);
        assert!(!bucket.cancel_pair(1));
        assert_eq!(bucket.control.load(Ordering::Relaxed), active);
        // A second reservation, cancelled: the lane frees once.
        assert!(bucket.reserve_pair(2, 0x45, id));
        assert!(bucket.cancel_pair(2));
        let cancelled = bucket.control.load(Ordering::Relaxed);
        assert_eq!(cancelled, active);
        assert_eq!(first_free(cancelled), Some(2));
        assert!(!bucket.cancel_pair(2));
        assert_eq!(bucket.activate_pair(2), None);
    }

    #[test]
    fn pending_pair_methods_keep_a_pair_published_between_calls() {
        use crate::storage::SlotIndex;
        let slot = |n| AllocationId::new(SlotIndex(n), 1);
        let bucket = Bucket::empty();
        let publish = |pair, tag, id| {
            let control = bucket.control.load(Ordering::Relaxed);
            bucket.publish_pair(pair, control, tag, id);
        };
        publish(0, 0x21, slot(1));
        assert!(bucket.reserve_pair(1, 0x45, slot(2)));
        publish(2, 0x13, slot(3));
        assert_eq!(bucket.activate_pair(1), Some(0x45));
        assert!(bucket.reserve_pair(3, 0x45, slot(4)));
        publish(4, 0x37, slot(5));
        assert!(bucket.cancel_pair(3));
        let control = bucket.control.load(Ordering::Relaxed);
        assert_eq!(occupied(control).collect::<Vec<_>>(), vec![0, 1, 2, 4]);
        assert_eq!(held_pairs(control), 4);
    }

    /// `peek_slot` names the slot of the lowest occupied pair whose word
    /// carries the whole tag. Its candidates are the occupied pairs whose
    /// lane filter equals the tag's low three bits, and among them the pair
    /// word's full tag decides. A pending pair and a cleared pair hold a
    /// word that carries the tag under an unoccupied lane, so the answer
    /// stays with the occupied pairs. The slot is bits 32..64 of the pair
    /// word, whatever the incarnation bits beside it hold.
    #[test]
    fn peek_slot_names_the_lowest_occupied_pair_that_carries_the_tag() {
        use crate::storage::SlotIndex;
        // The tags share their low three bits, the lane filter, and an
        // occupied lane of that filter differs from a pending lane in its
        // occupancy bit alone.
        const TAG: u16 = 0x47;
        const OTHER: u16 = 0x4F;
        let slot = |n| AllocationId::new(SlotIndex(n), 0x0009_ABCD);
        let bucket = Bucket::empty();
        let publish = |pair, tag, id| {
            let control = bucket.control.load(Ordering::Relaxed);
            bucket.publish_pair(pair, control, tag, id);
        };
        assert_eq!(bucket.peek_slot(TAG), None);
        publish(0, OTHER, slot(10));
        assert_eq!(
            lane_pairs(candidate_lanes(bucket.control.load(Ordering::Relaxed), TAG))
                .collect::<Vec<_>>(),
            vec![0]
        );
        assert_eq!(bucket.peek_slot(TAG), None);
        assert!(bucket.reserve_pair(1, TAG, slot(11)));
        assert_eq!(bucket.peek_slot(TAG), None);
        publish(3, TAG, slot(0x7FFF_0003));
        publish(5, TAG, slot(15));
        assert_eq!(bucket.peek_slot(TAG), Some(0x7FFF_0003));
        assert_eq!(bucket.peek_slot(OTHER), Some(10));
        bucket.clear(3);
        assert_eq!(
            Identity::unpack(bucket.pairs[3].word.load(Ordering::Relaxed)),
            Identity::new(TAG, slot(0x7FFF_0003))
        );
        assert_eq!(bucket.peek_slot(TAG), Some(15));
        assert_eq!(bucket.activate_pair(1), Some(TAG));
        assert_eq!(bucket.peek_slot(TAG), Some(11));
    }

    #[test]
    fn links_encode_index_plus_one_and_refuse_the_unencodable_index() {
        assert_eq!(OverflowLink::NONE.raw(), 0);
        assert_eq!(OverflowLink::decode(0), None);
        for index in [0, 1, 7, usize::MAX - 1] {
            let link = OverflowLink::encode(index).unwrap();
            assert_eq!(link.raw(), index + 1);
            assert_eq!(OverflowLink::decode(link.raw()), Some(index));
        }
        assert_eq!(OverflowLink::encode(usize::MAX), Err(UnencodableLink));
    }
}
