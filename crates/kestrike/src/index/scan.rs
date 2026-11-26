//! The reader's chain scan: copy every tag-matching identity of a chain
//! into fixed scratch, loading the word of each pair whose control lane
//! marks it occupied with the tag's filter bits, following only checked
//! in-range links up to the depth bound.
//!
//! The scan is written over an abstract bucket view so the same code runs on
//! the mapped buckets and, under `--cfg loom`, on model buckets. It runs
//! between the reader's two sequence loads and copies fields only; it never
//! follows a copied identity to a slot record, never touches the writer-only
//! free stack and keeps no bucket reference past the copy. A malformed
//! control word, a link out of range or a chain longer than the depth bound
//! is [`Corrupt`], which the caller fails closed on and never reports as an
//! absent key; a scratch write beyond the declared capacity is `Corrupt` too.
//! Under an unstable sequence the fields read may belong to different shard
//! states; the caller's second sequence load rejects such a copy before it is
//! used, which is why the scan itself only bounds its reads.

use std::sync::atomic::Ordering;

#[cfg(test)]
use super::bucket::PAIRS;
use super::bucket::{
    CONTROL_MASK, Identity, OverflowLink, candidate_lanes, lane_pairs, occupied_pairs,
};

/// One bucket as a reader sees it. Every method is one `SeqCst` load of an
/// atomic word: the sequence module's coherence argument places these loads
/// in one total order with the sequence word, which that argument depends
/// on. These loads are also the
/// publisher-to-reader edge for the record and payload writes behind a
/// copied identity; a consumer of a copied identity must keep an acquire
/// edge of its own.
pub(crate) trait BucketView {
    fn control(&self) -> u64;
    fn next(&self) -> usize;
    /// The identity pair `pair` holds, as one word load.
    fn identity(&self, pair: usize) -> Identity;
}

impl BucketView for super::bucket::Bucket {
    #[inline(always)]
    fn control(&self) -> u64 {
        self.control.load(Ordering::SeqCst)
    }

    #[inline(always)]
    fn next(&self) -> usize {
        self.next.load(Ordering::SeqCst)
    }

    #[inline(always)]
    fn identity(&self, pair: usize) -> Identity {
        Identity::unpack(self.pairs[pair].word.load(Ordering::SeqCst))
    }
}

/// The chain's tables are malformed, or the copy would exceed the scratch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Corrupt;

/// Work the scan performed, for the caller to debit: one visit per bucket
/// and one comparison per occupied pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ScanWork {
    pub visits: usize,
    pub comparisons: usize,
}

/// Copies the identities of every occupied pair whose tag equals `tag`
/// along the chain from base bucket `start`, over `base` base buckets and
/// the overflow buckets that follow them in `buckets`, following at most
/// `depth` links.
///
/// The control word's lanes compare every occupied pair's filter bits with
/// the tag's at once, one comparison per occupied pair; the scan then loads
/// the word of each pair whose lane matched and compares its full tag.
/// Returns how many identities were written to the front of `scratch`; the
/// work done is added to `work`, on an error too, so the caller can debit a
/// scan it retries.
///
/// # Errors
///
/// `Corrupt` on a reserved control bit, an out-of-range link, a chain
/// longer than `depth` links or a copy past `scratch`'s end.
#[inline(always)]
pub(crate) fn scan_chain<B: BucketView>(
    buckets: &[B],
    base: usize,
    start: usize,
    depth: usize,
    tag: u16,
    scratch: &mut [Identity],
    work: &mut ScanWork,
) -> Result<usize, Corrupt> {
    let overflow = buckets.len().checked_sub(base).ok_or(Corrupt)?;
    let mut bucket = buckets.get(start).ok_or(Corrupt)?;
    let mut copied = 0;
    for followed in 0..=depth {
        work.visits += 1;
        let control = bucket.control();
        if control & !CONTROL_MASK != 0 {
            return Err(Corrupt);
        }
        work.comparisons += occupied_pairs(control);
        for pair in lane_pairs(candidate_lanes(control, tag)) {
            let identity = bucket.identity(pair);
            if identity.tag == tag {
                *scratch.get_mut(copied).ok_or(Corrupt)? = identity;
                copied += 1;
            }
        }
        match OverflowLink::decode(bucket.next()) {
            None => return Ok(copied),
            Some(link) if link < overflow && followed < depth => {
                bucket = &buckets[base + link];
            }
            Some(_) => return Err(Corrupt),
        }
    }
    unreachable!("the scan returns from its last permitted bucket")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::bucket::Bucket;
    use crate::storage::{AllocationId, SlotIndex};

    fn blank() -> Identity {
        Identity::unpack(0)
    }

    /// A copy past the scratch's end, a start past the buckets and a base
    /// past the buckets are `Corrupt`; a fitting copy reports its work.
    #[test]
    fn the_scan_fails_closed_on_its_own_bounds() {
        let buckets = [Bucket::empty(), Bucket::empty()];
        for pair in 0..PAIRS {
            let control = buckets[0].control();
            buckets[0].publish_pair(pair, control, 7, AllocationId::new(SlotIndex(pair), 1));
        }
        let mut work = ScanWork::default();
        let mut short = [blank(); 2];
        assert_eq!(
            scan_chain(&buckets, 1, 0, 0, 7, &mut short, &mut work),
            Err(Corrupt)
        );
        let mut scratch = [blank(); PAIRS];
        assert_eq!(
            scan_chain(&buckets, 1, 2, 0, 7, &mut scratch, &mut work),
            Err(Corrupt)
        );
        assert_eq!(
            scan_chain(&buckets, 3, 0, 0, 7, &mut scratch, &mut work),
            Err(Corrupt)
        );
        let mut work = ScanWork::default();
        let copied = scan_chain(&buckets, 1, 0, 0, 7, &mut scratch, &mut work).unwrap();
        assert_eq!(copied, PAIRS);
        assert_eq!(
            work,
            ScanWork {
                visits: 1,
                comparisons: PAIRS
            }
        );
        assert_eq!(scratch[2].slot, 2);
    }

    /// Only occupied pairs whose tag matches are copied, whole and in pair
    /// order; a pair with another tag is compared and not copied, whether
    /// or not its filter bits match.
    #[test]
    fn the_scan_copies_exactly_the_occupied_tag_matching_pairs() {
        let buckets = [Bucket::empty()];
        let control = |bucket: &Bucket| bucket.control();
        buckets[0].publish_pair(0, 0, 7, AllocationId::new(SlotIndex(4), 0x1_0002));
        buckets[0].publish_pair(
            5,
            control(&buckets[0]),
            8,
            AllocationId::new(SlotIndex(5), 1),
        );
        // The same filter bits as the tag, another tag.
        buckets[0].publish_pair(
            9,
            control(&buckets[0]),
            7 | 16,
            AllocationId::new(SlotIndex(9), 1),
        );
        buckets[0].publish_pair(
            13,
            control(&buckets[0]),
            7,
            AllocationId::new(SlotIndex(6), 3),
        );
        let mut scratch = [blank(); PAIRS];
        let mut work = ScanWork::default();
        assert_eq!(
            scan_chain(&buckets, 1, 0, 0, 7, &mut scratch, &mut work),
            Ok(2)
        );
        assert_eq!(
            scratch[..2],
            [
                Identity {
                    tag: 7,
                    incarnation_low: 2,
                    slot: 4
                },
                Identity {
                    tag: 7,
                    incarnation_low: 3,
                    slot: 6
                },
            ]
        );
        assert_eq!(work.comparisons, 4);
        buckets[0].clear_pair(13, control(&buckets[0]));
        assert_eq!(
            scan_chain(&buckets, 1, 0, 0, 7, &mut scratch, &mut work),
            Ok(1)
        );
    }

    /// The identities a chain scan over `buckets`' first base bucket and
    /// its one overflow bucket returns for `tag`, checked never to include
    /// a pending pair: the pending identity is `pending`, planted in the
    /// overflow bucket behind a base bucket that holds a visible pair of the
    /// same tag.
    fn assert_no_pending(scan: impl Fn(&[Bucket], u16, &mut [Identity], &mut ScanWork) -> usize) {
        let buckets = [Bucket::empty(), Bucket::empty()];
        let visible = AllocationId::new(SlotIndex(4), 2);
        let pending = AllocationId::new(SlotIndex(8), 5);
        buckets[0].publish_pair(0, 0, 0x1F, visible);
        buckets[0].link(OverflowLink::encode(0).unwrap());
        assert!(buckets[1].reserve_pair(3, 0x1F, pending));
        let mut scratch = [blank(); 2 * PAIRS];
        let mut work = ScanWork::default();
        let copied = scan(&buckets, 0x1F, &mut scratch, &mut work);
        // The scan reached the overflow bucket that holds the pending pair.
        assert_eq!(work.visits, 2);
        assert!(
            !scratch[..copied].contains(&Identity::new(0x1F, pending)),
            "a lookup returned a pending pair"
        );
        assert_eq!(scratch[..copied], [Identity::new(0x1F, visible)]);
    }

    /// The chain scan, and so every lookup, skips a pending pair whose tag
    /// matches, in a linked overflow bucket whose only other lanes are
    /// free.
    #[test]
    fn the_scan_never_returns_a_pending_pair() {
        assert_no_pending(|buckets, tag, scratch, work| {
            scan_chain(buckets, 1, 0, 1, tag, scratch, work).unwrap()
        });
    }

    /// The planted control: a scan that selects lanes by their filter bits
    /// alone, ignoring occupancy, accepts the pending pair, and the check
    /// rejects it.
    #[test]
    #[should_panic(expected = "a lookup returned a pending pair")]
    fn negative_control_a_scan_that_ignores_occupancy_returns_a_pending_pair() {
        assert_no_pending(|buckets, tag, scratch, work| {
            let mut copied = 0;
            for bucket in buckets {
                work.visits += 1;
                let control = bucket.control();
                for pair in 0..PAIRS {
                    let filter = (control >> (pair as u32 * 4 + 1)) & 0b111;
                    let identity = bucket.identity(pair);
                    if filter == u64::from(tag & 0b111) && identity.tag == tag {
                        scratch[copied] = identity;
                        copied += 1;
                    }
                }
            }
            copied
        });
    }

    struct Recorded<'b> {
        bucket: &'b Bucket,
        loaded: std::cell::Cell<u64>,
    }

    impl BucketView for Recorded<'_> {
        fn control(&self) -> u64 {
            self.bucket.control()
        }

        fn next(&self) -> usize {
            self.bucket.next()
        }

        fn identity(&self, pair: usize) -> Identity {
            self.loaded.set(self.loaded.get() | 1 << pair);
            self.bucket.identity(pair)
        }
    }

    /// The words loaded are exactly those of the occupied pairs whose
    /// filter bits equal the tag's: an unoccupied pair, and an occupied pair
    /// with other filter bits, are never loaded; an occupied pair with the
    /// filter bits but another tag is loaded and not copied.
    #[test]
    fn the_scan_loads_only_the_occupied_pairs_whose_filter_matches() {
        let empty = Bucket::empty();
        let sparse = Bucket::empty();
        sparse.publish_pair(0, 0, 7, AllocationId::new(SlotIndex(1), 1));
        sparse.publish_pair(9, sparse.control(), 8, AllocationId::new(SlotIndex(2), 1));
        sparse.publish_pair(
            11,
            sparse.control(),
            7 | 8,
            AllocationId::new(SlotIndex(3), 1),
        );
        for (bucket, loaded, occupied, copied) in [
            (&empty, 0, 0, 0),
            (&sparse, 1 << 0 | 1 << 11, 1 << 0 | 1 << 9 | 1 << 11, 1),
        ] {
            let buckets = [Recorded {
                bucket,
                loaded: std::cell::Cell::new(0),
            }];
            let mut scratch = [blank(); PAIRS];
            let mut work = ScanWork::default();
            assert_eq!(
                scan_chain(&buckets, 1, 0, 0, 7, &mut scratch, &mut work),
                Ok(copied)
            );
            assert_eq!(buckets[0].loaded.get(), loaded);
            assert_eq!(work.comparisons, (occupied as u64).count_ones() as usize);
        }
    }

    /// A scan that fails on a malformed second bucket still reports the
    /// visit and the comparisons it made before, for the caller to debit.
    #[test]
    fn a_failed_scan_reports_the_work_it_did() {
        let buckets = [Bucket::empty(), Bucket::empty()];
        buckets[0].publish_pair(0, 0, 7, AllocationId::new(SlotIndex(0), 1));
        buckets[0].link(OverflowLink::encode(0).unwrap());
        // A reserved control bit on the linked bucket.
        buckets[1].publish_pair(0, 1 << 60, 7, AllocationId::new(SlotIndex(1), 1));
        assert_eq!(buckets[1].control() & !CONTROL_MASK, 1 << 60);
        let mut scratch = [blank(); PAIRS];
        let mut work = ScanWork::default();
        assert_eq!(
            scan_chain(&buckets, 1, 0, 1, 7, &mut scratch, &mut work),
            Err(Corrupt)
        );
        assert_eq!(
            work,
            ScanWork {
                visits: 2,
                comparisons: 1
            }
        );
    }
}
