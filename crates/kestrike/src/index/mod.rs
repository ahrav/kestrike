//! Foundations of the bounded concurrent index: checked geometry, chained
//! fourteen-pair buckets with their publication stores, keyed full-key hashing,
//! the shard sequence protocol and the reader's chain scan. No array lives
//! here; the storage layer places the arrays, holds the shard gate and
//! drives the sequence through these primitives.
//!
//! Invariants owned by this module:
//!
//! - A [`ValidatedIndex`] exists only for a configuration that passed every
//!   check in [`IndexConfig::validate`]: `0 < a < b`, a positive overflow
//!   denominator, `sum N[s]` at most the volume's slot count `O`, and every
//!   per-shard product, sum,
//!   array and scratch layout representable. No numeric limit has a default.
//!   Load factor and geometry bound the work per key; they do not promise
//!   collision-free admission.
//! - A bucket is 128 bytes at alignment 64 with its control word, link and
//!   fourteen one-word pairs at fixed offsets, asserted at compile time and
//!   checkable at run time through [`verify_layout`]. The control word holds
//!   one four-bit lane per pair, its occupancy bit and the low three bits of
//!   its tag, so a reader selects the pairs that can carry a tag from the
//!   control word alone and loads only their words. A lane with its occupancy
//!   bit clear and every filter bit set holds a pending pair: readers, scans
//!   and removal walks select occupied lanes only, placement skips the pending
//!   lane, and it keeps its bucket linked. Every shared field is an initialized
//!   atomic for the index's whole life; production writes to a bucket go
//!   through its crate-private store methods (pair publication, link, pair
//!   clear, and a pending pair's reservation, activation and cancel) and reads
//!   through the scan's bucket view, so a bucket's store order and every load
//!   strength live in this module. A test-only seam plants raw control and link
//!   words.
//! - A key's chain starts at its base bucket and follows at most `D`
//!   overflow links: a scan visits at most `1 + D` buckets, compares at most
//!   `14 (1 + D)` lanes and copies at most `14 (1 + D)` identities; nothing
//!   is rehashed, moved or swept.
//! - Each base bucket has a 64-bit chain summary in a dense array beside
//!   the buckets, holding two tag-selected bits for every occupied pair of
//!   its chain: an insert stores the exact union inside its bracket, with
//!   the same `Relaxed` store behind the bracket's fence as a pair, and a
//!   removal leaves a superset, so a tag the summary excludes is absent from
//!   the chain and a reader, loading the word `SeqCst` under its sequence
//!   check as it loads a bucket field, proves that absence from the summary
//!   word alone. The summary's bit selection lives here; its store is the
//!   insert commit's and its load the snapshot's, in the storage layer.
//! - A [`KeyHasher`] holds the initial SipHash state of one key pair drawn
//!   at initialization and derives route, bucket, tag and fingerprint from
//!   one 32-byte SipHash-1-3 pass for a fixed [`HASH_CHARGE`]: the
//!   fingerprint is the whole word, the bucket its low bits under `B - 1`,
//!   the tag the 16 bits above those, and the route a reduction of its low
//!   57 bits, so the high seven bits never enter the route; routing is
//!   bounded to enabled shards but not unbiased, and no derivation
//!   allocates. A multi-key pass derives up to eight keys' words together,
//!   each the word that key's own pass gives. The storage layer identifies
//!   an object in RAM by its key's fingerprint, and equal fingerprints
//!   share one bucket, tag and chain.
//!
//! The bucket's size, 128 bytes and fourteen pairs, is set by index bytes
//! per visible key under churn at the configured load.

#[cfg(test)]
mod activation_order_tests;
mod bucket;
#[cfg(kani)]
mod bucket_kani;
mod geometry;
mod hash;
mod lanes;
mod scan;
#[cfg(all(test, loom))]
mod scan_model;
mod sequence;
mod summary;

pub use bucket::{
    BucketLayout, BucketLayoutMismatch, CONTROL_MASK, FILTER_MASK, Identity, LANE_BITS,
    OCCUPANCY_MASK, OverflowLink, PAIRS, UnencodableLink, verify_layout,
};
pub use geometry::{
    EnabledShard, GeometryError, IndexConfig, IndexInventory, Ratio, SHARD_CONTROL_ALIGN,
    SHARD_CONTROL_BYTES, ShardGeometry, ShardIndex, ShardLimits, ValidatedIndex,
};
pub(crate) use hash::{BucketRun, Prefetch, reduce};
pub use hash::{HASH_CHARGE, HASH_STATE_BYTES, Key, KeyHasher, KeyRoute, RouteError};
pub(crate) use lanes::LANES;

pub(crate) use sequence::TERMINAL;
pub use summary::SUMMARY_BITS;
pub(crate) use summary::{excludes, summary_bits};

#[cfg(test)]
pub(crate) use bucket::is_pending;
pub(crate) use bucket::{
    Bucket, candidate_lanes, control_without, first_free, held_pairs, is_occupied, lane_pairs,
    occupied, occupied_pairs,
};
#[cfg(test)]
pub(crate) use hash::{DERIVATIONS, Seam};
#[cfg(test)]
pub(crate) use lanes::{Lanes, SCALAR_PASSES, VECTOR_PASSES};
pub(crate) use scan::{BucketView, Corrupt, ScanWork, scan_chain};
pub(crate) use sequence::{Busy, SeqWord, Unstable, read_stable, still, terminate, would_exhaust};
