//! The store-class contract: the record keys and versions, the conditional writes a class offers, its replies,
//! and the [`Store`] trait each class implements.
//!
//! A class gives linearizable reads and conditional writes on one record, every commit raising the record's
//! version by one, and one reply per request that is a commit, a documented "not committed" refusal, or unknown.
//! Every write is a create or an exact-version compare-and-swap of a whole value, so the client knows the value
//! each of its commits holds.

use core::num::NonZeroU64;

use crate::failover::loss::RECEIPT_LEN;
use crate::failover::records::{Namespace, SHARD_MAX, VOLUME_MAX, VolumeId};
use crate::failover::standbys::{CENSUS_MAX, Zone};
use crate::net::ownership::Shard;

/// A store record's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    Shard(Shard),
    Volume(VolumeId),
    /// Coverage page `i` of the shard, `i < B`.
    Page(Shard, u16),
    /// The standby census of the AZ.
    Standbys(Zone),
    /// The replacement receipt of the shard.
    Replacement(Shard),
}

/// A record version. The first commit of a record writes version 1 and every later commit raises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version(NonZeroU64);

impl Version {
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// The version the next commit writes, or `None` at `u64::MAX`.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// A record's encoded value at a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub version: Version,
    pub value: Vec<u8>,
}

/// One conditional write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// Commits `value` at [`Version::FIRST`] only when the record is absent.
    Create(Vec<u8>),
    /// Commits `value` at `expect + 1` only when the record is at `expect`.
    Exact { expect: Version, value: Vec<u8> },
}

/// A store reply to a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The write committed at this version.
    Committed(Version),
    /// The class documents that the write did not commit.
    NotCommitted(Refusal),
    /// The write may or may not have committed: a timeout, a failure that may commit, or a lost reply.
    Unknown,
}

/// The largest record value a store class accepts, 400 KiB. The simulated and soak stores accept a value of this
/// size; a class that stores the value beside other attributes in one item accepts a value smaller by their size.
pub const ITEM_LIMIT: usize = 400 * 1024;

// The codec lengths stand in for the class's item size; the store qualification measures the production item's
// stored form against this limit.
const _: () = assert!(
    SHARD_MAX <= ITEM_LIMIT
        && VOLUME_MAX <= ITEM_LIMIT
        && CENSUS_MAX <= ITEM_LIMIT
        && RECEIPT_LEN <= ITEM_LIMIT
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The condition did not hold.
    Condition,
    /// The class rejected the request, for example a value over its size limit.
    Rejected,
    /// The principal may not make the write.
    Denied,
}

/// The read returned no value: the store is unreachable, the read timed out, or the class returned an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

/// A store class. Each call issues at most one request and makes no retry, because a retry reports a condition failure
/// when the first conditional write committed.
pub trait Store {
    /// A linearizable read: the record's value at one point between the call and its return, reflecting every
    /// commit acknowledged before the call, or `None` when the record is absent at that point. A write that overlaps
    /// the call may be missing from the result.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when the class returns no value.
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable>;

    fn write(&mut self, key: &Key, write: &Write) -> Outcome;

    /// The identity of this store instance. The production class returns the identity of the table instance its
    /// exchange read when it was built: one value for the life of one table instance and a different value for every
    /// other instance, a restored or repointed table included. The holder of a production store rebuilds the store
    /// when the table name refers to a different instance. The soak store reports one class-wide value and relies on
    /// its state-directory lock and watermark. The client writes the store's namespace into each shard record and
    /// withdraws when a shard record names a different namespace.
    fn namespace(&self) -> Namespace;
}
