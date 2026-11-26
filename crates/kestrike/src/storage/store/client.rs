//! The store client: exact-version writes on read values, adoption only from acknowledged commits, and the durable
//! watermark every result is checked against.
//!
//! - EXACT-VERSION: [`Client::replace`], [`Client::flip`], [`Client::bump`], [`Client::take_over`],
//!   [`Client::transfer`], [`Client::designate`] and [`Client::retire`] submit [`Write::Exact`] expecting the version
//!   their [`Read`] holds, with the whole next value; the flip, the bump, the takeover, the transfer, the designation
//!   and the retirement compute it from the read value. A successor that breaks [`Record::succeeds`] returns [`StoreError::Successor`] before the client
//!   issues a request.
//! - ACKNOWLEDGED-ADOPTION: the client adopts a value, and creates a witness such as [`Bumped`] or [`Transferred`],
//!   only from its own acknowledged successful write. Only [`Bumped`] activates a session.
//! - WATERMARK: a [`Regression`] withdraws the client, and so does a failed record of the raised watermark or a
//!   batch that unwinds before it records the marks its elements raised.
//! - SERIAL-ISSUE: a request whose outcome is unknown may still commit after the client issues the next request.
//! - NAMESPACE: a shard record that names another store instance than [`Store::namespace`] withdraws the client. A
//!   read checks the decoded value before the watermark observes it; a create or exact-version write checks the value
//!   it would write before issuing any request; a replacement receipt, which names its replacement's namespace, is
//!   checked the same way. Volume records, coverage pages and the standby census carry no namespace, so a client
//!   checks them against the store instance only through the shard records it reads.
//! - MONITORS-OBSERVE: the client counts the outcome of each store request that returns [`StoreError::Unknown`],
//!   [`StoreError::Unavailable`] or [`StoreError::Refused`], and each result that its failed watermark log write
//!   turned into [`StoreError::Log`], once, under the record class of the key, in a [`Tally`]. A request counts
//!   whatever the call that issued it returns: a page create that [`Client::create_shard`] finds refused on an empty
//!   page counts as refused though the call continues. The client keeps the first cause that withdrew it as an
//!   [`Alarm`], which reads [`Alarm::Clear`] exactly while the client is admitted. [`Client::outcomes`] and
//!   [`Client::alarm`] return copies through a shared borrow, and only the client changes either value. Admission
//!   reads only whether the alarm is clear; the tally and the cause the alarm holds are report inputs alone.

use std::collections::BTreeSet;
use std::io;
use std::panic::{self, AssertUnwindSafe};

use super::watermark::{Regression, Watermark, WatermarkLog};
use super::{Item, Key, Outcome, Refusal, Store, Version, Write};
use crate::failover::flip::{
    FlipRefusal, TenureRefusal, bumped, designated, flipped, taken_over, transferred,
};
use crate::failover::loss::Receipt;
use crate::failover::reconcile::StandbyGate;
use crate::failover::records::{
    CodecError, CoveragePage, Host, Namespace, Record, ShardRecord, SuccessorRule, VolumeRecord,
};
use crate::failover::retire::{Admitted, Retirement, Stale, Target};
use crate::failover::standbys::Census;
use crate::net::ownership::{Shard, ShardGeneration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The read returned no value: the store was unreachable, the read timed out, or the class returned an error.
    Unavailable,
    /// The class reported that the write did not commit.
    Refused(Refusal),
    /// The write's outcome is unknown; nothing was adopted.
    Unknown,
    /// The store holds no record under the key, and the watermark holds no mark for it.
    Absent,
    /// The stored bytes, or the encoding of a value to write, did not decode as a record of the key.
    Codec(CodecError),
    /// The successor value breaks the record's successor rule, [`Record::succeeds`]; no request was made.
    Successor(SuccessorRule),
    /// The read value admits no flip; no request was made.
    Flip(FlipRefusal),
    /// The client returns `Stale` before issuing a request if any condition holds:
    /// - Retirement admission rejects the read.
    /// - Admission accepts a `Client::retire` request for the active volume.
    /// - A takeover reads another target, no standby or another standby than its successor, or `E = 0`.
    /// - A designation reads another target, `E = 0`, or its standby as owner.
    /// - A planned transfer reads another shard or `(g, owner, E)` than its outgoing tenure, `E = 0`, no standby or
    ///   another standby than its target, its target as owner, or no named checkpoint.
    Stale(Stale),
    /// `E` is [`ATTEMPTS_MAX`](crate::failover::records::ATTEMPTS_MAX); the shard admits no further attempt at this
    /// generation. A planned transfer also refuses at `E = ATTEMPTS_MAX - 1`, where a bump still fits: it needs room
    /// for its own attempt and the target's restart bump.
    AttemptsExhausted,
    /// A result failed the watermark check. The client is withdrawn, and [`Client::alarm`] keeps the first withdrawal
    /// cause.
    Regression(Regression),
    /// An earlier cause withdrew the client, and the client refuses each call before contacting the store.
    /// [`Client::alarm`] names the first withdrawal cause.
    Withdrawn,
    /// The shard record or replacement receipt names another store instance than the store's; the client is
    /// withdrawn.
    Namespace,
    /// The log failed to record the raised watermark, and the client is withdrawn. On a write the store may hold
    /// the written value, and the call returns no value or witness.
    Log,
}

impl From<TenureRefusal> for StoreError {
    /// A tenure writer's refusal as the error its store call returns before any request.
    fn from(refusal: TenureRefusal) -> Self {
        match refusal {
            TenureRefusal::AttemptsExhausted => Self::AttemptsExhausted,
            TenureRefusal::Target => Self::Stale(Stale::Target),
        }
    }
}

/// Defines one axis of a [`Tally`]: a closed enum and its `ALL` table, which lists every variant in declaration
/// order, so each variant's discriminant is its index in the table and in the tally.
macro_rules! axis {
    ($(#[$meta:meta])* $name:ident, [$($(#[$doc:meta])* $variant:ident),+ $(,)?]) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$doc])* $variant,)+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: [$name; [$($name::$variant),+].len()] = [$($name::$variant),+];
        }
    };
}

axis! {
    /// The record class of a store key: one per [`Key`] variant.
    RecordClass, [
        /// [`Key::Shard`].
        Shard,
        /// [`Key::Volume`].
        Volume,
        /// [`Key::Page`].
        Page,
        /// [`Key::Standbys`], the standby census.
        Census,
        /// [`Key::Replacement`], the replacement receipt.
        Receipt,
    ]
}

axis! {
    /// A store outcome the client tallies: a request whose outcome is unknown, a read that returned no value, a
    /// write the store reported not committed, and a result its failed watermark log write turned into `Log`.
    Tallied, [Unknown, Unavailable, Refused, Log]
}

impl RecordClass {
    pub fn of(key: &Key) -> Self {
        match key {
            Key::Shard(_) => Self::Shard,
            Key::Volume(_) => Self::Volume,
            Key::Page(..) => Self::Page,
            Key::Standbys(_) => Self::Census,
            Key::Replacement(_) => Self::Receipt,
        }
    }
}

/// The client's tallied outcomes since it opened, by record class and outcome. Each count only rises, saturating at
/// `u64::MAX`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally([[u64; Tallied::ALL.len()]; RecordClass::ALL.len()]);

impl Tally {
    /// The count of `outcome` under `class`.
    pub fn get(&self, class: RecordClass, outcome: Tallied) -> u64 {
        self.0[class as usize][outcome as usize]
    }

    /// The count of `outcome` summed over every record class, saturating at `u64::MAX`.
    pub fn total(&self, outcome: Tallied) -> u64 {
        RecordClass::ALL.iter().fold(0, |sum: u64, &class| {
            sum.saturating_add(self.get(class, outcome))
        })
    }

    /// The counts this tally gained over `earlier`, a tally the same client returned before it, cell by cell; a
    /// cell that saturated reads its gain up to the saturation.
    pub fn since(&self, earlier: &Self) -> Self {
        let mut gained = *self;
        for (cells, before) in gained.0.iter_mut().zip(&earlier.0) {
            for (count, before) in cells.iter_mut().zip(before) {
                *count = count.saturating_sub(*before);
            }
        }
        gained
    }

    fn add(&mut self, key: &Key, outcome: Tallied) {
        let count = &mut self.0[RecordClass::of(key) as usize][outcome as usize];
        *count = count.saturating_add(1);
    }
}

/// The store client's watermark alarm: the first cause that withdrew the client, or `Clear` while it is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alarm {
    Clear,
    /// A [`Regression::Value`]: a record's version or value fell below or reused its mark, a record whose mark is
    /// held was absent or failed to decode at or below the marked version, or a create or exact-version write
    /// committed at a version other than the one it names.
    Regression,
    /// A [`Regression::Checkpoint`]: at the adopted checkpoint's generation, a shard record named no checkpoint, an
    /// older one, or another one with the adopted checkpoint's `(session, capture)`.
    Checkpoint,
    /// The log failed to record a raised watermark, or a batch unwound.
    Log,
    /// A shard record or replacement receipt named another store instance than the store's.
    Namespace,
}

/// A record value at a version: one the client read, or one its own acknowledged create or exact-version write
/// committed.
/// Only the client makes one, so every exact-version write the client issues conditions on a value it knows was
/// current at that version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read<R> {
    key: Key,
    version: Version,
    value: R,
}

impl<R> Read<R> {
    pub fn version(&self) -> Version {
        self.version
    }

    pub fn value(&self) -> &R {
        &self.value
    }

    pub fn into_value(self) -> R {
        self.value
    }
}

/// The acknowledged success of the client's own flip: the record of `shard` holds `generation` with `E = 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flipped {
    shard: Shard,
    generation: ShardGeneration,
}

impl Flipped {
    pub fn shard(&self) -> Shard {
        self.shard
    }

    pub fn generation(&self) -> ShardGeneration {
        self.generation
    }
}

/// The acknowledged success of the client's own `E` bump of `shard` from `attempt` to `attempt + 1` at
/// `generation`, on a record naming `owner` after the write: the same owner for [`Client::bump`], the standby for
/// [`Client::take_over`]. Only those two make one, each from an acknowledged commit, and an attempt
/// adopts `n` only from this value.
#[derive(Debug, PartialEq, Eq)]
pub struct Bumped {
    committed: Read<ShardRecord>,
}

impl Bumped {
    pub fn shard(&self) -> Shard {
        self.committed.value.shard
    }

    pub fn generation(&self) -> ShardGeneration {
        self.committed.value.generation
    }

    pub fn owner(&self) -> Host {
        self.committed.value.owner
    }

    /// `n`, the value of `E` the bump conditioned on: the committed record holds `n + 1`.
    pub fn attempt(&self) -> u32 {
        self.committed.value.attempts - 1
    }

    /// The shard record at the version the bump committed.
    pub fn committed(&self) -> &Read<ShardRecord> {
        &self.committed
    }
}

/// `Outgoing` identifies the activated session's tenure for a planned transfer.
#[derive(Debug, PartialEq, Eq)]
pub struct Outgoing {
    shard: Shard,
    own: Target,
}

impl Outgoing {
    /// The tenure `session` activated: its shard and `(g, owner, E)`. The value proves no withdrawal and no certify.
    pub fn of(session: &crate::storage::Session) -> Self {
        Self {
            shard: session.shard(),
            own: session.target(),
        }
    }
}

/// `Transferred` confirms that the client's planned transfer committed. A session activates only from [`Bumped`]:
///
/// ```compile_fail,E0308
/// fn activate(transferred: kestrike::storage::store::Transferred) {
///     let _ = kestrike::storage::Session::activate(transferred);
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Transferred {
    committed: Read<ShardRecord>,
}

impl Transferred {
    /// The shard record at the version the transfer committed.
    pub fn committed(&self) -> &Read<ShardRecord> {
        &self.committed
    }
}

mod sealed {
    use crate::failover::records::{CoveragePage, ShardRecord, VolumeRecord};

    /// The record kinds this module implements [`super::Tracked`] for.
    pub trait Sealed {}

    impl Sealed for ShardRecord {}
    impl Sealed for CoveragePage {}
    impl Sealed for VolumeRecord {}
    impl Sealed for super::Census {}
    impl Sealed for super::Receipt {}
}

/// A record kind the client reads and writes: the key it must name, its codec at the store boundary and the
/// watermark entry its results check. This module implements it for the shard record, the coverage page, the
/// volume record, the standby census and the replacement receipt, and no other.
pub trait Tracked: Record + sealed::Sealed {
    fn names(&self, key: &Key) -> bool;

    /// `self`'s encoding for a write under `key`, refused unless it decodes back as a record of `key`.
    fn encoded(&self, key: &Key) -> Result<Vec<u8>, CodecError> {
        let bytes = self.encode();
        match &Self::decode(&bytes) {
            Ok(decoded) if decoded.names(key) => Ok(bytes),
            Ok(_) => Err(CodecError::Field),
            Err(error) => Err(*error),
        }
    }

    /// LENT-ENCODING: the bytes [`Tracked::encoded`] returns, for one store write. A record kind that holds its
    /// encoding lends those bytes for one store write; [`Tracked::restore`] returns them to the record.
    fn lend(&mut self, key: &Key) -> Result<Vec<u8>, CodecError> {
        self.encoded(key)
    }

    /// Takes back the bytes [`Tracked::lend`] handed over.
    fn restore(&mut self, _bytes: Vec<u8>) {}

    /// The store instance the value names; a record kind that names none returns `None`.
    fn namespace(&self) -> Option<Namespace> {
        None
    }

    /// Decodes a value the store returned, taking ownership of its bytes.
    fn decoded(bytes: Vec<u8>) -> Result<Self, CodecError> {
        Self::decode(&bytes)
    }

    /// Checks the value read or committed at `version` under `key` and raises the watermark to it, returning
    /// whether the watermark changed; a record kind without a watermark entry returns `Ok(false)`. A regression
    /// returns before the watermark changes.
    fn observe(
        &self,
        _key: Key,
        _version: Version,
        _mark: &mut Watermark,
    ) -> Result<bool, Regression> {
        Ok(false)
    }

    /// Records in the watermark what the client adopts from its own acknowledged write of `self`.
    fn adopt(&self, _mark: &mut Watermark) {}
}

impl Tracked for ShardRecord {
    fn names(&self, key: &Key) -> bool {
        *key == Key::Shard(self.shard)
    }

    fn namespace(&self) -> Option<Namespace> {
        Some(self.namespace)
    }

    fn observe(
        &self,
        key: Key,
        version: Version,
        mark: &mut Watermark,
    ) -> Result<bool, Regression> {
        mark.check_checkpoint(self)?;
        mark.observe(key, (version, (self.generation.get(), self.attempts)))
    }

    fn adopt(&self, mark: &mut Watermark) {
        mark.adopt_checkpoint(self);
    }
}

impl Tracked for CoveragePage {
    fn names(&self, key: &Key) -> bool {
        matches!(key, Key::Page(..))
    }

    /// A page decodes back exactly when its entry count fits the encoding's `u32` length field, so the client
    /// encodes a page that names `key` once.
    fn encoded(&self, key: &Key) -> Result<Vec<u8>, CodecError> {
        u32::try_from(self.entries.len()).map_err(|_| CodecError::Length)?;
        self.names(key)
            .then(|| self.encode())
            .ok_or(CodecError::Field)
    }

    /// Decodes the page in place, reusing the store's buffer for its entries.
    fn decoded(bytes: Vec<u8>) -> Result<Self, CodecError> {
        Self::decode_owned(bytes)
    }

    fn observe(
        &self,
        key: Key,
        version: Version,
        mark: &mut Watermark,
    ) -> Result<bool, Regression> {
        mark.observe(key, (version, (self.fence, 0)))
    }
}

impl Tracked for VolumeRecord {
    fn names(&self, key: &Key) -> bool {
        matches!(key, Key::Volume(volume) if *volume == self.volume)
    }
}

impl Tracked for Census {
    fn names(&self, key: &Key) -> bool {
        *key == Key::Standbys(self.zone())
    }

    fn lend(&mut self, key: &Key) -> Result<Vec<u8>, CodecError> {
        let named = self.names(key);
        let bytes = Census::lend(self)?;
        if named {
            return Ok(bytes);
        }
        Census::restore(self, bytes);
        Err(CodecError::Field)
    }

    fn restore(&mut self, bytes: Vec<u8>) {
        Census::restore(self, bytes);
    }

    fn decoded(bytes: Vec<u8>) -> Result<Self, CodecError> {
        Self::decode_owned(bytes)
    }
}

impl Tracked for Receipt {
    fn names(&self, key: &Key) -> bool {
        *key == Key::Replacement(self.request.shard)
    }

    fn namespace(&self) -> Option<Namespace> {
        Some(self.request.namespace)
    }
}

/// The one store client. It makes one store call at a time and adopts a value only from its own acknowledged
/// write. Whenever a call returns while the client is not withdrawn, the watermark it checks results against equals
/// the one its log holds.
///
/// Callers outside the crate flip generations through the gated `Reconciler::flip` and `Reconciler::flip_for`
/// methods. `Client::flip` and `Client::retire` are crate-private:
///
/// ```compile_fail,E0624
/// use kestrike::storage::store::{Client, Store, WatermarkLog};
/// fn named<S: Store, L: WatermarkLog>() {
///     let _ = Client::<S, L>::flip;
/// }
/// ```
///
/// ```compile_fail,E0624
/// use kestrike::storage::store::{Client, Store, WatermarkLog};
/// fn named<S: Store, L: WatermarkLog>() {
///     let _ = Client::<S, L>::retire;
/// }
/// ```
///
/// Callers outside the crate can name `Client::bump`:
///
/// ```
/// use kestrike::storage::store::{Client, Store, WatermarkLog};
/// fn named<S: Store, L: WatermarkLog>() {
///     let _ = Client::<S, L>::bump;
/// }
/// ```
pub struct Client<S, L> {
    store: S,
    log: L,
    mark: Watermark,
    /// The first cause that withdrew the client; the client is admitted exactly while it reads [`Alarm::Clear`].
    alarm: Alarm,
    tally: Tally,
}

impl<S: Store, L: WatermarkLog> Client<S, L> {
    /// A client over `store` whose results are checked against the watermark `log` holds. A host records
    /// [`Watermark::default`] to its log before its first open, and only then. The client takes the watermark from
    /// [`WatermarkLog::reload`], which makes it durable before the client issues a request, so a record whose
    /// directory sync was unconfirmed, or a raise whose sync did not return, is durable.
    ///
    /// # Errors
    ///
    /// The log's reload error; a log that holds no watermark reports `NotFound`.
    pub fn open(store: S, mut log: L) -> io::Result<Self> {
        let mark = log.reload()?;
        Ok(Self {
            store,
            log,
            mark,
            alarm: Alarm::Clear,
            tally: Tally::default(),
        })
    }

    /// Whether a regression, a namespace mismatch or a log failure withdrew the client, which then refuses every
    /// request with [`StoreError::Withdrawn`].
    pub fn withdrawn(&self) -> bool {
        self.alarm != Alarm::Clear
    }

    #[cfg(test)]
    pub fn watermark(&self) -> &Watermark {
        &self.mark
    }

    /// The outcomes the client tallied since it opened (MONITORS-OBSERVE).
    pub fn outcomes(&self) -> Tally {
        self.tally
    }

    /// The first cause that withdrew the client, [`Alarm::Clear`] while it is admitted (MONITORS-OBSERVE).
    pub fn alarm(&self) -> Alarm {
        self.alarm
    }

    /// Reads `key`, checks the value against the watermark and raises it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Regression`] withdraws the client, including for an absent record the watermark holds and for
    /// bytes at or below the watermark's version that do not decode as a record of `key`. Such bytes above that
    /// version, or for a key without a mark, return [`StoreError::Codec`].
    /// [`StoreError::Namespace`] withdraws it for a shard record of another store instance, after the read and before
    /// the watermark observes the value.
    pub fn read<R: Tracked>(&mut self, key: Key) -> Result<Read<R>, StoreError> {
        let read = self.read_one(key);
        self.settle_one(read)
    }

    /// Reads each of `keys` in order as [`Client::read`] does, and makes every mark the reads raised durable with one
    /// log write after the last read; the results return after that write completes. Once a result withdraws the
    /// client, every later key returns [`StoreError::Withdrawn`] at the client. A read that unwinds withdraws the
    /// client before the unwind leaves the call.
    ///
    /// # Errors
    ///
    /// Each key's result carries [`Client::read`]'s errors. When the log fails to make the raised marks durable, the
    /// client withdraws and replaces every `Ok` result whose key is among the raised keys with [`StoreError::Log`],
    /// including a read of a repeated key that raised nothing itself.
    pub fn read_all<R: Tracked>(&mut self, keys: &[Key]) -> Vec<Result<Read<R>, StoreError>> {
        let results = self.batch(|client| keys.iter().map(|&key| client.read_one(key)).collect());
        self.settle(results)
    }

    /// # Errors
    ///
    /// The errors of [`Client::read`].
    pub(crate) fn read_census(
        &mut self,
        key: Key,
        memo: &Option<Census>,
    ) -> Result<Read<Census>, StoreError> {
        let read = self.fetch(key, |bytes| Census::decode_like(bytes, memo));
        self.settle_one(read)
    }

    fn read_one<R: Tracked>(&mut self, key: Key) -> Result<(Read<R>, bool), StoreError> {
        self.fetch(key, R::decoded)
    }

    /// Reads `key` as [`Client::read`] does, decoding the store's bytes with `decode`, and returns the read and
    /// whether its mark rose in memory; settling makes the raised mark durable.
    fn fetch<R: Tracked>(
        &mut self,
        key: Key,
        decode: impl FnOnce(Vec<u8>) -> Result<R, CodecError>,
    ) -> Result<(Read<R>, bool), StoreError> {
        self.admit()?;
        let Some(Item { version, value }) = self.read_store(&key)? else {
            self.mark
                .absent(key)
                .map_err(|regression| self.regress(regression))?;
            return Err(StoreError::Absent);
        };
        let decoded = decode(value).and_then(|value| {
            (value.names(&key))
                .then_some(value)
                .ok_or(CodecError::Field)
        });
        let value = match decoded {
            Ok(value) => value,
            // WATERMARK: a decode failure at or below the held version is a regression.
            Err(_) if self.mark.held(&key).is_some_and(|held| version <= held) => {
                return Err(self.regress(Regression::Value(key)));
            }
            Err(error) => return Err(StoreError::Codec(error)),
        };
        self.namespaced(&value)?;
        let raised = value
            .observe(key, version, &mut self.mark)
            .map_err(|regression| self.regress(regression))?;
        Ok((
            Read {
                key,
                version,
                value,
            },
            raised,
        ))
    }

    /// Creates `key` holding `value` when the record is absent, and returns the value the acknowledged create
    /// committed. For a shard record that names a checkpoint, that checkpoint becomes the one adopted at its
    /// generation, the floor [`Regression::Checkpoint`] enforces.
    ///
    /// # Errors
    ///
    /// Before any request: [`StoreError::Withdrawn`] once the client is withdrawn, [`StoreError::Namespace`], which
    /// withdraws the client, for a shard record of another store instance, and [`StoreError::Codec`] when `value`
    /// does not encode as a record of `key`. After the request: the errors of the write and of the watermark check.
    pub fn create<R: Tracked>(&mut self, key: Key, value: R) -> Result<Read<R>, StoreError> {
        self.admit()?;
        self.namespaced(&value)?;
        let bytes = value.encoded(&key).map_err(StoreError::Codec)?;
        let version = self.submit(&key, &Write::Create(bytes))?;
        let created = self.adopt(key, version, value);
        self.settle_one(created)
    }

    /// Creates the shard's `B` empty coverage pages, each by conditional create, and then its shard record. A page
    /// create refused on its condition passes only when the page it finds is empty at [`Version::FIRST`], so a call
    /// that ended with an unknown outcome or a crash can be repeated and a page another writer changed refuses. The
    /// check reads the page through the store directly, outside [`Client::read`], because the client adopts no page
    /// state from it and keeps no watermark mark for a page it creates. It judges the page it finds against a mark
    /// the client already holds for that page, as a read does, and raises no mark.
    ///
    /// # Errors
    ///
    /// [`StoreError::Codec`] or [`StoreError::Namespace`] before any request when `record` does not encode as a shard
    /// record or names another store instance;
    /// [`StoreError::Refused`] with [`Refusal::Condition`] for a page that exists with another value or version;
    /// [`StoreError::Unavailable`] when the read of such a page returns no value;
    /// [`StoreError::Regression`], which withdraws the client, when such a page reads below the mark the client holds
    /// for it, or reads absent while the client holds a mark for it.
    pub fn create_shard(&mut self, record: ShardRecord) -> Result<Read<ShardRecord>, StoreError> {
        self.admit()?;
        self.namespaced(&record)?;
        record
            .encoded(&Key::Shard(record.shard))
            .map_err(StoreError::Codec)?;
        let empty = Write::Create(CoveragePage::default().encode());
        for page in 0..record.pages.get() {
            let key = Key::Page(record.shard, page);
            match self.submit(&key, &empty) {
                Ok(_) => {}
                Err(StoreError::Refused(Refusal::Condition)) => {
                    if !self.unwritten(key)? {
                        return Err(StoreError::Refused(Refusal::Condition));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        self.create(Key::Shard(record.shard), record)
    }

    /// Whether the store holds the page of `key` empty at [`Version::FIRST`]. The page is checked against the
    /// watermark first, without raising it: a regression withdraws the client (WATERMARK). A page that decodes is
    /// checked as a read checks it, an absent page regresses under any mark, and a page that does not decode
    /// regresses at or below the mark's version, since every mark was raised over bytes that decoded.
    fn unwritten(&mut self, key: Key) -> Result<bool, StoreError> {
        let held = self.read_store(&key)?;
        let Some(Item { version, value }) = held else {
            self.mark
                .absent(key)
                .map_err(|regression| self.regress(regression))?;
            return Ok(false);
        };
        let Ok(page) = CoveragePage::decoded(value) else {
            let regressed = self.mark.held(&key).is_some_and(|held| version <= held);
            if regressed {
                return Err(self.regress(Regression::Value(key)));
            }
            return Ok(false);
        };
        self.mark
            .check(key, (version, (page.fence, 0)))
            .map_err(|regression| self.regress(regression))?;
        Ok(version == Version::FIRST && page == CoveragePage::default())
    }

    /// Writes `next` over `read` by an exact-version compare-and-swap on `read`'s version, after the caller checked
    /// its predicate over `read`'s value, and returns the value the acknowledged write committed. For a shard record,
    /// once the committed value passes the watermark check, the checkpoint `next` names becomes the one adopted at
    /// its generation, the floor [`Regression::Checkpoint`] enforces.
    ///
    /// # Errors
    ///
    /// Before any request: [`StoreError::Withdrawn`] once the client is withdrawn, [`StoreError::Successor`] when
    /// `next` breaks [`Record::succeeds`] against `read`, [`StoreError::Namespace`], which withdraws the client, when
    /// `next` is a shard record of another store instance, and [`StoreError::Codec`] when `next` does not encode. After
    /// the request: [`StoreError::Refused`] when the store refused the write, [`StoreError::Unknown`] when its outcome
    /// is unknown, and [`StoreError::Regression`] or [`StoreError::Log`] after the store committed it.
    pub fn replace<R: Tracked>(&mut self, read: &Read<R>, next: R) -> Result<Read<R>, StoreError> {
        let written = self.replace_one(read, next);
        self.settle_one(written)
    }

    /// Writes each `(read, next)` pair in order as [`Client::replace`] does, and makes every mark the acknowledged
    /// writes raised durable with one log write after the last reply; the results return after that write completes.
    /// Once a result withdraws the client, every later pair returns [`StoreError::Withdrawn`] at the client. A step
    /// that unwinds, the iteration of `writes` included, withdraws the client before the unwind leaves the call.
    ///
    /// # Errors
    ///
    /// Each pair's result carries [`Client::replace`]'s errors. When the log fails to make the raised marks durable,
    /// the client withdraws and replaces every `Ok` result whose key is among the raised keys with
    /// [`StoreError::Log`]; the store may hold the written value.
    pub fn replace_all<'r, R: Tracked + 'r>(
        &mut self,
        writes: impl IntoIterator<Item = (&'r Read<R>, R)>,
    ) -> Vec<Result<Read<R>, StoreError>> {
        let results = self.batch(|client| {
            writes
                .into_iter()
                .map(|(read, next)| client.replace_one(read, next))
                .collect()
        });
        self.settle(results)
    }

    /// `replace_one` leaves raised marks in memory for the settle step to persist.
    fn replace_one<R: Tracked>(
        &mut self,
        read: &Read<R>,
        next: R,
    ) -> Result<(Read<R>, bool), StoreError> {
        self.admit()?;
        next.succeeds(&read.value).map_err(StoreError::Successor)?;
        self.exact_one(read, next)
    }

    /// Writes `next` over `read` by an exact-version compare-and-swap on `read`'s version, after the namespace check
    /// (NAMESPACE) and [`Tracked::lend`], and leaves raised marks in memory for the settle step to persist. Every
    /// exact-version write goes through it.
    fn exact_one<R: Tracked>(
        &mut self,
        read: &Read<R>,
        mut next: R,
    ) -> Result<(Read<R>, bool), StoreError> {
        self.namespaced(&next)?;
        let value = next.lend(&read.key).map_err(StoreError::Codec)?;
        let expect = read.version;
        let write = Write::Exact { expect, value };
        let submitted = self.submit(&read.key, &write);
        let (Write::Create(value) | Write::Exact { value, .. }) = write;
        next.restore(value);
        self.adopt(read.key, submitted?, next)
    }

    /// Flips the shard of `read` to its spare: writes [`flipped`]'s record by an exact-version compare-and-swap on
    /// `read`'s version. The caller must first make the spare, hold and receipt checks that `Reconciler::flip` and
    /// `Reconciler::flip_for` make under their gates.
    ///
    /// # Errors
    ///
    /// [`StoreError::Flip`] before any request when `read` names no spare distinct from its active volume or is at
    /// the last generation, and [`StoreError::Namespace`], which withdraws the client, when `read`'s record names
    /// another store instance.
    pub(crate) fn flip(&mut self, read: &Read<ShardRecord>) -> Result<Flipped, StoreError> {
        self.admit()?;
        let next = flipped(&read.value).map_err(StoreError::Flip)?;
        self.shard_write(read, &next)?;
        Ok(Flipped {
            shard: next.shard,
            generation: next.generation,
        })
    }

    /// If [`Retirement::admit`] approves removing the spare from `read`'s value, the client writes the updated value
    /// with a compare-and-swap on `read`'s version.
    ///
    /// # Errors
    ///
    /// If [`Retirement::admit`] rejects `read`'s value, the client returns [`StoreError::Stale`] before sending a
    /// store request. If admission accepts a request for the active volume, the client returns
    /// [`StoreError::Stale`] with [`Stale::Volume`] before sending a store request: `Reconciler::flip_for` handles
    /// that case through [`Client::flip`]. Other errors are those of [`Client::replace`].
    pub(crate) fn retire(
        &mut self,
        read: &Read<ShardRecord>,
        request: &Retirement,
    ) -> Result<Read<ShardRecord>, StoreError> {
        self.admit()?;
        match request.admit(&read.value).map_err(StoreError::Stale)? {
            Admitted::Flip => Err(StoreError::Stale(Stale::Volume)),
            Admitted::DropSpare => self.replace(
                read,
                ShardRecord {
                    spare: None,
                    ..read.value
                },
            ),
        }
    }

    /// Bumps `E` from `n`, the value `read` holds, to `n + 1` at `read`'s generation by an exact-version
    /// compare-and-swap on `read`'s version. The caller verifies that `read`'s value names its host as owner
    /// before calling. `bump` adopts the committed record's checkpoint at the record's generation.
    ///
    /// # Errors
    ///
    /// [`StoreError::AttemptsExhausted`] before any request when `n` is
    /// [`ATTEMPTS_MAX`](crate::failover::records::ATTEMPTS_MAX), and [`StoreError::Namespace`], which withdraws the
    /// client, when `read`'s record names another store instance. `Log` and `Regression` follow a committed write.
    pub fn bump(&mut self, read: &Read<ShardRecord>) -> Result<Bumped, StoreError> {
        self.admit()?;
        let next = bumped(&read.value)?;
        self.consume(read, &next)
    }

    /// The takeover CAS: writes `read`'s record with `successor` as owner, `E` consumed (`n -> n + 1`) and no standby,
    /// by an exact-version compare-and-swap on `read`'s version. Every other field is the read value's, so the
    /// retained volume keeps `g`, its identity, `ck` and the recovery manifest, and the witness names the successor.
    ///
    /// # Errors
    ///
    /// [`StoreError::Stale`] with [`Stale::Target`] before any request when `read` holds another `(g, owner, E)` than
    /// `target`, names no standby or another standby than `successor`, or holds `E = 0`, before
    /// [`StoreError::AttemptsExhausted`]; otherwise the errors of [`Client::bump`].
    pub fn take_over(
        &mut self,
        read: &Read<ShardRecord>,
        target: Target,
        successor: Host,
    ) -> Result<Bumped, StoreError> {
        self.admit()?;
        let next = taken_over(&read.value, target, successor)?;
        self.consume(read, &next)
    }

    /// The planned transfer write: hands the shard to `target`, the standby `read` names, by an exact-version
    /// compare-and-swap on `read`'s version. The committed record names `target` owner at `E + 1` with no standby and
    /// keeps every other field of `read` ([`transferred`]); it activates no session, and the target's own restart bump
    /// opens its tenure.
    ///
    /// The caller owns the planned exit's order, which neither `outgoing`, `_gate` nor the record's checkpoint proves:
    /// `read` is the read the current drain's acknowledged certify committed, over the checkpoint that drain's
    /// acknowledged Publish named, and the caller stopped emitting and withdrew its authority before this call.
    /// `outgoing` names the tenure of an activated session, so a transfer conditions on that tenure only. This method
    /// reads no volume record: the caller reads the volume record of `read`'s active volume after `read` and calls
    /// it only when that record enrolls a pair for `target`'s live attach, as [`Job::Transfer`] does. That read and
    /// this write are two requests, so an attach end that commits between them is not excluded.
    ///
    /// [`Job::Transfer`]: crate::host::lane::Job::Transfer
    ///
    /// # Errors
    ///
    /// Before any request: [`StoreError::Withdrawn`] after an earlier withdrawal, [`StoreError::Stale`] with
    /// [`Stale::Target`] and [`StoreError::AttemptsExhausted`] as [`transferred`] refuses,
    /// [`StoreError::Namespace`], which withdraws the client, when the record names another store instance, and
    /// [`StoreError::Codec`] for a record the codec cannot encode. After the request: [`StoreError::Refused`] for a
    /// write the class reports uncommitted, its condition included; [`StoreError::Unknown`] for a write that may have
    /// committed, which may still commit after the call returns; and [`StoreError::Log`] and
    /// [`StoreError::Regression`], which withdraw the client after the store reported the commit. Only an acknowledged and adopted write returns
    /// [`Transferred`].
    pub fn transfer(
        &mut self,
        _gate: &StandbyGate,
        read: &Read<ShardRecord>,
        outgoing: &Outgoing,
        target: Host,
    ) -> Result<Transferred, StoreError> {
        self.admit()?;
        let next = transferred(&read.value, (outgoing.shard, outgoing.own), target)?;
        let committed = self.shard_write(read, &next)?;
        Ok(Transferred { committed })
    }

    /// The designation write: writes `read`'s record naming `standby` as its standby, by an exact-version
    /// compare-and-swap on `read`'s version. Every other field is the read value's, so the tenure `(g, owner, E)`,
    /// `ck` and the recovery manifest stay, and a takeover CAS conditioned on an earlier version fails its condition.
    ///
    /// # Errors
    ///
    /// [`StoreError::Stale`] with [`Stale::Target`] before any request when `read` holds another `(g, owner, E)`
    /// than `target`, holds `E = 0` or names `standby` as owner; otherwise the errors of [`Client::replace`] after its
    /// request.
    pub(crate) fn designate(
        &mut self,
        read: &Read<ShardRecord>,
        target: Target,
        standby: Host,
    ) -> Result<Read<ShardRecord>, StoreError> {
        self.admit()?;
        let next = designated(&read.value, target, standby)?;
        self.shard_write(read, &next)
    }

    /// Writes `next`, the record [`bumped`] or [`taken_over`] computed from `read`'s value, by an exact-version
    /// compare-and-swap: the shared write of [`Client::bump`] and [`Client::take_over`].
    fn consume(
        &mut self,
        read: &Read<ShardRecord>,
        next: &ShardRecord,
    ) -> Result<Bumped, StoreError> {
        let committed = self.shard_write(read, next)?;
        Ok(Bumped { committed })
    }

    /// Writes the flipped, bumped, taken-over, transferred or designated `next` over `read` and persists its raised
    /// marks. Its callers compute `next` from `read`'s value by the flip, the bump, the takeover, the planned transfer
    /// or the designation, the tenure changes [`Record::succeeds`] refuses, so it skips that check.
    fn shard_write(
        &mut self,
        read: &Read<ShardRecord>,
        next: &ShardRecord,
    ) -> Result<Read<ShardRecord>, StoreError> {
        let written = self.exact_one(read, *next);
        self.settle_one(written)
    }

    fn admit(&self) -> Result<(), StoreError> {
        (self.alarm == Alarm::Clear)
            .then_some(())
            .ok_or(StoreError::Withdrawn)
    }

    /// Withdraws the client when `value` names another store instance than the store's (NAMESPACE).
    fn namespaced<R: Tracked>(&mut self, value: &R) -> Result<(), StoreError> {
        if value
            .namespace()
            .is_some_and(|namespace| namespace != self.store.namespace())
        {
            self.withdraw(Alarm::Namespace);
            return Err(StoreError::Namespace);
        }
        Ok(())
    }

    /// Reads `key` from the store for every client read; a store read error counts as unavailable under the key's
    /// record class.
    fn read_store(&mut self, key: &Key) -> Result<Option<Item>, StoreError> {
        self.store.read(key).map_err(|_| {
            self.tally.add(key, Tallied::Unavailable);
            StoreError::Unavailable
        })
    }

    /// Submits `write` and returns the version it committed. A commit at or below the version the watermark holds
    /// for `key` is a regression: the client observed that version before this request, so the store reused it. A
    /// create commits at [`Version::FIRST`] and an exact-version write at the version after its condition's; a
    /// commit at any other version is a regression.
    fn submit(&mut self, key: &Key, write: &Write) -> Result<Version, StoreError> {
        let version = match self.store.write(key, write) {
            Outcome::Committed(version) => version,
            Outcome::NotCommitted(refusal) => {
                self.tally.add(key, Tallied::Refused);
                return Err(StoreError::Refused(refusal));
            }
            Outcome::Unknown => {
                self.tally.add(key, Tallied::Unknown);
                return Err(StoreError::Unknown);
            }
        };
        let reused = self.mark.held(key).is_some_and(|held| version <= held);
        let expected = match write {
            Write::Create(_) => Some(Version::FIRST),
            Write::Exact { expect, .. } => expect.next(),
        };
        if reused || expected != Some(version) {
            return Err(self.regress(Regression::Value(*key)));
        }
        Ok(version)
    }

    fn regress(&mut self, regression: Regression) -> StoreError {
        self.withdraw(match regression {
            Regression::Value(_) => Alarm::Regression,
            Regression::Checkpoint(_) => Alarm::Checkpoint,
        });
        StoreError::Regression(regression)
    }

    /// Withdraws the client, keeping the first withdrawal cause.
    fn withdraw(&mut self, cause: Alarm) {
        if self.alarm == Alarm::Clear {
            self.alarm = cause;
        }
    }

    /// Checks the value the client's own acknowledged create or exact-version write committed at `version` against
    /// the watermark, raises the mark in memory and adopts the value, returning whether the mark rose. A regression
    /// withdraws the client.
    fn adopt<R: Tracked>(
        &mut self,
        key: Key,
        version: Version,
        value: R,
    ) -> Result<(Read<R>, bool), StoreError> {
        let raised = value
            .observe(key, version, &mut self.mark)
            .map_err(|regression| self.regress(regression))?;
        value.adopt(&mut self.mark);
        Ok((
            Read {
                key,
                version,
                value,
            },
            raised,
        ))
    }

    /// Makes the marks of `keys` durable with one log write and returns whether the log recorded them. The client
    /// is withdrawn while the write runs and returns to its earlier alarm when the write succeeds, so every admitted
    /// client's watermark is one the log holds (WATERMARK). A write that fails or unwinds keeps the client withdrawn,
    /// with the alarm at `Log` when it was clear before the write.
    fn record(&mut self, keys: &[Key]) -> bool {
        let alarm = self.alarm;
        self.withdraw(Alarm::Log);
        let logged = self.log.raise(&self.mark, keys).is_ok();
        if logged {
            self.alarm = alarm;
        }
        logged
    }

    /// Runs a batch's per-element steps. An earlier element may have raised a mark in memory when a later step
    /// unwinds, and the unwind skips the log write that records it, so the client withdraws before the unwind
    /// continues and no later call returns while its watermark is ahead of the log (WATERMARK).
    fn batch<T>(&mut self, steps: impl FnOnce(&mut Self) -> T) -> T {
        panic::catch_unwind(AssertUnwindSafe(|| steps(&mut *self))).unwrap_or_else(|payload| {
            self.withdraw(Alarm::Log);
            panic::resume_unwind(payload)
        })
    }

    fn settle_one<R>(
        &mut self,
        result: Result<(Read<R>, bool), StoreError>,
    ) -> Result<Read<R>, StoreError> {
        let (read, raised) = result?;
        if raised && !self.record(&[read.key]) {
            self.tally.add(&read.key, Tallied::Log);
            return Err(StoreError::Log);
        }
        Ok(read)
    }

    /// Makes the marks `results` raised durable with one log write and returns the results; a failed write
    /// withdraws the client and replaces every `Ok` result whose key is among the raised keys with
    /// [`StoreError::Log`], including a repeated key's result that raised nothing itself.
    fn settle<R>(
        &mut self,
        results: Vec<Result<(Read<R>, bool), StoreError>>,
    ) -> Vec<Result<Read<R>, StoreError>> {
        let raised: BTreeSet<Key> = results
            .iter()
            .filter_map(|result| match result {
                Ok((read, true)) => Some(read.key),
                _ => None,
            })
            .collect();
        let keys: Vec<Key> = raised.iter().copied().collect();
        let logged = keys.is_empty() || self.record(&keys);
        results
            .into_iter()
            .map(|result| match result {
                Ok((read, _)) if !logged && raised.contains(&read.key) => {
                    self.tally.add(&read.key, Tallied::Log);
                    Err(StoreError::Log)
                }
                result => result.map(|(read, _)| read),
            })
            .collect()
    }
}

#[cfg(test)]
mod successor_control_tests;
#[cfg(test)]
mod tally_saturation_tests;
