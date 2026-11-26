//! The storage owner: every mapping, every in-place control table and the
//! engine ledger, alive from a completed initialization until finalization
//! releases the last extent.
//!
//! Ownership rules the rest of the crate relies on:
//!
//! - A [`Storage`] exists only after initialization populated every mapping,
//!   wrote every control value and transferred ownership; initialization is
//!   the one constructor.
//! - Mappings stay mapped, populated and at their initial advice and binding
//!   for the owner's `Live` phase. The kernel may still swap or migrate
//!   their pages.
//! - Once ownership has transferred, finalization, in the `finalize`
//!   module, is the only path that releases a mapping: every extent at its
//!   original base and full length exactly once, most recently acquired
//!   first, reporting `Drained` only after every release succeeded. A
//!   release the kernel refuses leaves that mapping retained and charged,
//!   reported through [`Storage::retained`].
//! - The borrow checker is the domain proof: nothing can reference a mapping
//!   except through `&Storage`, so `finalize(&mut self)` runs only when no
//!   accessor exists. Public accessors check the owner's phase before they
//!   form a reference; `pub(super)` accessors such as `leases`, `eras` and
//!   `pool` take `is_live()` as a precondition and `debug_assert!` it.
//! - Dropping an owner leaves whatever it still owns mapped until the
//!   process exits; only finalization unmaps. The ordinary metadata follows
//!   normal drop glue.
//! - `E_used` never decreases while the owner lives; ordinary operation never
//!   refunds engine memory. [`Storage::engine_used`] keeps reporting the full
//!   charge after finalization as the historical figure; the refund is the
//!   completed release itself, and a retained mapping stays charged.
//!
//! Successful storage initialization certifies storage regions and owner
//! handoff; engine initialization accounts for other components' storage
//! separately.

use super::closing::CloseCursor;
use super::finalize::{FinalizeCursor, Phase};
use super::free::{WINDOW, WINDOW_LINES, window_of};
use super::gate::{Gate, GateError};
use super::image::{
    EraControls, GraceCursor, LeaseControls, ParkedWord, PoolDescriptor, PoolImage,
    RegistrationRecord, ReturnLine, RootDescriptor, RootImage,
};
use super::init::{InitFailure, initialize};
use super::ledger::{EngineBudget, PoolLedger};
use super::mapping::{Mapping, RetainedMapping};
use super::os::Platform;
use super::placement::{NodeMask, PlacementConfig};
use super::policy::PendingMark;
use super::prefetch::hint_read;
use super::shards::IndexImage;
use super::volume::VolumeWatermarks;
use crate::index::{Identity, Key, KeyHasher, KeyRoute, Prefetch, ValidatedIndex};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::ValidatedConfig;
use super::allocation::AllocationId;
use super::blocks::{Block, BlockArena};
use super::extent::ExtentLocator;
use super::geometry::EXTENT_PAYLOAD;
use super::held::Held;
use super::slot::Record;
use super::tables::{
    PoolAccess, RetainCounters, SEQUENCE_REFUSED, SlotIndex, SlotState, TableInventory, Tables,
    Telemetry,
};
use super::word;

/// Effective placement of one mapping: the mask it was bound to and how many
/// of its pages the post-population check covered without finding one outside
/// that mask. The range walk skips a page not present when it reaches it, so
/// this counts pages checked as a range, not pages individually observed. This
/// is evidence from initialization, not a promise of later residence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementReport {
    pub nodes: NodeMask,
    pub pages_verified: usize,
}

/// What the live volume reports about itself, read from its control mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolReport {
    pub descriptor: PoolDescriptor,
    /// Bytes of the volume's control mapping.
    pub control_extent: usize,
    /// `PoolLedger` snapshots the raw bytes and `O` while holding the pool's
    /// `Gate`. `ledger` is `None` when a panicking holder poisoned the pool's
    /// `Gate`, because the tables may be half-written.
    pub ledger: Option<PoolLedger>,
    /// Nonblocking gate attempts that found it busy or poisoned.
    pub failed_tries: usize,
    /// Dropped owners whose ledger transition still awaits the gate.
    pub pending_marks: usize,
    /// The escrow `U`: units promised to builders and not yet placed, a
    /// sample. A claim may take the ledger's free units less the clean
    /// reserve and these.
    pub escrow_units: u64,
    /// Right reservations that lost to another writer, summed over every
    /// registration record and the pool's counter, each counter a sample.
    pub retain_cas_failed: usize,
    /// Weak right reservations that failed with the expected value in
    /// place, summed the same way.
    pub retain_cas_spurious: usize,
    pub control_placement: PlacementReport,
    /// The volume's configured `alloc_search_words`.
    pub alloc_search_words: usize,
    /// The extent work bound of the largest extent, which every reservation
    /// and every return preflight.
    pub extent_bound: usize,
}

#[derive(Debug)]
pub(super) struct Pool {
    pub(super) capture: std::sync::Mutex<super::recovery::Capture>,
    pub(super) eligible: std::sync::atomic::AtomicUsize,
    /// The extent rows of the members `eligible` counts, one for each extent a member's slot holds: the rows a
    /// checkpoint of the membership places. Written under the capture mutex beside `eligible`.
    pub(super) member_rows: std::sync::atomic::AtomicU64,
    pub(super) insert_step: std::sync::atomic::AtomicU64,
    /// One past the position of the last block of the newest recorded REMOVE or REPLACE, `0` for none: raised under
    /// the capture mutex, which serializes its writers, by the thread that records the removal, before that thread
    /// clears the mapping and records or parks the retirement. Every retirement of the removed slot follows the raise, on that
    /// thread or on the service thread that acquires the park, so its load reads this value or a later one and the
    /// slot waits until that block is durable (HOLD-UNTIL-DURABLE).
    pub(super) suffix_tail: std::sync::atomic::AtomicU64,
    /// When the volume's delta writer must next look at the suffix, in platform clock nanoseconds: `0` while a sealed
    /// block waits, the open block's flush time, `u64::MAX` while nothing waits. Stored under the capture mutex from
    /// the log's state ([`SuffixLog::due`](super::recovery::suffix::SuffixLog::due)) by every append, capture start,
    /// delta stage and `Storage::with_suffix` call, so the tick takes the mutex only once that time passed.
    pub(super) suffix_due: std::sync::atomic::AtomicU64,
    /// The [`CaptureEpoch`](super::recovery::CaptureEpoch): the count of wholesale membership replacements.
    pub(super) capture_epoch: std::sync::atomic::AtomicU64,
    pub(super) control: Mapping,
    pub(super) image: PoolImage,
    /// The expiry sweep's deadline bound as the gate holder last published
    /// it, in whole seconds: no resident's deadline lies below it, `u32::MAX`
    /// for none. Read
    /// without the gate by the expiry step, which skips its sample and its
    /// hold when the bound says nothing can be expired; the gate-held copy
    /// in the pool state stays the one the sweep decides by.
    pub(super) deadline_bound: AtomicU32,
    /// Whether a warm attempt holds the restored slots it installed. The
    /// attempt sets it under the pool gate, in the hold that precedes its
    /// first install, and clears it under the pool gate at its readiness
    /// commit, so an attempt that ends before its commit leaves it set for
    /// the storage's life. The close service reads it without the gate.
    pub(super) warm_hold: AtomicBool,
}

impl Pool {
    /// Publishes the gate-held deadline bound for the expiry step's check
    /// outside the gate. Called by the holder that changed it.
    #[inline(always)]
    pub(super) fn publish_deadline_bound(&self, bound: u32) {
        self.deadline_bound.store(bound, Ordering::Relaxed);
    }

    /// Records that a warm attempt holds every restored slot it installs
    /// from here to its commit. The caller holds the pool gate and has
    /// installed no slot yet.
    pub(super) fn hold_warm(&self) {
        self.warm_hold.store(true, Ordering::Release);
    }

    /// Ends the hold [`hold_warm`](Self::hold_warm) recorded: the attempt
    /// committed, and its slots are the storage's own. The caller holds the
    /// pool gate.
    pub(super) fn commit_warm(&self) {
        self.warm_hold.store(false, Ordering::Release);
    }
}

/// The index: its validated geometry, its keyed hash state, and the mapping
/// that holds every shard's tables and the reader scratch.
#[derive(Debug)]
pub(super) struct IndexOwner {
    pub(super) mapping: Mapping,
    pub(super) image: IndexImage,
    pub(super) geometry: ValidatedIndex,
    pub(super) hasher: KeyHasher,
}

impl IndexOwner {
    /// The derivation's prefetch hint over this index's bucket runs, for a
    /// caller that will store to the bucket (`for_write`) or only read it.
    #[inline(always)]
    pub(super) fn prefetch(&self, for_write: bool) -> Prefetch<'_> {
        Prefetch {
            base: self.mapping.base().as_ptr().cast_const(),
            runs: self.image.runs(),
            for_write,
        }
    }
}

/// Every mapping in acquisition order: root, the volume's control, then the
/// index.
pub(super) fn mappings<'a>(
    root: &'a Mapping,
    pool: &'a Pool,
    index: Option<&'a Mapping>,
) -> impl Iterator<Item = &'a Mapping> + 'a {
    [root, &pool.control].into_iter().chain(index)
}

/// Owned, populated arena storage. See the module documentation for the
/// ownership rules.
pub struct Storage<P: Platform> {
    pub(super) platform: P,
    pub(super) page_size: usize,
    pub(super) root: Mapping,
    pub(super) root_image: RootImage,
    pub(super) pool: Pool,
    pub(super) index: Option<IndexOwner>,
    pub(super) engine: EngineBudget,
    /// The read share of the one volume this storage may attach.
    pub(super) read_ops: u32,
    /// Table slots that volume's reads may hold at once.
    pub(super) read_commands: u32,
    /// Commands that volume's reads may hold outstanding ahead of their current one.
    pub(super) read_ahead: u8,
    /// Table slots that volume's metadata commands may hold at once.
    pub(super) metadata_commands: u32,
    /// Resubmits of a failed metadata write before the volume records `MetadataFailed`.
    pub(super) metadata_retries: u32,
    /// The recovery helpers' bounds for that volume's load attempts.
    pub(super) recovery: super::volume::RecoveryLimits,
    /// The validated clock contract every root of this storage's volume carries.
    pub(super) clock: super::portable::ClockContract,
    /// The validated feed contract every root of this storage's volume carries.
    pub(super) feed: super::coverage::FeedContract,
    /// Fill reservations and builder promises proceed when the recovery readiness is `Live`, or `Detached` with no volume attached; an attached volume waiting at its gate, or an unfinished load or replay, returns `Bootstrapping`, and a withheld or closed attempt returns `Closed`.
    pub(super) readiness: super::readiness::Word,
    pub(super) record: super::record::ValidRecordConfig,
    /// Fill records over every index shard, `sum(F[s])`.
    pub(super) fill_records: usize,
    pub(super) init_peak: usize,
    /// The owner's phase; written only under the exclusive borrow
    /// finalization holds, read by every shared accessor.
    pub(super) phase: Phase,
    /// The close-service cursor, outside every mapping.
    pub(super) close: CloseCursor,
    /// Budgeted maintenance's root gate and cursors, outside every mapping.
    pub(super) maintain: super::maintain::MaintainCursor,
    /// The finalization cursor, outside every mapping.
    pub(super) finalize: FinalizeCursor,
}

// SAFETY: the raw pointers inside are bases of mappings this value owns
// exclusively. Control values fall into three groups: immutable after
// initialization (descriptors, watermarks), atomics (the slot records, the
// membership steps, the pending removal mark, lease controls, the admission cutoff, telemetry), and
// the locked tables. A `&mut` into a locked
// table exists only inside a `Tables<'_>` borrowed from a live `PoolAccess`,
// whose `GateGuard` took the pool's `Gate` with an acquire compare-exchange
// and releases it with a release store on drop. A range-split restore hands
// disjoint `&mut` lane slices of that `Tables<'_>` to scoped workers, which
// write the shared records and per-slot atomics only for their own lane's
// slots; the holder joins every worker before it folds or releases the gate,
// so the workers' writes reach the next holder through the join and the
// release.
// The index mapping adds two plain groups: each shard's free stack, read and
// written only through the `&mut [usize]` its shard `GateGuard` holder forms
// for the hold, and the candidate scratch, whose run for one registration is
// reached only through `&mut Registration`, with runs disjoint by
// registration index. The root mapping's fill tables add one more: each
// shard's fill keys, read and written only through the `&mut [Key]` its
// shard `GateGuard` holder forms; the fill state words beside them are
// atomics a departing owner writes without the gate. Moving the owner moves
// no mapping.
unsafe impl<P: Platform + Send> Send for Storage<P> {}
// SAFETY: as above; every `&self` mutation is either an atomic, serialized by
// the pool or a shard `Gate`, or confined to one registration's scratch run
// behind its exclusive borrow, and release requires `&mut self`. The
// platform is shared too, which `Platform`'s `Sync` supertrait permits.
unsafe impl<P: Platform> Sync for Storage<P> {}

impl<P: Platform> Storage<P> {
    /// One sample of the publication clock, in the ticks [`WritableFill::publish`](super::WritableFill::publish) compares its deadline against.
    pub(crate) fn clock_ticks(&self) -> Option<u64> {
        self.platform.now_ticks()
    }

    /// The pooled fill capacity, `min(sum(F[s]), lease_limit / 2)`: each reserved fill holds one fill record and two `Shared` lease credits, the publisher's and its terminal read right's, so the record term `sum(F[s])` and the lease term `lease_limit / 2` each bound the fills held at once, and the lesser binds. Owner start compares `put.puts` against it. Passing the record term, `put.puts <= sum(F[s])`, is a necessary condition for every BEGIN at the PUT cap to find a record: a BEGIN draws its record from its key's shard alone and refuses `FillSlotsFull` when that shard has none Free, while other shards may hold Free records; [`IndexConfig::fills`](crate::index::IndexConfig::fills) states the per-shard sizing rule. With the lease term binding, start refuses on lease credits, whatever the records. Index room and object slots can lower the bound further. Storage outside the live phase reports 0.
    pub(crate) fn fill_capacity(&self) -> usize {
        self.root().map_or(0, |root| {
            self.fill_records
                .min(root.lease_limit / super::place_claim::FILL_CREDITS)
        })
    }

    /// The terms of [`ValidatedConfig::structural_floor`] as this storage recorded them from its configuration, or `None` unless the storage is live.
    pub(crate) fn floor_terms(&self) -> Option<super::config::FloorTerms> {
        let pool = self.live_pool()?;
        Some(super::config::FloorTerms {
            reserve_units: pool.image.reserve_units,
            record_units: pool.image.largest_units,
            ceiling: super::extent::empty_placeable(
                pool.descriptor().geometry.payload_units(),
                pool.image.largest.units(0),
            ),
            marks: pool.watermarks(),
        })
    }

    pub(crate) fn payload_cap(&self) -> usize {
        self.root()
            .map_or(0, |root| root.metadata_cap + root.body_cap)
    }

    /// Acquires, populates and verifies every mapping described by `config`
    /// on `platform`, then transfers ownership to the returned value. Each
    /// mapping is advised `MADV_HUGEPAGE` before population, so on a node
    /// with fragmented free memory the call can stall in kernel reclaim and
    /// compaction.
    ///
    /// # Errors
    ///
    /// [`InitFailure`] naming the failed step and whether rollback released
    /// every acquired mapping. No owner exists on error.
    #[expect(
        clippy::result_large_err,
        reason = "a failure carries the retained mappings by value; boxing them would allocate during rollback"
    )]
    pub fn initialize(
        config: &ValidatedConfig,
        placement: &PlacementConfig,
        platform: P,
    ) -> Result<Self, InitFailure> {
        initialize(config, None, placement, platform)
    }

    /// As [`initialize`](Self::initialize), and also places `index`'s shard
    /// tables and reader scratch in one more mapping bound to the control
    /// home, builds the keyed hash state, and charges both under `E`. The
    /// index configuration was validated against `config`.
    ///
    /// # Errors
    ///
    /// As for [`initialize`](Self::initialize).
    #[expect(
        clippy::result_large_err,
        reason = "a failure carries the retained mappings by value; boxing them would allocate during rollback"
    )]
    pub fn initialize_indexed(
        config: &ValidatedConfig,
        index: ValidatedIndex,
        placement: &PlacementConfig,
        platform: P,
    ) -> Result<Self, InitFailure> {
        initialize(config, Some(index), placement, platform)
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Bytes charged against `E`: payload, root and control extents, the
    /// volume handle, and [`IndexInventory::total`] when an index is configured.
    ///
    /// [`IndexInventory::total`]: crate::index::IndexInventory::total
    pub fn engine_used(&self) -> usize {
        self.engine.used()
    }

    /// Largest simultaneous charge during initialization: `E_used` plus the
    /// residency scratch that existed while mappings were being populated.
    pub fn init_peak(&self) -> usize {
        self.init_peak
    }

    /// Bytes of the root control mapping.
    pub fn root_extent(&self) -> usize {
        self.root.len()
    }

    /// Engine-shared values as recorded in the root control mapping, or
    /// `None` once drained.
    pub fn root_descriptor(&self) -> Option<RootDescriptor> {
        self.root().copied()
    }

    /// The root descriptor in place; a reference, since the record carries a
    /// node mask and a copy would move it whole.
    #[inline(always)]
    pub(super) fn root(&self) -> Option<&RootDescriptor> {
        if !self.is_live() {
            return None;
        }
        // SAFETY: the root mapping is owned and its descriptor was written
        // before the owner existed; no exclusive reference into it exists.
        Some(unsafe { &self.root_image.descriptor.as_slice(&self.root)[0] })
    }

    /// The volume and the root descriptor, both present exactly while the
    /// owner is live.
    #[inline(always)]
    pub(super) fn live(&self) -> Option<(&Pool, &RootDescriptor)> {
        Some((self.live_pool()?, self.root()?))
    }

    /// The engine-wide lease controls. Precondition: `is_live()`, which
    /// callers hold through a lease or completed owner's borrow or check
    /// first; a drained call would read a released mapping.
    #[inline(always)]
    pub(super) fn leases(&self) -> &LeaseControls {
        debug_assert!(self.is_live());
        // SAFETY: the root mapping is owned and the record was initialized
        // before the owner existed; it holds only atomics.
        unsafe { &self.root_image.leases.as_slice(&self.root)[0] }
    }

    /// The parked-credit map, one bit per registration record in index
    /// order. Precondition: `is_live()`, as for [`leases`](Self::leases).
    #[inline(always)]
    pub(super) fn parked(&self) -> &[ParkedWord] {
        debug_assert!(self.is_live());
        // SAFETY: as for `leases`; every word holds only an atomic.
        unsafe { self.root_image.parked.as_slice(&self.root) }
    }

    /// Every registration record's return line, in index order.
    /// Precondition: `is_live()`, as for [`leases`](Self::leases).
    #[inline(always)]
    pub(super) fn returns(&self) -> &[ReturnLine] {
        debug_assert!(self.is_live());
        // SAFETY: as for `leases`; every line holds only an atomic.
        unsafe { self.root_image.returns.as_slice(&self.root) }
    }

    /// The era counter and grace certificate. Precondition: `is_live()`, as
    /// for [`leases`](Self::leases).
    #[inline(always)]
    pub(super) fn eras(&self) -> &EraControls {
        debug_assert!(self.is_live());
        // SAFETY: as for `leases`; the record holds only atomics.
        unsafe { &self.root_image.eras.as_slice(&self.root)[0] }
    }

    /// Every registration record, in index order. Precondition:
    /// `is_live()`, as for [`leases`](Self::leases).
    #[inline(always)]
    pub(super) fn registrations(&self) -> &[RegistrationRecord] {
        debug_assert!(self.is_live());
        // SAFETY: as for `leases`; every record holds only atomics.
        unsafe { self.root_image.registrations.as_slice(&self.root) }
    }

    /// Callers read and write the certification pass cursor only while
    /// holding [`maintenance_gate`](Self::maintenance_gate).
    pub(super) fn grace_cursor(&self) -> &GraceCursor {
        debug_assert!(self.is_live());
        // SAFETY: as for `leases`; the record holds only atomics.
        unsafe { &self.root_image.grace.as_slice(&self.root)[0] }
    }

    /// The certification pass gate. The root mapping owns this gate; no pool
    /// owns it.
    pub(super) fn maintenance_gate(&self) -> &Gate {
        debug_assert!(self.is_live());
        // SAFETY: the root mapping is owned and the gate was initialized
        // before the owner existed; it is one atomic word.
        unsafe { &self.root_image.maintenance.as_slice(&self.root)[0] }
    }

    /// The volume while the owner is live. Owners hold the borrow that keeps
    /// it live, so no check runs.
    #[inline(always)]
    pub(super) fn pool(&self) -> &Pool {
        debug_assert!(self.is_live());
        &self.pool
    }

    /// Returns `None` once the owner is drained. The `ledger` field locks
    /// the pool's `Gate`; callers must not hold that `Gate` when calling
    /// `pool_report`. A poisoned `Gate` yields a report whose `ledger` is
    /// `None`; every other field needs no `Gate`.
    pub fn pool_report(&self) -> Option<PoolReport> {
        let pool = self.live_pool()?;
        let descriptor = *pool.descriptor();
        Some(PoolReport {
            alloc_search_words: pool.image.alloc_search_words,
            extent_bound: pool.image.extent_bound,
            descriptor,
            control_extent: pool.control.len(),
            ledger: pool.ledger(),
            failed_tries: pool.failed_tries(),
            pending_marks: pool
                .telemetry()
                .pending_marks
                .load(std::sync::atomic::Ordering::Acquire),
            escrow_units: pool.telemetry().escrow(),
            retain_cas_failed: self.retain_failures(|retains| &retains.lost),
            retain_cas_spurious: self.retain_failures(|retains| &retains.stalled),
            control_placement: PlacementReport {
                nodes: descriptor.nodes,
                pages_verified: pool.control.pages_verified(),
            },
        })
    }

    /// One kind of failed right reservation, `counter` of each record's and
    /// the pool's [`RetainCounters`], summed. Precondition: `is_live()`.
    fn retain_failures(&self, counter: impl Fn(&RetainCounters) -> &AtomicUsize) -> usize {
        let records = self.registrations().iter().map(|record| &record.retains);
        std::iter::once(&self.pool.telemetry().retains)
            .chain(records)
            .map(|retains| counter(retains).load(Ordering::Relaxed))
            .sum()
    }

    /// Placement of the root control mapping, or `None` once drained.
    pub fn root_placement(&self) -> Option<PlacementReport> {
        Some(PlacementReport {
            nodes: self.root_descriptor()?.control_home,
            pages_verified: self.root.pages_verified(),
        })
    }

    /// Returns `None` when the phase is `Finalizing` or `Drained`, when the
    /// pool gate is poisoned, or when `slot` lies past the last record.
    ///
    /// # Panics
    ///
    /// When `word::state` finds the word malformed; the gate is held, so the
    /// panic poisons it.
    pub fn slot_state(&self, slot: SlotIndex) -> Option<(SlotState, u32)> {
        let pool = self.live_pool()?;
        // The answer ends the hold through `release`, so its drop is a panic
        // of the word's check, and that drop poisons the gate also in a call
        // made by a thread that was already unwinding.
        let access = pool.lock()?.poison_on_unwind();
        let report = pool.records().get(slot.0).map(|record| {
            let current = record.ident.load(Ordering::Relaxed);
            (word::state(current), word::incarnation(current))
        });
        access.release();
        report
    }

    /// Offset and element count of every table in the volume's control
    /// mapping.
    pub fn table_inventory(&self) -> Option<TableInventory> {
        Some(self.live_pool()?.image.tables.inventory())
    }

    /// Whether the volume's tables carry a sequence arena, which lets a fill
    /// place an object of two or more extents; `false` once the storage is
    /// drained.
    pub(crate) fn has_sequence_arena(&self) -> bool {
        self.live_pool()
            .is_some_and(|pool| pool.image.tables.has_arena())
    }

    /// Mappings finalization could not release, each at its original base,
    /// length and code. Empty until a release is refused; read from the
    /// owner's own state, never from a mapping.
    pub fn retained(&self) -> impl Iterator<Item = RetainedMapping> + '_ {
        mappings(
            &self.root,
            &self.pool,
            self.index.as_ref().map(|index| &index.mapping),
        )
        .filter_map(Mapping::retained)
    }

    /// The index while the owner is live, or `None` if none was configured
    /// or the owner is drained.
    #[inline(always)]
    pub(super) fn index(&self) -> Option<&IndexOwner> {
        if !self.is_live() {
            return None;
        }
        let index = self.index.as_ref()?;
        // The phase stands for every mapping: none is released while it is
        // `Live`.
        debug_assert!(index.mapping.is_owned());
        Some(index)
    }

    /// The index mapping's extent in bytes, or `None` without an index or
    /// for a drained owner.
    pub fn index_extent(&self) -> Option<usize> {
        Some(self.index()?.mapping.len())
    }

    /// The validated index geometry, or `None` without an index or for a
    /// drained owner.
    pub fn index_geometry(&self) -> Option<&ValidatedIndex> {
        Some(&self.index()?.geometry)
    }

    /// `key`'s route under this owner's keyed hash state, uncharged, or
    /// `None` without an index, drained, or with no enabled shard. A report
    /// path for recording the mappings a run derived; a lookup routes for
    /// itself and charges the hash pass. Always inlined, as the derivation
    /// it wraps is: the route stays in registers until the caller stores
    /// it, where a call would return the `Option<KeyRoute>` through memory
    /// for the caller to copy.
    #[inline(always)]
    pub fn route(&self, key: &Key) -> Option<KeyRoute> {
        let index = self.index()?;
        index
            .hasher
            .route_unpaid(key, &index.geometry, Prefetch::NONE)
    }

    /// Replaces the index's keyed hash state with `hasher`, a fixed key pair
    /// or a deterministic seam, while the index holds no key. The exclusive
    /// borrow excludes every cache, registration and volume over the
    /// storage, so the state stays fixed while any of them runs, and an
    /// empty index holds no entry the previous state placed.
    ///
    /// # Panics
    ///
    /// When the storage has no index, or any shard holds a visible key.
    #[cfg(test)]
    pub(crate) fn install_hasher(&mut self, hasher: KeyHasher) {
        let geometry = self.index_geometry().expect("an indexed storage");
        // A disabled shard has no table, so it reports nothing and holds no key.
        let occupied = (0..geometry.shards().len()).any(|shard| {
            self.shard_report(crate::index::ShardIndex(shard))
                .is_some_and(|report| report.visible != 0)
        });
        assert!(!occupied, "a hasher is installed only into an empty index");
        self.index.as_mut().expect("an indexed storage").hasher = hasher;
    }

    /// Call `hint_lookup` before intervening work, such as a request's
    /// authentication, to overlap that work with the prefetch latency of a
    /// later lookup of `key`.
    #[inline]
    pub fn hint_lookup(&self, key: &Key) {
        if let Some(index) = self.index() {
            let _ = self.route_hinted(index, key);
        }
    }

    /// The lookup's route derivation, shared with [`hint_lookup`](Self::hint_lookup)
    /// so an early hint requests the same lines the lookup's own derivation
    /// does. The key's placement window is hinted with the bucket because a
    /// hit validates and retains a record in that window unless the window
    /// was full at claim time.
    #[inline(always)]
    pub(super) fn route_hinted(&self, index: &IndexOwner, key: &Key) -> Option<KeyRoute> {
        let route = index
            .hasher
            .route_unpaid(key, &index.geometry, index.prefetch(false));
        if let (Some(route), Some(pool)) = (&route, self.live_pool()) {
            pool.prefetch_read_window(route.fingerprint());
        }
        route
    }

    /// The fingerprint of the object a visible index pair names, for the
    /// gate holder comparing candidates, or `None` when the coordinates name
    /// no anchored slot. The caller read `slot` from a pair occupied under
    /// the shard gate it holds: the pair's mapping has not ended, so the
    /// word holds the key's hash `bind` stored, never a retirement era.
    #[inline(always)]
    pub(super) fn visible_fingerprint(&self, slot: SlotIndex) -> Option<u64> {
        let record = self.live_pool()?.records().get(slot.0)?;
        let held = record.ident.load(Ordering::Acquire);
        (word::refs(held) != 0 && word::well_formed(held)).then(|| record.fingerprint())
    }

    /// Whether every mapping is owned and may be read: the `Live` phase.
    /// Finalization turns the phase before its first release, so a shared
    /// accessor that finds the owner live finds every mapping owned.
    #[inline(always)]
    pub(super) fn is_live(&self) -> bool {
        self.phase() == Phase::Live
    }

    pub(super) fn live_pool(&self) -> Option<&Pool> {
        self.is_live().then_some(&self.pool)
    }
}

impl Pool {
    /// The descriptor in place; it is immutable after initialization, and its
    /// node mask makes a copy far larger than the fields callers read. The
    /// pool's control mapping is owned: a `Pool` is reached only through a
    /// live storage or an accessor whose borrow keeps the storage live.
    #[inline]
    pub(super) fn descriptor(&self) -> &PoolDescriptor {
        // SAFETY: the control mapping is owned and its image was fully written
        // before the owner existed; no exclusive reference into it exists.
        unsafe { &self.image.descriptor.as_slice(&self.control)[0] }
    }

    /// One nonblocking attempt at the gate; a failed try is counted.
    #[inline(always)]
    pub(super) fn try_lock(&self) -> Result<PoolAccess<'_>, GateError> {
        // SAFETY: as for `descriptor`; the tables were initialized with it.
        let result = unsafe { self.image.tables.try_lock(&self.control) };
        if result.is_err() {
            self.telemetry_failed_try();
        }
        result
    }

    /// One nonblocking attempt that does not count as a failed try: for an
    /// owner's drop or cancel, whose gate attempt is fixed mandatory work,
    /// not budgeted reservation contention.
    #[inline(always)]
    pub(super) fn try_lock_quiet(&self) -> Result<PoolAccess<'_>, GateError> {
        // SAFETY: as for `try_lock`.
        unsafe { self.image.tables.try_lock(&self.control) }
    }

    /// Waiting gate access for reports (polls with backoff); `None` if poisoned.
    pub(super) fn lock(&self) -> Option<PoolAccess<'_>> {
        // SAFETY: as for `try_lock`.
        unsafe { self.image.tables.lock(&self.control) }
    }

    /// Both ledgers and the run index's drops under one waiting hold; `None` if poisoned.
    fn ledger(&self) -> Option<PoolLedger> {
        let mut access = self.lock()?;
        let mut tables = access.tables();
        let extents = tables.extents();
        let (raw, index_drops) = (extents.ledger(), extents.drops());
        Some(PoolLedger {
            raw,
            slots: tables.state.ledger,
            index_drops,
        })
    }

    /// The visits a run reservation spanning `units` units preflights: the
    /// allocator's work bound for that span, which can pass `extent_bound`
    /// because a run can span more units than the largest extent. One
    /// extent's reservation or return preflights `extent_bound` instead.
    #[inline]
    pub(super) fn run_work(&self, units: u64) -> usize {
        let descriptor = self.descriptor();
        super::extent::work_bound(
            descriptor.geometry.payload_units(),
            descriptor.slot_count,
            units,
        )
    }

    /// Counters usable without the gate.
    #[inline]
    pub(super) fn telemetry(&self) -> &Telemetry {
        // SAFETY: as for `try_lock`; the record holds only atomics.
        unsafe { self.image.tables.telemetry(&self.control) }
    }

    /// `slot`'s lifetime word, with no bounds check, for the hit path.
    ///
    /// # Safety
    ///
    /// `slot` must be below the pool's slot count.
    #[inline(always)]
    pub(super) unsafe fn slot_word(&self, slot: usize) -> &AtomicU64 {
        // SAFETY: the caller's `slot < O`.
        unsafe { &self.record(slot).ident }
    }

    /// `slot`'s record, with no bounds check, for the hit path.
    ///
    /// # Safety
    ///
    /// `slot` must be below the pool's slot count.
    #[inline(always)]
    pub(super) unsafe fn record(&self, slot: usize) -> &Record {
        // SAFETY: the caller's `slot < O`; the control mapping is owned and
        // a record holds only atomics.
        unsafe { self.image.tables.record(&self.control, slot) }
    }

    /// `slot`'s state and incarnation, read by a holder of the pool gate
    /// from one load of its word. Relaxed: only gate holders, and the lane
    /// workers a holder starts and joins within its hold, write either, so
    /// the hold and those spawn and join edges order them (`word` module).
    ///
    /// # Panics
    ///
    /// If `slot` is not below the slot count, or the word has a reserved bit
    /// set or an unknown state encoding; the caller holds the gate, so the
    /// panic poisons it.
    #[inline(always)]
    pub(super) fn gate_state(&self, slot: usize) -> (SlotState, u32) {
        let current = self.records()[slot].ident.load(Ordering::Relaxed);
        (word::state(current), word::incarnation(current))
    }

    /// Every slot's position word, in slot order: gate holders read and write it, and a parking thread stores its retirement's epoch marker into it without the gate.
    #[inline(always)]
    pub(super) fn positions(&self) -> &[AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.image.tables.positions(&self.control) }
    }

    /// Generations appear in slot order; each identifies the session that wrote the slot's record. Gate holders store generations; reads load them regardless of gate ownership.
    #[inline(always)]
    pub(super) fn generations(&self) -> &[AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.image.tables.generations(&self.control) }
    }

    /// Every slot's cache version, in slot order: gate holders write it beside the record generation and reads load it without the gate.
    #[inline(always)]
    pub(super) fn versions(&self) -> &[AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.image.tables.versions(&self.control) }
    }

    /// Every slot's membership step word, in slot order.
    #[inline(always)]
    pub(super) fn steps(&self) -> &[AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.image.tables.steps(&self.control) }
    }

    /// The parked-slot bitmap, one bit per slot, in slot order.
    #[inline(always)]
    pub(super) fn parked_slots(&self) -> &[AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.image.tables.parked_slots(&self.control) }
    }

    /// The parked-slot bitmap's summary, one bit per bitmap word.
    #[inline(always)]
    pub(super) fn parked_summary(&self) -> &[AtomicU64] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.image.tables.parked_summary(&self.control) }
    }

    /// The position words' shared words, read without the gate.
    #[inline(always)]
    pub(crate) fn journal_words(&self) -> &super::recovery::JournalWords {
        // SAFETY: as for `try_lock`; the shared words hold only atomics.
        unsafe { self.image.tables.journal_words(&self.control) }
    }

    /// Every slot's record, in slot order.
    #[inline(always)]
    pub(super) fn records(&self) -> &[Record] {
        // SAFETY: as for `try_lock`; the table holds only atomics.
        unsafe { self.image.tables.records(&self.control) }
    }

    /// The payload bytes, metadata plus body, of the extents `slot` holds,
    /// each one's [`extent_payload`](Self::extent_payload), the last under
    /// the slot's tail, and the units of those extents, as
    /// [`Tables::held_units`] counts them. Every extent of a sequence before
    /// its last carries [`EXTENT_PAYLOAD`], so a held prefix of `held`
    /// extents carries `held` full payloads unless it holds the last, whose
    /// payload comes from its own locator, and every extent before the last
    /// charges the first's units. Read by a gate holder for a ledger
    /// transition, in constant work: two locators of a sequence are decoded,
    /// whatever its length.
    ///
    /// # Panics
    ///
    /// As for [`extent_payload`](Self::extent_payload) and
    /// [`Tables::held`], and if the sequence block refuses the slot's own
    /// incarnation.
    #[inline(always)]
    pub(super) fn held_charge(&self, tables: &mut Tables<'_>, slot: usize) -> (usize, u32) {
        let tail = tables.tails[slot];
        match tables.held(slot) {
            Held::Direct(locator) => (
                self.extent_payload(locator, Some(tail)),
                locator.len_units(),
            ),
            Held::Sequence { block, count } => {
                let owner = tables.owner(slot);
                self.sequence_charge(tables, (block, count, owner), tail)
            }
        }
    }

    /// The sequence half of [`held_charge`](Self::held_charge), kept out of
    /// line so the direct-extent path stays small.
    ///
    /// # Panics
    ///
    /// As for [`held_charge`](Self::held_charge).
    #[cold]
    #[inline(never)]
    fn sequence_charge(
        &self,
        tables: &mut Tables<'_>,
        (block, count, owner): (Block, u32, AllocationId),
        tail: u16,
    ) -> (usize, u32) {
        let arena = tables.blocks();
        let prefix = arena.prefix(block, owner, count).expect(SEQUENCE_REFUSED);
        let full = EXTENT_PAYLOAD as usize;
        let payload = match prefix.last() {
            Some(&last) if prefix.len() == count as usize => {
                (prefix.len() - 1) * full
                    + self.extent_payload(ExtentLocator::from_bits(last), Some(tail))
            }
            _ => prefix.len() * full,
        };
        (payload, super::tables::prefix_units(prefix))
    }

    /// The payload bytes of the extent `locator` of a held object: a full
    /// extent before a sequence's last carries [`EXTENT_PAYLOAD`], and an
    /// object's last extent, given the slot's stored record tail
    /// `last_tail`, has a record of `(units - 1) * IO_UNIT + tail` bytes,
    /// where a tail of zero fills its last unit; that length names one
    /// payload length.
    ///
    /// # Panics
    ///
    /// For a last extent, if the locator spans no unit or no payload length
    /// gives that record length, which only corruption of the record or its
    /// tail produces; the caller holds the gate, so the panic poisons it.
    #[inline(always)]
    pub(super) fn extent_payload(&self, locator: ExtentLocator, last_tail: Option<u16>) -> usize {
        let Some(tail) = last_tail else {
            return EXTENT_PAYLOAD as usize;
        };
        let record_len = super::layout::record_len(locator.len_units(), tail);
        match self.image.record.payload_of(record_len) {
            Some(payload) => payload as usize,
            None => panic!("a held record's length names no payload"),
        }
    }

    /// The return work, in visits, a preflight funds for what `locator`
    /// names: the largest extent's work bound for a direct extent, or for a
    /// sequence of `count` extents one pop and that bound per extent plus
    /// the block's [`FREE_STEPS`](BlockArena::FREE_STEPS). A locator of
    /// neither form takes the bound; the gate holder that decodes it fails
    /// closed.
    #[inline]
    pub(super) fn held_work(&self, locator: ExtentLocator) -> usize {
        let bound = self.image.extent_bound;
        match Held::decode(locator) {
            Some(Held::Sequence { count, .. }) => {
                count as usize * (1 + bound) + BlockArena::FREE_STEPS
            }
            Some(Held::Direct(_)) | None => bound,
        }
    }

    /// The largest return work one service visit funds: the largest
    /// extent's work bound, plus a sequence visit's steps when the pool
    /// carries a sequence arena. Validation bounds the work bound so the
    /// sum and service's minimum fit.
    #[inline]
    pub(super) fn visit_bound(&self) -> usize {
        let sequence = if self.image.tables.has_arena() {
            super::release::SEQUENCE_VISIT
        } else {
            0
        };
        self.image.extent_bound + sequence
    }

    /// The locator of extent `index` of the sequence object `id` holds, read
    /// under one quiet gate try, or `None` when the gate is busy or poisoned.
    /// The caller holds a right on `id`, or owns its filling slot, either of
    /// which keeps its block and its extents fixed.
    ///
    /// # Panics
    ///
    /// If `id`'s slot holds no sequence, its block refuses `id`, or its
    /// prefix holds no extent at `index`, which only corruption produces;
    /// the panic poisons the gate.
    pub(super) fn sequence_extent(&self, id: AllocationId, index: u32) -> Option<ExtentLocator> {
        // The read's return ends the hold through `release`, so its drop is a panic of the read, and that drop poisons the gate also in a lookup made by a thread that was already unwinding.
        let mut access = self.try_lock_quiet().ok()?.poison_on_unwind();
        let mut tables = access.tables();
        let Held::Sequence { block, count } = tables.held(id.slot().0) else {
            panic!("a sequence lookup whose slot holds none");
        };
        let bits = tables
            .blocks()
            .prefix(block, id, count)
            .expect(super::tables::SEQUENCE_REFUSED)
            .get(index as usize)
            .copied()
            .expect("a sequence holds every extent its lookup names");
        access.release();
        Some(ExtentLocator::from_bits(bits))
    }

    /// The headroom watermarks, or `None` for a storage configured without
    /// maintenance.
    pub(super) fn watermarks(&self) -> Option<VolumeWatermarks> {
        // SAFETY: as for `try_lock`.
        unsafe { self.image.tables.watermarks(&self.control) }
    }

    /// The volume's pending removal mark.
    pub(super) fn pending_mark(&self) -> &PendingMark {
        // SAFETY: as for `try_lock`; the record holds only atomics.
        unsafe { self.image.tables.pending_mark(&self.control) }
    }

    /// The allocation `identity` names, with the slot's word as one load
    /// read it: its slot, below the slot count, at the slot's current
    /// incarnation, whose low 16 bits must equal the identity's; `None`
    /// otherwise. The load is `Acquire`, so the count beside the incarnation
    /// is ordered after every release decrement of an earlier count on the
    /// word. That the index maps the slot's current object is the caller's
    /// premise: a copy under a stable sequence inside the caller's pinned
    /// interval, or an occupied pair under the shard gate, where the
    /// mapping's anchor keeps the incarnation from moving.
    #[inline(always)]
    pub(super) fn resolve(&self, identity: Identity) -> Option<(AllocationId, u64)> {
        let slot = identity.slot as usize;
        if slot >= self.descriptor().slot_count {
            return None;
        }
        // SAFETY: `slot < O`, checked just above.
        let current = unsafe { self.slot_word(slot) }.load(Ordering::Acquire);
        let incarnation = word::incarnation(current);
        (incarnation as u16 == identity.incarnation_low)
            .then_some((AllocationId::new(SlotIndex(slot), incarnation), current))
    }

    /// Cache hints for slot `slot`'s record and policy `next` link; see
    /// [`TableImage::prefetch_slot`].
    #[inline(always)]
    pub(super) fn prefetch_slot(&self, slot: usize) {
        // SAFETY: as for `try_lock`.
        unsafe { self.image.tables.prefetch_slot(&self.control, slot) }
    }

    /// `prefetch_retirement` hints cache lines for `slot`'s retirement and return metadata; see [`TableImage::prefetch_retirement`].
    #[inline(always)]
    pub(super) fn prefetch_retirement(&self, slot: usize) {
        // SAFETY: as for `try_lock`.
        unsafe { self.image.tables.prefetch_retirement(&self.control, slot) }
    }

    /// The write hint requests the cache line containing `slot`'s record;
    /// see [`TableImage::prefetch_record`].
    #[inline(always)]
    pub(super) fn prefetch_record(&self, slot: usize) {
        // SAFETY: as for `try_lock`.
        unsafe { self.image.tables.prefetch_record(&self.control, slot) }
    }

    /// Callers that read `slot` outside any pin or gate use a read hint to
    /// prefetch the record's cache line. Wrapping arithmetic forms the
    /// address and the hint alone receives it, so every `slot` is accepted.
    #[inline(always)]
    pub(super) fn prefetch_record_read(&self, slot: usize) {
        hint_read(self.records().as_ptr().wrapping_add(slot).cast());
    }

    /// Write hints for the record lines of the placement window
    /// `fingerprint` names, when the pool has one: the lines a claim for the
    /// key writes and a lookup of it validates and retains on. Only
    /// addresses are formed.
    #[inline(always)]
    pub(super) fn prefetch_window(&self, fingerprint: u64) {
        if let Some(start) = window_of(fingerprint, self.descriptor().slot_count) {
            self.prefetch_window_records(start);
        }
    }

    #[inline(always)]
    pub(super) fn prefetch_read_window(&self, fingerprint: u64) {
        if let Some(start) = window_of(fingerprint, self.descriptor().slot_count) {
            self.prefetch_window_records(start);
            // SAFETY: as for `try_lock`.
            unsafe {
                let tables = &self.image.tables;
                tables.prefetch_generation(&self.control, start);
                tables.prefetch_generation(&self.control, start + WINDOW - 1);
                tables.prefetch_version(&self.control, start);
                tables.prefetch_version(&self.control, start + WINDOW - 1);
            }
        }
    }

    /// Write hints for every line a slot of the placement window
    /// `fingerprint` names is written through by its claim and its
    /// publication's bind: the window's record lines and, from the gate-held
    /// tables, the free-slot word, the tail and the policy `next` link of
    /// its slots. Only addresses are formed.
    #[inline(always)]
    pub(super) fn prefetch_claim(&self, fingerprint: u64) {
        if let Some(start) = window_of(fingerprint, self.descriptor().slot_count) {
            self.prefetch_window_records(start);
            // SAFETY: as for `try_lock`.
            unsafe {
                self.image
                    .tables
                    .prefetch_claim_tables(&self.control, start)
            }
        }
    }

    #[inline(always)]
    fn prefetch_window_records(&self, start: usize) {
        for line in 0..WINDOW_LINES {
            self.prefetch_record(start + line * (WINDOW / WINDOW_LINES));
        }
    }

    fn failed_tries(&self) -> usize {
        self.telemetry()
            .failed_tries
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    fn telemetry_failed_try(&self) {
        self.telemetry()
            .failed_tries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Test views of the lifetime words, and the tampering some tests apply to
/// them: every write here is a read-modify-write, as in production.
#[cfg(test)]
impl Pool {
    /// `slot`'s word, loaded with acquire.
    pub(super) fn word(&self, slot: usize) -> u64 {
        self.records()[slot].ident.load(Ordering::Acquire)
    }

    /// `slot`'s reference count.
    pub(super) fn refs(&self, slot: usize) -> usize {
        word::refs(self.word(slot))
    }

    /// `slot`'s abandonment, retirement and anchor flags.
    pub(super) fn flags(&self, slot: usize) -> u64 {
        self.word(slot) & word::FLAGS
    }

    /// `slot`'s current incarnation.
    pub(super) fn incarnation(&self, slot: usize) -> u32 {
        word::incarnation(self.word(slot))
    }

    /// Replaces `slot`'s word with what `edit` makes of it.
    pub(super) fn edit_word(&self, slot: usize, edit: impl Fn(u64) -> u64) {
        let _ =
            self.records()[slot]
                .ident
                .try_update(Ordering::AcqRel, Ordering::Relaxed, |word| Some(edit(word)));
    }

    /// Sets `slot`'s parked bit and its summary bit, the writes a park
    /// makes after its flag.
    pub(super) fn mark_parked_slot(&self, slot: usize) {
        super::pending::mark_parked::<_, super::pending::Published>(
            self.parked_slots(),
            self.parked_summary(),
            slot,
        );
    }

    /// The retirement era in `slot`'s fingerprint word.
    pub(super) fn retire_era(&self, slot: usize) -> u64 {
        self.records()[slot].retire_era()
    }

    /// Moves `slot`'s state to `state`, as a gate holder's read-modify-write
    /// would.
    pub(super) fn set_state(&self, slot: usize, state: SlotState) {
        self.edit_word(slot, |current| current & !word::STATE | state.bits());
    }

    /// Sets `slot`'s reference count to `refs`.
    pub(super) fn set_refs(&self, slot: usize, refs: usize) {
        self.edit_word(slot, |current| {
            current % word::REF + refs as u64 * word::REF
        });
    }

    /// Sets `slot`'s incarnation to `incarnation`.
    pub(super) fn set_incarnation(&self, slot: usize, incarnation: u32) {
        self.edit_word(slot, |current| {
            current & !word::INCARNATION | u64::from(incarnation)
        });
    }

    /// Points the claim cursor at free `slot`, so the next claim without a
    /// placement window takes it: for a test that reuses one slot on
    /// purpose.
    pub(super) fn claim_next(&self, slot: usize) {
        let mut access = self.lock().unwrap();
        let mut tables = access.tables();
        assert!(
            tables.free_slots().contains(slot),
            "slot {slot} is not free"
        );
        tables.state.cursor_claim = slot;
    }

    /// The first `count` free slots a claim placed by `fingerprint`, or by
    /// the claim cursor for `None`, would take in turn if each one it took
    /// were exhausted and quarantined: the claim's search order over the
    /// current free set.
    pub(super) fn claim_order(&self, fingerprint: Option<u64>, count: usize) -> Vec<usize> {
        use super::free::{FreeSlots, window_of, words};
        let slot_count = self.descriptor().slot_count;
        let mut access = self.lock().unwrap();
        let mut tables = access.tables();
        let cursor = tables.state.cursor_claim;
        let mut copy = vec![0u64; words(slot_count)];
        let mut set = FreeSlots::attach(&mut copy, slot_count);
        for slot in 0..slot_count {
            if tables.free_slots().contains(slot) {
                set.give(slot);
            }
        }
        let window = fingerprint.and_then(|fingerprint| window_of(fingerprint, slot_count));
        let mut order = Vec::with_capacity(count);
        while order.len() < count {
            let next = match window {
                Some(start) => set.first_in_window(start).or_else(|| set.next_from(start)),
                None => set.next_from(cursor),
            };
            let Some(slot) = next else { break };
            set.take(slot);
            order.push(slot);
        }
        order
    }
}

#[cfg(test)]
mod tests {
    use super::super::budget::WorkBudget;
    use super::super::closing::CloseError;
    use super::super::config::StorageConfig;
    use super::super::finalize::{Finalization, FinalizeError, Phase, Progress};
    use super::super::mapping::Region;
    use super::super::os::OsCode;
    use super::super::placement::PlacementConfig;
    use super::super::test_platform::{Fail, Op, TestPlatform, finalize};
    use super::Storage;

    const PAGE: usize = 4096;

    fn storage(slot_count: usize, platform: TestPlatform) -> Storage<TestPlatform> {
        let config = StorageConfig {
            page_size: PAGE,
            engine_budget: 1 << 20,
            body_cap: 400,
            metadata_cap: Some(64),
            lease_limit: 1024,
            object_rights: 64,
            reader_limit: 4,
            volume: crate::storage::test_volume(slot_count * crate::storage::IO_UNIT, slot_count),
        };
        let placement = PlacementConfig { control_home: 0 };
        Storage::initialize(&config.validate().unwrap(), &placement, platform).unwrap()
    }

    /// Finalization releases each mapping once, most recently acquired
    /// first, and reports drained only after the last; a repeat and a drop
    /// touch nothing.
    #[test]
    fn finalization_releases_each_mapping_once_and_repeat_touches_nothing() {
        let slot_count = 4;
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        let mut storage = storage(slot_count, platform);
        let mapped = log.ranges(Op::Map);
        assert_eq!(mapped.len(), 2);
        let used = storage.engine_used();
        assert_eq!(storage.phase(), Phase::Live);
        assert_eq!(
            storage.finalize_progress(),
            Progress {
                released: 0,
                retained: 0,
                remaining: 2
            }
        );

        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
        assert_eq!(storage.phase(), Phase::Drained);
        let mut expected = mapped;
        expected.reverse();
        assert_eq!(log.ranges(Op::Unmap), expected);
        assert_eq!(storage.retained().count(), 0);
        assert_eq!(storage.pool_report(), None);
        assert_eq!(storage.root_descriptor(), None);
        assert_eq!(storage.engine_used(), used);
        assert_eq!(
            storage.finalize_progress(),
            Progress {
                released: 2,
                retained: 0,
                remaining: 0
            }
        );

        let calls = log.all().len();
        assert_eq!(finalize(&mut storage), Err(FinalizeError::Drained));
        assert_eq!(log.all().len(), calls);
        drop(storage);
        assert_eq!(log.all().len(), calls);
    }

    /// Dropping an owner that was never finalized unmaps nothing and does
    /// not panic: the mappings are abandoned.
    #[test]
    fn drop_without_finalization_releases_nothing() {
        let slot_count = 4;
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        let storage = storage(slot_count, platform);
        assert_eq!(log.ranges(Op::Map).len(), 2);
        drop(storage);
        assert!(log.ranges(Op::Unmap).is_empty());
    }

    /// A refused release keeps its mapping retained at its base, length,
    /// charge and code, is never retried, and the extents after it still
    /// release exactly once; the result is closing, never drained, and the
    /// phase stays finalizing.
    #[test]
    fn refused_releases_are_retained_reported_charged_and_never_retried() {
        let slot_count = 4;
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        // In reverse order the first release is the pool's control mapping;
        // the root after it still releases.
        {
            let ordinal = 1;
            platform.fail_at(Fail {
                op: Op::Unmap,
                ordinal,
                code: OsCode(16),
                region: None,
            });
        }
        let mut storage = storage(slot_count, platform);
        let mapped = log.ranges(Op::Map);
        let used = storage.engine_used();

        assert_eq!(
            finalize(&mut storage),
            Ok(Finalization::Closing(Progress {
                released: 1,
                retained: 1,
                remaining: 0
            }))
        );
        assert_eq!(storage.phase(), Phase::Finalizing);
        let retained: Vec<_> = storage.retained().collect();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].region, Region::Control);
        assert_eq!((retained[0].base, retained[0].len), mapped[1]);
        assert!(retained.iter().all(|r| r.code == OsCode(16)));
        assert_eq!(storage.engine_used(), used);
        // Each release was attempted exactly once, in reverse order.
        assert_eq!(log.ranges(Op::Unmap), vec![mapped[1], mapped[0]]);
        // Every shared accessor refuses while finalizing.
        assert_eq!(storage.pool_report(), None);
        assert_eq!(storage.root_descriptor(), None);
        assert_eq!(
            storage.close_service(&mut WorkBudget::new(64)),
            Err(CloseError::NotLive)
        );

        // A repeat attempts nothing: the retained extents are not retried.
        let calls = log.all().len();
        assert_eq!(
            finalize(&mut storage),
            Ok(Finalization::Closing(Progress {
                released: 1,
                retained: 1,
                remaining: 0
            }))
        );
        assert_eq!(log.all().len(), calls);
        drop(storage);
        assert_eq!(log.all().len(), calls);
    }

    /// Finalization is prepaid per extent: a zero allowance releases nothing
    /// and leaves the phase live, one unit past the inspection releases
    /// exactly one extent, turns the phase and reports closing, and each
    /// further call resumes from the cursor.
    #[test]
    fn finalization_releases_at_most_the_paid_extents_and_resumes() {
        let slot_count = 4;
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        let mut storage = storage(slot_count, platform);
        let mapped = log.ranges(Op::Map);
        // The inspection: four registration records, the credit count, one
        // gate attempt and four slots under it.
        let inspection = 4 + 1 + 1 + 4;
        let mut zero = WorkBudget::new(0);
        assert_eq!(
            storage.finalize(&mut zero),
            Err(FinalizeError::BudgetExhausted)
        );
        assert_eq!(storage.phase(), Phase::Live);
        assert!(log.ranges(Op::Unmap).is_empty());

        let mut one = WorkBudget::new(inspection + 1);
        assert_eq!(
            storage.finalize(&mut one),
            Ok(Finalization::Closing(Progress {
                released: 1,
                retained: 0,
                remaining: 1
            }))
        );
        assert_eq!(one.remaining(), 0);
        assert_eq!(storage.phase(), Phase::Finalizing);
        assert_eq!(log.ranges(Op::Unmap), vec![mapped[1]]);
        assert_eq!(
            storage.finalize_progress(),
            Progress {
                released: 1,
                retained: 0,
                remaining: 1
            }
        );

        let mut one = WorkBudget::new(1);
        assert_eq!(storage.finalize(&mut one), Ok(Finalization::Drained));
        assert_eq!(log.ranges(Op::Unmap), vec![mapped[1], mapped[0]]);
        assert_eq!(storage.phase(), Phase::Drained);
    }

    /// Finalization never drains while a registration record is claimed,
    /// even when the claim lands between two `finalize` calls on a record
    /// that the earlier call already inspected: either `register` is
    /// refused, or the later `finalize` call reports the claimed record as a
    /// blocker.
    #[test]
    fn a_resumed_inspection_never_misses_a_blocker_that_began_between_calls() {
        let slot_count = 4;
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        let mut storage = storage(slot_count, platform);
        // The inspection visits registration records first, one unit each.
        assert_eq!(
            storage.finalize(&mut WorkBudget::new(1)),
            Err(FinalizeError::BudgetExhausted)
        );
        let forgotten = match storage.register() {
            Ok(registration) => {
                assert_eq!(registration.index().0, 0);
                std::mem::forget(registration);
                true
            }
            Err(_) => false,
        };
        let outcome = finalize(&mut storage);
        if forgotten {
            assert!(
                matches!(outcome, Ok(Finalization::Blocked(blockers)) if blockers.registrations == 1),
                "{outcome:?}"
            );
            assert!(log.ranges(Op::Unmap).is_empty());
        } else {
            assert_eq!(outcome, Ok(Finalization::Drained));
        }
    }

    #[test]
    fn an_inspection_sized_allowance_still_reaches_the_release_stage() {
        let slot_count = 4;
        let platform = TestPlatform::heap(PAGE);
        let log = platform.log();
        let mut storage = storage(slot_count, platform);
        let (records, credit_count, gate_attempt, slots) = (4, 1, 1, 4);
        let inspection = records + credit_count + gate_attempt + slots;
        let mut exact = WorkBudget::new(inspection);
        assert_eq!(
            storage.finalize(&mut exact),
            Err(FinalizeError::BudgetExhausted)
        );
        assert_eq!(exact.remaining(), 0);
        assert_eq!(storage.phase(), Phase::Live);
        assert!(log.ranges(Op::Unmap).is_empty());

        let mut exact = WorkBudget::new(inspection);
        assert_eq!(storage.finalize(&mut exact), Ok(Finalization::Drained));
        let releases = log.ranges(Op::Unmap).len();
        assert_eq!(releases, 2);
        assert_eq!(exact.remaining(), inspection - releases);
    }

    /// `prefetch_record_read` requests shared access to the record's cache
    /// line, allowing a writer on another core to retain a copy.
    #[test]
    fn the_record_read_hint_requests_the_line_shared() {
        use super::super::prefetch::{READ_HINTS, WRITE_HINTS};
        use std::cell::Cell;
        let slot_count = 4;
        let storage = storage(slot_count, TestPlatform::heap(PAGE));
        let pool = storage.live_pool().unwrap();
        let hints = || (READ_HINTS.with(Cell::get), WRITE_HINTS.with(Cell::get));
        let (reads, writes) = hints();
        pool.prefetch_record_read(slot_count - 1);
        assert_eq!(hints(), (reads + 1, writes));
    }
}
