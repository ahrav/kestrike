//! The arena creates one hugepage mapping, charges it before mapping, binds
//! it before first touch, verifies each page, and releases it at most once.
//!
//! Initialization runs in this order and stops at the first failure:
//!
//! 1. Page size, then topology, then the mask's nodes against the topology.
//! 2. The backing length and the pool metadata charged to a copy of the caller's engine budget, and the metadata allocated.
//! 3. One inaccessible hugepage mapping of the whole backing, whose base must
//!    be aligned to the hugepage size.
//! 4. The validated mask bound to the whole mapping, then read and write
//!    access enabled.
//! 5. Per backing page, in address order: population of that page, a
//!    residency probe of its first base page with one status byte, and the
//!    strict placement check against the bound mask.
//! 6. The backing carved into the three pools, every buffer free.
//!
//! Nothing before step 3 maps memory, and the caller's budget is written only
//! when initialization succeeds or when a rollback leaves the mapping
//! retained.
//! Any failure after a successful map releases the mapping once at its base and full extent.
//! A release the kernel refuses is reported with the mapping's base, length and code, and the mapping stays charged.
//! Page indices in every error count backing pages from the base.

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;

use super::super::init::{InitError, InitPhase, os};
use super::super::ledger::EngineBudget;
use super::super::mapping::{Mapping, Region, RetainedMapping};
use super::super::os::{HugepageSize, Platform};
use super::super::owner::PlacementReport;
use super::super::placement::{check_nodes, verify_chunk};
use super::area::DmaArea;
use super::config::{PoolKind, ValidatedBufferConfig};
use super::pool::{Buffer, BufferPoolReport, PoolExhausted, Pools, RxPosted};

/// Owner of one verified hugepage mapping and the platform that made it.
///
/// Dropping an arena leaves its mapping mapped and charged until the process
/// exits; [`release`](Self::release) is the one path that unmaps it. The
/// arena is `!Send` and `!Sync`, which keeps every use on the thread that
/// built it.
///
/// Release needs every registration borrow and every buffer handle ended:
///
/// ```
/// use kestrike::storage::{BufferArena, LinuxPlatform, PoolKind, Released};
///
/// fn use_then_release(arena: BufferArena<LinuxPlatform>) -> Option<Released> {
///     let backing = arena.backing();
///     assert!(backing.extent() >= backing.hugepage().bytes());
///     let mut buffer = arena.acquire(PoolKind::ReadResponse).ok()?;
///     buffer.bytes_mut()[0] = 1;
///     drop(buffer);
///     arena.release().ok()
/// }
/// ```
///
/// and refuses to compile while one is alive:
///
/// ```compile_fail,E0505
/// use kestrike::storage::{BufferArena, LinuxPlatform};
///
/// fn release_while_registered(arena: BufferArena<LinuxPlatform>) {
///     let backing = arena.backing();
///     arena.release();
///     let _ = backing.base();
/// }
/// ```
///
/// nor while a buffer handle is alive:
///
/// ```compile_fail,E0505
/// use kestrike::storage::{BufferArena, LinuxPlatform, PoolKind};
///
/// fn release_while_held(arena: BufferArena<LinuxPlatform>) {
///     let buffer = arena.acquire(PoolKind::Maintenance).unwrap();
///     let _ = arena.release();
///     let _ = buffer.offset();
/// }
/// ```
///
/// Moving an arena to another thread does not compile:
///
/// ```compile_fail,E0277
/// use kestrike::storage::{BufferArena, LinuxPlatform};
///
/// fn requires_send<T: Send>(_: T) {}
///
/// fn send(arena: BufferArena<LinuxPlatform>) {
///     requires_send(arena);
/// }
/// ```
///
/// nor does sharing one:
///
/// ```compile_fail,E0277
/// use kestrike::storage::{BufferArena, LinuxPlatform};
///
/// fn requires_sync<T: Sync>(_: &T) {}
///
/// fn share(arena: &BufferArena<LinuxPlatform>) {
///     requires_sync(arena);
/// }
/// ```
pub struct BufferArena<P: Platform> {
    platform: P,
    mapping: Mapping,
    config: ValidatedBufferConfig,
    pools: Pools,
    /// Outstanding [`RegistrationHold`]s, ended or not.
    registrations: Cell<u32>,
}

/// A failed initialization: what failed, and the mapping a refused rollback
/// left owned and charged, if any. No arena exists after a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaFailure {
    pub error: InitError,
    pub retained: Option<RetainedMapping>,
}

/// A release refused while buffers, device mempools or device registrations hold the arena; the arena comes back unchanged with its backing mapped.
pub struct ReleaseBlocked<P: Platform> {
    pub arena: BufferArena<P>,
    /// Buffers neither free nor retired, per kind.
    pub held: [(PoolKind, u32); PoolKind::ALL.len()],
    /// Whether a device mempool serves each kind.
    pub served: [(PoolKind, bool); PoolKind::ALL.len()],
    /// Device registrations whose hold has not ended.
    pub registrations: u32,
}

impl<P: Platform> fmt::Debug for ReleaseBlocked<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseBlocked")
            .field("arena", &self.arena)
            .field("held", &self.held)
            .field("served", &self.served)
            .field("registrations", &self.registrations)
            .finish()
    }
}

/// Outcome of [`BufferArena::release`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// The kernel unmapped the whole backing.
    Complete,
    /// The kernel refused; the mapping stays owned and charged, and nothing
    /// retries it.
    Retained(RetainedMapping),
}

/// The arena's backing, described for a driver that registers it with a
/// device. It never exposes the memory itself: the base is a pointer only
/// `unsafe` code can dereference. The token borrows the arena, so the arena
/// cannot be released while the token lives. The borrow ends at the token's
/// last use, so a driver keeps the token inside its registration guard, a
/// type with `Drop`, until the device has stopped and the registration is
/// undone. The guard's undo, after the device stops, ends device access to
/// the arena.
#[derive(Debug, Clone, Copy)]
pub struct ArenaBacking<'a> {
    base: NonNull<u8>,
    extent: usize,
    hugepage: HugepageSize,
    arena: PhantomData<&'a ()>,
}

/// A device registration's claim on the arena, from [`BufferArena::hold_registration`].
///
/// The hold borrows the arena, so release does not compile while it lives,
/// and it counts against release at run time until [`end`](Self::end) runs.
/// Dropping or forgetting a hold without ending it keeps the arena
/// unreleasable: a registration whose undo was never proven retains the
/// backing for the life of the process.
#[derive(Debug)]
pub struct RegistrationHold<'a> {
    backing: ArenaBacking<'a>,
    count: &'a Cell<u32>,
}

impl RegistrationHold<'_> {
    pub fn backing(&self) -> ArenaBacking<'_> {
        self.backing
    }

    /// Ends the claim. Call only once every device that could reach the
    /// arena through the registration has a proven stop and the
    /// registration is undone.
    pub(crate) fn end(self) {
        self.count.set(self.count.get() - 1);
    }
}

impl ArenaBacking<'_> {
    pub fn base(&self) -> NonNull<u8> {
        self.base
    }

    pub fn extent(&self) -> usize {
        self.extent
    }

    pub fn hugepage(&self) -> HugepageSize {
        self.hugepage
    }
}

impl<P: Platform> BufferArena<P> {
    /// Maps, binds, populates and verifies the backing of `config`, charging it to `budget`.
    ///
    /// # Errors
    ///
    /// Before any mapping, with `retained: None` and `budget` unchanged:
    /// `PageSizeUnavailable`, `TopologyUnavailable`, `Placement` naming
    /// `Region::Buffers`, then `Envelope` for the backing plus the pool metadata.
    ///
    /// After a mapping attempt, errors occur in this order:
    ///
    /// - `Os` with phase `Map`, then `MisalignedBase`.
    /// - `Os` with phase `Placement` for the bind, then `Os` with phase `Protect`.
    /// - Per backing page in address order: `Os` with phase `Populate` or `VerifyPopulation`, `Unpopulated`, then `Os` with phase `VerifyPlacement`, `PageStatusError` or `WrongNode`.
    ///
    /// A page index in an error counts backing pages from the base.
    /// A failed map leaves nothing to release; any later failure releases the mapping once.
    /// When `retained` is `Some`, `budget` carries the backing's charge.
    pub fn initialize(
        config: &ValidatedBufferConfig,
        platform: P,
        budget: &mut EngineBudget,
    ) -> Result<Self, ArenaFailure> {
        let refused = |error| ArenaFailure {
            error,
            retained: None,
        };
        let page_size = platform
            .page_size()
            .map_err(|code| refused(InitError::PageSizeUnavailable(code)))?;
        let topology = platform
            .topology()
            .map_err(|code| refused(InitError::TopologyUnavailable(code)))?;
        check_nodes(Region::Buffers, config.nodes(), &topology)
            .map_err(|error| refused(InitError::Placement(error)))?;
        let [backing, metadata] = config.charges();
        let mut charged = *budget;
        charged
            .charge(backing)
            .map_err(|exceeded| refused(InitError::Envelope(exceeded)))?;
        let backing_charged = charged;
        charged
            .charge(metadata)
            .map_err(|exceeded| refused(InitError::Envelope(exceeded)))?;
        let pools = Pools::with_capacity(config);
        let base = platform
            .map_hugepages(config.backing_len(), config.hugepage())
            .map_err(|code| refused(os(InitPhase::Map, Region::Buffers)(code)))?;
        let mut arena = Self {
            platform,
            mapping: Mapping::owned(Region::Buffers, base, config.backing_len()),
            config: *config,
            pools,
            registrations: Cell::new(0),
        };
        if let Err(error) = arena.bring_up(page_size) {
            let retained = arena.release_mapping();
            if retained.is_some() {
                *budget = backing_charged;
            }
            return Err(ArenaFailure { error, retained });
        }
        // SAFETY: the backing is live, populated and so zero-filled, writable, `base` carries its provenance, and nothing else reaches it yet.
        let whole = unsafe { DmaArea::new(base, 0, arena.mapping.len()) }.unwrap_or_else(|_| {
            unreachable!("the backing is a positive hugepage multiple at an aligned base")
        });
        // SAFETY: `whole` is the entire backing, sized from the configuration the pools were built from, and this is the arena's only carve.
        // The arena owns the pools and the mapping together and unmaps only in `release`, which consumes both, so the backing outlives every handle.
        unsafe { arena.pools.carve(whole) };
        *budget = charged;
        Ok(arena)
    }

    fn bring_up(&mut self, page_size: usize) -> Result<(), InitError> {
        let region = Region::Buffers;
        let base = self.mapping.base();
        let len = self.mapping.len();
        let unit = self.config.hugepage().bytes();
        if !base.as_ptr().addr().is_multiple_of(unit) {
            return Err(InitError::MisalignedBase {
                region,
                base: base.as_ptr().addr(),
                align: unit,
            });
        }
        let nodes = *self.config.nodes();
        // SAFETY: `base` and `len` are the original base and full extent of the live mapping this platform's `map_hugepages` returned, still owned by the arena.
        unsafe { self.platform.bind(base, len, &nodes) }
            .map_err(os(InitPhase::Placement, region))?;
        // SAFETY: as above.
        unsafe { self.platform.protect_read_write(base, len) }
            .map_err(os(InitPhase::Protect, region))?;
        let mut status = [0u8; 1];
        for page in 0..len / unit {
            // SAFETY: `page * unit < len <= isize::MAX`, so the offset stays inside the live mapping.
            let start = unsafe { base.add(page * unit) };
            // SAFETY: `start` is hugepage-aligned because the base is, so `start..start + unit` is one whole backing page of the readable and writable mapping.
            unsafe { self.platform.populate_write(start, unit) }
                .map_err(os(InitPhase::Populate, region))?;
            // SAFETY: `start..start + page_size` lies inside that backing
            // page, and the status buffer holds its one byte. A hugepage is
            // resident as a whole, so its first base page answers for it.
            unsafe { self.platform.residency(start, page_size, &mut status) }
                .map_err(os(InitPhase::VerifyPopulation, region))?;
            if status[0] & 1 == 0 {
                return Err(InitError::Unpopulated { region, page });
            }
            // SAFETY: `start..start + unit` is one populated backing page of the readable mapping; passing `unit` as the page size makes a refused range check query that one page.
            unsafe { verify_chunk(&self.platform, region, start, unit, unit, page, &nodes) }?;
        }
        self.mapping.set_pages_verified(len / unit);
        Ok(())
    }

    /// Releases the mapping if still owned, and reports it if the kernel
    /// refused.
    fn release_mapping(&mut self) -> Option<RetainedMapping> {
        // SAFETY: every reference into the mapping comes from a `Buffer` byte view, and every `Buffer` and `ArenaBacking` borrows the arena, so none survives into a call that holds the arena mutably or by value.
        unsafe { self.mapping.release(&self.platform) }.err()?;
        self.mapping.retained()
    }

    /// Unmaps the backing once and reports whether the kernel took it back.
    /// Taking the arena by value requires every [`ArenaBacking`] and [`Buffer`] borrow to have ended.
    /// A handle leaked with `mem::forget` still holds its buffer, and release
    /// refuses while any pool kind's `held` count is nonzero.
    ///
    /// Release also refuses while a [`RegistrationHold`] has not ended or a
    /// device mempool serves a kind.
    ///
    /// # Errors
    ///
    /// Release returns [`ReleaseBlocked`] with the arena and holder counts when any `held` count is nonzero, any kind is served, or any registration hold remains active; the backing stays mapped.
    #[expect(
        clippy::result_large_err,
        reason = "a refused release hands the arena back by value; boxing it would allocate on the release path"
    )]
    pub fn release(mut self) -> Result<Released, ReleaseBlocked<P>> {
        let held = self.pools.held();
        let served = self.pools.served_kinds();
        let registrations = self.registrations.get();
        if registrations > 0
            || held.iter().any(|(_, count)| *count > 0)
            || served.iter().any(|(_, served)| *served)
        {
            return Err(ReleaseBlocked {
                arena: self,
                held,
                served,
                registrations,
            });
        }
        Ok(self
            .release_mapping()
            .map_or(Released::Complete, Released::Retained))
    }

    /// Pops any free buffer of `kind`, most recently freed first.
    ///
    /// # Errors
    ///
    /// `PoolExhausted` when every buffer of `kind` is held, or while a
    /// [`PacketPool`](crate::net::PacketPool) view holds `kind`, whose
    /// leases alone take its buffers, or a device mempool serves it; other
    /// kinds are unaffected and nothing changes.
    pub fn acquire(&self, kind: PoolKind) -> Result<Buffer<'_>, PoolExhausted> {
        if self.pools.viewed(kind) || self.pools.served(kind) {
            return Err(PoolExhausted { kind });
        }
        self.pools.acquire(kind)
    }

    /// Pops a free buffer of `kind` and posts it to a device for receive; see [`RxPosted`].
    ///
    /// # Errors
    ///
    /// `PoolExhausted` when every buffer of `kind` is held, the arena has
    /// none, a [`PacketPool`](crate::net::PacketPool) view holds `kind`, or
    /// a device mempool serves it.
    pub fn post(&self, kind: PoolKind) -> Result<RxPosted<'_>, PoolExhausted> {
        if self.pools.viewed(kind) || self.pools.served(kind) {
            return Err(PoolExhausted { kind });
        }
        self.pools.post(kind)
    }

    /// Returns one device reference a device took over with [`NicHold::into_raw`](super::NicHold::into_raw) or a handle's `into_device`; a return naming no live reference is counted and changes nothing.
    ///
    /// # Safety
    ///
    /// When `(kind, index, incarnation)` names a live reference, the caller
    /// took that reference over once, with `into_raw` or `into_device`, on
    /// this arena's pools and this is its only return; a return of another holder's reference would
    /// let that holder read a buffer the pool already reused.
    ///
    /// Safe code cannot return a reference it does not own:
    ///
    /// ```compile_fail,E0133
    /// # fn forge<P: kestrike::storage::Platform>(arena: &kestrike::storage::BufferArena<P>, hold: kestrike::storage::NicHold<'_>) {
    /// let (kind, index, incarnation) = hold.identity();
    /// arena.nic_return(kind, index, incarnation);
    /// # }
    /// ```
    pub unsafe fn nic_return(&self, kind: PoolKind, index: u32, incarnation: u64) -> bool {
        // SAFETY: the caller's contract.
        unsafe { self.pools.nic_return(kind, index, incarnation) }
    }

    pub fn report(&self, kind: PoolKind) -> BufferPoolReport {
        self.pools.report(kind)
    }

    pub(crate) fn pools(&self) -> &Pools {
        &self.pools
    }

    /// The backing for device registration; see [`ArenaBacking`].
    pub fn backing(&self) -> ArenaBacking<'_> {
        ArenaBacking {
            base: self.mapping.base(),
            extent: self.mapping.len(),
            hugepage: self.config.hugepage(),
            arena: PhantomData,
        }
    }

    /// Claims the backing for a device registration; see [`RegistrationHold`].
    ///
    /// # Panics
    ///
    /// When `u32::MAX` holds are outstanding, which no registration path reaches.
    pub(crate) fn hold_registration(&self) -> RegistrationHold<'_> {
        let count = self.registrations.get().checked_add(1);
        self.registrations.set(count.unwrap_or_else(|| {
            unreachable!("registration holds are bounded by the process's devices")
        }));
        RegistrationHold {
            backing: self.backing(),
            count: &self.registrations,
        }
    }

    /// The bound mask and the backing pages the placement check covered.
    pub fn placement(&self) -> PlacementReport {
        PlacementReport {
            nodes: *self.config.nodes(),
            pages_verified: self.mapping.pages_verified(),
        }
    }

    pub fn config(&self) -> &ValidatedBufferConfig {
        &self.config
    }
}

impl<P: Platform> fmt::Debug for BufferArena<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferArena")
            .field("mapping", &self.mapping)
            .field("config", &self.config)
            .field("pools", &self.pools)
            .finish_non_exhaustive()
    }
}
