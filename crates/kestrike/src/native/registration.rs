//! The shared arena registration guard, which owns the arena's device-facing
//! state for every device in the process.
//!
//! Register runs in this order and stops at the first failure: posture
//! selection, capacity checks, per-page IOVAs, DPDK external memory, SPDK
//! translations. [`map`](ArenaRegistration::map) runs once after a VFIO
//! device attaches, and [`verify`](ArenaRegistration::verify) checks every
//! backing page through SPDK and DPDK. Undo runs SPDK, then the container
//! mapping, then the external memory, each under the caller's watchdog.

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::dma::{DmaMode, DmaPolicy, DmaPort, DmaReport, NativeDma};
use super::env::Environment;
use super::watchdog::Watchdog;
use crate::storage::{BufferArena, Platform, RegistrationHold};

/// A step of registration or undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationStep {
    /// The observed IOVA, IOMMU and VFIO modes admit no posture under the policy.
    Mode,
    /// No external memseg list is free, or the lock limit cannot cover an IOMMU mapping.
    Capacity,
    /// A backing page's physical address lookup fails, or its IOVA violates hugepage alignment.
    Address,
    ExtmemRegister,
    SpdkRegister,
    /// `map` ran before, or the container refused the mapping.
    Map,
    /// The registration is not mapped, or a page's translation is short or wrong.
    Verify,
    /// A device attached to the registration has not proved its stop.
    DeviceStop,
    SpdkUnregister,
    Unmap,
    ExtmemUnregister,
    /// The teardown watchdog expired; the supervisor was asked to contain.
    Watchdog,
}

/// A failed step. `retained` reports that native state may remain that no
/// later call undoes, including state whose undo the watchdog cut short, so
/// the arena stays held for the life of the process. A `Map` or `Verify` failure is not retained: the
/// registration lives on and [`unregister`](ArenaRegistration::unregister)
/// still undoes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationError {
    pub step: RegistrationStep,
    /// The native error number, when the step was a native call.
    pub code: Option<i32>,
    /// The backing page the step failed on, when it is per page.
    pub page: Option<usize>,
    pub retained: bool,
}

/// `RegistrationId` ties a lease and its stop proof to the registration that leased the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegistrationId(u64);

static NEXT_REGISTRATION: AtomicU64 = AtomicU64::new(0);

impl RegistrationId {
    fn next() -> Self {
        Self(NEXT_REGISTRATION.fetch_add(1, Ordering::Relaxed))
    }

    /// The identity scripted drivers and proofs share.
    #[cfg(test)]
    pub(crate) const SCRIPTED: Self = Self(u64::MAX);
}

/// `DeviceId` names one leased device: the registration that leased it and
/// the lease's number among that registration's leases, so no two leases
/// share one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeviceId {
    registration: RegistrationId,
    lease: u64,
}

impl DeviceId {
    /// The registration that leased the device.
    pub(crate) fn registration(self) -> RegistrationId {
        self.registration
    }
}

/// A registration's readiness, shared with the drivers that read it: set by a passing
/// [`verify`](ArenaRegistration::verify) and cleared by a failed verify or recheck.
#[derive(Debug, Clone, Default)]
pub(crate) struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// Whether every page verified and no check since found one changed.
    pub(crate) fn get(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }

    /// Readiness that stays set, for scripted drivers with no registration.
    #[cfg(test)]
    pub(crate) fn verified() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
}

/// One device that can reach the arena through the registration, from
/// [`ArenaRegistration::device_attached`]. The device's driver keeps the
/// lease until it observes the device's stop and turns the lease into a
/// [`DeviceStopped`]; a lease dropped instead leaves the registration
/// unable to undo. The lease reads its registration's readiness, so a driver
/// that holds only the lease can refuse to let the device reach memory after
/// a failed verify or recheck.
#[must_use = "a dropped lease keeps the registration from ever undoing"]
#[derive(Debug)]
pub struct DeviceLease {
    device: DeviceId,
    ready: Readiness,
}

impl DeviceLease {
    /// The registration that leased the device.
    pub(crate) fn registration(&self) -> RegistrationId {
        self.device.registration()
    }

    /// The leased device, which its stop proof names too.
    pub(crate) fn device(&self) -> DeviceId {
        self.device
    }

    /// Whether the leasing registration is ready, as
    /// [`ArenaRegistration::is_ready`] reports it now.
    pub(crate) fn ready(&self) -> bool {
        self.ready.get()
    }

    /// The proof a driver hands back once it observed the device's stop.
    pub(crate) fn stopped(self) -> DeviceStopped {
        DeviceStopped(self.device)
    }
}

/// Proof that one leased device stopped and can no longer reach the arena.
/// Only [`DeviceLease`] creates one, and it names that lease's device.
#[derive(Debug)]
pub struct DeviceStopped(DeviceId);

impl DeviceStopped {
    /// The device whose stop this proves.
    pub(crate) fn device(&self) -> DeviceId {
        self.0
    }
}

/// Proof that one registration was undone; the devices it leased detach after it.
///
/// The proof keeps the registration's borrow of the [`Environment`] for `'a`.
/// A device detaches only against a proof, and its detach is a native call
/// on state the environment's memory holds, so the environment cannot finish
/// while a proof a detach may still be shown lives:
///
/// ```compile_fail,E0505
/// use kestrike::native::{ArenaRegistration, DmaPolicy, Environment, Watchdog};
/// use kestrike::storage::{BufferArena, LinuxPlatform};
///
/// fn finish_before_detach(
///     env: Environment,
///     arena: &BufferArena<LinuxPlatform>,
///     watchdog: &Watchdog,
/// ) {
///     let policy = DmaPolicy { allow_no_iommu: false };
///     let Ok(registration) = ArenaRegistration::register(&env, arena, policy) else {
///         return;
///     };
///     let Ok(undone) = registration.unregister(watchdog) else {
///         return;
///     };
///     let _ = env.finish(watchdog);
///     drop(undone);
/// }
/// ```
#[derive(Debug)]
pub struct Unregistered<'a>(RegistrationId, PhantomData<&'a Environment>);

impl Unregistered<'_> {
    /// Whether this proof undid `registration`.
    pub(crate) fn undid(&self, registration: RegistrationId) -> bool {
        self.0 == registration
    }

    #[cfg(test)]
    pub(crate) fn scripted() -> Self {
        Self(RegistrationId::SCRIPTED, PhantomData)
    }
}

/// An undo that failed or was not attempted. Dropping it drops the guard,
/// but the arena's hold and the environment's count never end, so the arena
/// stays unreleasable and the environment unfinishable until the process ends.
pub struct Retained<'a> {
    pub error: RegistrationError,
    registration: Box<ArenaRegistration<'a>>,
}

impl fmt::Debug for Retained<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retained")
            .field("error", &self.error)
            .field("registration", &self.registration)
            .finish()
    }
}

impl Retained<'_> {
    pub fn report(&self) -> DmaReport {
        self.registration.report()
    }
}

/// The arena's registration with DPDK and SPDK, and its IOMMU mapping.
///
/// The guard borrows the arena, so the arena cannot be released while it lives:
///
/// ```compile_fail,E0505
/// use kestrike::native::{ArenaRegistration, DmaPolicy, Environment};
/// use kestrike::storage::{BufferArena, LinuxPlatform};
///
/// fn release_while_registered(env: &Environment, arena: BufferArena<LinuxPlatform>) {
///     let policy = DmaPolicy { allow_no_iommu: false };
///     let registration = ArenaRegistration::register(env, &arena, policy);
///     let _ = arena.release();
///     drop(registration);
/// }
/// ```
///
/// It also borrows the [`Environment`], which therefore cannot finish while the guard lives.
///
/// Dropping the guard without a successful
/// [`unregister`](Self::unregister) keeps the arena's
/// [`RegistrationHold`], so release refuses at run time as well.
pub struct ArenaRegistration<'a> {
    id: RegistrationId,
    env: &'a Environment,
    hold: RegistrationHold<'a>,
    port: Box<dyn DmaPort>,
    report: DmaReport,
    iovas: Vec<u64>,
    page_shift: u32,
    mapped: bool,
    /// Whether every page's translation verified and no recheck since found one changed.
    verified: Readiness,
    /// Leased devices not yet proven stopped.
    devices: u32,
    /// Leases made, which numbers the next one; one per nanosecond takes about 584 years to reach `u64::MAX`.
    leases: u64,
}

impl fmt::Debug for ArenaRegistration<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArenaRegistration")
            .field("id", &self.id)
            .field("report", &self.report)
            .field("mapped", &self.mapped)
            .field("verified", &self.verified.get())
            .field("devices", &self.devices)
            .finish_non_exhaustive()
    }
}

/// Pages whose DPDK translations one `dpdk_translations` call of the check
/// gathers into a 1 KiB stack array; while those pages lie in one memseg
/// list, DPDK's list table is searched once per chunk.
pub(super) const CHECK_CHUNK: usize = 64;

fn error(
    step: RegistrationStep,
    code: Option<i32>,
    page: Option<usize>,
    retained: bool,
) -> RegistrationError {
    // A zero native code means the call recorded no error number.
    RegistrationError {
        step,
        code: code.filter(|&code| code != 0),
        page,
        retained,
    }
}

impl<'a> ArenaRegistration<'a> {
    /// Registers the whole arena with the initialized environment's DPDK and SPDK.
    ///
    /// # Errors
    ///
    /// The first failed step. A failure before external registration, or one
    /// whose cleanup succeeded, leaves the arena releasable; a failed cleanup
    /// is reported `retained` and keeps the arena held.
    pub fn register<P: Platform>(
        env: &'a Environment,
        arena: &'a BufferArena<P>,
        policy: DmaPolicy,
    ) -> Result<Self, RegistrationError> {
        Self::register_with(env, arena.hold_registration(), policy, Box::new(NativeDma))
    }

    pub(crate) fn register_with(
        env: &'a Environment,
        hold: RegistrationHold<'a>,
        policy: DmaPolicy,
        mut port: Box<dyn DmaPort>,
    ) -> Result<Self, RegistrationError> {
        let backing = hold.backing();
        let (base, extent, page) = (
            backing.base().as_ptr().addr(),
            backing.extent(),
            backing.hugepage().bytes(),
        );
        let iova_mode = port.iova_mode();
        let refuse = |hold: RegistrationHold<'a>, step, code, page| {
            hold.end();
            Err(error(step, code, page, false))
        };
        // An unreadable IOMMU class is no observation of either posture.
        let Some(guest_iommu) = port.guest_iommu() else {
            return refuse(hold, RegistrationStep::Mode, None, None);
        };
        let vfio_no_iommu = port.vfio_no_iommu();
        let Some(mode) = DmaMode::select(iova_mode, guest_iommu, vfio_no_iommu, policy) else {
            return refuse(hold, RegistrationStep::Mode, None, None);
        };
        let lockable = u64::try_from(extent).is_ok_and(|extent| port.memlock_limit() >= extent);
        if port.free_memseg_lists() == 0 || (mode == DmaMode::Iommu && !lockable) {
            return refuse(hold, RegistrationStep::Capacity, None, None);
        }
        let pages = extent / page;
        let (iovas, physical_pages): (Vec<u64>, usize) = match mode {
            DmaMode::Iommu => (
                (0..pages)
                    .map(|index| (base + index * page) as u64)
                    .collect(),
                0,
            ),
            DmaMode::NoIommu => match port.physical_addresses(base, page, pages) {
                Ok(addresses) => {
                    let found = addresses.len();
                    (addresses, found)
                }
                Err(index) => return refuse(hold, RegistrationStep::Address, None, Some(index)),
            },
        };
        if let Some(index) = iovas
            .iter()
            .position(|iova| !iova.is_multiple_of(page as u64))
        {
            return refuse(hold, RegistrationStep::Address, None, Some(index));
        }
        // SAFETY: the populated hugepage backing stays mapped while `hold` is
        // outstanding, and a hold that never ends keeps it mapped for the
        // process's life; `iovas` has one IOVA per backing page.
        if let Err(code) = unsafe { port.extmem_register(base, extent, &iovas, page) } {
            return refuse(hold, RegistrationStep::ExtmemRegister, Some(code), None);
        }
        // From here native state may outlive a failure, so the environment counts it.
        env.registered();
        // SAFETY: as above, and DPDK now holds the range as external memory.
        if let Err(code) = unsafe { port.spdk_register(base, extent) } {
            let spdk_undone = code == libc::EBUSY || port.spdk_unregister(base, extent).is_ok();
            if spdk_undone && port.extmem_unregister(base, extent).is_ok() {
                env.unregistered();
                return refuse(hold, RegistrationStep::SpdkRegister, Some(code), None);
            }
            return Err(error(
                RegistrationStep::SpdkRegister,
                Some(code),
                None,
                true,
            ));
        }
        let report = DmaReport {
            iova_mode,
            guest_iommu,
            vfio_no_iommu,
            mode,
            extent,
            page_size: page,
            mappings: 0,
            verified_pages: 0,
            physical_pages,
            translated_bytes: 0,
        };
        Ok(Self {
            id: RegistrationId::next(),
            env,
            hold,
            port,
            report,
            iovas,
            page_shift: page.trailing_zeros(),
            mapped: false,
            verified: Readiness::default(),
            devices: 0,
            leases: 0,
        })
    }

    /// The arena backing's base address and extent in bytes.
    pub(crate) fn range(&self) -> (usize, usize) {
        let backing = self.hold.backing();
        (backing.base().as_ptr().addr(), backing.extent())
    }

    /// Establishes the arena's device mapping once, after the VFIO devices
    /// attach to the default container: one checked container mapping in
    /// IOMMU mode, none in no-IOMMU mode.
    ///
    /// # Errors
    ///
    /// `Map` when the registration was mapped before or the container refused.
    pub fn map(&mut self) -> Result<(), RegistrationError> {
        if self.mapped {
            return Err(error(RegistrationStep::Map, None, None, false));
        }
        if self.report.mode == DmaMode::Iommu {
            let (base, extent) = self.range();
            // SAFETY: the range is registered with DPDK and SPDK and the hold keeps it live until unmap.
            unsafe { self.port.container_map(base, base as u64, extent) }
                .map_err(|code| error(RegistrationStep::Map, Some(code), None, false))?;
            self.report.mappings = 1;
        }
        self.mapped = true;
        Ok(())
    }

    /// Checks every backing page: SPDK must translate the whole page to its
    /// IOVA and DPDK must report the same IOVA. Software translations do not
    /// prove a device mapping, so verify requires a successful [`map`](Self::map).
    ///
    /// # Errors
    ///
    /// `Verify` for an unmapped registration, or naming the first page whose translation is missing, short or wrong.
    /// A failed check invalidates any previous verification and resets `report.verified_pages` and `report.translated_bytes` to zero.
    pub fn verify(&mut self) -> Result<DmaReport, RegistrationError> {
        if !self.mapped {
            return Err(error(RegistrationStep::Verify, None, None, false));
        }
        self.report.translated_bytes = self.check().inspect_err(|_| {
            self.verified.set(false);
            self.report.verified_pages = 0;
            self.report.translated_bytes = 0;
        })?;
        self.report.verified_pages = self.iovas.len();
        self.verified.set(true);
        Ok(self.report)
    }

    /// Repeats [`verify`](Self::verify)'s check of every page on a verified
    /// registration, which a device restart runs before its queues name arena
    /// memory again.
    ///
    /// # Errors
    ///
    /// `Verify` for an unverified registration, or naming the first page whose translation changed; the registration is then unverified, so pools, ports, IOVA lookups and the arena commands of every driver holding its [`readiness`](Self::readiness) refuse until a later [`verify`](Self::verify) passes.
    pub fn recheck(&self) -> Result<(), RegistrationError> {
        if !self.verified.get() {
            return Err(error(RegistrationStep::Verify, None, None, false));
        }
        self.check()
            .map(drop)
            .inspect_err(|_| self.verified.set(false))
    }

    /// The bytes SPDK translated, the sum of the lengths it returned, once
    /// each page translates to its IOVA over the whole page and DPDK reports
    /// the same IOVA. SPDK answers once per run of pages whose IOVAs continue
    /// one another page by page: the run's pages its translation covers whole
    /// from the run's IOVA pass, and the first page past them is the first
    /// whose own translation is missing, short or wrong. DPDK answers for up
    /// to [`CHECK_CHUNK`] pages at a time, up to the first page SPDK refused,
    /// so the page an error names is the lowest that fails either check.
    fn check(&self) -> Result<usize, RegistrationError> {
        let (base, page, shift) = (self.range().0, self.report.page_size, self.page_shift);
        let iovas = &self.iovas[..];
        let fail = |index| Err(error(RegistrationStep::Verify, None, Some(index), false));
        let (mut translated, mut start, mut refused) = (0, 0, None);
        while start < iovas.len() {
            let (expected, mut end) = (iovas[start], start + 1);
            while end < iovas.len() && iovas[end] == iovas[end - 1].wrapping_add(page as u64) {
                end += 1;
            }
            let run = end - start;
            let covered = match self
                .port
                .spdk_translate(base + (start << shift), run << shift)
            {
                Some((iova, len)) if iova == expected => {
                    translated += len;
                    len >> shift
                }
                _ => 0,
            };
            if covered < run {
                refused = Some(start + covered);
                break;
            }
            start = end;
        }
        let mut dpdk = [None; CHECK_CHUNK];
        let checked = &iovas[..refused.unwrap_or(iovas.len())];
        for (chunk, expected) in checked.chunks(CHECK_CHUNK).enumerate() {
            let (first, dpdk) = (chunk * CHECK_CHUNK, &mut dpdk[..expected.len()]);
            self.port
                .dpdk_translations(base + (first << shift), page, dpdk);
            let mut pairs = expected.iter().zip(dpdk.iter());
            if let Some(at) = pairs.position(|(&iova, &native)| native != Some(iova)) {
                return fail(first + at);
            }
        }
        refused.map_or(Ok(translated), fail)
    }

    /// The identity leases and proofs of this registration carry.
    pub(crate) fn id(&self) -> RegistrationId {
        self.id
    }

    /// Counts leased devices awaiting proof of their stop. A device stays counted when its attach fails after
    /// leasing it.
    pub(crate) fn devices(&self) -> u32 {
        self.devices
    }

    /// Whether every page verified, the precondition for any arena command or descriptor.
    pub fn is_ready(&self) -> bool {
        self.verified.get()
    }

    /// A handle that reads [`is_ready`](Self::is_ready) for as long as it lives, so a driver that installed arena
    /// bounds while the registration was ready refuses arena commands once a check revokes readiness.
    pub(crate) fn readiness(&self) -> Readiness {
        self.verified.clone()
    }

    pub fn report(&self) -> DmaReport {
        self.report
    }

    /// The device-facing address of the `len` bytes at `va`, from the
    /// registration's explicit per-page IOVAs, when the registration verified
    /// every page and the range lies inside one backing page of the arena.
    pub fn iova(&self, va: usize, len: usize) -> Option<u64> {
        let (base, extent) = self.range();
        let shift = self.page_shift;
        let offset = va.checked_sub(base)?;
        let end = offset.checked_add(len)?;
        let ok = self.verified.get()
            && len > 0
            && end <= extent
            && offset >> shift == (end - 1) >> shift;
        ok.then(|| self.iovas[offset >> shift] + (offset & ((1 << shift) - 1)) as u64)
    }

    /// Each buffer's offset from its address to the IOVA [`iova`](Self::iova)
    /// returns for the whole buffer.
    ///
    /// A buffer yields `None` when it starts below the arena or at or past its
    /// extent, crosses a backing-page boundary or the extent, has zero length,
    /// or the registration is unverified. The buffers inside one backing page
    /// share that page's offset, so the table fills one run per page.
    pub(crate) fn offsets(&self, span: usize, len: usize, count: usize) -> Box<[Option<u64>]> {
        let (base, extent) = self.range();
        let shift = self.page_shift;
        let ready = self.verified.get() && len > 0;
        let mut offsets = Vec::with_capacity(count);
        while offsets.len() < count {
            let va = span + offsets.len() * len;
            let Some(offset) = va.checked_sub(base).filter(|&at| ready && at < extent) else {
                offsets.push(None);
                continue;
            };
            let page = offset >> shift;
            let end = ((page + 1) << shift).min(extent);
            let run = ((end - offset) / len).min(count - offsets.len());
            if run == 0 {
                offsets.push(None);
                continue;
            }
            let to_device = self.iovas[page].wrapping_sub((base + (page << shift)) as u64);
            offsets.resize(offsets.len() + run, Some(to_device));
        }
        offsets.into_boxed_slice()
    }

    /// Leases one device that can reach the arena through this registration;
    /// undo waits for every lease to come back as a [`DeviceStopped`].
    pub fn device_attached(&mut self) -> DeviceLease {
        let count = self.devices.checked_add(1);
        self.devices = count
            .unwrap_or_else(|| unreachable!("devices are bounded by the process's PCI devices"));
        let lease = self.leases;
        self.leases = lease + 1;
        DeviceLease {
            device: DeviceId {
                registration: self.id,
                lease,
            },
            ready: self.verified.clone(),
        }
    }

    /// Retires one leased device whose driver proved its stop.
    pub fn device_stopped(&mut self, stopped: DeviceStopped) -> Result<(), RegistrationError> {
        if stopped.0.registration != self.id {
            return Err(error(RegistrationStep::DeviceStop, None, None, false));
        }
        self.devices = self.devices.saturating_sub(1);
        Ok(())
    }

    /// Undoes the registration: SPDK first, while DPDK's external memory
    /// exists, then the container mapping, while the devices remain
    /// attached, then the external memory. Each step runs only while
    /// `watchdog` has not expired.
    ///
    /// # Errors
    ///
    /// [`Retained`] when a device has not proved its stop, a step fails, or
    /// the watchdog expired; the arena stays held.
    pub fn unregister(mut self, watchdog: &Watchdog) -> Result<Unregistered<'a>, Retained<'a>> {
        if let Err((step, code)) = self.undo(watchdog) {
            return Err(Retained {
                error: error(step, code, None, true),
                registration: Box::new(self),
            });
        }
        self.env.unregistered();
        self.hold.end();
        Ok(Unregistered(self.id, PhantomData))
    }

    fn undo(&mut self, watchdog: &Watchdog) -> Result<(), (RegistrationStep, Option<i32>)> {
        let (base, extent) = self.range();
        let alive = || {
            if watchdog.expired() {
                Err((RegistrationStep::Watchdog, None))
            } else {
                Ok(())
            }
        };
        if self.devices > 0 {
            return Err((RegistrationStep::DeviceStop, None));
        }
        alive()?;
        self.port
            .spdk_unregister(base, extent)
            .map_err(|code| (RegistrationStep::SpdkUnregister, Some(code)))?;
        if self.mapped && self.report.mode == DmaMode::Iommu {
            alive()?;
            self.port
                .container_unmap(base, base as u64, extent)
                .map_err(|code| (RegistrationStep::Unmap, Some(code)))?;
            self.report.mappings = 0;
        }
        alive()?;
        self.port
            .extmem_unregister(base, extent)
            .map_err(|code| (RegistrationStep::ExtmemUnregister, Some(code)))?;
        alive()
    }
}
