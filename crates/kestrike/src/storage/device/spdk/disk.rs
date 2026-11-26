//! The SPDK NVMe driver behind [`Disk`]: one I/O qpair on the EBS controller
//! the mappings file records as bound to `vfio-pci`.

use std::collections::BTreeSet;
use std::ffi::{CString, c_void};
use std::marker::PhantomData;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use spdk_sys as sys;
use sys::{
    spdk_nvme_reservation_acquire_action_SPDK_NVME_RESERVE_ACQUIRE as ACQUIRE,
    spdk_nvme_reservation_acquire_action_SPDK_NVME_RESERVE_PREEMPT as PREEMPT,
    spdk_nvme_reservation_acquire_action_SPDK_NVME_RESERVE_PREEMPT_ABORT as PREEMPT_ABORT,
    spdk_nvme_reservation_register_action_SPDK_NVME_RESERVE_REGISTER_KEY as REGISTER_KEY,
    spdk_nvme_reservation_register_cptpl_SPDK_NVME_RESERVE_PTPL_NO_CHANGES as PTPL_UNCHANGED,
    spdk_nvme_reservation_type_SPDK_NVME_RESERVE_EXCLUSIVE_ACCESS as EXCLUSIVE_ACCESS,
};

use super::super::disk::{
    CommandToken, Completion, CompletionSink, Disk, DmaRange, QuiesceStatus, RefusalReason,
    SubmitRefusal,
};
use super::super::geometry::{DeviceGeometry, DeviceRange};
#[cfg(test)]
use super::super::identify::IDENTIFY_LEN;
use super::super::identify::{
    AttachFacts, AttachedIdentity, IdentifyRaw, IdentifySnapshot, TransferLimits,
};
#[cfg(test)]
use super::super::pool::Buffer;
use super::super::reservation::{ReservationCommand, ReservationLimits, check_report_identity};
use super::super::status::{Classification, ControllerEvent, DeviceStatus};
use super::admin::AdminRequest;
use super::certify::{self, disable_proven};
use super::checks::{disconnect_outcome, identity_matches, refusal_for};
use super::limits::{Limits, LimitsError};
use super::native::{Native, Spdk};
use super::staging::{self, Slots, Staging};
use super::statistics::{LOG_PAGE, PAGE_LEN, Shared, StatisticsFailure, StatisticsHandle, parse};
use crate::bind::{
    AttachAuthority, DEVICE_LOCKS, DeviceLock, Host, NvmeBinding, OwnerLock, serial_of,
};
use crate::failover::admission::AdmissionError;
use crate::failover::evidence::Pair;
use crate::failover::identity::Exhid;
use crate::native::{
    ArenaRegistration, DeviceLease, DeviceStopped, Readiness, RegistrationId, Unregistered,
};

/// The canary's token, outside the command table's token space.
#[cfg(test)]
const CANARY: CommandToken = CommandToken::from_raw(u64::MAX);

/// Controller addresses a driver in this process attached. SPDK hands a
/// second connect to an attached controller the same controller, so a
/// second driver would share its queues and reset; attach refuses it.
static ATTACHED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

pub(super) fn attached() -> std::sync::MutexGuard<'static, BTreeSet<String>> {
    ATTACHED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether a driver in this process holds the controller at `bdf`.
fn address_attached(bdf: &str) -> bool {
    attached().contains(bdf)
}

fn address_held(lock: &OwnerLock) -> bool {
    lock.mappings()
        .ok()
        .and_then(|m| m.nvme)
        .is_some_and(|n| address_attached(&n.bdf))
}

/// How the driver attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpdkConfig {
    /// Commands the driver may hold accepted; the effective depth may be lower.
    pub queue_depth: u32,
    /// Report-only threshold for a slow I/O command, in microseconds; positive.
    pub timeout_io_us: u64,
    /// Threshold for a slow admin command, in microseconds; positive.
    pub timeout_admin_us: u64,
}

impl SpdkConfig {
    /// Whether every field is positive.
    pub fn is_valid(&self) -> bool {
        self.queue_depth > 0 && self.timeout_io_us > 0 && self.timeout_admin_us > 0
    }
}

/// Why attach refused. A refusal after a successful connect detaches the
/// controller and frees its address; when SPDK refuses that detach, the
/// controller stays attached with no arena-backed queue and its address
/// marked attached, so no later driver in the process reaches it, and the
/// registration keeps a lease for it that nothing returns, so neither the
/// registration's undo nor the environment's finish runs under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdkAttachError {
    /// A timeout threshold or the depth is zero.
    Config,
    Authority(AdmissionError),
    /// CTRATT bit 0 is clear, so SPDK would select the short host-ID Report format.
    ExtendedReportUnsupported,
    /// The reservation share or Report buffer exceeds the effective queue limits.
    ReservationLimits,
    /// The lock's directory holds no well-formed mappings file.
    Mappings,
    /// The mappings file was written on another instance or during another boot, or the host's IDs are unreadable.
    Stale,
    /// An earlier attach in this process connected to the recorded address.
    AlreadyAttached,
    /// The host-wide device lock of the recorded address is held elsewhere, or its directory refused the lock.
    DeviceLock(std::io::ErrorKind),
    /// SPDK could not parse the recorded address or connect to it.
    Connect,
    /// The file records no volume, or the live controller is not the recorded EBS volume: serial, model, PCI identity or namespace differ.
    Identity,
    Limits(LimitsError),
    /// The live geometry differs from the recorded geometry.
    Geometry,
    /// SPDK returned no namespace Identify data to copy.
    Capture,
    /// SPDK could not allocate the I/O qpair.
    Qpair,
    /// Get Features read a host identifier other than the one the controller was connected with.
    HostIdMismatch,
    /// Get Features left the host identifier unconfirmed; `HostIdFailure` records the cause.
    HostIdUnconfirmed(HostIdFailure),
    /// Attachment requires the recorded address's driver link to resolve to `vfio-pci`.
    KernelBinding,
}

/// Why the attach-time Get Features left the host identifier unconfirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIdFailure {
    /// SPDK refused the submit with this result.
    Submit(i32),
    /// An admin poll failed with this result.
    Poll(i32),
    /// The admin timeout expired while the command awaited completion.
    Timeout,
    /// The command completed with this error status word.
    Status(u16),
}

/// Why the startup canary failed; serve nothing after it.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryError {
    /// The registration is not the one that leased this device, has not
    /// verified every page, or the driver holds accepted commands.
    NotReady,
    /// The buffer is shorter than the read and its guard.
    Buffer,
    Refused(SubmitRefusal),
    /// No terminal arrived within the deadline; the buffer stays held by the
    /// device and the driver is gone.
    Timeout,
    Status(DeviceStatus),
    /// The device wrote outside the read's range.
    Guard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Running,
    /// The qpair or controller failed, or a terminal arrived outside a healthy poll; submits refuse `DeviceGone`.
    Gone(Option<i32>),
    /// Controller disable started; nothing is proven yet.
    Stopping,
    /// CC.EN and CSTS.RDY read zero and the qpair is freed.
    Stopped,
    /// Stopped, and the controller detached after the registration was undone.
    Detached,
}

/// The raw controller configuration (CC) and status (CSTS) words one disable
/// step read, and whether they proved the stop: both reads valid, CC.EN = 0
/// and CSTS.RDY = 0. The proving read is the stop certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StopReport {
    pub(crate) cc: u32,
    pub(crate) csts: u32,
    pub(crate) proven: bool,
}

/// The distinct handle addresses a scripted driver passes for its controller, namespace and qpair; a [`Native`] fixture treats them as opaque.
#[cfg(test)]
pub(crate) const SCRIPTED_CTRLR: usize = 0x1000;
#[cfg(test)]
pub(crate) const SCRIPTED_NS: usize = 0x2000;
#[cfg(test)]
pub(crate) const SCRIPTED_QPAIR: usize = 0x3000;

/// What a test reads from a driver while commands are outstanding.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DriverWitness {
    /// Commands SPDK accepted.
    pub(crate) accepted: usize,
    /// Terminals staged for accepted commands. An accepted command without
    /// one is a command the device may still read or write once a
    /// completion poll rang its doorbell.
    pub(crate) staged: usize,
    /// Staged terminals a healthy poll certified that await delivery.
    pub(crate) certified: usize,
    /// Callbacks that found a free or already staged record, or carried a null completion.
    pub(crate) strays: u64,
    /// The registers the latest disable read.
    pub(crate) stop: Option<StopReport>,
    /// Whether the driver still holds its registration's lease.
    pub(crate) leased: bool,
}

/// A request SPDK accepted stays allocated until the controller detached, because SPDK may still write its page or run its callback.
enum LogPage {
    None,
    /// SPDK accepted the command and its callback has not been observed.
    Outstanding(NonNull<AdminRequest<PAGE_LEN>>),
    /// The command was outstanding when the driver left running.
    Abandoned(NonNull<AdminRequest<PAGE_LEN>>),
}

impl LogPage {
    fn request(&self) -> Option<NonNull<AdminRequest<PAGE_LEN>>> {
        match self {
            Self::None => None,
            Self::Outstanding(request) | Self::Abandoned(request) => Some(*request),
        }
    }
}

/// The SPDK NVMe driver. It is `!Send`, because SPDK's qpair belongs to the
/// thread that polls it, and borrows its owner lock for its life, so no bind
/// or release runs while it lives.
///
/// Dropping a driver that has not detached frees nothing native: the
/// controller, any qpair not yet freed, and the staging native callbacks
/// point into stay allocated, and the arena registration keeps its
/// unreturned lease. A detached driver frees its staging and any log-page
/// request when dropped.
pub struct SpdkDisk<'l, N: Native = Spdk> {
    authority: Option<AttachAuthority>,
    ctrlr: NonNull<sys::spdk_nvme_ctrlr>,
    ns: NonNull<sys::spdk_nvme_ns>,
    qpair: NonNull<sys::spdk_nvme_qpair>,
    slots: Option<Slots>,
    limits: Limits,
    reservation_limits: Option<ReservationLimits>,
    /// Host ID and key of the own Report record.
    own: Pair,
    state: State,
    /// The data gate records the arena bounds after a successful canary, or at medium admission the bounds the
    /// reservation gate verified; a running driver refuses reads and writes `NotVerified` while it is `None`.
    registered: Option<(usize, usize)>,
    /// Set with the attach authority; a running driver refuses every read and write `NotVerified` while it holds,
    /// and the first gate pass for the own pair clears it through [`Disk::admit_medium`].
    medium_withheld: bool,
    /// The independent reservation gate records the verified arena bounds before fencing.
    reservation_registered: Option<(usize, usize)>,
    lease: Option<DeviceLease>,
    /// The registration that leased the device; its undo proof authorizes detach.
    registration: RegistrationId,
    /// That registration's readiness: while it is clear, every read, write and reservation command refuses
    /// `NotVerified`, whatever range the gates installed.
    ready: Readiness,
    address: String,
    /// The namespace whose EBS statistics page the driver reads.
    nsid: u32,
    /// The request flag and latest reading every [`StatisticsHandle`] shares.
    statistics: Arc<Shared>,
    log_page: LogPage,
    /// The registers the latest disable step read; `None` until a quiesce reads them.
    stop: Option<StopReport>,
    /// The first controller event observed; it ends the incarnation, so the driver turned gone with it.
    event: Option<ControllerEvent>,
    /// The attached device and the Identify data copied during attach.
    facts: AttachFacts,
    /// The device lock of `address`, held from attach until a successful detach or the driver's drop.
    device: Option<DeviceLock>,
    /// A pause the next quiesce takes after the disable started and before it reads the registers.
    #[cfg(test)]
    stall: Option<Box<dyn FnOnce()>>,
    _lock: PhantomData<&'l OwnerLock>,
    _owner_thread: PhantomData<*mut ()>,
    _native: PhantomData<N>,
}

impl<N: Native> std::fmt::Debug for SpdkDisk<'_, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpdkDisk")
            .field("limits", &self.limits)
            .field("state", &self.state)
            .field("stop", &self.stop)
            .finish_non_exhaustive()
    }
}

impl<N: Native> Drop for SpdkDisk<'_, N> {
    fn drop(&mut self) {
        if self.state != State::Detached {
            return;
        }
        if let Some(slots) = self.slots.take() {
            // SAFETY: the controller detached, so SPDK holds no callback argument into the slots.
            unsafe { slots.free() };
        }
        if let Some(request) = self.log_page.request() {
            // SAFETY: the controller detached, so SPDK holds no reference to the request, which `serve_statistics` allocated with `Box`.
            drop(unsafe { Box::from_raw(request.as_ptr()) });
        }
    }
}

fn refusal(reason: RefusalReason, code: Option<i32>) -> SubmitRefusal {
    SubmitRefusal { reason, code }
}

/// Whether `memory` lies in the arena backing at `base` with `extent` bytes:
/// its offset places it at the backing's base and it ends within the extent.
fn within((base, extent): (usize, usize), memory: DmaRange) -> bool {
    let start = memory.addr().as_ptr().addr();
    start.checked_sub(memory.offset()) == Some(base)
        && memory
            .offset()
            .checked_add(memory.byte_len() as usize)
            .is_some_and(|end| end <= extent)
}

impl<'l, N: Native> SpdkDisk<'l, N> {
    /// Authenticates the assignment and reads the local record the fresh path
    /// persisted, writing nothing and refusing an absent, invalid or differently
    /// bound record, before connecting; then checks Identify and geometry, and
    /// confirms by Get Features that the controller holds the record's host ID,
    /// before allocating the qpair.
    ///
    /// A present record does not by itself authorize a connect. After a fresh
    /// first acquisition, the caller attaches only after its `E`
    /// compare-and-swap succeeds with an acknowledgment; restarts use
    /// [`attach_restart`](Self::attach_restart).
    ///
    /// Each Report applies the own-record validation performed by
    /// [`check_own_record`](crate::storage::check_own_record), which locates
    /// the own record by host ID and key: a second record with the own host
    /// ID, or the own host ID under another key, withholds the Report's bytes
    /// from `CommandTable::reservation_report`.
    /// An absent own entry passes because it is legal before Register.
    ///
    /// The attached driver admits reservation commands that name the
    /// authority's key and pair and encode their payload, and refuses every
    /// read and write `NotVerified` until a gate pass for the own pair admits
    /// them ([`Disk::admit_medium`]): the fresh fencer's before its unit-0
    /// write, or the volume's.
    ///
    /// `metadata` confirms the instance ID and availability zone the
    /// assignment names, and that confirmation is as strong as the provider:
    /// a production caller passes the instance metadata service.
    pub fn attach(
        host: &Host,
        lock: &'l OwnerLock,
        metadata: &dyn crate::bind::Metadata,
        registration: &mut ArenaRegistration<'_>,
        config: SpdkConfig,
        reservation_limits: ReservationLimits,
    ) -> Result<Self, SpdkAttachError> {
        if !config.is_valid() {
            return Err(SpdkAttachError::Config);
        }
        if address_held(lock) {
            return Err(SpdkAttachError::AlreadyAttached);
        }
        let authority = lock
            .prepare_authority(host, metadata)
            .map_err(SpdkAttachError::Authority)?;
        let mut disk = Self::connect_locked(
            host,
            lock,
            registration,
            config,
            (authority.pair(), Some(&authority.record.binding().volume)),
            reservation_limits,
        )?;
        disk.install_authority(authority);
        Ok(disk)
    }

    /// The restart path connects using the caller-supplied `record`, which must have passed the restart sequence's
    /// store-record checks and step 2 binding check, and that names the mapped volume and the running instance.
    pub fn attach_restart(
        host: &Host,
        lock: &'l OwnerLock,
        registration: &mut ArenaRegistration<'_>,
        config: SpdkConfig,
        record: crate::failover::record::LocalRecord,
        reservation_limits: ReservationLimits,
    ) -> Result<Self, SpdkAttachError> {
        if !config.is_valid() {
            return Err(SpdkAttachError::Config);
        }
        if address_held(lock) {
            return Err(SpdkAttachError::AlreadyAttached);
        }
        let (instance, boot) = host
            .instance_and_boot()
            .ok_or(SpdkAttachError::Authority(AdmissionError::Instance))?;
        let mappings = lock.mappings().map_err(|_| SpdkAttachError::Mappings)?;
        let binding = record.binding();
        let mapped = mappings.nvme.as_ref().map(|nvme| nvme.volume.as_str());
        if mappings.check_current(&instance, &boot).is_err()
            || binding.instance != instance
            || mapped != Some(binding.volume.as_str())
        {
            return Err(SpdkAttachError::Authority(AdmissionError::Binding));
        }
        let mut disk = Self::connect_locked(
            host,
            lock,
            registration,
            config,
            (record.pair(), Some(&record.binding().volume)),
            reservation_limits,
        )?;
        disk.install_authority(AttachAuthority { record });
        Ok(disk)
    }

    #[cfg(test)]
    pub(crate) fn attach_qualification(
        host: &Host,
        lock: &'l OwnerLock,
        registration: &mut ArenaRegistration<'_>,
        config: SpdkConfig,
        own: Pair,
        limits: ReservationLimits,
    ) -> Result<Self, SpdkAttachError> {
        Self::connect_locked(host, lock, registration, config, (own, None), limits)
    }

    /// Connects the controller the locked mappings file records under `own`. With `admitted`, the volume an attach
    /// checked its record against, a file that now records another volume refuses `Binding` before the device lock
    /// and the connect, so the check and the connect agree on one mapping.
    fn connect_locked(
        host: &Host,
        lock: &'l OwnerLock,
        registration: &mut ArenaRegistration<'_>,
        config: SpdkConfig,
        (own, admitted): (Pair, Option<&str>),
        reservation_limits: ReservationLimits,
    ) -> Result<Self, SpdkAttachError> {
        if !config.is_valid() {
            return Err(SpdkAttachError::Config);
        }
        let mappings = lock.mappings().map_err(|_| SpdkAttachError::Mappings)?;
        let (instance, boot) = host.instance_and_boot().ok_or(SpdkAttachError::Stale)?;
        mappings
            .check_current(&instance, &boot)
            .map_err(|_| SpdkAttachError::Stale)?;
        let binding = mappings.nvme.as_ref().ok_or(SpdkAttachError::Identity)?;
        if admitted.is_some_and(|volume| volume != binding.volume) {
            return Err(SpdkAttachError::Authority(AdmissionError::Binding));
        }
        let serial = serial_of(&binding.volume).ok_or(SpdkAttachError::Identity)?;
        if host.driver(&binding.bdf).as_deref() != Some(crate::bind::VFIO) {
            return Err(SpdkAttachError::KernelBinding);
        }
        let device = DeviceLock::acquire(&host.under_root(Path::new(DEVICE_LOCKS)), &binding.bdf)
            .map_err(|error| SpdkAttachError::DeviceLock(error.kind()))?;
        let address = CString::new(format!("trtype:PCIe traddr:{}", binding.bdf))
            .map_err(|_| SpdkAttachError::Connect)?;
        let mut trid = sys::spdk_nvme_transport_id::default();
        // SAFETY: `trid` is a valid structure and `address` a C string.
        if unsafe { sys::spdk_nvme_transport_id_parse(&mut trid, address.as_ptr()) } != 0 {
            return Err(SpdkAttachError::Connect);
        }
        if !attached().insert(binding.bdf.clone()) {
            return Err(SpdkAttachError::AlreadyAttached);
        }
        let mut opts = sys::spdk_nvme_ctrlr_opts::default();
        // SAFETY: `trid` and `opts` are valid, sized structures. `registration` borrows the process's one
        // environment, which stays on the thread that initialized it, so every connect runs on that thread. The held
        // device lock and the address just inserted into the attached set keep every other cooperating attach of
        // this address, in this process or another, from connecting to it while this driver lives.
        let ctrlr = unsafe {
            N::connect_options(&mut opts, own.exhid.bytes());
            NonNull::new(N::connect(&trid, &opts))
        };
        let Some(ctrlr) = ctrlr else {
            attached().remove(&binding.bdf);
            return Err(SpdkAttachError::Connect);
        };
        // SAFETY: the controller is connected, no qpair or callback is registered on it yet, its address is marked attached, and `lock` is borrowed for `'l`, so no bind or release runs while the driver lives.
        let mut disk = unsafe {
            Self::configured(
                ctrlr,
                binding,
                &serial,
                config,
                reservation_limits,
                own,
                registration,
            )
        }?;
        disk.hold(device);
        Ok(disk)
    }
}

/// What configuring a connected controller produced.
struct Configured {
    ns: NonNull<sys::spdk_nvme_ns>,
    limits: Limits,
    qpair: NonNull<sys::spdk_nvme_qpair>,
    slots: Slots,
    identify: IdentifySnapshot,
}

impl<'l, N: Native> SpdkDisk<'l, N> {
    /// `hold` retains the device lock of the driver's address until a successful detach or the driver's drop.
    pub(super) fn hold(&mut self, device: DeviceLock) {
        self.device = Some(device);
    }

    /// Configures the connected controller and returns the running driver
    /// holding a lease from `registration`. A refusal detaches the controller
    /// and frees its address; when the detach fails, the address stays
    /// marked attached and `registration` keeps a lease that never returns.
    ///
    /// # Safety
    ///
    /// `ctrlr` is connected with `own`'s host ID, with no qpair allocated and no
    /// callback registered, `binding.bdf` is marked attached for it, and no bind
    /// or release runs on `binding.bdf` for `'l`; `attach` borrows the owner
    /// lock for `'l` to guarantee that.
    pub(super) unsafe fn configured(
        ctrlr: NonNull<sys::spdk_nvme_ctrlr>,
        binding: &NvmeBinding,
        serial: &str,
        config: SpdkConfig,
        reservation_limits: ReservationLimits,
        own: Pair,
        registration: &mut ArenaRegistration<'_>,
    ) -> Result<Self, SpdkAttachError> {
        let request = NonNull::from(Box::leak(Box::new(AdminRequest::<16>::new())));
        // SAFETY: the caller's contract, and `request` stays allocated until the detach below or until `configure`
        // returns with its command completed.
        let configured = match unsafe {
            Self::configure(
                ctrlr,
                binding,
                serial,
                config,
                reservation_limits,
                own.exhid,
                request,
            )
        } {
            Ok(configured) => configured,
            Err(error) => {
                // SAFETY: no qpair or timeout callback exists yet; the one application callback the detach may run
                // is the Get Features completion into `request`, which stays allocated through the detach.
                if unsafe { N::detach(ctrlr.as_ptr()) } == 0 {
                    attached().remove(&binding.bdf);
                    // SAFETY: the detach ended every admin command, so SPDK holds no pointer to the request.
                    drop(unsafe { Box::from_raw(request.as_ptr()) });
                } else {
                    // The controller stays attached in the environment's memory with no driver to stop it. Its
                    // lease is dropped unreturned, so the registration never undoes and the environment, which
                    // finalizes only once no DPDK memory user is live, never finishes.
                    let _kept = registration.device_attached();
                }
                return Err(error);
            }
        };
        // SAFETY: `configure` succeeded only after the Get Features callback ran, so SPDK holds no pointer to the
        // request.
        drop(unsafe { Box::from_raw(request.as_ptr()) });
        let lease = registration.device_attached();
        let ready = registration.readiness();
        Ok(Self {
            authority: None,
            ctrlr,
            ns: configured.ns,
            qpair: configured.qpair,
            slots: Some(configured.slots),
            limits: configured.limits,
            reservation_limits: Some(reservation_limits),
            own,
            state: State::Running,
            registered: None,
            medium_withheld: false,
            reservation_registered: None,
            registration: lease.registration(),
            ready,
            lease: Some(lease),
            address: binding.bdf.clone(),
            nsid: binding.nsid,
            statistics: Arc::default(),
            log_page: LogPage::None,
            stop: None,
            event: None,
            device: None,
            facts: AttachFacts {
                identity: AttachedIdentity {
                    serial: serial.to_owned(),
                    nsid: binding.nsid,
                    sector_size: binding.sector_size,
                    capacity: binding.capacity,
                },
                identify: configured.identify,
            },
            #[cfg(test)]
            stall: None,
            _lock: PhantomData,
            _owner_thread: PhantomData,
            _native: PhantomData,
        })
    }

    /// Re-identifies the connected controller and its namespace, copies both
    /// Identify structures, derives the limits, allocates the I/O qpair and
    /// registers the timeout callback. The copy precedes every later native
    /// call, so the snapshot holds the data the identity check read.
    ///
    /// # Safety
    ///
    /// `ctrlr` is connected with host ID `exhid`, with no qpair allocated and no
    /// callback registered, and polled only on this thread. `request` meets the
    /// contract of [`confirm_host_id`].
    unsafe fn configure(
        ctrlr: NonNull<sys::spdk_nvme_ctrlr>,
        binding: &NvmeBinding,
        serial: &str,
        config: SpdkConfig,
        reservation_limits: ReservationLimits,
        exhid: Exhid,
        request: NonNull<AdminRequest<16>>,
    ) -> Result<Configured, SpdkAttachError> {
        // SAFETY: the controller's identity data and namespace live as long as it stays attached, and no admin completion runs in this block, so nothing writes either structure during the copy.
        let (matched, ns, raw) = unsafe {
            let data = N::controller_data(ctrlr.as_ptr());
            let identity = data.as_ref().ok_or(SpdkAttachError::Identity)?;
            let pci = N::pci_ids(ctrlr.as_ptr());
            let ns = NonNull::new(N::namespace(ctrlr.as_ptr(), binding.nsid))
                .ok_or(SpdkAttachError::Identity)?;
            let matched = identity_matches(&identity.sn, &identity.mn, pci, serial);
            let raw = IdentifyRaw::capture(identity, N::namespace_data(ns.as_ptr()), binding.nsid);
            (matched, ns, raw)
        };
        if !matched {
            return Err(SpdkAttachError::Identity);
        }
        let raw = raw.ok_or(SpdkAttachError::Capture)?;
        if raw.ctratt() & 1 == 0 {
            return Err(SpdkAttachError::ExtendedReportUnsupported);
        }
        let mut qopts = sys::spdk_nvme_io_qpair_opts::default();
        // SAFETY: `ns` belongs to the attached controller.
        let facts = unsafe { N::namespace_facts(ctrlr.as_ptr(), ns.as_ptr(), &mut qopts) };
        let limits = facts
            .limits(config.queue_depth)
            .map_err(SpdkAttachError::Limits)?;
        if reservation_limits.commands() >= limits.depth
            || reservation_limits.report_bytes() > limits.transfer
        {
            return Err(SpdkAttachError::ReservationLimits);
        }
        let capacity = facts.sectors.checked_mul(u64::from(facts.sector_size));
        if facts.sector_size != binding.sector_size || capacity != Some(binding.capacity) {
            return Err(SpdkAttachError::Geometry);
        }
        let identify = IdentifySnapshot::new(
            raw,
            TransferLimits {
                namespace_max: facts.max_transfer,
                boundary: facts.boundary,
                command: limits.transfer,
            },
        );
        // SAFETY: the caller's contract; with no qpair allocated, the confirmation's callback is the only
        // application callback its admin polls run.
        unsafe {
            confirm_host_id::<N>(
                ctrlr,
                exhid,
                request,
                Duration::from_micros(config.timeout_admin_us),
            )
        }?;
        qopts.io_queue_size = limits.io_queue_size;
        qopts.io_queue_requests = qopts.io_queue_requests.max(limits.io_queue_requests);
        // A submit writes its queue entry; the next completion poll rings the
        // submission doorbell once for all entries written since the last ring.
        qopts.__bindgen_anon_1.delay_cmd_submit = true;
        // SAFETY: the controller is connected and `qopts` holds its defaults with the sizes above.
        let qpair = unsafe { N::alloc_io_qpair(ctrlr.as_ptr(), &qopts) };
        let qpair = NonNull::new(qpair).ok_or(SpdkAttachError::Qpair)?;
        let slots = Slots::new(limits.depth);
        // SAFETY: the timeout argument stays allocated until detach, after which SPDK holds no pointer to it.
        unsafe {
            N::register_timeout(
                ctrlr.as_ptr(),
                config.timeout_io_us,
                config.timeout_admin_us,
                Some(staging::timed_out),
                slots.timeout_arg(),
            );
        }
        Ok(Configured {
            ns,
            limits,
            qpair,
            slots,
            identify,
        })
    }
}

#[cfg(test)]
impl SpdkDisk<'_> {
    /// Makes the next `count` commands of opcode `opc` on this driver's qpair
    /// complete with status `(sct, sc)`: with `do_not_submit`, SPDK holds each
    /// one off the device for `timeout_us` and synthesizes its completion;
    /// without it, the device runs the command and SPDK rewrites its status.
    /// Returns SPDK's result.
    pub(crate) fn inject(
        &mut self,
        opc: u8,
        do_not_submit: bool,
        timeout_us: u64,
        count: u32,
        (sct, sc): (u8, u8),
    ) -> i32 {
        assert_eq!(
            self.state,
            State::Running,
            "injection needs a running driver"
        );
        // SAFETY: a running native driver's controller and qpair are live SPDK objects, polled only on this thread.
        unsafe {
            sys::spdk_nvme_qpair_add_cmd_error_injection(
                self.ctrlr.as_ptr(),
                self.qpair.as_ptr(),
                opc,
                do_not_submit,
                timeout_us,
                count,
                sct,
                sc,
            )
        }
    }

    /// Removes the injection [`inject`](Self::inject) installed for `opc`.
    pub(crate) fn clear_injection(&mut self, opc: u8) {
        assert_eq!(
            self.state,
            State::Running,
            "injection needs a running driver"
        );
        // SAFETY: as for `inject`.
        unsafe {
            sys::spdk_nvme_qpair_remove_cmd_error_injection(
                self.ctrlr.as_ptr(),
                self.qpair.as_ptr(),
                opc,
            );
        }
    }
}

impl<N: Native> SpdkDisk<'_, N> {
    fn staging(&mut self) -> &mut Staging {
        let Some(slots) = &mut self.slots else {
            unreachable!("slots live until the driver detaches")
        };
        // SAFETY: no native call is in progress, so no callback reaches the
        // cell, and `&mut self` keeps this the only reference into it.
        unsafe { slots.staging() }
    }

    /// Installs fixture bounds for a scripted queue.
    #[cfg(test)]
    pub(crate) fn set_reservation_limits(&mut self, limits: ReservationLimits) {
        self.reservation_limits = Some(limits);
    }

    /// Marks the canary passed with `memory`'s backing registered, for tests of the command path.
    #[cfg(test)]
    pub(crate) fn mark_verified(&mut self, memory: DmaRange) {
        let base = memory.addr().as_ptr().addr() - memory.offset();
        self.registered = Some((base, usize::MAX - base));
        self.reservation_registered = self.registered;
    }

    /// Reports a command timeout for `cid` to the driver's timeout callback, as SPDK does once a command passes the I/O threshold.
    #[cfg(test)]
    pub(crate) fn report_timeout(&mut self, cid: u16) {
        let arg = self.slots.as_ref().map(Slots::timeout_arg);
        // SAFETY: the slots stay allocated while the driver lives, and no native call is in progress.
        unsafe {
            staging::timed_out(
                arg.expect("slots live until detach"),
                self.ctrlr.as_ptr(),
                self.qpair.as_ptr(),
                cid,
            );
        }
    }

    /// Makes the next quiesce that would read the registers run `stall` first.
    #[cfg(test)]
    pub(crate) fn stall_before_proof(&mut self, stall: impl FnOnce() + 'static) {
        self.stall = Some(Box::new(stall));
    }

    /// Lets one test submit past the namespace's end, so the device itself refuses the range.
    #[cfg(test)]
    pub(crate) fn widen_capacity(&mut self, bytes: u64) {
        self.limits.capacity += bytes;
    }

    /// Callers supply a [`Native`] implementation that treats the
    /// controller, namespace and qpair pointers as opaque handles.
    #[cfg(test)]
    pub(crate) fn scripted(address: &str, limits: Limits) -> Self {
        Self::scripted_with(address, limits, None, Readiness::verified())
    }

    /// A scripted driver holding a lease from `registration`.
    #[cfg(test)]
    pub(crate) fn scripted_leased(
        address: &str,
        limits: Limits,
        registration: &mut ArenaRegistration<'_>,
    ) -> Self {
        Self::scripted_with(
            address,
            limits,
            Some(registration.device_attached()),
            registration.readiness(),
        )
    }

    /// Replaces the scripted driver's attach facts, whose Identify pages start zeroed, with `facts`.
    #[cfg(test)]
    pub(crate) fn set_facts(&mut self, facts: AttachFacts) {
        self.facts = facts;
    }

    #[cfg(test)]
    fn scripted_with(
        address: &str,
        limits: Limits,
        lease: Option<DeviceLease>,
        ready: Readiness,
    ) -> Self {
        assert!(
            attached().insert(address.to_owned()),
            "{address} is already attached"
        );
        Self {
            authority: None,
            ctrlr: NonNull::new(std::ptr::without_provenance_mut(SCRIPTED_CTRLR)).unwrap(),
            ns: NonNull::new(std::ptr::without_provenance_mut(SCRIPTED_NS)).unwrap(),
            qpair: NonNull::new(std::ptr::without_provenance_mut(SCRIPTED_QPAIR)).unwrap(),
            slots: Some(Slots::new(limits.depth)),
            limits,
            reservation_limits: None,
            own: Pair {
                exhid: Exhid::new([1; 16]).unwrap(),
                key: crate::failover::identity::Key::decode((1 << 32) | 1).unwrap(),
            },
            state: State::Running,
            registered: None,
            medium_withheld: false,
            reservation_registered: None,
            registration: lease
                .as_ref()
                .map_or(RegistrationId::SCRIPTED, DeviceLease::registration),
            ready,
            lease,
            address: address.to_owned(),
            nsid: 1,
            statistics: Arc::default(),
            log_page: LogPage::None,
            stop: None,
            event: None,
            device: None,
            facts: AttachFacts {
                identity: AttachedIdentity {
                    serial: "vol0".to_owned(),
                    nsid: 1,
                    sector_size: limits.sector_size,
                    capacity: limits.capacity,
                },
                identify: IdentifySnapshot::new(
                    IdentifyRaw::from_parts(
                        1,
                        Box::new([0; IDENTIFY_LEN]),
                        Box::new([0; IDENTIFY_LEN]),
                    ),
                    TransferLimits {
                        namespace_max: limits.transfer,
                        boundary: 0,
                        command: limits.transfer,
                    },
                ),
            },
            stall: None,
            _lock: PhantomData,
            _owner_thread: PhantomData,
            _native: PhantomData,
        }
    }

    /// Takes `authority` as this attach's and closes the medium gate until a gate pass for the own pair.
    fn install_authority(&mut self, authority: AttachAuthority) {
        self.own = authority.pair();
        self.authority = Some(authority);
        self.medium_withheld = true;
    }

    pub fn own(&self) -> Pair {
        self.own
    }

    #[cfg(test)]
    pub(crate) fn set_authority(&mut self, authority: AttachAuthority) {
        self.install_authority(authority);
    }

    #[cfg(test)]
    pub(crate) fn set_own(&mut self, own: Pair) {
        self.own = own;
    }

    /// Returns the attachment pair persisted before connect.
    #[cfg(test)]
    pub(crate) fn authority_pair(&self) -> Option<Pair> {
        self.authority.as_ref().map(AttachAuthority::pair)
    }

    /// A handle through which any thread asks this driver for the EBS statistics page and reads the latest reading.
    /// The owner thread's [`Disk::service`] calls submit the log-page command and poll the admin queue for it.
    pub fn statistics(&self) -> StatisticsHandle {
        StatisticsHandle(Arc::clone(&self.statistics))
    }

    /// Advances the statistics request of a running driver: while the log-page command is outstanding, polls the admin queue once and publishes the reading once the command's callback ran; otherwise submits the command when a handle asked for one.
    /// A terminal staged during the admin poll, a failed poll or a failed controller turns the driver gone.
    /// A submit SPDK accepts while the driver leaves `State::Running` abandons the log-page request and answers `DeviceGone`.
    fn serve_statistics(&mut self) {
        if self.state != State::Running {
            self.abandon_statistics();
            return;
        }
        if let LogPage::Outstanding(request) = self.log_page {
            let ctrlr = self.ctrlr.as_ptr();
            // SAFETY: the controller is attached and polled only on this thread; admin-poll callbacks reach the log-page request and the staging cell, and the driver holds no reference into either.
            let rc = self.outside_poll(|| unsafe { N::process_admin_completions(ctrlr) });
            if rc < 0 {
                self.failed(ControllerEvent::Reset, Some(-rc));
            }
            if self.state != State::Running {
                self.abandon_statistics();
                return;
            }
            self.take_log_page(request);
        } else if self.statistics.take_request() {
            let request = NonNull::from(Box::leak(Box::new(AdminRequest::<PAGE_LEN>::new())));
            // SAFETY: the request was just allocated and stays live.
            let (payload, len, callback, arg) = unsafe { AdminRequest::command(request) };
            let (ctrlr, nsid) = (self.ctrlr.as_ptr(), self.nsid);
            // SAFETY: the controller is attached; the page and the callback argument live in the request, which stays allocated until its callback ran; callbacks the submit runs reach the request and the staging cell, and the driver holds no reference into either.
            let rc = self.outside_poll(|| unsafe {
                N::get_log_page(ctrlr, LOG_PAGE, nsid, payload, len, callback, arg)
            });
            if rc == 0 {
                self.log_page = LogPage::Outstanding(request);
                if self.state != State::Running {
                    self.abandon_statistics();
                } else {
                    self.take_log_page(request);
                }
                return;
            }
            // SAFETY: SPDK refused the command, so it holds no reference to the request.
            drop(unsafe { Box::from_raw(request.as_ptr()) });
            let (_, gone) = refusal_for(rc);
            if gone {
                self.failed(ControllerEvent::Reset, Some(-rc));
            }
            // `take_request` consumed the request flag, so this branch answers the request itself.
            let failure = if self.state == State::Running {
                StatisticsFailure::Refused(rc)
            } else {
                self.gone_failure()
            };
            self.statistics.publish(Err(failure));
        }
    }

    /// Publishes the outstanding log-page command's outcome once its callback ran, inside the submit or a later admin
    /// poll. `request` is the request `log_page` names as outstanding.
    fn take_log_page(&mut self, request: NonNull<AdminRequest<PAGE_LEN>>) {
        // SAFETY: the request stays allocated while `log_page` names it, and its callback runs only on this thread.
        let Some(status) = (unsafe { (*request.as_ptr()).status }) else {
            return;
        };
        self.log_page = LogPage::None;
        // SAFETY: The callback has completed, and the driver exclusively owns the request allocated with `Box`.
        let request = unsafe { Box::from_raw(request.as_ptr()) };
        let completed = DeviceStatus::Nvme(status);
        if let Some(event) = ControllerEvent::of_status(completed) {
            self.failed(event, None);
        }
        let outcome = match completed.classify(PAGE_LEN as u32) {
            Classification::Success => parse(&request.payload).map_err(StatisticsFailure::Parse),
            _ => Err(StatisticsFailure::Status(status)),
        };
        self.statistics.publish(outcome);
    }

    fn gone_failure(&self) -> StatisticsFailure {
        let code = match self.state {
            State::Gone(code) => code,
            _ => None,
        };
        StatisticsFailure::DeviceGone(code)
    }

    /// Publishes `DeviceGone` once for the outstanding command, which also answers the requests coalesced behind it, or once per pending request flag.
    fn abandon_statistics(&mut self) {
        let owed = match self.log_page {
            LogPage::Outstanding(request) => {
                self.log_page = LogPage::Abandoned(request);
                self.statistics.take_request();
                true
            }
            LogPage::None | LogPage::Abandoned(_) => self.statistics.take_request(),
        };
        if owed {
            self.statistics.publish(Err(self.gone_failure()));
        }
    }

    /// The accepted and staged counts, the latest disable read and the lease, read without changing the driver.
    #[cfg(test)]
    pub(crate) fn witness(&mut self) -> DriverWitness {
        let leased = self.lease.is_some();
        let staging = self.staging();
        DriverWitness {
            accepted: staging.accepted(),
            staged: staging.staged(),
            certified: staging.certified(),
            strays: staging.strays,
            stop: self.stop,
            leased,
        }
    }

    /// Timeout reports so far and the last `(qpair, command ID)` reported.
    pub fn timeouts(&mut self) -> (u64, Option<(usize, u16)>) {
        let staging = self.staging();
        (staging.timeouts, staging.last_timeout)
    }

    /// The stop proof for the registration, once a quiesce returned `Stopped`.
    pub fn stop_proof(&mut self) -> Option<DeviceStopped> {
        (self.state == State::Stopped)
            .then(|| self.lease.take().map(DeviceLease::stopped))
            .flatten()
    }

    /// Detaches the stopped controller after the registration that leased it
    /// was undone and returns whether the controller was detached. A nonzero
    /// `N::detach` result keeps the driver stopped and its address reserved
    /// for a retry.
    pub fn detach(&mut self, undone: &Unregistered) -> bool {
        if self.state != State::Stopped || !undone.undid(self.registration) {
            return false;
        }
        // SAFETY: the controller is disabled, its I/O qpair freed and the arena unregistered.
        if unsafe { N::detach(self.ctrlr.as_ptr()) } != 0 {
            return false;
        }
        attached().remove(&self.address);
        self.device = None;
        self.state = State::Detached;
        true
    }

    /// Runs one native call that may invoke callbacks outside a completion
    /// poll on a running driver; a terminal staged during it, or a controller
    /// failure flag read after it, turns the driver gone.
    #[inline(always)]
    fn outside_poll(&mut self, call: impl FnOnce() -> i32) -> i32 {
        debug_assert_eq!(self.state, State::Running);
        debug_assert_eq!(self.staging().event, None);
        let before = self.staging().staged();
        let rc = call();
        // SAFETY: reads the controller's failure flag.
        let failed = unsafe { N::is_failed(self.ctrlr.as_ptr()) };
        if failed || self.staging().staged() != before {
            self.outside_event();
        }
        rc
    }

    /// Latches a controller event the call staged before recording `Reset`, so the staged event is the one
    /// [`failed`](Self::failed) keeps.
    #[cold]
    #[inline(never)]
    fn outside_event(&mut self) {
        self.latch_staged_event();
        self.failed(ControllerEvent::Reset, None);
    }

    /// `failed` records the first incarnation-ending `event` from a controller or queue failure, a terminal outside a
    /// healthy poll, or a completion status. A running driver, or one gone without a code, turns gone with `code`, so
    /// every later submit refuses.
    fn failed(&mut self, event: ControllerEvent, code: Option<i32>) {
        self.event.get_or_insert(event);
        match self.state {
            State::Running | State::Gone(None) => self.state = State::Gone(code),
            State::Gone(Some(_)) | State::Stopping | State::Stopped | State::Detached => {}
        }
    }

    /// Whether an attach authority still withholds the driver's reads and writes, until a gate pass for the own pair
    /// admits them.
    pub fn medium_withheld(&self) -> bool {
        self.medium_withheld
    }

    /// Enables reservation commands from this driver's page-verified arena before table ownership.
    /// SPDK copies payloads through its own DMA bounce buffers, whose allocations are outside the arena budget.
    /// This gate establishes arena provenance, and medium admission at a gate pass for the own pair admits reads
    /// and writes over the same range.
    ///
    /// # Errors
    ///
    /// Returns `NotVerified` unless this registration leased the device and verified every page.
    pub fn enable_reservations(
        &mut self,
        registration: &ArenaRegistration<'_>,
    ) -> Result<(), SubmitRefusal> {
        if registration.id() != self.registration || !registration.is_ready() {
            return Err(refusal(RefusalReason::NotVerified, None));
        }
        self.reservation_registered = Some(registration.range());
        Ok(())
    }

    /// Reads a startup canary: 4 KiB from the volume's start into the first
    /// 4 KiB of `buffer`, whose next 4 KiB must keep their guard pattern, and
    /// returns the buffer. Runs only with no command accepted and no attach
    /// authority withholding medium commands.
    ///
    /// # Errors
    ///
    /// [`CanaryError`]. On `Timeout` the device may still write the buffer,
    /// so the driver keeps it for the rest of the process and turns gone.
    #[cfg(test)]
    pub fn canary<'b>(
        &mut self,
        registration: &ArenaRegistration<'_>,
        mut buffer: Buffer<'b>,
        deadline: Duration,
    ) -> Result<Buffer<'b>, CanaryError> {
        const READ: u32 = 4096;
        if registration.id() != self.registration
            || !registration.is_ready()
            || self.staging().accepted() != 0
        {
            return Err(CanaryError::NotReady);
        }
        if buffer.capacity() < 2 * READ as usize {
            return Err(CanaryError::Buffer);
        }
        buffer.bytes_mut().fill(0xa5);
        let registered = registration.range();
        let memory = buffer.range(READ).map_err(|_| CanaryError::Buffer)?;
        if !within(registered, memory) {
            return Err(CanaryError::Buffer);
        }
        let device = DeviceRange::new(0, READ).map_err(|_| CanaryError::Buffer)?;
        // SAFETY: no reference to the buffer's bytes forms until its terminal is picked below, and a timeout keeps the buffer forever.
        unsafe { self.submit(false, CANARY, device, memory, true) }
            .map_err(CanaryError::Refused)?;
        let (start, mut out) = (Instant::now(), Vec::with_capacity(1));
        while out.is_empty() {
            if start.elapsed() > deadline {
                std::mem::forget(buffer);
                self.state = State::Gone(None);
                return Err(CanaryError::Timeout);
            }
            self.pick_completions(&mut CompletionSink::new(&mut out, 1));
        }
        if out[0].status.classify(READ) != Classification::Success {
            self.state = State::Gone(None);
            return Err(CanaryError::Status(out[0].status));
        }
        if buffer.bytes()[READ as usize..2 * READ as usize]
            .iter()
            .any(|&byte| byte != 0xa5)
        {
            self.state = State::Gone(None);
            return Err(CanaryError::Guard);
        }
        self.registered = Some(registered);
        Ok(buffer)
    }

    /// `canary` marks the driver's own startup read, which runs before a
    /// registered arena exists.
    #[inline(always)]
    unsafe fn submit(
        &mut self,
        write: bool,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
        canary: bool,
    ) -> Result<(), SubmitRefusal> {
        if self.state != State::Running {
            return Err(self.gone_refusal());
        }
        if self.medium_withheld {
            return Err(refusal(RefusalReason::NotVerified, None));
        }
        let limits = self.limits;
        if memory.byte_len() != device.byte_len()
            || device.byte_len() > limits.transfer
            || device.end() > limits.capacity
            || device.byte_len() & (limits.sector_size - 1) != 0
        {
            return Err(refusal(RefusalReason::InvalidRange, None));
        }
        if !canary {
            let Some(registered) = self.registered.filter(|_| self.ready.get()) else {
                return Err(refusal(RefusalReason::NotVerified, None));
            };
            if !within(registered, memory) {
                return Err(refusal(RefusalReason::InvalidRange, None));
            }
        }
        // SAFETY: The caller keeps `memory` exclusive to the device until the terminal or a proven stop. The checks above validate the transfer limits and, when `canary` is false, containment within the registered range.
        unsafe { self.issue(write, token, device, memory) }
    }

    #[cold]
    #[inline(never)]
    fn gone_refusal(&self) -> SubmitRefusal {
        let code = match self.state {
            State::Gone(code) => code,
            _ => None,
        };
        refusal(RefusalReason::DeviceGone, code)
    }

    /// # Safety
    ///
    /// `device` and `memory` passed the admission checks in [`Self::submit`], and the caller keeps `memory` exclusive to the device until the terminal or a proven stop.
    #[inline(always)]
    unsafe fn issue(
        &mut self,
        write: bool,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        let limits = self.limits;
        let index = self
            .staging()
            .accept(token.raw())
            .ok_or(refusal(RefusalReason::QueueFull, None))?;
        let (lba, count) = (
            device.start() >> limits.sector_shift,
            device.byte_len() >> limits.sector_shift,
        );
        let Some(slots) = &self.slots else {
            unreachable!("slots live until the driver detaches")
        };
        let arg = slots.context(index);
        let payload = memory.addr().as_ptr().cast::<c_void>();
        let (ns, qpair) = (self.ns.as_ptr(), self.qpair.as_ptr());
        // SAFETY: the caller keeps `memory` exclusive to the device until the terminal or a proven stop; the context and staging outlive the command.
        let rc = self.outside_poll(|| unsafe {
            if write {
                N::write(ns, qpair, payload, lba, count, Some(staging::complete), arg)
            } else {
                N::read(ns, qpair, payload, lba, count, Some(staging::complete), arg)
            }
        });
        if rc == 0 {
            return Ok(());
        }
        self.staging().refuse(index);
        let (reason, gone) = refusal_for(rc);
        if gone {
            self.failed(ControllerEvent::Reset, Some(-rc));
        }
        Err(refusal(reason, Some(-rc)))
    }

    /// Delivers certified staged terminals, at most the sink's remaining room.
    fn deliver(&mut self, sink: &mut CompletionSink<'_>) {
        let room = sink.remaining();
        self.staging().deliver(room, |token, status| {
            let pushed = sink.push(Completion {
                token: CommandToken::from_raw(token),
                status: DeviceStatus::Nvme(status),
            });
            // The sink's room never exceeds its vector's spare capacity, so a push within it lands.
            debug_assert!(pushed.is_ok());
        });
    }

    /// A staged controller event fails the controller even while its completion awaits delivery.
    fn latch_staged_event(&mut self) {
        if let Some(event) = self.staging().event {
            self.failed(event, None);
        }
    }

    /// The first mid-tenure controller event the driver observed: a failed controller or queue, or a completion with an abort or queue-deletion status. The event ends the incarnation, so the driver refuses every later submit; the owner quiesces it, discards the index and runs the restart sequence again.
    pub fn controller_event(&self) -> Option<ControllerEvent> {
        self.event
    }

    /// Whether the registers show the controller enabled and ready: the restart sequence's ready observation, which carries no deadline. A failed register read reads all ones, which reports the controller as not ready.
    pub fn ready(&self) -> bool {
        if self.state != State::Running {
            return false;
        }
        // SAFETY: `ctrlr` is the controller attach connected, and a `Running` driver has not detached it; the register reads and the mask functions take no other argument and keep no pointer.
        let (cc, csts, en, rdy) = unsafe {
            let (cc, csts) = N::registers(self.ctrlr.as_ptr());
            let masks = (
                sys::spdk_sys_nvme_cc_en_mask(),
                sys::spdk_sys_nvme_csts_rdy_mask(),
            );
            (cc, csts, masks.0, masks.1)
        };
        cc != u32::MAX && csts != u32::MAX && cc & en != 0 && csts & rdy != 0
    }
}

// SAFETY: the driver upholds I1 to I10: a refusal returns before SPDK queues
// anything; one terminal per accepted token comes from its record; SPDK
// transfers within the given range; a terminal is delivered only after a
// healthy poll observed it; picks deliver at most the sink's room and keep
// the rest staged; `Stopped` follows observed CC.EN = 0 and CSTS.RDY = 0
// before the qpair is freed; status passes through raw; each value owns its
// qpair, and attach refuses a second driver on one controller; a submit that
// unwinds after SPDK queued its command leaves it to the same disable proof,
// and staging keeps its token, so later picks and quiesce run unchanged.
unsafe impl<N: Native> Disk for SpdkDisk<'_, N> {
    fn geometry(&self) -> DeviceGeometry {
        DeviceGeometry {
            capacity: self.limits.capacity,
            max_transfer: self.limits.transfer,
            block_size: self.limits.sector_size,
            queue_depth: self.limits.depth,
        }
    }

    fn reservation_limits(&self) -> Option<ReservationLimits> {
        self.reservation_limits
    }

    /// Installs the page-verified arena range `enable_reservations` recorded as the data range, on any driver that
    /// enabled reservations, and opens the gate an attach authority closed, when `gate` names the driver's own pair;
    /// a gate value for another pair, or a driver that never enabled reservations, keeps the gate closed. Attach
    /// refused a namespace formatted with metadata or protection information
    /// ([`super::limits::NamespaceFacts::limits`], `Formatted`), so each transfer moves exactly its sector count.
    fn admit_medium(&mut self, gate: &crate::storage::Fenced) {
        if gate.own() != self.own {
            return;
        }
        if let Some(range) = self.reservation_registered {
            self.registered = Some(range);
            self.medium_withheld = false;
        }
    }

    fn check_reservation_report(
        &self,
        bytes: &[u8],
    ) -> Result<(), super::super::reservation::ReportError> {
        let limits = self
            .reservation_limits
            .expect("reservation Reports have validated limits");
        check_report_identity(bytes, limits, self.own)
    }

    unsafe fn submit_reservation(
        &mut self,
        token: CommandToken,
        command: ReservationCommand,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        if self.state != State::Running {
            return Err(refusal(
                RefusalReason::DeviceGone,
                match self.state {
                    State::Gone(code) => code,
                    _ => None,
                },
            ));
        }
        if self.authority.as_ref().is_some_and(|a| match command {
            ReservationCommand::Report { .. } => false,
            ReservationCommand::Register { new } => new != a.pair().key,
            ReservationCommand::Acquire { current } => current != a.pair().key,
            ReservationCommand::PreemptAndAbort(own) => own.pair() != a.pair(),
            ReservationCommand::PreemptLineage(lineage) => lineage.pair() != a.pair(),
            ReservationCommand::PreemptEnded(ended) => ended.pair() != a.pair(),
        }) {
            return Err(refusal(RefusalReason::NotVerified, None));
        }
        let limits = self
            .reservation_limits
            .ok_or(refusal(RefusalReason::Unsupported, None))?;
        if memory.byte_len() != command.len(limits) {
            return Err(refusal(RefusalReason::InvalidRange, None));
        }
        let registered = self
            .reservation_registered
            .filter(|_| self.ready.get())
            .ok_or(refusal(RefusalReason::NotVerified, None))?;
        if !within(registered, memory) {
            return Err(refusal(RefusalReason::InvalidRange, None));
        }
        if !matches!(command, ReservationCommand::Report { .. }) {
            let mut expected = [0; 16];
            command.encode(&mut expected);
            // SAFETY: the caller grants exclusive live memory, and its 16-byte length and registered range were checked above.
            let payload = unsafe { std::slice::from_raw_parts(memory.addr().as_ptr(), 16) };
            if payload != expected {
                return Err(refusal(RefusalReason::NotVerified, None));
            }
        }
        let index = self
            .staging()
            .accept(token.raw())
            .ok_or(refusal(RefusalReason::QueueFull, None))?;
        let arg = self
            .slots
            .as_ref()
            .expect("slots live until detach")
            .context(index);
        let (ns, qpair, payload) = (
            self.ns.as_ptr(),
            self.qpair.as_ptr(),
            memory.addr().as_ptr().cast::<c_void>(),
        );
        // SAFETY: the caller holds exclusive registered DMA memory and its token until terminal or proven stop. Stable staging contexts outlive all callbacks.
        let rc = self.outside_poll(|| unsafe {
            match command {
                ReservationCommand::Register { .. } => N::reservation_register(
                    ns,
                    qpair,
                    payload.cast(),
                    REGISTER_KEY,
                    PTPL_UNCHANGED,
                    Some(staging::complete),
                    arg,
                ),
                ReservationCommand::Report { .. } => N::reservation_report(
                    ns,
                    qpair,
                    payload,
                    memory.byte_len(),
                    Some(staging::complete),
                    arg,
                ),
                ReservationCommand::Acquire { .. } => N::reservation_acquire(
                    ns,
                    qpair,
                    payload.cast(),
                    ACQUIRE,
                    EXCLUSIVE_ACCESS,
                    Some(staging::complete),
                    arg,
                ),
                ReservationCommand::PreemptAndAbort(_) | ReservationCommand::PreemptLineage(_) => {
                    N::reservation_acquire(
                        ns,
                        qpair,
                        payload.cast(),
                        PREEMPT_ABORT,
                        EXCLUSIVE_ACCESS,
                        Some(staging::complete),
                        arg,
                    )
                }
                ReservationCommand::PreemptEnded(_) => N::reservation_acquire(
                    ns,
                    qpair,
                    payload.cast(),
                    PREEMPT,
                    EXCLUSIVE_ACCESS,
                    Some(staging::complete),
                    arg,
                ),
            }
        });
        if rc == 0 {
            return Ok(());
        }
        self.staging().refuse(index);
        let (reason, gone) = refusal_for(rc);
        if gone {
            self.failed(ControllerEvent::Reset, Some(-rc));
        }
        Err(refusal(reason, Some(-rc)))
    }

    unsafe fn submit_read(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        // SAFETY: the caller's contract.
        unsafe { self.submit(false, token, device, memory, false) }
    }

    unsafe fn submit_write(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        // SAFETY: the caller's contract.
        unsafe { self.submit(true, token, device, memory, false) }
    }

    /// Delivers certified terminals, then, on a running driver with commands
    /// awaiting terminals and room left in the sink, polls the I/O qpair once
    /// with a limit no larger than that room or the depth. The poll rings the
    /// submission doorbell for entries written since the last ring; a healthy
    /// poll certifies every staged terminal and the pick delivers again. Each
    /// delivery requires a certified terminal (`certified() > 0`).
    /// [`quiesce`](Disk::quiesce) and [`service`](Disk::service) handle the
    /// admin queue.
    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
        if sink.remaining() == 0 || self.state == State::Detached {
            return;
        }
        if self.staging().certified() > 0 {
            self.deliver(sink);
        }
        let waiting = self.staging().accepted() > self.staging().staged();
        if sink.remaining() > 0 && self.state == State::Running && waiting {
            let limit = u32::try_from(sink.remaining())
                .unwrap_or(u32::MAX)
                .min(self.limits.depth);
            // SAFETY: the qpair is live and polled only on this thread; callbacks reach only the staging cell.
            let rc = unsafe { N::process_completions(self.qpair.as_ptr(), limit) };
            // SAFETY: reads the controller's failure flag, which only a successful poll consults.
            let failed = rc >= 0 && unsafe { N::is_failed(self.ctrlr.as_ptr()) };
            self.latch_staged_event();
            if certify::certifies(rc, failed) {
                self.staging().certify();
            } else {
                self.failed(ControllerEvent::Reset, (rc < 0).then_some(-rc));
            }
            if self.staging().certified() > 0 {
                self.deliver(sink);
            }
        }
    }

    fn service(&mut self) {
        self.serve_statistics();
    }

    fn attach_facts(&self) -> Option<&AttachFacts> {
        Some(&self.facts)
    }

    /// Starts the controller disable on the first call, reporting `Failed`
    /// when SPDK refused to start it, and on later calls reports `Stopped`
    /// once the register reads prove it; until then, a removed controller
    /// included, every later call reports `Pending`.
    fn quiesce(&mut self) -> QuiesceStatus {
        match self.state {
            State::Stopped | State::Detached => return QuiesceStatus::Stopped,
            State::Running | State::Gone(_) => {
                // SAFETY: starts the controller disable; callbacks reach only the staging cell and the outstanding log-page request.
                let rc = unsafe { N::disconnect(self.ctrlr.as_ptr()) };
                self.state = State::Stopping;
                return disconnect_outcome(rc);
            }
            State::Stopping => {}
        }
        #[cfg(test)]
        if let Some(stall) = self.stall.take() {
            stall();
        }
        // SAFETY: advances the disable state machine and reads the registers
        // of the attached controller; the masks come from the native layout.
        let report = unsafe {
            N::process_admin_completions(self.ctrlr.as_ptr());
            let (cc, csts) = N::registers(self.ctrlr.as_ptr());
            let proven = disable_proven(
                cc,
                csts,
                sys::spdk_sys_nvme_cc_en_mask(),
                sys::spdk_sys_nvme_csts_rdy_mask(),
            );
            StopReport { cc, csts, proven }
        };
        self.stop = Some(report);
        if !report.proven {
            return QuiesceStatus::Pending;
        }
        // SAFETY: the controller is disabled, so it no longer reads the queues or the arena; freeing aborts every record, which the discard below supersedes.
        unsafe { N::free_io_qpair(self.qpair.as_ptr()) };
        self.staging().discard();
        self.state = State::Stopped;
        self.abandon_statistics();
        self.statistics.stop();
        QuiesceStatus::Stopped
    }
}

/// Get Features feature identifier of the Host Identifier.
const HOST_IDENTIFIER: u8 = 0x81;
/// Get Features cdw11 bit 0 (EXHID): read the 128-bit extended host identifier.
const EXTENDED_HOST_ID: u32 = 1;

/// Reads the controller's extended host identifier by Get Features into `request` and refuses unless the command
/// succeeds and the identifier equals `exhid`, the one the controller was connected with. Attach runs it before it
/// allocates the I/O qpair, so before any reservation command, with `timeout` set to the admin timeout. The driver
/// binds no controller reset or reconnect, so every reservation command of a driver runs under the confirmed host
/// ID.
///
/// The wait polls the admin queue at least once and checks `timeout` after each poll, so one poll that SPDK holds
/// while it services an asynchronous event extends the wait by that poll's duration.
///
/// # Errors
///
/// `HostIdMismatch` when the command succeeds with another identifier. `HostIdUnconfirmed` with `Submit` when SPDK
/// refuses the submit, `Poll` when an admin poll fails, `Timeout` when the command stays outstanding past `timeout`,
/// and `Status` when the command completes with an error status.
///
/// # Safety
///
/// `ctrlr` is connected and polled only on this thread, and no other application-submitted admin command is
/// outstanding, so `admin_done` is the only callback during these polls that writes application memory.
/// `request` points to a live, unsubmitted `AdminRequest<16>` that stays allocated until its callback ran or the
/// controller detached; the callback runs inside the submit, an admin poll or a detach on this thread.
unsafe fn confirm_host_id<N: Native>(
    ctrlr: NonNull<sys::spdk_nvme_ctrlr>,
    exhid: Exhid,
    request: NonNull<AdminRequest<16>>,
    timeout: Duration,
) -> Result<(), SpdkAttachError> {
    use SpdkAttachError::HostIdUnconfirmed as Unconfirmed;
    // SAFETY: the caller's contract keeps `request` live.
    let (payload, len, callback, arg) = unsafe { AdminRequest::command(request) };
    // SAFETY: the caller's contract keeps the payload and the argument allocated until the callback ran.
    let rc = unsafe {
        N::get_feature(
            ctrlr.as_ptr(),
            HOST_IDENTIFIER,
            EXTENDED_HOST_ID,
            payload,
            len,
            callback,
            arg,
        )
    };
    if rc != 0 {
        return Err(Unconfirmed(HostIdFailure::Submit(rc)));
    }
    let start = Instant::now();
    loop {
        // SAFETY: the caller's contract.
        let polled = unsafe { N::process_admin_completions(ctrlr.as_ptr()) };
        if polled < 0 {
            return Err(Unconfirmed(HostIdFailure::Poll(polled)));
        }
        // SAFETY: the callback writes `request` only inside a native call on this thread, and none runs here.
        if unsafe { (*request.as_ptr()).status.is_some() } || start.elapsed() >= timeout {
            break;
        }
    }
    // SAFETY: as above; the reference ends before this function returns.
    let request = unsafe { request.as_ref() };
    match request.status {
        None => Err(Unconfirmed(HostIdFailure::Timeout)),
        Some(status) if DeviceStatus::Nvme(status).classify(16) != Classification::Success => {
            Err(Unconfirmed(HostIdFailure::Status(status)))
        }
        Some(_) if request.payload == exhid.bytes() => Ok(()),
        Some(_) => Err(SpdkAttachError::HostIdMismatch),
    }
}
