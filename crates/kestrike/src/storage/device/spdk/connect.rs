//! [`connect_restart`] and [`connect_fresh`] attach the controller for the failover sequences' device steps through
//! [`SpdkDisk::attach_restart`] and [`SpdkDisk::attach`], read its registers for CC.EN and CSTS.RDY
//! ([`SpdkDisk::ready`]), then map and verify the arena registration and enable the driver's reservation commands
//! over it ([`ready`]). A step that fails after the attach returns the
//! attached driver with the failure, so its caller ends it through [`stop`] like any other attached driver; a fencer's
//! table that still owns a command ends through [`stop_table`].
//!
//! PROVEN-STOP (`NoPredecessorEffectAfterFB`): [`stop`] quiesces the controller until it reports `Stopped` within the
//! patience, takes the stop proof, records the device stopped in the registration, unregisters the arena under a
//! watchdog and detaches. A stop that stays unproven parks the thread with the controller attached and the arena
//! registered ([`hold`]), since a command the controller still owns may write its buffer.

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::disk::{SpdkAttachError, SpdkConfig, SpdkDisk};
use super::native::Native;
use crate::bind::{Host, Metadata, OwnerLock};
use crate::failover::evidence::Pair;
use crate::failover::record::LocalRecord;
use crate::native::{ArenaRegistration, RegistrationError, Supervisor, Watchdog};
use crate::storage::device::{
    CommandTable, Disk, QuiesceProgress, QuiesceStatus, ReservationLimits, SubmitRefusal,
};

/// Why a connect produced no ready driver: the attach refused, or a readiness step failed after it, with the
/// attached driver handed back for its stop. The error boxes that driver, so the error variant stays small.
#[derive(Debug)]
pub enum ConnectError<D> {
    Attach(SpdkAttachError),
    /// After the attach, the controller's registers read CC.EN or CSTS.RDY clear, or a register read failed.
    Controller(Box<D>),
    Unready(Box<D>, Unready),
}

/// A connect's result: the ready driver and the pair its controller connected with, or why it failed.
///
/// A connect does the device work that precedes the first reservation command. It returns `Ok` once the controller
/// reports ready with the pair's host ID set and confirmed and with every command of the driver ended; for a restart,
/// `restart::Device::ready` also requires every request of the earlier incarnation to have completed at the card.
///
/// The caller ties the connect to its sequence: an `Ok` driver is the controller of the volume the local record the
/// sequence checked binds, connected under that record's pair, so the caller builds the closure over the owner lock
/// the sequence's local records read, for the restart, the takeover and the fresh path alike. The driver also
/// submits only from buffers of the arena the fencer builds its table over. The fencer checks the host ID and the
/// issuer pair, which identify no volume, and it checks no arena.
///
/// On [`ConnectError::Attach`] the connect keeps what its partial attach acquired: it ends those resources, and a
/// controller that stays attached, as [`SpdkAttachError`] describes, remains with the connect's caller; the SPDK
/// connectors park the thread in that case. On [`ConnectError::Unready`] the attached driver comes back for its stop.
pub type Connected<D> = Result<(D, Pair), ConnectError<D>>;

/// The readiness step of the arena registration or the driver that failed after the attach.
#[derive(Debug)]
pub enum Unready {
    Map(RegistrationError),
    Verify(RegistrationError),
    Reservations(SubmitRefusal),
}

/// Maps and verifies `registration` and enables `disk`'s reservation commands over it, in that order.
///
/// # Errors
///
/// The first step that failed.
pub fn ready<N: Native>(
    registration: &mut ArenaRegistration<'_>,
    disk: &mut SpdkDisk<'_, N>,
) -> Result<(), Unready> {
    registration.map().map_err(Unready::Map)?;
    registration.verify().map_err(Unready::Verify)?;
    disk.enable_reservations(registration)
        .map_err(Unready::Reservations)
}

/// The same-host restart's connect: [`SpdkDisk::attach_restart`] under `record`, then [`ready`]. `registration` is
/// the unmapped registration the driver leases. The caller reads `record` through the `lock` the restart's
/// `LocalSource` reads, and it must be the record the restart checks at its step 2: the same binding and pair. The
/// fencer's host-ID step compares the host ID alone, and the attach checks the record's instance and volume against
/// the mappings file, which must be current for the host's instance and boot.
///
/// Between the attach and [`ready`], [`SpdkDisk::ready`] must report the controller enabled and ready.
///
/// # Errors
///
/// `connect_restart` returns [`ConnectError::Attach`] with the refusal when the attach fails.
/// [`ConnectError::Controller`] and [`ConnectError::Unready`] carry the attached driver.
pub fn connect_restart<'l, N: Native>(
    host: &Host,
    lock: &'l OwnerLock,
    registration: &mut ArenaRegistration<'_>,
    config: SpdkConfig,
    record: LocalRecord,
    limits: ReservationLimits,
) -> Connected<SpdkDisk<'l, N>> {
    let disk = attach_or_hold(registration, |registration| {
        SpdkDisk::attach_restart(host, lock, registration, config, record, limits)
    })
    .map_err(ConnectError::Attach)?;
    readied(disk, registration)
}

/// The fresh first acquisition's connect: [`SpdkDisk::attach`], which authenticates the assignment, reads the local
/// record the fresh path persisted under `lock` and confirms the instance and availability zone through `metadata`,
/// then [`ready`]. The fresh path calls it only after its acknowledged `E` bump.
///
/// The instance and zone confirmation is as strong as `metadata`. A production caller passes the instance metadata
/// service ([`Imds`](crate::bind::Imds)) and opens its session inside the connect closure, so the token covers both
/// requests after the bump. The fresh path's local records take no assignment, so a missing host key or an invalid assignment
/// refuses here, after the bump. The caller therefore authenticates the assignment, and checks its instance, mapped
/// volume and zone, before the sequence runs, and builds the local records' binding and key from it; this attach then
/// rechecks them.
///
/// Between the attach and [`ready`], [`SpdkDisk::ready`] must report the controller enabled and ready.
///
/// # Errors
///
/// `connect_fresh` returns [`ConnectError::Attach`] with the refusal when the attach fails.
/// [`ConnectError::Controller`] and [`ConnectError::Unready`] carry the attached driver.
pub fn connect_fresh<'l, N: Native>(
    host: &Host,
    lock: &'l OwnerLock,
    metadata: &dyn Metadata,
    registration: &mut ArenaRegistration<'_>,
    config: SpdkConfig,
    limits: ReservationLimits,
) -> Connected<SpdkDisk<'l, N>> {
    let disk = attach_or_hold(registration, |registration| {
        SpdkDisk::attach(host, lock, metadata, registration, config, limits)
    })
    .map_err(ConnectError::Attach)?;
    readied(disk, registration)
}

/// If `attach` fails after increasing the device count of `registration`, [`hold`] parks the thread and keeps
/// `registration` alive for the attached controller. `attach` must lease a device on failure only for a controller
/// it left attached.
pub(crate) fn attach_or_hold<D>(
    registration: &mut ArenaRegistration<'_>,
    attach: impl FnOnce(&mut ArenaRegistration<'_>) -> Result<D, SpdkAttachError>,
) -> Result<D, SpdkAttachError> {
    let leased = registration.devices();
    attach(registration).inspect_err(|error| {
        if registration.devices() > leased {
            hold(&format!("attach: {error:?} kept the controller attached"));
        }
    })
}

fn readied<'l, N: Native>(
    mut disk: SpdkDisk<'l, N>,
    registration: &mut ArenaRegistration<'_>,
) -> Connected<SpdkDisk<'l, N>> {
    if !disk.ready() {
        return Err(ConnectError::Controller(Box::new(disk)));
    }
    match ready(registration, &mut disk) {
        Ok(()) => {
            let pair = disk.own();
            Ok((disk, pair))
        }
        Err(unready) => Err(ConnectError::Unready(Box::new(disk), unready)),
    }
}

/// Ends `disk` and `registration` through PROVEN-STOP and returns the armed watchdog, whose deadline also covers the
/// environment's finish. A controller disable still pending after `patience` parks the thread.
///
/// `registration` is the one `disk` leased, `disk` is its last live lease, and nothing has taken `disk`'s stop proof;
/// otherwise the stop parks or refuses.
///
/// # Errors
///
/// A device-stopped record, watchdog, unregistration or detach that failed. Every error follows the proven disable,
/// and consumes both handles: the controller stays attached, and a refused unregistration keeps the arena
/// registered for the process's life.
pub fn stop<N: Native>(
    mut disk: SpdkDisk<'_, N>,
    mut registration: ArenaRegistration<'_>,
    patience: Duration,
) -> Result<Watchdog, String> {
    let stopping = Instant::now();
    while disk.quiesce() != QuiesceStatus::Stopped {
        if stopping.elapsed() > patience {
            hold("the controller's stop stayed unproven");
        }
    }
    let Some(stopped) = disk.stop_proof() else {
        hold("the controller gave no stop proof")
    };
    registration
        .device_stopped(stopped)
        .map_err(|error| format!("device stopped: {error:?}"))?;
    let watchdog = Watchdog::arm(Duration::from_secs(30), Arc::new(Park))
        .map_err(|error| format!("watchdog: {error}"))?;
    let undone = registration
        .unregister(&watchdog)
        .map_err(|retained| format!("unregister: {:?}", retained.error))?;
    if !disk.detach(&undone) {
        return Err("the controller stayed attached".to_owned());
    }
    Ok(watchdog)
}

/// Ends a fencer's table that still owns a command through PROVEN-STOP: quiesces it until every command of the table
/// ended, within `patience`, then ends its driver through [`stop`] with the patience left. A quiesce still unproven
/// after `patience` parks the thread with the table, its buffers and `registration` held, since a command the
/// controller still owns may write its buffer.
///
/// # Errors
///
/// As [`stop`].
pub fn stop_table<N: Native>(
    mut table: CommandTable<'_, SpdkDisk<'_, N>>,
    registration: ArenaRegistration<'_>,
    patience: Duration,
) -> Result<Watchdog, String> {
    let stopping = Instant::now();
    let mut out = Vec::with_capacity(usize::from(table.report().depth));
    while !matches!(table.quiesce(&mut out), QuiesceProgress::Quiesced(_)) {
        out.clear();
        if stopping.elapsed() > patience {
            hold("the fencer's table stayed unquiesced");
        }
    }
    out.clear();
    let Ok(disk) = table.release_idle() else {
        hold("the fencer's quiesced table still owned a command")
    };
    stop(
        disk,
        registration,
        patience.saturating_sub(stopping.elapsed()),
    )
}

/// The teardown watchdog's supervisor: on a missed deadline it parks the watchdog's thread, so the owner thread that
/// drops the watchdog waits on it for good.
struct Park;

impl Supervisor for Park {
    fn contain(&self) {
        hold("the teardown watchdog expired");
    }
}

/// Parks the calling thread for good, after one attempt at a notice on standard error. A notice standard error
/// refuses is dropped: an unwind out of here would end the process with the custody the park exists to keep.
pub(crate) fn hold(why: &str) -> ! {
    let _ = writeln!(
        std::io::stderr().lock(),
        "kestrike: {why}; custody stays held until the host is contained"
    );
    loop {
        std::thread::park();
    }
}
