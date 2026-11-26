//! The production storage driver: the SPDK NVMe poll-mode driver on the EBS
//! controller `kestrike-bind` bound to `vfio-pci`, behind [`Disk`](super::Disk).
//!
//! - Attach connects to the address the mappings file records once its driver link resolves to `vfio-pci`, re-identifies
//!   the controller (serial, model, PCI identity) and namespace (ID, sector
//!   size, capacity), copies the controller and namespace Identify data
//!   into the driver's [`AttachFacts`](super::AttachFacts) before any later
//!   native call, refuses a namespace with metadata or protection
//!   information or a sector size that does not divide 4 KiB, and allocates
//!   one I/O qpair sized so every accepted command, split at the namespace's
//!   boundary, fits SPDK's trackers and request pool.
//! - A submit is refused before SPDK sees it at the admission depth, for a
//!   range past the capacity or the transfer limit, once the driver is
//!   gone or stopping, and `NotVerified` while no verified arena range is
//!   installed or a failed check left the registration unverified, while an attach authority withholds reads and writes until
//!   a gate pass for the own pair, and for a reservation command naming a key or
//!   pair other than the attach authority's or carrying payload bytes that
//!   do not encode it; a buffer outside the installed range is
//!   `InvalidRange`. SPDK's `-ENOMEM` is `QueueFull`, `-ENXIO` latches
//!   `DeviceGone`, any other error is `InvalidRange`; 0 is accepted custody.
//!   An accepted submit writes its queue entry, and the next completion poll
//!   rings the submission doorbell once for all entries written since the
//!   previous ring.
//! - Native callbacks write terminals into preallocated staging records. A
//!   pick with a full sink returns before any native call. Otherwise it
//!   delivers at most the sink's room, polls SPDK with a nonzero limit no
//!   larger than that room, and delivers only terminals a healthy poll
//!   observed. A pick polls only the I/O qpair. A service call on a running
//!   driver submits the EBS statistics log-page command once a
//!   [`StatisticsHandle`] asked for it, and polls the admin queue once per
//!   call while that command is outstanding; quiesce polls it during the
//!   disable. A terminal staged during the service call's admin poll turns
//!   the driver gone. A failed poll, a failed
//!   controller, a terminal staged outside a healthy poll, or a Command Abort
//!   Requested or SQ Deletion status turns the driver gone, records the first
//!   such event for `controller_event`, and holds later terminals until a
//!   proven stop.
//! - Quiesce refuses new work, starts the controller disable, and returns
//!   `Stopped` only after valid register reads show CC.EN = 0 and
//!   CSTS.RDY = 0; only then does it free the qpair and discard every staged
//!   terminal. The driver keeps the raw CC and CSTS words of the latest
//!   disable read, so the proving read is the stop's certificate. A
//!   `Stopped` quiesce publishes `DeviceGone` for the statistics command and
//!   requests. The timeout callback counts reports and records the last
//!   `(qpair, command ID)`.
//! - Detach runs only on a stopped driver after the registration was undone,
//!   and a detach SPDK refuses leaves the driver stopped with its address
//!   reserved.

mod admin;
#[cfg(test)]
mod attach_tests;
mod certify;
mod checks;
#[cfg(test)]
mod checks_tests;
pub mod connect;
#[cfg(test)]
mod connect_tests;
mod disk;
#[cfg(test)]
mod disk_tests;
#[cfg(test)]
mod hardware_tests;
mod limits;
#[cfg(test)]
mod limits_tests;
mod native;
#[cfg(test)]
mod outstanding_tests;
#[cfg(test)]
mod record_tests;
#[cfg(test)]
mod reservation_tests;
mod staging;
#[cfg(test)]
mod staging_tests;
mod statistics;
#[cfg(test)]
mod statistics_tests;
#[cfg(test)]
mod stop_tests;

#[cfg(test)]
pub use disk::CanaryError;
#[cfg(test)]
pub(super) use disk::DriverWitness;
pub use disk::{HostIdFailure, SpdkAttachError, SpdkConfig, SpdkDisk};
pub use limits::LimitsError;
pub(crate) use native::{Native, Spdk};
#[cfg(test)]
pub(crate) use outstanding_tests::{
    scripted_attached, scripted_device_commanded, scripted_silent, scripted_silent_at,
    scripted_table,
};
#[cfg(test)]
pub(crate) use reservation_tests::{scripted_reserving, withdraw_with};
pub use statistics::{
    EbsStatistics, LatencyBin, LatencyHistogram, Reading, StatisticsError, StatisticsFailure,
    StatisticsHandle,
};
