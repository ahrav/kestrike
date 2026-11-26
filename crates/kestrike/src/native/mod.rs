//! The process's native SPDK and DPDK environment, the arena's
//! device-facing registration, and the DPDK ENA transport.
//!
//! Invariants owned by this module:
//!
//! - One [`Environment`] exists per process. It initializes once, from a
//!   [`EnvConfig`] naming the owning thread's core, the hugepage directory and
//!   the only PCI devices the process may attach, with no shared-memory
//!   identity, and finishes once. Initialization runs the pre-init hooks
//!   (where mempool ops register), then SPDK and DPDK, then DPDK's timer
//!   subsystem, and checks that the calling thread is the configured core.
//!   Finish finalizes the timers and then the environment. A finish refused
//!   before either finalizer returns the live environment; once the timers
//!   are finalized, a watchdog expiry leaves only a [`Contained`] value,
//!   whose only operation is drop.
//! - An [`ArenaRegistration`] is the one owner of the arena's device-facing
//!   state for every device in the process. It computes explicit per-page
//!   IOVAs, registers the arena with DPDK as external memory and then with
//!   SPDK, maps it once in the default VFIO container in IOMMU mode after a
//!   device attaches, and verifies every backing page's SPDK and DPDK
//!   translation. No device may use arena memory before
//!   [`ArenaRegistration::is_ready`].
//! - Undo runs only after every attached device proved its stop: SPDK
//!   unregisters while the external memory still exists, the IOMMU mapping is
//!   removed while the devices remain attached, then the external memory
//!   unregisters. A failed or unproven step keeps the registration's
//!   [`RegistrationHold`](crate::storage::RegistrationHold), so the arena
//!   stays mapped, charged and unreleasable.
//! - The DPDK transport serves the arena's packet kinds through Rust mempool
//!   ops ([`PacketMempool`]), validates every received frame before frame
//!   parsing and sends each datagram as a header buffer chained to at most
//!   two retained read buffers ([`Burst`], [`Wire`]), each holding a device
//!   reference until the device returns it. [`Burst::over`] builds a
//!   [`Burst`] only when its port's device lease and every pool's device
//!   name one device that the registration leased. [`EnaPort`] runs the ENA port
//!   only as qualified, starts it only over a verified registration, proves
//!   its DMA stop by clearing bus mastering before the driver frees anything,
//!   and recovers in place after a reset. The dataplane functions bring a
//!   port up and down in registration order and report its startup settings
//!   ([`StartupReport`]).
//! - Memory falls in three accounts:
//!   - The engine budget holds the Rust heap state the transport retains:
//!     each packet mempool's boxed ops state and a payload pool's
//!     descriptor stack, out flags and descriptor memory, the burst logic's
//!     translations, routes, batch arrays and boxed registration callbacks,
//!     and the addressing's source table and header templates. Each
//!     constructor charges its state to a
//!     copy of the caller's [`EngineBudget`](crate::storage::EngineBudget)
//!     before it allocates, claims a pool kind or creates a native pool, and
//!     commits the copy on success, so a composition that passes one budget
//!     charges each allocation once.
//!   - DPDK's control structures, mempool headers and device queue memory
//!     come from the host's hugepage pool, which every owner process on the
//!     host shares; the host's hugepage reservation must cover the native
//!     use of every owner process, which [`EnvConfig`] leaves unbounded per
//!     process.
//!   - Process-level work allocates from the process heap uncharged:
//!     environment initialization and teardown, the environment's arguments,
//!     its captured probe log, each watchdog's thread and each
//!     [`ControllerSupervisor`]'s id, expected acknowledgement and frame
//!     buffer of up to [`FRAME`] bytes.
//! - Teardown runs under a [`Watchdog`]. Its expiry asks the [`Supervisor`]
//!   to contain the devices and host, and every later step is skipped, so the
//!   mapped memory stays held in the parked process. Process exit is not a
//!   proof that DMA stopped: in no-IOMMU mode an abrupt death can release the
//!   backing before VFIO's close disables bus mastering, and a later reset
//!   does not undo that exposure. Hosts running in that mode accept this
//!   limitation explicitly.

#[cfg(test)]
mod arena_pool_charge_tests;
mod burst;
#[cfg(test)]
mod burst_poison_tests;
#[cfg(test)]
mod burst_tests;
#[cfg(test)]
mod bus_master_clear_tests;
#[cfg(test)]
mod chain_tests;
mod containment;
#[cfg(test)]
mod containment_lost_channel_tests;
#[cfg(test)]
mod containment_tests;
mod dataplane;
#[cfg(test)]
mod dataplane_tests;
mod dma;
mod ena;
#[cfg(test)]
mod ena_tests;
#[cfg(test)]
mod ended_watch_tests;
mod env;
#[cfg(test)]
mod env_tests;
mod mempool;
#[cfg(test)]
mod mempool_tests;
#[cfg(test)]
pub(crate) mod mock;
mod pci;
#[cfg(test)]
mod pci_tests;
mod recovery;
mod registration;
#[cfg(test)]
pub(crate) mod registration_tests;
mod watchdog;
#[cfg(test)]
mod watchdog_tests;
mod wire;
#[cfg(test)]
mod wire_checksum_tests;
#[cfg(test)]
pub(crate) mod wire_fuzz_tests;
#[cfg(test)]
mod wire_tests;

pub use burst::{
    Burst, BurstError, BurstRefusal, BurstReport, Health, Link, Port, Prepared, TxBurst, Unproven,
};
pub use containment::{ControllerSupervisor, EndpointError, FRAME};
pub(crate) use dataplane::pci_address;
pub use dataplane::{
    DataplaneError, SOURCE_PORTS, StartupReport, allowed_devices, attach_port, start_port,
    stations, stop_port,
};
#[cfg(test)]
pub(crate) use dataplane::{StopFailure, stop_port_watched};
pub use dma::{DmaMode, DmaPolicy, DmaReport, IovaMode};
#[cfg(test)]
pub(crate) use ena::CAUSE_TURNS;
pub use ena::{ALLOWANCES, EnaConfig, EnaPort, Llq, MTU, PortError, PortReport};
pub use env::{Contained, EnvConfig, EnvError, Environment, PciAddress, Unfinished};
pub use mempool::{MempoolError, OpsReport, PacketMempool};
#[cfg(test)]
pub(crate) use mempool::{OpsState, Role};
#[cfg(test)]
pub(crate) use pci::BUS_MASTER;
pub use recovery::{RecoveryEpisode, RecoveryStage, RecoveryWatch};
pub use registration::{
    ArenaRegistration, DeviceLease, DeviceStopped, RegistrationError, RegistrationStep, Retained,
    Unregistered,
};
pub(crate) use registration::{Readiness, RegistrationId};
pub use watchdog::{Supervisor, Watchdog};
pub use wire::{Refused, RxMeta, Station, Wire, WireError};
