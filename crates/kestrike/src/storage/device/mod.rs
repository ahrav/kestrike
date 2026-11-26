//! The storage-device substrate: host memory a storage device may read and write.
//! The buffer arena maps memory apart from every [`Storage`](super::Storage) region.
//!
//! Invariants owned by this module:
//!
//! - A [`ValidatedBufferConfig`] has a non-empty node mask and names each [`PoolKind`] exactly once, with a positive buffer count.
//! - Every buffer length is a positive multiple of [`IO_UNIT`].
//! - The backing size is the pools' summed bytes rounded up to the hugepage size.
//!   Validation computes the backing size with checked arithmetic and bounds it by `isize::MAX`.
//! - A [`BufferArena`] exists only after its hugepage mapping, labeled [`Region::Buffers`](super::Region::Buffers), passes the following checks:
//!   The backing and the pool metadata were charged to a copy of the caller's engine budget before mapping.
//!   The mapped base address is aligned to the hugepage size.
//!   The validated node mask was bound to the mapping before the first touch.
//!   Every backing page was populated, found resident, and found on a node in the mask.
//! - A failed initialization releases the mapping once at its full extent, or reports the mapping retained and charged.
//!   The caller's budget changes only on success or a retained rollback.
//! - The backing is carved into the configured pools contiguously in [`PoolKind::ALL`] order: the storage kinds a volume uses, the packet kinds a network endpoint receives frames into and builds transmit headers in, and the reservation-command reserve.
//!   Buffers are [`IO_UNIT`] aligned and pairwise disjoint, each inside its pool's span; the tail holds none.
//! - A [`Buffer`] handle is the only safe access to its buffer's bytes, and at most one handle names a buffer.
//!   Per pool, `free + application + storage + quarantined + posted + nic_held + retired = count` after every call.
//!   A buffer a device still reads after its handle dropped holds a [`NicHold`] per device reference and returns to its free stack only after the last one, and a receive buffer posted to a device has no CPU byte view until the device finished writing it.
//!   Acquire takes any free buffer of the kind, most recently freed first, and neither acquire nor drop allocates.
//! - The arena unmaps only through [`BufferArena::release`], at most once, and reports whether the kernel refused.
//!   Release refuses and returns the arena with its holders while any buffer is held, including one whose handle was leaked.
//!   Dropping the arena abandons the mapping.
//!   An [`ArenaBacking`], [`RegistrationHold`] or [`Buffer`] borrows the arena, so release cannot run while one lives.
//!   Release also refuses while a registration hold has not ended, including one dropped or forgotten.
//! - The arena and its pools are neither `Send` nor `Sync`, and neither a [`Buffer`] nor a [`CommandTable`] is `Send`.
//! - A driver implements the `unsafe` [`Disk`] seam, whose `# Safety` section states the guarantees safe code relies on to free and reuse buffers.
//!   Submission takes a [`CommandToken`], a [`DeviceRange`] and a [`DmaRange`] and is `unsafe` for its caller; picking completions and quiescing are safe.
//!   Only a [`CommandTable`] calls the unsafe submits in safe code.
//! - A [`CommandTable`] owns one driver, until the table is consumed with none of its commands outstanding, and every buffer its commands hold: a submitted buffer comes back only in its command's [`Terminal`] event, and a refused one comes back at once with nothing outstanding.
//!   Cancel quarantines and never frees; timeouts and dropped requests free nothing; quiesce is proven only when every command returned or the driver proved a stop.
//!   Its `free_slots + pending + abandoned + retired = depth`, and with one table over one arena its pending and abandoned commands equal the pools' storage and quarantined buffers.
//! - Callers of the substrate uphold three rules: a [`ReadDone`] is the only evidence of device-written bytes and covers exactly the requested length of a successful read; a failed or quiesced write leaves the device's contents unknown; and a freshly acquired buffer holds whatever its previous holder left there, which before its first use is the hugepage's zero fill.
//! - A [`DeviceRange`] and a [`ValidDeviceGeometry`] exist only after their unit, sector and limit checks passed.
//!   [`DeviceStatus::classify`] is the one rule that turns raw status into success, a short transfer or a failure.
//! - A [`CompletionSink`] never accepts more than its vector's spare capacity, and counts every push it refuses.
//! - Hugepage backing proves the CPU mapping and host population only.
//!   A driver that registers the arena with a device owns the device address translation, mapping and reach for it.
//! - An [`IdentifySnapshot`] owns the Identify bytes a driver captured at attach and decodes them only through [`IdentifyFacts::decode`]; [`completion_is_durable`] admits the `completion-without-volatile-cache` profile only for whole, decodable evidence that matches the attached device and reports no volatile write cache, and [`PersistenceProfile::derive`] builds that profile from the [`AttachFacts`] the driver returned.
//! - [`SpdkDisk`] is the production [`Disk`]: the SPDK NVMe poll-mode driver with one I/O qpair on the EBS controller bound to `vfio-pci`; its `spdk` module states the driver's invariants.

mod area;
#[cfg(kani)]
mod area_kani;
mod arena;
#[cfg(test)]
mod arena_tests;
mod config;
mod custody;
#[cfg(test)]
pub(crate) mod custody_witness;
#[cfg(test)]
mod custody_witness_tests;
mod disk;
#[cfg(test)]
mod disk_contract;
#[cfg(test)]
mod disk_contract_control_tests;
#[cfg(test)]
mod fault_tests;
#[cfg(test)]
mod fidelity_tests;
#[cfg(test)]
mod fit_tests;
mod geometry;
mod identify;
#[cfg(test)]
mod identify_bytes_tests;
#[cfg(test)]
mod identify_decode_tests;
#[cfg(test)]
pub(crate) mod identify_fixture;
#[cfg(test)]
mod identify_tests;
#[cfg(test)]
mod nic_tests;
mod packet;
#[cfg(test)]
mod persistence_contract;
#[cfg(test)]
mod persistence_tests;
mod pool;
#[cfg(test)]
mod pool_replay_tests;
#[cfg(test)]
mod pool_tests;
mod profile;
#[cfg(test)]
mod profile_tests;
#[cfg(test)]
mod refused_report_bytes_tests;
mod reservation;
#[cfg(test)]
mod reserved_completion_tests;
#[cfg(test)]
pub(crate) mod sim;
#[cfg(test)]
mod sim_tests;
#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the simulator supplies a Disk in place of the SPDK driver"
)]
mod spdk;
mod status;
mod table;
#[cfg(test)]
mod table_charge_tests;
#[cfg(test)]
mod table_tests;
mod torn_write;

pub use arena::{
    ArenaBacking, ArenaFailure, BufferArena, RegistrationHold, ReleaseBlocked, Released,
};
pub use config::{
    BufferConfig, BufferConfigError, IO_UNIT, PoolKind, PoolSpec, SECTOR, ValidatedBufferConfig,
};
pub(crate) use custody::{source_frees, source_writable};
pub use disk::{
    CommandToken, Completion, CompletionSink, Disk, DmaRange, QuiesceStatus, RefusalReason,
    SubmitRefusal,
};
pub use geometry::{
    DeviceGeometry, DeviceGeometryError, DeviceRange, DeviceRangeError, ValidDeviceGeometry,
};
pub use identify::{
    AttachFacts, AttachedIdentity, IDENTIFY_LEN, IdentifyFacts, IdentifyMalformed, IdentifyRaw,
    IdentifyRecord, IdentifySnapshot, NamespaceAtomics, NvmeVersion, TransferLimits,
    VolatileWriteCache,
};
pub(crate) use packet::{MEMPOOL_FLAGS, object_overhead};
pub use packet::{PRIVATE, PacketLayout};
pub(crate) use pool::Pool;
#[cfg(test)]
pub(crate) use pool::Pools;
pub use pool::{
    Buffer, BufferPoolReport, HoldError, NicHold, PoolExhausted, RxPosted, SourceRange, SpanError,
};
pub use profile::{
    AtomicsRefusal, Boundary, DeriveRefusal, PersistenceProfile, ProfileKind, ProfileRefusal,
    UnitSource, completion_is_durable,
};
pub(crate) use reservation::KEY_DATA_BYTES;
#[cfg(test)]
pub(crate) use reservation::check_report_identity;
pub use reservation::{
    EndedPreempt, EndedRefusal, HolderRefusal, LineagePreempt, ReportError, ReservationCommand,
    ReservationLimits, ReservationLimitsError, SelfPreempt, check_own_record,
    parse_extended_report, report_exhid,
};
pub(crate) use reservation::{held_by_recorded, own_record, unheld_among_recorded};
#[cfg(test)]
pub use spdk::CanaryError;
pub use spdk::connect;
pub use spdk::{
    EbsStatistics, HostIdFailure, LatencyBin, LatencyHistogram, LimitsError, Reading,
    SpdkAttachError, SpdkConfig, SpdkDisk, StatisticsError, StatisticsFailure, StatisticsHandle,
};
pub(crate) use spdk::{Native, Spdk};
#[cfg(test)]
pub(crate) use spdk::{
    scripted_attached, scripted_device_commanded, scripted_reserving, scripted_silent,
    scripted_silent_at, scripted_table, withdraw_with,
};
pub use status::{Classification, ControllerEvent, DeviceStatus};
pub use table::{
    Admission, CommandTable, Failure, Operation, PollReport, QuiesceProgress, Quiesced, ReadDone,
    Refusal, Rejected, Stale, TableError, TableReport, Terminal,
};
pub(crate) use table::{BorrowUntilDrop, slot_of};
pub use torn_write::TornWriteFields;
