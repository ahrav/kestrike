//! Volume configuration: the storage's capacity, slots, allocator work limit, placement, headroom watermarks, read share and record format; the per-tick limits; and every check attach runs.

use super::super::device::{DeriveRefusal, PoolKind, TableError};
use super::super::ledger::EngineBudgetExceeded;
use super::super::recovery::AreaRefusal;
use crate::failover::records::{Layout, LayoutRefusal};

/// The volume fields of [`StorageConfig`](super::super::StorageConfig); every field is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// `report_commands` is the driver's reservation-command share, from
/// [`Disk::reservation_limits`](crate::storage::Disk::reservation_limits) and
/// [`ReservationLimits::commands`](crate::storage::ReservationLimits::commands), or zero for a data-only driver.
/// Register, Report, Acquire, Preempt and Preempt-and-Abort all consume that share.
pub struct VolumeConfig {
    /// Raw capacity in bytes: a positive whole number of [`IO_UNIT`](super::super::IO_UNIT)s, at most `2^37` of them. Attach checks it against the device.
    pub raw_bytes: usize,
    /// Units reserved for recovery metadata; [`StorageConfig::validate`](super::super::StorageConfig::validate) requires `1 <= metadata_units < V`, where `V = raw_bytes / IO_UNIT`.
    pub metadata_units: u64,
    /// Object slot count `O`.
    pub slot_count: usize,
    /// Bitmap words, summary nodes and index nodes one extent reservation or return may visit, updates included; validation requires at least the bound the allocator derives from the payload units `P = V - metadata_units`, the slot count and the largest extent, and at most `ALLOC_SEARCH_WORDS_LIMIT`, `(usize::MAX - 22) / 2 - 22`.
    /// A reservation preflights the largest extent's bound, which equals every admitted extent's and is at most this many steps; a transfer return preflights the return work of what the slot holds (`Pool::held_work`), that bound for a direct extent or a sequence's whole return for a sequence handle; each debits the visits it makes; [`Storage::reserve_minimum`](crate::storage::Storage::reserve_minimum) includes this limit, and [`Storage::service_minimum`](crate::storage::Storage::service_minimum) includes, once per service pass, the largest extent's work bound plus a sequence visit's 22 steps when the volume carries a sequence arena; validation keeps the work bound at most this limit.
    pub alloc_search_words: usize,
    /// Read operations that may be live at once; each holds one table slot per outstanding command, at most `1 + read_ahead`.
    pub read_ops: u32,
    /// Table slots reads may hold at once; attach requires `1 <= read_commands` and `read_commands + metadata_commands + report_commands < depth`, refusing `MetadataCommandsOutOfRange` otherwise, so `depth - read_commands - metadata_commands - report_commands` slots stay for writes whatever the metadata commands claim.
    /// A read whose command finds every one of them held waits, with no buffer and no table slot, for a tick to submit it.
    pub read_commands: u32,
    /// Commands a read may hold outstanding ahead of its current one, at most [`MAX_READ_AHEAD`](super::MAX_READ_AHEAD): a grant made while its current command is outstanding or verifying submits the next command at once, also while the first command's header is still unverified, so a record larger than one command streams up to `1 + read_ahead` commands at a time from its first command on. Zero reads one command at a time.
    pub read_ahead: u8,
    /// Table slots reserved for metadata commands; attach requires `metadata_commands >= 1`, `read_commands + metadata_commands + report_commands < depth` and a maintenance pool of at least this many buffers, each at least one metadata block long. The attach bootstrap's root probes and RESET writes hold one command at a time, and a warm bootstrap's named-slot and suffix reads hold up to `metadata_commands`. Fill writes hold each of these slots that no staged or outstanding metadata command claims, and a staged command waits for the writes holding its slot to end.
    pub metadata_commands: u32,
    /// Times a metadata write whose terminal reported `Failed` is resubmitted with the same bytes before the volume records `MetadataFailed` and closes admission; attach requires at least one.
    pub metadata_retries: u32,
    /// The feed whose coverage positions the storage takes and every root records.
    pub feed: super::super::coverage::FeedContract,
    /// The physical-clock bounds publications convert under and every root records.
    pub clock: super::super::portable::ClockContract,
    /// The on-device record format every volume read verifies against.
    pub record: super::super::record::RecordConfig,
    /// Nodes the volume control mapping is bound to.
    pub nodes: super::super::placement::NodeMask,
    /// Roots of the sequence arena, 32 KiB each, whose blocks hold the extent sequences of promised objects of two or more extents; with zero roots every promise refuses `Blocks`. At most `u32::MAX / 1024`.
    pub block_roots: usize,
    /// Clean reserve `R` in [`IO_UNIT`](super::super::IO_UNIT)s: a claim of `C` charged units requires at least `C + R + U` free units, where `U` is the escrow of units promised to builders, and otherwise refuses `CleanReserve`, so every claim leaves `R` free beside the promised units. Validation requires `R >= 1`, `R + Cmax <= P` for the largest object's charged units `Cmax` and the payload units `P = V - metadata_units`, and with maintenance `R + Cmax <= low_units`.
    pub reserve_units: u64,
    /// Budgeted maintenance's headroom watermarks, or `None` for a storage that runs no maintenance, whose `maintain` refuses `NotConfigured` while admission is open and delegates to the close service after close.
    /// When present every value is required and checked; none has a default.
    pub maintenance: Option<VolumeWatermarks>,
    /// The recovery helpers' thread count and bounds for each warm attempt; attach requires every field positive and the byte bounds to hold one metadata block's window charge, the block's length in input bytes and 24 output bytes per input byte, the helpers' output factor, a validity floor every attach checks whether or not it starts a helper job, and charges both byte bounds to the engine budget.
    pub recovery: super::helpers::RecoveryLimits,
}

/// Validated volume geometry satisfies `payload_units = V - metadata_units` and `1 <= metadata_units < V`, where `V = raw_bytes / IO_UNIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeGeometry {
    metadata_units: u64,
    payload_units: u64,
}

impl VolumeGeometry {
    pub(crate) fn new(metadata_units: u64, payload_units: u64) -> Self {
        debug_assert!(
            metadata_units > 0
                && payload_units > 0
                && metadata_units + payload_units <= super::super::extent::LOCATOR_START_LIMIT
        );
        Self {
            metadata_units,
            payload_units,
        }
    }

    pub fn metadata_units(&self) -> u64 {
        self.metadata_units
    }

    pub fn payload_units(&self) -> u64 {
        self.payload_units
    }

    pub fn volume_units(&self) -> u64 {
        self.metadata_units + self.payload_units
    }

    /// The recorded `layout` assigns `layout.units` device units to the prefix and the remaining `volume_units` to the payload.
    pub fn recorded(layout: &Layout, volume_units: u64) -> Result<Self, GeometryRefusal> {
        layout.check_floor().map_err(GeometryRefusal::Layout)?;
        if volume_units > super::super::extent::LOCATOR_START_LIMIT {
            return Err(GeometryRefusal::VolumeTooLarge {
                volume: volume_units,
            });
        }
        if layout.units >= volume_units {
            return Err(GeometryRefusal::PastVolume {
                units: layout.units,
                volume: volume_units,
            });
        }
        Ok(Self::new(layout.units, volume_units - layout.units))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeometryRefusal {
    Layout(LayoutRefusal),
    VolumeTooLarge {
        volume: u64,
    },
    /// The recorded prefix of `units` units reaches the end of a volume of `volume` units, which needs at least one payload unit after it.
    PastVolume {
        units: u64,
        volume: u64,
    },
}

/// The volume's headroom watermarks for budgeted maintenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeWatermarks {
    /// Maintenance uses `low_units` as the headroom target `H`, counting placeable units less escrowed units, clamped at zero, plus in-flight units. Placeable units count each maximal free run's whole charges of `c` units, `c` the units of the largest object's first extent (63 when that object spans several extents), so they are at most the free units and a run shorter than `c` counts zero. Validation requires `reserve_units + record_units <= low_units <= payload_units - (payload_units mod c)`. A read whose units rule is not short therefore has free units less the escrow, plus in-flight units, of at least `low_units`, so at the watermark the claimable units are at least `low_units - reserve_units` less the in-flight units the headroom predicate credits, and while every eviction counted in `in_flight_units` also counts toward `retired_units`, a claim that passes the retired-pressure check sees at most `T - 1` of them, `T` being `retired_units`. An owner admitting `puts > 0` PUTs refuses to start below [`structural_floor`](super::super::ValidatedConfig::structural_floor)`(puts)`, `reserve_units + puts × Cmax + T` with `Cmax` the largest object's charged units, at which a read whose units rule is not short keeps at least `puts × Cmax + 1` units claimable for a claim that passes the retired-pressure check. A deployer sets `low_units = structural_floor(puts) + F`, with `F` the margin that covers the predicate's two raw terms: subtracting the escrow overstates the placeable space its placements leave by at most `c - 1` units per live builder, and the in-flight units overstate the placeable space their returns add by at most `c - 1` units per in-flight victim. Those two bounds hold while the escrow is at most the placeable units; a larger escrow clamps their difference to zero and overstates placeable space by the escrow less the placeable units as well, until returns land. The same raw terms can also understate placeable space, since a placement shorter than `c` can leave the placeable units unchanged and each returned extent that joins two free neighbours can add up to `2 * (c - 1)` units beyond its own; after such a read headroom can evict more than the watermark needs.
    ///
    /// An empty volume maximizes placeable units at `payload_units - (payload_units mod c)`, the [`placeable_ceiling`](super::super::ValidatedConfig::placeable_ceiling). `LowUnitsOutOfRange` caps `low_units` at that ceiling, so an empty volume satisfies the threshold when in-flight evictions are zero.
    ///
    /// An eviction whose retirement parks on a busy pool gate counts toward `in_flight_units` before service counts it toward `retired_units`, and in between the claimable units can fall short of the floor's bound. The owner's start check counts its PUTs alone; local fills claim against the same clean reserve, so a deployment that streams them beside PUTs sizes `low_units` from the floor of their sum.
    pub low_units: u64,
    /// Free object slots (free plus in flight) maintenance keeps: `1 <= min_free_slots < O`.
    pub min_free_slots: usize,
    /// The retired charge allowance `T`: units of retired objects not yet
    /// returned at or above which fills refuse with pressure, and within
    /// which a discretionary victim's whole charge must fit; `T >= Cmax`, so
    /// an empty retired backlog admits one victim of any size.
    pub retired_units: u64,
}

/// Work one [`Volume::poll_storage`](super::Volume::poll_storage) call may do; every field is positive, and both bursts are at most the table depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickConfig {
    /// Commands the tick may submit.
    pub submit_burst: u32,
    /// Terminals the tick may apply; also the capacity of the terminal scratch vector.
    pub terminal_burst: u32,
    /// Bytes the tick may fold into checksums.
    pub validate_bytes: usize,
}

/// Why attach refused. The driver comes back unchanged, the caller's budget is unchanged, and no table exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachError {
    /// The machine or driver limits disagree with the serving bounds.
    AuthorityBounds,
    /// The serving machine's session differs from the authority's session.
    AuthoritySession,
    /// The storage is not live: it is finalizing or drained.
    TornDown,
    /// The storage's admission is closed. Finalization keeps an inspection it paid for on the premise that nothing
    /// claims a slot after the cutoff, so a volume, whose bootstrap installs restored slots, never attaches past it.
    Closed,
    /// The arena holds no pool of this storage kind.
    MissingKind(PoolKind),
    /// A [`TickConfig`] field is zero.
    ZeroTickField,
    /// The larger burst exceeds the table depth.
    BurstAboveDepth { burst: u32, depth: u16 },
    /// `read_commands` is zero or at least the table depth.
    ReadCommandsOutOfRange { read_commands: u32, depth: u16 },
    /// `read_ahead` exceeds [`MAX_READ_AHEAD`](super::MAX_READ_AHEAD).
    ReadAheadOutOfRange { read_ahead: u8 },
    /// `Disk::attach_facts` returned `None`; attach derives the persistence profile from those facts.
    NoAttachFacts,
    /// The attach facts admit no persistence profile.
    Profile(DeriveRefusal),
    /// The metadata prefix fails to tile in qualifying blocks of the profile's unit.
    Metadata(AreaRefusal),
    /// `metadata_commands` or `metadata_retries` is zero.
    ZeroMetadataField,
    /// The maintenance pool has `buffers` free buffers of `buffer_len` bytes, fewer than `metadata_commands` or each shorter than one metadata block.
    MaintenanceShort { buffers: u32, buffer_len: u32 },
    /// the read, metadata and driver Report shares together reach the table depth, leaving fills no table slot.
    MetadataCommandsOutOfRange {
        read_commands: u32,
        metadata_commands: u32,
        reservation_commands: u32,
        depth: u16,
    },
    /// The physical-clock provider's readings name another scale than the storage's clock contract.
    ClockScale {
        provider: super::super::portable::ClockScale,
        contract: super::super::portable::ClockScale,
    },
    /// `chunk_len` does not divide the receive-write buffer length.
    ChunkLenNotDividingBuffer { chunk_len: u32, buffer_len: u32 },
    /// The windows that hold the largest admissible local header and the first payload chunk, `(floor(max_header_bytes / chunk_len) + 1) * chunk_len` bytes, exceed `min(read-response buffer length, max_transfer)`.
    ReadCommandFit { needed: u64, limit: u64 },
    /// The receive-write pool holds fewer than `sum(F[s]) + 1` buffers that have not retired: every live fill may hold its first segment's buffer until its last payload byte, and one more buffer lets some fill submit a later segment, so the fills cannot all wait on a pool that serves only this volume.
    ReceiveBuffersBelowFills { buffers: u32, needed: usize },
    /// The driver's geometry is invalid, the depth is zero, or the depth exceeds the device's queue depth.
    Table(TableError),
    /// The volume's `raw_bytes` exceed the device's validated `capacity`, so the volume's last units would lie past the device's end.
    VolumeExceedsDevice { raw_bytes: u64, capacity: u64 },
    /// The table and the volume's arrays, with a warm source also its envelope, together exceed the caller's budget.
    Envelope(EngineBudgetExceeded),
    /// This storage already attached a volume; attach succeeds once per storage.
    AlreadyAttached,
    /// A [`RecoveryLimits`](super::helpers::RecoveryLimits) count is zero, `helpers` exceeds `jobs`, the CPU set is empty, a byte bound holds less than one `unit`-byte metadata block's window charge (`unit` input bytes and `24 * unit` output bytes, the helpers' output factor), or the recovery I/O share's owner part holds less than one `unit`-byte metadata block plus one suffix block, or the share has a zero interval, no owner or more than 128 owners; with a warm source, less than one `unit`-byte slot read's charge or one destination guard's bytes, fewer `jobs` than the reader's windows and destinations, or an owner part below one slot read plus one suffix block. `unit` is the length the refusing check compared against: the metadata block length for the helper counts and byte bounds; the larger of the metadata block and a warm source's slot read for the recovery I/O share, its interval and owner count included; the slot read length for a warm source's window, guard and job bounds; and one `IO_UNIT` when the warm plan's estimate overflows, which no recovery limit fixes. Equal lengths identify no single check, so the caller tests every condition listed here against its limits.
    RecoveryLimits { unit: u32 },
    /// The warm source's records layout spans `units` and the volume's metadata prefix `metadata_units`, two different
    /// counts; a restored locator names a payload unit after the layout's units.
    NamedSlot { units: u64, metadata_units: u64 },
}

/// The clock contract of [`test_volume`]: smeared UTC, readings up to 4 ms wide, no rate error.
#[cfg(test)]
pub(crate) const TEST_CLOCK: super::super::portable::ClockContract =
    super::super::portable::ClockContract {
        scale: super::super::portable::ClockScale::UtcSmeared,
        max_uncertainty_ns: 4_000_000,
        rate_error_ppb: 0,
        provenance: 1,
    };

/// The feed contract of [`test_volume`].
#[cfg(test)]
pub(crate) const TEST_FEED: super::super::coverage::FeedContract =
    super::super::coverage::FeedContract {
        authority: [0xFE; 16],
        contract: 1,
    };

/// The metadata units of [`test_volume`]: the two root slots and fourteen blocks past them.
#[cfg(test)]
pub(crate) const TEST_METADATA_UNITS: u64 = 16;

/// A [`TEST_METADATA_UNITS`]-unit metadata prefix, two 4096-byte root slots and the blocks past them, precedes the `payload_bytes` payload, so the volume's `raw_bytes` are `payload_bytes + TEST_METADATA_UNITS * IO_UNIT`.
#[cfg(test)]
pub(crate) fn test_volume(payload_bytes: usize, slot_count: usize) -> VolumeConfig {
    test_volume_with(payload_bytes, TEST_METADATA_UNITS, slot_count)
}

#[cfg(test)]
pub(crate) fn test_volume_with(
    payload_bytes: usize,
    metadata_units: u64,
    slot_count: usize,
) -> VolumeConfig {
    VolumeConfig {
        raw_bytes: payload_bytes + metadata_units as usize * super::super::IO_UNIT,
        metadata_units,
        slot_count,
        alloc_search_words: super::super::extent::work_bound(
            (payload_bytes / super::super::IO_UNIT) as u64,
            slot_count,
            1,
        ),
        read_ops: 2,
        read_commands: 2,
        read_ahead: 0,
        metadata_commands: 1,
        metadata_retries: 2,
        clock: TEST_CLOCK,
        feed: TEST_FEED,
        block_roots: 0,
        reserve_units: 1,
        record: super::super::record::RecordConfig { chunk_len: 8192 },
        nodes: super::super::placement::NodeMask::from_nodes(&[0]).expect("node zero fits"),
        maintenance: None,
        recovery: test_recovery(),
    }
}

/// The recovery limits of [`test_volume`]: two helpers on the calling thread's CPUs, four live jobs, room for four 4 KiB blocks, and a recovery I/O share of 1 TiB per tick for one owner.
#[cfg(test)]
pub(crate) fn test_recovery() -> super::helpers::RecoveryLimits {
    super::helpers::RecoveryLimits {
        cpus: super::CpuSet::current().expect("the thread's affinity mask"),
        helpers: 2,
        jobs: 4,
        input_bytes: 4 * 4096,
        output_bytes: 4 * 4096 * super::helpers::OUTPUT_PER_BYTE,
        adopt: 4,
        io: super::super::recovery::HostShare {
            bytes: 1 << 40,
            interval: 1,
            owners: 1,
        },
    }
}
