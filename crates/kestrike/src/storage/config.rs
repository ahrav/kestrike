//! Storage configuration and its validation.
//!
//! [`StorageConfig`] is caller input with no defaults; every limit is supplied.
//! [`ValidatedConfig`] can only be produced by [`StorageConfig::validate`], so
//! holding one proves: the page size is a power of two; `Mmax` is present;
//! both caps fit the header's 32-bit length fields and `Mmax + Bmax` stays
//! within the 512 MiB object ceiling; every local header is shorter than one
//! 4 KiB unit, the shortest window, so it ends inside its record's first
//! window, which a compile-time check proves for every record format; the
//! window holding the largest local header and the first payload byte ends
//! within one extent's 256 KiB charge; the largest object's charge, summed
//! over its extents' headers, payloads and padding, fits the payload range;
//! the volume is a positive whole number `V` of units, at most `2^37` of them;
//! the metadata prefix `M` satisfies `1 <= M < V`, leaving `P = V - M`
//! payload units;
//! `alloc_search_words` is at least the extent allocator's work bound for
//! the payload units, the slot count and the largest extent, and at most
//! `ALLOC_SEARCH_WORDS_LIMIT`, `(usize::MAX - 22) / 2 - 22`; the slot count stays below
//! `TABLE_INDEX_LIMIT`, `2^31 - 1`, so every
//! slot index stays below the `u32::MAX` policy terminator; the clean
//! reserve `R` is at least one unit and `R + Cmax <= P`, where `Cmax` is the
//! largest object's charged units, so an empty volume
//! holds the largest object's charge; when watermarks are present, `min_free_slots` lies in
//! `1..O` and the headroom target `H`, `low_units`, satisfies
//! `R + Cmax <= H <= P - P mod c`, with `c` the units of the largest
//! object's first extent, so an empty volume, whose one free run holds
//! `P - P mod c` placeable units, meets `H`, and a volume whose free units
//! less the escrow, plus
//! its in-flight units, reach `H` holds, once its in-flight extents return,
//! the units the largest object needs to pass the clean reserve check beside
//! the units already promised, and the retired allowance `T`,
//! `retired_units`, satisfies `T >= Cmax`, so an empty retired backlog
//! admits one victim of any size; the volume names at least one node;
//! and the slot count `O` leaves the era counter room to stamp every admitted
//! object's retirement below `u64::MAX` after the terminal band begins, so no
//! stamp ever wraps.
//!
//! Validation performs no OS call and no heap allocation. Checks against the
//! device itself run when a volume attaches.
//!
//! [`ValidatedConfig::structural_floor`] derives the lowest `low_units` an
//! owner admitting `promises > 0` PUTs starts with, `R + promises × Cmax +
//! T`, from the same largest-object geometry validation checks, so its
//! `Cmax` is validation's record units.

use std::alloc::Layout;

use super::geometry::{EXTENT_CHARGE_LIMIT, LOCAL_HEADER_LIMIT, OBJECT_LIMIT};
use super::layout::{AllocationLayout, IO_UNIT, LayoutError, ObjectGeometry};
use super::ledger::EngineBudget;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
use super::volume::VolumeGeometry;
use super::word::REFS_MAX;

/// First terminal era. A retirement whose era bump lands at or above it
/// poisons admission and every later pin is refused; the bump that returns
/// the value just below it closes admission too, so that every stamp in the
/// band belongs to an object admitted before the close. Defined here, where
/// validation bounds the slot count against it, and used by the grace
/// protocol.
pub(crate) const ERA_TERMINAL: u64 = 1 << 63;

/// Stamps available above the terminal band: retirements after admission
/// closed consume distinct already-admitted slots, so a slot count within
/// this reserve keeps every stamp below `u64::MAX`.
const ERA_STAMP_RESERVE: u64 = u64::MAX - ERA_TERMINAL;

/// Exclusive bound on the slot count, `2^31 - 1`; every slot index below it
/// also stays below the `u32::MAX` policy terminator.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const TABLE_INDEX_LIMIT: usize = (1 << 31) - 1;

// A volume's outstanding counted retirements are at most its slots, so one coverage epoch's 31-bit count holds them all.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const _: () = assert!(TABLE_INDEX_LIMIT as u64 <= super::coverage::COUNT_LIMIT);

/// The largest `alloc_search_words`: the maintenance minimum adds the root
/// gate attempt and service's fixed steps to twice the sum of this value
/// and a sequence visit's steps, one visit bound per service pass, so
/// `SERVICE_MINIMUM + 2 * (bound + SEQUENCE_VISIT) <= usize::MAX - 1`; the
/// reservation minimum and a return's preflight add fewer steps to it
/// once, so every minimum sum stays at most `usize::MAX`.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) const ALLOC_SEARCH_WORDS_LIMIT: usize =
    (usize::MAX - 1 - super::release::SERVICE_MINIMUM) / 2 - super::release::SEQUENCE_VISIT;

/// A local header is largest for a full extent under the shortest window a
/// validated record format admits, one unit, and that header fits
/// [`LOCAL_HEADER_LIMIT`] and is shorter than one unit: every admitted
/// object's every local header does both, so each ends inside its record's
/// first window, the precondition of `ValidRecordConfig::local_layout`.
const _: () = assert!(
    super::record::header_bytes(super::geometry::EXTENT_PAYLOAD, IO_UNIT as u64)
        <= LOCAL_HEADER_LIMIT
        && super::record::header_bytes(super::geometry::EXTENT_PAYLOAD, IO_UNIT as u64)
            < IO_UNIT as u64
);

/// Units a volume may hold: a locator start names at most `2^37` of them.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const VOLUME_UNIT_LIMIT: u64 = super::extent::LOCATOR_START_LIMIT;

/// Unvalidated storage configuration. Every field is a required caller input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageConfig {
    /// Runtime page size in bytes; a power of two.
    pub page_size: usize,
    /// Engine memory limit `E` in bytes.
    pub engine_budget: usize,
    /// Inclusive body length cap `Bmax`.
    pub body_cap: usize,
    /// Inclusive metadata length cap `Mmax`. Required; `None` is rejected.
    pub metadata_cap: Option<usize>,
    /// Engine-wide lease credit limit `L`: the credits leases, reserved fills
    /// and fill rows hold at once. A lease holds one. A fill holds two from
    /// its reservation, the publisher's and its terminal read right's, until
    /// it ends; its first lease takes the publisher's, and its row keeps the
    /// other while a follower is joined or returns it at the publication.
    pub lease_limit: usize,
    /// Per-object external read-right limit `C`, recorded in the root
    /// descriptor: while the object is anchored its leases and volume reads
    /// in flight hold at most `C` rights, and after the anchor's release at
    /// most `C + 1`. The count, anchor included, never passes `C + 1`.
    /// `object_rights` must be at least two, the publisher's right and the
    /// right a joined fill's row retains for its followers, which a
    /// publication installs together beside the anchor, and `C + 1` must be
    /// representable, since the anchor shares the object's counter.
    pub object_rights: usize,
    /// Reader registration limit `R`: the number of registration records laid
    /// out in the root control mapping, each on its own cache line. Zero is
    /// accepted and admits no reader.
    pub reader_limit: usize,
    /// The one volume: its capacity, slots, allocator work limit, placement, headroom
    /// watermarks, read share and record format. Attach checks the rest
    /// against the device, the arena and the table.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub volume: super::volume::VolumeConfig,
}

/// Why a [`StorageConfig`] is rejected, or why its structural floor is
/// undefined. Each variant is a distinct refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// `page_size` is zero, not a power of two, or too large for a layout.
    InvalidPageSize { page_size: usize },
    /// `metadata_cap` is `None`.
    MissingMetadataCap,
    /// `object_rights` is below two, which leaves a joined publication no
    /// room for the publisher's right beside its row's retained right, or
    /// `object_rights + 1` exceeds the slot word's 18-bit count,
    /// `2^18 - 1`, so the anchor would overflow it.
    InvalidObjectRights { object_rights: usize },
    /// `Mmax` or `Bmax` exceeds the header's 32-bit length field.
    MaxLayoutOverflow,
    /// `Mmax + Bmax`, the largest object's payload, exceeds the combined
    /// ceiling `limit`, 512 MiB.
    ObjectTooLarge { len: u64, limit: u64 },
    /// The window holding the largest local header and the first payload
    /// byte ends at byte `end` of its extent, past `limit`, the most bytes
    /// one extent charges, 256 KiB.
    FirstWindowMisfit { end: u64, limit: u64 },
    /// `volume.raw_bytes` is zero.
    ZeroRawBytes,
    /// `volume.slot_count` is zero.
    ZeroSlotCount,
    /// `volume.clock` fails [`ClockContract::validate`](super::ClockContract::validate).
    Clock(super::ContractError),
    /// `volume.feed` fails [`FeedContract::validate`](super::FeedContract::validate).
    Feed(super::FeedError),
    /// `volume.raw_bytes` is not a whole number of [`IO_UNIT`]s.
    RawBytesNotUnitMultiple { raw_bytes: usize },
    /// The volume holds more than `2^37` units.
    VolumeTooLarge { units: u64 },
    /// `volume.metadata_units` is zero.
    ZeroMetadataUnits,
    /// `volume.metadata_units` is at least the volume's units, leaving no payload unit.
    MetadataExceedsVolume {
        metadata_units: u64,
        volume_units: u64,
    },
    /// The largest object charges more units than the payload range holds.
    RecordExceedsPayload {
        record_units: u64,
        payload_units: u64,
    },
    /// `volume.alloc_search_words` is below `bound`, the most words and
    /// nodes one extent reservation or return of this volume can visit, or
    /// above `ALLOC_SEARCH_WORDS_LIMIT`, `(usize::MAX - 22) / 2 - 22`, the largest
    /// value that keeps the reservation, service and maintenance minima at
    /// most `usize::MAX`.
    AllocSearchWords {
        alloc_search_words: usize,
        bound: usize,
    },
    /// The slot count `O` exceeds the era stamps reserved above the terminal
    /// band, `u64::MAX - 2^63`.
    SlotCountExceedsEraReserve { slot_count: usize, limit: u64 },
    /// `volume.slot_count` reaches the slot count bound `2^31 - 1`.
    TableIndexLimit { slot_count: usize },
    /// `volume.reserve_units` is zero.
    ZeroReserve,
    /// The clean reserve plus the largest object's charged units exceeds
    /// the payload units, or the sum overflows.
    ReserveExceedsPayload {
        reserve_units: u64,
        record_units: u64,
        payload_units: u64,
    },
    /// `low_units` lies outside `reserve_units + Cmax ..= P - P mod c`, where
    /// `Cmax` is the largest object's charged units, `P` the payload units
    /// and `c` the units of the largest object's first extent. The upper
    /// bound is the empty volume's placeable units, the most headroom any
    /// volume holds.
    LowUnitsOutOfRange { low_units: u64 },
    /// `min_free_slots` lies outside `1..O`.
    MinFreeSlotsOutOfRange { min_free_slots: usize },
    /// `retired_units` lies below `Cmax`, the largest object's charged units.
    RetiredUnitsBelowLargest {
        retired_units: u64,
        record_units: u64,
    },
    /// `volume.nodes` names no node.
    EmptyNodes,
    /// `volume.read_ops` is zero.
    ZeroReadOps,
    /// `volume.block_roots` passes `limit`, the most roots whose granules a
    /// `u32` block index names.
    BlockRoots { block_roots: usize, limit: usize },
    /// `volume.record` failed its own checks.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    Record(super::record::RecordConfigError),
    /// The structural floor needs the retired allowance `T`, and the volume
    /// carries no watermarks.
    FloorWithoutWatermarks,
    /// `R + promises × Cmax + T` exceeds `u64::MAX`.
    FloorOverflow { promises: u32 },
    /// The structural floor exceeds `ceiling`, the largest `low_units`
    /// validation admits.
    FloorExceedsCeiling { floor: u64, ceiling: u64 },
}

/// A configuration that passed [`StorageConfig::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedConfig {
    page_size: usize,
    body_cap: usize,
    metadata_cap: usize,
    lease_limit: usize,
    object_rights: usize,
    reader_limit: usize,
    engine: EngineBudget,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    volume: super::volume::VolumeConfig,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    record: super::record::ValidRecordConfig,
    /// The geometry of the largest object the caps admit.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    largest: ObjectGeometry,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    record_units: u64,
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    geometry: VolumeGeometry,
}

impl StorageConfig {
    /// Checks every invariant listed in the module documentation and stops at
    /// the first failure.
    ///
    /// Validation allocates nothing. The returned value carries the engine
    /// budget `E` with nothing charged: the volume's bytes are on the device.
    ///
    /// # Errors
    ///
    /// In this order:
    ///
    /// - `InvalidPageSize` if `page_size` is not a power of two or exceeds
    ///   `isize::MAX`.
    /// - `MissingMetadataCap` if `metadata_cap` is `None`.
    /// - `InvalidObjectRights` if `object_rights` is below two or
    ///   `object_rights + 1` exceeds `2^18 - 1`.
    /// - `Record` with the first failing check of `volume.record`.
    /// - `MaxLayoutOverflow` if `Mmax` or `Bmax` exceeds `u32::MAX`.
    /// - `ObjectTooLarge` if `Mmax + Bmax` exceeds the 512 MiB ceiling.
    /// - `FirstWindowMisfit` if the window holding the largest object's first
    ///   local header and the first payload byte ends past the 256 KiB extent
    ///   charge limit.
    /// - `ZeroRawBytes`, then `ZeroSlotCount`, for a zero field.
    /// - `Clock` for a clock contract that fails its validation, then `Feed` for a feed contract that fails its own.
    /// - `RawBytesNotUnitMultiple` if `raw_bytes` is not a unit multiple.
    /// - `VolumeTooLarge` above `2^37` units.
    /// - `ZeroMetadataUnits` if `metadata_units` is zero, then
    ///   `MetadataExceedsVolume` if it is at least the volume's units.
    /// - `RecordExceedsPayload` if the largest object charges more units than
    ///   the payload range holds.
    /// - `AllocSearchWords` if `alloc_search_words` is below the allocator's
    ///   work bound for the payload units, the slot count and the largest
    ///   extent, or above `ALLOC_SEARCH_WORDS_LIMIT`.
    /// - `SlotCountExceedsEraReserve` if `slot_count` exceeds `u64::MAX -
    ///   2^63`.
    /// - `TableIndexLimit` if `slot_count` reaches `2^31 - 1`.
    /// - `ZeroReserve` if `reserve_units` is zero.
    /// - `ReserveExceedsPayload` if `reserve_units` plus the largest object's
    ///   charged units exceeds the payload units or overflows.
    /// - `LowUnitsOutOfRange` if `low_units` is below `reserve_units` plus
    ///   the largest object's charged units or above
    ///   [`placeable_ceiling`](ValidatedConfig::placeable_ceiling), then
    ///   `MinFreeSlotsOutOfRange`, then
    ///   `RetiredUnitsBelowLargest` if `retired_units` is below the largest
    ///   object's charged units, when `maintenance` is present.
    /// - `EmptyNodes` if `nodes` is empty.
    /// - `ZeroReadOps` if `read_ops` is zero.
    /// - `BlockRoots` if `block_roots` exceeds `u32::MAX / 1024`.
    pub fn validate(&self) -> Result<ValidatedConfig, ConfigError> {
        let page_size = self.page_size;
        if Layout::from_size_align(page_size, page_size).is_err() {
            return Err(ConfigError::InvalidPageSize { page_size });
        }
        let metadata_cap = self.metadata_cap.ok_or(ConfigError::MissingMetadataCap)?;
        if self.object_rights < 2 || self.object_rights >= REFS_MAX {
            return Err(ConfigError::InvalidObjectRights {
                object_rights: self.object_rights,
            });
        }
        let engine = EngineBudget::new(self.engine_budget);
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        let (record, largest, record_units, geometry) = {
            let record = self.volume.record.validate().map_err(ConfigError::Record)?;
            let largest = largest_geometry(metadata_cap, self.body_cap, &record)?;
            let (geometry, record_units) = validate_volume(&self.volume, &largest)?;
            (record, largest, record_units, geometry)
        };
        Ok(ValidatedConfig {
            page_size,
            body_cap: self.body_cap,
            metadata_cap,
            lease_limit: self.lease_limit,
            object_rights: self.object_rights,
            reader_limit: self.reader_limit,
            engine,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            volume: self.volume,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            record,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            largest,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            record_units,
            #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
            geometry,
        })
    }
}

/// The geometry of the largest object the caps admit, after the cap,
/// ceiling and first-window checks of [`StorageConfig::validate`], in its
/// documented order. Extent 0 carries the most payload, so its local header
/// is the largest any extent of any admitted object holds.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn largest_geometry(
    metadata_cap: usize,
    body_cap: usize,
    record: &super::record::ValidRecordConfig,
) -> Result<ObjectGeometry, ConfigError> {
    let (Ok(metadata), Ok(body)) = (u32::try_from(metadata_cap), u32::try_from(body_cap)) else {
        return Err(ConfigError::MaxLayoutOverflow);
    };
    let len = u64::from(metadata) + u64::from(body);
    let geometry = ObjectGeometry::new(len, record).ok_or(ConfigError::ObjectTooLarge {
        len,
        limit: OBJECT_LIMIT,
    })?;
    let header = geometry.header_bytes(0);
    debug_assert!(header <= LOCAL_HEADER_LIMIT);
    let end = super::record::first_window_end(header, u64::from(record.chunk_len()));
    if end > EXTENT_CHARGE_LIMIT {
        return Err(ConfigError::FirstWindowMisfit {
            end,
            limit: EXTENT_CHARGE_LIMIT,
        });
    }
    Ok(geometry)
}

/// The volume checks of [`StorageConfig::validate`], in its documented order,
/// for the largest object's `largest` geometry.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn validate_volume(
    volume: &super::volume::VolumeConfig,
    largest: &ObjectGeometry,
) -> Result<(VolumeGeometry, u64), ConfigError> {
    let raw_bytes = volume.raw_bytes;
    if raw_bytes == 0 {
        return Err(ConfigError::ZeroRawBytes);
    }
    if volume.slot_count == 0 {
        return Err(ConfigError::ZeroSlotCount);
    }
    volume.clock.validate().map_err(ConfigError::Clock)?;
    volume.feed.validate().map_err(ConfigError::Feed)?;
    if !raw_bytes.is_multiple_of(IO_UNIT) {
        return Err(ConfigError::RawBytesNotUnitMultiple { raw_bytes });
    }
    let volume_units = (raw_bytes / IO_UNIT) as u64;
    if volume_units > VOLUME_UNIT_LIMIT {
        return Err(ConfigError::VolumeTooLarge {
            units: volume_units,
        });
    }
    let metadata_units = volume.metadata_units;
    if metadata_units == 0 {
        return Err(ConfigError::ZeroMetadataUnits);
    }
    let Some(payload_units) = volume_units
        .checked_sub(metadata_units)
        .filter(|units| *units > 0)
    else {
        return Err(ConfigError::MetadataExceedsVolume {
            metadata_units,
            volume_units,
        });
    };
    let record_units = largest.total_units();
    if record_units > payload_units {
        return Err(ConfigError::RecordExceedsPayload {
            record_units,
            payload_units,
        });
    }
    let bound = super::extent::work_bound(payload_units, volume.slot_count, largest.units(0));
    if volume.alloc_search_words < bound || volume.alloc_search_words > ALLOC_SEARCH_WORDS_LIMIT {
        return Err(ConfigError::AllocSearchWords {
            alloc_search_words: volume.alloc_search_words,
            bound,
        });
    }
    let slot_count = volume.slot_count;
    if slot_count as u64 > ERA_STAMP_RESERVE {
        return Err(ConfigError::SlotCountExceedsEraReserve {
            slot_count,
            limit: ERA_STAMP_RESERVE,
        });
    }
    if slot_count >= TABLE_INDEX_LIMIT {
        return Err(ConfigError::TableIndexLimit { slot_count });
    }
    let reserve_units = volume.reserve_units;
    if reserve_units == 0 {
        return Err(ConfigError::ZeroReserve);
    }
    let floor = reserve_units
        .checked_add(record_units)
        .filter(|floor| *floor <= payload_units)
        .ok_or(ConfigError::ReserveExceedsPayload {
            reserve_units,
            record_units,
            payload_units,
        })?;
    if let Some(marks) = volume.maintenance {
        let ceiling = super::extent::empty_placeable(payload_units, largest.units(0));
        if marks.low_units < floor || marks.low_units > ceiling {
            return Err(ConfigError::LowUnitsOutOfRange {
                low_units: marks.low_units,
            });
        }
        if marks.min_free_slots == 0 || marks.min_free_slots >= volume.slot_count {
            return Err(ConfigError::MinFreeSlotsOutOfRange {
                min_free_slots: marks.min_free_slots,
            });
        }
        if marks.retired_units < record_units {
            return Err(ConfigError::RetiredUnitsBelowLargest {
                retired_units: marks.retired_units,
                record_units,
            });
        }
    }
    if volume.nodes.is_empty() {
        return Err(ConfigError::EmptyNodes);
    }
    if volume.read_ops == 0 {
        return Err(ConfigError::ZeroReadOps);
    }
    if volume.block_roots > super::blocks::ROOT_LIMIT {
        return Err(ConfigError::BlockRoots {
            block_roots: volume.block_roots,
            limit: super::blocks::ROOT_LIMIT,
        });
    }
    Ok((
        VolumeGeometry::new(metadata_units, payload_units),
        record_units,
    ))
}

/// True when `bytes` is a whole number of pages and fits `isize::MAX`, so a
/// mapping of that extent is representable. `page_size` is a power of two.
pub(super) fn is_page_multiple(bytes: usize, page_size: usize) -> bool {
    Layout::from_size_align(bytes, page_size).is_ok() && bytes.is_multiple_of(page_size)
}

impl ValidatedConfig {
    /// Engine budget `E`, nothing charged yet.
    pub fn engine_budget(&self) -> EngineBudget {
        self.engine
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    pub fn metadata_cap(&self) -> usize {
        self.metadata_cap
    }

    pub fn body_cap(&self) -> usize {
        self.body_cap
    }

    /// Engine-wide lease credit limit `L`.
    pub fn lease_limit(&self) -> usize {
        self.lease_limit
    }

    /// Per-object external read-right limit `C`: at least one, and `C + 1`
    /// fits the slot word's 18-bit count.
    pub fn object_rights(&self) -> usize {
        self.object_rights
    }

    /// Reader registration limit `R`.
    pub fn reader_limit(&self) -> usize {
        self.reader_limit
    }

    /// The validated volume fields.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn volume(&self) -> &super::volume::VolumeConfig {
        &self.volume
    }

    /// The geometry partitions the volume's `V` units into `M` metadata units and `P = V - M` payload units.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub fn geometry(&self) -> VolumeGeometry {
        self.geometry
    }

    /// The validated record format.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(crate) fn record(&self) -> super::record::ValidRecordConfig {
        self.record
    }

    /// The geometry of the largest object the caps admit, `Mmax + Bmax`
    /// payload bytes; validation checked its local header and charge. Its
    /// first extent carries the most payload of any extent of any admitted
    /// object, so its units and local header bound them all.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    pub(crate) fn largest_geometry(&self) -> ObjectGeometry {
        self.largest
    }

    /// An empty volume's placeable units, `P - P mod c`, with `P` the
    /// payload units and `c` the units of the largest object's first
    /// extent. Headroom counts each maximal free run's whole charges of `c`
    /// units, and the empty volume maximizes their total across allocation
    /// states.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[inline]
    pub fn placeable_ceiling(&self) -> u64 {
        super::extent::empty_placeable(self.geometry.payload_units(), self.largest.units(0))
    }

    /// The structural floor of `low_units` for an owner admitting `promises`
    /// PUTs: `R + promises × Cmax + T`, with `R` the clean reserve, `Cmax`
    /// the largest object's charged units, which validation checks as its
    /// record units, and `T` the retired allowance. While every eviction
    /// counted in `in_flight_units` also counts toward `retired_units`, a
    /// promise or claim that passes the retired-pressure check sees
    /// `in_flight_units <= retired_units <= T - 1`, so a volume read not
    /// short at a `low_units` of at least the floor leaves at least
    /// `promises × Cmax + 1` claimable units, and claims totalling
    /// `promises × Cmax` pass the clean reserve check with no maintenance
    /// call between them. An eviction whose retirement parks on a busy pool
    /// gate counts toward `in_flight_units` first and toward `retired_units`
    /// once service retires it, and in between the claimable units can fall
    /// short of that bound. A defined floor lies in
    /// `R + Cmax ..=` [`placeable_ceiling`](Self::placeable_ceiling). To
    /// size `low_units`, validate with `low_units` at the ceiling, take the
    /// floor, set `low_units` from it and validate again.
    ///
    /// A local fill reserves through the `reserve_storage` and `promise_storage` a PUT reserves through, so its claims pass the same retired-pressure and clean-reserve checks, and a deployment that streams local fills beside PUTs passes their sum as `promises`.
    ///
    /// # Errors
    ///
    /// - `FloorWithoutWatermarks` for a volume without watermarks.
    /// - `FloorOverflow` if the sum exceeds `u64::MAX`.
    /// - `FloorExceedsCeiling` if the floor exceeds the
    ///   [`placeable_ceiling`](Self::placeable_ceiling).
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[inline]
    pub fn structural_floor(&self, promises: u32) -> Result<u64, ConfigError> {
        FloorTerms {
            reserve_units: self.volume.reserve_units,
            record_units: self.record_units,
            ceiling: self.placeable_ceiling(),
            marks: self.volume.maintenance,
        }
        .floor(promises)
    }

    /// Lays out one allocation against the configured caps and record format.
    ///
    /// Validation bounds both caps by `u32::MAX`, so any request within both
    /// caps is representable and never yields `CapacityOverflow`.
    ///
    /// # Errors
    ///
    /// - `UnknownLength` if either length is `None`.
    /// - `MetadataTooLarge` if `metadata_len > Mmax`.
    /// - `BodyTooLarge` if `body_len > Bmax`; checked after the metadata cap.
    /// - `MultipleExtents` if the payload needs more than one extent.
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[inline(always)]
    pub fn layout(
        &self,
        metadata_len: Option<usize>,
        body_len: Option<usize>,
    ) -> Result<AllocationLayout, LayoutError> {
        AllocationLayout::new(
            metadata_len,
            body_len,
            self.metadata_cap,
            self.body_cap,
            &self.record,
        )
    }
}

/// The terms of the structural floor `R + promises × Cmax + T`: the clean
/// reserve `R`, the largest object's charged units `Cmax`, the
/// [`placeable_ceiling`](ValidatedConfig::placeable_ceiling) that bounds the
/// floor, and the watermarks, whose `retired_units` is `T`.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FloorTerms {
    pub(crate) reserve_units: u64,
    pub(crate) record_units: u64,
    pub(crate) ceiling: u64,
    pub(crate) marks: Option<super::volume::VolumeWatermarks>,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
impl FloorTerms {
    /// The floor for `promises` PUTs, as
    /// [`ValidatedConfig::structural_floor`] states it.
    ///
    /// # Errors
    ///
    /// As [`ValidatedConfig::structural_floor`].
    #[inline]
    pub(crate) fn floor(self, promises: u32) -> Result<u64, ConfigError> {
        let marks = self.marks.ok_or(ConfigError::FloorWithoutWatermarks)?;
        let floor = u64::from(promises)
            .checked_mul(self.record_units)
            .and_then(|units| units.checked_add(self.reserve_units))
            .and_then(|units| units.checked_add(marks.retired_units))
            .ok_or(ConfigError::FloorOverflow { promises })?;
        if floor > self.ceiling {
            return Err(ConfigError::FloorExceedsCeiling {
                floor,
                ceiling: self.ceiling,
            });
        }
        Ok(floor)
    }
}

// The tests configure the volume, which exists only on 64-bit Linux.
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod tests {
    use super::*;
    use crate::instrument;
    use crate::storage::placement::NodeMask;
    use crate::storage::volume::VolumeWatermarks;

    const PAGE: usize = 4096;
    const SLOTS: usize = 7;
    const UNITS: usize = 16;

    fn config() -> StorageConfig {
        StorageConfig {
            page_size: PAGE,
            engine_budget: 64 * PAGE,
            body_cap: 4000,
            metadata_cap: Some(64),
            lease_limit: 1024,
            object_rights: 64,
            reader_limit: 4,
            volume: crate::storage::test_volume(UNITS * IO_UNIT, SLOTS),
        }
    }

    fn with_volume(edit: impl FnOnce(&mut crate::storage::VolumeConfig)) -> StorageConfig {
        let mut config = config();
        edit(&mut config.volume);
        config
    }

    /// Refuses `bad` with `error` and leaves the input as it was.
    fn refuses(bad: StorageConfig, error: ConfigError) {
        let before = bad;
        assert_eq!(bad.validate(), Err(error));
        assert_eq!(bad, before);
    }

    #[test]
    fn a_valid_configuration_charges_nothing_and_keeps_the_volume() {
        let validated = config().validate().unwrap();
        assert_eq!(validated.engine_budget().used(), 0);
        assert_eq!(validated.engine_budget().limit(), 64 * PAGE);
        assert_eq!(*validated.volume(), config().volume);
        assert_eq!((validated.metadata_cap(), validated.body_cap()), (64, 4000));
    }

    #[test]
    fn each_invalid_configuration_has_its_own_refusal() {
        let base = config();
        for page_size in [0, 3000, 1 << 63] {
            refuses(
                StorageConfig { page_size, ..base },
                ConfigError::InvalidPageSize { page_size },
            );
        }
        refuses(
            StorageConfig {
                metadata_cap: None,
                ..base
            },
            ConfigError::MissingMetadataCap,
        );
        for object_rights in [0, 1, REFS_MAX, REFS_MAX + 1, usize::MAX] {
            refuses(
                StorageConfig {
                    object_rights,
                    ..base
                },
                ConfigError::InvalidObjectRights { object_rights },
            );
        }
        // Two rights are the fewest a joined publication installs beside the
        // anchor: the publisher's and its row's retained right.
        let narrowest = StorageConfig {
            object_rights: 2,
            ..base
        };
        assert_eq!(narrowest.validate().unwrap().object_rights(), 2);
        // The anchor plus every right fills the 18-bit count exactly.
        let widest = StorageConfig {
            object_rights: REFS_MAX - 1,
            ..base
        };
        assert_eq!(widest.validate().unwrap().object_rights(), (1 << 18) - 2);
        for (metadata_cap, body_cap) in [(64, u32::MAX as usize + 1), (u32::MAX as usize + 1, 0)] {
            refuses(
                StorageConfig {
                    metadata_cap: Some(metadata_cap),
                    body_cap,
                    ..base
                },
                ConfigError::MaxLayoutOverflow,
            );
        }
        refuses(
            with_volume(|volume| volume.raw_bytes = 0),
            ConfigError::ZeroRawBytes,
        );
        refuses(
            with_volume(|volume| volume.slot_count = 0),
            ConfigError::ZeroSlotCount,
        );
        refuses(
            with_volume(|volume| volume.raw_bytes = IO_UNIT + 1),
            ConfigError::RawBytesNotUnitMultiple {
                raw_bytes: IO_UNIT + 1,
            },
        );
        let units = (1 << 37) + 1;
        refuses(
            StorageConfig {
                engine_budget: usize::MAX,
                ..with_volume(|volume| volume.raw_bytes = units as usize * IO_UNIT)
            },
            ConfigError::VolumeTooLarge { units },
        );
        // A payload of exactly the volume's bytes exceeds it by its header.
        refuses(
            StorageConfig {
                body_cap: UNITS * IO_UNIT - 64,
                ..base
            },
            ConfigError::RecordExceedsPayload {
                record_units: UNITS as u64 + 1,
                payload_units: UNITS as u64,
            },
        );
        // The base record spans one unit, so the bound is the one the test
        // volume carries, and one word fewer refuses; so does one word past
        // the limit that keeps the preflight sums in range.
        let bound = base.volume.alloc_search_words;
        for alloc_search_words in [0, bound - 1, ALLOC_SEARCH_WORDS_LIMIT + 1] {
            refuses(
                with_volume(|volume| volume.alloc_search_words = alloc_search_words),
                ConfigError::AllocSearchWords {
                    alloc_search_words,
                    bound,
                },
            );
        }
        // The largest extent, not the largest object, sizes the bound: on
        // 4,096 units, a 1,100-unit object's extents charge at most 63 units
        // each and touch no more chunks than a one-unit record, so the
        // one-unit bound validates, while a 1,100-unit extent would need
        // more.
        let units = 4096u64;
        let small = super::super::extent::work_bound(units, SLOTS, 1);
        assert_eq!(super::super::extent::work_bound(units, SLOTS, 63), small);
        assert!(small < super::super::extent::work_bound(units, SLOTS, 1100));
        let wide = StorageConfig {
            engine_budget: usize::MAX,
            body_cap: 1099 * IO_UNIT,
            ..with_volume(|volume| {
                volume.raw_bytes = units as usize * IO_UNIT;
                volume.alloc_search_words = small;
            })
        };
        let validated = wide.validate().unwrap();
        assert_eq!(validated.largest_geometry().units(0), 63);
        refuses(
            StorageConfig {
                ..with_volume(|volume| {
                    volume.raw_bytes = units as usize * IO_UNIT;
                    volume.alloc_search_words = small - 1;
                })
            },
            ConfigError::AllocSearchWords {
                alloc_search_words: small - 1,
                bound: small,
            },
        );
        let marks = |low_units, min_free_slots| {
            with_volume(|volume| {
                volume.maintenance = Some(VolumeWatermarks {
                    low_units,
                    min_free_slots,
                    retired_units: u64::MAX,
                })
            })
        };
        // The base reserve uses one unit and the base record with 4,064 payload bytes uses two, so `H` lies in `3..=UNITS`.
        for low_units in [0, 2, UNITS as u64 + 1] {
            refuses(
                marks(low_units, 1),
                ConfigError::LowUnitsOutOfRange { low_units },
            );
        }
        for low_units in [3, UNITS as u64] {
            assert!(marks(low_units, 1).validate().is_ok());
        }
        for min_free_slots in [0, SLOTS] {
            refuses(
                marks(3, min_free_slots),
                ConfigError::MinFreeSlotsOutOfRange { min_free_slots },
            );
        }
        assert!(marks(UNITS as u64, SLOTS - 1).validate().is_ok());
        refuses(
            with_volume(|volume| volume.nodes = NodeMask::from_nodes(&[]).unwrap()),
            ConfigError::EmptyNodes,
        );
        refuses(
            with_volume(|volume| volume.read_ops = 0),
            ConfigError::ZeroReadOps,
        );
        refuses(
            with_volume(|volume| volume.record.chunk_len = 0),
            ConfigError::Record(
                crate::storage::record::RecordConfig { chunk_len: 0 }
                    .validate()
                    .unwrap_err(),
            ),
        );
    }

    /// The era check runs before the table index limit, so a slot count
    /// above the era reserve reports the era; one at it reaches the index
    /// limit `2^31 - 1`, the exclusive bound on the slot count.
    #[test]
    fn slot_counts_are_bounded_by_the_era_reserve_then_the_index_limit() {
        let slots = |slot_count: usize| {
            with_volume(|volume| {
                volume.slot_count = slot_count;
                volume.alloc_search_words = ALLOC_SEARCH_WORDS_LIMIT;
            })
        };
        let limit = ERA_STAMP_RESERVE;
        let above = limit as usize + 1;
        refuses(
            slots(above),
            ConfigError::SlotCountExceedsEraReserve {
                slot_count: above,
                limit,
            },
        );
        let at = limit as usize;
        let index = TABLE_INDEX_LIMIT;
        for slot_count in [at, index] {
            refuses(
                slots(slot_count),
                ConfigError::TableIndexLimit { slot_count },
            );
        }
        assert!(slots(index - 1).validate().is_ok());
    }

    /// The largest volume, `2^37` units, validates.
    #[test]
    fn a_volume_of_exactly_the_unit_limit_validates() {
        let config = StorageConfig {
            engine_budget: usize::MAX,
            ..with_volume(|volume| {
                volume.raw_bytes = (1 << 37) * IO_UNIT;
                volume.alloc_search_words = super::super::extent::work_bound(1 << 37, SLOTS, 1);
            })
        };
        assert!(config.validate().is_ok());
    }

    /// The arena root count validates up to the most roots a `u32` block
    /// index names, and one more refuses.
    #[test]
    fn block_roots_past_the_index_limit_refuse() {
        let limit = super::super::blocks::ROOT_LIMIT;
        assert_eq!(limit, (u32::MAX / 1024) as usize);
        assert!(
            with_volume(|volume| volume.block_roots = limit)
                .validate()
                .is_ok()
        );
        refuses(
            with_volume(|volume| volume.block_roots = limit + 1),
            ConfigError::BlockRoots {
                block_roots: limit + 1,
                limit,
            },
        );
    }

    /// Caps whose sum is exactly the 512 MiB ceiling validate, and their
    /// largest object is 2,115 extents charging 545,533,952 bytes; one byte
    /// more refuses typed, as do the widest caps the header's 32-bit lengths
    /// allow.
    #[test]
    fn caps_at_the_object_ceiling_validate_and_one_byte_more_refuses() {
        use super::super::geometry::OBJECT_LIMIT;
        let ceiling = OBJECT_LIMIT as usize;
        let at = |metadata: usize, body: usize| StorageConfig {
            engine_budget: usize::MAX,
            metadata_cap: Some(metadata),
            body_cap: body,
            ..with_volume(|volume| {
                volume.raw_bytes = (1 << 24) * IO_UNIT;
                volume.alloc_search_words = ALLOC_SEARCH_WORDS_LIMIT;
            })
        };
        let validated = at(4096, ceiling - 4096).validate().unwrap();
        let largest = validated.largest_geometry();
        assert_eq!(largest.extents(), 2115);
        assert_eq!(largest.total_units() * IO_UNIT as u64, 545_533_952);
        for (metadata, body) in [(4097, ceiling - 4096), (0, ceiling + 1)] {
            refuses(
                at(metadata, body),
                ConfigError::ObjectTooLarge {
                    len: ceiling as u64 + 1,
                    limit: OBJECT_LIMIT,
                },
            );
        }
        let max = u32::MAX as usize;
        refuses(
            at(max, max),
            ConfigError::ObjectTooLarge {
                len: 2 * max as u64,
                limit: OBJECT_LIMIT,
            },
        );
    }

    /// The window that holds the largest local header and the first
    /// payload byte must fit one extent's 256 KiB charge: a 256 KiB window
    /// validates, and a 260 KiB window refuses before anything is laid out.
    #[test]
    fn a_window_past_one_extents_charge_refuses_as_a_first_window_misfit() {
        let window = |chunk_len: u32| {
            with_volume(|volume| volume.record = super::super::record::RecordConfig { chunk_len })
        };
        assert!(window(256 * 1024).validate().is_ok());
        refuses(
            window(260 * 1024),
            ConfigError::FirstWindowMisfit {
                end: 260 * 1024,
                limit: super::super::geometry::EXTENT_CHARGE_LIMIT,
            },
        );
    }

    /// A zero feed authority or contract refuses by name before any mapping.
    #[test]
    fn invalid_feed_contracts_refuse() {
        use crate::storage::FeedError;
        refuses(
            with_volume(|volume| volume.feed.authority = [0; 16]),
            ConfigError::Feed(FeedError::ZeroAuthority),
        );
        refuses(
            with_volume(|volume| volume.feed.contract = 0),
            ConfigError::Feed(FeedError::ZeroContract),
        );
    }

    /// Each invalid clock bound refuses by name before any mapping, and a rate bound just below one part per one validates.
    #[test]
    fn invalid_clock_contracts_refuse() {
        use crate::storage::ContractError;
        refuses(
            with_volume(|volume| volume.clock.max_uncertainty_ns = 0),
            ConfigError::Clock(ContractError::ZeroUncertainty),
        );
        refuses(
            with_volume(|volume| volume.clock.rate_error_ppb = 1_000_000_000),
            ConfigError::Clock(ContractError::RateErrorTooLarge {
                rate_error_ppb: 1_000_000_000,
            }),
        );
        refuses(
            with_volume(|volume| volume.clock.provenance = 0),
            ConfigError::Clock(ContractError::ZeroProvenance),
        );
        assert!(
            with_volume(|volume| volume.clock.rate_error_ppb = 999_999_999)
                .validate()
                .is_ok()
        );
    }

    /// `metadata_units < volume_units` keeps `volume_units - metadata_units` exact in `u64` arithmetic.
    #[test]
    fn the_metadata_prefix_refuses_by_its_own_variants_and_leaves_the_payload_units() {
        let prefixed = |volume_units: u64, metadata_units: u64| {
            with_volume(|volume| {
                volume.raw_bytes = volume_units as usize * IO_UNIT;
                volume.metadata_units = metadata_units;
            })
        };
        refuses(prefixed(17, 0), ConfigError::ZeroMetadataUnits);
        for metadata_units in [17, 18, u64::MAX] {
            refuses(
                prefixed(17, metadata_units),
                ConfigError::MetadataExceedsVolume {
                    metadata_units,
                    volume_units: 17,
                },
            );
        }
        let units = (1 << 37) + 1;
        refuses(
            StorageConfig {
                engine_budget: usize::MAX,
                ..prefixed(units, 0)
            },
            ConfigError::VolumeTooLarge { units },
        );
        refuses(
            StorageConfig {
                body_cap: 64 * IO_UNIT,
                ..prefixed(17, 17)
            },
            ConfigError::MetadataExceedsVolume {
                metadata_units: 17,
                volume_units: 17,
            },
        );
        for metadata_units in [1, 5, 16] {
            let geometry = prefixed(17, metadata_units)
                .validate()
                .map(|validated| validated.geometry());
            if metadata_units == 16 {
                assert_eq!(
                    geometry.map(|_| ()),
                    Err(ConfigError::RecordExceedsPayload {
                        record_units: 2,
                        payload_units: 1,
                    })
                );
                continue;
            }
            let geometry = geometry.unwrap();
            assert_eq!(geometry.metadata_units(), metadata_units);
            assert_eq!(geometry.payload_units(), 17 - metadata_units);
            assert_eq!(geometry.volume_units(), 17);
        }
    }

    #[test]
    fn an_exact_prefix_reserve_and_record_fit_validates_and_one_unit_short_refuses() {
        let body_cap = 15 * IO_UNIT - 144;
        let fit = |volume_units: u64, low_units: Option<u64>| StorageConfig {
            metadata_cap: Some(0),
            body_cap,
            ..with_volume(|volume| {
                volume.raw_bytes = volume_units as usize * IO_UNIT;
                volume.metadata_units = 5;
                volume.maintenance = low_units.map(|low_units| VolumeWatermarks {
                    low_units,
                    min_free_slots: 1,
                    retired_units: u64::MAX,
                });
            })
        };
        let exact = fit(21, None).validate().unwrap();
        assert_eq!(exact.largest_geometry().total_units(), 15);
        assert_eq!(exact.geometry().payload_units(), 16);
        refuses(
            fit(20, None),
            ConfigError::ReserveExceedsPayload {
                reserve_units: 1,
                record_units: 15,
                payload_units: 15,
            },
        );
        assert_eq!(exact.placeable_ceiling(), 15);
        for low_units in [16, 17, 21] {
            refuses(
                fit(21, Some(low_units)),
                ConfigError::LowUnitsOutOfRange { low_units },
            );
        }
        refuses(
            StorageConfig {
                body_cap: 16 * IO_UNIT,
                ..fit(21, None)
            },
            ConfigError::RecordExceedsPayload {
                record_units: 17,
                payload_units: 16,
            },
        );
    }

    /// A record whose header and payload fill the volume beside the
    /// one-unit reserve validates; one more payload byte is refused.
    #[test]
    fn the_largest_record_beside_the_reserve_at_the_volume_s_size_validates() {
        let body_cap = (UNITS - 1) * IO_UNIT - 144;
        let exact = StorageConfig {
            metadata_cap: Some(0),
            body_cap,
            ..config()
        };
        let layout = exact
            .validate()
            .unwrap()
            .layout(Some(0), Some(body_cap))
            .unwrap();
        assert_eq!(
            (layout.record().header_bytes(), layout.units()),
            (144, UNITS - 1)
        );
        refuses(
            StorageConfig {
                body_cap: body_cap + 1,
                ..exact
            },
            ConfigError::ReserveExceedsPayload {
                reserve_units: 1,
                record_units: UNITS as u64,
                payload_units: UNITS as u64,
            },
        );
    }

    /// Two full extents charge 63 units each under 8 KiB windows, so `Cmax`
    /// is 126 units: 127 units validate beside the one-unit reserve and 126
    /// refuse.
    #[test]
    fn the_reserve_check_charges_every_extent_of_the_largest_object() {
        let two_extents = |units: usize| StorageConfig {
            metadata_cap: Some(0),
            body_cap: 2 * super::super::geometry::EXTENT_PAYLOAD as usize,
            volume: crate::storage::test_volume(units * IO_UNIT, SLOTS),
            ..config()
        };
        assert!(two_extents(127).validate().is_ok());
        refuses(
            two_extents(126),
            ConfigError::ReserveExceedsPayload {
                reserve_units: 1,
                record_units: 126,
                payload_units: 126,
            },
        );
    }

    /// The reserve check rejects sums that overflow or exceed `payload_units`.
    #[test]
    fn the_clean_reserve_is_positive_and_leaves_room_for_the_largest_record() {
        // A 4,097-byte payload spans two units.
        let two_units =
            |payload_units: usize, reserve_units: u64, low_units: Option<u64>| StorageConfig {
                body_cap: IO_UNIT + 1,
                metadata_cap: Some(0),
                ..with_volume(|volume| {
                    volume.raw_bytes =
                        (payload_units + crate::storage::TEST_METADATA_UNITS as usize) * IO_UNIT;
                    volume.reserve_units = reserve_units;
                    volume.maintenance = low_units.map(|low_units| VolumeWatermarks {
                        low_units,
                        min_free_slots: 1,
                        retired_units: u64::MAX,
                    });
                })
            };
        let witness = two_units(3, 1, None).validate().unwrap();
        assert_eq!(
            witness.layout(Some(0), Some(IO_UNIT + 1)).unwrap().units(),
            2
        );
        assert_eq!(witness.volume().reserve_units, 1);
        // Three payload units hold one two-unit charge, so the placeable
        // ceiling of 2 lies below the 3-unit floor.
        refuses(
            two_units(3, 1, Some(3)),
            ConfigError::LowUnitsOutOfRange { low_units: 3 },
        );
        refuses(two_units(3, 0, Some(3)), ConfigError::ZeroReserve);
        refuses(two_units(3, 0, None), ConfigError::ZeroReserve);
        let exceeds =
            |payload_units: usize, reserve_units: u64| ConfigError::ReserveExceedsPayload {
                reserve_units,
                record_units: 2,
                payload_units: payload_units as u64,
            };
        refuses(two_units(2, 1, None), exceeds(2, 1));
        refuses(two_units(3, 2, None), exceeds(3, 2));
        refuses(two_units(3, u64::MAX, None), exceeds(3, u64::MAX));
        refuses(two_units(3, u64::MAX - 1, None), exceeds(3, u64::MAX - 1));
        // `H` below `R + Cmax` or above `V`.
        refuses(
            two_units(4, 1, Some(2)),
            ConfigError::LowUnitsOutOfRange { low_units: 2 },
        );
        refuses(
            two_units(4, 1, Some(5)),
            ConfigError::LowUnitsOutOfRange { low_units: 5 },
        );
        assert!(two_units(4, 1, Some(3)).validate().is_ok());
        assert!(two_units(4, 1, Some(4)).validate().is_ok());
    }

    /// The floor arithmetic of the tests below takes `R = 1`, the clean
    /// reserve [`with_volume`] leaves in place.
    fn large(chunk_len: u32, low_units: u64, retired_units: u64) -> StorageConfig {
        StorageConfig {
            engine_budget: usize::MAX,
            body_cap: 8_323_072,
            metadata_cap: Some(64),
            ..with_volume(|volume| {
                volume.raw_bytes = (LARGE_UNITS + volume.metadata_units) as usize * IO_UNIT;
                volume.alloc_search_words = ALLOC_SEARCH_WORDS_LIMIT;
                volume.record = super::super::record::RecordConfig { chunk_len };
                volume.maintenance = Some(VolumeWatermarks {
                    low_units,
                    min_free_slots: 1,
                    retired_units,
                });
            })
        }
    }

    const LARGE_UNITS: u64 = 4_000_000;
    const LARGE_RETIRED: u64 = 2_048_000;
    const LARGE_CEILING: u64 = LARGE_UNITS - LARGE_UNITS % 63;

    /// At 8,323,072 body bytes and 64 metadata bytes validation's record units are 2,065 under every chunk length it admits, and the floor's `Cmax` is that count.
    /// 256 promises give `1 + 256 * 2,065 + 2,048,000 = 2,576,641`, and zero promises give `R + T = 2,048,001`.
    #[test]
    fn the_floor_at_large_caps_is_the_reserve_the_promises_largest_charges_and_the_allowance() {
        let mut admitted = 0;
        for chunk_len in (1..=64).map(|k| k * IO_UNIT as u32) {
            let Ok(validated) = large(chunk_len, LARGE_RETIRED, LARGE_RETIRED).validate() else {
                continue;
            };
            admitted += 1;
            // Validation's record units are 2,065: one unit less of retired
            // allowance refuses naming them.
            refuses(
                large(chunk_len, LARGE_RETIRED, 2064),
                ConfigError::RetiredUnitsBelowLargest {
                    retired_units: 2064,
                    record_units: 2065,
                },
            );
            assert_eq!(validated.structural_floor(256), Ok(2_576_641));
            assert_eq!(validated.structural_floor(0), Ok(2_048_001));
        }
        assert_eq!(admitted, 64, "every unit multiple to 256 KiB validates");
    }

    /// Headroom counts whole `c`-unit charges within each maximal free run,
    /// where `c` counts the units of the largest object's first extent, so
    /// an empty volume of `P` payload units attains the most headroom any
    /// volume holds, `P - P mod c`, and validation bounds `low_units` by
    /// that count.
    #[test]
    fn a_watermark_above_the_empty_volume_s_placeable_units_refuses() {
        let mut unwatched = large(8192, LARGE_RETIRED, LARGE_RETIRED);
        unwatched.volume.maintenance = None;
        let validated = unwatched.validate().unwrap();
        assert_eq!(validated.largest_geometry().units(0), 63);
        assert_eq!(validated.placeable_ceiling(), LARGE_CEILING);
        assert_eq!(LARGE_CEILING, 3_999_996);
        assert!(large(8192, LARGE_CEILING, LARGE_RETIRED).validate().is_ok());
        for low_units in [LARGE_CEILING + 1, LARGE_UNITS] {
            refuses(
                large(8192, low_units, LARGE_RETIRED),
                ConfigError::LowUnitsOutOfRange { low_units },
            );
        }
    }

    /// Every floor returned by `structural_floor` is valid as `low_units`.
    #[test]
    fn the_floor_refuses_overflow_missing_watermarks_and_the_ceiling() {
        let validated = large(8192, LARGE_CEILING, LARGE_RETIRED)
            .validate()
            .unwrap();
        let cmax = 2065;
        let fits = (LARGE_CEILING - 1 - LARGE_RETIRED) / cmax;
        for promises in [0, 1, 256, fits as u32] {
            let floor = validated.structural_floor(promises).unwrap();
            assert!(large(8192, floor, LARGE_RETIRED).validate().is_ok());
        }
        let above = fits as u32 + 1;
        assert_eq!(
            validated.structural_floor(above),
            Err(ConfigError::FloorExceedsCeiling {
                floor: 1 + u64::from(above) * cmax + LARGE_RETIRED,
                ceiling: LARGE_CEILING,
            })
        );
        let at_ceiling = LARGE_CEILING - 1 - 256 * cmax;
        let floor_of = |retired_units, promises| {
            large(8192, LARGE_CEILING, retired_units)
                .validate()
                .unwrap()
                .structural_floor(promises)
        };
        assert_eq!(floor_of(at_ceiling, 256), Ok(LARGE_CEILING));
        assert_eq!(
            floor_of(at_ceiling + 1, 256),
            Err(ConfigError::FloorExceedsCeiling {
                floor: LARGE_CEILING + 1,
                ceiling: LARGE_CEILING,
            })
        );
        let sum = 1 + u64::from(u32::MAX) * cmax;
        assert_eq!(
            floor_of(u64::MAX - sum, u32::MAX),
            Err(ConfigError::FloorExceedsCeiling {
                floor: u64::MAX,
                ceiling: LARGE_CEILING,
            })
        );
        assert_eq!(
            floor_of(u64::MAX - sum + 1, u32::MAX),
            Err(ConfigError::FloorOverflow { promises: u32::MAX })
        );
        let mut unwatched = large(8192, LARGE_CEILING, LARGE_RETIRED);
        unwatched.volume.maintenance = None;
        assert_eq!(
            unwatched.validate().unwrap().structural_floor(0),
            Err(ConfigError::FloorWithoutWatermarks)
        );
    }

    #[test]
    fn layout_uses_configured_caps() {
        let validated = config().validate().unwrap();
        let layout = validated.layout(Some(64), Some(4000)).unwrap();
        assert_eq!(
            (layout.metadata_len(), layout.body_len(), layout.units()),
            (64, 4000, 2)
        );
        assert_eq!(
            validated.layout(Some(65), Some(0)),
            Err(LayoutError::MetadataTooLarge { len: 65, cap: 64 })
        );
        assert_eq!(
            validated.layout(Some(0), Some(4001)),
            Err(LayoutError::BodyTooLarge {
                len: 4001,
                cap: 4000
            })
        );
        assert_eq!(
            validated.layout(None, Some(0)),
            Err(LayoutError::UnknownLength)
        );
    }

    #[test]
    fn validation_and_layout_do_not_allocate() {
        let config = config();
        let before = instrument::allocations();
        let validated = config.validate().unwrap();
        let _ = validated.layout(Some(1), Some(1));
        let _ = with_volume(|volume| volume.raw_bytes = 1).validate();
        assert_eq!(instrument::allocations(), before);
    }
}
