//! What each control mapping contains and where.
//!
//! An image is laid out before its mapping is acquired, so the extent to map
//! and charge is known first, and it is written during control initialization
//! after population. Values are copied out of the configuration so the owner
//! never depends on the caller's tables after initialization. Descriptors are
//! plain `Copy` data; the volume's allocation tables follow them and are
//! owned by the `tables` module.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::config::ValidatedConfig;
use super::control::{ControlLayout, ControlLayoutOverflow, Field};
use super::fill::{FIRST_SERIAL, FillSerial};
use super::gate::Gate;
use super::grace::PassCursor;
use super::placement::NodeMask;
use super::row::FillRow;
use super::tables::{RetainCounters, TableImage};
use crate::index::Key;

/// Engine-shared values recorded in the root control mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootDescriptor {
    pub page_size: usize,
    pub metadata_cap: usize,
    pub body_cap: usize,
    pub engine_limit: usize,
    /// Engine-wide lease credit limit `L`.
    pub lease_limit: usize,
    /// Per-object external read-right limit `C`. Leases and volume reads in
    /// flight share the limit that
    /// [`StorageConfig::object_rights`](super::StorageConfig::object_rights)
    /// specifies.
    pub object_rights: usize,
    /// Reader registration limit `R`: the number of registration records.
    pub reader_limit: usize,
    /// Resolution of the platform's monotonic clock in nanoseconds, as
    /// reported at initialization. A lookup compares whole seconds of a
    /// sample against a deadline kept in whole seconds, rounded down; this
    /// records how coarse a tick can be, for the integrator converting
    /// freshness into deadlines, who reads it from the root descriptor.
    pub clock_resolution_ticks: u64,
    /// Node the root control mapping is bound to.
    pub control_home: NodeMask,
}

/// Engine-wide lease bookkeeping, written without any gate.
///
/// Aligned to its own cache line: a handoff, a resident acquisition, a
/// registration's borrow and their returns each modify `reserved`, and the
/// admission flag laid out before it in the root mapping
/// is read by every reservation, so sharing a line would turn those reads
/// into misses. The alignment is 128 bytes so that an adjacent-line prefetch
/// of the flag's line cannot pull the counters in.
#[derive(Debug)]
#[repr(align(128))]
pub(crate) struct LeaseControls {
    /// Credits taken from `L` right now: every credit backing a lease or a
    /// reserved fill that was reserved here directly, from its
    /// compare-exchange through its return, including one a handoff refused
    /// at the anchor holds briefly, plus every credit lent to a registration
    /// record. Never exceeds `L`.
    pub reserved: AtomicUsize,
    /// Credit reservation attempts whose compare-exchange saw another
    /// writer's value.
    pub cas_failed: AtomicUsize,
    /// Credit reservation attempts whose weak compare-exchange failed with the
    /// expected value still in place.
    pub cas_spurious: AtomicUsize,
}

/// One word of the parked-credit map: bit `i` of word `w` is set while
/// registration record `64 * w + i` may hold idle credits. The `lease`
/// module states the protocol. Each word has a 128-byte block of its own,
/// away from the lease counters and the neighbouring words, with room for
/// an adjacent-line prefetch.
#[derive(Debug)]
#[repr(C, align(128))]
pub(crate) struct ParkedWord {
    pub bits: AtomicU64,
    /// The in-progress sweep count for `bits` in the low 32 bits and the
    /// started sweep count in the high 32; the `lease` module's
    /// `take_parked` states how a refusal reads them.
    pub sweeps: AtomicU64,
}

pub(crate) const PARKED_PER_WORD: usize = u64::BITS as usize;

/// Where a registration record's leases return their credits: a line of
/// its own, apart from the record's, so a lease dropped on another thread
/// writes a line the record's owner reads once per batch, when its own idle
/// credits run out, and the owner's pin stores and takes stay on a line
/// only the owner writes. Read as a signed count like
/// [`RegistrationRecord::idle`].
#[derive(Debug)]
#[repr(C, align(64))]
pub(crate) struct ReturnLine {
    pub returned: AtomicUsize,
}

/// The engine-wide era counter, the grace certificate and the claimed
/// bound, padded to a 64-byte block of their own so on 64-byte-line targets
/// pin loads and retirement bumps never contend with the lease counters or a
/// registration record. All three words advance only; the bound is written
/// only by a registration that raises it, and a pin never writes the line.
#[derive(Debug)]
#[repr(C, align(64))]
pub(crate) struct EraControls {
    /// Monotonic era, bumped once per retirement; readers pin its value.
    pub era: AtomicU64,
    /// Highest era below which every retirement has completed its grace:
    /// no registered reader can still observe an identity retired below it.
    pub certified: AtomicU64,
    /// One past the highest registration record ever claimed: records at
    /// or above it have never held a pin, so a certification pass visits
    /// only the records below it.
    pub claimed_bound: AtomicUsize,
}

/// The engine-wide certification pass in progress, kept in the root control
/// mapping and read and written only under the root mapping's maintenance
/// gate. Atomics because the root mapping holds no locked table; the gate
/// supplies the exclusion and the ordering.
#[derive(Debug)]
#[repr(C, align(64))]
pub(crate) struct GraceCursor {
    start_era: AtomicU64,
    min_key: AtomicU64,
    next: AtomicUsize,
}

impl GraceCursor {
    pub(crate) fn idle() -> Self {
        Self {
            start_era: AtomicU64::new(PassCursor::IDLE.start_era),
            min_key: AtomicU64::new(PassCursor::IDLE.min_key),
            next: AtomicUsize::new(PassCursor::IDLE.next),
        }
    }

    /// The cursor as the last gate holder left it. Relaxed: the gate's
    /// acquire take already orders the previous holder's stores.
    #[inline]
    pub(crate) fn load(&self) -> PassCursor {
        PassCursor {
            start_era: self.start_era.load(Ordering::Relaxed),
            min_key: self.min_key.load(Ordering::Relaxed),
            next: self.next.load(Ordering::Relaxed),
        }
    }

    /// Records the cursor for the next holder; the gate's release free
    /// publishes it.
    #[inline]
    pub(crate) fn store(&self, cursor: PassCursor) {
        self.start_era.store(cursor.start_era, Ordering::Relaxed);
        self.min_key.store(cursor.min_key, Ordering::Relaxed);
        self.next.store(cursor.next, Ordering::Relaxed);
    }
}

/// One reader registration: its occupancy, its active pin, its idle lease
/// credits and its fixed statistics, padded to a 64-byte block of its own so
/// on 64-byte-line targets one reader's pin stores and contention counts never
/// invalidate another reader's line.
#[derive(Debug)]
#[repr(C, align(64))]
pub(crate) struct RegistrationRecord {
    /// Era pinned by the current protected interval; zero when none.
    pub pin: AtomicU64,
    /// Protected intervals entered through this record.
    pub intervals: AtomicU64,
    /// Lease credits lent to this record from the engine-wide count, not
    /// backing a lease right now and not waiting on the record's return
    /// line, read as a signed count: a take subtracts before it knows whether
    /// a credit was there and gives the credit back when none was, so the
    /// word is below zero between those two steps. The record's lookups take
    /// from here before moving the return line's credits here and before
    /// touching the shared counter; another record's lookup may take one
    /// when the shared counter is at `L`.
    pub idle: AtomicUsize,
    /// The record this record's last take at the limit took from, which
    /// the next such take visits first. Written only by this record's
    /// lookups; the initial zero names record zero.
    pub lender: AtomicUsize,
    /// The failed right reservations of this record's lookups.
    pub retains: RetainCounters,
    /// Whether a `Registration` handle owns this record.
    pub claimed: AtomicBool,
}

/// The placement the layout promises: every record and the era words are
/// 64-byte blocks, so the checked layout pads each to its own block.
const _: () = {
    assert!(std::mem::size_of::<EraControls>() == 64);
    assert!(std::mem::align_of::<EraControls>() == 64);
    assert!(std::mem::size_of::<GraceCursor>() == 64);
    assert!(std::mem::align_of::<GraceCursor>() == 64);
    assert!(std::mem::size_of::<RegistrationRecord>() == 64);
    assert!(std::mem::align_of::<RegistrationRecord>() == 64);
    assert!(std::mem::size_of::<ParkedWord>() == 128);
    assert!(std::mem::align_of::<ParkedWord>() == 128);
    assert!(std::mem::size_of::<ReturnLine>() == 64);
    assert!(std::mem::align_of::<ReturnLine>() == 64);
    assert!(std::mem::size_of::<FillControl>() == 64);
    assert!(std::mem::align_of::<FillControl>() == 64);
    assert!(std::mem::size_of::<FillCustody>() == 64);
    assert!(std::mem::align_of::<FillCustody>() == 64);
};

/// The next serial to issue, or one past the last encodable serial after exhaustion.
/// Only the shard gate holder advances this counter, after it installs a record.
#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct NextFillSerial(AtomicU64);

impl NextFillSerial {
    pub(super) const fn new() -> Self {
        Self(AtomicU64::new(FIRST_SERIAL))
    }

    pub(super) fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub(super) fn advance(&self, issued: FillSerial) {
        self.0.store(issued.get() + 1, Ordering::Relaxed);
    }

    /// Stores `raw` as the counter, including the values no grant leaves in it.
    #[cfg(test)]
    pub(super) fn set_for_test(&self, raw: u64) {
        self.0.store(raw, Ordering::Relaxed);
    }
}

/// The shard gate serializes every write to one shard's fill-table header.
#[derive(Debug)]
#[repr(C, align(64))]
pub(crate) struct FillControl {
    /// The serial the next attempt on this shard takes; it never wraps or resets.
    pub next_serial: NextFillSerial,
    /// The record the next service pass examines first.
    pub cursor: AtomicUsize,
}

/// One shard's fixed custody record: the fill record, attempt serial, candidate, incumbent and phase of the publication in custody, or none.
/// Initialization writes none; service skips a record custody names and finalization blocks on it.
#[derive(Debug)]
#[repr(C, align(64))]
pub(crate) struct FillCustody {
    /// Position of the record under custody; [`NO_RECORD`] when none.
    pub record: AtomicUsize,
    /// Serial of the attempt under custody; zero when none.
    pub serial: AtomicU64,
    /// Slot index of the candidate object the publication under custody holds resident; [`NO_RECORD`] when none.
    pub candidate: AtomicUsize,
    /// Slot index of the incumbent whose pair the publication takes over; [`NO_RECORD`] when none or once custody settles, after which the retirement obligation owns it.
    pub incumbent: AtomicUsize,
    /// How far the publication under custody had come, as the `publication` module encodes it; zero when none.
    pub phase: AtomicU64,
}

pub(crate) const NO_RECORD: usize = usize::MAX;

/// The state words are atomics an owner departs through without the gate; the keys and their fingerprints are written and read only under the shard gate.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FillImage {
    pub control: Field<FillControl>,
    pub custody: Field<FillCustody>,
    pub states: Field<AtomicU64>,
    pub keys: Field<Key>,
    /// Each record's key fingerprint, written with the key by the grant, so
    /// a removal that knows only a resident's fingerprint finds its
    /// replacement attempt.
    pub fingerprints: Field<u64>,
    /// Each record's place word: the index place and additional-key claim
    /// its fill took at reservation, as the `place_claim` module encodes
    /// them, or zero; written and read only under the shard gate.
    pub places: Field<u64>,
    /// Each record's row: its producer's terminal, its followers and the
    /// reserved object a follower reads, as the `row` module states.
    pub rows: Field<FillRow>,
}

#[derive(Debug)]
pub(crate) struct RootImage {
    pub descriptor: Field<RootDescriptor>,
    /// Admission cutoff: `Storage::close` and the `Cache` facade's drop each
    /// store `true`, which stays for the owner's life.
    pub closed: Field<AtomicBool>,
    /// A successful compare-exchange permanently marks the owner as issued,
    /// allowing at most one `Cache` facade.
    pub issued: Field<AtomicBool>,
    /// The first swap to `true` permanently marks the owner as attached to a device volume, allowing at most one `Volume` over its life.
    pub attached: Field<AtomicBool>,
    pub leases: Field<LeaseControls>,
    pub parked: Field<ParkedWord>,
    /// `R` return lines, one per registration record.
    pub returns: Field<ReturnLine>,
    pub eras: Field<EraControls>,
    /// Gate for the certification pass. A poisoned pool gate stops the
    /// volume's service only; certification and anchor release continue.
    pub maintenance: Field<Gate>,
    pub grace: Field<GraceCursor>,
    /// `R` registration records.
    pub registrations: Field<RegistrationRecord>,
    /// Each entry is one index shard's fill table, `None` when its record count is zero.
    pub fills: Box<[Option<FillImage>]>,
    /// Whether any entry of `fills` is a table, decided once so the passes over `fills` need no scan to skip an index without one.
    pub any_fills: bool,
    pub extent: usize,
}

impl RootImage {
    /// Lays out fixed controls, `reader_limit` registration records, and fill tables for shards with nonzero record counts.
    ///
    /// # Errors
    ///
    /// `ControlLayoutOverflow` if the page-rounded extent is unrepresentable.
    pub(crate) fn layout(
        page_size: usize,
        reader_limit: usize,
        fills: &[usize],
    ) -> Result<Self, ControlLayoutOverflow> {
        let mut layout = ControlLayout::new();
        let descriptor = layout.field::<RootDescriptor>(1)?;
        let closed = layout.field::<AtomicBool>(1)?;
        let issued = layout.field::<AtomicBool>(1)?;
        let attached = layout.field::<AtomicBool>(1)?;
        let leases = layout.field::<LeaseControls>(1)?;
        let parked = layout.field::<ParkedWord>(reader_limit.div_ceil(PARKED_PER_WORD))?;
        let returns = layout.field::<ReturnLine>(reader_limit)?;
        let eras = layout.field::<EraControls>(1)?;
        let maintenance = layout.field::<Gate>(1)?;
        let grace = layout.field::<GraceCursor>(1)?;
        let registrations = layout.field::<RegistrationRecord>(reader_limit)?;
        let mut tables = Vec::with_capacity(fills.len());
        for &records in fills {
            if records == 0 {
                tables.push(None);
                continue;
            }
            tables.push(Some(FillImage {
                control: layout.field::<FillControl>(1)?,
                custody: layout.field::<FillCustody>(1)?,
                states: layout.field::<AtomicU64>(records)?,
                keys: layout.field::<Key>(records)?,
                fingerprints: layout.field::<u64>(records)?,
                places: layout.field::<u64>(records)?,
                rows: layout.field::<FillRow>(records)?,
            }));
        }
        Ok(Self {
            descriptor,
            closed,
            issued,
            attached,
            leases,
            parked,
            returns,
            eras,
            maintenance,
            grace,
            registrations,
            any_fills: tables.iter().any(Option::is_some),
            fills: tables.into_boxed_slice(),
            extent: layout.extent(page_size)?,
        })
    }

    /// Counts only the per-shard `FillImage` placement descriptors, not the fill tables themselves.
    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(&*self.fills)
    }

    pub(crate) fn descriptor_for(
        config: &ValidatedConfig,
        clock_resolution_ticks: u64,
        control_home: NodeMask,
    ) -> RootDescriptor {
        RootDescriptor {
            page_size: config.page_size(),
            metadata_cap: config.metadata_cap(),
            body_cap: config.body_cap(),
            engine_limit: config.engine_budget().limit(),
            lease_limit: config.lease_limit(),
            object_rights: config.object_rights(),
            reader_limit: config.reader_limit(),
            clock_resolution_ticks,
            control_home,
        }
    }
}

/// The volume's fixed geometry, recorded in its control mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolDescriptor {
    /// Raw capacity in bytes: the volume's `V` units, metadata prefix and payload together, times
    /// [`IO_UNIT`](super::IO_UNIT).
    pub raw_bytes: usize,
    /// The validated split of `V` into metadata and payload units, from [`ValidatedConfig::geometry`].
    pub geometry: super::volume::VolumeGeometry,
    pub slot_count: usize,
    /// Nodes the volume control mapping is bound to.
    pub nodes: NodeMask,
}

impl PoolDescriptor {
    /// The returned range includes the metadata prefix in its device offset. `device_range` returns `None` if `payload_device_start` returns `None` or `DeviceRange::new` returns an error.
    #[inline]
    pub(crate) fn device_range(
        &self,
        start_unit: u64,
        offset_bytes: u64,
        len: u32,
    ) -> Option<super::device::DeviceRange> {
        let start = super::geometry::payload_device_start(
            self.geometry.metadata_units(),
            self.geometry.volume_units(),
            start_unit,
            offset_bytes,
            len,
        )?;
        super::device::DeviceRange::new(start, len).ok()
    }
}

#[derive(Debug)]
pub(crate) struct PoolImage {
    pub descriptor: Field<PoolDescriptor>,
    pub tables: TableImage,
    pub extent: usize,
    /// The volume's `alloc_search_words`, held outside the mapping so a
    /// drained owner still answers its budget minima.
    pub alloc_search_words: usize,
    /// The extent work bound of the largest extent, at most
    /// `alloc_search_words`.
    pub extent_bound: usize,
    /// The geometry of the largest object the caps admit. Its first extent
    /// is the largest extent of any admitted object, so its units and local
    /// header bound every reservation, read and write.
    pub largest: super::layout::ObjectGeometry,
    /// The units the largest object charges, `Cmax`, which bound every
    /// object's charge.
    pub largest_units: u64,
    /// The record format, which turns a slot's tail and units back into its
    /// payload length.
    pub record: super::record::RecordPricer,
    /// The clean reserve `R` in units, which every claim leaves free.
    pub reserve_units: u64,
    /// The retired allowance `T`, or `u64::MAX` for a storage without
    /// watermarks, which no retired charge reaches.
    pub retired_limit: u64,
}

impl PoolImage {
    /// # Errors
    ///
    /// `ControlLayoutOverflow` if the page-rounded extent is unrepresentable.
    pub(crate) fn layout(
        config: &ValidatedConfig,
        page_size: usize,
    ) -> Result<Self, ControlLayoutOverflow> {
        let mut layout = ControlLayout::new();
        let descriptor = layout.field::<PoolDescriptor>(1)?;
        let tables = TableImage::layout(&mut layout, config)?;
        let volume = config.volume();
        let largest = config.largest_geometry();
        let extent_bound = super::extent::work_bound(
            config.geometry().payload_units(),
            volume.slot_count,
            largest.units(0),
        );
        Ok(Self {
            descriptor,
            tables,
            extent: layout.extent(page_size)?,
            alloc_search_words: volume.alloc_search_words,
            extent_bound,
            largest,
            largest_units: largest.total_units(),
            record: config.record().pricer(),
            reserve_units: volume.reserve_units,
            retired_limit: volume
                .maintenance
                .map_or(u64::MAX, |marks| marks.retired_units),
        })
    }

    pub(crate) fn descriptor_for(config: &ValidatedConfig) -> PoolDescriptor {
        let volume = config.volume();
        debug_assert_eq!(
            config.geometry().volume_units() as usize * super::layout::IO_UNIT,
            volume.raw_bytes
        );
        PoolDescriptor {
            raw_bytes: volume.raw_bytes,
            geometry: config.geometry(),
            slot_count: volume.slot_count,
            nodes: volume.nodes,
        }
    }
}
