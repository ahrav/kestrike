//! Fallible storage initialization with exact rollback.
//!
//! The transaction first checks the runtime page size against the
//! configuration, reads the clock resolution, validates the placement
//! against the kernel's topology and lays out every control mapping. It
//! then charges the envelope: `E_used` (the root and volume control extents,
//! the volume handle, and with an index its mapping, geometry tables, hash
//! state, bucket runs and shard placement records) and `E_init_peak`
//! (`E_used` plus the residency scratch) must both fit `E` before the first
//! `map_inaccessible`. Then, per mapping in acquisition order (root, then the
//! volume's control, then the index if configured), it maps an
//! inaccessible range, advises it `MADV_HUGEPAGE`, binds the mapping to its
//! node mask, enables access, and then, chunk by chunk, populates the pages,
//! verifies their residency page by page and verifies their node against the
//! mask. After the last chunk it advises the mapping `MADV_NOHUGEPAGE`, which
//! keeps the huge pages population installed and disables later huge-page
//! collapse, so no normal-page range of the mapping becomes huge after
//! initialization; like a swap or a migration, a split under memory pressure
//! still changes the backing the kernel chose. Huge pages cut the
//! address-translation cost of the hit path's random accesses into the index
//! and slot tables. A populating fault takes a PMD-sized huge page when that
//! size's transparent huge page control is `always` or `madvise` (directly or
//! through `inherit`), the process permits transparent huge pages, the
//! aligned huge-page range around the fault lies inside the mapping, and the
//! kernel can allocate a huge page on a node of the mask; every other fault
//! takes base pages, or a smaller transparent huge page size the system
//! enables. On a kernel built without transparent huge pages both advice
//! steps succeed and normal pages back every mapping. Each population call
//! holds the kernel's address-space lock for its whole duration, including
//! any compaction a fault runs to allocate a huge page. Other threads of the
//! process wait for that lock to map, unmap or change protection. The chunk
//! bounds the range one population call faults and keeps that range's page
//! tables and page metadata cache-resident for its two verification walks;
//! the first touch of every page is still population, after binding.
//! Control values
//! are written in place only after every mapping is populated and placed,
//! and ownership transfers to the storage owner only after every control
//! value is written. No storage owner exists before that point.
//!
//! A population call's duration depends on the transparent huge page
//! `defrag` control. When it is `always`, `madvise` (the kernel
//! default) or `defer+madvise`, a huge-page fault in a mapping advised
//! `MADV_HUGEPAGE` runs direct reclaim and compaction on the bound nodes
//! before it falls back to base pages. On a node whose free memory is
//! fragmented, a population call then stalls for that reclaim, and other
//! threads of the process wait on the address-space lock for as long.
//! Under `defer` or `never`, a fault that finds no free huge page takes base
//! pages at once. Initialization therefore belongs before a process serves
//! requests.
//!
//! Every failure after the first acquisition releases each acquired mapping at
//! its original base and full extent, most recent first, exactly once. A
//! partly populated mapping is released at its full extent. Control values
//! need no destruction because no placed type has drop glue. A release the
//! kernel refuses leaves that mapping retained and charged; the failure then
//! reports [`Cleanup::Incomplete`] with every retained record, never complete
//! rollback and never a storage owner. That is how total-or-fail is kept
//! honest when the kernel will not cooperate: the caller still gets no owner,
//! and the retained records are the only handle on the leaked charge. Nothing
//! here spawns a thread, allocates during rollback, or formats text: every
//! error is fixed phase and `errno` data.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

use super::config::ValidatedConfig;
use super::fill::FREE;
use super::gate::Gate;
use super::grace::{ERA_FIRST, INACTIVE};
use super::image::{
    EraControls, FillControl, FillCustody, GraceCursor, LeaseControls, NO_RECORD, NextFillSerial,
    ParkedWord, PoolImage, RegistrationRecord, ReturnLine, RootImage,
};
use super::ledger::EngineBudgetExceeded;
use super::mapping::{Mapping, Region, RetainedMapping};
use super::os::{OsCode, Platform};
use super::owner::{IndexOwner, Pool, Storage, mappings};
use super::placement::{
    NodeMask, PlacementConfig, PlacementError, ValidatedPlacement, verify_chunk,
};
use super::row::FillRow;
use super::shards::IndexImage;
use super::tables::RetainCounters;
use crate::index::{Identity, KeyHasher, ValidatedIndex};

/// Pages per population, residency and placement step; the residency scratch
/// holds one status byte per page and is charged in `E_init_peak`.
pub(crate) const RESIDENCY_CHUNK_PAGES: usize = 1024;

/// The step of initialization that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitPhase {
    Map,
    PagePolicy,
    Placement,
    Protect,
    Populate,
    VerifyPopulation,
    VerifyPlacement,
    ControlInit,
    Transfer,
}

/// Why initialization did not produce a storage owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// The kernel would not report its page size.
    PageSizeUnavailable(OsCode),
    /// The configured page size is not the runtime page size.
    PageSizeMismatch { configured: usize, actual: usize },
    /// A control mapping's layout is unrepresentable.
    ControlLayoutOverflow { region: Region },
    /// `E_used` or `E_init_peak` would exceed `E`. Checked before any mapping.
    Envelope(EngineBudgetExceeded),
    /// The monotonic clock's resolution could not be read, so no lookup
    /// could ever take its witness. Checked before any mapping.
    ClockUnavailable(OsCode),
    /// The topology could not be read. `ENOENT` is a kernel without
    /// `CONFIG_NUMA`; `EPERM` is a seccomp profile denying `get_mempolicy`
    /// to a process without `CAP_SYS_NICE`. Checked before any mapping.
    TopologyUnavailable(OsCode),
    /// The placement names a node the topology rejects. Checked before any
    /// mapping.
    Placement(PlacementError),
    /// A kernel call or injected cut failed.
    Os {
        phase: InitPhase,
        region: Region,
        code: OsCode,
    },
    /// Population reported success but a page was not resident.
    Unpopulated { region: Region, page: usize },
    /// The node query for a page of a refused chunk failed.
    PageStatusError {
        region: Region,
        page: usize,
        code: OsCode,
    },
    /// A page is resident on a node outside the mask bound to its mapping.
    WrongNode {
        region: Region,
        page: usize,
        node: usize,
    },
    /// A hugepage mapping's base is not aligned to its page size; the arena checks this after mapping and before binding.
    MisalignedBase {
        region: Region,
        base: usize,
        align: usize,
    },
}

/// Mappings the kernel refused to release during rollback. They stay owned
/// and charged; nothing retries them.
#[derive(Debug)]
pub struct RetainedMappings {
    root: Mapping,
    pool: Pool,
    index: Option<Mapping>,
}

// SAFETY: the mappings inside are never dereferenced again; the only
// operations are integer reads of base, extent and error code for reporting.
unsafe impl Send for RetainedMappings {}
// SAFETY: as above; every method takes `&self` and reads integers.
unsafe impl Sync for RetainedMappings {}

impl RetainedMappings {
    pub fn iter(&self) -> impl Iterator<Item = RetainedMapping> + '_ {
        mappings(&self.root, &self.pool, self.index.as_ref()).filter_map(Mapping::retained)
    }
}

/// Outcome of rollback after a failed initialization.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "the retained mappings travel by value; boxing them would allocate during rollback"
)]
pub enum Cleanup {
    /// Every acquired mapping was released exactly once.
    Complete,
    /// At least one release failed; those mappings remain owned and charged.
    Incomplete(RetainedMappings),
}

/// A failed initialization: what failed and whether rollback completed.
#[derive(Debug)]
pub struct InitFailure {
    pub error: InitError,
    pub cleanup: Cleanup,
}

/// A failure before any mapping was acquired has nothing to roll back.
impl From<InitError> for InitFailure {
    fn from(error: InitError) -> Self {
        Self {
            error,
            cleanup: Cleanup::Complete,
        }
    }
}

pub(super) fn os(phase: InitPhase, region: Region) -> impl Fn(OsCode) -> InitError {
    move |code| InitError::Os {
        phase,
        region,
        code,
    }
}

struct Transaction<P> {
    platform: P,
    page_size: usize,
    clock_resolution: u64,
    placement: ValidatedPlacement,
    scratch: [u8; RESIDENCY_CHUNK_PAGES],
    root: Mapping,
    root_image: RootImage,
    pool: Pool,
    index: Option<IndexOwner>,
}

impl<P: Platform> Transaction<P> {
    fn slot(&mut self, region: Region) -> &mut Mapping {
        match region {
            Region::Root => &mut self.root,
            Region::Control => &mut self.pool.control,
            Region::Index => {
                &mut self
                    .index
                    .as_mut()
                    .expect("the index region is acquired only when an index is configured")
                    .mapping
            }
            Region::Buffers => unreachable!(
                "storage initialization never acquires the buffer arena, which owns its own mapping"
            ),
        }
    }

    /// Acquires one region, populated and verified chunk by chunk. The page
    /// advice and the binding take effect only at a fault, so both precede
    /// the first touch; the normal-page advice follows the last chunk. The
    /// mapping is recorded before any later step so a failure rolls it back
    /// at its full extent.
    fn acquire(&mut self, region: Region, len: usize) -> Result<(), InitError> {
        if len == 0 {
            *self.slot(region) = Mapping::empty(region);
            return Ok(());
        }
        let base = self
            .platform
            .map_inaccessible(len)
            .map_err(os(InitPhase::Map, region))?;
        *self.slot(region) = Mapping::owned(region, base, len);
        // SAFETY: `base` and `len` are exactly what the platform returned and
        // the mapping is recorded as owned, so it is live for every call.
        unsafe { self.platform.advise_huge_pages(base, len) }
            .map_err(os(InitPhase::PagePolicy, region))?;
        let nodes = *self.placement.nodes(region);
        // SAFETY: as above; binding precedes the first touch, which is the
        // population below.
        unsafe { self.platform.bind(base, len, &nodes) }
            .map_err(os(InitPhase::Placement, region))?;
        // SAFETY: as above.
        unsafe { self.platform.protect_read_write(base, len) }
            .map_err(os(InitPhase::Protect, region))?;
        self.populate_and_verify(region, base, len, &nodes)?;
        // Population is complete, so the normal-page advice keeps every
        // installed page, huge pages included, and disables later huge-page
        // collapse: no normal-page range becomes huge after initialization.
        // SAFETY: as above.
        unsafe { self.platform.advise_normal_pages(base, len) }
            .map_err(os(InitPhase::PagePolicy, region))?;
        let pages = len / self.page_size;
        self.slot(region).set_pages_verified(pages);
        Ok(())
    }

    /// Populates the mapping one bounded chunk at a time, requiring every
    /// page of each chunk resident and on a node of `nodes` before the next
    /// chunk is populated. A failure leaves a populated prefix; the caller
    /// releases the full extent.
    fn populate_and_verify(
        &mut self,
        region: Region,
        base: NonNull<u8>,
        len: usize,
        nodes: &NodeMask,
    ) -> Result<(), InitError> {
        let chunk = RESIDENCY_CHUNK_PAGES * self.page_size;
        let mut offset = 0;
        while offset < len {
            let sub = (len - offset).min(chunk);
            let pages = sub / self.page_size;
            let first_page = offset / self.page_size;
            // SAFETY: `offset < len`, so the start lies inside the live
            // mapping, and `offset` is a page multiple, so it is page aligned.
            let start = unsafe { base.add(offset) };
            // SAFETY: `start..start + sub` lies inside the live mapping, which
            // is readable and writable.
            unsafe { self.platform.populate_write(start, sub) }
                .map_err(os(InitPhase::Populate, region))?;
            let status = &mut self.scratch[..pages];
            // SAFETY: as above, and the status slice holds one byte per page
            // of `sub`.
            unsafe { self.platform.residency(start, sub, status) }
                .map_err(os(InitPhase::VerifyPopulation, region))?;
            if let Some(index) = status.iter().position(|byte| byte & 1 == 0) {
                return Err(InitError::Unpopulated {
                    region,
                    page: first_page + index,
                });
            }
            // SAFETY: `start..start + sub` lies inside the live, readable
            // mapping and is populated; `sub` is a page multiple.
            unsafe {
                verify_chunk(
                    &self.platform,
                    region,
                    start,
                    sub,
                    self.page_size,
                    first_page,
                    nodes,
                )
            }?;
            offset += sub;
        }
        Ok(())
    }

    fn write_controls(&mut self, config: &ValidatedConfig) -> Result<(), InitError> {
        self.platform
            .cut(InitPhase::ControlInit, Region::Root)
            .map_err(os(InitPhase::ControlInit, Region::Root))?;
        let root = RootImage::descriptor_for(
            config,
            self.clock_resolution,
            *self.placement.nodes(Region::Root),
        );
        // SAFETY: the root mapping is owned, readable and writable, laid out
        // for `root_image`, and nothing references it yet. It keeps its zero
        // fill from `map_inaccessible` up to this block: each platform call
        // in `acquire` preserves the mapping's bytes, and the steps between
        // store only into other mappings.
        unsafe {
            self.root_image.descriptor.init(&self.root, |_| root);
            self.root_image
                .closed
                .init(&self.root, |_| AtomicBool::new(false));
            self.root_image
                .issued
                .init(&self.root, |_| AtomicBool::new(false));
            self.root_image
                .attached
                .init(&self.root, |_| AtomicBool::new(false));
            self.root_image.leases.init(&self.root, |_| LeaseControls {
                reserved: AtomicUsize::new(0),
                cas_failed: AtomicUsize::new(0),
                cas_spurious: AtomicUsize::new(0),
            });
            self.root_image.parked.init(&self.root, |_| ParkedWord {
                bits: AtomicU64::new(0),
                sweeps: AtomicU64::new(0),
            });
            self.root_image.returns.init(&self.root, |_| ReturnLine {
                returned: AtomicUsize::new(0),
            });
            // Nothing is certified until a pass completes: `certified` starts
            // below the first era any retirement can be stamped with.
            self.root_image.eras.init(&self.root, |_| EraControls {
                era: AtomicU64::new(ERA_FIRST),
                certified: AtomicU64::new(0),
                claimed_bound: AtomicUsize::new(0),
            });
            self.root_image
                .maintenance
                .init(&self.root, |_| Gate::open());
            self.root_image
                .grace
                .init(&self.root, |_| GraceCursor::idle());
            self.root_image
                .registrations
                .init(&self.root, |_| RegistrationRecord {
                    pin: AtomicU64::new(INACTIVE),
                    intervals: AtomicU64::new(0),
                    idle: AtomicUsize::new(0),
                    lender: AtomicUsize::new(0),
                    retains: RetainCounters::new(),
                    claimed: AtomicBool::new(false),
                });
            for table in self.root_image.fills.iter().flatten() {
                table.control.init(&self.root, |_| FillControl {
                    next_serial: NextFillSerial::new(),
                    cursor: AtomicUsize::new(0),
                });
                table.custody.init(&self.root, |_| FillCustody {
                    record: AtomicUsize::new(NO_RECORD),
                    serial: AtomicU64::new(0),
                    candidate: AtomicUsize::new(NO_RECORD),
                    incumbent: AtomicUsize::new(NO_RECORD),
                    phase: AtomicU64::new(0),
                });
                table.states.init(&self.root, |_| AtomicU64::new(FREE));
                table.keys.init(&self.root, |_| [0; 32]);
                table.fingerprints.init(&self.root, |_| 0);
                table.places.init(&self.root, |_| 0);
                table.rows.init(&self.root, |_| FillRow::new());
            }
        }
        let region = Region::Control;
        self.platform
            .cut(InitPhase::ControlInit, region)
            .map_err(os(InitPhase::ControlInit, region))?;
        let pool = &self.pool;
        let descriptor = PoolImage::descriptor_for(config);
        // SAFETY: as for the root mapping, for the volume's control mapping
        // and its image.
        unsafe {
            pool.image.descriptor.init(&pool.control, |_| descriptor);
            pool.image.tables.init(&pool.control, config);
        }
        if let Some(index) = &self.index {
            self.platform
                .cut(InitPhase::ControlInit, Region::Index)
                .map_err(os(InitPhase::ControlInit, Region::Index))?;
            // A blank scratch entry is the zero word; a reader uses only the
            // entries its own scan wrote.
            let blank = Identity::unpack(0);
            // SAFETY: as for the root mapping, for the index mapping and its
            // image.
            unsafe { index.image.init(&index.mapping, blank) };
        }
        Ok(())
    }

    /// Acquires every mapping, writes every control value and runs the
    /// transfer cut. Any error leaves acquired mappings recorded for rollback.
    fn run(&mut self, config: &ValidatedConfig) -> Result<(), InitError> {
        self.acquire(Region::Root, self.root_image.extent)?;
        self.acquire(Region::Control, self.pool.image.extent)?;
        if let Some(extent) = self.index.as_ref().map(|index| index.image.extent) {
            self.acquire(Region::Index, extent)?;
        }
        self.write_controls(config)?;
        self.platform
            .cut(InitPhase::Transfer, Region::Root)
            .map_err(os(InitPhase::Transfer, Region::Root))
    }

    /// Releases every extent the transaction acquired, most recently
    /// acquired first, and counts the releases the kernel refused. This is
    /// the one release outside finalization: no owner exists yet, so no
    /// reference into any mapping can.
    fn rollback(mut self, error: InitError) -> InitFailure {
        let platform = &self.platform;
        let mut failed = 0;
        // SAFETY: no reference into any mapping exists; the transaction never
        // handed one out.
        unsafe {
            if let Some(index) = self.index.as_mut() {
                failed += usize::from(index.mapping.release(platform).is_err());
            }
            failed += usize::from(self.pool.control.release(platform).is_err());
            failed += usize::from(self.root.release(platform).is_err());
        }
        let cleanup = if failed > 0 {
            Cleanup::Incomplete(RetainedMappings {
                root: self.root,
                pool: self.pool,
                index: self.index.map(|index| index.mapping),
            })
        } else {
            Cleanup::Complete
        };
        InitFailure { error, cleanup }
    }
}

/// The engine bytes `E` initialization charges, by part, in charge order:
/// the root image with its fill tables and rows, the pool's control image
/// and owner record, the index inventory, and the startup scratch the peak
/// adds. Initialization refuses `Envelope` unless `E` covers their sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageCharges {
    pub(crate) root: usize,
    pub(crate) control: usize,
    pub(crate) index: usize,
    pub(crate) startup: usize,
}

impl StorageCharges {
    /// The engine budget `E` initialization needs: every charge, the
    /// startup peak's included, or `None` past `usize`.
    pub fn total(&self) -> Option<usize> {
        self.root
            .checked_add(self.control)?
            .checked_add(self.index)?
            .checked_add(self.startup)
    }

    /// The charges of a storage of `config` with `index`, which
    /// initialization takes in this order.
    ///
    /// # Errors
    ///
    /// `ControlLayoutOverflow` for an unrepresentable root or control image.
    pub fn of(config: &ValidatedConfig, index: Option<&ValidatedIndex>) -> Result<Self, InitError> {
        layouts(config, index).map(|layouts| layouts.charges)
    }
}

struct Layouts {
    root_image: RootImage,
    image: PoolImage,
    fill_records: usize,
    charges: StorageCharges,
}

fn layouts(config: &ValidatedConfig, index: Option<&ValidatedIndex>) -> Result<Layouts, InitError> {
    let page_size = config.page_size();
    let overflow = |region| InitError::ControlLayoutOverflow { region };
    let fills = index.map_or(&[][..], ValidatedIndex::fills);
    let fill_records = fills
        .iter()
        .try_fold(0usize, |sum, &records| sum.checked_add(records))
        .ok_or_else(|| overflow(Region::Root))?;
    let root_image = RootImage::layout(page_size, config.reader_limit(), fills)
        .map_err(|_| overflow(Region::Root))?;
    let image = PoolImage::layout(config, page_size).map_err(|_| overflow(Region::Control))?;
    let control = image
        .extent
        .checked_add(std::mem::size_of::<Pool>())
        .ok_or_else(|| overflow(Region::Control))?;
    let charges = StorageCharges {
        root: root_image.extent,
        control,
        index: index.map_or(0, |geometry| geometry.inventory().total),
        startup: RESIDENCY_CHUNK_PAGES,
    };
    Ok(Layouts {
        root_image,
        image,
        fill_records,
        charges,
    })
}

/// Runs the transaction described in the module documentation.
///
/// # Errors
///
/// [`InitFailure`] carrying the failing step and the rollback outcome. No
/// storage owner exists on error.
#[expect(
    clippy::result_large_err,
    reason = "a failure carries the retained mappings by value; boxing them would allocate during rollback"
)]
pub(crate) fn initialize<P: Platform>(
    config: &ValidatedConfig,
    index: Option<ValidatedIndex>,
    placement: &PlacementConfig,
    platform: P,
) -> Result<Storage<P>, InitFailure> {
    let page_size = platform
        .page_size()
        .map_err(InitError::PageSizeUnavailable)?;
    if page_size != config.page_size() {
        return Err(InitError::PageSizeMismatch {
            configured: config.page_size(),
            actual: page_size,
        }
        .into());
    }
    let clock_resolution = platform
        .clock_resolution()
        .map_err(InitError::ClockUnavailable)?;
    let topology = platform
        .topology()
        .map_err(InitError::TopologyUnavailable)?;
    let placement = placement
        .validate(&config.volume().nodes, &topology)
        .map_err(InitError::Placement)?;
    let Layouts {
        root_image,
        image,
        fill_records,
        charges,
    } = layouts(config, index.as_ref())?;
    let overflow = InitError::ControlLayoutOverflow {
        region: Region::Index,
    };
    let index_image = match &index {
        Some(geometry) => {
            let image = IndexImage::layout(geometry, config.reader_limit(), page_size)
                .map_err(|_| overflow)?;
            let inventory = geometry.inventory();
            debug_assert_eq!(image.extent, inventory.mapping_bytes);
            debug_assert_eq!(
                image.retained_bytes() + root_image.retained_bytes(),
                inventory.run_bytes + inventory.image_bytes
            );
            Some(image)
        }
        None => None,
    };
    let mut engine = config.engine_budget();
    for bytes in [charges.root, charges.control, charges.index] {
        engine.charge(bytes).map_err(InitError::Envelope)?;
    }
    let pool = Pool {
        capture: std::sync::Mutex::new(super::recovery::Capture::default()),
        eligible: std::sync::atomic::AtomicUsize::new(0),
        member_rows: std::sync::atomic::AtomicU64::new(0),
        insert_step: std::sync::atomic::AtomicU64::new(0),
        suffix_tail: std::sync::atomic::AtomicU64::new(0),
        suffix_due: std::sync::atomic::AtomicU64::new(u64::MAX),
        capture_epoch: std::sync::atomic::AtomicU64::new(0),
        control: Mapping::empty(Region::Control),
        image,
        deadline_bound: std::sync::atomic::AtomicU32::new(u32::MAX),
        warm_hold: std::sync::atomic::AtomicBool::new(false),
    };
    let index = index.zip(index_image).map(|(geometry, image)| IndexOwner {
        mapping: Mapping::empty(Region::Index),
        image,
        geometry,
        hasher: KeyHasher::seeded(),
    });
    let mut peak = engine;
    peak.charge(charges.startup).map_err(InitError::Envelope)?;

    let mut tx = Transaction {
        platform,
        page_size,
        clock_resolution,
        placement,
        scratch: [0u8; RESIDENCY_CHUNK_PAGES],
        root: Mapping::empty(Region::Root),
        root_image,
        pool,
        index,
    };
    if let Err(error) = tx.run(config) {
        return Err(tx.rollback(error));
    }
    Ok(Storage {
        platform: tx.platform,
        page_size,
        root: tx.root,
        root_image: tx.root_image,
        pool: tx.pool,
        index: tx.index,
        engine,
        read_ops: config.volume().read_ops,
        read_commands: config.volume().read_commands,
        read_ahead: config.volume().read_ahead,
        metadata_commands: config.volume().metadata_commands,
        metadata_retries: config.volume().metadata_retries,
        recovery: config.volume().recovery,
        clock: config.volume().clock,
        feed: config.volume().feed,
        readiness: super::readiness::Word::default(),
        record: config.record(),
        fill_records,
        init_peak: peak.used(),
        phase: super::finalize::Phase::Live,
        close: super::closing::CloseCursor::start(),
        maintain: super::maintain::MaintainCursor::start(),
        finalize: super::finalize::FinalizeCursor::start(),
    })
}

#[cfg(test)]
mod tests {
    use std::ptr::NonNull;

    use super::super::EngineBudgetExceeded;
    use super::super::blocks::{ArenaLists, BIT_WORDS, ROOT_WORDS};
    use super::super::config::{StorageConfig, ValidatedConfig};
    use super::super::extent::{ExtentRoot, RawPartition, RunNode, index_table_nodes, space_words};
    use super::super::finalize::{Finalization, FinalizeError};
    use super::super::gate::Gate;
    use super::super::image::{PoolDescriptor, PoolImage};
    use super::super::layout::IO_UNIT;
    use super::super::mapping::Region;
    use super::super::os::{LinuxPlatform, OsCode, Platform};
    use super::super::owner::{Pool, Storage};
    use super::super::placement::{MAX_NODES, NodeMask, PlacementConfig, PlacementError};
    use super::super::policy::Domain;
    use super::super::recovery::JournalWords;
    use super::super::slot::Record;
    use super::super::tables::{PoolState, Telemetry};
    use super::super::test_platform::finalize;
    use super::super::test_platform::{Fail, Log, Op, TestPlatform};
    use super::super::volume::{VolumeConfig, VolumeWatermarks};
    use super::{Cleanup, InitError, InitPhase, RESIDENCY_CHUNK_PAGES};

    fn placement() -> PlacementConfig {
        PlacementConfig { control_home: 0 }
    }

    /// The first node this task may allocate from, for native tests that must
    /// hold under any cpuset.
    fn native_node() -> usize {
        LinuxPlatform
            .topology()
            .unwrap()
            .allowed
            .nodes()
            .next()
            .unwrap()
    }

    /// Scratch charged in `E_init_peak`: one residency byte per page of a
    /// 1024-page chunk. Placement verification holds no scratch.
    const SCRATCH: usize = 1024;

    /// Reads the policy the kernel holds for the mapping containing `base`
    /// through `get_mempolicy(MPOL_F_ADDR)`, independently of the platform.
    fn policy_at(base: *const u8) -> (i32, NodeMask) {
        const MPOL_F_ADDR: libc::c_long = 1 << 1;
        let mut mode: libc::c_int = -1;
        let mut mask = NodeMask::default();
        // SAFETY: `base` lies inside a live mapping; the mask buffer holds
        // `MAX_NODES` bits, one fewer than the `maxnode` passed.
        let result = unsafe {
            libc::syscall(
                libc::SYS_get_mempolicy,
                &mut mode,
                mask.words_mut().as_mut_ptr(),
                MAX_NODES as libc::c_long + 1,
                base,
                MPOL_F_ADDR,
            )
        };
        assert_eq!(result, 0, "{:?}", std::io::Error::last_os_error());
        (mode, mask)
    }

    /// Page size for heap-backed tests; native tests use the runtime value.
    const HEAP_PAGE: usize = 4096;

    /// One volume of eight pages, 640 slots and a run index of 80 entries in
    /// 116 nodes, so its control mapping spans several pages.
    struct Fixture {
        page: usize,
        /// Roots of the sequence arena.
        roots: usize,
    }

    const SLOTS: usize = 640;

    impl Fixture {
        fn new(page: usize) -> Self {
            Self { page, roots: 0 }
        }

        fn payload_bytes(&self) -> usize {
            8 * self.page
        }

        /// Byte end of the last control table, from the record types and
        /// counts alone: each field starts at the next multiple of its
        /// alignment. Unrounded, so a table missing from the placements shows
        /// as a shortfall that page rounding would hide.
        fn control_end(&self) -> usize {
            let slots = SLOTS;
            let mut end = 0usize;
            let mut place = |size: usize, align: usize, count: usize| {
                end = end.next_multiple_of(align) + size * count;
            };
            place(size_of::<PoolDescriptor>(), align_of::<PoolDescriptor>(), 1);
            place(size_of::<PoolState>(), align_of::<PoolState>(), 1);
            place(size_of::<ExtentRoot>(), align_of::<ExtentRoot>(), 1);
            place(8, 8, space_words((self.payload_bytes() / IO_UNIT) as u64));
            place(
                size_of::<RunNode>(),
                align_of::<RunNode>(),
                index_table_nodes(slots),
            );
            assert_eq!((size_of::<RunNode>(), align_of::<RunNode>()), (128, 64));
            // The records start on a line.
            place(0, 64, 0);
            place(size_of::<Record>(), align_of::<Record>(), slots);
            place(2, 2, slots);
            place(8, 8, super::super::free::words(slots));
            place(size_of::<Telemetry>(), align_of::<Telemetry>(), 1);
            place(8, 8, slots.div_ceil(64));
            place(8, 8, slots.div_ceil(64).div_ceil(64));
            // The waiting set beside the retired bitmap.
            place(8, 8, slots.div_ceil(64));
            place(8, 8, slots.div_ceil(64));
            place(8, 8, slots.div_ceil(64).div_ceil(64));
            // The policy links start on a window of links.
            place(0, 16, 0);
            place(4, 4, slots);
            place(size_of::<Domain>(), align_of::<Domain>(), 1);
            place(16, 8, 1);
            // One position word per slot and their shared words.
            place(8, 8, slots);
            place(size_of::<JournalWords>(), align_of::<JournalWords>(), 1);
            // Every slot's full key, portable pair, record generation, cache version and insert step.
            place(32, 1, slots);
            place(8, 8, slots);
            place(4, 4, slots);
            place(8, 8, slots);
            place(8, 8, slots);
            place(8, 8, slots);
            place(
                size_of::<Option<VolumeWatermarks>>(),
                align_of::<Option<VolumeWatermarks>>(),
                1,
            );
            // The arena's lists, then its line-aligned roots of 32 KiB and
            // its 384 bytes of free and live bits per root.
            place(size_of::<ArenaLists>(), align_of::<ArenaLists>(), 1);
            place(0, 64, 0);
            place(8, 8, self.roots * ROOT_WORDS);
            place(8, 8, self.roots * BIT_WORDS);
            place(size_of::<Gate>(), align_of::<Gate>(), 1);
            end
        }

        fn control(&self) -> usize {
            self.control_end()
                .next_multiple_of(self.page)
                .max(self.page)
        }

        /// Independent envelope: one root page, the independently computed
        /// control extent, and the volume handle.
        fn expected_used(&self) -> usize {
            self.page + self.control() + std::mem::size_of::<Pool>()
        }

        /// Pages of the control mapping.
        fn control_pages(&self) -> usize {
            self.control() / self.page
        }

        fn config(&self, engine_budget: usize, nodes: NodeMask) -> StorageConfig {
            let mut volume = crate::storage::test_volume(self.payload_bytes(), SLOTS);
            volume.nodes = nodes;
            volume.block_roots = self.roots;
            StorageConfig {
                page_size: self.page,
                engine_budget,
                body_cap: 900,
                metadata_cap: Some(100),
                lease_limit: 1024,
                object_rights: 64,
                reader_limit: 4,
                volume,
            }
        }

        fn validated(&self) -> ValidatedConfig {
            self.config(1 << 24, NodeMask::from_nodes(&[0]).unwrap())
                .validate()
                .unwrap()
        }
    }

    fn native_page() -> usize {
        LinuxPlatform.page_size().unwrap()
    }

    /// A configuration of `slots` slots on `nodes`, its validated form and
    /// the extent of the control mapping it lays out, for a test that needs
    /// a control mapping of a given size.
    fn wide(page: usize, slots: usize, nodes: NodeMask) -> (StorageConfig, ValidatedConfig, usize) {
        let fixture = Fixture::new(page);
        let config = StorageConfig {
            body_cap: 60,
            metadata_cap: Some(4),
            volume: VolumeConfig {
                nodes,
                ..crate::storage::test_volume(fixture.payload_bytes(), slots)
            },
            ..fixture.config(1 << 30, nodes)
        };
        let validated = config.validate().unwrap();
        let control = PoolImage::layout(&validated, page).unwrap().extent;
        (config, validated, control)
    }

    /// Every mapped range was unmapped exactly once, most recent first.
    fn assert_exact_release(log: &Log) {
        let mut expected = log.ranges(Op::Map);
        expected.reverse();
        assert_eq!(log.ranges(Op::Unmap), expected);
    }

    fn check_reports<P: Platform>(storage: &Storage<P>, fixture: &Fixture) {
        let page = fixture.page;
        assert_eq!(storage.engine_used(), fixture.expected_used());
        assert_eq!(storage.init_peak(), fixture.expected_used() + SCRATCH);
        assert_eq!(storage.root_extent(), page);
        assert_eq!(storage.page_size(), page);

        let root = storage.root_descriptor().unwrap();
        assert_eq!(root.page_size, page);
        assert_eq!(root.metadata_cap, 100);
        assert_eq!(root.body_cap, 900);
        assert_eq!(root.engine_limit, 1 << 24);

        let report = storage.pool_report().unwrap();
        assert_eq!(report.control_extent, fixture.control());
        assert_eq!(
            report.descriptor.raw_bytes,
            8 * page + crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT
        );
        assert_eq!(
            report.descriptor.geometry.metadata_units(),
            crate::storage::TEST_METADATA_UNITS
        );
        assert_eq!(
            report.descriptor.geometry.payload_units(),
            (8 * page / IO_UNIT) as u64
        );
        assert_eq!(report.descriptor.slot_count, SLOTS);
        let ledger = report.ledger.unwrap();
        assert_eq!(
            ledger.raw,
            RawPartition::new(
                crate::storage::TEST_METADATA_UNITS as usize * IO_UNIT,
                8 * page
            )
        );
        assert_eq!(ledger.slots.free, SLOTS);
    }

    /// `Gate` ends the control layout; its offset plus size gives the
    /// pre-rounded end, which a fixture missing a table falls short of.
    fn check_table_ends<P: Platform>(storage: &Storage<P>, fixture: &Fixture) {
        let inventory = storage.table_inventory().unwrap();
        assert_eq!(fixture.control_end(), inventory.gate.0 + size_of::<Gate>());
        assert_eq!(inventory.extent_index.1, index_table_nodes(SLOTS));
        assert_eq!(inventory.domain.1, 1);
    }

    /// A residency query the owner did not make: every page of `mapping` is
    /// resident.
    fn assert_resident(mapping: &super::super::mapping::Mapping, page: usize) {
        let len = mapping.len();
        if len == 0 {
            return;
        }
        let mut status = vec![0u8; len / page];
        let base = mapping.base();
        // SAFETY: the mapping is owned and populated; the status buffer holds
        // one byte per page.
        unsafe {
            assert_eq!(
                libc::mincore(base.as_ptr().cast(), len, status.as_mut_ptr()),
                0
            );
        }
        assert!(status.iter().all(|byte| byte & 1 == 1));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "opens the sysfs node topology, which Miri's isolation refuses"
    )]
    fn native_initialization_populates_every_page_then_tears_down() {
        let fixture = Fixture::new(native_page());
        let page = fixture.page;
        let node = native_node();
        let mask = NodeMask::from_nodes(&[node]).unwrap();
        let placement = PlacementConfig { control_home: node };
        let platform = TestPlatform::linux();
        let log = platform.log();
        let config = fixture.config(1 << 24, mask).validate().unwrap();
        let allocations = crate::instrument::allocations();
        let mut storage = Storage::initialize(&config, &placement, platform).unwrap();
        // No construction allocation and nothing during verification.
        assert_eq!(crate::instrument::allocations(), allocations);
        check_reports(&storage, &fixture);

        let lens: Vec<usize> = log.ranges(Op::Map).iter().map(|(_, len)| *len).collect();
        assert_eq!(lens, [page, fixture.control()]);
        // Per mapping: map, huge-page advice, bind, protect, then one
        // populate and one residency call per chunk (every fixture mapping is
        // one chunk), then one bound check and the normal-page advice. No
        // per-page query: the kernel confirmed every range. Then one
        // control-init cut per control mapping and one transfer cut. These
        // counts are the measured kernel-call boundary of initialization.
        assert_eq!(log.calls(Op::PageSize).len(), 1);
        assert_eq!(log.calls(Op::Topology).len(), 1);
        for op in [
            Op::AdviseHuge,
            Op::AdviseNormal,
            Op::Bind,
            Op::Protect,
            Op::Populate,
            Op::Residency,
            Op::CheckBound,
        ] {
            assert_eq!(log.calls(op).len(), 2, "{op:?}");
        }
        assert!(log.calls(Op::PageNode).is_empty());
        // Every mapping's huge-page advice and bind precede its population,
        // and its normal-page advice follows its population.
        let all = log.all();
        for populate in log.calls(Op::Populate) {
            let populate_at = all.iter().position(|c| *c == populate).unwrap();
            let at = |op| {
                all.iter()
                    .position(|c| c.op == op && (c.base, c.len) == (populate.base, populate.len))
                    .unwrap()
            };
            assert!(at(Op::AdviseHuge) < at(Op::Bind));
            assert!(at(Op::Bind) < populate_at);
            assert!(populate_at < at(Op::AdviseNormal));
        }
        assert_eq!(log.calls(Op::Cut(InitPhase::ControlInit)).len(), 2);
        assert_eq!(log.calls(Op::Cut(InitPhase::Transfer)).len(), 1);
        assert!(log.calls(Op::Unmap).is_empty());
        let all = log.all();
        let last_populate = all.iter().rposition(|c| c.op == Op::Populate).unwrap();
        let first_control = all
            .iter()
            .position(|c| c.op == Op::Cut(InitPhase::ControlInit))
            .unwrap();
        assert!(last_populate < first_control);

        assert_resident(&storage.root, page);
        assert_resident(&storage.pool.control, page);
        check_placement_reports(&storage, &fixture, mask);
        // Independent policy witness: the kernel holds a strict bind to the
        // configured mask on every mapping, read through a syscall the owner
        // never makes.
        for mapping in [&storage.root, &storage.pool.control] {
            assert_eq!(policy_at(mapping.base().as_ptr()), (libc::MPOL_BIND, mask));
        }

        // Teardown through the real kernel: two releases, reverse order.
        let calls_before = log.all().len();
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
        assert_exact_release(&log);
        assert_eq!(log.all().len(), calls_before + 2);
        assert_eq!(finalize(&mut storage), Err(FinalizeError::Drained));
        assert_eq!(log.all().len(), calls_before + 2);
    }

    /// The kernel's range check accepts the bound mask and refuses another
    /// allowed node's mask with `EIO`, leaving the bound policy in place. The
    /// refusal needs a second allowed node; a one-node host proves only
    /// acceptance.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "opens the sysfs node topology, which Miri's isolation refuses"
    )]
    fn native_bound_check_accepts_own_mask_and_refuses_another() {
        let page = native_page();
        let len = 4 * page;
        let topology = LinuxPlatform.topology().unwrap();
        let mut allowed = topology.allowed.nodes();
        let home = allowed.next().unwrap();
        let mask = NodeMask::from_nodes(&[home]).unwrap();
        let base = LinuxPlatform.map_inaccessible(len).unwrap();
        // SAFETY: `base..base + len` is a live mapping owned by this test and
        // released at its end.
        unsafe {
            LinuxPlatform.bind(base, len, &mask).unwrap();
            LinuxPlatform.protect_read_write(base, len).unwrap();
            LinuxPlatform.populate_write(base, len).unwrap();
            assert_eq!(LinuxPlatform.check_bound(base, len, &mask), Ok(()));
            if let Some(other) = allowed.next() {
                let wrong = NodeMask::from_nodes(&[other]).unwrap();
                assert_eq!(
                    LinuxPlatform.check_bound(base, len, &wrong),
                    Err(OsCode(libc::EIO))
                );
            }
            assert_eq!(policy_at(base.as_ptr()), (libc::MPOL_BIND, mask));
            LinuxPlatform.unmap(base, len).unwrap();
        }
    }

    /// Binds four measured pages to the first allowed node and checks every
    /// page's node. With a second allowed node it then moves one page there in
    /// the same mapping: the page-node query follows the move, the old mask's
    /// check refuses with `EIO` and keeps the bound policy, and the expanded
    /// mask's check passes and installs that mask. Returns the first node and,
    /// on a host with a second allowed node, that node; a one-node host
    /// returns `None` in the second slot and proves only the bound answer.
    fn second_node_history() -> (usize, Option<usize>) {
        let page = native_page();
        let len = 4 * page;
        let topology = LinuxPlatform.topology().unwrap();
        let mut allowed = topology.allowed.nodes();
        let home = allowed.next().unwrap();
        let mask = NodeMask::from_nodes(&[home]).unwrap();
        let base = LinuxPlatform.map_inaccessible(len).unwrap();
        let pages: Vec<NonNull<u8>> = (0..4)
            .map(|i| base.map_addr(|a| a.saturating_add(i * page)))
            .collect();
        let second = allowed.next();
        // SAFETY: `base..base + len` is a live mapping owned by this call and
        // released at its end; every queried address is one of its pages.
        unsafe {
            LinuxPlatform.bind(base, len, &mask).unwrap();
            LinuxPlatform.protect_read_write(base, len).unwrap();
            LinuxPlatform.populate_write(base, len).unwrap();
            for &address in &pages {
                assert_eq!(LinuxPlatform.page_node(address), Ok(home));
            }
            if let Some(other) = second {
                let target = [other as libc::c_int];
                let mut moved = [i32::MIN];
                let moving = [pages[1].as_ptr().cast_const()];
                let result = libc::syscall(
                    libc::SYS_move_pages,
                    0 as libc::c_long,
                    1usize,
                    moving.as_ptr(),
                    target.as_ptr(),
                    moved.as_mut_ptr(),
                    2 as libc::c_long,
                );
                assert_eq!(result, 0, "{:?}", std::io::Error::last_os_error());
                assert_eq!(moved, [other as i32]);
                assert_eq!(LinuxPlatform.page_node(pages[1]), Ok(other));
                assert_eq!(LinuxPlatform.page_node(pages[0]), Ok(home));
                assert_eq!(
                    LinuxPlatform.check_bound(base, len, &mask),
                    Err(OsCode(libc::EIO))
                );
                // A refused check installs nothing; a passing check with a
                // different mask installs that mask, which is why the
                // transaction only ever checks with the mask it bound.
                assert_eq!(policy_at(base.as_ptr()), (libc::MPOL_BIND, mask));
                let both = NodeMask::from_nodes(&[home, other]).unwrap();
                assert_eq!(LinuxPlatform.check_bound(base, len, &both), Ok(()));
                assert_eq!(policy_at(base.as_ptr()), (libc::MPOL_BIND, both));
            }
            LinuxPlatform.unmap(base, len).unwrap();
        }
        (home, second)
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "opens the sysfs node topology, which Miri's isolation refuses"
    )]
    fn native_page_node_query_follows_a_moved_page() {
        second_node_history();
    }

    /// The placement qualification's second-node witness on the permitted
    /// host: one history moves a measured page to a real second allowed node,
    /// refuses the old mask and accepts the expanded one, and prints
    /// `observe: placement second node`. A one-node host prints its one-node
    /// classification instead, so the prerequisites role's witness stays
    /// missing and the row uncredited.
    #[test]
    #[ignore = "needs the permitted host with a second allowed NUMA node"]
    fn native_a_second_allowed_node_takes_a_moved_page_and_the_expanded_mask() {
        match second_node_history() {
            (home, Some(other)) => eprintln!(
                "observe: placement second node {other} beside node {home}: moved page followed, old mask refused, expanded mask accepted at {} byte pages",
                native_page()
            ),
            (home, None) => eprintln!(
                "observe: placement one-node host, node {home} alone: second-node evidence absent"
            ),
        }
    }

    /// A mask naming every node this task may allocate from binds, populates
    /// and verifies on the real kernel, and the kernel holds that whole mask
    /// as the policy. On a host with several allowed nodes this is the
    /// multi-node success witness; on a one-node host it degenerates to the
    /// one-node case.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "opens the sysfs node topology, which Miri's isolation refuses"
    )]
    fn native_multi_node_mask_initializes_and_verifies() {
        let fixture = Fixture::new(native_page());
        let allowed = LinuxPlatform.topology().unwrap().allowed;
        let home = allowed.nodes().next().unwrap();
        let placement = PlacementConfig { control_home: home };
        let platform = TestPlatform::linux();
        let log = platform.log();
        let config = fixture.config(1 << 24, allowed).validate().unwrap();
        let mut storage = Storage::initialize(&config, &placement, platform).unwrap();
        assert!(log.calls(Op::PageNode).is_empty());
        let a = storage.pool_report().unwrap();
        assert_eq!(a.control_placement.nodes, allowed);
        assert_eq!(a.control_placement.pages_verified, fixture.control_pages());
        assert_eq!(
            storage.root_placement().unwrap().nodes,
            NodeMask::from_nodes(&[home]).unwrap()
        );
        assert_eq!(
            policy_at(storage.pool.control.base().as_ptr()),
            (libc::MPOL_BIND, allowed)
        );
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }

    /// At 4 KiB pages, `three_chunk_slots` produces a control mapping that
    /// reaches the third residency chunk.
    fn three_chunk_slots(page: usize) -> usize {
        (1 << 18) * (page / HEAP_PAGE)
    }

    #[test]
    fn three_chunk_slots_span_three_chunks_at_every_page_size() {
        let mask = NodeMask::from_nodes(&[0]).unwrap();
        for page in [4096, 16384, 65536] {
            let (_, _, control) = wide(page, three_chunk_slots(page), mask);
            let chunk = RESIDENCY_CHUNK_PAGES * page;
            assert!(
                control > 2 * chunk,
                "{control} spans at least three {page}-byte-page chunks"
            );
        }
    }

    /// A single-node configuration whose control mapping spans three chunks
    /// or more, with what one healthy initialization of it on the real
    /// kernel shows: the ordinal of the `CheckBound` call that checks the
    /// control mapping's second chunk, and the number of `CheckBound` calls
    /// the initialization makes. A single-node bind leaves the kernel one
    /// node to place every page on.
    fn second_control_chunk() -> (ValidatedConfig, PlacementConfig, usize, usize) {
        let page = native_page();
        let home = native_node();
        let slots = three_chunk_slots(page);
        let (_, validated, control) = wide(page, slots, NodeMask::from_nodes(&[home]).unwrap());
        let chunk = RESIDENCY_CHUNK_PAGES * page;
        assert!(control > 2 * chunk, "{control} spans at least three chunks");
        let placement = PlacementConfig { control_home: home };
        let platform = TestPlatform::linux();
        let log = platform.log();
        let mut storage = Storage::initialize(&validated, &placement, platform).unwrap();
        let (base, len) = log.ranges(Op::Map)[1];
        assert_eq!(len, control);
        let checks = log.calls(Op::CheckBound);
        let ordinal = 1 + checks
            .iter()
            .position(|call| call.base == base + chunk)
            .unwrap();
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
        (validated, placement, ordinal, checks.len())
    }

    /// One `CheckBound` refusal, chosen by ordinal, makes the control
    /// mapping's second chunk settle through real page-node queries. The
    /// page-node queries are exactly that chunk's pages, once each and in
    /// order, and every page answers inside the bound mask. The
    /// initialization makes as many `CheckBound` calls as the healthy one,
    /// each with the volume's mask, so every other chunk passes its one range
    /// check. Healthy finalization then releases each mapping once.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "opens the sysfs node topology, which Miri's isolation refuses"
    )]
    fn native_one_refused_chunk_settles_on_real_page_nodes() {
        let (validated, placement, ordinal, checks) = second_control_chunk();
        let page = native_page();
        let platform = TestPlatform::linux();
        let log = platform.log();
        platform.fail_at(Fail {
            op: Op::CheckBound,
            ordinal,
            code: OsCode(libc::EIO),
            region: None,
        });
        let mut storage = Storage::initialize(&validated, &placement, platform).unwrap();
        let (base, control) = log.ranges(Op::Map)[1];
        let first = base + RESIDENCY_CHUNK_PAGES * page;
        let calls = log.calls(Op::CheckBound);
        assert_eq!(calls.len(), checks);
        let refused = calls[ordinal - 1];
        assert_eq!(
            (refused.base, refused.len),
            (first, RESIDENCY_CHUNK_PAGES * page),
            "the refusal names the second chunk"
        );
        assert!(
            log.masks()
                .iter()
                .filter(|(op, _)| *op == Op::CheckBound)
                .all(|(_, mask)| *mask == validated.volume().nodes)
        );
        let queried: Vec<(usize, usize)> = (0..RESIDENCY_CHUNK_PAGES)
            .map(|index| (first + index * page, page))
            .collect();
        assert_eq!(log.ranges(Op::PageNode), queried);
        let report = storage.pool_report().unwrap();
        assert_eq!(report.control_placement.pages_verified, control / page);
        assert_eq!(report.control_placement.nodes, validated.volume().nodes);
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
        assert_exact_release(&log);
    }

    /// Over a real mapping, the page queries that follow the chosen chunk's
    /// refused range check stop at the first defective page, and the error
    /// names that page's absolute index in the mapping. The refused check is
    /// the initialization's last range check. A failed node query, injected by
    /// ordinal over real page queries, and an off-mask node answer, from
    /// faked page nodes, each end the queries at their page. Any other
    /// range-check error fails verification before any page query. Each
    /// failure rolls back and releases every mapping once.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "opens the sysfs node topology, which Miri's isolation refuses"
    )]
    fn native_refused_chunk_defects_stop_at_their_absolute_page() {
        let (validated, placement, ordinal, _) = second_control_chunk();
        let page = native_page();
        let first_page = RESIDENCY_CHUNK_PAGES;
        let refusal = Fail {
            op: Op::CheckBound,
            ordinal,
            code: OsCode(libc::EIO),
            region: None,
        };
        let control = Region::Control;
        let home = i32::try_from(placement.control_home).unwrap();
        let off_mask = (placement.control_home + 1) % MAX_NODES;
        assert_ne!(off_mask, placement.control_home);
        let mut off_node = vec![home; first_page + 8];
        off_node[first_page + 6] = i32::try_from(off_mask).unwrap();
        struct Defect {
            fails: Vec<Fail>,
            fake: Option<Vec<i32>>,
            error: InitError,
            queries: usize,
        }
        let cases = [
            Defect {
                fails: vec![
                    refusal,
                    Fail {
                        op: Op::PageNode,
                        ordinal: 5,
                        code: OsCode(libc::EFAULT),
                        region: None,
                    },
                ],
                fake: None,
                error: InitError::PageStatusError {
                    region: control,
                    page: first_page + 4,
                    code: OsCode(libc::EFAULT),
                },
                queries: 5,
            },
            Defect {
                fails: vec![refusal],
                fake: Some(off_node),
                error: InitError::WrongNode {
                    region: control,
                    page: first_page + 6,
                    node: off_mask,
                },
                queries: 7,
            },
            Defect {
                fails: vec![Fail {
                    code: OsCode(libc::EINVAL),
                    ..refusal
                }],
                fake: None,
                error: InitError::Os {
                    phase: InitPhase::VerifyPlacement,
                    region: control,
                    code: OsCode(libc::EINVAL),
                },
                queries: 0,
            },
        ];
        for Defect {
            fails,
            fake,
            error: expected,
            queries,
        } in cases
        {
            let platform = TestPlatform::linux();
            let log = platform.log();
            for fail in fails {
                platform.fail_at(fail);
            }
            if let Some(fake) = fake {
                platform.fake_page_nodes(fake);
            }
            let failure = Storage::initialize(&validated, &placement, platform)
                .err()
                .unwrap();
            assert_eq!(failure.error, expected);
            assert!(matches!(failure.cleanup, Cleanup::Complete), "{expected:?}");
            let (base, _) = log.ranges(Op::Map)[1];
            let first = base + first_page * page;
            let calls = log.calls(Op::CheckBound);
            assert_eq!(calls.len(), ordinal, "{expected:?}");
            assert_eq!(calls[ordinal - 1].base, first, "{expected:?}");
            let queried: Vec<(usize, usize)> = (0..queries)
                .map(|index| (first + index * page, page))
                .collect();
            assert_eq!(log.ranges(Op::PageNode), queried, "{expected:?}");
            assert_exact_release(&log);
        }
    }

    /// A control mapping longer than a chunk on the real kernel: the
    /// per-chunk strict checks re-apply an equal policy, so the mapping stays
    /// one mapping with `MPOL_BIND` at both chunks, and every page counts as
    /// verified. The single-mapping witness is `/proc/self/maps`, which the
    /// owner never reads.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "opens the sysfs node topology, which Miri's isolation refuses"
    )]
    fn native_multi_chunk_control_stays_one_mapping() {
        let page = native_page();
        let node = native_node();
        let mask = NodeMask::from_nodes(&[node]).unwrap();
        let (_, validated, control) = wide(page, 70_000, mask);
        let pages = control / page;
        assert!(pages > RESIDENCY_CHUNK_PAGES && pages <= 2 * RESIDENCY_CHUNK_PAGES);
        let placement = PlacementConfig { control_home: node };
        let platform = TestPlatform::linux();
        let log = platform.log();
        let mut storage = Storage::initialize(&validated, &placement, platform).unwrap();
        assert_eq!(
            storage
                .pool_report()
                .unwrap()
                .control_placement
                .pages_verified,
            pages
        );
        // Root, then two control chunks.
        assert_eq!(log.calls(Op::CheckBound).len(), 3);
        let (base, len) = log.ranges(Op::Map)[1];
        assert_eq!(len, control);
        // One VMA covers the whole control range. The kernel may merge it
        // with an adjacent mapping of the same protection and policy, so the
        // VMA can extend past the range; a split leaves no VMA covering it.
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let covers = |line: &str| {
            let range = line.split_whitespace().next().unwrap_or("");
            let Some((start, end)) = range.split_once('-') else {
                return false;
            };
            let parse = |hex: &str| usize::from_str_radix(hex, 16).unwrap_or(0);
            parse(start) <= base && base + len <= parse(end)
        };
        assert!(
            maps.lines().any(covers),
            "the control mapping is not one mapping:\n{maps}"
        );
        for offset in [0, RESIDENCY_CHUNK_PAGES * page] {
            let inside = (base + offset) as *const u8;
            assert_eq!(policy_at(inside), (libc::MPOL_BIND, mask));
        }
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }

    /// On the real kernel the control mapping leaves initialization under the
    /// normal-page advice: its one VMA carries `VM_NOHUGEPAGE` (`nh`) and
    /// lacks `VM_HUGEPAGE` (`hg`), so the kernel collapses none of its
    /// normal-page ranges later. A kernel built without transparent huge
    /// pages sets neither flag.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "opens the sysfs node topology, which Miri's isolation refuses"
    )]
    fn native_initialization_ends_under_the_normal_page_advice() {
        let page = native_page();
        let node = native_node();
        let mask = NodeMask::from_nodes(&[node]).unwrap();
        let (_, validated, control) = wide(page, 80_000, mask);
        let placement = PlacementConfig { control_home: node };
        let platform = TestPlatform::linux();
        let log = platform.log();
        let mut storage = Storage::initialize(&validated, &placement, platform).unwrap();
        let (base, len) = log.ranges(Op::Map)[1];
        assert_eq!(len, control);
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut covering = false;
        let mut flags = None;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, end)) = range.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                covering = start <= base && base + len <= end;
            } else if covering && let Some(rest) = line.strip_prefix("VmFlags:") {
                flags = Some(
                    rest.split_whitespace()
                        .map(str::to_owned)
                        .collect::<Vec<_>>(),
                );
            }
        }
        let flags = flags.expect("one VMA covers the control mapping");
        let thp = std::path::Path::new("/sys/kernel/mm/transparent_hugepage/enabled").exists();
        assert_eq!(flags.iter().any(|flag| flag == "nh"), thp, "{flags:?}");
        assert!(!flags.iter().any(|flag| flag == "hg"), "{flags:?}");
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
    }

    /// Every mapping reports its bound mask and a verified page count equal
    /// to its extent in pages, derived here from the fixture, not read back.
    fn check_placement_reports<P: Platform>(
        storage: &Storage<P>,
        fixture: &Fixture,
        zero: NodeMask,
    ) {
        let root = storage.root_placement().unwrap();
        assert_eq!((root.nodes, root.pages_verified), (zero, 1));
        let report = storage.pool_report().unwrap();
        assert_eq!(
            (
                report.control_placement.nodes,
                report.control_placement.pages_verified
            ),
            (zero, fixture.control() / fixture.page)
        );
        assert_eq!(report.descriptor.nodes, zero);
    }

    #[test]
    fn heap_backed_control_construction_and_reads() {
        let fixture = Fixture::new(HEAP_PAGE);
        // The slots' tables, the run index and the 128-byte gate span
        // several pages.
        assert!(fixture.control_pages() >= 6, "{}", fixture.control_pages());
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        let mut storage =
            Storage::initialize(&fixture.validated(), &placement(), platform).unwrap();
        check_reports(&storage, &fixture);
        check_table_ends(&storage, &fixture);
        check_placement_reports(&storage, &fixture, NodeMask::from_nodes(&[0]).unwrap());
        assert_eq!(
            storage.root_descriptor().unwrap().control_home,
            NodeMask::from_nodes(&[0]).unwrap()
        );
        assert_eq!(finalize(&mut storage), Ok(Finalization::Drained));
        assert_exact_release(&log);
        assert_eq!(storage.root_placement(), None);
    }

    /// Distinct rejections, checked before any mapping: a volume mask naming
    /// a nonexistent, memoryless or disallowed node; a bad control home.
    /// Configuration validation refuses an empty mask, and placement
    /// validation refuses one on its own too.
    #[test]
    fn invalid_placement_rejects_before_any_mapping() {
        let fixture = Fixture::new(HEAP_PAGE);
        let zero = NodeMask::from_nodes(&[0]).unwrap();
        let payload = Region::Control;
        let cases: Vec<(NodeMask, usize, PlacementError)> = vec![
            (
                NodeMask::from_nodes(&[0, 4]).unwrap(),
                0,
                PlacementError::NodeDoesNotExist {
                    region: payload,
                    node: 4,
                },
            ),
            (
                NodeMask::from_nodes(&[3]).unwrap(),
                0,
                PlacementError::NodeWithoutMemory {
                    region: payload,
                    node: 3,
                },
            ),
            (
                NodeMask::from_nodes(&[1, 2]).unwrap(),
                0,
                PlacementError::NodeNotAllowed {
                    region: payload,
                    node: 2,
                },
            ),
            (
                zero,
                2,
                PlacementError::NodeNotAllowed {
                    region: Region::Root,
                    node: 2,
                },
            ),
            (
                zero,
                MAX_NODES,
                PlacementError::NodeDoesNotExist {
                    region: Region::Root,
                    node: MAX_NODES,
                },
            ),
            // The control home is checked before the volume's mask.
            (
                NodeMask::from_nodes(&[3]).unwrap(),
                4,
                PlacementError::NodeDoesNotExist {
                    region: Region::Root,
                    node: 4,
                },
            ),
        ];
        for (mask, home, expected) in cases {
            let platform = TestPlatform::heap(HEAP_PAGE);
            let log = platform.log();
            let config = PlacementConfig { control_home: home };
            let validated = fixture.config(1 << 24, mask).validate().unwrap();
            let failure = Storage::initialize(&validated, &config, platform)
                .err()
                .unwrap();
            assert_eq!(failure.error, InitError::Placement(expected));
            assert!(matches!(failure.cleanup, Cleanup::Complete));
            assert!(log.calls(Op::Map).is_empty());
        }
        assert_eq!(
            fixture.config(1 << 24, NodeMask::default()).validate(),
            Err(crate::storage::ConfigError::EmptyNodes)
        );
        assert_eq!(
            placement().validate(
                &NodeMask::default(),
                &crate::storage::test_platform::heap_topology()
            ),
            Err(PlacementError::EmptyNodeMask)
        );
        // A mask on node 1 is valid under the fake topology.
        let mask = NodeMask::from_nodes(&[0, 1]).unwrap();
        let platform = TestPlatform::heap(HEAP_PAGE);
        let validated = fixture.config(1 << 24, mask).validate().unwrap();
        let storage = Storage::initialize(&validated, &placement(), platform).unwrap();
        assert_eq!(storage.pool_report().unwrap().control_placement.nodes, mask);
    }

    fn page_queries(mapping: (usize, usize), last: usize) -> Vec<(usize, usize)> {
        (0..=last)
            .map(|page| (mapping.0 + page * HEAP_PAGE, HEAP_PAGE))
            .collect()
    }

    /// Single-page queries stop at the first defect and report its page.
    #[test]
    fn placement_verification_defects_reject_and_roll_back() {
        let fixture = Fixture::new(HEAP_PAGE);
        let validated = fixture.validated();
        let pool_a = Region::Control;
        // Fakes are indexed by page within the queried mapping; the root's
        // one page reads node 0, so the defect lands in the control mapping.
        // Each case records the first defective page; page queries stop there.
        let cases: Vec<(Vec<i32>, usize, InitError)> = vec![
            (
                vec![0, 0, 0, 0, 1, 0, 0],
                4,
                InitError::WrongNode {
                    region: pool_a,
                    page: 4,
                    node: 1,
                },
            ),
            (
                vec![0, 0, 0, 0, 0, 0, -libc::ENOMEM],
                6,
                InitError::PageStatusError {
                    region: pool_a,
                    page: 6,
                    code: OsCode(libc::ENOMEM),
                },
            ),
            // Mixed defects in one chunk: the lowest page wins with its own
            // kind, and the page after it is never queried.
            (
                vec![0, 0, 1, -libc::EIO, 0, 0, 0],
                2,
                InitError::WrongNode {
                    region: pool_a,
                    page: 2,
                    node: 1,
                },
            ),
            (
                vec![0, 0, -libc::EIO, 1, 0, 0, 0],
                2,
                InitError::PageStatusError {
                    region: pool_a,
                    page: 2,
                    code: OsCode(libc::EIO),
                },
            ),
        ];
        for (fake, defect, expected) in cases {
            let platform = TestPlatform::heap(HEAP_PAGE);
            let log = platform.log();
            platform.fake_page_nodes(fake);
            let failure = Storage::initialize(&validated, &placement(), platform)
                .err()
                .unwrap();
            assert_eq!(failure.error, expected);
            assert!(matches!(failure.cleanup, Cleanup::Complete));
            assert_eq!(log.ranges(Op::Map).len(), 2);
            // The root passed the range check without a per-page query; the
            // control mapping was refused and queried page by page up to the
            // defect.
            assert_eq!(log.calls(Op::CheckBound).len(), 2);
            let control = log.ranges(Op::Map)[1];
            assert_eq!(log.ranges(Op::PageNode), page_queries(control, defect));
            assert_exact_release(&log);
        }

        // A failed per-page query reports that page's status error.
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        platform.fake_page_nodes(vec![0, 0, 0, 0, 1, 0, 0]);
        platform.fail_at(Fail {
            op: Op::PageNode,
            ordinal: 1,
            code: OsCode(12),
            region: None,
        });
        let failure = Storage::initialize(&validated, &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::PageStatusError {
                region: pool_a,
                page: 0,
                code: OsCode(12),
            }
        );
        assert_exact_release(&log);

        // A refused chunk with every page answering inside the mask passes.
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        platform.fail_at(Fail {
            op: Op::CheckBound,
            ordinal: 2,
            code: OsCode(libc::EIO),
            region: None,
        });
        let storage = Storage::initialize(&validated, &placement(), platform).unwrap();
        let control = log.ranges(Op::Map)[1];
        assert_eq!(
            log.ranges(Op::PageNode),
            page_queries(control, fixture.control_pages() - 1)
        );
        check_placement_reports(&storage, &fixture, NodeMask::from_nodes(&[0]).unwrap());
        drop(storage);
    }

    /// The sequence arena is charged to `E` once, inside the control
    /// mapping: two roots add at least their 64 KiB and 768 bytes of free and
    /// live bits, a storage initializes at exactly its envelope, and one byte
    /// less refuses with nothing mapped.
    #[test]
    fn the_arena_is_charged_with_the_mapping_and_one_byte_short_refuses() {
        let zero = NodeMask::from_nodes(&[0]).unwrap();
        let fixture = Fixture {
            page: HEAP_PAGE,
            roots: 2,
        };
        let without = Fixture::new(HEAP_PAGE);
        assert!(fixture.control_end() >= without.control_end() + 2 * 8 * (ROOT_WORDS + BIT_WORDS));
        let exact = fixture.expected_used() + SCRATCH;
        let config = fixture.config(exact, zero).validate().unwrap();
        let storage = Storage::initialize(&config, &placement(), TestPlatform::heap(HEAP_PAGE))
            .expect("the exact envelope");
        assert_eq!(storage.engine_used(), fixture.expected_used());
        check_table_ends(&storage, &fixture);
        drop(storage);
        let short = fixture.config(exact - 1, zero).validate().unwrap();
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        let failure = Storage::initialize(&short, &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::Envelope(EngineBudgetExceeded {
                limit: exact - 1,
                used: fixture.expected_used(),
                requested: SCRATCH,
            })
        );
        assert!(log.ranges(Op::Map).is_empty());
    }

    #[test]
    fn rejected_configuration_and_envelope_make_no_kernel_call() {
        let fixture = Fixture::new(HEAP_PAGE);
        let zero = NodeMask::from_nodes(&[0]).unwrap();
        assert!(fixture.config(1 << 24, zero).validate().is_ok());
        let missing = StorageConfig {
            metadata_cap: None,
            ..fixture.config(1 << 24, zero)
        };
        assert_eq!(
            missing.validate().err(),
            Some(super::super::ConfigError::MissingMetadataCap)
        );

        // The root page does not fit `E`.
        let tight = fixture.config(HEAP_PAGE - 1, zero).validate().unwrap();
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        let failure = Storage::initialize(&tight, &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::Envelope(EngineBudgetExceeded {
                limit: HEAP_PAGE - 1,
                used: 0,
                requested: HEAP_PAGE,
            })
        );
        assert!(matches!(failure.cleanup, Cleanup::Complete));
        assert_eq!(log.calls(Op::PageSize).len(), 1);
        assert_eq!(log.calls(Op::ClockResolution).len(), 1);
        assert_eq!(log.calls(Op::Topology).len(), 1);
        assert_eq!(log.all().len(), 3);

        // Everything but the scratch fits `E`; the peak does not.
        let peak_limit = fixture.expected_used() + SCRATCH - 1;
        let tight = fixture.config(peak_limit, zero).validate().unwrap();
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        let failure = Storage::initialize(&tight, &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::Envelope(EngineBudgetExceeded {
                limit: peak_limit,
                used: fixture.expected_used(),
                requested: SCRATCH,
            })
        );
        assert_eq!(log.all().len(), 3);

        let platform = TestPlatform::heap(2 * HEAP_PAGE);
        let log = platform.log();
        let mismatch = Storage::initialize(&fixture.validated(), &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            mismatch.error,
            InitError::PageSizeMismatch {
                configured: HEAP_PAGE,
                actual: 2 * HEAP_PAGE,
            }
        );
        assert_eq!(log.all().len(), 1);
    }

    #[test]
    fn unavailable_page_size_refuses_before_any_other_call() {
        let fixture = Fixture::new(HEAP_PAGE);
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        platform.fail_at(Fail {
            op: Op::PageSize,
            ordinal: 1,
            code: OsCode(22),
            region: None,
        });
        let failure = Storage::initialize(&fixture.validated(), &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(failure.error, InitError::PageSizeUnavailable(OsCode(22)));
        assert!(matches!(failure.cleanup, Cleanup::Complete));
        assert_eq!(log.calls(Op::PageSize).len(), 1);
        assert_eq!(log.all().len(), 1);
    }

    /// Each cut lands after at least one prior acquisition. Ordinals count
    /// calls of one kind in acquisition order: root, then control. The third
    /// element is how many mappings exist when the cut fires and must
    /// therefore be released.
    fn cut_cases() -> Vec<(Fail, InitError, usize)> {
        let code = OsCode(12);
        let os = |phase, region| InitError::Os {
            phase,
            region,
            code,
        };
        let plain = |op, ordinal| Fail {
            op,
            ordinal,
            code,
            region: None,
        };
        let cut = |phase, region| Fail {
            op: Op::Cut(phase),
            ordinal: 0,
            code,
            region: Some(region),
        };
        let control = Region::Control;
        vec![
            (
                plain(Op::Topology, 1),
                InitError::TopologyUnavailable(code),
                0,
            ),
            (plain(Op::Map, 2), os(InitPhase::Map, control), 1),
            (
                plain(Op::AdviseHuge, 2),
                os(InitPhase::PagePolicy, control),
                2,
            ),
            (
                plain(Op::AdviseNormal, 2),
                os(InitPhase::PagePolicy, control),
                2,
            ),
            (plain(Op::Bind, 2), os(InitPhase::Placement, control), 2),
            (plain(Op::Protect, 2), os(InitPhase::Protect, control), 2),
            (plain(Op::Populate, 2), os(InitPhase::Populate, control), 2),
            (
                plain(Op::Residency, 2),
                os(InitPhase::VerifyPopulation, control),
                2,
            ),
            (
                plain(Op::CheckBound, 1),
                os(InitPhase::VerifyPlacement, Region::Root),
                1,
            ),
            (
                cut(InitPhase::ControlInit, control),
                os(InitPhase::ControlInit, control),
                2,
            ),
            (
                cut(InitPhase::Transfer, Region::Root),
                os(InitPhase::Transfer, Region::Root),
                2,
            ),
        ]
    }

    /// Every cut, without a sequence arena and with two roots: typed error,
    /// complete rollback, each mapped range unmapped exactly once most recent
    /// first, no heap allocation from the failing call to the returned
    /// failure.
    fn run_cuts(page: usize, make: impl Fn() -> TestPlatform) {
        for roots in [0, 2] {
            run_cuts_of(Fixture { page, roots }, &make);
        }
    }

    fn run_cuts_of(fixture: Fixture, make: &impl Fn() -> TestPlatform) {
        let page = fixture.page;
        let expected_lens = [page, fixture.control()];
        for (fail, expected, mapped) in cut_cases() {
            let platform = make();
            let log = platform.log();
            platform.fail_at(fail);
            let failure = Storage::initialize(&fixture.validated(), &placement(), platform)
                .err()
                .unwrap();
            let allocations = crate::instrument::allocations();
            assert_eq!(failure.error, expected, "{fail:?}");
            assert!(matches!(failure.cleanup, Cleanup::Complete), "{fail:?}");
            let ranges = log.ranges(Op::Map);
            assert_eq!(ranges.len(), mapped, "{fail:?}");
            let lens: Vec<usize> = ranges.iter().map(|(_, len)| *len).collect();
            assert_eq!(lens, expected_lens[..mapped], "{fail:?}");
            assert_exact_release(&log);
            assert_eq!(log.allocations_at_fail(), Some(allocations), "{fail:?}");
            if fail.op == Op::Bind {
                // The mapping whose bind failed was never populated.
                assert_eq!(log.calls(Op::Populate).len(), fail.ordinal - 1, "{fail:?}");
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls clock_getres, which Miri cannot call")]
    fn native_every_cut_rolls_back_exactly_once() {
        run_cuts(native_page(), TestPlatform::linux);
    }

    #[test]
    fn heap_backed_every_cut_rolls_back_exactly_once() {
        run_cuts(HEAP_PAGE, || TestPlatform::heap(HEAP_PAGE));
    }

    #[test]
    fn unpopulated_page_rejects_and_rolls_back() {
        let fixture = Fixture::new(HEAP_PAGE);
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        // Pages 0..5 resident, page 6 not: the root's one page reads the
        // first entry, so only the control mapping reaches page 6.
        platform.fake_residency(vec![1, 1, 1, 1, 1, 1, 0]);
        let failure = Storage::initialize(&fixture.validated(), &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::Unpopulated {
                region: Region::Control,
                page: 6,
            }
        );
        assert!(matches!(failure.cleanup, Cleanup::Complete));
        assert_exact_release(&log);
        assert_eq!(log.ranges(Op::Map).len(), 2);
    }

    /// A control mapping longer than a chunk is populated, queried and
    /// range-checked in two calls each, interleaved per chunk, and page
    /// indices are absolute, not chunk-relative. A population failure in the
    /// second chunk leaves a populated prefix that is still released at the
    /// full extent.
    #[test]
    fn population_and_verification_are_chunked_with_absolute_page_indices() {
        let (_, validated, control) = wide(HEAP_PAGE, 70_000, NodeMask::from_nodes(&[0]).unwrap());
        let pages = control / HEAP_PAGE;
        assert!(pages > RESIDENCY_CHUNK_PAGES && pages <= 2 * RESIDENCY_CHUNK_PAGES);
        let tail = control - RESIDENCY_CHUNK_PAGES * HEAP_PAGE;

        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        let storage = Storage::initialize(&validated, &placement(), platform).unwrap();
        let payload = log.ranges(Op::Map)[1];
        let chunk = RESIDENCY_CHUNK_PAGES * HEAP_PAGE;
        let chunks = [(payload.0, chunk), (payload.0 + chunk, tail)];
        for op in [Op::Populate, Op::Residency, Op::CheckBound] {
            assert_eq!(log.ranges(op)[1..3], chunks, "{op:?}");
        }
        // Each chunk is populated, checked for residency and range-checked
        // before the next chunk is populated; no page is queried individually.
        let steps: Vec<(Op, usize)> = log
            .all()
            .iter()
            .filter(|call| {
                (payload.0..payload.0 + payload.1).contains(&call.base)
                    && matches!(call.op, Op::Populate | Op::Residency | Op::CheckBound)
            })
            .map(|call| (call.op, call.base))
            .collect();
        assert_eq!(
            steps,
            [
                (Op::Populate, chunks[0].0),
                (Op::Residency, chunks[0].0),
                (Op::CheckBound, chunks[0].0),
                (Op::Populate, chunks[1].0),
                (Op::Residency, chunks[1].0),
                (Op::CheckBound, chunks[1].0),
            ]
        );
        assert_eq!(
            storage
                .pool_report()
                .unwrap()
                .control_placement
                .pages_verified,
            pages
        );
        drop(storage);

        // The kernel refuses the second chunk: the mapping is released at its
        // full extent exactly once, most recent mapping first.
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        platform.fail_at(Fail {
            op: Op::Populate,
            ordinal: 3,
            code: OsCode(12),
            region: None,
        });
        let failure = Storage::initialize(&validated, &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::Os {
                phase: InitPhase::Populate,
                region: Region::Control,
                code: OsCode(12),
            }
        );
        assert!(matches!(failure.cleanup, Cleanup::Complete));
        assert_eq!(log.ranges(Op::Populate).len(), 3);
        assert_eq!(log.ranges(Op::Map).len(), 2);

        // A wrong node in the second chunk refuses that chunk's range check
        // and is then reported with its absolute page; only the refused chunk
        // is queried page by page, after the first chunk passed: the positive
        // multi-chunk coverage witness.
        let mut nodes = vec![0i32; pages];
        nodes[RESIDENCY_CHUNK_PAGES] = 1;
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        platform.fake_page_nodes(nodes);
        let failure = Storage::initialize(&validated, &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::WrongNode {
                region: Region::Control,
                page: RESIDENCY_CHUNK_PAGES,
                node: 1,
            }
        );
        let payload = log.ranges(Op::Map)[1];
        assert_eq!(
            log.ranges(Op::CheckBound)[1..3],
            [(payload.0, chunk), (payload.0 + chunk, tail)]
        );
        assert_eq!(log.ranges(Op::PageNode), [(payload.0 + chunk, HEAP_PAGE)]);
        assert_exact_release(&log);

        // Resident everywhere except the first page of the second chunk.
        let mut status = vec![1u8; pages];
        status[RESIDENCY_CHUNK_PAGES] = 0;
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        // The root page is page 0 of its own mapping and reads resident.
        platform.fake_residency(status);
        let failure = Storage::initialize(&validated, &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::Unpopulated {
                region: Region::Control,
                page: RESIDENCY_CHUNK_PAGES,
            }
        );
        assert_exact_release(&log);
    }

    #[test]
    fn refused_releases_during_rollback_report_incomplete_cleanup() {
        let fixture = Fixture::new(HEAP_PAGE);
        let platform = TestPlatform::heap(HEAP_PAGE);
        let log = platform.log();
        platform.fail_at(Fail {
            op: Op::Cut(InitPhase::Transfer),
            ordinal: 0,
            code: OsCode(5),
            region: Some(Region::Root),
        });
        // In reverse order the first release is the control mapping and the
        // second is the root.
        for ordinal in [1, 2] {
            platform.fail_at(Fail {
                op: Op::Unmap,
                ordinal,
                code: OsCode(16),
                region: None,
            });
        }
        let failure = Storage::initialize(&fixture.validated(), &placement(), platform)
            .err()
            .unwrap();
        assert_eq!(
            failure.error,
            InitError::Os {
                phase: InitPhase::Transfer,
                region: Region::Root,
                code: OsCode(5),
            }
        );
        let Cleanup::Incomplete(retained) = failure.cleanup else {
            panic!("expected incomplete cleanup");
        };
        let mapped = log.ranges(Op::Map);
        let retained: Vec<_> = retained.iter().collect();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].region, Region::Root);
        assert_eq!((retained[0].base, retained[0].len), mapped[0]);
        assert_eq!(retained[1].region, Region::Control);
        assert_eq!((retained[1].base, retained[1].len), mapped[1]);
        assert!(retained.iter().all(|r| r.code == OsCode(16)));
        // Every release was attempted exactly once, in reverse order, and
        // the refused ones were not retried.
        let mut expected = mapped.clone();
        expected.reverse();
        assert_eq!(log.ranges(Op::Unmap), expected);
    }
}
