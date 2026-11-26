//! The warm bootstrap's install and readiness commit: a named slot's guarded load, decoded on the recovery helpers,
//! becomes the pool's restored slots, extent allocator and index entries, and one pool-gate hold then commits
//! allocation readiness. The attempt writes no device unit and no record, so the volume and its recovery evidence stay
//! as the predecessor left them until the commit.
//!
//! The stages run in order: the read of the named slot and its ancestry's suffix blocks through the metadata cells,
//! decoded on the helpers; conversion on the helpers, in pieces of each destination's chunks; then on the owner's
//! tick the collision check, which also groups each destination's publication pairs, and the held bitmap's marks, the
//! allocator's hold, the slot installs, the index publication, and the commit. The collision check and the marks run
//! on at most one scoped worker per lane, which takes the destinations dealt to it and its band, the installs split
//! over one scoped worker for each lane that has an entry to install, and a publication tick runs one worker for each
//! destination it takes, at most one per lane; the hold and the commit run on the owner. A lane owns a slot range for the installs and a unit band
//! for the marks, and a publication worker owns one destination's pairs.
//!
//! Invariants owned by this module:
//!
//! - READ-ONLY-PREFIX: the warm bootstrap's device commands are the slot reader's reads, each inside the records
//!   layout's units; it stages no probe or root write and reads no unit 0, so the prefix and the
//!   predecessor's recovery evidence stay as they were through every outcome of the attempt.
//! - SOURCE-LICENSES: a volume stages a warm bootstrap only from a [`WarmSource`], which names the checkpoint, cut and
//!   ancestry of the shard record a restart's or takeover's acknowledged write committed, under the tenure's complete
//!   coverage fencing; the gate value then licenses the reads, as it licenses every medium command. The source's copy
//!   of that coverage equals the live coverage until `LoadComplete` under a caller precondition: the coverage of the
//!   [`Fencing`](super::super::page_coverage::Fencing) returned beside the capability stays unchanged until then, so it
//!   reaches the owner with no `hold`, `cover_begin` or `cover_page`, and once installed the owner refuses every
//!   coverage hold while the readiness reads `Detached` or `Loading`. A record naming suffixes and no checkpoint mints no source: restart and takeover refuse it `SuffixOnly` at step 1, before any device command.
//! - ONE-CONTRACT: a checkpoint carries no clock contract; its portable expiry pairs convert under the shard's
//!   configured [`ClockContract`], which the writer and the recovering host share and whose scale the attach checks the
//!   clock against, so the conversion's contract comparison holds by construction and `Recovery` applies the local
//!   rate and uncertainty bounds. The shared contract is a deployment precondition the warm path does not check: no
//!   record carries the writer's scale, so attach compares the clock with the local configuration alone.
//! - BOUNDED (read): a read is staged only under a window's reserved helper charge, a destination job under the
//!   decode's guard bytes, and the reader's decode and replay estimate and [`warm_bytes`] are charged to the volume's
//!   budget, a budget of exactly the warm envelope that attach charged to the caller's engine budget (empty for a cold
//!   attach), whose charges the one attempt a volume runs holds for the volume's life; attach refuses recovery limits
//!   that hold less than one window or one guard.
//! - HOST-LOSS-KEEPS-VOLUME: every end of the attempt withholds, closes or stops the readiness with the media
//!   unchanged, and keeps the shard record; the volume stays retained for the next attach.
//! - ALLOCATION-READY: every stage that writes the pool's tables reads the readiness word under the pool gate and
//!   writes only while it reads `Loading` ([`admits`]), in the same hold; an install's workers run and are joined
//!   inside that hold. A withdrawal moves the word to `Withheld` by compare-and-swap before it passes the gate, so a
//!   hold that read `Loading` completes before the withdrawal returns, and every later hold refuses.
//!   Publication writes only the index's shard tables, under their own gates; each publisher reads the word before
//!   each run and stops at any state but `Loading`, and every pair it publishes names a slot whose marker refuses
//!   grants below `Live`.
//! - HOLD-BEFORE-INSTALL: one hold rebuilds the allocator with exactly the restored extents held, on a pristine pool,
//!   before any slot is installed; the extents of omitted entries, and every unit no restored entry names, are free.
//! - RETAINED-OR-REFUSED: each admitted entry is retained, omitted as expired or live-only, or refused. An entry is
//!   omitted only on evidence that it left the retained set or never joined it: a portable pair that every later
//!   load judges expired too ([`Recovery::retained`]; a pair that this load's reading or sample alone judges expired
//!   restores as a member that reads expired, whose units stay held like any member's), the absent pair
//!   [`PortableExpiry::ABSENT`] of a binding published live-only, whose deadline no load can honor, a
//!   `(key, version)` the tenure's fenced coverage covers, or a record of version 0 whose key the coverage
//!   touches, since FILL admission admits version 0 only while no interval of its key is held and an INVALIDATE of
//!   any interval removes every version of its key. The omission applies alike to a checkpoint entry and to a
//!   certified suffix's insert. The conversion identifies the absent pair from the stored pair alone.
//!   It does so before any clock verdict on the entry, so every load omits the entry at any reading.
//!   Every later loader omits each entry whose stored pair is [`PortableExpiry::ABSENT`], whatever lifetime it
//!   could assign: a checkpoint stays readable after a later fill reuses the units it names.
//!   Every other admitted entry restores, or the attempt refuses before any table write:
//!   a sequence entry, a record length or session the tenure does not admit, a malformed pair other than the absent
//!   one, a pair the clock withholds, or an entry the slot decode or the suffix withheld, whatever its expiry or
//!   coverage, since the load keeps neither, refuses `Unrestorable`, an extent, tail or slot past the
//!   storage's geometry, or a chunk or a place in its run that 32 bits cannot name, refuses `Bounds`, a restored set
//!   that routes more keys to an index shard than its visible limit
//!   refuses `Limits` at the marks, and a failed data unit that leaves no whole entry of the slot refuses `StaleWrite`,
//!   whatever the suffix holds, so no empty or suffix-only cache
//!   replaces the retained set. A refused attempt keeps the volume and its recovery evidence for a later load. A
//!   publication that still finds a shard's chains full past their depth bound ends the attempt `MetadataFailed` after
//!   the installs, under ENDED-HOLDS.
//! - EXACT-HELD: the mark workers each own one band of the held bitmap's words, and two restored extents that share a
//!   unit refuse the attempt `Overlap` before any table write, whether one worker or a band edge finds the shared
//!   unit; at the commit the slot ledger's resident count is the installed count less any slot an invalidation retired.
//! - DISJOINT-LANES: an install worker writes only the slots of its lane (the `tables` module's lanes), and the
//!   holder folds every lane's shared effect once before it releases the gate; a share that panics leaves the gate
//!   poisoned and the attempt `MetadataFailed`, so half-written tables admit no holder.
//! - READ-READY: each slot installs with the recovered-origin marker, so a grant on it refuses until the word reads
//!   `Live`, and publication into the index, under each shard's gate, follows every install: the stage moves to the
//!   publication only after the install tick whose lanes left no entry.
//! - COMMIT-AFTER-RECONSTRUCTION: `LoadComplete` is applied once, while the pool gate is held, after every restored
//!   slot, its extent and its index entry are in place; fills reserve only at `Live`, after `begin_replay`.
//! - ENDED-HOLDS: an attempt that ends before its commit retires nothing: each installed slot keeps its counted anchor
//!   and its extent stays held, so no extent with a counted reference is freed, and the attempt never reaches `Live`.
//!   The storage of an ended attempt keeps those slots until it drops: the hold stage records the attempt's hold in
//!   the storage before the first install and the commit clears it, so the close service leaves the pairs an ended
//!   attempt published mapped, the storage's finalization reports the slots blocked and its
//!   mappings stay until the storage drops with the process, and the next attach builds new tables over the same media.
//! - UNIQUE-ROUTE: the slot decode routes each entry to a destination by its fingerprint alone, so equal
//!   fingerprints reach one destination, and the marks refuse two restored keys of one destination that share one,
//!   over every piece of that destination, so the attempt ends `Collided` before any table write. The check groups
//!   the destination's pairs by index shard and bucket run ([`RUN_BITS`]), which is also the order the destination's
//!   publication writes them in; equal fingerprints route to one bucket, so it compares within a group.
//! - BOUNDED: the stage refuses a load whose [`warm_bytes`] the engine budget cannot hold; the conversion holds the
//!   load's own entries and hands the consumed chunks to helper jobs that free them after the commit or a refused
//!   conversion; each install
//!   tick takes at most [`INSTALL_RUN`] entries per lane and each publication tick as many pairs per destination; the
//!   marks walk the bitmap once, and the allocator's hold resets the allocator's tables and walks its runs twice, to
//!   check and count them and to build the free index. A withdrawal waits for the hold in progress: at most that
//!   reset and those walks, one install tick, or the commit's ledger read and readiness event. The decode keeps at most
//!   [`SPARES`](super::super::recovery::checkpoint::SPARES) emptied read buffers for the owner's copies, counted in
//!   its estimate.

use std::sync::Arc;

use crate::failover::records::{Ancestry, Layout, NamedCheckpoint, ShardRecord};
use crate::index::{KeyHasher, ValidatedIndex};
use crate::net::linear_probe::{probe, table_len};
use crate::net::ownership::Shard;

use super::super::IO_UNIT;
use super::super::allocation::AllocationId;
use super::super::budget::WorkBudget;
use super::super::cache::coverage::Coverage;
use super::super::capture::PoisonOnUnwind;
use super::super::checkpoint::{READ_LEN, ReaderRefusal, SlotReader, WINDOWS};
use super::super::device::{Disk, PoolKind};
use super::super::extent::ExtentLocator;
use super::super::gate::GateError;
use super::super::layout::record_len;
#[cfg(test)]
use super::super::ledger::EngineBudget;
use super::super::os::Platform;
use super::super::owner::{Pool, Storage};
use super::super::portable::recovery::{Recovery, Withheld};
use super::super::portable::{ClockContract, PortableExpiry, Reading};
use super::super::prefetch::hint_read;
use super::super::publish::{Pair, PublishError, publish_restored};
use super::super::readiness::{Event, State};
use super::super::record::{ValidRecordConfig, admits as reads};
use super::super::recovery::checkpoint::{Chunk, Damage, Loaded, SlotLoad, mark as mark_units};
use super::super::recovery::delta_replay::{SuffixReport, lsns};
use super::super::recovery::{LoadLimits, LoadRefusal, Session};
use super::super::reserve::{RestoreRefusal, Restored};
use super::super::tables::{Folded, Lane, PoolAccess, lane_len};
use super::super::{CacheVersion, MetadataOutcome};
use super::attach::Volume;
use super::helpers::{Charge, Job, Output, Panicked};
use super::metadata::{Command, Phase, Target};
use super::report::RecoveryPhase;

/// What a tenure's acknowledged shard record names for its warm bootstrap. Its expiry pairs convert under the shard's
/// configured clock contract, which the writer must have shared: no record carries the writer's scale, and attach
/// checks the clock against the local configuration alone (ONE-CONTRACT). The source names the checkpoint, its cut and the ancestry's
/// suffixes, the records layout of the volume, the reader session, which admits the predecessor sessions of the
/// tenure's generation below its own, and a copy of the tenure's fenced coverage, which every restored entry is checked
/// against and which equals the live coverage until `LoadComplete` (SOURCE-LICENSES).
/// A restart or takeover mints one from the record its own write committed, so the value licenses the bootstrap
/// (SOURCE-LICENSES).
#[derive(Debug, Clone)]
pub struct WarmSource {
    shard: Shard,
    named: NamedCheckpoint,
    cut: u64,
    ancestry: Ancestry,
    layout: Layout,
    reader: u64,
    coverage: Coverage,
}

impl WarmSource {
    /// The source `record` names under `layout` for the tenure of `session`, with a copy of `coverage`, or `None` for a
    /// record naming no checkpoint, whose tenure starts cold; such a record holds no suffix, since restart and takeover
    /// refuse a suffix-only record at step 1. Only a restart's or takeover's step 9 builds one in production.
    pub(crate) fn new(
        record: &ShardRecord,
        layout: Layout,
        session: &Session,
        coverage: &Coverage,
    ) -> Option<Self> {
        Some(Self {
            shard: record.shard,
            named: record.checkpoint?,
            cut: record.cut,
            ancestry: record.ancestry,
            layout,
            reader: session.get(),
            coverage: coverage.clone(),
        })
    }

    /// The records layout the source reads.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }
}

/// The inputs of a warm read, which attach computes once from the storage and the driver: the limits the decode checks
/// the slot's entries against, the read window, the destination count, and the envelope. The envelope is the reader's
/// decode and replay estimate plus the [`warm_bytes`] of a load of the layout's `entries` entries with, per
/// destination, one chunk for each read window the slot can touch, `ceil(slot bytes / window) + 1` for a slot that
/// starts inside a window, and one for the suffix's live entries, and one stitched chunk for each boundary between
/// those windows, which one entry's rows can cross; attach charges it to the engine budget, and the
/// attempt charges its actual estimates to a volume budget of exactly that size.
#[derive(Debug, Clone, Copy)]
pub(super) struct Planned {
    limits: LoadLimits,
    read_len: u64,
    destinations: usize,
    pub(super) envelope: usize,
}

impl Planned {
    /// The plan of `source` on `storage`, over maintenance buffers of `buffer_len` bytes and a driver transfer of
    /// `max_transfer` bytes, at the recovery helpers' lane count; `None` when a term of the envelope overflows.
    pub(super) fn of<P: Platform>(
        storage: &Storage<P>,
        (buffer_len, max_transfer): (u32, u32),
        source: &WarmSource,
    ) -> Option<Self> {
        let descriptor = storage.pool().descriptor();
        let payload_units = descriptor.geometry.payload_units();
        let limits = LoadLimits {
            payload_start: 0,
            payload_end: payload_units,
            reserve_units: storage
                .live_pool()
                .map_or(0, |pool| pool.image.reserve_units),
            slot_count: descriptor.slot_count,
            n_max: source.layout.entries as usize,
            record_chunk_len: storage.record.chunk_len(),
        };
        let read_len = read_len(buffer_len, max_transfer);
        let destinations = storage
            .index()
            .map_or(1, |index| index.geometry.enabled().len());
        let manifest = (source.named, source.cut, source.ancestry.as_slice());
        let reader =
            SlotReader::estimate(&source.layout, manifest, (&limits, destinations), read_len)
                .ok()?;
        let touched =
            (u64::from(source.named.units) * IO_UNIT as u64).div_ceil(read_len) as usize + 1;
        let lanes = storage.recovery.helpers.max(1) as usize;
        let groups = storage
            .index()
            .map_or(1, |index| groups_of(&index.geometry).1);
        let load = (
            limits.n_max,
            (touched + 1)
                .checked_mul(destinations)?
                .checked_add(touched - 1)?,
            destinations,
        );
        let shared = storage
            .index()
            .map_or(0, |index| index.geometry.inventory().geometry_bytes)
            .checked_add(source.coverage.heap_bytes())?;
        let warm = warm_estimate(load, payload_units, (lanes, groups, shared))?;
        Some(Self {
            limits,
            read_len,
            destinations,
            envelope: reader.checked_add(warm)?,
        })
    }

    /// The read window's helper charge and one destination guard's bytes, which the recovery limits must hold.
    pub(super) fn charges(&self) -> (Charge, usize) {
        let guard =
            super::super::recovery::checkpoint::guard_bytes(&self.limits, self.destinations);
        (Charge::decode(self.read_len as usize), guard)
    }

    /// The bytes one slot or suffix read spans, the largest charge the warm read makes to the recovery I/O share.
    pub(super) fn read_len(&self) -> u64 {
        self.read_len
    }

    /// The live jobs a warm read needs: every window it holds and one job per destination.
    pub(super) fn jobs(&self) -> usize {
        WINDOWS + self.destinations
    }
}

/// The bytes one slot read spans on a volume whose maintenance buffers hold `buffer_len` bytes and whose device
/// carries `max_transfer` per command: the largest power of two of whole units at most [`READ_LEN`] that both admit.
pub(super) fn read_len(buffer_len: u32, max_transfer: u32) -> u64 {
    let room = u64::from(buffer_len.min(max_transfer)).clamp(IO_UNIT as u64, READ_LEN);
    1 << room.ilog2()
}

/// The warm bootstrap's read: the reader over the named slot and the suffix blocks, the window charge each read
/// holds, and the source, whose coverage the stage takes.
pub(super) struct Read {
    reader: SlotReader,
    window: Charge,
    source: WarmSource,
}

/// The certified ends a warm load raises for the predecessor suffixes of `ancestry` from `cut`, as
/// `(session, certified)`: the blocks below each end were read whole and replayed, so the end is the lowest of the
/// suffix's first hole, its first unread LSN and its recorded end; a suffix certified to that end already is left out.
pub(super) fn certified(
    ancestry: &Ancestry,
    cut: u64,
    layout: &Layout,
    report: &SuffixReport,
) -> Vec<(u64, u64)> {
    (ancestry.as_slice().iter())
        .filter_map(|suffix| {
            let range = lsns(suffix, cut, layout);
            let hole = (report.damage.iter().chain(&report.tails))
                .map(|hole| hole.lsn)
                .chain(report.unread.iter().copied())
                .filter(|lsn| range.contains(lsn))
                .min();
            let end = hole.unwrap_or(range.end);
            (end > suffix.certified).then_some((suffix.session, end))
        })
        .collect()
}

/// The entries a lane installs, and the pairs a destination publishes, in one tick at most.
#[cfg(not(test))]
pub(super) const INSTALL_RUN: usize = 1 << 20;
#[cfg(test)]
pub(super) const INSTALL_RUN: usize = 16;

/// Whether a warm stage may write the pool's tables after reading `state` under the pool gate: only while the load
/// runs.
pub(super) fn admits(state: State) -> bool {
    state == State::Loading
}

/// How a conversion splits its output: the slot length of a lane, the unit-bitmap words of a band, the lane count,
/// the payload's units and the slot count.
#[derive(Debug, Clone, Copy)]
struct Split {
    lane: usize,
    band: usize,
    lanes: usize,
    payload_units: u64,
    slots: usize,
}

/// One piece of a destination's conversion: its chunks, the split of its output, and what a restored entry is checked
/// against.
#[derive(Debug)]
pub(super) struct Convert {
    destination: usize,
    chunks: Vec<Chunk>,
    split: Split,
    coverage: Arc<Coverage>,
    /// The shard's configured clock contract, encoded, standing in for the checkpoint writer's, which no record
    /// carries, and the storage's own, and the recovery sample.
    contracts: ([u8; 24], ClockContract),
    sample: (Option<u64>, Reading),
    record: ValidRecordConfig,
    max_units: u64,
    /// The tenure's session, which must admit every restored record.
    writer: u64,
}

/// One restored entry as its install and the collision check read it: its slot, its local deadline in deadline
/// seconds, its extent ending at the record's length, its key's routing fingerprint, which the collision check groups
/// the destination's pairs by, and its place among the piece's chunks, the chunk and the place in that chunk's run,
/// whose entry holds its other facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Placed {
    slot: u32,
    expires_at_s: u32,
    locator: ExtentLocator,
    chunk: u32,
    at: u32,
    print: u64,
}

impl Placed {
    /// The entry this place names among `chunks`, its piece's.
    fn entry<'c>(&self, chunks: &'c [Chunk]) -> &'c Loaded {
        chunks[self.chunk as usize].at(self.at as usize)
    }

    /// The binding of `entry`, the entry this place names.
    fn restored(&self, entry: &Loaded) -> Restored {
        Restored {
            id: AllocationId::of_record_tag(entry.identity.allocation),
            session: entry.identity.session,
            version: entry.identity.version,
            key: entry.identity.key,
            fingerprint: entry.print,
            expiry: PortableExpiry {
                deadline_ns: entry.deadline_ns,
                lifetime_ms: entry.lifetime_ms,
            },
            expires_at_s: self.expires_at_s,
            locator: self.locator,
            tail: entry.tail,
        }
    }
}

/// A conversion piece's result: the destination it belongs to, its restored entries, its restored extents packed by
/// band, the entries it omitted, the units and payload bytes the restored extents hold, the refusal of the whole
/// attempt, if any, and the consumed chunks, which the installs, the collision check and the publication read and a
/// helper frees.
#[derive(Debug)]
pub(super) struct Converted {
    destination: usize,
    /// The restored entries that ascend by slot in the load's order: each entry whose slot is at or above the one
    /// before it here. A lane's entries are one range of them.
    placed: Vec<Placed>,
    /// The restored entries whose slot is below the ascending run's last when they arrive, a suffix's in a captured
    /// load: by lane, and within a lane in the load's order. A lane's entries are one range of them.
    late: Vec<Placed>,
    extents: Vec<Vec<u64>>,
    omitted: u64,
    units: usize,
    payload: usize,
    refusal: Option<MetadataOutcome>,
    chunks: Vec<Chunk>,
}

#[cfg(test)]
thread_local! {
    /// Conversions this thread dispatches panic, for the containment tests.
    pub(super) static PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Each `spread` this thread calls returns `None` for its first share, the result of a worker the OS refused to
    /// start, for the containment tests.
    pub(super) static SPAWN_REFUSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A planted defect for a negative control: each `spread` this thread calls drops a share's caught panic payload
    /// bare, outside any unwind boundary.
    pub(super) static BARE_PAYLOAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A planted defect for a negative control: the hold rebuilds the allocator over the pristine pool and skips
    /// restoring the restored extents, so the fills that open at `Live` may place over restored units.
    pub(crate) static HOLD_SKIPS_RESTORE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A planted defect for a negative control: a conversion this thread runs refuses an entry whose pair is
    /// [`PortableExpiry::ABSENT`] as it refuses every other malformed pair.
    pub(crate) static REFUSE_ABSENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A planted defect for a negative control: a conversion this thread runs restores an entry whose pair is
    /// [`PortableExpiry::ABSENT`] as a member that never expires, though its units may hold a later fill's record.
    pub(crate) static RETAIN_ABSENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A whole withdrawal runs just before a stage's pool-gate try-lock.
    pub(super) static WITHDRAW_BEFORE_GATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A withdrawal's compare-and-swap lands inside the commit's hold, after its admission read.
    pub(super) static WITHDRAW_AT_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Converts `job`'s entries on a helper, judging each by these rules in order (RETAINED-OR-REFUSED): an extent past
/// the payload or of zero units, a tail of [`IO_UNIT`] bytes or more, a slot at or past the slot count, or a chunk
/// of the piece or a place in its run that 32 bits cannot name refuses the attempt `Bounds`; an entry whose portable
/// pair is [`PortableExpiry::ABSENT`] at any reading, whose pair [`Recovery::retained`] judges `Expired`,
/// whose `(key, version)` the coverage covers, or of version 0 whose key the coverage touches, as FILL admission
/// judges version 0, is omitted, and its units stay free; an entry of other than one extent, a pair withheld for any
/// other cause, a malformed pair other than the absent one included, a record length that names no payload within
/// `max_units` units, or a record the writer's session does not admit refuses it `Unrestorable`; every other entry
/// restores. A job stops at its first refusal and drops its remaining chunks on the helper. The restored entries leave as one run ascending by
/// slot and the late entries by lane, which the installs merge; each carries its fingerprint, which the destination's
/// collision check at the marks groups its pairs by.
pub(super) fn convert(job: Convert) -> Converted {
    let ((root, local), (before, reading)) = (job.contracts, job.sample);
    let recovery = Recovery::new(&root, &local, &reading, before);
    let split = job.split;
    let entries = job.chunks.iter().map(Chunk::len).sum();
    let mut out = Converted {
        destination: job.destination,
        placed: Vec::with_capacity(entries),
        late: Vec::new(),
        extents: vec![Vec::new(); split.lanes],
        omitted: 0,
        units: 0,
        payload: 0,
        refusal: None,
        chunks: Vec::with_capacity(job.chunks.len()),
    };
    for chunk in job.chunks {
        let index = out.chunks.len();
        for (at, entry, extents) in chunk.placed() {
            let named = entry.identity;
            let geometry = |bits: &u64| {
                let locator = ExtentLocator::from_bits(*bits);
                locator.len_units() > 0
                    && locator.start_unit() + u64::from(locator.len_units()) <= split.payload_units
            };
            if !extents.iter().all(geometry)
                || usize::from(entry.tail) >= IO_UNIT
                || slot_of(entry) >= split.slots
                || at.max(index) > u32::MAX as usize
            {
                out.refusal = Some(MetadataOutcome::Unloadable(LoadRefusal::Bounds));
                break;
            }
            // The stored absent pair identifies a live-only binding at every clock reading, so every load omits its
            // entry. `retained` returns `Expired` only if every later load omits the entry or keeps it expired, so a
            // later fill can reuse the units either omission frees.
            let pair = (entry.deadline_ns, entry.lifetime_ms);
            if live_only(pair) {
                out.omitted += 1;
                continue;
            }
            let deadline = recovery.retained(pair);
            #[cfg(test)]
            let deadline = match RETAIN_ABSENT.with(std::cell::Cell::get) && absent(pair) {
                true => Ok(u32::MAX - 1),
                false => deadline,
            };
            if deadline == Err(Withheld::Expired)
                || job
                    .coverage
                    .excludes(&named.key, CacheVersion(named.version))
            {
                out.omitted += 1;
                continue;
            }
            let (1, Some(&bits), Ok(expires_at_s)) = (extents.len(), extents.first(), deadline)
            else {
                out.refusal = Some(MetadataOutcome::Unloadable(LoadRefusal::Unrestorable));
                break;
            };
            let locator = ExtentLocator::from_bits(bits);
            let (start, units) = (locator.start_unit(), locator.len_units());
            let len = record_len(units, entry.tail);
            let payload = (u64::from(units) <= job.max_units)
                .then(|| job.record.payload_of(len))
                .flatten();
            let (Some(payload), true) = (payload, reads(&named, &named, job.writer)) else {
                out.refusal = Some(MetadataOutcome::Unloadable(LoadRefusal::Unrestorable));
                break;
            };
            let band = ((start / 64) as usize / split.band).min(split.lanes - 1);
            out.extents[band].push(bits);
            (out.units, out.payload) = (out.units + units as usize, out.payload + payload as usize);
            let placed = Placed {
                // A record tag names its slot in 32 bits.
                slot: slot_of(entry) as u32,
                expires_at_s,
                locator: locator.ending_at(len),
                // The bounds rule above admitted a chunk and a place that 32 bits name.
                chunk: index as u32,
                at: at as u32,
                print: entry.print,
            };
            // A capture walks the slots in order, so a load's entries ascend by slot but for the ones its suffix
            // replayed. The entries still to come number at most the room the ascending run has left, so the late
            // entries take one reservation of that size.
            match out.placed.last() {
                Some(last) if placed.slot < last.slot => {
                    if out.late.capacity() == 0 {
                        out.late.reserve_exact(entries - out.placed.len());
                    }
                    out.late.push(placed);
                }
                _ => out.placed.push(placed),
            }
        }
        out.chunks.push(chunk);
        if out.refusal.is_some() {
            return out;
        }
    }
    // A lane holds a range of slots, so ordering the late entries by lane, then by their place in the load, leaves
    // each lane's as one range in the load's order.
    let lane = |placed: &Placed| placed.slot as usize / split.lane;
    (out.late).sort_unstable_by_key(|placed| (lane(placed), placed.chunk, placed.at));
    out
}

/// Whether `pair` is [`PortableExpiry::ABSENT`], the pair of a binding published with no portable deadline, which
/// stays live-only: no load can honor its deadline, so every load omits its entry.
fn live_only(pair: (u64, u32)) -> bool {
    #[cfg(test)]
    if REFUSE_ABSENT.with(std::cell::Cell::get) || RETAIN_ABSENT.with(std::cell::Cell::get) {
        return false;
    }
    absent(pair)
}

/// Whether `pair` is [`PortableExpiry::ABSENT`].
fn absent((deadline_ns, lifetime_ms): (u64, u32)) -> bool {
    PortableExpiry {
        deadline_ns,
        lifetime_ms,
    } == PortableExpiry::ABSENT
}

/// A destination's publication pairs, each restored entry's `(fingerprint, allocation)`, in publication order.
pub(super) type Pairs = Vec<Pair>;

/// The publication pairs of `destination`, `(fingerprint, allocation)` for each restored entry of its pieces in
/// `converted`, ordered by publication group under `routing` and `groups`, the order its publication writes them in;
/// and whether two of them share a fingerprint. One pass over the entries' places sizes the groups by their
/// fingerprints; a second writes each pair once, at the next place of its group, reading its allocation tag from its
/// chunk. Equal fingerprints share a group, so [`repeated`] checks each group alone.
fn destination_pairs(
    converted: &[Converted],
    (routing, groups): (&(KeyHasher, ValidatedIndex), &(Vec<usize>, usize)),
    destination: usize,
) -> (Pairs, bool) {
    let pieces = (converted.iter()).filter(|piece| piece.destination == destination);
    let places = pieces.flat_map(|piece| {
        let places = (piece.placed.iter()).chain(&piece.late);
        places.map(move |placed| (placed, &piece.chunks[..]))
    });
    let group = |placed: &Placed| group_of(routing, &groups.0, placed.print);
    let mut starts = vec![0; groups.1 + 1];
    for (placed, _) in places.clone() {
        starts[group(placed) + 1] += 1;
    }
    for group in 1..starts.len() {
        starts[group] += starts[group - 1];
    }
    let mut next = starts[..groups.1].to_vec();
    let free = Pair {
        fingerprint: 0,
        tag: 0,
    };
    let mut pairs = vec![free; starts[groups.1]];
    for (placed, chunks) in places {
        let at = &mut next[group(placed)];
        pairs[*at] = Pair {
            fingerprint: placed.print,
            tag: placed.entry(chunks).identity.allocation,
        };
        *at += 1;
    }
    let mut table = Vec::new();
    let prints = |group: &[usize]| {
        pairs[group[0]..group[1]]
            .iter()
            .map(|pair| pair.fingerprint)
    };
    let collided = (starts.windows(2)).any(|group| repeated(prints(group), &mut table));
    (pairs, collided)
}

/// `repeated` reports whether two of `words` are equal.
///
/// Each call clears `table` and resizes it to two entries for no words, otherwise to [`table_len`] of the word count,
/// at least twice and fewer than four times the count, within the four words per entry [`warm_estimate`] charges. The
/// table entry 0 marks a free entry, so a separate flag records the word 0.
fn repeated(words: impl ExactSizeIterator<Item = u64>, table: &mut Vec<u64>) -> bool {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let size = table_len(words.len()).max(2);
    table.clear();
    table.resize(size, 0);
    let index = u64::BITS - size.trailing_zeros();
    let mut zero = false;
    for word in words {
        if word == 0 {
            if zero {
                return true;
            }
            zero = true;
            continue;
        }
        let hash = (word.wrapping_mul(SPREAD) >> index) as usize;
        match probe(table, hash, |held| held == 0, |held| held == word) {
            Ok(_) => return true,
            Err(at) => table[at] = word,
        }
    }
    false
}

/// The conversion pieces of `shards`, each destination's chunks split into about `2 * lanes / destinations` runs, so
/// the conversions spread over the helpers whatever the destination count; a piece is `(destination, chunks)`.
fn pieces(shards: Vec<Vec<Chunk>>, lanes: usize) -> Vec<(usize, Vec<Chunk>)> {
    let per = (2 * lanes).div_ceil(shards.len().max(1)).max(1);
    let mut pieces = Vec::new();
    for (destination, mut chunks) in shards.into_iter().enumerate() {
        let len = chunks.len().div_ceil(per).max(1);
        // Each split takes the tail, so a piece's vector holds its own chunks and the head keeps the one buffer.
        while chunks.len() > len {
            let at = chunks.len() - len;
            pieces.push((destination, chunks.split_off(at)));
        }
        pieces.push((destination, chunks));
    }
    pieces
}

/// The base buckets of one publication group, as a power of two: 4,096 buckets of two cache lines each are 512 KiB,
/// which with their summaries fit a second-level cache of 1 MiB. Tests run four buckets a group, so a small index
/// holds several groups a shard.
#[cfg(not(test))]
const RUN_BITS: u32 = 12;
#[cfg(test)]
const RUN_BITS: u32 = 2;

/// The first publication group of each enabled shard of `index`, by position, and the group count, at least one: a
/// shard has one group for each run of `2^RUN_BITS` base buckets.
fn groups_of(index: &ValidatedIndex) -> (Vec<usize>, usize) {
    let mut groups = 0;
    let offsets = (index.enabled().iter())
        .map(|shard| {
            let first = groups;
            groups += (shard.bucket_mask >> RUN_BITS) + 1;
            first
        })
        .collect();
    (offsets, groups.max(1))
}

/// The publication group of fingerprint `print` under `routing`, whose enabled shards' first groups are `offsets`: its
/// shard's first group plus the run of its base bucket.
fn group_of((hasher, index): &(KeyHasher, ValidatedIndex), offsets: &[usize], print: u64) -> usize {
    let route = hasher.reroute_unpaid(print, index);
    route.map_or(0, |route| {
        offsets[route.position()] + (route.bucket() >> RUN_BITS)
    })
}

/// The slot index `entry`'s allocation names.
fn slot_of(entry: &Loaded) -> usize {
    AllocationId::of_record_tag(entry.identity.allocation).slot_index()
}

/// Marks the extents of `extents`, locator bits, in `words`, the bitmap words `[first, first + words.len())`, and
/// returns whether two of them share a unit, with the units past `words` as `[start, end)` spills.
fn mark<'e>(
    words: &mut [u64],
    first: usize,
    extents: impl Iterator<Item = &'e u64>,
) -> (bool, Vec<(u64, u64)>) {
    let (base, limit) = (first as u64 * 64, (first + words.len()) as u64 * 64);
    let (mut seen, mut spills) = (false, Vec::new());
    for &bits in extents {
        let locator = ExtentLocator::from_bits(bits);
        let start = locator.start_unit();
        let end = start + u64::from(locator.len_units());
        let inside = (start.max(base), end.min(limit));
        if inside.0 < inside.1 {
            seen |= mark_units(words, inside.0 - base, inside.1 - base);
        }
        if end > limit {
            spills.push((start.max(limit), end));
        }
    }
    (seen, spills)
}

/// Marks in `held` the units the extents spilled past their bands' words and returns whether two extents share a
/// unit. `bands` holds each band's [`mark`] result over its own words of `held`; a shared unit is one a band saw
/// inside its words, or one a spill finds already marked.
fn overlapped(held: &mut [u64], bands: impl IntoIterator<Item = (bool, Vec<(u64, u64)>)>) -> bool {
    let mut overlap = false;
    for (seen, spills) in bands {
        overlap |= seen;
        for (start, end) in spills {
            overlap |= mark_units(held, start, end);
        }
    }
    overlap
}

/// The bytes a warm bootstrap of `load` allocates beside the load's own entries, over `payload_units` payload units,
/// `lanes` lanes and the publication groups of `index`, as [`warm_estimate`] counts them. `None` when the total overflows
/// `usize`.
pub(super) fn warm_bytes(
    load: &SlotLoad,
    payload_units: u64,
    (lanes, index): (usize, &ValidatedIndex),
    coverage: &Coverage,
) -> Option<usize> {
    let groups = groups_of(index).1;
    let chunks: usize = load.shards.iter().map(Vec::len).sum();
    let entries: usize = load.shards.iter().flatten().map(Chunk::len).sum();
    let shared = (index.inventory().geometry_bytes).checked_add(coverage.heap_bytes())?;
    warm_estimate(
        (entries, chunks, load.shards.len()),
        payload_units,
        (lanes, groups, shared),
    )
}

/// [`warm_bytes`] of a load of `entries` entries in `chunks` chunks over `destinations` destinations. Per entry: its
/// place, once for the ascending run's room and once for the late entries' reservation; its packed extent, three
/// times for a band vector and the copy it grows from; its publication pair; the four words the collision
/// check's probe table reaches; and its share of the free words a tick's lanes list as emptied, each word emptied by
/// 64 installs and listed in a vector that holds a copy while it doubles. The held bitmap. Per destination: the two
/// copies of its group starts and its shards' first groups, its pairs as the collision check's worker returns them
/// and as the attempt keeps them, a publication cursor and a tick's slice, and a publication result. Per conversion
/// piece, at most `2 * lanes` past one per destination ([`pieces`]): its band vectors, its `Converted` record, and per
/// lane the two run cursors, both copies of the two run slices and the two run counts of an install tick; the
/// consumed-chunk lists and the pieces' split lists; and the attempt's fixed state, its `Warm` record and per lane a
/// merge, a tick's fold and the tick's three run lists, its run list, reservation, work, result, refusal and counts;
/// each piece's chunks slice and the copy the free jobs split off; and the coverage and routing `Arc` blocks,
/// including `shared_bytes`, the heap bytes of the coverage copy's tables and the routing copy's geometry
/// tables. Scoped workers' spawn state is allocated beside this estimate.
fn warm_estimate(
    (entries, chunks, destinations): (usize, usize, usize),
    payload_units: u64,
    (lanes, groups, shared_bytes): (usize, usize, usize),
) -> Option<usize> {
    let per_entry = 2 * size_of::<Placed>() + size_of::<Pair>() + size_of::<[u64; 7]>();
    // A lane's emptied list holds at least four words, and the pool's last free word holds fewer than 64 slots.
    let emptied = (entries / 64)
        .checked_add(4 * lanes + 1)?
        .checked_mul(3 * size_of::<usize>())?;
    // Each `Arc` block holds two counts beside its value.
    let shared =
        (4 * size_of::<usize>() + size_of::<Coverage>() + size_of::<(KeyHasher, ValidatedIndex)>())
            .checked_add(shared_bytes)?;
    let tick = size_of::<Vec<&[Placed]>>()
        + size_of::<u64>()
        + size_of::<((Lane<'static>, Vec<&[Placed]>), usize)>()
        + size_of::<Option<(Folded, Option<RestoreRefusal>, (usize, Vec<&[Placed]>))>>()
        + size_of::<RestoreRefusal>()
        + size_of::<(usize, Vec<usize>)>();
    let fixed = size_of::<Warm>()
        + shared
        + lanes * (size_of::<Merge>() + size_of::<(Folded, [Vec<usize>; 3])>() + tick);
    let per_destination = 3 * groups.checked_add(1)?.checked_mul(size_of::<u64>())?
        + size_of::<(Pairs, bool)>()
        + size_of::<Pairs>()
        + size_of::<(usize, usize, &[Pair])>()
        + size_of::<Option<Result<usize, Option<PublishError>>>>();
    let run = size_of::<usize>() + size_of::<&[Placed]>();
    let per_piece = lanes * (size_of::<Vec<u64>>() + 4 * run)
        + size_of::<&[Chunk]>()
        + 2 * size_of::<Converted>();
    let vectors = destinations
        .checked_mul(per_destination)?
        .checked_add(
            destinations
                .checked_add(2 * lanes)?
                .checked_mul(per_piece)?,
        )?
        .checked_add(chunks.checked_mul(2 * size_of::<Chunk>())?)?;
    entries
        .checked_mul(per_entry)?
        .checked_add(
            usize::try_from(payload_units.div_ceil(64))
                .ok()?
                .checked_mul(size_of::<u64>())?,
        )?
        .checked_add(vectors)?
        .checked_add(emptied)?
        .checked_add(fixed)
}

/// The maximal runs of set bits of `held` below `end`, as ascending half-open unit ranges.
fn runs(held: &[u64], end: u64) -> impl Iterator<Item = (u64, u64)> + Clone + '_ {
    let next = move |from: u64, set: bool| {
        let mut at = from;
        while at < end {
            let word = held[(at / 64) as usize];
            let word = if set { word } else { !word } >> (at % 64);
            if word != 0 {
                return (at + u64::from(word.trailing_zeros())).min(end);
            }
            at = (at / 64 + 1) * 64;
        }
        end
    };
    let mut at = 0;
    std::iter::from_fn(move || {
        let start = next(at, true);
        (start < end).then(|| {
            at = next(start, false);
            (start, at)
        })
    })
}

/// Starts `work` on a scoped worker of `scope` placed on `cpus`, `None` when the OS refused the start. Placement is
/// best effort: a worker the kernel refuses the set keeps the owner's affinity, which changes speed only.
#[expect(
    clippy::disallowed_methods,
    reason = "a warm load with a busy share attempts a scoped worker; whether thread scheduling affects a simulated result is unverified"
)]
fn spawn<'scope, T: Send + 'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    cpus: &'scope super::CpuSet,
    work: impl FnOnce() -> T + Send + 'scope,
) -> Option<std::thread::ScopedJoinHandle<'scope, T>> {
    #[cfg(all(test, loom))]
    let _ = cpus;
    std::thread::Builder::new()
        .spawn_scoped(scope, move || {
            #[cfg(not(all(test, loom)))]
            // SAFETY: `pthread_self` names the calling thread, which stays live for the call.
            let _ = unsafe { cpus.apply(libc::pthread_self()) };
            work()
        })
        .ok()
}

/// Runs `work(k, input)` for the `k`th of `inputs` and returns the results in input order. A share that holds work
/// (`busy(k)`) runs on its own scoped worker placed on `cpus`; every other share runs on the calling thread, under
/// that thread's affinity, when the call reaches it. A result is `None` for a share that panicked or whose worker the
/// OS refused to start. A share's panic payload is dropped under [`contain`](super::contain), on the calling thread
/// or from its worker's join, so a payload whose destructor panics ends inside `spread`.
#[expect(
    clippy::disallowed_methods,
    reason = "a warm load with a busy share attempts a scoped worker; whether thread scheduling affects a simulated result is unverified"
)]
fn spread<I: Send, T: Send>(
    inputs: Vec<I>,
    busy: impl Fn(usize) -> bool,
    cpus: &super::CpuSet,
    work: impl Fn(usize, I) -> T + Sync,
) -> Vec<Option<T>> {
    std::thread::scope(|scope| {
        let work = &work;
        let mut results: Vec<Option<T>> = Vec::with_capacity(inputs.len());
        let mut workers = Vec::with_capacity(inputs.len());
        for (k, input) in inputs.into_iter().enumerate() {
            results.push(None);
            #[cfg(test)]
            if k == 0 && SPAWN_REFUSED.with(std::cell::Cell::get) {
                continue;
            }
            if busy(k) {
                workers.push((k, spawn(scope, cpus, move || work(k, input))));
            } else {
                #[cfg(test)]
                if BARE_PAYLOAD.with(std::cell::Cell::get) {
                    let run = std::panic::AssertUnwindSafe(|| work(k, input));
                    results[k] = std::panic::catch_unwind(run).ok();
                    continue;
                }
                results[k] = super::contain(|| work(k, input)).ok();
            }
        }
        for (k, worker) in workers {
            results[k] = worker.and_then(|worker| match worker.join() {
                Ok(result) => Some(result),
                #[cfg(test)]
                Err(payload) if BARE_PAYLOAD.with(std::cell::Cell::get) => {
                    drop(payload);
                    None
                }
                Err(payload) => {
                    let _ = super::contain(|| drop(payload));
                    None
                }
            });
        }
        results
    })
}

/// The pairs a publication worker publishes between two reads of the readiness word; tests run 4, so a worker's
/// tick of [`INSTALL_RUN`] pairs spans several runs.
#[cfg(not(test))]
const PUBLISH_RUN: usize = 1 << 12;
#[cfg(test)]
const PUBLISH_RUN: usize = 4;

/// The slots of one merge window: one word of the free set.
const WINDOW: usize = 64;

/// One lane's place in the merge of its runs: the entries it took of each run, two runs for each landed conversion
/// piece, and the slot bound of the window the merge is in, 0 before its first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Merge {
    taken: Vec<usize>,
    bound: usize,
}

/// One marked slot of a merge window: the run that marked it, the run's places from the marked one on, and the entry
/// the marked place names.
#[derive(Clone, Copy)]
struct Marked<'w> {
    run: usize,
    places: &'w [Placed],
    entry: &'w Loaded,
}

/// One install worker's tick: `lane` installs at most [`INSTALL_RUN`] entries of `runs` for writer session `writer`,
/// merged by slot window. Run `2p` is conversion piece `p`'s ascending entries and run `2p + 1` its late entries, and
/// both read their entries from `chunks[p]`. In each window the worker marks the slot of every ascending run's leading
/// entries below `bound`, requesting each entry's lines for reading and advancing the run past them, then installs the
/// marked slots in slot order from the places the marks recorded, so the lane's tables fill in ascending address order
/// whatever the run's length; a slot two entries name waits for the window's next round, where its install refuses. A
/// late run installs its leading entries below the bound in its own order. The bound then moves to the end of the
/// window that holds the least slot leading a run. The worker stops at the first refusal and returns the lane's pending
/// effects, that refusal and the bound to resume from; each of `runs` keeps the entries it did not install, a marked
/// entry included.
fn install_merged<'w>(
    mut lane: Lane<'_>,
    (runs, chunks): (&mut [&'w [Placed]], &[&'w [Chunk]]),
    mut bound: usize,
    writer: u64,
) -> (Folded, Option<RestoreRefusal>, usize) {
    let mut left = INSTALL_RUN;
    let entry = |run: usize, placed: &Placed| placed.entry(chunks[run / 2]);
    // A round reads only the cells of slots it marked, and marking a slot writes its cell, so a window leaves the
    // cells of the one before in place.
    let mut cells: [Option<Marked<'w>>; WINDOW] = [None; WINDOW];
    loop {
        let base = bound.saturating_sub(WINDOW);
        // The marked slots of the window, and whether two entries name one of them.
        let (mut marked, mut repeated) = (0u64, false);
        let mut least = usize::MAX;
        let refused = 'installs: {
            for (owner, run) in runs.iter_mut().enumerate() {
                let (all, mut taken) = (*run, 0);
                for placed in all {
                    if placed.slot as usize >= bound {
                        least = least.min(placed.slot as usize);
                        break;
                    }
                    if owner % 2 == 1 {
                        if left == 0 {
                            break;
                        }
                        if let Err(refusal) =
                            lane.install(&placed.restored(entry(owner, placed)), writer)
                        {
                            *run = &all[taken..];
                            break 'installs Some(refusal);
                        }
                        (taken, left) = (taken + 1, left - 1);
                        continue;
                    }
                    // An ascending run's entries below the window installed in an earlier one.
                    let cell = (placed.slot as usize).saturating_sub(base);
                    if marked >> cell & 1 == 1 {
                        repeated = true;
                        break;
                    }
                    let mark = Marked {
                        run: owner,
                        places: &all[taken..],
                        entry: entry(owner, placed),
                    };
                    (marked, cells[cell], taken) = (marked | 1 << cell, Some(mark), taken + 1);
                    let lines = std::ptr::from_ref(mark.entry).cast::<u8>();
                    hint_read(lines);
                    hint_read(lines.wrapping_add(size_of::<Loaded>() - 1));
                }
                *run = &all[taken..];
            }
            while marked != 0 && left > 0 {
                let cell = marked.trailing_zeros() as usize;
                let Some((mark, Some(placed))) =
                    cells[cell].map(|mark| (mark, mark.places.first()))
                else {
                    unreachable!("a marked slot holds its place: window {base}, slot {cell}")
                };
                if let Err(refusal) = lane.install(&placed.restored(mark.entry), writer) {
                    break 'installs Some(refusal);
                }
                (marked, left) = (marked & (marked - 1), left - 1);
            }
            None
        };
        // The scan advanced each run past its marked entries. A run's marked slots ascend and install in that order,
        // so the run resumes at its lowest slot still marked: the walk goes from the highest marked slot down, and a
        // run's last write is that slot's.
        while marked != 0 {
            let cell = 63 - marked.leading_zeros() as usize;
            marked &= !(1 << cell);
            if let Some(mark) = cells[cell] {
                runs[mark.run] = mark.places;
            }
        }
        if refused.is_some() || left == 0 || (least == usize::MAX && !repeated) {
            return (lane.done(), refused, bound);
        }
        if !repeated {
            bound = (least / WINDOW + 1) * WINDOW;
        }
    }
}

/// The slots lane `lane` of `split` holds, `[start, end)`; the last lane holds every slot from its start on.
fn lane_slots(split: Split, lane: usize) -> (usize, usize) {
    let start = lane * split.lane;
    match lane + 1 == split.lanes {
        true => (start, usize::MAX),
        false => (start, start + split.lane),
    }
}

/// The runs lane `lane` has yet to install under its merge `merge`: for each landed piece of `converted`, the rest of
/// its ascending entries whose slots the lane holds, then the rest of its late entries whose slots the lane holds.
fn lane_runs<'w>(
    converted: &'w [Converted],
    merge: &Merge,
    split: Split,
    lane: usize,
) -> Vec<&'w [Placed]> {
    let (slots, taken) = (lane_slots(split, lane), &merge.taken);
    let runs = (converted.iter().enumerate()).flat_map(|(p, converted)| {
        [
            &within(&converted.placed, slots)[taken[2 * p]..],
            &within(&converted.late, slots)[taken[2 * p + 1]..],
        ]
    });
    runs.collect()
}

/// The warm bootstrap's stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Convert,
    Mark,
    Hold,
    Install,
    Publish,
    Commit,
    Done,
}

/// A warm bootstrap's state: the conversion pieces to dispatch and those landed, the held bitmap, each lane's install
/// merge over the landed pieces, and each destination's publication pairs and cursor.
#[derive(Debug)]
pub(super) struct Warm {
    stage: Stage,
    /// The conversion pieces to dispatch, each a destination and a run of its chunks.
    queued: Vec<(usize, Vec<Chunk>)>,
    converted: Vec<Converted>,
    destinations: usize,
    split: Split,
    held: Vec<u64>,
    coverage: Option<Arc<Coverage>>,
    /// The storage's hasher and index geometry, which the collision check and the publication route by.
    routing: (KeyHasher, ValidatedIndex),
    contracts: [u8; 24],
    sample: (Option<u64>, Reading),
    /// Conversions dispatched and not yet landed.
    converting: usize,
    units: usize,
    payload: usize,
    omitted: u64,
    /// Each lane's install merge, each destination's pairs grouped for its publication at the marks and the pairs it
    /// published, the first publication group of each enabled shard with the group count, and the publication ticks
    /// taken.
    merges: Vec<Merge>,
    pairs: Vec<Pairs>,
    published: Vec<usize>,
    groups: (Vec<usize>, usize),
    turns: usize,
    installed: u64,
    /// The predecessor suffixes' certified ends the load established, taken once after the commit.
    certified: Vec<(u64, u64)>,
}

impl Warm {
    /// The restored bindings, which replay accounts for.
    pub(super) fn rows(&self) -> u64 {
        self.installed
    }

    /// Whether an owner step has work: a conversion to dispatch, or a stage after the conversions landed.
    pub(super) fn pending(&self) -> bool {
        match self.stage {
            Stage::Convert => !self.queued.is_empty(),
            Stage::Mark | Stage::Hold | Stage::Install | Stage::Publish | Stage::Commit => true,
            Stage::Done => false,
        }
    }
}

/// The entries of `run` whose slots lie in `[start, end)`, a lane's slots: one range of a run that ascends by slot or
/// by lane.
fn within(run: &[Placed], (start, end): (usize, usize)) -> &[Placed] {
    let below = |bound: usize| run.partition_point(|placed| (placed.slot as usize) < bound);
    &run[below(start)..below(end)]
}

impl<'s, 'a, P: Platform, D: Disk> Volume<'s, 'a, P, D> {
    /// Stages the warm bootstrap of `load`, a named slot's guarded load whose fingerprints are this storage's hasher's,
    /// under the tenure's fenced `coverage`, with `certified` as the predecessor suffixes'
    /// certified ends. The read step stages it once the slot reader finishes; the test-only assumed load stages at the
    /// gate's pass, before any probe. Expiry pairs convert under the shard's configured clock contract (ONE-CONTRACT).
    ///
    /// The attempt ends `Unloadable` with the guard's refusal when `verdict` refuses, `Unreadable` when a unit or a
    /// suffix block went unread, `StaleWrite` when the suffix history is damaged or the slot's damage left no entry,
    /// `Unrestorable` when the slot decode or the suffix withheld an entry or the recovery clock's verdict refuses, and `Memory` when the
    /// volume's engine budget cannot hold [`warm_bytes`] beside the reader's charge; `MetadataFailed` when the storage
    /// has no index or pool, or the stage starts a helper pool and the start fails. A load whose failed units lose
    /// entries installs the rest and keeps its damage as the loss record, which the recovery report carries.
    pub(super) fn stage_warm(
        &mut self,
        load: SlotLoad,
        coverage: Coverage,
        certified: Vec<(u64, u64)>,
    ) {
        let contracts = self.storage.clock.encode();
        debug_assert!(
            self.metadata.fenced.is_some(),
            "the warm path stages after the gate"
        );
        let (Some(index), Some(_)) = (self.storage.index(), self.storage.live_pool()) else {
            return self.end(MetadataOutcome::MetadataFailed);
        };
        let routing = (index.hasher.clone(), index.geometry.clone());
        self.recovery.warm_load(&load);
        let unread = (load.damage.as_ref()).is_some_and(|damage| !damage.unread.is_empty());
        // A failed data unit that left no whole entry of the slot would commit the suffix alone over the retained set;
        // unit 0 holds only counts, so its damage loses no entry.
        let failed = |damage: &Damage| damage.failed.iter().any(|&unit| unit > 0);
        let lost = load.damage.as_ref().is_some_and(failed) && load.slot_found == 0;
        let refused = match load.verdict {
            Err(refusal) => Some(refusal),
            Ok(()) if unread || !load.suffix.unread.is_empty() => Some(LoadRefusal::Unreadable),
            Ok(()) if !load.installable() => Some(LoadRefusal::StaleWrite),
            Ok(()) if lost => Some(LoadRefusal::StaleWrite),
            Ok(()) if load.slot_withheld > 0 || !load.suffix.withheld.is_empty() => {
                Some(LoadRefusal::Unrestorable)
            }
            Ok(()) => None,
        };
        let slots = self.descriptor.slot_count;
        let lanes = (self.storage.recovery.helpers as usize).max(1);
        let payload_units = self.descriptor.geometry.payload_units();
        let groups = groups_of(&routing.1);
        let fits = warm_bytes(&load, payload_units, (lanes, &routing.1), &coverage)
            .is_some_and(|bytes| self.budget.charge(bytes).is_ok());
        let refused = refused.or((!fits).then_some(LoadRefusal::Memory));
        let sample = self.recovery_sample();
        let clock = Recovery::new(&contracts, &self.storage.clock, &sample.1, sample.0).verdict();
        let refused = refused.or(clock.is_err().then_some(LoadRefusal::Unrestorable));
        if let Some(refusal) = refused {
            self.end(MetadataOutcome::Unloadable(refusal));
            return;
        }
        // An idle pool runs the conversions under its tag. The read's pool is idle here: the reader yields its load
        // only once every slot job's terminal landed. A stage that finds no idle pool starts one.
        if !(self.metadata.helpers.as_ref()).is_some_and(super::helpers::Helpers::idle)
            && self.start_helpers(self.storage.recovery).is_err()
        {
            self.end(MetadataOutcome::MetadataFailed);
            return;
        }
        let split = Split {
            slots,
            lane: lane_len(slots, lanes),
            band: (payload_units.div_ceil(64) as usize).div_ceil(lanes).max(1),
            lanes,
            payload_units,
        };
        // A load of no destination lands no conversion, so it starts at the marks.
        let stage = match load.shards.is_empty() {
            true => Stage::Mark,
            false => Stage::Convert,
        };
        let destinations = load.shards.len();
        let queued = pieces(load.shards, lanes);
        let runs = 2 * queued.len();
        self.metadata.warm = Some(Box::new(Warm {
            stage,
            converted: Vec::with_capacity(queued.len()),
            destinations,
            held: Vec::new(),
            coverage: (!queued.is_empty()).then(|| Arc::new(coverage)),
            queued,
            split,
            routing,
            contracts,
            sample,
            converting: 0,
            units: 0,
            payload: 0,
            omitted: 0,
            merges: vec![
                Merge {
                    taken: vec![0; runs],
                    bound: 0,
                };
                lanes
            ],
            pairs: Vec::new(),
            published: vec![0; destinations],
            groups,
            turns: 0,
            installed: 0,
            certified,
        }));
        self.metadata.phase = Phase::Warm;
    }

    /// Whether the attach restores retained entries: it carries a warm source, reads its slot or runs its warm
    /// bootstrap.
    pub(crate) fn warms(&self) -> bool {
        let metadata = &self.metadata;
        #[cfg(test)]
        if metadata.assumed.is_some() {
            return true;
        }
        metadata.warm_source.is_some() || metadata.reading.is_some() || metadata.warm.is_some()
    }

    /// Assumes a warm bootstrap of a finished `load` under the tenure's fenced `coverage`: the gate
    /// passes, and the bootstrap stages at its pass in place of the first probe, with no read.
    ///
    /// # Errors
    ///
    /// Once the attach passed its gate and submitted a probe.
    #[cfg(test)]
    pub(crate) fn assume_warm(&mut self, load: SlotLoad, coverage: Coverage) -> Result<(), ()> {
        let gate = super::fence::Fenced::assumed();
        match &self.metadata.phase {
            Phase::Gate { .. } => self.authority.pending_fence = Some(gate),
            Phase::ProbeA if self.metadata.commands.iter().all(Option::is_none) => {
                self.metadata.fenced = Some(gate);
            }
            _ => return Err(()),
        }
        self.budget = EngineBudget::unlimited();
        self.metadata.assumed = Some(Box::new(super::metadata::Assumed { load, coverage }));
        Ok(())
    }

    /// Begins the warm bootstrap `source` names, under the attach's plan of it, in place of the first probe: builds the
    /// slot reader under the storage's hasher and enabled shards, charges its decode and replay estimate to the volume's
    /// share of the engine budget, the plan's envelope, starts the helpers and enters `Phase::Warm` reading. The reader
    /// checks its estimate against that budget, so the charge after it holds. The attempt ends `Unloadable(Memory)` when
    /// the reader refuses the estimate, `Unloadable(Limits)` when the reader refuses the slot, and
    /// `MetadataFailed` when the storage has no index or the helpers cannot start.
    pub(super) fn begin_warm(&mut self, (source, planned): (WarmSource, Planned)) {
        self.metadata.loaded = Some(source.layout);
        let Some(index) = self.storage.index() else {
            return self.end(MetadataOutcome::MetadataFailed);
        };
        let reader = SlotReader::with_read_len(
            self.crc,
            &source.layout,
            source.shard,
            (source.named, source.cut, source.ancestry.as_slice()),
            source.reader,
            (planned.limits, &self.budget),
            (index.hasher.clone(), planned.destinations),
            planned.read_len,
        );
        let reader = match reader {
            Ok(reader) => reader,
            Err(ReaderRefusal::Memory) => {
                return self.end(MetadataOutcome::Unloadable(LoadRefusal::Memory));
            }
            Err(ReaderRefusal::Slot) => {
                return self.end(MetadataOutcome::Unloadable(LoadRefusal::Limits));
            }
        };
        // The reader refused `Memory` unless this budget holds its estimate.
        (self.budget.charge(reader.bytes()))
            .expect("the reader checked its estimate against this budget");
        if self.start_helpers(self.storage.recovery).is_err() {
            return self.end(MetadataOutcome::MetadataFailed);
        }
        self.metadata.warm_layout = Some(source.layout);
        self.metadata.reading = Some(Box::new(Read {
            reader,
            window: planned.charges().0,
            source,
        }));
        self.metadata.phase = Phase::Warm;
    }

    /// The read's step: dispatches the destination jobs the pool reserves under the decode's guard bytes, stages the
    /// reader's next reads into free metadata cells, each under a window's reserved charge and a maintenance buffer,
    /// and once the reader is done finishes the load: a load stages the install, and a helper or allocator failure
    /// ends the attempt `MetadataFailed` with the record kept.
    fn read_step(&mut self) {
        let Some(reading) = self.metadata.reading.as_mut() else {
            return;
        };
        let Some(helpers) = self.metadata.helpers.as_mut() else {
            return;
        };
        let guard = Charge {
            input: reading.reader.decode().guard_bytes(),
            output: 0,
        };
        while helpers.reserve(guard) {
            let Some(work) = reading.reader.decode().work() else {
                helpers.unreserve(guard);
                break;
            };
            #[cfg(test)]
            if super::helpers::PANIC.with(std::cell::Cell::get) {
                helpers.dispatch(guard, Job::Panic);
                continue;
            }
            helpers.dispatch(guard, Job::Slot(work));
        }
        let window = reading.window;
        for cell in self
            .metadata
            .commands
            .iter_mut()
            .filter(|cell| cell.is_none())
        {
            if !helpers.reserve(window) {
                break;
            }
            let Ok(buffer) = self.arena.acquire(PoolKind::Maintenance) else {
                helpers.unreserve(window);
                break;
            };
            let Some(range) = reading.reader.next_read() else {
                helpers.unreserve(window);
                break;
            };
            let unit = range.start() / IO_UNIT as u64;
            // The loop borrows the cells, so the read writes the staged command into its cell in place and counts it in
            // `staged`, as `Metadata::stage` does.
            *cell = Some(Command::unit(Target::Slot, unit, range, buffer));
            self.metadata.staged += 1;
        }
        if !reading.reader.done() {
            return;
        }
        let Some(reading) = self.metadata.reading.take() else {
            return;
        };
        let Read { reader, source, .. } = *reading;
        let Some(load) = reader.finish() else {
            return self.end(MetadataOutcome::MetadataFailed);
        };
        let certified = certified(&source.ancestry, source.cut, &source.layout, &load.suffix);
        self.stage_warm(load, source.coverage, certified);
    }

    /// Takes the bytes of a completed slot read of `range`, or counts it unread for a failed one, and dispatches the
    /// window job under the read's charge; a suffix read releases the charge. A terminal after the attempt ended
    /// changes nothing, its charge released by the cancel.
    pub(super) fn slot_read(
        &mut self,
        range: super::super::device::DeviceRange,
        bytes: Option<&[u8]>,
    ) {
        // The cancel released the read's charge, so a terminal after it copies and replays nothing.
        let helpers = (self.metadata.helpers.as_mut()).filter(|helpers| helpers.accepting());
        let (Some(reading), Some(helpers)) = (self.metadata.reading.as_mut(), helpers) else {
            return;
        };
        let work = match bytes {
            Some(bytes) => reading.reader.completed_copy(range, bytes),
            None => reading.reader.failed(range),
        };
        match work {
            Some(work) => _ = helpers.dispatch(reading.window, Job::Slot(work)),
            None => helpers.unreserve(reading.window),
        }
    }

    /// `poll_helpers` adopts this attempt's terminals, at most the adoption bound a tick: a slot job's terminal lands in
    /// the warm read and its panic fails the slot decode, a conversion lands in the warm bootstrap, and any other panic
    /// closes the attempt with no write.
    fn poll_helpers(&mut self) {
        let mut adopted = 0;
        while let Some(output) =
            (self.metadata.helpers.as_mut()).and_then(|helpers| helpers.poll(&mut adopted))
        {
            self.recovery.count(RecoveryPhase::Adoption, (1, 0));
            match output {
                Ok(Output::Slot(done)) => self.slot_done(Ok(done)),
                Ok(Output::Restored(converted)) => {
                    self.converted(converted);
                    // An ended attempt's helpers stopped accepting; its stale outputs drop with the pool.
                    if (self.metadata.helpers.as_ref()).is_none_or(|helpers| !helpers.accepting()) {
                        return;
                    }
                }
                Ok(Output::Freed) => {}
                Ok(Output::Encoded(_)) => {
                    unreachable!("an encode dispatches only once the metadata is open")
                }
                // A failed slot job fails the decode; the reader's finish then keeps the record.
                Err(Panicked) if self.metadata.reading.is_some() => self.slot_done(Err(())),
                Err(Panicked) => {
                    // CONTAINED: the attempt ends Closed with outcome `MetadataFailed`; nothing is written, so a later
                    // attach decides the volume.
                    let closed = self.storage.readiness.apply(Event::Close);
                    debug_assert_eq!(closed, Ok(super::super::readiness::State::Closed));
                    self.end(MetadataOutcome::MetadataFailed);
                    return;
                }
            }
        }
    }

    /// Adopts a slot decode job's terminal, or records a helper's panic as the decode's failure.
    fn slot_done(&mut self, done: Result<super::super::recovery::checkpoint::Done, ()>) {
        let Some(reading) = self.metadata.reading.as_mut() else {
            return;
        };
        match done {
            Ok(done) => reading.reader.decode().landed(done),
            Err(()) => reading.reader.decode().fail(),
        }
    }

    /// The predecessor suffixes' certified ends a committed warm load established, as `(session, certified end)`, once;
    /// `None` with no warm bootstrap, before the commit, after they were taken, and when the load raised no end.
    pub fn certified(&mut self) -> Option<Vec<(u64, u64)>> {
        let warm = self.metadata.warm.as_mut()?;
        (warm.stage == Stage::Done && !warm.certified.is_empty())
            .then(|| std::mem::take(&mut warm.certified))
    }

    /// Returns `Some(layout)` if the attach began a warm read and `None` otherwise. A committed warm load restored
    /// the named slot and the predecessor suffix blocks from the units in `layout`.
    pub fn warm_layout(&self) -> Option<Layout> {
        self.metadata.warm_layout
    }

    /// The warm bootstrap's step: adopts the helpers' terminals, then runs the read, dispatches the conversions the
    /// pool reserves, or runs the marks, the hold, one install or publication tick, or the commit; then folds the pool's
    /// high-water into the report's helper peaks.
    pub(super) fn warm_step(&mut self) {
        self.warm_stage_step();
        self.record_helper_peaks();
    }

    /// Installs a pool under `limits` and the next attempt tag, after the report took the peaks of the pool it
    /// replaces, which drops; a failed start keeps the current pool.
    pub(super) fn start_helpers(
        &mut self,
        limits: super::helpers::RecoveryLimits,
    ) -> std::io::Result<()> {
        self.record_helper_peaks();
        self.metadata.attempts += 1;
        let helpers = super::helpers::Helpers::start(limits, self.metadata.attempts)?;
        self.metadata.helpers = Some(helpers);
        Ok(())
    }

    /// Folds the current pool's high-water into the report's helper peaks, so a reservation of any stage counts.
    pub(super) fn record_helper_peaks(&mut self) {
        if let Some((jobs, held)) =
            (self.metadata.helpers.as_ref()).map(super::helpers::Helpers::peak)
        {
            self.recovery.record_peaks((jobs, held.input, held.output));
        }
    }

    fn warm_stage_step(&mut self) {
        if self.metadata.reading.is_some() {
            self.poll_helpers();
            return self.read_step();
        }
        let Some(stage) = self.metadata.warm.as_ref().map(|warm| warm.stage) else {
            return;
        };
        match stage {
            Stage::Convert => {
                self.dispatch_conversions();
                self.poll_helpers();
            }
            Stage::Mark => self.mark(),
            Stage::Hold => self.hold(),
            Stage::Install => self.install(),
            Stage::Publish => self.publish(),
            Stage::Commit => self.commit(),
            Stage::Done => {}
        }
    }

    fn dispatch_conversions(&mut self) {
        let (record, max_units, local) = (self.storage.record, self.max_units, self.storage.clock);
        let writer = self.authority.session().get();
        let (Some(warm), Some(helpers)) =
            (self.metadata.warm.as_mut(), self.metadata.helpers.as_mut())
        else {
            return;
        };
        while let Some((destination, chunks)) = (!warm.queued.is_empty()
            && helpers.reserve(Charge::default()))
        .then(|| warm.queued.pop())
        .flatten()
        {
            #[cfg(test)]
            if PANIC.with(std::cell::Cell::get) {
                warm.converting += usize::from(helpers.dispatch(Charge::default(), Job::Panic));
                continue;
            }
            let coverage = match warm.queued.is_empty() {
                true => warm.coverage.take(),
                false => warm.coverage.clone(),
            }
            .expect("the attempt holds the coverage until its last queued piece is dispatched");
            let job = Convert {
                destination,
                chunks,
                split: warm.split,
                coverage,
                contracts: (warm.contracts, local),
                sample: warm.sample,
                record,
                max_units: u64::from(max_units),
                writer,
            };
            warm.converting +=
                usize::from(helpers.dispatch(Charge::default(), Job::Restore(Box::new(job))));
        }
    }

    /// Adopts one conversion piece; once every piece landed, the marks follow.
    fn converted(&mut self, converted: Converted) {
        if let Some(refusal) = converted.refusal {
            // The adoption released this job's slot, so the refused output frees on a helper before the pool cancels.
            if let Some(helpers) = self.metadata.helpers.as_mut()
                && helpers.reserve(Charge::default())
            {
                helpers.dispatch(Charge::default(), Job::Free(vec![converted], Vec::new()));
            }
            return self.end(refusal);
        }
        let Some(warm) = self.metadata.warm.as_mut() else {
            return;
        };
        warm.converting -= 1;
        (warm.units, warm.payload) = (
            warm.units + converted.units,
            warm.payload + converted.payload,
        );
        warm.omitted += converted.omitted;
        warm.converted.push(converted);
        if warm.queued.is_empty() && warm.converting == 0 {
            warm.stage = Stage::Mark;
            self.recovery.warm_converted(warm.omitted);
        }
    }

    /// Refuses `Limits` when a destination's restored entries outnumber its index shard's visible limit, then runs the
    /// collision check and the marks in one [`spread`] of a share per lane: share `k` groups the pairs of destinations
    /// `k`, `k + lanes` and so on ([`destination_pairs`]) and marks the restored extents of band `k` in the held
    /// bitmap, writing only its band's words and spilling the bits an extent sets past them, which the holder then
    /// marks ([`overlapped`]). A lane with a destination or an extent gets a scoped worker, and the owner runs every
    /// other lane's share. The attempt ends with the first of these that holds: `MetadataFailed` when a share panicked
    /// or the OS refused to start its worker, `Collided` when two restored keys of one destination share a fingerprint,
    /// and `Overlap` when two extents share a unit, each before any table write. Otherwise the stage hands the marked
    /// bitmap to the allocator's hold and keeps each destination's grouped pairs for the
    /// publication. The bitmap is the attempt's own, so no gate is held.
    fn mark(&mut self) {
        let cpus = self.storage.recovery.cpus;
        let Some(warm) = self.metadata.warm.as_mut() else {
            return;
        };
        let mut routed = vec![0; warm.destinations];
        for piece in &warm.converted {
            routed[piece.destination] += piece.placed.len() + piece.late.len();
        }
        // Destination `d` is the `d`th enabled shard, as the attach's plan sets the reader's destinations.
        let index = &warm.routing.1;
        let visible = (index.enabled().iter()).map(|on| index.shards()[on.shard.0].visible);
        if visible.zip(routed).any(|(visible, count)| count > visible) {
            return self.end(MetadataOutcome::Unloadable(LoadRefusal::Limits));
        }
        let (destinations, lanes, band) = (warm.destinations, warm.split.lanes, warm.split.band);
        let mut held = vec![0; warm.split.payload_units.div_ceil(64) as usize];
        let (converted, checked) = (&warm.converted, (&warm.routing, &warm.groups));
        let extents = |lane| (converted.iter()).flat_map(move |piece| &piece.extents[lane]);
        let mut bands: Vec<&mut [u64]> = held.chunks_mut(band).collect();
        bands.resize_with(lanes, || &mut []);
        let busy = |lane| lane < destinations || extents(lane).next().is_some();
        let results = spread(bands, busy, &cpus, |lane, words| {
            let dealt = (lane..destinations).step_by(lanes);
            let pairs = dealt.map(|destination| destination_pairs(converted, checked, destination));
            (
                pairs.collect::<Vec<_>>(),
                mark(words, lane * band, extents(lane)),
            )
        });
        let Some(results) = results.into_iter().collect::<Option<Vec<_>>>() else {
            return self.end(MetadataOutcome::MetadataFailed);
        };
        let (mut pairs, mut collided) = (vec![Vec::new(); destinations], false);
        let mut marks = Vec::with_capacity(lanes);
        for (lane, (dealt, marked)) in results.into_iter().enumerate() {
            for (k, (found, repeats)) in dealt.into_iter().enumerate() {
                (pairs[lane + k * lanes], collided) = (found, collided | repeats);
            }
            marks.push(marked);
        }
        if collided {
            return self.end(MetadataOutcome::Collided);
        }
        if overlapped(&mut held, marks) {
            return self.end(MetadataOutcome::Unloadable(LoadRefusal::Overlap));
        }
        warm.pairs = pairs;
        warm.held = held;
        warm.stage = Stage::Hold;
    }

    /// One try-locked pool-gate hold whose readiness read under the hold admits a warm stage's writes, with the pool:
    /// `None` while another holder has the gate, and once the attempt ended, a poisoned gate or a missing pool ending it
    /// `MetadataFailed` and a read other than `Loading` stopping it. Each stage ends its completed or refused hold by
    /// `release` or `poison`, so the access is dropped only by a panic under the hold, and that drop poisons the gate
    /// even in a tick made while its thread already unwinds.
    fn admitted(&mut self) -> Option<(&'s Pool, PoolAccess<'s>)> {
        let storage = self.storage;
        let Some(pool) = storage.live_pool() else {
            self.end(MetadataOutcome::MetadataFailed);
            return None;
        };
        #[cfg(test)]
        if WITHDRAW_BEFORE_GATE.with(std::cell::Cell::get) {
            let _ = storage.withdraw();
        }
        match pool.try_lock_quiet() {
            Err(GateError::Contended) => None,
            Err(GateError::Poisoned) => {
                self.end(MetadataOutcome::MetadataFailed);
                None
            }
            Ok(access) if admits(storage.readiness.state()) => {
                Some((pool, access.poison_on_unwind()))
            }
            Ok(access) => {
                access.release();
                self.stop();
                None
            }
        }
    }

    /// The hold that rebuilds the allocator over a pristine pool with exactly the restored extents held.
    fn hold(&mut self) {
        let Some((pool, mut access)) = self.admitted() else {
            return;
        };
        let Some(warm) = self.metadata.warm.as_mut() else {
            return access.release();
        };
        #[cfg(test)]
        let skipped = HOLD_SKIPS_RESTORE.with(std::cell::Cell::get);
        #[cfg(not(test))]
        let skipped = false;
        let mut tables = access.tables();
        let restored = tables.pristine()
            && (skipped
                || tables.restore_runs(
                    runs(&warm.held, warm.split.payload_units),
                    (warm.units, warm.payload),
                ));
        if restored {
            // ENDED-HOLDS: from here to the commit the storage keeps every slot this attempt installs, so its close
            // service leaves their pairs mapped.
            pool.hold_warm();
        }
        access.release();
        if !restored {
            return self.end(MetadataOutcome::MetadataFailed);
        }
        self.recovery.record_held_units(warm.units as u64);
        warm.held = Vec::new();
        warm.stage = Stage::Install;
    }

    /// One hold that installs at most [`INSTALL_RUN`] restored entries per lane, each lane that has an entry to
    /// install on its own worker over its slot range, merging its pieces' runs by slot ([`install_merged`]), with the
    /// capture lock held, then folds the lanes' shared effects and publishes the deadline bound before it releases the
    /// gate. When a share panics or the OS refuses to start a worker, the holder poisons the gate and the attempt ends
    /// `MetadataFailed`; each capture visit takes the pool gate, so the poisoned gate keeps every one from reading the
    /// unfolded membership words. A fold that panics poisons capture serialization before the panic leaves, also in a
    /// tick made while its thread already unwinds.
    fn install(&mut self) {
        let (cpus, writer) = (self.storage.recovery.cpus, self.authority.session().get());
        let Some((pool, mut access)) = self.admitted() else {
            return;
        };
        let Some(warm) = self.metadata.warm.as_mut() else {
            return access.release();
        };
        let mut capture = match pool.capture_lock() {
            Ok(capture) => capture,
            Err(GateError::Contended) => return access.release(),
            Err(GateError::Poisoned) => {
                access.release();
                return self.end(MetadataOutcome::MetadataFailed);
            }
        };
        // A pass started before the attach took a `t0` below every restored slot's step, so its cut names none of them.
        capture.abandon();
        pool.replaced();
        // The restored membership is recoverable from the named checkpoint and the suffixes over it, so every change
        // to it is recorded in the tenure's suffix or refused.
        capture.suffix.require();
        let split = warm.split;
        let runs: Vec<Vec<&[Placed]>> = (0..split.lanes)
            .map(|lane| lane_runs(&warm.converted, &warm.merges[lane], split, lane))
            .collect();
        let chunks: Vec<&[Chunk]> = (warm.converted.iter())
            .map(|converted| &converted.chunks[..])
            .collect();
        let pending = |runs: &[&[Placed]]| runs.iter().map(|run| run.len()).sum::<usize>();
        let reserve: Vec<u64> = (runs.iter())
            .map(|runs| pending(runs).min(INSTALL_RUN) as u64)
            .collect();
        let clock = pool.insert_step.load(std::sync::atomic::Ordering::Relaxed);
        if clock.checked_add(reserve.iter().sum()).is_none() {
            drop(capture);
            access.release();
            return self.end(MetadataOutcome::Unloadable(LoadRefusal::Slot));
        }
        let mut tables = access.tables();
        let lanes = tables.lanes(pool, &capture, split.lane, &reserve);
        let bounds = warm.merges.iter().map(|merge| merge.bound);
        let work = lanes.zip(runs.iter().cloned()).zip(bounds);
        let busy = |lane: usize| reserve[lane] > 0;
        let installed = spread(
            work.collect(),
            busy,
            &cpus,
            |_, ((lane, mut runs), bound)| {
                let (fold, refusal, bound) =
                    install_merged(lane, (&mut runs, &chunks), bound, writer);
                (fold, refusal, (bound, runs))
            },
        );
        let Some(installed) = installed.into_iter().collect::<Option<Vec<_>>>() else {
            // A share panicked or its worker never started; the lanes that ran left tables no fold completed.
            drop(capture);
            access.poison();
            return self.end(MetadataOutcome::MetadataFailed);
        };
        let mut folds = Vec::with_capacity(installed.len());
        let (mut refusals, mut places) = (Vec::new(), Vec::with_capacity(installed.len()));
        let mut spent = true;
        for ((fold, refusal, (bound, left)), runs) in installed.into_iter().zip(&runs) {
            folds.push(fold);
            refusals.extend(refusal);
            spent &= left.iter().all(|run| run.is_empty());
            let taken = runs
                .iter()
                .zip(left)
                .map(|(run, left)| run.len() - left.len());
            places.push((bound, taken.collect::<Vec<_>>()));
        }
        let installed: usize = folds.iter().map(|fold| fold.installed).sum();
        // A panic in the fold found the tables malformed, and the fold's unwind poisons the capture, also in a tick
        // made while its thread already unwinds.
        let walk = PoisonOnUnwind(&mut capture);
        let folded = tables.fold_lanes(pool, walk.0, folds);
        walk.returned();
        if folded {
            pool.publish_deadline_bound(tables.state.earliest_deadline);
        }
        drop(capture);
        access.release();
        warm.installed += installed as u64;
        for (merge, (bound, taken)) in warm.merges.iter_mut().zip(places) {
            merge.bound = bound;
            for (at, taken) in merge.taken.iter_mut().zip(taken) {
                *at += taken;
            }
        }
        if let Some(refusal) = refusals.into_iter().next() {
            return self.end(match refusal {
                RestoreRefusal::NotFree => MetadataOutcome::Unloadable(LoadRefusal::Slot),
                RestoreRefusal::Session => MetadataOutcome::MetadataFailed,
            });
        }
        if spent {
            warm.stage = Stage::Publish;
        }
    }

    /// Publishes at most [`INSTALL_RUN`] pairs of each destination into the index, one worker a destination for at
    /// most as many destinations as lanes a tick, each pair under the shard gate its fingerprint routes to; a gate
    /// another holder keeps is tried again within the tick, then left to a later one. Each tick starts one destination
    /// later than the tick before, so a destination waiting on a gate keeps no other from a worker. A worker reads
    /// the readiness word before every [`PUBLISH_RUN`] pairs.
    fn publish(&mut self) {
        let (storage, cpus) = (self.storage, self.storage.recovery.cpus);
        let Some(warm) = self.metadata.warm.as_mut() else {
            return;
        };
        let (count, first) = (warm.pairs.len(), warm.turns);
        warm.turns += 1;
        let pending = (0..count)
            .map(|k| (first + k) % count)
            .filter(|&destination| warm.published[destination] < warm.pairs[destination].len())
            .take(warm.split.lanes);
        let (destinations, work): (Vec<usize>, Vec<_>) = pending
            .map(|destination| {
                let (pairs, at) = (&warm.pairs[destination], warm.published[destination]);
                (destination, &pairs[at..pairs.len().min(at + INSTALL_RUN)])
            })
            .unzip();
        // Every destination a tick takes has pairs left, so each share holds work.
        let published = spread(
            work,
            |_| true,
            &cpus,
            |_, pairs| {
                let (mut at, mut tries) = (0, 0);
                while at < pairs.len() {
                    if !admits(storage.readiness.state()) {
                        return Err(None);
                    }
                    let end = pairs.len().min(at + PUBLISH_RUN);
                    let budget = &mut WorkBudget::new(usize::MAX);
                    match publish_restored(storage, &pairs[at..end], budget) {
                        Ok(()) => at = end,
                        Err((published, PublishError::Contended)) if tries < 64 => {
                            (at, tries) = (at + published, tries + 1);
                            std::thread::yield_now();
                        }
                        Err((published, PublishError::Contended)) => return Ok(at + published),
                        Err((_, error)) => return Err(Some(error)),
                    }
                }
                Ok(at)
            },
        );
        // A failure in any worker ends the attempt, whichever worker saw a withdrawal.
        if (published.iter()).any(|result| matches!(result, None | Some(Err(Some(_))))) {
            return self.end(MetadataOutcome::MetadataFailed);
        }
        for (destination, result) in destinations.into_iter().zip(published) {
            match result {
                Some(Ok(published)) => warm.published[destination] += published,
                _ => return self.stop(),
            }
        }
        let spent = (warm.pairs.iter().zip(&warm.published)).all(|(pairs, at)| *at == pairs.len());
        if spent {
            warm.stage = Stage::Commit;
        }
    }

    /// The readiness commit: `LoadComplete` applied while the pool gate is held, after which the volume opens under
    /// the tenure's session and the helpers free each piece's consumed chunks and places and each destination's pairs.
    fn commit(&mut self) {
        let (storage, session) = (self.storage, self.authority.session().get());
        let Some((pool, mut access)) = self.admitted() else {
            return;
        };
        let Some(warm) = self.metadata.warm.as_mut() else {
            return access.release();
        };
        // An invalidation can retire a published restored slot before the commit, and fills reserve nothing below
        // `Live`, so the resident count is at most the installed count.
        let resident = access.tables().state.ledger.resident;
        debug_assert!(
            resident <= warm.installed as usize,
            "{resident} resident of {} installed",
            warm.installed
        );
        // A withdrawal's compare-and-swap can land after the read under this hold, and the table then keeps `Withheld`.
        #[cfg(test)]
        if WITHDRAW_AT_COMMIT.with(std::cell::Cell::get) {
            let _ = storage.try_withdraw();
        }
        pool.replaced();
        let committed = storage.readiness.apply(Event::LoadComplete) == Ok(State::Loaded);
        if committed {
            pool.commit_warm();
        }
        access.release();
        if !committed {
            return self.stop();
        }
        warm.stage = Stage::Done;
        self.recovery.warm_installed(warm.installed);
        // No job is live at the commit and the attach keeps the helpers at or below the job limit, so each of the
        // helpers' free jobs reserves; the pieces and pairs a refused reservation leaves are freed here on the owner.
        if let Some(helpers) = self.metadata.helpers.as_mut() {
            let (mut converted, mut pairs) = (
                std::mem::take(&mut warm.converted),
                std::mem::take(&mut warm.pairs),
            );
            let lanes = warm.split.lanes;
            let group = |len: usize| len.div_ceil(lanes).max(1);
            let (pieces, destinations) = (group(converted.len()), group(pairs.len()));
            while !converted.is_empty() || !pairs.is_empty() {
                let rest = (
                    converted.split_off(pieces.min(converted.len())),
                    pairs.split_off(destinations.min(pairs.len())),
                );
                if helpers.reserve(Charge::default()) {
                    helpers.dispatch(Charge::default(), Job::Free(converted, pairs));
                }
                (converted, pairs) = rest;
            }
            helpers.cancel();
        }
        self.open(session);
    }
}

#[cfg(test)]
#[path = "warm_cycle_tests.rs"]
pub(crate) mod cycle_tests;
#[cfg(test)]
#[path = "warm_read_tests.rs"]
mod read_tests;
#[cfg(test)]
#[path = "warm_sim_tests.rs"]
pub(crate) mod sim_tests;
#[cfg(test)]
#[path = "suffix_sim_tests.rs"]
mod suffix_sim_tests;
#[cfg(test)]
#[path = "warm_tests.rs"]
mod tests;
