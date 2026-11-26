//! The volume owner: attach, the read entries [`Volume::read`] and [`Volume::read_key`], cancel, close, release and its reports.

use std::sync::atomic::{AtomicBool, Ordering};

use super::super::allocation::AllocationId;
use super::super::budget::WorkBudget;
use super::super::device::{
    Admission, AttachFacts, BorrowUntilDrop, Buffer, BufferArena, CommandTable, CommandToken, Disk,
    IO_UNIT, PersistenceProfile, PoolKind, QuiesceProgress, Quiesced, Refusal, Rejected,
    TableReport, Terminal, ValidDeviceGeometry, slot_of,
};
use super::super::extent::ExtentLocator;
use super::super::held::Held;
use super::super::image::PoolDescriptor;
use super::super::join::{FillFollower, JoinedReadError, Observed, Sought, SoughtError};
use super::super::lease::{ExtentLease, ReadRight, release_right};
use super::super::ledger::EngineBudget;
use super::super::lookup::LookupError;
use super::super::os::Platform;
use super::super::owner::{Pool, Storage};
use super::super::portable::{ClockReport, PhysicalClock};
use super::super::prepare::PreparedLookup;
use super::super::record::{
    Crc32c, ExpectedHeader, ExtentPosition, RecordIdentity, ValidRecordConfig,
};
use super::super::recovery::{Area, JournalWords};
use super::super::register::Registration;
use super::clock::Clock;
use super::config::{AttachError, TickConfig};
use super::metadata::{Metadata, cells};
use super::read::{
    Ahead, Aheads, Command, ControlRefusal, Extent, Grant, JoinedRefusal, KeyRead, KeyReadError,
    MAX_READ_AHEAD, RawRead, ReadOp, ReadRecord, ReadRefusal, ReadRefused, ReadSpan, ReadStatus,
    Sequence, Stage, ValidatedChunk,
};
use super::ready::SlotSet;
use super::tick::{Submission, Unsubmitted};
use super::write::WriteRecord;
use crate::index::Key;
use crate::records::Records;

const UNIT: u64 = IO_UNIT as u64;

/// Which record an outstanding command belongs to.
#[derive(Debug, Clone, Copy)]
pub(super) enum Owner {
    Read(u32),
    Write(u32),
    /// The metadata command of a cell, the root cell or the journal cell.
    Metadata(u32),
}

/// Token bindings a volume keeps, reserved at attach so recording one allocates nothing.
#[cfg(test)]
const BOUND_ROOM: usize = 1 << 14;

/// The owner a command token was bound to when the volume accepted its command: a write set with its fill's serial, or a read record's slot and generation.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bound {
    Write {
        set: super::write::WriteSet,
        serial: u64,
    },
    Read {
        slot: u32,
        generation: u64,
    },
    /// A metadata command of metadata block `block`.
    Metadata {
        block: u64,
    },
}

/// One outstanding command, keyed in the token map by its token's table slot.
#[derive(Debug, Clone, Copy)]
pub(super) struct Mapped {
    pub(super) token: CommandToken,
    pub(super) owner: Owner,
    pub(super) units: u32,
}

/// What attach's checks derived, named so no two of its counts can trade places.
struct Plan {
    read_windows: u32,
    write_max: u32,
    max_chunks: u32,
    max_units: u32,
    header_max: u32,
    write_sets: u32,
    area: Area,
    charged: EngineBudget,
    warm: Option<super::warm::Planned>,
    /// The owner's recovery I/O share, admitting the largest recovery read plus one suffix block.
    io: super::super::recovery::IoShare,
}

/// The read path's shape, as [`Volume::read_shape`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadShape {
    /// The record chunk length, which is also each read window's length.
    pub chunk_len: u32,
    /// Bytes of one read-response buffer.
    pub response_buffer_len: u32,
    /// Read-response buffers in the arena.
    pub response_buffers: u32,
    /// Read-response buffers free now.
    pub response_free: u32,
    /// The device's largest transfer.
    pub max_transfer: u32,
    /// Bytes of the largest admissible local header.
    pub header_max: u32,
    /// Read operation records: the most reads in flight at once.
    pub read_ops: u32,
    /// Commands a read may submit ahead of its current one, under the conditions [`Volume::can_read_ahead`] checks.
    pub read_ahead: u8,
    /// The most record windows one read command carries, and so the most verified window checksums one chunk has.
    pub read_windows: u32,
}

/// Counters over the volume's life. Read and write counters count commands: every submitted command whose terminal the volume applies ends as done or failed exactly once, so `submitted == done + failed + in flight` for reads and for writes.
/// The status counters count delivered `Done` events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VolumeReport {
    pub reads_submitted: u64,
    /// Each table or driver refusal increments this counter, including initial read commands and later commands submitted by grants or ticks. Each refused retry counts separately; `reads_submitted` counts accepted commands.
    pub reads_refused: u64,
    /// Read commands whose bytes arrived successfully.
    pub reads_done: u64,
    /// Read commands that failed, were quiesced or ended abandoned after a cancel or a deadline.
    pub reads_failed: u64,
    pub writes_submitted: u64,
    /// Write commands the table or its driver refused; a refused command never counts as submitted.
    pub writes_refused: u64,
    pub writes_done: u64,
    pub writes_failed: u64,
    /// Read commands that ended short; each also counts in `reads_failed`.
    pub short: u64,
    /// Counts reads with `ReadStatus::Complete`.
    pub complete: u64,
    /// Reads whose `Done` carried `Cancelled`.
    pub cancelled: u64,
    /// Reads whose `Done` carried `TimedOut`.
    pub timed_out: u64,
    /// Commands a cancel or a deadline moved into the table's quarantine over the volume's life; each stays there until its terminal or a proven stop, and the pool reports' `quarantined` counts the buffers there now.
    pub quarantines: u64,
    /// Reads whose `Done` carried a `HeaderMismatch`; `lookup_false_positives` counts the first extents' `Key` ones among them.
    pub header_mismatch: u64,
    /// Reads whose `Done` carried a `ChunkMismatch`.
    pub chunk_mismatch: u64,
    /// Bytes folded into checksums.
    pub validated_bytes: u64,
    /// Reads whose `Done` carried `HeaderMismatch(Key)` at the first extent:
    /// the record header named a key other than the lease's. The lease is on an object of a
    /// different key with an equal fingerprint, or the extent holds a stale
    /// record of another key.
    pub lookup_false_positives: u64,
    /// Reads whose first command waited for room under a kept grant, for a later tick to submit.
    pub reads_waited: u64,
    /// Read commands submitted ahead of their read's current command; each also counts in `reads_submitted`.
    pub reads_ahead: u64,
    /// Terminals whose token the volume did not map, and completions a tick's table poll matched to no command.
    pub stale: u64,
    /// Metadata commands the table accepted; the read and write counters above count payload commands only.
    pub metadata_submitted: u64,
    /// Metadata submits the table or its driver refused.
    pub metadata_refused: u64,
    /// Metadata reads whose bytes arrived and metadata writes whose terminal was `Written`.
    pub metadata_done: u64,
    /// Metadata terminals that reported `Failed`, `Quiesced` or `Abandoned`, a retried `Failed` terminal included.
    pub metadata_failed: u64,
    /// The physical-clock provider's trust state, the monotonic sample after its last trusted reading, and the publications that persisted no portable pair, by cause.
    pub clock: ClockReport,
}

/// What one [`Volume::poll_storage`] call did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Commands the tick submitted: those of kept grants spent once their command verified, and retries of grants whose submit found the pool, the table or the device queue full.
    pub submitted: u32,
    pub terminals: u32,
    pub validated_bytes: usize,
}

/// The one device volume of a [`Storage`], driven by one owner thread.
///
/// The volume borrows its storage and the integrator's buffer arena and owns the command table, the read-operation array with its chunk-table copies and its ready and waiting sets of read slots, the write-set array, the token map and a terminal scratch vector, all allocated once at attach.
/// It is the storage's one payload path: [`WritableFill::receive`](super::super::WritableFill::receive) writes a fill's record through its write sets, [`Volume::read`] reads a hit's object under its [`ExtentLease`], and [`Volume::read_key`] reads it under its lookup's right.
/// Its `_borrows` field keeps the storage and the arena borrowed until the volume drops.
///
/// A volume cannot leave its thread or be shared:
///
/// ```compile_fail,E0277
/// use kestrike::storage::{Disk, Platform, Volume};
///
/// fn requires_send<T: Send>(_: T) {}
///
/// fn send<P: Platform + Send + Sync, D: Disk + Send>(volume: Volume<'_, '_, P, D>) {
///     requires_send(volume);
/// }
/// ```
///
/// ```compile_fail,E0277
/// use kestrike::storage::{Disk, Platform, Volume};
///
/// fn requires_sync<T: Sync>(_: &T) {}
///
/// fn share<P: Platform + Send + Sync, D: Disk + Sync>(volume: &Volume<'_, '_, P, D>) {
///     requires_sync(volume);
/// }
/// ```
///
/// The storage cannot be finalized while a volume borrows it:
///
/// ```compile_fail,E0502
/// use kestrike::storage::{
///     BufferArena, Disk, EngineBudget, LinuxPlatform, PhysicalClock, Storage, TickConfig, Volume,
///     WorkBudget,
/// };
///
/// fn finalize_under_volume<D: Disk>(
///     mut storage: Storage<LinuxPlatform>,
///     arena: BufferArena<LinuxPlatform>,
///     disk: D,
///     clock: Box<dyn PhysicalClock>,
///     authority: kestrike::storage::ServingAuthority,
/// ) {
///     let tick = TickConfig { submit_burst: 1, terminal_burst: 1, validate_bytes: 1 };
///     let Ok(_volume) = Volume::attach(&storage, &arena, disk, clock, authority, 2, tick, &mut EngineBudget::new(1 << 20)) else {
///         return;
///     };
///     let _ = storage.finalize(&mut WorkBudget::new(1));
/// }
/// ```
pub struct Volume<'s, 'a, P: Platform, D: Disk> {
    /// Owner-thread window, token, joined evidence and Report custody.
    pub(super) authority: super::authority::ServingAuthority,
    pub(super) storage: &'s Storage<P>,
    /// The storage's pool descriptor, immutable for the storage's life; every read and write command takes its device range from [`PoolDescriptor::device_range`].
    pub(super) descriptor: &'s PoolDescriptor,
    pub(super) journal_words: &'s JournalWords,
    pub(super) arena: &'a BufferArena<P>,
    pub(super) table: CommandTable<'a, D>,
    pub(super) crc: Crc32c,
    /// The tenure's session the bootstrap wrote, which every payload record header this volume writes carries; zero until both RESET roots are persisted or the warm bootstrap commits allocation readiness, which writes no root.
    pub(super) session: u64,
    pub(super) metadata: Metadata<'a>,
    /// The recovery report as the attach records it.
    pub(super) recovery: super::report::Recorder,
    /// The volume's recovery I/O share, the one owner of its accounting.
    pub(super) recovery_io: super::super::recovery::IoShare,
    /// The volume's budget: exactly the warm envelope attach charged to the caller's engine budget, and empty for a cold
    /// attach. A warm bootstrap's reader estimate and install allocations are charged to it and stay charged for the
    /// volume's life.
    pub(super) budget: EngineBudget,
    pub(super) record: ValidRecordConfig,
    pub(super) tick: TickConfig,
    /// The most whole record-aligned windows one read command carries: `min(read-response buffer length, max_transfer) / chunk_len`.
    pub(super) read_windows: u32,
    /// Bytes one write command may carry: `min(receive-write buffer length, max_transfer)`.
    pub(super) write_max: u32,
    /// The most chunks a header whose lengths fill at most `max_units` units can name: each read slot's share of `crcs`.
    pub(super) max_chunks: u32,
    /// Units of the largest admissible extent; a read of a longer locator is refused.
    pub(super) max_units: u32,
    /// Bytes of the largest admissible local header.
    pub(super) header_max: u32,
    pub(super) reads: Records<ReadRecord<'a>>,
    /// Table slots reads may hold at once, `1 <= read_commands < depth`.
    pub(super) read_commands: u32,
    /// Read commands the table holds under a mapped token, from an accepted submit to its applied terminal; at most `read_commands`.
    pub(super) read_held: u32,
    /// Commands a read may submit ahead of its current one, under the conditions [`can_read_ahead`](Self::can_read_ahead) checks.
    pub(super) read_ahead: u8,
    /// The write share: table slots the fills' writes may hold whatever the metadata commands claim, `depth - read_commands - metadata_commands` minus the driver's reservation share. The writes also hold each metadata slot no metadata command claims, as [`write_room`](Self::write_room) counts.
    pub(super) write_commands: u32,
    /// Write commands charged against the write share and the unclaimed metadata slots: each from before its driver call to its applied terminal, a definite refusal, or the proven stop that fails a submit whose driver call unwound.
    pub(super) write_held: u32,
    /// Write commands whose end lowered their set's outstanding count: one for each applied terminal, and one for each submit whose driver call unwound, at the proven stop that fails it. A submit the driver refuses leaves its set's count as the call found it and adds nothing here. A set's outstanding count falls only where this rises, so while it stands every set's count is at or above the value last read.
    pub(super) write_ends: u64,
    /// The ready set contains read slots whose operations have tick work.
    /// A submit whose driver call unwound loses the volume; a tick that unwinds may leave its slot's bit set until the next tick, which visits every live record of the lost volume and clears it, and the unwound record ends at its deadline or at the first tick after the proven stop.
    pub(super) ready: SlotSet,
    /// The read slots of an open volume whose operation holds a kept grant and whose last submit was [`Submission::Busy`]: a `Stage::Next` read, outside the ready set with its deadline under `next_deadline`, or a read whose command ahead found no room, which may also be in the ready set while it verifies.
    pub(super) waiting: SlotSet,
    /// Each read slot's copy of its header's chunk table, `max_chunks` entries per slot.
    pub(super) crcs: Box<[u32]>,
    /// Each read-response buffer's row of the verified checksums of the windows its chunk spans, `read_windows` entries per buffer, written when the chunk is handed off and read through [`chunk_crcs`](Self::chunk_crcs) while the chunk lives.
    pub(super) window_crcs: Box<[u32]>,
    pub(super) writes: Records<WriteRecord<'s>>,
    /// Indexed by a token's table-slot bits; holds the full token, compared on every terminal.
    pub(super) tokens: Box<[Option<Mapped>]>,
    /// Terminals taken from the table and not yet applied, at most `terminal_burst`.
    pub(super) scratch: Vec<Terminal<'a>>,
    pub(super) report: VolumeReport,
    /// The physical-clock provider attach took, read by a publication made a millisecond or more of the monotonic clock after the latest reading's sample.
    pub(super) clock: Clock,
    pub(super) closed: bool,
    /// Sticky once the table's admission was seen `Lost` or a driver call unwound; each tick and each `close` latch it first, because a proven stop moves the table's admission from `Lost` to `Stopped`.
    pub(super) lost: bool,
    /// Set for the length of a tick and of `close`'s quiesce: an unwind through either leaves it set, which marks the volume lost.
    pub(super) armed: bool,
    /// Set once the table proved a stop and delivered every record, or `close` reported `Quiesced`: no command can touch host memory again.
    pub(super) quiesced: bool,
    /// Write submits whose driver call unwound, each still counted in its set's `outstanding` until the first tick after the proven stop with every taken terminal applied, or `release`.
    pub(super) unwound_writes: u32,
    /// Every accepted command's token and the owner it was bound to, in acceptance order, within the room reserved at attach; `bound_overflow` marks an acceptance past it.
    #[cfg(test)]
    pub(super) bound: Vec<(CommandToken, Bound)>,
    #[cfg(test)]
    pub(super) bound_overflow: bool,
    /// Every read identity the volume minted, in order, within the room reserved at attach; each is minted before its read's first fallible submit, and `minted_overflow` marks one past the room.
    #[cfg(test)]
    pub(super) minted: Vec<(u32, u64)>,
    #[cfg(test)]
    pub(super) minted_overflow: bool,
    /// A scan starts at `cursor`; each tick that serves, one with at least two spare output slots, a live read and work to do, advances `cursor` by one to rotate access to the budget, and every other tick leaves it.
    pub(super) cursor: u32,
    /// A lower bound on the deadlines of the records outside the ready set: every `Stage::Reading` record, every read waiting for a grant, every member of the waiting set and every record whose submit unwound; a tick at or past it visits every live record.
    pub(super) next_deadline: u64,
    /// Dropping the volume is a use of its storage and arena borrows.
    _borrows: (BorrowUntilDrop<'s>, BorrowUntilDrop<'a>),
}

impl<'s, 'a, P: Platform, D: Disk> Volume<'s, 'a, P, D> {
    /// Attaches the storage's one volume over `disk` with a command table of `depth` slots and starts its bootstrap.
    ///
    /// Attach derives the persistence profile from the driver's [`Disk::attach_facts`] and tiles the storage's metadata prefix in blocks of the profile's unit, every block qualifying. After a [`Storage::withdraw`](super::super::Storage::withdraw) the volume attaches `Withheld`, which suspends bootstrap command submission and keeps [`metadata_outcome`](Self::metadata_outcome) at `Bootstrapping`.
    /// The ticks authorized by the serving machine run the bootstrap ([`metadata_outcome`](Self::metadata_outcome)). It opens with the attach gate, which passes at once on the restart's fencing-boundary value an authority from [`ServingAuthority::restarted`](super::authority::ServingAuthority::restarted) carries, and otherwise, under a serving machine that holds a token, runs Register, type-2 Acquire and Report, the only commands before it, while the readiness stays `Detached`; the gate pass admits the driver's medium commands ([`Disk::admit_medium`]); a gate refusal ends the bootstrap `Unfenced` and closes admission, and a driver without reservation commands refuses `Unsupported`. After the gate passes the readiness moves to `Loading` and the ticks read root slot A, then B, and RESET both slots under the authority's [`Session`](super::super::Session), the slot without the highest root first, refusing typed when a slot is unreadable, unsupported or foreign, the slots disagree, or a valid root holds a generation at or above the session; with both slots invalid the volume waits for [`format`](Self::format).
    /// An authority carrying a [`WarmSource`](super::warm::WarmSource) runs the warm bootstrap in place of the probes:
    /// after the gate the ticks read the named slot and its suffix blocks through the metadata cells, install the load
    /// and commit readiness with no root write, and attach charges the source's warm envelope to
    /// `budget` beside the arrays.
    /// Receives refuse `Bootstrapping` until the volume opens: both RESET roots are persisted, or the warm bootstrap committed allocation readiness with no root write. Fill reservations and builder promises refuse `Bootstrapping` until the readiness reaches `Live`, which a matching [`begin_replay`](Self::begin_replay) reaches over no restored binding and [`complete_replay`](Self::complete_replay) reaches after one. Every record a fill then writes carries the session in its header, which every read checks before exposing payload bytes (IDENTITY-BEFORE-BYTES).
    ///
    /// The volume's arrays and command table's metadata share one charge. Attach allocates bounded Report scratch after validation and chooses the crc32c mechanism once.
    ///
    /// The integrator reserves the arena's receive-write pool for this volume's fills and its maintenance pool for this volume's metadata commands; attach trusts the integrator to enforce both preconditions. Under them the `ReceiveBuffersBelowFills` bound guarantees that some fill can acquire a later segment's buffer.
    ///
    /// # Errors
    ///
    /// The first failing check wins, and each refusal returns `disk` with `budget` unchanged and drops `clock`: `TornDown`, `Closed` once the storage's admission closed, `MissingKind` for the first storage kind the arena lacks, `ZeroTickField`, `Table` for the geometry, a zero depth, a depth above the device's, or an invalid reservation reserve, `VolumeExceedsDevice`, `BurstAboveDepth`, `ReadCommandsOutOfRange`, `ReadAheadOutOfRange`, `NoAttachFacts`, `Profile`, `Metadata`, `ZeroMetadataField`, `RecoveryLimits`, `MaintenanceShort`, `MetadataCommandsOutOfRange`, with a warm source `NamedSlot` and then `RecoveryLimits` for limits short of its read, `ClockScale`, `ChunkLenNotDividingBuffer`, `ReadCommandFit`, `ReceiveBuffersBelowFills`, `Envelope`, `AuthoritySession` when the machine was built from another session, `AuthorityBounds` when the machine or driver limits disagree with the serving bounds, `RecoveryLimits` when the recovery I/O share's owner part is short of the largest recovery read plus one suffix block or the share is invalid, then `AlreadyAttached`.
    #[expect(
        clippy::too_many_arguments,
        reason = "attach takes explicit clock and authority inputs with its device and budgets"
    )]
    pub fn attach(
        storage: &'s Storage<P>,
        arena: &'a BufferArena<P>,
        disk: D,
        clock: Box<dyn PhysicalClock>,
        mut authority: super::authority::ServingAuthority,
        depth: u16,
        tick: TickConfig,
        budget: &mut EngineBudget,
    ) -> Result<Self, (AttachError, D)> {
        // Every check runs before the claim, on borrowed inputs, so a refusal hands the driver back.
        let checked = || -> Result<_, AttachError> {
            if storage.root().is_none() {
                return Err(AttachError::TornDown);
            }
            if storage.is_closed() {
                return Err(AttachError::Closed);
            }
            Self::plan(
                storage, arena, &disk, &*clock, &authority, depth, tick, budget,
            )
        };
        let Plan {
            read_windows,
            write_max,
            max_chunks,
            max_units,
            header_max,
            write_sets,
            area,
            mut charged,
            warm,
            io,
        } = match checked() {
            Ok(plan) => plan,
            Err(error) => return Err((error, disk)),
        };
        if let Some(limits) = disk.reservation_limits() {
            let pair = crate::failover::evidence::Pair {
                exhid: crate::failover::identity::Exhid::new([1; 16])
                    .expect("nonzero scratch identity"),
                key: crate::failover::identity::Key::decode((1 << 32) | 1)
                    .expect("valid scratch key"),
            };
            authority.entries = vec![
                crate::failover::evidence::Registrant {
                    cntlid: 0,
                    holder: false,
                    pair
                };
                limits.registrants() as usize
            ]
            .into_boxed_slice();
            authority
                .pending
                .reserve_exact(limits.registrants() as usize);
        }
        let read_ops = storage.read_ops;
        // The relaxed swap elects a single attach through the bit's modification order.
        if storage.attached().swap(true, Ordering::Relaxed) {
            return Err((AttachError::AlreadyAttached, disk));
        }
        authority.publish(&storage.readiness);
        // The bootstrap replaces the membership, so a capture pass or proof from before the gate rose cannot publish.
        storage.pool().replaced();
        let words = storage.pool().journal_words();
        // Every check `CommandTable::new` makes passed above, and `trial` shows the budget covers its charge.
        let report_commands = disk
            .reservation_limits()
            .map_or(0, |limits| limits.commands());
        let table = CommandTable::new(disk, arena, depth, &mut charged)
            .map_err(|(error, disk)| (AttachError::Table(error), disk))?;
        *budget = charged;
        let mut metadata = Metadata::new(
            area,
            storage.metadata_retries,
            cells(storage.metadata_commands),
        );
        metadata.warm_source =
            (authority.warm.take().zip(warm)).map(|(source, plan)| Box::new((*source, plan)));
        Ok(Self {
            authority,
            storage,
            descriptor: storage.pool().descriptor(),
            journal_words: words,
            arena,
            table,
            crc: Crc32c::detect(),
            session: 0,
            recovery: super::report::Recorder::default(),
            recovery_io: io,
            budget: EngineBudget::new(warm.map_or(0, |plan| plan.envelope)),
            metadata,
            record: storage.record,
            tick,
            read_windows,
            write_max,
            max_chunks,
            max_units,
            header_max,
            reads: Records::new(read_ops),
            read_commands: storage.read_commands,
            read_held: 0,
            read_ahead: storage.read_ahead,
            write_commands: u32::from(depth)
                - storage.read_commands
                - storage.metadata_commands
                - report_commands,
            write_held: 0,
            write_ends: 0,
            ready: SlotSet::new(read_ops),
            waiting: SlotSet::new(read_ops),
            crcs: vec![0; read_ops as usize * max_chunks as usize].into_boxed_slice(),
            window_crcs: vec![
                0;
                arena.config().pool(PoolKind::ReadResponse).count as usize
                    * read_windows as usize
            ]
            .into_boxed_slice(),
            writes: Records::new(write_sets),
            tokens: vec![None; usize::from(depth)].into_boxed_slice(),
            scratch: Vec::with_capacity(tick.terminal_burst as usize),
            report: VolumeReport::default(),
            clock: Clock::new(clock),
            closed: false,
            lost: false,
            armed: false,
            quiesced: false,
            unwound_writes: 0,
            #[cfg(test)]
            bound: Vec::with_capacity(BOUND_ROOM),
            #[cfg(test)]
            bound_overflow: false,
            #[cfg(test)]
            minted: Vec::with_capacity(BOUND_ROOM),
            #[cfg(test)]
            minted_overflow: false,
            cursor: 0,
            next_deadline: u64::MAX,
            _borrows: (BorrowUntilDrop::new(), BorrowUntilDrop::new()),
        })
    }

    /// The bytes [`attach`](Self::attach) charges for these inputs: the
    /// volume's arrays and its command table's metadata, after attach's
    /// checks that derive them.
    ///
    /// # Errors
    ///
    /// The first failing check of [`attach`](Self::attach) from `TornDown`
    /// through `ReceiveBuffersBelowFills`, `Envelope` when the volume's
    /// charge exceeds `usize::MAX`, then `AuthoritySession` when the machine was built from
    /// another session, `AuthorityBounds` when the machine or driver
    /// limits disagree with the serving bounds, and `RecoveryLimits` when
    /// the recovery I/O share's owner part is short or the share is invalid.
    pub fn attach_charge(
        storage: &'s Storage<P>,
        arena: &'a BufferArena<P>,
        disk: &D,
        clock: &dyn PhysicalClock,
        authority: &super::authority::ServingAuthority,
        depth: u16,
        tick: TickConfig,
    ) -> Result<usize, AttachError> {
        if storage.root().is_none() {
            return Err(AttachError::TornDown);
        }
        if storage.is_closed() {
            return Err(AttachError::Closed);
        }
        let plan = Self::plan(
            storage,
            arena,
            disk,
            clock,
            authority,
            depth,
            tick,
            &EngineBudget::new(usize::MAX),
        )?;
        Ok(plan.charged.used()
            + CommandTable::<D>::metadata_bytes(depth)
                .saturating_add(CommandTable::<D>::reservation_metadata_bytes(disk)))
    }

    /// Attach's checks after the teardown check, and the charges they
    /// derive, taken on a copy of `budget`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the dry-run uses the same explicit attach inputs"
    )]
    fn plan(
        storage: &'s Storage<P>,
        arena: &'a BufferArena<P>,
        disk: &D,
        clock: &dyn PhysicalClock,
        authority: &super::authority::ServingAuthority,
        depth: u16,
        tick: TickConfig,
        budget: &EngineBudget,
    ) -> Result<Plan, AttachError> {
        if let Some(kind) = PoolKind::STORAGE
            .into_iter()
            .find(|kind| arena.config().pool(*kind).count == 0)
        {
            return Err(AttachError::MissingKind(kind));
        }
        if tick.submit_burst == 0 || tick.terminal_burst == 0 || tick.validate_bytes == 0 {
            return Err(AttachError::ZeroTickField);
        }
        let geometry = CommandTable::check_driver(disk, depth).map_err(AttachError::Table)?;
        CommandTable::check_reservation_reserve(disk, arena, depth, geometry)
            .map_err(AttachError::Table)?;
        let raw_bytes = storage.pool().descriptor().geometry.volume_units() * IO_UNIT as u64;
        if raw_bytes > geometry.capacity() {
            return Err(AttachError::VolumeExceedsDevice {
                raw_bytes,
                capacity: geometry.capacity(),
            });
        }
        let burst = tick.submit_burst.max(tick.terminal_burst);
        if burst > u32::from(depth) {
            return Err(AttachError::BurstAboveDepth { burst, depth });
        }
        let (read_ops, read_commands) = (storage.read_ops, storage.read_commands);
        if read_commands == 0 || read_commands >= u32::from(depth) {
            return Err(AttachError::ReadCommandsOutOfRange {
                read_commands,
                depth,
            });
        }
        if storage.read_ahead > MAX_READ_AHEAD {
            return Err(AttachError::ReadAheadOutOfRange {
                read_ahead: storage.read_ahead,
            });
        }
        let area = Self::metadata_area(storage, arena, disk, depth)?;
        let warm = (authority.warm.as_deref())
            .map(|source| Self::warm_limits(storage, arena, geometry, source))
            .transpose()?;
        if clock.scale() != storage.clock.scale {
            return Err(AttachError::ClockScale {
                provider: clock.scale(),
                contract: storage.clock.scale,
            });
        }
        let (record, pools) = (storage.record, arena.config());
        let (chunk_len, buffer_len) = (
            record.chunk_len(),
            pools.pool(PoolKind::ReceiveWrite).buffer_len,
        );
        if !buffer_len.is_multiple_of(chunk_len) {
            return Err(AttachError::ChunkLenNotDividingBuffer {
                chunk_len,
                buffer_len,
            });
        }
        let largest = storage.pool.image.largest;
        let header_max = largest.header_bytes(0);
        let read = ReadSpan::new(
            chunk_len,
            pools.pool(PoolKind::ReadResponse).buffer_len,
            geometry.max_transfer(),
            header_max,
        );
        if !read.holds_header() {
            return Err(AttachError::ReadCommandFit {
                needed: read.needed(),
                limit: u64::from(read.limit()),
            });
        }
        // Every local header fits one write command: it fits
        // `LOCAL_HEADER_LIMIT` and is shorter than one unit, and both the
        // receive-write buffer, a multiple of the window, and the device's
        // validated largest transfer are positive unit multiples.
        let write_max = buffer_len.min(geometry.max_transfer());
        debug_assert!(header_max <= u64::from(write_max));
        // A retired buffer never returns to the free stack, so no fill takes it.
        let (buffers, needed) = (
            pools.pool(PoolKind::ReceiveWrite).count - arena.report(PoolKind::ReceiveWrite).retired,
            storage.fill_records.saturating_add(1),
        );
        if (buffers as usize) < needed {
            return Err(AttachError::ReceiveBuffersBelowFills { buffers, needed });
        }
        // One extent charges at most 64 units.
        let max_units = largest.units(0) as u32;
        // A header whose lengths fill at most `max_units` units names at
        // most the windows those units reach.
        let max_chunks = (u64::from(max_units) * UNIT).div_ceil(u64::from(chunk_len)) as u32;
        // Saturating, so a count past `u32::MAX` meets the envelope check instead of wrapping.
        let write_sets =
            u32::try_from(storage.fill_records + usize::from(depth)).unwrap_or(u32::MAX);
        let response_buffers = pools.pool(PoolKind::ReadResponse).count as usize;
        // Saturating, so a sum past `usize` meets the envelope check, which refuses it.
        let arrays = [
            Records::<ReadRecord<'a>>::metadata_bytes(read_ops),
            2usize.saturating_mul(SlotSet::metadata_bytes(read_ops)),
            (read_ops as usize)
                .saturating_mul(max_chunks as usize)
                .saturating_mul(size_of::<u32>()),
            response_buffers
                .saturating_mul(read.windows() as usize)
                .saturating_mul(size_of::<u32>()),
            Records::<WriteRecord<'s>>::metadata_bytes(write_sets),
            usize::from(depth) * size_of::<Option<Mapped>>(),
            (tick.terminal_burst as usize).saturating_mul(size_of::<Terminal<'a>>()),
            size_of_val(clock),
            size_of_val(&*authority.clock),
            disk.reservation_limits().map_or(0, |limits| {
                limits.registrants() as usize
                    * (size_of::<crate::failover::evidence::Registrant>()
                        + size_of::<(crate::failover::evidence::Pair, u64)>())
            }),
            cells(storage.metadata_commands)
                .saturating_mul(size_of::<Option<super::metadata::Command<'a>>>()),
            super::super::recovery::checkpoint::UNIT_LEN,
            storage
                .recovery
                .input_bytes
                .saturating_add(storage.recovery.output_bytes),
            (storage.recovery.helpers as usize)
                .saturating_mul(size_of::<std::thread::JoinHandle<()>>()),
            storage.index().map_or(0, |index| {
                let inventory = index.geometry.inventory();
                inventory.geometry_bytes + inventory.hash_state_bytes
            }),
        ]
        .into_iter()
        .fold(0usize, usize::saturating_add);
        let mut charged = *budget;
        charged.charge(arrays).map_err(AttachError::Envelope)?;
        // A warm read's envelope is the volume's share of the budget, which the attempt's estimates are charged to.
        let envelope = warm.map_or(0, |plan| plan.envelope);
        charged.charge(envelope).map_err(AttachError::Envelope)?;
        // Charged on a copy, so `CommandTable::new` cannot refuse its own charge after the claim.
        let mut trial = charged;
        trial
            .charge(
                CommandTable::<D>::metadata_bytes(depth)
                    .saturating_add(CommandTable::<D>::reservation_metadata_bytes(disk)),
            )
            .map_err(AttachError::Envelope)?;
        if !authority.machine.built_from(&authority.session) {
            return Err(AttachError::AuthoritySession);
        }
        if authority.bounds != authority.machine.bounds()
            || disk
                .reservation_limits()
                .is_some_and(|limits| !limits.agrees_with(&authority.bounds))
        {
            return Err(AttachError::AuthorityBounds);
        }
        let read_windows = read.windows();
        // The largest bulk charge is a warm read window or a checkpoint-unit command, which spans at most one metadata block.
        let bulk_max = warm
            .map_or(0, |plan| plan.read_len())
            .max(u64::from(area.layout().unit));
        let io = super::super::recovery::IoShare::of(storage.recovery.io, bulk_max).ok_or(
            AttachError::RecoveryLimits {
                unit: bulk_max as u32,
            },
        )?;
        Ok(Plan {
            read_windows,
            write_max,
            max_chunks,
            max_units,
            header_max: header_max as u32,
            write_sets,
            area,
            charged,
            warm,
            io,
        })
    }

    /// The plan of a warm bootstrap of `source` and the bounds it needs: the layout spans the whole metadata prefix,
    /// so every read stays in the prefix and the payload a restored locator names starts where its writer's did, and
    /// the recovery limits hold one read window's charge, one destination guard's bytes and a job for every window and
    /// destination.
    fn warm_limits(
        storage: &Storage<P>,
        arena: &BufferArena<P>,
        geometry: ValidDeviceGeometry,
        source: &super::warm::WarmSource,
    ) -> Result<super::warm::Planned, AttachError> {
        let metadata_units = storage.pool().descriptor().geometry.metadata_units();
        let layout = source.layout();
        if layout.units != metadata_units {
            return Err(AttachError::NamedSlot {
                units: layout.units,
                metadata_units,
            });
        }
        let lens = (
            arena.report(PoolKind::Maintenance).buffer_len,
            geometry.max_transfer(),
        );
        let plan =
            super::warm::Planned::of(storage, lens, source).ok_or(AttachError::RecoveryLimits {
                unit: IO_UNIT as u32,
            })?;
        let ((window, guard), recovery) = (plan.charges(), &storage.recovery);
        if recovery.input_bytes < window.input.max(guard)
            || recovery.output_bytes < window.output
            || (recovery.jobs as usize) < plan.jobs()
        {
            return Err(AttachError::RecoveryLimits {
                unit: window.input as u32,
            });
        }
        Ok(plan)
    }

    /// The metadata area attach admits: the profile `disk`'s attach facts derive, the prefix tiled in qualifying blocks of its unit, a nonzero metadata share and retry count, a maintenance pool holding `metadata_commands` buffers of at least one block, and a split leaving fills a slot.
    fn metadata_area(
        storage: &Storage<P>,
        arena: &BufferArena<P>,
        disk: &D,
        depth: u16,
    ) -> Result<Area, AttachError> {
        let facts = disk.attach_facts().ok_or(AttachError::NoAttachFacts)?;
        let profile = PersistenceProfile::derive(facts).map_err(AttachError::Profile)?;
        let metadata_units = storage.pool().descriptor().geometry.metadata_units();
        let area = Area::new(profile, metadata_units).map_err(AttachError::Metadata)?;
        let (commands, retries) = (storage.metadata_commands, storage.metadata_retries);
        if commands == 0 || retries == 0 {
            return Err(AttachError::ZeroMetadataField);
        }
        let unit = area.layout().unit;
        let recovery = &storage.recovery;
        let block = super::helpers::Charge::decode(unit as usize);
        if recovery.helpers == 0
            || recovery.helpers > recovery.jobs
            || recovery.jobs == 0
            || recovery.adopt == 0
            || recovery.input_bytes < block.input
            || recovery.output_bytes < block.output
            || recovery.cpus.is_empty()
        {
            return Err(AttachError::RecoveryLimits { unit });
        }
        let pool = arena.report(PoolKind::Maintenance);
        if pool.free < commands || pool.buffer_len < unit {
            return Err(AttachError::MaintenanceShort {
                buffers: pool.free,
                buffer_len: pool.buffer_len,
            });
        }
        let read_commands = storage.read_commands;
        let report_commands = disk
            .reservation_limits()
            .map_or(0, |limits| limits.commands());
        if u64::from(read_commands) + u64::from(commands) + u64::from(report_commands)
            >= u64::from(depth)
        {
            return Err(AttachError::MetadataCommandsOutOfRange {
                read_commands,
                metadata_commands: commands,
                reservation_commands: report_commands,
                depth,
            });
        }
        Ok(area)
    }

    /// Begins a read of the object `lease` names and submits its first command, or keeps it waiting under a kept grant when the read share, the table or the device queue is full; the command reads whole windows from the record's first byte, ending early at the record's last device block, and carries its header.
    /// Each later command waits for its own [`grant_read`](Self::grant_read), which submits it.
    ///
    /// The read consumes the lease: the layout check, the response buffer and a free operation record come first, then the lease ends into the operation, whose record takes over the lease's right on the slot while the lease's credit returns, then the record is stored and its first command submitted.
    /// A refusal before that hand-over returns the lease whole in [`ReadRefused::lease`].
    /// A first submit refused because reads hold all `read_commands` slots, the table is full or the device queue is full returns the buffer to its pool and keeps the read waiting under a kept grant, with no buffer and no table slot, for a later [`poll_storage`](Self::poll_storage) to submit; any other refused first submit frees the record, returns the buffer to its pool and releases the right.
    /// The key comes from the lease, which copied the key it was taken for, and the allocation, slot and incarnation from the lease's identity, fixed while a right is counted; the session is the slot's record generation, which `bind` sets to the volume's session and the restored install to the record's own, and the cache version is the slot's; the read predicate checks them and the header's session against the volume's session. The lengths and checksums come from the verified header.
    /// RAM matched the object by its fingerprint, so a first extent's header naming another key ends the read `Done { HeaderMismatch(Key) }` with no byte exposed and counts in [`VolumeReport::lookup_false_positives`].
    /// The operation's right keeps the object's extents and, for a sequence, its block, and is released on this thread once the operation's last command reached its terminal.
    /// The first tick with output room whose `now` is at or past `deadline` ends the read `Done { TimedOut }`, also when its command's terminal arrives in that tick; the record, buffer and right stay held until its commands' terminals.
    /// The timeout cancels the command only while the table holds it pending with admission open or lost: once `close` closed the table, or with its terminal already taken into the scratch vector, the command stays attached until that terminal ends it.
    /// A first submit whose driver call unwinds leaves the operation admitted while this call unwinds: a later tick delivers its `Done { Lost }` at the proven stop, or its `Done { TimedOut }` at its deadline, naming an operation the caller holds no handle for.
    /// The read keeps the lease's right in place of a new one, so the object's count stays within the `C + 1` the lookup's retain bound holds it to.
    ///
    /// # Errors
    ///
    /// In this order, each with the lease returned: `Lost`, `Closed` for a closed volume, one that has not passed its attach gate or an authority refusal, `ForeignLease`, `Closed` once the storage left its live phase, `Layout`, `PoolExhausted`, `OpsExhausted`; then a refusal of the first command other than a full read share, table or device queue, with the lease ended: `Lost` when it lost the volume, else `Submit` with the table's refusal.
    pub fn read(
        &mut self,
        lease: ExtentLease<'s, P>,
        deadline: u64,
    ) -> Result<ReadOp, ReadRefused<'s, P>> {
        let refuse = |refusal, lease| {
            Err(ReadRefused {
                refusal,
                lease: Some(lease),
            })
        };
        if let Err(refusal) = self.admission() {
            return refuse(refusal, lease);
        }
        if !std::ptr::eq(lease.storage(), self.storage) {
            return refuse(ReadRefusal::ForeignLease, lease);
        }
        let Some(pool) = self.storage.live_pool() else {
            return refuse(ReadRefusal::Closed, lease);
        };
        let request = Self::request(pool, lease.id(), lease.key());
        let buffer = match self.admit(&request) {
            Ok(buffer) => buffer,
            Err(refusal) => return refuse(refusal, lease),
        };
        let right = lease.into_read_right();
        self.begin(&request, buffer, deadline, Some(right))
            .map_err(|refusal| ReadRefused {
                refusal,
                lease: None,
            })
    }

    /// Looks `key` up through `registration` and begins a read of the object it finds, as [`read`](Self::read) of the lookup's lease would, with the lookup's right handed straight to the read's record.
    /// The lookup reserves only the right, under `Credit::Read`: the read's operation record, one of the volume's `read_ops`, bounds the right in place of `L`.
    /// The registration check runs first; then the lookup, with [`Registration::lookup`]'s order, charges and pinned interval, which ends before the read's checks; then [`read`](Self::read)'s checks in its order, `ForeignLease` aside, each refusal releasing the right; then the first command, which waits under a kept grant when the read share, the table or the device queue is full; any other refusal of it frees the record and releases the right.
    ///
    /// # Errors
    ///
    /// `ForeignRegistration` before any step when `registration` is another storage's; `Lookup` with the lookup's refusal, never `LeaseLimit`; then `Read` with `Lost`, `Closed`, `Layout`, `PoolExhausted` or `OpsExhausted`, then the first command's `Lost` or `Submit` for a refusal other than a full read share, table or device queue, which leaves the read waiting as under [`read`](Self::read).
    pub fn read_key(
        &mut self,
        registration: &mut Registration<'s, P>,
        key: &Key,
        retries: usize,
        budget: &mut WorkBudget,
        deadline: u64,
    ) -> Result<ReadOp, KeyReadError> {
        let prepared = PreparedLookup::scalar(self.storage, key);
        self.read_key_prepared(registration, &prepared, retries, budget, deadline)
    }

    /// [`read_key`](Self::read_key) of `prepared`'s key, its lookup starting from the route preparation derived for it when `prepared` carries one; the route chooses where the search starts, and the lookup validates and reserves as an unrouted one does.
    ///
    /// # Errors
    ///
    /// As [`read_key`](Self::read_key); `ForeignRegistration`, before any step, when `registration` or `prepared` belongs to another storage.
    pub(crate) fn read_key_prepared(
        &mut self,
        registration: &mut Registration<'s, P>,
        prepared: &PreparedLookup<'s, P>,
        retries: usize,
        budget: &mut WorkBudget,
        deadline: u64,
    ) -> Result<ReadOp, KeyReadError> {
        if !std::ptr::eq(registration.storage(), self.storage) || !prepared.is_for(self.storage) {
            return Err(KeyReadError::ForeignRegistration);
        }
        let right = registration
            .lookup_right_prepared(prepared, retries, budget)
            .map_err(KeyReadError::Lookup)?;
        self.read_right(prepared.key(), right, deadline)
            .map_err(KeyReadError::Read)
    }

    /// [`read_key_prepared`](Self::read_key_prepared), except that a lookup
    /// that proves the key missing joins the key's fill within
    /// `max_observers` followers, along the lookup's route, and returns the
    /// follower; `retries` bounds the join's gate tries as well. A visible
    /// object is read as `read_key_prepared` reads it.
    ///
    /// # Errors
    ///
    /// As [`read_key_prepared`](Self::read_key_prepared), with a miss that
    /// finds no joinable fill the lookup's `Missing` and a refused join
    /// `Join`.
    pub(crate) fn read_or_join_prepared(
        &mut self,
        registration: &mut Registration<'s, P>,
        prepared: &PreparedLookup<'s, P>,
        max_observers: u64,
        retries: usize,
        budget: &mut WorkBudget,
        deadline: u64,
    ) -> Result<KeyRead<'s, P>, KeyReadError> {
        if !std::ptr::eq(registration.storage(), self.storage) || !prepared.is_for(self.storage) {
            return Err(KeyReadError::ForeignRegistration);
        }
        let sought = registration
            .lookup_right_or_join(prepared, max_observers, retries, retries, budget)
            .map_err(|error| match error {
                SoughtError::Missing => KeyReadError::Lookup(LookupError::Missing),
                SoughtError::Lookup(error) => KeyReadError::Lookup(error),
                SoughtError::Join(error) => KeyReadError::Join(error),
            })?;
        match sought {
            Sought::Hit(right) => self
                .read_right(prepared.key(), right, deadline)
                .map(KeyRead::Started)
                .map_err(KeyReadError::Read),
            Sought::Joined(follower) => Ok(KeyRead::Joined(follower)),
        }
    }

    /// Observes `follower` under its shard gate, within `tries` attempts
    /// charged to `budget`, leaving the follower joined: `Ok` once its fill
    /// ended, or for a follower of another storage, which leaves the outcome
    /// to [`read_joined`](Self::read_joined).
    ///
    /// # Errors
    ///
    /// `Pending` while the fill has not ended, `Contended` or
    /// `BudgetExhausted` when the gate or the budget refused the
    /// observation, and `Corrupt` when the observation found the record
    /// malformed and poisoned the gate.
    pub(crate) fn joined_wait(
        &self,
        follower: &FillFollower<'s, P>,
        tries: usize,
        budget: &mut WorkBudget,
    ) -> Result<(), JoinedReadError> {
        if !std::ptr::eq(follower.storage(), self.storage) {
            return Ok(());
        }
        match follower.observe(tries, budget)? {
            Observed::Pending => Err(JoinedReadError::Pending),
            Observed::Ended(_) => Ok(()),
        }
    }

    /// Acquires the right on the version `follower`'s fill published, under
    /// `Credit::Read`, within `tries` gate attempts charged to `budget`, and
    /// begins its read as [`read_key_prepared`](Self::read_key_prepared)
    /// begins a hit's, the follower's interest ending with the acquisition.
    ///
    /// # Errors
    ///
    /// `Follower` with the follower, still joined, and its acquisition's
    /// refusal; `Read` with `ForeignLease` for another storage's follower,
    /// which detaches, or with the read's refusal after the acquisition, the
    /// right released.
    pub(crate) fn read_joined(
        &mut self,
        follower: FillFollower<'s, P>,
        tries: usize,
        budget: &mut WorkBudget,
        deadline: u64,
    ) -> Result<ReadOp, JoinedRefusal<'s, P>> {
        if !std::ptr::eq(follower.storage(), self.storage) {
            return Err(JoinedRefusal::Read(ReadRefusal::ForeignLease));
        }
        let key = *follower.key();
        let right = follower
            .acquire_right(tries, budget)
            .map_err(|(follower, error)| JoinedRefusal::Follower(follower, error))?;
        self.read_right(&key, right, deadline)
            .map_err(JoinedRefusal::Read)
    }

    /// Begins the read of `key`'s object, whose right a lookup reserved,
    /// with [`read`](Self::read)'s checks in its order, `ForeignLease`
    /// aside; a refusal releases the right.
    fn read_right(
        &mut self,
        key: &Key,
        right: ReadRight<'s, P>,
        deadline: u64,
    ) -> Result<ReadOp, ReadRefusal> {
        self.admission()?;
        let Some(pool) = self.storage.live_pool() else {
            return Err(ReadRefusal::Closed);
        };
        let request = Self::request(pool, right.id(), key);
        // `right` drops on a refusal here, releasing the lookup's right.
        let buffer = self.admit(&request)?;
        self.begin(&request, buffer, deadline, Some(right.into_id()))
    }

    /// The raw read of the object `id` names, taken for `key`; a right on `id` keeps the object's extents from returning, so the locator, an extent or a sequence handle, is the object's.
    pub(super) fn request(pool: &Pool, id: AllocationId, key: &Key) -> RawRead {
        // The columns' stores precede the publication's `Release` install, or the restored install's `Release` exchange, in one gate hold. A lookup's right comes from an `Acquire` load of the slot word that reads that write or its release sequence; a follower's comes after `fill::observe`'s `Acquire` load of the departed fill record, which pairs with the `Release` store `depart_held` makes after `bind`; the publisher's own lease follows `bind` on its thread. The held right keeps the return from clearing the columns, so relaxed loads see the slot's record generation and cache version.
        let slot = id.slot().0;
        RawRead {
            locator: pool.records()[slot].locator(),
            key: *key,
            allocation: id.record_tag(),
            session: pool.generations()[slot].load(Ordering::Relaxed),
            version: pool.versions()[slot].load(Ordering::Relaxed),
        }
    }

    /// Begins a raw read of one record and submits its first command, or keeps it waiting as [`read`](Self::read) does; the command reads whole windows from the record's first byte and carries its header; the read takes no right, so its caller keeps the extent.
    ///
    /// # Errors
    ///
    /// In this order: `Lost`, `Closed`, `Layout`, `PoolExhausted`, `OpsExhausted`, then `Lost` when the first command's refusal lost the volume, else `Submit` with the table's refusal, or `Submit(OutOfCapacity)` when its device range does not fit `u64`; a full read share, table or device queue leaves the read waiting as under [`read`](Self::read).
    #[cfg(test)]
    pub(crate) fn read_raw(
        &mut self,
        request: &RawRead,
        deadline: u64,
    ) -> Result<ReadOp, ReadRefusal> {
        self.admission()?;
        let buffer = self.admit(request)?;
        self.begin(request, buffer, deadline, None)
    }

    /// Whether the volume is lost: its table's admission is `Lost`, a tick or a `close` unwound, or either was seen before.
    ///
    /// Observing the loss through `is_lost` withdraws the storage's readiness attempt.
    pub fn is_lost(&self) -> bool {
        let lost = self.lost || self.armed || self.table.report().admission == Admission::Lost;
        if lost {
            let _ = self
                .storage
                .readiness
                .apply(super::super::readiness::Event::Withdraw);
        }
        lost
    }

    #[inline(always)]
    pub(super) fn past_gate(&self) -> Result<(), ReadRefusal> {
        if self.is_lost() {
            return Err(ReadRefusal::Lost);
        }
        if self.closed || self.metadata.fenced.is_none() {
            return Err(ReadRefusal::Closed);
        }
        Ok(())
    }

    /// Reads check loss, closure and the attach gate before the current serving token and window;
    /// an authority refusal returns `Closed` while retaining command custody.
    pub(super) fn admission(&self) -> Result<(), ReadRefusal> {
        self.past_gate()?;
        self.admit_authority(
            crate::failover::serving::Operation::Read,
            self.serving_token(),
        )
        .map(|_| ())
        .map_err(|_| ReadRefusal::Closed)
    }

    /// The layout check of a direct extent, the response buffer and then a free operation record of a read, each refused with nothing held; the buffer comes back for [`begin`](Self::begin). A sequence's extents are checked as the read reaches them; each extent its block holds has at most the largest extent's units.
    fn admit(&mut self, request: &RawRead) -> Result<Buffer<'a>, ReadRefusal> {
        let sequence = matches!(Held::decode(request.locator), Some(Held::Sequence { .. }));
        let len_units = request.locator.len_units();
        if !sequence && (len_units == 0 || len_units > self.max_units) {
            return Err(ReadRefusal::Layout);
        }
        let buffer = self
            .arena
            .acquire(PoolKind::ReadResponse)
            .map_err(|_| ReadRefusal::PoolExhausted)?;
        if !self.reads.has_free() {
            return Err(ReadRefusal::OpsExhausted);
        }
        Ok(buffer)
    }

    /// Stores the record of a read `admit` accepted, holding `right`, in the free slot `admit` confirmed, then submits its first command into `buffer`.
    /// On a live volume, a full read share, table or device queue keeps the record in the waiting set with its grant retained and its deadline covered by `next_deadline`; any other refusal frees the record and its right, and a refusal that lost the volume returns `Lost`. A driver call that unwinds loses the volume and leaves the record stored, `unmapped`, and outside the ready set until a tick reaches its deadline or the first tick after a proven stop ends the record.
    fn begin(
        &mut self,
        request: &RawRead,
        buffer: Buffer<'a>,
        deadline: u64,
        right: Option<AllocationId>,
    ) -> Result<ReadOp, ReadRefusal> {
        // A sequence's first locator comes from its block at the first command's submit; until then the extent fields are zero.
        let sequence = match Held::decode(request.locator) {
            Some(Held::Sequence { count, .. }) => Some(Sequence {
                id: right.expect("a read of a sequence holds its object's right"),
                count,
                next: None,
                locate: true,
            }),
            _ => None,
        };
        let (start_unit, end, len_units) = match sequence {
            Some(_) => (0, 0, 0),
            None => (
                request.locator.start_unit(),
                read_end(request.locator, self.table.geometry().block_size()),
                request.locator.len_units(),
            ),
        };
        // The record is stored with a zero key and the key copied into the entry, which keeps the identity out of a stack temporary.
        let record = ReadRecord {
            expected: ExpectedHeader {
                identity: RecordIdentity {
                    key: [0; 32],
                    allocation: request.allocation,
                    session: request.session,
                    version: request.version,
                },
                reader: self.session(),
                position: ExtentPosition::FIRST,
                len_units,
                lengths: None,
            },
            authority: self.serving_token(),
            deadline,
            start_unit,
            end,
            next_chunk: 0,
            layout: None,
            granted: false,
            token: None,
            unmapped: false,
            command: Command::default(),
            stage: Stage::Next,
            ahead: Aheads::new(),
            right,
            sequence,
        };
        let Ok((slot, generation)) = self.reads.insert(record) else {
            unreachable!("a free record was confirmed before the submit")
        };
        #[cfg(test)]
        if self.minted.len() < self.minted.capacity() {
            self.minted.push((slot, generation));
        } else {
            self.minted_overflow = true;
        }
        if let Some((_, record)) = self.reads.slot_mut(slot) {
            record.expected.identity.key = request.key;
        }
        match self.submit_read(slot, buffer) {
            Ok(()) => {}
            Err(unsubmitted) if !self.is_lost() && unsubmitted.waits() => {
                // The read waits for room outside the ready set, so its deadline joins the bound.
                if let Some((_, record)) = self.reads.slot_mut(slot) {
                    record.granted = true;
                    self.next_deadline = self.next_deadline.min(record.deadline);
                }
                self.waiting.set(slot, true);
                self.report.reads_waited += 1;
            }
            Err(unsubmitted) => {
                #[cfg(test)]
                if self.minted.last() == Some(&(slot, generation)) {
                    self.minted.pop();
                }
                self.free_read(slot);
                return Err(match unsubmitted {
                    Unsubmitted::Refused(refusal) if !self.is_lost() => {
                        ReadRefusal::Submit(refusal)
                    }
                    _ => ReadRefusal::Lost,
                });
            }
        }
        Ok(ReadOp { slot, generation })
    }

    /// Frees the read in `slot`, which holds no command, releasing its right with [`release_right`].
    pub(super) fn free_read(&mut self, slot: u32) {
        if let Some((_, record)) = self.reads.slot_mut(slot) {
            debug_assert!(
                !record.outstanding(),
                "a read freed with a command outstanding"
            );
            if let Some(id) = record.right {
                release_right(self.storage, id);
            }
        }
        self.reads.remove(slot);
        self.ready.set(slot, false);
        self.waiting.set(slot, false);
    }

    #[inline]
    pub(super) fn share_full(&self) -> bool {
        self.read_held >= self.read_commands
    }

    /// Records `token`'s binding, or marks the record incomplete once its reserved room is full.
    #[cfg(test)]
    pub(super) fn record_bound(&mut self, token: CommandToken, owner: Bound) {
        if self.bound.len() < self.bound.capacity() {
            self.bound.push((token, owner));
        } else {
            self.bound_overflow = true;
        }
    }

    /// Submits the next command of the read in `slot` into `buffer` and counts it; a refusal returns the buffer to its pool and leaves the record and `next_deadline` as they were.
    /// An accepted command moves the record to `Reading` with the command, its token and its end as `next_chunk`.
    /// `next_deadline` is lowered to the record's deadline before the driver call, so a call that unwinds leaves the record `unmapped` and reachable by the tick at its deadline, which ends it `TimedOut`, or by the first tick after the proven stop.
    pub(super) fn submit_read(&mut self, slot: u32, buffer: Buffer<'a>) -> Result<(), Unsubmitted> {
        self.submit_command(slot, buffer, false)
    }

    /// Submits the next command of the read in `slot` into `buffer` ahead of its current command, which stays outstanding or verifying; the command waits in the record's `ahead` until the current one hands off.
    /// Refusals behave as [`submit_read`](Self::submit_read)'s.
    pub(super) fn submit_ahead(
        &mut self,
        slot: u32,
        buffer: Buffer<'a>,
    ) -> Result<(), Unsubmitted> {
        self.submit_command(slot, buffer, true)
    }

    /// Whether the read in `slot` may submit a command ahead now: the volume reads ahead and is neither lost nor closed, the current command is outstanding or verifying with no submit of it unwinding, fewer than `read_ahead` commands are already ahead, and the record holds more to read.
    /// More to read is [`ReadRecord::plans_ahead`]: within the current extent, once its header verified, chunks at or past `next_chunk`, and before it, the extent's end past the newest command's bytes, so the next command ahead starts at that command's end window; then the next extent's commands, the furthest a command ahead reaches.
    pub(super) fn can_read_ahead(&self, slot: u32) -> bool {
        self.read_ahead > 0
            && !self.lost
            && !self.closed
            && self
                .reads
                .generation_of(slot)
                .and_then(|generation| self.reads.get(slot, generation))
                .is_some_and(|record| {
                    matches!(record.stage, Stage::Reading | Stage::Verifying(_))
                        && !record.unmapped
                        && record.ahead.len() < self.read_ahead
                        && record.plans_ahead()
                })
    }

    fn submit_command(
        &mut self,
        slot: u32,
        buffer: Buffer<'a>,
        ahead: bool,
    ) -> Result<(), Unsubmitted> {
        let authority = self
            .reads
            .generation_of(slot)
            .and_then(|generation| self.reads.get(slot, generation))
            .and_then(|record| record.authority);
        if self
            .admit_authority(crate::failover::serving::Operation::Read, authority)
            .is_err()
        {
            return Err(Refusal::Closed.into());
        }
        if self.share_full() {
            return Err(Refusal::TableFull {
                abandoned: self.table.report().abandoned,
            }
            .into());
        }
        let Some((_, record)) = self.reads.slot_mut(slot) else {
            return Err(Refusal::Closed.into());
        };
        let (chunk_len, windows) = (self.record.chunk_len(), self.read_windows);
        // Planning inside the current extent stays inline, so the command stays in registers; only a sequence's extent boundary calls out of line.
        let command = if record.plans_in_current(ahead) {
            // Every command ahead submits under `can_read_ahead`, so the current extent holds more to read.
            debug_assert!(!ahead || record.more_in_current());
            record.plan_current(ahead, chunk_len, windows)
        } else {
            let block = self.table.geometry().block_size();
            plan_in_sequence(self.storage, record, ahead, chunk_len, windows, block)
                .ok_or(Unsubmitted::Locator)?
        };
        let current = record.expected.position.index;
        let range = self
            .descriptor
            .device_range(command.start_unit, command.offset, command.len)
            .ok_or(Refusal::OutOfCapacity)?;
        debug_assert!(self.scratch.is_empty(), "terminals apply before submits");
        let bound = self.next_deadline;
        self.next_deadline = bound.min(record.deadline);
        record.unmapped = true;
        let withdrawal = super::tick::WithdrawOnUnwind(&self.storage.readiness);
        let result = self.table.submit_read(buffer, range);
        withdrawal.returned();
        record.unmapped = false;
        match result {
            Ok(token) => {
                record.granted = false;
                if record.layout.is_some() && command.extent == current {
                    record.next_chunk = command.end;
                }
                if ahead {
                    self.report.reads_ahead += 1;
                    record.ahead.push(Ahead {
                        command,
                        token: Some(token),
                        arrived: None,
                    });
                } else {
                    record.token = Some(token);
                    record.command = command;
                    record.stage = Stage::Reading;
                }
                map_token(&mut self.tokens, token, Owner::Read(slot), command.units());
                #[cfg(test)]
                if let Some(generation) = self.reads.generation_of(slot) {
                    self.record_bound(token, Bound::Read { slot, generation });
                }
                self.read_held += 1;
                self.report.reads_submitted += 1;
                Ok(())
            }
            Err(Rejected { refusal, .. }) => {
                self.next_deadline = bound;
                self.report.reads_refused += 1;
                Err(refusal.into())
            }
        }
    }

    /// Cancels a live read by moving it to `Ending(Cancelled)`; a later [`poll_storage`](Self::poll_storage) pushes that `Done`, the read's final event.
    /// A read with an outstanding command retains its record, buffer and command until that command's terminal releases them. For a read between commands, entering `Ending` immediately returns a buffer under verification to its pool, and the tick frees the record when it delivers `Done`.
    ///
    /// # Errors
    ///
    /// `Closed` after [`close`](Self::close); `Stale` if the handle names no live operation or its outcome is already decided.
    pub fn cancel_read(&mut self, op: ReadOp) -> Result<(), ControlRefusal> {
        let record = self.undecided(op)?;
        let token = record.token;
        let mut ahead = [None; MAX_READ_AHEAD as usize];
        for (slot, command) in ahead.iter_mut().zip(record.ahead.iter_mut()) {
            command.arrived = None;
            *slot = command.token;
        }
        record.granted = false;
        record.stage = Stage::Ending(ReadStatus::Cancelled);
        self.ready.set(op.slot, true);
        self.waiting.set(op.slot, false);
        self.quarantine(token);
        for token in ahead {
            self.quarantine(token);
        }
        Ok(())
    }

    /// Permits the live read `op` one more command: a read waiting for its grant submits that command in this call, as [`read`](Self::read) submits the first; on a volume that reads ahead, a read with its current command outstanding or being verified, more to read in its current or next extent and fewer than `read_ahead` commands ahead submits the next command ahead in this call, before or after its header verified; any other read keeps the grant for the tick that verifies and hands off its current command's chunks, within that tick's submit burst.
    ///
    /// [`read`](Self::read) submits a read's first command, which carries its header, or keeps it waiting under a kept grant, and every later command needs its own grant; a read waiting for one holds no buffer and no table slot and stays outside the tick's work, so the caller bounds how many response buffers each read holds.
    /// A kept grant admits one command however many grants kept it, and a cancel or the delivery of the operation's `Done` clears it, so an ended operation submits nothing more.
    /// The call returns [`Grant::Exhausted`] when submitted commands reach the end of the read's last extent; otherwise, it returns [`Grant::Merged`] if the read holds a kept grant or [`Grant::Added`] if it does not.
    /// A grant reserves nothing in the arena: the command acquires its response buffer at its submit, and a submit the pool, the read share, the table or the device queue refuses as full keeps the grant in the waiting set for a later [`poll_storage`](Self::poll_storage) to retry, a command ahead included, so a read whose command ahead found no room still submits it before its current command's terminal once room frees; any other refusal of a waiting read's command ends the read as a tick's refused submit does, `Quiesced`, `Lost` or `DeviceError`, delivered by the next tick, and any other refusal of a command ahead keeps the grant for the read's next command.
    /// A submit whose driver call unwinds leaves the read admitted and `unmapped` while this call unwinds, as a first submit's does under `read`.
    /// On a lost volume the call records the grant, and the volume's loss fences the submit.
    ///
    /// # Errors
    ///
    /// `Closed` after [`close`](Self::close); `Stale` if the handle names no live operation or its outcome is already decided.
    pub fn grant_read(&mut self, op: ReadOp) -> Result<Grant, ControlRefusal> {
        // A tick that unwound outside a submit's driver call leaves the table admitting, so the volume's own loss state fences the submit.
        let lost = self.is_lost();
        let record = self.undecided(op)?;
        if !record.more_to_read() {
            return Ok(Grant::Exhausted);
        }
        let deadline = record.deadline;
        let kept = record.granted;
        record.granted = true;
        if matches!(record.stage, Stage::Next) && !record.unmapped && !lost {
            match self.submit_next(op.slot) {
                Submission::Submitted => self.waiting.set(op.slot, false),
                // The read waits for room outside the ready set, so its deadline joins the bound.
                Submission::Busy | Submission::Deferred => {
                    self.next_deadline = self.next_deadline.min(deadline);
                    self.waiting.set(op.slot, true);
                }
                Submission::Ended => {
                    self.waiting.set(op.slot, false);
                    self.ready.set(op.slot, true);
                }
            }
        } else if !lost
            && self.can_read_ahead(op.slot)
            && let Submission::Busy | Submission::Deferred = self.submit_next_ahead(op.slot)
        {
            self.waiting.set(op.slot, true);
        }
        Ok(if kept { Grant::Merged } else { Grant::Added })
    }

    /// The record of the live read `op` whose outcome is still open, for a control call.
    ///
    /// # Errors
    ///
    /// `Closed` after [`close`](Self::close); `Stale` if the handle names no live operation or its outcome is already decided.
    fn undecided(&mut self, op: ReadOp) -> Result<&mut ReadRecord<'a>, ControlRefusal> {
        if self.closed {
            return Err(ControlRefusal::Closed);
        }
        self.reads
            .get_mut(op.slot, op.generation)
            .filter(|record| !matches!(record.stage, Stage::Ending(_) | Stage::Ended))
            .ok_or(ControlRefusal::Stale)
    }

    /// Whether the read `op`, admitted by this volume, holds no command and no record any longer, so no device transfer of it can still touch a buffer, its right or the extent.
    ///
    /// True once the handle's slot holds no record or a later generation: a record frees only after its `Done` was delivered and its last command reached its terminal, or, for a command whose submit unwound, at the first tick after the proven stop.
    /// False while the record lives, including after a delivered `Done` whose command still waits for its terminal, after a cancel or a deadline that left a command quarantined, and after a submit whose driver call unwound, which keeps the record until the proven stop.
    /// A `Done` alone therefore proves no drain.
    /// A handle from another volume names this volume's slot, so the answer is meaningful only for this volume's handles.
    pub(crate) fn read_drained(&self, op: ReadOp) -> bool {
        self.reads.get(op.slot, op.generation).is_none()
    }

    /// Counts the device reference returns that ended the last reference to a read-response buffer, wrapping; each such return increments it, so a value equal to an earlier call's shows that no read-response buffer stopped being read by a device in between, short of 2^64 returns.
    pub(crate) fn response_holds_ended(&self) -> u64 {
        self.arena.pools().holds_ended(PoolKind::ReadResponse)
    }

    /// Puts every read waiting for its next command into the ready set, once, as the volume closes; later ticks end each one `Quiesced`, or `TimedOut` past its deadline or `Lost` on a lost volume, as output room allows.
    /// A record whose submit unwound has no tick work before the proven stop and stays outside the set.
    fn wake_waiting(&mut self) {
        for slot in 0..self.reads.len() {
            if let Some((_, record)) = self.reads.slot_mut(slot)
                && record.has_work(true)
            {
                self.ready.set(slot, true);
                self.waiting.set(slot, false);
            }
        }
    }

    /// Cancels `token`'s command in the table, which quarantines its buffer until its terminal; see [`quarantine`](super::tick::quarantine).
    pub(super) fn quarantine(&mut self, token: Option<CommandToken>) {
        super::tick::quarantine(&mut self.table, &mut self.report, token);
    }

    /// Closes admission and works toward a proven quiesce; idempotent, also on a lost volume, and once `Quiesced` every later call reports `Quiesced`.
    ///
    /// The first call puts every read waiting for its next command, granted or not, into the ready set, except a record whose submit unwound, which waits for the proven stop; later ticks end each one without submitting, `Quiesced` unless its deadline passed or the volume is lost.
    ///
    /// Terminals it takes, including every outstanding command's after a proven stop, apply at the next [`poll_storage`](Self::poll_storage) whose output has two spare slots, which ends each affected operation once.
    /// A proven stop ends device access to host memory only: writes outstanding at the stop have unknown outcomes, and their sets fail when a tick applies their `Quiesced` terminals.
    /// A driver call of the quiesce that unwinds loses the volume, as one in a tick does.
    pub fn close(&mut self) -> QuiesceProgress {
        self.lost = self.is_lost();
        let _ = self
            .storage
            .readiness
            .apply(super::super::readiness::Event::Close);
        self.observe_recovery();
        self.halt_metadata();
        if !self.closed {
            self.closed = true;
            self.wake_waiting();
        }
        self.armed = true;
        let progress = self.table.quiesce(&mut self.scratch);
        self.armed = false;
        self.quiesced |= matches!(progress, QuiesceProgress::Quiesced(_));
        progress
    }

    /// Consumes the volume once [`close`](Self::close) reports `Quiesced`, dropping the table; otherwise returns it with the progress.
    ///
    /// After the proven stop every outstanding command's terminal is taken, so release applies each terminal no tick applied, fails each write set still counting a submit whose driver call unwound and releases its right, and then frees every read still live, releasing each operation's right on its slot, so every right the volume took ends with it and service and finalization see only the storage's own holders.
    /// The `Done` of an operation ended here is not delivered, so a caller that needs every `Done` polls until each operation ended before releasing.
    /// Releasing the arena stays the integrator's step, refused while any buffer is held.
    ///
    /// # Errors
    ///
    /// The volume and its quiesce progress when the device is not proven quiet.
    pub fn release(self) -> Result<Quiesced, Box<(Self, QuiesceProgress)>> {
        self.release_driver().map(|(proof, _driver)| proof)
    }

    /// [`release`](Self::release), handing back the driver. Under
    /// `Quiesced::AllReturned` the driver still runs; the integrator quiesces
    /// it to a proven stop and detaches it once the registration it reached
    /// the arena through was undone.
    ///
    /// # Errors
    ///
    /// As for [`release`](Self::release).
    pub fn release_driver(mut self) -> Result<(Quiesced, D), Box<(Self, QuiesceProgress)>> {
        let proof = match self.close() {
            QuiesceProgress::Quiesced(proof) => proof,
            progress => return Err(Box::new((self, progress))),
        };
        while let Some(terminal) = self.scratch.pop() {
            self.apply(terminal, u64::MAX);
        }
        self.fail_unwound_writes();
        for slot in 0..self.reads.len() {
            if let Some((_, record)) = self.reads.slot_mut(slot) {
                record.unmapped = false;
                self.free_read(slot);
            }
        }
        debug_assert!(
            (0..self.writes.len()).all(|slot| self
                .writes
                .slot_mut(slot)
                .is_none_or(|(_, set)| set.progress.outstanding_commands == 0)),
            "a write set outstanding after a proven stop"
        );
        let Ok(disk) = self.table.release_idle() else {
            unreachable!("a quiesced table holds no pending or abandoned record")
        };
        Ok((proof, disk))
    }

    /// The volume's driver, for a stop and teardown the driver proves itself,
    /// such as disabling its controller before its registration is undone.
    /// See [`CommandTable::disk_mut`] for driver access conditions.
    pub fn disk_mut(&mut self) -> Option<&mut D> {
        self.table.disk_mut()
    }

    /// The device and Identify data the volume's driver established at attach; see [`Disk::attach_facts`].
    pub fn attach_facts(&self) -> Option<&AttachFacts> {
        self.table.attach_facts()
    }

    /// `service_disk` runs the driver's housekeeping after the attach gate passes and while the serving machine's withdrawal cause is `None`; see [`Disk::service`].
    pub fn service_disk(&mut self) {
        if self.metadata.fenced.is_some() && self.authority.machine.cause().is_none() {
            self.table.service_disk();
        }
    }

    /// The volume's counters and its clock report, copied without a clock read.
    pub fn report(&self) -> VolumeReport {
        VolumeReport {
            clock: self.clock.report,
            ..self.report
        }
    }

    /// The volume's counters where they lie: [`Self::report`] without the clock report, which reads its default
    /// here.
    pub(crate) fn counters(&self) -> &VolumeReport {
        &self.report
    }

    /// Buffers of the arena's read-response and receive-write pools that are not free: held by reads, fills,
    /// leases or the device, quarantined, or retired.
    pub fn held_buffers(&self) -> u32 {
        let pools = self.arena.pools();
        pools.pool(PoolKind::ReadResponse).not_free()
            + pools.pool(PoolKind::ReceiveWrite).not_free()
    }

    /// The read path's shape: the record chunk, the read-response buffers, the device's largest transfer, the largest admissible local header and the operation records.
    pub(crate) fn read_shape(&self) -> ReadShape {
        let pool = self.arena.config().pool(PoolKind::ReadResponse);
        ReadShape {
            chunk_len: self.record.chunk_len(),
            response_buffer_len: pool.buffer_len,
            response_buffers: pool.count,
            response_free: self.arena.report(PoolKind::ReadResponse).free,
            max_transfer: self.table.geometry().max_transfer(),
            header_max: self.header_max,
            read_ops: self.reads.len(),
            read_ahead: self.read_ahead,
            read_windows: self.read_windows,
        }
    }

    /// The verified checksums of the windows `chunk`, a chunk this volume handed off, spans, in window order; they stay valid while the chunk lives, since its buffer returns to the pool only when it drops.
    pub fn chunk_crcs(&self, chunk: &ValidatedChunk<'a>) -> &[u32] {
        &self.window_crcs[chunk.buffer_index() * self.read_windows as usize..][..chunk.windows()]
    }

    /// The storage this volume serves.
    pub(crate) fn storage(&self) -> &'s Storage<P> {
        self.storage
    }

    /// The command table's per-slot tokens; see [`CommandTable::tokens`].
    #[cfg(test)]
    pub(crate) fn table_tokens(&self) -> Vec<(super::super::device::CommandToken, bool)> {
        self.table.tokens()
    }

    #[cfg(test)]
    pub(crate) fn table_mut(&mut self) -> &mut CommandTable<'a, D> {
        &mut self.table
    }

    pub fn table_report(&self) -> TableReport {
        self.table.report()
    }
}

/// The next command of `record`, a read of a sequence at an extent boundary, for [`Volume::submit_command`], whose device reads whole blocks of `block` bytes: the current extent's locator is read from the sequence's block first while `sequence.locate` is set, and a command ahead past the current extent's last command plans into the next extent, whose locator the first such command reads and [`Sequence::next`] keeps. `None` while the pool gate is busy or poisoned, or once the storage left its live phase.
///
/// `#[inline(never)]` keeps the boundary planning out of `submit_command`'s body; [`ReadRecord::plans_in_current`] sends every other command to [`ReadRecord::plan_current`] inline.
#[inline(never)]
fn plan_in_sequence<P: Platform>(
    storage: &Storage<P>,
    record: &mut ReadRecord<'_>,
    ahead: bool,
    chunk_len: u32,
    windows: u32,
    block: u32,
) -> Option<Command> {
    let current = record.expected.position.index;
    let Some(sequence) = record.sequence.as_mut() else {
        unreachable!("only a sequence read plans in its sequence")
    };
    if sequence.locate {
        let locator = locate(storage, sequence.id, current)?;
        sequence.locate = false;
        record.set_extent(Extent::of(locator, block));
    }
    let newest = *record.newest();
    if !ahead || (newest.extent == current && record.more_in_current()) {
        return Some(record.plan_current(ahead, chunk_len, windows));
    }
    let Some(sequence) = record.sequence.as_mut() else {
        unreachable!("only a sequence read plans in its sequence")
    };
    if newest.extent == current {
        let next = match sequence.next {
            Some(next) => next,
            None => {
                let next = Extent::of(locate(storage, sequence.id, current + 1)?, block);
                sequence.next = Some(next);
                next
            }
        };
        let mut command = Command::plan(chunk_len, None, 0, next.end, windows);
        command.extent = current + 1;
        command.start_unit = next.start_unit;
        return Some(command);
    }
    // A later command of the next extent.
    let Some(next) = sequence.next else {
        unreachable!("a command ahead in the next extent planned it")
    };
    Some(newest.following(chunk_len, next.end, windows))
}

/// The locator of extent `index` of the sequence `id` holds, or `None` while the pool gate is busy or poisoned, or once the storage left its live phase.
fn locate<P: Platform>(
    storage: &Storage<P>,
    id: AllocationId,
    index: u32,
) -> Option<ExtentLocator> {
    storage.live_pool()?.sequence_extent(id, index)
}

/// Bytes from the record's start a read of `locator`'s extent covers: the record's end rounded up to the device's `block` size, within the extent's units.
pub(super) fn read_end(locator: ExtentLocator, block: u32) -> u64 {
    let units = u64::from(locator.len_units()) * UNIT;
    locator
        .record_end()
        .next_multiple_of(u64::from(block))
        .min(units)
}

/// Records `token`'s owner in the map at its table slot.
///
/// The slot holds no live entry: the table reuses a slot only after delivering its terminal, and every tick applies each terminal it took before any submit, so the scratch vector is empty whenever the volume submits.
pub(super) fn map_token(
    tokens: &mut [Option<Mapped>],
    token: CommandToken,
    owner: Owner,
    units: u32,
) {
    let entry = &mut tokens[usize::from(slot_of(token))];
    debug_assert!(entry.is_none(), "one live token per table slot");
    *entry = Some(Mapped {
        token,
        owner,
        units,
    });
}

impl<P: Platform> Storage<P> {
    /// The volume attach bit, set once by the attach and never cleared. Precondition: `is_live()`.
    fn attached(&self) -> &AtomicBool {
        debug_assert!(self.is_live());
        // SAFETY: the root mapping is owned and the bit was initialized before the owner existed; atomics need no exclusion.
        unsafe { &self.root_image.attached.as_slice(&self.root)[0] }
    }

    /// Whether a volume attach has claimed this live storage; false once finalization starts, without touching the released root mapping. The attach sets the bit once, and it stays set while the storage is live.
    ///
    /// The load is relaxed because the attach's swap publishes the bit alone, and its readers in service and the allocation return combine it with the slot's capture step under the pool gate. A load that races an attach can return false; that caller then returns a resident directly unless its capture step is nonzero, which still forces retirement.
    pub(in crate::storage) fn volume_attached(&self) -> bool {
        self.is_live() && self.attached().load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[path = "attach_tests.rs"]
mod tests;
