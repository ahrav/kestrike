//! The command table: the single owner of every buffer a device may touch, from submission until the command's terminal event or a proven stop.
//!
//! Invariants:
//!
//! - Safe code submits only through the table, which exposes only its [`Disk`]'s geometry and attach facts. Only [`CommandTable::release_idle`] returns the driver, after the table receives every submitted command's terminal or a proven stop ends it.
//!   Data submit checks the reservation-buffer kind, then admission, arena binding, capacity, maximum transfer, span and block alignment, followed by its slot share. Reservation submit checks admission, capability, timing and reserve availability, then payload shape and the shared checks. Each path issues a token and holds the buffer unborrowed across the driver call.
//!   An accepted command moves the buffer into the slot's record; a driver call that unwinds moves it there as a reserved command and makes admission lost.
//!   A driver refusal frees the slot and returns the same buffer, still application-owned; a table refusal issues nothing and makes no driver call (REJECT-OWNS-NOTHING).
//! - A buffer in a record has no byte access and returns only in its terminal event (TERMINAL): read-done evidence for a successful read, a written event, a failed event, `Quiesced` after a proven stop, or, once cancelled, `Abandoned` with the buffer freed inside the table.
//!   Reservation terminals retain their buffers in the table's reserve. A timed-out Report holds its slot and quarantined buffer until its late terminal or a proven stop; the late terminal carries the status and no Report bytes.
//! - Tokens put the slot in the low 16 bits and a 48-bit generation above it, and each record keeps the last token its slot issued.
//!   Every issue, a refused one included, advances the slot's generation, so no token repeats in a table's life; a slot that issued the maximum generation retires when it next frees and never issues again.
//!   A completion changes state only for an accepted or detached command with the exact token. Every other completion counts as stale and preserves custody.
//! - Poll picks at most `min(spare output capacity, depth)` completions through a scratch sink allocated once, pushes at most one event for each, and never grows the output (BOUNDED).
//! - Admission is open, closed, lost or stopped; closed and lost never reopen, stopped is final, and no submit outside open reaches the driver.
//!   Quiesce is proven when no command is pending or abandoned, or when the driver returned `Stopped` and every outstanding record has been delivered. After a stop the table never calls the driver again, except the driver-owned-data accessors `attach_facts` and `reservation_limits`, and delivers every outstanding record once from its own records.
//!   A proven quiesce ends the device's access to host memory; writes outstanding at the stop have unknown device outcomes.
//! - After every public call, `free_slots + pending + abandoned + retired = depth`, and with one table over one arena, `pending + abandoned` equals the pools' storage plus quarantined buffers and `abandoned` equals the quarantined buffers.
//! - Data submit, cancel, close and report do O(1) work; reservation buffer selection, recycling and Report lookup do O(N_resv) work. Poll handles at most min(spare, depth) terminals and one bounded pick; quiesce adds at most one driver quiesce before proven stop. The stopped drain advances its cursor past each delivered record, visiting each record once across calls. Table bookkeeping allocates nothing after construction and never waits (NO-HIT-ALLOC).
//! - Publication, extent reuse and response sending rely on one type rule: [`ReadDone`] alone presents bytes as a read result, and it covers exactly the requested length of a successful read.
//!   A failed or quiesced read returns a plain buffer with unspecified contents.
//!
//! The table borrows its arena, so the arena cannot be released while the table lives, and a table dropped with commands in flight leaves their buffers owned forever, which blocks release without unmapping.
//! The table is not `Send`, whatever its driver.

use std::fmt;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;

use super::super::ledger::{EngineBudget, EngineBudgetExceeded};
use super::super::os::Platform;
use super::arena::BufferArena;
use super::config::PoolKind;
pub use super::custody::Admission;
use super::custody::{self, Ending, Phase, SLOT_BITS, Submitted};
use super::disk::{
    CommandToken, Completion, CompletionSink, Disk, QuiesceStatus, RefusalReason, SubmitRefusal,
};
use super::geometry::{DeviceGeometryError, DeviceRange, ValidDeviceGeometry};
use super::identify::AttachFacts;
use super::pool::{Buffer, Held, Pools};
use super::reservation::ReservationCommand;
use super::status::{Classification, DeviceStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Read,
    Write,
}

/// Why a submission was refused. Data buffers return to their caller; reservation buffers stay in the table's reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Closed,
    DeviceLost,
    Stopped,
    /// The buffer came from an arena other than the table's.
    ForeignArena,
    /// The range ends past the device's usable capacity.
    OutOfCapacity,
    /// The range is longer than the device's maximum transfer.
    TooLong,
    /// The range is longer than the buffer.
    SpanTooLong,
    /// The range's length is not a multiple of the device's block size.
    Unaligned,
    /// This submission's share has no available slot or retained reservation buffer; slots in another share may remain free.
    TableFull {
        abandoned: u32,
    },
    Device(SubmitRefusal),
    /// The buffer kind conflicts with the command, or its capacity is below the reservation payload length.
    ReservationBuffer,
    /// The ordinal precedes this Report interest's not-before ordinal.
    NotBefore,
    /// The ordinal is at or below the last accepted reservation submission's ordinal.
    TickQuota,
}

/// A refused submission, with the same buffer back, application-owned, and nothing outstanding.
#[derive(Debug)]
pub struct Rejected<'a> {
    pub buffer: Buffer<'a>,
    pub refusal: Refusal,
}

/// Why a completion failed its command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Device,
    /// A certified reservation conflict or preempt abort deposes the current owner.
    Deposed,
    Short {
        transferred: u32,
    },
}

/// Evidence that the device wrote exactly the requested length of this buffer in a successful read.
#[derive(Debug)]
pub struct ReadDone<'a> {
    buffer: Buffer<'a>,
    len: u32,
}

impl<'a> ReadDone<'a> {
    /// The bytes the device wrote: exactly the requested length.
    pub fn bytes(&self) -> &[u8] {
        &self.buffer.bytes()[..self.len as usize]
    }

    pub fn read_len(&self) -> u32 {
        self.len
    }

    /// The buffer, no longer presented as a read result.
    pub fn into_buffer(self) -> Buffer<'a> {
        self.buffer
    }
}

/// The one terminal event of an accepted command.
#[derive(Debug)]
pub enum Terminal<'a> {
    /// A reservation command ended; a `status` of `None` means a proven stop. Buffers stay in the table's reserve. For a successful Report, `CommandTable::reservation_report` exposes the bytes if the driver's identity check passes, and `CommandTable::refused_report` exposes them if the check refuses the Report.
    Reservation {
        token: CommandToken,
        status: Option<DeviceStatus>,
        /// The driver's check refused a successful Report. The terminal ends command custody; `reservation_report` returns `None` for the refused Report, and the crate's `refused_report` exposes its bytes.
        report_error: Option<super::reservation::ReportError>,
    },
    Read {
        token: CommandToken,
        done: ReadDone<'a>,
        status: DeviceStatus,
    },
    Written {
        token: CommandToken,
        buffer: Buffer<'a>,
        status: DeviceStatus,
    },
    /// The command failed; for a read the buffer's contents are unspecified.
    Failed {
        token: CommandToken,
        op: Operation,
        buffer: Buffer<'a>,
        status: DeviceStatus,
        failure: Failure,
    },
    /// The device proved a stop before the command completed; nothing about its success is known.
    Quiesced {
        token: CommandToken,
        op: Operation,
        buffer: Buffer<'a>,
    },
    /// A cancelled command ended; its buffer is free again. `status` is `None` when a proven stop ended it.
    Abandoned {
        token: CommandToken,
        op: Operation,
        status: Option<DeviceStatus>,
    },
}

impl Terminal<'_> {
    pub fn token(&self) -> CommandToken {
        match self {
            Self::Reservation { token, .. }
            | Self::Read { token, .. }
            | Self::Written { token, .. }
            | Self::Failed { token, .. }
            | Self::Quiesced { token, .. }
            | Self::Abandoned { token, .. } => *token,
        }
    }
}

/// What one poll did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollReport {
    pub delivered: usize,
    /// Completions that matched no accepted or detached command in this poll.
    pub stale: usize,
}

/// Why a quiesce is or is not proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quiesced {
    /// Every accepted command reached its terminal event.
    AllReturned,
    /// The driver proved a stop and every outstanding record has been delivered.
    DeviceStopped,
}

/// Progress of [`CommandTable::quiesce`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceProgress {
    /// Commands are still outstanding and the driver proved nothing.
    Draining {
        outstanding: u32,
    },
    /// The driver proved a stop; `remaining` records still need output room to be delivered.
    Delivering {
        remaining: u32,
    },
    Quiesced(Quiesced),
    /// The driver's quiesce failed; every obligation stays.
    Unproven {
        outstanding: u32,
        code: Option<i32>,
    },
}

/// Why a table could not be built. The driver comes back unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableError {
    Geometry(DeviceGeometryError),
    ZeroDepth,
    /// The depth exceeds the device's queue depth.
    DepthExceedsDevice {
        depth: u16,
        queue_depth: u32,
    },
    Envelope(EngineBudgetExceeded),
    /// The reservation share reaches depth, its pool lacks enough free buffers or capacity, or the Report exceeds maximum transfer.
    ReservationReserve,
}

/// A table's slot counts at the moment of the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableReport {
    pub depth: u16,
    pub free_slots: u32,
    /// Attached commands the table still owns: accepted, or reserved by a submit whose driver call never returned.
    pub pending: u32,
    /// Cancelled commands whose terminal event has not come.
    pub abandoned: u32,
    /// Slots that issued the maximum generation and never issue again.
    pub retired: u32,
    /// Completions that matched no accepted or detached command, over the table's life.
    pub stale: u64,
    pub admission: Admission,
}

/// A pending command's operation, length and phase in one word, so a record is four words that a submit writes together.
/// The length is the low 32 bits, the operation is bit 32, reservation custody is bit 33, a Report timeout is bit 34, and the phase starts at bit 40.
#[derive(Clone, Copy)]
struct Shape(u64);

impl Shape {
    const OP_SHIFT: u32 = 32;
    const PHASE_SHIFT: u32 = 40;
    const RESERVATION_BIT: u64 = 1 << 33;
    const TIMED_OUT_BIT: u64 = 1 << 34;

    #[inline(always)]
    fn new(op: Operation, len: u32, phase: Phase) -> Self {
        Self(u64::from(len) | (op as u64) << Self::OP_SHIFT | (phase as u64) << Self::PHASE_SHIFT)
    }

    #[inline(always)]
    fn op(self) -> Operation {
        if self.0 >> Self::OP_SHIFT & 1 == 0 {
            Operation::Read
        } else {
            Operation::Write
        }
    }

    #[inline(always)]
    fn with_reservation(self, reservation: bool) -> Self {
        Self(
            self.0
                | if reservation {
                    Self::RESERVATION_BIT
                } else {
                    0
                },
        )
    }
    #[inline(always)]
    fn reservation(self) -> bool {
        self.0 & Self::RESERVATION_BIT != 0
    }
    #[inline(always)]
    fn timed_out(self) -> bool {
        self.0 & Self::TIMED_OUT_BIT != 0
    }

    fn with_timed_out(self) -> Self {
        Self(self.0 | Self::TIMED_OUT_BIT)
    }

    #[inline(always)]
    fn len(self) -> u32 {
        self.0 as u32
    }

    #[inline(always)]
    fn phase(self) -> Phase {
        match self.0 >> Self::PHASE_SHIFT {
            0 => Phase::Reserved,
            1 => Phase::Accepted,
            _ => Phase::Detached,
        }
    }

    #[inline(always)]
    fn with_phase(self, phase: Phase) -> Self {
        let kept = self.0 & ((1 << Self::PHASE_SHIFT) - 1);
        Self(kept | (phase as u64) << Self::PHASE_SHIFT)
    }
}

struct ReservationSlot<'a> {
    buffer: Option<Buffer<'a>>,
    /// The successful Report whose bytes the buffer holds.
    report: Option<Snapshot>,
}

/// A successful Report's token and whether the driver's identity check refused it: [`CommandTable::reservation_report`]
/// exposes a passed one and [`CommandTable::refused_report`] a refused one.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    token: CommandToken,
    refused: bool,
}

struct Command<'a> {
    buffer: Held<'a>,
    shape: Shape,
}

struct Record<'a> {
    /// The last token this slot issued: its generation above the slot bits, generation zero before the first issue.
    /// A completion matches the record only by carrying exactly this token.
    token: CommandToken,
    /// The pending command; `None` while the slot is free or retired.
    command: Option<Command<'a>>,
}

/// Owner of one driver and of every buffer its commands hold; see the module documentation.
///
/// An out-of-tree driver implements [`Disk`] and runs against the table through public paths only.
/// This one copies synchronously at submit and reports the completion at the next pick:
///
/// ```no_run
/// use std::collections::VecDeque;
///
/// use kestrike::storage::{
///     BufferArena, BufferConfig, CommandTable, CommandToken, Completion, CompletionSink,
///     DeviceGeometry, DeviceRange, DeviceStatus, Disk, DmaRange, EngineBudget, HugepageSize,
///     LinuxPlatform, NodeMask, PoolKind, PoolSpec, QuiesceStatus, RefusalReason, SubmitRefusal,
///     Terminal,
/// };
///
/// struct ImmediateDisk {
///     store: Vec<u8>,
///     done: VecDeque<Completion>,
/// }
///
/// impl ImmediateDisk {
///     fn run(&mut self, token: CommandToken, device: DeviceRange, memory: DmaRange, read: bool) -> Result<(), SubmitRefusal> {
///         if self.done.len() == self.done.capacity() {
///             return Err(SubmitRefusal { reason: RefusalReason::QueueFull, code: None });
///         }
///         let start = device.start() as usize;
///         let len = device.byte_len() as usize;
///         let store = &mut self.store[start..start + len];
///         // SAFETY: the table keeps `memory` exclusively for this command until its completion is picked.
///         unsafe {
///             if read {
///                 std::ptr::copy_nonoverlapping(store.as_ptr(), memory.addr().as_ptr(), len);
///             } else {
///                 std::ptr::copy_nonoverlapping(memory.addr().as_ptr(), store.as_mut_ptr(), len);
///             }
///         }
///         self.done.push_back(Completion { token, status: DeviceStatus::Kernel(len as i32) });
///         Ok(())
///     }
/// }
///
/// // SAFETY: a refused submit touches nothing; each accepted command copies only its range before its one completion is queued; picks stop at the sink's limit and keep the rest; nothing is ever stopped.
/// unsafe impl Disk for ImmediateDisk {
///     fn geometry(&self) -> DeviceGeometry {
///         DeviceGeometry {
///             capacity: self.store.len() as u64,
///             max_transfer: 1 << 20,
///             block_size: 4096,
///             queue_depth: self.done.capacity() as u32,
///         }
///     }
///     unsafe fn submit_read(&mut self, token: CommandToken, device: DeviceRange, memory: DmaRange) -> Result<(), SubmitRefusal> {
///         self.run(token, device, memory, true)
///     }
///     unsafe fn submit_write(&mut self, token: CommandToken, device: DeviceRange, memory: DmaRange) -> Result<(), SubmitRefusal> {
///         self.run(token, device, memory, false)
///     }
///     fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
///         while let Some(completion) = self.done.pop_front() {
///             if let Err(kept) = sink.push(completion) {
///                 self.done.push_front(kept);
///                 break;
///             }
///         }
///     }
///     fn quiesce(&mut self) -> QuiesceStatus {
///         QuiesceStatus::Pending
///     }
/// }
///
/// let pools = [
///     PoolSpec { kind: PoolKind::ReadResponse, count: 4, buffer_len: 65536 },
///     PoolSpec { kind: PoolKind::ReceiveWrite, count: 4, buffer_len: 65536 },
///     PoolSpec { kind: PoolKind::Maintenance, count: 1, buffer_len: 4096 },
/// ];
/// let config = BufferConfig {
///     hugepage: HugepageSize::TwoMiB,
///     nodes: NodeMask::from_nodes(&[0]).unwrap(),
///     pools: &pools,
/// }
/// .validate()
/// .unwrap();
/// let mut budget = EngineBudget::new(64 << 20);
/// let arena = BufferArena::initialize(&config, LinuxPlatform, &mut budget).unwrap();
/// let disk = ImmediateDisk { store: vec![0; 1 << 24], done: VecDeque::with_capacity(8) };
/// let mut table = CommandTable::new(disk, &arena, 8, &mut budget).map_err(|(error, _)| error).unwrap();
/// let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
/// let token = table.submit_read(buffer, DeviceRange::new(0, 65536).unwrap()).unwrap();
/// let mut events = Vec::with_capacity(8);
/// table.poll(&mut events);
/// assert!(matches!(&events[0], Terminal::Read { token: t, .. } if *t == token));
/// drop(events);
/// drop(table);
/// arena.release().unwrap();
/// ```
///
/// A buffer moves into the table at submit and cannot be used afterwards:
///
/// ```compile_fail,E0382
/// use kestrike::storage::{CommandTable, DeviceRange, Disk, BufferArena, LinuxPlatform, PoolKind};
///
/// fn reuse<'a, D: Disk>(table: &mut CommandTable<'a, D>, arena: &'a BufferArena<LinuxPlatform>) {
///     let buffer = arena.acquire(PoolKind::ReadResponse).unwrap();
///     let _ = table.submit_read(buffer, DeviceRange::new(0, 4096).unwrap());
///     let _ = buffer.offset();
/// }
/// ```
///
/// The arena cannot be released while a table bound to it lives:
///
/// ```compile_fail,E0505
/// use kestrike::storage::{BufferArena, CommandTable, Disk, EngineBudget, LinuxPlatform};
///
/// fn release_under_table<D: Disk>(arena: BufferArena<LinuxPlatform>, disk: D) {
///     let table = CommandTable::new(disk, &arena, 1, &mut EngineBudget::new(1 << 20)).ok();
///     let _ = arena.release();
///     drop(table);
/// }
/// ```
///
/// nor while read-done evidence lives:
///
/// ```compile_fail,E0505
/// use kestrike::storage::{BufferArena, CommandTable, Disk, EngineBudget, LinuxPlatform, Terminal};
///
/// fn release_under_evidence<D: Disk>(arena: BufferArena<LinuxPlatform>, disk: D) {
///     let Ok(mut table) = CommandTable::new(disk, &arena, 1, &mut EngineBudget::new(1 << 20)) else {
///         return;
///     };
///     let mut out = Vec::with_capacity(1);
///     table.poll(&mut out);
///     let Some(Terminal::Read { done, .. }) = out.pop() else {
///         return;
///     };
///     drop(out);
///     drop(table);
///     let _ = arena.release();
///     let _ = done.read_len();
/// }
/// ```
///
/// A table cannot leave its thread, even with a `Send` driver:
///
/// ```compile_fail,E0277
/// use kestrike::storage::{CommandTable, Disk};
///
/// fn requires_send<T: Send>(_: T) {}
///
/// fn send<D: Disk + Send>(table: CommandTable<'_, D>) {
///     requires_send(table);
/// }
/// ```
pub struct CommandTable<'a, D: Disk> {
    disk: D,
    pools: &'a Pools,
    /// Dropping the table uses its arena borrow, so the arena's release compiles only after the table drops.
    _arena_use: BorrowUntilDrop<'a>,
    geometry: ValidDeviceGeometry,
    records: Box<[Record<'a>]>,
    free: Vec<u16>,
    scratch: Vec<Completion>,
    admission: Admission,
    /// Detached records; the attached count is the depth less the free, released, retired and detached slots, so the conservation equation holds by construction.
    abandoned: u32,
    retired: u32,
    stale: u64,
    /// Next record the stopped drain inspects.
    drain: usize,
    /// Slots the stopped drain emptied whose last token is below the maximum generation.
    /// After a proven stop the table issues no token, so the free list keeps the entries it held at the stop and the drain counts each slot it empties here or in `retired`.
    released: u32,
    /// The reservation share accounts for slots and in-flight commands separately from the data and metadata shares.
    reservation_share: u32,
    reservation_bytes: u32,
    reservation_pending: u32,
    /// The last accepted ordinal controls reservation quota independently of data submits.
    reservation_tick: Option<u64>,
    /// Each retained buffer is application-owned here or storage-owned by one outstanding command.
    reservation_buffers: Vec<ReservationSlot<'a>>,
}

/// A submit's buffer and issued token across its driver call: the record stays free, with the slot's previous token, and the buffer application-owned until the call returns.
/// Every outcome stores the issued token in the record: acceptance with the command, refusal alone, and an unwind with the command reserved.
/// Its drop finds the buffer still inside only while a panicking driver unwinds; it then records the command reserved, with the buffer in storage custody, and makes admission lost.
struct Reservation<'t, 'a> {
    record: &'t mut Record<'a>,
    admission: &'t mut Admission,
    token: CommandToken,
    op: Operation,
    len: u32,
    buffer: Option<Buffer<'a>>,
    reservation: bool,
}

impl<'a> Reservation<'_, 'a> {
    /// Records the command the driver accepted, its buffer in storage custody until its terminal event or a proven stop.
    #[inline(always)]
    fn accept(self) {
        let mut this = ManuallyDrop::new(self);
        if let Some(buffer) = this.buffer.take() {
            this.hold(buffer, Submitted::Accepted);
        }
    }

    /// Records the command `outcome` leaves held, its buffer in storage custody, and the admission after the driver call.
    #[inline(always)]
    fn hold(&mut self, buffer: Buffer<'a>, outcome: Submitted) {
        let (phase, admission) = custody::after_submit(*self.admission, outcome);
        *self.record = Record {
            token: self.token,
            command: Some(Command {
                buffer: buffer.into_storage(),
                shape: Shape::new(self.op, self.len, phase).with_reservation(self.reservation),
            }),
        };
        *self.admission = admission;
    }

    /// The buffer of a command the driver refused, still application-owned; admission becomes what `custody::after_refusal` returns.
    #[inline(always)]
    fn refuse(self, gone: bool) -> Buffer<'a> {
        let mut this = ManuallyDrop::new(self);
        let Some(buffer) = this.buffer.take() else {
            unreachable!("a reservation holds its buffer until the driver call returns")
        };
        this.record.token = this.token;
        *this.admission = custody::after_refusal(*this.admission, gone);
        buffer
    }
}

impl Drop for Reservation<'_, '_> {
    #[inline(always)]
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.hold(buffer, Submitted::Unwound);
        }
    }
}

fn token_of(slot: u16, generation: u64) -> CommandToken {
    CommandToken::from_raw(generation << SLOT_BITS | u64::from(slot))
}

/// Records the stopped drain steps past one at a time, for one terminal, before it passes whole runs of that many.
const RUN: usize = 8;

/// The count of whole runs of [`RUN`] records at the start of `records` that hold no command.
/// Always inlined: the scan runs inside the drain's loop, which lets the compiler keep the loop's cursor and counts in registers across it.
#[inline(always)]
fn empty_runs(records: &[Record<'_>]) -> usize {
    let (runs, _) = records.as_chunks::<RUN>();
    let empty = |run: &&[Record<'_>; RUN]| run.iter().all(|record| record.command.is_none());
    runs.iter().take_while(empty).count()
}

/// The table slot a token names: its low [`SLOT_BITS`] bits.
pub(crate) fn slot_of(token: CommandToken) -> u16 {
    (token.raw() & ((1 << SLOT_BITS) - 1)) as u16
}

impl<'a, D: Disk> CommandTable<'a, D> {
    /// Combine this per-slot charge with [`reservation_metadata_bytes`](Self::reservation_metadata_bytes) when budgeting a table.
    pub fn metadata_bytes(depth: u16) -> usize {
        usize::from(depth) * (size_of::<Record<'_>>() + size_of::<u16>() + size_of::<Completion>())
    }

    pub fn reservation_metadata_bytes(disk: &D) -> usize {
        disk.reservation_limits().map_or(0, |limits| {
            limits.commands() as usize * size_of::<ReservationSlot<'_>>()
        })
    }

    /// Validates the driver's geometry, charges the table's metadata to `budget`, and allocates it once.
    /// The driver has no outstanding command: any command submitted through it before ended first, as its submit's safety contract requires, so the table's tokens are the only ones outstanding.
    ///
    /// # Errors
    ///
    /// In this order: `Geometry`, `ZeroDepth`, `DepthExceedsDevice`, `ReservationReserve`, then `Envelope`, with the driver back and `budget` unchanged. Reservation buffers are acquired only after every check and charge succeeds.
    pub fn new<P: Platform>(
        disk: D,
        arena: &'a BufferArena<P>,
        depth: u16,
        budget: &mut EngineBudget,
    ) -> Result<Self, (TableError, D)> {
        let geometry = match Self::check_driver(&disk, depth) {
            Ok(geometry) => geometry,
            Err(error) => return Err((error, disk)),
        };
        if let Err(error) = Self::check_reservation_reserve(&disk, arena, depth, geometry) {
            return Err((error, disk));
        }
        let reservation_share = disk
            .reservation_limits()
            .map_or(0, |limits| limits.commands());
        if let Err(exceeded) = budget.charge(
            Self::metadata_bytes(depth).saturating_add(Self::reservation_metadata_bytes(&disk)),
        ) {
            return Err((TableError::Envelope(exceeded), disk));
        }
        let reservation_buffers = (0..reservation_share)
            .map(|_| {
                let buffer = arena
                    .acquire(PoolKind::Reservation)
                    .expect("the reserve was checked before any arena change");
                ReservationSlot {
                    buffer: Some(buffer),
                    report: None,
                }
            })
            .collect();
        let reservation_bytes = disk
            .reservation_limits()
            .map_or(0, |limits| limits.report_bytes());
        Ok(Self {
            disk,
            pools: arena.pools(),
            _arena_use: BorrowUntilDrop::new(),
            geometry,
            records: (0..depth)
                .map(|slot| Record {
                    token: token_of(slot, 0),
                    command: None,
                })
                .collect(),
            free: (0..depth).rev().collect(),
            scratch: Vec::with_capacity(usize::from(depth)),
            admission: Admission::Open,
            abandoned: 0,
            retired: 0,
            stale: 0,
            drain: 0,
            released: 0,
            reservation_bytes,
            reservation_share,
            reservation_pending: 0,
            reservation_tick: None,
            reservation_buffers,
        })
    }

    /// The driver's validated geometry, when a table of `depth` slots fits it: the checks [`new`](Self::new) makes before charging.
    ///
    /// # Errors
    ///
    /// In this order: `Geometry`, `ZeroDepth`, then `DepthExceedsDevice`.
    pub(crate) fn check_driver(disk: &D, depth: u16) -> Result<ValidDeviceGeometry, TableError> {
        let geometry = disk.geometry().validate().map_err(TableError::Geometry)?;
        if depth == 0 {
            return Err(TableError::ZeroDepth);
        }
        let queue_depth = geometry.queue_depth();
        if u32::from(depth) > queue_depth {
            return Err(TableError::DepthExceedsDevice { depth, queue_depth });
        }
        Ok(geometry)
    }

    pub(crate) fn check_reservation_reserve<P: Platform>(
        disk: &D,
        arena: &BufferArena<P>,
        depth: u16,
        geometry: ValidDeviceGeometry,
    ) -> Result<(), TableError> {
        if let Some(limits) = disk.reservation_limits() {
            let pool = arena.report(PoolKind::Reservation);
            if limits.commands() >= u32::from(depth)
                || pool.free < limits.commands()
                || pool.buffer_len < limits.report_bytes()
                || limits.report_bytes() > geometry.max_transfer()
            {
                return Err(TableError::ReservationReserve);
            }
        }
        Ok(())
    }

    /// The driver, once admission has left `Open` and zero commands are
    /// pending or abandoned; `None` otherwise. A driver swapped in while a
    /// command is outstanding could prove a stop for it while the original
    /// device still writes its buffer, so the loan waits until every buffer's
    /// device lifetime has ended.
    pub fn disk_mut(&mut self) -> Option<&mut D> {
        (self.admission != Admission::Open && self.pending() + self.abandoned == 0)
            .then_some(&mut self.disk)
    }

    /// Forwards a gate pass, the volume's or the fresh fencer's, to the driver while the table still reaches it; see
    /// [`Disk::admit_medium`]. A stopped table forwards nothing.
    pub(crate) fn admit_medium(&mut self, gate: &crate::storage::Fenced) {
        if custody::reaches_driver(self.admission) {
            self.disk.admit_medium(gate);
        }
    }

    /// The driver, when no record of the table is pending or abandoned: every command the table issued reached its
    /// terminal event, so the driver holds no completion of this table's tokens and no command that can still touch
    /// a buffer, and a later table over the driver sees no terminal of this one (`NoPredecessorEffectAfterFB`).
    /// Admission may still be open.
    ///
    /// # Errors
    ///
    /// The table itself while a command is pending or abandoned, a timed-out Report included; the caller drains it
    /// or ends the driver through a proven stop.
    #[expect(
        clippy::result_large_err,
        reason = "a refused release hands the table back by value; boxing it would allocate on the release path"
    )]
    pub(crate) fn release_idle(self) -> Result<D, Self> {
        if self.pending() + self.abandoned == 0 {
            Ok(self.disk)
        } else {
            Err(self)
        }
    }

    pub fn geometry(&self) -> ValidDeviceGeometry {
        self.geometry
    }

    /// Attached records the table owns.
    fn pending(&self) -> u32 {
        self.records.len() as u32
            - self.free.len() as u32
            - self.released
            - self.retired
            - self.abandoned
    }

    /// Each slot's last issued token and whether the slot holds a pending or
    /// abandoned command. The report counts both; this view names their tokens.
    #[cfg(test)]
    pub(crate) fn tokens(&self) -> Vec<(CommandToken, bool)> {
        self.records
            .iter()
            .map(|record| (record.token, record.command.is_some()))
            .collect()
    }

    pub fn report(&self) -> TableReport {
        TableReport {
            depth: self.records.len() as u16,
            free_slots: self.free.len() as u32 + self.released,
            pending: self.pending(),
            abandoned: self.abandoned,
            retired: self.retired,
            stale: self.stale,
            admission: self.admission,
        }
    }

    /// Submits a read of `device` into the start of `buffer`.
    ///
    /// # Errors
    ///
    /// [`Rejected`] with the same buffer, application-owned, for the first refusal that applies, in the order the module documentation gives.
    #[inline]
    pub fn submit_read(
        &mut self,
        buffer: Buffer<'a>,
        device: DeviceRange,
    ) -> Result<CommandToken, Rejected<'a>> {
        self.submit_command(Operation::Read, buffer, device, None)
    }

    /// Submits a write of the start of `buffer` to `device`.
    ///
    /// # Errors
    ///
    /// As for [`submit_read`](Self::submit_read).
    #[inline]
    pub fn submit_write(
        &mut self,
        buffer: Buffer<'a>,
        device: DeviceRange,
    ) -> Result<CommandToken, Rejected<'a>> {
        self.submit_command(Operation::Write, buffer, device, None)
    }

    /// Submits using a table-owned reservation buffer. One submission per ordinal has quota independent of data. Report interests become eligible at their not-before ordinal.
    ///
    /// # Errors
    ///
    /// Reservation submission checks admission, capability, the not-before ordinal, quota, idle reservation buffer availability, and shared submit conditions, in that order.
    /// Accepted ordinals strictly increase. A refusal preserves quota; buffer reuse consumes any snapshot it held.
    pub fn submit_reservation(
        &mut self,
        command: ReservationCommand,
        ordinal: u64,
    ) -> Result<CommandToken, Refusal> {
        match self.admission {
            Admission::Closed => return Err(Refusal::Closed),
            Admission::Lost => return Err(Refusal::DeviceLost),
            Admission::Stopped => return Err(Refusal::Stopped),
            Admission::Open => {}
        }
        if self.reservation_share == 0 {
            return Err(Refusal::Device(SubmitRefusal {
                reason: RefusalReason::Unsupported,
                code: None,
            }));
        }
        if let ReservationCommand::Report { not_before } = command
            && ordinal < not_before
        {
            return Err(Refusal::NotBefore);
        }
        if self.reservation_tick.is_some_and(|last| ordinal <= last) {
            return Err(Refusal::TickQuota);
        }
        let index = self
            .reservation_buffers
            .iter()
            .position(|slot| slot.buffer.is_some())
            .ok_or(Refusal::TableFull {
                abandoned: self.abandoned,
            })?;
        let slot = &mut self.reservation_buffers[index];
        slot.report = None;
        let buffer = slot.buffer.take().expect("a free reservation buffer");
        match self.submit_command(
            if command.is_report() {
                Operation::Read
            } else {
                Operation::Write
            },
            buffer,
            DeviceRange::new(0, 4096).expect("one aligned block"),
            Some(command),
        ) {
            Ok(token) => {
                self.reservation_tick = Some(ordinal);
                Ok(token)
            }
            Err(rejected) => {
                self.reservation_buffers[index].buffer = Some(rejected.buffer);
                Err(rejected.refusal)
            }
        }
    }

    pub fn reservation_limits(&self) -> Option<super::reservation::ReservationLimits> {
        self.disk.reservation_limits()
    }

    /// The bytes of a successful, certified Report whose identity check passed, held until buffer reuse. A stale token or a failed, identity-refused, timed-out or quiesced Report returns `None`. Parse before the next reservation submission.
    pub fn reservation_report(&self, token: CommandToken) -> Option<&[u8]> {
        self.report_bytes(token, false)
    }

    /// The bytes of a successful, certified Report that the driver's check refused with any error, `Unchecked`
    /// included, held until buffer reuse. The caller must validate these bytes with its own parser: the same-host
    /// restart and the fresh first acquisition read them, and the takeover and the volume read through
    /// `reservation_report` alone. A stale token, a
    /// failed, timed-out or quiesced Report, and a Report whose check passed return `None`.
    pub(crate) fn refused_report(&self, token: CommandToken) -> Option<&[u8]> {
        self.report_bytes(token, true)
    }

    fn report_bytes(&self, token: CommandToken, refused: bool) -> Option<&[u8]> {
        let slot = self
            .reservation_buffers
            .iter()
            .find(|slot| slot.report == Some(Snapshot { token, refused }))?;
        Some(&slot.buffer.as_ref()?.bytes()[..self.reservation_bytes as usize])
    }

    /// Fills the reserve entry a reservation command's submit emptied, with no Report exposed, and returns that entry.
    /// An attached command's buffer returns to the entry; a detached command's quarantined buffer frees, and the entry takes the top of the reservation pool's free stack: the freed buffer, or the one under it once the freed buffer's incarnations ran out; an empty stack leaves the entry empty.
    #[cold]
    #[inline(never)]
    fn recycle<'t>(
        reserve: &'t mut [ReservationSlot<'a>],
        pools: &'a Pools,
        buffer: Held<'a>,
        ending: Ending,
    ) -> &'t mut ReservationSlot<'a> {
        let entry = reserve
            .iter_mut()
            .find(|slot| slot.buffer.is_none())
            .expect("each outstanding reservation command leaves one empty reserve entry");
        let buffer = if ending == Ending::Free {
            buffer.free(pools);
            pools.acquire(PoolKind::Reservation).ok()
        } else {
            Some(buffer.into_buffer(pools))
        };
        *entry = ReservationSlot {
            buffer,
            report: None,
        };
        entry
    }

    fn recycle_reservation(
        &mut self,
        command: Command<'a>,
        report: Option<CommandToken>,
    ) -> Option<super::reservation::ReportError> {
        let ending = custody::ending(command.shape.phase());
        let entry = Self::recycle(
            &mut self.reservation_buffers,
            self.pools,
            command.buffer,
            ending,
        );
        let report_error = report.and_then(|_| {
            self.disk
                .check_reservation_report(
                    &entry
                        .buffer
                        .as_ref()
                        .expect("a successful attached Report returns its buffer")
                        .bytes()[..self.reservation_bytes as usize],
                )
                .err()
        });
        entry.report = report.map(|token| Snapshot {
            token,
            refused: report_error.is_some(),
        });
        report_error
    }

    /// Detaches a Report at its deadline. Its certified terminal or a proven
    /// device stop ends custody; the late terminal exposes status only.
    /// Returns false for a stale token, a data command, a reservation operation other than Report, or an already timed-out Report.
    pub fn timeout_report(&mut self, token: CommandToken) -> bool {
        let pools = self.pools;
        let Some(command) = self.pending_command(token) else {
            return false;
        };
        if !command.shape.reservation()
            || command.shape.op() != Operation::Read
            || command.shape.timed_out()
        {
            return false;
        }
        command.shape = command.shape.with_timed_out();
        if command.shape.phase() == Phase::Accepted {
            command.shape = command.shape.with_phase(Phase::Detached);
            command.buffer.detach(pools);
            self.abandoned += 1;
        }
        true
    }

    fn check(&self, buffer: &Buffer<'a>, device: DeviceRange) -> Result<(), Refusal> {
        if !custody::admits_submit(self.admission) {
            return Err(match self.admission {
                Admission::Closed => Refusal::Closed,
                Admission::Lost => Refusal::DeviceLost,
                Admission::Stopped => Refusal::Stopped,
                Admission::Open => unreachable!("an open table admits a submit"),
            });
        }
        if !buffer.belongs_to(self.pools) {
            return Err(Refusal::ForeignArena);
        }
        assert!(
            !buffer.device_held(),
            "a buffer a device reads takes no device write"
        );
        if device.end() > self.geometry.capacity() {
            return Err(Refusal::OutOfCapacity);
        }
        if device.byte_len() > self.geometry.max_transfer() {
            return Err(Refusal::TooLong);
        }
        if device.byte_len() as usize > buffer.capacity() {
            return Err(Refusal::SpanTooLong);
        }
        if !device.byte_len().is_multiple_of(self.geometry.block_size()) {
            return Err(Refusal::Unaligned);
        }
        Ok(())
    }

    /// Always inlined: submit is the per-I/O hot path, and inlining it lets the caller keep the buffer and token in registers instead of passing a 32-byte result through memory around a call.
    #[inline(always)]
    fn submit_command(
        &mut self,
        op: Operation,
        buffer: Buffer<'a>,
        device: DeviceRange,
        reservation_command: Option<ReservationCommand>,
    ) -> Result<CommandToken, Rejected<'a>> {
        let reservation = reservation_command.is_some();
        let len = if let Some(command) = reservation_command {
            let Some(limits) = self.disk.reservation_limits() else {
                return Err(Rejected {
                    buffer,
                    refusal: Refusal::Device(SubmitRefusal {
                        reason: RefusalReason::Unsupported,
                        code: None,
                    }),
                });
            };
            command.len(limits)
        } else {
            device.byte_len()
        };
        if reservation
            && (buffer.kind() != PoolKind::Reservation || buffer.capacity() < len as usize)
            || !reservation && buffer.kind() == PoolKind::Reservation
        {
            return Err(Rejected {
                buffer,
                refusal: Refusal::ReservationBuffer,
            });
        }
        let check_range = if reservation {
            DeviceRange::new(0, 4096).expect("aligned check range")
        } else {
            device
        };
        if let Err(refusal) = self.check(&buffer, check_range) {
            return Err(Rejected { buffer, refusal });
        }
        let full = if reservation {
            self.reservation_pending >= self.reservation_share
        } else {
            self.free.len() as u32 + self.reservation_pending <= self.reservation_share
        };
        if full {
            return Err(Rejected {
                buffer,
                refusal: Refusal::TableFull {
                    abandoned: self.abandoned,
                },
            });
        }
        let Some(slot) = self.free.pop() else {
            let refusal = Refusal::TableFull {
                abandoned: self.abandoned,
            };
            return Err(Rejected { buffer, refusal });
        };
        let mut buffer = buffer;
        let memory = if let Some(command) = reservation_command {
            command.encode(&mut buffer.bytes_mut()[..len as usize]);
            self.reservation_pending += 1;
            let Ok(range) = buffer.range(len.next_multiple_of(super::config::SECTOR as u32)) else {
                unreachable!(
                    "the reservation-buffer check proved the payload fits, and pool buffer lengths are sector multiples"
                )
            };
            super::disk::DmaRange::new(range.addr(), range.offset(), len)
        } else {
            let Ok(memory) = buffer.range(len) else {
                unreachable!("the span check proved the range fits the buffer")
            };
            memory
        };
        let record = &mut self.records[usize::from(slot)];
        // A slot that issued the maximum generation retired when it last freed, so a free slot's next generation fits above the slot bits.
        let token = custody::next_token(record.token.raw())
            .map(CommandToken::from_raw)
            .unwrap_or_else(|| unreachable!("a free slot has not issued the maximum generation"));
        let reservation = Reservation {
            record,
            admission: &mut self.admission,
            token,
            op,
            len,
            buffer: Some(buffer),
            reservation,
        };
        // SAFETY: the buffer moved into the reservation, so every reference to its bytes ended, and it leaves only as a refused buffer, or as storage custody that only the record's terminal event or a proven stop revives.
        // The table borrows the arena for `'a`, so the backing stays mapped. Data memory has the device range's length; reservation memory has the command's validated payload length and fits the checked Reservation buffer.
        // `token` is unique among outstanding tokens: the slot's generation just advanced and never repeats, the driver came to the table with nothing outstanding (`new`), and by I9 no other value reports this driver's commands.
        // The table has exclusive submission access until `release_idle` returns the driver after every command it issued ended.
        let result = unsafe {
            match reservation_command {
                Some(command) => self.disk.submit_reservation(token, command, memory),
                None => match op {
                    Operation::Read => self.disk.submit_read(token, device, memory),
                    Operation::Write => self.disk.submit_write(token, device, memory),
                },
            }
        };
        match result {
            Ok(()) => {
                reservation.accept();
                Ok(token)
            }
            Err(refusal) => {
                let buffer = reservation.refuse(refusal.reason == RefusalReason::DeviceGone);
                self.release(slot);
                if reservation_command.is_some() {
                    self.reservation_pending -= 1;
                }
                Err(Rejected {
                    buffer,
                    refusal: Refusal::Device(refusal),
                })
            }
        }
    }

    /// Returns `slot`, whose record holds no command, to the free list, or retires it when it issued the maximum generation.
    #[inline]
    fn release(&mut self, slot: u16) {
        if custody::retires(self.records[usize::from(slot)].token.raw()) {
            self.retired += 1;
        } else {
            if self.free.len() == self.free.capacity() {
                unreachable!(
                    "a slot is on the free list at most once, so the list holds at most `depth` entries"
                )
            }
            self.free.push(slot);
        }
    }

    /// Empties `slot`'s pending record, uncounts a detached one as abandoned, and frees the slot, or retires it when it issued the maximum generation.
    #[inline]
    fn take(&mut self, slot: u16) -> Command<'a> {
        let Some(command) = self.records[usize::from(slot)].command.take() else {
            unreachable!("only a pending record is taken")
        };
        self.release(slot);
        if command.shape.reservation() {
            self.reservation_pending -= 1;
        }
        if custody::ending(command.shape.phase()) == Ending::Free {
            self.abandoned -= 1;
        }
        command
    }

    /// Cancels an attached pending command: its buffer moves to quarantine and frees at the command's terminal event or a proven stop.
    /// Cancel never frees memory and never calls the driver.
    ///
    /// # Errors
    ///
    /// `Stale` when `token` names no attached pending command, names a reserved command whose driver call never returned, or admission is closed or stopped; `custody::targets` and `custody::cancels` decide.
    /// A command left uncancelled at close still ends in its own terminal event.
    pub fn cancel(&mut self, token: CommandToken) -> Result<(), Stale> {
        let (pools, admission) = (self.pools, self.admission);
        let Some(command) = self.pending_command(token) else {
            return Err(Stale);
        };
        if !custody::cancels(admission, command.shape.phase()) {
            return Err(Stale);
        }
        command.shape = command.shape.with_phase(Phase::Detached);
        command.buffer.detach(pools);
        self.abandoned += 1;
        Ok(())
    }

    /// The accepted or detached command `token` names: its slot's record holds exactly this token.
    fn pending_command(&mut self, token: CommandToken) -> Option<&mut Command<'a>> {
        let record = self.records.get_mut(usize::from(slot_of(token)))?;
        let issued = record.token.raw();
        let command = record.command.as_mut()?;
        custody::targets(issued, command.shape.phase(), token.raw()).then_some(command)
    }

    /// Refuses every later submission. Outstanding commands still finish.
    pub fn close(&mut self) {
        self.admission = custody::close(self.admission);
    }

    /// The driver's attach facts; see [`Disk::attach_facts`]. The table answers in every admission state, including after a proven stop.
    pub fn attach_facts(&self) -> Option<&AttachFacts> {
        self.disk.attach_facts()
    }

    /// See [`Disk::service`]; a stopped table never calls its driver.
    pub fn service_disk(&mut self) {
        if custody::reaches_driver(self.admission) {
            self.disk.service();
        }
    }

    /// Delivers finished commands into `out`, within its spare capacity; see the module documentation.
    pub fn poll(&mut self, out: &mut Vec<Terminal<'a>>) -> PollReport {
        if !custody::reaches_driver(self.admission) {
            let delivered = self.deliver_stopped(out);
            return PollReport {
                delivered,
                stale: 0,
            };
        }
        let spare = out.capacity() - out.len();
        let limit = spare.min(self.records.len());
        if limit == 0 {
            return PollReport {
                delivered: 0,
                stale: 0,
            };
        }
        // The sink holds entries only after a pick that found completions, so a poll after an empty one reads the sink's length and leaves it as it is.
        if !self.scratch.is_empty() {
            self.scratch.clear();
        }
        self.disk
            .pick_completions(&mut CompletionSink::new(&mut self.scratch, limit));
        if self.scratch.is_empty() {
            return PollReport {
                delivered: 0,
                stale: 0,
            };
        }
        self.deliver(out)
    }

    /// Delivers each picked completion as a terminal, counting the stale ones.
    /// Out of line so a poll that picked nothing stays a short straight path.
    #[inline(never)]
    fn deliver(&mut self, out: &mut Vec<Terminal<'a>>) -> PollReport {
        let (mut delivered, mut stale) = (0, 0);
        for index in 0..self.scratch.len() {
            let completion = self.scratch[index];
            if self.complete(completion, out) {
                delivered += 1;
            } else {
                stale += 1;
            }
        }
        self.stale += stale as u64;
        PollReport { delivered, stale }
    }

    fn complete(&mut self, completion: Completion, out: &mut Vec<Terminal<'a>>) -> bool {
        let token = completion.token;
        let Some(command) = self.pending_command(token) else {
            return false;
        };
        if command.shape.reservation() {
            return self.complete_reservation(completion, out);
        }
        if out.len() == out.capacity() {
            unreachable!("the pick is bounded by the output's spare capacity")
        }
        let slot = slot_of(token);
        let command = self.take(slot);
        let status = completion.status;
        let (op, len) = (command.shape.op(), command.shape.len());
        if custody::ending(command.shape.phase()) == Ending::Free {
            command.buffer.free(self.pools);
            out.push(Terminal::Abandoned {
                token,
                op,
                status: Some(status),
            });
            return true;
        }
        let buffer = command.buffer.into_buffer(self.pools);
        match (status.classify(len), op) {
            (Classification::Success, Operation::Read) => out.push(Terminal::Read {
                token,
                done: ReadDone { buffer, len },
                status,
            }),
            (Classification::Success, Operation::Write) => out.push(Terminal::Written {
                token,
                buffer,
                status,
            }),
            (Classification::Short { transferred }, _) => out.push(Terminal::Failed {
                token,
                op,
                buffer,
                status,
                failure: Failure::Short { transferred },
            }),
            (Classification::Failed, _) => out.push(Terminal::Failed {
                token,
                op,
                buffer,
                status,
                failure: if status.deposes() {
                    Failure::Deposed
                } else {
                    Failure::Device
                },
            }),
        }
        true
    }

    /// `complete_reservation` delivers a reservation command's terminal and recycles its reserve buffer.
    /// A late timed-out Report terminal ends custody and exposes status only.
    /// Keeping reservation completion out of line shortens the data-terminal path.
    #[cold]
    #[inline(never)]
    fn complete_reservation(
        &mut self,
        completion: Completion,
        out: &mut Vec<Terminal<'a>>,
    ) -> bool {
        let token = completion.token;
        if self.pending_command(token).is_none() {
            return false;
        }
        if out.len() == out.capacity() {
            unreachable!("the pick is bounded by the output's spare capacity")
        }
        let command = self.take(slot_of(token));
        let status = completion.status;
        let report = (command.shape.op() == Operation::Read
            && command.shape.phase() == Phase::Accepted
            && status.classify(command.shape.len()) == Classification::Success)
            .then_some(token);
        let report_error = self.recycle_reservation(command, report);
        out.push(Terminal::Reservation {
            token,
            status: Some(status),
            report_error,
        });
        true
    }

    /// Delivers `min(spare capacity, pending + abandoned)` outstanding records into `out` after a proven stop and returns that count.
    /// Attached data commands end as `Quiesced`, detached ones as `Abandoned` with the buffer freed and reservation commands as `Reservation` with no status and the reserve entry filled, in slot order.
    /// Only a delivered terminal spends output room, so with the same `room > 0` spare slots on every call, `M` outstanding records drain in `ceil(M / room)` calls.
    /// The drain cursor only advances, so the whole stopped drain makes one forward pass over the records.
    /// Each terminal is built in place in `out`'s spare capacity. The call keeps the cursor and the abandoned, retired and released counts in locals and stores them, and `out`'s length, once after its last terminal.
    /// A panic that unwinds out of the loop leaves `drain`, `abandoned`, `retired`, `released` and `out`'s length as the call found them, with each record the loop reached already empty and `reservation_pending` already lowered for each reservation command; the terminals built before it stay undropped in the spare capacity, so each `Quiesced` terminal's buffer stays held.
    /// Each emptied slot retires when it issued the maximum generation and counts in `released` otherwise.
    #[inline(never)]
    fn deliver_stopped(&mut self, out: &mut Vec<Terminal<'a>>) -> usize {
        let outstanding = (self.pending() + self.abandoned) as usize;
        let count = (out.capacity() - out.len()).min(outstanding);
        let pools = self.pools;
        let mut ahead = self.records[self.drain..].iter_mut();
        let unscanned = ahead.len();
        let (mut freed, mut retired) = (0, 0);
        for place in &mut out.spare_capacity_mut()[..count] {
            let mut steps = RUN;
            let record = loop {
                let Some(record) = ahead.next() else {
                    unreachable!("an outstanding record lies at or after the drain cursor")
                };
                if record.command.is_some() {
                    break record;
                }
                steps -= 1;
                if steps == 0 {
                    steps = RUN;
                    let empty = RUN * empty_runs(ahead.as_slice());
                    ahead = ahead.into_slice()[empty..].iter_mut();
                }
            };
            let token = record.token;
            let Some(Command { buffer, shape }) = record.command.take() else {
                unreachable!("the scan stopped at a record that holds a command")
            };
            retired += u32::from(custody::retires(token.raw()));
            let op = shape.op();
            let ending = custody::ending(shape.phase());
            freed += u32::from(ending == Ending::Free);
            // Each arm's value is the reference `MaybeUninit::write` returns, so every iteration initializes its place.
            let _: &mut Terminal<'a> = if shape.reservation() {
                self.reservation_pending -= 1;
                Self::recycle(&mut self.reservation_buffers, pools, buffer, ending);
                place.write(Terminal::Reservation {
                    token,
                    status: None,
                    report_error: None,
                })
            } else if ending == Ending::Free {
                buffer.free(pools);
                place.write(Terminal::Abandoned {
                    token,
                    op,
                    status: None,
                })
            } else {
                place.write(Terminal::Quiesced {
                    token,
                    op,
                    buffer: buffer.into_buffer(pools),
                })
            };
        }
        self.drain += unscanned - ahead.len();
        self.abandoned -= freed;
        self.retired += retired;
        self.released += count as u32 - retired;
        // SAFETY: `count` is at most `out`'s spare capacity, and the loop above ran once for each of the first `count` elements of that capacity and initialized it.
        unsafe { out.set_len(out.len() + count) };
        count
    }

    /// Closes admission and works toward a proven quiesce; call it again until it reports `Quiesced`.
    /// One call makes at most one bounded pick and one driver quiesce before the device stops, and no driver call after.
    /// Only `Quiesced` ends the table's obligations. `Draining` and `Unproven` deliver nothing from the table's records, though the call's pick may deliver finished commands; every outstanding buffer stays owned.
    pub fn quiesce(&mut self, out: &mut Vec<Terminal<'a>>) -> QuiesceProgress {
        self.close();
        if custody::reaches_driver(self.admission) {
            self.poll(out);
            if self.pending() + self.abandoned == 0 {
                return QuiesceProgress::Quiesced(Quiesced::AllReturned);
            }
            match self.disk.quiesce() {
                QuiesceStatus::Pending => {
                    return QuiesceProgress::Draining {
                        outstanding: self.pending() + self.abandoned,
                    };
                }
                QuiesceStatus::Failed(code) => {
                    return QuiesceProgress::Unproven {
                        outstanding: self.pending() + self.abandoned,
                        code,
                    };
                }
                QuiesceStatus::Stopped => self.admission = Admission::Stopped,
            }
        }
        self.deliver_stopped(out);
        match self.pending() + self.abandoned {
            0 => QuiesceProgress::Quiesced(Quiesced::DeviceStopped),
            remaining => QuiesceProgress::Delivering { remaining },
        }
    }

    /// Sets the generation `slot` issued last, so a test can reach exhaustion.
    #[cfg(test)]
    pub(crate) fn set_generation(&mut self, slot: u16, generation: u64) {
        self.records[usize::from(slot)].token = token_of(slot, generation);
    }
}

/// A cancel whose token names no attached pending command or names a reserved one, or a cancel after close or a proven stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stale;

/// Dropping the holder uses `'b`, so every borrow with lifetime `'b` stays live until the holder drops.
/// Holding the `Drop` in this field lets a consuming method of the holder move the holder's other fields out.
pub(crate) struct BorrowUntilDrop<'b>(PhantomData<&'b ()>);

impl BorrowUntilDrop<'_> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

/// The `Drop` impl makes drop check require `'b` live where the value drops, so dropping the holder uses `'b`.
impl Drop for BorrowUntilDrop<'_> {
    fn drop(&mut self) {}
}

impl<D: Disk> fmt::Debug for CommandTable<'_, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandTable")
            .field("report", &self.report())
            .finish_non_exhaustive()
    }
}

/// What a pending command holds before a fault or stop boundary: its
/// operation and phase, and its buffer's pool, index and
/// incarnation.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub(crate) operation: Operation,
    pub(crate) accepted: bool,
    pub(crate) buffer: (super::PoolKind, usize, u64),
}

#[cfg(test)]
impl<D: Disk> CommandTable<'_, D> {
    /// The evidence of the pending command `token` names, or `None` once its slot holds no command for it.
    pub(crate) fn evidence(&self, token: CommandToken) -> Option<Evidence> {
        let record = &self.records[usize::from(slot_of(token))];
        let command = record.command.as_ref().filter(|_| record.token == token)?;
        Some(Evidence {
            operation: command.shape.op(),
            accepted: command.shape.phase() == Phase::Accepted,
            buffer: command.buffer.identity(),
        })
    }
}

#[cfg(test)]
impl<'l, N: super::spdk::Native> CommandTable<'_, super::SpdkDisk<'l, N>> {
    /// The SPDK driver's witness while commands are outstanding; reading it
    /// neither lends nor changes the driver.
    pub(crate) fn driver_witness(&mut self) -> super::spdk::DriverWitness {
        self.disk.witness()
    }

    /// The SPDK driver itself, for a test that injects a fault or reports a
    /// timeout while the table holds commands.
    pub(crate) fn driver(&mut self) -> &mut super::SpdkDisk<'l, N> {
        &mut self.disk
    }
}

#[cfg(test)]
mod tests {
    use super::{Operation, Phase, Shape};

    /// Every operation, phase and transfer length a submit can record reads back unchanged, and a phase change keeps the operation and length.
    #[test]
    fn a_shape_word_round_trips_its_operation_length_and_phase() {
        let lengths = [4096, 1 << 20, u32::MAX - 4095];
        let phases = [Phase::Reserved, Phase::Accepted, Phase::Detached];
        for op in [Operation::Read, Operation::Write] {
            for len in lengths {
                for phase in phases {
                    let shape = Shape::new(op, len, phase);
                    assert_eq!((shape.op(), shape.len(), shape.phase()), (op, len, phase));
                    for next in phases {
                        let moved = shape.with_phase(next);
                        assert_eq!((moved.op(), moved.len(), moved.phase()), (op, len, next));
                    }
                }
            }
        }
    }
}
