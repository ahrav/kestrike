//! A seeded simulated device for tests: the disk half implements [`Disk`] for the code under test, and the control half lets the test script the schedule, inject faults and observe bytes.
//!
//! Byte movement ("execute") and completion delivery ("post", then "pick") are separate steps, so a test can observe memory while a command is in flight.
//! The device holds at most the configured depth of pending commands and posted device completions.
//! In `Direct` mode the device copies bytes through the range's raw pointer, which is sound only while the caller holds the buffer and forms no view of it.
//! In `Modeled` mode the device never touches memory: host bytes live in a shadow indexed by backing offset, and the test mirrors its own writes into it.
//! Every event lands in a fixed ring that [`SimControl::describe`] prints with the seed.
//! Apart from the ring, the device captures each accepted command, with its operation, device range, host offset and acceptance ordinal, and each completion it produced as it is delivered into the caller's sink, with its status, in order up to a bound reserved at construction; an event past the bound sets the capture's overflow flag instead, which marks its evidence incomplete ([`SimControl::capture`]).
//!
//! The device's metadata is bounded by its live obligations: a command's operation, hold, fault, delay and progress, an omission included, ride on its pending record, and a completion's provenance and delivery gate ride on its posted record.
//! A device completion's posted record also keeps its command's acceptance ordinal, host offset and length, so [`SimControl::held`] lists every command the device still holds with the memory it names; an injected completion names no memory.
//! Pending and posted device records together never outnumber the queue depth, and injected completions never outnumber their reserved capacity.
//! Every scripted input reserves capacity before it is accepted: scripted refusals, injections and damage records each fit their [`ScriptCapacity`], and a hold, a fault or a delay attaches to a pending command's record.
//! Input past its capacity, or naming a command that cannot carry it, is refused with a typed [`ScriptRefusal`] that leaves the device unchanged, and every submit refusal is logged and counted with its [`Origin`].
//! Two driving forms share one queue and one readiness rule: the seeded [`tick`](SimControl::tick) picks among ready commands with the device's own generator, and the selection seam lists each [`Stage`]'s ready set in acceptance order, the device's own count of the commands it accepted, as canonical [`Candidate`] descriptors, and applies one selected entry at a time.
//! A posted completion is delivered only once its delivery gate opens: a tick, a direct post or an injection opens it at once, a selected post leaves it for a selected admission, and a pick delivers the open ones in posted order.
//! A length that differs from the memory range's is refused `InvalidRange`, as the device answers it; a token already outstanding breaks the caller's `Disk` precondition and panics.
//!
//! The control also scripts the media faults of the fault contract, each admitted before any effect: a misdirection or an omission applies inside one execution and sector damage inside one control call, so no observer or post sees a half-applied fault:
//! a gray delay keeps a command out of every ready set and every direct execute or post until the device clock reaches its time, then executes and terminates it normally;
//! a misdirected read substitutes a distinct equal-length source range for the intended media, reads ordinarily, and restores the intended bytes before the command can post, through an unwind too;
//! a misdirected write writes ordinarily, copies the produced bytes to a distinct target, restores the intended preimage and keeps the target damage attributed;
//! sector damage changes whole covered 512-byte sectors through the raw media and keeps the damage attributed;
//! an omission moves every byte and never reports, keeping the command pending until a reset, classed as an ordinary episode or as hostile.
//! A torn write lands a 512-byte sector prefix ([`Fault::TornWrite`]); an unqualified landing leaves each 512-byte sector of a write old, new or seeded garbage ([`Fault::UnqualifiedLanding`]). Volatile-cache loss, timeout callbacks and queue-pair failures lie outside the device's fault contract.
//!
//! Every fault has one tag: honest or lying. [`Fault::report`] returns the tag for each [`Fault`] variant; the table below also tags the device's other fault controls.
//! A fault is lying when the device reports success for a command whose media or host bytes differ from the command's request, changes media with no command, posts a completion it did not produce, or answers a stop `Stopped` while it can still execute commands or deliver completions.
//! Every other fault is honest: the device claims no success over bytes other than the command's. It reports a success over exactly the requested bytes, a failure status, a short count or a submit refusal, or it reports nothing; a failure or short status leaves open which bytes moved.
//! The fault variant, the status a `Status` carries and the command's length determine the tag. A lying kind keeps its tag even when a command's bytes match the request. Admission and execution determine each fault's effects.
//! An honest tag accounts only for its own command's non-success; under a lying tag a loss is accounted for only by the damage the run recorded for the fault it injected, covering the lost bytes; the device itself attributes damage only to a misdirected write's target and to sector damage. Neither tag exempts any byte from a byte check.
//!
//! | Kind | Symbol | Tag |
//! | --- | --- | --- |
//! | Error status, no bytes | [`Fault::Status`] | Honest; lying for a status that classifies as success |
//! | Short count | [`Fault::Short`] | Honest |
//! | Torn write | [`Fault::TornWrite`] | Honest |
//! | Partial read failure | [`Fault::PartialReadFailure`] | Honest |
//! | Corrupt success; misdirected read or write | [`Fault::CorruptSuccess`], [`Fault::MisdirectedRead`], [`Fault::MisdirectedWrite`] | Lying |
//! | Lost command, lost completion, omission, unqualified landing | [`Fault::DropCommand`], [`Fault::DropCompletion`], [`Fault::Omit`], [`Fault::UnqualifiedLanding`] | Honest |
//! | Sector damage at rest | [`SimControl::try_damage`] | Lying |
//! | Gray delay | [`SimControl::try_delay`] | Honest |
//! | Submit refusal | [`SimControl::try_refuse_next`]; the model's refusals | Honest |
//! | Misaligned command | [`DeviceRangeError`](super::DeviceRangeError) and [`CommandTable`](super::CommandTable) refusals; the submit's panic on a length that is no multiple of the block | Honest |
//! | Dead device | [`SimControl::set_gone`]; [`QuiesceMode::Reset`] | Honest |
//! | Sticky read-only | none | Honest |
//! | Driver unwind | [`Unwind`] | Honest |
//! | Stop answers | [`QuiesceMode`] | Honest; [`QuiesceMode::FalseStopped`] lying |
//! | Unproduced completion; replayed write | [`SimControl::try_inject`]; [`Attempt::land`] | Lying |
//!
//! A device built by [`sim_attached`] carries scripted [`AttachFacts`] and the [`PersistenceProfile`] derived from them at construction; `attach_facts` returns those facts for the device's life. On a profile-bearing device a write whose range the profile qualifies lands whole or not at all: it moves every byte by an ordinary execution, a `DropCompletion` or an `Omit`, or none by a `DropCommand`, a failure status or a reset of a waiting command, and admission refuses every fault that would land part of it or report success over bytes other than the write's. An injected completion carries no range, so a success injected for a lost token is a containment control outside the profile; a misdirected write's target damage, like control-half sector damage, is a media control outside the profile too.
//! A misdirection snapshots the intended media into scratch reserved at construction, and damage and omission records ride on capacity reserved at construction, so faults allocate nothing.
//! These bounds hold for a device that records no write attempts: after [`SimControl::record_attempts`] the device also copies the lasting bytes of every write it executes into an unbounded record, faulted writes included, which [`SimControl::footprint`] does not count.
//!
//! The `fidelity_tests` table lists behavioral differences between this device and the production driver.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::rc::Rc;
use std::slice;

use sha2::{Digest, Sha256};

use super::super::seeded::SplitMix64;
use super::config::SECTOR;
use super::disk::{
    CommandToken, Completion, CompletionSink, Disk, DmaRange, QuiesceStatus, RefusalReason,
    SubmitRefusal,
};
use super::geometry::{DeviceGeometry, DeviceRange};
use super::identify::AttachFacts;
use super::profile::PersistenceProfile;
use super::status::{Classification, DeviceStatus};
use super::table::Operation;
use crate::sim::choice::{CANDIDATE_LEN, Candidate, Domain};

const RING: usize = 256;
const UNIT: usize = super::config::IO_UNIT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Direct,
    Modeled { backing_len: usize },
}

/// Which raw status form the device reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusForm {
    Nvme,
    Kernel,
}

/// A fault applied to one command when it executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// Moves nothing and reports `status`.
    Status(DeviceStatus),
    /// Moves the first `units` 4 KiB units, capped at the command's length, and reports that count as a kernel result.
    Short { units: u32 },
    /// Moves every byte XORed with `0x5A`, and reports success.
    CorruptSuccess,
    /// A write that lands only its first `sectors` 512-byte sectors, then reports failure.
    TornWrite { sectors: u32 },
    /// A read that writes only its first `sectors` 512-byte sectors of host memory, then reports failure.
    PartialReadFailure { sectors: u32 },
    /// The command vanishes: no bytes move and no completion is ever reported.
    DropCommand,
    /// Every byte moves, the command leaves the queue, and the completion is never reported.
    DropCompletion,
    /// Reads the equal-length range at device byte `source` in place of the intended one, then restores the intended media before the command can post; reports success.
    MisdirectedRead { source: u64 },
    /// Writes the intended range, copies the bytes it produced to the equal-length range at device byte `target`, and restores the intended range's preimage before the command can post; reports success and keeps the target damage attributed.
    /// An unwind between the copy and the restoration keeps the copy and its record and leaves the command pending with its fault spent, so its later execution writes the intended range.
    MisdirectedWrite { target: u64 },
    /// Every byte moves and the completion is never reported; the command keeps its pending record and queue room until a reset.
    Omit(Omission),
    /// A write that leaves each whole 512-byte sector of its range holding its preimage, its new bytes or garbage, chosen per sector by a generator over `seed` and the sector's index, and never reports; the command stays pending as an omitted episode until a reset.
    UnqualifiedLanding { seed: u64 },
}

impl Fault {
    /// Whether the fault on a write of `len` bytes lands part of it, or reports success while its range holds bytes other than the write's.
    pub(crate) fn breaks_whole_landing(self, len: u32) -> bool {
        match self {
            Self::TornWrite { .. }
            | Self::PartialReadFailure { .. }
            | Self::Short { .. }
            | Self::CorruptSuccess
            | Self::MisdirectedWrite { .. }
            | Self::UnqualifiedLanding { .. } => true,
            Self::Status(status) => status.classify(len) == Classification::Success,
            Self::DropCommand
            | Self::DropCompletion
            | Self::MisdirectedRead { .. }
            | Self::Omit(_) => false,
        }
    }

    /// The tag of this fault's kind on a command of `len` bytes, by the module's definitions: [`Report::Lying`] for a kind under which the device reports success over bytes other than the command's, [`Report::Honest`] otherwise.
    /// The fault variant, the status a `Status` carries and `len` determine the tag: a misdirection stays lying when its two ranges hold equal bytes.
    /// A `Status` moves no byte, so it lies exactly when its status classifies as success for `len`.
    pub(crate) fn report(self, len: u32) -> Report {
        match self {
            Self::Status(status) => match status.classify(len) {
                Classification::Success => Report::Lying,
                Classification::Short { .. } | Classification::Failed => Report::Honest,
            },
            Self::CorruptSuccess | Self::MisdirectedRead { .. } | Self::MisdirectedWrite { .. } => {
                Report::Lying
            }
            Self::Short { .. }
            | Self::TornWrite { .. }
            | Self::PartialReadFailure { .. }
            | Self::DropCommand
            | Self::DropCompletion
            | Self::Omit(_)
            | Self::UnqualifiedLanding { .. } => Report::Honest,
        }
    }
}

/// The tag of a [`Fault`] on an accepted command: whether the device's report for that command can claim success over bytes other than the command's.
/// The module documentation defines both tags and tags the device's other fault controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Report {
    /// The device claims no success over other bytes: it reports a success over exactly the requested bytes, a short count or a failure status, or it reports nothing while the command is lost or stays pending until a reset.
    Honest,
    /// The fault's kind, for this length, reports success over bytes other than the command's; a command whose bytes happen to match keeps the tag.
    Lying,
}

/// How a missing terminal is classed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Omission {
    /// An ordinary episode, which a proven stop ends.
    Episode,
    /// A terminal that never comes: a hostile outcome; only a reset ends the command, and the device keeps counting it.
    Hostile,
}

/// The pattern sector damage XORs into every byte it covers.
pub(crate) const DAMAGE_XOR: u8 = 0x5A;

/// Media one fault changed and still attributes: the range, the command that produced it, or none for raw sector damage, and the SHA-256 of the bytes it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Damage {
    pub start: u64,
    pub len: u64,
    pub token: Option<CommandToken>,
    pub digest: [u8; 32],
}

/// A driver call that unwinds instead of returning, before it queues or takes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unwind {
    Submit,
    Pick,
}

/// How the device answers a quiesce request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuiesceMode {
    /// `Pending`; commands keep executing, so only the caller's own accounting can show all returned.
    AllReturned,
    /// Drops every outstanding command and posted completion, then reports `Stopped`; later submits are refused `DeviceGone`.
    Reset,
    /// A hostile control: reports `Stopped` and keeps every command, which goes on executing and posting.
    /// Only a `Modeled` device takes it, so the access after the return lands in the host shadow, never in memory.
    FalseStopped,
    /// `Pending` forever; the device stops executing.
    Unproven,
    Failed(Option<i32>),
}

/// Who produced a submit refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The device model: a range it cannot serve, a full queue or a gone device.
    Model,
    /// A refusal the test scripted with [`refuse_next`](SimControl::refuse_next).
    Script,
}

/// The counter slot of `origin`, model first.
fn origin_slot(origin: Origin) -> usize {
    usize::from(origin == Origin::Script)
}

/// The containment-control class of an injected completion, which the device did not produce.
/// The class is the test's declaration; the device keeps no record of delivered tokens to check it against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Injection {
    /// A second report for a token the device already reported.
    Duplicate,
    /// A token the device never accepted.
    Foreign,
    /// A token of a command that ended before a successor took its place.
    Old,
    /// A token whose submit the device refused.
    Refused,
    /// A token that names a place no current command can hold.
    OutOfRange,
}

/// A completion's provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// The device produced it for an accepted command: the command's operation, its acceptance ordinal, and the host offset and length in bytes of the memory it names.
    Device {
        op: Operation,
        ordinal: u64,
        host: usize,
        len: u32,
    },
    Injected(Injection),
}

/// The scripted inputs a device admits at once beyond its command records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScriptCapacity {
    /// Scripted submit refusals queued and not yet consumed.
    pub refusals: u32,
    /// Injected completions posted and not yet delivered or reset.
    pub injections: u32,
    /// Attributed media damage records the device keeps.
    pub damage: u32,
}

/// The capacity the fixtures configure; a profile that declares no injection sets `injections` to zero.
pub(crate) const SCRIPT: ScriptCapacity = ScriptCapacity {
    refusals: 8,
    injections: 8,
    damage: 8,
};

/// A kind of scripted input or selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptKind {
    Refusal,
    Hold,
    Fault,
    Injection,
    Selection(Stage),
    Delay,
    Damage,
}

/// Why the simulator refused a scripted input or a selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScriptReason {
    /// The kind's reserved capacity is in use.
    Full { capacity: u32 },
    /// The named command is not pending, so no record can carry the input.
    NotPending(CommandToken),
    /// The named command is pending, so a table holding its buffer could return it while the device may still write it.
    Pending(CommandToken),
    /// The pending command already carries a fault.
    Faulted(CommandToken),
    /// The pending command's bytes already moved, so a fault could no longer apply.
    Executed(CommandToken),
    /// The selection names no entry of the `ready` candidates.
    Selection { index: usize, ready: usize },
    /// The device is gone, and a gone device takes no injected completion.
    Gone,
    /// A misdirected range or a damaged range passes the device's capacity.
    OutOfBounds { start: u64, len: u64 },
    /// A misdirected range is the intended range or overlaps it.
    Overlap { start: u64, len: u64 },
    /// Damage that is empty or does not cover whole 512-byte sectors.
    Unaligned { start: u64, len: u64 },
    /// A delay to a time the device clock already passed.
    Past { until: u64, now: u64 },
    /// The pending command is already delayed.
    Delayed(CommandToken),
    /// The fault misdirects or lands an operation the command does not perform.
    Operation(CommandToken),
    /// The device's persistence profile qualifies the write's range, and the fault would land part of it or report success over changed media.
    Qualified(CommandToken),
}

/// The simulator's refusal of the test's own scripted input or selection; the device's state is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScriptRefusal {
    pub kind: ScriptKind,
    pub reason: ScriptReason,
}

/// Which ready set a selection draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Stage {
    /// Unheld, due pending commands whose bytes have not moved, on a running device.
    Execute = 1,
    /// Unheld, due pending commands, executed or not, whose completion is not omitted, on a running device.
    Post = 2,
    /// Posted device completions whose delivery gate is closed.
    Admit = 3,
}

/// What a selection did to the entry it named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    /// The command's bytes moved; its completion is not posted.
    Executed,
    /// The command's completion is posted behind a closed gate.
    Posted,
    /// The completion's delivery gate opened.
    Admitted,
    /// A `DropCommand` or `DropCompletion` fault lost the command, which posts nothing and leaves the queue.
    Lost,
    /// An omission moved the command's bytes and withholds its completion; the command stays pending until a reset.
    Omitted,
}

/// One applied selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Selected {
    pub token: CommandToken,
    pub effect: Effect,
}

/// The capacity of the device's stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Reserved {
    pub pending: usize,
    pub posted: usize,
    pub refusals: usize,
    pub damage: usize,
    pub scratch: usize,
}

impl Reserved {
    /// The capacity of every store together.
    pub(crate) fn total(self) -> usize {
        self.pending + self.posted + self.refusals + self.damage + self.scratch
    }
}

/// The most records the device held at once since it was built, and the current capacity of its stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Footprint {
    pub pending: usize,
    pub posted: usize,
    /// Pending plus posted device records, the count the queue depth bounds.
    pub device: usize,
    pub refusals: usize,
    pub injections: usize,
    pub damage: usize,
    /// The stores' capacity now, which stays at its construction value while no insertion reallocates.
    pub reserved: Reserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    Submitted(CommandToken, Operation),
    Refused {
        token: CommandToken,
        reason: RefusalReason,
        origin: Origin,
    },
    /// Bytes moved for the token: `len` bytes at host offset `offset`.
    Executed {
        token: CommandToken,
        offset: usize,
        len: usize,
    },
    Posted(CommandToken),
    Injected(CommandToken, Injection),
    /// A posted completion's delivery gate opened.
    Admitted(CommandToken),
    Delivered(CommandToken),
    Lost(CommandToken),
    /// A delayed command executed `elapsed` after its delay was set.
    Delayed {
        token: CommandToken,
        elapsed: u64,
    },
    /// A misdirected command moved bytes against the range at device byte `at`.
    Misdirected {
        token: CommandToken,
        at: u64,
    },
    /// A completion that will never be reported, of its class.
    Omitted(CommandToken, Omission),
    /// An unqualified landing under `seed` set each of the write's sectors old, new or garbage; its completion will never be reported.
    Landed {
        token: CommandToken,
        seed: u64,
    },
    /// A `FalseStopped` quiesce reported `Stopped` with commands still pending.
    FalseStopped,
    Stopped,
}

/// One device-boundary event the device captured: a command it accepted, or a completion it delivered into the caller's sink.
/// The capture keeps every event in order until its bound, independent of the bounded diagnostic ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Captured {
    /// An accepted command: its operation, device range, host offset and the device's acceptance ordinal.
    Submitted {
        token: CommandToken,
        operation: Operation,
        device: DeviceRange,
        host: usize,
        ordinal: u64,
    },
    /// A device-produced completion handed to the sink, with its token and status; the event log records both device-produced and injected deliveries.
    Delivered {
        token: CommandToken,
        status: DeviceStatus,
    },
}

/// The device's capture: its events in order and whether an event arrived past the bound, which leaves the evidence incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Capture {
    pub events: Vec<Captured>,
    pub overflow: bool,
    /// Commands the device accepted, counted apart from the captured events.
    pub accepted: u64,
}

/// Events a capture holds before it flags overflow, reserved at construction so capturing allocates nothing.
const CAPTURE_BOUND: usize = 1 << 14;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SimConfig {
    pub seed: u64,
    pub capacity: u64,
    pub queue_depth: u32,
    pub max_transfer: u32,
    pub form: StatusForm,
    pub mode: Mode,
    pub script: ScriptCapacity,
}

#[derive(Debug)]
struct Command {
    token: CommandToken,
    op: Operation,
    device: DeviceRange,
    memory: DmaRange,
    /// Whether the command's bytes moved, and what it posts.
    progress: Progress,
    /// Kept out of every tick and ready set until released.
    held: bool,
    /// Applied when the command executes.
    fault: Option<Fault>,
    /// The device's count of commands it accepted before this one.
    ordinal: u64,
    /// A gray delay the command still serves; its execution ends it.
    delay: Option<Delay>,
}

/// A pending command's progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
    /// No byte moved yet.
    Waiting,
    /// The bytes moved, and this status posts.
    Executed(DeviceStatus),
    /// An omission moved the bytes; no completion posts.
    Omitted(Omission),
}

/// A gray delay: the device clock when it was set, and the time the command waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Delay {
    set: u64,
    until: u64,
}

impl Command {
    /// Whether no delay holds the command at device time `now`.
    fn due(&self, now: u64) -> bool {
        match self.delay {
            Some(delay) => delay.until <= now,
            None => true,
        }
    }

    /// Whether the command belongs to the `Execute` or `Post` ready set on a running device at device time `now`: the one readiness rule the seeded tick and the selection seam share. Admission readiness belongs to posted records.
    fn ready_for(&self, stage: Stage, now: u64) -> bool {
        let open = !self.held && self.due(now);
        match stage {
            Stage::Execute => open && self.progress == Progress::Waiting,
            Stage::Post => open && !matches!(self.progress, Progress::Omitted(_)),
            Stage::Admit => unreachable!("admission reads posted records"),
        }
    }
}

/// One ready entry: what a candidate describes and where its record sits.
#[derive(Debug, Clone, Copy)]
struct Entry {
    ordinal: u64,
    token: CommandToken,
    op: Operation,
    /// The device range of a pending command; a posted completion has none.
    device: Option<DeviceRange>,
    /// The record's index in the pending or posted store.
    at: usize,
}

/// The counter slot of `op`, reads first.
fn slot(op: Operation) -> usize {
    usize::from(op == Operation::Write)
}

/// A completion waiting for a pick, with its provenance and delivery gate.
#[derive(Debug, Clone, Copy)]
struct Posted {
    completion: Completion,
    provenance: Provenance,
    /// The delivery gate is open, so a pick may deliver it.
    eligible: bool,
}

/// One command the device holds: a pending command, or a device completion posted and not yet delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldCommand {
    pub token: CommandToken,
    pub operation: Operation,
    /// The host offset of the memory the command names, in the backing.
    pub host: usize,
    pub len: u32,
    /// The device's acceptance ordinal.
    pub ordinal: u64,
    /// The device executed the command: its bytes moved in whole or in part, or its fault decided they never move; an omitted command's completion never posts.
    pub moved: bool,
    /// The completion is posted and waits for a pick.
    pub posted: bool,
}

#[derive(Debug)]
struct Core {
    config: SimConfig,
    rng: SplitMix64,
    /// The media bytes, shared with every device built over the same handle.
    store: Media,
    host: Vec<u8>,
    pending: Vec<Command>,
    posted: VecDeque<Posted>,
    refusals: VecDeque<SubmitRefusal>,
    /// Injected completions posted and not yet delivered or reset.
    injected: usize,
    footprint: Footprint,
    /// The next driver call of this kind unwinds.
    unwind: Option<Unwind>,
    halted: bool,
    gone: bool,
    quiesce: QuiesceMode,
    /// The block size the geometry reports.
    block_size: u32,
    events: VecDeque<Event>,
    capture: Capture,
    capture_bound: usize,
    /// Events the ring dropped to make room, over the device's life.
    evicted: u64,
    /// Calls the disk half received: submits, picks, services and quiesces.
    calls: usize,
    /// Commands accepted and device completions delivered over the device's life, by operation, read first; unlike the event ring they never drop an entry.
    accepted: [usize; 2],
    delivered: [usize; 2],
    /// Injected completions delivered over the device's life.
    delivered_injections: usize,
    /// Submit refusals over the device's life, by origin, model first.
    refused: [usize; 2],
    /// Commands accepted over the device's life, the next command's ordinal.
    ordinals: u64,
    /// The device clock, which only the control moves, and only forward.
    now: u64,
    /// Reserved at construction for a misdirected command's snapshot of the intended media, the maximum transfer long; shared with the guard that restores it.
    scratch: Rc<RefCell<Vec<u8>>>,
    /// Attributed media damage, kept for the device's life within its reserved capacity.
    damage: Vec<Damage>,
    /// Hostile omissions over the device's life; a reset ends their commands and keeps the count.
    hostile: u64,
    /// Whether the next misdirected execution unwinds after its substitution and before its restoration.
    unwind_misdirection: bool,
    /// The lasting media effect of every write the device executed since [`SimControl::record_attempts`], in
    /// execution order: a misdirected write at its target, an unqualified landing as one attempt for each run of
    /// sectors it changed; `None` records none.
    attempts: Option<Vec<Attempt>>,
    /// Whether the device carries scripted attach facts, which fixed the block size at construction.
    attached: bool,
    /// The profile derived from the scripted facts at construction; `None` for a factless device and for facts the derivation refuses.
    profile: Option<PersistenceProfile>,
}

/// The disk half, owned by the code under test, with the attach facts it reports.
#[derive(Debug)]
pub(crate) struct SimDisk(Rc<RefCell<Core>>, Option<AttachFacts>);

/// The control half, kept by the test.
#[derive(Debug, Clone)]
pub(crate) struct SimControl(Rc<RefCell<Core>>);

/// Media bytes one or more simulated devices share: each incarnation's device
/// queues its own commands, and every executed write lands in the one store.
pub(crate) type Media = Rc<RefCell<Vec<u8>>>;

/// One write a device executed: the device byte where its bytes lasted and those bytes, short, flipped or moved to a
/// misdirection's target when a fault made them so. An unqualified landing is recorded as one attempt for each
/// maximal run of sectors that took new bytes or garbage, so a sector that kept its preimage lies in no attempt. A
/// write that moved no byte records no attempt, so an attempt holds at least one byte. An attempt outlives its completion and its device, so a test lands it again on the shared media at any later step,
/// any number of times: a write attempt the guest saw complete that the backend applies again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub start: u64,
    pub bytes: Vec<u8>,
}

impl Attempt {
    /// Whether the attempt wrote any byte of device unit `unit`.
    pub(crate) fn covers(&self, unit: u64) -> bool {
        let size = crate::storage::IO_UNIT as u64;
        let at = unit * size;
        self.start < at + size && at < self.start + self.bytes.len() as u64
    }

    /// Lands the attempt's bytes on `media` again, whatever a later write left there.
    pub(crate) fn land(&self, media: &Media) {
        let start = usize::try_from(self.start).unwrap();
        media.borrow_mut()[start..start + self.bytes.len()].copy_from_slice(&self.bytes);
    }
}

/// Records sectors `run` of the landing at device byte `start` as one attempt holding the bytes `media` has there,
/// when the device records write attempts.
fn record_run(
    attempts: &mut Option<Vec<Attempt>>,
    media: &[u8],
    start: usize,
    run: std::ops::Range<usize>,
) {
    if let Some(attempts) = attempts {
        let at = start + run.start * SECTOR;
        attempts.push(Attempt {
            start: at as u64,
            bytes: media[at..start + run.end * SECTOR].to_vec(),
        });
    }
}

/// Fresh zeroed media of `capacity` bytes.
pub(crate) fn media(capacity: u64) -> Media {
    Rc::new(RefCell::new(vec![0; usize::try_from(capacity).unwrap()]))
}

pub(crate) fn sim(config: SimConfig) -> (SimDisk, SimControl) {
    sim_over(config, media(config.capacity))
}

/// A simulated device whose commands move bytes in `store`, which other
/// devices may share; its queues, faults and log are its own.
///
/// # Panics
///
/// When `store` is shorter than the configured capacity.
pub(crate) fn sim_over(config: SimConfig, store: Media) -> (SimDisk, SimControl) {
    assert!(
        store.borrow().len() as u64 >= config.capacity,
        "the media covers the device's capacity"
    );
    assert!(
        config.form == StatusForm::Nvme || config.max_transfer <= i32::MAX as u32,
        "a kernel result encodes every transfer length"
    );
    let host = match config.mode {
        Mode::Direct => Vec::new(),
        Mode::Modeled { backing_len } => vec![0; backing_len],
    };
    let depth = config.queue_depth as usize;
    let scratch = usize::try_from(u64::from(config.max_transfer).min(config.capacity)).unwrap();
    let pending = Vec::with_capacity(depth);
    let posted = VecDeque::with_capacity(depth + config.script.injections as usize);
    let refusals = VecDeque::with_capacity(config.script.refusals as usize);
    let footprint = Footprint::default();
    let core = Rc::new(RefCell::new(Core {
        rng: SplitMix64::new(config.seed),
        store,
        host,
        pending,
        posted,
        refusals,
        injected: 0,
        footprint,
        unwind: None,
        halted: false,
        gone: false,
        // EBS's block size, so reads end at a record's last sector rather than its last unit.
        block_size: SECTOR as u32,
        quiesce: QuiesceMode::AllReturned,
        events: VecDeque::with_capacity(RING),
        capture: Capture {
            events: Vec::with_capacity(CAPTURE_BOUND),
            overflow: false,
            accepted: 0,
        },
        capture_bound: CAPTURE_BOUND,
        evicted: 0,
        calls: 0,
        accepted: [0; 2],
        delivered: [0; 2],
        delivered_injections: 0,
        refused: [0; 2],
        ordinals: 0,
        now: 0,
        scratch: Rc::new(RefCell::new(vec![0; scratch])),
        damage: Vec::with_capacity(config.script.damage as usize),
        hostile: 0,
        unwind_misdirection: false,
        attempts: None,
        attached: false,
        profile: None,
        config,
    }));
    (SimDisk(Rc::clone(&core), None), SimControl(core))
}

/// A simulated device over `store` that reports `facts` through
/// `attach_facts` and carries the profile derived from them, if any; its
/// block size is the identity's sector size. The Identify pages may
/// disagree with the identity, so derivation can refuse `Mismatch` or
/// `Malformed`.
///
/// # Panics
///
/// When the identity's capacity differs from the configured capacity, its
/// sector size is no power of two from 512 to 4096 bytes, or the Identify's
/// command limit exceeds the configured maximum transfer; and as
/// [`sim_over`] does.
pub(crate) fn sim_attached(
    config: SimConfig,
    store: Media,
    facts: AttachFacts,
) -> (SimDisk, SimControl) {
    let identity = &facts.identity;
    assert_eq!(
        identity.capacity, config.capacity,
        "the identity's capacity is the device's"
    );
    assert!(
        identity.sector_size.is_power_of_two() && (512..=4096).contains(&identity.sector_size),
        "the identity's sector size is a power of two from 512 to 4096 bytes"
    );
    assert!(
        facts.identify.transfer().command <= config.max_transfer,
        "the Identify's command limit fits the device's maximum transfer"
    );
    let (SimDisk(core, _), control) = sim_over(config, store);
    {
        let mut core = core.borrow_mut();
        core.block_size = identity.sector_size;
        core.attached = true;
        core.profile = PersistenceProfile::derive(&facts).ok();
    }
    (SimDisk(core, Some(facts)), control)
}

/// Restores a range of the media from a snapshot when dropped, by return or by unwind.
struct Restore {
    store: Media,
    scratch: Rc<RefCell<Vec<u8>>>,
    start: usize,
    len: usize,
}

impl Restore {
    /// Copies `len` media bytes at `start` into the front of `scratch`, which construction sized to the maximum transfer, so it holds every command's range.
    fn snapshot(store: &Media, scratch: &Rc<RefCell<Vec<u8>>>, start: usize, len: usize) -> Self {
        scratch.borrow_mut()[..len].copy_from_slice(&store.borrow()[start..start + len]);
        Self {
            store: Rc::clone(store),
            scratch: Rc::clone(scratch),
            start,
            len,
        }
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        self.store.borrow_mut()[self.start..self.start + self.len]
            .copy_from_slice(&self.scratch.borrow()[..self.len]);
    }
}

impl Core {
    /// Captures `event`, or flags the capture's overflow once it holds its bound.
    fn capture(&mut self, event: Captured) {
        if self.capture.events.len() < self.capture_bound {
            self.capture.events.push(event);
        } else {
            self.capture.overflow = true;
        }
    }

    fn log(&mut self, event: Event) {
        if self.events.len() == RING {
            self.events.pop_front();
            self.evicted += 1;
        }
        self.events.push_back(event);
    }

    fn describe(&self) -> String {
        let mut text = format!("seed {}; events:", self.config.seed);
        for event in &self.events {
            let _ = write!(text, "\n  {event:?}");
        }
        text
    }

    fn outstanding(&self) -> usize {
        self.pending.len() + self.posted.len()
    }

    /// Pending commands and posted device completions, which the queue depth bounds; injected completions ride on their own capacity.
    fn device_records(&self) -> usize {
        self.outstanding() - self.injected
    }

    /// Raises the high-water marks to the records held now.
    fn mark(&mut self) {
        debug_assert_eq!(
            self.injected,
            self.posted
                .iter()
                .filter(|posted| matches!(posted.provenance, Provenance::Injected(_)))
                .count()
        );
        let device = self.device_records();
        let mark = &mut self.footprint;
        mark.pending = mark.pending.max(self.pending.len());
        mark.posted = mark.posted.max(self.posted.len());
        mark.device = mark.device.max(device);
        mark.refusals = mark.refusals.max(self.refusals.len());
        mark.injections = mark.injections.max(self.injected);
    }

    /// The pending command `token` names, or the refusal of a `kind` input naming it.
    fn pending_at(&self, kind: ScriptKind, token: CommandToken) -> Result<usize, ScriptRefusal> {
        self.position(token).ok_or(ScriptRefusal {
            kind,
            reason: ScriptReason::NotPending(token),
        })
    }

    /// `stage`'s ready set in acceptance order: pending commands for `Execute` and `Post`, posted device completions behind a closed gate for `Admit`.
    /// A halted device executes and posts nothing; admission does not touch the device.
    /// The list is built on each call, so a caller selects between turns rather than inside an allocation-counted window.
    fn ready(&self, stage: Stage) -> Vec<Entry> {
        let mut ready: Vec<Entry> = match stage {
            Stage::Execute | Stage::Post if self.halted => Vec::new(),
            Stage::Execute | Stage::Post => (0..self.pending.len())
                .filter(|&at| self.pending[at].ready_for(stage, self.now))
                .map(|at| {
                    let command = &self.pending[at];
                    Entry {
                        ordinal: command.ordinal,
                        token: command.token,
                        op: command.op,
                        device: Some(command.device),
                        at,
                    }
                })
                .collect(),
            Stage::Admit => (0..self.posted.len())
                .filter_map(|at| {
                    let posted = &self.posted[at];
                    match posted.provenance {
                        Provenance::Device { op, ordinal, .. } if !posted.eligible => Some(Entry {
                            ordinal,
                            token: posted.completion.token,
                            op,
                            device: None,
                            at,
                        }),
                        _ => None,
                    }
                })
                .collect(),
        };
        ready.sort_by_key(|entry| entry.ordinal);
        ready
    }

    /// Admits `fault` on the pending command at `at`: it must be the command's first fault, before its bytes move, and a misdirection must name its own operation and another range of the intended range's length, inside the device and apart from the intended range.
    /// An unqualified landing names a write; on a write the device's profile qualifies, a fault that [`breaks_whole_landing`](Fault::breaks_whole_landing) is refused `Qualified`.
    /// The scratch holds the maximum transfer, so it fits every intended range; a misdirected write also needs a free damage record.
    fn admit_fault(&self, at: usize, fault: Fault) -> Result<(), ScriptReason> {
        let command = &self.pending[at];
        if command.progress != Progress::Waiting {
            return Err(ScriptReason::Executed(command.token));
        }
        if command.fault.is_some() {
            return Err(ScriptReason::Faulted(command.token));
        }
        if matches!(fault, Fault::UnqualifiedLanding { .. }) && command.op != Operation::Write {
            return Err(ScriptReason::Operation(command.token));
        }
        if command.op == Operation::Write
            && fault.breaks_whole_landing(command.device.byte_len())
            && self
                .profile
                .as_ref()
                .is_some_and(|profile| profile.qualifies(command.device))
        {
            return Err(ScriptReason::Qualified(command.token));
        }
        let (other, op) = match fault {
            Fault::MisdirectedRead { source } => (source, Operation::Read),
            Fault::MisdirectedWrite { target } => (target, Operation::Write),
            _ => return Ok(()),
        };
        let (start, len) = (command.device.start(), u64::from(command.device.byte_len()));
        if command.op != op {
            return Err(ScriptReason::Operation(command.token));
        }
        self.fits(other, len)?;
        if other < start + len && start < other + len {
            return Err(ScriptReason::Overlap { start: other, len });
        }
        if op == Operation::Write {
            self.damage_room()?;
        }
        Ok(())
    }

    /// Refuses a device range `start..start + len` that passes the device's capacity.
    fn fits(&self, start: u64, len: u64) -> Result<(), ScriptReason> {
        match start.checked_add(len) {
            Some(end) if end <= self.config.capacity => Ok(()),
            _ => Err(ScriptReason::OutOfBounds { start, len }),
        }
    }

    /// Keeps `damage` attributed and raises its high-water mark; [`damage_room`](Self::damage_room) reserved its record.
    fn attribute(&mut self, damage: Damage) {
        debug_assert!(self.damage.len() < self.damage.capacity());
        self.damage.push(damage);
        self.footprint.damage = self.footprint.damage.max(self.damage.len());
    }

    /// Refuses `Full` unless a damage record is free: the records kept plus one for each pending misdirected write, which reserves its record at admission, stay below the capacity.
    fn damage_room(&self) -> Result<(), ScriptReason> {
        let reserved = self
            .pending
            .iter()
            .filter(|command| matches!(command.fault, Some(Fault::MisdirectedWrite { .. })))
            .count();
        let capacity = self.config.script.damage;
        if self.damage.len() + reserved < capacity as usize {
            Ok(())
        } else {
            Err(ScriptReason::Full { capacity })
        }
    }

    /// The `pending` index of the command `token` names, for a direct execute or post.
    ///
    /// # Panics
    ///
    /// When `token` is not pending, or when a gray delay still holds it, as every ready set excludes it.
    fn due_position(&self, token: CommandToken) -> usize {
        let at = self
            .position(token)
            .unwrap_or_else(|| panic!("{token:?} not pending\n{}", self.describe()));
        assert!(
            self.pending[at].due(self.now),
            "{token:?} is delayed\n{}",
            self.describe()
        );
        at
    }

    /// `stage`'s ready entry `index`.
    fn selected(&self, stage: Stage, index: usize) -> Result<Entry, ScriptRefusal> {
        let ready = self.ready(stage);
        ready.get(index).copied().ok_or(ScriptRefusal {
            kind: ScriptKind::Selection(stage),
            reason: ScriptReason::Selection {
                index,
                ready: ready.len(),
            },
        })
    }

    fn success(&self, len: u32) -> DeviceStatus {
        match self.config.form {
            StatusForm::Nvme => DeviceStatus::Nvme(0x0001),
            StatusForm::Kernel => DeviceStatus::Kernel(len as i32),
        }
    }

    fn failure(&self) -> DeviceStatus {
        match self.config.form {
            StatusForm::Nvme => DeviceStatus::Nvme(0x0004),
            StatusForm::Kernel => DeviceStatus::Kernel(-libc::EIO),
        }
    }

    fn submit(
        &mut self,
        op: Operation,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        self.calls += 1;
        self.unwind_at(Unwind::Submit);
        if let Mode::Modeled { backing_len } = self.config.mode {
            assert!(
                memory.offset() + memory.byte_len() as usize <= backing_len,
                "the range lies inside the shadow backing"
            );
        }
        assert!(
            self.position(token).is_none()
                && !self
                    .posted
                    .iter()
                    .any(|posted| posted.completion.token == token),
            "a submission breaks the Disk precondition: {token:?} is outstanding\n{}",
            self.describe()
        );
        assert!(
            memory.byte_len().is_multiple_of(self.block_size),
            "a submission breaks the Disk precondition: {} bytes is no multiple of the {}-byte block\n{}",
            memory.byte_len(),
            self.block_size,
            self.describe()
        );
        let model = |reason| (SubmitRefusal { reason, code: None }, Origin::Model);
        let refused = if self.gone {
            Some(model(RefusalReason::DeviceGone))
        } else if let Some(scripted) = self.refusals.pop_front() {
            self.gone = scripted.reason == RefusalReason::DeviceGone;
            Some((scripted, Origin::Script))
        } else if device.end() > self.config.capacity
            || device.byte_len() > self.config.max_transfer
            || device.byte_len() != memory.byte_len()
        {
            Some(model(RefusalReason::InvalidRange))
        } else if self.device_records() >= self.config.queue_depth as usize {
            Some(model(RefusalReason::QueueFull))
        } else {
            None
        };
        if let Some((refused, origin)) = refused {
            self.refused[origin_slot(origin)] += 1;
            self.log(Event::Refused {
                token,
                reason: refused.reason,
                origin,
            });
            return Err(refused);
        }
        self.pending.push(Command {
            token,
            op,
            device,
            memory,
            progress: Progress::Waiting,
            held: false,
            fault: None,
            ordinal: self.ordinals,
            delay: None,
        });
        self.capture(Captured::Submitted {
            token,
            operation: op,
            device,
            host: memory.offset(),
            ordinal: self.ordinals,
        });
        self.ordinals += 1;
        self.accepted[slot(op)] += 1;
        self.mark();
        self.log(Event::Submitted(token, op));
        Ok(())
    }

    /// Unwinds when the next call of kind `at` was scripted to; `resume_unwind` skips the panic hook, so the test output stays clean.
    fn unwind_at(&mut self, at: Unwind) {
        if self.unwind.take_if(|scripted| *scripted == at).is_some() {
            std::panic::resume_unwind(Box::new("the driver unwound"));
        }
    }

    fn position(&self, token: CommandToken) -> Option<usize> {
        self.pending
            .iter()
            .position(|command| command.token == token)
    }

    /// Moves the first `len` bytes between the device store and host memory, XORing each with `0x5A` when `flip` is set.
    fn transfer(&mut self, at: usize, len: usize, flip: bool) {
        let command = &self.pending[at];
        let (op, token, memory) = (command.op, command.token, command.memory);
        let start = usize::try_from(command.device.start()).unwrap();
        let offset = memory.offset();
        let media = Rc::clone(&self.store);
        let mut media = media.borrow_mut();
        let store = &mut media[start..start + len];
        let moved = match (op, self.config.mode) {
            (Operation::Read, Mode::Modeled { .. }) => {
                let host = &mut self.host[offset..offset + len];
                host.copy_from_slice(store);
                host
            }
            (Operation::Write, Mode::Modeled { .. }) => {
                store.copy_from_slice(&self.host[offset..offset + len]);
                store
            }
            (Operation::Read, Mode::Direct) => {
                // SAFETY: `memory` belongs to a pending command, so the submit's caller keeps it mapped and reached by no other path; `len <= memory.byte_len()`, and the slice ends with this call.
                let host = unsafe { slice::from_raw_parts_mut(memory.addr().as_ptr(), len) };
                host.copy_from_slice(store);
                host
            }
            (Operation::Write, Mode::Direct) => {
                // SAFETY: as for the read; a write only reads its memory.
                store
                    .copy_from_slice(unsafe { slice::from_raw_parts(memory.addr().as_ptr(), len) });
                store
            }
        };
        if flip {
            for byte in moved.iter_mut() {
                *byte ^= 0x5A;
            }
        }
        if let (Operation::Write, Some(attempts), false) =
            (op, &mut self.attempts, moved.is_empty())
        {
            attempts.push(Attempt {
                start: start as u64,
                bytes: moved.to_vec(),
            });
        }
        self.log(Event::Executed { token, offset, len });
    }

    /// Lands the write at `at` sector by sector in place: each whole 512-byte sector keeps its preimage, takes its new bytes, or takes garbage, as a generator over `seed` and the sector's index chooses; the device's own generator is untouched, and nothing allocates unless the device records write attempts, when each run of changed sectors is copied into the record.
    fn land(&mut self, at: usize, seed: u64) {
        let command = &self.pending[at];
        let memory = command.memory;
        let start = usize::try_from(command.device.start()).unwrap();
        let sectors = command.device.byte_len() as usize / SECTOR;
        debug_assert!((command.device.byte_len() as usize).is_multiple_of(SECTOR));
        let media = Rc::clone(&self.store);
        let mut media = media.borrow_mut();
        // The first sector of the run of changed sectors that sector `index - 1` ends.
        let mut changed = None;
        for index in 0..sectors {
            let mut choice =
                SplitMix64::new(seed ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let sector = &mut media[start + index * SECTOR..start + (index + 1) * SECTOR];
            let offset = memory.offset() + index * SECTOR;
            match choice.below(3) {
                0 => {
                    if let Some(first) = changed.take() {
                        record_run(&mut self.attempts, &media, start, first..index);
                    }
                    continue;
                }
                1 => match self.config.mode {
                    Mode::Modeled { .. } => {
                        sector.copy_from_slice(&self.host[offset..offset + SECTOR]);
                    }
                    Mode::Direct => {
                        // SAFETY: as for a write's transfer: `memory` belongs to a pending command, so the submit's caller keeps it mapped and reached by no other path; the sector lies inside `memory`'s length, since `submit` refuses a device length that differs from the memory's and `index < byte_len / SECTOR`; a write only reads its memory.
                        sector.copy_from_slice(unsafe {
                            slice::from_raw_parts(
                                memory.addr().as_ptr().add(index * SECTOR),
                                SECTOR,
                            )
                        });
                    }
                },
                _ => {
                    for word in sector.as_chunks_mut::<8>().0 {
                        *word = choice.next_u64().to_le_bytes();
                    }
                }
            }
            changed.get_or_insert(index);
        }
        if let Some(first) = changed {
            record_run(&mut self.attempts, &media, start, first..sectors);
        }
    }

    /// Moves the command's bytes, applying its fault, records the status to post, and returns it.
    /// A dropped command leaves the queue here and returns `None`; an omitted one stays pending and returns `None` on every call.
    fn execute(&mut self, at: usize) -> Option<DeviceStatus> {
        let command = &mut self.pending[at];
        match command.progress {
            Progress::Waiting => {}
            Progress::Executed(status) => return Some(status),
            Progress::Omitted(_) => return None,
        }
        let (token, len) = (command.token, command.device.byte_len());
        let (delay, fault) = (command.delay.take(), command.fault.take());
        if let Some(delay) = delay {
            let elapsed = self.now - delay.set;
            self.log(Event::Delayed { token, elapsed });
        }
        let full = len as usize;
        let status = match fault {
            None => {
                self.transfer(at, full, false);
                self.success(len)
            }
            Some(Fault::Status(status)) => status,
            Some(Fault::Short { units }) => {
                let moved = (units as usize * UNIT).min(full);
                self.transfer(at, moved, false);
                DeviceStatus::Kernel(moved as i32)
            }
            Some(Fault::CorruptSuccess) => {
                self.transfer(at, full, true);
                self.success(len)
            }
            Some(Fault::TornWrite { sectors } | Fault::PartialReadFailure { sectors }) => {
                self.transfer(at, (sectors as usize * SECTOR).min(full), false);
                self.failure()
            }
            Some(Fault::DropCommand) => {
                self.pending.swap_remove(at);
                self.log(Event::Lost(token));
                return None;
            }
            Some(Fault::DropCompletion) => {
                self.transfer(at, full, false);
                self.pending.swap_remove(at);
                self.log(Event::Lost(token));
                return None;
            }
            Some(
                Fault::MisdirectedRead { source: other }
                | Fault::MisdirectedWrite { target: other },
            ) => {
                self.misdirect(at, other);
                self.success(len)
            }
            Some(Fault::UnqualifiedLanding { seed }) => {
                self.land(at, seed);
                self.pending[at].progress = Progress::Omitted(Omission::Episode);
                self.log(Event::Landed { token, seed });
                return None;
            }
            Some(Fault::Omit(class)) => {
                self.transfer(at, full, false);
                self.pending[at].progress = Progress::Omitted(class);
                if class == Omission::Hostile {
                    self.hostile += 1;
                }
                self.log(Event::Omitted(token, class));
                return None;
            }
        };
        self.pending[at].progress = Progress::Executed(status);
        Some(status)
    }

    /// Moves the bytes of the misdirected command at `at` against the equal-length range at device byte `other`, which admission placed in bounds and apart from the intended range, inside one restoration window.
    /// A read substitutes `other`'s bytes for the intended media and reads ordinarily; a write writes ordinarily and copies the bytes it produced to `other`, attributing that damage to the command.
    /// The guard restores the intended media before this returns or unwinds, so no observer or post sees the substitution.
    fn misdirect(&mut self, at: usize, other: u64) {
        let command = &self.pending[at];
        let (op, token) = (command.op, command.token);
        let start = usize::try_from(command.device.start()).unwrap();
        let len = command.device.byte_len() as usize;
        let other = usize::try_from(other).unwrap();
        let restore = Restore::snapshot(&self.store, &self.scratch, start, len);
        if op == Operation::Read {
            self.store
                .borrow_mut()
                .copy_within(other..other + len, start);
            self.transfer(at, len, false);
        } else {
            self.transfer(at, len, false);
            if let Some(attempt) = self
                .attempts
                .as_mut()
                .and_then(|attempts| attempts.last_mut())
            {
                attempt.start = other as u64;
            }
            let mut media = self.store.borrow_mut();
            media.copy_within(start..start + len, other);
            let digest = Sha256::digest(&media[other..other + len]).into();
            drop(media);
            self.attribute(Damage {
                start: other as u64,
                len: len as u64,
                token: Some(token),
                digest,
            });
        }
        self.log(Event::Misdirected {
            token,
            at: other as u64,
        });
        if std::mem::take(&mut self.unwind_misdirection) {
            std::panic::resume_unwind(Box::new("the device unwound inside a misdirection"));
        }
        drop(restore);
    }

    /// Executes the command at `at` if needed and posts its completion with its delivery gate open when `eligible`; `false` when a drop fault lost the command or an omission withholds its completion.
    fn post(&mut self, at: usize, eligible: bool) -> bool {
        let Some(status) = self.execute(at) else {
            return false;
        };
        let command = self.pending.swap_remove(at);
        self.posted.push_back(Posted {
            completion: Completion {
                token: command.token,
                status,
            },
            provenance: Provenance::Device {
                op: command.op,
                ordinal: command.ordinal,
                host: command.memory.offset(),
                len: command.memory.byte_len(),
            },
            eligible,
        });
        self.mark();
        self.log(Event::Posted(command.token));
        if eligible {
            self.log(Event::Admitted(command.token));
        }
        true
    }

    /// Picks up to `max` commands of `stage`'s ready set in seeded order over the pending store's order, and executes each, also posting it for `Stage::Post`.
    fn tick(&mut self, max: u32, stage: Stage) {
        if self.halted {
            return;
        }
        for _ in 0..max {
            let (pending, now) = (&self.pending, self.now);
            let ready = |at: &usize| pending[*at].ready_for(stage, now);
            let count = (0..pending.len()).filter(ready).count();
            if count == 0 {
                return;
            }
            let pick = self.rng.below(count as u64) as usize;
            let Some(at) = (0..pending.len()).filter(ready).nth(pick) else {
                return;
            };
            if stage == Stage::Execute {
                let _ = self.execute(at);
            } else {
                let _ = self.post(at, true);
            }
        }
    }
}

// SAFETY: I1 refused submits log no transfer and are never queued. I2 each accepted command is posted at most once and never after a reset; a held, delayed or halted command waits, a completion behind a closed gate waits for its admission, `DropCommand` and `DropCompletion` lose it on purpose, and an omission or an unqualified landing withholds its completion while the command stays pending, so a caller facing a missing completion keeps the memory owned until a proven stop. I3 every transfer and landing stays inside the command's range; a misdirection moves media against another device range and never another memory range. I4 in `Direct` mode the copy happens before the post, on the same thread. I5 delivery stops at the first refused push and keeps the completion in its place. I6 `Stopped` is returned only after the reset emptied both queues and marked the device gone, except under the hostile `FalseStopped` control, which `set_quiesce` admits only on a `Modeled` device, whose executions touch the host shadow and no memory; there late completions are still picked and later submits accepted, and a table sees them as stale or as new commands. I7 status and geometry pass through unchanged. I8 no bytes move outside an accepted command's range, except under a scripted misdirection, which moves media against one other device range that admission bounded inside the device and apart from the intended range, touches no memory beyond the command's own (I3), and restores the intended range through its guard before the post or an unwind. I9 only this disk half implements `Disk` and picks completions. I10 a scripted unwind happens before a submit queues its command or a pick takes a completion, so an unwound submit never touches its memory; the misdirection unwind fires inside a control-half execution (`execute`, `post`, `tick`, `execute_tick` or `select`), never inside a `Disk` method. The submit assert enforces the caller's token uniqueness against every pending command and posted completion. The control half's `inject` posts a completion the device did not produce, bypassing I2; it refuses a token the device still holds pending and a gone device, and a submit of an injected token panics while the injection is posted, so no execution touches memory a table returned on an injected completion.
unsafe impl Disk for SimDisk {
    fn geometry(&self) -> DeviceGeometry {
        let core = self.0.borrow();
        DeviceGeometry {
            capacity: core.config.capacity,
            max_transfer: core.config.max_transfer,
            block_size: core.block_size,
            queue_depth: core.config.queue_depth,
        }
    }

    unsafe fn submit_read(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        self.0
            .borrow_mut()
            .submit(Operation::Read, token, device, memory)
    }

    unsafe fn submit_write(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        self.0
            .borrow_mut()
            .submit(Operation::Write, token, device, memory)
    }

    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
        let mut core = self.0.borrow_mut();
        core.calls += 1;
        core.unwind_at(Unwind::Pick);
        let mut at = 0;
        while at < core.posted.len() {
            let posted = core.posted[at];
            if !posted.eligible {
                at += 1;
                continue;
            }
            if sink.push(posted.completion).is_err() {
                break;
            }
            core.posted.remove(at);
            match posted.provenance {
                Provenance::Device { op, .. } => {
                    core.delivered[slot(op)] += 1;
                    core.capture(Captured::Delivered {
                        token: posted.completion.token,
                        status: posted.completion.status,
                    });
                }
                Provenance::Injected(_) => {
                    core.injected -= 1;
                    core.delivered_injections += 1;
                }
            }
            core.log(Event::Delivered(posted.completion.token));
        }
    }

    fn service(&mut self) {
        self.0.borrow_mut().calls += 1;
    }

    fn admit_medium(&mut self, _gate: &crate::storage::Fenced) {
        self.0.borrow_mut().calls += 1;
    }

    fn attach_facts(&self) -> Option<&AttachFacts> {
        self.1.as_ref()
    }

    fn quiesce(&mut self) -> QuiesceStatus {
        let mut core = self.0.borrow_mut();
        core.calls += 1;
        match core.quiesce {
            QuiesceMode::AllReturned => QuiesceStatus::Pending,
            QuiesceMode::Unproven => {
                core.halted = true;
                QuiesceStatus::Pending
            }
            QuiesceMode::Failed(code) => QuiesceStatus::Failed(code),
            QuiesceMode::FalseStopped => {
                core.log(Event::FalseStopped);
                QuiesceStatus::Stopped
            }
            QuiesceMode::Reset => {
                core.pending.clear();
                core.posted.clear();
                core.injected = 0;
                core.gone = true;
                core.log(Event::Stopped);
                QuiesceStatus::Stopped
            }
        }
    }
}

impl SimControl {
    /// The seed and the event ring, for assertion messages.
    pub(crate) fn describe(&self) -> String {
        self.0.borrow().describe()
    }

    pub(crate) fn events(&self) -> Vec<Event> {
        self.0.borrow().events.iter().copied().collect()
    }

    pub(crate) fn capture(&self) -> Capture {
        let core = self.0.borrow();
        Capture {
            accepted: core.ordinals,
            ..core.capture.clone()
        }
    }

    /// Lowers the capture's bound, the most events it holds before flagging overflow, to at most its reserved room.
    pub(crate) fn set_capture_bound(&self, bound: usize) {
        self.0.borrow_mut().capture_bound = bound.min(CAPTURE_BOUND);
    }

    /// Empties the capture and clears its overflow flag; the device's acceptance ordinals continue.
    pub(crate) fn clear_capture(&self) {
        let mut core = self.0.borrow_mut();
        core.capture.events.clear();
        core.capture.overflow = false;
    }

    /// Restarts the device's event log, capture, command counts and acceptance ordinals as for a device whose life begins now, for a test that observes only the commands after a volume's bootstrap; the clock continues.
    ///
    /// # Panics
    ///
    /// When the device holds a pending command or a posted completion, whose ordinal the restart would orphan.
    pub(crate) fn rebase(&self) {
        let mut core = self.0.borrow_mut();
        assert!(
            core.pending.is_empty() && core.posted.is_empty(),
            "a rebase with commands in flight"
        );
        core.ordinals = 0;
        core.events.clear();
        core.capture.events.clear();
        core.capture.overflow = false;
        core.evicted = 0;
        core.calls = 0;
        core.accepted = [0; 2];
        core.delivered = [0; 2];
        core.refused = [0; 2];
    }

    /// Events the bounded log dropped to make room, over the device's life.
    pub(crate) fn evicted(&self) -> u64 {
        self.0.borrow().evicted
    }

    /// Events the log recorded over the device's life: those it dropped to
    /// make room and those it holds.
    pub(crate) fn logged(&self) -> u64 {
        let core = self.0.borrow();
        core.evicted + core.events.len() as u64
    }

    /// Commands of `op` the device accepted, over its life.
    pub(crate) fn accepted(&self, op: Operation) -> usize {
        self.0.borrow().accepted[slot(op)]
    }

    /// Completions the device produced for `op` commands and the driver delivered to its caller, over its life.
    pub(crate) fn delivered(&self, op: Operation) -> usize {
        self.0.borrow().delivered[slot(op)]
    }

    /// Submits refused with `origin`, over the device's life.
    pub(crate) fn refused(&self, origin: Origin) -> usize {
        self.0.borrow().refused[origin_slot(origin)]
    }

    /// Injected completions the driver delivered to its caller, over its life.
    pub(crate) fn delivered_injections(&self) -> usize {
        self.0.borrow().delivered_injections
    }

    /// The device's high-water marks and its stores' current capacity.
    pub(crate) fn footprint(&self) -> Footprint {
        let core = self.0.borrow();
        Footprint {
            reserved: Reserved {
                pending: core.pending.capacity(),
                posted: core.posted.capacity(),
                refusals: core.refusals.capacity(),
                damage: core.damage.capacity(),
                scratch: core.scratch.borrow().capacity(),
            },
            ..core.footprint
        }
    }

    pub(crate) fn outstanding(&self) -> usize {
        self.0.borrow().outstanding()
    }

    /// Every command the device holds, in acceptance order: each pending command and each posted device completion a pick has not delivered, with the memory it names.
    /// Injected completions name no memory and are left out. The call changes nothing on the device.
    pub(crate) fn held(&self) -> Vec<HeldCommand> {
        let core = self.0.borrow();
        let pending = core.pending.iter().map(|command| HeldCommand {
            token: command.token,
            operation: command.op,
            host: command.memory.offset(),
            len: command.memory.byte_len(),
            ordinal: command.ordinal,
            moved: command.progress != Progress::Waiting,
            posted: false,
        });
        let posted = core.posted.iter().filter_map(|posted| {
            let Provenance::Device {
                op,
                ordinal,
                host,
                len,
            } = posted.provenance
            else {
                return None;
            };
            Some(HeldCommand {
                token: posted.completion.token,
                operation: op,
                host,
                len,
                ordinal,
                moved: true,
                posted: true,
            })
        });
        let mut held: Vec<HeldCommand> = pending.chain(posted).collect();
        held.sort_by_key(|entry| entry.ordinal);
        held
    }

    /// Commands accepted and not yet posted, executed or not.
    pub(crate) fn pending(&self) -> usize {
        self.0.borrow().pending.len()
    }

    /// The returned media shares the device's backing store.
    pub(crate) fn shared_media(&self) -> Media {
        Rc::clone(&self.0.borrow().store)
    }

    /// Pending commands whose bytes already moved.
    pub(crate) fn executed_unposted(&self) -> usize {
        let core = self.0.borrow();
        core.pending
            .iter()
            .filter(|command| command.progress != Progress::Waiting)
            .count()
    }

    /// Posted completions whose delivery gate is open, which a pick would deliver.
    pub(crate) fn deliverable(&self) -> usize {
        self.0
            .borrow()
            .posted
            .iter()
            .filter(|posted| posted.eligible)
            .count()
    }

    /// Submits, picks, services, medium admissions and quiesces the disk half has received.
    pub(crate) fn driver_calls(&self) -> usize {
        self.0.borrow().calls
    }

    /// Keeps pending `token` out of every tick and ready set until [`release`](Self::release).
    ///
    /// # Errors
    ///
    /// `NotPending` when the device holds no pending command `token`.
    pub(crate) fn try_hold(&self, token: CommandToken) -> Result<(), ScriptRefusal> {
        let mut core = self.0.borrow_mut();
        let at = core.pending_at(ScriptKind::Hold, token)?;
        core.pending[at].held = true;
        Ok(())
    }

    /// [`try_hold`](Self::try_hold), panicking on a refusal.
    pub(crate) fn hold(&self, token: CommandToken) {
        self.try_hold(token)
            .unwrap_or_else(|refusal| self.panic(refusal));
    }

    /// Ends a hold on `token`; a command that is not pending carries none.
    pub(crate) fn release(&self, token: CommandToken) {
        let mut core = self.0.borrow_mut();
        if let Some(at) = core.position(token) {
            core.pending[at].held = false;
        }
    }

    fn panic(&self, refusal: ScriptRefusal) -> ! {
        panic!("{refusal:?}\n{}", self.describe())
    }

    /// The tokens of `stage`'s ready set, in acceptance order.
    pub(crate) fn ready(&self, stage: Stage) -> Vec<CommandToken> {
        let core = self.0.borrow();
        core.ready(stage).iter().map(|entry| entry.token).collect()
    }

    /// `stage`'s ready set as canonical choice candidates, in the same order: the disk domain, the stage, the acceptance ordinal big-endian, the operation (0 read, 1 write), and for a pending command the device range's length in sectors and start in I/O units, big-endian.
    /// The bytes name the command by the device's own acceptance count, never by the caller's token, an address or a clock, and sort in acceptance order.
    ///
    /// # Panics
    ///
    /// When a range's length exceeds 65,535 sectors or its start 2^24 - 1 I/O units, which no simulated geometry reaches.
    pub(crate) fn candidates(&self, stage: Stage) -> Vec<Candidate> {
        let core = self.0.borrow();
        core.ready(stage)
            .iter()
            .map(|entry| {
                let mut bytes = [0; CANDIDATE_LEN];
                bytes[0] = Domain::Disk as u8;
                bytes[1] = stage as u8;
                bytes[2..10].copy_from_slice(&entry.ordinal.to_be_bytes());
                bytes[10] = match entry.op {
                    Operation::Read => 0,
                    Operation::Write => 1,
                };
                if let Some(device) = entry.device {
                    let len = u16::try_from(device.byte_len() / SECTOR as u32)
                        .expect("a transfer below 65,536 sectors");
                    let start = u32::try_from(device.start() / UNIT as u64)
                        .ok()
                        .filter(|start| *start < 1 << 24)
                        .expect("a start below 2^24 units");
                    bytes[11..13].copy_from_slice(&len.to_be_bytes());
                    bytes[13..16].copy_from_slice(&start.to_be_bytes()[1..]);
                }
                Candidate(bytes)
            })
            .collect()
    }

    /// Applies `stage`'s ready entry `index`: `Execute` moves its bytes without posting, `Post` executes it if needed and posts its completion behind a closed gate, and `Admit` opens a posted completion's gate.
    ///
    /// # Errors
    ///
    /// `Selection` when `index` names no ready entry.
    pub(crate) fn select(&self, stage: Stage, index: usize) -> Result<Selected, ScriptRefusal> {
        let mut core = self.0.borrow_mut();
        let entry = core.selected(stage, index)?;
        let effect = match stage {
            Stage::Execute if core.execute(entry.at).is_some() => Effect::Executed,
            Stage::Post if core.post(entry.at, false) => Effect::Posted,
            // A drop removes the command; an omission leaves it pending.
            Stage::Execute | Stage::Post if core.position(entry.token).is_some() => Effect::Omitted,
            Stage::Execute | Stage::Post => Effect::Lost,
            Stage::Admit => {
                core.posted[entry.at].eligible = true;
                core.log(Event::Admitted(entry.token));
                Effect::Admitted
            }
        };
        Ok(Selected {
            token: entry.token,
            effect,
        })
    }

    /// Moves `token`'s bytes now without posting its completion.
    ///
    /// # Panics
    ///
    /// When `token` is not pending or a gray delay still holds it.
    pub(crate) fn execute(&self, token: CommandToken) {
        let mut core = self.0.borrow_mut();
        let at = core.due_position(token);
        let _ = core.execute(at);
    }

    /// Executes `token` if needed and posts its completion with its delivery gate open; a dropped command or completion posts nothing and logs `Lost`, and an omitted one stays pending and posts nothing.
    ///
    /// # Panics
    ///
    /// When `token` is not pending or a gray delay still holds it.
    pub(crate) fn post(&self, token: CommandToken) {
        let mut core = self.0.borrow_mut();
        let at = core.due_position(token);
        let _ = core.post(at, true);
    }

    /// One tick of up to `max` commands, executed and posted.
    pub(crate) fn tick(&self, max: u32) {
        self.0.borrow_mut().tick(max, Stage::Post);
    }

    /// One tick of up to `max` commands whose bytes move without a completion being posted.
    pub(crate) fn execute_tick(&self, max: u32) {
        self.0.borrow_mut().tick(max, Stage::Execute);
    }

    /// Applies `fault` to pending `token` when it executes.
    ///
    /// # Errors
    ///
    /// `try_fault` returns `NotPending` when `token` identifies no pending command, `Executed` when the command's bytes have moved, or `Faulted` when the command already carries a fault. For misdirection, it returns `Operation` when the fault targets a different operation, `OutOfBounds` when the redirected range exceeds the device bounds, or `Overlap` when that range overlaps the intended range. For a misdirected write, it returns `Full` when existing damage records plus reservations for pending misdirected writes reach or exceed `config.script.damage`. It returns `Operation` for an unqualified landing on a read, and `Qualified` when the device's profile qualifies the write's range and the fault [`breaks_whole_landing`](Fault::breaks_whole_landing).
    pub(crate) fn try_fault(&self, token: CommandToken, fault: Fault) -> Result<(), ScriptRefusal> {
        let mut core = self.0.borrow_mut();
        let at = core.pending_at(ScriptKind::Fault, token)?;
        core.admit_fault(at, fault)
            .map_err(|reason| ScriptRefusal {
                kind: ScriptKind::Fault,
                reason,
            })?;
        core.pending[at].fault = Some(fault);
        Ok(())
    }

    /// [`try_fault`](Self::try_fault), panicking on a refusal.
    pub(crate) fn fault(&self, token: CommandToken, fault: Fault) {
        self.try_fault(token, fault)
            .unwrap_or_else(|refusal| self.panic(refusal));
    }

    /// Keeps pending `token` out of every ready set until the device clock reaches `until`, then lets it execute and terminate as any other command; the command holds its queue room meanwhile.
    /// The clock only moves forward and a command takes one delay, so once the command is eligible it stays eligible.
    ///
    /// # Errors
    ///
    /// `NotPending` when the device holds no pending command `token`, `Executed` when its bytes already moved, `Delayed` when it already carries a delay, or `Past` when the clock already passed `until`.
    pub(crate) fn try_delay(&self, token: CommandToken, until: u64) -> Result<(), ScriptRefusal> {
        let mut core = self.0.borrow_mut();
        let at = core.pending_at(ScriptKind::Delay, token)?;
        let now = core.now;
        let command = &mut core.pending[at];
        let admitted = if command.progress != Progress::Waiting {
            Err(ScriptReason::Executed(token))
        } else if command.delay.is_some() {
            Err(ScriptReason::Delayed(token))
        } else if until < now {
            Err(ScriptReason::Past { until, now })
        } else {
            Ok(())
        };
        admitted.map_err(|reason| ScriptRefusal {
            kind: ScriptKind::Delay,
            reason,
        })?;
        command.delay = Some(Delay { set: now, until });
        Ok(())
    }

    /// [`try_delay`](Self::try_delay), panicking on a refusal.
    pub(crate) fn delay(&self, token: CommandToken, until: u64) {
        self.try_delay(token, until)
            .unwrap_or_else(|refusal| self.panic(refusal));
    }

    /// Sets the device clock to `now`, the time the test's turn controller reached.
    ///
    /// # Panics
    ///
    /// When `now` is earlier than the device clock, which only moves forward.
    pub(crate) fn advance_to(&self, now: u64) {
        let mut core = self.0.borrow_mut();
        assert!(now >= core.now, "the device clock moves only forward");
        core.now = now;
    }

    /// The earliest time after the device clock at which a pending command's gray delay ends, for a turn controller to schedule; `None` when no delay ends later.
    /// A delay whose time the clock reached leaves its command due, which the ready sets show.
    pub(crate) fn next_due(&self) -> Option<u64> {
        let core = self.0.borrow();
        core.pending
            .iter()
            .filter_map(|command| command.delay.map(|delay| delay.until))
            .filter(|until| *until > core.now)
            .min()
    }

    /// The device clock.
    pub(crate) fn now(&self) -> u64 {
        self.0.borrow().now
    }

    /// Changes every byte of the whole 512-byte sectors in `start..start + len` through the raw media, attributes the damage to no command, and returns its record.
    ///
    /// # Errors
    ///
    /// `Unaligned` when the range is empty or covers part of a sector, `OutOfBounds` when it passes the device's capacity, or `Full` when the damage records fill the [`ScriptCapacity`]; each refusal leaves the media as it was.
    pub(crate) fn try_damage(&self, start: u64, len: u64) -> Result<Damage, ScriptRefusal> {
        let mut core = self.0.borrow_mut();
        let sector = SECTOR as u64;
        let admitted = if len == 0 || !start.is_multiple_of(sector) || !len.is_multiple_of(sector) {
            Err(ScriptReason::Unaligned { start, len })
        } else {
            core.fits(start, len).and_then(|()| core.damage_room())
        };
        admitted.map_err(|reason| ScriptRefusal {
            kind: ScriptKind::Damage,
            reason,
        })?;
        let range = usize::try_from(start).unwrap()..usize::try_from(start + len).unwrap();
        let mut media = core.store.borrow_mut();
        for byte in &mut media[range.clone()] {
            *byte ^= DAMAGE_XOR;
        }
        let damage = Damage {
            start,
            len,
            token: None,
            digest: Sha256::digest(&media[range]).into(),
        };
        drop(media);
        core.attribute(damage);
        Ok(damage)
    }

    /// [`try_damage`](Self::try_damage), panicking on a refusal.
    pub(crate) fn damage(&self, start: u64, len: u64) -> Damage {
        self.try_damage(start, len)
            .unwrap_or_else(|refusal| self.panic(refusal))
    }

    /// Every damage record the device attributes, in the order it was made.
    pub(crate) fn damaged(&self) -> Vec<Damage> {
        self.0.borrow().damage.clone()
    }

    /// Hostile omissions over the device's life, which a reset leaves counted.
    pub(crate) fn hostile(&self) -> u64 {
        self.0.borrow().hostile
    }

    /// The pending commands whose completion an omission withholds, with its class, in queue order.
    pub(crate) fn omitted(&self) -> Vec<(CommandToken, Omission)> {
        let core = self.0.borrow();
        core.pending
            .iter()
            .filter_map(|command| match command.progress {
                Progress::Omitted(class) => Some((command.token, class)),
                _ => None,
            })
            .collect()
    }

    /// Makes the next misdirected execution unwind after it substituted or copied its bytes, before its guard restores the intended media.
    pub(crate) fn unwind_next_misdirection(&self) {
        self.0.borrow_mut().unwind_misdirection = true;
    }

    /// Posts `completion` as if the device reported it, as a containment control of class `class`, with its delivery gate open; it holds injection capacity, not queue depth, until delivered or reset.
    ///
    /// # Errors
    ///
    /// `Gone` when the device is gone, `Pending` when the device still holds the named command pending, since a table would then return a buffer this device may later write, or `Full` when the injections in flight fill the [`ScriptCapacity`].
    pub(crate) fn try_inject(
        &self,
        completion: Completion,
        class: Injection,
    ) -> Result<(), ScriptRefusal> {
        let mut core = self.0.borrow_mut();
        let capacity = core.config.script.injections;
        let refused = if core.gone {
            Some(ScriptReason::Gone)
        } else if core.position(completion.token).is_some() {
            Some(ScriptReason::Pending(completion.token))
        } else if core.injected >= capacity as usize {
            Some(ScriptReason::Full { capacity })
        } else {
            None
        };
        if let Some(reason) = refused {
            return Err(ScriptRefusal {
                kind: ScriptKind::Injection,
                reason,
            });
        }
        core.posted.push_back(Posted {
            completion,
            provenance: Provenance::Injected(class),
            eligible: true,
        });
        core.injected += 1;
        core.mark();
        core.log(Event::Injected(completion.token, class));
        core.log(Event::Admitted(completion.token));
        Ok(())
    }

    /// [`try_inject`](Self::try_inject), panicking on a refusal.
    pub(crate) fn inject(&self, completion: Completion, class: Injection) {
        self.try_inject(completion, class)
            .unwrap_or_else(|refusal| self.panic(refusal));
    }

    /// Refuses the next submit with `refusal`, whatever its arguments.
    /// A `DeviceGone` refusal also marks the device gone, so every later submit is refused too.
    ///
    /// # Errors
    ///
    /// `Full` when the queued scripted refusals fill the [`ScriptCapacity`].
    pub(crate) fn try_refuse_next(&self, refusal: SubmitRefusal) -> Result<(), ScriptRefusal> {
        let mut core = self.0.borrow_mut();
        let capacity = core.config.script.refusals;
        if core.refusals.len() >= capacity as usize {
            return Err(ScriptRefusal {
                kind: ScriptKind::Refusal,
                reason: ScriptReason::Full { capacity },
            });
        }
        core.refusals.push_back(refusal);
        core.mark();
        Ok(())
    }

    /// [`try_refuse_next`](Self::try_refuse_next), panicking on a refusal.
    pub(crate) fn refuse_next(&self, refusal: SubmitRefusal) {
        self.try_refuse_next(refusal)
            .unwrap_or_else(|refusal| self.panic(refusal));
    }

    /// Makes the next driver call of kind `at` unwind; `None` disarms a scripted unwind.
    pub(crate) fn unwind_next(&self, at: Option<Unwind>) {
        self.0.borrow_mut().unwind = at;
    }

    /// Sets the block size the geometry reports, for a table built afterwards.
    ///
    /// # Panics
    ///
    /// When the device carries scripted attach facts, whose identity fixed the block size at construction.
    pub(crate) fn set_block_size(&self, block_size: u32) {
        let mut core = self.0.borrow_mut();
        assert!(
            !core.attached,
            "an attached device's block size is its identity's sector size"
        );
        core.block_size = block_size;
    }

    /// The profile the device derived from its scripted facts at construction.
    pub(crate) fn profile(&self) -> Option<PersistenceProfile> {
        self.0.borrow().profile.clone()
    }

    /// The next value the device's own generator would draw, read from a copy so the generator is untouched.
    pub(crate) fn peek_rng(&self) -> u64 {
        self.0.borrow().rng.clone().next_u64()
    }

    pub(crate) fn set_halted(&self, halted: bool) {
        self.0.borrow_mut().halted = halted;
    }

    /// Makes every later submit fail `DeviceGone`; commands already accepted stay outstanding.
    pub(crate) fn set_gone(&self) {
        self.0.borrow_mut().gone = true;
    }

    /// # Panics
    ///
    /// When `mode` is `FalseStopped` and the device runs in `Direct` mode, whose late access would touch memory its caller took back.
    pub(crate) fn set_quiesce(&self, mode: QuiesceMode) {
        let mut core = self.0.borrow_mut();
        assert!(
            mode != QuiesceMode::FalseStopped || matches!(core.config.mode, Mode::Modeled { .. }),
            "a false stop needs a modeled device"
        );
        core.quiesce = mode;
    }

    pub(crate) fn write_device(&self, start: usize, bytes: &[u8]) {
        self.0.borrow().store.borrow_mut()[start..start + bytes.len()].copy_from_slice(bytes);
    }

    pub(crate) fn device(&self, start: usize, len: usize) -> Vec<u8> {
        self.0.borrow().store.borrow()[start..start + len].to_vec()
    }

    /// Copies the device bytes of `range` into `out`, passively: `false`
    /// when the device is borrowed elsewhere or `range` passes its store,
    /// leaving `out` as it was. `out` grows only once the range is known to
    /// lie inside the store.
    pub(crate) fn try_device_into(&self, range: std::ops::Range<usize>, out: &mut Vec<u8>) -> bool {
        let Ok(core) = self.0.try_borrow() else {
            return false;
        };
        let Ok(media) = core.store.try_borrow() else {
            return false;
        };
        let Some(bytes) = media.get(range) else {
            return false;
        };
        out.clear();
        out.extend_from_slice(bytes);
        true
    }

    /// Mirrors a host write into the modeled shadow.
    pub(crate) fn write_host(&self, offset: usize, bytes: &[u8]) {
        self.0.borrow_mut().host[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Host bytes as the modeled shadow holds them.
    pub(crate) fn host(&self, offset: usize, len: usize) -> Vec<u8> {
        self.0.borrow().host[offset..offset + len].to_vec()
    }

    /// Starts recording every write the device executes as an [`Attempt`].
    pub(crate) fn record_attempts(&self) {
        self.0.borrow_mut().attempts.get_or_insert_default();
    }

    /// The writes the device executed since [`record_attempts`](Self::record_attempts), in execution order.
    pub(crate) fn attempts(&self) -> Vec<Attempt> {
        self.0.borrow().attempts.clone().unwrap_or_default()
    }

    /// The bytes pending write `token` carries in its host memory, copied without moving any; `None` when no pending write carries `token`.
    pub(crate) fn submitted(&self, token: CommandToken) -> Option<Vec<u8>> {
        let core = self.0.borrow();
        let command = core
            .pending
            .iter()
            .find(|command| command.token == token && command.op == Operation::Write)?;
        let len = command.device.byte_len() as usize;
        let memory = command.memory;
        Some(match core.config.mode {
            Mode::Modeled { .. } => core.host[memory.offset()..memory.offset() + len].to_vec(),
            // SAFETY: as for a write's transfer: `memory` belongs to a pending command, so the submit's caller keeps it mapped and reached by no other path, `len <= memory.byte_len()`, the read only reads, and the slice ends with this copy.
            Mode::Direct => unsafe { slice::from_raw_parts(memory.addr().as_ptr(), len) }.to_vec(),
        })
    }
}
