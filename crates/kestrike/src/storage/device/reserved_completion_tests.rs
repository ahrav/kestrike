//! A completion or cancel naming a token reaches the record whose slot issued it only when that record's
//! command is accepted or detached. A command whose driver call never returned is reserved: the device may
//! still access its buffer (`Disk`, I10), so a completion that names its exact token is stale, and only a
//! proven stop ends the command.
//!
//! The tests run their reads through a `CommandTable` over a heap arena and a scripted driver.
//! The driver records the latest submission token. On request, it reports one successful completion with the
//! test-specified token or returns `QuiesceStatus::Stopped` when quiesced.
//!
//! - `a_completion_naming_a_reserved_command_is_stale_and_returns_no_buffer`: the driver's submit unwinds,
//!   which leaves the command reserved and admission lost. The poll that picks the completion delivers no
//!   terminal and counts one stale completion, the command stays pending with its buffer in storage custody,
//!   a cancel of the token answers `Stale`, a quiesce the driver cannot prove returns nothing, and the proven
//!   stop returns the buffer once, as `Quiesced`.
//! - `a_completion_naming_an_accepted_command_delivers_its_one_terminal`: the sibling. The driver accepts
//!   the submit, and the same completion delivers the command's one terminal with its buffer.
//! - `a_completion_naming_an_accepted_command_delivers_its_terminal_under_lost_admission`: the driver accepts
//!   the first read; the second read loses admission when its submit unwinds.
//!   The first read's completion delivers its terminal, and the proven stop returns the second read's buffer.
//!
//! Each test decides what it saw into a `Seen` value, lets the table, the terminals and the arena go, and
//! asserts afterwards, so a failing assertion unwinds through no fixture. The premises (the submit unwound
//! or was accepted, the record's phase, the completion entered the table's sink) are asserted first, apart
//! from the judgment.

use std::cell::Cell;
use std::rc::Rc;

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::TestPlatform;
use super::{
    Admission, BufferArena, BufferConfig, CommandTable, CommandToken, Completion, CompletionSink,
    DeviceGeometry, DeviceRange, DeviceStatus, Disk, DmaRange, Operation, PoolKind, PoolSpec,
    QuiesceProgress, QuiesceStatus, Quiesced, Stale, SubmitRefusal, Terminal,
};

const LEN: u32 = 16384;

const READS: u32 = 16;

const POOLS: [PoolSpec; 3] = [
    PoolSpec {
        kind: PoolKind::ReadResponse,
        count: READS,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::ReceiveWrite,
        count: 16,
        buffer_len: LEN,
    },
    PoolSpec {
        kind: PoolKind::Maintenance,
        count: 1,
        buffer_len: 4096,
    },
];

/// What the test and its driver share: the token the driver was given, what the test asked of the driver,
/// and what the driver did.
#[derive(Default)]
struct Script {
    /// The token of the latest submit.
    token: Cell<Option<CommandToken>>,
    /// A submit made while this is set unwinds.
    unwinds: Cell<bool>,
    /// The next pick reports one completion with this token.
    report: Cell<Option<CommandToken>>,
    /// Completions the table's sink took.
    pushed: Cell<u32>,
    /// The next quiesce proves a stop.
    stop: Cell<bool>,
}

/// A driver with no device. Its submit keeps the token, then unwinds or accepts.
struct Scripted {
    script: Rc<Script>,
}

// SAFETY: the driver reaches no device and no memory, so I3, I4 and I8 hold of every command. It reports a
// token only once and only after the one submit that named it; for a submit that unwound that report is
// the one I10 allows, and for an accepted one it is the completion I2 requires. `Stopped` is returned with
// no device access possible, and the tests submit nothing after it.
unsafe impl Disk for Scripted {
    fn geometry(&self) -> DeviceGeometry {
        DeviceGeometry {
            capacity: 1 << 20,
            max_transfer: LEN,
            block_size: 4096,
            queue_depth: 4,
        }
    }

    unsafe fn submit_read(
        &mut self,
        token: CommandToken,
        _: DeviceRange,
        _: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        self.script.token.set(Some(token));
        if self.script.unwinds.get() {
            panic!("the scripted driver's submit never returns");
        }
        Ok(())
    }

    unsafe fn submit_write(
        &mut self,
        _: CommandToken,
        _: DeviceRange,
        _: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        unreachable!("the scenario submits no write")
    }

    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
        let Some(token) = self.script.report.get() else {
            return;
        };
        let done = Completion {
            token,
            status: DeviceStatus::Kernel(LEN as i32),
        };
        if sink.push(done).is_ok() {
            self.script.report.set(None);
            self.script.pushed.set(self.script.pushed.get() + 1);
        }
    }

    fn quiesce(&mut self) -> QuiesceStatus {
        if self.script.stop.get() {
            QuiesceStatus::Stopped
        } else {
            QuiesceStatus::Pending
        }
    }
}

/// One terminal as a test keeps it once its buffer is gone: the token, and the buffer's offset in the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Read(CommandToken, usize, DeviceStatus),
    Quiesced(CommandToken, Operation, usize),
    Other(CommandToken),
}

fn ended(terminal: Terminal<'_>) -> Ended {
    match terminal {
        Terminal::Read {
            token,
            done,
            status,
        } => Ended::Read(token, done.into_buffer().offset(), status),
        Terminal::Quiesced { token, op, buffer } => Ended::Quiesced(token, op, buffer.offset()),
        other => Ended::Other(other.token()),
    }
}

fn custody(arena: &BufferArena<TestPlatform>) -> (u32, u32, u32) {
    let pool = arena.report(PoolKind::ReadResponse);
    (pool.storage, pool.application, pool.free)
}

/// What one run saw, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    /// The submit unwound, with the scripted driver's message.
    unwound: bool,
    /// The token the table returned from an accepted submit.
    returned: Option<CommandToken>,
    /// The token the driver was given.
    token: Option<CommandToken>,
    /// The offset of the buffer the read was submitted with.
    offset: usize,
    /// Whether the record the token names holds an accepted command, before the completion.
    accepted: Option<bool>,
    /// The token and buffer offset of a second read whose submit unwound after the first submit returned.
    bystander: Option<(CommandToken, usize)>,
    /// The table's pending commands and admission, and the pool's custody, before the completion.
    before: (u32, Admission, (u32, u32, u32)),
    /// Completions the table's sink took in the poll.
    pushed: u32,
    /// The poll's delivered and stale counts, and its terminals.
    poll: (usize, usize),
    polled: Vec<Ended>,
    /// The table's pending commands and stale total, and the pool's custody, after the poll.
    after: (u32, u64, (u32, u32, u32)),
    /// A cancel of the token after the poll.
    cancel: Result<(), Stale>,
    /// A quiesce the driver cannot prove, and its terminals.
    unproven: QuiesceProgress,
    unproven_ended: Vec<Ended>,
    /// The quiesce the driver proves, its terminals, and the custody once they are dropped.
    stopped: QuiesceProgress,
    stopped_ended: Vec<Ended>,
    last: (u32, (u32, u32, u32)),
    /// The arena released once the table was gone.
    released: bool,
}

/// One read through a table over a driver whose submit unwinds or accepts, then the completion that names
/// the read's token, a cancel, an unproven quiesce and the proven stop.
/// With `bystander`, a second read's submit unwinds and loses admission before the poll runs.
fn run(unwinds: bool, bystander: bool) -> Seen {
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
        pools: &POOLS,
    }
    .validate()
    .expect("a valid buffer configuration");
    let arena = BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .expect("a heap arena");
    let script = Rc::new(Script::default());
    script.unwinds.set(unwinds);
    let driver = Scripted {
        script: Rc::clone(&script),
    };
    let seen = {
        let mut table = CommandTable::new(driver, &arena, 4, &mut EngineBudget::new(usize::MAX))
            .map_err(|(error, _)| error)
            .expect("a table over the scripted driver");
        let buffer = arena
            .acquire(PoolKind::ReadResponse)
            .expect("a free read buffer");
        let offset = buffer.offset();
        let device = DeviceRange::new(0, LEN).expect("the first block");
        let submitted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            table.submit_read(buffer, device).ok()
        }));
        let unwound = submitted.as_ref().is_err_and(|panic| {
            panic.downcast_ref::<&str>() == Some(&"the scripted driver's submit never returns")
        });
        let returned = submitted.ok().flatten();
        let token = script.token.get();
        let bystander = bystander.then(|| {
            let buffer = arena
                .acquire(PoolKind::ReadResponse)
                .expect("a second free read buffer");
            let offset = buffer.offset();
            let device = DeviceRange::new(0, LEN).expect("the first block");
            script.unwinds.set(true);
            let submitted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                table.submit_read(buffer, device).ok()
            }));
            (submitted.is_err(), script.token.get(), offset)
        });
        let bystander = match bystander {
            Some((true, Some(reserved), offset)) => Some((reserved, offset)),
            _ => None,
        };
        let accepted = token.and_then(|token| table.evidence(token).map(|held| held.accepted));
        let report = table.report();
        let before = (report.pending, report.admission, custody(&arena));

        script.report.set(token);
        let mut out = Vec::with_capacity(4);
        let poll = table.poll(&mut out);
        let polled: Vec<Ended> = out.drain(..).map(ended).collect();
        let report = table.report();
        let after = (report.pending, report.stale, custody(&arena));
        let cancel = token.map_or(Err(Stale), |token| table.cancel(token));

        let unproven = table.quiesce(&mut out);
        let unproven_ended: Vec<Ended> = out.drain(..).map(ended).collect();
        script.stop.set(true);
        let stopped = table.quiesce(&mut out);
        let stopped_ended: Vec<Ended> = out.drain(..).map(ended).collect();
        let last = (table.report().pending, custody(&arena));
        Seen {
            unwound,
            returned,
            token,
            offset,
            accepted,
            bystander,
            before,
            pushed: script.pushed.get(),
            poll: (poll.delivered, poll.stale),
            polled,
            after,
            cancel,
            unproven,
            unproven_ended,
            stopped,
            stopped_ended,
            last,
            released: false,
        }
    };
    Seen {
        released: arena.release().is_ok(),
        ..seen
    }
}

/// A completion naming the exact token of a reserved command reaches no record. It is stale, the
/// command and its buffer stay with the table, and only the proven stop returns the buffer.
#[test]
fn a_completion_naming_a_reserved_command_is_stale_and_returns_no_buffer() {
    let seen = run(true, false);
    let token = seen
        .token
        .expect("premise: the driver was given the read's token");
    assert_eq!(
        (seen.unwound, seen.returned, seen.accepted),
        (true, None, Some(false)),
        "premise: the submit unwound and left the token's record holding a command that is not accepted"
    );
    assert_eq!(
        seen.before,
        (1, Admission::Lost, (1, 0, READS - 1)),
        "premise: the reserved command is pending, admission is lost and storage holds the buffer"
    );
    assert_eq!(
        seen.pushed, 1,
        "premise: the poll's pick put the completion naming the token into the table's sink"
    );
    assert_eq!(
        (seen.poll, seen.polled.as_slice()),
        ((0, 1), [].as_slice()),
        "a completion naming a reserved command's token is stale and delivers no terminal"
    );
    assert_eq!(
        seen.after,
        (1, 1, (1, 0, READS - 1)),
        "the reserved command stays pending and its buffer stays in storage custody"
    );
    assert_eq!(
        seen.cancel,
        Err(Stale),
        "a cancel naming a reserved command's token reaches no record"
    );
    assert_eq!(
        (seen.unproven, seen.unproven_ended.as_slice()),
        (QuiesceProgress::Draining { outstanding: 1 }, [].as_slice()),
        "without a proven stop the reserved command is still outstanding"
    );
    assert_eq!(
        (seen.stopped, seen.stopped_ended.as_slice()),
        (
            QuiesceProgress::Quiesced(Quiesced::DeviceStopped),
            [Ended::Quiesced(token, Operation::Read, seen.offset)].as_slice()
        ),
        "the proven stop ends the reserved command once and returns its own buffer"
    );
    assert_eq!(
        (seen.last, seen.released),
        ((0, (0, 0, READS)), true),
        "the buffer is free again and the arena releases"
    );
}

/// The sibling: the same completion for a command the driver accepted reaches its record and delivers the
/// command's one terminal with its buffer, so the stale verdict above is the reserved phase's.
#[test]
fn a_completion_naming_an_accepted_command_delivers_its_one_terminal() {
    let seen = run(false, false);
    let token = seen
        .token
        .expect("premise: the driver was given the read's token");
    assert_eq!(
        (seen.unwound, seen.returned, seen.accepted),
        (false, Some(token), Some(true)),
        "premise: the driver accepted the submit and the token's record holds an accepted command"
    );
    assert_eq!(
        seen.before,
        (1, Admission::Open, (1, 0, READS - 1)),
        "premise: the accepted command is pending and storage holds the buffer"
    );
    assert_eq!(
        seen.pushed, 1,
        "premise: the poll's pick put the completion naming the token into the table's sink"
    );
    assert_eq!(
        (seen.poll, seen.polled.as_slice()),
        (
            (1, 0),
            [Ended::Read(
                token,
                seen.offset,
                DeviceStatus::Kernel(LEN as i32)
            )]
            .as_slice()
        ),
        "a completion naming an accepted command's token delivers its one terminal with its buffer"
    );
    assert_eq!(
        seen.after,
        (0, 0, (0, 0, READS)),
        "the terminal ended the command and its buffer is free once dropped"
    );
    assert_eq!(
        seen.cancel,
        Err(Stale),
        "a cancel after the terminal names no pending command"
    );
    assert_eq!(
        (
            seen.unproven,
            seen.stopped,
            seen.unproven_ended.len() + seen.stopped_ended.len()
        ),
        (
            QuiesceProgress::Quiesced(Quiesced::AllReturned),
            QuiesceProgress::Quiesced(Quiesced::AllReturned),
            0
        ),
        "every command returned, so each quiesce is proven with nothing left to deliver"
    );
    assert_eq!(
        (seen.last, seen.released),
        ((0, (0, 0, READS)), true),
        "the arena releases"
    );
}

/// Under lost admission, the accepted read ends on completion; the reserved read stays pending until a proven
/// stop.
#[test]
fn a_completion_naming_an_accepted_command_delivers_its_terminal_under_lost_admission() {
    let seen = run(false, true);
    let token = seen
        .token
        .expect("premise: the driver was given the first read's token");
    let (reserved, reserved_offset) = seen
        .bystander
        .expect("premise: the second read's submit unwound and the driver kept its token");
    assert_eq!(
        (seen.unwound, seen.returned, seen.accepted),
        (false, Some(token), Some(true)),
        "premise: the driver accepted the first submit and its record holds an accepted command"
    );
    assert_ne!(
        token, reserved,
        "premise: the two reads have their own tokens"
    );
    assert_eq!(
        seen.before,
        (2, Admission::Lost, (2, 0, READS - 2)),
        "premise: both commands are pending, admission is lost and storage holds both buffers"
    );
    assert_eq!(
        seen.pushed, 1,
        "premise: the poll's pick put the completion naming the accepted token into the table's sink"
    );
    assert_eq!(
        (seen.poll, seen.polled.as_slice()),
        (
            (1, 0),
            [Ended::Read(
                token,
                seen.offset,
                DeviceStatus::Kernel(LEN as i32)
            )]
            .as_slice()
        ),
        "under lost admission an accepted command's completion delivers its one terminal with its buffer"
    );
    assert_eq!(
        seen.after,
        (1, 0, (1, 0, READS - 1)),
        "the accepted command ended and freed its buffer; the reserved read keeps its own"
    );
    assert_eq!(
        (seen.unproven, seen.unproven_ended.as_slice()),
        (QuiesceProgress::Draining { outstanding: 1 }, [].as_slice()),
        "without a proven stop the reserved read is still outstanding"
    );
    assert_eq!(
        (seen.stopped, seen.stopped_ended.as_slice()),
        (
            QuiesceProgress::Quiesced(Quiesced::DeviceStopped),
            [Ended::Quiesced(reserved, Operation::Read, reserved_offset)].as_slice()
        ),
        "the proven stop ends the reserved read once and returns its own buffer"
    );
    assert_eq!(
        (seen.last, seen.released),
        ((0, (0, 0, READS)), true),
        "both buffers are free again and the arena releases"
    );
}
