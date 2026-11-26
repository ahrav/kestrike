//! Before its volume exists, a [`Fencer`] implements the device half of the same-host restart ([`restart::Device`]),
//! of the named standby's takeover ([`takeover::Device`]) and of the fresh first acquisition ([`fresh::Device`]) over
//! any [`Disk`] that executes reservation commands. It connects through its caller's closure, builds a
//! [`CommandTable`] over the connected driver, and runs each command through that table to its terminal or its step
//! deadline.
//!
//! Invariants:
//!
//! - HOST-GATE: building a [`Fencer`] requires a [`HostGate`].
//! - RecordsBeforeDevice, CAS-BEFORE-DEVICE: the connect closure runs at the sequence's first device call:
//!   `Device::start` of the restart and the takeover, and the fresh path's host-ID step, which follows its
//!   acknowledged `E` bump. A sequence that refuses before that call leaves the device untouched; the takeover
//!   starts only after its acknowledged compare-and-swap.
//! - The connect closure carries the device work before the first reservation command (see [`Connected`]): the
//!   fencer builds its table over the driver the closure returned ready, and the host-ID step compares the supplied
//!   host ID with the host ID of the pair the closure returned. A closure that attached and then failed a readiness
//!   step hands its driver back, and `release` returns it.
//! - The fencer builds the table only when the driver reports the validated limits the fencer was given.
//! - Each Register, Acquire and Preempt-and-Abort names the connected pair as its issuer; a command for another pair
//!   refuses before its submit.
//! - Two Report contracts. The takeover's `report` returns a Report's bytes once the driver's identity check passed.
//!   The restart's and the fresh path's `report` return the bytes of every Report that completed with success,
//!   through [`CommandTable::refused_report`] when that check refused, so the sequence's own parse judges an
//!   own-host-ID alias or a second own record as observed evidence and keeps its flip.
//! - NoWriteBeforeFB: the fresh path's unit-0 write and read pass the sequence's `Fenced` value to
//!   [`CommandTable::admit_medium`] before the table submits them, so the driver admits a medium command only after
//!   the fencing boundary. A `Fenced` value for another pair, or a unit other than unit 0, refuses before the
//!   admission.
//! - DEVICE-FAILURE-HOLD: a command that ends without success, or whose wait ends before a poll delivers its
//!   terminal, returns `Failed`, which each sequence turns into its refusal. A step that ends with its command
//!   outstanding closes the table's admission, so every later submit refuses, and detaches a Report with
//!   [`CommandTable::timeout_report`]; its late terminal ends custody and exposes status alone.
//! - NoPredecessorEffectAfterFB: [`Fencer::release`] returns the driver through [`CommandTable::release_idle`] only
//!   after the fencer's table has received every command's terminal. If a command remains outstanding,
//!   `Fencer::release` returns the `CommandTable` with admission closed so the caller can stop the driver, and every
//!   step refuses before its submit.
//!
//! The step deadlines come from the validated [`ReservationLimits`]: a Report and a unit-0 write or read wait up to
//! `report_timeout`, and a Register, an Acquire or a Preempt-and-Abort up to `preempt_timeout`, measured on the
//! fencer's [`ServingClock`] from a reading taken before the submit. A reading of `None` there, or one below the
//! fencer's previous reading, refuses the step before its submit. A terminal delivered by a poll decides the step
//! even after the deadline. After a poll that delivers no terminal, the step ends if the clock returns `None`, or if
//! the reading falls below the previous reading or exceeds the deadline. A step waits inside one call, so a timeout
//! requires the clock to advance past the deadline across reads.

use crate::failover::evidence::Pair;
use crate::failover::fresh;
use crate::failover::identity::Exhid;
use crate::failover::restart::{self, Driver, Failed};
use crate::failover::takeover;
use crate::host::HostGate;
use crate::storage::activation::{RECORD_LEN, UNIT};
use crate::storage::device::connect::ConnectError;
pub use crate::storage::device::connect::Connected;
use crate::storage::{
    BufferArena, Classification, CommandTable, CommandToken, DeviceRange, Disk, EngineBudget,
    Fenced, IO_UNIT, LineagePreempt, Platform, PoolKind, ReservationCommand, ReservationLimits,
    SelfPreempt, ServingClock, Terminal,
};

/// The device half of one recovery sequence while the sequence's volume is unattached.
pub struct Fencer<'a, P: Platform, D: Disk, C> {
    arena: &'a BufferArena<P>,
    clock: &'a dyn ServingClock,
    limits: ReservationLimits,
    /// The latest clock reading of any step.
    last: Option<u64>,
    /// The ordinal of the next reservation submission; each submission takes a higher one.
    ordinal: u64,
    state: State<'a, D, C>,
}

enum State<'a, D: Disk, C> {
    /// Before the connect, holding the connect closure, or after the connect closure returned an attach error that
    /// [`Driver::of_attach`] leaves unclassified; `ready` refuses.
    Unconnected(Option<C>),
    /// The connect closure returned a driver condition; every later start returns it again.
    Barred(Driver),
    /// The connect attached the driver and a readiness step failed; `ready` refuses and `release` returns the driver.
    Unready(D),
    Connected {
        disk: D,
        pair: Pair,
    },
    Ready {
        table: CommandTable<'a, D>,
        pair: Pair,
    },
}

/// The result of [`Fencer::release`]. Dropping it or an unreleased fencer runs the fields' destructors alone: an
/// outstanding table keeps owning its commands' buffers, a driver ends through its own drop, and a controller stops
/// only through the caller's stop.
#[must_use = "an outstanding table ends through a proven stop, and a driver passes to the volume or to its stop"]
#[derive(Debug)]
pub enum Release<'a, D: Disk> {
    /// The driver, after a sequence that succeeded or refused, with every command of the fencer's table ended
    /// (NoPredecessorEffectAfterFB). The sequence's result alone grants the attach, and the driver's controller still
    /// runs: the caller must stop the controller before exiting.
    Driver(D),
    /// The fencer's table, closed to admission, which still owns a pending or abandoned command; the caller ends it
    /// through a proven stop.
    Outstanding(CommandTable<'a, D>),
    /// Before the connect, or after a connect closure that returned an attach error, whose effects [`Connected`]
    /// states; the connect closure retains custody of any controller that still requires cleanup.
    Unconnected,
}

/// One command the fencer runs through its table.
#[derive(Clone, Copy)]
enum Step<'b> {
    Reservation(ReservationCommand),
    /// A write whose buffer begins with the activation record.
    Write(DeviceRange, &'b [u8; RECORD_LEN]),
    Read(DeviceRange),
}

/// What one command's terminal showed the fencer.
enum Ended {
    Done,
    /// A successful read and the bytes it returned.
    Read(Vec<u8>),
}

impl<'a, P: Platform, D: Disk, C: FnOnce() -> Connected<D>> Fencer<'a, P, D, C> {
    /// A fencer that runs `connect` at the sequence's first device call with the obligations [`Connected`] states,
    /// builds its table over `arena` for a driver that reports `limits`, the validated limits its sequence holds, and
    /// times each step on `clock`. The fencer only reads `clock`. A latched suspend makes `clock` return `None`. If a
    /// step's first read returns `None`, the fencer refuses the step. A waiting step can time out only if `clock`
    /// advances between reads.
    pub fn new(
        _gate: &HostGate,
        connect: C,
        limits: ReservationLimits,
        arena: &'a BufferArena<P>,
        clock: &'a dyn ServingClock,
    ) -> Self {
        Self {
            arena,
            clock,
            limits,
            last: None,
            ordinal: 0,
            state: State::Unconnected(Some(connect)),
        }
    }

    /// The arena the fencer's table is built over: the one whose memory the connected driver registered.
    pub(super) fn arena(&self) -> &'a BufferArena<P> {
        self.arena
    }

    pub(super) fn holds_device(&self) -> bool {
        match &self.state {
            State::Unconnected(_) | State::Barred(_) => false,
            State::Unready(_) | State::Connected { .. } | State::Ready { .. } => true,
        }
    }

    /// Ends the fencer after its sequence succeeded or refused, before a volume attaches over the driver. Only a
    /// successful sequence permits volume attachment.
    pub fn release(self) -> Release<'a, D> {
        match self.state {
            State::Unconnected(_) | State::Barred(_) => Release::Unconnected,
            State::Unready(disk) | State::Connected { disk, .. } => Release::Driver(disk),
            State::Ready { table, .. } => match table.release_idle() {
                Ok(disk) => Release::Driver(disk),
                Err(mut table) => {
                    table.close();
                    Release::Outstanding(table)
                }
            },
        }
    }

    /// Runs the connect closure on the first call. A driver condition refuses this start and every later one; any
    /// other attach error leaves the fencer unconnected, and a failed readiness step keeps the attached driver, so
    /// `ready` fails in both.
    fn start(&mut self) -> Result<(), Driver> {
        let connect = match &mut self.state {
            State::Barred(driver) => return Err(*driver),
            State::Unconnected(connect) => connect.take(),
            State::Unready(_) | State::Connected { .. } | State::Ready { .. } => None,
        };
        let Some(connect) = connect else {
            return Ok(());
        };
        match connect() {
            Ok((disk, pair)) => self.state = State::Connected { disk, pair },
            Err(ConnectError::Controller(disk) | ConnectError::Unready(disk, _)) => {
                self.state = State::Unready(*disk);
            }
            Err(ConnectError::Attach(error)) => {
                if let Some(driver) = Driver::of_attach(&error) {
                    self.state = State::Barred(driver);
                    return Err(driver);
                }
            }
        }
        Ok(())
    }

    /// Builds the table over the connected driver with one slot beyond the driver's reservation share, the least
    /// depth [`CommandTable::new`] admits. A refusal keeps the driver connected, so `release` returns it.
    fn ready(&mut self) -> Result<(), Failed> {
        let State::Connected { disk, .. } = &self.state else {
            return Err(Failed(None));
        };
        if disk.reservation_limits() != Some(self.limits) {
            return Err(Failed(None));
        }
        let depth = self
            .limits
            .commands()
            .checked_add(1)
            .and_then(|depth| u16::try_from(depth).ok())
            .ok_or(Failed(None))?;
        // The budget covers exactly the metadata charge of this one `CommandTable::new` call.
        let mut budget = EngineBudget::new(
            CommandTable::<D>::metadata_bytes(depth)
                .saturating_add(CommandTable::<D>::reservation_metadata_bytes(disk)),
        );
        let State::Connected { disk, pair } =
            std::mem::replace(&mut self.state, State::Unconnected(None))
        else {
            unreachable!("the state was connected above")
        };
        match CommandTable::new(disk, self.arena, depth, &mut budget) {
            Ok(table) => {
                self.state = State::Ready { table, pair };
                Ok(())
            }
            Err((_, disk)) => {
                self.state = State::Connected { disk, pair };
                Err(Failed(None))
            }
        }
    }

    /// Confirms that the controller connected with `exhid`, the host ID of the local record's pair.
    fn set_host_id(&self, exhid: Exhid) -> Result<(), Failed> {
        match &self.state {
            State::Ready { pair, .. } if pair.exhid == exhid => Ok(()),
            _ => Err(Failed(None)),
        }
    }

    /// Command admission requires `issuer` to match the connected pair.
    fn issued_by(&self, issuer: Pair) -> Result<(), Failed> {
        match &self.state {
            State::Ready { pair, .. } if *pair == issuer => Ok(()),
            _ => Err(Failed(None)),
        }
    }

    /// The fencer treats `None` or a reading below its previous reading as a clock fault.
    fn read_clock(&mut self) -> Option<u64> {
        let now = self.clock.now_us()?;
        if self.last.is_some_and(|last| now < last) {
            return None;
        }
        self.last = Some(now);
        Some(now)
    }

    /// Submits `step`, polls the table until its terminal or its deadline, and returns the command's token with what
    /// a successful terminal showed. A reservation terminal succeeds only on a status that classifies as success for
    /// the command's transfer length. A table that still owns a command refuses the step before its submit.
    fn run(&mut self, step: Step<'_>) -> Result<(CommandToken, Ended), Failed> {
        let State::Ready { table, .. } = &self.state else {
            return Err(Failed(None));
        };
        let report = table.report();
        if report.pending + report.abandoned > 0 {
            return Err(Failed(None));
        }
        let limits = self.limits;
        let (deadline, requested) = match step {
            Step::Reservation(command) if command.is_report() => {
                (limits.report_timeout(), command.len(limits))
            }
            Step::Reservation(command) => (limits.preempt_timeout(), command.len(limits)),
            Step::Write(..) | Step::Read(_) => (limits.report_timeout(), 0),
        };
        let start = self.read_clock().ok_or(Failed(None))?;
        let ordinal = self.ordinal;
        let arena = self.arena;
        let State::Ready { table, .. } = &mut self.state else {
            unreachable!("the state was ready above")
        };
        let token = match step {
            Step::Reservation(command) => {
                self.ordinal += 1;
                table.submit_reservation(command, ordinal).ok()
            }
            Step::Write(range, bytes) => {
                arena
                    .acquire(PoolKind::ReceiveWrite)
                    .ok()
                    .and_then(|mut buffer| {
                        buffer.bytes_mut()[..RECORD_LEN].copy_from_slice(bytes);
                        table.submit_write(buffer, range).ok()
                    })
            }
            Step::Read(range) => arena
                .acquire(PoolKind::ReadResponse)
                .ok()
                .and_then(|buffer| table.submit_read(buffer, range).ok()),
        }
        .ok_or(Failed(None))?;
        let mut out = Vec::with_capacity(usize::from(table.report().depth));
        loop {
            let State::Ready { table, .. } = &mut self.state else {
                unreachable!("the state stays ready while a step waits")
            };
            table.poll(&mut out);
            if let Some(terminal) = out.drain(..).find(|terminal| terminal.token() == token) {
                let ended = match terminal {
                    Terminal::Reservation {
                        status: Some(status),
                        ..
                    } if status.classify(requested) == Classification::Success => Ok(Ended::Done),
                    Terminal::Written { .. } => Ok(Ended::Done),
                    Terminal::Read { done, .. } => Ok(Ended::Read(done.bytes().to_vec())),
                    Terminal::Reservation { status, .. } => Err(Failed(status)),
                    Terminal::Failed { status, .. } => Err(Failed(Some(status))),
                    Terminal::Quiesced { .. } | Terminal::Abandoned { .. } => Err(Failed(None)),
                };
                return ended.map(|ended| (token, ended));
            }
            match self.read_clock() {
                Some(now) if now - start <= deadline => {}
                _ => {
                    let State::Ready { table, .. } = &mut self.state else {
                        unreachable!("the state stays ready while a step waits")
                    };
                    table.timeout_report(token);
                    table.close();
                    return Err(Failed(None));
                }
            }
        }
    }

    /// Runs one reservation command other than a Report, issued by `issuer`, to its successful terminal.
    fn reservation(&mut self, issuer: Pair, command: ReservationCommand) -> Result<(), Failed> {
        self.issued_by(issuer)?;
        self.run(Step::Reservation(command)).map(drop)
    }

    /// Takes a Report and returns its bytes when its identity check passed, and with `refused` also when it refused.
    fn report(&mut self, refused: bool) -> Result<Vec<u8>, Failed> {
        let (token, _) = self.run(Step::Reservation(ReservationCommand::Report {
            not_before: 0,
        }))?;
        let State::Ready { table, .. } = &self.state else {
            unreachable!("a command that completed ran on the fencer's table")
        };
        table
            .reservation_report(token)
            .or_else(|| refused.then(|| table.refused_report(token)).flatten())
            .map(<[u8]>::to_vec)
            .ok_or(Failed(None))
    }

    /// Passes `fenced` to the table's medium admission, then runs one command over the activation unit: a write of
    /// `bytes` when given, and a read otherwise. A `fenced` value for a pair other than the connected one, or another
    /// unit, refuses before the admission and the submit.
    fn medium(
        &mut self,
        fenced: &Fenced,
        unit: u64,
        bytes: Option<&[u8; RECORD_LEN]>,
    ) -> Result<Ended, Failed> {
        let State::Ready { table, pair } = &mut self.state else {
            return Err(Failed(None));
        };
        if fenced.own() != *pair || unit != UNIT {
            return Err(Failed(None));
        }
        table.admit_medium(fenced);
        let range = unit
            .checked_mul(IO_UNIT as u64)
            .and_then(|start| DeviceRange::new(start, IO_UNIT as u32).ok())
            .ok_or(Failed(None))?;
        let step = match bytes {
            Some(bytes) => Step::Write(range, bytes),
            None => Step::Read(range),
        };
        self.run(step).map(|(_, ended)| ended)
    }
}

impl<P: Platform, D: Disk, C: FnOnce() -> Connected<D>> restart::Device for Fencer<'_, P, D, C> {
    fn start(&mut self) -> Result<(), Driver> {
        Fencer::start(self)
    }

    fn ready(&mut self) -> Result<(), Failed> {
        Fencer::ready(self)
    }

    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed> {
        Fencer::set_host_id(self, exhid)
    }

    fn report(&mut self) -> Result<Vec<u8>, Failed> {
        Fencer::report(self, true)
    }

    fn preempt(&mut self, preempt: SelfPreempt) -> Result<(), Failed> {
        self.reservation(preempt.pair(), ReservationCommand::PreemptAndAbort(preempt))
    }

    fn register(&mut self, own: Pair) -> Result<(), Failed> {
        self.reservation(own, ReservationCommand::Register { new: own.key })
    }

    fn preempt_lineage(&mut self, preempt: LineagePreempt) -> Result<(), Failed> {
        self.reservation(preempt.pair(), ReservationCommand::PreemptLineage(preempt))
    }
}

impl<P: Platform, D: Disk, C: FnOnce() -> Connected<D>> takeover::Device for Fencer<'_, P, D, C> {
    fn start(&mut self) -> Result<(), Driver> {
        Fencer::start(self)
    }

    fn ready(&mut self) -> Result<(), Failed> {
        Fencer::ready(self)
    }

    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed> {
        Fencer::set_host_id(self, exhid)
    }

    fn report(&mut self) -> Result<Vec<u8>, Failed> {
        Fencer::report(self, false)
    }

    fn register(&mut self, own: Pair) -> Result<(), Failed> {
        self.reservation(own, ReservationCommand::Register { new: own.key })
    }

    fn preempt(&mut self, preempt: LineagePreempt) -> Result<(), Failed> {
        self.reservation(preempt.pair(), ReservationCommand::PreemptLineage(preempt))
    }
}

impl<P: Platform, D: Disk, C: FnOnce() -> Connected<D>> fresh::Device for Fencer<'_, P, D, C> {
    /// The fresh path's first device call: the connect, the table and the host-ID check.
    fn set_host_id(&mut self, exhid: Exhid) -> Result<(), Failed> {
        self.start().map_err(|_| Failed(None))?;
        self.ready()?;
        Fencer::set_host_id(self, exhid)
    }

    fn register(&mut self, own: Pair) -> Result<(), Failed> {
        self.reservation(own, ReservationCommand::Register { new: own.key })
    }

    fn acquire(&mut self, own: Pair) -> Result<(), Failed> {
        self.reservation(own, ReservationCommand::Acquire { current: own.key })
    }

    fn report(&mut self) -> Result<Vec<u8>, Failed> {
        Fencer::report(self, true)
    }

    fn write(
        &mut self,
        fenced: &Fenced,
        unit: u64,
        bytes: &[u8; RECORD_LEN],
    ) -> Result<(), Failed> {
        self.medium(fenced, unit, Some(bytes)).map(drop)
    }

    fn read(&mut self, fenced: &Fenced, unit: u64) -> Result<Vec<u8>, Failed> {
        match self.medium(fenced, unit, None)? {
            Ended::Read(bytes) => Ok(bytes),
            Ended::Done => Err(Failed(None)),
        }
    }
}
