//! A reservation-capable test driver for the attach gate and the host fencer: [`Reserving`] passes data commands to a simulated device and answers Register, Acquire, Report, both Preempt-and-Abort forms and the ended-key Preempt itself from a modeled registrant table, so the simulated device's capture holds only medium commands. Several host doubles share one table per volume ([`reserving_as`]), each issuing its commands under its own pair. A preempt updates the table, and medium commands reach the simulated device in every reservation state. Every preempt form leaves every command already queued at a host double or the simulated device to complete in its own order, so a test over this double checks the table transition alone.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use super::super::device::sim::SimDisk;
use super::super::device::{
    AttachFacts, CommandToken, Completion, CompletionSink, DeviceGeometry, DeviceRange,
    DeviceStatus, Disk, DmaRange, QuiesceStatus, RefusalReason, ReservationCommand,
    ReservationLimits, SubmitRefusal,
};
use crate::failover::evidence::{Pair, RESERVATION_CONFLICT, Registrant};
use crate::failover::identity::{Epoch, Exhid, Incarnation, Key};

/// A serving clock that advances one microsecond at every read, so a step that never completes reaches its
/// deadline after as many polls as the deadline holds microseconds. A read past [`TICKS`] panics, so a wait that
/// never reaches its deadline fails the test.
#[derive(Default)]
pub(crate) struct Ticking(pub(crate) Cell<u64>);

/// The most readings one [`Ticking`] clock gives.
pub(crate) const TICKS: u64 = 1 << 20;

impl crate::storage::ServingClock for Ticking {
    fn now_us(&self) -> Option<u64> {
        let now = self.0.get();
        assert!(now < TICKS, "a step read the clock past its budget");
        self.0.set(now + 1);
        Some(now)
    }
}

/// The pair `ServingAuthority::fixture`'s token carries.
pub(crate) fn own() -> Pair {
    Pair {
        exhid: Exhid::new([1; 16]).unwrap(),
        key: Key::new(Epoch::new(1).unwrap(), Incarnation::new(1).unwrap()),
    }
}

/// Another host's pair.
pub(crate) fn foreign() -> Pair {
    Pair {
        exhid: Exhid::new([2; 16]).unwrap(),
        key: Key::new(Epoch::new(2).unwrap(), Incarnation::new(1).unwrap()),
    }
}

/// The limits `ServingAuthority::fixture` validates against.
pub(crate) fn limits() -> ReservationLimits {
    ReservationLimits::new(8, 2, 100, 100).unwrap()
}

/// Fixture authorities use these bounds: one retry, a window limit of `u64::MAX`, and the Report timeout from
/// `limits`.
pub(crate) fn bounds_of(limits: ReservationLimits) -> crate::failover::bounds::Bounds {
    bounds_with(limits, u64::MAX, 0)
}

/// Fixture authorities use a Report period of 100 microseconds and one retry. Panics when `Bounds::new` refuses
/// `window` and `clock_error`, as a fixture input error.
#[track_caller]
pub(crate) fn bounds_with(
    limits: ReservationLimits,
    window: u64,
    clock_error: u64,
) -> crate::failover::bounds::Bounds {
    crate::failover::bounds::Bounds::new(
        limits.registrants(),
        1,
        window,
        limits.report_timeout(),
        100,
        clock_error,
    )
    .expect("a window above the Report period, the deadline and the clock error")
}

pub(crate) struct ZeroClock;

impl super::super::ServingClock for ZeroClock {
    fn now_us(&self) -> Option<u64> {
        Some(0)
    }
}

/// How an [`OwnerClock`] reads the true elapsed microseconds `t` of its tenure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strategy {
    /// `offset_us` plus `t` rounded down to a multiple of `error_us + 1`: within `error_us` of `offset_us + t`,
    /// which keeps the serving clock contract when `error_us` is at most the bounds' `tau`.
    Honest { offset_us: u64, error_us: u64 },
    /// `offset_us + t / divisor`. For `divisor > 1` the reading falls behind `offset_us + t` by `t - t / divisor`,
    /// which breaks the contract's elapsed-time part once that loss over one window exceeds the bounds' `tau`.
    Slow { offset_us: u64, divisor: u64 },
    /// Zero at every `t`, as [`ZeroClock`] reads, which also breaks the elapsed-time part.
    Frozen,
}

impl Strategy {
    /// The reading at `t`, nondecreasing in `t` for every strategy. Panics, as a fixture input error, when the
    /// strategy has no `u64` reading at `t`: a `Slow` divisor of zero, an `Honest` `error_us` of `u64::MAX`, or an
    /// offset whose sum with the elapsed part exceeds `u64::MAX`.
    pub(crate) fn read(self, t: u64) -> u64 {
        let reading = match self {
            Self::Honest {
                offset_us,
                error_us,
            } => error_us
                .checked_add(1)
                .and_then(|granule| offset_us.checked_add(t / granule * granule)),
            Self::Slow { offset_us, divisor } => t
                .checked_div(divisor)
                .and_then(|elapsed| offset_us.checked_add(elapsed)),
            Self::Frozen => Some(0),
        };
        reading.unwrap_or_else(|| panic!("{self:?} has no u64 reading at {t}"))
    }
}

/// A serving clock that reads a cell of true elapsed microseconds through a [`Strategy`]. Each tenure has its own
/// cell, which its history only advances.
pub(crate) struct OwnerClock {
    pub(crate) strategy: Strategy,
    pub(crate) now: Rc<Cell<u64>>,
}

impl super::super::ServingClock for OwnerClock {
    fn now_us(&self) -> Option<u64> {
        Some(self.strategy.read(self.now.get()))
    }
}

/// The extended Report bytes of `entries` under reservation type `rtype`.
pub(crate) fn encode_report(rtype: u8, entries: &[Registrant]) -> Vec<u8> {
    let mut bytes = vec![0; 64 + 64 * entries.len()];
    bytes[4] = rtype;
    let count =
        u16::try_from(entries.len()).expect("a modeled table holds at most u16::MAX registrants");
    bytes[5..7].copy_from_slice(&count.to_le_bytes());
    for (at, entry) in entries.iter().enumerate() {
        let row = &mut bytes[64 + 64 * at..128 + 64 * at];
        row[..2].copy_from_slice(&entry.cntlid.to_le_bytes());
        row[2] = u8::from(entry.holder);
        row[8..16].copy_from_slice(&entry.pair.key.encode().to_le_bytes());
        row[16..32].copy_from_slice(&entry.pair.exhid.bytes());
    }
    bytes
}

pub(crate) fn ticks<D: Disk>(
    volume: &mut super::Volume<'_, '_, super::super::test_platform::TestPlatform, D>,
    control: &super::super::device::sim::SimControl,
    rounds: usize,
) {
    let mut out = Vec::with_capacity(16);
    for _ in 0..rounds {
        control.tick(64);
        let _ = volume.poll_storage(0, &mut out);
        out.clear();
    }
}

pub(crate) fn medium(control: &super::super::device::sim::SimControl) -> usize {
    use super::super::device::sim::{Captured, Origin};
    control
        .capture()
        .events
        .iter()
        .filter(|event| matches!(event, Captured::Submitted { .. }))
        .count()
        + control.refused(Origin::Model)
        + control.refused(Origin::Script)
}

pub(crate) fn storage() -> super::super::Storage<super::super::test_platform::TestPlatform> {
    super::volume_tests::storage(2)
}

/// An arena whose pools match `volume_fixture::arena`, plus the two reservation buffers [`limits`] needs.
pub(crate) fn arena() -> super::super::device::BufferArena<super::super::test_platform::TestPlatform>
{
    arena_with(4, 4)
}

pub(crate) fn arena_with(
    read: u32,
    receive: u32,
) -> super::super::device::BufferArena<super::super::test_platform::TestPlatform> {
    use super::super::volume_fixture::BUFFER;
    super::super::volume_fixture::pools_with(
        super::super::test_platform::TestPlatform::heap(4096),
        (read, BUFFER),
        (receive, BUFFER),
        4096,
        2,
    )
}

/// Attaches `storage`'s volume over a reserving driver on fresh simulated media under `authority`, and returns the volume, the simulated device's control and the registry.
pub(crate) fn attach_reserving<'s, 'a>(
    storage: &'s super::super::Storage<super::super::test_platform::TestPlatform>,
    arena: &'a super::super::device::BufferArena<super::super::test_platform::TestPlatform>,
    authority: super::ServingAuthority,
) -> (
    super::Volume<'s, 'a, super::super::test_platform::TestPlatform, Reserving>,
    super::super::device::sim::SimControl,
    Control,
) {
    use super::super::volume_fixture::{BUFFER, DEPTH, TICK, device_with};
    let (disk, control) = device_with(7, BUFFER);
    let (disk, registry) = reserving(disk);
    let volume = super::Volume::attach(
        storage,
        arena,
        disk,
        crate::storage::portable::scripted::ScriptedClock::trusted(),
        authority,
        DEPTH,
        TICK,
        &mut super::super::ledger::EngineBudget::new(1 << 25),
    )
    .map_err(|(error, _)| error)
    .expect("attach");
    (volume, control, registry)
}

pub(crate) fn read_record(
    volume: &mut super::Volume<'_, '_, super::super::test_platform::TestPlatform, Reserving>,
) -> Result<(), super::ReadRefusal> {
    let record = super::volume_tests::record(0, 0, super::volume_tests::CHUNK, volume.session, 35);
    volume.read_raw(&record.read, u64::MAX).map(|_| ())
}

/// One volume's modeled reservation state and reservation command log, which its host doubles share.
#[derive(Debug)]
pub(crate) struct Registry {
    /// A [`reserving`] double registers with `cntlid` 10; a [`reserving_as`] double registers with its supplied
    /// `cntlid`.
    pub(crate) entries: Vec<Registrant>,
    /// The reservation type byte a Report shows.
    pub(crate) rtype: u8,
    /// Every reservation command submitted by any host double, in order.
    pub(crate) log: Vec<ReservationCommand>,
    /// The pair of the host double that submitted each command of `log`, index for index.
    pub(crate) issuers: Vec<Pair>,
    /// Reservation completions the host doubles together may still deliver; `None` delivers every one.
    pub(crate) budget: Option<usize>,
    /// An entry the Acquire adds after it succeeds, as a racing host would.
    pub(crate) after_acquire: Option<Registrant>,
    /// The reservation type the Acquire leaves, 2 unless a test sets another.
    pub(crate) acquired_rtype: u8,
    /// The refusal every reservation submit returns while set, before the driver logs the command.
    pub(crate) refuse: Option<RefusalReason>,
    /// The status the next Report completes with in place of success; its bytes are written either way.
    pub(crate) report_status: Option<DeviceStatus>,
    /// The next command other than a Report that reaches execution short-circuits with this status, an ended-key
    /// Preempt included.
    pub(crate) mutation_status: Option<DeviceStatus>,
    /// The driver housekeeping calls the driver took.
    pub(crate) services: usize,
    /// Medium admissions the volume granted, each with the reservation commands logged when it came and whether a
    /// medium command had already been submitted.
    pub(crate) admissions: Vec<(usize, bool)>,
    /// Medium commands submitted, every admitted or refused read and write.
    pub(crate) medium: usize,
    /// While set, the identity check returns this error. For a successful Report, `reservation_report` then withholds
    /// the bytes and the crate's `refused_report` exposes them.
    pub(crate) report_check: Option<super::super::device::ReportError>,
}

/// The test's handle on a [`Reserving`] driver's registry.
pub(crate) type Control = Rc<RefCell<Registry>>;

/// A driver that adds reservation commands to a simulated device.
pub(crate) struct Reserving {
    inner: SimDisk,
    registry: Control,
    /// Register requires `new == own.key`, Acquire `current == own.key` and every preempt form `preempt.pair() ==
    /// own`; the host double's records carry `cntlid`.
    own: Pair,
    cntlid: u16,
    /// The reservation capacity the double advertises and checks Reports against.
    limits: ReservationLimits,
    /// This host's reservation commands awaiting their completion.
    pending: VecDeque<(CommandToken, ReservationCommand, DmaRange)>,
    /// Set once the inner device proved its stop; every later reservation submit refuses `DeviceGone`.
    stopped: bool,
}

/// `inner` with an empty registrant table, and the handle on it.
pub(crate) fn reserving(inner: SimDisk) -> (Reserving, Control) {
    let registry = registry();
    (reserving_as(inner, &registry, own(), 10), registry)
}

/// Pass the same handle to [`reserving_as`] for hosts that share a volume.
pub(crate) fn registry() -> Control {
    Rc::new(RefCell::new(Registry::default()))
}

/// An empty registrant table: no registrant, reservation type 0, every completion delivered, and an Acquire that
/// leaves type 2.
impl Default for Registry {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            rtype: 0,
            log: Vec::new(),
            issuers: Vec::new(),
            budget: None,
            after_acquire: None,
            acquired_rtype: 2,
            refuse: None,
            report_status: None,
            mutation_status: None,
            services: 0,
            admissions: Vec::new(),
            medium: 0,
            report_check: None,
        }
    }
}

/// A host double over `inner` that shares `registry`, the one reservation table of a volume, and issues its
/// commands as `own` from controller `cntlid`.
pub(crate) fn reserving_as(
    inner: SimDisk,
    registry: &Control,
    own: Pair,
    cntlid: u16,
) -> Reserving {
    Reserving {
        inner,
        registry: Rc::clone(registry),
        own,
        cntlid,
        limits: limits(),
        pending: VecDeque::new(),
        stopped: false,
    }
}

impl Reserving {
    /// The double checks Reports against the same `limits` it advertises.
    pub(crate) fn with_limits(self, limits: ReservationLimits) -> Self {
        Self { limits, ..self }
    }
}

impl Registry {
    /// The Report commands submitted to the driver, answered or still pending.
    pub(crate) fn reports(&self) -> usize {
        self.log
            .iter()
            .filter(|command| command.is_report())
            .count()
    }

    /// The Report commands the host double issuing as `issuer` submitted, answered or still pending.
    pub(crate) fn reports_by(&self, issuer: Pair) -> usize {
        let logged = self.log.iter().zip(&self.issuers);
        (logged.filter(|(command, by)| command.is_report() && **by == issuer)).count()
    }

    /// The host double issues the command as `own` from controller `cntlid`; `execute` returns its status. A Report
    /// writes its bytes into `memory`, and every preempt form calls [`Registry::preempt`] with the command's issuing
    /// pair, so a type-2 preempt whose PRKEY no registrant carries completes with status 0 and changes nothing. Status 0
    /// is this double's default; the Linux NVMe target answers Reservation Conflict there, and a test that needs that
    /// answer scripts it through `mutation_status`. Neither answer is evidence of EBS behavior.
    fn execute(
        &mut self,
        command: ReservationCommand,
        memory: DmaRange,
        own: Pair,
        cntlid: u16,
    ) -> DeviceStatus {
        let conflict = DeviceStatus::Nvme(RESERVATION_CONFLICT << 1);
        if !command.is_report()
            && let Some(status) = self.mutation_status.take()
        {
            return status;
        }
        match command {
            ReservationCommand::Register { new } => {
                match self
                    .entries
                    .iter()
                    .find(|entry| entry.pair.exhid == own.exhid)
                {
                    None => self.entries.push(Registrant {
                        cntlid,
                        holder: false,
                        pair: Pair {
                            exhid: own.exhid,
                            key: new,
                        },
                    }),
                    Some(entry) if entry.pair.key == new => {}
                    Some(_) => return conflict,
                }
            }
            ReservationCommand::Acquire { current } => {
                let foreign_holder = self
                    .entries
                    .iter()
                    .any(|entry| entry.holder && entry.pair.key != current);
                let Some(entry) = self
                    .entries
                    .iter_mut()
                    .find(|entry| entry.pair.exhid == own.exhid && entry.pair.key == current)
                else {
                    return conflict;
                };
                if foreign_holder {
                    return conflict;
                }
                entry.holder = true;
                self.rtype = self.acquired_rtype;
                if let Some(extra) = self.after_acquire.take() {
                    self.entries.push(extra);
                }
            }
            ReservationCommand::Report { .. } => {
                let mut bytes = encode_report(self.rtype, &self.entries);
                let len = memory.byte_len() as usize;
                bytes.resize(len, 0);
                // SAFETY: the table handed this memory to the driver with the command and takes it back only at the completion this execution posts; `len` is its length.
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), memory.addr().as_ptr(), len);
                }
                if let Some(status) = self.report_status.take() {
                    return status;
                }
            }
            ReservationCommand::PreemptAndAbort(preempt) => {
                return self.preempt(own, preempt.pair(), preempt.pair().key);
            }
            ReservationCommand::PreemptLineage(preempt) => {
                return self.preempt(own, preempt.pair(), preempt.preempted());
            }
            ReservationCommand::PreemptEnded(preempt) => {
                return self.preempt(own, preempt.pair(), preempt.ended());
            }
        }
        DeviceStatus::Nvme(0)
    }

    /// Preemption requires a registered `issuer` with `issuer.exhid == own.exhid`. When `preempted` is the holder's
    /// key, the issuer stays registered and becomes the one holder of a type-2 reservation; otherwise every
    /// registration under `preempted` ends, including the issuer's when `issuer.key == preempted`.
    fn preempt(&mut self, own: Pair, issuer: Pair, preempted: Key) -> DeviceStatus {
        if issuer.exhid != own.exhid || !self.entries.iter().any(|entry| entry.pair == issuer) {
            return DeviceStatus::Nvme(RESERVATION_CONFLICT << 1);
        }
        let transfers = self
            .entries
            .iter()
            .any(|entry| entry.holder && entry.pair.key == preempted);
        self.entries
            .retain(|entry| entry.pair.key != preempted || (transfers && entry.pair == issuer));
        if transfers {
            for entry in &mut self.entries {
                entry.holder = entry.pair == issuer;
            }
            self.rtype = 2;
        }
        DeviceStatus::Nvme(0)
    }
}

// SAFETY: data commands pass unchanged to the simulated device, which keeps the contract. A reservation command writes its memory only while it is pending, before its completion posts; each accepted token gets exactly one completion unless a `Stopped` quiesce comes first, which drops the pending reservation commands, so no reservation memory is touched after `Stopped`, and every later reservation submit refuses `DeviceGone`.
unsafe impl Disk for Reserving {
    fn geometry(&self) -> DeviceGeometry {
        self.inner.geometry()
    }

    unsafe fn submit_read(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        self.registry.borrow_mut().medium += 1;
        // SAFETY: the caller's contract passes through.
        unsafe { self.inner.submit_read(token, device, memory) }
    }

    unsafe fn submit_write(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        self.registry.borrow_mut().medium += 1;
        // SAFETY: the caller's contract passes through.
        unsafe { self.inner.submit_write(token, device, memory) }
    }

    fn admit_medium(&mut self, _gate: &super::Fenced) {
        let mut registry = self.registry.borrow_mut();
        let logged = registry.log.len();
        let after_medium = registry.medium > 0;
        registry.admissions.push((logged, after_medium));
    }

    fn reservation_limits(&self) -> Option<ReservationLimits> {
        Some(self.limits)
    }

    fn check_reservation_report(
        &self,
        bytes: &[u8],
    ) -> Result<(), super::super::device::ReportError> {
        if let Some(error) = self.registry.borrow().report_check {
            return Err(error);
        }
        super::super::device::check_report_identity(bytes, self.limits, self.own)
    }

    unsafe fn submit_reservation(
        &mut self,
        token: CommandToken,
        command: ReservationCommand,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        if self.stopped {
            return Err(SubmitRefusal {
                reason: RefusalReason::DeviceGone,
                code: None,
            });
        }
        let mut registry = self.registry.borrow_mut();
        if let Some(reason) = registry.refuse {
            return Err(SubmitRefusal { reason, code: None });
        }
        let own = self.own;
        let attached = match command {
            ReservationCommand::Register { new } => new == own.key,
            ReservationCommand::Acquire { current } => current == own.key,
            ReservationCommand::Report { .. } => true,
            ReservationCommand::PreemptAndAbort(preempt) => preempt.pair() == own,
            ReservationCommand::PreemptLineage(preempt) => preempt.pair() == own,
            ReservationCommand::PreemptEnded(preempt) => preempt.pair() == own,
        };
        if !attached {
            return Err(SubmitRefusal {
                reason: RefusalReason::NotVerified,
                code: None,
            });
        }
        crate::instrument::unmeasured(|| {
            registry.log.push(command);
            registry.issuers.push(own);
            self.pending.push_back((token, command, memory));
        });
        Ok(())
    }

    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
        self.inner.pick_completions(sink);
        let mut registry = self.registry.borrow_mut();
        crate::instrument::unmeasured(|| {
            while registry.budget != Some(0) && sink.remaining() > 0 {
                let Some((token, command, memory)) = self.pending.pop_front() else {
                    break;
                };
                let status = registry.execute(command, memory, self.own, self.cntlid);
                sink.push(Completion { token, status })
                    .expect("the sink had room for this completion");
                if let Some(budget) = registry.budget.as_mut() {
                    *budget -= 1;
                }
            }
        });
    }

    fn quiesce(&mut self) -> QuiesceStatus {
        let status = self.inner.quiesce();
        if status == QuiesceStatus::Stopped {
            self.pending.clear();
            self.stopped = true;
        }
        status
    }

    fn service(&mut self) {
        self.registry.borrow_mut().services += 1;
        self.inner.service();
    }

    fn attach_facts(&self) -> Option<&AttachFacts> {
        self.inner.attach_facts()
    }
}
