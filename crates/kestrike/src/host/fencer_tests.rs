use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use super::HostGate;
use super::fencer::{Connected, Fencer, Release};
use crate::failover::evidence::{NotSole, Pair, RESERVATION_CONFLICT, Registrant};
use crate::failover::fresh::tests::registrant;
use crate::failover::records::VolumeRecord;
use crate::failover::restart::tests::{
    self as restart_tests, own, sample, shard_now, shard_record, store as records,
};
use crate::failover::restart::{Check, Driver, Failed, Refused, Restarted};
use crate::failover::retire::Target;
use crate::failover::takeover;
use crate::failover::takeover::tests::{
    self as takeover_tests, Reservation, c_host, c_pair, d_host, stored_c, takeover_of, with_c,
    with_c_and_b,
};
use crate::storage::device::connect::ConnectError;
use crate::storage::device::sim::{Fault, QuiesceMode, SimControl, SimDisk, Stage};
use crate::storage::gate_fixture::{
    Control, Reserving, Ticking, arena as reserving_arena, encode_report, foreign, limits,
    registry, reserving_as,
};
use crate::storage::store::sim::Shared;
use crate::storage::store_tests::client;
use crate::storage::test_platform::TestPlatform;
use crate::storage::volume_fixture::{BUFFER, device_with};
use crate::storage::{
    Admission, BufferArena, CommandTable, DeviceStatus, Disk, EngineBudget, HolderRefusal,
    QuiesceProgress, Quiesced, ReservationCommand, ReservationLimits, ServingClock,
    SpdkAttachError, Terminal,
};

/// A serving clock that returns its scripted readings in order and panics past the script, so a step that reads
/// more often than the script allows fails instead of waiting.
struct Script(RefCell<VecDeque<Option<u64>>>);

impl Script {
    fn of(readings: &[Option<u64>]) -> Self {
        Self(RefCell::new(readings.iter().copied().collect()))
    }
}

impl ServingClock for Script {
    fn now_us(&self) -> Option<u64> {
        self.0
            .borrow_mut()
            .pop_front()
            .expect("the step read the clock past its script")
    }
}

/// `Lifting` returns each microsecond twice and releases all withheld `registry` completions when the reading equals
/// `lift_at`.
struct Lifting {
    ticks: Ticking,
    registry: Control,
    lift_at: u64,
}

impl ServingClock for Lifting {
    fn now_us(&self) -> Option<u64> {
        let now = self.ticks.now_us()? / 2;
        if now == self.lift_at {
            self.registry.borrow_mut().budget = None;
        }
        Some(now)
    }
}

/// A serving clock that advances one microsecond at every read and runs one tick of the simulated device under it,
/// so a medium command the fencer polls for executes and completes. Before the tick, each medium command the device
/// holds for the first time takes the next scripted fault, where `None` leaves it unfaulted.
pub(super) struct Driving {
    now: Cell<u64>,
    control: SimControl,
    faults: RefCell<VecDeque<Option<Fault>>>,
    seen: RefCell<Vec<crate::storage::CommandToken>>,
}

impl Driving {
    pub(super) fn new(
        control: &SimControl,
        faults: impl IntoIterator<Item = Option<Fault>>,
    ) -> Self {
        Self {
            now: Cell::new(0),
            control: control.clone(),
            faults: RefCell::new(faults.into_iter().collect()),
            seen: RefCell::default(),
        }
    }
}

impl ServingClock for Driving {
    fn now_us(&self) -> Option<u64> {
        for token in self.control.ready(Stage::Execute) {
            let mut seen = self.seen.borrow_mut();
            if !seen.contains(&token) {
                seen.push(token);
                if let Some(Some(fault)) = self.faults.borrow_mut().pop_front() {
                    self.control.fault(token, fault);
                }
            }
        }
        self.control.tick(64);
        let now = self.now.get();
        assert!(
            now < crate::storage::gate_fixture::TICKS,
            "a step read the clock past its budget"
        );
        self.now.set(now + 1);
        Some(now)
    }
}

/// Limits whose Report and preempt deadlines differ, so a step's clock readings show which deadline bounded it.
fn distinct_limits() -> ReservationLimits {
    ReservationLimits::new(8, 2, 100, 300).unwrap()
}

/// One volume's reservation table holding `entries` under a type-2 reservation.
pub(super) fn shared_table(entries: Vec<Registrant>) -> Control {
    let registry = registry();
    {
        let mut registry = registry.borrow_mut();
        registry.entries = entries;
        registry.rtype = 2;
    }
    registry
}

/// A host double on `registry` issuing as `own` from controller `cntlid`, over fresh simulated media.
pub(super) fn host(registry: &Control, own: Pair, cntlid: u16) -> (Reserving, SimControl) {
    let (disk, control) = device_with(7, BUFFER);
    (reserving_as(disk, registry, own, cntlid), control)
}

pub(super) fn connected<D>(disk: D, pair: Pair) -> impl FnOnce() -> Connected<D> {
    move || Ok((disk, pair))
}

pub(super) fn fencer_of<'a, D: Disk>(
    disk: D,
    pair: Pair,
    arena: &'a BufferArena<TestPlatform>,
    clock: &'a dyn ServingClock,
) -> Fencer<'a, TestPlatform, D, impl FnOnce() -> Connected<D>> {
    let limits = disk.reservation_limits().unwrap_or_else(limits);
    Fencer::new(
        &HostGate::qualified(),
        connected(disk, pair),
        limits,
        arena,
        clock,
    )
}

pub(super) fn commands(registry: &Control) -> Vec<&'static str> {
    registry
        .borrow()
        .log
        .iter()
        .map(|command| match command {
            ReservationCommand::Register { .. } => "register",
            ReservationCommand::Report { .. } => "report",
            ReservationCommand::Acquire { .. } => "acquire",
            ReservationCommand::PreemptAndAbort(_) => "preempt",
            ReservationCommand::PreemptLineage(_) => "lineage",
            ReservationCommand::PreemptEnded(_) => "ended",
        })
        .collect()
}

fn conflict() -> DeviceStatus {
    DeviceStatus::Nvme(RESERVATION_CONFLICT << 1)
}

/// The step-1 target of `shard_record(4)` after the restart's bump.
fn bumped() -> Target {
    Target {
        attempts: 5,
        ..Target::of(&shard_record(4))
    }
}

/// The table's pending and abandoned counts and its admission.
fn custody(table: &CommandTable<'_, Reserving>) -> (u32, u32, Admission) {
    let report = table.report();
    (report.pending, report.abandoned, report.admission)
}

/// When the fencer returns a table with an outstanding command, the incarnation establishes `DeviceStopped` with
/// one quiesce of the simulated reset before reclaiming the driver.
pub(super) fn stop(mut table: CommandTable<'_, Reserving>, control: &SimControl) -> Reserving {
    control.set_quiesce(QuiesceMode::Reset);
    let mut out = Vec::with_capacity(8);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    let Ok(disk) = table.release_idle() else {
        panic!("a stopped table holds no pending or abandoned record");
    };
    disk
}

/// A restart's outcome, comparable across devices: the refusal, or the session target of a restart that reached FB,
/// after checking that the stored shard record carries that target's attempts.
fn restart_outcome(result: Result<Restarted, Refused>, store: &Shared) -> Result<Target, Refused> {
    result.map(|restarted| {
        assert_eq!(
            shard_now(store).attempts,
            restarted.session().target().attempts
        );
        restarted.session().target()
    })
}

/// The restart through the fencer over a volume whose own pair holds beside C's recorded registration takes Report,
/// self Preempt-and-Abort and Report from the shared table, reaches FB at `E + 1`, leaves the own pair holding with C
/// still registered, and gives the driver back.
#[test]
fn a_restart_through_the_fencer_reaches_fb_and_releases_the_driver() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![
        registrant(own(), 1, true),
        registrant(c_pair(), 2, false),
    ]);
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let restarted = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap();
    assert_eq!(commands(&registry), ["report", "preempt", "report"]);
    assert_eq!(restarted.session().target().attempts, 5);
    assert_eq!(shard_now(&store).attempts, 5);
    assert_eq!(
        registry.borrow().entries,
        [registrant(own(), 1, true), registrant(c_pair(), 2, false)]
    );
    assert_eq!(registry.borrow().rtype, 2);
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

/// The rows both restart devices express, and the alias row: the scripted card and the fencer over the shared table
/// give equal results and equal registrant tables on each, and each fencer gives its driver back. On the alias row,
/// two records under the own host ID, the driver's identity check refuses the Report and the restart still reads its
/// bytes, so it refuses `NotHolding(DuplicateOwnRecord)` with the flip to the step-1 target. On the unrecorded-holder
/// row, a pair the volume record ties to no attach holds beside the registered own pair, and the restart refuses
/// `NotHolding(ForeignHolder)` with the same flip.
#[test]
fn the_restart_rows_agree_between_the_card_and_the_fencer() {
    let alias = Pair {
        key: foreign().key,
        ..own()
    };
    let rows: [(&str, Vec<Registrant>); 6] = [
        (
            "own holds",
            vec![registrant(own(), 1, true), registrant(c_pair(), 2, false)],
        ),
        (
            "unrecorded registrant",
            vec![registrant(own(), 1, true), registrant(foreign(), 2, false)],
        ),
        (
            "recorded holder",
            vec![registrant(own(), 1, false), registrant(c_pair(), 2, true)],
        ),
        (
            "unrecorded holder",
            vec![registrant(own(), 1, false), registrant(foreign(), 2, true)],
        ),
        (
            "nobody holds",
            vec![registrant(own(), 1, false), registrant(c_pair(), 2, false)],
        ),
        (
            "alias",
            vec![registrant(own(), 1, true), registrant(alias, 3, false)],
        ),
    ];
    for (row, entries) in rows {
        let scripted = records(shard_record(4), with_c());
        let mut card = restart_tests::Card::new();
        card.entries = entries.clone();
        let by_card = restart_outcome(
            restart_tests::restart().run(&mut client(&scripted), &sample(), &mut card),
            &scripted,
        );

        let fenced = records(shard_record(4), with_c());
        let registry = shared_table(entries);
        let (disk, _control) = host(&registry, own(), 1);
        let arena = reserving_arena();
        let clock = Ticking::default();
        let mut fencer = fencer_of(disk, own(), &arena, &clock);
        let by_fencer = restart_outcome(
            restart_tests::restart().run(&mut client(&fenced), &sample(), &mut fencer),
            &fenced,
        );
        assert_eq!(by_card, by_fencer, "{row}");
        assert_eq!(shard_now(&scripted), shard_now(&fenced), "{row}");
        assert_eq!(registry.borrow().entries, card.entries, "{row}");
        assert!(matches!(fencer.release(), Release::Driver(_)), "{row}");
        let cause = match row {
            "alias" => Some(NotSole::DuplicateOwnRecord),
            "unrecorded holder" => Some(NotSole::ForeignHolder),
            _ => None,
        };
        if let Some(cause) = cause {
            let refused = by_fencer.unwrap_err();
            assert_eq!(
                (&refused.check, refused.flip),
                (
                    &Check::NotHolding(cause),
                    Some(Target::of(&shard_record(4)))
                ),
                "{row}: {refused:?}"
            );
            assert_eq!(commands(&registry), ["report"], "{row}");
        }
    }
}

/// The takeover by C, the record's standby, through the takeover's scripted card and through the fencer over the
/// shared table: equal results and equal final tables where A holds, with C registered or not, with B, recorded,
/// registered beside, and where C itself holds; each fencer gives its driver back. The lineage preempt ends A's
/// registration alone, so B stays registered. On the alias row the driver withholds the Report, so the fencer's
/// takeover refuses at Report #1 where the card's refuses at its holder check; neither flips, both name C's tenure
/// as the recovery and leave the record at it.
#[test]
fn the_takeover_rows_agree_between_the_card_and_the_fencer() {
    let alias = Pair {
        key: foreign().key,
        ..c_pair()
    };
    let a = restart_tests::own();
    let b = takeover_tests::b_pair();
    type Row = (&'static str, Vec<Registrant>, fn() -> VolumeRecord);
    let rows: [Row; 5] = [
        (
            "A holds, C registered",
            vec![registrant(a, 1, true), registrant(c_pair(), 2, false)],
            with_c,
        ),
        (
            "A holds, C unregistered",
            vec![registrant(a, 1, true)],
            with_c,
        ),
        (
            "A holds, B registered",
            vec![registrant(a, 1, true), registrant(b, 5, false)],
            with_c_and_b,
        ),
        (
            "C holds",
            vec![registrant(a, 1, false), registrant(c_pair(), 2, true)],
            with_c,
        ),
        (
            "alias",
            vec![
                registrant(a, 1, true),
                registrant(c_pair(), 2, false),
                registrant(alias, 3, false),
            ],
            with_c,
        ),
    ];
    for (row, entries, record) in rows {
        let scripted = records(takeover_tests::shard_record(), record());
        let reservation = Rc::new(RefCell::new(Reservation {
            entries: entries.clone(),
            rtype: 2,
            ..Reservation::default()
        }));
        let mut card = takeover_tests::card_after_cas(&scripted, c_pair(), c_host(), &reservation);
        let by_card = takeover_of(&scripted, c_host())
            .run(&mut client(&scripted), &stored_c(), &mut card)
            .map(|restarted| restarted.session().target());

        let fenced = records(takeover_tests::shard_record(), record());
        let registry = shared_table(entries);
        let (disk, _control) = host(&registry, c_pair(), 9);
        let arena = reserving_arena();
        let clock = Ticking::default();
        let observed = fenced.clone();
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            move || {
                assert_eq!(
                    shard_now(&observed).owner,
                    c_host(),
                    "the connect follows the committed takeover"
                );
                Ok((disk, c_pair()))
            },
            limits(),
            &arena,
            &clock,
        );
        let by_fencer = takeover_of(&fenced, c_host())
            .run(&mut client(&fenced), &stored_c(), &mut fencer)
            .map(|restarted| restarted.session().target());
        assert_eq!(shard_now(&scripted), shard_now(&fenced), "{row}");
        assert_eq!(
            registry.borrow().entries,
            reservation.borrow().entries,
            "{row}"
        );
        assert!(matches!(fencer.release(), Release::Driver(_)), "{row}");
        if row == "alias" {
            let (card, fencer) = (by_card.unwrap_err(), by_fencer.unwrap_err());
            assert_eq!(fencer.check, takeover::Check::FirstReport(Failed(None)));
            assert_eq!(
                card.check,
                takeover::Check::Holder(HolderRefusal::Registrants(NotSole::DuplicateOwnRecord))
            );
            let committed = takeover_tests::taken(&takeover_tests::shard_record(), c_host());
            assert_eq!(card.recovery, Some(Target::of(&committed)));
            assert_eq!(fencer.recovery, Some(Target::of(&committed)));
            assert_eq!(shard_now(&fenced), committed);
            assert_eq!(commands(&registry), ["report"]);
            continue;
        }
        assert_eq!(by_card, by_fencer, "{row}");
        if row == "A holds, B registered" {
            assert_eq!(
                registry.borrow().entries,
                [registrant(b, 5, false), registrant(c_pair(), 9, true)]
            );
        }
    }
}

/// Two host doubles on one volume's table: C's takeover registers and preempts A's key, after which C holds, A's
/// registration is gone, C's fencer gives its driver back, and A's Report and C's show the same table.
#[test]
fn two_hosts_share_one_reservation_table() {
    let store = records(takeover_tests::shard_record(), with_c());
    let a = restart_tests::own();
    let registry = shared_table(vec![registrant(a, 1, true)]);
    let (c_disk, _c_control) = host(&registry, c_pair(), 9);
    let (a_disk, _a_control) = host(&registry, a, 1);
    let (c_arena, a_arena) = (reserving_arena(), reserving_arena());
    let clock = Ticking::default();
    let mut c = fencer_of(c_disk, c_pair(), &c_arena, &clock);
    takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut c)
        .unwrap();
    assert_eq!(
        commands(&registry),
        ["report", "register", "lineage", "report"]
    );
    assert_eq!(registry.borrow().entries, [registrant(c_pair(), 9, true)]);

    let seen_by_c = takeover::Device::report(&mut c).unwrap();
    assert!(matches!(c.release(), Release::Driver(_)));
    let mut a_fencer = fencer_of(a_disk, a, &a_arena, &clock);
    crate::failover::restart::Device::start(&mut a_fencer).unwrap();
    crate::failover::restart::Device::ready(&mut a_fencer).unwrap();
    let seen_by_a = crate::failover::restart::Device::report(&mut a_fencer).unwrap();
    assert_eq!(seen_by_a, seen_by_c);
}

/// A Report is a function of the table alone: C's Reports on buffers that earlier held a two-row Report equal A's
/// Report on a fresh table once a preempt leaves one row.
#[test]
fn a_report_after_a_preempt_shows_only_the_remaining_rows() {
    let store = records(takeover_tests::shard_record(), with_c());
    let a = restart_tests::own();
    let registry = shared_table(vec![registrant(a, 1, true), registrant(c_pair(), 9, false)]);
    let (c_disk, _c_control) = host(&registry, c_pair(), 9);
    let (a_disk, _a_control) = host(&registry, a, 1);
    let (c_arena, a_arena) = (reserving_arena(), reserving_arena());
    let clock = Ticking::default();
    let mut c = fencer_of(c_disk, c_pair(), &c_arena, &clock);
    takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut c)
        .unwrap();
    assert_eq!(commands(&registry), ["report", "lineage", "report"]);
    let seen_by_c = [
        takeover::Device::report(&mut c).unwrap(),
        takeover::Device::report(&mut c).unwrap(),
    ];
    let mut a_fencer = fencer_of(a_disk, a, &a_arena, &clock);
    crate::failover::restart::Device::start(&mut a_fencer).unwrap();
    crate::failover::restart::Device::ready(&mut a_fencer).unwrap();
    let seen_by_a = crate::failover::restart::Device::report(&mut a_fencer).unwrap();
    assert_eq!(seen_by_c, [seen_by_a.clone(), seen_by_a]);
}

/// Two host doubles keep their own pending commands: a Report A submitted stays with A while C's table polls and
/// its device stops, and C's Register runs only at C's poll, after A's Report took its bytes.
#[test]
fn each_host_double_completes_only_its_own_commands() {
    let a = restart_tests::own();
    let registry = shared_table(vec![registrant(a, 1, true)]);
    let (a_disk, _a_control) = host(&registry, a, 1);
    let (c_disk, c_control) = host(&registry, c_pair(), 9);
    let (a_arena, c_arena) = (reserving_arena(), reserving_arena());
    let budget = || EngineBudget::new(1 << 20);
    let mut a_table = CommandTable::new(a_disk, &a_arena, 3, &mut budget())
        .map_err(|(error, _)| error)
        .unwrap();
    let mut c_table = CommandTable::new(c_disk, &c_arena, 3, &mut budget())
        .map_err(|(error, _)| error)
        .unwrap();
    let mut out = Vec::with_capacity(8);

    let report = a_table
        .submit_reservation(ReservationCommand::Report { not_before: 0 }, 0)
        .unwrap();
    let polled = c_table.poll(&mut out);
    assert_eq!((polled.delivered, polled.stale), (0, 0));
    let register = c_table
        .submit_reservation(ReservationCommand::Register { new: c_pair().key }, 0)
        .unwrap();
    let polled = a_table.poll(&mut out);
    assert_eq!((polled.delivered, polled.stale), (1, 0));
    assert!(matches!(out.as_slice(), [Terminal::Reservation { token, .. }] if *token == report));
    out.clear();
    assert_eq!(registry.borrow().entries, [registrant(a, 1, true)]);
    let polled = c_table.poll(&mut out);
    assert_eq!((polled.delivered, polled.stale), (1, 0));
    assert!(matches!(out.as_slice(), [Terminal::Reservation { token, .. }] if *token == register));
    out.clear();
    assert_eq!(
        registry.borrow().entries,
        [registrant(a, 1, true), registrant(c_pair(), 9, false)]
    );

    registry.borrow_mut().budget = Some(0);
    let second = a_table
        .submit_reservation(ReservationCommand::Report { not_before: 1 }, 1)
        .unwrap();
    c_table
        .submit_reservation(ReservationCommand::Report { not_before: 1 }, 1)
        .unwrap();
    stop(c_table, &c_control);
    registry.borrow_mut().budget = None;
    let polled = a_table.poll(&mut out);
    assert_eq!((polled.delivered, polled.stale), (1, 0));
    assert!(matches!(out.as_slice(), [Terminal::Reservation { token, .. }] if *token == second));
}

/// DEVICE-FAILURE-HOLD: a Report that never completes refuses `FirstReport(Failed(None))` with no flip at its
/// `report_timeout`, the fencer keeps the timed-out Report's table detached and closed, a later Report refuses before
/// its clock reading and its submit, and the incarnation ends through a proven stop.
#[test]
fn a_report_that_never_completes_holds_and_keeps_its_table() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().budget = Some(0);
    let (disk, control) = host(&registry, own(), 1);
    let disk = disk.with_limits(distinct_limits());
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::FirstReport(Failed(None)),
            flip: None,
            recovery: Some(Target::of(&shard_record(4))),
        }
    );
    assert_eq!(commands(&registry), ["report"]);
    assert_eq!(
        clock.0.get(),
        102,
        "the Report waits its report_timeout of 100"
    );
    assert_eq!(
        crate::failover::restart::Device::ready(&mut fencer),
        Err(Failed(None))
    );
    assert_eq!(
        crate::failover::restart::Device::report(&mut fencer),
        Err(Failed(None))
    );
    assert_eq!(commands(&registry), ["report"]);
    assert_eq!(
        clock.0.get(),
        102,
        "a step over the detached Report refuses before it reads the clock"
    );
    let Release::Outstanding(table) = fencer.release() else {
        panic!("a timed-out Report keeps its slot until a proven stop");
    };
    assert_eq!(custody(&table), (0, 1, Admission::Closed));
    stop(table, &control);
    assert_eq!(shard_now(&store).attempts, 4);
}

/// DEVICE-FAILURE-HOLD after the bump: a self Preempt-and-Abort that never completes refuses `Preempt(Failed(None))`
/// with no flip at its `preempt_timeout`, keeps the command pending in a table closed to every later submit, and the
/// incarnation ends through a proven stop. A takeover whose Register never completes holds the same way.
#[test]
fn a_mutation_that_never_completes_holds_pending_with_admission_closed() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().budget = Some(1);
    let (disk, control) = host(&registry, own(), 1);
    let disk = disk.with_limits(distinct_limits());
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::Preempt(Failed(None)),
            flip: None,
            recovery: Some(bumped()),
        }
    );
    assert_eq!(
        clock.0.get(),
        303,
        "Report #1 reads once; the preempt waits its preempt_timeout of 300"
    );
    assert_eq!(
        crate::failover::restart::Device::report(&mut fencer),
        Err(Failed(None))
    );
    assert_eq!(commands(&registry), ["report", "preempt"]);
    let Release::Outstanding(table) = fencer.release() else {
        panic!("a pending preempt keeps its table until a proven stop");
    };
    assert_eq!(custody(&table), (1, 0, Admission::Closed));
    stop(table, &control);

    let store = records(takeover_tests::shard_record(), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().budget = Some(1);
    let (disk, control) = host(&registry, c_pair(), 9);
    let disk = disk.with_limits(distinct_limits());
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, c_pair(), &arena, &clock);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut fencer)
        .unwrap_err();
    let committed = Target::of(&takeover_tests::taken(
        &takeover_tests::shard_record(),
        c_host(),
    ));
    assert_eq!(
        (refused.check, refused.recovery),
        (takeover::Check::Register(Failed(None)), Some(committed))
    );
    assert_eq!(
        clock.0.get(),
        303,
        "the Register waits its preempt_timeout of 300"
    );
    assert_eq!(commands(&registry), ["report", "register"]);
    let Release::Outstanding(table) = fencer.release() else {
        panic!("a pending Register keeps its table until a proven stop");
    };
    assert_eq!(custody(&table), (1, 0, Admission::Closed));
    stop(table, &control);

    let store = records(takeover_tests::shard_record(), with_c());
    let registry = shared_table(vec![
        registrant(own(), 1, true),
        registrant(c_pair(), 9, false),
    ]);
    registry.borrow_mut().budget = Some(1);
    let (disk, control) = host(&registry, c_pair(), 9);
    let disk = disk.with_limits(distinct_limits());
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, c_pair(), &arena, &clock);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.recovery),
        (takeover::Check::Preempt(Failed(None)), Some(committed))
    );
    assert_eq!(
        clock.0.get(),
        303,
        "the lineage preempt waits its preempt_timeout of 300"
    );
    assert_eq!(commands(&registry), ["report", "lineage"]);
    let Release::Outstanding(table) = fencer.release() else {
        panic!("a pending lineage preempt keeps its table until a proven stop");
    };
    assert_eq!(custody(&table), (1, 0, Admission::Closed));
    stop(table, &control);
}

/// A Report whose completion comes after several empty polls and before its deadline decides its step: the restart
/// reaches FB and the driver comes back.
#[test]
fn a_report_that_completes_before_its_deadline_decides_the_step() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().budget = Some(0);
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Lifting {
        ticks: Ticking::default(),
        registry: Rc::clone(&registry),
        lift_at: 50,
    };
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap();
    assert_eq!(commands(&registry), ["report", "preempt", "report"]);
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

/// At age `report_timeout`, the Report remains eligible for polling. A completion on that poll determines the
/// step's outcome.
#[test]
fn a_report_that_completes_at_its_deadline_decides_the_step() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().budget = Some(0);
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Lifting {
        ticks: Ticking::default(),
        registry: Rc::clone(&registry),
        lift_at: limits().report_timeout(),
    };
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap();
    assert_eq!(commands(&registry), ["report", "preempt", "report"]);
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

/// A clock reading of `None` before a step's submit refuses the step with nothing submitted and the driver idle, a
/// Report step and a Register step alike. A reading of `None`, or one below the previous reading, while a Report
/// waits ends the step and detaches the Report.
#[test]
fn an_unreadable_or_regressing_clock_holds() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Script::of(&[None]);
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (Check::FirstReport(Failed(None)), None)
    );
    assert!(commands(&registry).is_empty());
    assert!(matches!(fencer.release(), Release::Driver(_)));

    let store = records(takeover_tests::shard_record(), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let (disk, _control) = host(&registry, c_pair(), 9);
    let arena = reserving_arena();
    let clock = Script::of(&[Some(0), None]);
    let mut fencer = fencer_of(disk, c_pair(), &arena, &clock);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut fencer)
        .unwrap_err();
    assert_eq!(refused.check, takeover::Check::Register(Failed(None)));
    assert_eq!(commands(&registry), ["report"]);
    assert!(matches!(fencer.release(), Release::Driver(_)));

    for (case, readings) in [
        ("unreadable", vec![Some(0), None]),
        ("regressing", vec![Some(10), Some(12), Some(11)]),
    ] {
        let store = records(shard_record(4), with_c());
        let registry = shared_table(vec![registrant(own(), 1, true)]);
        registry.borrow_mut().budget = Some(0);
        let (disk, control) = host(&registry, own(), 1);
        let arena = reserving_arena();
        let clock = Script::of(&readings);
        let mut fencer = fencer_of(disk, own(), &arena, &clock);
        let refused = restart_tests::restart()
            .run(&mut client(&store), &sample(), &mut fencer)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.flip),
            (Check::FirstReport(Failed(None)), None),
            "{case}"
        );
        let Release::Outstanding(table) = fencer.release() else {
            panic!("{case}: the detached Report keeps its slot until a proven stop");
        };
        assert_eq!(custody(&table), (0, 1, Admission::Closed), "{case}");
        stop(table, &control);
    }
}

/// DEVICE-FAILURE-HOLD for a completion with a failing status: Report #1 holds with its status and no flip, a self
/// preempt holds after the bump with its status and leaves the table as it was, and a takeover's Register holds with
/// its status; no later command follows, and each fencer gives its driver back.
#[test]
fn a_command_that_completes_with_a_failing_status_holds() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().report_status = Some(conflict());
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::FirstReport(Failed(Some(conflict()))),
            flip: None,
            recovery: Some(Target::of(&shard_record(4))),
        }
    );
    assert_eq!(commands(&registry), ["report"]);
    assert!(matches!(fencer.release(), Release::Driver(_)));

    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().mutation_status = Some(conflict());
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::Preempt(Failed(Some(conflict()))),
            flip: None,
            recovery: Some(bumped()),
        }
    );
    assert_eq!(commands(&registry), ["report", "preempt"]);
    assert_eq!(registry.borrow().entries, [registrant(own(), 1, true)]);
    assert!(matches!(fencer.release(), Release::Driver(_)));

    let store = records(takeover_tests::shard_record(), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().mutation_status = Some(conflict());
    let (disk, _control) = host(&registry, c_pair(), 9);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, c_pair(), &arena, &clock);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        refused.check,
        takeover::Check::Register(Failed(Some(conflict())))
    );
    assert_eq!(commands(&registry), ["report", "register"]);
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

/// A reservation terminal classifies against its command's transfer length: a kernel result equal to the Report's
/// buffer length or to a preempt's key data length succeeds, and the restart reaches FB; one byte short of either
/// holds with that result.
#[test]
fn a_kernel_result_classifies_against_the_command_s_transfer_length() {
    let report = |registry: &Control| {
        let (disk, _) = host(registry, own(), 1);
        crate::storage::Disk::reservation_limits(&disk)
            .unwrap()
            .report_bytes()
    };
    let kernel = |bytes: u32| DeviceStatus::Kernel(i32::try_from(bytes).unwrap());
    for short in [false, true] {
        for command in ["report", "preempt"] {
            let store = records(shard_record(4), with_c());
            let registry = shared_table(vec![registrant(own(), 1, true)]);
            let full = if command == "report" {
                report(&registry)
            } else {
                16
            };
            let status = kernel(full - u32::from(short));
            if command == "report" {
                registry.borrow_mut().report_status = Some(status);
            } else {
                registry.borrow_mut().mutation_status = Some(status);
            }
            let (disk, _control) = host(&registry, own(), 1);
            let arena = reserving_arena();
            let clock = Ticking::default();
            let mut fencer = Fencer::new(
                &HostGate::qualified(),
                connected(disk, own()),
                limits(),
                &arena,
                &clock,
            );
            let result = restart_tests::restart().run(&mut client(&store), &sample(), &mut fencer);
            match (short, command) {
                (false, _) => {
                    assert_eq!(result.unwrap().session().target().attempts, 5, "{command}")
                }
                (true, "report") => assert_eq!(
                    result.unwrap_err().check,
                    Check::FirstReport(Failed(Some(status)))
                ),
                (true, _) => assert_eq!(
                    result.unwrap_err().check,
                    Check::Preempt(Failed(Some(status)))
                ),
            }
            assert!(matches!(fencer.release(), Release::Driver(_)), "{command}");
        }
    }
}

/// The fresh path's `write` and `read` require a `Fenced` value for the connected pair and unit 0 before the medium
/// admission. On a pair or unit mismatch both return `Err(Failed(None))`, `registry.admissions` stays empty,
/// `registry.medium` stays at 0, and `release` returns the driver.
#[test]
fn a_unit_zero_command_for_another_pair_or_unit_refuses_before_its_admission() {
    use crate::failover::fresh::Device as _;
    use crate::storage::Fenced;
    let registry = shared_table(Vec::new());
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = Fencer::new(
        &HostGate::qualified(),
        connected(disk, own()),
        limits(),
        &arena,
        &clock,
    );
    crate::failover::fresh::Device::set_host_id(&mut fencer, own().exhid).unwrap();
    let record = [0; crate::storage::activation::RECORD_LEN];
    let other = Fenced::assumed_for(Pair {
        exhid: own().exhid,
        key: foreign().key,
    });
    let own_gate = Fenced::assumed_for(own());
    assert_eq!(fencer.write(&other, 0, &record), Err(Failed(None)));
    assert_eq!(fencer.read(&other, 0), Err(Failed(None)));
    assert_eq!(fencer.write(&own_gate, 1, &record), Err(Failed(None)));
    assert_eq!(fencer.read(&own_gate, 1), Err(Failed(None)));
    let registry = registry.borrow();
    assert!(registry.admissions.is_empty());
    assert_eq!(registry.medium, 0);
    drop(registry);
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

/// A unit-0 write and a unit-0 read that never complete each wait through their `report_timeout`, end at the first
/// clock reading past it, and keep their command pending in a table closed to every later submit.
#[test]
fn a_unit_zero_command_that_never_completes_waits_the_report_timeout() {
    use crate::failover::fresh::Device as _;
    use crate::storage::Fenced;
    let record = [0; crate::storage::activation::RECORD_LEN];
    for write in [true, false] {
        let registry = shared_table(Vec::new());
        let (disk, control) = host(&registry, own(), 1);
        let arena = reserving_arena();
        let clock = Ticking::default();
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            connected(disk.with_limits(distinct_limits()), own()),
            distinct_limits(),
            &arena,
            &clock,
        );
        crate::failover::fresh::Device::set_host_id(&mut fencer, own().exhid).unwrap();
        let gate = Fenced::assumed_for(own());
        if write {
            assert_eq!(fencer.write(&gate, 0, &record), Err(Failed(None)));
        } else {
            assert_eq!(fencer.read(&gate, 0), Err(Failed(None)));
        }
        assert_eq!(
            clock.0.get(),
            102,
            "write {write}: the unit-0 command waits its report_timeout of 100"
        );
        assert_eq!(registry.borrow().medium, 1, "write {write}");
        let Release::Outstanding(table) = fencer.release() else {
            panic!("write {write}: a pending unit-0 command keeps its table until a proven stop");
        };
        assert_eq!(custody(&table), (1, 0, Admission::Closed), "write {write}");
        stop(table, &control);
    }
}

/// A controller connected under the own host ID with another key refuses the restart's self preempt and the
/// takeover's Register before their submit: the table shows only Report #1, and the driver comes back.
#[test]
fn a_command_for_a_pair_other_than_the_connected_one_refuses_before_its_submit() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let other_key = Pair {
        key: foreign().key,
        ..own()
    };
    let mut fencer = fencer_of(disk, other_key, &arena, &clock);
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        (refused.check, refused.flip),
        (Check::Preempt(Failed(None)), None)
    );
    assert_eq!(commands(&registry), ["report"]);
    assert_eq!(registry.borrow().entries, [registrant(own(), 1, true)]);
    assert!(matches!(fencer.release(), Release::Driver(_)));

    let store = records(takeover_tests::shard_record(), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let (disk, _control) = host(&registry, c_pair(), 9);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let other_key = Pair {
        key: foreign().key,
        ..c_pair()
    };
    let mut fencer = fencer_of(disk, other_key, &arena, &clock);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut fencer)
        .unwrap_err();
    assert_eq!(refused.check, takeover::Check::Register(Failed(None)));
    assert_eq!(commands(&registry), ["report"]);
    assert_eq!(registry.borrow().entries, [registrant(own(), 1, true)]);
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

/// NoPredecessorEffectAfterFB, the release control: a driver that comes back while a command of the fencer's table is
/// outstanding would deliver that command's completion to the next table over it. For a restart whose first Report
/// and a fresh path whose Register never completes, the fencer returns the table, a proven stop drains it, and a
/// second table over the driver sees no terminal of the first and has its own Report refused by the stopped driver.
#[test]
fn a_second_table_over_a_released_driver_sees_no_terminal_of_the_first() {
    use crate::failover::fresh::Refusals;
    use crate::failover::fresh::tests::{self as fresh_tests, records as fresh_records};
    for sequence in ["restart", "fresh"] {
        let own = match sequence {
            "restart" => own(),
            _ => fresh_tests::local_record().pair(),
        };
        let registry = shared_table(vec![registrant(own, 1, true)]);
        registry.borrow_mut().budget = Some(0);
        let (disk, control) = host(&registry, own, 1);
        let arena = reserving_arena();
        let clock = Ticking::default();
        let mut fencer = fencer_of(disk, own, &arena, &clock);
        if sequence == "restart" {
            let store = records(shard_record(4), with_c());
            restart_tests::restart()
                .run(&mut client(&store), &sample(), &mut fencer)
                .unwrap_err();
        } else {
            let store =
                fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
            fresh_tests::fresh_of(crate::storage::store_tests::shard(), fresh_tests::holder())
                .run(
                    &mut client(&store),
                    &mut fresh_tests::plane(),
                    &mut fresh_records(&fresh_tests::Log::default()),
                    &mut fencer,
                    &mut Refusals::default(),
                )
                .unwrap_err();
        }
        assert_eq!(commands(&registry).len(), 1, "{sequence}");
        let disk = match fencer.release() {
            Release::Driver(disk) => disk,
            Release::Outstanding(table) => stop(table, &control),
            Release::Unconnected => panic!("the {sequence} connected"),
        };
        registry.borrow_mut().budget = None;
        let next = reserving_arena();
        let mut second = CommandTable::new(disk, &next, 3, &mut EngineBudget::new(1 << 20))
            .map_err(|(error, _)| error)
            .unwrap();
        let mut out = Vec::with_capacity(8);
        let report = second.poll(&mut out);
        assert_eq!((report.delivered, report.stale), (0, 0), "{sequence}");
        assert_eq!(
            second.submit_reservation(ReservationCommand::Report { not_before: 0 }, 0),
            Err(crate::storage::Refusal::Device(
                crate::storage::SubmitRefusal {
                    reason: crate::storage::RefusalReason::DeviceGone,
                    code: None,
                }
            )),
            "{sequence}: the stopped driver accepts no command of a later table"
        );
    }
}

/// A connect that fails with a kernel binding, with a held device lock and with a transport error, a controller
/// connected under another host ID, and a refused submission: each holds with the step-1 target as its recovery and
/// no flip, and issues no reservation command. A driver condition refuses every later start too, and the connect
/// closure runs once. `release` returns no driver where the connect produced none, and the driver otherwise.
#[test]
fn connect_and_submit_failures_hold() {
    type Connect = Box<dyn FnOnce(Reserving) -> Connected<Reserving>>;
    let cases: [(&str, Connect, Check, bool); 4] = [
        (
            "kernel binding",
            Box::new(|_| Err(ConnectError::Attach(SpdkAttachError::KernelBinding))),
            Check::Driver(Driver::KernelBinding),
            false,
        ),
        (
            "device lock",
            Box::new(|_| {
                Err(ConnectError::Attach(SpdkAttachError::DeviceLock(
                    std::io::ErrorKind::WouldBlock,
                )))
            }),
            Check::Driver(Driver::LiveQueues),
            false,
        ),
        (
            "transport",
            Box::new(|_| Err(ConnectError::Attach(SpdkAttachError::Connect))),
            Check::Ready(Failed(None)),
            false,
        ),
        (
            "host ID",
            Box::new(|disk| Ok((disk, c_pair()))),
            Check::HostId(Failed(None)),
            true,
        ),
    ];
    for (case, connect, check, driver) in cases {
        let store = records(shard_record(4), with_c());
        let registry = shared_table(vec![registrant(own(), 1, true)]);
        let (disk, _control) = host(&registry, own(), 1);
        let arena = reserving_arena();
        let clock = Ticking::default();
        let runs = Cell::new(0);
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            || {
                runs.set(runs.get() + 1);
                connect(disk)
            },
            limits(),
            &arena,
            &clock,
        );
        let refused = restart_tests::restart()
            .run(&mut client(&store), &sample(), &mut fencer)
            .unwrap_err();
        assert_eq!(
            refused,
            Refused {
                check: check.clone(),
                flip: None,
                recovery: Some(Target::of(&shard_record(4))),
            },
            "{case}"
        );
        let again = match check {
            Check::Driver(condition) => Err(condition),
            _ => Ok(()),
        };
        assert_eq!(
            crate::failover::restart::Device::start(&mut fencer),
            again,
            "{case}"
        );
        assert_eq!(runs.get(), 1, "{case}");
        assert!(commands(&registry).is_empty(), "{case}");
        let released = fencer.release();
        assert_eq!(matches!(released, Release::Driver(_)), driver, "{case}");
        assert!(driver || matches!(released, Release::Unconnected), "{case}");
    }

    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().refuse = Some(crate::storage::RefusalReason::DeviceGone);
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::FirstReport(Failed(None)),
            flip: None,
            recovery: Some(Target::of(&shard_record(4))),
        }
    );
    assert!(commands(&registry).is_empty());
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

/// A takeover whose controller connected under another host ID than its local record's refuses at its host-ID step
/// with its committed tenure as the recovery, issues no reservation command, and gives the driver back.
#[test]
fn a_takeover_over_a_controller_with_another_host_id_holds() {
    let store = records(takeover_tests::shard_record(), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let (disk, _control) = host(&registry, c_pair(), 9);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(disk, foreign(), &arena, &clock);
    let refused = takeover_of(&store, c_host())
        .run(&mut client(&store), &stored_c(), &mut fencer)
        .unwrap_err();
    let committed = Target::of(&takeover_tests::taken(
        &takeover_tests::shard_record(),
        c_host(),
    ));
    assert_eq!(
        (refused.check, refused.recovery),
        (takeover::Check::HostId(Failed(None)), Some(committed))
    );
    assert!(commands(&registry).is_empty());
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

/// A connected driver over which `ready` builds no table refuses `Ready(Failed(None))` with no reservation command
/// and comes back through `release`: a driver without reservation limits, an arena without the reservation reserve,
/// and a reservation share whose table depth `u16` cannot hold.
#[test]
fn a_driver_without_a_table_refuses_ready_and_comes_back() {
    let expect_hold = |refused: Refused| {
        assert_eq!(
            refused,
            Refused {
                check: Check::Ready(Failed(None)),
                flip: None,
                recovery: Some(Target::of(&shard_record(4))),
            }
        );
    };
    let store = records(shard_record(4), with_c());
    let (plain, _control): (SimDisk, _) = device_with(7, BUFFER);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let mut fencer = fencer_of(plain, own(), &arena, &clock);
    expect_hold(
        restart_tests::restart()
            .run(&mut client(&store), &sample(), &mut fencer)
            .unwrap_err(),
    );
    assert!(matches!(fencer.release(), Release::Driver(_)));

    let bare = crate::storage::volume_fixture::arena();
    let wide = |commands| ReservationLimits::new(8, commands, 100, 100).unwrap();
    for (case, limits, arena) in [
        ("no reserve", crate::storage::gate_fixture::limits(), &bare),
        ("u16::MAX share", wide(u32::from(u16::MAX)), &arena),
        ("u32::MAX share", wide(u32::MAX), &arena),
    ] {
        let store = records(shard_record(4), with_c());
        let registry = shared_table(vec![registrant(own(), 1, true)]);
        let (disk, _control) = host(&registry, own(), 1);
        let mut fencer = fencer_of(disk.with_limits(limits), own(), arena, &clock);
        expect_hold(
            restart_tests::restart()
                .run(&mut client(&store), &sample(), &mut fencer)
                .unwrap_err(),
        );
        assert!(commands(&registry).is_empty(), "{case}");
        assert!(matches!(fencer.release(), Release::Driver(_)), "{case}");
    }
}

/// RecordsBeforeDevice, CAS-BEFORE-DEVICE: a restart whose shard record awaits its fresh first acquisition and a
/// takeover by a host the record does not name each refuse before `Device::start`, so the connect closure never runs.
#[test]
fn a_sequence_that_refuses_before_its_start_runs_no_connect() {
    let store = records(shard_record(0), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Ticking::default();
    let ran = Cell::new(false);
    let mut fencer = Fencer::new(
        &HostGate::qualified(),
        || {
            ran.set(true);
            Ok((disk, own()))
        },
        limits(),
        &arena,
        &clock,
    );
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(refused.check, Check::Fresh);
    assert!(!ran.get());
    assert!(matches!(fencer.release(), Release::Unconnected));

    let store = records(takeover_tests::shard_record(), with_c());
    let before = shard_now(&store);
    let (disk, _control) = host(&registry, c_pair(), 9);
    let ran = Cell::new(false);
    let mut fencer = Fencer::new(
        &HostGate::qualified(),
        || {
            ran.set(true);
            Ok((disk, c_pair()))
        },
        limits(),
        &arena,
        &clock,
    );
    let refused = takeover_of(&store, d_host())
        .run(&mut client(&store), &stored_c(), &mut fencer)
        .unwrap_err();
    assert_eq!(refused.recovery, None, "{refused:?}");
    assert!(!ran.get());
    assert_eq!(shard_now(&store), before);
    assert!(commands(&registry).is_empty());
    assert!(matches!(fencer.release(), Release::Unconnected));
}

/// `NoEpochReuse`, CAS-BEFORE-DEVICE: a write whose outcome is unknown licenses nothing, whether or not it committed.
/// A fresh bump and a takeover compare-and-swap of unknown outcome each refuse before the connect closure runs, and
/// a restart whose bump is unknown refuses with Report #1 as its only command.
#[test]
fn a_write_of_unknown_outcome_is_followed_by_no_connect_and_no_fencing_command() {
    use crate::failover::fresh::tests::{self as fresh_tests, records as fresh_records};
    use crate::failover::fresh::{Check as FreshCheck, Refusals};
    use crate::storage::store::StoreError;
    use crate::storage::store::sim::Arm;
    for commit in [false, true] {
        let unknown = Arm::Timeout { commit };
        let registry = shared_table(Vec::new());
        let (disk, _control) = host(&registry, own(), 1);
        let arena = reserving_arena();
        let clock = Ticking::default();
        let ran = Cell::new(false);
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            || {
                ran.set(true);
                Ok((disk, own()))
            },
            limits(),
            &arena,
            &clock,
        );
        let store = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
        for arm in [Arm::Pass, Arm::Pass, Arm::Pass, unknown] {
            store.schedule(arm);
        }
        let refused =
            fresh_tests::fresh_of(crate::storage::store_tests::shard(), fresh_tests::holder())
                .run(
                    &mut client(&store),
                    &mut fresh_tests::plane(),
                    &mut fresh_records(&fresh_tests::Log::default()),
                    &mut fencer,
                    &mut Refusals::default(),
                )
                .unwrap_err();
        assert_eq!(
            refused.check,
            FreshCheck::Bump(StoreError::Unknown),
            "{commit}"
        );
        assert!(!ran.get(), "fresh, commit {commit}");
        assert!(commands(&registry).is_empty(), "fresh, commit {commit}");
        assert!(
            matches!(fencer.release(), Release::Unconnected),
            "fresh, commit {commit}"
        );

        let registry = shared_table(vec![registrant(own(), 1, true)]);
        let (disk, _control) = host(&registry, c_pair(), 9);
        let ran = Cell::new(false);
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            || {
                ran.set(true);
                Ok((disk, c_pair()))
            },
            limits(),
            &arena,
            &clock,
        );
        let store = records(takeover_tests::shard_record(), with_c());
        let nominated = takeover_of(&store, c_host());
        for arm in [Arm::Pass, Arm::Pass, unknown] {
            store.schedule(arm);
        }
        let refused = nominated
            .run(&mut client(&store), &stored_c(), &mut fencer)
            .unwrap_err();
        assert_eq!(
            refused.check,
            takeover::Check::TakeOver(StoreError::Unknown),
            "{commit}"
        );
        assert!(!ran.get(), "takeover, commit {commit}");
        assert!(commands(&registry).is_empty(), "takeover, commit {commit}");
        assert!(
            matches!(fencer.release(), Release::Unconnected),
            "takeover, commit {commit}"
        );

        let registry = shared_table(vec![registrant(own(), 1, true)]);
        let (disk, _control) = host(&registry, own(), 1);
        let mut fencer = fencer_of(disk, own(), &arena, &clock);
        let store = records(shard_record(4), with_c());
        for arm in [Arm::Pass, Arm::Pass, Arm::Pass, unknown] {
            store.schedule(arm);
        }
        let refused = restart_tests::restart()
            .run(&mut client(&store), &sample(), &mut fencer)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.flip),
            (Check::Bump(StoreError::Unknown), None),
            "{commit}"
        );
        assert_eq!(commands(&registry), ["report"], "restart, commit {commit}");
        assert!(
            matches!(fencer.release(), Release::Driver(_)),
            "restart, commit {commit}"
        );
    }
}

/// The fresh first acquisition through the fencer over the shared table and the scripted fresh card give equal
/// results, flips included, on the rows both express: an activation; a connect that fails with a kernel binding,
/// that fails its transport, and that connected with another host ID, each refused at the host-ID step before any
/// reservation command; an Acquire that a foreign holder refuses; a Register the driver refuses; a Report that never
/// completes; a Report the driver's identity check refuses for a second record under the own host ID, whose bytes
/// the sequence still reads; a unit-0 write that fails with a status that ends the tenure, one that fails with
/// another status, and one that never completes; and a read-back that fails once and passes on its retry. On the
/// activation the connect runs only after the acknowledged `E: 0 -> 1` bump, Register, Acquire and Report precede the
/// medium admission, and the unit-0 write and read follow it.
#[test]
fn the_fresh_rows_agree_between_the_card_and_the_fencer() {
    use crate::failover::fresh::tests::{self as fresh_tests, records as fresh_records};
    use crate::failover::fresh::{Check as FreshCheck, Refusals};
    // The fresh owner's pair is entry 0's, the key its local record carries.
    let own = || fresh_tests::local_record().pair();
    let failing = DeviceStatus::Nvme(0x02 << 1);
    let alias = Pair {
        exhid: own().exhid,
        key: foreign().key,
    };
    let rows = [
        "activates",
        "kernel binding",
        "transport",
        "host id",
        "foreign holder",
        "register refused",
        "report silent",
        "alias",
        "write deposed",
        "write failed",
        "write silent",
        "read once",
        "read deposed",
        "read silent",
        "read corrupt",
        "register wrong key",
    ];
    for row in rows {
        let scripted =
            fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
        let log = fresh_tests::Log::default();
        let mut card = fresh_tests::Card::new(&log);
        match row {
            "kernel binding" | "transport" | "host id" => card.fail = Some("host"),
            "foreign holder" => card.loss = Some("host"),
            "register refused" => card.fail = Some("register"),
            "report silent" => card.stop_at = Some(4),
            "alias" => {
                card.report_override = Some(encode_report(
                    2,
                    &[registrant(own(), 1, true), registrant(alias, 2, false)],
                ));
            }
            "write deposed" => card.write_status = Some(conflict()),
            "write failed" => card.write_status = Some(failing),
            "write silent" => card.stop_at = Some(5),
            "read once" => card.read_status = Some(failing),
            "read deposed" => card.read_status = Some(conflict()),
            "read silent" => card.stop_at = Some(6),
            "read corrupt" => card.torn = 2,
            "register wrong key" => card.fail = Some("register"),
            _ => {}
        }
        let mut local = fresh_records(&log);
        let by_card =
            fresh_tests::fresh_of(crate::storage::store_tests::shard(), fresh_tests::holder())
                .run(
                    &mut client(&scripted),
                    &mut fresh_tests::plane(),
                    &mut local,
                    &mut card,
                    &mut Refusals::default(),
                )
                .map(|activated| activated.session().target());

        let fenced = fresh_tests::store(fresh_tests::shard_record(0), fresh_tests::volume_record());
        let registry = shared_table(match row {
            "foreign holder" => vec![registrant(foreign(), 9, true)],
            _ => Vec::new(),
        });
        match row {
            "register refused" => {
                registry.borrow_mut().refuse = Some(crate::storage::RefusalReason::DeviceGone);
            }
            "report silent" => registry.borrow_mut().budget = Some(2),
            "alias" => registry.borrow_mut().after_acquire = Some(registrant(alias, 2, false)),
            _ => {}
        }
        let (disk, control) = host(&registry, own(), 1);
        let arena = reserving_arena();
        let clock = Driving::new(
            &control,
            match row {
                "write deposed" => vec![Some(Fault::Status(conflict()))],
                "write failed" => vec![Some(Fault::Status(failing))],
                "write silent" => vec![Some(Fault::DropCompletion)],
                "read once" => vec![None, Some(Fault::Status(failing))],
                "read deposed" => vec![None, Some(Fault::Status(conflict()))],
                "read silent" => vec![None, Some(Fault::DropCompletion)],
                "read corrupt" => vec![
                    None,
                    Some(Fault::CorruptSuccess),
                    Some(Fault::CorruptSuccess),
                ],
                _ => Vec::new(),
            },
        );
        let observed = fenced.clone();
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            move || {
                assert_eq!(
                    shard_now(&observed).attempts,
                    1,
                    "the connect follows the acknowledged bump"
                );
                match row {
                    "kernel binding" => Err(ConnectError::Attach(SpdkAttachError::KernelBinding)),
                    "transport" => Err(ConnectError::Attach(SpdkAttachError::Connect)),
                    "host id" => Ok((disk, foreign())),
                    "register wrong key" => Ok((
                        disk,
                        Pair {
                            exhid: own().exhid,
                            key: foreign().key,
                        },
                    )),
                    _ => Ok((disk, own())),
                }
            },
            limits(),
            &arena,
            &clock,
        );
        let log = fresh_tests::Log::default();
        let mut fenced_local = fresh_records(&log);
        let by_fencer =
            fresh_tests::fresh_of(crate::storage::store_tests::shard(), fresh_tests::holder())
                .run(
                    &mut client(&fenced),
                    &mut fresh_tests::plane(),
                    &mut fenced_local,
                    &mut fencer,
                    &mut Refusals::default(),
                )
                .map(|activated| activated.session().target());
        assert_eq!(by_card, by_fencer, "{row}");
        assert_eq!(shard_now(&scripted), shard_now(&fenced), "{row}");
        assert_eq!(local.refused, fenced_local.refused, "{row}");
        let (admissions, medium) = {
            let registry = registry.borrow();
            (registry.admissions.clone(), registry.medium)
        };
        match row {
            "activates" | "read once" => {
                assert!(by_fencer.is_ok(), "{row}");
                assert_eq!(commands(&registry), ["register", "acquire", "report"]);
                let reads = if row == "read once" { 2 } else { 1 };
                assert_eq!(
                    admissions,
                    [(3, false)]
                        .into_iter()
                        .chain(std::iter::repeat_n((3, true), reads))
                        .collect::<Vec<_>>(),
                    "{row}"
                );
                assert_eq!(
                    medium,
                    1 + reads,
                    "{row}: one unit-0 write and its read-backs"
                );
                assert!(matches!(fencer.release(), Release::Driver(_)), "{row}");
            }
            "kernel binding" | "transport" | "host id" => {
                assert_eq!(
                    by_fencer.unwrap_err().check,
                    FreshCheck::HostId(Failed(None)),
                    "{row}"
                );
                assert!(commands(&registry).is_empty(), "{row}");
                let released = fencer.release();
                if row == "host id" {
                    assert!(matches!(released, Release::Driver(_)), "{row}");
                } else {
                    assert!(matches!(released, Release::Unconnected), "{row}");
                }
            }
            "alias" => {
                let refused = by_fencer.unwrap_err();
                assert_eq!(
                    refused.check,
                    FreshCheck::NotSole(NotSole::DuplicateOwnRecord),
                    "{row}"
                );
                assert!(refused.flip.is_some(), "{row}");
                assert!(admissions.is_empty() && medium == 0, "{row}");
                assert!(matches!(fencer.release(), Release::Driver(_)), "{row}");
            }
            "write deposed" | "write failed" => {
                let refused = by_fencer.unwrap_err();
                let status = if row == "write deposed" {
                    conflict()
                } else {
                    failing
                };
                assert_eq!(
                    refused.check,
                    FreshCheck::Write(Failed(Some(status))),
                    "{row}"
                );
                assert_eq!(refused.flip.is_none(), row == "write deposed", "{row}");
                assert_eq!(medium, 1, "{row}");
                assert!(matches!(fencer.release(), Release::Driver(_)), "{row}");
            }
            "report silent" | "write silent" => {
                let check = by_fencer.unwrap_err().check;
                if row == "report silent" {
                    assert_eq!(check, FreshCheck::Report(Failed(None)));
                } else {
                    assert_eq!(check, FreshCheck::Write(Failed(None)));
                }
                let Release::Outstanding(table) = fencer.release() else {
                    panic!("{row}: a command that never completes keeps its table");
                };
                stop(table, &control);
            }
            "foreign holder" | "register refused" => {
                assert!(by_fencer.is_err(), "{row}");
                assert!(admissions.is_empty() && medium == 0, "{row}");
            }
            "register wrong key" => {
                assert_eq!(
                    by_fencer.unwrap_err().check,
                    FreshCheck::Register(Failed(None))
                );
                assert!(commands(&registry).is_empty(), "{row}");
                assert!(matches!(fencer.release(), Release::Driver(_)), "{row}");
            }
            "read deposed" => {
                let refused = by_fencer.unwrap_err();
                assert_eq!(refused.check, FreshCheck::Read(Failed(Some(conflict()))));
                assert!(refused.flip.is_none(), "{row}");
                assert_eq!(medium, 2, "{row}: one write and one read, no retry");
                assert!(matches!(fencer.release(), Release::Driver(_)), "{row}");
            }
            "read silent" | "read corrupt" => {
                let refused = by_fencer.unwrap_err();
                assert!(
                    matches!(refused.check, FreshCheck::Activation(_)),
                    "{row}: {refused:?}"
                );
                assert!(refused.flip.is_none(), "{row}");
                if row == "read silent" {
                    assert_eq!(medium, 2, "{row}: the retry finds the table closed");
                    let Release::Outstanding(table) = fencer.release() else {
                        panic!("{row}: the silent read keeps its table");
                    };
                    assert_eq!(custody(&table), (1, 0, Admission::Closed), "{row}");
                    stop(table, &control);
                } else {
                    assert_eq!(medium, 3, "{row}: one write and two read-backs");
                    assert!(matches!(fencer.release(), Release::Driver(_)), "{row}");
                }
            }
            other => panic!("no expectation for the row {other}"),
        }
    }
}

#[test]
fn a_driver_reporting_other_limits_refuses_ready() {
    for (case, reported) in [
        ("deadline", ReservationLimits::new(8, 2, 100, 101).unwrap()),
        (
            "registrants",
            ReservationLimits::new(7, 2, 100, 100).unwrap(),
        ),
    ] {
        let store = records(shard_record(4), with_c());
        let registry = shared_table(vec![registrant(own(), 1, true)]);
        let (disk, _control) = host(&registry, own(), 1);
        let arena = reserving_arena();
        let clock = Ticking::default();
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            connected(disk.with_limits(reported), own()),
            limits(),
            &arena,
            &clock,
        );
        let refused = restart_tests::restart()
            .run(&mut client(&store), &sample(), &mut fencer)
            .unwrap_err();
        assert_eq!(refused.check, Check::Ready(Failed(None)), "{case}");
        assert!(commands(&registry).is_empty(), "{case}");
        assert_eq!(shard_now(&store).attempts, 4, "{case}");
        assert!(matches!(fencer.release(), Release::Driver(_)), "{case}");

        let store = records(takeover_tests::shard_record(), with_c());
        let registry = shared_table(vec![registrant(own(), 1, true)]);
        let (disk, _control) = host(&registry, c_pair(), 9);
        let mut fencer = Fencer::new(
            &HostGate::qualified(),
            connected(disk.with_limits(reported), c_pair()),
            limits(),
            &arena,
            &clock,
        );
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut fencer)
            .unwrap_err();
        assert_eq!(
            refused.check,
            takeover::Check::Ready(Failed(None)),
            "{case}"
        );
        assert!(commands(&registry).is_empty(), "{case}");
        assert!(matches!(fencer.release(), Release::Driver(_)), "{case}");
    }
}

#[test]
fn a_step_that_unwinds_leaves_its_command_in_a_closed_table() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    registry.borrow_mut().budget = Some(0);
    let (disk, control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Script::of(&[Some(0)]);
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        restart_tests::restart().run(&mut client(&store), &sample(), &mut fencer)
    }));
    assert!(unwound.is_err());
    assert_eq!(
        crate::failover::restart::Device::report(&mut fencer),
        Err(Failed(None))
    );
    assert_eq!(commands(&registry), ["report"]);
    let Release::Outstanding(table) = fencer.release() else {
        panic!("the pending Report keeps its table until a proven stop");
    };
    assert_eq!(custody(&table), (1, 0, Admission::Closed));
    stop(table, &control);
}

#[test]
fn a_clock_that_regresses_between_steps_refuses_the_next_step() {
    let store = records(shard_record(4), with_c());
    let registry = shared_table(vec![registrant(own(), 1, true)]);
    let (disk, _control) = host(&registry, own(), 1);
    let arena = reserving_arena();
    let clock = Script::of(&[Some(500), Some(3)]);
    let mut fencer = fencer_of(disk, own(), &arena, &clock);
    let refused = restart_tests::restart()
        .run(&mut client(&store), &sample(), &mut fencer)
        .unwrap_err();
    assert_eq!(
        refused,
        Refused {
            check: Check::Preempt(Failed(None)),
            flip: None,
            recovery: Some(bumped()),
        }
    );
    assert_eq!(commands(&registry), ["report"]);
    assert!(matches!(fencer.release(), Release::Driver(_)));
}

#[test]
fn a_lineage_preempt_refused_or_failed_holds() {
    let committed = Target::of(&takeover_tests::taken(
        &takeover_tests::shard_record(),
        c_host(),
    ));
    let seeded = vec![registrant(own(), 1, true), registrant(c_pair(), 9, false)];
    let other_key = Pair {
        key: foreign().key,
        ..c_pair()
    };
    for (case, connected_as, status, check, log) in [
        (
            "other key",
            other_key,
            None,
            takeover::Check::Preempt(Failed(None)),
            &["report"][..],
        ),
        (
            "conflict",
            c_pair(),
            Some(conflict()),
            takeover::Check::Preempt(Failed(Some(conflict()))),
            &["report", "lineage"][..],
        ),
    ] {
        let store = records(takeover_tests::shard_record(), with_c());
        let registry = shared_table(seeded.clone());
        registry.borrow_mut().mutation_status = status;
        let (disk, _control) = host(&registry, c_pair(), 9);
        let arena = reserving_arena();
        let clock = Ticking::default();
        let mut fencer = fencer_of(disk, connected_as, &arena, &clock);
        let refused = takeover_of(&store, c_host())
            .run(&mut client(&store), &stored_c(), &mut fencer)
            .unwrap_err();
        assert_eq!(
            (refused.check, refused.recovery),
            (check, Some(committed)),
            "{case}"
        );
        assert_eq!(commands(&registry), log, "{case}");
        assert_eq!(registry.borrow().entries, seeded, "{case}");
        assert_eq!(registry.borrow().rtype, 2, "{case}");
        assert!(matches!(fencer.release(), Release::Driver(_)), "{case}");
    }
}

fn submit_once(
    registry: &Control,
    own: Pair,
    cntlid: u16,
    command: ReservationCommand,
) -> Result<Option<DeviceStatus>, crate::storage::Refusal> {
    let (disk, _control) = host(registry, own, cntlid);
    let arena = reserving_arena();
    let mut table = CommandTable::new(disk, &arena, 3, &mut EngineBudget::new(1 << 20))
        .map_err(|(error, _)| error)
        .unwrap();
    let submitted = table.submit_reservation(command, 0);
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    let status = match out.as_slice() {
        [Terminal::Reservation { status, .. }] => *status,
        _ => None,
    };
    submitted.map(|_| status)
}

fn exclusive<'r>(entries: &'r [Registrant]) -> crate::failover::evidence::Report<'r> {
    crate::failover::evidence::Report {
        submitted_at: 0,
        rtype: crate::failover::evidence::ReservationType::ExclusiveAccess,
        regctl: entries.len() as u32,
        entries,
    }
}

#[test]
fn a_self_preempt_by_a_non_holder_ends_its_own_registration() {
    let a = restart_tests::own();
    let bounds = crate::storage::gate_fixture::bounds_of(limits());
    let holding = [registrant(a, 1, true)];
    let preempt =
        crate::storage::SelfPreempt::from_report(&exclusive(&holding), &bounds, a).unwrap();
    for (case, entries, rtype, remaining) in [
        (
            "another holder",
            vec![registrant(a, 1, false), registrant(c_pair(), 9, true)],
            2,
            vec![registrant(c_pair(), 9, true)],
        ),
        (
            "nobody holds",
            vec![registrant(a, 1, false), registrant(c_pair(), 9, false)],
            0,
            vec![registrant(c_pair(), 9, false)],
        ),
    ] {
        let registry = shared_table(entries);
        registry.borrow_mut().rtype = rtype;
        let status = submit_once(
            &registry,
            a,
            1,
            ReservationCommand::PreemptAndAbort(preempt),
        );
        assert_eq!(status, Ok(Some(DeviceStatus::Nvme(0))), "{case}");
        assert_eq!(registry.borrow().entries, remaining, "{case}");
        assert_eq!(registry.borrow().rtype, rtype, "{case}");
    }
}

#[test]
fn the_reserving_double_refuses_a_preempt_for_another_pair() {
    let a = restart_tests::own();
    let bounds = crate::storage::gate_fixture::bounds_of(limits());
    let seeded = vec![registrant(a, 1, true), registrant(c_pair(), 9, false)];
    let c_holding = [registrant(c_pair(), 9, true)];
    let self_preempt =
        crate::storage::SelfPreempt::from_report(&exclusive(&c_holding), &bounds, c_pair())
            .unwrap();
    let lineage = crate::storage::LineagePreempt::resolve(
        &exclusive(&seeded),
        [a, c_pair()].iter(),
        [a].iter(),
        c_pair(),
        &bounds,
    )
    .unwrap();
    for (case, command) in [
        ("self", ReservationCommand::PreemptAndAbort(self_preempt)),
        ("lineage", ReservationCommand::PreemptLineage(lineage)),
    ] {
        let registry = shared_table(seeded.clone());
        let refused = submit_once(&registry, a, 1, command).unwrap_err();
        assert_eq!(
            refused,
            crate::storage::Refusal::Device(crate::storage::SubmitRefusal {
                reason: crate::storage::RefusalReason::NotVerified,
                code: None,
            }),
            "{case}"
        );
        assert_eq!(registry.borrow().entries, seeded, "{case}");
        assert_eq!(registry.borrow().rtype, 2, "{case}");
        assert!(commands(&registry).is_empty(), "{case}");
    }

    let registry = shared_table(seeded.clone());
    let (disk, _control) = host(&registry, c_pair(), 9);
    let arena = reserving_arena();
    let mut table = CommandTable::new(disk, &arena, 3, &mut EngineBudget::new(1 << 20))
        .map_err(|(error, _)| error)
        .unwrap();
    table
        .submit_reservation(ReservationCommand::PreemptLineage(lineage), 0)
        .unwrap();
    registry.borrow_mut().entries = vec![registrant(a, 1, true)];
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    assert!(matches!(
        out.as_slice(),
        [Terminal::Reservation { status: Some(status), .. }] if *status == conflict()
    ));
    assert_eq!(registry.borrow().entries, [registrant(a, 1, true)]);
    assert_eq!(registry.borrow().rtype, 2);
}

/// The ended-key Preempt over the reservation double: the registrations under the ended key end and the holder and
/// the type stay. A target that leaves the table after the resolve and before the execution completes with status 0
/// and changes nothing, so the status shows no key absent; only a later Report does.
#[test]
fn an_ended_preempt_ends_the_registrations_under_its_key_and_keeps_the_holder() {
    let a = restart_tests::own();
    let bounds = crate::storage::gate_fixture::bounds_of(limits());
    let mut volume = with_c();
    let entry = (volume.events.iter_mut())
        .rfind(|event| event.host == c_host())
        .unwrap();
    entry.kind = crate::failover::records::EventKind::Ended;
    let other = registrant(takeover_tests::b_pair(), 5, false);
    let seeded = vec![
        registrant(a, 1, true),
        registrant(c_pair(), 9, false),
        other,
    ];
    let ended = crate::storage::EndedPreempt::resolve(
        &exclusive(&seeded),
        &volume,
        c_pair().key,
        a,
        &bounds,
    )
    .unwrap();
    let registry = shared_table(seeded.clone());
    assert_eq!(
        submit_once(&registry, a, 1, ReservationCommand::PreemptEnded(ended)),
        Ok(Some(DeviceStatus::Nvme(0)))
    );
    assert_eq!(registry.borrow().entries, [registrant(a, 1, true), other]);
    assert_eq!(registry.borrow().rtype, 2);
    assert_eq!(commands(&registry), ["ended"]);

    let registry = shared_table(seeded.clone());
    let refused = submit_once(
        &registry,
        c_pair(),
        9,
        ReservationCommand::PreemptEnded(ended),
    );
    assert_eq!(
        refused,
        Err(crate::storage::Refusal::Device(
            crate::storage::SubmitRefusal {
                reason: crate::storage::RefusalReason::NotVerified,
                code: None,
            }
        )),
        "another host's double refuses the preempt resolved for A"
    );
    assert_eq!(registry.borrow().entries, seeded);
    assert_eq!(registry.borrow().rtype, 2);
    assert!(commands(&registry).is_empty());

    let registry = shared_table(seeded);
    let (disk, _control) = host(&registry, a, 1);
    let arena = reserving_arena();
    let mut table = CommandTable::new(disk, &arena, 3, &mut EngineBudget::new(1 << 20))
        .map_err(|(error, _)| error)
        .unwrap();
    table
        .submit_reservation(ReservationCommand::PreemptEnded(ended), 0)
        .unwrap();
    registry.borrow_mut().entries = vec![registrant(a, 1, true)];
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    assert!(matches!(
        out.as_slice(),
        [Terminal::Reservation { status: Some(status), .. }] if *status == DeviceStatus::Nvme(0)
    ));
    assert_eq!(registry.borrow().entries, [registrant(a, 1, true)]);
    assert_eq!(registry.borrow().rtype, 2);
}

#[test]
fn a_refused_report_snapshot_binds_to_its_token() {
    let a = restart_tests::own();
    let registry = shared_table(vec![registrant(a, 1, true)]);
    {
        let mut registry = registry.borrow_mut();
        registry.budget = Some(1);
        registry.report_check = Some(crate::storage::ReportError::Unchecked);
    }
    let (disk, control) = host(&registry, a, 1);
    let arena = reserving_arena();
    let mut table = CommandTable::new(disk, &arena, 3, &mut EngineBudget::new(1 << 20))
        .map_err(|(error, _)| error)
        .unwrap();
    let first = table
        .submit_reservation(ReservationCommand::Report { not_before: 0 }, 0)
        .unwrap();
    let second = table
        .submit_reservation(ReservationCommand::Report { not_before: 1 }, 1)
        .unwrap();
    let mut out = Vec::with_capacity(8);
    table.poll(&mut out);
    assert!(matches!(out.as_slice(), [Terminal::Reservation { token, .. }] if *token == first));
    out.clear();
    let mut expected = crate::storage::gate_fixture::encode_report(2, &[registrant(a, 1, true)]);
    expected.resize(limits().report_bytes() as usize, 0);
    assert_eq!(table.refused_report(first), Some(&expected[..]));
    assert_eq!(table.reservation_report(first), None);
    assert_eq!(table.refused_report(second), None);
    assert_eq!(table.reservation_report(second), None);

    registry.borrow_mut().budget = None;
    table.poll(&mut out);
    out.clear();
    assert_eq!(table.refused_report(second), Some(&expected[..]));
    registry.borrow_mut().budget = Some(0);
    let third = table
        .submit_reservation(ReservationCommand::Report { not_before: 2 }, 2)
        .unwrap();
    assert_eq!(table.refused_report(first), None);
    assert_eq!(table.reservation_report(first), None);
    control.set_quiesce(QuiesceMode::Reset);
    assert_eq!(
        table.quiesce(&mut out),
        QuiesceProgress::Quiesced(Quiesced::DeviceStopped)
    );
    assert_eq!(table.refused_report(third), None);
    assert_eq!(table.reservation_report(third), None);
}
