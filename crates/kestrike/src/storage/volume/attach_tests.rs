//! The attach over the simulated device's command capture: every root the attach writes carries the tenure's
//! session, a medium holding a valid root at or above it refuses with no device write, and no medium command runs
//! before the attach gate's Report shows the own pair as sole holder and registrant; every gate refusal ends the
//! attach with none.
//! Attach's charge covers the registrant arrays that a driver's reservation limits size, and a read's command after
//! its first is submitted only while the serving authority admits it on a reading taken for that submit.

use super::super::super::device::sim::{SimDisk, media};
use super::super::super::device::{
    AttachFacts, CommandToken, CompletionSink, DeviceGeometry, DeviceRange, Disk, DmaRange,
    Operation, QuiesceStatus, ReservationLimits, SubmitRefusal,
};
use super::super::super::recovery::{MetadataOutcome, Root, Session, Slot};
use super::super::super::volume_fixture::{MEDIA, TestVolume, fixture_format};
use super::super::authority_tests::Clock;
use super::super::bootstrap_tests::{
    FORMAT, LAYOUT, arena, attach_with, generations, over, place, run, tick, writes,
};
use super::super::gate_fixture::{Reserving, medium, ticks};
use super::super::volume_tests::storage as plain;
use super::super::{Grant, ReadEvent, ReadStatus};
use crate::storage::test_platform::TestPlatform;
use crate::storage::{BufferArena, Storage};

/// Attaches `disk` under a fixture authority holding `session`.
fn attach_under<'s, 'a>(
    storage: &'s Storage<TestPlatform>,
    arena: &'a BufferArena<TestPlatform>,
    disk: SimDisk,
    session: Session,
) -> TestVolume<'s, 'a> {
    attach_with(
        storage,
        arena,
        disk,
        crate::storage::ServingAuthority::fixture_under(session),
    )
}

/// Media whose slots hold RESET roots of generations `a` in A and `b` in B.
fn formatted(a: u64, b: u64) -> super::super::super::device::sim::Media {
    let store = media(MEDIA);
    let reset = |generation| {
        Root::reset(
            generation,
            crate::storage::TEST_CLOCK.encode(),
            crate::storage::TEST_FEED.encode(),
        )
    };
    place(&store, LAYOUT, FORMAT, &reset(a), Slot::A);
    place(&store, LAYOUT, FORMAT, &reset(b), Slot::B);
    store
}

/// Over media whose roots are below the session, the RESET writes both slots under the session, and the volume
/// opens under it.
#[test]
fn reset_writes_the_tenure_session() {
    let arena = arena();
    let session = crate::storage::next_session();
    let expected = session.get();
    let store = formatted(5, 4);
    let storage = plain(2);
    let (disk, control) = over(&store);
    let mut volume = attach_under(&storage, &arena, disk, session);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
    assert_eq!(volume.session(), expected);
    assert_eq!(generations(&store), [Some(expected); 2]);
}

/// The gate's three commands for the fixture authority's own pair: Register with no current key, Acquire under the own key, and the Report at ordinal 3.
fn gate_log() -> [super::super::super::device::ReservationCommand; 3] {
    use super::super::super::device::ReservationCommand;
    let own = super::super::gate_fixture::own();
    [
        ReservationCommand::Register { new: own.key },
        ReservationCommand::Acquire { current: own.key },
        ReservationCommand::Report { not_before: 3 },
    ]
}

/// The witness of a gate still waiting after `delivered` gate completions: the simulated device accepted or refused no medium
/// command and the driver's admission log is empty.
fn withheld(
    control: &super::super::super::device::sim::SimControl,
    registry: &super::super::gate_fixture::Control,
    delivered: usize,
) {
    assert_eq!(medium(control), 0, "{delivered} completions delivered");
    assert!(
        registry.borrow().admissions.is_empty(),
        "{delivered} completions delivered: no medium admission before the gate passes"
    );
}

/// The volume over the reserving driver.
type GatedVolume<'s, 'a> =
    super::super::Volume<'s, 'a, TestPlatform, super::super::gate_fixture::Reserving>;

/// Attaches over a reserving driver that delivers `delivered` gate completions and then none, ticks the volume 16 times, runs `plant` on it, ticks it 16 more times and asserts the witness of a waiting gate: no medium command, no medium admission, no refused medium submit, one gate command at a time, the outcome `Bootstrapping` and the readiness word `Detached`.
fn gate_waits_after(delivered: usize, plant: fn(&mut GatedVolume<'_, '_>)) {
    use super::super::super::readiness::State;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().budget = Some(delivered);
    ticks(&mut volume, &control, 16);
    plant(&mut volume);
    ticks(&mut volume, &control, 16);
    withheld(&control, &registry, delivered);
    assert_eq!(volume.report().metadata_refused, 0);
    assert_eq!(
        registry.borrow().log.as_slice(),
        &gate_log()[..=delivered],
        "one gate command at a time"
    );
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert_eq!(volume.readiness(), State::Detached);
}

/// A crash after each of the gate's steps, from the attach through the Register, the Acquire and the Report's submission, leaves the device with zero medium commands and no medium admission: the driver delivers `delivered` reservation completions and then none, and however long the volume ticks it submits no medium command, the device refuses none, the volume records no refused medium submit, the outcome stays `Bootstrapping` and the readiness word `Detached`. With every completion delivered, the gate's Register, Acquire and Report precede the one medium admission, which precedes the bootstrap's probes of both root slots and its `Unformatted` report; after `format_from` it submits RESET B only after RESET A's delivery and opens.
#[test]
fn no_medium_command_before_gate() {
    use super::super::super::readiness::State;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    for delivered in 0..3 {
        gate_waits_after(delivered, |_| {});
    }
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    ticks(&mut volume, &control, 32);
    assert_eq!(
        registry.borrow().log[..3],
        gate_log(),
        "the gate's sequence, then the serving machine's own Reports"
    );
    assert_eq!(volume.readiness(), State::Loading);
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Unformatted);
    assert_eq!(
        registry.borrow().admissions,
        [(3, false)],
        "one medium admission, after the gate's three commands and before any medium command"
    );
    volume.format_from(fixture_format).expect("formats");
    ticks(&mut volume, &control, 32);
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
    assert_eq!(
        registry.borrow().admissions.len(),
        1,
        "the gate admits once"
    );
    let reads = super::super::bootstrap_tests::read_starts(&control);
    assert_eq!(reads, [0, 4096], "the probes are the first medium commands");
    assert_eq!(writes(&control), [0, 4096], "RESET A, then B");
    let written = super::super::bootstrap_tests::submitted(&control, Operation::Write);
    let first = super::super::bootstrap_tests::positions(&control, written[0].0);
    let second = super::super::bootstrap_tests::positions(&control, written[1].0);
    assert!(
        first.1.expect("RESET A delivered") < second.0,
        "RESET B is submitted after RESET A's delivery"
    );
}

/// Judges the gate passed once the Acquire completed, while the Report is outstanding.
fn pass_on_the_acquire(volume: &mut GatedVolume<'_, '_>) {
    use super::super::fence::GateStep;
    use super::super::metadata::Phase;
    assert!(
        matches!(
            volume.metadata.phase,
            Phase::Gate {
                step: GateStep::Report,
                pending: Some(_)
            }
        ),
        "the Acquire completed and the Report is outstanding"
    );
    volume.gate_judged(Ok(super::super::Fenced::assumed()));
}

/// Planted defect: the gate is judged passed once the Acquire completed, while its Report is outstanding. The volume admits medium commands and submits its two root probes with two gate completions delivered, so the witness of a waiting gate rejects it.
#[test]
#[should_panic(expected = "2 completions delivered\n  left: 2\n right: 0")]
fn negative_control_a_gate_that_passes_on_the_acquire_submits_a_medium_command_before_the_report() {
    gate_waits_after(2, pass_on_the_acquire);
}

/// Medium commands require the Report after the own Acquire to pass the sole-registrant check; a failure ends the attach `Unfenced` with the matching cause, closes admission, and leaves the readiness word `Withheld`.
#[test]
fn foreign_holder_refuses_without_io() {
    use super::super::super::readiness::State;
    use super::super::GateRefusal;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving, foreign, own};
    use crate::failover::evidence::{Pair, Registrant};
    use crate::failover::serving::State as Serving;
    let arena = reserving_arena();
    let row = |cntlid, holder, pair| {
        Some(Registrant {
            cntlid,
            holder,
            pair,
        })
    };
    let rekeyed = Pair {
        key: foreign().key,
        ..own()
    };
    let cases = [
        (
            row(20, true, foreign()),
            2,
            GateRefusal::ForeignHolder,
            Serving::Withdrawn,
        ),
        (
            row(20, false, foreign()),
            2,
            GateRefusal::ForeignRegistrant,
            Serving::Withdrawn,
        ),
        (None, 0, GateRefusal::ReservationType, Serving::Withdrawn),
        (None, 1, GateRefusal::ReservationType, Serving::Withdrawn),
        (
            row(11, false, own()),
            2,
            GateRefusal::DuplicateOwnRecord,
            Serving::PreBoundary,
        ),
        (
            row(11, false, rekeyed),
            2,
            GateRefusal::DuplicateOwnRecord,
            Serving::PreBoundary,
        ),
    ];
    for (extra, rtype, refusal, serving) in cases {
        let storage = plain(2);
        let authority = crate::storage::ServingAuthority::fixture();
        let target = authority.session().target();
        let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
        {
            let mut registry = registry.borrow_mut();
            registry.after_acquire = extra;
            registry.acquired_rtype = rtype;
        }
        ticks(&mut volume, &control, 32);
        assert_eq!(
            volume.metadata_outcome(),
            MetadataOutcome::Unfenced(refusal)
        );
        assert_eq!(medium(&control), 0, "{refusal:?}");
        assert!(registry.borrow().admissions.is_empty(), "{refusal:?}");
        assert!(storage.is_closed(), "{refusal:?}");
        assert_eq!(volume.readiness(), State::Withheld, "{refusal:?}");
        let report = volume.authority_report();
        assert_eq!(report.state, serving, "{refusal:?} {rtype}");
        let trigger = match refusal {
            GateRefusal::ForeignHolder => Some(crate::failover::evidence::NotSole::ForeignHolder),
            GateRefusal::ForeignRegistrant => {
                Some(crate::failover::evidence::NotSole::ForeignRegistrant)
            }
            GateRefusal::ReservationType => {
                Some(crate::failover::evidence::NotSole::ReservationType)
            }
            _ => None,
        };
        assert_eq!(
            (report.withdrawal, report.flip),
            (
                trigger
                    .and_then(crate::failover::serving::ReportTrigger::new)
                    .map(crate::failover::serving::Cause::Report),
                trigger.map(|_| target)
            ),
            "{refusal:?} {rtype}"
        );
    }
}

#[test]
fn a_prior_holder_or_an_inconclusive_report_refuses_without_io() {
    use super::super::super::readiness::State;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving, foreign};
    use super::super::{GateRefusal, GateStep};
    use crate::failover::evidence::{NotSole, Pair, Registrant};
    use crate::failover::identity::{Epoch, Exhid, Incarnation, Key};
    use crate::failover::serving::{Cause, ReportTrigger};
    let arena = reserving_arena();
    let storage = plain(2);
    let authority = crate::storage::ServingAuthority::fixture();
    let target = authority.session().target();
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
    {
        let mut registry = registry.borrow_mut();
        registry.entries.push(Registrant {
            cntlid: 20,
            holder: true,
            pair: foreign(),
        });
        registry.rtype = 2;
    }
    ticks(&mut volume, &control, 32);
    assert_eq!(
        volume.metadata_outcome(),
        MetadataOutcome::Unfenced(GateRefusal::CommandFailed(GateStep::Acquire))
    );
    let report = volume.authority_report();
    assert_eq!(
        (report.state, report.withdrawal, report.flip),
        (
            crate::failover::serving::State::Withdrawn,
            ReportTrigger::new(NotSole::ForeignHolder).map(Cause::Report),
            Some(target)
        ),
        "a holder outside the recorded pairs retires the volume after a conflict at the gate"
    );
    assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..]);
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());
    assert!(storage.is_closed());
    assert_eq!(volume.readiness(), State::Withheld);

    let arena = reserving_arena();
    let storage = plain(2);
    let authority = crate::storage::ServingAuthority::fixture();
    let target = authority.session().target();
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
    {
        let mut registry = registry.borrow_mut();
        for host in 0..8u8 {
            registry.entries.push(Registrant {
                cntlid: 30 + u16::from(host),
                holder: false,
                pair: Pair {
                    exhid: Exhid::new([3 + host; 16]).unwrap(),
                    key: Key::new(
                        Epoch::new(3 + u32::from(host)).unwrap(),
                        Incarnation::new(1).unwrap(),
                    ),
                },
            });
        }
    }
    ticks(&mut volume, &control, 32);
    assert_eq!(
        volume.metadata_outcome(),
        MetadataOutcome::Unfenced(GateRefusal::ReportUnreadable)
    );
    assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..]);
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());
    assert_eq!(volume.readiness(), State::Withheld);
    let report = volume.authority_report();
    assert_eq!(
        (report.state, report.withdrawal, report.flip),
        (
            crate::failover::serving::State::Withdrawn,
            crate::failover::serving::ReportTrigger::new(
                crate::failover::evidence::NotSole::Excess
            )
            .map(crate::failover::serving::Cause::Report),
            Some(target)
        ),
        "an over-bound count at the gate retires the volume"
    );
}

/// A reservation submit that the device refuses for a full queue leaves the gate's step for a later tick, and the gate passes once the queue drains; a refusal for good ends the attach `Unfenced(CommandFailed(Register))` with no medium command.
#[test]
fn a_refused_gate_submit_retries_when_busy_and_refuses_otherwise() {
    use super::super::super::device::RefusalReason;
    use super::super::super::readiness::State;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    use super::super::{GateRefusal, GateStep};
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().refuse = Some(RefusalReason::QueueFull);
    ticks(&mut volume, &control, 8);
    assert!(registry.borrow().log.is_empty());
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert_eq!(volume.readiness(), State::Detached);
    registry.borrow_mut().refuse = None;
    ticks(&mut volume, &control, 32);
    assert_eq!(registry.borrow().log[..3], gate_log());
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Unformatted);

    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().refuse = Some(RefusalReason::InvalidRange);
    ticks(&mut volume, &control, 8);
    assert_eq!(
        volume.metadata_outcome(),
        MetadataOutcome::Unfenced(GateRefusal::CommandFailed(GateStep::Register))
    );
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());
    assert_eq!(volume.readiness(), State::Withheld);
}

/// The gate's Report is the serving machine's pending Report. Withholding the Report past its deadline causes a timeout and serving-window expiry; the attach ends `Unfenced(AuthorityLost)`, blocking medium commands. Delivering the own-holder Report renews the serving window from its submission time.
#[test]
fn the_gate_report_renews_the_window_or_times_out() {
    use super::super::super::readiness::State;
    use super::super::GateRefusal;
    use super::super::authority::AuthorityRefusal;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    let time = std::rc::Rc::new(std::cell::Cell::new(10));
    volume.set_serving_clock(Box::new(Clock(std::rc::Rc::clone(&time))));
    registry.borrow_mut().budget = Some(2);
    ticks(&mut volume, &control, 8);
    assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..]);
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    time.set(10 + volume.authority.bounds.report_deadline() + 1);
    let stale = volume.report().stale;
    ticks(&mut volume, &control, 1);
    registry.borrow_mut().budget = None;
    ticks(&mut volume, &control, 8);
    assert!(
        volume.report().stale > stale,
        "the timed-out Report's late terminal counts stale"
    );
    assert!(volume.metadata.fenced.is_none());
    assert_eq!(
        volume.metadata_outcome(),
        MetadataOutcome::Unfenced(GateRefusal::AuthorityLost)
    );
    assert_eq!(
        volume.authority_report().refusal,
        Some(AuthorityRefusal::ReportTimeout)
    );
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());
    assert_eq!(volume.readiness(), State::Withheld);

    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, _registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    volume.set_serving_clock(Box::new(Clock(std::rc::Rc::new(std::cell::Cell::new(50)))));
    assert_eq!(volume.authority.machine.window_start(), Some(0));
    ticks(&mut volume, &control, 8);
    assert_eq!(volume.readiness(), State::Loading);
    assert_eq!(volume.authority.machine.window_start(), Some(50));
}

/// A gated machine enforces the Report deadline before its serving window opens.
#[test]
fn a_gated_machine_s_report_ends_the_gate_on_timeout_and_opens_the_window_on_delivery() {
    use super::super::super::readiness::State;
    use super::super::GateRefusal;
    use super::super::gate_fixture::{
        arena as reserving_arena, attach_reserving, bounds_of, limits, own,
    };
    use crate::failover::serving::Machine;
    let gated = |time: &std::rc::Rc<std::cell::Cell<u64>>| {
        let bounds = bounds_of(limits());
        let session = crate::storage::next_session();
        let machine = Machine::gated(bounds, &session, own());
        assert_eq!(machine.window_start(), None);
        crate::storage::ServingAuthority::new(
            bounds,
            machine,
            Box::new(Clock(std::rc::Rc::clone(time))),
            session,
        )
    };

    let arena = reserving_arena();
    let storage = plain(2);
    let time = std::rc::Rc::new(std::cell::Cell::new(10));
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, gated(&time));
    registry.borrow_mut().budget = Some(2);
    ticks(&mut volume, &control, 8);
    assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..]);
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    time.set(10 + volume.authority.bounds.report_deadline() + 1);
    ticks(&mut volume, &control, 1);
    registry.borrow_mut().budget = None;
    ticks(&mut volume, &control, 8);
    assert_eq!(
        volume.metadata_outcome(),
        MetadataOutcome::Unfenced(GateRefusal::AuthorityLost)
    );
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());

    let arena = reserving_arena();
    let storage = plain(2);
    let time = std::rc::Rc::new(std::cell::Cell::new(50));
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, gated(&time));
    ticks(&mut volume, &control, 8);
    assert_eq!(registry.borrow().log[..3], gate_log());
    assert_eq!(volume.readiness(), State::Loading);
    assert_eq!(volume.authority.machine.window_start(), Some(50));
}

#[test]
fn an_aliased_gate_report_collected_before_its_deadline_refuses_without_retiring() {
    use super::super::super::readiness::State;
    use super::super::super::volume_fixture::{JUMP, ServingTime};
    use super::super::GateRefusal;
    use super::super::authority::AuthorityRefusal;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving, foreign, own};
    use crate::failover::evidence::{Pair, Registrant};
    use crate::failover::serving::State as Serving;
    let rekeyed = Pair {
        key: foreign().key,
        ..own()
    };
    for alias in [own(), rekeyed] {
        let arena = reserving_arena();
        let storage = plain(2);
        let (mut volume, control, registry) = attach_reserving(
            &storage,
            &arena,
            crate::storage::ServingAuthority::fixture(),
        );
        let time = std::rc::Rc::new(std::cell::Cell::new(10));
        volume.set_serving_clock(Box::new(ServingTime(std::rc::Rc::clone(&time))));
        {
            let mut registry = registry.borrow_mut();
            registry.after_acquire = Some(Registrant {
                cntlid: 11,
                holder: false,
                pair: alias,
            });
            registry.budget = Some(2);
        }
        ticks(&mut volume, &control, 8);
        assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..]);
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
        registry.borrow_mut().budget = None;
        let stale = volume.report().stale;
        // The turn's first deadline pass reads 10; the pass after the table collects the Report reads past its
        // deadline.
        let expired = 10 + volume.authority.bounds.report_deadline() + 1;
        JUMP.set(Some((1, expired)));
        ticks(&mut volume, &control, 1);
        JUMP.set(None);
        assert_eq!(time.get(), expired, "{alias:?}");
        ticks(&mut volume, &control, 8);
        assert_eq!(
            volume.report().stale,
            stale,
            "{alias:?}: a Report that expires after its collection applies its terminal"
        );
        assert_eq!(
            volume.metadata_outcome(),
            MetadataOutcome::Unfenced(GateRefusal::AuthorityLost),
            "{alias:?}"
        );
        assert_eq!(
            volume.authority_report().state,
            Serving::PreBoundary,
            "{alias:?}"
        );
        assert_eq!(
            volume.authority_report().refusal,
            Some(AuthorityRefusal::ReportTimeout),
            "{alias:?}"
        );
        assert_eq!(medium(&control), 0, "{alias:?}");
        assert!(registry.borrow().admissions.is_empty(), "{alias:?}");
        assert_eq!(volume.readiness(), State::Withheld, "{alias:?}");
    }
}

/// A retiring poll Report whose terminal the table collected before its deadline deposes the volume when the
/// terminal applies, however long the owner's output stays full: the expired Report's collected terminal
/// holds further Report submissions until it applies, so a later Report's deadline pass leaves it in place.
#[test]
fn a_collected_retiring_report_deposes_after_output_room_returns_past_the_next_report_deadline() {
    use super::super::super::device::ReportError;
    use super::super::authority::AuthorityRefusal;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    use crate::failover::serving::State as Serving;
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    let time = std::rc::Rc::new(std::cell::Cell::new(10));
    volume.set_serving_clock(Box::new(Clock(std::rc::Rc::clone(&time))));
    ticks(&mut volume, &control, 8);
    assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..]);
    assert_eq!(volume.authority_report().own_records, Some(1));
    let deadline = volume.authority.bounds.report_deadline();
    // The first periodic Report goes out one period after the gate's; the driver refuses its bytes with a
    // retiring cause.
    registry.borrow_mut().report_check = Some(ReportError::DuplicateOwnHostId { records: 2 });
    let submitted = 10 + volume.authority.bounds.report_period();
    time.set(submitted);
    ticks(&mut volume, &control, 1);
    assert_eq!(registry.borrow().log.len(), 4);
    // The table collects the Report's terminal; a full output keeps it pending across the ticks that expire it
    // and reach the next Report's deadline.
    volume.table.poll(&mut volume.scratch);
    assert_eq!(volume.scratch.len(), 1);
    let stale = volume.report().stale;
    let mut full = Vec::with_capacity(1);
    for now in [
        submitted + deadline + 1,
        submitted + deadline + 2,
        submitted + 2 * deadline + 3,
        submitted + 2 * deadline + 4,
    ] {
        time.set(now);
        control.tick(64);
        volume.poll_storage(0, &mut full);
    }
    assert_eq!(
        volume.scratch.len(),
        1,
        "the collected terminal waits for room"
    );
    assert_eq!(
        registry.borrow().log.len(),
        4,
        "an expired collected Report holds the next Report until its terminal applies"
    );
    ticks(&mut volume, &control, 1);
    assert_eq!(volume.report().stale, stale);
    assert_eq!(volume.authority_report().state, Serving::Withdrawn);
    assert_eq!(
        volume.authority_report().refusal,
        Some(AuthorityRefusal::OwnHostId)
    );
    assert_eq!(volume.authority_report().own_records, Some(2));
}

/// Before the gate passes, an attached volume reads `Detached` and refuses fills `Bootstrapping` and reads `Closed` even under a serving machine that admits both, and submits no medium command; coverage advances refuse `NotReady` and leave the applied position.
#[test]
fn a_serving_volume_before_its_gate_refuses_fills_reads_and_coverage() {
    use super::super::super::readiness::State;
    use super::super::ReadRefusal;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    use crate::failover::serving::{Event, Readiness, State as Serving};
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().budget = Some(0);
    volume.set_serving_clock(Box::new(Clock(std::rc::Rc::new(std::cell::Cell::new(1)))));
    let token = volume.serving_token().expect("the fixture holds a token");
    let machine = &mut volume.authority.machine;
    machine.cross_boundary(&crate::storage::Fenced::assumed());
    machine.step(Event::Readiness(Readiness::ReadReady { token }));
    assert_eq!(volume.authority_state(), Serving::Serving);
    volume.authority_effects();
    ticks(&mut volume, &control, 8);
    assert!(
        registry.borrow().log.is_empty(),
        "the gate runs only before the boundary"
    );
    assert_eq!(volume.readiness(), State::Detached);
    assert_eq!(
        storage.readiness.fill_refusal(),
        Some(crate::storage::ReserveError::Bootstrapping)
    );
    assert!(
        volume
            .admit_authority(
                crate::failover::serving::Operation::Read,
                volume.serving_token()
            )
            .is_ok(),
        "the serving machine admits the read"
    );
    assert_eq!(volume.admission(), Err(ReadRefusal::Closed));
    assert_eq!(
        storage.advance_coverage(1),
        Err(crate::storage::CoverageError::NotReady)
    );
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());
}

/// A close or readiness withdrawal by `Storage::withdraw` while the gate's Report is outstanding keeps the outcome `Bootstrapping` and blocks medium commands. After a close, the gate blocks the Report's late terminal and admits no driver, and fills return `Closed`. After readiness withdrawal, the Report passes the gate, which admits the driver once, while the word stays `Withheld`, keeping metadata stopped.
#[test]
fn a_close_or_withdrawal_during_the_gate_issues_no_medium_command() {
    use super::super::super::device::sim::QuiesceMode;
    use super::super::super::readiness::State;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    for closing in [false, true] {
        let arena = reserving_arena();
        let storage = plain(2);
        let (mut volume, control, registry) = attach_reserving(
            &storage,
            &arena,
            crate::storage::ServingAuthority::fixture(),
        );
        registry.borrow_mut().budget = Some(2);
        ticks(&mut volume, &control, 8);
        assert_eq!(volume.readiness(), State::Detached);
        assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..]);
        let expected = if closing {
            control.set_quiesce(QuiesceMode::Reset);
            let _ = volume.close();
            State::Closed
        } else {
            let _ = storage.withdraw();
            State::Withheld
        };
        registry.borrow_mut().budget = None;
        ticks(&mut volume, &control, 8);
        assert_eq!(volume.readiness(), expected, "closing {closing}");
        assert_eq!(
            storage.readiness.fill_refusal(),
            Some(crate::storage::ReserveError::Closed)
        );
        assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
        assert_eq!(medium(&control), 0);
        // After a withdrawal the gate passes and admits the driver once, while the stopped word issues nothing.
        assert_eq!(
            registry.borrow().admissions.len(),
            usize::from(!closing),
            "closing {closing}"
        );
        assert_eq!(volume.metadata.fenced.is_some(), !closing);
    }
}

/// If a serving machine's window expires or the machine withdraws or closes while the gate's Register, Acquire or Report is outstanding, the attach ends `Unfenced(AuthorityLost)`. The gate log stops at that command, blocking medium commands. A sole own-holder Report delivered afterwards leaves the gate log stopped.
#[test]
fn a_withdrawal_close_or_window_expiry_during_any_gate_step_ends_the_attach() {
    use super::super::super::readiness::State;
    use super::super::GateRefusal;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    use crate::failover::serving::{Cause, Event, State as Serving};
    for (delivered, (event, serving)) in (0..3).flat_map(|delivered| {
        [
            (Event::Expire { now: 0 }, Serving::PreBoundary),
            (Event::Withdraw(Cause::Planned), Serving::Withdrawn),
            (Event::Close, Serving::Closed),
        ]
        .map(|case| (delivered, case))
    }) {
        let arena = reserving_arena();
        let storage = plain(2);
        let (mut volume, control, registry) = attach_reserving(
            &storage,
            &arena,
            crate::storage::ServingAuthority::fixture(),
        );
        registry.borrow_mut().budget = Some(delivered);
        ticks(&mut volume, &control, 8);
        let _ = volume.authority_event(event);
        assert_eq!(volume.authority_state(), serving);
        registry.borrow_mut().budget = None;
        ticks(&mut volume, &control, 8);
        assert_eq!(
            volume.metadata_outcome(),
            MetadataOutcome::Unfenced(GateRefusal::AuthorityLost),
            "{delivered} completions delivered, {serving:?}"
        );
        assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..=delivered]);
        assert_eq!(
            volume.authority_report().flip,
            None,
            "{delivered} completions delivered, {serving:?}"
        );
        assert!(volume.metadata.fenced.is_none());
        assert_eq!(medium(&control), 0);
        assert!(registry.borrow().admissions.is_empty());
        assert!(storage.is_closed());
        assert_eq!(volume.readiness(), State::Withheld);
    }
}

#[test]
fn a_planned_withdrawal_before_the_first_gate_command_ends_the_attach_with_no_command() {
    use super::super::GateRefusal;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    use crate::failover::serving::{Cause, Event, State as Serving};
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    assert!(
        registry.borrow().log.is_empty(),
        "no gate command before the first poll"
    );
    let _ = volume.authority_event(Event::Withdraw(Cause::Planned));
    assert_eq!(volume.authority_state(), Serving::Withdrawn);
    ticks(&mut volume, &control, 8);
    assert_eq!(
        volume.metadata_outcome(),
        MetadataOutcome::Unfenced(GateRefusal::AuthorityLost)
    );
    assert!(registry.borrow().log.is_empty(), "no gate command");
    assert_eq!(volume.authority_report().flip, None);
    assert!(volume.metadata.fenced.is_none());
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());
    assert!(storage.is_closed());
}

#[test]
fn a_withdrawal_whose_close_effects_stop_metadata_during_the_gate_ends_the_attach() {
    use super::super::GateRefusal;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    use crate::failover::serving::{Cause, Event};
    for delivered in 0..3 {
        let arena = reserving_arena();
        let storage = plain(2);
        let (mut volume, control, registry) = attach_reserving(
            &storage,
            &arena,
            crate::storage::ServingAuthority::fixture(),
        );
        registry.borrow_mut().budget = Some(delivered);
        ticks(&mut volume, &control, 8);
        let _ = volume.authority_event(Event::Withdraw(Cause::Planned));
        assert!(volume.storage().try_withdraw(), "the owner's close effects");
        assert!(volume.readiness().stops_metadata());
        registry.borrow_mut().budget = None;
        ticks(&mut volume, &control, 8);
        assert_eq!(
            volume.metadata_outcome(),
            MetadataOutcome::Unfenced(GateRefusal::AuthorityLost),
            "{delivered} completions delivered"
        );
        assert!(volume.metadata.fenced.is_none());
        assert_eq!(medium(&control), 0);
        assert!(registry.borrow().admissions.is_empty());
        assert!(storage.is_closed());
    }
}

#[test]
fn an_own_host_registration_conflicts_under_another_key_and_passes_under_its_own() {
    use super::super::super::device::ReservationCommand;
    use super::super::super::readiness::State;
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving, foreign, own};
    use super::super::{GateRefusal, GateStep};
    use crate::failover::evidence::{Pair, Registrant};
    use crate::failover::serving::{Cause, Deposing};
    for rekeyed in [true, false] {
        let arena = reserving_arena();
        let storage = plain(2);
        let (mut volume, control, registry) = attach_reserving(
            &storage,
            &arena,
            crate::storage::ServingAuthority::fixture(),
        );
        let key = if rekeyed { foreign().key } else { own().key };
        registry.borrow_mut().entries.push(Registrant {
            cntlid: 10,
            holder: false,
            pair: Pair { key, ..own() },
        });
        ticks(&mut volume, &control, 32);
        if rekeyed {
            assert_eq!(
                volume.metadata_outcome(),
                MetadataOutcome::Unfenced(GateRefusal::CommandFailed(GateStep::Register))
            );
            assert_eq!(
                registry.borrow().log.as_slice(),
                &[gate_log()[0], ReservationCommand::Report { not_before: 2 }]
            );
            let report = volume.authority_report();
            assert_eq!(
                (report.state, report.withdrawal, report.flip),
                (
                    crate::failover::serving::State::Withdrawn,
                    Some(Cause::Status(Deposing::Conflict)),
                    None
                ),
                "an own-host record under another key is not retirement evidence before the boundary"
            );
            assert_eq!(medium(&control), 0);
            assert!(registry.borrow().admissions.is_empty());
            assert_eq!(volume.readiness(), State::Withheld);
        } else {
            assert_eq!(registry.borrow().log[..3], gate_log());
            assert_eq!(volume.metadata_outcome(), MetadataOutcome::Unformatted);
        }
    }
}

/// An unsuccessful gate Report ends the attach `Unfenced(CommandFailed(Report))`; the missing Report evidence closes the serving window. A reservation conflict deposes the serving machine and ends the attach `Unfenced(AuthorityLost)`. A gate submission refused because of device loss loses the volume while the reservation-command log remains empty. These outcomes block medium commands.
#[test]
fn a_failed_report_a_deposing_report_and_a_lost_device_end_the_gate() {
    use super::super::super::device::{DeviceStatus, RefusalReason};
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    use super::super::{GateRefusal, GateStep};
    use crate::failover::evidence::RESERVATION_CONFLICT;
    use crate::failover::serving::State as Serving;
    for (status, refusal, serving) in [
        (
            DeviceStatus::Nvme(0x6 << 1),
            GateRefusal::CommandFailed(GateStep::Report),
            Serving::PreBoundary,
        ),
        (
            DeviceStatus::Nvme(RESERVATION_CONFLICT << 1),
            GateRefusal::AuthorityLost,
            Serving::Withdrawn,
        ),
    ] {
        let arena = reserving_arena();
        let storage = plain(2);
        let (mut volume, control, registry) = attach_reserving(
            &storage,
            &arena,
            crate::storage::ServingAuthority::fixture(),
        );
        registry.borrow_mut().report_status = Some(status);
        ticks(&mut volume, &control, 32);
        assert_eq!(
            volume.metadata_outcome(),
            MetadataOutcome::Unfenced(refusal)
        );
        let report = volume.authority_report();
        assert_eq!(report.state, serving, "{refusal:?}");
        if serving == Serving::Withdrawn {
            assert_eq!(
                (report.withdrawal, report.flip),
                (
                    Some(crate::failover::serving::Cause::Status(
                        crate::failover::serving::Deposing::Conflict
                    )),
                    None
                ),
                "{report:?}"
            );
        }
        assert_eq!(registry.borrow().log.as_slice(), &gate_log()[..]);
        assert_eq!(medium(&control), 0);
        assert!(registry.borrow().admissions.is_empty());
    }
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().refuse = Some(RefusalReason::DeviceGone);
    ticks(&mut volume, &control, 8);
    assert!(volume.is_lost());
    assert!(registry.borrow().log.is_empty());
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());
}

/// A driver without reservation commands ends the attach `Unfenced(Unsupported)` with no medium command once the test-build pass-through is off.
#[test]
fn a_driver_without_reservations_refuses_unsupported() {
    refuses_unsupported(crate::storage::ServingAuthority::fixture());
}

#[test]
fn a_restart_value_over_a_driver_without_reservations_refuses_unsupported() {
    let mut authority = crate::storage::ServingAuthority::fixture();
    authority.pending_fence = Some(super::super::fence::Fenced::assumed());
    refuses_unsupported(authority);
}

fn refuses_unsupported(authority: crate::storage::ServingAuthority) {
    use super::super::super::readiness::State;
    use super::super::GateRefusal;
    use super::super::fence::UNGATED;
    /// Restores the pass-through when the test ends, a failing assertion included.
    struct Ungated;
    impl Drop for Ungated {
        fn drop(&mut self) {
            UNGATED.set(true);
        }
    }
    let _ungated = Ungated;
    UNGATED.set(false);
    let arena = arena();
    let storage = plain(2);
    let (disk, control) = super::super::super::volume_fixture::device_with(
        7,
        super::super::super::volume_fixture::BUFFER,
    );
    let mut volume = super::super::bootstrap_tests::attach_with(&storage, &arena, disk, authority);
    ticks(&mut volume, &control, 8);
    assert_eq!(
        volume.metadata_outcome(),
        MetadataOutcome::Unfenced(GateRefusal::Unsupported)
    );
    assert_eq!(medium(&control), 0);
    assert_eq!(volume.readiness(), State::Withheld);
}

/// A Report's byte-count status passes the gate only when it equals the Report's transfer length, and a successful Report whose bytes fail the driver's check ends the attach `Unfenced(ReportUnreadable)`; neither refusal issues a medium command.
#[test]
fn a_report_passes_only_at_its_length_and_with_checked_bytes() {
    use super::super::super::device::{DeviceStatus, ReportError};
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving, limits};
    use super::super::{GateRefusal, GateStep};
    for (status, check, outcome) in [
        (
            Some(DeviceStatus::Kernel(limits().report_bytes() as i32)),
            None,
            MetadataOutcome::Unformatted,
        ),
        (
            Some(DeviceStatus::Kernel(4096)),
            None,
            MetadataOutcome::Unfenced(GateRefusal::CommandFailed(GateStep::Report)),
        ),
        (
            None,
            Some(ReportError::Unchecked),
            MetadataOutcome::Unfenced(GateRefusal::ReportUnreadable),
        ),
    ] {
        let arena = reserving_arena();
        let storage = plain(2);
        let (mut volume, control, registry) = attach_reserving(
            &storage,
            &arena,
            crate::storage::ServingAuthority::fixture(),
        );
        {
            let mut registry = registry.borrow_mut();
            registry.report_status = status;
            registry.report_check = check;
        }
        ticks(&mut volume, &control, 32);
        assert_eq!(volume.metadata_outcome(), outcome, "{status:?} {check:?}");
        if outcome != MetadataOutcome::Unformatted {
            assert!(volume.metadata.fenced.is_none());
            assert_eq!(medium(&control), 0);
            assert!(registry.borrow().admissions.is_empty());
            assert!(storage.is_closed());
        }
    }
}

/// A standby attaching its own fresh spare holds no token, so however long it ticks and services its driver it issues no device command: no reservation command, no driver housekeeping and no medium command.
#[test]
fn standby_spare_attach_issues_no_command() {
    use super::super::gate_fixture::{arena as reserving_arena, attach_reserving};
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture_standby(),
    );
    ticks(&mut volume, &control, 64);
    volume.service_disk();
    assert!(registry.borrow().log.is_empty());
    assert_eq!(registry.borrow().services, 0, "no driver housekeeping");
    assert_eq!(medium(&control), 0);
    assert!(registry.borrow().admissions.is_empty());
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Bootstrapping);
    assert!(
        !volume.metadata_ready(),
        "an idle tokenless gate reports no metadata work"
    );
}

/// A medium holding a valid root at or above the session, in either slot, ends the bootstrap `StaleSession` after
/// its two probe reads: no write, the media unchanged and admission closed.
#[test]
fn stale_session_refuses_before_any_write() {
    let arena = arena();
    let attempt = 7;
    let expected = crate::storage::session_at(1, attempt).get();
    for (a, b) in [(expected, 4), (4, expected + 1)] {
        let store = formatted(a, b);
        let before = store.borrow().clone();
        let storage = plain(2);
        let (disk, control) = over(&store);
        let session = crate::storage::session_at(1, attempt);
        let mut volume = attach_under(&storage, &arena, disk, session);
        assert_eq!(
            run(&mut volume, &control),
            MetadataOutcome::StaleSession,
            "{a} {b}"
        );
        let reads = super::super::bootstrap_tests::read_starts(&control);
        assert_eq!(reads, [0, 4096], "read only the root slots");
        for _ in 0..8 {
            tick(&mut volume, &control);
        }
        assert!(writes(&control).is_empty(), "wrote nothing");
        assert!(*store.borrow() == before, "left the media unchanged");
        assert!(storage.is_closed(), "closed admission");
    }
}

/// A format writes both RESET roots under the session.
#[test]
fn format_writes_the_tenure_session() {
    let arena = arena();
    let session = crate::storage::next_session();
    let expected = session.get();
    let store = media(MEDIA);
    let storage = plain(2);
    let (disk, control) = over(&store);
    let mut volume = attach_under(&storage, &arena, disk, session);
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Unformatted);
    assert_eq!(volume.format_from(fixture_format), Ok(()));
    assert_eq!(run(&mut volume, &control), MetadataOutcome::Open);
    assert_eq!(volume.session(), expected);
    assert_eq!(generations(&store), [Some(expected); 2]);
}

#[test]
fn no_device_read_or_write_before_fb() {
    use super::super::gate_fixture::{
        arena as reserving_arena, attach_reserving, bounds_of, limits,
    };
    use crate::failover::evidence::Registrant;
    use crate::failover::fresh::tests::{Log, activate};
    use crate::failover::serving::State;
    let log = Log::default();
    let (activated, own) = activate(&log);
    let report = log.borrow().iter().position(|command| *command == "report");
    let report = report.expect("the fresh Report");
    assert!(
        log.borrow()[..report]
            .iter()
            .all(|command| !["write", "read"].contains(command)),
        "{log:?}"
    );
    let expected = (
        activated.session().generation(),
        activated.session().epoch(),
    );
    let (authority, fencing) = crate::storage::ServingAuthority::activated(
        bounds_of(limits()),
        Box::new(super::super::gate_fixture::ZeroClock),
        activated,
    );
    assert!(fencing.coverage().is_some());
    let arena = reserving_arena();
    let storage = plain(2);
    let (mut volume, control, registry) = attach_reserving(&storage, &arena, authority);
    {
        let mut registry = registry.borrow_mut();
        registry.entries.push(Registrant {
            cntlid: 10,
            pair: own,
            holder: true,
        });
        registry.rtype = 2;
    }
    ticks(&mut volume, &control, 8);
    assert_eq!(
        (volume.authority_state(), volume.authority_withdrawal()),
        (State::Recovering, None)
    );
    let token = volume
        .serving_token()
        .expect("the crossing issues the token");
    assert_eq!((token.exhid, token.key), (own.exhid, own.key));
    assert_eq!((token.generation, token.epoch), expected);
    let registry = registry.borrow();
    assert!(!registry.log.is_empty());
    assert!(
        registry.log.iter().all(|command| command.is_report()),
        "no Register or Acquire at the gate: {:?}",
        registry.log
    );
    assert_eq!(
        registry.admissions,
        [(0, false)],
        "one admission, before any medium command"
    );
}

/// The fixture's reserving driver under reservation limits the test chooses.
struct Limited {
    inner: Reserving,
    limits: ReservationLimits,
}

// SAFETY: every command passes unchanged to the reserving fixture driver, which keeps the contract; the reservation limits, and the Report check made under them, are the test's.
unsafe impl Disk for Limited {
    fn geometry(&self) -> DeviceGeometry {
        self.inner.geometry()
    }

    unsafe fn submit_read(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        // SAFETY: the caller's contract passes through.
        unsafe { self.inner.submit_read(token, device, memory) }
    }

    unsafe fn submit_write(
        &mut self,
        token: CommandToken,
        device: DeviceRange,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        // SAFETY: the caller's contract passes through.
        unsafe { self.inner.submit_write(token, device, memory) }
    }

    fn admit_medium(&mut self, gate: &super::super::Fenced) {
        self.inner.admit_medium(gate);
    }

    fn reservation_limits(&self) -> Option<ReservationLimits> {
        Some(self.limits)
    }

    fn check_reservation_report(
        &self,
        bytes: &[u8],
    ) -> Result<(), super::super::super::device::ReportError> {
        super::super::super::device::check_report_identity(
            bytes,
            self.limits,
            super::super::gate_fixture::own(),
        )
    }

    unsafe fn submit_reservation(
        &mut self,
        token: CommandToken,
        command: super::super::super::device::ReservationCommand,
        memory: DmaRange,
    ) -> Result<(), SubmitRefusal> {
        // SAFETY: the caller's contract passes through.
        unsafe { self.inner.submit_reservation(token, command, memory) }
    }

    fn pick_completions(&mut self, sink: &mut CompletionSink<'_>) {
        self.inner.pick_completions(sink);
    }

    fn quiesce(&mut self) -> QuiesceStatus {
        self.inner.quiesce()
    }

    fn service(&mut self) {
        self.inner.service();
    }

    fn attach_facts(&self) -> Option<&AttachFacts> {
        self.inner.attach_facts()
    }
}

/// The bytes attach holds per registrant the driver allows: its entry in the registrant scratch array and its room in the pending vector of pairs with their times.
const PER_REGISTRANT: usize = size_of::<crate::failover::evidence::Registrant>()
    + size_of::<(crate::failover::evidence::Pair, u64)>();

/// The charge of an attach over a simulated driver that states no reservation limits, under the fixture's storage, pools, depth and tick.
fn charge_without_limits() -> usize {
    use super::super::super::portable::scripted::ScriptedClock;
    use super::super::super::volume_fixture::{BUFFER, DEPTH, TICK, device_with};
    use super::super::gate_fixture::{arena, storage};
    use super::super::{ServingAuthority, Volume};
    let (storage, arena) = (storage(), arena());
    let (disk, _control) = device_with(7, BUFFER);
    Volume::attach_charge(
        &storage,
        &arena,
        &disk,
        &*ScriptedClock::trusted(),
        &ServingAuthority::fixture(),
        DEPTH,
        TICK,
    )
    .expect("the fixture's inputs pass attach's checks")
}

/// Attaches over a reserving driver whose limits allow `registrants` registrants, first with one byte less than the total the test computes and then with exactly that total.
/// The total is the charge of the same attach over a driver without limits, the command table's reservation slots, and one registrant entry and one pending pair's room per registrant: the smaller budget refuses `Envelope` and charges nothing, and the exact one attaches and is charged in full.
fn the_total_attaches_and_one_byte_less_refuses(registrants: u32) {
    use super::super::super::device::CommandTable;
    use super::super::super::ledger::EngineBudget;
    use super::super::super::portable::scripted::ScriptedClock;
    use super::super::super::volume_fixture::{BUFFER, DEPTH, TICK, device_with};
    use super::super::gate_fixture::{arena, reserving, storage};
    use super::super::{AttachError, ServingAuthority, Volume};
    let limits = ReservationLimits::new(registrants, 2, 100, 100).expect("valid limits");
    let (storage, arena) = (storage(), arena());
    let (disk, _control) = device_with(7, BUFFER);
    let (inner, _registry) = reserving(disk);
    let disk = Limited { inner, limits };
    // The table charges one reservation slot per command the limits allow, whatever their registrant count; the registrant term comes from the element sizes alone.
    let total = charge_without_limits()
        + CommandTable::<Limited>::reservation_metadata_bytes(&disk)
        + registrants as usize * PER_REGISTRANT;

    let mut short = EngineBudget::new(total - 1);
    let Err((refusal, disk)) = Volume::<TestPlatform, Limited>::attach(
        &storage,
        &arena,
        disk,
        ScriptedClock::trusted(),
        ServingAuthority::fixture_limits(limits),
        DEPTH,
        TICK,
        &mut short,
    ) else {
        panic!(
            "a budget one byte below the arrays of {registrants} registrants must refuse the attach"
        );
    };
    assert!(
        matches!(refusal, AttachError::Envelope(_)),
        "one byte below the total for {registrants} registrants refused {refusal:?}"
    );
    assert_eq!(short.used(), 0, "a refused attach charges nothing");

    let mut exact = EngineBudget::new(total);
    let attached = Volume::<TestPlatform, Limited>::attach(
        &storage,
        &arena,
        disk,
        ScriptedClock::trusted(),
        ServingAuthority::fixture_limits(limits),
        DEPTH,
        TICK,
        &mut exact,
    )
    .map_err(|(refusal, _)| refusal);
    assert!(
        attached.is_ok(),
        "the total for {registrants} registrants refused {:?}",
        attached.err()
    );
    assert_eq!(
        exact.used(),
        total,
        "attach charges the arrays of {registrants} registrants"
    );
}

/// Under limits of three registrants, attach charges three registrant entries and three pending pairs' room beside its other arrays: that total attaches, and one byte less refuses `Envelope`.
#[test]
fn attach_charges_the_arrays_of_three_registrants() {
    the_total_attaches_and_one_byte_less_refuses(3);
}

/// The same under limits of forty registrants: the charge follows the driver's registrant limit.
#[test]
fn attach_charges_the_arrays_of_forty_registrants() {
    the_total_attaches_and_one_byte_less_refuses(40);
}

/// Raising the driver's registrant limit raises the charge by the entry and pending room of each added registrant.
#[test]
fn each_allowed_registrant_adds_its_entry_and_pending_room_to_the_charge() {
    use super::super::super::portable::scripted::ScriptedClock;
    use super::super::super::volume_fixture::{BUFFER, DEPTH, TICK, device_with};
    use super::super::gate_fixture::{arena, reserving, storage};
    use super::super::{ServingAuthority, Volume};
    let charge = |registrants: u32| {
        let limits = ReservationLimits::new(registrants, 2, 100, 100).expect("valid limits");
        let (storage, arena) = (storage(), arena());
        let (disk, _control) = device_with(7, BUFFER);
        let (inner, _registry) = reserving(disk);
        Volume::attach_charge(
            &storage,
            &arena,
            &Limited { inner, limits },
            &*ScriptedClock::trusted(),
            &ServingAuthority::fixture_limits(limits),
            DEPTH,
            TICK,
        )
        .expect("the fixture's inputs pass attach's checks")
    };
    assert_eq!(charge(40) - charge(3), 37 * PER_REGISTRANT);
    assert_eq!(charge(4) - charge(3), PER_REGISTRANT);
}

#[test]
fn driver_limits_that_disagree_with_the_serving_bounds_refuse_attach() {
    use super::super::super::portable::scripted::ScriptedClock;
    use super::super::super::volume_fixture::{BUFFER, DEPTH, TICK, device_with};
    use super::super::gate_fixture::{arena, limits, reserving, storage};
    use super::super::{AttachError, ServingAuthority, Volume};
    let serving = limits();
    let charge = |driver: ReservationLimits| {
        let (storage, arena) = (storage(), arena());
        let (disk, _control) = device_with(7, BUFFER);
        let (inner, _registry) = reserving(disk);
        Volume::attach_charge(
            &storage,
            &arena,
            &Limited {
                inner,
                limits: driver,
            },
            &*ScriptedClock::trusted(),
            &ServingAuthority::fixture_limits(serving),
            DEPTH,
            TICK,
        )
    };
    assert!(charge(serving).is_ok());
    let (registrants, deadline) = (serving.registrants(), serving.report_timeout());
    for (registrants, deadline) in [
        (registrants - 1, deadline),
        (registrants + 1, deadline),
        (registrants, deadline - 1),
        (registrants, deadline + 1),
    ] {
        let driver = ReservationLimits::new(registrants, 2, deadline, 100).expect("valid limits");
        assert_eq!(
            charge(driver),
            Err(AttachError::AuthorityBounds),
            "{driver:?}"
        );
    }
}

/// The serving-clock reading of the turns before the authority stops admitting.
const SAMPLED: u64 = 100;

/// How the authority stops admitting the read's token between the first command and the grant of the second, or the control in which it keeps admitting.
#[derive(Debug, Clone, Copy)]
enum Stop {
    /// The authority keeps admitting: the control that shows the grant submits the second command.
    Never,
    /// The serving window closes.
    Expired,
    /// The tenure withdraws.
    Withdrawn,
    /// The serving clock reads earlier than the owner's last deadline sample, with no event and no turn in between.
    ClockBackward,
}

const STOPS: [Stop; 3] = [Stop::Expired, Stop::Withdrawn, Stop::ClockBackward];

/// Stops the authority admitting as `stop` names and checks that it refuses a read on a fresh reading: `NotServing` once withdrawn, `WindowExpired` otherwise. `Stop::Never` changes nothing.
fn stop(volume: &mut TestVolume<'_, '_>, time: &std::cell::Cell<u64>, stop: Stop) {
    use crate::failover::serving::{Cause, Denial, Event, Operation, ReportTrigger, State};
    match stop {
        Stop::Never => return,
        Stop::Expired => {
            volume.authority_event(Event::Expire { now: SAMPLED });
        }
        Stop::Withdrawn => {
            volume.authority_event(Event::Withdraw(Cause::Report(
                ReportTrigger::new(crate::failover::evidence::NotSole::ReservationType).unwrap(),
            )));
        }
        Stop::ClockBackward => time.set(SAMPLED - 1),
    }
    let denial = volume
        .admit_authority(Operation::Read, volume.serving_token())
        .expect_err("the authority refuses a read on a fresh reading");
    match stop {
        Stop::Withdrawn => assert_eq!(denial, Denial::NotServing(State::Withdrawn)),
        _ => assert_eq!(denial, Denial::WindowExpired),
    }
}

/// The count of `Chunk` events in `out` and the status of its `Done`, if one was delivered.
fn delivered(out: &[ReadEvent<'_>]) -> (usize, Option<ReadStatus>) {
    let chunks = out
        .iter()
        .filter(|event| matches!(event, ReadEvent::Chunk { .. }))
        .count();
    let done = out.iter().find_map(|event| match event {
        ReadEvent::Done { status, .. } => Some(*status),
        ReadEvent::Chunk { .. } => None,
    });
    (chunks, done)
}

/// The first command's `Chunk` event is handed off inside the window; the grant of the second command then arrives after the authority stopped admitting.
/// FRESH-AT-EFFECT: the grant submits no read command, and the read ends `Quiesced` with no further `Chunk` event.
/// In the control, whose authority keeps admitting, the same grant submits the second command and the read ends `Complete` with a second `Chunk` event.
#[test]
fn a_grant_after_the_first_handoff_submits_no_command_once_the_authority_refuses() {
    for case in STOPS.into_iter().chain([Stop::Never]) {
        grant_after_the_first_handoff(case, false);
    }
}

/// Runs the read under `case`; when `rewind` holds, the serving clock reads `SAMPLED` from after the stop on.
fn grant_after_the_first_handoff(case: Stop, rewind: bool) {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::super::volume_tests::{
        CHUNK, SESSION, TICK, arena, attach, place, record, storage, submits,
    };
    let storage = storage(1);
    let arena = arena();
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let time = Rc::new(Cell::new(SAMPLED));
    volume.authority.clock = Box::new(Clock(Rc::clone(&time)));
    let record = record(3, 100, 2 * CHUNK + 5, SESSION, 1);
    place(&storage, &control, &record);
    let before = submits(&control);
    let op = volume.read_raw(&record.read, u64::MAX).unwrap();
    assert_eq!(submits(&control), before + 1, "the first command");
    control.tick(64);
    let mut out = Vec::with_capacity(8);
    volume.poll_storage(0, &mut out);
    assert_eq!(
        delivered(&out),
        (1, None),
        "the first command hands off one chunk and the read waits for a grant at {case:?}"
    );
    stop(&mut volume, &time, case);
    if rewind {
        time.set(SAMPLED);
    }
    assert_eq!(volume.grant_read(op), Ok(Grant::Added));
    let second = usize::from(matches!(case, Stop::Never));
    assert_eq!(
        submits(&control),
        before + 1 + second,
        "FRESH-AT-EFFECT: the device accepted a read command the authority did not admit at {case:?}"
    );
    assert_eq!(
        volume.report().reads_submitted,
        1 + second as u64,
        "at {case:?}"
    );
    control.tick(64);
    volume.poll_storage(0, &mut out);
    assert_eq!(
        submits(&control),
        before + 1 + second,
        "FRESH-AT-EFFECT: a later tick submitted the refused command at {case:?}"
    );
    let expected = match case {
        Stop::Never => (2, Some(ReadStatus::Complete)),
        _ => (1, Some(ReadStatus::Quiesced)),
    };
    assert_eq!(delivered(&out), expected, "at {case:?}");
    drop(out);
    assert_eq!(volume.reads.live(), 0);
    assert_eq!(volume.table_report().pending, 0);
    volume.close();
}

/// The clock reads `SAMPLED` again after the backward stop, so the grant's reading equals the last deadline sample.
#[test]
#[should_panic(expected = "FRESH-AT-EFFECT: the device accepted a read command")]
fn negative_control_a_grant_admitted_on_the_deadline_sample_fails_fresh_at_effect() {
    grant_after_the_first_handoff(Stop::ClockBackward, true);
}

/// On a volume that reads ahead, a grant arriving while the first command is outstanding submits the second command ahead of it.
/// FRESH-AT-EFFECT: once the authority stopped admitting, that grant submits nothing, no later grant or tick submits a command, and the read ends `Quiesced` with no chunk.
#[test]
fn a_grant_for_a_command_ahead_submits_nothing_once_the_authority_refuses() {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::super::volume_tests::{
        CHUNK, SESSION, TICK, arena_with_read_len, attach, place, record, storage_reading_ahead,
        submits,
    };
    for case in STOPS.into_iter().chain([Stop::Never]) {
        let storage = storage_reading_ahead(2);
        let arena = arena_with_read_len(2 * CHUNK);
        let (mut volume, control) = attach(&storage, &arena, TICK);
        let time = Rc::new(Cell::new(SAMPLED));
        volume.authority.clock = Box::new(Clock(Rc::clone(&time)));
        let record = record(0, 0, 5 * CHUNK, SESSION, 1);
        place(&storage, &control, &record);
        let mut out = Vec::with_capacity(16);
        volume.poll_storage(0, &mut out);
        assert!(out.is_empty());
        let before = submits(&control);
        let op = volume.read_raw(&record.read, u64::MAX).unwrap();
        assert_eq!(submits(&control), before + 1, "the first command");
        stop(&mut volume, &time, case);
        assert_eq!(volume.grant_read(op), Ok(Grant::Added));
        let admitted = matches!(case, Stop::Never);
        assert_eq!(
            submits(&control),
            before + 1 + usize::from(admitted),
            "FRESH-AT-EFFECT: the device accepted a command ahead the authority did not admit at {case:?}"
        );
        assert_eq!(
            volume.report().reads_ahead,
            u64::from(admitted),
            "at {case:?}"
        );
        // Each round drops the chunks it took, so their buffers return to the pool.
        let (mut chunks, mut done) = (0, None);
        for _ in 0..64 {
            control.tick(64);
            volume.poll_storage(0, &mut out);
            let round = delivered(&out);
            out.clear();
            chunks += round.0;
            done = round.1;
            if done.is_some() {
                break;
            }
            let _ = volume.grant_read(op);
            assert!(
                admitted || submits(&control) == before + 1,
                "FRESH-AT-EFFECT: a tick or a later grant submitted a command the authority did not admit at {case:?}"
            );
        }
        if admitted {
            assert_eq!(done, Some(ReadStatus::Complete));
            assert!(chunks > 1, "the control hands off the record's commands");
            assert!(submits(&control) > before + 2);
        } else {
            assert_eq!(
                (chunks, done),
                (0, Some(ReadStatus::Quiesced)),
                "at {case:?}"
            );
        }
        drop(out);
        assert_eq!(volume.reads.live(), 0);
        assert_eq!(volume.table_report().pending, 0);
        volume.close();
    }
}
