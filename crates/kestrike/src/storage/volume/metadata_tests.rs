//! The metadata command owner over the simulated device: a staged metadata command goes to the device only on a serving-clock reading taken for its own submission and inside the Report window.

use std::cell::Cell;
use std::rc::Rc;

use super::super::checkpoint::{Checkpoint, PossiblyNamed, StagedCheckpoint};
use super::super::device::Disk;
use super::super::device::sim::SimControl;
use super::super::publish_tests::key;
use super::super::recovery::MetadataOutcome;
use super::super::test_platform::TestPlatform;
use super::super::volume_fixture::{Device, fixture_format};
use super::Volume;
use super::authority::ServingClock;
use super::gate_fixture::{arena, attach_reserving, bounds_with, limits, medium, own, ticks};
use super::metadata::{Phase, Target};
use super::placement_tests::test_layout;
use super::volume_tests::queue_full;
use crate::failover::serving::Machine;
use crate::net::ownership::Shard;

/// The Report window's length in the bounds of these tenures, in the serving clock's microseconds.
const WINDOW: u64 = 1_000;

/// A serving clock whose every reading is the value the test last set; `None` is a failed reading.
struct Reading(Rc<Cell<Option<u64>>>);
impl ServingClock for Reading {
    fn now_us(&self) -> Option<u64> {
        self.0.get()
    }
}

fn reading(time: Rc<Cell<Option<u64>>>) -> Box<dyn ServingClock> {
    Box::new(Reading(time))
}

/// A serving clock over the test's cell that answers its first reading above zero for every later reading the cell
/// holds. The fixture's time stays at zero until the deadline sample, so each later reading is that sample.
struct AtTheSample {
    time: Rc<Cell<Option<u64>>>,
    sample: Cell<Option<u64>>,
}
impl ServingClock for AtTheSample {
    fn now_us(&self) -> Option<u64> {
        let now = self.time.get()?;
        if now > 0 && self.sample.get().is_none() {
            self.sample.set(Some(now));
        }
        Some(self.sample.get().unwrap_or(now))
    }
}

/// How the staged command reaches its checked submissions.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Arrival {
    /// The checked submissions are the command's first.
    Immediate,
    /// The device's full queue refused the command once and the volume kept it staged.
    Retained,
}

/// The reading that submits the command after the refused ones.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Admitted {
    /// A reading one microsecond before the existing window's exclusive end.
    Inside,
    /// A reading at the old window's end, after a Report submitted at that instant renewed the window.
    Renewed,
}

type Tested<'s, 'a, D> = Volume<'s, 'a, TestPlatform, D>;

/// The targets of the staged, unsubmitted commands, in cell order.
fn staged<D: Disk>(volume: &Tested<'_, '_, D>) -> Vec<Target> {
    (volume.metadata.commands.iter().flatten())
        .filter(|command| command.buffer.is_some())
        .map(|command| command.target)
        .collect()
}

/// Whether no metadata command is staged or outstanding.
fn idle<D: Disk>(volume: &Tested<'_, '_, D>) -> bool {
    volume.metadata.commands.iter().all(Option::is_none)
}

/// Ticks the device and applies its terminals until the metadata is idle in a state `reached` accepts, checking
/// before each metadata step, so the phase's first command is not staged yet. The fixture gets 64 rounds, each one
/// device tick and one owner turn.
fn settle<D: Disk>(
    volume: &mut Tested<'_, '_, D>,
    control: &SimControl,
    what: &str,
    reached: impl Fn(&Tested<'_, '_, D>) -> bool,
) {
    let mut out = Vec::with_capacity(16);
    for _ in 0..64 {
        if idle(volume) && reached(volume) {
            return;
        }
        control.tick(64);
        volume.poll_terminals(0, &out);
        if idle(volume) && reached(volume) {
            return;
        }
        let _ = volume.poll_storage(0, &mut out);
        out.clear();
    }
    panic!("the bootstrap reaches {what} within 64 ticks");
}

/// Samples the deadlines two microseconds past the later of the window's start and the latest sample, stages one
/// command through `stage`, and checks that command's submissions against the clock: the staged-command premise,
/// each refused reading, then `admitted`.
fn rechecks_its_own_reading<D: Disk>(
    volume: &mut Tested<'_, '_, D>,
    control: &SimControl,
    time: &Rc<Cell<Option<u64>>>,
    (expect, arrival, admitted): (Target, Arrival, Admitted),
    stage: impl FnOnce(&mut Tested<'_, '_, D>),
) {
    let case = format!("{expect:?}, {arrival:?}, {admitted:?}");
    let window = |volume: &Tested<'_, '_, D>| {
        let machine = &volume.authority.machine;
        (
            machine.window_start().expect("a window"),
            machine.window_end().expect("a window"),
        )
    };
    let (start, end) = window(volume);
    let sample = start.max(volume.authority.now) + 2;
    assert!(sample < end - 1, "{case}: the sample leaves room inside");
    time.set(Some(sample));
    volume.authority_deadlines();
    assert_eq!(volume.authority.now, sample, "{case}: the deadline sample");
    assert_eq!(volume.authority.refusal, None, "{case}");

    stage(volume);
    assert_eq!(staged(volume), [expect], "{case}: one command is staged");
    assert_eq!(window(volume), (start, end), "{case}: the existing window");

    if arrival == Arrival::Retained {
        let refused = volume.report.metadata_refused;
        control.refuse_next(queue_full());
        assert_eq!(volume.metadata_step(1), 0, "{case}: the queue is full");
        assert_eq!(
            volume.report.metadata_refused,
            refused + 1,
            "{case}: the device refused the command once"
        );
        assert_eq!(staged(volume), [expect], "{case}: the refusal keeps it");
    }

    let (submitted, device) = (volume.report.metadata_submitted, medium(control));
    let mut readings = [
        (Some(end), "at the window's exclusive end"),
        (None, "absent"),
        (Some(sample - 1), "below the latest deadline sample"),
    ];
    // Each reading is the first one tried for two of the six command kinds.
    readings.rotate_left(match expect {
        Target::Probe(_) | Target::Delta(_) => 0,
        Target::Root | Target::UnitWrite { .. } => 1,
        Target::Slot | Target::UnitRead { .. } => 2,
    });
    for (reading, why) in readings {
        time.set(reading);
        assert_eq!(
            volume.metadata_step(1),
            0,
            "{case}: a submission whose own reading is {why} submits nothing"
        );
        assert_eq!(
            (volume.report.metadata_submitted, medium(control)),
            (submitted, device),
            "{case}: no command reaches the device on a reading {why}"
        );
        assert_eq!(staged(volume), [expect], "{case}: it stays staged, {why}");
        assert_eq!(volume.authority.now, sample, "{case}: the sample stands");
    }

    match admitted {
        Admitted::Inside => {
            time.set(Some(end - 1));
            assert_eq!(
                volume.metadata_step(1),
                1,
                "{case}: a reading just inside the window submits the command"
            );
        }
        Admitted::Renewed => {
            time.set(Some(end));
            ticks(volume, control, 8);
            assert_eq!(
                volume.authority.machine.window_start(),
                Some(end),
                "{case}: a Report submitted at the old end renewed the window"
            );
        }
    }
    assert!(
        volume.report.metadata_submitted > submitted && medium(control) > device,
        "{case}: the admitted reading sends the command to the device"
    );
    assert!(
        !staged(volume).contains(&expect) || admitted == Admitted::Renewed,
        "{case}: the command left its staged state"
    );
}

/// Stages the command the volume's own metadata step stages, a bootstrap phase's command or an open volume's sealed
/// suffix block: a step with a quota of zero stages it and submits nothing.
fn by_the_step<D: Disk>(volume: &mut Tested<'_, '_, D>) {
    assert_eq!(volume.metadata_step(0), 0);
}

/// The stage of a bootstrap, or of an open volume's checkpoint, whose command the case checks.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Stage {
    ProbeA,
    ProbeB,
    Root,
    UnitWrite,
    UnitRead,
}

/// Builds the volume's serving clock over the test's cell, whose value the test sets.
type ClockOver = fn(Rc<Cell<Option<u64>>>) -> Box<dyn ServingClock>;

/// Attaches a volume over the reserving driver under a tenure whose Report window is [`WINDOW`] long and whose
/// serving clock `clock` builds over the test's cell, drives it to `stage` and checks that stage's command.
fn over_the_reserving_driver(stage: Stage, case: (Arrival, Admitted), clock: ClockOver) {
    let bounds = bounds_with(limits(), WINDOW, 0);
    let session = crate::storage::next_session();
    let time = Rc::new(Cell::new(Some(0)));
    let authority = super::ServingAuthority::new(
        bounds,
        Machine::issued(bounds, &session, own()),
        clock(Rc::clone(&time)),
        session,
    );
    let buffers = arena();
    let storage = super::gate_fixture::storage();
    let (mut volume, control, _registry) = attach_reserving(&storage, &buffers, authority);
    let volume = &mut volume;

    settle(volume, &control, "the probe of slot A", |volume| {
        matches!(volume.metadata.phase, Phase::ProbeA)
    });
    if stage == Stage::ProbeA {
        let expect = Target::Probe(super::super::recovery::Slot::A);
        return rechecks_its_own_reading(
            volume,
            &control,
            &time,
            (expect, case.0, case.1),
            by_the_step,
        );
    }
    settle(volume, &control, "the probe of slot B", |volume| {
        matches!(volume.metadata.phase, Phase::ProbeB(_))
    });
    if stage == Stage::ProbeB {
        let expect = Target::Probe(super::super::recovery::Slot::B);
        return rechecks_its_own_reading(
            volume,
            &control,
            &time,
            (expect, case.0, case.1),
            by_the_step,
        );
    }
    settle(volume, &control, "unformatted media", |volume| {
        matches!(volume.metadata.phase, Phase::Unformatted)
    });
    volume.format_from(fixture_format).expect("fresh media");
    assert!(matches!(volume.metadata.phase, Phase::Reset { .. }));
    if stage == Stage::Root {
        return rechecks_its_own_reading(
            volume,
            &control,
            &time,
            (Target::Root, case.0, case.1),
            by_the_step,
        );
    }
    settle(volume, &control, "the open volume", |volume| {
        matches!(volume.metadata.phase, Phase::Open)
    });
    assert_eq!(volume.metadata_outcome(), MetadataOutcome::Open);
    let feed = volume.storage().feed;
    let _ = volume.begin_replay(feed, 0);
    ticks(volume, &control, 2);
    assert_eq!(
        volume.authority_state(),
        crate::failover::serving::State::Serving,
        "the checkpoint-unit kind needs a serving tenure"
    );

    let shard = Shard::new(7).unwrap();
    let mut possible = PossiblyNamed::new((shard, 2), test_layout(), None);
    let checkpoint = Checkpoint {
        shard,
        session: 2,
        capture: 2,
    };
    let units = vec![Box::new([0x5A; super::super::recovery::checkpoint::UNIT_LEN]); 4];
    let mut reserved = StagedCheckpoint::reserved_at(&mut possible, checkpoint, 1, units);
    let (slot, unit) = (1, 2);
    if stage == Stage::UnitWrite {
        rechecks_its_own_reading(
            volume,
            &control,
            &time,
            (Target::UnitWrite { slot, unit }, case.0, case.1),
            |volume| {
                volume
                    .stage_unit_write(&possible, &mut reserved, unit)
                    .expect("the unit write stages");
            },
        );
    } else {
        rechecks_its_own_reading(
            volume,
            &control,
            &time,
            (Target::UnitRead { slot, unit }, case.0, case.1),
            |volume| {
                volume
                    .stage_unit_read(&possible, (slot, unit))
                    .expect("the read-back stages");
            },
        );
    }
}

const ARRIVALS: [(Arrival, Admitted); 4] = [
    (Arrival::Immediate, Admitted::Inside),
    (Arrival::Immediate, Admitted::Renewed),
    (Arrival::Retained, Admitted::Inside),
    (Arrival::Retained, Admitted::Renewed),
];

/// A staged probe of either root slot is submitted only on a serving-clock reading taken for that submission and inside the Report window: a reading at the window's exclusive end, a failed reading or one below the latest deadline sample submits nothing and keeps the probe staged.
#[test]
fn a_staged_probe_is_submitted_only_on_its_own_reading_inside_the_window() {
    for case in ARRIVALS {
        over_the_reserving_driver(Stage::ProbeA, case, reading);
        over_the_reserving_driver(Stage::ProbeB, case, reading);
    }
}

/// A staged RESET root write is held back by the same three readings and submitted on one inside the window.
#[test]
fn a_staged_reset_root_write_is_submitted_only_on_its_own_reading_inside_the_window() {
    for case in ARRIVALS {
        over_the_reserving_driver(Stage::Root, case, reading);
    }
}

/// A staged checkpoint-unit write on a serving volume is held back by the same three readings and submitted on one inside the window.
#[test]
fn a_staged_checkpoint_unit_write_is_submitted_only_on_its_own_reading_inside_the_window() {
    for case in ARRIVALS {
        over_the_reserving_driver(Stage::UnitWrite, case, reading);
    }
}

/// A staged checkpoint-unit read-back on a serving volume is held back by the same three readings and submitted on one inside the window.
#[test]
fn a_staged_checkpoint_unit_read_back_is_submitted_only_on_its_own_reading_inside_the_window() {
    for case in ARRIVALS {
        over_the_reserving_driver(Stage::UnitRead, case, reading);
    }
}

/// The clock returns the latest deadline sample for the probe's readings, so the probe sees an in-window value at
/// the window's exclusive end.
#[test]
#[should_panic(expected = "whose own reading is at the window's exclusive end submits nothing")]
fn negative_control_a_probe_admitted_on_the_deadline_sample_fails_its_own_reading_check() {
    over_the_reserving_driver(
        Stage::ProbeA,
        (Arrival::Immediate, Admitted::Inside),
        |time| {
            Box::new(AtTheSample {
                time,
                sample: Cell::new(None),
            })
        },
    );
}

/// A cold tenure over the simulated device with no reservation commands, so no Report renews its window, opens its
/// suffix log, publishes one object and seals the block that records it; the next metadata step stages that block's
/// write in the journal cell.
fn a_sealed_suffix_block(arrival: Arrival) {
    use super::super::checkpoint::SuffixLimits;
    use super::super::device::sim::media;
    use super::super::publication_tests::publish;
    use super::super::record::Crc32c;
    use super::super::recovery::suffix::SuffixLog;
    use super::super::volume_fixture::{MEDIA, arena_with, attach_under, bootstrap};
    use super::warm::sim_tests::{layout, storage};
    use crate::failover::records::Suffix;

    let bounds = bounds_with(limits(), WINDOW, 0);
    let session = crate::storage::next_session();
    let time = Rc::new(Cell::new(Some(0)));
    let authority = super::ServingAuthority::new(
        bounds,
        Machine::issued(bounds, &session, own()),
        Box::new(Reading(Rc::clone(&time))),
        session,
    );
    let own_suffix = Suffix {
        session: authority.session().get(),
        start: 0,
        certified: 0,
        end: 16,
    };
    let storage = storage(1);
    let buffers = arena_with(4, 9);
    let (mut volume, control) =
        attach_under(&storage, &buffers, &media(MEDIA), authority).expect("attach");
    bootstrap(&mut volume, &control);
    let limits = SuffixLimits {
        flush_ns: 0,
        queue_blocks: 8,
        oldest_ns: 1 << 40,
        uncertified: 16,
    };
    let shard = super::super::store_tests::shard();
    let opened = storage.with_suffix(|log| {
        log.open(
            (Crc32c::detect(), shard),
            (limits, &layout()),
            own_suffix,
            0,
        )
    });
    assert_eq!(opened, Ok(true), "the suffix log opens");
    let mut dev = Device { volume, control };
    drop(publish(&storage, &mut dev, &key(1), &[1; 40]).expect("the object publishes"));
    assert_eq!(
        dev.volume.authority_state(),
        crate::failover::serving::State::Serving
    );
    let lsn = storage.with_suffix(|log| log.head()).unwrap();
    storage.with_suffix(SuffixLog::seal_cut).unwrap();
    assert!(idle(&dev.volume), "no metadata command before the stage");
    rechecks_its_own_reading(
        &mut dev.volume,
        &dev.control,
        &time,
        (Target::Delta(lsn), arrival, Admitted::Inside),
        by_the_step,
    );
}

/// A staged suffix block write is held back by the same three readings and submitted on one just inside the existing window.
#[test]
fn a_staged_suffix_block_write_is_submitted_only_on_its_own_reading_inside_the_window() {
    a_sealed_suffix_block(Arrival::Immediate);
    a_sealed_suffix_block(Arrival::Retained);
}

/// A successor takes the volume over from a tenure that left a named checkpoint and loads it warm over the reserving
/// driver, under a Report window [`WINDOW`] long; once the first read of the named slot ended, the next metadata step
/// stages the slot's next read.
fn a_warm_slot_read(arrival: Arrival, admitted: Admitted) {
    use super::super::store_tests::client;
    use super::helpers::PARK;
    use super::warm::sim_tests::{attach_successor, shard_store, storage, tenure_a_with};
    use crate::failover::takeover::tests::{
        Card, a_holds_c_registered, c_host, c_pair, stored_c, takeover_of,
    };

    let predecessor = tenure_a_with(50, |n| [&key(n)[..4], &[n; 40][..]].concat());
    let records = shard_store(predecessor.named, false);
    let mut card = Card::new(c_pair(), &a_holds_c_registered());
    let taken = takeover_of(&records, c_host())
        .run(&mut client(&records), &stored_c(), &mut card)
        .expect("the takeover");
    assert!(taken.warm().is_some(), "the record names the checkpoint");
    let own = taken.fenced().own();
    let bounds = bounds_with(limits(), WINDOW, 0);
    let time = Rc::new(Cell::new(Some(0)));
    let clock = Box::new(Reading(Rc::clone(&time)));
    let (authority, _fencing) = super::ServingAuthority::restarted(bounds, clock, taken);
    let storage = storage(1);
    let buffers = super::gate_fixture::arena_with(4, 9);
    let (mut volume, control, _) =
        attach_successor(&storage, &buffers, &predecessor.media, authority, own);
    PARK.with(|park| park.set(true));
    settle(
        &mut volume,
        &control,
        "the warm load's second read",
        |volume| {
            matches!(volume.metadata.phase, Phase::Warm) && volume.report.metadata_submitted == 1
        },
    );
    rechecks_its_own_reading(
        &mut volume,
        &control,
        &time,
        (Target::Slot, arrival, admitted),
        by_the_step,
    );
    PARK.with(|park| park.set(false));
}

/// A staged read of a warm load's named slot is held back by the same three readings and submitted on one inside the window.
#[test]
fn a_staged_warm_slot_read_is_submitted_only_on_its_own_reading_inside_the_window() {
    for (arrival, admitted) in ARRIVALS {
        a_warm_slot_read(arrival, admitted);
    }
}
