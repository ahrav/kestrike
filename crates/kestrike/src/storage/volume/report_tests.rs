//! The recovery report over simulated attaches: a RESET attach through `Live`, a fill and a hit, and withdrawals between ticks, with the recorder's milestones and readiness transitions.

use super::super::device::sim::media;
use super::super::lookup_tests::lookup;
use super::super::publication_tests::{payload, publish, reserved};
use super::super::publish_tests::key;
use super::super::readiness::{Event, State, Word};
use super::super::volume_fixture::{Device, MEDIA, ample_io, arena_with};
use super::super::{ReadEvent, ReadStatus};
use super::journal_tests::storage_with;
use super::report::{Recorder, RecoveryPhase, RecoveryReport, Transition};

/// The `(from, to)` pairs of `report`'s transitions.
fn transitions(report: &RecoveryReport) -> Vec<(State, State)> {
    (report.transitions.iter().flatten())
        .map(|transition| (transition.from, transition.to))
        .collect()
}

/// A RESET attach over fresh media reports its initialization and a replay over no rows; the first fill at `Live` is its fill readiness; it adopts no helper terminal and restores nothing.
#[test]
fn a_reset_attach_reports_no_retained_phase() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::over(&storage, &buffers, media(MEDIA));
    drop(publish(&storage, &mut dev, &key(1), &[7; 40]).unwrap());
    let mut out = Vec::with_capacity(16);
    let _ = dev.volume.poll_storage(1_000, &mut out);
    let report = dev.volume.recovery_report();
    for phase in [RecoveryPhase::Adoption, RecoveryPhase::RetainedReadiness] {
        assert_eq!(report.phase(phase).start, None, "{phase:?}");
    }
    assert_eq!(report.phase(RecoveryPhase::Replay).rows, 0);
    assert!(report.phase(RecoveryPhase::Initialization).end.is_some());
    assert_eq!(report.phase(RecoveryPhase::FillReadiness).operations, 1);
    assert_eq!(
        *transitions(&report).last().unwrap(),
        (State::Loaded, State::Live)
    );
}

/// `time_in` sums each stay from the transition into it to the next one, the last through `now`.
#[test]
fn time_in_sums_each_stay() {
    let report = recorded(3);
    sums_each_stay(&report);
    // A `now` inside a stay ends that stay there and leaves later stays out.
    let through_4 =
        [State::Loading, State::Loaded, State::Withheld].map(|state| report.time_in(state, 4));
    assert_eq!(through_4, [3, 1, 0]);
}

/// The report of a recorder that enters `Loading` at tick 0, `Loaded` at `loaded`, `Withheld` at 5 and `Closed` at 9.
fn recorded(loaded: u64) -> super::report::RecoveryReport {
    let mut recorder = super::report::Recorder::default();
    for (now, state) in [
        (0, State::Loading),
        (loaded, State::Loaded),
        (5, State::Withheld),
        (9, State::Closed),
    ] {
        recorder.tick_at(now);
        recorder.observe(state, 0);
    }
    recorder.report()
}

fn sums_each_stay(report: &super::report::RecoveryReport) {
    let times = [
        State::Loading,
        State::Loaded,
        State::Withheld,
        State::Closed,
    ]
    .map(|state| report.time_in(state, 12));
    assert_eq!(
        times,
        [3, 2, 4, 3],
        "time_in sums each stay from its transition to the next"
    );
}

/// Moving the `Loaded` transition from tick 3 to tick 4 shifts one tick from `Loaded` to `Loading`.
#[test]
#[should_panic(expected = "time_in sums each stay from its transition to the next")]
fn negative_control_a_transition_one_tick_late_fails_the_stay_sums() {
    sums_each_stay(&recorded(4));
}

/// Milestone eligibility follows the readiness word at event time, even when observations lag its changes. The next observation counts each eligible milestone once. An initial `Live` observation gives `Initialization` zero duration.
#[test]
fn milestones_count_only_events_while_the_word_holds_live() {
    use Step::{Observe, Read, Write};
    let report = replay(&[
        Observe(State::Live),
        Read { live: false },
        Write { live: false },
        Observe(State::Withheld),
    ])
    .report();
    assert_eq!(report.phase(RecoveryPhase::FirstSafeHit).start, None);
    assert_eq!(report.phase(RecoveryPhase::FillReadiness).start, None);
    let initialization = report.phase(RecoveryPhase::Initialization);
    assert_eq!(
        (initialization.start, initialization.end),
        (Some(1), Some(1))
    );
    let report = replay(&[
        Observe(State::Live),
        Read { live: true },
        Read { live: true },
        Write { live: true },
        Observe(State::Withheld),
    ])
    .report();
    let counted = |phase| {
        let phase = report.phase(phase);
        (phase.start, phase.operations)
    };
    assert_eq!(counted(RecoveryPhase::FirstSafeHit), (Some(5), 1));
    assert_eq!(counted(RecoveryPhase::FillReadiness), (Some(5), 1));
}

fn last_transition(report: &RecoveryReport) -> Transition {
    (report.transitions.iter().flatten().last().copied()).expect("a transition")
}

/// A withdrawal between ticks ends `Live` before the next tick completes a read; `FirstSafeHit` stays pending, and the withdrawal carries that tick's time.
#[test]
fn a_withdrawal_between_ticks_precedes_the_reads_the_next_tick_completes() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::over(&storage, &buffers, media(MEDIA));
    drop(publish(&storage, &mut dev, &key(1), &[7; 40]).unwrap());
    let mut reader = storage.register().unwrap();
    let lease = lookup(&mut reader, &key(1), 4).expect("served at Live");
    let op = dev
        .volume
        .read(lease.duplicate(), u64::MAX)
        .expect("admitted");
    assert_eq!(storage.withdraw(), State::Withheld);
    let mut out = Vec::with_capacity(16);
    let mut status = None;
    let mut now = 1_000;
    while status.is_none() && now < 1_064 {
        now += 1;
        dev.control.tick(64);
        let _ = dev.volume.poll_storage(now, &mut out);
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { .. } => {
                    let _ = dev.volume.grant_read(op);
                }
                ReadEvent::Done { status: ended, .. } => status = Some(ended),
            }
        }
    }
    assert_eq!(
        status,
        Some(ReadStatus::Complete),
        "a granted read completes"
    );
    assert_eq!(
        now, 1_001,
        "the first tick after the withdrawal completes the read"
    );
    drop(lease);
    let report = dev.volume.recovery_report();
    assert_eq!(report.phase(RecoveryPhase::FirstSafeHit).start, None);
    let withheld = last_transition(&report);
    assert_eq!(
        (withheld.from, withheld.to, withheld.at),
        (State::Live, State::Withheld, 1_001)
    );
}

/// A write submitted at `Live` between ticks is the first fill even when a withdrawal follows before the next tick: that tick records the fill, then the withdrawal, both at its time.
#[test]
fn a_write_between_ticks_reaches_fill_readiness_before_a_later_withdrawal() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::over(&storage, &buffers, media(MEDIA));
    let body = [9; 40];
    let mut fill = reserved(&storage, &key(2), &body).expect("reserved at Live");
    let taken = fill.receive(&mut dev.volume, &payload(&key(2), &body), &mut ample_io());
    assert_eq!(taken, Ok(44));
    assert_eq!(
        dev.volume
            .recovery_report()
            .phase(RecoveryPhase::FillReadiness)
            .start,
        None
    );
    assert_eq!(storage.withdraw(), State::Withheld);
    let mut out = Vec::with_capacity(16);
    dev.control.tick(64);
    let _ = dev.volume.poll_storage(1_001, &mut out);
    let report = dev.volume.recovery_report();
    let ready = report.phase(RecoveryPhase::FillReadiness);
    assert_eq!((ready.start, ready.operations), (Some(1_001), 1));
    let withheld = last_transition(&report);
    assert_eq!(
        (withheld.from, withheld.to, withheld.at),
        (State::Live, State::Withheld, 1_001)
    );
    drop(fill);
}

/// `FillReadiness` requires a write submitted while the readiness word holds `Live`: a write after a withdrawal leaves the phase pending, and the next tick records the withdrawal.
#[test]
fn a_write_after_a_withdrawal_leaves_fill_readiness_pending() {
    let storage = storage_with(|_| {});
    let buffers = arena_with(4, 5);
    let mut dev = Device::over(&storage, &buffers, media(MEDIA));
    let body = [9; 40];
    let mut fill = reserved(&storage, &key(2), &body).expect("reserved at Live");
    assert_eq!(storage.withdraw(), State::Withheld);
    let before = dev.volume.report().writes_submitted;
    let taken = fill.receive(&mut dev.volume, &payload(&key(2), &body), &mut ample_io());
    assert_eq!(taken, Ok(44), "the reservation keeps its rights");
    assert!(
        dev.volume.report().writes_submitted > before,
        "the receive submitted a write"
    );
    let mut out = Vec::with_capacity(16);
    dev.control.tick(64);
    let _ = dev.volume.poll_storage(1_001, &mut out);
    let report = dev.volume.recovery_report();
    assert_eq!(report.phase(RecoveryPhase::FillReadiness).start, None);
    let withheld = last_transition(&report);
    assert_eq!(
        (withheld.from, withheld.to, withheld.at),
        (State::Live, State::Withheld, 1_001)
    );
    drop(fill);
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Observe(State),
    Read { live: bool },
    Write { live: bool },
}

/// A readiness word holding `state`, reached along the table's path from `Detached` through `Live` to `Closed`.
fn word_in(state: State) -> Word {
    let path = [
        Event::Attach,
        Event::LoadComplete,
        Event::BeginReplay {
            matches: true,
            rows: 3,
        },
        Event::CompleteReplay,
        Event::Withdraw,
        Event::Close,
    ];
    let word = Word::default();
    for event in path {
        if word.state() == state {
            return word;
        }
        word.apply(event).expect("each event moves the word");
    }
    assert_eq!(word.state(), state, "the readiness table reaches {state:?}");
    word
}

fn replay(history: &[Step]) -> Recorder {
    let words = [word_in(State::Withheld), word_in(State::Live)];
    let mut recorder = Recorder::default();
    for (now, &step) in (1..).zip(history) {
        recorder.tick_at(now);
        match step {
            Step::Observe(state) => recorder.observe(state, 1),
            Step::Read { live } => recorder.completed_read(&words[usize::from(live)]),
            Step::Write { live } => recorder.submitted_write(&words[usize::from(live)]),
        }
    }
    recorder
}

#[test]
fn settled_holds_exactly_when_an_observation_changes_nothing() {
    use Step::{Observe, Read, Write};
    let histories: [&[Step]; 9] = [
        &[],
        &[Observe(State::Loading)],
        &[Observe(State::Loading), Observe(State::Loaded)],
        &[Observe(State::Loaded), Observe(State::Live)],
        &[Observe(State::Live), Read { live: true }],
        &[
            Observe(State::Live),
            Read { live: true },
            Write { live: true },
        ],
        &[
            Observe(State::Live),
            Read { live: true },
            Observe(State::Live),
            Write { live: true },
        ],
        &[Observe(State::Live), Write { live: false }],
        &[
            Observe(State::Live),
            Observe(State::Withheld),
            Read { live: false },
        ],
    ];
    let mut outcomes = [0; 2];
    for history in histories {
        let mut recorder = replay(history);
        recorder.tick_at(100);
        let last = history.iter().rev().find_map(|step| match step {
            Observe(state) => Some(*state),
            _ => None,
        });
        for state in State::ALL_STATES {
            let word = word_in(state);
            assert_eq!(recorder.current(&word), last == Some(state));
            let settled = recorder.settled(&word);
            let mut observed = recorder;
            observed.observe(state, 1);
            assert_eq!(settled, observed == recorder, "{history:?} then {state:?}");
            outcomes[usize::from(settled)] += 1;
        }
    }
    assert!(outcomes.iter().all(|&count| count > 0), "{outcomes:?}");
}

#[test]
fn the_word_holds_the_state_it_decodes_in_every_reached_state() {
    for state in State::ALL_STATES {
        let word = word_in(state);
        for probe in State::ALL_STATES {
            assert_eq!(word.holds(probe), probe == state, "{probe:?} in {state:?}");
        }
    }
}
