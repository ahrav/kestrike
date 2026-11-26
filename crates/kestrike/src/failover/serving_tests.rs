//! Serving-table tests.

use super::*;
use crate::failover::evidence_tests::{bounds, pair};
use crate::storage::{Fenced, Session};

fn own(lineage: u32, submitted_at: u64, certified_at: u64) -> Event {
    Event::OwnHolder(OwnReport {
        pair: pair(2, 4, 2),
        lineage,
        submitted_at,
        certified_at,
    })
}

/// The gate value for the rows' own pair.
fn fenced() -> Fenced {
    Fenced::assumed_for(pair(2, 4, 2))
}

fn rows(session: &Session) -> (Token, [Machine; 6]) {
    let pre = Machine::new(bounds(), session);
    let bounded = Machine::issued(bounds(), session, pair(2, 4, 2));
    let token = bounded.token().unwrap();
    let mut recovering = bounded.clone();
    recovering.cross_boundary(&fenced());
    let mut serving = recovering.clone();
    serving.step(Event::Readiness(Readiness::ReadReady { token }));
    let mut withdrawn = serving.clone();
    withdrawn.step(Event::Withdraw(Cause::Planned));
    let mut closed = serving.clone();
    closed.step(Event::Close);
    (
        token,
        [pre, bounded, recovering, serving, withdrawn, closed],
    )
}

fn events(token: Token) -> [Event; 14] {
    [
        own(1, 1, 1),
        Event::Withdraw(Cause::Planned),
        Event::Withdraw(Cause::Flipped),
        Event::Withdraw(Cause::Status(Deposing::Conflict)),
        Event::Expire { now: 50 },
        Event::Readiness(Readiness::ReadReady { token }),
        Event::Readiness(Readiness::AllocationReady { token }),
        Event::Close,
        Event::Withheld,
        Event::Metadata {
            token,
            now: 1,
            kind: MetadataKind::CheckpointRoot,
        },
        Event::Terminal { lineage: 1 },
        Event::Refresh { at: 1 },
        Event::ReadFailed { sent_at: 2 },
        Event::Peer { read_at: Some(3) },
    ]
}

/// The declared cell of each event in `row`: `m` moved, `s` stayed, `x` rejected, `a` admitted, with the state after the event.
fn declared_events(row: usize) -> [(char, State); 11] {
    use State::{Closed as C, PreBoundary as P, Recovering as R, Serving as S, Withdrawn as W};
    match row {
        0 | 1 => [
            ('s', P),
            ('m', W),
            ('m', W),
            ('m', W),
            ('s', P),
            ('s', P),
            ('s', P),
            ('m', C),
            ('x', P),
            ('x', P),
            ('s', P),
        ],
        2 => [
            ('m', R),
            ('m', W),
            ('m', W),
            ('m', W),
            ('s', R),
            ('m', S),
            ('s', R),
            ('m', C),
            ('m', C),
            ('a', R),
            ('s', R),
        ],
        3 => [
            ('m', S),
            ('m', W),
            ('m', W),
            ('m', W),
            ('s', S),
            ('s', S),
            ('m', S),
            ('m', C),
            ('x', S),
            ('a', S),
            ('s', S),
        ],
        4 => [
            ('s', W),
            ('s', W),
            ('s', W),
            ('s', W),
            ('s', W),
            ('s', W),
            ('s', W),
            ('m', C),
            ('s', W),
            ('x', W),
            ('s', W),
        ],
        _ => {
            let mut cells = [('s', C); 11];
            cells[9] = ('x', C);
            cells
        }
    }
}

fn declared(row: usize) -> [(char, State); 14] {
    let events = declared_events(row);
    let state = match row {
        0 | 1 => State::PreBoundary,
        2 => State::Recovering,
        3 => State::Serving,
        4 => State::Withdrawn,
        _ => State::Closed,
    };
    let mut cells = [('s', state); 14];
    cells[..11].copy_from_slice(&events);
    cells
}

fn class(outcome: Outcome) -> char {
    match outcome {
        Outcome::Moved { .. } => 'm',
        Outcome::Stayed(_) => 's',
        Outcome::Rejected(_) => 'x',
        Outcome::Admitted(_) => 'a',
    }
}

#[test]
fn awaits_readiness_holds_exactly_when_the_own_readiness_events_change_the_machine() {
    let session = crate::storage::next_session();
    let (token, machines) = rows(&session);
    let mut filled = machines[3].clone();
    filled.step(Event::Readiness(Readiness::AllocationReady { token }));
    for (row, machine) in machines.iter().chain([&filled]).enumerate() {
        let mut stepped = machine.clone();
        stepped.step(Event::Readiness(Readiness::ReadReady { token }));
        stepped.step(Event::Readiness(Readiness::AllocationReady { token }));
        assert_eq!(
            machine.awaits_readiness(),
            stepped != *machine,
            "row {row} in {:?}",
            machine.state()
        );
    }
    assert!(machines[2].awaits_readiness() && machines[3].awaits_readiness());
    assert!(!filled.awaits_readiness());
}

#[test]
fn every_state_and_event_pair_matches_the_declared_table() {
    let session = crate::storage::next_session();
    let (token, machines) = rows(&session);
    for (row, machine) in machines.iter().enumerate() {
        for (column, event) in events(token).into_iter().enumerate() {
            let mut machine = machine.clone();
            let outcome = machine.step(event);
            assert_eq!(
                (class(outcome), machine.state()),
                declared(row)[column],
                "row {row}, column {column}: {outcome:?}"
            );
        }
    }
}

#[test]
fn checkpoint_units_admitted_only_in_serving() {
    let session = crate::storage::next_session();
    let (token, machines) = rows(&session);
    for (row, machine) in machines.iter().enumerate() {
        let serving = machine.state() == State::Serving;
        let recovering = machine.state() == State::Recovering;
        for kind in [
            MetadataKind::CheckpointUnit,
            MetadataKind::CheckpointRoot,
            MetadataKind::ResetRoot,
        ] {
            let outcome = machine.clone().step(Event::Metadata {
                token,
                now: 1,
                kind,
            });
            let refused = matches!(
                outcome,
                Outcome::Rejected(Rejection::MetadataRefused { .. })
            );
            let admits = serving || (recovering && kind != MetadataKind::CheckpointUnit);
            assert_eq!(!refused, admits, "row {row}, {kind:?}: {outcome:?}");
        }
    }
}

#[test]
fn nothing_admitted_before_boundary() {
    let session = crate::storage::next_session();
    let (token, machines) = rows(&session);
    let operations = [
        Operation::Get,
        Operation::Read,
        Operation::Fill,
        Operation::Reply { lineage: 1 },
    ];
    for (row, machine) in machines[..2].iter().enumerate() {
        for operation in operations {
            assert_eq!(
                machine.admit_at(operation, token, 1),
                Err(Denial::NotServing(machine.state())),
                "row {row}"
            );
        }
        for event in events(token) {
            let mut stepped = machine.clone();
            stepped.step(event);
            assert_ne!(stepped.state(), State::Recovering, "row {row}: {event:?}");
        }
    }
    for (row, machine) in machines.iter().enumerate() {
        let mut crossed = machine.clone();
        let outcome = crossed.cross_boundary(&fenced());
        if row == 0 {
            assert_eq!(
                outcome,
                Outcome::Moved {
                    to: State::Recovering,
                    effect: Effect::Issue(token)
                },
                "the crossing issues the token for the gate value's pair"
            );
            assert_eq!(
                crossed.clone().step(Event::Metadata {
                    token,
                    now: 1,
                    kind: MetadataKind::CheckpointRoot,
                }),
                Outcome::Rejected(Rejection::AuthorityDenied(Denial::WindowExpired)),
                "the issued token admits nothing before an own-holder Report opens its window"
            );
            crossed.step(own(1, 1, 1));
            assert!(matches!(
                crossed.step(Event::Metadata {
                    token,
                    now: 1,
                    kind: MetadataKind::CheckpointRoot,
                }),
                Outcome::Admitted(_)
            ));
        } else if row == 1 {
            assert_eq!(
                outcome,
                Outcome::Moved {
                    to: State::Recovering,
                    effect: Effect::None
                }
            );
        } else {
            assert!(matches!(outcome, Outcome::Rejected(_)), "row {row}");
            assert_eq!(&crossed, machine, "row {row}");
        }
    }

    use crate::storage::gate_fixture::{arena, attach_reserving};
    let arena = arena();
    let storage = crate::storage::owner_fixture::storage(8);
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().budget = Some(2);
    crate::storage::gate_fixture::ticks(&mut volume, &control, 64);
    assert_eq!(volume.authority_state(), State::PreBoundary);
    assert_eq!(
        crate::storage::gate_fixture::read_record(&mut volume),
        Err(crate::storage::ReadRefusal::Closed),
        "a GET's device read"
    );
    assert_eq!(
        crate::storage::owner_fixture::reserve(&storage, &[5; 32], 0, 20).err(),
        Some(crate::storage::FillReserveError::Bootstrapping),
        "a fill reservation"
    );
    assert!(volume.format().is_err(), "a metadata staging attempt");
    crate::storage::gate_fixture::ticks(&mut volume, &control, 64);
    assert_eq!(volume.authority_state(), State::PreBoundary);
    assert!(
        registry.borrow().log.len() >= 3,
        "the gate's Register, Acquire and Report went out"
    );
    assert_eq!(
        crate::storage::gate_fixture::medium(&control),
        0,
        "NoWriteBeforeFB"
    );
    let token = volume.serving_token();
    assert!(token.is_some());
    for operation in operations {
        assert_eq!(
            volume.admit_authority(operation, token),
            Err(Denial::NotServing(State::PreBoundary))
        );
    }
    assert!(!volume.metadata_staging_admitted());
    for kind in [
        MetadataKind::CheckpointUnit,
        MetadataKind::CheckpointRoot,
        MetadataKind::ResetRoot,
    ] {
        assert!(!volume.metadata_authorized(kind));
    }
}

#[test]
fn token_from_own_activated_session_only() {
    let session = crate::storage::next_session();
    let (token, machines) = rows(&session);
    assert_eq!(
        (token.shard, token.generation, token.epoch, token.lineage),
        (session.shard(), session.generation(), session.epoch(), 1)
    );
    assert_eq!(
        machines[2].tenure(),
        (session.generation(), session.epoch())
    );
    let mut pre = machines[0].clone();
    for event in events(token) {
        pre.step(event);
        assert_eq!(pre.token(), None, "{event:?}");
    }
    let other = crate::storage::next_session();
    let (foreign, _) = rows(&other);
    assert_ne!(
        (foreign.generation, foreign.epoch),
        (token.generation, token.epoch)
    );
    for operation in [Operation::Get, Operation::Read, Operation::Fill] {
        assert_eq!(
            machines[3].admit_at(operation, foreign, 1),
            Err(Denial::TokenMismatch)
        );
    }
    let mut serving = machines[3].clone();
    assert_eq!(
        serving.step(Event::Readiness(Readiness::ReadReady { token: foreign })),
        Outcome::Stayed(Reason::LineageMismatch)
    );
    for state in machines.map(|machine| machine.state()) {
        match state {
            State::PreBoundary
            | State::Recovering
            | State::Serving
            | State::Withdrawn
            | State::Closed => {}
        }
    }
}

#[test]
fn stale_token_sends_and_writes_nothing() {
    let older = crate::storage::next_session();
    let (stale, older_machines) = rows(&older);
    let mut previous = older_machines[3].clone();
    previous.step(Event::Readiness(Readiness::AllocationReady {
        token: stale,
    }));
    let operations = [
        Operation::Get,
        Operation::Read,
        Operation::Reply { lineage: 1 },
        Operation::Fill,
    ];
    for operation in operations {
        assert_eq!(
            previous.admit_at(operation, stale, 1),
            Ok(stale),
            "admitted under the older token"
        );
    }
    assert_eq!(
        previous.clone().step(Event::Metadata {
            token: stale,
            now: 1,
            kind: MetadataKind::CheckpointRoot
        }),
        Outcome::Admitted(stale)
    );
    let session = crate::storage::next_session();
    let (_, machines) = rows(&session);
    let mut serving = machines[3].clone();
    serving.step(Event::Readiness(Readiness::AllocationReady {
        token: serving.token().unwrap(),
    }));
    assert_ne!(serving.token(), Some(stale));
    for operation in operations {
        assert_eq!(
            serving.admit_at(operation, stale, 1),
            Err(Denial::TokenMismatch),
            "{operation:?} admitted under the older token sends and writes nothing"
        );
    }
    assert_eq!(
        serving.clone().step(Event::Metadata {
            token: stale,
            now: 1,
            kind: MetadataKind::CheckpointRoot
        }),
        Outcome::Rejected(Rejection::AuthorityDenied(Denial::TokenMismatch))
    );
    assert_eq!(
        serving.clone().step(Event::Terminal { lineage: 0 }),
        Outcome::Stayed(Reason::StaleTokenCustodyOnly)
    );
    let current = serving.token().unwrap();
    assert_eq!(
        serving.admit_at(Operation::Reply { lineage: 0 }, current, 1),
        Err(Denial::StaleLineage {
            lineage: 0,
            current: 1
        })
    );
    assert_eq!(serving.admit_at(Operation::Fill, current, 1), Ok(current));
}

/// The causes that observe a later tenure, written out so the table tests judge `Cause::shows_successor` against a
/// list of their own.
fn successor(cause: Cause) -> bool {
    matches!(
        cause,
        Cause::Flipped | Cause::NewerFence { .. } | Cause::LaterTenure
    )
}

/// The causes that request the flip when they withdraw, written out as [`successor`] is.
fn retires(cause: Cause) -> bool {
    matches!(
        cause,
        Cause::Report(_)
            | Cause::ForceDetach
            | Cause::Attachment
            | Cause::Modification
            | Cause::RestartCheck
            | Cause::Exhausted
    )
}

/// SupersededRequestsNoFlip: a successor observation ends the machine's flip requests because the successor tenure
/// owns the shard.
#[test]
fn a_successor_observation_at_any_step_ends_flip_requests() {
    let causes = [
        Cause::RecordedHolder,
        Cause::Unheld,
        Cause::Report(ReportTrigger::new(NotSole::ForeignHolder).unwrap()),
        Cause::Status(Deposing::Conflict),
        Cause::Status(Deposing::PreemptAborted),
        Cause::ForceDetach,
        Cause::Attachment,
        Cause::Modification,
        Cause::RestartCheck,
        Cause::ActivationRecord,
        Cause::Exhausted,
        Cause::Planned,
        Cause::Flipped,
        Cause::NewerFence { page: 1, fence: 9 },
        Cause::LaterTenure,
        Cause::Regression,
    ];
    let session = crate::storage::next_session();
    let target = session.target();
    let (_, machines) = rows(&session);
    let mut suppressed = 0;
    for (row, start) in machines[..4].iter().enumerate() {
        for first in causes {
            for second in causes {
                for third in causes {
                    let mut machine = start.clone();
                    let (mut superseded, mut requested) = (false, None);
                    // TransferRetainsVolume: a machine a planned exit withdrew requests no flip afterwards.
                    let planned = first == Cause::Planned;
                    for cause in [first, second, third] {
                        superseded |= successor(cause);
                        let open = requested.is_none() && retires(cause) && !planned;
                        let requests = open && !superseded;
                        suppressed += u32::from(open && superseded);
                        if requests {
                            requested = Some(cause);
                        }
                        let effect = match machine.step(Event::Withdraw(cause)) {
                            Outcome::Moved { effect, .. } => effect,
                            _ => Effect::None,
                        };
                        let sequence = (first, second, third);
                        assert_eq!(
                            effect == Effect::RequestFlip(target),
                            requests,
                            "row {row}: {cause:?} in {sequence:?}"
                        );
                        assert_eq!(machine.superseded(), superseded, "row {row}: {sequence:?}");
                        assert_eq!(
                            machine.flip_request(),
                            requested.map(|_| target),
                            "row {row}: after {cause:?} in {sequence:?}"
                        );
                        assert_eq!(machine.cause(), requested.or(Some(first)));
                    }
                }
            }
        }
    }
    assert!(
        suppressed > 0,
        "some trigger followed a successor observation"
    );
    let closed = &machines[5];
    let mut after = closed.clone();
    let cause = after.cause();
    assert_eq!(
        after.step(Event::Withdraw(Cause::Flipped)),
        Outcome::Stayed(Reason::Closed)
    );
    assert_eq!(after.cause(), cause, "a closed machine takes no cause");
    assert!(
        after.superseded(),
        "and still latches the successor observation"
    );
    assert!(!after.flip_open(), "a closed machine requests no flip");
}

/// TransferRetainsVolume: a planned exit withdraws every state before the withdrawal with no flip request, and no
/// retirement trigger after it requests one, since the shard's next tenure takes over the same volume.
#[test]
fn a_planned_withdrawal_requests_no_flip_whatever_trigger_follows() {
    let triggers = crate::failover::superseded_flip_tests::triggers();
    assert!(triggers.iter().all(|trigger| retires(*trigger)));
    let session = crate::storage::next_session();
    let (_, machines) = rows(&session);
    for (row, start) in machines[..4].iter().enumerate() {
        let mut machine = start.clone();
        assert_eq!(
            machine.step(Event::Withdraw(Cause::Planned)),
            Outcome::Moved {
                to: State::Withdrawn,
                effect: Effect::None,
            },
            "row {row}"
        );
        assert!(
            !machine.flip_open(),
            "row {row}: the planned exit closes the flip"
        );
        for trigger in triggers {
            assert_eq!(
                machine.step(Event::Withdraw(trigger)),
                Outcome::Stayed(Reason::Withdrawn),
                "row {row}: {trigger:?}"
            );
            assert_eq!(
                (machine.cause(), machine.flip_request()),
                (Some(Cause::Planned), None),
                "row {row}: {trigger:?}"
            );
        }
    }
}

#[test]
fn withdraw_on_each_trigger() {
    let causes = [
        Cause::RecordedHolder,
        Cause::Unheld,
        Cause::Report(ReportTrigger::new(NotSole::ReservationType).unwrap()),
        Cause::Report(ReportTrigger::new(NotSole::ForeignHolder).unwrap()),
        Cause::Report(ReportTrigger::new(NotSole::ForeignRegistrant).unwrap()),
        Cause::Report(ReportTrigger::new(NotSole::DuplicateOwnRecord).unwrap()),
        Cause::Status(Deposing::Conflict),
        Cause::Status(Deposing::PreemptAborted),
        Cause::ForceDetach,
        Cause::Attachment,
        Cause::Modification,
        Cause::RestartCheck,
        Cause::ActivationRecord,
        Cause::Exhausted,
        Cause::Planned,
        Cause::Flipped,
        Cause::NewerFence { page: 1, fence: 9 },
        Cause::LaterTenure,
        Cause::Regression,
    ];
    let session = crate::storage::next_session();
    let target = session.target();
    assert_eq!(
        (target.generation, target.owner, target.attempts),
        (
            session.generation(),
            crate::storage::store_tests::record().owner,
            session.epoch().get() / 2
        )
    );
    let (token, machines) = rows(&session);
    let mut escalations = 0;
    // STATUS-IS-DEPOSITION: a deposing command status, a recorded holder's Report and a Report with nobody holding
    // beside recorded registrants withdraw alone; the next Report or owner poll decides between the hold and the
    // retirement, so a reservation change by a recorded attachment never retires the volume through a command
    // completion.
    for cause in causes {
        let triggers = retires(cause);
        for (row, machine) in machines[..4].iter().enumerate() {
            let mut machine = machine.clone();
            assert_eq!(
                machine.step(Event::Withdraw(cause)),
                Outcome::Moved {
                    to: State::Withdrawn,
                    effect: if triggers {
                        Effect::RequestFlip(target)
                    } else {
                        Effect::None
                    },
                },
                "row {row}: {cause:?}"
            );
            assert_eq!(machine.cause(), Some(cause));
            assert_eq!(machine.flip_request(), triggers.then_some(target));
            assert_eq!(machine.window_end(), None);
            for operation in [
                Operation::Get,
                Operation::Read,
                Operation::Fill,
                Operation::Reply { lineage: 1 },
            ] {
                assert_eq!(
                    machine.admit_at(operation, token, 1),
                    Err(Denial::NotServing(State::Withdrawn))
                );
            }
            for event in events(token)
                .into_iter()
                .chain([Event::Withdraw(Cause::Attachment)])
            {
                let mut after = machine.clone();
                let outcome = after.step(event);
                // SupersededRequestsNoFlip: a cause that observed a later tenure keeps the withdrawal without a flip
                // request, whatever trigger follows. `TransferRetainsVolume` exempts `Cause::Planned` from escalation
                // on a later retiring withdrawal. For a nonretiring, nonsuperseded cause other than `Cause::Planned`,
                // a later retiring withdrawal triggers one flip request.
                let escalates = !triggers
                    && !successor(cause)
                    && cause != Cause::Planned
                    && matches!(event, Event::Withdraw(later) if retires(later));
                escalations += u32::from(escalates);
                if escalates {
                    assert_eq!(
                        outcome,
                        Outcome::Moved {
                            to: State::Withdrawn,
                            effect: Effect::RequestFlip(target),
                        },
                        "row {row}: a retirement trigger after {cause:?} requests the flip"
                    );
                    assert_eq!(after.flip_request(), Some(target));
                    assert_eq!(
                        after.step(Event::Withdraw(Cause::Attachment)),
                        Outcome::Stayed(Reason::Withdrawn),
                        "the flip request goes out once"
                    );
                } else {
                    assert!(
                        !matches!(outcome, Outcome::Moved { effect, .. } if effect != Effect::None),
                        "row {row}: {event:?} after {cause:?} gave {outcome:?}"
                    );
                }
                if successor(cause) {
                    assert_eq!(
                        (after.flip_request(), after.cause()),
                        (None, Some(cause)),
                        "row {row}: {event:?} after {cause:?} names the stale target"
                    );
                }
                assert!(matches!(after.state(), State::Withdrawn | State::Closed));
                assert!(
                    after.admit_at(Operation::Read, token, 1).is_err(),
                    "row {row}: {event:?} after {cause:?} admits nothing"
                );
            }
            if machine.token().is_some() {
                assert_eq!(
                    machine.clone().step(Event::Terminal { lineage: 1 }),
                    Outcome::Stayed(Reason::TerminalApplied),
                    "custody stays with the withdrawn tenure"
                );
            }
        }
    }
    assert_eq!(
        escalations,
        6 * 4,
        "premise: the trigger after each quiet withdrawal but a planned one escalated in every row"
    );

    use crate::storage::gate_fixture::{arena, attach_reserving, own as own_pair};
    struct Clock(std::rc::Rc<std::cell::Cell<u64>>);
    impl crate::storage::ServingClock for Clock {
        fn now_us(&self) -> Option<u64> {
            Some(self.0.get())
        }
    }
    for withdraw in [true, false] {
        let arena = arena();
        let storage = crate::storage::gate_fixture::storage();
        let (mut volume, control, registry) = attach_reserving(
            &storage,
            &arena,
            crate::storage::ServingAuthority::fixture(),
        );
        let time = std::rc::Rc::new(std::cell::Cell::new(0));
        volume.set_serving_clock(Box::new(Clock(std::rc::Rc::clone(&time))));
        let mut out = Vec::with_capacity(16);
        crate::storage::gate_fixture::ticks(&mut volume, &control, 64);
        assert_ne!(
            volume.authority_state(),
            State::PreBoundary,
            "the gate passed"
        );
        assert_eq!(volume.format(), Ok(()), "the RESET roots are scheduled");
        let commands = registry.borrow().log.len();
        let services = registry.borrow().services;
        let submitted = control.capture().events.len();
        if withdraw {
            let tenure = volume.authority_report().tenure;
            let outcome = volume.authority_event(Event::Withdraw(Cause::Planned));
            let report = volume.authority_report();
            assert_eq!(
                (outcome, report.withdrawal, report.flip, report.tenure),
                (
                    Outcome::Moved {
                        to: State::Withdrawn,
                        effect: Effect::None,
                    },
                    Some(Cause::Planned),
                    None,
                    tenure
                )
            );
        }
        for _ in 0..64 {
            volume.service_disk();
            time.set(time.get() + 50);
            control.tick(64);
            let _ = volume.poll_storage(0, &mut out);
            out.clear();
        }
        if withdraw {
            assert_eq!(
                registry.borrow().log.len(),
                commands,
                "no later reservation command, a Release included"
            );
            assert_eq!(
                control.capture().events.len(),
                submitted,
                "no later medium command"
            );
            assert_eq!(
                registry.borrow().services,
                services,
                "no later driver housekeeping"
            );
            assert!(
                registry
                    .borrow()
                    .entries
                    .iter()
                    .any(|entry| entry.pair == own_pair()),
                "the registration stays"
            );
        } else {
            assert!(
                registry.borrow().log.len() > commands,
                "without the withdrawal the same loop submits periodic Reports"
            );
            assert!(
                control.capture().events.len() > submitted,
                "without the withdrawal the same loop writes the RESET roots"
            );
            assert!(
                registry.borrow().services > services,
                "without the withdrawal the same loop services the driver"
            );
        }
    }
}

#[test]
fn report_timeout_admits_nothing() {
    let session = crate::storage::next_session();
    let (token, machines) = rows(&session);
    let mut serving = machines[3].clone();
    assert_eq!(serving.admit_at(Operation::Read, token, 99), Ok(token));
    assert_eq!(
        serving.admit_at(Operation::Read, token, 100),
        Err(Denial::WindowExpired),
        "the window [0, 100) admits nothing at its end"
    );
    assert_eq!(
        serving.step(Event::Expire { now: 40 }),
        Outcome::Stayed(Reason::WindowClosed)
    );
    assert_eq!(serving.state(), State::Serving);
    for operation in [
        Operation::Get,
        Operation::Read,
        Operation::Fill,
        Operation::Reply { lineage: 1 },
    ] {
        assert!(serving.admit_at(operation, token, 41).is_err());
    }
    assert_eq!(
        serving.clone().step(Event::Terminal { lineage: 1 }),
        Outcome::Stayed(Reason::TerminalApplied)
    );
    assert_eq!(
        serving.step(own(1, 40, 42)),
        Outcome::Stayed(Reason::BeforeExpiry)
    );
    assert!(serving.admit_at(Operation::Read, token, 43).is_err());
    assert_eq!(
        serving.step(own(1, 41, 45)),
        Outcome::Moved {
            to: State::Serving,
            effect: Effect::Renew { until: 141 }
        }
    );
    assert_eq!(serving.admit_at(Operation::Read, token, 46), Ok(token));
    assert_eq!(
        serving.step(own(1, 50, 61)),
        Outcome::Stayed(Reason::ReportLate)
    );
    assert_eq!(
        serving.retry_at(Operation::Read, RESERVATION_CONFLICT, token, 46),
        Err(Denial::DeposingStatusNeverRetried(RESERVATION_CONFLICT))
    );
}

const S: u64 = 1_000_000;

#[test]
fn each_retained_guard_refuses_beside_its_accepted_twin() {
    let session = crate::storage::next_session();
    let (token, machines) = rows(&session);
    let serving = machines[3].clone();
    assert_eq!(
        serving.admit_at(Operation::Fill, token, 1),
        Err(Denial::FillsNotAdmitted)
    );
    let mut fills = serving.clone();
    fills.step(Event::Readiness(Readiness::AllocationReady { token }));
    assert_eq!(fills.admit_at(Operation::Fill, token, 1), Ok(token));

    let other = pair(3, 5, 3);
    assert!(other.exhid != token.exhid && other.key != token.key);
    assert_eq!(
        serving.clone().step(Event::OwnHolder(OwnReport {
            pair: other,
            lineage: 1,
            submitted_at: 1,
            certified_at: 1,
        })),
        Outcome::Stayed(Reason::PairMismatch)
    );
    assert!(matches!(
        serving.clone().step(own(1, 1, 1)),
        Outcome::Moved {
            effect: Effect::Renew { .. },
            ..
        }
    ));
    assert_eq!(
        serving.clone().step(own(1, 10, 9)),
        Outcome::Stayed(Reason::ReportLate),
        "certified before its submission"
    );
    assert!(matches!(
        serving.clone().step(own(1, 10, 10)),
        Outcome::Moved { .. }
    ));

    let mut renewed = serving.clone();
    renewed.step(own(1, 20, 20));
    assert_eq!(
        renewed.admit_at(Operation::Read, token, 19),
        Err(Denial::WindowNotStarted)
    );
    assert_eq!(renewed.admit_at(Operation::Read, token, 20), Ok(token));

    let foreign = rows(&crate::storage::next_session()).0;
    let varied = [
        Token {
            shard: crate::net::ownership::Shard::new(token.shard.get() + 1).unwrap(),
            ..token
        },
        Token {
            generation: crate::net::ownership::ShardGeneration::new(token.generation.get() + 1)
                .unwrap(),
            ..token
        },
        Token {
            epoch: foreign.epoch,
            ..token
        },
        Token {
            exhid: other.exhid,
            ..token
        },
        Token {
            key: other.key,
            ..token
        },
        Token {
            lineage: 2,
            ..token
        },
    ];
    for (field, varied) in varied.into_iter().enumerate() {
        assert_ne!(varied, token, "field {field}");
        assert_eq!(
            fills.admit_at(Operation::Read, varied, 1),
            Err(Denial::TokenMismatch),
            "field {field}"
        );
        assert_eq!(
            fills.clone().step(Event::Metadata {
                token: varied,
                now: 1,
                kind: MetadataKind::CheckpointRoot,
            }),
            Outcome::Rejected(Rejection::AuthorityDenied(Denial::TokenMismatch)),
            "field {field}"
        );
    }
    assert_eq!(fills.admit_at(Operation::Read, token, 1), Ok(token));
}

fn serving_unbounded() -> (Token, Machine) {
    let session = crate::storage::next_session();
    let bounds = Bounds::new(4, 2, u64::MAX, 10, 20, 5).unwrap();
    let mut machine = Machine::issued(bounds, &session, pair(2, 4, 2));
    let token = machine.token().unwrap();
    machine.cross_boundary(&fenced());
    machine.step(Event::Readiness(Readiness::ReadReady { token }));
    machine.step(Event::Readiness(Readiness::AllocationReady { token }));
    (token, machine)
}

fn deposition_run(late: bool) {
    for cause in [
        Cause::Flipped,
        Cause::NewerFence { page: 0, fence: 9 },
        Cause::LaterTenure,
        Cause::Regression,
    ] {
        let (token, mut machine) = serving_unbounded();
        let mut buffered = vec![Operation::Reply { lineage: 1 }];
        let mut pending = None;
        let mut sent = Vec::new();
        for (step, observed) in [Some(cause), None, None].into_iter().enumerate() {
            let now = step as u64 + 1;
            let applied = if late {
                std::mem::replace(&mut pending, observed)
            } else {
                observed
            };
            if let Some(cause) = applied {
                machine.step(Event::Withdraw(cause));
            }
            buffered.retain(|operation| {
                let admitted = machine.admit_at(*operation, token, now).is_ok();
                if admitted {
                    sent.push(step);
                }
                !admitted
            });
        }
        assert!(
            sent.is_empty(),
            "PR-TEN-4: the hit buffered before {cause:?} was sent at steps {sent:?}"
        );
        assert_eq!(buffered.len(), 1, "admission refused the buffered hit");
        assert_eq!(machine.state(), State::Withdrawn);
        assert_eq!(machine.flip_request(), None);
        for operation in [
            Operation::Get,
            Operation::Read,
            Operation::Fill,
            Operation::Reply { lineage: 1 },
        ] {
            assert!(machine.admit_at(operation, token, 9).is_err());
        }
    }
}

#[test]
fn deposition_drops_buffered_replies() {
    deposition_run(false);
}

#[test]
#[should_panic(expected = "PR-TEN-4")]
fn negative_control_a_deposition_applied_one_step_late_sends_the_buffered_hit() {
    deposition_run(true);
}

#[test]
fn store_timeout_moves_no_state() {
    let (token, mut machine) = serving_unbounded();
    machine.step(Event::Refresh { at: S });
    let before = machine.clone();
    let fields = |machine: &Machine| {
        (
            machine.state(),
            machine.token(),
            machine.window_start(),
            machine.window_end(),
            machine.expired_at(),
            machine.cause(),
        )
    };
    assert_eq!(
        machine.step(Event::ReadFailed { sent_at: 2 * S }),
        Outcome::Stayed(Reason::Availability)
    );
    assert_eq!(fields(&machine), fields(&before));
    assert_eq!(machine.withhold().failed_at(), Some(2 * S));
    machine.step(Event::ReadFailed { sent_at: 3 * S });
    assert_eq!(
        machine.withhold().failed_at(),
        Some(2 * S),
        "a later failure keeps the mark"
    );
    assert_eq!(fields(&machine), fields(&before));
    assert_eq!(machine.admit_at(Operation::Get, token, 4 * S), Ok(token));
    let mut refreshed = before.clone();
    refreshed.step(Event::Refresh { at: 5 * S });
    refreshed.step(Event::ReadFailed { sent_at: 4 * S });
    assert_eq!(
        refreshed.withhold().failed_at(),
        None,
        "a failure sent before the last refresh sets nothing"
    );
    let mut reordered = machine.clone();
    reordered.step(Event::Refresh { at: S + 1 });
    assert_eq!(
        reordered.withhold().failed_at(),
        Some(2 * S),
        "a success sent before the marked failure and returned after it keeps the mark"
    );
    reordered.step(Event::Refresh { at: 2 * S });
    assert_eq!(
        reordered.withhold().failed_at(),
        Some(3 * S),
        "a success sent at the marked failure's send time moves the mark to the later failure"
    );
    reordered.step(Event::Refresh { at: 3 * S });
    assert_eq!(
        reordered.withhold().failed_at(),
        None,
        "a success sent at or after every failure clears the mark"
    );
    let mut out_of_order = before.clone();
    out_of_order.step(Event::ReadFailed { sent_at: 3 * S });
    out_of_order.step(Event::ReadFailed { sent_at: 2 * S });
    assert_eq!(
        out_of_order.withhold().failed_at(),
        Some(2 * S),
        "an earlier-sent failure observed after a later-sent one sets the mark"
    );
}

#[test]
fn one_sided_partition_withholds() {
    let (token, mut machine) = serving_unbounded();
    machine.step(Event::Refresh { at: 0 });
    let step = S / 10;
    let mut first_miss = None;
    for tick in 1..=80 {
        let now = tick * step;
        if now % S == 2 * step && now > S {
            machine.step(Event::ReadFailed {
                sent_at: now - 2 * step,
            });
        }
        if now % S == 6 * step {
            machine.step(Event::Peer {
                read_at: Some(now - step),
            });
        }
        let hit = machine.admit_at(Operation::Get, token, now);
        match (hit, first_miss) {
            (Err(Denial::Withheld), None) => first_miss = Some(now),
            (Ok(_), Some(at)) => panic!("a hit at {now} after the withhold began at {at}"),
            _ => {}
        }
        if first_miss.is_some() {
            assert_eq!(
                machine.admit_at(Operation::Get, token, now),
                Err(Denial::Withheld)
            );
            assert_eq!(machine.admit_at(Operation::Read, token, now), Ok(token));
            assert_eq!(machine.admit_at(Operation::Fill, token, now), Ok(token));
            assert_eq!(
                machine.admit_at(Operation::Reply { lineage: 1 }, token, now),
                Ok(token)
            );
            assert_eq!((machine.state(), machine.cause()), (State::Serving, None));
        }
    }
    assert_eq!(machine.withhold().failed_at(), Some(S));
    assert_eq!(
        first_miss,
        Some(51 * step),
        "hits continue until the own read is older than W and a peer read follows the mark by more than M"
    );
    machine.step(Event::Refresh { at: 8 * S });
    assert_eq!(machine.withhold().failed_at(), None);
    assert_eq!(machine.admit_at(Operation::Get, token, 8 * S), Ok(token));
}

fn outage(hit: impl Fn(&Machine, Token, u64) -> bool) {
    let (token, mut machine) = serving_unbounded();
    machine.step(Event::Refresh { at: S });
    machine.step(Event::Refresh { at: 3 * S });
    let peers = [4_300_000, 4_700_000, 5_600_000];
    let end = 5 * S + 10 * crate::failover::withhold::W_US;
    let mut now = 5 * S;
    while now <= end {
        if (now / S) % 2 == 1 && now.is_multiple_of(S) {
            machine.step(Event::ReadFailed { sent_at: now });
        }
        machine.step(Event::Peer {
            read_at: peers.iter().copied().filter(|read| *read <= now).max(),
        });
        assert!(
            hit(&machine, token, now),
            "T22: hits continue through a store-wide outage at {now}"
        );
        assert_eq!(
            machine.admit_at(Operation::Fill, token, now),
            Ok(token),
            "FILL acknowledgments continue"
        );
        now += S / 2;
    }
    assert_eq!(machine.withhold().failed_at(), Some(5 * S));
}

#[test]
fn store_wide_outage_never_withholds() {
    outage(|machine, token, now| machine.admit_at(Operation::Get, token, now).is_ok());
}

#[test]
#[should_panic(expected = "T22")]
fn negative_control_comparing_peer_reads_with_the_last_success_withholds() {
    outage(|machine, token, now| {
        let withhold = machine.withhold();
        machine.admit_at(Operation::Get, token, now).is_ok()
            && !crate::failover::withhold::exceeds(
                now,
                withhold.refreshed_at(),
                withhold.refreshed_at(),
                withhold.peer_read_at(),
            )
    });
}

#[test]
fn an_absent_own_clock_withholds_nothing() {
    let (token, mut machine) = serving_unbounded();
    machine.step(Event::ReadFailed { sent_at: S });
    machine.step(Event::Peer {
        read_at: Some(9 * S),
    });
    let now = 10 * S;
    assert_eq!(
        machine.admit_at(Operation::Get, token, now),
        Ok(token),
        "a failure mark and a qualifying peer read withhold nothing without the own clock"
    );
    machine.step(Event::Refresh { at: 0 });
    assert_eq!(
        machine.admit_at(Operation::Get, token, now),
        Err(Denial::Withheld),
        "the same inputs withhold once the own clock reads older than W"
    );
}

#[test]
fn missing_peer_age_is_no_evidence() {
    let (token, mut machine) = serving_unbounded();
    machine.step(Event::Refresh { at: 0 });
    machine.step(Event::ReadFailed { sent_at: S });
    let now = 10 * S;
    assert_eq!(
        machine.admit_at(Operation::Get, token, now),
        Ok(token),
        "no peer input"
    );
    machine.step(Event::Peer { read_at: None });
    assert_eq!(
        machine.admit_at(Operation::Get, token, now),
        Ok(token),
        "a heartbeat without a read age"
    );
    machine.step(Event::Peer {
        read_at: Some(9 * S),
    });
    assert_eq!(
        machine.admit_at(Operation::Get, token, now),
        Err(Denial::Withheld),
        "the same state withholds on peer evidence"
    );
    machine.step(Event::Peer { read_at: None });
    assert_eq!(machine.admit_at(Operation::Get, token, now), Ok(token));
}

fn guest_stop(in_flight: bool) -> Option<u64> {
    let (token, mut machine) = serving_unbounded();
    for read in 0..=3 {
        machine.step(Event::Refresh { at: read * S });
    }
    let stop = 3 * S + 600_000;
    let resume = stop + 10 * S;
    let during = 8 * S;
    if in_flight {
        machine.step(Event::ReadFailed { sent_at: 3_500_000 });
        machine.step(Event::Peer {
            read_at: Some(during),
        });
        assert_eq!(
            machine.admit_at(Operation::Get, token, resume),
            Err(Denial::Withheld),
            "the read in flight across the stop fails at its send time and the peer read during the stop withholds"
        );
        return None;
    }
    machine.step(Event::Peer {
        read_at: Some(during),
    });
    let poll_sent = resume + 100_000;
    let poll_result = resume + 400_000;
    let qualifying = poll_sent + crate::failover::withhold::M_US;
    let mut now = resume;
    while now <= qualifying {
        if now >= poll_result && machine.withhold().failed_at().is_none() {
            machine.step(Event::ReadFailed { sent_at: poll_sent });
        }
        machine.step(Event::Peer {
            read_at: Some(now.max(during)),
        });
        assert_eq!(
            machine.admit_at(Operation::Get, token, now),
            Ok(token),
            "a heartbeat received at {now} reports a peer read no later than {now}"
        );
        now += 50_000;
    }
    machine.step(Event::Peer {
        read_at: Some(qualifying),
    });
    assert_eq!(
        machine.admit_at(Operation::Get, token, qualifying),
        Ok(token)
    );
    machine.step(Event::Peer {
        read_at: Some(qualifying + 1),
    });
    assert_eq!(
        machine.admit_at(Operation::Get, token, qualifying + 1),
        Err(Denial::Withheld),
        "the first peer read more than M after the failed poll's send time withholds"
    );
    Some(qualifying + 1 - resume)
}

#[test]
fn guest_stop_withhold() {
    assert_eq!(guest_stop(true), None);
    let window = guest_stop(false);
    eprintln!(
        "hits served from the resume until a peer read more than M after the failed poll's send time: {window:?} us"
    );
    assert_eq!(window, Some(100_000 + crate::failover::withhold::M_US + 1));
}

/// The reservation conflict status code, written out so the test judges `Machine::retry_at` against a value of its
/// own.
const CONFLICT: u16 = 0x83;
/// The preempt abort status code, written out as [`CONFLICT`] is.
const ABORT: u16 = 0x1b;

/// [`serving_unbounded`] with its own read at time zero, failed reads sent at seconds one to five and a peer read
/// half a second after each, so its availability withhold refuses a GET later than `W_US` after time zero.
fn withholding() -> (Token, Machine) {
    let (token, mut machine) = serving_unbounded();
    machine.step(Event::Refresh { at: 0 });
    for second in 1..6 {
        machine.step(Event::ReadFailed {
            sent_at: second * S,
        });
        machine.step(Event::Peer {
            read_at: Some(second * S + S / 2),
        });
    }
    (token, machine)
}

/// Machines in all five states, each with the token the test submits as its own. Two are before the boundary: one
/// built by [`Machine::new`], whose token the crossing issues, with the token of another session, and one built by
/// [`Machine::issued`] with the token it holds. Six are of one session and take its token: recovering, serving reads
/// only, serving fills, serving in the renewed window `[41, 141)`, withdrawn and closed. The last is the
/// [`withholding`] machine with its token.
fn machines() -> Vec<(Token, Machine)> {
    let (token, [_, _, recovering, reads, _, _]) = rows(&crate::storage::next_session());
    let (issued_token, [unissued, issued, _, _, _, _]) = rows(&crate::storage::next_session());
    let mut fills = reads.clone();
    fills.step(Event::Readiness(Readiness::AllocationReady { token }));
    let mut renewed = fills.clone();
    renewed.step(Event::Expire { now: 40 });
    renewed.step(own(1, 41, 45));
    let mut withdrawn = fills.clone();
    withdrawn.step(Event::Withdraw(Cause::Status(Deposing::PreemptAborted)));
    let mut closed = fills.clone();
    closed.step(Event::Close);
    let mut all = vec![
        (token, unissued),
        (issued_token, issued),
        (token, recovering),
        (token, reads),
        (token, fills),
        (token, renewed),
        (token, withdrawn),
        (token, closed),
    ];
    all.push(withholding());
    all
}

/// Each operation, with a reply of lineage 1, the lineage of every issued token, and a reply of lineage 2.
fn operations() -> [Operation; 5] {
    [
        Operation::Get,
        Operation::Read,
        Operation::Fill,
        Operation::Reply { lineage: 1 },
        Operation::Reply { lineage: 2 },
    ]
}

/// `own`, then tokens that differ from it in lineage and in key.
fn tokens(own: Token) -> [Token; 3] {
    [
        own,
        Token { lineage: 2, ..own },
        Token {
            key: pair(2, 4, 3).key,
            ..own
        },
    ]
}

/// Times inside and outside the windows `[0, 100)` and `[41, 141)` that machines of the sample hold, and one later
/// than `W_US`, where the [`withholding`] machine refuses a GET.
const TIMES: [u64; 8] = [0, 1, 40, 46, 99, 100, 141, 6 * S];

/// `Machine::retry_at` refuses the two deposing statuses, the reservation conflict `0x83` and the preempt abort
/// `0x1b`, with [`Denial::DeposingStatusNeverRetried`] at every sampled machine, operation, token and time,
/// whatever the admission gate answers there, and answers every other `u16` status as [`Machine::admit_at`] answers
/// the same operation, token and time. `Machine::retry_at` rejects deposing statuses before calling
/// [`Machine::admit_at`].
#[test]
fn a_deposing_status_is_refused_and_every_other_status_takes_the_admission_gate() {
    let mut states = std::collections::HashSet::new();
    let mut gate_answers = std::collections::HashSet::new();
    for (own, machine) in machines() {
        states.insert(machine.state());
        for operation in operations() {
            for token in tokens(own) {
                for now in TIMES {
                    let gate = machine.admit_at(operation, token, now);
                    gate_answers.insert(gate.err().map(|denial| std::mem::discriminant(&denial)));
                    for status in 0..=u16::MAX {
                        let answer = machine.retry_at(operation, status, token, now);
                        if status == CONFLICT || status == ABORT {
                            assert_eq!(
                                answer,
                                Err(Denial::DeposingStatusNeverRetried(status)),
                                "status {status:#x} was retried for {operation:?} at {now} in {:?}, where the gate answers {gate:?}",
                                machine.state()
                            );
                        } else {
                            assert_eq!(
                                answer,
                                gate,
                                "status {status:#x} left the admission gate for {operation:?} at {now} in {:?}",
                                machine.state()
                            );
                        }
                    }
                }
            }
        }
    }
    assert_eq!(states.len(), 5, "the sample holds every state");
    assert!(
        gate_answers.contains(&None),
        "the gate admits at no point of the sample"
    );
    // The set holds discriminants, so each payload below only selects its variant.
    for refusal in [
        Denial::NotServing(State::PreBoundary),
        Denial::TokenMismatch,
        Denial::WindowNotStarted,
        Denial::WindowExpired,
        Denial::Withheld,
        Denial::FillsNotAdmitted,
        Denial::StaleLineage {
            lineage: 2,
            current: 1,
        },
    ] {
        assert!(
            gate_answers.contains(&Some(std::mem::discriminant(&refusal))),
            "the gate answers no point of the sample with the refusal variant of {refusal:?}"
        );
    }
}

/// A coverage page fence names a later tenure only as an activated session. From each of the six rows, a fence that
/// is none latches `superseded`, closes the flip and leaves `has_successor` unset, and a later shard record, a store
/// write refused for a later tenure or an activated fence sets `has_successor` before or after it, a closed machine
/// included. A cause that shows no successor sets neither latch.
#[test]
fn a_page_fence_names_a_successor_only_as_an_activated_session() {
    use crate::net::ownership::{ActivatedEpoch, session_of};
    let fenced = |generation, epoch| Cause::NewerFence {
        page: 1,
        fence: session_of(generation, epoch),
    };
    // An odd candidate epoch, an unactivated epoch, the generation `Session::activate` refuses, an epoch past the
    // largest activated one, and generation zero.
    let unnamed = [
        fenced(9, 3),
        fenced(9, 0),
        fenced(u32::MAX, 2),
        fenced(9, ActivatedEpoch::MAX + 2),
        fenced(0, 2),
    ];
    let named = [Cause::Flipped, Cause::LaterTenure, fenced(9, 2)];
    let quiet = [
        Cause::Regression,
        Cause::Status(Deposing::Conflict),
        Cause::RecordedHolder,
        Cause::Unheld,
        Cause::Unverified,
        Cause::ForceDetach,
    ];
    let session = crate::storage::next_session();
    let (_, machines) = rows(&session);
    for (row, start) in machines.iter().enumerate() {
        assert!(!start.has_successor(), "row {row}");
        for fence in unnamed {
            let mut machine = start.clone();
            machine.step(Event::Withdraw(fence));
            assert!(
                machine.superseded() && !machine.flip_open(),
                "row {row}: {fence:?}"
            );
            assert!(!machine.has_successor(), "row {row}: {fence:?}");
            for cause in named {
                let mut later = machine.clone();
                later.step(Event::Withdraw(cause));
                assert!(later.has_successor(), "row {row}: {fence:?} then {cause:?}");
            }
        }
        for cause in named {
            let mut machine = start.clone();
            machine.step(Event::Withdraw(cause));
            assert!(
                machine.superseded() && machine.has_successor(),
                "row {row}: {cause:?}"
            );
            machine.step(Event::Withdraw(unnamed[0]));
            assert!(machine.has_successor(), "row {row}: {cause:?} then a fence");
        }
        for cause in quiet {
            let mut machine = start.clone();
            machine.step(Event::Withdraw(cause));
            assert!(
                !machine.superseded() && !machine.has_successor(),
                "row {row}: {cause:?}"
            );
        }
    }
}
