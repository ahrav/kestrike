//! BOUNDARY-FIRST: a serving machine starts in `PreBoundary`, which admits no read, fill, reply or metadata
//! submission, and only `Machine::cross_boundary`, with the attach gate's `Fenced` value, enters `Recovering`.
//!
//! The tests step `failover::serving::Machine`, a pure table, with fixed events and no device, clock or thread:
//!
//! - `a_machine_before_the_boundary_admits_nothing`: the three machines a tenure can hold before the boundary
//!   refuse every operation and every metadata kind at every sampled time.
//! - `no_event_of_the_table_crosses_the_boundary`: every machine reachable from those three by the table's
//!   events, without `cross_boundary`, is outside `Recovering` and `Serving` and admits nothing.
//! - `only_the_gates_value_enters_recovering_and_only_from_before_the_boundary`: `cross_boundary` moves
//!   `PreBoundary` to `Recovering` and is rejected, with the machine unchanged, from every other state.
//! - `the_same_inputs_are_admitted_once_the_boundary_is_crossed`: the Report, the root metadata submission and
//!   the read the first two tests saw refused are admitted after the crossing, so those refusals come from the
//!   boundary.

use super::evidence::Pair;
use super::evidence_tests::{bounds, pair};
use super::serving::{
    Cause, Denial, Deposing, Effect, Event, Machine, MetadataKind, Operation, Outcome, OwnReport,
    Readiness, Reason, Rejection, State, Token,
};
use crate::storage::{Fenced, Session, next_session};

/// The pair the attach gate registered for the tenure.
fn own() -> Pair {
    pair(2, 4, 2)
}

/// The tenure's one token as the module documentation defines it: the session's shard and `(g, a)`, the own pair
/// and lineage 1. Built here from the session, so no expected token is read back from a machine.
fn tenure_token(session: &Session) -> Token {
    Token {
        shard: session.shard(),
        generation: session.target().generation,
        epoch: session.epoch(),
        exhid: own().exhid,
        key: own().key,
        lineage: 1,
    }
}

/// The machines a tenure can hold before the boundary: without a token, with the gate's token and no window, and
/// with the gate's token and a window anchored at time zero.
fn before_the_boundary(session: &Session) -> [(&'static str, Machine); 3] {
    [
        ("no token", Machine::new(bounds(), session)),
        ("gate token", Machine::gated(bounds(), session, own())),
        (
            "gate token and window",
            Machine::issued(bounds(), session, own()),
        ),
    ]
}

/// An own-holder Report under the tenure's lineage, certified within the Report deadline.
fn own_report(submitted_at: u64) -> Event {
    Event::OwnHolder(OwnReport {
        pair: own(),
        lineage: 1,
        submitted_at,
        certified_at: submitted_at,
    })
}

const KINDS: [MetadataKind; 3] = [
    MetadataKind::CheckpointUnit,
    MetadataKind::CheckpointRoot,
    MetadataKind::ResetRoot,
];

const OPERATIONS: [Operation; 4] = [
    Operation::Get,
    Operation::Read,
    Operation::Fill,
    Operation::Reply { lineage: 1 },
];

/// Times inside, at the end of and past the window a Report at time 0 or 1 opens.
fn times() -> [u64; 5] {
    let window = bounds().window();
    [0, 1, window - 1, window, window + 1]
}

/// Every event column of the table with the tenure's token: own-holder Reports, both readiness kinds, expiries,
/// terminals, a metadata submission of each kind, the three withhold inputs, the recovery withhold, withdrawals
/// that request a flip, observe a successor and carry a deposing status, and the close.
fn table_events(token: Token) -> Vec<Event> {
    let mut events = vec![
        own_report(1),
        own_report(30),
        Event::Readiness(Readiness::ReadReady { token }),
        Event::Readiness(Readiness::AllocationReady { token }),
        Event::Expire { now: 0 },
        Event::Expire { now: 50 },
        Event::Terminal { lineage: 1 },
        Event::Terminal { lineage: 2 },
        Event::Refresh { at: 1 },
        Event::ReadFailed { sent_at: 2 },
        Event::Peer { read_at: Some(3) },
        Event::Peer { read_at: None },
        Event::Withheld,
        Event::Withdraw(Cause::Planned),
        Event::Withdraw(Cause::Attachment),
        Event::Withdraw(Cause::Flipped),
        Event::Withdraw(Cause::Status(Deposing::Conflict)),
        Event::Close,
    ];
    events.extend(KINDS.map(|kind| Event::Metadata {
        token,
        now: 1,
        kind,
    }));
    events
}

/// Each admission `machine` grants under `token`, and each refusal that is not the one a state outside `Serving`
/// and `Recovering` gives: `NotServing` with the machine's state for an operation, `MetadataRefused` with the state
/// and the kind for a metadata submission. Empty when the machine admits nothing.
fn admissions(machine: &Machine, token: Token) -> Vec<String> {
    let state = machine.state();
    let mut granted = Vec::new();
    for now in times() {
        for operation in OPERATIONS {
            let answer = machine.admit_at(operation, token, now);
            if answer != Err(Denial::NotServing(state)) {
                granted.push(format!("{operation:?} at {now}: {answer:?}"));
            }
        }
        for kind in KINDS {
            let answer = machine.clone().step(Event::Metadata { token, now, kind });
            if answer != Outcome::Rejected(Rejection::MetadataRefused { state, kind }) {
                granted.push(format!("{kind:?} at {now}: {answer:?}"));
            }
        }
    }
    granted
}

#[test]
fn a_machine_before_the_boundary_admits_nothing() {
    let session = next_session();
    let token = tenure_token(&session);
    let mut wrong = Vec::new();
    for (name, machine) in before_the_boundary(&session) {
        if machine.state() != State::PreBoundary {
            wrong.push(format!("{name}: starts in {:?}", machine.state()));
        }
        for granted in admissions(&machine, token) {
            wrong.push(format!("{name}: {granted}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "BOUNDARY-FIRST: a machine starts in PreBoundary, which admits no read, fill, reply or metadata submission: {wrong:?}"
    );
}

/// The closure of the machines before the boundary under every event of the table: each machine reached is stepped
/// by each event until no new machine appears. The crossing is never called, so by BOUNDARY-FIRST no machine of the
/// closure is `Recovering` or `Serving`, no step reports a move there or an admission, an own-holder Report before
/// the boundary stays `BeforeBoundary`, and no machine of the closure admits an operation or a metadata submission.
#[test]
fn no_event_of_the_table_crosses_the_boundary() {
    /// More machines than the closure holds; reaching it would leave the closure unfinished.
    const MOST: usize = 20_000;
    let session = next_session();
    let token = tenure_token(&session);
    let events = table_events(token);
    let mut reached: Vec<Machine> = before_the_boundary(&session)
        .into_iter()
        .map(|(_, machine)| machine)
        .collect();
    let mut wrong = Vec::new();
    let mut next = 0;
    while next < reached.len() && reached.len() < MOST && wrong.len() < 8 {
        let machine = reached[next].clone();
        next += 1;
        for event in &events {
            let mut stepped = machine.clone();
            let outcome = stepped.step(*event);
            let crossed = matches!(stepped.state(), State::Recovering | State::Serving)
                || matches!(
                    outcome,
                    Outcome::Moved {
                        to: State::Recovering | State::Serving,
                        ..
                    } | Outcome::Admitted(_)
                );
            let report_acted = machine.state() == State::PreBoundary
                && matches!(event, Event::OwnHolder(_))
                && (outcome != Outcome::Stayed(Reason::BeforeBoundary) || stepped != machine);
            if crossed || report_acted {
                wrong.push(format!(
                    "{event:?} on {:?} gave {outcome:?} and left {:?}",
                    machine.state(),
                    stepped.state()
                ));
            }
            for granted in admissions(&stepped, token) {
                wrong.push(format!(
                    "after {event:?} on {:?}: {granted}",
                    machine.state()
                ));
            }
            if !reached.contains(&stepped) {
                reached.push(stepped);
            }
        }
        if machine.state() == State::Closed {
            let mut stepped = machine.clone();
            let outcome = stepped.step(Event::Withdraw(Cause::Attachment));
            if outcome != Outcome::Stayed(Reason::Closed) || stepped != machine {
                wrong.push(format!(
                    "a retirement trigger on a closed machine gave {outcome:?}"
                ));
            }
        }
    }
    let finished = next == reached.len();
    let states: Vec<State> = [State::PreBoundary, State::Withdrawn, State::Closed]
        .into_iter()
        .filter(|state| reached.iter().any(|machine| machine.state() == *state))
        .collect();
    assert!(
        wrong.is_empty(),
        "BOUNDARY-FIRST: only cross_boundary enters Recovering, so no admission precedes the fencing boundary: {wrong:?}"
    );
    assert!(
        finished,
        "the closure did not finish within {MOST} machines"
    );
    assert_eq!(
        states,
        [State::PreBoundary, State::Withdrawn, State::Closed],
        "the closure reaches every state a machine can hold without crossing"
    );
    assert!(
        reached
            .iter()
            .any(|machine| machine.flip_request().is_some()),
        "the closure reaches a machine with a flip request"
    );
}

/// A machine in each state, the three before the boundary first, each paired with the outcome `cross_boundary`
/// must give it for the gate's value of the own pair.
fn crossings(session: &Session) -> Vec<(String, Machine, Outcome)> {
    let token = tenure_token(session);
    let fenced = Fenced::assumed_for(own());
    let moved = |effect| Outcome::Moved {
        to: State::Recovering,
        effect,
    };
    let rejected = |state| Outcome::Rejected(Rejection::Unsupported { state });
    let mut rows = Vec::new();
    for (name, machine) in before_the_boundary(session) {
        let effect = if name == "no token" {
            Effect::Issue(token)
        } else {
            Effect::None
        };
        rows.push((
            format!("PreBoundary, {name}"),
            machine.clone(),
            moved(effect),
        ));
        let mut withdrawn = machine.clone();
        withdrawn.step(Event::Withdraw(Cause::Planned));
        rows.push((
            format!("Withdrawn before the boundary, {name}"),
            withdrawn,
            rejected(State::Withdrawn),
        ));
        let mut closed = machine.clone();
        closed.step(Event::Close);
        rows.push((
            format!("Closed before the boundary, {name}"),
            closed,
            rejected(State::Closed),
        ));
        let mut recovering = machine;
        recovering.cross_boundary(&fenced);
        rows.push((
            format!("Recovering, {name}"),
            recovering.clone(),
            rejected(State::Recovering),
        ));
        let mut serving = recovering.clone();
        serving.step(Event::Readiness(Readiness::ReadReady { token }));
        rows.push((
            format!("Serving, {name}"),
            serving.clone(),
            rejected(State::Serving),
        ));
        let mut withdrawn = serving.clone();
        withdrawn.step(Event::Withdraw(Cause::Flipped));
        rows.push((
            format!("Withdrawn after serving, {name}"),
            withdrawn,
            rejected(State::Withdrawn),
        ));
        let mut closed = serving;
        closed.step(Event::Close);
        rows.push((
            format!("Closed after serving, {name}"),
            closed,
            rejected(State::Closed),
        ));
    }
    rows
}

#[test]
fn only_the_gates_value_enters_recovering_and_only_from_before_the_boundary() {
    let session = next_session();
    let token = tenure_token(&session);
    let fenced = Fenced::assumed_for(own());
    let mut wrong = Vec::new();
    for (name, machine, expected) in crossings(&session) {
        let before = machine.state();
        let stated = match expected {
            Outcome::Rejected(Rejection::Unsupported { state }) => state,
            _ => State::PreBoundary,
        };
        if before != stated {
            wrong.push(format!("{name}: the row's machine is in {before:?}"));
            continue;
        }
        let mut crossed = machine.clone();
        let outcome = crossed.cross_boundary(&fenced);
        if outcome != expected {
            wrong.push(format!(
                "{name}: cross_boundary gave {outcome:?}, not {expected:?}"
            ));
        }
        if before == State::PreBoundary {
            if crossed.state() != State::Recovering || crossed.token() != Some(token) {
                wrong.push(format!(
                    "{name}: crossed into {:?} with {:?}",
                    crossed.state(),
                    crossed.token()
                ));
            }
        } else if crossed != machine {
            wrong.push(format!("{name}: a rejected crossing changed the machine"));
        }
    }
    assert!(
        wrong.is_empty(),
        "BOUNDARY-FIRST: cross_boundary with the gate's Fenced value enters Recovering from PreBoundary alone: {wrong:?}"
    );
}

#[test]
fn the_same_inputs_are_admitted_once_the_boundary_is_crossed() {
    let session = next_session();
    let token = tenure_token(&session);
    let window = bounds().window();
    let root = Event::Metadata {
        token,
        now: 1,
        kind: MetadataKind::ResetRoot,
    };
    let mut machine = Machine::gated(bounds(), &session, own());
    let refused_before = (
        machine.step(own_report(1)),
        machine.step(root),
        machine.admit_at(Operation::Read, token, 1),
    );
    let crossed = machine.cross_boundary(&Fenced::assumed_for(own()));
    let renewed = machine.step(own_report(1));
    let root_admitted = machine.step(root);
    let read_in_recovering = machine.admit_at(Operation::Read, token, 1);
    let ready = machine.step(Event::Readiness(Readiness::ReadReady { token }));
    let read_admitted = machine.admit_at(Operation::Read, token, 1);
    assert_eq!(
        refused_before,
        (
            Outcome::Stayed(Reason::BeforeBoundary),
            Outcome::Rejected(Rejection::MetadataRefused {
                state: State::PreBoundary,
                kind: MetadataKind::ResetRoot,
            }),
            Err(Denial::NotServing(State::PreBoundary)),
        ),
        "before the boundary the Report, the root submission and the read change and admit nothing"
    );
    assert_eq!(
        (
            crossed,
            renewed,
            root_admitted,
            read_in_recovering,
            ready,
            read_admitted
        ),
        (
            Outcome::Moved {
                to: State::Recovering,
                effect: Effect::None,
            },
            Outcome::Moved {
                to: State::Recovering,
                effect: Effect::Renew { until: 1 + window },
            },
            Outcome::Admitted(token),
            Err(Denial::NotServing(State::Recovering)),
            Outcome::Moved {
                to: State::Serving,
                effect: Effect::None,
            },
            Ok(token),
        ),
        "after the crossing the same Report renews the window, the root submission is admitted, and the read is admitted once reads are ready"
    );
}
