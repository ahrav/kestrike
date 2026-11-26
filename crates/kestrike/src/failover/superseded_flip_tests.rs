//! A machine that observed a later tenure of its shard requests no flip afterwards.
//!
//! SupersededRequestsNoFlip: a cause that observed a later tenure of the shard (`Flipped`, `NewerFence`,
//! `LaterTenure`) closes `Machine::flip_open`, so a machine that took such a cause requests no flip
//! afterwards, whatever retirement trigger follows.
//!
//! The tests step `failover::serving::Machine`, a pure table, with fixed events and no device, clock or
//! thread. Each test decides its verdict into a list of the cells that broke the property and asserts on that
//! list at its end.
//!
//! - `a_machine_that_observed_a_later_tenure_requests_no_flip_whatever_trigger_follows`: from each state a tenure
//!   can withdraw from, a machine takes the observation as its withdrawing cause, or after a withdrawal that
//!   requested no flip; every flip-requesting trigger after it, alone and in a run of all six, changes nothing
//!   and requests nothing.
//! - `the_same_withdrawal_without_the_observation_requests_its_flip_once`: the same withdrawals without the
//!   observation, followed by the same triggers, request the flip of the tenure's own `(g, owner, E)` on the
//!   first trigger and nothing on the next, so the first test's silence comes from the observation.

use super::evidence::{NotSole, Pair};
use super::evidence_tests::{bounds, pair};
use super::retire::Target;
use super::serving::{
    Cause, Deposing, Effect, Event, Machine, Outcome, Readiness, Reason, ReportTrigger, State,
};
use crate::storage::{Fenced, Session, next_session};

/// The pair the attach gate registered for the tenure.
fn own() -> Pair {
    pair(2, 4, 2)
}

/// The machines of one tenure in each state a withdrawal can leave: before the boundary without a token and with
/// the gate's token and window, `Recovering` after the gate's value, and `Serving` after the recovery owner
/// opened reads.
fn withdrawable(session: &Session) -> [(&'static str, Machine); 4] {
    let before = Machine::new(bounds(), session);
    let issued = Machine::issued(bounds(), session, own());
    let token = issued.token().expect("the gate issued the tenure's token");
    let mut recovering = issued.clone();
    recovering.cross_boundary(&Fenced::assumed_for(own()));
    let mut serving = recovering.clone();
    serving.step(Event::Readiness(Readiness::ReadReady { token }));
    assert_eq!(
        [
            before.state(),
            issued.state(),
            recovering.state(),
            serving.state()
        ],
        [
            State::PreBoundary,
            State::PreBoundary,
            State::Recovering,
            State::Serving
        ],
        "premise: the fixture reaches each state a withdrawal can leave"
    );
    [
        ("before the boundary, no token", before),
        ("before the boundary, gate token", issued),
        ("recovering", recovering),
        ("serving", serving),
    ]
}

/// The causes that observed a later tenure of the shard.
fn observations() -> [Cause; 3] {
    [
        Cause::Flipped,
        Cause::NewerFence { page: 1, fence: 9 },
        Cause::LaterTenure,
    ]
}

/// The withdrawing causes that request no flip and observe no later tenure.
fn quiet_withdrawals() -> [Cause; 5] {
    [
        Cause::Status(Deposing::Conflict),
        Cause::Status(Deposing::PreemptAborted),
        Cause::RecordedHolder,
        Cause::Unheld,
        Cause::Unverified,
    ]
}

/// The retirement triggers, each of which requests the flip while the flip is open.
pub(super) fn triggers() -> [Cause; 6] {
    [
        Cause::Attachment,
        Cause::Modification,
        Cause::ForceDetach,
        Cause::RestartCheck,
        Cause::Exhausted,
        Cause::Report(
            ReportTrigger::new(NotSole::ForeignHolder)
                .expect("a foreign holder is an observed refusal"),
        ),
    ]
}

/// What a machine shows about its flip: the state, the cause it keeps, the request it made, and the two flags.
type Shown = (State, Option<Cause>, Option<Target>, bool, bool);

fn shown(machine: &Machine) -> Shown {
    (
        machine.state(),
        machine.cause(),
        machine.flip_request(),
        machine.superseded(),
        machine.flip_open(),
    )
}

/// Steps `trigger` on a machine that observed a later tenure and keeps `cause`, and records every way the step
/// broke the property.
fn step_superseded(
    machine: &mut Machine,
    cause: Cause,
    trigger: Cause,
    cell: &str,
    broken: &mut Vec<String>,
) {
    let outcome = machine.step(Event::Withdraw(trigger));
    if outcome != Outcome::Stayed(Reason::Withdrawn) {
        broken.push(format!("{cell}: {trigger:?} returned {outcome:?}"));
    }
    let after = shown(machine);
    if after != (State::Withdrawn, Some(cause), None, true, false) {
        broken.push(format!(
            "{cell}: after {trigger:?} the machine shows {after:?}"
        ));
    }
}

/// The machines that observed a later tenure, each with the cause it keeps: the observation as the withdrawing
/// cause from every withdrawable state, and the observation after each withdrawal that requested no flip. Records
/// a broken observation step in `broken`.
fn superseded_machines(
    session: &Session,
    broken: &mut Vec<String>,
) -> Vec<(String, Machine, Cause)> {
    let mut machines = Vec::new();
    for (name, start) in withdrawable(session) {
        for observation in observations() {
            let cell = format!("{name}, withdrawn by {observation:?}");
            let mut machine = start.clone();
            let outcome = machine.step(Event::Withdraw(observation));
            let withdrew = Outcome::Moved {
                to: State::Withdrawn,
                effect: Effect::None,
            };
            if outcome != withdrew {
                broken.push(format!("{cell}: the observation returned {outcome:?}"));
            }
            machines.push((cell, machine, observation));
            for quiet in quiet_withdrawals() {
                let cell = format!("{name}, withdrawn by {quiet:?}, then {observation:?}");
                let mut machine = start.clone();
                let first = machine.step(Event::Withdraw(quiet));
                assert_eq!(
                    (first, shown(&machine)),
                    (withdrew, (State::Withdrawn, Some(quiet), None, false, true)),
                    "premise: {cell}: the withdrawal requests no flip and leaves the flip open"
                );
                let outcome = machine.step(Event::Withdraw(observation));
                if outcome != Outcome::Stayed(Reason::Withdrawn) {
                    broken.push(format!("{cell}: the observation returned {outcome:?}"));
                }
                machines.push((cell, machine, quiet));
            }
        }
    }
    machines
}

#[test]
fn a_machine_that_observed_a_later_tenure_requests_no_flip_whatever_trigger_follows() {
    let session = next_session();
    let mut broken = Vec::new();
    let machines = superseded_machines(&session, &mut broken);
    assert_eq!(machines.len(), 4 * 3 * 6, "premise: every cell is built");
    let mut steps = 0;
    for (cell, machine, cause) in &machines {
        let observed = shown(machine);
        if observed != (State::Withdrawn, Some(*cause), None, true, false) {
            broken.push(format!(
                "{cell}: after the observation the machine shows {observed:?}"
            ));
        }
        // Each trigger alone, as the first event after the observation.
        for trigger in triggers() {
            let mut alone = machine.clone();
            step_superseded(&mut alone, *cause, trigger, cell, &mut broken);
            steps += 1;
        }
        // Every trigger in turn on one machine, then the observation and the first trigger again.
        let mut run = machine.clone();
        for trigger in triggers() {
            step_superseded(&mut run, *cause, trigger, cell, &mut broken);
            steps += 1;
        }
        for observation in observations() {
            step_superseded(&mut run, *cause, observation, cell, &mut broken);
        }
        step_superseded(&mut run, *cause, triggers()[0], cell, &mut broken);
        steps += 1;
    }
    assert_eq!(
        steps,
        72 * 13,
        "premise: every trigger was stepped in every cell"
    );
    assert!(
        broken.is_empty(),
        "SupersededRequestsNoFlip: a machine that observed a later tenure requested a flip or changed its withdrawal in {} cells; the first: {:?}",
        broken.len(),
        broken.first()
    );
}

#[test]
fn the_same_withdrawal_without_the_observation_requests_its_flip_once() {
    let session = next_session();
    let target = session.target();
    let mut broken = Vec::new();
    let mut cells = 0;
    for (name, start) in withdrawable(&session) {
        for quiet in quiet_withdrawals() {
            for (index, trigger) in triggers().into_iter().enumerate() {
                let cell = format!("{name}, withdrawn by {quiet:?}, then {trigger:?}");
                let mut machine = start.clone();
                machine.step(Event::Withdraw(quiet));
                let before = shown(&machine);
                if before != (State::Withdrawn, Some(quiet), None, false, true) {
                    broken.push(format!(
                        "{cell}: after the withdrawal the machine shows {before:?}"
                    ));
                }
                let first = machine.step(Event::Withdraw(trigger));
                let requested = Outcome::Moved {
                    to: State::Withdrawn,
                    effect: Effect::RequestFlip(target),
                };
                if first != requested {
                    broken.push(format!("{cell}: the first trigger returned {first:?}"));
                }
                let flipped = (State::Withdrawn, Some(trigger), Some(target), false, false);
                if shown(&machine) != flipped {
                    broken.push(format!(
                        "{cell}: after the first trigger the machine shows {:?}",
                        shown(&machine)
                    ));
                }
                let next = triggers()[(index + 1) % triggers().len()];
                let second = machine.step(Event::Withdraw(next));
                if second != Outcome::Stayed(Reason::Withdrawn) || shown(&machine) != flipped {
                    broken.push(format!(
                        "{cell}: the next trigger {next:?} returned {second:?} and left {:?}",
                        shown(&machine)
                    ));
                }
                cells += 1;
            }
        }
    }
    assert_eq!(cells, 4 * 5 * 6, "premise: every cell was stepped");
    assert!(
        broken.is_empty(),
        "a quiet withdrawal (a deposing status, RecordedHolder or Unheld) that observed no later tenure requests the flip of its own (g, owner, E) once, on the first retirement trigger; broken in {} cells; the first: {:?}",
        broken.len(),
        broken.first()
    );
}
