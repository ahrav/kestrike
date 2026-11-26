//! The closure of a serving machine's Report window, and the withhold inputs.
//!
//! WINDOW-IS-AVAILABILITY: `Event::Expire { now }`, the event of a Report timeout, an unreadable Report or a
//! clock fault, closes the Report window of a `Serving` or `Recovering` machine and moves no state: the step
//! answers `Stayed(WindowClosed)`, the state, the token and the absent cause stay, every admission from `now` on
//! refuses `WindowExpired`, and an own-holder Report submitted after `now` renews the window under the same
//! token. WITHHOLD-IS-AVAILABILITY: a store timeout (`Event::ReadFailed`), like `Event::Refresh` and
//! `Event::Peer`, answers `Stayed(Availability)` in every state and changes the withhold alone.
//!
//! Every expected instant is computed from the constants below, not read back from the machine.

use crate::failover::bounds::Bounds;
use crate::failover::evidence::Pair;
use crate::failover::evidence_tests::pair;
use crate::failover::serving::{
    Cause, Denial, Effect, Event, Machine, MetadataKind, Operation, Outcome, OwnReport, Readiness,
    Reason, Rejection, State, Token,
};
use crate::storage::{Fenced, next_session};

/// `delta`: a Report's belief holds on `[t_submit, t_submit + DELTA)`.
const DELTA: u64 = 100;
/// `T_report`: a Report certified later than this after its submission renews nothing.
const REPORT_DEADLINE: u64 = 10;
/// The instant the window closes in each history, inside the first window `[0, DELTA)`.
const CLOSED_AT: u64 = 40;

const OPERATIONS: [Operation; 4] = [
    Operation::Get,
    Operation::Read,
    Operation::Fill,
    Operation::Reply { lineage: 1 },
];

fn own() -> Pair {
    pair(2, 4, 2)
}

/// A `PreBoundary` machine that holds the gate's token, whose window is `[0, DELTA)`.
fn issued() -> Machine {
    let bounds = Bounds::new(4, 2, DELTA, REPORT_DEADLINE, 20, 5).unwrap();
    Machine::issued(bounds, &next_session(), own())
}

/// A `Recovering` machine past the fencing boundary, whose window is `[0, DELTA)`, and its token.
fn recovering() -> (Machine, Token) {
    let mut machine = issued();
    let token = machine.token().expect("an issued machine holds its token");
    let crossed = machine.cross_boundary(&Fenced::assumed_for(own()));
    assert_eq!(
        crossed,
        Outcome::Moved {
            to: State::Recovering,
            effect: Effect::None
        },
        "premise: the fencing boundary enters Recovering"
    );
    (machine, token)
}

/// A `Serving` machine whose window is `[0, DELTA)`, and its token.
fn serving() -> (Machine, Token) {
    let (mut machine, token) = recovering();
    let ready = machine.step(Event::Readiness(Readiness::ReadReady { token }));
    assert_eq!(
        ready,
        Outcome::Moved {
            to: State::Serving,
            effect: Effect::None
        },
        "premise: read readiness enters Serving"
    );
    (machine, token)
}

/// An own-holder Report of the machine's pair and lineage, certified within `T_report`.
fn report(submitted_at: u64) -> Event {
    Event::OwnHolder(OwnReport {
        pair: own(),
        lineage: 1,
        submitted_at,
        certified_at: submitted_at + REPORT_DEADLINE,
    })
}

/// What the property says a closure leaves alone: the state, the token, the cause and the flip request.
fn standing(machine: &Machine) -> (State, Option<Token>, bool, bool) {
    (
        machine.state(),
        machine.token(),
        machine.cause().is_some(),
        machine.flip_request().is_some(),
    )
}

#[test]
fn a_report_timeout_closes_a_serving_window_and_moves_no_state() {
    let (mut machine, token) = serving();
    for now in [0, CLOSED_AT, DELTA - 1] {
        assert_eq!(
            machine.admit_at(Operation::Read, token, now),
            Ok(token),
            "premise: a read is admitted at {now}, inside [0, {DELTA})"
        );
    }

    let closed = machine.step(Event::Expire { now: CLOSED_AT });
    assert_eq!(
        closed,
        Outcome::Stayed(Reason::WindowClosed),
        "a Report timeout or an unreadable Report closes the window and moves no state"
    );
    assert_eq!(
        standing(&machine),
        (State::Serving, Some(token), false, false),
        "the closure keeps Serving, the token, no cause and no flip request"
    );
    assert_eq!(
        (machine.window_end(), machine.expired_at()),
        (Some(CLOSED_AT), Some(CLOSED_AT)),
        "the window ends at the closure"
    );

    // Outside the window Serving admits nothing: each instant below lies in the first window's `[CLOSED_AT, DELTA)`
    // or past it.
    for now in [CLOSED_AT, CLOSED_AT + 1, DELTA - 1, DELTA, 10 * DELTA] {
        for operation in OPERATIONS {
            assert_eq!(
                machine.admit_at(operation, token, now),
                Err(Denial::WindowExpired),
                "{operation:?} at {now} is refused once the window closed at {CLOSED_AT}"
            );
        }
        assert_eq!(
            machine.step(Event::Metadata {
                token,
                now,
                kind: MetadataKind::CheckpointUnit,
            }),
            Outcome::Rejected(Rejection::AuthorityDenied(Denial::WindowExpired)),
            "a metadata submission at {now} is refused once the window closed"
        );
    }

    // A Report submitted at or before the closure carries a belief the closure already ended.
    assert_eq!(
        machine.step(report(CLOSED_AT)),
        Outcome::Stayed(Reason::BeforeExpiry)
    );
    assert_eq!(
        machine.admit_at(Operation::Read, token, CLOSED_AT + 1),
        Err(Denial::WindowExpired)
    );

    // The state and the token were kept, so an own-holder Report submitted after the closure renews the window
    // to `[submitted, submitted + DELTA)` and the same token admits a read again.
    let submitted = CLOSED_AT + 1;
    assert_eq!(
        machine.step(report(submitted)),
        Outcome::Moved {
            to: State::Serving,
            effect: Effect::Renew {
                until: submitted + DELTA
            }
        },
        "a Report submitted after the closure renews the kept Serving state"
    );
    assert_eq!(
        standing(&machine),
        (State::Serving, Some(token), false, false)
    );
    for now in [submitted, submitted + DELTA - 1] {
        assert_eq!(
            machine.admit_at(Operation::Read, token, now),
            Ok(token),
            "the same token admits a read at {now} in the renewed window"
        );
    }
    assert_eq!(
        machine.admit_at(Operation::Read, token, submitted + DELTA),
        Err(Denial::WindowExpired),
        "the renewed window is half-open"
    );
}

#[test]
fn the_same_closure_leaves_a_recovering_machine_recovering() {
    let (mut machine, token) = recovering();
    let root = |now| Event::Metadata {
        token,
        now,
        kind: MetadataKind::CheckpointRoot,
    };
    assert_eq!(
        machine.step(root(CLOSED_AT)),
        Outcome::Admitted(token),
        "premise: Recovering admits a root read inside its window"
    );

    let closed = machine.step(Event::Expire { now: CLOSED_AT });
    assert_eq!(
        closed,
        Outcome::Stayed(Reason::WindowClosed),
        "the closure moves no state in Recovering"
    );
    assert_eq!(
        standing(&machine),
        (State::Recovering, Some(token), false, false),
        "the closure keeps Recovering, the token, no cause and no flip request"
    );
    for now in [CLOSED_AT, DELTA - 1, DELTA] {
        assert_eq!(
            machine.step(root(now)),
            Outcome::Rejected(Rejection::AuthorityDenied(Denial::WindowExpired)),
            "Recovering admits nothing at {now}, outside its window"
        );
    }

    // The kept state still takes the rest of its tenure: a renewal, then read readiness, then a read.
    let submitted = CLOSED_AT + 1;
    assert_eq!(
        machine.step(report(submitted)),
        Outcome::Moved {
            to: State::Recovering,
            effect: Effect::Renew {
                until: submitted + DELTA
            }
        }
    );
    assert_eq!(machine.step(root(submitted)), Outcome::Admitted(token));
    assert_eq!(
        machine.step(Event::Readiness(Readiness::ReadReady { token })),
        Outcome::Moved {
            to: State::Serving,
            effect: Effect::None
        },
        "the machine the closure left Recovering still reaches Serving"
    );
    assert_eq!(
        machine.admit_at(Operation::Read, token, submitted),
        Ok(token)
    );
}

#[test]
fn a_store_timeout_updates_the_withhold_and_leaves_state_token_and_window() {
    let (mut machine, token) = serving();
    let before = (
        standing(&machine),
        machine.window_start(),
        machine.window_end(),
        machine.expired_at(),
    );
    assert_eq!(
        before,
        (
            (State::Serving, Some(token), false, false),
            Some(0),
            Some(DELTA),
            None
        ),
        "premise: Serving inside the window [0, {DELTA})"
    );
    assert_eq!(machine.withhold().failed_at(), None);

    // A shard-record read sent at 30 timed out: with no refresh recorded, the withhold marks its send time.
    assert_eq!(
        machine.step(Event::ReadFailed { sent_at: 30 }),
        Outcome::Stayed(Reason::Availability),
        "a store timeout is a withhold input and moves no state"
    );
    assert_eq!(
        machine.withhold().failed_at(),
        Some(30),
        "the store timeout updates the withhold"
    );
    // The mark keeps the earliest failed send time, in any observation order.
    for (sent_at, earliest) in [(35, 30), (20, 20)] {
        assert_eq!(
            machine.step(Event::ReadFailed { sent_at }),
            Outcome::Stayed(Reason::Availability)
        );
        assert_eq!(machine.withhold().failed_at(), Some(earliest));
    }
    assert_eq!(
        (
            standing(&machine),
            machine.window_start(),
            machine.window_end(),
            machine.expired_at(),
        ),
        before,
        "the store timeout leaves the state, the token and the window as they were"
    );
    for now in [CLOSED_AT, DELTA - 1] {
        assert_eq!(
            machine.admit_at(Operation::Read, token, now),
            Ok(token),
            "an admitted device read still passes at {now}; the window did not close"
        );
    }
}

#[test]
fn the_withhold_inputs_move_no_state_in_any_state() {
    let (recovering, _) = recovering();
    let (serving, _) = serving();
    let mut expired = serving.clone();
    assert_eq!(
        expired.step(Event::Expire { now: CLOSED_AT }),
        Outcome::Stayed(Reason::WindowClosed)
    );
    let mut closed = serving.clone();
    assert_eq!(
        closed.step(Event::Close),
        Outcome::Moved {
            to: State::Closed,
            effect: Effect::None
        }
    );
    let mut withdrawn = serving.clone();
    assert_eq!(
        withdrawn.step(Event::Withdraw(Cause::Unheld)),
        Outcome::Moved {
            to: State::Withdrawn,
            effect: Effect::None
        }
    );
    let rows = [
        (issued(), State::PreBoundary),
        (recovering, State::Recovering),
        (serving, State::Serving),
        (expired, State::Serving),
        (withdrawn, State::Withdrawn),
        (closed, State::Closed),
    ];
    let inputs = [
        Event::Refresh { at: 29 },
        Event::ReadFailed { sent_at: 30 },
        Event::Peer { read_at: Some(32) },
    ];
    for (mut machine, state) in rows {
        let before = (
            standing(&machine),
            machine.window_start(),
            machine.window_end(),
            machine.expired_at(),
        );
        assert_eq!(before.0.0, state, "premise: the row's state");
        for input in inputs {
            assert_eq!(
                machine.step(input),
                Outcome::Stayed(Reason::Availability),
                "{input:?} in {state:?} updates the withhold and moves no state"
            );
            assert_eq!(
                (
                    standing(&machine),
                    machine.window_start(),
                    machine.window_end(),
                    machine.expired_at(),
                ),
                before,
                "{input:?} in {state:?} leaves the state, the token and the window"
            );
        }
        assert_eq!(
            (
                machine.withhold().failed_at(),
                machine.withhold().refreshed_at(),
                machine.withhold().peer_read_at(),
            ),
            (Some(30), Some(29), Some(32)),
            "the three inputs reached the withhold in {state:?}: the failure sent after the refresh keeps its mark"
        );
    }
}
