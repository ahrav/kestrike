//! A serving machine admits an operation and a metadata submission only under its exact current token.
//!
//! OWN-SESSION-TOKEN: a machine admits an operation (`Machine::admit_at`, and `Machine::retry_at`, which goes
//! through it) and a metadata submission (`Event::Metadata`) only under its exact current token. Each history
//! holds a machine inside its Report window and, at one instant, presents the machine's own token and tokens
//! that differ from it in exactly one field: the shard, the generation, the activated epoch, the own pair's host
//! identifier, the own pair's key, the lineage. The own token is admitted; every other token is refused
//! `Denial::TokenMismatch`, for every operation and every metadata kind the state takes, and the refusal moves
//! nothing in the machine. The last history shows the clause on the withhold: while it holds, a GET under the
//! exact token is `Withheld`, a `Read` under the exact token is admitted, and a `Read` under a token that
//! differs in one field is still refused.
//!
//! The machines are built as the serving table's own tests build them. The differing shard is the next shard
//! number, whose tenures can hold the same `(g, a)`. The other differing field values come from machines of
//! another session or another pair, so each is a value a real tenure issues.

use crate::failover::bounds::Bounds;
use crate::failover::evidence::Pair;
use crate::failover::evidence_tests::pair;
use crate::failover::serving::{
    Denial, Effect, Event, Machine, MetadataKind, Operation, Outcome, OwnReport, Readiness,
    Rejection, State, Token,
};
use crate::failover::withhold::{M_US, W_US};
use crate::net::ownership::Shard;
use crate::storage::{Fenced, next_session, session_at};

/// `delta`: a Report's belief holds on `[t_submit, t_submit + DELTA)`.
const DELTA: u64 = 100;
/// `T_report`: a Report certified later than this after its submission renews nothing.
const REPORT_DEADLINE: u64 = 10;
/// The instant of every admission in the first window `[0, DELTA)`.
const NOW: u64 = 40;

const OPERATIONS: [Operation; 4] = [
    Operation::Get,
    Operation::Read,
    Operation::Fill,
    Operation::Reply { lineage: 1 },
];

const KINDS: [MetadataKind; 3] = [
    MetadataKind::CheckpointUnit,
    MetadataKind::CheckpointRoot,
    MetadataKind::ResetRoot,
];

fn bounds() -> Bounds {
    Bounds::new(4, 2, DELTA, REPORT_DEADLINE, 20, 5).unwrap()
}

fn own() -> Pair {
    pair(2, 4, 2)
}

/// A `Recovering` machine past the fencing boundary, whose window is `[0, DELTA)`, and its token.
fn recovering() -> (Machine, Token) {
    let mut machine = Machine::issued(bounds(), &next_session(), own());
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

/// A `Serving` machine that admits fills, whose window is `[0, DELTA)`, and its token.
fn serving() -> (Machine, Token) {
    let (mut machine, token) = recovering();
    assert_eq!(
        machine.step(Event::Readiness(Readiness::ReadReady { token })),
        Outcome::Moved {
            to: State::Serving,
            effect: Effect::None
        },
        "premise: read readiness enters Serving"
    );
    assert_eq!(
        machine.step(Event::Readiness(Readiness::AllocationReady { token })),
        Outcome::Moved {
            to: State::Serving,
            effect: Effect::AdmitFills
        },
        "premise: allocation readiness admits fills"
    );
    (machine, token)
}

/// The tokens that differ from `token` in exactly one field, each named by that field. The generation and the
/// epoch are those of other sessions' machines, the host identifier and the key those of other pairs' machines.
fn one_field_away(token: Token) -> [(&'static str, Token); 6] {
    let issued_for = |machine: Machine| machine.token().expect("an issued machine holds its token");
    let later_epoch = issued_for(Machine::issued(bounds(), &next_session(), own()));
    let later_generation = issued_for(Machine::issued(bounds(), &session_at(2, 0), own()));
    let other_host = issued_for(Machine::issued(bounds(), &next_session(), pair(3, 4, 2)));
    let other_key = issued_for(Machine::issued(bounds(), &next_session(), pair(2, 5, 2)));
    let away = [
        (
            "shard",
            Token {
                shard: Shard::new(token.shard.get() + 1).expect("the next shard number is a shard"),
                ..token
            },
        ),
        (
            "generation",
            Token {
                generation: later_generation.generation,
                ..token
            },
        ),
        (
            "epoch",
            Token {
                epoch: later_epoch.epoch,
                ..token
            },
        ),
        (
            "exhid",
            Token {
                exhid: other_host.exhid,
                ..token
            },
        ),
        (
            "key",
            Token {
                key: other_key.key,
                ..token
            },
        ),
        (
            "lineage",
            Token {
                lineage: token.lineage + 1,
                ..token
            },
        ),
    ];
    for (field, other) in away {
        assert_ne!(
            other, token,
            "premise: the token built for `{field}` differs from the machine's token"
        );
    }
    away
}

#[test]
fn a_serving_machine_admits_each_operation_only_under_its_exact_token() {
    let (machine, token) = serving();
    let before = machine.clone();

    // The exact token is admitted at this instant, for every operation.
    for operation in OPERATIONS {
        assert_eq!(
            machine.admit_at(operation, token, NOW),
            Ok(token),
            "{operation:?} under the exact token is admitted at {NOW}, inside [0, {DELTA})"
        );
        assert_eq!(
            machine.retry_at(operation, 0, token, NOW),
            Ok(token),
            "a retry of {operation:?} under the exact token is admitted at {NOW}"
        );
    }

    let mut admitted = Vec::new();
    for (field, other) in one_field_away(token) {
        for operation in OPERATIONS {
            let first = machine.admit_at(operation, other, NOW);
            let retried = machine.retry_at(operation, 0, other, NOW);
            if first != Err(Denial::TokenMismatch) || retried != Err(Denial::TokenMismatch) {
                admitted.push((field, operation, first, retried));
            }
        }
    }
    assert!(
        admitted.is_empty(),
        "at {NOW}, inside the window, a token that differs in one field is refused TokenMismatch \
         for every operation and every retry; listed: (field, operation, admit_at, retry_at): {admitted:?}"
    );
    assert_eq!(machine, before, "an admission check moves nothing");
}

#[test]
fn a_serving_machine_admits_each_metadata_kind_only_under_its_exact_token() {
    let (mut machine, token) = serving();
    let before = machine.clone();

    // The exact token is admitted at this instant, for every kind.
    for kind in KINDS {
        assert_eq!(
            machine.step(Event::Metadata {
                token,
                now: NOW,
                kind,
            }),
            Outcome::Admitted(token),
            "a {kind:?} submission under the exact token is admitted at {NOW}"
        );
    }

    let mut admitted = Vec::new();
    for (field, other) in one_field_away(token) {
        for kind in KINDS {
            let outcome = machine.step(Event::Metadata {
                token: other,
                now: NOW,
                kind,
            });
            if outcome != Outcome::Rejected(Rejection::AuthorityDenied(Denial::TokenMismatch)) {
                admitted.push((field, kind, outcome));
            }
        }
    }
    assert!(
        admitted.is_empty(),
        "at {NOW}, inside the window, a metadata submission under a token that differs in one field \
         is Rejected(AuthorityDenied(TokenMismatch)) for every kind; listed: (field, kind, outcome): {admitted:?}"
    );
    assert_eq!(machine, before, "a metadata admission check moves nothing");
}

#[test]
fn a_recovering_machine_admits_root_submissions_only_under_its_exact_token() {
    let (mut machine, token) = recovering();
    let before = machine.clone();
    let roots = [MetadataKind::CheckpointRoot, MetadataKind::ResetRoot];

    // The exact token is admitted at this instant, for both root kinds.
    for kind in roots {
        assert_eq!(
            machine.step(Event::Metadata {
                token,
                now: NOW,
                kind,
            }),
            Outcome::Admitted(token),
            "a {kind:?} submission under the exact token is admitted in Recovering at {NOW}"
        );
    }

    let mut admitted = Vec::new();
    for (field, other) in one_field_away(token) {
        for kind in roots {
            let outcome = machine.step(Event::Metadata {
                token: other,
                now: NOW,
                kind,
            });
            if outcome != Outcome::Rejected(Rejection::AuthorityDenied(Denial::TokenMismatch)) {
                admitted.push((field, kind, outcome));
            }
        }
    }
    assert!(
        admitted.is_empty(),
        "a root-kind submission to a Recovering machine under a token that differs in one field is \
         Rejected(AuthorityDenied(TokenMismatch)); listed: (field, kind, outcome): {admitted:?}"
    );

    // Recovering admits no operation, whatever the token: every other state refuses as NotServing.
    for operation in OPERATIONS {
        assert_eq!(
            machine.admit_at(operation, token, NOW),
            Err(Denial::NotServing(State::Recovering)),
            "{operation:?} in Recovering refuses as NotServing"
        );
    }
    assert_eq!(machine, before, "a metadata admission check moves nothing");
}

#[test]
fn a_read_passes_the_withhold_and_still_takes_the_token_check() {
    // The window that holds the admissions starts after `W`, so the withhold can hold inside it.
    const SUBMITTED: u64 = 2 * W_US;
    const LATE: u64 = SUBMITTED + NOW;

    let (mut machine, token) = serving();
    assert_eq!(
        machine.step(Event::OwnHolder(OwnReport {
            pair: own(),
            lineage: 1,
            submitted_at: SUBMITTED,
            certified_at: SUBMITTED + REPORT_DEADLINE,
        })),
        Outcome::Moved {
            to: State::Serving,
            effect: Effect::Renew {
                until: SUBMITTED + DELTA
            }
        },
        "premise: an own-holder Report renews the window to [{SUBMITTED}, {SUBMITTED} + {DELTA})"
    );
    // The own freshness clock refreshed at 1, a shard-record read sent at 2 failed, and a peer read the record
    // more than `M` after that: at `LATE` the own read age exceeds `W` and the withhold holds.
    machine.step(Event::Refresh { at: 1 });
    machine.step(Event::ReadFailed { sent_at: 2 });
    machine.step(Event::Peer {
        read_at: Some(2 + M_US + 1),
    });
    assert!(
        machine.withhold().withholds(LATE),
        "premise: the availability withhold holds at {LATE}"
    );

    assert_eq!(
        machine.admit_at(Operation::Get, token, LATE),
        Err(Denial::Withheld),
        "while the withhold holds, a GET under the exact token refuses Withheld"
    );
    assert_eq!(
        machine.admit_at(Operation::Read, token, LATE),
        Ok(token),
        "a Read under the exact token passes the withhold"
    );

    let mut admitted = Vec::new();
    for (field, other) in one_field_away(token) {
        for operation in [Operation::Read, Operation::Get] {
            let outcome = machine.admit_at(operation, other, LATE);
            if outcome != Err(Denial::TokenMismatch) {
                admitted.push((field, operation, outcome));
            }
        }
    }
    assert!(
        admitted.is_empty(),
        "a Read that passes the withhold still takes the token check, and a GET under another token \
         is refused for its token; listed: (field, operation, outcome): {admitted:?}"
    );
}
