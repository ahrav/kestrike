//! Rejection witnesses for the per-key domain: every history outside it is
//! Inconclusive with the field, bound or operation that put it there.

use super::action::ActionKind;
use super::domain::admitted;
use super::evidence::{Evidence, Hypothesis};
use super::golden::*;
use super::history::History;
use super::ids::{ClockSample, KeyId, Label, OpId, Ordinal, ResourceId, ResourceKind, Subject};
use super::outcome::Outcome;
use super::row::{Report, ReportKind, ReportState, Row};
use super::script::{META, Script};
use super::verdict::Inconclusive;

#[test]
fn truncated_and_poisoned_histories_are_inconclusive_from_the_checker() {
    let history = held_read_across_invalidation(MISSING, None);
    let mut truncated = History::new();
    for row in history.rows().iter().take(4) {
        truncated.push(row.clone());
    }
    assert_eq!(admitted(&truncated), Err(Inconclusive::Truncated));

    let mut poisoned = History::new();
    for row in history.rows() {
        poisoned.push(row.clone());
    }
    let mut report = Row::new(OpId(99), ActionKind::Report);
    report.subject = Some(Subject::Resource(ResourceId {
        kind: ResourceKind::Slot,
        index: 0,
    }));
    report.report = Some(Report {
        kind: ReportKind::Ledger,
        state: ReportState::Poisoned,
    });
    report.episode = history.rows()[0].episode;
    report.responded = Some(Ordinal(10_000));
    poisoned.push(report);
    poisoned.seal();
    assert_eq!(
        admitted(&poisoned),
        Err(Inconclusive::PoisonedReport {
            op: OpId(99),
            report: ReportKind::Ledger,
        })
    );
}

#[test]
fn a_publication_needs_an_acknowledged_fill() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let mut op = None;
    let refused_fill = edited(&s.finish(), |rows| {
        let fill = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Fill)
            .unwrap();
        fill.outcome = Some(REFUSED);
        op = Some(fill.op);
    });
    assert_eq!(
        admitted(&refused_fill),
        Err(Inconclusive::Malformed {
            op: op.unwrap(),
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_key_release_names_its_lookups_requested_key() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let first = s.lookup(K, HIT, Some(A));
    s.release_key(first, J);
    for _ in 0..2 {
        s.lookup(K, HIT, Some(A));
    }
    assert_eq!(
        admitted(&s.finish()),
        Err(Inconclusive::Malformed {
            op: first,
            field: super::row::Field::Key,
        })
    );
}

#[test]
fn one_lookup_row_per_operation() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let first = s.lookup(K, HIT, Some(A));
    for _ in 0..2 {
        s.lookup(K, HIT, Some(A));
    }
    let reused = edited(&s.finish(), |rows| {
        for lookup in rows.iter_mut().filter(|r| r.kind == ActionKind::Lookup) {
            lookup.op = first;
        }
    });
    assert_eq!(
        admitted(&reused),
        Err(Inconclusive::Malformed {
            op: first,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_publication_names_the_label_its_fill_carried() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(B));
    let mut op = None;
    let relabeled = edited(&s.finish(), |rows| {
        let publish = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Publish)
            .unwrap();
        publish.label = Some(B);
        publish.metadata_len = Some(META);
        publish.body_len = Some(BODY);
        op = Some(publish.op);
    });
    assert_eq!(
        admitted(&relabeled),
        Err(Inconclusive::Malformed {
            op: op.unwrap(),
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn one_publication_row_per_operation() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, None);
    let op = s.close(publish, Some(ACK));
    let again = s.open(op, ActionKind::Publish, K, Some(A));
    s.close(again, Some(REFUSED));
    s.lookup(K, HIT, Some(A));
    assert_eq!(
        admitted(&s.finish()),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn only_a_delivery_or_a_key_release_ends_a_lease() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for _ in 0..3 {
        s.lookup(K, HIT, Some(A));
    }
    let early_end = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let first = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Lookup)
            .unwrap();
        first.custody_end = Some(Ordinal(first.responded.unwrap().0 + 1));
    });
    let verdict = admitted(&early_end);
    assert!(
        matches!(
            verdict,
            Err(Inconclusive::DomainBound {
                dimension: "holders",
                observed: 3,
                ..
            })
        ),
        "{verdict:?}"
    );
}

#[test]
fn one_lookup_row_per_operation_for_every_outcome() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let hit = s.lookup(K, HIT, Some(A));
    let later = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(later, Outcome::Expired, Some(A));
    let reused = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .rev()
            .find(|r| r.kind == ActionKind::Lookup)
            .unwrap()
            .op = hit;
    });
    assert_eq!(
        admitted(&reused),
        Err(Inconclusive::Malformed {
            op: hit,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_second_fill_phase_for_one_operation_is_malformed() {
    let mut s = Script::new();
    let op = s.fill(K, A, BODY);
    let again = s.fill(K, B, BODY);
    let publish = s.open(op, ActionKind::Publish, K, Some(A));
    s.close(publish, Some(ACK));
    let replace = s.open(op, ActionKind::Replace, K, Some(B));
    s.close(replace, Some(ACK));
    s.lookup(K, HIT, Some(B));
    let shared = edited(&s.finish(), |rows| {
        for row in rows.iter_mut().filter(|r| r.op == again) {
            row.op = op;
        }
    });
    assert_eq!(
        admitted(&shared),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn an_operation_belongs_to_one_phase_family() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let aliased = edited(&s.finish(), |rows| {
        for row in rows.iter_mut().filter(|r| r.op == read) {
            row.op = op;
        }
    });
    assert_eq!(
        admitted(&aliased),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_publication_is_invoked_after_its_fill_responded() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let overlapping = edited(&s.finish(), |rows| {
        let fill = rows
            .iter()
            .position(|r| r.kind == ActionKind::Fill)
            .unwrap();
        let publish = rows
            .iter()
            .position(|r| r.kind == ActionKind::Publish)
            .unwrap();
        let fill_response = rows[fill].responded;
        rows[fill].responded = rows[publish].invoked;
        rows[publish].invoked = fill_response;
    });
    assert_eq!(
        admitted(&overlapping),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_key_release_follows_its_lookup_response() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.release_key(read, K);
    let early = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let lookup = rows.iter().find(|r| r.kind == ActionKind::Lookup).unwrap();
        let inside = Ordinal(lookup.invoked.unwrap().0 + 1);
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Release)
            .unwrap()
            .responded = Some(inside);
    });
    assert_eq!(
        admitted(&early),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Response,
        })
    );
}

#[test]
fn one_invalidation_row_per_operation() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let first = s.invalidate(K, ACK);
    s.publish(K, B, BODY);
    let second = s.invalidate(K, ACK);
    s.lookup(K, MISSING, None);
    let shared = edited(&s.finish(), |rows| {
        rows.iter_mut().find(|r| r.op == second).unwrap().op = first;
    });
    assert_eq!(
        admitted(&shared),
        Err(Inconclusive::Malformed {
            op: first,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn an_invalidation_has_its_own_operation() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let invalidate = s.invalidate(K, ACK);
    let missing = s.lookup(K, MISSING, None);
    let aliased = edited(&s.finish(), |rows| {
        rows.iter_mut().find(|r| r.op == missing).unwrap().op = invalidate;
    });
    assert_eq!(
        admitted(&aliased),
        Err(Inconclusive::Malformed {
            op: invalidate,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_write_completion_follows_its_fill_response() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let early = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let fill = rows.iter().find(|r| r.kind == ActionKind::Fill).unwrap();
        let inside = Ordinal(fill.invoked.unwrap().0 + 1);
        let done = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::WriteCompleted);
        done.unwrap().responded = Some(inside);
    });
    assert_eq!(
        admitted(&early),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Response,
        })
    );
}

#[test]
fn a_receive_follows_its_fill_response() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let early = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let fill = rows.iter().find(|r| r.kind == ActionKind::Fill).unwrap();
        let inside = Ordinal(fill.invoked.unwrap().0 + 1);
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Receive)
            .unwrap()
            .invoked = Some(inside);
    });
    assert_eq!(
        admitted(&early),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_write_completion_follows_its_receives() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let early = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let receive = rows.iter().find(|r| r.kind == ActionKind::Receive).unwrap();
        let inside = Ordinal(receive.invoked.unwrap().0 + 1);
        let done = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::WriteCompleted);
        done.unwrap().responded = Some(inside);
    });
    assert_eq!(
        admitted(&early),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Response,
        })
    );
}

#[test]
fn a_receive_names_its_fills_key_and_label() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let foreign = edited(&s.finish(), |rows| {
        let receive = rows.iter().find(|r| r.kind == ActionKind::Receive).unwrap();
        let mut extra = receive.clone();
        extra.label = Some(B);
        extra.invoked = Some(Ordinal(100));
        extra.responded = Some(Ordinal(101));
        let done = rows
            .iter()
            .position(|r| r.kind == ActionKind::WriteCompleted)
            .unwrap();
        rows.insert(done, extra);
        rows.iter_mut()
            .filter(|r| r.kind == ActionKind::WriteCompleted)
            .for_each(|r| r.responded = Some(Ordinal(102)));
        rows.iter_mut()
            .filter(|r| r.kind == ActionKind::Publish)
            .for_each(|r| {
                r.invoked = Some(Ordinal(103));
                r.responded = Some(Ordinal(104));
            });
        rows.iter_mut()
            .filter(|r| r.kind == ActionKind::Lookup)
            .for_each(|r| {
                r.invoked = Some(Ordinal(105));
                r.responded = Some(Ordinal(106));
            });
    });
    assert_eq!(
        admitted(&foreign),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn an_empty_record_still_receives_its_header() {
    let mut s = Script::new();
    s.publish_sized(K, A, 0, 0);
    s.lookup(K, HIT, Some(A));
    let unreceived = edited(&s.finish(), |rows| {
        rows.retain(|r| r.kind != ActionKind::Receive);
    });
    assert!(matches!(
        admitted(&unreceived),
        Err(Inconclusive::Malformed {
            field: super::row::Field::Response,
            ..
        })
    ));
}

#[test]
fn receives_precede_the_publication_whatever_its_outcome() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, None);
    let op = s.close(publish, Some(REFUSED));
    s.lookup(K, MISSING, None);
    let late = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let publish = rows.iter().find(|r| r.kind == ActionKind::Publish).unwrap();
        let inside = Ordinal(publish.invoked.unwrap().0 + 1);
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Receive)
            .unwrap()
            .responded = Some(inside);
    });
    assert_eq!(
        admitted(&late),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn receives_of_one_fill_follow_one_another() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let overlapping = edited(&s.finish(), |rows| {
        let receive = rows
            .iter()
            .position(|r| r.kind == ActionKind::Receive)
            .unwrap();
        let whole = rows[receive].payload.take().unwrap();
        let (head, tail) = whole.split_at(whole.len() / 2);
        rows[receive].payload = Some(head.to_vec());
        let mut second = rows[receive].clone();
        second.payload = Some(tail.to_vec());
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 4;
            }
        }
        let first = &rows[receive];
        second.invoked = Some(Ordinal(first.invoked.unwrap().0 + 1));
        second.responded = Some(Ordinal(first.responded.unwrap().0 - 1));
        rows.insert(receive + 1, second);
    });
    assert_eq!(
        admitted(&overlapping),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

/// How a fill's receive follows an acknowledged invalidation of its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LateReceive {
    /// An unversioned invalidation in the receive's tenure.
    Revoked,
    /// An invalidation of version two, which leaves the fill live for every
    /// other version.
    Interval,
    /// T2's unversioned invalidation, after which deposed T1 receives.
    Deposed,
}

/// A receive after an acknowledged invalidation that revoked its fill
/// outright in the receive's own segment is malformed; one after an
/// interval invalidation, or after another tenure's invalidation, is
/// admitted and left to the key model.
#[test]
fn a_receive_after_an_acknowledged_invalidation_is_malformed() {
    let late_receive = |late: LateReceive| {
        let mut s = Script::new();
        if late == LateReceive::Deposed {
            for tenure in [1, 2] {
                s.activate(
                    RECOVERED,
                    Some(super::ids::Tenure { g: tenure, a: 0 }),
                    None,
                );
            }
            s.in_tenure(Some(super::ids::Tenure { g: 1, a: 0 }));
        }
        let mut publish = s.begin_publish(K, A, BODY, None);
        if late == LateReceive::Interval {
            publish.set_version(1);
        }
        s.close(publish, Some(ACK));
        let fill = s.fill(K, B, BODY);
        if late == LateReceive::Deposed {
            s.in_tenure(Some(super::ids::Tenure { g: 2, a: 0 }));
        }
        let mut invalidate = s.begin_invalidate(K);
        if late == LateReceive::Interval {
            invalidate.set_covers(super::coverage::Cover::Range { lo: 2, hi: 2 });
        }
        s.close(invalidate, Some(ACK));
        s.lookup(K, MISSING, None);
        let history = edited(&s.finish(), |rows| {
            let receive = rows
                .iter()
                .position(|r| r.kind == ActionKind::Receive && r.op == fill);
            let mut late = rows.remove(receive.unwrap());
            let done = rows
                .iter()
                .position(|r| r.kind == ActionKind::WriteCompleted && r.op == fill);
            let mut done = rows.remove(done.unwrap());
            let last = rows.iter().filter_map(|r| r.responded).max().unwrap().0;
            late.invoked = Some(Ordinal(last + 1));
            late.responded = Some(Ordinal(last + 2));
            done.responded = Some(Ordinal(last + 3));
            rows.push(late);
            rows.push(done);
        });
        (history, fill)
    };
    let (revoked, fill) = late_receive(LateReceive::Revoked);
    assert_eq!(
        admitted(&revoked),
        Err(Inconclusive::Malformed {
            op: fill,
            field: super::row::Field::Invocation,
        })
    );
    for late in [LateReceive::Interval, LateReceive::Deposed] {
        assert_eq!(admitted(&late_receive(late).0), Ok(()), "{late:?}");
    }
}

#[test]
fn a_refused_receive_still_follows_the_fill_lifecycle() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let after_publish = edited(&s.finish(), |rows| {
        let receive = rows.iter().find(|r| r.kind == ActionKind::Receive).unwrap();
        let mut refused = receive.clone();
        refused.outcome = Some(REFUSED);
        refused.payload = Some(Vec::new());
        let last = rows.iter().filter_map(|r| r.responded).max().unwrap().0;
        refused.invoked = Some(Ordinal(last + 1));
        refused.responded = Some(Ordinal(last + 2));
        rows.push(refused);
    });
    assert_eq!(
        admitted(&after_publish),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_release_during_a_refused_read_ends_nothing() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let first = s.lookup(K, HIT, Some(A));
    s.deliver(first, K, A, BODY, REFUSED, Vec::new());
    for _ in 0..2 {
        s.lookup(K, HIT, Some(A));
    }
    let inside = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let refused = rows.iter().find(|r| r.kind == ActionKind::Deliver).unwrap();
        let during = Ordinal(refused.invoked.unwrap().0 + 1);
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Release)
            .unwrap()
            .responded = Some(during);
    });
    let verdict = admitted(&inside);
    assert!(
        matches!(
            verdict,
            Err(Inconclusive::DomainBound {
                dimension: "holders",
                observed: 3,
                ..
            })
        ),
        "{verdict:?}"
    );
}

#[test]
fn a_label_belongs_to_one_key() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let shared = s.publish(J, A, BODY);
    s.lookup(K, HIT, Some(A));
    s.lookup(J, HIT, Some(A));
    assert_eq!(
        admitted(&s.finish()),
        Err(Inconclusive::Malformed {
            op: shared,
            field: super::row::Field::Label,
        })
    );
}

#[test]
fn a_key_release_waits_for_the_reads_custody_end() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let inside = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let delivery = rows.iter().find(|r| r.kind == ActionKind::Deliver).unwrap();
        let during = Ordinal(delivery.responded.unwrap().0 + 1);
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Release)
            .unwrap()
            .responded = Some(during);
    });
    assert_eq!(
        admitted(&inside),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Response,
        })
    );
}

#[test]
fn a_close_has_its_own_operation() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    let close = s.close_cache(ACK);
    let aliased = edited(&s.finish(), |rows| {
        rows.iter_mut().find(|r| r.op == close).unwrap().op = read;
    });
    assert_eq!(
        admitted(&aliased),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_failed_receive_streams_no_bytes() {
    let mut s = Script::new();
    s.fill(K, A, BODY);
    s.lookup(K, MISSING, None);
    let mut op = None;
    let refused_with_bytes = edited(&s.finish(), |rows| {
        rows.retain(|r| r.kind != ActionKind::WriteCompleted);
        let receive = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Receive)
            .unwrap();
        receive.outcome = Some(REFUSED);
        op = Some(receive.op);
    });
    assert_eq!(
        admitted(&refused_with_bytes),
        Err(Inconclusive::Malformed {
            op: op.unwrap(),
            field: super::row::Field::Payload,
        })
    );
}

#[test]
fn one_write_completion_row_per_operation() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let twice = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let done = rows
            .iter()
            .position(|r| r.kind == ActionKind::WriteCompleted)
            .unwrap();
        let mut again = rows[done].clone();
        again.responded = Some(Ordinal(rows[done].responded.unwrap().0 + 1));
        rows.insert(done + 1, again);
    });
    assert_eq!(
        admitted(&twice),
        Err(Inconclusive::Malformed {
            op,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn one_successful_key_release_per_lookup() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.release_key(read, K);
    s.release_key(read, K);
    assert_eq!(
        admitted(&s.finish()),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Response,
        })
    );
}

#[test]
fn one_close_row_per_operation() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let first = s.close_cache(ACK);
    let second = s.close_cache(ACK);
    let shared = edited(&s.finish(), |rows| {
        rows.iter_mut().find(|r| r.op == second).unwrap().op = first;
    });
    assert_eq!(
        admitted(&shared),
        Err(Inconclusive::Malformed {
            op: first,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_key_release_names_a_lookup_that_acquired() {
    let mut s = Script::new();
    let miss = s.lookup(K, MISSING, None);
    s.release_key(miss, K);
    assert_eq!(
        admitted(&s.finish()),
        Err(Inconclusive::Malformed {
            op: miss,
            field: super::row::Field::Response,
        })
    );
}

#[test]
fn a_delivery_names_a_lookup_that_acquired_its_lease() {
    let without_release = |outcome: Outcome, label: Option<Label>, keep_lookup: bool| {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        let read = s.lookup(K, outcome, label);
        s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
        s.lookup(K, HIT, Some(A));
        let history = edited(&s.finish(), |rows| {
            rows.retain(|r| {
                r.kind != ActionKind::Release
                    && (keep_lookup || r.op != read || r.kind != ActionKind::Lookup)
            });
        });
        (read, history)
    };
    for (outcome, label, keep_lookup) in [(HIT, Some(A), false), (MISSING, None, true)] {
        let (read, history) = without_release(outcome, label, keep_lookup);
        assert_eq!(
            admitted(&history),
            Err(Inconclusive::Malformed {
                op: read,
                field: super::row::Field::Invocation,
            }),
            "{outcome:?} keep_lookup={keep_lookup}"
        );
    }
}

#[test]
fn a_delivery_is_invoked_after_its_lookup_responded() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let early = edited(&s.finish(), |rows| {
        let lookup = rows
            .iter()
            .position(|r| r.kind == ActionKind::Lookup)
            .unwrap();
        let deliver = rows
            .iter()
            .position(|r| r.kind == ActionKind::Deliver)
            .unwrap();
        let responded = rows[lookup].responded;
        rows[lookup].responded = rows[deliver].invoked;
        rows[deliver].invoked = responded;
    });
    assert_eq!(
        admitted(&early),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_delivery_after_an_effective_release_is_malformed() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.release_key(read, K);
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let after = edited(&s.finish(), |rows| {
        rows.pop();
    });
    assert_eq!(
        admitted(&after),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn holder_accounting_counts_live_evidence_only() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for _ in 0..3 {
        let read = s.lookup(K, HIT, Some(A));
        s.release_key(read, K);
    }
    let abstractly_released = edited(&s.finish(), |rows| {
        for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Release) {
            row.evidence = Evidence::Abstract(Hypothesis("released"));
        }
    });
    let verdict = admitted(&abstractly_released);
    assert!(
        matches!(
            verdict,
            Err(Inconclusive::DomainBound {
                dimension: "holders",
                observed: 3,
                ..
            })
        ),
        "{verdict:?}"
    );
}

#[test]
fn one_delivery_consumes_a_lookups_lease() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let twice = edited(&s.finish(), |rows| {
        let mut release = rows.pop().unwrap();
        let mut again = rows
            .iter()
            .find(|r| r.kind == ActionKind::Deliver)
            .unwrap()
            .clone();
        let last = release.responded.unwrap().0;
        again.invoked = Some(Ordinal(last + 1));
        again.responded = Some(Ordinal(last + 2));
        again.custody_end = Some(Ordinal(last + 3));
        release.responded = Some(Ordinal(last + 4));
        rows.push(again);
        rows.push(release);
    });
    assert_eq!(
        admitted(&twice),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_key_release_without_a_lookup_is_malformed() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.release_key(read, K);
    s.lookup(K, HIT, Some(A));
    let orphan = edited(&s.finish(), |rows| {
        rows.retain(|r| !(r.kind == ActionKind::Lookup && r.op == read));
    });
    assert_eq!(
        admitted(&orphan),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Response,
        })
    );
}

#[test]
fn a_delivery_names_the_lease_its_lookup_acquired() {
    let delivered = |key: KeyId, label: Label| {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        s.publish(J, C, BODY);
        let read = s.lookup(K, HIT, Some(A));
        s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
        let history = edited(&s.finish(), |rows| {
            rows.pop();
            let delivery = rows
                .iter_mut()
                .find(|r| r.kind == ActionKind::Deliver)
                .unwrap();
            delivery.subject = Some(Subject::Key(key));
            delivery.label = Some(label);
        });
        (read, admitted(&history))
    };
    let (read, wrong_label) = delivered(K, B);
    assert_eq!(
        wrong_label,
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Label,
        })
    );
    let (read, wrong_key) = delivered(J, A);
    assert_eq!(
        wrong_key,
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Key,
        })
    );
}

#[test]
fn a_retried_read_waits_for_the_refused_read_to_return_the_lease() {
    for outcome in [REFUSED, Outcome::Complete] {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        let read = s.lookup(K, HIT, Some(A));
        s.deliver(read, K, A, BODY, REFUSED, Vec::new());
        let payload = if outcome == Outcome::Complete {
            bytes(K, A, BODY)
        } else {
            Vec::new()
        };
        s.deliver(read, K, A, BODY, outcome, payload);
        let overlapping = edited(&s.finish(), |rows| {
            rows.retain(|r| r.kind != ActionKind::Release);
            for row in rows.iter_mut() {
                for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                    .into_iter()
                    .flatten()
                {
                    ordinal.0 *= 2;
                }
            }
            let first = rows
                .iter()
                .position(|r| r.kind == ActionKind::Deliver)
                .unwrap();
            let inside = Ordinal(rows[first].invoked.unwrap().0 + 1);
            rows[first + 1].invoked = Some(inside);
        });
        assert_eq!(
            admitted(&overlapping),
            Err(Inconclusive::Malformed {
                op: read,
                field: super::row::Field::Invocation,
            }),
            "{outcome:?}"
        );
    }
}

#[test]
fn a_fill_flow_stays_within_one_evidence_class() {
    let mut s = Script::new();
    let op = s.fill(K, A, BODY);
    s.lookup(K, MISSING, None);
    let hypothetical_fill = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Fill && r.op == op)
            .unwrap()
            .evidence = Evidence::Abstract(Hypothesis("filled"));
    });
    assert!(matches!(
        admitted(&hypothetical_fill),
        Err(Inconclusive::Malformed { op: found, .. }) if found == op
    ));
}

#[test]
fn a_refused_read_after_the_lease_was_consumed_is_malformed() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    s.deliver(read, K, A, BODY, REFUSED, Vec::new());
    let retried = edited(&s.finish(), |rows| {
        rows.retain(|r| r.kind != ActionKind::Release);
    });
    assert_eq!(
        admitted(&retried),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_refused_read_after_an_effective_release_is_malformed() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.release_key(read, K);
    s.deliver(read, K, A, BODY, REFUSED, Vec::new());
    let after = edited(&s.finish(), |rows| {
        rows.pop();
    });
    assert_eq!(
        admitted(&after),
        Err(Inconclusive::Malformed {
            op: read,
            field: super::row::Field::Invocation,
        })
    );
}
