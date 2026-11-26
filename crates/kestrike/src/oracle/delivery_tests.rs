//! Byte delivery goldens and rejection witnesses: the content catalog,
//! delivered lengths, identity and sessions, verified prefixes, and colliding
//! candidates.

use super::action::ActionKind;
use super::bounds::{MAX_CONTENT_BYTES, SearchBudget};
use super::checker::{check, check_within};
use super::content::{Geometry, expected_bytes};
use super::continuation::{Continuation, LIMITS};
use super::golden::*;
use super::history::History;
use super::ids::{Incarnation, KeyId, Label, Ordinal, SessionId};
use super::obligation::Obligation;
use super::outcome::{Failure, NoInformation, Outcome, VisibilityCause};
use super::row::Row;
use super::script::{INCARNATION, META, SESSION, Script};
use super::verdict::{Inconclusive, Verdict};

#[test]
fn golden_1_old_read_finishes_and_a_fresh_lookup_misses() {
    let verdict = check(&held_read_across_invalidation(MISSING, None));
    assert!(
        verdict.satisfies(&[Obligation::History, Obligation::Bytes]),
        "{verdict:?}"
    );
}

#[test]
fn golden_5_a_colliding_candidate_exposes_zero_bytes() {
    let mismatch = colliding_candidate(Outcome::Damaged(Failure::HeaderMismatch), Vec::new());
    let verdict = check(&mismatch);
    assert!(
        verdict.satisfies(&[Obligation::History, Obligation::Bytes, Obligation::Contain]),
        "{verdict:?}"
    );
    let leaked = colliding_candidate(Outcome::Complete, bytes(J, C, BODY));
    assert_eq!(
        assert_violates(&leaked, Obligation::Bytes),
        "a colliding candidate delivered another key's bytes"
    );
}

#[test]
fn golden_7_a_damaged_later_chunk_keeps_the_exact_prefix_and_a_typed_failure() {
    let damaged = Outcome::Damaged(Failure::ChunkMismatch { index: 2 });
    let prefix = Geometry::GOLDEN.verified_prefix(2, META as usize + LONG as usize);
    assert_eq!(prefix, 112);
    let verdict = check(&damaged_later_chunk(damaged, prefix));
    assert!(
        verdict.satisfies(&[Obligation::Bytes, Obligation::Contain]),
        "{verdict:?}"
    );
    assert_violates(
        &damaged_later_chunk(Outcome::Complete, prefix),
        Obligation::Bytes,
    );
    assert_eq!(
        assert_violates(
            &damaged_later_chunk(damaged, prefix + 18),
            Obligation::Contain
        ),
        "bytes from a failed chunk or a later one were exposed"
    );
}

/// A geometry judges bytes only with a positive chunk no shorter than its
/// header: a zero chunk or a longer header is Inconclusive before any
/// window arithmetic, a header equal to its chunk keeps a judgment, and an
/// accepted geometry's window arithmetic saturates at the record.
#[test]
fn an_undefined_geometry_is_inconclusive_before_its_window_arithmetic() {
    let damaged = Outcome::Damaged(Failure::ChunkMismatch { index: 2 });
    let total = META as usize + LONG as usize;
    for (chunk, header) in [(0, 0), (0, 16), (8, 16), (16, 17)] {
        assert_eq!(
            check_within(
                &damaged_later_chunk(damaged, 0),
                Geometry { chunk, header },
                &mut SearchBudget::per_key(),
            ),
            Verdict::Inconclusive(Inconclusive::Geometry { chunk, header }),
            "chunk {chunk}, header {header}"
        );
    }
    // Chunk and header both 16: the first window holds no payload and the
    // second holds bytes 0..16, so a failed third chunk keeps 16 bytes.
    let even = Geometry {
        chunk: 16,
        header: 16,
    };
    let verdict = check_within(
        &damaged_later_chunk(damaged, 16),
        even,
        &mut SearchBudget::per_key(),
    );
    assert!(
        verdict.satisfies(&[Obligation::Bytes, Obligation::Contain]),
        "{verdict:?}"
    );
    assert_eq!(
        check_within(
            &damaged_later_chunk(damaged, 32),
            even,
            &mut SearchBudget::per_key(),
        )
        .violated(),
        Some((
            Obligation::Contain,
            "bytes from a failed chunk or a later one were exposed"
        ))
    );
    let wide = Geometry {
        chunk: usize::MAX / 2,
        header: 2,
    };
    assert_eq!(wide.verified_prefix(u32::MAX, total), total);
    assert!(!wide.is_verified_boundary(usize::MAX - 1, usize::MAX));
    // With `header == chunk == usize::MAX - 1`, the first window holds no
    // payload and the second ends at payload byte `usize::MAX - 1`: a
    // verified boundary short of a `usize::MAX`-byte record, even though the
    // boundary plus the header exceeds `usize::MAX`.
    let edge = Geometry {
        chunk: usize::MAX - 1,
        header: usize::MAX - 1,
    };
    assert!(edge.is_verified_boundary(usize::MAX - 1, usize::MAX));
    // With `header == chunk == usize::MAX`, payload begins in the second
    // window, which covers the whole record, so the verified prefix before
    // chunk 2 is the whole record and an empty read reporting chunk 2 fails
    // containment.
    let full = Geometry {
        chunk: usize::MAX,
        header: usize::MAX,
    };
    assert_eq!(full.verified_prefix(1, total), 0);
    assert_eq!(full.verified_prefix(2, total), total);
    assert_eq!(
        check_within(
            &damaged_later_chunk(damaged, 0),
            full,
            &mut SearchBudget::per_key(),
        )
        .violated(),
        Some((
            Obligation::Contain,
            "bytes from a failed chunk or a later one were exposed"
        ))
    );
    let undefined = Geometry {
        chunk: 8,
        header: 16,
    };
    assert_eq!(
        Continuation::new(LIMITS, undefined).finish(),
        Verdict::Inconclusive(Inconclusive::Geometry {
            chunk: 8,
            header: 16
        }),
        "a continuation judges no row under an undefined geometry"
    );
}

#[test]
fn a_candidate_may_answer_with_a_wire_missing_or_no_information() {
    let mut s = Script::new();
    s.publish(J, C, BODY);
    s.lookup(K, MISSING, None);
    let verdict = check(&s.finish());
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    let refused = colliding_candidate(Outcome::NoInformation(NoInformation::Cancelled), Vec::new());
    assert!(check(&refused).satisfies(&[Obligation::Contain]));
    let leaked = colliding_candidate(
        Outcome::Damaged(Failure::HeaderMismatch),
        bytes(J, C, BODY)[..4].to_vec(),
    );
    assert_violates(&leaked, Obligation::Bytes);
}

#[test]
fn a_colliding_candidate_may_fail_before_its_header_with_zero_bytes() {
    for failure in [
        Failure::DeviceError,
        Failure::Short,
        Failure::Quiesced,
        Failure::Lost,
    ] {
        let failed = colliding_candidate(Outcome::Damaged(failure), Vec::new());
        let verdict = check(&failed);
        assert!(
            verdict.satisfies(&[Obligation::History, Obligation::Contain]),
            "{failure:?} {verdict:?}"
        );
        let leaked =
            colliding_candidate(Outcome::Damaged(failure), bytes(J, C, BODY)[..4].to_vec());
        assert_eq!(
            assert_violates(&leaked, Obligation::Bytes),
            "a colliding candidate delivered another key's bytes",
            "{failure:?}"
        );
    }
    for index in [0, 1] {
        let verified = colliding_candidate(
            Outcome::Damaged(Failure::ChunkMismatch { index }),
            Vec::new(),
        );
        assert_eq!(
            assert_violates(&verified, Obligation::Bytes),
            "a colliding candidate passed header verification",
            "{index}"
        );
    }
}

#[test]
fn delivery_rules_each_reject_their_wrong_history() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY + 1, Outcome::Complete, bytes(K, A, BODY));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::Bytes),
        "delivered lengths differ from the label's content"
    );

    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    let mut wrong = bytes(K, A, BODY);
    wrong[0] ^= 1;
    wrong.truncate(4);
    s.deliver(
        read,
        K,
        A,
        BODY,
        Outcome::Damaged(Failure::DeviceError),
        wrong,
    );
    assert_violates(&s.finish(), Obligation::Contain);
}

fn delivered(edit: impl FnOnce(&mut Vec<Row>)) -> History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    edited(&s.finish(), edit)
}

#[test]
fn a_delivery_names_the_identity_its_fill_declared() {
    let other_session = delivered(|rows| {
        let delivery = rows.iter_mut().find(|r| r.kind == ActionKind::Deliver);
        delivery.unwrap().session = Some(SessionId(SESSION.0 + 1));
    });
    assert_eq!(
        assert_violates(&other_session, Obligation::Bytes),
        "delivered identity differs from the acquired content"
    );
    let other_incarnation = delivered(|rows| {
        let delivery = rows.iter_mut().find(|r| r.kind == ActionKind::Deliver);
        delivery.unwrap().incarnation = Some(Incarnation(INCARNATION.0 + 1));
    });
    assert_eq!(
        assert_violates(&other_incarnation, Obligation::Bytes),
        "delivered identity differs from the acquired content"
    );
}

#[test]
fn one_fill_row_per_operation() {
    let mut op = None;
    let twice = delivered(|rows| {
        let mut again = rows
            .iter()
            .find(|r| r.kind == ActionKind::Fill)
            .unwrap()
            .clone();
        again.body_len = Some(BODY + 1);
        again.invoked = Some(Ordinal(100));
        again.responded = Some(Ordinal(101));
        op = Some(again.op);
        rows.push(again);
    });
    assert_eq!(
        check(&twice),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: op.unwrap(),
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn content_beyond_the_declared_bound_is_inconclusive() {
    let huge = delivered(|rows| {
        for row in rows
            .iter_mut()
            .filter(|r| matches!(r.kind, ActionKind::Fill | ActionKind::Deliver))
        {
            row.body_len = Some(u64::MAX);
        }
    });
    assert!(matches!(
        check(&huge),
        Verdict::Inconclusive(Inconclusive::DomainBound {
            dimension: "content bytes",
            limit: MAX_CONTENT_BYTES,
            ..
        })
    ));
}

#[test]
fn a_failed_read_of_an_empty_record_may_deliver_nothing() {
    let mut s = Script::new();
    s.publish_sized(K, A, 0, 0);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver_sized(
        read,
        K,
        A,
        (0, 0),
        Outcome::NoInformation(NoInformation::Cancelled),
        Vec::new(),
    );
    assert!(check(&s.finish()).satisfies(&[Obligation::Contain]));
}

#[test]
fn a_failed_delivery_ends_at_a_verified_chunk_boundary() {
    let first_window = Geometry::GOLDEN.chunk - Geometry::GOLDEN.header;
    let total = META as usize + LONG as usize;
    for (prefix, holds) in [
        (0, true),
        (first_window, true),
        (first_window + Geometry::GOLDEN.chunk, true),
        (total, false),
        (1, false),
        (first_window - 1, false),
        (first_window + 1, false),
    ] {
        let mut s = Script::new();
        s.publish(K, A, LONG);
        let read = s.lookup(K, HIT, Some(A));
        let mut payload = bytes(K, A, LONG);
        payload.truncate(prefix);
        s.deliver(
            read,
            K,
            A,
            LONG,
            Outcome::Damaged(Failure::DeviceError),
            payload,
        );
        let verdict = check(&s.finish());
        if holds {
            assert!(
                verdict.satisfies(&[Obligation::Contain]),
                "{prefix}: {verdict:?}"
            );
        } else {
            assert_eq!(
                rule(&verdict),
                Some((
                    Obligation::Contain,
                    "a failed read exposed bytes past a verified chunk boundary",
                )),
                "{prefix}"
            );
        }
    }
}

#[test]
fn a_failed_read_returns_less_than_the_record() {
    let mut s = Script::new();
    s.publish(K, A, LONG);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(
        read,
        K,
        A,
        LONG,
        Outcome::Damaged(Failure::Short),
        bytes(K, A, LONG),
    );
    assert_eq!(
        assert_violates(&s.finish(), Obligation::Contain),
        "a failed read exposed bytes past a verified chunk boundary"
    );
}

#[test]
fn a_refused_key_release_keeps_the_lease() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let first = s.lookup(K, HIT, Some(A));
    s.release_key(first, K);
    for _ in 0..2 {
        s.lookup(K, HIT, Some(A));
    }
    let refused = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Release)
            .unwrap()
            .outcome = Some(REFUSED);
    });
    let verdict = check(&refused);
    assert!(
        matches!(
            verdict,
            Verdict::Inconclusive(Inconclusive::DomainBound {
                dimension: "holders",
                observed: 3,
                ..
            })
        ),
        "{verdict:?}"
    );
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.release_key(read, K);
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let refused = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Release)
            .unwrap()
            .outcome = Some(REFUSED);
    });
    assert!(check(&refused).satisfies(&[Obligation::Bytes]));
}

#[test]
fn a_refused_read_returns_its_lease_whole() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let first = s.lookup(K, HIT, Some(A));
    s.deliver(first, K, A, BODY, REFUSED, Vec::new());
    for _ in 0..2 {
        s.lookup(K, HIT, Some(A));
    }
    let unreleased = edited(&s.finish(), |rows| {
        rows.retain(|r| r.kind != ActionKind::Release);
    });
    let verdict = check(&unreleased);
    assert!(
        matches!(
            verdict,
            Verdict::Inconclusive(Inconclusive::DomainBound {
                dimension: "holders",
                observed: 3,
                ..
            })
        ),
        "{verdict:?}"
    );
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, REFUSED, Vec::new());
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let retried = edited(&s.finish(), |rows| {
        let first = rows
            .iter()
            .position(|r| r.kind == ActionKind::Release)
            .unwrap();
        rows.remove(first);
    });
    let verdict = check(&retried);
    assert!(verdict.satisfies(&[Obligation::Bytes]), "{verdict:?}");
}

#[test]
fn received_bytes_are_the_generated_content() {
    let mut op = None;
    let corrupted = delivered(|rows| {
        let receive = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Receive)
            .unwrap();
        receive.payload.as_mut().unwrap()[0] ^= 1;
        op = Some(receive.op);
    });
    assert_eq!(
        check(&corrupted),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: op.unwrap(),
            field: super::row::Field::Payload,
        })
    );
}

#[test]
fn a_refused_read_exposes_nothing() {
    let mut s = Script::new();
    s.publish(K, A, LONG);
    let read = s.lookup(K, HIT, Some(A));
    let first_window = Geometry::GOLDEN.chunk - Geometry::GOLDEN.header;
    s.deliver(
        read,
        K,
        A,
        LONG,
        REFUSED,
        bytes(K, A, LONG)[..first_window].to_vec(),
    );
    assert_eq!(
        assert_violates(&s.finish(), Obligation::Contain),
        "a refused read exposed bytes"
    );
}

#[test]
fn an_eviction_may_commit_after_a_lease_acquired_since_its_selection() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let held = s.lookup(K, HIT, Some(A));
    s.evict(K, A);
    s.lookup(K, MISSING, None);
    s.deliver(held, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let verdict = check(&s.finish());
    assert!(
        verdict.satisfies(&[Obligation::History, Obligation::Bytes]),
        "{verdict:?}"
    );
}

#[test]
fn a_refused_or_unfinished_fill_declares_no_content() {
    let mut s = Script::new();
    s.fill(K, A, BODY);
    s.lookup(K, MISSING, None);
    let refused = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Fill)
            .unwrap()
            .outcome = Some(REFUSED);
        rows.retain(|r| !matches!(r.kind, ActionKind::Receive | ActionKind::WriteCompleted));
    });
    assert!(check(&refused).satisfies(&[Obligation::History]));
    let mut s = Script::new();
    s.fill(K, A, BODY);
    s.lookup(K, MISSING, None);
    let unfinished = edited(&s.finish(), |rows| {
        rows.retain(|r| r.kind != ActionKind::WriteCompleted);
        let receive = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Receive)
            .unwrap();
        receive.payload.as_mut().unwrap().truncate(4);
    });
    assert!(check(&unfinished).satisfies(&[Obligation::History]));
}

#[test]
fn a_refused_receive_delivers_no_bytes() {
    let refused = delivered(|rows| {
        let receive = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Receive)
            .unwrap();
        receive.outcome = Some(REFUSED);
    });
    assert!(matches!(
        check(&refused),
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: super::row::Field::Payload,
            ..
        })
    ));
}

#[test]
fn a_refused_fill_declares_no_catalog_entry() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    let again = s.fill(K, A, BODY + 1);
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let refused = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Fill && r.op == again)
            .unwrap()
            .outcome = Some(REFUSED);
        rows.retain(|r| r.op != again || r.kind == ActionKind::Fill);
    });
    let verdict = check(&refused);
    assert!(verdict.satisfies(&[Obligation::Bytes]), "{verdict:?}");
}

#[test]
fn a_colliding_delivery_names_its_owners_content() {
    let mut s = Script::new();
    s.publish(J, C, BODY);
    let candidate = s.candidate_lookup(K, J, HIT, Some(C));
    s.deliver(
        candidate,
        K,
        C,
        BODY + 1,
        Outcome::Damaged(Failure::HeaderMismatch),
        Vec::new(),
    );
    assert_eq!(
        assert_violates(&s.finish(), Obligation::Bytes),
        "delivered lengths differ from the label's content"
    );
}

#[test]
fn a_delivery_after_a_session_change_ends_in_a_header_mismatch() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.session_change(SessionId(SESSION.0 + 1));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::Bytes),
        "a delivery of content from a superseded session"
    );
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.session_change(SessionId(SESSION.0 + 1));
    s.deliver(
        read,
        K,
        A,
        BODY,
        Outcome::Damaged(Failure::HeaderMismatch),
        Vec::new(),
    );
    assert!(check(&s.finish()).satisfies(&[Obligation::Contain]));
}

#[test]
fn a_read_may_fail_before_its_header_after_a_session_change() {
    for outcome in [
        REFUSED,
        Outcome::NoInformation(NoInformation::Cancelled),
        Outcome::Damaged(Failure::DeviceError),
    ] {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        let read = s.lookup(K, HIT, Some(A));
        s.session_change(SessionId(SESSION.0 + 1));
        s.deliver(read, K, A, BODY, outcome, Vec::new());
        let verdict = check(&s.finish());
        assert!(
            matches!(verdict, Verdict::Pass(_)),
            "{outcome:?}: {verdict:?}"
        );
    }
}

#[test]
fn an_unfinished_fill_receives_a_prefix_of_its_content() {
    let mut s = Script::new();
    s.fill(K, A, BODY);
    s.lookup(K, MISSING, None);
    let base = s.finish();
    let corrupt = edited(&base, |rows| {
        rows.retain(|r| r.kind != ActionKind::WriteCompleted);
        let receive = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Receive)
            .unwrap();
        receive.payload.as_mut().unwrap()[0] ^= 1;
    });
    assert!(matches!(
        check(&corrupt),
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: super::row::Field::Payload,
            ..
        })
    ));
    let overlong = edited(&base, |rows| {
        rows.retain(|r| r.kind != ActionKind::WriteCompleted);
        let receive = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Receive)
            .unwrap();
        receive.payload.as_mut().unwrap().push(0);
    });
    assert!(matches!(
        check(&overlong),
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: super::row::Field::Payload,
            ..
        })
    ));
}

#[test]
fn a_fill_declares_the_current_session() {
    let mut s = Script::new();
    s.session_change(SessionId(SESSION.0 + 1));
    let op = s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    assert_eq!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op,
            field: super::row::Field::Session,
        })
    );
}

#[test]
fn a_refused_read_activates_no_byte_obligation() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, REFUSED, Vec::new());
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
    assert!(!verdict.satisfies(&[Obligation::Bytes]));
    assert!(!verdict.satisfies(&[Obligation::Contain]));
}

#[test]
fn a_refused_collision_read_activates_no_byte_obligation() {
    let mut s = Script::new();
    s.publish(J, C, BODY);
    let candidate = s.candidate_lookup(K, J, HIT, Some(C));
    s.deliver(candidate, K, C, BODY, REFUSED, Vec::new());
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
    assert!(!verdict.satisfies(&[Obligation::Bytes]));
    assert!(!verdict.satisfies(&[Obligation::Contain]));
}

#[test]
fn a_refused_session_change_changes_nothing() {
    let mut s = Script::new();
    s.session_change(SessionId(SESSION.0 + 1));
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let refused = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::SessionChange)
            .unwrap()
            .outcome = Some(Outcome::NoInformation(NoInformation::Cancelled));
    });
    let verdict = check(&refused);
    assert!(verdict.satisfies(&[Obligation::Bytes]), "{verdict:?}");
}

#[test]
fn a_candidate_delivery_counts_toward_its_owner_keys_labels() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.publish_replacing(K, B, BODY);
    s.publish(J, C, BODY);
    s.ended(K, B, VisibilityCause::CollisionCollateral);
    let candidate = s.candidate_lookup(K, J, HIT, Some(C));
    s.deliver(
        candidate,
        K,
        C,
        BODY,
        Outcome::Damaged(Failure::HeaderMismatch),
        Vec::new(),
    );
    let verdict = check(&s.finish());
    assert!(verdict.satisfies(&[Obligation::Contain]), "{verdict:?}");
}

#[test]
fn a_retried_read_after_a_release_during_a_refused_read_keeps_its_lease() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, REFUSED, Vec::new());
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let retried = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let refused = rows
            .iter()
            .find(|r| r.kind == ActionKind::Deliver && r.refused_read())
            .unwrap();
        let during = Ordinal(refused.invoked.unwrap().0 + 1);
        let release = rows
            .iter()
            .position(|r| r.kind == ActionKind::Release)
            .unwrap();
        rows[release].responded = Some(during);
        let last = rows.len() - 1;
        rows.remove(last);
    });
    let verdict = check(&retried);
    assert!(verdict.satisfies(&[Obligation::Bytes]), "{verdict:?}");
}

#[test]
fn received_fragments_are_judged_in_place_against_the_declared_content() {
    let split = |second_len: usize| {
        let mut s = Script::new();
        s.fill(K, A, BODY);
        s.lookup(K, MISSING, None);
        edited(&s.finish(), |rows| {
            rows.retain(|r| r.kind != ActionKind::WriteCompleted);
            let at = rows
                .iter()
                .position(|r| r.kind == ActionKind::Receive)
                .unwrap();
            let mut second = rows[at].clone();
            let payload = rows[at].payload.as_mut().unwrap();
            let half = payload.len() / 2;
            let tail = payload.split_off(half);
            let tick = rows[at].responded.unwrap().0;
            second.payload = Some(tail.iter().cycle().take(second_len).copied().collect());
            second.invoked = Some(Ordinal(tick + 1));
            second.responded = Some(Ordinal(tick + 2));
            for row in rows.iter_mut().skip(at + 1) {
                row.invoked = row.invoked.map(|o| Ordinal(o.0 + 2));
                row.responded = row.responded.map(|o| Ordinal(o.0 + 2));
            }
            rows.insert(at + 1, second);
        })
    };
    let total = META as usize + BODY as usize;
    let verdict = check(&split(total - total / 2));
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    assert!(matches!(
        check(&split(total)),
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: super::row::Field::Payload,
            ..
        })
    ));
}

#[test]
fn fills_keep_the_first_declared_session_until_a_session_change() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let second = s.publish(K, B, BODY);
    s.lookup(K, HIT, Some(B));
    let drifted = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Fill && r.op == second)
            .unwrap()
            .session = Some(SessionId(SESSION.0 + 1));
    });
    assert_eq!(
        check(&drifted),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: second,
            field: super::row::Field::Session,
        })
    );
}

#[test]
fn a_session_that_returns_still_supersedes_content_written_before_it_left() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.session_change(SessionId(SESSION.0 + 1));
    s.session_change(SESSION);
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::Bytes),
        "a delivery of content from a superseded session"
    );
}

#[test]
fn a_label_declares_one_content_across_fill_attempts() {
    let mut s = Script::new();
    let abandoned = s.begin_publish(K, A, BODY, None);
    s.close(abandoned, Some(REFUSED));
    let second = s.publish(K, A, BODY + 1);
    s.lookup(K, HIT, Some(A));
    assert_eq!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: second,
            field: super::row::Field::Label,
        })
    );
}

#[test]
fn overlapping_initial_fills_declare_one_session() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let second = s.publish(K, B, BODY);
    s.lookup(K, HIT, Some(B));
    let overlapping = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let first_invoked = rows
            .iter()
            .find(|r| r.kind == ActionKind::Fill)
            .unwrap()
            .invoked
            .unwrap();
        let later = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::Fill && r.op == second)
            .unwrap();
        later.invoked = Some(Ordinal(first_invoked.0 + 1));
        later.session = Some(SessionId(SESSION.0 + 1));
    });
    assert_eq!(
        check(&overlapping),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: second,
            field: super::row::Field::Session,
        })
    );
}

#[test]
fn a_session_change_during_a_fill_supersedes_its_content() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.session_change(SessionId(SESSION.0 + 1));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let overlapping = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let fill_invoked = rows
            .iter()
            .find(|r| r.kind == ActionKind::Fill)
            .unwrap()
            .invoked
            .unwrap();
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::SessionChange)
            .unwrap()
            .responded = Some(Ordinal(fill_invoked.0 + 1));
    });
    assert_eq!(
        assert_violates(&overlapping, Obligation::Bytes),
        "a delivery of content from a superseded session"
    );
}

#[test]
fn the_first_fill_anchors_the_session_fence_whatever_the_row_order() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.session_change(SessionId(SESSION.0 + 1));
    s.session_change(SESSION);
    let again = s.fill(K, A, BODY);
    let read = s.lookup(K, HIT, Some(A));
    s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    let reordered = edited(&s.finish(), |rows| {
        let later: Vec<Row> = rows.iter().filter(|r| r.op == again).cloned().collect();
        rows.retain(|r| r.op != again);
        rows.splice(0..0, later);
    });
    assert_eq!(
        assert_violates(&reordered, Obligation::Bytes),
        "a delivery of content from a superseded session"
    );
}

/// Every (key, label) pair over the whole label domain seeds its own
/// generator state, so no pair's expected stream is another pair's.
#[test]
fn distinct_key_label_pairs_seed_distinct_streams() {
    let len = Geometry::GOLDEN.chunk;
    let pairs = [
        (KeyId(0), Label(0)),
        (KeyId(1), Label(1 << 32)),
        (KeyId(0), Label(1 << 32)),
        (KeyId(1), Label(0)),
        (KeyId(0), Label(u64::MAX)),
        (KeyId(1), Label(u64::MAX)),
    ];
    for (i, &(key, label)) in pairs.iter().enumerate() {
        let bytes = expected_bytes(key, label, len);
        assert!(
            bytes.iter().any(|&b| b != 0),
            "{key:?} {label:?} streams bytes"
        );
        for &(other_key, other_label) in &pairs[i + 1..] {
            assert_ne!(
                bytes,
                expected_bytes(other_key, other_label, len),
                "{key:?} {label:?} aliases {other_key:?} {other_label:?}"
            );
        }
    }
}
