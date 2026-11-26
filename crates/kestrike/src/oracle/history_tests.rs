//! Per-key history goldens and rejection witnesses: legal orders, tenure
//! order, coverage, recorded removals and restores, client high-waters,
//! clocks and deadlines, fill and lease lifecycles, and the domain bounds.

use super::action::ActionKind;
use super::attempt::{PutOutcome, Receipt, Serial};
use super::bounds::{SEARCH_BOUND, SearchBudget};
use super::checker::{check, check_within};
use super::content::Geometry;
use super::coverage::Cover;
use super::evidence::Evidence;
use super::golden::*;
use super::history::History;
use super::ids::{
    ClockSample, KeyId, Label, OpId, Ordinal, ResourceId, ResourceKind, Subject, Tenure,
};
use super::obligation::{HANDOFF_ALIASES, Obligation};
use super::outcome::{Failure, NoInformation, Outcome, VisibilityCause};
use super::row::{Field, Row};
use super::rules::{Rule, without};
use super::script::Script;
use super::tenure::Place;
use super::tenure_golden::*;
use super::verdict::{Activations, Inconclusive, Verdict};

#[test]
fn golden_2_stale_version_control_fails_history() {
    let original = held_read_across_invalidation(MISSING, None);
    assert!(check(&original).satisfies(&[Obligation::History]));
    let control = held_read_across_invalidation(HIT, Some(A));
    let text = assert_violates(&control, Obligation::History);
    assert_eq!(
        text,
        "a hit of a version an acknowledged invalidation covered"
    );
}

#[test]
fn golden_3_replacement_overlapping_a_lookup_allows_old_new_missing_or_contended() {
    for (outcome, label) in [
        (HIT, Some(A)),
        (HIT, Some(B)),
        (MISSING, None),
        (CONTENDED, None),
    ] {
        let verdict = check(&replacement_overlapping_lookup(outcome, label));
        assert!(
            verdict.satisfies(&[Obligation::History]),
            "{label:?} {verdict:?}"
        );
    }
}

#[test]
fn golden_4_refused_invalidation_and_replacement_keep_the_incumbent() {
    assert!(check(&refused_effects(HIT, Some(A))).satisfies(&[Obligation::History]));
    assert!(check(&refused_effects(MISSING, None)).satisfies(&[Obligation::History]));
    assert_eq!(
        assert_violates(&refused_effects(HIT, Some(B)), Obligation::History),
        "a hit of a version no linearized fill published"
    );
    for refusal in [
        NoInformation::Contended,
        NoInformation::Closed,
        NoInformation::ClockUnavailable,
    ] {
        let refusal = Outcome::NoInformation(refusal);
        assert!(check(&refused_with(refusal, HIT, Some(A))).satisfies(&[Obligation::History]));
        assert!(check(&refused_with(refusal, MISSING, None)).satisfies(&[Obligation::History]));
    }
}

#[test]
fn golden_6_an_unpublished_fill_is_invisible_and_expiry_equality_is_expired() {
    let verdict = check(&unpublished_then_expiry(MISSING, Outcome::Expired));
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    assert_violates(
        &unpublished_then_expiry(HIT, Outcome::Expired),
        Obligation::History,
    );
    assert_eq!(
        assert_violates(&unpublished_then_expiry(MISSING, HIT), Obligation::History),
        "a hit at or past the deadline"
    );
}

#[test]
fn golden_10_a_pending_operation_explains_only_what_its_overlap_permits() {
    for (outcome, label) in [(HIT, Some(A)), (MISSING, None)] {
        let verdict = check(&pending_publication(true, outcome, label));
        assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    }
    for (outcome, label) in [(HIT, Some(A)), (MISSING, None)] {
        let verdict = check(&pending_publication(false, outcome, label));
        assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    }
    for pair in [
        ((HIT, Some(A)), (HIT, Some(A))),
        ((MISSING, None), (MISSING, None)),
        ((HIT, Some(A)), (MISSING, None)),
        ((MISSING, None), (HIT, Some(A))),
    ] {
        assert!(check(&timed_out_publication(pair.0, pair.1)).satisfies(&[Obligation::History]));
    }
    // A lookup answered before the pending publication was invoked has no
    // landing to explain its hit.
    let mut s = Script::new();
    s.fill(K, B, BODY);
    s.lookup(K, HIT, Some(A));
    let publish = s.begin_publish(K, A, BODY, None);
    s.close(
        publish,
        Some(Outcome::NoInformation(NoInformation::TimedOut)),
    );
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a hit of a version no linearized fill published"
    );
}

#[test]
fn a_search_past_its_bound_is_inconclusive_and_never_passes() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let missing = s.begin_lookup(K, ClockSample::Seconds(1));
    let lookups: Vec<_> = (0..13)
        .map(|_| s.begin_lookup(K, ClockSample::Seconds(1)))
        .collect();
    for lookup in lookups {
        s.end_lookup(lookup, CONTENDED, None);
    }
    s.end_lookup(missing, HIT, Some(B));
    let history = s.finish();
    assert_eq!(
        check(&history),
        Verdict::Inconclusive(Inconclusive::SearchBound {
            limit: SEARCH_BOUND
        })
    );
    let small = held_read_across_invalidation(MISSING, None);
    let mut zero = SearchBudget::new(0);
    assert_eq!(
        check_within(&small, Geometry::GOLDEN, &mut zero),
        Verdict::Inconclusive(Inconclusive::SearchBound { limit: 0 })
    );
}

#[test]
fn a_golden_with_zero_activations_of_its_declared_obligation_fails() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
    assert!(!verdict.satisfies(&[Obligation::History]));
    assert!(!verdict.satisfies(&[Obligation::Bytes]));
}

fn candidate_after(owner_history: impl FnOnce(&mut Script)) -> History {
    let mut s = Script::new();
    owner_history(&mut s);
    let candidate = s.candidate_lookup(K, J, HIT, Some(C));
    s.deliver(
        candidate,
        K,
        C,
        BODY,
        Outcome::Damaged(Failure::HeaderMismatch),
        Vec::new(),
    );
    s.finish()
}

#[test]
fn a_candidate_follows_its_owner_keys_eligible_mapping() {
    let refused = candidate_after(|s| {
        let publish = s.begin_publish(J, C, BODY, None);
        s.close(publish, Some(REFUSED));
    });
    let replaced = candidate_after(|s| {
        s.publish(J, C, BODY);
        let replace = s.begin_replace(J, Label(21), BODY);
        s.close(replace, Some(ACK));
    });
    let verdict = check(&replaced);
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
    let expired = candidate_after(|s| {
        let publish = s.begin_publish(J, C, BODY, Some(1));
        s.close(publish, Some(ACK));
        s.expire(J, C, 1);
    });
    let invalidated = candidate_after(|s| {
        s.publish(J, C, BODY);
        s.invalidate(J, ACK);
    });
    let ended = candidate_after(|s| {
        s.publish(J, C, BODY);
        s.ended(J, C, VisibilityCause::CollisionCollateral);
    });
    let unpublished = candidate_after(|_| {});
    for history in [refused, expired, invalidated, ended, unpublished] {
        assert_violates(&history, Obligation::History);
    }
    let mut s = Script::new();
    let lookup = s.begin_lookup(K, ClockSample::Seconds(1));
    let mut lookup = lookup;
    lookup.set_candidate(J);
    s.end_lookup(lookup, HIT, Some(C));
    s.publish(J, C, BODY);
    assert_violates(&s.finish(), Obligation::History);
}

fn ended_visible(
    cause: Option<VisibilityCause>,
    outcome: Outcome,
    label: Option<Label>,
) -> History {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(1));
    s.close(publish, Some(ACK));
    match cause {
        Some(VisibilityCause::Expiry) => {
            s.expire(K, A, 1);
            s.ended(K, A, VisibilityCause::Expiry);
        }
        Some(cause) => s.ended(K, A, cause),
        None => s.evict(K, A),
    }
    s.lookup(K, outcome, label);
    s.finish()
}

#[test]
fn every_visibility_end_removes_its_label_for_the_rest_of_the_tenure() {
    for cause in VisibilityCause::ALL.map(Some).into_iter().chain([None]) {
        let missing = check(&ended_visible(cause, MISSING, None));
        assert!(
            missing.satisfies(&[Obligation::History]),
            "{cause:?} {missing:?}"
        );
        assert_eq!(
            assert_violates(&ended_visible(cause, HIT, Some(A)), Obligation::History),
            "a hit after a recorded removal of its label in the same tenure",
            "{cause:?}"
        );
    }
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.ended(K, A, VisibilityCause::Eviction);
    s.publish(K, A, BODY);
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a publication label was published twice"
    );
}

fn ended_while_open(
    cause: Option<VisibilityCause>,
    acknowledged: bool,
    outcome: Outcome,
    label: Option<Label>,
) -> History {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(1));
    let end = |s: &mut Script| match cause {
        Some(VisibilityCause::Expiry) => {
            s.expire(K, A, 1);
            s.ended(K, A, VisibilityCause::Expiry);
        }
        Some(cause) => s.ended(K, A, cause),
        None => s.evict(K, A),
    };
    if acknowledged {
        end(&mut s);
        s.close(publish, Some(ACK));
    } else {
        s.close(
            publish,
            Some(Outcome::NoInformation(NoInformation::TimedOut)),
        );
        end(&mut s);
    }
    s.lookup(K, outcome, label);
    s.finish()
}

#[test]
fn a_visibility_end_retires_a_label_whose_publication_is_still_open() {
    for cause in VisibilityCause::ALL.map(Some).into_iter().chain([None]) {
        for acknowledged in [false, true] {
            let missing = check(&ended_while_open(cause, acknowledged, MISSING, None));
            assert!(
                missing.satisfies(&[Obligation::History]),
                "{cause:?} {acknowledged} {missing:?}"
            );
            let revived = ended_while_open(cause, acknowledged, HIT, Some(A));
            assert_eq!(
                assert_violates(&revived, Obligation::History),
                "a hit after a recorded removal of its label in the same tenure",
                "{cause:?} {acknowledged}"
            );
        }
    }
}

#[test]
fn an_acknowledged_invalidation_revokes_an_inflight_fill() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let fill = s.fill(K, B, BODY);
    s.invalidate(K, ACK);
    let replace = s.open(fill, ActionKind::Replace, K, Some(B));
    s.close(replace, Some(ACK));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a fill revoked by an invalidation or a tenure change published"
    );
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let fill = s.fill(K, B, BODY);
    s.invalidate(K, REFUSED);
    let replace = s.open(fill, ActionKind::Replace, K, Some(B));
    s.close(replace, Some(ACK));
    s.lookup(K, HIT, Some(B));
    assert!(check(&s.finish()).satisfies(&[Obligation::History]));
}

#[test]
fn memoization_keeps_a_wide_overlap_inside_the_bound() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let missing = s.begin_lookup(K, ClockSample::Seconds(1));
    let lookups: Vec<_> = (0..8)
        .map(|_| s.begin_lookup(K, ClockSample::Seconds(1)))
        .collect();
    for lookup in lookups {
        s.end_lookup(lookup, CONTENDED, None);
    }
    s.end_lookup(missing, HIT, Some(B));
    assert_violates(&s.finish(), Obligation::History);
}

#[test]
fn every_no_information_lookup_outcome_carries_nothing() {
    for member in NoInformation::ALL {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        s.invalidate(K, ACK);
        let lookup = s.begin_lookup(K, ClockSample::Seconds(1));
        if member == NoInformation::ClockUnavailable {
            s.clock_unavailable(lookup, A);
        } else {
            s.end_lookup(lookup, Outcome::NoInformation(member), None);
        }
        s.lookup(K, MISSING, None);
        let verdict = check(&s.finish());
        assert!(verdict.satisfies(&[Obligation::History]), "{member:?}");
    }
}

#[test]
fn clock_and_deadline_rules_each_reject_their_wrong_history() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let lookup = s.begin_lookup(K, ClockSample::Unavailable);
    let op = s.end_lookup(lookup, HIT, Some(A));
    assert_eq!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op,
            field: super::row::Field::Clock,
        })
    );
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    s.expire(K, A, 9);
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "expiry removed a label before its deadline"
    );
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let lookup = s.begin_lookup(K, ClockSample::Seconds(9));
    s.end_lookup(lookup, Outcome::Expired, Some(A));
    assert_violates(&s.finish(), Obligation::History);
}

#[test]
fn an_expired_lookup_names_a_published_label() {
    for stale in [A, C] {
        let mut s = Script::new();
        let publish = s.begin_publish(K, B, BODY, Some(10));
        s.close(publish, Some(ACK));
        let lookup = s.begin_lookup(K, ClockSample::Seconds(10));
        s.end_lookup(lookup, Outcome::Expired, Some(stale));
        assert_eq!(
            assert_violates(&s.finish(), Obligation::History),
            "Expired without a published label past its deadline",
            "{stale:?}"
        );
    }
}

#[test]
fn replacement_order_does_not_rank_labels_by_value() {
    for (old, new) in [(A, B), (B, A)] {
        let mut s = Script::new();
        s.publish(K, old, BODY);
        s.publish_replacing(K, new, BODY);
        s.lookup(K, HIT, Some(new));
        assert!(check(&s.finish()).satisfies(&[Obligation::History]));
        let mut s = Script::new();
        s.publish(K, old, BODY);
        s.publish_replacing(K, new, BODY);
        s.lookup(K, HIT, Some(old));
        assert!(check(&s.finish()).satisfies(&[Obligation::History]));
        let mut s = Script::new();
        s.publish(K, old, BODY);
        s.publish_replacing(K, new, BODY);
        s.ended(K, old, VisibilityCause::GraceEnd);
        s.lookup(K, HIT, Some(old));
        assert_eq!(
            assert_violates(&s.finish(), Obligation::History),
            "a hit after a recorded removal of its label in the same tenure"
        );
    }
}

#[test]
fn histories_beyond_the_declared_domain_are_inconclusive() {
    let mut s = Script::new();
    for key in 0..3 {
        s.publish(KeyId(key), Label(30 + u64::from(key)), BODY);
    }
    assert!(matches!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::DomainBound {
            dimension: "keys",
            ..
        })
    ));
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.publish_replacing(K, B, BODY);
    s.publish_replacing(K, Label(12), BODY);
    assert!(matches!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::DomainBound {
            dimension: "labels per key",
            ..
        })
    ));
    let mut released = Script::new();
    released.publish(K, A, BODY);
    for _ in 0..3 {
        let read = released.lookup(K, HIT, Some(A));
        released.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    }
    let verdict = check(&released.finish());
    assert!(verdict.satisfies(&[Obligation::Bytes]), "{verdict:?}");
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let reads: Vec<_> = (0..3).map(|_| s.lookup(K, HIT, Some(A))).collect();
    for read in reads {
        s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    }
    assert!(matches!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::DomainBound {
            dimension: "holders",
            ..
        })
    ));
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let first = s.lookup(K, HIT, Some(A));
    let buffer = ResourceId {
        kind: ResourceKind::Buffer,
        index: 0,
    };
    s.release_resource(first, buffer);
    let mut reads = vec![first];
    reads.extend((0..2).map(|_| s.lookup(K, HIT, Some(A))));
    for read in reads {
        s.deliver(read, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
    }
    assert!(matches!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::DomainBound {
            dimension: "holders",
            ..
        })
    ));
}

#[test]
fn a_second_key_that_exhausts_search_names_the_declared_bound() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    s.publish(J, C, BODY);
    let missing = s.begin_lookup(J, ClockSample::Seconds(1));
    let lookups: Vec<_> = (0..13)
        .map(|_| s.begin_lookup(J, ClockSample::Seconds(1)))
        .collect();
    for lookup in lookups {
        s.end_lookup(lookup, CONTENDED, None);
    }
    s.end_lookup(missing, HIT, Some(Label(21)));
    assert_eq!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::SearchBound {
            limit: SEARCH_BOUND
        })
    );
}

#[test]
fn a_candidate_miss_is_legal_whatever_the_requested_key_holds() {
    for (key, label) in [(J, C), (K, A)] {
        let mut s = Script::new();
        s.publish(key, label, BODY);
        s.candidate_lookup(K, J, MISSING, None);
        let verdict = check(&s.finish());
        assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    }
}

#[test]
fn an_expired_candidate_is_judged_against_its_owner_key() {
    let mut s = Script::new();
    let publish = s.begin_publish(J, C, BODY, Some(10));
    s.close(publish, Some(ACK));
    let mut lookup = s.begin_lookup(K, ClockSample::Seconds(10));
    lookup.set_candidate(J);
    s.end_lookup(lookup, Outcome::Expired, Some(C));
    let verdict = check(&s.finish());
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
}

#[test]
fn a_dropped_publication_never_lands() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, None);
    s.close(
        publish,
        Some(Outcome::NoInformation(NoInformation::Dropped)),
    );
    s.lookup(K, HIT, Some(A));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a hit of a version no linearized fill published"
    );
}

#[test]
fn a_removal_row_with_a_no_information_outcome_keeps_the_mapping() {
    for kind in [
        ActionKind::Expire,
        ActionKind::Evict,
        ActionKind::VisibilityEnded,
    ] {
        let mut s = Script::new();
        let publish = s.begin_publish(K, A, BODY, Some(10));
        s.close(publish, Some(ACK));
        match kind {
            ActionKind::Expire => s.expire(K, A, 10),
            ActionKind::Evict => s.evict(K, A),
            _ => s.ended(K, A, VisibilityCause::Eviction),
        }
        // An expiry's own sample reached the deadline, so the later lookup
        // reports the expiry; after the other removals it hits.
        let (sample, outcome) = if kind == ActionKind::Expire {
            (10, Outcome::Expired)
        } else {
            (1, HIT)
        };
        let lookup = s.begin_lookup(K, ClockSample::Seconds(sample));
        s.end_lookup(lookup, outcome, Some(A));
        let removed = s.finish();
        let refused = edited(&removed, |rows| {
            let removal = rows.iter_mut().find(|r| r.kind == kind).unwrap();
            removal.outcome = Some(Outcome::NoInformation(NoInformation::Cancelled));
        });
        let kept = check(&refused);
        assert!(kept.satisfies(&[Obligation::History]), "{kind:?} {kept:?}");
        assert_eq!(
            assert_violates(&removed, Obligation::History),
            if kind == ActionKind::Expire {
                "Expired without a published label past its deadline"
            } else {
                REMOVED
            },
            "{kind:?}"
        );
    }
}

#[test]
fn a_deadline_saturates_at_the_stored_seconds() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(u64::MAX));
    s.close(publish, Some(ACK));
    let lookup = s.begin_lookup(K, ClockSample::Seconds(u64::from(u32::MAX)));
    s.end_lookup(lookup, HIT, Some(A));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a hit at or past the deadline"
    );
}

#[test]
fn a_collision_hit_is_a_miss_on_the_requested_key() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.publish(J, C, BODY);
    let base = s;
    let mut displaced = base.clone();
    displaced.ended(K, A, VisibilityCause::CollisionCollateral);
    displaced.candidate_lookup(K, J, HIT, Some(C));
    let verdict = check(&displaced.finish());
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    let mut both_published = base;
    both_published.candidate_lookup(K, J, HIT, Some(C));
    let verdict = check(&both_published.finish());
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    let mut unpublished = Script::new();
    unpublished.publish(K, A, BODY);
    unpublished.fill(J, C, BODY);
    unpublished.candidate_lookup(K, J, HIT, Some(C));
    assert_eq!(
        assert_violates(&unpublished.finish(), Obligation::History),
        "a hit of a version no linearized fill published"
    );
}

#[test]
fn an_observed_expiry_forbids_a_later_hit() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let at = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(at, Outcome::Expired, Some(A));
    let base = s;
    let mut again = base.clone();
    let later = again.begin_lookup(K, ClockSample::Seconds(11));
    again.end_lookup(later, Outcome::Expired, Some(A));
    assert!(check(&again.finish()).satisfies(&[Obligation::History]));
    let mut regressed = base;
    let later = regressed.begin_lookup(K, ClockSample::Seconds(1));
    regressed.end_lookup(later, HIT, Some(A));
    assert_eq!(
        assert_violates(&regressed.finish(), Obligation::History),
        "a clock sample regressed behind an earlier one"
    );
}

#[test]
fn the_clock_never_regresses_across_a_replacement() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let at = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(at, Outcome::Expired, Some(A));
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(ACK));
    let later = s.begin_lookup(K, ClockSample::Seconds(1));
    s.end_lookup(later, HIT, Some(B));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a clock sample regressed behind an earlier one"
    );
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let first = s.begin_lookup(K, ClockSample::Seconds(5));
    let second = s.begin_lookup(K, ClockSample::Seconds(3));
    s.end_lookup(first, HIT, Some(A));
    s.end_lookup(second, HIT, Some(A));
    assert!(check(&s.finish()).satisfies(&[Obligation::History]));
}

#[test]
fn the_clock_never_regresses_across_keys() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let publish = s.begin_publish(J, C, BODY, Some(20));
    s.close(publish, Some(ACK));
    let at = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(at, Outcome::Expired, Some(A));
    let later = s.begin_lookup(J, ClockSample::Seconds(1));
    s.end_lookup(later, HIT, Some(C));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a clock sample regressed behind an earlier one"
    );
}

#[test]
fn a_publication_deadline_lies_ahead_of_the_observed_clock() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let at = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(at, Outcome::Expired, Some(A));
    let replace = s.begin_replace(K, B, BODY);
    let mut replace = replace;
    replace.set_deadline(5);
    s.close(replace, Some(ACK));
    let later = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(later, Outcome::Expired, Some(B));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a publication at or past its deadline"
    );
}

#[test]
fn a_publication_deadline_lies_ahead_of_the_clock_observed_on_another_key() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let at = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(at, Outcome::Expired, Some(A));
    let publish = s.begin_publish(J, C, BODY, Some(5));
    s.close(publish, Some(ACK));
    let later = s.begin_lookup(J, ClockSample::Seconds(10));
    s.end_lookup(later, Outcome::Expired, Some(C));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a publication at or past its deadline"
    );
}

#[test]
fn a_publication_follows_its_write_completion() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let unwritten = edited(&s.finish(), |rows| {
        rows.retain(|r| r.kind != ActionKind::WriteCompleted);
    });
    assert_eq!(
        assert_violates(&unwritten, Obligation::History),
        "a publication before its writes completed"
    );
}

#[test]
fn a_fill_may_release_its_resources() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    let buffer = ResourceId {
        kind: ResourceKind::Buffer,
        index: 0,
    };
    s.release_resource(op, buffer);
    s.lookup(K, HIT, Some(A));
    assert!(check(&s.finish()).satisfies(&[Obligation::History]));
}

#[test]
fn an_omitted_deadline_is_the_storage_horizon() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let lookup = s.begin_lookup(K, ClockSample::Seconds(u64::from(u32::MAX)));
    s.end_lookup(lookup, HIT, Some(A));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a hit at or past the deadline"
    );
}

#[test]
fn a_pending_publication_also_follows_its_write_completion() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, None);
    s.close(
        publish,
        Some(Outcome::NoInformation(NoInformation::TimedOut)),
    );
    s.lookup(K, HIT, Some(A));
    let unwritten = edited(&s.finish(), |rows| {
        rows.retain(|r| r.kind != ActionKind::WriteCompleted);
    });
    assert_eq!(
        assert_violates(&unwritten, Obligation::History),
        "a publication before its writes completed"
    );
}

#[test]
fn a_collision_lookup_keeps_its_clock_sample_on_the_requested_key() {
    let mut s = Script::new();
    s.publish(J, C, BODY);
    let mut lookup = s.begin_lookup(K, ClockSample::Seconds(10));
    lookup.set_candidate(J);
    let op = s.end_lookup(lookup, HIT, Some(C));
    let history = s.finish();
    let rows: Vec<&Row> = history.rows().iter().collect();
    let log = super::tenure::ActivationLog::of(&rows).expect("no activations");
    let derived = super::candidates::Derived::of(&rows, &log);
    let miss = super::candidates::key_ops(&rows, &derived, K)
        .into_iter()
        .find(|row| row.op == op)
        .expect("the requested key's miss");
    assert_eq!(
        (miss.outcome, miss.label, miss.clock),
        (Some(MISSING), None, Some(ClockSample::Seconds(10)))
    );
    // A's expiry end on K overlaps the collision lookup, so only the
    // requested key's miss, linearized before the end, carries a sample
    // that bounds the end's clock: second ten passes the deadline at second
    // five and second three does not.
    let overlapping = |second: u64| {
        let mut s = Script::new();
        let publish = s.begin_publish(K, A, BODY, Some(5));
        s.close(publish, Some(ACK));
        s.publish(J, C, BODY);
        let mut lookup = s.begin_lookup(K, ClockSample::Seconds(second));
        lookup.set_candidate(J);
        s.ended(K, A, VisibilityCause::Expiry);
        s.end_lookup(lookup, HIT, Some(C));
        s.finish()
    };
    let verdict = check(&overlapping(10));
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    assert_eq!(
        assert_violates(&overlapping(3), Obligation::History),
        "a visibility end by expiry before the deadline"
    );
}

#[test]
fn a_refused_write_completion_completes_nothing() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.lookup(K, HIT, Some(A));
    let refused = edited(&s.finish(), |rows| {
        let done = rows
            .iter_mut()
            .find(|r| r.kind == ActionKind::WriteCompleted);
        done.unwrap().outcome = Some(Outcome::NoInformation(NoInformation::Cancelled));
    });
    assert_eq!(
        assert_violates(&refused, Obligation::History),
        "a publication before its writes completed"
    );
}

#[test]
fn a_visibility_end_by_expiry_follows_the_deadline() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    s.ended(K, A, VisibilityCause::Expiry);
    s.lookup(K, MISSING, None);
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a visibility end by expiry before the deadline"
    );
}

#[test]
fn a_fill_admitted_during_an_open_invalidation_keeps_receiving() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let invalidate = s.begin_invalidate(K);
    let fill = s.fill(K, B, BODY);
    s.close(invalidate, Some(ACK));
    let replace = s.open(fill, ActionKind::Replace, K, Some(B));
    s.close(replace, Some(ACK));
    s.lookup(K, HIT, Some(B));
    let late_receive = edited(&s.finish(), |rows| {
        let invalidate = rows
            .iter()
            .position(|r| r.kind == ActionKind::Invalidate)
            .unwrap();
        let receive = rows
            .iter()
            .position(|r| r.kind == ActionKind::Receive && r.op == fill);
        let receive = receive.unwrap();
        let done = rows
            .iter()
            .position(|r| r.kind == ActionKind::WriteCompleted && r.op == fill);
        let done = done.unwrap();
        let (a, b, c) = (
            rows[receive].invoked,
            rows[receive].responded,
            rows[done].responded,
        );
        rows[invalidate].responded = a;
        rows[receive].invoked = b;
        rows[receive].responded = c;
        rows[done].responded = Some(Ordinal(c.unwrap().0 + 1));
        let shift = |o: &mut Option<Ordinal>| {
            if let Some(o) = o {
                o.0 += 2;
            }
        };
        for row in rows
            .iter_mut()
            .filter(|r| matches!(r.kind, ActionKind::Replace | ActionKind::Lookup))
        {
            shift(&mut row.invoked);
            shift(&mut row.responded);
        }
    });
    let verdict = check(&late_receive);
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
}

#[test]
fn an_expiry_visibility_end_may_rest_on_another_keys_sample() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let publish = s.begin_publish(J, C, BODY, Some(20));
    s.close(publish, Some(ACK));
    let sample = s.begin_lookup(J, ClockSample::Seconds(10));
    s.end_lookup(sample, HIT, Some(C));
    s.ended(K, A, VisibilityCause::Expiry);
    s.lookup(K, MISSING, None);
    let verdict = check(&s.finish());
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
}

#[test]
fn an_empty_sealed_history_passes_with_no_activation() {
    let verdict = check(&Script::new().finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
    assert!(!verdict.satisfies(&[Obligation::History]));
}

#[test]
fn a_closed_cache_answers_no_lookup_and_lands_no_publication() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.close_cache(ACK);
    s.lookup(K, HIT, Some(A));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a lookup answered after the cache closed"
    );
    let mut s = Script::new();
    let op = s.fill(K, A, BODY);
    s.close_cache(ACK);
    let publish = s.open(op, ActionKind::Publish, K, Some(A));
    s.close(publish, Some(ACK));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a publication after the cache closed"
    );
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.close_cache(ACK);
    s.lookup(K, Outcome::NoInformation(NoInformation::Closed), None);
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
}

#[test]
fn a_closed_cache_admits_no_fill_and_acknowledges_no_invalidation() {
    let mut s = Script::new();
    s.close_cache(ACK);
    s.fill(K, A, BODY);
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a fill admitted after the cache closed"
    );
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.close_cache(ACK);
    s.invalidate(K, ACK);
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "an invalidation after the cache closed"
    );
}

#[test]
fn a_candidates_label_belongs_to_its_owner_whatever_the_sample() {
    let mut s = Script::new();
    s.publish(J, C, BODY);
    let mut lookup = s.begin_lookup(K, ClockSample::Seconds(1));
    lookup.set_candidate(J);
    s.clock_unavailable(lookup, C);
    s.lookup(K, MISSING, None);
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
}

#[test]
fn only_sampling_actions_bound_the_clock() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let read = s.lookup(K, HIT, Some(A));
    s.release_key(read, K);
    s.ended(K, A, VisibilityCause::Expiry);
    s.lookup(K, MISSING, None);
    let sampled_release = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::Release)
            .unwrap()
            .clock = Some(ClockSample::Seconds(10));
    });
    assert_eq!(
        assert_violates(&sampled_release, Obligation::History),
        "a visibility end by expiry before the deadline"
    );
}

#[test]
fn a_publications_own_sample_bounds_its_deadline() {
    let mut s = Script::new();
    let mut publish = s.begin_publish(K, A, BODY, Some(10));
    publish.set_clock(ClockSample::Seconds(20));
    s.close(publish, Some(ACK));
    let lookup = s.begin_lookup(K, ClockSample::Seconds(20));
    s.end_lookup(lookup, Outcome::Expired, Some(A));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a publication at or past its deadline"
    );
}

#[test]
fn a_closed_cache_receives_nothing() {
    let mut s = Script::new();
    s.fill(K, A, BODY);
    s.lookup(K, MISSING, None);
    let received_after_close = edited(&s.finish(), |rows| {
        for row in rows.iter_mut() {
            for ordinal in [&mut row.invoked, &mut row.responded, &mut row.custody_end]
                .into_iter()
                .flatten()
            {
                ordinal.0 *= 2;
            }
        }
        let receive = rows.iter().find(|r| r.kind == ActionKind::Receive).unwrap();
        let mut close = Row::new(OpId(90), ActionKind::Close);
        close.episode = receive.episode;
        close.outcome = Some(ACK);
        close.invoked = Some(Ordinal(receive.invoked.unwrap().0 - 3));
        close.responded = Some(Ordinal(receive.invoked.unwrap().0 - 1));
        rows.push(close);
    });
    assert_eq!(
        assert_violates(&received_after_close, Obligation::History),
        "a receive after the cache closed"
    );
}

#[test]
fn an_expiry_end_replaces_only_itself_in_the_search() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    let op = s.close(publish, Some(ACK));
    s.ended(K, A, VisibilityCause::Expiry);
    s.lookup(K, MISSING, None);
    let aliased = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::VisibilityEnded)
            .unwrap()
            .op = op;
    });
    let verdict = check(&aliased);
    assert!(
        matches!(
            verdict,
            Verdict::Violation(_) | Verdict::Inconclusive(Inconclusive::Malformed { .. })
        ),
        "{verdict:?}"
    );
}

#[test]
fn a_refused_receive_after_revocation_is_the_expected_history() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let fill = s.fill(K, B, BODY);
    s.invalidate(K, ACK);
    s.lookup(K, MISSING, None);
    let revoked = edited(&s.finish(), |rows| {
        let receive = rows
            .iter()
            .position(|r| r.kind == ActionKind::Receive && r.op == fill);
        let mut refused = rows.remove(receive.unwrap());
        let done = rows
            .iter()
            .position(|r| r.kind == ActionKind::WriteCompleted && r.op == fill);
        rows.remove(done.unwrap());
        let last = rows.iter().filter_map(|r| r.responded).max().unwrap().0;
        refused.invoked = Some(Ordinal(last + 1));
        refused.responded = Some(Ordinal(last + 2));
        refused.outcome = Some(REFUSED);
        refused.payload = Some(Vec::new());
        rows.push(refused);
    });
    let verdict = check(&revoked);
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
}

#[test]
fn an_acknowledged_publication_sampled_its_clock() {
    let mut s = Script::new();
    let mut publish = s.begin_publish(K, A, BODY, Some(10));
    publish.set_clock(ClockSample::Unavailable);
    s.close(publish, Some(ACK));
    s.lookup(K, HIT, Some(A));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a publication acknowledged without a clock sample"
    );
}

#[test]
fn a_pending_publication_past_its_deadline_stays_refused() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(20));
    s.close(publish, Some(ACK));
    let at = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(at, HIT, Some(A));
    let mut replace = s.begin_replace(K, B, BODY);
    replace.set_deadline(10);
    s.close(
        replace,
        Some(Outcome::NoInformation(NoInformation::TimedOut)),
    );
    let later = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(later, HIT, Some(A));
    let verdict = check(&s.finish());
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
}

#[test]
fn a_pending_publication_with_a_failed_sample_lands_nothing() {
    let mut s = Script::new();
    let mut publish = s.begin_publish(K, A, BODY, Some(10));
    publish.set_clock(ClockSample::Unavailable);
    s.close(
        publish,
        Some(Outcome::NoInformation(NoInformation::TimedOut)),
    );
    s.lookup(K, HIT, Some(A));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "a hit of a version no linearized fill published"
    );
}

#[test]
fn a_removal_names_a_label_the_key_knew() {
    for kind in [
        ActionKind::Expire,
        ActionKind::Evict,
        ActionKind::VisibilityEnded,
    ] {
        let mut s = Script::new();
        match kind {
            ActionKind::Expire => s.expire(K, A, 1),
            ActionKind::Evict => s.evict(K, A),
            _ => s.ended(K, A, VisibilityCause::Eviction),
        }
        s.lookup(K, MISSING, None);
        assert_eq!(
            assert_violates(&s.finish(), Obligation::History),
            "a removal of a label the key never held",
            "{kind:?}"
        );
    }
}

#[test]
fn a_visibility_end_carries_no_sample_of_its_own() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    s.ended(K, A, VisibilityCause::Expiry);
    s.lookup(K, MISSING, None);
    let fabricated = edited(&s.finish(), |rows| {
        rows.iter_mut()
            .find(|r| r.kind == ActionKind::VisibilityEnded)
            .unwrap()
            .clock = Some(ClockSample::Seconds(10));
    });
    assert_eq!(
        assert_violates(&fabricated, Obligation::History),
        "a visibility end by expiry before the deadline"
    );
}

#[test]
fn a_removal_names_a_label_that_became_visible() {
    for kind in [
        ActionKind::Expire,
        ActionKind::Evict,
        ActionKind::VisibilityEnded,
    ] {
        let mut s = Script::new();
        s.fill(K, A, BODY);
        match kind {
            ActionKind::Expire => s.expire(K, A, 1),
            ActionKind::Evict => s.evict(K, A),
            _ => s.ended(K, A, VisibilityCause::Eviction),
        }
        s.lookup(K, MISSING, None);
        assert_eq!(
            assert_violates(&s.finish(), Obligation::History),
            "a removal of a label the key never held",
            "{kind:?}"
        );
    }
}

#[test]
fn an_eviction_waits_for_the_keys_current_fill() {
    for by_cause in [false, true] {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        s.fill(K, B, BODY);
        if by_cause {
            s.ended(K, A, VisibilityCause::Eviction);
        } else {
            s.evict(K, A);
        }
        s.lookup(K, MISSING, None);
        assert_eq!(
            assert_violates(&s.finish(), Obligation::History),
            "an eviction while a fill is current",
            "{by_cause}"
        );
    }
}

#[test]
fn a_pending_publication_past_another_keys_sample_lands_nothing() {
    let mut s = Script::new();
    let publish = s.begin_publish(J, C, BODY, Some(20));
    s.close(publish, Some(ACK));
    let sample = s.begin_lookup(J, ClockSample::Seconds(10));
    s.end_lookup(sample, HIT, Some(C));
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(
        publish,
        Some(Outcome::NoInformation(NoInformation::TimedOut)),
    );
    let later = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(later, Outcome::Expired, Some(A));
    assert_eq!(
        assert_violates(&s.finish(), Obligation::History),
        "Expired without a published label past its deadline"
    );
}

#[test]
fn a_pending_effect_after_close_stays_refused() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, None);
    s.close(publish, Some(ACK));
    let op = s.fill(K, B, BODY);
    s.close_cache(ACK);
    let replace = s.open(op, ActionKind::Replace, K, Some(B));
    s.close(
        replace,
        Some(Outcome::NoInformation(NoInformation::TimedOut)),
    );
    let invalidate = s.begin_invalidate(K);
    s.close(
        invalidate,
        Some(Outcome::NoInformation(NoInformation::Cancelled)),
    );
    s.lookup(K, Outcome::NoInformation(NoInformation::Closed), None);
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
}

#[test]
fn an_expiry_end_substitutes_only_its_own_row() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(1));
    s.close(publish, Some(ACK));
    s.publish(J, C, BODY);
    s.expire(K, A, 1);
    s.ended(K, A, VisibilityCause::Expiry);
    s.ended(J, C, VisibilityCause::Eviction);
    s.lookup(J, HIT, Some(C));
    let aliased = edited(&s.finish(), |rows| {
        let expiry = rows
            .iter()
            .find(|r| r.cause == Some(VisibilityCause::Expiry))
            .unwrap()
            .op;
        rows.iter_mut()
            .find(|r| r.cause == Some(VisibilityCause::Eviction))
            .unwrap()
            .op = expiry;
    });
    assert_eq!(
        assert_violates(&aliased, Obligation::History),
        "a hit after a recorded removal of its label in the same tenure"
    );
}

#[test]
fn an_open_sample_linearized_before_a_response_bounds_samples_taken_after_it() {
    let crossing = |later: u64| {
        let mut s = Script::new();
        let publish = s.begin_publish(K, A, BODY, Some(10));
        s.close(publish, Some(ACK));
        s.publish(J, C, BODY);
        let first = s.begin_lookup(K, ClockSample::Seconds(10));
        s.ended(K, A, VisibilityCause::Expiry);
        let second = s.begin_lookup(J, ClockSample::Seconds(later));
        s.end_lookup(second, HIT, Some(C));
        s.end_lookup(first, Outcome::Expired, Some(A));
        s.finish()
    };
    let verdict = check(&crossing(10));
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    assert_violates(&crossing(5), Obligation::History);
}

#[test]
fn a_pending_publications_sample_is_ordered_by_its_landing_window() {
    let pending = |custody_ended: bool| {
        let mut s = Script::new();
        let mut publish = s.begin_publish(K, A, BODY, None);
        publish.set_clock(ClockSample::Seconds(10));
        s.close(
            publish,
            Some(Outcome::NoInformation(NoInformation::TimedOut)),
        );
        let lookup = s.begin_lookup(K, ClockSample::Seconds(5));
        s.end_lookup(lookup, MISSING, None);
        edited(&s.finish(), |rows| {
            if custody_ended {
                let publish = rows
                    .iter_mut()
                    .find(|r| r.kind == ActionKind::Publish)
                    .unwrap();
                publish.custody_end = publish.responded.map(|o| Ordinal(o.0 + 1));
                let lookup = rows
                    .iter_mut()
                    .find(|r| r.kind == ActionKind::Lookup)
                    .unwrap();
                lookup.invoked = lookup.invoked.map(|o| Ordinal(o.0 + 2));
                lookup.responded = lookup.responded.map(|o| Ordinal(o.0 + 2));
            }
        })
    };
    let verdict = check(&pending(false));
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
    assert_eq!(
        assert_violates(&pending(true), Obligation::History),
        "a clock sample regressed behind an earlier one"
    );
}

#[test]
fn a_forced_refusal_keeps_the_pending_publications_landing_window() {
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(10));
    s.close(publish, Some(ACK));
    let lookup = s.begin_lookup(K, ClockSample::Seconds(10));
    s.end_lookup(lookup, Outcome::Expired, Some(A));
    let mut replace = s.begin_replace(K, B, BODY);
    replace.set_clock(ClockSample::Seconds(20));
    replace.set_deadline(10);
    s.close(
        replace,
        Some(Outcome::NoInformation(NoInformation::TimedOut)),
    );
    let between = s.begin_lookup(K, ClockSample::Seconds(15));
    s.end_lookup(between, Outcome::Expired, Some(A));
    let verdict = check(&s.finish());
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
}

#[test]
fn a_removal_action_selects_a_visible_label() {
    for kind in [ActionKind::Evict, ActionKind::Expire] {
        let mut s = Script::new();
        let publish = s.begin_publish(K, A, BODY, Some(1));
        s.close(publish, Some(ACK));
        for _ in 0..2 {
            match kind {
                ActionKind::Evict => s.evict(K, A),
                _ => s.expire(K, A, 1),
            }
        }
        s.lookup(K, MISSING, None);
        assert_eq!(
            assert_violates(&s.finish(), Obligation::History),
            "a removal selected a label already removed",
            "{kind:?}"
        );
    }
    let mut s = Script::new();
    let publish = s.begin_publish(K, A, BODY, Some(1));
    s.close(publish, Some(ACK));
    s.expire(K, A, 1);
    s.ended(K, A, VisibilityCause::Expiry);
    s.lookup(K, MISSING, None);
    let verdict = check(&s.finish());
    assert!(verdict.satisfies(&[Obligation::History]), "{verdict:?}");
}

mod remote_put {
    use super::{
        A, ACK, ActionKind, B, BODY, C, Change, ClockSample, Ending, Evidence, FAILED, Field,
        HANDOFF_ALIASES, HIT, History, Inconclusive, J, K, MISSING, NoInformation, Obligation,
        OpId, Ordinal, Position, PutOutcome, RECOVERED, REFUSED, Receipt, ResourceId, ResourceKind,
        Row, Script, Serial, Subject, Verdict, assert_violates, bytes, changed_retry, check,
        concurrent_then_ended, edited, expired_evidence, failure_beside_concurrent,
        failure_over_incumbent, historical_success, matching_retry, possible_publication,
        published_before_publication, put_then_get, put_then_lookup, receipt_without_write,
        resolved,
    };

    fn passes(history: &History, declared: &[Obligation]) {
        let verdict = check(history);
        assert!(verdict.satisfies(declared), "{verdict:?}");
    }

    fn after(
        result: Option<PutOutcome>,
        published: bool,
        lookup: (super::Outcome, Option<super::Label>),
    ) -> History {
        put_then_lookup(result, published, lookup, Position::AfterResult)
    }

    #[test]
    fn a_published_upload_serves_its_exact_bytes_to_a_get() {
        passes(
            &put_then_get(bytes(K, A, BODY)),
            &[Obligation::History, Obligation::Bytes],
        );
        assert_eq!(
            assert_violates(&put_then_get(bytes(K, B, BODY)), Obligation::Bytes),
            "a complete read returned bytes other than the label's content"
        );
    }

    #[test]
    fn a_full_receipt_without_its_writes_stays_unpublished() {
        passes(
            &receipt_without_write(FAILED, MISSING),
            &[Obligation::History],
        );
        assert_eq!(
            assert_violates(
                &receipt_without_write(PutOutcome::Published, MISSING),
                Obligation::History
            ),
            "Published without the attempt's publication"
        );
        assert_eq!(
            assert_violates(&receipt_without_write(FAILED, HIT), Obligation::History),
            "a hit of a version no linearized fill published"
        );
    }

    #[test]
    fn a_lost_result_leaves_the_attempt_unknown_with_or_without_its_publication() {
        let unknown = Some(PutOutcome::Unknown);
        passes(
            &after(unknown, true, (HIT, Some(A))),
            &[Obligation::History],
        );
        for published in [false, true] {
            passes(
                &after(unknown, published, (MISSING, None)),
                &[Obligation::History],
            );
        }
        assert_eq!(
            assert_violates(&after(unknown, false, (HIT, Some(A))), Obligation::History),
            "a hit of a version no linearized fill published"
        );
    }

    #[test]
    fn a_matching_retry_resolves_the_historical_result_without_republishing() {
        passes(&matching_retry(false), &[Obligation::History]);
        assert_eq!(
            assert_violates(&matching_retry(true), Obligation::History),
            "an attempt published twice"
        );
    }

    #[test]
    fn a_changed_retry_is_refused_and_leaves_the_accepted_attempt() {
        for change in [
            Change::Key,
            Change::Serial,
            Change::Metadata,
            Change::Body,
            Change::Deadline,
        ] {
            passes(&changed_retry(change, REFUSED), &[Obligation::History]);
            assert_eq!(
                assert_violates(&changed_retry(change, ACK), Obligation::History),
                "a changed retry replayed the attempt",
                "{change:?}"
            );
        }
    }

    #[test]
    fn an_attempt_whose_evidence_expired_stays_unknown_and_fills_nothing_new() {
        passes(&expired_evidence(false), &[Obligation::History]);
        assert_eq!(
            assert_violates(&expired_evidence(true), Obligation::History),
            "the owner filled after the attempt's authority"
        );
    }

    #[test]
    fn a_failed_or_unstarted_upload_never_publishes_its_label() {
        for result in [FAILED, PutOutcome::NotStarted] {
            for build in [failure_over_incumbent, failure_beside_concurrent] {
                passes(&build(result, (HIT, Some(A))), &[Obligation::History]);
                passes(&build(result, (MISSING, None)), &[Obligation::History]);
                assert_eq!(
                    assert_violates(&build(result, (HIT, Some(B))), Obligation::History),
                    "a hit of a version no linearized fill published"
                );
            }
        }
        // Incumbent preservation requires a separate check because the
        // history obligation permits a missing incumbent after an upload
        // failure.
        let incumbent = HANDOFF_ALIASES
            .iter()
            .find(|(alias, ..)| *alias == "put-failure-preserves-incumbent-publication")
            .map(|&(_, _, supported)| supported);
        assert_eq!(incumbent, Some(None));
    }

    #[test]
    fn a_possible_owner_publication_keeps_unknown_open_and_rejects_a_failure() {
        for publication in [NoInformation::Cancelled, NoInformation::TimedOut] {
            for lookup in [(HIT, Some(A)), (MISSING, None)] {
                passes(
                    &possible_publication(publication, PutOutcome::Unknown, lookup),
                    &[Obligation::History],
                );
            }
            for result in [FAILED, PutOutcome::NotStarted] {
                assert_eq!(
                    assert_violates(
                        &possible_publication(publication, result, (MISSING, None)),
                        Obligation::History
                    ),
                    "an attempt that did not publish published",
                    "{publication:?} {result:?}"
                );
            }
        }
    }

    #[test]
    fn an_owner_publication_without_a_clock_never_lands_and_admits_a_failure() {
        for publication in [NoInformation::Cancelled, NoInformation::TimedOut] {
            let unclocked = |result, lookup| {
                edited(&possible_publication(publication, result, lookup), |rows| {
                    for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Publish) {
                        row.clock = Some(ClockSample::Unavailable);
                    }
                })
            };
            passes(&unclocked(FAILED, (MISSING, None)), &[Obligation::History]);
            assert_eq!(
                assert_violates(
                    &unclocked(PutOutcome::Unknown, (HIT, Some(A))),
                    Obligation::History
                ),
                "a hit of a version no linearized fill published",
                "{publication:?}"
            );
        }
    }

    #[test]
    fn published_before_the_owner_publication_is_rejected() {
        assert_eq!(
            assert_violates(&published_before_publication(), Obligation::History),
            "Published without the attempt's publication"
        );
    }

    #[test]
    fn a_historical_published_after_its_label_ended_revives_nothing() {
        for lookup in [(HIT, Some(C)), (HIT, Some(A)), (MISSING, None)] {
            passes(
                &historical_success(Ending::Replacement, lookup),
                &[Obligation::History],
            );
        }
        for ending in [Ending::Invalidation, Ending::Expiry, Ending::Eviction] {
            passes(
                &historical_success(ending, (MISSING, None)),
                &[Obligation::History],
            );
            assert_eq!(
                assert_violates(
                    &historical_success(ending, (HIT, Some(A))),
                    Obligation::History
                ),
                if ending == Ending::Invalidation {
                    "a hit of a version an acknowledged invalidation covered"
                } else {
                    "a hit after a recorded removal of its label in the same tenure"
                }
            );
        }
    }

    #[test]
    fn a_concurrent_publication_then_its_invalidation_or_expiry_stays_legal() {
        for result in [PutOutcome::Published, FAILED] {
            for ending in [Ending::Invalidation, Ending::Expiry] {
                passes(
                    &concurrent_then_ended(result, ending, (MISSING, None)),
                    &[Obligation::History],
                );
                for label in [A, B] {
                    assert_eq!(
                        assert_violates(
                            &concurrent_then_ended(result, ending, (HIT, Some(label))),
                            Obligation::History
                        ),
                        match (ending, result == FAILED, label == B) {
                            (_, true, true) => "a hit of a version no linearized fill published",
                            (Ending::Invalidation, _, _) => {
                                "a hit of a version an acknowledged invalidation covered"
                            }
                            (_, false, false) => "a hit at or past the deadline",
                            _ => "a hit after a recorded removal of its label in the same tenure",
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn a_fresh_isolated_key_misses_after_a_failed_upload() {
        passes(
            &after(Some(FAILED), false, (MISSING, None)),
            &[Obligation::History],
        );
        assert_eq!(
            assert_violates(
                &after(Some(FAILED), false, (HIT, Some(A))),
                Obligation::History
            ),
            "a hit of a version no linearized fill published"
        );
        assert_eq!(
            assert_violates(
                &after(Some(FAILED), true, (HIT, Some(A))),
                Obligation::History
            ),
            "an attempt that did not publish published"
        );
    }

    #[test]
    fn an_unknown_result_gives_way_only_to_an_owner_terminal_even_after_abandonment() {
        for abandon in [false, true] {
            for later in [PutOutcome::Published, FAILED, PutOutcome::Unknown] {
                passes(&resolved(abandon, later), &[Obligation::History]);
            }
            assert_eq!(
                check(&resolved(abandon, PutOutcome::NotStarted)),
                Verdict::Inconclusive(Inconclusive::Malformed {
                    op: OpId(1),
                    field: Field::Outcome,
                }),
                "abandon {abandon}"
            );
        }
    }

    #[test]
    fn a_known_result_never_changes_and_a_known_attempt_is_never_abandoned() {
        let mut changed = Script::new();
        let op = changed.upload(K, A, BODY, true);
        changed.put_result(op, K, A, FAILED);
        changed.put_result(op, K, A, PutOutcome::Unknown);
        assert_eq!(
            assert_violates(&changed.finish(), Obligation::History),
            "a known attempt result changed"
        );
        let mut abandoned = Script::new();
        let op = abandoned.upload(K, A, BODY, true);
        abandoned.put_result(op, K, A, PutOutcome::Unknown);
        abandoned.put_result(op, K, A, FAILED);
        abandoned.abandon(op, K);
        assert_eq!(
            assert_violates(&abandoned.finish(), Obligation::History),
            "an abandonment of an attempt that was not Unknown"
        );
        let mut again = Script::new();
        let op = again.upload(K, A, BODY, true);
        again.put_result(op, K, A, PutOutcome::Unknown);
        again.abandon(op, K);
        again.put_result(op, K, A, FAILED);
        again.abandon(op, K);
        assert_eq!(
            assert_violates(&again.finish(), Obligation::History),
            "an abandonment of an attempt that was not Unknown"
        );
    }

    #[test]
    fn the_owner_rows_name_the_attempt_manifest_label_and_one_serial() {
        let original = put_then_get(bytes(K, A, BODY));
        let resized = edited(&original, |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Ready) {
                row.body_len = Some(BODY + 1);
            }
        });
        assert_eq!(
            assert_violates(&resized, Obligation::History),
            "the owner prepared another manifest"
        );
        let relabelled = edited(&original, |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::PutResult) {
                row.label = Some(B);
            }
        });
        assert_eq!(
            assert_violates(&relabelled, Obligation::History),
            "Published names another label"
        );
        let renamed = edited(&original, |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Ack) {
                row.serial = Serial::new(99);
            }
        });
        assert_eq!(
            assert_violates(&renamed, Obligation::History),
            "the rows of one attempt name two serials"
        );
        let mut two = Script::new();
        let first = two.upload(K, A, BODY, true);
        let second = two.upload(K, B, BODY, true);
        two.put_result(first, K, A, FAILED);
        two.put_result(second, K, B, FAILED);
        let shared = edited(&two.finish(), |rows| {
            let serial = rows.iter().filter(|r| r.op == first).find_map(|r| r.serial);
            for row in rows
                .iter_mut()
                .filter(|r| r.op == second && r.serial.is_some())
            {
                row.serial = serial;
            }
        });
        assert_eq!(
            assert_violates(&shared, Obligation::History),
            "two attempts share one serial"
        );
        let mut apart = Script::new();
        let first = apart.upload(K, A, BODY, true);
        let second = apart.upload(J, B, BODY, true);
        apart.put_result(first, K, A, FAILED);
        apart.put_result(second, J, B, FAILED);
        let per_key = edited(&apart.finish(), |rows| {
            let serial = rows.iter().filter(|r| r.op == first).find_map(|r| r.serial);
            for row in rows
                .iter_mut()
                .filter(|r| r.op == second && r.serial.is_some())
            {
                row.serial = serial;
            }
        });
        passes(&per_key, &[Obligation::History]);
        let refilled = edited(&original, |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Fill) {
                row.metadata_len = row.metadata_len.map(|len| len + 1);
            }
        });
        assert_eq!(
            assert_violates(&refilled, Obligation::History),
            "the owner prepared another manifest"
        );
        let owner_kinds = [
            vec![ActionKind::Authority],
            vec![ActionKind::Ready],
            vec![ActionKind::Ack],
            vec![
                ActionKind::Fill,
                ActionKind::Receive,
                ActionKind::WriteCompleted,
            ],
        ];
        for kept in owner_kinds {
            let mut s = Script::new();
            let op = s.upload(K, A, BODY, true);
            s.put_result(op, K, A, PutOutcome::NotStarted);
            let seen = edited(&s.finish(), |rows| {
                rows.retain(|r| {
                    matches!(r.kind, ActionKind::PutBegin | ActionKind::PutResult)
                        || kept.contains(&r.kind)
                });
            });
            assert_eq!(
                check(&seen).violated(),
                Some((
                    Obligation::History,
                    "NotStarted after the owner saw the attempt"
                )),
                "{kept:?}"
            );
        }
    }

    fn failed_upload() -> History {
        let mut s = Script::new();
        let op = s.upload(K, A, BODY, true);
        s.put_result(op, K, A, FAILED);
        s.finish()
    }

    #[test]
    fn the_rows_of_one_attempt_name_the_begin_key() {
        passes(&failed_upload(), &[Obligation::History]);
        for kind in [
            ActionKind::Authority,
            ActionKind::Ack,
            ActionKind::PutResult,
        ] {
            let rekeyed = edited(&failed_upload(), |rows| {
                for row in rows.iter_mut().filter(|r| r.kind == kind) {
                    row.subject = Some(Subject::Key(J));
                }
            });
            assert_eq!(
                check(&rekeyed).violated(),
                Some((Obligation::History, "the rows of one attempt name two keys")),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_owner_fill_is_acknowledged_before_the_authority_responds() {
        let straddling = edited(&failed_upload(), |rows| {
            for row in rows.iter_mut() {
                row.invoked = row.invoked.map(|o| Ordinal(o.0 * 10));
                row.responded = row.responded.map(|o| Ordinal(o.0 * 10));
                row.custody_end = row.custody_end.map(|o| Ordinal(o.0 * 10));
            }
            let fill_invoked = rows
                .iter()
                .find(|r| r.kind == ActionKind::Fill)
                .and_then(|r| r.invoked)
                .expect("the fill row");
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Authority) {
                row.responded = Some(Ordinal(fill_invoked.0 + 5));
            }
        });
        assert_eq!(
            assert_violates(&straddling, Obligation::History),
            "the owner filled after the attempt's authority"
        );
    }

    #[test]
    fn an_attempt_shares_its_operation_with_no_other_family() {
        let mut s = Script::new();
        let op = s.put_begin(K, A, BODY, false);
        s.put_result(op, K, A, PutOutcome::NotStarted);
        let lookup = s.lookup(K, MISSING, None);
        let shared = edited(&s.finish(), |rows| {
            for row in rows.iter_mut().filter(|r| r.op == lookup) {
                row.op = op;
            }
        });
        assert_eq!(
            check(&shared),
            Verdict::Inconclusive(Inconclusive::Malformed {
                op,
                field: Field::Invocation,
            })
        );
    }

    #[test]
    fn every_attempt_row_follows_its_begin() {
        let preceded = edited(&failed_upload(), |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::PutBegin) {
                row.invoked = row.invoked.map(|o| Ordinal(o.0 + 1000));
                row.responded = row.responded.map(|o| Ordinal(o.0 + 1000));
            }
        });
        assert_eq!(
            check(&preceded),
            Verdict::Inconclusive(Inconclusive::Malformed {
                op: OpId(1),
                field: Field::Invocation,
            })
        );
    }

    #[test]
    fn the_owner_phases_follow_authority_then_ready() {
        let swap = |first: ActionKind, second: ActionKind| {
            edited(&failed_upload(), |rows| {
                let a = rows.iter().position(|r| r.kind == first).expect("first");
                let b = rows.iter().position(|r| r.kind == second).expect("second");
                let (ra, rb) = (rows[a].responded, rows[b].responded);
                rows[a].responded = rb;
                rows[b].responded = ra;
            })
        };
        for out_of_order in [
            swap(ActionKind::Authority, ActionKind::Ready),
            swap(ActionKind::Ready, ActionKind::Ack),
            edited(&failed_upload(), |rows| {
                rows.retain(|r| r.kind != ActionKind::Authority);
            }),
        ] {
            assert_eq!(
                assert_violates(&out_of_order, Obligation::History),
                "the attempt's phases are out of order"
            );
        }
    }

    #[test]
    fn an_acknowledged_retry_shows_the_owner_saw_the_attempt() {
        let mut s = Script::new();
        let op = s.put_begin(K, A, BODY, false);
        s.retry(op, K, BODY, ACK);
        s.put_result(op, K, A, PutOutcome::NotStarted);
        let begin_resent = edited(&s.finish(), |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Retry) {
                row.serial = None;
                row.metadata_len = None;
                row.body_len = None;
            }
        });
        assert_eq!(
            assert_violates(&begin_resent, Obligation::History),
            "NotStarted after the owner saw the attempt"
        );
    }

    #[test]
    fn every_owner_flow_row_of_an_attempt_names_its_serial() {
        for kind in [
            ActionKind::Fill,
            ActionKind::Receive,
            ActionKind::WriteCompleted,
        ] {
            let unnamed = edited(&failed_upload(), |rows| {
                for row in rows.iter_mut().filter(|r| r.kind == kind) {
                    row.serial = None;
                }
            });
            assert_eq!(
                check(&unnamed).violated(),
                Some((
                    Obligation::History,
                    "an owner flow row of the attempt names no serial"
                )),
                "{kind:?}"
            );
        }
        let unnamed = edited(&matching_retry(false), |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Publish) {
                row.serial = None;
            }
        });
        assert_eq!(
            assert_violates(&unnamed, Obligation::History),
            "an owner flow row of the attempt names no serial"
        );
    }

    #[test]
    fn an_ack_and_a_fragment_stay_within_the_attempt_manifest() {
        // META + BODY fit one fragment, so the manifest counts one.
        let beyond = |history: &History, case: &str| {
            assert_eq!(
                check(history).violated(),
                Some((
                    Obligation::History,
                    "an owner row beyond the attempt's manifest"
                )),
                "{case}"
            );
        };
        let acked = |edit: fn(&mut Row)| {
            edited(&failed_upload(), |rows| {
                for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Ack) {
                    edit(row);
                }
            })
        };
        beyond(&acked(|ack| ack.grant = Some(2)), "grant");
        beyond(
            &acked(|ack| {
                ack.receipt = Some(Receipt { base: 2, mask: 0 });
                ack.grant = Some(2);
            }),
            "base",
        );
        let fragment = edited(&failed_upload(), |rows| {
            let ack = rows
                .iter()
                .position(|r| r.kind == ActionKind::Ack)
                .expect("the ack");
            let mut fragment = rows[ack].clone();
            fragment.kind = ActionKind::Fragment;
            fragment.receipt = None;
            fragment.grant = None;
            fragment.payload = Some(vec![1]);
            fragment.fragment = Some(1);
            fragment.responded = rows[ack].responded.map(|o| Ordinal(o.0 + 1000));
            rows.push(fragment);
        });
        beyond(&fragment, "fragment");
    }

    #[test]
    fn an_attempt_publishes_at_most_once_whatever_the_outcomes() {
        let twice = edited(
            &possible_publication(
                NoInformation::Cancelled,
                PutOutcome::Unknown,
                (MISSING, None),
            ),
            |rows| {
                let publish = rows
                    .iter()
                    .position(|r| r.kind == ActionKind::Publish)
                    .expect("the publication");
                let mut again = rows[publish].clone();
                again.invoked = again.invoked.map(|o| Ordinal(o.0 + 1000));
                again.responded = again.responded.map(|o| Ordinal(o.0 + 1000));
                again.outcome = Some(super::Outcome::NoInformation(NoInformation::TimedOut));
                rows.insert(publish + 1, again);
            },
        );
        assert_eq!(
            assert_violates(&twice, Obligation::History),
            "an attempt published twice"
        );
    }

    #[test]
    fn a_publication_and_a_published_result_follow_ready() {
        // Without its ACK the attempt's remaining phases are the authority
        // and READY, so the rule under test is the one that fires.
        for kinds in [
            vec![ActionKind::Authority, ActionKind::Ready, ActionKind::Ack],
            vec![ActionKind::Ready, ActionKind::Ack],
        ] {
            let unprepared = edited(&put_then_get(bytes(K, A, BODY)), |rows| {
                rows.retain(|r| !kinds.contains(&r.kind));
            });
            assert_eq!(
                assert_violates(&unprepared, Obligation::History),
                "the attempt's phases are out of order",
                "{kinds:?}"
            );
        }
        let late_ready = edited(&put_then_get(bytes(K, A, BODY)), |rows| {
            rows.retain(|r| r.kind != ActionKind::Ack);
            for row in rows.iter_mut() {
                row.invoked = row.invoked.map(|o| Ordinal(o.0 * 10));
                row.responded = row.responded.map(|o| Ordinal(o.0 * 10));
                row.custody_end = row.custody_end.map(|o| Ordinal(o.0 * 10));
            }
            let published = responded(rows, ActionKind::Publish);
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Ready) {
                row.responded = Some(Ordinal(published.0 + 5));
            }
        });
        assert_eq!(
            assert_violates(&late_ready, Obligation::History),
            "the attempt's phases are out of order"
        );
    }

    /// `failed_upload` with every ordinal scaled by ten, so a row can be
    /// placed between two of its neighbours.
    fn spaced_failed_upload() -> Vec<Row> {
        let mut rows = failed_upload().rows().to_vec();
        for row in &mut rows {
            row.invoked = row.invoked.map(|o| Ordinal(o.0 * 10));
            row.responded = row.responded.map(|o| Ordinal(o.0 * 10));
            row.custody_end = row.custody_end.map(|o| Ordinal(o.0 * 10));
        }
        rows
    }

    fn responded(rows: &[Row], kind: ActionKind) -> Ordinal {
        rows.iter()
            .find(|r| r.kind == kind)
            .and_then(|r| r.responded)
            .expect("the row's response")
    }

    #[test]
    fn a_fragment_payload_matches_the_attempt_geometry() {
        // META + BODY is 48 bytes: one fragment of exactly 48 bytes.
        let mut rows = spaced_failed_upload();
        for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Fragment) {
            row.payload = Some(vec![1; 47]);
        }
        assert_eq!(
            assert_violates(&sealed(rows), Obligation::History),
            "a fragment's payload disagrees with the attempt's manifest"
        );
    }

    #[test]
    fn a_publication_and_a_write_submission_are_invoked_after_ready() {
        let mut rows = spaced_failed_upload();
        let op = rows[0].op;
        let ready = responded(&rows, ActionKind::Ready);
        let ack = responded(&rows, ActionKind::Ack);
        let mut submit = Row::new(op, ActionKind::WriteSubmit);
        submit.subject = Some(Subject::Resource(ResourceId {
            kind: ResourceKind::Command,
            index: 0,
        }));
        submit.episode = rows[0].episode;
        submit.incarnation = rows.iter().find_map(|r| r.incarnation);
        submit.serial = Serial::new(u64::from(op.0));
        submit.invoked = Some(Ordinal(ready.0 - 5));
        submit.responded = Some(Ordinal(ack.0 + 5));
        rows.push(submit);
        assert_eq!(
            assert_violates(&sealed(rows), Obligation::History),
            "the attempt's phases are out of order"
        );
    }

    #[test]
    fn a_failed_result_after_the_authority_names_the_serial() {
        let unnamed = edited(&failed_upload(), |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::PutResult) {
                row.serial = None;
            }
        });
        assert_eq!(
            assert_violates(&unnamed, Obligation::History),
            "a Failed result after the authority names no serial"
        );
        let mut refused = Script::new();
        let op = refused.put_begin(K, A, BODY, false);
        refused.put_result(op, K, A, FAILED);
        let refused = edited(&refused.finish(), |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::PutResult) {
                row.serial = None;
            }
        });
        passes(&refused, &[Obligation::History]);
    }

    fn with_fragment(rows: &mut Vec<Row>, index: u32, byte: u8, after: Ordinal) {
        let op = rows[0].op;
        let mut fragment = Row::new(op, ActionKind::Fragment);
        fragment.subject = Some(Subject::Key(K));
        fragment.episode = rows[0].episode;
        fragment.serial = Serial::new(u64::from(op.0));
        fragment.fragment = Some(index);
        fragment.payload = Some(vec![byte; 48]);
        fragment.responded = Some(after);
        rows.push(fragment);
    }

    fn sealed(rows: Vec<Row>) -> History {
        let mut history = History::new();
        for row in rows {
            history.push(row);
        }
        history.seal();
        history
    }

    #[test]
    fn an_attempt_validates_each_fragment_once() {
        let mut rows = spaced_failed_upload();
        let ready = responded(&rows, ActionKind::Ready);
        passes(&sealed(rows.clone()), &[Obligation::History]);
        with_fragment(&mut rows, 0, 2, Ordinal(ready.0 + 6));
        assert_eq!(
            assert_violates(&sealed(rows), Obligation::History),
            "an attempt validated one fragment twice"
        );
    }

    #[test]
    fn a_known_result_ends_the_attempt_activity() {
        let mut rows = spaced_failed_upload();
        let result = responded(&rows, ActionKind::PutResult);
        for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Fragment) {
            row.responded = Some(Ordinal(result.0 + 5));
        }
        assert_eq!(
            assert_violates(&sealed(rows), Obligation::History),
            "attempt activity after a known result"
        );
        let late_ack = edited(&failed_upload(), |rows| {
            let result = responded(rows, ActionKind::PutResult);
            for row in rows.iter_mut().filter(|r| r.kind == ActionKind::Ack) {
                row.responded = Some(Ordinal(result.0 + 1));
            }
        });
        assert_eq!(
            assert_violates(&late_ack, Obligation::History),
            "attempt activity after a known result"
        );
    }

    #[test]
    fn an_abstract_duplicate_publication_stays_outside_the_domain() {
        let abstracted = edited(&matching_retry(true), |rows| {
            for row in rows.iter_mut().filter(|r| {
                matches!(
                    r.kind,
                    ActionKind::Fill
                        | ActionKind::Receive
                        | ActionKind::WriteCompleted
                        | ActionKind::Publish
                )
            }) {
                row.evidence = Evidence::Abstract(RECOVERED);
            }
        });
        let verdict = check(&abstracted);
        assert!(matches!(verdict, Verdict::Inconclusive(_)), "{verdict:?}");
    }

    #[test]
    fn attempt_rows_without_their_begin_stay_outside_the_domain() {
        let claimed = receipt_without_write(PutOutcome::Published, MISSING);
        let op = claimed.rows()[0].op;
        let unopened = edited(&claimed, |rows| {
            rows.retain(|r| r.kind != ActionKind::PutBegin);
        });
        assert_eq!(
            check(&unopened),
            Verdict::Inconclusive(Inconclusive::Malformed {
                op,
                field: Field::Invocation,
            })
        );
    }

    #[test]
    fn one_attempt_opens_with_one_begin() {
        let doubled = edited(&put_then_get(bytes(K, A, BODY)), |rows| {
            let mut again = rows
                .iter()
                .find(|r| r.kind == ActionKind::PutBegin)
                .cloned()
                .expect("the begin row");
            let last = rows
                .iter()
                .filter_map(|r| r.custody_end.or(r.responded))
                .max()
                .expect("an ordinal");
            again.invoked = Some(Ordinal(last.0 + 1));
            again.responded = Some(Ordinal(last.0 + 2));
            rows.push(again);
        });
        let begin = doubled
            .rows()
            .iter()
            .find(|r| r.kind == ActionKind::PutBegin)
            .map(|r| r.op)
            .expect("the begin row");
        assert_eq!(
            check(&doubled),
            Verdict::Inconclusive(Inconclusive::Malformed {
                op: begin,
                field: Field::Invocation,
            })
        );
    }
}

const COVERED: &str = "a hit of a version an acknowledged invalidation covered";
const UNPUBLISHED: &str = "a hit of a version no linearized fill published";
const REMOVED: &str = "a hit after a recorded removal of its label in the same tenure";
const BELOW_HIGH_WATER: &str = "a client accepted a response tagged below its high-water";
const HIGH_WATER_FELL: &str = "a client's recorded high-water fell";

fn passes_history(history: &History) -> Activations {
    match check(history) {
        Verdict::Pass(activations) if activations.count(Obligation::History) > 0 => activations,
        verdict => panic!("expected a History pass, got {verdict:?}"),
    }
}

fn names(history: &History, obligation: Obligation, rule: &str) {
    assert_eq!(assert_violates(history, obligation), rule);
}

/// Every history the tenure-ordered contract permits passes: a deposed
/// tenure's read by a client below its successor, a miss then a hit with no
/// restart, an older uncovered version after a restart, a lookup
/// overlapping an invalidation, a deposed fill then a successor miss, a
/// timed-out invalidation then a later tenure's hit, a restarted client
/// accepting a deposed tenure, a crashed client's unknown invalidation
/// followed by its restarted instance's read, a client rejecting a stale
/// response, once or duplicated, or one above its high-water, and a later
/// tenure's eviction while an earlier tenure's fill is open.
#[test]
fn tenure_order_legal_cases() {
    for (case, history) in legal() {
        let verdict = check(&history);
        assert!(
            verdict.satisfies(&[Obligation::History]),
            "{case}: {verdict:?}"
        );
    }
}

/// Every outcome the contract forbids fails by its own rule, the deposed
/// hit included once its reader's high-water reaches the successor, as
/// does the crashed client's read without a restart, a recorded
/// high-water falling below one the client never accepted, a fill
/// published by a later tenure, an effect landing in a tenure activated
/// after its window, a target naming a tenure unlogged at its
/// invocation, and a lower tenure's answer accepted after a higher one's,
/// whether it is recovery evidence, a contended reply or an answer of the
/// generation's earlier attachment.
#[test]
fn tenure_order_violations() {
    names(
        &crashed_client_then_hit(false),
        Obligation::History,
        BELOW_HIGH_WATER,
    );
    names(
        &recorded_high_water_fell(),
        Obligation::History,
        HIGH_WATER_FELL,
    );
    names(
        &fill_published_by_successor(),
        Obligation::History,
        "a fill revoked by an invalidation or a tenure change published",
    );
    names(
        &landing_after_window(),
        Obligation::History,
        "an eviction while a fill is current",
    );
    for (later, tenure) in [(false, T9), (true, T2)] {
        assert!(
            matches!(
                check(&unlogged_target(later)),
                Verdict::Inconclusive(Inconclusive::UnloggedTenure { tenure: named, .. }) if named == tenure
            ),
            "{later}"
        );
    }
    names(
        &covered_hit_by_another_client(),
        Obligation::History,
        COVERED,
    );
    names(
        &covered_hit_from_later_tenure(),
        Obligation::History,
        COVERED,
    );
    names(&covered_hit_after_restart(), Obligation::History, COVERED);
    names(
        &duplicated_invalidation_then_hit(),
        Obligation::History,
        COVERED,
    );
    names(
        &deposed_hit(Some(T2)),
        Obligation::History,
        BELOW_HIGH_WATER,
    );
    names(
        &accepted_below_high_water(None),
        Obligation::History,
        BELOW_HIGH_WATER,
    );
    names(
        &accepted_below_high_water(Some(T1)),
        Obligation::History,
        HIGH_WATER_FELL,
    );
    names(
        &rejected_then_high_water_fell(),
        Obligation::History,
        HIGH_WATER_FELL,
    );
    names(
        &rejected_unpublished_hit(),
        Obligation::History,
        UNPUBLISHED,
    );
    for history in [deposed_serves_successor_fill(), deposed_serves_later_fill()] {
        names(
            &history,
            Obligation::History,
            "a tenure served a version only a later tenure published",
        );
    }
    names(
        &wrong_bytes(),
        Obligation::Bytes,
        "a complete read returned bytes other than the label's content",
    );
    for refused in [false, true] {
        names(&unpublished_hit(refused), Obligation::History, UNPUBLISHED);
    }
    names(
        &hit_at_deadline(),
        Obligation::History,
        "a hit at or past the deadline",
    );
    assert!(matches!(
        check(&unlogged_tag()),
        Verdict::Inconclusive(Inconclusive::UnloggedTenure { tenure, .. }) if tenure == T2
    ));
    assert!(matches!(
        check(&unlogged_high_water()),
        Verdict::Inconclusive(Inconclusive::UnloggedTenure { tenure, .. }) if tenure == T9
    ));
    for answer in LowerAnswer::ALL {
        assert_eq!(
            assert_violates(&lower_answer_accepted(answer), Obligation::History),
            BELOW_HIGH_WATER,
            "{answer:?}"
        );
    }
}

#[test]
fn outage_miss_then_hit_is_legal() {
    let verdict = check(&outage_miss_then_hit());
    assert!(
        verdict.satisfies(&[Obligation::History, Obligation::Bytes]),
        "{verdict:?}"
    );
}

#[test]
fn outage_covered_twin_fails() {
    names(&outage_covered_twin(), Obligation::History, COVERED);
}

/// An interval covers an absent version; versions just outside it stay
/// eligible; every-version coverage excludes each version, a later
/// publication's included, versioned or not; an unversioned invalidation
/// covers only what was published, revoking a fill in flight without
/// covering its label; an interval revokes a live fill only for the
/// versions it covers; a recorded eviction of a covered label fails by
/// name; an unknown-outcome invalidation keeps its landed branch; an
/// unversioned publication on a key an interval names is malformed.
#[test]
fn coverage_cases() {
    names(&absent_version_covered(), Obligation::History, COVERED);
    passes_history(&versions_outside_the_interval());
    for label in [A, B] {
        names(&all_versions_covered(label), Obligation::History, COVERED);
    }
    for versioned in [true, false] {
        names(
            &all_versions_then_later_publication(versioned),
            Obligation::History,
            COVERED,
        );
    }
    passes_history(&unversioned_then_later_publication());
    passes_history(&range_over_live_fill(3));
    names(
        &range_over_live_fill(2),
        Obligation::History,
        "a fill revoked by an invalidation or a tenure change published",
    );
    passes_history(&refilled_after_invalidation());
    names(
        &eviction_of_covered_label(),
        Obligation::History,
        "a removal selected a label an invalidation covered",
    );
    let landed = check(&eviction_after_pending_invalidation());
    assert!(matches!(landed, Verdict::Pass(_)), "{landed:?}");
    let mut s = Script::new();
    let mut invalidate = s.begin_invalidate(K);
    invalidate.set_covers(Cover::Range { lo: 1, hi: 2 });
    s.close(invalidate, Some(ACK));
    let publication = s.publish(K, A, BODY);
    assert_eq!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: publication,
            field: Field::Version,
        })
    );
}

/// A tenure removes an entry once: a hit after a recorded removal of its
/// label fails until a restart starts a new tenure or a recorded restore
/// of the label follows the removal, and a slot release's removal belongs
/// to the releasing tenure's segment.
#[test]
fn recorded_removal_then_hit() {
    names(&deposed_slot_eviction(T1), Obligation::History, REMOVED);
    passes_history(&deposed_slot_eviction(T2));
    for removal in Removal::ALL {
        assert_eq!(
            assert_violates(&removal_then_hit(removal, false), Obligation::History),
            REMOVED,
            "{removal:?}"
        );
        let verdict = check(&removal_then_hit(removal, true));
        assert!(
            verdict.satisfies(&[Obligation::History]),
            "{removal:?}: {verdict:?}"
        );
    }
}

/// A restore is judged at residency against the coverage and the named
/// checkpoint, whether or not a hit follows.
#[test]
fn recorded_restore_cases() {
    names(
        &restored(Restored::Covered),
        Obligation::History,
        "a recorded restore of a covered version",
    );
    names(
        &restored(Restored::OtherCut),
        Obligation::History,
        "a recorded restore from a checkpoint the store did not name",
    );
    names(
        &restore_of_unpublished(),
        Obligation::History,
        "a recorded restore of a version never published",
    );
    for case in [Restored::Uncovered, Restored::AgainAfterEviction] {
        let verdict = check(&restored(case));
        assert!(
            verdict.satisfies(&[Obligation::History, Obligation::Restart]),
            "{case:?}: {verdict:?}"
        );
    }
}

/// A pending publication lands only in its target tenure's segment, after
/// its invocation, and with an unrecorded target at or above its floor, or
/// with no recorded floor at or above the client's high-water at send; with
/// no recorded target the verdict counts the weaker scope.
#[test]
fn pending_target_tenure() {
    for case in [
        Pending::BoundLater,
        Pending::UnrecordedAboveHit,
        Pending::BoundBeforeInvocation,
        Pending::UnrecordedAboveHighWater,
        Pending::FloorBelowHighWater,
    ] {
        assert_eq!(
            assert_violates(&targeted_publication(case), Obligation::History),
            UNPUBLISHED,
            "{case:?}"
        );
    }
    // Only B's sample differs between the twins: landing B's publication
    // before A's, against real time, is the one order that would pass the
    // regressed twin.
    let at_send = passes_history(&floor_taken_at_send());
    assert_eq!(at_send.unrecorded_targets, 1);
    let above = passes_history(&untargeted_publication_above_floor());
    assert_eq!(above.unrecorded_targets, 1);
    passes_history(&unbound_publications_in_order(25));
    let closed = check(&invalidation_landing_after_close());
    assert!(matches!(closed, Verdict::Pass(_)), "{closed:?}");
    let above_tag = check(&invalidation_floor_above_tag_after_close());
    assert!(matches!(above_tag, Verdict::Pass(_)), "{above_tag:?}");
    names(
        &publication_after_fill_tenure_closed(),
        Obligation::History,
        UNPUBLISHED,
    );
    let held = check(&unbound_effect_after_held_miss());
    assert!(matches!(held, Verdict::Pass(_)), "{held:?}");
    assert_violates(&unbound_publications_in_order(5), Obligation::History);
    // Across keys, the searches place the two publications independently:
    // an in-order pair passes, an out-of-order pair that may share T1 is
    // withheld, and a bound T1 sample between them lets a search reject it.
    let across = passes_history(&unbound_publications_across_keys(25, false));
    assert_eq!(across.unrecorded_targets, 2);
    let regressed = unbound_publications_across_keys(5, false);
    let later = regressed
        .rows()
        .iter()
        .filter(|row| row.kind == ActionKind::Publish)
        .map(|row| row.op)
        .max()
        .expect("the later publication");
    assert_eq!(
        check(&regressed),
        Verdict::Inconclusive(Inconclusive::UnplacedSample { op: later })
    );
    assert_eq!(
        assert_violates(
            &unbound_publications_across_keys(5, true),
            Obligation::History
        ),
        "a clock sample regressed behind an earlier one"
    );
    let bound = passes_history(&targeted_publication(Pending::BoundSame));
    assert_eq!(bound.unrecorded_targets, 0);
    let weaker = passes_history(&targeted_publication(Pending::Unrecorded));
    assert_eq!(weaker.unrecorded_targets, 1);
}

/// Clock and expiry rules hold inside one tenure's clock domain: a sample
/// may fall, a close stops answering, and a deadline binds only within the
/// tenure that sampled them, and each twin inside one tenure fails. A
/// deadline judgment that would cross tenures is counted as a weaker scope,
/// as is one for an unrecorded-target publication that lands below its
/// hit's tenure, whose sample no other tenure's clock bounds.
#[test]
fn clock_domain_cases() {
    passes_history(&sample_across_activation(true));
    names(
        &sample_across_activation(false),
        Obligation::History,
        "a clock sample regressed behind an earlier one",
    );
    passes_history(&hit_after_close(true));
    names(
        &hit_after_close(false),
        Obligation::History,
        "a lookup answered after the cache closed",
    );
    for (outcome, rule) in [
        (HIT, "a hit at or past the deadline"),
        (
            Outcome::Expired,
            "Expired without a published label past its deadline",
        ),
    ] {
        let across = passes_history(&deadline_across_activation(true, outcome));
        assert_eq!(across.cross_tenure_deadlines, 1, "{outcome:?}");
        names(
            &deadline_across_activation(false, outcome),
            Obligation::History,
            rule,
        );
    }
    // An expiry before its deadline passes only when the deadline lies in
    // another tenure's clock domain, which the verdict counts as unjudged.
    let Verdict::Pass(expiry) = check(&expiry_across_activation(true)) else {
        panic!("an expiry across an activation passes");
    };
    assert_eq!(expiry.cross_tenure_deadlines, 1);
    names(
        &expiry_across_activation(false),
        Obligation::History,
        "expiry removed a label before its deadline",
    );
    let Verdict::Pass(end) = check(&expiry_end_across_activation(true, true)) else {
        panic!("an expiry end across an activation passes");
    };
    assert_eq!(end.cross_tenure_deadlines, 1);
    names(
        &expiry_end_across_activation(false, true),
        Obligation::History,
        "a visibility end by expiry before the deadline",
    );
    let Verdict::Pass(unrecorded) = check(&expiry_end_across_activation(true, false)) else {
        panic!("an end that records nothing passes");
    };
    assert_eq!(unrecorded.cross_tenure_deadlines, 0);
    let within = passes_history(&outage_miss_then_hit());
    assert_eq!(within.cross_tenure_deadlines, 0);
    let unrecorded = passes_history(&unrecorded_route_publication());
    assert_eq!(
        (
            unrecorded.cross_tenure_deadlines,
            unrecorded.unrecorded_targets
        ),
        (1, 1)
    );
    // A sample past the deadline clears the expiry end when it lies in the
    // end's clock domain, and leaves the verdict to the landing segment
    // when the sampling effect may land in either of two segments.
    for (target, restarted) in [
        (Some(Place::In(Tenure::INITIAL)), false),
        (None, false),
        (Some(Place::In(T1)), true),
    ] {
        let verdict = check(&expiry_end_after_pending_sample(target, restarted));
        assert!(
            matches!(verdict, Verdict::Pass(_)),
            "{target:?}: {verdict:?}"
        );
    }
    // A refused effect whose window ended before the next activation takes
    // effect before every later operation of its timeline, so its sample
    // reaches no later tenure's clock under a shared ordinal; the lenient
    // reading leaves a client's landing open to every tenure and the strict
    // one decides.
    let early = "a visibility end by expiry before the deadline";
    names(
        &refusal_sampled_in_an_earlier_tenure(),
        Obligation::History,
        early,
    );
    assert!(matches!(
        check(&per_client(refusal_sampled_in_an_earlier_tenure())),
        Verdict::Inconclusive(Inconclusive::CrossClientOrder { .. })
    ));
    let unplaced = expiry_end_after_pending_sample(None, true);
    let end = unplaced.rows().last().expect("the visibility end").op;
    assert_eq!(
        check(&unplaced),
        Verdict::Inconclusive(Inconclusive::UnplacedSample { op: end })
    );
    // An unplaced sample on one key leaves the others judged, and their
    // definite violation is the verdict.
    names(
        &unplaced_then_unpublished_hit(),
        Obligation::History,
        UNPUBLISHED,
    );
    names(
        &unplaced_sample_at_collapse_then_unpublished_hit(),
        Obligation::History,
        UNPUBLISHED,
    );
    names(
        &unplaced_then_wrong_bytes(),
        Obligation::Bytes,
        "a complete read returned bytes other than the label's content",
    );
    let at_collapse = unplaced_sample_at_collapse();
    let end = at_collapse.rows().last().expect("the visibility end").op;
    assert_eq!(
        check(&at_collapse),
        Verdict::Inconclusive(Inconclusive::UnplacedSample { op: end })
    );
    // An effect with an unrecorded target uses its segment's clock, so
    // other keys' samples in that segment constrain its sample. A later
    // activated segment allowed by the target's floor supplies a fresh
    // clock.
    let regressed = "a clock sample regressed behind an earlier one";
    for target in [Place::In(T1), Place::AtLeast(T1)] {
        for (beside, other) in [(Beside::After, 55), (Beside::Before, 1)] {
            passes_history(&unbound_sample_beside_other_key(target, beside, other));
        }
        for (beside, other) in [(Beside::After, 1), (Beside::Before, 50)] {
            let history = unbound_sample_beside_other_key(target, beside, other);
            assert_eq!(
                assert_violates(&history, Obligation::History),
                regressed,
                "{target:?} {beside:?}"
            );
        }
    }
    for target in [Place::AtLeast(T1), Place::In(T2)] {
        passes_history(&unbound_effect_sampled_below_its_floor(target, &[T1, T2]));
    }
    for (target, tenures) in [
        (Place::AtLeast(T1), &[T1][..]),
        (Place::In(T1), &[T1, T2][..]),
    ] {
        let history = unbound_effect_sampled_below_its_floor(target, tenures);
        assert_eq!(
            assert_violates(&history, Obligation::History),
            regressed,
            "{target:?} {tenures:?}"
        );
    }
}

/// Under per-client ordinals, a failure that depends on ordering between
/// timelines is inconclusive.
#[test]
fn per_client_ordinal_cases() {
    let cross = covered_hit_by_another_client();
    let Verdict::Violation(shared) = check(&cross) else {
        panic!("the shared-ordinal history fails");
    };
    assert_eq!(
        check(&per_client(cross)),
        Verdict::Inconclusive(Inconclusive::CrossClientOrder { op: shared.op })
    );
    // A receive after another client's acknowledged invalidation is out of
    // the domain under a shared ordinal, which orders the two clients, and
    // judged under per-client ordinals, which order each client alone.
    let received = receive_after_another_clients_invalidation();
    assert!(matches!(
        check(&received),
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: Field::Invocation,
            ..
        })
    ));
    assert!(matches!(check(&per_client(received)), Verdict::Pass(_)));
    let interleaved = passes_history(&per_client(hit_then_invalidation_by_another_client()));
    assert_eq!(interleaved.cross_timeline_orders, 5);
    assert_eq!(
        passes_history(&hit_then_invalidation_by_another_client()).cross_timeline_orders,
        0
    );
    names(
        &per_client(covered_hit_by_the_same_client()),
        Obligation::History,
        COVERED,
    );
    names(
        &per_client(covered_hit_from_later_tenure()),
        Obligation::History,
        COVERED,
    );
    names(
        &per_client(accepted_below_high_water(None)),
        Obligation::History,
        BELOW_HIGH_WATER,
    );
    passes_history(&per_client(deposed_hit_below_successor()));

    let early = "a visibility end by expiry before the deadline";
    for history in [
        expiry_end_after_sample(Sampler::Nobody),
        per_client(expiry_end_after_sample(Sampler::Nobody)),
    ] {
        names(&history, Obligation::History, early);
    }
    passes_history(&expiry_end_after_sample(Sampler::Owner));
    passes_history(&per_client(expiry_end_after_sample(Sampler::Owner)));
    let sampled = expiry_end_after_sample(Sampler::OtherClient);
    passes_history(&sampled);
    let end = sampled.rows().last().expect("the visibility end").op;
    assert_eq!(
        check(&per_client(sampled)),
        Verdict::Inconclusive(Inconclusive::CrossClientOrder { op: end })
    );

    let mixed = covered_hit_after_cross_client_expiry();
    names(&mixed, Obligation::History, COVERED);
    assert!(matches!(
        check(&per_client(mixed)),
        Verdict::Inconclusive(Inconclusive::CrossClientOrder { .. })
    ));

    let behind = client_counter_behind_owner();
    assert!(matches!(
        check(&behind),
        Verdict::Inconclusive(Inconclusive::UnloggedTenure { tenure, .. }) if tenure == T2
    ));
    passes_history(&per_client(behind));

    let recovered = retained(Retained::Restored);
    let captured = recovered
        .rows()
        .iter()
        .find(|row| row.kind == ActionKind::Captured)
        .expect("a captured entry")
        .op;
    assert_eq!(
        check(&per_client(recovered)),
        Verdict::Inconclusive(Inconclusive::PerClientScope { op: captured })
    );
    for (case, (history, op)) in per_client_scope_rows() {
        assert_eq!(
            check(&per_client(history)),
            Verdict::Inconclusive(Inconclusive::PerClientScope { op }),
            "{case}"
        );
    }
}

/// One history for each row only a shared ordinal lets the checker judge,
/// each matching that one condition, with the operation it names: an
/// untagged client row, an operation two clients share, a restart naming a
/// cut, a restart a client recorded, a recovery row other than a restart,
/// and a row of a kind outside the per-client kinds. A row naming an upload
/// serial shares its operation with a `PutBegin`, which the kind condition
/// names.
fn per_client_scope_rows() -> [(&'static str, (History, OpId)); 6] {
    let untagged = {
        let mut s = Script::new();
        s.by_client(Some(C1));
        let invalidation = s.begin_invalidate(K);
        let op = s.close(
            invalidation,
            Some(Outcome::NoInformation(NoInformation::TimedOut)),
        );
        (s.finish(), op)
    };
    let shared = {
        let mut s = Script::new();
        s.in_tenure(Some(Tenure::INITIAL));
        s.by_client(Some(C1));
        let fill = s.fill(K, A, BODY);
        s.by_client(Some(C2));
        let publish = s.open(fill, ActionKind::Publish, K, Some(A));
        s.close(publish, Some(ACK));
        (s.finish(), fill)
    };
    let cut = {
        let mut s = Script::new();
        let op = s.activate(RECOVERED, Some(T1), Some(CUT));
        (s.finish(), op)
    };
    let client_restart = {
        let mut s = Script::new();
        let op = s.activate(RECOVERED, Some(T1), None);
        let history = edited(&s.finish(), |rows| {
            rows.last_mut().expect("the restart").client = Some(C1);
        });
        (history, op)
    };
    let recovered = {
        let mut s = Script::new();
        s.restart(RECOVERED, K);
        s.recovered_lookup(RECOVERED, K, MISSING, None);
        let op = s.finish();
        let lookup = op.rows().last().expect("the recovered lookup").op;
        (op, lookup)
    };
    let outside = {
        let mut s = Script::new();
        s.session_change(super::ids::SessionId(2));
        let history = s.finish();
        let op = history.rows()[0].op;
        (history, op)
    };
    [
        ("untagged client row", untagged),
        ("shared operation", shared),
        ("restart naming a cut", cut),
        ("restart a client recorded", client_restart),
        ("recovery row", recovered),
        ("kind outside the per-client kinds", outside),
    ]
}

/// The exact-outcome, retry and duplicate-publication rules hold under the
/// coverage model.
#[test]
fn retained_controls() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let fill = s.fill(K, A, BODY);
    let again = s.open(fill, ActionKind::Replace, K, Some(A));
    s.close(again, Some(Outcome::Acknowledged));
    names(
        &s.finish(),
        Obligation::History,
        "a publication label was published twice",
    );
    names(
        &matching_retry(true),
        Obligation::History,
        "an attempt published twice",
    );
    names(
        &receipt_without_write(PutOutcome::Published, MISSING),
        Obligation::History,
        "Published without the attempt's publication",
    );
    names(
        &receipt_without_write(FAILED, HIT),
        Obligation::History,
        UNPUBLISHED,
    );
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(REFUSED));
    s.lookup(K, HIT, Some(B));
    names(&s.finish(), Obligation::History, UNPUBLISHED);
}

/// Disabling each rule flips the verdict of a golden it decides; with every
/// rule in force the goldens keep their verdicts.
#[test]
fn rule_controls() {
    let controls = [
        (Rule::TenureOrder, deposed_hit(None)),
        (Rule::AbsentCoverage, absent_version_covered()),
        (Rule::HighWater, accepted_below_high_water(None)),
        (Rule::TagReconciliation, unlogged_tag()),
        (Rule::EvidenceClass, removal_then_hit(Removal::Evict, false)),
    ];
    for (rule, history) in controls {
        let enforced = matches!(check(&history), Verdict::Pass(_));
        let disabled = without(rule, || matches!(check(&history), Verdict::Pass(_)));
        assert_ne!(enforced, disabled, "{rule:?}");
    }
    let unordered = without(Rule::TenureOrder, || check(&deposed_hit(None)));
    assert_eq!(unordered.violated(), Some((Obligation::History, COVERED)));
}
