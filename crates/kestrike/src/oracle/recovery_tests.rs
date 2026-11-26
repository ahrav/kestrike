//! Abstract recovery goldens and rejection witnesses: the evidence ledger
//! under each hypothesis, admission and authority facts, and restart.

use super::action::ActionKind;
use super::checker::check;
use super::coverage::Cover;
use super::evidence::{Decision, DurableFact, Evidence};
use super::golden::*;
use super::history::History;
use super::ids::{ClientId, CutId, KeyId, Label, Tenure};
use super::obligation::Obligation;
use super::outcome::{Failure, NoInformation, Outcome};
use super::script::Script;
use super::verdict::{Inconclusive, Verdict};

#[test]
fn golden_8_completion_as_durability_control_fails_restart() {
    let original = check(&completion_as_durability(false));
    assert!(original.satisfies(&[Obligation::Restart]), "{original:?}");
    assert_eq!(
        assert_violates(&completion_as_durability(true), Obligation::Restart),
        "a write completion was taken as durable payload evidence"
    );
}

#[test]
fn an_upload_receipt_and_write_completion_are_no_durable_payload_evidence() {
    let original = check(&upload_as_durability(false));
    assert!(original.satisfies(&[Obligation::Restart]), "{original:?}");
    assert_eq!(
        assert_violates(&upload_as_durability(true), Obligation::Restart),
        "a write completion was taken as durable payload evidence"
    );
}

#[test]
fn golden_9_recovery_needs_every_fact_and_keeps_exclusions() {
    let served = check(&recovered(None, false, HIT));
    assert!(served.satisfies(&[Obligation::Restart]), "{served:?}");
    assert!(check(&recovered(None, true, MISSING)).satisfies(&[Obligation::Restart]));
    assert_eq!(
        assert_violates(&recovered(None, true, HIT), Obligation::Restart),
        "a recovery-safe exclusion was revived after restart"
    );
    for withheld in [DurableFact::Freshness, DurableFact::PortableExpiry] {
        assert!(
            check(&recovered(Some(withheld), false, MISSING)).satisfies(&[Obligation::Restart])
        );
        assert_violates(&recovered(Some(withheld), false, HIT), Obligation::Restart);
    }
    assert!(check(&b_or_miss(MISSING, None)).satisfies(&[Obligation::Restart]));
    assert_violates(&b_or_miss(HIT, Some(A)), Obligation::Restart);
    assert_eq!(
        assert_violates(&b_or_miss(HIT, Some(B)), Obligation::Restart),
        "a recovered candidate was found without admission"
    );
}

#[test]
fn golden_9_a_row_on_an_open_recovery_decision_is_inconclusive() {
    let history = b_or_miss(MISSING, None);
    let op = history.rows().last().unwrap().op;
    let marked = edited(&history, |rows| {
        rows.last_mut().unwrap().unresolved = Some(Decision::DurableBeforeExclusion);
    });
    assert_eq!(
        check(&marked),
        Verdict::Inconclusive(Inconclusive::Unresolved {
            op,
            decision: Decision::DurableBeforeExclusion,
        })
    );
}

#[test]
fn every_admission_and_authority_fact_is_required() {
    for withheld in ADMISSION {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        for fact in ADMISSION.into_iter().filter(|&f| f != withheld) {
            s.fact(RECOVERED, K, A, fact);
        }
        s.admission(RECOVERED, K, A);
        assert_violates(&s.finish(), Obligation::Restart);
    }
    for withheld in AUTHORITY {
        assert!(
            check(&recovered(Some(withheld), false, MISSING)).satisfies(&[Obligation::Restart])
        );
        assert_violates(&recovered(Some(withheld), false, HIT), Obligation::Restart);
    }
}

#[test]
fn facts_stay_inside_their_hypothesis() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for fact in ADMISSION.into_iter().chain(AUTHORITY) {
        s.fact(RECOVERED, K, A, fact);
    }
    s.admission(B_OR_MISS, K, A);
    assert_violates(&s.finish(), Obligation::Restart);
}

#[test]
fn b_or_miss_accepts_b_and_missing_and_rejects_a() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(ACK));
    for fact in ADMISSION.into_iter().chain(AUTHORITY) {
        s.fact(B_OR_MISS, K, A, fact);
        s.fact(B_OR_MISS, K, B, fact);
    }
    s.admission(B_OR_MISS, K, A);
    s.admission(B_OR_MISS, K, B);
    s.fact(B_OR_MISS, K, A, DurableFact::RecoveryExclusion);
    s.restart(B_OR_MISS, K);
    let base = s;
    let accepted = |outcome, label| {
        let mut s = base.clone();
        s.recovered_lookup(B_OR_MISS, K, outcome, label);
        check(&s.finish())
    };
    assert!(accepted(HIT, Some(B)).satisfies(&[Obligation::Restart]));
    assert!(accepted(MISSING, None).satisfies(&[Obligation::Restart]));
    assert!(matches!(accepted(HIT, Some(A)), Verdict::Violation(_)));
}

#[test]
fn a_live_invalidation_is_not_a_recovery_safe_exclusion() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.invalidate(K, ACK);
    for fact in ADMISSION.into_iter().chain(AUTHORITY) {
        s.fact(RECOVERED, K, A, fact);
    }
    s.admission(RECOVERED, K, A);
    s.restart(RECOVERED, K);
    s.recovered_lookup(RECOVERED, K, HIT, Some(A));
    assert!(check(&s.finish()).satisfies(&[Obligation::Restart]));
}

#[test]
fn a_recovered_lookup_before_restart_is_a_violation() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.recovered_lookup(RECOVERED, K, HIT, Some(A));
    assert_violates(&s.finish(), Obligation::Restart);
}

#[test]
fn a_recovered_expired_candidate_needs_admission_and_no_exclusion() {
    let found = |excluded, admitted| {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        s.fact(RECOVERED, K, A, DurableFact::PortableExpiry);
        if admitted {
            for fact in ADMISSION {
                s.fact(RECOVERED, K, A, fact);
            }
            s.admission(RECOVERED, K, A);
        }
        if excluded {
            s.fact(RECOVERED, K, A, DurableFact::RecoveryExclusion);
        }
        s.restart(RECOVERED, K);
        s.recovered_lookup(RECOVERED, K, Outcome::Expired, Some(A));
        s.finish()
    };
    assert!(check(&found(false, true)).satisfies(&[Obligation::Restart]));
    assert_eq!(
        assert_violates(&found(true, true), Obligation::Restart),
        "a recovery-safe exclusion was revived after restart"
    );
    assert_eq!(
        assert_violates(&found(false, false), Obligation::Restart),
        "a recovered candidate was found without admission"
    );
}

#[test]
fn a_recovered_candidate_is_judged_on_its_owner_keys_facts() {
    let recovered = |admitted: bool| {
        let mut s = Script::new();
        s.publish(J, C, BODY);
        if admitted {
            for fact in ADMISSION.into_iter().chain(AUTHORITY) {
                s.fact(RECOVERED, J, C, fact);
            }
            s.admission(RECOVERED, J, C);
        }
        s.restart(RECOVERED, K);
        s.recovered_lookup(RECOVERED, K, HIT, Some(C));
        edited(&s.finish(), |rows| {
            let lookup = rows.iter_mut().rev().find(|r| r.kind == ActionKind::Lookup);
            lookup.unwrap().candidate_key = Some(J);
        })
    };
    assert!(check(&recovered(true)).satisfies(&[Obligation::Restart]));
    assert_eq!(
        assert_violates(&recovered(false), Obligation::Restart),
        "a recovered candidate was found without admission"
    );
}

#[test]
fn abstract_evidence_with_a_no_information_outcome_adds_nothing() {
    let history = recovered(None, false, HIT);
    for kind in [
        ActionKind::Admission,
        ActionKind::Persistence,
        ActionKind::Restart,
    ] {
        let refused = edited(&history, |rows| {
            for row in rows.iter_mut().filter(|r| r.kind == kind) {
                row.outcome = Some(REFUSED);
            }
        });
        assert_violates(&refused, Obligation::Restart);
    }
}

#[test]
fn a_recovered_lookup_is_invoked_after_the_restart_responded() {
    let overlapping = edited(&recovered(None, false, HIT), |rows| {
        let restart = rows
            .iter()
            .position(|r| r.kind == ActionKind::Restart)
            .unwrap();
        let lookup = rows
            .iter()
            .rposition(|r| r.kind == ActionKind::Lookup)
            .unwrap();
        let before = rows[restart].responded;
        rows[restart].responded = rows[lookup].invoked;
        rows[lookup].invoked = before;
    });
    assert_eq!(
        assert_violates(&overlapping, Obligation::Restart),
        "recovered acquisition precedes restart"
    );
}

#[test]
fn restart_activates_only_at_a_recovered_lookup() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for fact in ADMISSION {
        s.fact(RECOVERED, K, A, fact);
    }
    s.admission(RECOVERED, K, A);
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
    assert!(!verdict.satisfies(&[Obligation::Restart]));
}

#[test]
fn one_recovered_lookup_row_per_operation() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for fact in ADMISSION.into_iter().chain(AUTHORITY) {
        s.fact(RECOVERED, K, A, fact);
    }
    s.admission(RECOVERED, K, A);
    s.restart(RECOVERED, K);
    s.recovered_lookup(RECOVERED, K, HIT, Some(A));
    s.recovered_lookup(RECOVERED, K, MISSING, None);
    let mut op = None;
    let reused = edited(&s.finish(), |rows| {
        let mut lookups = rows.iter_mut().filter(|r| r.kind == ActionKind::Lookup);
        let first = lookups.next().unwrap().op;
        lookups.next().unwrap().op = first;
        op = Some(first);
    });
    assert_eq!(
        check(&reused),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: op.unwrap(),
            field: super::row::Field::Invocation,
        })
    );
}

#[test]
fn a_recovered_expiry_needs_portable_expiry_authority() {
    let found = |facts: &[DurableFact]| {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        for &fact in ADMISSION.iter().chain(facts) {
            s.fact(RECOVERED, K, A, fact);
        }
        s.admission(RECOVERED, K, A);
        s.restart(RECOVERED, K);
        s.recovered_lookup(RECOVERED, K, Outcome::Expired, Some(A));
        s.finish()
    };
    assert!(check(&found(&[DurableFact::PortableExpiry])).satisfies(&[Obligation::Restart]));
    assert_eq!(
        assert_violates(&found(&[]), Obligation::Restart),
        "a recovered expiry without portable expiry authority"
    );
}

#[test]
fn a_no_information_recovered_lookup_activates_nothing() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for fact in ADMISSION.into_iter().chain(AUTHORITY) {
        s.fact(RECOVERED, K, A, fact);
    }
    s.admission(RECOVERED, K, A);
    s.restart(RECOVERED, K);
    s.recovered_lookup(RECOVERED, K, REFUSED, None);
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
    assert!(!verdict.satisfies(&[Obligation::Restart]));
}

#[test]
fn abstract_evidence_keeps_a_label_with_one_key() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    for fact in ADMISSION.into_iter().chain(AUTHORITY) {
        s.fact(RECOVERED, K, A, fact);
        s.fact(RECOVERED, J, A, fact);
    }
    s.admission(RECOVERED, K, A);
    s.admission(RECOVERED, J, A);
    s.restart(RECOVERED, K);
    s.recovered_lookup(RECOVERED, K, HIT, Some(A));
    s.recovered_lookup(RECOVERED, J, HIT, Some(A));
    assert!(matches!(
        check(&s.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: super::row::Field::Label,
            ..
        })
    ));
}

#[test]
fn recovery_evidence_counts_only_when_recorded_before_restart() {
    for late in [ADMISSION[1], AUTHORITY[0]] {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        for fact in ADMISSION.into_iter().chain(AUTHORITY) {
            if fact != late {
                s.fact(RECOVERED, K, A, fact);
            }
        }
        if late != ADMISSION[1] {
            s.admission(RECOVERED, K, A);
        }
        s.restart(RECOVERED, K);
        s.fact(RECOVERED, K, A, late);
        if late == ADMISSION[1] {
            s.admission(RECOVERED, K, A);
        }
        s.recovered_lookup(RECOVERED, K, HIT, Some(A));
        assert_violates(&s.finish(), Obligation::Restart);
    }
}

#[test]
fn an_abstract_fill_flow_adds_no_fact() {
    let mut s = Script::new();
    let op = s.publish(K, A, BODY);
    s.restart(RECOVERED, K);
    s.recovered_lookup(RECOVERED, K, MISSING, None);
    let hypothetical = edited(&s.finish(), |rows| {
        for row in rows.iter_mut().filter(|r| r.op == op) {
            row.evidence = Evidence::Abstract(RECOVERED);
        }
    });
    let verdict = check(&hypothetical);
    assert!(verdict.satisfies(&[Obligation::Restart]), "{verdict:?}");
}

/// Host loss keeps every retained entry of the named cut outside the damage
/// set: a lost entry fails even when every lookup misses. An earlier
/// tenure's acknowledged invalidation covering the entry, at any ordinal,
/// its recorded expiry, a slot release or eviction recorded after the
/// capture and before the activation, or the recovering tenure's own
/// invalidation before it restores the entry each exclude it; an eviction
/// recorded after the activation, or before a recapture, excludes nothing.
/// A replacement or invalidation that may still land or take effect last
/// leaves the entry unrequired, unless a close leaves it refused, its
/// interval misses the entry's version, an earlier invalidation revoked the
/// replacement's fill, its own sample is past its deadline, its label is
/// already published, its fill's segment lies below the entry's, a later
/// hit rules out the invalidation's landing, or it is recovery evidence the
/// key search does not read; a capture of a pending publication keeps that
/// publication's version, and a restore from a cut no capture recorded
/// fails. A capture whose outcome carries no information captures nothing. A row whose outcome
/// carries no information records no eviction, damage or restore. A
/// recovery-time eviction or visibility end before any restore cannot stand
/// in for one recorded before the loss, damage recorded after the tenure
/// serves excuses nothing, a restore of an entry the cut never captured
/// fails while one the retained set leaves unrequired passes, an effect
/// bound to a later tenure excuses nothing in an earlier recovery, and a
/// cold start, or an activation naming a cut no capture recorded, replaces
/// a captured cut only after whole-volume damage before the first lookup.
#[test]
fn retained_set_after_host_loss() {
    use super::tenure_golden::{
        LaterUse, Removal, Retained, invalidation_bound_above_recovery,
        invalidation_omitted_in_later_tenure, removed_then_recaptured, restore_from_uncaptured_cut,
        retained, superseded_by_earlier_tenure_fill,
        unbound_invalidation_before_forced_publication,
    };
    for case in [
        Retained::Restored,
        Retained::EvictedBefore,
        Retained::ReleasedBefore,
        Retained::ExpiredBefore,
        Retained::ExpiryEndedBefore,
        Retained::CaptureRefused,
        Retained::AllCapturesRefused,
        Retained::SupersededBefore,
        Retained::LateSupersession,
        Retained::OverlappingSupersession,
        Retained::PendingSupersession,
        Retained::LateInvalidation,
        Retained::PendingInvalidation,
        Retained::RangeCoversVersion,
        Retained::PendingPublicationCovered,
        Retained::InvalidatedBeforeRestore,
        Retained::Damaged,
        Retained::DamagedRowUnit,
        Retained::DamagedAfterUnansweredLookup,
        Retained::LaterDuplicateThenPendingInvalidation,
        Retained::PublishedAgainAfterInvalidationRestored,
        Retained::EarlierPendingTwinOmitted,
        Retained::UnorderedThroughMiss,
        Retained::ThroughMissAfterPublication,
        Retained::CoveredEntrySampledAboveLaterLabel,
        Retained::OverlappingSupersessionSampledEqual,
        Retained::OverlappingSupersessionSampledBefore,
        Retained::RestoredNotRequired,
        Retained::ColdStartAfterWholeLoss,
    ] {
        let verdict = check(&retained(case));
        assert!(matches!(verdict, Verdict::Pass(_)), "{case:?}: {verdict:?}");
    }
    let lost = "a retained entry outside every damage set was lost on host loss";
    for removal in Removal::ALL {
        let recaptured = check(&removed_then_recaptured(removal, true));
        assert!(
            matches!(recaptured, Verdict::Pass(_)),
            "{removal:?}: {recaptured:?}"
        );
        assert_eq!(
            assert_violates(
                &removed_then_recaptured(removal, false),
                Obligation::Restart
            ),
            lost,
            "{removal:?}"
        );
    }
    let stale = "a recovery-time stale refusal stood in for a recorded eviction";
    let cold = "host loss replaced a retained cut with a cold start";
    for (case, obligation, rule) in [
        (Retained::Lost, Obligation::Restart, lost),
        (Retained::RefusedEviction, Obligation::Restart, lost),
        (Retained::RevokedSupersession, Obligation::Restart, lost),
        (
            Retained::OverlappingRevokedSupersession,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::OverlappingRevokedSupersessionAcrossActivation,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PublicationForcedAfterPendingInvalidation,
            Obligation::Restart,
            lost,
        ),
        (Retained::LapsedSupersession, Obligation::Restart, lost),
        (Retained::DuplicatePending, Obligation::Restart, lost),
        (Retained::LaterDuplicate, Obligation::Restart, lost),
        (Retained::OrderedOverlap, Obligation::Restart, lost),
        (Retained::OrderedThroughMiss, Obligation::Restart, lost),
        (
            Retained::PendingInvalidationOverlapsPublication,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PendingInvalidationAfterSampledPublication,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::AcknowledgedInvalidationBeforeFill,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PendingInvalidationBeforeEarlierLabel,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PendingInvalidationLandingAboveActivation,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PendingInvalidationBeforeAcknowledgedPublication,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PendingInvalidationBeforeLandedPublication,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PendingInvalidationBeforeLandedPublicationTaggedLater,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::OrderedOverlapAcrossActivation,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PendingInvalidationOmitted,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PendingInvalidationOmittedByExpiry,
            Obligation::Restart,
            lost,
        ),
        (Retained::AbstractInvalidation, Obligation::Restart, lost),
        (
            Retained::UnrecordedCutRestored,
            Obligation::Restart,
            "a recovery restored an entry its cut never captured",
        ),
        (Retained::EvictedAfterActivation, Obligation::Restart, lost),
        (
            Retained::ClosedPendingInvalidation,
            Obligation::Restart,
            lost,
        ),
        (Retained::RangeMissesVersion, Obligation::Restart, lost),
        (
            Retained::PendingPublicationPendingCover,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::OpenPublicationThenPendingInvalidation,
            Obligation::Restart,
            lost,
        ),
        (
            Retained::PublishedAgainAfterInvalidation,
            Obligation::Restart,
            lost,
        ),
        (Retained::RefusedRestore, Obligation::Restart, lost),
        (Retained::RefusedDamage, Obligation::Restart, lost),
        (Retained::DamagedOtherLost, Obligation::Restart, lost),
        (Retained::DamagedAfterServing, Obligation::Restart, lost),
        (Retained::EvictedAfterRestore, Obligation::Restart, lost),
        (Retained::StaleRefusal, Obligation::Restart, stale),
        (Retained::StaleVisibilityEnd, Obligation::Restart, stale),
        (
            Retained::RestoredUncaptured,
            Obligation::Restart,
            "a recovery restored an entry its cut never captured",
        ),
        (
            Retained::LateInvalidationRestored,
            Obligation::History,
            "a recorded restore of a covered version",
        ),
        (Retained::ColdStart, Obligation::Restart, cold),
        (
            Retained::ColdStartDamagedAfterServing,
            Obligation::Restart,
            cold,
        ),
        (
            Retained::UnrecordedCut,
            Obligation::Restart,
            "host loss activated a cut no capture recorded",
        ),
    ] {
        assert_eq!(
            assert_violates(&retained(case), obligation),
            rule,
            "{case:?}"
        );
    }
    for history in [
        invalidation_bound_above_recovery(),
        unbound_invalidation_before_forced_publication(),
        superseded_by_earlier_tenure_fill(),
        invalidation_omitted_in_later_tenure(LaterUse::Hit, false),
        invalidation_omitted_in_later_tenure(LaterUse::Restore, false),
        invalidation_omitted_in_later_tenure(LaterUse::Expire, false),
        invalidation_omitted_in_later_tenure(LaterUse::Evict, false),
    ] {
        assert_eq!(assert_violates(&history, Obligation::Restart), lost);
    }
    for used in [
        LaterUse::Hit,
        LaterUse::Restore,
        LaterUse::Expire,
        LaterUse::Evict,
    ] {
        let verdict = check(&invalidation_omitted_in_later_tenure(used, true));
        assert!(
            verdict.satisfies(&[Obligation::Restart]),
            "{used:?}: {verdict:?}"
        );
    }
    assert_eq!(
        assert_violates(&restore_from_uncaptured_cut(), Obligation::Restart),
        "a recovery restored an entry its cut never captured"
    );
    let restored = check(&retained(Retained::Restored));
    assert!(restored.satisfies(&[Obligation::Restart]), "{restored:?}");
}

/// A hit of `key`'s `label` with a complete delivery of its bytes.
fn hit(s: &mut Script, key: KeyId, label: Label) {
    let op = s.lookup(key, HIT, Some(label));
    s.deliver(
        op,
        key,
        label,
        BODY,
        Outcome::Complete,
        bytes(key, label, BODY),
    );
}

/// When a history of [`recovered_and_read`] records its damage rows, and the
/// lookups, hits and tenures a shape adds or drops: `KeyNeverRead`,
/// `KeyNeverReadDamageAfter` and `LedgerLookupAfterDamage` drop T1's lookup
/// of A's key, and
/// `LaterTenureServes` drops T1's lookups and adds T2, which restores and
/// serves both entries whatever `restored` and `served` name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Damage before the activation.
    Plain,
    /// Damage before the captures.
    DamageBeforeCapture,
    /// Damage after T1's lookups.
    DamageAfterLookups,
    /// Damage in T2, which activates from the cut after T1's lookups,
    /// restores C and serves it.
    DamageInLaterTenure,
    /// Damage in T2, which activates from the cut after T1's restores and
    /// before T1's lookups, restores C and serves it.
    LaterTenureDamageBeforeLookups,
    /// Damage after T1's lookups, followed by a second miss of A.
    DamageBetweenMisses,
    /// T0 serves A before the activation.
    HitBeforeActivation,
    /// T0, deposed, serves A to a second client after T1's lookups.
    LowerTenureHit,
    /// T1 publishes a new label B of A's key after its lookups and serves
    /// B.
    RefilledUnderNewLabel,
    /// T1 never looks A's key up; damage before J's lookup.
    KeyNeverRead,
    /// T1 never looks A's key up; damage after J's lookup.
    KeyNeverReadDamageAfter,
    /// T1 never looks A's key up; damage after J's lookup, then a
    /// recovery-ledger lookup of A's key.
    LedgerLookupAfterDamage,
    /// T1 answers no lookup, and T2 activates from the cut, restores both
    /// entries and serves them.
    LaterTenureServes,
    /// A lookup of A's key times out before the damage, and T1's lookups
    /// follow it.
    TimedOutBeforeDamage,
    /// T1 answers a lookup of A's key with C, a colliding candidate whose
    /// header check fails. The damage follows that lookup and precedes T1's
    /// lookup of each key.
    CollisionBeforeDamage,
    /// T1 answers a lookup of C's key with A, a colliding candidate whose
    /// header check fails. The damage follows that lookup and precedes T1's
    /// lookup of each key.
    CandidateBeforeDamage,
}

/// T0 publishes A and C, both captured in the cut at units `(0, 1)` and
/// `(0, 2)`; T1 activates from the cut, restores what `restored` names and
/// answers a lookup of each key: a hit with a complete delivery for a key
/// `served` names, a miss for the other. Damage is recorded on each unit of
/// `damaged`, `None` naming the whole volume, where `shape` places it. A
/// shape may drop lookups and add a tenure, as [`Shape`] states, and then
/// `served` names nothing for the dropped lookups.
fn recovered_and_read(
    restored: [bool; 2],
    served: [bool; 2],
    damaged: &[Option<u32>],
    shape: Shape,
) -> History {
    let (cut, t1, t2) = (CutId(1), Tenure { g: 1, a: 0 }, Tenure { g: 2, a: 0 });
    let entries = [(K, A, 1), (J, C, 2)];
    let mut s = Script::new();
    let damage = |s: &mut Script, at: Shape| {
        if shape == at {
            for &unit in damaged {
                s.damaged(RECOVERED, unit);
            }
        }
    };
    for (key, label, _) in entries {
        s.publish(key, label, BODY);
    }
    damage(&mut s, Shape::DamageBeforeCapture);
    for (key, label, unit) in entries {
        s.captured(RECOVERED, (key, label), cut, (0, unit));
    }
    if shape == Shape::HitBeforeActivation {
        hit(&mut s, K, A);
    }
    damage(&mut s, Shape::HitBeforeActivation);
    damage(&mut s, Shape::KeyNeverRead);
    damage(&mut s, Shape::Plain);
    s.activate(RECOVERED, Some(t1), Some(cut));
    s.in_tenure(Some(t1));
    for ((key, label, _), restored) in entries.into_iter().zip(restored) {
        if restored {
            s.restore(key, label, cut);
        }
    }
    if shape == Shape::LaterTenureDamageBeforeLookups {
        s.activate(RECOVERED, Some(t2), Some(cut));
        s.in_tenure(Some(t2));
        damage(&mut s, Shape::LaterTenureDamageBeforeLookups);
        s.restore(J, C, cut);
        hit(&mut s, J, C);
        s.in_tenure(Some(t1));
    }
    if shape == Shape::TimedOutBeforeDamage {
        s.lookup(K, Outcome::NoInformation(NoInformation::TimedOut), None);
        damage(&mut s, Shape::TimedOutBeforeDamage);
    }
    for (at, key, owner, label) in [
        (Shape::CollisionBeforeDamage, K, J, C),
        (Shape::CandidateBeforeDamage, J, K, A),
    ] {
        if shape == at {
            let op = s.candidate_lookup(key, owner, HIT, Some(label));
            let mismatch = Outcome::Damaged(Failure::HeaderMismatch);
            s.deliver(op, key, label, BODY, mismatch, Vec::new());
            damage(&mut s, at);
        }
    }
    let unread = matches!(
        shape,
        Shape::KeyNeverRead | Shape::KeyNeverReadDamageAfter | Shape::LedgerLookupAfterDamage
    );
    let silent = shape == Shape::LaterTenureServes;
    for ((key, label, _), served) in entries.into_iter().zip(served) {
        if silent || (unread && key == K) {
            continue;
        }
        if served {
            hit(&mut s, key, label);
        } else {
            s.lookup(key, MISSING, None);
        }
    }
    damage(&mut s, Shape::DamageAfterLookups);
    damage(&mut s, Shape::KeyNeverReadDamageAfter);
    damage(&mut s, Shape::LedgerLookupAfterDamage);
    if shape == Shape::LedgerLookupAfterDamage {
        s.recovered_lookup(RECOVERED, K, MISSING, None);
    }
    if shape == Shape::RefilledUnderNewLabel {
        s.publish(K, B, BODY);
        hit(&mut s, K, B);
    }
    if shape == Shape::LaterTenureServes {
        s.activate(RECOVERED, Some(t2), Some(cut));
        s.in_tenure(Some(t2));
        for (key, label, _) in entries {
            s.restore(key, label, cut);
            hit(&mut s, key, label);
        }
    }
    damage(&mut s, Shape::DamageBetweenMisses);
    if shape == Shape::DamageBetweenMisses {
        s.lookup(K, MISSING, None);
    }
    if shape == Shape::LowerTenureHit {
        s.in_tenure(Some(Tenure::INITIAL));
        s.by_client(Some(ClientId(2)));
        hit(&mut s, K, A);
        s.by_client(None);
    }
    if shape == Shape::DamageInLaterTenure {
        s.activate(RECOVERED, Some(t2), Some(cut));
        s.in_tenure(Some(t2));
        damage(&mut s, Shape::DamageInLaterTenure);
        s.restore(J, C, cut);
        hit(&mut s, J, C);
    }
    s.finish()
}

/// The positive-preservation judgment counts a member served only by a hit
/// with a complete delivery at or above the activated tenure and after the
/// activation, excuses an unserved member only by damage on its own row or
/// payload unit recorded after its capture, at or below the tenure and
/// before the key's first lookup, and fails a member that is neither, which
/// `check` passes as a legal miss. A failure of `check` is its verdict, and
/// an activation naming no cut has no account.
#[test]
fn preservation_requires_each_retained_entry_served_or_on_a_damaged_unit() {
    use super::preservation::preserved;
    let unserved = "a retained entry outside every damage set was never served after host loss";
    let rule = |history: &History| preserved(history).unwrap_err().violated();
    let unserved_rule = Some((Obligation::Restart, unserved));
    let read = |restored, served, damaged: &[Option<u32>]| {
        recovered_and_read(restored, served, damaged, Shape::Plain)
    };

    let whole = preserved(&read([true; 2], [true; 2], &[])).unwrap();
    let [account] = whole.as_slice() else {
        panic!("{whole:?}");
    };
    assert_eq!((account.members, account.served), (2, 2));
    assert_eq!(account.served_bytes, 2 * bytes(K, A, BODY).len() as u64);
    assert!(account.excused.is_empty());

    // Restored and never served: `check` passes the misses, and the
    // preservation judgment fails them.
    let missed = read([true; 2], [false; 2], &[]);
    assert!(check(&missed).satisfies(&[Obligation::Restart]));
    assert_eq!(rule(&missed), unserved_rule);
    assert_eq!(rule(&read([true; 2], [true, false], &[])), unserved_rule);

    // Damage on A's payload unit excuses A alone; damage on the shared row
    // unit excuses both.
    let payload = preserved(&read([true; 2], [false, true], &[Some(1)])).unwrap();
    assert_eq!(
        (payload[0].served, &payload[0].excused[..]),
        (1, &[(K, A)][..])
    );
    assert_eq!(
        rule(&read([true; 2], [false, true], &[Some(2)])),
        unserved_rule
    );
    let row = preserved(&read([false; 2], [false; 2], &[Some(0)])).unwrap();
    assert_eq!(
        (row[0].members, row[0].served, row[0].excused.len()),
        (2, 0, 2)
    );

    // A restore after row-unit damage shows the row unit decoded, so that
    // damage excuses no later miss of the restored member.
    assert_eq!(
        rule(&read([true; 2], [false, true], &[Some(0)])),
        unserved_rule
    );

    // A damaged unit whose member is served anyway counts as served.
    let repaired = preserved(&read([true; 2], [true; 2], &[Some(1)])).unwrap();
    assert_eq!((repaired[0].served, repaired[0].excused.len()), (2, 0));

    // Damage excuses only when recorded after the capture, before the key's
    // first lookup and at or below the activated tenure: a miss before the
    // damage stays unexcused by a later miss, and damage a later tenure
    // records before T1's lookups excuses nothing in T1. A row naming the
    // whole volume excuses no member of a cut-naming activation.
    for shape in [
        Shape::DamageBeforeCapture,
        Shape::DamageAfterLookups,
        Shape::DamageInLaterTenure,
        Shape::LaterTenureDamageBeforeLookups,
        Shape::DamageBetweenMisses,
    ] {
        let late = recovered_and_read([true; 2], [false, true], &[Some(1)], shape);
        assert_eq!(rule(&late), unserved_rule);
    }
    assert_eq!(
        rule(&read([true; 2], [false, true], &[None])),
        unserved_rule
    );

    for shape in [Shape::CollisionBeforeDamage, Shape::CandidateBeforeDamage] {
        let collided = recovered_and_read([true; 2], [false, true], &[Some(1)], shape);
        assert!(matches!(check(&collided), Verdict::Pass(_)));
        assert_eq!(rule(&collided), unserved_rule);
    }

    // A hit before the activation, or from a lower tenure after it, serves
    // no member of the activation's retained set, and a hit of another label
    // of the member's key, published after the activation, serves nothing.
    for shape in [
        Shape::HitBeforeActivation,
        Shape::LowerTenureHit,
        Shape::RefilledUnderNewLabel,
    ] {
        let elsewhere = recovered_and_read([true; 2], [false, true], &[], shape);
        assert!(check(&elsewhere).satisfies(&[Obligation::Restart]));
        assert_eq!(rule(&elsewhere), unserved_rule, "an unserved member");
    }

    // The damage bound is the key's first answered lookup after the
    // activation: a lookup before the activation and a timed-out lookup set
    // no bound, so damage after either still excuses A.
    for shape in [Shape::HitBeforeActivation, Shape::TimedOutBeforeDamage] {
        let bounded = recovered_and_read([true; 2], [false, true], &[Some(1)], shape);
        let account = preserved(&bounded).unwrap();
        assert_eq!(&account[0].excused[..], &[(K, A)][..]);
    }

    // A key never looked up is bounded by the tenure's first answered lookup.
    let never = recovered_and_read([true; 2], [false, true], &[Some(1)], Shape::KeyNeverRead);
    assert_eq!(&preserved(&never).unwrap()[0].excused[..], &[(K, A)][..]);
    let after = Shape::KeyNeverReadDamageAfter;
    let after = recovered_and_read([true; 2], [false, true], &[Some(1)], after);
    assert_eq!(rule(&after), unserved_rule);

    // A recovery-ledger lookup is no lookup of the tenure: one of A's key
    // after the damage sets no bound, so J's earlier lookup still bounds the
    // damage and A stays unexcused.
    let ledger = Shape::LedgerLookupAfterDamage;
    let ledger = recovered_and_read([true; 2], [false, true], &[Some(1)], ledger);
    assert!(matches!(check(&ledger), Verdict::Pass(_)));
    assert_eq!(rule(&ledger), unserved_rule);

    // A later cut-naming tenure's hits serve the earlier activation's
    // members too.
    let later = recovered_and_read([true; 2], [false; 2], &[], Shape::LaterTenureServes);
    let served: Vec<_> = (preserved(&later).unwrap().iter())
        .map(|account| (account.tenure, account.served))
        .collect();
    assert_eq!(
        served,
        [(Tenure { g: 1, a: 0 }, 2), (Tenure { g: 2, a: 0 }, 2)]
    );

    // The checker's own failure is the verdict.
    let lost = read([false, true], [false, true], &[]);
    assert_eq!(
        rule(&lost),
        Some((
            Obligation::Restart,
            "a retained entry outside every damage set was lost on host loss"
        ))
    );

    let mut cold = Script::new();
    cold.activate(RECOVERED, None, None);
    assert_eq!(preserved(&cold.finish()), Ok(Vec::new()));
}

/// T0 publishes A and C, captured in the cut at units `(0, 1)` and `(0, 2)`;
/// damage lands on A's payload unit; T1 activates, restores both and serves
/// both whole; then, after damage on that unit again when `redamaged`, T2
/// activates from the cut, restores C and A when `restored`, misses A and
/// serves C.
fn served_then_lost(restored: bool, redamaged: bool) -> History {
    let (cut, t1, t2) = (CutId(1), Tenure { g: 1, a: 0 }, Tenure { g: 2, a: 0 });
    let mut s = Script::new();
    for (key, label) in [(K, A), (J, C)] {
        s.publish(key, label, BODY);
    }
    s.captured(RECOVERED, (K, A), cut, (0, 1));
    s.captured(RECOVERED, (J, C), cut, (0, 2));
    s.damaged(RECOVERED, Some(1));
    s.activate(RECOVERED, Some(t1), Some(cut));
    s.in_tenure(Some(t1));
    s.restore(K, A, cut);
    s.restore(J, C, cut);
    hit(&mut s, K, A);
    hit(&mut s, J, C);
    s.in_tenure(None);
    if redamaged {
        s.damaged(RECOVERED, Some(1));
    }
    s.activate(RECOVERED, Some(t2), Some(cut));
    s.in_tenure(Some(t2));
    if restored {
        s.restore(K, A, cut);
    }
    s.restore(J, C, cut);
    s.lookup(K, MISSING, None);
    hit(&mut s, J, C);
    s.finish()
}

/// A complete delivery of a member's label, whose lookup began after a damage
/// row on the member's payload unit, shows that unit read whole, so the row
/// excuses no loss under a later activation: a later tenure that misses the
/// member, or never restores it, fails, and fresh damage recorded after the
/// delivery excuses both.
#[test]
fn a_complete_delivery_retires_the_damage_that_preceded_it() {
    use super::preservation::preserved;
    let rule = |history: &History| preserved(history).unwrap_err().violated();
    let unserved = "a retained entry outside every damage set was never served after host loss";
    let lost = "a retained entry outside every damage set was lost on host loss";
    assert_eq!(
        rule(&served_then_lost(true, false)),
        Some((Obligation::Restart, unserved))
    );
    assert_eq!(
        rule(&served_then_lost(false, false)),
        Some((Obligation::Restart, lost))
    );
    for restored in [true, false] {
        let accounts = preserved(&served_then_lost(restored, true)).unwrap();
        assert_eq!(&accounts[1].excused[..], &[(K, A)][..], "{restored}");
    }
}

/// Retiring evidence counts for the activations it precedes and, for a
/// restore, for the activation of its own tenure, and only for the unit it
/// read. Damage on A's payload unit excuses T1's missing restore of A in
/// `check` though a later T2 restores and serves A whole. Damage on the row
/// unit after T1's restore excuses T2's loss of A though T1 then served A
/// whole, since a delivery reads the payload alone.
#[test]
fn retiring_evidence_counts_before_the_judged_activation_and_for_its_unit() {
    use super::preservation::preserved;
    let (cut, t1, t2) = (CutId(1), Tenure { g: 1, a: 0 }, Tenure { g: 2, a: 0 });
    for row_unit in [false, true] {
        let mut s = Script::new();
        for (key, label) in [(K, A), (J, C)] {
            s.publish(key, label, BODY);
        }
        s.captured(RECOVERED, (K, A), cut, (0, 1));
        s.captured(RECOVERED, (J, C), cut, (0, 2));
        if !row_unit {
            s.damaged(RECOVERED, Some(1));
        }
        s.activate(RECOVERED, Some(t1), Some(cut));
        s.in_tenure(Some(t1));
        if row_unit {
            s.restore(K, A, cut);
        }
        s.restore(J, C, cut);
        s.in_tenure(None);
        if row_unit {
            s.damaged(RECOVERED, Some(0));
        }
        s.in_tenure(Some(t1));
        if row_unit {
            hit(&mut s, K, A);
        } else {
            s.lookup(K, MISSING, None);
        }
        hit(&mut s, J, C);
        s.activate(RECOVERED, Some(t2), Some(cut));
        s.in_tenure(Some(t2));
        if !row_unit {
            s.restore(K, A, cut);
            hit(&mut s, K, A);
        }
        s.restore(J, C, cut);
        hit(&mut s, J, C);
        let history = s.finish();
        let verdict = check(&history);
        assert!(
            matches!(verdict, Verdict::Pass(_)),
            "{row_unit}: {verdict:?}"
        );
        let accounts = preserved(&history).unwrap();
        if row_unit {
            assert_eq!(&accounts[1].excused[..], &[(K, A)][..]);
        } else {
            // T2's whole hit of A serves T1's member too.
            assert_eq!((accounts[0].served, accounts[0].excused.len()), (2, 0));
        }
    }

    let (second, lost) = (
        CutId(2),
        "a retained entry outside every damage set was lost on host loss",
    );
    for shared in [false, true] {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        s.captured(RECOVERED, (K, A), cut, (0, 1));
        s.captured(RECOVERED, (K, A), second, (if shared { 0 } else { 2 }, 1));
        s.damaged(RECOVERED, Some(0));
        s.activate(RECOVERED, Some(t1), Some(second));
        s.in_tenure(Some(t1));
        s.restore(K, A, second);
        hit(&mut s, K, A);
        s.activate(RECOVERED, Some(t2), Some(cut));
        s.in_tenure(Some(t2));
        s.lookup(K, MISSING, None);
        let history = s.finish();
        if shared {
            let verdict = preserved(&history).unwrap_err();
            assert_eq!(verdict.violated(), Some((Obligation::Restart, lost)));
        } else {
            let accounts = preserved(&history).unwrap();
            assert_eq!(&accounts[1].excused[..], &[(K, A)][..]);
        }
    }
}

/// A hit or a complete delivery the client rejected serves no member, though
/// its bytes are whole: a rejected lookup, a rejected delivery and both fail
/// the unserved rule, and the same answer accepted serves the member.
#[test]
fn a_rejected_delivery_serves_no_retained_entry() {
    use super::preservation::preserved;
    let unserved = "a retained entry outside every damage set was never served after host loss";
    let (cut, t1) = (CutId(1), Tenure { g: 1, a: 0 });
    for (lookup, delivery) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        s.captured(RECOVERED, (K, A), cut, (0, 1));
        s.activate(RECOVERED, Some(t1), Some(cut));
        s.in_tenure(Some(t1));
        s.restore(K, A, cut);
        s.by_client(Some(ClientId(1)));
        if lookup {
            s.reject_next();
        }
        let op = s.lookup(K, HIT, Some(A));
        if delivery {
            s.reject_next();
        }
        s.deliver(op, K, A, BODY, Outcome::Complete, bytes(K, A, BODY));
        let history = s.finish();
        let arm = (lookup, delivery);
        assert!(check(&history).satisfies(&[Obligation::Restart]), "{arm:?}");
        match preserved(&history) {
            Ok(accounts) => assert!(arm == (false, false) && accounts[0].served == 1),
            Err(verdict) => {
                assert_ne!(arm, (false, false), "{verdict:?}");
                assert_eq!(verdict.violated(), Some((Obligation::Restart, unserved)));
            }
        }
    }
}

/// A captured entry that leaves the retained set only through a timed-out
/// invalidation or a timed-out replacement, either of which may or may not
/// have landed, makes the preservation judgment inconclusive, though `check`
/// passes the miss; acknowledged, either removes the entry and the account
/// holds no member.
#[test]
fn an_exclusion_by_an_unknown_outcome_is_inconclusive() {
    use super::preservation::preserved;
    let (cut, t1) = (CutId(1), Tenure { g: 1, a: 0 });
    let timed_out = Outcome::NoInformation(NoInformation::TimedOut);
    for invalidation in [true, false] {
        for known in [false, true] {
            let mut s = Script::new();
            s.publish(K, A, BODY);
            s.captured(RECOVERED, (K, A), cut, (0, 1));
            let outcome = if known { ACK } else { timed_out };
            if invalidation {
                let open = s.begin_invalidate(K);
                s.close(open, Some(outcome));
            } else {
                let open = s.begin_publish(K, B, BODY, None);
                s.close(open, Some(outcome));
            }
            s.activate(RECOVERED, Some(t1), Some(cut));
            s.in_tenure(Some(t1));
            s.lookup(K, MISSING, None);
            let history = s.finish();
            let name = format!("invalidation {invalidation}, acknowledged {known}");
            let verdict = check(&history);
            assert!(matches!(verdict, Verdict::Pass(_)), "{name}: {verdict:?}");
            let captured = (history.rows().iter())
                .find(|row| row.kind == ActionKind::Captured)
                .map(|row| row.op);
            match preserved(&history) {
                Ok(accounts) => {
                    assert!(known, "{name}: {accounts:?}");
                    assert_eq!(accounts[0].members, 0, "{name}");
                }
                Err(Verdict::Inconclusive(Inconclusive::UnknownExclusion { op })) => {
                    assert!(!known, "{name}");
                    assert_eq!(Some(op), captured, "{name}");
                }
                Err(verdict) => panic!("{name}: {verdict:?}"),
            }
        }
    }

    for known in [true, false] {
        let mut s = Script::new();
        let mut publication = s.begin_publish(K, A, BODY, None);
        publication.set_version(7);
        s.close(publication, Some(timed_out));
        s.captured(RECOVERED, (K, A), cut, (0, 1));
        let mut invalidation = s.begin_invalidate(K);
        invalidation.set_covers(Cover::Range { lo: 7, hi: 7 });
        s.close(invalidation, Some(if known { ACK } else { timed_out }));
        s.activate(RECOVERED, Some(t1), Some(cut));
        s.in_tenure(Some(t1));
        s.lookup(K, MISSING, None);
        let history = s.finish();
        let verdict = check(&history);
        assert!(matches!(verdict, Verdict::Pass(_)), "{known}: {verdict:?}");
        match preserved(&history) {
            Ok(accounts) => assert!(known && accounts[0].members == 0, "{accounts:?}"),
            Err(Verdict::Inconclusive(Inconclusive::UnknownExclusion { .. })) => assert!(!known),
            Err(verdict) => panic!("{known}: {verdict:?}"),
        }
    }

    // A restored and never served member is the verdict before an unknown
    // exclusion of another entry.
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.publish(J, C, BODY);
    s.captured(RECOVERED, (K, A), cut, (0, 1));
    s.captured(RECOVERED, (J, C), cut, (0, 2));
    let open = s.begin_invalidate(K);
    s.close(open, Some(timed_out));
    s.activate(RECOVERED, Some(t1), Some(cut));
    s.in_tenure(Some(t1));
    s.restore(J, C, cut);
    s.lookup(K, MISSING, None);
    s.lookup(J, MISSING, None);
    let unserved = "a retained entry outside every damage set was never served after host loss";
    let verdict = preserved(&s.finish()).unwrap_err();
    assert_eq!(verdict.violated(), Some((Obligation::Restart, unserved)));
}

/// The activated tenure's effect on a member after the member's restore
/// removes nothing from the retained set. An acknowledged invalidation, a
/// recorded eviction or a publication of another label that ends the member
/// before a lookup of its key leaves it unserved, and the judgment fails it,
/// though `check` passes the miss and the hit of the new label. The same
/// invalidation after a hit of the member leaves it served. In a tenure that
/// never restores the entry, an acknowledged invalidation after a miss of
/// its key removes it, and the account holds no member.
#[test]
fn an_effect_after_the_restore_leaves_an_unserved_member_failing() {
    use super::preservation::preserved;
    let (cut, t1) = (CutId(1), Tenure { g: 1, a: 0 });
    let unserved = "a retained entry outside every damage set was never served after host loss";
    let judged = |restored: bool, after: fn(&mut Script)| {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        s.captured(RECOVERED, (K, A), cut, (0, 1));
        s.activate(RECOVERED, Some(t1), Some(cut));
        s.in_tenure(Some(t1));
        if restored {
            s.restore(K, A, cut);
        }
        after(&mut s);
        let history = s.finish();
        let verdict = check(&history);
        assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
        preserved(&history)
    };
    let ended: [fn(&mut Script); 3] = [
        |s| {
            s.invalidate(K, ACK);
            s.lookup(K, MISSING, None);
        },
        |s| {
            s.evict(K, A);
            s.lookup(K, MISSING, None);
        },
        |s| {
            s.publish_replacing(K, B, BODY);
            hit(s, K, B);
        },
    ];
    for (arm, after) in ended.into_iter().enumerate() {
        let verdict = judged(true, after).unwrap_err();
        assert_eq!(
            verdict.violated(),
            Some((Obligation::Restart, unserved)),
            "arm {arm}"
        );
    }

    let served = judged(true, |s| {
        hit(s, K, A);
        s.invalidate(K, ACK);
        s.lookup(K, MISSING, None);
    });
    let served = served.unwrap();
    assert_eq!((served[0].members, served[0].served), (1, 1));

    let unrestored = judged(false, |s| {
        s.lookup(K, MISSING, None);
        s.invalidate(K, ACK);
    });
    assert_eq!(unrestored.unwrap()[0].members, 0);
}

/// The client high-water rule spans every key of the shard. A client that
/// accepts T2's answer on one key and then T1's on another passes `check`
/// over each key alone, and `check_clients` over all keys fails it.
#[test]
fn client_acceptance_is_judged_across_every_key() {
    use super::checker::check_clients;
    let (t1, t2, l) = (Tenure { g: 1, a: 0 }, Tenure { g: 2, a: 0 }, KeyId(2));
    let history = |keys: &[KeyId]| {
        let mut s = Script::new();
        s.activate(RECOVERED, Some(t1), None);
        s.activate(RECOVERED, Some(t2), None);
        s.by_client(Some(ClientId(1)));
        for (key, tenure) in [(K, t2), (J, t1), (l, t1)] {
            if keys.contains(&key) {
                s.in_tenure(Some(tenure));
                s.lookup(key, MISSING, None);
            }
        }
        s.finish()
    };
    for keys in [&[K][..], &[J, l][..]] {
        assert!(matches!(check(&history(keys)), Verdict::Pass(_)));
        assert_eq!(check_clients(&history(keys)), Ok(()));
    }
    let rule = "a client accepted a response tagged below its high-water";
    let whole = check_clients(&history(&[K, J, l])).unwrap_err();
    assert_eq!(whole.violated(), Some((Obligation::History, rule)));
}

/// The client judgment admits a history under the domain rules of `check`
/// with the key bound alone lifted. One label under two keys is malformed in
/// `check` and in `check_clients`. Across three keys, where each group of
/// `MAX_KEYS` keys passes `check` because the label's two keys lie in
/// different groups, `check_clients` over the whole history refuses the
/// label, and the same keys under distinct labels pass it.
#[test]
fn the_client_judgment_refuses_a_label_under_keys_of_two_groups() {
    use super::checker::check_clients;
    use super::row::Field;
    let l = KeyId(2);
    let history = |labels: &[(KeyId, Label)]| {
        let mut s = Script::new();
        let ops: Vec<_> = (labels.iter())
            .map(|&(key, label)| s.publish(key, label, BODY))
            .collect();
        (s.finish(), *ops.last().unwrap())
    };
    let malformed = |op| {
        Verdict::Inconclusive(Inconclusive::Malformed {
            op,
            field: Field::Label,
        })
    };

    let (pair, second) = history(&[(K, A), (J, A)]);
    assert_eq!(check(&pair), malformed(second));
    assert_eq!(check_clients(&pair), Err(malformed(second)));

    for group in [&[(K, A), (J, C)][..], &[(l, A)][..]] {
        assert!(matches!(check(&history(group).0), Verdict::Pass(_)));
    }
    let (wide, third) = history(&[(K, A), (J, C), (l, A)]);
    assert_eq!(check_clients(&wide), Err(malformed(third)));
    let (distinct, _) = history(&[(K, A), (J, C), (l, B)]);
    assert_eq!(check_clients(&distinct), Ok(()));
}

/// A client's high-water keeps what a live client reported on a rejected
/// answer: an observed rejection recording high-water T2, then a scripted
/// answer of the same client, records T2 again and passes.
#[test]
fn an_observed_rejection_keeps_the_high_water_it_reported() {
    use super::clients::Acceptance;
    let (t1, t2) = (Tenure { g: 1, a: 0 }, Tenure { g: 2, a: 0 });
    let mut s = Script::new();
    s.activate(RECOVERED, Some(t1), None);
    s.activate(RECOVERED, Some(t2), None);
    s.by_client(Some(ClientId(1)));
    s.in_tenure(Some(t1));
    s.observe_next(Acceptance {
        high_water: Some(t2),
        accepted: false,
    });
    s.lookup(K, MISSING, None);
    s.in_tenure(Some(t2));
    s.lookup(K, MISSING, None);
    let history = s.finish();
    let recorded: Vec<_> = (history.rows().iter())
        .filter_map(|row| row.acceptance)
        .map(|acceptance| acceptance.high_water)
        .collect();
    assert_eq!(recorded, [Some(t2), Some(t2)]);
    assert!(
        matches!(check(&history), Verdict::Pass(_)),
        "{:?}",
        check(&history)
    );
}
