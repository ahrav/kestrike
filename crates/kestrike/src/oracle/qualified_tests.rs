//! Qualified recovery goldens and controls: the third evidence class's
//! profile, identity, boundary, incarnation and predecessor rules, the
//! latest restart as each lookup's cut, exclusions across restarts, and
//! the undeclared-kind refusal.

use super::action::ActionKind;
use super::bounds::{HISTORY_BOUND, SEARCH_BOUND, SearchBudget};
use super::checker::{check, check_within};
use super::content::Geometry;
use super::evidence::{Decision, DurableFact, Evidence, Qualified};
use super::golden::*;
use super::obligation::Obligation;
use super::row::Field;
use super::script::Script;
use super::verdict::{Inconclusive, Verdict};

const COMPLETION: &str = "a write completion was taken as durable payload evidence";
const UNADMITTED: &str = "a recovered candidate was found without admission";
const REVIVED: &str = "a recovery-safe exclusion was revived after restart";
const LACKED: &str = "admission lacked binding, payload, identity or ownership evidence";

/// A payload row that does not count leaves the binding that names it
/// uncounted too, so the admission lacks both.
#[test]
fn qualified_evidence_counts_only_under_its_profile_identity_boundary_and_incarnation() {
    let matching = check(&qualified_recovery(Qualification::Matching));
    assert!(matching.satisfies(&[Obligation::Restart]), "{matching:?}");
    for qualification in [
        Qualification::OtherProfile,
        Qualification::OtherIdentity,
        Qualification::OtherBoundary,
        Qualification::FutureIncarnation,
        Qualification::Unqualified,
    ] {
        assert_eq!(
            assert_violates(&qualified_recovery(qualification), Obligation::Restart),
            LACKED,
            "{qualification:?}"
        );
    }
    assert_eq!(
        assert_violates(
            &qualified_recovery(Qualification::AfterRestart),
            Obligation::Restart
        ),
        "a recovered candidate was served without freshness, expiry, serving or replay authority"
    );
}

#[test]
fn a_root_fact_counts_only_after_every_predecessor() {
    for qualification in [Qualification::RootFirst, Qualification::RootBeforeSecond] {
        assert_eq!(
            assert_violates(&qualified_recovery(qualification), Obligation::Restart),
            LACKED,
            "{qualification:?}"
        );
    }
}

#[test]
fn a_reused_command_within_an_incarnation_is_malformed() {
    let history = reused_command();
    let payload = history
        .rows()
        .iter()
        .find(|row| row.fact == Some(DurableFact::Payload))
        .unwrap()
        .op;
    assert_eq!(
        check(&history),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: payload,
            field: Field::Evidence,
        })
    );
}

#[test]
fn a_command_reused_by_another_incarnation_or_identity_is_a_distinct_row() {
    let reused = check(&commands_reused_across_incarnations());
    assert!(reused.satisfies(&[Obligation::Restart]), "{reused:?}");
}

#[test]
fn a_recovered_lookup_under_another_identity_finds_no_restart() {
    let moved = edited(&qualified_recovery(Qualification::Matching), |rows| {
        let lookup = rows.iter_mut().rfind(|row| row.kind == ActionKind::Lookup);
        if let Evidence::Qualified(qualified) = &mut lookup.unwrap().evidence {
            qualified.identity = IDENTITY + 1;
        }
    });
    assert_eq!(
        assert_violates(&moved, Obligation::Restart),
        "recovered acquisition precedes restart"
    );
}

#[test]
fn a_qualified_completed_write_is_no_payload_fact_without_its_row() {
    let unadmitted = check(&qualified_completion_as_durability(false));
    assert!(
        unadmitted.satisfies(&[Obligation::Restart]),
        "{unadmitted:?}"
    );
    assert_eq!(
        assert_violates(
            &qualified_completion_as_durability(true),
            Obligation::Restart
        ),
        COMPLETION
    );
}

#[test]
fn the_latest_restart_before_a_lookup_is_its_cut() {
    let admitted = check(&two_restarts(Between::Admitted));
    assert!(admitted.satisfies(&[Obligation::Restart]), "{admitted:?}");
    assert_eq!(
        assert_violates(&two_restarts(Between::LateAdmission), Obligation::Restart),
        UNADMITTED
    );
    assert_eq!(
        assert_violates(&two_restarts(Between::StaleFacts), Obligation::Restart),
        LACKED
    );
}

/// A restart that responds after a lookup was invoked is no cut for that
/// lookup: the earlier restart is, and the admission follows it.
#[test]
fn a_restart_overlapping_a_lookup_is_not_its_cut() {
    let overlapping = edited(&two_restarts(Between::Admitted), |rows| {
        let second = rows
            .iter()
            .rposition(|row| row.kind == ActionKind::Restart)
            .unwrap();
        let lookup = rows
            .iter()
            .rposition(|row| row.kind == ActionKind::Lookup)
            .unwrap();
        let responded = rows[second].responded;
        rows[second].responded = rows[lookup].invoked;
        rows[lookup].invoked = responded;
    });
    assert_eq!(
        assert_violates(&overlapping, Obligation::Restart),
        UNADMITTED
    );
}

#[test]
fn an_abstract_lookup_is_judged_at_the_latest_restart() {
    let history = |late: bool| {
        let mut s = Script::new();
        s.publish(K, A, BODY);
        s.restart(RECOVERED, K);
        for fact in ADMISSION.into_iter().chain(AUTHORITY) {
            s.fact(RECOVERED, K, A, fact);
        }
        if !late {
            s.admission(RECOVERED, K, A);
        }
        s.restart(RECOVERED, K);
        if late {
            s.admission(RECOVERED, K, A);
        }
        s.recovered_lookup(RECOVERED, K, HIT, Some(A));
        s.finish()
    };
    assert!(check(&history(false)).satisfies(&[Obligation::Restart]));
    assert_eq!(
        assert_violates(&history(true), Obligation::Restart),
        UNADMITTED
    );
}

#[test]
fn the_stale_version_control_fails_by_exclusion_revival() {
    for (outcome, label) in [(MISSING, None), (HIT, Some(B))] {
        let verdict = check(&stale_version(outcome, label));
        assert!(verdict.satisfies(&[Obligation::Restart]), "{verdict:?}");
    }
    assert_eq!(
        assert_violates(&stale_version(HIT, Some(A)), Obligation::Restart),
        REVIVED
    );
}

/// An exclusion forbids, so one whose evidence does not count, or that
/// names another profile or identity, binds all the same.
#[test]
fn an_uncounted_qualified_exclusion_still_binds() {
    let edits: [fn(&mut Qualified); 6] = [
        |q| q.incarnation += 1,
        |q| q.predecessors[0] = Some(99),
        |q| q.boundary = "submission",
        |q| q.profile = "declared-512",
        |q| q.profile = "recovery-16k",
        |q| q.identity = IDENTITY + 1,
    ];
    for edit in edits {
        let uncounted = edited(&stale_version(HIT, Some(A)), |rows| {
            let exclusion = rows
                .iter_mut()
                .find(|row| row.fact == Some(DurableFact::RecoveryExclusion));
            if let Evidence::Qualified(qualified) = &mut exclusion.unwrap().evidence {
                edit(qualified);
            }
        });
        assert_eq!(assert_violates(&uncounted, Obligation::Restart), REVIVED);
    }
}

/// An exclusion fact keeps the excluded binding's frozen identity beside
/// its key and label.
#[test]
fn an_exclusion_fact_keeps_its_key_label_and_frozen_identity() {
    let history = stale_version(MISSING, None);
    let exclusions: Vec<_> = history
        .rows()
        .iter()
        .filter(|row| row.fact == Some(DurableFact::RecoveryExclusion))
        .map(|row| (row.key(), row.label, row.frozen))
        .collect();
    assert_eq!(exclusions, [(Some(K), Some(A), Some(FROZEN))]);
}

#[test]
fn an_exclusion_between_restarts_binds_after_the_second() {
    assert_eq!(
        assert_violates(&excluded_between_restarts(), Obligation::Restart),
        REVIVED
    );
}

/// A predecessor names a command of the writing incarnation: a payload the
/// incarnation before the restart wrote leaves the binding uncounted.
#[test]
fn a_predecessor_from_an_earlier_incarnation_does_not_count() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.fact(qualified(1, None, 0), K, A, DurableFact::Payload);
    s.restart(qualified(2, None, 0), K);
    s.fact(qualified(3, Some(1), 1), K, A, DurableFact::Binding);
    let rest = [DurableFact::Identity, DurableFact::Ownership];
    for (command, fact) in (4..).zip(rest.into_iter().chain(AUTHORITY)) {
        s.fact(qualified(command, None, 1), K, A, fact);
    }
    s.admission(qualified(20, None, 1), K, A);
    assert_eq!(assert_violates(&s.finish(), Obligation::Restart), LACKED);
}

/// An exclusion is a fact like any other: a binding that names its command
/// as a predecessor counts once the exclusion counted.
#[test]
fn an_exclusion_can_be_a_predecessor() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    s.exclusion(qualified(1, None, 0), K, A, FROZEN);
    s.fact(qualified(2, None, 0), K, B, DurableFact::Payload);
    let binding = Qualified {
        predecessors: [Some(1), Some(2)],
        ..qualified(3, None, 0)
    };
    s.fact(binding, K, B, DurableFact::Binding);
    s.fact(qualified(4, None, 0), K, B, DurableFact::Identity);
    s.fact(qualified(5, None, 0), K, B, DurableFact::Ownership);
    s.admission(qualified(6, None, 0), K, B);
    let verdict = check(&s.finish());
    assert!(matches!(verdict, Verdict::Pass(_)), "{verdict:?}");
}

/// The writing incarnation is the owner's: a restart recorded under another
/// attached identity advances it for every qualified scope.
#[test]
fn qualified_restarts_count_across_identities() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let other = Qualified {
        identity: IDENTITY + 1,
        ..qualified(1, None, 0)
    };
    s.restart(other, K);
    qualified_facts(&mut s, A, 1, 2);
    s.admission(qualified(20, None, 1), K, A);
    s.restart(qualified(21, None, 1), K);
    s.recovered_lookup(qualified(22, None, 2), K, HIT, Some(A));
    let verdict = check(&s.finish());
    assert!(verdict.satisfies(&[Obligation::Restart]), "{verdict:?}");
}

/// After a restart under another identity, facts naming incarnation 0 are
/// stale in every qualified scope.
#[test]
fn a_restart_under_another_identity_makes_incarnation_zero_stale() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let other = Qualified {
        identity: IDENTITY + 1,
        ..qualified(1, None, 0)
    };
    s.restart(other, K);
    qualified_facts(&mut s, A, 0, 2);
    s.admission(qualified(20, None, 1), K, A);
    assert_eq!(assert_violates(&s.finish(), Obligation::Restart), LACKED);
}

#[test]
fn a_later_incarnation_cannot_readmit_an_excluded_label() {
    let kept = check(&excluded_readmission(false));
    assert!(kept.satisfies(&[Obligation::Restart]), "{kept:?}");
    assert_eq!(
        assert_violates(&excluded_readmission(true), Obligation::Restart),
        "a recovery-safe exclusion was readmitted"
    );
}

#[test]
fn an_abstract_row_of_an_undeclared_kind_is_refused() {
    let history = held_read_across_invalidation(MISSING, None);
    let declared = [
        ActionKind::Persistence,
        ActionKind::Admission,
        ActionKind::Restart,
        ActionKind::Lookup,
        ActionKind::Fill,
        ActionKind::Receive,
        ActionKind::WriteCompleted,
        ActionKind::Publish,
        ActionKind::Replace,
        ActionKind::Invalidate,
    ];
    let mut kind = None;
    let planted = edited(&history, |rows| {
        let row = rows
            .iter_mut()
            .find(|row| {
                !declared.contains(&row.kind)
                    && row
                        .outcome
                        .is_none_or(|outcome| outcome.carries_information())
            })
            .unwrap();
        kind = Some(row.kind);
        row.evidence = Evidence::Abstract(RECOVERED);
    });
    assert_eq!(
        assert_violates(&planted, Obligation::Restart),
        "abstract action lacks declared recovery semantics",
        "{kind:?}"
    );
}

#[test]
fn a_qualified_row_on_an_open_decision_is_inconclusive_by_name() {
    let history = qualified_recovery(Qualification::Matching);
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
fn malformed_qualified_rows_name_their_field() {
    let history = qualified_recovery(Qualification::Matching);
    let persistence = |edit: &dyn Fn(&mut Qualified)| {
        let mut row = history
            .rows()
            .iter()
            .find(|row| row.kind == ActionKind::Persistence)
            .unwrap()
            .clone();
        if let Evidence::Qualified(qualified) = &mut row.evidence {
            edit(qualified);
        }
        row.malformed_field()
    };
    assert_eq!(persistence(&|_| {}), None);
    assert_eq!(persistence(&|q| q.profile = ""), Some(Field::Evidence));
    assert_eq!(persistence(&|q| q.boundary = ""), Some(Field::Evidence));
    assert_eq!(
        persistence(&|q| q.predecessors[0] = Some(q.command)),
        Some(Field::Evidence)
    );
    let mut fill = history
        .rows()
        .iter()
        .find(|row| row.kind == ActionKind::Fill)
        .unwrap()
        .clone();
    fill.evidence = Evidence::Qualified(qualified(1, None, 0));
    assert_eq!(fill.malformed_field(), Some(Field::Evidence));
    let mut binding = history
        .rows()
        .iter()
        .find(|row| row.fact == Some(DurableFact::Binding))
        .unwrap()
        .clone();
    binding.frozen = Some(FROZEN);
    assert_eq!(binding.malformed_field(), Some(Field::Frozen));
    let history = stale_version(MISSING, None);
    let mut exclusion = history
        .rows()
        .iter()
        .find(|row| row.fact == Some(DurableFact::RecoveryExclusion))
        .unwrap()
        .clone();
    exclusion.frozen = None;
    assert_eq!(exclusion.malformed_field(), Some(Field::Frozen));
}

#[test]
fn every_qualified_control_fits_both_bounds_with_twice_the_margin() {
    let controls = [
        qualified_recovery(Qualification::RootBeforeSecond),
        qualified_completion_as_durability(true),
        two_restarts(Between::LateAdmission),
        stale_version(HIT, Some(A)),
        excluded_readmission(true),
        excluded_between_restarts(),
        qualified_recovery(Qualification::RootFirst),
    ];
    for history in controls {
        let mut budget = SearchBudget::per_key();
        assert!(matches!(
            check_within(&history, Geometry::GOLDEN, &mut budget),
            Verdict::Violation(_)
        ));
        assert!(history.rows().len() * 2 <= HISTORY_BOUND);
        assert!(budget.high_water() * 2 <= SEARCH_BOUND);
    }
    let malformed = reused_command();
    assert!(malformed.rows().len() * 2 <= HISTORY_BOUND);
}

/// Root 1 names A and root 2 names B and omits A, so root 2's exclusion row for A follows its own binding row of B, each under its own command; a restart, then a recovered lookup answering `outcome`.
fn root_omission(
    outcome: super::outcome::Outcome,
    label: Option<super::ids::Label>,
) -> super::history::History {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(ACK));
    qualified_facts(&mut s, A, 0, 1);
    s.admission(qualified(20, None, 0), K, A);
    qualified_facts(&mut s, B, 0, 21);
    s.admission(qualified(40, None, 0), K, B);
    s.exclusion(qualified(41, Some(22), 0), K, A, FROZEN);
    s.restart(qualified(42, None, 0), K);
    s.recovered_lookup(qualified(43, None, 1), K, outcome, label);
    s.finish()
}

/// A root's exclusion row for a binding its predecessor named binds after the restart: a recovered hit of the omitted binding fails by exclusion revival, and the root's own binding or a miss passes.
#[test]
fn a_root_exclusion_then_a_recovered_hit_of_the_omitted_binding_is_revived() {
    assert_eq!(
        assert_violates(&root_omission(HIT, Some(A)), Obligation::Restart),
        REVIVED
    );
    for (outcome, label) in [(HIT, Some(B)), (MISSING, None)] {
        let verdict = check(&root_omission(outcome, label));
        assert!(verdict.satisfies(&[Obligation::Restart]), "{verdict:?}");
    }
}

/// A walk that reuses a leaf records no row for it; a row that chains through the reused leaf by its earlier command repeats that command and is malformed.
#[test]
fn a_chain_through_a_reused_leaf_is_malformed() {
    let mut s = Script::new();
    s.publish(K, A, BODY);
    let replace = s.begin_replace(K, B, BODY);
    s.close(replace, Some(ACK));
    qualified_facts(&mut s, A, 0, 1);
    s.admission(qualified(20, None, 0), K, A);
    s.fact(qualified(21, None, 0), K, B, DurableFact::Payload);
    s.fact(qualified(2, Some(21), 0), K, B, DurableFact::Binding);
    let history = s.finish();
    let reused = history
        .rows()
        .iter()
        .rfind(|row| row.fact == Some(DurableFact::Binding))
        .unwrap()
        .op;
    assert_eq!(
        check(&history),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: reused,
            field: Field::Evidence,
        })
    );
}
