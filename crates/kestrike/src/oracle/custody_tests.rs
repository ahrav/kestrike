//! Custody judgments over hand-written resource histories.

use super::action::ActionKind;
use super::attempt::PutOutcome;
use super::checker::check;
use super::custody::{Checkpoint, Custodian};
use super::golden::{B, FAILED, HIT, J, MISSING, bytes};
use super::history::History;
use super::ids::{Incarnation, KeyId, Label, OpId, Ordinal, ResourceKind};
use super::obligation::Obligation;
use super::outcome::{Failure, NoInformation, Outcome, VisibilityCause};
use super::recorder::Recorder;
use super::row::{Field, ReportKind, ReportState, Row};
use super::script::{META as SCRIPT_META, Script};
use super::verdict::{Inconclusive, Verdict};

const K: KeyId = KeyId(0);
const A: Label = Label(1);
const ID: (u64, u64) = (1, 1);
const META: u32 = 4;
const BODY: u64 = 60;
pub(super) const BUFFER: (ResourceKind, u32, u64) = (ResourceKind::Buffer, 0, 1);
const REUSED: (ResourceKind, u32, u64) = (ResourceKind::Buffer, 0, 2);
const SLOT: (ResourceKind, u32, u64) = (ResourceKind::Slot, 3, 7);
const COMMAND: (ResourceKind, u32, u64) = (ResourceKind::Command, 2, 0x10002);

pub(super) fn nic_return(early_reuse: bool) -> Recorder {
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Owner, None);
    r.take(BUFFER, Custodian::Nic, None);
    r.release(BUFFER, Custodian::Owner);
    if early_reuse {
        r.take(REUSED, Custodian::Owner, None);
    }
    r.release(BUFFER, Custodian::Nic);
    r.release(BUFFER, Custodian::Nic);
    if !early_reuse {
        r.take(REUSED, Custodian::Owner, None);
    }
    r.release(REUSED, Custodian::Owner);
    r
}

#[test]
fn a_nic_reference_pins_its_incarnation_and_duplicate_returns_change_nothing() {
    let verdict = check(&nic_return(false).finish());
    assert!(verdict.satisfies(&[Obligation::Custody]), "{verdict:?}");
}

#[test]
fn early_reuse_control_fails_custody() {
    assert_eq!(
        check(&nic_return(true).finish()).violated(),
        Some((
            Obligation::Custody,
            "a resource was reused while a custodian held an earlier incarnation"
        ))
    );
    let mut r = Recorder::new(1);
    r.take(
        (ResourceKind::Extent, 0, 1),
        Custodian::Reader,
        Some((0, 8)),
    );
    r.take(
        (ResourceKind::Extent, 1, 1),
        Custodian::Storage,
        Some((4, 4)),
    );
    assert_eq!(
        check(&r.finish()).violated(),
        Some((Obligation::Custody, "writable extents overlapped"))
    );
    let mut r = Recorder::new(1);
    r.take(
        (ResourceKind::Extent, 0, 1),
        Custodian::Reader,
        Some((0, 8)),
    );
    r.release((ResourceKind::Extent, 0, 1), Custodian::Reader);
    r.take(
        (ResourceKind::Extent, 1, 1),
        Custodian::Storage,
        Some((4, 4)),
    );
    assert!(check(&r.finish()).satisfies(&[Obligation::Custody]));
}

pub(super) fn released_checkpoint(leak: Option<(ResourceKind, u32, u64)>) -> Recorder {
    let mut r = Recorder::new(1);
    for resource in [BUFFER, SLOT, COMMAND, (ResourceKind::Credit, 0, 0)] {
        r.take(resource, Custodian::Storage, None);
    }
    r.take(
        (ResourceKind::BudgetCharge, 0, 0),
        Custodian::Owner,
        Some((0, 4)),
    );
    r.report(
        ResourceKind::Buffer,
        ReportKind::Pool,
        ReportState::Value(1),
    );
    for resource in [BUFFER, SLOT, COMMAND, (ResourceKind::Credit, 0, 0)] {
        if Some(resource) == leak {
            continue;
        }
        if resource == COMMAND {
            r.terminal(resource, Outcome::Complete);
        } else {
            r.release(resource, Custodian::Storage);
        }
    }
    r.report(
        ResourceKind::Buffer,
        ReportKind::Pool,
        ReportState::Value(u64::from(leak == Some(BUFFER))),
    );
    r.checkpoint(Checkpoint::Released);
    r
}

#[test]
fn leaked_capacity_control_fails_resources_and_budget_charge_is_exempt() {
    let verdict = check(&released_checkpoint(None).finish());
    assert!(verdict.satisfies(&[Obligation::Resources]), "{verdict:?}");
    for leak in [BUFFER, SLOT, COMMAND, (ResourceKind::Credit, 0, 0)] {
        assert_eq!(
            check(&released_checkpoint(Some(leak)).finish()).violated(),
            Some((
                Obligation::Resources,
                "a released checkpoint kept capacity its obligations no longer justify"
            )),
            "{leak:?}"
        );
    }
}

#[test]
fn a_report_that_disagrees_with_the_independent_count_is_a_violation() {
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Storage, None);
    r.report(
        ResourceKind::Buffer,
        ReportKind::Pool,
        ReportState::Value(0),
    );
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Resources,
            "a production report disagreed with the independent count"
        ))
    );
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Storage, None);
    r.report(
        ResourceKind::Buffer,
        ReportKind::Pool,
        ReportState::Poisoned,
    );
    assert!(matches!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::PoisonedReport { .. })
    ));
}

#[test]
fn an_unproven_stop_retains_its_custody() {
    let mut r = Recorder::new(1);
    r.take(COMMAND, Custodian::Storage, None);
    r.take(BUFFER, Custodian::Storage, None);
    r.checkpoint(Checkpoint::Unproven);
    r.report(
        ResourceKind::Command,
        ReportKind::Table,
        ReportState::Value(1),
    );
    let kept = check(&r.finish());
    assert!(kept.satisfies(&[Obligation::Resources]), "{kept:?}");
    let mut r = Recorder::new(1);
    r.take(COMMAND, Custodian::Storage, None);
    r.checkpoint(Checkpoint::Unproven);
    r.terminal(COMMAND, Outcome::Complete);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Resources,
            "an unproven stop returned retained custody"
        ))
    );
}

fn funded_interval(funded: u32, hit: bool) -> Recorder {
    let mut r = Recorder::new(1);
    r.checkpoint(Checkpoint::Qualified { funded, limit: 266 });
    r.published(K, A, META, BODY, ID);
    if hit {
        let read = r.lookup(K, Outcome::Hit, Some(A));
        r.delivered(
            read,
            (K, A),
            (META, BODY),
            ID,
            Outcome::Complete,
            Recorder::content(K, A, META, BODY),
        );
    } else {
        r.lookup(K, Outcome::Missing, None);
    }
    r
}

#[test]
fn always_miss_control_fails_progress_at_the_qualified_interval() {
    let verdict = check(&funded_interval(40, true).finish());
    assert!(
        verdict.satisfies(&[Obligation::Progress, Obligation::Bytes]),
        "{verdict:?}"
    );
    // A miss beside a published label is legal history, so the funded
    // interval's progress judgment is what rejects it.
    let missed = funded_interval(40, false);
    let attempt = missed
        .rows()
        .iter()
        .rfind(|row| row.kind == ActionKind::Lookup)
        .expect("the funded lookup")
        .op;
    let verdict = check(&missed.finish());
    assert_eq!(
        verdict.violated(),
        Some((
            Obligation::Progress,
            "a qualified funded interval produced no exact hit"
        ))
    );
    assert!(matches!(verdict, Verdict::Violation(v) if v.op == attempt));
    let mut r = Recorder::new(1);
    r.checkpoint(Checkpoint::Qualified {
        funded: 40,
        limit: 266,
    });
    let attempt = r.lookup(K, Outcome::Missing, None);
    let verdict = check(&r.finish());
    assert_eq!(
        verdict.violated(),
        Some((
            Obligation::Progress,
            "a qualified funded interval produced no exact hit"
        ))
    );
    assert!(matches!(verdict, Verdict::Violation(v) if v.op == attempt));
    assert_eq!(
        check(&funded_interval(267, true).finish()).violated(),
        Some((
            Obligation::Progress,
            "funded recovery exceeded its action bound"
        ))
    );
}

#[test]
fn an_unqualified_interval_permits_misses() {
    let mut r = Recorder::new(1);
    r.checkpoint(Checkpoint::Stopped);
    r.lookup(K, Outcome::Missing, None);
    assert!(matches!(check(&r.finish()), Verdict::Pass(_)));
}

#[test]
fn a_stream_that_stops_before_its_seal_is_truncated() {
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Storage, None);
    assert_eq!(
        check(&r.unsealed()),
        Verdict::Inconclusive(Inconclusive::Truncated)
    );
}

#[test]
fn grace_end_hands_the_key_a_visibility_end() {
    let grace = |fresh: Outcome, label: Option<Label>| {
        let mut r = Recorder::new(1);
        r.published(K, A, META, BODY, ID);
        r.hold(SLOT, Custodian::Grace, (K, A));
        r.end_visibility(SLOT, Custodian::Grace, (K, A), VisibilityCause::GraceEnd);
        r.lookup(K, fresh, label);
        r.finish()
    };
    assert!(check(&grace(Outcome::Missing, None)).satisfies(&[Obligation::History]));
    assert_eq!(
        check(&grace(Outcome::Hit, Some(A))).violated(),
        Some((
            Obligation::History,
            "a hit after a recorded removal of its label in the same tenure"
        ))
    );
}

#[test]
fn an_exclusive_custodian_takes_a_held_incarnation_once() {
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Storage, None);
    r.take(BUFFER, Custodian::Nic, None);
    r.take(BUFFER, Custodian::Nic, None);
    assert!(check(&r.finish()).satisfies(&[Obligation::Custody]));
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Storage, None);
    r.take(BUFFER, Custodian::Storage, None);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Custody,
            "an exclusive custodian took a resource it already held"
        ))
    );
}

#[test]
fn a_cancel_keeps_storage_custody_until_the_exact_terminal() {
    let stale = (ResourceKind::Command, 2, 0x20002);
    let cancelled = |terminal: (ResourceKind, u32, u64)| {
        let mut r = Recorder::new(1);
        r.take(COMMAND, Custodian::Storage, None);
        r.cancel(COMMAND);
        r.terminal(terminal, Outcome::Complete);
        r.take(stale, Custodian::Storage, None);
        r.finish()
    };
    assert!(check(&cancelled(COMMAND)).satisfies(&[Obligation::Custody]));
    assert_eq!(
        check(&cancelled(stale)).violated(),
        Some((
            Obligation::Custody,
            "a resource was reused while a custodian held an earlier incarnation"
        ))
    );
}

#[test]
fn a_qualified_checkpoint_needs_its_holders_released() {
    for (holder, custodian) in [(BUFFER, Custodian::Nic), (SLOT, Custodian::Reader)] {
        let mut r = Recorder::new(1);
        r.take(holder, custodian, None);
        r.checkpoint(Checkpoint::Qualified {
            funded: 1,
            limit: 266,
        });
        assert_eq!(
            check(&r.finish()).violated(),
            Some((
                Obligation::Progress,
                "a qualified checkpoint began with holders outstanding"
            )),
            "{custodian:?}"
        );
    }
}

#[test]
fn an_eviction_ends_the_slot_label_in_the_key_history() {
    let evicted = |fresh: Outcome, label: Option<Label>| {
        let mut r = Recorder::new(1);
        r.published(K, A, META, BODY, ID);
        r.hold(SLOT, Custodian::Storage, (K, A));
        r.end_visibility(SLOT, Custodian::Storage, (K, A), VisibilityCause::Eviction);
        r.lookup(K, fresh, label);
        r.finish()
    };
    assert!(check(&evicted(Outcome::Missing, None)).satisfies(&[Obligation::History]));
    assert_eq!(
        check(&evicted(Outcome::Hit, Some(A))).violated(),
        Some((
            Obligation::History,
            "a hit after a recorded removal of its label in the same tenure"
        ))
    );
}

#[test]
fn a_visibility_end_must_return_held_custody() {
    let ended = |returned: (ResourceKind, u32, u64), custodian: Custodian| {
        let mut r = Recorder::new(1);
        r.published(K, A, META, BODY, ID);
        r.hold(SLOT, Custodian::Storage, (K, A));
        r.end_visibility(returned, custodian, (K, A), VisibilityCause::GraceEnd);
        r.lookup(K, Outcome::Missing, None);
        r.finish()
    };
    let verdict = check(&ended(SLOT, Custodian::Storage));
    assert!(
        verdict.satisfies(&[Obligation::History, Obligation::Custody]),
        "{verdict:?}"
    );
    let stale = (ResourceKind::Slot, 3, 8);
    for (returned, custodian) in [(SLOT, Custodian::Grace), (stale, Custodian::Storage)] {
        assert_eq!(
            check(&ended(returned, custodian)).violated(),
            Some((
                Obligation::Custody,
                "a visibility end returned no held custody"
            )),
            "{returned:?} {custodian:?}"
        );
    }
}

fn with_outcome(r: &Recorder, op: OpId, outcome: Outcome) -> History {
    Recorder::rebuilt(r.rows().iter().cloned().map(|mut row| {
        if row.op == op {
            row.outcome = Some(outcome);
        }
        row
    }))
}

#[test]
fn a_take_or_release_without_information_leaves_custody_unchanged() {
    let refusals = NoInformation::ALL
        .into_iter()
        .filter(|member| *member != NoInformation::ClockUnavailable);
    for member in refusals {
        let refused = Outcome::NoInformation(member);
        let mut r = Recorder::new(1);
        r.take(BUFFER, Custodian::Storage, None);
        let release = r.release(BUFFER, Custodian::Storage);
        r.take(REUSED, Custodian::Storage, None);
        assert_eq!(
            check(&with_outcome(&r, release, refused)).violated(),
            Some((
                Obligation::Custody,
                "a resource was reused while a custodian held an earlier incarnation"
            )),
            "{member:?}"
        );
        let mut r = Recorder::new(1);
        let take = r.take(BUFFER, Custodian::Storage, None);
        r.report(
            ResourceKind::Buffer,
            ReportKind::Pool,
            ReportState::Value(0),
        );
        r.release(BUFFER, Custodian::Storage);
        r.report(
            ResourceKind::Buffer,
            ReportKind::Mismatched,
            ReportState::Value(1),
        );
        let verdict = check(&with_outcome(&r, take, refused));
        assert!(
            verdict.satisfies(&[Obligation::Resources]),
            "{member:?}: {verdict:?}"
        );
        let mut r = Recorder::new(1);
        r.published(K, A, META, BODY, ID);
        r.hold(SLOT, Custodian::Storage, (K, A));
        let ended = r.end_visibility(SLOT, Custodian::Storage, (K, A), VisibilityCause::Eviction);
        r.lookup(K, Outcome::Hit, Some(A));
        let verdict = check(&with_outcome(&r, ended, refused));
        assert!(
            verdict.satisfies(&[Obligation::History, Obligation::Custody]),
            "{member:?}: {verdict:?}"
        );
    }
}

#[test]
fn a_checkpoint_without_information_changes_nothing() {
    let mut r = Recorder::new(1);
    r.take(COMMAND, Custodian::Storage, None);
    r.checkpoint(Checkpoint::Unproven);
    let stopped = r.checkpoint(Checkpoint::Stopped);
    r.terminal(COMMAND, Outcome::Complete);
    assert!(check(&r.finish()).satisfies(&[Obligation::Custody]));
    let mut r = Recorder::new(1);
    r.take(COMMAND, Custodian::Storage, None);
    r.checkpoint(Checkpoint::Unproven);
    r.checkpoint(Checkpoint::Stopped);
    r.terminal(COMMAND, Outcome::Complete);
    let timed_out = Outcome::NoInformation(NoInformation::TimedOut);
    assert_eq!(
        check(&with_outcome(&r, stopped, timed_out)).violated(),
        Some((
            Obligation::Resources,
            "an unproven stop returned retained custody"
        ))
    );
    let mut r = Recorder::new(1);
    r.checkpoint(Checkpoint::Qualified {
        funded: 40,
        limit: 266,
    });
    let stopped = r.checkpoint(Checkpoint::Stopped);
    r.published(K, A, META, BODY, ID);
    let read = r.lookup(K, Outcome::Hit, Some(A));
    r.delivered(
        read,
        (K, A),
        (META, BODY),
        ID,
        Outcome::Complete,
        Recorder::content(K, A, META, BODY),
    );
    let verdict = check(&with_outcome(&r, stopped, timed_out));
    assert!(verdict.satisfies(&[Obligation::Progress]), "{verdict:?}");
}

#[test]
fn a_terminal_ends_a_command() {
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Storage, None);
    let terminal = r.terminal(BUFFER, Outcome::Complete);
    r.checkpoint(Checkpoint::Released);
    assert_eq!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: terminal,
            field: Field::Resource,
        })
    );
}

#[test]
fn a_report_names_the_resource_its_kind_measures() {
    let measured = [
        (ReportKind::Pool, ResourceKind::Buffer),
        (ReportKind::Table, ResourceKind::Command),
        (ReportKind::Ledger, ResourceKind::Slot),
        (ReportKind::Ledger, ResourceKind::Extent),
        (ReportKind::Ledger, ResourceKind::Credit),
        (ReportKind::EngineBudget, ResourceKind::BudgetCharge),
        (ReportKind::RequestShares, ResourceKind::RequestShare),
        (ReportKind::RetainedChunks, ResourceKind::RetainedChunk),
        (ReportKind::WriteProgress, ResourceKind::WriteQuota),
    ];
    for report in [
        ReportKind::Pool,
        ReportKind::Table,
        ReportKind::Ledger,
        ReportKind::EngineBudget,
        ReportKind::RequestShares,
        ReportKind::RetainedChunks,
        ReportKind::WriteProgress,
        ReportKind::Mismatched,
    ] {
        for resource in ResourceKind::ALL {
            let mut r = Recorder::new(1);
            r.report(resource, report, ReportState::Value(0));
            let verdict = check(&r.finish());
            let admitted =
                report == ReportKind::Mismatched || measured.contains(&(report, resource));
            assert_eq!(
                matches!(verdict, Verdict::Pass(_)),
                admitted,
                "{report:?} {resource:?}: {verdict:?}"
            );
        }
    }
    let mut r = Recorder::new(1);
    r.take(COMMAND, Custodian::Storage, None);
    r.report(
        ResourceKind::Command,
        ReportKind::Pool,
        ReportState::Value(1),
    );
    assert!(matches!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            field: Field::Report,
            ..
        })
    ));
}

#[test]
fn a_resource_release_sharing_a_lookup_op_names_the_label_owner() {
    let other = KeyId(1);
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.hold(SLOT, Custodian::Storage, (K, A));
    let ended = r.end_visibility(
        SLOT,
        Custodian::Storage,
        (other, A),
        VisibilityCause::Eviction,
    );
    let read = r.lookup(K, Outcome::Hit, Some(A));
    let shared = Recorder::rebuilt(r.rows().iter().cloned().map(|mut row| {
        if row.op == ended {
            row.op = read;
        }
        row
    }));
    assert_eq!(
        check(&shared),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: read,
            field: Field::Label,
        })
    );
}

#[test]
fn held_lengths_past_u64_match_no_report() {
    let mut r = Recorder::new(1);
    r.take(
        (ResourceKind::BudgetCharge, 0, 0),
        Custodian::Owner,
        Some((0, u64::MAX)),
    );
    r.take(
        (ResourceKind::BudgetCharge, 1, 0),
        Custodian::Owner,
        Some((0, 1)),
    );
    r.report(
        ResourceKind::BudgetCharge,
        ReportKind::EngineBudget,
        ReportState::Value(0),
    );
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Resources,
            "a production report disagreed with the independent count"
        ))
    );
}

#[test]
fn budget_charges_measure_bytes_and_extents_measure_addresses() {
    let mut r = Recorder::new(1);
    r.take(
        (ResourceKind::BudgetCharge, 0, 0),
        Custodian::Owner,
        Some((0, 8)),
    );
    r.take(
        (ResourceKind::BudgetCharge, 1, 0),
        Custodian::Owner,
        Some((0, 8)),
    );
    r.report(
        ResourceKind::BudgetCharge,
        ReportKind::EngineBudget,
        ReportState::Value(16),
    );
    let verdict = check(&r.finish());
    assert!(
        verdict.satisfies(&[Obligation::Custody, Obligation::Resources]),
        "{verdict:?}"
    );
    let mut r = Recorder::new(1);
    let taken = r.take(
        (ResourceKind::Extent, 0, 1),
        Custodian::Storage,
        Some((u64::MAX, 1)),
    );
    r.take(
        (ResourceKind::Extent, 1, 1),
        Custodian::Storage,
        Some((u64::MAX, 1)),
    );
    assert_eq!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: taken,
            field: Field::Resource,
        })
    );
}

#[test]
fn a_span_measured_resource_declares_its_geometry_when_first_taken() {
    let mut r = Recorder::new(1);
    r.take((ResourceKind::Extent, 0, 1), Custodian::Storage, None);
    r.report(
        ResourceKind::Extent,
        ReportKind::Ledger,
        ReportState::Value(1),
    );
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Custody,
            "a span-measured resource was taken without geometry"
        ))
    );
    let mut r = Recorder::new(1);
    r.take(
        (ResourceKind::Extent, 0, 1),
        Custodian::Storage,
        Some((0, 8)),
    );
    r.take((ResourceKind::Extent, 0, 1), Custodian::Reader, None);
    r.report(
        ResourceKind::Extent,
        ReportKind::Ledger,
        ReportState::Value(8),
    );
    let verdict = check(&r.finish());
    assert!(
        verdict.satisfies(&[Obligation::Custody, Obligation::Resources]),
        "{verdict:?}"
    );
}

#[test]
fn a_returned_incarnation_passes_forward_and_never_back() {
    let retaken = |next: (ResourceKind, u32, u64), custodian: Custodian| {
        let mut r = Recorder::new(1);
        r.take(BUFFER, Custodian::Storage, None);
        r.release(BUFFER, Custodian::Storage);
        r.take(next, custodian, None);
        r.release(BUFFER, Custodian::Storage);
        r.checkpoint(Checkpoint::Released);
        r.finish()
    };
    assert_eq!(
        check(&retaken(BUFFER, Custodian::Storage)).violated(),
        Some((
            Obligation::Custody,
            "an exclusive custodian retook an incarnation it had returned"
        ))
    );
    assert_eq!(
        check(&retaken(REUSED, Custodian::Storage)).violated(),
        Some((
            Obligation::Resources,
            "a released checkpoint kept capacity its obligations no longer justify"
        ))
    );
    let handed_over = check(&retaken(BUFFER, Custodian::Grace));
    assert_eq!(
        handed_over.violated(),
        Some((
            Obligation::Resources,
            "a released checkpoint kept capacity its obligations no longer justify"
        ))
    );
    let mut r = Recorder::new(1);
    r.take(REUSED, Custodian::Storage, None);
    r.release(REUSED, Custodian::Storage);
    r.take(BUFFER, Custodian::Grace, None);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Custody,
            "a resource was retaken under an earlier incarnation"
        ))
    );
}

#[test]
fn exclusive_custodians_hold_an_incarnation_one_at_a_time() {
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Owner, None);
    r.take(BUFFER, Custodian::Storage, None);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Custody,
            "two exclusive custodians held one incarnation"
        ))
    );
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Owner, None);
    r.release(BUFFER, Custodian::Owner);
    r.take(BUFFER, Custodian::Storage, None);
    assert!(check(&r.finish()).satisfies(&[Obligation::Custody]));
}

#[test]
fn a_visibility_end_names_the_publication_its_slot_holds() {
    const B: Label = Label(2);
    let other = (ResourceKind::Slot, 4, 7);
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.published(K, B, META, BODY, ID);
    r.hold(SLOT, Custodian::Storage, (K, A));
    r.hold(other, Custodian::Storage, (K, B));
    r.end_visibility(SLOT, Custodian::Storage, (K, B), VisibilityCause::Eviction);
    r.lookup(K, Outcome::Missing, None);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Custody,
            "a visibility end named a publication its slot did not hold"
        ))
    );
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.take(SLOT, Custodian::Storage, None);
    r.end_visibility(SLOT, Custodian::Storage, (K, A), VisibilityCause::Eviction);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Custody,
            "a visibility end named a publication its slot did not hold"
        ))
    );
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.hold(SLOT, Custodian::Storage, (K, A));
    r.release(SLOT, Custodian::Storage);
    r.take(SLOT, Custodian::Grace, None);
    r.end_visibility(SLOT, Custodian::Grace, (K, A), VisibilityCause::GraceEnd);
    r.lookup(K, Outcome::Missing, None);
    let verdict = check(&r.finish());
    assert!(
        verdict.satisfies(&[Obligation::History, Obligation::Custody]),
        "{verdict:?}"
    );
}

#[test]
fn a_counted_resource_carries_no_incarnation() {
    let credit = (ResourceKind::Credit, 0, 0);
    let mut r = Recorder::new(1);
    r.take(credit, Custodian::Reader, None);
    let returned = r.release(credit, Custodian::Reader);
    r.checkpoint(Checkpoint::Released);
    let numbered = Recorder::rebuilt(r.rows().iter().cloned().map(|mut row| {
        if row.op == returned {
            row.incarnation = Some(Incarnation(3));
        }
        row
    }));
    assert_eq!(
        check(&numbered),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: returned,
            field: Field::Incarnation,
        })
    );
}

#[test]
fn an_extent_or_write_quota_span_covers_at_least_one_unit() {
    for (resource, report) in [
        ((ResourceKind::Extent, 0, 1), ReportKind::Ledger),
        (
            (ResourceKind::WriteQuota, 0, 0x100),
            ReportKind::WriteProgress,
        ),
    ] {
        let mut r = Recorder::new(1);
        if resource.0 == ResourceKind::WriteQuota {
            r.take((ResourceKind::Command, 0, 0x100), Custodian::Storage, None);
        }
        let taken = r.take(resource, Custodian::Storage, Some((0, 0)));
        r.report(resource.0, report, ReportState::Value(0));
        assert_eq!(
            check(&r.finish()),
            Verdict::Inconclusive(Inconclusive::Malformed {
                op: taken,
                field: Field::Resource,
            }),
            "{resource:?}"
        );
    }
    let mut r = Recorder::new(1);
    r.take(
        (ResourceKind::BudgetCharge, 0, 0),
        Custodian::Owner,
        Some((0, 0)),
    );
    r.report(
        ResourceKind::BudgetCharge,
        ReportKind::EngineBudget,
        ReportState::Value(0),
    );
    assert!(check(&r.finish()).satisfies(&[Obligation::Resources]));
}

#[test]
fn received_bytes_match_the_declared_lengths_before_any_comparison() {
    for received in [
        BODY as usize + META as usize - 1,
        BODY as usize + META as usize + 1,
    ] {
        let mut r = Recorder::new(1);
        let fill = r.published_bytes(K, A, META, &vec![0xA5; received], ID);
        let declared = Recorder::rebuilt(r.rows().iter().cloned().map(|mut row| {
            if row.kind == ActionKind::Fill {
                row.body_len = Some(BODY);
            }
            row
        }));
        assert_eq!(
            check(&declared),
            Verdict::Inconclusive(Inconclusive::Malformed {
                op: fill,
                field: Field::Payload,
            }),
            "{received}"
        );
    }
}

#[test]
fn a_holder_takes_only_a_live_incarnation() {
    for holder in [Custodian::Nic, Custodian::Reader] {
        let mut r = Recorder::new(1);
        r.take(BUFFER, Custodian::Storage, None);
        r.release(BUFFER, Custodian::Storage);
        r.take(BUFFER, holder, None);
        assert_eq!(
            check(&r.finish()).violated(),
            Some((Obligation::Custody, "a holder took a completed incarnation")),
            "{holder:?}"
        );
    }
    let credit = (ResourceKind::Credit, 0, 0);
    let mut r = Recorder::new(1);
    r.take(credit, Custodian::Reader, None);
    r.release(credit, Custodian::Reader);
    r.take(credit, Custodian::Reader, None);
    assert!(check(&r.finish()).satisfies(&[Obligation::Custody]));
}

#[test]
fn a_counted_resource_is_taken_once_while_held() {
    let credit = (ResourceKind::Credit, 0, 0);
    let mut r = Recorder::new(1);
    r.take(credit, Custodian::Reader, None);
    r.take(credit, Custodian::Reader, None);
    r.report(
        ResourceKind::Credit,
        ReportKind::Ledger,
        ReportState::Value(1),
    );
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Custody,
            "a counted resource was taken while held"
        ))
    );
}

#[test]
fn a_qualified_checkpoint_needs_every_lease_returned() {
    const B: Label = Label(2);
    let other = KeyId(1);
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.lookup(K, Outcome::Hit, Some(A));
    let checkpoint = r.checkpoint(Checkpoint::Qualified {
        funded: 1,
        limit: 266,
    });
    r.published(other, B, META, BODY, ID);
    let read = r.lookup(other, Outcome::Hit, Some(B));
    r.delivered(
        read,
        (other, B),
        (META, BODY),
        ID,
        Outcome::Complete,
        Recorder::content(other, B, META, BODY),
    );
    let verdict = check(&r.finish());
    assert_eq!(
        verdict.violated(),
        Some((
            Obligation::Progress,
            "a qualified checkpoint began with a lease outstanding"
        ))
    );
    assert!(matches!(verdict, Verdict::Violation(v) if v.op == checkpoint));
}

#[test]
fn a_counted_resource_is_retaken_after_its_return() {
    let charge = (ResourceKind::BudgetCharge, 0, 0);
    let mut r = Recorder::new(1);
    r.take(charge, Custodian::Owner, Some((0, 4)));
    r.release(charge, Custodian::Owner);
    r.take(charge, Custodian::Owner, Some((0, 8)));
    r.report(
        ResourceKind::BudgetCharge,
        ReportKind::EngineBudget,
        ReportState::Value(8),
    );
    let verdict = check(&r.finish());
    assert!(
        verdict.satisfies(&[Obligation::Custody, Obligation::Resources]),
        "{verdict:?}"
    );
}

#[test]
fn a_qualified_interval_publishes_after_its_checkpoint_began() {
    let mut r = Recorder::new(1);
    let publication = r.published(K, A, META, BODY, ID);
    let checkpoint = r.checkpoint(Checkpoint::Qualified {
        funded: 1,
        limit: 266,
    });
    let read = r.lookup(K, Outcome::Hit, Some(A));
    r.delivered(
        read,
        (K, A),
        (META, BODY),
        ID,
        Outcome::Complete,
        Recorder::content(K, A, META, BODY),
    );
    let publish_invoked = r
        .rows()
        .iter()
        .find(|row| row.op == publication && row.kind == ActionKind::Publish)
        .and_then(|row| row.invoked)
        .expect("a publication");
    let in_flight = Recorder::rebuilt(r.rows().iter().cloned().map(|mut row| {
        let spread = |o: Option<Ordinal>| o.map(|Ordinal(o)| Ordinal(o * 2));
        row.invoked = spread(row.invoked);
        row.responded = spread(row.responded);
        row.custody_end = spread(row.custody_end);
        if row.op == checkpoint {
            row.responded = Some(Ordinal(publish_invoked.0 * 2 + 1));
        }
        row
    }));
    assert_eq!(
        check(&in_flight).violated(),
        Some((
            Obligation::Progress,
            "a qualified funded interval produced no exact hit"
        ))
    );
}

#[test]
fn a_report_without_information_is_no_sample() {
    let timed_out = Outcome::NoInformation(NoInformation::TimedOut);
    for state in [
        ReportState::Value(0),
        ReportState::Poisoned,
        ReportState::Absent,
    ] {
        let mut r = Recorder::new(1);
        r.take(BUFFER, Custodian::Storage, None);
        let report = r.report(ResourceKind::Buffer, ReportKind::Pool, state);
        let verdict = check(&with_outcome(&r, report, timed_out));
        assert!(
            matches!(verdict, Verdict::Pass(_)),
            "{state:?}: {verdict:?}"
        );
        assert!(!verdict.satisfies(&[Obligation::Resources]), "{state:?}");
    }
}

#[test]
fn a_slot_publication_ends_before_the_slot_moves_on() {
    const B: Label = Label(2);
    let other = KeyId(1);
    let reused = (ResourceKind::Slot, 3, 8);
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.hold(SLOT, Custodian::Storage, (K, A));
    r.release(SLOT, Custodian::Storage);
    r.published(other, B, META, BODY, ID);
    r.hold(reused, Custodian::Storage, (other, B));
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Custody,
            "a slot was reused before its publication's visibility ended"
        ))
    );
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.hold(SLOT, Custodian::Storage, (K, A));
    r.release(SLOT, Custodian::Storage);
    r.checkpoint(Checkpoint::Released);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Resources,
            "a released checkpoint left a publication's visibility open"
        ))
    );
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.hold(SLOT, Custodian::Storage, (K, A));
    r.release(SLOT, Custodian::Storage);
    r.take(SLOT, Custodian::Grace, None);
    r.end_visibility(SLOT, Custodian::Grace, (K, A), VisibilityCause::GraceEnd);
    r.published(other, B, META, BODY, ID);
    r.hold(reused, Custodian::Storage, (other, B));
    r.end_visibility(
        reused,
        Custodian::Storage,
        (other, B),
        VisibilityCause::Eviction,
    );
    r.checkpoint(Checkpoint::Released);
    let verdict = check(&r.finish());
    assert!(
        verdict.satisfies(&[Obligation::Custody, Obligation::Resources]),
        "{verdict:?}"
    );
}

#[test]
fn a_held_extent_keeps_one_geometry_per_incarnation() {
    let extent = (ResourceKind::Extent, 0, 1);
    let retaken = |span: Option<(u64, u64)>| {
        let mut r = Recorder::new(1);
        r.take(extent, Custodian::Storage, Some((0, 8)));
        r.take(extent, Custodian::Reader, span);
        r.finish()
    };
    for span in [None, Some((0, 8))] {
        assert!(
            check(&retaken(span)).satisfies(&[Obligation::Custody]),
            "{span:?}"
        );
    }
    assert_eq!(
        check(&retaken(Some((16, 8)))).violated(),
        Some((
            Obligation::Custody,
            "a held extent was taken under different geometry"
        ))
    );
}

#[test]
fn a_visibility_end_names_the_label_owner() {
    let other = KeyId(1);
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.hold(SLOT, Custodian::Storage, (K, A));
    let ended = r.end_visibility(
        SLOT,
        Custodian::Storage,
        (other, A),
        VisibilityCause::Eviction,
    );
    r.lookup(K, Outcome::Hit, Some(A));
    assert_eq!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: ended,
            field: Field::Label,
        })
    );
}

#[test]
fn a_qualified_interval_reads_back_its_own_publication() {
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.checkpoint(Checkpoint::Qualified {
        funded: 40,
        limit: 266,
    });
    let read = r.lookup(K, Outcome::Hit, Some(A));
    r.delivered(
        read,
        (K, A),
        (META, BODY),
        ID,
        Outcome::Complete,
        Recorder::content(K, A, META, BODY),
    );
    let verdict = check(&r.finish());
    assert_eq!(
        verdict.violated(),
        Some((
            Obligation::Progress,
            "a qualified funded interval produced no exact hit"
        ))
    );
    assert!(matches!(verdict, Verdict::Violation(v) if v.op == read));
}

#[test]
fn a_span_belongs_to_an_extent() {
    let mut r = Recorder::new(1);
    let taken = r.take(BUFFER, Custodian::Storage, Some((0, 8)));
    r.report(
        ResourceKind::Buffer,
        ReportKind::Pool,
        ReportState::Value(8),
    );
    assert_eq!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: taken,
            field: Field::Resource,
        })
    );
}

#[test]
fn a_visibility_end_returns_slot_custody() {
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.take(BUFFER, Custodian::Storage, None);
    let ended = r.end_visibility(
        BUFFER,
        Custodian::Storage,
        (K, A),
        VisibilityCause::Eviction,
    );
    r.lookup(K, Outcome::Missing, None);
    assert_eq!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: ended,
            field: Field::Resource,
        })
    );
}

#[test]
fn a_delivery_carries_the_content_identity() {
    let delivered = |identity: (u64, u64)| {
        let mut r = Recorder::new(1);
        r.published(K, A, META, BODY, ID);
        let read = r.lookup(K, Outcome::Hit, Some(A));
        r.delivered(
            read,
            (K, A),
            (META, BODY),
            identity,
            Outcome::Complete,
            Recorder::content(K, A, META, BODY),
        );
        r.finish()
    };
    assert!(check(&delivered(ID)).satisfies(&[Obligation::Bytes]));
    for identity in [(ID.0 + 1, ID.1), (ID.0, ID.1 + 1)] {
        assert_eq!(
            check(&delivered(identity)).violated(),
            Some((
                Obligation::Bytes,
                "delivered identity differs from the acquired content"
            )),
            "{identity:?}"
        );
    }
    let mut r = Recorder::new(1);
    let fill = r.published(K, A, META, BODY, ID);
    let anonymous = Recorder::rebuilt(r.rows().iter().cloned().map(|mut row| {
        if row.kind == ActionKind::Fill {
            row.session = None;
            row.incarnation = None;
        }
        row
    }));
    assert_eq!(
        check(&anonymous),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: fill,
            field: Field::Session,
        })
    );
}

#[test]
fn an_unmatched_return_counts_as_a_mismatch() {
    let returned = |reported: u64| {
        let mut r = Recorder::new(1);
        r.take(BUFFER, Custodian::Nic, None);
        r.release(BUFFER, Custodian::Nic);
        r.release(BUFFER, Custodian::Nic);
        r.release(REUSED, Custodian::Nic);
        r.report(
            ResourceKind::Buffer,
            ReportKind::Mismatched,
            ReportState::Value(reported),
        );
        r.finish()
    };
    assert!(check(&returned(2)).satisfies(&[Obligation::Resources]));
    assert_eq!(
        check(&returned(1)).violated(),
        Some((
            Obligation::Resources,
            "a production report disagreed with the independent count"
        ))
    );
}

const SHARE: (ResourceKind, u32, u64) = (ResourceKind::RequestShare, 0, 0);
const HEALTHY_SHARE: (ResourceKind, u32, u64) = (ResourceKind::RequestShare, 1, 0);

fn two_owners(returned: bool, turns: u32, hit: bool) -> Recorder {
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.take(SHARE, Custodian::Storage, None);
    r.isolated(SHARE);
    if returned {
        r.release(SHARE, Custodian::Storage);
    }
    r.checkpoint(Checkpoint::Healthy { turns, bound: 200 });
    r.take(HEALTHY_SHARE, Custodian::Storage, None);
    if hit {
        let read = r.lookup(K, Outcome::Hit, Some(A));
        r.delivered(
            read,
            (K, A),
            (META, BODY),
            ID,
            Outcome::Complete,
            Recorder::content(K, A, META, BODY),
        );
    }
    r.release(HEALTHY_SHARE, Custodian::Storage);
    r.report(
        ResourceKind::RequestShare,
        ReportKind::RequestShares,
        ReportState::Value(1),
    );
    r
}

#[test]
fn a_failed_owner_keeps_its_custody_while_a_healthy_owner_serves() {
    let verdict = check(&two_owners(false, 40, true).finish());
    assert!(
        verdict.satisfies(&[Obligation::Isolation, Obligation::Resources]),
        "{verdict:?}"
    );
    assert_eq!(
        check(&two_owners(true, 40, true).finish()).violated(),
        Some((
            Obligation::Isolation,
            "a failed owner returned custody its unproven stop retained"
        ))
    );
    assert_eq!(
        check(&two_owners(false, 201, true).finish()).violated(),
        Some((
            Obligation::Isolation,
            "a healthy owner starved past its fixture bound"
        ))
    );
    assert_eq!(
        check(&two_owners(false, 40, false).finish()).violated(),
        Some((
            Obligation::Isolation,
            "a healthy owner served no exact bytes"
        ))
    );
}

#[test]
fn a_released_checkpoint_ends_the_failed_owner_retention() {
    let charge = (ResourceKind::BudgetCharge, 0, 0);
    let mut r = Recorder::new(1);
    r.take(charge, Custodian::Owner, Some((0, 4)));
    r.isolated(charge);
    r.checkpoint(Checkpoint::Released);
    r.release(charge, Custodian::Owner);
    assert!(check(&r.finish()).satisfies(&[Obligation::Isolation]));
    let mut r = Recorder::new(1);
    r.take(charge, Custodian::Owner, Some((0, 4)));
    r.isolated(charge);
    r.checkpoint(Checkpoint::Released);
    r.take(SHARE, Custodian::Storage, None);
    r.checkpoint(Checkpoint::Unproven);
    r.release(SHARE, Custodian::Storage);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Resources,
            "an unproven stop returned retained custody"
        ))
    );
}

#[test]
fn a_healthy_checkpoint_needs_its_holders_released() {
    let mut r = Recorder::new(1);
    r.take(SLOT, Custodian::Reader, None);
    r.checkpoint(Checkpoint::Healthy {
        turns: 1,
        bound: 200,
    });
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Isolation,
            "a healthy checkpoint began with holders outstanding"
        ))
    );
}

#[test]
fn a_healthy_checkpoint_activates_no_progress() {
    let verdict = check(&two_owners(false, 40, true).finish());
    assert!(verdict.satisfies(&[Obligation::Isolation]), "{verdict:?}");
    assert!(!verdict.satisfies(&[Obligation::Progress]), "{verdict:?}");
}

#[test]
fn an_isolated_stop_retains_only_the_failed_owners_custody() {
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.take(HEALTHY_SHARE, Custodian::Storage, None);
    r.take(SHARE, Custodian::Storage, None);
    r.isolated(SHARE);
    r.checkpoint(Checkpoint::Healthy {
        turns: 40,
        bound: 200,
    });
    let read = r.lookup(K, Outcome::Hit, Some(A));
    r.delivered(
        read,
        (K, A),
        (META, BODY),
        ID,
        Outcome::Complete,
        Recorder::content(K, A, META, BODY),
    );
    r.release(HEALTHY_SHARE, Custodian::Storage);
    r.report(
        ResourceKind::RequestShare,
        ReportKind::RequestShares,
        ReportState::Value(1),
    );
    let verdict = check(&r.finish());
    assert!(
        verdict.satisfies(&[Obligation::Isolation, Obligation::Resources]),
        "{verdict:?}"
    );
    let mut r = Recorder::new(1);
    r.isolated(SHARE);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Isolation,
            "an isolated stop retained custody no custodian held"
        ))
    );
    let mut r = Recorder::new(1);
    let bare = r.checkpoint(Checkpoint::Isolated);
    assert_eq!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: bare,
            field: Field::Resource,
        })
    );
    let mut r = Recorder::new(1);
    let client = r.isolated((ResourceKind::SourceSlot, 0, 1));
    assert_eq!(
        check(&r.finish()),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: client,
            field: Field::Resource,
        })
    );
}

#[test]
fn an_isolated_stop_names_the_held_incarnation() {
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Storage, None);
    r.isolated(REUSED);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Isolation,
            "an isolated stop retained custody no custodian held"
        ))
    );
    let mut r = Recorder::new(1);
    r.take(BUFFER, Custodian::Storage, None);
    let stop = r.isolated(BUFFER);
    let anonymous = Recorder::rebuilt(r.rows().iter().cloned().map(|mut row| {
        if row.op == stop {
            row.incarnation = None;
        }
        row
    }));
    assert_eq!(
        check(&anonymous),
        Verdict::Inconclusive(Inconclusive::Malformed {
            op: stop,
            field: Field::Incarnation,
        })
    );
}

#[test]
fn an_isolated_stop_keeps_an_earlier_unproven_retention() {
    let mut r = Recorder::new(1);
    r.take(SHARE, Custodian::Storage, None);
    r.checkpoint(Checkpoint::Unproven);
    r.take(HEALTHY_SHARE, Custodian::Storage, None);
    r.isolated(HEALTHY_SHARE);
    r.release(SHARE, Custodian::Storage);
    assert_eq!(
        check(&r.finish()).violated(),
        Some((
            Obligation::Resources,
            "an unproven stop returned retained custody"
        ))
    );
}

#[test]
fn a_failed_owner_may_retain_a_holder_while_a_healthy_owner_serves() {
    let mut r = Recorder::new(1);
    r.published(K, A, META, BODY, ID);
    r.take(SHARE, Custodian::Storage, None);
    r.take(SLOT, Custodian::Reader, None);
    r.isolated(SHARE);
    r.isolated(SLOT);
    r.checkpoint(Checkpoint::Healthy {
        turns: 40,
        bound: 200,
    });
    r.take(HEALTHY_SHARE, Custodian::Storage, None);
    let read = r.lookup(K, Outcome::Hit, Some(A));
    r.delivered(
        read,
        (K, A),
        (META, BODY),
        ID,
        Outcome::Complete,
        Recorder::content(K, A, META, BODY),
    );
    r.release(HEALTHY_SHARE, Custodian::Storage);
    r.report(
        ResourceKind::RequestShare,
        ReportKind::RequestShares,
        ReportState::Value(1),
    );
    let verdict = check(&r.finish());
    assert!(
        verdict.satisfies(&[Obligation::Isolation, Obligation::Resources]),
        "{verdict:?}"
    );
}

mod remote_put_writes {
    use super::{
        ActionKind, B, Checkpoint, Custodian, FAILED, Failure, Field, HIT, History, Inconclusive,
        K, MISSING, Obligation, Outcome, Recorder, ReportKind, ReportState, ResourceKind, Row,
        Script, Verdict, check,
    };

    const UNITS: u64 = 8;
    const WRITES: u32 = 2;
    const EXTENT: (ResourceKind, u32, u64) = (ResourceKind::Extent, 5, 1);
    const FILL_UNITS: u64 = 16;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Ending {
        Complete,
        Cancelled,
        Short,
        Revoked,
        Closed,
    }

    const ENDINGS: [Ending; 5] = [
        Ending::Complete,
        Ending::Cancelled,
        Ending::Short,
        Ending::Revoked,
        Ending::Closed,
    ];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Fault {
        EarlyQuota,
        EarlyBuffer,
        EarlyExtent,
        FreedAtCancel,
        LeakedQuota,
    }

    fn write(index: u32) -> [(ResourceKind, u32, u64); 3] {
        let token = 0x100 + u64::from(index);
        [
            (ResourceKind::Command, index, token),
            (ResourceKind::WriteQuota, index, token),
            (ResourceKind::Buffer, index, 1),
        ]
    }

    /// The production reports a correct owner gives with `outstanding`
    /// writes in flight: commands, their units, their staged buffers and,
    /// while `extent` is held, the fill's extent units.
    fn reports(r: &mut Recorder, outstanding: u64, extent: bool) {
        r.report(
            ResourceKind::Command,
            ReportKind::Table,
            ReportState::Value(outstanding),
        );
        r.report(
            ResourceKind::WriteQuota,
            ReportKind::WriteProgress,
            ReportState::Value(outstanding * UNITS),
        );
        r.report(
            ResourceKind::Buffer,
            ReportKind::Pool,
            ReportState::Value(outstanding),
        );
        r.report(
            ResourceKind::Extent,
            ReportKind::Ledger,
            ReportState::Value(if extent { FILL_UNITS } else { 0 }),
        );
    }

    /// Two accepted writes of one remote fill, each a command, its quota of
    /// `UNITS` and its staged buffer, held through `ending` until each
    /// command's terminal, then the fill's extent and a released checkpoint.
    /// A `fault` records one early or missing return while the production
    /// reports keep counting what a correct owner still holds, or
    /// (`FreedAtCancel`) a write-progress report that drops one held write's
    /// units.
    fn writes(ending: Ending, fault: Option<Fault>) -> Recorder {
        let mut r = Recorder::new(1);
        r.take(EXTENT, Custodian::Owner, Some((0, FILL_UNITS)));
        for index in 0..WRITES {
            let [command, quota, buffer] = write(index);
            r.take(buffer, Custodian::Storage, None);
            r.take(command, Custodian::Storage, None);
            r.take(quota, Custodian::Storage, Some((0, UNITS)));
        }
        reports(&mut r, u64::from(WRITES), true);
        match ending {
            Ending::Cancelled => {
                for index in 0..WRITES {
                    let [command, ..] = write(index);
                    r.cancel(command);
                }
            }
            Ending::Revoked => {
                r.invalidate(K, Outcome::Acknowledged);
            }
            Ending::Closed => {
                r.close(Outcome::Acknowledged);
            }
            Ending::Complete | Ending::Short => {}
        }
        let [_, first_quota, first_buffer] = write(0);
        match fault {
            Some(Fault::EarlyQuota) => {
                r.release(first_quota, Custodian::Storage);
            }
            Some(Fault::EarlyBuffer) => {
                r.release(first_buffer, Custodian::Storage);
            }
            Some(Fault::EarlyExtent) => {
                r.release(EXTENT, Custodian::Owner);
            }
            Some(Fault::FreedAtCancel) => {
                r.report(
                    ResourceKind::WriteQuota,
                    ReportKind::WriteProgress,
                    ReportState::Value((u64::from(WRITES) - 1) * UNITS),
                );
            }
            Some(Fault::LeakedQuota) | None => {}
        }
        reports(&mut r, u64::from(WRITES), true);
        let terminal = match ending {
            Ending::Complete | Ending::Revoked => Outcome::Complete,
            Ending::Short => Outcome::Damaged(Failure::Short),
            Ending::Cancelled | Ending::Closed => Outcome::Damaged(Failure::Quiesced),
        };
        let returned_early = |index: u32, early: Fault| index == 0 && fault == Some(early);
        for index in 0..WRITES {
            let [command, quota, buffer] = write(index);
            r.terminal(command, terminal);
            let leaked = index == 1 && fault == Some(Fault::LeakedQuota);
            if !returned_early(index, Fault::EarlyQuota) && !leaked {
                r.release(quota, Custodian::Storage);
            }
            if !returned_early(index, Fault::EarlyBuffer) {
                r.release(buffer, Custodian::Storage);
            }
        }
        // The leaked quota keeps its unit count; the released checkpoint
        // names the leak.
        if fault != Some(Fault::LeakedQuota) {
            reports(&mut r, 0, true);
        }
        if fault != Some(Fault::EarlyExtent) {
            r.release(EXTENT, Custodian::Owner);
        }
        r.checkpoint(Checkpoint::Released);
        r
    }

    /// The custody rows up to the writes' cancel, close or first terminal,
    /// then the upload's per-key rows, then the rest, so the attempt ends and
    /// its key is looked up while its writes are held; the attempt precedes
    /// a close, which admits no later fill.
    fn combined(attempt: History, custody: Recorder) -> History {
        let custody: Vec<Row> = custody
            .finish()
            .rows()
            .iter()
            .cloned()
            .map(|mut row| {
                row.op.0 += 1000;
                row
            })
            .collect();
        let split = custody
            .iter()
            .position(|r| {
                matches!(
                    r.kind,
                    ActionKind::Cancel | ActionKind::Close | ActionKind::Terminal
                )
            })
            .expect("an ending or terminal row");
        let mut rows: Vec<Row> = custody[..split].to_vec();
        rows.extend(attempt.rows().iter().cloned());
        rows.extend(custody[split..].iter().cloned());
        Recorder::renumber(&mut rows);
        Recorder::rebuilt(rows)
    }

    #[test]
    fn accepted_writes_keep_command_quota_and_buffer_until_each_terminal() {
        for ending in ENDINGS {
            let verdict = check(&writes(ending, None).finish());
            assert!(
                verdict.satisfies(&[Obligation::Custody, Obligation::Resources]),
                "{ending:?}: {verdict:?}"
            );
        }
    }

    #[test]
    fn a_quota_returned_before_its_terminal_fails_custody() {
        for ending in ENDINGS {
            assert_eq!(
                check(&writes(ending, Some(Fault::EarlyQuota)).finish()).violated(),
                Some((
                    Obligation::Custody,
                    "a write quota returned before its command's terminal"
                )),
                "{ending:?}"
            );
        }
    }

    #[test]
    fn a_return_before_the_terminal_disagrees_with_the_owner_reports() {
        for ending in ENDINGS {
            for fault in [Fault::EarlyBuffer, Fault::EarlyExtent, Fault::FreedAtCancel] {
                assert_eq!(
                    check(&writes(ending, Some(fault)).finish()).violated(),
                    Some((
                        Obligation::Resources,
                        "a production report disagreed with the independent count"
                    )),
                    "{ending:?} {fault:?}"
                );
            }
        }
        assert_eq!(
            check(&writes(Ending::Complete, Some(Fault::LeakedQuota)).finish()).violated(),
            Some((
                Obligation::Resources,
                "a released checkpoint kept capacity its obligations no longer justify"
            ))
        );
    }

    #[test]
    fn a_quota_returns_after_its_own_terminal_while_a_reused_command_slot_is_held() {
        let mut r = Recorder::new(1);
        let old = (ResourceKind::Command, 0, 0x100);
        let quota = (ResourceKind::WriteQuota, 0, 0x100);
        let reused = (ResourceKind::Command, 0, 0x101);
        r.take(old, Custodian::Storage, None);
        r.take(quota, Custodian::Storage, Some((0, UNITS)));
        r.terminal(old, Outcome::Complete);
        r.take(reused, Custodian::Storage, None);
        r.release(quota, Custodian::Storage);
        r.terminal(reused, Outcome::Complete);
        r.checkpoint(Checkpoint::Released);
        let verdict = check(&r.finish());
        assert!(
            verdict.satisfies(&[Obligation::Custody, Obligation::Resources]),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_write_quota_is_taken_under_its_held_command() {
        let quota = (ResourceKind::WriteQuota, 0, 0x100);
        let unbound = |command: Option<(ResourceKind, u32, u64)>| {
            let mut r = Recorder::new(1);
            if let Some(command) = command {
                r.take(command, Custodian::Storage, None);
            }
            r.take(quota, Custodian::Storage, Some((0, UNITS)));
            r.finish()
        };
        for command in [
            None,
            Some((ResourceKind::Command, 0, 0x101)),
            Some((ResourceKind::Command, 1, 0x100)),
        ] {
            assert_eq!(
                check(&unbound(command)).violated(),
                Some((
                    Obligation::Custody,
                    "a write quota was taken without its command"
                )),
                "{command:?}"
            );
        }
    }

    #[test]
    fn a_command_returns_only_through_its_terminal() {
        let [command, quota, _] = write(0);
        let mut r = Recorder::new(1);
        r.take(command, Custodian::Storage, None);
        r.take(quota, Custodian::Storage, Some((0, UNITS)));
        let returned = r.release(command, Custodian::Storage);
        r.release(quota, Custodian::Storage);
        r.checkpoint(Checkpoint::Released);
        assert_eq!(
            check(&r.finish()),
            Verdict::Inconclusive(Inconclusive::Malformed {
                op: returned,
                field: Field::Resource,
            })
        );
    }

    #[test]
    fn a_failed_upload_with_held_writes_keeps_its_incumbent_and_never_publishes() {
        let attempt = |published: bool, lookup: (Outcome, Option<super::Label>)| {
            let mut s = Script::new();
            s.publish(K, super::A, super::BODY);
            let op = s.upload(K, B, super::BODY, published);
            if published {
                s.owner_publish(op, K, B);
            }
            s.put_result(op, K, B, FAILED);
            s.lookup(K, lookup.0, lookup.1);
            s.finish()
        };
        for ending in [Ending::Cancelled, Ending::Short, Ending::Closed] {
            let kept = combined(attempt(false, (HIT, Some(super::A))), writes(ending, None));
            let verdict = check(&kept);
            assert!(
                verdict.satisfies(&[
                    Obligation::History,
                    Obligation::Custody,
                    Obligation::Resources
                ]),
                "{ending:?}: {verdict:?}"
            );
            let missing = combined(attempt(false, (MISSING, None)), writes(ending, None));
            let verdict = check(&missing);
            assert!(
                verdict.satisfies(&[Obligation::History]),
                "{ending:?}: {verdict:?}"
            );
            let published = combined(attempt(true, (HIT, Some(B))), writes(ending, None));
            assert_eq!(
                check(&published).violated(),
                Some((
                    Obligation::History,
                    "an attempt that did not publish published"
                )),
                "{ending:?}"
            );
        }
    }
}

pub(super) mod remote_put_sources {
    use super::{
        A, ActionKind, B, Checkpoint, Custodian, FAILED, Field, HIT, History, Inconclusive, J, K,
        MISSING, NoInformation, Obligation, OpId, Outcome, PutOutcome, Recorder, SCRIPT_META,
        Script, Verdict, bytes, check,
    };

    const BODY: u64 = 60;
    const WIDE: u64 = 12_000;
    /// The upload's metadata and body bytes.
    const TOTAL: u64 = SCRIPT_META as u64 + WIDE;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(in crate::oracle) enum Order {
        ReceiptFirst,
        NicFirst,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(in crate::oracle) enum Fault {
        MaskOnly,
        ReuseUnderNic,
        /// The owner validates fragment 0 twice and never fragment 1, yet
        /// the receipt claims both.
        DuplicateCredit,
        OvercountedReceipt,
        /// The receipt claims fragment 1 before the owner validates it.
        EarlyCredit,
        /// A retention release names a fragment its slot never held.
        MislabelledRelease,
        /// The cancel names another slot than the one whose retention ends.
        ForeignCancel,
        /// The receipt's mask names fragment 1 before the owner validates
        /// it.
        InventedMaskBit,
    }

    /// An upload of two fragments, each in its own source slot held by
    /// retransmission retention and the NIC; the owner validates both, the
    /// client receives the full receipt, and each slot's NIC return comes
    /// before or after that receipt by `order`, then the attempt publishes
    /// and a GET hits.
    pub(in crate::oracle) fn sources(order: Order, fault: Option<Fault>) -> History {
        let mut s = Script::new();
        let op = s.put_begin(K, A, WIDE, false);
        s.owner_fill(op, K, A, WIDE);
        s.authority(op, K);
        s.ready(op, K, A, WIDE);
        for fragment in 0..2 {
            s.source(
                op,
                ActionKind::Take,
                Custodian::Retransmission,
                (fragment, 1),
                fragment,
            );
            s.source(
                op,
                ActionKind::Take,
                Custodian::Nic,
                (fragment, 1),
                fragment,
            );
            if fault == Some(Fault::EarlyCredit) && fragment == 1 {
                s.receipt(op, K, 2, 0);
            }
            if fault == Some(Fault::InventedMaskBit) && fragment == 1 {
                s.receipt(op, K, 0, 0b1);
            }
            let validated = if fault == Some(Fault::DuplicateCredit) {
                0
            } else {
                fragment
            };
            if !(fault == Some(Fault::OvercountedReceipt) && fragment == 1) {
                s.owner_fragment(op, K, validated, TOTAL);
            }
        }
        match fault {
            Some(Fault::MislabelledRelease) => {
                s.receipt(op, K, 1, 0);
                s.source(
                    op,
                    ActionKind::Release,
                    Custodian::Retransmission,
                    (1, 1),
                    0,
                );
            }
            Some(Fault::ForeignCancel) => {
                s.cancel_source(op, (0, 1));
                s.source(
                    op,
                    ActionKind::Release,
                    Custodian::Retransmission,
                    (1, 1),
                    1,
                );
            }
            _ => {}
        }
        if fault == Some(Fault::MaskOnly) {
            s.receipt(op, K, 0, 0b1);
            s.source(
                op,
                ActionKind::Release,
                Custodian::Retransmission,
                (1, 1),
                1,
            );
        }
        let nic = |s: &mut Script| {
            for fragment in 0..2 {
                s.source(
                    op,
                    ActionKind::Release,
                    Custodian::Nic,
                    (fragment, 1),
                    fragment,
                );
            }
        };
        if order == Order::NicFirst {
            nic(&mut s);
        }
        s.receipt(op, K, 2, 0);
        let released_early = matches!(
            fault,
            Some(Fault::MaskOnly | Fault::MislabelledRelease | Fault::ForeignCancel)
        );
        for fragment in 0..2 {
            if !(released_early && fragment == 1) {
                s.source(
                    op,
                    ActionKind::Release,
                    Custodian::Retransmission,
                    (fragment, 1),
                    fragment,
                );
            }
        }
        if fault == Some(Fault::ReuseUnderNic) {
            let other = s.put_begin(J, B, WIDE, true);
            s.owner_fill(other, J, B, WIDE);
            s.authority(other, J);
            s.ready(other, J, B, WIDE);
            s.source(
                other,
                ActionKind::Take,
                Custodian::Retransmission,
                (0, 2),
                0,
            );
        }
        if order == Order::ReceiptFirst {
            nic(&mut s);
        }
        s.owner_publish(op, K, A);
        s.put_result(op, K, A, PutOutcome::Published);
        s.lookup(K, HIT, Some(A));
        s.finish()
    }

    #[test]
    fn source_slots_return_after_receipt_and_nic_return_in_either_order() {
        for order in [Order::ReceiptFirst, Order::NicFirst] {
            let verdict = check(&sources(order, None));
            assert!(
                verdict.satisfies(&[
                    Obligation::Custody,
                    Obligation::Resources,
                    Obligation::History
                ]),
                "{order:?}: {verdict:?}"
            );
        }
    }

    #[test]
    fn each_source_and_receipt_fault_fails_by_name() {
        let cases = [
            (
                Fault::MaskOnly,
                Obligation::Custody,
                "retransmission retention ended before the receipt base passed its fragment",
            ),
            (
                Fault::ReuseUnderNic,
                Obligation::Custody,
                "a resource was reused while a custodian held an earlier incarnation",
            ),
            (
                Fault::DuplicateCredit,
                Obligation::History,
                "an attempt validated one fragment twice",
            ),
            (
                Fault::OvercountedReceipt,
                Obligation::Resources,
                "a receipt base counted fragments never received",
            ),
            (
                Fault::EarlyCredit,
                Obligation::Resources,
                "a receipt base counted fragments never received",
            ),
            (
                Fault::MislabelledRelease,
                Obligation::Custody,
                "a retention release named another fragment than its take",
            ),
            (
                Fault::ForeignCancel,
                Obligation::Custody,
                "retransmission retention ended before the receipt base passed its fragment",
            ),
            (
                Fault::InventedMaskBit,
                Obligation::Resources,
                "a receipt mask named a fragment never received",
            ),
        ];
        for (fault, obligation, rule) in cases {
            for order in [Order::ReceiptFirst, Order::NicFirst] {
                if fault == Fault::ReuseUnderNic && order == Order::NicFirst {
                    // Every NIC reference returned before the reuse, so the
                    // reuse is lawful.
                    let verdict = check(&sources(order, Some(fault)));
                    assert!(verdict.satisfies(&[Obligation::Custody]), "{verdict:?}");
                    continue;
                }
                assert_eq!(
                    check(&sources(order, Some(fault))).violated(),
                    Some((obligation, rule)),
                    "{fault:?} {order:?}"
                );
            }
        }
    }

    /// An attempt admitted, authorized and READY, with no receipt yet; its
    /// begin is `pending` when the history ends before its result.
    fn admitted(s: &mut Script, pending: bool) -> crate::oracle::OpId {
        let op = s.put_begin(K, A, WIDE, pending);
        s.owner_fill(op, K, A, WIDE);
        s.authority(op, K);
        s.ready(op, K, A, WIDE);
        op
    }

    /// Each event that ends a slot's retention: a receipt base past its
    /// fragment, the tenure's cancel, a decision and an `Unknown` result,
    /// which ends the client's upload as a decision does. The event ends
    /// retention only between the tenure's take and its release: before the
    /// take, it ends custody that did not yet exist, and after the release,
    /// the release came first.
    #[test]
    fn a_receipt_cancel_decision_or_unknown_result_ends_retention_it_follows() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum End {
            Receipt,
            Cancel,
            Decision,
            Unknown,
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum At {
            BeforeTake,
            BeforeRelease,
            AfterRelease,
        }
        let history = |end: End, at: At| {
            let mut s = Script::new();
            let op = admitted(&mut s, matches!(end, End::Receipt | End::Cancel));
            let ending = |s: &mut Script| match end {
                End::Receipt => {
                    s.owner_fragment(op, K, 0, TOTAL);
                    s.receipt(op, K, 1, 0);
                }
                End::Cancel => s.cancel_source(op, (0, 1)),
                End::Decision => s.put_result(op, K, A, FAILED),
                End::Unknown => s.put_result(op, K, A, PutOutcome::Unknown),
            };
            if at == At::BeforeTake {
                ending(&mut s);
            }
            s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            if at == At::BeforeRelease {
                ending(&mut s);
            }
            s.source(
                op,
                ActionKind::Release,
                Custodian::Retransmission,
                (0, 1),
                0,
            );
            if at == At::AfterRelease {
                ending(&mut s);
            }
            s.finish()
        };
        for end in [End::Receipt, End::Cancel, End::Decision, End::Unknown] {
            let verdict = check(&history(end, At::BeforeRelease));
            assert!(
                verdict.satisfies(&[Obligation::Custody]),
                "{end:?}: {verdict:?}"
            );
            for at in [At::BeforeTake, At::AfterRelease] {
                let expected = match (end, at) {
                    (End::Cancel, _) => (
                        Obligation::Custody,
                        "a source slot cancel named no retained tenure",
                    ),
                    (End::Decision | End::Unknown, At::BeforeTake) => (
                        Obligation::Custody,
                        "a source slot was taken after the attempt's result or cancel",
                    ),
                    (End::Receipt, At::BeforeTake) => (
                        Obligation::Custody,
                        "a source slot took a fragment the receipt base had passed",
                    ),
                    _ => (
                        Obligation::Custody,
                        "retransmission retention ended before the receipt base passed its fragment",
                    ),
                };
                assert_eq!(
                    check(&history(end, at)).violated(),
                    Some(expected),
                    "{end:?} {at:?}"
                );
            }
        }
    }

    /// A source slot's take and release name a fragment of the attempt's
    /// manifest; the two-fragment upload has no fragment 2.
    #[test]
    fn a_source_slot_naming_a_fragment_beyond_the_manifest_fails_history() {
        let mut s = Script::new();
        let op = admitted(&mut s, false);
        s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 2);
        s.put_result(op, K, A, FAILED);
        s.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            2,
        );
        assert_eq!(
            check(&s.finish()).violated(),
            Some((
                Obligation::History,
                "a source slot named a fragment beyond the attempt's manifest"
            ))
        );
    }

    /// A device reference to a source slot arises from sending the fragment
    /// the slot retains, so each NIC take follows the attempt's
    /// retransmission take of the same tenure and fragment and precedes its
    /// retention release.
    #[test]
    fn nic_custody_of_a_source_slot_begins_within_its_retransmission_tenure() {
        let rule = "a NIC take of a source slot followed no retransmission take of its fragment";
        let mut untaken = Script::new();
        let op = admitted(&mut untaken, true);
        untaken.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
        untaken.source(op, ActionKind::Release, Custodian::Nic, (0, 1), 0);
        assert_eq!(
            check(&untaken.finish()).violated(),
            Some((Obligation::Custody, rule))
        );
        let mut other = Script::new();
        let op = admitted(&mut other, true);
        other.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        other.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 1);
        assert_eq!(
            check(&other.finish()).violated(),
            Some((Obligation::Custody, rule))
        );
        let mut later = Script::new();
        let op = admitted(&mut later, true);
        later.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        later.owner_fragment(op, K, 0, TOTAL);
        later.receipt(op, K, 1, 0);
        later.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        later.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
        assert_eq!(
            check(&later.finish()).violated(),
            Some((
                Obligation::Custody,
                "a NIC take of a source slot followed its retention release"
            ))
        );
    }

    /// A receipt base equal to a fragment has not passed it; a cancel of a
    /// slot's earlier tenure ends nothing for its next tenure under another
    /// attempt; a slot that holds a new fragment in its next tenure releases
    /// it lawfully.
    #[test]
    fn retention_ends_only_past_its_own_fragment_and_tenure() {
        let mut equal = Script::new();
        let op = admitted(&mut equal, true);
        equal.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 1);
        equal.owner_fragment(op, K, 0, TOTAL);
        equal.receipt(op, K, 1, 0);
        equal.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            1,
        );
        let rule = "retransmission retention ended before the receipt base passed its fragment";
        assert_eq!(
            check(&equal.finish()).violated(),
            Some((Obligation::Custody, rule))
        );
        let mut stale = Script::new();
        let op = admitted(&mut stale, true);
        stale.source(op, ActionKind::Take, Custodian::Retransmission, (1, 1), 0);
        stale.cancel_source(op, (1, 1));
        stale.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (1, 1),
            0,
        );
        let next = stale.put_begin(J, B, WIDE, true);
        stale.owner_fill(next, J, B, WIDE);
        stale.authority(next, J);
        stale.ready(next, J, B, WIDE);
        stale.source(next, ActionKind::Take, Custodian::Retransmission, (1, 2), 1);
        stale.source(
            next,
            ActionKind::Release,
            Custodian::Retransmission,
            (1, 2),
            1,
        );
        assert_eq!(
            check(&stale.finish()).violated(),
            Some((Obligation::Custody, rule))
        );
        let mut reused = Script::new();
        let op = admitted(&mut reused, true);
        reused.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        reused.owner_fragment(op, K, 0, TOTAL);
        reused.receipt(op, K, 1, 0);
        reused.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        reused.source(op, ActionKind::Take, Custodian::Retransmission, (0, 2), 1);
        reused.owner_fragment(op, K, 1, TOTAL);
        reused.receipt(op, K, 2, 0);
        reused.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 2),
            1,
        );
        let verdict = check(&reused.finish());
        assert!(verdict.satisfies(&[Obligation::Custody]), "{verdict:?}");
    }

    fn without_information(history: &History, kind: ActionKind, outcome: Outcome) -> History {
        let mut rows = history.rows().to_vec();
        let at = rows
            .iter()
            .position(|r| r.kind == kind && r.source_slot())
            .expect("a source-slot row of the kind");
        rows[at].outcome = Some(outcome);
        Recorder::rebuilt(rows)
    }

    /// A source-slot take, release or cancel with a `NoInformation` outcome
    /// keeps custody and retention as they were: the take still holds after
    /// a refused release, the tenure's fragment is its effective take's, and
    /// a `NoInformation` cancel preserves retransmission retention.
    #[test]
    fn source_rows_without_information_leave_retention_unchanged() {
        let refusals = NoInformation::ALL
            .into_iter()
            .filter(|member| *member != NoInformation::ClockUnavailable);
        for member in refusals {
            let refused = Outcome::NoInformation(member);
            let mut release = Script::new();
            let op = admitted(&mut release, true);
            release.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            release.source(
                op,
                ActionKind::Release,
                Custodian::Retransmission,
                (0, 1),
                0,
            );
            let release = without_information(&release.finish(), ActionKind::Release, refused);
            let verdict = check(&release);
            assert!(
                verdict.satisfies(&[Obligation::Custody]),
                "{member:?}: {verdict:?}"
            );
            let mut take = Script::new();
            let op = admitted(&mut take, true);
            take.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 1);
            take.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            take.owner_fragment(op, K, 0, TOTAL);
            take.receipt(op, K, 1, 0);
            take.source(
                op,
                ActionKind::Release,
                Custodian::Retransmission,
                (0, 1),
                0,
            );
            let take = without_information(&take.finish(), ActionKind::Take, refused);
            let verdict = check(&take);
            assert!(
                verdict.satisfies(&[Obligation::Custody]),
                "{member:?}: {verdict:?}"
            );
            let mut cancel = Script::new();
            let op = admitted(&mut cancel, true);
            cancel.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            cancel.cancel_source(op, (0, 1));
            cancel.source(
                op,
                ActionKind::Release,
                Custodian::Retransmission,
                (0, 1),
                0,
            );
            let cancel = without_information(&cancel.finish(), ActionKind::Cancel, refused);
            assert_eq!(
                check(&cancel).violated(),
                Some((
                    Obligation::Custody,
                    "retransmission retention ended before the receipt base passed its fragment"
                )),
                "{member:?}"
            );
        }
    }

    /// A conclusive verdict for source-slot rows requires a `PutBegin` for
    /// their operation. A retention release under another attempt, or before
    /// its own attempt's take, fails custody even when a receipt passed the
    /// fragment, and so does a NIC release under another attempt.
    #[test]
    fn a_source_tenure_is_judged_with_the_attempt_that_took_it() {
        let mut orphan = Script::new();
        let stray = OpId(99);
        orphan.source(
            stray,
            ActionKind::Take,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        orphan.source(
            stray,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        assert_eq!(
            check(&orphan.finish()),
            Verdict::Inconclusive(Inconclusive::Malformed {
                op: stray,
                field: Field::Invocation,
            })
        );
        let mut foreign = Script::new();
        let taker = admitted(&mut foreign, true);
        foreign.source(
            taker,
            ActionKind::Take,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        let other = foreign.put_begin(J, B, WIDE, true);
        foreign.owner_fill(other, J, B, WIDE);
        foreign.authority(other, J);
        foreign.ready(other, J, B, WIDE);
        foreign.owner_fragment(other, J, 0, TOTAL);
        foreign.receipt(other, J, 1, 0);
        foreign.source(
            other,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        assert_eq!(
            check(&foreign.finish()).violated(),
            Some((
                Obligation::Custody,
                "a retention release ended a tenure its attempt never took"
            ))
        );
        let mut early = Script::new();
        let op = admitted(&mut early, true);
        early.owner_fragment(op, K, 0, TOTAL);
        early.receipt(op, K, 1, 0);
        early.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        early.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 1);
        assert_eq!(
            check(&early.finish()).violated(),
            Some((
                Obligation::Custody,
                "a retention release ended a tenure its attempt never took"
            ))
        );
        let mut device = Script::new();
        let taker = admitted(&mut device, true);
        device.source(
            taker,
            ActionKind::Take,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        device.source(taker, ActionKind::Take, Custodian::Nic, (0, 1), 0);
        let other = device.put_begin(J, B, WIDE, true);
        device.owner_fill(other, J, B, WIDE);
        device.authority(other, J);
        device.ready(other, J, B, WIDE);
        device.source(other, ActionKind::Release, Custodian::Nic, (0, 1), 0);
        assert_eq!(
            check(&device.finish()).violated(),
            Some((
                Obligation::Custody,
                "a NIC release returned a tenure its attempt never took"
            ))
        );
    }

    /// A source slot holds one fragment per tenure, so an attempt takes each
    /// tenure once; its retention begins before the attempt's known result.
    #[test]
    fn a_tenure_is_taken_once_and_before_the_attempt_s_result() {
        let mut twice = Script::new();
        let op = admitted(&mut twice, true);
        twice.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        twice.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 1);
        assert_eq!(
            check(&twice.finish()).violated(),
            Some((Obligation::Custody, "a source slot tenure was taken twice"))
        );
        let mut late = Script::new();
        let op = admitted(&mut late, false);
        late.put_result(op, K, A, FAILED);
        late.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        let after_result = (
            Obligation::Custody,
            "a source slot was taken after the attempt's result or cancel",
        );
        assert_eq!(check(&late.finish()).violated(), Some(after_result));
        let mut sent = Script::new();
        let op = admitted(&mut sent, false);
        sent.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        sent.put_result(op, K, A, FAILED);
        sent.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
        assert_eq!(check(&sent.finish()).violated(), Some(after_result));
        let mut unknown = Script::new();
        let op = admitted(&mut unknown, false);
        unknown.put_result(op, K, A, PutOutcome::Unknown);
        unknown.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        unknown.put_result(op, K, A, FAILED);
        unknown.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        assert_eq!(check(&unknown.finish()).violated(), Some(after_result));
        let mut cancelled = Script::new();
        let op = admitted(&mut cancelled, true);
        cancelled.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        cancelled.cancel_source(op, (0, 1));
        cancelled.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        cancelled.source(op, ActionKind::Take, Custodian::Retransmission, (1, 1), 1);
        assert_eq!(check(&cancelled.finish()).violated(), Some(after_result));
        let mut spread = Script::new();
        let op = admitted(&mut spread, true);
        spread.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        spread.source(op, ActionKind::Take, Custodian::Retransmission, (1, 1), 0);
        assert_eq!(
            check(&spread.finish()).violated(),
            Some((
                Obligation::Custody,
                "an attempt took one fragment into two source slots"
            ))
        );
        let mut shared = Script::new();
        let taker = admitted(&mut shared, true);
        shared.source(
            taker,
            ActionKind::Take,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        let other = shared.put_begin(J, B, WIDE, true);
        shared.owner_fill(other, J, B, WIDE);
        shared.authority(other, J);
        shared.ready(other, J, B, WIDE);
        shared.source(
            other,
            ActionKind::Take,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        assert_eq!(
            check(&shared.finish()).violated(),
            Some((
                Obligation::Custody,
                "an exclusive custodian took a resource it already held"
            ))
        );
    }

    /// NIC custody begins while the tenure is retained and may outlast the
    /// retention release.
    #[test]
    fn a_nic_take_begins_before_its_tenure_s_retention_release() {
        let history = |resend_after_release: bool| {
            let mut s = Script::new();
            let op = admitted(&mut s, true);
            s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            s.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
            s.owner_fragment(op, K, 0, TOTAL);
            s.receipt(op, K, 1, 0);
            s.source(
                op,
                ActionKind::Release,
                Custodian::Retransmission,
                (0, 1),
                0,
            );
            if resend_after_release {
                s.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
            }
            s.source(op, ActionKind::Release, Custodian::Nic, (0, 1), 0);
            s.finish()
        };
        let verdict = check(&history(false));
        assert!(verdict.satisfies(&[Obligation::Custody]), "{verdict:?}");
        assert_eq!(
            check(&history(true)).violated(),
            Some((
                Obligation::Custody,
                "a NIC take of a source slot followed its retention release"
            ))
        );
    }

    /// The client sends a fragment only below the grant it holds, so a NIC
    /// take names a fragment below the latest READY or ACK grant.
    #[test]
    fn a_nic_take_stays_below_the_active_grant() {
        let mut s = Script::new();
        let op = admitted(&mut s, true);
        s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 1);
        s.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 1);
        let mut rows = s.finish().rows().to_vec();
        let ready = rows
            .iter()
            .position(|r| r.kind == ActionKind::Ready)
            .expect("READY");
        rows[ready].grant = Some(1);
        assert_eq!(
            check(&Recorder::rebuilt(rows)).violated(),
            Some((
                Obligation::Custody,
                "a NIC take of a source slot exceeded the active grant"
            ))
        );
    }

    /// A cancel ends the retention of a tenure the attempt holds.
    #[test]
    fn a_cancel_names_a_retained_tenure() {
        let rule = "a source slot cancel named no retained tenure";
        let mut untaken = Script::new();
        let op = admitted(&mut untaken, true);
        untaken.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        untaken.cancel_source(op, (1, 1));
        assert_eq!(
            check(&untaken.finish()).violated(),
            Some((Obligation::Custody, rule))
        );
        let mut ended = Script::new();
        let op = admitted(&mut ended, true);
        ended.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        ended.owner_fragment(op, K, 0, TOTAL);
        ended.receipt(op, K, 1, 0);
        ended.source(
            op,
            ActionKind::Release,
            Custodian::Retransmission,
            (0, 1),
            0,
        );
        ended.cancel_source(op, (0, 1));
        assert_eq!(
            check(&ended.finish()).violated(),
            Some((Obligation::Custody, rule))
        );
    }

    #[test]
    fn a_tenure_is_released_once_per_take() {
        for custodian in [Custodian::Retransmission, Custodian::Nic] {
            let mut s = Script::new();
            let op = admitted(&mut s, true);
            s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            s.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
            s.owner_fragment(op, K, 0, TOTAL);
            s.receipt(op, K, 1, 0);
            s.source(op, ActionKind::Release, custodian, (0, 1), 0);
            s.source(op, ActionKind::Release, custodian, (0, 1), 0);
            assert_eq!(
                check(&s.finish()).violated(),
                Some((
                    Obligation::Custody,
                    "a source slot tenure was released more often than taken"
                )),
                "{custodian:?}"
            );
        }
        let mut resent = Script::new();
        let op = admitted(&mut resent, true);
        resent.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        resent.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
        resent.source(op, ActionKind::Release, Custodian::Nic, (0, 1), 0);
        resent.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
        resent.source(op, ActionKind::Release, Custodian::Nic, (0, 1), 0);
        let verdict = check(&resent.finish());
        assert!(verdict.satisfies(&[Obligation::Custody]), "{verdict:?}");
    }

    #[test]
    fn a_tenure_is_taken_after_ready_and_at_or_above_the_receipt_base() {
        let mut unready = Script::new();
        let op = unready.put_begin(K, A, WIDE, true);
        unready.owner_fill(op, K, A, WIDE);
        unready.authority(op, K);
        unready.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        unready.ready(op, K, A, WIDE);
        assert_eq!(
            check(&unready.finish()).violated(),
            Some((Obligation::History, "the attempt's phases are out of order"))
        );
        let mut stale = Script::new();
        let op = admitted(&mut stale, true);
        stale.owner_fragment(op, K, 0, TOTAL);
        stale.receipt(op, K, 1, 0);
        stale.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        assert_eq!(
            check(&stale.finish()).violated(),
            Some((
                Obligation::Custody,
                "a source slot took a fragment the receipt base had passed"
            ))
        );
        let mut current = Script::new();
        let op = admitted(&mut current, true);
        current.owner_fragment(op, K, 0, TOTAL);
        current.receipt(op, K, 1, 0);
        current.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 1);
        let verdict = check(&current.finish());
        assert!(verdict.satisfies(&[Obligation::Custody]), "{verdict:?}");
    }

    /// The client holds a cumulative receipt: from READY on, each ACK's base
    /// and grant are at least the previous ones.
    #[test]
    fn a_receipt_base_and_grant_never_regress() {
        let rule = "the attempt's receipt base or grant regressed";
        let mut base = Script::new();
        let op = admitted(&mut base, true);
        base.owner_fragment(op, K, 0, TOTAL);
        base.owner_fragment(op, K, 1, TOTAL);
        base.receipt(op, K, 2, 0);
        base.receipt(op, K, 1, 0);
        assert_eq!(
            check(&base.finish()).violated(),
            Some((Obligation::Resources, rule))
        );
        let mut grant = Script::new();
        let op = admitted(&mut grant, true);
        grant.owner_fragment(op, K, 0, TOTAL);
        grant.receipt(op, K, 1, 0);
        grant.receipt(op, K, 1, 0);
        let mut rows = grant.finish().rows().to_vec();
        let last = rows
            .iter()
            .rposition(|r| r.kind == ActionKind::Ack)
            .expect("an ACK");
        rows[last].grant = Some(1);
        assert_eq!(
            check(&Recorder::rebuilt(rows)).violated(),
            Some((Obligation::Resources, rule))
        );
        let mut steady = Script::new();
        let op = admitted(&mut steady, true);
        steady.owner_fragment(op, K, 0, TOTAL);
        steady.receipt(op, K, 1, 0);
        steady.receipt(op, K, 1, 0);
        steady.owner_fragment(op, K, 1, TOTAL);
        steady.receipt(op, K, 2, 0);
        let verdict = check(&steady.finish());
        assert!(verdict.satisfies(&[Obligation::Resources]), "{verdict:?}");
    }

    /// The admitted history's Fragment rows are the attempt's complete
    /// fragment evidence: a receipt base or mask with no validated fragment
    /// behind it is an impossible ACK even when the history records no
    /// fragment at all, a duplicated index fails the history before any
    /// receipt counts it, and the complete evidence keeps its receipt
    /// lawful.
    #[test]
    fn a_receipt_counts_only_the_fragments_the_history_validated() {
        let receipted = |validated: &[u32], base: u32, mask: u64| {
            let mut s = Script::new();
            let op = s.put_begin(K, A, WIDE, true);
            s.owner_fill(op, K, A, WIDE);
            s.authority(op, K);
            s.ready(op, K, A, WIDE);
            for &fragment in validated {
                s.owner_fragment(op, K, fragment, TOTAL);
            }
            s.receipt(op, K, base, mask);
            check(&s.finish())
        };
        let base = "a receipt base counted fragments never received";
        let mask = "a receipt mask named a fragment never received";
        for (validated, receipt, rule) in [
            (&[][..], (1, 0), base),
            (&[][..], (2, 0), base),
            (&[][..], (0, 0b1), mask),
            (&[0][..], (2, 0), base),
            (&[0][..], (0, 0b1), mask),
            (&[1][..], (1, 0), base),
        ] {
            assert_eq!(
                receipted(validated, receipt.0, receipt.1).violated(),
                Some((Obligation::Resources, rule)),
                "{validated:?} under {receipt:?}"
            );
        }
        assert_eq!(
            receipted(&[0, 0], 2, 0).violated(),
            Some((
                Obligation::History,
                "an attempt validated one fragment twice"
            )),
            "a duplicated index fails before the receipt rule counts it"
        );
        for (validated, receipt) in [
            (&[0, 1][..], (2, 0)),
            (&[1, 0][..], (2, 0)),
            (&[0][..], (1, 0)),
            (&[1][..], (0, 0b1)),
            (&[][..], (0, 0)),
        ] {
            let verdict = receipted(validated, receipt.0, receipt.1);
            assert!(
                verdict.satisfies(&[Obligation::Resources]),
                "{validated:?} under {receipt:?}: {verdict:?}"
            );
        }
    }

    /// A recorder may push rows in any order, so only ordinals say which
    /// came first.
    #[test]
    fn a_receipt_orders_validations_by_ordinal_not_by_row_position() {
        let mut s = Script::new();
        let op = admitted(&mut s, true);
        s.owner_fragment(op, K, 1, TOTAL);
        s.owner_fragment(op, K, 0, TOTAL);
        s.receipt(op, K, 2, 0);
        let rows = s.finish().rows().to_vec();
        let of = |kind| move |r: &super::Row| r.kind == kind;
        let ack = rows.iter().position(of(ActionKind::Ack)).expect("an ACK");
        let first = rows
            .iter()
            .position(of(ActionKind::Fragment))
            .expect("a fragment");
        let last = rows
            .iter()
            .rposition(of(ActionKind::Fragment))
            .expect("a fragment");
        let mut moved = rows.clone();
        let acknowledged = moved.remove(ack);
        moved.insert(first, acknowledged);
        let verdict = check(&Recorder::rebuilt(moved));
        assert!(verdict.satisfies(&[Obligation::Resources]), "{verdict:?}");
        let mut late = rows;
        let (validated, received) = (late[last].responded, late[ack].responded);
        late[last].responded = received;
        late[ack].responded = validated;
        assert_eq!(
            check(&Recorder::rebuilt(late)).violated(),
            Some((
                Obligation::Resources,
                "a receipt base counted fragments never received"
            ))
        );
    }

    #[test]
    fn the_first_failing_receipt_row_names_its_rule() {
        let mut s = Script::new();
        let op = admitted(&mut s, true);
        s.owner_fragment(op, K, 0, TOTAL);
        s.receipt(op, K, 0, 0b1);
        s.receipt(op, K, 2, 0);
        let rows = s.finish().rows().to_vec();
        assert_eq!(
            check(&Recorder::rebuilt(rows.clone())).violated(),
            Some((
                Obligation::Resources,
                "a receipt mask named a fragment never received"
            ))
        );
        let mut exchanged = rows;
        let last = exchanged.len() - 1;
        exchanged.swap(last - 1, last);
        assert_eq!(
            check(&Recorder::rebuilt(exchanged)).violated(),
            Some((
                Obligation::Resources,
                "a receipt base counted fragments never received"
            ))
        );
    }

    /// Bit 63 names base + 64, the receipt mask's maximum offset.
    #[test]
    fn a_receipt_mask_reaches_sixty_four_fragments_above_its_base() {
        const FRAGMENTS: u32 = 66;
        let body = u64::from(FRAGMENTS) * 8192 - u64::from(SCRIPT_META);
        let receipted = |validated: &[u32]| {
            let mut s = Script::new();
            let op = s.put_begin(K, A, body, true);
            s.owner_fill(op, K, A, body);
            s.authority(op, K);
            s.ready(op, K, A, body);
            for &fragment in validated {
                s.owner_fragment(op, K, fragment, u64::from(SCRIPT_META) + body);
            }
            s.receipt(op, K, 1, 1 << 63);
            let mut rows = s.finish().rows().to_vec();
            rows.last_mut().expect("the ACK").grant = Some(FRAGMENTS);
            check(&Recorder::rebuilt(rows))
        };
        let verdict = receipted(&[0, FRAGMENTS - 1]);
        assert!(verdict.satisfies(&[Obligation::Resources]), "{verdict:?}");
        assert_eq!(
            receipted(&[0]).violated(),
            Some((
                Obligation::Resources,
                "a receipt mask named a fragment never received"
            ))
        );
    }

    /// The owner validates a fragment only below the grant its latest READY
    /// or ACK carried; a later grant cannot authorise it after the fact.
    #[test]
    fn a_fragment_is_validated_below_the_active_grant() {
        let mut s = Script::new();
        let op = admitted(&mut s, true);
        s.owner_fragment(op, K, 0, TOTAL);
        s.owner_fragment(op, K, 1, TOTAL);
        s.receipt(op, K, 2, 0);
        let mut rows = s.finish().rows().to_vec();
        let ready = rows
            .iter()
            .position(|r| r.kind == ActionKind::Ready)
            .expect("READY");
        rows[ready].grant = Some(1);
        assert_eq!(
            check(&Recorder::rebuilt(rows)).violated(),
            Some((
                Obligation::History,
                "a fragment was validated beyond the active grant"
            ))
        );
    }

    /// A decision ends retransmission retention without a receipt, while
    /// the NIC keeps the slot until it returns; another attempt's retake of
    /// the slot before that return fails custody.
    #[test]
    fn a_decision_ends_retention_without_a_receipt_but_not_nic_custody() {
        let decided = |reuse_before_nic: bool| {
            let mut s = Script::new();
            let op = admitted(&mut s, false);
            s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            s.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
            s.put_result(op, K, A, FAILED);
            s.source(
                op,
                ActionKind::Release,
                Custodian::Retransmission,
                (0, 1),
                0,
            );
            if reuse_before_nic {
                let other = s.put_begin(J, B, WIDE, true);
                s.owner_fill(other, J, B, WIDE);
                s.authority(other, J);
                s.ready(other, J, B, WIDE);
                s.source(
                    other,
                    ActionKind::Take,
                    Custodian::Retransmission,
                    (0, 2),
                    0,
                );
            }
            s.source(op, ActionKind::Release, Custodian::Nic, (0, 1), 0);
            s.lookup(K, MISSING, None);
            s.finish()
        };
        let verdict = check(&decided(false));
        assert!(
            verdict.satisfies(&[Obligation::Custody, Obligation::History]),
            "{verdict:?}"
        );
        assert_eq!(
            check(&decided(true)).violated(),
            Some((
                Obligation::Custody,
                "a resource was reused while a custodian held an earlier incarnation"
            ))
        );
    }

    /// An owner's stop without proof retains the owner's capacity, and a
    /// released checkpoint requires that capacity returned; a client's source
    /// slot is the client's buffer, so the client frees it after either
    /// checkpoint once its retention ends.
    #[test]
    fn an_owner_checkpoint_leaves_client_source_slots_to_the_client() {
        for checkpoint in [Checkpoint::Unproven, Checkpoint::Released] {
            let mut s = Script::new();
            let op = admitted(&mut s, false);
            s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            s.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
            s.checkpoint(checkpoint);
            s.put_result(op, K, A, PutOutcome::Unknown);
            s.source(
                op,
                ActionKind::Release,
                Custodian::Retransmission,
                (0, 1),
                0,
            );
            s.source(op, ActionKind::Release, Custodian::Nic, (0, 1), 0);
            let verdict = check(&s.finish());
            assert!(
                verdict.satisfies(&[Obligation::Custody, Obligation::Resources]),
                "{checkpoint:?}: {verdict:?}"
            );
        }
    }

    /// A healthy owner's interval with an upload's source slot held by
    /// retention and the NIC still serves an exact GET; the client's buffer
    /// holds no cache capacity.
    #[test]
    fn a_healthy_interval_serves_under_held_source_custody() {
        let mut s = Script::new();
        let op = s.put_begin(K, B, WIDE, true);
        s.authority(op, K);
        s.ready(op, K, B, WIDE);
        s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
        s.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
        s.checkpoint(Checkpoint::Healthy {
            turns: 3,
            bound: 200,
        });
        s.publish(J, A, BODY);
        let get = s.lookup(J, HIT, Some(A));
        s.deliver(get, J, A, BODY, Outcome::Complete, bytes(J, A, BODY));
        s.checkpoint(Checkpoint::Stopped);
        let verdict = check(&s.finish());
        assert!(verdict.satisfies(&[Obligation::Isolation]), "{verdict:?}");
    }

    /// A funded qualified interval with an upload in flight, its source slot
    /// held by retention and the NIC, still serves an eligible GET exactly;
    /// an interval whose GET is never served fails progress.
    #[test]
    fn an_eligible_get_progresses_under_upload_pressure_and_suppressing_it_fails() {
        let interval = |served: bool| {
            let mut s = Script::new();
            let op = s.put_begin(K, B, WIDE, true);
            s.authority(op, K);
            s.ready(op, K, B, WIDE);
            s.source(op, ActionKind::Take, Custodian::Retransmission, (0, 1), 0);
            s.source(op, ActionKind::Take, Custodian::Nic, (0, 1), 0);
            s.checkpoint(Checkpoint::Qualified {
                funded: 4,
                limit: 266,
            });
            s.publish(J, A, BODY);
            if served {
                let get = s.lookup(J, HIT, Some(A));
                let bytes = bytes(J, A, BODY);
                s.deliver(get, J, A, BODY, Outcome::Complete, bytes);
            }
            s.checkpoint(Checkpoint::Stopped);
            s.finish()
        };
        let verdict = check(&interval(true));
        assert!(verdict.satisfies(&[Obligation::Progress]), "{verdict:?}");
        let suppressed = check(&interval(false));
        assert_eq!(
            suppressed.violated(),
            Some((
                Obligation::Progress,
                "a qualified funded interval produced no exact hit"
            ))
        );
    }
}
