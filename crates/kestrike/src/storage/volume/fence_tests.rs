//! The gate constructor's verdict over hand-built Reports, one refusal per failing check in the constructor's order.

use super::super::gate_fixture::{foreign, own};
use super::{Fenced, GateRefusal};
use crate::failover::evidence::{Pair, Registrant, Report, ReservationType};

#[path = "gate_replay.rs"]
mod gate_replay;

/// A Report's reservation type, its header count when it differs from the entries, its entries, and the verdict.
type Case = (
    ReservationType,
    Option<u32>,
    Vec<Registrant>,
    Result<(), GateRefusal>,
);

fn row(holder: bool, pair: Pair) -> Registrant {
    Registrant {
        cntlid: 10,
        holder,
        pair,
    }
}

fn verdict(rtype: ReservationType, regctl: u32, entries: &[Registrant]) -> Result<(), GateRefusal> {
    let report = Report {
        submitted_at: 0,
        rtype,
        regctl,
        entries,
    };
    Fenced::sole_registrant(
        &report,
        own(),
        &super::super::ServingAuthority::fixture().bounds,
    )
    .map(drop)
}

/// The gate requires a conclusive `ExclusiveAccess` Report containing exactly one registrant: `own()` holding the reservation. Refusals take precedence in this order: `ReportUnreadable`, `ReservationType`, `DuplicateOwnRecord`, `ForeignHolder`, `ForeignRegistrant`, `NotHolder`.
#[test]
fn sole_registrant_checks_count_type_records_and_holder_in_order() {
    use GateRefusal::{
        DuplicateOwnRecord, ForeignHolder, ForeignRegistrant, NotHolder, ReportUnreadable,
        ReservationType as Type,
    };
    let exclusive = ReservationType::ExclusiveAccess;
    let rekeyed = Pair {
        key: foreign().key,
        ..own()
    };
    let cases: [Case; 12] = [
        (exclusive, None, vec![row(true, own())], Ok(())),
        (
            exclusive,
            Some(2),
            vec![row(true, own())],
            Err(ReportUnreadable),
        ),
        (
            exclusive,
            Some(9),
            vec![row(true, own())],
            Err(ReportUnreadable),
        ),
        (
            ReservationType::None,
            None,
            vec![row(true, own())],
            Err(Type),
        ),
        (
            ReservationType::None,
            Some(2),
            vec![row(true, own())],
            Err(ReportUnreadable),
        ),
        (
            ReservationType::None,
            None,
            vec![row(true, own()), row(true, foreign())],
            Err(Type),
        ),
        (
            exclusive,
            None,
            vec![row(true, own()), row(false, rekeyed)],
            Err(DuplicateOwnRecord),
        ),
        (
            exclusive,
            None,
            vec![row(false, own()), row(true, own()), row(true, foreign())],
            Err(DuplicateOwnRecord),
        ),
        (
            exclusive,
            None,
            vec![row(true, own()), row(true, foreign())],
            Err(ForeignHolder),
        ),
        (
            exclusive,
            None,
            vec![row(true, own()), row(false, foreign())],
            Err(ForeignRegistrant),
        ),
        (
            exclusive,
            None,
            vec![row(true, rekeyed)],
            Err(ForeignHolder),
        ),
        (exclusive, None, vec![row(false, own())], Err(NotHolder)),
    ];
    for (rtype, regctl, entries, expected) in cases {
        let regctl = regctl.unwrap_or(entries.len() as u32);
        assert_eq!(
            verdict(rtype, regctl, &entries),
            expected,
            "{rtype:?} {regctl} {entries:?}"
        );
    }
    assert_eq!(verdict(exclusive, 0, &[]), Err(NotHolder));
}

#[test]
fn judge_maps_a_withheld_report_s_refusal_to_the_gate_verdict() {
    use super::super::super::device::ReportError;
    use super::{GateStep, judge};
    let bounds = super::super::ServingAuthority::fixture().bounds;
    let cases: [(bool, Option<ReportError>, GateRefusal); 9] = [
        (
            true,
            Some(ReportError::ReservationType(1)),
            GateRefusal::ReservationType,
        ),
        (
            true,
            Some(ReportError::DuplicateOwnHostId { records: 2 }),
            GateRefusal::DuplicateOwnRecord,
        ),
        (
            true,
            Some(ReportError::OwnHostIdKey),
            GateRefusal::DuplicateOwnRecord,
        ),
        (
            true,
            Some(ReportError::Truncated),
            GateRefusal::ReportUnreadable,
        ),
        (
            true,
            Some(ReportError::Inconclusive { regctl: 9 }),
            GateRefusal::ReportUnreadable,
        ),
        (
            true,
            Some(ReportError::DuplicateKey),
            GateRefusal::ForeignRegistrant,
        ),
        (
            true,
            Some(ReportError::Identity(
                crate::failover::identity::IdentityError::ExhidZero,
            )),
            GateRefusal::ForeignRegistrant,
        ),
        (true, None, GateRefusal::ReportUnreadable),
        (
            false,
            Some(ReportError::DuplicateOwnHostId { records: 2 }),
            GateRefusal::CommandFailed(GateStep::Report),
        ),
    ];
    for (succeeded, refusal, expected) in cases {
        assert_eq!(
            judge(succeeded, &Err(refusal), own(), &bounds).map(drop),
            Err(expected),
            "{succeeded} {refusal:?}"
        );
    }
}
