//! At the attach gate a Report whose bytes the driver withheld with `DuplicateKey` or
//! `Identity` ends the attach `Unfenced(ForeignRegistrant)`; a Report withheld for an inconclusive or
//! truncated header ends it `Unfenced(ReportUnreadable)`. Every refusal leaves the medium untouched.
//!
//! Each test drives a whole attach over the reserving driver of `gate_fixture`, whose `report_check`
//! makes the driver withhold the gate Report's bytes with one `ReportError`, observes the result into
//! a plain value after the fixtures did their work, and judges it with one equality.

use super::super::device::{ReportError, ReservationCommand};
use super::super::recovery::MetadataOutcome;
use super::gate_fixture::{
    arena, attach_reserving, bounds_of, limits, medium, own, storage, ticks,
};
use super::{GateRefusal, GateStep};
use crate::failover::identity::{Field, IdentityError};

/// What one attach left behind once its gate ended.
#[derive(Debug, PartialEq, Eq)]
struct Gate {
    /// The attach's metadata outcome.
    outcome: MetadataOutcome,
    /// The verdict `fence::judge` gives the same withheld Report, when the test withheld one.
    judged: Option<GateRefusal>,
    /// Reservation commands the driver took: the gate's Register, Acquire and Report.
    reservation_commands: usize,
    /// Whether the third reservation command is the gate's Report.
    report_taken: bool,
    /// Medium admissions the volume granted to the driver.
    admissions: usize,
    /// Medium commands that reached the simulated device or the driver.
    medium_commands: usize,
    /// Whether the volume holds a gate value.
    fenced: bool,
    /// Whether the storage closed with the refusal.
    closed: bool,
}

/// The expected state of a gate that refused with `refusal` after its Report.
fn refused(refusal: GateRefusal) -> Gate {
    Gate {
        outcome: MetadataOutcome::Unfenced(refusal),
        judged: Some(refusal),
        reservation_commands: 3,
        report_taken: true,
        admissions: 0,
        medium_commands: 0,
        fenced: false,
        closed: true,
    }
}

/// Runs one attach over a fresh reserving driver whose Report check returns `check`, and observes it.
fn gate(check: Option<ReportError>) -> Gate {
    let arena = arena();
    let storage = storage();
    let (mut volume, control, registry) = attach_reserving(
        &storage,
        &arena,
        crate::storage::ServingAuthority::fixture(),
    );
    registry.borrow_mut().report_check = check;
    ticks(&mut volume, &control, 32);
    let judged = check.and_then(|error| {
        super::fence::judge(true, &Err(Some(error)), own(), &bounds_of(limits())).err()
    });
    let registry = registry.borrow();
    Gate {
        outcome: volume.metadata_outcome(),
        judged,
        reservation_commands: registry.log.len(),
        report_taken: matches!(registry.log.get(2), Some(ReservationCommand::Report { .. })),
        admissions: registry.admissions.len(),
        medium_commands: medium(&control) + registry.medium,
        fenced: volume.metadata.fenced.is_some(),
        closed: storage.is_closed(),
    }
}

/// A gate Report withheld because one key appears under two host IDs registers a foreign pair: the
/// attach ends `Unfenced(ForeignRegistrant)`, not `ReportUnreadable`, with no medium admission and no
/// medium command.
#[test]
fn a_withheld_duplicate_key_report_ends_the_attach_foreign_registrant() {
    assert_eq!(
        gate(Some(ReportError::DuplicateKey)),
        refused(GateRefusal::ForeignRegistrant)
    );
}

/// A gate Report withheld because an entry's key or host ID violates the identity codec registers a
/// foreign pair: each codec violation ends the attach `Unfenced(ForeignRegistrant)`.
#[test]
fn a_withheld_identity_refusal_report_ends_the_attach_foreign_registrant() {
    let observed: Vec<Gate> = [
        IdentityError::ExhidZero,
        IdentityError::Zero(Field::Epoch),
        IdentityError::Reserved(Field::Incarnation),
    ]
    .into_iter()
    .map(|error| gate(Some(ReportError::Identity(error))))
    .collect();
    let expected: Vec<Gate> = (0..3)
        .map(|_| refused(GateRefusal::ForeignRegistrant))
        .collect();
    assert_eq!(observed, expected);
}

/// Control: a gate Report withheld for a header count above the registrant bound, or for a truncated
/// header, is no observation of a foreign pair: the attach ends `Unfenced(ReportUnreadable)`, also
/// with no medium admission and no medium command.
#[test]
fn a_withheld_inconclusive_or_truncated_report_ends_the_attach_report_unreadable() {
    let regctl = limits().registrants() + 1;
    let observed: Vec<Gate> = [ReportError::Inconclusive { regctl }, ReportError::Truncated]
        .into_iter()
        .map(|error| gate(Some(error)))
        .collect();
    let expected: Vec<Gate> = (0..2)
        .map(|_| refused(GateRefusal::ReportUnreadable))
        .collect();
    assert_eq!(observed, expected);
}

/// Control without the fault: the same attach whose driver withholds nothing passes its gate, so the
/// refusals above come from the withheld Report and not from the fixture.
#[test]
fn the_same_attach_with_no_withheld_report_passes_its_gate() {
    let passed = gate(None);
    assert_eq!(
        (
            matches!(passed.outcome, MetadataOutcome::Unfenced(_)),
            passed.judged,
            passed.reservation_commands,
            passed.report_taken,
            passed.admissions,
            passed.fenced,
            passed.closed,
        ),
        (false, None, 3, true, 1, true, false)
    );
}

/// The gate's judgment of a Report whose command failed does not consult the withheld bytes' refusal:
/// it ends `CommandFailed(Report)` for the errors that otherwise end `ForeignRegistrant`.
#[test]
fn a_failed_report_command_is_judged_before_its_withheld_refusal() {
    let judged: Vec<Option<GateRefusal>> = [
        ReportError::DuplicateKey,
        ReportError::Identity(IdentityError::ExhidZero),
    ]
    .into_iter()
    .map(|error| super::fence::judge(false, &Err(Some(error)), own(), &bounds_of(limits())).err())
    .collect();
    assert_eq!(
        judged,
        vec![Some(GateRefusal::CommandFailed(GateStep::Report)); 2]
    );
}
