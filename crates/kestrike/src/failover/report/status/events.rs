//! The step results a zone loop feeds its status: refused host reports, census reservations, standby enrollments,
//! loss decisions, reconciler step errors, provider creates, attach steps and attachment reclamation, each counted
//! once in [`Events`] under the label its exhaustive conversion gives it (CLOSED-LABELS), and the store client's
//! alarm and outcomes.

use super::part::{
    ATTACHES, AttachOutcome, CREATES, Create, DECISIONS, Decided, ENROLLMENTS, Enrollment, Events,
    RECLAIMS, REFUSED, RESERVATIONS, Reclaim, Refused, Reservation, STEP_ERRORS, StepError,
    StoreAlarm, StoreState,
};
use crate::failover::loss::{CreateError, Decision};
use crate::failover::reconcile::{ReconcileError, StandbyRefusal};
use crate::failover::report::ReportError;
use crate::failover::standbys::Refusal as PopulationRefusal;
use crate::storage::store::{Alarm, Tallied, Tally};

/// The position of `value` in `table`, which lists every value of its type.
pub(crate) fn at<T: PartialEq>(table: &[T], value: T) -> usize {
    table
        .iter()
        .position(|listed| *listed == value)
        .expect("a label table lists every value of its type")
}

impl From<&StandbyRefusal> for Enrollment {
    fn from(refusal: &StandbyRefusal) -> Self {
        match refusal {
            StandbyRefusal::Records(_) => Self::Records,
            StandbyRefusal::Tenure => Self::Tenure,
            StandbyRefusal::Persist(_) => Self::Persist,
            StandbyRefusal::Binding => Self::Binding,
            StandbyRefusal::Enrollment(_) => Self::Enrollment,
            StandbyRefusal::Write(_) => Self::Write,
        }
    }
}

impl From<ReconcileError> for StepError {
    fn from(error: ReconcileError) -> Self {
        match error {
            ReconcileError::Store(_) => Self::Store,
            ReconcileError::Conflict => Self::Conflict,
            ReconcileError::Stale => Self::Stale,
            ReconcileError::Retry => Self::Retry,
            ReconcileError::Named => Self::Named,
            ReconcileError::Unclean => Self::Unclean,
            ReconcileError::Layout(_) => Self::Layout,
            ReconcileError::Population(_) => Self::Population,
            ReconcileError::Held => Self::Held,
            ReconcileError::Exhausted => Self::Exhausted,
            ReconcileError::Create(_) => Self::Create,
        }
    }
}

impl From<Alarm> for StoreAlarm {
    fn from(alarm: Alarm) -> Self {
        match alarm {
            Alarm::Clear => Self::Clear,
            Alarm::Regression => Self::Regression,
            Alarm::Checkpoint => Self::Checkpoint,
            Alarm::Log => Self::Log,
            Alarm::Namespace => Self::Namespace,
        }
    }
}

impl StoreState {
    pub fn of(alarm: Alarm, tally: &Tally) -> Self {
        let total = |outcome| saturated(tally.total(outcome));
        Self {
            alarm: alarm.into(),
            outcomes: [
                total(Tallied::Unknown),
                total(Tallied::Unavailable),
                total(Tallied::Refused),
                total(Tallied::Log),
            ],
        }
    }
}

fn saturated(count: u64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

pub(super) fn count_one(count: &mut u32) {
    *count = count.saturating_add(1);
}

impl Events {
    /// A host report the loop refused with `error`; a duplicate counts nothing.
    pub fn refused(&mut self, error: ReportError) {
        let kind = match error {
            ReportError::Length => Refused::Length,
            ReportError::Magic => Refused::Magic,
            ReportError::Schema { .. } => Refused::Schema,
            ReportError::Writer => Refused::Writer,
            ReportError::Tag => Refused::Tag,
            ReportError::Flag => Refused::Flag,
            ReportError::Field => Refused::Field,
            ReportError::Duplicate => return,
        };
        count_one(&mut self.refused[at(REFUSED, kind)]);
    }

    /// A host report the loop accepted from a writer outside its zone.
    pub fn foreign(&mut self) {
        count_one(&mut self.refused[at(REFUSED, Refused::Foreign)]);
    }

    /// A census reservation's result.
    pub fn reserved(&mut self, result: Result<(), PopulationRefusal>) {
        let label = match result {
            Ok(()) => Reservation::Reserved,
            Err(PopulationRefusal::Headroom) => Reservation::Headroom,
            Err(PopulationRefusal::Full) => Reservation::Full,
            Err(PopulationRefusal::Taken) => Reservation::Taken,
            Err(PopulationRefusal::Ineligible) => Reservation::Ineligible,
            Err(PopulationRefusal::Closed) => Reservation::Closed,
        };
        count_one(&mut self.reservations[at(RESERVATIONS, label)]);
    }

    /// A standby enrollment's refusal.
    pub fn enrollment_refused(&mut self, refusal: &StandbyRefusal) {
        count_one(&mut self.enrollments[at(ENROLLMENTS, refusal.into())]);
    }

    /// A loss decision; `Retain` counts nothing.
    pub fn decided(&mut self, decision: Decision) {
        let label = match decision {
            Decision::Retain => return,
            Decision::Provision(_) => Decided::Provision,
            Decision::Hold(Some(_)) => Decided::Hold,
            Decision::Hold(None) => Decided::Exhausted,
        };
        count_one(&mut self.decisions[at(DECISIONS, label)]);
    }

    /// A reconciler step's error.
    pub fn failed(&mut self, error: ReconcileError) {
        count_one(&mut self.errors[at(STEP_ERRORS, error.into())]);
    }

    /// A provider create's result.
    pub fn created<T>(&mut self, result: &Result<T, CreateError>) {
        let label = match result {
            Ok(_) => Create::Created,
            Err(CreateError::Unknown) => Create::Unknown,
            Err(CreateError::Failed) => Create::Failed,
        };
        count_one(&mut self.creates[at(CREATES, label)]);
    }

    /// An attach step's result.
    pub fn attached(&mut self, outcome: AttachOutcome) {
        count_one(&mut self.attaches[at(ATTACHES, outcome)]);
    }

    /// An attachment reclamation step's result.
    pub fn reclaimed(&mut self, outcome: Reclaim) {
        count_one(&mut self.reclaims[at(RECLAIMS, outcome)]);
    }
}
