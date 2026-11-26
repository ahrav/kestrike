//! The producer keeps one [`RecoveryStatus`] per volume for the writer's boot, marks each recovery attempt's start
//! and end on it, and copies [`RecoveryStatus::recovery`] into the entry's recovery part.

use super::{Recovery, RecoveryCheck, RecoveryKind, RecoveryNext, RecoveryOutcome, StoreClass};
use crate::failover::{fresh, restart, takeover};
use crate::storage::page_coverage::{FenceRefused, Withdraw};
use crate::storage::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryRefusal {
    check: RecoveryCheck,
    next: RecoveryNext,
    store: Option<StoreClass>,
    /// A restart's lineage arm refused at a device command after its acknowledged bump, its Register, its preempt or
    /// its Report #2, or before its bump at a full registrant table.
    lineage: bool,
}

/// One volume's recovery attempts since the writer's boot: their count and the last attempt's kind, start time and
/// outcome, on the owner's turn clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryStatus {
    attempts: u32,
    last: Option<Attempt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Attempt {
    kind: RecoveryKind,
    started_us: u64,
    outcome: Outcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Running,
    Completed,
    Refused(RecoveryRefusal),
}

impl RecoveryStatus {
    pub const NO_ATTEMPT: Self = Self {
        attempts: 0,
        last: None,
    };

    /// A start while an attempt runs replaces that attempt, which stays counted.
    pub fn start(&mut self, kind: RecoveryKind, now_us: u64) {
        self.attempts = self.attempts.saturating_add(1);
        self.last = Some(Attempt {
            kind,
            started_us: now_us,
            outcome: Outcome::Running,
        });
    }

    /// `lineage` marks a running restart attempt as the lineage arm's, keeping its count and start: the caller calls it
    /// once the restart reached its fencing boundary through that arm ([`restart::Restarted::lineage`]), and
    /// [`RecoveryStatus::refuse`] calls it for a refusal at the arm's Register, preempt or Report #2 command, before
    /// any fencing boundary. It changes no other attempt.
    pub fn lineage(&mut self) {
        if let Some(attempt) = self.last.as_mut().filter(|attempt| {
            attempt.outcome == Outcome::Running && attempt.kind == RecoveryKind::Restart
        }) {
            attempt.kind = RecoveryKind::Lineage;
        }
    }

    /// `complete` changes the status only when an attempt is running, ending that attempt.
    pub fn complete(&mut self) {
        self.end(Outcome::Completed);
    }

    /// `refuse` ends the running attempt with `refusal`, as [`RecoveryStatus::complete`] ends it. A running restart
    /// attempt that `refusal` refuses at a device command of the lineage arm, or at the arm's full-table check, reads
    /// kind `lineage`, so the attempt's `check = recorded-holder` names the arm's own hold: the planner's device-hold guard
    /// (`failover::zone_loop`) reads it as a device hold, and a restart's plain recorded-holder hold keeps kind
    /// `restart`.
    pub fn refuse(&mut self, refusal: RecoveryRefusal) {
        if refusal.lineage {
            self.lineage();
        }
        self.end(Outcome::Refused(refusal));
    }

    /// Whether the last attempt runs.
    pub fn running(&self) -> bool {
        self.last
            .is_some_and(|attempt| attempt.outcome == Outcome::Running)
    }

    /// Whether the last attempt holds a recovery slot: it runs, or it refused with a next step of hold or restart.
    pub fn holds_slot(&self) -> bool {
        self.last.is_some_and(|attempt| match attempt.outcome {
            Outcome::Running => true,
            Outcome::Refused(refusal) => match refusal.next {
                RecoveryNext::Hold | RecoveryNext::Restart => true,
                RecoveryNext::Stop | RecoveryNext::Flip => false,
            },
            Outcome::Completed => false,
        })
    }

    fn end(&mut self, outcome: Outcome) {
        if let Some(attempt) = self
            .last
            .as_mut()
            .filter(|attempt| attempt.outcome == Outcome::Running)
        {
            attempt.outcome = outcome;
        }
    }

    /// The age is absent when `now_us` reads before the last attempt's start.
    pub fn recovery(&self, now_us: u64) -> Recovery {
        let Some(attempt) = self.last else {
            return Recovery {
                attempts: Some(self.attempts),
                ..Recovery::UNAVAILABLE
            };
        };
        let (outcome, refusal) = match attempt.outcome {
            Outcome::Running => (RecoveryOutcome::Running, None),
            Outcome::Completed => (RecoveryOutcome::Completed, None),
            Outcome::Refused(refusal) => (RecoveryOutcome::Refused, Some(refusal)),
        };
        Recovery {
            kind: Some(attempt.kind),
            outcome: Some(outcome),
            check: refusal.map(|r| r.check),
            next: refusal.map(|r| r.next),
            store: refusal.and_then(|r| r.store),
            attempts: Some(self.attempts),
            age_us: now_us.checked_sub(attempt.started_us),
        }
    }
}

impl From<&restart::Refused> for RecoveryRefusal {
    fn from(refused: &restart::Refused) -> Self {
        let next = match (refused.flip, refused.recovery) {
            (Some(_), _) => RecoveryNext::Flip,
            (None, Some(_)) => RecoveryNext::Hold,
            (None, None) => RecoveryNext::Stop,
        };
        let (check, store) = restart_check(&refused.check);
        Self {
            check,
            next,
            store: store.map(StoreClass::from),
            lineage: lineage_device(&refused.check),
        }
    }
}

/// Whether `check` is the lineage arm's own hold: a device command of the arm that ended without success, the
/// Register, the preempt or Report #2, a Report #2 whose bytes fail the parse included, since such a Report shows no
/// holder; or the full registrant table the arm refused to register into ([`restart::Lineage::Full`]), which lasts
/// until a registration leaves the table, so it pages as the device holds do. A failed shard reread, a superseded
/// tenure and a Report #2 refusal over parsed entries are no such hold.
fn lineage_device(check: &restart::Check) -> bool {
    use crate::failover::evidence::NotSole;
    use restart::{Check, Lineage};
    match check {
        Check::Lineage(Lineage::Register(_) | Lineage::Preempt(_) | Lineage::Full) => true,
        Check::Lineage(Lineage::Confirm(confirmed)) => {
            matches!(
                **confirmed,
                Check::SecondReport(_) | Check::NotSole(NotSole::Unreadable)
            )
        }
        _ => false,
    }
}

impl From<&takeover::Refused> for RecoveryRefusal {
    fn from(refused: &takeover::Refused) -> Self {
        let next = if refused.restarts() {
            RecoveryNext::Restart
        } else {
            RecoveryNext::Stop
        };
        let (check, store) = takeover_check(&refused.check);
        Self {
            check,
            next,
            store: store.map(StoreClass::from),
            lineage: false,
        }
    }
}

impl From<&fresh::Refused> for RecoveryRefusal {
    fn from(refused: &fresh::Refused) -> Self {
        let next = if refused.flip.is_some() {
            RecoveryNext::Flip
        } else if refused.check.restarts() {
            RecoveryNext::Restart
        } else {
            RecoveryNext::Stop
        };
        let (check, store) = fresh_check(&refused.check);
        Self {
            check,
            next,
            store: store.map(StoreClass::from),
            lineage: false,
        }
    }
}

fn withdraw_store(withdraw: &Withdraw) -> Option<&StoreError> {
    match withdraw {
        Withdraw::Store(error) => Some(error),
        Withdraw::NewerFence { .. }
        | Withdraw::Malformed { .. }
        | Withdraw::NoPage { .. }
        | Withdraw::Unpaired => None,
    }
}

fn fence_store(refused: &FenceRefused) -> Option<&StoreError> {
    match refused {
        FenceRefused::Fence(withdraw) => withdraw_store(withdraw),
        FenceRefused::Fencing(_) | FenceRefused::Unresolved { .. } => None,
    }
}

fn restart_check(check: &restart::Check) -> (RecoveryCheck, Option<&StoreError>) {
    use RecoveryCheck as R;
    use restart::Check as C;
    match check {
        C::Records(error) => (R::Records, Some(error)),
        C::Deposed => (R::Deposed, None),
        C::Lineage(restart::Lineage::Reread(error)) => (R::RecordedHolder, Some(error)),
        C::Lineage(restart::Lineage::Confirm(check)) => (R::RecordedHolder, restart_check(check).1),
        C::RecordedHolder | C::Lineage(_) => (R::RecordedHolder, None),
        C::Unheld => (R::Unheld, None),
        C::Fresh => (R::Fresh, None),
        C::Volume(_) => (R::Volume, None),
        C::Exhausted(_) => (R::Exhausted, None),
        C::SuffixOnly => (R::SuffixOnly, None),
        C::Local(_) => (R::Local, None),
        C::Driver(_) => (R::Driver, None),
        C::Ready(_) => (R::Ready, None),
        C::HostId(_) => (R::HostId, None),
        C::FirstReport(_) => (R::FirstReport, None),
        C::NotHolding(_) => (R::NotHolding, None),
        C::Unobserved => (R::Unobserved, None),
        C::Bump(error) => (R::Bump, Some(error)),
        C::Preempt(_) => (R::Preempt, None),
        C::SecondReport(_) => (R::SecondReport, None),
        C::NotSole(_) => (R::NotSole, None),
        C::Coverage(refused) => (R::Coverage, fence_store(refused)),
    }
}

fn takeover_check(check: &takeover::Check) -> (RecoveryCheck, Option<&StoreError>) {
    use RecoveryCheck as R;
    use takeover::Check as C;
    match check {
        C::Records(error) => (R::Records, Some(error)),
        C::Stale => (R::Stale, None),
        C::Restart => (R::Restart, None),
        C::Exhausted(_) => (R::Exhausted, None),
        C::Volume(_) => (R::Volume, None),
        C::Predecessor => (R::Predecessor, None),
        C::Local(_) => (R::Local, None),
        C::TakeOver(error) => (R::TakeOver, Some(error)),
        C::Driver(_) => (R::Driver, None),
        C::Ready(_) => (R::Ready, None),
        C::HostId(_) => (R::HostId, None),
        C::FirstReport(_) => (R::FirstReport, None),
        C::Unparsed(_) => (R::Unparsed, None),
        C::Holder(_) => (R::Holder, None),
        C::Register(_) => (R::Register, None),
        C::Preempt(_) => (R::Preempt, None),
        C::SecondReport(_) => (R::SecondReport, None),
        C::NotSole(_) => (R::NotSole, None),
        C::SecondUnparsed(_) => (R::SecondUnparsed, None),
        C::Superseded => (R::Superseded, None),
        C::Coverage(refused) => (R::Coverage, fence_store(refused)),
        C::SuffixOnly => (R::SuffixOnly, None),
    }
}

fn fresh_check(check: &fresh::Check) -> (RecoveryCheck, Option<&StoreError>) {
    use RecoveryCheck as R;
    use fresh::Check as C;
    match check {
        C::Records(error) => (R::Records, Some(error)),
        C::Unobserved => (R::Unobserved, None),
        C::Deposed => (R::Deposed, None),
        C::Restart => (R::Restart, None),
        C::Volume(_) => (R::Volume, None),
        C::Origin => (R::Origin, None),
        C::Exhausted(_) => (R::Exhausted, None),
        C::Persist(_) => (R::Persist, None),
        C::EnrollWrite(error) => (R::EnrollWrite, Some(error)),
        C::EnrollRefused(_) => (R::EnrollRefused, None),
        C::Bump(error) => (R::Bump, Some(error)),
        C::Local(_) => (R::Local, None),
        C::HostId(_) => (R::HostId, None),
        C::Register(_) => (R::Register, None),
        C::Acquire(_) => (R::Acquire, None),
        C::Report(_) => (R::Report, None),
        C::NotSole(_) => (R::NotSole, None),
        C::Hold(_) => (R::Hold, None),
        C::Write(_) => (R::Write, None),
        C::Read(_) => (R::Read, None),
        C::Activation(_) => (R::Activation, None),
        C::Confirm(error) => (R::Confirm, Some(error)),
        C::Superseded => (R::Superseded, None),
        C::Named => (R::Named, None),
        C::Fencing(_) => (R::Fencing, None),
        C::Fence(withdraw) => (R::Fence, withdraw_store(withdraw)),
        C::UnresolvedPage { .. } => (R::UnresolvedPage, None),
        C::Release(_) => (R::Release, None),
        C::Retention { original, .. } => (R::Retention, fresh_check(original).1),
    }
}

impl From<&restart::Check> for RecoveryCheck {
    fn from(check: &restart::Check) -> Self {
        restart_check(check).0
    }
}

impl From<&takeover::Check> for RecoveryCheck {
    fn from(check: &takeover::Check) -> Self {
        takeover_check(check).0
    }
}

impl From<&fresh::Check> for RecoveryCheck {
    fn from(check: &fresh::Check) -> Self {
        fresh_check(check).0
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
