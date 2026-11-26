//! The attach requires [`Fenced`] before its first medium command, obtained from the fresh Report, the restart's fencing boundary or the Register, Acquire and Report gate.
//!
//! GATE-BEFORE-MEDIUM: before [`Fenced`] exists the volume submits only reservation commands. [`Fenced::restarted`] is the fencing boundary of the same-host restart sequence (`failover::restart`): it reads that sequence's Report #2, which follows the ready wait and the self Preempt-and-Abort, and a volume whose authority carries it passes the gate with no gate command. [`Fenced::fresh`] is the fencing boundary of the fresh first acquisition (`failover::fresh`): it reads that path's fresh Report, which follows the acknowledged `E` bump, the own Register and the own type-2 Acquire, and passes the gate the same way. [`Fenced::restarted`] is also the admission capability of the same-volume takeover (`failover::takeover`): it reads the Report that follows the acknowledged takeover compare-and-swap and the Preempt-and-Abort of the superseded holder's key, the predecessor's or a holder whose tenure the predecessor's line of takeovers superseded, and passes the gate the same way. [`Fenced::sole_registrant`] is the Register, Acquire and Report gate's constructor; that gate runs under a [`Machine::gated`](crate::failover::serving::Machine::gated) machine, which holds the tenure's token for the attach's own pair before the boundary, and a Report timeout or a clock fault before its Report renews a window ends the attach `Unfenced(AuthorityLost)`. It reads the Report this attach took after its own Register and its own type-2 Acquire succeeded, and mints only when the Report's registrant count is conclusive, the Report shows a type-2 reservation, exactly one record carries the own host ID, and that record's (host ID, key) pair is the one holder and the one registrant.
//!
//! ADMISSION-CAPABILITY: a [`Fenced`] value licenses the volume's medium work under its tenure, because its Report showed the own pair holding after the sequence's reservation commands completed. The reservation is a deposition observable and stops the ordinary new writes of a preempted registration. The Report shows the registrant set at one instant and the controller's view of completed commands, so the recovery order after the boundary, the record checks and the preservation mechanism carry the residual of an earlier registration's effect that is already past the controller.
//!
//! Passing the gate opens the driver's medium commands ([`Disk::admit_medium`]), moves the readiness word from `Detached` to `Loading` and admits the root probes, the named-slot reads, the root writes and payload reads. Payload writes need the bootstrap to reach `Open`, which follows the gate: [`WritableFill::receive`](crate::storage::WritableFill::receive) refuses `Bootstrapping` until the metadata opens, for fills reserved before the attach as well, and the readiness word refuses new fills until `Live`.
//!
//! The gate's Report is the serving machine's pending Report, so the Report deadline, the window renewal of an own-holder Report and the withdrawal on retirement evidence apply to it; the gate's verdict applies before the machine's event. On an open, unlost volume, a serving machine that withdraws, closes or reaches its window's end while the gate runs ends the attach `Unfenced(AuthorityLost)`, also after the owner's withdrawal close effects stopped metadata, and so does the gate's Report when it completes under such a machine. A close or the volume's loss during the gate keeps the outcome `Bootstrapping`. After a readiness withdrawal by [`Storage::withdraw`](super::super::Storage::withdraw) under a serving machine that still holds authority, an outstanding gate command still takes its verdict: a refused or failed command ends the attach `Unfenced`, and a passing Report sets the gate while the readiness word stays `Withheld`, so no medium command follows.
//!
//! The Register, Acquire and Report gate judges the registrant set one Report shows. It drains no earlier incarnation's commands, and it admits an earlier incarnation registered under the same host ID and key as this attach. A Register or Acquire that a registration of another key refuses ends `CommandFailed`; another pair in a successful Report ends `ForeignHolder` or `ForeignRegistrant`.

use super::super::device::{
    Classification, CommandToken, DeviceStatus, Disk, KEY_DATA_BYTES, ReportError,
    ReservationCommand, Terminal,
};
use super::super::os::Platform;
use super::super::readiness::Event;
use super::super::recovery::MetadataOutcome;
use super::attach::Volume;
use super::authority::Unsent;
use super::metadata::Phase;
use super::tick::{busy, lost};
use crate::failover::bounds::Bounds;
use crate::failover::evidence::{NotSole, Pair, Report};
use crate::failover::serving::State;

/// The volume's admission of medium commands; the bootstrap holds one from the gate on. `own` is the pair the minting Report showed as the one holder of the type-2 reservation, with one record carrying its host ID. The fresh Report and the attach gate's Report also showed it as the one registrant; restart Report #2 and the takeover's Report #2 may list the volume record's recorded pairs as non-holding registrants.
///
/// Production constructors mint [`Fenced`] from the fresh Report, restart Report #2, the takeover's Report #2, or
/// the attach gate's Report under a machine holding the tenure's token. [`Disk::admit_medium`] uses that evidence to open medium commands
/// for the volume that owns it. Test builds also mint driver-only values.
///
/// ```compile_fail,E0451
/// # use kestrike::storage::Fenced;
/// let forged = Fenced { own: todo!() };
/// ```
///
/// ```compile_fail,E0599
/// # use kestrike::storage::Fenced;
/// let assumed = Fenced::assumed();
/// ```
///
/// ```compile_fail,E0599
/// # use kestrike::storage::Fenced;
/// let defaulted = Fenced::default();
/// ```
#[derive(Debug)]
pub struct Fenced {
    own: Pair,
}

impl Fenced {
    /// Mints the gate from `report`, which this attach took after its own Register and type-2 Acquire succeeded, for the own pair `own`.
    fn sole_registrant(
        report: &Report<'_>,
        own: Pair,
        bounds: &Bounds,
    ) -> Result<Self, GateRefusal> {
        report.sole(own, bounds)?;
        Ok(Self { own })
    }

    /// Mints the fencing boundary from Report #2 of the restart sequence for the own pair `own`, which the caller took after the controller-ready wait and a successful self Preempt-and-Abort. The restart drains the earlier incarnation's card-held and outstanding commands, a stale attempt landing after the boundary carries its earlier session, and the records the volume holds stay subject to the recovery order that follows the boundary.
    ///
    /// `recorded` holds the recorded pairs of the volume record Report #2 was judged against. The takeover's Report #2,
    /// after its CAS and the preempt of the superseded holder, drains no predecessor and mints the capability
    /// (ADMISSION-CAPABILITY).
    ///
    /// # Errors
    ///
    /// The first [`NotSole`] refusal of [`Report::registrants`] over `recorded`.
    pub(crate) fn restarted(
        report: &Report<'_>,
        own: Pair,
        recorded: &[Pair],
        bounds: &Bounds,
    ) -> Result<Self, NotSole> {
        report.registrants(own, Some(recorded), bounds)?;
        Ok(Self { own })
    }

    /// [`Fenced::fresh`] mints the fresh-acquisition fencing boundary from a fresh Report.
    ///
    /// # Errors
    ///
    /// The first [`NotSole`] refusal of [`Report::sole`].
    pub(crate) fn fresh(report: &Report<'_>, own: Pair, bounds: &Bounds) -> Result<Self, NotSole> {
        Self::restarted(report, own, &[], bounds)
    }

    pub(crate) fn own(&self) -> Pair {
        self.own
    }

    /// The gate a test double without reservation commands passes through. Public visibility makes `#[cfg(test)]`
    /// the access boundary for the external `compile_fail` doctest on [`Fenced`]. A non-test build that defines this
    /// constructor compiles the doctest's call, which fails the doctest.
    #[cfg(test)]
    pub fn assumed() -> Self {
        Self::assumed_for(super::gate_fixture::own())
    }

    /// A gate for `own` the tests assume.
    #[cfg(test)]
    pub(crate) fn assumed_for(own: Pair) -> Self {
        Self { own }
    }
}

/// The gate's verdict on its Report for the own pair `own`: `succeeded` says whether the Report's status classified as success over its transfer length, and `parsed` holds the parse of its bytes, `Err(Some)` for a parse error or the refusal the table recorded in place of withheld bytes, or `Err(None)` when the driver reports no reservation limits or the table holds neither the bytes nor a refusal.
pub(super) fn judge(
    succeeded: bool,
    parsed: &Result<Report<'_>, Option<ReportError>>,
    own: Pair,
    bounds: &Bounds,
) -> Result<Fenced, GateRefusal> {
    if !succeeded {
        return Err(GateRefusal::CommandFailed(GateStep::Report));
    }
    match parsed {
        Ok(report) => Fenced::sole_registrant(report, own, bounds),
        Err(Some(error)) => Err(error.refusal().into()),
        Err(None) => Err(GateRefusal::ReportUnreadable),
    }
}

#[cfg(test)]
thread_local! {
    /// Test builds pass a driver without reservation commands through the gate while this holds, its default; a test clears it to reach the `Unsupported` refusal.
    pub(crate) static UNGATED: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Why the attach refused at its gate, with no medium command issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRefusal {
    /// The driver offers no reservation commands.
    Unsupported,
    /// The table refused the Register, the Acquire or the Report for a reason other than a full queue or the device's loss, or the command completed without success; a Report whose status deposes the serving machine ends `AuthorityLost` instead.
    CommandFailed(GateStep),
    /// The serving machine withdrew, closed or reached its window's end while the gate ran.
    AuthorityLost,
    /// `ReportUnreadable` covers missing Report data, bytes withheld for truncated or inconclusive headers, parse failures, and registrant counts that exceed bounds or disagree with entries. Reservation-type parse failures map to `ReservationType`; withheld `DuplicateOwnHostId` or `OwnHostIdKey` refusals map to `DuplicateOwnRecord`; a `DuplicateKey` or `Identity` parse failure maps to `ForeignRegistrant`.
    ReportUnreadable,
    /// The Report shows a reservation type other than 2 after the Acquire.
    ReservationType,
    /// A pair other than this volume's own holds the reservation.
    ForeignHolder,
    /// A pair other than this volume's own is registered.
    ForeignRegistrant,
    /// A record other than the own record carries this volume's own host ID: a second record, or the one such record under another key.
    DuplicateOwnRecord,
    /// The own pair is not the holder.
    NotHolder,
}

impl From<NotSole> for GateRefusal {
    fn from(refusal: NotSole) -> Self {
        match refusal {
            NotSole::Unreadable | NotSole::Excess => Self::ReportUnreadable,
            NotSole::ReservationType => Self::ReservationType,
            NotSole::DuplicateOwnRecord => Self::DuplicateOwnRecord,
            NotSole::ForeignHolder => Self::ForeignHolder,
            NotSole::ForeignRegistrant => Self::ForeignRegistrant,
            NotSole::NotHolder => Self::NotHolder,
        }
    }
}

/// One reservation command of the gate's sequence, in issue order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStep {
    Register,
    Acquire,
    Report,
}

impl<P: Platform, D: Disk> Volume<'_, '_, P, D> {
    /// An authority carrying [`Fenced::restarted`] immediately satisfies the attach gate on a reservation-capable driver.
    ///
    /// A full table or device queue, an unavailable clock sample or exhausted ordinals return zero and leave the step for a later tick; a refusal for the device's loss loses the volume; any other refusal ends the attach `Unfenced(CommandFailed)`. A driver without reservation commands ends `Unfenced(Unsupported)`; while [`UNGATED`] holds, test builds instead pass it through [`Fenced::assumed`], so simulated-device fixtures without reservation commands run the bootstrap after the gate.
    pub(super) fn gate_step(&mut self) -> u32 {
        let Phase::Gate {
            step,
            pending: None,
        } = self.metadata.phase
        else {
            return 0;
        };
        if self.table.reservation_limits().is_none() {
            #[cfg(test)]
            if UNGATED.get() {
                if let Some(fenced) = self.authority.pending_fence.take() {
                    self.pass_gate(fenced);
                } else if self.serving_token().is_some() {
                    self.pass_gate(Fenced::assumed());
                }
                return 0;
            }
            self.end(MetadataOutcome::Unfenced(GateRefusal::Unsupported));
            return 0;
        }
        if let Some(fenced) = self.authority.pending_fence.take() {
            self.pass_gate(fenced);
            return 0;
        }
        let Some(token) = self.serving_token() else {
            return 0;
        };
        let submitted = match step {
            GateStep::Register => {
                self.submit_ordered(|_| ReservationCommand::Register { new: token.key })
            }
            GateStep::Acquire => {
                self.submit_ordered(|_| ReservationCommand::Acquire { current: token.key })
            }
            GateStep::Report => self.submit_report(),
        };
        let submitted = match submitted {
            Ok(submitted) => submitted,
            Err(Unsent::Deferred) => return 0,
            Err(Unsent::Refused(refusal)) if busy(refusal) => return 0,
            Err(Unsent::Refused(refusal)) if lost(refusal) => {
                self.lost = true;
                self.halt_metadata();
                return 0;
            }
            Err(Unsent::Refused(_)) => {
                self.end(MetadataOutcome::Unfenced(GateRefusal::CommandFailed(step)));
                return 0;
            }
        };
        self.metadata.phase = Phase::Gate {
            step,
            pending: Some(submitted),
        };
        1
    }

    pub(super) fn gate_admitted(&self) -> bool {
        self.authority_state() == State::PreBoundary
            && (self.authority.pending_fence.is_some()
                || self.serving_token().is_some()
                || self.table.reservation_limits().is_none())
    }

    /// Whether the serving machine withdrew, closed or reached its window's end while the gate runs. A gated machine
    /// gains a window when its gate's Report renews one; before that, any expiry, a Report timeout or a clock fault,
    /// counts as the window's end.
    pub(super) fn gate_authority_lost(&self) -> bool {
        if !matches!(self.metadata.phase, Phase::Gate { .. }) {
            return false;
        }
        let a = &self.authority;
        let window_over = match a.machine.window_end() {
            Some(end) => a.now >= end,
            None => a.pending_fence.is_none() && a.machine.expired_at().is_some(),
        };
        matches!(self.authority_state(), State::Withdrawn | State::Closed) || window_over
    }

    /// Whether `command` is the gate's outstanding Report.
    pub(super) fn gate_awaits(&self, command: CommandToken) -> bool {
        matches!(
            self.metadata.phase,
            Phase::Gate {
                step: GateStep::Report,
                pending: Some(pending),
            } if pending == command
        )
    }

    /// Applies `terminal` when it ends the gate's outstanding Register or Acquire, and returns whether it did. The serving machine owns the Report's terminal, so a Report terminal that reaches here, one whose Report timed out, counts as stale.
    pub(super) fn gate_terminal(&mut self, terminal: &Terminal<'_>) -> bool {
        let Phase::Gate {
            step,
            pending: Some(pending),
        } = self.metadata.phase
        else {
            return false;
        };
        let Terminal::Reservation { token, status, .. } = *terminal else {
            return false;
        };
        if token != pending {
            return false;
        }
        let next = match step {
            GateStep::Register => GateStep::Acquire,
            GateStep::Acquire => GateStep::Report,
            GateStep::Report => return false,
        };
        if !status.is_some_and(|status| succeeded(status, KEY_DATA_BYTES)) {
            self.end(MetadataOutcome::Unfenced(GateRefusal::CommandFailed(step)));
            return true;
        }
        self.metadata.phase = Phase::Gate {
            step: next,
            pending: None,
        };
        true
    }

    /// Passes the gate under `verdict`'s value, or ends the attach `Unfenced` with its refusal.
    pub(super) fn gate_judged(&mut self, verdict: Result<Fenced, GateRefusal>) {
        match verdict {
            Ok(fenced) => self.pass_gate(fenced),
            Err(refusal) => self.end(MetadataOutcome::Unfenced(refusal)),
        }
    }

    /// Admits medium commands under `fenced`: the driver opens its medium gate, the bootstrap moves to its probe of slot A and the readiness word to `Loading`.
    fn pass_gate(&mut self, fenced: Fenced) {
        debug_assert!(
            self.metadata.fenced.is_none() && matches!(self.metadata.phase, Phase::Gate { .. }),
            "the gate passes once, from its own phase"
        );
        self.table.admit_medium(&fenced);
        let crossed = self.authority.machine.cross_boundary(&fenced);
        debug_assert!(
            matches!(
                crossed,
                crate::failover::serving::Outcome::Moved {
                    to: State::Recovering,
                    ..
                }
            ),
            "a passing gate moves a PreBoundary machine to Recovering: {crossed:?}"
        );
        if matches!(crossed, crate::failover::serving::Outcome::Rejected(_)) {
            self.authority.refusal = Some(super::authority::AuthorityRefusal::Boundary);
        }
        self.authority_effects();
        self.metadata.fenced = Some(fenced);
        self.metadata.phase = Phase::ProbeA;
        let _ = self.storage.readiness.apply(Event::Attach);
    }
}

/// Whether a reservation command's status reports success over its transfer length `requested`, as the command table classifies it.
pub(super) fn succeeded(status: DeviceStatus, requested: u32) -> bool {
    matches!(status.classify(requested), Classification::Success)
}

#[cfg(test)]
#[path = "fence_tests.rs"]
mod tests;
