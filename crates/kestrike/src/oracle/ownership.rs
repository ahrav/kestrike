//! The ownership monitor checks each volume's steps, each tagged with its
//! tenure: which tenure acted on the device after each fence, and which cut
//! each successor recovered from.
//!
//! A tenure's fence is the call in which its recovery returned its
//! capability: a takeover's preempt confirmed by its Report, or a same-host
//! restart. The monitor keeps the fences in order, each with its durable cut.
//! For each fenced tenure the monitor keeps the last accepted count, the floor
//! (the last accepted count reported when the first later tenure fenced) and
//! the accepted count at withdrawal. The harness asserts that a tenure it keeps
//! stepping holds no waiting command at the fence, so its last reported count
//! equals its device's count then. The monitor reports each violation under
//! [`Obligation::Restart`]:
//!
//! - [`O1`], "a deposed tenure's medium command, accepted after its
//!   successor's fence, succeeded", states NEW-EXCLUSION (obligation records
//!   `takeover-reservation-provider-premises` and
//!   `takeover-history-preserves-the-retained-set`): the reservation ends each
//!   command a preempted registration issues after the preempt. At restart
//!   fences, the related restart property is the Tenure model's
//!   `NoPredecessorEffectAfterFB`, which bounds late landings of writes an
//!   ended incarnation issued before the fence; O1 checks none of those writes,
//!   which fall under the exemption below. The harness reports no success for a
//!   tenure a restart superseded.
//!   A success ordinal at or above the tenure's floor breaks O1. A command
//!   accepted before the fence may succeed after the fence: whether a
//!   reservation ends a command queued before its preempt is the END premise,
//!   which stays open in these histories.
//! - [`O2`], "a withdrawn tenure's device accepted a medium command", states
//!   `DetectedLossWithdraws` and WITHDRAWN-EXITS-ONLY-TO-CLOSED (obligation
//!   record `serving-table-token-and-metadata-admission`). After a tenure's
//!   `Withdrawn`, each `Commands` step of that tenure reports at most its
//!   accepted count at withdrawal.
//! - [`O3`], "a successor recovered from a cut other than the one its volume
//!   last made durable", states `RootNamedByStore` and `O-RESTART` (obligation
//!   record `takeover-history-preserves-the-retained-set`). Each `Recovered`
//!   step's cut equals the durable cut of its tenure's `Fenced` step.
//!
//! The monitor returns [`Inconclusive::Malformed`] with the tenure field for
//! any of these steps, wherever it lies in the list: a fence at or below an
//! earlier one, a step of a tenure never fenced, an accepted count below the
//! tenure's previous one, or a success ordinal at or above its step's accepted
//! count. Each rule reads a fenced tenure, so the monitor returns the same
//! verdict for an empty step list, at op 0, the index its first `Fenced` step
//! would hold. The next fence sets the earlier tenure's floor even if that
//! tenure emitted zero `Commands` steps. The monitor retains the accepted count
//! from the tenure's first `Withdrawn`. A step that breaks O1 and O2 fails O1.
//!
//! - `Fenced.durable` is the takeover history harness's one cut when the
//!   shard record read at the fence names a checkpoint, and `None` otherwise.
//!   The store double's initial record names its checkpoint, and the harness
//!   maps the initial checkpoint to its one oracle cut. When the harness
//!   recorded a whole-volume loss since the volume's previous `Fenced` step,
//!   or since the history began, the step carries `None`, so a cold start at
//!   the first fence after a recorded volume loss passes O3. A later fence
//!   with no new recorded loss carries the cut again while the record names
//!   its checkpoint, so a cold start there fails O3. A whole-volume loss
//!   recorded after a fence that carried the cut and before that tenure's
//!   first lookup is legal under `O-RESTART`, and the monitor fails a cold
//!   recovery of that tenure through O3. Both O3 failures are harness results.
//!   In the recorded histories, each volume loss precedes its fence, no cold
//!   start follows a second fence after one loss, and no fence reads a shard
//!   record that names no checkpoint, so only step lists reach a `Fenced` step
//!   with no cut and no recorded loss.
//! - A command accepted after the withdrawal inside the same owner poll counts
//!   as accepted before the withdrawal. A takeover that refuses after its
//!   preempt leaves its predecessor's floor unset. The harness reads successes
//!   only while a tenure's registration is gone from the reservation, so a
//!   tenure a restart superseded, which keeps its registration, reports an
//!   empty success list. The steps of a withdrawn owner that closes between
//!   samples end at its last sample.
//! - The harness scripts the fence: a deposed tenure's medium command the
//!   device has yet to execute completes with Reservation Conflict. On
//!   recorded histories O1 fails only through that script, O2 only through a
//!   step list, and O3 compares the harness's `Recovered` cut with its own
//!   `Fenced.durable` cut. The O1 control skips the script to inject a
//!   post-fence success that triggers O1. An O1 failure in these histories is
//!   a harness result until its replay traces the failure to cache code.
//! - The harness judges a device capture beyond its bound inconclusive. No test
//!   fills a capture past its bound, no control fails the seeded cycles' wiring
//!   of this verdict or the ownership arms of the actual-volume-loss control,
//!   and no count records how often each rule's precondition forms.
//! - Tests assert post-fence device acceptance of a deposed tenure's command
//!   only in the deposed-fill history, the O1 control, and the `Frozen` case
//!   of the stale-owner history `so4`, whose read ends in Reservation
//!   Conflict. In the seeded cycles, the superseded tenure acts only
//!   before its successor's fence. O1 evidence requires a command from that
//!   tenure after the fence.
//! - The takeover history tests and the seeded cycles step the monitor; the
//!   library tests and the `sim_worker` long-run test run them. No swept
//!   profile steps it, so a swept campaign reads its three rule texts uncaught.
//!   O1 reads delivered successful completions: a write the device executed
//!   with no delivered completion is outside it, and a pass says nothing about
//!   a real reservation.

use super::ids::{CutId, OpId, Tenure};
use super::obligation::Obligation;
use super::row::Field;
use super::verdict::{Inconclusive, Verdict, Violation};

pub(crate) const O1: &str =
    "a deposed tenure's medium command, accepted after its successor's fence, succeeded";
pub(crate) const O2: &str = "a withdrawn tenure's device accepted a medium command";
pub(crate) const O3: &str =
    "a successor recovered from a cut other than the one its volume last made durable";

/// The harness emits each step during the call that causes it; [`judge`]
/// reads steps in emission order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// `durable` is the harness's one cut when the shard record read at the
    /// fence names a checkpoint and no whole-volume loss was recorded since the
    /// volume's previous fence, or since the history began, and `None`
    /// otherwise.
    Fenced {
        tenure: Tenure,
        durable: Option<CutId>,
    },
    /// After one owner turn: the medium commands the tenure's device has
    /// accepted, and the acceptance ordinals, from zero, of those that
    /// completed with success.
    Commands {
        tenure: Tenure,
        accepted: u64,
        succeeded: Vec<u64>,
    },
    Withdrawn {
        tenure: Tenure,
    },
    /// The harness emits `Recovered` for both refused and opened loads.
    Recovered {
        tenure: Tenure,
        cut: Option<CutId>,
    },
}

struct Fence {
    tenure: Tenure,
    durable: Option<CutId>,
    /// The latest `Commands` count of this tenure, zero before its first `Commands` step.
    accepted: u64,
    /// The accepted count when the first later tenure fenced.
    floor: Option<u64>,
    /// The accepted count at the tenure's first `Withdrawn` step; a later `Withdrawn` leaves it unchanged.
    withdrawn: Option<u64>,
}

/// The monitor checks one volume's steps in order. It returns
/// [`Inconclusive::Malformed`] at op 0 for an empty step list, or at the first
/// malformed step even when a violation precedes it, and otherwise the first
/// violation, whose op is the step's index.
pub(crate) fn judge(steps: &[Step]) -> Result<(), Verdict> {
    if steps.is_empty() {
        return Err(Verdict::Inconclusive(Inconclusive::Malformed {
            op: OpId(0),
            field: Field::Tenure,
        }));
    }
    let mut fences: Vec<Fence> = Vec::new();
    let mut first = None;
    for (at, step) in steps.iter().enumerate() {
        let op = OpId(u32::try_from(at).unwrap_or(u32::MAX));
        let malformed = Verdict::Inconclusive(Inconclusive::Malformed {
            op,
            field: Field::Tenure,
        });
        let violation = |rule| {
            Verdict::Violation(Violation {
                obligation: Obligation::Restart,
                op,
                rule,
            })
        };
        match step {
            Step::Fenced { tenure, durable } => {
                if fences.iter().any(|fence| fence.tenure >= *tenure) {
                    return Err(malformed);
                }
                for fence in &mut fences {
                    fence.floor.get_or_insert(fence.accepted);
                }
                fences.push(Fence {
                    tenure: *tenure,
                    durable: *durable,
                    accepted: 0,
                    floor: None,
                    withdrawn: None,
                });
            }
            Step::Commands {
                tenure,
                accepted,
                succeeded,
            } => {
                let fence = fenced(&mut fences, *tenure).ok_or(malformed)?;
                let beyond = succeeded.iter().any(|ordinal| ordinal >= accepted);
                if *accepted < fence.accepted || beyond {
                    return Err(malformed);
                }
                let after = |floor: u64| succeeded.iter().any(|&ordinal| ordinal >= floor);
                if fence.floor.is_some_and(after) {
                    first.get_or_insert(violation(O1));
                } else if fence.withdrawn.is_some_and(|count| *accepted > count) {
                    first.get_or_insert(violation(O2));
                }
                fence.accepted = *accepted;
            }
            Step::Withdrawn { tenure } => {
                let fence = fenced(&mut fences, *tenure).ok_or(malformed)?;
                fence.withdrawn.get_or_insert(fence.accepted);
            }
            Step::Recovered { tenure, cut } => {
                let fence = fenced(&mut fences, *tenure).ok_or(malformed)?;
                if *cut != fence.durable {
                    first.get_or_insert(violation(O3));
                }
            }
        }
    }
    first.map_or(Ok(()), Err)
}

fn fenced(fences: &mut [Fence], tenure: Tenure) -> Option<&mut Fence> {
    fences.iter_mut().find(|fence| fence.tenure == tenure)
}
