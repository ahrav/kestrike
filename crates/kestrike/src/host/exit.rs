//! The closed set of ways one owner-process incarnation ends. Each incarnation acquires at most one tenure and
//! returns one [`Exit`]; a waiting standby may run one takeover per accepted nomination, and each that stops before
//! any device command returns it to its wait. [`Exit::parks`] splits the kinds: a parked process keeps running with no device and
//! rereads its role, and every other kind ends the process, whose next incarnation derives its role again from the
//! records. HOST-LOSS-KEEPS-VOLUME: no exit authorizes a replacement. [`Exit::Retire`] alone carries a flip request,
//! which no automatic step serves, and each parked kind keeps the volume, its generation and its records. The exit of
//! the recovery attempt is the incarnation's recorded outcome; a process leaving a park records no second one.

use crate::failover::retire::Target;
use crate::failover::{fresh, restart};

/// How one incarnation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// A stop request, a signal or an acknowledged transfer ended a serving tenure or a wait, and the process ends
    /// ([`Exit::parks`] is false). `serve::Served::Ended` carries `Exit::Stopped` beside the shut-down owner's parts.
    Stopped,
    /// The tenure, the wait or the recovery attempt ended for a cause the next incarnation resolves from the records.
    /// The process ends, and its next incarnation derives its role from the records alone and runs that role's
    /// sequence, or the wait of a standby or unnamed role; no cause carries a role across incarnations.
    Rerun(Rerun),
    /// A sequence held (DEVICE-FAILURE-HOLD, RECORDED-HOLDER-HOLD): a device step, an unreadable Report, a bump without
    /// an acknowledged success, a Report #1 whose holder is recorded for this host's own earlier attach, a Report #2
    /// under any recorded holder, a [`restart::Check::Lineage`] refusal of the restart's lineage arm after its bump (a
    /// failed Register, preempt or record reread, a record another tenure moved, and a refused Report #2 but a
    /// deposition, which ends [`Exit::Deposed`]), or a coverage step that stayed unresolved or whose page read failed
    /// ended it with no flip; the arm's coverage refusal takes the coverage mapping of every restart, and `recovery`
    /// names the `(g, owner, E)` the sequence knew the shard record to hold. The process ends, and the next
    /// incarnation's sequence judges the records again; a cause that recurs on every rerun, such as damaged media,
    /// holds again until the named standby's takeover, the fresh-host attach or an operator ends it. The hint licenses
    /// no write or session. A tenure whose fencer kept a command outstanding, and a bring-up whose bootstrap or replay
    /// ended short of `Live` with no flip request, a deposing status included, hold at the tenure's own `(g, owner,
    /// E)`.
    Held { recovery: Target },
    /// A later tenure of the shard exists: a sequence's records name another owner or another active volume, a
    /// coverage page holds a later activated session's fence, or a serving tenure's authority observed one
    /// (`serve::ended`) through a later shard record, such a coverage page, or a store write refused for a later
    /// tenure.
    /// The process ends, and the exit carries no retirement request (ROLE-BOUND).
    Deposed,
    /// A sequence refused with a flip request: on observed evidence, exhausted counters or a retained host-local
    /// refusal, or a fresh first acquisition's refusal that requests its spare's flip. A bring-up whose authority
    /// withdrew with a flip request also ends `Retire`, and so does a serving tenure that withdrew on a retirement
    /// trigger. `target` is the `(g, owner, E)` the request names. The process
    /// parks with the volume retained; no automatic step serves the request.
    Retire(Target),
    /// A sequence refused with neither a flip request nor a hold, or with a hold that recurs on every rerun: a
    /// suffix-only record, nobody holding the reservation beside recorded registrants, or a coverage page that fails
    /// the fencing checks (malformed entries, a record that does not decode, no record, or a fence that is no
    /// activated session), and a `C_page` below the encoded empty page. The process parks until its role changes.
    /// A takeover that stopped ends no incarnation: its standby stays in the wait. A restart's refusal of its
    /// host-local record parks the same way, except an unreadable record, which reruns as [`Rerun::Records`], and a
    /// retained refusal, which requests the flip and parks as [`Exit::Retire`].
    Refused(Refusal),
    /// The role read found the volume retired ([`Role::Retired`](super::Role::Retired)). The process parks.
    Retired,
    /// A setup failure: an unreadable configuration, a storage whose facade was already issued, a volume attach,
    /// storage facade, registration, owner endpoint or coverage install that refused the bring-up's inputs after the
    /// sequence returned its tenure, or a waiting role given a fencer that had connected. The process ends.
    Fault(String),
}

impl Exit {
    /// Whether the process parks: it keeps running, holds no device and rereads its role once per view period, and
    /// leaves with [`Rerun::RoleChanged`] when the role changed, with [`Rerun::Records`] when a role read fails on
    /// a withdrawn store client, and with [`Exit::Stopped`] on its stop request.
    /// [`Exit::Retire`], [`Exit::Refused`] and [`Exit::Retired`] park; every other kind ends the process.
    pub fn parks(&self) -> bool {
        match self {
            Self::Retire(_) | Self::Refused(_) | Self::Retired => true,
            Self::Stopped | Self::Rerun(_) | Self::Held { .. } | Self::Deposed | Self::Fault(_) => {
                false
            }
        }
    }
}

/// Why an incarnation ends so that the next one reruns its sequence from step 1. A rerun reuses nothing of the
/// ending incarnation: its session comes from its own acknowledged write (`NoEpochReuse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rerun {
    /// The serving tenure's attach lost its device (`net::Owner::lost`). A controller event is one cause: the driver
    /// refuses every later submit, so the volume loses its device at its next command.
    ControllerEvent,
    /// The serving tenure withdrew because a Report showed a recorded pair of another host holding the reservation,
    /// and its authority had observed no later tenure. While the shard record still names this host owner at its
    /// tenure, the next incarnation's same-host restart preempts the holder through its lineage arm after its own
    /// acknowledged bump; a record that moved on gives that incarnation another role.
    RecordedHolder,
    /// The owner entered the serving turn already poisoned (`net::Owner::poisoned`): an earlier turn of it unwound
    /// outside `serve`.
    Poisoned,
    /// A serving turn, the owner's poll or the caller's duties, unwound inside `serve`, which caught it, or a job
    /// the tenure's duties submitted to the store lane completed as `host::lane::Done::Panicked`: the job unwound
    /// on the lane thread or that thread ended with the job outstanding, and the possibly-named set the job carried
    /// is lost. In builds whose panics unwind, a restart or fresh sequence that unwinds inside `recover` ends
    /// `Unwound`, and a bring-up turn that unwinds inside `bring_up` ends `Unwound`.
    Unwound,
    /// A waiting standby's takeover refused and `Takeover::next` returned `takeover::Next::Restart`. The next
    /// incarnation reads its role. If the record names this host as owner, the incarnation runs the same-host
    /// restart. If the record still names the predecessor, the incarnation enters the standby wait. Each takeover
    /// conditions its write on the exact record version, so at most one takeover write can commit against that
    /// version.
    Takeover,
    /// A waiting or parked process read a restart or fresh role other than the one it waited in.
    RoleChanged,
    /// An incarnation whose role read fails ends with `Records`: `role` returns the store error before any sequence
    /// starts, and that read issued no store write and touched no device. A restart or a fresh first acquisition
    /// ends with `Records` when a record read fails or its step-1 record names the other sequence. A restart also ends
    /// with `Records` when its host-local record is unreadable. A parked or waiting process ends with `Records` when a
    /// role read fails on a withdrawn store client, so the next incarnation reopens one from the durable watermark. If
    /// the client remains usable, the process stays parked or waiting. The next incarnation rereads the records.
    Records,
    /// The serving tenure's authority withdrew or closed and `serve::ended` names no other exit for it: it requested
    /// no flip, observed no later tenure, and its cause is neither a planned exit nor a recorded holder nor, while
    /// open, an unheld reservation or an unverified registrant (`Cause::Unverified`) whose lapse no owner poll has
    /// verified (`Owner::lapse_verified`). A deposing command status is one such cause, and so is a verified or closed
    /// unverified withdrawal; the rerun is a new incarnation, never the withdrawn tenure resumed. The tenure's duties
    /// also end it `Withdrawn`, in any state of the authority, when a store-lane completion shows the store client
    /// withdrawn (`host::duties::Duties::turn`). The next incarnation's sequence judges the records and the
    /// reservation again.
    Withdrawn,
    /// The serving tenure's authority withdrew for a planned exit (`Cause::Planned`), whether it is still open or
    /// closed, with no flip requested and no later tenure observed (`serve::ended`). A roll at the tenure's bound, an
    /// accepted restart request and a transfer whose write was never issued end `Planned` on the turn that withdraws,
    /// since the serving loop reads a withdrawn authority ahead of its stop flag. A submitted transfer keeps the
    /// withdrawn tenure polling with the stop flag read while it is outstanding: an acknowledged transfer ends
    /// [`Exit::Stopped`], a later tenure ends [`Exit::Deposed`], and a refused or unknown outcome ends `Planned` on
    /// the turn whose view, sent after that outcome, still names this tenure. The next incarnation derives its role
    /// from the records. If the records name this host as owner, a same-host restart opens the next tenure.
    Planned,
    /// The fresh path refused with no retirement request, and with no refusal that ends `Deposed`, reruns as
    /// `Records` or parks as `Refused`. The next incarnation's role read finds `E = 0` and runs the fresh path again,
    /// or finds `E = 1` once the bump committed and runs the same-host restart.
    Unactivated,
}

/// The check that refused a sequence, for [`Exit::Refused`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Restart(restart::Check),
    Fresh(fresh::Check),
}
