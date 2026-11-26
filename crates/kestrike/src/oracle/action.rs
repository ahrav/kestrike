//! The action vocabulary and the fields each action must carry before a
//! checker may read its row.
//!
//! Every kind requires an episode and a response ordinal. A kind that
//! records an outcome names the one outcome family it admits;
//! [`NoInformation`] outcomes are valid for every outcome-recording kind
//! that [`ActionKind::admits_no_information`] accepts.
//! `Persistence`, `Admission`, `Restart`, `Captured` and `Damaged` are
//! recovery evidence kinds and require abstract or qualified evidence; a
//! lookup may also carry qualified evidence. Every other kind may be live;
//! the ledger accepts abstract evidence on fill, receive, write completion,
//! publication, replacement and invalidation rows without effect, leaves
//! captures and damage to the retained-set judgment, and rejects any other
//! abstract kind unless its outcome carries no information.
//! The remote PUT kinds, from `PutBegin` on, describe one upload attempt;
//! [`attempt`](super::attempt) holds their further rules.

use super::outcome::{NoInformation, OutcomeFamily};
use super::row::Field;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ActionKind {
    /// A fill reservation: admission of one key's content of known lengths.
    Fill,
    /// Bytes a fill streamed toward the device.
    Receive,
    /// Every write of a fill succeeded.
    WriteCompleted,
    /// A publication, including the test-only publish path.
    Publish,
    /// A publication replacing the key's current label.
    Replace,
    /// A candidate lookup and, on a hit, the acquisition of its lease.
    Lookup,
    /// The bytes a lease's read handed off and the read's outcome.
    Deliver,
    /// A device command's or request's terminal result.
    Terminal,
    Invalidate,
    Expire,
    Evict,
    Cancel,
    /// A resource refused for lack of capacity.
    Pressure,
    SessionChange,
    Close,
    /// A holder released its lease, right or resource.
    Release,
    /// A label's visibility ended for the row's cause.
    VisibilityEnded,
    /// A production report sampled at a stopped boundary.
    Report,
    /// One durable fact under the row's hypothesis.
    Persistence,
    /// Admission of the row's label to the recoverable set.
    Admission,
    /// A restart under the row's hypothesis.
    Restart,
    /// A custodian took one incarnation of a resource.
    Take,
    /// A stopped fixture boundary of the row's checkpoint kind.
    Checkpoint,
    /// A client invoked a remote PUT of one key's labelled content.
    PutBegin,
    /// The owner's authority for the attempt, naming its serial.
    Authority,
    /// The owner prepared storage for the attempt's manifest and sent READY
    /// with its first grant.
    Ready,
    /// The owner validated one distinct fragment of the attempt.
    Fragment,
    /// A cumulative receipt and grant the client received for the attempt.
    Ack,
    /// The owner submitted one write command of the attempt.
    WriteSubmit,
    /// The client's outcome for the attempt.
    PutResult,
    /// The client resent the attempt's BEGIN or PREPARE; `Acknowledged`
    /// replays the accepted attempt and `Refused` leaves it unchanged.
    Retry,
    /// The client abandoned an `Unknown` attempt; a later owner terminal may
    /// still resolve it.
    Abandon,
    /// A recovering tenure made one captured entry resident again from the
    /// cut it names.
    Restore,
    /// One entry a retained cut captured, with the units it occupies.
    Captured,
    /// Damage found at recovery in one unit, or in the whole volume.
    Damaged,
}

impl ActionKind {
    pub(crate) const ALL: [Self; 35] = [
        Self::Fill,
        Self::Receive,
        Self::WriteCompleted,
        Self::Publish,
        Self::Replace,
        Self::Lookup,
        Self::Deliver,
        Self::Terminal,
        Self::Invalidate,
        Self::Expire,
        Self::Evict,
        Self::Cancel,
        Self::Pressure,
        Self::SessionChange,
        Self::Close,
        Self::Release,
        Self::VisibilityEnded,
        Self::Report,
        Self::Persistence,
        Self::Admission,
        Self::Restart,
        Self::Take,
        Self::Checkpoint,
        Self::PutBegin,
        Self::Authority,
        Self::Ready,
        Self::Fragment,
        Self::Ack,
        Self::WriteSubmit,
        Self::PutResult,
        Self::Retry,
        Self::Abandon,
        Self::Restore,
        Self::Captured,
        Self::Damaged,
    ];

    /// The fields a row of this kind must carry, in the order admission
    /// checks them.
    pub(crate) const fn required(self) -> &'static [Field] {
        use super::row::Field::{
            BodyLength, CapturedUnits, Cause, Checkpoint, Clock, Custodian, CustodyEnd, Cut,
            Episode, Fact, Fragment, Grant, Incarnation, Invocation, Key, Label, MetadataLength,
            Outcome, Payload, Receipt, Report, Resource, Response, Serial, Session, Subject,
        };
        match self {
            Self::Fill => &[
                Key,
                Label,
                MetadataLength,
                BodyLength,
                Session,
                Incarnation,
                Invocation,
                Response,
                Outcome,
                Episode,
            ],
            Self::Receive => &[Key, Label, Invocation, Response, Payload, Episode],
            Self::WriteCompleted | Self::Evict => &[Key, Label, Response, Episode],
            Self::Publish | Self::Replace => &[Key, Label, Invocation, Response, Outcome, Episode],
            Self::Lookup => &[Key, Invocation, Response, Outcome, Episode],
            Self::Deliver => &[
                Key,
                Label,
                MetadataLength,
                BodyLength,
                Session,
                Incarnation,
                Invocation,
                Response,
                CustodyEnd,
                Outcome,
                Payload,
                Episode,
            ],
            Self::Terminal => &[Resource, Incarnation, Response, Outcome, Episode],
            Self::Invalidate => &[Key, Invocation, Response, Outcome, Episode],
            Self::Expire => &[Key, Label, Clock, Response, Episode],
            Self::Cancel => &[Resource, Incarnation, Invocation, Response, Episode],
            Self::Pressure => &[Resource, Response, Episode],
            Self::SessionChange => &[Session, Response, Episode],
            Self::Close => &[Invocation, Response, Outcome, Episode],
            Self::Release => &[Subject, Response, Episode],
            Self::VisibilityEnded => &[Key, Label, Cause, Response, Episode],
            Self::Report => &[Resource, Report, Response, Episode],
            Self::Persistence => &[Key, Label, Fact, Response, Episode],
            Self::Admission => &[Key, Label, Response, Episode],
            Self::Restart => &[Response, Episode],
            Self::Take => &[Resource, Custodian, Response, Episode],
            Self::Checkpoint => &[Checkpoint, Response, Episode],
            Self::PutBegin => &[
                Key,
                Label,
                MetadataLength,
                BodyLength,
                Invocation,
                Response,
                Episode,
            ],
            Self::Authority => &[Key, Serial, Response, Episode],
            Self::Ready => &[
                Key,
                Label,
                MetadataLength,
                BodyLength,
                Serial,
                Grant,
                Response,
                Episode,
            ],
            Self::Fragment => &[Key, Serial, Fragment, Payload, Response, Episode],
            Self::Ack => &[Key, Serial, Receipt, Grant, Response, Episode],
            Self::WriteSubmit => &[Resource, Incarnation, Serial, Invocation, Response, Episode],
            Self::PutResult => &[Key, Response, Outcome, Episode],
            Self::Retry => &[Key, Invocation, Response, Outcome, Episode],
            Self::Abandon => &[Key, Response, Episode],
            Self::Restore => &[Key, Label, Cut, Response, Episode],
            Self::Captured => &[Key, Label, Cut, CapturedUnits, Response, Episode],
            Self::Damaged => &[Response, Episode],
        }
    }

    /// The informative outcome family this kind records, when it records an
    /// outcome.
    pub(crate) const fn outcome_family(self) -> Option<OutcomeFamily> {
        match self {
            Self::Fill
            | Self::Publish
            | Self::Replace
            | Self::Invalidate
            | Self::Close
            | Self::Retry => Some(OutcomeFamily::Effect),
            Self::PutResult => Some(OutcomeFamily::Put),
            Self::Lookup => Some(OutcomeFamily::Lookup),
            Self::Deliver | Self::Terminal => Some(OutcomeFamily::Delivery),
            _ => None,
        }
    }

    /// Whether a row of this kind may record `member` as its outcome. Remote
    /// PUT fact rows carry no outcome: the attempt's outcome sits on its
    /// `PutResult`, and a retry records only the owner's acknowledgment or
    /// refusal.
    pub(crate) const fn admits_no_information(self, member: NoInformation) -> bool {
        match self {
            Self::Terminal => matches!(member, NoInformation::Dropped),
            Self::Retry => matches!(member, NoInformation::Refused),
            _ if self.is_remote_put() => false,
            _ => true,
        }
    }

    /// Whether the kind's rows are recovery evidence, abstract or qualified.
    pub(crate) const fn requires_recovery_evidence(self) -> bool {
        matches!(
            self,
            Self::Persistence | Self::Admission | Self::Restart | Self::Captured | Self::Damaged
        )
    }
}
