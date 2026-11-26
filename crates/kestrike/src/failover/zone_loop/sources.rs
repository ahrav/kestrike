//! The zone loop reads sealed host reports, the zone's instance listing and its volume listing through these
//! traits, and requests attachments through [`Attacher`]. The instance and volume sources return `Unlisted` when any
//! page of a listing fails, so a listing is whole or absent.

use crate::failover::attachments::{InstanceId, Unlisted};
use crate::failover::reconcile::{Detachable, Relisted};
use crate::failover::records::{Host, VolumeId};
use crate::failover::standbys::Zone;
use crate::failover::zone_loop::evidence::{Instance, VolumeCondition};

/// The source returned no answer for a host's report: the transport was unreachable, the call timed out or it
/// returned an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreachable;

pub trait ReportSource {
    /// The latest sealed report bytes `host` published, `None` when it has published none. The bytes are
    /// unauthenticated until `report::Reader::accept` verifies them.
    ///
    /// An implementation reads the host's last publication from a medium that answers while the host is dead:
    /// for a non-retired host, `tick_evidence` maps `Lost` to `Unknown` when `answered_us <= rule.silent_us`.
    /// An implementation returns at most `report::MAX_LEN + 1` bytes, so the caller tells an oversized publication
    /// from one of exactly `report::MAX_LEN` bytes.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] when the medium gave no answer.
    fn latest(&mut self, host: Host) -> Result<Option<Vec<u8>>, Unreachable>;
}

pub trait InstanceSource {
    /// The state and status checks of every instance of `zone`, in one whole listing.
    ///
    /// # Errors
    ///
    /// [`Unlisted`] when the source gave no complete listing: a page failed or was unreadable, or the source refused
    /// `zone` before any request.
    fn instances(&mut self, zone: Zone) -> Result<Vec<Instance>, Unlisted>;
}

/// One volume row of a zone listing: its state and status and the instance ID of every attachment record, in
/// every state the control plane reports, as `attachments::ControlPlane::attachments` lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedVolume {
    pub volume: VolumeId,
    pub condition: VolumeCondition,
    pub attachments: Vec<String>,
}

pub trait VolumeSource {
    /// Every cache volume of `zone`, in one whole listing, which may also hold the zone's other volumes.
    ///
    /// # Errors
    ///
    /// [`Unlisted`] when the source gave no complete listing: a page failed or was unreadable, or the source refused
    /// `zone` before any request.
    fn volumes(&mut self, zone: Zone) -> Result<Vec<ListedVolume>, Unlisted>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachRefusal {
    /// The volume or the instance is in a state that takes no new attachment.
    State,
    /// The instance or the volume is at an attachment limit.
    Limit,
    /// The control plane cannot identify the volume or instance, or it denies the request.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachReply {
    /// The control plane accepted the request. A later listing shows whether the attachment exists.
    Accepted,
    /// The control plane already holds an attachment record of the pair.
    AlreadyListed,
    Refused(AttachRefusal),
    /// The control plane may have attached the volume.
    Unknown,
}

/// The loop relies on the provider to create at most one attachment per volume and instance pair across repeated or
/// concurrent requests. For an attached pair, the provider returns `AlreadyListed` or `Accepted`. The client reports
/// `Unknown` when the outcome is uncertain, including after a timeout.
pub trait Attacher {
    /// Each `attach` call makes one control-plane request under one deadline.
    fn attach(&mut self, volume: VolumeId, instance: InstanceId) -> AttachReply;

    /// Each `detach` call makes one graceful control-plane detach request under one deadline for the attachment
    /// `witness` names.
    fn detach(&mut self, witness: Witness<'_>) -> DetachReply;
}

/// The witness a detach request takes: an ended entry with no recorded pair ([`Detachable`]), or a gone entry whose
/// instance no attach or ended entry of the volume record binds ([`Relisted`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Witness<'a> {
    Ended(&'a Detachable),
    Relisted(&'a Relisted),
}

impl Witness<'_> {
    pub fn volume(&self) -> VolumeId {
        match self {
            Self::Ended(witness) => witness.volume(),
            Self::Relisted(witness) => witness.volume(),
        }
    }

    pub fn instance(&self) -> InstanceId {
        match self {
            Self::Ended(witness) => witness.instance(),
            Self::Relisted(witness) => witness.instance(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachReply {
    Accepted,
    /// The control plane reports that the pair is already detached.
    AlreadyDetached,
    /// The control plane may have detached the volume.
    Unknown,
}
