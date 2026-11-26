//! The control plane's attachment records of a volume, the enumeration client that lists them, and their comparison
//! with the desired state.
//!
//! ATTACH-OUTSIDE-DESIRED-STATE: the desired state names the admitted set of a cache volume's attachments: the host
//! the shard record names for it and the peers its caller admits, each with the instance ID its caller supplies.
//! [`check`] accepts a listing only when it holds the own instance once, each admitted peer at most once, and nothing
//! else. Every listed record counts, whatever the state the control plane reports
//! for it, so an attaching, detaching or detached record of another instance refuses as a foreign attachment. A
//! listed instance ID is compared byte for byte with the desired one, so a malformed or unknown ID is foreign.
//!
//! The listing is the only evidence of an attachment that never registered and that the volume record's events
//! never recorded: such an attachment appears in no Report and in no attachment event.
//!
//! A listing holds the records the control plane returns when it is read, not an attachment history, and
//! `DescribeVolumes` is eventually consistent. A check that relies on a clean listing rests on the attachments that
//! could have written the volume being visible to that read.

use crate::failover::records::{Host, VolumeId};

/// A canonical instance ID, `i-` and 8 or 17 lowercase hexadecimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceId {
    len: u8,
    name: [u8; INSTANCE_LEN],
}

const INSTANCE_LEN: usize = 19;
const SHORT_INSTANCE_LEN: usize = 10;

/// A stored instance field occupies 20 bytes: one length byte, the ID bytes, and zero padding.
pub(crate) const INSTANCE_FIELD: usize = 1 + INSTANCE_LEN;

impl InstanceId {
    pub fn new(name: &str) -> Option<Self> {
        let bytes = name.as_bytes();
        let hex = bytes.get(2..).is_some_and(|digits| {
            digits
                .iter()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        });
        if !(bytes.starts_with(b"i-")
            && hex
            && matches!(bytes.len(), SHORT_INSTANCE_LEN | INSTANCE_LEN))
        {
            return None;
        }
        let mut name = [0; INSTANCE_LEN];
        name[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            len: bytes.len() as u8,
            name,
        })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.name[..usize::from(self.len)]
    }

    /// `field` encodes the ID in its canonical stored format.
    pub(crate) fn field(&self) -> [u8; INSTANCE_FIELD] {
        let mut field = [0; INSTANCE_FIELD];
        field[0] = self.len;
        field[1..].copy_from_slice(&self.name);
        field
    }

    /// `from_field` returns `Some(id)` if `id.field()` equals `*field`, and `None` otherwise.
    pub(crate) fn from_field(field: &[u8; INSTANCE_FIELD]) -> Option<Self> {
        let [len, ref name @ ..] = *field;
        let id = Self::new(core::str::from_utf8(name.get(..usize::from(len))?).ok()?)?;
        (id.name == *name).then_some(id)
    }

    /// Whether `listed` equals this ID byte for byte.
    fn is(&self, listed: &[u8]) -> bool {
        listed == self.as_bytes()
    }
}

/// `Unlisted` marks a failed read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unlisted;

/// The enumeration client: one control-plane call per listing.
pub trait ControlPlane {
    /// The instance ID of every control-plane attachment record of `volume`, in every state the control plane
    /// reports, including detaching and detached records, in the order the control plane returns them. The
    /// production class is one `DescribeVolumes` call filtered to the volume ID, made under a principal that may
    /// read the attachment records of cache-tagged volumes. The caller's thread runs `DescribeVolumes`
    /// synchronously. The configured listing deadline covers all retries; the class returns [`Unlisted`] when the
    /// deadline expires.
    ///
    /// # Errors
    ///
    /// [`Unlisted`] when the class obtains no usable, complete listing of exactly `volume`'s attachment records:
    /// the call failed or was refused, or its response is unreadable, incomplete or holds no record of `volume`. A
    /// complete listing yields one entry per attachment record; a record whose instance ID the class cannot read
    /// yields an empty entry, which [`check`] treats as foreign, so one unreadable record hides no other.
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted>;
}

/// The checks rely on the caller to verify that `instance` identifies the standby `host`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub host: Host,
    pub instance: InstanceId,
}

/// Why a listing differs from the desired state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// A listed record names an instance outside the admitted set: the first such ID, as listed.
    Foreign(String),
    /// The own instance or an admitted peer is listed more than once.
    Duplicate,
    /// The own instance is not listed.
    Missing,
}

impl Mismatch {
    /// Whether the mismatch shows an attachment outside the desired state, which retires the volume. A missing own
    /// record shows none: by itself it refuses the step that needed it and changes nothing else.
    pub fn retires(&self) -> bool {
        !matches!(self, Self::Missing)
    }
}

/// Compares `listed` with the desired state: every record names `own` or a member of `peers`, `own` once and each
/// member of `peers` at most once; byte-identical records count as duplicates.
///
/// # Errors
///
/// [`Mismatch::Foreign`] before [`Mismatch::Duplicate`] before [`Mismatch::Missing`].
pub fn check<'p>(
    listed: &[String],
    own: &InstanceId,
    peers: impl IntoIterator<Item = &'p InstanceId, IntoIter: Clone>,
) -> Result<(), Mismatch> {
    let peers = peers.into_iter();
    let (mut owned, mut duplicate) = (false, false);
    for (at, record) in listed.iter().enumerate() {
        let id = record.as_bytes();
        let instance = if own.is(id) {
            owned = true;
            own
        } else {
            peers
                .clone()
                .find(|peer| peer.is(id))
                .ok_or_else(|| Mismatch::Foreign(record.clone()))?
        };
        duplicate |= listed[..at]
            .iter()
            .any(|earlier| instance.is(earlier.as_bytes()));
    }
    if duplicate {
        return Err(Mismatch::Duplicate);
    }
    if owned {
        Ok(())
    } else {
        Err(Mismatch::Missing)
    }
}
