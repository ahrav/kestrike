//! `VolumeActions` is the reconciler's mutating EC2 adapter: it creates a
//! zone's replacement volumes for `loss::Provider` through `CreateVolume`,
//! and attaches and detaches the volume and instance pairs its caller names
//! for `zone_loop::sources::Attacher` through `AttachVolume` and
//! `DetachVolume`. `Volumes` and `Instances` hold the zone's read-only
//! listings.
//!
//! - Each `create`, `attach` and `detach` call sends at most one request,
//!   under the client's `Service::deadline` taken just before the send. The
//!   adapter decodes the reply outside that deadline. A call that ends in a
//!   `Fault` or an unreadable reply returns the action's unknown outcome.
//!   The zone loop reads the volume's attachment listing before it asks
//!   again for an attach or a detach. A create's callers,
//!   `Reconciler::create_replacement` and the zone loop's replace step
//!   through `Reconciler::create_attempt`, repeat the receipt's token from
//!   their read of the receipt, with no listing of the token's volume.
//! - IDEMPOTENT-PROVISIONING: `create` sends the receipt token unchanged as
//!   `ClientToken` and as the value of the `TOKEN_TAG` tag. The other
//!   parameters derive from the layout, the adapter's `VolumeSpec` and its
//!   zone name, fixed at construction, so every repeat of one attempt, from
//!   this adapter or from a rebuilt one of the same zone name and spec,
//!   sends the same body. A raised attempt carries another token and so
//!   another body.
//! - A repeat finds the token's first volume only while EC2 retains the
//!   token, for a duration EC2 leaves unstated. After EC2 drops the token, a
//!   repeat can make a second volume, and `create` returns it as `Ok`,
//!   because the second volume's reply meets the same conditions as the
//!   first's. Every volume a token made carries the token in `TOKEN_TAG`,
//!   so an operator finds them by filtering on that tag.
//! - `create` returns a volume only from a 200 reply in the adapter's zone
//!   whose `volumeId` `VolumeId` accepts, in any volume state. It returns
//!   `CreateError::Unknown` for every other reply, including throttling,
//!   quota refusals and `IdempotentParameterMismatch`. An error reply
//!   describes only the request that received it, and an earlier request
//!   under the same token may have made a volume.
//! - `detach` returns `Accepted` for a 200 naming the pair in state
//!   `detaching` or `detached`, `AlreadyDetached` for a 4xx
//!   `InvalidAttachment.NotFound`, and `Unknown` for every other reply.
//! - Graceful detach: every `DetachVolume` carries exactly two parameters,
//!   the volume ID and the instance ID.

use std::collections::BTreeMap;

use kestrike::failover::attachments::InstanceId;
use kestrike::failover::loss::{CreateError, Provider};
use kestrike::failover::records::{Layout, VolumeId, delta_blocks};
use kestrike::failover::zone_loop::config::ZoneBounds;
use kestrike::failover::zone_loop::sources::{
    AttachRefusal, AttachReply, Attacher, DetachReply, Witness,
};
use kestrike::storage::{IO_UNIT, VolumeGeometry};

use crate::client::Client;
use crate::clock::{Clock, SystemClock};
use crate::ec2::pages::serves;
use crate::ec2::query;
use crate::wire::{Reply, Wire};

const CREATE_VOLUME: &str = "CreateVolume";
const ATTACH_VOLUME: &str = "AttachVolume";
const DETACH_VOLUME: &str = "DetachVolume";

/// The tag key that holds a created volume's `ClientToken`.
pub const TOKEN_TAG: &str = "kestrike:create-token";
/// The tag key that holds a created volume's layout as `M/K/S/N_max`.
pub const LAYOUT_TAG: &str = "kestrike:layout";

/// An adapter keeps the device walk of at most this many volume and
/// instance pairs.
const PAIRS: usize = 1024;

/// Each `Walk` tracks one volume and instance pair's device walk: the
/// count of requests sent, the device candidates EC2 has rejected as taken
/// (bit `i` for candidate `i`), and the adapter's call count at the walk's
/// latest request.
#[derive(Debug, Default)]
struct Walk {
    asked: usize,
    taken: u64,
    last: u64,
}

/// The shape of every volume one zone's adapter creates: `io2` with
/// Multi-Attach enabled, so a shard's owner and its standby attach it
/// together, encrypted under `kms_key` or, when it is `None`, the account's
/// default EBS key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSpec {
    /// The size in GiB, 4 to 65,536 for `io2`.
    pub size_gib: u32,
    /// The provisioned IOPS, 100 to 256,000 and at most 1,000 per GiB of
    /// `size_gib` for `io2`.
    pub iops: u32,
    /// A KMS key ID, alias or ARN of 1 to 2,048 ASCII characters.
    pub kms_key: Option<String>,
}

impl VolumeSpec {
    fn valid(&self) -> bool {
        let key = self.kms_key.as_deref();
        (4..=65_536).contains(&self.size_gib)
            && (100..=256_000).contains(&self.iops)
            && u64::from(self.iops) <= 1000 * u64::from(self.size_gib)
            && key.is_none_or(|key| (1..=2048).contains(&key.len()) && key.is_ascii())
    }

    fn holds(&self, layout: &Layout) -> bool {
        let units = (u64::from(self.size_gib) << 30) / IO_UNIT as u64;
        VolumeGeometry::recorded(layout, units).is_ok() && delta_blocks(layout) > 0
    }
}

/// The reconciler's create, attach and detach requests for one zone. Only
/// `create` uses the zone name. `attach` and `detach` send the volume and
/// instance IDs their caller passes as given; the reconciler's steps
/// establish the pair's zone, account and admission before they call.
pub struct VolumeActions<W, C = SystemClock> {
    client: Client<W, C>,
    zone: String,
    spec: VolumeSpec,
    walks: BTreeMap<(VolumeId, InstanceId), Walk>,
    calls: u64,
}

impl<W: Wire, C: Clock> VolumeActions<W, C> {
    /// The adapter of the zone `bounds` configures, creating volumes of
    /// `spec`. `None` when `client` signs for another service or a region
    /// outside the zone's name, when `spec` falls outside the `io2` ranges
    /// its fields state, or when a volume of `spec` does not hold the zone's
    /// replacement layout as `holds` states. Construction checks these
    /// offline; EC2 checks the account's zone and the key's permissions
    /// when it answers a create.
    ///
    /// The writer rejects Local and Wavelength zone names.
    ///
    /// The caller passes the loop's `ZoneBounds` and keeps the zone name and
    /// `spec` fixed for as long as any attempt of the zone can be sent
    /// again, because a repeat of an attempt after either changed sends
    /// other parameters under the same token.
    pub fn new(client: Client<W, C>, bounds: &ZoneBounds, spec: VolumeSpec) -> Option<Self> {
        let config = bounds.config();
        let standard = config
            .name
            .strip_prefix(client.region())
            .is_some_and(|suffix| {
                suffix.len() == 1 && suffix.bytes().all(|byte| byte.is_ascii_lowercase())
            });
        let admitted = serves(&client, &config.name) && standard;
        (admitted && spec.valid() && spec.holds(&config.replacement)).then(|| Self {
            client,
            zone: config.name.clone(),
            spec,
            walks: BTreeMap::new(),
            calls: 0,
        })
    }

    fn detach_pair(&mut self, volume: VolumeId, instance: InstanceId) -> DetachReply {
        let params = [
            ("InstanceId", instance.as_str()),
            ("VolumeId", volume.as_str()),
        ];
        let reply = send(&mut self.client, DETACH_VOLUME, &params);
        reply.map_or(DetachReply::Unknown, |reply| {
            detach_reply(&reply, volume, instance)
        })
    }
}

/// Sends `action` with `params` as one request under a deadline the client
/// takes just before the send. A call that ends in a fault gives `None`.
fn send<W: Wire, C: Clock>(
    client: &mut Client<W, C>,
    action: &'static str,
    params: &[(&str, &str)],
) -> Option<Reply> {
    let deadline = client.deadline_from_now();
    query::send(client, action, params, deadline).ok()
}

impl<W: Wire, C: Clock> Provider for VolumeActions<W, C> {
    /// Sends at most one `CreateVolume` for `token` and `layout`. `create`
    /// returns `CreateError::Unknown` before any request when `token` lies
    /// outside the `ClientToken` form of 1 to 64 ASCII characters, or when
    /// `holds` refuses `layout`: `Layout::check_floor` refuses it, its
    /// prefix fills or exceeds a volume of the adapter's `VolumeSpec`, or
    /// its checkpoint slots leave zero delta blocks, the layout
    /// `ConfigRefusal::DeltaRegion` refuses.
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        let sendable = (1..=64).contains(&token.len()) && token.is_ascii();
        if !sendable || !self.spec.holds(&layout) {
            return Err(CreateError::Unknown);
        }
        let tag = format!(
            "{}/{}/{}/{}",
            layout.units, layout.slots, layout.slot_units, layout.entries
        );
        let (iops, size) = (self.spec.iops.to_string(), self.spec.size_gib.to_string());
        let mut params = vec![
            ("AvailabilityZone", self.zone.as_str()),
            ("ClientToken", token),
            ("Encrypted", "true"),
            ("Iops", iops.as_str()),
        ];
        if let Some(key) = &self.spec.kms_key {
            params.push(("KmsKeyId", key));
        }
        params.extend([
            ("MultiAttachEnabled", "true"),
            ("Size", size.as_str()),
            ("TagSpecification.1.ResourceType", "volume"),
            ("TagSpecification.1.Tag.1.Key", TOKEN_TAG),
            ("TagSpecification.1.Tag.1.Value", token),
            ("TagSpecification.1.Tag.2.Key", LAYOUT_TAG),
            ("TagSpecification.1.Tag.2.Value", tag.as_str()),
            ("VolumeType", "io2"),
        ]);
        let reply = send(&mut self.client, CREATE_VOLUME, &params);
        let document = reply.and_then(|reply| query::document(&reply, CREATE_VOLUME));
        let volume = document.and_then(|document| {
            let zone = document.text_of("availabilityZone");
            (zone == Some(self.zone.as_str())).then_some(())?;
            VolumeId::new(document.text_of("volumeId")?)
        });
        volume.ok_or(CreateError::Unknown)
    }
}

impl<W: Wire, C: Clock> Attacher for VolumeActions<W, C> {
    /// `attach` sends at most one `AttachVolume` request for `volume` and
    /// `instance`, naming the pair's next device candidate in order from its
    /// hash. The adapter keeps the walks of at most `PAIRS` pairs and, when a
    /// new pair finds the map full, drops the walk whose latest request is
    /// oldest. `Accepted` and `AlreadyListed` end the pair's walk.
    ///
    /// A 4xx `InvalidParameterValue` naming the sent device marks that
    /// name as taken for the walk. Such a reply reads as `Unknown` while
    /// another of the `DEVICES` names is unmarked and as `Refused(Other)`
    /// once every name is marked, so a name EC2 rejects on several laps
    /// counts once. Only such a reply marks a name.
    /// EBS identifies an NVMe volume to the host by its volume ID.
    fn attach(&mut self, volume: VolumeId, instance: InstanceId) -> AttachReply {
        let pair = (volume, instance);
        self.calls += 1;
        if self.walks.len() >= PAIRS && !self.walks.contains_key(&pair) {
            let oldest = self.walks.iter().min_by_key(|(_, walk)| walk.last);
            if let Some(oldest) = oldest.map(|(pair, _)| *pair) {
                self.walks.remove(&oldest);
            }
        }
        let walk = self.walks.entry(pair).or_default();
        walk.last = self.calls;
        let at = candidate(pair_hash(volume, instance), walk.asked);
        let device = device(at);
        walk.asked += 1;
        let marked = walk.taken | 1 << at;
        let walking = marked != EVERY_DEVICE;
        let params = [
            ("Device", device.as_str()),
            ("InstanceId", instance.as_str()),
            ("VolumeId", volume.as_str()),
        ];
        let reply = send(&mut self.client, ATTACH_VOLUME, &params);
        let taken = reply.as_ref().is_some_and(|reply| takes(reply, &device));
        let outcome = match reply {
            Some(_) if taken && walking => AttachReply::Unknown,
            Some(reply) => attach_reply(&reply, volume, instance),
            None => AttachReply::Unknown,
        };
        if matches!(outcome, AttachReply::Accepted | AttachReply::AlreadyListed) {
            self.walks.remove(&pair);
        } else if let Some(walk) = self.walks.get_mut(&pair).filter(|_| taken) {
            walk.taken = marked;
        }
        outcome
    }

    /// `detach` sends at most one graceful `DetachVolume` request naming
    /// `witness`'s volume and instance.
    fn detach(&mut self, witness: Witness<'_>) -> DetachReply {
        self.detach_pair(witness.volume(), witness.instance())
    }
}

fn names_pair(
    reply: &Reply,
    action: &str,
    volume: VolumeId,
    instance: InstanceId,
    states: [&str; 2],
) -> bool {
    query::document(reply, action).is_some_and(|document| {
        document.text_of("volumeId") == Some(volume.as_str())
            && document.text_of("instanceId") == Some(instance.as_str())
            && document
                .text_of("status")
                .is_some_and(|status| states.contains(&status))
    })
}

fn refusal(reply: &Reply) -> Option<(String, String)> {
    (400..500)
        .contains(&reply.status)
        .then(|| query::error(&reply.body))?
}

fn takes(reply: &Reply, device: &str) -> bool {
    refusal(reply)
        .is_some_and(|(code, message)| code == "InvalidParameterValue" && names(&message, device))
}

fn attach_reply(reply: &Reply, volume: VolumeId, instance: InstanceId) -> AttachReply {
    use AttachRefusal::{Limit, Other, State};
    let states = ["attaching", "attached"];
    if names_pair(reply, ATTACH_VOLUME, volume, instance, states) {
        return AttachReply::Accepted;
    }
    let Some((code, message)) = refusal(reply) else {
        return AttachReply::Unknown;
    };
    match code.as_str() {
        "VolumeInUse" if lists(&message, volume, instance) => AttachReply::AlreadyListed,
        "VolumeInUse" | "IncorrectState" | "IncorrectInstanceState" => AttachReply::Refused(State),
        "AttachmentLimitExceeded" => AttachReply::Refused(Limit),
        "InvalidParameterValue"
        | "InvalidVolume.NotFound"
        | "InvalidVolumeID.Malformed"
        | "InvalidVolume.ZoneMismatch"
        | "InvalidVolumeID.ZoneMismatch"
        | "InvalidInstanceID.NotFound"
        | "InvalidInstanceID.Malformed"
        | "EncryptedVolumesNotSupported"
        | "UnauthorizedOperation" => AttachReply::Refused(Other),
        _ => AttachReply::Unknown,
    }
}

fn detach_reply(reply: &Reply, volume: VolumeId, instance: InstanceId) -> DetachReply {
    if names_pair(
        reply,
        DETACH_VOLUME,
        volume,
        instance,
        ["detaching", "detached"],
    ) {
        return DetachReply::Accepted;
    }
    match refusal(reply) {
        Some((code, _)) if code == "InvalidAttachment.NotFound" => DetachReply::AlreadyDetached,
        _ => DetachReply::Unknown,
    }
}

fn lists(message: &str, volume: VolumeId, instance: InstanceId) -> bool {
    let form = format!(
        "{} is already attached to instance {}",
        volume.as_str(),
        instance.as_str()
    );
    message.strip_suffix('.').unwrap_or(message) == form
}

fn id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Whether `id` occurs in `text` with each end at a text boundary or a
/// character outside `[A-Za-z0-9-]`.
fn names(text: &str, id: &str) -> bool {
    text.match_indices(id).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + id.len()..].chars().next();
        !before.is_some_and(id_char) && !after.is_some_and(id_char)
    })
}

/// The count of device names `device` returns: `/dev/sdf` to `/dev/sdz`
/// and `/dev/xvdbb` to `/dev/xvdbz`, the HVM EBS data-volume names past the
/// instance store names `/dev/sdb` to `/dev/sde`.
const DEVICES: usize = 21 + 25;

/// A `Walk::taken` value with the bit of every device candidate set.
const EVERY_DEVICE: u64 = (1 << DEVICES) - 1;

/// Reducing `hash` before addition prevents the sum from wrapping, so any
/// `DEVICES` consecutive values of `asked` give every index once.
fn candidate(hash: u64, asked: usize) -> usize {
    ((hash % DEVICES as u64) as usize + asked % DEVICES) % DEVICES
}

fn device(at: usize) -> String {
    debug_assert!(at < DEVICES);
    let at = at as u8;
    if at < 21 {
        format!("/dev/sd{}", char::from(b'f' + at))
    } else {
        format!("/dev/xvdb{}", char::from(b'b' + at - 21))
    }
}

fn pair_hash(volume: VolumeId, instance: InstanceId) -> u64 {
    let bytes = volume.as_str().bytes().chain([0]);
    bytes
        .chain(instance.as_str().bytes())
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
}

#[cfg(test)]
#[path = "actions_tests.rs"]
mod tests;
