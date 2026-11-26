//! The shared oracle adapters of the composed world and the endpoint
//! tests: they record what a scene's owner and clients did as oracle rows,
//! observing through the clients' endpoint seams and the storage's copy-only
//! lenses, which take no lease, clock sample or budget charge.
//! An upload attempt records its authority, readiness, each fragment the
//! owner validated, receipts, each source slot's retention and NIC custody,
//! its publication and its client result;
//! a GET records its lookup and the bytes it delivered.
//!
//! Publication evidence comes from the owner and the device boundary: a
//! receive row per fragment below the owner's receipt base for the attempt's
//! serial, carrying the bytes the client sent for that fragment; a write
//! completion row naming every write command the simulated device accepted
//! for the attempt's serial, through the volume's token bindings, with the
//! terminal the device delivered into the sink; and the publication row once
//! the key is bound. [`Attempt::observe`] calls [`census`], which reconciles
//! the device's capture with the rows and panics on a gap.

use crate::oracle::{
    ActionKind, BoundaryEvent, CommandEvidence, Custodian, KeyId, Label, OpId, Outcome, PutOutcome,
    Recorder, Serial,
};
use crate::storage::device::sim::{Capture, Captured, SimControl};
use crate::storage::{Bound, Classification, CommandToken, Operation};

use crate::oracle::{ClockSample, ReportKind, ReportState, ResourceKind};
use crate::sim::round::Actor;
use crate::storage::Storage;
use crate::storage::lenses::Binding;
use crate::storage::owner_fixture::{TestPlatform, last_sample};

use super::owner_tests::TestOwner;
use super::put_tests::{After, Scene};
use super::requests::RequestId;
use super::upload::{PrepareRefused, UploadOutcome};

const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Bytes of one fragment.
pub(super) const FRAGMENT: usize = super::geometry::FRAGMENT_LEN as usize;

const TTL_MS: u32 = 60_000;

/// Turns the scene `turns` times, each turn one controller round that also
/// polls the uploading client, listed first.
pub(super) fn drive(scene: &mut Scene<'_, '_>, turns: u64) {
    drive_then(scene, turns, &mut |_, _| {});
}

/// [`drive`], running `after` in each turn's owner action right after its
/// poll ([`Scene::turn_then`]).
pub(super) fn drive_then<'m>(scene: &mut Scene<'_, 'm>, turns: u64, after: &mut After<'_, 'm>) {
    for _ in 0..turns {
        scene.turn_then(
            &mut [(Actor::Client(0), &mut |clients, _, now| {
                let _ = clients[0].poll(now);
            })],
            after,
        );
    }
}

/// Starts a PUT of key `name` for `object`, then prepares it once the
/// owner's authority arrived.
pub(super) fn upload(
    scene: &mut Scene<'_, '_>,
    name: u8,
    object: &[u8],
    wait_us: u64,
) -> RequestId {
    shaped(scene, name, 0, object, wait_us)
}

/// [`upload`] with the object's first `metadata` bytes as metadata.
pub(super) fn shaped(
    scene: &mut Scene<'_, '_>,
    name: u8,
    metadata: u32,
    object: &[u8],
    wait_us: u64,
) -> RequestId {
    let now = scene.turn * 100;
    let id = scene.clients[0]
        .put(
            super::owner_tests::key(name),
            crate::storage::CacheVersion(0),
            now,
            wait_us,
        )
        .unwrap();
    let body = object.len() as u32 - metadata;
    let mut prepared = Err(PrepareRefused::Phase);
    for _ in 0..400 {
        drive(scene, 1);
        prepared = scene.clients[0].prepare(id, metadata, body, TTL_MS);
        if prepared != Err(PrepareRefused::Phase) {
            break;
        }
    }
    assert_eq!(prepared, Ok(()));
    drive(scene, 4);
    id
}

/// The owner fill's session and allocation the adapter names for every
/// delivery of an uploaded label.
pub(super) const ID: (u64, u64) = (1, 1);

pub(super) fn put_outcome(outcome: UploadOutcome) -> PutOutcome {
    match outcome {
        UploadOutcome::Published => PutOutcome::Published,
        UploadOutcome::Failed(status) => PutOutcome::Failed(status as u16),
        UploadOutcome::NotStarted => PutOutcome::NotStarted,
        UploadOutcome::Unknown => PutOutcome::Unknown,
    }
}

/// One source slot's current tenure: the fragment it holds, the tenure
/// count, and whether a device reference holds it.
#[derive(Clone, Copy)]
pub(super) struct Held {
    pub(super) fragment: u32,
    pub(super) tenure: u64,
    pub(super) nic: bool,
    /// The slot's retention ended: it holds no piece any more.
    pub(super) released: bool,
}

/// Records one upload attempt from observations at turn boundaries: the
/// client's serial, as the owner's fill and the authority it precedes; its
/// first grant, as the owner's READY; each fragment the owner's PUT core
/// validated, before the receipt that counts it; each later receipt base and
/// grant; the owner's receipt base for the serial, which confirms receipt of
/// each leading fragment;
/// each client source slot's tenure, retention while it holds a piece and
/// NIC custody while a device reference holds it; the client's outcome; and
/// the owner's binding of the key, as the publication. A key that already
/// held an incumbent when the attempt began leaves that observation unable
/// to tell the attempt's label from the incumbent's, so the GET that follows
/// judges any publication there.
pub(super) struct Attempt<'t> {
    pub(super) op: OpId,
    pub(super) id: RequestId,
    pub(super) name: u8,
    pub(super) label: Label,
    pub(super) object: Vec<u8>,
    pub(super) serial: Option<Serial>,
    pub(super) receipt: (u32, u32),
    /// Leading fragments recorded as received: the owner's receipt base for the attempt's serial at the last observation.
    pub(super) validated: u32,
    /// The owner's validations of the attempt's fill recorded as Fragment rows.
    fragments: usize,
    /// The client holds the owner's READY: its grant became nonzero.
    pub(super) ready: bool,
    pub(super) incumbent: bool,
    pub(super) published: bool,
    pub(super) slots: Vec<Option<Held>>,
    /// Each physical source slot's tenure count, shared by every
    /// attempt on the scene.
    pub(super) tenures: &'t mut [u64],
    pub(super) outcome: Option<UploadOutcome>,
}

/// One tenure counter per source slot of the scene's client.
pub(super) fn tenures(scene: &Scene<'_, '_>) -> Vec<u64> {
    vec![0; scene.clients[0].sources().len()]
}

impl<'t> Attempt<'t> {
    pub(super) fn begin(
        scene: &mut Scene<'_, '_>,
        rec: &mut Recorder,
        named: (u8, Label),
        len: u64,
        tenures: &'t mut [u64],
    ) -> Self {
        Self::begin_waiting(scene, rec, named, len, tenures, 30_000_000)
    }

    /// [`begin`](Self::begin) with the PUT's deadline `wait_us` away.
    pub(super) fn begin_waiting(
        scene: &mut Scene<'_, '_>,
        rec: &mut Recorder,
        (name, label): (u8, Label),
        len: u64,
        tenures: &'t mut [u64],
        wait_us: u64,
    ) -> Self {
        let key = KeyId(name);
        let object = Recorder::content(key, label, 0, len);
        let incumbent = bound(scene, name);
        scene.owner.track_put_validation();
        let op = rec.put_begin(key, label, 0, len);
        let id = upload(scene, name, &object, wait_us);
        let mut attempt = Self {
            op,
            id,
            name,
            label,
            object,
            serial: None,
            receipt: (0, 0),
            validated: 0,
            fragments: 0,
            ready: false,
            incumbent,
            published: false,
            slots: vec![None; tenures.len()],
            tenures,
            outcome: None,
        };
        attempt.observe(scene, rec);
        attempt
    }

    pub(super) fn key(&self) -> KeyId {
        KeyId(self.name)
    }

    /// The bytes of fragment `index` of the object.
    fn piece(&self, index: u32) -> &[u8] {
        let start = index as usize * FRAGMENT;
        &self.object[start..self.object.len().min(start + FRAGMENT)]
    }

    /// Supplies fragment `index` and records the source slot that took
    /// it.
    pub(super) fn supply(
        &mut self,
        scene: &mut Scene<'_, '_>,
        rec: &mut Recorder,
        index: u32,
    ) -> bool {
        if scene.clients[0]
            .supply(self.id, index, self.piece(index))
            .is_err()
        {
            return false;
        }
        for (slot, source) in scene.clients[0].sources().iter().enumerate() {
            if source.piece().is_some() && self.slots[slot].is_none() {
                self.tenures[slot] += 1;
                let held = Held {
                    fragment: index,
                    tenure: self.tenures[slot],
                    nic: false,
                    released: false,
                };
                self.slots[slot] = Some(held);
                let at = (slot as u32, held.tenure);
                rec.source(
                    self.op,
                    ActionKind::Take,
                    Custodian::Retransmission,
                    at,
                    index,
                );
            }
        }
        true
    }

    /// Cancels the attempt; the cancel ends every held slot's retention.
    pub(super) fn cancel(&mut self, scene: &mut Scene<'_, '_>, rec: &mut Recorder) {
        scene.clients[0].cancel(self.id);
        for (slot, held) in self.slots.iter().enumerate() {
            if let Some(held) = held.filter(|held| !held.released) {
                let at = (slot as u32, held.tenure);
                rec.source(
                    self.op,
                    ActionKind::Cancel,
                    Custodian::Owner,
                    at,
                    held.fragment,
                );
            }
        }
    }

    /// Records what changed since the last observation: the fill and
    /// authority once the client holds a serial, READY at the first grant,
    /// each fragment the owner newly validated, each later client receipt,
    /// the write completion and publication once the key is bound, the
    /// client's outcome once decided, and each source slot's NIC custody and
    /// retention changes. A fragment the owner validated below the last
    /// recorded grant precedes the client's new receipt, which may count it;
    /// a fragment at or past that grant follows the new receipt, which
    /// granted it. Both orders hold when at most one client poll ran since
    /// the last observation.
    ///
    /// # Panics
    ///
    /// When the key is bound before the client held any authority serial;
    /// when the owner's validation record, the volume's token record or the
    /// device capture overflowed; when a fragment at or past the last
    /// recorded grant lies below the base or at or past the grant of the
    /// receipt the client holds, as it can after several client polls; or
    /// when the census finds a gap between the device's capture and the
    /// recorded rows.
    pub(super) fn observe(&mut self, scene: &Scene<'_, '_>, rec: &mut Recorder) {
        let key = self.key();
        if let Some((serial, base, grant)) = scene.clients[0].put_receipt(self.id)
            && let Some(serial) = Serial::new(serial)
        {
            if self.serial.is_none() {
                let manifest = (0, self.object.len() as u64);
                rec.owner_fill(self.op, (key, self.label), manifest, (ID, serial));
                rec.put_authority(self.op, key, serial);
            }
            self.serial = Some(serial);
            if !self.ready && grant > 0 {
                self.ready = true;
                let manifest = (0, self.object.len() as u64);
                rec.put_ready(self.op, (key, self.label), manifest, serial, grant);
                self.receipt = (0, grant);
            }
            let fill = (self.name, serial);
            let (fragments, validated) = owner_validated(scene, fill, self.fragments);
            self.fragments += fragments.len();
            // A fragment at or past the last recorded grant follows the row
            // of the receipt that raised the grant.
            let granted = self.receipt.1;
            for &index in fragments.iter().filter(|&&index| index < granted) {
                rec.put_fragment(self.op, key, serial, index, self.piece(index));
            }
            if self.ready {
                for fragment in self.validated..validated {
                    rec.owner_received(self.op, (key, self.label), self.piece(fragment), serial);
                }
                self.validated = self.validated.max(validated);
            }
            if self.ready && (base, grant) != self.receipt {
                self.receipt = (base, grant);
                rec.put_receipt(self.op, key, serial, (base, grant));
            }
            for &index in fragments.iter().filter(|&&index| index >= granted) {
                assert!(
                    (base..grant).contains(&index),
                    "fragment {index} lies outside receipt base {base} and grant {grant}: \
                     more than one client poll ran since the last observation"
                );
                rec.put_fragment(self.op, key, serial, index, self.piece(index));
            }
        }
        if !self.incumbent && !self.published && bound(scene, self.name) {
            let serial = self
                .serial
                .expect("the authority named a serial before publication");
            let commands = written(scene, serial);
            rec.owner_written(self.op, (key, self.label), serial, commands);
            rec.owner_publish(self.op, (key, self.label), serial);
            self.published = true;
        }
        census(scene, rec);
        if self.outcome.is_none()
            && let Some(outcome) = scene.clients[0].put_outcome(self.id)
        {
            self.outcome = Some(outcome);
            rec.put_result(
                self.op,
                (key, self.label),
                self.serial,
                put_outcome(outcome),
            );
        }
        for (slot, source) in scene.clients[0].sources().iter().enumerate() {
            let Some(held) = self.slots[slot].as_mut() else {
                continue;
            };
            let at = (slot as u32, held.tenure);
            let device = source.device_held();
            if device != held.nic {
                let kind = if device {
                    ActionKind::Take
                } else {
                    ActionKind::Release
                };
                rec.source(self.op, kind, Custodian::Nic, at, held.fragment);
                held.nic = device;
            }
            if source.piece().is_none() && !held.released {
                held.released = true;
                let fragment = held.fragment;
                rec.source(
                    self.op,
                    ActionKind::Release,
                    Custodian::Retransmission,
                    at,
                    fragment,
                );
            }
            if held.released && !held.nic {
                self.slots[slot] = None;
            }
        }
    }

    /// Supplies every fragment and drives the scene, observing after
    /// every turn, until the client decides the attempt and every
    /// source slot returned.
    pub(super) fn run(&mut self, scene: &mut Scene<'_, '_>, rec: &mut Recorder, turns: u64) {
        let count = self.object.len().div_ceil(FRAGMENT) as u32;
        let mut next = 0;
        for _ in 0..turns {
            while next < count && self.supply(scene, rec, next) {
                next += 1;
            }
            drive(scene, 1);
            self.observe(scene, rec);
            if self.outcome.is_some() && self.slots.iter().all(Option::is_none) {
                break;
            }
        }
    }
}

/// A GET of `name` recorded as a lookup and, on a complete read, the
/// delivery of the bytes it returned under `label`.
pub(super) fn get(scene: &mut Scene<'_, '_>, rec: &mut Recorder, name: u8, label: Label) {
    let key = KeyId(name);
    let (outcome, bytes) = scene.read(1, name, 1 << 16);
    if outcome == Some(super::fetch::Outcome::Complete) {
        let read = rec.lookup(key, Outcome::Hit, Some(label));
        let body = bytes.len() as u64;
        rec.delivered(read, (key, label), (0, body), ID, Outcome::Complete, bytes);
    } else {
        rec.lookup(key, Outcome::Missing, None);
    }
}

/// The request share of owner incarnation `owner`.
pub(super) fn share(owner: u32) -> (ResourceKind, u32, u64) {
    (ResourceKind::RequestShare, owner, 0)
}

/// The owner storage's last clock sample, in whole seconds.
pub(super) fn clock(storage: &Storage<TestPlatform>) -> ClockSample {
    last_sample(storage).map_or(ClockSample::Unavailable, |now| {
        ClockSample::Seconds(now / NANOS_PER_SECOND)
    })
}

/// Reports the owners' live requests as the request-share count.
pub(super) fn shares(rec: &mut Recorder, owners: &[&TestOwner<'_, '_, '_>]) {
    let live: u32 = owners.iter().map(|owner| owner.census().live()).sum();
    rec.report(
        ResourceKind::RequestShare,
        ReportKind::RequestShares,
        ReportState::Value(u64::from(live)),
    );
}

/// Records a hit of `key` at `label` and the delivery of `bytes`, the whole object.
pub(super) fn served(
    rec: &mut Recorder,
    storage: &Storage<TestPlatform>,
    (key, label): (KeyId, Label),
    bytes: Vec<u8>,
) -> OpId {
    let read = rec.lookup_at(key, Outcome::Hit, Some(label), Some(clock(storage)));
    let body = bytes.len() as u64;
    rec.delivered(read, (key, label), (0, body), ID, Outcome::Complete, bytes);
    read
}

/// # Panics
///
/// When `put_validated` reports a missed validation, which leaves the owner's evidence incomplete.
pub(super) fn owner_validated(
    scene: &Scene<'_, '_>,
    (name, serial): (u8, Serial),
    seen: usize,
) -> (Vec<u32>, u32) {
    let (validations, overflow) = scene.owner.put_validated();
    assert!(
        !overflow,
        "the owner's validation record missed a fragment; its evidence is incomplete"
    );
    let fill = (super::owner_tests::key(name), serial.0.get());
    let (mut unseen, mut base) = (Vec::new(), 0);
    let ours = validations.iter().filter(|v| (v.key, v.serial) == fill);
    for (at, validation) in ours.enumerate() {
        base = validation.base;
        if at >= seen {
            unseen.push(validation.index);
        }
    }
    (unseen, base)
}

/// The device's capture in the oracle's terms.
pub(super) fn boundary(capture: &Capture) -> Vec<BoundaryEvent> {
    let mut lengths: Vec<(CommandToken, u32)> = Vec::new();
    capture
        .events
        .iter()
        .map(|event| match *event {
            Captured::Submitted {
                token,
                operation,
                device,
                ordinal,
                ..
            } => {
                lengths.push((token, device.byte_len()));
                BoundaryEvent::Submitted {
                    token: token.raw(),
                    write: operation == Operation::Write,
                    start: device.start(),
                    len: device.byte_len(),
                    ordinal,
                }
            }
            Captured::Delivered { token, status } => {
                // A terminal succeeds only when it moved the command's whole length; a short transfer is a failure.
                let len = lengths
                    .iter()
                    .rev()
                    .find(|(t, _)| *t == token)
                    .map_or(0, |&(_, len)| len);
                BoundaryEvent::Delivered {
                    token: token.raw(),
                    success: status.classify(len) == Classification::Success,
                }
            }
        })
        .collect()
}

/// The write commands the device accepted for the attempt the owner names `serial`, from the device's capture and the
/// volume's token bindings, each with the terminal the device has delivered for it so far.
pub(super) fn written(scene: &Scene<'_, '_>, serial: Serial) -> Vec<CommandEvidence> {
    written_commands(
        scene.owner.volume_bound(),
        &scene.control.capture(),
        serial.0.get(),
    )
}

/// [`written`] over a volume's token bindings, with their overflow flag, and its device's capture.
///
/// # Panics
///
/// Panics when the volume's token record exceeds its capacity or the device capture exceeds its bound.
pub(super) fn written_commands(
    (bound, overflow): (&[(CommandToken, Bound)], bool),
    capture: &Capture,
    serial: u64,
) -> Vec<CommandEvidence> {
    assert!(
        !overflow,
        "the volume's token record overflowed its room; its evidence is incomplete"
    );
    assert!(
        !capture.overflow,
        "the device capture overflowed its bound; its evidence is incomplete"
    );
    let mut commands: Vec<CommandEvidence> = Vec::new();
    for event in &boundary(capture) {
        match *event {
            BoundaryEvent::Submitted {
                token,
                write: true,
                start,
                len,
                ordinal,
            } => {
                let ours = bound.iter().any(|&(bound_token, owner)| {
                    bound_token.raw() == token
                        && matches!(owner, Bound::Write { serial: s, .. } if s == serial)
                });
                if ours {
                    commands.push(CommandEvidence {
                        token,
                        start,
                        len,
                        ordinal,
                        delivered: None,
                    });
                }
            }
            BoundaryEvent::Delivered { token, success } => {
                if let Some(command) = commands
                    .iter_mut()
                    .rev()
                    .find(|c| c.token == token && c.delivered.is_none())
                {
                    command.delivered = Some(success);
                }
            }
            BoundaryEvent::Submitted { .. } => {}
        }
    }
    commands
}

/// The write evidence of each fill whose serial bound a write command through `owner`'s volume, in the order those
/// serials first bound one: the commands of each serial with their delivered terminals.
pub(super) fn fills_written(
    owner: &TestOwner<'_, '_, '_>,
    control: &SimControl,
) -> Vec<Vec<CommandEvidence>> {
    fills_written_in(owner.volume_bound(), control)
}

/// [`fills_written`] over a volume's token bindings, with their overflow flag.
pub(crate) fn fills_written_in(
    (bound, overflow): (&[(CommandToken, Bound)], bool),
    control: &SimControl,
) -> Vec<Vec<CommandEvidence>> {
    let mut serials: Vec<u64> = Vec::new();
    for (_, owner) in bound {
        if let Bound::Write { serial, .. } = *owner
            && !serials.contains(&serial)
        {
            serials.push(serial);
        }
    }
    let capture = control.capture();
    serials
        .into_iter()
        .map(|serial| written_commands((bound, overflow), &capture, serial))
        .collect()
}

/// Reconciles the device's capture with the recorded rows.
///
/// # Panics
///
/// On a gap the census names: an overflowed capture, an ordinal gap, an accepted count other than the device's, a token
/// accepted while outstanding or delivered with no outstanding command, or a recorded command that is no captured write,
/// is bound to another serial, or carries a terminal the capture did not deliver.
pub(super) fn census(scene: &Scene<'_, '_>, rec: &Recorder) {
    let capture = scene.control.capture();
    let bindings = write_bindings(scene.owner.volume_bound());
    if let Err(gap) = crate::oracle::census(
        &boundary(&capture),
        (capture.overflow, capture.accepted),
        &bindings,
        rec.rows(),
    ) {
        panic!("device-boundary census: {gap}");
    }
}

/// Each write token the volume bound with its fill's serial, as the census reads them. The volume's metadata
/// commands, its root blocks, suffix blocks and checkpoint units, take the serial `u64::MAX`, which lies past every
/// serial a fill draws, so the census sees every captured write bound once.
pub(super) fn write_bindings((bound, _): (&[(CommandToken, Bound)], bool)) -> Vec<(u64, u64)> {
    bound
        .iter()
        .filter_map(|&(token, owner)| match owner {
            Bound::Write { serial, .. } => Some((token.raw(), serial)),
            Bound::Metadata { .. } => Some((token.raw(), u64::MAX)),
            Bound::Read { .. } => None,
        })
        .collect()
}

pub(super) fn bound(scene: &Scene<'_, '_>, name: u8) -> bool {
    binding(scene, name).is_some()
}

pub(super) fn binding(scene: &Scene<'_, '_>, name: u8) -> Option<Binding> {
    let (mut bindings, mut facts, mut buffer) = (Vec::new(), Vec::new(), Vec::new());
    let media = scene.media();
    let storage = media.storage();
    storage.bindings_into(&mut bindings).ok()?;
    storage.slot_facts_into(&mut facts).ok()?;
    let wanted = super::owner_tests::key(name);
    bindings.into_iter().find(|&binding| {
        media
            .bound_record(binding, &facts, &mut buffer)
            .is_ok_and(|(key, _, _)| key == wanted)
    })
}

/// The length of an upload of three fragments, the last one short.
pub(super) const LEN: u64 = 3 * FRAGMENT as u64 - 100;

/// Uploads a fresh object under key `name` and label `name` through the
/// uploading client until it publishes, recording into `rec`, and returns
/// the object.
pub(super) fn upload_published(scene: &mut Scene<'_, '_>, rec: &mut Recorder, name: u8) -> Vec<u8> {
    let mut slots = tenures(scene);
    let mut attempt = Attempt::begin(scene, rec, (name, Label(name.into())), LEN, &mut slots);
    attempt.run(scene, rec, 600);
    assert_eq!(attempt.outcome, Some(UploadOutcome::Published));
    attempt.object.clone()
}
