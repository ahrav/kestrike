//! Off-volume store records: the shard record, the volume record and the coverage page, each with its codec and the
//! fields a successor value must keep.
//!
//! Every value is big-endian at a fixed offset behind a 4-byte magic and a 2-byte format version. A decoder accepts
//! exactly the encodings its encoder produces: the length, the magic, the version, every flag byte and every typed
//! field are checked, and the bytes of an absent part are zero. The volume and shard decoders accept formats 2 and
//! 3. Each later format's decoder accepts every earlier format a retained record may hold. Deploy all readers of a
//! new format before its first writer so every retained record stays readable. A version-1 reader rejects format-2
//! and format-3 records at its length check. Shard format 3 is format 2 followed by the standby host, and the encoder
//! writes it only for a record that names a standby, so a format-2 reader reads every record without one.
//!
//! The volume record tracks the next unused attachment-event sequence number across the volume's lifetime. Format 2
//! stores the first retained number, numbers the rest consecutively, and holds attach, detach and force-detach
//! events without an instance. Format 3 stores each event's number, kind (including ended and gone), and bound
//! instance, if any. Format 2 expresses an empty event list, and a nonempty one whose numbers are consecutive and
//! end at the next number minus one and whose events are attach, detach or force-detach events without an instance.
//! The encoder writes format 2 for every such record and format 3 for any other: a numbering gap between retained
//! numbers or after the last one, an ended or gone entry, or a bound instance. The format-3 decoder answers format-3
//! bytes of a record format 2 expresses with [`CodecError::Version`], so each record has one encoding, and a
//! format-2 reader reads every record format 2 expresses.
//!
//! Invariants owned here:
//!
//! - SUCCESSOR-RULES: a shard record keeps its shard, page count `B`, page cap `C_page` and store namespace from
//!   creation; a replacement keeps `(g, active volume, owner, E)` and the standby, which only the flip, the `E` bump,
//!   the takeover, the planned transfer and the designation change, the flip, the takeover and the planned transfer
//!   clearing the standby and the designation naming one,
//!   changes the named checkpoint and its cut only to a checkpoint with a strictly later `(session, capture)` and a
//!   cut not lower, and drops from its ancestry only the leading suffixes that end at or below the new cut. Every
//!   kept suffix keeps its session, start and end and raises only its certified end; only a last kept suffix of the
//!   record's current session `g·2^32 + 2E` extends its end, and an appended suffix is of the current session and
//!   lies after every prior suffix, or continues a dropped suffix of that session from its end, and starts at or
//!   after the prior cut when the prior record holds no suffix. A deposed tenure
//!   therefore adds no journal range to the replay its successor runs. A volume record keeps its volume, creation
//!   source, lineage and layout `(M, K, S, N_max)` and keeps or raises its next sequence number. Its events stay in
//!   increasing number order, and new events take the next numbers in order, each an attach, detach or force-detach.
//!   A retained event keeps its number, host, era and instance, except that an attach without an instance that
//!   stays its host's live attach may take one (BIND-AT-ATTACH); its kind moves forward only, from attach to ended,
//!   and from ended to gone once the prior record holds the entry with its pair dropped. A gone event may leave from
//!   any position. The record may also drop a prefix of unbound attach, detach or force-detach events. Each live
//!   attach of the successor is new or was live in the prior record. When format 2 expresses both records, these are
//!   the only event rules. Otherwise every attach live in the prior record stays its host's live attach or ends in
//!   place, and a force mark the prior record lacks arrives with a new force-detach. The record keeps its force mark
//!   and modification record, keeps its state or
//!   moves it forward and keeps or raises its fence. It drops a recorded pair under a fence raise or when the prior
//!   record marks the pair's attachment as ended, so a pair whose entry ends in the dropping write needs a raise,
//!   and one tenure may drop several ended pairs under one fence. A pair pinning an ended entry is one the prior
//!   record holds. When the prior record or the successor needs format 3, each pair the successor adds pins the live
//!   attach of its host, with or without a fence raise.
//!   Under an unchanged fence each new pair has an EXHID and a key distinct from those of every pair
//!   the write drops. The record check reads records only: under a raise the rule admits any drop, so a fence writer
//!   drops only the pairs whose attempts its fence ended. An owner drops only an ended attachment's pair, only
//!   after a Report shows that pair's key absent, under the fence the record holds ([`VolumeRecord::dropped`]), so
//!   the record check judges the owner's drop by the ended entries and keeps every live attach's pair. A coverage
//!   page keeps or raises its fence.
//!   The pair-identity rule compares consecutive records. Once a write drops a pair, a later write may add its
//!   EXHID and key again under the same fence; [`VolumeRecord::enroll`] admits that key only on the attach it
//!   derives from (KEY-PER-ATTACH).
//!   [`Record::succeeds`] refuses any other successor.
//! - KEY-PER-ATTACH: the reservation key of the attach entry numbered `n` is epoch 1 and incarnation `n + 1`
//!   ([`attachment_key`]). The volume assigns each event a unique sequence number, so distinct attach entries derive
//!   distinct keys. [`VolumeRecord::enroll`] admits a new pair only under the key of its host's live attach; a recorded
//!   pair under another key stays readable and replays.
//!   If a retained pair holds a later entry's epoch-1 key, [`VolumeRecord::enroll`] refuses the later entry
//!   `Shared` while the pair is recorded and admits it once a write drops the pair.
//! - A shard record's spare is a volume other than its active volume, and its standby a host other than its owner.
//! - The attempt counter `E` stays at or below [`ATTEMPTS_MAX`], so the activated epoch `2E` fits its type.
//! - BOUNDED-MANIFEST: a shard record's cut is zero without a checkpoint and at most `LSN_LIMIT + 1`, one past
//!   [`LSN_LIMIT`], the last LSN a journal issues. Its ancestry holds at most [`MAX_CHAIN`] suffixes, each of an
//!   activated session `(g, a)` with `2 <= a <= 2E`, a nonempty range `[start, end)` with `end` at most
//!   `LSN_LIMIT + 1` and a certified end in `start..=end`, in increasing session order over disjoint ascending LSN
//!   ranges, the first ending above the cut. A volume record holds at most [`MAX_REGISTRANTS`] distinct recorded
//!   pairs, each naming a retained attach or ended entry of its host, at most [`MAX_EVENTS`] events, each of era
//!   [`MIN_ERA`] or later, numbered in increasing order below the next sequence number, with an instance only on an
//!   attach, ended or gone entry, and a fence that is zero or an activated session. The encoded shard record
//!   occupies at most [`SHARD_MAX`] bytes and the encoded volume record at most [`VOLUME_MAX`] bytes.
//! - PREFIX-FLOOR: a layout [`Layout::check_floor`] admits records at least [`MIN_SLOTS`] slots of exactly
//!   `1 + ⌈N_max / q⌉` units and a prefix of at least `1 + K·S` units.

use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use crate::failover::attachments::{INSTANCE_FIELD, InstanceId};
use crate::failover::bounds::Bounds;
use crate::failover::evidence::Pair;
use crate::failover::identity::{
    Exhid, Incarnation, Key, MAX_VOLUME_LEN, is_volume, is_volume_field,
};
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration, session_of};
use crate::storage::LSN_LIMIT;

/// The largest attempt counter `E`, `2^31 - 2`, whose activated epoch `2E` is `ActivatedEpoch::MAX`.
pub const ATTEMPTS_MAX: u32 = (1 << 31) - 2;

/// The most attachment events a volume record holds.
pub const MAX_EVENTS: usize = 16;

/// The most suffixes a shard record's ancestry holds.
pub const MAX_CHAIN: usize = 4;

pub use crate::failover::bounds::MAX_REGISTRANTS;

/// The most hosts with a live attach that the owner's poll and restart admit on an active volume: the owner and two
/// standbys.
pub const MAX_ATTACHED: usize = 3;

const _: () = assert!(MAX_ATTACHED <= MAX_REGISTRANTS);

/// The binary era this build records for its own attachment events.
pub const ERA: u32 = 2;

/// The oldest binary era whose attachment events a volume record holds; an event of an earlier era refuses to
/// decode. [`ERA`] rises without a format change. Raising this floor makes every retained record that holds an
/// event below it unreadable, so it is a format change under the readers-first rule.
pub const MIN_ERA: u32 = 2;

const _: () = assert!(ERA >= MIN_ERA);
const _: () = assert!(2 * ATTEMPTS_MAX == ActivatedEpoch::MAX);
// Each cap fits the one-byte count that encodes it.
const _: () = assert!(MAX_CHAIN <= u8::MAX as usize);
const _: () = assert!(MAX_REGISTRANTS <= u8::MAX as usize);
const _: () = assert!(MAX_EVENTS <= u8::MAX as usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// The value is shorter or longer than its layout, or holds more events, pairs or suffixes than its cap.
    Length,
    Magic,
    Version,
    /// A flag or enumeration byte outside its values, or nonzero bytes of an absent part.
    Flag,
    /// A zero shard, generation, host, page count, cap or namespace, `E` above [`ATTEMPTS_MAX`], a spare equal to
    /// the active volume, a standby equal to the owner, a volume name outside the canonical grammar, a cut without a checkpoint or above
    /// `LSN_LIMIT + 1`, an ancestry outside BOUNDED-MANIFEST, or a volume record's event, pair, fence or force mark
    /// outside its rules.
    Field,
    /// The value's digest does not match its body.
    Checksum,
}

/// The successor rule a value broke: an immutable field it changed, a field it changed that only the flip, the `E`
/// bump, the takeover, the planned transfer or the designation changes, or a field it moved backward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuccessorRule {
    /// The shard or volume the record names.
    Identity,
    Pages,
    PageCap,
    Source,
    Lineage,
    Layout,
    /// The write breaks a volume-record event rule of SUCCESSOR-RULES in the module documentation: event order and
    /// numbering, kind transitions for retained events (attach to ended or ended to gone), event removal, liveness
    /// of retained attaches, or the force mark.
    Events,
    /// The state moved backward.
    State,
    Modification,
    Fence,
    Saturation,
    /// The shard record's `(g, active volume, owner, E)` or standby, which only the flip, the `E` bump, the takeover,
    /// the planned transfer and the designation change.
    Tenure,
    /// The named checkpoint or its cut was cleared or moved without a strictly later `(session, capture)`, or the
    /// cut was lowered.
    Checkpoint,
    /// The store namespace changed.
    Namespace,
    /// The ancestry broke the shard rule of SUCCESSOR-RULES: a suffix ending above the new cut keeps its session,
    /// start and end and may raise its certified end. The last kept suffix may extend its end when its session is
    /// the current one. At most one suffix is appended: it is of the current session, ends above the new cut and
    /// starts at or after the end of every prior suffix, or at or after the prior cut when the prior record holds no
    /// suffix, with a session above every prior suffix or, after a cut that drops every prior suffix, the last one's
    /// session.
    Ancestry,
    /// The write drops or changes a recorded pair while the fence stays unchanged and the prior record marks the
    /// pair's entry as live, pins an ended entry with a pair outside the prior record, or, under an unchanged fence,
    /// gives a new pair the EXHID or key of a pair it drops. When the prior record or the successor needs format 3,
    /// the rule also requires each added pair to pin its host's live attach, with or without a fence raise.
    Pairs,
}

/// A store record kind: its codec and the successor rule every conditional write of it obeys.
pub trait Record: Sized {
    fn encode(&self) -> Vec<u8>;

    /// # Errors
    ///
    /// The first failing check in the order length, magic, version, then fields in layout order. The length check
    /// includes the counts that set a variable record's length; the fixed-length shard record checks its ancestry
    /// count with its fields. After all field checks pass, `decode` returns `Version` for a format-3 volume record
    /// when format 2 expresses the record, since its one encoding is format 2.
    fn decode(bytes: &[u8]) -> Result<Self, CodecError>;

    /// Refuses `self` as the next value of a record holding `prior`, naming the first successor rule it breaks.
    fn succeeds(&self, prior: &Self) -> Result<(), SuccessorRule>;
}

/// A fleet host the records name: the host's fleet number, distinct from the NVMe host identifier it draws per
/// attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Host(NonZeroU64);

impl Host {
    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// A canonical volume name, `vol-` and 1 to 17 lowercase hexadecimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VolumeId {
    len: u8,
    name: [u8; MAX_VOLUME_LEN],
}

impl VolumeId {
    pub fn new(name: &str) -> Option<Self> {
        if !is_volume(name) {
            return None;
        }
        let mut bytes = [0; MAX_VOLUME_LEN];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Some(Self {
            len: name.len() as u8,
            name: bytes,
        })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.len)]).unwrap_or_default()
    }

    pub(crate) fn field(&self) -> [u8; VOLUME] {
        let mut field = [0; VOLUME];
        field[0] = self.len;
        field[1..].copy_from_slice(&self.name);
        field
    }

    /// The volume whose canonical [`field`](Self::field) equals `field`: a volume name of `field[0]` bytes, then
    /// zero bytes.
    #[inline]
    pub(crate) fn from_field(field: &[u8; VOLUME]) -> Option<Self> {
        let [len, name @ ..] = *field;
        is_volume_field(len, &name).then_some(Self { len, name })
    }
}

/// The checkpoint the store names for recovery: its slot, the capturing session `s`, the capture number `c` and
/// the unit count `n`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NamedCheckpoint {
    pub slot: u32,
    pub session: u64,
    pub capture: u32,
    pub units: u32,
}

/// The identity of the store instance that holds a shard record. A store reports its own, and the client refuses a
/// shard record that names another, so a record restored into or read from another table admits no write. The
/// all-zero value refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Namespace([u8; 16]);

impl Namespace {
    pub const fn new(bytes: [u8; 16]) -> Option<Self> {
        match u128::from_ne_bytes(bytes) {
            0 => None,
            _ => Some(Self(bytes)),
        }
    }

    pub fn bytes(self) -> [u8; 16] {
        self.0
    }
}

/// One tenure's certified journal suffix: the tenure's session `g·2^32 + a`, the LSN range `[start, end)` its
/// journal records occupy, and the certified end `certified` in `start..=end` that replay of the suffix must reach.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Suffix {
    pub session: u64,
    pub start: u64,
    pub certified: u64,
    pub end: u64,
}

/// The suffixes a recovery replays after the named checkpoint's cut, oldest first, at most [`MAX_CHAIN`]. The
/// entries past the length are zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Ancestry {
    len: u8,
    suffixes: [Suffix; MAX_CHAIN],
}

impl Ancestry {
    /// The ancestry of `suffixes`, or `None` for more than [`MAX_CHAIN`].
    pub fn new(suffixes: &[Suffix]) -> Option<Self> {
        let mut chain = Self::default();
        chain
            .suffixes
            .get_mut(..suffixes.len())?
            .copy_from_slice(suffixes);
        chain.len = suffixes.len() as u8;
        Some(chain)
    }

    pub fn as_slice(&self) -> &[Suffix] {
        &self.suffixes[..usize::from(self.len)]
    }

    /// Whether `self` is an ancestry SUCCESSOR-RULES admits after `prior` under the new cut `cut`, for a record whose
    /// current session is `current` and whose prior cut is `floor`. The suffixes of `prior` ending at or below `cut`
    /// are dropped; the rest are kept and lead `self`, and at most one suffix of `self` follows them, since every
    /// appended suffix is of `current` and sessions rise strictly. That suffix is of `current`, ends above `cut` and
    /// starts at or after the end of the last kept suffix of `self`, of the last suffix of `prior` when the cut drops
    /// every one, or at or after `floor` when `prior` holds none. The decoder checks the order within each chain
    /// (BOUNDED-MANIFEST).
    fn extends(&self, prior: &Self, cut: u64, floor: u64, current: u64) -> bool {
        let prior = prior.as_slice();
        let kept = &prior[prior.iter().take_while(|suffix| suffix.end <= cut).count()..];
        let Some((retained, appended)) = self.as_slice().split_at_checked(kept.len()) else {
            return false;
        };
        let last = kept.len().checked_sub(1);
        let kept_whole = retained
            .iter()
            .zip(kept)
            .enumerate()
            .all(|(at, (new, old))| {
                let extended = Some(at) == last && new.session == current && new.end > old.end;
                (new.session, new.start) == (old.session, old.start)
                    && new.certified >= old.certified
                    && (new.end == old.end || extended)
            });
        let top = retained.last().or(prior.last());
        let after = |suffix: &Suffix| {
            suffix.start >= top.map_or(floor, |top| top.end)
                && top.is_none_or(|top| {
                    suffix.session > top.session
                        || (kept.is_empty() && suffix.session == top.session)
                })
        };
        kept_whole
            && appended.len() <= 1
            && appended
                .iter()
                .all(|suffix| suffix.session == current && suffix.end > cut && after(suffix))
    }
}

/// One shard's record, the shard's one conditional-write unit: the generation `g` of the active volume, the active
/// volume and its owner, the attempt counter `E`, the spare and its host, the named checkpoint `ck` with the journal
/// LSN `cut` where its replay starts, the page count `B` and cap `C_page` fixed at creation, the namespace of the
/// store that holds it, the ancestry of certified suffixes after the cut, and the one standby host whose takeover
/// compare-and-swap the record admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardRecord {
    pub shard: Shard,
    pub generation: ShardGeneration,
    pub active: VolumeId,
    pub owner: Host,
    pub attempts: u32,
    pub spare: Option<(VolumeId, Host)>,
    pub checkpoint: Option<NamedCheckpoint>,
    /// Zero when `checkpoint` is absent.
    pub cut: u64,
    pub pages: NonZeroU16,
    pub page_cap: NonZeroU32,
    pub namespace: Namespace,
    pub ancestry: Ancestry,
    pub standby: Option<Host>,
}

/// A volume's lifecycle state, in the order a volume moves through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VolumeState {
    Provisioning,
    Fresh,
    Active,
    Retired,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreationSource {
    /// The cache's provisioning path, with a new volume ID.
    Provisioned,
    /// Any other creation; the fresh path refuses it.
    Foreign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lineage {
    None,
    Snapshot,
    Clone,
}

/// A write appends an attach, a detach or a force-detach. An attach entry then advances to ended and from ended to
/// gone, keeping its number, host, era and instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Attach,
    Detach,
    Force,
    /// Marks the end of the host's live attach. A recorded pair can still pin the entry until the record drops the
    /// pair.
    Ended,
    /// Records an ended entry as released; the entry may leave the record from any position.
    Gone,
}

impl EventKind {
    fn attachment(self) -> bool {
        matches!(self, Self::Attach | Self::Ended | Self::Gone)
    }

    /// Whether an entry of this kind admits its host's listed attachment: an attach or an ended entry. A gone entry
    /// admits none (ENDED-GRANTS-NOTHING).
    fn listed(self) -> bool {
        matches!(self, Self::Attach | Self::Ended)
    }
}

/// The era identifies the host's binary era. An attach, ended or gone entry may bind an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentEvent {
    /// The event's number in the volume's lifetime sequence, assigned once.
    pub seq: u32,
    pub kind: EventKind,
    pub host: Host,
    pub era: u32,
    /// The instance an attach, ended or gone entry binds.
    pub instance: Option<InstanceId>,
}

/// One registrant of the volume's lineage that may still hold write attempts: its host, the (EXHID, reservation
/// key) pair it registered, and `attach`, the sequence number of its host's retained attach or ended entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedPair {
    pub host: Host,
    pub pair: Pair,
    pub attach: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modification {
    InProgress,
    Completed,
}

/// How [`VolumeRecord::registrant`] classes a Report's registrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// The record holds the pair, pinning a retained attach of its host, live or marked by a later format-2 detach or
    /// force detach, or an ended entry.
    Recorded,
    /// The record holds no such pair, and its key is the key of an entry that is no host's live attach.
    Ended,
    /// Neither: a foreign registrant.
    Unknown,
}

/// Why [`VolumeRecord::enroll`] refuses a pair, in refusal order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enrollment {
    /// Enrollment requires a fresh or active volume.
    State,
    /// Enrollment requires the host's latest retained event to be an attach.
    Unattached,
    /// Another pair is enrolled for the host's live attach.
    Altered,
    /// The pair's key is not the key of the host's live attach ([`VolumeRecord::attach_key`]).
    Key,
    /// A recorded pair carries the same host ID or the same key.
    Shared,
    /// The record holds [`MAX_REGISTRANTS`] pairs, or `N_reg` pairs under a smaller bound.
    Full,
}

/// The volume's prefix layout: `M` metadata units, `K` checkpoint slots of `S` units, and the entry cap `N_max`.
/// Unit 0 holds the activation record, units `1 + k·S` to `(k + 1)·S` hold slot `k`, and the payload follows the
/// `M` units. [`Layout::check_floor`] admits a layout whose prefix holds every slot at its entry cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub units: u64,
    pub slots: u32,
    pub slot_units: u32,
    pub entries: u32,
}

/// The bytes a checkpoint unit spends on its own header before its entries.
pub(crate) const UNIT_OVERHEAD: usize = 128;

/// The bytes of one checkpoint entry.
pub(crate) const ENTRY_BYTES: usize = 96;

/// The checkpoint entries one 4 KiB unit holds after its header: `q = (4096 - 128) / 96 = 41`.
pub const UNIT_ENTRIES: u64 = ((crate::storage::IO_UNIT - UNIT_OVERHEAD) / ENTRY_BYTES) as u64;

const _: () = assert!(UNIT_ENTRIES == 41);

pub const MIN_SLOTS: u64 = 3;

/// Why [`Layout::check_floor`] refuses a recorded layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutRefusal {
    /// `K` is below [`MIN_SLOTS`].
    TooFewSlots { slots: u32 },
    /// `S` differs from the `1 + ⌈N_max / q⌉` units the entry cap requires.
    SlotUnits { recorded: u32, required: u64 },
    /// `M` is below the floor `1 + K·S`.
    BelowFloor { units: u64, floor: u64 },
}

/// The units `S = 1 + ⌈entries / q⌉` of a slot that holds `entries` checkpoint entries.
pub fn slot_units(entries: u64) -> u64 {
    entries.div_ceil(UNIT_ENTRIES) + 1
}

/// The prefix floor `1 + K·S` of `slots` slots, each sized by [`slot_units`] for `entries`, or `None` when it
/// exceeds `u64`. This is the arithmetic alone; [`Layout::check_floor`] also bounds `K` and requires `S` exactly.
pub fn prefix_floor(slots: u64, entries: u64) -> Option<u64> {
    slotted(slots, slot_units(entries))
}

/// `1 + slots·units`, or `None` when it exceeds `u64`.
fn slotted(slots: u64, units: u64) -> Option<u64> {
    slots.checked_mul(units)?.checked_add(1)
}

/// Counts prefix units available for delta blocks after unit 0 and the checkpoint slots. Returns zero when these
/// reservations fill or exceed the prefix.
pub fn delta_blocks(layout: &Layout) -> u64 {
    let slots = u64::from(layout.slots) * u64::from(layout.slot_units);
    layout.units.saturating_sub(1 + slots)
}

impl Layout {
    /// The prefix unit `1 + slot·S + unit` of unit `unit` of slot `slot`; `None` past the slots or the slot's units.
    pub fn prefix_unit(&self, slot: u32, unit: u32) -> Option<u64> {
        (slot < self.slots && unit < self.slot_units)
            .then(|| 1 + u64::from(slot) * u64::from(self.slot_units) + u64::from(unit))
    }

    /// Admits the layout when `K >= MIN_SLOTS`, `S` equals [`slot_units`] of `N_max`, and `M >= 1 + K·S`.
    ///
    /// # Errors
    ///
    /// [`LayoutRefusal::TooFewSlots`], then [`LayoutRefusal::SlotUnits`], then [`LayoutRefusal::BelowFloor`].
    pub fn check_floor(&self) -> Result<(), LayoutRefusal> {
        if u64::from(self.slots) < MIN_SLOTS {
            return Err(LayoutRefusal::TooFewSlots { slots: self.slots });
        }
        let required = slot_units(u64::from(self.entries));
        if u64::from(self.slot_units) != required {
            return Err(LayoutRefusal::SlotUnits {
                recorded: self.slot_units,
                required,
            });
        }
        let floor = slotted(u64::from(self.slots), required)
            .expect("K < 2^32 and S < 2^27 for u32 fields, so 1 + K·S < 2^59");
        if self.units < floor {
            return Err(LayoutRefusal::BelowFloor {
                units: self.units,
                floor,
            });
        }
        Ok(())
    }
}

/// Each volume numbers its events from zero; the record keeps a subset in increasing order, each numbered below
/// `next`, and every recorded pair pins a retained attach or ended entry of its own host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRecord {
    pub volume: VolumeId,
    pub state: VolumeState,
    pub source: CreationSource,
    pub lineage: Lineage,
    pub modification: Option<Modification>,
    pub layout: Layout,
    /// The sequence number the volume's next event takes.
    pub next: u32,
    /// Whether the volume's life holds a force-detach event, compacted ones included.
    pub forced: bool,
    /// The session of the last fence that ended the attempts of every pair it removed: zero before any fence, and
    /// otherwise an activated session `g·2^32 + a` with `g >= 1` and `a` an even epoch from 2 to
    /// `ActivatedEpoch::MAX`. The owner's drop of ended pairs keeps it ([`VolumeRecord::dropped`]).
    pub fence: u64,
    /// At most [`MAX_REGISTRANTS`].
    pub pairs: Vec<RecordedPair>,
    /// Oldest first; a record with more than [`MAX_EVENTS`] encodes bytes that refuse to decode.
    pub events: Vec<AttachmentEvent>,
}

/// One coverage page `(fence, entries, sat)`; the store's version is its `ver`. The entry bytes belong to the
/// coverage codec and are opaque here. The default is the empty page a shard starts with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoveragePage {
    pub fence: u64,
    pub saturated: bool,
    pub entries: Vec<u8>,
}

const SHARD_VERSION: u16 = 2;
const STANDBY_VERSION: u16 = 3;
const VOLUME_VERSION: u16 = 2;
const ENTRY_VERSION: u16 = 3;
const PAGE_VERSION: u16 = 1;
const HEAD: usize = 6;
pub(crate) const VOLUME: usize = 1 + MAX_VOLUME_LEN;
/// A named checkpoint's bytes after its flag.
pub(crate) const CHECKPOINT: usize = 20;
const SUFFIX: usize = 32;
const ANCESTRY: usize = 1 + SUFFIX * MAX_CHAIN;
/// A format-2 shard record's encoded length, 259 bytes.
pub const SHARD_LEN: usize =
    HEAD + 8 + VOLUME + 12 + 1 + VOLUME + 8 + 1 + CHECKPOINT + 8 + 6 + 16 + ANCESTRY;
/// A format-3 shard record's encoded length, 267 bytes: format 2 and the standby host.
pub const SHARD_MAX: usize = SHARD_LEN + 8;
const VOLUME_FIXED: usize = HEAD + VOLUME + 4 + 20 + 15;
const PAIR: usize = 36;
const EVENT: usize = 13;
const ENTRY: usize = 4 + EVENT + INSTANCE_FIELD;
/// A volume record's longest encoding: format 3 at [`MAX_REGISTRANTS`] pairs and [`MAX_EVENTS`] events.
pub const VOLUME_MAX: usize = VOLUME_FIXED + PAIR * MAX_REGISTRANTS + ENTRY * MAX_EVENTS;

const _: () =
    assert!(VOLUME_MAX == 947 && VOLUME_FIXED + PAIR * MAX_REGISTRANTS + EVENT * MAX_EVENTS == 563);
const PAGE_FIXED: usize = HEAD + 13;

/// A big-endian reader over one record value.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    /// Checks the magic and the format version.
    pub(crate) fn open(bytes: &'a [u8], magic: &[u8; 4], version: u16) -> Result<Self, CodecError> {
        let mut r = Self(bytes);
        if &r.take::<4>()? != magic {
            return Err(CodecError::Magic);
        }
        (r.u16()? == version)
            .then_some(r)
            .ok_or(CodecError::Version)
    }

    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.field().copied()
    }

    fn field<const N: usize>(&mut self) -> Result<&'a [u8; N], CodecError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(CodecError::Length)?;
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, CodecError> {
        self.take().map(u16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, CodecError> {
        self.take().map(u32::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        self.take().map(u64::from_be_bytes)
    }

    #[inline(always)]
    pub(crate) fn host(&mut self) -> Result<Host, CodecError> {
        Host::new(self.u64()?).ok_or(CodecError::Field)
    }

    #[inline(always)]
    fn volume(&mut self) -> Result<(VolumeId, &'a [u8; VOLUME]), CodecError> {
        let field = self.field::<VOLUME>()?;
        let volume = VolumeId::from_field(field).ok_or(CodecError::Field)?;
        Ok((volume, field))
    }

    /// The spare and its host after their flag, or `None` for a clear flag and zero bytes. A present spare has a
    /// canonical volume field other than `active`, the active volume's field, and a nonzero host.
    #[inline(always)]
    fn spare(&mut self, active: &[u8; VOLUME]) -> Result<Option<(VolumeId, Host)>, CodecError> {
        let (present, field) = (self.pick(&[false, true])?, self.field::<VOLUME>()?);
        let host = Host::new(self.u64()?);
        match present {
            true if field != active => match (VolumeId::from_field(field), host) {
                (Some(spare), Some(host)) => Ok(Some((spare, host))),
                _ => Err(CodecError::Field),
            },
            true => Err(CodecError::Field),
            false if *field == [0; VOLUME] && host.is_none() => Ok(None),
            false => Err(CodecError::Flag),
        }
    }

    /// The checkpoint after its flag, or `None` for a clear flag and zero bytes.
    #[inline(always)]
    pub(crate) fn checkpoint(&mut self) -> Result<Option<NamedCheckpoint>, CodecError> {
        let (present, bytes) = (self.pick(&[false, true])?, self.field::<CHECKPOINT>()?);
        let mut r = Reader(bytes);
        let ck = NamedCheckpoint {
            slot: r.u32()?,
            session: r.u64()?,
            capture: r.u32()?,
            units: r.u32()?,
        };
        match present {
            true => Ok(Some(ck)),
            false if *bytes == [0; CHECKPOINT] => Ok(None),
            false => Err(CodecError::Flag),
        }
    }

    /// The value an index byte selects from `values`; `[false, true]` reads a flag byte.
    pub(crate) fn pick<T: Copy>(&mut self, values: &[T]) -> Result<T, CodecError> {
        values
            .get(usize::from(self.u8()?))
            .copied()
            .ok_or(CodecError::Flag)
    }

    /// The ancestry field of a shard record at generation `generation`, attempt counter `attempts` and cut `cut`,
    /// checked against BOUNDED-MANIFEST: `Length` for a count above [`MAX_CHAIN`], `Flag` for a nonzero suffix past
    /// the count, and `Field` for a suffix outside its generation, an epoch that is odd, zero or above `2E`, an
    /// empty range, a certified end outside `start..=end`, an end past `LSN_LIMIT + 1`, a first suffix ending at or
    /// below the cut, or a suffix whose session or start does not follow the one before it.
    #[inline(always)]
    fn ancestry(
        &mut self,
        generation: u32,
        attempts: u32,
        cut: u64,
    ) -> Result<Ancestry, CodecError> {
        let len = self.u8()?;
        if usize::from(len) > MAX_CHAIN {
            return Err(CodecError::Length);
        }
        let mut chain = Ancestry {
            len,
            ..Ancestry::default()
        };
        for at in 0..MAX_CHAIN {
            let suffix = Suffix {
                session: self.u64()?,
                start: self.u64()?,
                certified: self.u64()?,
                end: self.u64()?,
            };
            if at >= usize::from(len) {
                (suffix == Suffix::default())
                    .then_some(())
                    .ok_or(CodecError::Flag)?;
                continue;
            }
            let epoch = u64::from(suffix.session as u32);
            let after = match at.checked_sub(1).map(|prior| chain.suffixes[prior]) {
                None => suffix.end > cut,
                Some(prior) => suffix.session > prior.session && suffix.start >= prior.end,
            };
            let admitted = suffix.session >> 32 == u64::from(generation)
                && epoch % 2 == 0
                && (2..=2 * u64::from(attempts)).contains(&epoch)
                && suffix.start < suffix.end
                && (suffix.start..=suffix.end).contains(&suffix.certified)
                && suffix.end <= LSN_LIMIT + 1
                && after;
            admitted.then_some(()).ok_or(CodecError::Field)?;
            chain.suffixes[at] = suffix;
        }
        Ok(chain)
    }

    /// One recorded pair: a nonzero host, a nonzero EXHID and a usable reservation key, else `Field`, then the
    /// attach sequence number.
    #[inline(always)]
    fn pair(&mut self) -> Result<RecordedPair, CodecError> {
        let host = self.host()?;
        let exhid = Exhid::new(self.take()?).map_err(|_| CodecError::Field)?;
        let key = Key::decode(self.u64()?).map_err(|_| CodecError::Field)?;
        Ok(RecordedPair {
            host,
            pair: Pair { exhid, key },
            attach: self.u32()?,
        })
    }

    #[inline(always)]
    fn event(&mut self, seq: u32, kinds: &[EventKind]) -> Result<AttachmentEvent, CodecError> {
        let (kind, host, era) = (self.pick(kinds)?, self.host()?, self.u32()?);
        if era < MIN_ERA {
            return Err(CodecError::Field);
        }
        Ok(AttachmentEvent {
            seq,
            kind,
            host,
            era,
            instance: None,
        })
    }

    /// An all-zero format-3 instance field represents `None`. Any other field requires a nonzero first byte, a kind
    /// satisfying `attachment()`, and successful parsing by `InstanceId::from_field`.
    #[inline(always)]
    fn entry(&mut self, seq: u32) -> Result<AttachmentEvent, CodecError> {
        let mut event = self.event(seq, &ENTRY_KINDS)?;
        let field = self.take::<INSTANCE_FIELD>()?;
        event.instance = match field {
            [0, rest @ ..] if rest == [0; INSTANCE_FIELD - 1] => None,
            [0, ..] => return Err(CodecError::Flag),
            _ if event.kind.attachment() => {
                Some(InstanceId::from_field(&field).ok_or(CodecError::Field)?)
            }
            _ => return Err(CodecError::Field),
        };
        Ok(event)
    }
}

/// A value's magic and format version, in a buffer of `capacity` bytes, the value's encoded length.
pub(crate) fn head(magic: &[u8; 4], version: u16, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.extend(magic);
    out.extend(version.to_be_bytes());
    out
}

/// A destination of a record's encoded fields, in layout order.
pub(crate) trait Sink {
    fn put<const N: usize>(&mut self, bytes: [u8; N]);
}

impl Sink for Vec<u8> {
    fn put<const N: usize>(&mut self, bytes: [u8; N]) {
        self.extend(bytes);
    }
}

/// Fills a buffer front to back. The layout constants size every buffer it fills for the fields written to it, so a
/// field past the end is a layout defect.
struct Writer<'a>(&'a mut [u8]);

impl Sink for Writer<'_> {
    fn put<const N: usize>(&mut self, bytes: [u8; N]) {
        let (head, rest) = core::mem::take(&mut self.0)
            .split_first_chunk_mut::<N>()
            .expect("the layout constants size the buffer for every field");
        *head = bytes;
        self.0 = rest;
    }
}

fn put_volume(out: &mut impl Sink, volume: Option<&VolumeId>) {
    out.put(volume.map_or([0; VOLUME], VolumeId::field));
}

pub(crate) fn put_checkpoint(out: &mut impl Sink, checkpoint: Option<NamedCheckpoint>) {
    out.put([u8::from(checkpoint.is_some())]);
    let ck = checkpoint.unwrap_or_default();
    out.put(ck.slot.to_be_bytes());
    out.put(ck.session.to_be_bytes());
    out.put(ck.capture.to_be_bytes());
    out.put(ck.units.to_be_bytes());
}

fn put_ancestry(out: &mut impl Sink, ancestry: &Ancestry) {
    out.put([ancestry.len]);
    for suffix in &ancestry.suffixes {
        for field in [suffix.session, suffix.start, suffix.certified, suffix.end] {
            out.put(field.to_be_bytes());
        }
    }
}

/// The position of `value` in `values`, its encoded byte. Each codec table lists every value of its type.
pub(crate) fn index<T: PartialEq>(values: &[T], value: &T) -> u8 {
    values
        .iter()
        .position(|candidate| candidate == value)
        .unwrap_or(0) as u8
}

pub(crate) const STATES: [VolumeState; 5] = [
    VolumeState::Provisioning,
    VolumeState::Fresh,
    VolumeState::Active,
    VolumeState::Retired,
    VolumeState::Deleted,
];
const SOURCES: [CreationSource; 2] = [CreationSource::Provisioned, CreationSource::Foreign];
const LINEAGES: [Lineage; 3] = [Lineage::None, Lineage::Snapshot, Lineage::Clone];
const ENTRY_KINDS: [EventKind; 5] = [
    EventKind::Attach,
    EventKind::Detach,
    EventKind::Force,
    EventKind::Ended,
    EventKind::Gone,
];
const KINDS: [EventKind; 3] = [ENTRY_KINDS[0], ENTRY_KINDS[1], ENTRY_KINDS[2]];
const MODIFIED: [Option<Modification>; 3] = [
    None,
    Some(Modification::InProgress),
    Some(Modification::Completed),
];

impl Record for ShardRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = [0; SHARD_MAX];
        let mut w = Writer(&mut out);
        w.put(*b"SHRD");
        let (version, len) = match self.standby {
            None => (SHARD_VERSION, SHARD_LEN),
            Some(_) => (STANDBY_VERSION, SHARD_MAX),
        };
        w.put(version.to_be_bytes());
        w.put(self.shard.get().to_be_bytes());
        w.put((self.generation.get() as u32).to_be_bytes());
        put_volume(&mut w, Some(&self.active));
        w.put(self.owner.get().to_be_bytes());
        w.put(self.attempts.to_be_bytes());
        let (spare, host) = self.spare.unzip();
        w.put([u8::from(spare.is_some())]);
        put_volume(&mut w, spare.as_ref());
        w.put(host.map_or(0, Host::get).to_be_bytes());
        put_checkpoint(&mut w, self.checkpoint);
        w.put(self.cut.to_be_bytes());
        w.put(self.pages.get().to_be_bytes());
        w.put(self.page_cap.get().to_be_bytes());
        w.put(self.namespace.bytes());
        put_ancestry(&mut w, &self.ancestry);
        w.put(self.standby.map_or(0, Host::get).to_be_bytes());
        debug_assert!(w.0.is_empty());
        out[..len].to_vec()
    }

    /// The length selects the format: [`SHARD_LEN`] bytes decode as format 2 and [`SHARD_MAX`] as format 3, whose
    /// standby host is nonzero and other than the owner.
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let version = match bytes.len() {
            SHARD_LEN => SHARD_VERSION,
            SHARD_MAX => STANDBY_VERSION,
            _ => return Err(CodecError::Length),
        };
        let mut r = Reader::open(bytes, b"SHRD", version)?;
        let shard = Shard::new(r.u32()?).ok_or(CodecError::Field)?;
        let raw_generation = r.u32()?;
        let generation = ShardGeneration::new(raw_generation.into()).ok_or(CodecError::Field)?;
        let (active, active_field) = r.volume()?;
        let owner = r.host()?;
        let attempts = r.u32()?;
        if attempts > ATTEMPTS_MAX {
            return Err(CodecError::Field);
        }
        let spare = r.spare(active_field)?;
        let checkpoint = r.checkpoint()?;
        let cut = r.u64()?;
        if (checkpoint.is_none() && cut != 0) || cut > LSN_LIMIT + 1 {
            return Err(CodecError::Field);
        }
        let pages = NonZeroU16::new(r.u16()?).ok_or(CodecError::Field)?;
        let page_cap = NonZeroU32::new(r.u32()?).ok_or(CodecError::Field)?;
        let namespace = Namespace::new(r.take()?).ok_or(CodecError::Field)?;
        let ancestry = r.ancestry(raw_generation, attempts, cut)?;
        let standby = (version == STANDBY_VERSION).then(|| r.host()).transpose()?;
        if standby == Some(owner) {
            return Err(CodecError::Field);
        }
        Ok(Self {
            shard,
            generation,
            active,
            owner,
            attempts,
            spare,
            checkpoint,
            cut,
            pages,
            page_cap,
            namespace,
            ancestry,
            standby,
        })
    }

    fn succeeds(&self, prior: &Self) -> Result<(), SuccessorRule> {
        let tenure = self.generation != prior.generation
            || self.active != prior.active
            || self.owner != prior.owner
            || self.attempts != prior.attempts
            || self.standby != prior.standby;
        let named = |r: &Self| r.checkpoint.map(|ck| (ck.session, ck.capture));
        let changed = self.checkpoint != prior.checkpoint || self.cut != prior.cut;
        // `None` orders below every checkpoint, so a successor that clears the checkpoint refuses.
        let later = named(self) > named(prior);
        // Any changed `E` breaks the Tenure rule, which is reported first, and an `E` above ATTEMPTS_MAX does not
        // encode, so `current` only has to avoid overflow.
        let current = session_of(
            self.generation.get() as u32,
            self.attempts.saturating_mul(2),
        );
        first_change(&[
            (self.shard != prior.shard, SuccessorRule::Identity),
            (self.pages != prior.pages, SuccessorRule::Pages),
            (self.page_cap != prior.page_cap, SuccessorRule::PageCap),
            (self.namespace != prior.namespace, SuccessorRule::Namespace),
            (tenure, SuccessorRule::Tenure),
            (
                (changed && !later) || self.cut < prior.cut,
                SuccessorRule::Checkpoint,
            ),
            (
                !self
                    .ancestry
                    .extends(&prior.ancestry, self.cut, prior.cut, current),
                SuccessorRule::Ancestry,
            ),
        ])
    }
}

impl Record for VolumeRecord {
    fn encode(&self) -> Vec<u8> {
        let first = self.legacy_first();
        let (version, entry) = match first {
            Some(_) => (VOLUME_VERSION, EVENT),
            None => (ENTRY_VERSION, ENTRY),
        };
        let mut fixed = [0; VOLUME_FIXED];
        let mut w = Writer(&mut fixed);
        w.put(*b"VOLR");
        w.put(version.to_be_bytes());
        put_volume(&mut w, Some(&self.volume));
        w.put([
            index(&STATES, &self.state),
            index(&SOURCES, &self.source),
            index(&LINEAGES, &self.lineage),
            index(&MODIFIED, &self.modification),
        ]);
        w.put(self.layout.units.to_be_bytes());
        w.put(self.layout.slots.to_be_bytes());
        w.put(self.layout.slot_units.to_be_bytes());
        w.put(self.layout.entries.to_be_bytes());
        w.put(first.unwrap_or(self.next).to_be_bytes());
        w.put([u8::from(self.forced)]);
        w.put(self.fence.to_be_bytes());
        w.put([self.pairs.len() as u8, self.events.len() as u8]);
        debug_assert!(w.0.is_empty());
        let mut out =
            Vec::with_capacity(VOLUME_FIXED + PAIR * self.pairs.len() + entry * self.events.len());
        out.put(fixed);
        for recorded in &self.pairs {
            let mut pair = [0; PAIR];
            let mut w = Writer(&mut pair);
            w.put(recorded.host.get().to_be_bytes());
            w.put(recorded.pair.exhid.bytes());
            w.put(recorded.pair.key.encode().to_be_bytes());
            w.put(recorded.attach.to_be_bytes());
            debug_assert!(w.0.is_empty());
            out.put(pair);
        }
        for event in &self.events {
            let mut bytes = [0; ENTRY];
            let mut w = Writer(&mut bytes[..entry]);
            if first.is_none() {
                w.put(event.seq.to_be_bytes());
            }
            w.put([index(&ENTRY_KINDS, &event.kind)]);
            w.put(event.host.get().to_be_bytes());
            w.put(event.era.to_be_bytes());
            if first.is_none() {
                w.put(event.instance.map_or([0; INSTANCE_FIELD], |id| id.field()));
            }
            debug_assert!(w.0.is_empty());
            out.extend_from_slice(&bytes[..entry]);
        }
        out
    }

    /// The length selects the format: `VOLUME_FIXED + 36·pairs + 13·events` bytes decode as format 2 and
    /// `VOLUME_FIXED + 36·pairs + 37·events` as format 3. With zero events both lengths match, and the bytes decode as
    /// format 2, the one encoding of an empty history.
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let count = |at: usize| bytes.get(at).map_or(0, |&count| usize::from(count));
        let (pairs, events) = (count(VOLUME_FIXED - 2), count(VOLUME_FIXED - 1));
        let length = |entry: usize| VOLUME_FIXED + PAIR * pairs + entry * events;
        let version = match bytes.len() {
            len if len == length(EVENT) => VOLUME_VERSION,
            len if len == length(ENTRY) => ENTRY_VERSION,
            _ => return Err(CodecError::Length),
        };
        if pairs > MAX_REGISTRANTS || events > MAX_EVENTS {
            return Err(CodecError::Length);
        }
        let mut r = Reader::open(bytes, b"VOLR", version)?;
        let (volume, _) = r.volume()?;
        let (state, source) = (r.pick(&STATES)?, r.pick(&SOURCES)?);
        let (lineage, modification) = (r.pick(&LINEAGES)?, r.pick(&MODIFIED)?);
        let (units, slots, slot_units, entries) = (r.u64()?, r.u32()?, r.u32()?, r.u32()?);
        let layout = Layout {
            units,
            slots,
            slot_units,
            entries,
        };
        let (stored, forced, fence) = (r.u32()?, r.pick(&[false, true])?, r.u64()?);
        if fence != 0 && !activated(fence) {
            return Err(CodecError::Field);
        }
        r.take::<2>()?;
        let mut recorded = Vec::with_capacity(pairs);
        for _ in 0..pairs {
            recorded.push(r.pair()?);
        }
        let mut history = Vec::with_capacity(events);
        let next = match version {
            VOLUME_VERSION => {
                for at in 0..events {
                    history.push(r.event(stored.wrapping_add(at as u32), &KINDS)?);
                }
                stored.checked_add(events as u32).ok_or(CodecError::Field)?
            }
            _ => {
                for _ in 0..events {
                    let seq = r.u32()?;
                    let ordered = history
                        .last()
                        .is_none_or(|prior: &AttachmentEvent| prior.seq < seq);
                    if !ordered || seq >= stored {
                        return Err(CodecError::Field);
                    }
                    history.push(r.entry(seq)?);
                }
                stored
            }
        };
        let record = Self {
            volume,
            state,
            source,
            lineage,
            modification,
            layout,
            next,
            forced,
            fence,
            pairs: recorded,
            events: history,
        };
        if !record.evidence_holds() {
            return Err(CodecError::Field);
        }
        if version == ENTRY_VERSION && record.legacy_first().is_some() {
            return Err(CodecError::Version);
        }
        Ok(record)
    }

    fn succeeds(&self, prior: &Self) -> Result<(), SuccessorRule> {
        let cleared = prior.modification.is_some() && self.modification.is_none();
        let legacy = prior.legacy_first().is_some() && self.legacy_first().is_some();
        let raised = self.fence > prior.fence;
        let dropped = || prior.pairs.iter().filter(|pair| !self.pairs.contains(pair));
        let added = || self.pairs.iter().filter(|pair| !prior.pairs.contains(pair));
        let drops_ended = dropped().all(|pair| prior.pins_ended(pair));
        let own_identity = added().all(|new| {
            dropped().all(|old| old.pair.exhid != new.pair.exhid && old.pair.key != new.pair.key)
        });
        let pins_live = legacy || added().all(|pair| self.live(pair.host) == Some(pair.attach));
        let pairs_kept = pins_live && (raised || (drops_ended && own_identity));
        first_change(&[
            (self.volume != prior.volume, SuccessorRule::Identity),
            (self.source != prior.source, SuccessorRule::Source),
            (self.lineage != prior.lineage, SuccessorRule::Lineage),
            (self.layout != prior.layout, SuccessorRule::Layout),
            (
                !self.events_follow(prior, legacy) || (prior.forced && !self.forced),
                SuccessorRule::Events,
            ),
            (self.state < prior.state, SuccessorRule::State),
            (cleared, SuccessorRule::Modification),
            (self.fence < prior.fence, SuccessorRule::Fence),
            (!pairs_kept, SuccessorRule::Pairs),
        ])
    }
}

impl Record for CoveragePage {
    fn encode(&self) -> Vec<u8> {
        let mut out = head(b"PAGE", PAGE_VERSION, self.encoded_len());
        out.extend(self.fence.to_be_bytes());
        out.push(u8::from(self.saturated));
        out.extend((self.entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.entries);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let (fence, saturated) = page_header(bytes)?;
        Ok(Self {
            fence,
            saturated,
            entries: bytes[PAGE_FIXED..].to_vec(),
        })
    }

    fn succeeds(&self, prior: &Self) -> Result<(), SuccessorRule> {
        first_change(&[
            (self.fence < prior.fence, SuccessorRule::Fence),
            (
                prior.saturated && !self.saturated,
                SuccessorRule::Saturation,
            ),
        ])
    }
}

/// Whether `session` is an activated session `g·2^32 + a`: `g >= 1` and `a` an even epoch from 2 to
/// `ActivatedEpoch::MAX`, the form a nonzero volume-record fence takes.
pub(crate) fn activated(session: u64) -> bool {
    session >> 32 != 0
        && ActivatedEpoch::new(session as u32).is_some_and(ActivatedEpoch::is_activated)
}

/// The reservation key of the attach entry numbered `seq`: epoch 1 and incarnation `seq + 1`, so the key uniquely
/// identifies the entry. `None` for `seq = 0xFFFF_FFFE`, whose incarnation would be the reserved value, and for
/// `seq = u32::MAX`, whose incarnation overflows.
pub fn attachment_key(seq: u32) -> Option<Key> {
    Incarnation::new(seq.checked_add(1)?)
        .ok()
        .map(Key::attachment)
}

/// The entry number whose [`attachment_key`] is `key`, or `None` when no entry number gives that key.
pub fn attachment_seq(key: Key) -> Option<u32> {
    let seq = key.incarnation().get().checked_sub(1)?;
    (attachment_key(seq) == Some(key)).then_some(seq)
}

impl VolumeRecord {
    /// `attached_once` returns true when the volume's complete history consists of one attach by `host`.
    pub fn attached_once(&self, host: Host) -> bool {
        self.uncompacted()
            && matches!(self.events.as_slice(), [event] if event.kind == EventKind::Attach && event.host == host)
    }

    /// `uncompacted` returns true exactly when the retained sequence numbers equal `0..next` in order.
    pub fn uncompacted(&self) -> bool {
        self.events.iter().map(|event| event.seq).eq(0..self.next)
    }

    /// Returns the new event's number, or `None` once `next` is `u32::MAX`.
    pub fn push(&mut self, kind: EventKind, host: Host, era: u32) -> Option<u32> {
        let seq = self.next;
        self.next = seq.checked_add(1)?;
        self.events.push(AttachmentEvent {
            seq,
            kind,
            host,
            era,
            instance: None,
        });
        self.forced |= kind == EventKind::Force;
        Some(seq)
    }

    pub(crate) fn event(&self, seq: u32) -> Option<&AttachmentEvent> {
        self.events.iter().find(|event| event.seq == seq)
    }

    /// True if `seq` identifies a removed event in a record that requires format 3. In a format 2-compatible
    /// record, a missing `seq` below `next` identifies a compacted leading event that could belong to any host.
    pub(crate) fn removed(&self, seq: u32) -> bool {
        seq < self.next && self.event(seq).is_none() && self.legacy_first().is_none()
    }

    /// `legacy_first` returns `Some(first)` when the retained sequence numbers equal `first..next` in order and
    /// every event has `instance == None` and a kind in `KINDS`. An empty record yields `Some(next)`.
    fn legacy_first(&self) -> Option<u32> {
        let first = self
            .next
            .checked_sub(u32::try_from(self.events.len()).ok()?)?;
        self.events
            .iter()
            .zip(first..self.next)
            .all(|(event, seq)| {
                event.seq == seq && event.instance.is_none() && KINDS.contains(&event.kind)
            })
            .then_some(first)
    }

    /// `self.next` must be at least `prior.next`, and the events of `self` must be in increasing number order. New
    /// events must have sequence numbers equal to `prior.next..self.next` in order and kinds in `KINDS`. Every other
    /// event of `self` must match `prior`'s event of its number in host, era and instance, with an equal kind, an
    /// attach-to-ended move, or an ended-to-gone move for an entry that no pair in `prior` pins. One rule permits an
    /// instance change (BIND-AT-ATTACH): an attach that is its host's live attach in `prior`, binds no instance there
    /// and stays an attach in `self` may take its first instance. An event of `prior` absent from
    /// `self` must be gone, or lie in the prefix of `prior` that `self` drops and have no instance and a kind in
    /// `KINDS`. Each live attach of `self` numbered below `prior.next` must be the live attach of its host in `prior`.
    fn events_follow(&self, prior: &Self, legacy: bool) -> bool {
        let ordered = self
            .events
            .windows(2)
            .all(|neighbors| neighbors[0].seq < neighbors[1].seq);
        let born = || self.events.iter().filter(|event| event.seq >= prior.next);
        let numbered = born().map(|event| event.seq).eq(prior.next..self.next);
        let fresh = born().all(|event| KINDS.contains(&event.kind));
        let kept = self
            .events
            .iter()
            .filter(|event| event.seq < prior.next)
            .all(|event| {
                prior.event(event.seq).is_some_and(|old| {
                    let kind_follows = match (old.kind, event.kind) {
                        (EventKind::Attach, EventKind::Ended) => true,
                        (EventKind::Ended, EventKind::Gone) => {
                            prior.pairs.iter().all(|pair| pair.attach != old.seq)
                        }
                        (was, now) => was == now,
                    };
                    // BIND-AT-ATTACH: an attach that stays its host's live attach may take its first instance.
                    let bound = old.instance == event.instance
                        || (old.instance.is_none()
                            && (old.kind, event.kind) == (EventKind::Attach, EventKind::Attach)
                            && prior.live(old.host) == Some(old.seq));
                    (old.host, old.era) == (event.host, event.era) && bound && kind_follows
                })
            });
        let split = prior
            .events
            .iter()
            .position(|old| self.event(old.seq).is_some())
            .unwrap_or(prior.events.len());
        let (oldest, rest) = prior.events.split_at(split);
        let left = oldest.iter().all(|old| {
            old.kind == EventKind::Gone || (old.instance.is_none() && KINDS.contains(&old.kind))
        }) && rest
            .iter()
            .all(|old| old.kind == EventKind::Gone || self.event(old.seq).is_some());
        let unrevived = self
            .live_attaches()
            .all(|(seq, host)| seq >= prior.next || prior.live(host) == Some(seq));
        let persists = legacy
            || prior.live_attaches().all(|(seq, host)| {
                self.live(host) == Some(seq)
                    || self
                        .event(seq)
                        .is_some_and(|event| event.kind == EventKind::Ended)
            });
        let marked = legacy
            || prior.forced
            || !self.forced
            || born().any(|event| event.kind == EventKind::Force);
        self.next >= prior.next
            && ordered
            && numbered
            && fresh
            && kept
            && left
            && unrevived
            && persists
            && marked
    }

    /// The sequence number of `host`'s latest retained event when that event attaches it.
    pub fn live(&self, host: Host) -> Option<u32> {
        self.latest(host)
            .filter(|(_, event)| event.kind == EventKind::Attach)
            .map(|(seq, _)| seq)
    }

    pub(crate) fn latest(&self, host: Host) -> Option<(u32, &AttachmentEvent)> {
        let event = self.events.iter().rfind(|event| event.host == host)?;
        Some((event.seq, event))
    }

    /// `has_attach_event` returns true while the record retains an event of `host` whose kind satisfies
    /// `attachment()`, so it stays true after a detach or force-detach.
    pub fn has_attach_event(&self, host: Host) -> bool {
        self.events
            .iter()
            .any(|event| event.kind.attachment() && event.host == host)
    }

    /// `live_hosts` yields each live host once, ordered by its latest retained attach event.
    pub fn live_hosts(&self) -> impl Iterator<Item = Host> + '_ {
        self.live_attaches().map(|(_, host)| host)
    }

    /// `hosts_with_attach_event` yields each host for which `has_attach_event` holds once, ordered by its first
    /// retained event whose kind satisfies `attachment()`. An ended or gone entry counts as its host's attach event,
    /// so `hosts_with_attach_event` still yields a host after a detach, a force detach or the end of its attach.
    pub fn hosts_with_attach_event(&self) -> impl Iterator<Item = Host> + '_ {
        self.events
            .iter()
            .enumerate()
            .filter(|&(at, event)| {
                event.kind.attachment()
                    && !self.events[..at]
                        .iter()
                        .any(|earlier| earlier.kind.attachment() && earlier.host == event.host)
            })
            .map(|(_, event)| event.host)
    }

    /// `live_attaches` yields the sequence number and host of each live host's latest retained attach event, in event
    /// order.
    pub(crate) fn live_attaches(&self) -> impl Iterator<Item = (u32, Host)> + '_ {
        self.events
            .iter()
            .enumerate()
            .filter(|&(at, event)| {
                event.kind == EventKind::Attach
                    && self.events[at + 1..]
                        .iter()
                        .all(|later| later.host != event.host)
            })
            .map(|(_, event)| (event.seq, event.host))
    }

    pub fn recorded(&self) -> impl ExactSizeIterator<Item = &Pair> + Clone {
        self.pairs.iter().map(|recorded| &recorded.pair)
    }

    pub fn recorded_pairs(&self) -> Vec<Pair> {
        self.recorded().copied().collect()
    }

    /// The pairs recorded for hosts other than `host`, each pinning a retained attach of its host, live or marked by a
    /// later format-2 detach or force detach, or an ended entry.
    pub(crate) fn recorded_beside(&self, host: Host) -> impl Iterator<Item = &Pair> + '_ {
        self.pairs
            .iter()
            .filter(move |held| held.host != host)
            .map(|held| &held.pair)
    }

    /// The recorded pairs that pin no live attach of their host: the host detached, its entry is marked ended, or the
    /// host attached again.
    pub(crate) fn ended_attach_pairs(&self) -> impl Iterator<Item = &Pair> + '_ {
        self.pairs
            .iter()
            .filter(|held| !self.pins_live_attach(held))
            .map(|held| &held.pair)
    }

    fn pins_live_attach(&self, held: &RecordedPair) -> bool {
        self.live(held.host) == Some(held.attach)
    }

    /// The instances bound by the attach and ended entries of hosts other than `host`. A gone entry's instance is
    /// left out: two settled listings showed it detached.
    pub(crate) fn instances_beside(&self, host: Host) -> impl Iterator<Item = &InstanceId> + Clone {
        self.bound_beside(host).map(|(_, instance)| instance)
    }

    /// Each attach or ended entry of a host other than `host` that binds an instance, as its host and that
    /// instance, in record order: the entries [`VolumeRecord::instances_beside`] reads. A host with several such
    /// entries appears once for each.
    pub(crate) fn bound_beside(
        &self,
        host: Host,
    ) -> impl Iterator<Item = (Host, &InstanceId)> + Clone {
        self.events
            .iter()
            .filter(move |event| event.host != host && event.kind.listed())
            .filter_map(|event| Some((event.host, event.instance.as_ref()?)))
    }

    /// Yields indices of instance-bound `Gone` entries removable when `host` gets a new `Attach`. The iterator skips
    /// another host's final `Gone` entry when that host's preceding event has a kind in `KINDS`: removal would make
    /// that event the host's latest.
    pub(crate) fn removable_gone(&self, host: Host) -> impl Iterator<Item = usize> + '_ {
        self.events
            .iter()
            .enumerate()
            .filter(move |&(at, event)| {
                let last = self.events[at + 1..]
                    .iter()
                    .all(|later| later.host != event.host);
                let exposed = self.events[..at]
                    .iter()
                    .rfind(|earlier| earlier.host == event.host)
                    .is_some_and(|earlier| KINDS.contains(&earlier.kind));
                event.kind == EventKind::Gone
                    && event.instance.is_some()
                    && (event.host == host || !last || !exposed)
            })
            .map(|(at, _)| at)
    }

    /// Whether a caller binds `host` as a peer through its own instance lookup: `host`'s newest retained attach,
    /// ended or gone entry is an attach or ended entry that binds no instance, as every attach of a format-2 record
    /// is, its later detach or force detach markers included. A newest entry that binds an instance gives the
    /// judges that instance through [`VolumeRecord::instances_beside`], and a newest gone entry admits no instance,
    /// so an older entry of the host that binds none binds no peer after either. The rule reads retained entries
    /// only; an entry the record no longer retains decides nothing.
    pub(crate) fn bound_by_lookup(&self, host: Host) -> bool {
        (self.events.iter())
            .rfind(|event| event.host == host && event.kind.attachment())
            .is_some_and(|event| event.kind.listed() && event.instance.is_none())
    }

    /// `ended` returns `true` exactly when `host`'s latest retained `Attach`, `Ended` or `Gone` entry is `Ended` or
    /// `Gone`.
    pub(crate) fn ended(&self, host: Host) -> bool {
        self.events
            .iter()
            .rfind(|event| event.host == host && event.kind.attachment())
            .is_some_and(|event| matches!(event.kind, EventKind::Ended | EventKind::Gone))
    }

    /// Whether the record holds a pair of `host`, pinning a live attach or an ended entry.
    pub(crate) fn records_pair_of(&self, host: Host) -> bool {
        self.pairs.iter().any(|recorded| recorded.host == host)
    }

    /// ENDED-NEVER-RETIRES: how a Report's registrant `pair` stands against the record. A pair the record holds,
    /// pinning a retained attach, live or marked by a later format-2 detach or force detach, or an ended entry, is
    /// [`Registration::Recorded`]. An unrecorded pair under the key
    /// [`attachment_key`] gives an entry numbered below `next` that is no host's live attach, an ended, gone or
    /// removed entry's, is [`Registration::Ended`]: KEY-PER-ATTACH gives that key to no later attach, so its
    /// registrant is a late Register of an ended attach. Another host ID under a key that a recorded pair of a live or
    /// detach-marked attach holds is [`Registration::Unknown`]. Under the key of a recorded pair that pins an ended
    /// entry it takes the same spent-key rule: [`Registration::Ended`] when that key is the [`attachment_key`] of a
    /// number below `next` that no live attach holds, as ENDED-NEVER-RETIRES asks, and ENDED-PREEMPT removes it with
    /// the key; [`Registration::Unknown`] when the pair carries a retained key of another epoch.
    /// For an unrecorded pair, a key encoding the sequence number of a retained `Detach` or `Force` yields
    /// [`Registration::Unknown`]: KEY-PER-ATTACH derives keys from attach entries alone. Every other pair is
    /// [`Registration::Unknown`].
    pub fn registrant(&self, pair: &Pair) -> Registration {
        if self.recorded().any(|recorded| recorded == pair) {
            return Registration::Recorded;
        }
        if self.carries_unended(pair.key) {
            return Registration::Unknown;
        }
        match self.spent_key(pair.key) {
            true => Registration::Ended,
            false => Registration::Unknown,
        }
    }

    /// A `true` result identifies a retired attachment sequence below `next`: a number no live attach holds and whose
    /// retained event, if any, is an attachment entry. KEY-PER-ATTACH derives keys from attach entries alone, so the
    /// key of a retained detach or force-detach event's number is no spent key. Later attaches use fresh sequences.
    pub(crate) fn spent_key(&self, key: Key) -> bool {
        attachment_seq(key).is_some_and(|seq| {
            seq < self.next
                && self.event(seq).is_none_or(|event| event.kind.attachment())
                && self.live_attaches().all(|(live, _)| live != seq)
        })
    }

    /// `admitted` yields the recorded pairs first, then each distinct pair listed in `entries` that
    /// [`VolumeRecord::registrant`] classes [`Registration::Ended`] and whose matching entries all have
    /// `holder == false`.
    pub(crate) fn admitted<'a>(
        &'a self,
        entries: &'a [crate::failover::evidence::Registrant],
    ) -> impl Iterator<Item = &'a Pair> + Clone {
        let ended = entries.iter().enumerate().filter(move |&(at, entry)| {
            entries[..at]
                .iter()
                .all(|earlier| earlier.pair != entry.pair)
                && self.ended_registrant(entries, &entry.pair)
        });
        self.recorded().chain(ended.map(|(_, entry)| &entry.pair))
    }

    pub(crate) fn ended_registrant(
        &self,
        entries: &[crate::failover::evidence::Registrant],
        pair: &Pair,
    ) -> bool {
        entries
            .iter()
            .all(|entry| !entry.holder || entry.pair != *pair)
            && self.registrant(pair) == Registration::Ended
    }

    /// KEY-PER-ATTACH: the reservation key that belongs to `host`'s live attach alone, derived from the entry's
    /// sequence number by [`attachment_key`], or `None` when the host has no live attach or the entry's number has
    /// no key. The volume assigns each event a unique sequence number, so distinct entries derive distinct keys.
    pub fn attach_key(&self, host: Host) -> Option<Key> {
        self.live(host).and_then(attachment_key)
    }

    /// The key a pair for `host`'s live attach enrolls or replays under: the key of the pair recorded for that
    /// attach, or else [`VolumeRecord::attach_key`]. `None` when the host has no live attach, or when its attach has
    /// no recorded pair and its number has no key.
    pub fn enrollment_key(&self, host: Host) -> Option<Key> {
        self.enrolled(host)
            .map(|pair| pair.key)
            .or_else(|| self.attach_key(host))
    }

    /// Whether `recorded` pins an entry of kind [`EventKind::Ended`].
    fn pins_ended(&self, recorded: &RecordedPair) -> bool {
        self.event(recorded.attach)
            .is_some_and(|event| event.kind == EventKind::Ended)
    }

    /// The recorded pairs that pin an ended entry, in record order: the pairs an owner past its fencing boundary
    /// may drop once a Report shows their keys absent (ENDED-NEVER-RETIRES, SUCCESSOR-RULES). A pair pinning an
    /// attach that a later format-2 detach or force detach of its host marks pins no ended entry.
    pub(crate) fn ended_pairs(&self) -> impl Iterator<Item = &RecordedPair> + '_ {
        self.pairs
            .iter()
            .filter(|recorded| self.pins_ended(recorded))
    }

    /// Whether a recorded pair that pins no ended entry carries `key`: the pair of a live attach, or of a format-2
    /// attach a later detach or force detach marks. ENDED-PREEMPT names no such key, whether or not a Report lists
    /// the pair, since its host may register under it.
    pub(crate) fn carries_unended(&self, key: Key) -> bool {
        (self.pairs.iter()).any(|recorded| recorded.pair.key == key && !self.pins_ended(recorded))
    }

    /// Whether KEY-PER-ATTACH gives `key` to a live attach, enrolled or not, or to a number at or past `next` that
    /// a later attach takes: [`attachment_key`] of such a number. ENDED-PREEMPT names no such key, whatever pair the
    /// record or the Report holds under it, so a delayed preempt never removes that attach's registration.
    pub(crate) fn derives_unended(&self, key: Key) -> bool {
        attachment_seq(key).is_some_and(|seq| {
            seq >= self.next || self.live_attaches().any(|(live, _)| live == seq)
        })
    }

    /// The owner's pair drop: the record without `pairs`, under the fence it holds, so the write is a successor
    /// [`Record::succeeds`] admits because the record holds each dropped pair's entry ended, and one the decoder
    /// reads. `session` is the serving owner's activated session `g·2^32 + a`: it decides only whether the
    /// constructor answers and is written nowhere. `None` when `pairs` is empty, names a pair that is not a
    /// recorded pair of an ended entry ([`VolumeRecord::ended_pairs`]), or `session` is not an activated session.
    /// The write raises no fence, so the successor check judges it by the ended entries and refuses the same
    /// record with a live attach's pair dropped as well. EndOrder: the caller first sees the pair pinned to its
    /// ended entry, and drops the pair once a Report that the owner submitted after that sighting, while serving
    /// past the owner's fencing boundary, shows the pair's key absent. The caller writes the result as an
    /// exact-version replace of the record it read after that Report; a conflict or an unknown outcome waits for a
    /// later poll.
    ///
    /// After the drop, [`VolumeRecord::registrant`] classes a late Register under the pair's key as
    /// [`Registration::Ended`] when the key is the [`attachment_key`] of an entry that is no live attach, as for
    /// every pair enrolled under KEY-PER-ATTACH. A retained pair enrolled under another key loses that tie: a late
    /// Register under its key is then [`Registration::Unknown`], and an owner's poll that reads it retires on
    /// `NotSole::ForeignRegistrant`. The retirement requires a Register under the pair's key to land after the Report
    /// samples a registrant set that excludes the key. A Register in flight across the end write can satisfy that
    /// ordering. The key then stays registered across the drop.
    pub fn dropped(&self, pairs: &[Pair], session: u64) -> Option<Self> {
        let ended = |pair: &Pair| self.ended_pairs().any(|recorded| recorded.pair == *pair);
        if pairs.is_empty() || !pairs.iter().all(ended) || !activated(session) {
            return None;
        }
        let mut kept = self.pairs.clone();
        kept.retain(|recorded| !pairs.contains(&recorded.pair));
        Some(Self {
            fence: self.fence,
            pairs: kept,
            events: self.events.clone(),
            ..*self
        })
    }

    /// The pair recorded for `host`'s live attach.
    pub fn enrolled(&self, host: Host) -> Option<Pair> {
        self.pinned(host, self.live(host)?)
    }

    pub(crate) fn pinned(&self, host: Host, attach: u32) -> Option<Pair> {
        self.pairs
            .iter()
            .find(|recorded| recorded.host == host && recorded.attach == attach)
            .map(|recorded| recorded.pair)
    }

    /// The record with `pair` enrolled for `host`'s live attach, or `None` when that pair is already enrolled for it.
    /// ENROLL-ONCE-PER-ATTACH: each live attach enrolls at most one pair, and every recorded pair carries its own host
    /// ID and its own key. KEY-PER-ATTACH: a pair not yet recorded for the live attach enrolls only when its key is
    /// [`VolumeRecord::attach_key`] of `host`; replaying the pair already recorded for that attach returns `Ok(None)`
    /// before the key check. RECORDED-WITHIN-BOUND: a successful insertion leaves at most [`Bounds::pair_cap`]
    /// recorded pairs.
    ///
    /// # Errors
    ///
    /// The first [`Enrollment`] refusal in variant order.
    pub fn enroll(
        &self,
        host: Host,
        pair: Pair,
        bounds: &Bounds,
    ) -> Result<Option<Self>, Enrollment> {
        if !matches!(self.state, VolumeState::Fresh | VolumeState::Active) {
            return Err(Enrollment::State);
        }
        let attach = self.live(host).ok_or(Enrollment::Unattached)?;
        match self.pinned(host, attach) {
            Some(enrolled) if enrolled == pair => return Ok(None),
            Some(_) => return Err(Enrollment::Altered),
            None => {}
        }
        if self.attach_key(host) != Some(pair.key) {
            return Err(Enrollment::Key);
        }
        if self
            .pairs
            .iter()
            .any(|recorded| recorded.pair.exhid == pair.exhid || recorded.pair.key == pair.key)
        {
            return Err(Enrollment::Shared);
        }
        if self.pairs.len() >= bounds.pair_cap() {
            return Err(Enrollment::Full);
        }
        let mut pairs = Vec::with_capacity(self.pairs.len() + 1);
        pairs.extend_from_slice(&self.pairs);
        pairs.push(RecordedPair { host, pair, attach });
        Ok(Some(Self {
            pairs,
            events: self.events.clone(),
            ..*self
        }))
    }

    /// When the history retains event `seq == 0` or is empty at `next == 0`, `forced` is true exactly when the
    /// history retains a force-detach; otherwise `forced` is true whenever it retains one. Every pair pins a retained
    /// attach or ended entry of its own host, and pinned events, EXHIDs, and keys are each unique across pairs
    /// (ENROLL-ONCE-PER-ATTACH).
    fn evidence_holds(&self) -> bool {
        let force = self
            .events
            .iter()
            .any(|event| event.kind == EventKind::Force);
        // A force-detach leaves only with the oldest events, so the mark stands for a departed one only after event 0
        // left.
        let departed = self.events.first().map_or(self.next, |event| event.seq) != 0;
        let marked = match departed {
            false => self.forced == force,
            true => self.forced || !force,
        };
        let pairs_pinned = self.pairs.iter().enumerate().all(|(at, recorded)| {
            self.event(recorded.attach).is_some_and(|event| {
                matches!(event.kind, EventKind::Attach | EventKind::Ended)
                    && event.host == recorded.host
            }) && self.pairs[..at].iter().all(|other| {
                other.attach != recorded.attach
                    && other.pair.exhid != recorded.pair.exhid
                    && other.pair.key != recorded.pair.key
            })
        });
        marked && pairs_pinned
    }
}

impl CoveragePage {
    pub fn encoded_len(&self) -> usize {
        PAGE_FIXED + self.entries.len()
    }

    /// [`Record::decode`] over bytes the caller owns, reusing their buffer for the entries.
    ///
    /// # Errors
    ///
    /// The error [`Record::decode`] returns for the same bytes.
    pub fn decode_owned(mut bytes: Vec<u8>) -> Result<Self, CodecError> {
        let (fence, saturated) = page_header(&bytes)?;
        bytes.drain(..PAGE_FIXED);
        Ok(Self {
            fence,
            saturated,
            entries: bytes,
        })
    }
}

/// A page's fence and saturation flag, after the checks of its length, magic, version and flag.
fn page_header(bytes: &[u8]) -> Result<(u64, bool), CodecError> {
    let declared = Reader(bytes.get(PAGE_FIXED - 4..).unwrap_or_default()).u32()?;
    if bytes.len() != PAGE_FIXED + declared as usize {
        return Err(CodecError::Length);
    }
    let mut r = Reader::open(bytes, b"PAGE", PAGE_VERSION)?;
    let (fence, saturated, _) = (r.u64()?, r.pick(&[false, true])?, r.u32()?);
    Ok((fence, saturated))
}

fn first_change(changed: &[(bool, SuccessorRule)]) -> Result<(), SuccessorRule> {
    changed.iter().find(|c| c.0).map_or(Ok(()), |c| Err(c.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failover::identity::{Epoch, Incarnation};

    const G: u64 = 3;
    const NAMESPACE: Namespace = Namespace::new([0x11; 16]).unwrap();

    fn session(epoch: u64) -> u64 {
        session_of(G as u32, epoch as u32)
    }

    fn suffix(epoch: u64, start: u64, certified: u64, end: u64) -> Suffix {
        Suffix {
            session: session(epoch),
            start,
            certified,
            end,
        }
    }

    fn chain(suffixes: &[Suffix]) -> Ancestry {
        Ancestry::new(suffixes).unwrap()
    }

    fn shard() -> ShardRecord {
        ShardRecord {
            shard: Shard::new(7).unwrap(),
            generation: ShardGeneration::new(G).unwrap(),
            active: VolumeId::new("vol-0a").unwrap(),
            owner: Host::new(11).unwrap(),
            attempts: 5,
            spare: Some((VolumeId::new("vol-0b").unwrap(), Host::new(12).unwrap())),
            checkpoint: Some(NamedCheckpoint {
                slot: 2,
                session: session(10),
                capture: 9,
                units: 40,
            }),
            cut: 100,
            pages: NonZeroU16::new(4).unwrap(),
            page_cap: NonZeroU32::new(65536).unwrap(),
            namespace: NAMESPACE,
            ancestry: chain(&[suffix(8, 90, 140, 140), suffix(10, 140, 150, 160)]),
            standby: None,
        }
    }

    fn host(value: u64) -> Host {
        Host::new(value).unwrap()
    }

    fn attach(seq: u32, host_id: u64) -> AttachmentEvent {
        AttachmentEvent {
            seq,
            kind: EventKind::Attach,
            host: host(host_id),
            era: ERA,
            instance: None,
        }
    }

    fn instance(tag: u64) -> InstanceId {
        InstanceId::new(&format!("i-{tag:017x}")).unwrap()
    }

    fn pair(tag: u8, epoch: u32, incarnation: u32) -> Pair {
        Pair {
            exhid: Exhid::new([tag; 16]).unwrap(),
            key: Key::new(
                Epoch::new(epoch).unwrap(),
                Incarnation::new(incarnation).unwrap(),
            ),
        }
    }

    fn recorded(host_id: u64, tag: u8, attach: u32) -> RecordedPair {
        RecordedPair {
            host: host(host_id),
            pair: pair(tag, 3, 7),
            attach,
        }
    }

    fn layout() -> Layout {
        Layout {
            units: 2_455_207,
            slots: 3,
            slot_units: 818_402,
            entries: 1 << 25,
        }
    }

    /// A compacted record: two events are gone, the third is a force-detach, and one pair pins the fourth.
    fn volume() -> VolumeRecord {
        VolumeRecord {
            volume: VolumeId::new("vol-0b").unwrap(),
            state: VolumeState::Active,
            source: CreationSource::Provisioned,
            lineage: Lineage::None,
            modification: None,
            layout: layout(),
            next: 4,
            forced: true,
            fence: session(10),
            pairs: vec![recorded(12, 0xE1, 3)],
            events: vec![
                AttachmentEvent {
                    seq: 2,
                    kind: EventKind::Force,
                    host: host(9),
                    era: STORED_ERA,
                    instance: None,
                },
                AttachmentEvent {
                    seq: 3,
                    kind: EventKind::Attach,
                    host: host(12),
                    era: 8,
                    instance: None,
                },
            ],
        }
    }

    /// A whole-history record with one attach and no pair.
    fn fresh() -> VolumeRecord {
        VolumeRecord {
            next: 1,
            forced: false,
            fence: 0,
            pairs: Vec::new(),
            events: vec![attach(0, 12)],
            ..volume()
        }
    }

    fn page() -> CoveragePage {
        CoveragePage {
            fence: session(12),
            saturated: false,
            entries: vec![0xA5, 0x5A, 0x01],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    const SHARD_GOLDEN: &str = concat!(
        "53485244",
        "0002",
        "00000007",
        "00000003",
        "06",
        "766f6c2d3061",
        "000000000000000000000000000000",
        "000000000000000b",
        "00000005",
        "01",
        "06",
        "766f6c2d3062",
        "000000000000000000000000000000",
        "000000000000000c",
        "01",
        "00000002",
        "000000030000000a",
        "00000009",
        "00000028",
        "0000000000000064",
        "0004",
        "00010000",
        "11111111111111111111111111111111",
        "02",
        "0000000300000008000000000000005a000000000000008c000000000000008c",
        "000000030000000a000000000000008c000000000000009600000000000000a0",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    const VOLUME_GOLDEN: &str = concat!(
        "564f4c52",
        "0002",
        "06",
        "766f6c2d3062",
        "000000000000000000000000000000",
        "02",
        "00",
        "00",
        "00",
        "00000000002576a7",
        "00000003",
        "000c7ce2",
        "02000000",
        "00000002",
        "01",
        "000000030000000a",
        "01",
        "02",
        "000000000000000c",
        "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
        "0000000300000007",
        "00000003",
        "02",
        "0000000000000009",
        "00000002",
        "00",
        "000000000000000c",
        "00000008",
    );
    const PAGE_GOLDEN: &str = concat!(
        "50414745",
        "0001",
        "000000030000000c",
        "00",
        "00000003",
        "a55a01"
    );
    /// Frozen version-1 encodings of a shard record with `beat = 1000` and a volume record with one event of era 8.
    const SHARD_V1: &str = concat!(
        "53485244",
        "0001",
        "00000007",
        "00000003",
        "06",
        "766f6c2d3061",
        "000000000000000000000000000000",
        "000000000000000b",
        "00000005",
        "01",
        "06",
        "766f6c2d3062",
        "000000000000000000000000000000",
        "000000000000000c",
        "01",
        "00000002",
        "000000030000000c",
        "00000009",
        "00000028",
        "00000000000003e8",
        "0004",
        "00010000",
    );
    const VOLUME_V1: &str = concat!(
        "564f4c52",
        "0001",
        "06",
        "766f6c2d3062",
        "000000000000000000000000000000",
        "02",
        "00",
        "00",
        "00",
        "00000000002576a7",
        "00000003",
        "000c7ce2",
        "02000000",
        "01",
        "00",
        "000000000000000c",
        "00000008",
    );

    /// Each version-2 record kind encodes to its golden bytes and decodes back to its value, with the shard record
    /// at exactly [`SHARD_LEN`] bytes and a record without a spare, checkpoint or ancestry round-tripping too.
    #[test]
    fn v2_records_round_trip_through_their_golden_bytes() {
        let (shard, volume, page) = (shard(), volume(), page());
        assert_eq!(hex(&shard.encode()), SHARD_GOLDEN);
        assert_eq!(hex(&volume.encode()), VOLUME_GOLDEN);
        assert_eq!(hex(&page.encode()), PAGE_GOLDEN);
        assert_eq!(shard.encode().len(), SHARD_LEN);
        assert_eq!(SHARD_LEN, 259);
        assert_eq!(ShardRecord::decode(&unhex(SHARD_GOLDEN)), Ok(shard));
        assert_eq!(
            VolumeRecord::decode(&unhex(VOLUME_GOLDEN)),
            Ok(volume.clone())
        );
        assert_eq!(CoveragePage::decode(&unhex(PAGE_GOLDEN)), Ok(page.clone()));
        assert_eq!(CoveragePage::decode_owned(unhex(PAGE_GOLDEN)), Ok(page));
        let bare = ShardRecord {
            spare: None,
            checkpoint: None,
            cut: 0,
            ancestry: Ancestry::default(),
            ..shard
        };
        assert_eq!(ShardRecord::decode(&bare.encode()), Ok(bare));
        assert_eq!(VolumeRecord::decode(&fresh().encode()), Ok(fresh()));
        type Tag = (fn(&mut VolumeRecord), usize, u8);
        let tags: [Tag; 11] = [
            (|r| r.state = VolumeState::Provisioning, 28, 0),
            (|r| r.state = VolumeState::Fresh, 28, 1),
            (|r| r.state = VolumeState::Retired, 28, 3),
            (|r| r.state = VolumeState::Deleted, 28, 4),
            (|r| r.source = CreationSource::Foreign, 29, 1),
            (|r| r.lineage = Lineage::Snapshot, 30, 1),
            (|r| r.lineage = Lineage::Clone, 30, 2),
            (|r| r.modification = Some(Modification::InProgress), 31, 1),
            (|r| r.modification = Some(Modification::Completed), 31, 2),
            (|r| r.events[0].kind = EventKind::Detach, 103, 1),
            (|r| r.events[0].kind = EventKind::Attach, 103, 0),
        ];
        for (change, at, tag) in tags {
            let mut next = volume.clone();
            change(&mut next);
            let mut bytes = unhex(VOLUME_GOLDEN);
            bytes[at] = tag;
            assert_eq!(next.encode(), bytes, "byte {at} tag {tag}");
            assert_eq!(VolumeRecord::decode(&bytes), Ok(next));
        }
    }

    /// A shard record naming a standby encodes format 3: the format-2 bytes with version 3 and the standby host
    /// appended, [`SHARD_MAX`] bytes in all, and decodes back. A record without one encodes format 2, which this
    /// decoder and a format-2 reader both read. Format 3 refuses a zero standby, a standby equal to the owner, and a
    /// version byte that disagrees with the length.
    #[test]
    fn a_standby_encodes_format_3_and_its_absence_format_2() {
        let named = ShardRecord {
            standby: Some(host(13)),
            ..shard()
        };
        let bytes = named.encode();
        assert_eq!((bytes.len(), SHARD_MAX), (267, 267));
        let mut expected = unhex(SHARD_GOLDEN);
        expected[5] = 3;
        expected.extend(13u64.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(ShardRecord::decode(&bytes), Ok(named));
        assert_eq!(hex(&shard().encode()), SHARD_GOLDEN);
        let patched = |at: usize, value: &[u8]| {
            let mut patched = bytes.clone();
            patched[at..at + value.len()].copy_from_slice(value);
            ShardRecord::decode(&patched)
        };
        assert_eq!(
            patched(SHARD_LEN, &0u64.to_be_bytes()),
            Err(CodecError::Field)
        );
        assert_eq!(
            patched(SHARD_LEN, &11u64.to_be_bytes()),
            Err(CodecError::Field)
        );
        assert_eq!(patched(5, &[2]), Err(CodecError::Version));
        let mut short = unhex(SHARD_GOLDEN);
        short[5] = 3;
        assert_eq!(ShardRecord::decode(&short), Err(CodecError::Version));
        assert_eq!(
            ShardRecord::decode(&bytes[..SHARD_MAX - 1]),
            Err(CodecError::Length)
        );
    }

    /// A replacement that names, clears or changes the standby breaks the tenure rule: only the flip, the takeover and
    /// the designation, which skip the rule, change it, and the bump keeps it.
    #[test]
    fn a_standby_change_breaks_the_tenure_rule() {
        let prior = ShardRecord {
            standby: Some(host(13)),
            ..shard()
        };
        for standby in [None, Some(host(14))] {
            let next = ShardRecord { standby, ..prior };
            assert_eq!(next.succeeds(&prior), Err(SuccessorRule::Tenure));
            assert_eq!(prior.succeeds(&next), Err(SuccessorRule::Tenure));
        }
        assert_eq!(prior.succeeds(&prior), Ok(()));
    }

    /// A shard record at every cap, a full chain at `E = ATTEMPTS_MAX` and `g = 2^32 - 1` ending at `LSN_LIMIT + 1`,
    /// is exactly 267 bytes with a standby named and 259 without one, and a cut at `LSN_LIMIT + 1` decodes; a volume record with 8 pairs and 16 events is
    /// exactly 563 bytes; one more suffix, pair or event than the cap encodes bytes that refuse with `Length`. The
    /// store contract bounds both lengths by its item limit at compile time.
    #[test]
    fn records_at_every_cap_encode_their_complete_size() {
        let g = u64::from(u32::MAX);
        let epoch = u64::from(ATTEMPTS_MAX) * 2;
        let suffixes: Vec<_> = (0..MAX_CHAIN as u64)
            .map(|at| Suffix {
                session: session_of(g as u32, (epoch - 2 * (3 - at)) as u32),
                start: LSN_LIMIT - 7 + 2 * at,
                certified: LSN_LIMIT - 6 + 2 * at,
                end: LSN_LIMIT - 5 + 2 * at,
            })
            .collect();
        let full = ShardRecord {
            generation: ShardGeneration::new(g).unwrap(),
            attempts: ATTEMPTS_MAX,
            cut: LSN_LIMIT - 8,
            ancestry: chain(&suffixes),
            standby: Some(host(13)),
            ..shard()
        };
        let bytes = full.encode();
        assert_eq!(bytes.len(), 267);
        assert_eq!(ShardRecord::decode(&bytes), Ok(full));
        let unnamed = ShardRecord {
            standby: None,
            ..full
        };
        assert_eq!(unnamed.encode().len(), 259);
        assert_eq!(ShardRecord::decode(&unnamed.encode()), Ok(unnamed));
        let at_limit = ShardRecord {
            cut: LSN_LIMIT,
            ancestry: chain(&[suffixes[MAX_CHAIN - 1]]),
            ..full
        };
        assert_eq!(ShardRecord::decode(&at_limit.encode()), Ok(at_limit));
        let past_last = ShardRecord {
            cut: LSN_LIMIT + 1,
            ancestry: Ancestry::default(),
            ..full
        };
        assert_eq!(ShardRecord::decode(&past_last.encode()), Ok(past_last));
        assert_eq!(Ancestry::new(&[Suffix::default(); MAX_CHAIN + 1]), None);
        let mut five = bytes.clone();
        five[SHARD_LEN - ANCESTRY] = 5;
        assert_eq!(ShardRecord::decode(&five), Err(CodecError::Length));

        let mut volume = volume();
        volume.next = MAX_EVENTS as u32;
        volume.forced = false;
        volume.events = (0..MAX_EVENTS as u32)
            .map(|at| attach(at, u64::from(at) + 1))
            .collect();
        volume.pairs = (0..MAX_REGISTRANTS)
            .map(|at| RecordedPair {
                pair: pair(at as u8 + 1, 3, at as u32 + 1),
                ..recorded(at as u64 + 1, at as u8 + 1, at as u32)
            })
            .collect();
        let mut bound = volume.clone();
        for event in &mut bound.events {
            event.instance = Some(instance(event.host.get()));
        }
        for (full, len, version) in [(volume, 563, 2), (bound, VOLUME_MAX, 3)] {
            let bytes = full.encode();
            assert_eq!((bytes.len(), bytes[5]), (len, version));
            assert_eq!(VolumeRecord::decode(&bytes), Ok(full.clone()));
            let mut more_events = full.clone();
            more_events.push(EventKind::Attach, host(17), ERA);
            assert_eq!(
                VolumeRecord::decode(&more_events.encode()),
                Err(CodecError::Length)
            );
            let mut more_pairs = full;
            more_pairs.pairs.push(recorded(9, 9, 8));
            assert_eq!(
                VolumeRecord::decode(&more_pairs.encode()),
                Err(CodecError::Length)
            );
        }
    }

    /// Every single-byte corruption, each nonzero XOR mask at each offset, of each golden, of a shard record with no
    /// spare, checkpoint or ancestry, of a shard record naming a standby and of a whole-history volume record, either refuses or decodes to a value that encodes exactly the corrupted
    /// bytes, so no corruption decodes to a value with another encoding; pinned offsets refuse with the first check
    /// they fail.
    #[test]
    fn corruption_refuses_with_the_first_failed_check() {
        let shard_golden = unhex(SHARD_GOLDEN);
        let volume_golden = unhex(VOLUME_GOLDEN);
        let page_golden = unhex(PAGE_GOLDEN);
        let bare_shard = ShardRecord {
            spare: None,
            checkpoint: None,
            cut: 0,
            ancestry: Ancestry::default(),
            ..shard()
        }
        .encode();
        let standby_shard = ShardRecord {
            standby: Some(host(13)),
            ..shard()
        }
        .encode();
        for mask in 1..=u8::MAX {
            for golden in [&shard_golden, &bare_shard, &standby_shard] {
                for at in 0..golden.len() {
                    let mut bytes = golden.clone();
                    bytes[at] ^= mask;
                    if let Ok(value) = ShardRecord::decode(&bytes) {
                        assert_eq!(
                            value.encode(),
                            bytes,
                            "a flipped byte decodes to a value that encodes other bytes: shard byte {at} mask {mask:#x}"
                        );
                    }
                }
            }
            for golden in [&volume_golden, &fresh().encode()] {
                for at in 0..golden.len() {
                    let mut bytes = golden.clone();
                    bytes[at] ^= mask;
                    if let Ok(value) = VolumeRecord::decode(&bytes) {
                        assert_eq!(
                            value.encode(),
                            bytes,
                            "a flipped byte decodes to a value that encodes other bytes: volume byte {at} mask {mask:#x}"
                        );
                    }
                }
            }
            for at in 0..page_golden.len() {
                let mut bytes = page_golden.clone();
                bytes[at] ^= mask;
                if let Ok(value) = CoveragePage::decode(&bytes) {
                    assert_eq!(value.encode(), bytes, "page byte {at} mask {mask:#x}");
                }
            }
        }
        let patched = |at: usize, byte: u8| {
            let mut bytes = shard_golden.clone();
            bytes[at] = byte;
            ShardRecord::decode(&bytes)
        };
        assert_eq!(
            ShardRecord::decode(&shard_golden[..SHARD_LEN - 1]),
            Err(CodecError::Length)
        );
        assert_eq!(patched(0, b'X'), Err(CodecError::Magic));
        assert_eq!(patched(5, 1), Err(CodecError::Version));
        assert_eq!(patched(9, 0), Err(CodecError::Field), "shard zero");
        assert_eq!(patched(13, 0), Err(CodecError::Field), "generation zero");
        assert_eq!(patched(14, 0), Err(CodecError::Field), "volume length zero");
        assert_eq!(patched(35, 1), Err(CodecError::Field), "volume padding");
        assert_eq!(patched(43, 0), Err(CodecError::Field), "owner zero");
        assert_eq!(patched(44, 0x80), Err(CodecError::Field), "E above max");
        assert_eq!(patched(48, 2), Err(CodecError::Flag), "spare flag");
        assert_eq!(patched(78, 0), Err(CodecError::Field), "spare host zero");
        assert_eq!(patched(79, 2), Err(CodecError::Flag), "checkpoint flag");
        assert_eq!(patched(109, 0), Err(CodecError::Field), "page count zero");
        assert_eq!(patched(111, 0), Err(CodecError::Field), "page cap zero");
        let mut zero_namespace = shard_golden.clone();
        zero_namespace[114..130].fill(0);
        assert_eq!(
            ShardRecord::decode(&zero_namespace),
            Err(CodecError::Field),
            "namespace zero"
        );
        assert_eq!(patched(130, 5), Err(CodecError::Length), "chain count");
        assert_eq!(patched(258, 1), Err(CodecError::Flag), "nonzero tail");
        assert_eq!(patched(138, 0x09), Err(CodecError::Field), "odd epoch");
        for (at, part) in [(60, "spare"), (78, "spare host"), (94, "checkpoint")] {
            let mut bytes = bare_shard.clone();
            bytes[at] = 1;
            assert_eq!(
                ShardRecord::decode(&bytes),
                Err(CodecError::Flag),
                "bytes of an absent {part}"
            );
        }
        let mut cut_without_ck = bare_shard.clone();
        cut_without_ck[107] = 1;
        assert_eq!(
            ShardRecord::decode(&cut_without_ck),
            Err(CodecError::Field),
            "a cut without a checkpoint"
        );
        let mut onto_active = shard_golden.clone();
        onto_active[49..71].copy_from_slice(&shard_golden[14..36]);
        assert_eq!(
            ShardRecord::decode(&onto_active),
            Err(CodecError::Field),
            "a spare equal to the active volume"
        );

        for (at, byte, error, what) in [
            (28, 5, CodecError::Flag, "state"),
            (29, 2, CodecError::Flag, "source"),
            (30, 3, CodecError::Flag, "lineage"),
            (31, 3, CodecError::Flag, "modification"),
            (56, 2, CodecError::Flag, "force mark"),
            (65, 9, CodecError::Length, "pair count"),
            (66, 17, CodecError::Length, "event count"),
            (74, 0, CodecError::Field, "pair host zero"),
            (103, 3, CodecError::Flag, "event kind"),
            (111, 0, CodecError::Field, "event host zero"),
            (115, 1, CodecError::Field, "era below MIN_ERA"),
            (102, 4, CodecError::Field, "attach past the events"),
            (5, 1, CodecError::Version, "version"),
        ] {
            let mut bytes = volume_golden.clone();
            bytes[at] = byte;
            assert_eq!(VolumeRecord::decode(&bytes), Err(error), "{what}");
        }
        let mut zero_exhid = volume_golden.clone();
        zero_exhid[75..91].fill(0);
        assert_eq!(VolumeRecord::decode(&zero_exhid), Err(CodecError::Field));
        let mut zero_key_epoch = volume_golden.clone();
        zero_key_epoch[91..95].fill(0);
        assert_eq!(
            VolumeRecord::decode(&zero_key_epoch),
            Err(CodecError::Field)
        );
        assert_eq!(
            VolumeRecord::decode(&volume_golden[..volume_golden.len() - 1]),
            Err(CodecError::Length)
        );
        for fence in [
            1,
            2,
            session(0),
            session(9),
            session(u64::from(ActivatedEpoch::MAX) + 2),
            u64::MAX,
        ] {
            let mut bytes = volume_golden.clone();
            bytes[57..65].copy_from_slice(&fence.to_be_bytes());
            assert_eq!(
                VolumeRecord::decode(&bytes),
                Err(CodecError::Field),
                "fence {fence:#x}"
            );
        }
        let mut top = volume();
        top.fence = session(u64::from(ActivatedEpoch::MAX));
        assert_eq!(VolumeRecord::decode(&top.encode()), Ok(top));
        assert_eq!(
            CoveragePage::decode(&page_golden[..page_golden.len() - 1]),
            Err(CodecError::Length)
        );
        for len in [0, PAGE_FIXED - 4, PAGE_FIXED - 1] {
            assert_eq!(
                CoveragePage::decode(&page_golden[..len]),
                Err(CodecError::Length)
            );
            assert_eq!(
                CoveragePage::decode_owned(page_golden[..len].to_vec()),
                Err(CodecError::Length)
            );
        }
        let mut magic_and_length = page_golden.clone();
        magic_and_length[0] = b'X';
        magic_and_length.push(0);
        assert_eq!(
            CoveragePage::decode(&magic_and_length),
            Err(CodecError::Length),
            "length is checked before the magic"
        );
        let mut saturated = page_golden.clone();
        saturated[14] = 2;
        assert_eq!(CoveragePage::decode(&saturated), Err(CodecError::Flag));
        assert_eq!(CoveragePage::decode_owned(saturated), Err(CodecError::Flag));
    }

    /// Frozen version-1 goldens refuse under the version-2 decoders, version-2 bytes fail the version-1 decoder's
    /// pinned length check, and a version-2-length value under any other version refuses with `Version`; the page
    /// stays at version 1 and refuses version 2.
    #[test]
    fn older_and_newer_formats_refuse_each_other() {
        let (v1_shard, v1_volume) = (unhex(SHARD_V1), unhex(VOLUME_V1));
        assert_eq!(v1_shard.len(), 114);
        assert_eq!(
            ShardRecord::decode(&v1_shard),
            Err(CodecError::Length),
            "an older-format record decodes in the new era"
        );
        assert_eq!(
            VolumeRecord::decode(&v1_volume),
            Err(CodecError::Length),
            "an older-format record decodes in the new era"
        );
        let mut v1_at_v2_length = v1_shard.clone();
        v1_at_v2_length.resize(SHARD_LEN, 0);
        assert_eq!(
            ShardRecord::decode(&v1_at_v2_length),
            Err(CodecError::Version)
        );
        let v2_shard = unhex(SHARD_GOLDEN);
        assert_ne!(v2_shard.len(), 114, "the version-1 decoder's length check");
        let v2_volume = unhex(VOLUME_GOLDEN);
        for pairs in 0..=MAX_REGISTRANTS {
            for events in 0..=MAX_EVENTS {
                let v2_len = VOLUME_FIXED + PAIR * pairs + EVENT * events;
                assert!(
                    (0..=usize::from(u8::MAX)).all(|v1_count| v2_len != 53 + 13 * v1_count),
                    "a version-2 volume of {pairs} pairs and {events} events passes the version-1 length check"
                );
                let v3_len = VOLUME_FIXED + PAIR * pairs + ENTRY * events;
                assert!(
                    pairs > events || (0..=MAX_EVENTS).all(|v1_count| v3_len != 53 + 13 * v1_count),
                    "a version-3 volume of {pairs} pairs and {events} events passes the version-1 length check"
                );
            }
        }
        for version in [0u16, 1, 3, 0xFFFF] {
            let mut shard = v2_shard.clone();
            shard[4..6].copy_from_slice(&version.to_be_bytes());
            assert_eq!(ShardRecord::decode(&shard), Err(CodecError::Version));
            let mut volume = v2_volume.clone();
            volume[4..6].copy_from_slice(&version.to_be_bytes());
            assert_eq!(VolumeRecord::decode(&volume), Err(CodecError::Version));
        }
        let mut page = unhex(PAGE_GOLDEN);
        assert!(CoveragePage::decode(&page).is_ok());
        page[5] = 2;
        assert_eq!(CoveragePage::decode(&page), Err(CodecError::Version));
    }

    /// The ancestry decoder refuses every chain outside BOUNDED-MANIFEST, including a suffix ending past
    /// `LSN_LIMIT + 1`, and the cut refuses above `LSN_LIMIT + 1`, one past the last LSN a journal issues.
    #[test]
    fn ancestry_decoding_refuses_impossible_chains() {
        let decode = |record: ShardRecord| ShardRecord::decode(&record.encode());
        let with = |ancestry| ShardRecord {
            ancestry,
            ..shard()
        };
        let cases: [(&str, Ancestry); 12] = [
            (
                "overlapping ranges",
                chain(&[suffix(8, 90, 140, 141), suffix(10, 140, 150, 160)]),
            ),
            ("start at end", chain(&[suffix(8, 140, 140, 140)])),
            ("certified below start", chain(&[suffix(8, 90, 89, 140)])),
            ("certified above end", chain(&[suffix(8, 90, 141, 140)])),
            (
                "another generation",
                chain(&[Suffix {
                    session: session_of(4, 8),
                    ..suffix(8, 90, 140, 140)
                }]),
            ),
            ("odd epoch", chain(&[suffix(9, 90, 140, 140)])),
            ("epoch above 2E", chain(&[suffix(12, 90, 140, 140)])),
            ("epoch zero", chain(&[suffix(0, 90, 140, 140)])),
            (
                "sessions not increasing",
                chain(&[suffix(10, 90, 140, 140), suffix(8, 140, 150, 160)]),
            ),
            (
                "equal sessions",
                chain(&[suffix(8, 90, 140, 140), suffix(8, 140, 150, 160)]),
            ),
            ("first ends at the cut", chain(&[suffix(8, 90, 100, 100)])),
            ("first ends below the cut", chain(&[suffix(8, 50, 60, 60)])),
        ];
        for (what, ancestry) in cases {
            assert_eq!(decode(with(ancestry)), Err(CodecError::Field), "{what}");
        }
        assert_eq!(
            decode(ShardRecord {
                checkpoint: None,
                cut: 1,
                ancestry: Ancestry::default(),
                ..shard()
            }),
            Err(CodecError::Field),
            "a cut without a checkpoint"
        );
        let past = with(chain(&[suffix(10, 0, LSN_LIMIT + 2, LSN_LIMIT + 2)]));
        assert_eq!(
            decode(past),
            Err(CodecError::Field),
            "an end past LSN_LIMIT + 1"
        );
        let past_cut = ShardRecord {
            cut: LSN_LIMIT + 2,
            ancestry: Ancestry::default(),
            ..shard()
        };
        assert_eq!(
            decode(past_cut),
            Err(CodecError::Field),
            "a cut above LSN_LIMIT + 1"
        );
        let whole = with(chain(&[suffix(10, 0, LSN_LIMIT + 1, LSN_LIMIT + 1)]));
        assert_eq!(
            decode(whole),
            Ok(whole),
            "the whole LSN range a journal issues"
        );
        let two = with(chain(&[
            suffix(2, 100, 101, 101),
            suffix(10, 101, 102, 103),
        ]));
        assert_eq!(decode(two), Ok(two), "the lowest epoch and a gap");
    }

    /// A shard successor that changes an immutable field refuses with that field's rule, and one that drops the
    /// spare is admitted.
    #[test]
    fn shard_successors_keep_immutable_fields() {
        let shard = shard();
        let next = ShardRecord {
            spare: None,
            ..shard
        };
        assert_eq!(next.succeeds(&shard), Ok(()));
        assert_eq!(shard.succeeds(&shard), Ok(()));
        let refused: [(ShardRecord, SuccessorRule); 8] = [
            (
                ShardRecord {
                    shard: Shard::new(8).unwrap(),
                    ..shard
                },
                SuccessorRule::Identity,
            ),
            (
                ShardRecord {
                    pages: NonZeroU16::new(5).unwrap(),
                    ..shard
                },
                SuccessorRule::Pages,
            ),
            (
                ShardRecord {
                    page_cap: NonZeroU32::new(1).unwrap(),
                    ..shard
                },
                SuccessorRule::PageCap,
            ),
            (
                ShardRecord {
                    namespace: Namespace::new([0x22; 16]).unwrap(),
                    ..shard
                },
                SuccessorRule::Namespace,
            ),
            (
                ShardRecord {
                    attempts: 6,
                    ..shard
                },
                SuccessorRule::Tenure,
            ),
            (
                ShardRecord {
                    generation: ShardGeneration::new(4).unwrap(),
                    ..shard
                },
                SuccessorRule::Tenure,
            ),
            (
                ShardRecord {
                    active: VolumeId::new("vol-0c").unwrap(),
                    ..shard
                },
                SuccessorRule::Tenure,
            ),
            (
                ShardRecord {
                    owner: Host::new(12).unwrap(),
                    ..shard
                },
                SuccessorRule::Tenure,
            ),
        ];
        for (next, rule) in refused {
            assert_eq!(next.succeeds(&shard), Err(rule), "{next:?}");
        }
        for attempts in [ATTEMPTS_MAX + 1, 1 << 31, u32::MAX] {
            let next = ShardRecord { attempts, ..shard };
            assert_eq!(
                next.succeeds(&shard),
                Err(SuccessorRule::Tenure),
                "E = {attempts}"
            );
        }
    }

    /// The checkpoint moves only to a strictly later `(session, capture)` with a cut not lower, and the ancestry
    /// drops only the leading suffixes the new cut subsumes, keeps every other suffix's session, start and end,
    /// raises the certified end of any kept suffix, extends only a last suffix of the current session `g·2^32 + 2E`,
    /// and appends only a suffix of the current session after every prior suffix, which may continue the current
    /// session's own suffix once a cut drops it. A deposed tenure's session neither appends nor extends.
    #[test]
    fn checkpoint_and_ancestry_successors_consolidate_only_subsumed_history() {
        let shard = shard();
        let named = shard.checkpoint.unwrap();
        let later = NamedCheckpoint {
            capture: named.capture + 1,
            ..named
        };
        let admitted = [
            (
                "a later capture at the same cut",
                ShardRecord {
                    checkpoint: Some(later),
                    ..shard
                },
            ),
            (
                "a later session resets the capture",
                ShardRecord {
                    checkpoint: Some(NamedCheckpoint {
                        session: named.session + 2,
                        capture: 0,
                        ..named
                    }),
                    ..shard
                },
            ),
            (
                "a later checkpoint consolidates the first suffix",
                ShardRecord {
                    checkpoint: Some(later),
                    cut: 140,
                    ancestry: chain(&[suffix(10, 140, 150, 160)]),
                    ..shard
                },
            ),
            (
                "a later checkpoint keeps unsubsumed history",
                ShardRecord {
                    checkpoint: Some(later),
                    cut: 120,
                    ..shard
                },
            ),
            (
                "the last suffix extends and certifies",
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 140), suffix(10, 140, 170, 180)]),
                    ..shard
                },
            ),
            (
                "the last suffix certifies in place",
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 140), suffix(10, 140, 160, 160)]),
                    ..shard
                },
            ),
            (
                "a tenure continues its own suffix after its checkpoint covers it",
                ShardRecord {
                    checkpoint: Some(later),
                    cut: 160,
                    ancestry: chain(&[suffix(10, 160, 160, 170)]),
                    ..shard
                },
            ),
            (
                "a later session appends after a cut that drops every suffix",
                ShardRecord {
                    checkpoint: Some(later),
                    cut: 160,
                    ancestry: chain(&[suffix(12, 160, 160, 170)]),
                    attempts: 6,
                    ..shard
                },
            ),
            (
                "a later session appends",
                ShardRecord {
                    ancestry: chain(&[
                        suffix(8, 90, 140, 140),
                        suffix(10, 140, 150, 160),
                        suffix(12, 160, 160, 170),
                    ]),
                    attempts: 6,
                    ..shard
                },
            ),
        ];
        for (what, next) in admitted {
            let prior = ShardRecord {
                attempts: next.attempts,
                ..shard
            };
            assert_eq!(next.succeeds(&prior), Ok(()), "{what}");
        }
        let uncertified = ShardRecord {
            ancestry: chain(&[suffix(8, 90, 120, 140), suffix(10, 140, 150, 160)]),
            ..shard
        };
        assert_eq!(
            shard.succeeds(&uncertified),
            Ok(()),
            "a successor certifies an earlier tenure's suffix"
        );
        let deposed = ShardRecord {
            attempts: 6,
            ..shard
        };
        let one = ShardRecord {
            ancestry: chain(&[suffix(10, 140, 150, 160)]),
            ..shard
        };
        let covered = ShardRecord {
            checkpoint: Some(later),
            cut: 160,
            ..one
        };
        let deposed_one = ShardRecord { attempts: 6, ..one };
        let consolidated = ShardRecord {
            ancestry: Ancestry::default(),
            ..covered
        };
        let gapped = ShardRecord {
            ancestry: chain(&[suffix(8, 90, 130, 130), suffix(10, 140, 150, 160)]),
            ..shard
        };
        assert_eq!(
            ShardRecord {
                ancestry: chain(&[suffix(10, 160, 160, 170)]),
                ..consolidated
            }
            .succeeds(&consolidated),
            Ok(()),
            "an append at the prior cut after the ancestry was consolidated away"
        );
        let deposed_covered = ShardRecord {
            attempts: 6,
            ..covered
        };
        let refused_writes = [
            (
                "a deposed session extends its end",
                deposed,
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 140), suffix(10, 140, 150, 170)]),
                    ..deposed
                },
            ),
            (
                "a deposed session appends",
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 140)]),
                    ..deposed
                },
                deposed,
            ),
            (
                "a deposed session continues its suffix after a covering cut",
                ShardRecord { attempts: 6, ..one },
                ShardRecord {
                    attempts: 6,
                    ancestry: chain(&[suffix(10, 160, 160, 170)]),
                    ..covered
                },
            ),
            (
                "a continuation that starts inside the dropped suffix",
                one,
                ShardRecord {
                    ancestry: chain(&[suffix(10, 150, 160, 170)]),
                    ..covered
                },
            ),
            (
                "a later session that starts inside the dropped suffix",
                deposed_one,
                ShardRecord {
                    ancestry: chain(&[suffix(12, 150, 160, 170)]),
                    ..deposed_covered
                },
            ),
            (
                "two appended suffixes of the current session",
                deposed,
                ShardRecord {
                    ancestry: chain(&[
                        suffix(8, 90, 140, 140),
                        suffix(10, 140, 150, 160),
                        suffix(12, 160, 160, 165),
                        suffix(12, 165, 165, 170),
                    ]),
                    ..deposed
                },
            ),
            (
                "an appended suffix that ends at or below the new cut",
                deposed_one,
                ShardRecord {
                    cut: 170,
                    ancestry: chain(&[suffix(12, 160, 160, 165)]),
                    ..deposed_covered
                },
            ),
            (
                "an append below the prior cut after the ancestry was consolidated away",
                consolidated,
                ShardRecord {
                    ancestry: chain(&[suffix(10, 150, 160, 170)]),
                    ..consolidated
                },
            ),
            (
                "an extended earlier end across a gap",
                gapped,
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 130, 135), suffix(10, 140, 150, 160)]),
                    ..gapped
                },
            ),
            (
                "a later session that starts inside the kept last suffix",
                deposed,
                ShardRecord {
                    ancestry: chain(&[
                        suffix(8, 90, 140, 140),
                        suffix(10, 140, 150, 160),
                        suffix(12, 150, 160, 170),
                    ]),
                    ..deposed
                },
            ),
        ];
        for (what, prior, next) in refused_writes {
            assert_eq!(
                next.succeeds(&prior),
                Err(SuccessorRule::Ancestry),
                "{what}"
            );
        }
        let refused = [
            (
                "a cleared checkpoint",
                ShardRecord {
                    checkpoint: None,
                    cut: 0,
                    ancestry: Ancestry::default(),
                    ..shard
                },
                SuccessorRule::Checkpoint,
            ),
            (
                "an earlier capture",
                ShardRecord {
                    checkpoint: Some(NamedCheckpoint {
                        capture: named.capture - 1,
                        ..named
                    }),
                    ..shard
                },
                SuccessorRule::Checkpoint,
            ),
            (
                "an earlier session with a later capture",
                ShardRecord {
                    checkpoint: Some(NamedCheckpoint {
                        session: named.session - 2,
                        capture: named.capture + 1,
                        ..named
                    }),
                    ..shard
                },
                SuccessorRule::Checkpoint,
            ),
            (
                "another slot at the same identity",
                ShardRecord {
                    checkpoint: Some(NamedCheckpoint { slot: 3, ..named }),
                    ..shard
                },
                SuccessorRule::Checkpoint,
            ),
            (
                "other units at the same identity",
                ShardRecord {
                    checkpoint: Some(NamedCheckpoint { units: 41, ..named }),
                    ..shard
                },
                SuccessorRule::Checkpoint,
            ),
            (
                "a cut change at the same identity",
                ShardRecord { cut: 120, ..shard },
                SuccessorRule::Checkpoint,
            ),
            (
                "a lowered cut",
                ShardRecord {
                    checkpoint: Some(later),
                    cut: 95,
                    ..shard
                },
                SuccessorRule::Checkpoint,
            ),
            (
                "a dropped suffix the cut does not subsume",
                ShardRecord {
                    checkpoint: Some(later),
                    cut: 120,
                    ancestry: chain(&[suffix(10, 140, 150, 160)]),
                    ..shard
                },
                SuccessorRule::Ancestry,
            ),
            (
                "a dropped last suffix",
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 140)]),
                    ..shard
                },
                SuccessorRule::Ancestry,
            ),
            (
                "a changed start",
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 140), suffix(10, 141, 150, 160)]),
                    ..shard
                },
                SuccessorRule::Ancestry,
            ),
            (
                "a relabeled session",
                ShardRecord {
                    ancestry: chain(&[suffix(6, 90, 140, 140), suffix(10, 140, 150, 160)]),
                    ..shard
                },
                SuccessorRule::Ancestry,
            ),
            (
                "a lowered certified end",
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 140), suffix(10, 140, 149, 160)]),
                    ..shard
                },
                SuccessorRule::Ancestry,
            ),
            (
                "a shortened last end",
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 140), suffix(10, 140, 150, 159)]),
                    ..shard
                },
                SuccessorRule::Ancestry,
            ),
            (
                "an extended earlier end",
                ShardRecord {
                    ancestry: chain(&[suffix(8, 90, 140, 141), suffix(10, 141, 150, 160)]),
                    ..shard
                },
                SuccessorRule::Ancestry,
            ),
            (
                "a second appended suffix of the current session",
                ShardRecord {
                    ancestry: chain(&[
                        suffix(8, 90, 140, 140),
                        suffix(10, 140, 150, 160),
                        suffix(10, 160, 160, 170),
                    ]),
                    ..shard
                },
                SuccessorRule::Ancestry,
            ),
        ];
        for (what, next, rule) in refused {
            assert_eq!(next.succeeds(&shard), Err(rule), "{what}");
        }
        let empty = ShardRecord {
            checkpoint: None,
            cut: 0,
            ancestry: Ancestry::default(),
            ..shard
        };
        let first = ShardRecord {
            ancestry: chain(&[suffix(10, 140, 150, 160)]),
            ..shard
        };
        assert_eq!(first.succeeds(&empty), Ok(()), "a first checkpoint");
        let whole = ShardRecord {
            ancestry: chain(&[suffix(10, 100, LSN_LIMIT + 1, LSN_LIMIT + 1)]),
            ..shard
        };
        let consolidated = ShardRecord {
            checkpoint: Some(later),
            cut: LSN_LIMIT + 1,
            ancestry: Ancestry::default(),
            ..whole
        };
        assert_eq!(
            ShardRecord::decode(&consolidated.encode()),
            Ok(consolidated)
        );
        assert_eq!(
            consolidated.succeeds(&whole),
            Ok(()),
            "a cut one past LSN_LIMIT drops the suffix that ends there"
        );
        assert_eq!(
            shard.succeeds(&empty),
            Err(SuccessorRule::Ancestry),
            "a first checkpoint that appends an earlier session's suffix"
        );
    }

    /// A chain at [`MAX_CHAIN`] admits a successor that keeps every suffix and refuses one with a fifth, so the
    /// record keeps its history instead of truncating an ancestor to make room.
    #[test]
    fn a_chain_at_its_cap_refuses_a_fifth_suffix_and_keeps_the_record() {
        let full: Vec<_> = (0..MAX_CHAIN as u64)
            .map(|at| suffix(2 + 2 * at, 100 + 10 * at, 110 + 10 * at, 110 + 10 * at))
            .collect();
        let at_cap = ShardRecord {
            ancestry: chain(&full),
            ..shard()
        };
        assert_eq!(ShardRecord::decode(&at_cap.encode()), Ok(at_cap));
        let mut five = full.clone();
        five.push(suffix(10, 140, 150, 150));
        assert_eq!(Ancestry::new(&five), None);
        let mut bytes = at_cap.encode();
        bytes[SHARD_LEN - ANCESTRY] = MAX_CHAIN as u8 + 1;
        assert_eq!(ShardRecord::decode(&bytes), Err(CodecError::Length));
        let truncated = ShardRecord {
            ancestry: chain(&five[1..]),
            ..at_cap
        };
        assert_eq!(
            truncated.succeeds(&at_cap),
            Err(SuccessorRule::Ancestry),
            "dropping the oldest suffix without a subsuming cut"
        );
        let consolidated = ShardRecord {
            checkpoint: Some(NamedCheckpoint {
                capture: 10,
                ..at_cap.checkpoint.unwrap()
            }),
            cut: 110,
            ancestry: chain(&five[1..]),
            ..at_cap
        };
        assert_eq!(consolidated.succeeds(&at_cap), Ok(()));
    }

    /// `E` at [`ATTEMPTS_MAX`] encodes and decodes, and one more refuses with `Field`.
    #[test]
    fn attempts_at_their_maximum_encode_and_one_more_refuses() {
        let at_max = ShardRecord {
            attempts: ATTEMPTS_MAX,
            ..shard()
        };
        assert_eq!(ShardRecord::decode(&at_max.encode()), Ok(at_max));
        let over = ShardRecord {
            attempts: ATTEMPTS_MAX + 1,
            ..shard()
        };
        assert_eq!(ShardRecord::decode(&over.encode()), Err(CodecError::Field));
    }

    /// A volume successor may remove an event prefix and append events.
    #[test]
    fn volume_history_compacts_only_facts_the_record_retains() {
        let volume = volume();
        let mut appended = volume.clone();
        appended.push(EventKind::Detach, host(12), 8);
        appended.state = VolumeState::Retired;
        assert_eq!(appended.succeeds(&volume), Ok(()));
        let mut compacted = volume.clone();
        compacted.events.remove(0);
        compacted.pairs.clear();
        compacted.fence += 2;
        assert_eq!(compacted.succeeds(&volume), Ok(()));
        let mut all = compacted.clone();
        all.events.clear();
        assert_eq!(all.succeeds(&compacted), Ok(()));
        let mut past = all.clone();
        past.next = 5;
        assert_eq!(
            past.succeeds(&compacted),
            Err(SuccessorRule::Events),
            "a next past the numbers the new events take"
        );
        type Change = (&'static str, fn(&mut VolumeRecord), SuccessorRule);
        let changes: [Change; 9] = [
            (
                "source",
                |r| r.source = CreationSource::Foreign,
                SuccessorRule::Source,
            ),
            (
                "lineage",
                |r| r.lineage = Lineage::Snapshot,
                SuccessorRule::Lineage,
            ),
            ("layout", |r| r.layout.slots = 4, SuccessorRule::Layout),
            ("lowered next", |r| r.next = 3, SuccessorRule::Events),
            (
                "a changed retained event",
                |r| r.events[0].kind = EventKind::Detach,
                SuccessorRule::Events,
            ),
            (
                "a changed era",
                |r| r.events[1].era += 1,
                SuccessorRule::Events,
            ),
            (
                "a compaction that renumbers the kept event",
                |r| {
                    r.events.remove(0);
                    r.events[0].seq = 2;
                },
                SuccessorRule::Events,
            ),
            (
                "state",
                |r| r.state = VolumeState::Fresh,
                SuccessorRule::State,
            ),
            (
                "identity",
                |r| r.volume = VolumeId::new("vol-0c").unwrap(),
                SuccessorRule::Identity,
            ),
        ];
        for (what, change, rule) in changes {
            let mut next = volume.clone();
            change(&mut next);
            assert_eq!(next.succeeds(&volume), Err(rule), "{what}");
        }
        let mut unforced = compacted.clone();
        unforced.forced = false;
        assert_eq!(unforced.succeeds(&compacted), Err(SuccessorRule::Events));
        assert_eq!(
            VolumeRecord::decode(&unforced.encode()),
            Ok(unforced),
            "a compacted record may hold no force mark when the prior did not"
        );
        let mut unmarked = volume.clone();
        unmarked.forced = false;
        assert_eq!(
            VolumeRecord::decode(&unmarked.encode()),
            Err(CodecError::Field),
            "a retained force-detach without the mark"
        );
        let mut whole_marked = fresh();
        whole_marked.forced = true;
        assert_eq!(
            VolumeRecord::decode(&whole_marked.encode()),
            Err(CodecError::Field),
            "a whole history marked without a force-detach"
        );
        let mut unpinned = volume.clone();
        unpinned.events.clear();
        assert_eq!(
            VolumeRecord::decode(&unpinned.encode()),
            Err(CodecError::Field),
            "a dropped event a pair references"
        );
        let modified = VolumeRecord {
            modification: Some(Modification::InProgress),
            ..volume.clone()
        };
        assert_eq!(volume.succeeds(&modified), Err(SuccessorRule::Modification));
        let mut full = fresh();
        full.next = MAX_EVENTS as u32;
        full.events = (0..MAX_EVENTS as u32)
            .map(|at| attach(at, u64::from(at) + 1))
            .collect();
        full.pairs = vec![recorded(1, 0xE1, 0)];
        assert_eq!(VolumeRecord::decode(&full.encode()), Ok(full.clone()));
        let mut seventeenth = full.clone();
        seventeenth.push(EventKind::Attach, host(17), ERA);
        assert_eq!(
            VolumeRecord::decode(&seventeenth.encode()),
            Err(CodecError::Length),
            "a 17th event without compaction"
        );
        seventeenth.events.remove(0);
        assert_eq!(
            VolumeRecord::decode(&seventeenth.encode()),
            Err(CodecError::Field),
            "a 17th event that compacts the event a pair pins"
        );
        let mut fits = volume.clone();
        fits.pairs.clear();
        fits.next = u32::MAX;
        fits.events[0].seq = u32::MAX - 2;
        fits.events[1].seq = u32::MAX - 1;
        let bytes = fits.encode();
        assert_eq!(bytes[52..56], (u32::MAX - 2).to_be_bytes(), "first");
        assert_eq!(VolumeRecord::decode(&bytes), Ok(fits.clone()));
        let mut overflow = bytes;
        overflow[55] += 1;
        assert_eq!(
            VolumeRecord::decode(&overflow),
            Err(CodecError::Field),
            "first + e overflows"
        );
        let mut exhausted = fits.clone();
        assert_eq!(exhausted.push(EventKind::Force, host(13), ERA), None);
        assert_eq!(
            exhausted, fits,
            "a push with no number left changes nothing"
        );
        let mut last = fits;
        last.events.push(attach(u32::MAX, 13));
        assert_eq!(
            VolumeRecord::decode(&last.encode()),
            Err(CodecError::Field),
            "an event at the last sequence number leaves no next one"
        );
        let mut final_push = fresh();
        final_push.next = u32::MAX - 1;
        final_push.events[0].seq = u32::MAX - 2;
        assert_eq!(
            final_push.push(EventKind::Attach, host(13), ERA),
            Some(u32::MAX - 1)
        );
        assert_eq!(final_push.next, u32::MAX);
        assert_eq!(
            VolumeRecord::decode(&final_push.encode()),
            Ok(final_push.clone()),
            "the last number takes an event"
        );
    }

    /// Pairs append freely, leave only with a fence raise, and refuse a lowered fence; a duplicate pair, one
    /// naming a detach event, another host's attach, a zero EXHID or a bad key fails to decode, and so do two pairs
    /// that pin one attach event or share an EXHID or a key.
    #[test]
    fn recorded_pairs_leave_only_with_a_fence() {
        let volume = volume();
        let mut added = volume.clone();
        added.push(EventKind::Attach, host(13), ERA);
        added.pairs.push(RecordedPair {
            pair: pair(0xE2, 4, 8),
            ..recorded(13, 0xE2, 4)
        });
        assert_eq!(added.succeeds(&volume), Ok(()));
        assert_eq!(VolumeRecord::decode(&added.encode()), Ok(added.clone()));
        let mut removed = volume.clone();
        removed.pairs.clear();
        assert_eq!(removed.succeeds(&volume), Err(SuccessorRule::Pairs));
        let mut changed = volume.clone();
        changed.pairs[0].pair = pair(0xE1, 3, 8);
        assert_eq!(changed.succeeds(&volume), Err(SuccessorRule::Pairs));
        let mut moved_host = volume.clone();
        moved_host.pairs[0].host = host(9);
        assert_eq!(moved_host.succeeds(&volume), Err(SuccessorRule::Pairs));
        let mut moved_pin = volume.clone();
        moved_pin.push(EventKind::Attach, host(12), ERA);
        moved_pin.pairs[0].attach = 4;
        assert_eq!(
            VolumeRecord::decode(&moved_pin.encode()),
            Ok(moved_pin.clone())
        );
        assert_eq!(moved_pin.succeeds(&volume), Err(SuccessorRule::Pairs));
        removed.fence += 2;
        assert_eq!(removed.succeeds(&volume), Ok(()));
        let mut lowered = volume.clone();
        lowered.fence -= 2;
        assert_eq!(lowered.succeeds(&volume), Err(SuccessorRule::Fence));
        type Corruption = (&'static str, fn(&mut VolumeRecord));
        let refused: [Corruption; 4] = [
            ("a duplicate pair", |r| r.pairs.push(recorded(12, 0xE1, 3))),
            ("a pair naming a detach", |r| {
                r.events[1].kind = EventKind::Detach;
            }),
            ("another host's attach", |r| r.pairs[0].host = host(9)),
            ("an attach below the first retained number", |r| {
                r.pairs[0].attach = 1
            }),
        ];
        for (what, change) in refused {
            let mut next = volume.clone();
            change(&mut next);
            assert_eq!(
                VolumeRecord::decode(&next.encode()),
                Err(CodecError::Field),
                "{what}"
            );
        }
        let mut same_pair = added.clone();
        same_pair.pairs[1].pair = same_pair.pairs[0].pair;
        assert_eq!(
            VolumeRecord::decode(&same_pair.encode()),
            Err(CodecError::Field),
            "one (EXHID, key) pinned to two hosts' attach events"
        );
        let mut other_key = added.clone();
        other_key.pairs[1].pair = pair(0xE1, 3, 8);
        let mut shared_key = added.clone();
        shared_key.pairs[1].pair = Pair {
            key: shared_key.pairs[0].pair.key,
            ..pair(0xE3, 3, 8)
        };
        let mut same_attach_twice = added.clone();
        same_attach_twice.pairs[1] = RecordedPair {
            pair: pair(0xE3, 4, 9),
            ..recorded(12, 0xE3, 3)
        };
        for (what, record) in [
            ("one EXHID under two keys", other_key),
            ("one key under two EXHIDs", shared_key),
            ("two pairs pin one attach event", same_attach_twice),
        ] {
            assert_eq!(
                VolumeRecord::decode(&record.encode()),
                Err(CodecError::Field),
                "{what}"
            );
        }
        let mut distinct = added.clone();
        distinct.pairs[1].pair = pair(0xE3, 4, 9);
        assert_eq!(
            VolumeRecord::decode(&distinct.encode()),
            Ok(distinct),
            "pairs of distinct attach events with distinct EXHIDs and keys"
        );
    }

    /// An attachment event of a binary era below [`MIN_ERA`] refuses to decode, one at the floor decodes, and an
    /// event of a later era than [`ERA`] decodes, so the written era rises without a format change.
    #[test]
    fn events_of_an_earlier_binary_era_refuse() {
        let mut old = fresh();
        old.events[0].era = MIN_ERA - 1;
        assert_eq!(VolumeRecord::decode(&old.encode()), Err(CodecError::Field));
        old.events[0].era = MIN_ERA;
        assert_eq!(VolumeRecord::decode(&old.encode()), Ok(old.clone()));
        old.events[0].era = ERA + 1;
        assert_eq!(VolumeRecord::decode(&old.encode()), Ok(old));
    }

    /// `attached_once` requires a complete history because compaction can hide earlier attaches.
    #[test]
    fn attached_once_requires_an_uncompacted_history() {
        let fresh = fresh();
        assert!(fresh.attached_once(host(12)));
        assert!(!fresh.attached_once(host(13)));
        let mut compacted = fresh.clone();
        compacted.events[0].seq = 1;
        compacted.next = 2;
        assert!(!compacted.attached_once(host(12)));
        let mut two = fresh;
        two.push(EventKind::Attach, host(12), ERA);
        assert!(!two.attached_once(host(12)));
    }

    /// A coverage page never lowers its fence or clears saturation.
    #[test]
    fn page_successors_keep_fence_and_saturation() {
        let page = page();
        let lowered = CoveragePage {
            fence: page.fence - 1,
            ..page.clone()
        };
        assert_eq!(lowered.succeeds(&page), Err(SuccessorRule::Fence));
        let saturated = CoveragePage {
            saturated: true,
            entries: Vec::new(),
            ..page.clone()
        };
        assert_eq!(saturated.succeeds(&page), Ok(()));
        assert_eq!(page.succeeds(&saturated), Err(SuccessorRule::Saturation));
    }

    /// An enrollment needs a fresh or active volume and the host's live attach, refuses a different pair for that
    /// attach, a pair under another key than the attach's own (an earlier attach's key included), a pair sharing a
    /// recorded host ID and a full record, returns `None` for the pair already
    /// enrolled, and appends a pair every successor rule admits; a re-attach enrolls a new pair and keeps the old. The
    /// pairs recorded beside a host are each other host's recorded pairs, a detached host's pair and the pair of a
    /// reattached host's ended attach included.
    #[test]
    fn enrollment_requires_the_hosts_live_attach_and_a_distinct_pair() {
        let wide = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
        let narrow = crate::failover::bounds::Bounds::new(1, 1, u64::MAX, 100, 100, 0).unwrap();
        let base = fresh();
        // Each pair carries the key of its attach entry: entry 0 is host 12's attach, entry 1 host 13's.
        let (own, other) = (pair(0xE1, 1, 1), pair(0xE2, 1, 2));
        let next = base.enroll(host(12), own, &wide).unwrap().unwrap();
        assert_eq!(
            next.pairs,
            vec![RecordedPair {
                host: host(12),
                pair: own,
                attach: 0
            }]
        );
        assert_eq!(next.succeeds(&base), Ok(()));
        assert_eq!(VolumeRecord::decode(&next.encode()), Ok(next.clone()));
        assert_eq!(next.enrolled(host(12)), Some(own));
        assert_eq!(next.enroll(host(12), own, &wide), Ok(None));
        assert_eq!(
            next.enroll(host(12), other, &wide),
            Err(Enrollment::Altered)
        );
        for state in [
            VolumeState::Provisioning,
            VolumeState::Retired,
            VolumeState::Deleted,
        ] {
            let record = VolumeRecord {
                state,
                ..base.clone()
            };
            assert_eq!(
                record.enroll(host(12), own, &wide),
                Err(Enrollment::State),
                "{state:?}"
            );
        }
        assert_eq!(
            base.enroll(host(13), own, &wide),
            Err(Enrollment::Unattached)
        );
        let mut detached = next.clone();
        detached.push(EventKind::Detach, host(12), ERA);
        assert_eq!(
            detached.enroll(host(12), other, &wide),
            Err(Enrollment::Unattached)
        );
        let mut two = next.clone();
        two.push(EventKind::Attach, host(13), ERA);
        let same_host_id = Pair {
            key: other.key,
            ..own
        };
        assert_eq!(
            two.enroll(host(13), same_host_id, &wide),
            Err(Enrollment::Shared)
        );
        let same_key = Pair {
            exhid: other.exhid,
            ..own
        };
        assert_eq!(
            two.enroll(host(13), same_key, &wide),
            Err(Enrollment::Key),
            "host 12's key is not the key of host 13's attach"
        );
        let standby = two.enroll(host(13), other, &wide).unwrap().unwrap();
        assert_eq!(standby.succeeds(&two), Ok(()));
        assert_eq!(
            standby.live_hosts().collect::<Vec<_>>(),
            vec![host(12), host(13)]
        );
        let beside = |record: &VolumeRecord, of: u64| {
            record
                .recorded_beside(host(of))
                .copied()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            (beside(&standby, 13), beside(&standby, 12)),
            (vec![own], vec![other])
        );
        let ended_of =
            |record: &VolumeRecord| record.ended_attach_pairs().copied().collect::<Vec<_>>();
        assert_eq!(ended_of(&standby), Vec::<Pair>::new());
        let mut marked = standby.clone();
        marked.events[0].kind = EventKind::Ended;
        assert_eq!(ended_of(&marked), vec![own], "an entry marked ended");
        let mut ended = standby.clone();
        ended.push(EventKind::Detach, host(12), ERA);
        assert_eq!(beside(&ended, 13), vec![own], "a detached host's pair");
        assert_eq!(ended_of(&ended), vec![own], "a detached host's pair");
        ended.push(EventKind::Attach, host(12), ERA);
        let mut forced = ended.clone();
        forced.push(EventKind::Force, host(14), ERA);
        assert_eq!(
            forced.hosts_with_attach_event().collect::<Vec<_>>(),
            vec![host(12), host(13)],
            "each host with an attach once, by its first attach"
        );
        assert_eq!(
            beside(&ended, 13),
            vec![own],
            "a pair recorded for an ended attach of a reattached host"
        );
        assert_eq!(
            ended_of(&ended),
            vec![own],
            "a reattached host's earlier pair"
        );
        assert_eq!(beside(&ended, 12), vec![other]);
        let mut full = base.clone();
        full.next = 9;
        full.events = (0..9).map(|at| attach(at, u64::from(at) + 20)).collect();
        full.pairs = (0..MAX_REGISTRANTS as u32)
            .map(|at| RecordedPair {
                host: host(20 + u64::from(at)),
                pair: pair(0x10 + at as u8, 1, at + 1),
                attach: at,
            })
            .collect();
        assert_eq!(
            full.enroll(host(28), pair(0x40, 1, 9), &wide),
            Err(Enrollment::Full)
        );
        assert_eq!(
            full.enroll(host(28), pair(0x40, 2, 9), &wide),
            Err(Enrollment::Key),
            "a wrong key refuses before the full record"
        );
        assert_eq!(
            next.enroll(host(12), own, &narrow),
            Ok(None),
            "the enrolled pair replays under any bound"
        );
        assert_eq!(
            two.enroll(host(13), other, &narrow),
            Err(Enrollment::Full),
            "N_reg = 1 admits the owner's pair alone"
        );
        let mut again = detached.clone();
        again.push(EventKind::Attach, host(12), ERA);
        let reattach = pair(0xE2, 1, 3);
        assert_eq!(again.attach_key(host(12)), Some(reattach.key));
        assert_eq!(
            again.enroll(
                host(12),
                Pair {
                    exhid: other.exhid,
                    ..own
                },
                &wide
            ),
            Err(Enrollment::Key),
            "the new attach under the key of host 12's earlier attach"
        );
        let reattached = again.enroll(host(12), reattach, &wide).unwrap().unwrap();
        assert_eq!(
            reattached.pairs,
            vec![
                RecordedPair {
                    host: host(12),
                    pair: own,
                    attach: 0
                },
                RecordedPair {
                    host: host(12),
                    pair: reattach,
                    attach: 2
                },
            ]
        );
        assert_eq!(reattached.succeeds(&again), Ok(()));
        assert_eq!(
            VolumeRecord::decode(&reattached.encode()),
            Ok(reattached.clone())
        );
        assert!(reattached.has_attach_event(host(12)) && !reattached.has_attach_event(host(13)));
    }

    /// KEY-PER-ATTACH: a host's key is the key of its live attach entry, epoch 1 and incarnation `seq + 1`, written
    /// out here as raw device keys, and it follows the entry's stored number across numbering gaps. A detached, ended
    /// or absent host has none, a reattach takes a new key, and the keys of 200 attaches numbered 0 to 199 are
    /// distinct while compaction shifts each entry's position away from its number; the loop checks the mapping over
    /// record-level pushes, which keep a host's earlier attach in the history. The last number has no key, since its
    /// incarnation would be reserved.
    #[test]
    fn each_attach_takes_the_key_of_its_own_sequence_number() {
        let raw = |record: &VolumeRecord, of: u64| record.attach_key(host(of)).map(Key::encode);
        let mut record = fresh();
        assert_eq!(raw(&record, 12), Some((1 << 32) | 1));
        assert_eq!(raw(&record, 13), None, "no entry");
        record.push(EventKind::Attach, host(13), ERA);
        record.push(EventKind::Detach, host(12), ERA);
        assert_eq!(
            (raw(&record, 12), raw(&record, 13)),
            (None, Some((1 << 32) | 2))
        );
        record.push(EventKind::Attach, host(12), ERA);
        assert_eq!(
            raw(&record, 12),
            Some((1 << 32) | 4),
            "a reattach takes its own key"
        );
        record.events[1].kind = EventKind::Ended;
        assert_eq!(raw(&record, 13), None, "an ended entry");
        let gapped = entries();
        assert_eq!(
            (raw(&gapped, 12), raw(&gapped, 15)),
            (Some((1 << 32) | 4), Some((1 << 32) | 9)),
            "entries 3 and 8, at positions 1 and 4 behind a gap"
        );
        let mut history = fresh();
        let mut life = std::collections::HashSet::from([history.attach_key(host(12)).unwrap()]);
        for at in 1..200u32 {
            if history.events.len() == MAX_EVENTS {
                history.events.remove(0);
            }
            history.push(EventKind::Attach, host(12 + u64::from(at % 3)), ERA);
            let key = history.attach_key(host(12 + u64::from(at % 3))).unwrap();
            assert_eq!(key.encode(), (1 << 32) | u64::from(at + 1), "attach {at}");
            assert!(
                life.insert(key),
                "attach {at} reuses no key of the volume's life"
            );
        }
        assert_eq!(life.len(), 200);
        assert_eq!(
            attachment_key(0xFFFF_FFFD).map(Key::encode),
            Some((1 << 32) | 0xFFFF_FFFE)
        );
        assert_eq!(attachment_key(0xFFFF_FFFE), None);
        let mut last = fresh();
        last.events[0].seq = 0xFFFF_FFFE;
        last.next = u32::MAX;
        let wide = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
        assert_eq!(raw(&last, 12), None);
        assert_eq!(
            last.enroll(host(12), pair(0xE1, 1, 1), &wide),
            Err(Enrollment::Key)
        );
        let enrollment =
            |record: &VolumeRecord, of: u64| record.enrollment_key(host(of)).map(Key::encode);
        assert_eq!(enrollment(&last, 13), None, "no live attach");
        assert_eq!(enrollment(&last, 12), None, "no recorded pair and no key");
        assert_eq!(
            enrollment(&fresh(), 12),
            Some((1 << 32) | 1),
            "the derived key"
        );
        let mut kept = last.clone();
        kept.pairs.push(RecordedPair {
            host: host(12),
            pair: pair(0xE1, 3, 7),
            attach: 0xFFFF_FFFE,
        });
        assert_eq!(
            enrollment(&kept, 12),
            Some((3 << 32) | 7),
            "the recorded pair's key, at a number with no key"
        );
        assert_eq!(kept.enroll(host(12), pair(0xE1, 3, 7), &wide), Ok(None));
    }

    /// A record whose pair carries a key no attach entry derives stays readable: it decodes, its pair replays as
    /// enrolled and no other pair takes its attach. A retained epoch-1 pair that holds a later entry's key refuses
    /// that entry `Shared` and, once a write drops it, leaves the key to that entry: KEY-PER-ATTACH holds for the
    /// pairs enrolled under the rule.
    #[test]
    fn a_retained_pair_under_an_older_key_stays_readable_and_replays() {
        let wide = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
        let older = pair(0xE1, 3, 7);
        let mut record = fresh();
        record.pairs.push(RecordedPair {
            host: host(12),
            pair: older,
            attach: 0,
        });
        assert_ne!(record.attach_key(host(12)), Some(older.key));
        assert_eq!(VolumeRecord::decode(&record.encode()), Ok(record.clone()));
        assert_eq!(record.succeeds(&fresh()), Ok(()));
        assert_eq!(record.enrolled(host(12)), Some(older));
        assert_eq!(record.enroll(host(12), older, &wide), Ok(None));
        assert_eq!(
            record.enroll(host(12), pair(0xE1, 1, 1), &wide),
            Err(Enrollment::Altered),
            "the attach's own key does not displace the recorded pair"
        );
        let mut legacy = fresh();
        legacy.pairs.push(RecordedPair {
            host: host(12),
            pair: pair(0xE1, 1, 2),
            attach: 0,
        });
        legacy.push(EventKind::Attach, host(13), ERA);
        let later = pair(0xE2, 1, 2);
        assert_eq!(legacy.attach_key(host(13)), Some(later.key));
        assert_eq!(
            legacy.enroll(host(13), later, &wide),
            Err(Enrollment::Shared),
            "entry 1's key, held by entry 0's retained epoch-1 pair"
        );
        let mut dropped = legacy.clone();
        dropped.pairs.clear();
        dropped.fence = session(2);
        assert_eq!(dropped.succeeds(&legacy), Ok(()));
        assert_eq!(VolumeRecord::decode(&dropped.encode()), Ok(dropped.clone()));
        let taken = dropped.enroll(host(13), later, &wide).unwrap().unwrap();
        assert_eq!(
            taken.enrolled(host(13)),
            Some(later),
            "once the pair leaves, entry 1 enrolls the key entry 0's pair held"
        );
        assert_eq!(taken.succeeds(&dropped), Ok(()));
        assert_eq!(VolumeRecord::decode(&taken.encode()), Ok(taken));
    }

    #[test]
    fn an_enrollment_allocates_its_two_vectors_once_and_a_replay_or_refusal_allocates_nothing() {
        let wide = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
        let mut two = fresh()
            .enroll(host(12), pair(0xE1, 1, 1), &wide)
            .unwrap()
            .unwrap();
        two.push(EventKind::Attach, host(13), ERA);
        let standby = pair(0xE2, 1, 2);
        let (allocations, reallocations) = (
            crate::instrument::allocations(),
            crate::instrument::reallocations(),
        );
        let next = two.enroll(host(13), standby, &wide).unwrap().unwrap();
        assert_eq!(
            crate::instrument::allocations() - allocations,
            2,
            "one event vector and one pair vector"
        );
        assert_eq!(crate::instrument::reallocations(), reallocations);
        let allocations = crate::instrument::allocations();
        assert_eq!(next.enroll(host(13), standby, &wide), Ok(None));
        assert_eq!(
            next.enroll(host(14), pair(0xE3, 3, 9), &wide),
            Err(Enrollment::Unattached)
        );
        assert_eq!(crate::instrument::allocations(), allocations);
    }

    /// Stored fixture events encode era 2 independently of [`ERA`].
    const STORED_ERA: u32 = 2;

    const VOLUME_V2_FIXTURE: &[u8] = include_bytes!("fixtures/volume-v2.rec");
    const VOLUME_V3_FIXTURE: &[u8] = include_bytes!("fixtures/volume-v3.rec");

    fn entry(
        seq: u32,
        kind: EventKind,
        host_id: u64,
        era: u32,
        id: Option<&str>,
    ) -> AttachmentEvent {
        AttachmentEvent {
            seq,
            kind,
            host: host(host_id),
            era,
            instance: id.map(|name| InstanceId::new(name).unwrap()),
        }
    }

    /// `entries()` models `fixtures/volume-v3.rec` after compaction of sequence numbers 4 and 6. The pair with
    /// `attach: 5` survives the transition to `Ended`.
    fn entries() -> VolumeRecord {
        VolumeRecord {
            next: 9,
            pairs: vec![
                recorded(12, 0xE1, 3),
                RecordedPair {
                    host: host(13),
                    pair: pair(0xE2, 4, 8),
                    attach: 5,
                },
            ],
            events: vec![
                entry(2, EventKind::Force, 9, STORED_ERA, None),
                entry(3, EventKind::Attach, 12, 8, Some("i-0000000c")),
                entry(
                    5,
                    EventKind::Ended,
                    13,
                    STORED_ERA,
                    Some("i-0000000000000000d"),
                ),
                entry(7, EventKind::Gone, 14, STORED_ERA, Some("i-0000000e")),
                entry(8, EventKind::Attach, 15, STORED_ERA, None),
            ],
            ..volume()
        }
    }

    #[test]
    fn each_volume_format_decodes_its_stored_fixture() {
        assert_eq!(VOLUME_V2_FIXTURE, unhex(VOLUME_GOLDEN));
        assert_eq!(VolumeRecord::decode(VOLUME_V2_FIXTURE), Ok(volume()));
        assert_eq!(VOLUME_V3_FIXTURE[4..6], [0, 3]);
        assert_eq!(VOLUME_V3_FIXTURE.len(), VOLUME_FIXED + 2 * PAIR + 5 * ENTRY);
        assert_eq!(VolumeRecord::decode(VOLUME_V3_FIXTURE), Ok(entries()));
        assert_eq!(entries().encode(), VOLUME_V3_FIXTURE);
    }

    #[test]
    fn format_3_encodes_only_what_format_2_cannot_express() {
        let version = |record: &VolumeRecord| record.encode()[5];
        let mut compacted = fresh();
        compacted.events.clear();
        compacted.next = 7;
        for record in [fresh(), volume(), compacted.clone()] {
            assert_eq!(version(&record), 2, "{record:?}");
        }
        let mut bound = fresh();
        bound.events[0].instance = Some(instance(12));
        let mut ended = fresh();
        ended.events[0].kind = EventKind::Ended;
        let mut gone = fresh();
        gone.events[0].kind = EventKind::Gone;
        let mut gap = fresh();
        gap.push(EventKind::Attach, host(13), ERA);
        gap.push(EventKind::Attach, host(14), ERA);
        gap.events.remove(1);
        let mut tail = fresh();
        tail.next = 2;
        assert!(fresh().uncompacted() && !gap.uncompacted() && !tail.uncompacted());
        assert!(fresh().attached_once(host(12)));
        assert!(!gap.attached_once(host(12)) && !tail.attached_once(host(12)));
        assert_eq!(
            ended.succeeds(&fresh()),
            Ok(()),
            "a format-2 record ends its attach"
        );
        for (what, record) in [
            ("a bound instance", bound.clone()),
            ("an ended entry", ended),
            ("a gone entry", gone),
            ("a gap between retained numbers", gap),
            ("a gap after the last retained number", tail),
        ] {
            assert_eq!(version(&record), 3, "{what}");
            assert_eq!(VolumeRecord::decode(&record.encode()), Ok(record), "{what}");
        }
        let mut unbound = bound.encode();
        unbound[VOLUME_FIXED + 17..VOLUME_FIXED + ENTRY].fill(0);
        let mut empty = compacted.encode();
        empty[5] = 3;
        let mut unstated = empty.clone();
        unstated[HEAD + VOLUME] = 9;
        let mut short = VOLUME_V3_FIXTURE.to_vec();
        short[5] = 2;
        for (what, bytes) in [
            ("an entry that format 2 expresses", unbound),
            ("no entries", empty),
            ("no entries and a state past deleted", unstated),
            ("format-3 bytes under version 2", short),
        ] {
            assert_eq!(
                VolumeRecord::decode(&bytes),
                Err(CodecError::Version),
                "{what}"
            );
        }
        for kind in [3, 4] {
            let mut bytes = fresh().encode();
            assert_eq!((bytes[5], bytes[VOLUME_FIXED]), (2, 0));
            bytes[VOLUME_FIXED] = kind;
            assert_eq!(
                VolumeRecord::decode(&bytes),
                Err(CodecError::Flag),
                "format-2 bytes with the kind byte {kind} of an ended or gone entry"
            );
        }
    }

    #[test]
    fn format_3_corruption_refuses_with_the_first_failed_check() {
        let golden = VOLUME_V3_FIXTURE.to_vec();
        for mask in 1..=u8::MAX {
            for at in 0..golden.len() {
                let mut bytes = golden.clone();
                bytes[at] ^= mask;
                if let Ok(value) = VolumeRecord::decode(&bytes) {
                    assert_eq!(value.encode(), bytes, "byte {at} mask {mask:#x}");
                }
            }
        }
        let at = |index: usize| VOLUME_FIXED + 2 * PAIR + index * ENTRY;
        let instance_field = |name: &str| InstanceId::new(name).unwrap().field();
        let cases: [(usize, Vec<u8>, CodecError, &str); 16] = [
            (5, vec![4], CodecError::Version, "version"),
            (VOLUME_FIXED - 2, vec![9], CodecError::Length, "pair count"),
            (
                VOLUME_FIXED - 1,
                vec![17],
                CodecError::Length,
                "event count",
            ),
            (at(0) + 4, vec![5], CodecError::Flag, "kind past gone"),
            (at(1) + 5, vec![0; 8], CodecError::Field, "host zero"),
            (
                at(1) + 13,
                1u32.to_be_bytes().to_vec(),
                CodecError::Field,
                "era below MIN_ERA",
            ),
            (
                at(4),
                7u32.to_be_bytes().to_vec(),
                CodecError::Field,
                "a number equal to the one before",
            ),
            (
                at(4),
                6u32.to_be_bytes().to_vec(),
                CodecError::Field,
                "a number below the one before",
            ),
            (
                at(4),
                9u32.to_be_bytes().to_vec(),
                CodecError::Field,
                "a number at next",
            ),
            (
                at(4),
                10u32.to_be_bytes().to_vec(),
                CodecError::Field,
                "a number above next",
            ),
            (
                at(4) + 18,
                vec![1],
                CodecError::Flag,
                "instance bytes without a length",
            ),
            (
                at(1) + 17,
                vec![11],
                CodecError::Field,
                "an instance length outside the grammar",
            ),
            (
                at(1) + 20,
                vec![b'g'],
                CodecError::Field,
                "an instance digit outside hexadecimal",
            ),
            (
                at(0) + 17,
                instance_field("i-00000009").to_vec(),
                CodecError::Field,
                "an instance on a force-detach",
            ),
            (
                VOLUME_FIXED + PAIR,
                14u64.to_be_bytes().to_vec(),
                CodecError::Field,
                "a pair pinning another host's ended entry",
            ),
            (
                at(3) + 4,
                vec![1],
                CodecError::Field,
                "an instance on a detach",
            ),
        ];
        for (offset, patch, error, what) in cases {
            let mut bytes = golden.clone();
            bytes[offset..offset + patch.len()].copy_from_slice(&patch);
            assert_eq!(VolumeRecord::decode(&bytes), Err(error), "{what}");
        }
        let mut detach = golden.clone();
        detach[at(0) + 4] = 1;
        let mut unbound_detach = entries();
        unbound_detach.events[0].kind = EventKind::Detach;
        assert_eq!(VolumeRecord::decode(&detach), Ok(unbound_detach.clone()));
        assert_eq!(unbound_detach.encode(), detach);
        let mut out_of_order = golden.clone();
        out_of_order[at(4)..at(4) + 4].copy_from_slice(&7u32.to_be_bytes());
        out_of_order[at(4) + 4] = 5;
        assert_eq!(
            VolumeRecord::decode(&out_of_order),
            Err(CodecError::Field),
            "the number is checked before the kind that follows it"
        );
        assert_eq!(
            VolumeRecord::decode(&golden[..golden.len() - 1]),
            Err(CodecError::Length)
        );
        let mut pinned_gone = entries();
        pinned_gone.events[2].kind = EventKind::Gone;
        assert_eq!(
            VolumeRecord::decode(&pinned_gone.encode()),
            Err(CodecError::Field),
            "a pair pinning a gone entry"
        );
        let third = |exhid: u8, key: Key, attach: u32| {
            let mut record = entries();
            record.pairs.push(RecordedPair {
                host: record.event(attach).unwrap().host,
                pair: Pair {
                    exhid: Exhid::new([exhid; 16]).unwrap(),
                    key,
                },
                attach,
            });
            VolumeRecord::decode(&record.encode()).map(|decoded| decoded == record)
        };
        let (held, unused) = (entries().pairs[0].pair.key, pair(0xE3, 4, 9).key);
        assert_eq!(third(0xE3, unused, 8), Ok(true));
        for (what, exhid, key, attach) in [
            ("two pairs pinning one entry", 0xE3, unused, 3),
            ("two pairs sharing an EXHID", 0xE1, unused, 8),
            ("two pairs sharing a key", 0xE3, held, 8),
        ] {
            assert_eq!(third(exhid, key, attach), Err(CodecError::Field), "{what}");
        }
    }

    #[test]
    fn attachment_entries_move_forward_and_leave_only_when_gone() {
        let prior = entries();
        let succeeds = |change: fn(&mut VolumeRecord)| {
            let mut next = prior.clone();
            change(&mut next);
            (next.succeeds(&prior), VolumeRecord::decode(&next.encode()))
        };
        type Change = (&'static str, fn(&mut VolumeRecord));
        let admitted: [Change; 7] = [
            ("attach to ended", |r| r.events[1].kind = EventKind::Ended),
            (
                "a live attach takes its first instance (BIND-AT-ATTACH)",
                |r| {
                    r.events[4].instance = Some(instance(15));
                },
            ),
            ("an attach born with its instance", |r| {
                r.push(EventKind::Attach, host(16), ERA);
                r.events[5].instance = Some(instance(16));
            }),
            ("a gone entry leaves", |r| {
                r.events.remove(3);
            }),
            ("the leading force-detach leaves", |r| {
                r.events.remove(0);
            }),
            ("an attach appended at next", |r| {
                r.push(EventKind::Attach, host(16), ERA);
            }),
            ("an attach without an instance ends", |r| {
                r.events[4].kind = EventKind::Ended;
            }),
        ];
        for (what, change) in admitted {
            let (verdict, decoded) = succeeds(change);
            assert_eq!(verdict, Ok(()), "{what}");
            assert!(decoded.is_ok(), "{what}: {decoded:?}");
        }
        let refused: [Change; 25] = [
            ("attach to gone", |r| r.events[4].kind = EventKind::Gone),
            ("ended to gone in the write that drops its pair", |r| {
                r.events[2].kind = EventKind::Gone;
                r.pairs.truncate(1);
            }),
            ("ended to gone under the pair that pins it", |r| {
                r.events[2].kind = EventKind::Gone;
            }),
            ("gone back to attach", |r| {
                r.events[3].kind = EventKind::Attach;
                r.push(EventKind::Attach, host(14), ERA);
            }),
            ("a retained host changed", |r| r.events[3].host = host(16)),
            ("two retained entries swapped", |r| r.events.swap(3, 4)),
            ("a retained entry duplicated", |r| {
                let gone = r.events[3];
                r.events.insert(4, gone);
            }),
            ("a new entry placed before a retained one", |r| {
                r.push(EventKind::Attach, host(16), ERA);
                let born = r.events.pop().unwrap();
                r.events.insert(4, born);
            }),
            ("ended back to attach", |r| {
                r.events[2].kind = EventKind::Attach;
                r.push(EventKind::Attach, host(13), ERA);
            }),
            ("gone back to ended", |r| {
                r.events[3].kind = EventKind::Ended
            }),
            ("a force-detach ends", |r| {
                r.events[0].kind = EventKind::Ended
            }),
            ("an ended entry's instance removed", |r| {
                r.events[2].instance = None;
            }),
            ("an instance bound to an attach as it ends", |r| {
                r.events[4].instance = Some(instance(15));
                r.events[4].kind = EventKind::Ended;
            }),
            ("an instance changed", |r| {
                r.events[1].instance = Some(instance(99));
            }),
            ("an era changed", |r| r.events[1].era += 1),
            ("an ended entry leaves", |r| {
                r.events.remove(2);
            }),
            ("a bound attach leaves with the leading run", |r| {
                r.events.drain(..2);
            }),
            (
                "an attach without an instance leaves behind a retained entry",
                |r| {
                    r.events.remove(4);
                },
            ),
            ("a lowered next", |r| r.next = 8),
            ("a raised next without an entry", |r| r.next = 10),
            ("an entry born ended", |r| {
                r.push(EventKind::Ended, host(16), ERA);
            }),
            ("an entry reusing a compacted number", |r| {
                r.events
                    .insert(2, entry(4, EventKind::Attach, 16, ERA, None));
            }),
            ("next raised past the appended entry", |r| {
                r.push(EventKind::Attach, host(16), ERA);
                r.next += 1;
            }),
            ("a detach reusing a compacted number", |r| {
                r.events
                    .insert(2, entry(4, EventKind::Detach, 16, ERA, None));
            }),
            ("an entry born gone", |r| {
                r.push(EventKind::Gone, host(16), ERA);
            }),
        ];
        for (what, change) in refused {
            assert_eq!(succeeds(change).0, Err(SuccessorRule::Events), "{what}");
        }

        // Host 12's detach and host 13's second attach each hide an earlier attach, so the changes below preserve
        // the set of live attaches.
        let hidden = VolumeRecord {
            next: 4,
            forced: false,
            fence: 0,
            pairs: Vec::new(),
            events: vec![
                entry(0, EventKind::Attach, 12, ERA, None),
                entry(1, EventKind::Detach, 12, ERA, None),
                entry(2, EventKind::Attach, 13, ERA, None),
                entry(3, EventKind::Attach, 13, ERA, Some("i-0000000d")),
            ],
            ..volume()
        };
        // BIND-AT-ATTACH binds only a live attach: host 12's attach behind its detach and host 13's attach behind
        // its later attach each refuse a first instance.
        for at in [0, 2] {
            let mut bound = hidden.clone();
            bound.events[at].instance = Some(InstanceId::new("i-0000000b").unwrap());
            assert_eq!(VolumeRecord::decode(&bound.encode()), Ok(bound.clone()));
            assert_eq!(
                bound.succeeds(&hidden),
                Err(SuccessorRule::Events),
                "hidden attach {at}"
            );
        }
        let kinds = [
            EventKind::Attach,
            EventKind::Detach,
            EventKind::Force,
            EventKind::Ended,
            EventKind::Gone,
        ];
        for from in kinds {
            for to in kinds {
                let of = |kind: EventKind| {
                    let mut record = hidden.clone();
                    record.events[0].kind = kind;
                    record.forced = from == EventKind::Force || to == EventKind::Force;
                    record
                };
                let forward = matches!(
                    (from, to),
                    (EventKind::Attach, EventKind::Ended) | (EventKind::Ended, EventKind::Gone)
                );
                let verdict = if from == to || forward {
                    Ok(())
                } else {
                    Err(SuccessorRule::Events)
                };
                assert_eq!(of(to).succeeds(&of(from)), verdict, "{from:?} to {to:?}");
            }
        }
        let mut ended = hidden.clone();
        ended.events[0].kind = EventKind::Ended;
        let mut gone = ended.clone();
        gone.events[0].kind = EventKind::Gone;
        let mut led = gone.clone();
        led.events.drain(..3);
        for (what, next, prior) in [
            ("a hidden attach ends", &ended, &hidden),
            ("the ended entry goes", &gone, &ended),
            ("the gone entry leaves with the run behind it", &led, &gone),
        ] {
            assert_eq!(
                VolumeRecord::decode(&next.encode()),
                Ok(next.clone()),
                "{what}"
            );
            assert_eq!(next.succeeds(prior), Ok(()), "{what}");
        }
        let forced = VolumeRecord {
            next: 5,
            forced: true,
            events: vec![
                entry(1, EventKind::Ended, 12, ERA, None),
                entry(2, EventKind::Force, 12, ERA, None),
                entry(3, EventKind::Attach, 13, ERA, None),
                entry(4, EventKind::Attach, 13, ERA, Some("i-0000000d")),
            ],
            ..ended.clone()
        };
        for (what, prior, at) in [
            ("a detach leaves from behind an ended entry", &ended, 1),
            (
                "a hidden attach leaves from behind an ended entry",
                &ended,
                2,
            ),
            (
                "a force-detach leaves from behind an ended entry",
                &forced,
                1,
            ),
        ] {
            let mut next = prior.clone();
            next.events.remove(at);
            for record in [prior, &next] {
                assert_eq!(
                    VolumeRecord::decode(&record.encode()),
                    Ok(record.clone()),
                    "{what}"
                );
            }
            assert_eq!(next.succeeds(prior), Err(SuccessorRule::Events), "{what}");
        }
    }

    /// `[enrolled, ended, one, two]`: the format-3 fixture with a pair for the attach numbered 8, that attach ended,
    /// then the pair of the entry numbered 5 dropped, then the pair of the entry numbered 8 dropped.
    fn ended_drops() -> [VolumeRecord; 4] {
        let mut enrolled = entries();
        enrolled.pairs.push(RecordedPair {
            host: host(15),
            pair: pair(0xE3, 4, 9),
            attach: 8,
        });
        let mut ended = enrolled.clone();
        ended.events[4].kind = EventKind::Ended;
        let mut one = ended.clone();
        one.pairs.remove(1);
        let mut two = one.clone();
        two.pairs.remove(1);
        [enrolled, ended, one, two]
    }

    /// Negative control for the ended-pair drop: a pair rule that drops a pair only under a fence raise refuses the
    /// drops one tenure writes under one fence, which `succeeds` admits.
    #[test]
    #[should_panic(expected = "a strict-raise rule admits each ended-pair drop")]
    fn negative_control_a_strict_raise_pair_rule_refuses_two_ended_pair_drops() {
        let strict = |next: &VolumeRecord, prior: &VolumeRecord| {
            next.fence > prior.fence || prior.pairs.iter().all(|kept| next.pairs.contains(kept))
        };
        let [_, ended, one, two] = ended_drops();
        assert_eq!((one.succeeds(&ended), two.succeeds(&one)), (Ok(()), Ok(())));
        assert_eq!(
            ended_drop_verdicts(strict),
            [false, false, true, false],
            "the strict rule's verdicts on the four drops"
        );
        assert_ended_drops_admitted(strict);
    }

    fn ended_drop_verdicts(rule: impl Fn(&VolumeRecord, &VolumeRecord) -> bool) -> [bool; 4] {
        let [_, ended, one, two] = ended_drops();
        let mut raised = one.clone();
        raised.fence += 2;
        let mut kept = two.clone();
        kept.fence = raised.fence;
        [
            rule(&one, &ended),
            rule(&two, &one),
            rule(&raised, &ended),
            rule(&kept, &raised),
        ]
    }

    fn assert_ended_drops_admitted(rule: impl Fn(&VolumeRecord, &VolumeRecord) -> bool) {
        assert_eq!(
            ended_drop_verdicts(rule),
            [true; 4],
            "a strict-raise rule admits each ended-pair drop"
        );
    }

    #[test]
    fn ended_pairs_leave_under_one_fence() {
        assert_ended_drops_admitted(|next, prior| next.succeeds(prior).is_ok());
        let [enrolled, ended, one, two] = ended_drops();
        for (next, prior) in [(&ended, &enrolled), (&one, &ended), (&two, &one)] {
            assert_eq!(next.succeeds(prior), Ok(()));
            assert_eq!(VolumeRecord::decode(&next.encode()), Ok(next.clone()));
        }
        assert_eq!((one.fence, two.fence), (enrolled.fence, enrolled.fence));
        let mut same_write = ended.clone();
        same_write.pairs.remove(2);
        let mut live = enrolled.clone();
        live.pairs.remove(0);
        for (what, mut next) in [
            ("an entry ended in the dropping write", same_write),
            ("a live attach's pair", live),
        ] {
            assert_eq!(
                next.succeeds(&enrolled),
                Err(SuccessorRule::Pairs),
                "{what}"
            );
            next.fence += 2;
            assert_eq!(
                next.succeeds(&enrolled),
                Ok(()),
                "{what} under a fence raise"
            );
        }
        let mut lowered = one.clone();
        lowered.fence -= 2;
        assert_eq!(lowered.succeeds(&ended), Err(SuccessorRule::Fence));
    }

    /// The owner's pair drop: `dropped` removes two ended pairs in one tenure's write and keeps the fence, for a
    /// session below, at and above it, and the successor check admits each write and refuses it with the live
    /// pair dropped as well. Each ended pair dropped alone leaves exactly the other ended pair and the live pair.
    /// A live entry's pair, a pair the record does not hold, an empty drop, a pair pinning an attach a later force
    /// detach marks, and a session that is no activated session give no record; the live drop the successor check
    /// refuses under the unchanged fence.
    #[test]
    fn the_owner_drops_ended_pairs_under_the_fence_it_read() {
        let [enrolled, ended, one, ..] = ended_drops();
        let dropped = [pair(0xE2, 4, 8), pair(0xE3, 4, 9)];
        assert_eq!(
            ended
                .ended_pairs()
                .map(|recorded| recorded.pair)
                .collect::<Vec<_>>(),
            dropped
        );
        for session in [session(8), ended.fence, session(12)] {
            let next = ended.dropped(&dropped, session).unwrap();
            assert_eq!(next.fence, ended.fence, "session {session}");
            assert_eq!(next.pairs, [recorded(12, 0xE1, 3)], "session {session}");
            assert_eq!(next.events, ended.events, "session {session}");
            assert_eq!(next.succeeds(&ended), Ok(()), "session {session}");
            assert_eq!(VolumeRecord::decode(&next.encode()), Ok(next.clone()));
            // The drop writes under the fence it read, so the successor check judges the write by its ended
            // entries: the same record without the live pair as well is refused.
            let mut widened = next.clone();
            widened.pairs.clear();
            assert_eq!(
                widened.succeeds(&ended),
                Err(SuccessorRule::Pairs),
                "session {session}: a live pair dropped beside the ended ones"
            );
        }
        let first = ended.dropped(&dropped[..1], ended.fence).unwrap();
        assert_eq!(
            first, one,
            "dropping 0xE2 alone keeps the live pair and 0xE3"
        );
        assert_eq!(first.succeeds(&ended), Ok(()));
        let second = ended.dropped(&dropped[1..], ended.fence).unwrap();
        let mut kept = ended.clone();
        kept.pairs.remove(2);
        assert_eq!(
            second, kept,
            "dropping 0xE3 alone keeps the live pair and 0xE2"
        );
        assert_eq!(second.succeeds(&ended), Ok(()));
        let live = pair(0xE1, 3, 7);
        for (what, pairs) in [
            ("a live entry's pair", vec![live]),
            ("a live pair beside an ended one", vec![dropped[0], live]),
            ("a pair the record does not hold", vec![pair(0x99, 4, 9)]),
            ("no pair", Vec::new()),
        ] {
            assert_eq!(ended.dropped(&pairs, session(12)), None, "{what}");
        }
        let mut marked = enrolled.clone();
        marked.push(EventKind::Force, host(15), STORED_ERA);
        assert_eq!(
            VolumeRecord::decode(&marked.encode()),
            Ok(marked.clone()),
            "a format-2-style force detach after the attach the pair pins"
        );
        assert_eq!(
            marked.dropped(&dropped[1..], session(12)),
            None,
            "a pair pinning an attach a later force detach marks pins no ended entry"
        );
        for (what, session) in [
            ("an odd epoch", session(12) + 1),
            ("generation zero", 12),
            ("epoch zero", session(0)),
            ("u64::MAX", u64::MAX),
        ] {
            assert_eq!(ended.dropped(&dropped, session), None, "{what}");
        }
        let mut forced = ended.clone();
        forced.pairs.remove(0);
        assert_eq!(
            forced.succeeds(&ended),
            Err(SuccessorRule::Pairs),
            "the successor check refuses a live pair's drop under the unchanged fence"
        );
    }

    /// ENDED-NEVER-RETIRES: over the format-3 fixture, a live entry's pair and an ended entry's pair are recorded;
    /// an unrecorded pair under the key of the ended entry, of a gone entry or of a removed number below `next` is an
    /// ended attach's registrant; the live entry's own key unrecorded, a key at or past `next` and a key of another
    /// epoch are unknown. The instances beside a host are those of other hosts' attach and ended entries.
    /// `Detach` and force-detach event numbers identify events; the original attach key identifies the attachment.
    #[test]
    fn registrant_classes_recorded_ended_and_unknown_pairs() {
        let record = entries();
        let late = |seq: u32| Pair {
            exhid: Exhid::new([0x77; 16]).unwrap(),
            key: attachment_key(seq).unwrap(),
        };
        for (what, registrant, class) in [
            ("a live pair", pair(0xE1, 3, 7), Registration::Recorded),
            ("an ended pair", pair(0xE2, 4, 8), Registration::Recorded),
            ("a dropped ended key", late(5), Registration::Ended),
            ("a gone entry's key", late(7), Registration::Ended),
            ("a removed entry's key", late(4), Registration::Ended),
            ("a force-detach's number", late(2), Registration::Unknown),
            ("the live entry's key", late(8), Registration::Unknown),
            ("the next number's key", late(9), Registration::Unknown),
            ("another epoch", pair(0x77, 2, 6), Registration::Unknown),
            (
                "an unrelated key",
                pair(0x77, 6, 600),
                Registration::Unknown,
            ),
        ] {
            assert_eq!(record.registrant(&registrant), class, "{what}");
        }
        let mut detached = record.clone();
        let detach = detached
            .push(EventKind::Detach, host(15), STORED_ERA)
            .unwrap();
        assert_eq!(
            detached.registrant(&late(detach)),
            Registration::Unknown,
            "a detach event's number"
        );
        assert_eq!(
            detached.registrant(&late(8)),
            Registration::Ended,
            "the key of the attach the detach ends"
        );
        assert_eq!(
            record.instances_beside(host(12)).collect::<Vec<_>>(),
            vec![&instance(0x0d)]
        );
        assert_eq!(
            record.instances_beside(host(13)).collect::<Vec<_>>(),
            vec![&InstanceId::new("i-0000000c").unwrap()]
        );
        // `bound_beside` names the host of each such entry: the bound attach of host 12 and the bound ended entry
        // of host 13, without the gone entry of host 14 and the attach of host 15 that binds none.
        assert_eq!(
            record.bound_beside(host(9)).collect::<Vec<_>>(),
            vec![
                (host(12), &InstanceId::new("i-0000000c").unwrap()),
                (host(13), &instance(0x0d)),
            ]
        );
        for beside in [9, 12, 13, 14, 15].map(host) {
            assert!(
                record
                    .bound_beside(beside)
                    .map(|(_, instance)| instance)
                    .eq(record.instances_beside(beside)),
                "both accessors read the same entries beside {beside:?}"
            );
            assert!(record.bound_beside(beside).all(|(of, _)| of != beside));
        }
        let listed = [
            crate::failover::evidence::Registrant {
                cntlid: 1,
                pair: late(5),
                holder: false,
            },
            crate::failover::evidence::Registrant {
                cntlid: 2,
                pair: late(5),
                holder: false,
            },
            crate::failover::evidence::Registrant {
                cntlid: 3,
                pair: late(8),
                holder: false,
            },
            crate::failover::evidence::Registrant {
                cntlid: 4,
                pair: pair(0xE1, 3, 7),
                holder: true,
            },
        ];
        assert_eq!(
            record.admitted(&listed).copied().collect::<Vec<_>>(),
            vec![pair(0xE1, 3, 7), pair(0xE2, 4, 8), late(5)],
            "the recorded pairs, then each listed ended attach's pair once"
        );
        let mut mixed = listed.to_vec();
        mixed.extend([
            crate::failover::evidence::Registrant {
                cntlid: 5,
                pair: late(7),
                holder: true,
            },
            crate::failover::evidence::Registrant {
                cntlid: 6,
                pair: late(7),
                holder: false,
            },
            crate::failover::evidence::Registrant {
                cntlid: 7,
                pair: late(4),
                holder: false,
            },
        ]);
        let admitted: Vec<_> = record.admitted(&mixed).copied().collect();
        for entry in mixed.iter().filter(|entry| {
            !mixed
                .iter()
                .any(|other| other.holder && other.pair == entry.pair)
        }) {
            assert_eq!(
                record.registrant(&entry.pair) != Registration::Unknown,
                admitted.contains(&entry.pair),
                "a non-holding registrant is admitted exactly when its class is known: {entry:?}"
            );
        }
        assert!(
            !admitted.contains(&late(7)),
            "a pair one of whose entries holds stays out of the admitted set"
        );
        let mut reversed = mixed.clone();
        reversed.swap(4, 5);
        assert_eq!(
            record.admitted(&reversed).copied().collect::<Vec<_>>(),
            vec![pair(0xE1, 3, 7), pair(0xE2, 4, 8), late(5), late(4)],
            "the holding entry after the non-holding one keeps the pair out as well"
        );
        assert_eq!(
            record.admitted(&mixed).copied().collect::<Vec<_>>(),
            vec![pair(0xE1, 3, 7), pair(0xE2, 4, 8), late(5), late(4)]
        );
        let shared = Pair {
            exhid: Exhid::new([0x78; 16]).unwrap(),
            key: pair(0xE1, 3, 7).key,
        };
        assert_eq!(
            record.registrant(&shared),
            Registration::Unknown,
            "another host ID under a recorded pair's key"
        );
    }

    /// `attachment_seq` inverts `attachment_key` over the keyed numbers, the largest included, and answers `None` for a
    /// key of another epoch.
    #[test]
    fn attachment_seq_inverts_the_attachment_key() {
        for seq in [0, 1, 7, 0xFFFF_FFFD] {
            assert_eq!(attachment_seq(attachment_key(seq).unwrap()), Some(seq));
        }
        assert_eq!(attachment_key(0xFFFF_FFFE), None);
        assert_eq!(attachment_seq(pair(0x77, 2, 6).key), None);
    }

    /// A format-2 detach or force event after a host's ended entry leaves the host ended, and a later live attach of
    /// the host after its gone entry makes it live again.
    #[test]
    fn a_later_detach_keeps_an_ended_host_ended_and_a_later_attach_does_not() {
        let mut record = entries();
        assert!(record.ended(host(13)));
        record.push(EventKind::Detach, host(13), ERA);
        assert!(record.ended(host(13)), "a detach after the ended entry");
        record.push(EventKind::Attach, host(14), ERA);
        assert!(
            !record.ended(host(14)),
            "a live attach after the gone entry"
        );
    }

    #[test]
    fn an_ended_or_gone_entry_grants_its_host_nothing() {
        let wide = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
        let record = entries();
        for of in [13, 14] {
            assert_eq!(record.live(host(of)), None, "host {of}");
            assert_eq!(record.enrolled(host(of)), None, "host {of}");
            assert!(record.has_attach_event(host(of)), "host {of}");
            assert_eq!(
                record.enroll(host(of), pair(0x70, 5, 1), &wide),
                Err(Enrollment::Unattached),
                "host {of}"
            );
        }
        assert_eq!(
            record
                .latest(host(13))
                .map(|(seq, event)| (seq, event.kind)),
            Some((5, EventKind::Ended))
        );
        assert_eq!(
            record.live_attaches().collect::<Vec<_>>(),
            vec![(3, host(12)), (8, host(15))]
        );
        assert_eq!(record.enrolled(host(12)), Some(pair(0xE1, 3, 7)));
        for kind in [EventKind::Force, EventKind::Detach] {
            let mut alone = record.clone();
            alone.events[0].kind = kind;
            alone.forced = kind == EventKind::Force;
            assert_eq!(VolumeRecord::decode(&alone.encode()), Ok(alone.clone()));
            assert_eq!(
                alone.latest(host(9)).map(|(_, event)| event.kind),
                Some(kind)
            );
            assert!(
                !alone.has_attach_event(host(9)),
                "{kind:?} alone is no attach event"
            );
        }
        assert_eq!(
            record
                .recorded_beside(host(15))
                .copied()
                .collect::<Vec<_>>(),
            vec![pair(0xE1, 3, 7), pair(0xE2, 4, 8)],
            "the recorded pairs beside a host include an ended entry's"
        );
        assert!(record.ended(host(13)) && record.ended(host(14)));
        assert!(!record.ended(host(12)) && !record.ended(host(9)) && !record.ended(host(16)));
        assert!(!record.uncompacted());
        let standby = Pair {
            exhid: Exhid::new([0x70; 16]).unwrap(),
            key: record.attach_key(host(15)).unwrap(),
        };
        let standby = record.enroll(host(15), standby, &wide).unwrap().unwrap();
        assert_eq!(standby.succeeds(&record), Ok(()));
        assert_eq!(VolumeRecord::decode(&standby.encode()), Ok(standby));
        let mut ended = fresh();
        ended.events[0].kind = EventKind::Ended;
        assert!(!ended.attached_once(host(12)) && ended.has_attach_event(host(12)));
    }

    /// Hosts 12, 13 and 14 attach, the entries of 12 and 14 move to `kind`, and 12 attaches again. A force-detach
    /// of host 9 closes the history.
    fn with_first_attaches_moved_to(kind: EventKind) -> VolumeRecord {
        let mut record = VolumeRecord {
            next: 0,
            forced: false,
            events: Vec::new(),
            ..fresh()
        };
        for of in [12, 13, 14] {
            record.push(EventKind::Attach, host(of), ERA);
        }
        record.events[0].kind = kind;
        record.events[2].kind = kind;
        record.push(EventKind::Attach, host(12), ERA);
        record.push(EventKind::Force, host(9), ERA);
        record
    }

    #[test]
    fn an_ended_entry_is_its_hosts_attach_event() {
        let record = with_first_attaches_moved_to(EventKind::Ended);
        assert_eq!(
            record.hosts_with_attach_event().collect::<Vec<_>>(),
            vec![host(12), host(13), host(14)],
            "each host once, by its first attach or ended entry"
        );
        assert_eq!(
            record.live_hosts().collect::<Vec<_>>(),
            vec![host(13), host(12)]
        );
    }

    #[test]
    fn a_gone_entry_is_its_hosts_attach_event() {
        let record = with_first_attaches_moved_to(EventKind::Gone);
        assert_eq!(
            record.hosts_with_attach_event().collect::<Vec<_>>(),
            vec![host(12), host(13), host(14)],
            "each host once, by its first attach or gone entry"
        );
        assert_eq!(
            record.live_hosts().collect::<Vec<_>>(),
            vec![host(13), host(12)]
        );
    }

    #[test]
    fn a_format_3_live_attach_leaves_only_through_ended_and_gone() {
        let prior = VolumeRecord {
            next: 2,
            forced: false,
            fence: 0,
            pairs: Vec::new(),
            events: vec![
                entry(0, EventKind::Attach, 12, ERA, None),
                entry(1, EventKind::Attach, 13, ERA, Some("i-0000000d")),
            ],
            ..volume()
        };
        assert_eq!(prior.encode()[5], 3);
        let mut dropped = prior.clone();
        dropped.events.remove(0);
        assert_eq!(VolumeRecord::decode(&dropped.encode()), Ok(dropped.clone()));
        assert_eq!(dropped.succeeds(&prior), Err(SuccessorRule::Events));
        for (kind, verdict) in [
            (EventKind::Ended, Err(SuccessorRule::Events)),
            (EventKind::Gone, Ok(())),
        ] {
            let mut before = prior.clone();
            before.events[0].kind = kind;
            assert_eq!(dropped.succeeds(&before), verdict, "{kind:?}");
        }
        dropped.fence = session(10);
        assert_eq!(dropped.succeeds(&prior), Err(SuccessorRule::Events));

        let mut legacy_prior = prior.clone();
        legacy_prior.events[1].instance = None;
        let mut legacy = legacy_prior.clone();
        legacy.events.remove(0);
        assert_eq!((legacy_prior.encode()[5], legacy.encode()[5]), (2, 2));
        assert_eq!(legacy.succeeds(&legacy_prior), Ok(()));

        let superseded = VolumeRecord {
            next: 3,
            events: vec![
                entry(0, EventKind::Attach, 12, ERA, None),
                entry(1, EventKind::Attach, 12, ERA, Some("i-0000000c")),
                entry(2, EventKind::Attach, 13, ERA, Some("i-0000000d")),
            ],
            ..prior.clone()
        };
        let mut compacted = superseded.clone();
        compacted.events.remove(0);
        assert_eq!(compacted.succeeds(&superseded), Ok(()));
        let mut bound_first = superseded.clone();
        bound_first.events[0].instance = Some(InstanceId::new("i-0000000b").unwrap());
        assert_eq!(
            VolumeRecord::decode(&bound_first.encode()),
            Ok(bound_first.clone())
        );
        assert_eq!(compacted.succeeds(&bound_first), Err(SuccessorRule::Events));

        let unbound_pair = VolumeRecord {
            events: vec![
                entry(0, EventKind::Attach, 12, ERA, None),
                entry(1, EventKind::Attach, 13, ERA, None),
            ],
            ..prior.clone()
        };
        let mut ending_other = unbound_pair.clone();
        ending_other.events.remove(0);
        ending_other.events[0].kind = EventKind::Ended;
        let gone_bound = VolumeRecord {
            events: vec![
                entry(0, EventKind::Attach, 12, ERA, None),
                entry(1, EventKind::Gone, 13, ERA, Some("i-0000000d")),
            ],
            ..prior.clone()
        };
        let emptied = VolumeRecord {
            events: Vec::new(),
            ..prior.clone()
        };
        for (what, next, before, versions) in [
            ("format 2 to format 3", &ending_other, &unbound_pair, (2, 3)),
            ("format 3 to format 2", &emptied, &gone_bound, (3, 2)),
        ] {
            assert_eq!((before.encode()[5], next.encode()[5]), versions, "{what}");
            assert_eq!(
                VolumeRecord::decode(&next.encode()),
                Ok(next.clone()),
                "{what}"
            );
            assert_eq!(next.succeeds(before), Err(SuccessorRule::Events), "{what}");
        }

        let mut ended_first = prior.clone();
        ended_first.events[0].kind = EventKind::Ended;
        type Change = (&'static str, fn(&mut VolumeRecord));
        let shadowing: [Change; 3] = [
            ("a detach after a live attach", |r| {
                r.push(EventKind::Detach, host(12), ERA);
            }),
            ("a force-detach after a bound live attach", |r| {
                r.push(EventKind::Force, host(13), ERA);
            }),
            ("a second attach of a live host", |r| {
                r.push(EventKind::Attach, host(12), ERA);
            }),
        ];
        for (what, change) in shadowing {
            let mut next = prior.clone();
            change(&mut next);
            assert_eq!(next.encode()[5], 3, "{what}");
            assert_eq!(
                VolumeRecord::decode(&next.encode()),
                Ok(next.clone()),
                "{what}"
            );
            assert_eq!(next.succeeds(&prior), Err(SuccessorRule::Events), "{what}");
        }
        let mut detached = ended_first.clone();
        detached.push(EventKind::Detach, host(12), ERA);
        assert_eq!(ended_first.succeeds(&prior), Ok(()));
        assert_eq!(detached.succeeds(&ended_first), Ok(()));
    }

    #[test]
    fn a_format_3_pair_pins_its_hosts_live_attach() {
        let prior = VolumeRecord {
            next: 3,
            forced: false,
            fence: 0,
            pairs: Vec::new(),
            events: vec![
                entry(0, EventKind::Attach, 12, ERA, None),
                entry(1, EventKind::Detach, 12, ERA, None),
                entry(2, EventKind::Attach, 13, ERA, Some("i-0000000d")),
            ],
            ..volume()
        };
        let mut superseded = prior.clone();
        superseded.pairs.push(recorded(12, 0xE1, 0));
        assert_eq!(
            VolumeRecord::decode(&superseded.encode()),
            Ok(superseded.clone())
        );
        assert_eq!(superseded.succeeds(&prior), Err(SuccessorRule::Pairs));
        superseded.fence = session(10);
        assert_eq!(superseded.succeeds(&prior), Err(SuccessorRule::Pairs));
        let mut live = prior.clone();
        live.pairs.push(recorded(13, 0xE2, 2));
        assert_eq!(live.succeeds(&prior), Ok(()));
        let legacy_prior = VolumeRecord {
            events: prior.events[..2].to_vec(),
            next: 2,
            ..prior.clone()
        };
        let mut legacy = legacy_prior.clone();
        legacy.pairs.push(recorded(12, 0xE1, 0));
        assert_eq!((legacy_prior.encode()[5], legacy.encode()[5]), (2, 2));
        assert_eq!(legacy.succeeds(&legacy_prior), Ok(()));

        let twice = VolumeRecord {
            next: 2,
            events: vec![
                entry(0, EventKind::Attach, 12, ERA, None),
                entry(1, EventKind::Attach, 12, ERA, Some("i-0000000c")),
            ],
            ..prior.clone()
        };
        for (what, attach, verdict) in [
            ("the host's earlier attach", 0, Err(SuccessorRule::Pairs)),
            ("the host's live attach", 1, Ok(())),
        ] {
            let mut next = twice.clone();
            next.pairs.push(recorded(12, 0xE1, attach));
            assert_eq!(
                VolumeRecord::decode(&next.encode()),
                Ok(next.clone()),
                "{what}"
            );
            assert_eq!(next.succeeds(&twice), verdict, "{what}");
        }
    }

    #[test]
    fn a_new_pair_under_the_same_fence_takes_no_dropped_identity() {
        let [_, ended, _, _] = ended_drops();
        let mut base = ended.clone();
        base.push(EventKind::Attach, host(16), ERA);
        let dropped = base.pairs[2];
        let replacement = |exhid: [u8; 16], key: Key| {
            let mut next = base.clone();
            next.pairs.remove(2);
            next.pairs.push(RecordedPair {
                host: host(16),
                pair: Pair {
                    exhid: Exhid::new(exhid).unwrap(),
                    key,
                },
                attach: 9,
            });
            next
        };
        let fresh_key = pair(0xE6, 6, 11).key;
        for (what, mut next, verdict) in [
            (
                "the dropped key",
                replacement([0xE5; 16], dropped.pair.key),
                Err(SuccessorRule::Pairs),
            ),
            (
                "the dropped EXHID",
                replacement([0xE3; 16], fresh_key),
                Err(SuccessorRule::Pairs),
            ),
            (
                "a fresh EXHID and key",
                replacement([0xE5; 16], fresh_key),
                Ok(()),
            ),
        ] {
            assert_eq!(
                VolumeRecord::decode(&next.encode()),
                Ok(next.clone()),
                "{what}"
            );
            assert_eq!(next.succeeds(&base), verdict, "{what}");
            next.fence += 2;
            assert_eq!(next.succeeds(&base), Ok(()), "{what} under a raise");
        }
        let mut mixed = base.clone();
        mixed.pairs.remove(2);
        mixed.pairs.remove(0);
        assert_eq!(VolumeRecord::decode(&mixed.encode()), Ok(mixed.clone()));
        assert_eq!(mixed.succeeds(&base), Err(SuccessorRule::Pairs));
        mixed.fence += 2;
        assert_eq!(mixed.succeeds(&base), Ok(()));

        let mut moved = ended.clone();
        moved.push(EventKind::Attach, host(15), ERA);
        moved.pairs[2].attach = 9;
        assert_eq!(VolumeRecord::decode(&moved.encode()), Ok(moved.clone()));
        assert_eq!(
            moved.succeeds(&ended),
            Err(SuccessorRule::Pairs),
            "an ended entry's pair moved to its host's new attach"
        );
        moved.fence += 2;
        assert_eq!(moved.succeeds(&ended), Ok(()));

        let wide = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
        let mut released = ended.clone();
        released.push(EventKind::Attach, host(15), ERA);
        let own = released.pairs.remove(2);
        assert_eq!(
            released.enroll(host(15), own.pair, &wide),
            Err(Enrollment::Key),
            "the ended attach's key on its host's new attach (KEY-PER-ATTACH)"
        );
        let rekeyed = Pair {
            key: released.attach_key(host(15)).unwrap(),
            ..own.pair
        };
        let enrolled = released.enroll(host(15), rekeyed, &wide).unwrap().unwrap();
        assert_eq!(
            (released.succeeds(&ended), enrolled.succeeds(&released)),
            (Ok(()), Ok(())),
            "a record keeps no dropped identity, so a later write under the same fence enrolls its EXHID again"
        );
        moved.fence = ended.fence;
        moved.pairs[2].pair = rekeyed;
        assert_eq!(
            moved.succeeds(&ended),
            Err(SuccessorRule::Pairs),
            "one write moves the EXHID under the same fence"
        );
        assert_eq!(
            enrolled, moved,
            "the two writes reach the record the one write refuses"
        );
    }

    /// KEY-PER-ATTACH over `write`, a writer of host 15's new attach on the released record of [`ended_drops`]: the
    /// writer is offered the pair of the host's ended attach under that attach's own key, [`attachment_key`] of
    /// entry 8, after a write dropped the pair, and must refuse it with `Key`.
    fn assert_a_new_attach_takes_no_earlier_attachs_key(
        write: impl FnOnce(&VolumeRecord, Pair) -> Result<Option<VolumeRecord>, Enrollment>,
    ) {
        let [_, ended, _, _] = ended_drops();
        let mut released = ended.clone();
        released.push(EventKind::Attach, host(15), ERA);
        let earlier = Pair {
            key: attachment_key(8).unwrap(),
            ..released.pairs.remove(2).pair
        };
        assert_eq!(released.succeeds(&ended), Ok(()));
        assert!(
            released
                .pairs
                .iter()
                .all(|kept| kept.pair.key != earlier.key)
        );
        assert_eq!(
            write(&released, earlier).map(|written| written.map(|_| ())),
            Err(Enrollment::Key),
            "a pair under an earlier attach's key enrolls the host's new attach"
        );
    }

    /// KEY-PER-ATTACH: [`VolumeRecord::enroll`] refuses the key of the host's ended attach on its new attach with
    /// `Key`, though no recorded pair holds that key any longer.
    #[test]
    fn a_new_attach_refuses_the_key_of_its_hosts_ended_attach() {
        let wide = crate::storage::gate_fixture::bounds_of(crate::storage::gate_fixture::limits());
        assert_a_new_attach_takes_no_earlier_attachs_key(|released, earlier| {
            released.enroll(host(15), earlier, &wide)
        });
    }

    /// Control for KEY-PER-ATTACH: the record checks admit a pair under an earlier attach's key once that pair was
    /// dropped, so a writer that applies only the record checks enrolls a host's new attach under its ended attach's
    /// key, and the shared assertion that the writer refuses `Key` fails.
    #[test]
    #[should_panic(expected = "a pair under an earlier attach's key enrolls the host's new attach")]
    fn negative_control_a_writer_without_the_key_rule_enrolls_the_earlier_attachs_key() {
        assert_a_new_attach_takes_no_earlier_attachs_key(|released, earlier| {
            let mut written = released.clone();
            written.pairs.push(RecordedPair {
                host: host(15),
                pair: earlier,
                attach: released.live(host(15)).unwrap(),
            });
            assert_eq!(
                (
                    written.succeeds(released),
                    VolumeRecord::decode(&written.encode())
                ),
                (Ok(()), Ok(written.clone()))
            );
            Ok(Some(written))
        });
    }

    #[test]
    fn removing_a_gone_entry_revives_no_older_attach() {
        let twice = VolumeRecord {
            next: 2,
            forced: false,
            fence: 0,
            pairs: vec![recorded(12, 0xE1, 0)],
            events: vec![
                entry(0, EventKind::Attach, 12, ERA, None),
                entry(1, EventKind::Attach, 12, ERA, Some("i-0000000c")),
            ],
            ..volume()
        };
        let mut ended = twice.clone();
        ended.events[1].kind = EventKind::Ended;
        let mut gone = ended.clone();
        gone.events[1].kind = EventKind::Gone;
        for (next, prior) in [(&ended, &twice), (&gone, &ended)] {
            assert_eq!(next.succeeds(prior), Ok(()));
            assert_eq!((next.live(host(12)), next.enrolled(host(12))), (None, None));
        }
        let mut removed = gone.clone();
        removed.events.remove(1);
        assert_eq!(VolumeRecord::decode(&removed.encode()), Ok(removed.clone()));
        assert_eq!(removed.live(host(12)), Some(0));
        assert_eq!(removed.succeeds(&gone), Err(SuccessorRule::Events));

        let mut full = gone.clone();
        full.next = 3;
        full.events
            .push(entry(2, EventKind::Gone, 13, ERA, Some("i-0000000d")));
        assert_eq!(full.removable_gone(host(14)).collect::<Vec<_>>(), [2]);
        assert_eq!(full.removable_gone(host(12)).collect::<Vec<_>>(), [1, 2]);
        let mut shed = full.clone();
        shed.events.remove(2);
        assert_eq!(shed.push(EventKind::Attach, host(14), ERA), Some(3));
        assert_eq!(shed.succeeds(&full), Ok(()));
        assert_eq!(shed.live(host(12)), None);
    }

    #[test]
    fn an_ended_entry_goes_after_its_pair_leaves() {
        let prior = entries();
        let mut dropped = prior.clone();
        dropped.pairs.truncate(1);
        let mut gone = dropped.clone();
        gone.events[2].kind = EventKind::Gone;
        for (next, prior) in [(&dropped, &prior), (&gone, &dropped)] {
            assert_eq!(next.succeeds(prior), Ok(()));
            assert_eq!(VolumeRecord::decode(&next.encode()), Ok(next.clone()));
        }
        let mut combined = gone.clone();
        combined.fence += 2;
        assert_eq!(combined.succeeds(&prior), Err(SuccessorRule::Events));
    }

    #[test]
    fn a_pair_on_an_ended_entry_is_one_the_prior_record_holds() {
        let [enrolled, ended, _, two] = ended_drops();
        let mut swapped = ended.clone();
        swapped.pairs[2].pair = pair(0xE4, 4, 10);
        let mut first = entries();
        first.events[4].kind = EventKind::Ended;
        let base = first.clone();
        first.pairs.push(RecordedPair {
            host: host(15),
            pair: pair(0xE4, 4, 10),
            attach: 8,
        });
        let mut readded = two.clone();
        readded.pairs.push(enrolled.pairs[2]);
        for (what, mut next, prior) in [
            ("a swapped pair", swapped, &ended),
            ("a first pair", first.clone(), &base),
            ("a dropped pair added back", readded, &two),
            ("a pair added in the ending write", first, &entries()),
        ] {
            assert_eq!(
                VolumeRecord::decode(&next.encode()),
                Ok(next.clone()),
                "{what}"
            );
            assert_eq!(next.succeeds(prior), Err(SuccessorRule::Pairs), "{what}");
            next.fence += 2;
            assert_eq!(
                next.succeeds(prior),
                Err(SuccessorRule::Pairs),
                "{what} under a raise"
            );
        }
        let mut reused = ended.clone();
        let dropped = reused.pairs.remove(2);
        reused.push(EventKind::Attach, host(16), ERA);
        reused.pairs.push(RecordedPair {
            host: host(16),
            pair: Pair {
                exhid: Exhid::new([0xE5; 16]).unwrap(),
                key: dropped.pair.key,
            },
            attach: 9,
        });
        assert_eq!(VolumeRecord::decode(&reused.encode()), Ok(reused.clone()));
        assert_eq!(reused.succeeds(&ended), Err(SuccessorRule::Pairs));
        reused.fence += 2;
        assert_eq!(reused.succeeds(&ended), Ok(()));
    }

    #[test]
    fn the_force_mark_stands_for_a_departed_force_detach_only_after_event_0_leaves() {
        let mut gap = fresh();
        gap.push(EventKind::Attach, host(13), ERA);
        gap.push(EventKind::Attach, host(14), ERA);
        gap.events.remove(1);
        let mut tail = fresh();
        tail.next = 2;
        for record in [gap.clone(), tail] {
            assert_eq!(VolumeRecord::decode(&record.encode()), Ok(record.clone()));
            let marked = VolumeRecord {
                forced: true,
                ..record
            };
            assert_eq!(
                VolumeRecord::decode(&marked.encode()),
                Err(CodecError::Field)
            );
        }
        let mut compacted = gap;
        compacted.events.remove(0);
        compacted.forced = true;
        assert_eq!(VolumeRecord::decode(&compacted.encode()), Ok(compacted));

        let mut prior = fresh();
        prior
            .events
            .push(entry(1, EventKind::Gone, 13, ERA, Some("i-0000000d")));
        prior.next = 2;
        assert_eq!(VolumeRecord::decode(&prior.encode()), Ok(prior.clone()));
        let mut marked = prior.clone();
        marked.events.remove(1);
        marked.forced = true;
        assert_eq!(marked.succeeds(&prior), Err(SuccessorRule::Events));
        assert_eq!(
            VolumeRecord::decode(&marked.encode()),
            Err(CodecError::Field)
        );

        let departed = VolumeRecord {
            next: 2,
            forced: false,
            fence: 0,
            pairs: Vec::new(),
            events: vec![
                entry(0, EventKind::Gone, 12, ERA, Some("i-0000000c")),
                entry(1, EventKind::Attach, 13, ERA, Some("i-0000000d")),
            ],
            ..volume()
        };
        let mut removed = departed.clone();
        removed.events.remove(0);
        assert_eq!(removed.succeeds(&departed), Ok(()));
        let mut removed_marked = removed.clone();
        removed_marked.forced = true;
        assert_eq!(
            VolumeRecord::decode(&removed_marked.encode()),
            Ok(removed_marked.clone())
        );
        assert_eq!(
            removed_marked.succeeds(&departed),
            Err(SuccessorRule::Events)
        );
        assert_eq!(
            removed_marked.succeeds(&removed),
            Err(SuccessorRule::Events)
        );
        let mut forced = removed.clone();
        forced.push(EventKind::Force, host(14), ERA);
        assert_eq!(forced.succeeds(&removed), Ok(()));
        let fixture = entries();
        let mut compacted_force = fixture.clone();
        compacted_force.events.remove(0);
        assert_eq!(compacted_force.succeeds(&fixture), Ok(()));

        let mut empty = fresh();
        empty.events.clear();
        for (next, forced, decoded) in [(7, false, true), (7, true, true), (0, true, false)] {
            let record = VolumeRecord {
                next,
                forced,
                ..empty.clone()
            };
            let bytes = record.encode();
            assert_eq!(bytes[5], 2);
            let expected = if decoded {
                Ok(record)
            } else {
                Err(CodecError::Field)
            };
            assert_eq!(
                VolumeRecord::decode(&bytes),
                expected,
                "next {next}, forced {forced}"
            );
        }
        let unmarked = VolumeRecord {
            next: 7,
            ..empty.clone()
        };
        let marked = VolumeRecord {
            forced: true,
            ..unmarked.clone()
        };
        assert_eq!((unmarked.encode()[5], marked.encode()[5]), (2, 2));
        assert_eq!(
            marked.succeeds(&unmarked),
            Ok(()),
            "between two records format 2 expresses, a compacted history takes the mark as before"
        );
    }

    #[test]
    fn a_pushed_force_detach_sets_the_force_mark() {
        let mut record = fresh();
        assert!(!record.forced);
        record.push(EventKind::Force, host(12), ERA);
        assert!(record.forced);
        assert_eq!(VolumeRecord::decode(&record.encode()), Ok(record.clone()));
        let unmarked = VolumeRecord {
            forced: false,
            ..record.clone()
        };
        assert_eq!(
            VolumeRecord::decode(&unmarked.encode()),
            Err(CodecError::Field),
            "a whole history holding a force-detach without the mark"
        );
        record.push(EventKind::Attach, host(13), ERA);
        assert!(record.forced);
        assert_eq!(VolumeRecord::decode(&record.encode()), Ok(record));
    }
}

#[cfg(kani)]
mod verification {
    use super::{
        ANCESTRY, ATTEMPTS_MAX, CodecError, LSN_LIMIT, MAX_CHAIN, Reader, SUFFIX, Suffix,
        UNIT_ENTRIES, prefix_floor, put_ancestry, slot_units, slotted,
    };

    /// The suffixes of a 129-byte ancestry field, parsed with `u64::from_be_bytes` at their fixed offsets.
    fn fields(bytes: &[u8]) -> [Suffix; MAX_CHAIN] {
        let word = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
        let mut suffixes = [Suffix::default(); MAX_CHAIN];
        for (at, suffix) in suffixes.iter_mut().enumerate() {
            let base = 1 + at * SUFFIX;
            *suffix = Suffix {
                session: word(base),
                start: word(base + 8),
                certified: word(base + 16),
                end: word(base + 24),
            };
        }
        suffixes
    }

    /// The chain BOUNDED-MANIFEST admits, restated over the parsed suffixes.
    fn admitted(suffixes: &[Suffix], generation: u32, attempts: u32, cut: u64) -> bool {
        suffixes.iter().enumerate().all(|(at, suffix)| {
            let epoch = suffix.session as u32;
            let ordered = match at {
                0 => suffix.end > cut,
                _ => {
                    suffix.session > suffixes[at - 1].session
                        && suffix.start >= suffixes[at - 1].end
                }
            };
            (suffix.session >> 32) as u32 == generation
                && epoch % 2 == 0
                && epoch >= 2
                && u64::from(epoch) <= 2 * u64::from(attempts)
                && suffix.start < suffix.end
                && suffix.start <= suffix.certified
                && suffix.certified <= suffix.end
                && suffix.end <= LSN_LIMIT + 1
                && ordered
        })
    }

    /// Over a symbolic ancestry field with a symbolic `g`, `E` at most `ATTEMPTS_MAX` and cut: the decoder admits
    /// exactly the chains the predicate admits, with a count above the cap refusing `Length` and a nonzero tail
    /// refusing `Flag`, and every admitted chain re-encodes to its count byte and suffix fields. Field-wise
    /// comparison keeps the suffix loops within four iterations; the encoder's eight-byte extends need eight, so the
    /// unwind bound is ten.
    #[kani::proof]
    #[kani::unwind(10)]
    fn ancestry_codec_admits_exactly_ordered_bounded_chains() {
        let bytes: [u8; ANCESTRY] = kani::any();
        let (generation, attempts, cut): (u32, u32, u64) = (kani::any(), kani::any(), kani::any());
        kani::assume(attempts <= ATTEMPTS_MAX);
        let len = usize::from(bytes[0]);
        let suffixes = fields(&bytes);
        let decoded = Reader(&bytes).ancestry(generation, attempts, cut);
        if len > MAX_CHAIN {
            assert_eq!(decoded, Err(CodecError::Length));
            kani::cover!(true);
            return;
        }
        let tail_zero = suffixes[len..].iter().all(|s| *s == Suffix::default());
        let admitted = admitted(&suffixes[..len], generation, attempts, cut);
        match decoded {
            Ok(chain) => {
                assert!(admitted && tail_zero);
                assert_eq!(chain.as_slice(), &suffixes[..len]);
                let mut out = Vec::with_capacity(ANCESTRY);
                put_ancestry(&mut out, &chain);
                assert_eq!(out.len(), ANCESTRY);
                assert_eq!(out[0], bytes[0]);
                assert_eq!(fields(&out), suffixes);
                kani::cover!(len == MAX_CHAIN);
            }
            Err(CodecError::Flag) => assert!(admitted && !tail_zero),
            Err(CodecError::Field) => assert!(!admitted),
            Err(error) => panic!("ancestry decode returned {error:?}"),
        }
        kani::cover!(len == 2 && !admitted);
    }

    #[kani::proof]
    fn prefix_floor_formula() {
        assert_eq!(prefix_floor(3, 1 << 25), Some(2_455_207));
        let entries = u64::from(kani::any::<u32>());
        let ceiling = slot_units(entries) - 1;
        assert!(ceiling * UNIT_ENTRIES >= entries);
        assert!(ceiling == 0 || (ceiling - 1) * UNIT_ENTRIES < entries);
        let (slots, units) = (u64::from(kani::any::<u8>()), kani::any::<u64>());
        let exact = 1 + u128::from(slots) * u128::from(units);
        kani::cover!(exact > u128::from(u64::MAX));
        kani::cover!(exact <= u128::from(u64::MAX) && slots > 0);
        match slotted(slots, units) {
            Some(floor) => assert_eq!(u128::from(floor), exact),
            None => assert!(exact > u128::from(u64::MAX)),
        }
    }
}
