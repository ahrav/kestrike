//! The reconciler's standby population: which shards need a host designated their standby, the headroom a
//! candidate host must report, and the per-AZ census record that caps the shards holding a standby slot and binds
//! each slot to one host. The cap bounds correlated recovery load where standbys are designated, and the takeover
//! path spends no budget.
//!
//! - POPULATION-CAP: the census of an AZ lists at most `cap` shards whenever [`Population::admit`] adds one, each
//!   with the `(g, owner, E)` and the host its slot was reserved for. A [`Slot`] comes only from a census the store
//!   client read or committed that lists its shard for its host at its target, and `Reconciler::designate` writes
//!   only at that target. Every reconciler reserves by an exact-version write of the one census record, so
//!   concurrent reconcilers share the cap.
//! - ONE-HOST-PER-SLOT: a census entry names one host. [`Population::admit`] moves a slot to another host only when
//!   the caller's evidence shows the incumbent lost: the entry's host at any target unless the record names it
//!   owner, or else the standby the record names. `Reconciler::designate` writes only for the host the census lists
//!   after its shard read, so a stale reconciler's retry cannot replace a newer designation.
//! - CENSUS-COVERS: every shard record that names a standby by a designation has a census entry. A reservation
//!   precedes its designation, and [`Census::released`] drops an entry only when the shard record, read after the
//!   census, names no standby and holds another `(g, owner, E)` than the entry's, and the entry's host is the
//!   record's owner or holds no live attach of its active volume. A shard record's `(g, owner, E)` never returns to
//!   an earlier value, and a reservation reads the shard record after the census, so an entry's `(g, owner, E)` only
//!   advances and a designation under a dropped entry's slot fails as stale. An entry whose reconciler stopped before
//!   its designation stays, counted, until the shard's tenure moves, and an entry whose host is attached stays
//!   counted while that attach is live.
//! - HEADROOM: a new reservation names a candidate whose host report shows a recovery slot below its limit and,
//!   unless the volume record shows its live attach of the active volume ([`Attach::Live`]), an attachment slot
//!   below its limit after the census entries of other shards that name it and whose shard its report does not list
//!   in the standby role, each of which can still take an attach of that host. An unavailable gauge admits no candidate. The caller
//!   bounds the report's age; [`Population::admit`] reads only its gauges and entries.
//! - FEASIBLE-SLOT: [`Population::admit`] refuses the owner, a candidate of a record at `E = 0`, and a candidate
//!   whose attach of the active volume reads [`Attach::Closed`], and `Reconciler::reserve` refuses
//!   an active volume whose record no designation accepts, each before any census write. Enrollment and the
//!   designation check the rest of the designation's conditions.
//! - HOST-LOSS-KEEPS-VOLUME: [`need`] answers only with a standby designation; after owner loss the designated host
//!   takes over the retained volume at its generation.
//! - SLOT-RECLAMATION: an attach ends in recorded steps, so a volume outlives any number of replacements while it
//!   holds at most [`MAX_ATTACHED`] live attaches and [`MAX_EVENTS`] entries. `Reconciler::end_attach` ends the
//!   attach of a host the shard record names neither owner nor standby, which takes the entry out of the live count at
//!   that write: ending the attach frees one live slot for [`Attach::of`], and [`Census::released`] judges the host
//!   as one with no live attach. The owner then drops the ended pair after a Report shows its key absent,
//!   `Reconciler::detachable` witnesses the entry ended with no pair before the control-plane detach, and
//!   `Reconciler::release_attach` marks it gone after two settled listings without its instance; a full record sheds
//!   a gone entry at the next standby attach. Until its end, an attach whose request failed for good stays live with
//!   no enrolled pair and is admitted through its entry's instance, or through `peers`
//!   (`failover::poll::Reads::peers`) for a format-2 entry. A live, enrolled, attached host stays a designation
//!   candidate, so a deposed owner designated again keeps its attach and its key; a host that attaches again
//!   after its entry went takes a new key. Recorded pairs stay within [`Bounds::pair_cap`]: an ended pair leaves only
//!   by the owner's drop, so successors that each enroll and end with no owner past its fencing boundary fill the
//!   pair cap and the next attach refuses `Closed`. The chain-depth statement of SUPERSEDED-TENURE-PREEMPT in
//!   `failover::takeover` counts attached hosts under these bounds.
//!
//! The census has no watermark entry, so a store that returned an earlier census could admit designations past the
//! cap; the cap bounds load and carries no ownership decision. The caller supplies each shard's AZ, since the shard
//! record names none, and reserves each shard in that one AZ. Any live enrolled host is a candidate, a deposed owner
//! on its original attachment included; its takeover then runs under the reused attachment key (KEY-REUSE-EXPOSURE in
//! `failover::takeover`), which costs availability and keeps safety.

use crate::failover::bounds::Bounds;
use crate::failover::records::{
    ATTEMPTS_MAX, CodecError, EventKind, Host, MAX_ATTACHED, MAX_EVENTS, Reader, Record,
    ShardRecord, SuccessorRule, VolumeRecord, attachment_key, head,
};
use crate::failover::report::{Gauge, HostReport, RecordedRole, VolumeEntry};
use crate::failover::retire::Target;
use crate::net::ownership::{Shard, ShardGeneration};
use crate::storage::store::Read;

/// An availability zone's number in the fleet, which keys its census.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Zone(pub u16);

/// The most entries a census holds.
pub const MAX_SLOTS: usize = 4096;

const CENSUS_VERSION: u16 = 1;
const CENSUS_FIXED: usize = 4 + 2 + 2 + 2;
const CENSUS_ENTRY: usize = 4 + 4 + 8 + 4 + 8;

/// A census's largest encoding.
pub const CENSUS_MAX: usize = CENSUS_FIXED + MAX_SLOTS * CENSUS_ENTRY;

/// One reserved slot: the `(g, owner, E)` it was reserved for and the host it was reserved for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub target: Target,
    pub host: Host,
}

/// One encoded census entry: the shard, then the generation, owner, `E` and host of its slot, big-endian.
type Row = [u8; CENSUS_ENTRY];

fn word<const N: usize>(row: &Row, at: usize) -> [u8; N] {
    let mut word = [0; N];
    word.copy_from_slice(&row[at..at + N]);
    word
}

/// The shard, generation, owner, `E` and host `row` holds.
fn fields(row: &Row) -> (u32, u32, u64, u32, u64) {
    let (shard, generation) = (word(row, 0), word(row, 4));
    let (owner, attempts, host) = (word(row, 8), word(row, 16), word(row, 20));
    (
        u32::from_be_bytes(shard),
        u32::from_be_bytes(generation),
        u64::from_be_bytes(owner),
        u32::from_be_bytes(attempts),
        u64::from_be_bytes(host),
    )
}

/// The entry `row` holds, or `None` for a zero generation, owner or host.
fn parsed(row: &Row) -> Option<Entry> {
    let (_, generation, owner, attempts, host) = fields(row);
    let target = Target {
        generation: ShardGeneration::new(generation.into())?,
        owner: Host::new(owner)?,
        attempts,
    };
    let host = Host::new(host)?;
    Some(Entry { target, host })
}

/// The row of `shard`'s slot holding `entry`.
fn row(shard: Shard, entry: Entry) -> Row {
    let mut row = [0; CENSUS_ENTRY];
    row[..4].copy_from_slice(&shard.get().to_be_bytes());
    row[4..8].copy_from_slice(&(entry.target.generation.get() as u32).to_be_bytes());
    row[8..16].copy_from_slice(&entry.target.owner.get().to_be_bytes());
    row[16..20].copy_from_slice(&entry.target.attempts.to_be_bytes());
    row[20..].copy_from_slice(&entry.host.get().to_be_bytes());
    row
}

fn feasible(generation: u32, owner: u64, attempts: u32, host: u64) -> bool {
    let attempted = (1..=ATTEMPTS_MAX).contains(&attempts);
    generation != 0 && owner != 0 && host != 0 && host != owner && attempted
}

fn admitted(rows: &[Row]) -> bool {
    let mut last = 0;
    rows.iter().all(|row| {
        let (shard, generation, owner, attempts, host) = fields(row);
        let before = core::mem::replace(&mut last, shard);
        shard > before && feasible(generation, owner, attempts, host)
    })
}

fn framed(bytes: &[u8]) -> Result<&[Row], CodecError> {
    let count = bytes
        .get(CENSUS_FIXED - 2..CENSUS_FIXED)
        .map_or(0, |count| {
            usize::from(u16::from_be_bytes([count[0], count[1]]))
        });
    if count > MAX_SLOTS || bytes.len() != CENSUS_FIXED + count * CENSUS_ENTRY {
        return Err(CodecError::Length);
    }
    let mut r = Reader::open(bytes, b"STBY", CENSUS_VERSION)?;
    r.take::<4>()?;
    Ok(r.0.as_chunks().0)
}

fn check(bytes: &[u8]) -> Result<(), CodecError> {
    let sound = admitted(framed(bytes)?);
    sound.then_some(()).ok_or(CodecError::Field)
}

fn shared(rows: &[Row], known: &[Row]) -> usize {
    type Stride = [Row; 64];
    let (rows, known) = (rows.as_chunks().0, known.as_chunks().0);
    let alike = |(ours, theirs): &(&Stride, &Stride)| ours.as_flattened() == theirs.as_flattened();
    64 * rows.iter().zip(known).take_while(alike).count()
}

/// One AZ's standby census: the shards holding a standby slot, ascending, each with its [`Entry`]. The value holds
/// its encoding: the magic `STBY`, the format version, the zone, the entry count and one 28-byte entry per shard,
/// big-endian. Every held entry carries a nonzero shard, generation, owner and host, since the decoder refuses a
/// zero field and [`Population::admit`] writes typed values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Census {
    bytes: Vec<u8>,
    sound: bool,
}

impl Census {
    /// The census of `zone` with no entry.
    pub fn empty(zone: Zone) -> Self {
        let mut bytes = head(b"STBY", CENSUS_VERSION, CENSUS_FIXED);
        bytes.extend(zone.0.to_be_bytes());
        bytes.extend(0u16.to_be_bytes());
        Self { bytes, sound: true }
    }

    /// [`Record::decode`] over bytes the caller owns, which become the census with no copy.
    ///
    /// # Errors
    ///
    /// The error [`Record::decode`] returns for the same bytes.
    pub fn decode_owned(bytes: Vec<u8>) -> Result<Self, CodecError> {
        check(&bytes)?;
        Ok(Self { bytes, sound: true })
    }

    /// CENSUS-MEMO: [`Census::decode_owned`] beside `memo`, a census its caller kept from an earlier read or write.
    ///
    /// # Errors
    ///
    /// The error [`Record::decode`] returns for the same bytes.
    pub(crate) fn decode_like(bytes: Vec<u8>, memo: &Option<Self>) -> Result<Self, CodecError> {
        let Some(known) = memo.as_ref().filter(|known| known.sound) else {
            return Self::decode_owned(bytes);
        };
        let rows = framed(&bytes)?;
        let same = shared(rows, known.rows());
        if !admitted(&rows[same.saturating_sub(1)..]) {
            return Err(CodecError::Field);
        }
        Ok(Self { bytes, sound: true })
    }

    /// LENT-ENCODING: the census lends its held encoding to one store write until [`Census::restore`] returns the
    /// bytes.
    ///
    /// # Errors
    ///
    /// `Field` for an entry the decoder refuses, as [`Population::admit`] writes for a record whose `E` is above
    /// [`ATTEMPTS_MAX`].
    pub(crate) fn lend(&mut self) -> Result<Vec<u8>, CodecError> {
        if !self.sound {
            check(&self.bytes)?;
        }
        Ok(core::mem::take(&mut self.bytes))
    }

    pub(crate) fn restore(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    pub fn zone(&self) -> Zone {
        Zone(u16::from_be_bytes([self.bytes[6], self.bytes[7]]))
    }

    fn rows(&self) -> &[Row] {
        self.bytes[CENSUS_FIXED..].as_chunks().0
    }

    fn at(&self, shard: Shard) -> Result<usize, usize> {
        let held = |row: &Row| fields(row).0;
        self.rows().binary_search_by_key(&shard.get(), held)
    }

    /// The entry of `shard`'s slot.
    pub fn slot(&self, shard: Shard) -> Option<Entry> {
        parsed(&self.rows()[self.at(shard).ok()?])
    }

    pub fn len(&self) -> usize {
        self.rows().len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows().is_empty()
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (Shard, Entry)> + '_ {
        let entry = |row: &Row| Some((Shard::new(fields(row).0)?, parsed(row)?));
        self.rows().iter().filter_map(entry)
    }

    /// HEADROOM: a reservation of another shard than `shard` for `candidate`'s writer counts against its attachment
    /// headroom until its report lists that shard in the standby role.
    pub(crate) fn pending(&self, shard: Shard, candidate: &HostReport) -> u64 {
        let named = candidate.writer.host.get().to_be_bytes();
        let standby = |held: u32| lists_standby(candidate, held);
        let mut pending = 0;
        for chunk in self.rows().chunks(64) {
            let named_bit = |mask: u64, (bit, row): (usize, &Row)| {
                mask | (u64::from(word::<8>(row, 20) == named) << bit)
            };
            let mut named_rows = chunk.iter().enumerate().fold(0, named_bit);
            while named_rows != 0 {
                let held = fields(&chunk[named_rows.trailing_zeros() as usize]).0;
                pending += u64::from(held != shard.get() && !standby(held));
                named_rows &= named_rows - 1;
            }
        }
        pending
    }

    /// The census with the `removed` rows from index `at` replaced by `added`, and the entry count that leaves.
    fn spliced(&self, at: usize, removed: usize, added: Option<Row>) -> Self {
        let rows = self.rows();
        let placed = added.is_none_or(|row| {
            let (shard, generation, owner, attempts, host) = fields(&row);
            let after = |held: &Row| fields(held).0 < shard;
            let before = |held: &Row| shard < fields(held).0;
            let ordered = rows[..at].last().is_none_or(after)
                && rows[at + removed..].first().is_none_or(before);
            shard != 0 && feasible(generation, owner, attempts, host) && ordered
        });
        let (kept, rest) = self.bytes.split_at(CENSUS_FIXED + at * CENSUS_ENTRY);
        let rest = &rest[removed * CENSUS_ENTRY..];
        let mut bytes = Vec::with_capacity(kept.len() + CENSUS_ENTRY + rest.len());
        bytes.extend_from_slice(kept);
        bytes.extend(added.iter().flatten());
        bytes.extend_from_slice(rest);
        let count = (bytes.len() - CENSUS_FIXED) / CENSUS_ENTRY;
        bytes[8..CENSUS_FIXED].copy_from_slice(&(count as u16).to_be_bytes());
        let sound = match self.sound {
            true => placed && count <= MAX_SLOTS,
            false => check(&bytes).is_ok(),
        };
        Self { bytes, sound }
    }

    /// The census without the entry of `record`'s shard, or `None` when the entry stays: the census lists no such
    /// entry, the record names a standby, the record holds the entry's `(g, owner, E)`, under which a reserved
    /// designation can still commit, or the entry's host is not the owner and `live` shows its live attach of the
    /// record's active volume. The caller reads `record` after the census it writes over, and the volume record
    /// `live` reads after `record` (CENSUS-COVERS).
    pub fn released(&self, record: &ShardRecord, live: impl Fn(Host) -> bool) -> Option<Self> {
        let at = self.release_at(record, live)?;
        Some(self.spliced(at, 1, None))
    }

    /// Whether [`Census::released`] drops the entry of `record`'s shard under `live`.
    pub(crate) fn releases(&self, record: &ShardRecord, live: impl Fn(Host) -> bool) -> bool {
        self.release_at(record, live).is_some()
    }

    fn release_at(&self, record: &ShardRecord, live: impl Fn(Host) -> bool) -> Option<usize> {
        let at = self.at(record.shard).ok()?;
        let entry = parsed(&self.rows()[at])?;
        if record.standby.is_some()
            || entry.target == Target::of(record)
            || (entry.host != record.owner && live(entry.host))
        {
            return None;
        }
        Some(at)
    }
}

impl Record for Census {
    fn encode(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Refuses a length other than the count's, more than [`MAX_SLOTS`] entries, shards out of ascending order, a
    /// zero shard, generation, owner or host, `E` of zero or above [`ATTEMPTS_MAX`], and an entry whose host is its
    /// target's owner, which [`Population::admit`] never writes (FEASIBLE-SLOT).
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        Self::decode_owned(bytes.to_vec())
    }

    /// A census keeps its zone.
    fn succeeds(&self, prior: &Self) -> Result<(), SuccessorRule> {
        if self.zone() == prior.zone() {
            Ok(())
        } else {
            Err(SuccessorRule::Identity)
        }
    }
}

pub(crate) fn room(gauge: Gauge, owed: u64) -> bool {
    matches!(gauge, Gauge::Known { used, limit } if used.saturating_add(owed) < limit.get())
}

pub(crate) fn lists_standby(candidate: &HostReport, shard: u32) -> bool {
    let listed =
        |seen: &VolumeEntry| seen.shard.get() == shard && seen.role == Some(RecordedRole::Standby);
    candidate.entries.iter().any(listed)
}

/// What a shard needs from the reconciler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// The owner is lost and the record names no standby or a lost one, as after owner and standby loss or after a
    /// successor owner is lost: attach a fresh host to the retained volume and designate it, so it takes over. Its
    /// takeover preempts a recorded registration of another host; with no registration holding, its Report #1
    /// refuses `Holder(Unresolved)` and the volume stays retained (NO-HOLDER-HOLD in `failover::restart`).
    Fresh,
    /// The caller's evidence does not show the owner lost, and the record names no standby or a lost one: enroll or
    /// replace a standby. This answer does not establish that the owner is live; the planner checks that on its own.
    Standby,
}

/// The need of the shard `record` holds, judged with `lost`, the reconciler's evidence that a host is gone. A record
/// at `E = 0`, whose fresh first acquisition has not run, and a record naming a standby `lost` does not show gone
/// need nothing. [`need_of`] also counts the owner or named standby as lost if its attach to the active volume has
/// ended.
pub fn need(record: &ShardRecord, lost: impl Fn(Host) -> bool) -> Option<Need> {
    if record.attempts == 0 || record.standby.is_some_and(|standby| !lost(standby)) {
        return None;
    }
    Some(if lost(record.owner) {
        Need::Fresh
    } else {
        Need::Standby
    })
}

/// For the active volume, ENDED-GRANTS-NOTHING makes an ended attach count as a loss of the owner or named standby.
pub fn need_of(
    record: &ShardRecord,
    volume: &VolumeRecord,
    lost: impl Fn(Host) -> bool,
) -> Option<Need> {
    let active = volume.volume == record.active;
    need(record, |host| {
        lost(host) || (active && volume.live(host).is_none())
    })
}

/// Applies the active-volume attachment check from [`need_of`] to `record.standby`.
pub fn standby_ended(record: &ShardRecord, volume: &VolumeRecord, host: Host) -> bool {
    record.standby == Some(host) && volume.volume == record.active && volume.live(host).is_none()
}

/// Why [`Population::admit`] refused a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The candidate's report shows its recovery gauge unavailable or at its limit, or, without a live attach of the
    /// active volume, its attachment gauge unavailable or with no slot left after the pending reservations (HEADROOM).
    Headroom,
    /// The census lists `cap` shards, or [`MAX_SLOTS`], and not this one.
    Full,
    /// The slot's incumbent is another host the caller's evidence does not show lost (ONE-HOST-PER-SLOT).
    Taken,
    /// The candidate is the record's owner, or the record is at `E = 0` (FEASIBLE-SLOT).
    Ineligible,
    /// The candidate's attach of the active volume reads [`Attach::Closed`]: [`Closed::of`] names its bound.
    Closed,
}

/// The candidate's attach of the shard record's active volume, from the volume record the caller reads after the
/// shard record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    /// The candidate holds a live attach whose pair is enrolled or whose entry's key is free, the one check
    /// [`Closed::of`] applies to a live attach, so its designation uses that attach.
    Live,
    /// A candidate with zero live attaches qualifies for a new attach entry when it passes every [`Closed::of`]
    /// check.
    Open,
    /// The candidate fails a [`Closed::of`] check, which names the bound.
    Closed,
}

impl Attach {
    /// The attach of `host` that `volume` shows under the owner's `bounds`, the rule `Reconciler::record_standby`
    /// applies before it records a new attach: `Closed` exactly when [`Closed::of`] names a bound.
    pub fn of(volume: &VolumeRecord, host: Host, bounds: &Bounds) -> Self {
        match (volume.live(host), Closed::of(volume, host, bounds)) {
            (_, Some(_)) => Self::Closed,
            (Some(_), None) => Self::Live,
            (None, None) => Self::Open,
        }
    }
}

/// Why a volume record admits no attach of a host ([`Attach::Closed`]), the first check of [`Closed::of`] that fails,
/// in the order it lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// The record holds [`MAX_ATTACHED`] live attaches.
    LiveCap,
    /// The record holds [`MAX_EVENTS`] events and no gone entry it can shed for the host, or the entry number the
    /// attach takes gives no [`attachment_key`].
    EntryCap,
    /// The record's pairs and its live attaches awaiting enrollment reach [`Bounds::pair_cap`].
    PairCap,
    /// The host's own entry blocks a new attach (ATTACH-AFTER-GONE). A retained `Ended` entry blocks it until
    /// reclamation marks the entry gone. A latest format-2 detach or force-detach blocks it while that event stays the
    /// host's latest, since only an `Ended` entry turns gone.
    OwnEntry,
    /// A recorded pair holds the key of the entry number the attach takes: the next entry's for a new attach, or the
    /// host's live unenrolled entry's own.
    KeyTaken,
}

impl Closed {
    /// The bound at which `volume` admits no attach of `host` under the owner's `bounds`, `None` when it admits one.
    /// The checks run in this order:
    ///
    /// 1. A live attach of `host`: `None` when its pair is enrolled or its entry's key is free; otherwise the key's
    ///    bound, `EntryCap` for an entry number with no key and `KeyTaken` for a key a recorded pair holds.
    /// 2. `OwnEntry` while `host` holds a retained `Ended` entry or its latest event is a format-2 detach or
    ///    force-detach.
    /// 3. `LiveCap` at [`MAX_ATTACHED`] live attaches.
    /// 4. `EntryCap` at [`MAX_EVENTS`] events with no gone entry the record can shed for `host`.
    /// 5. The bound of `volume.next`'s key, as in 1.
    /// 6. `PairCap` when the recorded pairs plus the live attaches awaiting enrollment reach [`Bounds::pair_cap`].
    pub fn of(volume: &VolumeRecord, host: Host, bounds: &Bounds) -> Option<Self> {
        let key = |seq: u32| match attachment_key(seq) {
            None => Some(Self::EntryCap),
            Some(key) if volume.pairs.iter().any(|recorded| recorded.pair.key == key) => {
                Some(Self::KeyTaken)
            }
            Some(_) => None,
        };
        if let Some(seq) = volume.live(host) {
            return volume.enrolled(host).map_or_else(|| key(seq), |_| None);
        }
        let ended = volume
            .events
            .iter()
            .any(|event| event.host == host && event.kind == EventKind::Ended);
        let detached = volume
            .latest(host)
            .is_some_and(|(_, event)| matches!(event.kind, EventKind::Detach | EventKind::Force));
        let awaiting = volume
            .live_hosts()
            .filter(|&live| volume.enrolled(live).is_none())
            .count();
        if ended || detached {
            Some(Self::OwnEntry)
        } else if volume.live_hosts().count() >= MAX_ATTACHED {
            Some(Self::LiveCap)
        } else if volume.events.len() >= MAX_EVENTS && volume.removable_gone(host).next().is_none()
        {
            Some(Self::EntryCap)
        } else if let Some(bound) = key(volume.next) {
            Some(bound)
        } else if volume.pairs.len() + awaiting >= bounds.pair_cap() {
            Some(Self::PairCap)
        } else {
            None
        }
    }
}

/// The admission of one designation: the census zone, the shard, the `(g, owner, E)` its census slot is reserved
/// for, and the host. Only [`Slot::held`] makes one, and [`Reconciler::designate`] requires it.
///
/// [`Reconciler::designate`]: crate::failover::reconcile::Reconciler::designate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    zone: Zone,
    shard: Shard,
    entry: Entry,
}

impl Slot {
    /// The slot `census`, a census the store client read or committed, lists for `shard` and `host`.
    pub fn held(census: &Read<Census>, shard: Shard, host: Host) -> Option<Self> {
        let entry = census.value().slot(shard).filter(|e| e.host == host)?;
        Some(Self {
            zone: census.value().zone(),
            shard,
            entry,
        })
    }

    pub fn zone(&self) -> Zone {
        self.zone
    }

    pub fn shard(&self) -> Shard {
        self.shard
    }

    pub fn target(&self) -> Target {
        self.entry.target
    }

    pub fn host(&self) -> Host {
        self.entry.host
    }
}

/// The per-AZ cap on shards holding a standby slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Population {
    pub cap: usize,
}

impl Population {
    /// The census that reserves the slot of `record`'s shard at `record`'s `(g, owner, E)` for `candidate`'s writer,
    /// `candidate` a report the report reader accepted and `attach` its attach of the active volume, or `None` when
    /// `census` already lists that slot for that host. A shard the census lists keeps its place and takes the
    /// record's target and the candidate (HEADROOM, FEASIBLE-SLOT). `lost` is the caller's evidence that a host can
    /// no longer serve as the shard's standby: a host that is gone, and a reserved host whose attach failed for good.
    /// The caller reads `record` after the census it writes over (CENSUS-COVERS).
    ///
    /// # Errors
    ///
    /// [`Refusal::Ineligible`], then [`Refusal::Closed`] and [`Refusal::Headroom`], then [`Refusal::Taken`] when the
    /// incumbent, the entry's host unless the record names it owner, or else the standby the record names, is
    /// another host `lost` does not show gone, then [`Refusal::Full`].
    pub fn admit(
        &self,
        census: &Census,
        record: &ShardRecord,
        candidate: &HostReport,
        attach: Attach,
        lost: impl Fn(Host) -> bool,
    ) -> Result<Option<Census>, Refusal> {
        let host = candidate.writer.host;
        if record.attempts == 0 || host == record.owner {
            return Err(Refusal::Ineligible);
        }
        let entry = Entry {
            target: Target::of(record),
            host,
        };
        let listed = census.at(record.shard);
        let held = listed.ok().and_then(|at| parsed(&census.rows()[at]));
        if held == Some(entry) {
            return Ok(None);
        }
        let headroom = candidate.host.headroom;
        let attaches = match attach {
            Attach::Live => true,
            Attach::Open => room(
                headroom.attachments,
                census.pending(record.shard, candidate),
            ),
            Attach::Closed => return Err(Refusal::Closed),
        };
        if !attaches || !room(headroom.recovery, 0) {
            return Err(Refusal::Headroom);
        }
        let incumbent = held
            .map(|held| held.host)
            .filter(|&h| h != record.owner)
            .or(record.standby);
        if incumbent.is_some_and(|h| h != host && !lost(h)) {
            return Err(Refusal::Taken);
        }
        if listed.is_err() && census.len() >= self.cap.min(MAX_SLOTS) {
            return Err(Refusal::Full);
        }
        let (Ok(at) | Err(at)) = listed;
        let added = Some(row(record.shard, entry));
        Ok(Some(census.spliced(at, usize::from(listed.is_ok()), added)))
    }
}

#[cfg(kani)]
mod population_kani;

#[cfg(test)]
#[path = "standbys_tests.rs"]
pub(crate) mod tests;
