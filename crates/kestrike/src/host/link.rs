//! The link between an owner process and its host's agent: a fixed-layout, versioned codec for the four messages
//! they exchange, the [`StatusCell`] the owner thread fills, and the [`Inbox`] it drains. An owner publishes a
//! [`Status`]; the agent sends it a [`Nominate`](Inbound::Nominate), a [`Peer`](Inbound::Peer) or a
//! [`Request`](Inbound::Request).
//!
//! Layout, big-endian at fixed offsets: the link [`VERSION`] `u16` at 0 and the kind `u8` at 2 (1 status,
//! 2 nominate, 3 peer, 4 request), then the kind's body.
//!
//! - Status, [`STATUS_LEN`] bytes: the phase label at 3, a presence byte at 4 (bit 0 tenure, bit 1 target, bit 2
//!   Report age, bit 3 read age, bit 4 entry), the exit label at 5 (0 none), the shard `u32` at 6, the pid `u32`
//!   at 10, the volume field at 14, the tenure's `g` `u64` and `a` `u32`, the target's `g` `u64`, owner `u64` and
//!   `E` `u32`, the Report age, the read age, `io`, `completions` and `pending`, `u64` each, and the report entry in
//!   [`VolumeEntry::encode`]'s form.
//! - Nominate, [`NOMINATE_LEN`] bytes: the shard `u32` at 3, the target's `g` `u64`, owner `u64` and `E` `u32`, and
//!   `until_us` `u64`.
//! - Peer, [`PEER_LEN`] bytes: a presence byte at 3 and `read_at` `u64` at 4.
//! - Request: the byte count `u16` at 3, from 1 to [`REQUEST_MAX`], and that many opaque bytes at 5.
//!
//! The phase and exit labels use the host report's tables: code 0 names no exit, and code `i + 1` the `i`-th label
//! of [`Phase`] or [`Ended`] in declaration order.
//!
//! Invariants:
//!
//! - ONE-ENCODING: an absent field has a clear presence bit and zero-filled bytes. [`decode`] accepts exactly the
//!   encodings [`encode`] and [`encode_status`] write, so a decoded message re-encodes to the bytes it came from. A
//!   short, long or wrong-version encoding, an unknown kind or label byte and a field outside its type each return
//!   a typed [`LinkError`].
//! - BOUNDED: every message has a fixed length or a length bounded by [`REQUEST_MAX`]. The inbox holds at most
//!   [`INBOX`] messages in storage reserved at construction.
//! - TRY-LOCK-ONLY: the owner thread and the link side both take the cell and the inbox with `try_lock`, so each
//!   call returns at once. A contended publication returns `false` and keeps the cell's value, and a contended
//!   drain keeps the messages queued.
//! - OCCUPANCY-FLAG: the cell and the inbox each keep an atomic flag that only the side holding the lock writes:
//!   set before the lock is released over a status or a message, cleared by the take and by the drain that passed
//!   its last message. The flag is true whenever a status or a message waits. After a drain whose callback unwinds
//!   on the last message it stays true over an empty queue until the next drain. [`StatusCell::take`] and
//!   [`Inbox::drain`] load the flag first and a call that loads false returns without the lock, so the owner's
//!   turn with nothing delivered costs one load. A false load is a missed poll, as a contended `try_lock` is, and a
//!   later call takes what waits. The flag gates the `try_lock`: the lock orders every read and write of the
//!   status and the queue, so the flag's loads and stores are relaxed. [`StatusCell::waiting`] also loads the
//!   cell's flag; it orders no data, so a relaxed load gives it the occupancy the last store left, and a publisher
//!   that reads it after its own accepted publication learns whether a take has followed that publication.
//! - LINK-CARRIES-VALUES: a nomination starts the takeover sequence, and that sequence's step 1 and its
//!   compare-and-swap determine whether the takeover commits. A peer read time is an availability input. A status
//!   and a request carry observations and bytes. The owner's records and its device change only through the
//!   sequences and the serving table.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

use super::exit::Exit;
use crate::failover::detect::host::Revalidated;
use crate::failover::records::{Host, VOLUME, VolumeId};
use crate::failover::report::{ENTRY_LEN, Ended, Phase, ReportError, VolumeEntry};
use crate::failover::retire::Target;
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};

/// The link layout version. Version 1 carries a schema-3 report entry of `ENTRY_LEN` bytes, so a change to the
/// report schema or the entry width changes this version.
pub const VERSION: u16 = 1;
const _: () = assert!(crate::failover::report::SCHEMA == 3 && ENTRY_LEN == 509 && VERSION == 1);
pub const REQUEST_MAX: usize = 128;
pub const INBOX: usize = 8;

const HEADER: usize = 3;
const TENURE: u8 = 1;
const TARGET: u8 = 1 << 1;
const REPORT_AGE: u8 = 1 << 2;
const READ_AGE: u8 = 1 << 3;
const ENTRY: u8 = 1 << 4;
const PRESENT: u8 = TENURE | TARGET | REPORT_AGE | READ_AGE | ENTRY;

const TARGET_LEN: usize = 8 + 8 + 4;
pub const STATUS_LEN: usize = HEADER + 3 + 4 + 4 + VOLUME + 12 + TARGET_LEN + 5 * 8 + ENTRY_LEN;
pub const NOMINATE_LEN: usize = HEADER + 4 + TARGET_LEN + 8;
pub const PEER_LEN: usize = HEADER + 1 + 8;

const _: () = assert!(HEADER + 2 + REQUEST_MAX < STATUS_LEN);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    Status = 1,
    Nominate = 2,
    Peer = 3,
    Request = 4,
}

const PHASES: [Phase; 8] = [
    Phase::Starting,
    Phase::Recovering,
    Phase::Held,
    Phase::Standby,
    Phase::Serving,
    Phase::Withdrawn,
    Phase::Closing,
    Phase::Parked,
];

const ENDINGS: [Ended; 8] = [
    Ended::Stopped,
    Ended::Rerun,
    Ended::Held,
    Ended::Deposed,
    Ended::Retire,
    Ended::Refused,
    Ended::Retired,
    Ended::Fault,
];

const fn phase_code(phase: Phase) -> u8 {
    match phase {
        Phase::Starting => 1,
        Phase::Recovering => 2,
        Phase::Held => 3,
        Phase::Standby => 4,
        Phase::Serving => 5,
        Phase::Withdrawn => 6,
        Phase::Closing => 7,
        Phase::Parked => 8,
    }
}

const fn ended_code(ended: Option<Ended>) -> u8 {
    match ended {
        None => 0,
        Some(Ended::Stopped) => 1,
        Some(Ended::Rerun) => 2,
        Some(Ended::Held) => 3,
        Some(Ended::Deposed) => 4,
        Some(Ended::Retire) => 5,
        Some(Ended::Refused) => 6,
        Some(Ended::Retired) => 7,
        Some(Ended::Fault) => 8,
    }
}

// Decode reads a label at its code minus one in `PHASES` or `ENDINGS`, so each table entry encodes to its place
// plus one.
const _: () = {
    let mut i = 0;
    while i < PHASES.len() {
        assert!(phase_code(PHASES[i]) as usize == i + 1);
        i += 1;
    }
    let mut i = 0;
    while i < ENDINGS.len() {
        assert!(ended_code(Some(ENDINGS[i])) as usize == i + 1);
        i += 1;
    }
};

impl From<&Exit> for Ended {
    fn from(exit: &Exit) -> Self {
        match exit {
            Exit::Stopped => Self::Stopped,
            Exit::Rerun(_) => Self::Rerun,
            Exit::Held { .. } => Self::Held,
            Exit::Deposed => Self::Deposed,
            Exit::Retire(_) => Self::Retire,
            Exit::Refused(_) => Self::Refused,
            Exit::Retired => Self::Retired,
            Exit::Fault(_) => Self::Fault,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub shard: Shard,
    pub volume: VolumeId,
    pub pid: u32,
    pub phase: Phase,
    pub tenure: Option<(ShardGeneration, ActivatedEpoch)>,
    /// `target` is the `(g, owner, E)` of the last shard record the process read.
    pub target: Option<Target>,
    pub report_age_us: Option<u64>,
    /// `read_age_us` is the tenure's freshness-clock age, which a heartbeat entry carries as its read age.
    pub read_age_us: Option<u64>,
    /// `io` counts the completed device commands of the tenure's attach.
    pub io: u64,
    /// `completions` counts the requests the owner answered in the tenure, each once at its answer, which a
    /// heartbeat header carries as its completions.
    pub completions: u64,
    /// `pending` counts the device commands the owner's table holds pending or abandoned and the owner's live
    /// requests, which a heartbeat header carries as its pending count.
    pub pending: u64,
    pub entry: Option<VolumeEntry>,
    /// `ended` labels the exit that ended the process's last incarnation.
    pub ended: Option<Ended>,
}

impl Status {
    pub fn idle(shard: Shard, volume: VolumeId, pid: u32, phase: Phase) -> Self {
        Self {
            shard,
            volume,
            pid,
            phase,
            tenure: None,
            target: None,
            report_age_us: None,
            read_age_us: None,
            io: 0,
            completions: 0,
            pending: 0,
            entry: None,
            ended: None,
        }
    }

    /// `parked` preserves `entry` (including its flip flag) and `target`, and sets `ended` to `exit`'s label.
    pub fn parked(&self, exit: &Exit) -> Self {
        Self {
            target: self.target,
            entry: self.entry,
            ended: Some(Ended::from(exit)),
            ..Self::idle(self.shard, self.volume, self.pid, Phase::Parked)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    len: u8,
    bytes: [u8; REQUEST_MAX],
}

impl Request {
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > REQUEST_MAX {
            return None;
        }
        let mut out = [0; REQUEST_MAX];
        out[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            len: bytes.len() as u8,
            bytes: out,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    Nominate(Revalidated),
    Peer { read_at: Option<u64> },
    Request(Request),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Status(Box<Status>),
    Inbound(Inbound),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// The length differs from the kind's layout, or the destination is shorter than the encoding.
    Length,
    Version,
    Kind,
    /// A label, presence or field byte lies outside its encoding.
    Field,
    /// The status entry failed its codec.
    Entry(ReportError),
}

struct Out<'a> {
    bytes: &'a mut [u8],
    at: usize,
}

impl Out<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.bytes[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }

    fn target(&mut self, target: Option<Target>) {
        let (g, owner, e) = target.map_or((0, 0, 0), |t| {
            (t.generation.get(), t.owner.get(), t.attempts)
        });
        self.put(&g.to_be_bytes());
        self.put(&owner.to_be_bytes());
        self.put(&e.to_be_bytes());
    }
}

struct In<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl In<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut field = [0; N];
        field.copy_from_slice(&self.bytes[self.at..self.at + N]);
        self.at += N;
        field
    }

    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take())
    }

    fn target(&mut self, present: bool) -> Result<Option<Target>, LinkError> {
        let (g, owner, attempts) = (self.u64(), self.u64(), self.u32());
        if !present {
            return (g == 0 && owner == 0 && attempts == 0)
                .then_some(None)
                .ok_or(LinkError::Field);
        }
        let generation = ShardGeneration::new(g).ok_or(LinkError::Field)?;
        let owner = Host::new(owner).ok_or(LinkError::Field)?;
        Ok(Some(Target {
            generation,
            owner,
            attempts,
        }))
    }

    fn optional(&mut self, present: bool) -> Result<Option<u64>, LinkError> {
        let value = self.u64();
        match present {
            true => Ok(Some(value)),
            false if value == 0 => Ok(None),
            false => Err(LinkError::Field),
        }
    }
}

fn header(out: &mut [u8], len: usize, kind: Kind) -> Result<Out<'_>, LinkError> {
    let bytes = out.get_mut(..len).ok_or(LinkError::Length)?;
    let mut out = Out { bytes, at: 0 };
    out.put(&VERSION.to_be_bytes());
    out.put(&[kind as u8]);
    Ok(out)
}

/// Writes `status` to the front of `out` and returns its length, [`STATUS_LEN`].
///
/// # Errors
///
/// `Length` when `out` is shorter than [`STATUS_LEN`], and `Entry` for an entry its codec refuses.
pub fn encode_status(status: &Status, out: &mut [u8]) -> Result<usize, LinkError> {
    if out.len() < STATUS_LEN {
        return Err(LinkError::Length);
    }
    let entry = (status.entry.as_ref())
        .map(VolumeEntry::encode)
        .transpose()
        .map_err(LinkError::Entry)?;
    let mut out = header(out, STATUS_LEN, Kind::Status)?;
    let present = [
        (status.tenure.is_some(), TENURE),
        (status.target.is_some(), TARGET),
        (status.report_age_us.is_some(), REPORT_AGE),
        (status.read_age_us.is_some(), READ_AGE),
        (entry.is_some(), ENTRY),
    ];
    let presence = (present.iter()).fold(0, |bits, &(set, bit)| bits | if set { bit } else { 0 });
    out.put(&[phase_code(status.phase), presence, ended_code(status.ended)]);
    out.put(&status.shard.get().to_be_bytes());
    out.put(&status.pid.to_be_bytes());
    out.put(&status.volume.field());
    let (g, a) = status.tenure.map_or((0, 0), |(g, a)| (g.get(), a.get()));
    out.put(&g.to_be_bytes());
    out.put(&a.to_be_bytes());
    out.target(status.target);
    for value in [
        status.report_age_us.unwrap_or(0),
        status.read_age_us.unwrap_or(0),
        status.io,
        status.completions,
        status.pending,
    ] {
        out.put(&value.to_be_bytes());
    }
    out.put(&entry.unwrap_or([0; ENTRY_LEN]));
    Ok(STATUS_LEN)
}

/// Writes an inbound message to the front of `out` and returns its length.
///
/// # Errors
///
/// `Length` when `out` is shorter than the message's layout.
pub fn encode(message: &Inbound, out: &mut [u8]) -> Result<usize, LinkError> {
    match message {
        Inbound::Nominate(witness) => {
            let mut out = header(out, NOMINATE_LEN, Kind::Nominate)?;
            out.put(&witness.shard.get().to_be_bytes());
            out.target(Some(witness.target));
            out.put(&witness.until_us.to_be_bytes());
            Ok(NOMINATE_LEN)
        }
        Inbound::Peer { read_at } => {
            let mut out = header(out, PEER_LEN, Kind::Peer)?;
            out.put(&[u8::from(read_at.is_some())]);
            out.put(&read_at.unwrap_or(0).to_be_bytes());
            Ok(PEER_LEN)
        }
        Inbound::Request(request) => {
            let bytes = request.as_bytes();
            let len = HEADER + 2 + bytes.len();
            let mut out = header(out, len, Kind::Request)?;
            out.put(&(bytes.len() as u16).to_be_bytes());
            out.put(bytes);
            Ok(len)
        }
    }
}

fn expected(bytes: &[u8]) -> Result<(Kind, usize), LinkError> {
    if bytes.len() < HEADER {
        return Err(LinkError::Length);
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != VERSION {
        return Err(LinkError::Version);
    }
    let kind = match bytes[2] {
        1 => Kind::Status,
        2 => Kind::Nominate,
        3 => Kind::Peer,
        4 => Kind::Request,
        _ => return Err(LinkError::Kind),
    };
    let len = match kind {
        Kind::Status => STATUS_LEN,
        Kind::Nominate => NOMINATE_LEN,
        Kind::Peer => PEER_LEN,
        Kind::Request => {
            let count = bytes.get(HEADER..HEADER + 2).ok_or(LinkError::Length)?;
            let count = usize::from(u16::from_be_bytes([count[0], count[1]]));
            if count == 0 || count > REQUEST_MAX {
                return Err(LinkError::Field);
            }
            HEADER + 2 + count
        }
    };
    Ok((kind, len))
}

/// Decodes one link message. The codec checks the layout only: the caller admits link messages from its paired
/// local agent or owner process in the current host boot, and `until_us` and `read_at` are that host's
/// `CLOCK_BOOTTIME` microseconds.
///
/// # Errors
///
/// `Length` for a length outside the kind's layout, `Version`, `Kind`, `Field` for a byte outside its encoding,
/// and `Entry` for a status entry its codec refuses.
pub fn decode(bytes: &[u8]) -> Result<Message, LinkError> {
    let (kind, len) = expected(bytes)?;
    #[cfg(test)]
    let bytes = match tests::trailing() {
        true => bytes.get(..len).ok_or(LinkError::Length)?,
        false => bytes,
    };
    if bytes.len() != len {
        return Err(LinkError::Length);
    }
    let mut body = In { bytes, at: HEADER };
    match kind {
        Kind::Status => status(&mut body).map(|status| Message::Status(Box::new(status))),
        Kind::Nominate => {
            let shard = Shard::new(body.u32()).ok_or(LinkError::Field)?;
            let target = body.target(true)?.ok_or(LinkError::Field)?;
            Ok(Message::Inbound(Inbound::Nominate(Revalidated {
                shard,
                target,
                until_us: body.u64(),
            })))
        }
        Kind::Peer => {
            let present = match body.u8() {
                0 => false,
                1 => true,
                _ => return Err(LinkError::Field),
            };
            let read_at = body.optional(present)?;
            Ok(Message::Inbound(Inbound::Peer { read_at }))
        }
        Kind::Request => Request::new(&bytes[HEADER + 2..])
            .map(|request| Message::Inbound(Inbound::Request(request)))
            .ok_or(LinkError::Field),
    }
}

fn status(body: &mut In<'_>) -> Result<Status, LinkError> {
    let phase = usize::from(body.u8())
        .checked_sub(1)
        .and_then(|i| PHASES.get(i))
        .copied()
        .ok_or(LinkError::Field)?;
    let presence = body.u8();
    if presence & !PRESENT != 0 {
        return Err(LinkError::Field);
    }
    let ended = match usize::from(body.u8()) {
        0 => None,
        code => Some(*ENDINGS.get(code - 1).ok_or(LinkError::Field)?),
    };
    let shard = Shard::new(body.u32()).ok_or(LinkError::Field)?;
    let pid = body.u32();
    let volume = VolumeId::from_field(&body.take()).ok_or(LinkError::Field)?;
    let (g, a) = (body.u64(), body.u32());
    let tenure = match presence & TENURE != 0 {
        true => Some((
            ShardGeneration::new(g).ok_or(LinkError::Field)?,
            ActivatedEpoch::new(a).ok_or(LinkError::Field)?,
        )),
        false if g == 0 && a == 0 => None,
        false => return Err(LinkError::Field),
    };
    let target = body.target(presence & TARGET != 0)?;
    let report_age_us = body.optional(presence & REPORT_AGE != 0)?;
    let read_age_us = body.optional(presence & READ_AGE != 0)?;
    let (io, completions, pending) = (body.u64(), body.u64(), body.u64());
    let entry: [u8; ENTRY_LEN] = body.take();
    let entry = match presence & ENTRY != 0 {
        true => Some(VolumeEntry::decode(&entry).map_err(LinkError::Entry)?),
        false if entry == [0; ENTRY_LEN] => None,
        false => return Err(LinkError::Field),
    };
    Ok(Status {
        shard,
        volume,
        pid,
        phase,
        tenure,
        target,
        report_age_us,
        read_age_us,
        io,
        completions,
        pending,
        entry,
        ended,
    })
}

/// `mutex`'s guard when no other thread holds it, after a panic of its last holder included.
fn try_hold<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    }
}

/// The owner's latest status: the owner thread writes it and the link side takes it.
#[derive(Debug, Default)]
pub struct StatusCell {
    /// True while `status` holds an untaken status. Each side writes it while it holds `status`.
    full: AtomicBool,
    status: Mutex<Option<Status>>,
}

impl StatusCell {
    /// `publish` returns `false` while the link side holds the cell. Otherwise it stores `status`, replacing any
    /// untaken status, and returns `true`.
    pub fn publish(&self, status: Status) -> bool {
        let Some(mut cell) = try_hold(&self.status) else {
            return false;
        };
        *cell = Some(status);
        self.full.store(true, Ordering::Relaxed);
        true
    }

    /// Whether a published status waits for its take. Read by the sole publisher of the cell after its own accepted
    /// publication, `false` shows that the agent's caller has taken that status; the agent receives it at the start of
    /// the turn it was taken for, before that turn seals a report.
    pub fn waiting(&self) -> bool {
        self.full.load(Ordering::Relaxed)
    }

    /// `take` returns the status written since the last take, and `None` when the cell is empty or the owner thread
    /// holds it. A call that loads a false flag returns without the lock.
    pub fn take(&self) -> Option<Status> {
        if !self.full.load(Ordering::Relaxed) {
            return None;
        }
        let mut cell = try_hold(&self.status)?;
        self.full.store(false, Ordering::Relaxed);
        cell.take()
    }

    /// Holds the cell as the other side would and shows its status; a test places a status through `publish`.
    #[cfg(test)]
    pub(crate) fn hold(&self) -> impl std::ops::Deref<Target = Option<Status>> + '_ {
        self.status.lock().unwrap()
    }
}

/// The messages delivered to one owner process that its next drain takes.
#[derive(Debug)]
pub struct Inbox {
    /// True while `queue` holds a message. Each side writes it while it holds `queue`.
    waiting: AtomicBool,
    queue: Mutex<VecDeque<Inbound>>,
}

impl Default for Inbox {
    fn default() -> Self {
        Self {
            waiting: AtomicBool::new(false),
            queue: Mutex::new(VecDeque::with_capacity(INBOX)),
        }
    }
}

impl Inbox {
    /// `deliver` queues `message` and returns `true`, or returns `false` when [`INBOX`] messages wait or the owner
    /// thread holds the inbox. A nomination replaces a queued one that expires no later, and returns `true` without
    /// queueing when the queued one expires later, so the inbox holds the witness with the latest expiry.
    pub fn deliver(&self, message: Inbound) -> bool {
        let Some(mut queue) = try_hold(&self.queue) else {
            return false;
        };
        if let Inbound::Nominate(witness) = message {
            let later = |queued: &Inbound| matches!(queued, Inbound::Nominate(kept) if kept.until_us > witness.until_us);
            if queue.iter().any(later) {
                return true;
            }
            queue.retain(|queued| !matches!(queued, Inbound::Nominate(_)));
        }
        if queue.len() == INBOX {
            return false;
        }
        queue.push_back(message);
        self.waiting.store(true, Ordering::Relaxed);
        true
    }

    /// `drain` passes every queued message to `each` in delivery order, and passes none while the link side holds
    /// the inbox. A call that loads a false flag returns without the lock. The flag clears after the last message,
    /// so a drain that `each` unwinds leaves the rest for the next drain.
    pub fn drain(&self, mut each: impl FnMut(Inbound)) {
        if !self.waiting.load(Ordering::Relaxed) {
            return;
        }
        let Some(mut queue) = try_hold(&self.queue) else {
            return;
        };
        while let Some(message) = queue.pop_front() {
            each(message);
        }
        self.waiting.store(false, Ordering::Relaxed);
    }

    /// Holds the inbox as the other side would.
    #[cfg(test)]
    pub(crate) fn hold(&self) -> impl std::ops::Deref<Target = VecDeque<Inbound>> + '_ {
        self.queue.lock().unwrap()
    }

    /// `nomination` returns the latest queued nomination and discards the other queued messages; a waiting standby
    /// takes its nominations through it and has no use for a `Peer` or a `Request`.
    pub fn nomination(&self) -> Option<Revalidated> {
        let mut latest = None;
        self.drain(|message| {
            if let Inbound::Nominate(witness) = message {
                latest = Some(witness);
            }
        });
        latest
    }
}

#[derive(Debug, Default)]
pub struct Link {
    pub status: StatusCell,
    pub inbox: Inbox,
}

#[cfg(test)]
#[path = "link_tests.rs"]
pub(crate) mod tests;
