//! The bundle format: the record stream of one run.
//!
//! A bundle is a sequence of fixed-width 48-byte records, each a tag byte,
//! a sub-tag byte, a 16-bit little-endian chunk field and a 44-byte
//! payload. It opens with a `Begin` record naming the format version, the
//! choice schema and the checkpoint interval, then carries the manifest and
//! the run's configuration as field records, every recorded choice, every
//! turn and clock move, every event the world emits, the first violation
//! and one terminal record.
//!
//! The semantic digest is SHA-256 over every record other than checkpoints
//! and diagnostics, in stream order, terminal included; diagnostic records
//! carry timings, CPU features and renderings outside it. A checkpoint
//! follows every `every` semantic records, the first violation and the
//! terminal, and nowhere else: its chain value is SHA-256 over the previous
//! chain value and the SHA-256 of the semantic records since, starting from
//! a fixed seed. A load recomputes every chain value at those places and
//! rejects a bundle whose checkpoint differs, is missing where one is due
//! or stands where none is.
//!
//! The recorder writes through a pending buffer of fixed capacity and keeps
//! diagnostics in a fixed ring that drops its oldest entry, so it is lossy
//! by declaration. Pushing a record while an action runs is a harness
//! defect. The record maximum counts every record: the recorder keeps room
//! below it for the ring, the terminal and their checkpoints, and once a
//! record would reach into that room it takes no more and closes with a
//! `Cap` terminal. A failed write or flush closes it with a `Sink`
//! terminal; after a failed write the bundle on disk ends before its
//! terminal's checkpoint, and a load reports it as `Truncated`.

use std::io::{Read, Write};

use sha2::{Digest, Sha256};

use crate::oracle::Obligation;

use super::choice::{Opens, RECORD_LEN as CHOICE_LEN, SCHEMA, opens};
use super::recovery::{Record as RecoveryRecord, RecordError, embedded, recovery_profile};

/// The bundle format version.
pub(crate) const VERSION: u16 = 1;

/// Bytes of every bundle record.
pub(crate) const RECORD: usize = 48;

/// Payload bytes of a record.
pub(crate) const PAYLOAD: usize = RECORD - 4;

/// Bytes of a turn's observation, the end of its payload: what the world
/// saw the turn's action collect, all zero when it saw nothing. A reader
/// that knows no observation reads a turn's time, event and outcome alone.
pub(crate) const TURN_OBSERVATION: usize = PAYLOAD - 32;

/// Bytes of one field or diagnostic chunk: the payload after its length
/// byte.
pub(crate) const CHUNK: usize = PAYLOAD - 1;

/// The chain value before the first checkpoint.
const SEED: &[u8] = b"image-cache bundle v1";

/// Records beyond the ring the recorder keeps below the maximum: a
/// violation's checkpoint, the terminal and the terminal's checkpoint. A
/// violation that lands on the cadence takes the cadence checkpoint, so
/// one of these records can stay unused.
const RESERVE: u64 = 3;

/// Records a bundle's record maximum holds beyond the ring when the
/// recorder opens: the `Begin` record, one more record and its checkpoint,
/// and [`RESERVE`]. [`Capacity::new`] adds the `Begin` record's checkpoint
/// when the cadence checkpoints every record.
pub(crate) const OPEN_ROOM: u64 = RESERVE + 3;

/// Records a push needs free beyond the records written and the ring: the
/// record, the cadence checkpoint it may bring, and [`RESERVE`].
pub(crate) const PUSH_ROOM: u64 = RESERVE + 2;

/// The most chunks one field records: each chunk's index is a `u16`.
pub(crate) const FIELD_CHUNKS: u64 = 1 << 16;

/// The most records the pending buffer or the ring holds. The recorder
/// allocates both buffers up front, and a `Vec` addresses at most
/// `isize::MAX` bytes.
pub(crate) const MAX_BUFFERED: u64 = (isize::MAX as u64) / RECORD as u64;

const _: () = assert!(
    Obligation::ALL.len() <= 8,
    "a terminal's masks hold one bit per obligation"
);

/// A record's tag, its first byte: what its payload holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Tag {
    Begin = 1,
    Field = 2,
    Choice = 3,
    Turn = 4,
    Clock = 5,
    Event = 6,
    Violation = 7,
    Terminal = 8,
    Checkpoint = 9,
    Diagnostic = 10,
}

impl Tag {
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        [
            Self::Begin,
            Self::Field,
            Self::Choice,
            Self::Turn,
            Self::Clock,
            Self::Event,
            Self::Violation,
            Self::Terminal,
            Self::Checkpoint,
            Self::Diagnostic,
        ]
        .into_iter()
        .find(|tag| *tag as u8 == code)
    }

    /// Whether the record enters the digest and the checkpoint chain.
    fn semantic(self) -> bool {
        !matches!(self, Self::Checkpoint | Self::Diagnostic)
    }
}

/// Whether a record tagged `code` enters the digest and the checkpoint
/// chain: every known tag but checkpoints and diagnostics.
pub(crate) fn is_semantic(code: u8) -> bool {
    Tag::from_code(code).is_some_and(Tag::semantic)
}

/// A field a bundle records before its first turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Field {
    /// The manifest's canonical form, as
    /// [`super::manifest::Manifest::canonical`] writes it.
    Manifest = 1,
    /// The controller's record: the profile record, under a recovery
    /// profile its `recovery-cut-v1` record prefixed by its `u32`
    /// little-endian length, then the world configuration and the limits.
    Config = 2,
}

impl Field {
    fn from_code(code: u8) -> Option<Self> {
        [Self::Manifest, Self::Config]
            .into_iter()
            .find(|field| *field as u8 == code)
    }
}

/// One event a world emits between actions: a kind code and its payload,
/// whose layout the kind fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Event {
    pub(crate) kind: u8,
    pub(crate) payload: [u8; PAYLOAD],
}

/// A completed run's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Outcome {
    Pass = 1,
    Violation = 2,
    Inconclusive = 3,
    Unsuccessful = 4,
}

/// Why a run left incomplete evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Infrastructure {
    /// A write to the sink failed, or a hook halted the run, as a session
    /// does once a write fails or its record or byte budget is spent.
    Sink = 1,
    /// The record maximum was reached.
    Cap = 2,
    /// The stream ends before its terminal's checkpoint.
    Truncated = 3,
    /// The harness broke its own contract, such as a record pushed while an
    /// action ran or a refused decision.
    Defect = 4,
}

/// How a run ended. Only a `Complete(Pass)` with a nonzero `required` mask
/// whose every bit fired counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Terminal {
    Complete {
        outcome: Outcome,
        /// Obligations the run checked, one bit each.
        fired: u8,
        /// Obligations the run must check to count.
        required: u8,
    },
    Infrastructure(Infrastructure),
}

impl Terminal {
    /// Whether the run counts as a pass.
    pub(crate) fn counts(&self) -> bool {
        matches!(
            *self,
            Self::Complete { outcome: Outcome::Pass, fired, required }
                if required != 0 && fired & required == required
        )
    }
}

/// The bit of `obligation` in a terminal's masks.
pub(crate) fn bit(obligation: Obligation) -> u8 {
    1 << obligation as u8
}

/// A run's counted work and time, which the terminal records apart: turns
/// and decisions are checked work, virtual and skipped time are not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Work {
    pub(crate) turns: u64,
    pub(crate) decisions: u64,
    pub(crate) progress: u64,
    pub(crate) virtual_us: u64,
    pub(crate) skipped_us: u64,
}

/// The terminal record's payload: the class, the outcome or
/// infrastructure code, the fired and required masks, then each work field
/// little-endian.
fn encode_terminal(terminal: Terminal, work: Work) -> [u8; PAYLOAD] {
    let mut payload = [0; PAYLOAD];
    match terminal {
        Terminal::Complete {
            outcome,
            fired,
            required,
        } => payload[..4].copy_from_slice(&[1, outcome as u8, fired, required]),
        Terminal::Infrastructure(class) => payload[..2].copy_from_slice(&[2, class as u8]),
    }
    let fields = [
        work.turns,
        work.decisions,
        work.progress,
        work.virtual_us,
        work.skipped_us,
    ];
    for (at, value) in fields.iter().enumerate() {
        payload[4 + 8 * at..12 + 8 * at].copy_from_slice(&value.to_le_bytes());
    }
    payload
}

/// [`encode_terminal`] in reverse, or `None` for an unknown class or code.
fn decode_terminal(payload: &[u8; PAYLOAD]) -> Option<(Terminal, Work)> {
    let terminal = match payload[0] {
        1 => Terminal::Complete {
            outcome: [
                Outcome::Pass,
                Outcome::Violation,
                Outcome::Inconclusive,
                Outcome::Unsuccessful,
            ]
            .into_iter()
            .find(|outcome| *outcome as u8 == payload[1])?,
            fired: payload[2],
            required: payload[3],
        },
        2 => Terminal::Infrastructure(
            [
                Infrastructure::Sink,
                Infrastructure::Cap,
                Infrastructure::Truncated,
                Infrastructure::Defect,
            ]
            .into_iter()
            .find(|class| *class as u8 == payload[1])?,
        ),
        _ => return None,
    };
    let value = |n: usize| {
        u64::from_le_bytes(
            payload[4 + 8 * n..12 + 8 * n]
                .try_into()
                .expect("eight bytes"),
        )
    };
    let work = Work {
        turns: value(0),
        decisions: value(1),
        progress: value(2),
        virtual_us: value(3),
        skipped_us: value(4),
    };
    Some((terminal, work))
}

/// A recorder's capacities, from the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capacity {
    pending: usize,
    ring: usize,
    records: u64,
    every: u32,
}

impl Capacity {
    /// Capacities of a pending buffer of `pending` records, a ring of
    /// `ring` diagnostics, a bundle of at most `records` records and a
    /// checkpoint after every `every` semantic records; `None` unless each
    /// is at least one, the pending buffer and the ring hold at most
    /// [`MAX_BUFFERED`] records, and the record maximum
    /// leaves room for the `Begin` record and its checkpoint when `every` is
    /// one, one more record and its checkpoint, the ring and the reserve.
    pub(crate) fn new(pending: usize, ring: usize, records: u64, every: u32) -> Option<Self> {
        let room = (ring as u64).checked_add(OPEN_ROOM + u64::from(every == 1))?;
        if pending == 0 || ring == 0 || every == 0 || records < room {
            return None;
        }
        if [pending, ring]
            .into_iter()
            .any(|buffered| buffered as u64 > MAX_BUFFERED)
        {
            return None;
        }
        Some(Self {
            pending,
            ring,
            records,
            every,
        })
    }

    /// Records a bundle holds, checkpoints and diagnostics included.
    pub(crate) fn records(&self) -> u64 {
        self.records
    }

    /// Whether a field of `bytes` recorded first after the `Begin` record
    /// fits within the record maximum. Before its last chunk's push the
    /// bundle holds the `Begin` record, the chunks before the last and the
    /// cadence checkpoints among them, which `chunks + chunks / every`
    /// bounds; that push needs room for `self.ring`, the chunk, its
    /// cadence checkpoint and `RESERVE`. Its chunk count is at most
    /// [`FIELD_CHUNKS`], the chunks a `u16` index numbers.
    pub(crate) fn holds_field(&self, bytes: usize) -> bool {
        let chunks = bytes.div_ceil(CHUNK) as u64;
        let before_last = chunks + chunks / u64::from(self.every);
        chunks <= FIELD_CHUNKS && before_last + self.ring as u64 + PUSH_ROOM <= self.records
    }

    /// Semantic records between cadence checkpoints.
    pub(crate) fn every(&self) -> u32 {
        self.every
    }
}

/// A closed bundle: the terminal it records, its semantic digest, the work
/// its terminal reports, and the sink.
#[derive(Debug)]
pub(crate) struct Closed<W> {
    pub(crate) terminal: Terminal,
    pub(crate) digest: [u8; 32],
    pub(crate) work: Work,
    pub(crate) sink: W,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Open,
    Closed(Infrastructure),
}

type Record = [u8; RECORD];

fn record(tag: Tag, sub: u8, chunk: u16, payload: &[u8]) -> Record {
    let mut out = [0; RECORD];
    out[0] = tag as u8;
    out[1] = sub;
    out[2..4].copy_from_slice(&chunk.to_le_bytes());
    out[4..4 + payload.len()].copy_from_slice(payload);
    out
}

/// `chunk`, at most 43 bytes, after its length byte, zero-padded.
fn sized(chunk: &[u8]) -> [u8; PAYLOAD] {
    let mut out = [0; PAYLOAD];
    out[0] = chunk.len() as u8;
    out[1..1 + chunk.len()].copy_from_slice(chunk);
    out
}

/// The chain value after `previous` over a segment hashing to `segment`.
fn chain(previous: &[u8; 32], segment: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(previous);
    hash.update(segment);
    hash.finalize().into()
}

fn seed() -> [u8; 32] {
    Sha256::digest(SEED).into()
}

/// The checkpoint represents `semantic` semantic records with chain digest
/// `chain`.
fn checkpoint_record(chain: &[u8; 32], semantic: u64) -> Record {
    let mut payload = [0; 40];
    payload[..32].copy_from_slice(chain);
    payload[32..].copy_from_slice(&semantic.to_le_bytes());
    record(Tag::Checkpoint, 0, 0, &payload)
}

/// Streams one run's bundle into `sink`. A recorder dropped while its
/// thread panics writes its pending records first, so the bundle of a run a
/// panic cut short holds every record before the panic.
pub(crate) struct Recorder<W: Write> {
    /// Present until [`finish`](Self::finish) hands it back.
    sink: Option<W>,
    capacity: Capacity,
    pending: Vec<u8>,
    digest: Sha256,
    segment: Sha256,
    chain: [u8; 32],
    /// Semantic records since the last checkpoint.
    since: u32,
    semantic: u64,
    records: u64,
    ring: Vec<Record>,
    /// The ring's next slot, once it is full.
    ring_at: usize,
    inside: bool,
    violated: bool,
    state: State,
}

impl<W: Write> Recorder<W> {
    /// A recorder over `sink` whose first record names the version, the
    /// choice schema and the checkpoint interval. Every buffer it uses is
    /// allocated here.
    pub(crate) fn new(sink: W, capacity: Capacity) -> Self {
        let mut recorder = Self {
            sink: Some(sink),
            capacity,
            pending: Vec::with_capacity(capacity.pending * RECORD),
            digest: Sha256::new(),
            segment: Sha256::new(),
            chain: seed(),
            since: 0,
            semantic: 0,
            records: 0,
            ring: Vec::with_capacity(capacity.ring),
            ring_at: 0,
            inside: false,
            violated: false,
            state: State::Open,
        };
        let mut begin = [0; 8];
        begin[..2].copy_from_slice(&VERSION.to_le_bytes());
        begin[2..4].copy_from_slice(&SCHEMA.to_le_bytes());
        begin[4..].copy_from_slice(&capacity.every.to_le_bytes());
        recorder.seal(record(Tag::Begin, 0, 0, &begin));
        if recorder.since == capacity.every {
            recorder.checkpoint();
        }
        recorder
    }

    /// Marks an action running: until [`leave`](Self::leave), a pushed
    /// record closes the recorder as a harness defect.
    pub(crate) fn enter(&mut self) {
        self.inside = true;
    }

    pub(crate) fn leave(&mut self) {
        self.inside = false;
    }

    /// Records `bytes` as field `field`, in numbered chunks of 43 bytes,
    /// each after its length byte.
    pub(crate) fn field(&mut self, field: Field, bytes: &[u8]) {
        for (at, chunk) in bytes.chunks(CHUNK).enumerate() {
            let Ok(at) = u16::try_from(at) else {
                self.state = State::Closed(Infrastructure::Cap);
                return;
            };
            self.push(record(Tag::Field, field as u8, at, &sized(chunk)));
        }
    }

    /// Records each choice record of `tape`.
    pub(crate) fn choices(&mut self, tape: &[u8]) {
        for choice in tape.chunks(CHOICE_LEN) {
            self.push(record(Tag::Choice, 0, 0, choice));
        }
    }

    /// Records one applied turn: its time at payload offset 0, its event at
    /// 8, its outcome at 24 and the world's observation of it at 32.
    pub(crate) fn turn(
        &mut self,
        now: u64,
        event: &[u8; 16],
        outcome: u64,
        observation: &[u8; TURN_OBSERVATION],
    ) {
        let mut payload = [0; PAYLOAD];
        payload[..8].copy_from_slice(&now.to_le_bytes());
        payload[8..24].copy_from_slice(event);
        payload[24..32].copy_from_slice(&outcome.to_le_bytes());
        payload[32..].copy_from_slice(observation);
        self.push(record(Tag::Turn, 0, 0, &payload));
    }

    /// Records a clock move to `now`.
    pub(crate) fn clock(&mut self, now: u64) {
        self.push(record(Tag::Clock, 0, 0, &now.to_le_bytes()));
    }

    pub(crate) fn event(&mut self, event: &Event) {
        self.push(record(Tag::Event, event.kind, 0, &event.payload));
    }

    /// Records the run's first violation, then a checkpoint, and writes
    /// both to the sink before any later record. A later violation, or one
    /// after the recorder closed, records nothing.
    pub(crate) fn violation(&mut self, payload: &[u8; PAYLOAD]) {
        if self.violated || self.state != State::Open {
            return;
        }
        self.violated = true;
        self.push(record(Tag::Violation, 0, 0, payload));
        if self.state == State::Open {
            if self.since > 0 {
                self.checkpoint();
            }
            self.flush();
        }
    }

    /// Records `entry`, a semantic record other than `Begin` and the
    /// terminal, as a stream that edits a recorded one does: a violation
    /// through [`violation`](Self::violation), any other as it is.
    pub(crate) fn raw(&mut self, entry: &[u8; RECORD]) {
        if entry[0] == Tag::Violation as u8 {
            self.violation(entry[4..].try_into().expect("a record's payload"));
        } else {
            self.push(*entry);
        }
    }

    /// Keeps `text`, cut at 43 bytes, in the diagnostic ring, dropping the
    /// oldest entry once the ring is full. Diagnostics stay outside the
    /// digest.
    pub(crate) fn diagnostic(&mut self, text: &str) {
        let bytes = &text.as_bytes()[..text.len().min(CHUNK)];
        let entry = record(Tag::Diagnostic, 0, 0, &sized(bytes));
        if self.ring.len() < self.capacity.ring {
            self.ring.push(entry);
        } else {
            self.ring[self.ring_at] = entry;
            self.ring_at = (self.ring_at + 1) % self.capacity.ring;
        }
    }

    /// Bytes of the pending buffer's allocation, fixed at construction.
    pub(crate) fn pending_capacity(&self) -> usize {
        self.pending.capacity()
    }

    /// Whether the sink received every record the run emitted so far: the
    /// recorder is open, so it took each record, and the pending buffer is
    /// empty.
    pub(crate) fn flushed(&self) -> bool {
        self.pending.is_empty() && self.state == State::Open
    }

    /// The semantic records taken so far and the SHA-256 over them in
    /// stream order, which equals the SHA-256 over the first that many
    /// semantic records of every bundle that continues this stream.
    pub(crate) fn prefix(&self) -> (u64, [u8; 32]) {
        (self.semantic, self.digest.clone().finalize().into())
    }

    /// Ends the bundle: writes the diagnostic ring, a terminal record of
    /// `terminal` and `work`, or of the infrastructure class that closed the
    /// recorder, and its checkpoint. A sink that failed keeps its `Sink`
    /// class and writes nothing more.
    pub(crate) fn finish(mut self, terminal: Terminal, work: Work) -> Closed<W> {
        self.inside = false;
        let mut terminal = match self.state {
            State::Open => terminal,
            State::Closed(class) => Terminal::Infrastructure(class),
        };
        if self.state != State::Closed(Infrastructure::Sink) {
            let ring = std::mem::take(&mut self.ring);
            let start = if ring.len() == self.capacity.ring {
                self.ring_at
            } else {
                0
            };
            for at in 0..ring.len() {
                self.write(&ring[(start + at) % ring.len()]);
            }
            self.seal(record(
                Tag::Terminal,
                0,
                0,
                &encode_terminal(terminal, work),
            ));
            self.checkpoint();
            self.flush();
            if self.sink().flush().is_err() {
                self.state = State::Closed(Infrastructure::Sink);
            }
        }
        if self.state == State::Closed(Infrastructure::Sink) {
            terminal = Terminal::Infrastructure(Infrastructure::Sink);
        }
        Closed {
            terminal,
            digest: std::mem::take(&mut self.digest).finalize().into(),
            work,
            sink: self
                .sink
                .take()
                .expect("an unfinished recorder holds its sink"),
        }
    }

    fn push(&mut self, entry: Record) {
        if self.state != State::Open {
            return;
        }
        if self.inside {
            self.state = State::Closed(Infrastructure::Defect);
            return;
        }
        // The record and the cadence checkpoint it may bring, beside the
        // ring and the reserve.
        let room = self.capacity.ring as u64 + PUSH_ROOM;
        if self.records + room > self.capacity.records {
            self.state = State::Closed(Infrastructure::Cap);
            return;
        }
        self.seal(entry);
        if self.since == self.capacity.every {
            self.checkpoint();
        }
    }

    /// Takes a semantic record into the digest, the chain segment and the
    /// stream.
    fn seal(&mut self, entry: Record) {
        self.digest.update(entry);
        self.segment.update(entry);
        self.since += 1;
        self.semantic += 1;
        self.write(&entry);
    }

    fn checkpoint(&mut self) {
        let segment = std::mem::take(&mut self.segment).finalize().into();
        self.chain = chain(&self.chain, segment);
        self.since = 0;
        self.write(&checkpoint_record(&self.chain, self.semantic));
    }

    fn write(&mut self, entry: &Record) {
        self.records += 1;
        if self.pending.len() + RECORD > self.pending.capacity() {
            self.flush();
        }
        self.pending.extend_from_slice(entry);
    }

    fn sink(&mut self) -> &mut W {
        self.sink
            .as_mut()
            .expect("an unfinished recorder holds its sink")
    }

    /// Writes the pending buffer to the sink; a failed write closes the
    /// recorder with a `Sink` terminal.
    pub(crate) fn flush(&mut self) {
        if self.state != State::Closed(Infrastructure::Sink)
            && self
                .sink
                .as_mut()
                .is_some_and(|sink| sink.write_all(&self.pending).is_err())
        {
            self.state = State::Closed(Infrastructure::Sink);
        }
        self.pending.clear();
    }
}

impl<W: Write> Drop for Recorder<W> {
    fn drop(&mut self) {
        if self.sink.is_some() && std::thread::panicking() {
            self.flush();
            let _ = self.sink().flush();
        }
    }
}

/// Why a bundle was rejected on load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoadError {
    /// The bundle holds `count` whole records, more than `max`.
    TooMany { count: usize, max: u64 },
    /// A complete bundle is followed by a partial record.
    Torn { len: usize },
    /// A field or diagnostic chunk's length byte passes the chunk width.
    Oversized { at: usize },
    /// A byte past a chunk's length or a choice record is nonzero, or a
    /// diagnostic's sub-tag or chunk field is nonzero.
    Padding { at: usize },
    /// The first record is not a `Begin` of a known version, schema and a
    /// nonzero interval, or a later record is a `Begin`.
    Version { at: usize },
    /// A record of an unknown tag.
    Tag { at: usize, tag: u8 },
    /// A terminal of an unknown class or code.
    Terminal { at: usize },
    /// A checkpoint's bytes differ from those its records require, a
    /// checkpoint appears where none is due, or a semantic record occupies a
    /// due checkpoint's position.
    Checkpoint { at: usize },
    /// A choice in the reserved persistence and crash domain under a live
    /// profile.
    Reserved { at: usize },
    /// A Config field that disagrees with the recorded profile, found at
    /// the first choice record: a recovery profile's holds no record that
    /// parses, or a live profile's embeds one.
    Recovery { at: usize, error: RecordError },
    /// A semantic record after the terminal, or any record after the
    /// terminal's checkpoint.
    AfterTerminal { at: usize },
    /// A second violation record, a complete terminal other than a
    /// violation that carries one, or a violation terminal without one; an
    /// infrastructure terminal may keep a violation recorded before it.
    Violation { at: usize },
    /// A complete terminal's decision count differs from the recorded
    /// choices; an infrastructure terminal's record is incomplete by its
    /// class.
    Decisions { recorded: u64, counted: u64 },
    /// An unknown field, or a field's chunks out of order.
    Field { at: usize },
}

/// A loaded bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Loaded {
    pub(crate) digest: [u8; 32],
    pub(crate) terminal: Terminal,
    pub(crate) work: Work,
    /// Choice identity records: the decisions the run made.
    pub(crate) decisions: u64,
    /// Each field's bytes, in recording order.
    pub(crate) fields: Vec<(Field, Vec<u8>)>,
    /// The recorded choice tape.
    pub(crate) tape: Vec<u8>,
    /// Each turn's selected event, in recording order.
    pub(crate) turns: Vec<[u8; 16]>,
    /// Events in recording order.
    pub(crate) events: Vec<Event>,
    pub(crate) violation: Option<[u8; PAYLOAD]>,
}

/// A sized chunk's bytes.
fn sized_data(at: usize, payload: &[u8; PAYLOAD]) -> Result<&[u8], LoadError> {
    let len = usize::from(payload[0]);
    if len > CHUNK {
        return Err(LoadError::Oversized { at });
    }
    if payload[1 + len..].iter().any(|&byte| byte != 0) {
        return Err(LoadError::Padding { at });
    }
    Ok(&payload[1..1 + len])
}

/// The extra record past `max_records` lets [`load`] reject oversized input
/// as `TooMany` while buffering stays bounded. `read` consumes sources
/// within the maximum in full, including a partial final record.
pub(crate) fn read(source: impl Read, max_records: u64) -> std::io::Result<Vec<u8>> {
    let limit = max_records.saturating_add(1).saturating_mul(RECORD as u64);
    let mut bytes = Vec::new();
    source.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The value of the recorded manifest's `profile` line among `fields`.
pub(crate) fn recorded_profile(fields: &[(Field, Vec<u8>)]) -> Option<&str> {
    let text = fields
        .iter()
        .find(|(field, _)| *field == Field::Manifest)
        .and_then(|(_, bytes)| std::str::from_utf8(bytes).ok())?;
    text.lines()
        .find_map(|line| line.strip_prefix("profile = "))
}

/// What a bundle's fields admit: `None` under a live profile, the parsed
/// `recovery-cut-v1` record under a recovery profile. The profile is the
/// recorded manifest's `profile` line.
///
/// # Errors
///
/// Under a recovery profile, the record's parse error, `Absent` when no
/// Config field was recorded; under a live profile, `Live` when the Config
/// field embeds a record that parses.
pub(crate) fn admitted(fields: &[(Field, Vec<u8>)]) -> Result<Option<RecoveryRecord>, RecordError> {
    let field = |wanted| {
        fields
            .iter()
            .find(|(field, _)| *field == wanted)
            .map(|(_, bytes)| bytes.as_slice())
    };
    let profile = recorded_profile(fields);
    let config = field(Field::Config);
    if !profile.is_some_and(recovery_profile) {
        return match config.map(embedded) {
            Some(Ok(_)) => Err(RecordError::Live),
            _ => Ok(None),
        };
    }
    embedded(config.ok_or(RecordError::Absent)?).map(Some)
}

/// Loads `bytes` as a bundle of at most `max_records` records, recomputing
/// the digest and every checkpoint. A stream that ends before its
/// terminal's checkpoint, a partial last record included, loads as
/// `Truncated` incomplete evidence. Choices in the reserved persistence
/// domain load only when the recorded manifest names a recovery profile
/// and the Config field holds its parsed `recovery-cut-v1` record, which
/// the loader reads at the first choice record.
///
/// # Errors
///
/// As [`LoadError`].
pub(crate) fn load(bytes: &[u8], max_records: u64) -> Result<Loaded, LoadError> {
    let count = bytes.len() / RECORD;
    if count as u64 > max_records {
        return Err(LoadError::TooMany {
            count,
            max: max_records,
        });
    }
    let mut loaded = Loaded {
        digest: [0; 32],
        terminal: Terminal::Infrastructure(Infrastructure::Truncated),
        work: Work::default(),
        decisions: 0,
        fields: Vec::new(),
        tape: Vec::new(),
        turns: Vec::new(),
        events: Vec::new(),
        violation: None,
    };
    let mut ended: Option<(Terminal, Work)> = None;
    let (mut digest, mut segment, mut chained) = (Sha256::new(), Sha256::new(), seed());
    let (mut semantic, mut since, mut every) = (0u64, 0u32, 0u32);
    // Whether the next record other than a diagnostic must be a checkpoint.
    let mut due = false;
    // Whether the fields admit reserved choices, once the first choice
    // record reads them.
    let mut admits: Option<bool> = None;
    let mut closed = false;
    for (at, entry) in bytes.as_chunks::<RECORD>().0.iter().enumerate() {
        let Some(tag) = Tag::from_code(entry[0]) else {
            return Err(LoadError::Tag { at, tag: entry[0] });
        };
        let chunk = u16::from_le_bytes([entry[2], entry[3]]);
        let payload: [u8; PAYLOAD] = entry[4..].try_into().expect("a record's payload");
        if (at == 0) != (tag == Tag::Begin) {
            return Err(LoadError::Version { at });
        }
        if closed {
            return Err(LoadError::AfterTerminal { at });
        }
        if tag.semantic() {
            if ended.is_some() {
                return Err(LoadError::AfterTerminal { at });
            }
            if due {
                return Err(LoadError::Checkpoint { at });
            }
            digest.update(entry);
            segment.update(entry);
            semantic += 1;
            since += 1;
            due = since == every;
        }
        match tag {
            Tag::Begin => {
                let version = u16::from_le_bytes([payload[0], payload[1]]);
                let schema = u16::from_le_bytes([payload[2], payload[3]]);
                every = u32::from_le_bytes(payload[4..8].try_into().expect("four bytes"));
                if version != VERSION || schema != SCHEMA || every == 0 {
                    return Err(LoadError::Version { at });
                }
                due = since == every;
            }
            Tag::Field => {
                let field = Field::from_code(entry[1]).ok_or(LoadError::Field { at })?;
                let data = sized_data(at, &payload)?;
                match loaded.fields.last_mut() {
                    Some((last, bytes)) if *last == field && chunk > 0 => {
                        if usize::from(chunk) * CHUNK != bytes.len() {
                            return Err(LoadError::Field { at });
                        }
                        bytes.extend_from_slice(data);
                    }
                    _ if chunk == 0 => loaded.fields.push((field, data.to_vec())),
                    _ => return Err(LoadError::Field { at }),
                }
            }
            Tag::Diagnostic => {
                if entry[1..4] != [0; 3] {
                    return Err(LoadError::Padding { at });
                }
                sized_data(at, &payload)?;
            }
            Tag::Choice => {
                if payload[CHOICE_LEN..].iter().any(|&byte| byte != 0) {
                    return Err(LoadError::Padding { at });
                }
                let choice = payload[..CHOICE_LEN].try_into().expect("a choice record");
                if admits.is_none() {
                    let record = admitted(&loaded.fields)
                        .map_err(|error| LoadError::Recovery { at, error })?;
                    admits = Some(record.is_some());
                }
                match opens(choice) {
                    Opens::Reserved if admits != Some(true) => {
                        return Err(LoadError::Reserved { at });
                    }
                    Opens::Reserved | Opens::Decision => loaded.decisions += 1,
                    Opens::Nothing => {}
                }
                loaded.tape.extend_from_slice(choice);
            }
            Tag::Turn => loaded
                .turns
                .push(payload[8..24].try_into().expect("sixteen bytes")),
            Tag::Clock => {}
            Tag::Event => loaded.events.push(Event {
                kind: entry[1],
                payload,
            }),
            Tag::Violation => {
                if loaded.violation.replace(payload).is_some() {
                    return Err(LoadError::Violation { at });
                }
                due = true;
            }
            Tag::Terminal => {
                let (terminal, work) =
                    decode_terminal(&payload).ok_or(LoadError::Terminal { at })?;
                let violated = matches!(
                    terminal,
                    Terminal::Complete {
                        outcome: Outcome::Violation,
                        ..
                    }
                );
                let complete = matches!(terminal, Terminal::Complete { .. });
                if complete && loaded.violation.is_some() != violated {
                    return Err(LoadError::Violation { at });
                }
                ended = Some((terminal, work));
                due = true;
            }
            Tag::Checkpoint => {
                if !due {
                    return Err(LoadError::Checkpoint { at });
                }
                let hashed = std::mem::take(&mut segment).finalize().into();
                chained = chain(&chained, hashed);
                if *entry != checkpoint_record(&chained, semantic) {
                    return Err(LoadError::Checkpoint { at });
                }
                (since, due) = (0, false);
                closed = ended.is_some();
            }
        }
    }
    if closed && !bytes.len().is_multiple_of(RECORD) {
        return Err(LoadError::Torn { len: bytes.len() });
    }
    if closed && let Some((terminal, work)) = ended {
        let complete = matches!(terminal, Terminal::Complete { .. });
        if complete && work.decisions != loaded.decisions {
            return Err(LoadError::Decisions {
                recorded: work.decisions,
                counted: loaded.decisions,
            });
        }
        (loaded.terminal, loaded.work) = (terminal, work);
    }
    loaded.digest = digest.finalize().into();
    Ok(loaded)
}

/// The bundle `bytes`, which loads, rerecorded with `edit` applied to its
/// semantic records between `Begin` and the terminal, under `capacity`, and
/// closed with its terminal and work, the decision count recounted from the
/// edited choices: an edited stream with valid checkpoints, as a test of
/// replay builds one.
///
/// # Panics
///
/// When `bytes` does not load.
pub(crate) fn reseal(
    bytes: &[u8],
    capacity: Capacity,
    edit: impl FnOnce(&mut Vec<Record>),
) -> Vec<u8> {
    let loaded = load(bytes, u64::MAX).expect("a bundle to reseal");
    let mut records: Vec<Record> = bytes
        .as_chunks::<RECORD>()
        .0
        .iter()
        .filter(|record| {
            Tag::from_code(record[0])
                .is_some_and(|tag| tag.semantic() && tag != Tag::Begin && tag != Tag::Terminal)
        })
        .copied()
        .collect();
    edit(&mut records);
    let decisions = records
        .iter()
        .filter(|record| record[0] == Tag::Choice as u8 && record[4] == 1)
        .count() as u64;
    let mut recorder = Recorder::new(Vec::new(), capacity);
    for record in &records {
        recorder.raw(record);
    }
    let work = Work {
        decisions,
        ..loaded.work
    };
    recorder.finish(loaded.terminal, work).sink
}
