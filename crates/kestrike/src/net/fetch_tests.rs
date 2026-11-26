//! The transfer cores end to end: an owner [`ServeCore`] and a client [`FetchCore`] exchanging encoded frames over seeded lossy, duplicating and reordering queues.
//!
//! An [`Oracle`] watches every frame each side sends and receives, every chunk the owner retains and every fragment the application takes, and checks them against the source objects directly, apart from the codec and the cores' own state: receipt ACKs within contiguous delivery, DATA within the client's sent grant, grants within application releases, chunks retained until the owner's ACK base passes them, one version's bytes in order, and success only after every fragment and a COMPLETE.

use std::cell::RefCell;
use std::ops::Range;

use crate::sim::round::{Act, Actor, round};
use crate::storage::seeded::SplitMix64;
use crate::storage::{Crc32c, EngineBudget};

use super::client_namespace::{ClientRequest, ClientRequests, IdentityPressure};
use super::datagram::{HEADER_LEN, PeerId};
use super::fetch::{
    Asked, Decider, FIRST_SEND_BUCKETS, Fetch, FetchConfig, FetchCore, FetchCoreError, FetchLimits,
    FetchPressure, FragmentLease, GAP_ACK_US, GAP_WAIT_US, Outcome, Releases,
};
use super::frame::{Header, Kind, Status, encode, parse};
use super::geometry::FRAGMENT_LEN;
use super::packet::{PacketLease, PacketPool, PacketUse};
use super::requests::{GENERATION_LIMIT, RequestId, RequestPressure, RequestTable};
use super::serve::{GetOutcome, Manifest, ReadEnd, ServeConfig, header};
use super::serve_tests::Core;
use super::session::{Admitted, Caps};
use super::slot_index::take_timer_scans;

type Chunk = Box<[u8]>;

const SESSION: Admitted = Admitted {
    peer: PeerId(0),
    epoch: 3,
    caps: Caps {
        slots: 8,
        window: 8,
    },
};

const SERVE: ServeConfig = ServeConfig {
    retry_us: 2_000,
    attempts: 50,
    linger_us: 50_000,
    rate_per_sec: 10_000_000,
    burst: 64,
    slots: 8,
    replies: 8,
    max_wait_us: 10_000_000,
};

const FETCH: FetchConfig = FetchConfig {
    retry_us: 3_000,
    attempts: 50,
    window: 8,
    boxes: 64,
};

/// `Fetcher` pairs a fetch core with its own request namespace for tests.
pub(super) struct Fetcher<'p> {
    pub(super) core: FetchCore<'p>,
    pub(super) requests: ClientRequests<'p>,
}

impl<'p> Fetcher<'p> {
    pub(super) fn new(
        config: FetchConfig,
        table: RequestTable<ClientRequest>,
        releases: &'p Releases,
        budget: &mut EngineBudget,
    ) -> Result<Self, FetchCoreError> {
        let mut staged = *budget;
        let mut requests = ClientRequests::new(table, releases, &mut staged)?;
        let core = FetchCore::new(config, &mut requests, &mut staged)?;
        *budget = staged;
        Ok(Self { core, requests })
    }

    pub(super) fn requests(&self) -> &RequestTable<ClientRequest> {
        self.requests.table()
    }

    pub(super) fn reserved(&self) -> u32 {
        self.core.reserved()
    }

    pub(super) fn report(&self) -> super::fetch::FetchReport {
        self.core.report()
    }

    pub(super) fn fetch(
        &mut self,
        session: Admitted,
        key: [u8; 32],
        metadata_cap: u32,
        body_cap: u32,
        now_us: u64,
        wait_us: u64,
    ) -> Result<RequestId, FetchPressure> {
        self.core.fetch(
            &mut self.requests,
            session,
            key,
            FetchLimits {
                metadata_cap,
                body_cap,
                wait_us,
                intended_us: now_us,
            },
            now_us,
        )
    }

    pub(super) fn start(&mut self, session: Admitted, header: &Header, now_us: u64) {
        self.core.start(&mut self.requests, session, header, now_us);
    }

    pub(super) fn wants(&self, session: Admitted, header: &Header) -> bool {
        self.core.wants(&self.requests, session, header).is_some()
    }

    /// Delivers a DATA frame as the client does: routed once by `wants`, then held or dropped by `data`.
    pub(super) fn data(
        &mut self,
        session: Admitted,
        header: &Header,
        lease: PacketLease<'p>,
        now_us: u64,
    ) {
        let wanted = self.core.wants(&self.requests, session, header);
        self.core
            .data(&mut self.requests, session, header, wanted, lease, now_us);
    }

    pub(super) fn complete(&mut self, session: Admitted, header: &Header) {
        self.core.complete(&mut self.requests, session, header);
    }

    pub(super) fn error(&mut self, session: Admitted, header: &Header) {
        self.core.error(&mut self.requests, session, header);
    }

    pub(super) fn cancel(&mut self, id: RequestId) {
        self.core.cancel(&mut self.requests, id);
    }

    pub(super) fn take(&mut self, id: RequestId) -> Option<FragmentLease<'p>> {
        self.core.take(&mut self.requests, id)
    }

    pub(super) fn outcome(&self, id: RequestId) -> Option<Outcome> {
        self.core.outcome(&self.requests, id)
    }

    pub(super) fn wire(&self, id: RequestId) -> Option<u64> {
        self.requests.fetch(id).map(Fetch::wire)
    }

    pub(super) fn close(&mut self, id: RequestId) -> bool {
        self.core.close(&mut self.requests, id)
    }

    pub(super) fn tick(&mut self, now_us: u64) {
        self.core.tick(&mut self.requests, now_us);
    }

    pub(super) fn due(&self) -> bool {
        self.core.due(&self.requests)
    }

    pub(super) fn deadline(&self) -> Option<u64> {
        self.core.deadline(&self.requests)
    }

    pub(super) fn end_session(&mut self, epoch: u64, status: Status) {
        self.core.end_session(&mut self.requests, epoch, status);
    }

    pub(super) fn cancel_all(&mut self) {
        self.core.cancel_all(&mut self.requests);
    }

    pub(super) fn unsend(&mut self, frame: Asked) {
        self.core.unsend(&mut self.requests, frame);
    }

    pub(super) fn poll(
        &mut self,
        now_us: u64,
        budget: usize,
        send: impl FnMut(super::fetch::Ask) -> bool,
    ) -> usize {
        self.core.poll(&mut self.requests, now_us, budget, send)
    }

    pub(super) fn check_timers(&self) {
        self.core.check_timers(&self.requests);
    }
}

/// Bytes of a 16 KiB command span under a 100-byte header: the first backing buffer's payload, which ends inside a fragment.
const UNALIGNED: u64 = 16_384 - 100;
const SPAN: u64 = 16_384;

/// Seeded faults of one direction, in percent.
#[derive(Clone, Copy)]
struct Faults {
    loss: u64,
    duplicate: u64,
    reorder: u64,
}

const CLEAN: Faults = Faults {
    loss: 0,
    duplicate: 0,
    reorder: 0,
};

/// A frame the run loses on its first send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lose {
    Get,
    Start,
    /// The ACK whose base covers every fragment.
    FinalAck,
    Complete,
}

impl Lose {
    fn of(header: &Header) -> Option<Self> {
        match header.kind {
            Kind::Get => Some(Self::Get),
            Kind::Start => Some(Self::Start),
            Kind::Ack if header.index == header.count => Some(Self::FinalAck),
            Kind::Complete => Some(Self::Complete),
            _ => None,
        }
    }
}

/// One direction of the network: datagrams in flight, subject to seeded loss, duplication and reordering.
struct Wire {
    queue: Vec<Vec<u8>>,
    faults: Faults,
}

impl Wire {
    fn push(&mut self, rng: &mut SplitMix64, datagram: Vec<u8>) {
        if rng.below(100) < self.faults.loss {
            return;
        }
        if rng.below(100) < self.faults.duplicate {
            self.queue.push(datagram.clone());
        }
        self.queue.push(datagram);
        if self.queue.len() > 1 && rng.below(100) < self.faults.reorder {
            let last = self.queue.len() - 1;
            let other = rng.below(last as u64) as usize;
            self.queue.swap(last, other);
        }
    }
}

/// The owner's simulated storage for one read: how far it delivered and whether a command is outstanding.
struct Reading {
    id: RequestId,
    object: usize,
    delivered: u64,
    commanded: bool,
}

/// A source object: its key, its metadata length and its payload.
struct Object {
    key: [u8; 32],
    metadata: u32,
    payload: Vec<u8>,
}

impl Object {
    fn manifest(&self, at: usize) -> Manifest {
        Manifest {
            allocation: 0x5_0000_0001 + at as u64,
            metadata_len: self.metadata,
            body_len: self.payload.len() as u32 - self.metadata,
        }
    }
}

fn object(n: u8, metadata: u32, len: usize) -> Object {
    let mut rng = SplitMix64::new(u64::from(n) + 99);
    Object {
        key: [n; 32],
        metadata: metadata.min(len as u32),
        payload: (0..len).map(|_| rng.next_u64() as u8).collect(),
    }
}

/// Encodes a frame from the owner or the client with fixed transport fields; tags stay zero; this test drives the transfer cores directly, below session authentication.
fn datagram(
    crc: Crc32c,
    mut header: Header,
    epoch: u64,
    sequence: u64,
    payload: [&[u8]; 2],
) -> Vec<u8> {
    header.principal = 1;
    header.key_epoch = 1;
    header.owner_nonce = [0x0A; 16];
    header.client_nonce = [0x0C; 16];
    header.epoch = epoch;
    header.sequence = sequence;
    header.datagram_len = (payload[0].len() + payload[1].len()) as u32;
    let mut out = [0u8; HEADER_LEN];
    encode(crc, &header, payload, &mut out).expect("the cores emit canonical frames");
    let mut bytes = out.to_vec();
    bytes.extend_from_slice(payload[0]);
    bytes.extend_from_slice(payload[1]);
    bytes
}

/// A history the oracle rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Violation {
    /// An ACK base past the fragments delivered contiguously to the client.
    EarlyAck,
    /// DATA past the grant the client sent, or a grant past the application's releases.
    Overcredit,
    /// The owner held fewer chunks than its ACK base leaves unreleased.
    EarlyRelease,
    /// The owner held a chunk its ACK base already passed.
    LateRelease,
    /// An exposed fragment of another version, out of order, or with other bytes.
    Splice,
    /// Success before every fragment and the request's COMPLETE were delivered to the client.
    FalseCompletion,
}

/// What the oracle knows of one request, from frames and events alone.
#[derive(Default)]
struct Track {
    count: u32,
    initial: u32,
    /// The wire request ID and session epoch of the client's GET; a frame delivered to the client counts for this request only when it carries both.
    request: Option<(u64, u64)>,
    /// Fragment indices delivered to the client.
    delivered: Vec<bool>,
    /// The highest grant the client sent.
    client_grant: u32,
    /// The highest ACK base delivered to the owner.
    owner_base: u32,
    /// Payload ranges of the chunks handed to the owner.
    chunks: Vec<Range<u64>>,
    total: u64,
    /// The client was delivered this request's COMPLETE.
    complete_delivered: bool,
    /// The manifest of the first exposed fragment and the bytes exposed so far.
    exposed: Option<Manifest>,
    exposed_len: u64,
    released: u32,
}

impl Track {
    fn contiguous(&self) -> u32 {
        self.delivered.iter().take_while(|got| **got).count() as u32
    }
}

/// Independent checks over one history of requests, indexed by source object.
struct Oracle {
    tracks: Vec<Track>,
}

impl Oracle {
    fn new(objects: usize) -> Self {
        Self {
            tracks: (0..objects).map(|_| Track::default()).collect(),
        }
    }

    /// The client sent `header` for object `at` in the session of `epoch`.
    fn client_sent(&mut self, at: usize, header: &Header, epoch: u64) -> Result<(), Violation> {
        let track = &mut self.tracks[at];
        match header.kind {
            Kind::Get => {
                track.initial = header.grant;
                track.request = Some((header.request, epoch));
            }
            Kind::Ack => {
                if header.index > track.contiguous() {
                    return Err(Violation::EarlyAck);
                }
                if header.grant > track.initial + track.released {
                    return Err(Violation::Overcredit);
                }
            }
            _ => return Ok(()),
        }
        track.client_grant = track.client_grant.max(header.grant);
        Ok(())
    }

    /// The owner received ACK `header` for object `at`.
    fn owner_received(&mut self, at: usize, header: &Header) {
        let track = &mut self.tracks[at];
        track.owner_base = track.owner_base.max(header.index);
    }

    /// The owner sent `header` for object `at`.
    fn owner_sent(&mut self, at: usize, header: &Header) -> Result<(), Violation> {
        let track = &mut self.tracks[at];
        match header.kind {
            Kind::Start => {
                track.count = header.count;
                track.delivered.resize(header.count as usize, false);
            }
            Kind::Data if header.index >= track.client_grant => return Err(Violation::Overcredit),
            _ => {}
        }
        Ok(())
    }

    /// The client was delivered DATA or COMPLETE `header` for object `at`; the track records it when `header` carries the request ID and epoch of the client's GET.
    fn client_received(&mut self, at: usize, header: &Header) {
        let track = &mut self.tracks[at];
        if track.request != Some((header.request, header.epoch)) {
            return;
        }
        match header.kind {
            Kind::Data => {
                track.delivered.resize(header.count as usize, false);
                track.delivered[header.index as usize] = true;
            }
            Kind::Complete => track.complete_delivered = true,
            _ => {}
        }
    }

    /// The owner took a chunk of object `at`, `total` payload bytes long, covering `range`.
    fn chunk(&mut self, at: usize, total: u64, range: Range<u64>) {
        let track = &mut self.tracks[at];
        track.total = total;
        track.chunks.push(range);
    }

    /// The owner holds `retained` chunks of a live request for object `at`.
    fn retained(&self, at: usize, retained: usize) -> Result<(), Violation> {
        let track = &self.tracks[at];
        let acked = (u64::from(track.owner_base) * u64::from(FRAGMENT_LEN)).min(track.total);
        let unreleased = track
            .chunks
            .iter()
            .filter(|chunk| chunk.end > acked)
            .count();
        match retained.cmp(&unreleased) {
            std::cmp::Ordering::Less => Err(Violation::EarlyRelease),
            std::cmp::Ordering::Greater => Err(Violation::LateRelease),
            std::cmp::Ordering::Equal => Ok(()),
        }
    }

    /// The application took a fragment of object `at` from `manifest` at `offset` carrying `bytes`, to compare with `source`.
    fn exposed(
        &mut self,
        at: usize,
        manifest: Manifest,
        offset: u64,
        bytes: &[u8],
        source: &[u8],
    ) -> Result<(), Violation> {
        let track = &mut self.tracks[at];
        let start = offset as usize;
        let same = *track.exposed.get_or_insert(manifest) == manifest
            && offset == track.exposed_len
            && source.get(start..start + bytes.len()) == Some(bytes);
        if !same {
            return Err(Violation::Splice);
        }
        track.exposed_len += bytes.len() as u64;
        Ok(())
    }

    /// The application released one fragment lease of object `at`.
    fn released(&mut self, at: usize) {
        self.tracks[at].released += 1;
    }

    /// The client reported `outcome` for object `at`. A `Complete` outcome requires delivery to the client of every DATA index and of the request's COMPLETE; an empty object requires the delivered COMPLETE alone.
    fn outcome(&self, at: usize, outcome: Outcome) -> Result<(), Violation> {
        let track = &self.tracks[at];
        let whole =
            track.contiguous() == track.count && track.delivered.len() == track.count as usize;
        if outcome == Outcome::Complete && !(whole && track.complete_delivered) {
            return Err(Violation::FalseCompletion);
        }
        Ok(())
    }
}

/// What one run reached and delivered, with witnesses of the recoveries it took.
#[derive(Debug, Default)]
struct Run {
    outcomes: Vec<Option<Outcome>>,
    bytes: Vec<Vec<u8>>,
    lost: u64,
    get_retries: u64,
    ack_retries: u64,
    owner_retries: u64,
    /// Fetches refused because the promised receive boxes were all reserved.
    receive_refusals: u64,
}

/// One end-to-end run.
struct Scenario<'o> {
    seed: u64,
    objects: &'o [Object],
    /// Which objects the owner stores.
    stored: &'o [bool],
    faults: Faults,
    /// Frames lost on their first send.
    lose: &'o [Lose],
    /// Turns the application holds each lease at most.
    hold: u64,
    /// The payload offset past which every read fails.
    fail_at: Option<u64>,
    /// The first backing buffer's payload length; later ones carry [`SPAN`].
    first: u64,
    /// The client's window and the data boxes of its packet pool.
    window: u32,
    data_boxes: u32,
    /// Silent retry intervals the client allows before it ends a request.
    attempts: u32,
    turns: u64,
}

impl Scenario<'_> {
    const BASE: Scenario<'static> = Scenario {
        seed: 0,
        objects: &[],
        stored: &[],
        faults: CLEAN,
        lose: &[],
        hold: 3,
        fail_at: None,
        first: UNALIGNED,
        window: 8,
        data_boxes: 56,
        attempts: 50,
        turns: 20_000,
    };
}

/// Runs a client fetching every object of `scenario` against its owner, checking every step with the [`Oracle`] and the pools' and tables' conservation, and returns what the client delivered. Each turn runs as one controller round: the application's releases and fetches, the client's sends, the owner's receive, the simulated device, the owner's sends, the client's receive, then the application's takes.
fn run(scenario: Scenario<'_>) -> Run {
    let Scenario {
        seed,
        objects,
        stored,
        faults,
        lose,
        hold,
        fail_at,
        first,
        window,
        data_boxes,
        attempts,
        turns,
    } = scenario;
    let crc = Crc32c::detect();
    let mut rng = SplitMix64::new(seed);
    let session = Admitted {
        caps: Caps { slots: 8, window },
        ..SESSION
    };
    let mut budget = EngineBudget::new(1 << 26);
    let mut owner =
        Core::<Chunk>::new(SERVE, RequestTable::new(8, 1, 8), 1, 32, 0, 4, &mut budget).unwrap();
    let boxes = data_boxes + 8;
    let pool = super::packet::test_pool(boxes, 8).unwrap();
    let releases = Releases::new(8, &mut budget).unwrap();
    let config = FetchConfig {
        window,
        attempts,
        boxes: data_boxes,
        ..FETCH
    };
    let mut client =
        Fetcher::new(config, RequestTable::new(8, 1, 8), &releases, &mut budget).unwrap();
    let mut oracle = Oracle::new(objects.len());
    let mut lose = lose.to_vec();
    let mut to_owner = Wire {
        queue: Vec::new(),
        faults,
    };
    let mut to_client = Wire {
        queue: Vec::new(),
        faults,
    };
    let mut reads: Vec<Reading> = Vec::new();
    // Each object's live request, and whether its request closed.
    let mut ids: Vec<Option<RequestId>> = vec![None; objects.len()];
    let mut closed = vec![false; objects.len()];
    let at_of = |key: [u8; 32]| objects.iter().position(|object| object.key == key);
    let mut out = Run {
        bytes: vec![Vec::new(); objects.len()],
        outcomes: vec![None; objects.len()],
        ..Run::default()
    };
    let mut held: Vec<(u64, usize, FragmentLease<'_>)> = Vec::new();
    let (mut owner_sequence, mut client_sequence) = (0u64, 0u64);
    let mut lost = 0;
    let mut last = 0;
    for turn in 0..turns {
        let now = turn * 100;
        last = now;
        {
            // Each action of the turn, by its position in the round.
            let step = RefCell::new(|action: usize| match action {
                0 => {
                    // The application releases leases it held long enough; the oracle counts each release.
                    held.retain(|(until, at, _)| {
                        let keep = *until > turn;
                        if !keep {
                            oracle.released(*at);
                        }
                        keep
                    });
                    // The client starts each fetch its receive boxes admit.
                    for (at, object) in objects.iter().enumerate() {
                        if ids[at].is_some() || closed[at] {
                            continue;
                        }
                        match client.fetch(session, object.key, 1 << 10, 1 << 22, now, 5_000_000) {
                            Ok(id) => ids[at] = Some(id),
                            Err(FetchPressure::Receive) => out.receive_refusals += 1,
                            Err(other) => panic!("{other:?}"),
                        }
                    }
                    client.check_timers();
                }
                1 => {
                    // The client sends its GETs, ACKs and CANCELs.
                    client.tick(now);
                    client.check_timers();
                    let mut violation = Ok(());
                    client.poll(now, 16, |ask| {
                        let at = at_of(ask.header.key).expect("a fetched key");
                        violation = violation.and(oracle.client_sent(at, &ask.header, ask.epoch));
                        if let Some(kind) = Lose::of(&ask.header)
                            && let Some(first) = lose.iter().position(|lost| *lost == kind)
                        {
                            lose.swap_remove(first);
                            lost += 1;
                            return true;
                        }
                        client_sequence += 1;
                        to_owner.push(
                            &mut rng,
                            datagram(crc, ask.header, ask.epoch, client_sequence, [&[], &[]]),
                        );
                        true
                    });
                    violation.unwrap_or_else(|v| panic!("seed {seed} turn {turn}: {v:?}"));
                    client.check_timers();
                }
                2 => {
                    // The owner takes what arrived.
                    for bytes in std::mem::take(&mut to_owner.queue) {
                        let frame = parse(crc, &bytes, false).expect("canonical");
                        let header = frame.header();
                        let at = at_of(header.key).expect("a fetched key");
                        match header.kind {
                            Kind::Get => {
                                if let GetOutcome::Read { id, .. } =
                                    owner.get(session, &header, now)
                                {
                                    if stored[at] {
                                        owner.read_started(id);
                                        reads.push(Reading {
                                            id,
                                            object: at,
                                            delivered: 0,
                                            commanded: true,
                                        });
                                    } else {
                                        owner.read_refused(id, Status::Missing, now);
                                    }
                                }
                            }
                            Kind::Ack => {
                                oracle.owner_received(at, &header);
                                owner.ack(session, &header, now);
                            }
                            Kind::Cancel => owner.cancel(session, &header, now),
                            other => panic!("the owner never receives {other:?}"),
                        }
                    }
                }
                3 => {
                    // The simulated device delivers one command per read per turn.
                    for read in &mut reads {
                        if owner.is_ended(read.id) {
                            continue;
                        }
                        let source = &objects[read.object];
                        let total = source.payload.len() as u64;
                        let manifest = source.manifest(read.object);
                        if read.commanded {
                            read.commanded = false;
                            let span = if read.delivered == 0 { first } else { SPAN };
                            let end = (read.delivered + span).min(total);
                            if fail_at.is_some_and(|fail| end > fail) {
                                owner.read_done(read.id, ReadEnd::Failed(Status::DeviceError), now);
                                continue;
                            }
                            if end > read.delivered {
                                let chunk: Chunk =
                                    source.payload[read.delivered as usize..end as usize].into();
                                oracle.chunk(read.object, total, read.delivered..end);
                                owner.chunk(
                                    read.id,
                                    manifest,
                                    read.delivered..end,
                                    chunk,
                                    &[],
                                    now,
                                );
                            }
                            read.delivered = end;
                            if end == total {
                                owner.read_done(read.id, ReadEnd::Complete(manifest), now);
                            }
                        } else if owner.wants_grant(read.id) {
                            owner.granted(read.id);
                            read.commanded = true;
                        }
                    }
                }
                4 => {
                    owner.tick(now);
                    for read in &reads {
                        if !owner.is_ended(read.id) {
                            assert!(owner.retained(read.id) <= 2, "at most two backing buffers");
                            oracle
                                .retained(read.object, owner.retained(read.id))
                                .unwrap_or_else(|v| panic!("seed {seed} turn {turn}: {v:?}"));
                        }
                    }
                    owner.release_drained(|_| true);
                    let mut violation = Ok(());
                    owner.poll(now, 32, |frames| {
                        let mut taken = 0;
                        for frame in frames {
                            taken += 1;
                            let at = at_of(frame.header.key).expect("a fetched key");
                            violation = violation.and(oracle.owner_sent(at, &frame.header));
                            if let Some(kind) = Lose::of(&frame.header)
                                && let Some(first) = lose.iter().position(|lost| *lost == kind)
                            {
                                lose.swap_remove(first);
                                lost += 1;
                                continue;
                            }
                            owner_sequence += 1;
                            to_client.push(
                                &mut rng,
                                datagram(
                                    crc,
                                    frame.header,
                                    frame.epoch,
                                    owner_sequence,
                                    [frame.payload[0].bytes(), frame.payload[1].bytes()],
                                ),
                            );
                        }
                        taken
                    });
                    violation.unwrap_or_else(|v| panic!("seed {seed} turn {turn}: {v:?}"));
                }
                5 => {
                    // The client takes what arrived.
                    for bytes in std::mem::take(&mut to_client.queue) {
                        let frame = parse(crc, &bytes, false).expect("canonical");
                        let header = frame.header();
                        match header.kind {
                            Kind::Start => client.start(session, &header, now),
                            Kind::Data => {
                                assert!(frame.check_body(crc).is_ok());
                                let Ok(mut lease) = pool.acquire(PacketUse::Control) else {
                                    continue;
                                };
                                oracle.client_received(
                                    at_of(header.key).expect("a fetched key"),
                                    &header,
                                );
                                lease.buffer_mut()[..bytes.len()].copy_from_slice(&bytes);
                                lease.set_len(bytes.len());
                                client.data(session, &header, lease, now);
                            }
                            Kind::Complete => {
                                oracle.client_received(
                                    at_of(header.key).expect("a fetched key"),
                                    &header,
                                );
                                client.complete(session, &header);
                            }
                            Kind::Error => client.error(session, &header),
                            other => panic!("the client never receives {other:?}"),
                        }
                    }
                    client.check_timers();
                }
                _ => {
                    // The application takes fragments in order and holds each for a seeded number of turns.
                    for at in 0..objects.len() {
                        let Some(id) = ids[at] else {
                            continue;
                        };
                        while let Some(fragment) = client.take(id) {
                            oracle
                                .exposed(
                                    at,
                                    fragment.manifest(),
                                    fragment.offset(),
                                    fragment.bytes(),
                                    &objects[at].payload,
                                )
                                .unwrap_or_else(|v| panic!("seed {seed} turn {turn}: {v:?}"));
                            out.bytes[at].extend_from_slice(fragment.bytes());
                            held.push((turn + rng.below(hold + 1), at, fragment));
                        }
                        if let Some(outcome) = client.outcome(id) {
                            oracle
                                .outcome(at, outcome)
                                .unwrap_or_else(|v| panic!("seed {seed} turn {turn}: {v:?}"));
                            out.outcomes[at] = Some(outcome);
                            if client.close(id) {
                                ids[at] = None;
                                closed[at] = true;
                            }
                        }
                    }
                }
            });
            let step = &step;
            let actors = [
                Actor::Harness(0),
                Actor::Client(0),
                Actor::Owner(0),
                Actor::Disk(0),
                Actor::Owner(0),
                Actor::Client(0),
                Actor::Harness(1),
            ];
            let mut actions: Vec<_> = (0..actors.len())
                .map(|action| move || step.borrow_mut()(action))
                .collect();
            let mut acts: Vec<_> = actors
                .into_iter()
                .zip(&mut actions)
                .map(|(actor, action)| Act::new(actor, action))
                .collect();
            round(&mut acts);
        }
        client.check_timers();
        let report = pool.report();
        assert_eq!(report.data + report.control + report.free, report.count);
        assert!(report.data <= data_boxes);
        if closed.iter().all(|closed| *closed) && held.is_empty() {
            break;
        }
    }
    drop(held);
    client.check_timers();
    client.poll(last, 64, |_| true);
    for id in ids.iter().flatten() {
        client.close(*id);
    }
    assert_eq!(client.requests().census().active, 0, "every request closed");
    assert_eq!(pool.report().free, boxes, "every box returned to its pool");
    assert_eq!(client.reserved(), 0, "every reservation returned");
    out.lost = lost;
    out.get_retries = client.report().get_retries;
    out.ack_retries = client.report().ack_retries;
    assert_eq!(
        client.report().data_pressure,
        0,
        "every granted fragment had a box"
    );
    out.owner_retries = owner.report().retries;
    out
}

/// Under seeded loss, duplication and reordering in both directions, multi-fragment transfers deliver exact metadata then body bytes of one version and end Complete, and both sides' retries recover every loss.
#[test]
fn seeded_faults_still_deliver_exact_bytes_of_one_version() {
    let objects = [
        object(1, 37, 100_000),
        object(2, 0, 8192),
        object(3, 5, 40_001),
        object(8, 0, 0),
    ];
    let classes = [
        CLEAN,
        Faults {
            loss: 20,
            duplicate: 0,
            reorder: 0,
        },
        Faults {
            loss: 0,
            duplicate: 30,
            reorder: 0,
        },
        Faults {
            loss: 0,
            duplicate: 0,
            reorder: 40,
        },
        Faults {
            loss: 10,
            duplicate: 10,
            reorder: 20,
        },
    ];
    let mut retried = 0;
    for (class, faults) in classes.iter().enumerate() {
        for seed in 0..6u64 {
            for first in [UNALIGNED, SPAN] {
                let run = run(Scenario {
                    seed: seed * 7 + class as u64,
                    objects: &objects,
                    stored: &[true; 4],
                    faults: *faults,
                    first,
                    ..Scenario::BASE
                });
                for (at, object) in objects.iter().enumerate() {
                    assert_eq!(
                        run.outcomes[at],
                        Some(Outcome::Complete),
                        "class {class} seed {seed} object {at}"
                    );
                    assert_eq!(
                        run.bytes[at], object.payload,
                        "class {class} seed {seed} object {at}"
                    );
                }
                retried += run.owner_retries.min(1) * u64::from(faults.loss > 0);
            }
        }
    }
    assert!(retried > 0, "lossy runs recovered through owner retries");
}

/// A lost GET, START, final ACK and COMPLETE are each recovered: the client resends its GET, the owner resends START and its unacknowledged last fragment, whose duplicate queues the final ACK again, and a resent final ACK replays the cached COMPLETE.
#[test]
fn lost_final_controls_are_recovered() {
    let objects = [object(9, 3, 30_000)];
    for lose in [Lose::Get, Lose::Start, Lose::FinalAck, Lose::Complete] {
        let run = run(Scenario {
            objects: &objects,
            stored: &[true],
            lose: &[lose],
            ..Scenario::BASE
        });
        assert_eq!(run.lost, 1, "{lose:?}");
        assert_eq!(run.outcomes[0], Some(Outcome::Complete), "{lose:?}");
        assert_eq!(run.bytes[0], objects[0].payload, "{lose:?}");
        match lose {
            Lose::Get => assert!(run.get_retries > 0),
            Lose::Start => assert!(run.owner_retries > 0 || run.get_retries > 0),
            // The owner resends its last fragment, and the duplicate queues the final ACK again.
            Lose::FinalAck => assert!(run.owner_retries > 0),
            Lose::Complete => assert!(run.ack_retries > 0),
        }
    }
}

/// The client's retry budget counts silent intervals since the last progress, so a long transfer under heavy loss with more recovered gaps than the budget still completes.
#[test]
fn a_small_retry_budget_survives_many_recovered_gaps() {
    let objects = [object(14, 0, 400_000)];
    let run = run(Scenario {
        seed: 21,
        objects: &objects,
        stored: &[true],
        faults: Faults {
            loss: 30,
            duplicate: 0,
            reorder: 0,
        },
        attempts: 3,
        turns: 60_000,
        ..Scenario::BASE
    });
    assert!(
        run.ack_retries > 3,
        "more recovered gaps than the budget: {run:?}"
    );
    assert_eq!(run.outcomes[0], Some(Outcome::Complete));
    assert_eq!(run.bytes[0], objects[0].payload);
}

/// Windows of one fragment and of the protocol's 4096 deliver the same bytes.
#[test]
fn windows_of_one_and_4096_deliver_the_same_bytes() {
    let objects = [object(4, 10, 60_000)];
    for window in [1, 4096] {
        let run = run(Scenario {
            seed: 11,
            objects: &objects,
            stored: &[true],
            faults: Faults {
                loss: 10,
                duplicate: 10,
                reorder: 10,
            },
            hold: 2,
            window,
            data_boxes: window.max(8),
            turns: 40_000,
            ..Scenario::BASE
        });
        assert_eq!(run.outcomes[0], Some(Outcome::Complete), "window {window}");
        assert_eq!(run.bytes[0], objects[0].payload);
    }
}

/// With receive boxes for fewer than two windows, the second fetch is refused until the first closes and the application drops its leases; then it starts and completes, and no granted fragment ever lacks a box.
#[test]
fn a_refused_fetch_starts_after_receive_boxes_are_released() {
    let objects = [object(10, 0, 70_000), object(11, 4, 70_000)];
    let run = run(Scenario {
        seed: 5,
        objects: &objects,
        stored: &[true, true],
        hold: 40,
        window: 4,
        data_boxes: 6,
        turns: 40_000,
        ..Scenario::BASE
    });
    assert!(run.receive_refusals > 0, "the pressure state was reached");
    for (at, object) in objects.iter().enumerate() {
        assert_eq!(run.outcomes[at], Some(Outcome::Complete));
        assert_eq!(run.bytes[at], object.payload);
    }
}

/// An application holding the whole window longer than the retry budget lasts stalls the transfer without failing it: the client spends no retries while it waits, and the transfer completes once leases drop.
#[test]
fn an_application_stall_spends_no_retries() {
    let objects = [object(15, 0, 90_000)];
    let run = run(Scenario {
        seed: 6,
        objects: &objects,
        stored: &[true],
        hold: 2_000,
        window: 2,
        attempts: 3,
        turns: 400_000,
        ..Scenario::BASE
    });
    assert_eq!(run.outcomes[0], Some(Outcome::Complete), "{run:?}");
    assert_eq!(run.bytes[0], objects[0].payload);
    assert_eq!(
        run.ack_retries, 0,
        "the client waited on the application without retrying"
    );
}

/// A key the owner does not hold ends Missing with no byte; a read that fails after fragments were handed out ends Incomplete with only a prefix of the object exposed.
#[test]
fn a_miss_and_a_partial_failure_end_explicitly() {
    let objects = [object(5, 0, 50_000), object(6, 0, 50_000)];
    let run = run(Scenario {
        seed: 3,
        objects: &objects,
        stored: &[false, true],
        hold: 0,
        fail_at: Some(40_000),
        ..Scenario::BASE
    });
    assert_eq!(run.outcomes[0], Some(Outcome::Missing));
    assert!(run.bytes[0].is_empty());
    assert_eq!(
        run.outcomes[1],
        Some(Outcome::Incomplete(Status::DeviceError))
    );
    assert!(!run.bytes[1].is_empty() && run.bytes[1].len() < 50_000);
    assert_eq!(
        run.bytes[1],
        objects[1].payload[..run.bytes[1].len()],
        "a prefix of one version"
    );
}

/// The oracle rejects each violation it guards against, so the passing histories above are evidence: an ACK past receipt, DATA past the sent grant, a grant past releases, a chunk released before the ACK base passes it, a fragment of another version or out of order, and success before every fragment or before COMPLETE.
#[test]
fn the_oracle_rejects_every_violation_it_checks() {
    let source = object(12, 0, 3 * 8192);
    let manifest = source.manifest(0);
    let header = |kind, index, grant| Header {
        kind,
        index,
        grant,
        count: 3,
        total: 3 * 8192,
        ..*parse_get()
    };
    let started = || {
        let mut oracle = Oracle::new(1);
        oracle
            .client_sent(0, &header(Kind::Get, 0, 2), parse_get().epoch)
            .unwrap();
        oracle.owner_sent(0, &header(Kind::Start, 0, 0)).unwrap();
        oracle
    };
    let mut oracle = started();
    oracle.client_received(0, &header(Kind::Data, 0, 0));
    assert_eq!(
        oracle.client_sent(0, &header(Kind::Ack, 2, 2), parse_get().epoch),
        Err(Violation::EarlyAck)
    );
    assert_eq!(
        oracle.client_sent(0, &header(Kind::Ack, 1, 3), parse_get().epoch),
        Err(Violation::Overcredit),
        "a grant before any release"
    );
    oracle.released(0);
    oracle
        .client_sent(0, &header(Kind::Ack, 1, 3), parse_get().epoch)
        .unwrap();

    let mut oracle = started();
    oracle.owner_sent(0, &header(Kind::Data, 1, 0)).unwrap();
    assert_eq!(
        oracle.owner_sent(0, &header(Kind::Data, 2, 0)),
        Err(Violation::Overcredit),
        "DATA past the grant of 2"
    );

    let mut oracle = started();
    oracle.chunk(0, 3 * 8192, 0..16_384);
    oracle.chunk(0, 3 * 8192, 16_384..3 * 8192);
    oracle.owner_received(0, &header(Kind::Ack, 1, 2));
    assert_eq!(
        oracle.retained(0, 1),
        Err(Violation::EarlyRelease),
        "base 1 covers only half the first chunk"
    );
    oracle.retained(0, 2).unwrap();
    oracle.owner_received(0, &header(Kind::Ack, 2, 2));
    assert_eq!(
        oracle.retained(0, 2),
        Err(Violation::LateRelease),
        "base 2 ends the first chunk"
    );
    oracle.retained(0, 1).unwrap();

    let mut oracle = started();
    let other = Manifest {
        allocation: 7,
        ..manifest
    };
    oracle
        .exposed(0, manifest, 0, &source.payload[..8192], &source.payload)
        .unwrap();
    assert_eq!(
        oracle.exposed(
            0,
            other,
            8192,
            &source.payload[8192..16_384],
            &source.payload
        ),
        Err(Violation::Splice),
        "another version"
    );
    assert_eq!(
        oracle.exposed(
            0,
            manifest,
            16_384,
            &source.payload[16_384..],
            &source.payload
        ),
        Err(Violation::Splice),
        "a gap"
    );
    assert_eq!(
        oracle.exposed(0, manifest, 8192, &[0; 8192], &source.payload),
        Err(Violation::Splice),
        "other bytes"
    );

    let mut oracle = started();
    oracle.client_received(0, &header(Kind::Data, 0, 0));
    oracle.client_received(0, &header(Kind::Data, 2, 0));
    oracle.client_received(0, &header(Kind::Complete, 3, 0));
    assert_eq!(
        oracle.outcome(0, Outcome::Complete),
        Err(Violation::FalseCompletion),
        "a missing fragment"
    );
    let mut oracle = started();
    for index in 0..3 {
        oracle.client_received(0, &header(Kind::Data, index, 0));
    }
    assert_eq!(
        oracle.outcome(0, Outcome::Complete),
        Err(Violation::FalseCompletion),
        "no COMPLETE"
    );
    oracle.client_received(0, &header(Kind::Complete, 3, 0));
    oracle.outcome(0, Outcome::Complete).unwrap();
}

/// The oracle credits completion on delivery to the client, bound to the request ID and epoch of the GET. A `Complete` outcome is a `FalseCompletion` after a COMPLETE the owner sent and the link dropped, a COMPLETE of another request or session, or a fragment of another request. It passes once every DATA and the request's COMPLETE arrive; an empty object fails before its COMPLETE arrives and passes after.
#[test]
fn the_oracle_credits_completion_only_on_client_delivery() {
    let get = *parse_get();
    let header = |kind, index, count| Header {
        kind,
        index,
        count,
        grant: 2,
        total: u64::from(count) * 8192,
        ..get
    };
    let started = |count| {
        let mut oracle = Oracle::new(1);
        oracle
            .client_sent(0, &header(Kind::Get, 0, count), get.epoch)
            .unwrap();
        oracle
            .owner_sent(0, &header(Kind::Start, 0, count))
            .unwrap();
        oracle
    };
    let delivered = |oracle: &mut Oracle| {
        for index in 0..2 {
            oracle.client_received(0, &header(Kind::Data, index, 2));
        }
    };
    let mut dropped = started(2);
    delivered(&mut dropped);
    dropped
        .owner_sent(0, &header(Kind::Complete, 2, 2))
        .unwrap();
    assert_eq!(
        dropped.outcome(0, Outcome::Complete),
        Err(Violation::FalseCompletion),
        "a COMPLETE sent and dropped"
    );
    for (other, what) in [
        (
            Header {
                request: get.request + 1,
                ..header(Kind::Complete, 2, 2)
            },
            "another request",
        ),
        (
            Header {
                epoch: get.epoch + 1,
                ..header(Kind::Complete, 2, 2)
            },
            "another session",
        ),
    ] {
        let mut oracle = started(2);
        delivered(&mut oracle);
        oracle.client_received(0, &other);
        assert_eq!(
            oracle.outcome(0, Outcome::Complete),
            Err(Violation::FalseCompletion),
            "a COMPLETE of {what}"
        );
    }
    let mut foreign = started(2);
    foreign.client_received(0, &header(Kind::Data, 0, 2));
    foreign.client_received(
        0,
        &Header {
            request: get.request + 1,
            ..header(Kind::Data, 1, 2)
        },
    );
    foreign.client_received(0, &header(Kind::Complete, 2, 2));
    assert_eq!(
        foreign.outcome(0, Outcome::Complete),
        Err(Violation::FalseCompletion),
        "a fragment of another request"
    );
    let mut whole = started(2);
    delivered(&mut whole);
    whole.client_received(0, &header(Kind::Complete, 2, 2));
    whole.outcome(0, Outcome::Complete).unwrap();
    let mut empty = started(0);
    assert_eq!(
        empty.outcome(0, Outcome::Complete),
        Err(Violation::FalseCompletion),
        "an empty object before its COMPLETE"
    );
    empty.client_received(0, &header(Kind::Complete, 0, 0));
    empty.outcome(0, Outcome::Complete).unwrap();
}

/// A header with every field set as a GET for key 12 carries it, for the oracle's controls.
fn parse_get() -> &'static Header {
    const GET: Header = Header {
        kind: Kind::Get,
        principal: 1,
        key_epoch: 1,
        owner_nonce: [0x0A; 16],
        client_nonce: [0x0C; 16],
        request: 0,
        sequence: 1,
        allocation: 0x5_0000_0001,
        total: 0,
        metadata_len: 0,
        body_len: 0,
        index: 0,
        count: 0,
        offset: 0,
        datagram_len: 0,
        grant: 0,
        status: 0,
        remaining_ms: 1000,
        key: [12; 32],
        epoch: 3,
        tag: [0; 16],
    };
    &GET
}

/// Forged early-release and double-credit ACKs release no chunk and admit no fragment beyond the client's grant; the next valid ACK admits exactly the fragments its grant names.
#[test]
fn forged_early_release_and_double_credit_create_no_capacity() {
    let crc = Crc32c::detect();
    let mut budget = EngineBudget::new(1 << 24);
    let mut owner =
        Core::<Chunk>::new(SERVE, RequestTable::new(8, 1, 8), 1, 32, 0, 4, &mut budget).unwrap();
    let session = Admitted {
        caps: Caps {
            slots: 8,
            window: 2,
        },
        ..SESSION
    };
    let source = object(7, 0, 5 * 8192).payload;
    let manifest = Manifest {
        allocation: 9,
        metadata_len: 0,
        body_len: 5 * 8192,
    };
    let get = Header {
        kind: Kind::Get,
        principal: 1,
        key_epoch: 1,
        owner_nonce: [0x0A; 16],
        client_nonce: [0x0C; 16],
        request: RequestId::from_wire(0).wire(),
        sequence: 1,
        allocation: 0,
        total: 0,
        metadata_len: 0,
        body_len: 1 << 20,
        index: 0,
        count: 0,
        offset: 0,
        datagram_len: 0,
        grant: 2,
        status: 0,
        remaining_ms: 1000,
        key: [7; 32],
        epoch: 3,
        tag: [0; 16],
    };
    let GetOutcome::Read { id, .. } = owner.get(session, &get, 0) else {
        panic!("new");
    };
    owner.read_started(id);
    owner.chunk(id, manifest, 0..5 * 8192, source.clone().into(), &[], 0);
    let mut sent = Vec::new();
    owner.poll(0, 16, |frames| {
        frames
            .map(|frame| {
                sent.push(frame.header.index);
                let _ = datagram(
                    crc,
                    frame.header,
                    frame.epoch,
                    1,
                    [frame.payload[0].bytes(), frame.payload[1].bytes()],
                );
            })
            .count()
    });
    assert_eq!(
        sent,
        [0, 0, 1],
        "START, then fragments within the grant of 2"
    );
    let ack = |base: u32, grant: u32| Header {
        kind: Kind::Ack,
        allocation: 9,
        total: manifest.total(),
        body_len: manifest.body_len,
        metadata_len: 0,
        count: 5,
        index: base,
        grant,
        remaining_ms: 0,
        ..get
    };
    // Early release: a base past what was sent.
    owner.ack(session, &ack(4, 6), 0);
    // Double credit: a grant past the window above the base.
    owner.ack(session, &ack(1, 9), 0);
    assert_eq!(owner.retained(id), 1, "no chunk released");
    let mut more = Vec::new();
    owner.poll(0, 16, |frames| {
        frames.map(|frame| more.push(frame.header.index)).count()
    });
    assert!(more.is_empty(), "no capacity was created");
    owner.ack(session, &ack(2, 4), 0);
    owner.poll(0, 16, |frames| {
        frames.map(|frame| more.push(frame.header.index)).count()
    });
    assert_eq!(more, [2, 3]);
}

/// DATA that arrives before START waits unexposed and unacknowledged until a matching START exposes it; a held fragment, a later START or later DATA naming another manifest is dropped; COMPLETE before every fragment leaves the request open.
#[test]
fn pre_start_data_waits_for_a_matching_start() {
    let crc = Crc32c::detect();
    let mut budget = EngineBudget::new(1 << 24);
    let pool = pool8();
    let releases = Releases::new(4, &mut budget).unwrap();
    let mut client =
        Fetcher::new(FETCH, RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let id = client
        .fetch(SESSION, [7; 32], 1 << 10, 1 << 20, 0, 1_000_000)
        .unwrap();
    let mut asks = Vec::new();
    client.poll(0, 4, |ask| {
        asks.push(ask.header);
        true
    });
    assert_eq!(asks[0].kind, Kind::Get);
    let manifest = Manifest {
        allocation: 9,
        metadata_len: 0,
        body_len: 9000,
    };
    let base = Header {
        kind: Kind::Start,
        allocation: 9,
        total: 9000,
        metadata_len: 0,
        body_len: 9000,
        count: 2,
        grant: 0,
        remaining_ms: 0,
        ..asks[0]
    };
    let data = |index: u32, allocation: u64| {
        let start = index as usize * 8192;
        let end = (start + 8192).min(9000);
        let body: Vec<u8> = (start..end).map(|n| n as u8).collect();
        let header = Header {
            kind: Kind::Data,
            allocation,
            index,
            offset: start as u64,
            ..base
        };
        let bytes = datagram(crc, header, 3, 1, [&body, &[]]);
        let lease = lease_of(&pool, &bytes);
        (parse(crc, &bytes, false).unwrap().header(), lease)
    };
    let (header, lease) = data(0, 9);
    client.data(SESSION, &header, lease, 0);
    let (header, lease) = data(1, 8);
    client.data(SESSION, &header, lease, 0);
    assert!(client.take(id).is_none(), "nothing exposed before START");
    asks.clear();
    client.poll(0, 4, |ask| {
        asks.push(ask.header);
        true
    });
    assert!(
        asks.iter().all(|ask| ask.kind != Kind::Ack),
        "no receipt ACK before START"
    );
    client.complete(
        SESSION,
        &Header {
            kind: Kind::Complete,
            index: 2,
            ..base
        },
    );
    assert_eq!(client.outcome(id), None, "COMPLETE needs every fragment");
    client.start(SESSION, &base, 0);
    let first = client
        .take(id)
        .expect("the held fragment 0, exposed by START");
    assert_eq!(
        (first.index(), first.offset(), first.manifest()),
        (0, 0, manifest)
    );
    assert!(
        client.take(id).is_none(),
        "the held fragment 1 named another manifest and was dropped"
    );
    client.complete(
        SESSION,
        &Header {
            kind: Kind::Complete,
            index: 2,
            ..base
        },
    );
    assert_eq!(
        client.outcome(id),
        None,
        "the second fragment is still owed"
    );
    let dropped = client.report().dropped;
    client.start(
        SESSION,
        &Header {
            allocation: 8,
            ..base
        },
        0,
    );
    let (header, lease) = data(1, 8);
    client.data(SESSION, &header, lease, 0);
    assert_eq!(
        client.report().dropped,
        dropped + 1,
        "DATA of another manifest after START"
    );
    assert!(client.take(id).is_none());
    let (header, lease) = data(1, 9);
    client.data(SESSION, &header, lease, 0);
    let second = client.take(id).expect("fragment 1 of the bound manifest");
    assert_eq!((second.offset(), second.manifest()), (8192, manifest));
    client.complete(
        SESSION,
        &Header {
            kind: Kind::Complete,
            index: 2,
            ..base
        },
    );
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
}

/// Only an application release grows the client's grant: received and duplicate fragments add nothing, each dropped lease adds one, and the lease stays readable after its request closed.
#[test]
fn grants_grow_only_on_release_and_leases_outlive_their_request() {
    let crc = Crc32c::detect();
    let mut budget = EngineBudget::new(1 << 24);
    let pool = pool8();
    let releases = Releases::new(4, &mut budget).unwrap();
    let config = FetchConfig { window: 2, ..FETCH };
    let mut client =
        Fetcher::new(config, RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let session = Admitted {
        caps: Caps {
            slots: 8,
            window: 2,
        },
        ..SESSION
    };
    let id = client
        .fetch(session, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let mut get = None;
    client.poll(0, 4, |ask| {
        get = Some(ask.header);
        true
    });
    let get = get.unwrap();
    let start = Header {
        kind: Kind::Start,
        allocation: 9,
        total: 4 * 8192,
        body_len: 4 * 8192,
        metadata_len: 0,
        count: 4,
        grant: 0,
        remaining_ms: 0,
        ..get
    };
    client.start(session, &start, 0);
    let grants = |client: &mut Fetcher<'_>| {
        let mut grants = Vec::new();
        client.poll(0, 4, |ask| {
            grants.push((ask.header.index, ask.header.grant));
            true
        });
        grants
    };
    assert_eq!(
        grants(&mut client),
        [(0, 2)],
        "the manifest ACK carries the initial grant"
    );
    for index in [0, 0, 1, 2] {
        deliver(&mut client, &pool, crc, session, &start, index);
    }
    assert_eq!(
        grants(&mut client),
        [(2, 2)],
        "receipt and a duplicate add no grant; fragment 2 was outside it"
    );
    let first = client.take(id).unwrap();
    assert_eq!(
        grants(&mut client),
        [],
        "taking a fragment is not a release"
    );
    drop(first);
    assert_eq!(grants(&mut client), [(2, 3)]);
    let second = client.take(id).unwrap();
    client.cancel(id);
    assert_eq!(
        client.outcome(id),
        Some(Outcome::Incomplete(Status::Cancelled)),
        "a cancel after exposure"
    );
    assert!(!client.close(id), "the CANCEL is still unsent");
    let mut cancels = Vec::new();
    client.poll(0, 4, |ask| {
        cancels.push((ask.header.kind, ask.header.status));
        true
    });
    assert_eq!(cancels, [(Kind::Cancel, Status::Cancelled as u16)]);
    assert!(client.close(id));
    assert_eq!(
        second.bytes(),
        &[1u8; 8192][..],
        "a lease outlives its request"
    );
    drop(second);
    assert_eq!(pool.report().free, 8);
}

/// Every client path allocates nothing: fetch, pre-START hold, START, receipt, duplicate, out-of-window and other-manifest drops, take, release, poll, ACK and GET retries, retry exhaustion, the deadline, ERROR, cancel, an oversize START and close.
#[test]
fn every_client_path_allocates_nothing() {
    let crc = Crc32c::detect();
    let pool = super::packet::test_pool(16, 2).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 2, 8);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    // The DATA datagrams are built before measuring: fragments 0 to 3 of the manifest and fragment 1 of another.
    let encode = |header: Header| {
        let body = [header.index as u8; 8192];
        let bytes = datagram(crc, header, 3, 1, [&body, &[]]);
        (parse(crc, &bytes, false).unwrap().header(), bytes)
    };
    let fragments: Vec<(Header, Vec<u8>)> = (0..4u32)
        .map(|index| {
            encode(Header {
                kind: Kind::Data,
                index,
                offset: u64::from(index) * 8192,
                ..start
            })
        })
        .chain([encode(Header {
            kind: Kind::Data,
            allocation: 8,
            index: 1,
            offset: 8192,
            ..start
        })])
        .collect();
    let error = Header {
        kind: Kind::Error,
        status: Status::Missing as u16,
        ..get
    };
    let allocations = crate::instrument::allocations();
    feed(&mut client, &pool, &fragments[0]);
    feed(&mut client, &pool, &fragments[4]);
    client.start(SESSION, &start, 0);
    feed(&mut client, &pool, &fragments[0]);
    feed(&mut client, &pool, &fragments[3]);
    feed(&mut client, &pool, &fragments[1]);
    client.poll(0, 4, |_| true);
    client.tick(3_000);
    client.poll(3_000, 4, |_| true);
    drop(client.take(id));
    drop(client.take(id));
    client.poll(3_000, 4, |_| true);
    feed(&mut client, &pool, &fragments[2]);
    feed(&mut client, &pool, &fragments[3]);
    drop(client.take(id));
    drop(client.take(id));
    client.complete(
        SESSION,
        &Header {
            kind: Kind::Complete,
            index: 4,
            ..start
        },
    );
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    assert!(client.close(id));
    let silent = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 10_000_000)
        .unwrap();
    // Fifty retries at waits that double to eight intervals end inside 500 intervals.
    for turn in 1..=500 {
        client.tick(turn * 3_000);
        client.poll(turn * 3_000, 4, |_| true);
    }
    assert_eq!(
        client.outcome(silent),
        Some(Outcome::Failed(Status::OwnerUnavailable))
    );
    assert!(client.close(silent));
    let late = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000)
        .unwrap();
    client.tick(1_000);
    client.poll(1_000, 4, |_| true);
    assert!(client.close(late));
    let refused = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    client.error(
        SESSION,
        &Header {
            request: client.wire(refused).unwrap(),
            ..error
        },
    );
    assert!(client.close(refused));
    let cancelled = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    client.cancel(cancelled);
    client.poll(0, 4, |_| true);
    assert!(client.close(cancelled));
    let oversize = client
        .fetch(SESSION, [7; 32], 0, 100, 0, 1_000_000)
        .unwrap();
    client.start(
        SESSION,
        &Header {
            request: client.wire(oversize).unwrap(),
            ..start
        },
        0,
    );
    client.poll(0, 4, |_| true);
    assert!(client.close(oversize));
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(
        client.report().dropped,
        3,
        "a duplicate, an outside-window fragment and another manifest's"
    );
}

/// Delivers DATA fragment `index` of `start`'s manifest, full of the byte `index`, to `client` in a lease of `pool`.
fn deliver<'p>(
    client: &mut impl StaleFrames<'p>,
    pool: &'p PacketPool,
    crc: Crc32c,
    session: Admitted,
    start: &Header,
    index: u32,
) {
    deliver_at(client, pool, crc, session, start, index, 0);
}

/// [`deliver`] at `now_us`.
fn deliver_at<'p>(
    client: &mut impl StaleFrames<'p>,
    pool: &'p PacketPool,
    crc: Crc32c,
    session: Admitted,
    start: &Header,
    index: u32,
    now_us: u64,
) {
    let body = vec![index as u8; 8192];
    let header = Header {
        kind: Kind::Data,
        index,
        offset: u64::from(index) * 8192,
        ..*start
    };
    let bytes = datagram(crc, header, 3, 1, [&body, &[]]);
    let lease = lease_of(pool, &bytes);
    client.data(session, &header, lease, now_us);
}

/// The last frame `client` sends when polled at `now_us`: its GET, ACK or CANCEL.
fn last_sent<'p>(client: &mut impl StaleFrames<'p>, now_us: u64) -> Header {
    let mut get = None;
    client.poll(now_us, 4, |ask| {
        get = Some(ask.header);
        true
    });
    get.expect("a frame")
}

/// GET retries keep the fingerprint and carry the shrinking remaining duration; after the deadline the request ends TimedOut, or Incomplete once a fragment was handed out, and the owner is told with a CANCEL.
#[test]
fn get_retries_shrink_their_duration_and_the_deadline_ends_the_request() {
    let crc = Crc32c::detect();
    let mut budget = EngineBudget::new(1 << 24);
    let pool = pool8();
    let releases = Releases::new(4, &mut budget).unwrap();
    let mut client =
        Fetcher::new(FETCH, RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let silent = client
        .fetch(SESSION, [7; 32], 16, 1 << 20, 0, 10_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    assert_eq!(get.remaining_ms, 10);
    client.tick(3_000);
    let retry = last_sent(&mut client, 3_000);
    assert_eq!(retry.remaining_ms, 7);
    let fingerprint = |h: &Header| (h.request, h.key, h.metadata_len, h.body_len, h.grant);
    assert_eq!(fingerprint(&retry), fingerprint(&get));
    client.tick(10_000);
    assert_eq!(
        client.outcome(silent),
        Some(Outcome::Failed(Status::TimedOut))
    );
    let cancel = last_sent(&mut client, 10_000);
    assert_eq!(
        (cancel.kind, cancel.status),
        (Kind::Cancel, Status::TimedOut as u16)
    );
    assert!(client.close(silent));

    let exposed = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 10_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = Header {
        kind: Kind::Start,
        allocation: 9,
        total: 2 * 8192,
        body_len: 2 * 8192,
        metadata_len: 0,
        count: 2,
        grant: 0,
        remaining_ms: 0,
        ..get
    };
    client.start(SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    drop(client.take(exposed).expect("fragment 0"));
    client.tick(10_000);
    assert_eq!(
        client.outcome(exposed),
        Some(Outcome::Incomplete(Status::TimedOut))
    );
}

/// The client ignores frames from another session epoch or peer, for another key, or for a closed request whose wire slot a later request holds.
#[test]
fn stale_frames_change_nothing() {
    stale_frames_change_nothing_on::<Unchanged>();
}

/// The body of [`stale_frames_change_nothing`], over the client `W` makes of a fetcher.
fn stale_frames_change_nothing_on<W: Wrap>() {
    let crc = Crc32c::detect();
    let mut budget = EngineBudget::new(1 << 24);
    let pool = pool8();
    let releases = Releases::new(4, &mut budget).unwrap();
    let mut client =
        W::wrap(Fetcher::new(FETCH, RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap());
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = Header {
        kind: Kind::Start,
        allocation: 9,
        total: 8192,
        body_len: 8192,
        metadata_len: 0,
        count: 1,
        grant: 0,
        remaining_ms: 0,
        ..get
    };
    let replaced = Admitted {
        epoch: 4,
        ..SESSION
    };
    client.start(replaced, &start, 0);
    client.start(
        SESSION,
        &Header {
            key: [8; 32],
            ..start
        },
        0,
    );
    deliver(&mut client, &pool, crc, replaced, &start, 0);
    client.error(
        replaced,
        &Header {
            kind: Kind::Error,
            status: Status::Missing as u16,
            ..get
        },
    );
    assert_eq!(
        client.outcome(id),
        None,
        "a replaced epoch's frames reach nothing"
    );
    assert!(client.take(id).is_none());
    client.start(SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    client.complete(
        SESSION,
        &Header {
            kind: Kind::Complete,
            index: 1,
            ..start
        },
    );
    assert_eq!(client.outcome(id), Some(Outcome::Complete));
    let fragment = client.take(id).expect("fragment 0");
    assert!(client.close(id));
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    client.error(
        SESSION,
        &Header {
            kind: Kind::Error,
            status: Status::Missing as u16,
            ..get
        },
    );
    assert!(client.take(id).is_none(), "a closed request takes nothing");
    drop(fragment);
    assert_eq!(pool.report().free, 8);
    let next = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let wire = client.wire(next).unwrap();
    assert_eq!(
        RequestId::from_wire(wire).slot(),
        RequestId::from_wire(get.request).slot(),
        "the closed request's wire slot"
    );
    client.start(SESSION, &start, 0);
    client.error(
        Admitted {
            peer: PeerId(1),
            ..SESSION
        },
        &Header {
            kind: Kind::Error,
            status: Status::Missing as u16,
            request: wire,
            ..get
        },
    );
    assert_eq!(
        client.outcome(next),
        None,
        "frames naming the closed request, or from another peer, reach nothing"
    );
    assert_eq!(last_sent(&mut client, 0).kind, Kind::Get);
}

/// Planted defect: a client whose session check is removed judges a replaced epoch's frames as the request's own
/// session's. The replaced epoch's ERROR then ends the request `Missing`, and the body of
/// [`stale_frames_change_nothing`] fails at its first check that stale frames reached nothing,
/// `assert_eq!(client.outcome(id), None)`, with the outcome the stale ERROR left.
#[test]
#[should_panic(expected = "a replaced epoch's frames reach nothing")]
fn negative_control_a_session_blind_client_lets_a_replaced_session_reach_the_request() {
    stale_frames_change_nothing_on::<Blind>();
}

/// The frame calls the stale-frame check makes, so it runs over the production client and over a broken one.
trait StaleFrames<'p> {
    fn fetch(
        &mut self,
        session: Admitted,
        key: [u8; 32],
        metadata_cap: u32,
        body_cap: u32,
        now_us: u64,
        wait_us: u64,
    ) -> Result<RequestId, FetchPressure>;
    fn start(&mut self, session: Admitted, header: &Header, now_us: u64);
    fn data(&mut self, session: Admitted, header: &Header, lease: PacketLease<'p>, now_us: u64);
    fn complete(&mut self, session: Admitted, header: &Header);
    fn error(&mut self, session: Admitted, header: &Header);
    fn take(&mut self, id: RequestId) -> Option<FragmentLease<'p>>;
    fn outcome(&self, id: RequestId) -> Option<Outcome>;
    fn wire(&self, id: RequestId) -> Option<u64>;
    fn close(&mut self, id: RequestId) -> bool;
    fn poll(
        &mut self,
        now_us: u64,
        budget: usize,
        send: impl FnMut(super::fetch::Ask) -> bool,
    ) -> usize;
}

impl<'p> StaleFrames<'p> for Fetcher<'p> {
    fn fetch(
        &mut self,
        session: Admitted,
        key: [u8; 32],
        metadata_cap: u32,
        body_cap: u32,
        now_us: u64,
        wait_us: u64,
    ) -> Result<RequestId, FetchPressure> {
        Fetcher::fetch(self, session, key, metadata_cap, body_cap, now_us, wait_us)
    }
    fn start(&mut self, session: Admitted, header: &Header, now_us: u64) {
        Fetcher::start(self, session, header, now_us);
    }
    fn data(&mut self, session: Admitted, header: &Header, lease: PacketLease<'p>, now_us: u64) {
        Fetcher::data(self, session, header, lease, now_us);
    }
    fn complete(&mut self, session: Admitted, header: &Header) {
        Fetcher::complete(self, session, header);
    }
    fn error(&mut self, session: Admitted, header: &Header) {
        Fetcher::error(self, session, header);
    }
    fn take(&mut self, id: RequestId) -> Option<FragmentLease<'p>> {
        Fetcher::take(self, id)
    }
    fn outcome(&self, id: RequestId) -> Option<Outcome> {
        Fetcher::outcome(self, id)
    }
    fn wire(&self, id: RequestId) -> Option<u64> {
        Fetcher::wire(self, id)
    }
    fn close(&mut self, id: RequestId) -> bool {
        Fetcher::close(self, id)
    }
    fn poll(
        &mut self,
        now_us: u64,
        budget: usize,
        send: impl FnMut(super::fetch::Ask) -> bool,
    ) -> usize {
        Fetcher::poll(self, now_us, budget, send)
    }
}

/// A client a check runs over, made from a production fetcher.
trait Wrap {
    type Client<'p>: StaleFrames<'p>;
    fn wrap(fetcher: Fetcher<'_>) -> Self::Client<'_>;
}

/// The production fetcher itself.
struct Unchanged;

impl Wrap for Unchanged {
    type Client<'p> = Fetcher<'p>;
    fn wrap(fetcher: Fetcher<'_>) -> Fetcher<'_> {
        fetcher
    }
}

/// The fetcher with its session check removed: every frame is judged as if the session the last request was
/// fetched under had sent it, whatever epoch or peer the frame names.
struct Blind;

/// [`Blind`]'s client.
struct SessionBlind<'p> {
    fetcher: Fetcher<'p>,
    fetched: Option<Admitted>,
}

impl Wrap for Blind {
    type Client<'p> = SessionBlind<'p>;
    fn wrap(fetcher: Fetcher<'_>) -> SessionBlind<'_> {
        SessionBlind {
            fetcher,
            fetched: None,
        }
    }
}

impl SessionBlind<'_> {
    fn judged_as(&self, session: Admitted) -> Admitted {
        self.fetched.unwrap_or(session)
    }
}

impl<'p> StaleFrames<'p> for SessionBlind<'p> {
    fn fetch(
        &mut self,
        session: Admitted,
        key: [u8; 32],
        metadata_cap: u32,
        body_cap: u32,
        now_us: u64,
        wait_us: u64,
    ) -> Result<RequestId, FetchPressure> {
        self.fetched = Some(session);
        self.fetcher
            .fetch(session, key, metadata_cap, body_cap, now_us, wait_us)
    }
    fn start(&mut self, session: Admitted, header: &Header, now_us: u64) {
        let session = self.judged_as(session);
        self.fetcher.start(session, header, now_us);
    }
    fn data(&mut self, session: Admitted, header: &Header, lease: PacketLease<'p>, now_us: u64) {
        let session = self.judged_as(session);
        self.fetcher.data(session, header, lease, now_us);
    }
    fn complete(&mut self, session: Admitted, header: &Header) {
        let session = self.judged_as(session);
        self.fetcher.complete(session, header);
    }
    fn error(&mut self, session: Admitted, header: &Header) {
        let session = self.judged_as(session);
        self.fetcher.error(session, header);
    }
    fn take(&mut self, id: RequestId) -> Option<FragmentLease<'p>> {
        self.fetcher.take(id)
    }
    fn outcome(&self, id: RequestId) -> Option<Outcome> {
        self.fetcher.outcome(id)
    }
    fn wire(&self, id: RequestId) -> Option<u64> {
        self.fetcher.wire(id)
    }
    fn close(&mut self, id: RequestId) -> bool {
        self.fetcher.close(id)
    }
    fn poll(
        &mut self,
        now_us: u64,
        budget: usize,
        send: impl FnMut(super::fetch::Ask) -> bool,
    ) -> usize {
        self.fetcher.poll(now_us, budget, send)
    }
}

/// The owner counts a fragment as sent only once its send returned true: an ACK past a refused fragment is stale, and one up to the accepted fragments releases what it covers.
#[test]
fn acks_count_only_fragments_whose_send_returned_true() {
    let mut budget = EngineBudget::new(1 << 24);
    let mut owner =
        Core::<Chunk>::new(SERVE, RequestTable::new(8, 1, 8), 1, 32, 0, 4, &mut budget).unwrap();
    let source = object(13, 0, 4 * 8192);
    let manifest = source.manifest(0);
    let get = Header {
        key: source.key,
        grant: 4,
        body_len: 1 << 20,
        allocation: 0,
        ..*parse_get()
    };
    let GetOutcome::Read { id, .. } = owner.get(SESSION, &get, 0) else {
        panic!("a new request");
    };
    owner.read_started(id);
    owner.chunk(
        id,
        manifest,
        0..16_384,
        source.payload[..16_384].into(),
        &[],
        0,
    );
    owner.granted(id);
    owner.chunk(
        id,
        manifest,
        16_384..4 * 8192,
        source.payload[16_384..].into(),
        &[],
        0,
    );
    owner.read_done(id, ReadEnd::Complete(manifest), 0);
    let mut sent = Vec::new();
    owner.poll(0, 16, |frames| {
        frames
            .take_while(|frame| !(frame.header.kind == Kind::Data && frame.header.index == 2))
            .map(|frame| sent.push((frame.header.kind, frame.header.index)))
            .count()
    });
    assert_eq!(sent, [(Kind::Start, 0), (Kind::Data, 0), (Kind::Data, 1)]);
    let ack = |base| Header {
        kind: Kind::Ack,
        allocation: manifest.allocation,
        total: manifest.total(),
        metadata_len: 0,
        body_len: manifest.body_len,
        count: 4,
        index: base,
        grant: 4,
        remaining_ms: 0,
        ..get
    };
    let stale = owner.report().stale_acks;
    owner.ack(SESSION, &ack(3), 0);
    assert_eq!(
        owner.report().stale_acks,
        stale + 1,
        "fragment 2 was never sent"
    );
    assert_eq!(owner.retained(id), 2);
    owner.ack(SESSION, &ack(2), 0);
    assert_eq!(
        owner.retained(id),
        1,
        "base 2 ends the first chunk at its command boundary"
    );
}

/// A fresh client core of `slots` request slots over `releases`, with `boxes` receive boxes and windows of `window`.
pub(super) fn client<'p>(
    releases: &'p Releases,
    slots: u32,
    window: u32,
    boxes: u32,
) -> Fetcher<'p> {
    let config = FetchConfig {
        window,
        boxes,
        ..FETCH
    };
    Fetcher::new(
        config,
        RequestTable::new(slots, 1, slots),
        releases,
        &mut EngineBudget::new(1 << 26),
    )
    .unwrap()
}

/// A START for `get`'s request naming a `total`-byte body under allocation 9.
fn start_for(get: &Header, total: u64) -> Header {
    Header {
        kind: Kind::Start,
        allocation: 9,
        total,
        body_len: total as u32,
        metadata_len: 0,
        count: total.div_ceil(8192) as u32,
        grant: 0,
        remaining_ms: 0,
        ..*get
    }
}

/// Wire statuses 1 through 24, plus 0 and `u16::MAX`, which lie outside the named range 1 through 28, end a request as the table says: `Incomplete` whenever a fragment was handed out; before that a miss for `Missing` and `Expired`, pressure for the pressure statuses, and failure for the rest. The client reads 0 and `u16::MAX` as `InvalidRequest`; the test spells that status literally, so a decoding that maps either value to a status other than `InvalidRequest` fails the comparison.
#[test]
fn every_error_status_maps_to_its_outcome() {
    let crc = Crc32c::detect();
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let pool = super::packet::test_pool(4, 1).unwrap();
    let mut client = client(&releases, 1, 8, 8);
    for wire in (0..=24u16).chain([u16::MAX]) {
        let status = match wire {
            0 | u16::MAX => Status::InvalidRequest,
            _ => Status::from_wire(wire).expect("1 through 24 name statuses"),
        };
        let expected = |exposed: bool| match (wire, exposed) {
            (_, true) => Outcome::Incomplete(status),
            (1 | 2, false) => Outcome::Missing,
            (3..=10, false) => Outcome::Pressure(status),
            _ => Outcome::Failed(status),
        };
        for exposed in [false, true] {
            let id = client
                .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
                .unwrap();
            let get = last_sent(&mut client, 0);
            if exposed {
                let start = start_for(&get, 2 * 8192);
                client.start(SESSION, &start, 0);
                deliver(&mut client, &pool, crc, SESSION, &start, 0);
                drop(client.take(id).expect("fragment 0"));
            }
            let error = Header {
                kind: Kind::Error,
                status: wire,
                ..get
            };
            client.error(SESSION, &error);
            assert_eq!(
                client.outcome(id),
                Some(expected(exposed)),
                "status {wire} exposed {exposed}"
            );
            assert!(client.close(id), "an ERROR needs no CANCEL");
        }
    }
    assert_eq!(client.reserved(), 0);
}

/// Cancelling before any fragment was handed out fails the request `Cancelled`; exhausting the retries ends it `OwnerUnavailable` with a CANCEL `TimedOut`; a START above the GET's caps fails it `TooLarge` with a CANCEL `Cancelled`.
#[test]
fn cancels_exhaustion_and_oversize_starts_end_explicitly() {
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = Fetcher::new(
        FetchConfig {
            attempts: 1,
            ..FETCH
        },
        RequestTable::new(2, 1, 2),
        &releases,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    let cancels = |client: &mut Fetcher<'_>, now| {
        let mut cancels = Vec::new();
        client.poll(now, 4, |ask| {
            cancels.push((ask.header.kind, ask.header.status));
            true
        });
        cancels
    };
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    last_sent(&mut client, 0);
    client.cancel(id);
    assert_eq!(client.outcome(id), Some(Outcome::Failed(Status::Cancelled)));
    assert_eq!(decider(&client, id), Decider::Cancel);
    assert_eq!(
        cancels(&mut client, 0),
        [(Kind::Cancel, Status::Cancelled as u16)]
    );
    assert!(client.close(id));

    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    last_sent(&mut client, 0);
    client.tick(3_000);
    assert_eq!(
        cancels(&mut client, 3_000),
        [(Kind::Get, 0)],
        "the one retry"
    );
    // The budget's end waits twice the interval after the one retry.
    client.tick(9_000);
    assert_eq!(
        client.outcome(id),
        Some(Outcome::Failed(Status::OwnerUnavailable))
    );
    assert_eq!(
        cancels(&mut client, 9_000),
        [(Kind::Cancel, Status::TimedOut as u16)]
    );
    assert_eq!(
        decider(&client, id),
        Decider::Wait,
        "exhausted attempts end the client's wait"
    );
    assert!(client.close(id));

    let id = client
        .fetch(SESSION, [7; 32], 100, 1000, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    client.start(SESSION, &start_for(&get, 1001), 5_000);
    assert_eq!(client.outcome(id), Some(Outcome::Failed(Status::TooLarge)));
    assert_eq!(
        cancels(&mut client, 5_000),
        [(Kind::Cancel, Status::Cancelled as u16)]
    );
    let terminal = client.core.terminal(&client.requests, id).unwrap();
    assert_eq!(
        (terminal.decided_by, terminal.decided_us),
        (Decider::Cancel, 5_000),
        "the cap check cancels at the START's time"
    );
    let outcomes = client.report().outcomes;
    assert_eq!(
        (outcomes.cancelled, outcomes.timed_out, outcomes.total()),
        (2, 1, 3)
    );
    assert!(client.close(id));
}

/// A lease that outlives its request adds no grant to the request that reuses its slot, and stays reserved until dropped: with boxes for one window, a fetch is refused while the old lease is held and admitted after it drops.
#[test]
fn a_lease_outliving_its_request_credits_no_later_generation() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 1, 2, 2);
    let old = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    client.start(SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    let held = client.take(old).expect("fragment 0");
    client.cancel(old);
    last_sent(&mut client, 0);
    assert!(client.close(old));
    assert_eq!(client.reserved(), 1, "the held lease stays reserved");
    let narrow = Admitted {
        caps: Caps {
            slots: 8,
            window: 2,
        },
        ..SESSION
    };
    assert_eq!(
        client.fetch(narrow, [7; 32], 0, 1 << 20, 0, 1_000_000),
        Err(FetchPressure::Receive),
        "one box free, a window of two"
    );
    let one = Admitted {
        caps: Caps {
            slots: 8,
            window: 1,
        },
        ..SESSION
    };
    let new = client
        .fetch(one, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    assert_eq!(new.slot(), old.slot());
    let get = last_sent(&mut client, 0);
    assert_eq!(get.grant, 1);
    client.start(one, &start_for(&get, 4 * 8192), 0);
    drop(held);
    assert_eq!(
        client.reserved(),
        1,
        "the old lease dropped; the new window remains"
    );
    let mut grants = Vec::new();
    client.poll(0, 4, |ask| {
        grants.push(ask.header.grant);
        true
    });
    assert_eq!(
        grants,
        [1],
        "the old lease's drop granted the new request nothing"
    );
}

/// Ticks before the earliest timer change nothing, and a request admitted after a quiet tick folds its deadline and retry time into the bound, so it still times out and retries on schedule.
#[test]
fn timers_fold_into_quiet_ticks() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 2, 8);
    client.tick(0);
    let patient = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 20_000)
        .unwrap();
    assert_eq!(last_sent(&mut client, 0).kind, Kind::Get);
    client.tick(2_999);
    assert_eq!(client.poll(2_999, 4, |_| true), 0);
    client.tick(3_000);
    assert_eq!(last_sent(&mut client, 3_000).kind, Kind::Get);
    assert_eq!(client.report().get_retries, 1);
    let brief = client
        .fetch(SESSION, [8; 32], 0, 1 << 20, 3_000, 1_000)
        .unwrap();
    assert_eq!(last_sent(&mut client, 3_000).kind, Kind::Get);
    client.tick(4_000);
    assert_eq!(
        client.outcome(brief),
        Some(Outcome::Failed(Status::TimedOut))
    );
    assert_eq!(client.outcome(patient), None);
    assert_eq!(last_sent(&mut client, 4_000).kind, Kind::Cancel);
    assert!(client.close(brief));
    // The second retry waits twice the interval.
    client.tick(8_999);
    assert_eq!(client.poll(8_999, 4, |_| true), 0);
    client.tick(9_000);
    assert_eq!(last_sent(&mut client, 9_000).kind, Kind::Get);
    assert_eq!(client.report().get_retries, 2);
    client.tick(20_000);
    assert_eq!(
        client.outcome(patient),
        Some(Outcome::Failed(Status::TimedOut))
    );
}

/// A fragment held above the base opens a gap that queues nothing until it outlasts [`GAP_WAIT_US`], so reordered fragments fill it silently; a gap that outlasts the wait queues a gap ACK carrying the receipt mask, and one more after each [`GAP_ACK_US`], spending no retry; the fragment that fills the hole advances the base past every held fragment, closes the gap, and the ACK that follows carries an empty mask.
#[test]
fn a_gap_queues_acks_with_the_receipt_mask_once_it_outlasts_the_wait() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 8, 16);
    client.tick(0);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 6 * 8192);
    client.start(SESSION, &start, 0);
    let bound = last_sent(&mut client, 0);
    assert_eq!((bound.kind, bound.index, bound.offset), (Kind::Ack, 0, 0));
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    let first = last_sent(&mut client, 0);
    assert_eq!((first.kind, first.index, first.offset), (Kind::Ack, 1, 0));
    // Fragment 2 arrives before 1: a gap opens and closes within the wait, and no ACK names it.
    deliver(&mut client, &pool, crc, SESSION, &start, 2);
    assert_eq!(client.report().reordered, 0);
    client.tick(GAP_WAIT_US - 1);
    assert_eq!(
        client.poll(GAP_WAIT_US - 1, 4, |_| true),
        0,
        "a young gap is silent"
    );
    deliver(&mut client, &pool, crc, SESSION, &start, 1);
    assert_eq!(client.report().reordered, 1);
    let closed = last_sent(&mut client, GAP_WAIT_US - 1);
    assert_eq!(
        (closed.index, closed.offset),
        (3, 0),
        "the gap closed before the wait"
    );
    client.tick(GAP_WAIT_US + GAP_ACK_US);
    assert_eq!(client.poll(GAP_WAIT_US + GAP_ACK_US, 4, |_| true), 0);
    assert_eq!(client.report().gap_acks, 0);
    // Fragments 4 and 5 arrive while 3 is missing, and the gap outlasts the wait.
    let opened = 2 * GAP_ACK_US;
    deliver_at(&mut client, &pool, crc, SESSION, &start, 4, opened);
    deliver_at(&mut client, &pool, crc, SESSION, &start, 5, opened);
    client.tick(opened + GAP_WAIT_US - 1);
    assert_eq!(client.poll(opened + GAP_WAIT_US - 1, 4, |_| true), 0);
    client.tick(opened + GAP_WAIT_US);
    let gap = last_sent(&mut client, opened + GAP_WAIT_US);
    assert_eq!(
        (gap.kind, gap.index, gap.offset),
        (Kind::Ack, 3, 0b11),
        "fragments 4 and 5 held above base 3"
    );
    assert_eq!(client.report().gap_acks, 1);
    let again_at = opened + GAP_WAIT_US + GAP_ACK_US;
    client.tick(again_at - 1);
    assert_eq!(client.poll(again_at - 1, 4, |_| true), 0);
    client.tick(again_at);
    let again = last_sent(&mut client, again_at);
    assert_eq!(
        (again.index, again.offset),
        (3, 0b11),
        "the gap outlasted its interval"
    );
    assert_eq!(client.report().gap_acks, 2);
    assert_eq!(client.report().ack_retries, 0, "a gap ACK spends no retry");
    deliver_at(&mut client, &pool, crc, SESSION, &start, 3, again_at + 10);
    let filled = last_sent(&mut client, again_at + 10);
    assert_eq!(
        (filled.index, filled.offset),
        (6, 0),
        "every held fragment acknowledged"
    );
    while client.take(id).is_some() {}
    assert_eq!(client.outcome(id), None);
}

/// When START binds held fragments above a missing base fragment, the gap opens at the START, and its gap ACK is due [`GAP_WAIT_US`] later.
#[test]
fn a_start_that_binds_held_data_above_a_missing_base_opens_the_gap() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 8, 16);
    client.tick(0);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    deliver(&mut client, &pool, crc, SESSION, &start, 1);
    deliver(&mut client, &pool, crc, SESSION, &start, 2);
    let bound_at = 100;
    client.start(SESSION, &start, bound_at);
    let bound = last_sent(&mut client, bound_at);
    assert_eq!((bound.kind, bound.index, bound.offset), (Kind::Ack, 0, 0));
    assert_eq!(
        client.deadline(),
        Some(bound_at + GAP_WAIT_US),
        "the gap opened at the START"
    );
    client.tick(bound_at + GAP_WAIT_US);
    let gap = last_sent(&mut client, bound_at + GAP_WAIT_US);
    assert_eq!(
        (gap.kind, gap.index, gap.offset),
        (Kind::Ack, 0, 0b11),
        "fragments 1 and 2 held above base 0"
    );
    assert_eq!(client.report().gap_acks, 1);
    assert_eq!(client.outcome(id), None);
}

/// A gap ACK the transport refuses keeps its receipt mask: `unsend` puts the ACK back with the mask it carried, so the next poll names the holes again.
#[test]
fn an_unsent_gap_ack_keeps_its_receipt_mask() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 8, 16);
    client.tick(0);
    client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    client.start(SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    assert_eq!(last_sent(&mut client, 0).index, 1);
    deliver(&mut client, &pool, crc, SESSION, &start, 2);
    client.tick(GAP_WAIT_US);
    let mut asked = None;
    client.poll(GAP_WAIT_US, 4, |ask| {
        asked = Some((ask.header, Asked::from(&ask)));
        true
    });
    let (gap, frame) = asked.expect("a gap ACK");
    assert_eq!((gap.kind, gap.index, gap.offset), (Kind::Ack, 1, 0b1));
    client.unsend(frame);
    let again = last_sent(&mut client, GAP_WAIT_US);
    assert_eq!(
        (again.kind, again.index, again.offset),
        (Kind::Ack, 1, 0b1),
        "the put-back ACK carries the mask"
    );
    assert_eq!(
        client.report().gap_acks,
        1,
        "the put-back ACK is the same gap ACK"
    );
}

/// START drops held fragments naming another manifest; when none survive above the base, no gap opens, and the request waits on its retry alone.
#[test]
fn a_start_that_drops_every_held_fragment_opens_no_gap() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 8, 16);
    client.tick(0);
    client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    let other = Header {
        allocation: start.allocation + 1,
        ..start
    };
    deliver(&mut client, &pool, crc, SESSION, &other, 2);
    let bound_at = 100;
    client.start(SESSION, &start, bound_at);
    assert_eq!(
        client.report().dropped,
        1,
        "the other manifest's fragment dropped"
    );
    let bound = last_sent(&mut client, bound_at);
    assert_eq!((bound.kind, bound.index, bound.offset), (Kind::Ack, 0, 0));
    assert_eq!(
        client.deadline(),
        Some(bound_at + FETCH.retry_us),
        "no gap: the next timer is the retry"
    );
    client.tick(bound_at + GAP_WAIT_US);
    assert_eq!(client.poll(bound_at + GAP_WAIT_US, 4, |_| true), 0);
    assert_eq!(client.report().gap_acks, 0);
    client.check_timers();
}

/// Requests admitted one microsecond apart have timers that rise in slot order, so a batch that ends or advances them in slot order removes the least timer at every step. The batch and the deadline read after it scan at most twice the slot count.
#[test]
fn many_timer_changes_scan_the_timer_index_a_bounded_number_of_times() {
    const SLOTS: u32 = 4096;
    fn key(at: usize) -> [u8; 32] {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(at as u64).to_le_bytes());
        key
    }
    let session = Admitted {
        caps: Caps {
            slots: SLOTS,
            window: 1,
        },
        ..SESSION
    };
    type Change = fn(&mut Fetcher<'_>, Admitted, &[RequestId]);
    let changes: [(&str, Change); 5] = [
        ("cancel_all", |client, _, _| client.cancel_all()),
        ("end_session", |client, session, _| {
            client.end_session(session.epoch, Status::SessionMismatch);
        }),
        ("a tick past every deadline", |client, _, _| {
            client.tick(u64::from(SLOTS) + 1_000_000);
        }),
        ("one ERROR each", |client, session, ids| {
            for (at, &id) in ids.iter().enumerate() {
                let error = Header {
                    status: Status::Missing as u16,
                    ..header(Kind::Error, client.wire(id).unwrap(), key(at))
                };
                client.error(session, &error);
            }
        }),
        ("one START each", |client, session, ids| {
            for (at, &id) in ids.iter().enumerate() {
                let get = header(Kind::Get, client.wire(id).unwrap(), key(at));
                client.start(session, &start_for(&get, 8192), 10_000);
            }
        }),
    ];
    for (change, apply) in changes {
        let releases = Releases::new(SLOTS, &mut EngineBudget::new(1 << 20)).unwrap();
        let mut client = client(&releases, SLOTS, 1, SLOTS);
        let ids: Vec<RequestId> = (0..SLOTS as usize)
            .map(|at| {
                client
                    .fetch(session, key(at), 0, 1 << 20, at as u64, 1_000_000)
                    .unwrap()
            })
            .collect();
        take_timer_scans();
        apply(&mut client, session, &ids);
        let _ = client.deadline();
        let scans = take_timer_scans();
        assert!(
            scans <= 2 * SLOTS as usize,
            "{change}: {scans} timer slots scanned for {SLOTS} requests"
        );
        client.check_timers();
    }
}

/// Closing a request in the middle of the live list keeps the others' timers, and a request reusing its slot gets its own.
#[test]
fn timers_survive_closing_a_request_between_others() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 2, 8);
    let ids: Vec<RequestId> = (1..=3u8)
        .map(|n| {
            client
                .fetch(SESSION, [n; 32], 0, 1 << 20, 0, 10_000)
                .unwrap()
        })
        .collect();
    client.poll(0, 4, |_| true);
    client.cancel(ids[1]);
    client.poll(0, 4, |_| true);
    assert!(client.close(ids[1]));
    let reused = client
        .fetch(SESSION, [4; 32], 0, 1 << 20, 5_000, 1_000)
        .unwrap();
    assert_eq!(reused.slot(), ids[1].slot());
    client.tick(6_000);
    assert_eq!(
        client.outcome(reused),
        Some(Outcome::Failed(Status::TimedOut))
    );
    assert_eq!(
        (client.outcome(ids[0]), client.outcome(ids[2])),
        (None, None)
    );
    client.tick(10_000);
    assert_eq!(
        (client.outcome(ids[0]), client.outcome(ids[2])),
        (
            Some(Outcome::Failed(Status::TimedOut)),
            Some(Outcome::Failed(Status::TimedOut))
        )
    );
    assert_eq!(client.poll(10_000, 4, |_| true), 3, "three CANCELs");
    assert!(client.close(reused) && client.close(ids[0]) && client.close(ids[2]));
    assert_eq!(client.requests().census().active, 0);
}

/// Each due frame is sent once, in slot order from the slot after the last frame poll offered, within the poll's budget, and a refused send leaves the frame due for the next poll.
#[test]
fn poll_sends_each_due_frame_once_in_order() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 2, 8);
    let first = client
        .fetch(SESSION, [1; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let second = client
        .fetch(SESSION, [2; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let (first_wire, second_wire) = (client.wire(first).unwrap(), client.wire(second).unwrap());
    let mut sent: Vec<(Kind, u64)> = Vec::new();
    let record = |sent: &mut Vec<(Kind, u64)>, client: &mut Fetcher<'_>, budget| {
        client.poll(0, budget, |ask| {
            sent.push((ask.header.kind, ask.header.request));
            true
        })
    };
    assert_eq!(record(&mut sent, &mut client, 1), 1);
    assert_eq!(sent, [(Kind::Get, first_wire)]);
    assert_eq!(client.poll(0, 4, |_| false), 0);
    assert_eq!(record(&mut sent, &mut client, 4), 1);
    assert_eq!(sent, [(Kind::Get, first_wire), (Kind::Get, second_wire)]);
    assert_eq!(client.poll(0, 4, |_| true), 0);
    client.cancel(second);
    client.cancel(first);
    sent.clear();
    assert_eq!(record(&mut sent, &mut client, 4), 2);
    assert_eq!(
        sent,
        [(Kind::Cancel, first_wire), (Kind::Cancel, second_wire)],
        "the cursor passed the second request's slot, so the round wraps to the first"
    );
    assert!(client.close(first));
    assert!(client.close(second));
}

/// The configured window is clamped to the protocol's `1..=4096`, and the initial grant is the smaller of it and the session's window.
#[test]
fn windows_clamp_to_the_protocol_range() {
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let wide = Admitted {
        caps: Caps {
            slots: 8,
            window: 4096,
        },
        ..SESSION
    };
    for (window, grant) in [(0, 1), (3, 3), (4096, 4096), (5000, 4096)] {
        let mut client = client(&releases, 1, window, 8192);
        client
            .fetch(wide, [7; 32], 0, 1 << 20, 0, 1_000_000)
            .unwrap();
        assert_eq!(last_sent(&mut client, 0).grant, grant, "window {window}");
    }
}

/// Hands the encoded DATA `fragment` to `client` in a lease of `pool`.
fn feed<'p>(client: &mut Fetcher<'p>, pool: &'p PacketPool, (header, bytes): &(Header, Vec<u8>)) {
    let lease = lease_of(pool, bytes);
    client.data(SESSION, header, lease, 0);
}

/// A release board with fewer slots than the request table is refused at construction, with the budget unchanged.
#[test]
fn a_short_release_board_is_refused() {
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut budget = EngineBudget::new(1 << 24);
    let refused = Fetcher::new(FETCH, RequestTable::new(4, 1, 4), &releases, &mut budget);
    assert!(matches!(
        refused,
        Err(FetchCoreError::Board { slots: 4, board: 2 })
    ));
    assert_eq!(budget.used(), 0);
}

/// A pool of eight receive boxes, two of them reserved for control.
fn pool8() -> PacketPool<'static> {
    super::packet::test_pool(8, 2).unwrap()
}

/// A lease of `pool` holding the received datagram `bytes`.
pub(super) fn lease_of<'p>(pool: &'p PacketPool<'_>, bytes: &[u8]) -> PacketLease<'p> {
    let mut lease = pool.acquire(PacketUse::Control).unwrap();
    lease.buffer_mut()[..bytes.len()].copy_from_slice(bytes);
    lease.set_len(bytes.len());
    lease
}

/// A `Wanted` handle stands for one turn's answer: `data` holds the fragment it names when the request state is unchanged, and drops the fragment, counting it, when the handle outlived its request or the base moved past its index. A frame `wants` refuses routes again in `data` and is dropped the same way.
#[test]
fn a_wanted_handle_holds_only_under_the_state_it_was_answered_for() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = Fetcher::new(
        FETCH,
        RequestTable::new(2, 1, 2),
        &releases,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 3 * 8192);
    client.start(SESSION, &start, 0);
    let fragment = |index: u32| Header {
        kind: Kind::Data,
        index,
        offset: u64::from(index) * 8192,
        ..start
    };
    let bytes = |index: u32| datagram(crc, fragment(index), 3, 1, [&[index as u8; 8192], &[]]);

    let wanted = client
        .core
        .wants(&client.requests, SESSION, &fragment(1))
        .expect("fragment 1 fits the empty window");
    let dropped = client.report().dropped;
    client.core.data(
        &mut client.requests,
        SESSION,
        &fragment(1),
        Some(wanted),
        lease_of(&pool, &bytes(1)),
        0,
    );
    assert_eq!(pool.report().free, 7, "the wanted fragment is held");
    assert_eq!(client.report().dropped, dropped);

    // The base moves past index 1 once fragment 0 arrives; a handle answered before that places no entry.
    let stale = client
        .core
        .wants(&client.requests, SESSION, &fragment(0))
        .expect("fragment 0 fits");
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    assert_eq!(pool.report().free, 6);
    client.core.data(
        &mut client.requests,
        SESSION,
        &fragment(0),
        Some(stale),
        lease_of(&pool, &bytes(0)),
        0,
    );
    assert_eq!(
        pool.report().free,
        6,
        "a fragment below the base is dropped"
    );
    assert_eq!(client.report().dropped, dropped + 1);

    // Without a handle, `data` routes the frame itself and refuses the duplicate the same way.
    assert!(
        client
            .core
            .wants(&client.requests, SESSION, &fragment(1))
            .is_none(),
        "the entry is taken"
    );
    client.core.data(
        &mut client.requests,
        SESSION,
        &fragment(1),
        None,
        lease_of(&pool, &bytes(1)),
        0,
    );
    assert_eq!(pool.report().free, 6);
    assert_eq!(client.report().dropped, dropped + 2);

    // A handle that outlives its request names a released generation and holds nothing.
    let outlived = client
        .core
        .wants(&client.requests, SESSION, &fragment(2))
        .expect("fragment 2 fits");
    client.error(
        SESSION,
        &Header {
            kind: Kind::Error,
            status: Status::DeviceError as u16,
            ..get
        },
    );
    drop(client.take(id));
    drop(client.take(id));
    assert!(client.close(id));
    assert_eq!(pool.report().free, 8);
    client.core.data(
        &mut client.requests,
        SESSION,
        &fragment(2),
        Some(outlived),
        lease_of(&pool, &bytes(2)),
        0,
    );
    assert_eq!(
        pool.report().free,
        8,
        "nothing is held for a closed request"
    );
    assert_eq!(client.report().dropped, dropped + 3);
    assert_eq!(client.requests().census().live(), 0);
}

fn started(client: &mut Fetcher<'_>, total: u64) -> (RequestId, Header) {
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let wire = client.wire(id).unwrap();
    let mut get = None;
    client.poll(0, 4, |ask| {
        get = get.or((ask.header.request == wire).then_some(ask.header));
        true
    });
    let get = get.expect("the GET");
    client.start(SESSION, &start_for(&get, total), 0);
    (id, get)
}

fn fragment_of(start: &Header, index: u32) -> Header {
    Header {
        kind: Kind::Data,
        index,
        offset: u64::from(index) * 8192,
        ..*start
    }
}

/// When a request ends or binds another manifest after `wants` returns its handle, `data` drops the fragment, increments `dropped`, and returns the fragment's lease to the pool.
#[test]
fn a_wanted_handle_holds_nothing_its_request_no_longer_fits() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();

    let mut ended = client(&releases, 2, 8, 16);
    let (id, get) = started(&mut ended, 3 * 8192);
    let fragment = fragment_of(&start_for(&get, 3 * 8192), 0);
    let wanted = ended
        .core
        .wants(&ended.requests, SESSION, &fragment)
        .expect("fragment 0 fits the empty window");
    ended.error(
        SESSION,
        &Header {
            kind: Kind::Error,
            status: Status::DeviceError as u16,
            ..get
        },
    );
    let dropped = ended.report().dropped;
    ended.core.data(
        &mut ended.requests,
        SESSION,
        &fragment,
        Some(wanted),
        lease_of(&pool, &datagram(crc, fragment, 3, 1, [&[0; 8192], &[]])),
        0,
    );
    assert_eq!(pool.report().free, 8, "a decided request holds nothing");
    assert_eq!(ended.report().dropped, dropped + 1);
    assert!(
        ended.take(id).is_none(),
        "a decided request hands out nothing"
    );
    ended.poll(0, 4, |_| true);
    assert!(ended.close(id));
    drop(ended);

    let mut rebound = client(&releases, 2, 8, 16);
    let id = rebound
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut rebound, 0);
    let other = fragment_of(
        &Header {
            allocation: 10,
            ..start_for(&get, 3 * 8192)
        },
        0,
    );
    let wanted = rebound
        .core
        .wants(&rebound.requests, SESSION, &other)
        .expect("a fragment before START fits any manifest");
    rebound.start(SESSION, &start_for(&get, 3 * 8192), 0);
    let dropped = rebound.report().dropped;
    rebound.core.data(
        &mut rebound.requests,
        SESSION,
        &other,
        Some(wanted),
        lease_of(&pool, &datagram(crc, other, 3, 1, [&[0; 8192], &[]])),
        0,
    );
    assert_eq!(
        pool.report().free,
        8,
        "a fragment of another manifest is dropped"
    );
    assert_eq!(rebound.report().dropped, dropped + 1);
    assert!(rebound.take(id).is_none());
}

/// `data` holds a fragment by a `Wanted` handle only when the frame names the handle's request; a frame naming another request is dropped and counted under `dropped`.
#[test]
fn a_wanted_handle_reaches_only_the_request_its_frame_names() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 2, 8, 16);
    let (first, first_get) = started(&mut client, 3 * 8192);
    let (second, second_get) = started(&mut client, 3 * 8192);
    let wanted = client
        .core
        .wants(
            &client.requests,
            SESSION,
            &fragment_of(&start_for(&first_get, 3 * 8192), 0),
        )
        .expect("the first request's fragment 0 fits");
    let foreign = fragment_of(&start_for(&second_get, 3 * 8192), 0);
    let dropped = client.report().dropped;
    client.core.data(
        &mut client.requests,
        SESSION,
        &foreign,
        Some(wanted),
        lease_of(&pool, &datagram(crc, foreign, 3, 1, [&[0; 8192], &[]])),
        0,
    );
    assert_eq!(pool.report().free, 8, "the foreign frame is dropped");
    assert_eq!(client.report().dropped, dropped + 1);
    assert!(
        client.take(first).is_none(),
        "the handle's request holds nothing"
    );
    assert!(
        client.take(second).is_none(),
        "the frame's request held nothing"
    );
}

/// A failed request returns its received but untaken fragments to their pool when it ends, before it closes; a resent matching START queues the ACK again and leaves the retry count spent, so the budget still ends a silent request.
#[test]
fn failure_frees_untaken_fragments_and_a_resent_start_keeps_the_retry_count() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = Fetcher::new(
        FetchConfig {
            attempts: 1,
            ..FETCH
        },
        RequestTable::new(2, 1, 2),
        &releases,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    client.start(SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 1);
    assert_eq!(pool.report().free, 6);
    client.error(
        SESSION,
        &Header {
            kind: Kind::Error,
            status: Status::DeviceError as u16,
            ..get
        },
    );
    assert_eq!(pool.report().free, 8, "freed when the request ended");
    assert!(client.close(id));

    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    client.start(SESSION, &start, 0);
    last_sent(&mut client, 0);
    client.tick(3_000);
    let mut kinds = Vec::new();
    client.poll(3_000, 4, |ask| {
        kinds.push(ask.header.kind);
        true
    });
    assert_eq!(kinds, [Kind::Ack], "the one retry");
    client.start(SESSION, &start, 4_000);
    kinds.clear();
    client.poll(4_000, 4, |ask| {
        kinds.push(ask.header.kind);
        true
    });
    assert_eq!(kinds, [Kind::Ack], "the resent START queued the ACK");
    // The resent START made no progress, so the end waits twice the interval.
    client.tick(8_999);
    assert_eq!(client.outcome(id), None);
    client.tick(9_000);
    assert_eq!(
        client.outcome(id),
        Some(Outcome::Failed(Status::OwnerUnavailable))
    );
}

/// Leases that outlive their core stay reserved on the board: a later core over the same board counts their boxes, and their release grants its requests nothing; a second live core over the board is refused, and so is a core whose boxes hold less than one window.
#[test]
fn leases_outliving_their_core_credit_no_later_core() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut first = client(&releases, 1, 2, 2);
    let id = first
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut first, 0);
    let start = start_for(&get, 4 * 8192);
    first.start(SESSION, &start, 0);
    deliver(&mut first, &pool, crc, SESSION, &start, 0);
    let held = first.take(id).expect("fragment 0");
    drop(first);
    let mut second = client(&releases, 1, 2, 2);
    assert_eq!(second.reserved(), 1, "the outliving lease stays reserved");
    let one = Admitted {
        caps: Caps {
            slots: 8,
            window: 1,
        },
        ..SESSION
    };
    second
        .fetch(one, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut second, 0);
    second.start(one, &start_for(&get, 4 * 8192), 0);
    drop(held);
    let mut grants = Vec::new();
    second.poll(0, 4, |ask| {
        grants.push(ask.header.grant);
        true
    });
    assert_eq!(
        grants,
        [1],
        "the old lease's drop granted the later core nothing"
    );
    assert_eq!(second.reserved(), 1);
    let short = Fetcher::new(
        FetchConfig {
            window: 4,
            boxes: 3,
            ..FETCH
        },
        RequestTable::new(1, 1, 1),
        &releases,
        &mut EngineBudget::new(1 << 20),
    );
    assert!(
        matches!(short, Err(FetchCoreError::BoardInUse)),
        "the second core is live"
    );
    drop(second);
    let short = Fetcher::new(
        FetchConfig {
            window: 4,
            boxes: 3,
            ..FETCH
        },
        RequestTable::new(1, 1, 1),
        &releases,
        &mut EngineBudget::new(1 << 20),
    );
    assert!(matches!(short, Err(FetchCoreError::Boxes)));
}

#[test]
fn a_namespace_serves_one_fetch_core() {
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut first = client(&releases, 2, 2, 4);
    let mut budget = EngineBudget::new(1 << 20);
    let second = FetchCore::new(FETCH, &mut first.requests, &mut budget);
    assert!(matches!(second, Err(FetchCoreError::Paired)));
    assert_eq!(budget, EngineBudget::new(1 << 20));
    first
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
}

#[test]
#[should_panic(expected = "a fetch core runs over the namespace it was built from")]
fn a_core_kept_past_its_namespace_refuses_a_successor() {
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let Fetcher { mut core, requests } = client(&releases, 2, 2, 4);
    drop(requests);
    let mut successor = ClientRequests::new(
        RequestTable::new(2, 1, 2),
        &releases,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let _ = core.fetch(
        &mut successor,
        SESSION,
        [7; 32],
        FetchLimits {
            metadata_cap: 0,
            body_cap: 1 << 20,
            wait_us: 1_000_000,
            intended_us: 0,
        },
        0,
    );
}

#[test]
#[should_panic(expected = "a fetch core runs over the namespace it was built from")]
fn a_core_refuses_another_boards_namespace() {
    let board = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let other = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut ours = client(&board, 2, 2, 4);
    let mut theirs = client(&other, 2, 2, 4);
    ours.core.tick(&mut theirs.requests, 0);
}

#[test]
#[should_panic(expected = "a fetch core runs over the namespace it was built from")]
fn a_kept_core_hands_out_nothing_from_a_successor() {
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let Fetcher { mut core, requests } = client(&releases, 2, 2, 4);
    drop(requests);
    let mut successor = client(&releases, 2, 2, 4);
    let id = successor
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let _ = core.take(&mut successor.requests, id);
}

#[test]
fn every_namespace_taking_method_refuses_another_namespace() {
    let pool = pool8();
    let board = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let other = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut ours = client(&board, 2, 2, 4);
    let mut theirs = client(&other, 2, 2, 4);
    cross_every_call(&pool, &mut ours, &mut theirs);
}

type CrossedCall<'p, 'c> = Box<dyn FnOnce(&mut FetchCore<'p>, &mut ClientRequests<'p>) + 'c>;

/// Calls each namespace-taking method of `ours.core` with `theirs.requests`.
fn cross_every_call<'p>(
    pool: &'p PacketPool<'_>,
    ours: &mut Fetcher<'p>,
    theirs: &mut Fetcher<'p>,
) {
    let id = theirs
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let mut ask = None;
    theirs.poll(0, 4, |sent| {
        ask = Some(sent);
        true
    });
    let ask = ask.expect("the GET");
    let start = start_for(&ask.header, 4 * 8192);
    let calls: [(&str, CrossedCall<'p, '_>); 16] = [
        (
            "fetch",
            Box::new(|core, requests| {
                let limits = FetchLimits {
                    metadata_cap: 0,
                    body_cap: 1 << 20,
                    wait_us: 1_000_000,
                    intended_us: 0,
                };
                let _ = core.fetch(requests, SESSION, [7; 32], limits, 0);
            }),
        ),
        (
            "start",
            Box::new(|core, requests| core.start(requests, SESSION, &start, 0)),
        ),
        (
            "wants",
            Box::new(|core, requests| {
                core.wants(requests, SESSION, &start);
            }),
        ),
        (
            "data",
            Box::new(|core, requests| {
                core.data(requests, SESSION, &start, None, lease_of(pool, &[0; 64]), 0)
            }),
        ),
        (
            "complete",
            Box::new(|core, requests| core.complete(requests, SESSION, &start)),
        ),
        (
            "error",
            Box::new(|core, requests| core.error(requests, SESSION, &start)),
        ),
        (
            "cancel",
            Box::new(|core, requests| core.cancel(requests, id)),
        ),
        (
            "take",
            Box::new(|core, requests| {
                let _ = core.take(requests, id);
            }),
        ),
        (
            "outcome",
            Box::new(|core, requests| {
                let _ = core.outcome(requests, id);
            }),
        ),
        (
            "close",
            Box::new(|core, requests| {
                let _ = core.close(requests, id);
            }),
        ),
        ("tick", Box::new(|core, requests| core.tick(requests, 0))),
        (
            "due",
            Box::new(|core, requests| {
                let _ = core.due(requests);
            }),
        ),
        (
            "deadline",
            Box::new(|core, requests| {
                let _ = core.deadline(requests);
            }),
        ),
        (
            "end_session",
            Box::new(|core, requests| {
                core.end_session(requests, SESSION.epoch, Status::SessionMismatch)
            }),
        ),
        (
            "cancel_all",
            Box::new(|core, requests| core.cancel_all(requests)),
        ),
        (
            "unsend",
            Box::new(|core, requests| core.unsend(requests, Asked::from(&ask))),
        ),
    ];
    for (name, call) in calls {
        let crossed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            call(&mut ours.core, &mut theirs.requests)
        }));
        assert_eq!(
            crossed
                .err()
                .and_then(|payload| payload.downcast_ref::<&str>().copied()),
            Some("a fetch core runs over the namespace it was built from"),
            "{name} accepted another namespace"
        );
    }
    let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ours.core.poll(&mut theirs.requests, 0, 4, |_| true)
    }));
    assert_eq!(
        polled
            .err()
            .and_then(|payload| payload.downcast_ref::<&str>().copied()),
        Some("a fetch core runs over the namespace it was built from"),
        "poll accepted another namespace"
    );
    assert_eq!(theirs.reserved(), 2, "the crossed calls changed nothing");
    assert_eq!(theirs.outcome(id), None);
}

#[test]
fn each_held_lease_charges_one_orphan_through_retirement_destruction_and_replacement() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut first = client(&releases, 2, 2, 4);
    let mut leases = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let id = first
            .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
            .unwrap();
        let wire = first.wire(id).unwrap();
        let mut get = None;
        first.poll(0, 4, |ask| {
            get = get.or((ask.header.request == wire).then_some(ask.header));
            true
        });
        let start = start_for(&get.expect("the GET"), 4 * 8192);
        first.start(SESSION, &start, 0);
        deliver(&mut first, &pool, crc, SESSION, &start, 0);
        leases.push(first.take(id).expect("fragment 0"));
        ids.push(id);
    }
    first.cancel(ids[0]);
    first.poll(0, 4, |_| true);
    assert!(first.close(ids[0]));
    assert_eq!(first.reserved(), 2 + 1, "the retired request's lease");
    drop(first);
    let second = client(&releases, 2, 2, 4);
    assert_eq!(second.reserved(), 2, "one charge for each held lease");
    for lease in &leases {
        assert_eq!(lease.bytes(), &[0; 8192]);
    }
    drop(leases.pop());
    assert_eq!(second.reserved(), 1);
    drop(leases.pop());
    assert_eq!(second.reserved(), 0);
}

fn owner_of(slots: u32) -> Core<Chunk> {
    Core::new(
        ServeConfig { slots, ..SERVE },
        RequestTable::new(8, 1, 8),
        1,
        16,
        0,
        4,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap()
}

/// The owner indexes wire slots per client, so every GET names a slot below its session's negotiated cap, and a request past the cap is refused locally until one closes.
#[test]
fn wire_slots_stay_within_each_sessions_slot_cap() {
    let one = |peer| Admitted {
        peer: PeerId(peer),
        caps: Caps {
            slots: 1,
            window: 8,
        },
        ..SESSION
    };
    let releases = Releases::new(2, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut spread = Fetcher::new(
        FETCH,
        RequestTable::new(2, 2, 1),
        &releases,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    let mut owners = [owner_of(1), owner_of(1)];
    let ids: Vec<RequestId> = (0..2u16)
        .map(|peer| {
            spread
                .fetch(one(peer), [peer as u8 + 1; 32], 0, 1 << 20, 0, 1_000_000)
                .unwrap()
        })
        .collect();
    let mut gets = Vec::new();
    spread.poll(0, 4, |ask| {
        gets.push((ask.peer, ask.header));
        true
    });
    assert_eq!(gets.len(), 2);
    for (peer, get) in &gets {
        assert!(
            matches!(
                owners[usize::from(peer.0)].get(one(0), get, 0),
                GetOutcome::Read { .. }
            ),
            "owner {} takes request {:#x}",
            peer.0,
            get.request
        );
    }
    // The forged slot tests whether an out-of-range lookup can cross peer boundaries.
    let (_, second) = gets[1];
    spread.error(
        one(0),
        &Header {
            kind: Kind::Error,
            status: Status::Missing as u16,
            request: second.request | 1 << 48,
            ..second
        },
    );
    assert_eq!(
        spread.outcome(ids[1]),
        None,
        "a slot past the width names nothing"
    );

    let two = Admitted {
        caps: Caps {
            slots: 2,
            window: 8,
        },
        ..SESSION
    };
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 8, 64);
    let mut owner = owner_of(2);
    let first = client
        .fetch(two, [1; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    client
        .fetch(two, [2; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    assert!(
        matches!(
            client.fetch(two, [3; 32], 0, 1 << 20, 0, 1_000_000),
            Err(FetchPressure::Identity(IdentityPressure::Requests(
                RequestPressure::Peer
            )))
        ),
        "the owner holds two of this client's requests"
    );
    let mut gets = Vec::new();
    client.poll(0, 4, |ask| {
        gets.push(ask.header);
        true
    });
    for get in &gets {
        assert!(matches!(owner.get(two, get, 0), GetOutcome::Read { .. }));
    }
    client.cancel(first);
    let cancel = last_sent(&mut client, 0);
    owner.cancel(two, &cancel, 0);
    owner.release_drained(|_| true);
    assert!(client.close(first));
    client
        .fetch(two, [3; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    assert!(
        matches!(owner.get(two, &get, 0), GetOutcome::Read { .. }),
        "the closed request's wire slot serves the next"
    );
}

/// A core rebuilt over a used board sends request IDs the earlier core never sent, so an owner that still tracks the earlier IDs in the same session starts a read for the new request.
#[test]
fn a_rebuilt_core_sends_request_ids_its_session_never_carried() {
    let mut owner = owner_of(8);
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut first = client(&releases, 1, 8, 8);
    let id = first
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let old = last_sent(&mut first, 0);
    let GetOutcome::Read { id: read, .. } = owner.get(SESSION, &old, 0) else {
        panic!("a new request");
    };
    owner.read_refused(read, Status::Missing, 0);
    owner.poll(0, 4, |frames| {
        frames
            .map(|frame| first.error(SESSION, &frame.header))
            .count()
    });
    assert_eq!(first.outcome(id), Some(Outcome::Missing));
    assert!(first.close(id));
    owner.release_drained(|_| true);
    drop(first);
    let mut second = client(&releases, 1, 8, 8);
    second
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let new = last_sent(&mut second, 0);
    let outcome = owner.get(SESSION, &new, 0);
    assert!(
        matches!(outcome, GetOutcome::Read { .. }),
        "the owner serves the new request, not the earlier one's cached Missing: {outcome:?}"
    );
    assert_ne!(new.request, old.request);
}

/// The board keeps its wire generations across core replacement, and exhaustion refuses later fetches before they reserve anything.
#[test]
fn a_board_past_its_last_wire_generation_refuses_fetches() {
    let releases = Releases::with_generation_limit(1, 1, &mut EngineBudget::new(1 << 20)).unwrap();
    let end = |client: &mut Fetcher<'_>, id| {
        client.cancel(id);
        client.poll(0, 4, |_| true);
        assert!(client.close(id));
    };
    let mut first = client(&releases, 1, 8, 8);
    let id = first
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    end(&mut first, id);
    drop(first);
    let mut second = client(&releases, 1, 8, 8);
    let id = second
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    assert_eq!(
        RequestId::from_wire(second.wire(id).unwrap()).generation(),
        1
    );
    end(&mut second, id);
    assert_eq!(
        second.fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000),
        Err(FetchPressure::Identity(IdentityPressure::Generations))
    );
    assert_eq!(second.reserved(), 0);
    assert_eq!(second.requests().census().active, 0);
}

/// A board of the actual width, started at its last wire generation, `GENERATION_LIMIT - 1`, issues that generation once; after the request ends the next fetch is refused for generations, holding nothing.
#[test]
fn a_board_at_its_actual_last_wire_generation_issues_it_once_then_refuses() {
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    releases.start_wire_at(GENERATION_LIMIT - 1);
    let mut client = client(&releases, 1, 8, 8);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let wire = RequestId::from_wire(client.wire(id).unwrap());
    assert_eq!(wire.generation(), GENERATION_LIMIT - 1);
    client.cancel(id);
    client.poll(0, 4, |_| true);
    assert!(client.close(id));
    assert_eq!(
        client.fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000),
        Err(FetchPressure::Identity(IdentityPressure::Generations))
    );
    assert_eq!(client.reserved(), 0);
    assert_eq!(client.requests().census().active, 0);
}

/// A clock jump of half the `u64` range between two fetches advances no wire generation: the second fetch carries the generation after the first.
#[test]
fn a_clock_jump_advances_no_wire_generation() {
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 1, 8, 8);
    let first = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let before = RequestId::from_wire(client.wire(first).unwrap()).generation();
    client.cancel(first);
    let jump = u64::MAX / 2;
    client.poll(jump, 4, |_| true);
    assert!(client.close(first));
    let second = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, jump, 1_000_000)
        .unwrap();
    let after = RequestId::from_wire(client.wire(second).unwrap()).generation();
    assert_eq!(after, before + 1);
}

/// The slots of the frames `client` sends when polled at time 0 with `budget`, through a transport that takes `take` of them.
fn polled_slots(client: &mut Fetcher<'_>, budget: usize, take: usize) -> Vec<u16> {
    let mut slots = Vec::new();
    client.poll(0, budget, |ask| {
        if slots.len() == take {
            return false;
        }
        slots.push(RequestId::from_wire(ask.header.request).slot());
        true
    });
    slots
}

/// `poll` sends due frames in slot order from the slot after the last frame it offered, sent or refused, across bitmap words: a frame that comes due behind the cursor waits for the wrap, a refused send stays due, and a poll with nothing due sends nothing.
#[test]
fn poll_sends_round_robin_from_its_cursor_across_marked_words() {
    let releases = Releases::new(130, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 130, 1, 256);
    let wide = Admitted {
        caps: Caps {
            slots: 130,
            window: 8,
        },
        ..SESSION
    };
    let ids: Vec<RequestId> = (0..130u8)
        .map(|n| {
            client
                .fetch(wide, [n; 32], 0, 1 << 20, 0, 1_000_000)
                .unwrap()
        })
        .collect();
    let mut slots: Vec<u16> = ids.iter().map(|id| id.slot()).collect();
    slots.sort_unstable();
    assert_eq!(polled_slots(&mut client, 50, 50), slots[..50]);
    assert_eq!(polled_slots(&mut client, 50, 50), slots[50..100]);
    let behind = ids.iter().find(|id| id.slot() == 10).unwrap();
    client.cancel(*behind);
    let mut expected = slots[100..].to_vec();
    expected.push(10);
    assert_eq!(
        polled_slots(&mut client, 50, 50),
        expected,
        "the CANCEL behind the cursor follows the wrap"
    );
    assert!(polled_slots(&mut client, 50, 50).is_empty());
    assert!(polled_slots(&mut client, 50, 50).is_empty());
    let refused = ids.iter().find(|id| id.slot() == 20).unwrap();
    client.cancel(*refused);
    assert!(polled_slots(&mut client, 50, 0).is_empty());
    assert_eq!(
        polled_slots(&mut client, 50, 50),
        [20],
        "a refused frame stays due"
    );
}

/// `tick` acts at the earliest deadline or retry even when progress is recorded at a time before an earlier tick: that progress still retries `retry_us` after it.
#[test]
fn tick_retries_on_time_after_progress_at_an_earlier_clock() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 8, 8);
    client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 10_000, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 10_000);
    client.tick(12_000);
    assert_eq!(
        client.report().get_retries,
        0,
        "the GET retry is due at 13,000"
    );
    client.start(SESSION, &start_for(&get, 4 * 8192), 0);
    assert_eq!(last_sent(&mut client, 0).kind, Kind::Ack);
    client.tick(2_999);
    assert_eq!(client.report().ack_retries, 0);
    client.tick(3_000);
    assert_eq!(
        client.report().ack_retries,
        1,
        "progress at 0 retries at 3,000"
    );
    assert_eq!(last_sent(&mut client, 3_000).kind, Kind::Ack);
}

/// A request whose every granted fragment awaits release spends no retries however long it waits; the release that ends the wait restarts the retry clock when `poll` folds it, so the ACK retry comes `retry_us` after that poll.
#[test]
fn a_release_that_ends_a_stall_restarts_the_retry_clock() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 2, 8);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    client.start(SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 1);
    let ack = last_sent(&mut client, 0);
    assert_eq!((ack.index, ack.grant), (2, 2));
    for now in [3_000, 50_000, 99_000] {
        client.tick(now);
    }
    assert_eq!(client.report().ack_retries, 0, "held back, not silent");
    drop(client.take(id).expect("fragment 0"));
    drop(client.take(id).expect("fragment 1"));
    let ack = last_sent(&mut client, 100_000);
    assert_eq!(
        (ack.index, ack.grant),
        (2, 4),
        "the release grants two more"
    );
    client.tick(102_999);
    assert_eq!(
        client.report().ack_retries,
        0,
        "the retry clock restarted at the poll, not at the tick at 99,000"
    );
    client.tick(103_000);
    assert_eq!(client.report().ack_retries, 1);
    let retry = last_sent(&mut client, 103_000);
    assert_eq!((retry.kind, retry.index, retry.grant), (Kind::Ack, 2, 4));
}

/// A window of 5 fragments wraps its entries over a lossy, duplicating and reordering transfer about eight windows long and delivers the exact bytes.
#[test]
fn an_odd_window_wraps_its_entries() {
    let objects = [object(16, 7, 41 * 8192 - 300)];
    for seed in 0..3 {
        let run = run(Scenario {
            seed,
            objects: &objects,
            stored: &[true],
            faults: Faults {
                loss: 10,
                duplicate: 10,
                reorder: 20,
            },
            window: 5,
            turns: 40_000,
            ..Scenario::BASE
        });
        assert_eq!(run.outcomes[0], Some(Outcome::Complete), "seed {seed}");
        assert_eq!(run.bytes[0], objects[0].payload, "seed {seed}");
    }
}

/// `due` reports a frame waiting for poll and `deadline` the earliest timer; `cancel_all` queues a CANCEL for every undecided request, and `end_session` ends only the named session's requests and queues none.
#[test]
fn due_frames_timers_and_bulk_endings() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 2, 8);
    assert_eq!(
        (client.due(), client.deadline()),
        (false, None),
        "an idle core"
    );
    let other = Admitted {
        epoch: 4,
        ..SESSION
    };
    let first = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let second = client
        .fetch(other, [7; 32], 0, 1 << 20, 0, 500_000)
        .unwrap();
    assert!(client.due(), "the GETs are due");
    client.poll(0, 4, |_| true);
    assert!(!client.due());
    assert_eq!(client.deadline(), Some(FETCH.retry_us), "the first retry");
    client.end_session(4, Status::SessionMismatch);
    assert_eq!(
        client.outcome(second),
        Some(Outcome::Failed(Status::SessionMismatch))
    );
    assert_eq!(client.outcome(first), None);
    assert!(
        !client.due(),
        "a replaced session's request queues no CANCEL"
    );
    client.cancel_all();
    assert_eq!(
        client.outcome(first),
        Some(Outcome::Failed(Status::Cancelled))
    );
    let first_wire = client.wire(first).unwrap();
    let mut cancels = Vec::new();
    client.poll(0, 4, |ask| {
        cancels.push((ask.header.kind, ask.header.request));
        true
    });
    assert_eq!(cancels, [(Kind::Cancel, first_wire)]);
    assert_eq!(client.deadline(), None);
}

/// A frame handed out for a request reaches no successor in its table slot. Request A's GET frame is kept, A is
/// cancelled, its CANCEL goes out and A retires; request B then takes A's table slot under another wire request ID
/// and its GET is handed out. Putting A's frame back leaves B with no frame due, and a taken datagram of A's frame
/// counts the datagram and times no first send. B's own frame, taken 50 µs after B's admission, then times B's
/// first send in the bucket that starts at 32 µs.
#[test]
fn a_frame_of_a_retired_request_reaches_no_successor_in_its_slot() {
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 1, 2, 8);
    let handed = |client: &mut Fetcher<'_>, now_us: u64| {
        let mut frame = None;
        client.poll(now_us, 4, |ask| {
            assert_eq!(ask.header.kind, Kind::Get);
            frame = Some(Asked::from(&ask));
            true
        });
        frame.expect("a GET")
    };
    let first = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let first_wire = client.wire(first).unwrap();
    let stale = handed(&mut client, 0);
    client.cancel(first);
    assert_eq!(last_sent(&mut client, 0).kind, Kind::Cancel);
    assert!(client.close(first), "premise: the first request retires");
    let second = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 100, 1_000_000)
        .unwrap();
    assert_eq!(second.slot(), first.slot(), "premise: the same table slot");
    assert_ne!(
        client.wire(second).unwrap(),
        first_wire,
        "premise: another wire request ID"
    );
    let own = handed(&mut client, 100);
    assert!(!client.due(), "premise: the successor's GET is handed out");
    client.unsend(stale);
    assert!(
        !client.due(),
        "the retired request's frame puts nothing back"
    );
    client.core.taken(&mut client.requests, &[stale], 120);
    let report = client.core.report();
    assert_eq!(
        (
            report.gets_per_datagram[0],
            report.first_send_us,
            report.first_sends
        ),
        (1, 0, [0; FIRST_SEND_BUCKETS]),
        "the retired request's frame counts its datagram and times no first send"
    );
    client.core.taken(&mut client.requests, &[own], 150);
    let report = client.core.report();
    let mut buckets = [0; FIRST_SEND_BUCKETS];
    buckets[5] = 1;
    assert_eq!(
        (
            report.gets_per_datagram[0],
            report.first_send_us,
            report.first_sends
        ),
        (2, 50, buckets),
        "the successor's own frame times its first send"
    );
}

/// A frame `poll` handed out and `unsend` put back stays due, and the next poll hands it out again: a GET, an ACK, and a CANCEL with its status, whose slot retires only once the CANCEL goes out.
#[test]
fn an_unsent_frame_stays_due_for_the_next_poll() {
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 1, 2, 8);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let wire = client.wire(id).unwrap();
    let mut asks = Vec::new();
    let mut round = |client: &mut Fetcher<'_>| {
        asks.clear();
        client.poll(0, 4, |ask| {
            asks.push(ask);
            true
        });
        assert_eq!(asks.len(), 1, "one frame per round");
        assert!(!client.due());
        client.unsend(Asked::from(&asks[0]));
        assert!(client.due(), "the put-back frame waits again");
        let again = last_sent(client, 0);
        assert_eq!(
            (again.kind, again.request, again.status),
            (asks[0].header.kind, wire, asks[0].header.status)
        );
        asks[0].header
    };
    let get = round(&mut client);
    assert_eq!(get.kind, Kind::Get);
    client.start(SESSION, &start_for(&get, 3 * 8192), 0);
    assert_eq!(round(&mut client).kind, Kind::Ack);
    client.cancel(id);
    let mut asks = Vec::new();
    client.poll(0, 4, |ask| {
        asks.push(ask);
        true
    });
    assert_eq!(asks.len(), 1);
    client.unsend(Asked::from(&asks[0]));
    assert!(!client.close(id), "the CANCEL still waits");
    let cancel = last_sent(&mut client, 0);
    assert_eq!(
        (cancel.kind, cancel.status),
        (Kind::Cancel, Status::Cancelled as u16)
    );
    assert!(client.close(id));
}

/// While every granted fragment awaits the application, `deadline` names only the request's deadline and nothing is due; dropping a lease makes the grant due at once.
#[test]
fn a_held_window_waits_on_the_deadline_and_a_release_is_due() {
    let crc = Crc32c::detect();
    let pool = pool8();
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 1, 2, 8);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 900_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    client.start(SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 1);
    let held = [client.take(id).unwrap(), client.take(id).unwrap()];
    client.poll(0, 4, |_| true);
    assert!(!client.due());
    assert_eq!(
        client.deadline(),
        Some(900_000),
        "only the deadline, with the window held"
    );
    drop(held);
    assert!(client.due(), "the release's grant is due");
}

/// With a window of 8 and an owner that sends two fragments ahead of each ACK, releases raise the grant without an ACK of their own, and the next receipt ACK carries the raised grant; once the owner has sent every fragment the advertised grant admits, a release makes a grant-only ACK due at once.
#[test]
fn releases_ride_on_receipt_acks_while_the_owner_has_credit() {
    let crc = Crc32c::detect();
    let pool = super::packet::test_pool(16, 2).unwrap();
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 1, 8, 8);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 900_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    assert_eq!((get.kind, get.grant), (Kind::Get, 8));
    let start = start_for(&get, 12 * 8192);
    client.start(SESSION, &start, 0);
    let acks = |client: &mut Fetcher<'_>| {
        let mut acks = Vec::new();
        client.poll(0, 4, |ask| {
            acks.push((ask.header.index, ask.header.grant));
            true
        });
        acks
    };
    assert_eq!(acks(&mut client), [(0, 8)], "the manifest ACK");
    // The owner's burst: two fragments, then it waits for the ACK.
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 1);
    assert_eq!(acks(&mut client), [(2, 8)], "the receipt ACK");
    drop([client.take(id).unwrap(), client.take(id).unwrap()]);
    assert!(
        !client.due(),
        "six fragments of credit cover the next burst"
    );
    assert_eq!(
        acks(&mut client),
        [],
        "the releases wait for the next receipt ACK"
    );
    deliver(&mut client, &pool, crc, SESSION, &start, 2);
    deliver(&mut client, &pool, crc, SESSION, &start, 3);
    assert_eq!(
        acks(&mut client),
        [(4, 10)],
        "the receipt ACK carries the raised grant"
    );
    drop([client.take(id).unwrap(), client.take(id).unwrap()]);
    // The owner spends the whole advertised grant, so credit is short of a burst.
    for index in 4..10 {
        deliver(&mut client, &pool, crc, SESSION, &start, index);
    }
    assert_eq!(acks(&mut client), [(10, 12)]);
    let held: Vec<_> = (4..10).map(|_| client.take(id).unwrap()).collect();
    assert!(
        !client.due(),
        "nothing is owed a frame while the leases are held"
    );
    drop(held);
    assert!(
        client.due(),
        "the owner waits on credit, so the grant is due at once"
    );
    assert_eq!(acks(&mut client), [(10, 18)], "the grant-only ACK");
}

/// A grant folded while the owner had credit becomes due once a fragment arrives that leaves the advertised grant within a burst of the highest fragment received: the owner reached its credit limit after the release, so the grant-only ACK carries the folded grant at once.
#[test]
fn a_folded_grant_becomes_due_when_a_later_fragment_runs_the_credit_low() {
    let crc = Crc32c::detect();
    let pool = super::packet::test_pool(16, 2).unwrap();
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 1, 8, 8);
    let id = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 900_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 12 * 8192);
    client.start(SESSION, &start, 0);
    let acks = |client: &mut Fetcher<'_>| {
        let mut acks = Vec::new();
        client.poll(0, 4, |ask| {
            acks.push((ask.header.index, ask.header.grant));
            true
        });
        acks
    };
    assert_eq!(acks(&mut client), [(0, 8)], "the manifest ACK");
    deliver(&mut client, &pool, crc, SESSION, &start, 0);
    deliver(&mut client, &pool, crc, SESSION, &start, 1);
    assert_eq!(acks(&mut client), [(2, 8)], "the receipt ACK");
    drop([client.take(id).unwrap(), client.take(id).unwrap()]);
    assert_eq!(
        acks(&mut client),
        [],
        "six fragments of credit cover the next burst, so the releases fold without an ACK"
    );
    // The owner spent the whole advertised grant; fragments 2 to 6 are in flight or lost.
    deliver(&mut client, &pool, crc, SESSION, &start, 7);
    assert!(
        client.due(),
        "the owner waits on credit the client already released"
    );
    assert_eq!(acks(&mut client), [(2, 10)], "the grant-only ACK");
    assert!(!client.due(), "the folded grant went out");
}

/// Across a seeded history of fetches, starts, deliveries, takes, releases, cancels and ticks, `due` holds exactly when the next poll sends a frame, and `wants` exactly when `data` holds the fragment.
#[test]
fn due_agrees_with_what_poll_sends() {
    let crc = Crc32c::detect();
    let pool = super::packet::test_pool(32, 4).unwrap();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 4, 2, 8);
    let mut rng = SplitMix64::new(17);
    let mut live: Vec<(RequestId, Header, u32)> = Vec::new();
    let mut held = Vec::new();
    let mut open: Vec<RequestId> = Vec::new();
    let mut now = 0;
    let mut sends = 0;
    for _ in 0..2_000 {
        now += rng.below(1_500);
        match rng.below(7) {
            0 if live.len() < 4 => {
                if let Ok(id) = client.fetch(SESSION, [7; 32], 0, 1 << 20, now, 50_000) {
                    let get = last_sent(&mut client, now);
                    live.push((id, start_for(&get, 6 * 8192), 0));
                    open.push(id);
                }
            }
            1 if !live.is_empty() => {
                let (_, start, _) = live[rng.below(live.len() as u64) as usize];
                client.start(SESSION, &start, now);
            }
            2 if !live.is_empty() => {
                let at = rng.below(live.len() as u64) as usize;
                let (_, start, next) = live[at];
                if next < 6 {
                    let header = Header {
                        kind: Kind::Data,
                        index: next,
                        ..start
                    };
                    let wanted = client.wants(SESSION, &header);
                    let held_before = client.report().dropped + client.report().data_pressure;
                    deliver(&mut client, &pool, crc, SESSION, &start, next);
                    let dropped = client.report().dropped + client.report().data_pressure;
                    assert_eq!(
                        wanted,
                        dropped == held_before,
                        "wants agrees with data at {now}"
                    );
                    live[at].2 += 1;
                }
            }
            3 => {
                for (id, _, _) in &live {
                    held.extend(client.take(*id));
                }
            }
            4 if !held.is_empty() => drop(held.swap_remove(rng.below(held.len() as u64) as usize)),
            5 if !live.is_empty() => {
                let (id, _, _) = live.swap_remove(rng.below(live.len() as u64) as usize);
                client.cancel(id);
            }
            _ => client.tick(now),
        }
        if held.len() > 3 {
            drop(held.remove(0));
        }
        let due = client.due();
        let sent = client.poll(now, 16, |_| true);
        assert_eq!(due, sent > 0, "at {now}");
        sends += sent;
        open.retain(|id| client.outcome(*id).is_none() || !client.close(*id));
        live.retain(|(id, _, _)| client.outcome(*id).is_none());
    }
    assert!(sends > 200, "the history sent frames: {sends}");
}

/// Timers, sends, readiness and bulk endings reach every live request however its slot sits among closed ones: of 130 requests, only those in table slots 0, 64 and 129 stay live, and each retry, deadline and CANCEL names exactly those.
#[test]
fn live_requests_among_closed_slots_are_visited() {
    let session = Admitted {
        caps: Caps {
            slots: 130,
            window: 8,
        },
        ..SESSION
    };
    let releases = Releases::new(130, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 130, 2, 260);
    let ids: Vec<RequestId> = (0..130)
        .map(|_| {
            client
                .fetch(session, [7; 32], 0, 1 << 20, 0, 1_000_000)
                .unwrap()
        })
        .collect();
    assert_eq!(client.poll(0, 200, |_| true), 130, "every GET goes out");
    let keep = [0u16, 64, 129];
    for id in ids.iter().filter(|id| !keep.contains(&id.slot())) {
        client.cancel(*id);
    }
    let cancelled = client.poll(0, 200, |ask| {
        assert_eq!(ask.header.kind, Kind::Cancel);
        true
    });
    assert_eq!(cancelled, 127);
    for id in ids.iter().filter(|id| !keep.contains(&id.slot())) {
        assert!(client.close(*id));
    }
    let live: Vec<RequestId> = ids
        .iter()
        .copied()
        .filter(|id| keep.contains(&id.slot()))
        .collect();
    assert_eq!(live.len(), 3);
    let mut wires: Vec<u64> = live.iter().map(|id| client.wire(*id).unwrap()).collect();
    wires.sort_unstable();
    assert_eq!(
        (client.due(), client.deadline()),
        (false, Some(FETCH.retry_us)),
        "the GET retry is the earliest timer"
    );
    assert_eq!(
        client.poll(0, 200, |_| true),
        0,
        "an idle round sends nothing"
    );
    client.tick(FETCH.retry_us);
    assert!(client.due(), "the retries are due");
    let mut retried = Vec::new();
    client.poll(FETCH.retry_us, 200, |ask| {
        assert_eq!(ask.header.kind, Kind::Get);
        retried.push(ask.header.request);
        true
    });
    retried.sort_unstable();
    assert_eq!(retried, wires);
    client.tick(1_000_000);
    for id in &live {
        assert_eq!(
            client.outcome(*id),
            Some(Outcome::Failed(Status::TimedOut)),
            "the deadline ends slot {}",
            id.slot()
        );
    }
    let mut cancels = Vec::new();
    client.poll(1_000_000, 200, |ask| {
        assert_eq!(ask.header.kind, Kind::Cancel);
        cancels.push(ask.header.request);
        true
    });
    cancels.sort_unstable();
    assert_eq!(cancels, wires);
    for id in &live {
        assert!(client.close(*id));
    }
    assert_eq!((client.due(), client.deadline()), (false, None));
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_miss_and_a_partial_failure_end_explicitly,
    a_refused_fetch_starts_after_receive_boxes_are_released,
    an_application_stall_spends_no_retries,
    an_odd_window_wraps_its_entries,
    lost_final_controls_are_recovered,
    seeded_faults_still_deliver_exact_bytes_of_one_version,
    windows_of_one_and_4096_deliver_the_same_bytes,
);

/// A fetch core over a 4-slot, one-peer table that retries every `retry_us`, at most `attempts` times.
fn limited<'p>(releases: &'p Releases, retry_us: u64, attempts: u32) -> Fetcher<'p> {
    let config = FetchConfig {
        retry_us,
        attempts,
        ..FETCH
    };
    Fetcher::new(
        config,
        RequestTable::new(4, 1, 4),
        releases,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap()
}

/// A live GET's timer is reported at its value, 0 and `u64::MAX` included, and the tick at the deadline ends the request `TimedOut` while the tick before it leaves it live. With retries every `u64::MAX` microseconds, the timer is the deadline.
#[test]
fn a_get_timer_is_present_at_every_timestamp_and_expires_at_its_deadline() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    for (member, now, wait, deadline) in [
        ("get-timer-zero-live", 0, 0, 0),
        ("get-timer-max-live", 1_000, u64::MAX - 1_000, u64::MAX),
        ("get-timer-saturating-live", u64::MAX - 5, 100, u64::MAX),
        ("get-inclusive-expiry", 0, 10_000, 10_000),
    ] {
        let mut client = limited(&releases, u64::MAX, 3);
        let id = client
            .fetch(SESSION, [7; 32], 16, 1 << 20, now, wait)
            .unwrap();
        assert_eq!(client.deadline(), Some(deadline), "{member}");
        client.check_timers();
        if deadline > now {
            client.poll(now, 4, |_| true);
            client.tick(deadline - 1);
            assert_eq!(
                client.outcome(id),
                None,
                "{member}: live before the deadline"
            );
            assert_eq!(client.deadline(), Some(deadline), "{member}");
        }
        client.tick(deadline);
        assert_eq!(
            client.outcome(id),
            Some(Outcome::Failed(Status::TimedOut)),
            "{member}: the deadline's tick ends it"
        );
        assert_eq!(
            client.deadline(),
            None,
            "{member}: a decided request has no timer"
        );
        client.check_timers();
    }
}

/// At `now_us == u64::MAX`, a tick acts only on the live request's timer; a decided request still awaiting retirement and a free slot below the table's high water carry no timer and stay as they were.
#[test]
fn a_tick_at_the_last_timestamp_leaves_decided_and_free_slots() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = limited(&releases, u64::MAX, 3);
    let freed = client
        .fetch(SESSION, [6; 32], 16, 1 << 20, 0, 1_000)
        .unwrap();
    let decided = client
        .fetch(SESSION, [7; 32], 16, 1 << 20, 0, 1_000)
        .unwrap();
    let live = client
        .fetch(SESSION, [8; 32], 16, 1 << 20, 0, u64::MAX)
        .unwrap();
    client.cancel(freed);
    client.poll(0, 4, |_| true);
    assert!(
        client.close(freed),
        "a free slot below the table's high water"
    );
    client.cancel(decided);
    client.poll(0, 4, |ask| ask.header.kind != Kind::Cancel);
    assert_eq!(
        client.outcome(decided),
        Some(Outcome::Failed(Status::Cancelled))
    );
    assert_eq!(
        client.deadline(),
        Some(u64::MAX),
        "the live GET's timer alone"
    );
    let (decided_wire, live_wire) = (client.wire(decided).unwrap(), client.wire(live).unwrap());
    client.tick(u64::MAX);
    assert_eq!(
        client.outcome(decided),
        Some(Outcome::Failed(Status::Cancelled)),
        "the decided request keeps its outcome"
    );
    assert_eq!(
        client.outcome(live),
        Some(Outcome::Failed(Status::TimedOut))
    );
    assert_eq!(client.deadline(), None);
    let mut cancels = Vec::new();
    client.poll(u64::MAX, 4, |ask| {
        cancels.push((ask.header.kind, ask.header.request, ask.header.status));
        true
    });
    cancels.sort_unstable_by_key(|&(_, wire, _)| wire);
    let mut expected = [
        (Kind::Cancel, decided_wire, Status::Cancelled as u16),
        (Kind::Cancel, live_wire, Status::TimedOut as u16),
    ];
    expected.sort_unstable_by_key(|&(_, wire, _)| wire);
    assert_eq!(
        cancels, expected,
        "the decided request's CANCEL stays due beside the live request's"
    );
    client.check_timers();
}

/// The retry count starts at 0 with the first GET sent and grows by one per retry-timer resend, and a retry timer that finds the count at the limit ends the request `OwnerUnavailable` before counting. At limit 0 the first retry timer ends the request with no resend; at `u32::MAX`, a count seeded one below the limit resends once and the next retry timer ends it.
#[test]
fn get_retries_hold_at_zero_and_at_the_largest_limit() {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    for (member, attempts, seed) in [
        ("get-retry-zero", 0, None),
        ("get-retry-max", u32::MAX, Some(u32::MAX - 1)),
    ] {
        let mut client = limited(&releases, 1_000, attempts);
        let id = client
            .fetch(SESSION, [7; 32], 16, 1 << 20, 0, u64::MAX)
            .unwrap();
        assert_eq!(
            last_sent(&mut client, 0).kind,
            Kind::Get,
            "{member}: the first GET"
        );
        if let Some(seed) = seed {
            client.core.seed_attempts(&mut client.requests, id, seed);
            let retry = client.deadline().unwrap();
            client.tick(retry);
            assert_eq!(client.outcome(id), None, "{member}: the last resend is due");
            assert_eq!(last_sent(&mut client, retry).kind, Kind::Get, "{member}");
            assert_eq!(client.core.attempts(&client.requests, id), Some(u32::MAX));
        }
        let retry = client.deadline().unwrap();
        client.tick(retry);
        assert_eq!(
            client.outcome(id),
            Some(Outcome::Failed(Status::OwnerUnavailable)),
            "{member}: the retries ran out"
        );
        client.check_timers();
    }
}

/// A retried GET the transport refuses is due again with its retry still counted, and a START that binds the manifest, a fragment that advances the receipt base and a release folded into the grant each restart the count.
#[test]
fn a_refused_get_resend_keeps_its_count_and_progress_resets_it() {
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = limited(&releases, 1_000, 5);
    let id = client
        .fetch(SESSION, [7; 32], 16, 1 << 20, 0, u64::MAX)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let retry = client.deadline().unwrap();
    client.tick(retry);
    assert_eq!(client.core.attempts(&client.requests, id), Some(1));
    let mut refused = None;
    assert!(client.due());
    client.poll(retry, 4, |ask| {
        refused = Some(Asked::from(&ask));
        true
    });
    assert!(
        !client.due(),
        "the poll handed the GET resend to the transport"
    );
    client.unsend(refused.expect("the GET resend"));
    assert!(
        client.due(),
        "get-retry-unsend: the refused GET is due again"
    );
    assert_eq!(
        client.core.attempts(&client.requests, id),
        Some(1),
        "get-retry-unsend: the refusal returns no retry"
    );
    let start = start_for(&get, 2 * 8192);
    client.start(SESSION, &start, retry);
    assert_eq!(
        client.core.attempts(&client.requests, id),
        Some(0),
        "get-retry-progress-reset: START restarts the count"
    );
    let crc = Crc32c::detect();
    for (event, now) in [("receipt", 2 * retry), ("release", 4 * retry)] {
        let due = client.deadline().unwrap();
        client.tick(due);
        assert_eq!(
            client.core.attempts(&client.requests, id),
            Some(1),
            "{event}"
        );
        client.poll(due, 4, |_| true);
        if event == "receipt" {
            deliver_at(&mut client, &pool, crc, SESSION, &start, 0, now);
        } else {
            drop(client.take(id).expect("fragment 0"));
            client.poll(now, 4, |_| true);
        }
        assert_eq!(
            client.core.attempts(&client.requests, id),
            Some(0),
            "get-retry-progress-reset: a {event} restarts the count"
        );
    }
    client.check_timers();
}

/// The 130 slots span three bitmap words and two levels of bounds. Alternating occupancy exercises full and sparse groups.
#[test]
fn the_timer_index_matches_a_model_of_optional_timers() {
    const SLOTS: usize = 130;
    let mut timers = super::slot_index::Timers::new(SLOTS as u32);
    let mut model: Vec<Option<u64>> = vec![None; SLOTS];
    let mut rng = SplitMix64::new(895);
    let values = [0, 1, 500, 1_000, u64::MAX - 1, u64::MAX];
    let (mut filled, mut sparse) = (false, false);
    for step in 0..4_000 {
        let slot = match rng.next_u64() % 4 {
            0 => [0, 63, 64, 127, 128, 129][(rng.next_u64() % 6) as usize],
            _ => (rng.next_u64() % SLOTS as u64) as usize,
        };
        let writes = if (step / 500) % 2 == 0 {
            !rng.next_u64().is_multiple_of(3)
        } else {
            rng.next_u64().is_multiple_of(16)
        };
        let timer = writes.then(|| values[(rng.next_u64() % 6) as usize]);
        timers.set(slot, timer);
        model[slot] = timer;
        let carried = model.iter().flatten().count();
        filled |= carried * 2 >= SLOTS;
        sparse |= carried * 8 < SLOTS;
        let least = model.iter().flatten().copied().min();
        assert!(timers.floor() <= least, "step {step}");
        assert_eq!(timers.floor().is_some(), least.is_some(), "step {step}");
        assert_eq!(timers.least(SLOTS), least, "step {step}");
        assert_eq!(
            timers.floor(),
            least,
            "a fold leaves the floor exact, step {step}"
        );
        for (at, expected) in model.iter().enumerate() {
            assert_eq!(timers.get(at), *expected, "step {step} slot {at}");
        }
        let now = values[(rng.next_u64() % 6) as usize];
        let from = (rng.next_u64() % (SLOTS as u64 + 1)) as usize;
        let due = (from..SLOTS).find(|&at| model[at].is_some_and(|timer| timer <= now));
        assert_eq!(
            timers.next_due(from, SLOTS, now),
            due,
            "step {step} from {from} now {now}"
        );
        timers.fold(SLOTS);
        assert_eq!(
            timers.floor(),
            least,
            "a fold finds the least timer, step {step}"
        );
    }
    assert!(
        filled && sparse,
        "timers filled at least half the slots and later fewer than an eighth"
    );
}

/// Both the tree walk and the presence scan used when `now_us == u64::MAX` restrict results to `from..end`.
#[test]
fn next_due_stops_at_its_end_before_a_due_timer_past_it() {
    let mut timers = super::slot_index::Timers::new(16);
    timers.set(5, Some(0));
    assert_eq!(timers.next_due(0, 4, 0), None);
    assert_eq!(timers.next_due(0, 5, 0), None);
    assert_eq!(timers.next_due(0, 4, u64::MAX), None);
    assert_eq!(timers.next_due(0, 6, 0), Some(5));
    assert_eq!(timers.next_due(5, 6, u64::MAX), Some(5));
    let mut timers = super::slot_index::Timers::new(130);
    timers.set(129, Some(7));
    assert_eq!(timers.next_due(0, 129, 7), None);
    assert_eq!(timers.next_due(64, 128, 7), None);
    assert_eq!(timers.next_due(0, 130, 7), Some(129));
}

/// A random walk of writes, reads, folds, scans and ticks over tables from one slot to five levels of bounds. Writes between reads leave paths stale, so scans meet bounds below their least timers; a read before a write lets the write recompute its path at once.
#[test]
fn the_timer_index_matches_a_model_at_every_tree_height() {
    for slots in [1, 2, 7, 63, 64, 65, 129, 130, 513, 1000, 4096, 4097] {
        for seed in 0..4 {
            timer_walk(slots, 0x895_0000 + slots as u64 * 8 + seed);
        }
    }
}

fn timer_walk(slots: usize, seed: u64) {
    let mut rng = SplitMix64::new(seed);
    let mut timers = super::slot_index::Timers::new(slots as u32);
    let mut model: Vec<Option<u64>> = vec![None; slots];
    let least = |model: &[Option<u64>]| model.iter().flatten().copied().min();
    let due = |model: &[Option<u64>], from: usize, end: usize, now: u64| {
        (from..end).find(|&at| model[at].is_some_and(|timer| timer <= now))
    };
    // A value or a time near the least timer, at an end of the `u64` range, or small.
    let pick = |rng: &mut SplitMix64, model: &[Option<u64>]| {
        let low = least(model).unwrap_or(500);
        match rng.below(10) {
            0 => 0,
            1 => u64::MAX,
            2 => u64::MAX - 1,
            3 => low,
            4 => low.saturating_sub(1),
            5 => low.saturating_add(1),
            _ => rng.below(1_000),
        }
    };
    // Occupancy drifts so full, sparse and empty tables alternate.
    let mut fill = 50;
    for step in 0..6_000 {
        if step % 97 == 0 {
            fill = [0, 2, 10, 25, 50, 90, 100][rng.below(7) as usize];
        }
        // An end past the last slot that carries a timer.
        let last = model
            .iter()
            .rposition(Option::is_some)
            .map_or(0, |at| at + 1);
        let end = last + rng.below((slots - last) as u64 + 1) as usize;
        match rng.below(12) {
            0..=4 => {
                let slot = rng.below(slots as u64) as usize;
                let timer = (rng.below(100) < fill).then(|| pick(&mut rng, &model));
                timers.set(slot, timer);
                model[slot] = timer;
            }
            5 => assert_eq!(timers.least(end), least(&model), "least, step {step}"),
            6 => {
                timers.fold(end);
                if let Some(low) = least(&model) {
                    assert_eq!(timers.floor(), Some(low), "fold, step {step}");
                }
            }
            7 | 8 => {
                let from = rng.below(end as u64 + 2) as usize;
                let now = pick(&mut rng, &model);
                assert_eq!(
                    timers.next_due(from, end, now),
                    due(&model, from, end, now),
                    "step {step} from {from} end {end} now {now}"
                );
            }
            _ => {
                // A tick: rewrite each due slot in slot order, then fold.
                let now = pick(&mut rng, &model);
                let mut from = 0;
                loop {
                    let found = timers.next_due(from, end, now);
                    assert_eq!(found, due(&model, from, end, now), "tick, step {step}");
                    let Some(slot) = found else { break };
                    from = slot + 1;
                    let timer = match rng.below(4) {
                        0 => None,
                        1 => Some(now.saturating_add(1 + rng.below(50))),
                        2 => Some(u64::MAX),
                        _ => Some(now.saturating_add(rng.below(3))),
                    };
                    timers.set(slot, timer);
                    model[slot] = timer;
                }
                timers.fold(end);
                if let Some(low) = least(&model) {
                    assert_eq!(timers.floor(), Some(low), "tick fold, step {step}");
                }
            }
        }
        if step % 16 == 0 || step == 5_999 {
            for (at, expected) in model.iter().enumerate() {
                assert_eq!(timers.get(at), *expected, "step {step} slot {at}");
            }
            let low = least(&model);
            assert_eq!(timers.floor().is_some(), low.is_some(), "step {step}");
            assert!(timers.floor() <= low, "step {step}");
            if timers.exact() {
                assert_eq!(timers.floor(), low, "an exact floor, step {step}");
            }
        }
    }
}

/// Who decided request `id`'s outcome, read from its terminal observation.
fn decider(client: &Fetcher<'_>, id: RequestId) -> Decider {
    client
        .core
        .terminal(&client.requests, id)
        .expect("a decided request")
        .decided_by
}

/// The kind, wire request ID, fragment index, offset field and status of a frame.
type Brief = (Kind, u64, u32, u64, u16);

/// A core of four slots whose cursor stands at slot 1 and whose slots hold, in order: a request whose gap ACK is due at [`GAP_WAIT_US`] with base 1 and receipt mask `0b1`, a request whose GET is due, a cancelled request whose CANCEL is due, and a request whose GET is due. Returns the core and each request's frame, in slot order.
fn core_with_an_ack_a_get_a_cancel_and_a_get_due<'p>(
    releases: &'p Releases,
    pool: &'p PacketPool,
) -> (Fetcher<'p>, [Brief; 4]) {
    let crc = Crc32c::detect();
    let mut client = client(releases, 4, 4, 16);
    client.tick(0);
    let acked = client
        .fetch(SESSION, [7; 32], 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let get = last_sent(&mut client, 0);
    let start = start_for(&get, 4 * 8192);
    client.start(SESSION, &start, 0);
    deliver(&mut client, pool, crc, SESSION, &start, 0);
    assert_eq!(last_sent(&mut client, 0).index, 1);
    deliver(&mut client, pool, crc, SESSION, &start, 2);
    client.tick(GAP_WAIT_US);
    let mut ids = [acked; 4];
    for (key, id) in (1u8..).zip(&mut ids[1..]) {
        *id = client
            .fetch(SESSION, [key; 32], 0, 1 << 20, GAP_WAIT_US, 1_000_000)
            .unwrap();
    }
    client.cancel(ids[2]);
    assert_eq!(ids.map(|id| id.slot()), [0, 1, 2, 3]);
    let wires = ids.map(|id| client.wire(id).unwrap());
    let frames = [
        (Kind::Ack, wires[0], 1, 0b1, 0),
        (Kind::Get, wires[1], 0, 0, 0),
        (Kind::Cancel, wires[2], 0, 0, Status::Cancelled as u16),
        (Kind::Get, wires[3], 0, 0, 0),
    ];
    (client, frames)
}

/// The count `client.poll` returns at [`GAP_WAIT_US`] with `budget`, and the frames it hands to a transport that takes `take` of them.
fn polled_frames(client: &mut Fetcher<'_>, budget: usize, take: usize) -> (usize, Vec<Brief>) {
    let mut frames = Vec::new();
    let sent = client.poll(GAP_WAIT_US, budget, |ask| {
        if frames.len() == take {
            return false;
        }
        let header = ask.header;
        frames.push((
            header.kind,
            header.request,
            header.index,
            header.offset,
            header.status,
        ));
        true
    });
    (sent, frames)
}

/// An ACK or CANCEL that `poll` selects after a GET reached `send` reaches `send` behind the poll's GET frames, in selection order, and counts in the returned total. The CANCEL carries its status and the ACK its request's base and receipt mask, and the next poll sends neither again.
#[test]
fn a_frame_selected_after_a_get_follows_the_polls_gets_and_leaves_once() {
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (mut client, [ack, first, cancel, second]) =
        core_with_an_ack_a_get_a_cancel_and_a_get_due(&releases, &pool);
    assert_eq!(
        polled_frames(&mut client, 4, 4),
        (4, vec![first, second, cancel, ack]),
        "selected from slot 1 as GET, CANCEL, GET, ACK"
    );
    assert_eq!(polled_frames(&mut client, 4, 4), (0, vec![]));
    client.check_timers();
}

/// A frame waiting behind the poll's GET frames uses one of the poll's `budget` frames, so a poll hands `send` at most `budget` frames and a frame past the budget stays due.
#[test]
fn a_frame_waiting_behind_the_gets_counts_in_the_polls_budget() {
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (mut client, [ack, first, cancel, second]) =
        core_with_an_ack_a_get_a_cancel_and_a_get_due(&releases, &pool);
    assert_eq!(
        polled_frames(&mut client, 2, 4),
        (2, vec![first, cancel]),
        "the waiting CANCEL is the poll's second frame"
    );
    assert_eq!(
        polled_frames(&mut client, 4, 4),
        (2, vec![second, ack]),
        "selected from slot 3 as GET, ACK"
    );
    assert_eq!(polled_frames(&mut client, 4, 4), (0, vec![]));
    client.check_timers();
}

/// A refusal leaves every frame that had not reached `send` due and unchanged. `poll` counts only the frames `send` took, and the next poll sends the refused frame and each waiting frame once: after a refused GET with a CANCEL waiting, and after a waiting ACK that `send` refused.
#[test]
fn a_refusal_keeps_each_frame_waiting_behind_the_gets_due() {
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (mut client, [ack, first, cancel, second]) =
        core_with_an_ack_a_get_a_cancel_and_a_get_due(&releases, &pool);
    assert_eq!(
        polled_frames(&mut client, 4, 1),
        (1, vec![first]),
        "the second GET is refused while the CANCEL waits"
    );
    assert_eq!(
        polled_frames(&mut client, 4, 4),
        (3, vec![ack, cancel, second]),
        "selected from slot 0, where no GET precedes the ACK and the CANCEL"
    );
    assert_eq!(polled_frames(&mut client, 4, 4), (0, vec![]));
    client.check_timers();
    drop(client);
    let (mut client, [ack, first, cancel, second]) =
        core_with_an_ack_a_get_a_cancel_and_a_get_due(&releases, &pool);
    assert_eq!(
        polled_frames(&mut client, 4, 3),
        (3, vec![first, second, cancel]),
        "the waiting ACK is refused"
    );
    assert_eq!(polled_frames(&mut client, 4, 4), (1, vec![ack]));
    assert_eq!(polled_frames(&mut client, 4, 4), (0, vec![]));
    client.check_timers();
}

/// The kind, wire request ID, fragment index and grant of a frame.
type Granted = (Kind, u64, u32, u32);

/// A core of `holding + 2` slots under a window of 2 whose cursor stands at slot 0. The first and the last slot each hold a request whose GET is due again at [`FETCH`]'s retry interval. Each slot between them holds a request that received fragments 0 and 1 of a four-fragment object, sent their receipt ACK with a grant of 2 and handed both fragments to the application, so it has no frame due and each lease the application releases raises its grant by one. Returns the core, each request's wire ID in slot order, the leases of each fragment 0 in slot order and the leases of each fragment 1 in slot order.
fn core_with_gets_around_requests_holding_leases<'p>(
    releases: &'p Releases,
    pool: &'p PacketPool,
    holding: u8,
) -> (
    Fetcher<'p>,
    Vec<u64>,
    Vec<FragmentLease<'p>>,
    Vec<FragmentLease<'p>>,
) {
    let crc = Crc32c::detect();
    let mut client = client(releases, u32::from(holding) + 2, 2, 16);
    let mut ids: Vec<RequestId> = (0..=holding)
        .map(|key| {
            client
                .fetch(SESSION, [key; 32], 0, 1 << 20, 0, 1_000_000)
                .unwrap()
        })
        .collect();
    let mut gets = Vec::new();
    client.poll(0, 8, |ask| {
        gets.push(ask.header);
        true
    });
    assert_eq!(gets.len(), ids.len());
    for get in &gets[1..] {
        let start = start_for(get, 4 * 8192);
        client.start(SESSION, &start, 0);
        deliver(&mut client, pool, crc, SESSION, &start, 0);
        deliver(&mut client, pool, crc, SESSION, &start, 1);
    }
    assert_eq!(
        client.poll(0, 8, |ask| ask.header.kind == Kind::Ack),
        usize::from(holding),
        "one receipt ACK for each request holding fragments"
    );
    // The last slot's GET is the latest frame selected ahead of the returned core's polls, so their scans start at slot 0.
    ids.push(
        client
            .fetch(SESSION, [u8::MAX; 32], 0, 1 << 20, 0, 1_000_000)
            .unwrap(),
    );
    assert_eq!(client.poll(0, 8, |ask| ask.header.kind == Kind::Get), 1);
    assert!(ids.iter().map(|id| id.slot()).eq(0..u16::from(holding) + 2));
    let (mut firsts, mut seconds) = (Vec::new(), Vec::new());
    for id in &ids[1..=usize::from(holding)] {
        firsts.push(client.take(*id).expect("fragment 0"));
        seconds.push(client.take(*id).expect("fragment 1"));
    }
    client.tick(FETCH.retry_us);
    let wires = ids.iter().map(|id| client.wire(*id).unwrap()).collect();
    (client, wires, firsts, seconds)
}

/// The count `client.poll` returns at [`FETCH`]'s retry interval with `budget`, the frames it hands to a `send` that takes each of them and releases every lease of `leases` on the GET of wire request `releasing`, and the heap allocations the poll makes.
fn polled_releasing<'p>(
    client: &mut Fetcher<'p>,
    budget: usize,
    releasing: u64,
    leases: &mut Vec<FragmentLease<'p>>,
) -> (usize, Vec<Granted>, usize) {
    let mut frames = Vec::with_capacity(budget);
    let allocations = crate::instrument::allocations();
    let sent = client.poll(FETCH.retry_us, budget, |ask| {
        let header = ask.header;
        frames.push((header.kind, header.request, header.index, header.grant));
        if header.kind == Kind::Get && header.request == releasing {
            leases.clear();
        }
        true
    });
    let allocated = crate::instrument::allocations() - allocations;
    (sent, frames, allocated)
}

/// A lease that `send` releases for a request whose ACK waits behind the poll's GET frames raises the grant that ACK carries, and the request keeps its one frame of the poll's `budget`. With a budget of four frames the poll hands out both GETs, the waiting ACK, and the ACK of a second request, which a release inside `send` made due.
#[test]
fn a_release_inside_send_raises_a_waiting_acks_grant_within_its_one_budget_frame() {
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (mut client, wires, mut firsts, mut leases) =
        core_with_gets_around_requests_holding_leases(&releases, &pool, 2);
    let [first, waiting, quiet, last] = wires[..] else {
        panic!("four requests");
    };
    // This release makes the request's ACK due ahead of the poll, so the scan selects it behind the first GET.
    drop(firsts.remove(0));
    leases.append(&mut firsts);
    assert_eq!(
        polled_releasing(&mut client, 4, last, &mut leases),
        (
            4,
            vec![
                (Kind::Get, first, 0, 2),
                (Kind::Get, last, 0, 2),
                (Kind::Ack, waiting, 2, 4),
                (Kind::Ack, quiet, 2, 4),
            ],
            0
        ),
        "the last GET's `send` releases one more lease of the waiting request and both leases of the quiet one"
    );
    assert_eq!(
        polled_releasing(&mut client, 4, last, &mut leases),
        (0, vec![], 0)
    );
    client.check_timers();
}

/// The cancelled request releases one lease before the poll. The last GET's `send` releases the cancelled request's remaining lease and both of the quiet request's leases. The pending CANCEL consumes one frame, leaving the fourth for the quiet request's ACK.
#[test]
fn a_release_inside_send_keeps_a_waiting_cancel_within_its_one_budget_frame() {
    let pool = pool8();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (mut client, wires, mut firsts, mut leases) =
        core_with_gets_around_requests_holding_leases(&releases, &pool, 2);
    let [first, cancelled, quiet, last] = wires[..] else {
        panic!("four requests");
    };
    let id = client
        .requests
        .table()
        .live_id(1)
        .expect("the request in slot 1");
    client.cancel(id);
    drop(firsts.remove(0));
    leases.append(&mut firsts);
    assert_eq!(
        polled_releasing(&mut client, 4, last, &mut leases),
        (
            4,
            vec![
                (Kind::Get, first, 0, 2),
                (Kind::Get, last, 0, 2),
                (Kind::Cancel, cancelled, 0, 0),
                (Kind::Ack, quiet, 2, 4),
            ],
            0
        ),
        "the last GET's `send` releases one more lease of the cancelled request and both leases of the quiet one"
    );
    assert_eq!(
        polled_releasing(&mut client, 4, last, &mut leases),
        (0, vec![], 0)
    );
    client.check_timers();
}

/// A poll whose `send` releases a lease of every request waiting behind the GET frames allocates nothing and hands each waiting ACK out once, carrying the raised grant: a waiting request holds one entry of the core's waiting slots, whose capacity is one entry per slot.
#[test]
fn releases_inside_send_keep_the_waiting_slots_within_their_capacity() {
    let pool = pool8();
    let releases = Releases::new(5, &mut EngineBudget::new(1 << 20)).unwrap();
    let (mut client, wires, firsts, mut leases) =
        core_with_gets_around_requests_holding_leases(&releases, &pool, 3);
    let [first, a, b, c, last] = wires[..] else {
        panic!("five requests");
    };
    // These releases make all three ACKs due ahead of the poll, so each waits behind the first GET.
    drop(firsts);
    assert_eq!(
        polled_releasing(&mut client, 8, last, &mut leases),
        (
            5,
            vec![
                (Kind::Get, first, 0, 2),
                (Kind::Get, last, 0, 2),
                (Kind::Ack, a, 2, 4),
                (Kind::Ack, b, 2, 4),
                (Kind::Ack, c, 2, 4),
            ],
            0
        ),
        "the last GET's `send` releases one more lease of each waiting request"
    );
    assert_eq!(
        polled_releasing(&mut client, 8, last, &mut leases),
        (0, vec![], 0)
    );
    client.check_timers();
}
