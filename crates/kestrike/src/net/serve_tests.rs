//! Owner transfer core checks: frames for scripted verified reads, retention against cumulative receipt, finite retries, duplicate and terminal handling, pacing and allocation.

use crate::storage::{EngineBudget, EngineBudgetExceeded};

use super::datagram::{FRAME_OVERHEAD, HEADER_LEN, PeerId};
use super::frame::{Header, Kind, Status};
use super::pace::{Pacer, Shaper};
use super::requests::{RequestId, RequestTable};
use super::serve::{
    Chunk as Retaining, DATA_BURST, GetOutcome, HOLE_GUARD_US, Manifest, Out, PutReply, ReadEnd,
    Retained, ServeConfig, ServeCore, ServeReport, next_set_wrapping, take_send_visits,
};
use super::served::{Request, Requests};
use super::session::{Admitted, Caps};

type Chunk = Box<[u8]>;

/// A GET transfer core over its own request namespace, composed as the owner composes them, so a test calls each core method on one value.
#[derive(Clone)]
pub(super) struct Core<C> {
    pub(super) serve: ServeCore,
    pub(super) requests: Requests<C>,
}

impl<C: Retaining> Core<C> {
    /// A core and a namespace over `table`, with `config.slots` wire slots for each of its peers.
    pub(super) fn new(
        config: ServeConfig,
        table: RequestTable<Request<C>>,
        peers: u16,
        batch: u32,
        now_us: u64,
        windows: u32,
        budget: &mut EngineBudget,
    ) -> Result<Self, EngineBudgetExceeded> {
        assert_eq!(table.peers(), peers);
        let requests = Requests::new(table, config.slots, budget)?;
        let serve = ServeCore::new(config, &requests, batch, now_us, windows, budget)?;
        Ok(Self { serve, requests })
    }

    pub(super) fn requests(&self) -> &RequestTable<Request<C>> {
        self.requests.table()
    }

    pub(super) fn report(&self) -> ServeReport {
        self.serve.report()
    }

    pub(super) fn control(&mut self, now_us: u64, exceeded: Option<u64>) {
        self.serve.control(now_us, exceeded);
    }

    pub(super) fn read_ahead(&mut self, ahead: u8) {
        self.serve.read_ahead(ahead);
    }

    pub(super) fn get(&mut self, session: Admitted, header: &Header, now_us: u64) -> GetOutcome {
        self.serve.get(&mut self.requests, session, header, now_us)
    }

    pub(super) fn read_started(&mut self, id: RequestId) {
        self.serve.read_started(&mut self.requests, id);
    }

    pub(super) fn read_refused(&mut self, id: RequestId, status: Status, now_us: u64) {
        self.serve
            .read_refused(&mut self.requests, id, status, now_us);
    }

    pub(super) fn chunk(
        &mut self,
        id: RequestId,
        manifest: Manifest,
        range: std::ops::Range<u64>,
        chunk: C,
        window_crcs: &[u32],
        now_us: u64,
    ) -> bool {
        self.serve.chunk(
            &mut self.requests,
            id,
            manifest,
            super::serve::ChunkInput {
                range,
                chunk,
                window_crcs,
            },
            now_us,
        )
    }

    pub(super) fn read_done(&mut self, id: RequestId, end: ReadEnd, now_us: u64) {
        self.serve.read_done(&mut self.requests, id, end, now_us);
    }

    pub(super) fn wants_grant(&self, id: RequestId) -> bool {
        self.serve.wants_grant(&self.requests, id)
    }

    pub(super) fn granted(&mut self, id: RequestId) {
        self.requests.get_granted(id);
    }

    pub(super) fn is_ended(&self, id: RequestId) -> bool {
        self.requests.get_is_ended(id)
    }

    pub(super) fn retained(&self, id: RequestId) -> usize {
        self.requests.get_retained(id)
    }

    pub(super) fn ack(&mut self, session: Admitted, header: &Header, now_us: u64) {
        self.serve.ack(&mut self.requests, session, header, now_us);
    }

    pub(super) fn cancel(&mut self, session: Admitted, header: &Header, now_us: u64) {
        self.serve
            .cancel(&mut self.requests, session, header, now_us);
    }

    pub(super) fn reap(&mut self) -> u32 {
        self.serve.reap(&mut self.requests)
    }

    pub(super) fn tick(&mut self, now_us: u64) {
        self.serve.tick(&mut self.requests, now_us);
    }

    pub(super) fn release_drained(&mut self, drained: impl FnMut(RequestId) -> bool) -> u32 {
        self.serve.release_drained(&mut self.requests, drained)
    }

    pub(super) fn retire_peer(&mut self, peer: PeerId, now_us: u64) {
        self.serve.retire_peer(&mut self.requests, peer, now_us);
        self.requests.retire(peer);
    }

    pub(super) fn poll<'a>(
        &mut self,
        now_us: u64,
        budget: usize,
        send: impl FnOnce(&mut dyn Iterator<Item = Out<'_, 'a>>) -> usize,
    ) -> usize
    where
        C: Retained<'a>,
    {
        self.serve.poll(&mut self.requests, now_us, budget, send)
    }

    pub(super) fn check_indexes(&self) {
        self.serve.check_indexes(&self.requests);
    }
}

pub(super) const CONFIG: ServeConfig = ServeConfig {
    retry_us: 1_000,
    attempts: 3,
    linger_us: 5_000,
    rate_per_sec: 1_000_000,
    burst: 1_000,
    slots: 8,
    replies: 8,
    max_wait_us: 1_000_000,
};

pub(super) fn session(window: u32) -> Admitted {
    Admitted {
        peer: PeerId(0),
        epoch: 4,
        caps: Caps { slots: 8, window },
    }
}

fn core() -> Core<Chunk> {
    let table = RequestTable::<Request<Chunk>>::new(4, 2, 2);
    Core::new(CONFIG, table, 2, 128, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap()
}

/// A GET for slot `slot` at `generation` with an initial grant of `grant`.
pub(super) fn get(slot: u16, generation: u64, grant: u32) -> Header {
    Header {
        kind: Kind::Get,
        principal: 1,
        key_epoch: 1,
        owner_nonce: [1; 16],
        client_nonce: [2; 16],
        request: RequestId::from_wire(u64::from(slot) << 48 | generation).wire(),
        sequence: 1,
        allocation: 0,
        total: 0,
        metadata_len: 1 << 10,
        body_len: 1 << 20,
        index: 0,
        count: 0,
        offset: 0,
        datagram_len: 0,
        grant,
        status: 0,
        remaining_ms: 100,
        key: [9; 32],
        epoch: 4,
        tag: [0; 16],
    }
}

pub(super) fn ack(get: &Header, manifest: &Manifest, base: u32, grant: u32) -> Header {
    Header {
        kind: Kind::Ack,
        allocation: manifest.allocation,
        total: manifest.total(),
        metadata_len: manifest.metadata_len,
        body_len: manifest.body_len,
        index: base,
        count: manifest.count(),
        grant,
        remaining_ms: 0,
        ..*get
    }
}

pub(super) fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|n| (n * 7 + 3) as u8).collect()
}

/// A sent frame: its header and payload concatenated, with the slice count.
#[derive(Debug)]
struct Sent {
    peer: PeerId,
    header: Header,
    bytes: Vec<u8>,
    slices: usize,
}

fn poll(core: &mut Core<Chunk>, now_us: u64) -> Vec<Sent> {
    let mut sent = Vec::new();
    core.poll(now_us, 64, |frames| {
        frames
            .map(|out| {
                sent.push(Sent {
                    peer: out.peer,
                    header: out.header,
                    bytes: [out.payload[0].bytes(), out.payload[1].bytes()].concat(),
                    slices: out.payload.iter().filter(|slice| !slice.is_empty()).count(),
                });
            })
            .count()
    });
    sent
}

fn kinds(sent: &[Sent]) -> Vec<(Kind, u32)> {
    sent.iter()
        .map(|frame| (frame.header.kind, frame.header.index))
        .collect()
}

/// Starts a GET and returns its table handle.
fn started(core: &mut Core<Chunk>, header: &Header, window: u32) -> RequestId {
    let GetOutcome::Read { id, .. } = core.get(session(window), header, 0) else {
        panic!("a new request");
    };
    core.read_started(id);
    id
}

/// Wire bytes of a DATA fragment carrying `payload` bytes, as the shaper charges them.
fn wire(payload: u64) -> u64 {
    (FRAME_OVERHEAD + HEADER_LEN) as u64 + payload
}

#[test]
fn get_end_notification_survives_release_until_consumed() {
    let mut core = core();
    assert!(!core.serve.take_ends());
    let request = get(0, 1, 1);
    let id = started(&mut core, &request, 1);
    assert!(!core.serve.take_ends());
    let cancel = Header {
        kind: Kind::Cancel,
        status: Status::Cancelled as u16,
        ..request
    };
    core.cancel(session(1), &cancel, 1);
    assert_eq!(core.release_drained(|_| true), 1);
    assert_eq!(core.requests().census().live(), 0);
    assert!(core.requests().get(id).is_none());
    assert!(core.serve.take_ends());
    assert!(!core.serve.take_ends());
}

/// A CANCEL received before its GET ends that wire slot's generation: the
/// late GET is dropped, and the slot's next generation admits.
#[test]
fn a_cancel_ahead_of_its_get_admits_no_read() {
    let mut core = core();
    let request = get(0, 1, 1);
    let cancel = Header {
        kind: Kind::Cancel,
        status: Status::Cancelled as u16,
        ..request
    };
    core.cancel(session(1), &cancel, 0);
    assert_eq!(core.requests().census().live(), 0);
    assert!(matches!(
        core.get(session(1), &request, 1),
        GetOutcome::Dropped
    ));
    assert_eq!(core.requests().census().live(), 0);
    assert!(matches!(
        core.get(session(1), &get(0, 2, 1), 2),
        GetOutcome::Read { .. }
    ));
}

/// A core shaped at the floor rate with a full bucket as of [`Shaper::CONTROL_US`], holding one GET per peer, each granted and retaining `fragments` full fragments.
pub(super) fn shaped_core(fragments: u32) -> Core<Chunk> {
    let table = RequestTable::<Request<Chunk>>::new(4, 2, 2);
    let mut core = Core::new(CONFIG, table, 2, 128, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    // A count that rose over an idle interval shapes the core at the floor and fills the bucket.
    core.control(0, Some(0));
    core.control(Shaper::CONTROL_US, Some(1));
    assert_eq!(core.report().shaped_bytes_per_s, Shaper::FLOOR);
    let body = fragments as usize * 8192;
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: body as u32,
    };
    for peer in [0, 1] {
        let admitted = Admitted {
            peer: PeerId(peer),
            ..session(fragments)
        };
        let GetOutcome::Read { id, .. } = core.get(admitted, &get(1, 0, fragments), 0) else {
            panic!("a new request");
        };
        core.read_started(id);
        core.chunk(id, manifest, 0..body as u64, payload(body).into(), &[], 0);
    }
    core
}

/// One frame of a shaped round, by its peer, kind and index.
type Framed = (PeerId, Kind, u32);

fn framed(sent: &[Sent]) -> Vec<Framed> {
    sent.iter()
        .map(|frame| (frame.peer, frame.header.kind, frame.header.index))
        .collect()
}

/// The frames a full bucket admits from [`shaped_core`]`(fragments)`, then the frame the shaper refuses and the bytes left in the bucket: the round visits the peers in turn, each visit stages the request's START then its fragments, up to [`DATA_BURST`] frames, and the first frame whose wire bytes exceed the bucket ends the round.
fn shaped_order(fragments: u32) -> (Vec<Framed>, Framed, u64) {
    let (mut sent, mut next, mut bucket) = (Vec::new(), [None::<u32>; 2], Shaper::BURST);
    loop {
        for (peer, next) in next.iter_mut().enumerate() {
            let mut burst = 0;
            while burst < DATA_BURST {
                let frame = match *next {
                    None => (PeerId(peer as u16), Kind::Start, 0),
                    Some(index) if index < fragments => (PeerId(peer as u16), Kind::Data, index),
                    Some(_) => break,
                };
                let bytes = if frame.1 == Kind::Start {
                    wire(0)
                } else {
                    wire(8192)
                };
                if bytes > bucket {
                    return (sent, frame, bucket);
                }
                bucket -= bytes;
                sent.push(frame);
                *next = Some(next.map_or(0, |index| index + 1));
                burst += 1;
            }
        }
    }
}

/// The shaper bounds the bytes all peers' request frames take together: a full bucket stages each request's START and the fragments that fit in burst order, the request it refuses keeps its turn, a frame that goes unsent returns its bytes, and the refill at the shaped rate admits the refused fragment first.
#[test]
fn a_throttled_request_is_first_once_bytes_refill() {
    let mut core = shaped_core(16);
    let at = Shaper::CONTROL_US;
    let first = poll(&mut core, at);
    let (expected, refused, left) = shaped_order(16);
    assert_eq!(
        framed(&first),
        expected,
        "each request's START and the fragments that fit, in bursts"
    );
    assert_eq!(
        expected.len(),
        2 + 15,
        "two STARTs and fifteen fragments fit"
    );
    let refill_us = (wire(8192) - left).div_ceil(Shaper::FLOOR / 1_000_000);
    assert!(
        poll(&mut core, at + refill_us - 1).is_empty(),
        "the bucket is below the refused fragment"
    );
    // An unsent frame returns its bytes, so the next poll offers it again.
    assert_eq!(
        core.poll(at + refill_us, 64, |frames| {
            frames.count();
            0
        }),
        0
    );
    let refilled = poll(&mut core, at + refill_us);
    assert_eq!(
        framed(&refilled),
        [refused],
        "the throttled request sends the refused fragment first"
    );
    core.check_indexes();
}

/// A data round whose bucket holds fewer bytes than the fragment the shaper refused visits no request; once the bucket refills to the fragment, or the refused request's state changes, the round visits again.
#[test]
fn a_round_below_the_refused_fragment_visits_no_request() {
    let mut core = shaped_core(16);
    let at = Shaper::CONTROL_US;
    let first = poll(&mut core, at);
    let (expected, refused, left) = shaped_order(16);
    assert_eq!(framed(&first), expected);
    let refill_us = (wire(8192) - left).div_ceil(Shaper::FLOOR / 1_000_000);
    take_send_visits();
    assert!(
        poll(&mut core, at + refill_us / 2).is_empty(),
        "part of a fragment refilled"
    );
    assert_eq!(
        take_send_visits(),
        0,
        "the bucket is below the refused fragment, so no request is visited"
    );
    let refilled = poll(&mut core, at + refill_us);
    assert_eq!(framed(&refilled), [refused]);
    assert!(
        take_send_visits() >= 1,
        "a full fragment refilled, so the round visits"
    );
    // The burst went on to the request's next fragment, which the shaper refused in turn.
    let refused = refused.0;
    let half = at + refill_us + wire(8192) / 2 / (Shaper::FLOOR / 1_000_000);
    assert!(poll(&mut core, half).is_empty(), "half a fragment refilled");
    assert_eq!(take_send_visits(), 0);
    // Cancelling the refused request makes the round visit requests again with only half a fragment refilled.
    let request = get(1, 0, 16);
    let cancel = Header {
        kind: Kind::Cancel,
        status: Status::Cancelled as u16,
        ..request
    };
    core.cancel(
        Admitted {
            peer: refused,
            ..session(16)
        },
        &cancel,
        half,
    );
    assert!(poll(&mut core, half).is_empty(), "half a fragment refilled");
    assert!(
        take_send_visits() >= 1,
        "the ended request was visited and passed over"
    );
    core.check_indexes();
}

/// Burst accounting spans polls: with one fragment's bytes refilled per poll, the throttled request finishes its remaining burst before the other peer receives a full burst.
#[test]
fn a_burst_the_shaper_splits_across_polls_still_yields() {
    let mut core = shaped_core(32);
    let at = Shaper::CONTROL_US;
    let (expected, refused, left) = shaped_order(32);
    assert_eq!(framed(&poll(&mut core, at)), expected);
    assert_eq!(
        refused,
        (PeerId(0), Kind::Data, DATA_BURST as u32),
        "the full bucket ends peer 0's second burst after one fragment"
    );
    let per_us = Shaper::FLOOR / 1_000_000;
    let mut now = at + (wire(8192) - left).div_ceil(per_us);
    let mut sent = Vec::new();
    for _ in 0..4 * DATA_BURST {
        sent.extend(framed(&poll(&mut core, now)));
        now += wire(8192).div_ceil(per_us);
    }
    let burst = DATA_BURST as u32;
    let mut order: Vec<Framed> = (burst..2 * burst - 1)
        .map(|index| (PeerId(0), Kind::Data, index))
        .collect();
    order.extend((burst - 1..2 * burst - 1).map(|index| (PeerId(1), Kind::Data, index)));
    order.push((PeerId(0), Kind::Data, 2 * burst - 1));
    assert_eq!(
        sent[..order.len()],
        order[..],
        "each burst ends after DATA_BURST frames however many polls it spans"
    );
    core.check_indexes();
}

/// Queues one refused GET per peer `each` times at `now_us`, so each peer holds `each` ERROR replies.
fn refuse(core: &mut Core<Chunk>, each: usize, now_us: u64) {
    for peer in [0, 1] {
        let admitted = Admitted {
            peer: PeerId(peer),
            ..session(8)
        };
        for _ in 0..each {
            // A grant above the session's window is refused.
            let refused = core.get(admitted, &get(2, 0, 9), now_us);
            assert_eq!(refused, GetOutcome::Refused(Status::InvalidRequest));
        }
    }
}

/// Replies take their wire bytes from the shaper: with every fragment sent, the queued ERROR replies drain the bucket at a header's bytes each, the round stops at the first reply the bucket cannot cover, and the next poll resumes there.
#[test]
fn replies_take_shaper_bytes() {
    let mut core = shaped_core(7);
    let at = Shaper::CONTROL_US;
    assert_eq!(
        poll(&mut core, at).len(),
        2 + 14,
        "every fragment fits the burst"
    );
    let per_us = Shaper::FLOOR / 1_000_000;
    let mut bucket = Shaper::BURST - 2 * wire(0) - 14 * wire(8192);
    let mut throttled = 0;
    for step in 1..=8 {
        refuse(&mut core, 8, at + step);
        let sent = poll(&mut core, at + step);
        assert!(sent.iter().all(|frame| frame.header.kind == Kind::Error));
        bucket += per_us;
        let expected = (bucket / wire(0)).min(16);
        assert_eq!(sent.len() as u64, expected, "poll {step}");
        bucket -= expected * wire(0);
        throttled += u64::from(expected < 16);
    }
    assert!(throttled >= 2, "the bucket ran below sixteen headers");
    core.check_indexes();
}

/// While a fragment waits on the shaper, replies spend only the bytes above its need, so its credit accumulates across polls although replies claim every refill; once it stages, the next poll's replies spend the refill, and both flows progress.
#[test]
fn replies_claiming_every_refill_leave_a_waiting_fragment_its_bytes() {
    let mut core = shaped_core(16);
    let at = Shaper::CONTROL_US;
    let first = poll(&mut core, at);
    let fits = ((Shaper::BURST - 2 * wire(0)) / wire(8192)) as usize;
    assert_eq!(first.len(), 2 + fits, "the burst leaves a fragment waiting");
    let per_us = Shaper::FLOOR / 1_000_000;
    // Each microsecond refills fewer bytes than the three replies queued per peer, so unreserved replies would claim every refill.
    assert!(3 * 2 * wire(0) > per_us);
    let (mut data, mut errors) = (0, 0);
    let polls = 200;
    for step in 1..=polls {
        refuse(&mut core, 3, at + step);
        for frame in poll(&mut core, at + step) {
            match frame.header.kind {
                Kind::Data => data += 1,
                Kind::Error => errors += 1,
                kind => panic!("unexpected {kind:?}"),
            }
        }
    }
    // A fragment needs about seventeen refills once replies leave it its bytes.
    let waits = wire(8192).div_ceil(per_us);
    assert!(
        data >= polls / (waits + 2) && data <= polls / waits + 1,
        "{data} fragments over {polls} polls, one per about {waits} refills"
    );
    assert!(
        errors >= data,
        "{errors} replies; the poll after each fragment spends the refill on replies"
    );
    core.check_indexes();
}

/// A batch of two, two refusals from peer 0 queued before every poll, and peer 1 holding request A with DATA fragments ready and request B with its ERROR pending; each of A's fragments and B's ERROR reaches the accepted prefix within `B_server` = 2 polls of becoming eligible.
///
/// Geometry: a staging capacity of 2, which caps each poll's budget at 2; an unshaped core, so the shaper admits every frame; per-peer pacing at one token per microsecond with a burst of 1,000, the clock advancing 1 µs per poll and peer 0 spending at most two tokens per poll, so pacing admits every frame; A holds 8 fragments under a grant of 8, and its START and fragment 0 go out before the flood starts; every send is accepted.
///
/// Derivation of `B_server`: peer 0's ring holds at least two replies at every poll, so a poll that stages replies first fills both sends with them while A or B is marked ready, and the next poll stages requests first. A requests-first round visits each ready request once, from the cursor, and stages one frame for each, so with A and B ready each stages one frame, and A alone stages up to two. A requests-first poll hands the next poll back to replies. An eligible frame therefore waits at most one replies-first poll and is staged in the poll after it.
#[test]
fn ready_requests_send_within_two_polls_beside_a_batch_two_reply_flood() {
    const B_SERVER: u64 = 2;
    let mut core = Core::<Chunk>::new(
        CONFIG,
        RequestTable::new(4, 2, 2),
        2,
        2,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let flooding = session(8);
    let served = Admitted {
        peer: PeerId(1),
        ..session(8)
    };
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 8 * 8192,
    };
    let GetOutcome::Read { id: a, .. } = core.get(served, &get(1, 0, 8), 0) else {
        panic!("a new request");
    };
    core.read_started(a);
    assert!(core.chunk(a, manifest, 0..8 * 8192, payload(8 * 8192).into(), &[], 0));
    core.read_done(a, ReadEnd::Complete(manifest), 0);
    assert_eq!(
        kinds(&poll(&mut core, 0)),
        [(Kind::Start, 0), (Kind::Data, 0)]
    );
    let GetOutcome::Read { id: b, .. } = core.get(served, &get(2, 0, 8), 0) else {
        panic!("a new request");
    };
    core.read_started(b);
    core.read_refused(b, Status::Missing, 0);
    // An episode starts when its frame becomes eligible: B's ERROR and A's fragment 1 at poll 1, and each later fragment of A at the poll after the one that sent its predecessor. A fragment that a second round stages in its predecessor's poll meets the bound at once.
    let (mut error_at, mut data_at) = (None, Vec::new());
    let mut eligible = 1;
    let mut flooded = 0;
    for step in 1..=40u64 {
        for _ in 0..2 {
            let refused = core.get(flooding, &get(2, 0, 9), step);
            assert_eq!(refused, GetOutcome::Refused(Status::InvalidRequest));
        }
        let sent = poll(&mut core, step);
        assert_eq!(sent.len(), 2, "poll {step} fills the batch");
        let replies = sent.iter().filter(|frame| frame.peer == PeerId(0)).count();
        flooded += u64::from(replies == 2);
        for frame in sent.iter().filter(|frame| frame.peer == PeerId(1)) {
            match frame.header.kind {
                Kind::Error => {
                    assert_eq!(frame.header.request, get(2, 0, 8).request);
                    assert!(error_at.is_none(), "B's ERROR is sent once");
                    error_at = Some(step);
                }
                Kind::Data => {
                    assert_eq!(frame.header.index as usize, data_at.len() + 1);
                    data_at.push(step);
                }
                kind => panic!("unexpected {kind:?} from peer 1"),
            }
        }
        if data_at.last() == Some(&step) {
            eligible = step + 1;
        }
        // A frame still unsent after this poll has waited `step - since + 1` polls; it fails once that reaches the bound.
        let within = |since: u64| step + 1 - since < B_SERVER;
        assert!(
            error_at.is_some() || within(1),
            "B's ERROR unsent by poll {step}"
        );
        assert!(
            data_at.len() == 7 || eligible > step || within(eligible),
            "fragment {} eligible at poll {eligible} unsent by poll {step}",
            data_at.len() + 1
        );
    }
    assert_eq!(data_at.len(), 7, "every granted fragment went out");
    // The witness: peer 1's eight frames go out two to a requests-first poll, so peer 0's replies alone fill the other 36 polls, and the flood overran peer 0's ring.
    assert_eq!(flooded, 36, "polls that sent only peer 0's replies");
    assert!(core.report().dropped_replies > 0);
    core.check_indexes();
}

/// For a scripted read of two buffers, the core sends START, every DATA fragment with at most two slices, and COMPLETE only after the final ACK; DATA bytes match the payload.
#[test]
fn a_scripted_read_sends_start_data_and_complete() {
    let mut core = core();
    let request = get(1, 0, 8);
    let id = started(&mut core, &request, 8);
    let data = payload(20_000);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 1000,
        body_len: 19_000,
    };
    // The first buffer holds 12,000 payload bytes, the second the rest, so fragment 1 spans both.
    assert!(core.chunk(id, manifest, 0..12_000, data[..12_000].into(), &[], 0));
    assert!(
        core.wants_grant(id),
        "one buffer held and the grant admits fragment 1"
    );
    core.granted(id);
    assert!(
        !core.wants_grant(id),
        "two buffers counting the outstanding command"
    );
    assert!(core.chunk(id, manifest, 12_000..20_000, data[12_000..].into(), &[], 0));
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    let sent = poll(&mut core, 0);
    assert_eq!(
        kinds(&sent),
        [
            (Kind::Start, 0),
            (Kind::Data, 0),
            (Kind::Data, 1),
            (Kind::Data, 2)
        ]
    );
    let mut body = Vec::new();
    for frame in &sent[1..] {
        assert!(frame.slices <= 2);
        assert_eq!(frame.header.offset, u64::from(frame.header.index) * 8192);
        assert_eq!(frame.header.count, 3);
        assert_eq!(frame.header.request, request.request);
        body.extend_from_slice(&frame.bytes);
    }
    assert_eq!(sent[2].slices, 2, "fragment 1 crosses the buffer boundary");
    assert_eq!(body, data);
    assert!(
        poll(&mut core, 0).is_empty(),
        "COMPLETE waits for the final ACK"
    );
    core.ack(session(8), &ack(&request, &manifest, 3, 11), 0);
    assert_eq!(core.retained(id), 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Complete, 3)]);
    assert!(core.is_ended(id));
    assert_eq!(
        core.release_drained(|_| false),
        0,
        "custody holds until the read drained"
    );
    assert_eq!(core.requests().census().draining, 1);
    assert_eq!(core.release_drained(|of| of == id), 1);
    assert_eq!(core.requests().census(), Default::default());
}

/// The hand-over builds every frame's header from the request's state: START, DATA and COMPLETE carry the request's wire ID, key and manifest, DATA its fragment's index, offset and length, and a refusal's ERROR its status; frames a partial batch leaves are offered again with the same header, payload and body crc.
#[test]
fn handed_over_frames_carry_their_headers_and_repeat_unchanged_when_left() {
    let mut core = core();
    let request = get(1, 0, 8);
    let id = started(&mut core, &request, 8);
    let data = payload(2 * 8192 + 100);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 100,
        body_len: 2 * 8192,
    };
    assert!(core.chunk(
        id,
        manifest,
        0..data.len() as u64,
        data.clone().into(),
        &[],
        0
    ));
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    let other = Admitted {
        peer: PeerId(1),
        ..session(2)
    };
    let refused = get(2, 0, 9);
    assert!(matches!(
        core.get(other, &refused, 0),
        GetOutcome::Refused(Status::InvalidRequest)
    ));
    let mut offered: Vec<(PeerId, Header, Vec<u8>, u32)> = Vec::new();
    let taken = core.poll(0, 8, |frames| {
        frames
            .map(|out| {
                let bytes = [out.payload[0].bytes(), out.payload[1].bytes()].concat();
                offered.push((out.peer, out.header, bytes, out.body_crc));
            })
            .count()
            .min(1)
    });
    assert_eq!(taken, 1);
    let offered_kinds: Vec<Kind> = offered
        .iter()
        .map(|(_, header, _, _)| header.kind)
        .collect();
    assert_eq!(
        offered_kinds,
        [Kind::Error, Kind::Start, Kind::Data, Kind::Data, Kind::Data]
    );
    let (peer, error, bytes, _) = &offered[0];
    assert_eq!(
        (*peer, error.request, error.key),
        (PeerId(1), refused.request, refused.key)
    );
    assert_eq!(error.status, Status::InvalidRequest as u16);
    assert!(bytes.is_empty());
    for (peer, header, bytes, crc) in &offered[1..] {
        assert_eq!(*peer, PeerId(0));
        assert_eq!((header.request, header.key), (request.request, request.key));
        assert_eq!(
            (
                header.allocation,
                header.metadata_len,
                header.body_len,
                header.total,
                header.count
            ),
            (7, 100, 2 * 8192, manifest.total(), 3)
        );
        if header.kind == Kind::Data {
            let range = u64::from(header.index) * 8192..;
            assert_eq!(header.offset, u64::from(header.index) * 8192);
            assert_eq!(header.datagram_len as usize, bytes.len());
            assert_eq!(bytes, &data[range.start as usize..][..bytes.len()]);
            assert_eq!(*crc, crate::storage::Crc32c::detect().checksum(bytes));
        } else {
            assert!(bytes.is_empty());
        }
    }
    let mut again: Vec<(PeerId, Header, Vec<u8>, u32)> = Vec::new();
    core.poll(0, 8, |frames| {
        frames
            .map(|out| {
                let bytes = [out.payload[0].bytes(), out.payload[1].bytes()].concat();
                again.push((out.peer, out.header, bytes, out.body_crc));
            })
            .count()
    });
    assert_eq!(
        again,
        offered[1..],
        "the frames the transport left repeat byte for byte"
    );
    core.ack(session(8), &ack(&request, &manifest, 3, 8), 0);
    let complete = poll(&mut core, 0);
    assert_eq!(kinds(&complete), [(Kind::Complete, 3)]);
    assert_eq!(
        (
            complete[0].header.request,
            complete[0].header.key,
            complete[0].header.total
        ),
        (request.request, request.key, manifest.total())
    );
}

/// A chunk stays retained until the cumulative base passes its last fragment; an ACK that names another manifest, an unsent fragment, a lower base, a lower grant or a grant past the window changes nothing.
#[test]
fn chunks_release_only_behind_the_receipt_base_and_bad_acks_change_nothing() {
    let mut core = core();
    let request = get(2, 0, 2);
    let id = started(&mut core, &request, 2);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 16_384,
    };
    core.chunk(id, manifest, 0..16_384, payload(16_384).into(), &[], 0);
    let sent = poll(&mut core, 0);
    assert_eq!(
        kinds(&sent),
        [(Kind::Start, 0), (Kind::Data, 0), (Kind::Data, 1)]
    );
    let stale = core.report().stale_acks;
    core.ack(session(2), &ack(&request, &manifest, 3, 2), 0);
    core.ack(session(2), &ack(&request, &manifest, 1, 9), 0);
    core.ack(
        session(2),
        &Header {
            allocation: 8,
            ..ack(&request, &manifest, 1, 2)
        },
        0,
    );
    assert_eq!(core.report().stale_acks, stale + 3);
    assert_eq!(core.retained(id), 1);
    core.ack(session(2), &ack(&request, &manifest, 1, 3), 0);
    assert_eq!(core.retained(id), 1, "fragment 1 is still unacknowledged");
    core.ack(session(2), &ack(&request, &manifest, 0, 3), 0);
    assert_eq!(core.report().stale_acks, stale + 4, "a lower base");
    core.ack(session(2), &ack(&request, &manifest, 1, 2), 0);
    assert_eq!(core.report().stale_acks, stale + 5, "a lower grant");
    core.ack(session(2), &ack(&request, &manifest, 2, 3), 0);
    assert_eq!(core.retained(id), 0);
}

/// The first send of a fragment needs the cumulative grant; with a window of 1 each fragment waits for the grant its predecessor's release adds.
#[test]
fn a_window_of_one_sends_one_new_fragment_per_grant() {
    let mut core = core();
    let request = get(3, 0, 1);
    let id = started(&mut core, &request, 1);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 3 * 8192,
    };
    core.chunk(id, manifest, 0..3 * 8192, payload(3 * 8192).into(), &[], 0);
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    assert_eq!(
        kinds(&poll(&mut core, 0)),
        [(Kind::Start, 0), (Kind::Data, 0)]
    );
    for index in 1..3 {
        assert!(
            poll(&mut core, 0).is_empty(),
            "no grant for fragment {index}"
        );
        core.ack(session(1), &ack(&request, &manifest, index, index + 1), 0);
        assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Data, index)]);
    }
    core.ack(session(1), &ack(&request, &manifest, 3, 4), 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Complete, 3)]);
}

/// A window of 4096 admits every fragment of a large transfer at once.
#[test]
fn a_window_of_4096_sends_every_fragment_without_waiting() {
    let mut core = core();
    let request = get(4, 0, 4096);
    let id = started(&mut core, &request, 4096);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 40 * 8192,
    };
    core.chunk(
        id,
        manifest,
        0..40 * 8192,
        payload(40 * 8192).into(),
        &[],
        0,
    );
    let mut sent = Vec::new();
    core.poll(0, 100, |frames| {
        frames.map(|out| sent.push(out.header.kind)).count()
    });
    assert_eq!(sent.len(), 41);
}

/// A lost START and lost DATA are resent from the base after the retry interval; a lost COMPLETE is recovered when the client's repeated final ACK replays the cached COMPLETE; exhausting the attempts ends the request with one ERROR.
#[test]
fn lost_frames_recover_by_retries_and_exhaustion_ends_once() {
    let mut core = core();
    let request = get(5, 0, 4);
    let id = started(&mut core, &request, 4);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 2 * 8192,
    };
    core.chunk(id, manifest, 0..2 * 8192, payload(2 * 8192).into(), &[], 0);
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    assert_eq!(
        poll(&mut core, 0).len(),
        3,
        "START and both fragments, all lost"
    );
    core.tick(500);
    assert!(poll(&mut core, 500).is_empty(), "before the retry interval");
    core.tick(1_000);
    assert_eq!(
        kinds(&poll(&mut core, 1_000)),
        [(Kind::Start, 0), (Kind::Data, 0), (Kind::Data, 1)]
    );
    core.ack(session(4), &ack(&request, &manifest, 1, 5), 1_100);
    core.tick(2_100);
    assert_eq!(
        kinds(&poll(&mut core, 2_100)),
        [(Kind::Data, 1)],
        "the retry restarts at the base"
    );
    core.ack(session(4), &ack(&request, &manifest, 2, 6), 2_200);
    assert_eq!(kinds(&poll(&mut core, 2_200)), [(Kind::Complete, 2)]);
    // The COMPLETE was lost: the client's repeated final ACK replays it.
    core.ack(session(4), &ack(&request, &manifest, 2, 6), 2_300);
    assert_eq!(kinds(&poll(&mut core, 2_300)), [(Kind::Complete, 2)]);
    assert_eq!(core.report().completed, 1);
    // A second request whose client never answers.
    let silent = get(6, 0, 4);
    let other = started(&mut core, &silent, 4);
    core.chunk(
        other,
        manifest,
        0..2 * 8192,
        payload(2 * 8192).into(),
        &[],
        3_000,
    );
    poll(&mut core, 3_000);
    let mut errors = 0;
    // Three retries at waits of one, two and four intervals, then the end eight intervals later.
    for step in 1..=20 {
        core.tick(3_000 + step * 1_000);
        errors += poll(&mut core, 3_000 + step * 1_000)
            .iter()
            .filter(|frame| frame.header.kind == Kind::Error)
            .inspect(|frame| assert_eq!(frame.header.status, Status::TimedOut as u16))
            .count();
    }
    assert_eq!(errors, 1, "exactly one terminal");
    assert!(core.is_ended(other));
}

/// A receipt mask resends exactly the holes below the highest held fragment, once per guard interval: a repeated mask within the interval resends nothing, a mask after it resends the holes still open, a mask naming an unsent fragment is stale, and the base passing a hole drops it. The slow retry still restarts from the base and clears the queued holes.
#[test]
fn a_receipt_mask_resends_only_the_holes_once_per_guard_interval() {
    let mut core = core();
    let request = get(5, 0, 8);
    let id = started(&mut core, &request, 8);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 6 * 8192,
    };
    core.chunk(id, manifest, 0..6 * 8192, payload(6 * 8192).into(), &[], 0);
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    assert_eq!(poll(&mut core, 0).len(), 7, "START and six fragments");
    // Fragments 2, 3 and 5 held: holes at 0, 1 and 4.
    let mut gap = ack(&request, &manifest, 0, 8);
    gap.offset = 0b10110;
    core.ack(session(8), &gap, HOLE_GUARD_US);
    assert_eq!(
        kinds(&poll(&mut core, HOLE_GUARD_US)),
        [(Kind::Data, 0), (Kind::Data, 1), (Kind::Data, 4)],
        "the holes, in order, and nothing else"
    );
    assert_eq!(core.report().hole_resends, 3);
    core.ack(session(8), &gap, HOLE_GUARD_US + 100);
    assert!(
        poll(&mut core, HOLE_GUARD_US + 100).is_empty(),
        "the same mask inside the guard interval resends nothing"
    );
    // Fragments 0 and 1 arrived: the base moves to 4 and the mask shows 5 held.
    let mut later = ack(&request, &manifest, 4, 12);
    later.offset = 0b1;
    core.ack(session(8), &later, HOLE_GUARD_US + 200);
    assert!(
        poll(&mut core, HOLE_GUARD_US + 200).is_empty(),
        "the hole at 4 was resent inside the guard interval"
    );
    core.ack(session(8), &later, 2 * HOLE_GUARD_US + 200);
    assert_eq!(
        kinds(&poll(&mut core, 2 * HOLE_GUARD_US + 200)),
        [(Kind::Data, 4)],
        "after the guard interval the open hole is resent again"
    );
    let mut unsent = ack(&request, &manifest, 4, 12);
    unsent.offset = 0b100;
    let stale = core.report().stale_acks;
    core.ack(session(8), &unsent, 3 * HOLE_GUARD_US);
    assert_eq!(
        core.report().stale_acks,
        stale + 1,
        "a mask naming fragment 7, which was never sent, is stale"
    );
    assert!(poll(&mut core, 3 * HOLE_GUARD_US).is_empty());
    core.tick(3 * HOLE_GUARD_US + 1_000);
    assert_eq!(
        kinds(&poll(&mut core, 3 * HOLE_GUARD_US + 1_000)),
        [(Kind::Data, 4), (Kind::Data, 5)],
        "the retry restarts from the base"
    );
    core.ack(
        session(8),
        &ack(&request, &manifest, 6, 14),
        3 * HOLE_GUARD_US + 1_100,
    );
    assert_eq!(
        kinds(&poll(&mut core, 3 * HOLE_GUARD_US + 1_100)),
        [(Kind::Complete, 6)]
    );
    assert_eq!(core.report().hole_resends, 4);
    core.check_indexes();
}

/// A hole frame the transport refuses counts as no resend: the report counts hole resends among the frames the caller accepted, so a partial send leaves the count at the accepted hole frames and the next poll offers the refused hole again.
#[test]
fn an_unsent_hole_frame_counts_no_resend() {
    let mut core = core();
    let request = get(5, 0, 8);
    let id = started(&mut core, &request, 8);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 6 * 8192,
    };
    core.chunk(id, manifest, 0..6 * 8192, payload(6 * 8192).into(), &[], 0);
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    assert_eq!(poll(&mut core, 0).len(), 7, "START and six fragments");
    let mut gap = ack(&request, &manifest, 0, 8);
    gap.offset = 0b10110;
    core.ack(session(8), &gap, HOLE_GUARD_US);
    // The transport takes the first hole frame and refuses the other two.
    assert_eq!(
        core.poll(HOLE_GUARD_US, 64, |frames| {
            assert_eq!(frames.count(), 3);
            1
        }),
        1
    );
    assert_eq!(core.report().hole_resends, 1, "one hole frame left");
    assert_eq!(
        kinds(&poll(&mut core, HOLE_GUARD_US)),
        [(Kind::Data, 1), (Kind::Data, 4)],
        "the refused holes stay queued"
    );
    assert_eq!(core.report().hole_resends, 3);
    core.check_indexes();
}

/// A duplicate GET tightens the deadline and requeues the unacknowledged work without a new read; a conflicting duplicate is refused; after the request ended, a duplicate replays its terminal within the horizon and drops after it; an older generation drops.
#[test]
fn duplicates_and_cached_terminals_follow_their_horizon() {
    let mut core = core();
    let request = get(1, 3, 2);
    let id = started(&mut core, &request, 2);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 100,
    };
    core.chunk(id, manifest, 0..100, payload(100).into(), &[], 0);
    poll(&mut core, 0);
    assert_eq!(
        core.get(
            session(2),
            &Header {
                remaining_ms: 1,
                ..request
            },
            0
        ),
        GetOutcome::Duplicate
    );
    assert_eq!(
        kinds(&poll(&mut core, 0)),
        [(Kind::Start, 0), (Kind::Data, 0)]
    );
    core.tick(1_000);
    let ended = poll(&mut core, 1_000);
    assert_eq!(
        kinds(&ended),
        [(Kind::Error, 0)],
        "the tightened deadline ended it"
    );
    assert_eq!(
        core.get(
            session(2),
            &Header {
                grant: 1,
                ..request
            },
            1_000
        ),
        GetOutcome::Refused(Status::ConflictingRequest)
    );
    poll(&mut core, 1_000);
    assert_eq!(core.get(session(2), &request, 2_000), GetOutcome::Replayed);
    let replay = poll(&mut core, 2_000);
    assert_eq!(
        (replay[0].header.kind, replay[0].header.status),
        (Kind::Error, Status::TimedOut as u16)
    );
    core.tick(6_000);
    assert_eq!(
        core.get(session(2), &request, 6_000),
        GetOutcome::Dropped,
        "past the horizon"
    );
    assert_eq!(
        core.get(session(2), &get(1, 2, 2), 6_000),
        GetOutcome::Dropped,
        "an older generation"
    );
    assert_eq!(core.requests().census().draining, 1);
    let GetOutcome::Read { id: next, .. } = core.get(session(2), &get(1, 4, 2), 6_000) else {
        panic!("the sent terminal freed the wire binding");
    };
    assert_ne!(next.slot(), id.slot());
    assert!(core.requests().get(id).is_some());
    assert_eq!(core.release_drained(|ended| ended == id), 1);
    assert!(core.requests().get(next).is_some());
    assert_eq!(core.requests().census().active, 1);
    assert_eq!(core.requests().census().draining, 0);
}

/// A CANCEL stops sends and drops the retained chunks while the request keeps its table slot until the drain predicate holds; manifest caps refuse an oversize object with TooLarge.
#[test]
fn cancel_and_oversize_end_with_custody_held() {
    let mut core = core();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 9000,
    };
    core.chunk(id, manifest, 0..9000, payload(9000).into(), &[], 0);
    core.cancel(
        session(2),
        &Header {
            kind: Kind::Cancel,
            status: Status::Cancelled as u16,
            metadata_len: 0,
            body_len: 0,
            grant: 0,
            remaining_ms: 0,
            ..request
        },
        0,
    );
    assert!(poll(&mut core, 0).is_empty());
    assert_eq!(core.retained(id), 0);
    assert_eq!(core.requests().census().draining, 1);
    let small = Header {
        body_len: 10,
        ..get(2, 0, 2)
    };
    let big = started(&mut core, &small, 2);
    assert!(!core.chunk(big, manifest, 0..9000, payload(9000).into(), &[], 0));
    let sent = poll(&mut core, 0);
    assert_eq!(
        (sent[0].header.kind, sent[0].header.status),
        (Kind::Error, Status::TooLarge as u16)
    );
    assert!(
        !sent.iter().any(|frame| frame.header.kind == Kind::Start),
        "no manifest for a refused object"
    );
}

/// The shaper admits everything until a control step sees the allowance exceeded, then shapes at seven eighths of the egress it measured; later steps lower the rate by an eighth while the count rises and raise it by the step while it holds, never below the floor; the bucket admits a burst at once and refills at the rate.
#[test]
fn shaping_follows_the_allowance_exceeded_count() {
    let mut shaper = Shaper::new(0);
    assert_eq!(shaper.rate(), Shaper::UNSHAPED);
    assert_eq!(shaper.control_due_us(), Shaper::CONTROL_US);
    // Taken and refunded bytes leave the interval's egress, so the measured rate below counts only the bytes that stayed taken.
    for _ in 0..1_000 {
        assert!(shaper.take(0, 8_384), "unshaped");
        shaper.refund(8_384);
    }
    // 20 MB over the first 20 ms: 1 GB/s. The first step records the count; the second sees it rise.
    for _ in 0..2_500 {
        assert!(shaper.take(0, 8_000), "unshaped");
    }
    shaper.control(Shaper::CONTROL_US, Some(10));
    assert_eq!(
        shaper.rate(),
        Shaper::UNSHAPED,
        "the first step records the count"
    );
    for _ in 0..2_500 {
        assert!(shaper.take(Shaper::CONTROL_US, 8_000), "unshaped");
    }
    shaper.control(2 * Shaper::CONTROL_US, Some(11));
    let shaped = 1_000_000_000 - 1_000_000_000 / 8;
    assert_eq!(
        shaper.rate(),
        shaped,
        "seven eighths of the measured egress"
    );
    let at = 2 * Shaper::CONTROL_US;
    let burst = (0..100).take_while(|_| shaper.take(at, 8_384)).count() as u64;
    assert_eq!(burst, Shaper::BURST / 8_384, "a full bucket at once");
    assert!(
        !shaper.take(at + 1, 8_384),
        "one microsecond refills less than a datagram"
    );
    let refill_us = 8_384 * 1_000_000 / shaped + 1;
    assert!(
        shaper.take(at + refill_us, 8_384),
        "refilled at the shaped rate"
    );
    shaper.refund(8_384);
    assert!(
        shaper.take(at + refill_us, 8_384),
        "a refund returns the bytes"
    );
    assert!(!shaper.take(at + refill_us, 8_384), "and only the bytes");
    shaper.control(3 * Shaper::CONTROL_US, Some(11));
    assert_eq!(
        shaper.rate(),
        shaped + Shaper::STEP,
        "a held count raises the rate by the step"
    );
    let mut rate = shaper.rate();
    for step in 4..200 {
        shaper.control(step * Shaper::CONTROL_US, Some(11 + step));
        rate = (rate - rate / 8).max(Shaper::FLOOR);
        assert_eq!(shaper.rate(), rate, "step {step}");
    }
    assert_eq!(
        shaper.rate(),
        Shaper::FLOOR,
        "a rising count never lowers the rate below the floor"
    );
}

/// Under a backlog, shaped egress measures the shaper's own rate. A count that rises at every step keeps the rate nonincreasing until [`Shaper::FLOOR`].
#[test]
fn a_rising_count_under_a_backlog_never_raises_the_rate() {
    let mut shaper = Shaper::new(0);
    let datagram = (FRAME_OVERHEAD + HEADER_LEN) as u64 + 8192;
    let backlog = |shaper: &mut Shaper, from: u64| {
        for at in (from..from + Shaper::CONTROL_US).step_by(2) {
            shaper.take(at, datagram);
        }
    };
    backlog(&mut shaper, 0);
    shaper.control(Shaper::CONTROL_US, Some(0));
    backlog(&mut shaper, Shaper::CONTROL_US);
    shaper.control(2 * Shaper::CONTROL_US, Some(1));
    let shaped = shaper.rate();
    assert!(shaped < Shaper::UNSHAPED && shaped > Shaper::FLOOR);
    let mut rate = shaped;
    for step in 3..40 {
        backlog(&mut shaper, (step - 1) * Shaper::CONTROL_US);
        shaper.control(step * Shaper::CONTROL_US, Some(step));
        assert!(
            shaper.rate() <= rate,
            "step {step}: the rate rose from {rate} to {} while the count kept rising",
            shaper.rate()
        );
        rate = shaper.rate();
    }
    assert_eq!(
        rate,
        Shaper::FLOOR,
        "a count that never stops rising reaches the floor"
    );
}

/// The first cut starts from the measured egress, bounded by the ceiling as every later rate is.
#[test]
fn the_first_cut_stays_within_the_ceiling() {
    let mut shaper = Shaper::new(0);
    shaper.control(Shaper::CONTROL_US, Some(0));
    assert!(shaper.take(Shaper::CONTROL_US + 1, 1 << 31), "unshaped");
    shaper.control(2 * Shaper::CONTROL_US, Some(1));
    assert_eq!(shaper.rate(), Shaper::CEILING);
}

#[test]
fn a_step_without_a_count_keeps_the_baseline() {
    let mut shaper = Shaper::new(0);
    shaper.control(Shaper::CONTROL_US, None);
    assert_eq!(shaper.control_due_us(), 2 * Shaper::CONTROL_US);
    assert_eq!(shaper.rate(), Shaper::UNSHAPED);
    shaper.control(2 * Shaper::CONTROL_US, Some(10));
    shaper.control(3 * Shaper::CONTROL_US, None);
    assert_eq!(shaper.rate(), Shaper::UNSHAPED, "no count, no rise");
    shaper.control(4 * Shaper::CONTROL_US, Some(11));
    assert_eq!(
        shaper.rate(),
        Shaper::FLOOR,
        "the rise across the gap shapes"
    );
    shaper.control(5 * Shaper::CONTROL_US, None);
    assert_eq!(
        shaper.rate(),
        Shaper::FLOOR,
        "no count keeps the learned rate"
    );
    assert_eq!(shaper.control_due_us(), 6 * Shaper::CONTROL_US);
}

/// Two shapers under the qualified equal-share claim, stepped by literal counts at equal control periods.
/// Shaped at seven eighths of measured egresses of 10 and 2 GB/s, they hold 8.75 and 1.75 GB/s, a 5:1 ratio one shared cut leaves in place, so backing off together alone leaves the shares unequal.
/// Each later shared rise cuts both rates by an eighth, so the difference after `k` cuts stays within `k` bytes per second of `d_0 * 7^k / 8^k`, each cut rounding each rate up by less than one byte per second: earlier errors shrink by seven eighths per cut, so they sum below `k`, and the floored expected value adds less than one byte, so the integer gap is at most `k`; three held steps add [`Shaper::STEP`] to both, leaving the difference and lowering the faster shaper's share; the cut that takes the lower rate below [`Shaper::FLOOR`] clamps it there, and the difference leaves the seven-eighths law, since the lower rate no longer falls with the higher.
/// Once shaped, a step reads the rate and not the interval's egress, so the backlog after shaping is the shapers' own output and the test drives no further egress.
/// With `withheld`, the faster shaper's step at that later cut sees its count unchanged, one shaper missing a shared rise, which premise (a) excludes.
fn two_shapers_converge_in_shared_cuts(withheld: Option<u32>) {
    const DURATION: u64 = Shaper::CONTROL_US;
    let (mut fast, mut slow) = (Shaper::new(0), Shaper::new(0));
    // Egress over one control interval at `bytes_per_s`, in 8 000-byte datagrams.
    let egress = |shaper: &mut Shaper, at: u64, bytes_per_s: u64| {
        for _ in 0..bytes_per_s / 1_000_000 * DURATION / 8_000 {
            assert!(shaper.take(at, 8_000), "unshaped");
        }
    };
    egress(&mut fast, 0, 10_000_000_000);
    egress(&mut slow, 0, 2_000_000_000);
    let (mut at, mut count) = (DURATION, 0);
    fast.control(at, Some(count));
    slow.control(at, Some(count));
    egress(&mut fast, at, 10_000_000_000);
    egress(&mut slow, at, 2_000_000_000);
    (at, count) = (at + DURATION, count + 1);
    fast.control(at, Some(count));
    slow.control(at, Some(count));
    assert_eq!(
        (fast.rate(), slow.rate()),
        (8_750_000_000, 1_750_000_000),
        "one shared cut keeps the 5:1 ratio"
    );
    let d_0 = fast.rate() - slow.rate();
    for k in 1..=9u32 {
        at += DURATION;
        count += 1;
        let missed = withheld == Some(k);
        fast.control(at, Some(if missed { count - 1 } else { count }));
        slow.control(at, Some(count));
        let d = fast.rate() - slow.rate();
        let expected = (u128::from(d_0) * 7u128.pow(k) / 8u128.pow(k)) as u64;
        assert!(
            d.abs_diff(expected) <= u64::from(k),
            "event {k}: difference {d} off the contraction {expected} by more than {k}"
        );
    }
    assert!(slow.rate() > Shaper::FLOOR, "both still above the floor");
    let (held_fast, held_slow) = (fast.rate(), slow.rate());
    let d = held_fast - held_slow;
    for _ in 0..3 {
        at += DURATION;
        fast.control(at, Some(count));
        slow.control(at, Some(count));
    }
    assert_eq!(
        (fast.rate(), slow.rate()),
        (held_fast + 3 * Shaper::STEP, held_slow + 3 * Shaper::STEP),
        "held steps add the step to both and leave the difference"
    );
    assert!(
        u128::from(fast.rate()) * u128::from(held_slow)
            < u128::from(held_fast) * u128::from(slow.rate()),
        "held steps lower the faster shaper's share"
    );
    at += DURATION;
    count += 1;
    fast.control(at, Some(count));
    slow.control(at, Some(count));
    assert_eq!(
        slow.rate(),
        Shaper::FLOOR,
        "the cut clamps the lower rate at the floor"
    );
    let law = d - d / 8;
    let clamped = fast.rate() - slow.rate();
    assert!(
        clamped + 1 < law,
        "the clamp leaves the seven-eighths law: {clamped} against {law}"
    );
}

#[test]
fn two_shaped_shapers_contract_their_difference_by_seven_eighths_per_shared_cut() {
    two_shapers_converge_in_shared_cuts(None);
}

/// The faster shaper misses the third shared rise: its step adds [`Shaper::STEP`] while the slower one cuts, and the difference grows at that event.
#[test]
#[should_panic(expected = "event 3: difference")]
fn negative_control_a_rise_one_shaper_misses_breaks_the_contraction() {
    two_shapers_converge_in_shared_cuts(Some(3));
}

/// The pacer admits at most its burst at once and then one datagram per refill interval, keeping fractional credit and capping a late wake at the burst.
#[test]
fn pacing_keeps_rate_burst_and_fractional_refill() {
    let mut pacer = Pacer::new(1_000, 3, 0);
    assert!((0..3).all(|_| pacer.take(0)));
    assert!(!pacer.take(0));
    assert_eq!(pacer.ready_at(0), 1_000);
    assert!(!pacer.take(999));
    assert!(pacer.take(1_000));
    assert!(!pacer.take(1_500), "half a token");
    assert!(pacer.take(2_000), "the fraction carried over");
    let sent = (0..10).filter(|_| pacer.take(1_000_000)).count();
    assert_eq!(sent, 3, "a late wake spends at most the burst");
    let mut core = Core::<Chunk>::new(
        ServeConfig {
            rate_per_sec: 1_000,
            burst: 2,
            ..CONFIG
        },
        RequestTable::new(4, 2, 2),
        2,
        128,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let request = get(1, 0, 8);
    let id = started(&mut core, &request, 8);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 5 * 8192,
    };
    core.chunk(id, manifest, 0..5 * 8192, payload(5 * 8192).into(), &[], 0);
    assert_eq!(poll(&mut core, 0).len(), 2, "the burst");
    assert_eq!(poll(&mut core, 999).len(), 0);
    assert_eq!(poll(&mut core, 1_000).len(), 1);
}

/// Steady-state GET, chunk, ACK, poll, tick and release allocate nothing.
#[test]
fn steady_state_serving_allocates_nothing() {
    let mut core = core();
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 3 * 8192,
    };
    let chunks: Vec<Chunk> = (0..4).map(|_| payload(3 * 8192).into()).collect();
    let mut count = 0;
    let allocations = crate::instrument::allocations();
    for (generation, chunk) in chunks.into_iter().enumerate() {
        let request = get(1, generation as u64, 4);
        let GetOutcome::Read { id, .. } = core.get(session(4), &request, 0) else {
            panic!("new");
        };
        core.read_started(id);
        core.chunk(id, manifest, 0..3 * 8192, chunk, &[], 0);
        core.read_done(id, ReadEnd::Complete(manifest), 0);
        count += core.poll(0, 64, |frames| frames.count());
        core.tick(2_000);
        count += core.poll(2_000, 64, |frames| frames.count());
        assert_eq!(core.get(session(4), &request, 2_000), GetOutcome::Duplicate);
        core.ack(session(4), &ack(&request, &manifest, 3, 7), 2_000);
        count += core.poll(2_000, 64, |frames| frames.count());
        core.release_drained(|_| true);
        assert_eq!(core.get(session(4), &request, 2_000), GetOutcome::Replayed);
        assert!(matches!(
            core.get(
                session(4),
                &Header {
                    grant: 9,
                    ..request
                },
                2_000
            ),
            GetOutcome::Refused(_)
        ));
        count += core.poll(2_000, 64, |frames| frames.count());
    }
    assert_eq!(crate::instrument::allocations(), allocations);
    assert!(count > 4 * 5, "{count}");
}

/// Over seeded histories of GETs, duplicates, refusals, chunks under the read-grant policy, read ends, ACKs, cancels, ticks and partial drains, every live request is counted active or draining exactly once, retained chunks plus an outstanding command stay within two buffers, retention matches the receipt base, an ended request holds no chunk, a request leaves the table only through a drain the predicate proved, and the ready bits, due times, ended bits and tick bound that let calls skip requests cover every request that could act; completions, errors and retries all occur.
#[test]
fn seeded_histories_conserve_requests_and_retention() {
    use crate::storage::seeded::SplitMix64;
    struct Live {
        id: RequestId,
        request: Header,
        manifest: Manifest,
        offered: u64,
        commanded: bool,
        base: u32,
    }
    let mut totals = (0u64, 0u64, 0u64);
    for seed in 0..24u64 {
        let mut rng = SplitMix64::new(seed);
        let mut core = core();
        let mut live: Vec<Live> = Vec::new();
        let mut drained_ok: Vec<RequestId> = Vec::new();
        let mut generation = 0u64;
        let mut now = 0u64;
        for _ in 0..500 {
            now += rng.below(400);
            match rng.below(9) {
                0 => {
                    let slot = rng.below(8) as u16;
                    generation += 1;
                    let request = get(slot, generation, 1 + rng.below(4) as u32);
                    if let GetOutcome::Read { id, .. } = core.get(session(4), &request, now) {
                        core.read_started(id);
                        let body = rng.below(4 * 8192) as u32;
                        let manifest = Manifest {
                            allocation: generation,
                            metadata_len: 0,
                            body_len: body,
                        };
                        if rng.below(8) == 0 {
                            core.read_refused(id, Status::Missing, now);
                        }
                        live.push(Live {
                            id,
                            request,
                            manifest,
                            offered: 0,
                            commanded: true,
                            base: 0,
                        });
                    }
                }
                1 if !live.is_empty() => {
                    let at = rng.below(live.len() as u64) as usize;
                    let entry = &mut live[at];
                    let total = entry.manifest.total();
                    if entry.commanded && (entry.offered < total || total == 0) {
                        let end = (entry.offered + 12_000).min(total);
                        let chunk: Chunk = payload((end - entry.offered) as usize).into();
                        if total > 0 {
                            core.chunk(
                                entry.id,
                                entry.manifest,
                                entry.offered..end,
                                chunk,
                                &[],
                                now,
                            );
                        }
                        entry.offered = end;
                        entry.commanded = false;
                        if end == total {
                            core.read_done(entry.id, ReadEnd::Complete(entry.manifest), now);
                        }
                    } else if !entry.commanded && core.wants_grant(entry.id) {
                        core.granted(entry.id);
                        entry.commanded = true;
                    } else if rng.below(6) == 0 {
                        core.read_done(entry.id, ReadEnd::Failed(Status::DeviceError), now);
                    }
                }
                2 if !live.is_empty() => {
                    let at = rng.below(live.len() as u64) as usize;
                    let entry = &mut live[at];
                    let count = entry.manifest.count();
                    let base =
                        entry.base + rng.below(u64::from(count - entry.base.min(count)) + 1) as u32;
                    let before = core.report().stale_acks;
                    core.ack(
                        session(4),
                        &ack(
                            &entry.request,
                            &entry.manifest,
                            base,
                            base + 1 + rng.below(3) as u32,
                        ),
                        now,
                    );
                    if core.report().stale_acks == before {
                        entry.base = base;
                    }
                }
                3 if !live.is_empty() => {
                    let request = live[rng.below(live.len() as u64) as usize].request;
                    let cancel = Header {
                        kind: Kind::Cancel,
                        status: Status::Cancelled as u16,
                        metadata_len: 0,
                        body_len: 0,
                        grant: 0,
                        remaining_ms: 0,
                        ..request
                    };
                    core.cancel(session(4), &cancel, now);
                }
                4 if !live.is_empty() => {
                    let request = live[rng.below(live.len() as u64) as usize].request;
                    core.get(session(4), &request, now);
                }
                5 => core.tick(now),
                6 => {
                    let proven: Vec<RequestId> = live
                        .iter()
                        .map(|entry| entry.id)
                        .filter(|_| rng.below(2) == 0)
                        .collect();
                    core.release_drained(|id| {
                        let ok = proven.contains(&id);
                        if ok {
                            drained_ok.push(id);
                        }
                        ok
                    });
                }
                _ => {
                    core.poll(now, 16, |frames| {
                        frames
                            .inspect(|out| {
                                assert!(
                                    out.payload.iter().filter(|slice| !slice.is_empty()).count()
                                        <= 2
                                );
                            })
                            .count()
                    });
                }
            }
            core.check_indexes();
            let census = core.requests().census();
            let count = live
                .iter()
                .filter(|entry| core.requests().get(entry.id).is_some())
                .count() as u32;
            assert_eq!(census.active + census.draining, count, "seed {seed}");
            for entry in &live {
                if core.requests().get(entry.id).is_none() {
                    assert!(
                        drained_ok.contains(&entry.id),
                        "a request left only through a proven drain, seed {seed}"
                    );
                    continue;
                }
                let retained = core.retained(entry.id);
                assert!(
                    retained + usize::from(entry.commanded && !core.is_ended(entry.id)) <= 2,
                    "seed {seed}"
                );
                if core.is_ended(entry.id) {
                    assert_eq!(retained, 0, "an ended request holds no chunk");
                } else {
                    let acked = u64::from(entry.base) * 8192;
                    let expected = (0..entry.offered.div_ceil(12_000))
                        .map(|chunk| ((chunk * 12_000), ((chunk + 1) * 12_000).min(entry.offered)))
                        .filter(|&(_, end)| end > acked && acked < entry.manifest.total())
                        .count();
                    assert_eq!(
                        retained, expected,
                        "retention follows the base, seed {seed}"
                    );
                }
            }
            live.retain(|entry| core.requests().get(entry.id).is_some());
        }
        let report = core.report();
        totals.0 += report.completed;
        totals.1 += report.errors;
        totals.2 += report.retries;
    }
    assert!(totals.0 > 0 && totals.1 > 0 && totals.2 > 0, "{totals:?}");
}

/// The read-grant policy keeps at most two buffers across retained chunks and an outstanding command, and holds the next command once the client's grant stops below the next buffer's first fragment, even after every chunk was released.
#[test]
fn the_read_grant_policy_keeps_two_buffers_and_the_window() {
    let mut core = core();
    let request = get(1, 0, 1);
    let id = started(&mut core, &request, 1);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 4 * 8192,
    };
    assert!(!core.wants_grant(id));
    core.chunk(id, manifest, 0..8192, payload(8192).into(), &[], 0);
    assert!(
        !core.wants_grant(id),
        "the grant of 1 admits fragment 0 only"
    );
    poll(&mut core, 0);
    core.ack(session(1), &ack(&request, &manifest, 1, 1), 0);
    assert_eq!(core.retained(id), 0);
    assert!(
        !core.wants_grant(id),
        "fragment 1 is outside the grant although nothing is retained"
    );
    core.ack(session(1), &ack(&request, &manifest, 1, 2), 0);
    assert!(core.wants_grant(id));
    core.granted(id);
    assert!(!core.wants_grant(id), "one command at a time");
}

/// A core that reads ahead grants a second command while the first is outstanding, keeps a request at three buffers across retained chunks and commands, and reads at most one command past the client's grant: the oldest outstanding command must start inside it.
#[test]
fn a_core_that_reads_ahead_grants_two_commands_within_three_buffers() {
    let mut wide = core();
    wide.read_ahead(1);
    let request = get(1, 0, 64);
    let id = started(&mut wide, &request, 64);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 8 * 8192,
    };
    assert!(wide.wants_grant(id), "a second command ahead of the first");
    wide.granted(id);
    assert!(!wide.wants_grant(id), "two commands at a time");
    wide.chunk(id, manifest, 0..16384, payload(16384).into(), &[], 0);
    assert!(wide.wants_grant(id));
    wide.granted(id);
    wide.chunk(id, manifest, 16384..32768, payload(16384).into(), &[], 0);
    assert_eq!(wide.retained(id), 2);
    assert!(
        !wide.wants_grant(id),
        "two chunks and one command fill three buffers"
    );
    let mut narrow = core();
    narrow.read_ahead(1);
    let small = get(1, 0, 2);
    let id = started(&mut narrow, &small, 2);
    assert!(
        narrow.wants_grant(id),
        "the command ahead runs one command past the grant of 2"
    );
    narrow.granted(id);
    narrow.chunk(id, manifest, 0..16384, payload(16384).into(), &[], 0);
    assert!(
        !narrow.wants_grant(id),
        "the oldest outstanding command starts at fragment 2, outside the grant of 2"
    );
}

/// A core that reads three commands ahead grants a request four commands at once while its buffers stay within BUFFERS_PER_READ plus three, and grants another only once a chunk hands off.
#[test]
fn a_core_three_commands_ahead_grants_four_commands_within_its_buffers() {
    let mut core = core();
    core.read_ahead(3);
    let request = get(1, 0, 64);
    let id = started(&mut core, &request, 64);
    for granted in 1..=3 {
        assert!(core.wants_grant(id), "command {granted} ahead");
        core.granted(id);
    }
    assert!(!core.wants_grant(id), "four commands at a time");
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 16 * 8192,
    };
    core.chunk(id, manifest, 0..16384, payload(16384).into(), &[], 0);
    assert!(core.wants_grant(id), "a hand-off frees a command");
}

/// A test chunk a device holds while its flag is set. A copy shares the
/// flag.
#[derive(Clone, Debug)]
pub(super) struct Tx(
    pub(super) Box<[u8]>,
    pub(super) std::rc::Rc<std::cell::Cell<bool>>,
);

impl AsRef<[u8]> for Tx {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl super::serve::Chunk for Tx {
    fn device_held(&self) -> bool {
        self.1.get()
    }

    fn crc(
        &self,
        crc: crate::storage::Crc32c,
        _runs: &mut crate::storage::ZeroRuns,
        _window_crcs: &[u32],
        range: std::ops::Range<usize>,
    ) -> u32 {
        crc.checksum(&self.0[range])
    }
}

impl super::serve::Retained<'_> for Tx {
    fn source(
        &self,
        _range: std::ops::Range<usize>,
    ) -> Option<crate::storage::SourceRange<'_, 'static>> {
        None
    }
}

/// A chunk the receipt passed, or of an ended request, stays retained while a device holds it: it keeps its place in the two-buffer bound, so no next command is granted, and an ended request keeps draining. `reap` drops it once the device lets go, with no further ACK, and its return count names only the requests that stopped holding.
#[test]
fn a_device_held_chunk_stays_retained_until_reaped() {
    let table = RequestTable::<Request<Tx>>::new(4, 2, 2);
    let mut core =
        Core::<Tx>::new(CONFIG, table, 2, 128, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let request = get(1, 0, 4);
    let GetOutcome::Read { id, .. } = core.get(session(4), &request, 0) else {
        panic!("a new request");
    };
    core.read_started(id);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 4 * 8192,
    };
    let held = [
        std::rc::Rc::new(std::cell::Cell::new(true)),
        std::rc::Rc::new(std::cell::Cell::new(true)),
    ];
    core.chunk(
        id,
        manifest,
        0..8192,
        Tx(payload(8192).into(), held[0].clone()),
        &[],
        0,
    );
    core.granted(id);
    core.chunk(
        id,
        manifest,
        8192..16384,
        Tx(payload(8192).into(), held[1].clone()),
        &[],
        0,
    );
    core.poll(0, 8, |frames| frames.count());
    core.ack(session(4), &ack(&request, &manifest, 2, 4), 0);
    assert_eq!(
        core.retained(id),
        2,
        "both passed chunks stay while the device reads them"
    );
    assert!(!core.wants_grant(id), "they keep the read at two buffers");
    core.check_indexes();
    assert_eq!(core.reap(), 0, "nothing returned yet");
    held[0].set(false);
    assert_eq!(core.reap(), 0, "one chunk still held");
    assert_eq!(core.retained(id), 1);
    assert!(
        core.wants_grant(id),
        "the returned buffer admits the next command"
    );
    core.granted(id);
    core.cancel(
        session(4),
        &Header {
            kind: Kind::Cancel,
            ..request
        },
        10,
    );
    assert!(core.is_ended(id));
    assert_eq!(
        core.release_drained(|_| true),
        0,
        "an ended request keeps draining while its chunk is held"
    );
    core.check_indexes();
    held[1].set(false);
    assert_eq!(core.reap(), 1, "the last return ends the request's hold");
    assert_eq!(core.retained(id), 0);
    assert_eq!(core.release_drained(|_| true), 1);
    assert_eq!(core.reap(), 0, "no request holds a chunk");
}

/// Holders in different words of the holding set: a reap drops exactly the chunks whose device let go and keeps the chunks of holders still read, and an ended holder's drain waits for its own return.
#[test]
fn a_reap_scans_holders_across_words() {
    const SLOTS: u32 = 130;
    let config = ServeConfig {
        slots: SLOTS,
        ..CONFIG
    };
    let session = Admitted {
        caps: Caps {
            slots: SLOTS,
            window: 4,
        },
        ..session(4)
    };
    let table = RequestTable::<Request<Tx>>::new(SLOTS, 1, SLOTS);
    let mut core =
        Core::<Tx>::new(config, table, 1, 128, 0, 4, &mut EngineBudget::new(1 << 24)).unwrap();
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 8192,
    };
    let mut held = Vec::new();
    for wire in 0..SLOTS as u16 {
        let request = get(wire, 0, 4);
        let GetOutcome::Read { id, .. } = core.get(session, &request, 0) else {
            panic!("a new request");
        };
        core.read_started(id);
        let device = std::rc::Rc::new(std::cell::Cell::new(true));
        core.chunk(
            id,
            manifest,
            0..8192,
            Tx(payload(8192).into(), device.clone()),
            &[],
            0,
        );
        held.push((id, request, device));
    }
    while core.poll(0, 128, |frames| frames.count()) > 0 {}
    // Requests in words 0, 1 and 2 take their whole receipt while the device holds their chunk; every other request is released from the hold first.
    let holders = [3usize, 64, 129];
    for (at, (id, request, device)) in held.iter().enumerate() {
        if !holders.contains(&at) {
            device.set(false);
        }
        core.ack(session, &ack(request, &manifest, 1, 4), 0);
        assert_eq!(core.retained(*id), usize::from(holders.contains(&at)));
    }
    core.check_indexes();
    assert_eq!(core.reap(), 0, "every holder's device still reads");
    held[64].2.set(false);
    assert_eq!(core.reap(), 1, "only the word-1 holder's return drops");
    assert_eq!(core.retained(held[64].0), 0);
    assert_eq!(core.retained(held[3].0), 1);
    assert_eq!(core.retained(held[129].0), 1);
    core.check_indexes();
    // The word-2 holder ends while its chunk is held, so its drain waits for the return.
    core.cancel(
        session,
        &Header {
            kind: Kind::Cancel,
            ..held[129].1
        },
        1,
    );
    assert_eq!(core.release_drained(|_| true), 0);
    held[3].2.set(false);
    assert_eq!(core.reap(), 1, "the word-0 holder's return drops");
    core.check_indexes();
    held[129].2.set(false);
    assert_eq!(core.reap(), 1, "the ended word-2 holder's return drops");
    assert_eq!(core.release_drained(|_| true), 1, "and its drain completes");
    core.check_indexes();
    assert_eq!(core.reap(), 0, "no request holds a chunk");
}

#[test]
fn a_reap_reaches_every_holder_past_one_still_held() {
    let table = RequestTable::<Request<Tx>>::new(4, 2, 2);
    let mut core =
        Core::<Tx>::new(CONFIG, table, 2, 128, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 4 * 8192,
    };
    let mut holders = Vec::new();
    for wire in [1, 2] {
        let request = get(wire, 0, 4);
        let GetOutcome::Read { id, .. } = core.get(session(4), &request, 0) else {
            panic!("a new request");
        };
        core.read_started(id);
        let held = std::rc::Rc::new(std::cell::Cell::new(true));
        core.chunk(
            id,
            manifest,
            0..8192,
            Tx(payload(8192).into(), held.clone()),
            &[],
            0,
        );
        core.poll(0, 8, |frames| frames.count());
        core.ack(session(4), &ack(&request, &manifest, 1, 4), 0);
        assert_eq!(core.retained(id), 1, "the passed chunk stays while held");
        holders.push((id, held));
    }
    core.check_indexes();
    holders.sort_by_key(|(id, _)| id.slot());
    let [first, last] = &holders[..] else {
        panic!("two holders");
    };
    last.1.set(false);
    assert_eq!(core.reap(), 1, "the later holder's return drops");
    assert_eq!(core.retained(last.0), 0);
    assert_eq!(core.retained(first.0), 1, "the earlier holder still reads");
    core.check_indexes();
    first.1.set(false);
    assert_eq!(core.reap(), 1);
    assert_eq!(core.retained(first.0), 0);
    core.check_indexes();
    assert_eq!(core.reap(), 0, "no request holds a chunk");
}

/// An ERROR queued at a logical end is sent even when the drain predicate already holds; the request is released only after it.
#[test]
fn a_pending_error_is_sent_before_release() {
    let mut core = core();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    core.read_refused(id, Status::Missing, 0);
    assert_eq!(
        core.release_drained(|_| true),
        0,
        "the ERROR is still queued"
    );
    assert_eq!(
        core.report().errors_of(Status::Missing),
        0,
        "a queued ERROR counts once sent"
    );
    let sent = poll(&mut core, 0);
    assert_eq!(core.report().errors_of(Status::Missing), 1);
    assert_eq!(core.report().errors_by_status.iter().sum::<u64>(), 1);
    assert_eq!(
        (sent[0].header.kind, sent[0].header.status),
        (Kind::Error, Status::Missing as u16)
    );
    assert_eq!(core.release_drained(|_| true), 1);
    let pressed = started(&mut core, &get(2, 0, 2), 2);
    core.read_refused(pressed, Status::StoragePressure, 0);
    poll(&mut core, 0);
    assert_eq!(core.report().errors_of(Status::StoragePressure), 1);
    assert_eq!(
        core.report().errors_of(Status::Missing),
        1,
        "each status counts apart"
    );
}

/// A reply-ring refusal increments its status counter when the send takes its ERROR frame.
#[test]
fn a_refusal_from_the_reply_ring_counts_under_its_status() {
    let mut core = core();
    // A grant above the session's window is refused before the core admits a request.
    let refused = core.get(session(8), &get(3, 0, 9), 0);
    assert_eq!(refused, GetOutcome::Refused(Status::InvalidRequest));
    assert_eq!(
        core.report().errors_of(Status::InvalidRequest),
        0,
        "a queued refusal counts once sent"
    );
    let sent = poll(&mut core, 0);
    assert_eq!(
        (sent[0].header.kind, sent[0].header.status),
        (Kind::Error, Status::InvalidRequest as u16)
    );
    assert_eq!(core.report().errors_of(Status::InvalidRequest), 1);
    assert_eq!(core.report().errors_by_status.iter().sum::<u64>(), 1);
}

/// A reply-only poll preserves reply priority: with a one-frame budget, the next poll stages a queued ERROR ahead of a ready request's START.
#[test]
fn a_reply_only_poll_leaves_the_next_poll_replies_first() {
    let mut core = core();
    // The core refuses grants above the session's window before admitting a request.
    let refused = core.get(session(8), &get(3, 0, 9), 0);
    assert_eq!(refused, GetOutcome::Refused(Status::InvalidRequest));
    take_send_visits();
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Error, 0)]);
    assert_eq!(take_send_visits(), 0, "the data round has zero visits");
    let request = get(0, 1, 1);
    let id = started(&mut core, &request, 1);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 64,
    };
    core.chunk(id, manifest, 0..64, payload(64).into(), &[], 0);
    let refused = core.get(session(8), &get(3, 1, 9), 0);
    assert_eq!(refused, GetOutcome::Refused(Status::InvalidRequest));
    let mut first = Vec::new();
    core.poll(1, 1, |frames| {
        frames.map(|out| first.push(out.header.kind)).count()
    });
    assert_eq!(
        first,
        [Kind::Error],
        "the reply stages ahead of the request's START"
    );
    assert_eq!(kinds(&poll(&mut core, 2))[0], (Kind::Start, 0));
    core.check_indexes();
}

/// A sent reply frees the wire binding of a draining record only. In a debug build, a sent PUT ERROR that names an active PUT record panics at the unbind.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "unbinding names a draining record")]
fn a_debug_build_stops_a_sent_reply_that_names_an_active_put() {
    let mut budget = EngineBudget::new(1 << 20);
    let table = RequestTable::<Request<Chunk, ()>>::new(4, 2, 2);
    let mut requests = Requests::new(table, CONFIG.slots, &mut budget).unwrap();
    let mut serve = ServeCore::new(CONFIG, &requests, 128, 0, 4, &mut budget).unwrap();
    let (peer, wire) = (PeerId(0), RequestId::from_wire(1 << 48 | 1));
    let id = requests.admit(peer, wire, || Request::Put(())).unwrap();
    let error = PutReply {
        kind: Kind::PutError,
        manifest: Manifest {
            allocation: 7,
            metadata_len: 0,
            body_len: 0,
        },
        grant: 0,
        status: Status::Cancelled as u16,
        index: 0,
        offset: 0,
    };
    serve.queue_put(Some(id), peer, 4, wire.wire(), [9; 32], error);
    serve.poll(&mut requests, 0, 64, |frames| frames.count());
}

/// A peer out of pacing tokens holds back only its own replies: another peer's reply goes out, and each peer's reply ring is its own.
#[test]
fn one_peers_paced_replies_leave_other_peers_replies_free() {
    let mut core = Core::<Chunk>::new(
        ServeConfig {
            rate_per_sec: 1,
            burst: 1,
            replies: 2,
            ..CONFIG
        },
        RequestTable::new(4, 2, 2),
        2,
        128,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let busy = session(2);
    let other = Admitted {
        peer: PeerId(1),
        ..session(2)
    };
    // Peer 0 spends its one token, then queues more refusals than its ring holds.
    for generation in 0..4 {
        if generation == 1 {
            assert_eq!(
                core.report().reply_high_water,
                1,
                "one queued reply sits below the ring's width"
            );
        }
        core.get(
            busy,
            &Header {
                grant: 9,
                ..get(1, generation, 9)
            },
            0,
        );
    }
    assert_eq!(core.report().dropped_replies, 2, "peer 0's ring holds two");
    assert_eq!(
        (core.report().reply_high_water, core.report().reply_capacity),
        (2, 2),
        "the full ring's occupancy reached its width"
    );
    assert_eq!(poll(&mut core, 0).len(), 1, "peer 0's burst");
    core.get(
        other,
        &Header {
            grant: 9,
            ..get(1, 0, 9)
        },
        0,
    );
    let sent = poll(&mut core, 1);
    assert_eq!(
        sent.len(),
        1,
        "peer 1's refusal goes out while peer 0 waits"
    );
    assert_eq!(sent[0].header.status, Status::InvalidRequest as u16);
}

/// Live requests in table slots 3, 64 and 66 of a 70-slot table, two of them past a 64-slot word boundary, each send their frames in one burst per round in slot order; a poll whose budget ends inside a burst resumes at the next live slot, a round wraps from slot 66 past slot 3 to the request whose burst was cut, and once every request waits for an ACK a poll sends nothing.
#[test]
fn the_data_round_serves_sparse_live_slots_in_cyclic_order() {
    let mut core = Core::<Chunk>::new(
        ServeConfig {
            slots: 70,
            ..CONFIG
        },
        RequestTable::new(70, 1, 70),
        1,
        8,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let wide = Admitted {
        caps: Caps {
            slots: 70,
            window: 4,
        },
        ..session(4)
    };
    let kept = [3u16, 64, 66];
    let mut ids = Vec::new();
    for slot in 0..70u16 {
        let GetOutcome::Read { id, .. } = core.get(wide, &get(slot, 0, 4), 0) else {
            panic!("a new request");
        };
        assert_eq!(id.slot(), slot, "slots fill in order");
        core.read_started(id);
        ids.push(id);
        if !kept.contains(&slot) {
            let cancel = Header {
                kind: Kind::Cancel,
                ..get(slot, 0, 4)
            };
            core.cancel(wide, &cancel, 0);
        }
    }
    assert_eq!(core.release_drained(|_| true), 67);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 3 * 8192,
    };
    for slot in kept {
        let id = ids[usize::from(slot)];
        core.chunk(id, manifest, 0..3 * 8192, payload(3 * 8192).into(), &[], 0);
        core.read_done(id, ReadEnd::Complete(manifest), 0);
    }
    let mut round = |budget: usize| {
        let mut sent = Vec::new();
        core.poll(0, budget, |frames| {
            frames
                .map(|out| {
                    sent.push((
                        RequestId::from_wire(out.header.request).slot(),
                        out.header.kind,
                        out.header.index,
                    ));
                })
                .count()
        });
        sent
    };
    assert_eq!(
        round(6),
        [
            (3, Kind::Start, 0),
            (3, Kind::Data, 0),
            (3, Kind::Data, 1),
            (3, Kind::Data, 2),
            (64, Kind::Start, 0),
            (64, Kind::Data, 0),
        ]
    );
    assert_eq!(
        round(6),
        [
            (66, Kind::Start, 0),
            (66, Kind::Data, 0),
            (66, Kind::Data, 1),
            (66, Kind::Data, 2),
            (64, Kind::Data, 1),
            (64, Kind::Data, 2),
        ]
    );
    assert!(round(8).is_empty(), "every request waits for its ACK");
}

/// A data round in which nothing sends ends where it began: after slot 2's request sent last and released, a round over the idle requests in slots 0 and 1 leaves the next round to start at slot 3, so slot 0's START goes before that of a request admitted afterwards into table slot 2. Frames name each request by its wire slot, which equals its table slot except for that late request's wire slot 3.
#[test]
fn a_round_without_a_send_leaves_the_next_round_where_it_began() {
    let mut core = Core::<Chunk>::new(
        CONFIG,
        RequestTable::new(4, 1, 4),
        1,
        8,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let window = 4;
    let ids: Vec<RequestId> = (0..3)
        .map(|slot| started(&mut core, &get(slot, 0, 4), window))
        .collect();
    assert_eq!(
        ids.iter().map(|id| id.slot()).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 8192,
    };
    core.chunk(ids[2], manifest, 0..8192, payload(8192).into(), &[], 0);
    let first = |core: &mut Core<Chunk>| {
        let mut sent = Vec::new();
        core.poll(0, 1, |frames| {
            frames
                .map(|out| sent.push(RequestId::from_wire(out.header.request).slot()))
                .count()
        });
        sent
    };
    assert_eq!(first(&mut core), [2], "only slot 2's request has a frame");
    let cancel = Header {
        kind: Kind::Cancel,
        ..get(2, 0, 4)
    };
    core.cancel(session(window), &cancel, 0);
    assert_eq!(core.release_drained(|id| id == ids[2]), 1);
    assert!(
        first(&mut core).is_empty(),
        "slots 0 and 1 wait for their reads"
    );
    let late = started(&mut core, &get(3, 0, 4), window);
    assert_eq!(late.slot(), 2, "the released slot is reused");
    core.chunk(ids[0], manifest, 0..8192, payload(8192).into(), &[], 0);
    core.chunk(late, manifest, 0..8192, payload(8192).into(), &[], 0);
    assert_eq!(
        first(&mut core),
        [0],
        "the round resumes at slot 3 and wraps to slot 0"
    );
    assert_eq!(
        first(&mut core),
        [3],
        "then the late request, on wire slot 3"
    );
}

/// A GET's duration is capped at the core's longest wait.
#[test]
fn a_request_runs_no_longer_than_the_longest_wait() {
    let mut core = Core::<Chunk>::new(
        ServeConfig {
            max_wait_us: 2_000,
            ..CONFIG
        },
        RequestTable::new(4, 2, 2),
        2,
        128,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let request = Header {
        remaining_ms: u32::MAX,
        ..get(1, 0, 2)
    };
    let GetOutcome::Read { deadline_us, .. } = core.get(session(2), &request, 10) else {
        panic!("new");
    };
    assert_eq!(deadline_us, 2_010);
}

/// Retiring a peer's session ends its live request with custody, forgets the slots' cached terminals so a new session's GET starts a read, and keeps a draining slot busy until release.
#[test]
fn retiring_a_session_ends_work_and_forgets_cached_terminals() {
    let mut core = core();
    let finished = get(1, 0, 2);
    let done = started(&mut core, &finished, 2);
    core.read_refused(done, Status::Missing, 0);
    poll(&mut core, 0);
    core.release_drained(|_| true);
    let running = get(2, 0, 2);
    let live = started(&mut core, &running, 2);
    core.retire_peer(PeerId(0), 10);
    assert!(core.is_ended(live));
    assert_eq!(core.requests().census().draining, 1);
    let next = Admitted {
        epoch: 5,
        ..session(2)
    };
    assert!(
        matches!(
            core.get(
                next,
                &Header {
                    epoch: 5,
                    ..finished
                },
                20
            ),
            GetOutcome::Read { .. }
        ),
        "the cached terminal went with the session"
    );
    assert_eq!(
        core.get(
            next,
            &Header {
                epoch: 5,
                ..running
            },
            20
        ),
        GetOutcome::Refused(Status::RequestPressure)
    );
    core.release_drained(|id| id == live);
    // The refusal settled the new session's generation 0 on the slot, so the
    // session's next GET on it takes generation 1.
    assert!(matches!(
        core.get(
            next,
            &Header {
                epoch: 5,
                ..get(2, 1, 2)
            },
            30
        ),
        GetOutcome::Read { .. }
    ));
}

/// A GET refused `InvalidRequest` for a grant above its session's window settles its wire identity, so the owner admits no later GET under the request ID it answered: the same ID with an admissible grant is refused as conflicting within the horizon and dropped after it, no request is admitted, every frame sent is a refusal's ERROR, and the next generation admits.
#[test]
fn a_get_refused_for_its_grant_is_never_admitted_under_the_same_request_id() {
    let mut core = core();
    let refused = get(1, 3, 9);
    assert_eq!(
        core.get(session(2), &refused, 0),
        GetOutcome::Refused(Status::InvalidRequest)
    );
    assert_eq!(
        core.get(session(2), &get(1, 3, 2), 0),
        GetOutcome::Refused(Status::ConflictingRequest),
        "the answered identity admits nothing"
    );
    assert_eq!(
        core.get(session(2), &refused, 0),
        GetOutcome::Refused(Status::InvalidRequest),
        "a retransmission is refused again"
    );
    assert_eq!(core.requests().census().active, 0);
    let sent = poll(&mut core, 0);
    assert_eq!(
        sent.iter()
            .map(|frame| (frame.header.kind, frame.header.status))
            .collect::<Vec<_>>(),
        [
            (Kind::Error, Status::InvalidRequest as u16),
            (Kind::Error, Status::ConflictingRequest as u16),
            (Kind::Error, Status::InvalidRequest as u16),
        ]
    );
    let horizon_us = 100_000 + CONFIG.linger_us;
    assert_eq!(
        core.get(session(2), &get(1, 3, 2), horizon_us - 1),
        GetOutcome::Refused(Status::ConflictingRequest),
        "the refusal's row answers until its horizon"
    );
    assert_eq!(
        core.get(session(2), &get(1, 3, 2), horizon_us),
        GetOutcome::Dropped,
        "the identity stays consumed past the refusal's horizon"
    );
    assert!(matches!(
        core.get(session(2), &get(1, 4, 2), horizon_us),
        GetOutcome::Read { .. }
    ));
    core.check_indexes();
}

/// A duplicate GET with a longer duration keeps the original deadline.
#[test]
fn a_duplicate_get_never_extends_the_deadline() {
    let mut core = core();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    assert_eq!(
        core.get(
            session(2),
            &Header {
                remaining_ms: 10_000,
                ..request
            },
            0
        ),
        GetOutcome::Duplicate
    );
    core.tick(100_000);
    assert!(core.is_ended(id), "the original 100 ms deadline holds");
    assert_eq!(
        poll(&mut core, 100_000)[0].header.status,
        Status::TimedOut as u16
    );
}

/// A datagram the transport refuses is neither charged nor counted sent: the next poll sends the same frame, and the pacer's one token is still there.
#[test]
fn a_refused_send_charges_nothing_and_is_resent() {
    let mut core = Core::<Chunk>::new(
        ServeConfig {
            rate_per_sec: 1,
            burst: 1,
            ..CONFIG
        },
        RequestTable::new(4, 2, 2),
        2,
        128,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 100,
    };
    core.chunk(id, manifest, 0..100, payload(100).into(), &[], 0);
    assert_eq!(core.poll(0, 8, |_| 0), 0);
    assert_eq!(
        kinds(&poll(&mut core, 0)),
        [(Kind::Start, 0)],
        "the token was still there"
    );
    assert_eq!(core.poll(0, 8, |_| 0), 0);
    assert!(poll(&mut core, 0).is_empty(), "no token until the refill");
    assert_eq!(kinds(&poll(&mut core, 1_000_000)), [(Kind::Data, 0)]);
}

/// A refused first DATA send, retransmission, COMPLETE and ERROR each keep their pending state, spend no pacing token and advance no first-send index: with one token per millisecond, the poll right after each refusal sends the same frame, and a request whose ERROR the transport refused stays draining until the ERROR goes out.
#[test]
fn refused_data_retransmit_and_terminal_frames_charge_nothing_and_are_resent() {
    let mut core = Core::<Chunk>::new(
        ServeConfig {
            rate_per_sec: 1_000,
            burst: 1,
            ..CONFIG
        },
        RequestTable::new(4, 2, 2),
        2,
        128,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 100,
    };
    core.chunk(id, manifest, 0..100, payload(100).into(), &[], 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Start, 0)]);
    core.ack(session(2), &ack(&request, &manifest, 0, 2), 500);
    assert_eq!(
        core.poll(1_000, 8, |_| 0),
        0,
        "the first DATA send is refused"
    );
    assert_eq!(
        kinds(&poll(&mut core, 1_000)),
        [(Kind::Data, 0)],
        "the same first send, on the same token"
    );
    core.tick(1_600);
    assert_eq!(core.report().retries, 1);
    assert_eq!(
        core.poll(2_000, 8, |_| 0),
        0,
        "the retransmission is refused"
    );
    assert_eq!(
        kinds(&poll(&mut core, 2_000)),
        [(Kind::Data, 0)],
        "the same retransmission, on the same token"
    );
    core.read_done(id, ReadEnd::Complete(manifest), 2_100);
    core.ack(session(2), &ack(&request, &manifest, 1, 2), 2_200);
    assert_eq!(core.poll(3_000, 8, |_| 0), 0, "the COMPLETE is refused");
    assert_eq!(
        core.report().completed,
        0,
        "a refused COMPLETE ends nothing"
    );
    assert_eq!(kinds(&poll(&mut core, 3_000)), [(Kind::Complete, 1)]);
    assert_eq!(core.report().completed, 1);
    let failing = get(2, 0, 2);
    let failed = started(&mut core, &failing, 2);
    core.read_refused(failed, Status::Missing, 3_100);
    assert_eq!(core.poll(4_000, 8, |_| 0), 0, "the ERROR is refused");
    assert_eq!(
        core.release_drained(|_| true),
        1,
        "only the completed request drains"
    );
    assert_eq!(core.report().errors, 0);
    let sent = poll(&mut core, 4_000);
    assert_eq!(
        (sent.len(), sent[0].header.kind),
        (1, Kind::Error),
        "the same ERROR, on the same token"
    );
    assert_eq!(
        core.release_drained(|_| true),
        1,
        "the sent ERROR lets its request drain"
    );
    core.check_indexes();
}

/// A batch the transport takes in part leaves every later frame as it was: the next poll offers the same frames in the same order with their pacing tokens back, a COMPLETE the transport left ends nothing and counts nothing, and once taken it ends the request and counts.
#[test]
fn a_partly_taken_batch_keeps_its_rest_for_the_next_poll() {
    let mut core = Core::<Chunk>::new(
        ServeConfig {
            rate_per_sec: 1,
            burst: 5,
            ..CONFIG
        },
        RequestTable::new(4, 2, 2),
        2,
        128,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    // The peer's five tokens cover START, three fragments and COMPLETE only if the frames the transport leaves give theirs back.
    let request = get(1, 0, 8);
    let id = started(&mut core, &request, 8);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 3 * 8192,
    };
    core.chunk(id, manifest, 0..3 * 8192, payload(3 * 8192).into(), &[], 0);
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    // Another peer's refused GET queues an ERROR reply, which a poll offers before any request's frame.
    let other = Admitted {
        peer: PeerId(1),
        ..session(2)
    };
    assert!(matches!(
        core.get(other, &get(2, 0, 9), 0),
        GetOutcome::Refused(Status::InvalidRequest)
    ));
    let mut offered = Vec::new();
    let taken = core.poll(0, 8, |frames| {
        frames
            .map(|out| offered.push((out.peer, out.header.kind, out.header.index)))
            .count()
            .min(2)
    });
    assert_eq!(taken, 2);
    assert_eq!(
        offered,
        [
            (PeerId(1), Kind::Error, 0),
            (PeerId(0), Kind::Start, 0),
            (PeerId(0), Kind::Data, 0),
            (PeerId(0), Kind::Data, 1),
            (PeerId(0), Kind::Data, 2),
        ]
    );
    assert_eq!(
        kinds(&poll(&mut core, 0)),
        [(Kind::Data, 0), (Kind::Data, 1), (Kind::Data, 2)],
        "the three fragments the transport left, with the tokens they took back"
    );
    core.ack(session(8), &ack(&request, &manifest, 3, 8), 0);
    assert_eq!(core.poll(0, 8, |_| 0), 0);
    assert!(
        !core.is_ended(id),
        "a COMPLETE the transport left ends nothing"
    );
    assert_eq!(core.report().completed, 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Complete, 3)]);
    assert!(core.is_ended(id));
    assert_eq!(core.report().completed, 1);
    assert!(poll(&mut core, 0).is_empty());
}

fn offer<R>(
    core: &mut Core<Chunk>,
    budget: usize,
    take: usize,
    mut each: impl FnMut(Out<'_, '_>) -> R,
) -> Vec<R> {
    let mut offered = Vec::new();
    core.poll(0, budget, |frames| {
        offered.extend(frames.map(&mut each));
        take
    });
    offered
}

/// A sixteen-byte stand-in for a session's body digest: the fragment's length and its first bytes, so each fragment of the payload digests differently.
fn stand_in_digest(bytes: &[u8]) -> [u8; 16] {
    let mut digest = [0; 16];
    digest[..8].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
    for (slot, byte) in digest[8..].iter_mut().zip(bytes) {
        *slot = *byte;
    }
    digest
}

/// A delivered chunk caches the digest of every fragment it holds whole, and staging carries each cached digest in the fragment's frame: with the whole payload in one chunk every DATA frame carries its digest, and with a chunk boundary inside fragment 1 that fragment leaves its digest to the sender while fragments 0 and 2 carry theirs.
#[test]
fn a_delivered_chunk_caches_the_digests_of_its_whole_fragments() {
    let body = 3 * 8192;
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: body as u32,
    };
    let payload = payload(body);
    let frames = |core: &mut Core<Chunk>| {
        let mut out = Vec::new();
        core.poll(0, 8, |frames| {
            out.extend(frames.map(|frame| {
                (
                    frame.header.kind,
                    frame.header.index,
                    frame.digest,
                    [frame.payload[0].bytes(), frame.payload[1].bytes()].concat(),
                )
            }));
            out.len()
        });
        out
    };
    for split in [None, Some(12_288u64)] {
        let mut core = core();
        let id = started(&mut core, &get(1, 0, 8), 8);
        let mut digest = |bytes: &[u8]| Some(stand_in_digest(bytes));
        let chunks: Vec<std::ops::Range<u64>> = match split {
            None => std::iter::once(0..body as u64).collect(),
            Some(at) => vec![0..at, at..body as u64],
        };
        for range in chunks {
            let bytes: Chunk = payload[range.start as usize..range.end as usize].into();
            assert!(core.serve.chunk_with_digests(
                &mut core.requests,
                id,
                manifest,
                super::serve::ChunkInput {
                    range,
                    chunk: bytes,
                    window_crcs: &[],
                },
                0,
                Some(&mut digest),
            ));
        }
        let sent = frames(&mut core);
        assert_eq!(sent.len(), 4, "START and three fragments");
        assert_eq!((sent[0].0, sent[0].2), (Kind::Start, None));
        for (kind, index, digest, bytes) in &sent[1..] {
            assert_eq!(*kind, Kind::Data);
            let expected = Some(stand_in_digest(bytes));
            assert_eq!(bytes.len(), 8192);
            assert_eq!(
                &payload[*index as usize * 8192..(*index as usize + 1) * 8192],
                bytes
            );
            let straddles = split.is_some() && *index == 1;
            assert_eq!(
                *digest,
                if straddles { None } else { expected },
                "fragment {index} with split {split:?}"
            );
        }
    }
}

/// Resuming at the first untaken frame preserves round order across polls.
#[test]
fn a_partly_taken_data_round_resumes_at_the_first_frame_it_left() {
    let mut core = Core::<Chunk>::new(
        CONFIG,
        RequestTable::new(4, 1, 4),
        1,
        8,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 3 * 8192,
    };
    for slot in 1..=3 {
        let id = started(&mut core, &get(slot, 0, 8), 8);
        core.chunk(id, manifest, 0..3 * 8192, payload(3 * 8192).into(), &[], 0);
    }
    let frame = |out: Out<'_, '_>| {
        (
            RequestId::from_wire(out.header.request).slot(),
            out.header.kind,
            out.header.index,
        )
    };
    assert_eq!(
        offer(&mut core, 3, 1, frame),
        [(1, Kind::Start, 0), (1, Kind::Data, 0), (1, Kind::Data, 1)]
    );
    assert_eq!(
        offer(&mut core, 3, 1, frame),
        [(1, Kind::Data, 0), (1, Kind::Data, 1), (1, Kind::Data, 2)],
        "the fragments the transport left go first"
    );
    assert_eq!(
        offer(&mut core, 3, 1, frame),
        [(1, Kind::Data, 1), (1, Kind::Data, 2), (2, Kind::Start, 0)],
        "the burst runs to the request's last granted fragment before the next request's START"
    );
}

/// Burst progress persists across polls and counts only the frames the transport takes. With one frame taken per poll, the round moves to the next request after [`DATA_BURST`] taken frames, START included.
#[test]
fn a_burst_the_transport_takes_one_frame_at_a_time_still_yields() {
    let mut core = Core::<Chunk>::new(
        CONFIG,
        RequestTable::new(4, 1, 4),
        1,
        8,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 16 * 8192,
    };
    for slot in 1..=2 {
        let id = started(&mut core, &get(slot, 0, 16), 16);
        core.chunk(
            id,
            manifest,
            0..16 * 8192,
            payload(16 * 8192).into(),
            &[],
            0,
        );
    }
    let frame = |out: Out<'_, '_>| {
        (
            RequestId::from_wire(out.header.request).slot(),
            out.header.kind,
            out.header.index,
        )
    };
    let taken: Vec<_> = (0..2 * DATA_BURST + 1)
        .map(|_| offer(&mut core, 8, 1, frame)[0])
        .collect();
    let mut expected = vec![(1, Kind::Start, 0)];
    expected.extend((0..DATA_BURST as u32 - 1).map(|index| (1, Kind::Data, index)));
    expected.push((2, Kind::Start, 0));
    expected.extend((0..DATA_BURST as u32 - 1).map(|index| (2, Kind::Data, index)));
    expected.push((1, Kind::Data, DATA_BURST as u32 - 1));
    assert_eq!(
        taken, expected,
        "each request's burst ends after DATA_BURST taken frames"
    );
    core.check_indexes();
}

/// Resuming at the first untaken reply preserves peer alternation across polls.
#[test]
fn a_partly_taken_reply_round_resumes_at_the_first_reply_it_left() {
    let mut core = core();
    for peer in 0..2 {
        let refused = Admitted {
            peer: PeerId(peer),
            ..session(2)
        };
        for generation in 0..2 {
            core.get(refused, &get(1, generation, 9), 0);
        }
    }
    let reply = |out: Out<'_, '_>| {
        assert_eq!(out.header.kind, Kind::Error);
        (
            out.peer.0,
            RequestId::from_wire(out.header.request).generation(),
        )
    };
    assert_eq!(
        offer(&mut core, 4, 1, reply),
        [(0, 0), (1, 0), (0, 1), (1, 1)]
    );
    assert_eq!(
        offer(&mut core, 4, 1, reply),
        [(1, 0), (0, 1), (1, 1)],
        "peer 1's left reply goes first"
    );
    assert_eq!(offer(&mut core, 4, 1, reply), [(0, 1), (1, 1)]);
    assert_eq!(offer(&mut core, 4, 1, reply), [(1, 1)]);
    assert!(offer(&mut core, 4, 1, reply).is_empty());
}

/// A core over 70 peers, two words of peer bits, whose pacers hold `burst` tokens refilled once a second.
fn wide_reply_core(burst: u64) -> Core<Chunk> {
    Core::<Chunk>::new(
        ServeConfig {
            rate_per_sec: 1,
            burst,
            ..CONFIG
        },
        RequestTable::new(70, 70, 1),
        70,
        8,
        0,
        4,
        &mut EngineBudget::new(1 << 22),
    )
    .unwrap()
}

/// Queues on `peer`'s ring the refusal of a GET at `generation` whose grant exceeds the session's window.
fn refuse_on(core: &mut Core<Chunk>, peer: u16, generation: u64) {
    let session = Admitted {
        peer: PeerId(peer),
        ..session(2)
    };
    assert_eq!(
        core.get(session, &get(1, generation, 9), 0),
        GetOutcome::Refused(Status::InvalidRequest)
    );
}

/// The peer and request generation of an offered reply.
fn replied(out: Out<'_, '_>) -> (u16, u64) {
    assert_eq!(out.header.kind, Kind::Error);
    (
        out.peer.0,
        RequestId::from_wire(out.header.request).generation(),
    )
}

/// The wrapping set-bit scan agrees with a model over one word and over three, for every start bit below the bit count: the first set bit at or after `from`, else the first set bit below it.
#[test]
fn the_wrapping_set_bit_scan_agrees_with_a_model() {
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut patterns = vec![
        vec![0],
        vec![1],
        vec![1 << 63],
        vec![0; 3],
        vec![1, 0, 0],
        vec![1 << 63, 0, 0],
        vec![0, 1, 0],
        vec![0, 0, 1 << 63],
    ];
    for words in [1, 3] {
        for _ in 0..32 {
            let mut pattern = vec![0; words];
            for word in &mut pattern {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *word = seed & (seed >> 17) & (seed >> 31);
            }
            patterns.push(pattern);
        }
    }
    for words in patterns {
        let bits = words.len() as u32 * 64;
        let set = |bit: u32| words[bit as usize / 64] & (1 << (bit % 64)) != 0;
        for from in 0..bits {
            let model = (from..bits).chain(0..from).find(|&bit| set(bit));
            assert_eq!(
                next_set_wrapping(&words, from),
                model,
                "{words:x?} from {from}"
            );
        }
    }
}

/// Replies queued on peers 3, 64 and 66 of 70, two of them past a 64-peer word boundary, go out one per peer per round in peer order; a poll that ends mid-round resumes at the next peer with a reply, and a round wraps from peer 66 to peer 3.
#[test]
fn a_reply_round_serves_sparse_peers_in_cyclic_order() {
    let mut core = wide_reply_core(1_000);
    for peer in [3, 64, 66] {
        for generation in 0..2 {
            refuse_on(&mut core, peer, generation);
        }
    }
    core.check_indexes();
    assert_eq!(offer(&mut core, 2, 2, replied), [(3, 0), (64, 0)]);
    assert_eq!(offer(&mut core, 2, 2, replied), [(66, 0), (3, 1)]);
    assert_eq!(offer(&mut core, 2, 2, replied), [(64, 1), (66, 1)]);
    assert!(offer(&mut core, 2, 2, replied).is_empty());
    core.check_indexes();
}

/// A reply round whose only queued replies wait on pacing stops after one visit to every peer and leaves the next round to start where those visits began, so replies queued later on peers 5 and 20 go out in peer order from there.
#[test]
fn a_paced_reply_round_resumes_where_its_idle_visits_began() {
    let mut core = wide_reply_core(1);
    refuse_on(&mut core, 10, 0);
    refuse_on(&mut core, 10, 1);
    assert_eq!(
        offer(&mut core, 1, 1, replied),
        [(10, 0)],
        "peer 10's one token"
    );
    refuse_on(&mut core, 69, 0);
    assert_eq!(
        offer(&mut core, 1, 1, replied),
        [(69, 0)],
        "peer 69's reply"
    );
    assert!(
        offer(&mut core, 4, 4, replied).is_empty(),
        "peer 10 waits on pacing"
    );
    refuse_on(&mut core, 5, 0);
    refuse_on(&mut core, 20, 0);
    assert_eq!(
        offer(&mut core, 4, 4, replied),
        [(5, 0), (20, 0)],
        "the round starts at peer 0, where the idle round began"
    );
    core.check_indexes();
}

/// A reply the transport left unsent goes out on the next poll even when the staging poll passed a later ring entry emptied by CANCEL.
#[test]
fn a_refused_reply_survives_an_emptied_entry_passed_behind_it() {
    let mut core = core();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    core.read_refused(id, Status::DeviceError, 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Error, 0)]);
    core.release_drained(|_| true);
    let refused = get(2, 0, 9);
    assert_eq!(
        core.get(session(2), &refused, 0),
        GetOutcome::Refused(Status::InvalidRequest)
    );
    assert_eq!(core.get(session(2), &request, 0), GetOutcome::Replayed);
    let cancel = Header {
        kind: Kind::Cancel,
        status: Status::Cancelled as u16,
        metadata_len: 0,
        body_len: 0,
        grant: 0,
        remaining_ms: 0,
        ..request
    };
    core.cancel(session(2), &cancel, 0);
    let offered = |out: Out<'_, '_>| (out.header.kind, out.header.request);
    assert_eq!(
        offer(&mut core, 4, 0, offered),
        [(Kind::Error, refused.request)],
        "the replay's entry is passed, not sent"
    );
    core.check_indexes();
    assert_eq!(
        offer(&mut core, 4, 1, offered),
        [(Kind::Error, refused.request)],
        "the refused reply is offered again"
    );
    assert!(offer(&mut core, 4, 1, offered).is_empty());
    core.check_indexes();
}

/// An empty object sends START and, after its manifest ACK, COMPLETE with no DATA; a final ACK that arrives before the read's end makes COMPLETE follow that end.
#[test]
fn an_empty_object_and_a_late_read_end_complete_in_order() {
    let mut core = core();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    let empty = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 0,
    };
    core.read_done(id, ReadEnd::Complete(empty), 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Start, 0)]);
    core.ack(session(2), &ack(&request, &empty, 0, 2), 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Complete, 0)]);
    let later = get(2, 0, 2);
    let id = started(&mut core, &later, 2);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 100,
    };
    core.chunk(id, manifest, 0..100, payload(100).into(), &[], 0);
    poll(&mut core, 0);
    core.ack(session(2), &ack(&later, &manifest, 1, 3), 0);
    assert!(poll(&mut core, 0).is_empty(), "the read has not ended");
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Complete, 1)]);
}

/// A new GET at the last generation is refused CounterExhausted; a lower generation after a higher one was admitted drops.
#[test]
fn generations_end_in_counter_exhaustion_and_older_ones_drop() {
    let mut core = core();
    let last = get(1, super::requests::GENERATION_LIMIT, 2);
    assert_eq!(
        core.get(session(2), &last, 0),
        GetOutcome::Refused(Status::CounterExhausted)
    );
    assert_eq!(
        poll(&mut core, 0)[0].header.status,
        Status::CounterExhausted as u16
    );
    started(&mut core, &get(2, 4, 2), 2);
    assert_eq!(core.get(session(2), &get(2, 3, 2), 0), GetOutcome::Dropped);
}

/// An identical ACK makes no progress, so it leaves the retry budget spent and exhaustion still ends the request before its deadline.
#[test]
fn a_repeated_ack_does_not_reset_the_retry_budget() {
    let mut core = core();
    let request = get(1, 0, 4);
    let id = started(&mut core, &request, 4);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 3 * 8192,
    };
    core.chunk(id, manifest, 0..3 * 8192, payload(3 * 8192).into(), &[], 0);
    poll(&mut core, 0);
    core.ack(session(4), &ack(&request, &manifest, 1, 5), 0);
    // Three retries at waits of one, two and four intervals, then the end eight intervals later.
    for step in 1..=15u64 {
        core.ack(
            session(4),
            &ack(&request, &manifest, 1, 5),
            step * 1_000 - 1,
        );
        core.tick(step * 1_000);
        poll(&mut core, step * 1_000);
    }
    assert!(
        core.is_ended(id),
        "three retries, then the end, well before the 100 ms deadline"
    );
}

/// Retries without progress wait one, two, four and then eight intervals, eight at most, and receipt progress restores a one-interval wait.
#[test]
fn retries_without_progress_back_off_and_progress_restores_the_interval() {
    let table = RequestTable::<Request<Chunk>>::new(4, 2, 2);
    let config = ServeConfig {
        attempts: 10,
        ..CONFIG
    };
    let mut core = Core::new(config, table, 2, 128, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let request = get(1, 0, 4);
    let id = started(&mut core, &request, 4);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 3 * 8192,
    };
    core.chunk(id, manifest, 0..3 * 8192, payload(3 * 8192).into(), &[], 0);
    poll(&mut core, 0);
    // Retries at 1, 3, 7, 15 and 23 thousand microseconds: waits of 1, 2, 4, 8 and 8 intervals.
    let mut retried_at = Vec::new();
    for now in (100..=23_000).step_by(100) {
        let before = core.report().retries;
        core.tick(now);
        poll(&mut core, now);
        if core.report().retries > before {
            retried_at.push(now);
        }
    }
    assert_eq!(retried_at, [1_000, 3_000, 7_000, 15_000, 23_000]);
    core.ack(session(4), &ack(&request, &manifest, 1, 5), 23_500);
    core.tick(24_499);
    assert_eq!(core.report().retries, 5, "progress restarts the wait");
    core.tick(24_500);
    assert_eq!(core.report().retries, 6, "one interval after the progress");
    core.check_indexes();
}

/// A CANCEL clears the request's pending ERROR and its queued replays: nothing is sent for it afterwards.
#[test]
fn a_cancel_clears_pending_errors_and_queued_replays() {
    let mut core = core();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    core.read_refused(id, Status::DeviceError, 0);
    let cancel = Header {
        kind: Kind::Cancel,
        status: Status::Cancelled as u16,
        metadata_len: 0,
        body_len: 0,
        grant: 0,
        remaining_ms: 0,
        ..request
    };
    core.cancel(session(2), &cancel, 0);
    assert!(
        poll(&mut core, 0).is_empty(),
        "the pending ERROR was cleared"
    );
    core.release_drained(|_| true);
    assert_eq!(core.get(session(2), &request, 0), GetOutcome::Replayed);
    core.cancel(session(2), &cancel, 0);
    assert!(
        poll(&mut core, 0).is_empty(),
        "the queued replay was cleared"
    );
}

/// A CANCEL targets its session's request by wire ID and key: one under another key leaves the live request sending with its chunk retained and clears only the queued replies under its own key.
#[test]
fn a_cancel_under_another_key_leaves_the_request_running() {
    let mut core = core();
    let request = get(1, 0, 2);
    let id = started(&mut core, &request, 2);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 9000,
    };
    core.chunk(id, manifest, 0..9000, payload(9000).into(), &[], 0);
    let conflicting = Header {
        key: [5; 32],
        ..request
    };
    let cancel = |key| Header {
        kind: Kind::Cancel,
        status: Status::Cancelled as u16,
        metadata_len: 0,
        body_len: 0,
        grant: 0,
        remaining_ms: 0,
        key,
        ..request
    };
    assert_eq!(
        core.get(session(2), &conflicting, 0),
        GetOutcome::Refused(Status::ConflictingRequest)
    );
    core.cancel(session(2), &cancel([6; 32]), 0);
    assert!(
        !core.is_ended(id),
        "a CANCEL under a third key ends nothing"
    );
    assert_eq!(core.retained(id), 1);
    let sent = poll(&mut core, 0);
    assert_eq!(
        sent.iter()
            .map(|frame| (frame.header.kind, frame.header.key[0]))
            .collect::<Vec<_>>(),
        [
            (Kind::Error, 5),
            (Kind::Start, 9),
            (Kind::Data, 9),
            (Kind::Data, 9)
        ],
        "the conflicting GET's refusal survives a CANCEL under a third key"
    );
    assert_eq!(
        core.get(session(2), &conflicting, 0),
        GetOutcome::Refused(Status::ConflictingRequest)
    );
    core.cancel(session(2), &cancel([5; 32]), 0);
    assert!(
        !core.is_ended(id),
        "a CANCEL under the conflicting key ends nothing"
    );
    assert!(
        poll(&mut core, 0).is_empty(),
        "the refusal under the CANCEL's key was cleared"
    );
    core.cancel(session(2), &cancel(request.key), 0);
    assert!(
        core.is_ended(id),
        "a CANCEL under the request's key ends it"
    );
    assert_eq!(core.retained(id), 0);
}

/// Retirement discards the old session's pending ERRORs and queued replies, which no later session can carry, so nothing is sent for them and the requests release once drained.
#[test]
fn retirement_discards_the_old_sessions_queued_frames() {
    let mut core = core();
    let failed = get(1, 0, 2);
    let id = started(&mut core, &failed, 2);
    core.read_refused(id, Status::DeviceError, 0);
    core.get(
        session(2),
        &Header {
            grant: 9,
            ..get(2, 0, 9)
        },
        0,
    );
    core.retire_peer(PeerId(0), 0);
    assert!(poll(&mut core, 0).is_empty());
    assert_eq!(core.release_drained(|_| true), 1);
}

/// A GET from another epoch of the same peer never joins a live request of the old epoch, and a GET past the session's negotiated slots is refused.
#[test]
fn duplicates_bind_their_session_and_slots_bind_the_negotiated_cap() {
    let mut core = core();
    let request = get(1, 0, 2);
    started(&mut core, &request, 2);
    let replaced = Admitted {
        epoch: 5,
        ..session(2)
    };
    assert_eq!(
        core.get(
            replaced,
            &Header {
                epoch: 5,
                ..request
            },
            0
        ),
        GetOutcome::Refused(Status::SessionMismatch)
    );
    let narrow = Admitted {
        caps: Caps {
            slots: 2,
            window: 2,
        },
        ..session(2)
    };
    assert_eq!(
        core.get(narrow, &get(2, 0, 2), 0),
        GetOutcome::Refused(Status::InvalidRequest)
    );
}

/// Retries fire at exactly the time the last progress schedules, whatever ticks ran before: a tick between due times changes nothing, an ACK that makes progress moves the retry later, and a first DATA sent after every earlier fragment was acknowledged waits from that earlier progress.
#[test]
fn retries_fire_at_their_due_time_across_idle_ticks() {
    let mut core = core();
    let request = get(1, 0, 1);
    let id = started(&mut core, &request, 1);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 2 * 8192,
    };
    core.chunk(id, manifest, 0..2 * 8192, payload(2 * 8192).into(), &[], 0);
    assert_eq!(
        kinds(&poll(&mut core, 0)),
        [(Kind::Start, 0), (Kind::Data, 0)],
        "a window of one"
    );
    // The START receipt at 500 makes progress; fragment 0 is still unacknowledged.
    core.ack(session(1), &ack(&request, &manifest, 0, 1), 500);
    core.tick(1_400);
    assert!(
        poll(&mut core, 1_400).is_empty(),
        "the retry is due at 1,500"
    );
    core.tick(1_499);
    assert!(poll(&mut core, 1_499).is_empty());
    core.tick(1_500);
    assert_eq!(kinds(&poll(&mut core, 1_500)), [(Kind::Data, 0)]);
    assert_eq!(core.report().retries, 1);
    // Everything sent is acknowledged at 1,600, so no retry is pending.
    core.ack(session(1), &ack(&request, &manifest, 1, 1), 1_600);
    core.tick(5_000);
    assert!(
        poll(&mut core, 5_000).is_empty(),
        "the grant admits nothing new"
    );
    assert_eq!(core.report().retries, 1);
    // The grant raised at 5,100 lets fragment 1 go out at 5,200; its retry counts from the 5,100 progress.
    core.ack(session(1), &ack(&request, &manifest, 1, 2), 5_100);
    assert_eq!(kinds(&poll(&mut core, 5_200)), [(Kind::Data, 1)]);
    core.tick(6_099);
    assert!(poll(&mut core, 6_099).is_empty());
    core.tick(6_100);
    assert_eq!(kinds(&poll(&mut core, 6_100)), [(Kind::Data, 1)]);
    assert_eq!(core.report().retries, 2);
}

/// A request that gains a frame after a poll found none is sent by the next poll: a chunk after an empty poll, a grant after the window closed, and a new request in a table slot a released request vacated.
#[test]
fn a_frame_gained_after_an_empty_poll_is_sent_next() {
    let mut core = core();
    let request = get(1, 0, 1);
    let id = started(&mut core, &request, 1);
    assert!(poll(&mut core, 0).is_empty(), "no manifest yet");
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 2 * 8192,
    };
    core.chunk(id, manifest, 0..2 * 8192, payload(2 * 8192).into(), &[], 0);
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    assert_eq!(
        kinds(&poll(&mut core, 0)),
        [(Kind::Start, 0), (Kind::Data, 0)]
    );
    assert!(poll(&mut core, 0).is_empty(), "the window of one is spent");
    core.ack(session(1), &ack(&request, &manifest, 1, 2), 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Data, 1)]);
    core.ack(session(1), &ack(&request, &manifest, 2, 2), 0);
    assert_eq!(kinds(&poll(&mut core, 0)), [(Kind::Complete, 2)]);
    assert_eq!(core.release_drained(|_| true), 1);
    assert!(poll(&mut core, 0).is_empty());
    // The next request takes the vacated table slot and sends from it.
    let next = get(2, 0, 1);
    let later = started(&mut core, &next, 1);
    assert_eq!(later.slot(), id.slot(), "the freed slot is reused first");
    core.chunk(
        later,
        manifest,
        0..2 * 8192,
        payload(2 * 8192).into(),
        &[],
        0,
    );
    assert_eq!(
        kinds(&poll(&mut core, 0)),
        [(Kind::Start, 0), (Kind::Data, 0)]
    );
}

/// A drain release visits every ended request wherever it sits among active ones, releases exactly those the predicate proves, and leaves the rest draining.
#[test]
fn a_drain_release_visits_every_ended_request() {
    let mut core = core();
    let other = Admitted {
        peer: PeerId(1),
        ..session(2)
    };
    let first = started(&mut core, &get(0, 0, 2), 2);
    let GetOutcome::Read { id: between, .. } = core.get(other, &get(0, 0, 2), 0) else {
        panic!("peer 1's request");
    };
    core.read_started(between);
    let last = started(&mut core, &get(1, 0, 2), 2);
    let ids = [first, between, last];
    assert!(ids[0].slot() < ids[1].slot() && ids[1].slot() < ids[2].slot());
    core.read_refused(ids[0], Status::Missing, 0);
    core.read_refused(ids[2], Status::Missing, 0);
    assert_eq!(poll(&mut core, 0).len(), 2, "both ERRORs go out");
    assert_eq!(core.requests().census().draining, 2);
    assert_eq!(core.release_drained(|id| id == ids[2]), 1);
    assert!(core.requests().get(ids[0]).is_some(), "still draining");
    assert!(core.requests().get(ids[1]).is_some(), "still active");
    assert!(core.requests().get(ids[2]).is_none());
    assert_eq!(core.release_drained(|_| true), 1);
    assert_eq!(core.requests().census().draining, 0);
    assert_eq!(core.requests().census().active, 1);
    assert_eq!(core.release_drained(|_| true), 0);
}

/// Replies queued after an empty reply round go out on the next poll, and a retired peer's queued replies never do.
#[test]
fn replies_queued_after_an_empty_round_are_sent_and_a_retired_peers_are_not() {
    let mut core = core();
    assert!(poll(&mut core, 0).is_empty());
    let refused = Header {
        grant: 9,
        ..get(1, 0, 9)
    };
    assert_eq!(
        core.get(session(2), &refused, 0),
        GetOutcome::Refused(Status::InvalidRequest)
    );
    let sent = poll(&mut core, 0);
    assert_eq!(kinds(&sent), [(Kind::Error, 0)]);
    assert_eq!(sent[0].header.status, Status::InvalidRequest as u16);
    assert!(poll(&mut core, 0).is_empty());
    let other = Admitted {
        peer: PeerId(1),
        ..session(2)
    };
    core.get(session(2), &refused, 0);
    core.get(session(2), &refused, 0);
    core.retire_peer(PeerId(0), 0);
    assert!(
        poll(&mut core, 0).is_empty(),
        "the retired peer's replies are discarded"
    );
    core.get(other, &refused, 0);
    assert_eq!(poll(&mut core, 0).len(), 1, "peer 1's refusal");
}

/// Checking a token and spending it after the send matches taking one, and spends nothing while the bucket is empty.
#[test]
fn a_ready_check_and_a_spend_match_a_take() {
    let mut pacer = Pacer::new(1_000, 2, 0);
    assert!(pacer.ready(0));
    pacer.spend();
    assert!(pacer.ready(0));
    pacer.spend();
    assert!(!pacer.ready(0), "the burst is spent");
    assert!(!pacer.ready(999));
    assert!(pacer.ready(1_000));
    assert!(pacer.ready(1_000), "a check takes nothing");
    assert!(pacer.take(1_000));
    assert!(!pacer.ready(1_000));
}

/// A wait on receipt that starts after the request waited on nothing for longer than the retry interval retries at the next tick, because its retry counts from its last progress, and resends from the base; this holds whether or not a tick ran during the idle interval.
#[test]
fn a_wait_started_after_an_idle_interval_retries_from_its_last_progress() {
    for idle_tick in [false, true] {
        let mut core = core();
        let request = get(2, 0, 8);
        let id = started(&mut core, &request, 8);
        let manifest = Manifest {
            allocation: 7,
            metadata_len: 0,
            body_len: 3 * 8192,
        };
        core.chunk(id, manifest, 0..8192, payload(8192).into(), &[], 0);
        core.granted(id);
        assert_eq!(
            kinds(&poll(&mut core, 0)),
            [(Kind::Start, 0), (Kind::Data, 0)]
        );
        core.ack(session(8), &ack(&request, &manifest, 1, 9), 100);
        core.check_indexes();
        if idle_tick {
            // Every sent fragment is acknowledged, so a tick past the retry time retries nothing.
            core.tick(1_200);
            core.check_indexes();
            assert!(poll(&mut core, 1_200).is_empty());
        }
        core.chunk(
            id,
            manifest,
            8192..3 * 8192,
            payload(2 * 8192).into(),
            &[],
            3_000,
        );
        assert_eq!(
            kinds(&poll(&mut core, 3_000)),
            [(Kind::Data, 1), (Kind::Data, 2)]
        );
        core.check_indexes();
        core.tick(3_000);
        core.check_indexes();
        assert_eq!(core.report().retries, 1, "idle tick {idle_tick}");
        assert_eq!(
            kinds(&poll(&mut core, 3_000)),
            [(Kind::Data, 1), (Kind::Data, 2)],
            "the retry restarts at the base"
        );
        core.tick(4_999);
        assert_eq!(
            core.report().retries,
            1,
            "the next retry without progress waits twice the interval"
        );
        core.tick(5_000);
        assert_eq!(core.report().retries, 2);
        core.check_indexes();
    }
}

/// A data round sends each request's granted frames in one burst, in slot order from where the last round stopped, skipping requests with nothing to send; an ACK that opens a request's grant brings it back into the round at its slot.
#[test]
fn the_data_round_skips_idle_requests_and_resumes_after_its_last_send() {
    let table = RequestTable::<Request<Chunk>>::new(4, 2, 3);
    let mut core = Core::new(CONFIG, table, 2, 64, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 4 * 8192,
    };
    let requests: Vec<Header> = (0..3).map(|slot| get(slot, 0, 2)).collect();
    let ids: Vec<RequestId> = requests
        .iter()
        .map(|request| {
            let id = started(&mut core, request, 4);
            core.chunk(id, manifest, 0..4 * 8192, payload(4 * 8192).into(), &[], 0);
            id
        })
        .collect();
    let order = |core: &mut Core<Chunk>, budget| {
        let mut sent = Vec::new();
        core.poll(0, budget, |frames| {
            for out in frames {
                sent.push((out.header.request >> 48, out.header.kind, out.header.index));
            }
            sent.len()
        });
        core.check_indexes();
        sent
    };
    assert_eq!(
        order(&mut core, 4),
        [
            (0, Kind::Start, 0),
            (0, Kind::Data, 0),
            (0, Kind::Data, 1),
            (1, Kind::Start, 0)
        ]
    );
    // Request 0 spent its grant of two; the round resumes at request 2, wraps past the idle request 0, and finishes request 1's grant.
    assert_eq!(
        order(&mut core, 64),
        [
            (2, Kind::Start, 0),
            (2, Kind::Data, 0),
            (2, Kind::Data, 1),
            (1, Kind::Data, 0),
            (1, Kind::Data, 1)
        ]
    );
    assert!(order(&mut core, 64).is_empty(), "every grant is spent");
    core.ack(session(4), &ack(&requests[1], &manifest, 2, 4), 0);
    assert_eq!(
        order(&mut core, 64),
        [(1, Kind::Data, 2), (1, Kind::Data, 3)],
        "only the opened request sends"
    );
    assert!(ids.iter().all(|&id| !core.is_ended(id)));
}

/// While peer 0 is out of pacing tokens, a poll sends peer 1's 16 frames within 23 request visits, one per send plus one per ready request; peer 0 sends again after the refill.
#[test]
fn a_data_round_visits_a_paced_peers_requests_once_per_poll() {
    let config = ServeConfig {
        rate_per_sec: 1_000,
        burst: 16,
        ..CONFIG
    };
    let table = RequestTable::<Request<Chunk>>::new(8, 2, 6);
    let mut core = Core::new(config, table, 2, 64, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let small = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 4 * 8192,
    };
    for slot in 0..6 {
        let id = started(&mut core, &get(slot, 0, 4), 4);
        core.chunk(id, small, 0..4 * 8192, payload(4 * 8192).into(), &[], 0);
    }
    // Six requests of five frames each spend peer 0's burst of 16 and keep frames to send.
    assert_eq!(core.poll(0, 64, |frames| frames.count()), 16);
    let other = Admitted {
        peer: PeerId(1),
        ..session(64)
    };
    let large = Manifest {
        allocation: 8,
        metadata_len: 0,
        body_len: 32 * 8192,
    };
    let GetOutcome::Read { id, .. } = core.get(other, &get(0, 0, 64), 0) else {
        panic!("peer 1's request");
    };
    core.read_started(id);
    core.chunk(id, large, 0..32 * 8192, payload(32 * 8192).into(), &[], 0);
    take_send_visits();
    let mut peers = Vec::new();
    let sent = core.poll(0, 16, |frames| {
        peers.extend(frames.map(|out| out.peer));
        peers.len()
    });
    let visits = take_send_visits();
    assert_eq!(sent, 16);
    assert!(peers.iter().all(|&peer| peer == PeerId(1)));
    assert!(
        visits <= 16 + 7,
        "{visits} visits for 16 sends among 7 ready requests"
    );
    core.check_indexes();
    let mut refilled = Vec::new();
    core.poll(1_000_000, 64, |frames| {
        refilled.extend(frames.map(|out| out.peer));
        refilled.len()
    });
    assert!(
        refilled.contains(&PeerId(0)),
        "the paced requests send after the refill"
    );
}

#[test]
fn requests_of_one_paced_peer_take_turns_at_one_token_per_poll() {
    let config = ServeConfig {
        retry_us: 1_000_000,
        rate_per_sec: 1_000,
        burst: 1,
        ..CONFIG
    };
    let table = RequestTable::<Request<Chunk>>::new(4, 2, 2);
    let mut core = Core::new(config, table, 2, 64, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 16 * 8192,
    };
    for slot in 0..2 {
        let id = started(&mut core, &get(slot, 0, 16), 16);
        core.chunk(
            id,
            manifest,
            0..16 * 8192,
            payload(16 * 8192).into(),
            &[],
            0,
        );
    }
    let senders: Vec<u64> = (0..8u64)
        .flat_map(|at| poll(&mut core, at * 1_000))
        .map(|frame| frame.header.request >> 48)
        .collect();
    assert_eq!(
        senders,
        [0, 1, 0, 1, 0, 1, 0, 1],
        "one frame per token, the two requests alternating"
    );
    core.check_indexes();
}

/// A test chunk that counts its body crc derivations and, on each, meets the zero-run lengths `lens` of its record shape, as a chunk deriving from window checksums does.
struct Probe {
    bytes: Box<[u8]>,
    lens: [u64; 3],
    derived: std::rc::Rc<std::cell::Cell<usize>>,
}

impl AsRef<[u8]> for Probe {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl super::serve::Chunk for Probe {
    fn device_held(&self) -> bool {
        false
    }

    fn crc(
        &self,
        crc: crate::storage::Crc32c,
        runs: &mut crate::storage::ZeroRuns,
        _window_crcs: &[u32],
        range: std::ops::Range<usize>,
    ) -> u32 {
        self.derived.set(self.derived.get() + 1);
        for len in self.lens {
            runs.run(crc, len);
        }
        crc.checksum(&self.bytes[range])
    }
}

impl super::serve::Retained<'_> for Probe {
    fn source(
        &self,
        _range: std::ops::Range<usize>,
    ) -> Option<crate::storage::SourceRange<'_, 'static>> {
        None
    }
}

/// Polls `core` at `now_us` and returns the DATA frames it sent.
fn data_sent(core: &mut Core<Probe>, now_us: u64) -> usize {
    let mut data = 0;
    core.poll(now_us, 64, |frames| {
        frames
            .map(|out| data += usize::from(out.header.kind == Kind::Data))
            .count()
    });
    data
}

/// A DATA frame's body crc is derived only once its peer's pacer admits the frame: polls that find the pacer empty derive nothing, so derivations equal DATA frames sent.
#[test]
fn a_paced_frame_derives_its_body_crc_only_when_sent() {
    let config = ServeConfig {
        rate_per_sec: 1_000,
        burst: 1,
        ..CONFIG
    };
    let table = RequestTable::<Request<Probe>>::new(4, 1, 4);
    let mut core =
        Core::<Probe>::new(config, table, 1, 16, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let GetOutcome::Read { id, .. } = core.get(session(8), &get(1, 0, 8), 0) else {
        panic!("a new request");
    };
    core.read_started(id);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 3 * 8192,
    };
    let derived = std::rc::Rc::new(std::cell::Cell::new(0));
    let chunk = Probe {
        bytes: payload(3 * 8192).into(),
        lens: [1, 2, 3],
        derived: derived.clone(),
    };
    core.chunk(id, manifest, 0..3 * 8192, chunk, &[], 0);
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    let mut sent = 0;
    for now_us in [0, 0, 0, 400, 800, 1_000, 1_000, 1_500, 2_000, 2_000, 3_000] {
        sent += data_sent(&mut core, now_us);
    }
    assert!(sent >= 3, "every fragment sent once the pacer refills");
    assert_eq!(derived.get(), sent, "one derivation per DATA frame sent");
}

/// Each request keeps the zero runs of its own record shape: four requests whose shapes meet twelve lengths between them, served round robin, build each length once.
#[test]
fn round_robin_requests_build_each_of_their_zero_runs_once() {
    let table = RequestTable::<Request<Probe>>::new(8, 1, 8);
    let mut core =
        Core::<Probe>::new(CONFIG, table, 1, 64, 0, 4, &mut EngineBudget::new(1 << 20)).unwrap();
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 4 * 8192,
    };
    let derived = std::rc::Rc::new(std::cell::Cell::new(0));
    for shape in 0..4u16 {
        let GetOutcome::Read { id, .. } = core.get(session(8), &get(shape, 0, 8), 0) else {
            panic!("a new request");
        };
        core.read_started(id);
        let base = 100 * u64::from(shape);
        let chunk = Probe {
            bytes: payload(4 * 8192).into(),
            lens: [base + 7, base + 8, base + 9],
            derived: derived.clone(),
        };
        core.chunk(id, manifest, 0..4 * 8192, chunk, &[], 0);
        core.read_done(id, ReadEnd::Complete(manifest), 0);
    }
    crate::storage::take_zero_run_builds();
    // A batch of four frames per poll stages one fragment of each request per round.
    for _ in 0..8 {
        core.poll(0, 4, |frames| frames.count());
    }
    assert_eq!(derived.get(), 16, "every fragment of every request derived");
    assert_eq!(
        crate::storage::take_zero_run_builds(),
        12,
        "each request builds its three lengths once"
    );
}

/// Every status an ERROR frame can carry has its own entry in the report's status counts.
#[test]
fn every_wire_status_has_its_error_count_entry() {
    let codes: Vec<_> = (0..=u16::MAX)
        .filter_map(Status::from_wire)
        .map(|status| status as usize)
        .collect();
    assert_eq!(
        codes,
        (1..=super::serve::STATUSES).collect::<Vec<_>>(),
        "codes 1 through STATUSES, each once"
    );
}

#[test]
fn a_refused_terminal_keeps_its_binding_and_a_sent_terminal_frees_it() {
    let mut core = core();
    let request = get(0, 1, 2);
    let old = started(&mut core, &request, 2);
    core.read_refused(old, Status::Missing, 0);
    assert_eq!(core.poll(0, 128, |_| 0), 0);
    assert_eq!(core.requests.slot(PeerId(0), 0).unwrap().active, Some(old));
    assert_eq!(poll(&mut core, 0)[0].header.kind, Kind::Error);
    assert_eq!(core.requests.slot(PeerId(0), 0).unwrap().active, None);
    assert_eq!(core.release_drained(|_| false), 0);
    assert_eq!(core.requests().census().draining, 1);
    let replacement = get(0, 2, 2);
    let next = started(&mut core, &replacement, 2);
    assert_ne!(next.slot(), old.slot());
    let census = core.requests().census();
    let report = core.report();
    assert_eq!(core.get(session(2), &request, 0), GetOutcome::Dropped);
    core.cancel(
        session(2),
        &Header {
            kind: Kind::Cancel,
            ..request
        },
        0,
    );
    core.ack(
        session(2),
        &Header {
            kind: Kind::Ack,
            ..request
        },
        0,
    );
    assert_eq!(core.requests().census(), census);
    assert_eq!(core.report().stale_acks, report.stale_acks + 1);
    assert_eq!(core.report().requests, report.requests);
    assert_eq!(core.report().refused_pressure, report.refused_pressure);
    assert!(!core.is_ended(next));
    assert_eq!(core.release_drained(|id| id == old), 1);
    assert_eq!(core.requests.slot(PeerId(0), 0).unwrap().active, Some(next));
}

#[test]
fn only_a_sent_terminal_replay_frees_a_silently_cancelled_binding() {
    let mut core = core();
    let request = get(0, 1, 2);
    let old = started(&mut core, &request, 2);
    core.cancel(
        session(2),
        &Header {
            kind: Kind::Cancel,
            ..request
        },
        0,
    );
    assert!(poll(&mut core, 0).is_empty());
    assert_eq!(core.requests.slot(PeerId(0), 0).unwrap().active, Some(old));
    assert_eq!(
        core.get(
            session(2),
            &Header {
                body_len: request.body_len - 1,
                ..request
            },
            0
        ),
        GetOutcome::Refused(Status::ConflictingRequest)
    );
    assert_eq!(
        poll(&mut core, 0)[0].header.status,
        Status::ConflictingRequest as u16
    );
    assert_eq!(core.requests.slot(PeerId(0), 0).unwrap().active, Some(old));
    assert_eq!(core.get(session(2), &request, 0), GetOutcome::Replayed);
    assert_eq!(core.poll(0, 128, |_| 0), 0);
    assert_eq!(core.requests.slot(PeerId(0), 0).unwrap().active, Some(old));
    assert_eq!(poll(&mut core, 0)[0].header.kind, Kind::Error);
    assert_eq!(core.requests.slot(PeerId(0), 0).unwrap().active, None);
    assert_eq!(core.requests().census().draining, 1);
    let next = started(&mut core, &get(0, 2, 2), 2);
    assert_ne!(old.slot(), next.slot());
    assert_eq!(core.release_drained(|id| id == old), 1);
    assert_eq!(core.requests.slot(PeerId(0), 0).unwrap().active, Some(next));
}
