//! Packed GETs at the client over its test owner and a throttled transport: the GET frames one poll hands out leave
//! as one block in the fewest datagrams of up to eight frames, every other frame keeps a datagram of its own, a
//! transport that takes a prefix of the datagrams leaves exactly the frames of the rest due, a spent send sequence
//! drops the frames it did not stage, and the fetch report counts GETs per datagram and the time from admission to
//! each GET's first taken send. Assertions about what the client sent read literal lengths and parse each 192-byte
//! chunk as one frame.

use super::*;

use super::super::datagram::MAX_PACKED_GETS;
use super::super::fetch::FIRST_SEND_BUCKETS;
use super::super::rules::{Chain, Effect, MANIFEST, Rule, Selector};

/// Session caps wide enough for the 17-GET cases.
const WIDE_CAPS: Caps = Caps {
    slots: 32,
    window: 2,
};

/// [`CONFIG`] widened for the 17-GET cases: 32 request slots, a window of 2, 64 boxes and a batch of 24.
const WIDE: ClientConfig = ClientConfig {
    caps: WIDE_CAPS,
    fetch: FetchConfig {
        window: 2,
        boxes: 64,
        ..CONFIG.fetch
    },
    batch: 24,
    ..CONFIG
};

/// A receive pool of 112 buffers with 24 reserved for control, so 88 data buffers back [`WIDE`]'s 64 boxes.
fn wide_pool() -> PacketPool<'static> {
    super::super::packet::test_pool(112, 24).unwrap()
}

fn wide_releases() -> Releases {
    Releases::new(32, &mut EngineBudget::new(1 << 20)).unwrap()
}

/// A client under [`WIDE`] over a table of 32 request slots, with `sources` and boot nonce `[0x0C; 16]`.
fn wide_client<'m, D: Datagrams<'m>>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    transport: D,
    sources: Box<[super::super::upload::SourceSlot<'m>]>,
) -> Client<'m, D> {
    pinned_client_with(pool, releases, transport, WIDE, sources)
}

impl Owner {
    /// A test owner whose session caps and serve core admit 32 requests.
    fn wide(objects: Vec<([u8; 32], Vec<u8>)>) -> Self {
        let serve = ServeConfig {
            slots: 32,
            replies: 32,
            ..SERVE
        };
        Self::sized(objects, [0x0A; 16], WIDE_CAPS, serve)
    }
}

/// A datagram toward the owner as its length and the kind, request and sequence of each of its frames.
type Sent = (usize, Vec<(Kind, u64, u64)>);

/// The kind, request and sequence of each 192-byte frame of `datagram`, which is a whole number of frames.
fn frames_of(datagram: &[u8]) -> Vec<(Kind, u64, u64)> {
    assert_eq!(datagram.len() % HEADER_LEN, 0, "whole frames");
    datagram
        .chunks(HEADER_LEN)
        .map(kind_request_sequence)
        .collect()
}

/// Every datagram in flight toward the owner, taken off the link, as its length and its frames.
fn sent(net: &Rc<RefCell<Net<'_>>>) -> Vec<Sent> {
    take_toward(net, 1)
        .iter()
        .map(|datagram| (datagram.len(), frames_of(datagram)))
        .collect()
}

/// Opens `client`'s session with `owner` over `net`, returning the turn reached; nothing is in flight after.
fn opened<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    owner: &mut Owner,
    owner_end: &mut LinkEnd<'_>,
    net: &Rc<RefCell<Net<'_>>>,
) -> u64 {
    client.session(0);
    let turn = drive(client, owner, owner_end, net, 0, 1_000, active);
    assert_eq!(client.state(), SessionState::Active);
    assert!(take_toward(net, 1).is_empty(), "nothing in flight");
    turn
}

/// Admits `count` GETs of key `[1; 32]` at `now`, which take table slots 0 up of a fresh client, in admission order.
fn gets<'m, D: Datagrams<'m>>(client: &mut Client<'m, D>, count: u16, now: u64) -> Vec<RequestId> {
    let ids: Vec<_> = (0..count)
        .map(|_| client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap())
        .collect();
    assert!(
        ids.iter().map(|id| id.slot()).eq(0..count),
        "premise: {count} GETs at slots 0 up"
    );
    ids
}

/// `K` GET frames handed out in one poll leave in `ceil(K / 8)` datagrams of literal lengths, cut from the block's
/// start, each frame a canonical GET under the next session sequence. A fresh client's requests take table slots 0 up
/// and hand-out starts at slot 0, so hand-out order is slot order, and the request IDs are literal.
#[test]
fn k_gets_of_one_poll_leave_in_the_fewest_datagrams_of_eight() {
    for (k, lengths) in [
        (1, &[192][..]),
        (2, &[384]),
        (8, &[1536]),
        (9, &[1536, 192]),
        (17, &[1536, 1536, 192]),
    ] {
        let pool = wide_pool();
        let releases = wide_releases();
        let (client_end, mut owner_end, net) = network(64, 8384, 21, [Faults::default(); 2]);
        let mut owner = Owner::wide(vec![]);
        let mut client = wide_client(&pool, &releases, client_end, Box::default());
        let now = opened(&mut client, &mut owner, &mut owner_end, &net) * 100;
        gets(&mut client, k, now);
        let report = client.poll(now);
        assert_eq!(report.sent as usize, lengths.len(), "K = {k}");
        let sent = sent(&net);
        let datagrams: Vec<usize> = sent.iter().map(|(len, _)| *len).collect();
        assert_eq!(datagrams, lengths, "K = {k}");
        let frames: Vec<_> = sent.into_iter().flat_map(|(_, frames)| frames).collect();
        let expected: Vec<_> = (0..u64::from(k))
            .map(|n| (Kind::Get, n << 48 | n, 1 + n))
            .collect();
        assert_eq!(frames, expected, "K = {k}");
    }
}

/// Hand-out follows table slots from the cursor, so after the cursor moved to slot 5, nine GETs at slots 0 to 8 are
/// handed out from slot 5 and wrap: the first datagram carries slots 5 to 8 then 0 to 3, and the second slot 4. The
/// order the test claims comes from the requests' slots and the cursor alone. The five requests retired in
/// admission order leave table slots 4 down to 0 to the next five GETs, whose wire slots are 0 up, so an order by
/// wire slot gives another list.
#[test]
fn a_moved_cursor_starts_the_block_at_its_slot() {
    let pool = wide_pool();
    let releases = wide_releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 22, [Faults::default(); 2]);
    let mut owner = Owner::wide(vec![]);
    let mut client = wide_client(&pool, &releases, client_end, Box::default());
    let now = opened(&mut client, &mut owner, &mut owner_end, &net) * 100;
    let first: Vec<_> = (0..5)
        .map(|_| client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap())
        .collect();
    assert_eq!(client.poll(now).sent, 1);
    for id in &first {
        client.cancel(*id);
    }
    assert_eq!(client.poll(now).sent, 5, "five CANCELs, each alone");
    for id in &first {
        assert!(client.retire(*id));
    }
    take_toward(&net, 1);
    let ids: Vec<_> = (0..9)
        .map(|_| client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap())
        .collect();
    let slot_pairs: Vec<(u16, u64)> = ids
        .iter()
        .map(|id| (id.slot(), client.get_wire(*id).unwrap() >> 48))
        .collect();
    assert_eq!(
        slot_pairs[..5],
        [(4, 0), (3, 1), (2, 2), (1, 3), (0, 4)],
        "premise: table slot and wire slot differ, so the two orders differ"
    );
    let cursor = 5;
    let mut order: Vec<_> = ids.clone();
    order.sort_by_key(|id| (id.slot() + 32 - cursor) % 32);
    let slots: Vec<u16> = order.iter().map(|id| id.slot()).collect();
    assert_eq!(
        slots,
        [5, 6, 7, 8, 0, 1, 2, 3, 4],
        "premise: the slots the GETs took"
    );
    assert_eq!(client.poll(now).sent, 2);
    let sent = sent(&net);
    let datagrams: Vec<usize> = sent.iter().map(|(len, _)| *len).collect();
    assert_eq!(datagrams, [1536, 192]);
    let frames: Vec<_> = sent.into_iter().flat_map(|(_, frames)| frames).collect();
    let claimed: Vec<_> = order
        .iter()
        .zip(11..)
        .map(|(id, sequence)| (Kind::Get, client.get_wire(*id).unwrap(), sequence))
        .collect();
    assert_eq!(frames, claimed);
    let literal: Vec<u64> = frames.iter().map(|(_, request, _)| *request).collect();
    assert_eq!(
        literal,
        [
            5 << 48 | 10,
            6 << 48 | 11,
            7 << 48 | 12,
            8 << 48 | 13,
            4 << 48 | 9,
            3 << 48 | 8,
            2 << 48 | 7,
            1 << 48 | 6,
            5,
        ]
    );
}

/// A client of the 8-slot fixture with a window of 2 over `transport`, after one poll sent eight GETs at slots 0 to 7 as one packed
/// datagram and the test owner answered them: the GETs at `kept` name the owner's object and the rest a missing key,
/// and the START of each GET at `kept` is taken off the link, with every other frame toward the client cleared. The
/// poll leaves the cursor at slot 0, after slot 7.
struct Answered<'m, D> {
    client: Client<'m, D>,
    net: Rc<RefCell<Net<'m>>>,
    ids: Vec<RequestId>,
    starts: Vec<Vec<u8>>,
    now: u64,
}

impl<'m, D: Datagrams<'m>> Answered<'m, D> {
    /// Admits one more GET of the owner's object at `now`.
    fn get(&mut self) -> RequestId {
        self.client
            .get([1; 32], 0, 1 << 20, self.now, 1_000_000)
            .unwrap()
    }
}

fn eight_answered<'m, D: Datagrams<'m>>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    end: impl FnOnce(LinkEnd<'m>) -> D,
    kept: &[usize],
) -> Answered<'m, D> {
    let (client_end, mut owner_end, net) = network(64, 8384, 23, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(1_000, 23))]);
    let config = ClientConfig {
        fetch: FetchConfig {
            window: 2,
            ..CONFIG.fetch
        },
        ..CONFIG
    };
    let mut client = client_with(pool, releases, end(client_end), config);
    let turn = opened(&mut client, &mut owner, &mut owner_end, &net);
    let now = turn * 100;
    let ids: Vec<_> = (0..8)
        .map(|n| {
            let key = if kept.contains(&n) { [1; 32] } else { [2; 32] };
            client.get(key, 0, 1 << 20, now, 1_000_000).unwrap()
        })
        .collect();
    assert!(
        ids.iter().map(|id| id.slot()).eq(0..8),
        "premise: slots 0 to 7"
    );
    assert_eq!(client.poll(now).sent, 1);
    let sent: Vec<_> = net.borrow().peek(1).into_iter().collect();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].len(),
        8 * HEADER_LEN,
        "one packed datagram of eight"
    );
    owner_turn(&mut owner, &mut owner_end, &net, turn + 1);
    let starts = kept
        .iter()
        .map(|&n| take_start(&net, client.get_wire(ids[n]).unwrap()))
        .collect();
    net.borrow_mut().clear(0);
    Answered {
        client,
        net,
        ids,
        starts,
        now: now + 100,
    }
}

/// Cancels the requests at `cancelled`, sends their CANCELs in one poll, which leaves the cursor at slot 0 when slot 7
/// is among them, and retires them in the listed order, so the next GETs take the retired slots in reverse order.
fn cancel_and_retire<'m, D: Datagrams<'m>>(answered: &mut Answered<'m, D>, cancelled: &[usize]) {
    for &n in cancelled {
        answered.client.cancel(answered.ids[n]);
    }
    assert_eq!(
        answered.client.poll(answered.now).sent as usize,
        cancelled.len()
    );
    for &n in cancelled {
        assert!(answered.client.retire(answered.ids[n]));
    }
    take_toward(&answered.net, 1);
}

/// The wire order of three hand-outs, each from slot 0, with the order the test claims taken from the requests'
/// table slots. GET, ACK, GET, GET leaves as one datagram of three GET frames, under sequences s, s + 1 and s + 2, and
/// then the ACK under s + 3: the ACK follows the GET block, numbered when staged. ACK, GET, ACK, GET leaves as the
/// ACK, one datagram of two GET frames and the second ACK. GET, a CANCEL of another request, GET leaves as one
/// 384-byte datagram and then the CANCEL, in one poll. In the poll that takes a leading ACK and then the GET block, the
/// counters move for the GET datagram alone.
#[test]
fn an_ack_or_cancel_handed_out_between_gets_follows_the_get_block() {
    let (pool, board) = (receive_pool(), releases());
    let mut answered = eight_answered(&pool, &board, |end| end, &[1]);
    cancel_and_retire(&mut answered, &[7, 6, 5, 4, 3, 2, 0]);
    let (x, y, z) = (answered.get(), answered.get(), answered.get());
    assert_eq!(
        [x.slot(), answered.ids[1].slot(), y.slot(), z.slot()],
        [0, 1, 2, 3],
        "premise: hand-out from slot 0 is GET, ACK, GET, GET"
    );
    answered.net.borrow_mut().inject(0, &answered.starts[0]);
    assert_eq!(answered.client.poll(answered.now + 100).sent, 2);
    assert_eq!(
        sent(&answered.net),
        [
            (
                576,
                vec![
                    (Kind::Get, 8, 16),
                    (Kind::Get, 2 << 48 | 9, 17),
                    (Kind::Get, 3 << 48 | 10, 18),
                ]
            ),
            (192, vec![(Kind::Ack, 1 << 48 | 1, 19)]),
        ]
    );

    let (pool, board) = (receive_pool(), releases());
    let mut answered = eight_answered(&pool, &board, |end| end, &[0, 2]);
    cancel_and_retire(&mut answered, &[7, 6, 5, 4, 3, 1]);
    let (x, y) = (answered.get(), answered.get());
    assert_eq!(
        [
            answered.ids[0].slot(),
            x.slot(),
            answered.ids[2].slot(),
            y.slot()
        ],
        [0, 1, 2, 3],
        "premise: hand-out from slot 0 is ACK, GET, ACK, GET"
    );
    for start in &answered.starts {
        answered.net.borrow_mut().inject(0, start);
    }
    let before = counters(&answered.client);
    assert_eq!(answered.client.poll(answered.now + 100).sent, 3);
    let after = counters(&answered.client);
    let mut moved = before;
    moved.0[1] += 1;
    moved.1 += 200;
    moved.2[6] += 2;
    assert_eq!(
        after, moved,
        "the GET block taken behind the leading ACK counts one datagram of two and two first sends of 100 µs"
    );
    assert_eq!(
        sent(&answered.net),
        [
            (192, vec![(Kind::Ack, 0, 15)]),
            (
                384,
                vec![(Kind::Get, 1 << 48 | 8, 16), (Kind::Get, 3 << 48 | 9, 17)]
            ),
            (192, vec![(Kind::Ack, 2 << 48 | 2, 18)]),
        ]
    );

    let (pool, board) = (receive_pool(), releases());
    let mut answered = eight_answered(&pool, &board, |end| end, &[]);
    cancel_and_retire(&mut answered, &[7, 6, 5, 4, 3, 2, 0]);
    let (x, y) = (answered.get(), answered.get());
    answered.client.cancel(answered.ids[1]);
    assert_eq!(
        [x.slot(), answered.ids[1].slot(), y.slot()],
        [0, 1, 2],
        "premise: hand-out from slot 0 is GET, CANCEL, GET"
    );
    assert_eq!(answered.client.poll(answered.now + 100).sent, 2);
    assert_eq!(
        sent(&answered.net),
        [
            (384, vec![(Kind::Get, 8, 16), (Kind::Get, 2 << 48 | 9, 17)]),
            (192, vec![(Kind::Cancel, 1 << 48 | 1, 18)]),
        ]
    );
}

/// A client of [`WIDE`] with `sources` over a [`Throttled`] end of a fresh link, its session open with `owner`, with
/// the limits, the owner's link end, the link and the turn.
fn throttled<'m>(
    pool: &'m PacketPool<'m>,
    releases: &'m Releases,
    sources: Box<[super::super::upload::SourceSlot<'m>]>,
    owner: &mut Owner,
    seed: u64,
) -> (
    Client<'m, Throttled<'m>>,
    Rc<Limits>,
    LinkEnd<'m>,
    Rc<RefCell<Net<'m>>>,
    u64,
) {
    let (client_end, mut owner_end, net) = network(64, 8384, seed, [Faults::default(); 2]);
    let (transport, limits) = Throttled::new(client_end);
    let mut client = wide_client(pool, releases, transport, sources);
    let turn = opened(&mut client, owner, &mut owner_end, &net);
    (client, limits, owner_end, net, turn)
}

/// Every datagram in flight toward the owner as its length and its frames; the link keeps them.
fn in_flight(net: &Rc<RefCell<Net<'_>>>) -> Vec<Sent> {
    let mut datagrams = Vec::new();
    net.borrow_mut().retain(1, |datagram| {
        datagrams.push((datagram.len(), frames_of(datagram)));
        true
    });
    datagrams
}

/// Seventeen GETs leave as datagrams of 8, 8 and 1 frames; a transport whose allowance takes one datagram takes the
/// first, so the poll reports `(sent, blocked)` of (1, true), and the next poll carries exactly the nine requests of
/// the refused datagrams, each under a fresh sequence, while the eight taken stay sent: the owner admits 17 requests
/// and its serve core counts no duplicate GET, and its session counts no repeated sequence. The counters move for
/// the taken datagram alone: one datagram of eight and eight first sends after the first poll, and the two other
/// datagrams with nine first sends of 500 µs after the second poll, 500 µs later.
#[test]
fn a_refused_datagram_puts_back_exactly_its_frames() {
    let pool = wide_pool();
    let releases = wide_releases();
    let mut owner = Owner::wide(vec![]);
    let (mut client, limits, mut owner_end, net, turn) =
        throttled(&pool, &releases, Box::default(), &mut owner, 24);
    let now = turn * 100;
    gets(&mut client, 17, now);
    limits.allowance.set(Some(1));
    let report = client.poll(now);
    assert_eq!((report.sent, report.blocked), (1, true));
    let taken = in_flight(&net);
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].0, 1536);
    let first: Vec<u64> = taken[0].1.iter().map(|(_, request, _)| *request).collect();
    assert_eq!(first, (0..8).map(|n| n << 48 | n).collect::<Vec<u64>>());
    assert_eq!(
        counters(&client),
        ([0, 0, 0, 0, 0, 0, 0, 1], 0, buckets(&[(0, 8)])),
        "the refused datagrams move no counter"
    );
    limits.allowance.set(None);
    let report = client.poll(now + 500);
    assert_eq!((report.sent, report.blocked), (2, false));
    let rest = in_flight(&net).split_off(1);
    let lengths: Vec<usize> = rest.iter().map(|(len, _)| *len).collect();
    assert_eq!(lengths, [1536, 192]);
    let frames: Vec<_> = rest.into_iter().flat_map(|(_, frames)| frames).collect();
    let expected: Vec<_> = (8..17u64)
        .map(|n| (Kind::Get, n << 48 | n, 10 + n))
        .collect();
    assert_eq!(
        frames, expected,
        "the refused frames, each staged again under a fresh sequence"
    );
    assert_eq!(
        counters(&client),
        ([1, 0, 0, 0, 0, 0, 0, 2], 4_500, buckets(&[(0, 8), (8, 9)])),
        "each put-back GET waited 500 µs for its first taken send"
    );
    assert_eq!(client.fetch_report().get_retries, 0);
    owner_turn(&mut owner, &mut owner_end, &net, turn + 1);
    assert_eq!(owner.serve.report().requests, 17);
    assert_eq!(
        owner.serve.report().duplicates,
        0,
        "no taken GET reached the owner again under a fresh sequence"
    );
    assert_eq!(owner.sessions.report().duplicate, 0);
}

/// A transport that takes only the first datagram of a poll leaves exactly the frames of the rest due: for hand-out
/// GET, ACK, GET, GET the next poll sends only the ACK, and for ACK, GET, ACK, GET it sends the two GETs, packed, and
/// the second ACK. The ACK held behind the GET block never leaves while a GET of its poll is refused.
#[test]
fn a_prefix_taken_leaves_exactly_the_rest_due() {
    for (kept, cancelled, new, expected) in [
        (
            &[1][..],
            &[7, 6, 5, 4, 3, 2, 0][..],
            3,
            vec![(192, vec![(Kind::Ack, 1 << 48 | 1, 20)])],
        ),
        (
            &[0, 2],
            &[7, 6, 5, 4, 3, 1],
            2,
            vec![
                (
                    384,
                    vec![(Kind::Get, 1 << 48 | 8, 19), (Kind::Get, 3 << 48 | 9, 20)],
                ),
                (192, vec![(Kind::Ack, 2 << 48 | 2, 21)]),
            ],
        ),
    ] {
        let (pool, board) = (receive_pool(), releases());
        let limits = Rc::new(Limits::default());
        limits.per_call.set(usize::MAX);
        let end = |end| Throttled {
            end,
            limits: limits.clone(),
        };
        let mut answered = eight_answered(&pool, &board, end, kept);
        cancel_and_retire(&mut answered, cancelled);
        for _ in 0..new {
            answered.get();
        }
        for start in &answered.starts {
            answered.net.borrow_mut().inject(0, start);
        }
        limits.allowance.set(Some(1));
        let report = answered.client.poll(answered.now + 100);
        assert_eq!((report.sent, report.blocked), (1, true), "{kept:?}");
        take_toward(&answered.net, 1);
        limits.allowance.set(None);
        let report = answered.client.poll(answered.now + 200);
        assert_eq!(report.sent as usize, expected.len(), "{kept:?}");
        assert_eq!(sent(&answered.net), expected, "{kept:?}");
        assert_eq!(
            answered.client.poll(answered.now + 300).sent,
            0,
            "{kept:?}: nothing else due"
        );
    }
}

/// With `n` sequences left, a poll that hands out GET, ACK, GET, GET stages its frames in wire order, GET, GET, GET
/// and then the held ACK, puts the first `n` on the link, counts the `4 - n` it could not stage as dropped and ends
/// the session's requests after its sends. At `n` of 1 and 2 the sequence runs out at a GET, and at `n` of 3 at the
/// held ACK.
#[test]
fn a_spent_sequence_sends_the_staged_frames_and_drops_the_rest() {
    let wire = [
        (Kind::Get, 8),
        (Kind::Get, 2 << 48 | 9),
        (Kind::Get, 3 << 48 | 10),
        (Kind::Ack, 1 << 48 | 1),
    ];
    for n in 0..=3u64 {
        let (pool, board) = (receive_pool(), releases());
        let mut answered = eight_answered(&pool, &board, |end| end, &[1]);
        cancel_and_retire(&mut answered, &[7, 6, 5, 4, 3, 2, 0]);
        let new: Vec<_> = (0..3).map(|_| answered.get()).collect();
        answered.net.borrow_mut().inject(0, &answered.starts[0]);
        answered
            .client
            .sessions_mut()
            .set_send(PeerId(0), u64::MAX - n);
        let report = answered.client.poll(answered.now + 100);
        assert_eq!(report.dropped as u64, 4 - n, "n = {n}");
        let sent = sent(&answered.net);
        let lengths: Vec<usize> = sent.iter().map(|(len, _)| *len).collect();
        let packed = [&[][..], &[192], &[384], &[576]][n as usize];
        assert_eq!(lengths, packed, "n = {n}");
        let frames: Vec<_> = sent.into_iter().flat_map(|(_, frames)| frames).collect();
        let expected: Vec<_> = wire[..n as usize]
            .iter()
            .zip(u64::MAX - n..)
            .map(|(&(kind, request), sequence)| (kind, request, sequence))
            .collect();
        assert_eq!(
            frames, expected,
            "n = {n}: the first {n} frames in wire order"
        );
        assert_eq!(
            answered.client.sessions_mut().active(PeerId(0)),
            None,
            "n = {n}"
        );
        for id in new.iter().chain([&answered.ids[1]]) {
            assert_eq!(
                answered.client.outcome(*id),
                Some(Outcome::Failed(Status::SessionMismatch)),
                "n = {n}: the spent sequence ends the session's requests"
            );
        }
    }
}

/// A poll that hands out GET, ACK, GET holds the ACK behind the GET block and allocates nothing: the hold scratch is
/// charged at initialization. The datagrams it sent show that it held a frame: the two GETs packed, then the ACK.
#[test]
fn a_poll_that_holds_a_frame_allocates_nothing() {
    let (pool, board) = (receive_pool(), releases());
    let mut answered = eight_answered(&pool, &board, |end| end, &[1]);
    cancel_and_retire(&mut answered, &[7, 6, 5, 4, 3, 2, 0]);
    for _ in 0..2 {
        answered.get();
    }
    answered.net.borrow_mut().inject(0, &answered.starts[0]);
    let before = crate::instrument::allocations();
    let report = answered.client.poll(answered.now + 100);
    let allocations = crate::instrument::allocations() - before;
    assert_eq!(report.sent, 2);
    assert_eq!(
        sent(&answered.net),
        [
            (384, vec![(Kind::Get, 8, 16), (Kind::Get, 2 << 48 | 9, 17)]),
            (192, vec![(Kind::Ack, 1 << 48 | 1, 18)]),
        ],
        "the ACK handed out between the GETs was held"
    );
    assert_eq!(allocations, 0);
    let probe = crate::instrument::allocations();
    drop(std::hint::black_box(vec![0u8; 1]));
    assert!(
        crate::instrument::allocations() > probe,
        "the counter sees an allocation on this thread"
    );
}

/// The fetch report's GET counters.
fn counters<D>(client: &Client<'_, D>) -> ([u64; MAX_PACKED_GETS], u64, [u64; FIRST_SEND_BUCKETS]) {
    let report = client.fetch_report();
    (
        report.gets_per_datagram,
        report.first_send_us,
        report.first_sends,
    )
}

/// `counts` as a full `first_sends` array.
fn buckets(counts: &[(usize, u64)]) -> [u64; FIRST_SEND_BUCKETS] {
    let mut buckets = [0; FIRST_SEND_BUCKETS];
    for &(at, count) in counts {
        buckets[at] = count;
    }
    buckets
}

/// Turns the link, the client when `polls`, and the test owner every 100 µs from `from_us` to `to_us`, both
/// included, taking the fragments of `ids`.
fn run_between<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    owner: &mut Owner,
    owner_end: &mut LinkEnd<'_>,
    net: &Rc<RefCell<Net<'_>>>,
    (from_us, to_us): (u64, u64),
    polls: bool,
    ids: &[RequestId],
) {
    for now in (from_us..=to_us).step_by(100) {
        net.borrow_mut().advance(now / 100);
        if polls {
            let _ = client.poll(now);
        }
        owner.turn(owner_end, now);
        for id in ids {
            while client.take(*id).is_some() {}
        }
    }
}

/// Drives from `from_us` to `to_us` until every request of `ids` completed, then retires them.
fn settle<'m, D: Datagrams<'m>>(
    client: &mut Client<'m, D>,
    owner: &mut Owner,
    owner_end: &mut LinkEnd<'_>,
    net: &Rc<RefCell<Net<'_>>>,
    window: (u64, u64),
    ids: &[RequestId],
) {
    run_between(client, owner, owner_end, net, window, true, ids);
    for id in ids {
        assert_eq!(client.outcome(*id), Some(Outcome::Complete));
        assert!(client.retire(*id));
    }
}

/// A scripted history with each counter's expected value in microseconds. A GET admitted and taken in the poll at
/// 1,000, which its caller intended for 900, adds 0 and one entry of `first_sends[0]`: the time runs from admission. GETs admitted at 2,000, 2,100 and 2,200 and taken together at
/// 2,200 add 300 and one entry of `gets_per_datagram[2]`. Three GETs at 3,000 whose datagram the transport refuses
/// move nothing until it takes them at 3,500, which adds 1,500. Three GETs at 4,000 whose call fails move nothing until
/// their retries leave packed at 7,000, which adds 9,000. A GET at 8,000 that the link loses moves
/// `gets_per_datagram[0]` when it is taken and again when its retry is taken at 11,000, and adds one entry to
/// `first_sends` only. A GET that the transport refuses and the application then cancels moves nothing.
#[test]
fn gets_per_datagram_and_first_sends_count_taken_datagrams() {
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 26, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], object(1_000, 26))]);
    let (transport, limits) = Throttled::new(client_end);
    let mut client = client(&pool, &releases, transport);
    let turn = opened(&mut client, &mut owner, &mut owner_end, &net);
    assert!(
        turn * 100 < 1_000,
        "premise: the session opened before 1,000 µs"
    );
    fn get<'m>(client: &mut Client<'m, Throttled<'m>>, now: u64) -> RequestId {
        client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap()
    }
    let mut gets_per_datagram = [0; MAX_PACKED_GETS];

    let one = client
        .get_intended([1; 32], 0, 1 << 20, 900, 1_000, 1_000_000)
        .unwrap();
    assert_eq!(client.poll(1_000).sent, 1);
    gets_per_datagram[0] = 1;
    assert_eq!(
        counters(&client),
        (gets_per_datagram, 0, buckets(&[(0, 1)]))
    );
    settle(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (1_100, 1_900),
        &[one],
    );

    let three = [2_000, 2_100, 2_200].map(|now| get(&mut client, now));
    assert_eq!(client.poll(2_200).sent, 1);
    gets_per_datagram[2] = 1;
    let mut first_sends = buckets(&[(0, 2), (6, 1), (7, 1)]);
    assert_eq!(counters(&client), (gets_per_datagram, 300, first_sends));
    settle(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (2_300, 2_900),
        &three,
    );

    let three = [0; 3].map(|_| get(&mut client, 3_000));
    limits.allowance.set(Some(0));
    assert!(client.poll(3_000).blocked);
    assert_eq!(
        counters(&client),
        (gets_per_datagram, 300, first_sends),
        "a refused datagram moves nothing"
    );
    limits.allowance.set(None);
    run_between(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (3_100, 3_400),
        false,
        &[],
    );
    assert_eq!(client.poll(3_500).sent, 1);
    gets_per_datagram[2] = 2;
    first_sends[8] = 3;
    assert_eq!(counters(&client), (gets_per_datagram, 1_800, first_sends));
    settle(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (3_600, 3_900),
        &three,
    );

    let three = [0; 3].map(|_| get(&mut client, 4_000));
    limits.fail_next.set(true);
    assert!(client.poll(4_000).failed.is_some());
    assert_eq!(
        counters(&client),
        (gets_per_datagram, 1_800, first_sends),
        "the leading datagram of a failed call moves nothing"
    );
    run_between(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (4_100, 6_900),
        true,
        &three,
    );
    assert_eq!(counters(&client), (gets_per_datagram, 1_800, first_sends));
    assert_eq!(client.poll(7_000).sent, 1, "the three retries leave packed");
    gets_per_datagram[2] = 3;
    first_sends[11] = 3;
    assert_eq!(counters(&client), (gets_per_datagram, 10_800, first_sends));
    assert_eq!(client.fetch_report().get_retries, 3);
    settle(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (7_100, 7_900),
        &three,
    );

    let ended = get(&mut client, 7_950);
    limits.allowance.set(Some(0));
    assert!(client.poll(7_950).blocked);
    client.cancel(ended);
    limits.allowance.set(None);
    assert_eq!(client.poll(7_950).sent, 1, "its CANCEL");
    assert!(client.retire(ended));
    assert_eq!(
        counters(&client),
        (gets_per_datagram, 10_800, first_sends),
        "a GET that ends before a taken send records nothing"
    );
    run_between(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (7_950, 7_950),
        false,
        &[],
    );

    let lost = Rule::new(
        Selector::All(vec![Selector::Kind(Kind::Get), Selector::Toward(1)]),
        Effect::Drop,
    )
    .window(0, 1);
    net.borrow_mut()
        .set_rules(Chain::new(vec![lost], &[], &MANIFEST).unwrap());
    let alone = get(&mut client, 8_000);
    assert_eq!(client.poll(8_000).sent, 1);
    gets_per_datagram[0] = 2;
    first_sends[0] = 3;
    assert_eq!(counters(&client), (gets_per_datagram, 10_800, first_sends));
    run_between(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (8_100, 10_900),
        true,
        &[alone],
    );
    assert_eq!(
        client.outcome(alone),
        None,
        "premise: the link lost the GET"
    );
    assert_eq!(client.poll(11_000).sent, 1);
    gets_per_datagram[0] = 3;
    assert_eq!(
        counters(&client),
        (gets_per_datagram, 10_800, first_sends),
        "a resent GET adds no first send"
    );
    assert_eq!(client.fetch_report().get_retries, 4);
    settle(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (11_100, 11_900),
        &[alone],
    );
}

/// The test owner walks every frame of a packed datagram: a 384-byte datagram of two GETs from the client admits
/// both, as two requests and two session admissions, and each completes with exact bytes.
#[test]
fn the_test_owner_admits_both_gets_of_a_packed_datagram() {
    let source = object(1_000, 27);
    let pool = receive_pool();
    let releases = releases();
    let (client_end, mut owner_end, net) = network(64, 8384, 27, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![([1; 32], source.clone())]);
    let mut client = client(&pool, &releases, client_end);
    let turn = opened(&mut client, &mut owner, &mut owner_end, &net);
    let ids: Vec<_> = (0..2)
        .map(|_| {
            client
                .get([1; 32], 0, 1 << 20, turn * 100, 1_000_000)
                .unwrap()
        })
        .collect();
    assert_eq!(client.poll(turn * 100).sent, 1);
    let lengths: Vec<usize> = in_flight(&net).iter().map(|(len, _)| *len).collect();
    assert_eq!(lengths, [384]);
    owner_turn(&mut owner, &mut owner_end, &net, turn + 1);
    assert_eq!(owner.serve.report().requests, 2);
    finish_all(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        turn + 2,
        &ids,
        &source,
    );
    assert_eq!(owner.serve.report().requests, 2);
}

/// Four source slots over `shared`.
fn four_sources(
    shared: &crate::storage::BufferArena<crate::storage::test_platform::TestPlatform>,
) -> Box<[super::super::upload::SourceSlot<'_>]> {
    super::super::memory::sources(shared, 4, &mut EngineBudget::new(1 << 20)).unwrap()
}

/// Behind two packed datagrams of eight GETs a PUT BEGIN counts as handed only when a transport call was given it.
/// A call that carries the two packed datagrams and the BEGIN and takes nothing hands the BEGIN, so the upload ends
/// `Unknown` when its session ends. When six held CANCELs follow the GET block, the refused call carries eight
/// datagrams and stops before the BEGIN, which no call was given, so the upload ends `NotStarted`. The poll stages
/// 22 fetch frames and the BEGIN within its batch of 24.
#[test]
fn a_put_begin_behind_packed_datagrams_is_handed_only_when_a_call_carried_it() {
    for cancelled in [0, 6] {
        let shared = crate::storage::owner_fixture::arena(4);
        let (pool, releases) = (wide_pool(), wide_releases());
        let mut owner = Owner::wide(vec![]);
        let (mut client, limits, _owner_end, net, turn) =
            throttled(&pool, &releases, four_sources(&shared), &mut owner, 28);
        let now = turn * 100;
        let early: Vec<_> = (0..cancelled)
            .map(|_| client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap())
            .collect();
        if cancelled > 0 {
            assert_eq!(client.poll(now).sent, 1);
            take_toward(&net, 1);
            for id in &early {
                client.cancel(*id);
            }
        }
        for _ in 0..16 {
            client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
        }
        let put = client
            .put([7; 32], CacheVersion(0), now, 1_000_000)
            .unwrap();
        limits.allowance.set(Some(0));
        limits.offered.borrow_mut().clear();
        assert!(client.poll(now).blocked);
        assert!(take_toward(&net, 1).is_empty());
        let mut carried = vec![1536, 1536];
        carried.extend(if cancelled == 0 {
            vec![HEADER_LEN]
        } else {
            vec![HEADER_LEN; cancelled]
        });
        assert_eq!(
            *limits.offered.borrow(),
            [carried],
            "premise: the one call carried the GET block and then the BEGIN, or the six held CANCELs"
        );
        client.sessions_mut().set_send(PeerId(0), u64::MAX);
        limits.allowance.set(None);
        client.poll(now + 100);
        assert_eq!(
            client.sessions_mut().active(PeerId(0)),
            None,
            "premise: the session ended"
        );
        let expected = if cancelled == 0 {
            UploadOutcome::Unknown
        } else {
            UploadOutcome::NotStarted
        };
        assert_eq!(
            client.put_outcome(put),
            Some(expected),
            "{cancelled} CANCELs"
        );
    }
}

/// A PUT BEGIN that is the only frame of its poll leaves in a call of one datagram, and a call that fails still
/// hands it: the failed call carried the BEGIN, so the upload ends `Unknown` when its session ends, where an upload
/// no call carried ends `NotStarted`. No later call carries a frame of the upload: the BEGIN's retry is not due when
/// the session ends, and the GET whose staging ends the session goes unsent.
#[test]
fn a_failed_call_of_a_lone_put_begin_hands_the_upload() {
    let shared = crate::storage::owner_fixture::arena(4);
    let (pool, releases) = (wide_pool(), wide_releases());
    let mut owner = Owner::wide(vec![]);
    let (mut client, limits, _owner_end, net, turn) =
        throttled(&pool, &releases, four_sources(&shared), &mut owner, 33);
    let now = turn * 100;
    let put = client
        .put([7; 32], CacheVersion(0), now, 1_000_000)
        .unwrap();
    limits.offered.borrow_mut().clear();
    limits.fail_next.set(true);
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.blocked, report.failed),
        (0, false, Some(Some(libc::EIO)))
    );
    assert_eq!(
        *limits.offered.borrow(),
        [vec![HEADER_LEN]],
        "premise: the failed call carried the BEGIN alone"
    );
    assert!(take_toward(&net, 1).is_empty());
    client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    client.sessions_mut().set_send(PeerId(0), u64::MAX);
    assert!(now + 100 < now + WIDE.upload.retry_us);
    client.poll(now + 100);
    assert_eq!(
        client.sessions_mut().active(PeerId(0)),
        None,
        "premise: the session ended"
    );
    assert_eq!(
        limits.offered.borrow().len(),
        1,
        "premise: no later call carried a frame"
    );
    assert_eq!(client.put_outcome(put), Some(UploadOutcome::Unknown));
}

/// Offering a PUT BEGIN alone to the transport, after a call took the eight datagrams ahead of it, counts as handoff
/// even when the call fails. If the session ends before retry, the client reports `UploadOutcome::Unknown`.
#[test]
fn a_failed_lone_call_of_a_put_begin_behind_taken_datagrams_hands_the_upload() {
    let shared = crate::storage::owner_fixture::arena(4);
    let (pool, releases) = (wide_pool(), wide_releases());
    let mut owner = Owner::wide(vec![]);
    let (mut client, limits, _owner_end, net, turn) =
        throttled(&pool, &releases, four_sources(&shared), &mut owner, 36);
    let now = turn * 100;
    let early: Vec<_> = (0..6)
        .map(|_| client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap())
        .collect();
    assert_eq!(client.poll(now).sent, 1);
    take_toward(&net, 1);
    for id in &early {
        client.cancel(*id);
    }
    for _ in 0..16 {
        client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    }
    let put = client
        .put([7; 32], CacheVersion(0), now, 1_000_000)
        .unwrap();
    limits.offered.borrow_mut().clear();
    limits.fail_after.set(Some(1));
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.blocked, report.failed),
        (8, false, Some(Some(libc::EIO)))
    );
    let mut ahead = vec![1536, 1536];
    ahead.extend([HEADER_LEN; 6]);
    assert_eq!(
        *limits.offered.borrow(),
        [ahead, vec![HEADER_LEN]],
        "premise: the first call stopped before the BEGIN and the failed call carried it alone"
    );
    assert_eq!(
        take_toward(&net, 1).len(),
        8,
        "premise: the transport took the eight datagrams ahead of the BEGIN"
    );
    client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
    client.sessions_mut().set_send(PeerId(0), u64::MAX);
    assert!(now + 100 < now + WIDE.upload.retry_us);
    client.poll(now + 100);
    assert_eq!(
        client.sessions_mut().active(PeerId(0)),
        None,
        "premise: the session ended"
    );
    assert_eq!(
        limits.offered.borrow().len(),
        2,
        "premise: no later call carried a frame"
    );
    assert_eq!(client.put_outcome(put), Some(UploadOutcome::Unknown));
}

/// A PUT DATA fragment behind two packed datagrams of eight GETs leaves in a datagram of its own with its payload,
/// the supplied bytes under the upload's wire request and fragment index, and once the transport took all three datagrams the next poll sends nothing: the taken fragment is not sent again.
/// With a transport that takes every datagram one call carries the three. With one that takes two datagrams a call,
/// the second call carries the fragment's datagram alone, after the two packed datagrams the first call took, and
/// that datagram carries the same payload.
#[test]
fn a_taken_put_data_fragment_behind_packed_datagrams_is_not_sent_again() {
    let whole = vec![1536, 1536, HEADER_LEN + 8192];
    let cases = [
        (usize::MAX, vec![whole.clone()]),
        (2, vec![whole, vec![HEADER_LEN + 8192]]),
    ];
    for (per_call, offered) in cases {
        let shared = crate::storage::owner_fixture::arena(4);
        let (pool, releases) = (wide_pool(), wide_releases());
        let mut owner = Owner::wide(vec![]);
        let (mut client, limits, mut owner_end, net, mut turn) =
            throttled(&pool, &releases, four_sources(&shared), &mut owner, 29);
        let key = [7; 32];
        let put = client
            .put(key, CacheVersion(0), turn * 100, 1 << 40)
            .unwrap();
        let wire = client.put_wire(put).unwrap();
        quiet(&mut client, &net, turn);
        let (authority, _) = put_frame(Kind::PutAuthority, &header(Kind::PutAuthority, wire, key));
        deliver(
            &mut client,
            &mut owner,
            &mut owner_end,
            &net,
            authority,
            turn,
        );
        client.prepare(put, 0, PUT_TOTAL, 60_000).unwrap();
        turn += 1;
        quiet(&mut client, &net, turn);
        let prepared = Manifest {
            allocation: PUT_SERIAL,
            metadata_len: 0,
            body_len: PUT_TOTAL,
        };
        let ready = Header {
            status: 0,
            grant: 2,
            ..super::super::serve::manifest_header(Kind::PutReady, wire, key, &prepared)
        };
        turn += 1;
        assert_eq!(
            deliver(&mut client, &mut owner, &mut owner_end, &net, ready, turn).dropped,
            0,
            "premise: the READY is taken"
        );
        take_toward(&net, 1);
        let fragment = object(8192, 29);
        assert!(client.supply(put, 0, &fragment).is_ok());
        let now = turn * 100;
        for _ in 0..16 {
            client.get([1; 32], 0, 1 << 20, now, 1 << 40).unwrap();
        }
        limits.per_call.set(per_call);
        limits.offered.borrow_mut().clear();
        let report = client.poll(now);
        assert_eq!((report.sent, report.blocked), (3, false));
        assert_eq!(*limits.offered.borrow(), offered, "the calls of the poll");
        let taken = take_toward(&net, 1);
        let lengths: Vec<usize> = taken.iter().map(Vec::len).collect();
        assert_eq!(lengths, [1536, 1536, HEADER_LEN + 8192]);
        let data = parse(Crc32c::detect(), &taken[2], false).unwrap();
        let named = data.header();
        assert_eq!(
            (named.kind, named.request, named.index),
            (Kind::PutData, wire, 0),
            "the third datagram is the upload's first fragment"
        );
        assert_eq!(data.raw_body(), &fragment[..], "with the supplied bytes");
        assert_eq!(client.poll(now + 100).sent, 0, "nothing is due again");
        assert!(take_toward(&net, 1).is_empty());
    }
}

/// A call that takes a prefix of its datagrams is followed, in the same poll, by a call that starts at the first
/// datagram it left: with nine GETs due as datagrams of 8 and 1 and a transport that takes one datagram per call,
/// the first call is given both and the second the lone one, and both leave in that poll.
#[test]
fn a_call_that_takes_a_prefix_is_followed_by_a_call_for_the_rest() {
    let (pool, releases) = (wide_pool(), wide_releases());
    let mut owner = Owner::wide(vec![]);
    let (mut client, limits, _owner_end, net, turn) =
        throttled(&pool, &releases, Box::default(), &mut owner, 30);
    let now = turn * 100;
    gets(&mut client, 9, now);
    limits.offered.borrow_mut().clear();
    limits.per_call.set(1);
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.blocked, report.failed),
        (2, false, None)
    );
    assert_eq!(*limits.offered.borrow(), [vec![1536, 192], vec![192]]);
    let sent = sent(&net);
    let lengths: Vec<usize> = sent.iter().map(|(len, _)| *len).collect();
    assert_eq!(lengths, [1536, 192]);
    let frames: Vec<_> = sent.into_iter().flat_map(|(_, frames)| frames).collect();
    let expected: Vec<_> = (0..9u64).map(|n| (Kind::Get, n << 48 | n, 1 + n)).collect();
    assert_eq!(frames, expected);
    assert_eq!(
        counters(&client),
        ([1, 0, 0, 0, 0, 0, 0, 1], 0, buckets(&[(0, 9)]))
    );
}

/// A failed call loses its leading datagram alone, and the next call of the same poll starts at the datagram after
/// it: with nine GETs due as datagrams of 8 and 1, a first call that fails loses the eight, and the second call
/// sends the ninth GET. The eight lost GETs move no counter and stay sent, and once the ninth request is cancelled
/// the eight alone retry, packed, one retry interval later.
#[test]
fn a_failed_call_is_followed_by_a_call_for_the_datagrams_after_its_first() {
    let (pool, releases) = (wide_pool(), wide_releases());
    let mut owner = Owner::wide(vec![]);
    let (mut client, limits, _owner_end, net, turn) =
        throttled(&pool, &releases, Box::default(), &mut owner, 31);
    let now = turn * 100;
    let ids = gets(&mut client, 9, now);
    limits.offered.borrow_mut().clear();
    limits.fail_next.set(true);
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.blocked, report.failed),
        (1, false, Some(Some(libc::EIO)))
    );
    assert_eq!(*limits.offered.borrow(), [vec![1536, 192], vec![192]]);
    assert_eq!(
        sent(&net),
        [(192, vec![(Kind::Get, 8 << 48 | 8, 9)])],
        "the datagram after the lost one left in the same poll"
    );
    assert_eq!(
        counters(&client),
        ([1, 0, 0, 0, 0, 0, 0, 0], 0, buckets(&[(0, 1)])),
        "the lost datagram of eight moves no counter"
    );
    client.cancel(ids[8]);
    assert_eq!(client.poll(now).sent, 1, "the ninth request's CANCEL");
    assert_eq!(
        sent(&net),
        [(192, vec![(Kind::Cancel, 8 << 48 | 8, 10)])],
        "none of the eight lost GETs is due"
    );
    let report = client.poll(now + WIDE.fetch.retry_us);
    assert_eq!((report.sent, report.blocked), (1, false));
    let expected: Vec<_> = (0..8u64)
        .map(|n| (Kind::Get, n << 48 | n, 11 + n))
        .collect();
    assert_eq!(sent(&net), [(1536, expected)]);
    assert_eq!(client.fetch_report().get_retries, 8);
    assert_eq!(
        counters(&client),
        (
            [1, 0, 0, 0, 0, 0, 0, 1],
            24_000,
            buckets(&[(0, 1), (11, 8)])
        ),
        "each lost GET takes its first send when its retry is taken"
    );
}

/// A poll whose hand-out is GET, 22 CANCELs of other requests, GET holds the 22 CANCELs and sends them after the two
/// GETs, packed, in hand-out order, each under the sequence it took when staged, and allocates nothing: the 24 frames
/// fill the batch, and the hold scratch holds every CANCEL. The hand-out starts at the cursor, slot 23, where the
/// first new GET sits, wraps to the cancelled requests at slots 0 to 21, and ends at the second new GET at slot 22.
/// With the second new GET cancelled as well, the hand-out is one GET and 23 CANCELs, the most frames a batch of 24
/// holds behind a GET, and the poll sends the lone GET and then the 23 CANCELs in order, again allocating nothing.
#[test]
fn a_poll_holds_every_frame_handed_out_between_its_gets_in_order() {
    for lone in [false, true] {
        let (pool, releases) = (wide_pool(), wide_releases());
        let (client_end, mut owner_end, net) = network(64, 8384, 32, [Faults::default(); 2]);
        let mut owner = Owner::wide(vec![]);
        let mut client = wide_client(&pool, &releases, client_end, Box::default());
        let now = opened(&mut client, &mut owner, &mut owner_end, &net) * 100;
        let ids = gets(&mut client, 23, now);
        assert_eq!(client.poll(now).sent, 3);
        client.cancel(ids[22]);
        assert_eq!(client.poll(now).sent, 1, "the CANCEL of slot 22");
        assert!(client.retire(ids[22]));
        take_toward(&net, 1);
        let y = client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
        let x = client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap();
        assert_eq!(
            (x.slot(), y.slot()),
            (23, 22),
            "premise: from the cursor at slot 23 the hand-out is x, slots 0 to 21, y"
        );
        let mut block = vec![(Kind::Get, client.get_wire(x).unwrap(), 25)];
        let mut cancelled = ids[..22].to_vec();
        if lone {
            cancelled.push(y);
        } else {
            block.push((Kind::Get, client.get_wire(y).unwrap(), 26));
        }
        let held = 25 + block.len() as u64;
        let mut expected = vec![(block.len() * HEADER_LEN, block)];
        for (id, sequence) in cancelled.iter().zip(held..) {
            expected.push((
                192,
                vec![(Kind::Cancel, client.get_wire(*id).unwrap(), sequence)],
            ));
            client.cancel(*id);
        }
        let before = crate::instrument::allocations();
        let report = client.poll(now);
        let allocations = crate::instrument::allocations() - before;
        assert_eq!(report.sent as usize, expected.len(), "lone {lone}");
        assert_eq!(expected.len(), if lone { 24 } else { 23 });
        assert_eq!(sent(&net), expected, "lone {lone}");
        assert_eq!(allocations, 0, "lone {lone}");
    }
}

/// The first-send histogram at its edges, each GET refused once and taken by a later poll so its wait is exact. A
/// wait of `2^23 - 1` µs counts in bucket 22, and waits of `2^23` and `2^24` µs both count in bucket 23, the last.
/// A poll at a time below the GET's admission records a wait of 0 in bucket 0. Two GETs that each waited `2^63` µs
/// leave in one packed datagram, count twice in the last bucket, and their sum of `2^64` holds `first_send_us` at
/// `u64::MAX`. The GET retry interval and each GET's wait are `u64::MAX`, so no retry and no deadline falls in the
/// history.
#[test]
fn first_sends_clamp_at_the_last_bucket_and_the_sum_saturates() {
    let (pool, releases) = (receive_pool(), releases());
    let (client_end, mut owner_end, net) = network(64, 8384, 33, [Faults::default(); 2]);
    let mut owner = Owner::new(vec![]);
    let (transport, limits) = Throttled::new(client_end);
    let config = ClientConfig {
        fetch: FetchConfig {
            retry_us: u64::MAX,
            ..CONFIG.fetch
        },
        ..CONFIG
    };
    let mut client = client_with(&pool, &releases, transport, config);
    let mut now = opened(&mut client, &mut owner, &mut owner_end, &net) * 100;
    let mut sum = 0u64;
    let mut first_sends = [0; FIRST_SEND_BUCKETS];
    // Ends `id` and frees its boxes for the next GET: its CANCEL leaves alone and moves no GET counter.
    fn end<'m>(client: &mut Client<'m, Throttled<'m>>, id: RequestId, now: u64) {
        client.cancel(id);
        assert_eq!(client.poll(now).sent, 1, "the CANCEL");
        assert!(client.retire(id));
    }
    for (wait, bucket) in [((1 << 23) - 1, 22), (1 << 23, 23), (1 << 24, 23)] {
        let id = client.get([1; 32], 0, 1 << 20, now, u64::MAX).unwrap();
        limits.allowance.set(Some(0));
        assert!(client.poll(now).blocked);
        limits.allowance.set(None);
        now += wait;
        assert_eq!(client.poll(now).sent, 1, "wait {wait}");
        sum += wait;
        first_sends[bucket] += 1;
        let report = client.fetch_report();
        assert_eq!(
            (report.first_send_us, report.first_sends),
            (sum, first_sends),
            "wait {wait}"
        );
        end(&mut client, id, now);
    }

    let id = client.get([1; 32], 0, 1 << 20, now, u64::MAX).unwrap();
    assert_eq!(
        client.poll(now - 1_000).sent,
        1,
        "a poll below the admission"
    );
    first_sends[0] += 1;
    let report = client.fetch_report();
    assert_eq!(
        (report.first_send_us, report.first_sends),
        (sum, first_sends)
    );
    end(&mut client, id, now);

    for _ in 0..2 {
        client.get([1; 32], 0, 1 << 20, now, u64::MAX).unwrap();
    }
    limits.allowance.set(Some(0));
    assert!(client.poll(now).blocked);
    limits.allowance.set(None);
    assert_eq!(client.poll(now + (1 << 63)).sent, 1, "one packed datagram");
    first_sends[23] += 2;
    let report = client.fetch_report();
    assert_eq!(
        (report.first_send_us, report.first_sends),
        (u64::MAX, first_sends)
    );
    assert_eq!(report.gets_per_datagram, [4, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(report.get_retries, 0);
}

/// A call that fails after an earlier call of the same poll took a datagram loses the datagram it leads and no other.
/// With 17 GETs due as datagrams of 8, 8 and 1 and a transport that takes one datagram per call, the first call takes
/// the first eight, the second call fails and loses the middle eight, and the third call sends the last GET. The lost
/// eight move no counter and stay sent until their retries, which give them their first sends.
#[test]
fn a_call_that_fails_after_a_taken_one_loses_the_datagram_it_leads() {
    let (pool, releases) = (wide_pool(), wide_releases());
    let mut owner = Owner::wide(vec![]);
    let (mut client, limits, _owner_end, net, turn) =
        throttled(&pool, &releases, Box::default(), &mut owner, 34);
    let now = turn * 100;
    gets(&mut client, 17, now);
    limits.offered.borrow_mut().clear();
    limits.per_call.set(1);
    limits.fail_after.set(Some(1));
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.blocked, report.failed),
        (2, false, Some(Some(libc::EIO)))
    );
    assert_eq!(
        *limits.offered.borrow(),
        [vec![1536, 1536, 192], vec![1536, 192], vec![192]]
    );
    let first: Vec<_> = (0..8u64).map(|n| (Kind::Get, n << 48 | n, 1 + n)).collect();
    assert_eq!(
        sent(&net),
        [(1536, first), (192, vec![(Kind::Get, 16 << 48 | 16, 17)])]
    );
    assert_eq!(
        counters(&client),
        ([1, 0, 0, 0, 0, 0, 0, 1], 0, buckets(&[(0, 9)])),
        "the lost datagram of eight moves no counter"
    );
    limits.per_call.set(usize::MAX);
    assert_eq!(client.poll(now).sent, 0, "none of the lost eight is due");
    let report = client.poll(now + WIDE.fetch.retry_us);
    assert_eq!((report.sent, report.blocked), (3, false));
    assert_eq!(client.fetch_report().get_retries, 17);
    assert_eq!(
        counters(&client),
        (
            [2, 0, 0, 0, 0, 0, 0, 3],
            24_000,
            buckets(&[(0, 9), (11, 8)])
        ),
        "the lost eight take their first sends when their retries are taken"
    );
}

/// A poll whose frames are one datagram of fetch frames makes one transport call for that datagram, and the call's
/// result moves what a call for the same datagram moves in a longer poll. A lone GET the transport refuses stays
/// due: the poll reports `(sent, blocked)` of (0, true), no counter moves, and the next poll offers the datagram
/// again; once taken 400 µs after admission it counts one datagram of one GET and one first send in the bucket
/// that starts at 256 µs. A lone ACK the transport refuses stays due as well and moves no GET counter when it is
/// taken. A lone GET whose call fails is lost as sent: the poll reports the failure, the next poll makes no call and
/// no counter moves. A GET with a PUT BEGIN staged behind it is two datagrams, which leave in one call.
#[test]
fn a_poll_of_one_fetch_datagram_makes_one_call_and_keeps_its_result() {
    let shared = crate::storage::owner_fixture::arena(4);
    let (pool, releases) = (wide_pool(), wide_releases());
    let mut owner = Owner::wide(vec![([1; 32], object(1_000, 41))]);
    let (mut client, limits, mut owner_end, net, turn) =
        throttled(&pool, &releases, four_sources(&shared), &mut owner, 41);
    let now = turn * 100;
    fn get<'m>(client: &mut Client<'m, Throttled<'m>>, now: u64) -> RequestId {
        client.get([1; 32], 0, 1 << 20, now, 1_000_000).unwrap()
    }
    let unmoved = ([0; MAX_PACKED_GETS], 0, [0; FIRST_SEND_BUCKETS]);

    let refused = get(&mut client, now);
    limits.allowance.set(Some(0));
    limits.offered.borrow_mut().clear();
    let report = client.poll(now);
    assert_eq!(
        (report.sent, report.blocked, report.failed),
        (0, true, None)
    );
    assert_eq!(
        counters(&client),
        unmoved,
        "a refused lone GET moves nothing"
    );
    limits.allowance.set(None);
    let report = client.poll(now + 400);
    assert_eq!((report.sent, report.blocked), (1, false));
    assert_eq!(
        *limits.offered.borrow(),
        [vec![HEADER_LEN], vec![HEADER_LEN]],
        "each poll made one call for the lone GET"
    );
    let mut gets_per_datagram = [0; MAX_PACKED_GETS];
    gets_per_datagram[0] = 1;
    let taken_once = (gets_per_datagram, 400, buckets(&[(8, 1)]));
    assert_eq!(counters(&client), taken_once);

    run_between(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (now + 500, now + 900),
        false,
        &[],
    );
    limits.allowance.set(Some(0));
    limits.offered.borrow_mut().clear();
    let report = client.poll(now + 1_000);
    assert!(report.received > 0, "premise: the fragment arrived");
    assert_eq!((report.sent, report.blocked), (0, true));
    limits.allowance.set(None);
    assert!(in_flight(&net).is_empty(), "premise: the link is empty");
    assert_eq!(client.poll(now + 1_100).sent, 1);
    assert_eq!(
        *limits.offered.borrow(),
        [vec![HEADER_LEN], vec![HEADER_LEN]],
        "each poll made one call for the lone ACK"
    );
    let ack = in_flight(&net);
    assert_eq!(ack.len(), 1, "the refused ACK left in the next poll");
    assert_eq!(
        (ack[0].0, ack[0].1[0].0),
        (HEADER_LEN, Kind::Ack),
        "premise: the lone frame is an ACK"
    );
    assert_eq!(
        counters(&client),
        taken_once,
        "a lone ACK moves no GET counter"
    );
    settle(
        &mut client,
        &mut owner,
        &mut owner_end,
        &net,
        (now + 1_200, now + 1_900),
        &[refused],
    );

    let _lost = get(&mut client, now + 2_000);
    limits.offered.borrow_mut().clear();
    limits.fail_next.set(true);
    let report = client.poll(now + 2_000);
    assert_eq!(
        (report.sent, report.blocked, report.failed),
        (0, false, Some(Some(libc::EIO)))
    );
    assert!(now + 2_100 < now + 2_000 + WIDE.fetch.retry_us);
    assert_eq!(client.poll(now + 2_100).sent, 0);
    assert_eq!(
        *limits.offered.borrow(),
        [vec![HEADER_LEN]],
        "the failed call carried the GET alone, and the next poll made no call"
    );
    assert_eq!(
        counters(&client),
        taken_once,
        "a lone GET whose call fails moves nothing"
    );

    let _beside = get(&mut client, now + 2_200);
    client
        .put([7; 32], CacheVersion(0), now + 2_200, 1_000_000)
        .unwrap();
    limits.offered.borrow_mut().clear();
    assert_eq!(client.poll(now + 2_200).sent, 2);
    assert_eq!(
        *limits.offered.borrow(),
        [vec![HEADER_LEN, HEADER_LEN]],
        "a GET and a PUT BEGIN leave in one call of two datagrams"
    );
    gets_per_datagram[0] = 2;
    assert_eq!(
        counters(&client),
        (gets_per_datagram, 400, buckets(&[(0, 1), (8, 1)]))
    );
}
