//! The transfer cores end to end over a [`Datagrams`] transport: the owner's [`ServeCore`] and the client's [`FetchCore`] exchange encoded frames through two transport ends, over the seeded fault network under each fault class.

use std::cell::{Cell, RefCell};

use crate::sim::round::{Act, Actor, round};
use crate::storage::seeded::SplitMix64;
use crate::storage::{Crc32c, EngineBudget};

use super::datagram::{DatagramError, Datagrams, HEADER_LEN, Outgoing, Payload, PeerId, Received};
use super::fetch::{FetchConfig, FetchReport, Outcome, Releases};
use super::fetch_tests::Fetcher;
use super::frame::{Header, Kind, encode, parse};
use super::link::{Faults, network};
use super::packet::{PacketLease, PacketPool};
use super::requests::RequestTable;
use super::serve::{GetOutcome, Manifest, ReadEnd, ServeConfig, ServeReport};
use super::serve_tests::Core;
use super::session::{Admitted, Caps};

const SESSION: Admitted = Admitted {
    peer: PeerId(0),
    epoch: 3,
    caps: Caps {
        slots: 4,
        window: 8,
    },
};

const SERVE: ServeConfig = ServeConfig {
    retry_us: 2_000,
    attempts: 200,
    linger_us: 50_000,
    rate_per_sec: 10_000_000,
    burst: 64,
    slots: 4,
    replies: 8,
    max_wait_us: 30_000_000,
};

const FETCH: FetchConfig = FetchConfig {
    retry_us: 3_000,
    attempts: 200,
    window: 8,
    boxes: 16,
};

const BATCH: usize = 8;

/// Fills the transport fields every frame of this exchange carries; tags stay zero because sessions are out of this test's scope.
fn stamp(mut header: Header, epoch: u64, sequence: u64, payload_len: usize) -> Header {
    header.principal = 1;
    header.key_epoch = 1;
    header.owner_nonce = [0x0A; 16];
    header.client_nonce = [0x0C; 16];
    header.epoch = epoch;
    header.sequence = sequence;
    header.datagram_len = payload_len as u32;
    header
}

/// Receives one batch from `transport` into leases of `pool`, keeping each datagram from peer 0 with whether it was truncated.
fn receive<'a, 'p, D: Datagrams<'a>>(
    transport: &mut D,
    pool: &'p PacketPool<'a>,
    out: &mut Vec<(PacketLease<'p>, bool)>,
) {
    let mut leases: [Option<PacketLease<'p>>; BATCH] = std::array::from_fn(|_| None);
    let mut meta = [Received::default(); BATCH];
    let got = transport.receive(pool, &mut leases, &mut meta).unwrap_or(0);
    for (lease, meta) in leases.into_iter().zip(meta).take(got) {
        if let (Some(lease), Some(PeerId(0))) = (lease, meta.peer) {
            out.push((lease, meta.truncated));
        }
    }
}

/// Fetches `object` from an owner across `owner_end` and `client_end`, advancing time with `clock` once per turn, for at most `turns` turns; returns the outcome and the bytes the application took.
fn exchange<'a, O: Datagrams<'a>, C: Datagrams<'a>>(
    owner_end: &mut O,
    client_end: &mut C,
    object: &[u8],
    clock: impl FnMut(u64) -> u64,
    turns: u64,
) -> Exchange {
    exchange_hooked(owner_end, client_end, object, clock, turns, |_| {})
}

/// [`exchange`] with `sent` called after the owner's send of each turn, while its datagrams are in flight toward the client. Each turn moves the clock, then runs one controller round: the client's timers and sends, the owner's receive, timers and sends, then the client's receive.
fn exchange_hooked<'a, O: Datagrams<'a>, C: Datagrams<'a>>(
    owner_end: &mut O,
    client_end: &mut C,
    object: &[u8],
    mut clock: impl FnMut(u64) -> u64,
    turns: u64,
    mut sent: impl FnMut(u64),
) -> Exchange {
    let crc = Crc32c::detect();
    let mut budget = EngineBudget::new(1 << 26);
    let mut owner = Core::<Box<[u8]>>::new(
        SERVE,
        RequestTable::new(4, 1, 4),
        1,
        BATCH as u32,
        0,
        4,
        &mut budget,
    )
    .unwrap();
    let owner_pool = super::packet::test_pool(32, BATCH as u32).unwrap();
    let client_pool = super::packet::test_pool(32, BATCH as u32).unwrap();
    let releases = Releases::new(4, &mut budget).unwrap();
    let mut client =
        Fetcher::new(FETCH, RequestTable::new(4, 1, 4), &releases, &mut budget).unwrap();
    let key = [0x42; 32];
    let manifest = Manifest {
        allocation: 0x5_0000_0001,
        metadata_len: 11,
        body_len: object.len() as u32 - 11,
    };
    let id = client
        .fetch(SESSION, key, 64, 1 << 22, 0, 20_000_000)
        .unwrap();
    let mut bytes = Vec::new();
    let (mut owner_sequence, mut client_sequence) = (0, 0);
    let inbox = RefCell::new(Vec::new());
    // Truncated datagrams the codec refused before any core read them.
    let refused = Cell::new(0);
    let client = RefCell::new(client);
    let client_end = RefCell::new(client_end);
    for turn in 0..turns {
        // The clock moves the link before the round, as the controller moves
        // passive state, so every actor of the turn reads the turn's time.
        let now = Cell::new(clock(turn));
        let mut client_turn = || {
            let now = now.get();
            let mut client = client.borrow_mut();
            client.tick(now);
            client.poll(now, BATCH, |ask| {
                client_sequence += 1;
                let header = stamp(ask.header, ask.epoch, client_sequence, 0);
                let mut out = [0u8; HEADER_LEN];
                encode(crc, &header, [&[], &[]], &mut out).expect("canonical");
                client_end
                    .borrow_mut()
                    .send(&[Outgoing {
                        peer: PeerId(0),
                        header: &out,
                        payload: [Payload::EMPTY; 2],
                    }])
                    .is_ok_and(|sent| sent == 1)
            });
        };
        let mut owner_turn = || {
            let now = now.get();
            let mut inbox = inbox.borrow_mut();
            receive(owner_end, &owner_pool, &mut inbox);
            for (lease, truncated) in inbox.drain(..) {
                let Ok(frame) = parse(crc, lease.bytes(), truncated) else {
                    refused.set(refused.get() + u64::from(truncated));
                    continue;
                };
                let header = frame.header();
                match header.kind {
                    Kind::Get => {
                        if let GetOutcome::Read { id, .. } = owner.get(SESSION, &header, now) {
                            owner.read_started(id);
                            owner.chunk(
                                id,
                                manifest,
                                0..object.len() as u64,
                                object.into(),
                                &[],
                                now,
                            );
                            owner.read_done(id, ReadEnd::Complete(manifest), now);
                        }
                    }
                    Kind::Ack => owner.ack(SESSION, &header, now),
                    Kind::Cancel => owner.cancel(SESSION, &header, now),
                    _ => {}
                }
            }
            owner.tick(now);
            owner.release_drained(|_| true);
            owner.poll(now, BATCH, |frames| {
                let mut taken = 0;
                for frame in frames {
                    owner_sequence += 1;
                    let len = frame.payload[0].len() + frame.payload[1].len();
                    let header = stamp(frame.header, frame.epoch, owner_sequence, len);
                    let mut out = [0u8; HEADER_LEN];
                    let pieces = [frame.payload[0].bytes(), frame.payload[1].bytes()];
                    encode(crc, &header, pieces, &mut out).expect("canonical");
                    let sent = owner_end.send(&[Outgoing {
                        peer: PeerId(0),
                        header: &out,
                        payload: frame.payload,
                    }]);
                    if !sent.is_ok_and(|sent| sent == 1) {
                        break;
                    }
                    taken += 1;
                }
                taken
            });
            sent(turn);
        };
        let mut client_receive = || {
            let now = now.get();
            let mut client = client.borrow_mut();
            let mut inbox = inbox.borrow_mut();
            receive(&mut **client_end.borrow_mut(), &client_pool, &mut inbox);
            for (lease, truncated) in inbox.drain(..) {
                let Ok(frame) = parse(crc, lease.bytes(), truncated) else {
                    refused.set(refused.get() + u64::from(truncated));
                    continue;
                };
                let header = frame.header();
                let body = frame.check_body(crc).is_ok();
                match header.kind {
                    Kind::Start => client.start(SESSION, &header, now),
                    Kind::Data if body => client.data(SESSION, &header, lease, now),
                    Kind::Complete => client.complete(SESSION, &header),
                    Kind::Error => client.error(SESSION, &header),
                    _ => {}
                }
            }
            while let Some(fragment) = client.take(id) {
                bytes.extend_from_slice(fragment.bytes());
            }
        };
        round(&mut [
            Act::new(Actor::Client(0), &mut client_turn),
            Act::new(Actor::Owner(0), &mut owner_turn),
            Act::new(Actor::Client(0), &mut client_receive),
        ]);
        let client = client.borrow();
        if let Some(outcome) = client.outcome(id) {
            return Exchange {
                outcome: Some(outcome),
                bytes,
                refused: refused.get(),
                turns: turn + 1,
                serve: owner.report(),
                fetch: client.report(),
            };
        }
    }
    let client = client.borrow();
    Exchange {
        outcome: client.outcome(id),
        bytes,
        refused: refused.get(),
        turns,
        serve: owner.report(),
        fetch: client.report(),
    }
}

/// What one exchange reached: the client's outcome, the bytes the application took, the truncated datagrams the codec refused, the turns it ran, and both cores' counters.
struct Exchange {
    outcome: Option<Outcome>,
    bytes: Vec<u8>,
    refused: u64,
    turns: u64,
    serve: ServeReport,
    fetch: FetchReport,
}

fn object(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

/// Each fault class, applied to both directions of the simulated network.
fn classes() -> [(&'static str, Faults); 11] {
    let none = Faults::default();
    [
        ("clean", none),
        ("loss", Faults { loss: 15, ..none }),
        (
            "duplicate",
            Faults {
                duplicate: 25,
                ..none
            },
        ),
        (
            "reorder",
            Faults {
                reorder: 40,
                ..none
            },
        ),
        ("delay", Faults { delay: 30, ..none }),
        ("stale", Faults { stale: 20, ..none }),
        (
            "truncate",
            Faults {
                truncate: 10,
                ..none
            },
        ),
        (
            "would block",
            Faults {
                would_block: 30,
                ..none
            },
        ),
        ("error", Faults { error: 10, ..none }),
        (
            "burst",
            Faults {
                loss: 30,
                burst: 4,
                ..none
            },
        ),
        // A transfer resends only what it lost, so the resend row loses
        // first sends too; it stays below 100 percent so the cores complete.
        (
            "resend loss",
            Faults {
                loss: 15,
                resend_loss: 30,
                ..none
            },
        ),
    ]
}

/// The transfer cores complete a multi-fragment transfer over the simulated network under each fault class, delivering the exact bytes; every class reaches its fault, a burst and a resend loss by their audit reasons, the codec refuses every truncated datagram before a core reads it, and the same seed replays the same schedule.
#[test]
fn the_cores_complete_over_the_simulator_under_each_fault_class() {
    let source = object(100_000, 1);
    for (name, faults) in classes() {
        let mut reports = Vec::new();
        for _ in 0..2 {
            let (mut owner, mut client, net) = network(64, 8384, 7, [faults; 2]);
            let Exchange {
                outcome,
                bytes,
                refused,
                ..
            } = crate::sim::round::afresh(|| {
                exchange(
                    &mut owner,
                    &mut client,
                    &source,
                    |turn| {
                        net.borrow_mut().advance(turn);
                        turn * 100
                    },
                    100_000,
                )
            });
            assert_eq!(outcome, Some(Outcome::Complete), "{name}");
            assert_eq!(bytes, source, "{name}");
            let net = net.borrow();
            let truncated = net.report(0).truncated + net.report(1).truncated;
            assert_eq!(
                refused, truncated,
                "{name}: the codec refused every truncated datagram"
            );
            // Each direction's report, with the bursts and resends its link
            // dropped.
            let direction = |toward| {
                let source = super::audit::Source::Link { actor: 0, toward };
                let dropped = |reason| net.audit().count_at(source, reason);
                (
                    net.report(toward),
                    dropped(super::audit::Reason::LostBurst),
                    dropped(super::audit::Reason::LostResend),
                )
            };
            reports.push((direction(0), direction(1)));
        }
        // Each run restarts the round ordinals, so both take the same orders
        // and the seed replays the schedule under every schedule.
        assert_eq!(
            reports[0], reports[1],
            "{name}: the seed replays the schedule"
        );
        // Whether a run's draws reach the fault follows its order, so the
        // listed order's seed reaches every class.
        let (toward_owner, toward_client) = reports[0];
        let reached = [toward_owner, toward_client]
            .iter()
            .any(|(report, bursts, resends)| match name {
                "burst" => *bursts > 0,
                "resend loss" => *resends > 0,
                "loss" => report.lost > 0,
                "duplicate" => report.duplicated > 0,
                "stale" => report.stale > 0,
                "reorder" => report.reordered > 0,
                "delay" => report.delayed > 0,
                "truncate" => report.truncated > 0,
                "would block" => report.blocked > 0,
                "error" => report.errors > 0,
                _ => true,
            });
        if crate::sim::round::legacy() {
            assert!(reached, "{name}: the fault was injected");
        }
    }
}

/// One DATA fragment lost in flight is resent from the client's receipt mask within a few turns, well inside the owner's retry interval, and the transfer completes with no slow retry on either side.
#[test]
fn one_lost_fragment_is_recovered_from_the_receipt_mask_before_any_retry() {
    let source = object(60_000, 3);
    let (mut owner, mut client, net) = network(64, 8384, 11, [Faults::default(); 2]);
    let dropped = std::cell::Cell::new(0);
    let Exchange {
        outcome,
        bytes,
        turns,
        serve,
        fetch,
        ..
    } = exchange_hooked(
        &mut owner,
        &mut client,
        &source,
        |turn| {
            net.borrow_mut().advance(turn);
            turn * 100
        },
        100_000,
        |_| {
            // Fragment 3 of the first burst toward the client is lost; every later datagram arrives.
            if dropped.get() == 0 {
                net.borrow_mut().retain(1, |datagram| {
                    let data = datagram[10] == Kind::Data as u8;
                    let index = u32::from_be_bytes([
                        datagram[96],
                        datagram[97],
                        datagram[98],
                        datagram[99],
                    ]);
                    if data && index == 3 {
                        dropped.set(dropped.get() + 1);
                        false
                    } else {
                        true
                    }
                });
            }
        },
    );
    assert_eq!(dropped.get(), 1, "the fragment was in flight once");
    assert_eq!(outcome, Some(Outcome::Complete));
    assert_eq!(bytes, source);
    assert!(
        turns * 100 < SERVE.retry_us,
        "completed in {turns} turns, inside the owner's retry interval"
    );
    assert_eq!(serve.retries, 0, "{serve:?}");
    assert_eq!(serve.hole_resends, 1, "{serve:?}");
    assert_eq!(fetch.ack_retries, 0, "{fetch:?}");
    assert!(fetch.gap_acks >= 1, "{fetch:?}");
}

/// An owner that dies mid-transfer leaves the client with an explicit `Incomplete` or `Failed` outcome by its deadline, and the bytes the application took are a prefix of the one version.
#[test]
fn a_dead_owner_ends_the_fetch_explicitly() {
    let source = object(200_000, 2);
    let (mut owner, mut client, net) = network(64, 8384, 9, [Faults::default(); 2]);
    let Exchange { outcome, bytes, .. } = exchange(
        &mut owner,
        &mut client,
        &source,
        |turn| {
            let mut net = net.borrow_mut();
            net.advance(turn);
            if turn == 3 {
                net.kill(0);
            }
            turn * 1_000
        },
        100_000,
    );
    assert!(
        matches!(outcome, Some(Outcome::Incomplete(_) | Outcome::Failed(_))),
        "{outcome:?}"
    );
    assert_eq!(bytes, source[..bytes.len()], "a prefix of one version");
}

/// The simulator copies each accepted datagram's header and inline pieces at send return, so overwriting them afterwards leaves the delivered bytes as sent; a full queue reports the accepted prefix.
#[test]
fn the_simulator_snapshots_accepted_bytes_and_bounds_its_queue() {
    let (mut a, mut b, net) = network(2, 8384, 0, [Faults::default(); 2]);
    let mut header = [0x11u8; 16];
    let mut payload = [0x22u8; 32];
    let snapshot = [header.as_slice(), &payload].concat();
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &header,
        payload: [Payload::Inline(&payload), Payload::EMPTY],
    };
    assert_eq!(a.send(&[datagram; 3]), Ok(2), "the queue holds two");
    assert_eq!(net.borrow().report(1).full, 1);
    header.fill(0);
    payload.fill(0);
    let pool = super::packet::test_pool(4, 1).unwrap();
    let mut leases: [Option<PacketLease<'_>>; 2] = [None, None];
    let mut meta = [Received::default(); 2];
    assert_eq!(b.receive(&pool, &mut leases, &mut meta), Ok(2));
    assert_eq!(leases[0].as_ref().unwrap().bytes(), snapshot.as_slice());
    assert_eq!(meta[0].peer, Some(PeerId(0)));
}

/// The simulator decides a call the way the seam requires before it draws a call fault: an empty receive or send is a successful empty batch, and a refused leading datagram fails the call with its error code; only a call that reaches the network draws the fault.
#[test]
fn the_simulator_decides_empty_and_refused_calls_before_drawing_a_fault() {
    let failing = Faults {
        error: 100,
        ..Faults::default()
    };
    let (mut a, mut b, net) = network(2, 16, 0, [failing; 2]);
    let pool = super::packet::test_pool(4, 1).unwrap();
    let mut meta = [Received::default(); 1];
    assert_eq!(
        b.receive(&pool, &mut [], &mut meta),
        Ok(0),
        "no slots, no call"
    );
    assert_eq!(a.send(&[]), Ok(0), "no datagrams, no call");
    let foreign = Outgoing {
        peer: PeerId(1),
        header: b"z",
        payload: [Payload::EMPTY; 2],
    };
    assert_eq!(
        a.send(&[foreign]),
        Err(DatagramError::Failed { code: None }),
        "a leading datagram for an unconfigured peer fails the call"
    );
    let oversized = Outgoing {
        peer: PeerId(0),
        header: &[0; 17],
        payload: [Payload::EMPTY; 2],
    };
    assert_eq!(
        a.send(&[oversized]),
        Err(DatagramError::Failed {
            code: Some(libc::EMSGSIZE)
        }),
        "a leading datagram past the link's length fails the call"
    );
    assert_eq!(
        net.borrow().report(1).errors,
        0,
        "no call reached the network"
    );
    let sent = Outgoing {
        peer: PeerId(0),
        header: b"ok",
        payload: [Payload::EMPTY; 2],
    };
    assert_eq!(
        a.send(&[sent]),
        Err(DatagramError::Failed {
            code: Some(libc::EIO)
        }),
        "a send that reaches the network draws its fault"
    );
    assert_eq!(net.borrow().report(1).errors, 1);
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_dead_owner_ends_the_fetch_explicitly,
    one_lost_fragment_is_recovered_from_the_receipt_mask_before_any_retry,
    the_cores_complete_over_the_simulator_under_each_fault_class,
);
