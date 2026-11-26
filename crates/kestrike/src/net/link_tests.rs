//! The simulated link's rule chain, reserve-first admission, recorded fault
//! draws, selected transmit returns, containment classes and outcome audit.

use std::cell::RefCell;
use std::rc::Rc;

use crate::sim::choice::{ChoiceError, Chooser, Defect};
use crate::storage::device::sim::{Event, Injection, Omission, Origin};
use crate::storage::{CommandToken, PoolKind, RefusalReason, SubmitRefusal};

use super::audit::{Audit, Class, Reason, Source, Verdict, device_outcome};
use super::datagram::{DatagramError, Datagrams, Outgoing, Payload, PeerId, Received};
use super::frame::{AUTHENTICATED_LEN, Direction, Kind};
use super::link::{
    Draws, Faults, LinkLimits, Net, TxRelease, UNBOUNDED, network, network_drawn, network_later,
    sites,
};
use super::owner_tests::{ENDPOINT, PRINCIPALS};
use super::packet::{PacketLease, PacketPool, test_arena, test_pool};
use super::put_tests::scene;
use super::rules::{
    Bound, Chain, Corruption, Decision, Dropped, Effect, Layer, MANIFEST, Manifest, Message, Rule,
    Selector, contain,
};

fn message(kind: Kind, toward: usize, ordinal: u64) -> Message {
    Message {
        link: 0,
        toward,
        ordinal,
        header: Some(super::serve::header(kind, 7, [0; 32])),
    }
}

/// The encoded GET of `request`, a frame the link's rules and resend key
/// decode.
fn get_frame(request: u64) -> Vec<u8> {
    let get = super::frame_tests::Raw::get();
    super::frame_tests::Raw { request, ..get }.bytes()
}

fn plain<'a>(header: &[u8]) -> Outgoing<'_, 'a> {
    Outgoing {
        peer: PeerId(0),
        header,
        payload: [Payload::EMPTY, Payload::EMPTY],
    }
}

/// Receives every due datagram at `end` and returns how many arrived.
fn drain(end: &mut super::link::LinkEnd<'_>) -> usize {
    let pool = test_pool(8, 1).unwrap();
    drain_with_pool(end, &pool)
}

/// Reuses a receive pool whose arena outlives the link's posted buffers.
fn drain_with_pool<'a>(end: &mut super::link::LinkEnd<'a>, pool: &PacketPool<'a>) -> usize {
    let mut count = 0;
    loop {
        let mut meta = [Received::default(); 4];
        let mut leases: [Option<PacketLease<'_>>; 4] = [None, None, None, None];
        match end.receive(pool, &mut leases, &mut meta) {
            Ok(0) | Err(_) => return count,
            Ok(n) => count += n,
        }
    }
}

/// Rules update one pending decision in order and the last one commits:
/// a later rule's deliver overrides an earlier drop, the taps see the
/// pending decision after each rule, and the tap past the last rule sees
/// the committed one. Through the link, a later deliver also overrides the
/// direction's loss fault.
#[test]
fn rules_commit_one_decision_after_the_last_rule() {
    let rules = vec![
        Rule::new(Selector::Any, Effect::Drop),
        Rule::new(Selector::Kind(Kind::Get), Effect::Deliver),
    ];
    let mut chain = Chain::new(rules, &[0, 1, 2], &MANIFEST).unwrap();
    let get = chain.decide(&message(Kind::Get, 1, 0), Decision::default());
    let ack = chain.decide(&message(Kind::Ack, 1, 1), Decision::default());
    assert_eq!(get.drop, None, "the later rule overrode the drop");
    assert_eq!(ack.drop, Some(Dropped::Rule(0)));
    let seen: Vec<_> = chain
        .captures()
        .iter()
        .map(|capture| (capture.ordinal, capture.tap, capture.decision.drop))
        .collect();
    let dropped = Some(Dropped::Rule(0));
    assert_eq!(
        seen,
        [
            (0, 0, None),
            (0, 1, dropped),
            (0, 2, None),
            (1, 0, None),
            (1, 1, dropped),
            (1, 2, dropped)
        ]
    );
    let lossy = Faults {
        loss: 100,
        ..Faults::default()
    };
    let (mut near, mut far, net) = network(8, 8384, 3, [lossy; 2]);
    let deliver = vec![
        Rule::new(Selector::Any, Effect::Drop),
        Rule::new(Selector::Any, Effect::Deliver),
    ];
    net.borrow_mut()
        .set_rules(Chain::new(deliver, &[], &MANIFEST).unwrap());
    assert_eq!(near.send(&[plain(b"h")]), Ok(1));
    assert_eq!(
        drain(&mut far),
        1,
        "rule 1's drop never took effect before rule 2 ran"
    );
    assert_eq!(net.borrow().report(1).lost, 0);
    let isolate = vec![Rule::new(Selector::Toward(1), Effect::Isolate)];
    net.borrow_mut()
        .set_rules(Chain::new(isolate, &[], &MANIFEST).unwrap());
    assert_eq!(
        near.send(&[plain(b"a"), plain(b"b")]),
        Ok(2),
        "an isolated send is taken"
    );
    assert_eq!(drain(&mut far), 0, "and never delivered");
    assert_eq!(net.borrow().audit().count(Reason::Isolated), 2);
}

/// Every field a rule sets, a later rule sets back: duplication,
/// reordering, delay, corruption and truncation each return to their
/// unset delivery, and the committed decision is the plain one.
#[test]
fn later_rules_set_back_every_field_an_earlier_rule_set() {
    let rules = vec![
        Rule::new(Selector::Any, Effect::Duplicate),
        Rule::new(Selector::Any, Effect::Reorder),
        Rule::new(Selector::Any, Effect::Delay(5)),
        Rule::new(Selector::Any, Effect::Corrupt(Corruption::Tag)),
        Rule::new(Selector::Any, Effect::Truncate),
        Rule::new(Selector::Any, Effect::NoDuplicate),
        Rule::new(Selector::Any, Effect::InOrder),
        Rule::new(Selector::Any, Effect::Prompt),
        Rule::new(Selector::Any, Effect::Clean),
        Rule::new(Selector::Any, Effect::Whole),
    ];
    let mut chain = Chain::new(rules, &[5, 10], &MANIFEST).unwrap();
    let committed = chain.decide(&message(Kind::Data, 0, 0), Decision::default());
    let set = chain.captures()[0].decision;
    assert!(set.duplicate && set.reorder == Some(true) && set.delay == Some(5));
    assert_eq!(
        (set.corrupt, set.truncate),
        (Some(Corruption::Tag), Some(true))
    );
    assert_eq!(
        committed,
        Decision {
            reorder: Some(false),
            delay: Some(0),
            truncate: Some(false),
            ..Decision::default()
        }
    );
    assert_eq!(
        chain.captures()[1].decision,
        committed,
        "the last tap sees the committed one"
    );
}

/// A reordered copy goes ahead of every queued one.
#[test]
fn a_reordered_copy_goes_ahead_of_the_queue() {
    let (mut near, mut far, net) = network(8, 8384, 0, [Faults::default(); 2]);
    let rules = vec![Rule::new(Selector::Any, Effect::Reorder).window(1, 1)];
    net.borrow_mut()
        .set_rules(Chain::new(rules, &[], &MANIFEST).unwrap());
    assert_eq!(near.send(&[plain(b"first"), plain(b"second")]), Ok(2));
    let pool = test_pool(8, 1).unwrap();
    let mut meta = [Received::default(); 2];
    let mut leases: [Option<PacketLease<'_>>; 2] = [None, None];
    assert_eq!(far.receive(&pool, &mut leases, &mut meta), Ok(2));
    let order = leases.map(|lease| lease.unwrap().bytes().to_vec());
    assert_eq!(order, [b"second".to_vec(), b"first".to_vec()]);
    assert_eq!(net.borrow().audit().count(Reason::Reordered), 1);
}

/// Each selector picks out its own kind, direction, request, PUT serial,
/// session, fragment range or ACK hole, and a rule's window keeps its own
/// count of matches.
#[test]
fn selectors_isolate_their_traffic_and_windows_keep_state() {
    let mut data = message(Kind::Data, 0, 0);
    if let Some(header) = data.header.as_mut() {
        header.index = 3;
        header.allocation = 9;
        header.epoch = 4;
    }
    let mut hole = message(Kind::PutAck, 1, 1);
    if let Some(header) = hole.header.as_mut() {
        header.offset = 0b10;
    }
    let mut other = message(Kind::Get, 1, 2);
    if let Some(header) = other.header.as_mut() {
        header.request = 8;
    }
    let cases: [(Selector, [bool; 3]); 9] = [
        (Selector::Any, [true, true, true]),
        (Selector::Kind(Kind::Data), [true, false, false]),
        (Selector::Toward(1), [false, true, true]),
        (Selector::Request(7), [true, true, false]),
        (Selector::Serial(9), [true, false, false]),
        (Selector::Session(4), [true, false, false]),
        (
            Selector::Fragments { first: 2, last: 4 },
            [true, false, false],
        ),
        (Selector::Holes, [false, true, false]),
        (
            Selector::All(vec![Selector::Toward(1), Selector::Request(7)]),
            [false, true, false],
        ),
    ];
    for (selector, expected) in cases {
        let mut chain = Chain::new(
            vec![Rule::new(selector.clone(), Effect::Drop)],
            &[],
            &MANIFEST,
        )
        .unwrap();
        let dropped =
            [&data, &hole, &other].map(|m| chain.decide(m, Decision::default()).drop.is_some());
        assert_eq!(dropped, expected, "{selector:?}");
    }
    let mut chain = Chain::new(
        vec![Rule::new(Selector::Any, Effect::Drop).window(1, 2)],
        &[],
        &MANIFEST,
    )
    .unwrap();
    let dropped: Vec<bool> = (0..5)
        .map(|n| {
            chain
                .decide(&message(Kind::Ack, 1, n), Decision::default())
                .drop
                .is_some()
        })
        .collect();
    assert_eq!(dropped, [false, true, true, false, false]);
}

/// What one link's traffic leaves: the reports, rule captures, audit
/// reasons and the ordered delivery log with its overflow flag.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Schedule {
    reports: Vec<super::link::NetReport>,
    captures: Vec<super::rules::Capture>,
    reasons: Vec<Reason>,
    deliveries: Vec<super::link::Delivery>,
    overflow: bool,
}

impl Schedule {
    /// Whether `other` replays this schedule: equal reports, captures,
    /// audit reasons and ordered deliveries, with neither log overflowed.
    fn replayed_by(&self, other: &Self) -> bool {
        !self.overflow && !other.overflow && self == other
    }
}

/// One link's traffic under faults and a tapped rule chain, drawn from
/// `draws`: the schedule it leaves.
fn schedule(draws: &Draws) -> Schedule {
    let faults = Faults {
        loss: 20,
        duplicate: 20,
        reorder: 20,
        delay: 3,
        stale: 10,
        truncate: 10,
        would_block: 5,
        error: 5,
        burst: 3,
        resend_loss: 30,
    };
    let (mut near, mut far, net) = network_drawn(16, 8384, [faults; 2], (draws, 0));
    let rules = vec![
        Rule::new(Selector::Any, Effect::Delay(1)).window(3, 4),
        Rule::new(Selector::Any, Effect::Duplicate).window(10, 2),
    ];
    net.borrow_mut()
        .set_rules(Chain::new(rules, &[0, 2], &MANIFEST).unwrap());
    let pool = test_pool(8, 1).unwrap();
    for turn in 0..200 {
        net.borrow_mut().advance(turn);
        // Every fifth send is an unparsed datagram; the frames name 32
        // requests, each repeating every 40 turns, so later ones are
        // resends.
        if turn % 5 == 0 {
            let _ = near.send(&[plain(&[turn as u8; 40])]);
        } else {
            let _ = near.send(&[plain(&get_frame(turn % 40))]);
        }
        drain_with_pool(&mut far, &pool);
    }
    let net = net.borrow();
    assert_eq!(net.draw_error(), None, "every draw was on the tape");
    for toward in 0..2 {
        let source = Source::Link { actor: 0, toward };
        let count = |reasons: &[Reason]| -> u64 {
            reasons
                .iter()
                .map(|&reason| net.audit().count_at(source, reason) as u64)
                .sum()
        };
        let report = net.report(toward);
        let audited = [
            (
                report.lost,
                count(&[
                    Reason::Lost,
                    Reason::LostBurst,
                    Reason::LostResend,
                    Reason::RuleDrop,
                    Reason::Isolated,
                    Reason::DeadEnd,
                ]),
            ),
            (report.duplicated, count(&[Reason::Duplicated])),
            (report.stale, count(&[Reason::Stale])),
            (report.delayed, count(&[Reason::Delayed])),
            (report.reordered, count(&[Reason::Reordered])),
            (report.truncated, count(&[Reason::Truncated])),
            (report.errors, count(&[Reason::CallFailed])),
            (report.blocked, count(&[Reason::WouldBlock])),
            (report.missed, count(&[Reason::Missed])),
            (report.altered, count(&[Reason::Altered])),
        ];
        for (counted, recorded) in audited {
            assert_eq!(
                counted, recorded,
                "toward {toward}: every counted outcome is audited"
            );
        }
        let records = net.audit().records().iter();
        let full = records.filter(|r| r.source == source && matches!(r.reason, Reason::Full(_)));
        assert_eq!(
            report.full,
            full.count() as u64,
            "toward {toward}: every refusal is audited"
        );
    }
    let reasons = net
        .audit()
        .records()
        .iter()
        .map(|record| record.reason)
        .collect();
    let (deliveries, overflow) = net.deliveries();
    Schedule {
        reports: vec![net.report(0), net.report(1)],
        captures: net.rules().captures().to_vec(),
        reasons,
        deliveries: deliveries.to_vec(),
        overflow,
    }
}

fn recorder(root: u64) -> Draws {
    Rc::new(RefCell::new(Chooser::record(root, &sites(0))))
}

/// Every fault, burst and resend loss included, is a recorded choice at the link's registered sites: two
/// fresh runs from one root give one schedule, one capture order and one
/// audit; another root gives another; the tape replays the schedule; and a
/// link with no faults draws nothing.
#[test]
fn every_fault_draw_is_a_recorded_choice_that_replays() {
    let draws = recorder(41);
    let first = schedule(&draws);
    assert!(
        first.replayed_by(&schedule(&recorder(41))),
        "equal roots, equal schedules, taps and ordered deliveries"
    );
    assert!(!first.replayed_by(&schedule(&recorder(42))));
    let report = first.reports[1];
    assert!(report.lost > 0 && report.duplicated > 0 && report.truncated > 0);
    assert!(report.reordered > 0 && report.delayed > 0, "{report:?}");
    for reason in [Reason::Lost, Reason::LostBurst, Reason::LostResend] {
        assert!(first.reasons.contains(&reason), "{reason:?} drawn");
    }
    let digests: std::collections::BTreeSet<_> = first
        .deliveries
        .iter()
        .map(|delivery| delivery.digest)
        .collect();
    assert!(digests.len() > 1, "distinguishable deliveries");
    let tape = Rc::try_unwrap(draws)
        .unwrap()
        .into_inner()
        .finish()
        .unwrap();
    let replay: Draws = Rc::new(RefCell::new(Chooser::replay(&sites(0), tape)));
    assert!(
        first.replayed_by(&schedule(&replay)),
        "the tape replays the schedule"
    );
    Rc::try_unwrap(replay)
        .unwrap()
        .into_inner()
        .finish()
        .unwrap();
    let quiet = recorder(43);
    {
        let (mut near, mut far, _net) =
            network_drawn(16, 8384, [Faults::default(); 2], (&quiet, 0));
        assert_eq!(near.send(&[plain(b"h"); 4]), Ok(4));
        assert_eq!(drain(&mut far), 4);
    }
    assert_eq!(
        quiet.borrow().decisions(),
        0,
        "a zero percentage draws nothing"
    );
}

/// A later incarnation built with `network_later` leaves the living
/// link's fault draws admitted until it launches; from its launch the
/// chooser refuses the earlier incarnation's draws and admits the later
/// one's.
#[test]
fn a_later_link_takes_the_draws_only_from_its_launch() {
    let draws = recorder(44);
    let lossy = [Faults {
        loss: 50,
        ..Faults::default()
    }; 2];
    let (mut near, _far, living) = network_drawn(16, 8384, lossy, (&draws, 0));
    let (mut later_near, _later_far, later) = network_later(16, 8384, lossy, (&draws, 0));
    let _ = near.send(&[plain(b"before")]);
    assert_eq!(living.borrow().draw_error(), None, "the living link draws");
    later.borrow_mut().launch();
    let _ = later_near.send(&[plain(b"after")]);
    assert_eq!(later.borrow().draw_error(), None, "the launched link draws");
    let _ = near.send(&[plain(b"stale")]);
    let stale = ChoiceError::HarnessDefect(Defect::Incarnation {
        actor: 0,
        incarnation: 0,
    });
    assert_eq!(
        living.borrow().draw_error(),
        Some(stale),
        "the earlier incarnation's draws are refused once the later launched"
    );
}

#[test]
#[should_panic(expected = "a link draws only once its incarnation launched")]
fn a_later_link_draws_only_once_launched() {
    let draws = recorder(45);
    let lossy = [Faults {
        loss: 50,
        ..Faults::default()
    }; 2];
    let (_near, _far, _living) = network_drawn(16, 8384, lossy, (&draws, 0));
    let (mut later_near, _later_far, _later) = network_later(16, 8384, lossy, (&draws, 0));
    let _ = later_near.send(&[plain(b"early")]);
}

/// The delivery log records what the receiving end got, in the order it
/// got it: under loss, duplication, reordering, delay and truncation, the
/// digests of the delivered and truncated entries toward the far end equal
/// the digests of the bytes its receives returned, one for one.
#[test]
fn the_delivery_log_follows_the_receiving_end() {
    use sha2::{Digest, Sha256};
    let faults = Faults {
        loss: 20,
        duplicate: 20,
        reorder: 20,
        delay: 3,
        truncate: 10,
        ..Faults::default()
    };
    let (mut near, mut far, net) = network(16, 8384, 7, [Faults::default(), faults]);
    let pool = test_pool(8, 1).unwrap();
    let mut received = Vec::new();
    for turn in 0..100 {
        net.borrow_mut().advance(turn);
        let _ = near.send(&[plain(&[turn as u8; 40])]);
        loop {
            let mut meta = [Received::default(); 4];
            let mut leases: [Option<PacketLease<'_>>; 4] = [None, None, None, None];
            let Ok(n @ 1..) = far.receive(&pool, &mut leases, &mut meta) else {
                break;
            };
            for lease in leases.iter().take(n).flatten() {
                received.push(<[u8; 32]>::from(Sha256::digest(lease.bytes())));
            }
        }
    }
    let net = net.borrow();
    let (deliveries, overflow) = net.deliveries();
    let logged: Vec<[u8; 32]> = deliveries
        .iter()
        .filter(|delivery| delivery.toward == 1 && delivery.landed != super::link::Landed::Missed)
        .map(|delivery| delivery.digest)
        .collect();
    assert!(!overflow);
    assert!(net.report(1).reordered > 0 && net.report(1).truncated > 0);
    assert_eq!(logged, received);
}

/// Two distinguishable deliveries swapped leave every report, capture and
/// audit reason equal, and the ordered log alone refuses the pair as a
/// replay.
#[test]
fn a_swapped_delivery_pair_is_no_replay() {
    let first = schedule(&recorder(41));
    let at = first
        .deliveries
        .windows(2)
        .position(|pair| pair[0].toward == pair[1].toward && pair[0].digest != pair[1].digest)
        .expect("two distinguishable deliveries in one direction");
    let mut swapped = first.clone();
    swapped.deliveries.swap(at, at + 1);
    assert_eq!(
        (&swapped.reports, &swapped.captures, &swapped.reasons),
        (&first.reports, &first.captures, &first.reasons)
    );
    assert!(!first.replayed_by(&swapped));
}

/// The delivery log holds the manifest's captures; a delivery past them
/// sets its overflow flag, and an overflowed log replays nothing, itself
/// included.
#[test]
fn an_overflowed_delivery_log_fails_the_comparison() {
    let (mut near, mut far, net) = network(16, 8384, 0, [Faults::default(); 2]);
    let pool = test_pool(8, 1).unwrap();
    for turn in 0..=super::rules::MANIFEST.captures as u64 {
        net.borrow_mut().advance(turn);
        assert_eq!(near.send(&[plain(&turn.to_le_bytes())]), Ok(1));
        drain_with_pool(&mut far, &pool);
    }
    let net = net.borrow();
    let (deliveries, overflow) = net.deliveries();
    assert_eq!(deliveries.len(), super::rules::MANIFEST.captures);
    assert!(overflow);
    let overflowed = Schedule {
        reports: Vec::new(),
        captures: Vec::new(),
        reasons: Vec::new(),
        deliveries: deliveries.to_vec(),
        overflow,
    };
    assert!(!overflowed.replayed_by(&overflowed));
}

/// A receive's call fault runs in the link's uncounted work, recorded draw
/// and audit record included, so the caller's allocation count over a
/// blocking or failing link measures the endpoint alone.
#[test]
fn receive_call_faults_stay_out_of_the_allocation_count() {
    let pool = test_pool(8, 1).unwrap();
    let calls = 64;
    for faults in [
        Faults {
            would_block: 100,
            ..Faults::default()
        },
        Faults {
            error: 100,
            ..Faults::default()
        },
    ] {
        let (_near, mut far, net) = network(8, 8384, 0, [Faults::default(), faults]);
        let mut allocations = 0;
        for _ in 0..calls {
            let mut meta = [Received::default(); 4];
            let mut leases: [Option<PacketLease<'_>>; 4] = [None, None, None, None];
            let before = crate::instrument::allocations();
            let received = far.receive(&pool, &mut leases, &mut meta);
            allocations += crate::instrument::allocations() - before;
            assert!(
                matches!(received, Ok(0) | Err(DatagramError::Failed { .. })),
                "{received:?}"
            );
        }
        let report = net.borrow().report(1);
        assert_eq!(
            report.blocked + report.errors,
            calls,
            "every call drew its fault"
        );
        assert_eq!(
            net.borrow().audit().records().len(),
            calls as usize,
            "every fault audited"
        );
        assert_eq!(allocations, 0, "{faults:?}");
    }
}

/// A datagram reserves every entry, copied byte and transmit slot its
/// original, duplicate and stale copies need together, before the link
/// holds any source: a reservation that fails refuses the whole datagram
/// with its bound, ends the accepted prefix, and leaves the source with no
/// device reference, as the source's own count shows.
#[test]
fn copies_reserve_together_before_any_hold() {
    let arena = test_arena(4, 16384);
    let buffer = arena.acquire(PoolKind::PacketHeader).unwrap();
    let source = buffer.source(0..4).unwrap();
    let datagram = Outgoing {
        peer: PeerId(0),
        header: b"hdr",
        payload: [Payload::Retained(source), Payload::EMPTY],
    };
    let duplicate = || {
        Chain::new(
            vec![Rule::new(Selector::Any, Effect::Duplicate)],
            &[],
            &MANIFEST,
        )
        .unwrap()
    };
    let full = |net: &Rc<RefCell<Net<'_>>>, bound| net.borrow().audit().count(Reason::Full(bound));
    // The pool's per-buffer device-reference counts cross-check `nic_held`.
    let pool_held = || {
        let mut counts = Vec::new();
        arena
            .pools()
            .device_counts_into(PoolKind::PacketHeader, &mut counts);
        counts
            .iter()
            .map(|&count| usize::from(count))
            .sum::<usize>()
    };

    let (mut near, _far, net) = network(3, 8384, 0, [Faults::default(); 2]);
    net.borrow_mut().set_rules(duplicate());
    assert_eq!(
        near.send(&[datagram, datagram]),
        Ok(1),
        "the second needs two entries; one is free"
    );
    assert_eq!(net.borrow().pending(1), 2);
    assert_eq!(net.borrow().nic_held(), 2, "one reference per kept copy");
    assert_eq!(pool_held(), 2, "the pool counts both references");
    assert_eq!(full(&net, Bound::Entries), 1);
    net.borrow_mut().clear(1);
    assert!(!buffer.device_held());
    assert_eq!(pool_held(), 0);

    let stale = Faults {
        stale: 100,
        ..Faults::default()
    };
    let (mut near, mut far, net) = network(3, 8384, 0, [stale; 2]);
    assert_eq!(
        near.send(&[plain(b"first")]),
        Ok(1),
        "nothing delivered to replay yet"
    );
    assert_eq!(drain(&mut far), 1);
    assert_eq!(near.send(&[plain(b"pad")]), Ok(1));
    assert_eq!(
        net.borrow().pending(1),
        2,
        "the pad and a stale replay of the first"
    );
    assert_eq!(
        near.send(&[datagram]),
        Ok(0),
        "the original and its stale copy need two entries; one is free"
    );
    assert_eq!(full(&net, Bound::Entries), 1);
    assert!(
        !buffer.device_held(),
        "no hold before the failed reservation"
    );
    assert_eq!(pool_held(), 0);

    for (limits, bound) in [
        (
            LinkLimits {
                copy_bytes: 5,
                ..UNBOUNDED
            },
            Bound::CopyBytes,
        ),
        (
            LinkLimits {
                tx_slots: 1,
                ..UNBOUNDED
            },
            Bound::TxSlots,
        ),
    ] {
        let (mut near, _far, net) = network(8, 8384, 0, [Faults::default(); 2]);
        net.borrow_mut().set_limits(limits);
        net.borrow_mut().set_rules(duplicate());
        assert_eq!(near.send(&[datagram]), Ok(0), "{bound:?}");
        assert_eq!(full(&net, bound), 1);
        assert_eq!(net.borrow().nic_held(), 0);
        assert!(
            !buffer.device_held(),
            "{bound:?}: no hold before the failed reservation"
        );
        assert_eq!(pool_held(), 0, "{bound:?}");
    }

    // A source at its hold cap fixes the order: a link that held before it
    // reserved would refuse the datagram as unholdable.
    let capped = arena.acquire(PoolKind::PacketHeader).unwrap();
    let at_cap = capped.source(0..4).unwrap();
    let _holds: Vec<_> = (0..u16::MAX).map(|_| at_cap.hold().unwrap()).collect();
    let unholdable = Outgoing {
        payload: [Payload::Retained(at_cap), Payload::EMPTY],
        ..datagram
    };
    for (capacity, limits, bound) in [
        (1, UNBOUNDED, Bound::Entries),
        (
            8,
            LinkLimits {
                copy_bytes: 5,
                ..UNBOUNDED
            },
            Bound::CopyBytes,
        ),
        (
            8,
            LinkLimits {
                tx_slots: 1,
                ..UNBOUNDED
            },
            Bound::TxSlots,
        ),
    ] {
        let (mut near, _far, net) = network(capacity, 8384, 0, [Faults::default(); 2]);
        net.borrow_mut().set_limits(limits);
        net.borrow_mut().set_rules(duplicate());
        assert_eq!(near.send(&[unholdable]), Ok(0), "{bound:?}");
        assert_eq!(full(&net, bound), 1, "{bound:?}");
        assert_eq!(
            net.borrow().audit().count(Reason::NotHoldable),
            0,
            "{bound:?}: the reservation refused before any hold"
        );
    }
}

/// With withheld returns and two transmit slots, a batch is accepted only
/// up to its slots; accepted datagrams wait undelivered in the queue, and
/// delivered ones keep their slots until a selected event makes one
/// returnable, after which the sender's reclaim ends that charge and frees
/// a slot for the next send. Unaccepted, accepted-but-undelivered and
/// awaiting-return datagrams are each observed apart.
#[test]
fn withheld_returns_bound_acceptance_until_a_selected_return() {
    let arena = test_arena(4, 16384);
    let buffer = arena.acquire(PoolKind::PacketHeader).unwrap();
    let source = buffer.source(0..4).unwrap();
    let datagram = Outgoing {
        peer: PeerId(0),
        header: b"hdr",
        payload: [Payload::Retained(source), Payload::EMPTY],
    };
    let (mut near, mut far, net) = network(8, 8384, 0, [Faults::default(); 2]);
    net.borrow_mut().set_tx_release(TxRelease::Withheld);
    net.borrow_mut().set_limits(LinkLimits {
        tx_slots: 2,
        ..UNBOUNDED
    });
    assert_eq!(
        near.send(&[datagram; 3]),
        Ok(2),
        "bounded partial acceptance"
    );
    assert_eq!(
        net.borrow().audit().count(Reason::Full(Bound::TxSlots)),
        1,
        "one unaccepted"
    );
    assert_eq!(net.borrow().pending(1), 2, "two accepted, undelivered");
    assert_eq!(drain(&mut far), 2);
    assert_eq!(
        (net.borrow().pending(1), net.borrow().withheld()),
        (0, 2),
        "two awaiting return"
    );
    assert!(buffer.device_held());
    assert_eq!(near.send(&[datagram]), Ok(0), "every slot is still charged");
    near.reclaim();
    assert_eq!(
        net.borrow().withheld(),
        2,
        "no reclaim returns a withheld reference"
    );
    net.borrow_mut().return_tx(1);
    assert_eq!(net.borrow().reclaimable(0), 1);
    assert_eq!(
        net.borrow().reclaimable(1),
        0,
        "only the sender reclaims it"
    );
    near.reclaim();
    assert_eq!((net.borrow().withheld(), net.borrow().nic_held()), (1, 1));
    assert_eq!(
        near.send(&[datagram]),
        Ok(1),
        "the returned slot admits the next send"
    );
}

/// The scene's receivers, as the containment check judges copies toward
/// each end of link `net`.
fn receivers<'k>(
    rings: &'k [super::auth::KeyRing; 2],
    net: usize,
) -> impl Fn(usize) -> super::rules::Receiver<'k> + 'k {
    move |toward| {
        let direction = if toward == 1 {
            Direction::ClientToOwner
        } else {
            Direction::OwnerToClient
        };
        (&rings[net], PeerId(0), ENDPOINT, direction)
    }
}

/// Each corruption class, applied to real traffic, is rejected by the layer
/// it names, and the GET still completes with its exact bytes; toward the
/// owner, the owner's own drop count shows the rejection. The unsupported
/// class is a containment control, left out of the witnesses. A class whose
/// flip lands in another layer fails the check, and one whose byte lies past
/// the delivered bytes is a harness defect that leaves no damaged copy.
#[test]
fn each_corruption_class_is_rejected_by_its_named_layer() {
    let object = super::owner_tests::payload(1000, 1);
    for (class, kind, toward) in [
        (Some(Corruption::Header), Kind::Data, 0),
        (Some(Corruption::Tag), Kind::Data, 0),
        (Some(Corruption::GetBody), Kind::Data, 0),
        (Some(Corruption::Header), Kind::Get, 1),
        (Some(Corruption::Tag), Kind::Get, 1),
        (Some(Corruption::Unsupported), Kind::Data, 0),
        (None, Kind::Data, 0),
    ] {
        scene(&PRINCIPALS, |mut scene| {
            let effect = class.map_or(Effect::Truncate, Effect::Corrupt);
            let selector = Selector::All(vec![Selector::Kind(kind), Selector::Toward(toward)]);
            let rules = vec![Rule::new(selector, effect).window(0, 1)];
            scene.nets[1]
                .borrow_mut()
                .set_rules(Chain::new(rules, &[], &MANIFEST).unwrap());
            let dropped = scene.owner.report().dropped;
            let (outcome, bytes) = scene.read(1, 1, 0);
            assert_eq!(outcome, Some(super::fetch::Outcome::Complete), "{class:?}");
            assert_eq!(bytes, object, "{class:?}");
            if toward == 1 {
                assert_eq!(
                    scene.owner.report().dropped,
                    dropped + 1,
                    "{class:?}: the owner dropped it"
                );
            }
            let net = scene.nets[1].borrow();
            assert_eq!(net.damaged().len(), 1, "{class:?}");
            let checked = contain(net.damaged(), receivers(&scene.rings, 1)).unwrap();
            let witnessed = usize::from(class.is_none_or(|class| class.layer().is_some()));
            assert_eq!(checked, witnessed, "{class:?}");
            let reason = class.map_or(Reason::Truncated, Reason::Corrupted);
            let record = net
                .audit()
                .records()
                .iter()
                .find(|record| record.reason == reason)
                .copied()
                .unwrap();
            let expected = if class == Some(Corruption::Unsupported) {
                Class::Containment
            } else {
                Class::Injected
            };
            assert_eq!(record.class, expected, "{class:?}");
            assert_eq!(net.verdict(&[]), Verdict::Pass, "{class:?}");
        });
    }
    scene(&PRINCIPALS, |mut scene| {
        let selector = Selector::All(vec![Selector::Kind(Kind::Data), Selector::Toward(0)]);
        let rules = vec![Rule::new(selector, Effect::Corrupt(Corruption::PutBody)).window(0, 1)];
        scene.nets[1]
            .borrow_mut()
            .set_rules(Chain::new(rules, &[], &MANIFEST).unwrap());
        scene.read(1, 1, 0);
        let net = scene.nets[1].borrow();
        assert_eq!(
            contain(net.damaged(), receivers(&scene.rings, 1)),
            Ok(1),
            "a body byte of GET DATA lands in the tag, which covers the body's digest"
        );
        let mut misnamed = net.damaged()[0].clone();
        misnamed.corruption = Some(Corruption::Header);
        assert_eq!(
            contain(&[misnamed], receivers(&scene.rings, 1)),
            Err((Some(Corruption::Header), Some(Layer::Auth))),
            "a copy whose class names another layer than the one that rejects it fails containment"
        );
    });
    scene(&PRINCIPALS, |mut scene| {
        let selector = Selector::All(vec![Selector::Kind(Kind::Ack), Selector::Toward(1)]);
        let rules = vec![Rule::new(selector, Effect::Corrupt(Corruption::GetBody)).window(0, 1)];
        scene.nets[1]
            .borrow_mut()
            .set_rules(Chain::new(rules, &[], &MANIFEST).unwrap());
        scene.read(1, 1, 0);
        let net = scene.nets[1].borrow();
        assert!(net.damaged().is_empty(), "nothing was flipped");
        let Verdict::Fail(record) = net.verdict(&[]) else {
            panic!("a corruption that changed nothing is a harness defect");
        };
        assert_eq!(
            (record.class, record.reason),
            (Class::Harness, Reason::Inapplicable(Corruption::GetBody))
        );
    });
    assert_eq!(Corruption::Header.layer(), Some(Layer::Frame));
}

/// The audit partitions outcomes: a loss fault is injected, a full queue
/// modeled, a premature return a containment control, a foreign peer and an
/// oversize datagram production defects that fail the world unless
/// declared, and an unattributed scripted failure a harness defect that
/// fails it regardless. Device refusals join the audit by origin.
#[test]
fn the_audit_partitions_outcomes_and_fails_on_harness_and_production() {
    let lossy = Faults {
        loss: 100,
        ..Faults::default()
    };
    let arena = test_arena(4, 16384);
    let buffer = arena.acquire(PoolKind::PacketHeader).unwrap();
    let oversize = [0u8; 65];
    let (mut near, mut far, net) = network(1, 64, 0, [Faults::default(), lossy]);
    assert_eq!(near.send(&[plain(b"one")]), Ok(1), "lost on the way");
    assert_eq!(
        far.send(&[plain(b"two"), plain(b"three")]),
        Ok(1),
        "a one-entry queue"
    );
    assert_eq!(drain(&mut near), 1);
    net.borrow_mut().set_tx_release(TxRelease::Premature);
    let retained = Outgoing {
        peer: PeerId(0),
        header: b"r",
        payload: [
            Payload::Retained(buffer.source(0..2).unwrap()),
            Payload::EMPTY,
        ],
    };
    assert_eq!(far.send(&[retained]), Ok(1));
    let classes = |net: &Rc<RefCell<Net<'_>>>| {
        net.borrow()
            .audit()
            .records()
            .iter()
            .map(|record| (record.class, record.reason))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        classes(&net),
        [
            (Class::Injected, Reason::Lost),
            (Class::Modeled, Reason::Full(Bound::Entries)),
            (Class::Containment, Reason::PrematureReturn),
        ]
    );
    assert_eq!(net.borrow().audit().verdict(&[]), Verdict::Pass);
    let foreign = Outgoing {
        peer: PeerId(1),
        ..plain(b"x")
    };
    assert_eq!(
        near.send(&[foreign]),
        Err(DatagramError::Failed { code: None })
    );
    assert_eq!(
        near.send(&[plain(&oversize)]),
        Err(DatagramError::Failed {
            code: Some(libc::EMSGSIZE)
        })
    );
    let held = arena.acquire(PoolKind::PacketHeader).unwrap();
    let capped = held.source(0..2).unwrap();
    // Every reference the source can count, held until the test ends.
    let _holds: Vec<_> = (0..u16::MAX).map(|_| capped.hold().unwrap()).collect();
    let unholdable = Outgoing {
        peer: PeerId(0),
        header: b"c",
        payload: [Payload::Retained(capped), Payload::EMPTY],
    };
    net.borrow_mut().set_tx_release(TxRelease::AtDelivery);
    net.borrow_mut().clear(0);
    assert!(far.send(&[unholdable]).is_err(), "the source is at its cap");
    let tail: Vec<_> = classes(&net).into_iter().skip(3).collect();
    assert_eq!(
        tail,
        [
            (Class::Production, Reason::ForeignPeer),
            (Class::Production, Reason::Oversize),
            (Class::Production, Reason::NotHoldable),
        ]
    );
    let audit = net.borrow().audit().clone();
    let Verdict::Fail(record) = audit.verdict(&[]) else {
        panic!("an undeclared production refusal fails the world");
    };
    assert_eq!(
        (record.class, record.reason),
        (Class::Production, Reason::ForeignPeer)
    );
    let declared = [Reason::ForeignPeer, Reason::Oversize, Reason::NotHoldable];
    assert_eq!(
        audit.verdict(&declared),
        Verdict::Pass,
        "declared, they record as modeled"
    );
    assert_eq!(Audit::judged(&record, &declared), Class::Modeled);
    net.borrow_mut().fail_unattributed();
    assert_eq!(
        near.send(&[plain(b"y")]),
        Err(DatagramError::Failed { code: None })
    );
    let Verdict::Fail(record) = net.borrow().audit().verdict(&declared) else {
        panic!("a harness defect fails the world");
    };
    assert_eq!(
        (record.class, record.reason),
        (Class::Harness, Reason::Unattributed)
    );
    scene(&PRINCIPALS, |mut scene| {
        scene.control.refuse_next(SubmitRefusal {
            reason: RefusalReason::QueueFull,
            code: None,
        });
        scene.read(1, 1, 0);
        let mut audit = Audit::new(MANIFEST.records);
        audit.absorb(&scene.control, 9);
        let scripted = Reason::DeviceRefused(Origin::Script, RefusalReason::QueueFull);
        assert_eq!(audit.count_at(Source::Device(9), scripted), 1);
        assert_eq!(audit.records()[0].class, Class::Injected);
        assert_eq!(audit.verdict(&[]), Verdict::Pass);
    });
}

/// Each device event maps to its class and typed reason: a model refusal
/// of a range is a production defect, any other model refusal is modeled,
/// a scripted refusal, a foreign completion and a lost command are
/// injected, and a duplicate completion is a containment control.
#[test]
fn device_outcomes_carry_their_class_and_typed_reason() {
    let token = CommandToken::from_raw(5);
    let refused = |reason, origin| Event::Refused {
        token,
        reason,
        origin,
    };
    let cases = [
        (
            refused(RefusalReason::InvalidRange, Origin::Model),
            Class::Production,
        ),
        (
            refused(RefusalReason::QueueFull, Origin::Model),
            Class::Modeled,
        ),
        (
            refused(RefusalReason::DeviceGone, Origin::Model),
            Class::Modeled,
        ),
        (
            refused(RefusalReason::InvalidRange, Origin::Script),
            Class::Injected,
        ),
        (Event::Injected(token, Injection::Foreign), Class::Injected),
        (Event::Injected(token, Injection::Old), Class::Injected),
        (Event::Injected(token, Injection::Refused), Class::Injected),
        (
            Event::Injected(token, Injection::OutOfRange),
            Class::Injected,
        ),
        (
            Event::Injected(token, Injection::Duplicate),
            Class::Containment,
        ),
        (Event::Lost(token), Class::Injected),
        (Event::Omitted(token, Omission::Episode), Class::Injected),
        (Event::Omitted(token, Omission::Hostile), Class::Containment),
        (Event::FalseStopped, Class::Containment),
    ];
    for (event, class) in cases {
        let (found, reason) = device_outcome(&event).expect("an audited event");
        assert_eq!(found, class, "{event:?}");
        let expected = match event {
            Event::Refused {
                reason: refusal,
                origin,
                ..
            } => Reason::DeviceRefused(origin, refusal),
            Event::Injected(_, injection) => Reason::DeviceInjected(injection),
            Event::Omitted(_, omission) => Reason::DeviceOmitted(omission),
            Event::FalseStopped => Reason::DeviceFalseStopped,
            _ => Reason::DeviceLost,
        };
        assert_eq!(reason, expected, "{event:?}");
    }
    assert_eq!(device_outcome(&Event::Posted(token)), None);
    let mut audit = Audit::new(8);
    let (class, reason) = device_outcome(&cases[0].0).unwrap();
    audit.note(class, reason, Source::Device(1));
    assert!(
        matches!(audit.verdict(&[]), Verdict::Fail(_)),
        "an undeclared range refusal fails"
    );
    assert_eq!(audit.verdict(&[reason]), Verdict::Pass);
}

/// Rules, taps, captures and audit records stay within the manifest: a
/// chain past its rule or tap bound is refused, captures past their bound
/// stop with the overflow recorded and every earlier capture kept, and an
/// audit past its bound is inconclusive when its kept records pass and
/// fails when a kept or unkept record fails.
#[test]
fn manifest_bounds_end_inconclusive_and_keep_every_witness() {
    let rule = Rule::new(Selector::Any, Effect::Drop);
    let too_many = vec![rule.clone(); MANIFEST.rules + 1];
    assert_eq!(
        Chain::new(too_many, &[], &MANIFEST).err(),
        Some(Bound::Rules)
    );
    let taps: Vec<usize> = vec![0; MANIFEST.taps + 1];
    assert_eq!(
        Chain::new(vec![rule.clone()], &taps, &MANIFEST).err(),
        Some(Bound::Taps)
    );
    assert_eq!(
        Chain::new(vec![rule.clone()], &[2], &MANIFEST).err(),
        Some(Bound::Taps)
    );
    let small = Manifest {
        captures: 3,
        ..MANIFEST
    };
    let mut chain = Chain::new(vec![rule], &[1], &small).unwrap();
    for n in 0..5 {
        chain.decide(&message(Kind::Ack, 1, n), Decision::default());
    }
    let kept: Vec<u64> = chain
        .captures()
        .iter()
        .map(|capture| capture.ordinal)
        .collect();
    assert_eq!(kept, [0, 1, 2], "the first captures stay");
    assert_eq!(chain.overflow(), Some(Bound::Captures));
    let at = Source::Link {
        actor: 0,
        toward: 1,
    };
    let mut audit = Audit::new(2);
    for _ in 0..3 {
        audit.note(Class::Injected, Reason::Lost, at);
    }
    assert_eq!(audit.verdict(&[]), Verdict::Inconclusive(Bound::Records));
    let mut failing = Audit::new(1);
    failing.note(Class::Harness, Reason::Unattributed, at);
    failing.note(Class::Injected, Reason::Lost, at);
    assert!(
        matches!(failing.verdict(&[]), Verdict::Fail(_)),
        "a kept failing record still fails"
    );
    let mut unkept = Audit::new(1);
    unkept.note(Class::Injected, Reason::Lost, at);
    unkept.note(Class::Harness, Reason::Unattributed, at);
    assert!(
        matches!(unkept.verdict(&[]), Verdict::Fail(_)),
        "a failing record past the bound still fails"
    );
    let (mut near, _far, net) = network(4, 8384, 0, [Faults::default(); 2]);
    net.borrow_mut().set_rules(
        Chain::new(
            vec![Rule::new(Selector::Any, Effect::Delay(1))],
            &[1],
            &small,
        )
        .unwrap(),
    );
    for _ in 0..5 {
        let _ = near.send(&[plain(b"t")]);
        net.borrow_mut().clear(1);
    }
    assert_eq!(
        net.borrow().verdict(&[]),
        Verdict::Inconclusive(Bound::Captures),
        "a dropped capture never passes"
    );
    let before = crate::instrument::live_bytes();
    {
        let arena = test_arena(8, 16384);
        let pool = PacketPool::new(&arena, PoolKind::PacketReceive, 1).unwrap();
        let (mut near, mut far, net) = network(4, 8384, 0, [Faults::default(); 2]);
        net.borrow_mut().set_rules(
            Chain::new(
                vec![Rule::new(Selector::Any, Effect::Truncate)],
                &[],
                &MANIFEST,
            )
            .unwrap(),
        );
        for _ in 0..=MANIFEST.captures {
            assert_eq!(near.send(&[plain(b"t")]), Ok(1));
            drain_with_pool(&mut far, &pool);
        }
        let net = net.borrow();
        assert_eq!(
            net.damaged().len(),
            MANIFEST.captures,
            "every earlier damaged copy stays"
        );
        assert_eq!(
            net.verdict(&[]),
            Verdict::Inconclusive(Bound::Damaged),
            "a dropped damaged copy never passes"
        );
    }
    assert_eq!(
        crate::instrument::live_bytes(),
        before,
        "draining damaged copies must not retain receive arenas"
    );
}

/// A link drawing from a chooser that never registered its sites latches
/// the chooser's refusal and leaves each fault off, and the error stays for
/// the run to report.
#[test]
fn a_refused_link_draw_latches_and_draws_nothing() {
    let unregistered: Draws = Rc::new(RefCell::new(Chooser::record(1, &[])));
    let every = Faults {
        loss: 100,
        duplicate: 100,
        reorder: 100,
        delay: 100,
        stale: 100,
        truncate: 100,
        would_block: 100,
        error: 100,
        burst: 100,
        resend_loss: 100,
    };
    let (mut near, mut far, net) = network_drawn(8, 8384, [every; 2], (&unregistered, 0));
    net.borrow_mut().set_tx_release(TxRelease::Delayed(100));
    assert_eq!(near.send(&[plain(b"a"), plain(b"b")]), Ok(2));
    let pool = test_pool(8, 1).unwrap();
    let mut meta = [Received::default(); 4];
    let mut leases: [Option<PacketLease<'_>>; 4] = [None, None, None, None];
    assert_eq!(
        far.receive(&pool, &mut leases, &mut meta),
        Ok(2),
        "nothing lost, duplicated, replayed or delayed"
    );
    let order: Vec<&[u8]> = leases[..2]
        .iter()
        .map(|lease| lease.as_ref().unwrap().bytes())
        .collect();
    assert_eq!(order, [&b"a"[..], &b"b"[..]], "in order");
    assert!(meta.iter().all(|meta| !meta.truncated), "nothing truncated");
    assert_eq!(
        net.borrow().report(1),
        super::link::NetReport {
            delivered: 2,
            ..super::link::NetReport::default()
        },
        "no fault fired, and each lease handed back counted once"
    );
    assert!(net.borrow().draw_error().is_some());
    assert_eq!(unregistered.borrow().decisions(), 0);
}

/// A stale replay repeats the bytes the device read, before the link's
/// corruption of the delivered copy: only the corrupted copy is damaged.
#[test]
fn a_stale_replay_repeats_the_bytes_before_corruption() {
    let stale = Faults {
        stale: 100,
        ..Faults::default()
    };
    let (mut near, mut far, net) = network(8, 8384, 0, [stale; 2]);
    let corrupt = Rule::new(Selector::Any, Effect::Corrupt(Corruption::Unsupported)).window(0, 1);
    net.borrow_mut()
        .set_rules(Chain::new(vec![corrupt], &[], &MANIFEST).unwrap());
    assert_eq!(near.send(&[plain(b"first")]), Ok(1));
    let pool = test_pool(8, 1).unwrap();
    let mut meta = [Received::default(); 4];
    let mut leases: [Option<PacketLease<'_>>; 4] = [None, None, None, None];
    assert_eq!(far.receive(&pool, &mut leases[..1], &mut meta[..1]), Ok(1));
    assert_ne!(
        leases[0].as_ref().unwrap().bytes(),
        b"first",
        "the delivered copy is corrupted"
    );
    assert_eq!(near.send(&[plain(b"second")]), Ok(1));
    assert_eq!(far.receive(&pool, &mut leases[1..], &mut meta[1..]), Ok(2));
    let replayed: Vec<&[u8]> = leases[1..3]
        .iter()
        .map(|lease| lease.as_ref().unwrap().bytes())
        .collect();
    assert!(
        replayed.contains(&&b"first"[..]),
        "the replay carries the read bytes: {replayed:?}"
    );
    assert_eq!(net.borrow().damaged().len(), 1);
}

/// A device log that dropped events to make room leaves the audit
/// inconclusive: no dropped event can pass unseen.
#[test]
fn an_evicted_device_log_is_inconclusive() {
    scene(&PRINCIPALS, |mut scene| {
        while scene.control.evicted() == 0 {
            scene.read(1, 1, 0);
        }
        let mut audit = Audit::new(MANIFEST.records);
        audit.absorb(&scene.control, 0);
        assert_eq!(audit.verdict(&[]), Verdict::Inconclusive(Bound::Records));
    });
}

/// Absorbing the device log after every action keeps each event exactly
/// once however many events the bounded log evicts, while an audit that
/// absorbs only after the eviction is inconclusive. So are an audit whose
/// cursor the evictions passed and one whose cursor is past the log's end,
/// which the call moves back to the end.
#[test]
fn absorbing_after_every_action_outlives_the_device_log() {
    scene(&PRINCIPALS, |mut scene| {
        let scripted = Reason::DeviceRefused(Origin::Script, RefusalReason::QueueFull);
        let refusal = SubmitRefusal {
            reason: RefusalReason::QueueFull,
            code: None,
        };
        let mut audit = Audit::new(MANIFEST.records);
        let mut seen = 0;
        scene.control.refuse_next(refusal);
        scene.read(1, 1, 0);
        audit.absorb_since(&scene.control, 0, &mut seen);
        let mut lagging = audit.clone();
        let mut lagging_seen = seen;
        assert!(lagging_seen > 0);
        while scene.control.evicted() <= lagging_seen {
            scene.read(1, 1, 0);
            audit.absorb_since(&scene.control, 0, &mut seen);
        }
        scene.control.refuse_next(refusal);
        scene.read(1, 1, 0);
        audit.absorb_since(&scene.control, 0, &mut seen);
        assert_eq!(seen, scene.control.logged());
        assert_eq!(audit.count_at(Source::Device(0), scripted), 2);
        audit.absorb_since(&scene.control, 0, &mut seen);
        assert_eq!(audit.count_at(Source::Device(0), scripted), 2);
        assert_eq!(audit.verdict(&[]), Verdict::Pass);
        lagging.absorb_since(&scene.control, 0, &mut lagging_seen);
        assert_eq!(lagging.verdict(&[]), Verdict::Inconclusive(Bound::Records));
        let mut late = Audit::new(MANIFEST.records);
        late.absorb_since(&scene.control, 0, &mut 0);
        assert_eq!(late.verdict(&[]), Verdict::Inconclusive(Bound::Records));
        let mut ahead = Audit::new(MANIFEST.records);
        let mut past = scene.control.logged() + 1;
        ahead.absorb_since(&scene.control, 0, &mut past);
        assert_eq!(ahead.verdict(&[]), Verdict::Inconclusive(Bound::Records));
        assert_eq!(past, scene.control.logged());
    });
}

/// Under the premature-return control a source changed after its reference
/// returned alters the delivered datagram, which audits as a containment
/// control and leaves the verdict passing.
#[test]
fn a_premature_return_alteration_is_a_containment_control() {
    let arena = test_arena(4, 16384);
    let mut buffer = arena.acquire(PoolKind::PacketHeader).unwrap();
    buffer.bytes_mut()[..4].copy_from_slice(b"abcd");
    let (mut near, mut far, net) = network(8, 8384, 0, [Faults::default(); 2]);
    net.borrow_mut().set_tx_release(TxRelease::Premature);
    {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: b"h",
            payload: [
                Payload::Retained(buffer.source(0..4).unwrap()),
                Payload::EMPTY,
            ],
        };
        assert_eq!(near.send(&[datagram]), Ok(1));
    }
    buffer.bytes_mut()[0] = b'z';
    assert_eq!(drain(&mut far), 1);
    let net = net.borrow();
    let altered: Vec<_> = net
        .audit()
        .records()
        .iter()
        .filter(|record| record.reason == Reason::Altered)
        .collect();
    assert_eq!(altered.len(), 1);
    assert_eq!(altered[0].class, Class::Containment);
    assert_eq!(net.report(1).altered, 1);
    assert_eq!(net.verdict(&[]), Verdict::Pass);
}

#[test]
fn a_duplicate_that_exhausts_the_source_count_is_an_injected_refusal() {
    let arena = test_arena(4, 16384);
    let buffer = arena.acquire(PoolKind::PacketHeader).unwrap();
    let source = buffer.source(0..4).unwrap();
    // Every reference but one, held until the test ends: the original fits, its duplicate does not.
    let _holds: Vec<_> = (1..u16::MAX).map(|_| source.hold().unwrap()).collect();
    let datagram = Outgoing {
        peer: PeerId(0),
        header: b"hdr",
        payload: [Payload::Retained(source), Payload::EMPTY],
    };
    let (mut near, _far, net) = network(8, 8384, 0, [Faults::default(); 2]);
    net.borrow_mut().set_rules(
        Chain::new(
            vec![Rule::new(Selector::Any, Effect::Duplicate)],
            &[],
            &MANIFEST,
        )
        .unwrap(),
    );
    assert!(near.send(&[datagram]).is_err());
    let net = net.borrow();
    assert_eq!(net.nic_held(), 0, "the first copy's reference returned");
    let refusals: Vec<_> = net
        .audit()
        .records()
        .iter()
        .filter(|record| record.reason == Reason::NotHoldable)
        .map(|record| record.class)
        .collect();
    assert_eq!(refusals, [Class::Injected]);
    assert_eq!(net.verdict(&[]), Verdict::Pass);
}

#[test]
fn an_alteration_is_classified_by_its_send_time_release_mode() {
    let arena = test_arena(4, 16384);
    let mut buffer = arena.acquire(PoolKind::PacketHeader).unwrap();
    buffer.bytes_mut()[..4].copy_from_slice(b"abcd");
    let (mut near, mut far, net) = network(8, 8384, 0, [Faults::default(); 2]);
    net.borrow_mut().set_tx_release(TxRelease::Premature);
    {
        let datagram = Outgoing {
            peer: PeerId(0),
            header: b"h",
            payload: [
                Payload::Retained(buffer.source(0..4).unwrap()),
                Payload::EMPTY,
            ],
        };
        assert_eq!(near.send(&[datagram]), Ok(1));
    }
    net.borrow_mut().set_tx_release(TxRelease::AtDelivery);
    buffer.bytes_mut()[0] = b'z';
    assert_eq!(drain(&mut far), 1);
    let net = net.borrow();
    let altered: Vec<_> = net
        .audit()
        .records()
        .iter()
        .filter(|record| record.reason == Reason::Altered)
        .collect();
    assert_eq!(altered.len(), 1);
    assert_eq!(altered[0].class, Class::Containment);
    assert_eq!(net.verdict(&[]), Verdict::Pass);
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    an_evicted_device_log_is_inconclusive,
    each_corruption_class_is_rejected_by_its_named_layer,
);

/// Retiring keeps every harness and production-defect record, drops the
/// passing ones read at or after the cursor, keeps the failing ones before
/// it, and returns the count that remains; the verdict still fails.
#[test]
fn retiring_an_audit_keeps_its_failing_records() {
    let at = Source::Link {
        actor: 0,
        toward: 1,
    };
    let mut audit = Audit::new(8);
    audit.note(Class::Injected, Reason::Lost, at);
    audit.note(Class::Production, Reason::ForeignPeer, at);
    audit.note(Class::Harness, Reason::Unattributed, at);
    audit.note(Class::Injected, Reason::Duplicated, at);
    assert_eq!(audit.retire(0), 2);
    let classes: Vec<Class> = audit.records().iter().map(|record| record.class).collect();
    assert_eq!(classes, [Class::Production, Class::Harness]);
    assert!(matches!(audit.verdict(&[]), Verdict::Fail(_)));
    audit.note(Class::Modeled, Reason::Lost, at);
    assert_eq!(audit.retire(2), 2);
    assert_eq!(audit.records().len(), 2);
    assert!(matches!(audit.verdict(&[]), Verdict::Fail(_)));
}

/// A failing record noted past the bound stays the verdict's first failure
/// after a retire makes room: the retire moves it into the kept records
/// ahead of later ones.
#[test]
fn retiring_keeps_the_first_failure_noted_past_the_bound_first() {
    let at = Source::Link {
        actor: 0,
        toward: 1,
    };
    let mut audit = Audit::new(2);
    audit.note(Class::Injected, Reason::Lost, at);
    audit.note(Class::Injected, Reason::Duplicated, at);
    audit.note(Class::Production, Reason::ForeignPeer, at);
    assert_eq!(audit.retire(0), 1);
    audit.note(Class::Harness, Reason::Unattributed, at);
    let Verdict::Fail(first) = audit.verdict(&[]) else {
        panic!("a failing record was noted");
    };
    assert_eq!(
        (first.class, first.reason),
        (Class::Production, Reason::ForeignPeer)
    );
    assert_eq!(audit.records().len(), 2);
}

/// `delivered` counts each lease a receive hands back toward its end and
/// nothing else: a duplicate and a stale copy count as their own
/// deliveries, a truncated datagram counts once, an injected datagram
/// counts, and a lost datagram and one the ring missed count none.
#[test]
fn delivered_counts_each_lease_a_receive_hands_back() {
    let pool = test_pool(16, 1).unwrap();
    let receive = |far: &mut super::link::LinkEnd<'_>| {
        let mut meta = [Received::default(); 8];
        let mut leases: [Option<PacketLease<'_>>; 8] = Default::default();
        let got = far.receive(&pool, &mut leases, &mut meta).unwrap();
        assert_eq!(leases.iter().filter(|lease| lease.is_some()).count(), got);
        got as u64
    };
    for (faults, sent, expected) in [
        (Faults::default(), 2, 2),
        (
            Faults {
                duplicate: 100,
                ..Faults::default()
            },
            1,
            2,
        ),
        (
            Faults {
                stale: 100,
                ..Faults::default()
            },
            2,
            3,
        ),
        (
            Faults {
                truncate: 100,
                ..Faults::default()
            },
            1,
            1,
        ),
        (
            Faults {
                loss: 100,
                ..Faults::default()
            },
            2,
            0,
        ),
    ] {
        let (mut near, mut far, net) = network(8, 8384, 5, [Faults::default(), faults]);
        let mut got = 0;
        for (at, bytes) in [b"a", b"b"].into_iter().take(sent).enumerate() {
            assert_eq!(near.send(&[plain(bytes)]), Ok(1), "{faults:?}");
            for turn in 0..4 {
                net.borrow_mut().advance(4 * at as u64 + turn + 1);
                got += receive(&mut far);
            }
        }
        let report = net.borrow().report(1);
        assert_eq!((got, report.delivered), (expected, expected), "{faults:?}");
    }
    let (_, mut far, net) = network(8, 8384, 5, [Faults::default(); 2]);
    net.borrow_mut().inject(1, b"injected");
    assert_eq!(receive(&mut far), 1);
    assert_eq!(net.borrow().report(1).delivered, 1, "an injected datagram");
    // A ring of one posted buffer misses the second due datagram.
    let (_, mut far, net) = network(8, 8384, 5, [Faults::default(); 2]);
    far.set_ring(1);
    net.borrow_mut().inject(1, b"first");
    net.borrow_mut().inject(1, b"second");
    assert_eq!(receive(&mut far), 1);
    let report = net.borrow().report(1);
    assert_eq!(
        (report.delivered, report.missed),
        (1, 1),
        "a missed datagram"
    );
}

/// Each datagram's fate in carried order toward end 1 of a link that
/// carried `sent` datagrams that way and no other: `None` for one that
/// arrived, else the reason the link dropped it.
fn fates(net: &Net<'_>, sent: u64) -> Vec<Option<Reason>> {
    let (deliveries, overflow) = net.deliveries();
    assert!(!overflow);
    let arrived: std::collections::BTreeSet<u64> =
        deliveries.iter().map(|delivery| delivery.ordinal).collect();
    let mut dropped = net.audit().records().iter().map(|record| record.reason);
    let fates: Vec<_> = (0..sent)
        .map(|ordinal| {
            (!arrived.contains(&ordinal)).then(|| dropped.next().expect("an audited drop"))
        })
        .collect();
    assert_eq!(dropped.next(), None, "every drop is one carried datagram's");
    fates
}

/// With `burst` above zero, a datagram whose committed decision is the loss
/// fault draws a run of 0 to `burst`, and that many later datagrams start
/// dropped as a burst with no loss draw: every `LostBurst` follows a `Lost`
/// in carried order, in runs of at most `burst` that reach `burst`, and the
/// run draws one decision for each datagram outside a run and one for each
/// loss. A rule that delivers a datagram of a run clears its
/// drop, and the datagram still takes its place in the run; a loss a rule
/// delivers draws no run; and a change of the direction's faults ends a
/// run. With `burst` at zero the same root draws one decision per datagram
/// and drops no burst.
#[test]
fn a_loss_hit_takes_a_drawn_run_of_later_datagrams() {
    const SENT: u64 = 400;
    const BURST: u32 = 3;
    let lossy = |burst| Faults {
        loss: 15,
        burst,
        ..Faults::default()
    };
    // The run from root 61, with `rule` set and the faults set again after
    // ordinal `reset`.
    let pool = test_pool(8, 1).unwrap();
    let run = |burst, rule: Option<Rule>, reset: Option<u64>| {
        let draws = recorder(61);
        let (mut near, mut far, net) = network_drawn(16, 8384, [lossy(burst); 2], (&draws, 0));
        if let Some(rule) = rule {
            net.borrow_mut()
                .set_rules(Chain::new(vec![rule], &[], &MANIFEST).unwrap());
        }
        for turn in 0..SENT {
            net.borrow_mut().advance(turn);
            assert_eq!(near.send(&[plain(&turn.to_le_bytes())]), Ok(1));
            drain_with_pool(&mut far, &pool);
            if reset == Some(turn) {
                net.borrow_mut().set_faults(1, lossy(burst));
            }
        }
        let fates = fates(&net.borrow(), SENT);
        let decisions = draws.borrow().decisions();
        drop((near, far, net));
        let tape = Rc::try_unwrap(draws)
            .unwrap()
            .into_inner()
            .finish()
            .unwrap();
        (fates, decisions, tape)
    };
    let burst = Some(Reason::LostBurst);
    let (fates, decisions, tape) = run(BURST, None, None);
    assert_ne!(fates[0], burst);
    for pair in fates.windows(2) {
        if pair[1] == burst {
            assert!(
                matches!(pair[0], Some(Reason::Lost | Reason::LostBurst)),
                "a burst follows a loss: {pair:?}"
            );
        }
    }
    let runs: Vec<usize> = fates
        .split(|fate| *fate != burst)
        .map(<[_]>::len)
        .filter(|&len| len > 0)
        .collect();
    assert!(runs.len() > 1, "the root draws runs: {runs:?}");
    assert_eq!(runs.iter().max(), Some(&(BURST as usize)), "{runs:?}");
    // `BURST + 1` later datagrams leave room for a longest run and the
    // datagram that marks its end.
    let drawn: std::collections::BTreeSet<usize> = fates
        .iter()
        .enumerate()
        .filter(|&(at, fate)| *fate == Some(Reason::Lost) && at + BURST as usize + 1 < fates.len())
        .map(|(at, _)| {
            fates[at + 1..]
                .iter()
                .take_while(|fate| **fate == burst)
                .count()
        })
        .collect();
    assert_eq!(
        drawn,
        (0..=BURST as usize).collect(),
        "a loss draws each run from 0 to burst"
    );
    let count = |reason| fates.iter().filter(|fate| **fate == Some(reason)).count() as u64;
    let (lost, bursts) = (count(Reason::Lost), count(Reason::LostBurst));
    assert_eq!(
        decisions,
        (SENT - bursts) + lost,
        "a loss draw per datagram outside a run, and a burst draw per loss"
    );
    // Deliver the first datagram of the first run: its drop clears and it
    // still takes its place, so every other fate and the tape stay.
    let first = fates.iter().position(|fate| *fate == burst).expect("a run");
    let deliver = Rule::new(Selector::Any, Effect::Deliver).window(first as u32, 1);
    let (delivered, _, kept) = run(BURST, Some(deliver), None);
    let mut expected = fates.clone();
    expected[first] = None;
    assert_eq!(delivered, expected, "only the delivered datagram changed");
    assert_eq!(kept, tape, "the run took the delivered datagram");
    // Deliver the loss that drew that run: a run follows a committed loss,
    // so the datagram after it is no burst.
    let loss = first - 1;
    assert_eq!(fates[loss], Some(Reason::Lost));
    let deliver = Rule::new(Selector::Any, Effect::Deliver).window(loss as u32, 1);
    let (unarmed, _, _) = run(BURST, Some(deliver), None);
    assert_eq!(unarmed[loss], None);
    assert_ne!(unarmed[first], burst, "a delivered loss arms no run");
    let (reset, _, _) = run(BURST, None, Some(loss as u64));
    assert_eq!(reset[..first], fates[..first]);
    assert_ne!(reset[first], burst, "setting the faults ended the run");
    // With `duplicate: 100`, each datagram consumes one extra decision,
    // inside a run or not.
    let draws = recorder(61);
    let doubled = Faults {
        duplicate: 100,
        ..lossy(BURST)
    };
    let (mut near, mut far, net) = network_drawn(16, 8384, [doubled; 2], (&draws, 0));
    for turn in 0..SENT {
        net.borrow_mut().advance(turn);
        assert_eq!(near.send(&[plain(&turn.to_le_bytes())]), Ok(1));
        drain_with_pool(&mut far, &pool);
    }
    assert_eq!(
        draws.borrow().decisions(),
        decisions + SENT,
        "a datagram inside a run makes the duplicate draw"
    );
    // Traffic toward end 0 between the datagrams toward end 1 leaves their
    // loss runs, recorded reasons and total decision count unchanged.
    let draws = recorder(61);
    let faults = [Faults::default(), lossy(BURST)];
    let (mut near, mut far, net) = network_drawn(16, 8384, faults, (&draws, 0));
    for turn in 0..SENT {
        net.borrow_mut().advance(turn);
        assert_eq!(near.send(&[plain(&turn.to_le_bytes())]), Ok(1));
        assert_eq!(far.send(&[plain(&turn.to_le_bytes())]), Ok(1));
        assert_eq!(
            drain_with_pool(&mut near, &pool),
            1,
            "a datagram toward end 0 arrives"
        );
        drain_with_pool(&mut far, &pool);
    }
    let records = net.borrow().audit().records().to_vec();
    let reasons: Vec<Reason> = records.iter().map(|record| record.reason).collect();
    let expected: Vec<Reason> = fates.iter().flatten().copied().collect();
    assert_eq!(reasons, expected, "each direction keeps its own run");
    assert_eq!(draws.borrow().decisions(), decisions);
    assert!(
        records
            .iter()
            .filter(|record| record.reason == Reason::LostBurst)
            .all(|record| record.class == Class::Injected),
        "a burst drop is injected"
    );
    let (alone, decisions, _) = run(0, None, None);
    assert!(!alone.contains(&burst));
    assert_eq!(decisions, SENT, "one loss draw per datagram");
    // Fed draws fix each run's length: a loss hit with a run of 2, a miss,
    // a loss hit with a run of 0, and a miss.
    let fed = Rc::new(RefCell::new(Chooser::fed(
        &sites(0),
        vec![0, 2, 99, 0, 0, 99],
    )));
    let (mut near, mut far, net) = network_drawn(16, 8384, [lossy(BURST); 2], (&fed, 0));
    for turn in 0..6u64 {
        assert_eq!(near.send(&[plain(&turn.to_le_bytes())]), Ok(1));
        drain_with_pool(&mut far, &pool);
    }
    let lost = Some(Reason::Lost);
    assert_eq!(
        super::link_tests::fates(&net.borrow(), 6),
        [lost, burst, burst, None, lost, None],
        "each run takes the length its draw selected"
    );
    assert_eq!(fed.borrow().decisions(), 6);
    assert_eq!(net.borrow().draw_error(), None);
}

/// At 100 percent resend loss, distinct frames all arrive, as does an
/// unparsed datagram sent twice, and a frame repeated toward the same end
/// drops as `LostResend`, with one resend draw for each repeat. The window
/// holds exactly the keys of the last [`MANIFEST`]`.captures` datagrams: the
/// oldest of them still drops, and the one before it arrives as a first
/// send. A resend the loss fault already dropped makes no resend draw, a
/// rule that delivers a resend clears its drop, and a datagram the loss
/// fault dropped still enters the window.
#[test]
fn resend_loss_drops_only_datagrams_the_link_carried_before() {
    let faults = |loss| Faults {
        loss,
        resend_loss: 100,
        ..Faults::default()
    };
    let draws = recorder(5);
    let (mut near, mut far, net) = network_drawn(16, 8384, [faults(0); 2], (&draws, 0));
    let pool = test_pool(8, 1).unwrap();
    let mut turn = 0;
    let mut send = |bytes: &[u8]| {
        net.borrow_mut().advance(turn);
        turn += 1;
        assert_eq!(near.send(&[plain(bytes)]), Ok(1));
        drain_with_pool(&mut far, &pool)
    };
    for request in 1..=20 {
        assert_eq!(
            send(&get_frame(request)),
            1,
            "frame {request} is a first send"
        );
    }
    assert_eq!(send(b"unparsed"), 1);
    assert_eq!(send(b"unparsed"), 1, "an unparsed datagram is a first send");
    assert_eq!(send(&get_frame(5)), 0, "a resend drops");
    assert_eq!(draws.borrow().decisions(), 1, "one draw, for the resend");
    let captures = MANIFEST.captures as u64;
    for request in 100..100 + captures {
        assert_eq!(send(&get_frame(request)), 1, "frame {request}");
    }
    // The window now holds frames 100 on; the repeat of frame 5 just before
    // them left it, and sending 5 again pushes frame 100 out.
    assert_eq!(send(&get_frame(5)), 1, "a frame the window forgot arrives");
    assert_eq!(send(&get_frame(101)), 0, "the oldest key kept drops");
    assert_eq!(draws.borrow().decisions(), 2);
    // End 1 already tracks frame 101; end 0 treats frame 101 as a first send.
    assert_eq!(far.send(&[plain(&get_frame(101))]), Ok(1));
    assert_eq!(
        drain_with_pool(&mut near, &pool),
        1,
        "each end has its window"
    );
    assert_eq!(far.send(&[plain(&get_frame(101))]), Ok(1));
    assert_eq!(drain_with_pool(&mut near, &pool), 0);
    {
        let net = net.borrow();
        let source = |toward| Source::Link { actor: 0, toward };
        assert_eq!(net.audit().count_at(source(1), Reason::LostResend), 2);
        assert_eq!(net.audit().count_at(source(0), Reason::LostResend), 1);
        assert_eq!(net.report(1).lost, 2, "the report counts each resend lost");
        assert!(
            net.audit()
                .records()
                .iter()
                .all(|record| record.class == Class::Injected),
            "a resend drop is injected"
        );
    }
    // `send` returns `Some(reason)` on drop and `None` on arrival.
    let mut send = |net: &Rc<RefCell<Net<'_>>>, request| {
        let before = net.borrow().audit().records().len();
        assert_eq!(near.send(&[plain(&get_frame(request))]), Ok(1));
        let arrived = drain_with_pool(&mut far, &pool);
        let net = net.borrow();
        let added = &net.audit().records()[before..];
        assert_eq!(arrived + added.len(), 1, "the frame arrived or dropped");
        added.first().map(|record| record.reason)
    };
    net.borrow_mut().set_faults(1, faults(100));
    assert_eq!(send(&net, 9000), Some(Reason::Lost));
    let before = draws.borrow().decisions();
    assert_eq!(send(&net, 101), Some(Reason::Lost));
    assert_eq!(
        draws.borrow().decisions() - before,
        1,
        "a lost resend draws only the loss"
    );
    net.borrow_mut().set_faults(1, faults(0));
    let deliver = Rule::new(Selector::Any, Effect::Deliver).window(0, 1);
    net.borrow_mut()
        .set_rules(Chain::new(vec![deliver], &[], &MANIFEST).unwrap());
    let before = draws.borrow().decisions();
    assert_eq!(send(&net, 101), None, "the rule delivered the resend");
    assert_eq!(
        draws.borrow().decisions() - before,
        1,
        "the resend draw ran before the rule cleared it"
    );
    assert_eq!(send(&net, 101), Some(Reason::LostResend));
    assert_eq!(
        send(&net, 9000),
        Some(Reason::LostResend),
        "a datagram the loss fault dropped entered the window"
    );
}

/// The resend key is a frame's kind, session epoch, request, allocation,
/// fragment index and offset: frames that differ in any one of them have
/// distinct keys, and frames that differ only in other fields share one.
#[test]
fn the_resend_key_is_six_decoded_fields() {
    use super::link::ResendKey;
    let base = super::serve::header(Kind::Get, 7, [0x5A; 32]);
    let key = ResendKey::of(&base);
    let same = super::frame::Header {
        principal: 1,
        key_epoch: 1,
        owner_nonce: [1; 16],
        client_nonce: [1; 16],
        sequence: 4,
        total: 1,
        metadata_len: 1,
        body_len: 1,
        count: 1,
        datagram_len: 1,
        grant: 9,
        status: 1,
        remaining_ms: 3,
        key: [1; 32],
        tag: [1; 16],
        ..base
    };
    assert_eq!(
        ResendKey::of(&same),
        key,
        "the fifteen other fields leave the key"
    );
    let distinct = [
        super::frame::Header {
            kind: Kind::Cancel,
            ..base
        },
        super::frame::Header { epoch: 1, ..base },
        super::frame::Header { request: 8, ..base },
        super::frame::Header {
            allocation: 1,
            ..base
        },
        super::frame::Header { index: 1, ..base },
        super::frame::Header { offset: 1, ..base },
    ];
    for header in distinct {
        assert_ne!(ResendKey::of(&header), key, "{header:?}");
    }
}

/// Each draw owns a fixed pair of site numbers, one per end, and the link
/// registers exactly those sites.
#[test]
fn each_draw_keeps_its_site_numbers() {
    use super::link::{Draw, site};
    let numbers = [
        (Draw::Loss, 2),
        (Draw::Duplicate, 4),
        (Draw::Reorder, 6),
        (Draw::ReorderAt, 8),
        (Draw::Delay, 10),
        (Draw::Stale, 12),
        (Draw::Truncate, 14),
        (Draw::WouldBlock, 16),
        (Draw::Error, 18),
        (Draw::Release, 20),
        (Draw::Burst, 22),
        (Draw::Resend, 24),
    ];
    for (draw, number) in numbers {
        let pair = [0, 1].map(|toward| site(0, draw, toward).site);
        assert_eq!(pair, [number, number + 1], "{draw:?}");
    }
    let registered: Vec<u16> = sites(0).iter().map(|site| site.site).collect();
    assert_eq!(registered, (2..26).collect::<Vec<u16>>());
}

/// A refused burst or resend draw latches its own site and leaves its fault
/// off: with the burst site refused, a committed loss arms no run, so the
/// next datagram makes the loss draw; with the resend site refused, a
/// repeated frame arrives.
#[test]
fn a_refused_burst_or_resend_draw_leaves_its_fault_off() {
    use super::link::{Draw, site};
    let refusing = |refused: Draw| -> Draws {
        let registered: Vec<_> = sites(0)
            .into_iter()
            .filter(|registered| *registered != site(0, refused, 1))
            .collect();
        Rc::new(RefCell::new(Chooser::record(1, &registered)))
    };
    let unregistered = |draw| {
        Some(ChoiceError::HarnessDefect(Defect::Unregistered(site(
            0, draw, 1,
        ))))
    };
    let lossy = Faults {
        loss: 100,
        burst: 3,
        ..Faults::default()
    };
    let draws = refusing(Draw::Burst);
    let (mut near, mut far, net) = network_drawn(8, 8384, [lossy; 2], (&draws, 0));
    for turn in 0..2u8 {
        assert_eq!(near.send(&[plain(&[turn])]), Ok(1));
    }
    assert_eq!(drain(&mut far), 0);
    let reasons: Vec<Reason> = net
        .borrow()
        .audit()
        .records()
        .iter()
        .map(|record| record.reason)
        .collect();
    assert_eq!(
        reasons,
        [Reason::Lost; 2],
        "a refused burst draw arms no run"
    );
    assert_eq!(net.borrow().draw_error(), unregistered(Draw::Burst));
    let resend = Faults {
        resend_loss: 100,
        ..Faults::default()
    };
    let draws = refusing(Draw::Resend);
    let (mut near, mut far, net) = network_drawn(8, 8384, [resend; 2], (&draws, 0));
    for _ in 0..2 {
        assert_eq!(near.send(&[plain(&get_frame(1))]), Ok(1));
    }
    assert_eq!(drain(&mut far), 2, "a refused resend draw drops nothing");
    assert_eq!(net.borrow().draw_error(), unregistered(Draw::Resend));
}

/// The largest burst setting draws its run below `2^32` at the burst site:
/// a fed selection of `u32::MAX` arms a run that drops the next datagram as
/// a burst, and the tape records that selection and replays it.
#[test]
fn the_largest_burst_draws_its_run() {
    let faults = Faults {
        loss: 100,
        burst: u32::MAX,
        ..Faults::default()
    };
    let fed = Rc::new(RefCell::new(Chooser::fed(
        &sites(0),
        vec![0, 255, 255, 255, 255],
    )));
    let (mut near, mut far, net) = network_drawn(8, 8384, [faults; 2], (&fed, 0));
    for _ in 0..2 {
        assert_eq!(near.send(&[plain(b"a")]), Ok(1));
    }
    assert_eq!(drain(&mut far), 0, "the run drops the second datagram");
    let reasons: Vec<Reason> = net
        .borrow()
        .audit()
        .records()
        .iter()
        .map(|record| record.reason)
        .collect();
    assert_eq!(reasons, [Reason::Lost, Reason::LostBurst]);
    assert_eq!(
        fed.borrow().decisions(),
        2,
        "the loss draw and the burst draw"
    );
    assert_eq!(net.borrow().draw_error(), None);
    drop((near, far, net));
    let tape = Rc::try_unwrap(fed).unwrap().into_inner().finish().unwrap();
    let recorded = crate::sim::choice::draws(&tape).expect("a well-formed tape");
    let selections: Vec<Vec<u8>> = recorded.into_iter().map(|draw| draw.bytes).collect();
    assert_eq!(
        selections,
        [vec![0], vec![255; 4]],
        "the burst draw selected u32::MAX below 2^32"
    );
    let replayed = Rc::new(RefCell::new(Chooser::replay(&sites(0), tape)));
    let (mut near, mut far, net) = network_drawn(8, 8384, [faults; 2], (&replayed, 0));
    for _ in 0..2 {
        assert_eq!(near.send(&[plain(b"a")]), Ok(1));
    }
    assert_eq!(drain(&mut far), 0);
    assert_eq!(net.borrow().draw_error(), None, "the tape replays the run");
    drop((near, far, net));
    Rc::try_unwrap(replayed)
        .unwrap()
        .into_inner()
        .finish()
        .expect("the replay read the whole tape");
}

/// Every datagram that reaches the draws takes a window slot at every
/// setting, an unparsed one included: a frame repeated after
/// [`MANIFEST`]`.captures` less one unparsed datagrams drops, and one
/// repeated after that many arrives. Frames carried while resend loss is
/// zero stay in the window, and a key the window forgot during a zero
/// interval arrives once the setting is above zero again.
#[test]
fn the_resend_window_counts_every_datagram_at_every_setting() {
    let resend = |resend_loss| Faults {
        resend_loss,
        ..Faults::default()
    };
    let draws = recorder(5);
    let (mut near, mut far, net) = network_drawn(16, 8384, [resend(100); 2], (&draws, 0));
    let pool = test_pool(8, 1).unwrap();
    let mut send = |bytes: &[u8]| {
        assert_eq!(near.send(&[plain(bytes)]), Ok(1));
        drain_with_pool(&mut far, &pool)
    };
    let captures = MANIFEST.captures as u64;
    assert_eq!(send(&get_frame(1)), 1);
    for n in 1..captures {
        assert_eq!(send(&n.to_le_bytes()), 1, "an unparsed datagram arrives");
    }
    assert_eq!(
        send(&get_frame(1)),
        0,
        "the oldest slot still holds frame 1"
    );
    assert_eq!(draws.borrow().decisions(), 1);
    assert_eq!(send(&get_frame(2)), 1);
    for n in 0..captures {
        assert_eq!(send(&n.to_le_bytes()), 1);
    }
    assert_eq!(
        send(&get_frame(2)),
        1,
        "unparsed datagrams pushed frame 2 out"
    );
    assert_eq!(draws.borrow().decisions(), 1);
    // Frame 3 before a zero interval and frame 4 inside it.
    assert_eq!(send(&get_frame(3)), 1);
    net.borrow_mut().set_faults(1, resend(0));
    assert_eq!(send(&get_frame(4)), 1);
    assert_eq!(draws.borrow().decisions(), 1, "zero draws nothing");
    net.borrow_mut().set_faults(1, resend(100));
    assert_eq!(send(&get_frame(3)), 0, "the window kept frame 3");
    assert_eq!(send(&get_frame(4)), 0, "the zero setting tracked frame 4");
    assert_eq!(draws.borrow().decisions(), 3);
    // Frame 5, then 4,096 datagrams at zero, the last of them frame 6.
    assert_eq!(send(&get_frame(5)), 1);
    net.borrow_mut().set_faults(1, resend(0));
    for n in 1..captures {
        assert_eq!(send(&n.to_le_bytes()), 1);
    }
    assert_eq!(send(&get_frame(6)), 1);
    net.borrow_mut().set_faults(1, resend(100));
    assert_eq!(
        send(&get_frame(5)),
        1,
        "the zero interval pushed frame 5 out"
    );
    assert_eq!(draws.borrow().decisions(), 3);
    assert_eq!(send(&get_frame(6)), 0, "a frame carried at zero matches");
    assert_eq!(draws.borrow().decisions(), 4);
}

/// Burst and resend loss together, every draw fed: a repeat inside a run
/// drops as a burst and makes no resend draw, a committed resend drop arms
/// no run, and a datagram injected inside a run leaves the run and the
/// window as they were.
#[test]
fn a_burst_and_a_resend_loss_keep_their_own_draws() {
    let faults = Faults {
        loss: 50,
        burst: 3,
        resend_loss: 100,
        ..Faults::default()
    };
    // A loss hit and a run of 2; a loss miss and a resend hit; two loss
    // misses.
    let feed = vec![0, 2, 99, 0, 99, 99];
    let fed = Rc::new(RefCell::new(Chooser::fed(&sites(0), feed)));
    let (mut near, mut far, net) = network_drawn(8, 8384, [faults; 2], (&fed, 0));
    let pool = test_pool(8, 1).unwrap();
    let mut send = |request| {
        assert_eq!(near.send(&[plain(&get_frame(request))]), Ok(1));
        drain_with_pool(&mut far, &pool)
    };
    assert_eq!(send(1), 0, "a loss arms a run of 2");
    net.borrow_mut().inject(1, &get_frame(4));
    assert_eq!(send(1), 1, "the injected frame arrives and frame 1 drops");
    assert_eq!(send(2), 0, "the run takes the next datagram");
    assert_eq!(send(2), 0, "a resend drops");
    assert_eq!(send(3), 1, "a resend drop arms no run");
    assert_eq!(send(4), 1, "the injected frame took no window slot");
    let reasons: Vec<Reason> = net
        .borrow()
        .audit()
        .records()
        .iter()
        .map(|record| record.reason)
        .collect();
    assert_eq!(
        reasons,
        [
            Reason::Lost,
            Reason::LostBurst,
            Reason::LostBurst,
            Reason::LostResend
        ]
    );
    assert_eq!(fed.borrow().decisions(), 6);
    assert_eq!(net.borrow().draw_error(), None);
}

/// A packed datagram, two GET frames back to back, reads as its first GET frame. A GET kind selector and a
/// request selector of the first frame match it, and a request selector of the second frame misses it. A tap
/// captures it under the first frame's kind, and its resend key is the first frame's: under a resend loss of 100 and
/// an empty rule chain, a lone copy of the second frame arrives as a first send and a lone copy of the first frame
/// drops as a resend. Over two GET frames that both authenticate at the receiver, a tag corruption flips the first
/// frame's tag byte alone: the first frame then fails authentication on its tag, the second still authenticates, and
/// containment judges the first frame toward the owner and the whole datagram toward a client. A second packed
/// datagram whose first frame the link carried before drops as a resend. A GET body corruption finds no body byte in the first frame, as on a lone GET
/// datagram, and changes nothing.
#[test]
fn a_packed_datagram_reads_as_its_first_get_frame() {
    let packed = [get_frame(1), get_frame(2)].concat();
    assert_eq!(packed.len(), 384);
    let message = Message::decode(0, 1, 0, &packed);
    assert_eq!(
        message.header.map(|header| (header.kind, header.request)),
        Some((Kind::Get, 1))
    );
    for (selector, selected) in [
        (Selector::Kind(Kind::Get), true),
        (Selector::Request(1), true),
        (Selector::Request(2), false),
    ] {
        let mut chain = Chain::new(
            vec![Rule::new(selector.clone(), Effect::Drop)],
            &[],
            &MANIFEST,
        )
        .unwrap();
        let dropped = chain.decide(&message, Decision::default()).drop.is_some();
        assert_eq!(dropped, selected, "{selector:?}");
    }

    let resend = Faults {
        resend_loss: 100,
        ..Faults::default()
    };
    let draws = recorder(33);
    let (mut near, mut far, net) = network_drawn(16, 8384, [resend; 2], (&draws, 0));
    net.borrow_mut()
        .set_rules(Chain::new(Vec::new(), &[0], &MANIFEST).unwrap());
    let pool = test_pool(8, 1).unwrap();
    let mut turn = 0;
    let mut send = |bytes: &[u8]| {
        net.borrow_mut().advance(turn);
        turn += 1;
        assert_eq!(near.send(&[plain(bytes)]), Ok(1));
        drain_with_pool(&mut far, &pool)
    };
    assert_eq!(send(&packed), 1, "the packed datagram is a first send");
    assert_eq!(
        send(&get_frame(2)),
        1,
        "the second frame's key is not in the window"
    );
    assert_eq!(
        send(&get_frame(1)),
        0,
        "a lone copy of the first frame drops as a resend"
    );
    assert_eq!(
        send(&[get_frame(1), get_frame(3)].concat()),
        0,
        "a packed datagram behind a carried first frame drops as a resend, its second frame a first send"
    );
    {
        let net = net.borrow();
        let captures = net.rules().captures();
        let seen: Vec<_> = captures
            .iter()
            .map(|capture| (capture.kind, capture.ordinal, capture.decision.drop))
            .collect();
        assert_eq!(
            seen,
            [
                (Some(Kind::Get), 0, None),
                (Some(Kind::Get), 1, None),
                (Some(Kind::Get), 2, Some(Dropped::Resend)),
                (Some(Kind::Get), 3, Some(Dropped::Resend)),
            ],
            "the tap captures the packed datagram under its first frame's kind, and only the first frame's key is a resend"
        );
        assert_eq!(net.audit().count(Reason::LostResend), 2);
    }

    let pool = test_pool(8, 1).unwrap();
    let ring = super::auth::KeyRing::load(
        &PRINCIPALS[..1],
        &super::owner_tests::entries()[..1],
        1,
        &mut crate::storage::EngineBudget::new(1 << 20),
    )
    .unwrap();
    let packed = [1, 2]
        .map(|request| {
            let get = get_frame(request);
            let header = super::frame::Header {
                principal: PRINCIPALS[0],
                key_epoch: 1,
                ..super::frame::parse(crate::storage::Crc32c::detect(), &get, false)
                    .unwrap()
                    .header()
            };
            super::auth_tests::sealed(&ring, PeerId(0), &header, &[], Direction::ClientToOwner)
        })
        .concat();
    assert_eq!(packed.len(), 384);
    let authentic = |frame: &[u8]| {
        let frame = super::frame::parse(crate::storage::Crc32c::detect(), frame, false).unwrap();
        ring.authenticate(&frame, PeerId(0), ENDPOINT, Direction::ClientToOwner)
            .map(|_| ())
    };
    assert_eq!(
        [authentic(&packed[..192]), authentic(&packed[192..])],
        [Ok(()), Ok(())],
        "premise: both frames authenticate at the receiver"
    );
    for (class, changed) in [(Corruption::Tag, true), (Corruption::GetBody, false)] {
        let (mut near, mut far, net) = network(16, 8384, 34, [Faults::default(); 2]);
        let corrupt = Rule::new(Selector::Kind(Kind::Get), Effect::Corrupt(class));
        net.borrow_mut()
            .set_rules(Chain::new(vec![corrupt], &[], &MANIFEST).unwrap());
        assert_eq!(near.send(&[plain(&packed)]), Ok(1));
        let mut meta = [Received::default(); 1];
        let mut leases: [Option<PacketLease<'_>>; 1] = [None];
        net.borrow_mut().advance(1);
        assert_eq!(far.receive(&pool, &mut leases, &mut meta), Ok(1));
        let delivered = leases[0].take().unwrap().bytes().to_vec();
        let differs: Vec<usize> = (0..packed.len())
            .filter(|&at| delivered[at] != packed[at])
            .collect();
        let net = net.borrow();
        if changed {
            assert_eq!(differs, [AUTHENTICATED_LEN], "{class:?}");
            assert_eq!(
                [authentic(&delivered[..192]), authentic(&delivered[192..])],
                [Err(super::auth::AuthError::Tag), Ok(())],
                "the first frame fails on its tag and the second is as sent"
            );
            let receiver = |_| (&ring, PeerId(0), ENDPOINT, Direction::ClientToOwner);
            assert_eq!(contain(net.damaged(), receiver), Ok(1), "{class:?}");
            let client = |_| (&ring, PeerId(0), ENDPOINT, Direction::OwnerToClient);
            assert_eq!(
                contain(net.damaged(), client),
                Err((Some(Corruption::Tag), Some(Layer::Frame))),
                "toward a client the same copy is one datagram, which the frame codec refuses"
            );
        } else {
            assert!(differs.is_empty(), "{class:?}");
            assert!(net.damaged().is_empty(), "{class:?}");
            assert_eq!(
                net.audit().count(Reason::Inapplicable(class)),
                1,
                "{class:?}"
            );
        }
    }
}
