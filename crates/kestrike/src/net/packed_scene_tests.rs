//! Packed GETs between a real client and a real owner over the in-memory link: each request of a packed datagram
//! keeps its own identity, deadline, cancellation, retry and outcome, a lost packed datagram leaves each GET to its own
//! retry clock, a retry resolves on its own wire slot, and a copied or late frame meets the session replay window or
//! its wire slot's watermark. Each scenario asserts in-test the premise that brings it to its guard, and reads what the
//! client sent through literal lengths and `parse` on each 192-byte chunk.

use std::cell::RefCell;
use std::rc::Rc;

use crate::sim::round::Actor;
use crate::storage::Crc32c;
use crate::storage::owner_fixture::read_tokens;

use super::client::Client;
use super::datagram::HEADER_LEN;
use super::fetch::{FetchReport, Outcome};
use super::frame::{Header, Kind, Status, parse};
use super::link::{LinkEnd, Net};
use super::owner_tests::{PRINCIPALS, key, payload};
use super::put_tests::{Scene, scene};
use super::requests::RequestId;
use super::rules::{Chain, Effect, MANIFEST, Rule, Selector};
use super::window_tests::submitted;

/// What the owner shows of its requests: the serve report, the census, the lookups, the read commands the device
/// accepted and the datagrams the owner sent. A copy of a handled datagram leaves all of it unchanged.
fn untouched(
    scene: &Scene<'_, '_>,
) -> (
    super::serve::ServeReport,
    super::requests::RequestCensus,
    u64,
    usize,
    u64,
) {
    (
        scene.owner.serve_report(),
        scene.owner.census(),
        scene.owner.lookups(),
        submitted(&scene.control),
        scene.owner.report().sent,
    )
}

/// The object the scene's owner publishes under key 1 before it starts.
fn object() -> Vec<u8> {
    payload(1000, 1)
}

/// The header of each 192-byte frame of `datagram`, which is a whole number of frames with no payload.
fn headers(datagram: &[u8]) -> Vec<Header> {
    assert_eq!(datagram.len() % HEADER_LEN, 0, "whole frames");
    let crc = Crc32c::detect();
    datagram
        .chunks(HEADER_LEN)
        .map(|frame| {
            parse(crc, frame, false)
                .expect("a canonical frame")
                .header()
        })
        .collect()
}

/// The headers of each datagram in flight toward the owner on client 0's link, each a whole number of 192-byte
/// frames parsed one by one; the link keeps them.
fn toward_owner(nets: &[Rc<RefCell<Net<'_>>>; 2]) -> Vec<(usize, Vec<Header>)> {
    let mut datagrams = Vec::new();
    nets[0].borrow_mut().retain(1, |bytes| {
        datagrams.push((bytes.len(), headers(bytes)));
        true
    });
    datagrams
}

/// One turn in which client 0 polls at the turn's time ahead of the link, the disk and the owner, returning the
/// datagrams its poll left in flight toward the owner.
fn polled(scene: &mut Scene<'_, '_>) -> Vec<(usize, Vec<Header>)> {
    let mut sent = Vec::new();
    scene.turn_with(&mut [(Actor::Client(0), &mut |clients, nets, now| {
        let _ = clients[0].poll(now);
        sent = toward_owner(nets);
    })]);
    sent
}

/// Takes every fragment client 0 holds for `ids` into `bytes`.
fn take<'m>(client: &mut Client<'m, LinkEnd<'m>>, ids: &[RequestId], bytes: &mut [Vec<u8>]) {
    for (id, bytes) in ids.iter().zip(bytes) {
        while let Some(fragment) = client.take(*id) {
            bytes.extend_from_slice(fragment.bytes());
        }
    }
}

/// Polls client 0 each turn, taking its fragments, until `done` holds or 4,000 turns pass; `done` also receives
/// the datagrams the turn's poll sent.
fn drive(
    scene: &mut Scene<'_, '_>,
    ids: &[RequestId],
    bytes: &mut [Vec<u8>],
    mut done: impl FnMut(&mut Scene<'_, '_>, &[(usize, Vec<Header>)]) -> bool,
) {
    for _ in 0..4_000 {
        let sent = polled(scene);
        take(&mut scene.clients[0], ids, bytes);
        if done(scene, &sent) {
            return;
        }
    }
    panic!("the scenario settled within 4,000 turns");
}

/// Whether every request of `ids` at client 0 has an outcome.
fn decided(scene: &Scene<'_, '_>, ids: &[RequestId]) -> bool {
    ids.iter().all(|id| scene.clients[0].outcome(*id).is_some())
}

/// The owner's request, duplicate and replay counts and the read commands it submitted.
fn served(scene: &Scene<'_, '_>) -> (u64, u64, u64, usize) {
    let serve = scene.owner.serve_report();
    (
        serve.requests,
        serve.duplicates,
        serve.replays,
        submitted(&scene.control),
    )
}

/// Two GETs for one key from one client leave in one 384-byte datagram under two request IDs, and the owner admits
/// them as two requests with two reads and no duplicate: packing coalesces nothing by key. Cancelling the first after
/// its START sends one CANCEL for it and leaves the second to complete with exact bytes. On this clean link the
/// client's `gets_per_datagram[1]` moves by one and the owner's `get_frames` and `get_datagrams` by 2 and 1.
#[test]
fn same_key_gets_in_one_datagram_are_separate_requests() {
    scene(&PRINCIPALS, |mut scene| {
        let (fetched, owner, before) = (
            scene.clients[0].fetch_report(),
            scene.owner.report(),
            served(&scene),
        );
        let now = scene.turn * 100;
        let ids = [0, 1].map(|_| {
            scene.clients[0]
                .get(key(1), 0, 1 << 20, now, 30_000_000)
                .unwrap()
        });
        let wires = ids.map(|id| scene.clients[0].get_wire(id).unwrap());
        assert_ne!(wires[0], wires[1]);
        let sent = polled(&mut scene);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].0, 384);
        let frames: Vec<_> = sent[0]
            .1
            .iter()
            .map(|get| (get.kind, get.request, get.key))
            .collect();
        assert_eq!(
            frames,
            [(Kind::Get, wires[0], key(1)), (Kind::Get, wires[1], key(1))]
        );
        let start = Selector::All(vec![Selector::Toward(0), Selector::Request(wires[0])]);
        scene.nets[0].borrow_mut().set_rules(
            Chain::new(
                vec![Rule::new(start, Effect::Drop).window(1, u32::MAX)],
                &[],
                &MANIFEST,
            )
            .unwrap(),
        );
        let mut bytes = [Vec::new(), Vec::new()];
        let mut cancels = Vec::new();
        let mut started = false;
        drive(&mut scene, &ids, &mut bytes, |scene, sent| {
            cancels.extend(
                sent.iter()
                    .flat_map(|(_, frames)| frames)
                    .filter(|frame| frame.kind == Kind::Cancel)
                    .map(|frame| frame.request),
            );
            let crc = Crc32c::detect();
            if !started {
                scene.nets[0].borrow_mut().retain(0, |bytes| {
                    let header = parse(crc, bytes, false).unwrap().header();
                    started |= header.kind == Kind::Start && header.request == wires[0];
                    true
                });
                return false;
            }
            if scene.clients[0].outcome(ids[0]).is_none() {
                scene.clients[0].cancel(ids[0]);
            }
            decided(scene, &ids) && scene.owner.census().live() == 0
        });
        assert_eq!(
            scene.clients[0].outcome(ids[0]),
            Some(Outcome::Failed(Status::Cancelled))
        );
        assert_eq!(scene.clients[0].outcome(ids[1]), Some(Outcome::Complete));
        assert_eq!(bytes[1], object());
        assert_eq!(
            cancels,
            [wires[0]],
            "the client sent one CANCEL, naming the cancelled request"
        );
        let (requests, duplicates, replays, reads) = served(&scene);
        assert_eq!(
            (
                requests - before.0,
                duplicates - before.1,
                replays - before.2,
                reads - before.3
            ),
            (2, 0, 0, 2)
        );
        let after = scene.owner.report();
        assert_eq!(
            (
                after.get_frames - owner.get_frames,
                after.get_datagrams - owner.get_datagrams
            ),
            (2, 1)
        );
        let moved: Vec<u64> = scene.clients[0]
            .fetch_report()
            .gets_per_datagram
            .iter()
            .zip(fetched.gets_per_datagram)
            .map(|(after, before)| after - before)
            .collect();
        assert_eq!(moved, [0, 1, 0, 0, 0, 0, 0, 0]);
    });
}

/// Two GETs of one packed datagram keep their own deadlines and reads. Admitted together with waits 1 ms apart,
/// they carry remaining times of 30,000 and 30,001 ms. The owner submits both reads in the receiving poll; with the
/// second read held at the device, the first GET completes with exact bytes while the second still reads, and the
/// second completes once the device releases its read.
#[test]
fn each_get_of_a_packed_datagram_keeps_its_own_deadline_and_read() {
    scene(&PRINCIPALS, |mut scene| {
        let first = read_tokens(&scene.control).len();
        let now = scene.turn * 100;
        let ids = [30_000_000, 30_001_000]
            .map(|wait| scene.clients[0].get(key(1), 0, 1 << 20, now, wait).unwrap());
        let mut sent = Vec::new();
        let mut held = None;
        scene.turn_then(
            &mut [(Actor::Client(0), &mut |clients, nets, now| {
                let _ = clients[0].poll(now);
                sent = toward_owner(nets);
            })],
            &mut |control, _| {
                let submitted = read_tokens(control);
                if held.is_none() && submitted.len() == first + 2 {
                    control.hold(submitted[first + 1]);
                    held = Some(submitted[first + 1]);
                }
            },
        );
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].0, 384);
        let remaining: Vec<u32> = sent[0].1.iter().map(|get| get.remaining_ms).collect();
        assert_eq!(
            remaining,
            [30_000, 30_001],
            "each GET carries its own remaining time"
        );
        let held = held.expect("premise: both reads were submitted in the receiving poll");
        let mut bytes = [Vec::new(), Vec::new()];
        drive(&mut scene, &ids, &mut bytes, |scene, _| {
            scene.clients[0].outcome(ids[0]).is_some()
        });
        assert_eq!(scene.clients[0].outcome(ids[0]), Some(Outcome::Complete));
        assert_eq!(bytes[0], object());
        assert_eq!(
            scene.clients[0].outcome(ids[1]),
            None,
            "the second GET still reads"
        );
        assert!(bytes[1].is_empty());
        scene.control.release(held);
        drive(&mut scene, &ids, &mut bytes, |scene, _| {
            scene.clients[0].outcome(ids[1]).is_some()
        });
        assert_eq!(scene.clients[0].outcome(ids[1]), Some(Outcome::Complete));
        assert_eq!(bytes[1], object());
    });
}

/// Ends client 0's template GET, the one the scene's refresh sent and its link cleared, so its retries leave the
/// client's counters and wire to the scenario's own requests.
fn quiet(scene: &mut Scene<'_, '_>) {
    let template = scene.template_id(0);
    assert_eq!(
        scene.clients[0].get_wire(template),
        Some(scene.template(0).request),
        "premise: the handle names the GET of the template header"
    );
    scene.clients[0].cancel(template);
    polled(scene);
    assert!(
        scene.clients[0].retire(template),
        "premise: the template GET retired"
    );
    scene.turns(4);
}

/// Retry interval of the scene's clients.
const RETRY_US: u64 = 3_000;

/// The datagrams client 0 sends from this turn on that carry a GET frame of `ids`, each as its time, its length and
/// the requests of `ids` its GET frames name, until `ids` complete. After the first poll that leaves a datagram in
/// flight toward the owner, every datagram in flight toward the owner is taken off the link before the owner
/// receives it, as datagrams the link loses; the result lists the lost ones that carry a GET frame of `ids` too.
fn after_a_lost_datagram(
    scene: &mut Scene<'_, '_>,
    ids: &[RequestId],
    bytes: &mut [Vec<u8>],
) -> Vec<(u64, usize, Vec<u64>)> {
    let wires: Vec<u64> = ids
        .iter()
        .map(|id| scene.clients[0].get_wire(*id).unwrap())
        .collect();
    let mut gets = Vec::new();
    let mut lost = false;
    for _ in 0..4_000 {
        let now = scene.turn * 100;
        let mut sent = Vec::new();
        scene.turn_with(&mut [(Actor::Client(0), &mut |clients, nets, now| {
            let _ = clients[0].poll(now);
            sent = toward_owner(nets);
            if !lost && !sent.is_empty() {
                nets[0].borrow_mut().clear(1);
                lost = true;
            }
        })]);
        for (len, frames) in sent {
            let requests: Vec<u64> = frames
                .iter()
                .filter(|frame| frame.kind == Kind::Get && wires.contains(&frame.request))
                .map(|frame| frame.request)
                .collect();
            if !requests.is_empty() {
                gets.push((now, len, requests));
            }
        }
        take(&mut scene.clients[0], ids, bytes);
        if decided(scene, ids) {
            return gets;
        }
    }
    panic!("the GETs ended within 4,000 turns");
}

/// A packed datagram the link drops leaves each GET to its own retry clock. A admitted at `t` and B at `t + 300`
/// leave together at `t + 300` in one 384-byte datagram, which the link drops. The poll at `t + R` sends one 192-byte
/// datagram naming A, and the poll at `t + 300 + R` one naming B; `get_retries` moves by 2, both complete with exact
/// bytes, and the owner shows two requests and no duplicate. With equal admission times both retry at `t + R` in one
/// packed datagram.
#[test]
fn a_lost_packed_datagram_leaves_each_get_to_its_own_retry_clock() {
    scene(&PRINCIPALS, |mut scene| {
        quiet(&mut scene);
        let (before, retries) = (served(&scene), scene.clients[0].fetch_report().get_retries);
        let t = scene.turn * 100;
        let a = scene.clients[0]
            .get(key(1), 0, 1 << 20, t, 30_000_000)
            .unwrap();
        scene.turns(3);
        assert_eq!(scene.turn * 100, t + 300);
        let b = scene.clients[0]
            .get(key(1), 0, 1 << 20, t + 300, 30_000_000)
            .unwrap();
        let wires = [a, b].map(|id| scene.clients[0].get_wire(id).unwrap());
        let mut bytes = [Vec::new(), Vec::new()];
        let gets = after_a_lost_datagram(&mut scene, &[a, b], &mut bytes);
        assert_eq!(
            [a.slot(), b.slot()],
            [0, 1],
            "premise: hand-out starts at the cursor, slot 1, after the template's CANCEL at slot 0"
        );
        assert_eq!(
            gets,
            [
                (t + 300, 384, vec![wires[1], wires[0]]),
                (t + RETRY_US, 192, vec![wires[0]]),
                (t + 300 + RETRY_US, 192, vec![wires[1]]),
            ]
        );
        assert_eq!(scene.clients[0].fetch_report().get_retries - retries, 2);
        for (id, bytes) in [a, b].iter().zip(&bytes) {
            assert_eq!(scene.clients[0].outcome(*id), Some(Outcome::Complete));
            assert_eq!(*bytes, object());
        }
        let (requests, duplicates, _, _) = served(&scene);
        assert_eq!((requests - before.0, duplicates - before.1), (2, 0));

        let t = scene.turn * 100;
        let pair = [0, 1].map(|_| {
            scene.clients[0]
                .get(key(1), 0, 1 << 20, t, 30_000_000)
                .unwrap()
        });
        let wires = pair.map(|id| scene.clients[0].get_wire(id).unwrap());
        let mut bytes = [Vec::new(), Vec::new()];
        let mut gets = after_a_lost_datagram(&mut scene, &pair, &mut bytes);
        for (_, _, requests) in &mut gets {
            requests.sort_unstable();
        }
        let mut wires = wires;
        wires.sort_unstable();
        assert_eq!(
            gets,
            [
                (t, 384, vec![wires[0], wires[1]]),
                (t + RETRY_US, 384, vec![wires[0], wires[1]]),
            ],
            "GETs admitted together retry together and pack again"
        );
        for (id, bytes) in pair.iter().zip(&bytes) {
            assert_eq!(scene.clients[0].outcome(*id), Some(Outcome::Complete));
            assert_eq!(*bytes, object());
        }
    });
}

/// A GET retry resolves on its own wire slot. A and B, both hits, leave in one packed datagram and the owner admits
/// both in the receiving poll; every frame toward the client naming B is dropped until the link carries a second GET
/// naming B. The link dropped at least one such frame by then, B is still undecided, and that GET is B's first
/// retry: a 192-byte datagram naming B alone. Across it the owner shows no new request, one duplicate and no new
/// read: it requeues B's frames on B's wire slot, B completes with exact bytes, and A's outcome and bytes are
/// unchanged.
#[test]
fn a_get_retry_resolves_on_its_own_wire_slot() {
    scene(&PRINCIPALS, |mut scene| {
        quiet(&mut scene);
        let before = served(&scene);
        let t = scene.turn * 100;
        let ids = [0, 1].map(|_| {
            scene.clients[0]
                .get(key(1), 0, 1 << 20, t, 30_000_000)
                .unwrap()
        });
        let wires = ids.map(|id| scene.clients[0].get_wire(id).unwrap());
        let replies = Selector::All(vec![Selector::Toward(0), Selector::Request(wires[1])]);
        let lost = scene.nets[0].borrow().report(0).lost;
        scene.nets[0]
            .borrow_mut()
            .set_rules(Chain::new(vec![Rule::new(replies, Effect::Drop)], &[], &MANIFEST).unwrap());
        let names_b = |sent: &[(usize, Vec<Header>)]| {
            sent.iter()
                .flat_map(|(_, frames)| frames)
                .filter(|frame| frame.kind == Kind::Get && frame.request == wires[1])
                .count()
        };
        let sent = polled(&mut scene);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, 384);
        let mut gets_of_b = names_b(&sent);
        assert_eq!(
            gets_of_b, 1,
            "premise: B's first GET left in the packed datagram"
        );
        let (requests, _, _, reads) = served(&scene);
        assert_eq!(
            (requests - before.0, reads - before.3),
            (2, 2),
            "premise: the owner admits both in the receiving poll"
        );
        let mut bytes = [Vec::new(), Vec::new()];
        drive(&mut scene, &ids, &mut bytes, |scene, sent| {
            gets_of_b += names_b(sent);
            scene.clients[0].outcome(ids[0]).is_some()
        });
        assert_eq!(scene.clients[0].outcome(ids[0]), Some(Outcome::Complete));
        assert_eq!(bytes[0], object());
        let terminal = scene.clients[0].terminal(ids[0]);
        let mut retry = None;
        let mut premise = None;
        for _ in 0..4_000 {
            let across = served(&scene);
            let mut sent = Vec::new();
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, nets, now| {
                let _ = clients[0].poll(now);
                sent = toward_owner(nets);
                gets_of_b += names_b(&sent);
                if names_b(&sent) > 0 {
                    let dropped = nets[0].borrow().report(0).lost - lost;
                    premise = Some((dropped, clients[0].outcome(ids[1])));
                    nets[0]
                        .borrow_mut()
                        .set_rules(Chain::new(Vec::new(), &[], &MANIFEST).unwrap());
                }
            })]);
            take(&mut scene.clients[0], &ids, &mut bytes);
            if let Some((len, frames)) = sent
                .into_iter()
                .find(|(_, frames)| frames.iter().any(|frame| frame.request == wires[1]))
            {
                let requests: Vec<_> = frames
                    .iter()
                    .map(|frame| (frame.kind, frame.request))
                    .collect();
                retry = Some((len, requests, across, served(&scene)));
                break;
            }
        }
        let (len, requests, across, after) = retry.expect("B's GET retry");
        let (dropped, undecided) = premise.expect("the retry ended the drops");
        assert!(
            dropped > 0,
            "premise: the link dropped a frame that named B toward the client"
        );
        assert_eq!(undecided, None, "premise: B is undecided at its retry");
        assert_eq!(gets_of_b, 2, "premise: the GET judged is B's first retry");
        assert_eq!((len, requests), (192, vec![(Kind::Get, wires[1])]));
        assert_eq!(
            (after.0 - across.0, after.1 - across.1, after.3 - across.3),
            (0, 1, 0),
            "the retry reaches B's own record: no new request and no new read"
        );
        drive(&mut scene, &ids, &mut bytes, |scene, _| {
            scene.clients[0].outcome(ids[1]).is_some()
        });
        assert_eq!(scene.clients[0].outcome(ids[1]), Some(Outcome::Complete));
        assert_eq!(bytes[1], object());
        assert_eq!(bytes[0], object());
        assert_eq!(
            scene.clients[0].terminal(ids[0]),
            terminal,
            "A's outcome is unchanged"
        );
        let (requests, _, _, reads) = served(&scene);
        assert_eq!((requests - before.0, reads - before.3), (2, 2));
    });
}

/// What a copied frame must leave unchanged at the client: each request's outcome and the fetch report.
fn client_state(scene: &Scene<'_, '_>, ids: &[RequestId]) -> (Vec<Option<Outcome>>, FetchReport) {
    (
        ids.iter().map(|id| scene.clients[0].outcome(*id)).collect(),
        scene.clients[0].fetch_report(),
    )
}

/// A late GET frame reaches only its own generation, and a copied one is refused at session admission, between a
/// real client and a real owner with no hand-built frame. The client's first datagram holds two GET frames and is
/// kept and taken off the link; A names the request of its first frame and B the request of its second. A and B
/// retry together in one packed datagram, under fresh sequences, and complete.
///
/// A copy of that handled retry datagram, injected after A completed and again after a successor S holds A's wire
/// slot, is refused frame by frame by the replay window as `Duplicate`: the session's duplicate count and the packed
/// frames refused under `Session` move by 2, and the owner's serve state and the client's outcomes, bytes and fetch
/// report stay as they were.
///
/// The kept datagram, delivered for the first time while S's read is held, is admitted by the session, so the
/// session report stays and `get_frames` moves by 2. A's frame, the first, meets its wire slot's watermark, S's
/// later generation, and is dropped before any lookup; the owner goes on to B's frame, which at its slot's watermark
/// generation replays B's retained terminal: duplicates and replays move by 1, requests and reads by 0, and the one
/// datagram the owner sends is B's COMPLETE as the owner first sent it, under a fresh sequence. S then completes with its own bytes under one admission.
/// The watermark's in-tree control is
/// `namespace_tests::negative_control_a_release_that_forgets_the_watermark_readmits_a_released_identity`.
#[test]
fn a_late_get_frame_reaches_only_its_own_generation() {
    scene(&PRINCIPALS, |mut scene| {
        quiet(&mut scene);
        let t = scene.turn * 100;
        let ids = [0, 1].map(|_| {
            scene.clients[0]
                .get(key(1), 0, 1 << 20, t, 30_000_000)
                .unwrap()
        });
        let mut kept = Vec::new();
        scene.turn_with(&mut [(Actor::Client(0), &mut |clients, nets, now| {
            let _ = clients[0].poll(now);
            nets[0].borrow_mut().retain(1, |bytes| {
                kept.push(bytes.to_vec());
                false
            });
        })]);
        assert_eq!(kept.len(), 1);
        let kept = kept.remove(0);
        assert_eq!(
            kept.len(),
            384,
            "premise: the first datagram is one packed datagram"
        );
        let first = headers(&kept);
        let named = |wire: u64| {
            let id = ids
                .iter()
                .find(|id| scene.clients[0].get_wire(**id) == Some(wire));
            *id.expect("premise: the kept datagram names the two requests")
        };
        let (a, b) = (named(first[0].request), named(first[1].request));
        let wires = [first[0].request, first[1].request];
        assert_ne!(a, b);
        assert_eq!(
            [first[0].kind, first[1].kind],
            [Kind::Get; 2],
            "premise: the kept datagram is A's GET and then B's"
        );
        let mut retry = None;
        let mut terminal = None;
        let mut bytes = [Vec::new(), Vec::new()];
        for _ in 0..4_000 {
            scene.turn_with(&mut [(Actor::Client(0), &mut |clients, nets, now| {
                nets[0].borrow_mut().retain(0, |reply| {
                    let header = parse(Crc32c::detect(), reply, false).unwrap().header();
                    if header.kind == Kind::Complete && header.request == wires[1] {
                        terminal = Some(header);
                    }
                    true
                });
                let _ = clients[0].poll(now);
                nets[0].borrow_mut().retain(1, |datagram| {
                    if retry.is_none() && datagram.len() == 384 {
                        retry = Some(datagram.to_vec());
                    }
                    true
                });
            })]);
            take(&mut scene.clients[0], &[a, b], &mut bytes);
            if decided(&scene, &[a, b]) && scene.owner.census().live() == 0 {
                break;
            }
        }
        let retry = retry.expect("premise: A and B retried in one packed datagram");
        let terminal = terminal.expect("premise: the owner sent B its COMPLETE");
        let again = headers(&retry);
        let mut retried = [again[0].request, again[1].request];
        retried.sort_unstable();
        let mut both = wires;
        both.sort_unstable();
        assert_eq!(
            ([again[0].kind, again[1].kind], retried),
            ([Kind::Get; 2], both),
            "premise: the retry datagram holds the GETs of A and B"
        );
        let newest = first[0].sequence.max(first[1].sequence);
        assert!(
            again[0].sequence > newest && again[1].sequence > newest,
            "premise: the retried frames carry fresh sequences"
        );
        for (id, bytes) in [a, b].iter().zip(&bytes) {
            assert_eq!(scene.clients[0].outcome(*id), Some(Outcome::Complete));
            assert_eq!(*bytes, object());
        }
        let session = super::owner::DropReason::Session as usize;
        let copy = |scene: &mut Scene<'_, '_>, live: [RequestId; 2]| {
            let (owner, client, sessions, report) = (
                untouched(scene),
                client_state(scene, &live),
                scene.owner.session_report(),
                scene.owner.report(),
            );
            scene.nets[0].borrow_mut().inject(1, &retry);
            polled(scene);
            polled(scene);
            let after = scene.owner.report();
            assert_eq!(
                scene.owner.session_report().duplicate - sessions.duplicate,
                2
            );
            assert_eq!(
                after.packed_dropped_by[session] - report.packed_dropped_by[session],
                2
            );
            assert_eq!(after.get_frames, report.get_frames);
            assert_eq!(untouched(scene), owner);
            assert_eq!(client_state(scene, &live), client);
            for id in live {
                assert!(
                    scene.clients[0].take(id).is_none(),
                    "the copy hands the client no byte"
                );
            }
        };
        copy(&mut scene, [a, b]);

        assert!(scene.clients[0].retire(a));
        let now = scene.turn * 100;
        let successor = scene.clients[0]
            .get(key(1), 0, 1 << 20, now, 30_000_000)
            .unwrap();
        let wire = scene.clients[0].get_wire(successor).unwrap();
        assert_eq!(wire >> 48, wires[0] >> 48, "premise: S takes A's wire slot");
        assert!(wire > wires[0], "premise: at a later generation");
        let reads = read_tokens(&scene.control).len();
        let mut held = None;
        scene.turn_then(
            &mut [(Actor::Client(0), &mut |clients, _, now| {
                let _ = clients[0].poll(now);
            })],
            &mut |control, _| {
                if let Some(&token) = read_tokens(control).get(reads) {
                    control.hold(token);
                    held = Some(token);
                }
            },
        );
        let held = held.expect("premise: S's read was submitted and is held");
        assert_eq!(
            scene.owner.census().live(),
            1,
            "premise: S holds A's wire slot"
        );
        copy(&mut scene, [successor, b]);

        let (owner, sessions, report) = (
            untouched(&scene),
            scene.owner.session_report(),
            scene.owner.report(),
        );
        assert_eq!(
            scene.nets[0].borrow().pending(0),
            0,
            "premise: nothing is in flight toward the client"
        );
        scene.nets[0].borrow_mut().inject(1, &kept);
        polled(&mut scene);
        let after = untouched(&scene);
        assert_eq!(
            scene.owner.session_report(),
            sessions,
            "the session admits both frames"
        );
        assert_eq!(scene.owner.report().get_frames - report.get_frames, 2);
        assert_eq!(
            (
                after.0.requests - owner.0.requests,
                after.0.duplicates - owner.0.duplicates,
                after.0.replays - owner.0.replays,
                after.3 - owner.3,
                after.2 - owner.2
            ),
            (0, 1, 1, 0, 0),
            "A's frame stops at its slot's watermark and B's replays B's terminal"
        );
        assert_eq!(scene.owner.census().live(), 1, "S keeps its slot");
        let mut replies = Vec::new();
        scene.nets[0].borrow_mut().retain(0, |bytes| {
            replies.push(parse(Crc32c::detect(), bytes, false).unwrap().header());
            true
        });
        assert_eq!(after.4 - owner.4, 1, "the owner sends one reply");
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(
            Header {
                sequence: terminal.sequence,
                tag: terminal.tag,
                ..replies[0]
            },
            terminal,
            "the reply is B's retained COMPLETE: its request, key, session and manifest, under a fresh sequence and tag"
        );
        assert!(replies[0].sequence > terminal.sequence);

        let late = client_state(&scene, &[b]);
        scene.control.release(held);
        let mut own = [Vec::new()];
        drive(&mut scene, &[successor], &mut own, |scene, _| {
            scene.clients[0].outcome(successor).is_some()
        });
        assert_eq!(scene.clients[0].outcome(successor), Some(Outcome::Complete));
        assert_eq!(own[0], object());
        assert_eq!(
            scene.owner.serve_report().requests - owner.0.requests,
            0,
            "S completes under its one admission"
        );
        assert_eq!(
            client_state(&scene, &[b]).0,
            late.0,
            "B's replayed terminal changes no outcome of B at the client"
        );
        assert!(
            scene.clients[0].take(b).is_none(),
            "and hands the client no byte of B"
        );
    });
}
