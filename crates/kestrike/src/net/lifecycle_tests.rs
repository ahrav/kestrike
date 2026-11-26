//! The end-to-end lifecycle through the highest seam: a client and an owner over the seeded simulator and a simulated disk, closing the client from every state, recovering after each pressure class releases, and two control schedules a correct pair never turns into a success.
//!
//! The owner's side of the lifecycle and the end-to-end regression anchors run through the same seam in `owner_tests`: shutdown from every owner state (`shutdown_from_every_state_releases_only_after_the_drain`), a failed quiesce with a held command (`a_failed_quiesce_reports_its_blockers_and_keeps_custody`), a leaked lease (`a_leaked_lease_blocks_finalization_after_shutdown`), the warm re-key with no attach or charge (`a_warm_rekey_serves_resident_hits_afterwards`), one version under faults (`a_multi_frame_get_delivers_one_version_under_faults`), slow-peer isolation (`a_slow_peer_holding_its_window_delays_no_other_peer`), sent-timeout custody (`a_sent_timeout_keeps_custody_until_the_late_terminal`), silent-cancel custody (`a_silent_cancel_keeps_its_wire_binding_until_the_read_drains`), invalidation during a read (`a_read_before_invalidation_finishes_and_the_next_get_looks_up_afresh`) and empty and corrupt objects (`an_empty_object_completes_and_a_corrupt_header_succeeds_never`).

use std::cell::RefCell;
use std::rc::Rc;

use crate::storage::owner_fixture::{SimControl, TestPlatform, arena, storage};
use crate::storage::{
    BufferArena, CommandToken, Crc32c, EngineBudget, PoolKind, RefusalReason, Storage,
    SubmitRefusal, WorkBudget,
};

use super::auth::KeyRing;
use super::client::{Client, ClientMemory, GetRefused, SessionState};
use super::datagram::{HEADER_LEN, PeerId};
use super::fetch::{FragmentLease, Outcome, Releases};
use super::frame::{Direction, Header, Kind, Status, encode, mac_input_for, parse, seal};
use super::frame_tests::put_frame;
use super::link::{Faults, LinkEnd, Net, network};
use super::owner_tests::{
    OWNER, PRINCIPALS, TestOwner, client_config, drive, entries, hold_next_read, key, open,
    payload, pool, start,
};
use super::packet::PacketPool;
use super::requests::{RequestId, RequestTable};
use crate::sim::round::{Act, Actor, round};

/// Four fragments of body: a window's worth of receive buffers per GET.
const BODY: usize = 30_000;

/// A client and an owner joined by one clean simulated link, the owner serving keys 1 and 2.
struct Scene<'s, 'm> {
    client: Client<'m, LinkEnd<'m>>,
    owner: TestOwner<'s, 'm, 'm>,
    control: SimControl,
    nets: [Rc<RefCell<Net<'m>>>; 1],
    storage: &'s Storage<TestPlatform>,
    buffers: &'m BufferArena<TestPlatform>,
    client_pool: &'m PacketPool<'m>,
    turn: u64,
}

/// The objects a scene serves, key `n` holding `object(n)`.
fn object(n: u8) -> Vec<u8> {
    payload(BODY, u64::from(n))
}

/// Runs `body` over a fresh scene whose objects hold `rights` rights each; the client's 24 receive buffers cover six windows, so its four request slots fill before its boxes do.
fn scene(rights: usize, body: impl FnOnce(Scene<'_, '_>)) {
    let storage = storage(rights);
    let buffers = arena(8);
    let receive = pool();
    let objects: Vec<Vec<u8>> = (1..=2).map(object).collect();
    let published: Vec<_> = objects
        .iter()
        .zip(1u8..)
        .map(|(bytes, n)| (key(n), 0, bytes.as_slice()))
        .collect();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 77, [Faults::default(); 2]);
    let (owner, control) = start(&storage, &buffers, &receive, &published, vec![owner_end]);
    let mut config = client_config(0);
    config.fetch.boxes = 24;
    let memory = ClientMemory {
        receive: &client_pool,
        releases: &releases,
        requests: RequestTable::new(4, 1, 4),
        sources: Box::default(),
        routes: super::client_tests::routes(),
    };
    let client = Client::initialize(
        config,
        memory,
        client_end,
        &entries()[..1],
        1,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    body(Scene {
        client,
        owner,
        control,
        nets: [net],
        storage: &storage,
        buffers: &buffers,
        client_pool: &client_pool,
        turn: 0,
    });
}

impl<'m> Scene<'_, 'm> {
    fn open(&mut self) {
        self.turn = open(
            &mut self.client,
            &mut self.owner,
            &self.control,
            &self.nets,
            self.turn,
        );
    }

    fn turns(&mut self, turns: u64) {
        self.turn = drive(
            &mut [&mut self.client],
            &mut self.owner,
            &self.control,
            &self.nets,
            self.turn,
            turns,
            |_| false,
        );
    }

    /// Turns until the owner holds no live request, so a later GET finds its wire slot free.
    fn settle(&mut self) {
        for _ in 0..20_000 {
            let census = self.owner.census();
            if census.active + census.draining == 0 {
                return;
            }
            self.turns(1);
        }
        panic!("the owner kept a live request");
    }

    fn issue(&mut self, n: u8) -> Result<RequestId, GetRefused> {
        self.client
            .get(key(n), 0, 1 << 20, self.turn * 100, 30_000_000)
    }

    /// Drives `id` to its outcome, taking its fragments in order into `held`, then retires it.
    fn finish(&mut self, id: RequestId, held: &mut Vec<FragmentLease<'m>>) -> Option<Outcome> {
        self.turn = drive(
            &mut [&mut self.client],
            &mut self.owner,
            &self.control,
            &self.nets,
            self.turn,
            20_000,
            |clients| {
                while let Some(fragment) = clients[0].take(id) {
                    held.push(fragment);
                }
                clients[0].outcome(id).is_some()
            },
        );
        let outcome = self.client.outcome(id);
        assert!(self.client.retire(id), "a decided request retires");
        outcome
    }

    /// GETs key `n` to its outcome and checks a success against the object's exact bytes.
    fn get(&mut self, n: u8) -> Option<Outcome> {
        let id = self.issue(n).expect("the client admits the GET");
        let mut held = Vec::new();
        let outcome = self.finish(id, &mut held);
        if outcome == Some(Outcome::Complete) {
            assert_eq!(joined(&held), object(n), "key {n}");
        }
        outcome
    }

    fn hold_read(&mut self) -> CommandToken {
        let (token, turn) = hold_next_read(
            &mut self.client,
            &mut self.owner,
            &self.control,
            &self.nets[0],
            self.turn,
        );
        self.turn = turn;
        token
    }

    /// Closes the owner and turns it until it shuts down.
    fn shut_down(self) {
        shut_down(self.owner, &self.control, self.turn);
    }
}

/// Closes `owner` at `turn` and turns it with its device, one controller round per turn, until it shuts down.
fn shut_down(mut owner: TestOwner<'_, '_, '_>, control: &SimControl, turn: u64) {
    let _ = owner.close(turn * 100);
    for at in turn..turn + 2_000 {
        if owner.blockers().is_none() {
            break;
        }
        round(&mut [
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || owner.poll(at * 100)),
        ]);
    }
    assert!(owner.shutdown().is_ok(), "the owner drained and shut down");
}

/// The bytes of `fragments`, checked to run in order from offset zero.
fn joined(fragments: &[FragmentLease<'_>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for fragment in fragments {
        assert_eq!(fragment.offset(), bytes.len() as u64, "in order");
        bytes.extend_from_slice(fragment.bytes());
    }
    bytes
}

/// The client state a close starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseFrom {
    Unopened,
    Opening,
    Idle,
    InFlight,
    Failed,
}

/// Closing the client returns its last turn's report, whose CANCEL alone ends a GET in flight at the owner, and keeps every taken lease readable until it drops, from each state: never opened, opening, active and idle, with a GET in flight, and after a failed opening. Every box then returns to the client's pool, and the owner drains and shuts down.
#[test]
fn the_client_closes_from_every_state() {
    for state in [
        CloseFrom::Unopened,
        CloseFrom::Opening,
        CloseFrom::Idle,
        CloseFrom::InFlight,
        CloseFrom::Failed,
    ] {
        scene(8, |mut scene| {
            let mut held = Vec::new();
            match state {
                CloseFrom::Unopened => {}
                CloseFrom::Opening => {
                    scene.client.session(scene.turn * 100);
                    scene.turns(1);
                    assert_eq!(scene.client.state(), SessionState::Opening);
                }
                CloseFrom::Failed => {
                    let lost = Faults {
                        loss: 100,
                        ..Faults::default()
                    };
                    scene.nets[0].borrow_mut().set_faults(1, lost);
                    scene.client.session(scene.turn * 100);
                    for _ in 0..1_000 {
                        if scene.client.state() != SessionState::Opening {
                            break;
                        }
                        scene.turns(1);
                    }
                    assert_eq!(scene.client.state(), SessionState::Failed);
                }
                CloseFrom::Idle | CloseFrom::InFlight => {
                    scene.open();
                    if state == CloseFrom::InFlight {
                        let id = scene.issue(1).unwrap();
                        for _ in 0..5_000 {
                            if let Some(fragment) = scene.client.take(id) {
                                held.push(fragment);
                                break;
                            }
                            scene.turns(1);
                        }
                        assert_eq!(held.len(), 1, "a fragment arrived before the close");
                        assert_eq!(scene.client.outcome(id), None, "the GET is in flight");
                    }
                }
            }
            let Scene {
                client,
                mut owner,
                control,
                nets,
                client_pool,
                turn,
                ..
            } = scene;
            let (report, _transport) = client.close(turn * 100);
            assert_eq!(report.failed, None, "{state:?}");
            let mut turn = turn;
            if state == CloseFrom::InFlight {
                assert!(report.sent >= 1, "the close sent the GET's CANCEL");
                // The owner ends the request on the CANCEL alone, before its own close.
                for _ in 0..2_000 {
                    if owner.census().live() == 0 {
                        break;
                    }
                    round(&mut [
                        Act::new(Actor::Link(0), &mut || nets[0].borrow_mut().advance(turn)),
                        Act::new(Actor::Disk(0), &mut || control.tick(64)),
                        Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
                    ]);
                    turn += 1;
                }
                assert_eq!(owner.census().live(), 0, "the CANCEL released the request");
            }
            let bytes = joined(&held);
            assert_eq!(
                bytes,
                object(1)[..bytes.len()],
                "{state:?}: a held lease stays readable"
            );
            assert_eq!(client_pool.report().data, held.len() as u32, "{state:?}");
            drop(held);
            assert_eq!(
                client_pool.report().data,
                0,
                "{state:?}: every box returned"
            );
            shut_down(owner, &control, turn);
        });
    }
}

/// The client's four request slots refuse a fifth GET while the owner's two-request share serves two of the four and refuses the rest, and once they end a GET is admitted and completes; its receive buffers, held by taken leases, refuse a GET whose window they cannot cover, and once the leases drop a GET completes.
#[test]
fn the_clients_slots_and_boxes_recover_once_released() {
    scene(8, |mut scene| {
        scene.open();
        let keys = [1, 2, 1, 2];
        let running: Vec<_> = keys.iter().map(|n| scene.issue(*n).unwrap()).collect();
        assert_eq!(scene.issue(1), Err(GetRefused::RequestPressure));
        let mut completed = 0;
        for (id, n) in running.into_iter().zip(keys) {
            let mut held = Vec::new();
            match scene.finish(id, &mut held) {
                Some(Outcome::Complete) => {
                    assert_eq!(joined(&held), object(n));
                    completed += 1;
                }
                outcome => assert_eq!(outcome, Some(Outcome::Pressure(Status::RequestPressure))),
            }
        }
        assert_eq!(
            completed, 2,
            "the owner's two-request share served two of the four"
        );
        assert_eq!(scene.get(1), Some(Outcome::Complete), "a slot freed");

        let mut held = Vec::new();
        let mut refused = false;
        for n in [1, 2, 1, 2, 1, 2, 1] {
            match scene.issue(n) {
                Ok(id) => assert_eq!(scene.finish(id, &mut held), Some(Outcome::Complete)),
                Err(refusal) => {
                    assert_eq!(refusal, GetRefused::ReceivePressure);
                    refused = true;
                    break;
                }
            }
        }
        assert!(refused, "{} held leases leave no window", held.len());
        drop(held);
        assert_eq!(scene.get(2), Some(Outcome::Complete), "the boxes returned");
        scene.shut_down();
    });
}

/// With the peer's two-request share held by two reads whose commands the device holds, a third GET ends `RequestPressure`; once the commands run, both reads complete and a further GET completes.
#[test]
fn the_peers_share_recovers_once_its_reads_finish() {
    scene(8, |mut scene| {
        scene.open();
        let first = scene.issue(1).unwrap();
        let one = scene.hold_read();
        let second = scene.issue(2).unwrap();
        let two = scene.hold_read();
        assert_eq!(
            scene.get(1),
            Some(Outcome::Pressure(Status::RequestPressure))
        );
        scene.control.release(one);
        scene.control.release(two);
        for (id, n) in [(first, 1), (second, 2)] {
            let mut held = Vec::new();
            assert_eq!(scene.finish(id, &mut held), Some(Outcome::Complete));
            assert_eq!(joined(&held), object(n));
        }
        assert_eq!(scene.get(1), Some(Outcome::Complete), "the share freed");
        scene.shut_down();
    });
}

/// With two rights per object, a lease held outside the owner and a running read hold them, so a second GET of their key ends `ObjectPressure`; once the read finishes and the lease drops, a GET of the key completes.
#[test]
fn an_objects_rights_recover_once_its_read_finishes() {
    scene(2, |mut scene| {
        scene.open();
        let mut reader = scene.storage.register().unwrap();
        let lease = reader
            .lookup(&key(1), 3, &mut WorkBudget::new(1 << 12))
            .unwrap();
        let running = scene.issue(1).unwrap();
        let token = scene.hold_read();
        assert_eq!(
            scene.get(1),
            Some(Outcome::Pressure(Status::ObjectPressure))
        );
        scene.control.release(token);
        let mut held = Vec::new();
        assert_eq!(scene.finish(running, &mut held), Some(Outcome::Complete));
        drop(lease);
        drop(reader);
        assert_eq!(scene.get(1), Some(Outcome::Complete), "the rights freed");
        scene.shut_down();
    });
}

/// A GET's lookup hands its right straight to the read and reserves no lease credit, so with every credit held by another registration's leases on one object a GET still completes.
#[test]
fn a_get_completes_while_another_registration_holds_every_lease_credit() {
    scene(16, |mut scene| {
        scene.open();
        let mut reader = scene.storage.register().unwrap();
        let mut leases = Vec::new();
        let refused = loop {
            match reader.lookup(&key(1), 3, &mut WorkBudget::new(1 << 12)) {
                Ok(lease) => leases.push(lease),
                Err(error) => break error,
            }
        };
        assert_eq!(
            (leases.len(), refused),
            (16, crate::storage::LookupError::LeaseLimit)
        );
        assert_eq!(
            scene.get(2),
            Some(Outcome::Complete),
            "a GET takes no credit"
        );
        drop(leases);
        drop(reader);
        assert_eq!(scene.get(2), Some(Outcome::Complete));
        scene.shut_down();
    });
}

/// A GET whose first read command finds the device queue full waits for a later tick to submit it, and completes.
#[test]
fn a_get_whose_device_queue_was_full_waits_and_completes() {
    scene(8, |mut scene| {
        scene.open();
        scene.control.refuse_next(SubmitRefusal {
            reason: RefusalReason::QueueFull,
            code: None,
        });
        assert_eq!(scene.get(1), Some(Outcome::Complete), "the read waited");
        assert_eq!(scene.get(1), Some(Outcome::Complete));
        scene.shut_down();
    });
}

/// With every read-response buffer drawn by another holder, a GET ends `RetransmissionPressure`; once the buffers return, a GET completes. Start refuses a request table larger than the volume's read records, so a started owner keeps read-operation pressure out of reach. `Contended` requires a compare-exchange lost to a concurrent thread. Receive pressure is the client's own `GetRefused::ReceivePressure`, covered above.
#[test]
fn the_response_buffers_recover_once_returned() {
    scene(8, |mut scene| {
        scene.open();
        let drawn: Vec<_> =
            std::iter::from_fn(|| scene.buffers.acquire(PoolKind::ReadResponse).ok()).collect();
        assert!(!drawn.is_empty());
        assert_eq!(
            scene.get(1),
            Some(Outcome::Pressure(Status::RetransmissionPressure))
        );
        drop(drawn);
        assert_eq!(
            scene.get(1),
            Some(Outcome::Complete),
            "the buffers returned"
        );
        scene.shut_down();
    });
}

/// A path that loses every datagram toward the client spends the GET's attempts, ending it `Failed(OwnerUnavailable)` with no fragment handed out; once the path heals, a GET of the same key completes with exact bytes.
#[test]
fn a_reject_all_schedule_yields_no_success_and_heals() {
    scene(8, |mut scene| {
        scene.open();
        let lost = Faults {
            loss: 100,
            ..Faults::default()
        };
        scene.nets[0].borrow_mut().set_faults(0, lost);
        let id = scene.issue(1).unwrap();
        let mut held = Vec::new();
        let outcome = scene.finish(id, &mut held);
        assert!(
            matches!(outcome, Some(Outcome::Failed(Status::OwnerUnavailable))),
            "{outcome:?}"
        );
        assert!(held.is_empty(), "nothing arrived");
        scene.nets[0].borrow_mut().set_faults(0, Faults::default());
        scene.settle();
        if scene.client.state() != SessionState::Active {
            scene.open();
        }
        assert_eq!(scene.get(1), Some(Outcome::Complete), "the path healed");
        scene.shut_down();
    });
}

/// Every PUT kind, sealed under the client's live session and its key and naming the live GET's request, moves only the owner's drop counter and `wrong_operation`: the four PUTs that reach admission count four `wrong_operation`, the peer's PUT permission check answers `PermissionDenied`, and the volume's write counters stay put. A replayed PUT BEGIN sequence drops at the session with `wrong_operation` unchanged. Two fresh GETs reuse the PUT BEGIN and PUT AUTHORITY sequences; together they produce one drop and one request start. A PUT DATA body altered with its crc32c kept drops and leaves its sequence unseen, and the GET sent beside them completes with exact bytes. Once the GET ends, a PUT BEGIN naming its retained row counts one `wrong_operation` before and after the row expires and leaves the census unchanged; under a renewed session the same PUT BEGIN drops with `wrong_operation` unchanged.
#[test]
fn put_frames_naming_get_identities_move_only_counters() {
    scene(8, |mut scene| {
        scene.open();
        let crc = Crc32c::detect();
        let id = scene.issue(1).unwrap();
        scene.client.poll(scene.turn * 100);
        let get = scene.nets[0]
            .borrow()
            .peek(1)
            .and_then(|bytes| parse(crc, &bytes, false).ok().map(|frame| frame.header()))
            .expect("the GET toward the owner");
        assert_eq!(get.kind, Kind::Get);
        let ring = KeyRing::load(
            &PRINCIPALS[..1],
            &entries()[..1],
            1,
            &mut EngineBudget::new(1 << 20),
        )
        .unwrap();
        let sealed = |header: &Header, body: &[u8]| {
            let mut encoded = [0u8; HEADER_LEN];
            encode(crc, header, [body, &[]], &mut encoded).unwrap();
            let input = mac_input_for(
                &encoded,
                [body, &[]],
                OWNER.endpoint,
                Direction::ClientToOwner,
            )
            .unwrap();
            let tag = ring.tag(PeerId(0), &input).unwrap();
            seal(&mut encoded, tag);
            let mut datagram = encoded.to_vec();
            datagram.extend_from_slice(body);
            datagram
        };
        // Turns the owner alone until the link toward it is empty, returning the received, dropped and request count changes; one receive batch holds eight datagrams.
        let drain = |scene: &mut Scene<'_, '_>| {
            let (report, requests) = (scene.owner.report(), scene.owner.serve_report().requests);
            while scene.nets[0].borrow().pending(1) > 0 {
                let turn = scene.turn;
                round(&mut [
                    Act::new(Actor::Link(0), &mut || {
                        scene.nets[0].borrow_mut().advance(turn)
                    }),
                    Act::new(Actor::Disk(0), &mut || scene.control.tick(64)),
                    Act::new(Actor::Owner(0), &mut || scene.owner.poll(turn * 100)),
                ]);
                scene.turn += 1;
            }
            let after = scene.owner.report();
            (
                after.received - report.received,
                after.dropped - report.dropped,
                scene.owner.serve_report().requests - requests,
            )
        };
        let mut forged = 0;
        for (kind, at) in Kind::ALL.into_iter().filter(|kind| kind.is_put()).zip(1..) {
            let base = Header {
                sequence: get.sequence + at,
                ..get
            };
            let (put, body) = put_frame(kind, &base);
            scene.nets[0].borrow_mut().inject(1, &sealed(&put, &body));
            forged += 1;
        }
        let volume = scene.owner.volume_report();
        let wrong_before = scene.owner.report().wrong_operation;
        assert_eq!(
            scene.owner.put_permission(PeerId(0)),
            Err(Status::PermissionDenied)
        );
        assert_eq!(
            drain(&mut scene),
            (forged + 1, forged - 3, 1),
            "only the GET started a request, and the owner accepted the three PUT kinds it serves"
        );
        assert_eq!(scene.owner.report().wrong_operation - wrong_before, 4);
        let (repeat, body) = put_frame(
            Kind::PutBegin,
            &Header {
                sequence: get.sequence + 1,
                ..get
            },
        );
        let before = scene.owner.report().wrong_operation;
        scene.nets[0]
            .borrow_mut()
            .inject(1, &sealed(&repeat, &body));
        assert_eq!(drain(&mut scene), (1, 1, 0));
        assert_eq!(scene.owner.report().wrong_operation, before);
        let reads = scene.owner.volume_report();
        assert_eq!(
            (reads.writes_submitted, reads.writes_refused),
            (volume.writes_submitted, volume.writes_refused),
            "no PUT frame reached the volume"
        );
        // Admission recorded the sequences of the four PUT kinds a client sends, PUT BEGIN's among them; dispatch drops the kinds sent the wrong way, PUT AUTHORITY's among them, before admission sees their sequences.
        let fresh = |slot: u64, sequence: u64| Header {
            request: slot << 48 | 1,
            sequence,
            // A key the owner never published, so each admitted GET ends at its lookup.
            key: key(9),
            ..get
        };
        let at_begin = sealed(&fresh(1, get.sequence + 1), &[]);
        let at_authority = sealed(&fresh(2, get.sequence + 2), &[]);
        scene.nets[0].borrow_mut().inject(1, &at_begin);
        scene.nets[0].borrow_mut().inject(1, &at_authority);
        assert_eq!(drain(&mut scene), (2, 1, 1));
        // A PUT DATA body changed so that its crc32c holds fails its tag at the endpoint, and its sequence stays unseen.
        let (data, body) = put_frame(
            Kind::PutData,
            &Header {
                sequence: get.sequence + 10,
                ..get
            },
        );
        let mut altered = sealed(&data, &body);
        for (byte, delta) in altered[HEADER_LEN + 20..]
            .iter_mut()
            .zip([0xF1, 0x76, 0xEC, 0x05, 0x01])
        {
            *byte ^= delta;
        }
        assert!(parse(crc, &altered, false).unwrap().check_body(crc).is_ok());
        scene.nets[0].borrow_mut().inject(1, &altered);
        assert_eq!(drain(&mut scene), (1, 1, 0));
        scene.nets[0]
            .borrow_mut()
            .inject(1, &sealed(&fresh(3, get.sequence + 10), &[]));
        assert_eq!(drain(&mut scene), (1, 0, 1), "the sequence stayed unseen");
        let mut held = Vec::new();
        assert_eq!(scene.finish(id, &mut held), Some(Outcome::Complete));
        assert_eq!(joined(&held), object(1));
        drop(held);
        // A generated order can deliver the COMPLETE in the round the owner
        // sends it, before the owner's next turn releases the ended GET, so
        // the scene turns, bounded, until that release.
        crate::sim::round::catch_up(|| {
            scene.owner.census().live() == 0 || {
                scene.turns(1);
                false
            }
        });
        for (sequence, expired) in [(100, false), (101, true)] {
            if expired {
                scene.turn +=
                    (u64::from(get.remaining_ms) * 1000 + OWNER.serve.linger_us) / 100 + 1;
            }
            let (put, body) = put_frame(
                Kind::PutBegin,
                &Header {
                    sequence: get.sequence + sequence,
                    ..get
                },
            );
            let before = scene.owner.report().wrong_operation;
            let census = scene.owner.census();
            assert_eq!(census.live(), 0);
            scene.nets[0].borrow_mut().inject(1, &sealed(&put, &body));
            assert_eq!(drain(&mut scene), (1, 0, 0));
            assert_eq!(scene.owner.report().wrong_operation, before + 1);
            assert_eq!(scene.owner.census(), census);
        }
        scene.open();
        let _ = scene.issue(2).unwrap();
        scene.client.poll(scene.turn * 100);
        let renewed = scene.nets[0]
            .borrow()
            .peek(1)
            .and_then(|bytes| parse(crc, &bytes, false).ok().map(|frame| frame.header()))
            .unwrap();
        assert_ne!(renewed.epoch, get.epoch);
        scene.nets[0].borrow_mut().clear(1);
        let (put, body) = put_frame(
            Kind::PutBegin,
            &Header {
                request: get.request,
                sequence: renewed.sequence + 1,
                ..renewed
            },
        );
        let before = scene.owner.report().wrong_operation;
        scene.nets[0].borrow_mut().inject(1, &sealed(&put, &body));
        assert_eq!(drain(&mut scene), (1, 0, 0));
        assert_eq!(scene.owner.report().wrong_operation, before);
        assert_eq!(scene.owner.census().live(), 0, "the BEGIN acquired nothing");
        scene.shut_down();
    });
}

/// An authenticated COMPLETE for a running GET, sealed under the owner's key and admitted by the client's session before any fragment arrived, ends nothing: the GET completes only after every fragment and the owner's own COMPLETE, with exact bytes.
#[test]
fn an_early_complete_never_completes_a_get() {
    scene(8, |mut scene| {
        scene.open();
        let crc = Crc32c::detect();
        let kind_of = |bytes: &[u8]| parse(crc, bytes, false).ok().map(|frame| frame.header());
        let id = scene.issue(1).unwrap();
        let mut start = None;
        for _ in 0..5_000 {
            let (turn, net) = (scene.turn, &scene.nets[0]);
            let now = turn * 100;
            round(&mut [
                Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
                Act::new(Actor::Client(0), &mut || {
                    let _ = scene.client.poll(now);
                }),
                Act::new(Actor::Disk(0), &mut || scene.control.tick(64)),
                // The owner's DATA leaves the link toward the client right
                // after the turn that sends it, before the client can take
                // it, and its START is recorded there.
                Act::new(Actor::Owner(0), &mut || {
                    scene.owner.poll(now);
                    net.borrow_mut().retain(0, |bytes| {
                        let header = kind_of(bytes);
                        if let Some(header) = header.filter(|header| header.kind == Kind::Start) {
                            start = Some(header);
                        }
                        header.is_none_or(|header| header.kind != Kind::Data)
                    });
                }),
            ]);
            scene.turn += 1;
            if start.is_some() {
                break;
            }
        }
        let start: Header = start.expect("the owner sent START");
        let forged = Header {
            kind: Kind::Complete,
            index: start.count,
            sequence: start.sequence + 1,
            ..start
        };
        let mut encoded = [0u8; HEADER_LEN];
        encode(crc, &forged, [&[], &[]], &mut encoded).unwrap();
        let ring = KeyRing::load(
            &PRINCIPALS[..1],
            &entries()[..1],
            1,
            &mut EngineBudget::new(1 << 20),
        )
        .unwrap();
        let input = mac_input_for(
            &encoded,
            [&[], &[]],
            OWNER.endpoint,
            Direction::OwnerToClient,
        )
        .unwrap();
        let tag = ring.tag(PeerId(0), &input).unwrap();
        seal(&mut encoded, tag);
        scene.nets[0].borrow_mut().inject(0, &encoded);
        let turn = scene.turn;
        for at in turn..turn + 4 {
            round(&mut [
                Act::new(Actor::Harness(0), &mut || {
                    scene.nets[0].borrow_mut().retain(0, |bytes| {
                        kind_of(bytes).is_none_or(|header| header.kind != Kind::Data)
                    });
                }),
                Act::new(Actor::Link(0), &mut || {
                    scene.nets[0].borrow_mut().advance(at)
                }),
                Act::new(Actor::Client(0), &mut || {
                    let report = scene.client.poll(at * 100);
                    assert_eq!(
                        report.dropped, 0,
                        "every frame, the forged COMPLETE among them, was admitted"
                    );
                }),
            ]);
        }
        assert_eq!(
            scene.nets[0].borrow().pending(0),
            0,
            "the client received the forged COMPLETE"
        );
        assert_eq!(
            scene.client.outcome(id),
            None,
            "a COMPLETE before every fragment ends nothing"
        );
        scene.turn = turn + 4;
        let mut held = Vec::new();
        assert_eq!(scene.finish(id, &mut held), Some(Outcome::Complete));
        assert_eq!(joined(&held), object(1));
        scene.shut_down();
    });
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_get_completes_while_another_registration_holds_every_lease_credit,
    a_get_whose_device_queue_was_full_waits_and_completes,
    a_reject_all_schedule_yields_no_success_and_heals,
    an_early_complete_never_completes_a_get,
    put_frames_naming_get_identities_move_only_counters,
    the_client_closes_from_every_state,
    the_peers_share_recovers_once_its_reads_finish,
);
