//! Session replacement with a GET's custody still out: a client fragment
//! lease, an owner read the device holds and a NIC reference on a sent reply.
//! The successor is admitted and served while that custody remains, and the
//! old custody ends only through its own release and return, charging the old
//! request alone. The PUT counterparts are
//! `put_tests::a_replaced_upload_drains_its_own_writes_while_a_successor_publishes_beside_it`
//! and
//! `upload_tests::a_replaced_uploads_device_held_source_outlives_the_replacement_and_its_successor`.

use crate::sim::round::{Act, Actor, round};
use crate::storage::owner_fixture::{arena, storage};
use crate::storage::{Crc32c, EngineBudget};

use super::datagram::PeerId;
use super::fetch::{Outcome, Releases};
use super::frame::{Kind, Status, parse};
use super::geometry::FRAGMENT_LEN;
use super::link::{Faults, TxRelease, network};
use super::owner_tests::{
    OWNER, PRINCIPALS, client, collect, drive, hold_next_read, key, open, payload, pool, start,
};
use super::put_tests::{error, request, scene_with, send_all, upload_at};
use super::reserve_tests::audited;

/// A GET whose fragment the application holds, whose next read the device
/// holds and whose sent reply the NIC still references, through a session
/// replacement: the replaced request ends `SessionMismatch` and keeps its slot
/// and share while the read is out; a successor on the same key is admitted
/// and served to exact bytes beside that draining custody; the device's return
/// ends the old read's custody; the held fragment keeps its bytes and charges
/// one reserved box until the application drops it.
#[test]
fn a_successor_is_served_while_the_replaced_requests_fragment_read_and_reference_stay_held() {
    let object = payload(30_000, 41);
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 41, [Faults::default(); 2]);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    let replaced = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    // The first read is held until the NIC withholds its returns, so the first
    // chunk's reply keeps a NIC reference; a later read is then held and the
    // application keeps the first fragment's lease.
    let (first_read, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    nets[0].borrow_mut().set_tx_release(TxRelease::Withheld);
    control.release(first_read);
    let mut stale = None;
    let mut turn = turn;
    for _ in 0..200 {
        let (now, net) = (turn * 100, &nets[0]);
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(now);
            }),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            // The old session's DATA is observed in flight right after the
            // owner's poll sends it, before the client can take it.
            Act::new(Actor::Owner(0), &mut || {
                owner.poll(now);
                stale = stale.take().or_else(|| net.borrow().peek(0));
            }),
        ]);
        turn += 1;
        if stale.is_some() {
            break;
        }
    }
    let stale = stale.expect("a datagram of the old session in flight");
    let header = parse(Crc32c::detect(), &stale, false).unwrap().header();
    assert_eq!((header.kind, header.request), (Kind::Data, replaced.wire()));
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    let mut held = None;
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        200,
        |clients| {
            held = held.take().or_else(|| clients[0].take(replaced));
            held.is_some()
        },
    );
    let fragment = held.expect("the first fragment");
    let first = fragment.bytes().to_vec();
    assert_eq!(&object[..first.len()], &first[..]);
    let nic_held = nets[0].borrow().withheld();
    assert!(nic_held > 0, "the NIC references a sent reply");
    let reserved = client.reserved();
    // The replacement ends the old request's logical work and keeps its custody.
    let turn = open(&mut client, &mut owner, &control, &nets, turn);
    assert_eq!(
        client.outcome(replaced),
        Some(Outcome::Incomplete(Status::SessionMismatch)),
        "the replaced request ends short after the bytes it handed out"
    );
    assert_eq!(owner.census().active, 0, "the replaced request ended");
    assert_eq!(
        owner.census().draining,
        1,
        "the held read keeps its slot and share"
    );
    assert_eq!(
        fragment.bytes(),
        &first[..],
        "the held fragment keeps its bytes"
    );
    assert_eq!(
        client.reserved(),
        reserved,
        "the replacement charges nothing new"
    );
    // The successor is admitted and served beside the draining custody.
    let successor = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    assert_ne!(
        successor.slot(),
        replaced.slot(),
        "the draining slot stays bound"
    );
    // The old session's DATA, redelivered now, reaches no request.
    let dropped = client.fetch_report().dropped;
    nets[0].borrow_mut().inject(0, &stale);
    // One DATA of the successor is held back on the wire right after the
    // owner's poll sends it, before the client can take it, so the successor
    // completes through its retransmission.
    let mut withheld = None;
    let mut bytes = Vec::new();
    let mut turn = turn;
    for _ in 0..5_000 {
        let (now, net) = (turn * 100, &nets[0]);
        round(&mut [
            Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
            Act::new(Actor::Client(0), &mut || {
                let _ = client.poll(now);
            }),
            Act::new(Actor::Disk(0), &mut || control.tick(64)),
            Act::new(Actor::Owner(0), &mut || {
                owner.poll(now);
                if withheld.is_none() {
                    net.borrow_mut().retain(0, |datagram| {
                        let data = parse(Crc32c::detect(), datagram, false).is_ok_and(|frame| {
                            let header = frame.header();
                            header.kind == Kind::Data
                                && header.request >> 48 == u64::from(successor.slot())
                        });
                        if data && withheld.is_none() {
                            withheld = Some(datagram.to_vec());
                        }
                        !(data && withheld.as_deref() == Some(datagram))
                    });
                }
            }),
        ]);
        turn += 1;
        collect(&mut client, successor, &mut bytes);
        if client.outcome(successor).is_some() {
            break;
        }
    }
    collect(&mut client, successor, &mut bytes);
    assert_eq!(client.outcome(successor), Some(Outcome::Complete));
    assert_eq!(bytes, object, "the successor returns its own bytes");
    let withheld = withheld.expect("a DATA of the successor held back");
    assert_eq!(
        client.fetch_report().dropped,
        dropped,
        "the stale DATA ended at the session layer"
    );
    assert_eq!(
        owner.census().draining,
        2,
        "the old read is still held, and the completed successor waits for the NIC's returns"
    );
    // The device returns the old read; the NIC still references the old
    // request's sent chunk, so the old request keeps draining.
    control.release(token);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(
        owner.census().draining,
        2,
        "the old request's NIC reference keeps it draining beside the successor"
    );
    // The NIC returns every reference: the old custody ends and the old request leaves.
    nets[0].borrow_mut().release_tx();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50,
        |_| false,
    );
    assert_eq!(owner.census().live(), 0, "the old custody drained");
    assert_eq!(fragment.bytes(), &first[..]);
    // The old request retires with its fragment out; a later request takes
    // its slot; the fragment's drop then frees the old request's one orphan
    // charge and grants the slot's new request nothing.
    assert!(client.retire(replaced));
    let later = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    assert_eq!(later.slot(), replaced.slot(), "the freed slot is reused");
    let before = client.reserved();
    drop(fragment);
    assert_eq!(
        client.reserved(),
        before - 1,
        "the drop releases one orphan charge"
    );
    let mut bytes = Vec::new();
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], later, &mut bytes);
            clients[0].outcome(later).is_some()
        },
    );
    collect(&mut client, later, &mut bytes);
    assert_eq!(client.outcome(later), Some(Outcome::Complete));
    assert_eq!(bytes, object);
    // The successor retires and a third request takes its wire slot under the
    // next generation; the successor's withheld DATA, within the session's
    // replay window and unseen by it, arrives before the third request's START
    // and reaches no request.
    assert!(client.retire(successor));
    let third = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    assert_eq!(third.slot(), successor.slot());
    let dropped = client.fetch_report().dropped;
    nets[0].borrow_mut().inject(0, &withheld);
    let turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        1,
        |_| false,
    );
    assert_eq!(
        client.fetch_report().dropped,
        dropped + 1,
        "the retired successor's DATA named no live request"
    );
    assert!(client.take(third).is_none());
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        5_000,
        |clients| {
            collect(clients[0], third, &mut bytes);
            clients[0].outcome(third).is_some()
        },
    );
    collect(&mut client, third, &mut bytes);
    assert_eq!(client.outcome(third), Some(Outcome::Complete));
    assert_eq!(bytes, object, "the third request returns its own bytes");
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_successor_is_served_while_the_replaced_requests_fragment_read_and_reference_stay_held,
);

#[test]
fn a_replaced_peer_at_its_put_cap_reads_inside_its_reserve_while_its_old_put_drains() {
    scene_with(OWNER, &PRINCIPALS, |mut scene| {
        let reached = audited(&mut scene, OWNER);
        let object = payload(2 * FRAGMENT_LEN as usize, 71);
        let (at, serial) = upload_at(&mut scene, request(3, 1), &object, 60_000);
        let writes = send_all(&mut scene, at, serial, &object, 0..2);
        for &token in &writes {
            scene.control.hold(token);
        }
        scene.reopen(1);
        let census = scene.owner.peer_census(PeerId(1));
        assert_eq!(
            (census.active, census.draining),
            (0, 1),
            "the old PUT drains"
        );
        assert_eq!(scene.owner.put_occupancy().peers[1], 1, "and stays charged");
        assert_eq!(
            scene.read(1, 1, 0),
            (Some(Outcome::Complete), payload(1000, 1)),
            "the new epoch's GET is admitted inside the reserve"
        );
        scene.refresh(1);
        let begin = scene.frame(1, Kind::PutBegin, request(2, 50), 6, |_| {});
        assert_eq!(error(&scene.one(1, &begin)), Some(Status::RequestPressure));
        scene.turns(20);
        assert_eq!(
            scene.owner.put_occupancy().peers[1],
            1,
            "the held writes keep the charge"
        );
        for &token in &writes {
            scene.control.release(token);
        }
        scene.turns(20);
        assert_eq!(
            scene.owner.put_occupancy().live,
            0,
            "the old PUT released at its writes' end"
        );
        scene.begin(1, request(2, 51), 6);
        let seen = reached.get();
        assert!(seen.peer_put_cap && seen.full_share, "{seen:?}");
    });
}
