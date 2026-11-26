//! A session replacement ends the replaced session's requests on the owner
//! at once, and each keeps its slot and share until its own read or write returns.
//!
//! Every replacement here is opened by the same client, so it carries the same boot nonce as the session
//! it replaces; each run records the nonce and the owner's session epoch on both sides of the replacement
//! as its premise.
//!
//! - `a_same_boot_replacement_ends_the_get_and_its_held_read_drains_before_a_successor_is_served`: a GET
//!   whose first owner read the device holds, so no byte reached the client, then the replacement. Right
//!   after it the client's GET has ended `Failed(SessionMismatch)` and the owner's census shows no active
//!   request and one draining. Once the
//!   device returns the read the census is empty, and a successor on the same wire slot is served the
//!   object's exact bytes.
//! - `without_a_replacement_the_get_stays_active_through_its_held_read_and_completes`: the comparison. The
//!   same steps without the replacement: the GET stays active and undecided while its read is held, and
//!   completes with the object's exact bytes once the read returns.
//! - `a_same_boot_replacement_ends_the_upload_and_its_held_writes_keep_its_share_until_they_return`: an
//!   upload with both fragments accepted and both device writes held, then the replacement. Right after it
//!   the peer has no active request and one draining, still charged to the peer's PUT share; once the
//!   writes return the charge and the request are gone.
//!
//! Each run decides what it saw into a value, lets its fixtures go, and asserts afterwards, so a failed
//! expectation ends in the test's own result line.

use crate::storage::EngineBudget;
use crate::storage::owner_fixture::{arena, storage};

use super::datagram::PeerId;
use super::fetch::{Outcome, Releases};
use super::frame::Status;
use super::geometry::FRAGMENT_LEN;
use super::link::{Faults, network};
use super::owner_tests::{
    OWNER, PRINCIPALS, client, collect, drive, hold_next_read, key, open, payload, pool, start,
};
use super::put_tests::{request, scene_with, send_all, upload_at};
use super::requests::RequestCensus;

/// What one GET run saw.
#[derive(Debug)]
struct Seen {
    /// The owner's census with the GET's first read held by the device, before any replacement.
    held: RequestCensus,
    /// Whether the client's boot nonce is the same after the step that may replace the session.
    same_boot: bool,
    /// The owner's epochs of the peer's session before and after that step.
    epochs: (Option<u64>, Option<u64>),
    /// The GET's outcome and the owner's census right after that step, with the read still held.
    after: (Option<Outcome>, RequestCensus),
    /// The owner's census once the device returned the read and the owner was driven on.
    returned: RequestCensus,
    /// The GET's final outcome and whether the bytes it delivered are the published object.
    first: (Option<Outcome>, bool),
    /// For a replaced GET: whether its successor took the same wire slot, the successor's outcome, and
    /// whether its bytes are the published object.
    successor: Option<(bool, Option<Outcome>, bool)>,
}

const PEER: PeerId = PeerId(0);

/// One GET of a multi-chunk object whose first owner read the device holds. With `replace` the client
/// then opens a new session; without it the owner is driven for as many turns with nothing else
/// happening. The read is then released.
fn get_with_a_held_read(replace: bool) -> Seen {
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
    let first = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (token, turn) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
    let held = owner.census();
    let nonce = client.boot_nonce();
    let epoch = owner.session_epoch(PEER);
    let turn = if replace {
        open(&mut client, &mut owner, &control, &nets, turn)
    } else {
        drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            50,
            |_| false,
        )
    };
    let same_boot = client.boot_nonce() == nonce;
    let epochs = (epoch, owner.session_epoch(PEER));
    let after = (client.outcome(first), owner.census());
    // The device returns the held read. A replaced GET is driven until the owner's census is empty, an
    // undisturbed one until the client decided it.
    control.release(token);
    let mut bytes = Vec::new();
    let mut turn = turn;
    for _ in 0..5_000 {
        turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            1,
            |_| false,
        );
        collect(&mut client, first, &mut bytes);
        let settled = if replace {
            owner.census().live() == 0
        } else {
            client.outcome(first).is_some()
        };
        if settled {
            break;
        }
    }
    if !replace {
        // The owner's record of a completed GET leaves once its last ACK and references returned.
        turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            50,
            |_| false,
        );
    }
    collect(&mut client, first, &mut bytes);
    let returned = owner.census();
    let outcome = client.outcome(first);
    let successor = replace.then(|| {
        let retired = client.retire(first);
        let next = client
            .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
            .unwrap();
        let mut bytes = Vec::new();
        drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            5_000,
            |clients| {
                collect(clients[0], next, &mut bytes);
                clients[0].outcome(next).is_some()
            },
        );
        collect(&mut client, next, &mut bytes);
        (
            retired && next.slot() == first.slot(),
            client.outcome(next),
            bytes == object,
        )
    });
    Seen {
        held,
        same_boot,
        epochs,
        after,
        returned,
        first: (outcome, bytes == object),
        successor,
    }
}

const ONE_ACTIVE: RequestCensus = RequestCensus {
    active: 1,
    draining: 0,
    retired: 0,
};
const ONE_DRAINING: RequestCensus = RequestCensus {
    active: 0,
    draining: 1,
    retired: 0,
};
const EMPTY: RequestCensus = RequestCensus {
    active: 0,
    draining: 0,
    retired: 0,
};

#[test]
fn a_same_boot_replacement_ends_the_get_and_its_held_read_drains_before_a_successor_is_served() {
    let seen = get_with_a_held_read(true);
    assert_eq!(
        seen.held, ONE_ACTIVE,
        "premise: the GET is the owner's one active request while the device holds its read: {seen:?}"
    );
    assert!(
        seen.same_boot && seen.epochs.0.is_some() && seen.epochs.1 > seen.epochs.0,
        "premise: the owner activated a later session of the same client boot nonce: {seen:?}"
    );
    assert_eq!(
        seen.after.0,
        Some(Outcome::Failed(Status::SessionMismatch)),
        "the replaced GET, which had handed out no byte, ended SessionMismatch at the client: {seen:?}"
    );
    assert_eq!(
        seen.after.1, ONE_DRAINING,
        "right after the replacement the owner holds no active request of the replaced session, and the \
         held read keeps its request draining: {seen:?}"
    );
    assert_eq!(
        seen.returned, EMPTY,
        "the request left the census once the device returned its read: {seen:?}"
    );
    assert_eq!(
        seen.successor,
        Some((true, Some(Outcome::Complete), true)),
        "a successor on the same wire slot is served the object's exact bytes: {seen:?}"
    );
}

#[test]
fn without_a_replacement_the_get_stays_active_through_its_held_read_and_completes() {
    let seen = get_with_a_held_read(false);
    assert_eq!(
        seen.held, ONE_ACTIVE,
        "premise: the GET is the owner's one active request while the device holds its read: {seen:?}"
    );
    assert!(
        seen.same_boot && seen.epochs.0.is_some() && seen.epochs.1 == seen.epochs.0,
        "premise: the session was not replaced: {seen:?}"
    );
    assert_eq!(
        seen.after,
        (None, ONE_ACTIVE),
        "the GET stays undecided and active while its read is held: {seen:?}"
    );
    assert_eq!(
        seen.first,
        (Some(Outcome::Complete), true),
        "the GET completes with the object's exact bytes once the read returns: {seen:?}"
    );
    assert_eq!(
        seen.returned, EMPTY,
        "the completed GET left the census: {seen:?}"
    );
}

/// What the upload run saw of peer 1: its active and draining requests and its PUT charge.
#[derive(Debug, Default)]
struct Upload {
    /// With both fragments accepted and both device writes held, before the replacement.
    held: (u32, u32, u32),
    same_boot: bool,
    epochs: (Option<u64>, Option<u64>),
    /// Right after the replacement, with the writes still held.
    after: (u32, u32, u32),
    /// The peer's active requests, its draining requests and its PUT charge after the device completed both writes.
    returned: (u32, u32, u32),
    /// The owner's count of live PUTs over every peer after the device completed both writes.
    live: u32,
}

#[test]
fn a_same_boot_replacement_ends_the_upload_and_its_held_writes_keep_its_share_until_they_return() {
    const UPLOADER: PeerId = PeerId(1);
    let mut seen = None;
    scene_with(OWNER, &PRINCIPALS, |mut scene| {
        let object = payload(2 * FRAGMENT_LEN as usize, 71);
        let (at, serial) = upload_at(&mut scene, request(3, 1), &object, 60_000);
        let writes = send_all(&mut scene, at, serial, &object, 0..2);
        for &token in &writes {
            scene.control.hold(token);
        }
        let charged = |scene: &super::put_tests::Scene<'_, '_>| {
            let census = scene.owner.peer_census(UPLOADER);
            (
                census.active,
                census.draining,
                scene.owner.put_occupancy().peers[1],
            )
        };
        let held = charged(&scene);
        let nonce = scene.clients[1].boot_nonce();
        let epoch = scene.owner.session_epoch(UPLOADER);
        scene.reopen(1);
        let same_boot = scene.clients[1].boot_nonce() == nonce && writes.len() == 2;
        let epochs = (epoch, scene.owner.session_epoch(UPLOADER));
        let after = charged(&scene);
        for &token in &writes {
            scene.control.release(token);
        }
        scene.turns(20);
        seen = Some(Upload {
            held,
            same_boot,
            epochs,
            after,
            returned: charged(&scene),
            live: scene.owner.put_occupancy().live,
        });
    });
    let seen = seen.expect("the scene ran its body");
    assert_eq!(
        seen.held,
        (1, 0, 1),
        "premise: the upload is the peer's one active request, charged to its PUT share, with both \
         writes held: {seen:?}"
    );
    assert!(
        seen.same_boot && seen.epochs.0.is_some() && seen.epochs.1 > seen.epochs.0,
        "premise: the owner activated a later session of the same client boot nonce over two held \
         writes: {seen:?}"
    );
    assert_eq!(
        seen.after,
        (0, 1, 1),
        "right after the replacement the peer has no active request, and the upload drains with its \
         share still charged: {seen:?}"
    );
    assert_eq!(
        (seen.returned, seen.live),
        ((0, 0, 0), 0),
        "the upload, its charge to the peer's PUT share and the owner's live PUT left once the device \
         returned its writes: {seen:?}"
    );
}
