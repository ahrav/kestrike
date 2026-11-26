//! At the watermark, a retained row of another operation yields `Route::WrongOperation`;
//! `Namespace::route` increments its counter and every other field stays unchanged. Rows keep their
//! operation through expiry.
//!
//! The scenario runs a client and an owner over one clean simulated link and a simulated disk, built from
//! the fixtures of `net::owner_tests` as `net::lifecycle_tests` builds its scene. The client's GET of key 1
//! completes and the owner releases it, which leaves the GET's retained row on its wire slot with no live
//! record. The scenario then injects PUT BEGIN, PUT PREPARE and PUT CANCEL frames, sealed under the
//! client's key and its live session, each with a sequence the session has not seen. It injects the three
//! kinds first while the row's evidence is current and again after the turn time passed the row's
//! `expires_us`. The owner alone turns until it has taken each frame.
//!
//! - `put_frames_at_a_retained_get_row_move_only_the_wrong_operation_counter`: the frames carry the GET's
//!   wire request. After each frame `Owner::request_slot` of the GET's slot, the request census, the PUT
//!   report, the owner's sent count and the frames queued toward the client equal their values before it,
//!   and `OwnerReport::wrong_operation` rose by exactly one.
//! - `put_frames_at_an_unused_identity_leave_the_wrong_operation_counter`: the comparison. The same steps
//!   with frames that carry generation 1 of the next wire slot, which no request used. The counter stays
//!   where it was and the GET's slot keeps its row.
//!
//! Premises, which fail a test under the word "premise": the GET completed and left a retained row with no
//! binding, the owner received each frame and dropped none, and each frame met the row before or after
//! `expires_us` as its phase says. Each run decides its observations into values, shuts the owner down and
//! lets every fixture go before a test asserts.

use std::cell::RefCell;
use std::rc::Rc;

use crate::sim::round::{Act, Actor, round};
use crate::storage::owner_fixture::{SimControl, arena, storage};
use crate::storage::{Crc32c, EngineBudget};

use super::auth::KeyRing;
use super::client::{Client, ClientMemory};
use super::datagram::{HEADER_LEN, PeerId};
use super::fetch::{Outcome, Releases};
use super::frame::{Direction, Header, Kind, encode, mac_input_for, parse, seal};
use super::frame_tests::put_frame;
use super::link::{Faults, Net, network};
use super::owner_tests::{
    OWNER, PRINCIPALS, TestOwner, client_config, drive, entries, key, open, payload, pool, start,
};
use super::requests::{RequestId, RequestTable};

/// The PUT kinds the tests send.
const KINDS: [Kind; 3] = [Kind::PutBegin, Kind::PutPrepare, Kind::PutCancel];

/// The first sequence the injected frames carry past the GET's own, above every frame the client sent
/// for the GET.
const SEQUENCE_GAP: u64 = 100;

/// Owner turns that run with nothing injected before each frame's values are read.
const IDLE_TURNS: u64 = 4;

/// The wire request the injected frames carry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Named {
    /// The ended GET's own wire request.
    RetainedGet,
    /// Generation 1 of the wire slot after the GET's, which no request used.
    Unused,
}

/// What one injected frame showed.
#[derive(Debug)]
struct Frame {
    kind: Kind,
    /// The frame belongs to the phase past the row's `expires_us`.
    expired: bool,
    /// The GET's slot held a retained row and no binding before the frame.
    retained: bool,
    /// Every turn that could take the frame ran on the side of `expires_us` its phase names.
    timed: bool,
    /// The owner's received and dropped counts rose by one and by zero.
    arrived: bool,
    /// The rise of `OwnerReport::wrong_operation`.
    wrong: u64,
    /// Each compared value that differs from its value before the frame.
    changed: Vec<&'static str>,
}

/// What one run showed.
#[derive(Debug)]
struct Run {
    /// The setup premises that did not form.
    unformed: Vec<&'static str>,
    frames: Vec<Frame>,
}

/// The values the tests compare around each frame.
#[derive(PartialEq, Eq)]
struct Values {
    slot: String,
    census: super::requests::RequestCensus,
    put: super::put::PutReport,
    sent: u64,
    queued: usize,
}

fn values(owner: &TestOwner<'_, '_, '_>, net: &Rc<RefCell<Net<'_>>>, slot: u16) -> Values {
    Values {
        slot: format!("{:?}", owner.request_slot(PeerId(0), slot)),
        census: owner.census(),
        put: owner.put_report(),
        sent: owner.report().sent,
        queued: net.borrow().pending(0),
    }
}

/// One round of the link, the device and the owner at `turn`; the client does not run.
fn owner_turn(
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    net: &Rc<RefCell<Net<'_>>>,
    turn: u64,
) {
    round(&mut [
        Act::new(Actor::Link(0), &mut || net.borrow_mut().advance(turn)),
        Act::new(Actor::Disk(0), &mut || control.tick(64)),
        Act::new(Actor::Owner(0), &mut || owner.poll(turn * 100)),
    ]);
}

/// Runs the scenario with frames that carry the wire request `named` and returns what it showed, after
/// the owner shut down and every fixture ended.
fn run(named: Named) -> Run {
    let mut unformed = Vec::new();
    let mut frames = Vec::new();
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let object = payload(30_000, 1);
    let published = [(key(1), 0, object.as_slice())];
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 77, [Faults::default(); 2]);
    let (mut owner, control) = start(&storage, &buffers, &receive, &published, vec![owner_end]);
    let mut config = client_config(0);
    config.fetch.boxes = 24;
    let memory = ClientMemory {
        receive: &client_pool,
        releases: &releases,
        requests: RequestTable::new(4, 1, 4),
        sources: Box::default(),
        routes: super::client_tests::routes(),
    };
    let mut client = Client::initialize(
        config,
        memory,
        client_end,
        &entries()[..1],
        1,
        &mut EngineBudget::new(1 << 24),
    )
    .unwrap();
    let nets = [net];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);

    // The GET, whose first frame gives the session and request fields the injected frames keep.
    let crc = Crc32c::detect();
    let id = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .expect("the client admits the GET");
    client.poll(turn * 100);
    let get = nets[0]
        .borrow()
        .peek(1)
        .and_then(|bytes| parse(crc, &bytes, false).ok().map(|frame| frame.header()))
        .expect("the GET toward the owner");
    let mut delivered = 0;
    turn = drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        20_000,
        |clients| {
            while let Some(fragment) = clients[0].take(id) {
                delivered += fragment.bytes().len();
            }
            clients[0].outcome(id).is_some()
        },
    );
    if get.kind != Kind::Get
        || client.outcome(id) != Some(Outcome::Complete)
        || delivered != object.len()
        || !client.retire(id)
    {
        unformed.push("the GET completed with every byte and retired");
    }
    // The owner releases the ended GET on a turn after it sent the COMPLETE, and the client's last
    // frames reach it: both ends turn until the owner holds no live request and the link is empty.
    let quiet = |owner: &TestOwner<'_, '_, '_>| {
        owner.census().live() == 0
            && nets[0].borrow().pending(0) == 0
            && nets[0].borrow().pending(1) == 0
    };
    for _ in 0..20_000 {
        if quiet(&owner) {
            break;
        }
        turn = drive(
            &mut [&mut client],
            &mut owner,
            &control,
            &nets,
            turn,
            1,
            |_| false,
        );
    }
    if !quiet(&owner) {
        unformed.push("the owner released the GET and the link emptied");
    }

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
    let slot = RequestId::from_wire(get.request).slot();
    let request = match named {
        Named::RetainedGet => get.request,
        Named::Unused => u64::from((slot + 1) % 4) << 48 | 1,
    };
    let mut sequence = get.sequence + SEQUENCE_GAP;
    for expired in [false, true] {
        for kind in KINDS {
            let row = owner.request_slot(PeerId(0), slot);
            let expires_us = row
                .and_then(|row| row.cached)
                .map(|cached| cached.expires_us);
            let retained = row.is_some_and(|row| row.active.is_none() && row.cached.is_some());
            if expired {
                // The first turn whose time is past the row's expiry, when the scenario is not there yet.
                turn = turn.max(expires_us.unwrap_or(0) / 100 + 1);
            }
            for _ in 0..IDLE_TURNS {
                owner_turn(&mut owner, &control, &nets[0], turn);
                turn += 1;
            }
            let before = values(&owner, &nets[0], slot);
            let report = owner.report();
            let first_us = turn * 100;
            let base = Header {
                request,
                sequence,
                ..get
            };
            sequence += 1;
            let (put, body) = put_frame(kind, &base);
            nets[0].borrow_mut().inject(1, &sealed(&put, &body));
            for _ in 0..64 {
                if nets[0].borrow().pending(1) == 0 {
                    break;
                }
                owner_turn(&mut owner, &control, &nets[0], turn);
                turn += 1;
            }
            let last_us = (turn - 1) * 100;
            let after = values(&owner, &nets[0], slot);
            let ended = owner.report();
            let mut changed = Vec::new();
            for (name, same) in [
                ("the request slot", before.slot == after.slot),
                ("the request census", before.census == after.census),
                ("the PUT report", before.put == after.put),
                ("the owner's sent count", before.sent == after.sent),
                (
                    "the frames queued toward the client",
                    before.queued == after.queued,
                ),
            ] {
                if !same {
                    changed.push(name);
                }
            }
            frames.push(Frame {
                kind,
                expired,
                retained,
                timed: expires_us.is_some_and(|expires_us| {
                    if expired {
                        expires_us <= first_us
                    } else {
                        last_us < expires_us
                    }
                }),
                arrived: nets[0].borrow().pending(1) == 0
                    && ended.received == report.received + 1
                    && ended.dropped == report.dropped,
                wrong: ended.wrong_operation - report.wrong_operation,
                changed,
            });
        }
    }

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
    if owner.shutdown().is_err() {
        unformed.push("the owner drained and shut down");
    }
    drop(client);
    Run { unformed, frames }
}

/// The setup premises of `run` that did not form, with each frame whose own premises did not form. A run
/// that did not inject the three kinds in each phase, current first, is unformed as a whole.
fn unformed(run: &Run) -> Vec<String> {
    let injected: Vec<(Kind, bool)> = run
        .frames
        .iter()
        .map(|frame| (frame.kind, frame.expired))
        .collect();
    let planned: Vec<(Kind, bool)> = [false, true]
        .into_iter()
        .flat_map(|expired| KINDS.map(|kind| (kind, expired)))
        .collect();
    let order = (injected != planned).then(|| format!("the run injected {injected:?}"));
    let frames = run
        .frames
        .iter()
        .filter(|frame| !(frame.retained && frame.timed && frame.arrived))
        .map(|frame| format!("{frame:?}"));
    run.unformed
        .iter()
        .map(|premise| premise.to_string())
        .chain(order)
        .chain(frames)
        .collect()
}

/// A PUT BEGIN, PUT PREPARE and PUT CANCEL at the wire identity of an ended GET's retained row, while the
/// row's evidence is current and after it expired: each changes nothing the tests compare and
/// raises `wrong_operation` by exactly one.
#[test]
fn put_frames_at_a_retained_get_row_move_only_the_wrong_operation_counter() {
    let run = run(Named::RetainedGet);
    let unformed = unformed(&run);
    assert!(unformed.is_empty(), "premise: {unformed:?}");
    let moved: Vec<&Frame> = run
        .frames
        .iter()
        .filter(|frame| frame.wrong != 1 || !frame.changed.is_empty())
        .collect();
    assert!(
        moved.is_empty(),
        "a PUT frame at a retained GET row drew an answer or moved more than the wrong-operation \
         counter: {moved:?}"
    );
}

/// The comparison: the same frames at an identity no request used leave `wrong_operation` where it was and
/// the GET's slot with its row.
#[test]
fn put_frames_at_an_unused_identity_leave_the_wrong_operation_counter() {
    let run = run(Named::Unused);
    let unformed = unformed(&run);
    assert!(unformed.is_empty(), "premise: {unformed:?}");
    let moved: Vec<&Frame> = run
        .frames
        .iter()
        .filter(|frame| frame.wrong != 0 || frame.changed.contains(&"the request slot"))
        .collect();
    assert!(
        moved.is_empty(),
        "a PUT frame at an unused identity counted a wrong operation or changed the GET's slot: \
         {moved:?}"
    );
}
