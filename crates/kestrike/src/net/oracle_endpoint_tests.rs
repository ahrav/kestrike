//! The tests judge owner endpoint histories with the history oracle.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use crate::oracle::{
    ActionKind, Checkpoint, Custodian, Inconclusive, KeyId, Label, Obligation, Recorder,
    ReportKind, ReportState, ResourceKind, Row, Verdict, check,
};
use crate::storage::owner_fixture::{
    QuiesceMode, SimControl, TestPlatform, Unwind, arena, storage,
};
use crate::storage::{EngineBudget, Storage};

use crate::sim::round::{Act, Actor, push_each, round};

use super::adapters::{ID, fills_written, served, share, shares};
use super::client::Client;
use super::fetch::{Outcome as Fetched, Releases};
use super::link::{Faults, LinkEnd, Net, network};
use super::owner_tests::{TestOwner, client, collect, hold_next_read, key, open, pool, start};

const HELD: KeyId = KeyId(0);
const SERVED: KeyId = KeyId(1);
const A: Label = Label(1);
const HELD_LABEL: Label = Label(2);
const BOUND: u32 = 200;

pub(super) fn served_content(len: u64) -> Vec<u8> {
    Recorder::content(SERVED, A, 0, len)
}

pub(super) fn turn_both<'m>(
    clients: &mut [&mut Client<'m, LinkEnd<'m>>],
    owners: &mut [(&mut TestOwner<'_, '_, '_>, &SimControl)],
    nets: &[&Rc<RefCell<Net<'_>>>],
    turn: u64,
) {
    let now = turn * 100;
    let mut advances: Vec<_> = nets
        .iter()
        .map(|net| move || net.borrow_mut().advance(turn))
        .collect();
    let mut polls: Vec<_> = clients
        .iter_mut()
        .map(|client| {
            move || {
                let _ = client.poll(now);
            }
        })
        .collect();
    let mut owner_turns: Vec<_> = owners
        .iter_mut()
        .map(|(owner, control)| {
            let control: &SimControl = control;
            (move || control.tick(64), move || owner.poll(now))
        })
        .collect();
    let mut acts = Vec::new();
    push_each(&mut acts, Actor::Link, &mut advances);
    push_each(&mut acts, Actor::Client, &mut polls);
    for (i, (tick, poll)) in owner_turns.iter_mut().enumerate() {
        acts.push(Act::new(Actor::Disk(i as u16), tick));
        acts.push(Act::new(Actor::Owner(i as u16), poll));
    }
    round(&mut acts);
}

fn two_owners(routed: bool) -> Vec<Row> {
    let a_buffers = arena(8);
    let rows = stopped_owner_beside_a_healthy_one(&a_buffers, routed);
    assert!(
        a_buffers.release().is_err(),
        "the failed owner's arena stays held"
    );
    rows
}

fn stopped_owner_beside_a_healthy_one(
    a_buffers: &crate::storage::BufferArena<TestPlatform>,
    routed: bool,
) -> Vec<Row> {
    let held_object = Recorder::content(HELD, HELD_LABEL, 0, 30_000);
    let served_object = served_content(20_000);
    let (a_storage, a_receive) = (storage(8), pool());
    let (b_storage, b_buffers, b_receive) = (storage(8), arena(8), pool());
    let client_pool = pool();
    let releases = [
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
        Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap(),
    ];
    let (a_client_end, a_owner_end, a_net) = network(64, 8384, 41, [Faults::default(); 2]);
    let (b_client_end, b_owner_end, b_net) = network(64, 8384, 42, [Faults::default(); 2]);
    let mut rec = Recorder::new(1);
    let (_spare_client, spare_owner_end, _spare_net) =
        network(64, 8384, 45, [Faults::default(); 2]);
    let (a_ends, b_ends) = if routed {
        (vec![a_owner_end, b_owner_end], vec![spare_owner_end])
    } else {
        (vec![a_owner_end], vec![b_owner_end])
    };
    let (mut owner_a, control_a) = start(
        &a_storage,
        a_buffers,
        &a_receive,
        &[(key(1), 0, &held_object), (key(2), 0, &served_object)],
        a_ends,
    );
    assert_eq!(
        fills_written(&owner_a, &control_a).len(),
        2,
        "both preloads wrote through the device"
    );
    let mut preloaded = fills_written(&owner_a, &control_a).into_iter();
    rec.published_written(HELD, HELD_LABEL, 0, &held_object, ID, preloaded.next());
    rec.published_written(SERVED, A, 0, &served_object, ID, preloaded.next());
    let mut client_a = client(0, &client_pool, &releases[0], a_client_end);
    let b_peer = usize::from(routed);
    let mut client_b = client(b_peer, &client_pool, &releases[1], b_client_end);
    let (mut owner_b, control_b) = start(
        &b_storage,
        &b_buffers,
        &b_receive,
        &[(key(2), 0, &served_object)],
        b_ends,
    );
    let a_nets = [a_net.clone()];
    let mut turn = open(&mut client_a, &mut owner_a, &control_a, &a_nets, 0);
    if routed {
        let nets = [a_net.clone(), b_net.clone()];
        turn = open(&mut client_b, &mut owner_a, &control_a, &nets, turn);
    } else {
        turn = open(
            &mut client_b,
            &mut owner_b,
            &control_b,
            std::slice::from_ref(&b_net),
            turn,
        );
    }
    let held = client_a
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    let (_token, at) = hold_next_read(&mut client_a, &mut owner_a, &control_a, &a_net, turn);
    turn = at;
    rec.take(share(0), Custodian::Storage, None);
    shares(&mut rec, &[&owner_a, &owner_b]);
    let accounts = |owner: &TestOwner<'_, '_, '_>| {
        let report = a_buffers.report(crate::storage::PoolKind::ReadResponse);
        (
            owner.census().live(),
            report.count - report.free - report.retired,
            owner.volume_report().reads_submitted,
        )
    };
    let before = accounts(&owner_a);
    assert_eq!(
        before.0, 1,
        "the failed owner holds one request at its stop"
    );
    control_a.set_quiesce(QuiesceMode::Unproven);
    let _ = owner_a.close(turn * 100);
    rec.isolated(share(0));
    let id = client_b
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    if !routed {
        rec.take(share(1), Custodian::Storage, None);
    }
    let began = turn;
    let mut bytes = Vec::new();
    while turn < began + u64::from(BOUND) {
        turn_both(
            &mut [&mut client_a, &mut client_b],
            &mut [(&mut owner_a, &control_a), (&mut owner_b, &control_b)],
            &[&a_net, &b_net],
            turn,
        );
        turn += 1;
        collect(&mut client_b, id, &mut bytes);
        assert_eq!(
            owner_a.census().live(),
            1,
            "the failed owner keeps its request"
        );
        if client_b.outcome(id).is_some() {
            break;
        }
    }
    let turns = u32::try_from(turn - began).expect("a bounded interval");
    rec.checkpoint(Checkpoint::Healthy {
        turns,
        bound: BOUND,
    });
    if !routed {
        assert_eq!(client_b.outcome(id), Some(Fetched::Complete));
    }
    if client_b.outcome(id) == Some(Fetched::Complete) {
        assert_eq!(bytes, served_object);
        served(&mut rec, &b_storage, (SERVED, A), bytes);
        for _ in 0..2_000 {
            if owner_b.census().live() == 0 {
                break;
            }
            turn_both(
                &mut [&mut client_b],
                &mut [(&mut owner_b, &control_b)],
                &[&b_net],
                turn,
            );
            turn += 1;
        }
        rec.release(share(1), Custodian::Storage);
    }
    shares(&mut rec, &[&owner_a, &owner_b]);
    assert_eq!(
        accounts(&owner_a),
        before,
        "the failed owner's resource accounts kept their pre-stop values"
    );
    assert_eq!(client_a.outcome(held), None, "the held GET still waits");
    let (owner_a, blocked) = *owner_a
        .shutdown()
        .err()
        .expect("an unproven stop blocks the release");
    assert_eq!(blocked.census.live(), before.0);
    drop(owner_a);
    rec.rows().to_vec()
}

fn judged(rows: Vec<Row>) -> Verdict {
    check(&Recorder::rebuilt(rows))
}

#[test]
fn a_failed_owner_keeps_its_custody_while_a_healthy_owner_serves() {
    let rows = two_owners(false);
    let verdict = judged(rows.clone());
    assert!(
        verdict.satisfies(&[Obligation::Isolation, Obligation::Resources]),
        "{verdict:?}"
    );
    let mut returned = rows;
    let at = returned
        .iter()
        .position(|row| row.checkpoint == Some(Checkpoint::Isolated))
        .expect("the failed owner's stop");
    let mut release = returned
        .iter()
        .find(|row| {
            row.kind == ActionKind::Take
                && row
                    .resource()
                    .is_some_and(|r| r.kind == ResourceKind::RequestShare && r.index == 0)
        })
        .expect("the failed owner's share")
        .clone();
    release.kind = ActionKind::Release;
    returned.insert(at + 1, release);
    Recorder::renumber(&mut returned);
    assert_eq!(
        judged(returned).violated(),
        Some((
            Obligation::Isolation,
            "a failed owner returned custody its unproven stop retained"
        ))
    );
}

#[test]
fn always_miss_control_routes_the_healthy_get_to_the_failed_owner() {
    assert_eq!(
        judged(two_owners(true)).violated(),
        Some((
            Obligation::Isolation,
            "a healthy owner served no exact bytes"
        ))
    );
}

fn retired_get() -> Vec<Row> {
    let object = served_content(20_000);
    let (storage, buffers, receive) = (storage(8), arena(8), pool());
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 43, [Faults::default(); 2]);
    let mut rec = Recorder::new(1);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(2), 0, &object)],
        vec![owner_end],
    );
    let preloaded = Some(
        fills_written(&owner, &control)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(SERVED, A, 0, &object, ID, preloaded);
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net.clone()];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(key(2), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    rec.take(share(0), Custodian::Storage, None);
    let mut bytes = Vec::new();
    for _ in 0..5_000 {
        turn_both(
            &mut [&mut client],
            &mut [(&mut owner, &control)],
            &[&net],
            turn,
        );
        turn += 1;
        collect(&mut client, id, &mut bytes);
        if client.outcome(id).is_some() {
            break;
        }
    }
    assert_eq!(client.outcome(id), Some(Fetched::Complete));
    assert_eq!(bytes, object);
    served(&mut rec, &storage, (SERVED, A), bytes);
    assert!(client.retire(id));
    for _ in 0..2_000 {
        if owner.census().live() == 0 {
            break;
        }
        turn_both(
            &mut [&mut client],
            &mut [(&mut owner, &control)],
            &[&net],
            turn,
        );
        turn += 1;
    }
    rec.release(share(0), Custodian::Storage);
    shares(&mut rec, &[&owner]);
    rec.checkpoint(Checkpoint::Released);
    rec.rows().to_vec()
}

#[test]
fn a_retired_request_returns_its_share_and_the_leak_control_fails_resources() {
    let rows = retired_get();
    let verdict = judged(rows.clone());
    assert!(
        verdict.satisfies(&[Obligation::Bytes, Obligation::Resources]),
        "{verdict:?}"
    );
    let mut leaked = rows;
    let returned = leaked
        .iter()
        .rposition(|row| {
            row.kind == ActionKind::Release
                && row
                    .resource()
                    .is_some_and(|r| r.kind == ResourceKind::RequestShare)
        })
        .expect("the share's return");
    leaked.remove(returned);
    assert_eq!(
        judged(leaked).violated(),
        Some((
            Obligation::Resources,
            "a production report disagreed with the independent count"
        ))
    );
}

#[test]
fn an_endpoint_turn_that_unwinds_leaves_the_stream_truncated() {
    let object = Recorder::content(HELD, HELD_LABEL, 0, 30_000);
    let (storage, buffers, receive) = (storage(8), arena(8), pool());
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 44, [Faults::default(); 2]);
    let mut rec = Recorder::new(1);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &object)],
        vec![owner_end],
    );
    let preloaded = Some(
        fills_written(&owner, &control)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(HELD, HELD_LABEL, 0, &object, ID, preloaded);
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net.clone()];
    let turn = open(&mut client, &mut owner, &control, &nets, 0);
    client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap();
    rec.take(share(0), Custodian::Storage, None);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        for at in turn..turn + 200 {
            control.unwind_next(Some(Unwind::Pick));
            turn_both(
                &mut [&mut client],
                &mut [(&mut owner, &control)],
                &[&net],
                at,
            );
        }
        shares(&mut rec, &[&owner]);
        std::mem::replace(&mut rec, Recorder::new(1)).finish()
    }));
    let payload = unwound.expect_err("the device pick unwound the turn");
    if payload.downcast_ref::<&str>() != Some(&"the driver unwound") {
        std::panic::resume_unwind(payload);
    }
    let verdict = check(&rec.unsealed());
    assert_eq!(verdict, Verdict::Inconclusive(Inconclusive::Truncated));
}

pub(super) fn healthy_gets(
    storage: &Storage<TestPlatform>,
    (object, written): (&[u8], Vec<crate::oracle::CommandEvidence>),
    gets: Vec<(u64, u32, Vec<u8>)>,
    (held, live): (u32, u32),
) -> Verdict {
    let mut rec = Recorder::new(1);
    rec.published_written(SERVED, A, 0, object, ID, Some(written));
    for peer in 0..held {
        rec.take(share(peer), Custodian::Storage, None);
    }
    for (turns, bound, bytes) in gets {
        let turns = u32::try_from(turns).expect("a bounded interval");
        rec.checkpoint(Checkpoint::Healthy { turns, bound });
        served(&mut rec, storage, (SERVED, A), bytes);
    }
    rec.report(
        ResourceKind::RequestShare,
        ReportKind::RequestShares,
        ReportState::Value(u64::from(live)),
    );
    check(&rec.finish())
}

pub(super) fn draining_share(live: [u32; 3]) -> Verdict {
    let mut rec = Recorder::new(1);
    rec.take(share(0), Custodian::Storage, None);
    let [queued, sent, drained] = live.map(|live| ReportState::Value(u64::from(live)));
    rec.report(
        ResourceKind::RequestShare,
        ReportKind::RequestShares,
        queued,
    );
    rec.report(ResourceKind::RequestShare, ReportKind::RequestShares, sent);
    rec.release(share(0), Custodian::Storage);
    rec.report(
        ResourceKind::RequestShare,
        ReportKind::RequestShares,
        drained,
    );
    rec.checkpoint(Checkpoint::Released);
    check(&rec.finish())
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    a_failed_owner_keeps_its_custody_while_a_healthy_owner_serves,
    a_retired_request_returns_its_share_and_the_leak_control_fails_resources,
    always_miss_control_routes_the_healthy_get_to_the_failed_owner,
);
