//! Simulated host-pair histories judged by the history oracle, each step
//! named by the workload's canonical action kind under one declared
//! profile.
//!
//! The isolation episode: owner A fails holding a read while owner B serves
//! exact bytes within its bound; A's buffer arena binds a fresh owner only
//! after a reset proves A's stop; B's peer fills its request queue and then
//! its receive pool with the session active; once every holder released, a
//! funded interval publishes a replacement and serves it exactly.
//!
//! The held readers: two readers acquire a key's old version before it is
//! invalidated and replaced; one is delivered the old version whole, the
//! other is cancelled and keeps its command until the late terminal, and a
//! later GET acquires the replacement.

use std::cell::RefCell;
use std::rc::Rc;

use crate::oracle::{
    ActionKind, Checkpoint, Custodian, KeyId, Label, Obligation, Outcome, Recorder, ReportKind,
    ReportState, ResourceKind, Row, Verdict, check,
};
use crate::sim::action::{ActionKind as Action, Profile};
use crate::storage::owner_fixture::{QuiesceMode, SimControl, arena, reserve, storage};
use crate::storage::{CommandToken, EngineBudget, PoolKind, Storage, WorkBudget};

use super::adapters::{ID, clock, fills_written, served, share, shares};
use super::client::{Client, GetRefused, SessionState};
use super::fetch::{FragmentLease, Outcome as Fetched, Releases};
use super::frame::Status;
use super::link::{Faults, LinkEnd, Net, network};
use super::oracle_endpoint_tests::{served_content, turn_both};
use super::owner_tests::{TestOwner, client, collect, hold_next_read, key, open, pool, start};
use super::requests::RequestId;

const HELD: KeyId = KeyId(0);
const SERVED: KeyId = KeyId(1);
const A: Label = Label(1);
const HELD_LABEL: Label = Label(2);
/// The label of the replacement the qualified interval publishes.
const QUALIFIED: Label = Label(5);
const BOUND: u32 = 200;
/// The funded actions the healed interval may spend: the invalidation, the
/// replacement's fill and publication, and the GET.
const HEAL_ACTIONS: u32 = 4;
/// The requests one peer may keep at an owner; the owner answers a GET past them with pressure.
const QUEUE: u32 = super::owner_tests::OWNER.peer_requests;
/// The request share index of the first GET B holds under pressure.
const PRESSED: u32 = 10;
/// The credit index of the first fragment lease the client hoards.
const HOARDED: u32 = 100;
/// Session and allocation of the qualified replacement.
const REPLACEMENT: (u64, u64) = (1, 3);

type Link<'n> = Rc<RefCell<Net<'n>>>;

fn pressed(n: u32) -> (ResourceKind, u32, u64) {
    (ResourceKind::RequestShare, PRESSED + n, 0)
}

fn hoarded(n: u32) -> (ResourceKind, u32, u64) {
    (ResourceKind::Credit, HOARDED + n, 0)
}

/// The read buffer of owner incarnation `incarnation` over A's arena.
fn buffer(incarnation: u64) -> (ResourceKind, u32, u64) {
    (ResourceKind::Buffer, 0, incarnation)
}

/// Reader `reader`'s read command.
fn command(reader: u32, token: CommandToken) -> (ResourceKind, u32, u64) {
    (ResourceKind::Command, reader, token.raw())
}

/// The canonical actions a history took, each one its profile declares.
struct Script {
    profile: Profile,
    taken: Vec<Action>,
}

impl Script {
    fn new(name: &'static str, declared: &[Action]) -> Self {
        Self {
            profile: Profile {
                name,
                declared: declared.to_vec(),
                root: 0x0668,
            },
            taken: Vec::new(),
        }
    }

    fn act(&mut self, action: Action) {
        assert!(
            self.profile.declares(action),
            "{action:?} outside {}",
            self.profile.name
        );
        self.taken.push(action);
    }

    /// Whether the history took every action its profile declares.
    fn covered(&self) -> bool {
        self.profile
            .declared
            .iter()
            .all(|action| self.taken.contains(action))
    }
}

fn get<'m>(client: &mut Client<'m, LinkEnd<'m>>, name: u8, turn: u64) -> RequestId {
    client
        .get(key(name), 0, 1 << 20, turn * 100, 30_000_000)
        .unwrap()
}

/// Turns one client, owner and link `turns` times.
fn settle<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    net: &Link<'_>,
    turns: u64,
    turn: &mut u64,
) {
    for _ in 0..turns {
        turn_both(&mut [client], &mut [(owner, control)], &[net], *turn);
        *turn += 1;
    }
}

/// Turns until `id` ends, keeping every fragment lease, and returns the
/// leases and the bytes they hold.
fn fetch_leased<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    id: RequestId,
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    net: &Link<'_>,
    turn: &mut u64,
) -> (Vec<FragmentLease<'m>>, Vec<u8>) {
    let (mut leases, mut bytes) = (Vec::new(), Vec::new());
    for _ in 0..2_000 {
        settle(client, owner, control, net, 1, turn);
        while let Some(fragment) = client.take(id) {
            assert_eq!(fragment.offset(), bytes.len() as u64, "in order");
            bytes.extend_from_slice(fragment.bytes());
            leases.push(fragment);
        }
        if client.outcome(id).is_some() {
            break;
        }
    }
    assert_eq!(client.outcome(id), Some(Fetched::Complete));
    (leases, bytes)
}

/// Turns until `id` ends and returns its bytes.
fn fetch_whole<'m>(
    client: &mut Client<'m, LinkEnd<'m>>,
    id: RequestId,
    owner: &mut TestOwner<'_, '_, '_>,
    control: &SimControl,
    net: &Link<'_>,
    turn: &mut u64,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..2_000 {
        settle(client, owner, control, net, 1, turn);
        collect(client, id, &mut bytes);
        if client.outcome(id).is_some() {
            break;
        }
    }
    assert_eq!(client.outcome(id), Some(Fetched::Complete));
    bytes
}

fn drain(owner: &mut TestOwner<'_, '_, '_>, control: &SimControl, net: &Link<'_>, turn: &mut u64) {
    for _ in 0..2_000 {
        if owner.census().live() == 0 {
            return;
        }
        turn_both(&mut [], &mut [(owner, control)], &[net], *turn);
        *turn += 1;
    }
    panic!("the owner kept a request after its outcome");
}

/// Invalidates key `name` and publishes `bytes` there through the running
/// owner, turning the client while the fill's writes run.
fn replace<'m, 's>(
    client: &mut Client<'m, LinkEnd<'m>>,
    owner: &mut TestOwner<'s, '_, '_>,
    (storage, control, net): (
        &'s Storage<crate::storage::owner_fixture::TestPlatform>,
        &SimControl,
        &Link<'_>,
    ),
    (name, bytes): (u8, &[u8]),
    script: &mut Script,
    turn: &mut u64,
) {
    script.act(Action::Invalidate);
    owner
        .invalidate(&key(name), 2, &mut WorkBudget::new(1024))
        .unwrap();
    script.act(Action::Fill);
    let mut fill = reserve(storage, &key(name), 0, bytes.len()).expect("a fill");
    let mut taken = 0;
    while !owner.fill_progress(&fill).is_ready() {
        if taken < bytes.len()
            && let Ok(n) = owner.receive_fill(
                &mut fill,
                &bytes[taken..(taken + 4096).min(bytes.len())],
                &mut WorkBudget::with_io(0, usize::MAX, usize::MAX),
            )
        {
            taken += n;
        }
        settle(client, owner, control, net, 1, turn);
        assert!(*turn < 1_000_000, "the replacement's writes ran");
    }
    script.act(Action::Publish);
    drop(
        owner
            .publish_fill(fill, u64::MAX, 2, &mut WorkBudget::new(1024))
            .unwrap(),
    );
}

const EPISODE: [Action; 8] = [
    Action::Get,
    Action::Close,
    Action::Release,
    Action::Pressure,
    Action::Read,
    Action::Invalidate,
    Action::Fill,
    Action::Publish,
];

/// The episode's rows and canonical actions, recorded as production owners and clients act.
fn episode() -> (Vec<Row>, Script) {
    let mut script = Script::new("host-pair-isolation", &EPISODE);
    let held_object = Recorder::content(HELD, HELD_LABEL, 0, 30_000);
    let served_object = served_content(20_000);
    let replacement = Recorder::content(SERVED, QUALIFIED, 0, 16_000);
    let (a_storage, a_buffers, a_receive) = (storage(8), arena(8), pool());
    let (b_storage, b_buffers, b_receive) = (storage(8), arena(8), pool());
    let (r_storage, rebound_receive, client_pool) = (storage(8), pool(), pool());
    let releases = [(); 3].map(|()| Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap());
    let (a_client_end, a_owner_end, a_net) = network(64, 8384, 41, [Faults::default(); 2]);
    let (b_client_end, b_owner_end, b_net) = network(64, 8384, 42, [Faults::default(); 2]);
    let (r_client_end, r_owner_end, r_net) = network(64, 8384, 43, [Faults::default(); 2]);
    let mut rec = Recorder::new(1);
    let (mut owner_a, control_a) = start(
        &a_storage,
        &a_buffers,
        &a_receive,
        &[(key(1), 0, &held_object)],
        vec![a_owner_end],
    );
    let (mut owner_b, control_b) = start(
        &b_storage,
        &b_buffers,
        &b_receive,
        &[(key(2), 0, &served_object)],
        vec![b_owner_end],
    );
    let held_written = Some(
        fills_written(&owner_a, &control_a)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(HELD, HELD_LABEL, 0, &held_object, ID, held_written);
    let served_written = Some(
        fills_written(&owner_b, &control_b)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(SERVED, A, 0, &served_object, ID, served_written);
    let mut client_a = client(0, &client_pool, &releases[0], a_client_end);
    let mut client_b = client(0, &client_pool, &releases[1], b_client_end);
    let mut turn = open(
        &mut client_a,
        &mut owner_a,
        &control_a,
        std::slice::from_ref(&a_net),
        0,
    );
    turn = open(
        &mut client_b,
        &mut owner_b,
        &control_b,
        std::slice::from_ref(&b_net),
        turn,
    );

    // A fails holding a read in its arena's buffer.
    script.act(Action::Get);
    let held = get(&mut client_a, 1, turn);
    let (token, at) = hold_next_read(&mut client_a, &mut owner_a, &control_a, &a_net, turn);
    turn = at;
    rec.take(share(0), Custodian::Storage, None);
    rec.take(buffer(1), Custodian::Storage, None);
    shares(&mut rec, &[&owner_a, &owner_b]);
    script.act(Action::Close);
    control_a.set_quiesce(QuiesceMode::Unproven);
    let _ = owner_a.close(turn * 100);
    rec.isolated(share(0));
    rec.isolated(buffer(1));

    // B serves exact bytes within its bound while A holds.
    script.act(Action::Get);
    let id = get(&mut client_b, 2, turn);
    let began = turn;
    let healthy_at = rec.checkpoint(Checkpoint::Healthy {
        turns: 0,
        bound: BOUND,
    });
    rec.take(share(1), Custodian::Storage, None);
    let mut bytes = Vec::new();
    while turn < began + u64::from(BOUND) && client_b.outcome(id).is_none() {
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
    }
    let healthy_turns = u32::try_from(turn - began).unwrap();
    assert_eq!(client_b.outcome(id), Some(Fetched::Complete));
    assert_eq!(bytes, served_object);
    served(&mut rec, &b_storage, (SERVED, A), bytes);
    drain(&mut owner_b, &control_b, &b_net, &mut turn);
    rec.release(share(1), Custodian::Storage);
    shares(&mut rec, &[&owner_a, &owner_b]);
    assert_eq!(client_a.outcome(held), None, "the held GET still waits");
    let held_buffers = || {
        let report = a_buffers.report(PoolKind::ReadResponse);
        report.count - report.free - report.retired
    };
    assert!(
        held_buffers() > 0,
        "the failed owner's arena holds its read"
    );

    // The approved boundary: the device returns the held read and a reset proves A's stop; only then does A's arena rebind.
    let (mut owner_a, _blocked) = *owner_a
        .shutdown()
        .err()
        .expect("the unproven stop blocks the release");
    script.act(Action::Release);
    control_a.release(token);
    control_a.set_quiesce(QuiesceMode::Reset);
    let mut proven = None;
    for _ in 0..2_000 {
        settle(
            &mut client_a,
            &mut owner_a,
            &control_a,
            &a_net,
            1,
            &mut turn,
        );
        match owner_a.shutdown() {
            Ok(shutdown) => {
                proven = Some(shutdown);
                break;
            }
            Err(back) => owner_a = back.0,
        }
    }
    drop(proven.expect("a reset proves the failed owner's stop"));
    rec.checkpoint(Checkpoint::Stopped);
    rec.release(share(0), Custodian::Storage);
    rec.release(buffer(1), Custodian::Storage);
    drop(client_a);
    assert_eq!(
        held_buffers(),
        0,
        "the proven stop returned the arena's buffers"
    );
    let (mut rebound, control_r) = start(
        &r_storage,
        &a_buffers,
        &rebound_receive,
        &[(key(2), 0, &served_object)],
        vec![r_owner_end],
    );
    let mut client_r = client(0, &client_pool, &releases[2], r_client_end);
    turn = open(
        &mut client_r,
        &mut rebound,
        &control_r,
        std::slice::from_ref(&r_net),
        turn,
    );
    script.act(Action::Get);
    let id = get(&mut client_r, 2, turn);
    rec.take(share(2), Custodian::Storage, None);
    rec.take(buffer(2), Custodian::Storage, None);
    let bytes = fetch_whole(
        &mut client_r,
        id,
        &mut rebound,
        &control_r,
        &r_net,
        &mut turn,
    );
    assert_eq!(
        bytes, served_object,
        "the owner over A's rebound arena serves"
    );
    served(&mut rec, &r_storage, (SERVED, A), bytes);
    drain(&mut rebound, &control_r, &r_net, &mut turn);
    rec.release(share(2), Custodian::Storage);
    rec.release(buffer(2), Custodian::Storage);

    // Queue pressure: B holds a read for each request its peer may keep, and the owner answers the next GET with pressure while the session stays active.
    script.act(Action::Pressure);
    let mut pending = Vec::new();
    for n in 0..QUEUE {
        let id = get(&mut client_b, 2, turn);
        let (token, at) = hold_next_read(&mut client_b, &mut owner_b, &control_b, &b_net, turn);
        turn = at;
        rec.take(pressed(n), Custodian::Reader, None);
        pending.push((id, token));
    }
    shares(&mut rec, &[&owner_b]);
    let refused = get(&mut client_b, 2, turn);
    settle(
        &mut client_b,
        &mut owner_b,
        &control_b,
        &b_net,
        500,
        &mut turn,
    );
    assert_eq!(
        client_b.outcome(refused),
        Some(Fetched::Pressure(Status::RequestPressure))
    );
    assert!(client_b.retire(refused));
    assert_eq!(
        client_b.state(),
        SessionState::Active,
        "control traffic continues under pressure"
    );
    assert_eq!(
        owner_b.census().live(),
        QUEUE,
        "the held reads keep every request"
    );

    // Pool pressure: the device returns the held reads and the client keeps every fragment lease until its receive pool refuses a GET.
    script.act(Action::Read);
    for &(_, token) in &pending {
        control_b.release(token);
    }
    let mut hoard = Vec::new();
    for (n, &(id, _)) in pending.iter().enumerate() {
        let (leases, bytes) = fetch_leased(
            &mut client_b,
            id,
            &mut owner_b,
            &control_b,
            &b_net,
            &mut turn,
        );
        assert_eq!(bytes, served_object);
        assert!(client_b.retire(id));
        rec.release(pressed(n as u32), Custodian::Reader);
        hoard.extend(leases);
    }
    let refusal =
        (0..64).find_map(
            |_| match client_b.get(key(2), 0, 1 << 20, turn * 100, 30_000_000) {
                Ok(id) => {
                    let (leases, bytes) = fetch_leased(
                        &mut client_b,
                        id,
                        &mut owner_b,
                        &control_b,
                        &b_net,
                        &mut turn,
                    );
                    assert_eq!(
                        bytes, served_object,
                        "a GET completes or is refused at the bound"
                    );
                    assert!(client_b.retire(id));
                    hoard.extend(leases);
                    None
                }
                Err(refusal) => Some(refusal),
            },
        );
    assert_eq!(refusal, Some(GetRefused::ReceivePressure));
    let hoarded_leases = u32::try_from(hoard.len()).unwrap();
    for n in 0..hoarded_leases {
        rec.take(hoarded(n), Custodian::Reader, None);
    }
    settle(
        &mut client_b,
        &mut owner_b,
        &control_b,
        &b_net,
        500,
        &mut turn,
    );
    assert_eq!(
        client_b.state(),
        SessionState::Active,
        "control traffic continues with the pool exhausted"
    );
    drain(&mut owner_b, &control_b, &b_net, &mut turn);
    shares(&mut rec, &[&owner_b]);

    // Heal: the holders release, and a funded interval publishes a replacement and serves it exactly.
    script.act(Action::Release);
    drop(hoard);
    for n in 0..hoarded_leases {
        rec.release(hoarded(n), Custodian::Reader);
    }
    let qualified_at = rec.checkpoint(Checkpoint::Qualified {
        funded: 0,
        limit: HEAL_ACTIONS,
    });
    let heal_began = script.taken.len();
    replace(
        &mut client_b,
        &mut owner_b,
        (&b_storage, &control_b, &b_net),
        (2, &replacement),
        &mut script,
        &mut turn,
    );
    rec.invalidate(SERVED, Outcome::Acknowledged);
    let replaced = Some(
        fills_written(&owner_b, &control_b)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(SERVED, QUALIFIED, 0, &replacement, REPLACEMENT, replaced);
    script.act(Action::Get);
    let id = get(&mut client_b, 2, turn);
    rec.take(share(1), Custodian::Storage, None);
    let read = rec.lookup_at(
        SERVED,
        Outcome::Hit,
        Some(QUALIFIED),
        Some(clock(&b_storage)),
    );
    let bytes = fetch_whole(
        &mut client_b,
        id,
        &mut owner_b,
        &control_b,
        &b_net,
        &mut turn,
    );
    assert_eq!(
        bytes, replacement,
        "the healed owner serves the replacement"
    );
    rec.delivered(
        read,
        (SERVED, QUALIFIED),
        (0, bytes.len() as u64),
        REPLACEMENT,
        Outcome::Complete,
        bytes,
    );
    drain(&mut owner_b, &control_b, &b_net, &mut turn);
    rec.release(share(1), Custodian::Storage);
    shares(&mut rec, &[&owner_b]);
    let funded = u32::try_from(script.taken.len() - heal_began).unwrap();
    let mut rows = rec.rows().to_vec();
    for row in &mut rows {
        if row.op == healthy_at {
            row.checkpoint = Some(Checkpoint::Healthy {
                turns: healthy_turns,
                bound: BOUND,
            });
        } else if row.op == qualified_at {
            row.checkpoint = Some(Checkpoint::Qualified {
                funded,
                limit: HEAL_ACTIONS,
            });
        }
    }
    (rows, script)
}

fn judged(rows: Vec<Row>) -> Verdict {
    check(&Recorder::rebuilt(rows))
}

fn healthy(row: &Row) -> bool {
    matches!(row.checkpoint, Some(Checkpoint::Healthy { .. }))
}

fn qualified(row: &Row) -> bool {
    matches!(row.checkpoint, Some(Checkpoint::Qualified { .. }))
}

fn release_of(row: &Row, kind: ResourceKind, from: u32) -> bool {
    row.kind == ActionKind::Release
        && row
            .resource()
            .is_some_and(|resource| resource.kind == kind && resource.index >= from)
}

/// Whether the episode holds every ingredient the qualification needs, in
/// order: a failed owner's retained custody, a healthy owner's interval
/// before the failed stop is proven, the proven stop, a request-share
/// report at the queue's limit, an exhausted receive pool, and a qualified interval
/// after every pressed share and hoarded lease returned.
fn conjunction(rows: &[Row]) -> Result<(), &'static str> {
    let at = |found: &dyn Fn(&Row) -> bool| rows.iter().position(found);
    let last = |found: &dyn Fn(&Row) -> bool| rows.iter().rposition(found);
    let isolated =
        at(&|row| row.checkpoint == Some(Checkpoint::Isolated)).ok_or("no failed owner")?;
    let served = at(&healthy).ok_or("no healthy interval")?;
    let stopped = at(&|row| row.checkpoint == Some(Checkpoint::Stopped)).ok_or("no proven stop")?;
    let pressed = at(&|row| {
        row.report.is_some_and(|report| {
            report.kind == ReportKind::RequestShares
                && report.state == ReportState::Value(u64::from(QUEUE))
        })
    })
    .ok_or("no pressure at the limit")?;
    let pooled = at(&|row| {
        row.kind == ActionKind::Take
            && row
                .resource()
                .is_some_and(|r| r.kind == ResourceKind::Credit && r.index >= HOARDED)
    })
    .ok_or("no exhausted pool")?;
    let healed = last(&qualified).ok_or("no qualified interval")?;
    let returned = [
        last(&|row| release_of(row, ResourceKind::RequestShare, PRESSED)),
        last(&|row| release_of(row, ResourceKind::Credit, HOARDED)),
    ];
    if !(isolated < served
        && served < stopped
        && stopped < pressed
        && pressed < pooled
        && returned.iter().all(|r| r.is_some_and(|r| r < healed)))
    {
        return Err("the ingredients are out of order");
    }
    Ok(())
}

#[test]
fn the_isolation_episode_passes_the_oracle_and_its_conjunction() {
    let (rows, script) = episode();
    let verdict = judged(rows.clone());
    assert!(
        verdict.satisfies(&[
            Obligation::Bytes,
            Obligation::Isolation,
            Obligation::Resources,
            Obligation::Progress
        ]),
        "{verdict:?}"
    );
    assert_eq!(conjunction(&rows), Ok(()));
    assert!(
        script.covered(),
        "the episode took every declared action: {:?}",
        script.taken
    );
}

fn first(rows: &[Row], found: impl Fn(&Row) -> bool) -> usize {
    rows.iter().position(found).expect("the episode's row")
}

/// The first delivery after the failed owner's isolation, B's healthy one.
fn healthy_delivery(rows: &[Row]) -> usize {
    let isolated = first(rows, |row| row.checkpoint == Some(Checkpoint::Isolated));
    isolated + first(&rows[isolated..], |row| row.kind == ActionKind::Deliver)
}

/// Moves the row at `from` to just before the row at `to`, then renumbers.
fn moved(mut rows: Vec<Row>, from: usize, to: usize) -> Vec<Row> {
    let row = rows.remove(from);
    rows.insert(if from < to { to - 1 } else { to }, row);
    Recorder::renumber(&mut rows);
    rows
}

#[test]
fn stale_bytes_an_early_return_starvation_and_a_held_heal_fail_the_oracle() {
    let (rows, _) = episode();
    let mut stale = rows.clone();
    let delivery = healthy_delivery(&stale);
    stale[delivery].payload.as_mut().unwrap()[0] ^= 1;
    assert_eq!(
        judged(stale).violated(),
        Some((
            Obligation::Bytes,
            "a complete read returned bytes other than the label's content"
        ))
    );

    let mut failed_path = rows.clone();
    let delivery = healthy_delivery(&failed_path);
    let len = failed_path[delivery].payload.as_ref().unwrap().len() as u64;
    failed_path[delivery].payload = Some(Recorder::content(HELD, HELD_LABEL, 0, len));
    assert_eq!(
        judged(failed_path)
            .violated()
            .map(|(obligation, _)| obligation),
        Some(Obligation::Bytes),
        "B's delivery carrying the only bytes A held"
    );

    let isolated = first(&rows, |row| row.checkpoint == Some(Checkpoint::Isolated));
    let returned = first(&rows, |row| {
        row.kind == ActionKind::Release && row.resource().is_some_and(|r| r.index == 0)
    });
    assert_eq!(
        judged(moved(rows.clone(), returned, isolated + 1)).violated(),
        Some((
            Obligation::Isolation,
            "a failed owner returned custody its unproven stop retained"
        )),
        "A's share returned before its proven stop"
    );

    let rebound = first(&rows, |row| {
        row.kind == ActionKind::Take && row.incarnation == Some(crate::oracle::Incarnation(2))
    });
    let stopped = first(&rows, |row| row.checkpoint == Some(Checkpoint::Stopped));
    assert_eq!(
        judged(moved(rows.clone(), rebound, stopped)).violated(),
        Some((
            Obligation::Custody,
            "a resource was reused while a custodian held an earlier incarnation"
        )),
        "A's arena rebound before its proven stop"
    );

    let mut starved = rows.clone();
    let at = first(&starved, healthy);
    starved[at].checkpoint = Some(Checkpoint::Healthy {
        turns: BOUND + 1,
        bound: BOUND,
    });
    assert_eq!(
        judged(starved).violated(),
        Some((
            Obligation::Isolation,
            "a healthy owner starved past its fixture bound"
        ))
    );

    let healed = first(&rows, qualified);
    let lease = rows
        .iter()
        .rposition(|row| release_of(row, ResourceKind::Credit, HOARDED))
        .unwrap();
    assert_eq!(
        judged(moved(rows.clone(), healed, lease)).violated(),
        Some((
            Obligation::Progress,
            "a qualified checkpoint began with holders outstanding"
        )),
        "the heal began while a hoarded lease was held"
    );

    let mut overspent = rows;
    overspent[healed].checkpoint = Some(Checkpoint::Qualified {
        funded: HEAL_ACTIONS + 1,
        limit: HEAL_ACTIONS,
    });
    assert_eq!(
        judged(overspent).violated(),
        Some((
            Obligation::Progress,
            "funded recovery exceeded its action bound"
        ))
    );
}

#[test]
fn an_episode_missing_an_ingredient_of_the_conjunction_is_rejected() {
    let (rows, _) = episode();
    let without = |found: &dyn Fn(&Row) -> bool| {
        let mut rows = rows.clone();
        rows.retain(|row| !found(row));
        conjunction(&rows)
    };
    assert_eq!(
        without(&|row| row.checkpoint == Some(Checkpoint::Isolated)),
        Err("no failed owner")
    );
    assert_eq!(without(&healthy), Err("no healthy interval"));
    assert_eq!(
        without(&|row| row.checkpoint == Some(Checkpoint::Stopped)),
        Err("no proven stop")
    );
    assert_eq!(
        without(&|row| row
            .report
            .is_some_and(|r| r.kind == ReportKind::RequestShares)),
        Err("no pressure at the limit")
    );
    assert_eq!(
        without(&|row| row.kind == ActionKind::Take
            && row
                .resource()
                .is_some_and(|r| r.kind == ResourceKind::Credit)),
        Err("no exhausted pool")
    );
    assert_eq!(without(&qualified), Err("no qualified interval"));
    let healed = first(&rows, qualified);
    let lease = rows
        .iter()
        .rposition(|row| release_of(row, ResourceKind::Credit, HOARDED))
        .unwrap();
    assert_eq!(
        conjunction(&moved(rows.clone(), healed, lease)),
        Err("the ingredients are out of order"),
        "the heal began before the last hoarded lease returned"
    );
    let stopped = first(&rows, |row| row.checkpoint == Some(Checkpoint::Stopped));
    assert_eq!(
        conjunction(&moved(rows.clone(), stopped, 1)),
        Err("the ingredients are out of order")
    );
}

const READ: KeyId = KeyId(2);
const OLD: Label = Label(3);
const NEW: Label = Label(4);
/// The replacement's session and allocation.
const REPLACED: (u64, u64) = (1, 2);

const READERS: [Action; 7] = [
    Action::Get,
    Action::Acquire,
    Action::Invalidate,
    Action::Fill,
    Action::Publish,
    Action::Cancel,
    Action::Read,
];

/// Two readers hold production key 1's old version while the key is invalidated and
/// replaced: one is then delivered the old version whole, the other is
/// cancelled and keeps its command until the late terminal, and a later GET
/// is served the replacement.
fn held_readers() -> (Vec<Row>, Script) {
    let mut script = Script::new("host-pair-held-readers", &READERS);
    let old = Recorder::content(READ, OLD, 0, 20_000);
    let new = Recorder::content(READ, NEW, 0, 18_000);
    let (storage, buffers, receive, client_pool) = (storage(8), arena(8), pool(), pool());
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 44, [Faults::default(); 2]);
    let mut rec = Recorder::new(1);
    let (mut owner, control) = start(
        &storage,
        &buffers,
        &receive,
        &[(key(1), 0, &old)],
        vec![owner_end],
    );
    let old_written = Some(
        fills_written(&owner, &control)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(READ, OLD, 0, &old, ID, old_written);
    let mut client = client(0, &client_pool, &releases, client_end);
    let mut turn = open(
        &mut client,
        &mut owner,
        &control,
        std::slice::from_ref(&net),
        0,
    );
    let mut readers = Vec::new();
    for reader in 0..2 {
        script.act(Action::Get);
        let id = get(&mut client, 1, turn);
        let (token, at) = hold_next_read(&mut client, &mut owner, &control, &net, turn);
        turn = at;
        script.act(Action::Acquire);
        let read = rec.lookup_at(READ, Outcome::Hit, Some(OLD), Some(clock(&storage)));
        rec.take(command(reader, token), Custodian::Storage, None);
        readers.push((id, token, read));
    }
    replace(
        &mut client,
        &mut owner,
        (&storage, &control, &net),
        (1, &new),
        &mut script,
        &mut turn,
    );
    rec.invalidate(READ, Outcome::Acknowledged);
    let new_written = Some(
        fills_written(&owner, &control)
            .pop()
            .expect("a live fill\'s write evidence"),
    );
    rec.published_written(READ, NEW, 0, &new, REPLACED, new_written);
    let [(delivered, kept, first_read), (cancelled, late, _)] = readers[..] else {
        unreachable!("two readers")
    };
    script.act(Action::Cancel);
    client.cancel(cancelled);
    rec.cancel(command(1, late));
    script.act(Action::Read);
    control.release(kept);
    let bytes = fetch_whole(
        &mut client,
        delivered,
        &mut owner,
        &control,
        &net,
        &mut turn,
    );
    assert_eq!(
        bytes, old,
        "the reader acquired before the invalidation gets the old version"
    );
    assert!(client.retire(delivered));
    rec.terminal(command(0, kept), Outcome::Complete);
    rec.delivered(
        first_read,
        (READ, OLD),
        (0, old.len() as u64),
        ID,
        Outcome::Complete,
        bytes,
    );
    script.act(Action::Get);
    let second = get(&mut client, 1, turn);
    let bytes = fetch_whole(&mut client, second, &mut owner, &control, &net, &mut turn);
    assert_eq!(bytes, new, "a GET after the replacement acquires it");
    script.act(Action::Acquire);
    let read = rec.lookup_at(READ, Outcome::Hit, Some(NEW), Some(clock(&storage)));
    rec.delivered(
        read,
        (READ, NEW),
        (0, new.len() as u64),
        REPLACED,
        Outcome::Complete,
        bytes,
    );
    assert_eq!(
        client.outcome(cancelled),
        Some(Fetched::Failed(Status::Cancelled))
    );
    assert_eq!(
        owner.census().live(),
        1,
        "the cancelled reader keeps its command"
    );
    control.release(late);
    drain(&mut owner, &control, &net, &mut turn);
    rec.terminal(command(1, late), Outcome::Complete);
    (rec.rows().to_vec(), script)
}

#[test]
fn held_readers_keep_their_acquisition_through_invalidation_replacement_and_a_late_terminal() {
    let (rows, script) = held_readers();
    let verdict = judged(rows.clone());
    assert!(
        verdict.satisfies(&[Obligation::Bytes, Obligation::Custody]),
        "{verdict:?}"
    );
    assert!(script.covered(), "{:?}", script.taken);
    let removed = Some((
        Obligation::History,
        "a hit of a version an acknowledged invalidation covered",
    ));
    let mut stale = rows.clone();
    let lookup = first(&stale, |row| {
        row.kind == ActionKind::Lookup && row.label == Some(NEW)
    });
    let at = lookup + first(&stale[lookup..], |row| row.kind == ActionKind::Deliver);
    let len = stale[at].payload.as_ref().unwrap().len() as u64;
    stale[lookup].label = Some(OLD);
    stale[at].label = Some(OLD);
    stale[at].payload = Some(Recorder::content(READ, OLD, 0, len));
    assert_eq!(
        judged(stale).violated(),
        removed,
        "a GET after the invalidation served the old version"
    );
    let acquired = first(&rows, |row| row.kind == ActionKind::Lookup);
    let invalidated = first(&rows, |row| row.kind == ActionKind::Invalidate);
    assert_eq!(
        judged(moved(rows, acquired, invalidated + 1)).violated(),
        removed,
        "the delivered reader's acquisition moved after the invalidation"
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    an_episode_missing_an_ingredient_of_the_conjunction_is_rejected,
    stale_bytes_an_early_return_starvation_and_a_held_heal_fail_the_oracle,
    the_isolation_episode_passes_the_oracle_and_its_conjunction,
);
