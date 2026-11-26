//! Two hosts through the production driver, duties and agent: A owns the warm volume's shard and C is its named
//! standby. A's agent turns every round over its owner's status. C's agent turns over a fixed standby status until
//! C's standby wait starts and then over the statuses the wait publishes to C's link, the heartbeats A's agent sent until the loss or isolation, and, once a suspect has an open probe round, the DEAD
//! votes of two probers in partitions 2 and 3, which stand in for the indirect probes of other hosts' agents. In the
//! held case A's agent goes on turning over a held status after A's process stops, so its heartbeats report A
//! unhealthy, and the probers read the declared hold.

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicBool, Ordering};

use super::agent::tests::{answer, keys, reporting, slices};
use super::agent::{Agent, Inputs, Outputs, Synced};
use super::duties::tests::{periods, records};
use super::duties::{Duties, Linked, Records};
use super::fencer_tests::fencer_of;
use super::inputs_tests::inputs_of;
use super::lane::Lane;
use super::lane::tests::bounds as suffix_bounds;
use super::link::{Inbound, Link, Status};
use super::recover::{Role, Signals, role, stand_by};
use super::serve::loop_tests::{
    CLIENT_END, OWNER_END, Rounds, Stage, TestOwner, staged_by, staged_over,
};
use super::serve::tests::warm_volume_certified;
use super::{Exit, HostGate};
use crate::failover::arbiter::{ArbiterBounds, Clock, Partition};
use crate::failover::attachments::InstanceId;
use crate::failover::detect::host::{Reading, WatchBounds};
use crate::failover::detect::tests::{DECLARED, SILENT, planted};
use crate::failover::detect::{DetectBounds, Failure, Liveness};
use crate::failover::reconcile::StandbyGate;
use crate::failover::records::Host;
use crate::failover::report::{Phase, RecoveryStatus};
use crate::failover::restart::tests::{host as a_host, shard_now, volume_id};
use crate::failover::sim::host;
use crate::failover::takeover::tests::{c_host, c_pair, holder_of, instance_of, stored_c};
use crate::net::{Outcome as Fetched, RequestId, SessionState};
use crate::storage::device::sim::Media;
use crate::storage::gate_fixture::{Control, registry};
use crate::storage::store::Client;
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::store_tests::{client, shard};
use crate::storage::test_platform::TestPlatform;
use crate::storage::warm_sim::{object_key, storage};

const H: u64 = 1_000;

fn watch_bounds() -> WatchBounds {
    WatchBounds {
        detect: DetectBounds {
            h: H,
            d: 3,
            tau: 0,
            jitter: 500,
            peer_grace: 2_000,
            exit_windows: 2,
            dwell: 3_000,
            hosts: 12,
        },
        arbiter: ArbiterBounds {
            h: H,
            holder_grace: 500,
            k: 2,
            rounds: 3,
            clock_age: 1_000_000,
            dwell: 2_000,
            hosts: 8,
        },
        shards: 16,
        per_tick: 4,
        self_suspect: 3,
    }
}

fn placement() -> Vec<(Host, Partition)> {
    vec![
        (a_host(), Partition(1)),
        (c_host(), Partition(9)),
        (host(21), Partition(2)),
        (host(22), Partition(3)),
    ]
}

fn clock(now: u64) -> Clock {
    Clock::Trusted { sampled_at: now }
}

fn agent_of(own: Host, store: &Shared) -> Agent {
    let peers: Vec<_> = [a_host(), c_host(), host(21), host(22)]
        .into_iter()
        .filter(|peer| *peer != own)
        .collect();
    let boot = super::agent::tests::boot_of(own);
    let mut agent = Agent::new(
        &HostGate::qualified(),
        (own, boot, 1_000),
        watch_bounds(),
        keys(own, &peers),
        reporting(own, 3 * H),
    )
    .unwrap();
    resync(&mut agent, store, 0);
    agent
}

fn dead_votes(agent: &Agent, own: Host, reading: Reading) -> Vec<Vec<u8>> {
    let requests: Vec<_> = agent.watch().probes().collect();
    (requests.into_iter())
        .flat_map(|r| [21, 22].map(|prober| answer(r, prober, own, reading)))
        .collect()
}

fn beats_to(out: &Outputs, to: Host) -> Vec<Vec<u8>> {
    (out.heartbeats.iter())
        .filter(|(peer, _)| *peer == to)
        .map(|(_, bytes)| bytes.clone())
        .collect()
}

fn deliver(out: &Outputs, link: &Link) -> usize {
    let mut nominations = 0;
    for (to, message) in &out.messages {
        assert_eq!(*to, volume_id());
        nominations += usize::from(matches!(message, Inbound::Nominate(_)));
        assert!(link.inbox.deliver(*message), "the inbox holds the message");
    }
    nominations
}

struct Standby {
    agent: Agent,
    link: &'static Link,
    now: Cell<u64>,
    inbound: RefCell<Vec<Vec<u8>>>,
    nominations: Cell<usize>,
    /// The probers' DEAD reading of a suspect.
    reading: Reading,
    /// The failure kinds C's detector read of A after each turn, in order.
    read: RefCell<Vec<Failure>>,
    /// Whether C's standby wait runs. Before it does, C's agent turns over a fixed standby status in its place; while
    /// it runs, over the statuses the wait publishes to C's link.
    waiting: Cell<bool>,
}

impl Standby {
    fn new(store: &Shared) -> Self {
        Self {
            agent: agent_of(c_host(), store),
            link: Box::leak(Box::default()),
            now: Cell::new(0),
            inbound: RefCell::new(Vec::new()),
            nominations: Cell::new(0),
            reading: SILENT,
            read: RefCell::new(Vec::new()),
            waiting: Cell::new(false),
        }
    }

    fn turn(&mut self, now: u64) {
        self.now.set(now);
        let statuses: Vec<Status> = match self.waiting.get() {
            true => self.link.status.take().into_iter().collect(),
            false => vec![Status::idle(shard(), volume_id(), 3, Phase::Standby)],
        };
        let beats = self.inbound.take();
        let beats: Vec<&[u8]> = beats.iter().map(Vec::as_slice).collect();
        let votes = dead_votes(&self.agent, c_host(), self.reading);
        let out = self.agent.turn(
            now,
            Inputs {
                statuses: &statuses,
                heartbeats: &beats,
                probes: &slices(&votes),
                clock: clock(now),
                ..Inputs::NONE
            },
        );
        self.nominations
            .set(self.nominations.get() + deliver(&out, self.link));
        if let Some(Liveness::Dead(s)) = self.agent.watch().liveness(a_host()) {
            self.read.borrow_mut().push(s.failure);
        }
    }
}

struct Owner {
    agent: Agent,
    link: &'static Link,
}

fn instance(h: Host) -> Option<InstanceId> {
    Some(instance_of(h))
}

fn linked_duties<'w>(
    stage: &Stage<'w>,
    records: Records<'w>,
    link: &'w Link,
) -> Duties<'w, Shared, MemLog, TestPlatform> {
    let client = Client::open(stage.store.clone(), MemLog::default()).unwrap();
    Duties::new(
        (
            &HostGate::qualified(),
            crate::failover::reconcile::StandbyGate::qualified(),
        ),
        Lane::inline(client, stage.storage),
        records,
        None,
        suffix_bounds(),
        periods(),
    )
    .linked(Linked {
        link,
        pid: 1,
        status_us: H,
        recovery: Some(RecoveryStatus::NO_ATTEMPT),
    })
}

fn retained(n: u8) -> Vec<u8> {
    let fill = if n == 2 { 0xee } else { n };
    [&object_key(n)[..4], &[fill; 40][..]].concat()
}

#[derive(Default)]
struct Gets {
    pending: Option<(u8, RequestId, Vec<u8>)>,
    done: Vec<(u8, Option<Vec<u8>>)>,
}

impl Gets {
    fn step(&mut self, rounds: &Rounds<'_>) {
        let active = rounds.client.borrow().state() == SessionState::Active;
        if active && self.pending.is_none() && self.done.len() < 4 {
            let n = self.done.len() as u8 + 1;
            self.pending = Some((n, rounds.get(n), Vec::new()));
        }
        if let Some((n, id, bytes)) = self.pending.as_mut()
            && let Some(outcome) = rounds.fetched(*id, bytes)
        {
            let body = (outcome == Fetched::Complete).then(|| std::mem::take(bytes));
            self.done.push((*n, body));
            self.pending = None;
        }
    }
}

struct Succeeded {
    exit: Exit,
    served: Vec<(u8, Option<Vec<u8>>)>,
    nominations: usize,
}

fn succeed(store: &Shared, media: &Media, registry: &Control, standby: &mut Standby) -> Succeeded {
    succeed_beside(store, media, registry, standby, &mut |_, _| {})
}

/// C's takeover and tenure as in [`succeed`], with `beside` called at each of C's standby periods before C's agent
/// turns, with the period's time and C, for the hosts that go on running beside it.
fn succeed_beside(
    store: &Shared,
    media: &Media,
    registry: &Control,
    standby: &mut Standby,
    beside: &mut dyn FnMut(u64, &Standby),
) -> Succeeded {
    let stop = AtomicBool::new(false);
    let periods = Cell::new(0);
    let link = standby.link;
    standby.waiting.set(true);
    let standby = RefCell::new(standby);
    staged_by(
        (registry.clone(), c_pair(), false),
        (store.clone(), media.clone()),
        (|| storage(1), 0),
        |disk, arena, fencing_clock, serving| {
            let fencer = fencer_of(disk, c_pair(), arena, fencing_clock);
            let recovery = stand_by(
                (&HostGate::qualified(), &StandbyGate::qualified()),
                (&inputs_of(c_host()), &instance),
                &mut client(store),
                &stored_c(),
                |_| panic!("the named standby persists nothing"),
                fencer,
                serving,
                Signals {
                    stop: &stop,
                    period: |_| {
                        periods.set(periods.get() + 1);
                        assert!(periods.get() < 50, "no takeover");
                        let mut standby = standby.borrow_mut();
                        let now = standby.now.get() + H;
                        beside(now, &standby);
                        standby.turn(now);
                        true
                    },
                    nominations: || standby.borrow().link.inbox.nomination(),
                    now: || standby.borrow().now.get(),
                    status: &link.status,
                    pid: 3,
                    window_us: H,
                },
            );
            match recovery {
                Ok(tenure) => *tenure,
                Err(ended) => panic!("the standby ended {:?}", ended.exit),
            }
        },
        |mut stage| {
            let link: &'static Link = Box::leak(Box::default());
            let mut duties = linked_duties(
                &stage,
                Records {
                    holder: holder_of(c_host()),
                    instance: &instance,
                },
                link,
            );
            let mut gets = Gets::default();
            let (served, _) = stage.serve_until(
                |rounds, _, stop| {
                    gets.step(rounds);
                    if gets.done.len() == 4 {
                        stop.store(true, Ordering::Release);
                    }
                },
                |owner: &mut TestOwner<'_>, now| duties.turn(owner, now),
            );
            Succeeded {
                exit: served.exit,
                served: gets.done,
                nominations: standby.borrow().nominations.get(),
            }
        },
    )
}

fn agents(store: &Shared) -> (Owner, Standby) {
    let owner = Owner {
        agent: agent_of(a_host(), store),
        link: Box::leak(Box::default()),
    };
    (owner, Standby::new(store))
}

fn exchange(owner: &mut Owner, standby: &mut Standby, now: u64, isolated: bool) {
    let statuses: Vec<Status> = owner.link.status.take().into_iter().collect();
    let out = owner.agent.turn(
        now,
        Inputs {
            statuses: &statuses,
            clock: clock(now),
            ..Inputs::NONE
        },
    );
    for (to, message) in &out.messages {
        assert_eq!(*to, volume_id());
        assert!(owner.link.inbox.deliver(*message));
    }
    if !isolated {
        standby
            .inbound
            .borrow_mut()
            .extend(beats_to(&out, c_host()));
    }
    standby.turn(now);
}

/// A serves the warm volume for 30 turns while its agent's heartbeats reach C's, then A's process stops. Returns the
/// stage's registry and media, A's exit, and both agents.
fn serve_beside(volume: (Shared, Media), store: &Shared) -> (Control, Media, Exit, Owner, Standby) {
    staged_over(volume, |mut stage| {
        let (mut owner, mut standby) = agents(store);
        let mut duties = linked_duties(&stage, records(), owner.link);
        let turns = Cell::new(0);
        let (served, _) = stage.serve_until(
            |_, _, stop| {
                if turns.get() >= 30 {
                    stop.store(true, Ordering::Release);
                }
            },
            |a: &mut TestOwner<'_>, now| {
                turns.set(turns.get() + 1);
                let exit = duties.turn(a, now);
                exchange(&mut owner, &mut standby, now, false);
                exit
            },
        );
        (
            stage.registry.clone(),
            stage.media.clone(),
            served.exit,
            owner,
            standby,
        )
    })
}

/// Host loss: A stops with its heartbeats. C's agent nominates A's target, C's standby wait takes the shard
/// over and the tenure serves the retained set `Live`, and A's next incarnation derives `Unnamed` from the records.
#[test]
fn a_lost_owners_standby_takes_over_and_serves_the_retained_set() {
    let volume = warm_volume_certified(0);
    let store = volume.0.clone();
    let (registry, media, exit, _, mut standby) = serve_beside(volume, &store);
    assert_eq!(exit, Exit::Stopped);
    assert_eq!(standby.nominations.get(), 0, "A's heartbeats kept it alive");
    let succeeded = succeed(&store, &media, &registry, &mut standby);
    assert_eq!(succeeded.exit, Exit::Stopped);
    assert!(succeeded.nominations >= 1);
    let record = shard_now(&store);
    assert_eq!((record.owner, record.standby), (c_host(), None));
    let expected: Vec<_> = (1..=4).map(|n| (n, Some(retained(n)))).collect();
    assert_eq!(succeeded.served, expected, "C serves the retained set");
    let next = role(&mut client(&store), shard(), &holder_of(a_host()));
    assert_eq!(next, Ok(Role::Unnamed), "A's next incarnation");
}

/// The status A's agent turns over once A's process has stopped: a process of A's shard and volume that reports
/// `Held`.
fn held_status() -> Status {
    Status::idle(shard(), volume_id(), 2, Phase::Held)
}

/// One turn of A's agent over the held status at `now`, its heartbeats to C delivered; returns A's health bit.
fn held_turn(owner: &mut Owner, standby: &Standby, now: u64) -> bool {
    let statuses = [held_status()];
    let out = owner.agent.turn(
        now,
        Inputs {
            statuses: &statuses,
            clock: clock(now),
            ..Inputs::NONE
        },
    );
    standby
        .inbound
        .borrow_mut()
        .extend(beats_to(&out, c_host()));
    owner.agent.healthy(now)
}

/// A held owner: A serves, then its process stops and A's agent goes on turning over a `Held` status, so every
/// heartbeat it sends reports A unhealthy. C's detector reads the declared hold, the probers' DEAD votes read it too
/// in the one prober class, and C's agent nominates A's target on the ordinary quorum. C's standby wait takes the
/// shard over warm and serves the retained set, and the record names C owner with no standby.
#[test]
fn a_held_owners_standby_takes_it_over_on_one_class_and_serves_the_retained_set() {
    let volume = warm_volume_certified(0);
    let store = volume.0.clone();
    let (registry, media, exit, mut owner, mut standby) = serve_beside(volume, &store);
    assert_eq!(exit, Exit::Stopped);
    assert_eq!(standby.nominations.get(), 0, "A's heartbeats kept it alive");
    standby.reading = DECLARED;
    let unhealthy = Cell::new(true);
    let succeeded = succeed_beside(&store, &media, &registry, &mut standby, &mut |now, c| {
        let healthy = held_turn(&mut owner, c, now);
        unhealthy.set(unhealthy.get() && !healthy);
    });
    assert!(
        unhealthy.get(),
        "A's agent reported A unhealthy at every turn"
    );
    let read = standby.read.borrow();
    assert!(
        read.contains(&Failure::Declared) && !read.contains(&Failure::Silent),
        "C read A's hold declared and never silent: {read:?}"
    );
    assert_eq!(succeeded.exit, Exit::Stopped);
    assert!(succeeded.nominations >= 1);
    let record = shard_now(&store);
    assert_eq!((record.owner, record.standby), (c_host(), None));
    let expected: Vec<_> = (1..=4).map(|n| (n, Some(retained(n)))).collect();
    assert_eq!(succeeded.served, expected, "C serves the retained set");
}

/// The nominations C's agent sends in 20 standby periods while A's agent turns over a held status, with the probers
/// answering `reading` in the one prober class; the run stops at the first nomination.
fn held_nominations(reading: Reading) -> usize {
    let store = warm_volume_certified(0).0.clone();
    let (mut owner, mut standby) = agents(&store);
    standby.reading = reading;
    for n in 1..=20 {
        let now = n * H;
        assert!(!held_turn(&mut owner, &standby, now), "A reads unhealthy");
        standby.turn(now);
        if standby.nominations.get() > 0 {
            break;
        }
    }
    standby.nominations.get()
}

/// The held owner's nomination rests on the declared reading: DEAD votes of the one prober class that read the hold
/// declared nominate, and gray votes of that one class, the probers reading an observed stall, nominate nothing,
/// because gray evidence needs a second observer class.
#[test]
fn a_held_owner_is_nominated_on_declared_votes_and_not_on_gray_votes_of_one_class() {
    assert!(held_nominations(DECLARED) >= 1);
    assert_eq!(
        held_nominations(Reading::Dead(Failure::Gray)),
        0,
        "gray votes of one class"
    );
}

/// The control whose detector reads `D` declared windows as an observed stall fails the held-owner case: C never
/// nominates A, so no takeover starts.
#[test]
fn the_control_that_reads_a_declared_hold_as_a_stall_nominates_no_held_owner() {
    let nominations = planted("declared-as-gray", || held_nominations(DECLARED));
    assert_eq!(nominations, 0, "the control nominates no held owner");
}

/// One GET of A's client: the object, the request, whether the client issued it after C's preempt, the network
/// ordinal its first datagram carries, the bytes it surfaced and its outcome.
struct Asked {
    n: u8,
    id: RequestId,
    after: bool,
    /// [`Rounds::carried`] when the client admitted the GET. The client sends nothing between two polls, and its
    /// next poll sends the GET first, so the GET's first datagram carries this ordinal.
    sent: u64,
    bytes: Vec<u8>,
    outcome: Option<Fetched>,
}

/// Every GET A's client issued across C's preempt, each followed to its outcome or through the drain after A's
/// exit, and the network ordinal of the first datagram sent after the preempt.
#[derive(Default)]
struct Ledger {
    asked: Vec<Asked>,
    fence: Option<u64>,
    /// The GETs issued before the preempt that were still open when it ran.
    open_at_fence: usize,
}

impl Ledger {
    fn collect(&mut self, rounds: &Rounds<'_>) {
        for asked in (self.asked.iter_mut()).filter(|asked| asked.outcome.is_none()) {
            asked.outcome = rounds.fetched(asked.id, &mut asked.bytes);
        }
    }

    /// Collects every open GET, then, while the client's session is active, asks A for objects 1 to 4 in turn: one
    /// GET at a time before the preempt, and one GET after it, retried each round until the client admits it.
    /// `preempted` holds once C's preempt ran; A's owner sends nothing between the preempt and this call, so the fence
    /// is the first ordinal sent after the preempt.
    fn step(&mut self, rounds: &Rounds<'_>, preempted: bool) {
        self.collect(rounds);
        if preempted && self.fence.is_none() {
            self.fence = Some(rounds.carried());
            self.open_at_fence = (self.asked.iter())
                .filter(|asked| asked.outcome.is_none())
                .count();
        }
        let after = self.fence.is_some();
        let ask = if after {
            !self.asked.iter().any(|asked| asked.after)
        } else {
            self.asked.iter().all(|asked| asked.outcome.is_some())
        };
        if !ask || rounds.client.borrow().state() != SessionState::Active {
            return;
        }
        let n = (self.asked.len() % 4) as u8 + 1;
        if let Ok(id) = rounds.try_get(n) {
            self.asked.push(Asked {
                n,
                id,
                after,
                sent: rounds.carried(),
                bytes: Vec::new(),
                outcome: None,
            });
        }
    }
}

/// Rounds the stage runs after A's exit and teardown, so every datagram A sent reaches the client.
const DRAIN_ROUNDS: usize = 200;

struct Isolated {
    exit: Exit,
    ledger: Ledger,
    succeeded: Succeeded,
    /// The datagrams that reached the client carrying an ordinal at or after the fence.
    to_client: usize,
    /// The GETs issued after the preempt whose first datagram A's end received whole.
    reached: usize,
    in_flight: usize,
}

/// An isolated live owner through the drain: A keeps serving while its heartbeats stop reaching C, C takes the
/// shard over through a fencer on the reservation table `c_registry` returns for A's, and A's client asks A for every
/// object C serves after the preempt.
fn isolated(c_registry: fn(&Control) -> Control) -> Isolated {
    let volume = warm_volume_certified(0);
    let store = volume.0.clone();
    staged_over(volume, |mut stage| {
        let (mut owner, mut standby) = agents(&store);
        let mut duties = linked_duties(&stage, records(), owner.link);
        let (registry, media) = (c_registry(&stage.registry), stage.media.clone());
        let turns = Cell::new(0);
        let succeeded = RefCell::new(None);
        let ledger = RefCell::new(Ledger::default());
        let (served, _) = stage.serve_until(
            |rounds, _, _| {
                let preempted = succeeded.borrow().is_some();
                ledger.borrow_mut().step(rounds, preempted);
            },
            |a: &mut TestOwner<'_>, now| {
                turns.set(turns.get() + 1);
                let exit = duties.turn(a, now);
                let isolated = turns.get() > 20;
                exchange(&mut owner, &mut standby, now, isolated);
                if succeeded.borrow().is_none() && standby.nominations.get() > 0 {
                    let taken = succeed(&store, &media, &registry, &mut standby);
                    *succeeded.borrow_mut() = Some(taken);
                }
                exit
            },
        );
        let mut ledger = ledger.into_inner();
        for _ in 0..DRAIN_ROUNDS {
            stage.rounds.round();
            ledger.collect(&stage.rounds);
        }
        let fence = ledger.fence.expect("C's preempt ran while A served");
        Isolated {
            exit: served.exit,
            succeeded: succeeded.into_inner().unwrap(),
            to_client: stage.rounds.delivered_since(CLIENT_END, fence),
            reached: (ledger.asked.iter())
                .filter(|asked| asked.after && stage.rounds.delivered(OWNER_END, asked.sent))
                .count(),
            in_flight: stage.rounds.in_flight(CLIENT_END),
            ledger,
        }
    })
}

/// The objects A's client received complete in a GET issued after the preempt that C also served.
fn served_by_both(isolated: &Isolated) -> Vec<u8> {
    (isolated.ledger.asked.iter())
        .filter(|asked| asked.after && asked.outcome == Some(Fetched::Complete))
        .map(|asked| asked.n)
        .filter(|n| (isolated.succeeded.served.iter()).any(|(m, body)| m == n && body.is_some()))
        .collect()
}

/// An isolated live owner: A keeps serving while its heartbeats stop reaching C. C takes the shard over
/// and serves the retained set; A then observes its deposition and exits `Deposed`. One ledger follows every GET of
/// A's client across the preempt and through a drain after A's teardown: A sends the client no datagram after the
/// preempt, so no GET open at the preempt and none issued after it receives a byte A sent after it, and the GETs
/// for the objects C serves reach A and stay unanswered with nothing left in flight.
#[test]
fn an_isolated_owner_is_deposed_and_no_object_is_served_by_both_tenures_after_the_preempt() {
    let isolated = isolated(Control::clone);
    assert_eq!(isolated.exit, Exit::Deposed, "A observed its deposition");
    assert_eq!(isolated.succeeded.exit, Exit::Stopped);
    let expected: Vec<_> = (1..=4).map(|n| (n, Some(retained(n)))).collect();
    assert_eq!(
        isolated.succeeded.served, expected,
        "C serves the retained set"
    );
    let ledger = &isolated.ledger;
    let before: Vec<_> = (ledger.asked.iter()).filter(|asked| !asked.after).collect();
    assert!(
        (before.iter())
            .any(|asked| asked.outcome == Some(Fetched::Complete)
                && asked.bytes == retained(asked.n)),
        "A served the retained bytes before the preempt"
    );
    assert_eq!(
        ledger.open_at_fence, 1,
        "a GET issued before the preempt was open when it ran"
    );
    assert_eq!(
        isolated.to_client, 0,
        "A sent the client no datagram after the preempt"
    );
    let after: Vec<_> = (ledger.asked.iter()).filter(|asked| asked.after).collect();
    assert_eq!(after.len(), 1, "A's client asked A once after the preempt");
    assert!(
        (isolated.succeeded.served.iter()).any(|(n, body)| *n == after[0].n && body.is_some()),
        "for an object C serves"
    );
    assert_eq!(
        isolated.reached,
        after.len(),
        "A's end received the first datagram of each GET issued after the preempt"
    );
    assert_eq!(isolated.in_flight, 0, "the drain delivered every datagram");
    assert!(
        (after.iter()).all(|asked| asked.outcome.is_none() && asked.bytes.is_empty()),
        "A answered no GET issued after the preempt"
    );
    let both = served_by_both(&isolated);
    assert!(
        both.is_empty(),
        "objects both tenures served after the preempt: {both:?}"
    );
}

/// The control: C's fencer acts on a copy of the reservation table, so C's preempt leaves A's reservation in place
/// and A goes on reading the device after C's takeover. A then serves objects C serves to GETs issued after the
/// preempt, which the ledger sees: the isolation case's "objects both tenures served after the preempt" assertion
/// fails.
#[test]
fn the_control_whose_preempt_misses_the_predecessor_fails_the_isolation_case() {
    let isolated = isolated(|shared| {
        let apart = registry();
        {
            let (table, mut copy) = (shared.borrow(), apart.borrow_mut());
            copy.entries = table.entries.clone();
            copy.rtype = table.rtype;
        }
        apart
    });
    assert_eq!(isolated.succeeded.exit, Exit::Stopped, "C still took over");
    assert!(
        !served_by_both(&isolated).is_empty(),
        "the control serves an object from both tenures after the preempt"
    );
}

/// One turn of `agent` at `now` that syncs the shard record `store` holds.
fn resync(agent: &mut Agent, store: &Shared, now: u64) {
    let records = [shard_now(store)];
    let placement = placement();
    let out = agent.turn(
        now,
        Inputs {
            sync: Some(Synced {
                records: &records,
                placement: &placement,
            }),
            clock: clock(now),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
}

/// A's restart after its process stopped, through `recover` on A's pair, whose bump reply is lost and whose bump
/// commits when `commit` holds; the final status `held_status` builds for it, handed over to A's link.
fn held_restart(store: &Shared, registry: &Control, commit: bool, owner: &Owner) -> Status {
    use crate::storage::store::sim::Arm;
    let arena = crate::storage::gate_fixture::arena_with(16, 9);
    let clock = crate::storage::gate_fixture::Ticking::default();
    let read = shard_now(store);
    for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Timeout { commit }] {
        store.schedule(arm);
    }
    let disk = super::fencer_tests::host(registry, crate::failover::restart::tests::own(), 1).0;
    let recovery = super::recover_tests::recovered(Role::Restart, store, disk, &arena, &clock);
    let super::recover::Recovery::Ended(ended) = recovery else {
        panic!("the restart acquired a tenure or waits");
    };
    assert_eq!(
        ended.exit,
        Exit::Held {
            recovery: crate::failover::retire::Target::of(&read)
        }
    );
    let mut attempts = RecoveryStatus::NO_ATTEMPT;
    attempts.start(crate::failover::report::RecoveryKind::Restart, 0);
    let status = super::recover::held_status(
        (&holder_of(a_host()), shard(), 2),
        (&ended.exit, ended.refusal),
        attempts,
        1,
    )
    .expect("the held restart's final status");
    assert_eq!(shard_now(store).attempts, read.attempts + u32::from(commit));
    assert!(super::recover::hand_over(&owner.link.status, status, 8).is_ok());
    status
}

/// HOST-HEALTH with the real publisher: A serves, stops, and its next incarnation's restart holds after a bump whose
/// reply is lost, at either outcome of that bump. `held_status` builds the final status and `hand_over` gives it to
/// A's link; A's agent takes it once and goes on turning, reports A unhealthy in every heartbeat, and C's standby
/// takes the shard over warm and serves the retained set.
#[test]
fn a_restart_held_after_an_unanswered_bump_is_taken_over_by_its_named_standby() {
    for commit in [false, true] {
        let volume = warm_volume_certified(0);
        let store = volume.0.clone();
        let (registry, media, exit, mut owner, mut standby) = serve_beside(volume, &store);
        assert_eq!(exit, Exit::Stopped);
        let held = held_restart(&store, &registry, commit, &owner);
        let now = standby.now.get() + H;
        resync(&mut owner.agent, &store, now);
        resync(&mut standby.agent, &store, now);
        standby.now.set(now);
        standby.reading = DECLARED;
        let unhealthy = Cell::new(true);
        let succeeded = succeed_beside(&store, &media, &registry, &mut standby, &mut |now, c| {
            let statuses: Vec<Status> = owner.link.status.take().into_iter().collect();
            assert!(statuses.iter().all(|status| *status == held));
            let out = owner.agent.turn(
                now,
                Inputs {
                    statuses: &statuses,
                    clock: clock(now),
                    ..Inputs::NONE
                },
            );
            c.inbound.borrow_mut().extend(beats_to(&out, c_host()));
            unhealthy.set(unhealthy.get() && !owner.agent.healthy(now));
        });
        assert!(
            unhealthy.get(),
            "commit {commit}: A read unhealthy at every turn"
        );
        assert!(succeeded.nominations >= 1, "commit {commit}");
        let record = shard_now(&store);
        assert_eq!(
            (record.owner, record.standby),
            (c_host(), None),
            "commit {commit}"
        );
        let expected: Vec<_> = (1..=4).map(|n| (n, Some(retained(n)))).collect();
        assert_eq!(succeeded.served, expected, "commit {commit}");
    }
}
