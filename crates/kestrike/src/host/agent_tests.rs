use std::cell::Cell;
use std::num::NonZeroU64;

use super::{
    Agent, HostSample, Inputs, Keys, Outputs, RESTART_GRACE_US, ReportSink, STALE_US, Synced,
};
use crate::failover::arbiter::Partition;
use crate::failover::detect::Liveness;
use crate::failover::detect::beat::{self, BeatError, Header};
use crate::failover::detect::host::{ProbeRequest, Reading, WatchBounds, WatchRefusal};
use crate::failover::detect::probe::{self, Message, ProbeError, ProbeKey};
use crate::failover::detect::tests::{SILENT, bounds, clock, header, key, sealed};
use crate::failover::records::{Host, ShardRecord, VolumeId, VolumeState as Recorded};
use crate::failover::report::tests::bare;
use crate::failover::report::{
    BuildIdentity, Detector, Gauge, Headroom, Health, MAX_ENTRIES, Members, Reader, RecordedRole,
    ReportKey, VolumeEntry, Writer,
};
use crate::failover::report::{Ended, Phase};
use crate::failover::retire::Target;
use crate::failover::serving::State;
use crate::failover::sim::host;
use crate::host::link::{Inbound, Status};
use crate::host::{Exit, HostGate};
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration, VolumeState};
use crate::storage::store_tests::record as base_record;

pub(crate) const OWN: u64 = 1;
const BOOT: [u8; 16] = [0xA1; 16];

/// The boot nonce of the test agent of host `h`; [`BOOT`] is the observer's.
pub(crate) fn boot_of(h: Host) -> [u8; 16] {
    [h.get() as u8 | 0xA0; 16]
}
const H: u64 = 10;

thread_local! {
    static UNREVALIDATED: Cell<bool> = const { Cell::new(false) };
    static PUBLISHED_ONLY: Cell<bool> = const { Cell::new(false) };
    static UNBOUND: Cell<bool> = const { Cell::new(false) };
    static ANY_HOLD: Cell<bool> = const { Cell::new(false) };
    static FIRED: Cell<bool> = const { Cell::new(false) };
    static FRESH_LATCH: Cell<bool> = const { Cell::new(false) };
}

/// The health rule's mutant: a held or silent process makes the host unhealthy whether or not its shard names a
/// standby elsewhere. `quiet` is true when the health rule read the host healthy and one of its processes is held or
/// silent. An armed mutant returns `quiet`, which turns that reading unhealthy, and then sets [`fired`].
pub(super) fn any_hold(quiet: bool) -> bool {
    fire(&ANY_HOLD, quiet)
}

/// The plant under which a latched held restart seals only while its status is fresh.
pub(super) fn fresh_latch() -> bool {
    FRESH_LATCH.with(Cell::get)
}

pub(super) fn unbound() -> bool {
    UNBOUND.with(Cell::get)
}

pub(super) fn unrevalidated() -> bool {
    UNREVALIDATED.with(Cell::get)
}

/// The nomination mutant: the agent keeps only the nominations the last tick published. `drops` is true when
/// clearing the kept nominations ahead of that tick's publications changes them. An armed mutant returns `drops`,
/// on which the agent clears them, and then sets [`fired`].
pub(super) fn published_only(drops: bool) -> bool {
    fire(&PUBLISHED_ONLY, drops)
}

/// Whether `plant` is armed and `changes` the agent's decision at its hook, which sets [`fired`].
fn fire(plant: &'static std::thread::LocalKey<Cell<bool>>, changes: bool) -> bool {
    let fires = changes && plant.with(Cell::get);
    if fires {
        FIRED.with(|fired| fired.set(true));
    }
    fires
}

/// Whether the `any-hold` or the `published-only` plant changed an agent's decision on this thread since the last
/// [`arm`].
pub(crate) fn fired() -> bool {
    FIRED.with(Cell::get)
}

/// Whether any plant of [`planted`] is set on this thread.
pub(crate) fn armed() -> bool {
    [
        &UNBOUND,
        &UNREVALIDATED,
        &PUBLISHED_ONLY,
        &ANY_HOLD,
        &FRESH_LATCH,
    ]
    .into_iter()
    .any(|plant| plant.with(Cell::get))
}

/// Arms `plant` on this thread until [`disarm`] and clears [`fired`].
pub(crate) fn arm(plant: &'static str) {
    FIRED.with(|fired| fired.set(false));
    cell_of(plant).with(|plant| plant.set(true));
}

/// Clears `plant` on this thread.
pub(crate) fn disarm(plant: &'static str) {
    cell_of(plant).with(|plant| plant.set(false));
}

fn cell_of(plant: &'static str) -> &'static std::thread::LocalKey<Cell<bool>> {
    match plant {
        "unrevalidated" => &UNREVALIDATED,
        "published-only" => &PUBLISHED_ONLY,
        "unbound" => &UNBOUND,
        "any-hold" => &ANY_HOLD,
        "fresh-latch" => &FRESH_LATCH,
        _ => panic!("no plant {plant}"),
    }
}

pub(crate) fn planted<R>(plant: &'static str, body: impl FnOnce() -> R) -> R {
    arm(plant);
    let result = body();
    disarm(plant);
    result
}

/// The record of `shard` with active volume `vol-<shard>`, the volume of [`status`]'s process for that shard.
pub(crate) fn record(shard: u32, owner: u64, standby: Option<u64>) -> ShardRecord {
    ShardRecord {
        shard: Shard::new(shard).unwrap(),
        active: volume(shard),
        owner: host(owner),
        attempts: 2,
        standby: standby.map(host),
        ..base_record()
    }
}

pub(crate) fn placement() -> Vec<(Host, Partition)> {
    [
        (OWN, 9),
        (11, 1),
        (12, 1),
        (13, 1),
        (14, 4),
        (21, 2),
        (22, 3),
        (31, 5),
    ]
    .into_iter()
    .map(|(h, p)| (host(h), Partition(p)))
    .collect()
}

/// The host key of `h`, from which `detect::tests::key` derives its heartbeat key.
pub(crate) fn host_key(h: Host) -> [u8; 32] {
    [h.get() as u8; 32]
}

pub(crate) fn probe_key(h: Host) -> ProbeKey {
    ProbeKey::derive(&host_key(h))
}

/// The keys of `own` and of each host of `peers`, derived from their host keys.
pub(crate) fn keys(own: Host, peers: &[Host]) -> Keys {
    Keys {
        own: key(own).unwrap(),
        probe: probe_key(own),
        peers: peers.iter().map(|&h| (h, key(h).unwrap())).collect(),
        probers: peers.iter().map(|&h| (h, probe_key(h))).collect(),
    }
}

pub(crate) const BUILD: BuildIdentity = BuildIdentity {
    era: crate::failover::records::ERA,
    digest: Some([0xB1; 32]),
};

/// A report writer of `own` sealing at most once per `period_us`, with the fixture build.
pub(crate) fn reporting(own: Host, period_us: u64) -> (Writer, BuildIdentity) {
    let period = NonZeroU64::new(period_us).unwrap();
    (Writer::new(own, &host_key(own), period).unwrap(), BUILD)
}

pub(crate) const REPORT_US: u64 = 3 * H;

pub(crate) fn agent() -> Agent {
    let peers: Vec<_> = [11, 12, 13, 14, 21, 22, 31].into_iter().map(host).collect();
    Agent::new(
        &HostGate::qualified(),
        (host(OWN), BOOT, 500),
        bounds(),
        keys(host(OWN), &peers),
        reporting(host(OWN), REPORT_US),
    )
    .unwrap()
}

/// `prober`'s reply of `reading` to `request`, sealed for `to` under the prober's probe key.
pub(crate) fn answer(request: ProbeRequest, prober: u64, to: Host, reading: Reading) -> Vec<u8> {
    let reply = Message::Reply { request, reading };
    probe::encode(
        &reply,
        boot_of(to),
        host(prober),
        to,
        &probe_key(host(prober)),
    )
    .to_vec()
}

pub(crate) fn slices(messages: &[Vec<u8>]) -> Vec<&[u8]> {
    messages.iter().map(Vec::as_slice).collect()
}

fn volume(n: u32) -> VolumeId {
    VolumeId::new(&format!("vol-{n:02x}")).unwrap()
}

pub(crate) fn status(shard: u32, phase: Phase) -> Status {
    Status {
        tenure: (phase == Phase::Serving).then(|| {
            (
                ShardGeneration::new(3).unwrap(),
                ActivatedEpoch::new(4).unwrap(),
            )
        }),
        report_age_us: Some(7),
        read_age_us: Some(5),
        io: 100 * u64::from(shard),
        completions: 10 * u64::from(shard),
        pending: u64::from(shard),
        ..Status::idle(Shard::new(shard).unwrap(), volume(shard), shard, phase)
    }
}

fn synced(records: &[ShardRecord], statuses: &[Status]) -> Agent {
    let mut agent = agent();
    let placement = placement();
    let out = agent.turn(
        0,
        Inputs {
            statuses,
            sync: Some(Synced {
                records,
                placement: &placement,
            }),
            clock: clock(0),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    agent
}

fn at(agent: &mut Agent, now: u64, probes: &[Vec<u8>]) -> Outputs {
    agent.turn(
        now,
        Inputs {
            probes: &slices(probes),
            clock: clock(now),
            ..Inputs::NONE
        },
    )
}

fn beat_to(out: &Outputs, peer: u64) -> (Header, Vec<beat::Entry>) {
    let (_, bytes) = (out.heartbeats.iter())
        .find(|(to, _)| *to == host(peer))
        .unwrap_or_else(|| panic!("no heartbeat to {peer}: {:?}", out.heartbeats));
    let (header, entries) = beat::decode(bytes, host(peer), key).unwrap();
    (header, entries.collect())
}

fn nominations(out: &Outputs) -> Vec<(VolumeId, Target, u64)> {
    (out.messages.iter())
        .filter_map(|(to, message)| match message {
            Inbound::Nominate(witness) => Some((*to, witness.target, witness.until_us)),
            _ => None,
        })
        .collect()
}

/// The DEAD replies of probers 21 and 22 to every open probe round of `agent` whose request `keep` selects.
fn votes_on(agent: &Agent, keep: impl Fn(&ProbeRequest) -> bool) -> Vec<Vec<u8>> {
    let requests: Vec<_> = agent.watch().probes().filter(keep).collect();
    (requests.into_iter())
        .flat_map(|r| [21, 22].map(|prober| answer(r, prober, host(OWN), SILENT)))
        .collect()
}

fn dead_votes(agent: &Agent) -> Vec<Vec<u8>> {
    votes_on(agent, |_| true)
}

fn nominated(records: &[ShardRecord], statuses: &[Status]) -> (Agent, Outputs) {
    let mut agent = synced(records, statuses);
    for t in [10, 20, 30] {
        at(&mut agent, t, &[]);
    }
    let votes = dead_votes(&agent);
    at(&mut agent, 30, &votes);
    let votes = dead_votes(&agent);
    let out = at(&mut agent, 40, &votes);
    (agent, out)
}

#[test]
fn a_heartbeat_carries_one_entry_per_tenure_with_summed_counters_to_each_tracked_peer() {
    let records = [
        record(1, OWN, Some(11)),
        record(2, OWN, Some(12)),
        record(3, OWN, Some(11)),
        record(4, OWN, Some(14)),
        record(5, 13, Some(OWN)),
    ];
    let statuses: Vec<_> = (1..=4).map(|s| status(s, Phase::Serving)).collect();
    let mut agent = synced(&records, &statuses);
    let out = agent.turn(
        0,
        Inputs {
            clock: clock(0),
            ..Inputs::NONE
        },
    );
    assert!(
        out.heartbeats.is_empty(),
        "the sync turn sent the window's heartbeats"
    );
    let out = at(&mut agent, H, &[]);
    let mut to: Vec<_> = out.heartbeats.iter().map(|(peer, _)| peer.get()).collect();
    to.sort_unstable();
    assert_eq!(
        to,
        [11, 12, 13, 14, 21, 22, 31],
        "one heartbeat per tracked peer and per placed host a probe may ask"
    );
    for peer in [11, 12, 13, 14] {
        let (header, entries) = beat_to(&out, peer);
        assert_eq!(entries.len(), 4);
        assert_eq!(
            (header.io, header.completions, header.pending),
            (1_000, 100, 10)
        );
        assert!(header.healthy);
        assert_eq!((header.host, header.sequence), (host(OWN), 2));
        let shards: Vec<_> = entries.iter().map(|e| e.shard.get()).collect();
        assert_eq!(shards, [1, 2, 3, 4]);
        assert!(
            (entries.iter()).all(|e| e.read_age_us == Some(5 + H) && e.report_age_us == 7 + H),
            "the status's ages, received at 0, grow by its time in the agent's table: {entries:?}"
        );
    }
    let later = at(&mut agent, H + 5, &[]);
    assert!(later.heartbeats.is_empty(), "one heartbeat per window");
    let fresh = at(&mut agent, STALE_US, &[]);
    assert_eq!(
        beat_to(&fresh, 11).1.len(),
        4,
        "a status at the bound is fresh"
    );
    let stale = at(&mut agent, STALE_US + H, &[]);
    assert!(
        beat_to(&stale, 11).1.is_empty(),
        "a stale status adds no entry"
    );
}

#[test]
fn a_heartbeat_entry_reads_retired_only_for_a_volume_record_past_active() {
    let records = [record(1, OWN, Some(11))];
    let serving = status(1, Phase::Serving);
    let reported = |state| Status {
        entry: Some(VolumeEntry {
            volume: serving.volume,
            shard: serving.shard,
            tenure: serving.tenure,
            volume_state: state,
            ..bare("vol-01", RecordedRole::Owner)
        }),
        ..serving
    };
    for (sent, wire) in [
        (serving, VolumeState::Active),
        (reported(None), VolumeState::Active),
        (reported(Some(Recorded::Provisioning)), VolumeState::Active),
        (reported(Some(Recorded::Fresh)), VolumeState::Active),
        (reported(Some(Recorded::Active)), VolumeState::Active),
        (reported(Some(Recorded::Retired)), VolumeState::Retired),
        (reported(Some(Recorded::Deleted)), VolumeState::Retired),
    ] {
        let mut agent = synced(&records, &[sent]);
        let (_, entries) = beat_to(&at(&mut agent, H, &[]), 11);
        let volumes: Vec<_> = entries.iter().map(|e| e.volume).collect();
        let state = sent.entry.map(|entry| entry.volume_state);
        assert_eq!(volumes, [wire], "volume record state {state:?}");
    }
}

/// The heartbeat uses the turn before receipt as the sample time to bound read and report ages from above. The
/// staleness bound starts at receipt.
#[test]
fn a_heartbeat_dates_a_status_from_the_turn_before_the_one_that_received_it() {
    let records = [record(1, OWN, Some(11))];
    let mut agent = synced(&records, &[]);
    at(&mut agent, H, &[]);
    let received_at = 2 * H - 3;
    let out = agent.turn(
        received_at,
        Inputs {
            statuses: &[status(1, Phase::Serving)],
            clock: clock(received_at),
            ..Inputs::NONE
        },
    );
    assert!(out.heartbeats.is_empty(), "the window's heartbeat is sent");
    let (_, entries) = beat_to(&at(&mut agent, 2 * H, &[]), 11);
    let ages: Vec<_> = (entries.iter())
        .map(|e| (e.read_age_us, e.report_age_us))
        .collect();
    assert_eq!(
        ages,
        [(Some(5 + H), 7 + H)],
        "the status's ages, sampled after the turn at {H}, grow by the time since that turn"
    );
    let fresh = at(&mut agent, received_at + STALE_US, &[]);
    assert_eq!(
        beat_to(&fresh, 11).1.len(),
        1,
        "a status is fresh for the bound after its receipt"
    );
    let stale = at(&mut agent, received_at + STALE_US + H, &[]);
    assert!(beat_to(&stale, 11).1.is_empty());
}

fn health(records: &[ShardRecord], statuses: &[Status], silent_for: u64) -> bool {
    let mut agent = synced(records, statuses);
    let out = at(&mut agent, silent_for.max(H), &[]);
    beat_to(&out, 11).0.healthy
}

#[test]
fn the_host_is_unhealthy_only_for_a_held_or_silent_process_whose_shard_has_a_standby_elsewhere() {
    let grace = RESTART_GRACE_US;
    let named = [record(1, OWN, Some(11))];
    let tracked = record(2, 12, Some(11));
    let unnamed = [record(1, OWN, None), tracked];
    let held = [status(1, Phase::Held)];
    let serving = [status(1, Phase::Serving)];
    assert!(!health(&named, &held, H), "held with a standby elsewhere");
    assert!(
        !health(&named, &serving, grace + H),
        "silent past the restart grace"
    );
    assert!(health(&named, &serving, grace), "silent inside the grace");
    assert!(health(&named, &serving, H));
    assert!(health(&unnamed, &held, H), "no standby: held");
    assert!(health(&unnamed, &serving, grace + H), "no standby: silent");
    let own_standby = [record(1, OWN, Some(OWN)), tracked];
    assert!(health(&own_standby, &held, H), "the standby is this host");
    for quiet in [Phase::Parked, Phase::Closing] {
        assert!(health(&named, &[status(1, quiet)], grace + H), "{quiet:?}");
    }
    let stopped = Status {
        ended: Some(Ended::Stopped),
        ..status(1, Phase::Closing)
    };
    assert!(health(&named, &[stopped], grace + H), "a stopped process");
    let restarted = Status {
        ended: Some(Ended::Stopped),
        ..status(1, Phase::Starting)
    };
    assert!(
        !health(&named, &[restarted], grace + H),
        "a later incarnation silent past the grace"
    );
    let rerun = Status {
        ended: Some(Ended::Held),
        ..status(1, Phase::Starting)
    };
    assert!(!health(&named, &[rerun], H), "the last incarnation held");
    let served = Status {
        ended: Some(Ended::Held),
        ..status(1, Phase::Serving)
    };
    assert!(health(&named, &[served], H), "the rerun serves");
    for phase in [
        Phase::Starting,
        Phase::Recovering,
        Phase::Standby,
        Phase::Serving,
        Phase::Withdrawn,
    ] {
        assert!(
            !health(&named, &[status(1, phase)], grace + H),
            "{phase:?} silent"
        );
        assert!(
            health(&named, &[status(1, phase)], grace),
            "{phase:?} in the grace"
        );
    }
}

#[test]
fn an_armed_agent_mutant_fires_only_on_a_decision_it_changes() {
    let named = [record(1, OWN, Some(11))];
    let unnamed = [record(1, OWN, None), record(2, 12, Some(11))];
    let held = [status(1, Phase::Held)];
    let serving = [status(1, Phase::Serving)];
    let read = |plant, records: &[ShardRecord], statuses: &[Status]| {
        planted(plant, || (health(records, statuses, H), fired()))
    };
    let (healthy, unhealthy) = (true, false);
    assert_eq!(
        read("any-hold", &unnamed, &serving),
        (healthy, false),
        "a serving process"
    );
    assert_eq!(
        read("any-hold", &named, &held),
        (unhealthy, false),
        "the health rule's own reading"
    );
    assert_eq!(
        read("any-hold", &unnamed, &held),
        (unhealthy, true),
        "a held process the mutant turns unhealthy"
    );
    let mixed = [
        record(1, OWN, None),
        record(2, 12, Some(11)),
        record(3, OWN, Some(11)),
    ];
    let both = [status(1, Phase::Held), status(3, Phase::Held)];
    assert_eq!(
        read("any-hold", &mixed, &both),
        (unhealthy, false),
        "an unnamed hold ahead of a named one, which the health rule already reads unhealthy"
    );
    assert_eq!(
        read("published-only", &named, &serving),
        (healthy, false),
        "a turn with an empty kept set"
    );
}

/// The `published-only` mutant fires where its clear changes the kept nominations. A kept nomination that no
/// standby process took, and that the detector publishes again under a new observation generation, is kept unsent
/// with the mutant as without it. The mutant fires once the last tick published nothing and its clear drops the
/// kept nomination.
#[test]
fn the_published_only_mutant_fires_only_when_its_clear_changes_the_kept_nominations() {
    let records = [record(1, 11, Some(OWN))];
    // No process of this host shows `Standby`, so the kept nomination stays unsent.
    let (mut agent, first) = nominated(&records, &[]);
    assert!(nominations(&first).is_empty());
    let moved: Vec<_> = (placement().into_iter())
        .map(|(h, p)| (h, if h == host(11) { Partition(4) } else { p }))
        .collect();
    let sync = Some(Synced {
        records: &records,
        placement: &moved,
    });
    let out = agent.turn(
        50,
        Inputs {
            sync,
            clock: clock(50),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    let mut t = 60;
    while agent.watch().census().nominations < 2 {
        assert!(t <= 200, "the detector publishes the target again");
        let votes = dead_votes(&agent);
        at(&mut agent, t, &votes);
        t += 10;
    }
    let kept = |agent: &Agent| -> Vec<_> {
        (agent.kept.iter())
            .map(|kept| (kept.nominated, kept.sent_at))
            .collect()
    };
    let republished = kept(&agent);
    assert_eq!(republished, [(agent.watch().published()[0], None)]);
    let changed = planted("published-only", || {
        agent.keep();
        fired()
    });
    assert_eq!(
        (changed, kept(&agent)),
        (false, republished),
        "the clear and the last tick's publication rebuild the same unsent nomination"
    );
    at(&mut agent, t, &[]);
    assert!(agent.watch().published().is_empty());
    assert_eq!(agent.kept.len(), 1);
    let changed = planted("published-only", || {
        agent.keep();
        fired()
    });
    assert_eq!(
        (changed, agent.kept.len()),
        (true, 0),
        "the clear drops a nomination the last tick did not publish"
    );
}

#[test]
fn a_held_process_counts_only_while_its_shard_names_this_host_owner() {
    let held = [status(1, Phase::Held)];
    let mut agent = synced(&[record(1, OWN, Some(11))], &held);
    assert!(!beat_to(&at(&mut agent, H, &[]), 11).0.healthy);
    let placement = placement();
    let moved = [record(1, 11, Some(14))];
    let out = agent.turn(
        2 * H,
        Inputs {
            sync: Some(Synced {
                records: &moved,
                placement: &placement,
            }),
            clock: clock(2 * H),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    assert!(beat_to(&out, 11).0.healthy, "the shard moved to 11");
    let standby = [record(1, 14, Some(11)), record(2, OWN, Some(11))];
    let mut agent = synced(&standby, &[status(1, Phase::Held)]);
    assert!(
        beat_to(&at(&mut agent, H, &[]), 11).0.healthy,
        "a shard this host does not own"
    );
}

/// For a role this host owns with a standby on another host, the first sync naming the role starts
/// [`RESTART_GRACE_US`]. The host becomes unhealthy when that grace has passed and the table holds no status of
/// the role's volume. Repeated syncs naming the role keep the start, and a status of the role's volume ends the
/// check. After a sync that does not name the role, the next sync naming it starts a new grace when the table
/// holds no such status.
#[test]
fn an_owned_role_with_no_status_past_the_restart_grace_makes_the_host_unhealthy() {
    let grace = RESTART_GRACE_US;
    let named = [record(1, OWN, Some(11))];
    let tracked = record(2, 12, Some(11));
    assert!(health(&named, &[], grace), "no status inside the grace");
    assert!(!health(&named, &[], grace + H), "no status past the grace");
    for (records, why) in [
        ([record(1, OWN, None), tracked], "no standby"),
        ([record(1, OWN, Some(OWN)), tracked], "this host stands by"),
        (
            [record(1, 11, Some(OWN)), tracked],
            "this host is the standby",
        ),
    ] {
        assert!(health(&records, &[], grace + H), "{why}");
    }
    let other = [Status {
        volume: volume(0xee),
        ..status(1, Phase::Serving)
    }];
    assert!(
        !health(&named, &other, grace + H),
        "a status of another volume of the shard is no status of the role"
    );

    let placement = placement();
    let sync = |agent: &mut Agent, now: u64, records: &[ShardRecord]| {
        let out = agent.turn(
            now,
            Inputs {
                sync: Some(Synced {
                    records,
                    placement: &placement,
                }),
                clock: clock(now),
                ..Inputs::NONE
            },
        );
        assert!(out.refused.is_empty(), "{:?}", out.refused);
        beat_to(&out, 11).0.healthy
    };
    let mut agent = synced(&named, &[]);
    assert!(sync(&mut agent, grace, &named), "inside the grace");
    assert!(
        !beat_to(&at(&mut agent, grace + H, &[]), 11).0.healthy,
        "a sync that names the role again keeps its start"
    );
    let starting = [status(1, Phase::Starting)];
    let out = agent.turn(
        grace + 2 * H,
        Inputs {
            statuses: &starting,
            clock: clock(grace + 2 * H),
            ..Inputs::NONE
        },
    );
    assert!(
        beat_to(&out, 11).0.healthy,
        "a status of the role's process ends the rule"
    );

    let mut agent = synced(&named, &[]);
    assert!(sync(&mut agent, H, &[record(1, 11, Some(14))]));
    assert!(sync(&mut agent, grace, &named));
    assert!(
        beat_to(&at(&mut agent, grace + H, &[]), 11).0.healthy,
        "the role's grace starts over at the sync that names it again"
    );
    assert!(
        !beat_to(&at(&mut agent, 2 * grace + H, &[]), 11).0.healthy,
        "and ends one grace after that sync"
    );
}

#[test]
fn the_heartbeat_progress_counters_never_fall_when_a_tenure_resets_its_counts() {
    let records = [record(1, OWN, Some(11))];
    let mut agent = synced(&records, &[status(1, Phase::Serving)]);
    let first = beat_to(&at(&mut agent, H, &[]), 11).0;
    assert_eq!((first.io, first.completions), (100, 10));
    let rolled = Status {
        tenure: Some((
            ShardGeneration::new(3).unwrap(),
            ActivatedEpoch::new(6).unwrap(),
        )),
        io: 5,
        completions: 1,
        ..status(1, Phase::Serving)
    };
    let out = agent.turn(
        2 * H,
        Inputs {
            statuses: &[rolled],
            clock: clock(2 * H),
            ..Inputs::NONE
        },
    );
    let second = beat_to(&out, 11).0;
    assert_eq!(
        (second.io, second.completions),
        (105, 11),
        "the new tenure adds on"
    );
    let later = Status { io: 9, ..rolled };
    let out = agent.turn(
        3 * H,
        Inputs {
            statuses: &[later],
            clock: clock(3 * H),
            ..Inputs::NONE
        },
    );
    assert_eq!(
        beat_to(&out, 11).0.io,
        109,
        "the same tenure adds its increase"
    );
    let lower = Status { io: 7, ..rolled };
    let again = Status { io: 10, ..rolled };
    for (t, sample, total) in [(4 * H, lower, 109), (5 * H, again, 110)] {
        let out = agent.turn(
            t,
            Inputs {
                statuses: &[sample],
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        assert_eq!(
            beat_to(&out, 11).0.io,
            total,
            "a lower sample of one tenure adds nothing and keeps the high water as the baseline"
        );
    }
    let stale = at(&mut agent, 5 * H + STALE_US + 1, &[]);
    assert_eq!(
        beat_to(&stale, 11).0.io,
        110,
        "a stale status keeps the total"
    );
}

/// A sync that stops listing shard 2 keeps its fresh status: the next heartbeat still carries the process's entry,
/// and the same process's statuses after the sync add only their increase.
#[test]
fn a_sync_keeps_a_fresh_status_of_an_unlisted_role_and_its_progress_baseline() {
    let records = [record(1, OWN, Some(11)), record(2, OWN, Some(11))];
    let statuses = [status(1, Phase::Serving), status(2, Phase::Serving)];
    let mut agent = synced(&records, &statuses);
    let first = beat_to(&at(&mut agent, H, &[]), 11).0;
    assert_eq!((first.io, first.completions), (300, 30));
    let placement = placement();
    let moved = [record(1, OWN, Some(11)), record(2, 12, Some(11))];
    let out = agent.turn(
        H + 1,
        Inputs {
            sync: Some(Synced {
                records: &moved,
                placement: &placement,
            }),
            clock: clock(H + 1),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    assert_eq!(
        beat_to(&at(&mut agent, 2 * H, &[]), 11).1.len(),
        2,
        "the unlisted process's fresh status keeps its heartbeat entry"
    );
    let grown = Status {
        io: 250,
        completions: 25,
        ..statuses[1]
    };
    for (t, sent, totals) in [
        (3 * H, statuses, (300, 30)),
        (4 * H, [statuses[0], grown], (350, 35)),
    ] {
        let out = agent.turn(
            t,
            Inputs {
                statuses: &sent,
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        let header = beat_to(&out, 11).0;
        assert_eq!(
            (header.io, header.completions),
            totals,
            "{t}: the unlisted process's statuses after the sync add only their increase"
        );
    }
}

#[test]
fn a_status_of_another_volume_of_a_shard_counts_for_neither_health_nor_nomination() {
    let old = volume(0xee);
    let held = Status {
        volume: old,
        ..status(1, Phase::Held)
    };
    let records = [record(1, OWN, Some(11))];
    let mut agent = synced(&records, &[held]);
    assert!(
        beat_to(&at(&mut agent, H, &[]), 11).0.healthy,
        "a held process of a volume the record does not name active leaves the host healthy"
    );
    let standing = Status {
        volume: old,
        ..status(1, Phase::Standby)
    };
    let (_, out) = nominated(&[record(1, 11, Some(OWN))], &[standing]);
    assert!(
        nominations(&out).is_empty(),
        "no nomination goes to a process of another volume"
    );
}

/// A sync that still lists a kept nomination's shard and target keeps it, a refused sync keeps it, and a sync
/// whose record of the shard names another target drops it.
#[test]
fn a_kept_nomination_stays_until_a_sync_stops_listing_its_target() {
    let records = [record(1, 11, Some(OWN))];
    let (mut agent, _) = nominated(&records, &[status(1, Phase::Standby)]);
    assert_eq!(agent.kept.len(), 1);
    let placement = placement();
    let retargeted = [ShardRecord {
        attempts: records[0].attempts + 1,
        ..record(1, 11, Some(OWN))
    }];
    for (t, records, placement, accepted, kept) in [
        (41, &records, &placement[..], true, 1),
        (42, &records, &[][..], false, 1),
        (43, &retargeted, &placement[..], true, 0),
    ] {
        let out = agent.turn(
            t,
            Inputs {
                sync: Some(Synced { records, placement }),
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        assert_eq!(out.refused.is_empty(), accepted, "{t}: {:?}", out.refused);
        assert_eq!(agent.kept.len(), kept, "{t}");
    }
}

#[test]
fn a_kept_nomination_is_sent_once_per_window_while_it_revalidates() {
    let records = [record(1, 11, Some(OWN))];
    let statuses = [status(1, Phase::Standby)];
    let (mut agent, first) = nominated(&records, &statuses);
    let target = Target::of(&records[0]);
    assert_eq!(nominations(&first), [(statuses[0].volume, target, 40 + H)]);
    assert!(
        first.deadline.is_some_and(|at| at > 40 && at <= 40 + H),
        "the resend is due within a window: {:?}",
        first.deadline
    );
    assert_eq!(agent.watch().census().nominations, 1);
    let between = at(&mut agent, 45, &[]);
    assert!(nominations(&between).is_empty(), "one per window");
    for t in [50, 60] {
        let votes = dead_votes(&agent);
        let out = at(&mut agent, t, &votes);
        assert_eq!(
            nominations(&out),
            [(statuses[0].volume, target, t + H)],
            "{t}"
        );
        assert!(agent.watch().published().is_empty(), "{t}: published once");
    }
    assert_eq!(agent.watch().census().nominations, 1);
    let placement = placement();
    let unlisted = [record(2, 12, Some(OWN))];
    let votes = dead_votes(&agent);
    let out = agent.turn(
        70,
        Inputs {
            probes: &slices(&votes),
            sync: Some(Synced {
                records: &unlisted,
                placement: &placement,
            }),
            clock: clock(70),
            ..Inputs::NONE
        },
    );
    assert!(nominations(&out).is_empty(), "the sync stopped listing it");
}

#[test]
fn a_new_observation_generation_ends_the_kept_nominations_messages() {
    let records = [record(1, 11, Some(OWN))];
    let statuses = [status(1, Phase::Standby)];
    let (mut agent, first) = nominated(&records, &statuses);
    assert_eq!(nominations(&first).len(), 1);
    let moved: Vec<_> = (placement().into_iter())
        .map(|(h, p)| (h, if h == host(11) { Partition(4) } else { p }))
        .collect();
    let out = agent.turn(
        50,
        Inputs {
            sync: Some(Synced {
                records: &records,
                placement: &moved,
            }),
            clock: clock(50),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    assert!(nominations(&out).is_empty(), "the owner's generation moved");
    assert!(out.deadline.is_some_and(|at| at > 50), "{:?}", out.deadline);
    for t in [60, 70] {
        let votes = dead_votes(&agent);
        let out = at(&mut agent, t, &votes);
        assert!(nominations(&out).is_empty());
        assert!(
            out.deadline.is_some_and(|at| at > t),
            "{t}: {:?}",
            out.deadline
        );
    }
}

/// After the owner's observation generation moves, the detector publishes the target again under the new
/// generation once a new quorum forms; the agent keeps one nomination per target, replaced by the new one, and its
/// witness reaches the standby again.
#[test]
fn a_nomination_of_a_new_observation_generation_replaces_the_kept_one() {
    let records = [record(1, 11, Some(OWN))];
    let statuses = [status(1, Phase::Standby)];
    let (mut agent, first) = nominated(&records, &statuses);
    assert_eq!(nominations(&first).len(), 1);
    let old = agent.kept[0].nominated;
    let moved: Vec<_> = (placement().into_iter())
        .map(|(h, p)| (h, if h == host(11) { Partition(4) } else { p }))
        .collect();
    let out = agent.turn(
        50,
        Inputs {
            statuses: &statuses,
            sync: Some(Synced {
                records: &records,
                placement: &moved,
            }),
            clock: clock(50),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    let mut sent = Vec::new();
    for t in (60..=200).step_by(10) {
        let votes = dead_votes(&agent);
        let out = agent.turn(
            t,
            Inputs {
                statuses: &statuses,
                probes: &slices(&votes),
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        sent = nominations(&out);
        if !sent.is_empty() {
            break;
        }
    }
    let target = Target::of(&records[0]);
    assert_eq!(
        sent.iter()
            .map(|(to, at, _)| (*to, *at))
            .collect::<Vec<_>>(),
        [(statuses[0].volume, target)],
        "the new generation's nomination reaches the standby"
    );
    assert_eq!(agent.watch().census().nominations, 2, "published twice");
    assert_eq!(agent.kept.len(), 1, "one kept nomination per target");
    let new = agent.kept[0].nominated;
    assert_eq!((new.shard, new.nomination.target), (old.shard, target));
    assert_ne!(new.generation, old.generation, "the kept one is replaced");
}

#[test]
fn a_nomination_goes_only_to_the_process_whose_status_shows_standby_for_its_shard() {
    let records = [record(1, 11, Some(OWN))];
    let statuses = [status(1, Phase::Parked), status(2, Phase::Standby)];
    let (mut agent, first) = nominated(&records, &statuses);
    assert!(nominations(&first).is_empty());
    let standing = [status(1, Phase::Standby)];
    let votes = dead_votes(&agent);
    let out = agent.turn(
        50,
        Inputs {
            statuses: &standing,
            probes: &slices(&votes),
            clock: clock(50),
            ..Inputs::NONE
        },
    );
    assert_eq!(nominations(&out).len(), 1, "the standby status arrived");
}

/// Each window from 40 to 140: the detector's suspects, whether the turn returned the repair demand, and the
/// nominations it sent. Owner 11 falls silent first and is nominated, 12 falls silent at 30 and 13 at 60, so one
/// window holds two suspects before the third reaches the threshold of 3.
fn self_suspected() -> Vec<(usize, bool, usize)> {
    let records = [
        record(1, 11, Some(OWN)),
        record(2, 12, Some(OWN)),
        record(3, 13, Some(OWN)),
    ];
    let statuses = [status(1, Phase::Standby)];
    let mut agent = synced(&records, &statuses);
    let mut windows = Vec::new();
    for (sequence, t) in (10..=140).step_by(10).enumerate() {
        let senders: Vec<u64> = [(12, 30), (13, 60)]
            .into_iter()
            .filter(|(_, until)| t <= *until)
            .map(|(h, _)| h)
            .collect();
        let beats: Vec<_> = (senders.into_iter())
            .map(|h| sealed(&header(h, 1, sequence as u64 + 1), &[], OWN))
            .collect();
        let beats: Vec<&[u8]> = beats.iter().map(Vec::as_slice).collect();
        let votes = votes_on(&agent, |request| request.suspect == host(11));
        let out = agent.turn(
            t,
            Inputs {
                heartbeats: &beats,
                probes: &slices(&votes),
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        if t >= 40 {
            let suspects = agent.watch().census().suspected;
            windows.push((suspects, out.repair.is_some(), nominations(&out).len()));
        }
    }
    windows
}

#[test]
fn an_observer_that_suspects_itself_sends_no_nomination_and_reports_the_repair_demand() {
    let windows = self_suspected();
    assert!(
        windows
            .iter()
            .any(|&(suspects, _, sent)| suspects == 2 && sent > 0),
        "two suspects stay below the threshold of 3 and the nomination is sent: {windows:?}"
    );
    assert!(
        windows.iter().any(|&(_, repair, _)| repair),
        "the agent reports the repair demand: {windows:?}"
    );
    assert!(
        (windows.iter()).all(|&(_, repair, sent)| !repair || sent == 0),
        "no nomination once the observer suspects itself: {windows:?}"
    );
}

#[test]
fn the_control_that_skips_revalidation_fails_the_self_suspicion_scenario() {
    let windows = planted("unrevalidated", self_suspected);
    assert!(
        (windows.iter()).any(|&(_, repair, sent)| repair && sent > 0),
        "the control nominates while the observer suspects itself: {windows:?}"
    );
}

#[test]
fn an_admitted_heartbeat_that_advances_the_peer_read_time_sends_one_peer_to_each_serving_status() {
    let records = [record(1, OWN, Some(11)), record(2, OWN, Some(11))];
    let statuses = [
        status(1, Phase::Serving),
        status(2, Phase::Serving),
        status(3, Phase::Standby),
    ];
    let mut agent = synced(&records, &statuses);
    let entry = beat::Entry {
        shard: Shard::new(9).unwrap(),
        generation: ShardGeneration::new(3).unwrap(),
        epoch: ActivatedEpoch::new(2).unwrap(),
        volume: VolumeState::Active,
        report_age_us: 0,
        read_age_us: Some(0),
    };
    let acking = sealed(
        &Header {
            ack: 1,
            ack_boot: BOOT,
            ..header(11, 1, 1)
        },
        &[entry],
        OWN,
    );
    let out = agent.turn(
        5,
        Inputs {
            heartbeats: &[&acking],
            clock: clock(5),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    let peers: Vec<_> = (out.messages.iter())
        .filter(|(_, message)| matches!(message, Inbound::Peer { .. }))
        .copied()
        .collect();
    let read = Inbound::Peer { read_at: Some(0) };
    assert_eq!(
        peers,
        [(statuses[0].volume, read), (statuses[1].volume, read)],
        "the acknowledged heartbeat, sent at 0, dates the read"
    );
    let again = at(&mut agent, 6, &[]);
    assert!(
        again.messages.is_empty(),
        "an unchanged read time sends nothing"
    );
}

fn peers(out: &Outputs) -> Vec<(VolumeId, Inbound)> {
    (out.messages.iter())
        .filter(|(_, message)| matches!(message, Inbound::Peer { .. }))
        .copied()
        .collect()
}

/// A process that restarts on the same volume, and a process that opens another tenure, are sent the unchanged peer
/// read time again on the turn their serving status arrives; an unchanged status is sent nothing.
#[test]
fn a_process_restarted_on_the_same_volume_is_sent_the_peer_read_time_again() {
    let records = [record(1, OWN, Some(11))];
    let serving = status(1, Phase::Serving);
    let mut agent = synced(&records, &[serving]);
    let entry = beat::Entry {
        shard: Shard::new(9).unwrap(),
        generation: ShardGeneration::new(3).unwrap(),
        epoch: ActivatedEpoch::new(2).unwrap(),
        volume: VolumeState::Active,
        report_age_us: 0,
        read_age_us: Some(0),
    };
    let acking = sealed(
        &Header {
            ack: 1,
            ack_boot: BOOT,
            ..header(11, 1, 1)
        },
        &[entry],
        OWN,
    );
    let out = agent.turn(
        5,
        Inputs {
            heartbeats: &[&acking],
            clock: clock(5),
            ..Inputs::NONE
        },
    );
    let read = Inbound::Peer { read_at: Some(0) };
    assert_eq!(peers(&out), [(serving.volume, read)]);
    let restarted = Status {
        pid: serving.pid + 1,
        ..serving
    };
    let reopened = Status {
        tenure: Some((
            ShardGeneration::new(3).unwrap(),
            ActivatedEpoch::new(6).unwrap(),
        )),
        ..restarted
    };
    for (t, sent, expected) in [
        (6, serving, vec![]),
        (7, restarted, vec![(serving.volume, read)]),
        (8, restarted, vec![]),
        (9, reopened, vec![(serving.volume, read)]),
    ] {
        let out = agent.turn(
            t,
            Inputs {
                statuses: &[sent],
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        assert_eq!(agent.watch().peer_read_at(), Some(0), "{t}");
        assert_eq!(peers(&out), expected, "{t}: {sent:?}");
    }
    // Past the staleness bound the process leaves the list of processes sent the read time, so the renewal of
    // its status, with the same process id and tenure, is sent the unchanged read time once.
    let stale = 9 + STALE_US + 1;
    let out = at(&mut agent, stale, &[]);
    assert_eq!(peers(&out), []);
    for (t, expected) in [
        (stale + 1, vec![(serving.volume, read)]),
        (stale + 2, vec![]),
    ] {
        let out = agent.turn(
            t,
            Inputs {
                statuses: &[reopened],
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        assert_eq!(agent.watch().peer_read_at(), Some(0), "{t}");
        assert_eq!(peers(&out), expected, "{t}");
    }
}

#[test]
fn a_heartbeat_with_a_wrong_tag_is_refused() {
    let records = [record(1, OWN, Some(11))];
    let mut agent = synced(&records, &[]);
    let mut forged = sealed(&header(11, 1, 1), &[], OWN);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let out = agent.turn(
        5,
        Inputs {
            heartbeats: &[&forged],
            clock: clock(5),
            ..Inputs::NONE
        },
    );
    assert_eq!(out.refused, [WatchRefusal::Beat(BeatError::Tag)]);
}

/// The records name host 11 only, so the detector tracks no host 12, whose key the agent holds. A forged heartbeat
/// of host 12 is refused by its tag and a sealed one as an untracked sender, and a host with no key as a sender.
#[test]
fn an_untracked_senders_heartbeat_is_refused_by_its_tag_before_its_tracking() {
    let records = [record(1, OWN, Some(11))];
    let mut agent = synced(&records, &[]);
    let untracked = sealed(&header(12, 1, 1), &[], OWN);
    let mut forged = untracked.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let unkeyed = sealed(&header(99, 1, 1), &[], OWN);
    let out = agent.turn(
        5,
        Inputs {
            heartbeats: &[&forged, &untracked, &unkeyed],
            clock: clock(5),
            ..Inputs::NONE
        },
    );
    assert_eq!(
        out.refused,
        [
            WatchRefusal::Beat(BeatError::Tag),
            WatchRefusal::Beat(BeatError::Sender),
            WatchRefusal::Beat(BeatError::Sender),
        ]
    );
}

/// The window's heartbeat to a peer acknowledges the whole boot nonce and sequence of the last heartbeat admitted
/// from it: a refused replay leaves the acknowledgment, a later boot of the peer with a lower sequence replaces
/// it, and a peer the agent admitted none from reads no acknowledgment. The nonces differ at every byte and the
/// sequences fill both halves of their field, apart from the progress counts, so a narrowed, shifted or
/// misplaced read changes the acknowledged value.
#[test]
fn a_heartbeat_acknowledges_the_boot_and_sequence_of_the_last_one_admitted() {
    let records = [record(1, OWN, Some(11)), record(2, OWN, Some(12))];
    let mut agent = synced(&records, &[]);
    let nonce: [u8; 16] = std::array::from_fn(|at| 0x11 + at as u8);
    let sequence = 0x0102_0304_0506_0708_u64;
    let from_11 = |boot: [u8; 16], stamp: u8, sequence: u64| {
        let header = Header {
            boot,
            io: 5,
            completions: 6,
            ..header(11, stamp, sequence)
        };
        sealed(&header, &[], OWN)
    };
    let beats = [
        from_11(nonce, 3, sequence),
        from_11(nonce, 3, sequence + 2),
        from_11(nonce, 3, sequence + 1),
    ];
    let out = agent.turn(
        5,
        Inputs {
            heartbeats: &slices(&beats),
            clock: clock(5),
            ..Inputs::NONE
        },
    );
    assert_eq!(out.refused, [WatchRefusal::Replay]);
    let out = at(&mut agent, H, &[]);
    let (to_11, _) = beat_to(&out, 11);
    assert_eq!((to_11.ack, to_11.ack_boot), (sequence + 2, nonce));
    let (to_12, _) = beat_to(&out, 12);
    assert_eq!((to_12.ack, to_12.ack_boot), (0, [0; 16]));
    let rebooted: [u8; 16] = std::array::from_fn(|at| 0xF1 - at as u8);
    let reboot = from_11(rebooted, 9, 3);
    let out = agent.turn(
        H + 1,
        Inputs {
            heartbeats: &[&reboot],
            clock: clock(H + 1),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    let out = at(&mut agent, 2 * H, &[]);
    let (to_11, _) = beat_to(&out, 11);
    assert_eq!((to_11.ack, to_11.ack_boot), (3, rebooted));
}

/// Heartbeats admitted in an order other than host order are each acknowledged to their own sender. The records
/// list the standbys out of host order, so a sync whose records stop naming host 13 searches a roster it had to
/// sort: it forgets host 13's acknowledgment, and hosts 11 and 12 keep theirs.
#[test]
fn each_peer_is_acknowledged_its_own_last_heartbeat_until_the_records_drop_it() {
    let named = [
        record(1, OWN, Some(12)),
        record(2, OWN, Some(11)),
        record(3, OWN, Some(13)),
    ];
    let mut agent = synced(&named, &[]);
    let beats = [
        sealed(&header(13, 2, 5), &[], OWN),
        sealed(&header(11, 3, 7), &[], OWN),
        sealed(&header(12, 4, 9), &[], OWN),
        sealed(&header(11, 3, 8), &[], OWN),
    ];
    let out = agent.turn(
        5,
        Inputs {
            heartbeats: &slices(&beats),
            clock: clock(5),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    let acks = |out: &Outputs| {
        [11, 12, 13, 14].map(|peer| {
            let (header, _) = beat_to(out, peer);
            (header.ack, header.ack_boot)
        })
    };
    let out = at(&mut agent, H, &[]);
    let none = (0, [0; 16]);
    assert_eq!(acks(&out), [(8, [3; 16]), (9, [4; 16]), (5, [2; 16]), none]);
    let placement = placement();
    for (t, records) in [(H + 1, &named[..2]), (H + 2, &named[..])] {
        let out = agent.turn(
            t,
            Inputs {
                sync: Some(Synced {
                    records,
                    placement: &placement,
                }),
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        assert!(out.refused.is_empty(), "{:?}", out.refused);
    }
    let out = at(&mut agent, 2 * H, &[]);
    assert_eq!(acks(&out), [(8, [3; 16]), (9, [4; 16]), none, none]);
}

/// A second sync replaces the role lists of the first: the lists hold the roles of the second sync's records and
/// none of the first's.
#[test]
fn a_second_sync_replaces_the_role_lists_of_the_first() {
    let first = [
        record(1, OWN, Some(11)),
        record(2, OWN, None),
        record(3, 12, Some(OWN)),
    ];
    let mut agent = synced(&first, &[]);
    let roles = |shards: &[u32]| -> Vec<(Shard, VolumeId)> {
        (shards.iter())
            .map(|&shard| (Shard::new(shard).unwrap(), volume(shard)))
            .collect()
    };
    assert_eq!(agent.standby_named, roles(&[1]));
    assert_eq!(agent.roles, roles(&[1, 2, 3]));
    assert_eq!(agent.owned, Some(roles(&[1, 2])));
    let second = [record(4, 13, Some(OWN)), record(5, OWN, Some(13))];
    let placement = placement();
    let out = agent.turn(
        1,
        Inputs {
            sync: Some(Synced {
                records: &second,
                placement: &placement,
            }),
            clock: clock(1),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    assert_eq!(agent.standby_named, roles(&[5]));
    assert_eq!(agent.roles, roles(&[4, 5]));
    assert_eq!(agent.owned, Some(roles(&[5])));
}

/// A sink that keeps every report it receives.
#[derive(Default)]
struct Kept(Vec<Vec<u8>>);

impl ReportSink for Kept {
    fn deliver(&mut self, report: &[u8]) {
        self.0.push(report.to_vec());
    }
}

/// The serving status of `shard` carrying its owner's report entry.
fn reporting_status(shard: u32) -> Status {
    let serving = status(shard, Phase::Serving);
    Status {
        entry: Some(VolumeEntry {
            volume: serving.volume,
            shard: serving.shard,
            tenure: serving.tenure,
            ..bare("vol-0", RecordedRole::Owner)
        }),
        ..serving
    }
}

#[test]
fn a_full_report_seals_every_listed_role_before_an_unlisted_one() {
    let mut wide = bounds();
    wide.shards = MAX_ENTRIES + 1;
    let mut agent = Agent::new(
        &HostGate::qualified(),
        (host(OWN), BOOT, 500),
        wide,
        keys(host(OWN), &[host(11)]),
        reporting(host(OWN), REPORT_US),
    )
    .unwrap();
    let placement = placement();
    let unlisted = MAX_ENTRIES as u32 + 1;
    let turn = |agent: &mut Agent, now, shards: std::ops::RangeInclusive<u32>| {
        let records: Vec<_> = (shards.clone())
            .map(|shard| record(shard, OWN, Some(11)))
            .collect();
        // The process of the role the second sync drops keeps publishing, so its row stays fresh and comes first.
        let statuses: Vec<_> = std::iter::once(unlisted)
            .chain(shards.filter(|shard| *shard != unlisted))
            .map(reporting_status)
            .collect();
        let out = agent.turn(
            now,
            Inputs {
                statuses: &statuses,
                sync: Some(Synced {
                    records: &records,
                    placement: &placement,
                }),
                clock: clock(now),
                ..Inputs::NONE
            },
        );
        assert!(out.refused.is_empty(), "{:?}", out.refused);
        assert_eq!(out.seal_refused, None);
        out.report
    };
    let first = turn(&mut agent, 0, unlisted..=unlisted).expect("the first turn seals");
    let full = turn(&mut agent, REPORT_US, 1..=MAX_ENTRIES as u32).expect("one period later");
    let mut reader = Reader::default();
    assert_eq!(reader.accept(&first, reader_key).unwrap().entries.len(), 1);
    let report = reader.accept(&full, reader_key).unwrap();
    let shards: Vec<u32> = report.entries.iter().map(|e| e.shard.get()).collect();
    assert_eq!(
        shards,
        (1..=MAX_ENTRIES as u32).collect::<Vec<_>>(),
        "the report's entries are the listed roles'"
    );
    assert_eq!(
        report.host.producer_missing,
        Members::Known {
            used: 0,
            limit: MAX_ENTRIES as u64
        }
    );
}

pub(crate) fn reader_key(h: Host) -> Option<ReportKey> {
    Some(ReportKey::derive(&host_key(h)))
}

#[test]
fn a_report_holds_one_entry_per_fresh_status_and_verifies_under_its_report_key() {
    let records = [
        record(1, OWN, Some(11)),
        record(2, OWN, Some(11)),
        record(3, OWN, Some(11)),
        record(4, OWN, Some(11)),
        record(6, OWN, Some(11)),
        record(5, 13, Some(OWN)),
    ];
    let first = [reporting_status(3)];
    let mut agent = agent();
    let placement = placement();
    let sync = Synced {
        records: &records,
        placement: &placement,
    };
    let out = agent.turn(
        0,
        Inputs {
            statuses: &first,
            sync: Some(sync),
            clock: clock(0),
            wall_us: 1_000,
            ..Inputs::NONE
        },
    );
    let mut sink = Kept::default();
    out.deliver(&mut sink);
    let later = STALE_US + REPORT_US;
    let sample = HostSample {
        headroom: Headroom {
            ram: Gauge::known(3, 8),
            ..HostSample::UNAVAILABLE.headroom
        },
        recovery_io: Gauge::known(5, 9),
    };
    let withdrawn = Status {
        phase: Phase::Withdrawn,
        ended: Some(Ended::Rerun),
        ..reporting_status(2)
    };
    let statuses = [
        reporting_status(1),
        withdrawn,
        status(4, Phase::Recovering),
        status(5, Phase::Standby),
    ];
    let out = agent.turn(
        later,
        Inputs {
            statuses: &statuses,
            clock: clock(later),
            wall_us: 2_000,
            host: sample,
            ..Inputs::NONE
        },
    );
    assert_eq!(out.seal_refused, None);
    out.deliver(&mut sink);
    assert_eq!(sink.0.len(), 2, "one report each period");
    assert_eq!(
        sink.0.last(),
        out.report.as_ref(),
        "the sink receives the sealed bytes unchanged"
    );
    let mut reader = Reader::default();
    let early = reader.accept(&sink.0[0], reader_key).unwrap();
    assert_eq!(early.entries.len(), 1);
    let report = reader.accept(&sink.0[1], reader_key).unwrap();
    assert_eq!((report.writer.host, report.sequence), (host(OWN), 2));
    let volumes: Vec<_> = report.entries.iter().map(|e| e.volume).collect();
    assert_eq!(
        volumes,
        [statuses[0].volume, statuses[1].volume],
        "the stale status of shard 3 has no entry"
    );
    let labels: Vec<_> = (report.entries.iter())
        .map(|e| (e.shard, e.phase, e.ended))
        .collect();
    assert_eq!(
        labels,
        [
            (statuses[0].shard, Some(Phase::Serving), None),
            (
                statuses[1].shard,
                Some(Phase::Withdrawn),
                Some(Ended::Rerun)
            ),
        ],
        "each entry carries its status's volume, shard, phase and exit"
    );
    assert_eq!(report.host.build, BUILD);
    assert_eq!(
        (
            report.host.headroom,
            report.host.recovery_io,
            report.sealed_at_us
        ),
        (sample.headroom, sample.recovery_io, 2_000),
        "the caller's sample and wall clock reach the report"
    );
    assert_eq!(report.host.health, Some(Health::Healthy));
    assert_eq!(
        report.host.producer_missing,
        Members::Known { used: 3, limit: 5 }
    );
    assert_eq!(report.host.detector, Detector::of(&agent.watch().census()));
}

#[test]
fn a_host_with_no_tenure_seals_one_valid_empty_report_per_period() {
    let records = [record(1, 11, Some(OWN))];
    let statuses = [status(1, Phase::Standby)];
    let mut agent = synced(&records, &statuses);
    let mut sink = Kept::default();
    let mut sealed_at = vec![0];
    for t in (5..=100).step_by(5) {
        let out = agent.turn(
            t,
            Inputs {
                statuses: &statuses,
                clock: clock(t),
                wall_us: t,
                ..Inputs::NONE
            },
        );
        if out.report.is_some() {
            sealed_at.push(t);
        }
        out.deliver(&mut sink);
    }
    assert_eq!(sealed_at, [0, 30, 60, 90], "one report per period");
    assert_eq!(sink.0.len(), 3, "the sync turn's report went undelivered");
    let mut reader = Reader::default();
    for (sequence, bytes) in (2..).zip(&sink.0) {
        let report = reader.accept(bytes, reader_key).unwrap();
        assert_eq!(report.sequence, sequence);
        assert!(report.entries.is_empty(), "a standby status has no entry");
    }
}

/// The hosts of the probing scenario: the observer in partition 9, the suspect 11 and host 12 in partition 1, and
/// nine probers 50 to 58, each in a partition of its own.
fn probing_placement() -> Vec<(Host, Partition)> {
    let mut placement = vec![
        (host(OWN), Partition(9)),
        (host(11), Partition(1)),
        (host(12), Partition(1)),
    ];
    placement.extend((50..=58).map(|h| (host(h), Partition(h as u32))));
    placement
}

/// The agent of `own` in the probing scenario, synced with shard 1 owned by 11 and stood by by the observer.
fn probing_agent(own: u64) -> Agent {
    let records = [record(1, 11, Some(OWN))];
    probing_agent_over(own, &probing_placement(), &[], &records, &[])
}

/// The agent of `own` synced with `records` over `placement`, keyed for every placed host but `keyless`, with
/// `statuses` received.
fn probing_agent_over(
    own: u64,
    placement: &[(Host, Partition)],
    keyless: &[u64],
    records: &[ShardRecord],
    statuses: &[Status],
) -> Agent {
    probing_agent_bounded(own, placement, keyless, records, statuses, bounds())
}

/// [`probing_agent_over`] with the detector bounds `watch`.
fn probing_agent_bounded(
    own: u64,
    placement: &[(Host, Partition)],
    keyless: &[u64],
    records: &[ShardRecord],
    statuses: &[Status],
    watch: WatchBounds,
) -> Agent {
    let peers: Vec<_> = (placement.iter())
        .map(|(h, _)| *h)
        .filter(|h| *h != host(own) && !keyless.contains(&h.get()))
        .collect();
    let mut agent = Agent::new(
        &HostGate::qualified(),
        (host(own), boot_of(host(own)), 500),
        watch,
        keys(host(own), &peers),
        reporting(host(own), REPORT_US),
    )
    .unwrap();
    let out = agent.turn(
        0,
        Inputs {
            statuses,
            sync: Some(Synced { records, placement }),
            clock: clock(0),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    agent
}

/// The observer's agent after three silent windows of suspect 11, with the probe requests its last turn sent.
fn probing() -> (Agent, Outputs) {
    let mut agent = probing_agent(OWN);
    for t in [10, 20] {
        at(&mut agent, t, &[]);
    }
    let out = at(&mut agent, 30, &[]);
    (agent, out)
}

fn sent_request(out: &Outputs, to: u64) -> ProbeRequest {
    let (_, bytes) = (out.probes.iter())
        .find(|(prober, _)| *prober == host(to))
        .unwrap_or_else(|| panic!("no request to {to}"));
    match probe::decode(bytes, host(to), |h| Some(probe_key(h))).unwrap() {
        (from, boot, Message::Request(request)) if (from, boot) == (host(OWN), BOOT) => request,
        decoded => panic!("not a request of the observer: {decoded:?}"),
    }
}

#[test]
fn probe_requests_go_only_to_probers_outside_the_suspects_partition() {
    let (agent, out) = probing();
    let request = agent.watch().probes().next().expect("an open probe round");
    assert_eq!(request.suspect, host(11));
    let mut to: Vec<u64> = out.probes.iter().map(|(prober, _)| prober.get()).collect();
    to.sort_unstable();
    to.dedup();
    assert_eq!(
        to.len(),
        8,
        "one request per prober, up to the vote record's size"
    );
    assert!(
        to.iter().all(|prober| (50..=58).contains(prober)),
        "none to the observer, the suspect or host 12 of the suspect's partition: {to:?}"
    );
    for prober in to {
        assert_eq!(sent_request(&out, prober), request, "{prober}");
    }
    let quiet = at(&mut probing().0, 35, &[]);
    assert!(quiet.probes.is_empty(), "one request per window");
}

#[test]
fn an_answering_agent_replies_with_its_detectors_reading_and_the_bound_reply_reaches_the_detector()
{
    let (mut observer, out) = probing();
    let mut prober = probing_agent(50);
    for t in [10, 20, 30] {
        at(&mut prober, t, &[]);
    }
    let held = prober.watch().liveness(host(11)).unwrap();
    assert!(matches!(held, Liveness::Dead(_)), "{held:?}");
    let asked: Vec<_> = (out.probes.iter())
        .filter(|(to, _)| *to == host(50))
        .map(|(_, bytes)| bytes.to_vec())
        .collect();
    let answered = at(&mut prober, 31, &asked);
    assert!(
        answered.probes_refused.is_empty(),
        "{:?}",
        answered.probes_refused
    );
    let [(to, reply)] = answered.probes[..] else {
        panic!("one reply: {:?}", answered.probes);
    };
    assert_eq!(to, host(OWN));
    let decoded = probe::decode(&reply, host(OWN), |h| Some(probe_key(h))).unwrap();
    let Liveness::Dead(suspicion) = held else {
        unreachable!()
    };
    assert_eq!(
        decoded,
        (
            host(50),
            BOOT,
            Message::Reply {
                request: sent_request(&out, 50),
                reading: Reading::Dead(suspicion.failure),
            }
        )
    );
    let before = observer.watch().snapshot();
    let bound = at(&mut observer, 32, &[reply.to_vec()]);
    assert!(bound.probes_refused.is_empty() && bound.refused.is_empty());
    assert_ne!(
        observer.watch().snapshot(),
        before,
        "the vote reached the detector"
    );
    let replayed = at(&mut observer, 33, &[reply.to_vec()]);
    assert_eq!(replayed.probes_refused, [ProbeError::Unrequested]);
    let about = |suspect| ProbeRequest {
        suspect: host(suspect),
        ..sent_request(&out, 50)
    };
    let untracked = Message::Request(about(77));
    let bytes = probe::encode(&untracked, BOOT, host(OWN), host(50), &probe_key(host(OWN)));
    let refused = at(&mut prober, 34, &[bytes.to_vec()]);
    assert_eq!(refused.probes_refused, [ProbeError::Untracked]);
    assert!(refused.probes.is_empty());
}

/// The unrequested replies to the open round's request: one from `unasked`, a prober the observer did not ask, and
/// two from prober 50, which it asked, naming the request with another suspect partition or an earlier issue time.
fn unrequested(request: ProbeRequest, unasked: u64) -> [Vec<u8>; 3] {
    let moved = ProbeRequest {
        partition: Partition(77),
        ..request
    };
    let earlier = ProbeRequest {
        issued: request.issued - 1,
        ..request
    };
    [
        answer(request, unasked, host(OWN), SILENT),
        answer(moved, 50, host(OWN), SILENT),
        answer(earlier, 50, host(OWN), SILENT),
    ]
}

/// For each unrequested reply on its own, the observer's refusals and whether its detector changed.
fn unrequested_reply() -> Vec<(Vec<ProbeError>, bool)> {
    let (_, out) = probing();
    let unasked = (50..=58)
        .find(|prober| out.probes.iter().all(|(to, _)| *to != host(*prober)))
        .expect("one of the nine probers goes unasked");
    let replies = unrequested(sent_request(&out, 50), unasked);
    (replies.iter())
        .map(|reply| {
            let (mut agent, _) = probing();
            let before = agent.watch().snapshot();
            let unasked = at(&mut agent, 31, std::slice::from_ref(reply));
            (unasked.probes_refused, agent.watch().snapshot() != before)
        })
        .collect()
}

#[test]
fn a_forged_or_unrequested_reply_never_reaches_the_detector() {
    for (refused, changed) in unrequested_reply() {
        assert_eq!((refused, changed), (vec![ProbeError::Unrequested], false));
    }
    let (mut agent, out) = probing();
    let request = sent_request(&out, 50);
    let before = agent.watch().snapshot();
    let mut tampered = answer(request, 50, host(OWN), SILENT);
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let reply = Message::Reply {
        request,
        reading: SILENT,
    };
    let wrong_key = probe::encode(&reply, BOOT, host(50), host(OWN), &probe_key(host(51)));
    let forged = at(&mut agent, 31, &[tampered, wrong_key.to_vec()]);
    assert_eq!(forged.probes_refused, [ProbeError::Tag, ProbeError::Tag]);
    assert_eq!(
        agent.watch().snapshot(),
        before,
        "the detector is unchanged"
    );
    let bound = at(&mut agent, 32, &[answer(request, 50, host(OWN), SILENT)]);
    assert!(
        bound.probes_refused.is_empty(),
        "{:?}",
        bound.probes_refused
    );
    assert_ne!(agent.watch().snapshot(), before);
}

#[test]
fn the_control_that_skips_the_binding_fails_the_unrequested_reply_scenario() {
    for (refused, changed) in planted("unbound", unrequested_reply) {
        assert!(
            refused.is_empty() && changed,
            "the control passes the unrequested reply to the detector: {refused:?}"
        );
    }
}

#[test]
fn keys_from_a_host_projection_check_a_peers_probe_tags() {
    use crate::failover::zone_loop::directory::{DerivedKey, Directory, HostProjection};
    use crate::failover::zone_loop::tests::directory::{host_key as listed_key, listing};
    let listing = listing(3, 1);
    let derived = |h: &Host| {
        let key = listed_key(h.get());
        [
            (*h, DerivedKey::Heartbeat(beat::BeatKey::derive(&key))),
            (*h, DerivedKey::Probe(ProbeKey::derive(&key))),
        ]
    };
    let hosts: Vec<Host> = listing.hosts.iter().map(|entry| entry.host).collect();
    let keys = hosts.iter().flat_map(derived).collect();
    let directory = Directory::<HostProjection>::new(listing, keys).unwrap();
    let own = Keys::of(host(1), &listed_key(1), directory.keys());
    assert_eq!(
        own.probers.iter().map(|(h, _)| h.get()).collect::<Vec<_>>(),
        [2, 3]
    );
    let mut agent = Agent::new(
        &HostGate::qualified(),
        (host(1), BOOT, 500),
        bounds(),
        own,
        reporting(host(1), REPORT_US),
    )
    .unwrap();
    let request = ProbeRequest {
        suspect: host(3),
        ..sent_request(&probing().1, 50)
    };
    let asked = Message::Request(request);
    let peer = probe::encode(
        &asked,
        BOOT,
        host(2),
        host(1),
        &ProbeKey::derive(&listed_key(2)),
    );
    let other = probe::encode(
        &asked,
        BOOT,
        host(2),
        host(1),
        &ProbeKey::derive(&listed_key(3)),
    );
    let out = at(&mut agent, 1, &[peer.to_vec(), other.to_vec()]);
    assert_eq!(
        out.probes_refused,
        [ProbeError::Tag, ProbeError::Untracked],
        "the directory's probe key of host 2 verifies its request; another key does not"
    );
}

#[test]
fn requests_spread_over_partitions_before_a_second_prober_of_one_and_skip_a_host_without_a_probe_key()
 {
    let mut placement = vec![(host(OWN), Partition(9)), (host(11), Partition(1))];
    placement.extend((50..=54).map(|h| (host(h), Partition(2))));
    placement.extend((55..=58).map(|h| (host(h), Partition(h as u32))));
    placement.push((host(59), Partition(7)));
    let records = [record(1, 11, Some(OWN))];
    let mut agent = probing_agent_over(OWN, &placement, &[59], &records, &[]);
    let mut asked = Vec::new();
    for t in [10, 20, 30, 40] {
        let out = at(&mut agent, t, &[]);
        if !out.probes.is_empty() {
            asked.push(
                out.probes
                    .iter()
                    .map(|(prober, _)| prober.get())
                    .collect::<Vec<_>>(),
            );
        }
    }
    let [first, second] = &asked[..] else {
        panic!("two rounds of requests: {asked:?}");
    };
    for to in [first, second] {
        assert_eq!(to.len(), 8, "{to:?}");
        assert!(!to.contains(&59), "host 59 holds no probe key: {to:?}");
        let partitions: Vec<u64> = (to[..5].iter())
            .map(|&prober| if prober <= 54 { 2 } else { prober })
            .collect();
        let mut distinct = partitions.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            5,
            "one prober of each of the five partitions before a second of any: {to:?}"
        );
        assert!(
            to[5..].iter().all(|prober| (50..=54).contains(prober)),
            "{to:?}"
        );
    }
    let lead = |to: &[u64]| to.iter().copied().find(|prober| *prober <= 54);
    assert_ne!(
        lead(first),
        lead(second),
        "the next round asks another host of partition 2 first"
    );
}

#[test]
fn a_reply_naming_a_request_the_agent_did_not_send_never_reaches_the_detector() {
    let (mut agent, out) = probing();
    let request = sent_request(&out, 50);
    let earlier = ProbeRequest {
        issued: request.issued - 1,
        ..request
    };
    let before = agent.watch().snapshot();
    let unsent = at(&mut agent, 31, &[answer(earlier, 50, host(OWN), SILENT)]);
    assert_eq!(unsent.probes_refused, [ProbeError::Unrequested]);
    assert!(unsent.refused.is_empty());
    assert_eq!(agent.watch().snapshot(), before);
    let second = at(&mut agent, 40, &[]);
    let next = sent_request(&second, 50);
    assert_eq!(next.round, 2);
    let mixed = ProbeRequest { round: 1, ..next };
    let before = agent.watch().snapshot();
    let unsent = at(&mut agent, 41, &[answer(mixed, 50, host(OWN), SILENT)]);
    assert_eq!(
        unsent.probes_refused,
        [ProbeError::Unrequested],
        "round 1 with round 2's issue time is no sent request"
    );
    assert_eq!(agent.watch().snapshot(), before);
    let bound = at(&mut agent, 42, &[answer(next, 50, host(OWN), SILENT)]);
    assert!(bound.probes_refused.is_empty() && bound.refused.is_empty());
    let snapshot = agent.watch().snapshot();
    assert!(
        snapshot.contains("class: ObserverClass(1)") && !snapshot.contains("ObserverClass(50)"),
        "the vote carries the prober class, not the prober's partition: {snapshot}"
    );
}

#[test]
fn an_alive_reply_in_the_judging_window_still_vetoes_the_cycle() {
    let (mut agent, _) = probing();
    at(&mut agent, 40, &[]);
    let last = at(&mut agent, 50, &[]);
    let request = sent_request(&last, 50);
    assert_eq!(request.round, 3, "the last probe round");
    at(&mut agent, 60, &[]);
    assert!(
        agent.watch().probes().next().is_none(),
        "the judging window takes no new request"
    );
    assert_eq!(agent.watch().census().suspected, 1);
    let late = at(
        &mut agent,
        61,
        &[answer(request, 50, host(OWN), Reading::Alive)],
    );
    assert!(
        late.probes_refused.is_empty() && late.refused.is_empty(),
        "{:?} {:?}",
        late.probes_refused,
        late.refused
    );
    assert_eq!(
        agent.watch().census().suspected,
        0,
        "the veto takes the suspect out of the count"
    );
}

#[test]
fn an_unhealthy_prober_answers_unknown() {
    let records = [record(1, 11, Some(OWN)), record(2, 50, Some(11))];
    let held = [status(2, Phase::Held)];
    let mut prober = probing_agent_over(50, &probing_placement(), &[], &records, &held);
    for t in [10, 20, 30] {
        let out = at(&mut prober, t, &[]);
        assert!(
            out.repair.is_none(),
            "two suspects stay below the threshold"
        );
    }
    assert!(matches!(
        prober.watch().liveness(host(11)),
        Some(Liveness::Dead(_))
    ));
    assert!(!prober.healthy(30));
    let (_, out) = probing();
    let asked: Vec<_> = (out.probes.iter())
        .filter(|(to, _)| *to == host(50))
        .map(|(_, bytes)| bytes.to_vec())
        .collect();
    let answered = at(&mut prober, 31, &asked);
    let [(_, reply)] = answered.probes[..] else {
        panic!("one reply: {:?}", answered.probes);
    };
    let decoded = probe::decode(&reply, host(OWN), |h| Some(probe_key(h))).unwrap();
    assert!(
        matches!(
            decoded.2,
            Message::Reply {
                reading: Reading::Unknown,
                ..
            }
        ),
        "{decoded:?}"
    );
}

#[test]
fn each_liveness_reading_answers_its_reply_reading() {
    use crate::failover::detect::{Failure, ObservationGeneration, Suspicion};
    let suspicion = |failure| Suspicion {
        generation: ObservationGeneration(1),
        failure,
        since: 0,
    };
    assert_eq!(super::reading(Liveness::Alive), Reading::Alive);
    assert_eq!(super::reading(Liveness::Unknown), Reading::Unknown);
    for failure in [Failure::Silent, Failure::Gray, Failure::Declared] {
        assert_eq!(
            super::reading(Liveness::Dead(suspicion(failure))),
            Reading::Dead(failure)
        );
    }
}

#[test]
fn a_prober_that_hears_the_suspect_answers_alive() {
    let mut prober = probing_agent(50);
    for (sequence, t) in [10, 20, 30].into_iter().enumerate() {
        let beat = sealed(&header(11, 1, sequence as u64 + 1), &[], 50);
        let out = prober.turn(
            t,
            Inputs {
                heartbeats: &[&beat],
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        assert!(out.refused.is_empty(), "{:?}", out.refused);
    }
    assert_eq!(prober.watch().liveness(host(11)), Some(Liveness::Alive));
    let (_, out) = probing();
    let asked: Vec<_> = (out.probes.iter())
        .filter(|(to, _)| *to == host(50))
        .map(|(_, bytes)| bytes.to_vec())
        .collect();
    let answered = at(&mut prober, 31, &asked);
    let [(_, reply)] = answered.probes[..] else {
        panic!("one reply: {:?}", answered.probes);
    };
    let decoded = probe::decode(&reply, host(OWN), |h| Some(probe_key(h))).unwrap();
    assert_eq!(
        decoded.2,
        Message::Reply {
            request: sent_request(&out, 50),
            reading: Reading::Alive,
        }
    );
}

#[test]
fn a_prober_that_never_heard_the_suspect_answers_unknown_and_vetoes_nothing() {
    let (mut observer, out) = probing();
    let mut prober = probing_agent(50);
    assert_eq!(prober.watch().liveness(host(11)), Some(Liveness::Alive));
    let asked: Vec<_> = (out.probes.iter())
        .filter(|(to, _)| *to == host(50))
        .map(|(_, bytes)| bytes.to_vec())
        .collect();
    let answered = at(&mut prober, 1, &asked);
    let [(_, reply)] = answered.probes[..] else {
        panic!("one reply: {:?}", answered.probes);
    };
    let decoded = probe::decode(&reply, host(OWN), |h| Some(probe_key(h))).unwrap();
    assert_eq!(
        decoded.2,
        Message::Reply {
            request: sent_request(&out, 50),
            reading: Reading::Unknown,
        },
        "a prober that admitted no heartbeat from the suspect has no ALIVE observation to relay"
    );
    assert_eq!(observer.watch().census().suspected, 1);
    let bound = at(&mut observer, 31, &[reply.to_vec()]);
    assert!(
        bound.probes_refused.is_empty() && bound.refused.is_empty(),
        "{:?} {:?}",
        bound.probes_refused,
        bound.refused
    );
    assert_eq!(
        observer.watch().census().suspected,
        1,
        "the reply of a prober with no observation leaves the suspicion standing"
    );
}

/// Prober 50's turn at `now` over `beats` and the observer's open request about suspect 11: the reading of its
/// reply and the heartbeats it refused.
fn answered(prober: &mut Agent, now: u64, beats: &[Vec<u8>]) -> (Reading, Vec<WatchRefusal>) {
    let (_, out) = probing();
    let asked: Vec<_> = (out.probes.iter())
        .filter(|(to, _)| *to == host(50))
        .map(|(_, bytes)| bytes.to_vec())
        .collect();
    let turn = prober.turn(
        now,
        Inputs {
            heartbeats: &slices(beats),
            probes: &slices(&asked),
            clock: clock(now),
            ..Inputs::NONE
        },
    );
    // The turn's probes also hold the requests the prober sends about its own suspects.
    let replies: Vec<Reading> = (turn.probes.iter())
        .filter(|(to, _)| *to == host(OWN))
        .filter_map(
            |(_, bytes)| match probe::decode(bytes, host(OWN), |h| Some(probe_key(h))) {
                Ok((_, _, Message::Reply { reading, .. })) => Some(reading),
                _ => None,
            },
        )
        .collect();
    let [reading] = replies[..] else {
        panic!("one reply: {replies:?}");
    };
    (reading, turn.refused)
}

#[test]
fn a_prober_inside_new_peer_grace_relays_the_alive_reading_of_a_suspect_it_hears() {
    let mut prober = probing_agent(50);
    let beat = sealed(&header(11, 1, 1), &[], 50);
    assert_eq!(
        answered(&mut prober, 5, &[beat]),
        (Reading::Alive, vec![]),
        "the heartbeat admitted in this turn backs the reading"
    );
}

#[test]
fn a_retracked_prober_answers_unknown_until_it_admits_a_heartbeat_of_the_new_generation() {
    let mut prober = probing_agent(50);
    for (sequence, t) in [10, 20, 30].into_iter().enumerate() {
        let beat = sealed(&header(11, 1, sequence as u64 + 1), &[], 50);
        let (reading, refused) = answered(&mut prober, t + 1, &[beat]);
        assert_eq!((reading, refused), (Reading::Alive, vec![]), "{t}");
    }
    let sync =
        |prober: &mut Agent, now, records: &[ShardRecord], placement: &[(Host, Partition)]| {
            let out = prober.turn(
                now,
                Inputs {
                    sync: Some(Synced { records, placement }),
                    clock: clock(now),
                    ..Inputs::NONE
                },
            );
            assert!(out.refused.is_empty(), "{:?}", out.refused);
            assert_eq!(prober.watch().liveness(host(11)), Some(Liveness::Alive));
        };
    // Suspect 11 gains a target the prober stands by for, which opens a newer observation generation.
    let gained = [record(1, 11, Some(OWN)), record(3, 11, Some(50))];
    sync(&mut prober, 32, &gained, &probing_placement());
    assert_eq!(
        answered(&mut prober, 33, &[]),
        (Reading::Unknown, vec![]),
        "the reading the retrack starts with rests on no heartbeat"
    );
    let replayed = sealed(&header(11, 1, 3), &[], 50);
    assert_eq!(
        answered(&mut prober, 34, &[replayed]),
        (Reading::Unknown, vec![WatchRefusal::Replay]),
        "a refused heartbeat backs nothing"
    );
    for t in [42, 52] {
        at(&mut prober, t, &[]);
    }
    assert_eq!(prober.watch().liveness(host(11)), Some(Liveness::Alive));
    assert_eq!(
        answered(&mut prober, 53, &[]),
        (Reading::Unknown, vec![]),
        "past the new grace with two empty windows the reading is still ALIVE, with no heartbeat behind it"
    );
    let newer = sealed(&header(11, 1, 4), &[], 50);
    assert_eq!(
        answered(&mut prober, 54, &[newer]),
        (Reading::Alive, vec![])
    );
    // Suspect 11 moves partition, which opens another generation; the heartbeat that establishes its next boot
    // arrives in the generation that boot opens.
    let mut moved = probing_placement();
    moved[1].1 = Partition(77);
    sync(&mut prober, 55, &gained, &moved);
    assert_eq!(answered(&mut prober, 56, &[]), (Reading::Unknown, vec![]));
    let rebooted = sealed(&header(11, 2, 1), &[], 50);
    assert_eq!(
        answered(&mut prober, 57, &[rebooted]),
        (Reading::Alive, vec![])
    );
}

#[test]
fn a_stalled_suspicion_that_grace_withholds_answers_unknown() {
    let mut graced = bounds();
    graced.detect.peer_grace = 60;
    let records = [record(1, 11, Some(OWN))];
    // The suspect sends one heartbeat each window with flat counters and pending work. Each is fresh when the prober
    // answers, and D = 3 stalled windows stand at the close at 40, inside the grace of 60.
    let flat = |sequence| {
        let beat = Header {
            io: 1,
            completions: 1,
            ..header(11, 1, sequence)
        };
        vec![sealed(&beat, &[], 50)]
    };
    let mut prober = probing_agent_bounded(50, &probing_placement(), &[], &records, &[], graced);
    for (sequence, t) in [(1, 5), (2, 11), (3, 21), (4, 31)] {
        assert_eq!(
            answered(&mut prober, t, &flat(sequence)),
            (Reading::Alive, vec![]),
            "{t}: fewer than D stalled windows"
        );
    }
    assert_eq!(
        answered(&mut prober, 41, &flat(5)),
        (Reading::Unknown, vec![]),
        "D stalled windows stand behind the reading the grace keeps ALIVE"
    );
    assert_eq!(prober.watch().liveness(host(11)), Some(Liveness::Alive));
}

#[test]
fn an_alive_answer_needs_a_heartbeat_inside_both_age_limits() {
    let records = [record(1, 11, Some(OWN))];
    let beat = |sequence| vec![sealed(&header(11, 1, sequence), &[], 50)];
    // h = 10, jitter = 5, D = 3: the limit is h + jitter = 15, below D * h - tau - jitter = 25 at tau = 0.
    let mut prober = probing_agent(50);
    assert_eq!(answered(&mut prober, 9, &beat(1)).0, Reading::Alive);
    // One empty window stands at 21, and the heartbeat of 9 is 12 old: the answer follows the age and no window.
    assert_eq!(answered(&mut prober, 21, &[]).0, Reading::Alive);
    assert_eq!(answered(&mut prober, 24, &[]).0, Reading::Alive, "15 old");
    assert_eq!(answered(&mut prober, 25, &[]).0, Reading::Unknown, "16 old");
    assert_eq!(answered(&mut prober, 26, &beat(2)).0, Reading::Alive);
    // h = 10, jitter = 8, D = 2: D * h - tau - jitter = 12 is the lower limit, so 11 is the oldest ALIVE.
    let mut wide = bounds();
    (wide.detect.d, wide.detect.jitter) = (2, 8);
    let mut prober = probing_agent_bounded(50, &probing_placement(), &[], &records, &[], wide);
    assert_eq!(answered(&mut prober, 9, &beat(1)).0, Reading::Alive);
    assert_eq!(answered(&mut prober, 20, &[]).0, Reading::Alive, "11 old");
    assert_eq!(answered(&mut prober, 21, &[]).0, Reading::Unknown, "12 old");
    // A clock error of tau = 1 lowers that limit to D * h - tau - jitter = 11, so 10 is the oldest ALIVE.
    wide.detect.tau = 1;
    let mut prober = probing_agent_bounded(50, &probing_placement(), &[], &records, &[], wide);
    assert_eq!(answered(&mut prober, 9, &beat(1)).0, Reading::Alive);
    assert_eq!(answered(&mut prober, 19, &[]).0, Reading::Alive, "10 old");
    assert_eq!(answered(&mut prober, 20, &[]).0, Reading::Unknown, "11 old");
}

/// The prober's agent synced at `at` over the probing placement with `watch` bounds.
fn late_prober(at: u64, watch: WatchBounds) -> Agent {
    let records = [record(1, 11, Some(OWN))];
    let placement = probing_placement();
    let peers: Vec<_> = (placement.iter())
        .map(|(h, _)| *h)
        .filter(|h| *h != host(50))
        .collect();
    let mut prober = Agent::new(
        &HostGate::qualified(),
        (host(50), boot_of(host(50)), 500),
        watch,
        keys(host(50), &peers),
        reporting(host(50), REPORT_US),
    )
    .unwrap();
    let synced = prober.turn(
        at,
        Inputs {
            sync: Some(Synced {
                records: &records,
                placement: &placement,
            }),
            clock: clock(at),
            ..Inputs::NONE
        },
    );
    assert!(synced.refused.is_empty(), "{:?}", synced.refused);
    prober
}

#[test]
fn a_prober_that_paused_or_received_the_last_heartbeat_later_answers_unknown() {
    let last = vec![sealed(&header(11, 1, 1), &[], 50)];
    // A pause: the last heartbeat arrives at 8, its window closes at 15, and the next turn is the request's at 41.
    // That turn closes the window unobserved, which leaves no empty window standing.
    let mut paused = late_prober(5, bounds());
    assert_eq!(answered(&mut paused, 8, &last).0, Reading::Alive);
    at(&mut paused, 15, &[]);
    assert_eq!(
        answered(&mut paused, 41, &[]),
        (Reading::Unknown, vec![]),
        "33 old"
    );
    // Skew inside the jitter bound: the observer receives the heartbeat at 8 and asks at 40; the prober, synced at
    // 2, receives it at 13, so one empty window stands at its close at 32.
    let mut skewed = late_prober(2, bounds());
    assert_eq!(answered(&mut skewed, 13, &last).0, Reading::Alive);
    for t in [22, 32] {
        at(&mut skewed, t, &[]);
    }
    assert_eq!(
        answered(&mut skewed, 41, &[]),
        (Reading::Unknown, vec![]),
        "28 old"
    );
    // D = 2: the observer receives the heartbeat at 9 and asks at 30; the prober, synced at 13, receives it at 14
    // and its close at 23 holds it, so no empty window stands at 31.
    let mut two = bounds();
    two.detect.d = 2;
    let mut skewed = late_prober(13, two);
    assert_eq!(answered(&mut skewed, 14, &last).0, Reading::Alive);
    at(&mut skewed, 23, &[]);
    assert_eq!(
        answered(&mut skewed, 31, &[]),
        (Reading::Unknown, vec![]),
        "17 old, past D * h - tau - jitter = 15"
    );
}

#[test]
fn a_prober_whose_windows_trail_the_observers_answers_unknown_until_its_own_suspicion() {
    let mut observer = probing_agent(OWN);
    // The prober syncs at 5, so each of its windows closes 5 after the observer's.
    let mut prober = late_prober(5, bounds());
    let last = |to| sealed(&header(11, 1, 1), &[], to);
    // The suspect's last heartbeat reaches both hosts at 8.
    for (agent, to) in [(&mut observer, OWN), (&mut prober, 50)] {
        let out = agent.turn(
            8,
            Inputs {
                heartbeats: &[&last(to)],
                clock: clock(8),
                ..Inputs::NONE
            },
        );
        assert!(out.refused.is_empty(), "{:?}", out.refused);
    }
    for t in [10, 20, 30] {
        at(&mut observer, t, &[]);
        at(&mut prober, t + 5, &[]);
    }
    // The observer closes its third empty window at 40 and asks; the prober has closed two.
    let asked = |out: &Outputs| -> Vec<Vec<u8>> {
        (out.probes.iter())
            .filter(|(to, _)| *to == host(50))
            .map(|(_, bytes)| bytes.to_vec())
            .collect()
    };
    let replies = |turn: &Outputs| -> Vec<Vec<u8>> {
        (turn.probes.iter())
            .filter(|(to, bytes)| {
                *to == host(OWN)
                    && matches!(
                        probe::decode(bytes, host(OWN), |h| Some(probe_key(h))),
                        Ok((_, _, Message::Reply { .. }))
                    )
            })
            .map(|(_, bytes)| bytes.to_vec())
            .collect()
    };
    let reading = |reply: &[u8]| match probe::decode(reply, host(OWN), |h| Some(probe_key(h))) {
        Ok((_, _, Message::Reply { reading, .. })) => reading,
        decoded => panic!("not a reply: {decoded:?}"),
    };
    let first = at(&mut observer, 40, &[]);
    assert_eq!(observer.watch().census().suspected, 1);
    assert_eq!(prober.watch().liveness(host(11)), Some(Liveness::Alive));
    let early = replies(&at(&mut prober, 41, &asked(&first)));
    assert_eq!(
        early.iter().map(|reply| reading(reply)).collect::<Vec<_>>(),
        [Reading::Unknown],
        "the heartbeat behind the prober's ALIVE reading is 33 old"
    );
    let bound = at(&mut observer, 42, &early);
    assert!(bound.probes_refused.is_empty() && bound.refused.is_empty());
    assert_eq!(
        observer.watch().census().suspected,
        1,
        "the trailing prober's reply leaves the suspicion standing"
    );
    // The prober closes its third empty window at 45 and answers the observer's next round DEAD.
    at(&mut prober, 45, &[]);
    let second = at(&mut observer, 50, &[]);
    let late = replies(&at(&mut prober, 51, &asked(&second)));
    assert_eq!(
        late.iter().map(|reply| reading(reply)).collect::<Vec<_>>(),
        [SILENT]
    );
}

#[test]
fn a_sent_request_unanswered_past_its_vote_lifetime_takes_no_reply() {
    let (mut agent, out) = probing();
    let request = sent_request(&out, 50);
    let deadline = request.issued + agent.watch().reach() + H;
    let (mut kept, _) = probing();
    let last = at(
        &mut kept,
        deadline,
        &[answer(request, 50, host(OWN), SILENT)],
    );
    assert!(
        !last.probes_refused.contains(&ProbeError::Unrequested),
        "a reply at the binding's deadline is bound: {:?}",
        last.probes_refused
    );
    let late = at(
        &mut agent,
        deadline + 1,
        &[answer(request, 50, host(OWN), SILENT)],
    );
    assert_eq!(
        late.probes_refused,
        [ProbeError::Unrequested],
        "the first turn past the deadline refuses it"
    );
    assert!(
        late.refused.is_empty(),
        "the reply never reaches the detector: {:?}",
        late.refused
    );
}

#[test]
fn a_self_suspecting_prober_answers_unknown() {
    let records = [
        record(1, 11, Some(OWN)),
        record(2, 12, Some(OWN)),
        record(3, 51, Some(OWN)),
    ];
    let mut prober = probing_agent_over(50, &probing_placement(), &[], &records, &[]);
    let mut repaired = false;
    for t in [10, 20, 30] {
        repaired |= at(&mut prober, t, &[]).repair.is_some();
    }
    assert!(repaired, "four silent peers make the prober suspect itself");
    assert!(prober.healthy(30));
    assert!(matches!(
        prober.watch().liveness(host(11)),
        Some(Liveness::Dead(_))
    ));
    let (_, out) = probing();
    let asked: Vec<_> = (out.probes.iter())
        .filter(|(to, _)| *to == host(50))
        .map(|(_, bytes)| bytes.to_vec())
        .collect();
    let answered = at(&mut prober, 31, &asked);
    let [(_, reply)] = answered.probes[..] else {
        panic!("one reply: {:?}", answered.probes);
    };
    let decoded = probe::decode(&reply, host(OWN), |h| Some(probe_key(h))).unwrap();
    assert!(
        matches!(
            decoded.2,
            Message::Reply {
                reading: Reading::Unknown,
                ..
            }
        ),
        "{decoded:?}"
    );
}

#[test]
fn a_prober_stays_degraded_until_a_tick_at_or_after_its_self_suspicion_deadline() {
    let records = [
        record(1, 11, Some(OWN)),
        record(2, 12, Some(OWN)),
        record(3, 51, Some(OWN)),
    ];
    let mut prober = probing_agent_over(50, &probing_placement(), &[], &records, &[]);
    for t in [10, 20] {
        at(&mut prober, t, &[]);
    }
    // The tick of the windows due at 30 runs at 31, so the dwell of 20 ends at 51, between two ticks.
    let until = |out: &Outputs| out.repair.map(|repair| repair.until);
    assert_eq!(until(&at(&mut prober, 31, &[])), Some(51));
    // A sync leaves two suspects, the owner 11 and the standby, below the threshold of three.
    let out = prober.turn(
        32,
        Inputs {
            sync: Some(Synced {
                records: &records[..1],
                placement: &probing_placement(),
            }),
            clock: clock(32),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    for t in [40, 50] {
        assert_eq!(until(&at(&mut prober, t, &[])), Some(51), "{t}");
    }
    assert_eq!(
        answered(&mut prober, 52, &[]),
        (Reading::Unknown, vec![]),
        "the deadline of 51 has passed and the last tick ran at 50"
    );
    assert_eq!(until(&at(&mut prober, 60, &[])), None);
    assert_eq!(answered(&mut prober, 61, &[]), (SILENT, vec![]));
}

#[test]
fn a_reply_to_a_request_of_an_earlier_boot_never_binds() {
    let records = [record(1, 11, Some(OWN))];
    let placement = probing_placement();
    let peers: Vec<_> = (placement.iter())
        .map(|(h, _)| *h)
        .filter(|h| *h != host(OWN))
        .collect();
    let booted = |boot: [u8; 16]| {
        let mut agent = Agent::new(
            &HostGate::qualified(),
            (host(OWN), boot, 500),
            bounds(),
            keys(host(OWN), &peers),
            reporting(host(OWN), REPORT_US),
        )
        .unwrap();
        let sync = Synced {
            records: &records,
            placement: &placement,
        };
        let synced = Inputs {
            sync: Some(sync),
            clock: clock(0),
            ..Inputs::NONE
        };
        agent.turn(0, synced);
        let mut out = Outputs::default();
        for t in [10, 20, 30] {
            out = at(&mut agent, t, &[]);
        }
        (agent, out)
    };
    let (_, earlier) = booted([0xE1; 16]);
    let (mut agent, current) = booted(BOOT);
    let request = sent_request(&current, 50);
    let reply = Message::Reply {
        request,
        reading: SILENT,
    };
    let sealed =
        |boot| probe::encode(&reply, boot, host(50), host(OWN), &probe_key(host(50))).to_vec();
    let (_, old_boot, old_request) = probe::decode(
        &earlier
            .probes
            .iter()
            .find(|(to, _)| *to == host(50))
            .unwrap()
            .1,
        host(50),
        |h| Some(probe_key(h)),
    )
    .unwrap();
    assert_eq!(
        old_request,
        Message::Request(request),
        "both boots ask the same request"
    );
    let before = agent.watch().snapshot();
    let stale = at(&mut agent, 31, &[sealed(old_boot)]);
    assert_eq!(stale.probes_refused, [ProbeError::Unrequested]);
    assert_eq!(agent.watch().snapshot(), before);
    let bound = at(&mut agent, 32, &[sealed(BOOT)]);
    assert!(bound.probes_refused.is_empty() && bound.refused.is_empty());
    assert_ne!(agent.watch().snapshot(), before);
}

#[test]
fn an_entry_naming_another_volume_or_shard_is_left_out_and_counted_missing() {
    let records = [record(1, OWN, Some(11)), record(2, OWN, Some(11))];
    let foreign = Status {
        entry: Some(VolumeEntry {
            volume: volume(9),
            ..reporting_status(2).entry.unwrap()
        }),
        ..reporting_status(2)
    };
    let mut agent = synced(&records, &[reporting_status(1), foreign]);
    let out = at(&mut agent, REPORT_US, &[]);
    let report = Reader::default()
        .accept(out.report.as_ref().unwrap(), reader_key)
        .unwrap();
    let shards: Vec<_> = report.entries.iter().map(|e| e.shard.get()).collect();
    assert_eq!(
        shards,
        [1],
        "the entry naming vol-09 for shard 2 is left out"
    );
    assert_eq!(
        report.host.producer_missing,
        Members::Known { used: 1, limit: 2 }
    );
}

#[test]
fn a_parked_owners_report_keeps_its_last_entry_with_the_flip_flag_and_exit_label() {
    let records = [record(1, OWN, Some(11))];
    let serving = reporting_status(1);
    let last = Status {
        entry: serving.entry.map(|entry| VolumeEntry {
            flip: true,
            serving: Some(State::Withdrawn),
            ..entry
        }),
        ..serving
    };
    let parked = last.parked(&Exit::Retire(Target::of(&records[0])));
    assert_eq!((parked.tenure, parked.entry), (None, last.entry));
    let mut agent = synced(&records, &[parked]);
    let out = at(&mut agent, REPORT_US, &[]);
    let report = Reader::default()
        .accept(out.report.as_ref().unwrap(), reader_key)
        .unwrap();
    let entries: Vec<_> = (report.entries.iter())
        .map(|e| (e.shard.get(), e.flip, e.phase, e.ended))
        .collect();
    assert_eq!(
        entries,
        [(1, true, Some(Phase::Parked), Some(Ended::Retire))],
        "the reconciler reads the retirement request from the parked owner's entry"
    );
    assert_eq!(
        report.host.producer_missing,
        Members::Known { used: 0, limit: 1 }
    );
}

#[test]
fn a_report_before_any_accepted_sync_reads_its_producer_gauge_unavailable_and_a_held_host_unhealthy()
 {
    let mut agent = agent();
    let out = at(&mut agent, 0, &[]);
    let early = Reader::default()
        .accept(out.report.as_ref().unwrap(), reader_key)
        .unwrap();
    assert_eq!(early.host.producer_missing, Members::Unavailable);
    let held = [status(1, Phase::Held)];
    let mut agent = synced(&[record(1, OWN, Some(11))], &held);
    let out = at(&mut agent, REPORT_US, &[]);
    let report = Reader::default()
        .accept(out.report.as_ref().unwrap(), reader_key)
        .unwrap();
    assert_eq!(report.host.health, Some(Health::Unhealthy));
}

#[test]
fn a_degraded_prober_still_relays_an_alive_reading() {
    let records = [record(1, 11, Some(OWN)), record(2, 50, Some(11))];
    let held = [status(2, Phase::Held)];
    let mut prober = probing_agent_over(50, &probing_placement(), &[], &records, &held);
    for (sequence, t) in [10, 20, 30].into_iter().enumerate() {
        let beat = sealed(&header(11, 1, sequence as u64 + 1), &[], 50);
        prober.turn(
            t,
            Inputs {
                heartbeats: &[&beat],
                clock: clock(t),
                ..Inputs::NONE
            },
        );
    }
    assert!(!prober.healthy(30));
    assert_eq!(prober.watch().liveness(host(11)), Some(Liveness::Alive));
    let (_, out) = probing();
    let asked: Vec<_> = (out.probes.iter())
        .filter(|(to, _)| *to == host(50))
        .map(|(_, bytes)| bytes.to_vec())
        .collect();
    let answered = at(&mut prober, 31, &asked);
    let [(_, reply)] = answered.probes[..] else {
        panic!("one reply: {:?}", answered.probes);
    };
    let decoded = probe::decode(&reply, host(OWN), |h| Some(probe_key(h))).unwrap();
    assert!(
        matches!(
            decoded.2,
            Message::Reply {
                reading: Reading::Alive,
                ..
            }
        ),
        "{decoded:?}"
    );
}

#[test]
fn a_sync_that_moves_a_prober_drops_its_binding() {
    let (mut agent, out) = probing();
    let request = sent_request(&out, 50);
    let records = [record(1, 11, Some(OWN))];
    let moved: Vec<_> = (probing_placement().into_iter())
        .map(|(h, p)| (h, if h == host(50) { Partition(60) } else { p }))
        .collect();
    let synced = agent.turn(
        31,
        Inputs {
            sync: Some(Synced {
                records: &records,
                placement: &moved,
            }),
            clock: clock(31),
            ..Inputs::NONE
        },
    );
    assert!(synced.refused.is_empty(), "{:?}", synced.refused);
    let late = at(&mut agent, 32, &[answer(request, 50, host(OWN), SILENT)]);
    assert_eq!(late.probes_refused, [ProbeError::Unrequested]);
}

/// A sync that leaves a prober in its partition keeps the binding of the request sent to it before the sync, so
/// the prober's DEAD reply reaches the detector.
#[test]
fn a_sync_that_keeps_a_probers_partition_keeps_its_binding() {
    let (mut agent, out) = probing();
    let request = sent_request(&out, 50);
    let records = [record(1, 11, Some(OWN))];
    let placement = probing_placement();
    let synced = agent.turn(
        31,
        Inputs {
            sync: Some(Synced {
                records: &records,
                placement: &placement,
            }),
            clock: clock(31),
            ..Inputs::NONE
        },
    );
    assert!(synced.refused.is_empty(), "{:?}", synced.refused);
    let before = agent.watch().snapshot();
    let late = at(&mut agent, 32, &[answer(request, 50, host(OWN), SILENT)]);
    assert!(
        late.probes_refused.is_empty() && late.refused.is_empty(),
        "{:?} {:?}",
        late.probes_refused,
        late.refused
    );
    assert_ne!(
        agent.watch().snapshot(),
        before,
        "the detector took the vote"
    );
}

#[test]
fn a_moved_probers_alive_reply_still_vetoes() {
    let (mut agent, out) = probing();
    let request = sent_request(&out, 50);
    let records = [record(1, 11, Some(OWN))];
    let moved: Vec<_> = (probing_placement().into_iter())
        .map(|(h, p)| (h, if h == host(50) { Partition(60) } else { p }))
        .collect();
    let synced = agent.turn(
        31,
        Inputs {
            sync: Some(Synced {
                records: &records,
                placement: &moved,
            }),
            clock: clock(31),
            ..Inputs::NONE
        },
    );
    assert!(synced.refused.is_empty(), "{:?}", synced.refused);
    assert_eq!(agent.watch().census().suspected, 1);
    let veto = at(
        &mut agent,
        32,
        &[answer(request, 50, host(OWN), Reading::Alive)],
    );
    assert!(
        veto.probes_refused.is_empty() && veto.refused.is_empty(),
        "{:?} {:?}",
        veto.probes_refused,
        veto.refused
    );
    assert_eq!(agent.watch().census().suspected, 0, "the veto arrived");
}

#[test]
fn the_detector_refuses_the_alive_reply_of_a_prober_a_sync_unplaced_or_moved_beside_the_suspect() {
    // `None` removes prober 50 from the placement; partition 1 is suspect 11's.
    for moved_to in [None, Some(Partition(1))] {
        let (mut agent, out) = probing();
        let request = sent_request(&out, 50);
        let records = [record(1, 11, Some(OWN))];
        let placement: Vec<_> = (probing_placement().into_iter())
            .filter_map(|(h, p)| match (h == host(50), moved_to) {
                (false, _) => Some((h, p)),
                (true, to) => to.map(|to| (h, to)),
            })
            .collect();
        let synced = agent.turn(
            31,
            Inputs {
                sync: Some(Synced {
                    records: &records,
                    placement: &placement,
                }),
                clock: clock(31),
                ..Inputs::NONE
            },
        );
        assert!(synced.refused.is_empty(), "{:?}", synced.refused);
        let late = at(
            &mut agent,
            32,
            &[answer(request, 50, host(OWN), Reading::Alive)],
        );
        assert!(
            late.probes_refused.is_empty(),
            "{moved_to:?}: the binding passes ALIVE: {:?}",
            late.probes_refused
        );
        assert_eq!(late.refused, [WatchRefusal::Prober], "{moved_to:?}");
        assert_eq!(
            agent.watch().census().suspected,
            1,
            "{moved_to:?}: the detector takes no veto from a prober outside its eligible placement"
        );
    }
}

#[test]
fn successive_requests_ask_every_partition_when_more_than_max_probers_are_placed() {
    let mut placement = vec![(host(OWN), Partition(9)), (host(11), Partition(1))];
    placement.extend((40..=49).map(|h| (host(h), Partition(h as u32))));
    let records = [record(1, 11, Some(OWN))];
    let mut agent = probing_agent_over(OWN, &placement, &[], &records, &[]);
    let mut asked = std::collections::BTreeSet::new();
    let mut rounds = 0;
    for t in (10..=60).step_by(10) {
        let out = at(&mut agent, t, &[]);
        if !out.probes.is_empty() {
            rounds += 1;
            assert!(out.probes.len() <= 8, "{:?}", out.probes);
        }
        asked.extend(out.probes.iter().map(|(to, _)| to.get()));
    }
    assert!(rounds >= 2, "two requests or more: {rounds}");
    assert_eq!(
        asked.into_iter().collect::<Vec<_>>(),
        (40..=49).collect::<Vec<_>>(),
        "ten partitions, eight a request: successive requests cover all ten"
    );
}

#[test]
fn two_suspects_probed_in_the_same_windows_each_ask_every_partition() {
    // A request covers at most eight partitions, so each silent suspect needs at least two requests to reach all
    // nine.
    let records = [record(1, 11, Some(OWN)), record(2, 12, Some(OWN))];
    let mut agent = probing_agent_over(OWN, &probing_placement(), &[], &records, &[]);
    let mut asked = [11, 12].map(|suspect| (suspect, std::collections::BTreeSet::new()));
    for t in (10..=120).step_by(10) {
        let out = at(&mut agent, t, &[]);
        for (to, bytes) in &out.probes {
            let decoded = probe::decode(bytes, *to, |h| Some(probe_key(h))).unwrap();
            let Message::Request(request) = decoded.2 else {
                panic!("the observer answers no request here: {decoded:?}");
            };
            let (_, probers) = (asked.iter_mut())
                .find(|(suspect, _)| host(*suspect) == request.suspect)
                .expect("a request about suspect 11 or 12");
            probers.insert(to.get());
        }
    }
    for (suspect, probers) in asked {
        assert_eq!(
            probers.into_iter().collect::<Vec<_>>(),
            (50..=58).collect::<Vec<_>>(),
            "successive requests about suspect {suspect} cover all nine partitions"
        );
    }
}

#[test]
fn an_agent_refuses_a_key_list_that_names_a_host_twice() {
    let mut twice = keys(host(OWN), &[host(11), host(12)]);
    twice.probers.push((host(11), probe_key(host(12))));
    let built = Agent::new(
        &HostGate::qualified(),
        (host(OWN), BOOT, 500),
        bounds(),
        twice,
        reporting(host(OWN), REPORT_US),
    );
    assert_eq!(built.err(), Some(WatchRefusal::Duplicate));
}

#[test]
fn a_replayed_status_of_an_earlier_tenure_or_a_falling_sample_changes_nothing() {
    let records = [record(1, OWN, Some(11))];
    let rolled = Status {
        tenure: Some((
            ShardGeneration::new(3).unwrap(),
            ActivatedEpoch::new(6).unwrap(),
        )),
        io: 5,
        ..status(1, Phase::Serving)
    };
    let mut agent = synced(&records, &[rolled]);
    assert_eq!(beat_to(&at(&mut agent, H, &[]), 11).0.io, 5);
    let earlier = status(1, Phase::Serving);
    let fell = Status { io: 4, ..rolled };
    for (t, replay) in [(2 * H, earlier), (3 * H, fell)] {
        let out = agent.turn(
            t,
            Inputs {
                statuses: &[replay],
                clock: clock(t),
                ..Inputs::NONE
            },
        );
        assert_eq!(beat_to(&out, 11).0.io, 5, "{replay:?} adds nothing");
    }
    let stale = at(&mut agent, STALE_US + 1, &[]);
    assert!(
        beat_to(&stale, 11).1.is_empty(),
        "neither replay refreshed the row received at 0"
    );
}

fn sync_at(agent: &mut Agent, now: u64, records: &[ShardRecord], statuses: &[Status]) -> Outputs {
    let placement = placement();
    let out = agent.turn(
        now,
        Inputs {
            statuses,
            sync: Some(Synced {
                records,
                placement: &placement,
            }),
            clock: clock(now),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    out
}

/// A status of the role's volume that the table holds from before the role's current run ends the no-status
/// check, and the hold and silence rules judge it. The sync at `H` lists the shard for other hosts and the sync
/// at `2 * H` names the role again; the row received at 0 is inside the restart grace at both, so it stays. A
/// parked or closing row keeps the host healthy past the new run's grace, a serving row reads silent one grace
/// after its own receipt, and a held row reads unhealthy at once.
#[test]
fn a_status_kept_from_before_a_roles_run_reports_the_role() {
    let grace = RESTART_GRACE_US;
    let named = [record(1, OWN, Some(11))];
    let relisted = |phase: Phase| {
        let mut agent = synced(&named, &[status(1, phase)]);
        sync_at(&mut agent, H, &[record(1, 11, Some(14))], &[]);
        let out = sync_at(&mut agent, 2 * H, &named, &[]);
        (agent, beat_to(&out, 11).0.healthy)
    };
    for quiet in [Phase::Parked, Phase::Closing] {
        let (mut agent, healthy) = relisted(quiet);
        assert!(healthy, "{quiet:?}: at the sync that names the role again");
        assert!(
            beat_to(&at(&mut agent, 2 * H + grace + H, &[]), 11)
                .0
                .healthy,
            "{quiet:?}: past the grace of the new run"
        );
    }
    let (mut agent, healthy) = relisted(Phase::Serving);
    assert!(healthy, "a serving row inside the grace of its receipt");
    assert!(beat_to(&at(&mut agent, grace, &[]), 11).0.healthy);
    assert!(
        !beat_to(&at(&mut agent, grace + H, &[]), 11).0.healthy,
        "a serving row is silent one grace after its receipt at 0"
    );
    assert!(!relisted(Phase::Held).1, "a held row counts at once");
}

/// A process whose status row a sync dropped adds only its increase when it publishes again. The role is
/// unlisted at `2 * H` and the sync one grace later drops the row received at 0. After it, with the role still
/// unlisted and with the role listed again, the unchanged status adds nothing, a falling sample and a status of an
/// earlier tenure change nothing, a grown status adds its increase, and a restarted process adds its whole counts.
#[test]
fn a_status_after_its_rows_eviction_adds_only_its_increase() {
    let grace = RESTART_GRACE_US;
    let tracked = record(2, 12, Some(11));
    let named = [record(1, OWN, Some(11)), tracked];
    let moved = [record(1, 11, Some(14)), tracked];
    let serving = status(1, Phase::Serving);
    let fell = Status { io: 90, ..serving };
    let earlier = Status {
        tenure: Some((
            ShardGeneration::new(3).unwrap(),
            ActivatedEpoch::new(2).unwrap(),
        )),
        io: 500,
        ..serving
    };
    let grown = Status {
        io: 130,
        completions: 13,
        ..serving
    };
    let restarted = Status {
        pid: 9,
        io: 7,
        completions: 1,
        ..serving
    };
    for relisted in [false, true] {
        let mut agent = synced(&named, &[serving]);
        let first = beat_to(&at(&mut agent, H, &[]), 11).0;
        assert_eq!((first.io, first.completions), (100, 10));
        sync_at(&mut agent, 2 * H, &moved, &[]);
        sync_at(&mut agent, grace + 3 * H, &moved, &[]);
        if relisted {
            sync_at(&mut agent, grace + 4 * H, &named, &[]);
        }
        let mut t = grace + 4 * H;
        for (sent, totals) in [
            (serving, (100, 10)),
            (fell, (100, 10)),
            (earlier, (100, 10)),
            (grown, (130, 13)),
            (restarted, (137, 14)),
        ] {
            t += H;
            let out = agent.turn(
                t,
                Inputs {
                    statuses: &[sent],
                    clock: clock(t),
                    ..Inputs::NONE
                },
            );
            let header = beat_to(&out, 11).0;
            assert_eq!(
                (header.io, header.completions),
                totals,
                "relisted {relisted}: pid {} tenure {:?} io {}",
                sent.pid,
                sent.tenure,
                sent.io
            );
        }
    }
}

/// A status received on the agent's first turn has no earlier turn to bound its publication, so the heartbeat
/// counts its ages from the clock's origin: each reported age is at least the status's true age.
#[test]
fn a_status_received_on_the_first_turn_is_dated_from_the_clock_origin() {
    let mut agent = agent();
    let t = 1_000_000;
    let out = sync_at(
        &mut agent,
        t,
        &[record(1, OWN, Some(11))],
        &[status(1, Phase::Serving)],
    );
    let (_, entries) = beat_to(&out, 11);
    let ages: Vec<_> = (entries.iter())
        .map(|e| (e.read_age_us, e.report_age_us))
        .collect();
    assert_eq!(ages, [(Some(5 + t), 7 + t)]);
}

#[test]
fn the_restart_grace_is_the_constant_unless_a_test_sets_it_and_the_set_value_moves_all_three_reads()
{
    assert_eq!(agent().grace(), RESTART_GRACE_US);
    let grace = 10 * H;
    let named = [record(1, OWN, Some(11))];
    let moved = [record(1, 11, Some(14))];
    let healthy_at = |agent: &mut Agent, now: u64| beat_to(&at(agent, now, &[]), 11).0.healthy;
    for scaled in [false, true] {
        let make = |statuses: &[Status]| {
            let mut agent = synced(&named, statuses);
            if scaled {
                agent.set_restart_grace(grace);
            }
            agent
        };
        let mut silent = make(&[status(1, Phase::Serving)]);
        assert!(healthy_at(&mut silent, grace), "silence inside the grace");
        assert_eq!(
            healthy_at(&mut silent, grace + H),
            !scaled,
            "silence past the set grace, scaled {scaled}"
        );
        let mut unreported = make(&[]);
        assert!(
            healthy_at(&mut unreported, grace),
            "no status inside the grace"
        );
        assert_eq!(
            healthy_at(&mut unreported, grace + H),
            !scaled,
            "no status past the set grace, scaled {scaled}"
        );
        let mut evicted = make(&[status(1, Phase::Parked)]);
        sync_at(&mut evicted, H, &moved, &[]);
        sync_at(&mut evicted, grace + 2 * H, &moved, &[]);
        sync_at(&mut evicted, grace + 3 * H, &named, &[]);
        let start = grace + 3 * H;
        assert!(healthy_at(&mut evicted, start + grace));
        assert_eq!(
            healthy_at(&mut evicted, start + grace + H),
            !scaled,
            "the parked row is evicted past the set grace, scaled {scaled}"
        );
    }
}

/// The status a waiting standby publishes for shard `shard` as the wait builds it: phase `Standby` at a target with
/// no tenure, and an entry in the standby role with no tenure and no serving state.
fn waiting_status(shard: u32) -> Status {
    let shard_id = Shard::new(shard).unwrap();
    let entry = VolumeEntry {
        role: Some(RecordedRole::Standby),
        volume_state: Some(Recorded::Active),
        named: Some(true),
        ..VolumeEntry::unobserved(volume(shard), shard_id)
    };
    Status {
        target: Some(Target::of(&record(shard, 12, Some(OWN)))),
        entry: Some(entry),
        ..Status::idle(shard_id, volume(shard), shard, Phase::Standby)
    }
}

/// The host owns shard 1 and waits as shard 2's standby. Its report holds the owner's entry and the waiting
/// standby's entry in the standby role, phase `Standby`; the producer gauge counts the owned role produced. A
/// `Standby` status whose entry claims the owner role, or a serving state, is left out.
#[test]
fn a_waiting_standbys_entry_is_sealed_and_an_owner_claim_under_its_status_is_left_out() {
    let records = [record(1, OWN, Some(11)), record(2, 12, Some(OWN))];
    let waiting = waiting_status(2);
    let mut agent = synced(&records, &[reporting_status(1), waiting]);
    let out = at(&mut agent, REPORT_US, &[]);
    let report = Reader::default()
        .accept(out.report.as_ref().unwrap(), reader_key)
        .unwrap();
    let sealed: Vec<_> = (report.entries.iter())
        .map(|e| (e.shard.get(), e.role, e.phase))
        .collect();
    assert_eq!(
        sealed,
        [
            (1, Some(RecordedRole::Owner), Some(Phase::Serving)),
            (2, Some(RecordedRole::Standby), Some(Phase::Standby)),
        ]
    );
    assert_eq!(report.entries[1].tenure, None);
    assert_eq!(
        report.host.producer_missing,
        Members::Known { used: 0, limit: 1 }
    );
    let entry = waiting.entry.unwrap();
    let claims = [
        VolumeEntry {
            role: Some(RecordedRole::Owner),
            ..entry
        },
        VolumeEntry {
            role: None,
            ..entry
        },
        VolumeEntry {
            serving: Some(State::Serving),
            ..entry
        },
        VolumeEntry {
            role: Some(RecordedRole::Replacement),
            ..entry
        },
    ];
    let tenure = (
        ShardGeneration::new(3).unwrap(),
        ActivatedEpoch::new(4).unwrap(),
    );
    let tenured = Status {
        tenure: Some(tenure),
        entry: Some(VolumeEntry {
            tenure: Some(tenure),
            ..entry
        }),
        ..waiting
    };
    let claimed = (claims.into_iter())
        .map(|claim| Status {
            entry: Some(claim),
            ..waiting
        })
        .chain([tenured]);
    for claimed in claimed {
        let mut agent = synced(&records, &[reporting_status(1), claimed]);
        let out = at(&mut agent, REPORT_US, &[]);
        let report = Reader::default()
            .accept(out.report.as_ref().unwrap(), reader_key)
            .unwrap();
        let shards: Vec<_> = report.entries.iter().map(|e| e.shard.get()).collect();
        assert_eq!(shards, [1], "{claimed:?}");
        let (_, beats) = beat_to(&out, 11);
        let beaten: Vec<_> = beats.iter().map(|e| e.shard.get()).collect();
        assert_eq!(beaten, [1], "{claimed:?}");
    }
    let unrecorded = Status {
        entry: Some(VolumeEntry {
            role: Some(RecordedRole::Unrecorded),
            named: Some(false),
            ..entry
        }),
        ..waiting
    };
    let mut agent = synced(&records, &[reporting_status(1), unrecorded]);
    let out = at(&mut agent, REPORT_US, &[]);
    let report = Reader::default()
        .accept(out.report.as_ref().unwrap(), reader_key)
        .unwrap();
    let sealed: Vec<_> = (report.entries.iter())
        .map(|e| (e.shard.get(), e.role, e.phase))
        .collect();
    assert_eq!(
        sealed[1],
        (2, Some(RecordedRole::Unrecorded), Some(Phase::Standby)),
        "an unrecorded waiting entry is sealed"
    );
}

/// A waiting status leaves the volume's progress baseline to the last tenure's status: an owner status at a tenure,
/// then a `Standby` status of the same volume, then a replay of the owner status add the owner's counts once.
#[test]
fn a_waiting_status_leaves_the_owner_baseline_so_a_replay_adds_nothing() {
    let records = [record(1, OWN, Some(11))];
    let owner = status(1, Phase::Serving);
    let mut agent = synced(&records, &[owner]);
    let waiting = Status {
        pid: owner.pid + 1,
        ..waiting_status(1)
    };
    for (now, statuses) in [(1, vec![waiting]), (2, vec![owner])] {
        agent.turn(
            now,
            Inputs {
                statuses: &statuses,
                clock: clock(now),
                ..Inputs::NONE
            },
        );
    }
    let out = at(&mut agent, H, &[]);
    let (header, _) = beat_to(&out, 11);
    assert_eq!(
        (header.io, header.completions),
        (owner.io, owner.completions),
        "the owner's counts, once"
    );
}

/// A waiting status's entry for a role this host owns produces no owner entry: the producer gauge counts the owned
/// role missing.
#[test]
fn a_waiting_entry_for_an_owned_role_counts_the_role_missing() {
    let records = [record(1, OWN, Some(11))];
    let mut agent = synced(&records, &[waiting_status(1)]);
    let out = at(&mut agent, REPORT_US, &[]);
    let report = Reader::default()
        .accept(out.report.as_ref().unwrap(), reader_key)
        .unwrap();
    assert_eq!(report.entries.len(), 1, "the waiting entry is sealed");
    assert_eq!(
        report.host.producer_missing,
        Members::Known { used: 1, limit: 1 }
    );
}

/// No reader of the agent takes a waiting standby for an owner: on a host that owns shard 1 and waits as shard 2's
/// standby, the heartbeat carries the owner's tenure alone, the peer read time goes to the serving process alone,
/// the host reads healthy, and a nomination of shard 2 goes to the waiting process.
#[test]
fn a_waiting_standby_beside_an_owned_shard_reads_as_no_owner() {
    let records = [record(1, OWN, Some(11)), record(2, 12, Some(OWN))];
    let serving = status(1, Phase::Serving);
    let mut agent = synced(&records, &[serving, waiting_status(2)]);
    let entry = beat::Entry {
        shard: Shard::new(9).unwrap(),
        generation: ShardGeneration::new(3).unwrap(),
        epoch: ActivatedEpoch::new(2).unwrap(),
        volume: VolumeState::Active,
        report_age_us: 0,
        read_age_us: Some(0),
    };
    let acking = sealed(
        &Header {
            ack: 1,
            ack_boot: BOOT,
            ..header(11, 1, 1)
        },
        &[entry],
        OWN,
    );
    let out = agent.turn(
        5,
        Inputs {
            heartbeats: &[&acking],
            clock: clock(5),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    let read = Inbound::Peer { read_at: Some(0) };
    assert_eq!(peers(&out), [(serving.volume, read)]);
    let out = at(&mut agent, H, &[]);
    let (_, beats) = beat_to(&out, 11);
    let shards: Vec<_> = beats.iter().map(|e| e.shard.get()).collect();
    assert_eq!(shards, [1], "the owner's tenure alone");
    assert!(agent.healthy(H));
    let (_, out) = nominated(&records, &[serving, waiting_status(2)]);
    let sent: Vec<_> = nominations(&out).iter().map(|(to, ..)| *to).collect();
    assert!(
        !sent.is_empty() && sent.iter().all(|to| *to == volume(2)),
        "a nomination reaches the waiting process alone: {sent:?}"
    );
}

/// The refusal class of a restart that read `read` and held after a bump whose reply is unknown.
pub(crate) fn unknown_bump(read: Target) -> crate::failover::report::RecoveryRefusal {
    use crate::failover::restart::{Check, Refused};
    use crate::storage::store::StoreError;
    crate::failover::report::RecoveryRefusal::from(&Refused {
        check: Check::Bump(StoreError::Unknown),
        flip: None,
        recovery: Some(read),
    })
}

/// The final status [`held_status`](super::super::recover::held_status) builds for process `pid` of `record`'s
/// shard whose restart read `record` and held after a bump whose reply is unknown.
pub(crate) fn held_final(record: &ShardRecord, pid: u32) -> Status {
    let holder = crate::failover::poll::Holder {
        volume: record.active,
        ..crate::failover::takeover::tests::holder_of(host(OWN))
    };
    let mut recovery = crate::failover::report::RecoveryStatus::NO_ATTEMPT;
    recovery.start(crate::failover::report::RecoveryKind::Restart, 0);
    let exit = Exit::Held {
        recovery: Target::of(record),
    };
    super::super::recover::held_status(
        (&holder, record.shard, pid),
        (&exit, Some(unknown_bump(Target::of(record)))),
        recovery,
        5,
    )
    .expect("a held restart's final status")
}

/// The report entries the agent seals at `now` with `statuses` received at that turn and, when given, `records`
/// synced at it.
fn sealed_entries(
    agent: &mut Agent,
    now: u64,
    statuses: &[Status],
    records: Option<&[ShardRecord]>,
) -> Vec<VolumeEntry> {
    let placement = placement();
    let out = agent.turn(
        now,
        Inputs {
            statuses,
            sync: records.map(|records| Synced {
                records,
                placement: &placement,
            }),
            clock: clock(now),
            ..Inputs::NONE
        },
    );
    assert!(out.refused.is_empty(), "{:?}", out.refused);
    let report = out.report.expect("a report is due");
    Reader::default()
        .accept(&report, reader_key)
        .unwrap()
        .entries
        .clone()
}

/// HELD-RESTART-LATCH: the final status of a restart held after a bump whose reply is unknown seals its diagnostic
/// entry, the tenure `(g, 2E)` of the target the restart read with every tenure-keyed count null, in every report
/// while the latch stands, past the status's freshness bound; it gives no heartbeat entry and no progress credit.
#[test]
fn a_held_restart_s_final_status_seals_its_entry_past_the_freshness_bound_with_no_heartbeat_entry()
{
    let records = [record(1, OWN, None), record(2, OWN, None)];
    // Counts on the final status that a credit would add to the heartbeat's totals.
    let held = Status {
        io: 50,
        completions: 5,
        ..held_final(&records[0], 7)
    };
    let serving = status(2, Phase::Serving);
    let mut agent = synced(&records, &[held, serving]);
    let fresh = at(&mut agent, H, &[]);
    let (header, beats) = beat_to(&fresh, 11);
    let shards: Vec<u32> = beats.iter().map(|entry| entry.shard.get()).collect();
    assert_eq!(shards, [2], "only the tenured twin gives a heartbeat entry");
    assert_eq!(
        (header.io, header.completions),
        (serving.io, serving.completions),
        "the held status adds no progress credit"
    );
    let tenure = Some((
        records[0].generation,
        ActivatedEpoch::new(2 * records[0].attempts).unwrap(),
    ));
    for now in [REPORT_US, STALE_US + REPORT_US, 10 * STALE_US] {
        let entries = sealed_entries(&mut agent, now, &[], None);
        let held: Vec<_> = entries
            .iter()
            .filter(|entry| entry.shard.get() == 1)
            .collect();
        assert_eq!(held.len(), 1, "at {now}: {entries:?}");
        let entry = held[0];
        assert!(entry.held_restart(), "at {now}: {entry:?}");
        assert_eq!((entry.tenure, entry.phase), (tenure, Some(Phase::Held)));
    }
}

/// HELD-RESTART-LATCH's clearings and its successor rule: a later status of the volume, a new incarnation's
/// `Starting` status, a sync that no longer names this host owner of the volume at the read target or one above it,
/// and the agent's restart each clear the latch; a late final status of a process a successor replaced latches
/// nothing.
#[test]
fn the_held_restart_latch_clears_on_each_of_its_four_events_and_takes_no_late_final_status() {
    let records = [record(1, OWN, None)];
    let held = held_final(&records[0], 7);
    let latched = |agent: &mut Agent, now, statuses: &[Status], sync: Option<&[ShardRecord]>| {
        let entries = sealed_entries(agent, now, statuses, sync);
        entries.iter().any(VolumeEntry::held_restart)
    };
    // A later status of the volume.
    let mut agent = synced(&records, &[held]);
    let serving = Status {
        volume: held.volume,
        ..status(1, Phase::Recovering)
    };
    assert!(!latched(&mut agent, REPORT_US, &[serving], None));
    // A new incarnation's first status, which it publishes before its sequence can bump.
    let mut agent = synced(&records, &[held]);
    let starting = Status::idle(held.shard, held.volume, 8, Phase::Starting);
    assert!(!latched(&mut agent, REPORT_US, &[starting], None));
    // A late final status of the replaced process latches nothing.
    assert!(!latched(&mut agent, 2 * REPORT_US, &[held], None));
    // A redelivery of the latched status keeps it.
    let mut agent = synced(&records, &[held]);
    assert!(latched(&mut agent, REPORT_US, &[held], None));
    // A sync at the read target and at one attempt above it keeps the latch; another owner, another active volume
    // or a target two above clears it.
    let bumped = ShardRecord {
        attempts: records[0].attempts + 1,
        ..records[0]
    };
    assert!(latched(&mut agent, 2 * REPORT_US, &[], Some(&records)));
    assert!(latched(&mut agent, 3 * REPORT_US, &[], Some(&[bumped])));
    for moved in [
        ShardRecord {
            owner: host(11),
            ..records[0]
        },
        ShardRecord {
            active: volume(9),
            ..records[0]
        },
        ShardRecord {
            attempts: records[0].attempts + 2,
            ..records[0]
        },
    ] {
        let mut agent = synced(&records, &[held]);
        assert!(
            !latched(&mut agent, REPORT_US, &[], Some(&[moved])),
            "{moved:?}"
        );
    }
    // A sync of a record older than the read keeps the latch.
    let older = ShardRecord {
        attempts: records[0].attempts - 1,
        owner: host(11),
        ..records[0]
    };
    let mut agent = synced(&records, &[held]);
    assert!(latched(&mut agent, REPORT_US, &[], Some(&[older])));
    // A sync that lists no record of the shard ends the host's role in it and clears the latch, and a later sync
    // that lists the record again sets none.
    let mut agent = synced(&records, &[held]);
    let other = [record(2, OWN, None)];
    assert!(!latched(&mut agent, REPORT_US, &[], Some(&other)));
    assert!(!latched(&mut agent, 2 * REPORT_US, &[], Some(&records)));
    // A final status that arrives after the sync that would have cleared its latch sets none, in either order of
    // the two; the volume's row still takes the status.
    for moved in [
        ShardRecord {
            owner: host(11),
            ..records[0]
        },
        ShardRecord {
            attempts: records[0].attempts + 2,
            ..records[0]
        },
    ] {
        let mut agent = synced(&[moved], &[]);
        assert!(
            !latched(&mut agent, REPORT_US, &[held], None),
            "after the sync: {moved:?}"
        );
        let row = (agent.statuses.iter()).find(|kept| kept.status.volume == held.volume);
        assert_eq!(row.map(|kept| kept.status.pid), Some(held.pid));
        assert!(!latched(&mut agent, 2 * REPORT_US, &[], None));
    }
    // A sync that supports the final status lets it latch on a later turn, and so does an agent with no sync yet.
    let mut agent = synced(&records, &[]);
    assert!(latched(&mut agent, REPORT_US, &[held], None));
    let mut unsynced = self::agent();
    assert!(latched(&mut unsynced, REPORT_US, &[held], None));
    // The agent keeps the latch in memory only, so an agent that starts again holds none until a final status
    // reaches it.
}

/// A lagging sync of a record older than the restart's read keeps the latch past the restart grace, and with it
/// the volume's row: when the current record returns, the health bit reads the held process at once.
#[test]
fn a_latch_kept_through_an_older_record_keeps_its_row_and_the_health_bit() {
    let records = [record(1, OWN, Some(11))];
    let held = held_final(&records[0], 7);
    let latched = |agent: &mut Agent, now, sync: &[ShardRecord]| {
        let entries = sealed_entries(agent, now, &[], Some(sync));
        entries.iter().any(VolumeEntry::held_restart)
    };
    let mut agent = synced(&records, &[held]);
    assert!(!agent.healthy(REPORT_US));
    let older = ShardRecord {
        attempts: records[0].attempts - 1,
        owner: host(11),
        standby: None,
        ..records[0]
    };
    let late = RESTART_GRACE_US + REPORT_US;
    assert!(latched(&mut agent, late, &[older]));
    assert!(latched(&mut agent, late + REPORT_US, &records));
    assert!(
        !agent.healthy(late + REPORT_US),
        "the latched process reads held"
    );
}

/// The successor rule's accepting side: a process's own `Starting` status lets its final status latch; a successor's
/// `Starting` status clears the latch and names the successor, whose own final status latches, while the
/// predecessor's late final status leaves the successor's row and the host's health as they were. A `Closing`
/// status ends the named process, so a later process that published no `Starting` status still latches.
#[test]
fn a_final_status_latches_after_its_own_starting_status_and_a_late_predecessor_changes_no_row() {
    let records = [record(1, OWN, Some(11))];
    let (shard, volume) = (records[0].shard, records[0].active);
    let held = |pid| held_final(&records[0], pid);
    let starting = |pid| Status::idle(shard, volume, pid, Phase::Starting);
    let latched = |agent: &mut Agent, now, statuses: &[Status]| {
        let entries = sealed_entries(agent, now, statuses, None);
        entries.iter().any(VolumeEntry::held_restart)
    };
    let mut agent = synced(&records, &[starting(7)]);
    assert!(
        latched(&mut agent, REPORT_US, &[held(7)]),
        "its own Starting status"
    );
    assert!(!agent.healthy(REPORT_US), "the held process reads held");
    assert!(
        !latched(&mut agent, 2 * REPORT_US, &[starting(8)]),
        "the successor's Starting status"
    );
    assert!(agent.healthy(2 * REPORT_US), "the successor reads starting");
    assert!(
        !latched(&mut agent, 3 * REPORT_US, &[held(7)]),
        "the late predecessor"
    );
    assert!(
        agent.healthy(3 * REPORT_US),
        "the late predecessor leaves the health bit"
    );
    let row = (agent.statuses.iter())
        .find(|kept| kept.status.volume == volume)
        .unwrap();
    assert_eq!((row.status.pid, row.status.phase), (8, Phase::Starting));
    assert!(
        latched(&mut agent, 4 * REPORT_US, &[held(8)]),
        "the successor's own final status"
    );
    let mut agent = synced(&records, &[starting(7)]);
    let closing = Status::idle(shard, volume, 7, Phase::Closing);
    assert!(!latched(&mut agent, REPORT_US, &[closing]));
    assert!(
        latched(&mut agent, 2 * REPORT_US, &[held(9)]),
        "a later process with no Starting status"
    );
    assert!(!agent.healthy(2 * REPORT_US));
}

/// A process whose `Starting` status the cell lost before a take still latches its final status: the named
/// process ended with no `Closing` status, alone or with a successor of its own, or the later process published an
/// ordinary status first. The volume's row and the health bit then read the held process.
#[test]
fn a_final_status_of_a_later_process_latches_with_no_starting_status_of_its_own() {
    let records = [record(1, OWN, Some(11))];
    let (shard, volume) = (records[0].shard, records[0].active);
    let held = |pid| held_final(&records[0], pid);
    let starting = |pid| Status::idle(shard, volume, pid, Phase::Starting);
    let latched = |agent: &mut Agent, now, statuses: &[Status]| {
        let entries = sealed_entries(agent, now, statuses, None);
        entries.iter().any(VolumeEntry::held_restart)
    };
    let row = |agent: &Agent| {
        let kept = (agent.statuses.iter()).find(|kept| kept.status.volume == volume);
        kept.map(|kept| (kept.status.pid, kept.status.phase))
    };
    let mut agent = synced(&records, &[starting(7)]);
    assert!(
        latched(&mut agent, REPORT_US, &[held(9)]),
        "no Closing status from 7 and no Starting status from 9"
    );
    assert!(!agent.healthy(REPORT_US), "the held process reads held");
    assert_eq!(row(&agent), Some((9, Phase::Held)));
    let mut agent = synced(&records, &[starting(7)]);
    assert!(!latched(&mut agent, REPORT_US, &[starting(8)]));
    assert!(
        latched(&mut agent, 2 * REPORT_US, &[held(9)]),
        "a process later than the newest named one and the one it replaced"
    );
    let mut agent = synced(&records, &[starting(7)]);
    let recovering = Status::idle(shard, volume, 9, Phase::Recovering);
    assert!(!latched(&mut agent, REPORT_US, &[recovering]));
    assert!(
        latched(&mut agent, 2 * REPORT_US, &[held(9)]),
        "an ordinary status of 9 and no Starting status from it"
    );
    assert_eq!(row(&agent), Some((9, Phase::Held)));
}

/// The process whose final status the agent drops is the one whose status the newest `Starting` status replaced: a
/// repeated `Starting` status of the newest process keeps it, a process's own repeated `Starting` status names no
/// replaced process, and each new incarnation moves it to the incarnation before.
#[test]
fn the_dropped_final_status_is_the_one_of_the_process_the_newest_starting_status_replaced() {
    let records = [record(1, OWN, Some(11))];
    let (shard, volume) = (records[0].shard, records[0].active);
    let held = |pid| held_final(&records[0], pid);
    let starting = |pid| Status::idle(shard, volume, pid, Phase::Starting);
    let latched = |agent: &mut Agent, now, statuses: &[Status]| {
        let entries = sealed_entries(agent, now, statuses, None);
        entries.iter().any(VolumeEntry::held_restart)
    };
    let mut agent = synced(&records, &[starting(7)]);
    assert!(!latched(&mut agent, REPORT_US, &[starting(8)]));
    assert!(!latched(&mut agent, 2 * REPORT_US, &[starting(8)]));
    assert!(
        !latched(&mut agent, 3 * REPORT_US, &[held(7)]),
        "the late predecessor after a repeated Starting status"
    );
    assert!(agent.healthy(3 * REPORT_US));
    assert!(latched(&mut agent, 4 * REPORT_US, &[held(8)]));
    let mut agent = synced(&records, &[starting(7)]);
    assert!(!latched(&mut agent, REPORT_US, &[starting(7)]));
    assert!(
        latched(&mut agent, 2 * REPORT_US, &[held(7)]),
        "its own repeated Starting status"
    );
    let mut agent = synced(&records, &[starting(7)]);
    assert!(!latched(&mut agent, REPORT_US, &[starting(8)]));
    assert!(!latched(&mut agent, 2 * REPORT_US, &[starting(9)]));
    assert!(
        !latched(&mut agent, 3 * REPORT_US, &[held(8)]),
        "the process the newest one replaced"
    );
    assert!(latched(&mut agent, 4 * REPORT_US, &[held(9)]));
}

/// A status the replay checks reject, a sample of an earlier tenure, leaves the latch standing.
#[test]
fn a_rejected_replay_leaves_the_held_restart_latch() {
    let records = [record(1, OWN, None)];
    let later = status(1, Phase::Serving);
    let replay = Status {
        tenure: Some((
            ShardGeneration::new(3).unwrap(),
            ActivatedEpoch::new(2).unwrap(),
        )),
        ..later
    };
    let held = held_final(&records[0], 7);
    let mut agent = synced(&records, &[later]);
    let entries = sealed_entries(&mut agent, REPORT_US, &[held], None);
    assert!(entries.iter().any(VolumeEntry::held_restart));
    let entries = sealed_entries(&mut agent, 2 * REPORT_US, &[replay], None);
    assert!(entries.iter().any(VolumeEntry::held_restart), "{entries:?}");
}

/// A latched held restart credits no owned role in the producer-missing gauge: its process has ended.
#[test]
fn a_latched_held_restart_counts_its_owned_role_missing() {
    let records = [record(1, OWN, None)];
    let held = held_final(&records[0], 7);
    let mut agent = synced(&records, &[held]);
    let out = at(&mut agent, 10 * STALE_US, &[]);
    let report = Reader::default()
        .accept(out.report.as_ref().unwrap(), reader_key)
        .unwrap();
    assert!(report.entries.iter().any(VolumeEntry::held_restart));
    assert_eq!(
        report.host.producer_missing,
        Members::Known { used: 1, limit: 1 }
    );
}

/// `VolumeEntry::held_restart` takes the entry `held_status` builds and refuses each departure from it.
#[test]
fn the_held_restart_predicate_refuses_each_departure_from_its_shape() {
    use crate::failover::report::{
        Recovery, RecoveryCheck, RecoveryKind, RecoveryNext, StoreClass,
    };
    let entry = held_final(&record(1, OWN, None), 7).entry.unwrap();
    assert!(entry.held_restart());
    let r = entry.recovery;
    let with = |recovery: Recovery| VolumeEntry { recovery, ..entry };
    let zero = Some((
        ShardGeneration::new(3).unwrap(),
        ActivatedEpoch::new(0).unwrap(),
    ));
    let departures = [
        (
            "role",
            VolumeEntry {
                role: Some(RecordedRole::Standby),
                ..entry
            },
        ),
        (
            "tenure",
            VolumeEntry {
                tenure: None,
                ..entry
            },
        ),
        (
            "epoch 0",
            VolumeEntry {
                tenure: zero,
                ..entry
            },
        ),
        (
            "phase",
            VolumeEntry {
                phase: Some(Phase::Parked),
                ..entry
            },
        ),
        (
            "exit label",
            VolumeEntry {
                ended: Some(Ended::Rerun),
                ..entry
            },
        ),
        (
            "serving",
            VolumeEntry {
                serving: Some(State::Withdrawn),
                ..entry
            },
        ),
        (
            "flip",
            VolumeEntry {
                flip: true,
                ..entry
            },
        ),
        (
            "served",
            VolumeEntry {
                served: Some(0),
                ..entry
            },
        ),
        (
            "report age",
            VolumeEntry {
                report_age_us: Some(1),
                ..entry
            },
        ),
        (
            "volume state",
            VolumeEntry {
                volume_state: Some(Recorded::Active),
                ..entry
            },
        ),
        (
            "kind",
            with(Recovery {
                kind: Some(RecoveryKind::Lineage),
                ..r
            }),
        ),
        ("outcome", with(Recovery { outcome: None, ..r })),
        (
            "check",
            with(Recovery {
                check: Some(RecoveryCheck::FirstReport),
                ..r
            }),
        ),
        (
            "next",
            with(Recovery {
                next: Some(RecoveryNext::Stop),
                ..r
            }),
        ),
        (
            "store",
            with(Recovery {
                store: Some(StoreClass::Log),
                ..r
            }),
        ),
    ];
    for (name, departed) in departures {
        assert!(!departed.held_restart(), "{name}");
    }
}

/// The hand-over's retry loop: a publication refused once and then accepted takes two calls, and one always
/// refused takes every try.
#[test]
fn the_hand_over_retries_a_refused_publication_up_to_its_tries() {
    use super::super::recover::retried;
    let calls = Cell::new(0);
    let once = retried(4, || {
        calls.set(calls.get() + 1);
        calls.get() > 1
    });
    assert_eq!((once, calls.get()), (Ok(()), 2));
    calls.set(0);
    let never = retried(4, || {
        calls.set(calls.get() + 1);
        false
    });
    assert_eq!((never, calls.get()), (Err(()), 4));
}

/// `own_entry`'s held-restart conjunct: a `Held` status with no tenure seals an entry with a tenure only when the
/// status names a target whose `(g, 2E)` the entry carries and the entry has the held restart's shape.
#[test]
fn a_held_status_seals_a_tenured_entry_only_in_the_held_restart_s_shape() {
    let records = [record(1, OWN, None)];
    let held = held_final(&records[0], 7);
    let entry = held.entry.unwrap();
    let other = Target {
        attempts: records[0].attempts + 1,
        ..Target::of(&records[0])
    };
    let variants = [
        (
            "no exit label",
            Status {
                ended: None,
                ..held
            },
        ),
        (
            "no target",
            Status {
                target: None,
                ..held
            },
        ),
        (
            "another target",
            Status {
                target: Some(other),
                ..held
            },
        ),
        (
            "a serving state",
            Status {
                entry: Some(VolumeEntry {
                    serving: Some(State::Withdrawn),
                    ..entry
                }),
                ..held
            },
        ),
        (
            "a count",
            Status {
                entry: Some(VolumeEntry {
                    served: Some(0),
                    ..entry
                }),
                ..held
            },
        ),
        (
            "another store class",
            Status {
                entry: Some(VolumeEntry {
                    recovery: crate::failover::report::Recovery {
                        store: Some(crate::failover::report::StoreClass::Unavailable),
                        ..entry.recovery
                    },
                    ..entry
                }),
                ..held
            },
        ),
    ];
    for (name, status) in variants {
        let mut agent = synced(&records, &[status]);
        let entries = sealed_entries(&mut agent, REPORT_US, &[], None);
        assert!(entries.is_empty(), "{name}: {entries:?}");
    }
    let mut agent = synced(&records, &[held]);
    assert_eq!(sealed_entries(&mut agent, REPORT_US, &[], None), [entry]);
}

/// A final status handed over after a turn that sealed no report, and first sealed past its freshness bound, still
/// reaches the report: the latch, not the status's freshness, carries it to the first seal after the hand-over.
#[test]
fn a_held_restart_s_entry_missed_by_the_first_seal_after_its_hand_over_reaches_the_next() {
    let records = [record(1, OWN, None)];
    let held = held_final(&records[0], 7);
    let mut agent = synced(&records, &[]);
    let out = agent.turn(
        1,
        Inputs {
            statuses: &[held],
            clock: clock(1),
            ..Inputs::NONE
        },
    );
    assert!(out.report.is_none(), "no report is due at the hand-over");
    let later = STALE_US + 2 * REPORT_US;
    let entries = sealed_entries(&mut agent, later, &[], None);
    assert_eq!(entries, [held.entry.unwrap()]);
}

/// `hand_over` retries a publication the held cell refuses and returns the status after its last try; a free cell
/// takes it, and `waiting` reads `false` once the agent's caller took it.
#[test]
fn a_final_status_the_held_cell_refuses_returns_to_its_caller_and_a_free_cell_takes_it() {
    use super::super::link::StatusCell;
    use super::super::recover::hand_over;
    let cell = StatusCell::default();
    let held = held_final(&record(1, OWN, None), 7);
    {
        let _held = cell.hold();
        assert_eq!(hand_over(&cell, held, 4), Err(Box::new(held)));
    }
    assert_eq!(hand_over(&cell, held, 4), Ok(()));
    assert!(cell.waiting());
    assert_eq!(cell.take(), Some(held));
    assert!(!cell.waiting());
}

/// `held_status` builds a final status only for a restart held after a bump whose reply is unknown: another exit,
/// another bump error, no refusal, no started attempt and a read at `E = 0` give none.
#[test]
fn held_status_builds_only_the_held_restart_s_final_status() {
    use super::super::recover::held_status;
    use crate::failover::report::{RecoveryKind, RecoveryRefusal, RecoveryStatus};
    use crate::failover::restart::{Check, Refused};
    use crate::storage::store::StoreError;
    let read = record(1, OWN, None);
    let target = Target::of(&read);
    let holder = crate::failover::poll::Holder {
        volume: read.active,
        ..crate::failover::takeover::tests::holder_of(host(OWN))
    };
    let mut started = RecoveryStatus::NO_ATTEMPT;
    started.start(RecoveryKind::Restart, 0);
    let held = Exit::Held { recovery: target };
    let unavailable = RecoveryRefusal::from(&Refused {
        check: Check::Bump(StoreError::Unavailable),
        flip: None,
        recovery: Some(target),
    });
    let built = |exit: &Exit, refusal, recovery| {
        held_status((&holder, read.shard, 7), (exit, refusal), recovery, 5)
    };
    let status = built(&held, Some(unknown_bump(target)), started).unwrap();
    assert_eq!(
        (status.phase, status.tenure, status.target, status.ended),
        (Phase::Held, None, Some(target), Some(Ended::Held))
    );
    assert_eq!((status.io, status.completions, status.pending), (0, 0, 0));
    assert!(status.entry.unwrap().held_restart());
    assert_eq!(
        built(&Exit::Stopped, Some(unknown_bump(target)), started),
        None
    );
    assert_eq!(built(&held, Some(unavailable), started), None);
    assert_eq!(built(&held, None, started), None);
    assert_eq!(
        built(
            &held,
            Some(unknown_bump(target)),
            RecoveryStatus::NO_ATTEMPT
        ),
        None
    );
    let mut ended = started;
    ended.refuse(unavailable);
    assert_eq!(
        built(&held, Some(unknown_bump(target)), ended),
        None,
        "an attempt another refusal ended"
    );
    let unread = Exit::Held {
        recovery: Target {
            attempts: 0,
            ..target
        },
    };
    assert_eq!(built(&unread, Some(unknown_bump(target)), started), None);
}

/// The control: a latch that seals only while its status is fresh drops the held restart's entry from the report
/// sealed past the freshness bound.
#[test]
fn the_control_whose_latch_keeps_the_freshness_rule_drops_the_held_restart_s_entry() {
    let records = [record(1, OWN, None)];
    let held = held_final(&records[0], 7);
    let entries = planted("fresh-latch", || {
        let mut agent = synced(&records, &[held]);
        sealed_entries(&mut agent, 10 * STALE_US, &[], None)
    });
    assert!(
        entries.is_empty(),
        "the planted fresh latch drops the held restart's entry: {entries:?}"
    );
}
