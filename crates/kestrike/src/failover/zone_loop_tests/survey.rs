use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::failover::loss::Health;
use crate::failover::loss::tests::receipt;
use crate::failover::reconcile::{Reconciler, StandbyGate};
use crate::failover::records::{
    ERA, EventKind, Host, RecordedPair, ShardRecord, VolumeId, VolumeRecord, VolumeState,
    attachment_key,
};
use crate::failover::report::{
    Gauge, Hold, HostReport, Phase as OwnerPhase, RecoveryCheck, RecoveryKind, VolumeEntry,
    Withdrawal,
};
use crate::failover::retire::Target;
use crate::failover::sim::host;
use crate::failover::standbys::tests::{report_of, roomy};
use crate::failover::standbys::{Attach, Census, Closed, Need, Population};
use crate::failover::takeover::tests::{c_host, c_pair};
use crate::failover::zone_loop::config::{Fraction, ZoneBounds};
use crate::failover::zone_loop::directory::{
    Color, Directory, DirectoryState, HostEntry, Listing, SuccessionRefusal,
};
use crate::failover::zone_loop::evidence::{
    HostEvidence, ListedVolumeState, VolumeCondition, VolumeJudgement, VolumeStatus,
};
use crate::failover::zone_loop::observe::{
    Completeness, HostView, Observation, ShardRecords, ShardView, Source, ZoneView,
};
use crate::failover::zone_loop::plan::{Context, Plan, Step, Survey, UNVERIFIED_AS_DEVICE, plan};
use crate::failover::zone_loop::sources::{ListedVolume, Unreachable};
use crate::failover::zone_loop::status::{
    Blocker, EnrollPhase, Exposure, ShardState, VerdictCounts, ZoneStatus,
};
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};
use crate::storage::store::sim::{Arm, AsReconciler, MemLog};
use crate::storage::store::{Client, Key, StoreError};
use crate::storage::store_tests::{OWNER, record};

use super::config::config_of;
use super::directory::{entry, instance, report_keys, shard_entry};
use super::observe::{Fixture, S, START, ZONE, volume};
use super::world::Event;

fn shard(number: u32) -> Shard {
    Shard::new(number).unwrap()
}

fn bind(volume: &mut VolumeRecord, number: u64) {
    let seq = volume.live(host(number)).unwrap();
    let event = volume.events.iter_mut().find(|event| event.seq == seq);
    event.unwrap().instance = Some(instance(number));
}

fn placed(number: u64, partition: u32, color: u16) -> HostEntry {
    let mut placed = entry(number, partition);
    placed.placement.color = Color(color);
    placed
}

/// The owner 11 in partition 2 and color 1, and candidates 12 to 20 in partition `n % 3` and color `n % 2`.
fn hosts() -> Vec<HostEntry> {
    (OWNER..=20)
        .map(|n| placed(n, (n % 3) as u32, (n % 2) as u16))
        .collect()
}

struct Scene {
    listing: Listing,
    verdicts: BTreeMap<u64, HostEvidence>,
    reports: BTreeMap<u64, HostReport>,
    shards: Vec<ShardRecords>,
    census: Census,
    volumes: Vec<ListedVolume>,
}

fn shard_record(number: u32, owner: u64, standby: Option<u64>) -> ShardRecord {
    ShardRecord {
        shard: shard(number),
        active: volume(number),
        owner: host(owner),
        attempts: 1,
        spare: None,
        standby: standby.map(host),
        ..record()
    }
}

/// `OWNER` marks the fixture history to reassign when the active volume has no record for the requested owner.
fn records(number: u32, owner: u64, standby: Option<u64>, active: VolumeRecord) -> ShardRecords {
    let mut records = unattached(number, owner, standby, active);
    let active = &mut records.active;
    if active.live(host(owner)).is_none() {
        let first = active.events[0].host;
        active.events[0].host = host(owner);
        for recorded in active.pairs.iter_mut().filter(|pair| pair.host == first) {
            recorded.host = host(owner);
        }
    }
    if let Some(standby) = standby.filter(|&standby| active.live(host(standby)).is_none()) {
        active.push(EventKind::Attach, host(standby), ERA).unwrap();
    }
    records
}

fn unattached(number: u32, owner: u64, standby: Option<u64>, active: VolumeRecord) -> ShardRecords {
    let active = VolumeRecord {
        volume: volume(number),
        ..active
    };
    ShardRecords {
        record: shard_record(number, owner, standby),
        active,
        spare: None,
        receipt: None,
        replacement: None,
        entries: Vec::new(),
        judgement: VolumeJudgement {
            health: Some(Health::Available),
            others: 0,
            complete: true,
            streak: u32::MAX,
            confirmed: true,
        },
    }
}

/// A listing row of `volume`, in use, attached to `instances`.
fn listed(volume: VolumeId, instances: &[u64]) -> ListedVolume {
    ListedVolume {
        volume,
        condition: VolumeCondition {
            state: ListedVolumeState::InUse,
            status: VolumeStatus::Ok,
        },
        attachments: (instances.iter())
            .map(|&n| instance(n).as_str().to_owned())
            .collect(),
    }
}

fn plenty(number: u64) -> HostReport {
    report_of(host(number), Gauge::known(0, 64), Gauge::known(0, 2))
}

impl Scene {
    fn new(shards: Vec<ShardRecords>) -> Self {
        let hosts = hosts();
        let scene_volumes: Vec<VolumeId> =
            shards.iter().map(|records| records.record.active).collect();
        let listing = Listing {
            version: 1,
            zone: ZONE,
            zone_hold: false,
            host_roles_max: 10,
            shards: shards
                .iter()
                .map(|records| shard_entry(records.record.shard.get()))
                .collect(),
            hosts,
        };
        let numbers = listing.hosts.iter().map(|entry| entry.host.get());
        Self {
            verdicts: numbers.clone().map(|n| (n, HostEvidence::Live)).collect(),
            reports: numbers.map(|n| (n, plenty(n))).collect(),
            listing,
            shards,
            census: Census::empty(ZONE),
            volumes: (scene_volumes.iter()).map(|&id| listed(id, &[])).collect(),
        }
    }

    fn standby_needs(count: u32) -> Self {
        Self::new(
            (1..=count)
                .map(|n| records(n, OWNER, None, volume_record()))
                .collect(),
        )
    }

    fn observation(&self) -> Observation {
        let keys = report_keys(&self.listing);
        let directory = Directory::new(self.listing.clone(), keys).unwrap();
        let hosts = (directory.hosts().iter())
            .map(|entry| HostView {
                entry: *entry,
                verdict: self.verdicts[&entry.host.get()],
                answered: true,
                report: self.reports.get(&entry.host.get()).cloned().map(Arc::new),
            })
            .collect();
        let shards = (self.shards.iter())
            .map(|records| ShardView {
                shard: records.record.shard,
                records: Ok(Some(records.clone())),
            })
            .collect();
        Observation {
            complete: Completeness {
                reports: true,
                instances: true,
                volumes: true,
                store: true,
            },
            answered: true,
            zone: Ok(ZoneView {
                directory,
                hosts,
                volumes: Ok(self.volumes.clone()),
                census: Ok(self.census.clone()),
                shards,
                unnamed: Some(0),
            }),
            dropped: 0,
        }
    }

    fn plan_under(&self, bounds: &ZoneBounds) -> Plan {
        plan_with(&self.observation(), bounds)
    }

    fn plan(&self) -> Plan {
        self.plan_under(&bounds_with(|_| {}))
    }
}

fn plan_with(observation: &Observation, bounds: &ZoneBounds) -> Plan {
    plan_at(observation, bounds, START, &BTreeMap::new(), false)
}

fn plan_at(
    observation: &Observation,
    bounds: &ZoneBounds,
    now_us: u64,
    starts: &BTreeMap<(Shard, Host, VolumeId), u64>,
    warming: bool,
) -> Plan {
    let exposure = Exposure::default();
    let context = Context {
        bounds,
        now_us,
        warming,
        starts,
        exposure: &exposure,
        stuck: &BTreeSet::new(),
    };
    plan(observation, &context)
}

/// The bounds of the default configuration of 64 shards after `change`. The plan reads no call budget, so the
/// helper raises `calls_per_tick` above the changed `enroll_inflight_max` where validation requires it.
fn bounds_with(
    change: impl FnOnce(&mut crate::failover::zone_loop::config::ZoneConfig),
) -> ZoneBounds {
    let mut config = config_of(64);
    change(&mut config);
    config.calls_per_tick = config.calls_per_tick.max(config.enroll_inflight_max + 1);
    config.validate().unwrap()
}

pub(super) fn state_of(plan: &Plan, number: u32) -> (ShardState, Option<Blocker>) {
    let found = plan
        .shards
        .iter()
        .find(|entry| entry.shard == shard(number))
        .unwrap();
    (found.state, found.blocker)
}

pub(super) fn reserves(plan: &Plan) -> Vec<(u32, u64)> {
    let reserve = |step: &Step| match *step {
        Step::Reserve { shard, host, .. } => Some((shard.get(), host.get())),
        _ => None,
    };
    plan.steps.iter().filter_map(reserve).collect()
}

/// `volume` with each recorded pair under the key of its attach entry, as enrollment records it (KEY-PER-ATTACH).
fn keyed(mut volume: VolumeRecord) -> VolumeRecord {
    for recorded in &mut volume.pairs {
        recorded.pair.key = crate::failover::records::attachment_key(recorded.attach).unwrap();
    }
    volume
}

/// The restart fixture's active volume, the owner's pair recorded under its attach entry's key.
fn volume_record() -> VolumeRecord {
    keyed(crate::failover::restart::tests::volume_record())
}

/// The takeover fixture's lineage of `successors`, each pair recorded under its attach entry's key.
fn lineage(successors: &[(Host, crate::failover::evidence::Pair)]) -> VolumeRecord {
    keyed(crate::failover::takeover::tests::lineage(successors))
}

/// `shard`'s census at the target of its record naming `host`, for each pair.
fn census_of(slots: &[(ShardRecord, u64)]) -> Census {
    let population = Population { cap: 64 };
    let mut census = Census::empty(ZONE);
    for (record, named) in slots {
        let admitted = population.admit(
            &census,
            record,
            &roomy(host(*named)),
            Attach::Live,
            |_| None,
            |_| false,
        );
        census = admitted.unwrap().unwrap();
    }
    census
}

#[test]
fn a_live_role_host_whose_entry_ended_reads_as_a_need() {
    let end = |records: &mut ShardRecords, number: u64| {
        let seq = records.active.live(host(number)).unwrap();
        let event = records
            .active
            .events
            .iter_mut()
            .find(|event| event.seq == seq);
        event.unwrap().kind = EventKind::Ended;
    };
    let need_of = |scene: &Scene| {
        let plan = scene.plan();
        let found = plan
            .shards
            .iter()
            .find(|entry| entry.shard == shard(1))
            .unwrap();
        let need = match found.state {
            ShardState::Enrolling { need, .. } => Some(need),
            _ => None,
        };
        (need, found.protected)
    };
    let named = || Scene::new(vec![records(1, OWNER, Some(13), volume_record())]);
    assert_eq!(need_of(&named()), (None, true));
    let mut standby_ended = named();
    end(&mut standby_ended.shards[0], 13);
    assert_eq!(need_of(&standby_ended), (Some(Need::Standby), false));
    let mut both_ended = standby_ended;
    end(&mut both_ended.shards[0], OWNER);
    assert_eq!(need_of(&both_ended), (Some(Need::Fresh), false));
}

#[test]
fn a_candidate_below_the_era_floor_is_passed_over() {
    let best = reserves(&Scene::standby_needs(1).plan());
    assert_eq!(best, [(1, 12)]);
    let mut scene = Scene::standby_needs(1);
    scene.reports.get_mut(&12).unwrap().host.build.era = crate::failover::records::MIN_ERA - 1;
    let chosen = reserves(&scene.plan());
    assert_eq!(chosen.len(), 1);
    assert_ne!(chosen[0].1, 12);
}

#[test]
fn a_standby_need_reserves_the_best_candidate_of_another_partition_and_color() {
    let plan = Scene::standby_needs(1).plan();
    assert_eq!(reserves(&plan), [(1, 12)]);
    let (state, blocker) = state_of(&plan, 1);
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Unreserved,
        host: host(12),
    };
    assert_eq!((state, blocker), (enrolling, None));
}

#[test]
fn the_plan_is_identical_under_any_host_order() {
    let scene = Scene::standby_needs(3);
    let bounds = bounds_with(|_| {});
    let forward = scene.observation();
    let mut reversed = forward.clone();
    let zone = reversed.zone.as_mut().unwrap();
    zone.hosts.reverse();
    zone.shards.reverse();
    assert_eq!(plan_with(&forward, &bounds), plan_with(&reversed, &bounds));
}

#[test]
fn each_candidate_filter_excludes_its_host_and_names_its_blocker() {
    let blocker = |scene: &Scene| state_of(&scene.plan(), 1);
    let no_candidate = ShardState::NoCandidate;

    let mut placement = Scene::standby_needs(1);
    placement
        .listing
        .hosts
        .retain(|entry| [OWNER, 14, 20].contains(&entry.host.get()));
    assert_eq!(
        blocker(&placement),
        (no_candidate, Some(Blocker::Placement))
    );

    let mut unknown = Scene::standby_needs(1);
    for verdict in unknown.verdicts.values_mut() {
        *verdict = HostEvidence::Unknown;
    }
    unknown.verdicts.insert(OWNER, HostEvidence::Live);
    assert_eq!(
        blocker(&unknown),
        (no_candidate, Some(Blocker::NoEligibleHost))
    );

    let mut headroom = Scene::standby_needs(1);
    for (number, report) in headroom.reports.iter_mut() {
        *report = report_of(host(*number), Gauge::known(0, 64), Gauge::known(2, 2));
    }
    assert_eq!(blocker(&headroom), (no_candidate, Some(Blocker::Headroom)));

    let mut capped = Scene::standby_needs(1);
    capped
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    let others: Vec<_> = (2..=7)
        .map(|n| (shard_record(n, OWNER, None), 12))
        .collect();
    capped.census = census_of(&others);
    capped.listing.shards.extend((2..=7).map(shard_entry));
    assert_eq!(blocker(&capped), (no_candidate, Some(Blocker::PerHostCap)));

    let mut roles = Scene::standby_needs(1);
    roles
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    roles.listing.host_roles_max = 2;
    roles.shards.push(records(2, 12, None, volume_record()));
    roles.listing.shards.push(shard_entry(2));
    roles.census = census_of(&[(shard_record(3, OWNER, None), 12)]);
    roles.listing.shards.push(shard_entry(3));
    assert_eq!(blocker(&roles), (no_candidate, Some(Blocker::PerHostCap)));

    let mut full = Scene::standby_needs(1);
    full.census = census_of(&[(shard_record(2, OWNER, None), 16)]);
    let one = bounds_with(|config| config.population_cap = 1);
    let plan = full.plan_under(&one);
    assert_eq!(
        state_of(&plan, 1),
        (no_candidate, Some(Blocker::CensusFull))
    );
}

#[test]
fn a_host_with_a_live_attach_ranks_first() {
    let mut scene = Scene::new(vec![records(
        1,
        OWNER,
        None,
        lineage(&[(c_host(), c_pair())]),
    )]);
    scene.listing.hosts.push(placed(c_host().get(), 0, 0));
    scene.verdicts.insert(c_host().get(), HostEvidence::Live);
    scene.reports.insert(c_host().get(), plenty(c_host().get()));
    assert_eq!(reserves(&scene.plan()), [(1, c_host().get())]);
}

#[test]
fn the_fresh_need_starts_first_and_at_most_four_enrollments_hold_a_slot() {
    const H: u64 = 13;
    let mut shards = Vec::new();
    for n in 1..=4 {
        shards.push(records(n, 12 + 2 * u64::from(n), None, volume_record()));
    }
    for n in 5..=8 {
        shards.push(records(n, OWNER, Some(H), volume_record()));
    }
    shards.push(records(9, H, Some(15), volume_record()));
    let mut scene = Scene::new(shards);
    scene
        .listing
        .hosts
        .extend((21..=26).map(|n| placed(n, (n % 3) as u32, (n % 2) as u16)));
    for n in 21..=26 {
        scene.verdicts.insert(n, HostEvidence::Live);
        scene.reports.insert(n, plenty(n));
    }
    scene.verdicts.insert(H, HostEvidence::Lost);
    scene.verdicts.insert(15, HostEvidence::Lost);
    let plan = scene.plan();
    let reserved = reserves(&plan);
    let order: Vec<u32> = reserved.iter().map(|(shard, _)| *shard).collect();
    assert_eq!(order, [9, 5, 6, 7], "{reserved:?}");
    let (state, _) = state_of(&plan, 9);
    assert!(matches!(
        state,
        ShardState::Enrolling {
            need: Need::Fresh,
            ..
        }
    ));
    scene.census = census_of(&[
        (shard_record(5, OWNER, None), 12),
        (shard_record(6, OWNER, None), 16),
    ]);
    let plan = scene.plan();
    assert_eq!(plan.inflight, 2);
    assert_eq!(reserves(&plan).len(), 2);
}

fn hold_scene(unknown: usize) -> Scene {
    let mut shards = vec![records(1, OWNER, None, volume_record())];
    let enrolled = lineage(&[(c_host(), c_pair())]);
    shards.push(records(2, OWNER, None, enrolled.clone()));
    let mut recorded = enrolled;
    recorded.pairs.retain(|pair| pair.host != c_host());
    shards.push(records(3, OWNER, None, recorded));
    shards.push(records(4, OWNER, None, volume_record()));
    let mut scene = Scene::new(shards);
    scene.listing.hosts = (OWNER..OWNER + 15)
        .map(|n| placed(n, (n % 8) as u32, (n % 2) as u16))
        .collect();
    scene.listing.hosts.push(placed(c_host().get(), 0, 0));
    let numbers: Vec<u64> = scene
        .listing
        .hosts
        .iter()
        .map(|entry| entry.host.get())
        .collect();
    scene.verdicts = numbers.iter().map(|&n| (n, HostEvidence::Live)).collect();
    scene.reports = numbers.iter().map(|&n| (n, plenty(n))).collect();
    for n in (OWNER + 1..OWNER + 15).rev().take(unknown) {
        scene.verdicts.insert(n, HostEvidence::Unknown);
    }
    let mut slots: Vec<_> = [2, 3]
        .map(|n| (scene.shards[n as usize - 1].record, c_host().get()))
        .into();
    slots.push((scene.shards[3].record, 12));
    scene.census = census_of(&slots);
    scene
}

#[test]
fn the_zone_host_hold_stops_new_attaches_and_keeps_recorded_ones() {
    let held = hold_scene(5).plan();
    assert!(held.holds.zone_host);
    assert!(reserves(&held).is_empty());
    let c = c_host();
    assert!(held.steps.iter().any(|step| matches!(step, Step::Designate { shard: at, host, .. } if *at == shard(2) && *host == c)));
    assert!(held.steps.iter().any(
        |step| matches!(step, Step::Attach { shard: at, host, .. } if *at == shard(3) && *host == c)
    ));
    assert!(
        !held
            .steps
            .iter()
            .any(|step| matches!(step, Step::RecordAttach { .. }))
    );
    let recovered = hold_scene(1).plan();
    assert!(
        recovered
            .steps
            .iter()
            .any(|step| matches!(step, Step::RecordAttach { shard: at, .. } if *at == shard(4)))
    );
    assert!(!recovered.holds.zone_host);
    assert_eq!(reserves(&recovered).len(), 1);
    let disabled = bounds_with(|config| {
        config.host_hold = Fraction {
            numerator: 99,
            denominator: 100,
        }
    });
    let control = hold_scene(5).plan_under(&disabled);
    assert_eq!(
        reserves(&control).len(),
        1,
        "control: with the hold disabled a start appears"
    );
}

#[test]
fn at_most_sixteen_new_attach_starts_are_admitted_in_any_window() {
    let mut scene = Scene::standby_needs(20);
    scene.listing.host_roles_max = 64;
    let bounds = bounds_with(|config| {
        config.enroll_inflight_max = 64;
        config.standbys_per_host_max = 64;
    });
    let observation = scene.observation();
    let mut starts = BTreeMap::new();
    let exposure = Exposure::default();
    for tick in 0..120 {
        let now_us = START + tick * 10 * S;
        starts.retain(|_, at: &mut u64| now_us - *at < bounds.config().attach_window_us);
        let context = Context {
            bounds: &bounds,
            now_us,
            warming: false,
            starts: &starts,
            exposure: &exposure,
            stuck: &BTreeSet::new(),
        };
        let plan = plan(&observation, &context);
        for start in plan.starts {
            starts.entry(start).or_insert(now_us);
        }
        let window = starts.values().filter(|&&at| now_us - at < 600 * S).count();
        assert!(window <= 16, "tick {tick}: {window}");
    }
    assert_eq!(starts.len(), 16);
}

fn owner_entry(number: u32, change: impl FnOnce(&mut VolumeEntry)) -> (Host, VolumeEntry) {
    let mut entry = super::observe::entry("vol-0a", number, record().generation.get(), 1);
    entry.volume = volume(number);
    change(&mut entry);
    (host(OWNER), entry)
}

#[test]
fn a_held_owner_still_gets_a_standby_enrollment() {
    let mut scene = Scene::standby_needs(1);
    scene.shards[0].entries = vec![owner_entry(1, |entry| entry.hold = Some(Hold::Held))];
    assert_eq!(reserves(&scene.plan()), [(1, 12)]);
    scene.shards[0].entries = vec![owner_entry(1, |entry| entry.phase = Some(OwnerPhase::Held))];
    let plan = scene.plan();
    assert_eq!(reserves(&plan), [(1, 12)]);
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Unreserved,
        host: host(12),
    };
    assert_eq!(
        state_of(&plan, 1),
        (enrolling, Some(Blocker::DeviceFailureHold))
    );
}

/// The record a planned transfer leaves when the end of its target's attach committed between the transfer job's
/// volume read and its shard write: the owner's entry in the active volume's record is
/// ended with its pair recorded, the record names no standby, and the owner's host answers and reads live while its
/// parked process reports no entry. `standbys::need_of` counts a named owner with no live attach lost
/// (ENDED-GRANTS-NOTHING), so the plan reserves a fresh host for the shard, whether the owner's host reads live or
/// lost; that host's designation over the ended owner's tenure is what lets it take the shard over.
#[test]
fn a_live_owner_whose_attach_ended_gets_a_fresh_host_enrollment() {
    let mut scene = Scene::standby_needs(1);
    let active = &mut scene.shards[0].active;
    let seq = active.live(host(OWNER)).expect("the owner's live attach");
    let entry = active.events.iter_mut().find(|event| event.seq == seq);
    entry.expect("the owner's entry").kind = EventKind::Ended;
    assert!(active.live(host(OWNER)).is_none() && !active.pairs.is_empty());
    let fresh = ShardState::Enrolling {
        need: Need::Fresh,
        phase: EnrollPhase::Unreserved,
        host: host(12),
    };
    for owner in [None, Some(HostEvidence::Lost)] {
        if let Some(evidence) = owner {
            scene.verdicts.insert(OWNER, evidence);
        }
        let plan = scene.plan();
        assert_eq!(reserves(&plan), [(1, 12)], "{owner:?}");
        assert_eq!(state_of(&plan, 1), (fresh, None), "{owner:?}");
    }
}

fn guard_scene(successor: bool, predecessor: bool) -> Scene {
    let mut scene = Scene::standby_needs(1);
    scene.shards[0].active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(12), c_pair())])
    };
    scene.shards[0].entries = vec![owner_entry(1, |entry| {
        entry.recovery.kind = Some(RecoveryKind::Takeover);
        entry.phase = Some(if successor {
            OwnerPhase::Held
        } else {
            OwnerPhase::Serving
        });
    })];
    let mut former = owner_entry(1, |entry| {
        entry.tenure = Some((record().generation, ActivatedEpoch::new(0).unwrap()));
        entry.phase = Some(if predecessor {
            OwnerPhase::Held
        } else {
            OwnerPhase::Standby
        });
    })
    .1;
    former.role = None;
    scene.reports.get_mut(&12).unwrap().entries.push(former);
    scene
}

fn refusal(check: RecoveryCheck) -> crate::failover::report::Recovery {
    crate::failover::report::Recovery {
        kind: Some(RecoveryKind::Restart),
        outcome: Some(crate::failover::report::RecoveryOutcome::Refused),
        check: Some(check),
        ..crate::failover::report::Recovery::UNAVAILABLE
    }
}

fn guarded(plan: &Plan) -> bool {
    reserves(plan).is_empty()
        && state_of(plan, 1) == (ShardState::NoCandidate, Some(Blocker::DeviceFailureHold))
}

/// DEVICE-HOLD-GUARD over the restart's own refusal conversion: a successor whose restart refused at a device
/// command of its lineage arm, its Register, its preempt or its Report #2, or at the arm's full registrant table
/// before its bump, reports `check = recorded-holder`, `next = hold` with kind `lineage`, and beside a predecessor's device hold the plan reserves no standby. A plain
/// recorded-holder refusal of the same restart keeps kind `restart` and its exemption, so the standby is reserved.
#[test]
fn a_failed_lineage_device_step_beside_a_predecessor_device_hold_plans_no_standby() {
    use crate::failover::report::{RecoveryNext, RecoveryRefusal, RecoveryStatus};
    use crate::failover::restart::{Check, Failed, Lineage, Refused};
    let held = |check: Check| {
        let refused = Refused {
            check,
            flip: None,
            recovery: Some(Target::of(&record())),
        };
        let mut status = RecoveryStatus::NO_ATTEMPT;
        status.start(RecoveryKind::Restart, 0);
        status.refuse(RecoveryRefusal::from(&refused));
        let mut scene = guard_scene(true, true);
        let entry = &mut scene.shards[0].entries[0].1;
        entry.recovery = status.recovery(10);
        assert_eq!(
            (entry.recovery.check, entry.recovery.next),
            (
                Some(RecoveryCheck::RecordedHolder),
                Some(RecoveryNext::Hold)
            ),
            "{refused:?}"
        );
        (entry.recovery.kind, scene.plan())
    };
    for step in [
        Lineage::Register(Failed(None)),
        Lineage::Full,
        Lineage::Preempt(Failed(None)),
        Lineage::Confirm(Box::new(Check::SecondReport(Failed(None)))),
    ] {
        let (kind, plan) = held(Check::Lineage(step.clone()));
        assert_eq!(kind, Some(RecoveryKind::Lineage), "{step:?}");
        assert!(guarded(&plan), "{step:?}: {:?}", plan.steps);
    }
    let (kind, plan) = held(Check::RecordedHolder);
    assert_eq!(kind, Some(RecoveryKind::Restart));
    assert!(
        !reserves(&plan).is_empty(),
        "a plain recorded-holder hold keeps its exemption"
    );
}

#[test]
fn a_device_hold_on_both_sides_of_a_takeover_plans_no_standby() {
    assert!(guarded(&guard_scene(true, true).plan()));
    assert_eq!(reserves(&guard_scene(true, false).plan()), [(1, 12)]);
    assert_eq!(reserves(&guard_scene(false, true).plan()), [(1, 16)]);
    // The held report of a lost predecessor keeps the guard while the successor holds, and a serving successor
    // clears it.
    let mut lost = guard_scene(true, true);
    lost.verdicts.insert(12, HostEvidence::Lost);
    assert!(guarded(&lost.plan()));
    let mut cleared = guard_scene(false, true);
    cleared.verdicts.insert(12, HostEvidence::Lost);
    assert_eq!(reserves(&cleared.plan()), [(1, 16)]);
    let mut serving = guard_scene(true, true);
    let owner = &mut serving.shards[0].entries[0].1;
    owner.phase = None;
    owner.serving = Some(crate::failover::serving::State::Serving);
    assert_eq!(reserves(&serving.plan()), [(1, 16)]);
    // An entry without a phase reads as serving when its readiness is granted; a withheld entry and an entry in
    // phase `Recovering` keep the guard.
    let mut withheld = guard_scene(true, true);
    let owner = &mut withheld.shards[0].entries[0].1;
    owner.phase = None;
    owner.serving = Some(crate::failover::serving::State::Serving);
    owner.withheld = true;
    assert!(guarded(&withheld.plan()));
    let mut early = guard_scene(true, true);
    let owner = &mut early.shards[0].entries[0].1;
    owner.phase = Some(OwnerPhase::Recovering);
    owner.serving = Some(crate::failover::serving::State::Serving);
    assert!(guarded(&early.plan()));
    let mut recorded = guard_scene(true, true);
    recorded.shards[0].entries[0].1.withdrawal = Some(Withdrawal::RecordedHolder);
    assert_eq!(reserves(&recorded.plan()), [(1, 16)]);
    let mut unattached = guard_scene(true, false);
    let held = owner_entry(1, |entry| entry.phase = Some(OwnerPhase::Held)).1;
    unattached.reports.get_mut(&16).unwrap().entries.push(held);
    assert_eq!(reserves(&unattached.plan()), [(1, 12)]);
    let mut other = guard_scene(true, true);
    other.reports.get_mut(&12).unwrap().entries[0].shard = shard(2);
    assert_eq!(reserves(&other.plan()), [(1, 12)]);
    let mut enrolling = guard_scene(true, true);
    enrolling.census = census_of(&[(enrolling.shards[0].record, 18)]);
    let plan = enrolling.plan();
    assert!(guarded(&plan) && plan.steps.is_empty());
    assert_eq!(plan.inflight, 1);
    let mut lineage_arm = guard_scene(true, true);
    lineage_arm.shards[0].entries[0].1.recovery.kind = Some(RecoveryKind::Lineage);
    assert!(guarded(&lineage_arm.plan()));
    let mut restart = guard_scene(true, true);
    restart.shards[0].entries[0].1.recovery.kind = Some(RecoveryKind::Restart);
    assert!(guarded(&restart.plan()));
    let mut absent = guard_scene(true, true);
    absent.shards[0].entries.clear();
    assert!(guarded(&absent.plan()));
    let mut recovering = guard_scene(true, true);
    recovering.shards[0].entries[0].1.phase = Some(OwnerPhase::Recovering);
    assert!(guarded(&recovering.plan()));
    for registration in [Withdrawal::RecordedHolder, Withdrawal::Unheld] {
        let mut scene = guard_scene(true, true);
        scene.reports.get_mut(&12).unwrap().entries[0].withdrawal = Some(registration);
        assert_eq!(reserves(&scene.plan()), [(1, 12)], "{registration:?}");
    }
    let mut refused = guard_scene(true, true);
    let former = &mut refused.reports.get_mut(&12).unwrap().entries[0];
    former.recovery = refusal(RecoveryCheck::Unheld);
    assert!(former.encode().is_ok());
    assert_eq!(reserves(&refused.plan()), [(1, 12)]);
    let mut elsewhere = guard_scene(true, true);
    elsewhere.reports.get_mut(&12).unwrap().entries[0].volume = volume(2);
    assert_eq!(reserves(&elsewhere.plan()), [(1, 12)]);
    let mut own = guard_scene(true, false);
    let owned = own.shards[0].entries[0].1;
    own.reports.get_mut(&OWNER).unwrap().entries.push(owned);
    assert_eq!(reserves(&own.plan()), [(1, 12)]);
}

/// With a serving owner, a slot host that reports the device-failure hold on the shard's active volume retains its
/// slot and counts as one in-flight unit. The hold blocks `Attach` in `Recorded` and `Designate` in `Enrolled`.
#[test]
fn a_slot_host_that_reports_the_device_hold_gets_no_enrollment_step() {
    let slotted = |held: bool, enrolled: bool, listed: bool| {
        let mut scene = guard_scene(false, held);
        if !enrolled {
            let pairs = &mut scene.shards[0].active.pairs;
            pairs.retain(|pair| pair.host != host(12));
        }
        if !listed {
            scene.volumes.clear();
        }
        scene.census = census_of(&[(scene.shards[0].record, 12)]);
        (scene.plan(), Target::of(&scene.shards[0].record))
    };
    let (shard, host) = (shard(1), host(12));
    for (enrolled, phase) in [
        (true, EnrollPhase::Enrolled),
        (false, EnrollPhase::Recorded),
    ] {
        let enrolling = ShardState::Enrolling {
            need: Need::Standby,
            phase,
            host,
        };
        let (plan, _) = slotted(true, enrolled, true);
        assert!(plan.steps.is_empty(), "{phase:?}: {:?}", plan.steps);
        assert_eq!(
            state_of(&plan, 1),
            (enrolling, Some(Blocker::DeviceFailureHold))
        );
        assert_eq!(plan.inflight, 1);
        let (plan, target) = slotted(false, enrolled, true);
        let step = match enrolled {
            true => Step::Designate {
                shard,
                host,
                target,
            },
            false => Step::Attach {
                shard,
                host,
                target,
            },
        };
        assert_eq!(plan.steps, [step]);
        assert_eq!(state_of(&plan, 1), (enrolling, None));
    }
    // For a recorded attach, a missing volume listing makes `ControlPlaneUnavailable` take precedence over
    // `DeviceFailureHold`.
    let (plan, _) = slotted(true, false, false);
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
    assert_eq!(state_of(&plan, 1).1, Some(Blocker::ControlPlaneUnavailable));
}

#[test]
fn host_side_labels_give_their_shard_its_blocker() {
    let protected = |change: fn(&mut VolumeEntry)| {
        let mut scene = Scene::new(vec![records(1, OWNER, Some(12), volume_record())]);
        scene.shards[0].entries = vec![owner_entry(1, change)];
        state_of(&scene.plan(), 1)
    };
    let at = |blocker| (ShardState::Protected, blocker);
    let recorded = protected(|entry| entry.withdrawal = Some(Withdrawal::RecordedHolder));
    assert_eq!(recorded, at(Some(Blocker::RecordedHolderHold)));
    let held_refused = |entry: &mut VolumeEntry| {
        entry.phase = Some(OwnerPhase::Held);
        entry.recovery = refusal(RecoveryCheck::RecordedHolder);
    };
    assert!(owner_entry(1, held_refused).1.encode().is_ok());
    assert_eq!(
        protected(held_refused),
        at(Some(Blocker::RecordedHolderHold))
    );
    let device = protected(|entry| entry.phase = Some(OwnerPhase::Held));
    assert_eq!(device, at(Some(Blocker::DeviceFailureHold)));
    let unheld = protected(|entry| {
        entry.phase = Some(OwnerPhase::Held);
        entry.withdrawal = Some(Withdrawal::Unheld);
    });
    assert_eq!(unheld, at(None));
    let unverified = |entry: &mut VolumeEntry| {
        entry.phase = Some(OwnerPhase::Held);
        entry.withdrawal = Some(Withdrawal::Unverified);
    };
    assert_eq!(protected(unverified), at(None));
    UNVERIFIED_AS_DEVICE.set(true);
    let planted = protected(unverified);
    UNVERIFIED_AS_DEVICE.set(false);
    assert_eq!(
        planted,
        at(Some(Blocker::DeviceFailureHold)),
        "control: the unverified label read as a device hold blocks the shard"
    );
    assert_eq!(protected(|_| {}), at(None));
    let suspecting = |owner: HostEvidence, standby: Option<u64>, own: Option<u64>| {
        let mut scene = Scene::new(vec![records(1, OWNER, Some(12), volume_record())]);
        scene.verdicts.insert(OWNER, owner);
        scene
            .reports
            .get_mut(&12)
            .unwrap()
            .host
            .detector
            .self_suspect_us = standby;
        scene
            .reports
            .get_mut(&OWNER)
            .unwrap()
            .host
            .detector
            .self_suspect_us = own;
        state_of(&scene.plan(), 1)
    };
    let unknown = HostEvidence::Unknown;
    let selfish = Some(Blocker::SelfSuspect);
    assert_eq!(suspecting(unknown, Some(5 * S), None), at(selfish));
    assert_eq!(suspecting(unknown, Some(0), None), at(None));
    assert_eq!(suspecting(unknown, None, None), at(None));
    assert_eq!(suspecting(unknown, None, Some(5 * S)), at(None));
    assert_eq!(suspecting(HostEvidence::Live, Some(5 * S), None), at(None));
    let mut gray = Scene::new(vec![records(1, OWNER, Some(12), volume_record())]);
    gray.reports
        .get_mut(&12)
        .unwrap()
        .host
        .detector
        .self_suspect_us = Some(5 * S);
    let health = &mut gray.reports.get_mut(&OWNER).unwrap().host.health;
    *health = Some(crate::failover::report::Health::Unhealthy);
    assert_eq!(state_of(&gray.plan(), 1), at(selfish));
    // The owner's hold label outranks its standby's self-suspicion.
    gray.shards[0].entries = vec![owner_entry(1, |entry| entry.phase = Some(OwnerPhase::Held))];
    assert_eq!(
        state_of(&gray.plan(), 1),
        at(Some(Blocker::DeviceFailureHold))
    );
    // An enrollment's own blocker outranks the owner's hold label.
    let mut short = Scene::standby_needs(1);
    for (number, report) in short.reports.iter_mut() {
        *report = report_of(host(*number), Gauge::known(0, 64), Gauge::known(2, 2));
    }
    short.shards[0].entries = vec![owner_entry(1, |entry| {
        entry.withdrawal = Some(Withdrawal::RecordedHolder)
    })];
    assert_eq!(
        state_of(&short.plan(), 1),
        (ShardState::NoCandidate, Some(Blocker::Headroom))
    );
    let mut gone = Scene::new(vec![records(1, OWNER, Some(12), volume_record())]);
    gone.verdicts.insert(OWNER, HostEvidence::Lost);
    gone.verdicts.insert(12, HostEvidence::Lost);
    gone.reports
        .get_mut(&12)
        .unwrap()
        .host
        .detector
        .self_suspect_us = Some(5 * S);
    let (state, blocker) = state_of(&gone.plan(), 1);
    assert!(matches!(
        state,
        ShardState::Enrolling {
            need: Need::Fresh,
            ..
        }
    ));
    assert_eq!(blocker, None);
}

/// QUORUM-PREMISE: hosts 11, 15 and 18 read lost, so the possible probers of standby 12 stand in partition 1 alone.
#[test]
fn a_self_suspecting_standby_outranks_quorum_unreachable() {
    let cut_off = |dwell: Option<u64>| {
        let mut scene = Scene::new(vec![records(1, OWNER, Some(12), volume_record())]);
        for lost in [OWNER, 15, 18] {
            scene.verdicts.insert(lost, HostEvidence::Lost);
        }
        scene
            .reports
            .get_mut(&12)
            .unwrap()
            .host
            .detector
            .self_suspect_us = dwell;
        state_of(&scene.plan(), 1)
    };
    let at = |blocker| (ShardState::Protected, Some(blocker));
    assert_eq!(cut_off(Some(5 * S)), at(Blocker::SelfSuspect));
    assert_eq!(cut_off(None), at(Blocker::QuorumUnreachable));
}

#[test]
fn a_flip_request_at_the_current_tenure_plans_no_step() {
    let mut scene = Scene::standby_needs(1);
    scene.shards[0].entries = vec![owner_entry(1, |entry| entry.flip = true)];
    let plan = scene.plan();
    let retirement = (
        ShardState::RetirementRequested,
        Some(Blocker::RetirementRequested),
    );
    assert_eq!(state_of(&plan, 1), retirement);
    assert!(plan.steps.is_empty());
}

#[test]
fn volume_and_owner_evidence_give_their_states() {
    let with = |change: fn(&mut Scene)| {
        let mut scene = Scene::standby_needs(1);
        change(&mut scene);
        state_of(&scene.plan(), 1)
    };
    let impaired = with(|scene| scene.shards[0].judgement.health = Some(Health::Impaired));
    assert_eq!(
        impaired,
        (ShardState::VolumeImpaired, Some(Blocker::VolumeImpaired))
    );
    let unconfirmed = with(|scene| {
        scene.shards[0].judgement.health = Some(Health::Lost);
        scene.shards[0].judgement.complete = false;
    });
    assert_eq!(
        unconfirmed,
        (ShardState::LossUnconfirmed, Some(Blocker::LossUnconfirmed))
    );
    let correlated = with(|scene| {
        scene.shards[0].judgement.health = Some(Health::Lost);
        scene.shards[0].judgement.others = 1;
    });
    assert_eq!(
        correlated,
        (ShardState::ReplacementHeld, Some(Blocker::CorrelatedHold))
    );
    let owner = with(|scene| {
        scene.verdicts.insert(OWNER, HostEvidence::Conflict);
    });
    assert_eq!(
        owner,
        (ShardState::OwnerUnknown, Some(Blocker::OwnerNotReady))
    );
    let standby = with(|scene| {
        scene.shards[0].record.standby = Some(host(12));
        let active = &mut scene.shards[0].active;
        active.push(EventKind::Attach, host(12), ERA).unwrap();
        scene.verdicts.insert(12, HostEvidence::Unknown);
    });
    assert_eq!(
        standby,
        (ShardState::StandbyUnknown, Some(Blocker::LossUnconfirmed))
    );
    let closed = with(|scene| {
        let full = lineage(&[(c_host(), c_pair()), (host(222), c_pair())]);
        scene.shards[0].active = VolumeRecord {
            volume: volume(1),
            ..full
        };
    });
    assert_eq!(closed, (ShardState::Closed, Some(Blocker::AttachClosed)));
}

/// An isolated loss provisions once its run of complete views reaches the configured `loss_ticks`; a loss beside
/// another impaired volume holds on any view once confirmed, and defers before.
#[test]
fn the_loss_run_follows_the_configured_loss_ticks() {
    let bounds = bounds_with(|config| config.loss_ticks = 3);
    let with = |streak: u32, complete: bool, others: usize, confirmed: bool| {
        let mut scene = Scene::standby_needs(1);
        let judged = &mut scene.shards[0].judgement;
        judged.health = Some(Health::Lost);
        (judged.streak, judged.complete) = (streak, complete);
        (judged.others, judged.confirmed) = (others, confirmed);
        state_of(&scene.plan_under(&bounds), 1)
    };
    let unconfirmed = (ShardState::LossUnconfirmed, Some(Blocker::LossUnconfirmed));
    let open = ShardState::Replacing {
        phase: crate::failover::loss::Phase::Open,
    };
    assert_eq!(
        with(2, true, 0, true),
        unconfirmed,
        "one view short of the run"
    );
    assert_eq!(with(3, true, 0, false), (open, None), "the run");
    assert_eq!(with(3, false, 0, true), unconfirmed, "an incomplete view");
    let held = (ShardState::ReplacementHeld, Some(Blocker::CorrelatedHold));
    assert_eq!(with(0, false, 1, true), held, "a confirmed correlated loss");
    assert_eq!(
        with(3, true, 1, false),
        unconfirmed,
        "an unconfirmed correlated loss"
    );
}

pub(super) fn warm(fixture: &mut Fixture, ticks: u64) {
    for step in 0..ticks {
        surveyed(fixture, START + step * 10 * S);
    }
}

pub(super) fn roomy_fixture(hosts: u64, shards: u32) -> Fixture {
    let mut fixture = Fixture::new(hosts, shards);
    fixture.headroom = crate::failover::report::Headroom {
        attachments: Gauge::known(0, 64),
        recovery: Gauge::known(0, 2),
        ..fixture.headroom
    };
    let mut listing = super::directory::listing(hosts, shards);
    for entry in &mut listing.hosts {
        entry.placement.color = Color((entry.host.get() % 2) as u16);
    }
    fixture.listing = Some(listing);
    fixture
}

#[test]
fn survey_changes_no_store_key_and_calls_no_attachment_over_ticks_with_unmet_needs() {
    let mut fixture = roomy_fixture(6, 3);
    let before = fixture.commits();
    warm(&mut fixture, 100);
    assert_eq!(fixture.commits(), before);
    let events = fixture.world.events();
    assert!(
        !events
            .iter()
            .any(|seen| matches!(seen, Event::Write(_) | Event::Attachments(_)))
    );
    let survey = fixture.zone.survey(
        Ok(fixture.directory()),
        &mut fixture.world,
        START + 1_000 * S,
    );
    assert!(!survey.plan.holds.warm_up);
    assert!(!reserves(&survey.plan).is_empty());
}

pub(super) fn designate_attached(fixture: &Fixture, number: u32, standby: Host) {
    let mut owner = Client::open(fixture.store.clone(), MemLog::default()).unwrap();
    let read = owner
        .read::<ShardRecord>(Key::Shard(shard(number)))
        .unwrap();
    let active = owner
        .read::<VolumeRecord>(Key::Volume(read.value().active))
        .unwrap();
    let mut attached = active.value().clone();
    let era = attached.events[0].era;
    attached.push(EventKind::Attach, standby, era).unwrap();
    owner.replace(&active, attached).unwrap();
    let target = Target::of(read.value());
    owner.designate(&read, target, standby).unwrap();
}

pub(super) fn designate_all(fixture: &Fixture) {
    for number in 1..=fixture.shards {
        let standby = host(1 + u64::from(number + 1) % fixture.hosts);
        designate_attached(fixture, number, standby);
    }
}

fn satisfied(plan: &Plan) -> bool {
    let shards: Vec<u32> = plan.shards.iter().map(|entry| entry.shard.get()).collect();
    plan.steps.is_empty()
        && shards == [1, 2, 3]
        && plan
            .shards
            .iter()
            .all(|entry| entry.state == ShardState::Protected)
}

#[test]
fn a_satisfied_zone_plans_nothing_for_a_thousand_ticks() {
    let mut fixture = roomy_fixture(4, 3);
    designate_all(&fixture);
    let before = fixture.commits();
    for step in 0..1_000 {
        let survey = surveyed(&mut fixture, START + step * 10 * S);
        assert!(
            survey.plan.steps.is_empty(),
            "tick {step}: {:?}",
            survey.plan
        );
        if step > 10 {
            assert!(satisfied(&survey.plan), "tick {step}: {:?}", survey.plan);
        }
    }
    assert_eq!(fixture.commits(), before);
}

#[test]
fn warm_up_and_the_operator_hold_start_no_attach() {
    let mut fixture = roomy_fixture(6, 2);
    let first = surveyed(&mut fixture, START);
    assert!(first.plan.holds.warm_up && first.plan.steps.is_empty());
    assert!(first.status.holds.warm_up);
    warm(&mut fixture, 10);
    let mut held = fixture.listing.clone().unwrap();
    held.version = 2;
    held.zone_hold = true;
    fixture.listing = Some(held);
    let survey = surveyed(&mut fixture, START + 200 * S);
    assert!(survey.plan.holds.operator && !survey.plan.holds.warm_up);
    assert_eq!(survey.status.holds, survey.plan.holds);
    let attaching = |step: &Step| {
        matches!(
            step,
            Step::Reserve { .. } | Step::RecordAttach { .. } | Step::Attach { .. }
        )
    };
    assert!(!survey.plan.steps.iter().any(attaching));
}

#[test]
fn the_color_filter_and_the_attachment_gauge_exclude_their_hosts() {
    let mut color = Scene::standby_needs(1);
    color
        .listing
        .hosts
        .retain(|entry| [OWNER, 13, 19].contains(&entry.host.get()));
    assert_eq!(
        state_of(&color.plan(), 1),
        (ShardState::NoCandidate, Some(Blocker::Placement))
    );
    let mut attachments = Scene::standby_needs(1);
    for (number, report) in attachments.reports.iter_mut() {
        *report = report_of(host(*number), Gauge::known(2, 2), Gauge::known(0, 2));
    }
    assert_eq!(
        state_of(&attachments.plan(), 1),
        (ShardState::NoCandidate, Some(Blocker::Headroom))
    );
}

#[test]
fn new_reservations_order_by_need_then_exposure_then_owner_then_shard() {
    let mut shards: Vec<ShardRecords> = (1..=3)
        .map(|n| records(n, OWNER, None, volume_record()))
        .collect();
    shards.push(records(4, 13, Some(15), volume_record()));
    let mut scene = Scene::new(shards);
    scene.verdicts.insert(13, HostEvidence::Lost);
    scene.verdicts.insert(15, HostEvidence::Lost);
    let bounds = bounds_with(|config| config.enroll_inflight_max = 64);
    let starts = BTreeMap::new();
    let mut exposure = Exposure::default();
    exposure.observe(shard(3), false, START - 100 * S);
    exposure.observe(shard(1), false, START - 10 * S);
    let context = Context {
        bounds: &bounds,
        now_us: START,
        warming: false,
        starts: &starts,
        exposure: &exposure,
        stuck: &BTreeSet::new(),
    };
    let plan = plan(&scene.observation(), &context);
    let order: Vec<u32> = reserves(&plan).iter().map(|(shard, _)| *shard).collect();
    assert_eq!(order, [4, 3, 1, 2]);
}

#[test]
fn one_tick_reserves_a_host_up_to_its_limits_once_across_shards() {
    let mut scene = Scene::standby_needs(4);
    scene
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    let others: Vec<_> = (5..=9)
        .map(|n| (shard_record(n, OWNER, None), 12))
        .collect();
    scene.census = census_of(&others);
    scene.listing.shards.extend((5..=9).map(shard_entry));
    scene.listing.host_roles_max = 64;
    let bounds = bounds_with(|config| config.enroll_inflight_max = 64);
    let plan = scene.plan_under(&bounds);
    assert_eq!(reserves(&plan), [(1, 12)]);
}

#[test]
fn a_slot_held_through_a_listing_outage_still_counts_in_flight() {
    let mut recorded = lineage(&[(c_host(), c_pair())]);
    recorded.pairs.retain(|pair| pair.host != c_host());
    let mut shards = vec![records(1, OWNER, None, recorded)];
    shards.extend((2..=6).map(|n| records(n, OWNER, None, volume_record())));
    let mut scene = Scene::new(shards);
    scene.listing.hosts.push(placed(c_host().get(), 0, 0));
    scene.verdicts.insert(c_host().get(), HostEvidence::Live);
    scene.reports.insert(c_host().get(), plenty(c_host().get()));
    scene.census = census_of(&[(scene.shards[0].record, c_host().get())]);
    let mut observation = scene.observation();
    let zone = observation.zone.as_mut().unwrap();
    zone.volumes = Err(crate::failover::attachments::Unlisted);
    for view in &mut zone.shards {
        view.records
            .as_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .judgement
            .health = None;
    }
    let plan = plan_with(&observation, &bounds_with(|_| {}));
    assert_eq!(plan.inflight, 1);
    assert!(plan.steps.is_empty());
    let unknown = state_of(&plan, 2);
    assert_eq!(unknown.1, Some(Blocker::ControlPlaneUnavailable));
    let recorded = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Recorded,
        host: c_host(),
    };
    let unlisted = (recorded, Some(Blocker::ControlPlaneUnavailable));
    assert_eq!(state_of(&plan, 1), unlisted);
    assert!(!plan.steps.iter().any(|step| step.shard() == shard(1)));
}

#[test]
fn a_quarter_of_hosts_within_the_largest_partition_holds_nothing() {
    let mut scene = hold_scene(5);
    for entry in &mut scene.listing.hosts {
        entry.placement.partition =
            crate::failover::arbiter::Partition((entry.host.get() % 2) as u32);
    }
    let plan = scene.plan();
    assert!(!plan.holds.zone_host);
    assert_eq!(reserves(&plan).len(), 1);
}

#[test]
fn an_unobserved_directory_leaves_every_known_shard_unobserved() {
    let mut fixture = roomy_fixture(4, 2);
    warm(&mut fixture, 2);
    let survey = fixture.zone.survey(
        Err(crate::failover::zone_loop::sources::Unreachable),
        &mut fixture.world,
        START + 100 * S,
    );
    let states: Vec<ShardState> = survey.plan.shards.iter().map(|entry| entry.state).collect();
    let unobserved = ShardState::Unobserved(Source::Directory);
    assert_eq!(states, [unobserved; 2]);
    let blockers: Vec<Option<Blocker>> = (survey.plan.shards.iter())
        .map(|entry| entry.blocker)
        .collect();
    assert_eq!(blockers, [None; 2]);
}

#[test]
fn the_start_window_holds_across_surveys() {
    let mut fixture = roomy_fixture(8, 20);
    let mut listing = fixture.listing.clone().unwrap();
    listing.host_roles_max = 64;
    fixture.listing = Some(listing);
    fixture.zone.bounds = bounds_with(|config| {
        config.enroll_inflight_max = 64;
        config.standbys_per_host_max = 64;
    });
    let mut admitted: BTreeMap<(Shard, Host, VolumeId), u64> = BTreeMap::new();
    for step in 0..120 {
        let now = START + step * 10 * S;
        let survey = surveyed(&mut fixture, now);
        admitted.retain(|_, at| now - *at < 600 * S);
        for start in survey.plan.starts {
            admitted.entry(start).or_insert(now);
        }
        assert!(admitted.len() <= 16, "tick {step}: {}", admitted.len());
    }
}

#[test]
fn the_survey_remembers_admitted_starts_across_a_changed_directory() {
    let mut fixture = roomy_fixture(8, 20);
    let mut listing = fixture.listing.clone().unwrap();
    listing.host_roles_max = 64;
    fixture.listing = Some(listing.clone());
    fixture.zone.bounds = bounds_with(|config| {
        config.enroll_inflight_max = 64;
        config.standbys_per_host_max = 64;
    });
    let window = fixture.zone.bounds.config().attach_window_us;
    let (first, started) = warmed(&mut fixture);
    let batch: BTreeSet<Shard> = (first.plan.starts.iter())
        .map(|&(shard, ..)| shard)
        .collect();
    assert_eq!(batch.len(), 16);
    let mut rest = listing;
    rest.version = 2;
    rest.shards.retain(|entry| !batch.contains(&entry.shard));
    fixture.listing = Some(rest);
    for at in [started + 10 * S, started + window - 10 * S] {
        assert!(
            reserves(&surveyed(&mut fixture, at).plan).is_empty(),
            "{at}"
        );
    }
    let opened = surveyed(&mut fixture, started + window);
    assert_eq!(reserves(&opened.plan).len(), 4);
}

#[test]
fn the_roles_limit_binds_within_one_tick() {
    let mut scene = Scene::standby_needs(3);
    scene
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    scene.listing.host_roles_max = 3;
    scene
        .shards
        .push(records(4, 12, Some(OWNER), volume_record()));
    scene.listing.shards.push(shard_entry(4));
    let bounds = bounds_with(|config| config.enroll_inflight_max = 64);
    assert_eq!(reserves(&scene.plan_under(&bounds)), [(1, 12), (2, 12)]);
}

#[test]
fn one_free_attachment_slot_admits_one_new_attach_per_tick() {
    let mut scene = Scene::standby_needs(3);
    scene
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    let tight = report_of(host(12), Gauge::known(1, 2), Gauge::known(0, 2));
    scene.reports.insert(12, tight);
    let bounds = bounds_with(|config| config.enroll_inflight_max = 64);
    assert_eq!(reserves(&scene.plan_under(&bounds)), [(1, 12)]);
}

#[test]
fn an_unread_shard_keeps_its_slot_in_flight_and_counts_as_a_role_of_every_host() {
    let unread = |roles_max: u32| {
        let mut scene = Scene::standby_needs(2);
        scene
            .listing
            .hosts
            .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
        scene.listing.host_roles_max = roles_max;
        scene.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
        let mut observation = scene.observation();
        let unavailable = Source::Store(StoreError::Unavailable);
        observation.zone.as_mut().unwrap().shards[0].records = Err(unavailable);
        plan_with(&observation, &bounds_with(|_| {}))
    };
    let roomy = unread(10);
    assert_eq!(roomy.inflight, 1);
    let unobserved = ShardState::Unobserved(Source::Store(StoreError::Unavailable));
    assert_eq!(
        state_of(&roomy, 1),
        (unobserved, Some(Blocker::StoreUnavailable))
    );
    assert_eq!(reserves(&roomy), [(2, 12)]);
    let full = unread(2);
    assert!(reserves(&full).is_empty());
    assert_eq!(
        state_of(&full, 2),
        (ShardState::NoCandidate, Some(Blocker::PerHostCap))
    );
}

fn releases(plan: &Plan) -> Vec<u32> {
    let release = |step: &Step| match *step {
        Step::Release { shard, .. } => Some(shard.get()),
        _ => None,
    };
    plan.steps.iter().filter_map(release).collect()
}

fn only(number: u64) -> Scene {
    let mut scene = Scene::standby_needs(1);
    scene
        .listing
        .hosts
        .retain(|entry| [OWNER, number].contains(&entry.host.get()));
    scene
}

#[test]
fn census_entries_of_shards_outside_the_directory_count_against_host_limits() {
    let mut capped = only(12);
    let others: Vec<_> = (2..=7)
        .map(|n| (shard_record(n, OWNER, None), 12))
        .collect();
    capped.census = census_of(&others);
    assert_eq!(
        state_of(&capped.plan(), 1),
        (ShardState::NoCandidate, Some(Blocker::PerHostCap))
    );
    let mut outside = Scene::standby_needs(1);
    outside.census = census_of(&[(outside.shards[0].record, 16)]);
    outside.shards[0].record.attempts = 2;
    outside.listing.shards.clear();
    assert_eq!(reserves(&outside.plan()), [(1, 16)]);
    // An entry of a shard outside the view counts as one role of the host it names.
    let roles = |entries: &[(ShardRecord, u64)]| {
        let mut scene = only(12);
        scene.listing.host_roles_max = 1;
        scene.census = census_of(entries);
        scene.plan()
    };
    assert_eq!(reserves(&roles(&[])), [(1, 12)]);
    let named = |host| roles(&[(shard_record(9, OWNER, None), host)]);
    assert_eq!(reserves(&named(16)), [(1, 12)]);
    assert_eq!(
        state_of(&named(12), 1),
        (ShardState::NoCandidate, Some(Blocker::PerHostCap))
    );
}

#[test]
fn the_volume_listing_decides_a_recorded_attach_phase() {
    let c = c_host();
    let mut recorded = lineage(&[(c, c_pair())]);
    recorded.pairs.retain(|pair| pair.host != c);
    let mut scene = Scene::new(vec![records(1, OWNER, None, recorded)]);
    scene.listing.hosts.push(placed(c.get(), 0, 0));
    scene.verdicts.insert(c.get(), HostEvidence::Live);
    scene.reports.insert(c.get(), plenty(c.get()));
    scene.census = census_of(&[(scene.shards[0].record, c.get())]);
    let phase = |scene: &Scene| {
        let plan = scene.plan();
        let attach = (plan.steps.iter()).any(|step| matches!(step, Step::Attach { .. }));
        (state_of(&plan, 1), attach)
    };
    let enrolling = |phase| ShardState::Enrolling {
        need: Need::Standby,
        phase,
        host: c,
    };
    assert_eq!(
        phase(&scene),
        ((enrolling(EnrollPhase::Recorded), None), true)
    );
    scene.volumes = vec![listed(volume(1), &[c.get()])];
    assert_eq!(
        phase(&scene),
        ((enrolling(EnrollPhase::Attached), None), false)
    );
    let unlisted = (
        (
            enrolling(EnrollPhase::Recorded),
            Some(Blocker::ControlPlaneUnavailable),
        ),
        false,
    );
    scene.volumes.clear();
    assert_eq!(phase(&scene), unlisted);
    let rows = [listed(volume(1), &[]), listed(volume(1), &[c.get()])];
    for order in [rows.clone(), [rows[1].clone(), rows[0].clone()]] {
        scene.volumes = order.into();
        assert_eq!(phase(&scene), unlisted);
    }
    let peers = [listed(volume(1), &[OWNER]), listed(volume(1), &[])];
    for order in [peers.clone(), [peers[1].clone(), peers[0].clone()]] {
        scene.volumes = order.into();
        assert_eq!(phase(&scene), unlisted);
    }
    let mut unreadable = listed(volume(1), &[OWNER]);
    unreadable.attachments.push(String::new());
    scene.volumes = vec![unreadable];
    assert_eq!(phase(&scene), unlisted);
    scene.volumes = vec![listed(volume(1), &[OWNER])];
    assert_eq!(
        phase(&scene),
        ((enrolling(EnrollPhase::Recorded), None), true)
    );
    // Another volume's row, listed first and attached to the host, leaves this volume's phase to its own row.
    scene.volumes = vec![listed(volume(2), &[c.get()]), listed(volume(1), &[OWNER])];
    assert_eq!(
        phase(&scene),
        ((enrolling(EnrollPhase::Recorded), None), true)
    );
}

/// If a recorded pair holds the derived key of the slot host's live attach, or that attach's number has no key,
/// [`Attach::of`] returns `Attach::Closed`. The slot then reads `Closed` with `AttachClosed`, gets no step and
/// keeps its in-flight unit, whether the listing shows the volume attached to the slot host or to no instance.
/// When the live attach has a key, every recorded pair holds a different key and the listing shows the volume
/// attached to no instance, the planner emits `Step::Attach`.
#[test]
fn a_slot_whose_live_attach_can_enroll_no_pair_reads_closed() {
    let c = c_host();
    let mut recorded = lineage(&[(c, c_pair())]);
    recorded.pairs.retain(|pair| pair.host != c);
    let mut held = recorded.clone();
    held.pairs[0].pair.key =
        crate::failover::records::attachment_key(recorded.live(c).unwrap()).unwrap();
    let mut keyless = recorded.clone();
    keyless.events.last_mut().unwrap().seq = u32::MAX - 1;
    keyless.next = u32::MAX;
    let plan_of = |active: &VolumeRecord, instances: &[u64]| {
        let mut scene = Scene::new(vec![records(1, OWNER, None, active.clone())]);
        scene.listing.hosts.push(placed(c.get(), 0, 0));
        scene.verdicts.insert(c.get(), HostEvidence::Live);
        scene.reports.insert(c.get(), plenty(c.get()));
        scene.census = census_of(&[(scene.shards[0].record, c.get())]);
        scene.volumes = vec![listed(volume(1), instances)];
        scene.plan()
    };
    let bounds = bounds_with(|_| {});
    let attaching = |step: &Step| matches!(step, Step::Attach { .. });
    assert_eq!(Attach::of(&recorded, c, bounds.bounds()), Attach::Live);
    assert!(plan_of(&recorded, &[]).steps.iter().any(attaching));
    let shut = (ShardState::Closed, Some(Blocker::AttachClosed));
    for (active, case) in [(&held, "held key"), (&keyless, "no key")] {
        assert_eq!(
            Attach::of(active, c, bounds.bounds()),
            Attach::Closed,
            "{case}"
        );
        for instances in [&[][..], &[c.get()]] {
            let plan = plan_of(active, instances);
            assert_eq!(state_of(&plan, 1), shut, "{case}, on {instances:?}");
            assert!(plan.steps.is_empty(), "{case}: {:?}", plan.steps);
            assert_eq!(
                plan.inflight, 1,
                "{case}: the slot keeps its in-flight unit"
            );
        }
    }
}

#[test]
fn only_the_owner_entry_for_the_active_volume_requests_a_flip() {
    let other = |flip| {
        owner_entry(1, |entry| {
            entry.volume = volume(9);
            entry.flip = flip;
        })
    };
    let active = |flip| owner_entry(1, |entry| entry.flip = flip);
    let retirement = (
        ShardState::RetirementRequested,
        Some(Blocker::RetirementRequested),
    );
    for entries in [
        vec![other(true), active(false)],
        vec![active(false), other(true)],
    ] {
        let mut scene = Scene::standby_needs(1);
        scene.shards[0].entries = entries;
        assert_eq!(reserves(&scene.plan()), [(1, 12)]);
    }
    for entries in [
        vec![other(false), active(true)],
        vec![active(true), other(false)],
    ] {
        let mut scene = Scene::standby_needs(1);
        scene.shards[0].entries = entries;
        let plan = scene.plan();
        assert_eq!(state_of(&plan, 1), retirement);
        assert!(plan.steps.is_empty());
    }
    // The owner's entry alone requests a flip: with another host's entry for the active volume at the record's
    // tenure, ahead of the owner's entry or after it, the enrollment stays planned.
    let peer = (host(12), active(true).1);
    for entries in [vec![peer, active(false)], vec![active(false), peer]] {
        let mut scene = Scene::standby_needs(1);
        scene.shards[0].entries = entries;
        assert_eq!(reserves(&scene.plan()), [(1, 12)]);
    }
}

#[test]
fn one_plan_adds_no_census_entry_past_the_cap() {
    let mut scene = Scene::standby_needs(3);
    scene.census = census_of(&[(shard_record(3, OWNER, None), 16)]);
    let plan = scene.plan_under(&bounds_with(|config| config.population_cap = 2));
    assert_eq!(reserves(&plan), [(1, 12)]);
    assert_eq!(
        state_of(&plan, 2),
        (ShardState::NoCandidate, Some(Blocker::CensusFull))
    );
    let mut full = Scene::standby_needs(1);
    full.census = census_of(&[(full.shards[0].record, 16)]);
    full.shards[0].record.attempts = 2;
    full.verdicts.insert(16, HostEvidence::Lost);
    let one = bounds_with(|config| config.population_cap = 1);
    assert_eq!(reserves(&full.plan_under(&one)), [(1, 12)]);
}

#[test]
fn the_zone_host_hold_counts_active_hosts_read_lost_or_unknown() {
    let held = |state: DirectoryState, verdict: HostEvidence| {
        let mut scene = hold_scene(0);
        for n in (OWNER + 1..OWNER + 15).rev().take(5) {
            let entry = scene.listing.hosts.iter_mut().find(|e| e.host.get() == n);
            entry.unwrap().state = state;
            scene.verdicts.insert(n, verdict);
        }
        let plan = scene.plan();
        assert_eq!(reserves(&plan).is_empty(), plan.holds.zone_host);
        plan.holds.zone_host
    };
    assert!(held(DirectoryState::Active, HostEvidence::Unknown));
    assert!(held(DirectoryState::Active, HostEvidence::Lost));
    assert!(!held(DirectoryState::Draining, HostEvidence::Unknown));
    assert!(!held(DirectoryState::Retired, HostEvidence::Lost));
}

#[test]
fn a_slot_without_its_shard_record_counts_in_flight_and_reads_unobserved() {
    let absent = |inflight_max: u32| {
        let mut scene = Scene::standby_needs(2);
        scene.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
        let mut observation = scene.observation();
        observation.zone.as_mut().unwrap().shards[0].records = Ok(None);
        plan_with(
            &observation,
            &bounds_with(|config| config.enroll_inflight_max = inflight_max),
        )
    };
    let plan = absent(4);
    assert_eq!(plan.inflight, 1);
    let unobserved = ShardState::Unobserved(Source::Store(StoreError::Absent));
    assert_eq!(
        state_of(&plan, 1),
        (unobserved, Some(Blocker::StoreUnavailable))
    );
    let reserved: Vec<u32> = reserves(&plan).iter().map(|(shard, _)| *shard).collect();
    assert_eq!(reserved, [2]);
    assert!(reserves(&absent(1)).is_empty());
    let mut tight = Scene::standby_needs(2);
    tight
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    tight.listing.host_roles_max = 2;
    tight.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
    let mut observation = tight.observation();
    observation.zone.as_mut().unwrap().shards[0].records = Ok(None);
    let plan = plan_with(&observation, &bounds_with(|_| {}));
    assert_eq!(
        state_of(&plan, 2),
        (ShardState::NoCandidate, Some(Blocker::PerHostCap))
    );
    let mut fresh = Scene::standby_needs(2);
    let mut observation = fresh.observation();
    observation.zone.as_mut().unwrap().shards[0].records = Ok(None);
    let plan = plan_with(&observation, &bounds_with(|_| {}));
    assert_eq!(state_of(&plan, 1), (ShardState::Initial, None));
    assert_eq!(reserves(&plan), [(2, 12)]);
    fresh.shards[1].judgement.health = Some(Health::Lost);
    fresh.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
    let mut observation = fresh.observation();
    observation.zone.as_mut().unwrap().shards[0].records = Ok(None);
    let plan = plan_with(&observation, &bounds_with(|_| {}));
    assert_eq!(
        state_of(&plan, 2),
        (ShardState::LossUnconfirmed, Some(Blocker::LossUnconfirmed))
    );
    fresh.census = Census::empty(ZONE);
    let open = ShardState::Replacing {
        phase: crate::failover::loss::Phase::Open,
    };
    assert_eq!(state_of(&fresh.plan(), 2), (open, None));
}

/// SLOT-HOST: a census entry at the record's own target that names another host than the live named standby holds
/// an in-flight unit and resumes its host's enrollment, so the shard reads `Enrolling`; its `protected` flag follows
/// the named standby and stays true. When the named standby is lost, the entry holds the same unit and the flag
/// reads false.
#[test]
fn a_slot_beside_a_live_named_standby_resumes_its_hosts_enrollment() {
    let mut scene = Scene::new(vec![
        records(1, OWNER, Some(13), volume_record()),
        records(2, OWNER, None, volume_record()),
    ]);
    scene.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
    let one = bounds_with(|config| config.enroll_inflight_max = 1);
    let recording = |host: u64| Step::RecordAttach {
        shard: shard(1),
        host: crate::failover::sim::host(host),
        target: Target::of(&scene.shards[0].record),
    };
    let plan = scene.plan_under(&one);
    assert_eq!(plan.inflight, 1);
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Reserved,
        host: host(12),
    };
    assert_eq!(state_of(&plan, 1), (enrolling, None));
    assert!(plan.shards[0].protected);
    assert_eq!(plan.steps, [recording(12)]);
    scene.verdicts.insert(13, HostEvidence::Lost);
    let plan = scene.plan_under(&one);
    assert_eq!(plan.inflight, 1);
    assert!(!plan.shards[0].protected);
    assert_eq!(plan.steps, [recording(12)]);
}

/// An ended attach leaves the shard unprotected even when the census lists the named standby and host evidence is
/// `Live`.
#[test]
fn a_named_standby_whose_attach_ended_is_replaced_by_another_candidate() {
    let named = |ended: bool, verdict: HostEvidence| {
        let active = lineage(&[(host(16), c_pair())]);
        let mut scene = Scene::new(vec![records(1, OWNER, Some(16), active)]);
        if ended {
            let active = &mut scene.shards[0].active;
            let (seq, _) = active.latest(host(16)).unwrap();
            let entry = active.events.iter_mut().find(|event| event.seq == seq);
            entry.unwrap().kind = EventKind::Ended;
        }
        scene.census = census_of(&[(scene.shards[0].record, 16)]);
        scene.verdicts.insert(16, verdict);
        scene.plan()
    };
    let plan = named(false, HostEvidence::Live);
    assert_eq!(state_of(&plan, 1), (ShardState::Protected, None));
    assert!(plan.shards[0].protected);
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
    for verdict in [HostEvidence::Live, HostEvidence::Unknown] {
        let plan = named(true, verdict);
        assert!(!plan.shards[0].protected, "{verdict:?}");
        assert_eq!(reserves(&plan), [(1, 12)], "{verdict:?}");
        let enrolling = ShardState::Enrolling {
            need: Need::Standby,
            phase: EnrollPhase::Unreserved,
            host: host(12),
        };
        assert_eq!(state_of(&plan, 1), (enrolling, None), "{verdict:?}");
    }
}

/// A named standby that reads `Live` and whose entry of the active volume is gone or absent keeps its census slot,
/// and the plan records a new attach entry for it.
#[test]
fn a_named_standby_whose_entry_is_gone_or_absent_keeps_its_slot_and_records_a_new_attach() {
    for gone in [false, true] {
        let active = match gone {
            true => lineage(&[(host(16), c_pair())]),
            false => volume_record(),
        };
        let mut scene = Scene::new(vec![unattached(1, OWNER, Some(16), active)]);
        if gone {
            let active = &mut scene.shards[0].active;
            active.pairs.retain(|pair| pair.host != host(16));
            let (seq, _) = active.latest(host(16)).unwrap();
            let entry = active.events.iter_mut().find(|event| event.seq == seq);
            entry.unwrap().kind = EventKind::Gone;
        }
        assert!(scene.shards[0].active.live(host(16)).is_none());
        scene.census = census_of(&[(scene.shards[0].record, 16)]);
        let plan = scene.plan();
        let record = Step::RecordAttach {
            shard: shard(1),
            host: host(16),
            target: Target::of(&scene.shards[0].record),
        };
        assert_eq!(plan.steps, [record], "gone {gone}");
        assert!(!plan.shards[0].protected, "gone {gone}");
    }
}

#[test]
fn a_start_the_window_refuses_leaves_attachment_headroom_to_a_known_start() {
    let tight = |known: VolumeId| {
        let mut scene = Scene::standby_needs(2);
        scene
            .listing
            .hosts
            .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
        let report = report_of(host(12), Gauge::known(1, 2), Gauge::known(0, 2));
        scene.reports.insert(12, report);
        let bounds = bounds_with(|config| config.enroll_inflight_max = 64);
        let mut starts: BTreeMap<_, _> = (100..115)
            .map(|n| ((shard(n), host(12), volume(n)), START))
            .collect();
        starts.insert((shard(2), host(12), known), START);
        plan_at(&scene.observation(), &bounds, START, &starts, false)
    };
    let plan = tight(volume(2));
    assert_eq!(reserves(&plan), [(2, 12)]);
    assert_eq!(plan.starts, [(shard(2), host(12), volume(2))]);
    assert!(reserves(&tight(volume(9))).is_empty());
}

#[test]
fn a_reservation_owes_the_attachment_a_later_reservation_of_the_host_needs() {
    let mut scene = Scene::new(vec![
        records(1, OWNER, None, lineage(&[(host(12), c_pair())])),
        records(2, OWNER, None, volume_record()),
    ]);
    scene
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    let report = report_of(host(12), Gauge::known(1, 2), Gauge::known(0, 2));
    scene.reports.insert(12, report.clone());
    let plan = scene.plan_under(&bounds_with(|config| config.enroll_inflight_max = 64));
    assert_eq!(reserves(&plan), [(1, 12)]);
    assert_eq!(
        state_of(&plan, 2),
        (ShardState::NoCandidate, Some(Blocker::Headroom))
    );
    let population = Population { cap: 64 };
    let first = (population.admit(
        &Census::empty(ZONE),
        &scene.shards[0].record,
        &report,
        Attach::Live,
        |_| None,
        |_| false,
    ))
    .unwrap()
    .unwrap();
    let second = population.admit(
        &first,
        &scene.shards[1].record,
        &report,
        Attach::Open,
        |_| None,
        |_| false,
    );
    assert_eq!(second, Err(crate::failover::standbys::Refusal::Headroom));
    // A host whose report lists shard 1 in the standby role on shard 1's active volume holds that attachment
    // already, so the free slot serves shard 2.
    let mut listed = report;
    let mut standby = super::observe::entry(volume(1).as_str(), 1, record().generation.get(), 1);
    standby.role = Some(crate::failover::report::RecordedRole::Standby);
    listed.entries.push(standby);
    scene.reports.insert(12, listed);
    let plan = scene.plan_under(&bounds_with(|config| config.enroll_inflight_max = 64));
    assert_eq!(reserves(&plan), [(1, 12), (2, 12)]);
}

/// The old-volume twin of [`a_reservation_owes_the_attachment_a_later_reservation_of_the_host_needs`]: a standby
/// entry for shard 1 on a volume other than its active one holds no attachment of that volume, so the reservation of
/// shard 1 still owes host 12's one free slot and shard 2 reads `Headroom`.
#[test]
fn a_standby_entry_on_an_old_volume_leaves_the_reservation_owing_the_attachment() {
    let mut scene = Scene::new(vec![
        records(1, OWNER, None, lineage(&[(host(12), c_pair())])),
        records(2, OWNER, None, volume_record()),
    ]);
    scene
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    let mut report = report_of(host(12), Gauge::known(1, 2), Gauge::known(0, 2));
    let mut standby = super::observe::entry("vol-0a", 1, record().generation.get(), 1);
    standby.role = Some(crate::failover::report::RecordedRole::Standby);
    assert_ne!(standby.volume, scene.shards[0].record.active);
    report.entries.push(standby);
    scene.reports.insert(12, report);
    let plan = scene.plan_under(&bounds_with(|config| config.enroll_inflight_max = 64));
    assert_eq!(reserves(&plan), [(1, 12)]);
    assert_eq!(
        state_of(&plan, 2),
        (ShardState::NoCandidate, Some(Blocker::Headroom))
    );
}

#[test]
fn a_retarget_on_the_same_host_adds_no_census_entry() {
    let mut scene = Scene::standby_needs(2);
    scene
        .listing
        .hosts
        .retain(|entry| [OWNER, 12].contains(&entry.host.get()));
    let slots: Vec<_> = scene.shards.iter().map(|r| (r.record, 12)).collect();
    scene.census = census_of(&slots);
    for records in &mut scene.shards {
        records.record.attempts = 2;
    }
    let bounds = bounds_with(|config| {
        config.enroll_inflight_max = 64;
        config.standbys_per_host_max = 2;
    });
    let plan = scene.plan_under(&bounds);
    assert_eq!(reserves(&plan), [(1, 12), (2, 12)]);
    assert!(releases(&plan).is_empty());
    scene.shards.push(records(3, OWNER, None, volume_record()));
    scene.listing.shards.push(shard_entry(3));
    scene.volumes.push(listed(volume(3), &[]));
    let capped = bounds_with(|config| {
        config.enroll_inflight_max = 64;
        config.population_cap = 3;
    });
    assert_eq!(
        reserves(&scene.plan_under(&capped)),
        [(1, 12), (2, 12), (3, 12)]
    );
}

#[test]
fn a_stale_slot_of_a_lost_host_is_released_by_shard() {
    let mut scene = Scene::standby_needs(2);
    let slots = [(scene.shards[0].record, 16), (scene.shards[1].record, 18)];
    scene.census = census_of(&slots);
    for records in &mut scene.shards {
        records.record.attempts = 2;
    }
    scene.verdicts.insert(16, HostEvidence::Lost);
    scene.verdicts.insert(18, HostEvidence::Lost);
    scene.listing.zone_hold = true;
    let bounds = bounds_with(|_| {});
    let plan = scene.plan();
    assert!(reserves(&plan).is_empty());
    assert_eq!(releases(&plan), [1, 2]);
    let mut reversed = scene.observation();
    reversed.zone.as_mut().unwrap().shards.reverse();
    assert_eq!(plan_with(&reversed, &bounds), plan);
    let warming = plan_at(&scene.observation(), &bounds, START, &BTreeMap::new(), true);
    assert!(warming.steps.is_empty());
    let mut retiring = scene;
    retiring.shards[0].entries = vec![owner_entry(1, |entry| {
        entry.tenure = Some((record().generation, ActivatedEpoch::new(4).unwrap()));
        entry.flip = true;
    })];
    assert_eq!(releases(&retiring.plan()), [2]);
    let mut attached = Scene::standby_needs(1);
    attached.shards[0].active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(16), c_pair())])
    };
    attached.census = census_of(&[(attached.shards[0].record, 16)]);
    attached.shards[0].record.attempts = 2;
    let plan = attached.plan();
    assert_eq!(reserves(&plan), [(1, 16)]);
    assert!(releases(&plan).is_empty());
}

#[test]
fn a_stale_slot_keeps_its_live_incumbent_and_waits_on_an_unknown_one() {
    let stale = |verdict| {
        let mut scene = Scene::standby_needs(1);
        scene.census = census_of(&[(scene.shards[0].record, 16)]);
        scene.shards[0].record.attempts = 2;
        scene.verdicts.insert(16, verdict);
        scene.plan()
    };
    assert_eq!(reserves(&stale(HostEvidence::Live)), [(1, 16)]);
    for verdict in [HostEvidence::Unknown, HostEvidence::Conflict] {
        let plan = stale(verdict);
        assert!(plan.steps.is_empty());
        assert_eq!(
            state_of(&plan, 1),
            (ShardState::NoCandidate, Some(Blocker::LossUnconfirmed))
        );
    }
    assert_eq!(reserves(&stale(HostEvidence::Lost)), [(1, 12)]);
    let mut colored = Scene::standby_needs(1);
    colored.census = census_of(&[(colored.shards[0].record, 13)]);
    colored.shards[0].record.attempts = 2;
    assert_eq!(reserves(&colored.plan()), [(1, 13)]);
    let mut current = Scene::standby_needs(1);
    current.census = census_of(&[(current.shards[0].record, 16)]);
    current.verdicts.insert(16, HostEvidence::Unknown);
    let plan = current.plan();
    assert!(plan.steps.is_empty());
    assert_eq!(plan.inflight, 1);
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::NoCandidate, Some(Blocker::LossUnconfirmed))
    );
}

/// In `OwnerUnknown` or `VolumeImpaired`, incumbent evidence of `Unknown` or `Conflict` keeps the stale slot
/// reserved for that host. `Lost` releases the slot and preserves the shard state.
#[test]
fn a_stale_slot_of_an_unconfirmed_incumbent_stays_whatever_state_the_shard_reads() {
    let stale = |incumbent: HostEvidence, change: fn(&mut Scene)| {
        let mut scene = Scene::standby_needs(1);
        scene.census = census_of(&[(scene.shards[0].record, 16)]);
        scene.shards[0].record.attempts = 2;
        scene.verdicts.insert(16, incumbent);
        change(&mut scene);
        scene.plan()
    };
    let owner_unknown: fn(&mut Scene) = |scene| {
        scene.verdicts.insert(OWNER, HostEvidence::Unknown);
    };
    let impaired: fn(&mut Scene) =
        |scene| scene.shards[0].judgement.health = Some(Health::Impaired);
    let states = [
        (
            owner_unknown,
            (ShardState::OwnerUnknown, Some(Blocker::OwnerNotReady)),
        ),
        (
            impaired,
            (ShardState::VolumeImpaired, Some(Blocker::VolumeImpaired)),
        ),
    ];
    for (change, state) in states {
        for verdict in [HostEvidence::Unknown, HostEvidence::Conflict] {
            let plan = stale(verdict, change);
            assert_eq!(state_of(&plan, 1), state);
            assert!(plan.steps.is_empty(), "{verdict:?}: {:?}", plan.steps);
        }
        let plan = stale(HostEvidence::Lost, change);
        assert_eq!(state_of(&plan, 1), state);
        assert_eq!(releases(&plan), [1]);
    }
}

/// A slot at a stale target stays out of the in-flight count, and the assessment names its live incumbent while the
/// in-flight limit withholds the reservation.
#[test]
fn a_stale_slot_holds_no_in_flight_unit_and_its_assessment_names_the_incumbent() {
    let mut scene = Scene::standby_needs(2);
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    scene.shards[0].record.attempts = 2;
    let plan = scene.plan();
    assert_eq!(plan.inflight, 0);
    assert_eq!(reserves(&plan), [(1, 16), (2, 12)]);
    scene.census = census_of(&[(scene.shards[1].record, 18)]);
    let earlier = ShardRecord {
        attempts: 1,
        ..scene.shards[0].record
    };
    let slots = [(earlier, 16), (scene.shards[1].record, 18)];
    scene.census = census_of(&slots);
    let one = bounds_with(|config| config.enroll_inflight_max = 1);
    let plan = scene.plan_under(&one);
    assert_eq!(plan.inflight, 1);
    assert!(reserves(&plan).is_empty());
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Unreserved,
        host: host(16),
    };
    assert_eq!(state_of(&plan, 1), (enrolling, None));
}

#[test]
fn a_current_slot_of_a_lost_host_is_reserved_for_another_candidate() {
    let mut scene = Scene::standby_needs(1);
    scene.shards[0].active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(16), c_pair())])
    };
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    scene.verdicts.insert(16, HostEvidence::Lost);
    let unbound = scene.plan();
    assert_eq!(unbound.steps.len(), 1, "{:?}", unbound.steps);
    assert_eq!(reserves(&unbound), [(1, 12)]);
    bind(&mut scene.shards[0].active, 16);
    let plan = scene.plan();
    assert_eq!(plan.inflight, 0);
    assert_eq!(reserves(&plan), [(1, 12)]);
    let end = Step::End {
        shard: shard(1),
        host: host(16),
    };
    assert_eq!(plan.steps.len(), 2, "{:?}", plan.steps);
    assert_eq!(plan.steps[0], end);
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Unreserved,
        host: host(12),
    };
    assert_eq!(state_of(&plan, 1), (enrolling, None));
}

/// A release follows the loss evidence and the recorded attach of the slot's host: a lost host's stale slot is
/// released though the volume record still shows its attach, and a live host's recorded attach keeps its stale slot
/// while its reservation is withheld.
#[test]
fn a_named_standby_that_attached_again_enrolls_at_its_slot_before_it_protects() {
    let scene = || Scene::new(vec![records(1, OWNER, Some(13), volume_record())]);
    let plain = scene().plan();
    assert_eq!(state_of(&plain, 1).0, ShardState::Protected);
    let mut slotted = scene();
    slotted.census = census_of(&[(slotted.shards[0].record, 13)]);
    let plan = slotted.plan();
    let found = plan
        .shards
        .iter()
        .find(|entry| entry.shard == shard(1))
        .unwrap();
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Recorded,
        host: host(13),
    };
    assert_eq!((found.state, found.protected), (enrolling, false));
    let attach = |step: &Step| matches!(*step, Step::Attach { host: at, .. } if at == host(13));
    assert!(plan.steps.iter().any(attach), "{:?}", plan.steps);
    assert!(reserves(&plan).is_empty());

    let mut owner_bumped = slotted;
    owner_bumped.shards[0].record.attempts += 1;
    let plan = owner_bumped.plan();
    let found = plan
        .shards
        .iter()
        .find(|entry| entry.shard == shard(1))
        .unwrap();
    let reserving = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Unreserved,
        host: host(13),
    };
    assert_eq!((found.state, found.protected), (reserving, false));
    assert_eq!(reserves(&plan), [(1, 13)]);
}

#[test]
fn a_candidate_needing_a_new_entry_is_passed_over_when_listed_or_unlisted_volume() {
    let mut listed_first = Scene::standby_needs(1);
    listed_first.volumes = vec![listed(volume(1), &[12])];
    let chosen = reserves(&listed_first.plan());
    assert_eq!(chosen.len(), 1);
    assert_ne!(chosen[0].1, 12);
    let mut unlisted = Scene::standby_needs(1);
    unlisted.volumes.clear();
    let plan = unlisted.plan();
    assert!(reserves(&plan).is_empty());
    assert_eq!(
        state_of(&plan, 1),
        (
            ShardState::NoCandidate,
            Some(Blocker::ControlPlaneUnavailable)
        )
    );
    let mut reserved = Scene::standby_needs(1);
    reserved.census = census_of(&[(reserved.shards[0].record, 12)]);
    reserved.volumes.clear();
    let plan = reserved.plan();
    let recording = |step: &Step| matches!(step, Step::RecordAttach { .. });
    assert!(!plan.steps.iter().any(recording), "{:?}", plan.steps);
    assert_eq!(state_of(&plan, 1).1, Some(Blocker::ControlPlaneUnavailable));
}

#[test]
fn a_live_attached_candidate_below_the_era_floor_keeps_its_place() {
    let mut scene = Scene::standby_needs(1);
    scene.shards[0]
        .active
        .push(EventKind::Attach, host(12), ERA)
        .unwrap();
    scene.reports.get_mut(&12).unwrap().host.build.era = crate::failover::records::MIN_ERA - 1;
    assert_eq!(reserves(&scene.plan()), [(1, 12)]);
}

#[test]
fn a_stale_bare_slot_of_a_live_host_is_not_released() {
    let mut scene = Scene::standby_needs(1);
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    scene.shards[0].record.attempts = 2;
    scene.listing.zone_hold = true;
    let plan = scene.plan();
    assert!(reserves(&plan).is_empty());
    assert!(releases(&plan).is_empty(), "{:?}", plan.steps);
    scene.verdicts.insert(16, HostEvidence::Lost);
    assert_eq!(releases(&scene.plan()), [1]);
}

#[test]
fn a_release_weighs_the_incumbents_loss_before_its_recorded_attach() {
    let stale = |verdict: HostEvidence| {
        let mut scene = Scene::standby_needs(1);
        scene.shards[0].active = VolumeRecord {
            volume: volume(1),
            ..lineage(&[(host(16), c_pair())])
        };
        scene.census = census_of(&[(scene.shards[0].record, 16)]);
        scene.shards[0].record.attempts = 2;
        scene.verdicts.insert(16, verdict);
        scene
    };
    let mut lost = stale(HostEvidence::Lost);
    lost.listing.zone_hold = true;
    let plan = lost.plan();
    assert!(reserves(&plan).is_empty());
    assert_eq!(releases(&plan), [1]);
    let mut silent = stale(HostEvidence::Live);
    silent.reports.remove(&16);
    let plan = silent.plan();
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::NoCandidate, Some(Blocker::Headroom))
    );
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
    // A shard that reads `NoCandidate` for a cause other than an unconfirmed loss releases its lost host's slot.
    let mut alone = stale(HostEvidence::Lost);
    alone
        .listing
        .hosts
        .retain(|entry| [OWNER, 16].contains(&entry.host.get()));
    let plan = alone.plan();
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::NoCandidate, Some(Blocker::NoEligibleHost))
    );
    assert_eq!(releases(&plan), [1]);
    // A takeover by the slot's host ended the slot's enrollment: host 16 owns the shard after the loss of host 11,
    // and its stale slot is released though it holds a live attach.
    let taken = lineage(&[(host(16), c_pair())]);
    let mut owned = Scene::new(vec![records(1, 16, None, taken)]);
    owned.census = census_of(&[(shard_record(1, OWNER, None), 16)]);
    owned.verdicts.insert(OWNER, HostEvidence::Lost);
    owned.listing.zone_hold = true;
    let plan = owned.plan();
    assert!(reserves(&plan).is_empty());
    assert_eq!(releases(&plan), [1]);
}

/// Shard 1's census slot at an earlier target of its record, naming host 16, which reads `incumbent`. Host 16 holds no
/// event of the active volume, or, with `ended`, an attach of it that a recorded detach ended.
fn stale_slot(incumbent: HostEvidence, ended: bool) -> Scene {
    let mut scene = Scene::standby_needs(1);
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    scene.shards[0].record.attempts = 2;
    scene.verdicts.insert(16, incumbent);
    if ended {
        let active = &mut scene.shards[0].active;
        active.push(EventKind::Attach, host(16), 0).unwrap();
        active.push(EventKind::Detach, host(16), 0).unwrap();
        assert!(active.latest(host(16)).is_some() && active.live(host(16)).is_none());
    }
    scene
}

/// A hold or limit preserves the upper bound of one candidate per slot (`ONE-CANDIDATE-PER-SLOT` in
/// `zone_loop::plan`). While `withhold` is in force, the plan keeps the stale slot's live incumbent in place. During
/// that hold or limit, the plan releases a slot whose incumbent is lost or whose attach ended, or reserves it for
/// another host.
fn assert_withheld_slot_stays(withhold: impl Fn(&mut Scene) -> Plan) {
    let mut held = stale_slot(HostEvidence::Live, false);
    let plan = withhold(&mut held);
    assert!(
        reserves(&plan).iter().all(|&(at, _)| at != 1),
        "{:?}",
        plan.steps
    );
    assert!(!releases(&plan).contains(&1), "{:?}", plan.steps);
    for (incumbent, ended) in [(HostEvidence::Lost, false), (HostEvidence::Live, true)] {
        let mut moved = stale_slot(incumbent, ended);
        let plan = withhold(&mut moved);
        let elsewhere = reserves(&plan).iter().any(|&(at, to)| at == 1 && to != 16);
        assert!(
            releases(&plan).contains(&1) || elsewhere,
            "{incumbent:?}, ended {ended}: {:?}",
            plan.steps
        );
    }
}

/// FP-LOOP-07: the release pass drops a stale slot whose host is the owner, reads `Lost`, or has an ended attach of
/// the active volume and no live one, under a hold too; a live host with no attach entry, and a host that reads
/// unknown or in conflict, keep the slot.
#[test]
fn a_stale_slot_moves_only_for_the_owner_a_lost_host_or_an_ended_attach() {
    let end = |scene: &mut Scene| {
        let active = &mut scene.shards[0].active;
        let seq = active.push(EventKind::Attach, host(16), ERA).unwrap();
        let event = active.events.iter_mut().find(|event| event.seq == seq);
        event.unwrap().kind = EventKind::Ended;
    };
    let owner = |scene: &mut Scene| scene.shards[0].record.owner = host(16);
    let lost = |scene: &mut Scene| {
        scene.verdicts.insert(16, HostEvidence::Lost);
    };
    let ended_held = |scene: &mut Scene| {
        end(scene);
        scene.listing.zone_hold = true;
    };
    let unknown_ended = |scene: &mut Scene| {
        end(scene);
        scene.verdicts.insert(16, HostEvidence::Unknown);
    };
    let live = |_: &mut Scene| {};
    let unknown = |scene: &mut Scene| {
        scene.verdicts.insert(16, HostEvidence::Unknown);
    };
    let conflict = |scene: &mut Scene| {
        scene.verdicts.insert(16, HostEvidence::Conflict);
    };
    type Row<'a> = (&'a str, &'a dyn Fn(&mut Scene), bool);
    let rows: [Row<'_>; 7] = [
        ("owner", &owner, true),
        ("lost", &lost, true),
        ("ended under the operator hold", &ended_held, true),
        ("ended, unknown", &unknown_ended, true),
        ("live with no attach entry", &live, false),
        ("unknown", &unknown, false),
        ("conflict", &conflict, false),
    ];
    for (what, change, moves) in rows {
        let mut scene = stale_slot(HostEvidence::Live, false);
        change(&mut scene);
        let plan = scene.plan();
        let elsewhere = reserves(&plan).iter().any(|&(at, to)| at == 1 && to != 16);
        assert_eq!(
            releases(&plan).contains(&1) || elsewhere,
            moves,
            "{what}: {:?}",
            plan.steps
        );
        if !moves {
            assert!(!releases(&plan).contains(&1), "{what}: {:?}", plan.steps);
        }
    }
}

#[test]
fn the_operator_hold_keeps_a_stale_slot_of_a_live_incumbent() {
    assert_withheld_slot_stays(|scene| {
        scene.listing.zone_hold = true;
        let plan = scene.plan();
        assert!(plan.holds.operator);
        plan
    });
    let plan = stale_slot(HostEvidence::Live, false).plan();
    assert_eq!(reserves(&plan), [(1, 16)]);
    assert!(releases(&plan).is_empty());
}

#[test]
fn unknown_active_volume_health_keeps_a_stale_slot_of_a_live_incumbent() {
    assert_withheld_slot_stays(|scene| {
        scene.shards[0].judgement.health = None;
        scene.plan()
    });
    let mut paused = stale_slot(HostEvidence::Live, false);
    paused.shards[0].judgement.health = None;
    let waiting = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Unreserved,
        host: host(16),
    };
    let unknown = Some(Blocker::ControlPlaneUnavailable);
    assert_eq!(state_of(&paused.plan(), 1), (waiting, unknown));
    paused.shards[0].judgement.health = Some(Health::Available);
    let plan = paused.plan();
    assert_eq!(reserves(&plan), [(1, 16)]);
    assert!(releases(&plan).is_empty());
}

#[test]
fn the_zone_host_hold_keeps_a_stale_slot_of_a_live_incumbent() {
    assert_withheld_slot_stays(|scene| {
        for n in [12, 13, 14, 15, 17] {
            scene.verdicts.insert(n, HostEvidence::Unknown);
        }
        let plan = scene.plan();
        assert!(plan.holds.zone_host && !plan.holds.operator);
        plan
    });
}

/// The limits that withhold a reservation: the in-flight limit, the attach start window, the host roles limit
/// (`PerHostCap`) and the incumbent's headroom (`Headroom`). A live incumbent whose latest event is a detach reads
/// `AttachClosed` in place of `Headroom`, because `Attach::of` closes a host's attach after its detach.
#[test]
fn a_limit_keeps_a_stale_slot_of_a_live_incumbent() {
    assert_withheld_slot_stays(|scene| {
        scene.shards.push(records(2, OWNER, None, volume_record()));
        scene.listing.shards.push(shard_entry(2));
        scene.volumes.push(listed(volume(2), &[]));
        let slots = [
            (
                ShardRecord {
                    attempts: 1,
                    ..scene.shards[0].record
                },
                16,
            ),
            (scene.shards[1].record, 18),
        ];
        scene.census = census_of(&slots);
        let plan = scene.plan_under(&bounds_with(|config| config.enroll_inflight_max = 1));
        assert_eq!(plan.inflight, 1);
        plan
    });
    assert_withheld_slot_stays(|scene| {
        let bounds = bounds_with(|config| config.attach_starts_per_window = 1);
        let earlier = (shard(9), host(12), volume(9));
        let starts = BTreeMap::from([(earlier, START)]);
        plan_at(&scene.observation(), &bounds, START + S, &starts, false)
    });
    assert_withheld_slot_stays(|scene| {
        scene.shards.push(records(2, 16, None, volume_record()));
        scene.listing.shards.push(shard_entry(2));
        scene.volumes.push(listed(volume(2), &[]));
        scene.listing.host_roles_max = 1;
        let plan = scene.plan();
        if scene.verdicts[&16] == HostEvidence::Live {
            assert_eq!(
                state_of(&plan, 1),
                (ShardState::NoCandidate, Some(Blocker::PerHostCap))
            );
        }
        plan
    });
    assert_withheld_slot_stays(|scene| {
        scene.reports.remove(&16);
        let plan = scene.plan();
        if scene.verdicts[&16] == HostEvidence::Live {
            let detached = scene.shards[0].active.latest(host(16)).is_some();
            let expected = match detached {
                true => (ShardState::Closed, Some(Blocker::AttachClosed)),
                false => (ShardState::NoCandidate, Some(Blocker::Headroom)),
            };
            assert_eq!(state_of(&plan, 1), expected, "detached {detached}");
        }
        plan
    });
}

/// UNKNOWN-BLOCKS: a host outside the zone's view reads unknown in every role, so the plan waits on it.
#[test]
fn a_role_host_outside_the_zone_view_reads_unknown_and_blocks() {
    let standby = Scene::new(vec![records(1, OWNER, Some(99), volume_record())]);
    let plan = standby.plan();
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::StandbyUnknown, Some(Blocker::LossUnconfirmed))
    );
    assert!(plan.steps.is_empty());
    let owner = Scene::new(vec![records(1, 99, None, volume_record())]);
    let plan = owner.plan();
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::OwnerUnknown, Some(Blocker::OwnerNotReady))
    );
    assert!(plan.steps.is_empty());
    let mut incumbent = Scene::standby_needs(1);
    incumbent.census = census_of(&[(incumbent.shards[0].record, 99)]);
    let plan = incumbent.plan();
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::NoCandidate, Some(Blocker::LossUnconfirmed))
    );
    assert!(plan.steps.is_empty());
    assert_eq!(plan.inflight, 1);
}

/// A shard without a slot reads `CensusFull` at a full census from its assessment, before the in-flight limit ends
/// the plan's admissions.
#[test]
fn a_full_census_is_named_while_the_in_flight_limit_admits_nothing() {
    let mut scene = Scene::standby_needs(2);
    scene.census = census_of(&[(scene.shards[1].record, 12)]);
    let bounds = bounds_with(|config| {
        config.population_cap = 1;
        config.enroll_inflight_max = 1;
    });
    let plan = scene.plan_under(&bounds);
    assert_eq!(plan.inflight, 1);
    assert!(reserves(&plan).is_empty());
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::NoCandidate, Some(Blocker::CensusFull))
    );
}

/// A fresh-host need follows the loss of the owner, so the placement filter is off and a host of the lost owner's
/// partition and color is its candidate.
#[test]
fn a_fresh_need_takes_a_host_of_the_lost_owners_partition_and_color() {
    let mut scene = Scene::new(vec![unattached(1, 13, Some(15), volume_record())]);
    scene
        .listing
        .hosts
        .retain(|entry| [13, 15, 19].contains(&entry.host.get()));
    scene.verdicts.insert(13, HostEvidence::Lost);
    scene.verdicts.insert(15, HostEvidence::Lost);
    let placement = |scene: &Scene, number: u64| {
        let entry = scene.listing.hosts.iter().find(|e| e.host == host(number));
        entry.unwrap().placement
    };
    assert_eq!(placement(&scene, 13), placement(&scene, 19));
    let plan = scene.plan();
    assert_eq!(reserves(&plan), [(1, 19)]);
    let enrolling = ShardState::Enrolling {
        need: Need::Fresh,
        phase: EnrollPhase::Unreserved,
        host: host(19),
    };
    assert_eq!(state_of(&plan, 1), (enrolling, None));
}

/// ORDER: among steps in flight a fresh-host need comes first, then shard number.
#[test]
fn in_flight_steps_order_by_need_then_shard() {
    let mut scene = Scene::new(vec![
        records(1, OWNER, None, volume_record()),
        unattached(2, 13, Some(15), volume_record()),
        records(3, OWNER, None, volume_record()),
    ]);
    scene.verdicts.insert(13, HostEvidence::Lost);
    scene.verdicts.insert(15, HostEvidence::Lost);
    let slots = [
        (scene.shards[0].record, 12),
        (shard_record(2, 13, None), 14),
        (scene.shards[2].record, 16),
    ];
    scene.census = census_of(&slots);
    let plan = scene.plan();
    let recorded: Vec<(u32, u64)> = (plan.steps.iter())
        .map(|step| match *step {
            Step::RecordAttach { shard, host, .. } => (shard.get(), host.get()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(recorded, [(2, 14), (1, 12), (3, 16)]);
}

/// The zone host hold needs more lost or unknown hosts than the largest partition holds, counted over the hosts
/// the directory has not retired.
#[test]
fn the_zone_host_hold_needs_more_bad_hosts_than_the_largest_partition_holds() {
    let scene = |unknown: usize, state: DirectoryState| {
        let mut scene = hold_scene(unknown);
        for n in [12, 13, 14, 15, 17] {
            let entry = scene.listing.hosts.iter_mut().find(|e| e.host.get() == n);
            entry.unwrap().state = state;
            if state == DirectoryState::Retired {
                scene.verdicts.insert(n, HostEvidence::Lost);
            }
        }
        let observation = scene.observation();
        let directory = &observation.zone.as_ref().unwrap().directory;
        assert_eq!(directory.largest_partition(), 3);
        let unknown = (scene.verdicts.values())
            .filter(|verdict| **verdict == HostEvidence::Unknown)
            .count();
        (scene.plan().holds.zone_host, unknown)
    };
    // Three unknown hosts of eleven active ones exceed a quarter and equal the largest partition: the hold stays off.
    assert_eq!(scene(3, DirectoryState::Draining), (false, 3));
    // Five retired hosts read lost and stay out of the count.
    assert_eq!(scene(3, DirectoryState::Retired), (false, 3));
    assert_eq!(scene(4, DirectoryState::Draining), (true, 4));
}

#[test]
fn a_slot_or_volume_that_admits_no_reservation_reads_closed() {
    let full = lineage(&[(c_host(), c_pair()), (host(222), c_pair())]);
    let mut closed = Scene::new(vec![records(1, OWNER, None, full)]);
    closed.census = census_of(&[(closed.shards[0].record, 12)]);
    bind(&mut closed.shards[0].active, c_host().get());
    let plan = closed.plan();
    let shut = (ShardState::Closed, Some(Blocker::AttachClosed));
    assert_eq!(state_of(&plan, 1), shut);
    assert_eq!(closed_of(&plan, 1), Some(Closed::LiveCap));
    let end = Step::End {
        shard: shard(1),
        host: c_host(),
    };
    assert_eq!(plan.steps, [end]);
    assert_eq!(plan.inflight, 1);
    let mut open = Scene::standby_needs(1);
    open.census = census_of(&[(open.shards[0].record, 12)]);
    let recording = |step: &Step| matches!(step, Step::RecordAttach { .. });
    assert!(open.plan().steps.iter().any(recording));
    let mut retired = Scene::standby_needs(1);
    retired.shards[0].active.state = VolumeState::Retired;
    let plan = retired.plan();
    assert_eq!(state_of(&plan, 1), shut);
    assert_eq!(
        closed_of(&plan, 1),
        None,
        "a volume no census reservation accepts names no bound"
    );
    assert!(plan.steps.is_empty());
    // The slot host 16 is not the lowest candidate: 12 stays open, so only the slot host's own bound closes the
    // shard, and the same volume with no slot reserves 12.
    let mut detached = Scene::standby_needs(1);
    let volume = &mut detached.shards[0].active;
    volume.push(EventKind::Attach, host(16), ERA).unwrap();
    volume.push(EventKind::Detach, host(16), ERA).unwrap();
    let unslotted = detached.plan();
    assert_eq!(closed_of(&unslotted, 1), None);
    assert_eq!(reserves(&unslotted), [(1, 12)]);
    detached.census = census_of(&[(detached.shards[0].record, 16)]);
    let plan = detached.plan();
    assert_eq!(state_of(&plan, 1), shut);
    assert_eq!(
        closed_of(&plan, 1),
        Some(Closed::OwnEntry),
        "the slot host's latest detach closes its attach while it stays the host's latest event"
    );
}

/// With no census slot and every candidate closed, the plan names the bound of the lowest-numbered candidate that
/// reached the attach check. The owner and two hosts outside the directory hold three live attaches, so each of
/// the candidates 12, 16 and 18 reads `LiveCap` unless its own latest detach reads `OwnEntry` first: a detach of 12
/// gives `OwnEntry` and a detach of 16 gives 12's `LiveCap`.
#[test]
fn a_closed_shard_names_the_lowest_candidate_s_bound() {
    let cause = |detached: u64| {
        let mut scene = Scene::standby_needs(1);
        let volume = &mut scene.shards[0].active;
        for outside in [50, 51] {
            volume.push(EventKind::Attach, host(outside), ERA).unwrap();
        }
        volume.push(EventKind::Attach, host(detached), ERA).unwrap();
        volume.push(EventKind::Detach, host(detached), ERA).unwrap();
        assert_eq!(volume.live_hosts().count(), 3);
        let plan = scene.plan();
        assert_eq!(
            state_of(&plan, 1),
            (ShardState::Closed, Some(Blocker::AttachClosed))
        );
        closed_of(&plan, 1)
    };
    assert_eq!(cause(12), Some(Closed::OwnEntry));
    assert_eq!(cause(16), Some(Closed::LiveCap));
}

/// Admission's second choice names the bound of the candidates its tally leaves. Shard 2's volume holds live attaches
/// of the owner, host 12 and a host outside the directory, and host 16's latest event is a detach, so 12 reads
/// `Live`, 16 `OwnEntry` and 18 `LiveCap`. Under one standby per host, shard 1's reservation of 12 removes 12 from
/// shard 2's second choice, which reads closed under 16's `OwnEntry`; under two per host both shards reserve 12.
#[test]
fn admission_names_the_bound_of_the_candidates_its_tally_leaves() {
    let mut scene = Scene::standby_needs(2);
    let volume = &mut scene.shards[1].active;
    for live in [12, 50] {
        volume.push(EventKind::Attach, host(live), ERA).unwrap();
    }
    volume.push(EventKind::Attach, host(16), ERA).unwrap();
    volume.push(EventKind::Detach, host(16), ERA).unwrap();
    let plan = |per_host: u32| {
        scene.plan_under(&bounds_with(|config| {
            config.enroll_inflight_max = 64;
            config.standbys_per_host_max = per_host;
        }))
    };
    let one = plan(1);
    assert_eq!(reserves(&one), [(1, 12)]);
    assert_eq!(
        state_of(&one, 2),
        (ShardState::Closed, Some(Blocker::AttachClosed))
    );
    assert_eq!(closed_of(&one, 2), Some(Closed::OwnEntry));
    let two = plan(2);
    assert_eq!(reserves(&two), [(1, 12), (2, 12)]);
    assert_eq!(closed_of(&two, 2), None);
}

/// The bound the plan names for shard `number` in the closed state.
fn closed_of(plan: &Plan, number: u32) -> Option<Closed> {
    let found = plan
        .shards
        .iter()
        .find(|entry| entry.shard == shard(number));
    found.unwrap().closed
}

/// `volume` with an ended entry of host `h` bound to its instance and holding its recorded pair, as an end leaves it
/// before the owner drops the pair.
fn pinned_ended(volume: &mut VolumeRecord, h: u64) {
    let seq = volume.push(EventKind::Attach, host(h), ERA).unwrap();
    volume.pairs.push(RecordedPair {
        host: host(h),
        pair: c_pair(),
        attach: seq,
    });
    let entry = volume
        .events
        .iter_mut()
        .find(|event| event.seq == seq)
        .unwrap();
    entry.kind = EventKind::Ended;
    entry.instance = Some(instance(h));
}

#[test]
fn a_full_volume_ends_a_third_attach_only_when_its_end_admits_the_candidate() {
    let full = || {
        let mut volume = lineage(&[(c_host(), c_pair()), (host(222), c_pair())]);
        bind(&mut volume, c_host().get());
        Scene::new(vec![records(1, OWNER, None, volume)])
    };
    let end = Step::End {
        shard: shard(1),
        host: c_host(),
    };
    let shut = (ShardState::Closed, Some(Blocker::AttachClosed));
    let open = full().plan();
    assert_eq!(state_of(&open, 1), shut);
    assert_eq!(open.steps, [end]);
    let mut cramped = full();
    for n in 12..=20 {
        let report = report_of(host(n), Gauge::known(0, 64), Gauge::known(2, 2));
        cramped.reports.insert(n, report);
    }
    let plan = cramped.plan();
    assert_eq!(state_of(&plan, 1), shut);
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
    let capped = full().plan_under(&bounds_with(|c| c.owner.registrant_max = 3));
    assert_eq!(capped.steps, [end]);
    let mut tight = full();
    pinned_ended(&mut tight.shards[0].active, 223);
    let tight = tight.plan_under(&bounds_with(|c| c.owner.registrant_max = 3));
    assert_eq!(state_of(&tight, 1), shut);
    assert!(tight.steps.is_empty(), "{:?}", tight.steps);
    let mut held = full();
    held.listing.zone_hold = true;
    assert!(held.plan().steps.is_empty());
    let mut unknown = full();
    unknown.shards[0].judgement.health = None;
    assert!(unknown.plan().steps.is_empty());
    let unbound = |bound: &[u64]| {
        let mut volume = lineage(&[(c_host(), c_pair()), (host(222), c_pair())]);
        for &number in bound {
            bind(&mut volume, number);
        }
        Scene::new(vec![records(1, OWNER, None, volume)]).plan()
    };
    assert!(unbound(&[]).steps.is_empty());
    let later = Step::End {
        shard: shard(1),
        host: host(222),
    };
    assert_eq!(unbound(&[222]).steps, [later]);
    let mut slotted = full();
    slotted.census = census_of(&[(slotted.shards[0].record, 12)]);
    assert_eq!(slotted.plan().steps, [end]);
    let mut pinned = full();
    pinned.census = census_of(&[(pinned.shards[0].record, 12)]);
    pinned_ended(&mut pinned.shards[0].active, 223);
    let shut_slot = pinned.plan_under(&bounds_with(|c| c.owner.registrant_max = 3));
    assert!(shut_slot.steps.is_empty(), "{:?}", shut_slot.steps);
    slotted.volumes = vec![listed(volume(1), &[12])];
    assert!(slotted.plan().steps.is_empty());
}

#[test]
fn a_full_volume_ends_a_live_third_host_without_headroom_for_a_candidate_with_room() {
    let mut volume = lineage(&[(host(12), c_pair()), (host(222), c_pair())]);
    bind(&mut volume, 12);
    let mut scene = Scene::new(vec![records(1, OWNER, None, volume)]);
    let cramped = report_of(host(12), Gauge::known(0, 64), Gauge::known(2, 2));
    scene.reports.insert(12, cramped);
    let plan = scene.plan();
    let end = Step::End {
        shard: shard(1),
        host: host(12),
    };
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::NoCandidate, Some(Blocker::Headroom))
    );
    assert_eq!(plan.steps, [end]);
    for n in 13..=20 {
        let report = report_of(host(n), Gauge::known(0, 64), Gauge::known(2, 2));
        scene.reports.insert(n, report);
    }
    assert!(scene.plan().steps.is_empty());
}

#[test]
fn a_slot_host_whose_entry_is_gone_records_a_new_attach() {
    let mut scene = Scene::standby_needs(1);
    let mut active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(16), c_pair())])
    };
    bind(&mut active, 16);
    active.pairs.retain(|pair| pair.host != host(16));
    let seq = active.live(host(16)).unwrap();
    let event = active.events.iter_mut().find(|event| event.seq == seq);
    event.unwrap().kind = EventKind::Gone;
    scene.shards[0].active = active;
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    let plan = scene.plan();
    let record = Step::RecordAttach {
        shard: shard(1),
        host: host(16),
        target: Target::of(&scene.shards[0].record),
    };
    assert_eq!(plan.steps, [record]);
    assert_eq!(plan.inflight, 1);
    let at = scene.listing.hosts.iter().position(|e| e.host == host(16));
    scene.listing.hosts[at.unwrap()].state = DirectoryState::Draining;
    let draining = scene.plan();
    assert_eq!(draining.inflight, 0);
    let moved = reserves(&draining);
    assert!(moved.len() == 1 && moved[0].1 != 16, "{:?}", draining.steps);
    for entry in &mut scene.listing.hosts {
        if entry.host != host(OWNER) && entry.host != host(16) {
            entry.state = DirectoryState::Draining;
        }
    }
    let alone = scene.plan();
    let recording = |step: &Step| matches!(step, Step::RecordAttach { .. });
    assert!(!alone.steps.iter().any(recording), "{:?}", alone.steps);
}

#[test]
fn an_ended_role_host_takes_no_detach_or_release_and_a_non_role_twin_does() {
    let scene = |standby: Option<u64>, shown: bool| {
        let mut active = VolumeRecord {
            volume: volume(1),
            ..lineage(&[(host(13), c_pair())])
        };
        bind(&mut active, 13);
        active.pairs.retain(|pair| pair.host != host(13));
        let seq = active.live(host(13)).unwrap();
        let event = active.events.iter_mut().find(|event| event.seq == seq);
        event.unwrap().kind = EventKind::Ended;
        let mut scene = Scene::new(vec![records(1, OWNER, standby, active)]);
        if shown {
            scene.volumes = vec![listed(volume(1), &[13])];
        }
        scene.plan()
    };
    let unwinds = |plan: &Plan| {
        let steps = plan.steps.iter();
        let mine = steps.filter(|step| match step {
            Step::Detach { host: h, .. } | Step::ReleaseAttach { host: h, .. } => *h == host(13),
            _ => false,
        });
        mine.copied().collect::<Vec<Step>>()
    };
    for shown in [true, false] {
        assert!(unwinds(&scene(Some(13), shown)).is_empty(), "{shown}");
    }
    let (shard, host) = (shard(1), host(13));
    assert_eq!(unwinds(&scene(None, true)), [Step::Detach { shard, host }]);
    assert_eq!(
        unwinds(&scene(None, false)),
        [Step::ReleaseAttach { shard, host }]
    );
}

#[test]
fn a_slot_host_ended_or_ending_holds_no_in_flight_unit() {
    let bounds = bounds_with(|c| c.enroll_inflight_max = 1);
    let scene = |kind: Option<EventKind>| {
        let mut scene = Scene::standby_needs(1);
        let mut active = VolumeRecord {
            volume: volume(1),
            ..lineage(&[(host(16), c_pair())])
        };
        bind(&mut active, 16);
        if let Some(kind) = kind {
            active.pairs.retain(|pair| pair.host != host(16));
            let seq = active.live(host(16)).unwrap();
            let event = active.events.iter_mut().find(|event| event.seq == seq);
            event.unwrap().kind = kind;
        } else {
            let at = scene.listing.hosts.iter().position(|e| e.host == host(16));
            scene.listing.hosts[at.unwrap()].state = DirectoryState::Draining;
        }
        scene.shards[0].active = active;
        scene.census = census_of(&[(scene.shards[0].record, 16)]);
        scene
    };
    let ended = scene(Some(EventKind::Ended)).plan_under(&bounds);
    assert_eq!(ended.inflight, 0);
    let moved = reserves(&ended);
    assert!(moved.len() == 1 && moved[0].1 != 16, "{:?}", ended.steps);
    let ending = scene(None).plan_under(&bounds);
    assert_eq!(ending.inflight, 1);
    let end = Step::End {
        shard: shard(1),
        host: host(16),
    };
    assert_eq!(ending.steps[0], end);
    let moved = reserves(&ending);
    assert!(moved.len() == 1 && moved[0].1 != 16, "{:?}", ending.steps);
}

#[test]
fn the_state_precedence_takes_the_first_state_that_holds() {
    let counts = core::cell::RefCell::new(Vec::new());
    let with = |change: &dyn Fn(&mut ShardRecords)| {
        let mut scene = Scene::standby_needs(1);
        change(&mut scene.shards[0]);
        let plan = scene.plan();
        let replace = Step::Replace {
            shard: shard(1),
            target: Target::of(&scene.shards[0].record),
            host: None,
        };
        assert!(plan.steps.iter().all(|step| *step == replace), "{plan:?}");
        counts.borrow_mut().push(plan.steps.len());
        state_of(&plan, 1)
    };
    let lost = |records: &mut ShardRecords| records.judgement.health = Some(Health::Lost);
    let impaired = |records: &mut ShardRecords| records.judgement.health = Some(Health::Impaired);
    let flip = |records: &mut ShardRecords| {
        records.entries = vec![owner_entry(1, |entry| entry.flip = true)];
    };
    let open = ShardState::Replacing {
        phase: crate::failover::loss::Phase::Open,
    };
    let initial = |records: &mut ShardRecords| records.record.attempts = 0;
    assert_eq!(with(&initial), (ShardState::Initial, None));
    assert_eq!(
        with(&|records| {
            initial(records);
            lost(records);
        }),
        (open, None)
    );
    assert_eq!(
        with(&|records| {
            flip(records);
            impaired(records);
        }),
        (
            ShardState::RetirementRequested,
            Some(Blocker::RetirementRequested)
        )
    );
    let held = |records: &mut ShardRecords| {
        records.receipt = Some(crate::failover::loss::Receipt {
            held: true,
            ..receipt()
        });
    };
    let unheld = |records: &mut ShardRecords| records.receipt = Some(receipt());
    let later: [&dyn Fn(&mut ShardRecords); 2] = [&held, &unheld];
    for receipt_of in later {
        assert_eq!(
            with(&|records| {
                flip(records);
                receipt_of(records);
            }),
            (
                ShardState::RetirementRequested,
                Some(Blocker::RetirementRequested)
            )
        );
    }
    assert_eq!(
        with(&|records| {
            held(records);
            lost(records);
        }),
        (ShardState::ReplacementHeld, Some(Blocker::CorrelatedHold))
    );
    assert_eq!(
        with(&|records| {
            records.receipt = Some(receipt());
            impaired(records);
        }),
        (open, None)
    );
    assert_eq!(
        with(&|records| {
            let mut current = receipt();
            current.request.generation = records.record.generation;
            records.receipt = Some(current);
            impaired(records);
        }),
        (ShardState::VolumeImpaired, Some(Blocker::VolumeImpaired))
    );
    assert_eq!(
        with(&|records| {
            let last = ShardGeneration::new(u64::from(u32::MAX) - 1).unwrap();
            records.record.generation = last;
            lost(records);
        }),
        (
            ShardState::ReplacementExhausted,
            Some(Blocker::ReplacementExhausted)
        )
    );
    assert_eq!(
        with(&|records| {
            records.record.standby = Some(host(12));
            impaired(records);
        }),
        (ShardState::VolumeImpaired, Some(Blocker::VolumeImpaired))
    );
    assert_eq!(
        *counts.borrow(),
        [0, 1, 0, 0, 0, 0, 1, 0, 0, 0],
        "a replace step for the lost volume with no receipt and for the open receipt alone"
    );
}

#[test]
fn each_remaining_candidate_filter_excludes_its_host() {
    let blocker = |scene: &Scene| state_of(&scene.plan(), 1);
    let none = |blocker| (ShardState::NoCandidate, Some(blocker));
    assert_eq!(reserves(&only(12).plan()), [(1, 12)]);
    let mut draining = only(12);
    let twelve = draining
        .listing
        .hosts
        .iter_mut()
        .find(|e| e.host == host(12));
    twelve.unwrap().state = DirectoryState::Draining;
    assert_eq!(blocker(&draining), none(Blocker::NoEligibleHost));
    for verdict in [
        HostEvidence::Conflict,
        HostEvidence::Lost,
        HostEvidence::Unknown,
    ] {
        let mut scene = only(12);
        scene.verdicts.insert(12, verdict);
        assert_eq!(
            blocker(&scene),
            none(Blocker::NoEligibleHost),
            "{verdict:?}"
        );
    }
    let mut silent = only(12);
    silent.reports.remove(&12);
    assert_eq!(blocker(&silent), none(Blocker::Headroom));
    let mut recovery = only(12);
    let unavailable = report_of(host(12), Gauge::known(0, 64), Gauge::Unavailable);
    recovery.reports.insert(12, unavailable);
    assert_eq!(blocker(&recovery), none(Blocker::Headroom));
    let tight = report_of(host(12), Gauge::known(1, 2), Gauge::known(0, 2));
    let mut free = only(12);
    free.reports.insert(12, tight.clone());
    assert_eq!(reserves(&free.plan()), [(1, 12)]);
    let mut pending = only(12);
    pending.reports.insert(12, tight.clone());
    pending.census = census_of(&[(shard_record(2, OWNER, None), 12)]);
    assert_eq!(blocker(&pending), none(Blocker::Headroom));
    let mut live = only(12);
    live.reports.insert(
        12,
        report_of(host(12), Gauge::known(2, 2), Gauge::known(0, 2)),
    );
    live.shards[0].active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(12), c_pair())])
    };
    assert_eq!(reserves(&live.plan()), [(1, 12)]);
}

#[test]
fn candidates_rank_by_census_entries_then_free_recovery_slots() {
    let three = || {
        let mut scene = Scene::standby_needs(1);
        scene
            .listing
            .hosts
            .retain(|entry| [OWNER, 12, 18].contains(&entry.host.get()));
        scene
    };
    let mut entries = three();
    entries.census = census_of(&[(shard_record(2, OWNER, None), 12)]);
    assert_eq!(reserves(&entries.plan()), [(1, 18)]);
    let mut recovery = three();
    let roomier = report_of(host(18), Gauge::known(0, 64), Gauge::known(0, 4));
    recovery.reports.insert(18, roomier);
    assert_eq!(reserves(&recovery.plan()), [(1, 18)]);
    // Fewer census entries outrank more free recovery slots.
    let mut both = three();
    both.census = census_of(&[(shard_record(2, OWNER, None), 12)]);
    let roomier = report_of(host(12), Gauge::known(0, 64), Gauge::known(0, 4));
    both.reports.insert(12, roomier);
    assert_eq!(reserves(&both.plan()), [(1, 18)]);
    // The rank reads the free slots: the limit less the slots in use.
    let mut used = three();
    let larger = report_of(host(12), Gauge::known(0, 64), Gauge::known(3, 4));
    used.reports.insert(12, larger);
    assert_eq!(reserves(&used.plan()), [(1, 18)]);
    // A reservation this plan made counts as an entry of its host when the next start ranks its candidates.
    let mut pair = three();
    pair.shards.push(records(2, OWNER, None, volume_record()));
    pair.listing.shards.push(shard_entry(2));
    pair.volumes.push(listed(volume(2), &[]));
    assert_eq!(reserves(&pair.plan()), [(1, 12), (2, 18)]);
}

#[test]
fn new_reservations_prefer_the_owner_with_more_shards_without_a_standby() {
    let scene = Scene::new(vec![
        records(1, 14, None, volume_record()),
        records(2, OWNER, None, volume_record()),
        records(3, OWNER, None, volume_record()),
    ]);
    let one = bounds_with(|config| config.enroll_inflight_max = 1);
    let reserved: Vec<u32> = (reserves(&scene.plan_under(&one)).iter())
        .map(|(shard, _)| *shard)
        .collect();
    assert_eq!(reserved, [2]);
    // The count covers an owner's shards without a live named standby past `E = 0`: shards 4 and 5 name a live
    // standby and shards 6 and 7 are at `E = 0`, so host 14 still counts one.
    let mut shards = scene.shards.clone();
    shards.extend((4..=5).map(|n| records(n, 14, Some(12), volume_record())));
    shards.extend((6..=7).map(|n| records(n, 14, None, volume_record())));
    for records in &mut shards[5..] {
        records.record.attempts = 0;
    }
    let scene = Scene::new(shards);
    let reserved: Vec<u32> = (reserves(&scene.plan_under(&one)).iter())
        .map(|(shard, _)| *shard)
        .collect();
    assert_eq!(reserved, [2]);
}

#[test]
fn every_planned_step_carries_its_shard_record_target() {
    let mut scene = hold_scene(0);
    scene.shards[0].record.generation = ShardGeneration::new(7).unwrap();
    scene.shards[0].record.attempts = 3;
    let plan = scene.plan();
    let fresh = Target {
        generation: ShardGeneration::new(7).unwrap(),
        owner: host(OWNER),
        attempts: 3,
    };
    let enrolled = Target {
        generation: record().generation,
        owner: host(OWNER),
        attempts: 1,
    };
    assert!(plan.steps.iter().any(|step| matches!(
        *step,
        Step::Reserve { shard: at, target, .. } if at == shard(1) && target == fresh
    )));
    let designate = Step::Designate {
        shard: shard(2),
        host: c_host(),
        target: enrolled,
    };
    assert!(plan.steps.contains(&designate));
    let attach = Step::Attach {
        shard: shard(3),
        host: c_host(),
        target: enrolled,
    };
    let record_attach = Step::RecordAttach {
        shard: shard(4),
        host: host(12),
        target: enrolled,
    };
    assert!(plan.steps.contains(&attach) && plan.steps.contains(&record_attach));
    let mut stale = Scene::standby_needs(1);
    stale.shards[0].record.generation = ShardGeneration::new(7).unwrap();
    let older = stale.shards[0].record;
    stale.census = census_of(&[(older, 16)]);
    stale.shards[0].record.attempts = 3;
    let plan = stale.plan();
    let current = Target {
        generation: ShardGeneration::new(7).unwrap(),
        owner: host(OWNER),
        attempts: 3,
    };
    let reserve = Step::Reserve {
        shard: shard(1),
        host: host(16),
        target: current,
    };
    assert_eq!(plan.steps, [reserve]);
    assert_eq!(plan.shards[0].target, Some(Target::of(&older)));
}

#[test]
fn the_operator_hold_keeps_designations_and_withholds_attaches() {
    let kinds = |plan: &Plan| {
        let kind = |step: &Step| match step {
            Step::Reserve { .. } => "reserve",
            Step::RecordAttach { .. } => "record",
            Step::Attach { .. } => "attach",
            Step::Designate { .. } => "designate",
            Step::Release { .. } => "release",
            Step::End { .. } | Step::Detach { .. } | Step::ReleaseAttach { .. } => "reclaim",
            Step::Replace { .. } => "replace",
        };
        let mut kinds: Vec<(u32, &str)> = (plan.steps.iter())
            .map(|step| (step.shard().get(), kind(step)))
            .collect();
        kinds.sort();
        kinds
    };
    let open = hold_scene(0).plan();
    assert_eq!(
        kinds(&open),
        [
            (1, "reserve"),
            (2, "designate"),
            (3, "attach"),
            (4, "record")
        ]
    );
    let order: Vec<u32> = open.steps.iter().map(|step| step.shard().get()).collect();
    assert_eq!(order, [2, 3, 4, 1]);
    let mut live = hold_scene(0);
    live.shards[0].active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(12), c_pair())])
    };
    live.listing.zone_hold = true;
    assert!(reserves(&live.plan()).contains(&(1, 12)));
    let mut held = hold_scene(0);
    held.listing.zone_hold = true;
    let plan = held.plan();
    assert!(plan.holds.operator && !plan.holds.zone_host);
    assert_eq!(kinds(&plan), [(2, "designate")]);
    let bounds = bounds_with(|_| {});
    let warming = plan_at(&held.observation(), &bounds, START, &BTreeMap::new(), true);
    assert!(warming.steps.is_empty());
}

#[test]
fn the_start_window_withholds_new_starts_until_earlier_ones_expire() {
    let mut scene = Scene::standby_needs(20);
    scene.listing.host_roles_max = 64;
    let bounds = bounds_with(|config| {
        config.enroll_inflight_max = 64;
        config.standbys_per_host_max = 64;
    });
    let window = bounds.config().attach_window_us;
    let first = scene.plan_under(&bounds);
    assert_eq!(reserves(&first).len(), 16);
    let starts: BTreeMap<_, _> = first.starts.iter().map(|&start| (start, START)).collect();
    let slots: Vec<_> = (reserves(&first).iter())
        .map(|&(n, at)| (scene.shards[n as usize - 1].record, at))
        .collect();
    scene.census = census_of(&slots);
    let shards = |now_us| {
        let plan = plan_at(&scene.observation(), &bounds, now_us, &starts, false);
        reserves(&plan)
            .iter()
            .map(|(shard, _)| *shard)
            .collect::<Vec<u32>>()
    };
    assert!(shards(START + window - 1).is_empty());
    assert_eq!(shards(START + window), [17, 18, 19, 20]);
}

#[test]
fn completed_enrollments_hold_no_in_flight_slot() {
    let enrolled = || lineage(&[(host(12), c_pair())]);
    let mut shards: Vec<ShardRecords> = (1..=4)
        .map(|n| records(n, OWNER, Some(12), enrolled()))
        .collect();
    shards.push(records(5, OWNER, None, volume_record()));
    let mut scene = Scene::new(shards);
    let slots: Vec<_> = scene.shards[..4].iter().map(|r| (r.record, 12)).collect();
    scene.census = census_of(&slots);
    let plan = scene.plan();
    assert_eq!(plan.inflight, 0);
    let reserved: Vec<u32> = reserves(&plan).iter().map(|(shard, _)| *shard).collect();
    assert_eq!(reserved, [5]);
    assert!(releases(&plan).is_empty());
    assert_eq!(state_of(&plan, 1), (ShardState::Protected, None));
    // A record that names its standby keeps its census entry at a stale target too (CENSUS-COVERS).
    for records in &mut scene.shards[..4] {
        records.record.attempts = 2;
    }
    let plan = scene.plan();
    assert_eq!(plan.inflight, 0);
    assert!(releases(&plan).is_empty());
    assert_eq!(state_of(&plan, 1), (ShardState::Protected, None));
}

/// Surveys every tick from `START` and returns the first survey outside warm-up with its time. Warm-up ends within
/// 16 ticks under the fixture's bounds.
fn warmed(fixture: &mut Fixture) -> (Survey, u64) {
    let ticks = (0..16).map(|step| START + step * 10 * S);
    let mut surveys = ticks.map(|now| (surveyed(fixture, now), now));
    let ended = surveys.find(|(survey, _)| !survey.plan.holds.warm_up);
    ended.expect("warm-up ends within 16 ticks")
}

/// Publishes a fresh report without entries from every host, then surveys once at `now_us`.
pub(super) fn surveyed(fixture: &mut Fixture, now_us: u64) -> Survey {
    for number in 1..=fixture.hosts {
        fixture.publish(number, &[]);
    }
    fixture
        .zone
        .survey(Ok(fixture.directory()), &mut fixture.world, now_us)
}

#[test]
fn the_exposure_clock_follows_the_survey_and_the_directory() {
    let mut fixture = roomy_fixture(6, 2);
    assert_eq!(fixture.zone.deadline(), None);
    surveyed(&mut fixture, START);
    let tick = fixture.zone.bounds.config().tick_us;
    assert_eq!(fixture.zone.deadline(), Some(START + tick));
    surveyed(&mut fixture, START + 50 * S);
    let exposure = |fixture: &Fixture, n, now_us| fixture.zone.survey.exposure.of(shard(n), now_us);
    assert_eq!(exposure(&fixture, 1, START + 50 * S), Some(50 * S));
    let original = fixture.listing.clone().unwrap();
    let mut dropped = original.clone();
    dropped.version = 2;
    dropped.shards.retain(|entry| entry.shard != shard(2));
    fixture.listing = Some(dropped);
    surveyed(&mut fixture, START + 60 * S);
    assert_eq!(exposure(&fixture, 2, START + 60 * S), None);
    assert_eq!(exposure(&fixture, 1, START + 60 * S), Some(60 * S));
    let mut relisted = original.clone();
    relisted.version = 3;
    fixture.listing = Some(relisted);
    surveyed(&mut fixture, START + 70 * S);
    assert_eq!(exposure(&fixture, 2, START + 70 * S), Some(0));
    let mut observed = original.clone();
    observed.version = 4;
    observed.shards.retain(|entry| entry.shard != shard(2));
    fixture.listing = Some(observed);
    let directory = fixture.directory();
    (fixture.zone).observe(Ok(directory), &mut fixture.world, START + 72 * S);
    let mut back = original;
    back.version = 5;
    fixture.listing = Some(back);
    surveyed(&mut fixture, START + 75 * S);
    assert_eq!(exposure(&fixture, 2, START + 75 * S), Some(0));
    let unreachable = crate::failover::zone_loop::sources::Unreachable;
    (fixture.zone).survey(Err(unreachable), &mut fixture.world, START + 80 * S);
    assert_eq!(exposure(&fixture, 1, START + 80 * S), Some(80 * S));
    assert_eq!(fixture.zone.deadline(), Some(START + 80 * S + tick));
    let mut owner = Client::open(fixture.store.clone(), MemLog::default()).unwrap();
    let read = owner.read::<ShardRecord>(Key::Shard(shard(1))).unwrap();
    let standby = host(4);
    owner
        .designate(&read, Target::of(read.value()), standby)
        .unwrap();
    surveyed(&mut fixture, START + 90 * S);
    assert_eq!(exposure(&fixture, 1, START + 90 * S), Some(90 * S));
    let active = read.value().active;
    let held = owner.read::<VolumeRecord>(Key::Volume(active)).unwrap();
    let mut attached = held.value().clone();
    attached.push(EventKind::Attach, standby, ERA).unwrap();
    owner.replace(&held, attached).unwrap();
    surveyed(&mut fixture, START + 95 * S);
    assert_eq!(exposure(&fixture, 1, START + 95 * S), None);
    let mut retired = fixture.listing.clone().unwrap();
    retired.version = 6;
    let entry = retired.hosts.iter_mut().find(|entry| entry.host == standby);
    entry.unwrap().state = DirectoryState::Retired;
    fixture.listing = Some(retired);
    surveyed(&mut fixture, START + 100 * S);
    assert_eq!(exposure(&fixture, 1, START + 100 * S), Some(0));
}

/// Warm-up needs one complete observation of each source: while any one source stays incomplete past the settle
/// time the plan stays empty, and the first tick that completes it ends warm-up.
#[test]
fn warm_up_waits_for_a_complete_observation_of_each_source() {
    let config = roomy_fixture(6, 2).zone.bounds.config().clone();
    let settle = (2 * config.report_period_us).max(config.attach_settle_us);
    let ticks = settle / (10 * S) + 3;
    for source in ["reports", "instances", "volumes", "store"] {
        let mut fixture = roomy_fixture(6, 2);
        let fault = |fixture: &mut Fixture, on: bool| match source {
            "reports" if on => drop(fixture.world.faults.reports.insert(host(1))),
            "reports" => fixture.world.faults.reports.clear(),
            "instances" => fixture.world.faults.instances = on,
            "volumes" => fixture.world.faults.volumes = on,
            _ if on => (fixture.store).schedule(crate::storage::store::sim::Arm::Unavailable),
            _ => {}
        };
        for tick in 0..ticks {
            fault(&mut fixture, true);
            let survey = surveyed(&mut fixture, START + tick * 10 * S);
            assert!(survey.plan.holds.warm_up, "{source} at tick {tick}");
            assert!(survey.plan.steps.is_empty(), "{source} at tick {tick}");
        }
        fault(&mut fixture, false);
        let survey = surveyed(&mut fixture, START + ticks * 10 * S);
        assert!(!survey.plan.holds.warm_up, "{source}");
        assert!(!reserves(&survey.plan).is_empty(), "{source}");
    }
}

/// A start the plan keeps planning holds the stamp of its first admission until its window ends, and is stamped
/// again at the tick that admits it anew, so each of its windows admits it once.
#[test]
fn a_pending_start_keeps_its_stamp_for_one_window_and_is_stamped_again_after_it() {
    let window = roomy_fixture(1, 1).zone.bounds.config().attach_window_us;
    let pending_through = |last: u64| {
        let mut fixture = roomy_fixture(8, 20);
        let mut listing = fixture.listing.clone().unwrap();
        listing.host_roles_max = 64;
        fixture.listing = Some(listing.clone());
        fixture.zone.bounds = bounds_with(|config| {
            config.enroll_inflight_max = 64;
            config.standbys_per_host_max = 64;
        });
        let (first, started) = warmed(&mut fixture);
        let batch: BTreeSet<Shard> = (first.plan.starts.iter())
            .map(|&(shard, ..)| shard)
            .collect();
        assert_eq!(batch.len(), 16);
        for now in (started + 10 * S..=started + last).step_by(10 * S as usize) {
            let planned: BTreeSet<Shard> = (surveyed(&mut fixture, now).plan.starts.iter())
                .map(|&(shard, ..)| shard)
                .collect();
            assert_eq!(planned, batch, "at {now}");
        }
        let mut rest = listing;
        rest.version = 2;
        rest.shards.retain(|entry| !batch.contains(&entry.shard));
        fixture.listing = Some(rest);
        (fixture, started)
    };
    let (mut fixture, started) = pending_through(window - 10 * S);
    let opened = surveyed(&mut fixture, started + window);
    assert_eq!(reserves(&opened.plan).len(), 4);
    let (mut fixture, started) = pending_through(window);
    let held = surveyed(&mut fixture, started + window + 10 * S);
    assert!(reserves(&held.plan).is_empty());
    let opened = surveyed(&mut fixture, started + 2 * window);
    assert_eq!(reserves(&opened.plan).len(), 4);
}

#[test]
fn warm_up_lasts_until_every_source_completes_after_the_settle_time() {
    let mut fixture = roomy_fixture(6, 2);
    let config = fixture.zone.bounds.config().clone();
    let settle = (2 * config.report_period_us).max(config.attach_settle_us);
    fixture.world.faults.volumes = true;
    let ticks = settle / (10 * S) + 3;
    for tick in 0..ticks {
        let survey = surveyed(&mut fixture, START + tick * 10 * S);
        assert!(survey.plan.holds.warm_up, "tick {tick}");
        assert!(survey.plan.steps.is_empty(), "tick {tick}");
    }
    fixture.world.faults.volumes = false;
    let survey = surveyed(&mut fixture, START + ticks * 10 * S);
    assert!(!survey.plan.holds.warm_up);
    assert!(!reserves(&survey.plan).is_empty());
    fixture.world.faults.volumes = true;
    let refaulted = surveyed(&mut fixture, START + (ticks + 1) * 10 * S);
    assert!(!refaulted.plan.holds.warm_up);
    fixture.world.faults.volumes = false;
    let mut fresh = roomy_fixture(6, 2);
    assert!(surveyed(&mut fresh, START).plan.holds.warm_up);
    assert!(surveyed(&mut fresh, START + settle - 1).plan.holds.warm_up);
    assert!(!surveyed(&mut fresh, START + settle).plan.holds.warm_up);
}

/// The status counts the verdict of every host of the zone: unknown until a host's report sequence advances, then
/// live.
#[test]
fn the_status_counts_the_verdict_of_every_zone_host() {
    let mut fixture = roomy_fixture(10, 1);
    let first = surveyed(&mut fixture, START).status;
    let unknown = VerdictCounts {
        unknown: 10,
        ..VerdictCounts::default()
    };
    assert_eq!(first.verdicts, Some(unknown));
    let second = surveyed(&mut fixture, START + 10 * S).status;
    let live = VerdictCounts {
        live: 10,
        ..VerdictCounts::default()
    };
    assert_eq!(second.verdicts, Some(live));
}

#[test]
fn the_exposure_clock_runs_from_the_first_unprotected_tick_to_designation() {
    let mut fixture = roomy_fixture(4, 1);
    fixture.zone.bounds = bounds_with(|config| config.standby_target_us = 450 * S);
    warm(&mut fixture, 1);
    let row = |status: &ZoneStatus| (status.shards[0].exposure_us, status.shards[0].overdue);
    let early = surveyed(&mut fixture, START + 300 * S).status;
    assert_eq!((early.tick, row(&early)), (2, (Some(300 * S), false)));
    assert_eq!((early.census, early.inflight), (Some(0), Some(0)));
    let at = surveyed(&mut fixture, START + 450 * S).status;
    assert_eq!((at.tick, row(&at)), (3, (Some(450 * S), false)));
    let past = surveyed(&mut fixture, START + 450 * S + 1).status;
    assert_eq!(row(&past), (Some(450 * S + 1), true));
    assert_eq!(past.started_us, START);
    designate_all(&fixture);
    let protected = surveyed(&mut fixture, START + 460 * S).status;
    assert_eq!(row(&protected), (None, false));
    // The named standby, host 3, goes unanswered. Its fresh last report keeps it live; once that report is stale a
    // second exposure opens at that tick, not at the loop's start.
    fixture.world.faults.reports.insert(host(3));
    let fresh = surveyed(&mut fixture, START + 470 * S).status;
    assert_eq!(row(&fresh), (None, false));
    let reopened = surveyed(&mut fixture, START + 510 * S).status;
    assert_eq!(row(&reopened), (Some(0), false));
    let later = surveyed(&mut fixture, START + 540 * S).status;
    assert_eq!(row(&later), (Some(30 * S), false));
    let mut restarted = roomy_fixture(4, 1);
    let status = surveyed(&mut restarted, START + 900 * S).status;
    assert_eq!(
        (status.started_us, status.tick, row(&status)),
        (START + 900 * S, 1, (Some(0), false))
    );
}

#[test]
fn a_cap_below_the_shard_count_is_reported_and_a_slotless_shard_reads_census_full() {
    let mut fixture = roomy_fixture(4, 3);
    fixture.zone.bounds = bounds_with(|config| config.population_cap = 1);
    let client = Client::open(AsReconciler(fixture.store.clone()), MemLog::default()).unwrap();
    let slot = Reconciler::new(client)
        .reserve(
            &StandbyGate::qualified(),
            &Population { cap: 1 },
            fixture.zone.bounds.bounds(),
            ZONE,
            shard(1),
            &roomy(host(1)),
            |_| None,
            |_| false,
        )
        .unwrap();
    warm(&mut fixture, 2);
    let survey = surveyed(&mut fixture, START + 50 * S);
    let status = &survey.status;
    let below = status.cap_below.unwrap();
    assert_eq!((below.cap, below.shards, status.cap), (1, 3, 1));
    assert_eq!((status.census, status.inflight), (Some(1), Some(1)));
    let row = |number| status.shards[number as usize - 1];
    assert_eq!(row(1).target, Some(slot.target()));
    for number in [2, 3] {
        let refused = (row(number).state, row(number).blocker, row(number).target);
        assert_eq!(
            refused,
            (ShardState::NoCandidate, Some(Blocker::CensusFull), None)
        );
    }
    assert!(reserves(&survey.plan).is_empty());
    // Designating the slot's host keeps the census entry and ends the enrollment in flight.
    designate_attached(&fixture, 1, host(1));
    let designated = surveyed(&mut fixture, START + 60 * S).status;
    assert_eq!((designated.census, designated.inflight), (Some(1), Some(0)));
    // Three of four hosts unanswered exceed the largest partition and a quarter of the hosts: the zone host hold.
    fixture
        .world
        .faults
        .reports
        .extend([host(1), host(2), host(3)]);
    // Their fresh last reports keep them live; once those reports are stale they read unknown.
    let fresh = surveyed(&mut fixture, START + 70 * S).status;
    assert!(!fresh.holds.zone_host);
    let held = surveyed(&mut fixture, START + 120 * S).status;
    assert!(held.holds.zone_host && !held.holds.operator);
    assert_eq!(held.verdicts.unwrap().unknown, 3);
    let complete = Completeness {
        reports: false,
        instances: true,
        volumes: true,
        store: true,
    };
    assert_eq!(held.complete, complete);
}

#[test]
fn a_failed_census_read_keeps_each_clock_and_an_initial_shard_runs_none() {
    let mut fixture = roomy_fixture(4, 1);
    let mut listing = fixture.listing.clone().unwrap();
    listing.shards.push(shard_entry(2));
    fixture.listing = Some(listing);
    warm(&mut fixture, 1);
    let readable = surveyed(&mut fixture, START + 10 * S).status;
    let rows = |status: &ZoneStatus| -> Vec<_> {
        (status.shards.iter())
            .map(|row| (row.state, row.exposure_us, row.overdue))
            .collect()
    };
    assert_eq!(readable.shards[0].exposure_us, Some(10 * S));
    assert_eq!(rows(&readable)[1], (ShardState::Initial, None, false));
    fixture.store.schedule(Arm::Unavailable);
    let failed = surveyed(&mut fixture, START + 601 * S).status;
    let unread = ShardState::Unobserved(Source::Store(
        crate::storage::store::StoreError::Unavailable,
    ));
    assert_eq!(
        rows(&failed),
        [(unread, Some(601 * S), true), (unread, None, false)]
    );
    assert_eq!((failed.census, failed.inflight), (None, None));
    assert_eq!(failed.verdicts.unwrap().live, 4);
    let complete = Completeness {
        reports: true,
        instances: true,
        volumes: true,
        store: false,
    };
    assert_eq!(failed.complete, complete);
}

#[test]
fn a_shard_with_a_live_named_standby_runs_no_exposure_clock_while_its_volume_is_impaired() {
    let mut fixture = roomy_fixture(4, 1);
    designate_all(&fixture);
    let impaired = crate::failover::zone_loop::evidence::VolumeCondition {
        state: crate::failover::zone_loop::evidence::ListedVolumeState::InUse,
        status: crate::failover::zone_loop::evidence::VolumeStatus::Impaired,
    };
    fixture.world.volume(volume(1), impaired);
    for step in 0..80 {
        let survey = surveyed(&mut fixture, START + step * 10 * S);
        if step > 10 {
            assert_eq!(survey.status.shards[0].state, ShardState::VolumeImpaired);
            assert_eq!(survey.status.shards[0].exposure_us, None);
            assert_eq!(survey.status.verdicts.unwrap().live, 4);
        }
    }
    // The named standby, host 3, goes unanswered. Its fresh last report keeps the clock closed; once that report is
    // stale the volume stays impaired and the clock opens, then closes again once host 3 reads live.
    fixture.world.faults.reports.insert(host(3));
    let fresh = surveyed(&mut fixture, START + 800 * S).status;
    assert!(!fresh.complete.reports);
    assert_eq!(fresh.shards[0].exposure_us, None);
    let silent = surveyed(&mut fixture, START + 850 * S).status;
    let shard = silent.shards[0];
    assert_eq!(
        (shard.state, shard.exposure_us),
        (ShardState::VolumeImpaired, Some(0))
    );
    fixture.world.faults.reports.clear();
    let answered = surveyed(&mut fixture, START + 860 * S).status;
    let shard = answered.shards[0];
    assert_eq!(
        (shard.state, shard.exposure_us),
        (ShardState::VolumeImpaired, None)
    );
}

#[test]
fn verdict_counts_count_each_verdict_of_the_zone_hosts() {
    let mut scene = Scene::standby_needs(1);
    let verdicts = [
        (12, HostEvidence::Lost),
        (13, HostEvidence::Lost),
        (14, HostEvidence::Lost),
        (15, HostEvidence::Conflict),
        (16, HostEvidence::Conflict),
        (17, HostEvidence::Unknown),
    ];
    scene.verdicts.extend(verdicts);
    let observation = scene.observation();
    let counts = VerdictCounts::of(&observation.zone.as_ref().unwrap().hosts);
    let expected = VerdictCounts {
        live: 4,
        lost: 3,
        conflict: 2,
        unknown: 1,
    };
    assert_eq!(counts, expected);
}

#[test]
fn an_unobserved_directory_keeps_each_exposure_clock_and_the_held_cap_warning() {
    let mut exposed = roomy_fixture(4, 2);
    exposed.zone.bounds = bounds_with(|config| config.population_cap = 1);
    let mut listing = exposed.listing.clone().unwrap();
    listing.zone_hold = true;
    exposed.listing = Some(listing.clone());
    warm(&mut exposed, 1);
    let survey = exposed
        .zone
        .survey(Err(Unreachable), &mut exposed.world, START + 601 * S);
    assert!(survey.plan.steps.is_empty());
    assert_eq!(survey.plan.holds, survey.status.holds);
    let outage = survey.status;
    let unobserved = ShardState::Unobserved(Source::Directory);
    assert_eq!(outage.shards.len(), 2);
    for row in &outage.shards {
        assert_eq!(
            (row.state, row.exposure_us, row.overdue),
            (unobserved, Some(601 * S), true)
        );
    }
    let below = outage.cap_below.unwrap();
    assert_eq!((below.cap, below.shards), (1, 2));
    assert_eq!((outage.census, outage.verdicts), (None, None));
    assert_eq!(outage.inflight, None);
    assert_eq!(outage.complete, Completeness::default());
    assert!(outage.holds.operator && !outage.holds.zone_host);
    // The loop refuses a changed listing at the held version, and the operator hold stays set.
    listing.zone_hold = false;
    exposed.listing = Some(listing);
    let refused = surveyed(&mut exposed, START + 611 * S);
    assert!(refused.plan.steps.is_empty());
    let state = refused.status.shards[0].state;
    let succession = ShardState::Unobserved(Source::Succession(SuccessionRefusal::Version));
    assert_eq!(state, succession);
    assert!(refused.plan.holds.operator);
    assert_eq!(refused.plan.holds, refused.status.holds);

    let mut protected = roomy_fixture(4, 1);
    designate_all(&protected);
    warm(&mut protected, 3);
    let outage = protected
        .zone
        .survey(Err(Unreachable), &mut protected.world, START + 700 * S)
        .status;
    let row = outage.shards[0];
    assert_eq!(
        (row.state, row.exposure_us, row.overdue),
        (unobserved, None, false)
    );
}

#[test]
fn a_shard_that_leaves_the_directory_drops_its_exposure_clock() {
    // A relisted shard starts a new exposure clock; a continuously listed shard keeps its accumulated exposure.
    for (removal, relisting) in [(true, true), (false, true), (false, false)] {
        let mut fixture = roomy_fixture(4, 2);
        warm(&mut fixture, 1);
        let mut listing = fixture.listing.clone().unwrap();
        listing.version = 2;
        listing.shards.retain(|entry| entry.shard == shard(1));
        fixture.listing = Some(listing.clone());
        if removal {
            let departed = surveyed(&mut fixture, START + 10 * S).status;
            assert_eq!(departed.shards.len(), 1);
        } else {
            fixture.observe(START + 10 * S);
        }
        listing.version = 3;
        listing.shards.push(shard_entry(2));
        fixture.listing = Some(listing);
        if !relisting {
            fixture.observe(START + 20 * S);
        }
        let back = surveyed(&mut fixture, START + 710 * S).status;
        let rows: Vec<_> = (back.shards.iter())
            .map(|row| (row.shard.get(), row.exposure_us, row.overdue))
            .collect();
        assert_eq!(
            rows,
            [(1, Some(710 * S), true), (2, Some(0), false)],
            "removal by survey: {removal}, relisting by survey: {relisting}"
        );
    }
}

#[test]
fn a_named_standby_beside_another_hosts_slot_holds_a_role() {
    let scene = |slot: u64, roles_max: u32| {
        let mut scene = Scene::new(vec![
            records(1, OWNER, Some(12), volume_record()),
            records(2, OWNER, None, volume_record()),
        ]);
        scene
            .listing
            .hosts
            .retain(|entry| [OWNER, 12, 16].contains(&entry.host.get()));
        let sixteen = scene.listing.hosts.iter_mut().find(|e| e.host == host(16));
        sixteen.unwrap().state = DirectoryState::Draining;
        scene.listing.host_roles_max = roles_max;
        scene.census = census_of(&[(shard_record(1, OWNER, None), slot)]);
        scene.plan()
    };
    assert_eq!(
        state_of(&scene(16, 1), 2),
        (ShardState::NoCandidate, Some(Blocker::PerHostCap))
    );
    assert_eq!(reserves(&scene(12, 2)), [(2, 12)]);
}

#[test]
fn a_slot_host_that_cannot_progress_gives_its_shard_the_blocker_and_keeps_the_named_standby() {
    let displaced = || {
        let mut scene = Scene::new(vec![records(1, OWNER, Some(13), volume_record())]);
        scene.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
        scene
    };
    let stays = |plan: &Plan| {
        let moves = |step: &Step| matches!(step, Step::Reserve { .. } | Step::Designate { .. });
        !plan.steps.iter().any(moves)
            && plan.shards[0].protected
            && plan.shards[0].state != ShardState::Protected
    };
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Reserved,
        host: host(12),
    };
    let plan = displaced().plan();
    assert_eq!(state_of(&plan, 1), (enrolling, None), "control");
    assert_eq!(plan.inflight, 1, "control");
    assert!(
        matches!(plan.steps.as_slice(), [Step::RecordAttach { .. }]),
        "control"
    );
    let mut held = displaced();
    let hold = owner_entry(1, |entry| entry.phase = Some(OwnerPhase::Held)).1;
    held.reports.get_mut(&12).unwrap().entries.push(hold);
    let plan = held.plan();
    assert_eq!(
        state_of(&plan, 1),
        (enrolling, Some(Blocker::DeviceFailureHold))
    );
    assert_eq!(plan.inflight, 0);
    assert!(plan.steps.is_empty() && stays(&plan), "{:?}", plan.steps);
    let mut unnamed = Scene::new(vec![records(1, OWNER, None, volume_record())]);
    unnamed.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
    let hold = owner_entry(1, |entry| entry.phase = Some(OwnerPhase::Held)).1;
    unnamed.reports.get_mut(&12).unwrap().entries.push(hold);
    let plan = unnamed.plan();
    assert_eq!(
        state_of(&plan, 1),
        (enrolling, Some(Blocker::DeviceFailureHold)),
        "control"
    );
    assert_eq!(plan.inflight, 1, "control");
    for (attachments, recovery) in [
        (Gauge::known(0, 64), Gauge::known(2, 2)),
        (Gauge::known(64, 64), Gauge::known(0, 2)),
    ] {
        let mut tight = displaced();
        tight
            .reports
            .insert(12, report_of(host(12), attachments, recovery));
        let plan = tight.plan();
        assert_eq!(state_of(&plan, 1), (enrolling, Some(Blocker::Headroom)));
        assert!(plan.steps.is_empty() && stays(&plan), "{:?}", plan.steps);
    }
    let mut full = displaced();
    full.shards[0]
        .active
        .push(EventKind::Attach, host(14), ERA)
        .unwrap();
    bind(&mut full.shards[0].active, 14);
    let plan = full.plan();
    let closed = (ShardState::Closed, Some(Blocker::AttachClosed));
    assert_eq!(state_of(&plan, 1), closed);
    let end = Step::End {
        shard: shard(1),
        host: host(14),
    };
    assert_eq!(plan.steps, [end]);
    let mut closed = displaced();
    closed.listing.zone_hold = true;
    let plan = closed.plan();
    assert!(plan.holds.operator && plan.steps.is_empty() && stays(&plan));
    assert_eq!(state_of(&plan, 1), (enrolling, None));
}

#[test]
fn a_failed_slot_host_beside_a_live_named_standby_reserves_that_standby_alone() {
    let failed = |change: &dyn Fn(&mut Scene)| {
        let mut scene = Scene::new(vec![records(1, OWNER, Some(13), volume_record())]);
        scene.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
        scene.verdicts.insert(12, HostEvidence::Lost);
        change(&mut scene);
        scene.plan()
    };
    // Host 13 shares the owner's color, so a free choice of candidate passes it over.
    let plan = failed(&|_| {});
    assert_eq!(reserves(&plan), [(1, 13)]);
    assert!(plan.shards[0].protected);
    assert_ne!(state_of(&plan, 1).0, ShardState::Protected);
    let plan = failed(&|scene| scene.listing.host_roles_max = 1);
    assert_eq!(reserves(&plan), [(1, 13)]);
    let plan = failed(&|scene| {
        let full = report_of(host(13), Gauge::known(0, 64), Gauge::known(2, 2));
        scene.reports.insert(13, full);
    });
    assert!(reserves(&plan).is_empty(), "{:?}", plan.steps);
    assert_eq!(
        state_of(&plan, 1),
        (ShardState::NoCandidate, Some(Blocker::Headroom))
    );
    assert!(plan.shards[0].protected);
}

/// A displaced shard keeps its live named standby, so the per-owner count that orders new starts counts only the
/// shard with no standby, and that shard, under another owner, takes the plan's one start. With that shard
/// protected, the plan reserves the displaced shard's named standby.
#[test]
fn a_displaced_shards_reservation_follows_the_start_of_a_shard_with_no_standby() {
    let one = bounds_with(|config| config.enroll_inflight_max = 1);
    let planned = |standby: Option<u64>| {
        let mut scene = Scene::new(vec![
            records(1, OWNER, Some(13), volume_record()),
            records(2, 20, standby, volume_record()),
        ]);
        scene.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
        scene.verdicts.insert(12, HostEvidence::Lost);
        scene.plan_under(&one)
    };
    let plan = planned(None);
    assert_eq!(plan.inflight, 0);
    let reserved: Vec<u32> = reserves(&plan).iter().map(|&(shard, _)| shard).collect();
    assert_eq!(reserved, [2], "{:?}", plan.steps);
    assert!(plan.shards[0].protected && !plan.shards[1].protected);
    let plan = planned(Some(15));
    assert_eq!(state_of(&plan, 2), (ShardState::Protected, None), "control");
    assert_eq!(reserves(&plan), [(1, 13)], "control");
}

#[test]
fn a_displaced_standby_reads_each_unconfirmed_or_stale_role_as_the_ordinary_plan_does() {
    let displaced = |slot_owner: u64, change: &dyn Fn(&mut Scene)| {
        let mut scene = Scene::new(vec![records(
            1,
            OWNER,
            Some(13),
            lineage(&[(host(12), c_pair())]),
        )]);
        scene.shards[0].active.volume = volume(1);
        scene.census = census_of(&[(shard_record(1, slot_owner, None), 12)]);
        change(&mut scene);
        scene.plan()
    };
    let designate = Step::Designate {
        shard: shard(1),
        host: host(12),
        target: Target::of(&shard_record(1, OWNER, Some(13))),
    };
    let plan = displaced(OWNER, &|_| {});
    assert_eq!(plan.steps, [designate], "control");
    let plan = displaced(OWNER, &|scene| {
        let full = report_of(host(12), Gauge::known(0, 64), Gauge::known(2, 2));
        scene.reports.insert(12, full);
    });
    let enrolled = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Enrolled,
        host: host(12),
    };
    assert_eq!(state_of(&plan, 1), (enrolled, Some(Blocker::Headroom)));
    assert!(plan.steps.is_empty() && plan.shards[0].protected);
    let plan = displaced(OWNER, &|scene| {
        scene.verdicts.insert(13, HostEvidence::Unknown);
    });
    let unknown = (ShardState::StandbyUnknown, Some(Blocker::LossUnconfirmed));
    assert_eq!(state_of(&plan, 1), unknown);
    assert!(plan.steps.is_empty() && !plan.shards[0].protected);
    let plan = displaced(OWNER, &|scene| {
        scene.verdicts.insert(OWNER, HostEvidence::Unknown);
    });
    assert_eq!(state_of(&plan, 1).0, ShardState::OwnerUnknown);
    assert!(plan.steps.is_empty() && plan.shards[0].protected);
    let plan = displaced(OWNER, &|scene| {
        scene.verdicts.insert(12, HostEvidence::Unknown);
    });
    let unconfirmed = (ShardState::NoCandidate, Some(Blocker::LossUnconfirmed));
    assert_eq!(state_of(&plan, 1), unconfirmed);
    assert!(plan.steps.is_empty() && plan.shards[0].protected);
    // An entry at another owner's target is a stale slot beside a protected shard.
    let plan = displaced(14, &|_| {});
    assert_eq!(state_of(&plan, 1).0, ShardState::Protected);
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
}

#[test]
fn a_bare_displaced_entry_that_choose_refuses_leaves_its_in_flight_unit_to_other_starts() {
    let one = bounds_with(|config| config.enroll_inflight_max = 1);
    let full = || report_of(host(12), Gauge::known(64, 64), Gauge::known(0, 2));
    let mut scene = Scene::new(vec![
        records(1, OWNER, Some(13), volume_record()),
        records(2, OWNER, None, volume_record()),
    ]);
    scene.census = census_of(&[(shard_record(1, OWNER, None), 12)]);
    scene.reports.insert(12, full());
    let plan = scene.plan_under(&one);
    assert_eq!(plan.inflight, 0);
    assert_eq!(reserves(&plan).len(), 1, "{:?}", plan.steps);
    assert_eq!(reserves(&plan)[0].0, 2);
    assert_eq!(state_of(&plan, 1).1, Some(Blocker::Headroom));
    let hold = owner_entry(1, |entry| entry.phase = Some(OwnerPhase::Held)).1;
    scene.reports.insert(12, plenty(12));
    scene.reports.get_mut(&12).unwrap().entries.push(hold);
    let plan = scene.plan_under(&one);
    assert_eq!(plan.inflight, 0);
    assert_eq!(reserves(&plan).len(), 1, "{:?}", plan.steps);
    assert_eq!(reserves(&plan)[0].0, 2);
    assert_eq!(state_of(&plan, 1).1, Some(Blocker::DeviceFailureHold));
    let mut attaching = Scene::new(vec![
        records(1, OWNER, Some(13), volume_record()),
        records(2, OWNER, None, lineage(&[(host(16), c_pair())])),
    ]);
    attaching.shards[1].active.volume = volume(2);
    attaching.census = census_of(&[
        (shard_record(1, OWNER, None), 12),
        (shard_record(2, OWNER, None), 16),
    ]);
    let recording = |step: &&Step| matches!(step, Step::RecordAttach { .. });
    let plan = attaching.plan_under(&one);
    assert_eq!(plan.inflight, 2);
    assert_eq!(
        plan.steps.iter().filter(recording).count(),
        0,
        "{:?}",
        plan.steps
    );
    attaching.reports.insert(12, full());
    let plan = attaching.plan_under(&one);
    assert_eq!(plan.inflight, 1);
}

#[test]
fn a_resumed_bare_reservation_records_no_attach_past_the_in_flight_limit() {
    let one = bounds_with(|config| config.enroll_inflight_max = 1);
    let mut scene = Scene::new(vec![
        records(1, OWNER, Some(13), volume_record()),
        records(2, OWNER, None, volume_record()),
    ]);
    scene.census = census_of(&[
        (shard_record(1, OWNER, None), 16),
        (shard_record(2, OWNER, None), 12),
    ]);
    let recording = |step: &&Step| matches!(step, Step::RecordAttach { .. });
    for verdict in [HostEvidence::Live, HostEvidence::Lost] {
        scene.verdicts.insert(13, verdict);
        let resumed = scene.plan_under(&one);
        assert_eq!(resumed.steps.iter().filter(recording).count(), 1);
    }
    let mut attaching = Scene::new(vec![
        records(1, OWNER, Some(13), lineage(&[(host(16), c_pair())])),
        records(2, OWNER, None, volume_record()),
    ]);
    attaching.shards[0].active.volume = volume(1);
    attaching.census = census_of(&[(shard_record(1, OWNER, None), 16)]);
    let plan = attaching.plan_under(&one);
    assert_eq!(plan.inflight, 1);
    assert!(reserves(&plan).is_empty());
    // The recorded attach of shard 1 holds the one in-flight unit, so the bare slot of shard 2 waits while shard 1's
    // enrolled slot host is designated over the live named standby (SLOT-HOST).
    attaching.census = census_of(&[
        (shard_record(1, OWNER, None), 16),
        (shard_record(2, OWNER, None), 12),
    ]);
    let plan = attaching.plan_under(&one);
    assert_eq!(plan.inflight, 2);
    let designate = Step::Designate {
        shard: shard(1),
        host: host(16),
        target: Target::of(&attaching.shards[0].record),
    };
    assert_eq!(plan.steps, [designate]);
    let two = bounds_with(|config| config.enroll_inflight_max = 2);
    let plan = attaching.plan_under(&two);
    assert_eq!(plan.steps.iter().filter(recording).count(), 1);
}

#[test]
fn unknown_active_volume_health_plans_no_enrollment_step() {
    let mut scene = Scene::standby_needs(1);
    scene.shards[0].judgement.health = None;
    let plan = scene.plan();
    assert!(plan.steps.is_empty());
    assert_eq!(state_of(&plan, 1).1, Some(Blocker::ControlPlaneUnavailable));
    scene.shards[0].judgement.health = Some(Health::Available);
    assert_eq!(reserves(&scene.plan()), [(1, 12)]);
}

#[test]
fn a_held_slot_on_a_volume_that_admits_no_reservation_reads_closed() {
    let c = c_host();
    let enrolled = lineage(&[(c, c_pair())]);
    let mut recorded = enrolled.clone();
    recorded.pairs.retain(|pair| pair.host != c);
    for active in [volume_record(), recorded, enrolled] {
        let mut scene = Scene::new(vec![records(1, OWNER, None, active)]);
        scene.listing.hosts.push(placed(c.get(), 0, 0));
        scene.verdicts.insert(c.get(), HostEvidence::Live);
        scene.reports.insert(c.get(), plenty(c.get()));
        scene.census = census_of(&[(scene.shards[0].record, c.get())]);
        assert_eq!(scene.plan().steps.len(), 1);
        scene.shards[0].active.state = VolumeState::Retired;
        let plan = scene.plan();
        let shut = (ShardState::Closed, Some(Blocker::AttachClosed));
        assert_eq!(state_of(&plan, 1), shut);
        assert!(plan.steps.is_empty());
        assert_eq!(plan.inflight, 1);
    }
}

/// DIRECTORY-SCOPE: the in-flight count and the loss judgement cover the directory's shards. Beside four census
/// entries of shards outside the view, each naming a live host, a listed shard starts its enrollment, records its
/// attach and gets its lost-volume decision.
#[test]
fn census_slots_of_shards_outside_the_view_hold_no_in_flight_unit() {
    let outside: Vec<_> = (6..=9)
        .map(|n| (shard_record(n, OWNER, None), 10 + u64::from(n)))
        .collect();
    let mut scene = Scene::standby_needs(1);
    scene.census = census_of(&outside);
    let plan = scene.plan();
    assert_eq!(plan.inflight, 0);
    assert_eq!(reserves(&plan), [(1, 12)]);
    scene.shards[0].judgement.health = Some(Health::Lost);
    let open = ShardState::Replacing {
        phase: crate::failover::loss::Phase::Open,
    };
    assert_eq!(state_of(&scene.plan(), 1), (open, None));
    let mut reserved = Scene::standby_needs(1);
    let mut slots = vec![(reserved.shards[0].record, 12)];
    slots.extend(outside);
    reserved.census = census_of(&slots);
    let plan = reserved.plan();
    assert_eq!(plan.inflight, 1);
    assert!(
        matches!(plan.steps[..], [Step::RecordAttach { .. }]),
        "{:?}",
        plan.steps
    );
}

#[test]
fn a_later_start_moves_to_the_next_host_when_the_first_fills() {
    let mut scene = Scene::standby_needs(2);
    scene
        .listing
        .hosts
        .retain(|entry| [OWNER, 12, 16].contains(&entry.host.get()));
    let bounds = bounds_with(|config| config.standbys_per_host_max = 1);
    let plan = scene.plan_under(&bounds);
    assert_eq!(reserves(&plan), [(1, 12), (2, 16)]);
    let enrolling = ShardState::Enrolling {
        need: Need::Standby,
        phase: EnrollPhase::Unreserved,
        host: host(16),
    };
    assert_eq!(state_of(&plan, 2), (enrolling, None));
}

#[test]
fn an_unreadable_census_leaves_every_shard_unobserved() {
    let mut scene = Scene::standby_needs(2);
    scene.listing.zone_hold = true;
    let mut observation = scene.observation();
    let source = Source::Store(StoreError::Unavailable);
    observation.zone.as_mut().unwrap().census = Err(source);
    let plan = plan_with(&observation, &bounds_with(|_| {}));
    assert!(plan.steps.is_empty());
    assert_eq!(plan.inflight, 0);
    assert!(plan.holds.operator);
    let unobserved = (
        ShardState::Unobserved(source),
        Some(Blocker::StoreUnavailable),
    );
    assert_eq!(state_of(&plan, 1), unobserved);
    assert_eq!(state_of(&plan, 2), unobserved);
}

/// A predecessor's Held entry under the `unverified` label is a question of records, not of its device: a standby
/// enrolled in the active volume is designated for the shard, where the same entry with no withdrawal label holds the
/// step under `DeviceFailureHold`. Control: with the label read as a device hold, the designation is held too.
#[test]
fn an_unverified_held_entry_lets_the_standby_be_designated() {
    let plan = |label: Option<Withdrawal>| {
        let mut scene = guard_scene(false, true);
        let former = scene
            .reports
            .get_mut(&12)
            .unwrap()
            .entries
            .last_mut()
            .unwrap();
        former.withdrawal = label;
        scene.census = census_of(&[(scene.shards[0].record, 12)]);
        (scene.plan(), Target::of(&scene.shards[0].record))
    };
    let designate = |target| Step::Designate {
        shard: shard(1),
        host: host(12),
        target,
    };
    let (unverified, target) = plan(Some(Withdrawal::Unverified));
    assert_eq!(unverified.steps, [designate(target)]);
    let (device, _) = plan(None);
    assert!(device.steps.is_empty(), "{:?}", device.steps);
    assert_eq!(state_of(&device, 1).1, Some(Blocker::DeviceFailureHold));
    UNVERIFIED_AS_DEVICE.set(true);
    let (planted, _) = plan(Some(Withdrawal::Unverified));
    UNVERIFIED_AS_DEVICE.set(false);
    assert!(
        planted.steps.is_empty(),
        "control: the unverified label read as a device hold holds the designation"
    );
}

fn ends(plan: &Plan) -> Vec<u64> {
    let end = |step: &Step| match *step {
        Step::End { host, .. } => Some(host.get()),
        _ => None,
    };
    plan.steps.iter().filter_map(end).collect()
}

/// A shard whose volume holds the owner's attach and a live, bound attach of host 13, enrolled when `enrolled`.
fn third_attached(enrolled: bool) -> Scene {
    let mut active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(13), c_pair())])
    };
    bind(&mut active, 13);
    if !enrolled {
        active.pairs.retain(|pair| pair.host != host(13));
    }
    Scene::new(vec![records(1, OWNER, None, active)])
}

#[test]
fn a_stuck_entry_is_ended_only_while_it_holds_no_enrolled_pair() {
    let plan_of = |enrolled: bool| {
        let scene = third_attached(enrolled);
        let seq = scene.shards[0].active.live(host(13)).unwrap();
        let stuck = BTreeSet::from([(volume(1), seq)]);
        let (bounds, exposure) = (bounds_with(|_| {}), Exposure::default());
        let context = Context {
            bounds: &bounds,
            now_us: START,
            warming: false,
            starts: &BTreeMap::new(),
            exposure: &exposure,
            stuck: &stuck,
        };
        plan(&scene.observation(), &context)
    };
    assert_eq!(ends(&plan_of(false)), [13]);
    assert_eq!(ends(&plan_of(true)), [] as [u64; 0]);
    assert_eq!(ends(&third_attached(false).plan()), [] as [u64; 0]);
}

#[test]
fn a_lost_hosts_attach_is_ended_only_after_the_shards_first_attempt() {
    let plan_at = |attempts: u32| {
        let mut scene = third_attached(true);
        scene.verdicts.insert(13, HostEvidence::Lost);
        scene.shards[0].record.attempts = attempts;
        scene.plan()
    };
    assert_eq!(ends(&plan_at(1)), [13]);
    let initial = plan_at(0);
    assert_eq!(state_of(&initial, 1), (ShardState::Initial, None));
    assert!(initial.steps.is_empty(), "{:?}", initial.steps);
}

#[test]
fn an_ended_entry_with_its_pair_recorded_or_no_usable_listing_takes_no_detach_or_release() {
    let scene = |pinned: bool, listing: Option<&[u64]>| {
        let mut scene = third_attached(pinned);
        let active = &mut scene.shards[0].active;
        let seq = active.live(host(13)).unwrap();
        let event = active.events.iter_mut().find(|event| event.seq == seq);
        event.unwrap().kind = EventKind::Ended;
        scene.volumes = match listing {
            Some(instances) => vec![listed(volume(1), instances)],
            None => Vec::new(),
        };
        scene.plan()
    };
    let unwinds = |plan: &Plan| {
        let unwinding =
            |step: &&Step| matches!(step, Step::Detach { .. } | Step::ReleaseAttach { .. });
        plan.steps
            .iter()
            .filter(unwinding)
            .copied()
            .collect::<Vec<Step>>()
    };
    let (shard, host) = (shard(1), host(13));
    assert_eq!(
        unwinds(&scene(false, Some(&[13]))),
        [Step::Detach { shard, host }]
    );
    assert_eq!(
        unwinds(&scene(false, Some(&[]))),
        [Step::ReleaseAttach { shard, host }]
    );
    for listing in [Some(&[13][..]), Some(&[][..])] {
        assert_eq!(unwinds(&scene(true, listing)), [], "{listing:?}");
    }
    assert_eq!(unwinds(&scene(false, None)), []);
}

#[test]
fn the_capacity_end_needs_a_full_volume_no_other_end_and_an_owner_to_drop_the_pair() {
    let cramped = bounds_with(|c| c.owner.registrant_max = 3);
    let shut = (ShardState::Closed, Some(Blocker::AttachClosed));
    let mut two = lineage(&[(c_host(), c_pair())]);
    bind(&mut two, c_host().get());
    pinned_ended(&mut two, 223);
    let roomy = Scene::new(vec![records(1, OWNER, None, two)]).plan_under(&cramped);
    assert_eq!(state_of(&roomy, 1), shut);
    assert!(roomy.steps.is_empty(), "{:?}", roomy.steps);

    let mut three = lineage(&[(c_host(), c_pair()), (host(13), c_pair())]);
    bind(&mut three, c_host().get());
    bind(&mut three, 13);
    let mut beside = Scene::new(vec![records(1, OWNER, None, three)]);
    beside.verdicts.insert(13, HostEvidence::Lost);
    let plan = beside.plan();
    assert_eq!(ends(&plan), [13], "{:?}", plan.steps);

    let capped = bounds_with(|c| c.owner.registrant_max = 3);
    let mut outside = lineage(&[(c_host(), c_pair()), (host(222), c_pair())]);
    bind(&mut outside, c_host().get());
    let served = Scene::new(vec![records(1, OWNER, None, outside.clone())]);
    assert_eq!(ends(&served.plan_under(&capped)), [c_host().get()]);
    let mut orphaned = Scene::new(vec![records(1, OWNER, None, outside.clone())]);
    orphaned.verdicts.insert(OWNER, HostEvidence::Lost);
    let plan = orphaned.plan_under(&capped);
    assert_eq!(state_of(&plan, 1), shut);
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);

    let mut crowded = lineage(&[
        (c_host(), c_pair()),
        (host(222), c_pair()),
        (host(223), c_pair()),
    ]);
    bind(&mut crowded, c_host().get());
    let mut ended = Scene::new(vec![records(1, OWNER, None, crowded)]);
    let active = &mut ended.shards[0].active;
    let seq = active.live(host(OWNER)).unwrap();
    let event = active.events.iter_mut().find(|event| event.seq == seq);
    event.unwrap().kind = EventKind::Ended;
    let plan = ended.plan_under(&bounds_with(|c| c.owner.registrant_max = 4));
    assert_eq!(state_of(&plan, 1), shut);
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);

    let cramped = |number: u64| report_of(host(number), Gauge::known(0, 64), Gauge::known(2, 2));
    let mut current = Scene::new(vec![records(1, OWNER, None, outside.clone())]);
    current.census = census_of(&[(current.shards[0].record, 12)]);
    current.reports.insert(12, cramped(12));
    assert_eq!(ends(&current.plan()), [c_host().get()]);
    let mut stale = Scene::new(vec![records(1, OWNER, None, outside)]);
    stale.census = census_of(&[(stale.shards[0].record, 12)]);
    stale.shards[0].record.attempts += 1;
    stale.reports.insert(12, cramped(12));
    let plan = stale.plan();
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
}

#[test]
fn a_replacement_of_a_slot_host_ended_in_the_tick_takes_no_second_in_flight_unit() {
    let bounds = bounds_with(|c| c.enroll_inflight_max = 2);
    let mut scene = Scene::standby_needs(2);
    let mut active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(16), c_pair())])
    };
    bind(&mut active, 16);
    let at = scene.listing.hosts.iter().position(|e| e.host == host(16));
    scene.listing.hosts[at.unwrap()].state = DirectoryState::Draining;
    scene.shards[0].active = active;
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    let plan = scene.plan_under(&bounds);
    assert_eq!(plan.inflight, 1);
    assert_eq!(ends(&plan), [16]);
    let moved = reserves(&plan);
    let shards: Vec<u32> = moved.iter().map(|(shard, _)| *shard).collect();
    assert_eq!(shards, [1, 2], "{:?}", plan.steps);
    assert!(moved.iter().all(|(_, named)| *named != 16), "{moved:?}");
}

#[test]
fn the_capacity_end_waits_under_the_zone_host_hold() {
    let mut volume = lineage(&[(c_host(), c_pair()), (host(222), c_pair())]);
    bind(&mut volume, c_host().get());
    let mut scene = Scene::new(vec![records(1, OWNER, None, volume)]);
    assert_eq!(ends(&scene.plan()), [c_host().get()]);
    for n in 16..=20 {
        scene.verdicts.insert(n, HostEvidence::Unknown);
    }
    let plan = scene.plan();
    assert!(plan.holds.zone_host && !plan.holds.operator);
    assert!(plan.steps.is_empty(), "{:?}", plan.steps);
}

#[test]
fn a_replacement_of_an_ended_slot_host_is_admitted_behind_a_start_the_in_flight_limit_refuses() {
    let bounds = bounds_with(|c| c.enroll_inflight_max = 1);
    let mut scene = Scene::standby_needs(2);
    let mut active = VolumeRecord {
        volume: volume(2),
        ..lineage(&[(host(16), c_pair())])
    };
    bind(&mut active, 16);
    let at = scene.listing.hosts.iter().position(|e| e.host == host(16));
    scene.listing.hosts[at.unwrap()].state = DirectoryState::Draining;
    scene.shards[1].active = active;
    scene.census = census_of(&[(scene.shards[1].record, 16)]);
    let plan = scene.plan_under(&bounds);
    assert_eq!(plan.inflight, 1);
    let moved = reserves(&plan);
    assert!(
        moved.len() == 1 && moved[0].0 == 2 && moved[0].1 != 16,
        "{:?}",
        plan.steps
    );
}

#[test]
fn the_reclaim_steps_follow_the_in_flight_steps_and_precede_the_reservations() {
    let mut scene = Scene::standby_needs(2);
    let mut enrolled = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(16), c_pair())])
    };
    bind(&mut enrolled, 16);
    scene.shards[0].active = enrolled;
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    let mut lost = VolumeRecord {
        volume: volume(2),
        ..lineage(&[(host(13), c_pair())])
    };
    bind(&mut lost, 13);
    scene.shards[1].active = lost;
    scene.verdicts.insert(13, HostEvidence::Lost);
    let plan = scene.plan();
    let designate = Step::Designate {
        shard: shard(1),
        host: host(16),
        target: Target::of(&scene.shards[0].record),
    };
    let end = Step::End {
        shard: shard(2),
        host: host(13),
    };
    assert_eq!(plan.steps[..2], [designate, end], "{:?}", plan.steps);
    assert!(
        matches!(plan.steps[2..], [Step::Reserve { shard: at, .. }] if at == shard(2)),
        "{:?}",
        plan.steps
    );
}

/// ORDER: every `ReleaseAttach` follows every `Attach` and `Detach` of the plan, whatever their shards, so a
/// release runs after each listing those steps read in the call.
#[test]
fn the_gone_marks_follow_every_attach_and_detach_of_the_plan() {
    let ended = |number: u32, of: u64| {
        let mut active = VolumeRecord {
            volume: volume(number),
            ..lineage(&[(host(of), c_pair())])
        };
        bind(&mut active, of);
        active.pairs.retain(|pair| pair.host != host(of));
        let seq = active.live(host(of)).unwrap();
        let event = active.events.iter_mut().find(|event| event.seq == seq);
        event.unwrap().kind = EventKind::Ended;
        records(number, OWNER, None, active)
    };
    let mut scene = Scene::new(vec![ended(1, 13), ended(2, 14)]);
    scene.volumes = vec![listed(volume(1), &[]), listed(volume(2), &[14])];
    let plan = scene.plan();
    let at = |wanted: Step| plan.steps.iter().position(|step| *step == wanted);
    let release = at(Step::ReleaseAttach {
        shard: shard(1),
        host: host(13),
    });
    let detach = at(Step::Detach {
        shard: shard(2),
        host: host(14),
    });
    assert!(release.is_some() && detach.is_some(), "{:?}", plan.steps);
    assert!(detach < release, "{:?}", plan.steps);
}

#[test]
fn the_capacity_end_takes_the_first_bound_attach_and_an_end_of_another_host_exempts_no_start() {
    let mut both = lineage(&[(c_host(), c_pair()), (host(222), c_pair())]);
    bind(&mut both, c_host().get());
    let seq = both.live(host(222)).unwrap();
    let event = both.events.iter_mut().find(|event| event.seq == seq);
    event.unwrap().instance = Some(instance(222));
    let plan = Scene::new(vec![records(1, OWNER, None, both)]).plan();
    assert_eq!(ends(&plan), [c_host().get()], "{:?}", plan.steps);

    let bounds = bounds_with(|c| c.enroll_inflight_max = 1);
    let mut scene = Scene::standby_needs(2);
    let mut lost = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(13), c_pair())])
    };
    bind(&mut lost, 13);
    scene.shards[0].active = lost;
    scene.verdicts.insert(13, HostEvidence::Lost);
    scene.census = census_of(&[(scene.shards[1].record, 16)]);
    let plan = scene.plan_under(&bounds);
    assert_eq!(plan.inflight, 1);
    assert_eq!(ends(&plan), [13]);
    assert!(reserves(&plan).is_empty(), "{:?}", plan.steps);
}

#[test]
fn a_census_slot_host_whose_entry_is_gone_plans_a_new_attach_entry() {
    let mut scene = Scene::standby_needs(1);
    let mut active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(16), c_pair())])
    };
    active.pairs.retain(|pair| pair.host != host(16));
    let seq = active.live(host(16)).unwrap();
    let event = active.events.iter_mut().find(|event| event.seq == seq);
    let event = event.unwrap();
    event.instance = Some(instance(16));
    event.kind = EventKind::Gone;
    scene.shards[0].active = active;
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    let plan = scene.plan();
    let record = Step::RecordAttach {
        shard: shard(1),
        host: host(16),
        target: Target::of(&scene.shards[0].record),
    };
    assert_eq!(plan.steps, [record]);
    assert_eq!(plan.inflight, 1);
}

/// The replacement's attaching host is counted by its roles against `host_roles_max`, a role the shard record names
/// standby included when no census entry names it. In the false-suspicion order the census slot of shard 2 moved from
/// host 12 to host 13 while shard 2's record still names 12 standby: at a limit of one role, 12 holds that role and
/// no host takes shard 1's replacement. With shard 2's record naming no standby, 12 takes it.
#[test]
fn a_replacement_host_counts_a_standby_role_its_census_entry_left() {
    let plan_of = |named: Option<u64>| {
        let mut scene = Scene::new(vec![
            records(1, OWNER, None, volume_record()),
            records(2, OWNER, None, volume_record()),
        ]);
        scene.census = census_of(&[(scene.shards[1].record, 13)]);
        scene.shards[1] = records(2, OWNER, named, volume_record());
        scene.listing.host_roles_max = 1;
        for entry in &mut scene.listing.hosts {
            if ![12, 13].contains(&entry.host.get()) {
                entry.state = DirectoryState::Draining;
            }
        }
        scene.shards[0].judgement.health = Some(Health::Lost);
        created_receipt(&mut scene.shards[0]);
        scene.plan()
    };
    let host_of = |plan: &Plan| {
        plan.steps.iter().find_map(|step| match *step {
            Step::Replace { host, .. } => Some(host),
            _ => None,
        })
    };
    assert_eq!(host_of(&plan_of(Some(12))), Some(None));
    assert_eq!(host_of(&plan_of(None)), Some(Some(host(12))));
}

/// Gives `records` an unheld receipt of the next generation that records `vol-0e` as created, with no replacement
/// record read, so the plan chooses the replacement's attaching host.
fn created_receipt(records: &mut ShardRecords) {
    let record = &records.record;
    let crate::failover::loss::Decision::Provision(request) =
        crate::failover::loss::decide(record, (record.active, Health::Lost), 0)
    else {
        panic!("no replacement request for {record:?}");
    };
    let made = crate::failover::records::VolumeId::new("vol-0e").unwrap();
    records.receipt = Some(crate::failover::loss::Receipt {
        request,
        phase: crate::failover::loss::Phase::Created(made),
        ..receipt()
    });
}

/// HOST-LOSS-KEEPS-VOLUME: a lost active volume whose owner raised a retirement request reads the
/// request and plans no replacement step; the same loss without the request plans one.
#[test]
fn a_retirement_request_beside_a_lost_volume_plans_no_replacement() {
    let plan_of = |requested: bool| {
        let mut scene = Scene::standby_needs(1);
        scene.shards[0].judgement.health = Some(Health::Lost);
        if requested {
            scene.shards[0].entries = vec![owner_entry(1, |entry| entry.flip = true)];
        }
        scene.plan()
    };
    let replaces = |plan: &Plan| {
        plan.steps
            .iter()
            .any(|step| matches!(step, Step::Replace { .. }))
    };
    let requested = plan_of(true);
    assert_eq!(
        state_of(&requested, 1),
        (
            ShardState::RetirementRequested,
            Some(Blocker::RetirementRequested)
        )
    );
    assert!(!replaces(&requested));
    assert!(replaces(&plan_of(false)));
}

/// The `Replace` steps of `plan`, as shard numbers.
fn replaced_shards(plan: &Plan) -> Vec<u32> {
    let replace = |step: &Step| match *step {
        Step::Replace { shard, .. } => Some(shard.get()),
        _ => None,
    };
    plan.steps.iter().filter_map(replace).collect()
}

/// HOLDS and CORRELATED-HOLD in the plan: an isolated confirmed loss plans a replace step, and neither the operator
/// hold nor the zone host hold plans one; under either hold an open receipt beside another impaired volume still
/// plans the step whose one write is the latch, and the same receipt with no impaired volume plans nothing. An
/// issued or created receipt reads the same way: no step under either hold with no impaired volume, the latch's
/// step beside one, and its step with no hold. A released receipt beside an impaired volume has no latch to write
/// and plans nothing under either hold.
#[test]
fn the_zone_holds_withhold_replacement_work_and_keep_the_latch() {
    let scene_of = |hold: Option<bool>, receipt_open: bool, others: usize| {
        let mut scene = Scene::standby_needs(1);
        scene.shards[0].judgement.health = Some(Health::Lost);
        scene.shards[0].judgement.others = others;
        if receipt_open {
            scene.shards[0].receipt = Some(receipt());
        }
        match hold {
            Some(true) => scene.listing.zone_hold = true,
            Some(false) => {
                for n in (OWNER + 1..=20).take(8) {
                    scene.verdicts.insert(n, HostEvidence::Unknown);
                }
            }
            None => {}
        }
        scene.plan()
    };
    assert_eq!(replaced_shards(&scene_of(None, false, 0)), [1]);
    for operator in [true, false] {
        let held = scene_of(Some(operator), false, 0);
        assert!(held.holds.operator == operator && held.holds.zone_host != operator);
        assert!(replaced_shards(&held).is_empty(), "operator {operator}");
        let open = scene_of(Some(operator), true, 0);
        assert!(replaced_shards(&open).is_empty(), "operator {operator}");
        let latch = scene_of(Some(operator), true, 1);
        assert_eq!(replaced_shards(&latch), [1], "operator {operator}");
        let start = scene_of(Some(operator), false, 1);
        assert_eq!(replaced_shards(&start), [1], "operator {operator}");
    }
    let made = crate::failover::records::VolumeId::new("vol-0e").unwrap();
    let phases = [
        crate::failover::loss::Phase::Issued,
        crate::failover::loss::Phase::Created(made),
    ];
    let with = |hold: Option<bool>,
                others: usize,
                change: &dyn Fn(&mut crate::failover::loss::Receipt)| {
        let mut scene = Scene::standby_needs(1);
        scene.shards[0].judgement.health = Some(Health::Lost);
        scene.shards[0].judgement.others = others;
        let mut held = receipt();
        change(&mut held);
        scene.shards[0].receipt = Some(held);
        match hold {
            Some(true) => scene.listing.zone_hold = true,
            Some(false) => {
                for n in (OWNER + 1..=20).take(8) {
                    scene.verdicts.insert(n, HostEvidence::Unknown);
                }
            }
            None => {}
        }
        replaced_shards(&scene.plan())
    };
    for phase in phases {
        let at_phase = move |held: &mut crate::failover::loss::Receipt| held.phase = phase;
        assert_eq!(with(None, 0, &at_phase), [1], "{phase:?} with no hold");
        for operator in [true, false] {
            assert!(
                with(Some(operator), 0, &at_phase).is_empty(),
                "{phase:?} in flight under a zone hold, operator {operator}"
            );
            assert_eq!(
                with(Some(operator), 1, &at_phase),
                [1],
                "{phase:?} beside an impaired volume still latches, operator {operator}"
            );
        }
    }
    let released = |held: &mut crate::failover::loss::Receipt| held.released = true;
    assert_eq!(with(None, 1, &released), [1]);
    for operator in [true, false] {
        assert!(
            with(Some(operator), 1, &released).is_empty(),
            "a released receipt has no latch to write, operator {operator}"
        );
    }
}

/// REPLACE's unit count: at `replacements_inflight_max = 1` two isolated losses with no receipt plan one start, in
/// shard order, and two plan at a limit of two. An open receipt over a volume that no longer reads lost holds no
/// unit, so the other shard's start still plans; an issued receipt holds its unit. An open receipt over a confirmed
/// loss takes the free unit while its attempt is within `create_attempts_max`, and takes none past it.
#[test]
fn replacements_take_inflight_units_for_provider_work_alone() {
    let scene_of = |first: Option<crate::failover::loss::Phase>, first_lost: bool| {
        let mut scene = Scene::standby_needs(2);
        for records in &mut scene.shards {
            records.judgement.health = Some(Health::Lost);
        }
        if !first_lost {
            scene.shards[0].judgement.health = Some(Health::Available);
        }
        if let Some(phase) = first {
            scene.shards[0].receipt = Some(crate::failover::loss::Receipt { phase, ..receipt() });
        }
        scene
    };
    let at = |max: u32| bounds_with(move |config| config.replacements_inflight_max = max);
    let both = scene_of(None, true);
    assert_eq!(replaced_shards(&both.plan_under(&at(1))), [1]);
    assert_eq!(replaced_shards(&both.plan_under(&at(2))), [1, 2]);
    let dormant = scene_of(Some(crate::failover::loss::Phase::Open), false);
    assert_eq!(replaced_shards(&dormant.plan_under(&at(1))), [1, 2]);
    let issued = scene_of(Some(crate::failover::loss::Phase::Issued), false);
    assert_eq!(replaced_shards(&issued.plan_under(&at(1))), [1]);
    let made = crate::failover::records::VolumeId::new("vol-0e").unwrap();
    let created = scene_of(Some(crate::failover::loss::Phase::Created(made)), false);
    assert_eq!(
        replaced_shards(&created.plan_under(&at(1))),
        [1],
        "a created receipt keeps its unit over a volume that reads available again"
    );
    assert_eq!(replaced_shards(&created.plan_under(&at(2))), [1, 2]);
    let open = scene_of(Some(crate::failover::loss::Phase::Open), true);
    assert_eq!(replaced_shards(&open.plan_under(&at(1))), [1]);
    assert_eq!(replaced_shards(&open.plan_under(&at(2))), [1, 2]);
    let mut exhausted = scene_of(Some(crate::failover::loss::Phase::Open), true);
    let spent = exhausted.shards[0].receipt.as_mut().unwrap();
    spent.attempt = at(1).config().create_attempts_max + 1;
    assert_eq!(
        replaced_shards(&exhausted.plan_under(&at(1))),
        [1, 2],
        "an open receipt past its attempts keeps its alarm step and leaves the unit to shard 2"
    );
    exhausted.shards[0].receipt.as_mut().unwrap().attempt -= 1;
    assert_eq!(replaced_shards(&exhausted.plan_under(&at(1))), [1]);
}

/// The replacement's host needs attachment headroom, the owner included, and one plan charges each host it picks:
/// an owner whose report shows no free attachment slot gives the replacement to another host, and two shards whose
/// owners drain do not both pick a host with one free slot.
#[test]
fn a_replacement_host_needs_attachment_room_and_one_plan_charges_each_pick() {
    let host_of = |plan: &Plan, number: u32| {
        plan.steps.iter().find_map(|step| match *step {
            Step::Replace {
                shard: at, host, ..
            } if at == shard(number) => host,
            _ => None,
        })
    };
    let mut scene = Scene::standby_needs(1);
    created_receipt(&mut scene.shards[0]);
    assert_eq!(host_of(&scene.plan(), 1), Some(host(OWNER)));
    let full = report_of(host(OWNER), Gauge::known(64, 64), Gauge::known(0, 2));
    scene.reports.insert(OWNER, full);
    let other = host_of(&scene.plan(), 1);
    assert!(other.is_some_and(|other| other != host(OWNER)), "{other:?}");

    let mut scene = Scene::standby_needs(2);
    for records in &mut scene.shards {
        created_receipt(records);
    }
    for entry in &mut scene.listing.hosts {
        if entry.host == host(OWNER) {
            entry.state = DirectoryState::Draining;
        }
    }
    let numbers: Vec<u64> = scene.reports.keys().copied().collect();
    for n in numbers {
        scene.reports.insert(
            n,
            report_of(host(n), Gauge::known(63, 64), Gauge::known(0, 2)),
        );
    }
    let plan = scene.plan();
    let (first, second) = (host_of(&plan, 1), host_of(&plan, 2));
    assert!(
        first.is_some() && second.is_some() && first != second,
        "{first:?} {second:?}"
    );
}

/// The `host` of shard `number`'s `Replace` step in `plan`: `None` when the plan holds no such step, `Some(None)`
/// when the step names no host.
fn replace_host(plan: &Plan, number: u32) -> Option<Option<Host>> {
    plan.steps.iter().find_map(|step| match *step {
        Step::Replace {
            shard: at, host, ..
        } if at == shard(number) => Some(host),
        _ => None,
    })
}

/// The replacement's host, one rule at a time. The owner takes it unless its report shows an era below `MIN_ERA` or
/// a device-failure hold of the shard. With the owner draining, the host of fewest roles takes it, also when a
/// lower-numbered host holds more. One free attachment slot serves one replacement of a plan, with role room to
/// spare, and a slot the plan's reservation takes serves no replacement. A pick counts as a role for the plan's
/// later picks, in the ranking and against `host_roles_max`, and so does the host a replacement's attach event
/// names.
#[test]
fn a_replacement_host_is_chosen_by_era_device_hold_roles_and_attachment_slots() {
    let drain_owner = |scene: &mut Scene| {
        for entry in &mut scene.listing.hosts {
            if entry.host == host(OWNER) {
                entry.state = DirectoryState::Draining;
            }
        }
    };
    let mut scene = Scene::standby_needs(1);
    created_receipt(&mut scene.shards[0]);
    assert_eq!(replace_host(&scene.plan(), 1), Some(Some(host(OWNER))));
    let report = scene.reports.get_mut(&OWNER).unwrap();
    report.host.build.era = crate::failover::records::MIN_ERA - 1;
    let chosen = replace_host(&scene.plan(), 1).unwrap();
    assert!(
        chosen.is_some_and(|chosen| chosen != host(OWNER)),
        "era: {chosen:?}"
    );

    let mut scene = Scene::standby_needs(1);
    created_receipt(&mut scene.shards[0]);
    let held = owner_entry(1, |entry| entry.phase = Some(OwnerPhase::Held)).1;
    scene.reports.get_mut(&OWNER).unwrap().entries.push(held);
    let chosen = replace_host(&scene.plan(), 1).unwrap();
    assert!(
        chosen.is_some_and(|chosen| chosen != host(OWNER)),
        "device hold: {chosen:?}"
    );

    let mut scene = Scene::new(vec![
        records(1, OWNER, None, volume_record()),
        records(2, 12, Some(13), volume_record()),
    ]);
    created_receipt(&mut scene.shards[0]);
    drain_owner(&mut scene);
    assert_eq!(
        replace_host(&scene.plan(), 1),
        Some(Some(host(14))),
        "hosts 12 and 13 hold a role each, so host 14 has the fewest"
    );

    let full = |number: u64| report_of(host(number), Gauge::known(64, 64), Gauge::known(0, 2));
    let one_slot = |number: u64| report_of(host(number), Gauge::known(63, 64), Gauge::known(0, 2));
    let mut scene = Scene::standby_needs(2);
    for records in &mut scene.shards {
        created_receipt(records);
    }
    let numbers: Vec<u64> = scene.reports.keys().copied().collect();
    for n in numbers {
        scene.reports.insert(n, full(n));
    }
    scene.reports.insert(12, one_slot(12));
    let plan = scene.plan();
    assert_eq!(
        (replace_host(&plan, 1), replace_host(&plan, 2)),
        (Some(Some(host(12))), Some(None)),
        "host 12's one slot serves one replacement"
    );

    scene.shards[0].receipt = None;
    let plan = scene.plan();
    assert_eq!(reserves(&plan), [(1, 12)]);
    assert_eq!(
        replace_host(&plan, 2),
        Some(None),
        "the reservation takes host 12's slot"
    );
    scene.shards[0].record.standby = Some(host(13));
    scene.shards[0]
        .active
        .push(EventKind::Attach, host(13), ERA)
        .unwrap();
    let plan = scene.plan();
    assert!(reserves(&plan).is_empty(), "{:?}", plan.steps);
    assert_eq!(replace_host(&plan, 2), Some(Some(host(12))));

    let two_created = || {
        let mut scene = Scene::standby_needs(2);
        for records in &mut scene.shards {
            created_receipt(records);
        }
        drain_owner(&mut scene);
        scene
    };
    let plan = two_created().plan();
    assert_eq!(
        (replace_host(&plan, 1), replace_host(&plan, 2)),
        (Some(Some(host(12))), Some(Some(host(13)))),
        "with slots to spare, the first pick's role sends the second to the next host"
    );

    let mut scene = two_created();
    scene.listing.host_roles_max = 1;
    let numbers: Vec<u64> = scene.reports.keys().copied().collect();
    for n in numbers.into_iter().filter(|&n| n != 12) {
        scene.reports.insert(n, full(n));
    }
    let plan = scene.plan();
    assert_eq!(
        (replace_host(&plan, 1), replace_host(&plan, 2)),
        (Some(Some(host(12))), Some(None)),
        "host 12 has slots to spare and room for one role"
    );

    let made = scene.shards[0].receipt.as_ref().unwrap().phase.volume();
    let mut replacement = volume_record();
    replacement.volume = made.unwrap();
    replacement.events.clear();
    replacement.push(EventKind::Attach, host(12), ERA).unwrap();
    scene.shards[0].replacement = Some(replacement);
    scene.shards[1].receipt.as_mut().unwrap().phase =
        crate::failover::loss::Phase::Created(VolumeId::new("vol-0d").unwrap());
    let plan = scene.plan();
    assert_eq!(
        (replace_host(&plan, 1), replace_host(&plan, 2)),
        (Some(Some(host(12))), Some(None)),
        "the host a replacement's attach event names holds that role"
    );
    scene.listing.host_roles_max = 2;
    assert_eq!(replace_host(&scene.plan(), 2), Some(Some(host(12))));
}

/// A lost slot host and a slot at a stale target hold no in-flight unit, so the end of the slot host's attach
/// exchanges none: under an in-flight limit of one, the plan reserves one shard's replacement.
#[test]
fn a_replacement_of_a_lost_slot_host_takes_an_in_flight_unit() {
    let bounds = bounds_with(|c| c.enroll_inflight_max = 1);
    let mut scene = Scene::standby_needs(2);
    let mut active = VolumeRecord {
        volume: volume(1),
        ..lineage(&[(host(16), c_pair())])
    };
    bind(&mut active, 16);
    scene.shards[0].active = active;
    scene.census = census_of(&[(scene.shards[0].record, 16)]);
    scene.verdicts.insert(16, HostEvidence::Lost);
    let plan = scene.plan_under(&bounds);
    assert_eq!(plan.inflight, 0);
    assert_eq!(ends(&plan), [16]);
    let moved = reserves(&plan);
    assert_eq!(moved.len(), 1, "{:?}", plan.steps);
    assert_ne!(moved[0].1, 16);

    let stale = ShardRecord {
        attempts: 1,
        ..scene.shards[0].record
    };
    scene.shards[0].record.attempts = 2;
    scene.census = census_of(&[(stale, 16)]);
    let plan = scene.plan_under(&bounds);
    assert_eq!(plan.inflight, 0);
    assert_eq!(ends(&plan), [16]);
    assert_eq!(reserves(&plan).len(), 1, "{:?}", plan.steps);
}

#[test]
fn an_attach_whose_pair_key_refuses_its_end_takes_no_end() {
    let unkeyed = crate::failover::takeover::tests::lineage;
    let scene = |own_key: bool| {
        let mut active = VolumeRecord {
            volume: volume(1),
            ..unkeyed(&[(host(13), c_pair())])
        };
        bind(&mut active, 13);
        let seq = active.live(host(13)).unwrap();
        assert_ne!(Some(c_pair().key), attachment_key(seq));
        if own_key {
            let pinned = active.pairs.iter_mut().find(|pair| pair.host == host(13));
            pinned.unwrap().pair.key = attachment_key(seq).unwrap();
        }
        let mut scene = Scene::new(vec![records(1, OWNER, None, active)]);
        scene.verdicts.insert(13, HostEvidence::Lost);
        scene.plan()
    };
    let refused = scene(false);
    assert_eq!(ends(&refused), [] as [u64; 0], "{:?}", refused.steps);
    assert_eq!(reserves(&refused).len(), 1, "{:?}", refused.steps);
    let admitted = scene(true);
    assert_eq!(ends(&admitted), [13], "{:?}", admitted.steps);
    assert_eq!(reserves(&admitted).len(), 1, "{:?}", admitted.steps);

    let mut full = unkeyed(&[(c_host(), c_pair()), (host(222), c_pair())]);
    bind(&mut full, c_host().get());
    let seq = full.live(host(222)).unwrap();
    let event = full.events.iter_mut().find(|event| event.seq == seq);
    event.unwrap().instance = Some(instance(222));
    let pinned = full.pairs.iter_mut().find(|pair| pair.host == host(222));
    pinned.unwrap().pair.key = attachment_key(seq).unwrap();
    let plan = Scene::new(vec![records(1, OWNER, None, full)]).plan();
    assert_eq!(ends(&plan), [222], "{:?}", plan.steps);
}

/// Ends host 11's attach of shard `at`'s volume when the volume holds one, so a new candidate of that shard needs a
/// new attach.
fn end_owner_attach(scene: &mut Scene, at: usize) {
    let volume = &mut scene.shards[at].active;
    let Some(seq) = volume.live(host(OWNER)) else {
        return;
    };
    let event = volume.events.iter_mut().find(|event| event.seq == seq);
    event.unwrap().kind = EventKind::Ended;
}

/// A full-census scene for FRESH-FIRST. Shard 1 was taken over by host 11, its owner now, and its census entry names
/// host 11 at an earlier target, so `Census::releases` drops it. Shard 2's owner, host 13, is lost with no standby
/// and no entry, so it needs a fresh host. The cap is the census's length.
fn fresh_scene() -> Scene {
    let mut scene = Scene::new(vec![
        records(1, OWNER, None, volume_record()),
        records(2, 13, None, volume_record()),
    ]);
    scene.verdicts.insert(13, HostEvidence::Lost);
    scene.census = census_of(&[(shard_record(1, 15, None), OWNER)]);
    scene
}

fn capped(cap: usize) -> ZoneBounds {
    bounds_with(|config| config.population_cap = cap)
}

fn plans_release(plan: &Plan, number: u32) -> bool {
    (plan.steps.iter())
        .any(|step| matches!(step, Step::Release { shard: at, .. } if *at == shard(number)))
}

fn plans_reserve(plan: &Plan, number: u32) -> bool {
    reserves(plan).iter().any(|&(at, _)| at == number)
}

/// Whether the plan withholds shard `number`'s re-reservation: its release in place of its reservation, its state
/// an unreserved standby enrollment refused `CensusFull`, and no attach start for it.
fn withholds(plan: &Plan, number: u32) -> bool {
    let refused = matches!(
        state_of(plan, number),
        (
            ShardState::Enrolling {
                need: Need::Standby,
                phase: EnrollPhase::Unreserved,
                ..
            },
            Some(Blocker::CensusFull)
        )
    );
    let started = plan.starts.iter().any(|&(at, ..)| at == shard(number));
    refused && plans_release(plan, number) && !plans_reserve(plan, number) && !started
}

/// FRESH-FIRST's count and choice on the plan. A refused fresh need withholds the re-reservation of a shard whose
/// entry `Census::releases` drops, and no other: a re-reservation on an entry that stays listed (a lost named
/// standby's at the current target) keeps its reservation, a `Standby` start the cap refuses withholds nothing, a
/// fresh need with unknown volume health or whose attach the operator hold stops withholds nothing, and a release
/// the tick already plans for another shard covers the need. With two refused fresh needs and one planned release
/// the plan withholds one re-reservation, the lowest shard's, and an entry above a lowered cap adds one.
#[test]
fn a_refused_fresh_need_withholds_only_a_releasable_re_reservation_by_shard() {
    let base = fresh_scene();
    let plan = base.plan_under(&capped(1));
    assert!(withholds(&plan, 1), "{:?}", plan.steps);
    let refused = (ShardState::NoCandidate, Some(Blocker::CensusFull));
    assert_eq!(state_of(&plan, 2), refused);

    let mut retained = fresh_scene();
    retained.shards[0] = records(1, OWNER, Some(14), volume_record());
    retained.verdicts.insert(14, HostEvidence::Lost);
    retained.census = census_of(&[(shard_record(1, OWNER, Some(14)), 14)]);
    let plan = retained.plan_under(&capped(1));
    assert!(
        plans_reserve(&plan, 1) && !plans_release(&plan, 1),
        "{:?}",
        plan.steps
    );
    assert_eq!(state_of(&plan, 2), refused);

    let mut standby = fresh_scene();
    standby.verdicts.insert(13, HostEvidence::Live);
    standby.shards.push(records(3, 12, None, volume_record()));
    standby.listing.shards.push(shard_entry(3));
    standby.volumes.push(listed(volume(3), &[]));
    let plan = standby.plan_under(&capped(2));
    assert!(
        plans_reserve(&plan, 1) && !plans_release(&plan, 1),
        "{:?}",
        plan.steps
    );
    assert_eq!(reserves(&plan).len(), 2, "{:?}", plan.steps);

    let mut unknown = fresh_scene();
    unknown.shards[1].judgement.health = None;
    let plan = unknown.plan_under(&capped(1));
    assert!(
        plans_reserve(&plan, 1) && !plans_release(&plan, 1),
        "{:?}",
        plan.steps
    );

    let mut held = fresh_scene();
    end_owner_attach(&mut held, 1);
    let live = (held.shards[0].active).push(EventKind::Attach, host(12), ERA);
    live.unwrap();
    bind(&mut held.shards[0].active, 12);
    held.listing.zone_hold = true;
    let plan = held.plan_under(&capped(1));
    assert_eq!(reserves(&plan), [(1, 12)], "{:?}", plan.steps);
    assert!(!plans_release(&plan, 1));
    held.listing.zone_hold = false;
    assert!(withholds(&held.plan_under(&capped(1)), 1));

    let mut two = fresh_scene();
    two.shards.push(records(3, 17, None, volume_record()));
    two.shards.push(records(4, 19, None, volume_record()));
    two.shards.push(records(5, 16, None, volume_record()));
    for n in 3..=5 {
        two.listing.shards.push(shard_entry(n));
        two.volumes.push(listed(volume(n), &[]));
    }
    two.verdicts.insert(19, HostEvidence::Lost);
    two.verdicts.insert(16, HostEvidence::Unknown);
    two.census = census_of(&[
        (shard_record(1, 15, None), OWNER),
        (shard_record(3, 15, None), 17),
        (shard_record(5, 15, None), 16),
    ]);
    let plan = two.plan_under(&capped(3));
    assert!(withholds(&plan, 1), "{:?}", plan.steps);
    assert!(
        plans_reserve(&plan, 3) && !plans_release(&plan, 3),
        "{:?}",
        plan.steps
    );
    assert!(plans_release(&plan, 5));
    assert_eq!((state_of(&plan, 2), state_of(&plan, 4)), (refused, refused));

    let mut covered = two;
    covered
        .shards
        .retain(|records| records.record.shard != shard(4));
    covered
        .listing
        .shards
        .retain(|entry| entry.shard != shard(4));
    let plan = covered.plan_under(&capped(3));
    assert!(
        plans_reserve(&plan, 1) && plans_reserve(&plan, 3),
        "{:?}",
        plan.steps
    );
    assert!(plans_release(&plan, 5) && !plans_release(&plan, 1));

    let mut lowered = fresh_scene();
    lowered.shards.push(records(3, 17, None, volume_record()));
    lowered.listing.shards.push(shard_entry(3));
    lowered.volumes.push(listed(volume(3), &[]));
    lowered.census = census_of(&[
        (shard_record(1, 15, None), OWNER),
        (shard_record(3, 15, None), 17),
    ]);
    let plan = lowered.plan_under(&capped(1));
    assert!(
        withholds(&plan, 1) && withholds(&plan, 3),
        "{:?}",
        plan.steps
    );
}

/// A refused fresh need keeps the start credit it needs from a later start of the tick: with one start left in the
/// window, the fresh need's new attach takes the credit, a lost named standby's replacement on shard 3, which needs a
/// new attach, waits, and shard 1's re-reservation on a live attach is withheld. Control: with three starts left,
/// shard 3 reserves.
#[test]
fn a_refused_fresh_need_keeps_its_start_credit_from_a_later_standby_start() {
    let mut scene = fresh_scene();
    scene.shards.push(records(3, 12, Some(14), volume_record()));
    scene.listing.shards.push(shard_entry(3));
    scene.volumes.push(listed(volume(3), &[]));
    scene.verdicts.insert(14, HostEvidence::Lost);
    scene.census = census_of(&[
        (shard_record(1, 15, None), OWNER),
        (shard_record(3, 12, Some(14)), 14),
    ]);
    for at in 1..3 {
        end_owner_attach(&mut scene, at);
    }
    let live = (scene.shards[0].active).push(EventKind::Attach, host(12), ERA);
    live.unwrap();
    bind(&mut scene.shards[0].active, 12);
    let bounds = bounds_with(|config| {
        config.population_cap = 2;
        config.attach_starts_per_window = 1;
    });
    let plan = scene.plan_under(&bounds);
    assert!(withholds(&plan, 1), "{:?}", plan.steps);
    assert!(!plans_reserve(&plan, 3), "{:?}", plan.steps);
    let roomy = bounds_with(|config| {
        config.population_cap = 2;
        config.attach_starts_per_window = 3;
    });
    let plan = scene.plan_under(&roomy);
    assert!(
        withholds(&plan, 1) && plans_reserve(&plan, 3),
        "{:?}",
        plan.steps
    );
}

/// A fresh need the census refuses charges the tick's later starts only for a place the tick frees. In the first
/// three rows shard 1's entry names its lost standby at the record's target, so `Census::releases` keeps it and no
/// place frees for shard 2's fresh need; shard 1's replacement then takes the tick's one in-flight unit, its one
/// start credit, and the one role its candidate has left. With two refused fresh needs and one releasable entry, the
/// plan charges one fresh need, withholds that entry's re-reservation, and leaves the third in-flight unit to a lost
/// named standby's replacement. At a census above a lowered cap whose one releasable entry frees no place, the fresh
/// need charges nothing and still withholds that entry's re-reservation, and a lost named standby's replacement
/// takes the second in-flight unit.
#[test]
fn a_refused_fresh_need_no_place_frees_for_charges_no_later_start() {
    let refused = (ShardState::NoCandidate, Some(Blocker::CensusFull));
    let mut retained = fresh_scene();
    retained.shards[0] = records(1, OWNER, Some(14), volume_record());
    retained.verdicts.insert(14, HostEvidence::Lost);
    retained.census = census_of(&[(shard_record(1, OWNER, Some(14)), 14)]);
    let replaces = |scene: &Scene, bounds: &ZoneBounds| {
        let plan = scene.plan_under(bounds);
        assert_eq!(state_of(&plan, 2), refused);
        assert!(!plans_release(&plan, 1), "{:?}", plan.steps);
        plans_reserve(&plan, 1)
    };

    let one_unit = bounds_with(|config| {
        config.population_cap = 1;
        config.enroll_inflight_max = 1;
    });
    assert!(replaces(&retained, &one_unit));

    let mut opening = fresh_scene();
    opening.shards[0] = unattached(1, OWNER, Some(14), volume_record());
    opening.verdicts.insert(14, HostEvidence::Lost);
    opening.census = retained.census.clone();
    end_owner_attach(&mut opening, 1);
    let one_credit = bounds_with(|config| {
        config.population_cap = 1;
        config.attach_starts_per_window = 1;
    });
    let plan = opening.plan_under(&one_credit);
    assert_eq!(plan.starts.len(), 1, "{:?}", plan.steps);
    assert!(replaces(&opening, &one_credit));

    let mut one_role = fresh_scene();
    one_role.shards[0] = retained.shards[0].clone();
    one_role.verdicts.insert(14, HostEvidence::Lost);
    one_role.census = retained.census.clone();
    one_role
        .listing
        .hosts
        .retain(|entry| [OWNER, 12, 13, 14].contains(&entry.host.get()));
    one_role.listing.host_roles_max = 1;
    assert!(replaces(&one_role, &capped(1)));

    let mut two = fresh_scene();
    two.shards.push(records(3, 12, Some(14), volume_record()));
    two.shards.push(records(4, 19, None, volume_record()));
    for n in 3..=4 {
        two.listing.shards.push(shard_entry(n));
        two.volumes.push(listed(volume(n), &[]));
    }
    two.verdicts.insert(14, HostEvidence::Lost);
    two.verdicts.insert(19, HostEvidence::Lost);
    two.census = census_of(&[
        (shard_record(1, 15, None), OWNER),
        (shard_record(3, 12, Some(14)), 14),
    ]);
    let three_units = bounds_with(|config| {
        config.population_cap = 2;
        config.enroll_inflight_max = 3;
    });
    let plan = two.plan_under(&three_units);
    assert!(withholds(&plan, 1), "{:?}", plan.steps);
    assert!(plans_reserve(&plan, 3), "{:?}", plan.steps);
    assert_eq!((state_of(&plan, 2), state_of(&plan, 4)), (refused, refused));

    let mut lowered = two;
    lowered
        .shards
        .retain(|records| records.record.shard != shard(4));
    lowered
        .listing
        .shards
        .retain(|entry| entry.shard != shard(4));
    let two_units = bounds_with(|config| {
        config.population_cap = 1;
        config.enroll_inflight_max = 2;
    });
    let plan = lowered.plan_under(&two_units);
    assert!(withholds(&plan, 1), "{:?}", plan.steps);
    assert!(plans_reserve(&plan, 3), "{:?}", plan.steps);
    assert_eq!(state_of(&plan, 2), refused);
}

/// A census of shard 1's releasable entry, which names its owner at an earlier target, and shard 5's, which names
/// its lost owner 16 at an earlier target, so shard 5 queues a fresh start on its own entry. Shards 2 and 4 have
/// lost owners and no entry; host 12 holds a live attach of shard 1's volume and host 14 of shard 4's, and every
/// other candidate needs a new attach.
fn kept_entry_scene() -> Scene {
    let mut scene = fresh_scene();
    scene.shards.push(records(4, 19, None, volume_record()));
    scene.shards.push(records(5, 16, None, volume_record()));
    for n in 4..=5 {
        scene.listing.shards.push(shard_entry(n));
        scene.volumes.push(listed(volume(n), &[]));
    }
    scene.verdicts.insert(19, HostEvidence::Lost);
    scene.verdicts.insert(16, HostEvidence::Lost);
    scene.census = census_of(&[
        (shard_record(1, 15, None), OWNER),
        (shard_record(5, 15, None), 16),
    ]);
    for (at, live) in [(0, 12), (2, 14)] {
        let active = &mut scene.shards[at].active;
        active.push(EventKind::Attach, host(live), ERA).unwrap();
        bind(active, live);
    }
    scene
}

/// `admit` judges the fresh starts the census refuses after the fresh starts that hold a census entry, so the places
/// it charges for are the places the plan frees. Shard 5's fresh start on its own releasable entry takes the
/// window's one start credit and keeps the entry; one place is left to free, shard 1's. Shard 4's fresh need, whose
/// candidate holds a live attach, is counted and charged, and shard 1's re-reservation is withheld; shard 2's, which
/// needs a new attach, waits for a credit. With one role left on shard 4's candidate, which the entry of a shard
/// outside the directory names, a lost named standby's replacement on shard 3 leaves that host to shard 4. With two in-flight units and no credit limit, shard 5's start
/// and a lost named standby's replacement take the units, and the fresh needs without an entry charge nothing.
#[test]
fn a_refused_fresh_need_is_charged_after_the_fresh_starts_that_keep_an_entry() {
    let refused = (ShardState::NoCandidate, Some(Blocker::CensusFull));
    let scene = kept_entry_scene();
    let one_credit = bounds_with(|config| {
        config.population_cap = 2;
        config.attach_starts_per_window = 1;
    });
    let plan = scene.plan_under(&one_credit);
    assert!(withholds(&plan, 1), "{:?}", plan.steps);
    assert!(
        plans_reserve(&plan, 5) && !plans_release(&plan, 5),
        "{:?}",
        plan.steps
    );
    assert_eq!((state_of(&plan, 2), state_of(&plan, 4)), (refused, refused));

    let mut contended = kept_entry_scene();
    contended
        .shards
        .push(records(3, 15, Some(18), volume_record()));
    contended.listing.shards.push(shard_entry(3));
    contended.volumes.push(listed(volume(3), &[]));
    contended.verdicts.insert(18, HostEvidence::Lost);
    contended.census = census_of(&[
        (shard_record(1, 15, None), OWNER),
        (shard_record(3, 15, Some(18)), 18),
        (shard_record(5, 15, None), 16),
        (shard_record(9, 15, None), 14),
    ]);
    let active = &mut contended.shards[4].active;
    active.push(EventKind::Attach, host(14), ERA).unwrap();
    bind(active, 14);
    let one_role = bounds_with(|config| {
        config.population_cap = 4;
        config.attach_starts_per_window = 1;
        config.standbys_per_host_max = 2;
    });
    let plan = contended.plan_under(&one_role);
    assert!(withholds(&plan, 1), "{:?}", plan.steps);
    assert!(!plans_reserve(&plan, 3), "{:?}", plan.steps);
    assert_eq!(state_of(&plan, 4), refused);

    let mut units = kept_entry_scene();
    units.shards[0] = records(1, OWNER, Some(18), volume_record());
    units.verdicts.insert(18, HostEvidence::Lost);
    units.census = census_of(&[
        (shard_record(1, OWNER, Some(18)), 18),
        (shard_record(5, 15, None), 16),
    ]);
    let two_units = bounds_with(|config| {
        config.population_cap = 2;
        config.enroll_inflight_max = 2;
    });
    let plan = units.plan_under(&two_units);
    assert!(
        plans_reserve(&plan, 1) && plans_reserve(&plan, 5),
        "{:?}",
        plan.steps
    );
    assert!(releases(&plan).is_empty(), "{:?}", plan.steps);
    assert_eq!((state_of(&plan, 2), state_of(&plan, 4)), (refused, refused));
}
