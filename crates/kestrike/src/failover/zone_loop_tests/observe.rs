use core::num::NonZeroU64;
use std::collections::BTreeMap;

use crate::failover::attachments::{ControlPlane, Unlisted};
use crate::failover::loss::Health;
use crate::failover::reconcile::{Reconciler, StandbyGate};
use crate::failover::reconcile_tests::Provisioner;
use crate::failover::records::{ERA, Host, ShardRecord, VolumeId};
use crate::failover::report::tests::{bare, unavailable_headroom, unobserved};
use crate::failover::report::{
    BuildIdentity, Headroom, HostState, RecordedRole, ReportKey, VolumeEntry, Writer,
};
use crate::failover::retire::Target;
use crate::failover::sim::{host, layout};
use crate::failover::standbys::{Census, Entry, Zone};
use crate::failover::zone_loop::ZoneLoop;
use crate::failover::zone_loop::directory::{
    DerivedKey, Directory, DirectoryState, Listing, ReconcilerProjection, SuccessionRefusal,
};
use crate::failover::zone_loop::evidence::{
    HostEvidence, Instance, InstanceEvidence, InstanceState, ListedVolumeState, StatusCheck,
    VolumeCondition, VolumeStatus,
};
use crate::failover::zone_loop::observe::{
    Completeness, Observation, ShardRecords, Source, ZoneView,
};
use crate::failover::zone_loop::sources::{Unreachable, VolumeSource};
use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};
use crate::storage::store::sim::{Arm, AsProvisioner, AsReconciler, MemLog, Shared};
use crate::storage::store::{Client, Key, StoreError};
use crate::storage::store_tests::record;

use super::config::{REPORT_PERIOD_US, bounds};
use super::directory::{host_key, instance, listing, report_keys};
use super::world::{Event, Recording, World};

pub(crate) const S: u64 = 1_000_000;
pub(crate) const START: u64 = 1_000 * S;
pub(crate) const ZONE: Zone = Zone(1);
const ALL: Completeness = Completeness {
    reports: true,
    instances: true,
    volumes: true,
    store: true,
};
const ROTATED: [u8; 32] = [0x91; 32];

type Loop = ZoneLoop<Recording<AsReconciler<Shared>>, MemLog>;

pub(crate) fn volume(shard: u32) -> VolumeId {
    VolumeId::new(&format!("vol-{:02x}", 0xa0 + shard)).unwrap()
}

pub(super) fn id(shard: u32) -> Shard {
    Shard::new(shard).unwrap()
}

pub(crate) fn owner_of(shard: u32, hosts: u64) -> Host {
    host(1 + u64::from(shard) % hosts)
}

pub(super) fn condition(state: ListedVolumeState, status: VolumeStatus) -> VolumeCondition {
    VolumeCondition { state, status }
}

pub(super) fn in_use() -> VolumeCondition {
    condition(ListedVolumeState::InUse, VolumeStatus::Ok)
}

pub(super) fn error() -> VolumeCondition {
    condition(ListedVolumeState::Error, VolumeStatus::Impaired)
}

fn period() -> NonZeroU64 {
    NonZeroU64::new(REPORT_PERIOD_US).unwrap()
}

pub(super) fn reconciler(store: &Shared) -> Reconciler<AsReconciler<Shared>, MemLog> {
    Reconciler::new(Client::open(AsReconciler(store.clone()), MemLog::default()).unwrap())
}

pub(super) fn owner(store: &Shared) -> Client<Shared, MemLog> {
    Client::open(store.clone(), MemLog::default()).unwrap()
}

fn snapshot(
    hosts: u64,
    shards: u32,
    change: impl FnOnce(&mut Listing),
) -> Directory<ReconcilerProjection> {
    let mut listing = listing(hosts, shards);
    change(&mut listing);
    let keys = report_keys(&listing);
    Directory::new(listing, keys).unwrap()
}

fn rotated(version: u64) -> Directory<ReconcilerProjection> {
    let mut listing = listing(2, 1);
    listing.version = version;
    let mut keys = report_keys(&listing);
    keys[0].1 = DerivedKey::Report(ReportKey::derive(&ROTATED));
    Directory::new(listing, keys).unwrap()
}

pub(crate) struct Fixture {
    pub(crate) store: Shared,
    pub(crate) world: World,
    pub(crate) zone: Loop,
    log: MemLog,
    pub(crate) hosts: u64,
    pub(crate) shards: u32,
    pub(crate) listing: Option<Listing>,
    pub(crate) headroom: Headroom,
    writers: BTreeMap<u64, Writer>,
    elapsed: u64,
}

impl Fixture {
    pub(crate) fn new(hosts: u64, shards: u32) -> Self {
        let store = Shared::new();
        let mut provisioner =
            Reconciler::new(Client::open(AsProvisioner(store.clone()), MemLog::default()).unwrap());
        let mut reconciler = reconciler(&store);
        let mut owner = owner(&store);
        for shard in 1..=shards {
            let created = ShardRecord {
                shard: id(shard),
                active: volume(shard),
                owner: owner_of(shard, hosts),
                spare: None,
                ..record()
            };
            provisioner.create_shard(created).unwrap();
            reconciler.provision(volume(shard), layout()).unwrap();
            let attached = reconciler.record_attach(volume(shard), created.owner, ERA);
            attached.unwrap();
            let read = owner
                .read::<ShardRecord>(Key::Shard(created.shard))
                .unwrap();
            owner.bump(&read).unwrap();
        }
        let mut world = World::new(ZONE);
        for number in 1..=hosts {
            world.instances.push(Instance {
                instance: instance(number),
                state: InstanceState::Running,
                system_check: StatusCheck::Ok,
                instance_check: StatusCheck::Ok,
            });
        }
        for shard in 1..=shards {
            world.volume(volume(shard), in_use());
            world.attach(volume(shard), instance(owner_of(shard, hosts).get()));
        }
        let recording = Recording {
            inner: AsReconciler(store.clone()),
            log: world.log.clone(),
        };
        let log = MemLog::default();
        let client = Client::open(recording, log.clone()).unwrap();
        let zone = ZoneLoop::new(Reconciler::new(client), bounds());
        let writer = |number: u64| Writer::new(host(number), &host_key(number), period()).unwrap();
        let writers = (1..=hosts).map(|number| (number, writer(number))).collect();
        Self {
            store,
            world,
            zone,
            log,
            hosts,
            shards,
            listing: None,
            headroom: unavailable_headroom(),
            writers,
            elapsed: 0,
        }
    }

    pub(crate) fn directory(&self) -> Directory<ReconcilerProjection> {
        let listing = (self.listing.clone()).unwrap_or_else(|| listing(self.hosts, self.shards));
        let keys = report_keys(&listing);
        Directory::new(listing, keys).unwrap()
    }

    pub(crate) fn sealed(&mut self, number: u64, entries: &[VolumeEntry]) -> Vec<u8> {
        let state = HostState {
            headroom: self.headroom,
            ..host_state()
        };
        self.elapsed += REPORT_PERIOD_US;
        let writer = self.writers.get_mut(&number).unwrap();
        writer
            .seal(&state, entries, self.elapsed, self.elapsed)
            .unwrap()
    }

    pub(crate) fn publish(&mut self, number: u64, entries: &[VolumeEntry]) {
        let bytes = self.sealed(number, entries);
        self.world.reports.insert(host(number), bytes);
    }

    fn tick(
        &mut self,
        directory: Result<Directory<ReconcilerProjection>, Unreachable>,
        now_us: u64,
    ) -> Observation {
        let observation = self.zone.observe(directory, &mut self.world, now_us);
        let events = self.world.events();
        let wrote = events.iter().any(|seen| matches!(seen, Event::Write(_)));
        assert!(!wrote, "{events:?}");
        observation
    }

    pub(crate) fn observe(&mut self, now_us: u64) -> Observation {
        let directory = self.directory();
        self.tick(Ok(directory), now_us)
    }

    fn run(&mut self, from_us: u64, to_us: u64) -> Observation {
        let mut now_us = from_us;
        loop {
            let observation = self.observe(now_us);
            if now_us >= to_us {
                return observation;
            }
            now_us += 10 * S;
        }
    }

    pub(crate) fn spare(&mut self) -> VolumeId {
        let spare = VolumeId::new("vol-0f").unwrap();
        let mut reconciler = reconciler(&self.store);
        reconciler.provision(spare, layout()).unwrap();
        let attached = reconciler.record_attach(spare, host(1), ERA).unwrap();
        let held = owner(&self.store).read::<ShardRecord>(Key::Shard(id(2)));
        let target = Target::of(held.unwrap().value());
        reconciler.add_spare(id(2), target, &attached).unwrap();
        spare
    }

    pub(crate) fn commits(&self) -> Vec<usize> {
        let mut keys = vec![Key::Standbys(ZONE)];
        for shard in 1..=self.shards {
            keys.extend([
                Key::Shard(id(shard)),
                Key::Volume(volume(shard)),
                Key::Replacement(id(shard)),
            ]);
            keys.extend((0..record().pages.get()).map(|page| Key::Page(id(shard), page)));
        }
        let held = self.store.0.borrow();
        keys.iter().map(|key| held.commit_count(key)).collect()
    }
}

pub(crate) fn host_state() -> HostState {
    let build = BuildIdentity {
        era: ERA,
        digest: None,
    };
    unobserved(build, unavailable_headroom())
}

fn zone(observation: &Observation) -> &ZoneView {
    observation.zone.as_ref().unwrap()
}

fn records(observation: &Observation, at: usize) -> &ShardRecords {
    let records = zone(observation).shards[at].records.as_ref();
    records.unwrap().as_ref().unwrap()
}

fn verdict(observation: &Observation, number: u64) -> HostEvidence {
    let hosts = &zone(observation).hosts;
    let view = hosts.iter().find(|view| view.entry.host == host(number));
    view.unwrap().verdict
}

fn held(observation: &Observation, number: u64) -> Option<u64> {
    let hosts = &zone(observation).hosts;
    let view = hosts.iter().find(|view| view.entry.host == host(number));
    view.unwrap().report.as_ref().map(|report| report.sequence)
}

pub(crate) fn entry(name: &str, shard: u32, generation: u64, attempts: u32) -> VolumeEntry {
    VolumeEntry {
        shard: id(shard),
        tenure: Some((
            ShardGeneration::new(generation).unwrap(),
            ActivatedEpoch::new(2 * attempts).unwrap(),
        )),
        ..bare(name, RecordedRole::Owner)
    }
}

#[test]
fn observe_reads_the_evidence_then_the_census_then_each_shard_before_its_volumes() {
    let mut fixture = Fixture::new(2, 2);
    fixture.publish(1, &[]);
    fixture.publish(2, &[]);
    fixture.world.log.borrow_mut().clear();
    let observation = fixture.observe(START);
    assert_eq!(observation.unobserved(), None);
    let expected = [
        Event::Report(host(1)),
        Event::Report(host(2)),
        Event::Instances,
        Event::Volumes,
        Event::Read(Key::Standbys(ZONE)),
        Event::Read(Key::Shard(id(1))),
        Event::Read(Key::Volume(volume(1))),
        Event::Read(Key::Replacement(id(1))),
        Event::Read(Key::Shard(id(2))),
        Event::Read(Key::Volume(volume(2))),
        Event::Read(Key::Replacement(id(2))),
    ];
    assert_eq!(fixture.world.events(), expected);
    assert_eq!(observation.complete, ALL);
}

#[test]
fn a_failed_directory_snapshot_ends_the_tick_unobserved() {
    let mut fixture = Fixture::new(2, 1);
    let observation = fixture.tick(Err(Unreachable), START);
    assert_eq!(observation.unobserved(), Some(Source::Directory));
    assert_eq!(observation.complete, Completeness::default());
    assert!(fixture.world.events().is_empty());
    let foreign = snapshot(2, 0, |listing| listing.zone = Zone(2));
    let observation = fixture.tick(Ok(foreign), START);
    assert_eq!(observation.unobserved(), Some(Source::Directory));
    assert!(fixture.world.events().is_empty());
}

#[test]
fn a_failed_report_source_leaves_that_host_without_a_new_report() {
    let mut fixture = Fixture::new(2, 1);
    fixture.publish(1, &[]);
    fixture.publish(2, &[]);
    fixture.observe(START);
    fixture.publish(1, &[]);
    fixture.publish(2, &[]);
    fixture.world.faults.reports.insert(host(1));
    let observation = fixture.observe(START + 10 * S);
    let reports = false;
    assert_eq!(observation.complete, Completeness { reports, ..ALL });
    assert_eq!(
        (held(&observation, 1), held(&observation, 2)),
        (Some(1), Some(2))
    );
    let hosts = &zone(&observation).hosts;
    assert_eq!([hosts[0].answered, hosts[1].answered], [false, true]);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    assert_eq!(verdict(&observation, 2), HostEvidence::Live);
    fixture.world.faults.reports.clear();
    let observation = fixture.observe(START + 20 * S);
    assert_eq!(held(&observation, 1), Some(2));
    assert_eq!(observation.complete, ALL);
}

#[test]
fn a_failed_report_read_keeps_a_fresh_verdict_and_extends_no_freshness() {
    for ended in [false, true] {
        let mut fixture = Fixture::new(1, 1);
        if ended {
            fixture.world.instances[0].state = InstanceState::Terminated;
        }
        fixture.publish(1, &[]);
        fixture.observe(START);
        fixture.publish(1, &[]);
        fixture.observe(START + 10 * S);
        fixture.world.faults.reports.insert(host(1));
        let observation = fixture.observe(START + 20 * S);
        let fresh = match ended {
            true => HostEvidence::Conflict,
            false => HostEvidence::Live,
        };
        assert_eq!(verdict(&observation, 1), fresh, "ended {ended}");
        assert!(!observation.complete.reports);
        let silence = fixture.zone.reports.silence(host(1), START + 20 * S);
        assert_eq!(silence.silent_us, 10 * S);
        let observation = fixture.observe(START + 50 * S);
        assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    }
}

#[test]
fn an_unanswered_report_source_makes_its_host_unknown_until_a_silent_window_answers() {
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].system_check = StatusCheck::Impaired;
    fixture.publish(1, &[]);
    fixture.observe(START);
    fixture.publish(1, &[]);
    fixture.observe(START + 10 * S);
    fixture.world.faults.reports.insert(host(1));
    let observation = fixture.run(START + 20 * S, START + 400 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    fixture.world.faults.reports.clear();
    let observation = fixture.run(START + 410 * S, START + 460 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    let observation = fixture.observe(START + 470 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
}

#[test]
fn a_report_after_an_outage_reads_live() {
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].system_check = StatusCheck::Impaired;
    fixture.publish(1, &[]);
    fixture.observe(START);
    fixture.publish(1, &[]);
    fixture.observe(START + 10 * S);
    fixture.world.faults.reports.insert(host(1));
    fixture.run(START + 20 * S, START + 400 * S);
    fixture.world.faults.reports.clear();
    fixture.publish(1, &[]);
    let observation = fixture.observe(START + 410 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Live);
}

#[test]
fn a_tick_that_ends_at_the_directory_counts_as_an_unanswered_read() {
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    let observation = fixture.run(START, START + 70 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
    fixture.tick(Err(Unreachable), START + 80 * S);
    let observation = fixture.run(START + 90 * S, START + 140 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    let observation = fixture.observe(START + 150 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);

    // Two such ticks in a row restart the window at the second, and the next tick falls inside the listing gap.
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    fixture.run(START, START + 70 * S);
    fixture.tick(Err(Unreachable), START + 80 * S);
    fixture.tick(Err(Unreachable), START + 90 * S);
    let observation = fixture.run(START + 100 * S, START + 150 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    let observation = fixture.observe(START + 160 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
}

#[test]
fn a_first_report_restarts_the_silence_of_a_silent_host() {
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    let observation = fixture.run(START, START + 70 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
    fixture.publish(1, &[]);
    let observation = fixture.observe(START + 80 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    fixture.publish(1, &[]);
    let observation = fixture.observe(START + 90 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Conflict);
}

#[test]
fn an_authenticated_report_the_reader_cannot_order_is_an_unanswered_read_once() {
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    let boot = |_| Writer::new(host(1), &host_key(1), period()).unwrap();
    let mut writers: Vec<Writer> = (0..6).map(boot).collect();
    for (at, writer) in (0u64..).zip(writers.iter_mut().take(4)) {
        let bytes = writer
            .seal(&host_state(), &[], 100 * S * (at + 1), 0)
            .unwrap();
        fixture.world.reports.insert(host(1), bytes);
        fixture.observe(START + at * 10 * S);
    }
    let late = writers[4].seal(&host_state(), &[], 1, 0).unwrap();
    let later = writers[5].seal(&host_state(), &[], 2, 0).unwrap();
    fixture.world.reports.insert(host(1), late.clone());
    let observation = fixture.observe(START + 40 * S);
    assert_eq!(observation.dropped, 1);
    assert!(!zone(&observation).hosts[0].answered);
    let observation = fixture.run(START + 50 * S, START + 100 * S);
    assert!(zone(&observation).hosts[0].answered);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    let observation = fixture.observe(START + 110 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
    for tick in 12..30 {
        let refused = if tick % 2 == 0 { &later } else { &late };
        fixture.world.reports.insert(host(1), refused.clone());
        let observation = fixture.observe(START + tick * 10 * S);
        assert!(!zone(&observation).hosts[0].answered, "tick {tick}");
        assert_eq!(
            verdict(&observation, 1),
            HostEvidence::Unknown,
            "tick {tick}"
        );
    }
}

#[test]
fn a_failed_instance_listing_leaves_every_host_unknown() {
    for fault in [false, true] {
        let mut fixture = Fixture::new(2, 1);
        for listed in &mut fixture.world.instances {
            listed.state = InstanceState::Terminated;
        }
        fixture.publish(2, &[]);
        fixture.run(START, START + 70 * S);
        fixture.world.faults.instances = fault;
        fixture.publish(2, &[]);
        fixture.observe(START + 80 * S);
        let observation = fixture.observe(START + 90 * S);
        let instances = !fault;
        assert_eq!(observation.complete, Completeness { instances, ..ALL });
        let expected = match fault {
            true => [HostEvidence::Unknown; 2],
            false => [HostEvidence::Lost, HostEvidence::Conflict],
        };
        let verdicts = [verdict(&observation, 1), verdict(&observation, 2)];
        assert_eq!(verdicts, expected, "fault {fault}");
    }
}

#[test]
fn a_listing_with_two_forms_of_one_row_is_incomplete_in_either_order() {
    for reversed in [false, true] {
        let mut fixture = Fixture::new(2, 1);
        let mut ended = fixture.world.instances[0];
        ended.state = InstanceState::Terminated;
        fixture.world.instances.push(ended);
        let mut errored = fixture.world.volumes[0].clone();
        errored.condition = error();
        fixture.world.volumes.push(errored);
        if reversed {
            fixture.world.instances.reverse();
            fixture.world.volumes.reverse();
        }
        let observation = fixture.run(START, START + 70 * S);
        let (instances, volumes) = (false, false);
        let expected = Completeness {
            instances,
            volumes,
            ..ALL
        };
        assert_eq!(observation.complete, expected, "reversed {reversed}");
        assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
        assert_eq!(zone(&observation).volumes, Err(Unlisted));
        let judged = records(&observation, 0).judgement;
        assert_eq!((judged.health, judged.complete), (None, false));
    }
    let mut fixture = Fixture::new(2, 1);
    let row = fixture.world.instances[0];
    fixture.world.instances.push(row);
    let listed = fixture.world.volumes[0].clone();
    fixture.world.volumes.push(listed);
    let observation = fixture.observe(START);
    assert_eq!(observation.complete, ALL);
}

#[test]
fn a_failed_volume_listing_leaves_the_volumes_unknown_and_unlisted() {
    let mut fixture = Fixture::new(2, 1);
    fixture.observe(START - 10 * S);
    assert_eq!(
        fixture.zone.volumes.health(volume(1), fixture.zone.ticks),
        Some(Health::Available)
    );
    fixture.world.faults.volumes = true;
    let observation = fixture.observe(START);
    let volumes = false;
    assert_eq!(observation.complete, Completeness { volumes, ..ALL });
    assert_eq!(zone(&observation).volumes, Err(Unlisted));
    assert_eq!(
        fixture.zone.volumes.health(volume(1), fixture.zone.ticks),
        None
    );
    fixture.world.faults.volumes = false;
    let observation = fixture.observe(START + 10 * S);
    assert!(zone(&observation).volumes.is_ok());
    assert_eq!(
        fixture.zone.volumes.health(volume(1), fixture.zone.ticks),
        Some(Health::Available)
    );
}

#[test]
fn a_failed_census_read_leaves_the_zone_unobserved_and_reads_no_shard() {
    let mut fixture = Fixture::new(2, 2);
    fixture.store.schedule(Arm::Unavailable);
    fixture.world.log.borrow_mut().clear();
    let observation = fixture.observe(START);
    let unavailable = Source::Store(StoreError::Unavailable);
    assert_eq!(observation.unobserved(), Some(unavailable));
    let store = false;
    assert_eq!(observation.complete, Completeness { store, ..ALL });
    let shards = &zone(&observation).shards;
    assert_eq!(shards.len(), 2);
    assert!(
        shards
            .iter()
            .all(|shard| shard.records.as_ref().err() == Some(&unavailable))
    );
    let events = fixture.world.events();
    let reads: Vec<&Event> = events
        .iter()
        .filter(|seen| matches!(seen, Event::Read(_)))
        .collect();
    assert_eq!(reads, [&Event::Read(Key::Standbys(ZONE))]);
}

#[test]
fn a_failed_shard_read_leaves_that_shard_alone_unobserved() {
    let mut fixture = Fixture::new(2, 2);
    fixture.store.schedule(Arm::Pass);
    fixture.store.schedule(Arm::Unavailable);
    let observation = fixture.observe(START);
    assert_eq!(observation.unobserved(), None);
    let store = false;
    assert_eq!(observation.complete, Completeness { store, ..ALL });
    let shards = &zone(&observation).shards;
    let unavailable = Source::Store(StoreError::Unavailable);
    assert_eq!(shards[0].records.as_ref().err(), Some(&unavailable));
    let second = records(&observation, 1);
    assert_eq!(second.record.shard, id(2));
    assert_eq!(second.active.volume, volume(2));
}

#[test]
fn a_log_failure_withdraws_the_client_for_every_later_read() {
    let mut fixture = Fixture::new(2, 2);
    fixture.log.fail.set(true);
    let observation = fixture.observe(START);
    let shards = &zone(&observation).shards;
    let failed = |error| Some(Source::Store(error));
    let first = shards[0].records.as_ref().err().copied();
    assert_eq!(first, failed(StoreError::Log));
    let withdrawn = failed(StoreError::Withdrawn);
    assert_eq!(shards[1].records.as_ref().err().copied(), withdrawn);
    fixture.log.fail.set(false);
    let observation = fixture.observe(START + 10 * S);
    assert_eq!(observation.unobserved(), withdrawn);
}

#[test]
fn a_changed_tag_and_a_report_from_outside_the_directory_are_dropped_and_counted() {
    let mut fixture = Fixture::new(2, 1);
    let mut bytes = fixture.sealed(1, &[]);
    *bytes.last_mut().unwrap() ^= 1;
    fixture.world.reports.insert(host(1), bytes);
    let mut outsider = Writer::new(host(9), &host_key(9), period()).unwrap();
    let foreign = outsider
        .seal(&host_state(), &[], 1, REPORT_PERIOD_US)
        .unwrap();
    fixture.world.reports.insert(host(2), foreign);
    let observation = fixture.observe(START);
    assert_eq!(observation.dropped, 2);
    let hosts = &zone(&observation).hosts;
    assert!(hosts.iter().all(|view| view.report.is_none()));
    assert_eq!(observation.complete, ALL);
}

#[test]
fn the_same_bytes_offered_twice_extend_no_freshness() {
    let mut fixture = Fixture::new(1, 1);
    fixture.publish(1, &[]);
    fixture.observe(START);
    fixture.publish(1, &[]);
    fixture.observe(START + 10 * S);
    let observation = fixture.observe(START + 41 * S);
    assert_eq!(observation.dropped, 0);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    let silence = fixture.zone.reports.silence(host(1), START + 41 * S);
    assert_eq!(silence.silent_us, 31 * S);
    fixture.publish(1, &[]);
    let observation = fixture.observe(START + 42 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Live);
}

#[test]
fn a_report_entry_counts_for_a_shard_only_at_the_shard_records_tenure() {
    let mut fixture = Fixture::new(2, 3);
    let unbumped = ShardRecord {
        shard: id(4),
        active: volume(4),
        owner: host(1),
        spare: None,
        ..record()
    };
    let open = Client::open(AsProvisioner(fixture.store.clone()), MemLog::default());
    Reconciler::new(open.unwrap())
        .create_shard(unbumped)
        .unwrap();
    reconciler(&fixture.store)
        .provision(volume(4), layout())
        .unwrap();
    fixture.shards = 4;
    let generation = record().generation.get();
    let current = entry(volume(1).as_str(), 1, generation, 1);
    let other_volume = entry("vol-0a", 1, generation, 1);
    let sibling = entry(volume(2).as_str(), 2, generation, 1);
    let earlier = entry(volume(3).as_str(), 3, generation, 0);
    let later = entry(volume(2).as_str(), 2, generation + 1, 1);
    let ahead = entry(volume(2).as_str(), 2, generation, 2);
    let unactivated = entry(volume(4).as_str(), 4, generation, 0);
    fixture.publish(2, &[current, other_volume, sibling, earlier, unactivated]);
    fixture.publish(1, &[later]);
    let observation = fixture.observe(START);
    assert_eq!(records(&observation, 0).entries, [(host(2), current)]);
    assert_eq!(records(&observation, 1).entries, [(host(2), sibling)]);
    assert!(records(&observation, 2).entries.is_empty());
    assert!(records(&observation, 3).entries.is_empty());
    assert_eq!(records(&observation, 3).record.attempts, 0);
    let mut owner = owner(&fixture.store);
    let read = owner.read::<ShardRecord>(Key::Shard(id(1))).unwrap();
    owner.bump(&read).unwrap();
    fixture.publish(1, &[ahead]);
    let observation = fixture.observe(START + 10 * S);
    assert_eq!(observation.dropped, 0);
    assert!(records(&observation, 0).entries.is_empty());
    assert_eq!(records(&observation, 1).entries, [(host(2), sibling)]);
    let bumped = entry(volume(1).as_str(), 1, generation, 2);
    fixture.publish(2, &[bumped, sibling]);
    let observation = fixture.observe(START + 20 * S);
    assert_eq!(records(&observation, 0).entries, [(host(2), bumped)]);
}

/// A waiting standby's entry, which carries no tenure, joins no shard's entries: the host that owns shard 1 and waits
/// as shard 2's standby gives shard 1 its owner entry and shard 2 none, so the planner's owner entry and the status
/// builder's class, which read those entries, take no standby for an owner.
#[test]
fn a_waiting_standbys_entry_is_no_shards_entry_at_its_tenure() {
    let mut fixture = Fixture::new(2, 2);
    let generation = record().generation.get();
    let current = entry(volume(1).as_str(), 1, generation, 1);
    let waiting = VolumeEntry {
        role: Some(RecordedRole::Standby),
        volume_state: Some(crate::failover::records::VolumeState::Active),
        named: Some(true),
        ..VolumeEntry::unobserved(volume(2), id(2))
    };
    fixture.publish(2, &[current, waiting]);
    let observation = fixture.observe(START);
    assert_eq!(observation.dropped, 0);
    assert_eq!(records(&observation, 0).entries, [(host(2), current)]);
    assert!(records(&observation, 1).entries.is_empty());
}

#[test]
fn observe_changes_no_store_key_over_ticks_with_unmet_needs() {
    let mut fixture = Fixture::new(3, 3);
    let before = fixture.commits();
    for tick in 0..100 {
        for number in 1..=3 {
            fixture.publish(number, &[]);
        }
        fixture.observe(START + tick * 10 * S);
    }
    assert_eq!(fixture.commits(), before);
    let observation = fixture.observe(START + 1_000 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Live);
    for shard in &zone(&observation).shards {
        let records = shard.records.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(records.record.standby, None);
        assert_eq!(records.record.attempts, 1);
    }
    let evidence = (volume(1), Health::Lost);
    let gate = StandbyGate::qualified();
    let planted = (fixture.zone.reconciler).replacement(&gate, id(1), evidence, 0, layout());
    planted.unwrap();
    assert_ne!(fixture.commits(), before);
    let events = fixture.world.events();
    assert!(events.iter().any(|seen| matches!(seen, Event::Write(_))));
}

#[test]
fn the_zone_double_serves_one_listing_to_both_volume_sources() {
    let mut world = World::new(ZONE);
    world.volume(volume(1), in_use());
    world.attach(volume(1), instance(1));
    world.attach(volume(1), instance(2));
    let (first, second) = (instance(1), instance(2));
    let both = [first.as_str(), second.as_str()];
    assert_eq!(world.volumes(ZONE).unwrap()[0].attachments, both);
    assert_eq!(world.attachments(&volume(1)).unwrap(), both);
    world.detach(volume(1), instance(1));
    let remaining = [second.as_str()];
    assert_eq!(world.volumes(ZONE).unwrap()[0].attachments, remaining);
    assert_eq!(world.attachments(&volume(1)).unwrap(), remaining);
    assert_eq!(world.attachments(&volume(2)), Err(Unlisted));
    world.faults.attachments = true;
    assert_eq!(world.attachments(&volume(1)), Err(Unlisted));

    // A condition update keeps the volume's attachments, and the log holds every request in arrival order.
    world.faults.attachments = false;
    world.volume(volume(1), error());
    let listed = world.volumes(ZONE).unwrap();
    assert_eq!(listed[0].condition, error());
    assert_eq!(listed[0].attachments, remaining);
    assert_eq!(world.attachments(&volume(1)).unwrap(), remaining);
    let (zone, one, two) = (
        Event::Volumes,
        Event::Attachments(volume(1)),
        Event::Attachments(volume(2)),
    );
    let requests = [zone, one, zone, one, two, one, zone, one];
    assert_eq!(world.events(), requests);
}

#[test]
fn a_refused_report_keeps_the_report_held_before_it() {
    let mut fixture = Fixture::new(1, 1);
    fixture.publish(1, &[]);
    fixture.observe(START);
    let mut forged = fixture.sealed(1, &[]);
    *forged.last_mut().unwrap() ^= 1;
    fixture.world.reports.insert(host(1), forged);
    let observation = fixture.observe(START + 10 * S);
    assert_eq!(observation.dropped, 1);
    assert_eq!(held(&observation, 1), Some(1));
    let silence = fixture.zone.reports.silence(host(1), START + 10 * S);
    assert!(!silence.advanced);
}

#[test]
fn a_report_in_another_hosts_slot_is_dropped() {
    let mut fixture = Fixture::new(2, 1);
    let first = fixture.sealed(2, &[]);
    let second = fixture.sealed(2, &[]);
    fixture.world.reports.insert(host(2), first);
    fixture.world.reports.insert(host(1), second);
    let observation = fixture.observe(START);
    assert_eq!(observation.dropped, 1);
    let held = (held(&observation, 1), held(&observation, 2));
    assert_eq!(held, (None, Some(1)));
    assert_eq!(verdict(&observation, 2), HostEvidence::Unknown);
    assert!(!fixture.zone.reports.silence(host(2), START).advanced);

    let mut fixture = Fixture::new(2, 1);
    let directory = snapshot(3, 1, |listing| listing.hosts[2].placement.zone = Zone(2));
    let mut foreign = Writer::new(host(3), &host_key(3), period()).unwrap();
    let bytes = foreign
        .seal(&host_state(), &[], 1, REPORT_PERIOD_US)
        .unwrap();
    fixture.world.reports.insert(host(1), bytes);
    let observation = fixture.tick(Ok(directory), START);
    assert_eq!(observation.dropped, 1);
    let hosts: Vec<Host> = (zone(&observation).hosts.iter())
        .map(|view| view.entry.host)
        .collect();
    assert_eq!(hosts, [host(1), host(2)]);
    assert!(!fixture.world.events().contains(&Event::Report(host(3))));
}

#[test]
fn observe_reads_each_shard_record_then_its_volumes_then_its_receipt() {
    let mut fixture = Fixture::new(2, 2);
    let spare = fixture.spare();
    fixture.world.log.borrow_mut().clear();
    let observation = fixture.observe(START);
    let reads: Vec<Event> = (fixture.world.events().into_iter())
        .filter(|seen| matches!(seen, Event::Read(_)))
        .collect();
    let expected = [
        Key::Standbys(ZONE),
        Key::Shard(id(1)),
        Key::Volume(volume(1)),
        Key::Replacement(id(1)),
        Key::Shard(id(2)),
        Key::Volume(volume(2)),
        Key::Volume(spare),
        Key::Replacement(id(2)),
    ];
    assert_eq!(reads, expected.map(Event::Read));
    let named = records(&observation, 1).spare.as_ref();
    assert_eq!(named.unwrap().volume, spare);
}

/// The loop reads a receipt's created volume as a replacement in creation when the receipt is of a later generation
/// and the volume is outside the shard record's roles. A receipt at the record's generation is served, and a volume
/// the record names spare is read once, as the spare.
#[test]
fn only_an_unnamed_volume_of_a_later_generation_receipt_is_read_as_a_replacement() {
    let created = |fixture: &Fixture, later: bool, volume: VolumeId| {
        let held = owner(&fixture.store).read::<ShardRecord>(Key::Shard(id(2)));
        let record = *held.unwrap().value();
        let generation = record.generation.get() + u64::from(later);
        let receipt = crate::failover::loss::Receipt {
            request: crate::failover::loss::Request {
                namespace: record.namespace,
                shard: record.shard,
                generation: ShardGeneration::new(generation).unwrap(),
            },
            phase: crate::failover::loss::Phase::Created(volume),
            ..crate::failover::loss::tests::receipt()
        };
        let open = Client::open(AsReconciler(fixture.store.clone()), MemLog::default());
        open.unwrap()
            .create(Key::Replacement(id(2)), receipt)
            .unwrap();
    };
    let reads = |fixture: &mut Fixture| {
        fixture.world.log.borrow_mut().clear();
        let observation = fixture.observe(START);
        let reads: Vec<Event> = (fixture.world.events().into_iter())
            .filter(|seen| matches!(seen, Event::Read(_)))
            .collect();
        (observation, reads)
    };
    let first = [
        Key::Standbys(ZONE),
        Key::Shard(id(1)),
        Key::Volume(volume(1)),
        Key::Replacement(id(1)),
        Key::Shard(id(2)),
        Key::Volume(volume(2)),
    ];

    let mut served = Fixture::new(2, 2);
    created(&served, false, VolumeId::new("vol-0e").unwrap());
    let (observation, read) = reads(&mut served);
    let mut expected = first.to_vec();
    expected.push(Key::Replacement(id(2)));
    assert_eq!(
        read,
        expected
            .iter()
            .copied()
            .map(Event::Read)
            .collect::<Vec<_>>()
    );
    assert!(records(&observation, 1).receipt.is_some());
    assert!(records(&observation, 1).replacement.is_none());

    let mut named = Fixture::new(2, 2);
    let spare = named.spare();
    created(&named, true, spare);
    let (observation, read) = reads(&mut named);
    let mut expected = first.to_vec();
    expected.extend([Key::Volume(spare), Key::Replacement(id(2))]);
    assert_eq!(
        read,
        expected
            .iter()
            .copied()
            .map(Event::Read)
            .collect::<Vec<_>>()
    );
    assert!(records(&observation, 1).replacement.is_none());
    let read_spare = records(&observation, 1).spare.as_ref();
    assert_eq!(read_spare.map(|record| record.volume), Some(spare));
}

#[test]
fn a_failed_spare_or_receipt_read_fails_its_shard_alone() {
    for (passes, failed) in [(6, 1), (3, 0)] {
        let mut fixture = Fixture::new(2, 2);
        fixture.spare();
        for _ in 0..passes {
            fixture.store.schedule(Arm::Pass);
        }
        fixture.store.schedule(Arm::Unavailable);
        let observation = fixture.observe(START);
        let shards = &zone(&observation).shards;
        let unavailable = Source::Store(StoreError::Unavailable);
        assert_eq!(shards[failed].records.as_ref().err(), Some(&unavailable));
        let sibling = shards[1 - failed].records.as_ref();
        assert!(sibling.is_ok_and(Option::is_some));
        assert!(!observation.complete.store);
    }
}

#[test]
fn observe_returns_the_stored_census_and_receipt() {
    let mut fixture = Fixture::new(2, 2);
    let observation = fixture.observe(START);
    assert_eq!(zone(&observation).census, Ok(Census::empty(ZONE)));
    assert!(records(&observation, 1).receipt.is_none());
    let held = owner(&fixture.store).read::<ShardRecord>(Key::Shard(id(1)));
    let slot = Entry {
        target: Target::of(held.unwrap().value()),
        host: host(1),
    };
    let census = crate::failover::standbys::tests::listing(ZONE, id(1), slot);
    let open = Client::open(AsReconciler(fixture.store.clone()), MemLog::default());
    open.unwrap().create(Key::Standbys(ZONE), census).unwrap();
    let mut reconciler = reconciler(&fixture.store);
    let evidence = (volume(2), Health::Lost);
    let gate = StandbyGate::qualified();
    let started = reconciler.replacement(&gate, id(2), evidence, 0, layout());
    let receipt = started.unwrap().unwrap().into_value();
    for tick in 1..=2 {
        let observation = fixture.observe(START + tick * 10 * S);
        let census = zone(&observation).census.as_ref().unwrap();
        assert_eq!((census.slot(id(1)), census.slot(id(2))), (Some(slot), None));
        assert_eq!(records(&observation, 1).receipt.as_ref(), Some(&receipt));
        assert!(records(&observation, 0).receipt.is_none());
    }
}

#[test]
fn a_failed_volume_read_fails_its_shard_and_an_absent_shard_record_is_none() {
    let mut fixture = Fixture::new(2, 2);
    for arm in [Arm::Pass, Arm::Pass, Arm::Unavailable] {
        fixture.store.schedule(arm);
    }
    let observation = fixture.observe(START);
    let shards = &zone(&observation).shards;
    let unavailable = Source::Store(StoreError::Unavailable);
    assert_eq!(shards[0].records.as_ref().err(), Some(&unavailable));
    assert!(shards[1].records.as_ref().is_ok_and(Option::is_some));

    let mut fixture = Fixture::new(2, 1);
    let wider = snapshot(2, 2, |listing| listing.version = 2);
    fixture.observe(START);
    let observation = fixture.tick(Ok(wider), START + 10 * S);
    let shards = &zone(&observation).shards;
    assert!(matches!(shards[1].records, Ok(None)));
    assert!(observation.complete.store);
}

#[test]
fn an_older_or_altered_directory_snapshot_is_unobserved() {
    let mut fixture = Fixture::new(2, 1);
    let newer = snapshot(2, 1, |listing| listing.version = 2);
    fixture.tick(Ok(newer), START);
    let version = Some(Source::Succession(SuccessionRefusal::Version));
    fixture.world.log.borrow_mut().clear();
    let observation = fixture.observe(START + 10 * S);
    assert_eq!(observation.unobserved(), version);
    assert_eq!(observation.complete, Completeness::default());
    assert!(fixture.world.events().is_empty());
    type Change = fn(&mut Listing);
    let changes: [Change; 4] = [
        |l| l.zone_hold = true,
        |l| l.hosts[0].instance = instance(9),
        |l| l.shards.clear(),
        |l| l.host_roles_max = 3,
    ];
    for change in changes {
        let same = snapshot(2, 1, |listing| {
            listing.version = 2;
            change(listing);
        });
        let observation = fixture.tick(Ok(same), START + 30 * S);
        assert_eq!(observation.unobserved(), version);
        assert!(fixture.world.events().is_empty());
    }
}

#[test]
fn a_directory_that_renames_an_instance_is_unobserved() {
    let mut fixture = Fixture::new(2, 1);
    fixture.publish(1, &[]);
    fixture.observe(START);
    let renamed = snapshot(2, 1, |listing| {
        listing.version = 2;
        listing.hosts[0].instance = instance(9);
    });
    let observation = fixture.tick(Ok(renamed), START + 10 * S);
    let reassigned = Source::Succession(SuccessionRefusal::Reassigned(host(1)));
    assert_eq!(observation.unobserved(), Some(reassigned));
    let observation = fixture.observe(START + 20 * S);
    assert_eq!(held(&observation, 1), Some(1));
}

#[test]
fn a_same_version_snapshot_with_another_report_key_is_refused() {
    let mut fixture = Fixture::new(2, 1);
    fixture.publish(1, &[]);
    fixture.observe(START);
    fixture.world.log.borrow_mut().clear();
    let observation = fixture.tick(Ok(rotated(1)), START + 10 * S);
    let version = Source::Succession(SuccessionRefusal::Version);
    assert_eq!(observation.unobserved(), Some(version));
    assert!(fixture.world.events().is_empty());
    fixture.publish(1, &[]);
    let observation = fixture.observe(START + 20 * S);
    assert_eq!(held(&observation, 1), Some(2));
    assert_eq!(verdict(&observation, 1), HostEvidence::Live);
}

#[test]
fn a_rotated_report_key_drops_the_reports_of_the_earlier_key() {
    let mut fixture = Fixture::new(2, 1);
    fixture.publish(1, &[]);
    fixture.publish(2, &[]);
    fixture.observe(START);
    fixture.publish(1, &[]);
    fixture.publish(2, &[]);
    let observation = fixture.observe(START + 10 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Live);
    let observation = fixture.tick(Ok(rotated(2)), START + 20 * S);
    assert_eq!(observation.unobserved(), None);
    assert_eq!(observation.dropped, 1);
    assert_eq!(held(&observation, 1), None);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    assert_eq!(held(&observation, 2), Some(2));
    assert_eq!(verdict(&observation, 2), HostEvidence::Live);
    let kept = fixture.zone.reports.silence(host(2), START + 20 * S);
    assert_eq!((kept.advanced, kept.silent_us), (true, 10 * S));
    let mut writer = Writer::new(host(1), &ROTATED, period()).unwrap();
    let bytes = writer.seal(&host_state(), &[], 1, 0).unwrap();
    fixture.world.reports.insert(host(1), bytes);
    let observation = fixture.tick(Ok(rotated(2)), START + 30 * S);
    assert_eq!(observation.dropped, 0);
    assert_eq!(held(&observation, 1), Some(1));
    assert!(
        !fixture
            .zone
            .reports
            .silence(host(1), START + 30 * S)
            .advanced
    );
}

#[test]
fn each_shard_carries_the_judgement_of_its_active_volume() {
    let mut fixture = Fixture::new(2, 2);
    fixture.world.volume(volume(2), error());
    let observation = fixture.observe(START);
    let first = records(&observation, 1).judgement.health;
    assert_eq!(first, Some(Health::Impaired));
    fixture.world.faults.volumes = true;
    let observation = fixture.observe(START + 10 * S);
    let volumes = false;
    assert_eq!(observation.complete, Completeness { volumes, ..ALL });
    for at in 0..2 {
        let judged = records(&observation, at).judgement;
        assert_eq!((judged.health, judged.complete), (None, false));
    }
    fixture.world.faults.volumes = false;
    let observation = fixture.observe(START + 20 * S);
    let restarted = records(&observation, 1).judgement.health;
    assert_eq!(restarted, Some(Health::Impaired));
    let observation = fixture.observe(START + 30 * S);
    let judged = |at: usize| records(&observation, at).judgement;
    assert_eq!(judged(1).health, Some(Health::Lost));
    assert_eq!(
        (judged(0).health, judged(0).others),
        (Some(Health::Available), 1)
    );
    assert!(judged(0).complete && judged(1).complete);
}

#[test]
fn a_named_spare_counts_beside_a_lost_volume() {
    let impaired = condition(ListedVolumeState::InUse, VolumeStatus::Impaired);
    let unvalued = condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData);
    let cases = [
        (in_use(), 0, true),
        (impaired, 1, true),
        (unvalued, 0, false),
    ];
    for (listed, others, complete) in cases {
        let mut fixture = Fixture::new(2, 2);
        let spare = fixture.spare();
        fixture.world.volume(spare, listed);
        fixture.world.volume(volume(1), error());
        fixture.observe(START);
        let observation = fixture.observe(START + 10 * S);
        let judged = records(&observation, 0).judgement;
        let expected = (Some(Health::Lost), others, complete);
        assert_eq!((judged.health, judged.others, judged.complete), expected);
    }
}

#[test]
fn a_replacement_in_creation_counts_beside_a_lost_volume() {
    let mut fixture = Fixture::new(2, 2);
    let mut reconciler = reconciler(&fixture.store);
    let gate = StandbyGate::qualified();
    let evidence = (volume(2), Health::Lost);
    reconciler
        .replacement(&gate, id(2), evidence, 0, layout())
        .unwrap();
    let mut provider = Provisioner::default();
    let created = reconciler.create_replacement(&gate, id(2), 0, &mut provider);
    let replacement = created.unwrap().value().volume;
    let creating = condition(ListedVolumeState::Creating, VolumeStatus::Ok);
    fixture.world.volume(replacement, creating);
    fixture.world.volume(volume(1), error());
    fixture.observe(START);
    let observation = fixture.observe(START + 10 * S);
    let judged = records(&observation, 0).judgement;
    assert_eq!((judged.health, judged.others), (Some(Health::Lost), 1));
}

#[test]
fn an_unread_shard_leaves_every_volume_judgement_incomplete() {
    let mut fixture = Fixture::new(2, 2);
    fixture.world.volume(volume(1), error());
    fixture.world.volume(volume(2), error());
    fixture.observe(START);
    fixture.store.schedule(Arm::Pass);
    fixture.store.schedule(Arm::Unavailable);
    let observation = fixture.observe(START + 10 * S);
    let shards = &zone(&observation).shards;
    assert!(shards[0].records.is_err());
    let second = records(&observation, 1);
    assert_eq!(second.judgement.health, Some(Health::Lost));
    assert!(!second.judgement.complete);
}

#[test]
fn a_retired_host_stays_lost_while_its_report_source_fails() {
    let mut fixture = Fixture::new(2, 1);
    fixture.observe(START);
    let retired = snapshot(2, 1, |listing| {
        listing.version = 2;
        listing.hosts[1].state = DirectoryState::Retired;
    });
    fixture.world.faults.reports.insert(host(2));
    let observation = fixture.tick(Ok(retired), START + 10 * S);
    assert_eq!(verdict(&observation, 2), HostEvidence::Lost);
}

#[test]
fn an_absent_active_volume_record_fails_its_shard() {
    let mut fixture = Fixture::new(2, 2);
    let open = Client::open(AsProvisioner(fixture.store.clone()), MemLog::default());
    let created = ShardRecord {
        shard: id(3),
        active: volume(3),
        owner: host(1),
        spare: None,
        ..record()
    };
    Reconciler::new(open.unwrap())
        .create_shard(created)
        .unwrap();
    fixture.shards = 3;
    let observation = fixture.observe(START);
    let shards = &zone(&observation).shards;
    let absent = Source::Store(StoreError::Absent);
    assert_eq!(shards[2].records.as_ref().err(), Some(&absent));
    assert!(!observation.complete.store);
}

#[test]
fn an_unobserved_stretch_counts_as_an_unanswered_read() {
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    let observation = fixture.run(START, START + 70 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
    fixture.world.faults.reports.insert(host(1));
    fixture.observe(START + 80 * S);
    fixture.world.faults.reports.clear();
    let observation = fixture.observe(START + 200 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    let observation = fixture.run(START + 210 * S, START + 260 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
    let observation = fixture.observe(START + 270 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);

    // A call exactly `LISTING_GAP_TICKS` ticks after the previous one is inside the gap and keeps the verdict.
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    fixture.run(START, START + 70 * S);
    let observation = fixture.observe(START + 90 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
    let observation = fixture.observe(START + 111 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
}

#[test]
fn reports_alternating_between_two_boots_never_read_lost() {
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    let boot = |_| Writer::new(host(1), &host_key(1), period()).unwrap();
    let mut writers: Vec<Writer> = (0..2).map(boot).collect();
    for tick in 0u64..30 {
        let elapsed = (tick / 2 + 1) * REPORT_PERIOD_US;
        let writer = &mut writers[(tick % 2) as usize];
        let bytes = writer.seal(&host_state(), &[], elapsed, elapsed).unwrap();
        fixture.world.reports.insert(host(1), bytes);
        let observation = fixture.observe(START + tick * 10 * S);
        assert_eq!(observation.dropped, 0, "tick {tick}");
        assert_ne!(verdict(&observation, 1), HostEvidence::Lost, "tick {tick}");
        let silence = fixture.zone.reports.silence(host(1), START + tick * 10 * S);
        assert!(silence.silent_us <= 10 * S, "tick {tick}");
    }
    let silence = fixture.zone.reports.silence(host(1), START + 290 * S);
    assert_eq!(silence.silent_us, 0);
}

#[test]
fn a_replayed_older_report_is_an_unanswered_read() {
    let mut fixture = Fixture::new(2, 1);
    let first = fixture.sealed(1, &[]);
    fixture.world.reports.insert(host(1), first.clone());
    fixture.observe(START);
    fixture.publish(1, &[]);
    fixture.observe(START + 10 * S);
    fixture.world.reports.insert(host(1), first.clone());
    let observation = fixture.observe(START + 20 * S);
    assert_eq!(observation.dropped, 1);
    assert!(!zone(&observation).hosts[0].answered);
    assert_eq!(held(&observation, 1), Some(2));
    fixture.tick(Ok(rotated(2)), START + 30 * S);
    let restored = snapshot(2, 1, |listing| listing.version = 3);
    let observation = fixture.tick(Ok(restored.clone()), START + 40 * S);
    assert_eq!(observation.dropped, 1);
    assert!(!zone(&observation).hosts[0].answered);
    assert_eq!(held(&observation, 1), None);
    fixture.publish(1, &[]);
    let observation = fixture.tick(Ok(restored), START + 50 * S);
    assert_eq!(held(&observation, 1), Some(3));
    assert!(
        !fixture
            .zone
            .reports
            .silence(host(1), START + 50 * S)
            .advanced
    );
}

/// Consecutive reads of identical refused bytes count as answered after the first. After a held, missing,
/// unreachable or unreadable result, the first read of the same refused bytes counts as unanswered.
#[test]
fn a_refused_report_that_reappears_after_another_read_is_an_unanswered_read() {
    for between in ["held", "none", "unreachable", "unreadable"] {
        let mut fixture = Fixture::new(1, 1);
        fixture.world.instances[0].state = InstanceState::Terminated;
        let first = fixture.sealed(1, &[]);
        let second = fixture.sealed(1, &[]);
        fixture.world.reports.insert(host(1), first.clone());
        fixture.observe(START);
        fixture.world.reports.insert(host(1), second.clone());
        fixture.observe(START + 10 * S);
        fixture.world.reports.insert(host(1), first.clone());
        let observation = fixture.observe(START + 20 * S);
        assert_eq!(observation.dropped, 1, "{between}");
        assert!(!zone(&observation).hosts[0].answered, "{between}");
        match between {
            "held" => drop(fixture.world.reports.insert(host(1), second)),
            "none" => drop(fixture.world.reports.remove(&host(1))),
            "unreachable" => drop(fixture.world.faults.reports.insert(host(1))),
            _ => drop(fixture.world.reports.insert(host(1), vec![0; 8])),
        }
        let observation = fixture.run(START + 30 * S, START + 80 * S);
        let unreachable = between == "unreachable";
        assert_eq!(
            zone(&observation).hosts[0].answered,
            !unreachable,
            "{between}"
        );
        assert_eq!(held(&observation, 1), Some(2), "{between}");
        assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
        fixture.world.faults.reports.clear();
        fixture.world.reports.insert(host(1), first);
        let observation = fixture.observe(START + 90 * S);
        assert_eq!(observation.dropped, 1, "{between}");
        assert!(!zone(&observation).hosts[0].answered, "{between}");
        assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
        let observation = fixture.run(START + 100 * S, START + 150 * S);
        assert_eq!(observation.dropped, 1, "{between}");
        assert!(zone(&observation).hosts[0].answered, "{between}");
        assert_eq!(verdict(&observation, 1), HostEvidence::Unknown);
        let observation = fixture.observe(START + 160 * S);
        assert_eq!(verdict(&observation, 1), HostEvidence::Lost, "{between}");
    }
}

/// A rekey clears the host's held report. After the key is restored, the same report bytes are dropped: the first
/// read counts as unanswered and the next as answered.
#[test]
fn a_restored_report_key_reads_the_forgotten_report_as_a_refused_duplicate() {
    let mut fixture = Fixture::new(2, 1);
    fixture.publish(1, &[]);
    let observation = fixture.observe(START);
    assert_eq!(held(&observation, 1), Some(1));
    let observation = fixture.tick(Ok(rotated(2)), START + 10 * S);
    assert_eq!((observation.dropped, held(&observation, 1)), (1, None));
    let restored = snapshot(2, 1, |listing| listing.version = 3);
    let observation = fixture.tick(Ok(restored.clone()), START + 20 * S);
    assert_eq!(observation.dropped, 1);
    assert!(!zone(&observation).hosts[0].answered);
    assert_eq!(held(&observation, 1), None);
    let observation = fixture.tick(Ok(restored), START + 30 * S);
    assert_eq!(observation.dropped, 1);
    assert!(zone(&observation).hosts[0].answered);
    assert_eq!(held(&observation, 1), None);
}

#[test]
fn a_rotated_report_key_restarts_the_silent_window() {
    let mut fixture = Fixture::new(2, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    let observation = fixture.run(START, START + 70 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
    let mut now = START + 80 * S;
    while now <= START + 140 * S {
        let observation = fixture.tick(Ok(rotated(2)), now);
        assert_eq!(verdict(&observation, 1), HostEvidence::Unknown, "at {now}");
        now += 10 * S;
    }
    let observation = fixture.tick(Ok(rotated(2)), START + 150 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
}

#[test]
fn a_tick_that_ends_at_the_directory_restarts_the_listing_runs() {
    let mut fixture = Fixture::new(2, 1);
    fixture.world.volume(volume(1), error());
    fixture.world.instances.remove(1);
    let observation = fixture.observe(START);
    assert_eq!(
        records(&observation, 0).judgement.health,
        Some(Health::Impaired)
    );
    fixture.tick(Err(Unreachable), START + 10 * S);
    let observation = fixture.observe(START + 20 * S);
    assert_eq!(
        records(&observation, 0).judgement.health,
        Some(Health::Impaired)
    );
    let absent = fixture.zone.instances.evidence(host(2), fixture.zone.ticks);
    assert_eq!(absent, InstanceEvidence::Absent { ticks: 1 });
    let observation = fixture.observe(START + 30 * S);
    assert_eq!(
        records(&observation, 0).judgement.health,
        Some(Health::Lost)
    );
}

#[test]
fn calls_inside_one_tick_count_one_observation() {
    let mut fixture = Fixture::new(2, 1);
    fixture.world.volume(volume(1), error());
    fixture.run(START, START + 70 * S);
    fixture.world.instances.remove(1);
    for now in [START + 80 * S, START + 80 * S, START + 82 * S] {
        let observation = fixture.observe(now);
        let judged = records(&observation, 0).judgement.health;
        assert_eq!(judged, Some(Health::Lost));
        assert_eq!(verdict(&observation, 2), HostEvidence::Unknown, "at {now}");
    }
    let mut fixture = Fixture::new(2, 1);
    fixture.world.volume(volume(1), error());
    for now in [START, START, START + 3 * S] {
        let observation = fixture.observe(now);
        let judged = records(&observation, 0).judgement.health;
        assert_eq!(judged, Some(Health::Impaired), "at {now}");
    }
    let observation = fixture.observe(START + 10 * S);
    assert_eq!(
        records(&observation, 0).judgement.health,
        Some(Health::Lost)
    );

    // A call one microsecond short of half a tick after the counted one repeats the tick; one at half a tick counts.
    let mut fixture = Fixture::new(2, 1);
    fixture.world.volume(volume(1), error());
    let half = fixture.zone.bounds.config().tick_us / 2;
    for (now, health) in [
        (START, Health::Impaired),
        (START + half - 1, Health::Impaired),
        (START + half, Health::Lost),
    ] {
        let observation = fixture.observe(now);
        let judged = records(&observation, 0).judgement.health;
        assert_eq!(judged, Some(health), "at {now}");
    }
}

/// The first complete listing consumes the tick's credit. A later directory or volume-listing failure leaves that
/// credit spent.
#[test]
fn a_call_after_a_failed_one_inside_a_counted_tick_earns_no_credit() {
    for at_directory in [false, true] {
        let mut fixture = Fixture::new(2, 1);
        fixture.observe(START);
        if at_directory {
            fixture.tick(Err(Unreachable), START + S);
        } else {
            fixture.world.faults.volumes = true;
            let observation = fixture.observe(START + S);
            assert_eq!(records(&observation, 0).judgement.health, None);
            fixture.world.faults.volumes = false;
        }
        fixture.world.volume(volume(1), error());
        for now in [START + 2 * S, START + 5 * S] {
            let observation = fixture.observe(now);
            let judged = records(&observation, 0).judgement.health;
            let case = format!("at_directory {at_directory} at {now}");
            assert_eq!(judged, Some(Health::Impaired), "{case}");
        }
        let observation = fixture.observe(START + 15 * S);
        let judged = records(&observation, 0).judgement.health;
        assert_eq!(judged, Some(Health::Lost), "at_directory {at_directory}");
    }
}

#[test]
fn volume_rows_that_differ_only_in_attachments_are_two_forms() {
    for reversed in [false, true] {
        let mut fixture = Fixture::new(2, 1);
        fixture.world.volume(volume(1), error());
        let observation = fixture.observe(START);
        assert_eq!(
            records(&observation, 0).judgement.health,
            Some(Health::Impaired)
        );
        let mut other = fixture.world.volumes[0].clone();
        other.attachments.push(instance(2).as_str().to_owned());
        fixture.world.volumes.push(other);
        if reversed {
            fixture.world.volumes.reverse();
        }
        let observation = fixture.observe(START + 10 * S);
        let volumes = false;
        assert_eq!(observation.complete, Completeness { volumes, ..ALL });
        assert_eq!(zone(&observation).volumes, Err(Unlisted));
        assert_eq!(records(&observation, 0).judgement.health, None);
        fixture.world.volumes.truncate(1);
        fixture.world.volumes[0].attachments.truncate(1);
        let observation = fixture.observe(START + 20 * S);
        let judged = records(&observation, 0).judgement.health;
        assert_eq!(judged, Some(Health::Impaired), "reversed {reversed}");
    }
}

#[test]
fn a_shards_own_replacement_stays_out_of_its_correlated_count() {
    for impaired_peer in [false, true] {
        let mut fixture = Fixture::new(2, 2);
        let mut reconciler = reconciler(&fixture.store);
        let gate = StandbyGate::qualified();
        let evidence = (volume(2), Health::Lost);
        reconciler
            .replacement(&gate, id(2), evidence, 0, layout())
            .unwrap();
        let mut provider = Provisioner::default();
        let created = reconciler.create_replacement(&gate, id(2), 0, &mut provider);
        let replacement = created.unwrap().value().volume;
        let creating = condition(ListedVolumeState::Creating, VolumeStatus::Ok);
        fixture.world.volume(replacement, creating);
        fixture.world.volume(volume(2), error());
        if impaired_peer {
            let warning = condition(ListedVolumeState::InUse, VolumeStatus::Warning);
            fixture.world.volume(volume(1), warning);
        }
        fixture.observe(START);
        let observation = fixture.observe(START + 10 * S);
        let judged = records(&observation, 1).judgement;
        let expected = (Some(Health::Lost), usize::from(impaired_peer), true);
        assert_eq!((judged.health, judged.others, judged.complete), expected);
        let read = records(&observation, 1).replacement.as_ref();
        assert_eq!(read.map(|record| record.volume), Some(replacement));
    }
}

#[test]
fn a_shards_own_spare_counts_beside_its_lost_active_volume() {
    let impaired = condition(ListedVolumeState::InUse, VolumeStatus::Impaired);
    let unvalued = condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData);
    let cases = [
        (in_use(), 0, true),
        (impaired, 1, true),
        (unvalued, 0, false),
    ];
    for (listed, others, complete) in cases {
        let mut fixture = Fixture::new(2, 2);
        let spare = fixture.spare();
        fixture.world.volume(spare, listed);
        fixture.world.volume(volume(2), error());
        fixture.observe(START);
        let observation = fixture.observe(START + 10 * S);
        let judged = records(&observation, 1).judgement;
        let expected = (Some(Health::Lost), others, complete);
        assert_eq!((judged.health, judged.others, judged.complete), expected);
    }
}

#[test]
fn a_replacement_named_spare_stays_out_of_its_shards_correlated_count() {
    let impaired = condition(ListedVolumeState::InUse, VolumeStatus::Impaired);
    let unvalued = condition(ListedVolumeState::InUse, VolumeStatus::InsufficientData);
    for listed in [impaired, unvalued] {
        let mut fixture = Fixture::new(2, 2);
        let mut reconciler = reconciler(&fixture.store);
        let gate = StandbyGate::qualified();
        let evidence = (volume(2), Health::Lost);
        reconciler
            .replacement(&gate, id(2), evidence, 0, layout())
            .unwrap();
        let mut provider = Provisioner::default();
        let created = reconciler.create_replacement(&gate, id(2), 0, &mut provider);
        let replacement = created.unwrap().value().volume;
        let attached = reconciler.record_attach(replacement, host(1), ERA).unwrap();
        let held = owner(&fixture.store).read::<ShardRecord>(Key::Shard(id(2)));
        let target = Target::of(held.unwrap().value());
        reconciler.add_spare(id(2), target, &attached).unwrap();
        fixture.world.volume(replacement, listed);
        fixture.world.volume(volume(2), error());
        fixture.observe(START);
        let observation = fixture.observe(START + 10 * S);
        let shard = records(&observation, 1);
        let spare = shard.spare.as_ref().map(|record| record.volume);
        assert_eq!(
            (spare, shard.replacement.is_none()),
            (Some(replacement), true)
        );
        let judged = shard.judgement;
        let expected = (Some(Health::Lost), 0, true);
        assert_eq!((judged.health, judged.others, judged.complete), expected);
    }
}

#[test]
fn a_retired_replacement_in_creation_stays_out_of_every_count() {
    for listed in [true, false] {
        let mut fixture = Fixture::new(2, 2);
        let mut reconciler = reconciler(&fixture.store);
        let gate = StandbyGate::qualified();
        let evidence = (volume(2), Health::Lost);
        reconciler
            .replacement(&gate, id(2), evidence, 0, layout())
            .unwrap();
        let mut provider = Provisioner::default();
        let created = reconciler.create_replacement(&gate, id(2), 0, &mut provider);
        let replacement = created.unwrap().value().volume;
        reconciler.retire(id(2), replacement).unwrap();
        if listed {
            fixture.world.volume(replacement, error());
        }
        fixture.world.volume(volume(1), error());
        fixture.observe(START);
        let observation = fixture.observe(START + 10 * S);
        let judged = records(&observation, 0).judgement;
        let expected = (Some(Health::Lost), 0, true);
        assert_eq!((judged.health, judged.others, judged.complete), expected);
    }
}

#[test]
fn a_same_version_snapshot_cannot_return_a_retired_host_to_active() {
    let mut fixture = Fixture::new(2, 1);
    let retired = snapshot(2, 1, |listing| {
        listing.version = 2;
        listing.hosts[1].state = DirectoryState::Retired;
    });
    fixture.tick(Ok(retired.clone()), START);
    let active = snapshot(2, 1, |listing| listing.version = 2);
    fixture.world.log.borrow_mut().clear();
    let observation = fixture.tick(Ok(active), START + 10 * S);
    let version = Source::Succession(SuccessionRefusal::Version);
    assert_eq!(observation.unobserved(), Some(version));
    assert!(fixture.world.events().is_empty());
    let observation = fixture.tick(Ok(retired), START + 20 * S);
    assert_eq!(verdict(&observation, 2), HostEvidence::Lost);
}

#[test]
fn a_refused_succession_counts_as_an_unanswered_read() {
    let mut fixture = Fixture::new(1, 1);
    fixture.world.instances[0].state = InstanceState::Terminated;
    let newer = snapshot(1, 1, |listing| listing.version = 2);
    let mut now = START;
    while now <= START + 70 * S {
        fixture.tick(Ok(newer.clone()), now);
        now += 10 * S;
    }
    let observation = fixture.observe(START + 80 * S);
    let version = Source::Succession(SuccessionRefusal::Version);
    assert_eq!(observation.unobserved(), Some(version));
    let mut now = START + 90 * S;
    while now <= START + 140 * S {
        let observation = fixture.tick(Ok(newer.clone()), now);
        assert_eq!(verdict(&observation, 1), HostEvidence::Unknown, "at {now}");
        now += 10 * S;
    }
    let observation = fixture.tick(Ok(newer), START + 150 * S);
    assert_eq!(verdict(&observation, 1), HostEvidence::Lost);
}
