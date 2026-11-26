use std::collections::BTreeSet;

use crate::failover::arbiter::Partition;
use crate::failover::detect::beat::BeatKey;
use crate::failover::detect::probe::ProbeKey;
use crate::failover::records::{Host, LayoutRefusal};
use crate::failover::report::{MAX_ENTRIES, ReportKey};
pub(crate) use crate::failover::sim::instance;
use crate::failover::sim::{host, layout};
use crate::failover::standbys::{MAX_SLOTS, Zone};
use crate::failover::zone_loop::directory::*;
use crate::net::ownership::Shard;

pub(crate) fn entry(number: u64, partition: u32) -> HostEntry {
    HostEntry {
        host: host(number),
        instance: instance(number),
        placement: Placement {
            zone: Zone(1),
            partition: Partition(partition),
            color: Color(0),
        },
        state: DirectoryState::Active,
    }
}

pub(crate) fn shard_entry(shard: u32) -> ShardEntry {
    ShardEntry {
        shard: Shard::new(shard).unwrap(),
        zone: Zone(1),
        layout: layout(),
    }
}

pub(crate) fn listing(hosts: u64, shards: u32) -> Listing {
    Listing {
        version: 1,
        zone: Zone(1),
        zone_hold: false,
        host_roles_max: 10,
        hosts: (1..=hosts).map(|n| entry(n, (n % 3) as u32)).collect(),
        shards: (1..=shards).map(shard_entry).collect(),
    }
}

/// The host key of host `number`: every byte of the number, so no two hosts of a listing share one.
pub(crate) fn host_key(number: u64) -> [u8; 32] {
    let mut key = [0; 32];
    for chunk in key.chunks_mut(8) {
        chunk.copy_from_slice(&number.to_le_bytes());
    }
    key
}

fn report_key(number: u64) -> DerivedKey {
    DerivedKey::Report(ReportKey::derive(&host_key(number)))
}

pub(crate) fn report_keys(listing: &Listing) -> Vec<(Host, DerivedKey)> {
    let keyed = |entry: &HostEntry| (entry.host, report_key(entry.host.get()));
    listing.hosts.iter().map(keyed).collect()
}

fn beat_keys(listing: &Listing) -> Vec<(Host, DerivedKey)> {
    let key = |entry: &HostEntry| BeatKey::derive(&host_key(entry.host.get()));
    let keyed = |entry: &HostEntry| (entry.host, DerivedKey::Heartbeat(key(entry)));
    listing.hosts.iter().map(keyed).collect()
}

fn probe_keys(listing: &Listing) -> Vec<(Host, DerivedKey)> {
    let key = |entry: &HostEntry| ProbeKey::derive(&host_key(entry.host.get()));
    let keyed = |entry: &HostEntry| (entry.host, DerivedKey::Probe(key(entry)));
    listing.hosts.iter().map(keyed).collect()
}

/// The host projection's keys of `listing`: a heartbeat key for every listed host, then a probe key for each.
fn host_keys(listing: &Listing) -> Vec<(Host, DerivedKey)> {
    let mut keys = beat_keys(listing);
    keys.extend(probe_keys(listing));
    keys
}

/// The reconciler's directory of `listing`, with a report key for every listed host.
fn build(listing: Listing) -> Result<Directory<ReconcilerProjection>, DirectoryRefusal> {
    let keys = report_keys(&listing);
    Directory::new(listing, keys)
}

pub(crate) fn directory(hosts: u64, shards: u32) -> Directory<ReconcilerProjection> {
    build(listing(hosts, shards)).unwrap()
}

/// The directory that follows `base` at the next version, with `change` applied.
fn successor(base: &Listing, change: impl FnOnce(&mut Listing)) -> Directory<ReconcilerProjection> {
    let mut listing = base.clone();
    listing.version = base.version + 1;
    change(&mut listing);
    build(listing).unwrap()
}

fn refused(change: impl FnOnce(&mut Listing)) -> DirectoryRefusal {
    let mut listing = listing(4, 4);
    change(&mut listing);
    build(listing).unwrap_err()
}

#[test]
fn a_sound_directory_holds_its_hosts_shards_and_report_keys_in_order() {
    let mut listing = listing(4, 3);
    listing.hosts.reverse();
    listing.shards.reverse();
    let directory = build(listing).unwrap();
    let hosts: Vec<u64> = directory.hosts().iter().map(|e| e.host.get()).collect();
    assert_eq!(hosts, [1, 2, 3, 4]);
    let shards: Vec<u32> = directory.shards().iter().map(|e| e.shard.get()).collect();
    assert_eq!(shards, [1, 2, 3]);
    let key = directory.keys().report(host(2)).unwrap();
    assert_eq!(key.0, ReportKey::derive(&host_key(2)).0);
    assert!(directory.keys().report(host(9)).is_none());
    assert_eq!(directory.host_roles_max().get(), 10);
    assert_eq!(directory.host(host(3)).unwrap().instance, instance(3));
    assert!(!directory.zone_hold());
    assert_eq!(directory.version(), 1);
    assert_eq!(directory.zone(), Zone(1));
}

#[test]
fn a_directory_carries_the_operators_hold_and_roles_limit() {
    let mut held = listing(2, 1);
    held.version = 7;
    held.zone_hold = true;
    held.host_roles_max = 3;
    let held = build(held).unwrap();
    assert!(held.zone_hold());
    assert_eq!(held.host_roles_max().get(), 3);
    assert_eq!(held.version(), 7);
}

#[test]
fn the_roles_limit_runs_from_one_to_the_report_entry_bound() {
    let limit = |max: usize| {
        let mut listing = listing(2, 1);
        listing.host_roles_max = max as u32;
        let reconciler = build(listing.clone()).map(|_| ());
        let host_side = Directory::<HostProjection>::new(listing.clone(), host_keys(&listing));
        assert_eq!(reconciler, host_side.map(|_| ()));
        reconciler
    };
    assert_eq!(limit(0), Err(DirectoryRefusal::RolesMax));
    assert_eq!(limit(1), Ok(()));
    assert_eq!(limit(MAX_ENTRIES), Ok(()));
    assert_eq!(limit(MAX_ENTRIES + 1), Err(DirectoryRefusal::RolesMax));
}

#[test]
fn a_directory_holds_at_most_max_hosts_hosts_and_keys_and_max_slots_shards() {
    let full = listing(MAX_HOSTS as u64, 1);
    let at_cap = build(full.clone()).unwrap();
    assert_eq!(at_cap.hosts().len(), MAX_HOSTS);
    let mut over = full.clone();
    over.hosts.push(entry(MAX_HOSTS as u64 + 1, 0));
    assert_eq!(build(over).unwrap_err(), DirectoryRefusal::TooMany);
    let mut keys = report_keys(&full);
    keys.push((host(MAX_HOSTS as u64 + 1), report_key(MAX_HOSTS as u64 + 1)));
    let built = Directory::<ReconcilerProjection>::new(full.clone(), keys);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::TooMany);
    let host_side = Directory::<HostProjection>::new(full.clone(), host_keys(&full)).unwrap();
    assert_eq!(
        host_side.keys().hosts().count(),
        MAX_HOSTS,
        "two keys per host at the cap"
    );
    let mut keys = host_keys(&full);
    keys.push(keys[0]);
    let built = Directory::<HostProjection>::new(full.clone(), keys);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::TooMany);
    let shards = build(listing(1, MAX_SLOTS as u32)).unwrap();
    assert_eq!(shards.shards().len(), MAX_SLOTS);
    let built = build(listing(1, MAX_SLOTS as u32 + 1));
    assert_eq!(built.unwrap_err(), DirectoryRefusal::TooMany);
    let mut first = listing(1, MAX_SLOTS as u32 + 1);
    first.host_roles_max = 0;
    assert_eq!(build(first).unwrap_err(), DirectoryRefusal::TooMany);

    // Retired hosts stay listed, so a full chain admits no new host and cannot drop a tombstone to make room.
    let mut retired = full;
    retired.hosts[0].state = DirectoryState::Retired;
    let prior = build(retired.clone()).unwrap();
    let mut grown = retired.clone();
    grown.version = 2;
    grown.hosts.push(entry(MAX_HOSTS as u64 + 1, 0));
    let built = Directory::<ReconcilerProjection>::new(grown, report_keys(&retired));
    assert_eq!(built.unwrap_err(), DirectoryRefusal::TooMany);
    let mut compacted = retired;
    compacted.version = 2;
    compacted.hosts.remove(0);
    compacted.hosts.push(entry(MAX_HOSTS as u64 + 1, 0));
    let compacted = build(compacted).unwrap();
    assert_eq!(
        compacted.succeeds(&prior),
        Err(SuccessionRefusal::Departed(host(1)))
    );
}

#[test]
fn duplicates_foreign_shards_and_unkeyed_hosts_are_refused() {
    assert_eq!(
        refused(|l| l.hosts.push(entry(2, 0))),
        DirectoryRefusal::DuplicateHost(host(2))
    );
    let second_instance = |l: &mut Listing| {
        let mut twice = entry(2, 0);
        twice.instance = instance(9);
        l.hosts.push(twice);
    };
    assert_eq!(
        refused(second_instance),
        DirectoryRefusal::DuplicateHost(host(2))
    );
    assert_eq!(
        refused(|l| l.hosts[3].instance = instance(1)),
        DirectoryRefusal::DuplicateInstance(host(4))
    );
    assert_eq!(
        refused(|l| l.shards.push(shard_entry(3))),
        DirectoryRefusal::DuplicateShard(Shard::new(3).unwrap())
    );
    assert_eq!(
        refused(|l| l.shards[1].zone = Zone(2)),
        DirectoryRefusal::ForeignShard(Shard::new(2).unwrap())
    );
    assert_eq!(
        refused(|l| l.shards[0].layout.slots = 2),
        DirectoryRefusal::Layout(
            Shard::new(1).unwrap(),
            LayoutRefusal::TooFewSlots { slots: 2 }
        )
    );
    assert_eq!(
        refused(|l| l.shards[1].layout.units = 9),
        DirectoryRefusal::Layout(
            Shard::new(2).unwrap(),
            LayoutRefusal::BelowFloor {
                units: 9,
                floor: 10
            }
        )
    );
    let mut listing = listing(4, 4);
    let full = report_keys(&listing);
    let short = Directory::<ReconcilerProjection>::new(listing.clone(), full[..3].to_vec());
    assert_eq!(short.unwrap_err(), DirectoryRefusal::MissingKey(host(4)));
    let mut keys = full.clone();
    keys.remove(2);
    let missing = Directory::<ReconcilerProjection>::new(listing.clone(), keys.clone());
    assert_eq!(missing.unwrap_err(), DirectoryRefusal::MissingKey(host(3)));
    listing.hosts.remove(2);
    let between = Directory::<ReconcilerProjection>::new(listing.clone(), full[..3].to_vec());
    assert_eq!(between.unwrap_err(), DirectoryRefusal::UnlistedKey(host(3)));
    keys.push((host(9), report_key(9)));
    let unlisted = Directory::<ReconcilerProjection>::new(listing, keys);
    assert_eq!(
        unlisted.unwrap_err(),
        DirectoryRefusal::UnlistedKey(host(9))
    );
}

#[test]
fn the_first_refusal_in_the_documented_order_is_reported() {
    let roles_and_host = refused(|l| {
        l.host_roles_max = 0;
        l.hosts.push(entry(2, 0));
    });
    assert_eq!(roles_and_host, DirectoryRefusal::RolesMax);
    let layout_then_duplicate = refused(|l| {
        l.shards[0].layout.slots = 2;
        l.shards.push(shard_entry(3));
    });
    assert_eq!(
        layout_then_duplicate,
        DirectoryRefusal::Layout(
            Shard::new(1).unwrap(),
            LayoutRefusal::TooFewSlots { slots: 2 }
        )
    );
    let mut foreign = listing(4, 4);
    foreign.shards[3].zone = Zone(2);
    let mut keys = report_keys(&foreign);
    keys.remove(0);
    let built = Directory::<ReconcilerProjection>::new(foreign, keys);
    assert_eq!(
        built.unwrap_err(),
        DirectoryRefusal::ForeignShard(Shard::new(4).unwrap())
    );
    // `DuplicateShard` takes precedence over the zone and layout refusals of either copy, in either list order.
    let twice = DirectoryRefusal::DuplicateShard(Shard::new(2).unwrap());
    let foreign_first = refused(|l| {
        l.shards[1].zone = Zone(2);
        l.shards.push(shard_entry(2));
    });
    assert_eq!(foreign_first, twice);
    let foreign_second = refused(|l| {
        l.shards.push(ShardEntry {
            zone: Zone(2),
            ..shard_entry(2)
        });
    });
    assert_eq!(foreign_second, twice);
    let unsound_first = refused(|l| {
        l.shards[1].layout.slots = 2;
        l.shards.push(shard_entry(2));
    });
    assert_eq!(unsound_first, twice);
    let unsound_second = refused(|l| {
        let mut copy = shard_entry(2);
        copy.layout.slots = 2;
        l.shards.push(copy);
    });
    assert_eq!(unsound_second, twice);
}

#[test]
fn each_projection_refuses_the_other_projections_keys() {
    let listing = listing(3, 1);
    let mut report = report_keys(&listing);
    report[1] = beat_keys(&listing)[1];
    let built = Directory::<ReconcilerProjection>::new(listing.clone(), report);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::ForeignKey(host(2)));
    let mut beats = host_keys(&listing);
    beats[0] = report_keys(&listing)[0];
    let built = Directory::<HostProjection>::new(listing.clone(), beats);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::ForeignKey(host(1)));
    let mut doubled = host_keys(&listing);
    doubled.push(doubled[2]);
    let built = Directory::<HostProjection>::new(listing.clone(), doubled);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::DuplicateKey(host(3)));
    let mut rekeyed = report_keys(&listing);
    rekeyed.push((host(1), report_key(9)));
    let built = Directory::<ReconcilerProjection>::new(listing.clone(), rekeyed);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::DuplicateKey(host(1)));
    // Key refusals follow the key list, not host order: the shared value of host 3 comes before host 1's foreign
    // key, which a host-ordered or kind-first check would report instead.
    let reports = report_keys(&listing);
    let out_of_order = vec![reports[1], (host(3), reports[1].1), beat_keys(&listing)[0]];
    let built = Directory::<ReconcilerProjection>::new(listing.clone(), out_of_order);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::SharedKey(host(3)));
    let host_side = Directory::<HostProjection>::new(listing.clone(), host_keys(&listing)).unwrap();
    let beat = host_side.keys().heartbeat(host(3)).unwrap();
    assert_eq!(beat.0, BeatKey::derive(&host_key(3)).0);
    assert_ne!(beat.0, ReportKey::derive(&host_key(3)).0);
}

#[test]
fn two_hosts_never_share_one_key() {
    let wide = u64::from(u32::MAX) + 2;
    let mut listing = listing(2, 1);
    listing.hosts.push(entry(257, 0));
    listing.hosts.push(entry(wide, 0));
    let distinct = build(listing.clone()).unwrap();
    let reports = distinct.keys();
    for other in [257, wide] {
        assert_ne!(
            reports.report(host(1)).unwrap().0,
            reports.report(host(other)).unwrap().0
        );
    }
    assert_ne!(distinct.host(host(1)).unwrap().instance, instance(wide));
    let beats = Directory::<HostProjection>::new(listing.clone(), host_keys(&listing)).unwrap();
    for other in [257, wide] {
        assert_ne!(
            beats.keys().heartbeat(host(1)).unwrap().0,
            beats.keys().heartbeat(host(other)).unwrap().0
        );
    }
    let mut shared = report_keys(&listing);
    shared[2].1 = shared[0].1;
    let built = Directory::<ReconcilerProjection>::new(listing.clone(), shared);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::SharedKey(host(257)));
    let mut shared = host_keys(&listing);
    shared[1].1 = shared[0].1;
    let built = Directory::<HostProjection>::new(listing.clone(), shared);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::SharedKey(host(2)));
    let mut doubled = host_keys(&listing);
    doubled.push(doubled[0]);
    let built = Directory::<HostProjection>::new(listing, doubled);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::DuplicateKey(host(1)));
}

#[test]
fn a_projection_formats_its_hosts_and_no_key() {
    let listing = listing(3, 1);
    let hosts: BTreeSet<Host> = listing.hosts.iter().map(|entry| entry.host).collect();
    let expected = format!("{hosts:?}");
    let reconciler = build(listing.clone()).unwrap();
    assert_eq!(format!("{:?}", reconciler.keys()), expected);
    let host_side = Directory::<HostProjection>::new(listing.clone(), host_keys(&listing)).unwrap();
    assert_eq!(format!("{:?}", host_side.keys()), expected);
}

#[test]
fn a_later_directory_rises_in_version_and_keeps_each_hosts_instance() {
    let base = listing(4, 2);
    let prior = build(base.clone()).unwrap();
    let next = |change: fn(&mut Listing)| successor(&base, change);
    assert_eq!(next(|_| {}).succeeds(&prior), Ok(()));
    let retired = next(|l| l.hosts[0].state = DirectoryState::Retired);
    assert_eq!(retired.succeeds(&prior), Ok(()));
    let draining = next(|l| l.hosts[0].state = DirectoryState::Draining);
    assert_eq!(draining.succeeds(&prior), Ok(()));
    let grown = next(|l| l.hosts.push(entry(5, 0)));
    assert_eq!(grown.succeeds(&prior), Ok(()));
    let version = next(|l| l.version = 1).succeeds(&prior);
    assert_eq!(version, Err(SuccessionRefusal::Version));
    let lower = directory(4, 2).succeeds(&next(|_| {}));
    assert_eq!(lower, Err(SuccessionRefusal::Version));
    let renamed = next(|l| l.hosts[1].instance = instance(7));
    assert_eq!(
        renamed.succeeds(&prior),
        Err(SuccessionRefusal::Reassigned(host(2)))
    );
    let moved = next(|l| {
        l.hosts[0].instance = instance(8);
        l.hosts.push(HostEntry {
            instance: instance(1),
            ..entry(9, 0)
        });
    });
    assert_eq!(
        moved.succeeds(&prior),
        Err(SuccessionRefusal::Reassigned(host(1)))
    );
    let reassigned_then_departed = next(|l| {
        l.hosts[1].instance = instance(7);
        l.hosts.remove(3);
    });
    assert_eq!(
        reassigned_then_departed.succeeds(&prior),
        Err(SuccessionRefusal::Reassigned(host(2)))
    );
    let mut moved_down = listing(4, 2);
    moved_down.hosts.remove(0);
    let from_two = build(moved_down).unwrap();
    let taken = next(|l| {
        l.hosts[0].instance = instance(3);
        l.hosts[2].instance = instance(9);
    });
    assert_eq!(
        taken.succeeds(&from_two),
        Err(SuccessionRefusal::Reassigned(host(3)))
    );
    let departed = next(|l| {
        l.hosts.remove(2);
    });
    assert_eq!(
        departed.succeeds(&prior),
        Err(SuccessionRefusal::Departed(host(3)))
    );
    let mut readded = listing(4, 2);
    readded.version = 3;
    readded.hosts[2].instance = instance(7);
    let readded = build(readded).unwrap();
    assert_eq!(
        readded.succeeds(&prior),
        Err(SuccessionRefusal::Reassigned(host(3)))
    );
    let mut other = listing(4, 0);
    other.zone = Zone(2);
    let other = build(other).unwrap();
    assert_eq!(other.succeeds(&prior), Err(SuccessionRefusal::Zone));
}

#[test]
fn a_retired_host_stays_listed_and_retired() {
    let mut retired = listing(4, 2);
    retired.hosts[1].state = DirectoryState::Retired;
    let retired_prior = build(retired.clone()).unwrap();
    assert_eq!(
        retired_prior.host(host(2)).unwrap().state,
        DirectoryState::Retired
    );
    let next = |change: fn(&mut Listing)| successor(&retired, change);
    assert_eq!(next(|_| {}).succeeds(&retired_prior), Ok(()));
    let replaced = next(|l| l.hosts.push(entry(5, 0)));
    assert_eq!(replaced.succeeds(&retired_prior), Ok(()));
    let active = next(|l| l.hosts[1].state = DirectoryState::Active);
    assert_eq!(
        active.succeeds(&retired_prior),
        Err(SuccessionRefusal::Unretired(host(2)))
    );
    let draining = next(|l| l.hosts[1].state = DirectoryState::Draining);
    assert_eq!(
        draining.succeeds(&retired_prior),
        Err(SuccessionRefusal::Unretired(host(2)))
    );
    let dropped = next(|l| {
        l.hosts.remove(1);
    });
    assert_eq!(
        dropped.succeeds(&retired_prior),
        Err(SuccessionRefusal::Departed(host(2)))
    );
    let renamed = next(|l| l.hosts[1].instance = instance(9));
    assert_eq!(
        renamed.succeeds(&retired_prior),
        Err(SuccessionRefusal::Reassigned(host(2)))
    );
    let rezoned = next(|l| l.hosts[1].placement.zone = Zone(2));
    assert_eq!(
        rezoned.succeeds(&retired_prior),
        Err(SuccessionRefusal::Rezoned(host(2)))
    );
}

#[test]
fn a_host_keeps_its_instances_zone() {
    let mut mixed = listing(4, 2);
    mixed.hosts[2].placement.zone = Zone(2);
    let prior = build(mixed.clone()).unwrap();
    let next = |change: fn(&mut Listing)| successor(&mixed, change);
    assert_eq!(next(|_| {}).succeeds(&prior), Ok(()));
    let repartitioned = next(|l| {
        l.hosts[0].placement.partition = Partition(7);
        l.hosts[0].placement.color = Color(3);
    });
    assert_eq!(repartitioned.succeeds(&prior), Ok(()));
    let out = next(|l| l.hosts[1].placement.zone = Zone(3));
    assert_eq!(
        out.succeeds(&prior),
        Err(SuccessionRefusal::Rezoned(host(2)))
    );
    let into = next(|l| l.hosts[2].placement.zone = Zone(1));
    assert_eq!(
        into.succeeds(&prior),
        Err(SuccessionRefusal::Rezoned(host(3)))
    );
    let both = next(|l| {
        l.hosts[1].placement.zone = Zone(3);
        l.hosts[1].instance = instance(9);
    });
    assert_eq!(
        both.succeeds(&prior),
        Err(SuccessionRefusal::Reassigned(host(2)))
    );
    // Hosts of other zones keep their identity and zone too.
    let elsewhere = next(|l| l.hosts[2].placement.zone = Zone(3));
    assert_eq!(
        elsewhere.succeeds(&prior),
        Err(SuccessionRefusal::Rezoned(host(3)))
    );
    let foreign_renamed = next(|l| l.hosts[2].instance = instance(9));
    assert_eq!(
        foreign_renamed.succeeds(&prior),
        Err(SuccessionRefusal::Reassigned(host(3)))
    );
    let foreign_dropped = next(|l| {
        l.hosts.remove(2);
    });
    assert_eq!(
        foreign_dropped.succeeds(&prior),
        Err(SuccessionRefusal::Departed(host(3)))
    );
}

#[test]
fn the_largest_partition_counts_unretired_hosts_of_the_zone() {
    let mut listing = listing(12, 1);
    for retired in [0, 3, 6, 1, 4] {
        listing.hosts[retired].state = DirectoryState::Retired;
    }
    for foreign in [2, 5, 8] {
        listing.hosts[foreign].placement.zone = Zone(2);
    }
    listing.hosts[7].state = DirectoryState::Draining;
    let mut second = listing.clone();
    second.zone = Zone(2);
    second.shards[0].zone = Zone(2);
    let fleet = build(listing).unwrap();
    assert_eq!(fleet.largest_partition(), 2);
    let zone: Vec<u64> = fleet.zone_hosts().map(|entry| entry.host.get()).collect();
    assert_eq!(zone, [1, 2, 4, 5, 7, 8, 10, 11, 12]);
    let second = build(second).unwrap();
    assert_eq!(second.largest_partition(), 3);
    let zone: Vec<u64> = second.zone_hosts().map(|entry| entry.host.get()).collect();
    assert_eq!(zone, [3, 6, 9]);
    assert_eq!(directory(0, 0).largest_partition(), 0);
}

#[test]
fn the_host_projection_holds_each_hosts_probe_key_and_the_reconciler_projection_refuses_one() {
    let listing = listing(3, 1);
    let host_side = Directory::<HostProjection>::new(listing.clone(), host_keys(&listing)).unwrap();
    for number in 1..=3 {
        let probe = host_side.keys().probe(host(number)).unwrap();
        assert_eq!(probe.0, ProbeKey::derive(&host_key(number)).0);
        assert_ne!(probe.0, host_side.keys().heartbeat(host(number)).unwrap().0);
    }
    assert!(host_side.keys().probe(host(9)).is_none());
    let mut reports = report_keys(&listing);
    reports.push(probe_keys(&listing)[1]);
    let built = Directory::<ReconcilerProjection>::new(listing.clone(), reports);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::ForeignKey(host(2)));
    let beats_only = Directory::<HostProjection>::new(listing.clone(), beat_keys(&listing));
    assert_eq!(
        beats_only.unwrap_err(),
        DirectoryRefusal::MissingKey(host(1))
    );
    let mut unpaired = beat_keys(&listing);
    unpaired.extend(
        probe_keys(&listing)
            .into_iter()
            .filter(|(h, _)| *h != host(2)),
    );
    let built = Directory::<HostProjection>::new(listing.clone(), unpaired);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::MissingKey(host(2)));
    let mut probes_only = probe_keys(&listing);
    probes_only.extend(
        beat_keys(&listing)
            .into_iter()
            .filter(|(h, _)| *h != host(3)),
    );
    let built = Directory::<HostProjection>::new(listing.clone(), probes_only);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::MissingKey(host(3)));
    let mut doubled = host_keys(&listing);
    doubled.push(probe_keys(&listing)[0]);
    let built = Directory::<HostProjection>::new(listing, doubled);
    assert_eq!(built.unwrap_err(), DirectoryRefusal::DuplicateKey(host(1)));
}
