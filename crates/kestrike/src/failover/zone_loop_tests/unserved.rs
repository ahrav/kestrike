use crate::failover::records::ShardRecord;
use crate::failover::report::alarm_tests::controls::{self, Twin};
use crate::failover::report::status::{CLASSES, Class};
use crate::failover::report::{Phase, RecordedRole, VolumeEntry};
use crate::failover::sim::host;
use crate::failover::zone_loop::Tick;
use crate::failover::zone_loop::evidence::InstanceState;
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::storage::store::sim::MemLog;
use crate::storage::store::{Client, Key};

use super::directory::instance;
use super::observe::{Fixture, S, START, entry, id, owner_of, volume};
use super::survey::{designate_all, warm};

fn record(fixture: &Fixture) -> ShardRecord {
    let mut client = Client::open(fixture.store.clone(), MemLog::default()).unwrap();
    *client
        .read::<ShardRecord>(Key::Shard(id(1)))
        .unwrap()
        .value()
}

fn at_tenure(record: &ShardRecord, role: RecordedRole, phase: Phase) -> VolumeEntry {
    VolumeEntry {
        role: Some(role),
        phase: Some(phase),
        ..entry(
            volume(1).as_str(),
            1,
            record.generation.get(),
            record.attempts,
        )
    }
}

struct Run {
    /// The tick 300 seconds into the silence.
    tick: Tick,
    /// `wrote` covers commits to any store key during the silence.
    wrote: bool,
}

/// Host `n` belongs to partition `n % 3`; shard 1 has owner H2 in partition 2 and named standby H3 in partition 0.
/// The loop classifies `lost` hosts as lost and `silent` hosts as unknown. The owner's last report before the
/// silence holds `owner` as its entries.
fn stop(lost: &[u64], silent: &[u64], owner: &[VolumeEntry]) -> Run {
    let mut fixture = Fixture::new(6, 1);
    warm(&mut fixture, 12);
    designate_all(&fixture);
    let record = record(&fixture);
    assert_eq!(
        (record.owner, record.standby),
        (owner_of(1, 6), Some(host(3)))
    );
    fixture.publish(2, owner);
    let before = fixture.commits();
    for &number in lost {
        let listed = (fixture.world.instances.iter_mut())
            .find(|listed| listed.instance == instance(number))
            .unwrap();
        listed.state = InstanceState::Terminated;
    }
    let standby = at_tenure(&record, RecordedRole::Standby, Phase::Standby);
    let mut last = None;
    for at in 0..=30 {
        let reporting = |number: &u64| !lost.contains(number) && !silent.contains(number);
        for number in (1..=fixture.hosts).filter(reporting) {
            let entries = if number == 3 { vec![standby] } else { vec![] };
            fixture.publish(number, &entries);
        }
        let now_us = START + (200 + 10 * at) * S;
        let directory = Ok(fixture.directory());
        last = Some(fixture.zone.tick(directory, &mut fixture.world, now_us));
    }
    Run {
        tick: last.unwrap(),
        wrote: fixture.commits() != before,
    }
}

fn class(tick: &Tick, class: Class) -> u32 {
    let at = CLASSES.iter().position(|listed| *listed == class);
    tick.part.classes[at.unwrap()]
}

fn row(run: &Run) -> (ShardState, Option<Blocker>) {
    let row = run.tick.survey.status.shards[0];
    (row.state, row.blocker)
}

/// Losing H2 and H6 confines the standby H3's possible probers outside H2's partition to partition 1 (H1 and H4);
/// losing H2 alone leaves H6 in partition 0 as well, so a takeover can gather its quorum. The two blocker counts
/// are the alarm row's control pair.
#[test]
fn a_lost_owner_whose_standby_has_probers_in_one_partition_reads_quorum_unreachable() {
    let at = Blocker::QuorumUnreachable.position();
    let fault = stop(&[2, 6], &[], &[]);
    let unreachable = (ShardState::Protected, Some(Blocker::QuorumUnreachable));
    assert_eq!(row(&fault), unreachable);
    assert_eq!(fault.tick.part.hosts.verdicts, [4, 2, 0, 0]);
    assert!(!fault.tick.part.flags.warm_up);
    let steps = &fault.tick.survey.plan.steps;
    assert!(steps.is_empty(), "{steps:?}");
    assert!(!fault.wrote, "the blocker writes no store key");
    let clean = stop(&[2], &[], &[]);
    assert_eq!(row(&clean), (ShardState::Protected, None));
    assert_eq!(
        (
            class(&fault.tick, Class::Fresh),
            class(&clean.tick, Class::Fresh)
        ),
        (1, 1)
    );
    assert_eq!(
        Twin {
            fault: fault.tick.part.blockers[at],
            clean: clean.tick.part.blockers[at],
        },
        controls::quorum_unreachable(),
        "quorum-unreachable"
    );
}

#[test]
fn a_lost_owner_with_no_prober_partition_left_reads_quorum_unreachable() {
    let run = stop(&[1, 2, 4, 6], &[], &[]);
    assert_eq!(run.tick.part.hosts.verdicts, [2, 4, 0, 0]);
    let unreachable = (ShardState::Protected, Some(Blocker::QuorumUnreachable));
    assert_eq!(row(&run), unreachable);
}

/// The planted rule that counts the lost H6 among the standby's possible probers reads partitions 1 and 0 for the
/// loss of H2 and H6, so `a_lost_owner_whose_standby_has_probers_in_one_partition_reads_quorum_unreachable` fails
/// under it.
#[test]
fn the_control_that_counts_lost_hosts_as_probers_misses_quorum_unreachable() {
    use crate::failover::zone_loop::plan::LOST_PROBERS_COUNTED;
    LOST_PROBERS_COUNTED.set(true);
    let planted = stop(&[2, 6], &[], &[]);
    LOST_PROBERS_COUNTED.set(false);
    assert_eq!(
        row(&planted),
        (ShardState::Protected, None),
        "the planted count of lost probers misses quorum-unreachable"
    );
}

/// When H2 is lost, H6 still counts as a possible prober while its verdict is unknown. The blocker requires a lost
/// verdict for the owner H2, even when H6 is lost.
#[test]
fn a_host_read_unknown_counts_as_a_possible_prober_and_an_unknown_owner_as_no_loss() {
    let prober = stop(&[2], &[6], &[]);
    assert_eq!(prober.tick.part.hosts.verdicts, [4, 1, 0, 1]);
    assert_eq!(row(&prober), (ShardState::Protected, None));
    let owner = stop(&[6], &[2], &[]);
    assert_eq!(owner.tick.part.hosts.verdicts, [4, 1, 0, 1]);
    assert_eq!(row(&owner), (ShardState::Protected, None));
}

#[test]
fn a_lost_owner_s_last_device_hold_yields_to_quorum_unreachable() {
    let mut fixture = Fixture::new(6, 1);
    warm(&mut fixture, 12);
    designate_all(&fixture);
    let held = at_tenure(&record(&fixture), RecordedRole::Owner, Phase::Held);
    let fault = stop(&[2, 6], &[], &[held]);
    let unreachable = (ShardState::Protected, Some(Blocker::QuorumUnreachable));
    assert_eq!(row(&fault), unreachable);
    let clean = stop(&[2], &[], &[held]);
    let device = (ShardState::Protected, Some(Blocker::DeviceFailureHold));
    assert_eq!(row(&clean), device);
}

/// The live owner's fresh report omits the shard in both cases: the record matches the owner's last tenure or
/// exceeds it by one epoch.
#[test]
fn a_live_owner_with_no_entry_for_the_shard_reads_protected_with_no_blocker() {
    for bumped in [false, true] {
        let mut fixture = Fixture::new(6, 1);
        warm(&mut fixture, 12);
        designate_all(&fixture);
        if bumped {
            let mut owner = Client::open(fixture.store.clone(), MemLog::default()).unwrap();
            let stored = owner.read::<ShardRecord>(Key::Shard(id(1))).unwrap();
            owner.bump(&stored).unwrap();
        }
        let mut last = None;
        for at in 0..=30 {
            for number in 1..=fixture.hosts {
                fixture.publish(number, &[]);
            }
            let now_us = START + (200 + 10 * at) * S;
            let directory = Ok(fixture.directory());
            last = Some(fixture.zone.tick(directory, &mut fixture.world, now_us));
        }
        let tick = last.unwrap();
        let row = tick.survey.status.shards[0];
        assert_eq!(
            (row.state, row.blocker),
            (ShardState::Protected, None),
            "bumped {bumped}"
        );
        assert_eq!(class(&tick, Class::Silent), 1, "bumped {bumped}");
    }
}
