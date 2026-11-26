use crate::failover::records::ShardRecord;
use crate::failover::report::alarm_tests::controls::{self, Twin};
use crate::failover::report::status::{CLASSES, Class};
use crate::failover::report::{Phase, RecordedRole, VolumeEntry};
use crate::failover::sim::host;
use crate::failover::zone_loop::Tick;
use crate::failover::zone_loop::directory::DirectoryState;
use crate::failover::zone_loop::evidence::{InstanceState, StatusCheck};
use crate::failover::zone_loop::status::{Blocker, ShardState};
use crate::storage::store::sim::MemLog;
use crate::storage::store::{Client, Key};

use super::directory::{instance, listing};
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
    stop_after(lost, silent, owner, |_| {})
}

/// `stop_after` runs `stop` with `prepare` applied to the fixture once the lost hosts' instances end.
fn stop_after(
    lost: &[u64],
    silent: &[u64],
    owner: &[VolumeEntry],
    prepare: impl FnOnce(&mut Fixture),
) -> Run {
    let mut stopped = Stopped::new(lost, silent, owner, prepare);
    let tick = stopped.run();
    Run {
        tick,
        wrote: stopped.fixture.commits() != stopped.before,
    }
}

/// A zone whose `lost` hosts' instances ended after the owner's last report, with the hosts that keep publishing.
struct Stopped {
    fixture: Fixture,
    /// The store's commits when the silence starts.
    before: Vec<usize>,
    standby: VolumeEntry,
    reporting: Vec<u64>,
    /// The ticks run so far, ten seconds apart.
    ticks: u64,
}

impl Stopped {
    fn new(
        lost: &[u64],
        silent: &[u64],
        owner: &[VolumeEntry],
        prepare: impl FnOnce(&mut Fixture),
    ) -> Self {
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
        prepare(&mut fixture);
        let reporting = |number: &u64| !lost.contains(number) && !silent.contains(number);
        Self {
            before,
            standby: at_tenure(&record, RecordedRole::Standby, Phase::Standby),
            reporting: (1..=fixture.hosts).filter(reporting).collect(),
            ticks: 0,
            fixture,
        }
    }

    /// One tick ten seconds after the last, after each reporting host publishes.
    fn tick(&mut self) -> Tick {
        for &number in &self.reporting {
            let entries = if number == 3 {
                vec![self.standby]
            } else {
                vec![]
            };
            self.fixture.publish(number, &entries);
        }
        let now_us = START + (200 + 10 * self.ticks) * S;
        self.ticks += 1;
        let directory = Ok(self.fixture.directory());
        (self.fixture.zone).tick(directory, &mut self.fixture.world, now_us)
    }

    /// The tick 300 seconds into the silence.
    fn run(&mut self) -> Tick {
        let mut last = None;
        for _ in 0..=30 {
            last = Some(self.tick());
        }
        last.unwrap()
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

/// H6's evidence in the tick that reads it lost.
#[derive(Debug, Clone, Copy, Default)]
struct Prober {
    /// The directory lists H6 retired.
    retired: bool,
    /// H6's instance is terminated.
    terminated: bool,
    /// H6's instance check reads impaired for the whole silence, past its dwell.
    impaired: bool,
    /// H6 publishes no report during the silence.
    silent: bool,
}

/// `lost_prober` loses the owner H2 and gives H6 the evidence of `prober`.
fn lost_prober(prober: Prober) -> Run {
    let silent: &[u64] = if prober.silent { &[6] } else { &[] };
    stop_after(&[2], silent, &[], |fixture| {
        let listed = (fixture.world.instances.iter_mut())
            .find(|listed| listed.instance == instance(6))
            .unwrap();
        if prober.terminated {
            listed.state = InstanceState::Terminated;
        }
        if prober.impaired {
            listed.instance_check = StatusCheck::Impaired;
        }
        if prober.retired {
            let mut listing = listing(fixture.hosts, fixture.shards);
            listing.version += 1;
            listing.hosts[5].state = DirectoryState::Retired;
            fixture.listing = Some(listing);
        }
    })
}

/// A retired H6 whose instance runs can still answer the standby's probes, so it counts as a possible prober in
/// partition 0 and the shard carries no blocker, as the twin with H6 alive does. Impaired checks with a publishing
/// report, and a silent report with passing checks, leave it counted, as they leave an active host's verdict short
/// of lost. A retired H6 whose instance ended, and an H6 with a silent report and impaired checks past their dwell,
/// retired or active, answer no probe, and the shard reads quorum-unreachable.
#[test]
fn a_retired_prober_counts_as_a_possible_prober_while_its_instance_runs() {
    let counted = (ShardState::Protected, None);
    let unreachable = (ShardState::Protected, Some(Blocker::QuorumUnreachable));
    let retired = Prober {
        retired: true,
        ..Prober::default()
    };
    let unanswering = Prober {
        impaired: true,
        silent: true,
        ..Prober::default()
    };
    for (prober, expected) in [
        (retired, counted),
        (
            Prober {
                impaired: true,
                ..retired
            },
            counted,
        ),
        (
            Prober {
                silent: true,
                ..retired
            },
            counted,
        ),
        (
            Prober {
                terminated: true,
                ..retired
            },
            unreachable,
        ),
        (unanswering, unreachable),
        (
            Prober {
                retired: true,
                ..unanswering
            },
            unreachable,
        ),
    ] {
        let run = lost_prober(prober);
        assert_eq!(run.tick.part.hosts.verdicts, [4, 2, 0, 0], "{prober:?}");
        assert_eq!(row(&run), expected, "{prober:?}");
    }
}

/// The planted rule that reads a retired host as silent while its instance runs reads quorum-unreachable for the
/// retired running H6, so `a_retired_prober_counts_as_a_possible_prober_while_its_instance_runs` fails under it.
#[test]
fn the_control_that_reads_a_running_retired_prober_as_silent_reads_quorum_unreachable() {
    use crate::failover::zone_loop::plan::RUNNING_RETIRED_SILENT;
    RUNNING_RETIRED_SILENT.set(true);
    let planted = lost_prober(Prober {
        retired: true,
        ..Prober::default()
    });
    RUNNING_RETIRED_SILENT.set(false);
    assert_eq!(
        row(&planted),
        (ShardState::Protected, Some(Blocker::QuorumUnreachable)),
        "the planted silence of a running retired prober reads quorum-unreachable"
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

/// A tick whose instance listing fails holds no instance evidence for any host, so every active host, the named
/// standby among them, reads unknown: the shard leaves `Protected` for `LossUnconfirmed`, and QUORUM-PREMISE, which
/// only a `Protected` shard reads, counts no host on that tick. The retired owner H2 and the retired H6 read lost on
/// it. On the complete tick before, a running H6 leaves the shard with no blocker and a terminated H6 leaves it
/// quorum-unreachable.
#[test]
fn a_failed_instance_listing_reads_the_standby_unknown_ahead_of_the_quorum_premise() {
    let retire = |fixture: &mut Fixture| {
        let mut listing = listing(fixture.hosts, fixture.shards);
        listing.version += 1;
        listing.hosts[1].state = DirectoryState::Retired;
        listing.hosts[5].state = DirectoryState::Retired;
        fixture.listing = Some(listing);
    };
    let row = |tick: &Tick| {
        let row = tick.survey.status.shards[0];
        (row.state, row.blocker)
    };
    for (lost, complete) in [
        (&[2][..], None),
        (&[2, 6][..], Some(Blocker::QuorumUnreachable)),
    ] {
        let mut stopped = Stopped::new(lost, &[], &[], retire);
        let before = stopped.run();
        assert_eq!(before.part.hosts.verdicts, [4, 2, 0, 0], "{lost:?}");
        assert_eq!(row(&before), (ShardState::Protected, complete), "{lost:?}");
        stopped.fixture.world.faults.instances = true;
        let gap = stopped.tick();
        assert!(!gap.part.flags.instances, "{lost:?}");
        assert_eq!(gap.part.hosts.verdicts, [0, 2, 0, 4], "{lost:?}");
        let unconfirmed = (ShardState::StandbyUnknown, Some(Blocker::LossUnconfirmed));
        assert_eq!(row(&gap), unconfirmed, "{lost:?}");
    }
}
