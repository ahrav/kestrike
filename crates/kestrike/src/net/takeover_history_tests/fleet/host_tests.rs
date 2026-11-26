use std::collections::BTreeSet;

use super::faults::{Action, Episode, Faults, Hostile, Kind, Trigger};
use super::hosts::{self, Scenario};
use super::oracles;
use super::*;
use crate::failover::report::Gauge;
use crate::storage::store::sim::Arm;

const H0: u64 = 1001;
const H1: u64 = 1002;
const H3: u64 = 1004;
const H5: u64 = 1006;

fn passing(config: &Config) -> Report {
    let report = run_shared(config).expect("a run inside the limits");
    assert_eq!(
        report.credit(),
        Verdict::Pass,
        "{}",
        report.lines().join("\n")
    );
    report
}

fn taken(report: &Report) -> Vec<(u32, u64)> {
    let mut taken: Vec<(u32, u64)> = (report.hosts.takeovers.iter())
        .filter(|attempt| attempt.refused.is_none())
        .map(|attempt| (attempt.shard, attempt.host))
        .collect();
    taken.sort_unstable();
    taken
}

fn hostile(config: Config, plant: Plant, at: u32) -> Report {
    let report = run(&config.hostile(plant, at)).expect("a run inside the limits");
    assert!(report.planted, "{plant:?} changed the run");
    report
}

/// The last committed version of each shard's record, in shard order.
fn last_records(report: &Report) -> Vec<ShardRecord> {
    let histories = report.evidence.histories.iter();
    histories
        .map(|(_, versions)| *versions.last().unwrap())
        .collect()
}

fn hosted(config: &Config) -> (Fleet<'_>, Draws) {
    let (mut fleet, draws) = hosted_unstarted(config);
    fleet.start_hosts();
    (fleet, draws)
}

/// `config`'s seeded fleet under its scenario's fault script, before its hosts start, and its recording draws.
fn hosted_unstarted(config: &Config) -> (Fleet<'_>, Draws) {
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(config, &mut draws, WAIT_ROUNDS);
    (seeded.expect("a recorded topology"), draws)
}

/// Runs `config`'s fleet under `script` in place of its scenario's episodes.
fn scripted(config: &Config, script: Vec<Episode>) -> Report {
    scripted_with(config, script, false)
}

/// [`scripted`], with a held process's due rerun ordered ahead of a queued takeover when `rerun_first`.
pub(super) fn scripted_with(config: &Config, script: Vec<Episode>, rerun_first: bool) -> Report {
    played(config, script, rerun_first).expect("a run inside the limits")
}

/// The run of `config`'s fleet under `script`, or the limit that stopped it.
fn played(config: &Config, script: Vec<Episode>, rerun_first: bool) -> Result<Report, Stopped> {
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(script, fleet.topology.members.len());
    fleet.alarms.scripted = true;
    fleet.rerun_first = rerun_first;
    let _agent = super::AgentPlant::set(config);
    let _inline = Inline::set();
    fleet.play_script(draws)
}

/// Before any tenure serves, each host's headroom counts the volumes attached to its instance unbound and the
/// shards whose record names it owner or standby as its roles of the role budget, holds no recovery slot and reads
/// the procfs and device gauges unavailable. H3 of the host-loss layout holds three attaches in three roles; H1 of
/// the attach-survivor layout holds two attaches, s5's standby and s2's third attach, in one role, so neither gauge
/// can stand for the other; and under the census-full layout H1 holds no role, since s5's record names no standby.
#[test]
fn a_host_with_no_serving_tenure_counts_each_live_attach_unbound_and_its_roles_of_the_role_budget()
{
    let host_loss = Config::host_loss(1);
    let survivor = Config::attach_survivor(1);
    let full = Config::census_full(1);
    for (config, host, attachments, roles) in [
        (&host_loss, H3, 3, 3),
        (&survivor, H1, 2, 1),
        (&full, H1, 0, 0),
    ] {
        let (fleet, _) = hosted(config);
        let live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
        let member = (fleet.member_of(Host::new(host).unwrap())).expect("the host's member");
        let headroom = fleet.headroom(&live, member);
        let scenario = config.scenario;
        assert_eq!(
            headroom.attachments,
            Gauge::known(attachments, 64),
            "{scenario:?}"
        );
        let workers = Gauge::known(roles, u64::from(ROLES_MAX));
        assert_eq!(headroom.workers, workers, "{scenario:?}");
        assert_eq!(headroom.recovery, Gauge::known(0, 1), "{scenario:?}");
        let unavailable = [
            headroom.ram,
            headroom.cpu_load,
            headroom.iops,
            headroom.bandwidth,
        ];
        assert_eq!(unavailable, [Gauge::Unavailable; 4], "{scenario:?}");
    }
}

/// A host lost in several roles hands its three shards to their named standbys warm, on roots 1 and 2. Root 2's
/// report is the shared run that `host_loss_under_the_4_mib_share_fails_the_limiter_check_with_no_refused_charge`
/// reads, so the second root adds no fleet run to the fast tier. The scheduled case runs root 2 as well.
#[test]
fn a_host_lost_in_several_roles_hands_its_shards_to_their_named_standbys_warm() {
    for root in [1, 2] {
        a_host_lost_in_several_roles_hands_its_shards_to_their_named_standbys_warm_on(root);
    }
}

pub(super) fn a_host_lost_in_several_roles_hands_its_shards_to_their_named_standbys_warm_on(
    root: u64,
) {
    let report = passing(&Config::host_loss(root));
    assert_eq!(taken(&report), [(1, H3), (2, H3), (3, H5)]);
    assert_eq!((report.takeovers, report.crashes), (3, 1));
    for attempt in &report.hosts.takeovers {
        let at = |command| attempt.commands.iter().position(|c| *c == command);
        // The named standby preempts the recorded lineage it read (`PreemptLineage`).
        let (register, preempt) = (at("register"), at("lineage"));
        assert!(
            register.is_some() && register < preempt,
            "the named standby registers before it preempts: {:?}",
            attempt.commands
        );
    }
    let log = &report.hosts;
    assert_eq!(log.host_losses, 1);
    assert!(log.loads_beside_service >= 1);
    assert!(
        log.served_beside_load >= 1,
        "a shard of a loading host serves a GET while the load runs"
    );
    assert_eq!((log.lapsed, log.stale_hits, log.exempt.len()), (0, 0, 0));
    assert_eq!((log.refused, log.stale_replies), (0, 0));
    assert!(log.reports > 0);
    // H3's first sealed report counts s3, which it serves, through its bind mapping and the standby attaches
    // of s0 and s1 unbound, so a served volume counted twice or left out reads other than 3; its reports read
    // the recovery slot held while a takeover's load runs and free once the loads end.
    let (used, roles) = (Gauge::known, u64::from(ROLES_MAX));
    let h3 = log.sealed(H3);
    assert_eq!(h3[0], [used(3, 64), used(3, roles), used(0, 1)]);
    assert!(
        h3.iter()
            .all(|gauges| gauges[..2] == [used(3, 64), used(3, roles)])
    );
    assert!(h3.iter().any(|gauges| gauges[2] == used(1, 1)), "{h3:?}");
    assert_eq!(h3.last().map(|gauges| gauges[2]), Some(used(0, 1)));
    assert_eq!(report.evidence.volumes, Volumes::default());
    for (shard, versions) in &report.evidence.histories {
        let first = versions.first().expect("a seeded record");
        for version in versions {
            let kept = (version.generation, version.active, version.checkpoint);
            assert_eq!(kept, (first.generation, first.active, first.checkpoint));
        }
        let at = (shard.get() - 1) as usize;
        let recovered = &report.shards[at].recoveries;
        assert_eq!(
            (&report.shards[at].invalidated, &report.shards[at].unserved),
            (&BTreeSet::from([1]), &Vec::new()),
            "shard {} acknowledges the INVALIDATE of object 1, and each sweep serves every object it counts",
            shard.get()
        );
        if at < 3 {
            let last = recovered.last().expect("a takeover");
            assert_eq!(last.host, report.shards[at].standby);
            assert_eq!(last.sweep, Some((7, 7)), "the invalidated object misses");
            assert_eq!(last.tenure.a, recovered[0].tenure.a + 2);
            assert!(
                last.read_bytes > 0,
                "the device double counted the load's reads"
            );
        } else {
            assert_eq!(recovered.len(), 1, "shard {} keeps its tenure", shard.get());
        }
    }
}

/// F3 over a recovery from a checkpoint the serving duties published. In the host-loss run, s0's boot tenure on H0
/// runs its duties under a capture policy and publishes a checkpoint of its own tenure before H0 is lost; its World
/// records that capture as a cut of its own, and H3's takeover of the record that names it activates that cut, restores its members from it and
/// serves them, so the history oracle decides F3 and passes the run's retention, and the ownership monitor finds
/// the successor's cut equal to the one the record made durable. The published capture holds the boot tenure's
/// resident set, object 1 still among its slots, and H3 restores every member but the INVALIDATEd object 1, which
/// the coverage pages exclude and the retained set leaves out. In the planted control every restore of the run names
/// the seeded cut in place of the activated one, and F3 fails at s0, whose activation named the published cut: a
/// restore names a cut other than its tenure's activation.
#[test]
fn a_takeover_from_a_checkpoint_the_duties_published_is_judged_against_that_capture() {
    const CAPTURING: usize = 0;
    let config = Config::host_loss(1);
    let play = |planted: bool| {
        let (mut fleet, draws) = hosted_unstarted(&config);
        fleet.capturing = vec![CAPTURING];
        fleet.alarms.scripted = true;
        if planted {
            for cell in &mut fleet.cells {
                cell.world.restore_from = Some(super::super::CUT);
            }
        }
        let _agent = super::AgentPlant::set(&config);
        let _inline = Inline::set();
        fleet.play_script(draws).expect("a run inside the limits")
    };
    let report = play(false);
    let (shard, versions) = &report.evidence.histories[CAPTURING];
    let seeded = versions.first().expect("a seeded record").checkpoint;
    let h3 = Host::new(H3).unwrap();
    let taken = versions.iter().find(|version| version.owner == h3);
    let named = taken.expect("H3's takeover").checkpoint;
    let boot = report.shards[CAPTURING].recoveries[0].tenure;
    assert_ne!(named, seeded, "shard {}: the duties published", shard.get());
    let session = named.expect("a named checkpoint").session;
    assert_eq!(
        tenure_of(session),
        boot,
        "H3 took over the boot tenure's checkpoint"
    );
    let last = report.shards[CAPTURING]
        .recoveries
        .last()
        .expect("a takeover");
    assert_eq!(
        (last.host, last.sweep),
        (Host::new(H3).unwrap(), Some((7, 7)))
    );
    assert_eq!(
        report.verdicts.retained,
        Verdict::Pass,
        "{}",
        report.summary()
    );
    assert_eq!(
        report.verdicts.one_owner,
        Verdict::Pass,
        "{}",
        report.summary()
    );
    let control = play(true);
    let unnamed = "a recorded restore from a checkpoint the store did not name";
    assert_eq!(
        control.verdicts.retained,
        Verdict::Fail(unnamed, "shard 1".into()),
        "{}",
        control.summary()
    );
}

/// The `trio` layout holds the three properties the at-threshold partition arms rest on: its first partition holds
/// three hosts and is the zone's largest, so the zone loop's host hold, which counts lost hosts
/// beyond the largest partition, stays off at its loss; every shard with a host in it keeps its other host outside
/// it; and every survivor keeps probers in two partitions other than the lost one.
#[test]
fn the_trio_layout_loses_its_largest_partition_of_three_with_every_shard_and_prober_kept_outside() {
    use super::topology::Topology;
    let shape = Config::trio(1).shape;
    assert_eq!(shape.check(), Ok(()));
    let topology = Topology::draw(&shape, &mut Draws::record(1)).expect("a fixed layout");
    let lost = Placing::TRIO_LOST;
    let partition = |at: usize| topology.members[at].partition;
    let lost_partition = partition(lost[0]);
    assert!(lost.iter().all(|&at| partition(at) == lost_partition));
    let size = |p| {
        (0..topology.members.len())
            .filter(|&at| partition(at) == p)
            .count()
    };
    assert_eq!(size(lost_partition), lost.len());
    assert_eq!(lost.len(), crate::host::agent::SELF_SUSPECT);
    for at in 0..topology.members.len() {
        assert!(
            size(partition(at)) <= lost.len(),
            "H{at}'s partition is no larger"
        );
        let in_lost = partition(at) == lost_partition;
        assert_eq!(in_lost, lost.contains(&at), "H{at}");
    }
    for placement in &topology.placements {
        let (owner, standby) = (placement.owner, placement.standby);
        assert!(
            !(lost.contains(&owner) && lost.contains(&standby)),
            "shard {} keeps one host outside the lost partition",
            placement.shard.get()
        );
    }
    let survivors: Vec<usize> = (0..topology.members.len())
        .filter(|at| !lost.contains(at))
        .collect();
    for &at in &survivors {
        let probing: BTreeSet<u32> = (survivors.iter())
            .filter(|&&peer| peer != at)
            .map(|&peer| partition(peer).0)
            .filter(|&p| p != lost_partition.0)
            .collect();
        assert!(probing.len() >= 2, "H{at} keeps probers in {probing:?}");
    }
    let standby_only = (topology.placements.iter()).all(|p| p.owner != 2) && topology.roles(2) == 1;
    assert!(standby_only, "H2 holds s2's standby role alone");
}

#[test]
fn a_lost_partition_takes_over_above_the_threshold_and_suspects_itself_at_it() {
    a_lost_partition_takes_over_above_the_threshold_and_suspects_itself_at_it_on(1);
}

pub(super) fn a_lost_partition_takes_over_above_the_threshold_and_suspects_itself_at_it_on(
    root: u64,
) {
    let above = passing(&Config::partition_loss(root));
    assert_eq!(taken(&above), [(1, H3), (2, H3), (3, H5)]);
    assert_eq!(
        (above.hosts.host_losses, above.hosts.repair_demands),
        (2, 0)
    );
    let records = last_records(&above);
    assert_eq!(
        records[3].standby,
        Some(Host::new(H0).unwrap()),
        "s3's standby is lost"
    );
    assert_eq!(
        records[5].standby,
        Some(Host::new(H1).unwrap()),
        "s5's standby is lost"
    );

    let at = passing(&Config::partition_loss_at(root));
    assert_eq!((taken(&at).len(), at.hosts.nominations), (0, 0));
    assert_eq!(at.hosts.host_losses, 3);
    assert!(at.hosts.repair_demands >= 1);
    assert_eq!(at.evidence.volumes, Volumes::default());
    assert_eq!(at.takeovers, 0);
}

#[test]
fn a_false_suspicion_is_vetoed_and_its_isolated_sibling_nominates() {
    a_false_suspicion_is_vetoed_and_its_isolated_sibling_nominates_on(1);
}

pub(super) fn a_false_suspicion_is_vetoed_and_its_isolated_sibling_nominates_on(root: u64) {
    let config = Config::false_suspicion(root);
    let report = passing(&config);
    assert_eq!(replay(&config, &report.recording()).as_ref(), Ok(&report));
    assert!(report.hosts.vetoes >= 1);
    assert!(
        report.hosts.contested >= 1,
        "an ALIVE reply met a DEAD reply to one probe"
    );
    assert_eq!((report.hosts.nominations, report.takeovers), (0, 0));
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
    for shard in &report.shards[..2] {
        assert_eq!(shard.recoveries.len(), 1);
        assert_eq!(shard.owner.get(), H0);
    }

    let isolated = passing(&Config::owner_isolation(root));
    assert!(isolated.hosts.nominations >= 1, "the probers read DEAD");
    assert_eq!(taken(&isolated), [(1, H3), (2, H3), (3, H5)]);
}

#[test]
fn a_paused_or_isolated_owner_withdraws_each_deposed_tenure() {
    a_paused_or_isolated_owner_withdraws_each_deposed_tenure_on(1);
}

pub(super) fn a_paused_or_isolated_owner_withdraws_each_deposed_tenure_on(root: u64) {
    for config in [Config::owner_pause(root), Config::owner_isolation(root)] {
        let report = passing(&config);
        assert_eq!(taken(&report), [(1, H3), (2, H3), (3, H5)]);
        let log = &report.hosts;
        let shards: Vec<u32> = log.withdrawals.iter().map(|(shard, _)| *shard).collect();
        assert_eq!(shards, [1, 2, 3], "{:?}", config.scenario);
        assert_eq!(log.unwithdrawn, 0);
        // Each withdrawn tenure ends as `serve` ends a deposed process: torn down, its owner's parts returned.
        let torn = report.duties.torn.iter();
        let torn: Vec<(u32, bool)> = torn.map(|&(shard, _, shut)| (shard, shut)).collect();
        assert_eq!(
            torn,
            [(1, true), (2, true), (3, true)],
            "{:?}",
            config.scenario
        );
    }
}

#[test]
fn each_required_outcome_of_a_host_scenario_fails_by_its_rule_and_the_unaltered_run_passes() {
    let legal = passing(&Config::host_loss(1));
    assert_eq!(hosts::expected(&legal), Verdict::Pass);
    let rule = |edit: fn(&mut Report)| {
        let mut report = legal.clone();
        edit(&mut report);
        hosts::expected(&report).rule()
    };
    let stale = "a later tenure served an object an acknowledged INVALIDATE covered";
    assert_eq!(rule(|report| report.hosts.stale_hits = 1), Some(stale));
    let mut serial = legal.clone();
    serial.hosts.overlapped = 0;
    assert_eq!(hosts::expected(&serial), Verdict::Unrun(hosts::TWO_LOADS));
    let unwithdrawn = "a deposed owner kept serving to the end of the run";
    assert_eq!(
        rule(|report| report.hosts.unwithdrawn = 1),
        Some(unwithdrawn)
    );
    let unnamed = "a lost shard recovered on a host other than its named standby";
    let elsewhere = |report: &mut Report| {
        let versions = &mut report.evidence.histories[0].1;
        let seeded = versions[0].owner;
        let taken = versions.iter_mut().find(|record| record.owner != seeded);
        taken.unwrap().owner = Host::new(H5).unwrap();
    };
    assert_eq!(rule(elsewhere), Some(unnamed));
    let checkpoint = "a shard record dropped or replaced its named checkpoint";
    let dropped = |report: &mut Report| {
        let versions = &mut report.evidence.histories[0].1;
        versions.last_mut().unwrap().checkpoint = None;
    };
    assert_eq!(rule(dropped), Some(checkpoint));
    let refused = "a detector, a report writer or the report reader refused a host's own input";
    assert_eq!(rule(|report| report.hosts.refused = 1), Some(refused));
    let mut starved = legal.clone();
    starved.hosts.served_beside_load = 0;
    let beside = Verdict::Unrun("witness load-while-serving-own-shard missing");
    assert_eq!(hosts::expected(&starved), beside);
    let suspect =
        "an observer that a veto or its self-suspicion bars nominated or took a shard over";
    let suspecting = passing(&Config::partition_loss_at(1));
    let mut barred = suspecting;
    barred.hosts.nominations = 1;
    assert_eq!(hosts::expected(&barred).rule(), Some(suspect));
    let vetoed = passing(&Config::false_suspicion(1));
    assert_eq!(hosts::expected(&vetoed), Verdict::Pass);
    let mut nominated = vetoed.clone();
    nominated.hosts.nominations = 1;
    assert_eq!(hosts::expected(&nominated).rule(), Some(suspect));
    let mut uncontested = vetoed;
    uncontested.hosts.contested = 0;
    let veto = Verdict::Unrun("witness veto missing");
    assert_eq!(hosts::expected(&uncontested), veto);
}

/// CAS-BEFORE-DEVICE control: the host that takes s0 over starts its fencer's device before its standby's view
/// period, while the record still names H0 owner and before any takeover write. The fencer's connect records that
/// record and the period's write log, and the assertion the period makes once `host::stand_by` returns, the one that
/// judges every takeover, panics.
#[test]
#[should_panic(expected = "the first device call follows its own acknowledged takeover write")]
fn a_device_command_before_the_takeover_write_fails_the_standby_periods_assertion() {
    let _ = run(&Config::host_loss(1).hostile(Plant::EarlyDevice, 0));
}

/// CAS-BEFORE-DEVICE control of the period's own write log: s5's record already names H1, its standby, owner with
/// no standby, as a takeover write that committed with an unknown reply leaves it, and H1's fencer starts its device
/// before the period of H1's next witness (plant `EarlyDevice`). The connect meets a record that names the taking
/// host, and the period has no acknowledged write of its own, so the assertion the period makes once
/// `host::stand_by` returns panics. A check of the record alone passes this call.
#[test]
#[should_panic(expected = "the first device call follows its own acknowledged takeover write")]
fn a_device_call_under_a_record_that_names_the_taker_fails_the_periods_assertion_without_its_own_acknowledged_write()
 {
    let (at, member) = (5, 1);
    let config = Config::host_loss(1).hostile(Plant::EarlyDevice, at as u32);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(Vec::new(), fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let _ = fleet.play_script_with(draws, |fleet, live, slots| {
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        assert_eq!(fleet.cells[at].placement.standby, member);
        let before = fleet.record_now(at);
        let taken = ShardRecord {
            owner: fleet.topology.members[member].host,
            standby: None,
            attempts: before.attempts + 1,
            ..before
        };
        commit_shard(fleet, &taken);
        let witness = crate::failover::detect::host::Revalidated {
            shard: before.shard,
            target: crate::failover::retire::Target::of(&before),
            until_us: u64::MAX,
        };
        fleet.take_over(live, slots, member, (before.active, witness, 0))
    });
}

/// A period whose witness lapsed and whose role read ends the process clears the process's `Standby` status, as a
/// period with a fresh witness does: s5's record is rewritten to name H1, its waiting standby, owner, and a witness
/// that lapsed reaches H1's period. The period ends `Rerun(RoleChanged)` at its role read: the fleet counts the
/// lapse and no attempt, queues the next incarnation, and H1's `Standby` status is gone before the next host turn
/// could publish it.
#[test]
fn a_lapsed_period_that_ends_at_its_role_read_ends_the_standby_status() {
    let (at, member) = (5, 1);
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(Vec::new(), fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let ran = fleet.play_script_with(draws, |fleet, live, slots| {
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        assert!(fleet.cells[at].waiting.is_some_and(|(of, ..)| of == member));
        let before = fleet.record_now(at);
        let taken = ShardRecord {
            owner: fleet.topology.members[member].host,
            standby: None,
            attempts: before.attempts + 1,
            ..before
        };
        commit_shard(fleet, &taken);
        let lapsed = crate::failover::detect::host::Revalidated {
            shard: before.shard,
            target: crate::failover::retire::Target::of(&before),
            until_us: 0,
        };
        fleet.take_over(live, slots, member, (before.active, lapsed, 0))?;
        assert_eq!((fleet.log.lapsed, fleet.log.lapsed_acted), (1, 0));
        assert!(fleet.log.takeovers.is_empty(), "{:?}", fleet.log.takeovers);
        assert!(
            fleet.refused.contains_key(&(at, member)),
            "the next incarnation is queued"
        );
        assert_eq!(
            fleet.cells[at].waiting, None,
            "the ended process published a Standby status"
        );
        Ok(())
    });
    ran.expect("a run inside the limits");
}

/// The CAS-BEFORE-DEVICE check's directed rows: a device call follows the committed takeover
/// only when the record names the taking host owner with no standby and the period's own last write of the shard
/// record had an acknowledged `Committed` reply. A takeover write whose reply was unknown and that committed leaves
/// the record naming the host, and a device call after it fails the check, which the record alone would pass.
#[test]
fn a_device_call_after_a_committed_but_unknown_takeover_write_fails_the_cas_before_device_check() {
    use crate::failover::records::Host;
    let (host, other) = (Host::new(H5).unwrap(), Host::new(H0).unwrap());
    assert!(super::owners::follows(Some((host, None)), host, true));
    // The period's write log over a store whose next write times out with its commit: the record changes and the
    // log reads the write unacknowledged.
    use crate::storage::store::sim::{ActorFaults, Faulted, Shared};
    use crate::storage::store::{Key, Outcome, Store, Write};
    let store = Shared::new();
    let faults = std::rc::Rc::new(std::cell::RefCell::new(ActorFaults::default()));
    faults
        .borrow_mut()
        .arm_write(0, Arm::Timeout { commit: true });
    let acked = super::owners::Acked::default();
    let mut logged = super::owners::AckLogged {
        inner: Faulted {
            inner: store.clone(),
            actor: 0,
            faults,
        },
        log: &acked,
    };
    let shard = crate::net::ownership::Shard::new(1).unwrap();
    let outcome = Store::write(&mut logged, &Key::Shard(shard), &Write::Create(vec![1]));
    assert_eq!(outcome, Outcome::Unknown);
    assert!(
        store.0.borrow().current(&Key::Shard(shard)).is_some(),
        "the write committed"
    );
    assert!(!acked.last_acknowledged(shard));
    let unknown =
        "a device call followed a takeover write whose reply was unknown and that committed";
    assert!(
        !super::owners::follows(Some((host, None)), host, false),
        "{unknown}"
    );
    assert!(
        !super::owners::follows(Some((other, Some(host))), host, true),
        "the lost owner's record"
    );
    assert!(
        !super::owners::follows(Some((host, Some(other))), host, true),
        "a standby still named"
    );
    assert!(
        !super::owners::follows(None, host, true),
        "no record of the shard"
    );
}

/// A takeover that unwinds fails its standby's view period. `host::stand_by` contains the unwind of s0's standby,
/// whose store unwinds at the takeover's compare-and-swap, and ends `Rerun(Unwound)`; the period asserts outside
/// that boundary that no takeover unwound.
#[test]
#[should_panic(expected = "the takeover unwound")]
fn a_takeover_that_unwinds_inside_the_standbys_view_period_fails_the_period() {
    let config = Config::host_loss(1);
    let (fleet, _draws) = hosted(&config);
    let cell = &fleet.cells[0];
    let member = cell.placement.standby;
    let (pair, local) = cell.local_of(member).expect("the standby's local record");
    let grounds = Grounds::over(storage_shared(1, fleet.share_on(member)));
    let witness = crate::failover::detect::host::Revalidated {
        shard: cell.placement.shard,
        target: crate::failover::retire::Target::of(&fleet.record_now(0)),
        until_us: u64::MAX,
    };
    let acked = owners::Acked::default();
    let store = owners::AckLogged {
        inner: super::tests::Unwinding(fleet.store.clone()),
        log: &acked,
    };
    let log = fleet.hosts[member].log.clone();
    let mut client =
        crate::storage::store::Client::open(store, log).expect("a host's store client");
    let persist = |_| Ok(local.0.clone().expect("the standby's local record"));
    let _ = owners::stand_by(
        (cell, fleet.topology.members[member], pair),
        (fleet.round, &fleet.store),
        &grounds,
        (&mut client, &local),
        (Some((witness, 0)), false, Some(&acked)),
        persist,
    );
}

/// A host scenario runs no reconciler, so its settle check stays unrun, except that a tenure no fault deposed
/// that ended with an authority other than `Serving` fails it, and the credit reads that failure.
#[test]
fn a_host_scenario_fails_a_tenure_that_stopped_serving_with_no_fault_deposing_it() {
    let config = Config::host_loss(1);
    let (mut fleet, _) = hosted(&config);
    let live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let unrun = Verdict::Unrun(oracles::NO_RECONCILER);
    assert_eq!(fleet.report(&live, 0, Vec::new()).verdicts.settles, unrun);
    fleet.cells[3].withdrawals = 1;
    let report = fleet.report(&live, 0, Vec::new());
    let withdrawn = Some("a tenure that no fault deposed stopped serving");
    assert_eq!(report.verdicts.settles.rule(), withdrawn);
    assert_eq!(report.credit().rule(), withdrawn);
}

/// H3's agent tracks the peers its synced records name. Once those records omit s5, H3 tracks no row for H4 and H1,
/// s5's owner and standby, which are placed in its zone and still send it heartbeats: its agent refuses them
/// `Sender` and the fleet counts none of them as a refused input. A heartbeat of H0 whose tag has one bit flipped
/// counts one, and so does a heartbeat whose sender the zone does not place, which the agent also refuses `Sender`.
/// A heartbeat that names the untracked H4 with its last byte flipped authenticates to no key and counts one, beside
/// an unplaced sender's in the same round.
#[test]
fn a_refused_heartbeat_counts_unless_a_placed_peer_the_receiver_tracks_no_row_for_sent_it() {
    use crate::failover::detect::beat::{self, BeatKey, Header};
    const H2: u64 = 1003;
    const H4: u64 = 1005;
    let config = Config::host_loss(1);
    let (mut fleet, _) = hosted(&config);
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let host = |id: u64| Host::new(id).unwrap();
    let (h3, h4) = (host(H3), host(H4));
    let mut round = |fleet: &mut Fleet<'_>| {
        fleet.host_round(&mut live);
        fleet.round += 1;
        fleet.log.refused
    };
    let tracked = |fleet: &Fleet<'_>| -> Vec<u64> {
        let watch = fleet.hosts[3].agent.as_ref().unwrap().watch();
        let peers = fleet.topology.members.iter().map(|of| of.host);
        let tracked = peers.filter(|&peer| watch.liveness(peer).is_some());
        tracked.map(Host::get).collect()
    };
    assert_eq!(round(&mut fleet), 0);
    assert_eq!(tracked(&fleet), [H0, H1, H2, H4, H5]);
    let named = |record: &ShardRecord| record.owner == h4 || record.standby == Some(h4);
    fleet.hosts[3].records.retain(|record| !named(record));
    fleet.sync(3);
    assert_eq!(round(&mut fleet), 0);
    assert_eq!(tracked(&fleet), [H0, H2, H5], "s5's hosts lose their rows");
    let due = fleet.hosts[3].inbox.len();
    assert!(due >= 1, "H4 turned after H3: {due} heartbeats wait");
    assert_eq!(round(&mut fleet), 0, "heartbeats of H1 and H4, untracked");
    let sealed = |sender: u64| {
        let header = Header {
            host: host(sender),
            boot: [7; 16],
            booted_at_us: 1,
            sequence: 1,
            ack: 0,
            io: 0,
            completions: 0,
            pending: 0,
            ack_boot: [0; 16],
            healthy: true,
        };
        let key = BeatKey::derive(&hosts::host_key(header.host));
        let mut bytes = vec![0; beat::MAX_LEN];
        let len = beat::encode(&header, &[], h3, &key, &mut bytes).unwrap();
        bytes.truncate(len);
        bytes
    };
    // A forged heartbeat that names an untracked placed peer authenticates to no key, so it counts, and it hides no
    // other refusal of its round.
    let mut forged = sealed(H4);
    *forged.last_mut().unwrap() ^= 1;
    let at = fleet.round;
    fleet.hosts[3].inbox.push((at, forged));
    fleet.hosts[3].inbox.push((at, sealed(H5 + 1)));
    assert_eq!(
        round(&mut fleet),
        2,
        "a forged untracked peer and an unplaced sender"
    );

    let mut forged = sealed(H0);
    *forged.last_mut().unwrap() ^= 1;
    let at = fleet.round;
    fleet.hosts[3].inbox.push((at, forged));
    assert_eq!(round(&mut fleet), 3, "a heartbeat whose tag fails");

    let unplaced = H5 + 1;
    assert!(fleet.member_of(host(unplaced)).is_none());
    let at = fleet.round;
    fleet.hosts[3].inbox.push((at, sealed(unplaced)));
    assert_eq!(round(&mut fleet), 4, "a sender the zone does not place");
    assert_eq!(round(&mut fleet), 4);
}

/// The fleet's nomination queue keeps, for each standby process, the witness a production link inbox keeps. The
/// same witnesses go in the same order to `Fleet::deliver` and to one `host::link::Inbox` per volume: one that
/// expires earlier than the queued witness, one that expires with it and one that expires later, on two volumes of
/// H3 in turn. After each delivery the queue's witness for the volume equals the inbox's. An entry whose witness is
/// replaced keeps its place in the queue and takes the turn time of the new witness, and an entry whose witness
/// outlasts a later delivery keeps its own.
#[test]
fn the_nomination_queue_keeps_the_witness_a_link_inbox_keeps() {
    use crate::failover::detect::host::Revalidated;
    use crate::failover::retire::Target;
    use crate::host::link::{Inbound, Inbox};
    let config = Config::host_loss(1);
    let (mut fleet, _) = hosted(&config);
    let records = &fleet.hosts[3].records;
    let (s0, s3) = (records[0], records[3]);
    assert_ne!(s0.active, s3.active);
    let witness = |record: &ShardRecord, until_us: u64| Revalidated {
        shard: record.shard,
        target: Target::of(record),
        until_us,
    };
    let volumes = [s0.active, s3.active];
    let inboxes = [Inbox::default(), Inbox::default()];
    // Each delivery: the volume's index, the witness, the turn time and the turn time its entry holds afterwards.
    let deliveries = [
        (0, witness(&s0, 100), 1, 1),
        (1, witness(&s3, 50), 2, 2),
        (0, witness(&s0, 90), 3, 1),
        (0, witness(&s3, 100), 4, 4),
        (1, witness(&s3, 60), 5, 5),
        (0, witness(&s0, 120), 6, 6),
        (1, witness(&s3, 55), 7, 5),
        (0, witness(&s0, 110), 8, 6),
    ];
    for (step, (at, delivered, turn, kept_turn)) in deliveries.into_iter().enumerate() {
        fleet.deliver(3, volumes[at], delivered, turn);
        assert!(inboxes[at].deliver(Inbound::Nominate(delivered)));
        let queued: Vec<_> = fleet.nominated.iter().copied().collect();
        let places: Vec<_> = queued.iter().map(|(of, on, ..)| (*of, *on)).collect();
        let expected = [(3, volumes[0]), (3, volumes[1])];
        assert_eq!(places, expected[..queued.len()], "step {step}");
        let (.., kept, held_turn) = queued[at];
        let inbox = inboxes[at].hold();
        assert_eq!(*inbox, [Inbound::Nominate(kept)], "step {step}");
        assert_eq!(held_turn, kept_turn, "step {step}");
    }
    for (at, inbox) in inboxes.iter().enumerate() {
        assert_eq!(inbox.nomination(), Some(fleet.nominated[at].2));
    }
}

/// The one-owner controls of the host loss over its root-1 evidence: a second host's activation of s0's takeover
/// tenure, as plant `TwinStart` logs it, fails by the twin-tenure rule, and the takeover's activation moved to H5
/// by the unnamed-tenure rule. The scheduled case runs the live `TwinStart` plant ([`twin_start_on`]) on root 1.
#[test]
fn host_loss_controls_fail_one_owner_by_a_twin_start_and_a_moved_activation() {
    let config = Config::host_loss(1);
    let evidence = passing(&config).evidence;
    let unaltered = oracles::one_owner(&evidence.histories, &evidence.activations);
    assert_eq!(unaltered, Verdict::Pass);

    let mut twinned = evidence.activations.clone();
    let taken = (evidence.activations.iter())
        .find(|(shard, _, host)| shard.get() == 1 && host.get() == H3)
        .expect("s0's takeover activation");
    twinned.push((taken.0, taken.1, Host::new(H5).unwrap()));
    let rule = oracles::one_owner(&evidence.histories, &twinned).rule();
    assert_eq!(rule, Some("two hosts activated one tenure"));

    let mut moved = evidence.activations.clone();
    let successor = (moved.iter_mut())
        .find(|(shard, _, host)| shard.get() == 1 && host.get() == H3)
        .expect("s0's takeover activation");
    successor.2 = Host::new(H5).unwrap();
    let rule = oracles::one_owner(&evidence.histories, &moved).rule();
    let unnamed = "a tenure activated that no record version names for its host";
    assert_eq!(rule, Some(unnamed));
}

#[test]
fn a_host_loss_log_with_a_generation_raised_after_the_loss_fails_the_volume_check() {
    let evidence = passing(&Config::host_loss(1)).evidence;
    let unaltered = oracles::keeps_volume(
        &evidence.histories,
        evidence.volumes,
        1,
        &oracles::Losses::default(),
    );
    assert_eq!(unaltered, Verdict::Pass);
    let mut raised = evidence.histories.clone();
    let last = raised[0].1.last_mut().expect("s0's record");
    let next = last.generation.get() + 1;
    last.generation = crate::net::ownership::ShardGeneration::new(next).unwrap();
    let rule =
        oracles::keeps_volume(&raised, evidence.volumes, 1, &oracles::Losses::default()).rule();
    let moved = "a generation or an active volume changed with no volume lost";
    assert_eq!(rule, Some(moved));
}

/// The host-share controls of the host loss over its root-1 evidence: a host with two roles whose share is built
/// over one owner, as plant `WholeShare` builds it, fails by the roles rule, and that host's peak reads raised past
/// twice its share, as plant `UnchargedRead` charges them, fail by the reads rule. The scheduled case runs the live
/// plants ([`host_share_controls_on`]) on root 1.
#[test]
fn host_loss_controls_fail_the_host_share_by_its_roles_and_by_its_reads() {
    let report = passing(&Config::host_loss(1));
    assert_eq!(report.verdicts.within_share, Verdict::Pass);
    let judged = |edit: &dyn Fn(&mut oracles::HostUse)| {
        let mut used = report.evidence.host_use.clone();
        assert_eq!(oracles::within_share(&used), Verdict::Pass);
        let roles = used.iter_mut().find(|used| used.roles > 1);
        edit(roles.expect("a host with two roles"));
        oracles::within_share(&used).rule()
    };
    let roles = "a host's roles exceed the owners its recovery share divides over";
    let whole = judged(&|used| used.shares.iter_mut().for_each(|share| share.owners = 1));
    assert_eq!(whole, Some(roles));
    let uncharged = judged(&|used| {
        let most = used
            .shares
            .iter()
            .map(|share| share.bytes)
            .max()
            .unwrap_or(0);
        used.peak_bytes = most.saturating_mul(2) + 1;
    });
    assert_eq!(
        uncharged,
        Some("a host's recovery reads passed twice its share")
    );
}

/// The live host-share and twin-start controls of the host loss on `root`.
pub(super) fn host_share_controls_on(root: u64) {
    let config = Config::host_loss(root);
    let whole = hostile(config, Plant::WholeShare, 3);
    assert_eq!(whole.verdicts.within_share.rule(), Some(oracles::ROLES));
    let uncharged = hostile(config, Plant::UnchargedRead, 3);
    assert_eq!(uncharged.verdicts.within_share.rule(), Some(oracles::READS));
    twin_start_on(root);
}

/// The live `TwinStart` control on `root`: a second host starts s0's takeover tenure, and the one-owner check fails by
/// the twin-tenure rule.
fn twin_start_on(root: u64) {
    let twin = hostile(Config::host_loss(root), Plant::TwinStart, 0);
    assert_eq!(twin.hosts.twin_started, 1);
    assert_eq!(twin.verdicts.one_owner.rule(), Some(oracles::TWIN_TENURE));
}

/// Fast witnesses of the host loss's retention, untouched-shard and removed-crash controls, each the root-1 report
/// altered as its plant alters a run: s1's sweep after its takeover one object short (`RestoredEntryMiss`) fails the
/// retained-set check, that sweep skipped (`SkippedSweep`) reads it `Unrun` and so the credit, one neighbour GET
/// refused (`NeighborRefusal`) fails the untouched-shard check, and no host loss and no takeover (`NoCrashEpisode`)
/// leaves the credit `Unrun` on the takeover witness. The scheduled case runs the live controls
/// ([`host_loss_retention_controls_on`]) on root 1.
#[test]
fn host_loss_controls_fail_retention_and_untouched_shards_and_a_removed_crash_reads_unrun() {
    let report = passing(&Config::host_loss(1));
    let judged = |edit: &dyn Fn(&mut Report)| {
        let mut report = report.clone();
        edit(&mut report);
        report.verdicts = report.judged();
        report
    };
    assert_eq!(judged(&|_| {}).verdicts, report.verdicts);
    fn last_sweep(report: &mut Report) -> &mut Option<(u32, u32)> {
        let sweeps = &mut report.evidence.retention[1].sweeps;
        sweeps.last_mut().expect("s1's sweeps")
    }
    let eligible = report.evidence.retention[1]
        .sweeps
        .last()
        .expect("s1's sweeps");
    let eligible = eligible.expect("s1's last sweep").0;
    let missed = judged(&|report| *last_sweep(report) = Some((eligible, eligible - 1)));
    let unserved = Verdict::Fail(
        "a retained entry was not served its exact bytes at the recovered tenure",
        format!("shard 2 served {} of {eligible}", eligible - 1),
    );
    assert_eq!(missed.verdicts.retained, unserved);
    let skipped = judged(&|report| *last_sweep(report) = None);
    let unswept = Verdict::Unrun("the retained-set sweep did not run");
    assert_eq!(skipped.verdicts.retained, unswept);
    assert_eq!(skipped.credit(), unswept);

    let refused = judged(&|report| report.evidence.neighbour_gets[0].1 = false);
    let rule = refused.verdicts.untouched.rule();
    let unserved = "an untouched shard did not serve a request its object's bytes";
    assert_eq!(rule, Some(unserved));

    let none = judged(&|report| {
        report.hosts.takeovers.clear();
        report.hosts.host_losses = 0;
        report.takeovers = 0;
    });
    assert_eq!(none.credit(), Verdict::Unrun("witness takeovers missing"));
}

/// The live retention, untouched-shard and removed-crash controls of the host loss on `root`.
pub(super) fn host_loss_retention_controls_on(root: u64) {
    let config = Config::host_loss(root);
    let missed = hostile(config, Plant::RestoredEntryMiss, 1);
    let unserved = Verdict::Fail(
        "a retained entry was not served its exact bytes at the recovered tenure",
        "shard 2 served 6 of 7".into(),
    );
    assert_eq!(missed.verdicts.retained, unserved);
    let skipped = hostile(config, Plant::SkippedSweep, 1);
    let unswept = Verdict::Unrun("the retained-set sweep did not run");
    assert_eq!(skipped.verdicts.retained, unswept);
    assert_eq!(skipped.credit(), unswept);

    let refused = hostile(config, Plant::NeighborRefusal, 0);
    let rule = refused.verdicts.untouched.rule();
    let unserved = "an untouched shard did not serve a request its object's bytes";
    assert_eq!(rule, Some(unserved));

    let none = run(&config.hostile(Plant::NoCrashEpisode, 0)).unwrap();
    assert_eq!(none.credit(), Verdict::Unrun("witness takeovers missing"));
    assert_eq!((none.takeovers, none.hosts.host_losses), (0, 0));
}

/// A host-loss tape replayed under a shape of more objects is refused at its first changed candidate set, on root 1;
/// the scheduled case runs the host loss again on root 3, replays it to an equal report and digest, and keeps the
/// first arrival's draws in a run of one request.
#[test]
fn a_host_loss_tape_replayed_under_more_objects_is_refused_at_its_candidates() {
    a_tape_replayed_under_more_objects_is_refused_at_its_candidates(&Config::host_loss(1));
}

fn a_tape_replayed_under_more_objects_is_refused_at_its_candidates(config: &Config) {
    let report = passing(config);
    let mut fuller = *config;
    fuller.shape.objects = 9;
    let recording = Recording {
        identity: fuller.identity(),
        tape: report.tape.clone(),
    };
    match replay(&fuller, &recording) {
        Err(Stopped::Choice(refusal)) => {
            assert_eq!(refusal.error, crate::sim::choice::ChoiceError::Candidates);
        }
        other => panic!("{other:?}"),
    }
}

pub(super) fn a_host_loss_replays_its_recording_and_an_extra_arrival_moves_no_other_decision_on(
    root: u64,
) {
    let config = Config::host_loss(root);
    let report = passing(&config);
    assert_eq!(run(&config).as_ref(), Ok(&report));
    let replayed = replay(&config, &report.recording()).expect("the recording replays");
    assert_eq!((&replayed, replayed.digest()), (&report, report.digest()));
    a_tape_replayed_under_more_objects_is_refused_at_its_candidates(&config);

    let one = passing(&Config {
        requests: 1,
        ..config
    });
    let arrivals = &report.hosts.arrivals;
    assert_eq!(arrivals.len(), 2);
    assert_eq!(
        one.hosts.arrivals,
        arrivals[..1],
        "the first arrival keeps its draws"
    );
    assert_eq!(
        one.hosts.boot, report.hosts.boot,
        "the boot order keeps its draws"
    );
    assert_eq!(
        one.hosts.fired, report.hosts.fired,
        "every episode fires at its round"
    );
    assert_eq!(one.hosts.takeovers, report.hosts.takeovers);
    assert_eq!(one.evidence.histories, report.evidence.histories);
}

/// H0's isolation has no heal, so its loss ends when another tenure serves each shard H0 held. The loss then
/// stays open through the three takeovers: a GET at a takeover's load start to a shard the open loss names is
/// judged by its refusal alone, and a watch covers every other GET the untouched check judges.
#[test]
fn an_isolation_with_no_heal_keeps_its_loss_open_until_each_shard_is_taken_over() {
    let mut script = Scenario::OwnerIsolation.episodes(false);
    script[0].heal = None;
    let report = scripted(&Config::owner_isolation(1), script);
    assert_eq!(taken(&report), [(1, H3), (2, H3), (3, H5)]);
    assert_eq!(
        report.credit(),
        Verdict::Pass,
        "{}",
        report.lines().join("\n")
    );
}

/// H0 pauses, its three shards are taken over, and H0 then crashes for good while its three deposed tenures are
/// still live. The crash drops them, so the run ends with no deposed tenure left serving and none withdrawn, and
/// the pause's heal leaves the crashed host down.
#[test]
fn a_crash_drops_the_deposed_tenures_of_its_host() {
    use super::faults::Pattern;
    let mut script = Scenario::OwnerPause.episodes(false);
    script.push(Episode {
        trigger: Trigger::After(Pattern::TakeOver, 3),
        scope: vec![0],
        action: Action::Crash,
        heal: None,
    });
    let report = scripted(&Config::owner_pause(1), script);
    assert_eq!(taken(&report), [(1, H3), (2, H3), (3, H5)]);
    // The run carries the scripted mark, so the alarm oracle reads it as a run with no expected set.
    assert_eq!(report.alarms(), Verdict::Unrun(alarms::NOT_JUDGED));
    let log = &report.hosts;
    assert_eq!((log.unwithdrawn, log.withdrawals.len()), (0, 0));
    let withdrawn = Verdict::Unrun("witness withdrawn missing");
    assert_eq!(hosts::expected(&report), withdrawn);
}

/// A crash or a pause ends at once, a cut with a heal at its heal round whatever tenure serves, and a cut with no
/// heal only when another tenure serves each lost shard.
#[test]
fn the_cause_of_a_loss_ends_by_its_kind() {
    use super::hosts::Ends;
    for moved in [false, true] {
        assert!(Ends::Hosts.reached(0, moved));
        assert!(!Ends::Heal(5).reached(4, moved));
        assert!(Ends::Heal(5).reached(5, moved));
        assert_eq!(Ends::Takeover.reached(u64::MAX, moved), moved);
    }
}

#[test]
fn the_legal_profile_admits_no_hostile_kind_and_a_hostile_run_names_its_kind() {
    for hostile in Hostile::ALL {
        assert!(!Kind::Hostile(hostile).admitted(Profile::Legal));
        assert!(!Kind::Hostile(hostile).admitted(Profile::Hostile(Plant::TwinTenure, 0)));
        assert!(Kind::Hostile(hostile).admitted(Profile::Arm(hostile)));
        for other in Hostile::ALL.into_iter().filter(|other| *other != hostile) {
            assert!(!Kind::Hostile(hostile).admitted(Profile::Arm(other)));
        }
    }
    let legal = [
        Kind::Crash,
        Kind::Pause,
        Kind::LinkDrop,
        Kind::Delay,
        Kind::Partition,
        Kind::Isolation,
        Kind::StoreArm,
        Kind::StoreOutage,
        Kind::Volume,
        Kind::OperatorRelease,
        Kind::Handoff,
    ];
    assert!(legal.iter().all(|kind| kind.admitted(Profile::Legal)));
    for arm in [Arm::LostWrite, Arm::DoubleWin, Arm::StaleCurrentRead] {
        let episode = Episode {
            trigger: Trigger::AtTime(0),
            scope: vec![0],
            action: Action::Store(arm),
            heal: None,
        };
        assert_eq!(Kind::of(&episode), Kind::Hostile(Hostile::StoreKill));
        let faults = Faults::new(vec![episode], 6);
        let refused = faults.admit(Profile::Legal).unwrap_err();
        let kind = Kind::Hostile(Hostile::StoreKill);
        assert_eq!((refused.episode, refused.kind), (0, kind));
        assert_eq!(faults.admit(Profile::Arm(Hostile::StoreKill)), Ok(()));
    }
    for scenario in [
        Scenario::HostLoss,
        Scenario::PartitionLoss,
        Scenario::FalseSuspicion,
        Scenario::OwnerPause,
    ] {
        let faults = Faults::new(scenario.episodes(false), 6);
        assert_eq!(faults.admit(Profile::Legal), Ok(()));
    }

    let report = run(&Config::host_loss(1).arm(Hostile::ForeignRegistrant)).unwrap();
    assert_eq!(report.credit(), Verdict::Unrun(HOSTILE));
    assert!(
        report
            .summary()
            .ends_with("; profile hostile:foreign-registrant")
    );
    let planted = run(&Config::host_loss(1).hostile(Plant::WholeShare, 3)).unwrap();
    assert!(planted.summary().ends_with("; plant WholeShare at 3"));
}

#[test]
fn every_host_scenario_prints_its_host_line_with_the_exempt_shards() {
    let mut report = passing(&Config::host_loss(1));
    let host_line = |report: &Report| {
        let mut lines = report.lines().into_iter();
        let line = lines.find(|line| line.contains(" hosts nominations "));
        line.expect("the host line")
    };
    assert!(report.hosts.exempt.is_empty());
    let line = host_line(&report);
    assert!(line.contains(" exempt {} "), "{line}");
    report.hosts.exempt = BTreeSet::from([2, 5]);
    let line = host_line(&report);
    assert!(line.contains(" exempt {2, 5} "), "{line}");
}

/// The digest of a host run covers every field of its host log: the drawn boot order and arrivals, the round each
/// episode fired at and the exempt shards by name, beside each count and list the host line already held.
#[test]
fn the_digest_of_a_host_run_changes_with_every_field_of_its_host_log() {
    let report = passing(&Config::host_loss(1));
    type Edit = fn(&mut hosts::HostLog);
    let edits: [(&str, Edit); 32] = [
        ("nominations", |log| log.nominations += 1),
        ("addressed", |log| log.addressed += 1),
        ("unmatched probes", |log| log.unmatched_probes += 1),
        ("vetoes", |log| log.vetoes += 1),
        ("contested", |log| log.contested += 1),
        ("repair demands", |log| log.repair_demands += 1),
        ("host losses", |log| log.host_losses += 1),
        ("lapsed", |log| log.lapsed += 1),
        ("lapsed-acted", |log| log.lapsed_acted += 1),
        ("overlapped", |log| log.overlapped += 1),
        ("unslotted", |log| log.unslotted += 1),
        ("rerun dropped", |log| log.rerun_dropped += 1),
        ("refused reruns", |log| log.refused_reruns += 1),
        ("gray readings", |log| log.gray_readings += 1),
        ("a gray pair", |log| {
            log.gray.insert((1001, 1002));
        }),
        ("a held entry", |log| log.held.push((1, 1001, 1))),
        ("takeovers", |log| log.takeovers[0].commands.push("ready")),
        ("reports", |log| log.reports += 1),
        ("refused", |log| log.refused += 1),
        ("stale replies", |log| log.stale_replies += 1),
        ("an arrival's round", |log| log.arrivals[0].0 += 1),
        ("the boot order", |log| log.boot.swap(0, 1)),
        ("a firing round", |log| log.fired[0] = Some(2)),
        ("an exempt shard", |log| {
            log.exempt.insert(4);
        }),
        ("loads beside service", |log| log.loads_beside_service += 1),
        ("served beside load", |log| log.served_beside_load += 1),
        ("twins", |log| log.twin_started += 1),
        ("withdrawals", |log| log.withdrawals.push((1, 0))),
        ("unwithdrawn", |log| log.unwithdrawn += 1),
        ("stale hits", |log| log.stale_hits += 1),
        ("a sealed headroom", |log| {
            log.headrooms[0].2[2] = Gauge::known(1, 1)
        }),
        ("an unfired episode", |log| log.fired[0] = None),
    ];
    for (part, edit) in edits {
        let mut edited = report.clone();
        edit(&mut edited.hosts);
        assert_ne!(edited.digest(), report.digest(), "{part}");
    }
    let exempting = |shard: u32| {
        let mut edited = report.clone();
        edited.hosts.exempt.insert(shard);
        edited.digest()
    };
    assert_ne!(exempting(4), exempting(5), "which shard is exempt");
}

/// The digest covers the whole report: each oracle input, a record version's checkpoint included, and whether the
/// profile's plant changed the run.
#[test]
fn the_digest_of_a_run_changes_with_its_oracle_evidence_and_its_planted_flag() {
    let report = passing(&Config::host_loss(1));
    type Edit = fn(&mut Report);
    let edits: [(&str, Edit); 5] = [
        ("a record version's checkpoint", |report| {
            let versions = &mut report.evidence.histories[0].1;
            versions.first_mut().unwrap().checkpoint = None;
        }),
        ("a record's versions", |report| {
            report.evidence.histories[5].1.pop();
        }),
        ("an activation", |report| {
            report.evidence.activations.pop();
        }),
        ("a volume count", |report| {
            report.evidence.volumes.receipts += 1
        }),
        ("the planted flag", |report| {
            report.planted = !report.planted
        }),
    ];
    for (part, edit) in edits {
        let mut edited = report.clone();
        edit(&mut edited);
        assert_ne!(edited.digest(), report.digest(), "{part}");
    }
}

#[test]
fn each_episode_fires_once_when_its_trigger_holds_and_its_heal_undoes_it() {
    use super::faults::{Effect, Pattern};
    let episode = |trigger, scope: Vec<usize>, action, heal| Episode {
        trigger,
        scope,
        action,
        heal,
    };
    let mut faults = Faults::new(
        vec![
            episode(Trigger::AtTime(0), vec![4], Action::Drop(vec![5]), None),
            episode(Trigger::AtTime(0), vec![3], Action::Outage, Some(5)),
            episode(Trigger::AtTime(1), vec![2], Action::Crash, Some(2)),
            episode(Trigger::AtTime(2), vec![0], Action::Partition, Some(3)),
            episode(
                Trigger::After(Pattern::TakeOver, 1),
                vec![1],
                Action::Delay(vec![2], 4),
                Some(2),
            ),
            episode(
                Trigger::After(Pattern::Nominated, 1),
                vec![5],
                Action::Pause,
                Some(1),
            ),
        ],
        6,
    );
    let at = |round: u64| {
        move |trigger: &Trigger| match *trigger {
            Trigger::AtTime(time) => round >= time,
            Trigger::After(Pattern::TakeOver, _) => round >= 3,
            Trigger::After(Pattern::Nominated, _) => round >= 1,
            Trigger::When(_) => false,
        }
    };
    assert_eq!(
        faults.step(0, at(0)),
        [Effect::Cut {
            until: None,
            isolated: Vec::new(),
        }]
    );
    assert!(!faults.links.reaches(4, 5) && !faults.links.reaches(5, 4));
    let reach = |faults: &Faults, now| {
        faults.store.borrow_mut().set_now(now);
        let mut faulted = crate::storage::store::sim::Faulted {
            inner: crate::storage::store::sim::Shared::new(),
            actor: 3,
            faults: faults.store.clone(),
        };
        let key = crate::storage::store::Key::Shard(crate::storage::store_tests::shard());
        crate::storage::store::Store::read(&mut faulted, &key).is_ok()
    };
    assert!(!reach(&faults, 4) && reach(&faults, 5));
    assert_eq!(faults.step(1, at(1)), [Effect::Crash(2), Effect::Pause(5)]);
    let cut = Effect::Cut {
        until: Some(5),
        isolated: vec![0],
    };
    let healed = [cut, Effect::Resume(5)];
    assert_eq!(faults.step(2, at(2)), healed);
    assert!((1..6).all(|other| !faults.links.reaches(0, other)));
    assert!(faults.links.reaches(1, 2));
    assert_eq!(faults.step(3, at(3)), [Effect::Return(2)]);
    assert_eq!((faults.links.delay(1, 2), faults.links.delay(2, 1)), (4, 4));
    assert!(!faults.settled());
    assert_eq!(faults.step(5, at(5)), [Effect::Resume(0)]);
    assert!((1..6).all(|other| faults.links.reaches(0, other)));
    assert_eq!(faults.links.delay(1, 2), 0);
    assert!(!faults.links.reaches(4, 5), "a drop with no heal stays");
    assert!(faults.settled());
    assert_eq!(faults.last_change(), Some(5));
}

/// Three delays of H1's link to H2 overlap: 4 rounds from round 0 to 10, 2 rounds from round 2 to 5 and 4 rounds
/// from round 3 to 12. The link carries the largest delay in force, and each heal takes off its own episode's
/// delay alone.
#[test]
fn a_delay_that_heals_leaves_an_overlapping_delay_in_force() {
    let delay = |from: u64, rounds: u64, heal: u64| Episode {
        trigger: Trigger::AtTime(from),
        scope: vec![1],
        action: Action::Delay(vec![2], rounds),
        heal: Some(heal),
    };
    let script = vec![
        delay(0, 4, 10),
        delay(2, 2, 3),
        delay(3, 4, 9),
        delay(12, 2, 2),
    ];
    let mut faults = Faults::new(script, 6);
    let mut delays = |round: u64| {
        let due = |trigger: &Trigger| matches!(*trigger, Trigger::AtTime(at) if round >= at);
        assert_eq!(faults.step(round, due), []);
        (faults.links.delay(1, 2), faults.links.delay(2, 1))
    };
    assert_eq!(delays(0), (4, 4));
    assert_eq!(delays(2), (4, 4), "the shorter delay began");
    assert_eq!(delays(3), (4, 4));
    assert_eq!(delays(5), (4, 4), "the shorter delay healed");
    assert_eq!(delays(10), (4, 4), "the first of two equal delays healed");
    assert_eq!(
        delays(12),
        (2, 2),
        "the last 4-round delay healed and a delay of 2 began"
    );
    assert_eq!(delays(14), (0, 0));
    assert_eq!(faults.links, super::faults::HostLinks::default());
}

/// Two crashes of H2 overlap, the second inside the first, and two pauses of H4 overlap by one round. A host goes
/// down or pauses once, at the first episode, and returns or resumes once, when the last episode on it heals.
#[test]
fn a_host_under_two_crashes_or_two_pauses_returns_when_the_last_one_heals() {
    use super::faults::Effect;
    let episode = |from: u64, member: usize, action: Action, heal: u64| Episode {
        trigger: Trigger::AtTime(from),
        scope: vec![member],
        action,
        heal: Some(heal),
    };
    let script = vec![
        episode(0, 2, Action::Crash, 10),
        episode(2, 2, Action::Crash, 3),
        episode(1, 4, Action::Pause, 3),
        episode(3, 4, Action::Pause, 4),
    ];
    let mut faults = Faults::new(script, 6);
    let mut effects = |round: u64| {
        let due = |trigger: &Trigger| matches!(*trigger, Trigger::AtTime(at) if round >= at);
        faults.step(round, due)
    };
    assert_eq!(effects(0), [Effect::Crash(2)]);
    assert_eq!(effects(1), [Effect::Pause(4)]);
    assert_eq!(effects(2), [], "H2 is down already");
    assert_eq!(effects(3), [], "H4 is paused already");
    assert_eq!(effects(4), [], "H4's first pause healed under its second");
    assert_eq!(effects(5), [], "H2's second crash healed under its first");
    assert_eq!(effects(7), [Effect::Resume(4)]);
    assert_eq!(effects(10), [Effect::Return(2)]);
}

/// A crash holds a host down through a pause or an isolation of it that begins or heals meanwhile, and a pause
/// holds a host through a crash that heals under it: the host returns paused. A host isolated twice reconnects
/// when the second cut heals.
#[test]
fn a_heal_leaves_a_host_in_the_state_its_other_episodes_hold_it_in() {
    use super::faults::Effect;
    let episode = |from: u64, member: usize, action: Action, heal: u64| Episode {
        trigger: Trigger::AtTime(from),
        scope: vec![member],
        action,
        heal: Some(heal),
    };
    let script = vec![
        episode(1, 0, Action::Crash, 10),
        episode(2, 0, Action::Pause, 3),
        episode(3, 0, Action::Partition, 4),
        episode(1, 4, Action::Pause, 10),
        episode(2, 4, Action::Crash, 3),
        episode(0, 5, Action::Partition, 9),
        episode(4, 5, Action::Partition, 2),
    ];
    let mut faults = Faults::new(script, 6);
    let mut effects = |round: u64| {
        let due = |trigger: &Trigger| matches!(*trigger, Trigger::AtTime(at) if round >= at);
        faults.step(round, due)
    };
    let cut = |until: u64, member: usize| Effect::Cut {
        until: Some(until),
        isolated: vec![member],
    };
    assert_eq!(effects(0), [cut(9, 5)]);
    assert_eq!(effects(1), [Effect::Crash(0), Effect::Pause(4)]);
    assert_eq!(
        effects(2),
        [Effect::Crash(4)],
        "H0 is down; H4 crashes paused"
    );
    assert_eq!(effects(3), [cut(7, 0)]);
    assert_eq!(effects(4), [cut(6, 5)]);
    let paused = [Effect::Return(4), Effect::Pause(4)];
    assert_eq!(effects(5), paused, "H0's pause healed under its crash");
    assert_eq!(effects(6), [], "H5's second cut healed under its first");
    assert_eq!(effects(7), [], "H0's isolation healed under its crash");
    assert_eq!(effects(9), [Effect::Resume(5)]);
    assert_eq!(effects(11), [Effect::Return(0), Effect::Resume(4)]);
}

/// A store arm's heal takes the arm off its actor's queue when no request took it, and an arm with no heal stays
/// queued. A write arm heals the same way.
#[test]
fn a_store_arm_that_heals_untaken_leaves_its_actors_queue() {
    for action in [
        Action::Store(Arm::Unavailable),
        Action::StoreWrite(Arm::Unavailable),
    ] {
        let arm = |member: usize, heal: Option<u64>| Episode {
            trigger: Trigger::AtTime(0),
            scope: vec![member],
            action: action.clone(),
            heal,
        };
        let mut faults = Faults::new(vec![arm(3, Some(2)), arm(4, None)], 6);
        let mut queued = |round: u64| {
            let due = |trigger: &Trigger| matches!(*trigger, Trigger::AtTime(at) if round >= at);
            assert_eq!(faults.step(round, due), []);
            let store = faults.store.borrow();
            (store.queued(3), store.queued(4))
        };
        assert_eq!(queued(0), (1, 1), "{action:?}");
        assert_eq!(queued(1), (1, 1), "{action:?}");
        assert_eq!(queued(2), (0, 1), "H3's arm healed untaken: {action:?}");
    }
}

/// A request takes the arm of H3's first episode before a second episode queues an equal arm. The first
/// episode's heal finds its own arm taken and leaves the second episode's arm queued. A write arm heals the same
/// way: a read passes it by, and a write takes it.
#[test]
fn a_store_arm_that_heals_taken_leaves_an_equal_arm_of_another_episode_queued() {
    use crate::storage::store::{Outcome, Store, Write};
    for action in [
        Action::Store(Arm::Unavailable),
        Action::StoreWrite(Arm::Unavailable),
    ] {
        let arm = |from: u64, heal: Option<u64>| Episode {
            trigger: Trigger::AtTime(from),
            scope: vec![3],
            action: action.clone(),
            heal,
        };
        let mut faults = Faults::new(vec![arm(0, Some(5)), arm(2, None)], 6);
        let step = |faults: &mut Faults, round: u64| {
            let due = |trigger: &Trigger| matches!(*trigger, Trigger::AtTime(at) if round >= at);
            assert_eq!(faults.step(round, due), []);
            faults.store.borrow().queued(3)
        };
        assert_eq!(step(&mut faults, 0), 1, "{action:?}");
        let mut faulted = crate::storage::store::sim::Faulted {
            inner: crate::storage::store::sim::Shared::new(),
            actor: 3,
            faults: faults.store.clone(),
        };
        let key = crate::storage::store::Key::Shard(crate::storage::store_tests::shard());
        let read = faulted.read(&key);
        match action {
            Action::Store(_) => assert!(read.is_err(), "the read took the first episode's arm"),
            _ => {
                assert_eq!(read, Ok(None), "the read passed the write arm by");
                let written = faulted.write(&key, &Write::Create(vec![1]));
                assert_eq!(written, Outcome::Unknown, "the write took the arm");
            }
        }
        assert_eq!(faults.store.borrow().queued(3), 0, "{action:?}");
        assert_eq!(
            step(&mut faults, 2),
            1,
            "{action:?}: the second episode's arm"
        );
        assert_eq!(
            step(&mut faults, 5),
            1,
            "{action:?}: the first episode healed"
        );
    }
}

/// An episode with a heal of zero rounds fires and heals in one step of the script.
#[test]
fn an_episode_with_a_heal_of_zero_rounds_heals_in_the_step_it_fires_in() {
    use super::faults::Effect;
    let crash = Episode {
        trigger: Trigger::AtTime(1),
        scope: vec![2],
        action: Action::Crash,
        heal: Some(0),
    };
    let mut faults = Faults::new(vec![crash], 6);
    let due = |trigger: &Trigger| matches!(*trigger, Trigger::AtTime(1));
    assert_eq!(faults.step(1, due), [Effect::Crash(2), Effect::Return(2)]);
    assert!(faults.settled());
    assert_eq!(faults.step(2, due), []);
}

/// A host scenario's owners each acknowledge an INVALIDATE of object 1, so a shape of one object leaves a GET
/// draw no object and is refused before any draw. The same shape runs when the scenario draws no GET.
#[test]
fn a_host_scenario_of_one_object_is_refused_before_any_draw() {
    let mut config = Config::host_loss(1);
    config.shape.objects = 1;
    let refused = run(&config).map(|report| report.summary());
    assert_eq!(refused, Err(Stopped::Shape(bounds::Refused::Objects(1))));
    config.requests = 0;
    assert!(run(&config).is_ok(), "a run with no request draws no GET");
    let planted = run(&config.hostile(Plant::RestoredEntryMiss, 1));
    let planted = planted.expect("a run inside the limits");
    assert!(!planted.planted, "no object lies outside the INVALIDATE");
    let mut restarts = Config::six(1);
    restarts.shape.objects = 1;
    assert!(
        run(&restarts).is_ok(),
        "a restart run invalidates no object"
    );
}

/// Only takeovers that returned a session advance the `Pattern::TakeOver` trigger; published nominations advance
/// `Pattern::Nominated` independently.
#[test]
fn an_after_trigger_fires_at_its_occurrence_of_committed_takeovers_and_of_nominations() {
    use super::faults::Pattern;
    use super::hosts::Attempt;
    let config = Config::host_loss(1);
    let (mut fleet, draws) = hosted(&config);
    fleet.draws = Some(draws);
    let delay = |pattern, from: usize, to: usize| Episode {
        trigger: Trigger::After(pattern, 2),
        scope: vec![from],
        action: Action::Delay(vec![to], 3),
        heal: None,
    };
    let script = vec![
        delay(Pattern::TakeOver, 1, 2),
        delay(Pattern::Nominated, 4, 5),
    ];
    fleet.faults = Faults::new(script, fleet.hosts.len());
    fleet.alarms.scripted = true;
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let mut slots = super::Slots {
        grounds: &[],
        pools: &[],
        members: Vec::new(),
        used: Vec::new(),
    };
    let mut delays = |fleet: &mut Fleet<'_>| {
        fleet
            .episodes(&mut live, &mut slots)
            .expect("a round's episodes");
        let links = &fleet.faults.links;
        (links.delay(1, 2), links.delay(4, 5))
    };
    let attempt = |refused: Option<&str>| Attempt {
        shard: 1,
        host: H3,
        refused: refused.map(String::from),
        commands: Vec::new(),
    };
    fleet.log.nominations = 1;
    fleet.log.takeovers = vec![
        attempt(Some("Standby")),
        attempt(Some("Standby")),
        attempt(None),
    ];
    assert_eq!(delays(&mut fleet), (0, 0), "one occurrence of each pattern");
    fleet.log.takeovers.push(attempt(None));
    assert_eq!(delays(&mut fleet), (3, 0), "the second committed takeover");
    fleet.log.nominations = 2;
    assert_eq!(delays(&mut fleet), (3, 3), "the second nomination");
}

/// Every tenure of a host run runs the production serving duties over an inline store lane: each one that served
/// ended its duties' open `Opened` (a View, an exact-version Confirm and a suffix reservation), each of the six boot
/// tenures acknowledged its FILL and its INVALIDATE, the latter through the duties' coverage write, no duty named an
/// exit, and the untouched shards' record views held to one volume-record and one shard-record read a view period
/// with no write.
#[test]
fn every_serving_tenure_runs_its_duties_and_opens_and_covers_with_no_exit() {
    let report = passing(&Config::host_loss(1));
    let recoveries: usize = report
        .shards
        .iter()
        .map(|shard| shard.recoveries.len())
        .sum();
    let duties = &report.duties;
    assert_eq!(duties.opened as usize, recoveries);
    assert_eq!(duties.acknowledged as usize, report.shards.len());
    assert_eq!(duties.exits, []);
    let boots = report.shards.len() as u64;
    assert!(
        duties.writes >= 2 * u64::from(duties.opened) + boots,
        "a Confirm and a suffix reservation a tenure and a coverage write a boot tenure: {duties:?}"
    );
    assert!(duties.reads > duties.writes);
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
    let line = report
        .lines()
        .into_iter()
        .find(|line| line.contains(" duties opened "));
    assert!(line.is_some(), "the report carries the duties' line");
}

/// FC4 for the serving duties: a timeout on s4's boot Confirm, its suffix reservation or its coverage write, committed
/// or not, licenses nothing. The tenure retries in place, names no exit, runs no second
/// incarnation, acknowledges its INVALIDATE only after a coverage commit of its own, and H2's report counts the unknown
/// store result. The fast tier runs a lost Confirm and a committed coverage write on root 1; the scheduled case runs
/// the other four cells on root 1 and every cell on root 2.
#[test]
fn a_store_timeout_on_a_duty_write_retries_in_place_and_acknowledges_after_its_commit() {
    for cell in FAST_UNKNOWN {
        store_unknown_cell_retries_in_place(1, cell);
    }
}

/// The store-result cells the fast tier runs.
pub(super) const FAST_UNKNOWN: [hosts::Unknown; 2] = [
    hosts::Unknown {
        write: hosts::DutyWrite::Confirm,
        commit: false,
    },
    hosts::Unknown {
        write: hosts::DutyWrite::Page,
        commit: true,
    },
];

/// On root 1 the fast cells and the scheduled row's `repair-and-host unknown-*` members are together every
/// store-result cell, each once. On root 2 the row's members are every cell.
#[test]
fn the_fast_tier_and_the_scheduled_row_run_every_store_result_cell_once() {
    let members = super::tests::inventory_members("search-nightly", "fleet-scheduled-roots");
    let listed = |root: &str| -> Vec<String> {
        (members.iter())
            .filter_map(|member| member.strip_prefix("repair-and-host ")?.strip_suffix(root))
            .filter(|name| name.starts_with("unknown-"))
            .map(str::to_owned)
            .collect()
    };
    let mut run = listed(" root 1");
    run.extend(FAST_UNKNOWN.iter().map(|cell| cell.name()));
    run.sort_unstable();
    let mut every: Vec<String> = hosts::Unknown::all()
        .into_iter()
        .map(hosts::Unknown::name)
        .collect();
    every.sort_unstable();
    assert_eq!(run, every);
    let mut second = listed(" root 2");
    second.sort_unstable();
    assert_eq!(second, every, "the row's second root");
}

/// The checks of [`a_store_timeout_on_a_duty_write_retries_in_place_and_acknowledges_after_its_commit`] for `cell`
/// on `root`, which the scheduled case also runs.
pub(super) fn store_unknown_cell_retries_in_place(root: u64, cell: hosts::Unknown) {
    use super::hosts::DutyWrite;
    let report = passing(&Config::store_unknown(root, cell));
    let faulted = report
        .duties
        .faulted
        .clone()
        .expect("the faulted boot tenure");
    assert!(
        faulted.taken,
        "{}: the duties' write took the timeout",
        cell.name()
    );
    assert_eq!(faulted.timed_out, Some(cell.write), "{}", cell.name());
    assert_eq!(
        faulted.recoveries,
        1,
        "{}: no second incarnation",
        cell.name()
    );
    let shard = hosts::DUTY_SHARD;
    assert!(!report.duties.exits.iter().any(|(of, ..)| *of == shard));
    let acknowledged = faulted
        .acknowledged_at
        .expect("the INVALIDATE acknowledged");
    assert!(
        acknowledged > faulted.held_at,
        "{}: a coverage commit before the ack",
        cell.name()
    );
    // The shard-record writes are the Confirm and the reservation, and a boot tenure's coverage write is one page
    // write. A timed-out Confirm, committed or not, and a committed reservation each take one Confirm more after the
    // next view's re-read; a lost reservation takes a Confirm and a reservation more. A timed-out coverage write takes
    // one rewrite more, and a committed one also a write its condition refuses.
    let writes = (faulted.record_writes, faulted.page_writes);
    let expected = match (cell.write, cell.commit) {
        (DutyWrite::Confirm, _) | (DutyWrite::Reserve, true) => (3, 1),
        (DutyWrite::Reserve, false) => (4, 1),
        (DutyWrite::Page, false) => (2, 2),
        (DutyWrite::Page, true) => (2, 3),
    };
    assert_eq!(writes, expected, "{}: record and page writes", cell.name());
    let sealed = report.hosts.sealed_stores(hosts::DUTY_HOST, shard);
    assert!(
        sealed
            .clone()
            .any(|store| store.unknown.is_some_and(|n| n > 0)),
        "{}: H2's report counts the unknown result",
        cell.name()
    );
    assert!(
        sealed
            .clone()
            .all(|store| store.watermark == crate::failover::report::Watermark::Clear),
        "{}: an unknown result raises no store alarm",
        cell.name()
    );
}

/// A regression scenario's run under the store-kill profile: its scenario's outcomes pass and, as every hostile run,
/// it earns no credit.
fn store_killed(config: &Config) -> Report {
    let report = run_shared(config).expect("a run inside the limits");
    assert_eq!(
        hosts::expected(&report),
        Verdict::Pass,
        "{}",
        report.lines().join("\n")
    );
    assert_eq!(report.credit(), Verdict::Unrun(super::HOSTILE));
    assert!(report.summary().ends_with("; profile hostile:store-kill"));
    report
}

/// Under the store-kill profile, the store commits the coverage write, but the duties see a timeout. Their re-read
/// returns the page's first version, whose fence lies below the tenure's. The tenure's authority withdraws with
/// `Cause::Regression`, and the INVALIDATE stays unacknowledged. A record view that reads an older shard record
/// version than the one last observed withdraws the duties' store client and the authority with
/// `Cause::Regression`. The duties return `Rerun(Withdrawn)` in both runs, the process tears the tenure down, and its
/// next incarnation serves the shard at the next attempt. H2's sealed report includes the store regression alarm for
/// s4. The legal profile refuses each regression before any draw. The scheduled case runs root 2.
#[test]
fn a_regressed_read_withdraws_the_tenure_and_the_hosts_report_carries_the_regression_alarm() {
    a_regressed_read_withdraws_the_tenure_and_the_hosts_report_carries_the_regression_alarm_on(1);
}

pub(super) fn a_regressed_read_withdraws_the_tenure_and_the_hosts_report_carries_the_regression_alarm_on(
    root: u64,
) {
    let withdrawn = crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn);
    let shard = hosts::DUTY_SHARD;
    let page = store_killed(&Config::page_regressed(root));
    let faulted = page
        .duties
        .faulted
        .clone()
        .expect("the faulted boot tenure");
    assert_eq!(faulted.acknowledged_at, None);
    assert!(faulted.stale_served, "the stale page read was served");
    let regression = crate::failover::serving::Cause::Regression;
    assert_eq!(
        faulted.withdrawal,
        Some(regression),
        "the authority withdrew for the regressed page"
    );
    let exits: Vec<_> = (page.duties.exits.iter())
        .map(|(at, tenure, exit, _)| (*at, *tenure, exit.clone()))
        .collect();
    assert_eq!(exits, [(shard, faulted.tenure, withdrawn.clone())]);
    // The record at the withdrawn tenure's close still names that tenure: its rerun's bump follows the close.
    assert_eq!(page.duties.exits[0].3, (faulted.tenure.g, faulted.tenure.a));
    reran(&page, faulted.tenure);

    let record = store_killed(&Config::record_regressed(root));
    let faulted = record
        .duties
        .faulted
        .clone()
        .expect("the faulted boot tenure");
    assert!(
        faulted.acknowledged_at.is_some(),
        "the INVALIDATE acknowledged before the stale view"
    );
    assert!(faulted.stale_served, "the stale record read was served");
    assert_eq!(
        faulted.withdrawal,
        Some(regression),
        "the authority withdrew for the regressed record"
    );
    let exits: Vec<_> = (record.duties.exits.iter())
        .map(|(at, tenure, exit, _)| (*at, *tenure, exit.clone()))
        .collect();
    assert_eq!(exits, [(shard, faulted.tenure, withdrawn)]);
    reran(&record, faulted.tenure);
    let alarmed = (record.hosts.sealed_stores(hosts::DUTY_HOST, shard))
        .any(|store| store.watermark == crate::failover::report::Watermark::Regression);
    assert!(alarmed, "{:?}", record.hosts.stores);

    for config in [Config::page_regressed(root), Config::record_regressed(root)] {
        let legal = Config {
            profile: Profile::Legal,
            ..config
        };
        let refused = run(&legal).map(|_| ()).unwrap_err();
        let kill = Kind::Hostile(Hostile::StoreKill);
        assert!(
            matches!(refused, Stopped::Inadmissible(faults::Inadmissible { kind, .. }) if kind == kill),
            "{:?}: {refused:?}",
            config.scenario
        );
    }
}

/// The faulted tenure's exit ended the process as `serve` ends it: `serve::teardown` shut the owner down with its
/// parts returned, and the next incarnation on the same host restarted the shard at the next attempt, activated that
/// tenure, swept its whole retained set and serves at the run's end.
fn reran(report: &Report, faulted: Tenure) {
    let shard = hosts::DUTY_SHARD;
    assert_eq!(report.duties.torn, [(shard, faulted, true)]);
    let recoveries = &report.shards[hosts::DUTY_CELL].recoveries;
    let rerun = recoveries.last().expect("the rerun's recovery");
    assert_eq!(
        rerun.tenure,
        Tenure {
            a: faulted.a + 2,
            ..faulted
        }
    );
    assert_eq!(
        rerun.host, recoveries[0].host,
        "the same host's next incarnation"
    );
    assert!(
        rerun
            .sweep
            .is_some_and(|(eligible, served)| eligible == served && eligible > 0)
    );
    let lined =
        (report.duties.lines.iter()).any(|&(of, tenure)| of == shard && tenure == rerun.tenure);
    assert!(
        lined,
        "the rerun's serving turn read its recovery line: {:?}",
        report.duties.lines
    );
    let activated = (report.evidence.activations.iter()).any(|(of, tenure, host)| {
        of.get() == shard && *tenure == rerun.tenure && *host == rerun.host
    });
    assert!(activated, "the rerun's tenure is activated");
}

/// The standby of every shard waits through the production standby wait, one `host::stand_by` view period each
/// `DUTY_VIEW_US`: in the host-loss case each period of each shard's standby wait made its role read, two record
/// reads, and wrote nothing, and every period ended `Exit::Stopped`. Control: one more read of s4's shard record in
/// each period of its standby's wait fails the untouched-shard rule by the standby's bound.
#[test]
fn a_standby_waits_with_two_record_reads_a_period_and_one_more_read_fails_the_bound() {
    let report = passing(&Config::host_loss(1));
    let waited: Vec<&Vec<(u64, u64)>> = report.shards.iter().map(|shard| &shard.waits).collect();
    let whole = waited[hosts::DUTY_CELL].len();
    assert!(
        whole > 0 && waited[hosts::DUTY_CELL + 1].len() == whole,
        "the standbys of s4 and s5 run through the whole run and wait in every view period: {waited:?}"
    );
    assert!(
        waited.iter().all(|waits| waits.len() <= whole),
        "no standby waits in more periods than one that runs through the whole run: {waited:?}"
    );
    assert!(
        waited
            .iter()
            .all(|waits| waits.iter().all(|&period| period == (2, 0))),
        "{waited:?}"
    );
    let exits: Vec<&String> = report
        .shards
        .iter()
        .flat_map(|shard| &shard.wait_exits)
        .collect();
    assert!(exits.is_empty(), "{exits:?}");
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
    let extra = hostile(
        Config::host_loss(1),
        Plant::StandbyExtraRead,
        hosts::DUTY_CELL as u32,
    );
    let bound = "an untouched shard's standby made more than two record reads or a write in a view period of its wait";
    assert_eq!(
        extra.verdicts.untouched.rule(),
        Some(bound),
        "{}",
        extra.summary()
    );
}

#[test]
fn every_running_standby_waits_once_each_view_period() {
    let config = Config::host_loss(1);
    let (mut fleet, _) = hosted(&config);
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    for _ in 0..2 * (DUTY_VIEW_US / ROUND_US) {
        fleet.turn(&mut live);
    }
    let waited: Vec<&Vec<(u64, u64)>> = fleet.cells.iter().map(|cell| &cell.waits).collect();
    assert!(
        waited.iter().all(|waits| waits[..] == [(2, 0), (2, 0)]),
        "{waited:?}"
    );
}

/// A standby process whose inbox holds a nomination runs its next view period with that witness, which is the
/// period `Fleet::take_over` runs: while the nominations of s4's and s5's standbys are queued,
/// `Fleet::standby_waits` runs no period for them, and every other shard's standby waits as before.
#[test]
fn a_standby_with_a_queued_nomination_runs_no_period_without_the_witness() {
    use crate::failover::detect::host::Revalidated;
    use crate::failover::retire::Target;
    let config = Config::host_loss(1);
    let (mut fleet, _) = hosted(&config);
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let period = DUTY_VIEW_US / ROUND_US;
    for _ in 0..period {
        fleet.turn(&mut live);
    }
    let waits = |fleet: &Fleet<'_>| -> Vec<usize> {
        fleet.cells.iter().map(|cell| cell.waits.len()).collect()
    };
    assert!(waits(&fleet).iter().all(|&periods| periods == 1));
    let queued = [hosts::DUTY_CELL, hosts::DUTY_CELL + 1];
    for at in queued {
        let record = fleet.record_now(at);
        let standby = record.standby.expect("the seeded standby");
        let member = fleet.member_of(standby).expect("a placed standby");
        let witness = Revalidated {
            shard: record.shard,
            target: Target::of(&record),
            until_us: u64::MAX,
        };
        fleet.deliver(member, record.active, witness, fleet.round);
    }
    for _ in 0..period {
        fleet.turn(&mut live);
    }
    assert_eq!(fleet.nominated.len(), 2, "both nominations stay queued");
    let expected: Vec<usize> = (0..fleet.cells.len())
        .map(|at| if queued.contains(&at) { 1 } else { 2 })
        .collect();
    assert_eq!(waits(&fleet), expected);
}

/// A cell that moves to another volume, as a fresh activation moves it, excuses its standby's waits on the records
/// it then holds: the two role reads of the volume record it left leave the count with that record's requests.
#[test]
fn a_cell_that_moves_to_another_volume_excuses_only_the_waits_on_the_records_it_holds() {
    let config = Config::host_loss(1);
    let (mut fleet, _) = hosted(&config);
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    for _ in 0..2 * (DUTY_VIEW_US / ROUND_US) {
        fleet.turn(&mut live);
    }
    let at = hosts::DUTY_CELL;
    assert_eq!(fleet.cells[at].waits[..], [(2, 0), (2, 0)]);
    let before = fleet.hosts_requests(at);
    let left = Key::Volume(fleet.cells[at].placement.volume);
    let on_left = fleet.store.0.borrow().requests(&left);
    assert!(
        on_left >= 2,
        "each period's role read reads the volume record"
    );
    fleet.cells[at].placement.volume =
        crate::failover::records::VolumeId::new("vol-0f000000000000bbb").unwrap();
    // The volume record the cell left held `on_left` requests, two of them the standby's role reads.
    assert_eq!(fleet.hosts_requests(at), before - (on_left - 2));
}

/// A waiting standby has a read-only budget of two reads per view period across all records. A cross-shard read
/// counts against the reader's budget and violates the target shard's request rule.
#[test]
fn a_standby_read_of_another_shards_record_fails_the_bound_and_that_shards_request_rule() {
    let bound = "an untouched shard's standby made more than two record reads or a write in a view period of its wait";
    let request =
        "an untouched shard's records took a store request other than its own record views";
    let (s4, s5) = (hosts::DUTY_CELL, hosts::DUTY_CELL + 1);
    let strayed = |reader: usize, read: usize| {
        let config = Config::host_loss(1).hostile(Plant::StandbyExtraRead, reader as u32);
        let mut draws = Draws::record(config.root);
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        fleet.standby_extra = Some(Key::Shard(fleet.cells[read].placement.shard));
        let _inline = Inline::set();
        let report = (fleet.play_script(draws)).expect("a run inside the limits");
        assert!(report.planted, "the extra read changed the run");
        report
    };
    let (third, foreign) = (strayed(s4, s5), strayed(s5, s4));
    assert_eq!(
        (&third.verdicts.untouched, &foreign.verdicts.untouched),
        (
            &Verdict::Fail(bound, "shard 5 reads 3 writes 0".into()),
            &Verdict::Fail(request, "shard 5".into())
        ),
        "{}\n{}",
        third.summary(),
        foreign.summary()
    );
}

/// An exit that names a rerun while a GET to its shard is in flight still ends the process before the run does.
/// With no episode scripted the hosts are settled when s4's tenure names `Rerun(Withdrawn)` and a GET to s4 goes out:
/// the host loop waits for the GET, tears the tenure down with its parts returned and gives the rerun its turn. H2's
/// one tenure slot is taken, so the rerun is counted unslotted.
#[test]
fn an_exit_named_while_a_get_is_in_flight_is_torn_down_and_rerun_before_the_run_ends() {
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(Vec::new(), fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let at = hosts::DUTY_CELL;
    let mut ended = None;
    let ran = fleet.play_script_with(draws, |fleet, live, slots| {
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        let serving = live[at].as_mut().expect("the boot tenure");
        serving.duty_exit = Some(crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn));
        ended = Some(serving.tenure);
        fleet.send(live, at, 2, Purpose::Neighbour);
        assert_eq!(fleet.flights.len(), 1, "the GET is in flight");
        fleet.run_hosts(live, slots)
    });
    let report = ran.expect("a run inside the limits");
    let ended = ended.expect("the ended tenure");
    assert_eq!(report.duties.torn, [(hosts::DUTY_SHARD, ended, true)]);
    assert_eq!(report.hosts.unslotted, 1, "{}", report.summary());
}

/// A rerun queued for a host that pauses before the host loop gives it its turn waits for the host's resume: a
/// paused host's processes run nothing, and the process's next incarnation starts once the host runs again. s4's
/// tenure names `Rerun(Withdrawn)` and is torn down, then H2 pauses: the host loop ends with the rerun still queued
/// and none dropped. Once H2 runs again the loop gives the rerun its turn; H2's one tenure slot is taken, so the rerun
/// is counted unslotted.
#[test]
fn a_rerun_queued_for_a_paused_host_waits_for_its_resume() {
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(Vec::new(), fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let at = hosts::DUTY_CELL;
    let mut ended = None;
    let ran = fleet.play_script_with(draws, |fleet, live, slots| {
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        let serving = live[at].as_mut().expect("the boot tenure");
        serving.duty_exit = Some(crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn));
        ended = Some(serving.tenure);
        fleet.turn(live);
        assert!(fleet.reruns.contains_key(&at), "the exit queued a rerun");
        let member = fleet.cells[at].holder;
        fleet.hosts[member].up = hosts::Up::Paused;
        fleet.run_hosts(live, slots)?;
        assert_eq!(fleet.log.rerun_dropped, 0, "the paused host's rerun");
        assert!(fleet.reruns.contains_key(&at), "the rerun waits");
        fleet.hosts[member].up = hosts::Up::Running;
        fleet.run_hosts(live, slots)?;
        assert!(fleet.reruns.is_empty(), "the rerun had its turn");
        Ok(())
    });
    let report = ran.expect("a run inside the limits");
    let ended = ended.expect("the ended tenure");
    assert_eq!(report.duties.torn, [(hosts::DUTY_SHARD, ended, true)]);
    let log = &report.hosts;
    assert_eq!(
        (log.rerun_dropped, log.unslotted),
        (0, 1),
        "{}",
        report.summary()
    );
}

/// Fast witnesses of the untouched-shard rule's exact form, over H0's loss with the report altered: one extra read of
/// s4's shard record through its duties' store fails it by the reads rule, and one rewrite of that record, with the
/// read before it, by the writes rule; the unaltered run passes. The scheduled case runs the live controls ([`untouched_controls_on`]) on
/// root 1.
#[test]
fn untouched_shard_controls_fail_by_one_extra_read_and_one_duty_write() {
    let reads = "an untouched shard's reads were other than one volume-record and one shard-record read a view period";
    let write = "an untouched shard's serving duties wrote its records";
    let report = passing(&Config::host_loss(1));
    let judged = |edit: fn(&mut oracles::Views)| {
        let mut altered = report.clone();
        let shard = hosts::DUTY_CELL as u32 + 1;
        let watched = altered.evidence.watched.iter_mut();
        let watch = watched.into_iter().find(|watch| watch.shard.get() == shard);
        edit(&mut watch.expect("s4's watch").views);
        altered.judged().untouched
    };
    assert_eq!(judged(|_| {}), Verdict::Pass);
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
    assert_eq!(judged(|views| views.shard += 1).rule(), Some(reads));
    // The `DutyRewrite` plant's rewrite reads the record before it writes it, as `Fleet::plant_views` counts both.
    let rewritten = judged(|views| {
        views.shard += 1;
        views.writes += 1;
    });
    assert_eq!(rewritten.rule(), Some(write));
}

/// The live controls of the untouched-shard rule on `root`: one extra read of s4's shard record through its duties'
/// store during H0's loss fails it by the reads rule, and one rewrite of that record by the writes rule; a plant
/// index past the last cell plants nothing, a deposed tenure's slot of the live table included.
pub(super) fn untouched_controls_on(root: u64) {
    let at = hosts::DUTY_CELL as u32;
    let read = hostile(Config::host_loss(root), Plant::ExtraRead, at);
    assert_eq!(
        read.verdicts.untouched.rule(),
        Some(oracles::VIEW_READS),
        "{}",
        read.summary()
    );
    let wrote = hostile(Config::host_loss(root), Plant::DutyRewrite, at);
    assert_eq!(
        wrote.verdicts.untouched.rule(),
        Some(oracles::VIEW_WRITE),
        "{}",
        wrote.summary()
    );
    for plant in [Plant::ExtraRead, Plant::DutyRewrite] {
        let past =
            run(&Config::owner_pause(root).hostile(plant, 6)).expect("a run inside the limits");
        assert!(!past.planted, "{plant:?} past the cells");
    }
}

/// The store-result outcomes fail by their own rules when the report is altered: a duty exit or a second recovery of
/// the faulted tenure, an acknowledgement at the hold's acknowledged page commits, and, over a regressed coverage
/// read, any acknowledgement; a missing fault, a timeout on another write than the cell's, a stale read not served, a
/// missing acknowledgement, counted result, withdrawal or alarm reads its witness `Unrun`. Run live, a coverage write
/// that acknowledges on its unknown reply (`Plant::AckOnUnknown`) fails by the acknowledgement rule.
/// A regression run whose faulted authority serves, or withdrew for a cause other than `Cause::Regression`, leaves
/// the regression-withdrawn witness `Unrun`.
#[test]
fn each_store_result_outcome_fails_by_its_rule_and_a_missing_witness_reads_unrun() {
    use super::hosts::{DutyWrite, Unknown};
    let cell = Unknown {
        write: DutyWrite::Confirm,
        commit: false,
    };
    let unknown = passing(&Config::store_unknown(1, cell));
    let rule = |report: &Report, edit: &dyn Fn(&mut Report)| {
        let mut report = report.clone();
        edit(&mut report);
        hosts::expected(&report)
    };
    let tenure = (unknown.duties.faulted.as_ref())
        .expect("the faulted tenure")
        .tenure;
    let shard = hosts::DUTY_SHARD;
    let rerun =
        "a store result with an unknown outcome ended the tenure's duties or reran its incarnation";
    let exited = rule(&unknown, &|r| {
        (r.duties.exits).push((
            shard,
            tenure,
            crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn),
            (tenure.g, tenure.a),
        ));
    });
    assert_eq!(exited.rule(), Some(rerun));
    let again = rule(&unknown, &|r| {
        r.duties.faulted.as_mut().unwrap().recoveries = 2
    });
    assert_eq!(again.rule(), Some(rerun));
    let early = "a tenure acknowledged an INVALIDATE without a committed coverage write of its own";
    let at_hold = rule(&unknown, &|r| {
        let faulted = r.duties.faulted.as_mut().unwrap();
        faulted.acknowledged_at = Some(faulted.held_at);
    });
    assert_eq!(at_hold.rule(), Some(early));
    let untaken = rule(&unknown, &|r| {
        r.duties.faulted.as_mut().unwrap().taken = false
    });
    assert_eq!(untaken, Verdict::Unrun(hosts::DUTY_FAULT));
    let elsewhere = rule(&unknown, &|r| {
        r.duties.faulted.as_mut().unwrap().timed_out = Some(DutyWrite::Reserve)
    });
    assert_eq!(elsewhere, Verdict::Unrun(hosts::DUTY_FAULT));
    let unacknowledged = rule(&unknown, &|r| {
        r.duties.faulted.as_mut().unwrap().acknowledged_at = None
    });
    assert_eq!(unacknowledged, Verdict::Unrun(hosts::DUTY_ACKNOWLEDGED));
    let uncounted = rule(&unknown, &|r| {
        r.hosts
            .stores
            .retain(|store| store.unknown.is_none_or(|n| n == 0))
    });
    assert_eq!(uncounted, Verdict::Unrun(hosts::UNKNOWN_REPORTED));

    let committed = Unknown {
        write: DutyWrite::Page,
        commit: true,
    };
    let planted = Config::store_unknown(1, committed).hostile(Plant::AckOnUnknown, 0);
    let planted = run(&planted).expect("a run inside the limits");
    assert!(planted.planted, "the planted ack met an unknown reply");
    assert_eq!(hosts::expected(&planted).rule(), Some(early));
    // The plant acts on a coverage write's unknown reply alone: over a timed-out Confirm it changes nothing.
    let idle = run(&Config::store_unknown(1, cell).hostile(Plant::AckOnUnknown, 0));
    let idle = idle.expect("a run inside the limits");
    assert!(!idle.planted, "no coverage write's reply was unknown");
    assert_eq!(hosts::expected(&idle), Verdict::Pass);

    let page = store_killed(&Config::page_regressed(1));
    let acknowledged = rule(&page, &|r| {
        let faulted = r.duties.faulted.as_mut().unwrap();
        faulted.acknowledged_at = Some(faulted.held_at + 1);
    });
    assert_eq!(acknowledged.rule(), Some(early));
    let unwithdrawn = Verdict::Unrun("witness regression-withdrawn missing");
    let stayed = rule(&page, &|r| r.duties.exits.clear());
    assert_eq!(stayed, unwithdrawn);
    let caused = |report: &Report, cause| {
        rule(report, &|r| {
            r.duties.faulted.as_mut().unwrap().withdrawal = cause
        })
    };
    let other = Some(crate::failover::serving::Cause::Unverified);
    for cause in [None, other] {
        assert_eq!(caused(&page, cause), unwithdrawn, "{cause:?}");
    }
    let unserved = |report: &Report| {
        rule(report, &|r| {
            r.duties.faulted.as_mut().unwrap().stale_served = false
        })
    };
    assert_eq!(unserved(&page), Verdict::Unrun(hosts::DUTY_FAULT));
    let record = store_killed(&Config::record_regressed(1));
    assert_eq!(unserved(&record), Verdict::Unrun(hosts::DUTY_FAULT));
    for cause in [None, other] {
        assert_eq!(caused(&record, cause), unwithdrawn, "{cause:?}");
    }
    let quiet = rule(&record, &|r| {
        r.hosts
            .stores
            .retain(|store| store.watermark != crate::failover::report::Watermark::Regression);
    });
    assert_eq!(
        quiet,
        Verdict::Unrun("witness regression-alarm-reported missing")
    );
    // The regression's rerun: with the same host's next incarnation removed from the record of
    // recoveries, or its teardown kept, the rerun witness reads missing; a torn-down owner that kept its custody, or a
    // rerun that found no free slot, fails by name.
    assert_eq!(hosts::REGRESSION_RERAN, "witness regression-rerun missing");
    assert_eq!(
        hosts::TORN_KEPT,
        "a torn-down owner kept its custody past the teardown's patience"
    );
    assert_eq!(
        hosts::UNSLOTTED,
        "a rerun found no free tenure slot on its host"
    );
    let faulted = page.duties.faulted.as_ref().unwrap().tenure;
    let unrerun = rule(&page, &|r| {
        let recoveries = &mut r.shards[hosts::DUTY_CELL].recoveries;
        recoveries.retain(|recovery| recovery.tenure.a != faulted.a + 2);
    });
    assert_eq!(unrerun, Verdict::Unrun(hosts::REGRESSION_RERAN));
    let untorn = rule(&record, &|r| r.duties.torn.clear());
    assert_eq!(untorn, Verdict::Unrun(hosts::REGRESSION_RERAN));
    let kept = rule(&page, &|r| {
        for torn in &mut r.duties.torn {
            torn.2 = false;
        }
    });
    assert_eq!(kept.rule(), Some(hosts::TORN_KEPT));
    let unslotted = rule(&page, &|r| r.hosts.unslotted = 1);
    assert_eq!(unslotted.rule(), Some(hosts::UNSLOTTED));
    // Run live with each teardown read as one whose owner kept its custody (`Fleet::kept_owner`), the run queues no
    // rerun for the withdrawn tenure, and the scenario's outcome fails TORN_KEPT.
    let config = Config::page_regressed(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.kept_owner = true;
    fleet.alarms.scripted = true;
    let _agent = super::AgentPlant::set(&config);
    let _inline = Inline::set();
    let kept = fleet.play_script(draws).expect("a run that ends");
    assert_eq!(
        hosts::expected(&kept).rule(),
        Some(hosts::TORN_KEPT),
        "{}",
        kept.summary()
    );
    let recoveries = &kept.shards[hosts::DUTY_CELL].recoveries;
    assert!(
        recoveries
            .iter()
            .all(|recovery| recovery.tenure.a != faulted.a + 2),
        "{recoveries:?}"
    );
}

/// A tenure's serving duties that end at an exit its scenario does not script fail the run's credit by name, in a host
/// run and in a restart run, whatever the tenure's authority reads; the scripted exits pass: a superseded tenure's,
/// and the regression scenario's withdrawal of its faulted tenure. A tenure whose duties named an exit is not served.
#[test]
fn an_unscripted_duty_exit_fails_the_credit_by_name() {
    let unscripted = "a tenure's serving duties ended at an exit its scenario does not script";
    assert_eq!(hosts::DUTY_EXIT, unscripted);
    let unwound = crate::host::Exit::Rerun(crate::host::Rerun::Unwound);
    let exited = |report: &Report, at: u32| {
        let mut report = report.clone();
        let (_, history) = &report.evidence.histories[at as usize - 1];
        let last = history.last().expect("a shard record");
        let tenure = Tenure {
            g: last.generation.get(),
            a: u64::from(last.attempts) * 2,
        };
        report
            .duties
            .exits
            .push((at, tenure, unwound.clone(), (tenure.g, tenure.a)));
        report.credit()
    };
    let host_loss = passing(&Config::host_loss(1));
    assert_eq!(exited(&host_loss, 5).rule(), Some(hosts::DUTY_EXIT));
    let restarts = super::tests::passing(&Config::six(1));
    assert_eq!(exited(&restarts, 2).rule(), Some(hosts::DUTY_EXIT));
    let mut superseded = host_loss.clone();
    let earlier = Tenure { g: 1, a: 0 };
    let later = (3, 12);
    superseded
        .duties
        .exits
        .push((1, earlier, unwound.clone(), later));
    assert_eq!(
        superseded.credit().rule(),
        Some(hosts::DUTY_EXIT),
        "a superseded tenure's unwind"
    );
    let mut deposed = host_loss.clone();
    deposed
        .duties
        .exits
        .push((1, earlier, crate::host::Exit::Deposed, later));
    assert_eq!(
        deposed.credit(),
        Verdict::Pass,
        "a superseded tenure's deposition"
    );
    // A recorded-holder exit while the record still named the tenure itself, followed by the same host's rerun bump
    // (the shard's last record names a later tenure), is no deposition: it fails by name.
    let mut reran = host_loss.clone();
    let holder = crate::host::Exit::Rerun(crate::host::Rerun::RecordedHolder);
    reran
        .duties
        .exits
        .push((1, earlier, holder, (earlier.g, earlier.a)));
    assert_eq!(
        reran.credit().rule(),
        Some(hosts::DUTY_EXIT),
        "an exit its own rerun superseded"
    );
    let page = store_killed(&Config::page_regressed(1));
    assert_eq!(hosts::unscripted_exit(&page), None);
    let mut other = page.clone();
    let faulted = other.duties.faulted.as_ref().unwrap().tenure;
    let withdrawn = crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn);
    other
        .duties
        .exits
        .push((6, faulted, withdrawn, (faulted.g, faulted.a)));
    assert_eq!(
        hosts::unscripted_exit(&other).and_then(|v| v.rule()),
        Some(hosts::DUTY_EXIT),
        "another shard's boot tenure at the same (g, a)"
    );
}

/// Inside a store outage of a tenure's holder host, its serving duties' requests reach no store and take no arm of the
/// duty actor; another host's outage leaves them reaching the store, and after the window the queued arm is taken.
#[test]
fn a_holder_hosts_store_outage_stops_its_tenures_duties_and_no_other_hosts() {
    use crate::storage::store::sim::{ActorFaults, Faulted, Shared};
    use crate::storage::store::{Key, Outcome, Store, Write};
    let faults = std::rc::Rc::new(std::cell::RefCell::new(ActorFaults::default()));
    let store = Shared::new();
    let duties = |holder: u32| HostOut {
        holder: Some(holder),
        faults: faults.clone(),
        inner: Faulted {
            inner: store.clone(),
            actor: duty_actor(hosts::DUTY_CELL),
            faults: faults.clone(),
        },
    };
    let key = Key::Shard(crate::net::ownership::Shard::new(5).expect("a shard"));
    let create = Write::Create(vec![1]);
    faults.borrow_mut().outage(Some(2), 0, 10);
    faults.borrow_mut().set_now(5);
    (faults.borrow_mut()).arm_write(duty_actor(hosts::DUTY_CELL), Arm::Timeout { commit: false });
    let mut held = duties(2);
    assert_eq!(held.read(&key), Err(crate::storage::store::Unavailable));
    assert_eq!(held.write(&key, &create), Outcome::Unknown);
    assert_eq!(
        store.0.borrow().requests(&key),
        0,
        "no request reached the store"
    );
    assert_eq!(faults.borrow().queued(duty_actor(hosts::DUTY_CELL)), 1);
    assert_eq!(
        duties(3).read(&key),
        Ok(None),
        "another host's duties reach the store"
    );
    faults.borrow_mut().set_now(10);
    assert_eq!(
        held.write(&key, &create),
        Outcome::Unknown,
        "the queued timeout"
    );
    assert_eq!(faults.borrow().queued(duty_actor(hosts::DUTY_CELL)), 0);
    let none = HostOut {
        holder: None,
        ..duties(2)
    };
    faults.borrow_mut().set_now(5);
    let mut none = none;
    assert_eq!(
        none.write(&key, &create),
        Outcome::Committed(crate::storage::store::Version::FIRST)
    );
}

/// A witness consumed after it lapsed starts nothing: on the host-loss scenario the standby's period reads the run's
/// first witness out of its inbox and stalls two rounds before it reads its clock (`Fleet::witness_hold`), as a
/// production period can between `Inbox::nomination` and `Takeover::nominated`, so the period judges the witness on
/// its own host's clock past `until_us`. The witness has left the inbox, so the agent's resends queue behind it and
/// replace nothing. The period issues no device command and no write of the shard record (`lapsed` one,
/// `lapsed-acted` zero), and the agent's next witness for the same target takes the shard over, so the takeovers
/// match the unheld run's. Control: the same stall with the period reading the witness at its send time takes the
/// shard over on the stale witness and fails `LAPSED_ACTED` by name.
#[test]
fn a_witness_consumed_after_it_lapsed_starts_no_takeover_and_a_send_time_clock_fails_by_name() {
    let played = |sent: bool| {
        let config = Config::host_loss(1);
        let mut draws = Draws::record(config.root);
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        fleet.witness_hold = Some((2, sent));
        fleet.alarms.scripted = true;
        let _agent = super::AgentPlant::set(&config);
        let _inline = Inline::set();
        fleet.play_script(draws).expect("a run that ends")
    };
    let held = played(false);
    assert_eq!(held.credit(), Verdict::Pass, "{}", held.lines().join("\n"));
    assert_eq!((held.hosts.lapsed, held.hosts.lapsed_acted), (1, 0));
    assert_eq!(taken(&held), [(1, H3), (2, H3), (3, H5)]);
    let rule = "a standby's period acted on a witness that had lapsed when the period took it";
    assert_eq!(rule, hosts::LAPSED_ACTED);
    let stale = played(true);
    assert_eq!(stale.hosts.lapsed_acted, 1, "{}", stale.summary());
    assert_eq!(hosts::expected(&stale).rule(), Some(rule));
}

/// A lost host that returns as owner after unknown takeover replies that did not commit restarts over slots of its
/// own: H0 crashes and its crash heals five rounds later, and H3's takeovers of s0 and s1 each time out at their
/// compare-and-swap with a write that did not commit (`Rerun::Takeover`). The records still name H0 owner of both when
/// H0 returns, so H0 restarts s0 and s1 and serves each warm at its next attempt, and H5 takes s2 over. The run plans
/// one return slot per role of the crashed host (`Fleet::return_slots`), since a slot that H0's dropped tenure held
/// keeps that tenure's storage state. H0's return also reads every shard record of its zone, record views that the
/// untouched-shard check counts apart (`Fleet::viewed`), so s3, whose tenure served through the loss, stays
/// untouched.
#[test]
fn a_lost_host_that_returns_as_owner_after_an_uncommitted_takeover_restarts_on_a_slot_of_its_own() {
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].heal = Some(5);
    let unknown = Episode {
        scope: vec![3],
        action: Action::StoreWrite(Arm::Timeout { commit: false }),
        heal: None,
        ..script[0].clone()
    };
    script.extend([unknown.clone(), unknown]);
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(script, fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _agent = super::AgentPlant::set(&config);
    let _inline = Inline::set();
    let report = fleet.play_script(draws).expect("a run that ends");
    let attempts: Vec<_> = (report.hosts.takeovers.iter())
        .map(|attempt| (attempt.shard, attempt.host, attempt.refused.as_deref()))
        .collect();
    assert_eq!(
        attempts[..2],
        [(1, H3, Some("TakeOver")), (2, H3, Some("TakeOver"))],
        "{attempts:?}"
    );
    assert_eq!(taken(&report), [(3, H5)]);
    for at in [0, 1] {
        let restarted = report.shards[at]
            .recoveries
            .last()
            .expect("the returning owner's restart");
        assert_eq!(
            (restarted.host.get(), restarted.tenure.a),
            (H0, 12),
            "s{at}"
        );
        assert!(
            restarted
                .sweep
                .is_some_and(|(of, served)| of > 0 && of == served),
            "s{at}"
        );
    }
    let verdicts = &report.verdicts;
    assert_eq!(
        (&verdicts.one_owner, &verdicts.untouched),
        (&Verdict::Pass, &Verdict::Pass),
        "{}",
        report.summary()
    );
}

/// A takeover whose compare-and-swap reply is unknown is taken again: H0 is lost, and H5's takeover of s2 times
/// out at its compare-and-swap with a write that did not commit. The takeover ends `Rerun::Takeover`, the next
/// incarnation reads H0's record and waits as s2's standby, and the agent, which keeps the nomination while the
/// records name its target, sends its next witness within a window; H5's second takeover then commits and serves.
/// The host loop runs on while the standby waits on its retake, so the run cannot end with s2 unserved while the
/// agent still nominates its target. The scheduled case runs the committed sibling, whose next incarnation reads H5
/// named owner and serves through the restart's lineage arm, which the run records (`VolumeLog::arm`).
#[test]
fn a_takeover_whose_swap_reply_is_unknown_is_taken_again_on_the_next_witness_or_restarted() {
    a_takeover_whose_swap_reply_is_unknown_recovers_on(false);
}

/// The checks of the test above with a swap that committed (`commit`) or did not.
pub(super) fn a_takeover_whose_swap_reply_is_unknown_recovers_on(commit: bool) {
    let mut script = Scenario::HostLoss.episodes(false);
    script.push(Episode {
        scope: vec![5],
        action: Action::StoreWrite(Arm::Timeout { commit }),
        heal: None,
        ..script[0].clone()
    });
    let report = scripted(&Config::host_loss(1), script);
    assert_eq!(
        taken(&report),
        [(1, H3), (2, H3), (3, H5)],
        "commit {commit}"
    );
    let s2: Vec<_> = (report.hosts.takeovers.iter())
        .filter(|attempt| attempt.shard == 3)
        .map(|attempt| attempt.refused.as_deref())
        .collect();
    let expected: &[Option<&str>] = match commit {
        false => &[Some("TakeOver"), None],
        true => &[None],
    };
    assert_eq!(s2, expected, "commit {commit}");
    // The period whose swap reply was unknown issued no device command.
    let unknown = (report.hosts.takeovers.iter()).find(|attempt| attempt.shard == 3);
    let commands = unknown.map(|attempt| attempt.commands.clone());
    assert_eq!(commands, Some(Vec::new()), "commit {commit}");
    // The swap's write is told apart by the record: H5's owner change, and after a committed swap the next
    // incarnation's own bump one attempt above it, which a clean takeover makes no.
    let h5 = crate::failover::records::Host::new(H5).unwrap();
    let mut held: Vec<u32> = (report.evidence.histories[2].1.iter())
        .filter(|record| record.owner == h5)
        .map(|record| record.attempts)
        .collect();
    held.dedup();
    let taken = held.first().copied().expect("H5's owner change");
    let expected = match commit {
        true => vec![taken, taken + 1],
        false => vec![taken],
    };
    assert_eq!(held, expected, "commit {commit}");
    // After a committed swap the next incarnation serves through the restart's lineage arm; a second takeover
    // serves through none.
    let arms: Vec<(u32, u64)> = (report.volumes.arm.iter())
        .map(|&(shard, host, _)| (shard, host))
        .collect();
    let expected = match commit {
        true => vec![(3, H5)],
        false => Vec::new(),
    };
    assert_eq!(arms, expected, "commit {commit}");
    assert_eq!(
        report.credit(),
        Verdict::Pass,
        "commit {commit}: {}",
        report.summary()
    );
}

/// The retake stays pending while the isolated owner's own tenure still fills the cell. H0 is isolated with no heal,
/// so its tenure of s2 stays live and unreachable, and H5's takeover of s2 times out at its compare-and-swap with a
/// write that did not commit. H5's next incarnation waits on its retake under H0's tenure, the host loop runs on,
/// and the agent's next witness starts the takeover that commits and serves.
#[test]
fn a_retake_under_an_isolated_owners_tenure_keeps_the_run_open_for_the_next_witness() {
    let mut script = Scenario::OwnerIsolation.episodes(false);
    script[0].heal = None;
    script.push(Episode {
        scope: vec![5],
        action: Action::StoreWrite(Arm::Timeout { commit: false }),
        heal: None,
        ..script[0].clone()
    });
    let report = scripted(&Config::owner_isolation(1), script);
    let s2: Vec<_> = (report.hosts.takeovers.iter())
        .filter(|attempt| attempt.shard == 3)
        .map(|attempt| attempt.refused.as_deref())
        .collect();
    assert_eq!(s2, [Some("TakeOver"), None], "{}", report.summary());
    assert_eq!(taken(&report), [(1, H3), (2, H3), (3, H5)]);
    assert_eq!(report.credit(), Verdict::Pass, "{}", report.summary());
}

/// A fresh activation whose Confirm reply is unknown ends `Rerun(Unactivated)` after its bump committed, and the
/// next incarnation reads the record at `E = 1`. s3's volume is lost alone, H0 takes the shard over, and the
/// reconciler replaces the volume and flips. H0's fresh activation commits its enrollment write and its bump, and
/// its Confirm times out. The activation stays due: the next incarnation takes the restart role over the
/// replacement, bumps to `E = 2` and serves the shard cold, the shard keeps the `Confirm` blocker of the incarnation
/// that ended, and the lone loss earns its credit.
#[test]
fn a_fresh_activation_whose_confirm_reply_is_unknown_after_its_bump_runs_again_and_serves_cold() {
    let mut script = Scenario::LostAlone.episodes(false);
    // The activation's writes are H0's next three: the enrollment, the bump and the Confirm.
    let writes = [Arm::Pass, Arm::Pass, Arm::Timeout { commit: false }];
    script.extend(writes.map(|arm| Episode {
        trigger: Trigger::When(|fleet| fleet.fresh_due().is_some()),
        scope: vec![0],
        action: Action::StoreWrite(arm),
        heal: None,
    }));
    let report = scripted(&Config::lost_alone(1), script);
    let s3 = &report.shards[hosts::FAULTED];
    assert_eq!(s3.blockers.last().map(String::as_str), Some("Confirm"));
    let shard = hosts::FAULTED as u32 + 1;
    let volumes = &report.volumes;
    assert_eq!(
        (&volumes.cold, &volumes.fresh_refused),
        (&vec![shard], &vec![])
    );
    let last = *report.evidence.histories[hosts::FAULTED].1.last().unwrap();
    assert_eq!((last.owner.get(), last.attempts), (H0, 2));
    let cold = s3.recoveries.last().expect("the replacement's recovery");
    assert_eq!((cold.host, cold.sweep), (last.owner, Some((0, 0))));
    assert_eq!(report.credit(), Verdict::Pass, "{}", report.summary());
}

/// H3, the owner of s3 alone, crashes and returns two rounds later, before a suspicion, under an outage of its own
/// store requests that heals 20 rounds after the crash.
fn return_under_an_outage() -> Vec<Episode> {
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].scope = vec![3];
    script[0].heal = Some(2);
    script.push(Episode {
        scope: vec![3],
        action: Action::Outage,
        heal: Some(20),
        ..script[0].clone()
    });
    script
}

/// A restart whose incarnation ends with an exit that names a rerun runs again: H3, the owner of s3 alone, crashes
/// and returns two rounds later, before a suspicion, under a store outage of its own requests. Each restart's role
/// read fails, which ends the incarnation `Rerun::Records`, and the host loop runs the next incarnation from the
/// round after, as the process's supervisor starts it. Once the outage heals, the next incarnation restarts s3 warm
/// on H3, and no takeover starts. That incarnation completes H3's return as a restart that served at once does: the
/// zone log records the restart at its tenure, and the tenure acknowledges its FILL and its INVALIDATE.
#[test]
fn a_restart_that_ends_in_a_rerun_exit_runs_again_and_serves_after_the_outage() {
    let report = scripted(&Config::host_loss(1), return_under_an_outage());
    assert_eq!(report.verdicts.one_owner, Verdict::Pass);
    assert!(
        report.hosts.takeovers.is_empty(),
        "{:?}",
        report.hosts.takeovers
    );
    let reruns = report.hosts.refused_reruns;
    assert!(reruns >= 10, "one rerun a round over the outage: {reruns}");
    let s3 = &report.shards[3];
    let last = s3.recoveries.last().expect("a recovery");
    assert_eq!((s3.recoveries.len(), last.host.get()), (2, H3));
    assert!(last.after_crash);
    let returned: Vec<_> = (report.zones.restarts.iter())
        .map(|&(shard, host, tenure, _)| (shard, host, tenure))
        .collect();
    assert_eq!(returned, [(4, H3, last.tenure)]);
    assert_eq!(report.zones.acknowledged, 1);
    assert!(
        last.sweep
            .is_some_and(|(of, served)| of > 0 && of == served),
        "s3 restarts warm: {:?}",
        last.sweep
    );
    assert!(
        s3.blockers.iter().all(|check| check == "Unavailable") && !s3.blockers.is_empty(),
        "{:?}",
        s3.blockers
    );
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
}

/// A restart whose own record read fails ends with the production rerun exit and runs again: H3, the owner of s3
/// alone, crashes and returns two rounds later. Its requests take queued arms: the six record views of its boot and both reads of its restart's role read pass, and the restart's own first read of the
/// shard record inside `host::recover` is unavailable. `host::recover` ends the incarnation `Rerun::Records`, whose
/// blocker names the check (`Records`, not the role read's `Unavailable`), no held entry appears, the host loop counts
/// one refused rerun, and the next incarnation restarts s3 warm on H3 with no takeover.
#[test]
fn a_restart_whose_own_record_read_fails_reruns_through_its_production_exit_and_serves() {
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].scope = vec![3];
    script[0].heal = Some(2);
    let down =
        |fleet: &Fleet<'_>| (fleet.hosts.get(3)).is_some_and(|host| host.up == hosts::Up::Down);
    let passes = 6 + 2;
    for n in 0..=passes {
        let arm = if n == passes {
            Arm::Unavailable
        } else {
            Arm::Pass
        };
        script.push(Episode {
            trigger: Trigger::When(down),
            scope: vec![3],
            action: Action::Store(arm),
            heal: None,
        });
    }
    let report = scripted(&Config::host_loss(1), script);
    assert!(
        report.hosts.takeovers.is_empty(),
        "{:?}",
        report.hosts.takeovers
    );
    assert_eq!(report.hosts.refused_reruns, 1);
    assert!(report.hosts.held.is_empty(), "{:?}", report.hosts.held);
    let s3 = &report.shards[3];
    assert_eq!(s3.blockers, ["Records"]);
    let hosts: Vec<(u64, u64)> = (s3.recoveries.iter())
        .map(|r| (r.host.get(), r.tenure.a))
        .collect();
    assert_eq!(hosts, [(H3, 10), (H3, 12)]);
    let last = s3.recoveries.last().expect("the rerun's recovery");
    assert!(
        last.sweep
            .is_some_and(|(of, served)| of > 0 && of == served),
        "{:?}",
        last.sweep
    );
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
}

/// A crash that drops a bring-up in progress counts no withdrawal: on the host-loss scenario H3 crashes, and returns
/// five rounds later, while its takeover loads of s0 and s1 are rising. Its dropped tenures had not served, so the
/// settle verdict reads its host scenario's `Unrun` and not the withdrawn rule, and the run ends with s0, s1 and s2
/// taken over.
#[test]
fn a_crash_that_drops_a_rising_tenure_counts_no_withdrawal() {
    fn rising_on_h3(fleet: &Fleet<'_>) -> bool {
        (fleet.rises.iter()).any(|rise| fleet.cells[rise.at].holder == 3)
    }
    let mut script = Scenario::HostLoss.episodes(false);
    script.push(Episode {
        trigger: Trigger::When(rising_on_h3),
        scope: vec![3],
        action: Action::Crash,
        heal: Some(5),
    });
    let report = scripted(&Config::host_loss(1), script);
    assert_eq!(report.hosts.fired.len(), 2);
    assert!(
        report.hosts.fired.iter().all(Option::is_some),
        "{:?}",
        report.hosts.fired
    );
    let withdrawn = "a tenure that no fault deposed stopped serving";
    assert_ne!(
        report.verdicts.settles.rule(),
        Some(withdrawn),
        "{}",
        report.summary()
    );
    assert_eq!(
        report.verdicts.settles,
        Verdict::Unrun(oracles::NO_RECONCILER)
    );
    assert_eq!(taken(&report), [(1, H3), (2, H3), (3, H5)]);
}

/// The flat-progress gray owner: under plant `FlatProgress` (code 56) every tenure of H0 publishes flat device and
/// completion counters with one command pending while H0 stays healthy and no fault runs. Every other host's detector
/// reads H0 `Dead` with a gray failure, which needs a second observer class, and the fleet's probers all vote in one
/// class, so the arbiter declines with `GrayNeedsSecondClass`: no detector publishes a nomination, no takeover starts,
/// and H0 keeps its three shards. No credit is claimed for gray recovery. Sibling: H0's crash in the host-loss case
/// nominates and takes the three shards over on the same layout.
#[test]
fn a_flat_progress_owner_reads_gray_and_no_detector_nominates_it() {
    let config = Config::host_loss(1).hostile(Plant::FlatProgress, 0);
    let report = scripted(&config, Vec::new());
    assert!(report.planted);
    let log = &report.hosts;
    assert!(log.gray_readings > 0, "{}", report.summary());
    // Each of the five other hosts reads H0 gray, and no observer reads another peer gray.
    let observers: Vec<u64> = (1002..=1006).collect();
    let gray: Vec<(u64, u64)> = observers.iter().map(|&observer| (observer, 1001)).collect();
    assert_eq!(log.gray.iter().copied().collect::<Vec<_>>(), gray);
    assert_eq!((log.nominations, log.addressed), (0, 0));
    assert!(log.takeovers.is_empty());
    assert!(log.exempt.is_empty(), "H0 stays healthy");
    for at in 0..3 {
        let recoveries = &report.shards[at].recoveries;
        assert_eq!(recoveries.len(), 1, "s{at} keeps its boot tenure");
        assert_eq!(recoveries[0].host.get(), 1001);
    }
}

/// The flat-progress plant changes a run only through a tenure status it publishes with frozen counters. H1 owns no
/// shard on the small layout, so the plant aimed at H1 publishes none: the run reads unplanted, no observer reads a
/// peer gray, and the run earns no credit.
#[test]
fn a_flat_progress_plant_on_a_host_with_no_tenure_changes_nothing() {
    let placing = super::topology::Placing::SMALL;
    assert!(placing.iter().all(|&(owner, _)| owner != 1));
    let config = Config::host_loss(1).hostile(Plant::FlatProgress, 1);
    let report = scripted(&config, Vec::new());
    assert!(!report.planted);
    assert!(report.hosts.gray.is_empty(), "{:?}", report.hosts.gray);
    assert!(matches!(report.credit(), Verdict::Unrun(_)));
}

/// H3's takeovers of s0 and s1 in a host-loss run, each the last recovery of its shard.
fn h3_takeovers(report: &Report) -> [Recovered; 2] {
    assert_eq!(taken(report), [(1, H3), (2, H3), (3, H5)]);
    [0, 1].map(|at| {
        let recovery = *report.shards[at].recoveries.last().unwrap();
        assert_eq!(recovery.host.get(), H3, "s{at}");
        assert_eq!(recovery.share.owners, 3, "s{at}");
        recovery
    })
}

/// `Shape::share_bytes` sets each host's share per interval: 32 KiB with `Config::limited`. H3 splits its 32 KiB
/// share among three roles, giving each owner a budget of 10,922 bytes per share interval. Under that budget each
/// of H3's takeovers of s0 and s1 reports a share window in which its limiter refused a charge, so the limiter check
/// passes for both. Both takeovers serve their full sweeps. Roots 1 and 2 give the same result. H3's two loads
/// overlap: the second bring-up starts while the first is in progress (`overlapped`), and the round loop steps both
/// in the same rounds. Each owner's limiter drains its own part of the host's share, so each load meets its own
/// refused charges.
#[test]
fn a_recovery_load_above_its_part_of_a_small_host_share_meets_a_refused_charge_and_still_loads_warm()
 {
    for root in [1, 2] {
        let limited = passing(&Config::limited(root));
        assert!(limited.hosts.overlapped >= 1, "{}", limited.summary());
        let loads = h3_takeovers(&limited);
        for (at, recovery) in loads.iter().enumerate() {
            assert_eq!(recovery.share.bytes, 32_768, "root {root} s{at}");
            assert!(
                recovery
                    .sweep
                    .is_some_and(|(of, served)| of > 0 && of == served),
                "root {root} s{at}: {recovery:?}"
            );
        }
        let met = oracles::meets_limiter(&loads);
        assert_eq!(met, Verdict::Pass, "root {root}");
        let within = &limited.verdicts.within_share;
        assert_eq!(within, &Verdict::Pass, "root {root}");
    }
}

/// The limiter's control: under plant `IgnoredShare` (code 95) storage's limiter admits every charge, so H3's
/// two overlapping takeover loads of the limited shape meet no share window whose limiter refused a charge, where
/// the unplanted run's both do, and the limiter check fails by its rule. The host-share check, which sums loads
/// against twice the share, still passes, and the hostile run earns no credit.
#[test]
fn a_limiter_that_admits_every_charge_meets_no_refused_window_on_the_limited_shape() {
    let unrefused = "a recovery load met no share window whose limiter refused a charge";
    let report =
        run(&Config::limited(1).hostile(Plant::IgnoredShare, 3)).expect("a run inside the limits");
    assert!(report.planted);
    assert!(report.hosts.overlapped >= 1, "{}", report.summary());
    let loads = h3_takeovers(&report);
    for (at, recovery) in loads.iter().enumerate() {
        assert_eq!(recovery.share.bytes, 32_768, "s{at}");
        assert_eq!(
            recovery.saturated, 0,
            "s{at} met a refused window under the bypass: {recovery:?}"
        );
    }
    let at_host = format!("host {H3} share 32768 over 3");
    assert_eq!(
        oracles::meets_limiter(&loads),
        Verdict::Fail(unrefused, at_host)
    );
    assert_eq!(report.verdicts.within_share, Verdict::Pass);
    assert_eq!(report.credit(), Verdict::Unrun(super::HOSTILE));
}

/// Under `Config::host_loss`'s 4 MiB share the limiter admits every charge of the same two takeovers, so each
/// reports zero windows with a refused charge and fails the limiter check by its rule, on roots 1 and 2. The check
/// is unrun over no load.
#[test]
fn host_loss_under_the_4_mib_share_fails_the_limiter_check_with_no_refused_charge() {
    let unrefused = "a recovery load met no share window whose limiter refused a charge";
    for root in [1, 2] {
        let unlimited = passing(&Config::host_loss(root));
        for (at, free) in h3_takeovers(&unlimited).iter().enumerate() {
            assert_eq!(free.share.bytes, SHARE_BYTES, "root {root} s{at}");
            assert_eq!(free.saturated, 0, "root {root} s{at}: {free:?}");
            let failed = oracles::meets_limiter(std::slice::from_ref(free));
            let at_host = format!("host {H3} share {SHARE_BYTES} over 3");
            let rule = Verdict::Fail(unrefused, at_host);
            assert_eq!(failed, rule, "root {root} s{at}");
        }
    }
    let unrun = Verdict::Unrun("no recovery load was judged against its limiter");
    assert_eq!(oracles::meets_limiter(&[]), unrun);
}

/// NAMED-STANDBY: a kept nomination is sent again each window until its target leaves the records.
/// Under plant `EmitOnce` (code 57) the agents send each nomination once, at its publication: after H5's takeover of
/// s2 times out at its compare-and-swap with a write that did not commit, H5 waits as s2's standby again and no agent
/// addresses it a second witness. The run stops at the host loop's horizon, and the stall names s2 and the resend
/// rule: the record still names the target of the standby's one witness, and no witness followed in the windows
/// since its wait began. Without the plant the same script and horizon serve s2 on the second witness; the scheduled
/// case runs that sibling (`emit_once_played(.., false)`).
#[test]
fn an_agent_that_sends_a_nomination_once_strands_a_retaken_shard_and_stalls_the_run() {
    let (stalled, dropped) = emit_once_played(1, true);
    assert!(dropped, "the mutant dropped a kept nomination");
    let Err(Stopped::Stalled(stall)) = stalled.map(|report| report.summary()) else {
        panic!("the run settles without a second witness");
    };
    let rule = "a kept nomination was not sent again while its target stayed in the records";
    assert_eq!(rule, hosts::RESEND);
    assert_eq!((stall.waited, stall.shard), (rule, Some(3)));
}

/// The `EmitOnce` control's script on `root` under a horizon of 600 rounds: the host loss with H5's takeover of s2
/// timed out at its compare-and-swap with a write that did not commit, under plant `EmitOnce` when `planted`.
/// Returns how the run ended and whether the agent's plant dropped a kept nomination.
fn emit_once_played(root: u64, planted: bool) -> (Result<Report, Stopped>, bool) {
    let mut script = Scenario::HostLoss.episodes(false);
    script.push(Episode {
        scope: vec![5],
        action: Action::StoreWrite(Arm::Timeout { commit: false }),
        heal: None,
        ..script[0].clone()
    });
    // Both runs stop at 600 rounds; the unplanted one takes s2 again within a few windows of the timeout.
    let config = match planted {
        true => Config::host_loss(root).hostile(Plant::EmitOnce, 0),
        false => Config::host_loss(root),
    };
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(script, fleet.topology.members.len());
    fleet.alarms.scripted = true;
    fleet.horizon = 600;
    let _agent = super::AgentPlant::set(&config);
    let _inline = Inline::set();
    let ended = fleet.play_script(draws);
    (ended, super::AgentPlant::fired(&config))
}

/// The `EmitOnce` control's unplanted sibling: the agents re-send the kept nomination, so H5 takes s2 again within
/// the 600 rounds.
pub(super) fn an_agent_that_resends_a_kept_nomination_takes_the_retaken_shard_within_the_horizon_on(
    root: u64,
) {
    let (resent, _) = emit_once_played(root, false);
    let resent = resent.expect("the unplanted run settles within 600 rounds");
    assert_eq!(taken(&resent), [(1, H3), (2, H3), (3, H5)]);
}

/// The resend rule's reading of the witnesses the agents addressed: it names a cell whose standby has waited, with
/// the record naming a target it was addressed a witness for, for more than `RESEND_WINDOWS` rounds since the later
/// of the last such witness and the start of its wait. A standby that never got a witness, a witness for another
/// shard of the same host, a wait or a witness inside the window, and a record whose present target no witness
/// named each leave the cell unnamed, so a horizon stall keeps the settle's name. A later witness for a target
/// that left the record keeps the round of the present target's last witness.
#[test]
fn the_resend_rule_names_a_waiting_standby_whose_last_witness_and_wait_are_older_than_the_window() {
    use crate::failover::records::{Record, ShardRecord};
    use crate::storage::store::{Key, Outcome, Store, Write};
    let window = hosts::RESEND_WINDOWS;
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let mut fleet = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    fleet.start_hosts();
    let at = 2;
    let member = fleet.cells[at].placement.standby;
    let shard = fleet.cells[at].placement.shard.get();
    let target = crate::failover::retire::Target::of(&fleet.record_now(at));
    let stale = crate::failover::retire::Target {
        attempts: target.attempts - 1,
        ..target
    };
    let read = |fleet: &mut Fleet<'_>, round: u64| {
        fleet.round = round;
        fleet.unsent()
    };
    // An agent's witness for `target` to the standby's process of `shard`, addressed in `round`.
    let witness = |fleet: &mut Fleet<'_>, shard: u32, target, round: u64| {
        fleet.round = round;
        fleet.witness(member, shard, target);
    };
    assert_eq!(read(&mut fleet, 500), None, "no standby waits again");
    fleet.round = 100;
    fleet.retake(at, member);
    assert_eq!(
        read(&mut fleet, 500),
        None,
        "no witness reached the standby"
    );
    witness(&mut fleet, shard + 1, target, 4);
    assert_eq!(read(&mut fleet, 500), None, "a witness for another shard");
    witness(&mut fleet, shard, stale, 4);
    assert_eq!(
        read(&mut fleet, 500),
        None,
        "a witness for a target the record does not name"
    );

    // A witness before the wait, which a takeover consumed or let lapse: the wait's start is the floor.
    witness(&mut fleet, shard, target, 4);
    assert_eq!(read(&mut fleet, 100 + window), None);
    assert_eq!(read(&mut fleet, 101 + window), Some(at));
    // A witness after the wait began that started no takeover, or whose takeover left the wait going on. A later
    // witness for the stale target keeps its round.
    witness(&mut fleet, shard, target, 106);
    witness(&mut fleet, shard, stale, 108);
    assert_eq!(read(&mut fleet, 106 + window), None);
    assert_eq!(read(&mut fleet, 107 + window), Some(at));
    // An agent that resends while every takeover fails: the last witness is one or two rounds old.
    witness(&mut fleet, shard, target, 298);
    assert_eq!(read(&mut fleet, 300), None);
    // A second wait after a second failed takeover is measured from its own start.
    fleet.round = 300;
    fleet.retake(at, member);
    assert_eq!(read(&mut fleet, 300 + window), None);
    assert_eq!(read(&mut fleet, 301 + window), Some(at));

    // The owner bumps its attempt: the record names the same owner and standby under a new target, which no
    // witness names.
    let key = Key::Shard(fleet.cells[at].placement.shard);
    let item = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored shard record");
    let mut record = ShardRecord::decode(&item.value).expect("a shard record");
    record.attempts += 1;
    let write = Write::Exact {
        expect: item.version,
        value: record.encode(),
    };
    let outcome = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
    assert_eq!(fleet.retakes.get(&at), Some(&member));
    assert_eq!(
        read(&mut fleet, 900),
        None,
        "witnesses for targets that left the record"
    );
}

/// The host health rule: a host reads unhealthy only for a held or silent process whose shard names a
/// standby elsewhere. On the stall scenario H0's takeover of s3 holds at its device step while s3's record names no
/// standby, so H0 stays healthy and its own shards s0, s1 and s2 keep their tenures. Under plant `UnhealthyOnAnyHold`
/// (code 58) the hold of a shard with no standby makes H0 unhealthy too, its agent's peers nominate H0's shards, and
/// they change hands although their volumes are healthy.
#[test]
fn a_health_rule_that_reads_any_hold_unhealthy_moves_shards_whose_volumes_are_healthy() {
    let moved = |report: &Report, at: usize| {
        let versions = &report.evidence.histories[at].1;
        versions
            .windows(2)
            .filter(|pair| pair[0].owner != pair[1].owner)
            .count()
    };
    // The stall test checks the rule's side: s3 alone is exempt and every other shard keeps serving.
    let mutant = run(&Config::stall(1).hostile(Plant::UnhealthyOnAnyHold, 0)).expect("a run");
    let moves: Vec<usize> = (0..3).map(|at| moved(&mutant, at)).collect();
    let rule = "a shard whose volume is healthy changed hands";
    assert_eq!(rule, hosts::HEALTHY_MOVED);
    assert!(
        moves.iter().any(|&n| n > 0),
        "{moves:?}: {}",
        mutant.summary()
    );
    assert!(mutant.planted, "the any-hold mutant changed the run");
    assert_eq!(
        hosts::expected(&mutant).rule(),
        Some(rule),
        "{}",
        mutant.summary()
    );
}

/// NoEpochReuse at the driver: a restart activates its session only from its own acknowledged bump.
/// Under plant `RoleReadActivation` (code 59) a restart of s3 on H3 whose role read returned logs an activation at
/// the tenure that read named, the one the record held ahead of the restart's bump and the boot activated, and the
/// one-owner check fails the run by its reactivation rule. H3 crashes and returns under an outage of its store
/// requests: each incarnation whose role read fails logs nothing, and the first one whose role read returns logs
/// the one planted activation, beside the boot's at that tenure. The plant appends that entry to the driver's
/// activation log once the incarnation returned and starts no session, so it shows the check that judges such an
/// activation, not a session the sequence would open. Sibling: the same crash, return and outage with no plant
/// passes the one-owner check (`a_restart_that_ends_in_a_rerun_exit_runs_again_and_serves_after_the_outage`). The
/// scheduled case runs H3's crash and return with no outage and no plant
/// (`a_restart_after_a_crash_and_return_activates_from_its_own_bump_on`).
#[test]
fn an_activation_from_the_role_read_fails_the_one_owner_rule() {
    let planted = scripted(
        &Config::host_loss(1).hostile(Plant::RoleReadActivation, 3),
        return_under_an_outage(),
    );
    assert!(planted.planted);
    let reruns = planted.hosts.refused_reruns;
    assert!(reruns >= 10, "one rerun a round over the outage: {reruns}");
    let by_h3: Vec<_> = (planted.evidence.activations.iter())
        .filter(|(shard, _, host)| shard.get() == 4 && host.get() == H3)
        .map(|(_, tenure, _)| *tenure)
        .collect();
    let boot = by_h3[0];
    let at_boot = by_h3.iter().filter(|tenure| **tenure == boot).count();
    assert_eq!(
        (at_boot, by_h3.len()),
        (2, 3),
        "the boot's activation, the one the returned role read logged, and the restart's own: {by_h3:?}"
    );
    let reactivated = "one tenure activated twice";
    assert_eq!(
        planted.verdicts.one_owner.rule(),
        Some(reactivated),
        "{}",
        planted.summary()
    );
}

/// H3 crashes once H0 acknowledged its workload and returns two rounds later, before a suspicion.
fn h3_crash_and_return() -> Vec<Episode> {
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].scope = vec![3];
    script[0].heal = Some(2);
    script
}

/// H3's crash and return with no outage and no plant, beside the role-read control: the restart of s3 activates from
/// H3's own bump and passes the one-owner rule.
pub(super) fn a_restart_after_a_crash_and_return_activates_from_its_own_bump_on(root: u64) {
    let unplanted = scripted(&Config::host_loss(root), h3_crash_and_return());
    assert_eq!(unplanted.verdicts.one_owner, Verdict::Pass);
    let recovered = &unplanted.shards[3].recoveries;
    assert_eq!(
        recovered.len(),
        2,
        "H3's boot and its restart: {recovered:?}"
    );
    assert!(recovered.iter().all(|recovery| recovery.host.get() == H3));
    assert!(
        recovered[1].tenure.a > recovered[0].tenure.a,
        "{recovered:?}"
    );
}

/// The `RoleReadActivation` plant logs only at a tenure a role read named for an owner. s3's shard record names H3
/// owner while s3's volume record reads retired, so H3's role read returns `Role::Retired`, which names no tenure:
/// the restart ends `Exit::Retired`, the plant logs no activation and the run does not read planted.
#[test]
fn a_role_read_that_names_no_owner_tenure_logs_no_planted_activation() {
    use crate::failover::records::{Record, VolumeRecord, VolumeState};
    use crate::storage::store::{Key, Outcome, Store, Write};
    let config = Config::host_loss(1).hostile(Plant::RoleReadActivation, 3);
    let mut draws = Draws::record(config.root);
    let mut fleet = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    fleet.start_hosts();
    let _inline = Inline::set();
    let member = fleet.cells[3].placement.owner;
    assert_eq!(fleet.record_now(3).owner.get(), H3);
    let key = Key::Volume(fleet.cells[3].placement.volume);
    let item = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored volume record");
    let mut volume = VolumeRecord::decode(&item.value).expect("a volume record");
    volume.state = VolumeState::Retired;
    let write = Write::Exact {
        expect: item.version,
        value: volume.encode(),
    };
    let outcome = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");

    let grounds = [Grounds::over(storage_shared(1, fleet.share_on(member)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let restarted = fleet.restart_by(&mut live, &mut slots, (3, false, false), member);
    assert!(matches!(restarted, Ok(super::volumes::Restarted::Held)));
    assert_eq!(fleet.cells[3].blockers, ["Retired"]);
    assert_eq!(fleet.activations, []);
    assert!(!fleet.planted);
}

/// The exit and phase table: a waiting phase holds no device. In the host-loss case every view period of
/// each standby's wait ends `Exit::Stopped` and its fencer never connects (the standby-wait test checks the
/// exits). Under plant `WaitDevice` (code 41) the wait of s4's standby starts its fencer's device before each period:
/// the production wait returns that device with `Exit::Fault` before its first period, the fleet lists the exit, and
/// the host scenario's check fails the run by its waiting-phase rule.
#[test]
fn a_wait_whose_fencer_holds_a_device_ends_fault_and_fails_the_waiting_phase_rule() {
    let report = run(&Config::host_loss(1).hostile(Plant::WaitDevice, hosts::DUTY_CELL as u32));
    let report = report.expect("a run inside the limits");
    assert!(report.planted);
    let exits = &report.shards[hosts::DUTY_CELL].wait_exits;
    assert!(
        !exits.is_empty() && exits.iter().all(|exit| exit.starts_with("Fault")),
        "{exits:?}"
    );
    let rule = "a standby wait held a device";
    assert_eq!(rule, hosts::WAIT_DEVICE);
    assert_eq!(
        hosts::expected(&report).rule(),
        Some(rule),
        "{}",
        report.summary()
    );
}

/// A restart whose bump's reply is unknown ends `Exit::Held`, and the process publishes the `Held` status with its
/// refusal's class in a host scenario with no reconciler too: H3 crashes and returns two rounds later, before a
/// suspicion, and its restart's bump of s3 times out with no commit. H3's host reads itself unhealthy (s3 exempt),
/// since s3's record names H0 standby elsewhere. `Held::status` builds the recovery of the published entry, and the
/// case reads it three ways: its check names the bump, H3's accepted report carries s3's entry in phase `Held`, and its
/// next step holds H3's recovery slot in H3's last sealed report. The scheduled case runs the whole test: it has no
/// planted control, and it left the fast tier.
pub(super) fn a_held_restart_publishes_its_held_status_in_a_host_scenario_on(root: u64) {
    let mut script = h3_crash_and_return();
    script.push(Episode {
        scope: vec![3],
        action: Action::StoreWrite(Arm::Timeout { commit: false }),
        heal: None,
        ..script[0].clone()
    });
    let report = scripted(&Config::host_loss(root), script);
    let s3 = &report.shards[3];
    assert!(
        s3.blockers.iter().any(|check| check.contains("Bump")),
        "{:?}",
        s3.blockers
    );
    assert!(
        report.hosts.exempt.contains(&4),
        "{:?}",
        report.hosts.exempt
    );
    // H3's accepted report carries s3's entry in phase `Held`, and the hold's next step keeps H3's recovery slot.
    let held: Vec<(u64, u32)> = (report.hosts.held.iter())
        .map(|&(_, host, shard)| (host, shard))
        .collect();
    assert_eq!(held, [(H3, 4)]);
    let slot = report.hosts.sealed(H3).last().map(|gauges| gauges[2]);
    assert_eq!(slot, Some(Gauge::known(1, 1)), "host {H3}");
}

/// Whether a process holds s3 (`Exit::Held`).
fn s3_held(fleet: &Fleet<'_>) -> bool {
    !fleet.cells[3].held.is_empty()
}

/// A returned host's restart that ends `Exit::Held` keeps its return open, and the held process's rerun completes
/// it. H3 crashes and returns two rounds later, its restart's bump of s3 times out with no commit and holds, and a
/// scripted episode then runs the held process's next incarnation. That incarnation restarts s3 on H3 and completes
/// the return as a restart that served at once does: the zone log records the restart at its tenure, and the tenure
/// acknowledges its FILL and its INVALIDATE.
#[test]
fn a_returned_host_s_held_restart_completes_its_return_at_its_rerun() {
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].scope = vec![3];
    script[0].heal = Some(2);
    script.push(Episode {
        scope: vec![3],
        action: Action::StoreWrite(Arm::Timeout { commit: false }),
        heal: None,
        ..script[0].clone()
    });
    script.push(Episode {
        trigger: Trigger::When(s3_held),
        scope: Vec::new(),
        action: Action::Rerun(3),
        heal: None,
    });
    let report = scripted(&Config::host_loss(1), script);
    assert!(
        report.hosts.takeovers.is_empty(),
        "{:?}",
        report.hosts.takeovers
    );
    let s3 = &report.shards[3];
    let last = s3.recoveries.last().expect("a recovery");
    assert_eq!((s3.recoveries.len(), last.host.get()), (2, H3));
    let returned: Vec<_> = (report.zones.restarts.iter())
        .map(|&(shard, host, tenure, _)| (shard, host, tenure))
        .collect();
    assert_eq!(returned, [(4, H3, last.tenure)]);
    assert_eq!(report.zones.acknowledged, 1);
}

/// A held process's hold stands until its next incarnation starts. H3's restart of s3 holds at a bump that times
/// out, and the hold's rerun is queued. With H3's tenure slot taken when the rerun's turn comes, no incarnation
/// runs, H3 still holds s3, and the rerun stays queued; once a slot is free the host loop's next take of the queue
/// starts the incarnation, and the hold ends with it.
#[test]
fn a_held_process_whose_rerun_finds_no_slot_keeps_its_hold_until_an_incarnation_starts() {
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let (at, member) = (3, 3);
    assert_eq!(fleet.cells[at].placement.owner, member);
    fleet.hosts[member].up = hosts::Up::Running;
    let timeout = Arm::Timeout { commit: false };
    fleet
        .faults
        .store
        .borrow_mut()
        .arm_write(member as u32, timeout);
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let restarted = fleet.restart_by(&mut live, &mut slots, (at, true, false), member);
    let restarted = restarted.expect("a restart that stops on no wait");
    assert!(matches!(restarted, super::volumes::Restarted::Held));
    let holds = |fleet: &Fleet<'_>| fleet.cells[at].held.iter().any(|(of, _)| *of == member);
    assert!(holds(&fleet));

    fleet.rerun_held(at);
    fleet.round += 1;
    let due = fleet.refused_due().expect("the held process's rerun");
    assert_eq!(due, (at, member, true));
    slots.used = vec![true];
    let rerun = fleet.rerun_refused(&mut live, &mut slots, due);
    rerun.expect("a rerun that stops on no wait");
    assert_eq!(fleet.log.unslotted, 1);
    assert!(
        holds(&fleet),
        "no incarnation ran, so the process still holds"
    );

    // The rerun stays queued, and the host loop takes it again from the next round.
    assert_eq!(fleet.refused_due(), None);
    fleet.round += 1;
    let due = fleet.refused_due().expect("the rerun that found no slot");
    assert_eq!(due, (at, member, true));
    slots.used = vec![false];
    let rerun = fleet.rerun_refused(&mut live, &mut slots, due);
    rerun.expect("a rerun that stops on no wait");
    assert_eq!(fleet.log.refused_reruns, 1);
    assert!(
        !holds(&fleet),
        "the hold ended with the incarnation that held"
    );
    assert_eq!(fleet.refused_due(), None);
}

/// Whether H3's last accepted report carries s3 in phase `Held`.
fn s3_published_held(fleet: &Fleet<'_>) -> bool {
    fleet.hosts[3].held.contains(&4)
}

/// H3's crash and return with s3's volume keeping one command of H3's restart fencer, and the held process's rerun
/// once H3's report carries s3 in phase `Held`.
fn h3_unrefused_hold() -> Vec<Episode> {
    let mut script = h3_crash_and_return();
    script.push(Episode {
        scope: Vec::new(),
        action: Action::KeepCommand(3),
        heal: None,
        ..script[0].clone()
    });
    script.push(Episode {
        trigger: Trigger::When(s3_published_held),
        scope: Vec::new(),
        action: Action::Rerun(3),
        heal: None,
    });
    script
}

/// The judgment of [`h3_unrefused_hold`]'s run: s3's blocker is the `Exit::Held` itself, since no sequence refused;
/// H3's accepted reports carry s3 in phase `Held` and H3's recovery slot; and the held process's rerun completes
/// H3's return as a restart of s3 at its own tenure.
fn unrefused_hold_judged(report: &Report) -> Result<(), String> {
    let s3 = &report.shards[3];
    if !s3.blockers.iter().any(|check| check.starts_with("Held")) {
        return Err(format!("no unrefused held exit: {:?}", s3.blockers));
    }
    let held: Vec<(u64, u32)> = (report.hosts.held.iter())
        .map(|&(_, host, shard)| (host, shard))
        .collect();
    if held != [(H3, 4)] {
        return Err(format!("held entries {held:?}"));
    }
    let slots = report.hosts.sealed(H3);
    if !slots.iter().any(|gauges| gauges[2] == Gauge::known(1, 1)) {
        return Err(format!("H3's recovery gauges {slots:?}"));
    }
    let last = s3.recoveries.last().ok_or("no recovery of s3")?;
    let returned: Vec<_> = (report.zones.restarts.iter())
        .map(|&(shard, host, tenure, _)| (shard, host, tenure))
        .collect();
    if (s3.recoveries.len(), last.host.get()) != (2, H3) || returned != [(4, H3, last.tenure)] {
        return Err(format!("H3's return: {:?} {returned:?}", s3.recoveries));
    }
    Ok(())
}

/// DEVICE-FAILURE-HOLD with no refusal: a restart whose sequence succeeds while its fencer still holds a command ends
/// `Exit::Held` with no refusal, and the fleet keeps it as a hold. H3 crashes and returns two rounds later, and s3's
/// volume keeps one command of H3's restart fencer, so `host::recover` returns the outstanding table, which the
/// proven stop drains. The hold's status keeps its attempt running, so it names no check and holds the recovery
/// slot; H3 publishes s3 in phase `Held`; and `Fleet::rerun_held` runs the held process's next incarnation, which
/// completes H3's return. Control: under `UnrefusedHold` (code 98) H3's restart of s3 over the kept command still
/// ends held, and the fleet keeps no hold; the live planted run is the scheduled row's `held-unrefused-control`.
#[test]
fn a_restart_that_succeeds_with_a_kept_command_holds_with_no_check_and_its_rerun_completes_the_return()
 {
    let running = super::volumes::Held::of_restart(None).status();
    let recovery = running.recovery(0);
    assert_eq!(
        (recovery.outcome, recovery.check, recovery.next),
        (
            Some(crate::failover::report::RecoveryOutcome::Running),
            None,
            None
        )
    );
    assert!(running.holds_slot());
    let report = scripted(&Config::host_loss(1), h3_unrefused_hold());
    assert_eq!(unrefused_hold_judged(&report), Ok(()));
    assert_eq!(report.verdicts.one_owner, Verdict::Pass);
    assert_eq!(kept_command_holds(&Config::host_loss(1)), (true, false));
    let planted = Config::host_loss(1).hostile(Plant::UnrefusedHold, 3);
    assert_eq!(kept_command_holds(&planted), (false, true));
}

/// Whether H0's last accepted report carries s3 in phase `Held`.
fn s3_published_held_by_h0(fleet: &Fleet<'_>) -> bool {
    fleet.hosts[0].held.contains(&4)
}

/// DEVICE-FAILURE-HOLD with no refusal on a takeover: H3 crashes, and s3's volume keeps one command of the fencer of
/// H0's takeover, so the takeover's sequence succeeds and `host::stand_by` ends `Exit::Held` with no refusal. The
/// fleet keeps it as a hold of kind takeover: H0 publishes s3 in phase `Held`, and once it has, the held process's
/// rerun restarts s3 on H0 at a later tenure.
#[test]
fn a_takeover_that_succeeds_with_a_kept_command_holds_and_its_rerun_serves_the_shard() {
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].scope = vec![3];
    script.push(Episode {
        scope: Vec::new(),
        action: Action::KeepCommand(3),
        heal: None,
        ..script[0].clone()
    });
    script.push(Episode {
        trigger: Trigger::When(s3_published_held_by_h0),
        scope: Vec::new(),
        action: Action::Rerun(3),
        heal: None,
    });
    let report = scripted(&Config::host_loss(1), script);
    let refused: Vec<_> = (report.hosts.takeovers.iter())
        .map(|attempt| (attempt.shard, attempt.host, attempt.refused.clone()))
        .collect();
    assert!(
        matches!(&refused[..], [(4, H0, Some(held))] if held.starts_with("Held")),
        "{refused:?}"
    );
    let held: Vec<(u64, u32)> = (report.hosts.held.iter())
        .map(|&(_, host, shard)| (host, shard))
        .collect();
    assert_eq!(held, [(H0, 4)]);
    let s3 = &report.shards[3];
    let last = s3.recoveries.last().expect("a recovery of s3");
    assert_eq!((last.host.get(), last.after_crash), (H0, true));
    assert_eq!(report.verdicts.one_owner, Verdict::Pass);
}

/// H3's restart of s3 over a volume that keeps one command of its fencer, run alone on `config`'s fleet: whether
/// the fleet keeps H3's hold of s3, and whether the run planted. The restart ends `Exit::Held` with no refusal.
fn kept_command_holds(config: &Config) -> (bool, bool) {
    let (mut fleet, _draws) = hosted(config);
    let (at, member) = (3, 3);
    fleet.hosts[member].up = hosts::Up::Running;
    fleet.cells[at].keeps.set(true);
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let restarted = fleet.restart_by(&mut live, &mut slots, (at, true, false), member);
    let restarted = restarted.expect("a restart that stops on no wait");
    assert!(matches!(restarted, super::volumes::Restarted::Held));
    let blocker = fleet.cells[at]
        .blockers
        .last()
        .expect("the held exit's blocker");
    assert!(blocker.starts_with("Held"), "{blocker}");
    assert!(
        !fleet.cells[at].keeps.get(),
        "the restart took the kept command"
    );
    let holds = fleet.cells[at].held.iter().any(|(of, _)| *of == member);
    (holds, fleet.planted)
}

/// The live control of [`a_restart_that_succeeds_with_a_kept_command_holds_with_no_check_and_its_rerun_completes_the_return`]:
/// under `UnrefusedHold` (code 98) the fleet keeps no hold for H3's held restart of s3, so H3 publishes no `Held`
/// entry, no rerun runs, s3 is never served again, and the run stalls at the host scenario's settle.
pub(super) fn an_unrefused_hold_the_fleet_drops_stalls_the_settle_on(root: u64) {
    let config = Config::host_loss(root).hostile(Plant::UnrefusedHold, 3);
    match played(&config, h3_unrefused_hold(), false) {
        Err(Stopped::Stalled(stall)) => {
            assert_eq!(stall.waited, "the host scenario's settle", "{stall:?}")
        }
        other => panic!("{:?}", other.map(|report| unrefused_hold_judged(&report))),
    }
}

/// A returned host's restart that holds queues no next incarnation, so the return reads as still to run
/// (`Fleet::returning`) only from the round the hold's rerun is queued. H3's restart of s3 after its return holds at
/// a bump that times out; the rerun's tenure then rises, and the return is complete once its session is active.
#[test]
fn a_returned_host_s_held_restart_reads_as_returning_once_its_rerun_is_queued() {
    let config = Config::host_loss(1);
    let _inline = Inline::set();
    let (mut fleet, draws) = hosted(&config);
    fleet.draws = Some(draws);
    let (at, member) = (3, 3);
    assert_eq!(fleet.cells[at].placement.owner, member);
    fleet.hosts[member].up = hosts::Up::Running;
    let timeout = Arm::Timeout { commit: false };
    fleet
        .faults
        .store
        .borrow_mut()
        .arm_write(member as u32, timeout);
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let returned = fleet.restart_returned(&mut live, &mut slots, (at, member));
    returned.expect("a restart that stops on no wait");
    assert!(fleet.cells[at].held.iter().any(|(of, _)| *of == member));
    assert!(fleet.returning.is_empty(), "{:?}", fleet.returning);

    fleet.rerun_held(at);
    assert!(fleet.returning.contains(&(at, member)));
    fleet.round += 1;
    let due = fleet.refused_due().expect("the held process's rerun");
    let rerun = fleet.rerun_refused(&mut live, &mut slots, due);
    rerun.expect("a rerun that stops on no wait");
    assert!(fleet.returning.is_empty(), "{:?}", fleet.returning);
    // The rerun's tenure rises with the return, and the zone log lists the restart once its session is active.
    assert_eq!((fleet.rises.len(), fleet.zone_log.restarts.len()), (1, 0));
    for _ in 0..64 {
        fleet.step_rises(&mut live).expect("a rise inside its wait");
        if fleet.rises.is_empty() {
            break;
        }
        fleet.turn(&mut live);
    }
    assert!(fleet.rises.is_empty(), "the rise ended");
    assert_eq!(fleet.zone_log.restarts.len(), 1);
}

/// A `Standby` status as the fleet publishes it for s0: the standby's member and the target its status carries.
type Published = Option<(usize, crate::failover::retire::Target)>;

/// Commits `value` as the next version of the record stored under `key`.
fn commit(fleet: &Fleet<'_>, key: Key, value: Vec<u8>) {
    let stored = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored record");
    let write = Write::Exact {
        expect: stored.version,
        value,
    };
    let outcome = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
}

/// Commits `record` as the next version of its shard's stored record.
fn commit_shard(fleet: &Fleet<'_>, record: &ShardRecord) {
    commit(fleet, Key::Shard(record.shard), record.encode());
}

/// Three view periods of the wait of s0's standby. The first reads s0's record. The store then commits a bump of
/// the record, and the second period runs with `arms` queued for its volume read and its shard read. The third
/// runs with no arm. Returns the statuses that carry the first record's target and the bumped record's, and the
/// statuses published after the second and the third period.
fn the_standby_s_status_across_a_bump_read_under(
    arms: [Arm; 2],
) -> (Published, Published, [Published; 2]) {
    use crate::failover::retire::Target;
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let at = 0;
    let read = fleet.record_now(at);
    let standby = (read.standby)
        .and_then(|host| fleet.member_of(host))
        .expect("s0's standby");
    let published = |fleet: &Fleet<'_>| fleet.cells[at].waiting.map(|(of, target, _)| (of, target));
    fleet.standby_waits();
    assert_eq!(published(&fleet), Some((standby, Target::of(&read))));
    let bumped = ShardRecord {
        attempts: read.attempts + 1,
        ..read
    };
    commit_shard(&fleet, &bumped);
    for arm in arms {
        fleet.faults.store.borrow_mut().arm(standby as u32, arm);
    }
    fleet.standby_waits();
    assert_eq!(fleet.cells[at].waits.last(), Some(&(2, 0)));
    assert!(fleet.cells[at].wait_exits.is_empty());
    let armed = published(&fleet);
    fleet.standby_waits();
    let targets = [&read, &bumped].map(|record| Some((standby, Target::of(record))));
    (targets[0], targets[1], [armed, published(&fleet)])
}

/// A standby's `Standby` status carries the target of the last shard record its wait read. A view period whose
/// shard read returns no value reads no role, so the status keeps the earlier target while the store holds a later
/// version.
#[test]
fn a_view_period_whose_shard_read_returns_no_value_keeps_the_standby_s_published_target() {
    let (volume_read, shard_read) = (Arm::Pass, Arm::Unavailable);
    let (first, bumped, [armed, unarmed]) =
        the_standby_s_status_across_a_bump_read_under([volume_read, shard_read]);
    assert_eq!(armed, first);
    assert_eq!(unarmed, bumped);
}

/// A view period whose two reads each take a queued arm that passes them reads its role, so the standby's status
/// carries the target of the record that period read.
#[test]
fn a_view_period_whose_reads_pass_under_queued_arms_publishes_the_target_it_read() {
    let (_, bumped, [armed, unarmed]) =
        the_standby_s_status_across_a_bump_read_under([Arm::Pass, Arm::Pass]);
    assert_eq!(armed, bumped);
    assert_eq!(unarmed, bumped);
}

/// The waiting standby's status comes from the production wait: once a view period of the waits ran, s0's standby
/// turns over the status `host::stand_by` published to its period's status cell, phase `Standby` at the record's
/// target with the report entry `host::recover::standing` built, role `Standby` and named, since its enrolled pair
/// stands on the active volume. Before any period the process publishes only the target with no entry.
#[test]
fn a_waiting_standby_turns_over_the_status_and_entry_the_production_wait_published() {
    use crate::failover::report::{Phase as OwnerPhase, RecordedRole};
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let at = 0;
    let record = fleet.record_now(at);
    let host = record.standby.expect("s0's standby");
    let standby = fleet.member_of(host).expect("s0's standby member");
    let live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let now = fleet.detector_now();
    let target = crate::failover::retire::Target::of(&record);
    fleet.publish_wait(at, standby, target);
    let shard = fleet.cells[at].placement.shard;
    let early = fleet.statuses(&live, standby, now);
    let early = (early.iter()).find(|status| status.shard == shard);
    let early = early.expect("the incarnation's Standby status");
    assert_eq!((early.phase, early.entry), (OwnerPhase::Standby, None));
    fleet.standby_waits();
    let published = fleet.cells[at].published.borrow().clone();
    let [(of, published)] = published[..] else {
        panic!("one published status: {published:?}");
    };
    assert_eq!(of, host);
    let statuses = fleet.statuses(&live, standby, now);
    let sent = (statuses.iter()).find(|status| status.shard == shard);
    let sent = sent.expect("the standby's status");
    assert_eq!(sent.phase, OwnerPhase::Standby);
    assert_eq!(sent.target, Some(target));
    assert_eq!(sent.entry, published.entry);
    let entry = sent.entry.expect("the production wait's entry");
    assert_eq!(
        (entry.role, entry.named),
        (Some(RecordedRole::Standby), Some(true))
    );
}

/// Each waiting host's publication stands beside the others of its cell. s2's volume holds a third attach, of H1,
/// and with H1's pair gone from the volume record H1's unnamed wait runs a view period of s2 after the named
/// standby's. Both periods publish, and the named standby turns over the entry its own wait published.
#[test]
fn an_unnamed_host_s_period_keeps_the_named_standby_s_published_status() {
    use crate::failover::report::{Phase as OwnerPhase, RecordedRole};
    let config = Config::attach_survivor(1);
    let (mut fleet, _draws) = hosted(&config);
    let at = hosts::ATTACH_CELL;
    let third = fleet.topology.members[1].host;
    assert_eq!(third.get(), H1);
    let mut volume = fleet.volume_now(at);
    volume.pairs.retain(|recorded| recorded.host != third);
    commit(&fleet, Key::Volume(volume.volume), volume.encode());
    let record = fleet.record_now(at);
    let host = record.standby.expect("s2's standby");
    let standby = fleet.member_of(host).expect("s2's standby member");
    let live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let now = fleet.detector_now();
    let target = crate::failover::retire::Target::of(&record);
    fleet.publish_wait(at, standby, target);
    fleet.standby_waits();
    fleet.unnamed_waits();
    let published: Vec<_> = (fleet.cells[at].published.borrow().iter())
        .copied()
        .collect();
    let published =
        |of: Host| (published.iter()).find_map(|&(host, status)| (host == of).then_some(status));
    let unnamed = published(third).expect("the unnamed host's period published");
    let entry = unnamed.entry.expect("the unnamed wait's entry");
    assert_eq!(entry.role, Some(RecordedRole::Unrecorded));
    let shard = fleet.cells[at].placement.shard;
    let statuses = fleet.statuses(&live, standby, now);
    let sent = (statuses.iter()).find(|status| status.shard == shard);
    let sent = sent.expect("the standby's status");
    assert_eq!(
        (sent.phase, sent.target),
        (OwnerPhase::Standby, Some(target))
    );
    let entry = sent
        .entry
        .expect("the entry the named standby's own wait published");
    assert_eq!(
        (entry.role, entry.named),
        (Some(RecordedRole::Standby), Some(true))
    );
    assert_eq!(Some(sent.entry), published(host).map(|status| status.entry));
}

/// A wait classifies its role from the volume record and the shard record its view period read. A retired or deleted
/// volume record that the shard record still names active makes the role retired while the shard record names the
/// host standby, so that period ends the process's `Standby` status. A provisioning record of the named volume
/// reads as the shard's active volume, and the status stands.
#[test]
fn a_view_period_whose_volume_record_reads_retired_ends_the_standby_s_status() {
    use crate::failover::records::VolumeState;
    let cases = [
        (VolumeState::Retired, false),
        (VolumeState::Deleted, false),
        (VolumeState::Provisioning, true),
    ];
    for (state, stands) in cases {
        let config = Config::host_loss(1);
        let (mut fleet, _draws) = hosted(&config);
        let at = 0;
        let standby = (fleet.record_now(at).standby)
            .and_then(|host| fleet.member_of(host))
            .expect("s0's standby");
        fleet.standby_waits();
        let published = fleet.cells[at].waiting;
        assert!(published.is_some_and(|(of, ..)| of == standby));
        let volume = VolumeRecord {
            state,
            ..fleet.volume_now(at)
        };
        commit(&fleet, Key::Volume(volume.volume), volume.encode());
        fleet.standby_waits();
        assert_eq!(fleet.cells[at].waits.last(), Some(&(2, 0)), "{state:?}");
        assert!(fleet.cells[at].wait_exits.is_empty(), "{state:?}");
        assert_eq!(
            fleet.cells[at].waiting,
            published.filter(|_| stands),
            "{state:?}"
        );
    }
}

/// The `Standby` status of a next incarnation that waits carries the target and the active volume of one record
/// version, the one its role read returned. With a later version stored at the next generation on another volume,
/// the status still names the volume of the version whose target it carries.
#[test]
fn a_waiting_incarnation_s_status_names_the_volume_of_the_record_version_it_read() {
    use crate::failover::retire::Target;
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let at = 0;
    let read = fleet.record_now(at);
    let standby = (read.standby)
        .and_then(|host| fleet.member_of(host))
        .expect("s0's standby");
    let generation = crate::net::ownership::ShardGeneration::new(read.generation.get() + 1);
    let flipped = ShardRecord {
        generation: generation.expect("a next generation"),
        active: fleet.cells[1].placement.volume,
        ..read
    };
    assert_ne!(flipped.active, read.active);
    commit_shard(&fleet, &flipped);
    fleet.publish_wait(at, standby, Target::of(&read));
    assert_eq!(
        fleet.cells[at].waiting,
        Some((standby, Target::of(&read), read.active))
    );
}

/// A view period's status comes from its role read, the first read of each record in the period. A standby that the
/// shard record names and the volume record does not enroll calls `enroll_standby` after its role read, which reads
/// both records again. With the role read's shard read returning the previous version and the later read the
/// current one, the status carries the target of the version the role read returned.
#[test]
fn a_view_period_that_reads_its_records_again_to_enroll_publishes_its_role_read() {
    use crate::failover::retire::Target;
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let at = 0;
    let read = fleet.record_now(at);
    let standby = (read.standby)
        .and_then(|host| fleet.member_of(host))
        .expect("s0's standby");
    let host = fleet.topology.members[standby].host;
    fleet.standby_waits();
    let published = Some((standby, Target::of(&read), read.active));
    assert_eq!(fleet.cells[at].waiting, published);
    let mut volume = fleet.volume_now(at);
    assert!(volume.live(host).is_some() && volume.enrolled(host).is_some());
    volume.pairs.retain(|recorded| recorded.host != host);
    commit(&fleet, Key::Volume(volume.volume), volume.encode());
    let bumped = ShardRecord {
        attempts: read.attempts + 1,
        ..read
    };
    commit_shard(&fleet, &bumped);
    // The role read's volume read passes and its shard read returns the previous version.
    for arm in [Arm::Pass, Arm::StaleCurrentRead] {
        fleet.faults.store.borrow_mut().arm(standby as u32, arm);
    }
    fleet.standby_waits();
    let (reads, writes) = *fleet.cells[at].waits.last().expect("a period");
    assert!(
        reads > 2 && writes == 0,
        "the period read its records again: {reads}, {writes}"
    );
    assert!(fleet.cells[at].wait_exits.is_empty());
    assert_eq!(fleet.cells[at].waiting, published);
}

/// The fleet runs a wait only for the standby the stored shard record names. Once a committed record names no
/// standby, the former standby runs no view period for the shard, so its `Standby` status ends in that view period
/// with no read of its own.
#[test]
fn a_standby_the_stored_record_stops_naming_runs_no_period_and_publishes_no_status() {
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let at = 0;
    let read = fleet.record_now(at);
    let standby = (read.standby)
        .and_then(|host| fleet.member_of(host))
        .expect("s0's standby");
    fleet.standby_waits();
    assert!(
        fleet.cells[at]
            .waiting
            .is_some_and(|(of, ..)| of == standby)
    );
    let periods = fleet.cells[at].waits.len();
    let unnamed = ShardRecord {
        standby: None,
        ..read
    };
    commit_shard(&fleet, &unnamed);
    let requests = fleet.cells[at].requests(&fleet.store);
    fleet.standby_waits();
    assert_eq!(fleet.cells[at].waiting, None);
    assert_eq!(fleet.cells[at].waits.len(), periods);
    assert!(fleet.cells[at].wait_exits.is_empty());
    assert_eq!(fleet.cells[at].requests(&fleet.store), requests);
}

/// A serving tenure's rerun that is itself refused keeps the round its tenure ended. The run has no loss: s3's boot
/// tenure on H3 names `Rerun(Withdrawn)`. In the first run the rerun restarts s3 on H3 at once. In the second, H3's
/// store requests fail for `OUTAGE` rounds from the step that queues the rerun: the rerun's role read fails in the
/// round the tenure ended, each next incarnation runs a round later, and the first one after the heal restarts s3
/// on H3. That recovery counts the first run's rounds and one more for each refused rerun the host loop ran.
#[test]
fn a_serving_tenures_rerun_refused_under_an_outage_counts_its_rounds_from_the_round_its_tenure_ended()
 {
    const OUTAGE: u64 = 8;
    let rerun = |script: Vec<Episode>| {
        let config = Config::host_loss(1);
        let mut draws = Draws::record(config.root);
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        fleet.faults = Faults::new(script, fleet.topology.members.len());
        fleet.alarms.scripted = true;
        let _inline = Inline::set();
        let ran = fleet.play_script_with(draws, |fleet, live, slots| {
            for _ in 0..hosts::TAIL_ROUNDS {
                fleet.turn(live);
            }
            let serving = live[3].as_mut().expect("the boot tenure");
            serving.duty_exit = Some(crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn));
            fleet.run_hosts(live, slots)
        });
        let report = ran.expect("a run inside the limits");
        let s3 = &report.shards[3];
        let last = *s3.recoveries.last().expect("a recovery");
        assert_eq!((s3.recoveries.len(), last.host.get()), (2, H3));
        assert!(!last.after_crash);
        (last.rounds, u64::from(report.hosts.refused_reruns))
    };
    let outage = Episode {
        trigger: Trigger::When(|fleet| !fleet.reruns.is_empty()),
        scope: vec![3],
        action: Action::Outage,
        heal: Some(OUTAGE),
    };
    let (direct, none) = rerun(Vec::new());
    let (refused, reruns) = rerun(vec![outage]);
    assert_eq!(none, 0);
    assert!(
        reruns >= OUTAGE,
        "one rerun a round over the outage: {reruns}"
    );
    assert_eq!(refused, direct + reruns);
}

/// A process refused for the first time in a round the faults are settled in still gets its next incarnation's
/// turn, and a refusal that recurs holds no run open. H3's store requests fail from the first host round with no
/// heal, so the fault is settled once the tail rounds pass. s3's boot tenure on H3 then names `Rerun(Withdrawn)`: its
/// rerun's role read fails and queues the next incarnation. The host loop runs one more round for it, that
/// incarnation's role read fails again, and the run ends there with s3 unserved and its blocker named.
#[test]
fn a_restart_refused_after_the_tail_rounds_runs_its_next_incarnation_once_before_the_run_ends() {
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    let outage = Episode {
        trigger: Trigger::AtTime(0),
        scope: vec![3],
        action: Action::Outage,
        heal: None,
    };
    fleet.faults = Faults::new(vec![outage], fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let mut ended = 0;
    let ran = fleet.play_script_with(draws, |fleet, live, slots| {
        fleet.episodes(live, slots)?;
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        assert!(fleet.faults.settled());
        let serving = live[3].as_mut().expect("the boot tenure");
        serving.duty_exit = Some(crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn));
        ended = fleet.round;
        fleet.run_hosts(live, slots)
    });
    let report = ran.expect("a run that ends before the horizon");
    let s3 = &report.shards[3];
    assert_eq!(
        (s3.recoveries.len(), report.hosts.refused_reruns),
        (1, 1),
        "{}",
        report.summary()
    );
    assert_eq!(s3.blockers, ["Unavailable", "Unavailable"]);
    assert!(
        report.rounds <= ended + 4,
        "{} rounds after {ended}",
        report.rounds
    );
}

/// A refused rerun whose role read fails under a record that names another owner runs again, and the wait on a
/// retake is recorded from the role the next incarnation read. s3's record names another owner with H3 its standby,
/// and H3's store requests fail for the first rerun: its role read fails, the next incarnation is queued and no
/// retake is recorded. With the outage over, the next incarnation reads the standby role and waits on its retake.
#[test]
fn a_refused_rerun_whose_role_read_fails_under_another_owners_record_runs_again_before_it_waits() {
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.start_hosts();
    let (at, member) = (3, 3);
    assert_eq!(fleet.cells[at].placement.owner, member);
    fleet.hosts[member].up = hosts::Up::Running;
    let members = &fleet.topology.members;
    let (host, successor) = (members[member].host, members[member + 1].host);
    let key = Key::Shard(fleet.cells[at].placement.shard);
    let item = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored shard record");
    let before = fleet.record_now(at);
    let taken = ShardRecord {
        owner: successor,
        standby: Some(host),
        attempts: before.attempts + 1,
        ..before
    };
    let write = Write::Exact {
        expect: item.version,
        value: taken.encode(),
    };
    let committed = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(committed, Outcome::Committed(_)));
    fleet
        .faults
        .store
        .borrow_mut()
        .outage(Some(member as u32), 0, 1);
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let rerun = fleet.rerun_refused(&mut live, &mut slots, (at, member, true));
    rerun.expect("a rerun that stops on no wait");
    assert!(
        fleet.refused.contains_key(&(at, member)),
        "{:?}",
        fleet.refused
    );
    assert!(fleet.retakes.is_empty(), "{:?}", fleet.retakes);

    fleet.faults.store.borrow_mut().set_now(1);
    fleet.refused.remove(&(at, member));
    let rerun = fleet.rerun_refused(&mut live, &mut slots, (at, member, true));
    rerun.expect("a rerun that stops on no wait");
    assert!(fleet.refused.is_empty(), "{:?}", fleet.refused);
    assert_eq!(fleet.retakes.get(&at), Some(&member));
    assert_eq!(fleet.log.refused_reruns, 2);
    assert_eq!(slots.used, [false]);
}

/// A wait's rerun exit queues its process's next incarnation once. s0's record comes to name its standby's host owner
/// while the boot owner holds the cell, so the standby's next period reads the restart role and ends
/// `Rerun(RoleChanged)`: the host log lists the role change, and the next incarnation is queued from that round with
/// no loss before it. When the process is already queued after a loss, the period queues nothing: the entry keeps
/// its round and its loss, and the host log lists no role change.
#[test]
fn a_wait_that_reads_its_host_owner_queues_one_next_incarnation_and_keeps_an_earlier_one() {
    let waited = |queued: bool| {
        let config = Config::host_loss(1);
        let (mut fleet, _draws) = hosted(&config);
        let at = 0;
        let read = fleet.record_now(at);
        let host = read.standby.expect("s0's standby");
        let member = fleet.member_of(host).expect("the standby's member");
        fleet.standby_waits();
        assert_eq!(fleet.cells[at].waiting.map(|(of, ..)| of), Some(member));
        let named = ShardRecord {
            owner: host,
            standby: None,
            attempts: read.attempts + 1,
            ..read
        };
        commit_shard(&fleet, &named);
        let earlier = (fleet.round, true);
        if queued {
            fleet.refused.insert((at, member), earlier);
        }
        fleet.standby_waits();
        assert_eq!(fleet.cells[at].wait_exits, ["Rerun(RoleChanged)"]);
        let key = (at, member);
        let entry = fleet.refused.get(&key).copied();
        let start = fleet.rerun_starts.get(&key).copied();
        (entry, start, fleet.log.role_changes.len(), fleet.round)
    };
    let (entry, start, listed, round) = waited(false);
    assert_eq!(
        (entry, start, listed),
        (Some((round, false)), Some(round), 1)
    );
    let (entry, start, listed, round) = waited(true);
    assert_eq!((entry, start, listed), (Some((round, true)), None, 0));
}

/// A restart's incarnation whose role read returns the standby role waits as that standby, and its wait publishes
/// `Standby` with the target that read returned, before any view period of the waits runs. s3's record names another
/// owner with H3 its standby, and H3's next incarnation for s3 reads it.
#[test]
fn a_restart_whose_role_read_names_its_host_standby_publishes_the_standby_status() {
    use crate::failover::retire::Target;
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let (at, member) = (3, 3);
    assert_eq!(fleet.cells[at].placement.owner, member);
    fleet.hosts[member].up = hosts::Up::Running;
    let members = &fleet.topology.members;
    let (host, successor) = (members[member].host, members[member + 1].host);
    let before = fleet.record_now(at);
    let taken = ShardRecord {
        owner: successor,
        standby: Some(host),
        attempts: before.attempts + 1,
        ..before
    };
    commit_shard(&fleet, &taken);
    assert_eq!(fleet.cells[at].waiting, None);
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let rerun = fleet.rerun_refused(&mut live, &mut slots, (at, member, true));
    rerun.expect("a rerun that stops on no wait");
    assert_eq!(fleet.retakes.get(&at), Some(&member));
    assert_eq!(
        fleet.cells[at].waiting,
        Some((member, Target::of(&taken), taken.active))
    );
}

/// A process that published `Standby` holds the record version it read in its host's watermark, so a later role read
/// that returns an older version regresses: the incarnation reads no role, ends with its next one queued, and ends
/// the status. s3's record names another owner with H3 its standby; H3's incarnation reads it and publishes, and its
/// next incarnation's shard read returns the version before, which named H3 owner.
#[test]
fn a_stale_role_read_after_a_published_status_regresses_and_ends_the_status() {
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let (at, member) = (3, 3);
    assert_eq!(fleet.cells[at].placement.owner, member);
    fleet.hosts[member].up = hosts::Up::Running;
    let members = &fleet.topology.members;
    let (host, successor) = (members[member].host, members[member + 1].host);
    let before = fleet.record_now(at);
    assert_eq!(before.owner, host);
    let taken = ShardRecord {
        owner: successor,
        standby: Some(host),
        attempts: before.attempts + 1,
        ..before
    };
    commit_shard(&fleet, &taken);
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let rerun = fleet.rerun_refused(&mut live, &mut slots, (at, member, true));
    rerun.expect("a rerun that stops on no wait");
    assert!(fleet.cells[at].waiting.is_some_and(|(of, ..)| of == member));

    // The next role read's volume read passes and its shard read returns the version that named H3 owner.
    for arm in [Arm::Pass, Arm::StaleCurrentRead] {
        fleet.faults.store.borrow_mut().arm(member as u32, arm);
    }
    let restarted = fleet.restart_by(&mut live, &mut slots, (at, true, false), member);
    let check = match restarted.expect("a restart that stops on no wait") {
        super::volumes::Restarted::Deposed { check, .. } => check,
        _ => panic!("the record names another owner"),
    };
    assert!(
        check
            .as_deref()
            .is_some_and(|check| check.contains("Regression")),
        "{check:?}"
    );
    assert!(fleet.refused.contains_key(&(at, member)));
    assert_eq!(fleet.cells[at].waiting, None);
    assert_eq!(slots.used, [false]);
}

/// An incarnation whose role read returns a role other than standby ends the `Standby` status its process published
/// before. H3 waits as s0's standby and publishes; s0's record then names no standby, and H3's next incarnation for
/// s0 reads the unnamed role.
#[test]
fn an_incarnation_whose_role_read_names_its_host_no_standby_ends_the_standby_status() {
    let config = Config::host_loss(1);
    let (mut fleet, _draws) = hosted(&config);
    let at = 0;
    let read = fleet.record_now(at);
    let member = (read.standby)
        .and_then(|host| fleet.member_of(host))
        .expect("s0's standby");
    fleet.standby_waits();
    assert!(fleet.cells[at].waiting.is_some_and(|(of, ..)| of == member));
    let unnamed = ShardRecord {
        standby: None,
        ..read
    };
    commit_shard(&fleet, &unnamed);
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let rerun = fleet.rerun_refused(&mut live, &mut slots, (at, member, true));
    rerun.expect("a rerun that stops on no wait");
    assert!(fleet.retakes.is_empty(), "{:?}", fleet.retakes);
    assert_eq!(fleet.cells[at].waiting, None);
}

/// A returned host whose role read fails under a record that names another owner keeps its return open for the
/// next incarnation. s3's record names another owner and H3's store requests fail for its first restart: the zone
/// log lists the return with the read's error, which is no deposed host's end, and the next incarnation is queued as
/// a returning one. With the outage over it reads its role, and the zone log lists the role H3 waits in.
#[test]
fn a_returned_hosts_failed_role_read_under_another_owners_record_completes_its_return_on_the_rerun()
{
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.start_hosts();
    let (at, member) = (3, 3);
    fleet.hosts[member].up = hosts::Up::Running;
    let members = &fleet.topology.members;
    let successor = members[member + 1].host;
    let key = Key::Shard(fleet.cells[at].placement.shard);
    let item = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored shard record");
    let before = fleet.record_now(at);
    let taken = ShardRecord {
        owner: successor,
        attempts: before.attempts + 1,
        ..before
    };
    let write = Write::Exact {
        expect: item.version,
        value: taken.encode(),
    };
    let committed = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(committed, Outcome::Committed(_)));
    fleet
        .faults
        .store
        .borrow_mut()
        .outage(Some(member as u32), 0, 1);
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let returned = fleet.restart_returned(&mut live, &mut slots, (at, member));
    returned.expect("a return that stops on no wait");
    let accepted = |fleet: &Fleet<'_>| -> Vec<bool> {
        (fleet.zone_log.deposed.iter())
            .map(|(.., check, _)| super::zones::deposed(check))
            .collect()
    };
    assert_eq!(accepted(&fleet), [false]);
    assert!(
        fleet.refused.contains_key(&(at, member)),
        "{:?}",
        fleet.refused
    );
    // The zone's settlement waits for the queued incarnation of the return.
    fleet.returned_at = Some(fleet.round);
    fleet.zone_settled(&live);
    assert_eq!(fleet.zone_log.settled_in, None);

    fleet.faults.store.borrow_mut().set_now(1);
    fleet.refused.remove(&(at, member));
    let rerun = fleet.rerun_refused(&mut live, &mut slots, (at, member, true));
    rerun.expect("a rerun that stops on no wait");
    assert_eq!(
        accepted(&fleet),
        [false, true],
        "{:?}",
        fleet.zone_log.deposed
    );
    fleet.zone_settled(&live);
    assert_eq!(fleet.zone_log.settled_in, Some(0));
    assert!(fleet.refused.is_empty() && fleet.returning.is_empty());
    assert_eq!(slots.used, [false]);
}

/// An incarnation that ends with a rerun exit under a record that names another owner still queues its next one.
/// s3's record names another owner with H3 its standby. H3's role read returns the record's previous version, which
/// names H3 owner, so the incarnation starts a restart, and that restart's next record read fails: the incarnation
/// ends `Rerun(Records)`. The attempt reads deposed, since the record names another owner, and the next incarnation
/// is queued; with no fault left it reads the standby role and waits on its retake.
#[test]
fn a_rerun_exit_under_another_owners_record_queues_the_next_incarnation() {
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.start_hosts();
    let (at, member) = (3, 3);
    fleet.hosts[member].up = hosts::Up::Running;
    let members = &fleet.topology.members;
    let (host, successor) = (members[member].host, members[member + 1].host);
    let key = Key::Shard(fleet.cells[at].placement.shard);
    let item = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored shard record");
    let before = fleet.record_now(at);
    let taken = ShardRecord {
        owner: successor,
        standby: Some(host),
        attempts: before.attempts + 1,
        ..before
    };
    let write = Write::Exact {
        expect: item.version,
        value: taken.encode(),
    };
    let committed = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(committed, Outcome::Committed(_)));
    // The role read's volume record passes, its shard record reads stale, and the restart's next read fails.
    for arm in [Arm::Pass, Arm::StaleCurrentRead, Arm::Unavailable] {
        fleet.faults.store.borrow_mut().arm(member as u32, arm);
    }
    let grounds = [Grounds::over(storage_shared(1, fleet.share(at)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let restarted = fleet.restart_by(&mut live, &mut slots, (at, true, false), member);
    let check = match restarted.expect("a restart that stops on no wait") {
        super::volumes::Restarted::Deposed { check, .. } => check,
        _ => panic!("the record names another owner"),
    };
    assert_eq!(check.as_deref(), Some("Records"));
    assert_eq!(fleet.faults.store.borrow().queued(member as u32), 0);
    assert!(
        fleet.refused.contains_key(&(at, member)),
        "{:?}",
        fleet.refused
    );
    let cell = &fleet.cells[at];
    assert_eq!((cell.blocked, cell.blockers.len()), (false, 0));

    fleet.refused.remove(&(at, member));
    let rerun = fleet.rerun_refused(&mut live, &mut slots, (at, member, true));
    rerun.expect("a rerun that stops on no wait");
    assert!(fleet.refused.is_empty(), "{:?}", fleet.refused);
    assert_eq!(fleet.retakes.get(&at), Some(&member));
    assert_eq!(slots.used, [false]);
}

/// A standby's view period that ends with a rerun exit at its role read ends the process, and the host loop runs
/// its next incarnation. s5's record is rewritten to name H1, its standby, owner at the next attempt, as a takeover
/// whose reply H1 never read leaves it, and a witness for s5 then reaches H1's wait. The period's role read finds
/// the restart role and ends `Rerun(RoleChanged)` with the attempt logged refused. The next round's incarnation
/// reads the same role and runs H1's restart of s5, which serves; in the second run H1's bump times out and the
/// restart holds. In both runs H4's boot tenure, which still held the cell, moves to the deposed slots when H1's
/// incarnation takes the cell: it ends `Deposed` at its next record view and counts as a withdrawal.
#[test]
fn a_standby_period_that_ends_at_a_changed_role_runs_its_next_incarnation() {
    let (at, member) = (5, 1);
    let run = |script: Vec<Episode>| {
        let config = Config::host_loss(1);
        let mut draws = Draws::record(config.root);
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        fleet.faults = Faults::new(script, fleet.topology.members.len());
        fleet.alarms.scripted = true;
        let _inline = Inline::set();
        let ran = fleet.play_script_with(draws, |fleet, live, slots| {
            for _ in 0..hosts::TAIL_ROUNDS {
                fleet.turn(live);
            }
            assert_eq!(fleet.cells[at].placement.standby, member);
            let host = fleet.topology.members[member].host;
            let key = Key::Shard(fleet.cells[at].placement.shard);
            let item =
                (fleet.store.0.borrow().current(&key).cloned()).expect("a stored shard record");
            let before = fleet.record_now(at);
            let taken = ShardRecord {
                owner: host,
                standby: None,
                attempts: before.attempts + 1,
                ..before
            };
            let write = Write::Exact {
                expect: item.version,
                value: taken.encode(),
            };
            let committed = Store::write(&mut fleet.store.clone(), &key, &write);
            assert!(matches!(committed, Outcome::Committed(_)));
            let witness = crate::failover::detect::host::Revalidated {
                shard: before.shard,
                target: crate::failover::retire::Target::of(&before),
                until_us: u64::MAX,
            };
            (fleet.nominated).push_back((member, before.active, witness, 0));
            fleet.run_hosts(live, slots)
        });
        let report = ran.expect("a run inside the limits");
        let attempts: Vec<_> = (report.hosts.takeovers.iter())
            .map(|attempt| (attempt.shard, attempt.host, attempt.refused.as_deref()))
            .collect();
        assert_eq!(attempts, [(6, H1, Some("Rerun(RoleChanged)"))]);
        assert_eq!(report.hosts.refused_reruns, 1, "{}", report.summary());
        // H4's boot tenure left through its own `Deposed` exit.
        let exits: Vec<_> = (report.duties.exits.iter())
            .map(|(shard, _, exit, _)| (*shard, exit.clone()))
            .collect();
        assert_eq!(exits, [(6, crate::host::Exit::Deposed)]);
        let withdrawn: Vec<u32> = (report.hosts.withdrawals.iter())
            .map(|&(shard, _)| shard)
            .collect();
        assert_eq!((withdrawn, report.hosts.unwithdrawn), (vec![6], 0));
        let served: Vec<u64> = (report.shards[at].recoveries.iter())
            .map(|recovered| recovered.host.get())
            .collect();
        (served, report.shards[at].blockers.clone())
    };
    let (served, blockers) = run(Vec::new());
    assert_eq!(served, [1005, H1], "H4's boot tenure, then H1's restart");
    assert_eq!(blockers, [] as [&str; 0]);

    let timeout = Episode {
        trigger: Trigger::AtTime(0),
        scope: vec![member],
        action: Action::StoreWrite(Arm::Timeout { commit: false }),
        heal: None,
    };
    let (served, blockers) = run(vec![timeout]);
    assert_eq!(served, [1005], "H1's restart holds at its bump");
    assert_eq!(blockers, ["Bump"]);
}

/// A standby process that ends publishes no `Standby` status after its exit. s5's standby H1 waits and publishes.
/// s5's record is then rewritten to name H1 owner at the next attempt, and a witness for s5 reaches H1's queue: the
/// witness-bearing period's role read finds the restart role and the period ends `Rerun(RoleChanged)`. The status
/// ends with the process, before the host loop runs its next incarnation.
#[test]
fn a_standby_period_with_a_witness_that_ends_the_process_ends_the_standby_status() {
    let (at, member) = (5, 1);
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(Vec::new(), fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let ran = fleet.play_script_with(draws, |fleet, live, slots| {
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        assert_eq!(fleet.cells[at].placement.standby, member);
        assert!(fleet.cells[at].waiting.is_some_and(|(of, ..)| of == member));
        let before = fleet.record_now(at);
        let taken = ShardRecord {
            owner: fleet.topology.members[member].host,
            standby: None,
            attempts: before.attempts + 1,
            ..before
        };
        commit_shard(fleet, &taken);
        let witness = crate::failover::detect::host::Revalidated {
            shard: before.shard,
            target: crate::failover::retire::Target::of(&before),
            until_us: u64::MAX,
        };
        fleet.take_over(live, slots, member, (before.active, witness, 0))?;
        let refused = (fleet.log.takeovers.last()).and_then(|attempt| attempt.refused.clone());
        assert_eq!(refused.as_deref(), Some("Rerun(RoleChanged)"));
        assert!(fleet.refused.contains_key(&(at, member)));
        assert_eq!(fleet.cells[at].waiting, None);
        fleet.run_hosts(live, slots)
    });
    ran.expect("a run inside the limits");
}

/// A takeover's period with its witness makes a role read, and the standby's status follows it. s5's standby H1
/// waits and publishes. s5's record is then bumped by its owner, and a witness that names the earlier target reaches
/// H1's queue: the period reads the bumped record, its takeover refuses the stale witness with no write, and the
/// period ends `Stopped`. The status carries the bumped record's target before the next view period of the waits.
#[test]
fn a_standby_period_with_a_stale_witness_publishes_the_target_its_role_read_returned() {
    use crate::failover::retire::Target;
    let (at, member) = (5, 1);
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(Vec::new(), fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let ran = fleet.play_script_with(draws, |fleet, live, slots| {
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        assert_eq!(fleet.cells[at].placement.standby, member);
        let before = fleet.record_now(at);
        let published = Some((member, Target::of(&before), before.active));
        assert_eq!(fleet.cells[at].waiting, published);
        let bumped = ShardRecord {
            attempts: before.attempts + 1,
            ..before
        };
        commit_shard(fleet, &bumped);
        let witness = crate::failover::detect::host::Revalidated {
            shard: before.shard,
            target: Target::of(&before),
            until_us: u64::MAX,
        };
        fleet.take_over(live, slots, member, (before.active, witness, 0))?;
        let refused = (fleet.log.takeovers.last()).and_then(|attempt| attempt.refused.clone());
        assert_eq!(refused.as_deref(), Some("Stopped"));
        assert_eq!(fleet.record_now(at), bumped);
        let read = Some((member, Target::of(&bumped), bumped.active));
        assert_eq!(fleet.cells[at].waiting, read);
        Ok(())
    });
    ran.expect("a run inside the limits");
}

/// A standby whose takeover acquires a tenure waits no more: its `Standby` status ends as the takeover returns,
/// before the next view period of the waits. s5's standby H1 waits and publishes, and a witness for s5's record
/// reaches its queue; H1's compare-and-swap commits and H1 serves s5.
#[test]
fn a_standby_whose_takeover_acquires_a_tenure_ends_its_standby_status() {
    let (at, member) = (5, 1);
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(Vec::new(), fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let ran = fleet.play_script_with(draws, |fleet, live, slots| {
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        assert_eq!(fleet.cells[at].placement.standby, member);
        assert!(fleet.cells[at].waiting.is_some_and(|(of, ..)| of == member));
        let before = fleet.record_now(at);
        let witness = crate::failover::detect::host::Revalidated {
            shard: before.shard,
            target: crate::failover::retire::Target::of(&before),
            until_us: u64::MAX,
        };
        fleet.take_over(live, slots, member, (before.active, witness, 0))?;
        let taken = fleet.record_now(at);
        assert_eq!(taken.owner, fleet.topology.members[member].host);
        assert_eq!(fleet.cells[at].holder, member);
        assert_eq!(fleet.cells[at].waiting, None);
        Ok(())
    });
    ran.expect("a run inside the limits");
}

/// A fresh activation refused for the first time in a round the run is settled in still gets its retry's turn, and
/// a retry that is refused again holds no run open. s3's volume is lost alone and H0 takes the shard over; H0 is
/// paused from the step after the flip with no heal, so the replacement stays unactivated and the host loop ends
/// past the settle bound. H0 then resumes with its next write armed to time out, and the host loop runs again: the
/// activation's enrollment write times out and ends `Rerun(Unactivated)` in a round every other end condition
/// holds in. With one armed write the retry runs a round later and serves the shard cold. With two, the retry is
/// refused again and the loop ends in that round.
#[test]
fn a_fresh_activation_refused_in_a_settled_round_runs_its_retry_once_before_the_run_ends() {
    let resumed = |timeouts: usize| {
        let mut script = Scenario::LostAlone.episodes(false);
        script.push(Episode {
            trigger: Trigger::When(|fleet| !fleet.store.0.borrow().flips.is_empty()),
            scope: vec![0],
            action: Action::Pause,
            heal: None,
        });
        let config = Config::lost_alone(1);
        let mut draws = Draws::record(config.root);
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        fleet.faults = Faults::new(script, fleet.topology.members.len());
        fleet.alarms.scripted = true;
        let _inline = Inline::set();
        let mut rounds = 0;
        let ran = fleet.play_script_with(draws, |fleet, live, slots| {
            fleet.run_hosts(live, slots)?;
            assert!(fleet.recon.settled && fleet.faults.settled());
            assert_eq!(fleet.fresh_due(), None, "H0 is paused");
            fleet.hosts[0].up = hosts::Up::Running;
            for _ in 0..timeouts {
                (fleet.faults.store.borrow_mut()).arm_write(0, Arm::Timeout { commit: false });
            }
            assert_eq!(fleet.fresh_due(), Some(hosts::FAULTED));
            let from = fleet.round;
            let ran = fleet.run_hosts(live, slots);
            rounds = fleet.round - from;
            ran
        });
        let report = ran.expect("a run inside the limits");
        let blockers = report.shards[hosts::FAULTED].blockers.clone();
        (report.volumes.cold.clone(), blockers, rounds)
    };
    let shard = hosts::FAULTED as u32 + 1;
    let (cold, blockers, _) = resumed(1);
    assert_eq!(cold, [shard], "the retry served the replacement");
    assert_eq!(blockers.last().map(String::as_str), Some("EnrollWrite"));

    let (cold, blockers, rounds) = resumed(2);
    assert_eq!(cold, [] as [u32; 0]);
    assert_eq!(
        blockers[blockers.len() - 2..],
        ["EnrollWrite", "EnrollWrite"]
    );
    assert_eq!(
        rounds, 1,
        "the first refusal's retry ran a round later, and the run ended there"
    );
}

/// A refused rerun of a serving tenure waits, as the rerun did, until each open loss has sent its drawn GETs. s3's
/// boot tenure on H3 names `Rerun(Withdrawn)` and H3's store requests fail from the step that queues its rerun, so
/// the rerun is refused. H4 then crashes, which opens a loss with drawn GETs. Two episodes mark rounds: one fires
/// at the first refused rerun the host loop ran, the other once the open loss has sent every drawn GET. The first
/// refused rerun runs no earlier than that round.
#[test]
fn a_refused_rerun_of_a_serving_tenure_waits_for_an_open_losss_drawn_gets() {
    let config = Config::host_loss(1);
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    let mark = |trigger: Trigger| Episode {
        trigger,
        scope: vec![2],
        action: Action::Store(Arm::Pass),
        heal: None,
    };
    let script = vec![
        Episode {
            trigger: Trigger::When(|fleet| !fleet.reruns.is_empty()),
            scope: vec![3],
            action: Action::Outage,
            heal: Some(12),
        },
        Episode {
            trigger: Trigger::When(|fleet| !fleet.rerun_starts.is_empty()),
            scope: vec![4],
            action: Action::Crash,
            heal: None,
        },
        mark(Trigger::When(|fleet| fleet.log.refused_reruns > 0)),
        mark(Trigger::When(|fleet| {
            let due = |loss: &hosts::Loss| !loss.episode.due.is_empty();
            !fleet.losses.is_empty() && !fleet.losses.iter().any(due)
        })),
    ];
    fleet.faults = Faults::new(script, fleet.topology.members.len());
    fleet.alarms.scripted = true;
    let _inline = Inline::set();
    let ran = fleet.play_script_with(draws, |fleet, live, slots| {
        for _ in 0..hosts::TAIL_ROUNDS {
            fleet.turn(live);
        }
        let serving = live[3].as_mut().expect("the boot tenure");
        serving.duty_exit = Some(crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn));
        fleet.run_hosts(live, slots)
    });
    let report = ran.expect("a run inside the limits");
    let [_, Some(lost), Some(rerun), Some(sent)] = report.hosts.fired[..] else {
        panic!("every episode fires: {:?}", report.hosts.fired);
    };
    assert!(
        lost < sent,
        "the loss's GETs take rounds to send: {lost} and {sent}"
    );
    assert!(
        rerun >= sent,
        "the first refused rerun ran in round {rerun}, the GETs were sent by {sent}"
    );
}

/// A crash that returns in the step it fires in supersedes the rerun queued for the same process. H3 crashes and
/// returns under a store outage of its own requests, so its restart of s3 is refused and rerun each round. In the
/// first step after the outage H3 crashes again and returns at once: the return queues the restart of s3, and the
/// rerun queued for the crashed process is dropped. s3 is restarted once, by the return.
#[test]
fn a_crash_that_returns_at_once_supersedes_the_rerun_queued_for_its_process() {
    const OUTAGE: u64 = 20;
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].scope = vec![3];
    script[0].heal = Some(2);
    script.push(Episode {
        scope: vec![3],
        action: Action::Outage,
        heal: Some(OUTAGE),
        ..script[0].clone()
    });
    script.push(Episode {
        trigger: Trigger::AtTime(OUTAGE),
        scope: vec![3],
        action: Action::Crash,
        heal: Some(0),
    });
    let report = scripted(&Config::host_loss(1), script);
    let s3 = &report.shards[3];
    let hosts: Vec<u64> = (s3.recoveries.iter())
        .map(|recovered| recovered.host.get())
        .collect();
    assert_eq!(
        hosts,
        [H3, H3],
        "the boot tenure and one restart: {}",
        report.summary()
    );
    assert_eq!(report.hosts.rerun_dropped, 1);
    let returned: Vec<_> = (report.zones.restarts.iter())
        .map(|&(shard, host, tenure, _)| (shard, host, tenure))
        .collect();
    assert_eq!(returned, [(4, H3, s3.recoveries[1].tenure)]);
}

/// The standby outage provides the baseline because every boot tenure belongs to another host. Each record view
/// missed during the holder outage accounts for two fewer duty reads.
#[test]
fn a_hosts_store_outage_stops_the_record_views_of_its_boot_tenure() {
    const VIEWS: u64 = 3;
    const OUTAGE: u64 = VIEWS * oracles::VIEW_ROUNDS;
    let outage = |member: usize| {
        let episode = Episode {
            trigger: Trigger::AtTime(0),
            scope: vec![member],
            action: Action::Outage,
            heal: Some(OUTAGE),
        };
        scripted(&Config::host_loss(1), vec![episode])
    };
    let placing = super::topology::Placing::SMALL;
    let (holder, standby) = placing[hosts::DUTY_CELL];
    assert!(placing.iter().all(|&(owner, _)| owner != standby));
    let (held, idle) = (outage(holder), outage(standby));
    for report in [&held, &idle] {
        assert_eq!(report.takeovers, 0, "{}", report.summary());
        assert_eq!(report.duties.exits, [], "{}", report.summary());
    }
    assert_eq!(held.rounds, idle.rounds);
    assert_eq!(held.duties.writes, idle.duties.writes);
    assert_eq!(
        held.duties.reads + 2 * VIEWS,
        idle.duties.reads,
        "duty reads under the holder's outage and under the standby's over {} rounds",
        held.rounds
    );
}

/// Replay over scheduled actors: each round of a host scenario from the hosts' start on records its runnable
/// actors, every running host, every tenure that steps and every running reconciler, as one forced decision at
/// `draws::ACTORS`. The host-loss recording replays to an equal report. Control: the same tape replayed under a
/// script that also crashes H1, which holds no tenure, so its crash opens no loss and draws nothing, is refused with
/// `Candidates` in the round after the crash, before any actor of that round steps. The scheduled case runs the
/// equal replay and the sibling (`actor_replay_siblings_on`): with the actor decision off in the recording and in
/// the replay, the same extra crash replays with no refusal, so the refusal comes from the actor decision and from no
/// other draw. The candidates are those three kinds: a standby's or an unnamed host's wait and the owner processes
/// the host loop runs between rounds (a queued takeover, restart or rerun, a fresh activation) are not among them,
/// so this test shows no refusal for a change in those alone.
#[test]
fn a_tape_recorded_with_another_set_of_runnable_actors_is_refused_before_its_round_steps() {
    let (recorded, played) = actor_tape(1);
    let refused = played(Draws::replay(recorded.tape.clone()), actor_script(), true);
    let Err(Stopped::Choice(refusal)) = refused.map(|report| report.summary()) else {
        panic!("another set of runnable actors replays");
    };
    assert_eq!(refusal.error, crate::sim::choice::ChoiceError::Candidates);
    assert!(refusal.applied < recorded.decisions, "{refusal:?}");
}

/// The host-loss script with a crash of H1, which holds no tenure, at round 5.
fn actor_script() -> Vec<Episode> {
    let mut script = Scenario::HostLoss.episodes(false);
    script.push(Episode {
        trigger: Trigger::AtTime(5),
        scope: vec![1],
        action: Action::Crash,
        heal: None,
    });
    script
}

/// A host-loss run on `root` that plays `script` from `draws`, recording each round's runnable actors when `actors`.
type ActorPlay = Box<dyn Fn(Draws, Vec<Episode>, bool) -> Result<Report, Stopped>>;

/// The host-loss run on `root` with its actor decisions recorded, and the player the replays use.
fn actor_tape(root: u64) -> (Report, ActorPlay) {
    let config = Config::host_loss(root);
    let played: ActorPlay = Box::new(
        move |mut draws: Draws, script: Vec<Episode>, actors: bool| {
            let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
            let mut fleet = seeded.expect("a recorded topology");
            fleet.faults = Faults::new(script, fleet.topology.members.len());
            fleet.alarms.scripted = true;
            fleet.record_actors = actors;
            let _inline = Inline::set();
            fleet.play_script(draws)
        },
    );
    let recorded = played(
        Draws::record(config.root),
        Scenario::HostLoss.episodes(false),
        true,
    );
    let recorded = recorded.expect("a run inside the limits");
    assert!(recorded.actor_turns > 0);
    (recorded, played)
}

/// The actor-replay control's unplanted siblings: the recording replays to an equal digest, and with the actor
/// decision off in the recording and in the replay the extra crash replays with no refusal.
pub(super) fn actor_replay_siblings_on(root: u64) {
    let (recorded, played) = actor_tape(root);
    let replayed = played(
        Draws::replay(recorded.tape.clone()),
        Scenario::HostLoss.episodes(false),
        true,
    );
    assert_eq!(
        replayed.map(|report| report.digest()),
        Ok(recorded.digest())
    );
    let config = Config::host_loss(root);
    let unrecorded = played(
        Draws::record(config.root),
        Scenario::HostLoss.episodes(false),
        false,
    );
    let unrecorded = unrecorded.expect("a run inside the limits");
    assert_eq!(unrecorded.actor_turns, 0);
    let unrefused = played(
        Draws::replay(unrecorded.tape.clone()),
        actor_script(),
        false,
    );
    assert!(
        unrefused.is_ok(),
        "{:?}",
        unrefused.map(|report| report.summary())
    );
}

/// The declared-hold cases' judgment: the silent host is nominated while two declarations stand, so declarations
/// stay out of the self-suspicion count (DECLARED-FRESH), and no detector nominates while three declarations stand
/// (DECLARED-BRAKE). The scheduled case passes these texts to the cases' controls.
pub(super) const DECLARED_COUNTED: &str =
    "two standing declarations and a silent host put the observers in self-suspicion";
pub(super) const DECLARED_UNBRAKED: &str = "a detector nominated while three declarations stood";

/// The rounds since the hosts started at which the declared-hold script's volumes stalled and healed, at which a
/// detector first published a nomination (`ReconLog::first_nomination`), and, when the script crashes a host, at
/// whose start a witness for s5 first waited in its standby's queue and at whose start such a witness first waited
/// while the agents of s3's and s4's owners both read their hosts unhealthy on a hold. The last round lies past
/// twice the stall's length when no witness waited under both declarations before it. A script with no crash
/// records the round at whose start the three stalled shards' owners had all declared (`three_declared`), which
/// lies past twice the stall's length when they never did.
pub(super) struct Declared {
    pub(super) report: Report,
    pub(super) stalled: u64,
    pub(super) healed: u64,
    pub(super) nominated: Option<u64>,
    pub(super) s5_witnessed: Option<u64>,
    pub(super) s5_under_two: Option<u64>,
    pub(super) three_declared: Option<u64>,
}

impl std::fmt::Debug for Declared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            stalled,
            healed,
            nominated,
            s5_witnessed,
            s5_under_two,
            three_declared,
            ..
        } = self;
        write!(
            f,
            "stalled {stalled} healed {healed} nominated {nominated:?} s5 witnessed {s5_witnessed:?} under two declarations {s5_under_two:?} three declared {three_declared:?}: {}",
            self.report.summary()
        )
    }
}

/// Runs `small` under `Config::stall(root)`, with two GETs a loss, under a script that stalls the volumes of the shards
/// at `stalled` (each owner's restart then ends `Exit::Held` and its agent declares its host unhealthy) and crashes
/// the hosts at `crashed`, all once every owner acknowledged its workload. When the script crashes a host (s5's
/// owner, the one crash scripted here), two last episodes with no effect mark rounds: one fires at the first round a
/// witness for s5 waits in its standby's queue, and the other at the first round such a witness waits while the
/// agents of s3's and s4's owners both read their hosts unhealthy on a hold, or once the hosts ran twice the stall's
/// length. A script with no crash (the three-declarations case) marks one round the same way: the first at whose
/// start the agents of s3's, s4's and s5's owners all read their hosts unhealthy on a hold, or once the hosts ran
/// twice the stall's length. Each marker fires in every run of its script. With `defect`, the detector runs with
/// that planted defect of `failover::detect` for the whole run.
///
/// The losses the stalls and the crash open together each owe s2's owner H0 two GETs; a GET past one peer's
/// allowance in flight waits for one to settle (`Fleet::neighbour_gets`), so H0 answers every GET and the untouched
/// check judges them all.
pub(super) fn declared(
    root: u64,
    stalled: &[usize],
    crashed: &[usize],
    defect: Option<&'static str>,
) -> Declared {
    fn up(fleet: &Fleet<'_>) -> bool {
        fleet.booted_all() && fleet.cells.iter().all(|cell| cell.acknowledged)
    }
    fn s5_witnessed(fleet: &Fleet<'_>) -> bool {
        let shard = fleet.cells[5].placement.shard;
        (fleet.nominated.iter()).any(|(_, _, witness, _)| witness.shard == shard)
    }
    // The agents of the owners of the shards at `cells` all read their hosts unhealthy on a hold. The reading is
    // taken at time zero, where the health rule's silent and unreported clauses are off.
    fn declared_by(fleet: &Fleet<'_>, cells: &[usize]) -> bool {
        cells.iter().all(|&at| {
            let agent = fleet.hosts[fleet.cells[at].placement.owner].agent.as_ref();
            agent.is_some_and(|agent| !agent.healthy(0))
        })
    }
    // The hosts ran twice the stall's length. As an alternative of a marker's trigger it lets the episode fire in
    // every run, so the fault script settles.
    fn late(fleet: &Fleet<'_>) -> bool {
        fleet.round - fleet.host_start > 2 * hosts::STALL_ROUNDS
    }
    fn s5_witnessed_under_two(fleet: &Fleet<'_>) -> bool {
        (s5_witnessed(fleet) && declared_by(fleet, &[3, 4])) || late(fleet)
    }
    fn three_declared(fleet: &Fleet<'_>) -> bool {
        declared_by(fleet, &[3, 4, 5]) || late(fleet)
    }
    let mut script: Vec<Episode> = (stalled.iter())
        .map(|&at| Episode {
            trigger: Trigger::When(up),
            scope: Vec::new(),
            action: Action::Stall(at),
            heal: Some(hosts::STALL_ROUNDS),
        })
        .collect();
    if !crashed.is_empty() {
        script.push(Episode {
            trigger: Trigger::When(up),
            scope: crashed.to_vec(),
            action: Action::Crash,
            heal: None,
        });
    }
    let markers: &[fn(&Fleet<'_>) -> bool] = match crashed.is_empty() {
        true => &[three_declared],
        false => &[s5_witnessed, s5_witnessed_under_two],
    };
    for &marker in markers {
        script.push(Episode {
            trigger: Trigger::When(marker),
            scope: Vec::new(),
            action: Action::Delay(Vec::new(), 0),
            heal: Some(0),
        });
    }
    let config = Config::stall(root);
    let run = || scripted_with(&config, script, false);
    let report = match defect {
        Some(defect) => crate::failover::detect::tests::planted(defect, run),
        None => run(),
    };
    let fired = &report.hosts.fired;
    let stalled = fired[0].expect("the stalls fired");
    let last = fired[fired.len() - 1];
    let (s5_witnessed, s5_under_two, three_declared) = match crashed.is_empty() {
        true => (None, None, last),
        false => (fired[fired.len() - 2], last, None),
    };
    Declared {
        healed: stalled + hosts::STALL_ROUNDS,
        stalled,
        nominated: report.recon.first_nomination,
        s5_witnessed,
        s5_under_two,
        three_declared,
        report,
    }
}

/// The owner changes each shard's record history commits, in shard order.
fn shard_owner_changes(report: &Report) -> Vec<u32> {
    (report.evidence.histories.iter())
        .map(|(_, versions)| owner_changes(versions))
        .collect()
}

/// Whether the declared-hold judgment holds for two declarations and a silent host: a witness for the silent owner's
/// shard s5 reaches its standby while both declarations stand, and no observer reports a repair demand. The first
/// round a witness for s5 waits lies between the stall and its heal, and in that round both declared owners' agents
/// read their hosts unhealthy on a hold.
pub(super) fn two_declared_judged(run: &Declared) -> Result<(), &'static str> {
    let early = (run.s5_witnessed).is_some_and(|round| run.stalled < round && round < run.healed);
    let standing = early && run.s5_under_two == run.s5_witnessed;
    match standing && run.report.hosts.repair_demands == 0 {
        true => Ok(()),
        false => Err(DECLARED_COUNTED),
    }
}

/// Whether the brake's judgment holds for three declarations: no nomination is published while all three stand. A
/// first nomination breaks it when it comes at or after the round in which all three owners had declared and before
/// the stall's heal.
pub(super) fn three_declared_judged(run: &Declared) -> Result<(), &'static str> {
    let standing = run.three_declared.zip(run.nominated);
    match standing
        .is_some_and(|(declared, nominated)| declared <= nominated && nominated < run.healed)
    {
        true => Err(DECLARED_UNBRAKED),
        false => Ok(()),
    }
}

/// Two held hosts and a silent one at the agent's threshold of three: on `small`, s3's and s4's volumes stall, so
/// H3's and H2's restarts end `Exit::Held` and both agents declare their hosts unhealthy (s3 and s4 exempt), and H4,
/// s5's owner, crashes. A fresh declaration stays out of the self-suspicion count, so no observer suspects itself
/// and no repair demand is raised: while both declarations stand, the detectors nominate s5's owner, H1 takes s5
/// over and serves it, and H0's takeover of s3 commits and holds at its device step on the stalled volume. s4 keeps
/// its owner on this layout because H4's crash leaves s4's standby H5 with probers in one partition alone (H5's
/// partition holds no other host), not by a rule of the declarations. The control, run by the scheduled case, plants
/// `declared-counts`; under it s5 is taken over only after the stalls heal.
pub(super) fn two_held_hosts_and_a_silent_one_at_a_threshold_of_three_nominate_the_silent_one_on(
    root: u64,
) {
    let run = declared(root, &[3, 4], &[4], None);
    let report = &run.report;
    assert_eq!(two_declared_judged(&run), Ok(()), "{run:?}");
    assert_eq!(report.hosts.exempt, BTreeSet::from([4, 5]));
    assert_eq!(report.hosts.repair_demands, 0);
    assert_eq!(taken(report), [(6, H1)], "H1 takes s5 over and serves it");
    assert_eq!(shard_owner_changes(report), [0, 0, 0, 1, 0, 1]);
    let s3 = (report.hosts.takeovers.iter()).find(|attempt| attempt.shard == 4);
    let s3 = s3.expect("H0's takeover of s3");
    assert_eq!(s3.host, H0);
    assert!(s3.refused.is_some(), "H0's takeover holds: {s3:?}");
    let s3_last = report.evidence.histories[3].1.last().unwrap();
    assert_eq!(s3_last.owner.get(), H0, "H0's compare-and-swap committed");
    held_once_by(report, 4, [H0, H3]);
    let s5 = report.shards[5].recoveries.last().expect("H1's recovery");
    assert_eq!(s5.host.get(), H1);
    assert!(s5.sweep.is_some_and(|(of, served)| of > 0 && of == served));
    passes_its_fleet_checks(report);
    assert_eq!(report.credit(), Verdict::Pass, "{}", report.summary());
}

/// Each start of `shard`'s entry in phase `Held` as its report round and its host, in the order the fleet received
/// the sealed reports. A host whose entry starts twice is listed twice.
fn held_starts(report: &Report, shard: u32) -> Vec<(u64, u64)> {
    let held = (report.hosts.held.iter()).filter(|(.., of)| *of == shard);
    held.map(|(round, host, _)| (*round, *host)).collect()
}

/// Asserts that `shard`'s entry in phase `Held` starts exactly once in the sealed reports of each host of `holders`,
/// both in one report round. `holders` is in member order, the order in which the fleet receives a round's reports:
/// the owner's restart and the standby's takeover both hold before the first report round after the stall, so the
/// reports order the two starts by member alone.
fn held_once_by(report: &Report, shard: u32, holders: [u64; 2]) {
    let starts = held_starts(report, shard);
    let round = starts.first().map_or(0, |(round, _)| *round);
    assert_eq!(
        starts,
        holders.map(|host| (round, host)),
        "the starts of shard {shard}'s Held entry"
    );
}

/// The fleet checks that judge a declared-hold script: one owner per tenure, the volume check, the retained set, the
/// host share and the untouched shards. The stall scenario's credit judges each stalled volume and excuses the shard
/// of a crashed owner, so the two-held case also earns it; the three-declarations case moves no stalled shard and
/// reads the stall scenario's takeover witness missing.
fn passes_its_fleet_checks(report: &Report) {
    let verdicts = &report.verdicts;
    let judged = [
        &verdicts.one_owner,
        &verdicts.keeps_volume,
        &verdicts.retained,
        &verdicts.within_share,
        &verdicts.untouched,
    ];
    assert!(
        judged.iter().all(|verdict| **verdict == Verdict::Pass),
        "{}",
        report.summary()
    );
}

/// The control of the two-held case: with fresh declarations counted toward self-suspicion (`declared-counts`), the
/// two declarations and the silent host reach the threshold, the observers suspect themselves and report repair
/// demands, and no nomination comes while the declarations stand: s3 never moves, and s5 is taken over only after
/// the stalls heal and the held owners recover.
pub(super) fn the_two_held_case_fails_when_declarations_count_on(root: u64, rule: &'static str) {
    assert_eq!(rule, DECLARED_COUNTED);
    let run = declared(root, &[3, 4], &[4], Some("declared-counts"));
    assert_eq!(two_declared_judged(&run), Err(rule), "{run:?}");
    assert!(run.report.hosts.repair_demands > 0);
    assert!(
        run.nominated.is_some_and(|round| round >= run.healed),
        "{run:?}"
    );
    assert_eq!(shard_owner_changes(&run.report)[3], 0, "s3 never moves");
    assert_eq!(taken(&run.report), [(6, H1)], "H1 takes s5 after the heal");
}

/// Three hosts that declare at once: on `small`, s3's, s4's and s5's volumes stall together, so H3, H2 and H4 each
/// hold and declare, and the three declarations brake nominations on declared evidence (DECLARED-BRAKE): no detector
/// publishes a nomination while all three stand, so no takeover starts and no shard changes hands during the stall.
/// After the stall heals, the three held processes rerun and their loads run in the same rounds, so the three
/// declarations end together, no detector nominates any of the three owners after the heal either, and each owner
/// serves its own shard again. The control, run by the scheduled case, plants `unbraked`.
pub(super) fn three_declaring_hosts_nominate_none_on_declared_evidence_on(root: u64) {
    let run = declared(root, &[3, 4, 5], &[], None);
    let report = &run.report;
    assert_eq!(three_declared_judged(&run), Ok(()), "{run:?}");
    assert_eq!(report.hosts.exempt, BTreeSet::from([4, 5, 6]));
    assert_eq!(report.hosts.repair_demands, 0);
    assert_eq!(run.nominated, None, "{run:?}");
    assert_eq!(shard_owner_changes(report), [0, 0, 0, 0, 0, 0]);
    assert!(taken(report).is_empty(), "{:?}", taken(report));
    // Each held owner's rerun after the heal serves its own shard again, warm and whole.
    for at in 3..6 {
        let recoveries = &report.shards[at].recoveries;
        let (boot, rerun) = (recoveries.first().unwrap(), recoveries.last().unwrap());
        assert!(recoveries.len() >= 2, "s{at}: {recoveries:?}");
        assert_eq!(rerun.host, boot.host, "s{at}: {recoveries:?}");
        assert!(
            rerun
                .sweep
                .is_some_and(|(of, served)| of > 0 && of == served),
            "s{at}: {rerun:?}"
        );
    }
    passes_its_fleet_checks(report);
}

/// The control of the three-declarations case: with the brake removed (`unbraked`), the detectors nominate the three
/// declared owners during the stall, and the three takeovers commit and hold on the stalled volumes.
pub(super) fn the_three_declarations_case_fails_without_the_brake_on(
    root: u64,
    rule: &'static str,
) {
    assert_eq!(rule, DECLARED_UNBRAKED);
    let run = declared(root, &[3, 4, 5], &[], Some("unbraked"));
    assert_eq!(three_declared_judged(&run), Err(rule), "{run:?}");
    assert!(run.nominated.is_some_and(|round| round < run.healed));
    assert_eq!(shard_owner_changes(&run.report), [0, 0, 0, 1, 1, 1]);
    assert!(taken(&run.report).is_empty(), "every takeover holds");
    for (shard, holders) in [(4, [H0, H3]), (5, [1003, H5]), (6, [H1, 1005])] {
        held_once_by(&run.report, shard, holders);
    }
}

/// A refused runnable-actor decision steps no actor of its round. One recorded round of the host-loss fleet names
/// every host. The same tape replayed with H1 stopped keeps a `Candidates` refusal, and the round count, the hosts'
/// report count and the standby waits' period count stay as they were before the turn. The tape replayed with every
/// host stopped, a round with no runnable actor, is refused the same way. Sibling: the tape replayed with every host
/// running steps the round, so the round count, the report count and the period count all rise and the three counts
/// can tell a stepped round from a refused one.
#[test]
fn a_refused_runnable_actor_decision_steps_no_actor_of_its_round() {
    let config = Config::host_loss(1);
    let stepped = |fleet: &Fleet<'_>| {
        let periods: usize = fleet.cells.iter().map(|cell| cell.waits.len()).sum();
        (fleet.round, fleet.log.reports, periods)
    };
    let _inline = Inline::set();
    let (mut fleet, draws) = hosted(&config);
    fleet.draws = Some(draws);
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let before = stepped(&fleet);
    fleet.turn(&mut live);
    assert_eq!(fleet.draw_refusal, None);
    assert_eq!(fleet.actor_turns, 1);
    let draws = fleet.draws.take().expect("the round's decisions");
    let tape = draws.finish().expect("a recorded tape");

    let replayed = |stopped: &[usize]| {
        let mut draws = Draws::replay(tape.clone());
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("the recorded topology");
        fleet.start_hosts();
        for &member in stopped {
            fleet.hosts[member].up = hosts::Up::Down;
        }
        fleet.draws = Some(draws);
        let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
        assert_eq!(stepped(&fleet), before);
        fleet.turn(&mut live);
        (
            fleet.draw_refusal.map(|refusal| refusal.error),
            stepped(&fleet),
        )
    };
    let candidates = Some(crate::sim::choice::ChoiceError::Candidates);
    let every: Vec<usize> = (0..config.shape.hosts as usize).collect();
    for stopped in [&[1][..], &every[..]] {
        let (refusal, after) = replayed(stopped);
        assert_eq!(refusal, candidates, "hosts {stopped:?} stopped");
        assert_eq!(after, before, "a refused round stepped an actor");
    }

    let (refusal, after) = replayed(&[]);
    assert_eq!(refusal, None);
    assert_eq!(after.0, before.0 + 1);
    assert!(after.1 > before.1 && after.2 > before.2, "{after:?}");
}

/// Each kind of runnable actor is a candidate of the round's decision. A booted reconciler fleet records one round,
/// whose decision names its hosts, its boot tenures and its reconciler. With every host running, the tape replayed
/// with s3's boot tenure out of its slot is refused with `Candidates`, and so is the tape replayed with the
/// reconciler down; each refused round leaves the round count and the reconcilers' call count as they were. Sibling:
/// the unaltered replay is refused nowhere and steps the round.
#[test]
fn a_replay_whose_round_lacks_one_tenure_or_one_reconciler_is_refused_with_every_host_running() {
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Lacks {
        Nothing,
        Tenure,
        Reconciler,
    }
    let config = Config::settle(1);
    let round = |draws: Draws, lacks: Lacks| {
        let mut draws = draws;
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        fleet.faults = Faults::new(Vec::new(), fleet.topology.members.len());
        fleet.alarms.scripted = true;
        let _inline = Inline::set();
        let mut seen = None;
        let ran = fleet.play_script_with(draws, |fleet, live, _| {
            let running = (fleet.hosts.iter()).all(|host| host.up == hosts::Up::Running);
            assert!(running && live[3].is_some() && !fleet.reconcilers.is_empty());
            // The tenure taken out of its slot stays alive until the round ends.
            let _held = match lacks {
                Lacks::Tenure => live[3].take(),
                Lacks::Reconciler => {
                    fleet.reconcilers[0].status = reconcile::Status::Down { until: u64::MAX };
                    None
                }
                Lacks::Nothing => None,
            };
            let before = (fleet.round, fleet.recon.calls);
            fleet.turn(live);
            let refusal = fleet.draw_refusal.take().map(|refusal| refusal.error);
            seen = Some((refusal, before, (fleet.round, fleet.recon.calls)));
            Ok(())
        });
        (seen.expect("the round ran"), ran.map(|report| report.tape))
    };
    let ((refusal, before, after), tape) = round(Draws::record(config.root), Lacks::Nothing);
    assert_eq!(refusal, None);
    assert!(after.0 == before.0 + 1 && after.1 > before.1, "{after:?}");
    let tape = tape.expect("a recorded round");

    for lacks in [Lacks::Tenure, Lacks::Reconciler] {
        let ((refusal, before, after), _) = round(Draws::replay(tape.clone()), lacks);
        let candidates = Some(crate::sim::choice::ChoiceError::Candidates);
        assert_eq!(refusal, candidates, "{lacks:?}");
        assert_eq!(after, before, "{lacks:?}: a refused round stepped an actor");
    }
    let ((refusal, before, after), replayed) = round(Draws::replay(tape.clone()), Lacks::Nothing);
    assert_eq!(refusal, None);
    assert!(after.0 == before.0 + 1 && after.1 > before.1, "{after:?}");
    assert_eq!(replayed.ok(), Some(tape));
}

/// A held entry the fleet publishes carries the hold's real age and attempt count. On the host-loss layout, H3's
/// restart of s3 holds at round 10 and its next incarnation holds again at round 25 on an unknown bump. The hold the
/// agent's status and headroom read then counts two attempts, and at round 40 its age is the 15 rounds since the
/// second incarnation started, in the held entry H3's status publishes as in the hold its headroom counts. A hold of
/// another member starts its own count of one.
#[test]
fn a_hold_of_several_incarnations_publishes_its_age_and_its_attempt_count() {
    use crate::failover::report::RecoveryRefusal;
    use crate::failover::restart::{Check, Refused};
    use crate::storage::store::StoreError;
    const S3: usize = 3;
    let config = Config::host_loss(1);
    let (mut fleet, _) = hosted(&config);
    let target = crate::failover::retire::Target::of(&fleet.record_now(S3));
    let refusal = RecoveryRefusal::from(&Refused {
        check: Check::Bump(StoreError::Unknown),
        flip: None,
        recovery: Some(target),
    });
    let h3 = (fleet.member_of(Host::new(H3).unwrap())).expect("H3's member");
    let h0 = (fleet.member_of(Host::new(H0).unwrap())).expect("H0's member");
    for round in [10, 25] {
        fleet.round = round;
        fleet.held(S3, h3, super::volumes::Held::of_restart(Some(refusal)));
    }
    fleet.round = 40;
    let live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let now = fleet.detector_now();
    let (at, held, _) = fleet.holds(&live, h3).next().expect("H3's hold");
    let recovery = held.status().recovery(now);
    assert_eq!(at, S3);
    assert_eq!(recovery.attempts, Some(2), "two incarnations held");
    assert_eq!(
        recovery.age_us,
        Some(15 * ROUND_US),
        "aged from the second start"
    );
    assert_eq!(fleet.headroom(&live, h3).recovery, Gauge::known(1, 1));
    let statuses = fleet.statuses(&live, h3, now);
    let held_entry = (statuses.iter()).find(|status| status.shard.get() == 4);
    let published = (held_entry.and_then(|status| status.entry.as_ref()))
        .expect("H3 publishes s3's held entry")
        .recovery;
    assert_eq!(
        (published.attempts, published.age_us),
        (Some(2), Some(15 * ROUND_US))
    );
    fleet.held(S3, h0, super::volumes::Held::of_restart(Some(refusal)));
    let (_, other, _) = fleet.holds(&live, h0).next().expect("H0's hold");
    assert_eq!(other.status().recovery(now).attempts, Some(1));
}

/// A hold the store caused, with the device up, turns the owner's host unhealthy and its named standby takes the
/// shard over, as the host health rule has it. On the host-loss layout H3 crashes and returns two rounds later, and
/// its restart of s3 meets a bump whose reply is unknown with no commit, so the restart ends `Exit::Held` with the
/// `Bump` check. The fleet records the hold and H3's status publishes s3's entry in phase `Held`; s3's record names
/// H0 standby in another partition, so H3's agent reads its host unhealthy with s3 exempt, a detector nominates H3
/// for s3, and H0 takes s3 over and sweeps its retained set whole, with one owner per tenure.
#[test]
fn a_store_caused_hold_turns_the_owners_host_unhealthy_and_its_named_standby_takes_over() {
    let mut script = h3_crash_and_return();
    script.push(Episode {
        scope: vec![3],
        action: Action::StoreWrite(Arm::Timeout { commit: false }),
        heal: None,
        ..script[0].clone()
    });
    let report = scripted(&Config::host_loss(1), script);
    let s3 = &report.shards[3];
    assert_eq!(s3.blockers, ["Bump"], "the restart held on its bump");
    assert_eq!(
        held_starts(&report, 4),
        [(2, H3)],
        "{:?}",
        report.hosts.held
    );
    assert_eq!(report.hosts.exempt, BTreeSet::from([4]));
    assert!(report.hosts.nominations >= 1);
    assert_eq!(taken(&report), [(4, H0)], "H0 takes s3 over");
    let last = s3.recoveries.last().expect("H0's recovery");
    assert_eq!(last.host.get(), H0);
    assert!(
        last.sweep
            .is_some_and(|(of, served)| of > 0 && of == served)
    );
    assert_eq!(
        report.verdicts.one_owner,
        Verdict::Pass,
        "{}",
        report.summary()
    );
}

/// The settle fleet with its hosts started and s0's standby, host 3, removed from the volume record's pairs, so
/// that host's unnamed wait is due.
fn unenrolled(config: &Config) -> Fleet<'_> {
    let (fleet, _draws) = hosted(config);
    let standby = (fleet.record_now(0).standby).and_then(|host| fleet.member_of(host));
    assert_eq!(standby, Some(3));
    let mut volume = fleet.volume_now(0);
    let host = fleet.topology.members[3].host;
    volume.pairs.retain(|recorded| recorded.host != host);
    commit(&fleet, Key::Volume(volume.volume), volume.encode());
    fleet
}

/// An unnamed host's enrollment client reads under the host's watermark log. A view period whose shard read returns
/// the version before the one the host's log holds withdraws that client, and the period fails the run by name.
#[test]
#[should_panic(expected = "host 3's enrollment client of s0 was withdrawn")]
fn an_unnamed_period_whose_shard_read_regresses_fails_the_run_by_name() {
    let config = Config::settle(1);
    let mut fleet = unenrolled(&config);
    let read = fleet.record_now(0);
    let bumped = ShardRecord {
        attempts: read.attempts + 1,
        ..read
    };
    commit_shard(&fleet, &bumped);
    fleet.read_record(3, 0);
    let (volume_read, shard_read) = (Arm::Pass, Arm::StaleRead);
    for arm in [volume_read, shard_read] {
        fleet.faults.store.borrow_mut().arm(3, arm);
    }
    fleet.unnamed_waits();
}

/// A shard record version above the host's watermark that fails to decode gives the period's role read a codec
/// error, which leaves the enrollment client in service. The period judges each record its reads returned, and the
/// returned version fails the run.
#[test]
#[should_panic(
    expected = "host 3's view period of s0 read values the layer cannot decode under their keys"
)]
fn an_unnamed_period_over_a_shard_record_that_fails_to_decode_fails_the_run() {
    let config = Config::settle(1);
    let mut fleet = unenrolled(&config);
    let shard = fleet.record_now(0).shard;
    commit(&fleet, Key::Shard(shard), vec![0; 4]);
    fleet.unnamed_waits();
}

/// A shard record stored under another shard's key gives the period's role read the same codec error. The period
/// compares the key each returned record names with the key it was read under, and the mismatch fails the run.
#[test]
#[should_panic(
    expected = "host 3's view period of s0 read values the layer cannot decode under their keys"
)]
fn an_unnamed_period_over_a_shard_record_that_names_another_shard_fails_the_run() {
    let config = Config::settle(1);
    let mut fleet = unenrolled(&config);
    let shard = fleet.record_now(0).shard;
    let other = fleet.record_now(1);
    assert_ne!(other.shard, shard);
    commit(&fleet, Key::Shard(shard), other.encode());
    fleet.unnamed_waits();
}

/// A stale shard read returns a version above the host's watermark that fails to decode, while the store's current
/// version decodes. The period judges the returned version, which fails the run.
#[test]
#[should_panic(
    expected = "host 3's view period of s0 read values the layer cannot decode under their keys"
)]
fn an_unnamed_period_whose_stale_read_returns_a_record_that_fails_to_decode_fails_the_run() {
    let config = Config::settle(1);
    let mut fleet = unenrolled(&config);
    let read = fleet.record_now(0);
    commit(&fleet, Key::Shard(read.shard), vec![0; 4]);
    commit_shard(&fleet, &read);
    let (volume_read, shard_read) = (Arm::Pass, Arm::StaleRead);
    for arm in [volume_read, shard_read] {
        fleet.faults.store.borrow_mut().arm(3, arm);
    }
    fleet.unnamed_waits();
}

/// The period's enrollment reads coverage page 0 once the role read's records admit the host. A page version that
/// fails to decode gives that read a codec error, which leaves the enrollment client in service, and the returned
/// page fails the run.
#[test]
#[should_panic(
    expected = "host 3's view period of s0 read values the layer cannot decode under their keys"
)]
fn an_unnamed_period_over_a_coverage_page_that_fails_to_decode_fails_the_run() {
    let config = Config::settle(1);
    let mut fleet = unenrolled(&config);
    let shard = fleet.record_now(0).shard;
    commit(&fleet, Key::Page(shard, 0), vec![0; 4]);
    fleet.unnamed_waits();
}

/// One restart of cell 3 by its seeded owner on a started host-loss fleet, stepped by hand: `Fleet::restart_by`
/// queues the tenure's rise, and each pass steps the rises and then takes one fleet turn, as the host loop does.
/// `waits` are the fleet's wait during the bootstrap and from the session's opening on. `unwatched` are the turns
/// taken with no look at the rises, before the first look and after the look that opened the session, as a look
/// that waits behind another recovery's sweep. Returns the turns taken until the bootstrap's end was seen and
/// until the rise ended, or the stall that stopped the run.
fn rise_turns(waits: (u32, u32), unwatched: (u32, u32)) -> Result<(u32, u32), Stopped> {
    let config = Config::host_loss(1);
    let _inline = Inline::set();
    let (mut fleet, draws) = hosted(&config);
    fleet.draws = Some(draws);
    fleet.wait = waits.0;
    let at = 3;
    let member = fleet.cells[at].placement.owner;
    let grounds = [Grounds::over(storage_shared(1, fleet.share_on(member)))];
    let pools = [Pools::new(&grounds[0])];
    let mut slots = Slots {
        grounds: &grounds,
        pools: &pools,
        members: vec![member],
        used: vec![false],
    };
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    assert!(!fleet.serves_own(&live, member));
    let restarted = fleet.restart_by(&mut live, &mut slots, (at, false, false), member);
    assert!(matches!(restarted, Ok(super::volumes::Restarted::Rising)));
    assert_eq!(fleet.rises.len(), 1);
    let (mut turns, mut booted) = (0, None);
    for _ in 0..unwatched.0 {
        fleet.turn(&mut live);
        turns += 1;
    }
    loop {
        fleet.step_rises(&mut live)?;
        let Some(rise) = fleet.rises.first() else {
            assert!(fleet.serves_own(&live, member), "a tenure whose rise ended");
            return Ok((booted.expect("a bootstrap that ended"), turns));
        };
        // A tenure whose bring-up is in progress serves nothing yet.
        assert!(
            !fleet.serves_own(&live, member),
            "a rising tenure read as serving after {turns} turns"
        );
        let skipped = if rise.opened && booted.is_none() {
            booted = Some(turns);
            fleet.wait = waits.1;
            unwatched.1
        } else {
            0
        };
        for _ in 0..=skipped {
            fleet.turn(&mut live);
            turns += 1;
        }
    }
}

/// A rise's phase stops at the configured wait as a synchronous bring-up's does (`Fleet::turns_while`): the phase
/// may take `Fleet::wait` turns, and a phase still pending after that many stalls the run. The restart's bootstrap
/// takes a fixed count of turns: under a wait of one turn less it stalls by name.
#[test]
fn a_rise_whose_phase_is_pending_after_the_configured_wait_stalls_as_a_synchronous_bring_up_does() {
    let wait = WAIT_ROUNDS;
    let (booted, _) = rise_turns((wait, wait), (0, 0)).expect("a rise inside the default wait");
    assert!(booted > 1, "{booted}");
    let Err(Stopped::Stalled(stall)) = rise_turns((booted - 1, wait), (0, 0)) else {
        panic!(
            "a bootstrap of {booted} turns ended under a wait of {}",
            booted - 1
        );
    };
    assert_eq!((stall.waited, stall.shard), ("the bootstrap", Some(4)));
}

/// A phase that ends after its wait stalls the run also when the host loop looks at the rise later, as it does
/// behind another recovery's sweep: the fleet keeps the round each phase ended in. A phase that ended inside its
/// wait passes however late the look. Both hold for the bootstrap and for the client session.
#[test]
fn a_phase_that_ended_after_its_wait_stalls_however_late_the_host_loop_looks() {
    let wait = WAIT_ROUNDS;
    let (booted, ended) = rise_turns((wait, wait), (0, 0)).expect("a rise inside the default wait");
    let session = ended - booted;
    assert!(session > 1, "{session}");
    // The bootstrap ends at its last allowed turn and is looked at five turns later; the session becomes active
    // inside a wait of eight turns, which also covers the sweep's GETs, and is looked at five turns after that wait.
    let late_looks = rise_turns((booted, 8), (booted + 5, 8 + 5));
    assert!(late_looks.is_ok(), "{late_looks:?}");
    // The bootstrap ends one turn after its wait, with no look until it has ended.
    let Err(Stopped::Stalled(stall)) = rise_turns((booted - 1, wait), (booted, 0)) else {
        panic!(
            "a bootstrap of {booted} turns ended under a wait of {}",
            booted - 1
        );
    };
    assert_eq!(stall.waited, "the bootstrap");
    // The session becomes active one turn after its wait, with no look until it is active.
    let Err(Stopped::Stalled(stall)) = rise_turns((wait, session - 1), (0, session)) else {
        panic!(
            "a session of {session} turns ended under a wait of {}",
            session - 1
        );
    };
    assert_eq!(stall.waited, "the client session");
}

/// `overlapped` counts a takeover load that starts while another takeover load of the same member is in progress,
/// by the member that started each rise. A restart's load beside a takeover's, and a takeover load of a cell that
/// another member has since taken, are no two takeover loads of one host.
#[test]
fn the_overlap_count_needs_two_takeover_loads_started_by_one_member() {
    use super::owners::Then;
    let config = Config::host_loss(1);
    let tenure = |a| Tenure { g: 1, a };
    let take = |member| Then::TakeOver {
        member,
        lost_at: 0,
        lineage: false,
    };
    let queued = |rises: &[(usize, usize, Then)]| {
        let (mut fleet, _draws) = hosted(&config);
        let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
        for (n, &(at, member, then)) in rises.iter().enumerate() {
            // The caller of `queue_rise` sets the cell's holder first, as `take_over` and `restart_by` do.
            fleet.cells[at].holder = member;
            let rise = (Some(tenure(10 + n as u64)), Source::Named);
            fleet
                .queue_rise(&mut live, at, rise, then)
                .expect("a queued rise");
        }
        fleet.log.overlapped
    };
    assert_eq!(queued(&[(0, 3, take(3)), (1, 3, take(3))]), 1);
    let restart = Then::Restart {
        member: 3,
        lost_at: 0,
        after_loss: true,
        lineage: false,
        from: 0,
        returned: false,
    };
    assert_eq!(
        queued(&[(0, 3, restart), (1, 3, take(3))]),
        0,
        "a restart's load beside a takeover's"
    );
    // Member 5 takes cell 0 while member 3's takeover load of it is still listed.
    assert_eq!(
        queued(&[(0, 3, take(3)), (0, 5, take(5))]),
        0,
        "a load of a cell another member has since taken"
    );
}

/// A recovery's rounds end when its client session becomes active, also when the host loop accounts for it later:
/// on the host loss of root 1, H3's two takeover loads and H5's start in one round and their sessions become
/// active together, so the three report the same rounds. A recovery accounted behind another's sweep of eight GETs
/// would read 32 rounds more for each sweep ahead of it.
#[test]
fn overlapping_takeover_loads_report_the_rounds_until_their_own_sessions_became_active() {
    let report = passing(&Config::host_loss(1));
    assert_eq!(taken(&report), [(1, H3), (2, H3), (3, H5)]);
    assert_eq!(report.hosts.overlapped, 1);
    let rounds = [0, 1, 2].map(|at| report.shards[at].recoveries.last().unwrap().rounds);
    assert_eq!(rounds, [22, 22, 22], "{}", report.summary());
}
