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
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.start_hosts();
    (fleet, draws)
}

/// Runs `config`'s fleet under `script` in place of its scenario's episodes.
fn scripted(config: &Config, script: Vec<Episode>) -> Report {
    scripted_with(config, script, false)
}

/// [`scripted`], with a held process's due rerun ordered ahead of a queued takeover when `rerun_first`.
pub(super) fn scripted_with(config: &Config, script: Vec<Episode>, rerun_first: bool) -> Report {
    let mut draws = Draws::record(config.root);
    let seeded = Fleet::seeded(config, &mut draws, WAIT_ROUNDS);
    let mut fleet = seeded.expect("a recorded topology");
    fleet.faults = Faults::new(script, fleet.topology.members.len());
    fleet.rerun_first = rerun_first;
    let _inline = Inline::set();
    fleet.play_script(draws).expect("a run inside the limits")
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
        let headroom = fleet.headroom(&live, member, 0);
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

#[test]
fn a_host_lost_in_several_roles_hands_its_shards_to_their_named_standbys_warm_on_two_roots() {
    for root in [1, 2] {
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
/// period, while the record still names H0 owner. The fencer's connect records that record, and the assertion the
/// period makes once `host::stand_by` returns, the one that judges every takeover, panics.
#[test]
#[should_panic(expected = "the first device call follows the committed takeover")]
fn a_device_command_before_the_takeover_write_fails_the_standby_periods_assertion() {
    let _ = run(&Config::host_loss(1).hostile(Plant::EarlyDevice, 0));
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
    let store = super::tests::Unwinding(fleet.store.clone());
    let log = fleet.hosts[member].log.clone();
    let mut client =
        crate::storage::store::Client::open(store, log).expect("a host's store client");
    let persist = |_| Ok(local.0.clone().expect("the standby's local record"));
    let _ = owners::stand_by(
        (cell, fleet.topology.members[member], pair),
        (fleet.round, &fleet.store),
        &grounds,
        (&mut client, &local),
        (Some((witness, 0)), false),
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
    let mut forged = sealed(H0);
    *forged.last_mut().unwrap() ^= 1;
    let at = fleet.round;
    fleet.hosts[3].inbox.push((at, forged));
    assert_eq!(round(&mut fleet), 1, "a heartbeat whose tag fails");

    let unplaced = H5 + 1;
    assert!(fleet.member_of(host(unplaced)).is_none());
    let at = fleet.round;
    fleet.hosts[3].inbox.push((at, sealed(unplaced)));
    assert_eq!(round(&mut fleet), 2, "a sender the zone does not place");
    assert_eq!(round(&mut fleet), 2);
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

#[test]
fn host_loss_controls_fail_one_owner_by_a_twin_start_and_a_moved_activation() {
    let config = Config::host_loss(1);
    let evidence = passing(&config).evidence;
    let unaltered = oracles::one_owner(&evidence.histories, &evidence.activations);
    assert_eq!(unaltered, Verdict::Pass);

    let twin = hostile(config, Plant::TwinStart, 0);
    assert_eq!(twin.hosts.twin_started, 1);
    let rule = twin.verdicts.one_owner.rule();
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

#[test]
fn host_loss_controls_fail_the_host_share_by_its_roles_and_by_its_reads() {
    let config = Config::host_loss(1);
    assert_eq!(passing(&config).verdicts.within_share, Verdict::Pass);
    let whole = hostile(config, Plant::WholeShare, 3);
    let rule = whole.verdicts.within_share.rule();
    let roles = "a host's roles exceed the owners its recovery share divides over";
    assert_eq!(rule, Some(roles));
    let uncharged = hostile(config, Plant::UnchargedRead, 3);
    let rule = uncharged.verdicts.within_share.rule();
    assert_eq!(rule, Some("a host's recovery reads passed twice its share"));
}

#[test]
fn host_loss_controls_fail_retention_and_untouched_shards_and_a_removed_crash_reads_unrun() {
    let config = Config::host_loss(1);
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

#[test]
fn a_host_loss_replays_its_recording_and_an_extra_arrival_moves_no_other_decision() {
    let config = Config::host_loss(3);
    let report = passing(&config);
    assert_eq!(run(&config).as_ref(), Ok(&report));
    let replayed = replay(&config, &report.recording()).expect("the recording replays");
    assert_eq!((&replayed, replayed.digest()), (&report, report.digest()));

    let mut fuller = config;
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
    let edits: [(&str, Edit); 30] = [
        ("nominations", |log| log.nominations += 1),
        ("addressed", |log| log.addressed += 1),
        ("unmatched probes", |log| log.unmatched_probes += 1),
        ("vetoes", |log| log.vetoes += 1),
        ("contested", |log| log.contested += 1),
        ("repair demands", |log| log.repair_demands += 1),
        ("host losses", |log| log.host_losses += 1),
        ("lapsed", |log| log.lapsed += 1),
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
    assert_eq!(
        page.duties.exits,
        [(shard, faulted.tenure, withdrawn.clone())]
    );
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
    assert_eq!(record.duties.exits, [(shard, faulted.tenure, withdrawn)]);
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

/// Controls of the untouched-shard rule's exact form: one extra read of s4's shard record
/// through its duties' store during H0's loss fails it by the reads rule, and one rewrite of that record by the
/// writes rule; the unplanted run passes.
#[test]
fn untouched_shard_controls_fail_by_one_extra_read_and_one_duty_write() {
    let reads = "an untouched shard's reads were other than one volume-record and one shard-record read a view period";
    let write = "an untouched shard's serving duties wrote its records";
    let at = hosts::DUTY_CELL as u32;
    let read = hostile(Config::host_loss(1), Plant::ExtraRead, at);
    assert_eq!(
        read.verdicts.untouched.rule(),
        Some(reads),
        "{}",
        read.summary()
    );
    let wrote = hostile(Config::host_loss(1), Plant::DutyRewrite, at);
    assert_eq!(
        wrote.verdicts.untouched.rule(),
        Some(write),
        "{}",
        wrote.summary()
    );
    assert_eq!(
        passing(&Config::host_loss(1)).verdicts.untouched,
        Verdict::Pass
    );
    // A plant index past the last cell plants nothing, a deposed tenure's slot of the live table included.
    for plant in [Plant::ExtraRead, Plant::DutyRewrite] {
        let past = run(&Config::owner_pause(1).hostile(plant, 6)).expect("a run inside the limits");
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
        report.duties.exits.push((at, tenure, unwound.clone()));
        report.credit()
    };
    let host_loss = passing(&Config::host_loss(1));
    assert_eq!(exited(&host_loss, 5).rule(), Some(hosts::DUTY_EXIT));
    let restarts = super::tests::passing(&Config::six(1));
    assert_eq!(exited(&restarts, 2).rule(), Some(hosts::DUTY_EXIT));
    let mut superseded = host_loss.clone();
    let earlier = Tenure { g: 1, a: 0 };
    superseded.duties.exits.push((1, earlier, unwound.clone()));
    assert_eq!(
        superseded.credit().rule(),
        Some(hosts::DUTY_EXIT),
        "a superseded tenure's unwind"
    );
    let mut deposed = host_loss.clone();
    deposed
        .duties
        .exits
        .push((1, earlier, crate::host::Exit::Deposed));
    assert_eq!(
        deposed.credit(),
        Verdict::Pass,
        "a superseded tenure's deposition"
    );
    let page = store_killed(&Config::page_regressed(1));
    assert_eq!(hosts::unscripted_exit(&page), None);
    let mut other = page.clone();
    let faulted = other.duties.faulted.as_ref().unwrap().tenure;
    let withdrawn = crate::host::Exit::Rerun(crate::host::Rerun::Withdrawn);
    other.duties.exits.push((6, faulted, withdrawn));
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

/// A restart whose incarnation ends with an exit that names a rerun runs again: H3, the owner of s3 alone, crashes
/// and returns two rounds later, before a suspicion, under a store outage of its own requests. Each restart's role
/// read fails, which ends the incarnation `Rerun::Records`, and the host loop runs the next incarnation from the
/// round after, as the process's supervisor starts it. Once the outage heals, the next incarnation restarts s3 warm
/// on H3, and no takeover starts. That incarnation completes H3's return as a restart that served at once does: the
/// zone log records the restart at its tenure, and the tenure acknowledges its FILL and its INVALIDATE.
#[test]
fn a_restart_that_ends_in_a_rerun_exit_runs_again_and_serves_after_the_outage() {
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].scope = vec![3];
    script[0].heal = Some(2);
    script.push(Episode {
        scope: vec![3],
        action: Action::Outage,
        heal: Some(20),
        ..script[0].clone()
    });
    let report = scripted(&Config::host_loss(1), script);
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

/// A restart whose bump's reply is unknown ends `Exit::Held`, and the process publishes the `Held` status with its
/// refusal's class in a host scenario with no reconciler too: H3 crashes and returns two rounds later, before a
/// suspicion, and its restart's bump of s3 times out with no commit. H3's host reads itself unhealthy (s3 exempt),
/// since s3's record names H0 standby elsewhere. `Held::status` builds the recovery of the published entry, and the
/// case reads it three ways: its check names the bump, H3's accepted report carries s3's entry in phase `Held`, and its
/// next step holds H3's recovery slot in H3's last sealed report.
#[test]
fn a_held_restart_publishes_its_held_status_in_a_host_scenario() {
    let mut script = Scenario::HostLoss.episodes(false);
    script[0].scope = vec![3];
    script[0].heal = Some(2);
    script.push(Episode {
        scope: vec![3],
        action: Action::StoreWrite(Arm::Timeout { commit: false }),
        heal: None,
        ..script[0].clone()
    });
    let report = scripted(&Config::host_loss(1), script);
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
    let restarted = fleet.restart_by(&mut live, &mut slots, (at, true), member);
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

/// A returned host's restart that holds queues no next incarnation, so the return reads as still to run
/// (`Fleet::returning`) only from the round the hold's rerun is queued. H3's restart of s3 after its return holds at
/// a bump that times out; the rerun then completes the return.
#[test]
fn a_returned_host_s_held_restart_reads_as_returning_once_its_rerun_is_queued() {
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
    let restarted = fleet.restart_by(&mut live, &mut slots, (at, true), member);
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
    let restarted = fleet.restart_by(&mut live, &mut slots, (at, true), member);
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
            .map(|(shard, _, exit)| (*shard, exit.clone()))
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
