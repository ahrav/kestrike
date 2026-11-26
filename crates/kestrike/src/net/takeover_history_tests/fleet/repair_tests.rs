use std::collections::BTreeSet;

use super::hosts;
use super::oracles;
use super::reconcile::{self, CrashCell, Reclaim, Refused, Repair};
use super::*;
use crate::failover::retire::Target;
use crate::failover::standbys::Need;
use crate::failover::zone_loop::actuate::{Reason, Verdict as StepVerdict};
use crate::failover::zone_loop::plan::Step;
use crate::failover::zone_loop::status::Blocker;

/// A reservation step of shard 1 by host 2 that the census refused with `refusal`.
fn reserve(refusal: crate::failover::standbys::Refusal) -> Refused {
    let target = Target {
        generation: crate::net::ownership::ShardGeneration::new(1).unwrap(),
        owner: crate::failover::sim::host(1),
        attempts: 1,
    };
    let step = Step::Reserve {
        shard: crate::net::ownership::Shard::new(1).unwrap(),
        host: crate::failover::sim::host(2),
        target,
    };
    Refused::Step(step, StepVerdict::Wait(Reason::Population(refusal)))
}

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

fn last_records(report: &Report) -> Vec<ShardRecord> {
    let histories = report.evidence.histories.iter();
    histories
        .map(|(_, versions)| *versions.last().unwrap())
        .collect()
}

/// The hosts that versions of the shard's record named standby under an unchanged owner, in version order: one entry
/// per designation write.
fn designated(report: &Report, shard: u32) -> Vec<u64> {
    let (_, versions) = &report.evidence.histories[shard as usize - 1];
    let changed = versions
        .windows(2)
        .filter(|pair| pair[0].owner == pair[1].owner && pair[0].standby != pair[1].standby);
    changed
        .filter_map(|pair| pair[1].standby.map(|host| host.get()))
        .collect()
}

fn blocked(report: &Report, shard: u32) -> Option<Blocker> {
    let mut settled = report.evidence.settled.iter();
    settled
        .find(|settled| settled.shard.get() == shard)
        .and_then(|settled| settled.blocker)
}

/// With no fault, the loop's first survey after warm-up finds each named standby in the boot census, the settle phase
/// finds every shard served with an enrolled standby the census lists, and the loop makes no store write and no
/// mutating call from then on (LOOP-FIXPOINT).
#[test]
fn the_boot_survey_lists_every_named_standby_and_the_fleet_settles_with_six_census_entries() {
    the_boot_survey_lists_every_named_standby_and_the_fleet_settles_with_six_census_entries_on(1);
}

fn the_boot_survey_lists_every_named_standby_and_the_fleet_settles_with_six_census_entries_on(
    root: u64,
) {
    let report = passing(&Config::settle(root));
    assert_eq!(report.evidence.censuses, [6]);
    assert!(report.recon.designations.is_empty());
    assert!(report.evidence.settled.iter().all(|settled| settled.served));
    assert!(report.recon.settle.and_then(|phase| phase.turns).is_some());
    assert_eq!(report.recon.after_settle, Some((0, 0)));
    assert!(report.recon.calls > 0);
    for shard in 1..=6 {
        assert_eq!(designated(&report, shard), Vec::<u64>::new());
    }
    // The loop observes the zone host hold only before the hosts' first sealed reports arrive.
    assert!(!report.recon.zone_held_rounds.is_empty());
    assert!(
        (report.recon.zone_held_rounds.iter()).all(|&round| round < hosts::REPORT_ROUNDS),
        "a hold after the first reports: {:?}",
        report.recon.zone_held_rounds
    );
}

/// Control: one census write through loop 0's store once the fixpoint count started fails LOOP-FIXPOINT by its rule
/// text, and the quiet sibling passes over its counted ticks; a run whose count covers fewer ticks reads the
/// witness unrun.
#[test]
fn a_store_write_of_a_settled_zone_fails_the_fixpoint_rule_and_the_quiet_sibling_passes() {
    let fixpoint = "a settled zone's loop made a store write or a mutating call";
    let quiet = passing(&Config::settle(1));
    assert_eq!(quiet.recon.after_settle, Some((0, 0)));
    assert!(quiet.recon.fixpoint_ticks >= reconcile::FIXPOINT_TICKS);
    let written = planted(Config::settle(1), Plant::SettledWrite, 0);
    let writes = written.recon.after_settle.map(|(writes, _)| writes);
    assert_eq!(writes, Some(1));
    assert_eq!(hosts::expected(&written).rule(), Some(fixpoint));
    let mut short = quiet.clone();
    short.recon.fixpoint_ticks = reconcile::FIXPOINT_TICKS - 1;
    assert_eq!(
        hosts::expected(&short),
        Verdict::Unrun(hosts::FIXPOINT_TICKS)
    );
}

/// A fixpoint count that held a store write keeps it as a breach of LOOP-FIXPOINT when a later unsettled sample ends
/// the count, and the rule fails by name after the fleet settles again over a quiet count. A write a loop makes in
/// the round whose sample finds a shard unsettled answers that shard, and the rule passes.
#[test]
fn an_unsettled_sample_keeps_the_breach_its_fixpoint_count_held() {
    let fixpoint = "a settled zone's loop made a store write or a mutating call";
    let quiet = passing(&Config::settle(1));
    let resettled = |log: &mut reconcile::ReconLog| {
        log.sample(false, false);
        log.sample(true, true);
        for _ in 0..reconcile::FIXPOINT_TICKS {
            log.tick_after_settle();
        }
        assert_eq!(log.after_settle, Some((0, 0)));
    };

    let mut written = quiet.clone();
    written.recon.effects.0 += 1;
    written.recon.sample(true, false);
    assert_eq!(written.recon.after_settle, Some((1, 0)));
    resettled(&mut written.recon);
    let failed = Verdict::Fail(fixpoint, "1 writes, 0 calls".into());
    assert_eq!(hosts::expected(&written), failed);

    let mut answered = quiet.clone();
    answered.recon.effects.0 += 1;
    resettled(&mut answered.recon);
    assert_eq!(hosts::expected(&answered), Verdict::Pass);
}

/// After H0's loss and the three takeovers of the host-loss case, the reconciler designates new standbys for s0, s1
/// and s2 and replaces s3's lost standby H0 under the cap, and every shard settles served with a standby.
#[test]
fn after_a_host_loss_the_reconciler_reenrolls_four_standbys_and_every_shard_settles() {
    after_a_host_loss_the_reconciler_reenrolls_four_standbys_and_every_shard_settles_on(1);
}

fn after_a_host_loss_the_reconciler_reenrolls_four_standbys_and_every_shard_settles_on(root: u64) {
    let report = passing(&Config::reenroll(root));
    assert_eq!(taken(&report), [(1, H3), (2, H3), (3, H5)]);
    let repaired: BTreeSet<u32> = (report.recon.designations.iter())
        .filter(|d| d.after_loss && d.repair == Repair::Need(Need::Standby))
        .map(|d| d.shard)
        .collect();
    assert_eq!(repaired, BTreeSet::from([1, 2, 3, 4]));
    for record in last_records(&report) {
        let standby = record.standby.expect("a named standby").get();
        assert!(standby != H0 && standby != record.owner.get());
    }
    assert!(report.evidence.settled.iter().all(|settled| settled.served));
    assert_eq!(report.evidence.volumes, Volumes::default());
}

/// H5 stands by for s2 and s4 and owns nothing. While its reports stop and its instance runs, its slots stay; its loss
/// moves the two census slots to running hosts, each designated once, with no takeover and no tenure change, and every
/// untouched shard serves its GETs.
#[test]
fn a_lost_standby_host_moves_its_slots_to_running_hosts_with_no_takeover() {
    a_lost_standby_host_moves_its_slots_to_running_hosts_with_no_takeover_on(1);
}

fn a_lost_standby_host_moves_its_slots_to_running_hosts_with_no_takeover_on(root: u64) {
    // LOST-NEEDS-TWO-CLASSES: while H5's reports stop and the zone double lists its instance running with healthy
    // checks, past twice the loop's silence window, no census slot, shard record or designation changes.
    let silent = passing(&Config::standby_silent(root));
    assert!(u64::from(silent.recon.paused_ticks) * reconcile::TICK_ROUNDS >= reconcile::AGE_ROUNDS);
    assert_eq!(silent.evidence.censuses, [6]);
    assert!(silent.recon.designations.is_empty());
    for shard in [3, 5] {
        let versions = &silent.evidence.histories[shard - 1].1;
        let first = versions[0];
        let kept =
            |record: &ShardRecord| (record.owner, record.standby) == (first.owner, first.standby);
        assert!(versions.iter().all(kept), "shard {shard}: {versions:?}");
        assert_eq!(first.standby.map(|host| host.get()), Some(H5));
    }
    assert_eq!((taken(&silent), silent.takeovers), (Vec::new(), 0));

    let report = passing(&Config::standby_loss(root));
    assert_eq!((taken(&report), report.takeovers), (Vec::new(), 0));
    for shard in [3, 5] {
        let hosts = designated(&report, shard);
        assert_eq!(hosts.len(), 1, "shard {shard}: {hosts:?}");
        assert_ne!(hosts[0], H5);
    }
    for shard in &report.shards {
        let at = shard.placement.shard.get();
        assert_eq!(shard.recoveries.len(), 1, "shard {at} keeps its tenure");
    }
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
}

/// With H0 and H3 lost, s0, s1 and s3 each get a fresh host that the loop attaches as the volume's third attach,
/// waits for its enrollment and designates, and whose takeover loads warm and serves the retained set, while H5 takes
/// s2 over; no volume is created and no volume record holds more than three live attaches. The loop then ends the
/// lost hosts' attaches outside the records' roles, which frees a live attach slot, and each of the three shards
/// takes a new standby.
#[test]
fn after_owner_and_standby_loss_fresh_hosts_take_the_retained_volumes_over_warm() {
    after_owner_and_standby_loss_fresh_hosts_take_the_retained_volumes_over_warm_on(1);
}

fn after_owner_and_standby_loss_fresh_hosts_take_the_retained_volumes_over_warm_on(root: u64) {
    let report = passing(&Config::double_loss(root));
    let taken = taken(&report);
    assert!(taken.contains(&(3, H5)), "{taken:?}");
    let fresh: Vec<_> = (report.recon.designations.iter())
        .filter(|d| d.repair == Repair::Need(Need::Fresh))
        .collect();
    let shards: BTreeSet<u32> = fresh.iter().map(|d| d.shard).collect();
    assert_eq!(shards, BTreeSet::from([1, 2, 4]));
    for d in &fresh {
        let at = (d.shard, d.host);
        assert!(taken.contains(&at), "{at:?}");
        let recovered = &report.shards[d.shard as usize - 1].recoveries;
        let last = recovered.last().expect("the fresh host's load");
        assert_eq!(last.host.get(), d.host);
        assert_eq!(
            last.sweep,
            Some((7, 7)),
            "the fresh host serves the retained set"
        );
    }
    assert_eq!(report.evidence.volumes.volume_writes, 0);
    assert!(report.evidence.attached.iter().all(|(_, live)| *live <= 3));
    for shard in [1, 2, 4] {
        assert!(
            report.recon.reclaims.contains(&(shard, Reclaim::End)),
            "shard {shard}"
        );
        assert_eq!(blocked(&report, shard), None, "shard {shard}");
        assert_eq!(designated(&report, shard).len(), 2, "shard {shard}");
    }
    for shard in [5, 6] {
        assert_eq!(report.shards[shard - 1].recoveries.len(), 1);
    }
}

/// Above the self-suspicion threshold the partition's loss leads to five designations: s0, s1 and s2 on their new
/// owners and s3 and s5 for their lost standbys. At the agent's threshold of three (`host::agent::SELF_SUSPECT`) the
/// three hosts of `trio`'s largest partition are lost (FC12): s0 and s1, whose owners are lost, carry `SelfSuspect`, no
/// status after the hosts' first report period reads the zone host hold, every volume is retained, and no
/// nomination starts before the designation that drops the lost H2 from s2's record. With two suspects left H3 then
/// takes s0 over and H5 takes s1.
#[test]
fn a_lost_partition_takes_five_designations_above_the_threshold_and_names_self_suspicion_at_it() {
    a_lost_partition_takes_five_designations_above_the_threshold_and_names_self_suspicion_at_it_on(
        1,
    );
}

fn a_lost_partition_takes_five_designations_above_the_threshold_and_names_self_suspicion_at_it_on(
    root: u64,
) {
    let above = passing(&Config::partition_repair(root));
    assert_eq!(taken(&above), [(1, H3), (2, H3), (3, H5)]);
    let repaired: BTreeSet<u32> = (above.recon.designations.iter())
        .filter(|d| d.after_loss)
        .map(|d| d.shard)
        .collect();
    assert_eq!(repaired, BTreeSet::from([1, 2, 3, 4, 6]));

    let at = passing(&Config::partition_repair_at(root));
    assert_eq!(at.config.shape.placing, Placing::Trio);
    let suspected: BTreeSet<u32> = (at.recon.blockers.iter())
        .filter(|(_, _, blocker, _)| *blocker == Blocker::SelfSuspect)
        .map(|(_, shard, ..)| *shard)
        .collect();
    assert_eq!(suspected, BTreeSet::from([1, 2]));
    assert_eq!(taken(&at), [(1, H3), (2, H5)]);
    // The loop reads the zone host hold only on its ticks before the hosts' first reports reach it, the loss's own
    // round among them, and on none after: the loss of three hosts, the largest partition, trips no hold.
    let repaired = (at.recon.designations.iter()).map(|d| d.round).max();
    let repaired = repaired.expect("the designations after the loss");
    assert!(
        repaired >= hosts::REPORT_ROUNDS,
        "designated after the first reports"
    );
    assert!(
        !at.recon.zone_held_rounds.is_empty(),
        "the loop reads the hold before the first reports reach it"
    );
    assert!(
        (at.recon.zone_held_rounds.iter()).all(|&round| round < hosts::REPORT_ROUNDS),
        "three lost hosts equal the largest partition: {:?}",
        at.recon.zone_held_rounds
    );
    assert_eq!(at.evidence.volumes, Volumes::default());
    let s2 = (at.recon.designations.iter()).find(|d| d.shard == 3 && d.after_loss);
    let s2 = s2.expect("the designation that drops the lost H2 from s2's record");
    assert!(
        at.recon
            .first_nomination
            .is_some_and(|round| round > s2.round)
    );
    let suspect =
        "an observer that a veto or its self-suspicion bars nominated or took a shard over";
    // The hosts take their turn before the reconcilers in a round, so a nomination in the designation's own
    // round was published before the designation.
    for nominated in [s2.round - 1, s2.round] {
        let mut early = at.clone();
        early.recon.first_nomination = Some(nominated);
        assert_eq!(
            hosts::expected(&early).rule(),
            Some(suspect),
            "round {nominated}"
        );
    }
    let mut after = at.clone();
    after.recon.first_nomination = Some(s2.round + 1);
    assert_eq!(hosts::expected(&after), Verdict::Pass);
}

/// Census full on `small` with cap 5: the loop's status reports the cap below the six shards. s5 starts unlisted
/// while H4 serves it, and its `Standby` need reads `CensusFull`; after H4's loss its `Fresh` need reads `CensusFull`
/// too. When another shard's entry is released, s5 is admitted, because the plan keeps the place a tick frees for a
/// `Fresh` need the census refused (FRESH-FIRST in `zone_loop::plan`): the loop designates a fresh host for s5, that
/// host takes s5 over warm on its retained volume at the same generation, no volume is created, and the census never
/// lists more than five shards. F4 and F5 pass, and the scenario's credit passes with its fresh-host witness.
#[test]
fn a_full_census_refuses_s5_both_needs_and_admits_it_on_a_released_entry_to_recover_warm() {
    a_full_census_refuses_s5_both_needs_and_admits_it_on_a_released_entry_to_recover_warm_on(1);
}

fn a_full_census_refuses_s5_both_needs_and_admits_it_on_a_released_entry_to_recover_warm_on(
    root: u64,
) {
    let report = run_shared(&Config::census_full(root)).expect("a run inside the limits");
    assert_eq!(report.credit(), Verdict::Pass);
    assert_eq!(report.verdicts.census, Some(Verdict::Pass));
    assert_eq!(report.verdicts.settles, Verdict::Pass);
    let recon = &report.recon;
    assert_eq!(recon.cap_below, Some((5, 6)));
    assert!(report.evidence.censuses.iter().all(|&len| len <= 5));
    assert!(recon.refused_full >= 2);
    let s5: Vec<_> = recon.fulls.iter().filter(|full| full.0 == 6).collect();
    let standby = Repair::Need(Need::Standby);
    assert_eq!(
        s5.first(),
        Some(&&(6, standby, true, 5)),
        "s5 refused while H4 serves"
    );
    let fresh = Repair::Need(Need::Fresh);
    assert!(
        s5.contains(&&(6, fresh, false, 5)),
        "s5 refused after H4's loss: {s5:?}"
    );
    // The designation of a fresh host for s5 once another shard's entry is released, and that host's warm takeover.
    let designated = (recon.designations.iter())
        .find(|d| d.shard == 6 && d.repair == fresh && d.after_loss)
        .expect("a fresh host designated for s5");
    assert!(taken(&report).contains(&(6, designated.host)));
    let recovered = report.shards[5].recoveries.last().unwrap();
    assert_eq!(recovered.host.get(), designated.host);
    assert!(recovered.after_crash);
    assert!(
        recovered
            .sweep
            .is_some_and(|(of, served)| of > 0 && of == served),
        "s5 recovers warm: {:?}",
        recovered.sweep
    );
    let first = report.evidence.histories[5].1[0];
    let s5 = last_records(&report)[5];
    assert_eq!(
        (s5.generation, s5.active, s5.owner.get()),
        (first.generation, first.active, designated.host)
    );
    assert_eq!(report.evidence.volumes, Volumes::default());
    assert_eq!(report.volumes.calls, 0);
}

/// Exhausted attach slots: s2's volume holds the attaches of H0, H5 and H1. With H0 and H5 lost the loop
/// designates H1 again, ranked first on its live attach, and H1 takes s2 over. With H1 lost too the loop ends H1's
/// attach, which frees a slot, and a fresh host takes s2 over warm once the zone host hold ends.
#[test]
fn a_volume_at_three_attaches_redesignates_its_surviving_attached_host_or_closes() {
    a_volume_at_three_attaches_redesignates_its_surviving_attached_host_or_closes_on(1);
}

fn a_volume_at_three_attaches_redesignates_its_surviving_attached_host_or_closes_on(root: u64) {
    let survivor = passing(&Config::attach_survivor(root));
    assert!(taken(&survivor).contains(&(3, H1)));
    let again = (survivor.recon.designations.iter())
        .find(|d| d.shard == 3)
        .expect("s2's designation");
    assert!(again.attached && again.host == H1);
    assert!(
        survivor
            .evidence
            .attached
            .iter()
            .all(|(_, live)| *live <= 3)
    );

    // With H1 lost too, the loop ends H1's attach, the one attach outside the record's roles, which frees a live
    // attach slot. Three lost hosts of six are above the largest partition, so the zone host hold withholds the fresh
    // host's start until the operator retires the lost hosts in the directory; H2 then attaches, enrolls, is
    // designated and takes s2 over warm, with no volume created.
    let closed = passing(&Config::attach_closed(root));
    assert!(closed.recon.reclaims.contains(&(3, Reclaim::End)));
    let retired: BTreeSet<u64> = closed.recon.retired.iter().copied().collect();
    assert_eq!(retired, BTreeSet::from([H0, H1, H5]));
    let fresh = (closed.recon.designations.iter())
        .find(|d| d.shard == 3 && d.repair == Repair::Need(Need::Fresh))
        .expect("s2's fresh host");
    assert!(!fresh.attached);
    assert!(taken(&closed).contains(&(3, fresh.host)));
    let last = closed.shards[2]
        .recoveries
        .last()
        .expect("the fresh host's load");
    assert_eq!((last.host.get(), last.sweep), (fresh.host, Some((7, 7))));
    assert_eq!(closed.evidence.volumes, Volumes::default());
    let (first, s2) = (closed.evidence.histories[2].1[0], last_records(&closed)[2]);
    assert_eq!(
        (s2.owner.get(), s2.generation),
        (fresh.host, first.generation)
    );
    assert!(closed.evidence.attached.iter().all(|(_, live)| *live <= 3));
    assert_ne!(blocked(&closed, 3), Some(Blocker::AttachClosed));
}

/// An unknown registrant on s0's reservation makes the owner withdraw with a flip request; s0 carries
/// `RetirementRequested`, nothing flips, nothing is created, and the summary names the hostile profile.
#[test]
fn a_foreign_registrant_raises_retirement_requested_with_no_flip_and_no_create() {
    a_foreign_registrant_raises_retirement_requested_with_no_flip_and_no_create_on(1);
}

fn a_foreign_registrant_raises_retirement_requested_with_no_flip_and_no_create_on(root: u64) {
    let report = run(&Config::foreign(root)).expect("a run inside the limits");
    assert!(report.planted);
    let volumes = report.evidence.volumes;
    let created = (volumes.flips, volumes.volume_writes, volumes.receipts);
    assert_eq!((created, volumes.flip_requests), ((0, 0, 0), 1));
    assert_eq!(blocked(&report, 1), Some(Blocker::RetirementRequested));
    assert_eq!(report.verdicts.settles, Verdict::Pass);
    assert_eq!(
        report.verdicts.census,
        Some(Verdict::Unrun(oracles::NO_RESERVATION))
    );
    let first = report.evidence.histories[0].1[0];
    let s0 = last_records(&report)[0];
    let kept = (s0.generation, s0.active, s0.owner);
    assert_eq!(kept, (first.generation, first.active, first.owner));
    assert!(
        report
            .summary()
            .ends_with("; profile hostile:foreign-registrant")
    );
    assert_eq!(report.credit().rule(), Some(oracles::FLIP_REQUEST));
}

/// Two reconcilers after H0's loss: reconciler 1's actuation inside reconciler 0's census read of its first
/// reservation makes 0's exact-version census write lose its version condition; reconciler 1's designation over a
/// survey a round old is refused by TICK-ORDER before any effect; each shard takes at most one designation, and the
/// census stays under its cap. Each order of the two reconcilers in a round is one recorded decision beyond the
/// host-loss run's, with each round's runnable-actor decision left out of both counts.
#[test]
fn two_reconcilers_over_one_census_converge_on_one_designation_per_need() {
    two_reconcilers_over_one_census_converge_on_one_designation_per_need_on(1);
}

fn two_reconcilers_over_one_census_converge_on_one_designation_per_need_on(root: u64) {
    let report = passing(&Config::racing(root));
    let recon = &report.recon;
    assert!(recon.condition >= 1 && recon.stale() >= 1);
    assert!(recon.raced && recon.race_shard.is_some());
    let unrepaired = passing(&Config::host_loss(root));
    let unrepaired = unrepaired.decisions - unrepaired.actor_turns;
    assert!(recon.orders >= 1);
    assert_eq!(
        report.decisions - report.actor_turns,
        unrepaired + u64::from(recon.orders)
    );
    let stale = (recon.refusals.iter())
        .any(|(_, _, refused)| matches!(refused, Refused::Discarded(Step::Designate { .. }, _)));
    assert!(stale, "{:?}", recon.refusals);
    assert!(
        recon.contended >= 1,
        "reconciler 1 works a need after the loss"
    );
    for shard in 1..=4 {
        let hosts = designated(&report, shard);
        assert_eq!(hosts.len(), 1, "shard {shard}: {hosts:?}");
    }
    for shard in 5..=6 {
        assert_eq!(designated(&report, shard), Vec::<u64>::new());
    }
}

/// The crash boundary sits above the tally: a dead incarnation's read and write reach neither the tally nor the
/// store, while a live incarnation's requests count once each. A census write that commits the census it found counts
/// as a rewrite, an acknowledged one and one that committed with an unknown reply alike, and a changed census does
/// not.
#[test]
fn a_dead_incarnation_reaches_no_tally_and_a_committed_unchanged_census_counts_as_a_rewrite() {
    use crate::failover::standbys::{Census, Zone};
    use crate::storage::store::sim::{Arm, Shared};
    use crate::storage::store::{Key, Outcome, Store, Write};
    use reconcile::{Counted, Crashing, Effected};
    let shared = Shared::new();
    let tally = std::rc::Rc::new(std::cell::RefCell::new(std::collections::BTreeMap::new()));
    let effects = std::rc::Rc::new(std::cell::RefCell::new(Effected::default()));
    let mut crashing = Crashing {
        store: Counted {
            inner: shared.clone(),
            counts: tally.clone(),
        },
        effects: effects.clone(),
    };
    let key = Key::Standbys(Zone(1));
    let census = Census::empty(Zone(1)).encode();
    let created = crashing.write(&key, &Write::Create(census.clone()));
    assert!(matches!(created, Outcome::Committed(_)), "{created:?}");
    let same = |version| Write::Exact {
        expect: version,
        value: census.clone(),
    };
    let version = |shared: &Shared| shared.0.borrow().current(&key).map(|item| item.version);
    let first = version(&shared).expect("the census");
    crashing.write(&key, &same(first));
    assert_eq!(effects.borrow().rewrites, 1, "an acknowledged rewrite");
    let second = version(&shared).expect("the census");
    let held =
        crate::storage::store::sim::Armed::arm_next(&mut crashing, Arm::Timeout { commit: true });
    let unknown = crashing.write(&key, &same(second));
    crate::storage::store::sim::Armed::disarm(&mut crashing, held);
    assert_eq!(unknown, Outcome::Unknown);
    assert_eq!(
        effects.borrow().rewrites,
        2,
        "a rewrite that committed with an unknown reply"
    );
    let counted = tally.borrow().get(&key).copied();
    let requests = shared.0.borrow().requests(&key);
    effects.borrow_mut().dead = true;
    assert!(crashing.read(&key).is_err());
    assert_eq!(crashing.write(&key, &same(second)), Outcome::Unknown);
    assert_eq!(
        tally.borrow().get(&key).copied(),
        counted,
        "the tally after the crash"
    );
    assert_eq!(
        shared.0.borrow().requests(&key),
        requests,
        "the store after the crash"
    );
}

/// One crash-table cell: the reconciler crashed once at the cell's effect, with the written key one commit further
/// for an acknowledged or committed ending and unchanged for a lost one, and restarted once, F4 held after every
/// tick, the repaired shard took one designation for each need (a `Fresh` cell's fresh host and then its standby),
/// only releases shrank the census, the volume keeps the repair's attach among its three, and the run replays to an
/// equal report.
fn crash_cell_converges(cell: CrashCell) -> String {
    let name = cell.name();
    let config = Config::crash(1, cell);
    let report = passing(&config);
    assert_eq!(report.recon.crashed, std::slice::from_ref(&name));
    let wrote = usize::from(cell.ending != reconcile::Ending::Lost);
    let [(before, at_crash)] = report.recon.crash_writes[..] else {
        panic!("{name}: {:?}", report.recon.crash_writes);
    };
    assert_eq!(
        at_crash,
        before + wrote,
        "{name}: the crash follows the call's write as the cell names its ending"
    );
    assert_eq!(report.recon.restarts, 1, "{name}");
    assert_eq!(report.verdicts.census, Some(Verdict::Pass), "{name}");
    let needs = 1 + usize::from(cell.fresh);
    assert_eq!(designated(&report, 1).len(), needs, "{name}");
    let versions = report.evidence.censuses.windows(2);
    let dropped = versions.filter(|pair| pair[1] < pair[0]).count() as u32;
    assert!(
        dropped <= report.recon.releases,
        "{name}: only a release drops an entry"
    );
    let volume = &report.evidence.attached[0];
    assert_eq!(volume.1, 3, "{name}: the repair's attach stays recorded");
    let listed = &report.evidence.listed[0];
    assert_eq!(
        listed.1, 1,
        "{name}: the zone double lists each attachment once"
    );
    let need = if cell.fresh {
        Need::Fresh
    } else {
        Need::Standby
    };
    assert_eq!(
        report.recon.crash_aim,
        Some((1, need)),
        "{name}: the cut effect belongs to s0's repair"
    );
    let lost_attach =
        cell.call == reconcile::Call::Attach && cell.ending == reconcile::Ending::Lost;
    assert_eq!(
        report.evidence.requests[0].1,
        1 + usize::from(lost_attach),
        "{name}: one attach request per candidate, and a retry only after a lost one"
    );
    assert!(
        (report.evidence.standby_local.iter()).any(|&(shard, held)| shard.get() == 1 && held),
        "{name}: s0's standby holds the local record of its enrolled pair"
    );
    assert_eq!(replay(&config, &report.recording()), Ok(report), "{name}");
    name
}

/// Whether `cell` is one of the fast tier's enrollment cells: one cell of each call, the ending turning with the
/// call and the fresh flag alternating, so the five fast cells reach all three endings and both layouts.
fn fast_cell(cell: &CrashCell) -> bool {
    let call = cell.call as usize;
    cell.ending as usize == call % 3 && cell.fresh == (call % 2 == 1)
}

/// Runs the fast cell of `call`; the scheduled case runs the other cells.
fn crash_cells_converge(call: reconcile::Call) {
    let cells: Vec<String> = (CrashCell::all().into_iter())
        .filter(|cell| cell.call == call && fast_cell(cell))
        .map(crash_cell_converges)
        .collect();
    assert_eq!(cells.len(), 1, "{cells:?}");
}

/// A crash cell's cleanup withdraws its own armed write and leaves the write arms an episode queued for the
/// enrolling host. The enrollment crash cell runs with no, one and two episodes that arm H3's next write to time out
/// uncommitted. H3 is the host the cell enrolls: each armed timeout meets one enrollment write, which leaves H3
/// unenrolled for the next scan, and the cell's own arm meets the write after them. So each episode delays the run
/// by one scan, every episode's arm is taken, and the cell crashes once and converges each time.
#[test]
fn a_crash_cells_cleanup_leaves_the_write_arms_an_episode_queued_for_the_enrolling_host() {
    use super::faults::{Action, Episode, Faults, Trigger};
    use crate::storage::store::sim::Arm;
    const ENROLLING: usize = 3;
    let cell = CrashCell {
        fresh: false,
        call: reconcile::Call::Enroll,
        ending: reconcile::Ending::Lost,
    };
    let rounds = |timeouts: usize| {
        let config = Config::crash(1, cell);
        let mut script = config.scenario.episodes(false);
        script.extend((0..timeouts).map(|_| Episode {
            trigger: Trigger::AtTime(0),
            scope: vec![ENROLLING],
            action: Action::StoreWrite(Arm::Timeout { commit: false }),
            heal: None,
        }));
        let mut draws = Draws::record(config.root);
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        fleet.faults = Faults::new(script, fleet.topology.members.len());
        fleet.alarms.scripted = true;
        let _inline = Inline::set();
        let mut queued = 0;
        let ran = fleet.play_script_with(draws, |fleet, live, slots| {
            let ran = fleet.run_hosts(live, slots);
            queued = fleet.faults.store.borrow().queued(ENROLLING as u32);
            ran
        });
        let report = ran.expect("a run inside the limits");
        assert_eq!(
            queued, 0,
            "{timeouts} timeouts: every armed write was taken"
        );
        assert_eq!(report.recon.crashed, [cell.name()], "{timeouts} timeouts");
        assert_eq!(report.recon.crash_writes.len(), 1, "{timeouts} timeouts");
        assert_eq!(
            report.verdicts.census,
            Some(Verdict::Pass),
            "{timeouts} timeouts"
        );
        report.rounds
    };
    let (none, one, two) = (rounds(0), rounds(1), rounds(2));
    let scan = one - none;
    assert!(
        scan > 0,
        "a timed-out enrollment write costs a scan: {none} and {one} rounds"
    );
    assert_eq!(
        two,
        one + scan,
        "the second episode's arm met the second enrollment write"
    );
}

#[test]
fn one_crash_cell_after_a_reservation_is_reached_and_converges() {
    crash_cells_converge(reconcile::Call::Reserve);
}

#[test]
fn one_crash_cell_after_an_attach_record_is_reached_and_converges() {
    crash_cells_converge(reconcile::Call::Record);
}

#[test]
fn one_crash_cell_after_an_attach_request_is_reached_and_converges() {
    crash_cells_converge(reconcile::Call::Attach);
}

#[test]
fn one_crash_cell_after_an_enrollment_is_reached_and_converges() {
    crash_cells_converge(reconcile::Call::Enroll);
}

#[test]
fn one_crash_cell_after_a_designation_is_reached_and_converges() {
    crash_cells_converge(reconcile::Call::Designate);
}

fn planted(config: Config, plant: Plant, at: u32) -> Report {
    let report = run(&config.hostile(plant, at)).expect("a run inside the limits");
    assert!(report.planted, "{plant:?} changed the run");
    report
}

/// The rule texts the census and settle controls fail by.
struct ControlRules {
    over_cap: &'static str,
    uncovered: &'static str,
    unsettled: &'static str,
    unbacked: &'static str,
}

/// The rule texts as the oracles define them, for the scheduled case's root.
const CONTROL_RULES: ControlRules = ControlRules {
    over_cap: oracles::OVER_CAP,
    uncovered: oracles::UNCOVERED,
    unsettled: oracles::UNSETTLED,
    unbacked: oracles::UNBACKED,
};

/// Controls of F4 and F5: a second reconciler under the cap plus one fails F4 by its first rule and a census that loses
/// a covered entry by its second; skipping s0's `Standby` need, and a collected status that drops every blocker of s3,
/// which ends the full-census run with no standby under `CensusFull`, fail F5 by its first rule; a `CensusFull` entered
/// with no refusal fails F5 by its second. The scheduled case runs them on root 2 and runs the stranded-s5 control and
/// the unplanted siblings ([`census_and_settle_siblings_on`]) on roots 1 and 2.
#[test]
fn census_and_settle_controls_fail_f4_and_f5_by_name() {
    let rules = ControlRules {
        over_cap: "a zone's census lists more shards than its cap",
        uncovered: "a shard record names a designated standby with no census entry",
        unsettled: "a shard reached neither a serving owner with an enrolled standby nor a named blocker within the settle bound",
        unbacked: "a blocker was recorded with no typed refusal behind it",
    };
    census_and_settle_controls_on(1, &rules);
}

/// The census and settle controls on `root`, each failing by its rule in `rules`.
fn census_and_settle_controls_on(root: u64, rules: &ControlRules) {
    let ControlRules {
        over_cap: over,
        uncovered,
        unsettled,
        unbacked,
    } = *rules;
    let wide = planted(Config::census_full(root), Plant::WideCap, 0);
    assert_eq!(wide.verdicts.census.unwrap().rule(), Some(over));
    assert!(wide.evidence.censuses.iter().any(|&len| len > 5));

    let dropped = planted(Config::reenroll(root), Plant::DropNeed, 0);
    let judged = &dropped.verdicts.settles;
    assert_eq!(judged, &Verdict::Fail(unsettled, "shard 1".into()));

    let silent = planted(Config::census_full(root), Plant::SilentBlocker, 3);
    let judged = &silent.verdicts.settles;
    assert_eq!(judged, &Verdict::Fail(unsettled, "shard 4".into()));
    assert!(!(silent.recon.blockers.iter()).any(|(_, shard, ..)| *shard == 4));

    let entered = planted(Config::census_full(root), Plant::UnbackedBlocker, 0);
    let judged = &entered.verdicts.settles;
    let at = "shard 1 CensusFull".to_owned();
    assert_eq!(judged, &Verdict::Fail(unbacked, at));

    let dropped = planted(Config::settle(root), Plant::UncoveredEntry, 0);
    let judged = dropped.verdicts.census.expect("the census verdict");
    assert_eq!(judged.rule(), Some(uncovered));
    assert!(dropped.evidence.censuses.iter().all(|&len| len <= 6));
}

/// The unplanted census-full and re-enrollment runs pass F4 and F5 on `root`, and removing s5's enrollment steps in
/// the full census, which strands s5 with no designation, fails F5 by its first rule (`rules.unsettled`). The scheduled
/// case runs this on roots 1 and 2; the fast tier's census-full and re-enrollment cases pass the same siblings on root
/// 1.
fn census_and_settle_siblings_on(root: u64, rules: &ControlRules) {
    for sibling in [Config::census_full(root), Config::reenroll(root)] {
        let report = run_shared(&sibling).expect("a run inside the limits");
        assert_eq!(report.verdicts.census, Some(Verdict::Pass));
        assert_eq!(report.verdicts.settles, Verdict::Pass);
    }
    let stranded = planted(Config::census_full(root), Plant::DropNeed, 5);
    let judged = &stranded.verdicts.settles;
    assert_eq!(judged, &Verdict::Fail(rules.unsettled, "shard 6".into()));
    assert!(!(stranded.recon.designations.iter()).any(|d| d.shard == 6));
}

/// Control: with s2's `Standby` need skipped after its standby host H5 is lost, s2 keeps serving beside a lost
/// standby that its volume enrolls and the census lists, and F5 fails by its first rule.
#[test]
fn a_standby_need_dropped_after_the_standby_hosts_loss_fails_f5_by_its_first_rule() {
    let unsettled = "a shard reached neither a serving owner with an enrolled standby nor a named blocker within the settle bound";
    standby_need_dropped_on(1, unsettled);
}

/// The dropped standby need's control on `root`, failing F5 by `unsettled`; the scheduled case runs root 2.
fn standby_need_dropped_on(root: u64, unsettled: &'static str) {
    let lost = planted(Config::standby_loss(root), Plant::DropNeed, 2);
    let judged = &lost.verdicts.settles;
    assert_eq!(judged, &Verdict::Fail(unsettled, "shard 3".into()));
}

/// Hand-built inputs reach every rule of F4 and F5 by name, and each oracle reads `Unrun` when its event never
/// happened.
#[test]
fn the_census_and_settle_oracles_fail_each_rule_by_name_and_read_a_missing_event_unrun() {
    let over_cap = "a zone's census lists more shards than its cap";
    let uncovered_rule = "a shard record names a designated standby with no census entry";
    let unsettled_rule = "a shard reached neither a serving owner with an enrolled standby nor a named blocker within the settle bound";
    let unbacked_rule = "a blocker was recorded with no typed refusal behind it";
    use super::reconcile::{ReconLog, SettlePhase};
    let mut log = ReconLog::default();
    log.reservations = 1;
    let uncovering = oracles::census(&[1, 2, 2], (2, 1), &log);
    assert_eq!(
        uncovering,
        Verdict::Unrun("witness boot-coverage missing"),
        "no boot survey found every named standby listed, so the covers rule judged nothing"
    );
    log.covered.insert(1);
    assert_eq!(oracles::census(&[1, 2, 2], (2, 1), &log), Verdict::Pass);
    let one_of_two = oracles::census(&[1, 2, 2], (2, 2), &log);
    assert_eq!(
        one_of_two,
        Verdict::Unrun(oracles::NO_COVERAGE),
        "F4 needs a boot survey's coverage in each zone"
    );
    log.covered.insert(2);
    assert_eq!(oracles::census(&[1, 2, 2], (2, 2), &log), Verdict::Pass);
    let over = oracles::census(&[1, 2, 3], (2, 1), &log);
    assert_eq!(
        over,
        Verdict::Fail(over_cap, "version 3 lists 3 of 2".into())
    );
    log.uncovered = Some((4, 17));
    let uncovered = oracles::census(&[1], (2, 1), &log);
    assert_eq!(
        uncovered,
        Verdict::Fail(uncovered_rule, "shard 4 at round 17".into())
    );
    let unrun = oracles::census(&[], (2, 1), &ReconLog::default());
    assert_eq!(unrun, Verdict::Unrun(oracles::NO_RESERVATION));

    let shard = crate::net::ownership::Shard::new(1).unwrap();
    let served = [oracles::Settled {
        shard,
        served: true,
        blocker: None,
    }];
    let held = [oracles::Settled {
        served: false,
        blocker: Some(Blocker::CensusFull),
        ..served[0]
    }];
    let silent = [oracles::Settled {
        blocker: None,
        ..held[0]
    }];
    let mut log = ReconLog::default();
    assert_eq!(
        oracles::settled(&served, &log),
        Verdict::Unrun(oracles::NO_SETTLE)
    );
    log.settle = Some(SettlePhase {
        started: 0,
        turns: Some(3),
    });
    assert_eq!(oracles::settled(&served, &log), Verdict::Pass);
    let unsettled = Verdict::Fail(unsettled_rule, "shard 1".into());
    assert_eq!(oracles::settled(&silent, &log), unsettled);
    let full = Refused::row(Blocker::CensusFull);
    let mut backed = log.clone();
    backed.enter(1, full.clone(), Blocker::CensusFull);
    assert_eq!(oracles::settled(&held, &backed), Verdict::Pass);
    let mut unbacked = log.clone();
    unbacked.enter(
        1,
        Refused::row(Blocker::RetirementRequested),
        Blocker::CensusFull,
    );
    let judged = oracles::settled(&held, &unbacked);
    assert_eq!(
        judged,
        Verdict::Fail(unbacked_rule, "shard 1 CensusFull".into())
    );
    let census_full = Verdict::Fail(unbacked_rule, "shard 1 CensusFull".into());
    let mut elsewhere = log.clone();
    elsewhere.refusals.push((1, 2, full.clone()));
    elsewhere
        .blockers
        .push((2, 1, Blocker::CensusFull, Some(1)));
    let judged = oracles::settled(&held, &elsewhere);
    assert_eq!(judged, census_full, "another shard's refusal");
    let mut after = log.clone();
    after.blockers.push((1, 1, Blocker::CensusFull, Some(2)));
    after.refusals.push((2, 1, full.clone()));
    let judged = oracles::settled(&held, &after);
    assert_eq!(judged, census_full, "a later refusal");
    let closed = [oracles::Settled {
        blocker: Some(Blocker::AttachClosed),
        ..held[0]
    }];
    let judged = oracles::settled(&closed, &backed);
    let at = "shard 1 Some(AttachClosed)".to_owned();
    assert_eq!(judged, Verdict::Fail(unbacked_rule, at));
    let stale = [oracles::Settled {
        served: true,
        ..held[0]
    }];
    let stale_rule = "a shard that serves with an enrolled standby carries a blocker";
    let at = "shard 1 Some(CensusFull)".to_owned();
    assert_eq!(
        oracles::settled(&stale, &backed),
        Verdict::Fail(stale_rule, at)
    );
    // The settle phase samples `Settled::settled`; its per-shard result must agree with `oracles::settled` for a
    // single shard.
    for (state, log) in [(&served, &log), (&held, &backed)] {
        assert!(state[0].settled(), "{state:?}");
        assert_eq!(oracles::settled(state, log), Verdict::Pass);
    }
    for state in [&silent, &stale] {
        assert!(!state[0].settled(), "{state:?}");
        assert!(matches!(
            oracles::settled(state, &backed),
            Verdict::Fail(..)
        ));
    }
    let bound = reconcile::REPAIR_SETTLE_ROUNDS;
    let mut within = log.clone();
    within.settle = Some(SettlePhase {
        started: 0,
        turns: Some(bound),
    });
    assert_eq!(oracles::settled(&served, &within), Verdict::Pass);
    for turns in [Some(bound + 1), None] {
        let mut late = log.clone();
        late.settle = Some(SettlePhase { started: 0, turns });
        assert_eq!(
            oracles::settled(&served, &late).rule(),
            Some(unsettled_rule),
            "{turns:?}"
        );
    }
}

/// Each blocker entry names its own earlier refusal of its shard.
#[test]
fn each_blocker_names_a_refusal_of_its_own() {
    use super::reconcile::{ReconLog, SettlePhase};
    use crate::failover::standbys::Refusal as P;
    let held = |blocker| {
        [oracles::Settled {
            shard: crate::net::ownership::Shard::new(1).unwrap(),
            served: false,
            blocker: Some(blocker),
        }]
    };
    let full = held(Blocker::CensusFull);
    let unbacked_rule = "a blocker was recorded with no typed refusal behind it";
    let unbacked = Verdict::Fail(unbacked_rule, "shard 1 CensusFull".into());
    let mut log = ReconLog::default();
    log.settle = Some(SettlePhase {
        started: 0,
        turns: Some(3),
    });
    let mut once = log.clone();
    once.enter(1, reserve(P::Full), Blocker::CensusFull);
    assert_eq!(once.blockers, [(2, 1, Blocker::CensusFull, Some(1))]);
    assert_eq!(oracles::settled(&full, &once), Verdict::Pass);

    for (refusal, case) in [
        (Some(1), "the first blocker's refusal"),
        (None, "no refusal"),
        (Some(9), "a sequence number no refusal carries"),
    ] {
        let mut again = once.clone();
        again.blockers.push((3, 1, Blocker::CensusFull, refusal));
        assert_eq!(oracles::settled(&full, &again), unbacked, "{case}");
        // Only the matching refusal at the sequence number the blocker names can back that entry.
        again.refusals.push((3, 1, reserve(P::Full)));
        again.blockers[1].0 = 4;
        assert_eq!(oracles::settled(&full, &again), unbacked, "{case}, spare");
    }
    let mut twice = once.clone();
    twice.refusals.push((3, 1, reserve(P::Full)));
    twice.blockers.push((4, 1, Blocker::CensusFull, Some(3)));
    assert_eq!(oracles::settled(&full, &twice), Verdict::Pass);

    // A blocker can name an earlier matching refusal even when later entries exist for the same shard.
    let mut delayed = log.clone();
    delayed.refusals.push((1, 1, reserve(P::Headroom)));
    delayed.refusals.push((2, 1, reserve(P::Closed)));
    delayed
        .refusals
        .push((3, 1, Refused::row(Blocker::RetirementRequested)));
    let retirement = Blocker::RetirementRequested;
    delayed.blockers.push((4, 1, retirement, Some(3)));
    delayed.refusals.push((5, 1, reserve(P::Headroom)));
    let closed = Blocker::AttachClosed;
    delayed.blockers.push((6, 1, closed, Some(2)));
    assert_eq!(oracles::settled(&held(closed), &delayed), Verdict::Pass);

    let report = run_shared(&Config::census_full(1)).expect("a run inside the limits");
    let shards = &report.evidence.settled;
    assert!(!report.recon.blockers.is_empty());
    assert_eq!(oracles::settled(shards, &report.recon), Verdict::Pass);
    for entry in 0..report.recon.blockers.len() {
        let mut edited = report.recon.clone();
        edited.blockers[entry].3 = None;
        let judged = oracles::settled(shards, &edited);
        assert_eq!(judged.rule(), Some(unbacked_rule), "entry {entry}");
    }
}

/// `backs` matches each blocker to a status row that names it and to the reservation step the census refused with
/// the population refusal that names it, and to no other refusal.
#[test]
fn each_blocker_is_backed_by_its_own_typed_refusal_alone() {
    use crate::failover::standbys::Refusal as P;
    let refusals: Vec<Refused> = [
        reserve(P::Full),
        reserve(P::Closed),
        reserve(P::Headroom),
        reserve(P::Taken),
        reserve(P::Ineligible),
    ]
    .into_iter()
    .chain(Blocker::ALL.into_iter().map(Refused::row))
    .collect();
    let populations = |blocker| match blocker {
        Blocker::CensusFull => vec![0],
        Blocker::AttachClosed => vec![1],
        Blocker::Headroom => vec![2],
        Blocker::NoEligibleHost => vec![3, 4],
        _ => vec![],
    };
    for (at, blocker) in Blocker::ALL.into_iter().enumerate() {
        let backed: Vec<usize> = (0..refusals.len())
            .filter(|&of| reconcile::backs(blocker, &refusals[of]))
            .collect();
        let mut backing = populations(blocker);
        backing.push(5 + at);
        assert_eq!(backed, backing, "{blocker:?}");
    }
}

/// A repair run draws decisions beyond the host-loss run's, each round's runnable-actor decision left out of both
/// counts, replays its tape to an equal report, and a tape one byte short is refused.
#[test]
fn a_repair_run_replays_its_recording_and_a_short_tape_is_refused() {
    let unrepaired = passing(&Config::host_loss(1));
    let unrepaired = unrepaired.decisions - unrepaired.actor_turns;
    for config in [Config::racing(1), Config::double_loss(1)] {
        let report = passing(&config);
        let reconcilers = config.shape.reconcilers;
        let drawn_here = report.decisions - report.actor_turns;
        assert_eq!(
            drawn_here > unrepaired,
            reconcilers > 1,
            "two reconcilers draw their order"
        );
        let drawn = u64::from(report.recon.orders);
        assert_eq!(drawn_here, unrepaired + drawn);
        assert_eq!(replay(&config, &report.recording()), Ok(report.clone()));
        let mut short = report.recording();
        short.tape.truncate(short.tape.len() - 1);
        let refused = replay(&config, &short);
        assert!(matches!(refused, Err(Stopped::Choice(_))), "{refused:?}");
    }
}

/// Each new required outcome and witness of a repair scenario fails or reads `Unrun` by its own rule when its
/// report is altered, and the unaltered report passes: a volume record above three live attaches, a takeover after
/// a standby-only loss, a fresh host designated without its prober quorum, whose `Unrun` the settle verdict's
/// failure gives way to, and the missing witnesses of the double loss and the two-reconciler case.
/// `Unrun(PROBER_PREMISE)` replaces only the settle verdict's `UNSETTLED` failure: an `UNBACKED` or `STALE_BLOCKER`
/// failure of that verdict keeps the credit, because a missing quorum accounts only for `UNSETTLED`.
#[test]
fn each_repair_outcome_fails_by_its_rule_and_the_unaltered_run_passes() {
    let double = passing(&Config::double_loss(1));
    assert_eq!(hosts::expected(&double), Verdict::Pass);
    let rule = |report: &Report, edit: fn(&mut Report)| {
        let mut report = report.clone();
        edit(&mut report);
        hosts::expected(&report)
    };
    let over = "a volume record holds more live attaches than MAX_ATTACHED";
    let four = rule(&double, |report| report.evidence.attached[0].1 = 4);
    assert_eq!(four.rule(), Some(over));
    let early = "an attach request preceded its attach record or a detach preceded its pair's drop";
    let unrecorded = rule(&double, |report| report.recon.unordered = 1);
    assert_eq!(unrecorded.rule(), Some(early));
    let again = "a reconciler's census write committed the census it found";
    let rewritten = rule(&double, |report| report.recon.rewrites = 1);
    assert_eq!(rewritten.rule(), Some(again));
    let premise = Verdict::Unrun("premise prober-quorum missing");
    assert_eq!(
        rule(&double, |report| report.recon.premise_failed = true),
        premise
    );
    let mut quorumless = double.clone();
    quorumless.recon.premise_failed = true;
    quorumless.verdicts.settles = Verdict::Fail(oracles::UNSETTLED, "shard 1".into());
    assert_eq!(quorumless.credit(), premise);
    for rule in [oracles::UNBACKED, oracles::STALE_BLOCKER] {
        let mut unsound = quorumless.clone();
        unsound.verdicts.settles = Verdict::Fail(rule, "shard 1".into());
        assert_eq!(unsound.credit().rule(), Some(rule));
    }
    quorumless.verdicts.one_owner = Verdict::Fail(oracles::TWO_OWNERS, "shard 1".into());
    assert_eq!(quorumless.credit().rule(), Some(oracles::TWO_OWNERS));

    let standby = passing(&Config::standby_loss(1));
    let survived = "a shard whose owner survived was taken over";
    let taken_over = |report: &mut Report| {
        let attempt = super::hosts::Attempt {
            shard: 3,
            host: H5,
            refused: None,
            commands: Vec::new(),
        };
        report.hosts.takeovers.push(attempt);
    };
    assert_eq!(rule(&standby, taken_over).rule(), Some(survived));

    let racing = passing(&Config::racing(1));
    let contended = Verdict::Unrun("witness second-reconciler-after-loss missing");
    assert_eq!(
        rule(&racing, |report| report.recon.contended = 0),
        contended
    );
    let conflicted = |report: &mut Report| {
        for (_, _, refused) in &mut report.recon.refusals {
            if let Refused::Discarded(step, _) = refused {
                *refused = Refused::Step(*step, StepVerdict::Wait(Reason::Unknown));
            }
        }
    };
    let stale = Verdict::Unrun("witness stale-designation-refused missing");
    assert_eq!(
        rule(&racing, conflicted),
        stale,
        "a designation that waits on an unknown write is no stale-tenure refusal"
    );
}

/// Preflight: a shape the scenario cannot run is refused before any draw, by its tenure budget, its zone count, its
/// reconciler count or its layout, and an episode the profile refuses is refused before any draw too.
#[test]
fn a_repair_shape_the_scenario_cannot_run_is_refused_before_any_draw() {
    use super::bounds::Refused;
    use super::hosts::Scenario;
    let refused = |config: Config| play(&config, || panic!("a draw preceded the refusal"));
    let mut two_zones = Config::settle(1);
    two_zones.shape = Config::dense(1).shape;
    assert_eq!(refused(two_zones), Err(Stopped::Shape(Refused::Zones(2))));
    let one = Config::repair(1, Scenario::Racing);
    assert_eq!(refused(one), Err(Stopped::Shape(Refused::Reconcilers(1))));
    for cell in CrashCell::all() {
        let mut two = Config::crash(1, cell);
        two.shape.reconcilers = 2;
        let refusal = Err(Stopped::Shape(Refused::Reconcilers(2)));
        assert_eq!(refused(two), refusal, "{}", cell.name());
    }
    for cell in super::volumes::ReplaceCell::all() {
        let mut two = Config::replace(1, cell);
        two.shape.reconcilers = 2;
        let refusal = Err(Stopped::Shape(Refused::Reconcilers(2)));
        assert_eq!(refused(two), refusal, "{}", cell.name());
    }
    let tiny = Config {
        scenario: Scenario::CensusFull,
        ..Config::tiny(1)
    };
    assert_eq!(
        refused(tiny),
        Err(Stopped::Shape(Refused::Placing(Placing::Tiny)))
    );
    let mut wide = Config::settle(1);
    wide.shape = Shape {
        placing: Placing::Drawn,
        partitions: 4,
        hosts: 16,
        shards: 32,
        cap: 32,
        ..wide.shape
    };
    assert_eq!(refused(wide), Err(Stopped::Shape(Refused::Tenures(160))));
    let mut crowded = Config::settle(1);
    crowded.shape = Shape {
        placing: Placing::Drawn,
        partitions: 4,
        hosts: 13,
        shards: 13,
        cap: 13,
        ..crowded.shape
    };
    assert_eq!(
        refused(crowded),
        Err(Stopped::Shape(Refused::Hosts(13))),
        "a zone of 13 hosts exceeds the 12 placements a host's detector accepts"
    );
    let legal = Config::foreign(1).arm_legal();
    let inadmissible = refused(legal);
    assert!(
        matches!(inadmissible, Err(Stopped::Inadmissible(_))),
        "{inadmissible:?}"
    );
}

/// A boot census under a cap of five cannot list s5's named standby. The loop plans nothing for a shard whose record
/// names a live standby, so s5 carries no blocker, F4 reads no reservation and no coverage, and F5 reads s5
/// unsettled.
#[test]
fn a_named_standby_the_boot_census_cannot_list_leaves_its_shard_uncovered_and_unsettled() {
    let mut config = Config::settle(1);
    config.shape.cap = 5;
    let report = run(&config).expect("a run that ends");
    assert_eq!(report.evidence.censuses, [5]);
    assert_eq!(blocked(&report, 6), None);
    assert!(report.recon.covered.is_empty() && report.recon.booted.contains(&1));
    assert_eq!(
        report.verdicts.census,
        Some(Verdict::Unrun(oracles::NO_RESERVATION)),
        "the loop reserves nothing for a shard whose record names a live standby"
    );
    assert_eq!(report.verdicts.settles.rule(), Some(oracles::UNSETTLED));
}

/// A forced decision records its index, and a replay that forces another index over the same candidates is refused
/// before the decision applies.
#[test]
fn a_replayed_forced_decision_holds_the_recorded_index() {
    use super::draws::{self, Draws, Tag};
    let mut recorded = Draws::record(1);
    let values = [0, 1];
    assert_eq!(
        recorded.forced(draws::RECONCILER, Tag::Actor, &values, 1),
        Ok(1)
    );
    let tape = recorded.finish().expect("a finished tape");
    let mut same = Draws::replay(tape.clone());
    assert_eq!(
        same.forced(draws::RECONCILER, Tag::Actor, &values, 1),
        Ok(1)
    );
    let mut other = Draws::replay(tape);
    let refused = other.forced(draws::RECONCILER, Tag::Actor, &values, 0);
    assert_eq!(refused.map_err(|refusal| refusal.applied), Err(0));
}

/// The scheduled case runs the thirteen repair and host scenario tests on root 2 (nine in this module, three in
/// `host_tests` and one in `tests`); the fast tier runs them on root 1. The scheduled case also runs the census and
/// settle controls and the dropped standby need's control on root 2, the census and settle siblings with the
/// stranded-s5 control on roots 1 and 2, the pinned runs on root 2, the four store-result cells of the serving duties
/// the fast tier leaves out on root 1, every store-result cell and both regressed reads on root 2, the committed
/// sibling of the unknown takeover swap on root 1, and the scheduled tier's 25 enrollment crash cells on root 1. Each
/// passing check or cell prints one line, and the last line counts the checks and the cells.
#[test]
#[ignore = "repair and host scenarios and the census and settle controls on their second root and the enrollment crash cells of the scheduled tier; the search-nightly lane's row fleet-scheduled-roots runs it with --ignored"]
fn the_repair_and_host_scenarios_pass_on_their_scheduled_roots() {
    use super::host_tests;
    use super::hosts::Unknown;
    /// A scenario's name, the root it runs on and the check that runs it on a root.
    type Check = (&'static str, u64, fn(u64));
    let checks: [Check; 21] = [
        (
            "settle",
            2,
            the_boot_survey_lists_every_named_standby_and_the_fleet_settles_with_six_census_entries_on,
        ),
        (
            "reenroll",
            2,
            after_a_host_loss_the_reconciler_reenrolls_four_standbys_and_every_shard_settles_on,
        ),
        (
            "standby-loss",
            2,
            a_lost_standby_host_moves_its_slots_to_running_hosts_with_no_takeover_on,
        ),
        (
            "double-loss",
            2,
            after_owner_and_standby_loss_fresh_hosts_take_the_retained_volumes_over_warm_on,
        ),
        (
            "partition-repair",
            2,
            a_lost_partition_takes_five_designations_above_the_threshold_and_names_self_suspicion_at_it_on,
        ),
        (
            "census-full",
            2,
            a_full_census_refuses_s5_both_needs_and_admits_it_on_a_released_entry_to_recover_warm_on,
        ),
        (
            "attach-cap",
            2,
            a_volume_at_three_attaches_redesignates_its_surviving_attached_host_or_closes_on,
        ),
        (
            "foreign",
            2,
            a_foreign_registrant_raises_retirement_requested_with_no_flip_and_no_create_on,
        ),
        (
            "racing",
            2,
            two_reconcilers_over_one_census_converge_on_one_designation_per_need_on,
        ),
        (
            "partition-loss",
            2,
            host_tests::a_lost_partition_takes_over_above_the_threshold_and_suspects_itself_at_it_on,
        ),
        (
            "false-suspicion",
            2,
            host_tests::a_false_suspicion_is_vetoed_and_its_isolated_sibling_nominates_on,
        ),
        (
            "deposed-owner",
            2,
            host_tests::a_paused_or_isolated_owner_withdraws_each_deposed_tenure_on,
        ),
        (
            "dense",
            2,
            super::tests::hosts_that_own_several_shards_in_two_zones_restart_them_warm_on,
        ),
        ("census-and-settle-controls", 2, |root| {
            census_and_settle_controls_on(root, &CONTROL_RULES)
        }),
        ("census-and-settle-siblings", 1, |root| {
            census_and_settle_siblings_on(root, &CONTROL_RULES)
        }),
        ("census-and-settle-siblings", 2, |root| {
            census_and_settle_siblings_on(root, &CONTROL_RULES)
        }),
        ("standby-need-dropped", 2, |root| {
            standby_need_dropped_on(root, oracles::UNSETTLED)
        }),
        ("pinned", 2, super::tests::pinned_runs_repeat_their_digests),
        ("takeover-unknown-committed", 1, |_| {
            host_tests::a_takeover_whose_swap_reply_is_unknown_recovers_on(true)
        }),
        ("handoff", 2, |root| {
            let _ = super::handoff_tests::an_admitted_transfer_s_target_reads_its_role_and_serves_through_its_lineage_arm_on(root);
        }),
        (
            "handoff-ended",
            2,
            super::handoff_tests::a_transfer_to_an_ended_target_parks_it_and_the_designated_host_takes_the_shard_over_warm_on,
        ),
    ];
    for (name, root, check) in checks {
        check(root);
        println!("fleet: scheduled repair-and-host {name} root {root}: pass");
    }
    // The store-result cells the fast tier leaves out, each printed under the name of the cell it ran.
    let unknown: Vec<Unknown> = (Unknown::all().into_iter())
        .filter(|cell| !host_tests::FAST_UNKNOWN.contains(cell))
        .collect();
    for &cell in &unknown {
        host_tests::store_unknown_cell_retries_in_place(1, cell);
        println!(
            "fleet: scheduled repair-and-host {} root 1: pass",
            cell.name()
        );
    }
    // Every store-result cell and both regressed reads on their second root.
    let second = Unknown::all();
    for &cell in &second {
        host_tests::store_unknown_cell_retries_in_place(2, cell);
        println!(
            "fleet: scheduled repair-and-host {} root 2: pass",
            cell.name()
        );
    }
    host_tests::a_regressed_read_withdraws_the_tenure_and_the_hosts_report_carries_the_regression_alarm_on(2);
    println!("fleet: scheduled repair-and-host regressed-reads root 2: pass");
    let cells: Vec<String> = (CrashCell::all().into_iter())
        .filter(|cell| !fast_cell(cell))
        .map(crash_cell_converges)
        .collect();
    for name in &cells {
        println!("fleet: scheduled repair-and-host {name} root 1: pass");
    }
    println!(
        "fleet: scheduled repair-and-host: {} checks and {} crash cells passed",
        checks.len() + unknown.len() + second.len() + 1,
        cells.len()
    );
}

/// The scheduled row's `repair-and-host <cell> root 1` members are exactly the enrollment crash cells the fast tier
/// leaves out, by the names the scheduled case prints.
#[test]
fn the_scheduled_row_lists_each_enrollment_crash_cell_the_fast_tier_leaves_out() {
    let members = super::tests::inventory_members("search-nightly", "fleet-scheduled-roots");
    let mut listed: Vec<&str> = (members.iter())
        .map(String::as_str)
        .filter(|member| {
            let cell = ["repair-and-host enroll-", "repair-and-host fresh-"];
            cell.iter().any(|kind| member.starts_with(kind)) && member.ends_with(" root 1")
        })
        .collect();
    let mut scheduled: Vec<String> = (CrashCell::all().into_iter())
        .filter(|cell| !fast_cell(cell))
        .map(|cell| format!("repair-and-host {} root 1", cell.name()))
        .collect();
    listed.sort_unstable();
    scheduled.sort_unstable();
    assert_eq!(listed, scheduled);
    let fast = CrashCell::all().into_iter().filter(fast_cell);
    let endings: BTreeSet<u8> = fast.clone().map(|cell| cell.ending as u8).collect();
    let layouts: BTreeSet<bool> = fast.map(|cell| cell.fresh).collect();
    assert_eq!((endings.len(), layouts.len()), (3, 2));
}

/// F6 in a reconciler scenario divides each recovery share over the shape's static roles bound and compares it with
/// the most roles each host held: the re-enrollment run passes, and a share built over one owner fails by the roles
/// rule on the standby that takes s3 over and on a fresh host that takes a shard over after a double loss.
#[test]
fn a_reconciler_run_judges_the_host_share_over_the_roles_bound_and_the_peak_roles() {
    let roles = "a host's roles exceed the owners its recovery share divides over";
    let report = passing(&Config::reenroll(1));
    assert_eq!(report.verdicts.within_share, Verdict::Pass);
    let whole = planted(Config::reenroll(1), Plant::WholeShare, 3);
    assert_eq!(whole.verdicts.within_share.rule(), Some(roles));
    let fresh = planted(Config::double_loss(1), Plant::WholeShare, 2);
    assert_eq!(fresh.verdicts.within_share.rule(), Some(roles));
}

/// `Reconciler::designate` reads the census after the shard record and writes the shard record on that read's
/// version alone. Inside the census read of loop 0's first designation after H0's loss, a simulated second writer
/// moves that shard's slot to another running host. The designation commits the planned host, so the
/// shard names a standby whose census slot names another host. Under SLOT-HOST the census entry selects the
/// candidate: the loop resumes the slot host's enrollment and designates it over the named standby, so the record
/// and the census name one host, no blocker stands, and F4 and F5 pass. The run does not reach SLOT-HOST's other
/// settled outcome, a slot host that stays refused with no attach request for `attach_stuck_us`, after which the
/// named standby takes the slot back; `failover::zone_loop::tests::slot_host` covers it.
#[test]
fn a_slot_moved_inside_a_designation_designates_the_slot_s_host_over_the_named_standby_and_settles()
{
    let report = run(&Config::slot_moved(1)).expect("a run inside the limits");
    assert_eq!(report.credit(), Verdict::Pass, "{}", report.summary());
    let (shard, planned, moved) = report.recon.slot_moved.expect("the slot moved");
    assert_ne!(planned, moved);
    assert_eq!(designated(&report, shard), [planned, moved]);
    let record = last_records(&report)[shard as usize - 1];
    assert_eq!(record.standby.map(|host| host.get()), Some(moved));
    let slot = report.evidence.slots[shard as usize - 1].1;
    assert_eq!(slot.map(|host| host.get()), Some(moved));
    assert_eq!(report.verdicts.census, Some(Verdict::Pass));
    assert_eq!(blocked(&report, shard), None);
    assert_eq!(report.verdicts.settles, Verdict::Pass);
}
