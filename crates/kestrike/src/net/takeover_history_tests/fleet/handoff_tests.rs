use super::hosts::{self, HANDOFF_CELL};
use super::*;
use crate::failover::restart::{Check, Local};
use crate::host::{Exit, Refusal, Rerun};

const H1: u64 = 1002;
const H4: u64 = 1005;
const S6: u32 = HANDOFF_CELL as u32 + 1;

fn handed(report: &Report) -> &handoff::Handed {
    let handoffs = &report.hosts.handoffs;
    assert_eq!(handoffs.len(), 1, "{handoffs:?}");
    let handed = &handoffs[0];
    assert_eq!(
        (handed.shard, handed.from, handed.to, handed.committed),
        (S6, H4, H1, true),
        "{handed:?}"
    );
    assert_eq!(handed.exit, Some(Exit::Stopped));
    handed
}

fn from_transfer(report: &Report) -> Vec<ShardRecord> {
    let (_, versions) = &report.evidence.histories[HANDOFF_CELL];
    let at = (versions.iter())
        .position(|record| record.owner.get() == H1)
        .expect("a version naming the target owner");
    versions[at - 1..].to_vec()
}

#[test]
fn an_admitted_transfer_s_target_reads_its_role_and_serves_through_its_lineage_arm() {
    let report =
        an_admitted_transfer_s_target_reads_its_role_and_serves_through_its_lineage_arm_on(1);
    // H1's recovery counts its rounds from the round its wait read the role change, with no crash before it.
    let last = report.shards[HANDOFF_CELL].recoveries.last();
    let last = last.expect("H1's load");
    assert_eq!((last.after_crash, last.rounds), (false, 18));
}

pub(super) fn an_admitted_transfer_s_target_reads_its_role_and_serves_through_its_lineage_arm_on(
    root: u64,
) -> Report {
    let config = Config::handoff(root);
    let report = run_shared(&config).expect("a run inside the limits");
    assert_eq!(replay(&config, &report.recording()).as_ref(), Ok(&report));
    assert_eq!(
        report.credit(),
        Verdict::Pass,
        "{}",
        report.lines().join("\n")
    );
    handed(&report);
    let versions = from_transfer(&report);
    let (outgoing, transferred) = (versions[0], versions[1]);
    assert_eq!(outgoing.owner.get(), H4);
    assert_eq!(
        (
            transferred.owner.get(),
            transferred.standby,
            transferred.attempts
        ),
        (H1, None, outgoing.attempts + 1)
    );
    assert_eq!(
        (transferred.generation, transferred.active),
        (outgoing.generation, outgoing.active)
    );
    let restarted = versions[2];
    assert_eq!(
        (restarted.owner.get(), restarted.attempts),
        (H1, transferred.attempts + 1),
        "H1's own bump opens its tenure"
    );
    let shard = &report.shards[HANDOFF_CELL];
    assert_eq!(shard.wait_exits, ["Rerun(RoleChanged)"]);
    assert!(
        (report.hosts.role_changes.iter()).any(|&(_, of, host)| of == S6 && host == H1),
        "{:?}",
        report.hosts.role_changes
    );
    assert!(
        (report.volumes.arm.iter()).any(|&(of, host, _)| of == S6 && host == H1),
        "{:?}",
        report.volumes.arm
    );
    let last = shard.recoveries.last().expect("H1's load");
    assert_eq!(last.host.get(), H1);
    let (requested, served) = last.sweep.expect("H1's sweep");
    assert!(requested > 0 && requested == served, "{:?}", last.sweep);
    let hosts: Vec<u64> = shard.activated.iter().map(|(_, host)| host.get()).collect();
    assert_eq!(hosts, [H4, H1]);
    assert_eq!(handed(&report).attempts, Some(transferred.attempts));
    let (h1, _) = shard.activated[1];
    assert_eq!(
        h1,
        crate::oracle::Tenure {
            g: restarted.generation.get(),
            a: u64::from(restarted.attempts) * 2
        },
        "H1 activates at its own bump, not at the attempt the transfer wrote"
    );
    assert!(report.hosts.takeovers.is_empty());
    assert!(report.hosts.parks.is_empty(), "{:?}", report.hosts.parks);
    // The host loop ran one next incarnation for a rerun exit, the target's, on a free slot of a running host.
    let log = &report.hosts;
    assert_eq!(
        (log.refused_reruns, log.rerun_dropped, log.unslotted),
        (1, 0, 0)
    );
    report
}

#[test]
fn control_a_target_whose_wait_stops_at_the_transfer_never_serves_through_its_lineage_arm() {
    let config = Config::handoff(1).hostile(Plant::TargetUnwaited, HANDOFF_CELL as u32);
    let report = run_shared(&config).expect("a run inside the limits");
    assert!(report.planted);
    assert_eq!(
        hosts::TARGET_SERVED,
        "witness target-lineage-served missing"
    );
    assert_eq!(
        hosts::expected(&report),
        Verdict::Unrun(hosts::TARGET_SERVED),
        "{}",
        report.lines().join("\n")
    );
    handed(&report);
    assert!(report.hosts.role_changes.is_empty());
    let hosts: Vec<u64> = (report.shards[HANDOFF_CELL].activated.iter())
        .map(|(_, host)| host.get())
        .collect();
    assert_eq!(hosts, [H4]);
}

#[test]
fn a_transfer_to_an_ended_target_parks_it_and_the_designated_host_takes_the_shard_over_warm() {
    a_transfer_to_an_ended_target_parks_it_and_the_designated_host_takes_the_shard_over_warm_on(1);
}

pub(super) fn a_transfer_to_an_ended_target_parks_it_and_the_designated_host_takes_the_shard_over_warm_on(
    root: u64,
) {
    let config = Config::handoff_ended(root);
    let report = run_shared(&config).expect("a run inside the limits");
    assert_eq!(replay(&config, &report.recording()).as_ref(), Ok(&report));
    assert_eq!(
        report.credit(),
        Verdict::Pass,
        "{}",
        report.lines().join("\n")
    );
    assert!(handed(&report).ended);
    let versions = from_transfer(&report);
    assert_eq!(
        (versions[1].owner.get(), versions[1].standby),
        (H1, None),
        "the record names the ended target"
    );
    // The ended target writes nothing: no version names H1 at a later attempt than the transfer's.
    let bumped = (versions.iter())
        .any(|record| record.owner.get() == H1 && record.attempts != versions[1].attempts);
    assert!(!bumped, "{versions:?}");
    let parks = &report.hosts.parks;
    assert_eq!(parks.len(), 1, "{parks:?}");
    let park = &parks[0];
    assert_eq!((park.shard, park.host), (S6, H1));
    assert_eq!(
        park.exit,
        Exit::Refused(Refusal::Restart(Check::Local(Local::Ended)))
    );
    assert!(park.commands.is_empty(), "{:?}", park.commands);
    // Two next incarnations ran for a rerun exit: the target's restart that parks, and its rerun when the park ends.
    assert_eq!(report.hosts.refused_reruns, 2);
    let (left, exit) = park.left.clone().expect("the park ends at the takeover");
    assert_eq!(exit, Some(Exit::Rerun(Rerun::RoleChanged)));
    assert!(park.periods > 1 && left > park.round, "{park:?}");
    assert!(
        !(report.hosts.held.iter()).any(|&(_, host, shard)| host == H1 && shard == S6),
        "{:?}",
        report.hosts.held
    );
    assert!(report.hosts.parked_published.is_empty());
    assert_eq!(
        report.hosts.exempt,
        std::collections::BTreeSet::from([S6]),
        "H1's health bit drops once its silence passes the scaled grace"
    );
    let fresh = crate::failover::standbys::Need::Fresh;
    let designated = (report.recon.designations.iter())
        .find(|d| d.shard == S6 && d.repair == reconcile::Repair::Need(fresh))
        .expect("a fresh-host designation of s6");
    assert_eq!(
        designated.host, H4,
        "the fresh need prefers the host with a live attach, the outgoing owner"
    );
    assert!(report.hosts.nominations > 0);
    let taken: Vec<(u32, u64)> = (report.hosts.takeovers.iter())
        .filter(|attempt| attempt.refused.is_none())
        .map(|attempt| (attempt.shard, attempt.host))
        .collect();
    assert_eq!(taken, [(S6, H4)]);
    let last = report.shards[HANDOFF_CELL]
        .recoveries
        .last()
        .expect("H4's load");
    assert_eq!(last.host.get(), H4);
    let (requested, served) = last.sweep.expect("H4's sweep");
    assert!(requested > 0 && requested == served, "{:?}", last.sweep);
    assert_eq!(report.verdicts.settles, Verdict::Pass);
}

#[test]
fn control_a_restart_that_reports_after_its_ended_refusal_fails_the_parked_device_rule() {
    let config = Config::handoff_ended(1).hostile(Plant::ParkedCommand, HANDOFF_CELL as u32);
    let report = run_shared(&config).expect("a run inside the limits");
    assert!(report.planted, "{}", report.summary());
    let parks = &report.hosts.parks;
    assert_eq!(parks.len(), 1, "{parks:?}");
    // One Report from the restart, before the park, and one from the park's first view period.
    assert_eq!(parks[0].commands, ["report", "report"]);
    match hosts::expected(&report) {
        Verdict::Fail(rule, at) => {
            assert_eq!(
                rule,
                "a restart that refused its ended attach issued a reservation command"
            );
            assert!(at.starts_with(&format!("shard {S6} host {H1}")), "{at}");
        }
        other => panic!("{other:?}\n{}", report.lines().join("\n")),
    }
}

#[test]
fn control_a_parked_target_whose_health_bit_never_drops_leaves_its_shard_unsettled() {
    let config = Config::handoff_ended(1).hostile(Plant::UnscaledGrace, HANDOFF_CELL as u32);
    let report = run_shared(&config).expect("a run inside the limits");
    assert!(report.planted);
    assert!(handed(&report).ended);
    let fresh = crate::failover::standbys::Need::Fresh;
    let designated = (report.recon.designations.iter())
        .find(|d| d.shard == S6 && d.repair == reconcile::Repair::Need(fresh))
        .expect("a fresh-host designation of s6");
    assert!(
        report.rounds > designated.round + hosts::HANDOFF_GRACE_ROUNDS,
        "the run outlasts the scaled grace after the designation"
    );
    assert_eq!(
        report.verdicts.settles,
        Verdict::Fail(
            "a shard reached neither a serving owner with an enrolled standby nor a named blocker within the settle bound",
            format!("shard {S6}")
        ),
        "{}",
        report.lines().join("\n")
    );
    let park = &report.hosts.parks[0];
    assert_eq!(park.host, H1);
    assert_eq!(
        park.exit,
        Exit::Refused(Refusal::Restart(Check::Local(Local::Ended)))
    );
    assert!(park.left.is_none(), "{park:?}");
    assert!(!report.hosts.exempt.contains(&S6));
    assert_eq!(report.hosts.nominations, 0);
    assert!(report.hosts.takeovers.is_empty());
}

#[test]
fn control_a_parked_process_that_publishes_a_status_fails_the_parked_status_rule() {
    let config = Config::handoff_ended(1).hostile(Plant::ParkedPublishes, HANDOFF_CELL as u32);
    let report = run_shared(&config).expect("a run inside the limits");
    match hosts::expected(&report) {
        Verdict::Fail(rule, at) => {
            assert_eq!(rule, "a parked process published a status");
            assert!(at.starts_with(&format!("shard {S6} host {H1}")), "{at}");
        }
        other => panic!("{other:?}\n{}", report.lines().join("\n")),
    }
}

#[test]
fn control_a_parked_process_that_publishes_an_entryless_withdrawn_status_fails_the_parked_status_rule()
 {
    let config = Config::handoff_ended(1).hostile(Plant::ParkedWithdraws, HANDOFF_CELL as u32);
    let report = run_shared(&config).expect("a run inside the limits");
    assert!(report.planted, "{}", report.summary());
    match hosts::expected(&report) {
        Verdict::Fail(rule, at) => {
            assert_eq!(rule, "a parked process published a status");
            assert!(at.starts_with(&format!("shard {S6} host {H1}")), "{at}");
        }
        other => panic!("{other:?}\n{}", report.lines().join("\n")),
    }
}

/// Each handoff witness reads `Unrun` under its own name when the evidence it reads is taken out of a passing
/// report: the committed handoff, the target's role change and its lineage arm, the park's end at a role change,
/// the fresh-need designation of another host, and the nomination and the designated host's takeover.
#[test]
fn each_handoff_witness_reads_unrun_by_its_name_when_its_evidence_is_missing() {
    let plain = run_shared(&Config::handoff(1)).expect("a run inside the limits");
    let ended = run_shared(&Config::handoff_ended(1)).expect("a run inside the limits");
    for report in [&plain, &ended] {
        assert_eq!(hosts::expected(report), Verdict::Pass);
    }
    let without = |report: &Report, take: fn(&mut Report)| {
        let mut altered = report.clone();
        take(&mut altered);
        hosts::expected(&altered)
    };
    type Case<'r> = (&'r Report, fn(&mut Report), &'static str);
    let cases: [Case<'_>; 8] = [
        (
            &plain,
            |r| r.hosts.handoffs[0].committed = false,
            hosts::HANDED_OFF,
        ),
        (
            &ended,
            |r| r.hosts.handoffs[0].committed = false,
            hosts::HANDED_OFF,
        ),
        (
            &plain,
            |r| r.hosts.role_changes.clear(),
            hosts::TARGET_SERVED,
        ),
        (&plain, |r| r.volumes.arm.clear(), hosts::TARGET_SERVED),
        (
            &ended,
            |r| r.hosts.parks[0].left = None,
            hosts::TARGET_PARKED,
        ),
        (
            &ended,
            |r| r.recon.designations.retain(|d| d.shard != S6),
            hosts::FRESH_DESIGNATED,
        ),
        (
            &ended,
            |r| r.hosts.nominations = 0,
            hosts::DESIGNATED_RECOVERED,
        ),
        (
            &ended,
            |r| r.hosts.takeovers.clear(),
            hosts::DESIGNATED_RECOVERED,
        ),
    ];
    for (at, (report, take, witness)) in cases.into_iter().enumerate() {
        assert_eq!(without(report, take), Verdict::Unrun(witness), "case {at}");
    }
}
