use std::collections::BTreeSet;

use super::hosts::{self, Scenario};
use super::oracles::{self, Admission, Admitted};
use super::reconcile::Refused;
use super::volume_tests::{entered, passing, provisions_nothing};
use super::*;
use crate::failover::zone_loop::status::Blocker;
use crate::net::ownership::Shard;

const H0: u64 = 1001;
const H3: u64 = 1004;
/// The shards of zone 1, the zone the zone scenarios stop.
const DOWN: [u32; 6] = [1, 2, 3, 4, 5, 6];

/// The zone-loss case on root 1, which `run_shared` runs once for the tests that read it.
fn loss_on_root_1() -> Report {
    passing(&Config::zone_loss(1))
}

/// Zone 2 kept its boot tenures, owners and records through the outage, and served every GET drawn for it. `drawn`
/// is the least count of those GETs: the outage's episode and the return's episode each draw the configured
/// requests among zone 2's shards alone, since no shard of zone 1 serves then.
fn other_zone_untouched(report: &Report, drawn: std::ops::RangeInclusive<u32>) {
    let zones = &report.zones;
    assert_eq!(
        (&zones.other_moved, &zones.other_censuses),
        (&vec![], &vec![])
    );
    let (mut served, mut offered) = (0, 0);
    for shard in &report.shards[DOWN.len()..] {
        let at = shard.placement.shard.get();
        assert_eq!(
            shard.recoveries.len(),
            1,
            "shard {at} keeps its boot tenure"
        );
        assert_eq!(
            shard.neighbour.served, shard.neighbour.offered,
            "shard {at}"
        );
        assert_eq!(entered(report, at), [], "shard {at}");
        let (_, versions) = &report.evidence.histories[at as usize - 1];
        let owners: BTreeSet<u64> = versions.iter().map(|record| record.owner.get()).collect();
        assert_eq!(owners.len(), 1, "shard {at}");
        served += shard.neighbour.served;
        offered += shard.neighbour.offered;
    }
    assert_eq!(served, offered);
    assert!(drawn.contains(&offered), "{offered} GETs drawn for zone 2");
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
}

/// Each of the six returning owners restarted at its shard's next attempt, swept its seven retained objects outside
/// the acknowledged INVALIDATE, acknowledged a FILL and an INVALIDATE, and was judged by the fence check.
fn six_owners_returned_warm(report: &Report) {
    let zones = &report.zones;
    let shards: BTreeSet<u32> = zones.restarts.iter().map(|(shard, ..)| *shard).collect();
    assert_eq!(shards, BTreeSet::from(DOWN));
    assert_eq!((zones.restarts.len(), zones.acknowledged), (6, 6));
    for &(shard, host, tenure, from) in &zones.restarts {
        let report_of = &report.shards[shard as usize - 1];
        let recoveries = &report_of.recoveries;
        let last = recoveries.last().expect("the returning tenure");
        let before = &recoveries[recoveries.len() - 2];
        assert_eq!(
            (last.tenure, last.host.get()),
            (tenure, host),
            "shard {shard}"
        );
        assert_eq!(
            tenure.a,
            before.tenure.a + 2,
            "shard {shard} bumps its attempt"
        );
        assert_eq!(last.sweep, Some((7, 7)), "shard {shard} loads warm");
        assert_eq!(u64::from(report_of.attempts) * 2, tenure.a, "shard {shard}");
        let first = (report.evidence.admissions.iter())
            .find(|of| of.shard.get() == shard && of.tenure == tenure)
            .expect("the returning tenure's first admission");
        assert_eq!(first.admitted, Admitted::Hit, "shard {shard}");
        assert_eq!(
            tenure.a,
            (u64::from(from) + 1) * 2,
            "shard {shard} is one attempt above the record its restart read"
        );
        // The stamp is taken when the first hit's GET is sent: each page then holds its fence commit as its last
        // version, and the tenure's INVALIDATE commits one more version on its page afterwards.
        let (_, pages) = &report.evidence.fences[shard as usize - 1];
        let commits = oracles::fence_commits(pages, tenure);
        let stamped: Vec<Option<usize>> = first.pages.iter().copied().map(Some).collect();
        assert_eq!(stamped, commits, "shard {shard}");
        let later: usize = pages.iter().map(Vec::len).sum();
        assert!(later > first.pages.iter().sum(), "shard {shard}");
    }
    assert_eq!(
        report.hosts.stale_hits, 0,
        "no acknowledged INVALIDATE is lost"
    );
    assert_eq!(report.verdicts.fenced, Some(Verdict::Pass));
    assert_eq!(report.verdicts.one_owner, Verdict::Pass);
}

/// The `az` topology passes the shape check with ten hosts: zone 1 holds `small` and zone 2 `tiny` on its own four
/// hosts. The no-fault sibling settles with one census per zone, eight entries in all, no restart after boot, and
/// a first admission judged for each of the eight boot tenures.
#[test]
fn az_places_small_and_tiny_in_two_zones_and_settles_with_no_fault() {
    let config = Config::az_settle(1);
    assert_eq!(config.shape.check(), Ok(()));
    assert_eq!(config.shape.members(), 10);
    az_settles_with_no_fault_on(1);
    let mut misplaced = config.shape;
    misplaced.shards = 6;
    let refused = bounds::Refused::Placing(topology::Placing::Az);
    assert_eq!(misplaced.check(), Err(refused));
}

/// The no-fault run on `az` on `root`: the fixed placement, one census per zone with eight entries in all, no restart
/// after boot, no takeover and no crash, a first admission judged for each of the eight boot tenures, and nothing
/// provisioned.
fn az_settles_with_no_fault_on(root: u64) {
    let report = passing(&Config::az_settle(root));
    let placed: Vec<(u16, u64, u64)> = (report.shards.iter())
        .map(|shard| {
            (
                shard.placement.zone.0,
                shard.owner.get(),
                shard.standby.get(),
            )
        })
        .collect();
    let small = [
        (1, 1001, 1004),
        (1, 1001, 1004),
        (1, 1001, 1006),
        (1, 1004, 1001),
        (1, 1003, 1006),
        (1, 1005, 1002),
    ];
    assert_eq!(placed[..6], small);
    assert_eq!(placed[6..], [(2, 2001, 2002), (2, 2004, 2003)]);
    assert_eq!(report.evidence.censuses, [6, 2]);
    assert_eq!(report.evidence.census_entries, 8);
    assert_eq!(report.zones, zones::ZoneLog::default());
    assert_eq!(report.recon.blockers, []);
    assert!(
        report
            .shards
            .iter()
            .all(|shard| shard.recoveries.len() == 1)
    );
    assert_eq!(report.verdicts.fenced, Some(Verdict::Pass));
    assert_eq!(report.evidence.admissions.len(), 8);
    assert_eq!((report.takeovers, report.crashes), (0, 0));
    provisions_nothing(&report);
}

/// HOST-LOSS-KEEPS-VOLUME: every host of zone 1 stops while the store and both reconcilers stay
/// up. No takeover starts in zone 1, its six shards carry `NoEligibleHost` behind the candidate choice's refusal, and
/// the outage writes no shard record, volume record or receipt for zone 1 and calls no provider. Zone 2's records,
/// census and tenures stay as they were and its GETs settle. On return each owner restarts by an attempt bump,
/// commits its last coverage fence before its first admitted operation and serves its retained set warm, in an
/// order the run's decisions draw.
#[test]
fn a_lost_zone_keeps_its_volumes_under_a_blocker_and_each_owner_returns_fenced_and_warm() {
    keeps_its_volumes_and_returns_fenced_and_warm(&loss_on_root_1());
}

/// The checks of the zone-loss case on one run; the scheduled case runs root 2.
fn keeps_its_volumes_and_returns_fenced_and_warm(report: &Report) {
    let zones = &report.zones;
    assert_eq!(zones.down, DOWN);
    assert!(zones.returned);
    assert_eq!(zones.unplaced, DOWN);
    assert_eq!((zones.down_writes, zones.down_calls), (0, 0));
    for shard in DOWN {
        let entered = entered(report, shard);
        assert!(
            entered.contains(&Blocker::NoEligibleHost),
            "shard {shard}: {entered:?}"
        );
        let refused = report.recon.refusals.iter();
        let backing = refused.filter(|(_, of, _)| *of == shard);
        let named = |(_, _, refused): &&(u64, u32, Refused)| {
            matches!(refused, Refused::Status(_, Blocker::NoEligibleHost))
        };
        assert!(backing.into_iter().any(|entry| named(&entry)));
    }
    assert_eq!((report.takeovers, report.hosts.nominations), (0, 0));
    assert_eq!((report.crashes, report.hosts.host_losses), (6, 6));
    assert_eq!(report.evidence.losses.hosts, DOWN);
    assert_eq!(report.verdicts.keeps_volume, Verdict::Pass);
    provisions_nothing(report);
    other_zone_untouched(report, 4..=4);
    six_owners_returned_warm(report);
    assert!(zones.deposed.is_empty());
    assert_eq!(
        zones.fence_writes, 12,
        "two pages for each returning tenure"
    );
    let settled_in = zones
        .settled_in
        .expect("every returned shard served with a standby");
    assert!(
        settled_in <= reconcile::REPAIR_SETTLE_ROUNDS,
        "{settled_in}"
    );
    let printed = report.lines().join("\n");
    assert!(printed.contains(" fence-writes 12 "), "{printed}");
    let settled = report.evidence.settled.iter();
    assert!(
        settled
            .into_iter()
            .all(|shard| shard.served && shard.blocker.is_none())
    );
    assert_eq!(report.verdicts.settles, Verdict::Pass);
}

/// LOSS-NEEDS-EVIDENCE: while zone 1 is down the control plane reports each of its volumes impaired.
/// `Reconciler::replacement` retains each one, the shard carries `VolumeImpaired`, and nothing is provisioned. The
/// return is the zone-loss case's.
#[test]
fn impaired_evidence_for_a_down_zone_retains_every_volume_and_provisions_nothing() {
    let report = passing(&Config::zone_impaired(1));
    assert_eq!(report.volumes.retained, 6);
    assert_eq!(report.zones.impaired, DOWN);
    for shard in DOWN {
        assert!(entered(&report, shard).contains(&Blocker::VolumeImpaired));
        let refused = report.recon.refusals.iter();
        let retained = refused.filter(|(_, of, r)| {
            *of == shard && matches!(r, Refused::Status(_, Blocker::VolumeImpaired))
        });
        assert_eq!(retained.count(), 1, "shard {shard}");
    }
    assert_eq!((report.zones.down_writes, report.zones.down_calls), (0, 0));
    assert_eq!(report.takeovers, 0);
    provisions_nothing(&report);
    other_zone_untouched(&report, 4..=4);
    six_owners_returned_warm(&report);
}

/// One owner per tenure: H3 crashes and H0 takes s3 over before the zone stops. On return H3's role read of s3 names
/// it unnamed under a record that names H0, so its incarnation waits and serves nothing, and H0 restarts s3 at the
/// next attempt.
#[test]
fn a_returning_host_whose_record_names_another_owner_waits_unnamed_and_serves_nothing() {
    let report = passing(&Config::zone_deposed(1));
    let zones = &report.zones;
    let [(shard, host, check, attempts)] = &zones.deposed[..] else {
        panic!("one deposed host: {:?}", zones.deposed);
    };
    assert_eq!((*shard, *host, check.as_str()), (4, H3, "Unnamed"));
    // H0's takeover left the record at attempt 6, and H0's restart on return raises it to 7.
    assert!([6, 7].contains(attempts), "{attempts}");
    assert_eq!(report.takeovers, 1);
    let activations = report.evidence.activations.iter();
    let by_h3: Vec<Tenure> = activations
        .filter(|(shard, _, host)| shard.get() == 4 && host.get() == H3)
        .map(|(_, tenure, _)| *tenure)
        .collect();
    assert_eq!(
        by_h3,
        [Tenure { g: 3, a: 10 }],
        "H3 activated its boot tenure alone"
    );
    let returned = zones.restarts.iter().find(|(shard, ..)| *shard == 4);
    assert_eq!(returned, Some(&(4, H0, Tenure { g: 3, a: 14 }, 6)));
    let s3 = &report.shards[3].recoveries;
    let hosts: Vec<u64> = s3.iter().map(|recovered| recovered.host.get()).collect();
    assert_eq!(hosts, [H3, H0, H0]);
    assert_eq!((zones.down_writes, zones.down_calls), (0, 0));
    provisions_nothing(&report);
    other_zone_untouched(&report, 4..=8);
    six_owners_returned_warm(&report);
}

/// The deposed-owner guard of a returning restart, from a produced log: under plant
/// `ForeignPreRead` (code 96) the returning restart of s2 reads its pre-read record with another host named owner while
/// its incarnation acquires a tenure. `Fleet::restart_by` drops that tenure unserved, the zone log names the host
/// deposed with the `Restarted` check, and the zone outcome fails DEPOSED_SERVED by name; s2 keeps no recovery by its
/// returning owner, and its activations hold no tenure past the boot one.
#[test]
fn a_returning_restart_under_a_foreign_pre_read_drops_its_tenure_and_fails_deposed_served() {
    let rule = "a deposed host served after its zone returned";
    assert_eq!(rule, hosts::DEPOSED_SERVED);
    let report = run(&Config::zone_loss(1).hostile(Plant::ForeignPreRead, 2))
        .expect("a run inside the limits");
    assert!(report.planted);
    assert_eq!(
        hosts::expected(&report).rule(),
        Some(rule),
        "{}",
        report.summary()
    );
    let deposed: Vec<_> = (report.zones.deposed.iter())
        .map(|(shard, _, check, _)| (*shard, check.as_str()))
        .collect();
    assert_eq!(deposed, [(3, super::zones::RESTARTED)]);
    let activated = (report.evidence.activations.iter()).filter(|(shard, ..)| shard.get() == 3);
    assert_eq!(activated.count(), 1, "the boot tenure alone");
    assert_eq!(
        report.shards[2].recoveries.len(),
        1,
        "the boot recovery alone"
    );
}

/// When the shard record names another owner, both role-read outcomes of the returning host leave the cell
/// unblocked. `zones::deposed` accepts the logged check when the role read succeeds and rejects it when the read
/// fails.
#[test]
fn a_returning_hosts_failed_role_read_under_another_owners_record_leaves_the_cell_unblocked() {
    let returned = |stopped: bool| {
        let config = Config::zone_deposed(1);
        let mut draws = Draws::record(config.root);
        let seeded = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS);
        let mut fleet = seeded.expect("a recorded topology");
        fleet.start_hosts();
        let at = 3;
        let member = fleet.cells[at].placement.owner;
        // The write models a completed takeover by the successor before the former owner returns.
        let members = &fleet.topology.members;
        let successor = members[(member + 1) % members.len()].host;
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
        if stopped {
            let mut store = fleet.faults.store.borrow_mut();
            store.outage(Some(member as u32), 0, u64::MAX);
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
        let returning = fleet.restart_returned(&mut live, &mut slots, (at, member));
        returning.expect("a return that stops on no wait");
        assert_eq!(slots.used, [false]);
        let cell = &fleet.cells[at];
        let state = (cell.blocked, cell.blockers.clone(), cell.flip_requests);
        (fleet.zone_log.deposed.clone(), state, taken.attempts)
    };

    let unchanged = (false, Vec::new(), 0);
    let (deposed, cell, attempts) = returned(false);
    let [(shard, host, check, read)] = &deposed[..] else {
        panic!("one deposed host: {deposed:?}");
    };
    assert_eq!((*shard, *host, *read), (4, H3, attempts));
    assert!(super::zones::deposed(check), "{check}");
    assert_eq!(cell, unchanged);

    let (deposed, cell, attempts) = returned(true);
    let [(shard, host, check, read)] = &deposed[..] else {
        panic!("one deposed host: {deposed:?}");
    };
    assert_eq!((*shard, *host, *read), (4, H3, attempts));
    assert!(!super::zones::deposed(check), "{check}");
    assert_eq!(cell, unchanged);
}

/// `zones::deposed` depends on the `Debug` text in a returning host's check, so the cases format production values.
#[test]
fn the_deposed_witness_accepts_a_waiting_role_and_a_deposed_refusal_alone() {
    use crate::failover::report::RecoveryCheck;
    use crate::failover::retire::Target;
    use crate::host::Role;
    use crate::net::ownership::ShardGeneration;
    use crate::storage::store::StoreError;

    let target = Target {
        generation: ShardGeneration::new(3).unwrap(),
        owner: Host::new(H0).unwrap(),
        attempts: 6,
    };
    let named = |check: &dyn std::fmt::Debug| format!("{check:?}");
    for witness in [
        named(&Role::Unnamed),
        named(&Role::Standby { target }),
        named(&RecoveryCheck::Deposed),
    ] {
        assert!(super::zones::deposed(&witness), "{witness}");
    }
    for other in [
        super::zones::RESTARTED.to_owned(),
        named(&Role::Restart),
        named(&Role::Retired),
        named(&RecoveryCheck::NotHolding),
        named(&StoreError::Unavailable),
    ] {
        assert!(!super::zones::deposed(&other), "{other}");
    }
}

/// Control of the fence-before-admission check: the log of one returning tenure's first admitted operation is moved
/// ahead of its fence commits. The run fails by the check's rule naming the shard, with the six returning tenures
/// judged, and the unplanted sibling passes.
#[test]
fn control_an_admission_logged_ahead_of_its_fence_fails_fence_before_admission() {
    let rule = "a tenure admitted an operation before its last coverage fence commit";
    let sibling = &loss_on_root_1();
    assert_eq!(sibling.verdicts.fenced, Some(Verdict::Pass));
    assert_eq!(sibling.credit(), Verdict::Pass);
    let config = Config::zone_loss(1).hostile(Plant::EarlyAdmission, 2);
    let report = run(&config).expect("a run inside the limits");
    assert!(report.planted);
    let at = "shard 3 tenure Tenure { g: 3, a: 12 } Hit".to_owned();
    let failed = Verdict::Fail(rule, at);
    assert_eq!(report.verdicts.fenced, Some(failed.clone()));
    assert_eq!(report.credit(), failed);
    assert_eq!(report.zones.restarts.len(), 6);
    let judged = (report.zones.restarts.iter()).filter(|&&(shard, _, tenure, _)| {
        let admissions = report.evidence.admissions.iter();
        admissions
            .into_iter()
            .any(|of| of.shard.get() == shard && of.tenure == tenure)
    });
    assert_eq!(judged.count(), 6, "fence-before-admission checked");
}

/// The check takes a tenure's fence commit on a page as the first version carrying its session. It passes an
/// admission at or after every page's fence commit, a later coverage write of the tenure included, fails an admission
/// before one page's fence commit, a page the tenure never fenced, a page count that differs and an unknown shard,
/// and reads a run with no admission `Unrun`.
#[test]
fn the_fence_check_fails_an_early_admission_by_name_and_reads_no_admission_unrun() {
    let order = "a tenure admitted an operation before its last coverage fence commit";
    let shard = Shard::new(1).unwrap();
    let tenure = Tenure { g: 3, a: 12 };
    let (old, own) = ((3 << 32) | 10, (3 << 32) | 12);
    let fences = vec![(shard, vec![vec![old, own, own], vec![old, old, own]])];
    let admitted = |pages: Vec<usize>| {
        vec![Admission {
            shard,
            tenure,
            admitted: Admitted::Fill,
            pages,
        }]
    };
    let judge = |admissions: &[Admission]| oracles::fenced_before_admission(&fences, admissions);
    assert_eq!(
        oracles::fence_commits(&fences[0].1, tenure),
        [Some(2), Some(3)]
    );
    assert_eq!(judge(&admitted(vec![2, 3])), Verdict::Pass);
    assert_eq!(judge(&admitted(vec![3, 3])), Verdict::Pass);
    let early = judge(&admitted(vec![2, 2]));
    let at = "shard 1 tenure Tenure { g: 3, a: 12 } Fill".to_owned();
    assert_eq!(early, Verdict::Fail(order, at));
    assert_eq!(judge(&admitted(vec![1, 3])).rule(), Some(order));
    assert_eq!(judge(&admitted(vec![3])).rule(), Some(order));
    let mut unfenced = admitted(vec![3, 3]);
    unfenced[0].tenure = Tenure { g: 3, a: 14 };
    assert_eq!(judge(&unfenced).rule(), Some(order));
    let mut elsewhere = admitted(vec![3, 3]);
    elsewhere[0].shard = Shard::new(2).unwrap();
    assert_eq!(judge(&elsewhere).rule(), Some(order));
    assert_eq!(
        judge(&[]),
        Verdict::Unrun("no tenure admitted an operation")
    );
}

/// Each required outcome of a zone scenario fails by its own rule when the run's log is altered, and each witness
/// reads `Unrun` when the log lacks it.
#[test]
fn each_zone_outcome_fails_by_its_rule_and_a_missing_witness_reads_unrun() {
    let legal = &loss_on_root_1();
    assert_eq!(hosts::expected(legal), Verdict::Pass);
    let judged = |edit: fn(&mut Report)| {
        let mut report = legal.clone();
        edit(&mut report);
        hosts::expected(&report)
    };
    let rule = |edit| judged(edit).rule();
    let down_write =
        "a shard record, volume record or receipt of a zone with every host stopped was written";
    let other_zone =
        "a zone loss changed another zone's shard record, volume record, census or tenure";
    let no_bump = "a returning owner restarted without an attempt bump";
    let cold = "a returning owner did not serve its retained set warm";
    let deposed_served = "a deposed host served after its zone returned";
    assert_eq!(rule(|r| r.zones.down_writes = 1), Some(down_write));
    assert_eq!(rule(|r| r.zones.down_calls = 1), Some(down_write));
    assert_eq!(rule(|r| r.zones.other_moved.push(7)), Some(other_zone));
    assert_eq!(rule(|r| r.zones.other_censuses.push(2)), Some(other_zone));
    // The tenure and its recovery stay as the run left them, and the record the restart read already held the
    // tenure's attempt.
    assert_eq!(rule(|r| r.zones.restarts[0].3 += 1), Some(no_bump));
    assert_eq!(rule(|r| r.zones.restarts[0].3 -= 1), Some(no_bump));
    assert_eq!(rule(|r| r.zones.restarts[0].2.a += 2), Some(no_bump));
    let chilled = |r: &mut Report| {
        let shard = r.zones.restarts[0].0 as usize;
        r.shards[shard - 1].recoveries.last_mut().unwrap().sweep = Some((7, 6));
    };
    assert_eq!(rule(chilled), Some(cold));
    // H3's record named H0 before its restart, and the restart returned a session.
    let served = |r: &mut Report| {
        let restarted = super::zones::RESTARTED.to_owned();
        r.zones.deposed.push((4, H3, restarted, 6));
    };
    assert_eq!(rule(served), Some(deposed_served));
    assert_eq!(
        rule(|r| r.zones.deposed.push((4, H3, "Deposed".to_owned(), 6))),
        None,
        "a deposed host that refused passes"
    );

    let unrun = |edit| judged(edit);
    let missing = Verdict::Unrun;
    assert_eq!(unrun(|r| r.zones.returned = false), missing(hosts::AZ_DOWN));
    assert_eq!(
        unrun(|r| r.zones.restarts.truncate(5)),
        missing(hosts::AZ_RESTARTS)
    );
    assert_eq!(
        unrun(|r| r.zones.acknowledged = 5),
        missing(hosts::AZ_ACKNOWLEDGED)
    );
    let unjudged = |r: &mut Report| {
        let (shard, _, tenure, _) = r.zones.restarts[0];
        let admissions = &mut r.evidence.admissions;
        admissions.retain(|of| (of.shard.get(), of.tenure) != (shard, tenure));
    };
    assert_eq!(unrun(unjudged), missing(hosts::FENCE_CHECKED));
    assert_eq!(
        unrun(|r| r.zones.unplaced.truncate(5)),
        missing(hosts::AZ_DOWN)
    );
    // Judged as the other two zone scenarios, the zone-loss log lacks their witnesses.
    assert_eq!(
        unrun(|r| r.config.scenario = Scenario::ZoneDeposed),
        missing(hosts::AZ_DEPOSED)
    );
    assert_eq!(
        unrun(|r| r.config.scenario = Scenario::ZoneImpaired),
        missing(hosts::AZ_IMPAIRED)
    );
    // A host whose record named another owner and whose restart refused at another check earns no deposed witness.
    let elsewhere = |r: &mut Report| {
        r.config.scenario = Scenario::ZoneDeposed;
        let refused = "Records(Unavailable)".to_owned();
        r.zones.deposed.push((4, H3, refused, 6));
    };
    assert_eq!(unrun(elsewhere), missing(hosts::AZ_DEPOSED));
    // The retained-volumes witness needs the six retained volumes and the six impaired blockers carried at the
    // return; the log passes as the impaired arm once it holds both.
    let counted = |r: &mut Report| {
        r.config.scenario = Scenario::ZoneImpaired;
        r.volumes.retained = 6;
    };
    assert_eq!(unrun(counted), missing(hosts::AZ_IMPAIRED));
    let carried = |r: &mut Report| {
        r.config.scenario = Scenario::ZoneImpaired;
        r.zones.impaired = DOWN.to_vec();
    };
    assert_eq!(unrun(carried), missing(hosts::AZ_IMPAIRED));
    let retained = |r: &mut Report| {
        r.config.scenario = Scenario::ZoneImpaired;
        (r.volumes.retained, r.zones.impaired) = (6, DOWN.to_vec());
    };
    assert_eq!(unrun(retained), Verdict::Pass);
    // A zone that stayed down leaves the impaired and the deposed arm unrun too.
    let impaired_down = |r: &mut Report| {
        r.config.scenario = Scenario::ZoneImpaired;
        r.zones.returned = false;
    };
    assert_eq!(unrun(impaired_down), missing(hosts::AZ_DOWN));
    let deposed_down = |r: &mut Report| {
        r.config.scenario = Scenario::ZoneDeposed;
        r.zones.returned = false;
    };
    assert_eq!(unrun(deposed_down), missing(hosts::AZ_DOWN));
}

/// The zone scenarios and the early-admission plant have their own identity bytes, plant code 45 among them.
#[test]
fn a_zone_run_has_its_own_identity() {
    assert_eq!(Plant::EarlyAdmission.code(), 45);
    let scenarios = [
        Scenario::ZoneLoss,
        Scenario::ZoneImpaired,
        Scenario::ZoneDeposed,
    ];
    assert_eq!(scenarios.map(Scenario::code), [[23, 0], [24, 0], [25, 0]]);
    let configs = [
        Config::az_settle(1),
        Config::zone_loss(1),
        Config::zone_impaired(1),
        Config::zone_deposed(1),
        Config::zone_loss(1).hostile(Plant::EarlyAdmission, 2),
    ];
    let identities: BTreeSet<String> = configs.iter().map(Config::identity).collect();
    assert_eq!(identities.len(), 5);
}

/// The zone-loss run on root 1 replays its tape to an equal report, and a tape one byte short is refused; the
/// scheduled case runs it.
fn a_zone_run_replays_its_recording() {
    let (config, report) = (Config::zone_loss(1), &loss_on_root_1());
    assert_eq!(replay(&config, &report.recording()), Ok(report.clone()));
    let mut short = report.recording();
    short.tape.truncate(short.tape.len() - 1);
    let refused = replay(&config, &short);
    assert!(matches!(refused, Err(Stopped::Choice(_))), "{refused:?}");
}

/// A fleet seeded on `az` with its hosts started and no tenure serving.
fn started(config: &Config) -> Fleet<'_> {
    let mut draws = draws::Draws::record(config.root);
    let mut fleet = Fleet::seeded(config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    fleet.start_hosts();
    fleet
}

/// Commits the current value of `key` again.
fn rewrite(fleet: &Fleet<'_>, key: crate::storage::store::Key) {
    use crate::storage::store::{Outcome, Store, Write};
    let item = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored value");
    let write = Write::Exact {
        expect: item.version,
        value: item.value,
    };
    let outcome = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
}

/// The outage's counters read the store and the down zone's provider double: commits of a down zone's shard record and
/// replacement receipt and a call on that zone's provider, and commits of another zone's shard record, volume record
/// and census, made while every host of zone 1 is down, reach the zone log; a call on zone 2's provider does not
/// count as the down zone's. The outage stays open while one host of zone 1 is still down,
/// and a commit made in that interval is counted. A shard counts as unplaced only when the log entered the blocker
/// during the outage and its cell carries it at the return.
#[test]
fn an_outage_counts_real_commits_and_closes_when_the_whole_zone_runs_again() {
    use crate::failover::loss::{Health, Provider};
    use crate::failover::reconcile::StandbyGate;
    use crate::failover::standbys::Zone;
    use crate::storage::store::Key;
    let config = Config::zone_loss(1);
    let mut fleet = started(&config);
    let live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let enter = |fleet: &mut Fleet<'_>, at: usize| {
        let shard = fleet.cells[at].placement.shard.get();
        let row = Refused::row(Blocker::NoEligibleHost);
        (fleet.recon).enter(shard, row, Blocker::NoEligibleHost);
        fleet.cells[at].blocker = Some(Blocker::NoEligibleHost);
    };
    // s2 took its blocker before the outage and carries it through.
    enter(&mut fleet, 1);
    for member in 0..6 {
        fleet.hosts[member].up = hosts::Up::Down;
    }
    fleet.zone_down(&live);
    assert_eq!(fleet.zone_log.down, DOWN);
    for at in [0, 2, 3, 4, 5] {
        enter(&mut fleet, at);
    }
    fleet.cells[2].blocker = None;
    let (down, other) = (fleet.cells[0].placement, fleet.cells[6].placement);
    rewrite(&fleet, Key::Shard(down.shard));
    let gate = StandbyGate::qualified();
    let lost = (down.volume, Health::Lost);
    let receipt = (fleet.recon_client(0))
        .replacement(&gate, down.shard, lost, 0, layout())
        .expect("a receipt write");
    assert!(receipt.is_some());
    let create = |fleet: &mut Fleet<'_>, zone: u16| {
        let double = fleet.double(Zone(zone)).expect("the zone's double");
        let token = "a create during the outage";
        (double.provider.create(token, layout())).expect("a created volume");
    };
    create(&mut fleet, 1);
    create(&mut fleet, 2);
    rewrite(&fleet, Key::Shard(other.shard));
    rewrite(&fleet, Key::Volume(fleet.cells[7].placement.volume));
    rewrite(&fleet, Key::Standbys(Zone(2)));

    fleet.hosts[0].up = hosts::Up::Running;
    assert!(
        !fleet.zone_returned(&live),
        "five hosts of the zone are down"
    );
    assert!(!fleet.zone_log.returned);
    rewrite(&fleet, Key::Volume(down.volume));
    for member in 1..6 {
        fleet.hosts[member].up = hosts::Up::Running;
    }
    assert!(fleet.zone_returned(&live));
    let log = &fleet.zone_log;
    assert!(log.returned);
    assert_eq!((log.down_writes, log.down_calls), (3, 1));
    assert_eq!(
        (&log.other_moved, &log.other_censuses),
        (&vec![7, 8], &vec![2])
    );
    let unplaced = "s2 took its blocker before the outage and s3 carries none";
    assert_eq!(log.unplaced, [1, 4, 5, 6], "{unplaced}");
    assert!(!fleet.zone_returned(&live), "the outage closes once");
}

/// The outage compares each other zone's serving tenures: s7's tenure ends while zone 1 is down, with no store
/// write, and the zone log names s7 alone.
#[test]
fn an_outage_reads_an_ended_tenure_of_another_zone_as_changed() {
    let config = Config::zone_loss(1);
    let mut draws = draws::Draws::record(config.root);
    let mut fleet = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    let owner = fleet.cells[6].placement.owner;
    let grounds = Grounds::over(storage_shared(1, fleet.share_on(owner)));
    let pools = Pools::new(&grounds);
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let booted = fleet.recover(&mut live, (&grounds, &pools), (6, false), &mut draws);
    assert_eq!(booted, Ok(()));
    fleet.start_hosts();
    for member in 0..6 {
        fleet.hosts[member].up = hosts::Up::Down;
    }
    fleet.zone_down(&live);
    let serving = live[6].take().expect("s7's boot tenure");
    fleet.cells[6].close(&serving, true);
    for member in 0..6 {
        fleet.hosts[member].up = hosts::Up::Running;
    }
    assert!(fleet.zone_returned(&live));
    let log = &fleet.zone_log;
    assert_eq!((log.down_writes, log.down_calls), (0, 0));
    assert_eq!((&log.other_moved, &log.other_censuses), (&vec![7], &vec![]));
}

/// A first admission carries the page counts read when its operation was submitted: a coverage commit that lands
/// while s7's GET is in flight lies outside the stamp. An admitted operation submitted later leaves the stamp, and
/// one submitted earlier replaces it.
#[test]
fn a_first_admission_is_stamped_with_the_page_counts_at_its_submission() {
    use crate::storage::store::Key;
    let config = Config::zone_loss(1);
    let mut draws = draws::Draws::record(config.root);
    let mut fleet = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    let owner = fleet.cells[6].placement.owner;
    let grounds = Grounds::over(storage_shared(1, fleet.share_on(owner)));
    let pools = Pools::new(&grounds);
    let mut live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let booted = fleet.recover(&mut live, (&grounds, &pools), (6, false), &mut draws);
    assert_eq!(booted, Ok(()));
    let shard = fleet.cells[6].placement.shard;
    let tenure = live[6].as_ref().expect("s7's boot tenure").tenure;
    let counts = |fleet: &Fleet<'_>| -> Vec<usize> {
        let store = fleet.store.0.borrow();
        (0..fleet.cells[6].pages)
            .map(|page| store.commit_count(&Key::Page(shard, page)))
            .collect()
    };
    fleet.admissions.clear();
    let sent = counts(&fleet);
    fleet.send(&mut live, 6, 1, Purpose::Sweep);
    assert_eq!(fleet.admissions, [], "the GET is in flight");
    rewrite(&fleet, Key::Page(shard, 0));
    assert_ne!(counts(&fleet), sent);
    assert_eq!(fleet.drain(&mut live), Ok(()));
    let first = Admission {
        shard,
        tenure,
        admitted: Admitted::Hit,
        pages: sent,
    };
    assert_eq!(fleet.admissions, std::slice::from_ref(&first));
    let later = counts(&fleet);
    fleet.admit(6, tenure, Admitted::Invalidate, later);
    assert_eq!(fleet.admissions, [first]);
    fleet.admit(6, tenure, Admitted::Fill, vec![2, 2]);
    let earlier = Admission {
        shard,
        tenure,
        admitted: Admitted::Fill,
        pages: vec![2, 2],
    };
    assert_eq!(fleet.admissions, [earlier]);
}

/// The preflight checks the tenure slots a run allocates: 32 on `az`, 48 on `small` with a reconciler, and a host
/// scenario with reconcilers on 32 hosts plans 208 and is refused before any draw.
#[test]
fn a_run_is_refused_before_any_draw_when_its_planned_slots_pass_the_limit() {
    assert_eq!(Config::zone_loss(1).slots(), 32);
    assert_eq!(Config::settle(1).slots(), 48);
    assert_eq!(Config::host_loss(1).slots(), 12);
    assert_eq!(Config::six(1).slots(), 12);
    let mut wide = Config::dense(1);
    (wide.shape.hosts, wide.scenario) = (16, Scenario::Settle);
    assert_eq!(wide.slots(), 16 + 32 * 6);
    let refused = play(&wide, || panic!("no draw precedes the refusal"));
    let tenures = bounds::Refused::Tenures(208);
    assert_eq!(refused, Err(Stopped::Shape(tenures)));
}

/// The scheduled roots of the zone scenarios: the zone-loss case on root 2, whose decisions restart the six returning
/// owners in another order than root 1's, the replay of root 1's zone-loss tape, and the no-fault sibling on root 2.
/// Each check that passes prints one line, and the last line counts them.
#[test]
#[ignore = "zone scenarios on their second root; the search-nightly lane's row fleet-scheduled-roots runs it with --ignored"]
fn the_zone_scenarios_pass_on_their_scheduled_roots() {
    let checks: [(&str, &dyn Fn()); 3] = [
        ("loss root 2", &|| {
            let second = passing(&Config::zone_loss(2));
            keeps_its_volumes_and_returns_fenced_and_warm(&second);
            // The run's decisions order the returning restarts, so the two roots restart the six shards in two
            // orders.
            let order = |report: &Report| -> Vec<u32> {
                let restarts = report.zones.restarts.iter();
                restarts.map(|(shard, ..)| *shard).collect()
            };
            assert_ne!(order(&loss_on_root_1()), order(&second));
        }),
        ("loss-replay root 1", &a_zone_run_replays_its_recording),
        ("settle root 2", &|| az_settles_with_no_fault_on(2)),
    ];
    for (name, check) in checks {
        check();
        println!("fleet: scheduled zone {name}: pass");
    }
    println!("fleet: scheduled zone: {} checks passed", checks.len());
}
