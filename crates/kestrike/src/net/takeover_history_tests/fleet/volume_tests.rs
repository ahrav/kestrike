use std::collections::BTreeSet;

use super::hosts::{BESIDE, FAULTED, Scenario};
use super::oracles;
use super::reconcile::Refused;
use super::volumes::{Boundary, CrashPoint, ReplaceCell};
use super::*;
use crate::failover::loss::{Phase, Receipt};
use crate::failover::records::VolumeId;
use crate::failover::report::Gauge;
use crate::failover::zone_loop::status::Blocker;

const H0: u64 = 1001;
const H3: u64 = 1004;
const H5: u64 = 1006;
/// The shard numbers of the faulted cell and of the cell impaired beside it.
const S3: u32 = FAULTED as u32 + 1;
const S4: u32 = BESIDE as u32 + 1;

pub(super) fn passing(config: &Config) -> Report {
    let report = run_shared(config).expect("a run inside the limits");
    assert_eq!(
        report.credit(),
        Verdict::Pass,
        "{}",
        report.lines().join("\n")
    );
    report
}

/// The blockers the log entered for `shard`, in order.
pub(super) fn entered(report: &Report, shard: u32) -> Vec<Blocker> {
    let blockers = report.recon.blockers.iter();
    blockers
        .filter(|(_, of, ..)| *of == shard)
        .map(|(_, _, blocker, _)| *blocker)
        .collect()
}

fn carried(report: &Report, shard: u32) -> Option<Blocker> {
    let mut settled = report.evidence.settled.iter();
    settled
        .find(|settled| settled.shard.get() == shard)
        .and_then(|settled| settled.blocker)
}

fn history(report: &Report, shard: u32) -> &[ShardRecord] {
    &report.evidence.histories[shard as usize - 1].1
}

/// The owner changes of `shard`'s record inside one generation.
fn moves(report: &Report, shard: u32) -> usize {
    let changed = history(report, shard)
        .windows(2)
        .filter(|pair| pair[0].generation == pair[1].generation && pair[0].owner != pair[1].owner);
    changed.count()
}

/// The run's store history, provider log and hosts' effects hold no receipt, create, flip, flip request,
/// generation change or active-volume change.
pub(super) fn provisions_nothing(report: &Report) {
    assert_eq!(report.evidence.volumes, Volumes::default());
    let volumes = &report.volumes;
    assert_eq!((volumes.calls, volumes.made, volumes.flipped), (0, 0, 0));
    assert!(volumes.created.is_empty() && volumes.cold.is_empty());
    assert!(report.evidence.receipts.iter().all(Option::is_none));
    for (shard, versions) in &report.evidence.histories {
        let generations: BTreeSet<u64> = versions.iter().map(|r| r.generation.get()).collect();
        let actives: BTreeSet<_> = versions.iter().map(|r| r.active).collect();
        let at = shard.get();
        assert_eq!((generations.len(), actives.len()), (1, 1), "shard {at}");
    }
}

/// Every shard other than `faulted` keeps its boot tenure and its owner.
fn others_keep_serving(report: &Report, faulted: &[u32]) {
    for shard in &report.shards {
        let at = shard.placement.shard.get();
        if faulted.contains(&at) {
            continue;
        }
        assert_eq!(shard.recoveries.len(), 1, "shard {at} keeps its tenure");
        assert_eq!(shard.blockers, Vec::<String>::new(), "shard {at}");
        assert_eq!(moves(report, at), 0, "shard {at}");
    }
}

/// The no-fault siblings: `small` and `tiny` under their reconciler settle with no receipt, create or flip.
#[test]
fn with_no_fault_the_reconciler_writes_no_receipt_and_calls_no_provider() {
    with_no_fault_the_reconciler_writes_no_receipt_and_calls_no_provider_on(1);
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn with_no_fault_the_reconciler_writes_no_receipt_and_calls_no_provider_on(root: u64) {
    for config in [Config::settle(root), Config::tiny_settle(root)] {
        let report = passing(&config);
        provisions_nothing(&report);
        assert_eq!(report.volumes, volumes::VolumeLog::default());
        assert_eq!(report.recon.blockers, []);
    }
}

/// s3's volume stalls and the control plane reports it impaired. The loop retains the volume and its status names
/// `VolumeImpaired` for the shard on every row from the impairment on, and no other blocker. H3's restart holds at its
/// device step, its host reports itself unhealthy, and H0, the named standby, takes the shard over by its own write and
/// holds at its device step too; each of the two hosts reports s3's entry in phase `Held` while it holds. The loop's
/// planner passes over the standby need of the shard while its volume reads impaired (ONE-STATE of
/// `failover::zone_loop::status`), so the shard moves once. After the stall clears, H0's restart finds H3's recorded
/// registration still holding and recovers the shard through its lineage arm: it serves warm with no standby
/// and carries `VolumeImpaired` while served, and the volume is retained once. Nothing is provisioned, and no other
/// shard moves. The test reads no device-hold guard count, because under `VolumeImpaired` the planner never reaches
/// the device-hold guard.
#[test]
fn an_impaired_volume_is_retained_through_one_takeover_that_holds_and_the_successor_s_restart() {
    an_impaired_volume_is_retained_through_one_takeover_that_holds_and_the_successor_s_restart_on(
        1,
    );
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn an_impaired_volume_is_retained_through_one_takeover_that_holds_and_the_successor_s_restart_on(
    root: u64,
) {
    let report = passing(&Config::impaired(root));
    provisions_nothing(&report);
    assert_eq!(report.volumes.stalled, [S3]);
    assert_eq!(report.volumes.retained, 1);
    assert_eq!(report.recon.designations, []);
    assert_eq!(carried(&report, S3), Some(Blocker::VolumeImpaired));
    let (_, held) = held_by_both(&report);
    let runs = runs(&report, S3);
    assert!(
        matches!(runs[..], [(Blocker::VolumeImpaired, _, None)]),
        "{runs:?}"
    );
    assert_eq!(entered(&report, S3), [Blocker::VolumeImpaired]);
    assert_eq!(moves(&report, S3), 1);
    let last = history(&report, S3).last().unwrap();
    assert_eq!((last.owner.get(), last.standby), (H0, None));
    let attempts: Vec<_> = (report.hosts.takeovers.iter())
        .map(|attempt| (attempt.shard, attempt.host, attempt.refused.as_deref()))
        .collect();
    // The stalled volume delivers no completion, so the takeover's first Report after its compare-and-swap times out.
    assert_eq!(attempts, [(S3, H0, Some("FirstReport"))]);
    let recovered = recovered_by_the_arm(&report);
    assert!(held < recovered && runs[0].1 < recovered, "{runs:?}");
    no_standby_while_held(&report, recovered);
    others_keep_serving(&report, &[S3]);
    assert_eq!(report.hosts.exempt, BTreeSet::from([S3]));
    assert_eq!(report.verdicts.untouched, Verdict::Pass);
}

/// The same impairment with a stall that clears before any suspicion: no takeover starts, H3's restart after the
/// stall loads warm and serves its retained set, and the shard drops `VolumeImpaired` once the control plane reports
/// the volume healthy.
#[test]
fn an_impaired_volume_whose_stall_clears_early_restarts_warm_with_no_takeover() {
    an_impaired_volume_whose_stall_clears_early_restarts_warm_with_no_takeover_on(1);
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn an_impaired_volume_whose_stall_clears_early_restarts_warm_with_no_takeover_on(root: u64) {
    let report = passing(&Config::impaired_brief(root));
    provisions_nothing(&report);
    assert_eq!(report.volumes.retained, 1);
    assert!(report.hosts.takeovers.is_empty() && report.takeovers == 0);
    assert!(entered(&report, S3).contains(&Blocker::VolumeImpaired));
    assert_eq!(carried(&report, S3), None);
    let recoveries = &report.shards[FAULTED].recoveries;
    let last = recoveries.last().unwrap();
    assert_eq!(recoveries.len(), 2);
    assert_eq!((last.host.get(), last.sweep), (H3, Some((7, 7))));
    assert!(report.evidence.settled.iter().all(|settled| settled.served));
    others_keep_serving(&report, &[S3]);
}

/// The faulted shard's recoveries after a stall that outlasted one takeover: its seeded owner's, then the successor
/// H0's restart once the stall cleared, which served warm through the restart's lineage arm at a later `E` and
/// received every object of its sweep. Returns the round of that restart, counted as a designation's round is.
fn recovered_by_the_arm(report: &Report) -> u64 {
    let recoveries = &report.shards[FAULTED].recoveries;
    assert_eq!(recoveries.len(), 2, "{recoveries:?}");
    let (first, last) = (&recoveries[0], &recoveries[1]);
    assert_eq!((first.host.get(), last.host.get()), (H3, H0));
    assert!(last.tenure.a > first.tenure.a, "{recoveries:?}");
    assert!(
        last.sweep
            .is_some_and(|(of, served)| of > 0 && of == served),
        "the successor's sweep: {:?}",
        last.sweep
    );
    let arm = &report.volumes.arm;
    assert_eq!(arm.len(), 1, "{arm:?}");
    let (shard, host, round) = arm[0];
    assert_eq!((shard, host), (S3, H0));
    round
}

/// No standby is designated for the faulted shard before the successor's restart recovered it at round `recovered`,
/// so the guard held for the whole hold.
fn no_standby_while_held(report: &Report, recovered: u64) {
    let early: Vec<_> = (report.recon.designations.iter())
        .filter(|designation| designation.shard == S3 && designation.round < recovered)
        .collect();
    assert!(early.is_empty(), "{early:?}");
}

/// `shard`'s runs of one blocker in the loop's status rows: the blocker, the round of its first row and the round of
/// the first row that named another or none.
fn runs(report: &Report, shard: u32) -> Vec<(Blocker, u64, Option<u64>)> {
    (report.recon.runs.iter())
        .filter(|(of, ..)| *of == shard)
        .map(|(_, blocker, from, to)| (*blocker, *from, *to))
        .collect()
}

/// The faulted shard's two holds as the hosts report them: each of H3, the first owner, and H0, its successor, begins
/// to carry s3's entry in phase `Held` (the harness's `volumes::Held`) once, H3 in a report sealed no later than H0's.
/// Both first appear in the reports of one seal, since H0's takeover holds within the report period of H3's hold, so
/// the order is read from the sealing rounds and not from the log's order within a round. Returns those two rounds.
fn held_by_both(report: &Report) -> (u64, u64) {
    let held: Vec<_> = (report.hosts.held.iter())
        .filter(|(.., shard)| *shard == S3)
        .collect();
    assert_eq!(held.len(), 2, "{held:?}");
    let began = |host: u64| {
        let at = held.iter().find(|(_, of, _)| *of == host);
        at.map(|(round, ..)| *round).expect("the host's held entry")
    };
    let (first, successor) = (began(H3), began(H0));
    assert!(first <= successor, "{held:?}");
    (first, successor)
}

/// A stall the control plane reports healthy: H3 holds, H0 takes s3 over once and holds at its own device step, each
/// host reports s3's entry in phase `Held` while it holds, the status names `DeviceFailureHold` in one continuous run
/// from the first host's hold to the successor's recovery with no standby enrolled for H0, and nothing is provisioned.
/// After the stall clears, H0's restart finds H3's recorded registration still holding and recovers the shard through
/// its lineage arm: the shard ends served with a standby enrolled again and carries no blocker.
#[test]
fn a_stall_the_control_plane_reports_healthy_moves_the_shard_once_holds_and_recovers_by_the_successor_s_restart()
 {
    a_stall_the_control_plane_reports_healthy_moves_the_shard_once_holds_and_recovers_on(1);
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn a_stall_the_control_plane_reports_healthy_moves_the_shard_once_holds_and_recovers_on(root: u64) {
    let report = passing(&Config::stall(root));
    provisions_nothing(&report);
    // The declared hold: H3's Held status makes its agent declare itself unhealthy, so s3 alone is exempt.
    assert_eq!(report.hosts.exempt, BTreeSet::from([S3]));
    assert_eq!(report.volumes.retained, 0);
    assert_eq!(moves(&report, S3), 1);
    let (first, held) = held_by_both(&report);
    let hold = Blocker::DeviceFailureHold;
    assert_eq!(entered(&report, S3), [hold]);
    assert_eq!(carried(&report, S3), None);
    let recovered = recovered_by_the_arm(&report);
    assert!(held < recovered);
    assert!(report.volumes.guarded >= 1);
    no_standby_while_held(&report, recovered);
    // H0's recovery slot as its sealed reports read it, by sealing round.
    let slot: Vec<(u64, Gauge)> = (report.hosts.headrooms.iter())
        .filter(|(_, host, _)| *host == H0)
        .map(|(round, _, gauges)| (*round, gauges[2]))
        .collect();
    let (busy, free) = (Gauge::known(1, 1), Gauge::known(0, 1));
    let freed = slot
        .iter()
        .find(|(round, gauge)| *round >= recovered && *gauge == free);
    let (freed, _) = *freed.expect("a report of H0 sealed after its recovery");
    let runs = runs(&report, S3);
    assert!(
        matches!(runs[..], [(Blocker::DeviceFailureHold, from, Some(to))] if first <= from && from < recovered && to == freed),
        "{runs:?}"
    );
    let settled = &report.evidence.settled[FAULTED];
    assert!(settled.served && settled.blocker.is_none(), "{settled:?}");
    let last = history(&report, S3).last().unwrap();
    assert_eq!(last.owner.get(), H0);
    assert!(
        last.standby.is_some(),
        "the recovered shard has a standby enrolled again"
    );
    others_keep_serving(&report, &[S3]);
    // s3's former owner H3 holds its recovery of s3 to the end, so its last sealed report reads the recovery slot
    // held. Its successor H0 reads it held in a report sealed while it holds and free in its last report, after it
    // recovered through the arm.
    let last = report.hosts.sealed(H3).last().map(|gauges| gauges[2]);
    assert_eq!(last, Some(busy), "host {H3}");
    let holding =
        (slot.iter()).any(|(round, gauge)| (held..recovered).contains(round) && *gauge == busy);
    assert!(holding, "host {H0}: {slot:?}");
    assert_eq!(
        slot.last().map(|(_, gauge)| *gauge),
        Some(free),
        "host {H0}"
    );
}

/// Control: a reconciler that keeps the `Standby` need of the held successor enrolls H3, the former owner, as s3's
/// standby; H0 then reports itself unhealthy and H3 takes the shard back, which fails the at-most-once rule. The
/// unplanted sibling moves the shard once.
#[test]
fn control_a_reconciler_that_enrolls_the_former_owner_moves_a_stalled_shard_twice() {
    let rule = "a shard on a stalled volume changed hands more than once";
    control_a_reconciler_that_enrolls_the_former_owner_moves_a_stalled_shard_twice_on(1, rule);
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn control_a_reconciler_that_enrolls_the_former_owner_moves_a_stalled_shard_twice_on(
    root: u64,
    rule: &'static str,
) {
    assert_eq!(moves(&passing(&Config::stall(root)), S3), 1);
    let config = Config::stall(root).hostile(Plant::EnrollBack, FAULTED as u32);
    let report = run(&config).expect("a run inside the limits");
    assert!(report.planted);
    let back = (report.recon.designations.iter()).any(|d| d.shard == S3 && d.host == H3);
    assert!(back, "{:?}", report.recon.designations);
    assert!(moves(&report, S3) >= 2);
    assert_eq!(hosts::expected(&report).rule(), Some(rule));
    assert_eq!(report.evidence.volumes.flips, 0);
}

fn receipt(report: &Report, shard: u32) -> Receipt {
    report.evidence.receipts[shard as usize - 1]
        .clone()
        .expect("the shard's receipt")
}

/// The lost shard's generation rose by one onto the one volume the provider made, its receipt records that volume,
/// its owner activated at `E = 1` by the fresh path, attached cold and counts no retained object, and no other
/// shard changed its generation or its volume or holds a receipt.
fn replaced_once(report: &Report, shard: u32, stranded: &[VolumeId]) {
    let volumes = &report.volumes;
    assert_eq!(volumes.stranded, stranded, "the stranded volumes");
    assert_eq!(volumes.lost, [shard]);
    assert!(volumes.made == 1 && volumes.flipped <= 1);
    assert_eq!(report.evidence.replaced, [(1, 1)]);
    assert_eq!(report.evidence.volumes, Volumes::default());
    let versions = history(report, shard);
    let (first, last) = (versions[0], *versions.last().unwrap());
    assert_eq!(last.generation.get(), first.generation.get() + 1);
    assert_ne!(last.active, first.active);
    assert_eq!((last.spare, last.checkpoint), (None, None));
    let receipt = receipt(report, shard);
    assert_eq!(receipt.phase, Phase::Created(last.active));
    assert_eq!((receipt.attempt, receipt.held), (1, false));
    assert_eq!(volumes.created, [(shard, last.active.as_str().to_owned())]);
    assert_eq!(volumes.provided, [(receipt.token(), last.active)]);
    assert_eq!(volumes.cold, [shard]);
    let cold = report.shards[shard as usize - 1].recoveries.last().unwrap();
    let tenure = crate::oracle::Tenure {
        g: last.generation.get(),
        a: 2,
    };
    assert_eq!((cold.tenure, cold.sweep), (tenure, Some((0, 0))));
    assert_eq!(cold.host, last.owner);
    for (other, versions) in &report.evidence.histories {
        if other.get() != shard {
            let kept = versions.iter().all(|record| {
                (record.generation, record.active) == (versions[0].generation, versions[0].active)
            });
            assert!(kept, "shard {}", other.get());
            let receipt = &report.evidence.receipts[other.get() as usize - 1];
            assert_eq!(*receipt, None, "shard {}", other.get());
        }
    }
    let settled = &report.evidence.settled[shard as usize - 1];
    assert!(settled.served, "the replaced shard serves with a standby");
}

/// s3's volume is lost alone: the first listing in state `error` retains it, the second confirms the loss, and the
/// reconciler runs the receipt to one create, records the attach, names the spare and flips, the owner activates by
/// `Fresh::run` and serves cold, and the reconciler then enrolls a standby on the replacement.
#[test]
fn a_volume_lost_alone_is_replaced_once_at_the_next_generation_and_starts_cold() {
    a_volume_lost_alone_is_replaced_once_at_the_next_generation_and_starts_cold_on(1);
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn a_volume_lost_alone_is_replaced_once_at_the_next_generation_and_starts_cold_on(root: u64) {
    let report = passing(&Config::lost_alone(root));
    replaced_once(&report, S3, &[]);
    assert_eq!(report.volumes.calls, 1);
    assert_eq!((report.volumes.latched, report.volumes.released), (0, 0));
    // One listing in state `error` is short of the loss count: the first survey retains the volume as impaired,
    // and the receipt starts only once a second listing confirms the loss.
    assert_eq!(report.volumes.retained, 1);
    let entered = entered(&report, S3);
    assert!(entered.contains(&Blocker::VolumeImpaired), "{entered:?}");
    others_keep_serving(&report, &[S3]);
}

/// s3's volume is lost while s4's is impaired: the receipt latches held, `create_replacement` refuses `Held` and the
/// shard carries `CorrelatedHold` with no provider call, until the operator's release; the replacement then runs as
/// for a lone loss. s4 keeps serving under `VolumeImpaired`.
#[test]
fn a_loss_beside_an_impaired_volume_holds_until_the_operator_release() {
    a_loss_beside_an_impaired_volume_holds_until_the_operator_release_on(1);
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn a_loss_beside_an_impaired_volume_holds_until_the_operator_release_on(root: u64) {
    let report = passing(&Config::correlated(root));
    assert_eq!(
        (report.volumes.latched, report.volumes.latched_at_create),
        (1, 0),
        "the decide call latched the hold"
    );
    held_until_the_release(&report);
}

/// The hold of s3's replacement refused its create step `Held` with no provider call until the operator's one
/// release, the replacement then ran as for a lone loss, and s4 kept serving under `VolumeImpaired`.
fn held_until_the_release(report: &Report) {
    let volumes = &report.volumes;
    assert_eq!(volumes.released, 1);
    assert_eq!(volumes.calls_at_release, Some(0));
    assert!(entered(report, S3).contains(&Blocker::CorrelatedHold));
    let refused = report.recon.refusals.iter();
    assert!(
        refused.into_iter().any(|(_, shard, of)| *shard == S3
            && matches!(of, Refused::Status(_, Blocker::CorrelatedHold)))
    );
    replaced_once(report, S3, &[]);
    assert_eq!(volumes.calls, 1);
    assert!(receipt(report, S3).released);
    assert_eq!(carried(report, S4), Some(Blocker::VolumeImpaired));
    assert_eq!(report.shards[BESIDE].recoveries.len(), 1);
    others_keep_serving(report, &[S3]);
}

/// s3's volume is lost with every other volume healthy, so `Reconciler::replacement` starts an unheld receipt. The
/// control plane then reports s4's volume impaired before the create step runs. `create_replacement` latches the
/// receipt held and refuses `Held` with no provider call, and the shard carries `CorrelatedHold` until the operator's
/// release; the replacement then runs as for a lone loss. The run has its own identity and replays to an equal
/// report.
#[test]
fn a_volume_that_turns_impaired_after_the_receipt_holds_the_create_until_the_operator_release() {
    a_volume_that_turns_impaired_after_the_receipt_holds_the_create_until_the_operator_release_on(
        1,
    );
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn a_volume_that_turns_impaired_after_the_receipt_holds_the_create_until_the_operator_release_on(
    root: u64,
) {
    let config = Config::correlated_late(root);
    let report = passing(&config);
    assert_eq!(
        (report.volumes.latched, report.volumes.latched_at_create),
        (0, 1),
        "the create step latched the hold"
    );
    held_until_the_release(&report);
    assert_ne!(config.identity(), Config::correlated(root).identity());
    if root == 1 {
        assert_eq!(replay(&config, &report.recording()), Ok(report));
    }
}

/// What a cell's step leaves at its crash. The step commits the writes that precede the cell's write: the issue
/// write before the volume-record create, both before the created-volume write, and the spare record's rewrite before
/// the flip. It commits the cell's own write unless the cell names it lost, and the loop dies right after that write,
/// so a crash at the issue write precedes the provider's call. The receipt reads issued at every crash that follows
/// a provider call, and it records the volume once the created-volume write committed.
fn crash_point(cell: ReplaceCell, created: VolumeId) -> CrashPoint {
    use reconcile::Ending;
    let lost = cell.ending == Ending::Lost;
    let written = |after: Phase, before: Option<Phase>| if lost { before } else { Some(after) };
    let (before, calls, receipt) = match cell.boundary {
        Boundary::Replacement => (0, 0, written(Phase::Open, None)),
        Boundary::CreateOpen => (0, 0, written(Phase::Issued, Some(Phase::Open))),
        Boundary::CreateIssued => (1, 1, Some(Phase::Issued)),
        Boundary::CreateCreated => {
            let receipt = written(Phase::Created(created), Some(Phase::Issued));
            (2, 1, receipt)
        }
        Boundary::RecordAttach | Boundary::AddSpare => (0, 1, Some(Phase::Created(created))),
        Boundary::Flip => (1, 1, Some(Phase::Created(created))),
    };
    CrashPoint {
        commits: before + usize::from(!lost),
        calls,
        receipt,
    }
}

/// One cell of the replacement crash table on `tiny`: the reconciler crashed once in the cell's step, after the
/// commits and provider calls the cell names, and restarted once, the restarted reconciler converged on one volume
/// for the receipt and one flip, fleet oracles F1 and F4 pass, and the run replays to an equal report. A crash after
/// the flip's write landed, acknowledged or with its reply unknown, strands the displaced volume: its record reads
/// `Active` to the end of the run and no shard record names it. The operator clears that state with two acts,
/// `Reconciler::retire(shard, displaced)` for the stranded volume and then `Reconciler::release_hold` for the receipt
/// the next loss in the zone latches; the zone status counts such volumes (`ZoneStatus::unnamed`), which the alarm
/// catalog's `volume-unnamed` row reads, and this test reads the store's records instead. Every other cell strands no
/// volume.
fn replace_cell_converges(cell: ReplaceCell) -> String {
    let name = cell.name();
    let config = Config::replace(1, cell);
    let report = passing(&config);
    assert_eq!(report.volumes.crashed, std::slice::from_ref(&name));
    assert_eq!(report.recon.restarts, 1, "{name}");
    let displaced = history(&report, 1).first().unwrap().active;
    let stranded: &[_] = if cell.strands() { &[displaced] } else { &[] };
    replaced_once(&report, 1, stranded);
    let created = history(&report, 1).last().unwrap().active;
    let point = crash_point(cell, created);
    assert_eq!(report.volumes.crash_points, [point], "{name}");
    // A crash after the provider's call with no committed created-volume write repeats the create under the
    // receipt's token, which the provider answers with the volume it made.
    let recorded = matches!(point.receipt, Some(Phase::Created(_)));
    let calls = 1 + usize::from(point.calls == 1 && !recorded);
    assert_eq!(report.volumes.calls, calls, "{name}");
    assert_eq!(report.verdicts.one_owner, Verdict::Pass, "{name}");
    assert_eq!(report.verdicts.census, Some(Verdict::Pass), "{name}");
    assert_eq!(replay(&config, &report.recording()), Ok(report), "{name}");
    name
}

/// Runs the crash cells of `boundaries`: every ending of each when `every` is set, and otherwise one ending of each,
/// the ending turning with the boundary's place in the table so the fast cells reach all three endings. Returns the
/// name of each cell it ran.
fn replace_cells_converge(boundaries: &[Boundary], every: bool) -> Vec<String> {
    let fast = |cell: &ReplaceCell| {
        let code = usize::from(cell.code());
        code % 3 == (code / 3) % 3
    };
    let cells: Vec<String> = (ReplaceCell::all().into_iter())
        .filter(|cell| boundaries.contains(&cell.boundary) && (every || fast(cell)))
        .map(replace_cell_converges)
        .collect();
    let distinct = cells.iter().collect::<BTreeSet<_>>().len();
    let endings = if every { 3 } else { 1 };
    assert_eq!(distinct, boundaries.len() * endings, "{cells:?}");
    cells
}

#[test]
fn one_crash_cell_of_each_boundary_at_the_receipt_and_its_issue_is_reached_and_converges() {
    replace_cells_converge(&[Boundary::Replacement, Boundary::CreateOpen], false);
}

#[test]
fn one_crash_cell_of_each_boundary_at_the_created_volume_is_reached_and_converges() {
    replace_cells_converge(&[Boundary::CreateIssued, Boundary::CreateCreated], false);
}

#[test]
fn one_crash_cell_of_each_boundary_at_the_attach_record_the_spare_and_the_flip_is_reached_and_converges()
 {
    replace_cells_converge(
        &[Boundary::RecordAttach, Boundary::AddSpare, Boundary::Flip],
        false,
    );
}

/// A crash after an unknown create write repeats the create under the receipt's one token, which the provider
/// answers with the volume it made. A receipt whose committed write records the volume calls no provider again.
#[test]
fn a_restarted_reconciler_repeats_the_receipts_token_and_gets_its_one_volume() {
    for boundary in [Boundary::CreateIssued, Boundary::CreateCreated] {
        for ending in [reconcile::Ending::Committed, reconcile::Ending::Lost] {
            let report = passing(&Config::replace(1, ReplaceCell { boundary, ending }));
            let volumes = &report.volumes;
            let recorded =
                (boundary, ending) == (Boundary::CreateCreated, reconcile::Ending::Committed);
            let calls = if recorded { 1 } else { 2 };
            assert_eq!(
                (volumes.calls, volumes.made),
                (calls, 1),
                "{boundary:?} {ending:?}"
            );
        }
    }
}

#[test]
fn the_replacement_crash_table_has_21_cells_with_distinct_codes_names_and_identities() {
    let cells = ReplaceCell::all();
    let codes: BTreeSet<u8> = cells.iter().map(|cell| cell.code()).collect();
    let names: BTreeSet<String> = cells.iter().map(|cell| cell.name()).collect();
    let identities: BTreeSet<String> = (cells.iter())
        .map(|cell| Config::replace(1, *cell).identity())
        .collect();
    assert_eq!(
        (cells.len(), codes.len(), names.len(), identities.len()),
        (21, 21, 21, 21)
    );
    assert_eq!(cells[4].name(), "replace-createopen-committed");
}

/// Control: in the host-loss case with the reconciler running, the plant makes the reconciler read s0's volume lost
/// once H0, its host, is lost, and leaves the shard's record alone otherwise. The production replacement acts on
/// that verdict: it writes s0's receipt, makes one volume with one provider create call and flips s0 to it at the
/// next generation, and fleet oracle F2 fails by its host-loss rule. The unplanted sibling passes F2 with host
/// losses counted.
#[test]
fn control_a_host_loss_reported_as_volume_loss_fails_host_loss_keeps_volume() {
    let rule = "a host loss changed a shard's generation or provisioned a volume";
    control_a_host_loss_reported_as_volume_loss_fails_host_loss_keeps_volume_on(1, rule);
}

/// The checks of the test above on one root; the scheduled case runs root 2.
fn control_a_host_loss_reported_as_volume_loss_fails_host_loss_keeps_volume_on(
    root: u64,
    rule: &'static str,
) {
    let sibling = passing(&Config::reenroll(root));
    assert_eq!(sibling.verdicts.keeps_volume, Verdict::Pass);
    assert!(sibling.hosts.host_losses >= 1);
    let report = run(&Config::reenroll(root).hostile(Plant::LossEvidence, 0))
        .expect("a run inside the limits");
    assert!(report.planted);
    assert!(report.hosts.host_losses >= 1);
    assert!(
        report.volumes.lost.is_empty(),
        "the injector lost no volume"
    );
    let volumes = &report.volumes;
    assert_eq!((volumes.calls, volumes.made, volumes.flipped), (1, 1, 1));
    let created: Vec<u32> = volumes.created.iter().map(|(shard, _)| *shard).collect();
    assert_eq!(created, [1]);
    let receipts = &report.evidence.receipts;
    let receipt = receipts[0]
        .as_ref()
        .expect("a replacement receipt for shard 1");
    assert_eq!(receipt.request.shard.get(), 1);
    assert!(matches!(receipt.phase, Phase::Created(_)), "{receipt:?}");
    assert!(receipts[1..].iter().all(Option::is_none), "{receipts:?}");
    let generations = history(&report, 1)
        .iter()
        .map(|record| record.generation.get());
    assert_eq!(
        generations.max(),
        Some(history(&report, 1)[0].generation.get() + 1)
    );
    let failed = Verdict::Fail(rule, "shard 1".to_owned());
    assert_eq!(report.verdicts.keeps_volume, failed);
    assert_eq!(report.credit(), failed);
    // LOSS-NEEDS-EVIDENCE on the provider double itself: the sibling's loop called no create, and the planted loop's
    // one call fails the host-loss provider rule.
    assert_eq!(sibling.volumes.calls, 0);
    let provisioned = Verdict::Fail(hosts::PROVISIONED, "1 create calls".to_owned());
    assert_eq!(hosts::expected(&report), provisioned);
    // The flip deposes s0's serving tenure in its own slot. Its `Deposed` exit ends as `serve` ends it: torn down
    // with its owner's parts returned.
    let exits = report.duties.exits.iter();
    let deposed = exits.filter(|(.., exit)| *exit == crate::host::Exit::Deposed);
    let deposed: Vec<_> = deposed
        .map(|&(shard, tenure, _)| (shard, tenure, true))
        .collect();
    assert_eq!(deposed.len(), 1, "{:?}", report.duties.exits);
    assert_eq!(report.duties.torn, deposed);
}

/// F2 judges against what the injector lost: a generation change of a shard whose volume it marked lost passes, of
/// a shard whose host it lost fails by the host-loss rule, and of any other shard by the generation rule, another
/// shard's lost volume notwithstanding.
#[test]
fn the_volume_check_excuses_a_lost_volume_and_names_a_host_loss() {
    let evidence = passing(&Config::lost_alone(1)).evidence;
    let judge = |losses: &oracles::Losses| {
        oracles::keeps_volume(&evidence.histories, Volumes::default(), 1, losses)
    };
    assert_eq!(evidence.losses.volumes, [S3]);
    assert_eq!(judge(&evidence.losses), Verdict::Pass);
    let host = oracles::Losses {
        volumes: Vec::new(),
        hosts: vec![S3],
    };
    assert_eq!(judge(&host).rule(), Some(oracles::HOST_LOSS));
    let none = oracles::Losses::default();
    assert_eq!(judge(&none).rule(), Some(oracles::GENERATION));
    // A lost volume excuses its own shard alone.
    let beside = oracles::Losses {
        volumes: vec![S4],
        hosts: Vec::new(),
    };
    let failed = Verdict::Fail(oracles::GENERATION, format!("shard {S3}"));
    assert_eq!(judge(&beside), failed);
    let host_beside = oracles::Losses {
        volumes: vec![S4],
        hosts: vec![S3],
    };
    assert_eq!(judge(&host_beside).rule(), Some(oracles::HOST_LOSS));
}

/// `report` judged by its scenario's required outcomes and witnesses after `edit` altered a copy of it.
fn altered(report: &Report, edit: impl FnOnce(&mut Report)) -> Verdict {
    let mut report = report.clone();
    edit(&mut report);
    hosts::expected(&report)
}

/// The volume counts that F2 judges excuse the lost shard alone. With s3's volume marked lost, a receipt and a
/// generation change of s3 leave the counts at zero, and a receipt and a generation change of s0 each count.
#[test]
fn the_volume_counts_excuse_the_receipt_and_the_flip_of_the_lost_shard_alone() {
    use crate::failover::loss::Health;
    use crate::failover::reconcile::StandbyGate;
    use crate::net::ownership::ShardGeneration;
    use crate::storage::store::{Key, Outcome, Store, Write};
    use crate::storage::warm_sim::layout;
    let config = Config::lost_alone(1);
    let mut draws = draws::Draws::record(config.root);
    let mut fleet = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    fleet.start_hosts();
    fleet.volumes.lost.push(S3);
    let gate = StandbyGate::qualified();
    let receipt = |fleet: &Fleet<'_>, at: usize| {
        let placement = fleet.cells[at].placement;
        let lost = (placement.volume, Health::Lost);
        let mut reconciler = fleet.recon_client(0);
        let written = reconciler.replacement(&gate, placement.shard, lost, 0, layout());
        assert!(matches!(written, Ok(Some(_))), "{written:?}");
    };
    let flip = |fleet: &Fleet<'_>, at: usize| {
        let key = Key::Shard(fleet.cells[at].placement.shard);
        let item = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored shard record");
        let record = ShardRecord::decode(&item.value).expect("a shard record");
        let generation = ShardGeneration::new(record.generation.get() + 1);
        let next = ShardRecord {
            generation: generation.expect("a next generation"),
            ..record
        };
        let write = Write::Exact {
            expect: item.version,
            value: next.encode(),
        };
        let outcome = Store::write(&mut fleet.store.clone(), &key, &write);
        assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
    };
    receipt(&fleet, FAULTED);
    flip(&fleet, FAULTED);
    assert_eq!(fleet.volumes(), Volumes::default());
    receipt(&fleet, 0);
    let one_receipt = Volumes {
        receipts: 1,
        ..Volumes::default()
    };
    assert_eq!(fleet.volumes(), one_receipt);
    flip(&fleet, 0);
    let and_one_flip = Volumes {
        flips: 1,
        ..one_receipt
    };
    assert_eq!(fleet.volumes(), and_one_flip);
}

/// Control: the lone-loss fleet as seeded, judged through `Fleet::report` with no run. The seeded store strands no
/// volume. s3's shard record is then rewritten through the store to name another active volume at the next
/// generation, the flip's write, while the displaced volume's record still reads `Active`: the stored state a crash
/// after the flip leaves, in a scenario with no crash. The report lists the displaced volume, fails the stranded rule,
/// and its credit reads that failure.
#[test]
fn control_a_store_whose_flip_left_the_displaced_volume_active_fails_the_stranded_rule() {
    use crate::net::ownership::ShardGeneration;
    use crate::storage::store::{Key, Outcome, Store, Write};
    let rule = "a volume no shard record names stayed active with no crash after its flip";
    let config = Config::lost_alone(1);
    let mut draws = draws::Draws::record(config.root);
    let mut fleet = Fleet::seeded(&config, &mut draws, WAIT_ROUNDS).expect("a recorded topology");
    fleet.start_hosts();
    fleet.volumes.lost.push(S3);
    let live: Live<'_> = fleet.cells.iter().map(|_| None).collect();
    let seeded = fleet.report(&live, 0, Vec::new());
    assert!(seeded.volumes.stranded.is_empty(), "{seeded:?}");
    assert_eq!(hosts::expected(&seeded), Verdict::Unrun(hosts::FLIPS));

    let key = Key::Shard(fleet.cells[FAULTED].placement.shard);
    let item = (fleet.store.0.borrow().current(&key).cloned()).expect("a stored shard record");
    let record = ShardRecord::decode(&item.value).expect("a shard record");
    let displaced = record.active;
    let generation = ShardGeneration::new(record.generation.get() + 1);
    let flipped = ShardRecord {
        active: VolumeId::new("vol-0f000000000000ccc").expect("a volume ID"),
        generation: generation.expect("a next generation"),
        ..record
    };
    let write = Write::Exact {
        expect: item.version,
        value: flipped.encode(),
    };
    let outcome = Store::write(&mut fleet.store.clone(), &key, &write);
    assert!(matches!(outcome, Outcome::Committed(_)), "{outcome:?}");
    let report = fleet.report(&live, 0, Vec::new());
    assert_eq!(report.volumes.stranded, [displaced]);
    let failed = Verdict::Fail(rule, format!("volume {}", displaced.as_str()));
    assert_eq!(hosts::expected(&report), failed);
    assert_eq!(report.credit(), failed);
}

/// Scenario checks report named failures when one receipt has two volumes, a receipt names a volume missing from the
/// provider's log, a create precedes the release, a stalled shard moves twice, or the stranded list holds a volume
/// other than the one a landed flip's crash displaced. Each volume-scenario witness reads `Unrun` when the log lacks
/// that witness. A cell whose flip landed reads its stranded-volume witness `Unrun` when its list omits the displaced
/// volume.
#[test]
fn the_volume_scenarios_fail_their_rules_by_name_and_read_a_missing_witness_unrun() {
    let missing = Verdict::Unrun;
    let correlated = passing(&Config::correlated(1));
    let rule = "a replacement receipt's create made a second volume";
    let second = altered(&correlated, |r| r.volumes.made = 2);
    assert_eq!(second.rule(), Some(rule));
    let rule = "a create reached the provider before the operator released the correlated hold";
    let early = altered(&correlated, |r| r.volumes.calls_at_release = Some(1));
    assert_eq!(early.rule(), Some(rule));
    let rule = "a replacement receipt records a volume the provider did not make for its token";
    let unprovided = Verdict::Fail(rule, format!("shard {S3}"));
    let seeded = history(&correlated, S3)[0].active;
    let swapped = altered(&correlated, |r| r.volumes.provided[0].1 = seeded);
    assert_eq!(swapped, unprovided);
    let retokened = altered(&correlated, |r| r.volumes.provided[0].0.push('0'));
    assert_eq!(retokened, unprovided);
    for latched in [0, 2] {
        let unlatched = altered(&correlated, |r| r.volumes.latched = latched);
        assert_eq!(unlatched, missing(hosts::HOLD_LATCHED), "{latched}");
    }
    let unreleased = altered(&correlated, |r| r.volumes.released = 0);
    assert_eq!(unreleased, missing(hosts::HOLD_RELEASED));
    let unflipped = altered(&correlated, |r| r.evidence.replaced = vec![(0, 1)]);
    assert_eq!(unflipped, missing(hosts::FLIPS));
    let warm = altered(&correlated, |r| r.volumes.cold.clear());
    assert_eq!(warm, missing(hosts::COLD_START));
    let unlost = altered(&correlated, |r| {
        r.volumes.lost.clear();
        (r.volumes.made, r.volumes.calls) = (0, 0);
    });
    assert_eq!(unlost, missing(hosts::VOLUME_LOST));
    // Judged as the late impairment and as a crash-table cell, the correlated log lacks their witnesses.
    let late = altered(&correlated, |r| {
        r.config.scenario = Scenario::CorrelatedLate
    });
    assert_eq!(late, missing(hosts::LATCHED_AT_CREATE));
    let late_unreleased = altered(&correlated, |r| {
        r.config.scenario = Scenario::CorrelatedLate;
        (r.volumes.latched_at_create, r.volumes.released) = (1, 0);
    });
    assert_eq!(late_unreleased, missing(hosts::HOLD_RELEASED));
    let cell = Scenario::Replace(ReplaceCell::all()[0]);
    let uncrashed = altered(&correlated, |r| r.config.scenario = cell);
    assert_eq!(uncrashed, missing(hosts::CRASH_CELL));
    // A listed volume fails the stranded rule in a run no crash cut after its flip. A cell whose flip landed lists
    // the displaced volume alone: without it the cell's witness is missing, and a second volume fails the rule, as
    // the displaced volume does when the cell is judged as one whose flip write was lost.
    let rule = "a volume no shard record names stayed active with no crash after its flip";
    let stranded = |volume: VolumeId| Verdict::Fail(rule, format!("volume {}", volume.as_str()));
    let left = altered(&correlated, |r| r.volumes.stranded = vec![seeded]);
    assert_eq!(left, stranded(seeded));
    let landed = ReplaceCell {
        boundary: Boundary::Flip,
        ending: reconcile::Ending::Acknowledged,
    };
    let flipped = passing(&Config::replace(1, landed));
    let displaced = history(&flipped, 1)[0].active;
    assert_eq!(flipped.volumes.stranded, [displaced]);
    let retired = altered(&flipped, |r| r.volumes.stranded.clear());
    assert_eq!(retired, missing(hosts::DISPLACED_STRANDED));
    let created = history(&flipped, 1).last().unwrap().active;
    let second = altered(&flipped, |r| r.volumes.stranded.push(created));
    assert_eq!(second, stranded(created));
    let unlanded = Scenario::Replace(ReplaceCell {
        ending: reconcile::Ending::Lost,
        ..landed
    });
    let lost = altered(&flipped, |r| r.config.scenario = unlanded);
    assert_eq!(lost, stranded(displaced));

    let stalled = passing(&Config::stall(1));
    let unmove = |r: &mut Report| {
        let versions = &mut r.evidence.histories[FAULTED].1;
        let owner = versions[0].owner;
        versions.iter_mut().for_each(|record| record.owner = owner);
    };
    let unmoved = altered(&stalled, unmove);
    assert_eq!(unmoved, missing(hosts::STALLED_TAKEOVER));
    let unstalled = altered(&stalled, |r| r.volumes.stalled.clear());
    assert_eq!(unstalled, missing(hosts::VOLUME_STALLED));
    let without =
        |r: &mut Report, blocker: Blocker| r.recon.blockers.retain(|(_, _, b, _)| *b != blocker);
    let unheld = altered(&stalled, |r| without(r, Blocker::DeviceFailureHold));
    assert_eq!(unheld, missing(hosts::DEVICE_HOLD));
    // The stalled shard moved once, to its named standby. One more move, back to the host the record then names
    // standby, fails the at-most-once rule.
    let back = altered(&stalled, |r| {
        let versions = &mut r.evidence.histories[FAULTED].1;
        let (first, last) = (versions[0], *versions.last().unwrap());
        versions.push(ShardRecord {
            standby: Some(first.owner),
            ..last
        });
        versions.push(ShardRecord {
            owner: first.owner,
            standby: None,
            ..last
        });
    });
    let rule = "a shard on a stalled volume changed hands more than once";
    let twice = format!("shard {S3} moved 2 times");
    assert_eq!(back, Verdict::Fail(rule, twice));

    // Judged as the impaired cases, the stall log lacks the impaired blocker; with that blocker logged it lacks each
    // outcome the stall did not have.
    let impaired = |r: &mut Report, scenario: Scenario| {
        r.config.scenario = scenario;
        (r.recon).enter(
            S3,
            Refused::row(Blocker::VolumeImpaired),
            Blocker::VolumeImpaired,
        );
    };
    let unretained = altered(&stalled, |r| r.config.scenario = Scenario::Impaired);
    assert_eq!(unretained, missing(hosts::IMPAIRED));
    let retained = altered(&stalled, |r| impaired(r, Scenario::Impaired));
    assert_eq!(retained, Verdict::Pass);
    let unrecovered = altered(&stalled, |r| {
        impaired(r, Scenario::Impaired);
        r.shards[FAULTED].recoveries.truncate(1);
    });
    assert_eq!(unrecovered, missing(hosts::RESTART_AFTER_STALL));
    let taken = altered(&stalled, |r| impaired(r, Scenario::ImpairedBrief));
    assert_eq!(taken, missing(hosts::NO_TAKEOVER));
    let cold = altered(&stalled, |r| {
        impaired(r, Scenario::ImpairedBrief);
        unmove(r);
        r.shards[FAULTED].recoveries.truncate(1);
    });
    assert_eq!(cold, missing(hosts::WARM_AFTER_STALL));
    let brief = altered(&stalled, |r| {
        impaired(r, Scenario::ImpairedBrief);
        r.volumes.stalled.clear();
    });
    assert_eq!(brief, missing(hosts::VOLUME_STALLED));
}

/// A flip gives the next generation to the host of the spare the read record names. A history altered to another
/// owner at the generation rise fails the named-successor rule, also when the read record names that owner
/// standby, and a rise onto the host of the spare the read record names passes it.
#[test]
fn a_generation_rise_onto_a_host_other_than_the_spares_fails_the_named_successor_rule() {
    let lone = passing(&Config::lost_alone(1));
    let versions = history(&lone, S3);
    let rises = versions.windows(2);
    let rise = (rises.clone()).position(|pair| pair[0].generation != pair[1].generation);
    let rise = rise.expect("the lone loss flips once");
    let spare = versions[rise].spare.expect("a flip reads a spare").1;
    assert_eq!(versions[rise + 1].owner, spare);
    let other = [H3, H5].map(|n| Host::new(n).unwrap());
    let other = (other.into_iter()).find(|&host| host != spare).unwrap();
    // Every version from the flip on names `other` owner, so the rise is the one owner change the edit makes.
    let elsewhere = |r: &mut Report| {
        let versions = &mut r.evidence.histories[FAULTED].1;
        (versions[rise + 1..].iter_mut()).for_each(|record| record.owner = other);
    };
    let unnamed = Verdict::Fail(
        hosts::UNNAMED_SUCCESSOR,
        format!("shard {S3} on host {}", other.get()),
    );
    assert_eq!(altered(&lone, elsewhere), unnamed);
    let onto_the_standby = altered(&lone, |r| {
        r.evidence.histories[FAULTED].1[rise].standby = Some(other);
        elsewhere(r);
    });
    assert_eq!(onto_the_standby, unnamed);
    let onto_the_spare = altered(&lone, |r| {
        let read = &mut r.evidence.histories[FAULTED].1[rise];
        read.spare = read.spare.map(|(volume, _)| (volume, other));
        elsewhere(r);
    });
    assert_ne!(onto_the_spare.rule(), Some(hosts::UNNAMED_SUCCESSOR));
}

/// A volume run's tape one byte short is refused, on root 1; the scheduled case replays the run to an equal report.
#[test]
fn a_volume_run_s_tape_one_byte_short_is_refused() {
    let config = Config::impaired(1);
    refuses_a_short_tape(&config, passing(&config).recording());
}

/// `short`, a recording of `config`'s run, is refused as `Short` once its tape lacks its last byte.
fn refuses_a_short_tape(config: &Config, mut short: Recording) {
    short.tape.truncate(short.tape.len() - 1);
    let refused = replay(config, &short);
    let short = crate::sim::choice::ChoiceError::Short;
    assert!(
        matches!(&refused, Err(Stopped::Choice(refusal)) if refusal.error == short),
        "{refused:?}"
    );
}

/// `config`'s run replays its tape to an equal report, and a tape one byte short is refused.
pub(super) fn replays_and_refuses_a_short_tape(config: &Config) {
    let report = passing(config);
    let recording = report.recording();
    assert_eq!(replay(config, &recording), Ok(report));
    refuses_a_short_tape(config, recording);
}

/// F5 lets a served shard carry `VolumeImpaired`, the reconciler's retention of an impaired volume its tenure serves
/// on, and no other blocker; an unserved shard's `VolumeImpaired` or `CorrelatedHold` stays its final blocker past a
/// later restart's or takeover's hold, and only while no later volume-side blocker was entered.
#[test]
fn a_served_shard_carries_only_volume_impaired_and_a_later_hold_leaves_a_volume_blocker_carried() {
    use super::reconcile::{ReconLog, SettlePhase};
    let shard = crate::net::ownership::Shard::new(1).unwrap();
    let state = |served, blocker| {
        [oracles::Settled {
            shard,
            served,
            blocker: Some(blocker),
        }]
    };
    let mut log = ReconLog::default();
    log.settle = Some(SettlePhase {
        started: 0,
        turns: Some(3),
    });
    log.enter(
        1,
        Refused::row(Blocker::VolumeImpaired),
        Blocker::VolumeImpaired,
    );
    let hold = Refused::row(Blocker::RecordedHolderHold);
    log.enter(1, hold, Blocker::RecordedHolderHold);

    let serving = state(true, Blocker::VolumeImpaired);
    assert!(serving[0].settled());
    assert_eq!(oracles::settled(&serving, &log), Verdict::Pass);
    let stale = state(true, Blocker::RecordedHolderHold);
    assert!(!stale[0].settled());
    let at = "shard 1 Some(RecordedHolderHold)".to_owned();
    assert_eq!(
        oracles::settled(&stale, &log),
        Verdict::Fail(oracles::STALE_BLOCKER, at)
    );

    for carried in [Blocker::VolumeImpaired, Blocker::RecordedHolderHold] {
        let held = state(false, carried);
        assert!(held[0].settled());
        assert_eq!(oracles::settled(&held, &log), Verdict::Pass, "{carried:?}");
    }

    let mut later = log.clone();
    later.enter(
        1,
        Refused::row(Blocker::CorrelatedHold),
        Blocker::CorrelatedHold,
    );
    let superseded = state(false, Blocker::VolumeImpaired);
    let at = "shard 1 Some(VolumeImpaired)".to_owned();
    assert_eq!(
        oracles::settled(&superseded, &later),
        Verdict::Fail(oracles::UNBACKED, at)
    );
    let correlated = state(false, Blocker::CorrelatedHold);
    assert_eq!(oracles::settled(&correlated, &later), Verdict::Pass);
}

/// The scheduled roots of the volume scenarios: every check above that runs one root on the fast tier, on root 2,
/// the correlated run's replay on root 1, the rerun-first order of the held owner's rerun against its standby's
/// takeover on root 1, and all 21 replacement crash cells with their three endings each. Each check and each cell
/// that passes prints one line, and the last line counts them.
#[test]
#[ignore = "volume scenarios on their second root and the full replacement crash table; the search-nightly lane's row fleet-scheduled-roots runs it with --ignored"]
fn the_volume_scenarios_pass_on_their_scheduled_roots_and_every_crash_cell() {
    let moved = "a shard on a stalled volume changed hands more than once";
    let provisioned = "a host loss changed a shard's generation or provisioned a volume";
    let checks: [(&str, &dyn Fn()); 11] = [
        ("no-fault root 2", &|| {
            with_no_fault_the_reconciler_writes_no_receipt_and_calls_no_provider_on(2)
        }),
        ("impaired root 2", &|| {
            an_impaired_volume_is_retained_through_one_takeover_that_holds_and_the_successor_s_restart_on(2)
        }),
        ("impaired-brief root 2", &|| {
            an_impaired_volume_whose_stall_clears_early_restarts_warm_with_no_takeover_on(2)
        }),
        ("stall root 2", &|| {
            a_stall_the_control_plane_reports_healthy_moves_the_shard_once_holds_and_recovers_on(2)
        }),
        ("control enroll-back root 2", &|| {
            control_a_reconciler_that_enrolls_the_former_owner_moves_a_stalled_shard_twice_on(
                2, moved,
            )
        }),
        ("lost-alone root 2", &|| {
            a_volume_lost_alone_is_replaced_once_at_the_next_generation_and_starts_cold_on(2)
        }),
        ("correlated root 2", &|| {
            a_loss_beside_an_impaired_volume_holds_until_the_operator_release_on(2)
        }),
        ("correlated-late root 2", &|| {
            a_volume_that_turns_impaired_after_the_receipt_holds_the_create_until_the_operator_release_on(2)
        }),
        ("control loss-evidence root 2", &|| {
            control_a_host_loss_reported_as_volume_loss_fails_host_loss_keeps_volume_on(
                2,
                provisioned,
            )
        }),
        ("correlated-replay root 1", &|| {
            replays_and_refuses_a_short_tape(&Config::correlated(1))
        }),
        ("held-race-rerun-first root 1", &|| {
            a_held_owner_s_rerun_and_its_standby_s_takeover_race_on(true);
        }),
    ];
    for (name, check) in checks {
        check();
        println!("fleet: scheduled volume {name}: pass");
    }
    let cells = replace_cells_converge(&Boundary::ALL, true);
    for cell in &cells {
        println!("fleet: scheduled volume {cell} root 1: pass");
    }
    println!(
        "fleet: scheduled volume: {} checks and {} crash cells passed",
        checks.len(),
        cells.len()
    );
}

/// The control of the declared hold with the production statuses: on the stall scenario H3's restart ends `Exit::Held`,
/// and H3 publishes the `Held` status built from that incarnation's `host::recover::Ended::refusal`, so its host agent
/// declares itself unhealthy. H0, s3's named standby, publishes `Standby` from its own wait, with the target that
/// wait's role read returned, and its agent addresses the witness to that status; the stall test checks that H0's
/// takeover then moves s3 once and serves it warm after the stall. Under plant `WaitUnpublished` (code 55) H0's wait
/// publishes no `Standby` status for s3, so no witness reaches H0, the shard never moves, and the credit reads its
/// stalled-takeover witness missing.
#[test]
fn a_standby_whose_wait_publishes_no_status_takes_no_held_shard_over() {
    let unpublished = run(&Config::stall(1).hostile(Plant::WaitUnpublished, FAULTED as u32));
    let unpublished = unpublished.expect("a run inside the limits");
    assert!(unpublished.planted);
    let log = &unpublished.hosts;
    assert!(log.nominations > 0, "{}", unpublished.summary());
    assert_eq!((log.addressed, log.lapsed), (0, 0));
    assert_eq!(moves(&unpublished, S3), 0);
    assert!(unpublished.hosts.takeovers.is_empty());
    assert_eq!(unpublished.hosts.exempt, BTreeSet::from([S3]));
    let missing = "witness takeovers-of-stalled-shard missing";
    assert_eq!(missing, hosts::STALLED_TAKEOVER);
    assert_eq!(
        unpublished.credit(),
        Verdict::Unrun(missing),
        "{}",
        unpublished.summary()
    );
}

/// Whether a witness for s3 waits in the fleet's queue for its standby process.
fn s3_nominated(fleet: &Fleet<'_>) -> bool {
    let shard = fleet.cells[FAULTED].placement.shard;
    (fleet.nominated.iter()).any(|(_, _, witness, _)| witness.shard == shard)
}

/// The race of the held process's own rerun against the standby's takeover: s3's volume stalls with the control plane
/// reporting it healthy, H3's restart ends `Exit::Held`, and H0 is nominated. In the round the witness reaches H0's
/// queue the stall clears and H3's held process runs its next incarnation. The race ends with one winner in either
/// order. Takeover first: H0's compare-and-swap commits at the record version the witness names, H0 serves s3, and H3's
/// rerun finds the record naming another owner and runs no restart. Rerun first: H3's restart bumps `E` and serves s3,
/// and H0's takeover finds the record past the witness's target and writes nothing. Each order commits exactly one
/// owner change or bump over the version both read. The fast tier runs the takeover-first order; the scheduled case
/// runs the rerun-first order.
#[test]
fn a_held_owner_s_rerun_and_its_standby_s_takeover_race_to_one_winner_in_either_order() {
    let report = a_held_owner_s_rerun_and_its_standby_s_takeover_race_on(false);
    // Control: the loser's write committed beside the winner's at the version both read, one more owner at the
    // winner's attempt, fails the one-owner rule by name.
    let twice = loser_beside_winner(&report, H3);
    let two = "two hosts own one attempt of a shard";
    assert_eq!(two, oracles::TWO_OWNERS);
    assert_eq!(twice.rule(), Some(two));
}

/// The one-owner verdict over `report`'s histories with s3's last version repeated under `loser` as owner.
fn loser_beside_winner(report: &Report, loser: u64) -> Verdict {
    let mut histories = report.evidence.histories.clone();
    let (_, versions) = (histories.iter_mut())
        .find(|(shard, _)| shard.get() == S3)
        .expect("s3's history");
    let won = *versions.last().unwrap();
    let loser = crate::failover::records::Host::new(loser).unwrap();
    versions.push(ShardRecord {
        owner: loser,
        ..won
    });
    oracles::one_owner(&histories, &report.evidence.activations)
}

/// The checks of the test above with the held process's rerun ordered first (`rerun_first`) or second.
pub(super) fn a_held_owner_s_rerun_and_its_standby_s_takeover_race_on(rerun_first: bool) -> Report {
    let mut script = Scenario::Stall.episodes(false);
    script.push(super::faults::Episode {
        trigger: super::faults::Trigger::When(s3_nominated),
        scope: Vec::new(),
        action: super::faults::Action::Rerun(FAULTED),
        heal: None,
    });
    {
        let report = super::host_tests::scripted_with(&Config::stall(1), script, rerun_first);
        let versions = history(&report, S3);
        let last = versions.last().unwrap();
        let (winner, loser) = match rerun_first {
            false => (H0, H3),
            true => (H3, H0),
        };
        assert_eq!(last.owner.get(), winner, "rerun first {rerun_first}");
        let recoveries = &report.shards[FAULTED].recoveries;
        let served = recoveries.last().unwrap();
        assert_eq!(served.host.get(), winner, "rerun first {rerun_first}");
        assert!(
            served
                .sweep
                .is_some_and(|(of, swept)| of > 0 && of == swept),
            "rerun first {rerun_first}: {:?}",
            served.sweep
        );
        let after_hold = recoveries.iter().skip(1);
        assert!(
            after_hold
                .into_iter()
                .all(|recovery| recovery.host.get() != loser),
            "rerun first {rerun_first}: {recoveries:?}"
        );
        assert_eq!(moves(&report, S3), usize::from(!rerun_first));
        let attempts: Vec<_> = (report.hosts.takeovers.iter())
            .map(|attempt| (attempt.shard, attempt.host, attempt.refused.as_deref()))
            .collect();
        let log = &report.hosts;
        // Every incarnation of the race runs: H3's rerun reads its own role and `host::recover` either way.
        assert_eq!(
            (log.refused_reruns, log.rerun_dropped),
            (1, 0),
            "rerun first {rerun_first}"
        );
        match rerun_first {
            // H3's rerun read the record naming H0 and waited.
            false => assert_eq!(attempts, [(S3, H0, None)]),
            true => {
                assert_eq!(attempts, [(S3, H0, Some("Stopped"))]);
                let commands = &report.hosts.takeovers[0].commands;
                assert!(
                    commands.is_empty(),
                    "H0's reservation commands: {commands:?}"
                );
            }
        }
        // One write commits over the version both read, and none after it: the winner's swap or bump, and no second
        // restart over the winner's serving tenure once the stall's own heal falls due.
        let first = versions.first().expect("s3's seeded record");
        let changes: Vec<(u64, u32)> = (versions.windows(2))
            .filter(|pair| (pair[0].owner, pair[0].attempts) != (pair[1].owner, pair[1].attempts))
            .map(|pair| (pair[1].owner.get(), pair[1].attempts))
            .collect();
        let held = first.attempts + 1;
        assert_eq!(
            changes,
            [(H3, held), (winner, held + 1)],
            "rerun first {rerun_first}: H3's held bump, then the winner's write"
        );
        assert_eq!(
            recoveries.len(),
            2,
            "rerun first {rerun_first}: {recoveries:?}"
        );
        // Both rerun orders leave H3's recovery slot free.
        let slot = report.hosts.sealed(H3).last().map(|gauges| gauges[2]);
        assert_eq!(
            slot,
            Some(Gauge::known(0, 1)),
            "rerun first {rerun_first}: host {H3}"
        );
        assert_eq!(
            report.verdicts.one_owner,
            Verdict::Pass,
            "rerun first {rerun_first}"
        );
        report
    }
}
