//! The pull-request fixtures of the cycle histories: short seeded runs that pass, each control failing through
//! its declared rule, and the tape, ledger and census rules on their own inputs.

use super::census::{REQUIRED, Refused, Status, census};
use super::ledger::{Accounted, Limits, Sample, UNPUBLISHED, crossing_floor, judge};
use super::tape::{Arrival, Buckets, Kind, Mix, PhaseReport, Tape};
use super::*;
use crate::net::observe::{FREE_RUNS, Tables};
use crate::storage::device::DeviceRange;
use crate::storage::write_guard::{Conflict, Guarded};
use crate::storage::{AllocationId, SlotIndex};

/// The seed of the planted controls, whose first two cycles are host-loss takeovers.
const CONTROL_SEED: u64 = 27;

const SLOT_SEEDS: [u64; 2] = [2, 3];

const SLOT_CYCLES: u32 = 18;

const SLOT_TOTALS: &str = "cycles: slot-reuse: 2 seeds of 18 cycles; replacements 36 drops 36 preempts 1 live-max 3; \
                           every run passed its four verdicts and its quiescent conservation, and no replaced host \
                           returned";

/// A run of `cycles` cycles under [`CONTROL_SEED`] with `plant` at cycle 1, which follows a host loss.
fn planted(plant: Plant, cycles: u32) -> Report {
    let config = Config {
        plant: Some((plant, 1)),
        ..Config::discovery(CONTROL_SEED, cycles)
    };
    let report = run(&config);
    assert!(report.planted, "{plant:?}: the plant changed its target");
    let restarts = report.composed.recoveries[Recovery::Restart as usize];
    let host_loss = match report.cycles.get(1) {
        Some(cycle) => cycle.class != Class::ProcessDeath,
        None => restarts == 0,
    };
    assert!(
        host_loss,
        "{plant:?}: the planted cycle follows a host loss"
    );
    report
}

/// Six cycles under each of five seeds, the control seed among them as the controls' unplanted sibling, pass the four
/// verdicts and the quiescent conservation judgment, and the five runs compose every recovery kind and a row unit
/// the recovery's loss report counts. Every phase settles each offered request in one bucket with none dropped;
/// every tenure serves its whole eligible set from the capturing tenure's cut at the generation and volume the run
/// started with; fills, acknowledged INVALIDATEs and recorded suffixes grow the resident slots, the coverage entries
/// and the chain, all of it accounted, so the growth passes; six boundaries meet the crossing floor of a tolerance
/// of four; each serve phase's peak holds at least the resident bytes of its boundary; the publish-aligned judgment
/// reads inconclusive with no publication after quiescence; and the plateau reads inconclusive with no accepted
/// band. Every boundary sample reads `Tables::Conserved`: a sample taken inside a warm load would read
/// `Tables::Unreadable`, so each sample follows its tenure's warm-load commit. At least one judged sample has more
/// resident slots than its tenure filled, so a slot its warm load restored was still resident when
/// [`conserved`](crate::net::observe::conserved) read its tables: a tenure's successful fills are its only new
/// residents, one each.
#[test]
fn seeded_cycles_pass_four_verdicts_with_accounted_growth_conserved() {
    let mut recoveries = [0; 7];
    let (mut failed_units, mut interrupted) = (0, 0);
    let mut responses = 0;
    let mut kept_restored = false;
    let mut fresh_hosts = 0;
    for seed in [1, CONTROL_SEED, 5, 11, 13] {
        let report = run(&Config::discovery(seed, 6));
        assert!(report.passed(), "{}", report.lines().join("\n"));
        assert_eq!(report.oracle, [None, None], "seed {seed}");
        assert!(
            report
                .cycles
                .iter()
                .any(|cycle| cycle.class != Class::ProcessDeath),
            "seed {seed}: a tenure recovers from a host loss"
        );
        fresh_hosts += report.composed.fresh_hosts;
        assert!(report.guarded.clean(), "seed {seed}: {:?}", report.guarded);
        assert!(
            report.guard_held(),
            "seed {seed}: the guard checked at least one write per fill: {:?}",
            report.guarded
        );
        assert_eq!(admitted(&report), Ok(()), "seed {seed}");
        if seed == 1 {
            // Each edit isolates a guard condition that makes admission fail while `edited.passed()` remains true.
            let fills = u64::from(report.composed.fills);
            assert!(fills >= 2 && report.guarded.checked >= fills);
            let conflict = Conflict {
                rule: crate::storage::write_guard::W1,
                writer: AllocationId::new(SlotIndex(1), 1),
                holder: AllocationId::new(SlotIndex(2), 1),
                range: DeviceRange::new(0, IO_UNIT as u32).expect("a range"),
            };
            type Edit = fn(&mut Guarded, u64, Conflict);
            let edits: [(&str, Edit); 3] = [
                ("fewer checked writes than fills", |g, fills, _| {
                    g.checked = fills - 1
                }),
                ("a skipped slot", |g, _, _| g.skipped = 1),
                ("a conflict", |g, _, conflict| g.first = Some(conflict)),
            ];
            for (edit, apply) in edits {
                let mut edited = report.clone();
                apply(&mut edited.guarded, fills, conflict);
                assert!(edited.passed() && !edited.guard_held(), "{edit}");
                let refused = admitted(&edited).expect_err(edit);
                assert!(refused.ends_with(&format!("guarded {:?}", edited.guarded)));
            }
        }
        assert_eq!(report.cycles.len(), 6);
        assert_eq!(
            report.conservation.plateau,
            Verdict::Inconclusive("no accepted plateau band")
        );
        let aligned = "no checkpoint or frontier publication follows a quiescent boundary";
        assert_eq!(report.conservation.aligned, Verdict::Inconclusive(aligned));
        assert!(crossing_floor(report.config.epsilon, 1) <= 6);
        let phases = report.cycles.iter().flat_map(|cycle| cycle.phases.iter());
        assert!(phases.clone().all(|phase| phase.buckets.settled()));
        let total = report.buckets();
        assert!(total.settled() && total.retained > 0);
        assert_eq!(total.dropped(), 0);
        interrupted += total.interrupted;
        let first = &report.cycles[0];
        for cycle in &report.cycles {
            assert_eq!(cycle.served, cycle.eligible, "seed {seed}: {cycle:?}");
            assert!(cycle.eligible > 0);
            assert_eq!((cycle.cut.0, cycle.cut.1), (first.cut.0, first.cut.1));
            assert_eq!(cycle.tenure.g, first.tenure.g, "the generation is kept");
            let sample = cycle.sample.expect("a boundary sample");
            assert_eq!(sample.resident_slots, sample.accounted.resident_slots);
            assert_eq!(
                sample.conservation,
                Tables::Conserved,
                "seed {seed}: {cycle:?}"
            );
            kept_restored |= sample.resident_slots > u64::from(cycle.fills);
            assert!(
                cycle.phases[0].peak_charged >= sample.resident_bytes,
                "{cycle:?}"
            );
            failed_units += cycle.failed_units;
        }
        for (sum, count) in recoveries.iter_mut().zip(report.composed.recoveries) {
            *sum += count;
        }
        for pair in report.cycles.windows(2) {
            let credited = report.reached.contains(&(pair[1].class, Site::Response));
            assert!(!pair[0].response || credited, "seed {seed}: {pair:?}");
            responses += u32::from(pair[0].response);
        }
        assert!(
            report
                .cycles
                .windows(2)
                .all(|pair| pair[0].tenure < pair[1].tenure)
        );
        let composed = report.composed;
        assert!(
            composed.fills > 0 && composed.invalidations > 0,
            "seed {seed}: {composed:?}"
        );
        assert_eq!(composed.captures, 6);
        let last = report.cycles[5].sample.expect("a boundary sample");
        assert!(last.suffixes > 0 && last.coverage_entries > 0);
        assert_eq!(last.coverage_entries, last.accounted.coverage_entries);
    }
    assert!(recoveries.iter().all(|count| *count > 0), "{recoveries:?}");
    assert!(fresh_hosts > 0, "a fresh host attaches the retained volume");
    assert!(
        failed_units > 0,
        "a loss report counts an injected row unit"
    );
    assert!(
        interrupted > 0,
        "a cut settles an unfinished GET interrupted"
    );
    assert!(responses > 0, "a cut drops with its owner holding a GET");
    assert!(
        kept_restored,
        "a judged boundary sample holds a slot its warm load restored"
    );
}

/// One configuration runs to equal reports in two runs, its identity is a function of its fields, and neither
/// the output set nor the census takes a second report of one identity.
#[test]
fn one_identity_replays_to_an_equal_report_and_is_kept_once() {
    let config = Config::discovery(2, 4);
    let (first, second) = (run(&config), run(&config));
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first, second);
    assert!(first.guard_held(), "{:?}", first.guarded);
    assert_ne!(config.identity(), Config::discovery(3, 4).identity());
    assert_ne!(config.identity(), Config::discovery(2, 5).identity());
    let mut outputs = Outputs::default();
    assert_eq!(outputs.keep(first.clone()), Ok(()));
    let mut other = second.clone();
    other.cycles.clear();
    assert_eq!(outputs.keep(other), Err(config.identity()));
    assert_eq!(
        outputs.reports(),
        [&first],
        "the first report is kept whole"
    );
    let repeated = census(&REQUIRED, &[&first, &second]);
    assert_eq!(repeated, Err(Refused::Repeated(config.identity())));
}

/// The run identity is a fixed encoding: seed 1's 32-cycle discovery configuration has the identity the long-run
/// case prints, an absent band or plant differs from a present zero one, and every plant has its own identity. These
/// vectors check the encoding only, not the simulation's behavior across revisions.
#[test]
fn the_run_identity_is_a_fixed_encoding_of_every_field() {
    let base = Config::discovery(1, 32);
    assert_eq!(base.identity(), "f437f622cbdab38c");
    let banded = Config {
        band: Some(0),
        ..base
    };
    assert_ne!(banded.identity(), base.identity());
    let reuse = Config::slot_reuse(1, 24);
    assert_eq!(reuse.identity(), "9f73e8a4174670b8");
    assert_ne!(reuse.identity(), Config::discovery(1, 24).identity());
    let plants = [
        Plant::AlwaysMiss,
        Plant::RestoredEntryMiss,
        Plant::TotalEviction,
        Plant::SwappedClass,
        Plant::Attribution,
        Plant::ShrunkCoverage,
        Plant::Leak,
        Plant::StuckCapture,
        Plant::NoPublish,
        Plant::DroppedFill,
        Plant::UnreportedDamage,
        Plant::LeakedUnit,
        Plant::KeptPair,
        Plant::EarlyRelease,
        Plant::FourthAttach,
        Plant::ListedDrop,
        Plant::ReturnedHost,
        Plant::NoEffectPreempt,
        Plant::RefusedRecovery,
        Plant::RefusedDesignation,
        Plant::EndedRole,
        Plant::EarlyReturn,
        Plant::UnsettledRelease,
    ];
    let mut identities: BTreeSet<String> = (plants.iter())
        .map(|plant| {
            let config = Config {
                plant: Some((*plant, 0)),
                ..base
            };
            config.identity()
        })
        .collect();
    assert_eq!(
        identities.len(),
        plants.len(),
        "each plant has its own code"
    );
    identities.insert(base.identity());
    identities.insert(banded.identity());
    assert_eq!(identities.len(), plants.len() + 2);
}

/// The always-miss control: the recovered tenure restores the cut and then drops every restored entry from RAM, so
/// every GET is a legal miss. Safety, containment and progress pass, and retention fails in the harness's sweep
/// and in the oracle's judgment.
#[test]
fn control_always_miss_fails_retention_while_safety_passes() {
    let report = planted(Plant::AlwaysMiss, 2);
    assert_eq!(
        report.retention.rule(),
        Some("a retained entry was not served its exact bytes at the recovered tenure"),
        "{}",
        report.summary()
    );
    assert_eq!(
        report.oracle,
        [
            None,
            Some("a retained entry outside every damage set was never served after host loss")
        ]
    );
    assert_eq!(report.cycles[1].served, 0);
    assert!(report.cycles[1].eligible > 0);
    assert!(report.safety.passed() && report.containment.passed() && report.progress.passed());
}

/// The restored-entry-miss control: one restored entry is dropped from RAM with no record. Retention fails for
/// that entry alone.
#[test]
fn control_one_restored_entry_that_misses_fails_retention() {
    let report = planted(Plant::RestoredEntryMiss, 2);
    assert_eq!(
        report.retention.rule(),
        Some("a retained entry was not served its exact bytes at the recovered tenure"),
        "{}",
        report.summary()
    );
    assert_eq!(
        report.oracle,
        [
            None,
            Some("a retained entry outside every damage set was never served after host loss")
        ]
    );
    let cycle = &report.cycles[1];
    assert_eq!(cycle.served + 1, cycle.eligible);
    assert!(report.safety.passed() && report.containment.passed());
}

/// The total-eviction control: a row unit is flipped and the load refuses the whole slot. The oracle fails
/// retention for an entry no damaged unit holds, and the run ends with its progress failed at the load.
#[test]
fn control_total_eviction_on_one_damaged_unit_fails_retention() {
    let report = planted(Plant::TotalEviction, 3);
    assert_eq!(
        report.retention.rule(),
        Some("a retained entry outside every damage set was lost on host loss"),
        "{}",
        report.summary()
    );
    assert_eq!(
        report.progress.rule(),
        Some("a recovery's load did not open")
    );
    assert_eq!(report.cycles.len(), 1, "the refused load serves no cycle");
    assert!(report.safety.passed());
}

/// The swapped-class control: a host-loss recovery attaches with no warm source, as an actual volume loss does.
/// Every GET misses: retention fails by the harness's sweep rule, and the oracle names the cold-start rule.
#[test]
fn control_a_host_loss_treated_as_a_volume_loss_fails_retention() {
    let report = planted(Plant::SwappedClass, 2);
    assert_eq!(
        report.retention.rule(),
        Some("a retained entry was not served its exact bytes at the recovered tenure")
    );
    assert_eq!(
        report.oracle,
        [
            None,
            Some("host loss replaced a retained cut with a cold start")
        ],
        "{}",
        report.summary()
    );
    assert!(report.safety.passed());
    let warm = run(&Config::discovery(CONTROL_SEED, 2));
    assert_eq!(warm.oracle, [None, None], "{}", warm.summary());
    assert!(warm.retention.passed(), "{}", warm.summary());
    assert_eq!(warm.cycles.len(), 2, "{}", warm.summary());
    let (retained, lost) = (&warm.cycles[1], &report.cycles[1]);
    assert!(
        retained.eligible > 0 && retained.served == retained.eligible,
        "the warm sibling serves every retained entry: {retained:?}"
    );
    assert_eq!(
        (lost.eligible, lost.served),
        (retained.eligible, 0),
        "the cold start serves none of the entries its warm sibling serves"
    );
}

/// The attribution control: a payload unit is flipped and its damage row names another unit. Containment fails
/// because the rows differ from the injected units, and the oracle excuses no loss on the unnamed unit.
#[test]
fn control_a_damage_row_on_the_wrong_unit_fails_containment() {
    let report = planted(Plant::Attribution, 2);
    let rule = "a damage row names a unit no fault was injected on";
    assert_eq!(
        report.containment.rule(),
        Some(rule),
        "{}",
        report.summary()
    );
    assert_eq!(
        report.oracle,
        [
            None,
            Some("a retained entry outside every damage set was never served after host loss")
        ]
    );
    assert!(report.safety.passed());
}

/// The safety control: a coverage write drops an acknowledged entry of its page, so the next tenure restores and
/// serves a covered version. Safety fails in the harness's sweep and in the oracle's `History` rules, and retention
/// does not pass, since the failing group's preservation judgment never ran.
#[test]
fn control_a_shrunk_coverage_page_fails_safety() {
    let report = planted(Plant::ShrunkCoverage, 3);
    let rule = "a covered version was served after its acknowledged INVALIDATE";
    assert_eq!(report.safety.rule(), Some(rule), "{}", report.summary());
    assert_eq!(
        report.oracle[0],
        Some("a recorded restore of a covered version")
    );
    let unjudged = "the oracle's preservation judgment did not run for a group of keys";
    assert_eq!(report.retention, Verdict::Inconclusive(unjudged));
    let uncontained = "the oracle's uncaptured-restore rules did not run for a group of keys";
    assert_eq!(report.containment, Verdict::Inconclusive(uncontained));
    let cut = &report.cycles[1];
    assert!(
        !cut.response,
        "a cut that runs no round credits no Response"
    );
    assert!(cut.phases[1].buckets.offered == cut.phases[1].buckets.interrupted);
}

/// The dropped-fill control: the tenure drops a FILL it acknowledged from RAM before its closing sweep, so retention
/// fails by the own-tenure FILL rule while safety passes.
#[test]
fn control_a_dropped_fill_fails_retention_in_its_own_tenure() {
    let sibling = Config {
        mix: Mix {
            fill: 60,
            invalidate: 0,
        },
        ..Config::discovery(3, 2)
    };
    let unplanted = run(&sibling);
    assert!(unplanted.cycles[0].fills > 0);
    assert!(unplanted.retention.passed(), "{}", unplanted.summary());
    assert!(
        unplanted.guard_held() && unplanted.guarded.checked > 0,
        "the unplanted fills overlap no held extent: {:?}",
        unplanted.guarded
    );
    let mut unchecked = unplanted.clone();
    unchecked.guarded.checked = 0;
    assert!(
        !unchecked.guard_held(),
        "published fills with no checked write fail the guard"
    );
    unchecked.composed.fills = 0;
    assert!(unchecked.guard_held(), "a run with no fill needs no check");
    let config = Config {
        plant: Some((Plant::DroppedFill, 0)),
        ..sibling
    };
    let report = run(&config);
    assert!(report.planted, "the plant dropped a fill");
    assert_eq!(
        report.retention.rule(),
        Some("an acknowledged FILL was not served in its own tenure"),
        "{}",
        report.summary()
    );
    assert!(
        report.safety.passed() && report.containment.passed(),
        "{}",
        report.summary()
    );
}

/// The unreported-damage control: a row unit is flipped with no damage row, so the recovery's loss report counts a
/// unit the harness never injected and containment fails by the loss-report rule.
#[test]
fn control_an_unreported_row_flip_fails_containment_by_the_loss_report() {
    let report = planted(Plant::UnreportedDamage, 2);
    assert_eq!(
        report.containment.rule(),
        Some("the recovery's loss report differs from the injected row units"),
        "{}",
        report.summary()
    );
    assert!(report.cycles[1].failed_units > 0);
}

/// The leak control: one coverage entry no INVALIDATE accounts for is written before every cycle. Under a
/// tolerance of four the ledger fails at the fifth boundary, `floor(4 / 1) + 1`, naming the quantity, and every
/// other verdict passes. A run of four boundaries cannot show that leak and reads inconclusive.
#[test]
fn control_a_leak_fails_at_the_first_boundary_past_its_tolerance() {
    let report = planted(Plant::Leak, 6);
    let rule = "leak: unaccounted coverage entries past the tolerance";
    let failed = Verdict::Fail(rule, "boundary 4".into());
    assert_eq!(report.conservation.exact, failed, "{}", report.summary());
    assert_eq!(crossing_floor(report.config.epsilon, 1), 5);
    let verdicts = [
        &report.safety,
        &report.containment,
        &report.retention,
        &report.progress,
    ];
    assert!(
        verdicts.iter().all(|verdict| verdict.passed()),
        "{}",
        report.summary()
    );
    let short = planted(Plant::Leak, 4);
    let floor = Verdict::Inconclusive("fewer boundaries than the leak crossing floor");
    assert_eq!(short.conservation.exact, floor);
}

/// The stuck-capture control: the tenure's capture pass is started and never finished, so the ledger fails by name
/// at the planted boundary.
#[test]
fn control_a_stuck_capture_fails_the_ledger_by_name() {
    let stuck = planted(Plant::StuckCapture, 6);
    let rule = "stuck-capture: a capture pass is in flight at the boundary";
    let failed = Verdict::Fail(rule, "boundary 1".into());
    assert_eq!(stuck.conservation.exact, failed, "{}", stuck.summary());
}

/// The leaked-unit control: the recovered tenure of cycle 1 leaks a payload unit at its quiescent boundary, so
/// [`conserved`](crate::net::observe::conserved) reads that boundary's sample as violated by the free-run text and
/// the ledger fails by it at that boundary. Its unplanted sibling is
/// [`seeded_cycles_pass_four_verdicts_with_accounted_growth_conserved`], which runs the same seed and reads every
/// boundary sample as `Tables::Conserved`.
#[test]
fn control_a_leaked_unit_fails_the_ledger_by_the_conservation_rule() {
    let leaked = planted(Plant::LeakedUnit, 2);
    let failed = Verdict::Fail(FREE_RUNS, "boundary 1".into());
    assert_eq!(leaked.conservation.exact, failed, "{}", leaked.summary());
    let sample = leaked.cycles[1].sample.expect("a boundary sample");
    assert_eq!(sample.conservation, Tables::Violated(FREE_RUNS));
}

/// The no-publish control: the tenure holds every INVALIDATE it takes and writes no coverage page, so the ledger
/// fails by name at the planted boundary.
#[test]
fn control_an_unpublished_invalidate_fails_the_ledger_by_name() {
    let unpublished = planted(Plant::NoPublish, 2);
    let rule = "no-publish: the boundary holds an INVALIDATE with no acknowledged publication";
    let failed = Verdict::Fail(rule, "boundary 1".into());
    assert_eq!(
        unpublished.conservation.exact,
        failed,
        "{}",
        unpublished.summary()
    );
}

/// Boundary exhaustion: a drain with no ticks reaches no boundary, so the ledger has no sample, the run ends at
/// that cycle with its acknowledged fills left out of the cut, and conservation, progress and retention read
/// inconclusive while containment passes.
#[test]
fn a_drain_that_reaches_no_boundary_is_inconclusive() {
    let config = Config {
        drain_ticks: 0,
        mix: Mix {
            fill: 40,
            invalidate: 6,
        },
        ..Config::discovery(3, 6)
    };
    let report = run(&config);
    let missing = Verdict::Inconclusive("a boundary has no sample");
    assert_eq!(report.conservation.exact, missing, "{}", report.summary());
    let undrained = "a drain did not reach its boundary within its tick bound";
    assert_eq!(report.progress, Verdict::Inconclusive(undrained));
    assert_eq!(
        report.cycles.len(),
        1,
        "the run ends at the missed boundary"
    );
    assert!(report.cycles[0].sample.is_none() && report.cycles[0].fills > 0);
    let short = Verdict::Inconclusive("the run ended before its last cycle");
    assert_eq!(report.retention, short);
    assert!(report.containment.passed(), "{}", report.summary());
    assert!(!report.passed());
}

/// A run that captures no object is refused before its first cycle.
#[test]
#[should_panic(expected = "a run captures at least one object")]
fn a_run_of_no_captured_object_is_refused() {
    let config = Config {
        objects: 0,
        ..Config::discovery(1, 2)
    };
    run(&config);
}

/// A run past `MAX_CYCLES` is refused before its first cycle.
#[test]
#[should_panic(expected = "cycles whose boot nonces and leak keys stay distinct")]
fn a_run_past_the_cycle_bound_is_refused() {
    run(&Config::discovery(1, MAX_CYCLES + 1));
}

/// The plateau is judged only against a declared band: a band that holds the run's resident bytes reads
/// inconclusive, since no publication follows a quiescent boundary, and a band of zero fails once fills and
/// INVALIDATEs move them; neither run passes.
#[test]
fn the_plateau_is_judged_against_a_declared_band() {
    let banded = |band| {
        let config = Config {
            band: Some(band),
            ..Config::discovery(1, 6)
        };
        run(&config)
    };
    let held = banded(1 << 20);
    let unpublished = super::ledger::UNPUBLISHED;
    assert_eq!(
        held.conservation.plateau,
        Verdict::Inconclusive(unpublished)
    );
    assert!(
        !held.passed(),
        "a held band earns no pass with no publication"
    );
    let left = banded(0);
    let rule = "plateau: resident bytes left the accepted band";
    assert_eq!(left.conservation.plateau.rule(), Some(rule));
    assert!(!left.passed());
}

/// The actual-volume-loss control stays apart from host loss. With the loss recorded, the cold start is legal,
/// safety passes and retention is unrun, which is no credit. The same cold start with no recorded loss is a host
/// loss treated as a volume loss and fails retention by the cold-start rule.
#[test]
fn an_actual_volume_loss_provisions_cold_and_credits_no_retention() {
    let (verdicts, served) = volume_loss_control(true);
    let unrun = "an actual volume loss provisions cold and credits no retention";
    assert_eq!(verdicts, [Verdict::Pass, Verdict::Unrun(unrun)]);
    assert_eq!(served, [6, 0]);
    assert!(!verdicts[1].passed());
    let (verdicts, served) = volume_loss_control(false);
    assert_eq!(
        verdicts[1].rule(),
        Some("host loss replaced a retained cut with a cold start")
    );
    assert_eq!(served, [6, 0]);
}

/// With the history rows of the recorded volume-loss control passing, an ownership failure fails safety and a
/// malformed step list reads safety inconclusive, with retention unrun in both.
#[test]
fn the_volume_loss_control_puts_its_ownership_verdict_in_safety() {
    use crate::oracle::ownership::Step;
    let unrun = Verdict::Unrun("an actual volume loss provisions cold and credits no retention");
    let (world, _) = volume_loss_world(true);
    assert_eq!(volume_loss_verdicts(&world), [Verdict::Pass, unrun.clone()]);
    let restart = {
        let mut steps = world.steps.borrow_mut();
        let last = (steps.list.iter_mut()).rev().find_map(|step| match step {
            Step::Fenced { tenure, durable } => Some((tenure, durable)),
            _ => None,
        });
        let (tenure, durable) = last.expect("the restart's fence");
        *durable = Some(super::super::CUT);
        *tenure
    };
    let [safety, retention] = volume_loss_verdicts(&world);
    let recovered =
        "a successor recovered from a cut other than the one its volume last made durable";
    assert_eq!(safety.rule(), Some(recovered));
    assert_eq!(retention, unrun);
    (world.steps.borrow_mut().list).push(Step::Fenced {
        tenure: restart,
        durable: None,
    });
    let inconclusive = Verdict::Inconclusive("the ownership judgment was inconclusive");
    assert_eq!(volume_loss_verdicts(&world), [inconclusive, unrun]);
}

/// Each fence considers only volume losses recorded since the previous fence when it sets `Fenced.durable`.
#[test]
fn a_recorded_volume_loss_clears_the_durable_cut_of_the_next_fence_only() {
    let mut world = World::new(6, false);
    let (taken, _) = world.takeover(c_host());
    assert!(taken.is_ok(), "C's takeover");
    world.events.push(Event::VolumeLost);
    restart_of(&world, c_host()).expect("the first restart after the loss");
    restart_of(&world, c_host()).expect("the second restart");
    use crate::oracle::ownership::Step;
    let cut = Some(super::super::CUT);
    let steps = world.steps.borrow();
    let durable: Vec<_> = (steps.list.iter())
        .filter_map(|step| match step {
            Step::Fenced { durable, .. } => Some(*durable),
            _ => None,
        })
        .collect();
    assert_eq!(durable, [cut, None, cut]);
}

/// The tape draws integers alone, in a sequence its seed fixes. Arrivals at one tick are all runnable at that
/// tick, `next_due` names the next tick strictly after now, and an exhausted phase names none.
#[test]
fn same_tick_arrivals_are_all_runnable_and_the_next_due_tick_is_strictly_later() {
    let mix = Mix {
        fill: 10,
        invalidate: 6,
    };
    let ticks = |seed| {
        let mut phase = Tape::new(seed).phase(64, 1, mix);
        phase.runnable(u64::MAX)
    };
    assert_eq!(ticks(7), ticks(7));
    assert_ne!(ticks(7), ticks(8));
    let arrivals = ticks(7);
    let shared = arrivals
        .windows(2)
        .find(|pair| pair[0].tick == pair[1].tick);
    let tick = shared.expect("two arrivals share a tick")[0].tick;
    let at_tick = arrivals
        .iter()
        .filter(|arrival| arrival.tick == tick)
        .count();
    let mut phase = Tape::new(7).phase(64, 1, mix);
    let before = phase.runnable(tick.saturating_sub(1)).len();
    let due: Vec<Arrival> = phase.runnable(tick);
    assert_eq!(due.len(), at_tick);
    assert!(due.len() >= 2 && due.iter().all(|arrival| arrival.tick == tick));
    assert_eq!(
        before + due.len(),
        arrivals.iter().filter(|a| a.tick <= tick).count()
    );
    assert!(
        phase.runnable(tick).is_empty(),
        "an arrival is offered once"
    );
    let next = phase.next_due();
    assert!(next.is_none_or(|next| next > tick));
    assert_eq!(next, arrivals.iter().map(|a| a.tick).find(|t| *t > tick));
    phase.runnable(u64::MAX);
    assert!(phase.exhausted() && phase.next_due().is_none());
    let kinds = |kind: fn(&Kind) -> bool| arrivals.iter().filter(|a| kind(&a.kind)).count();
    assert!(kinds(|kind| matches!(kind, Kind::Get(_))) > kinds(|kind| *kind == Kind::Fill));
}

/// A sample at a quiescent boundary whose every quantity is accounted.
fn quiet(cycle: u32) -> Sample {
    Sample {
        cycle,
        resident_slots: 44,
        resident_bytes: 1936,
        page_bytes: 19,
        page_cap: 4096,
        suffixes: 1,
        attachments: 2,
        accounted: Accounted {
            resident_slots: 44,
            coverage_entries: 0,
            suffixes: 1,
        },
        ..Sample::default()
    }
}

const LIMITS: Limits = Limits {
    epsilon: 4,
    slope: 1,
    chain_cap: 4,
    attach_cap: 3,
    band: None,
};

/// The ledger fails by the breaking rule's name at its boundary when an exact quantity is off by one, an accounted
/// quantity is off its account, a quantity exceeds its cap, or a sample's tables are violated. Within one sample a
/// quantity outranks the tables. A failure outranks an unreadable snapshot, which reads inconclusive by its reason
/// and outranks a missing sample; a missing sample outranks the crossing floor. Five quiet boundaries pass, and the
/// publish-aligned judgment repeats a failure and otherwise reads inconclusive.
#[test]
fn the_ledger_fails_each_quantity_by_name_and_reads_missing_evidence_inconclusive() {
    let run_of = |samples: &[Option<Sample>]| judge(samples, &LIMITS).exact;
    let five: Vec<Option<Sample>> = (0..5).map(|cycle| Some(quiet(cycle))).collect();
    assert_eq!(run_of(&five), Verdict::Pass);
    type Edit = (fn(&mut Sample), &'static str);
    let edits: [Edit; 15] = [
        (|s| s.held_invalidations = 1, "no-publish"),
        (|s| s.capture = true, "stuck-capture"),
        (|s| s.filling = 1, "exact: filling slots"),
        (|s| s.reserved_bytes = 1, "exact: reserved bytes"),
        (|s| s.pending_marks = 1, "exact: pending ledger marks"),
        (|s| s.escrow_units = 1, "exact: escrowed units"),
        (|s| s.quarantined_slots = 1, "exact: quarantined slots"),
        (|s| s.resident_slots = 45, "accounted: resident slots"),
        (|s| s.suffixes = 2, "accounted: the suffix chain"),
        (
            |s| s.accounted.coverage_entries = 1,
            "accounted: the store holds fewer",
        ),
        (
            |s| s.coverage_entries = 5,
            "leak: unaccounted coverage entries",
        ),
        (|s| s.attachments = 4, "cap: the volume's live attachments"),
        (|s| s.conservation = Tables::Violated(FREE_RUNS), FREE_RUNS),
        (
            |s| {
                s.attachments = 4;
                s.conservation = Tables::Violated(FREE_RUNS);
            },
            "cap: the volume's live attachments",
        ),
        (
            |s| {
                s.filling = 1;
                s.conservation = Tables::Unreadable("the storage is inside a warm load");
            },
            "exact: filling slots",
        ),
    ];
    for (edit, name) in edits {
        let mut samples = five.clone();
        edit(samples[3].as_mut().expect("a sample"));
        samples[1] = None;
        let judged = judge(&samples, &LIMITS);
        let Verdict::Fail(rule, at) = judged.exact.clone() else {
            panic!("{name}: the edited sample passed");
        };
        assert!(rule.starts_with(name), "{name}: {rule}");
        assert_eq!(at, "boundary 3", "{name}");
        assert_eq!(judged.aligned, judged.exact, "{name}");
    }
    let aligned = "no checkpoint or frontier publication follows a quiescent boundary";
    assert_eq!(
        judge(&five, &LIMITS).aligned,
        Verdict::Inconclusive(aligned)
    );
    let mut held = five.clone();
    held[2].as_mut().expect("a sample").retired_slots = 3;
    assert_eq!(run_of(&held), Verdict::Pass, "retired slots stay held");
    let mut tolerated = five.clone();
    tolerated[4].as_mut().expect("a sample").coverage_entries = 4;
    assert_eq!(
        run_of(&tolerated),
        Verdict::Pass,
        "four unaccounted entries are tolerated"
    );
    let mut capped = five.clone();
    let sample = capped[2].as_mut().expect("a sample");
    (sample.suffixes, sample.accounted.suffixes) = (5, 5);
    assert_eq!(
        run_of(&capped).rule(),
        Some("cap: the suffix chain is past its cap")
    );
    let mut paged = five.clone();
    paged[2].as_mut().expect("a sample").page_bytes = 4097;
    assert_eq!(
        run_of(&paged).rule(),
        Some("cap: a coverage page is past its byte cap")
    );
    let mut missing = five.clone();
    missing[4] = None;
    let no_sample = Verdict::Inconclusive("a boundary has no sample");
    assert_eq!(run_of(&missing), no_sample);
    let reason = "the storage is inside a warm load";
    let mut sampled = five.clone();
    sampled[2].as_mut().expect("a sample").conservation = Tables::Unreadable(reason);
    assert_eq!(
        run_of(&sampled),
        Verdict::Inconclusive(reason),
        "an unreadable snapshot keeps five sampled boundaries from passing"
    );
    let mut unread = missing.clone();
    unread[2].as_mut().expect("a sample").conservation = Tables::Unreadable(reason);
    let judged = judge(&unread, &LIMITS);
    assert_eq!(judged.exact, Verdict::Inconclusive(reason));
    assert_eq!(judged.aligned, Verdict::Inconclusive(UNPUBLISHED));
    unread[3].as_mut().expect("a sample").filling = 1;
    assert_eq!(
        run_of(&unread).rule(),
        Some("exact: filling slots at the boundary"),
        "a later boundary's failure outranks an unreadable snapshot"
    );
    let floor = Verdict::Inconclusive("fewer boundaries than the leak crossing floor");
    assert_eq!(run_of(&five[..4]), floor);
    assert_eq!(run_of(&missing[..4]), floor, "four boundaries, all sampled");
    assert_eq!(
        run_of(&missing[2..]),
        no_sample,
        "three boundaries, one with no sample"
    );
    assert_eq!(
        (
            crossing_floor(4, 1),
            crossing_floor(4, 2),
            crossing_floor(0, 1),
            crossing_floor(u64::MAX, 1)
        ),
        (5, 3, 1, u64::MAX)
    );
    let unbounded = Limits {
        epsilon: u64::MAX,
        ..LIMITS
    };
    assert_eq!(judge(&five, &unbounded).exact, floor);
}

/// The census lists every site under every class. The undecided sites read `undecided` under every class, a
/// required site no run reached reads `gap`, a reached one `covered` and every other `not-required`; a descriptor
/// that marks an undecided site required is refused.
#[test]
fn the_census_lists_every_site_and_refuses_a_required_undecided_site() {
    use crate::sim::cut::{Class, Site};
    let mut report = run(&Config::discovery(1, 6));
    report.reached = BTreeSet::from([
        (Class::ProcessDeath, Site::Response),
        (Class::HostOrDevice, Site::RecoveryMutation),
    ]);
    let rows = census(&REQUIRED, &[&report]).expect("a census");
    assert_eq!(rows.len(), Class::ALL.len() * Site::ALL.len());
    let status = |class: Class, site: Site| {
        let row = rows.iter().find(|row| (row.0, row.1) == (class, site));
        row.expect("a row for every class and site").2
    };
    for class in Class::ALL {
        assert_eq!(status(class, Site::Exclusion), Status::Undecided);
        assert_eq!(status(class, Site::Successor), Status::Undecided);
        assert_eq!(status(class, Site::Submission), Status::NotRequired);
    }
    assert_eq!(status(Class::ProcessDeath, Site::Response), Status::Covered);
    assert_eq!(
        status(Class::HostOrDevice, Site::RecoveryMutation),
        Status::Covered
    );
    assert_eq!(status(Class::HostOrDevice, Site::Response), Status::Gap);
    assert_eq!(status(Class::ProcessDeath, Site::Persistence), Status::Gap);
    assert_eq!(
        status(Class::ReplacementAttach, Site::Response),
        Status::Gap
    );
    assert_eq!(
        status(Class::ControllerReset, Site::Response),
        Status::NotRequired
    );
    let mut descriptor = REQUIRED;
    descriptor[0].1 = &[Site::Response, Site::Successor];
    let refused = census(&descriptor, &[&report]);
    assert_eq!(refused, Err(Refused::UndecidedRequired(Site::Successor)));
}

/// A cut reaches `Response` under the class of the recovery after it only when its owner held a GET at the drop,
/// a second crash inside a recovery reaches `RecoveryMutation` under that recovery's class, and the last cut reaches
/// nothing.
#[test]
fn a_cut_reaches_response_only_when_its_owner_held_a_get() {
    use crate::sim::cut::{Class, Site};
    let cycle = |recovery, class, response| Cycle {
        recovery,
        class,
        tenure: Tenure { g: 3, a: 10 },
        cut: (0, 0, 0),
        eligible: 0,
        served: 0,
        failed_units: 0,
        suffix: true,
        fills: 1,
        invalidations: 1,
        phases: [PhaseReport::default(); 3],
        sample: None,
        response,
    };
    let cycles = [
        cycle(Recovery::Restart, Class::ProcessDeath, true),
        cycle(Recovery::Takeover, Class::HostOrDevice, false),
        cycle(Recovery::Interrupted, Class::ReplacementAttach, true),
        cycle(Recovery::Restart, Class::ProcessDeath, true),
    ];
    assert!(reach(&cycles[..1]).is_empty(), "a lone cut reaches nothing");
    let reached = reach(&cycles);
    let expected = BTreeSet::from([
        (Class::HostOrDevice, Site::Response),
        (Class::ReplacementAttach, Site::RecoveryMutation),
        (Class::ProcessDeath, Site::Response),
    ]);
    assert_eq!(reached, expected);
}

/// The fresh host's first attach is its own class whichever cycle enrolled it: a designated recovery enrolls D as
/// standby and is recovered by A, and the next designated recovery's takeover by D is classed `ReplacementAttach`.
#[test]
fn a_fresh_hosts_first_attach_is_classed_after_an_enrollment_with_no_attach() {
    let config = Config::discovery(1, 3);
    let mut world = World::new(config.objects, false);
    let mut run = Run::new(&config, &world);
    let mut recover = |recovery| {
        let (taken, class) = run.recover(&mut world, recovery).unwrap();
        drop(taken);
        (record_now(&world).owner, class)
    };
    assert_eq!(recover(Recovery::Takeover), (c_host(), Class::HostOrDevice));
    assert_eq!(
        recover(Recovery::Designated),
        (a_host(), Class::HostOrDevice)
    );
    assert_eq!(
        recover(Recovery::Designated),
        (d_host(), Class::ReplacementAttach)
    );
    assert_eq!(run.composed.fresh_hosts, 1);
}

/// The discovery report the long-run case prints, at two seeds of six cycles: each run's lines, its summary naming
/// every verdict, its configuration and one line a cycle, then the digest of those lines; the census over both
/// runs; the compositions summed over both runs; the unscored cases; and the closing line that labels the runs
/// unpowered discovery.
#[test]
fn discovery_prints_each_runs_verdicts_the_census_and_the_compositions() {
    let lines = discovery(1..=2, 6).expect("both runs pass");
    let per_run = 4 + 6 + 1;
    assert_eq!(lines.len(), 2 * per_run + 4, "{lines:#?}");
    for (run_lines, seed) in lines.chunks(per_run).zip([1, 2]) {
        let report = run(&Config::discovery(seed, 6));
        assert_eq!(run_lines[..per_run - 1], report.lines()[..]);
        let summary = format!(
            "cycles: seed {seed} cycles 6: safety pass; containment pass; retention pass; progress pass; \
             quiescent conservation pass; publish-aligned conservation inconclusive [no checkpoint or frontier \
             publication follows a quiescent boundary]; plateau inconclusive [no accepted plateau band]; identity {}",
            report.identity
        );
        assert_eq!(run_lines[0], summary);
        let configuration = format!("cycles: {} configuration ", report.identity);
        assert!(run_lines[1].starts_with(&configuration));
        for (at, line) in run_lines[4..10].iter().enumerate() {
            assert!(line.starts_with(&format!("cycles: {} cycle {at} ", report.identity)));
        }
        let digest = format!("cycles: {} digest {}", report.identity, report.digest());
        assert_eq!(run_lines[per_run - 1], digest);
    }
    let tail = &lines[2 * per_run..];
    let undecided = crate::sim::ledger::UNDECIDED.len() * crate::sim::cut::Class::ALL.len();
    assert!(
        tail[0].starts_with("cycles: census: covered ")
            && tail[0].contains(" gap ")
            && tail[0].contains("; gaps ["),
        "{}",
        tail[0]
    );
    assert!(
        tail[0].contains(&format!(" undecided {undecided} ")),
        "{}",
        tail[0]
    );
    let labels: Vec<&str> = (tail[1].split(' ').skip(2).step_by(2)).collect();
    let expected = [
        "restarts",
        "takeovers",
        "designated",
        "interrupted",
        "unknown",
        "after-preempt",
        "stale",
        "fresh-hosts",
        "unauthorized",
        "damaged",
        "repaired",
        "landings",
        "chain-full",
        "fills",
        "invalidations",
        "captures",
    ];
    assert!(tail[1].starts_with("cycles: composed: "), "{}", tail[1]);
    assert_eq!(labels, expected, "{}", tail[1]);
    assert!(
        tail[1].ends_with(" captures 12"),
        "every cycle runs one capture pass: {}",
        tail[1]
    );
    let unscored = "cycles: unscored: successor checkpoint publication and consolidation; duplicate extents; \
                    both roots affected; log-full and quarantine-full; missing REMOVE and REPLACE dependencies, \
                    covered by the directed suffix histories; a delayed old-tenure write after its successor's \
                    fence; a second fresh host; a GET racing a mutation, excluded by the drain before each mutation; \
                    every row unit of the checkpoint damaged, which the warm load refuses as a whole slot; an \
                    INVALIDATE or a flip of a FILL the cycles published";
    assert_eq!(tail[2], unscored);
    let closing = "cycles: discovery: 2 seeds of 6 cycles, unpowered; every run passed its four verdicts and its \
                   quiescent conservation, and no run is a confirmation";
    assert_eq!(tail[3], closing);
}

/// A phase's dropped count is the offered requests no bucket holds: an unsettled request is dropped and fails
/// settlement, and a request settled twice fails settlement with none dropped.
#[test]
fn a_request_in_no_bucket_is_dropped_and_one_in_two_is_unsettled() {
    let missing = Buckets {
        offered: 3,
        retained: 2,
        ..Buckets::default()
    };
    assert_eq!(missing.dropped(), 1);
    assert!(!missing.settled());
    let twice = Buckets {
        offered: 1,
        retained: 1,
        refused: 1,
        ..Buckets::default()
    };
    assert_eq!(twice.dropped(), 0);
    assert!(!twice.settled());
    let once = Buckets {
        offered: 2,
        miss: 1,
        interrupted: 1,
        ..Buckets::default()
    };
    assert!(once.settled() && once.dropped() == 0);
}

/// The two pinned roots of the slot-reuse cycles, 18 cycles each: every cycle replaces a host, restarts and takeovers
/// both run, each run passes the four verdicts and the quiescent conservation judgment with its write guard, at most
/// three live attaches and no returning host, at least one ended-key preempt runs, and the totals line is fixed.
#[test]
fn slot_reuse_cycles_replace_a_host_every_cycle_and_pass_the_four_verdicts() {
    let mut reports = Vec::new();
    for seed in SLOT_SEEDS {
        let report = run(&Config::slot_reuse(seed, SLOT_CYCLES));
        assert_eq!(admitted(&report), Ok(()));
        let composed = report.composed;
        assert_eq!(composed.replacements, SLOT_CYCLES, "{composed:?}");
        assert!(
            composed.drops == SLOT_CYCLES && composed.live == 3,
            "{composed:?}"
        );
        let [restarts, takeovers, ..] = composed.recoveries;
        assert!(
            restarts > 0 && takeovers > 0 && composed.fresh_hosts > 0,
            "{composed:?}"
        );
        assert_eq!(report.cycles.len(), SLOT_CYCLES as usize);
        for (at, cycle) in report.cycles.iter().enumerate() {
            assert!(
                cycle.eligible > 0 && cycle.served == cycle.eligible,
                "seed {} cycle {at}: {} of {} retained entries served",
                report.config.seed,
                cycle.served,
                cycle.eligible
            );
        }
        reports.push(report);
    }
    assert!(reports.iter().any(|report| report.composed.preempts > 0));
    let lines = slot_reuse_lines(&reports).unwrap();
    assert_eq!(lines.last().map(String::as_str), Some(SLOT_TOTALS));
    assert!(
        reports
            .iter()
            .all(|report| lines.contains(&report.summary()))
    );
}

fn slot_planted(plant: Plant, cycles: u32) -> Report {
    let report = slot_planted_at(plant, (SLOT_SEEDS[0], 1), cycles);
    assert!(
        report.safety.passed() && report.retention.passed(),
        "{}",
        report.summary()
    );
    report
}

fn slot_planted_at(plant: Plant, (seed, at): (u64, u32), cycles: u32) -> Report {
    let config = Config {
        plant: Some((plant, at)),
        ..Config::slot_reuse(seed, cycles)
    };
    let report = run(&config);
    assert!(report.planted, "{plant:?}: the plant changed its target");
    report
}

#[test]
fn control_a_detach_before_the_pair_drop_is_refused_and_fails_progress() {
    let report = slot_planted(Plant::KeptPair, 3);
    let Verdict::Fail(rule, at) = &report.progress else {
        panic!("{}", report.summary());
    };
    assert_eq!(
        (*rule, at.as_str()),
        (
            "the replaced host was not detached and released",
            "cycle 1: detachable: Conflict"
        )
    );
    assert!(report.containment.passed(), "{}", report.summary());
    assert_eq!(report.composed.replacements, 2);
}

/// The early-release control: the entry is recorded gone while its instance is attached, which fails containment;
/// the next cycle's owner poll sees the gone entry's instance listed and retires on a foreign attachment.
#[test]
fn control_a_release_before_its_detach_fails_containment_and_the_next_poll_retires() {
    let report = slot_planted(Plant::EarlyRelease, 3);
    let rule = "an entry was recorded gone while its instance is attached";
    assert_eq!(
        report.containment.rule(),
        Some(rule),
        "{}",
        report.summary()
    );
    let Verdict::Fail(rule, at) = &report.progress else {
        panic!("{}", report.summary());
    };
    assert_eq!(*rule, "a reclaim poll did not continue");
    assert!(
        at.starts_with("cycle 2: Retire") && at.contains("Foreign"),
        "{at}"
    );
    assert_eq!(report.composed.replacements, 1, "{:?}", report.composed);
}

/// The fourth-attach control: a fourth live entry fails containment, and the next cycle's `record_standby` refuses.
#[test]
fn control_a_fourth_live_attach_fails_containment_and_the_next_attach_is_refused() {
    let report = slot_planted(Plant::FourthAttach, 3);
    let rule = "a record holds more than three live attaches";
    assert_eq!(
        report.containment.rule(),
        Some(rule),
        "{}",
        report.summary()
    );
    assert_eq!(report.composed.live, 4);
    assert_eq!(
        report.progress.rule(),
        Some("a generated host's attach was not recorded")
    );
}

#[test]
fn control_a_drop_while_the_report_lists_its_key_fails_containment() {
    let report = slot_planted(Plant::ListedDrop, 3);
    let rule = "a pair dropped while its poll's Report lists its key";
    assert_eq!(
        report.containment.rule(),
        Some(rule),
        "{}",
        report.summary()
    );
    assert!(report.progress.passed(), "{}", report.summary());
    assert_eq!(slot_planted(Plant::ListedDrop, 3), report);
}

/// The returned-host control: the cycle attaches the host the previous cycle replaced, which fails containment.
#[test]
fn control_a_returning_host_fails_containment() {
    let report = slot_planted_at(Plant::ReturnedHost, (SLOT_SEEDS[0], 2), 4);
    let rule = "a replaced host returned";
    assert_eq!(
        report.containment.rule(),
        Some(rule),
        "{}",
        report.summary()
    );
    assert!(
        report.safety.passed() && report.retention.passed() && report.progress.passed(),
        "{}",
        report.summary()
    );
    let recoveries: Vec<Recovery> = report.cycles.iter().map(|cycle| cycle.recovery).collect();
    assert_eq!(
        recoveries[2..],
        [Recovery::Restart, Recovery::Takeover],
        "the returned host takes over under its new enrollment"
    );
}

/// The slot-reuse discovery prints each run's lines and digest and then the totals line, and its lines refuse a run
/// that is no slot-reuse run or that has another cycle count.
#[test]
fn slot_reuse_discovery_prints_each_run_then_the_totals_and_refuses_a_warm_run() {
    let lines = slot_reuse_discovery(2..=2, 6).unwrap();
    let report = run(&Config::slot_reuse(2, 6));
    assert!(lines.contains(&report.summary()));
    let digest = format!("cycles: {} digest {}", report.identity, report.digest());
    assert_eq!(lines[lines.len() - 2], digest);
    assert_eq!(
        lines[lines.len() - 1],
        "cycles: slot-reuse: 1 seeds of 6 cycles; replacements 6 drops 6 preempts 1 live-max 3; every run passed \
         its four verdicts and its quiescent conservation, and no replaced host returned",
    );
    assert_eq!(report.composed.live, MAX_ATTACHED as u32);
    assert!(slot_reuse_lines([&report]).is_ok());
    let edited = |edit: &dyn Fn(&mut Report)| {
        let mut other = report.clone();
        edit(&mut other);
        if other.identity == report.identity {
            other.identity = other.config.identity();
        }
        other
    };
    let refusal = |reports: &[&Report]| {
        let refused = slot_reuse_lines(reports.iter().copied()).unwrap_err();
        let check = refused.split(": ").nth(1).map(str::to_owned);
        check.unwrap_or(refused)
    };
    type Edit<'e> = &'e dyn Fn(&mut Report);
    let alone: [(&str, Edit<'_>); 9] = [
        ("configuration", &|other| other.config.reuse = false),
        ("configuration", &|other| other.config.gap += 1),
        ("configuration", &|other| {
            other.config.plant = Some((Plant::NoEffectPreempt, 1));
        }),
        ("plant", &|other| other.planted = true),
        ("replacements", &|other| other.composed.replacements -= 1),
        ("replacements", &|other| other.composed.replacements += 1),
        ("drops", &|other| other.composed.drops -= 1),
        ("drops", &|other| other.composed.drops += 1),
        ("live attaches", &|other| {
            other.composed.live = MAX_ATTACHED as u32 + 1;
        }),
    ];
    for (check, edit) in alone {
        let refused = edited(edit);
        assert_eq!(admitted(&refused), Ok(()));
        assert_eq!(refusal(&[&refused]), check, "{:?}", refused.config);
    }
    let renamed = edited(&|other| other.identity = "0000000000000000".to_owned());
    assert_eq!(admitted(&renamed), Ok(()));
    assert_eq!(refusal(&[&renamed]), "identity");
    let longer = edited(&|other| {
        other.config.cycles = 7;
        other.config.seed = 3;
        other.composed.replacements = 7;
        other.composed.drops = 7;
    });
    assert!(slot_reuse_lines([&longer]).is_ok());
    assert_eq!(refusal(&[&report, &longer]), "cycle count");
    assert_eq!(refusal(&[&report, &report]), "repeated seed or identity");
    let other_seed = edited(&|other| other.config.seed = 3);
    assert!(slot_reuse_lines([&report, &other_seed]).is_ok());
    assert_eq!(
        slot_reuse_lines(Vec::<Report>::new()),
        Err("no slot-reuse run".to_owned())
    );
}

#[test]
fn a_preempt_with_no_effect_is_issued_again_and_the_pair_drops_after_its_key_leaves() {
    let report = slot_planted(Plant::NoEffectPreempt, 3);
    assert!(
        report.containment.passed() && report.progress.passed(),
        "{}",
        report.summary()
    );
    assert_eq!(report.composed.replacements, 3);
    let unplanted = run(&Config::slot_reuse(SLOT_SEEDS[0], 3));
    assert_eq!(
        report.composed.preempts,
        unplanted.composed.preempts + 2,
        "{:?}",
        report.composed
    );
    assert_eq!(report.composed.drops, unplanted.composed.drops);
}

#[test]
fn control_a_refused_recovery_fails_progress_and_ends_the_run() {
    for (seed, at, step) in [
        (2, 2, "the owner's restart: "),
        (2, 1, "the standby's takeover: "),
    ] {
        let report = slot_planted_at(Plant::RefusedRecovery, (seed, at), 4);
        let Verdict::Fail(rule, refused) = &report.progress else {
            panic!("{}", report.summary());
        };
        assert_eq!(*rule, "a slot-reuse recovery was refused");
        let by = refused
            .strip_prefix(&format!("cycle {at}: "))
            .and_then(|refused| refused.strip_prefix(step));
        assert!(by.is_some_and(|by| by.contains("Unavailable")), "{refused}");
        assert!(
            report.safety.passed() && report.containment.passed(),
            "{}",
            report.summary()
        );
        assert_eq!(report.cycles.len(), at as usize);
        assert_eq!(report.composed.replacements, at);
    }
}

#[test]
fn control_a_refused_designation_fails_progress_and_ends_the_replacement() {
    let report = slot_planted(Plant::RefusedDesignation, 3);
    let Verdict::Fail(rule, at) = &report.progress else {
        panic!("{}", report.summary());
    };
    assert_eq!(
        (*rule, at.as_str()),
        (
            "a generated standby was not designated",
            "cycle 1: reserve: Store(Unavailable)"
        )
    );
    assert!(report.containment.passed(), "{}", report.summary());
    assert_eq!(report.composed.replacements, 1);
    assert_eq!(report.composed.live, MAX_ATTACHED as u32);
}

#[test]
fn control_an_ended_role_host_fails_containment() {
    let report = slot_planted(Plant::EndedRole, 3);
    assert_eq!(
        report.containment,
        Verdict::Fail(
            "a host the shard record names was ended",
            "cycle 1".to_owned()
        ),
        "{}",
        report.summary()
    );
    assert_eq!(report.composed.replacements, 2, "{:?}", report.composed);
}

#[test]
fn control_an_attach_of_a_host_whose_entry_is_ended_fails_containment() {
    let report = slot_planted(Plant::EarlyReturn, 3);
    assert_eq!(
        report.containment,
        Verdict::Fail(
            "a host attached again before its ended entry was gone",
            "cycle 1".to_owned()
        ),
        "{}",
        report.summary()
    );
    assert_eq!(report.composed.replacements, 1, "{:?}", report.composed);
}

#[test]
fn control_an_entry_gone_before_its_listings_settled_fails_containment() {
    let report = slot_planted(Plant::UnsettledRelease, 3);
    assert_eq!(
        report.containment,
        Verdict::Fail(
            "an entry was recorded gone on listings that are not settled",
            "cycle 1".to_owned()
        ),
        "{}",
        report.summary()
    );
    assert!(report.progress.passed(), "{}", report.summary());
    assert_eq!(report.composed.replacements, 2, "{:?}", report.composed);
}

#[test]
fn a_refused_slot_reuse_recovery_is_an_error_that_names_its_step() {
    let config = Config::slot_reuse(SLOT_SEEDS[0], 1);
    let mut world = World::new(config.objects, false);
    let mut run = Run::new(&config, &world);
    world.records.schedule(Arm::Pass);
    world.records.schedule(Arm::Unavailable);
    let refused = run.recover(&mut world, Recovery::Restart).map(drop);
    assert!(
        refused
            .as_ref()
            .is_err_and(|refusal| refusal.starts_with("the owner's restart: ")),
        "{refused:?}"
    );
}
