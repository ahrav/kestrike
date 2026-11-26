//! Recovery-profile runs of the recovery world: every planned process-death
//! cut advances each stage once in order, the Crash turn's effect choice
//! precedes its effect, the cold relaunch answers Missing and fires the
//! Restart obligation, the campaign credits, and an omitted, skipped or
//! out-of-order ledger, or a truncated run, earns no credit.
//!
//! Window coverage comes from the recorded ledger. The write check uses the living run's
//! capture and keeps its evidence in memory.

use crate::sim::choice::Domain;
use crate::sim::ledger::{
    Activation, Campaign, Checked, Evidence, Gap, LEDGER, LIMITS, Ledger, LedgerError, Stage,
    campaign, counts, rebuild,
};
use crate::sim::manifest::Manifest;
use crate::sim::recovery::{Mismatch, Recovery};
use crate::sim::trace::{Field, Infrastructure, Loaded, Outcome, RECORD, Terminal, bit, load};
use crate::sim::window;

use crate::oracle::Obligation;

use crate::sim::turn::End;

use super::super::super::observe::{FREE_RUNS, Failure};
use super::super::Events;
use super::super::bundle::{Violated, admit, judge_recovery, run_into, traced};
use super::super::replay::{Replayed, replay};

/// A recovery manifest of `profile` whose restart bound is `restarts`.
fn manifest(profile: &str, restarts: u64) -> Manifest {
    let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), "x86_64-linux");
    Manifest::parse(&text).unwrap().with("restarts", restarts)
}

fn bounds(manifest: &Manifest) -> super::Bounds {
    let bound = |key| manifest.count(key) as usize;
    super::Bounds {
        lifecycle: super::super::super::restart::Manifest {
            slots: bound("slots"),
            restarts: bound("restarts"),
            bundles: bound("bundles"),
        },
        link: super::super::super::link::LinkLimits {
            copy_bytes: bound("link_copy_bytes"),
            tx_slots: bound("tx_slots"),
        },
        turns: crate::sim::turn::Limits {
            total: manifest.count("turns"),
            same_time: manifest.count("same_time"),
            no_progress: manifest.count("no_progress"),
        },
    }
}

/// The manifest profile name that selects `recovery`.
fn name(recovery: Recovery) -> &'static str {
    match recovery {
        Recovery::Kib16 => "recovery-16k",
        Recovery::Sector => "recovery-512",
        Recovery::Torn => "recovery-torn",
    }
}

fn recorded(profile: &str, restarts: u64) -> (Vec<u8>, Loaded) {
    recorded_under(&manifest(profile, restarts))
}

fn recorded_under(manifest: &Manifest) -> (Vec<u8>, Loaded) {
    let bytes = traced(admit(manifest).unwrap(), Vec::new()).sink;
    let loaded = load(&bytes, u64::MAX).unwrap();
    (bytes, loaded)
}

/// Every cut of the profile's table, with the restart bound past it,
/// advances planned, reached, activated, recovered and checked Pass once
/// each; the terminal is a complete pass with Restart fired, the campaign
/// credits, and the bundle replays to its digest, count and terminal.
#[test]
fn every_planned_cut_is_reached_activated_recovered_and_checked() {
    for recovery in [Recovery::Kib16, Recovery::Sector, Recovery::Torn] {
        let profile = name(recovery);
        let table = recovery.table();
        let (bytes, loaded) = recorded(profile, table.len() as u64);
        let ledger = rebuild(&loaded.events, table.len() as u32).unwrap();
        assert_eq!(ledger.cuts.len(), table.len(), "{profile}");
        for (at, cut) in table.iter().enumerate() {
            let progress = &ledger.cuts[&(at as u32)];
            assert_eq!(
                progress.stages,
                [
                    Stage::Planned,
                    Stage::Reached,
                    Stage::Activated,
                    Stage::Recovered,
                    Stage::Checked
                ],
                "{profile} cut {at}"
            );
            assert_eq!(progress.checked, Some(Checked::Pass));
            let activation = progress.activation.as_ref().unwrap();
            assert_eq!(
                (activation, activation.evidence),
                (
                    &Activation {
                        landing: cut.mask.clone(),
                        class: cut.class,
                        drained: true,
                        ..activation.clone()
                    },
                    Evidence::Attributed
                ),
                "{profile} cut {at}: the measured landing is the planned one"
            );
        }
        let restart = bit(Obligation::Restart);
        assert_eq!(
            loaded.terminal,
            Terminal::Complete {
                outcome: Outcome::Pass,
                fired: restart,
                required: restart
            }
        );
        assert_eq!(campaign(&loaded), Some(Campaign::Credited), "{profile}");
        assert_eq!(replay(&bytes).unwrap().0, Replayed::Reproduced, "{profile}");
    }
}

/// The index, among `bytes`' records, of each persistence-domain decision's
/// identity record, and of each `LEDGER` event of `stage`.
fn positions(bytes: &[u8], stage: Stage) -> (Vec<usize>, Vec<usize>) {
    const CHOICE: u8 = 3;
    const EVENT: u8 = 6;
    const IDENTITY: u8 = 1;
    let records = bytes.as_chunks::<RECORD>().0;
    let crashes = (0..records.len())
        .filter(|&at| {
            let record = &records[at];
            record[0] == CHOICE
                && record[4] == IDENTITY
                && record[4 + 1 + 2] == Domain::Persistence as u8
        })
        .collect();
    let staged = (0..records.len())
        .filter(|&at| {
            records[at][0] == EVENT && records[at][1] == LEDGER && records[at][4] == stage as u8
        })
        .collect();
    (crashes, staged)
}

/// Each cut's Reached entry precedes its Crash turn's effect choice, a
/// persistence-domain decision on the tape, which precedes its Activated
/// entry; an after-boundary cut dies with its fill's writes still queued,
/// so no completion reached the owner before the death.
#[test]
fn the_effect_choice_falls_between_reach_and_activation() {
    let table = Recovery::Kib16.table();
    let (bytes, loaded) = recorded("recovery-16k", table.len() as u64);
    let (crashes, reached) = positions(&bytes, Stage::Reached);
    let (_, activated) = positions(&bytes, Stage::Activated);
    assert_eq!(crashes.len(), table.len());
    for at in 0..table.len() {
        assert!(
            reached[at] < crashes[at] && crashes[at] < activated[at],
            "cut {at}"
        );
    }
    let ledger = rebuild(&loaded.events, table.len() as u32).unwrap();
    for (at, cut) in table.iter().enumerate() {
        let progress = &ledger.cuts[&(at as u32)];
        let queue = progress.activation.as_ref().unwrap().queue;
        assert_eq!(
            progress.reached,
            Some(queue),
            "cut {at}: no command completed between reach and act"
        );
        if !cut.mask.is_empty() {
            assert!(queue > 0, "cut {at} died with its writes queued");
        }
    }
    const HOLD: u8 = 5;
    assert!(
        loaded.turns.iter().any(|turn| turn[1] == HOLD),
        "the run held a reached target at least once"
    );
}

/// A replay whose tape ends at a Crash turn's effect choice, the Crash
/// turn itself selected, ends as a defect with that cut reached and never
/// activated and the owner still alive: the owner dies only after the
/// choice is on the tape.
#[test]
fn a_crash_without_its_effect_choice_never_kills_the_owner() {
    let table = Recovery::Kib16.table();
    let (bytes, loaded) = recorded("recovery-16k", table.len() as u64);
    let (crashes, _) = positions(&bytes, Stage::Reached);
    let choices: Vec<usize> = bytes
        .as_chunks::<RECORD>()
        .0
        .iter()
        .enumerate()
        .filter(|(_, record)| record[0] == 3)
        .map(|(at, _)| at)
        .collect();
    let kept = choices.iter().filter(|&&at| at < crashes[1]).count();
    let mut tape = loaded.tape.clone();
    tape.truncate(kept * crate::sim::choice::RECORD_LEN);
    let manifest = manifest("recovery-16k", table.len() as u64);
    let admitted = admit(&manifest).unwrap();
    let mut shortened = loaded.clone();
    shortened.tape = tape;
    let chooser = admitted.replayer(&shortened).unwrap();
    let direct = admitted.replayer(&shortened).unwrap();
    let (closed, end, _) = run_into(admitted, Vec::new(), chooser);
    assert!(matches!(end, End::Defect(_)), "{end:?}");
    let replayed = load(&closed.sink, u64::MAX).unwrap();
    const CRASH_TURN: u8 = 2;
    assert_eq!(replayed.turns.last().map(|turn| turn[1]), Some(CRASH_TURN));
    let ran = super::run(
        direct,
        &super::super::upload_profile(manifest.root),
        Recovery::Kib16,
        bounds(&manifest),
        &mut (),
    );
    assert!(matches!(ran.report.end, End::Defect(_)));
    assert_eq!(ran.compared_writes, [(0, 0)]);
    assert!(
        ran.alive,
        "the owner outlives a Crash turn whose effect choice failed"
    );
    let ledger = rebuild(&replayed.events, table.len() as u32).unwrap();
    assert_eq!(
        ledger.cuts[&1].stages,
        [Stage::Planned, Stage::Reached],
        "the second cut stands reached and unactivated"
    );
    assert_eq!(ledger.cuts[&0].stages.len(), 5);
}

/// A restart bound below the cut count skips the cuts past it, so the
/// campaign is Inconclusive by the first skipped cut's bound and the
/// terminal is inconclusive, which no form counts.
#[test]
fn a_cut_past_the_restart_bound_leaves_the_campaign_inconclusive() {
    let (_, loaded) = recorded("recovery-16k", 1);
    assert_eq!(
        campaign(&loaded),
        Some(Campaign::Inconclusive(Gap::Bound { cut: 1 }))
    );
    assert!(matches!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Outcome::Inconclusive,
            ..
        }
    ));
    assert!(!loaded.terminal.counts());
}

#[test]
fn a_recovery_run_holds_its_links_to_the_manifest_bounds() {
    let table = Recovery::Kib16.table();
    let tight = manifest("recovery-16k", table.len() as u64).with("link_copy_bytes", 1);
    let (_, loaded) = recorded_under(&tight);
    assert_eq!(
        loaded.terminal,
        Terminal::Complete {
            outcome: Outcome::Inconclusive,
            fired: 0,
            required: bit(Obligation::Restart)
        }
    );
    assert_eq!(
        campaign(&loaded),
        Some(Campaign::Inconclusive(Gap::Failed { cut: 0 }))
    );
    assert!(!counts(&loaded));
}

/// The omitted-cut control: a bundle whose ledger lacks a required cut's
/// entries earns no credit and names the cut; a stage out of order refuses
/// the ledger; a truncated run's terminal fires no Restart; a recovery
/// record derived by another executable is refused by its first differing
/// field.
#[test]
fn omitted_out_of_order_and_truncated_ledgers_earn_no_credit() {
    let table = Recovery::Kib16.table();
    let (_, loaded) = recorded("recovery-16k", table.len() as u64);
    let ledger_of = |cut: u8| {
        move |event: &crate::sim::trace::Event| event.kind == LEDGER && event.payload[1] == cut
    };
    let mut omitted = loaded.clone();
    omitted.events.retain(|event| !ledger_of(2)(event));
    assert_eq!(
        campaign(&omitted),
        Some(Campaign::Inconclusive(Gap::Omitted { cut: 2 }))
    );
    let mut reordered = loaded.clone();
    let reached = reordered
        .events
        .iter()
        .position(|event| ledger_of(0)(event) && event.payload[0] == Stage::Reached as u8)
        .unwrap();
    reordered.events.remove(reached);
    assert_eq!(
        campaign(&reordered),
        Some(Campaign::Refused(LedgerError::Order {
            cut: 0,
            stage: Stage::Activated
        }))
    );
    assert!(crate::sim::window::recorded(&reordered).is_none());
    let mut truncated = loaded.clone();
    truncated.terminal = Terminal::Infrastructure(Infrastructure::Truncated);
    assert_eq!(
        campaign(&truncated),
        Some(Campaign::Inconclusive(Gap::NoRestart))
    );
    assert!(!truncated.terminal.counts());
    let mut mismatched = loaded.clone();
    let config = &mut mismatched
        .fields
        .iter_mut()
        .find(|(field, _)| *field == Field::Config)
        .unwrap()
        .1;
    let key = b"descriptor = ";
    let at = config
        .windows(key.len())
        .position(|window| window == key)
        .unwrap()
        + key.len();
    config[at..at + 64].fill(b'0');
    assert_eq!(
        campaign(&mismatched),
        Some(Campaign::Mismatched(Mismatch::Descriptor))
    );
    assert!(!counts(&mismatched));
    let clean = crate::sim::window::recorded(&loaded).unwrap();
    assert!(clean.1.iter().any(|row| row.count > 0));
    assert_eq!(crate::sim::window::recorded(&mismatched), Some(clean));
}

#[test]
fn a_recovery_that_revives_unadmitted_evidence_fails_its_check() {
    let table = Recovery::Kib16.table();
    let manifest = manifest("recovery-16k", table.len() as u64);
    let chooser = admit(&manifest).unwrap().recorder();
    let ran = super::run_planted(
        chooser,
        &super::super::upload_profile(manifest.root),
        Recovery::Kib16,
        bounds(&manifest),
        super::Plant::Revived,
        &mut (),
    );
    assert_eq!(
        ran.failed,
        Some("a recovered candidate was found without admission")
    );
    assert!(!ran.restarted);
}

/// The outcome of a complete terminal; an infrastructure terminal fails the
/// test.
fn complete(terminal: Terminal) -> Outcome {
    match terminal {
        Terminal::Complete { outcome, .. } => outcome,
        other => panic!("an infrastructure terminal: {other:?}"),
    }
}

/// The applied turns of `ran` whose event is `turn`'s.
fn applied(ran: &super::Ran, turn: super::Turn) -> u64 {
    let event = turn.candidate();
    let turns = ran.report.turns.iter();
    turns.filter(|applied| applied.event == event).count() as u64
}

/// A unit leaked on the new incarnation's storage at each Relaunch turn
/// fails the conservation rule's free-run text, which the run carries as its
/// failed rule and its bundle as a `Restart` violation under that text. Its
/// unplanted sibling, [`the_rule_judges_every_turn_of_a_living_incarnation`],
/// runs the same profile to a complete pass with no leak.
#[test]
fn a_unit_leaked_after_a_relaunch_fails_the_free_runs() {
    let (ran, _, _) = planted_run(Recovery::Kib16, super::Plant::LeakedUnit);
    assert!(ran.leaked, "premise: the relaunch leaked a unit");
    assert_eq!(ran.failed, Some(FREE_RUNS));
    assert_eq!((ran.broken, ran.report.end), (None, End::Done));
    let cuts = Recovery::Kib16.table().len() as u64;
    assert_eq!(
        applied(&ran, super::Turn::Relaunch),
        cuts,
        "the run relaunches after every planned cut"
    );
    let (terminal, violated) = judge_recovery(&ran);
    assert_eq!(complete(terminal), Outcome::Violation);
    let expected = Failure::Violation(Obligation::Restart, FREE_RUNS);
    assert_eq!(violated, Some(Violated::Observed(expected)));
}

/// The conservation rule judges the living incarnation after every turn but
/// a Crash turn, which kills it, the Relaunch turns included, and after
/// every clock move, each of which comes while an incarnation lives: its
/// judgments equal the turns applied less the Crash turns plus the clock
/// moves, the first at the start and each later one 100 microseconds on.
/// The run relaunches after each crash, finishes, and passes every check.
#[test]
fn the_rule_judges_every_turn_of_a_living_incarnation() {
    let (ran, _, _) = planted_run(Recovery::Kib16, super::Plant::None);
    assert_eq!((ran.failed, ran.broken, ran.leaked), (None, None, false));
    assert_eq!(ran.report.end, End::Done);
    assert_eq!(complete(judge_recovery(&ran).0), Outcome::Pass);
    let crashes = applied(&ran, super::Turn::Crash);
    assert!(crashes > 0, "premise: the run crashed its owner");
    assert_eq!(
        applied(&ran, super::Turn::Relaunch),
        crashes,
        "premise: each crash relaunched"
    );
    assert_eq!(ran.report.turns.len() as u64, ran.report.turn_count);
    let clocks = 1 + ran.report.virtual_us / 100;
    assert_eq!(
        ran.conserved,
        ran.report.turn_count - crashes + clocks,
        "{} turns, {crashes} crashes, {clocks} clock moves",
        ran.report.turn_count
    );
}

/// A pool gate poisoned on the new incarnation's storage at its Relaunch
/// turn leaves the conservation snapshot unreadable, which ends the run at
/// that turn, unsuccessful by the snapshot's reason with no failed rule.
#[test]
fn an_unreadable_table_after_a_relaunch_ends_the_run_unsuccessful() {
    let (ran, _, _) = planted_run(Recovery::Kib16, super::Plant::PoisonedPool);
    assert_eq!(ran.failed, None);
    assert_eq!(ran.broken, Some("the pool gate was held or poisoned"));
    assert_eq!(complete(judge_recovery(&ran).0), Outcome::Unsuccessful);
    let relaunch = super::Turn::Relaunch.candidate();
    let turns = &ran.report.turns;
    let first = turns.iter().position(|applied| applied.event == relaunch);
    assert_eq!(
        first,
        Some(turns.len() - 1),
        "the first Relaunch is the last turn"
    );
    assert_eq!(ran.report.end, End::Done);
}

fn planted_run(recovery: Recovery, plant: super::Plant) -> (super::Ran, Ledger, Result<(), Gap>) {
    let table = recovery.table();
    let manifest = manifest(name(recovery), table.len() as u64);
    let mut events = Events::default();
    let ran = super::run_planted(
        admit(&manifest).unwrap().recorder(),
        &super::super::upload_profile(manifest.root),
        recovery,
        bounds(&manifest),
        plant,
        &mut events,
    );
    let ledger = rebuild(&events.0, table.len() as u32).unwrap();
    let credit = crate::sim::ledger::credit(&ledger, &table, &recovery.descriptor(), ran.restarted);
    (ran, ledger, credit)
}

fn planted_credit(recovery: Recovery, plant: super::Plant) -> Result<(), Gap> {
    planted_run(recovery, plant).2
}

fn gaps(rows: &[window::Row]) -> Vec<&str> {
    rows.iter()
        .filter(|r| r.status == window::Status::Gap)
        .map(|r| r.name.as_str())
        .collect()
}

#[test]
fn every_planned_window_is_covered_under_each_class_of_its_profile() {
    for profile in [Recovery::Kib16, Recovery::Sector, Recovery::Torn] {
        let cuts = profile.table().len();
        let (_, loaded) = recorded(name(profile), cuts as u64);
        let ledger = rebuild(&loaded.events, cuts as u32).unwrap();
        let rows = window::census(profile, &ledger);
        assert_eq!(gaps(&rows), Vec::<&str>::new(), "{profile:?}");
        assert_eq!(
            rows.len(),
            if profile == Recovery::Torn { 22 } else { 16 },
            "{profile:?}"
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r.status == window::Status::Covered)
                .count(),
            4,
            "{profile:?}"
        );
    }
}

#[test]
fn omitting_the_second_fill_names_only_its_after_window() {
    let profile = Recovery::Kib16;
    let (ran, ledger, credit) = planted_run(profile, super::Plant::Unfilled);
    assert_eq!((ran.broken, ran.failed, ran.write_gap), (None, None, None));
    assert!(ran.restarted);
    assert_eq!(ran.compared_writes, [(0, 0), (1, 1), (2, 1), (3, 1)]);
    assert_eq!(ledger.cuts[&3].checked, Some(Checked::Pass));
    assert_eq!(
        gaps(&window::census(profile, &ledger)),
        ["1.accepted-submission.0.after.ProcessDeath"]
    );
    assert_eq!(credit, Err(Gap::Unmatched { cut: 3 }));
}

#[test]
fn every_accepted_write_is_a_declared_child_in_declared_order() {
    for profile in [Recovery::Kib16, Recovery::Sector, Recovery::Torn] {
        let (ran, _, credit) = planted_run(profile, super::Plant::None);
        let table = profile.table();
        if let Some((at, gap)) = ran.write_gap {
            panic!("{profile:?} cut {at} {:?}: {gap:?}", table.get(at as usize));
        }
        let expected: Vec<_> = table
            .iter()
            .enumerate()
            .map(|(at, cut)| (at as u32, cut.mask.len()))
            .collect();
        assert_eq!(ran.compared_writes, expected, "{profile:?}");
        assert_eq!(credit, Ok(()), "{profile:?}");
    }
}

#[test]
fn adjacent_windows_with_the_same_held_write_count_their_own_cuts() {
    let (_, loaded) = recorded("recovery-16k", 2);
    let rows = window::census(Recovery::Kib16, &rebuild(&loaded.events, 4).unwrap());
    let row = |name: &str| {
        let r = rows.iter().find(|r| r.name == name).unwrap();
        (r.status, r.count)
    };
    assert_eq!(
        row("0.accepted-submission.0.after.ProcessDeath"),
        (window::Status::Covered, 1)
    );
    assert_eq!(
        row("1.accepted-submission.0.before.ProcessDeath"),
        (window::Status::Gap, 0)
    );
}

#[test]
fn shifting_the_comparison_reports_the_first_accepted_fill_range() {
    let range = crate::storage::DeviceRange::new(128 * 512, 16 * 512).unwrap();
    for (profile, cut) in [
        (Recovery::Kib16, 1),
        (Recovery::Sector, 1),
        (Recovery::Torn, 2),
    ] {
        let (ran, _, credit) = planted_run(profile, super::Plant::Unmatched);
        assert_eq!(
            ran.write_gap,
            Some((cut, super::measure::WriteGap::Undeclared(range))),
            "{profile:?}"
        );
        assert_eq!(credit, Err(Gap::Unmatched { cut }), "{profile:?}");
    }
}

#[test]
fn the_torn_table_plans_none_whole_and_sector_prefix_landings() {
    let table = Recovery::Torn.table();
    let masks: Vec<&[u64]> = table.iter().map(|cut| cut.mask.as_slice()).collect();
    for landing in [[0], [0b1], [0b111_1111], [0xFFFF]] {
        assert!(masks.contains(&landing.as_slice()), "{landing:?}");
    }
    assert!(
        table
            .iter()
            .flat_map(|cut| &cut.mask)
            .all(|&word| word.trailing_ones() == word.count_ones()),
        "the table holds only supported landings"
    );
    assert_eq!(table.len(), 20);
}

#[test]
fn a_wrong_landing_class_or_drain_or_ambiguous_evidence_withholds_credit() {
    use super::Plant;
    let table = Recovery::Torn.table();
    let first =
        |partial: fn(&crate::sim::cut::Cut) -> bool| table.iter().position(partial).unwrap() as u32;
    let dropped = first(|cut| cut.mask == [0]);
    let held = first(|cut| !cut.mask.is_empty());
    assert_eq!(
        planted_credit(Recovery::Torn, Plant::Whole),
        Err(Gap::Landing { cut: dropped })
    );
    assert_eq!(
        planted_credit(Recovery::Torn, Plant::Indistinct),
        Err(Gap::Ambiguous { cut: held })
    );
    assert_eq!(
        planted_credit(Recovery::Torn, Plant::Swapped),
        Err(Gap::Class { cut: 0 })
    );
    assert_eq!(
        planted_credit(Recovery::Torn, Plant::Stuck),
        Err(Gap::Undrained { cut: held })
    );
}

/// A cold relaunch answers every recovered lookup Missing, so every Lookup
/// turn sees no hit, and the summary's census counts each stage.
#[test]
fn a_cold_relaunch_answers_missing_and_the_census_counts_each_stage() {
    let table = Recovery::Kib16.table();
    let manifest = manifest("recovery-16k", table.len() as u64);
    let chooser = admit(&manifest).unwrap().recorder();
    let ran = super::run(
        chooser,
        &super::super::upload_profile(manifest.root),
        Recovery::Kib16,
        bounds(&manifest),
        &mut (),
    );
    const LOOKUP: u8 = 4;
    let lookups: Vec<u64> = ran
        .report
        .turns
        .iter()
        .filter(|turn| turn.event.0[1] == LOOKUP)
        .map(|turn| turn.outcome)
        .collect();
    assert_eq!(lookups, vec![0; table.len()]);
    let (_, loaded) = recorded("recovery-16k", table.len() as u64);
    let stages = |bundle| crate::sim::window::recorded(bundle).map(|(stages, _)| stages);
    assert_eq!(stages(&loaded), Some([4, 4, 4, 4, 4, 0]));
    let (_, bounded) = recorded("recovery-16k", 1);
    assert_eq!(stages(&bounded), Some([4, 1, 1, 1, 1, 3]));
    assert!(LIMITS.contains("measured on media against the submitted bytes"));
}

/// `lookups_follow_relaunches` holds exactly when the turns hold a
/// Relaunch and the turn after every Relaunch is a Lookup.
#[test]
fn ib_campaign_recovery_each_relaunch_is_followed_by_its_lookup() {
    let turns = |listed: &[super::Turn]| -> Vec<[u8; 16]> {
        listed.iter().map(|turn| turn.candidate().0).collect()
    };
    use super::Turn::{Crash, Hold, Lookup, Relaunch};
    assert!(super::lookups_follow_relaunches(&turns(&[
        Crash, Relaunch, Lookup
    ])));
    assert!(super::lookups_follow_relaunches(&turns(&[
        Relaunch, Lookup, Crash, Relaunch, Lookup
    ])));
    for refused in [
        &[][..],
        &[Crash, Hold][..],
        &[Relaunch, Hold, Lookup][..],
        &[Relaunch, Lookup, Relaunch][..],
    ] {
        assert!(
            !super::lookups_follow_relaunches(&turns(refused)),
            "{refused:?}"
        );
    }
}

/// Every turn the recovery world offers names its operation in the
/// narrative's recovery world, a fill with its operation index.
#[test]
fn every_recovery_turn_names_its_operation() {
    use crate::net::world_tests::narrate::{World, tests::turn_line};
    for (turn, named) in [
        (super::Turn::Fill(4), "fill operation=4"),
        (super::Turn::Crash, "crash operation=0"),
        (super::Turn::Relaunch, "relaunch operation=0"),
        (super::Turn::Lookup, "lookup operation=0"),
        (super::Turn::Hold, "hold operation=0"),
    ] {
        let line = turn_line(World::Recovery, turn.candidate().0, 0);
        assert!(
            line.contains(&format!("domain=Workload code={named} outcome=0")),
            "{line}"
        );
    }
}
