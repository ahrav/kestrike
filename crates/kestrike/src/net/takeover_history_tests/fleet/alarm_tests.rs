//! The fleet's alarm oracle on its scenarios and its controls: a clean and two fault scenarios fire their expected
//! rows, a catalog without an expected row fails the oracle by its rule text, and every status the oracle reads is a
//! reconciler tick's sealed part. A run that sealed nothing reads not run, a scenario with no stated set reads not
//! judged, and the fleet verdict over such a scenario reads incomplete. The scheduled case judges every scenario.

use super::super::cycles::Verdict;
use super::alarms::{self, AlarmLog, Expected, Source};
use super::hosts::{self, Scenario};
use super::*;
use crate::failover::report::alarm_tests::catalog;
use std::collections::BTreeSet;

/// The shipped catalog with row `id` removed.
fn without(id: &str) -> serde_json::Value {
    let mut catalog = catalog();
    let rows = catalog["rows"].as_array_mut().expect("the catalog's rows");
    let before = rows.len();
    rows.retain(|row| row["id"] != id);
    assert_eq!(rows.len() + 1, before, "the catalog holds {id}");
    catalog
}

/// A clean settle fires no row; a full census fires its census rows and the lost hosts' silence; the attach-closed
/// layout fires `attach-closed` with the self-suspicion three lost hosts bring. Each run's alarm verdict passes, and
/// every status the oracle reads is one of the reconciler actors' ticks: the statuses sealed equal the loops' ticks,
/// and no writer refused a tick. With `census-refused-full` or `attach-closed` removed from the evaluated catalog
/// the oracle fails its scenario by `ALARM_SET` ("the fired alarm rows differ from the scenario's expected set"),
/// naming the row missing; judged against the empty set under the shipped catalog the same run fails with every
/// row of its set extra; and the clean run passes under a catalog without `host-silent`, a row it never fires.
#[test]
fn each_scenario_fires_its_named_rows_and_a_removed_row_fails_by_the_rule_text() {
    let cases = [
        (Config::settle(1), None),
        (Config::census_full(1), Some("census-refused-full")),
        (Config::attach_closed(1), Some("attach-closed")),
    ];
    for (config, named) in cases {
        let scenario = config.scenario;
        let report = run_shared(&config).expect("a run that ends");
        assert_eq!(
            report.alarms(),
            Verdict::Pass,
            "{scenario:?}: {}",
            report.summary()
        );
        let log = &report.alarm_log;
        let statuses = (log.sealed.iter())
            .filter(|s| s.source == Source::Status)
            .count();
        assert_eq!(statuses as u32, report.recon.calls, "{scenario:?}");
        assert_eq!((log.unsealed, log.unsealable), (0, 0), "{scenario:?}");
        assert!(statuses > 0, "{scenario:?}: the loops sealed statuses");
        let expected = alarms::expected(&config);
        let Expected::Rows(rows) = expected else {
            panic!("{scenario:?} states its set");
        };
        assert_eq!(rows.is_empty(), named.is_none(), "{scenario:?}");
        let Some(removed) = named else {
            let judged = alarms::judged(log, &without("host-silent"), expected, true);
            assert_eq!(
                judged,
                Verdict::Pass,
                "{scenario:?} without a row it never fires"
            );
            continue;
        };
        {
            assert!(rows.contains(&removed), "{scenario:?} names {removed}");
            let judged = alarms::judged(log, &without(removed), expected, true);
            let Verdict::Fail(rule, at) = &judged else {
                panic!("{scenario:?} without {removed}: {judged:?}");
            };
            let text = "the fired alarm rows differ from the scenario's expected set";
            assert_eq!(*rule, text, "{scenario:?}: the rule is ALARM_SET");
            assert!(at.starts_with(&format!("missing [\"{removed}\"]")), "{at}");
            let empty = alarms::judged(log, &catalog(), Expected::Rows(&[]), true);
            let extra = format!("missing [] extra {rows:?}");
            assert_eq!(empty, Verdict::Fail(text, extra), "{scenario:?}");
        }
    }
}

/// A run with no sealed record, or with reports and no status while its reconcilers run, reads
/// `Unrun(NO_RECORDS)` whatever its expected set; a sealed record the readers refuse fails `UNREAD`, and a tick a
/// writer refused for a reason other than its pacing, or an early tick no scenario scripts, fails `UNSEALED`; a
/// volume case and a run under a
/// test's own fault script read `Unrun(NOT_JUDGED)`, and a run under a hostile configuration reads
/// `Unrun(PLANTED)`. The fleet verdict over any scenario that did not pass, and over no scenario, reads
/// `Unrun(INCOMPLETE)`, while one failure reads that failure. The status requirement follows the configuration, and
/// a configuration off its fixture's census cap has no expected set.
#[test]
fn a_run_with_no_sealed_record_is_not_run_and_a_scenario_with_no_set_makes_the_fleet_verdict_incomplete()
 {
    let shipped = catalog();
    let none = Expected::Rows(&[]);
    let empty = AlarmLog::default();
    assert_eq!(
        alarms::judged(&empty, &shipped, none, false),
        Verdict::Unrun(alarms::NO_RECORDS)
    );
    let report = run_shared(&Config::settle(1)).expect("a run that ends");
    let mut reports = report.alarm_log.clone();
    reports
        .sealed
        .retain(|sealed| sealed.source == Source::Report);
    assert_eq!(
        alarms::judged(&reports, &shipped, none, true),
        Verdict::Unrun(alarms::NO_RECORDS)
    );
    assert_eq!(
        alarms::judged(&reports, &shipped, none, false),
        Verdict::Pass
    );
    let mut forged = reports.clone();
    let mut bytes = forged.sealed[0].bytes.clone();
    *bytes.last_mut().expect("a tag") ^= 1;
    forged.receive(Source::Report, 0, &bytes);
    let refused = alarms::judged(&forged, &shipped, none, false);
    assert_eq!(refused.rule(), Some(alarms::UNREAD), "{refused:?}");
    let volume = Config::lost_alone(1);
    let not_judged = alarms::judged(&report.alarm_log, &shipped, alarms::expected(&volume), true);
    let mut scripted = report.alarm_log.clone();
    scripted.scripted = true;
    assert_eq!(
        alarms::verdict(&scripted, &Config::settle(1)),
        Verdict::Unrun(alarms::NOT_JUDGED)
    );
    let mut unsealable = report.alarm_log.clone();
    unsealable.unsealable = 1;
    let refused = alarms::verdict(&unsealable, &Config::settle(1));
    assert_eq!(refused.rule(), Some(alarms::UNSEALED), "{refused:?}");
    // One early tick outside the two-reconciler race fails a run that would pass.
    let mut early = report.alarm_log.clone();
    early.unsealed = 1;
    let refused = alarms::verdict(&early, &Config::settle(1));
    assert_eq!(refused.rule(), Some(alarms::UNSEALED), "{refused:?}");
    // The status requirement follows the configuration: the settle's reports alone read not run under the settle,
    // whose reconciler runs, and pass under the host loss, which runs none and states the same empty set.
    assert_eq!(
        alarms::verdict(&reports, &Config::settle(1)),
        Verdict::Unrun(alarms::NO_RECORDS)
    );
    assert_eq!(
        alarms::verdict(&reports, &Config::host_loss(1)),
        Verdict::Pass
    );
    // A configuration off its fixture's census cap has no expected set.
    let capped = |mut config: Config, cap: u16| {
        config.shape.cap = cap;
        alarms::expected(&config)
    };
    let stated = |expected: Expected| matches!(expected, Expected::Rows(_));
    assert_eq!(capped(Config::reenroll(1), 5), Expected::NotJudged);
    assert!(stated(alarms::expected(&Config::reenroll(1))));
    assert_eq!(capped(Config::az_settle(1), 5), Expected::NotJudged);
    assert_eq!(capped(Config::zone_loss(1), 5), Expected::NotJudged);
    assert_eq!(alarms::expected(&Config::az_settle(1)), Expected::Rows(&[]));
    assert_eq!(capped(Config::census_full(1), 6), Expected::NotJudged);
    assert!(stated(alarms::expected(&Config::census_full(1))));
    assert_eq!(capped(Config::past_target(1), 6), Expected::NotJudged);
    assert!(stated(alarms::expected(&Config::past_target(1))));
    assert!(stated(capped(Config::settle(1), 5)) && stated(capped(Config::host_loss(1), 5)));
    assert_eq!(not_judged, Verdict::Unrun(alarms::NOT_JUDGED));
    let planted = Config::settle(1).hostile(Plant::DropNeed, 0);
    assert_eq!(
        alarms::verdict(&report.alarm_log, &planted),
        Verdict::Unrun(alarms::PLANTED)
    );
    let failed = Verdict::Fail(alarms::ALARM_SET, "missing [] extra [\"x\"]".into());
    let fleet = alarms::fleet_verdict;
    assert_eq!(fleet(&[Verdict::Pass, Verdict::Pass]), Verdict::Pass);
    let incomplete = Verdict::Unrun(alarms::INCOMPLETE);
    assert_eq!(fleet(&[Verdict::Pass, not_judged.clone()]), incomplete);
    assert_eq!(fleet(&[Verdict::Unrun(alarms::NO_RECORDS)]), incomplete);
    assert_eq!(fleet(&[]), incomplete);
    assert_eq!(fleet(&[not_judged, failed.clone(), Verdict::Pass]), failed);
}

/// Every scenario's configuration on root 1, by the name its scheduled line prints.
fn scenarios() -> Vec<(String, Config)> {
    use super::hosts::Unknown;
    use super::reconcile::CrashCell;
    use super::volumes::ReplaceCell;
    let named: [(&str, Config); 37] = [
        ("restarts", Config::six(1)),
        ("host-loss", Config::host_loss(1)),
        ("partition-loss", Config::partition_loss(1)),
        ("partition-loss-at", Config::partition_loss_at(1)),
        ("false-suspicion", Config::false_suspicion(1)),
        ("owner-pause", Config::owner_pause(1)),
        ("owner-isolation", Config::owner_isolation(1)),
        ("page-regressed", Config::page_regressed(1)),
        ("record-regressed", Config::record_regressed(1)),
        ("settle", Config::settle(1)),
        ("tiny-settle", Config::tiny_settle(1)),
        ("az-settle", Config::az_settle(1)),
        ("reenroll", Config::reenroll(1)),
        ("standby-loss", Config::standby_loss(1)),
        ("standby-silent", Config::standby_silent(1)),
        ("double-loss", Config::double_loss(1)),
        ("quorum-loss", Config::quorum_loss(1)),
        ("partition-repair", Config::partition_repair(1)),
        ("partition-repair-at", Config::partition_repair_at(1)),
        ("census-full", Config::census_full(1)),
        ("past-target", Config::past_target(1)),
        ("attach-survivor", Config::attach_survivor(1)),
        ("attach-closed", Config::attach_closed(1)),
        ("foreign", Config::foreign(1)),
        ("racing", Config::racing(1)),
        ("slot-moved", Config::slot_moved(1)),
        ("handoff", Config::handoff(1)),
        ("handoff-ended", Config::handoff_ended(1)),
        ("zone-loss", Config::zone_loss(1)),
        ("zone-impaired", Config::zone_impaired(1)),
        ("zone-deposed", Config::zone_deposed(1)),
        ("impaired", Config::impaired(1)),
        ("impaired-brief", Config::impaired_brief(1)),
        ("stall", Config::stall(1)),
        ("lost-alone", Config::lost_alone(1)),
        ("correlated", Config::correlated(1)),
        ("correlated-late", Config::correlated_late(1)),
    ];
    let mut all: Vec<(String, Config)> = (named.into_iter())
        .map(|(name, config)| (name.to_owned(), config))
        .collect();
    all.extend(
        (Unknown::all().into_iter()).map(|cell| (cell.name(), Config::store_unknown(1, cell))),
    );
    all.extend((CrashCell::all().into_iter()).map(|cell| (cell.name(), Config::crash(1, cell))));
    all.extend(
        (ReplaceCell::all().into_iter()).map(|cell| (cell.name(), Config::replace(1, cell))),
    );
    all
}

/// Every scenario of the fleet on root 1, each run once: a scenario that states its set fires exactly it, holds its
/// required outcome and witnesses (`hosts::expected`) on the same report, and prints one line; the restart scenario, whose hosts run no agent and seal no report, reads not run; the volume cases and
/// the replacement cells read not judged. The fleet verdict over all of them reads incomplete, and over the scenarios
/// that state a set and sealed records it passes. Four controls then fail by `ALARM_SET`: the double loss judged
/// against its set widened by `volume-lost` reads that row missing, and a settle under a census cap of five read
/// through `Report::alarms` under the clean settle's configuration, whose set is empty, reads its two census rows
/// extra; the standby-target scenario judged under a catalog without `no-standby-past-target` reads that row
/// missing; and the quorum loss under `LostProbersCounted` (code 99) reads `quorum-unreachable` missing. The scenarios'
/// names and configuration identities are distinct. The last line counts the three kinds and the controls.
#[test]
#[ignore = "every fleet scenario's alarm set on root 1; the search-nightly lane's row fleet-scheduled-roots runs it with --ignored"]
fn every_scenario_fires_its_expected_alarm_set_on_its_scheduled_root() {
    let (mut verdicts, mut passed) = (Vec::new(), Vec::new());
    let (mut not_run, mut not_judged) = (0, 0);
    let listed = scenarios();
    let names: BTreeSet<&str> = listed.iter().map(|(name, _)| name.as_str()).collect();
    let identities: BTreeSet<String> =
        (listed.iter().map(|(_, config)| config.identity())).collect();
    assert_eq!(
        (names.len(), identities.len()),
        (listed.len(), listed.len())
    );
    for (name, config) in listed {
        let root = config.root;
        let report = run_shared(&config).expect("a run that ends");
        assert_eq!(report.config, config, "{name}");
        let verdict = report.alarms();
        match &verdict {
            Verdict::Pass => {
                // The member counts only when the scenario's own outcome and witnesses hold on the same report.
                let reached = hosts::expected(&report);
                assert_eq!(reached, Verdict::Pass, "{name}: {}", report.summary());
                println!("fleet: scheduled alarms-{name} root {root}: pass");
                passed.push(verdict.clone());
            }
            Verdict::Unrun(why) if *why == alarms::NO_RECORDS => {
                assert_eq!(config.scenario, Scenario::Restarts, "{name}");
                not_run += 1;
            }
            Verdict::Unrun(why) if *why == alarms::NOT_JUDGED => {
                let stated = alarms::expected(&config);
                assert_eq!(stated, Expected::NotJudged, "{name}");
                not_judged += 1;
            }
            other => panic!("{name}: {}\n{}", other.word(), report.summary()),
        }
        verdicts.push(verdict);
    }
    assert_eq!(
        alarms::fleet_verdict(&verdicts),
        Verdict::Unrun(alarms::INCOMPLETE)
    );
    assert_eq!(alarms::fleet_verdict(&passed), Verdict::Pass);
    assert_eq!((passed.len(), not_run, not_judged), (66, 1, 27));
    // A wrong expected set fails by the rule text: a fault scenario's set with a row its run does not fire, and the
    // clean scenario's empty set over a settle whose census cap lies below its shard count.
    let text = "the fired alarm rows differ from the scenario's expected set";
    let shipped = catalog();
    let lost = run_shared(&Config::double_loss(1)).expect("a run that ends");
    let wider = Expected::Rows(&["host-silent", "need-fresh", "shard-silent", "volume-lost"]);
    let missing = alarms::judged(&lost.alarm_log, &shipped, wider, true);
    let at = "missing [\"volume-lost\"] extra []".to_owned();
    assert_eq!(missing, Verdict::Fail(text, at));
    println!("fleet: scheduled alarms-control-missing-row root 1: pass");
    let mut capped = Config::settle(1);
    capped.shape.cap = 5;
    let settled = run_shared(&capped).expect("a run that ends");
    assert_eq!(
        settled.alarms(),
        Verdict::Pass,
        "the capped settle fires its census rows"
    );
    // The same records under the clean settle's configuration, whose set is empty, read through `Report::alarms`.
    assert_eq!(alarms::expected(&Config::settle(1)), Expected::Rows(&[]));
    let mut relabelled = settled;
    relabelled.config = Config::settle(1);
    let at = "missing [] extra [\"census-cap-below-shards\", \"census-near-cap\"]".to_owned();
    assert_eq!(relabelled.alarms(), Verdict::Fail(text, at));
    println!("fleet: scheduled alarms-control-extra-row root 1: pass");
    // The standby-target scenario judged under a catalog without `no-standby-past-target` reads that row missing.
    let past = run_shared(&Config::past_target(1)).expect("a run that ends");
    let expected = alarms::expected(&Config::past_target(1));
    let judged = alarms::judged(
        &past.alarm_log,
        &without("no-standby-past-target"),
        expected,
        true,
    );
    let at = "missing [\"no-standby-past-target\"] extra []".to_owned();
    assert_eq!(judged, Verdict::Fail(text, at));
    println!("fleet: scheduled alarms-control-past-target-row root 1: pass");
    quorum_unreachable_control_on(1);
    println!("fleet: scheduled alarms-control-quorum-unreachable-row root 1: pass");
    println!(
        "fleet: scheduled alarms: {} sets passed, {not_run} not run, {not_judged} not judged, 4 controls failed by the rule",
        passed.len()
    );
}

/// The quorum-loss scenario under `LostProbersCounted` (code 99): the zone loop counts the lost H4 among s2's
/// possible probers, so its status names no `quorum-unreachable` blocker, and the run's records judged against the
/// scenario's set read that row missing.
fn quorum_unreachable_control_on(root: u64) {
    let text = "the fired alarm rows differ from the scenario's expected set";
    let config = Config::quorum_loss(root).hostile(Plant::LostProbersCounted, 0);
    let planted = run_shared(&config).expect("a run that ends");
    let expected = alarms::expected(&Config::quorum_loss(root));
    let judged = alarms::judged(&planted.alarm_log, &catalog(), expected, true);
    let at = "missing [\"quorum-unreachable\"] extra []".to_owned();
    assert_eq!(judged, Verdict::Fail(text, at));
}

/// The quorum-loss scenario fires its stated set, `quorum-unreachable` among it, and holds its outcome and
/// witnesses on root 1. Its live control, `quorum_unreachable_control_on`, runs in the scheduled alarm case.
#[test]
fn the_quorum_loss_scenario_fires_its_set_with_quorum_unreachable() {
    let report = run_shared(&Config::quorum_loss(1)).expect("a run that ends");
    assert_eq!(report.alarms(), Verdict::Pass, "{}", report.summary());
    assert_eq!(report.credit(), Verdict::Pass, "{}", report.summary());
    assert_eq!(
        hosts::expected(&report),
        Verdict::Pass,
        "{}",
        report.summary()
    );
    let stated = alarms::expected(&Config::quorum_loss(1));
    assert!(matches!(stated, Expected::Rows(rows) if rows.contains(&"quorum-unreachable")));
}

/// The report's digest covers the alarm log: an edit of one sealed byte, of either refused-seal count or of the
/// scripted mark changes it.
#[test]
fn the_digest_of_a_run_changes_with_its_alarm_log() {
    let report = run_shared(&Config::settle(1)).expect("a run that ends");
    type Edit = (&'static str, fn(&mut AlarmLog));
    let edits: [Edit; 4] = [
        ("a sealed byte", |log| log.sealed[0].bytes[0] ^= 1),
        ("the early ticks", |log| log.unsealed += 1),
        ("the refused seals", |log| log.unsealable += 1),
        ("the scripted mark", |log| log.scripted = true),
    ];
    for (name, edit) in edits {
        let mut edited = report.clone();
        edit(&mut edited.alarm_log);
        assert_ne!(edited.digest(), report.digest(), "{name}");
    }
}

/// A reconciler's sealer logs a tick it seals, counts a second tick inside the seal period as early and a tick its
/// writer refuses for another reason as refused, and neither refusal adds a record.
#[test]
fn a_sealer_counts_an_early_tick_apart_from_any_other_refusal() {
    use crate::failover::report::status::{StatusReader, tests::key_of};
    let report = run_shared(&Config::settle(1)).expect("a run that ends");
    let sealed = (report.alarm_log.sealed.iter()).find(|sealed| sealed.source == Source::Status);
    let bytes = &sealed.expect("a sealed status").bytes;
    let status = StatusReader::default().accept(bytes, key_of);
    let part = status.expect("an accepted status").zones.remove(0);
    let (mut sealers, mut log) = (alarms::Sealers::default(), AlarmLog::default());
    sealers.open(0, 200);
    sealers.seal(0, &part, 1_000, &mut log);
    assert_eq!((log.sealed.len(), log.unsealed, log.unsealable), (1, 0, 0));
    sealers.seal(0, &part, 1_000, &mut log);
    assert_eq!((log.sealed.len(), log.unsealed, log.unsealable), (1, 1, 0));
    let mut wide = part.clone();
    let row = wide.rows.first().copied();
    let rows = crate::failover::report::status::MAX_ROWS + 1;
    wide.rows = vec![row.expect("premise: the part holds a row"); rows];
    sealers.seal(0, &wide, 2_000, &mut log);
    assert_eq!((log.sealed.len(), log.unsealed, log.unsealable), (1, 1, 1));
}

/// The catalog rows, in catalog order, that no judged scenario's expected set holds: the fleet's alarm oracle
/// judges each of them by its absence alone, as an extra row of a run that fires it.
const UNJUDGED: [&str; 40] = [
    "store-instance-change",
    "hold-recorded-holder",
    "hold-no-holder",
    "hold-device",
    "hold-store",
    "unknown-recovery-write",
    "suffix-only",
    "load-refused",
    "enumeration-foreign",
    "retention-damage",
    "read-defect",
    "chain-at-cap",
    "handoff-due",
    "exit-restarting",
    "exit-stuck",
    "coverage-saturated",
    "first-hit-slow",
    "recovery-stuck",
    "store-unknown-rate",
    "mutation-backlog-full",
    "suffix-backlog-full",
    "publication-stuck",
    "enumeration-unlisted",
    "replacement-held",
    "replacement-exhausted",
    "volume-lost",
    "volume-unnamed",
    "report-forged",
    "report-schema",
    "stale-serving",
    "store-unread",
    "sources-unread",
    "attach-failed",
    "status-absent",
    "budget-attempts",
    "budget-generation",
    "store-regression-reconciler",
    "store-instance-change-reconciler",
    "store-unknown-rate-reconciler",
    "registrant-ended",
];

/// The shipped catalog's rows, in catalog order, that no expected set of `listed` holds.
fn unjudged(listed: &[(String, Config)]) -> Vec<String> {
    let stated: BTreeSet<&str> = (listed.iter())
        .filter_map(|(_, config)| match alarms::expected(config) {
            Expected::Rows(rows) => Some(rows.iter().copied()),
            Expected::NotJudged => None,
        })
        .flatten()
        .collect();
    let shipped = catalog();
    let rows = shipped["rows"].as_array().expect("the catalog's rows");
    (rows.iter())
        .map(|row| row["id"].as_str().expect("a row id"))
        .filter(|id| !stated.contains(id))
        .map(str::to_owned)
        .collect()
}

/// The catalog rows that no judged scenario's expected set holds, computed from `alarms::expected` over every
/// scenario's root-1 configuration, are the written list `UNJUDGED`, so a catalog row that enters or leaves the union
/// of the stated sets, a new row no set states included, changes the list by name. The control drops the
/// standby-target scenario, the one scenario whose set holds `no-standby-past-target`, and the computed list gains
/// exactly that row.
#[test]
fn the_catalog_rows_no_judged_scenario_expects_are_the_written_list() {
    let listed = scenarios();
    assert_eq!(unjudged(&listed), UNJUDGED);
    let without: Vec<(String, Config)> = (listed.into_iter())
        .filter(|(_, config)| config.scenario != Scenario::PastTarget)
        .collect();
    let widened = unjudged(&without);
    let gained: Vec<&String> = (widened.iter())
        .filter(|row| !UNJUDGED.contains(&row.as_str()))
        .collect();
    let violation = "the list gains exactly no-standby-past-target";
    assert_eq!(gained, ["no-standby-past-target"], "{violation}");
    assert_eq!(widened.len(), UNJUDGED.len() + 1);
}

/// Every statement of the fleet's modules that replaces a fleet's fault script (`fleet.faults = ..`) is followed,
/// within two lines, by the statement that marks the run's alarm log as scripted, so [`alarms::verdict`] reads the
/// run as one with no expected set. The test reads the modules' source, so a test that arrives with a merge and
/// installs its own script fails here until it sets the mark.
#[test]
fn every_statement_that_replaces_the_fault_script_marks_the_alarm_log() {
    let fleet = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/net/takeover_history_tests/fleet");
    let modules = std::fs::read_dir(&fleet).expect("the fleet's modules");
    let mut paths: Vec<_> = modules
        .map(|entry| entry.expect("a module").path())
        .collect();
    paths.sort();
    let (mut sites, mut unmarked) = (0, Vec::new());
    for path in paths {
        let source = std::fs::read_to_string(&path).expect("a readable module");
        let lines: Vec<&str> = source.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("fleet.faults = ") {
                continue;
            }
            sites += 1;
            let mut next = lines[at + 1..].iter().take(2);
            if !next.any(|line| line.trim() == "fleet.alarms.scripted = true;") {
                let name = path.file_name().expect("a module's name");
                unmarked.push(format!("{}:{}", name.to_string_lossy(), at + 1));
            }
        }
    }
    assert!(sites > 0, "premise: the modules hold a replaced script");
    assert_eq!(
        unmarked,
        Vec::<String>::new(),
        "sites that leave the log unmarked"
    );
}
