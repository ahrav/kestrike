use super::*;
use crate::campaign::report::tests::Fixture;
use crate::campaign::state_fixture::Sharded;
use crate::step::{self, Outcome, Script, Step};
use crate::store::fixture::{Case, snapshot};
use std::fs;

/// The bulk files of the fixture's settled attempt that collect reclaims
/// beside its two launcher logs: its bundle and three worker streams, the
/// `inspect` stdout the report measures from staying.
const BULK: u64 = 4;

/// Lifecycle records keep their paths in the comparison while their
/// fixture-specific cgroup bytes are normalized across cases.
fn comparable(path: &Path) -> BTreeMap<std::path::PathBuf, Option<Vec<u8>>> {
    snapshot(path)
        .into_iter()
        .map(|(entry, bytes)| {
            let bytes = if entry.ends_with("intent") || entry.ends_with("started") {
                bytes.map(|_| Vec::new())
            } else {
                bytes
            };
            (entry, bytes)
        })
        .collect()
}

fn kept_bytes(before: &BTreeMap<std::path::PathBuf, Option<Vec<u8>>>, path: &Path) {
    let after = snapshot(path);
    for (entry, bytes) in before {
        if let Some(kept) = after.get(entry) {
            assert_eq!(kept, bytes, "{}", entry.display());
        }
    }
}

fn launcher_logs(store: &Store, directory: &Dir, bytes: &[u8]) {
    for output in crate::custody::LAUNCHER_OUTPUTS {
        store.create_once(directory, &name(output), bytes).unwrap();
    }
}

fn evidence_records(
    store: &Store,
    directory: &Dir,
) -> (
    Dir,
    crate::record::Verified<crate::record::Artifact>,
    crate::record::Verified<crate::record::Finished>,
) {
    let finished = store
        .read_record::<crate::record::Finished>(directory, &name("finished"))
        .unwrap()
        .unwrap();
    let artifacts = store
        .open_dir(directory, &name("artifacts"))
        .unwrap()
        .unwrap();
    let evidence = store
        .open_dir(&artifacts, &name(finished.record().attempt.as_str()))
        .unwrap()
        .unwrap();
    let artifact = store
        .read_record::<crate::record::Artifact>(&evidence, &name("artifact"))
        .unwrap()
        .unwrap();
    (evidence, artifact, finished)
}

/// A finished job with collectible launcher logs beside the verified
/// admission probe the report reads.
fn populated() -> (Case, String) {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let directory = fixture.finish(&job, Some(7));
    launcher_logs(&fixture.store, &directory, b"unreferenced launcher log");
    let id = job.job().id().to_string();
    drop(fixture.store);
    (fixture.case, id)
}

/// Adds a sweepable probe to a state that also holds collectible logs.
fn empty_probe(case: &Case) {
    let store = Store::open(&case.state).unwrap();
    crate::campaign::state_fixture::probe(&store, "probe-empty", 0);
}

#[test]
fn dry_run_and_real_run_plan_the_same_logs_beside_an_empty_probe() {
    let (case, _) = populated();
    empty_probe(&case);
    let before = snapshot(&case.state);
    let dry = collect(&case.state, true).unwrap();
    assert_eq!(snapshot(&case.state), before);
    assert_eq!(dry["held"], json!([]));
    assert_eq!(dry["projected_inodes"], 2 + BULK);
    assert_eq!(dry["probes"]["removed"], json!(["probe-empty"]));
    let real = collect(&case.state, false).unwrap();
    for key in [
        "entries",
        "held",
        "probes",
        "projected_bytes",
        "projected_inodes",
    ] {
        assert_eq!(dry[key], real[key], "{key}");
    }
    assert_eq!(dry["projected_bytes"], real["freed_bytes"]);
    assert_eq!(dry["projected_inodes"], real["freed_inodes"]);
    assert!(!case.state.join("probes/probe-empty").exists());
}

/// The reader outputs collect preserves: `report`, `findings` and `show`
/// without the free bytes and inodes of its `storage`, which a deletion
/// changes.
fn readers(path: &Path) -> Vec<Vec<u8>> {
    let mut shown = crate::campaign::show(path).unwrap();
    let storage = shown["storage"].as_object_mut().unwrap();
    storage.remove("free_bytes");
    storage.remove("free_inodes");
    [
        crate::campaign::report(path).unwrap(),
        crate::campaign::findings(path).unwrap(),
        shown,
    ]
    .iter()
    .map(|value| serde_json::to_vec(value).unwrap())
    .collect()
}

#[test]
fn dry_run_preserves_tree_hash_and_reader_bytes_and_projects_the_census() {
    let (case, id) = populated();
    let before = snapshot(&case.state);
    let hash = crate::record::Digest::of(format!("{before:?}").as_bytes());
    let expected = readers(&case.state);
    let dry = collect(&case.state, true).unwrap();
    assert!(dry["held"].as_array().unwrap().is_empty(), "{dry}");
    assert_eq!(dry["projected_inodes"], 2 + BULK);
    assert_eq!(dry["freed_inodes"], 0);
    assert_eq!(
        hash,
        crate::record::Digest::of(format!("{:?}", snapshot(&case.state)).as_bytes())
    );
    let removed = collect(&case.state, false).unwrap();
    assert_eq!(removed["freed_inodes"], 2 + BULK);
    assert_eq!(removed["freed_bytes"], dry["projected_bytes"]);
    // The census after the pass also counts the `reclaimed` record.
    let marker = fs::metadata(
        case.state
            .join(crate::campaign::state_fixture::attempts_dir(&id))
            .join("0001/reclaimed"),
    )
    .unwrap()
    .len();
    assert_eq!(
        removed["before"]["bytes"].as_u64().unwrap() + marker
            - removed["after"]["bytes"].as_u64().unwrap(),
        removed["freed_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        removed["before"]["inodes"].as_u64().unwrap() + 1
            - removed["after"]["inodes"].as_u64().unwrap(),
        2 + BULK
    );
    assert_eq!(expected, readers(&case.state));
    assert_eq!(collect(&case.state, false).unwrap()["freed_inodes"], 0);
}

/// The `Read` and `Sync` steps one dry run takes beyond opening a view and
/// projecting the report, for `jobs` collectible single-attempt jobs.
fn collection_overhead(jobs: u64) -> [usize; 2] {
    let fixture = Fixture::new();
    fixture.probe();
    for run in 0..jobs {
        let job = fixture.admit(run);
        let directory = fixture.finish(&job, Some(7));
        launcher_logs(&fixture.store, &directory, b"overhead log");
    }
    drop(fixture.store);
    let path = &fixture.case.state;
    let (projected, snapshot) = crate::store::fixture::scripted([], || {
        crate::campaign::report::project(&View::open(path).unwrap())
    });
    assert_eq!(projected.unwrap().unwrap()["held"], json!([]));
    let (dry, collected) = crate::store::fixture::scripted([], || collect(path, true));
    assert_eq!(dry.unwrap().unwrap()["projected_inodes"], (2 + BULK) * jobs);
    [Step::Read, Step::Sync].map(|kind| {
        let count = |trace: &[Step]| trace.iter().filter(|point| **point == kind).count();
        count(&collected) - count(&snapshot)
    })
}

#[test]
fn collection_adds_fixed_record_reads_per_job_and_constant_syncs() {
    // Past the snapshot, each settled job adds only its reclaim's record
    // reads, the same for every job, and no sync.
    let [one, two, three] = [1, 2, 3].map(collection_overhead);
    let reads = ["finished", "captured", "artifact", "manifest", "reclaimed"].len();
    assert_eq!([two[0] - one[0], three[0] - two[0]], [reads, reads]);
    assert_eq!([one[1], two[1]], [three[1], three[1]]);
}

#[test]
fn interruption_at_every_removal_resumes_to_the_uninterrupted_tree() {
    let (case, _) = populated();
    collect(&case.state, false).unwrap();
    let expected = comparable(&case.state);
    // The `reclaimed` record's staging unlink precedes the bulk removals.
    let removals = 1 + 2 + BULK as usize;
    for k in 0..=removals {
        let (case, _) = populated();
        let before = snapshot(&case.state);
        step::install(Some(Script {
            nth: Some((Step::Unlink, k, Outcome::Kill)),
            ..Script::default()
        }));
        let interrupted =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect(&case.state, false)));
        let script = step::install(None).unwrap();
        let reached = script
            .reached
            .iter()
            .filter(|point| **point == Step::Unlink)
            .count();
        if k < removals {
            assert!(interrupted.unwrap_err().is::<step::Killed>());
            assert_eq!(reached, k + 1);
        } else {
            interrupted.unwrap().unwrap();
            assert_eq!(reached, removals);
        }
        collect(&case.state, false).unwrap();
        kept_bytes(&before, &case.state);
        assert_eq!(comparable(&case.state), expected, "removal {k}");
    }
}

#[test]
fn unknown_and_damaged_roots_pin_their_subtrees() {
    for unknown in ["attempt", "calibration", "top", "job"] {
        let (case, id) = populated();
        if unknown != "attempt" {
            empty_probe(&case);
        }
        match unknown {
            "attempt" => fs::write(
                case.state
                    .join(crate::campaign::state_fixture::attempts_dir(&id))
                    .join("0001/operator-state"),
                b"held",
            )
            .unwrap(),
            "calibration" => {
                fs::create_dir(case.state.join("calibrations")).unwrap();
                fs::create_dir(case.state.join("calibrations").join(&id)).unwrap();
                fs::write(
                    case.state.join("calibrations").join(&id).join("plan"),
                    b"damaged",
                )
                .unwrap();
                fs::create_dir(case.state.join("calibrations").join(&id).join("replays")).unwrap();
                fs::write(
                    case.state
                        .join("calibrations")
                        .join(&id)
                        .join("replays/bundle"),
                    b"retain",
                )
                .unwrap();
            }
            "top" => fs::write(case.state.join("operator-state"), b"held").unwrap(),
            "job" => fs::write(
                case.state
                    .join(crate::campaign::state_fixture::job_file(format!(
                        "{id}.json"
                    ))),
                b"damaged",
            )
            .unwrap(),
            _ => unreachable!(),
        }
        let expected = snapshot(&case.state);
        let result = collect(&case.state, false);
        if unknown == "top" {
            let error = result.unwrap_err();
            assert_eq!(error.exit(), crate::exit::Supervisor::Held);
            assert!(error.to_string().contains("record kind is undeclared"));
            assert_eq!(snapshot(&case.state), expected);
            continue;
        }
        let result = result.unwrap();
        assert_eq!(result["freed_inodes"], 0, "{unknown}: {result}");
        assert!(!result["held"].as_array().unwrap().is_empty());
        if unknown == "attempt" {
            assert_eq!(
                result["held"][0]["path"],
                crate::layout::attempt_path(&id, 1).to_str().unwrap()
            );
            assert!(
                result["held"][0]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("unknown attempt entry")
            );
        }
        if unknown != "attempt" {
            assert_eq!(result["probes"]["swept"], true);
            assert_eq!(result["probes"]["removed"], json!(["probe-empty"]));
            let mut expected = expected;
            expected.retain(|path, _| !path.starts_with("probes/probe-empty"));
            assert_eq!(snapshot(&case.state), expected);
        } else {
            assert_eq!(snapshot(&case.state), expected);
        }
    }
}

#[test]
fn dry_run_preserves_staging_orphans_and_requires_both_locks() {
    let (case, _) = populated();
    empty_probe(&case);
    fs::write(case.state.join(".staging/orphan"), b"retain").unwrap();
    let expected = snapshot(&case.state);
    collect(&case.state, true).unwrap();
    assert_eq!(snapshot(&case.state), expected);
    let locked = Store::for_collection(&case.state).unwrap();
    assert!(matches!(
        collect(&case.state, true),
        Err(Error::Store(crate::store::Error::Busy))
    ));
    drop(locked);
    crate::store::create_dir(&case.state.join("hardware")).unwrap();
    let hardware = Store::open(&case.state.join("hardware")).unwrap();
    for dry_run in [true, false] {
        let before = snapshot(&case.state);
        assert!(matches!(
            collect(&case.state, dry_run),
            Err(Error::Store(crate::store::Error::Busy))
        ));
        assert_eq!(snapshot(&case.state), before);
    }
    drop(hardware);
}

#[test]
fn finding_and_calibration_roots_keep_logs_while_the_campaign_control_is_collected() {
    let fixture = Fixture::new();
    fixture.probe();
    let control = fixture.admit(0);
    let control_dir = fixture.finish(&control, Some(7));
    let finding = fixture.admit(1);
    let finding_dir = fixture.finish_at(&finding, 1, Some(7), crate::record::Class::Watchdog);
    let finding_retry = fixture.finish_at(&finding, 2, Some(7), crate::record::Class::Pass);
    let calibration = fixture.admit_purpose(2, Purpose::Calibration);
    let calibration_dir = fixture.finish(&calibration, Some(7));
    for directory in [&control_dir, &finding_dir, &finding_retry, &calibration_dir] {
        launcher_logs(&fixture.store, directory, b"keep rooted logs");
    }
    let control_id = control.job().id().to_string();
    let finding_path = fixture
        .case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(
            finding.job().id().to_string(),
        ));
    let calibration_path = fixture
        .case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(
            calibration.job().id().to_string(),
        ));
    let finding_before = snapshot(&finding_path.join("0001"));
    let calibration_before = snapshot(&calibration_path);
    drop(fixture.store);
    let result = collect(&fixture.case.state, false).unwrap();
    assert_eq!(result["held"], json!([]), "{result}");
    assert_eq!(result["freed_inodes"], 2 * (2 + BULK), "{result}");
    assert_eq!(
        result["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["path"].as_str().unwrap())
            .filter(|path| path.ends_with("launcher.stdout") || path.ends_with("launcher.stderr"))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
        [(&control_id, 1), (&finding.job().id().to_string(), 2)]
            .into_iter()
            .flat_map(
                |(id, number)| crate::custody::LAUNCHER_OUTPUTS.map(|output| {
                    format!(
                        "{}/{output}",
                        crate::layout::attempt_path(id, number).display()
                    )
                })
            )
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(snapshot(&finding_path.join("0001")), finding_before);
    assert_eq!(snapshot(&calibration_path), calibration_before);
}

#[test]
fn charged_or_unreadable_attempts_keep_logs_and_authority_records() {
    let _processes = crate::store::fixture::processes();
    for kind in ["charged", "intent", "symlink", "fifo"] {
        let (case, id) = populated();
        let path = case
            .state
            .join(crate::campaign::state_fixture::attempts_dir(&id))
            .join("0001");
        match kind {
            "charged" => {
                let store = Store::open(&case.state).unwrap();
                let job = crate::layout::attempts(&store, &id).unwrap().unwrap();
                let directory = store.open_dir(&job, &name("0001")).unwrap().unwrap();
                crate::custody::charge(
                    &store,
                    &directory,
                    &crate::record::Text::new(&format!("{id}-0001")).unwrap(),
                )
                .unwrap();
            }
            "intent" => fs::write(path.join("intent"), b"damaged").unwrap(),
            "symlink" => {
                fs::remove_file(path.join(crate::custody::LAUNCHER_STDOUT)).unwrap();
                std::os::unix::fs::symlink(
                    case.state.join(".state"),
                    path.join(crate::custody::LAUNCHER_STDOUT),
                )
                .unwrap();
            }
            "fifo" => {
                fs::remove_file(path.join(crate::custody::LAUNCHER_STDOUT)).unwrap();
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(path.join(crate::custody::LAUNCHER_STDOUT))
                        .output()
                        .unwrap()
                        .status
                        .success()
                );
            }
            _ => unreachable!(),
        }
        let logs = fs::read(path.join(crate::custody::LAUNCHER_STDERR)).unwrap();
        let result = collect(&case.state, false).unwrap();
        assert_eq!(result["freed_inodes"], 0, "{kind}: {result}");
        assert!(
            !result["held"].as_array().unwrap().is_empty(),
            "{kind}: {result}"
        );
        assert_eq!(
            fs::read(path.join(crate::custody::LAUNCHER_STDERR)).unwrap(),
            logs
        );
        assert!(path.join("attempt").exists());
        if kind == "charged" {
            assert!(path.join("reservation").exists());
        }
    }
}

#[test]
fn interruption_after_each_durable_removal_resumes_to_the_same_tree() {
    let (case, _) = populated();
    collect(&case.state, false).unwrap();
    let expected = comparable(&case.state);
    let removals = 2 + BULK;
    for k in 0..removals as usize {
        let (case, _) = populated();
        let before = snapshot(&case.state);
        step::install(Some(Script {
            nth: Some((Step::Removed, k, Outcome::Kill)),
            ..Script::default()
        }));
        let interrupted =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect(&case.state, false)));
        let script = step::install(None).unwrap();
        assert!(interrupted.unwrap_err().is::<step::Killed>());
        assert_eq!(
            script
                .reached
                .iter()
                .filter(|point| **point == Step::Removed)
                .count(),
            k + 1
        );
        let remaining = collect(&case.state, false).unwrap();
        assert_eq!(remaining["freed_inodes"], removals - 1 - k as u64);
        kept_bytes(&before, &case.state);
        assert_eq!(comparable(&case.state), expected);
    }
}

#[test]
fn a_directory_replaced_by_a_symlink_at_unlink_keeps_the_external_tree() {
    let (case, id) = populated();
    let external = Case::new();
    for output in crate::custody::LAUNCHER_OUTPUTS {
        fs::write(external.state.join(output), b"outside evidence").unwrap();
    }
    let expected = snapshot(&external.state);
    let path = case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(&id))
        .join("0001");
    let foreign = external.state.clone();
    let mut unlinks = 0;
    step::install(Some(Script {
        observe: Some(Box::new(move |point| {
            if point == Step::Unlink {
                unlinks += 1;
            }
            if point == Step::Unlink && unlinks == 2 {
                assert!(path.join("reclaimed").is_file());
                fs::rename(&path, path.with_file_name("retained")).unwrap();
                std::os::unix::fs::symlink(&foreign, &path).unwrap();
            }
        })),
        ..Script::default()
    }));
    let result = collect(&case.state, false);
    let script = step::install(None).unwrap();
    assert!(result.is_err());
    assert_eq!(
        script
            .reached
            .iter()
            .filter(|point| **point == Step::Unlink)
            .count(),
        2
    );
    assert_eq!(snapshot(&external.state), expected);
    let repeated = collect(&case.state, false).unwrap();
    assert_eq!(repeated["freed_inodes"], 0);
    assert!(!repeated["held"].as_array().unwrap().is_empty());
    assert_eq!(snapshot(&external.state), expected);
}

#[test]
fn every_collection_sync_failure_exits_held_and_performs_no_later_removal() {
    let (case, _) = populated();
    let (result, trace) = crate::store::fixture::scripted([], || collect(&case.state, false));
    result.unwrap().unwrap();
    let expected = comparable(&case.state);
    let first_removal = trace
        .iter()
        .position(|point| *point == Step::Unlink)
        .unwrap();
    assert_eq!(
        trace[..first_removal]
            .iter()
            .filter(|point| **point == Step::Sync)
            .count(),
        61
    );
    let syncs: Vec<_> = trace
        .iter()
        .enumerate()
        .filter_map(|(index, point)| (*point == Step::Sync).then_some(index))
        .collect();
    assert!(syncs.len() > 2);
    for index in syncs {
        let (case, _) = populated();
        let before = snapshot(&case.state);
        let (result, trace) =
            crate::store::fixture::scripted([(index, Outcome::Errno(libc::EIO))], || {
                collect(&case.state, false)
            });
        let error = result.unwrap().unwrap_err();
        assert_eq!(
            error.exit(),
            crate::exit::Supervisor::Held,
            "sync {index}: {error}"
        );
        assert_eq!(error.held_code(), "store", "sync {index}: {error}");
        assert_eq!(trace[index], Step::Sync);
        assert!(
            !trace[index + 1..].contains(&Step::Unlink),
            "removal after failed sync {index}"
        );
        let rerun = collect(&case.state, false).unwrap();
        assert!(rerun["held"].as_array().unwrap().is_empty());
        assert!(rerun["freed_inodes"].as_u64().unwrap() <= 2 + BULK);
        kept_bytes(&before, &case.state);
        assert_eq!(comparable(&case.state), expected);
    }
}

#[test]
fn collection_constructor_and_writer_refuse_the_same_symlinked_state_paths() {
    let (case, _) = populated();
    let link = case.root.join("link");
    std::os::unix::fs::symlink(&case.state, &link).unwrap();
    let before = snapshot(&case.state);
    for path in [link.clone(), link.join(""), link.join(".")] {
        let writer = Store::open(&path).unwrap_err();
        let collector = Store::for_collection(&path).unwrap_err();
        assert_eq!(writer.exit(), collector.exit());
        assert_eq!(writer.to_string(), collector.to_string());
        assert!(collect(&path, false).is_err());
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn a_tree_past_the_census_bound_collects_unmeasured() {
    let (case, id) = populated();
    empty_probe(&case);
    let extra = case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(id))
        .join("0001/artifacts/census");
    fs::create_dir(&extra).unwrap();
    for index in 0..crate::SCAN_BOUND {
        fs::write(extra.join(index.to_string()), []).unwrap();
    }
    let report = crate::campaign::report(&case.state).unwrap();
    assert_eq!(report["held"].as_array().unwrap().len(), 1);
    assert_eq!(report["held"][0]["path"], "probes/probe-empty");
    // The whole-tree walk passes the scan bound, so collect reports no
    // measurement and still runs its pass, whose listings stay bounded. The
    // unknown `census` entry pins its own attempt.
    let collected = collect(&case.state, false).unwrap();
    assert_eq!(collected["before"], Value::Null);
    assert_eq!(collected["after"], Value::Null);
    assert_eq!(collected["probes"]["removed"], json!(["probe-empty"]));
    assert_eq!(collected["freed_inodes"], 0);
    assert_eq!(
        collected["held"].as_array().unwrap().len(),
        1,
        "{collected}"
    );
    assert_eq!(fs::read_dir(&extra).unwrap().count(), crate::SCAN_BOUND);
}

#[test]
fn dry_run_cli_preserves_collectible_state_and_repeated_flag_is_rejected() {
    let (case, _) = populated();
    let before = snapshot(&case.state);
    let mut args = vec![
        "--state".into(),
        case.state.as_os_str().to_owned(),
        "--dry-run".into(),
    ];
    assert_eq!(
        crate::campaign::run("collect", &args),
        crate::exit::Supervisor::Success
    );
    assert_eq!(snapshot(&case.state), before);
    args.push("--dry-run".into());
    assert_eq!(
        crate::campaign::run("collect", &args),
        crate::exit::Supervisor::Rejected
    );
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn finding_free_retry_logs_are_collected_from_every_numbered_attempt() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let first = fixture.finish_at(&job, 1, Some(7), crate::record::Class::Interrupted);
    let second = fixture.finish_at(&job, 2, Some(7), crate::record::Class::Pass);
    for directory in [&first, &second] {
        launcher_logs(&fixture.store, directory, b"retry log");
    }
    let path = fixture.case.state.clone();
    drop(fixture.store);
    let before = readers(&path);
    let result = collect(&path, false).unwrap();
    assert_eq!(result["held"], json!([]), "{result}");
    assert_eq!(result["freed_inodes"], 2 * (2 + BULK));
    let paths: BTreeSet<_> = result["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["path"].as_str().unwrap().to_owned())
        .collect();
    for number in [1, 2] {
        for output in crate::custody::LAUNCHER_OUTPUTS {
            assert!(paths.contains(&format!(
                "{}/{output}",
                crate::layout::attempt_path(&job.job().id().to_string(), number).display()
            )));
        }
    }
    assert_eq!(before, readers(&path));
    assert_eq!(collect(&path, false).unwrap()["freed_inodes"], 0);
}

#[test]
fn pending_capture_pins_prior_retry_logs_before_and_after_settlement() {
    let fixture = Fixture::new();
    fixture.probe();
    let control = fixture.admit(0);
    let control_dir = fixture.finish(&control, Some(7));
    let failure = fixture.admit(1);
    let first = fixture.finish_at(&failure, 1, Some(7), crate::record::Class::Infrastructure);
    let (second, job, completed) =
        fixture.finish_unsettled(&failure, 2, Some(7), crate::record::Class::Watchdog);
    for directory in [&control_dir, &first, &second] {
        launcher_logs(&fixture.store, directory, b"retry log");
    }
    let path = fixture.case.state.clone();
    let rooted = path.join(crate::campaign::state_fixture::attempts_dir(
        failure.job().id().to_string(),
    ));
    let before = snapshot(&rooted);
    drop(fixture.store);
    let pending = readers(&path);
    let result = collect(&path, false).unwrap();
    assert_eq!(result["held"], json!([]), "{result}");
    assert_eq!(result["freed_inodes"], 2 + BULK);
    assert_eq!(before, snapshot(&rooted));
    assert_eq!(pending, readers(&path));
    let store = Store::open(&path).unwrap();
    crate::attempt::settle(&store, job, completed).unwrap();
    drop(store);
    let settled = snapshot(&rooted);
    assert_eq!(collect(&path, false).unwrap()["freed_inodes"], 0);
    assert_eq!(settled, snapshot(&rooted));
}

#[test]
fn every_host_read_fault_stops_collection_before_any_unlink() {
    for sweepable in [false, true] {
        let fixture = Fixture::new();
        fixture.probe();
        for run in [0, 1] {
            let job = fixture.admit(run);
            let directory = fixture.finish(&job, Some(7));
            launcher_logs(&fixture.store, &directory, b"read fault control");
        }
        fixture
            .store
            .mkdir(fixture.store.root(), &name("calibrations"))
            .unwrap();
        let calibrations = fixture
            .store
            .open_dir(fixture.store.root(), &name("calibrations"))
            .unwrap()
            .unwrap();
        fixture
            .store
            .mkdir(&calibrations, &name(&"a".repeat(64)))
            .unwrap();
        if sweepable {
            crate::campaign::state_fixture::probe(&fixture.store, "probe-empty", 0);
        }
        let path = fixture.case.state.clone();
        drop(fixture.store);
        let before = snapshot(&path);
        let (result, trace) = crate::store::fixture::scripted([], || collect(&path, false));
        assert_eq!(result.unwrap().unwrap()["freed_inodes"], 2 * (2 + BULK));
        // Restores the swept probe, every removed file and drops the reclaim
        // records, so each faulted run starts from the populated tree.
        let after = snapshot(&path);
        if sweepable {
            empty_probe(&fixture.case);
        }
        for (entry, bytes) in &before {
            if let Some(bytes) = bytes
                && !after.contains_key(entry)
            {
                fs::write(path.join(entry), bytes).unwrap();
            }
        }
        for entry in after.keys().filter(|entry| !before.contains_key(*entry)) {
            fs::remove_file(path.join(entry)).unwrap();
        }
        assert_eq!(snapshot(&path), before);
        let first_removal = trace
            .iter()
            .position(|point| *point == Step::Unlink)
            .unwrap();
        let points: Vec<_> = trace[..first_removal]
            .iter()
            .enumerate()
            .filter_map(|(index, point)| {
                matches!(point, Step::List | Step::Open | Step::Read | Step::Stat)
                    .then_some((index, *point))
            })
            .collect();
        assert!(points.iter().any(|(_, point)| *point == Step::List));
        assert!(points.iter().any(|(_, point)| *point == Step::Read));
        for (index, point) in points {
            let (result, trace) =
                crate::store::fixture::scripted([(index, Outcome::Errno(libc::EIO))], || {
                    collect(&path, false)
                });
            let error = result.unwrap().expect_err(&format!("{point:?} {index}"));
            assert_eq!(
                error.exit(),
                crate::exit::Supervisor::Held,
                "{point:?} {index}: {error}"
            );
            assert_eq!(trace[index], point);
            assert!(!trace.contains(&Step::Unlink), "{point:?} {index}");
            assert_eq!(snapshot(&path), before, "{point:?} {index}");
        }
    }
}

#[test]
fn cgroup_lookup_faults_stop_report_and_collect_while_damage_stays_diagnostic() {
    let (case, id) = populated();
    let before = snapshot(&case.state);
    let view = View::open(&case.state).unwrap();
    let probes = view
        .open_dir(view.root(), &name("probes"))
        .unwrap()
        .unwrap();
    let probe = view
        .open_dir(&probes, &name("probe-fixture"))
        .unwrap()
        .unwrap();
    let (released, release_trace) = crate::store::fixture::scripted([], || {
        crate::campaign::probe::released(
            &view,
            &probe,
            &crate::record::Text::new("probe-fixture").unwrap(),
        )
    });
    released.unwrap().unwrap();
    let lookup = release_trace
        .iter()
        .rposition(|point| *point == Step::Open)
        .unwrap();
    let index_in = |trace: &[Step]| {
        trace
            .windows(release_trace.len())
            .position(|window| window == release_trace)
            .unwrap()
            + lookup
    };
    let (result, trace) =
        crate::store::fixture::scripted([], || crate::campaign::report(&case.state));
    result.unwrap().unwrap();
    let index = index_in(&trace);
    let (result, _) = crate::store::fixture::scripted([(index, Outcome::Errno(libc::EIO))], || {
        crate::campaign::report(&case.state)
    });
    let error = result.unwrap().unwrap_err();
    assert!(error.host_fault());
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    let (result, trace) = crate::store::fixture::scripted([], || collect(&case.state, true));
    result.unwrap().unwrap();
    let index = index_in(&trace);
    let (result, trace) =
        crate::store::fixture::scripted([(index, Outcome::Errno(libc::EIO))], || {
            collect(&case.state, false)
        });
    assert_eq!(
        result.unwrap().unwrap_err().exit(),
        crate::exit::Supervisor::Held
    );
    assert!(!trace.contains(&Step::Unlink));
    assert_eq!(snapshot(&case.state), before);
    fs::write(
        case.state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{id}.json"
            ))),
        b"damaged",
    )
    .unwrap();
    let report = crate::campaign::report(&case.state).unwrap();
    assert!(
        report["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == format!("jobs/{id}"))
    );
    assert_eq!(
        crate::campaign::run(
            "report",
            &["--state".into(), case.state.as_os_str().to_owned()]
        ),
        crate::exit::Supervisor::Success
    );
}

#[test]
fn queued_target_holds_preserve_their_scope_beside_collectible_jobs() {
    for state in [
        "absent",
        "empty",
        "minted",
        "pin",
        "result",
        "damaged-result",
    ] {
        let fixture = Fixture::new();
        fixture.probe();
        let healthy = fixture.admit(0);
        let directory = fixture.finish(&healthy, Some(7));
        launcher_logs(&fixture.store, &directory, b"healthy log");
        let target = fixture.targeted(1);
        let path = fixture.case.state.clone();
        let id = target.job().id().to_string();
        if matches!(state, "empty" | "minted") {
            let attempts =
                crate::layout::make_shard(&fixture.store, crate::layout::ATTEMPTS, &id).unwrap();
            fixture.store.mkdir(&attempts, &name(&id)).unwrap();
            if state == "minted" {
                let root = fixture
                    .store
                    .open_dir(&attempts, &name(&id))
                    .unwrap()
                    .unwrap();
                fixture.store.mkdir(&root, &name("0001")).unwrap();
            }
        }
        let jobs = fixture
            .store
            .shard_jobs(healthy.job().id())
            .unwrap()
            .unwrap();
        let target_jobs = fixture.store.shard_jobs(&id).unwrap().unwrap();
        if matches!(state, "pin" | "result") {
            let mut result = fixture
                .store
                .read_record::<crate::record::JobResult>(
                    &jobs,
                    &name(&format!(
                        "{}{}",
                        healthy.job().id(),
                        crate::record::JobResult::SUFFIX
                    )),
                )
                .unwrap()
                .unwrap()
                .record()
                .clone();
            result.job = target.job().id().digest();
            result.manifest = target.job().manifest_sha256();
            result.finished.attempt = crate::record::Text::new(&format!("{id}-0001")).unwrap();
            if state == "pin" {
                fixture
                    .store
                    .create_record(
                        &target_jobs,
                        &name(&format!("{id}{}", crate::record::Pin::SUFFIX)),
                        &crate::record::Pin { result },
                    )
                    .unwrap();
            } else {
                fixture
                    .store
                    .create_record(
                        &target_jobs,
                        &name(&format!("{id}{}", crate::record::JobResult::SUFFIX)),
                        &result,
                    )
                    .unwrap();
            }
        }
        if state == "damaged-result" {
            fixture
                .store
                .create_once(
                    &target_jobs,
                    &name(&format!("{id}{}", crate::record::JobResult::SUFFIX)),
                    b"damaged",
                )
                .unwrap();
        }
        let bundle = path.join(crate::campaign::state_fixture::job_file(format!(
            "{id}.bundle"
        )));
        fs::write(&bundle, b"damaged frozen target").unwrap();
        drop(fixture.store);
        let before = readers(&path);
        let tree = snapshot(&path);
        let result = collect(&path, false).unwrap();
        let local = matches!(state, "absent" | "empty");
        assert_eq!(
            result["freed_inodes"],
            if local { 2 + BULK } else { 0 },
            "{state}: {result}"
        );
        if !local {
            assert_eq!(tree, snapshot(&path), "{state}");
        }
        assert!(
            result["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["path"] == format!("jobs/{id}"))
        );
        assert_eq!(fs::read(&bundle).unwrap(), b"damaged frozen target");
        assert_eq!(before, readers(&path));
    }
}

#[test]
fn structural_store_holds_keep_their_reason_beside_an_earlier_local_hold() {
    use std::os::unix::ffi::OsStringExt;
    let (case, _) = populated();
    fs::write(case.state.join("operator-state"), b"held").unwrap();
    let hardware = case.state.join("hardware");
    crate::store::create_dir(&hardware).unwrap();
    let store = Store::open(&hardware).unwrap();
    store.mkdir(store.root(), &name("runs")).unwrap();
    drop(store);
    fs::create_dir(
        hardware
            .join("runs")
            .join(std::ffi::OsString::from_vec(vec![0xff])),
    )
    .unwrap();
    let before = snapshot(&case.state);
    let report = crate::campaign::report(&case.state).unwrap();
    let held = report["held"].as_array().unwrap();
    assert_eq!(held[0]["path"], "operator-state");
    assert!(held.iter().any(|row| row["held_code"] == "store"));
    let (result, trace) = crate::store::fixture::scripted([], || collect(&case.state, false));
    let error = result.unwrap().unwrap_err();
    assert!(matches!(error, Error::Held(_)));
    assert!(error.to_string().contains("hardware/runs"));
    assert!(error.to_string().contains("foreign entry"));
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(!trace.contains(&Step::Unlink));
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn unfinished_attempt_keeps_prior_job_logs_beside_a_collectible_control() {
    let fixture = Fixture::new();
    fixture.probe();
    let control = fixture.admit(0);
    let control_dir = fixture.finish(&control, Some(7));
    let job = fixture.admit(1);
    let first = fixture.finish_at(&job, 1, Some(7), crate::record::Class::Interrupted);
    let (second, _, _) = fixture.finish_unsettled(&job, 2, Some(7), crate::record::Class::Pass);
    fixture.store.delete(&second, &name("finished")).unwrap();
    for directory in [&control_dir, &first, &second] {
        launcher_logs(&fixture.store, directory, b"retained job log");
    }
    let path = fixture.case.state.clone();
    let root = path.join(crate::campaign::state_fixture::attempts_dir(
        job.job().id().to_string(),
    ));
    let expected = snapshot(&root);
    drop(fixture.store);
    let before = readers(&path);
    let result = collect(&path, false).unwrap();
    assert_eq!(result["held"], json!([]), "{result}");
    assert_eq!(result["freed_inodes"], 2 + BULK);
    assert_eq!(snapshot(&root), expected);
    assert_eq!(readers(&path), before);
    assert_eq!(collect(&path, false).unwrap()["freed_inodes"], 0);
    assert_eq!(snapshot(&root), expected);
}

#[test]
fn held_attempt_pins_its_subtree_while_prior_retry_logs_are_collectible() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let first = fixture.finish_at(&job, 1, Some(7), crate::record::Class::Interrupted);
    let second = fixture.finish_at(&job, 2, Some(7), crate::record::Class::Pass);
    for directory in [&first, &second] {
        launcher_logs(&fixture.store, directory, b"retry log");
    }
    fixture
        .store
        .create_once(&second, &name("operator-state"), b"held")
        .unwrap();
    let path = fixture.case.state.clone();
    let held_path = path
        .join(crate::campaign::state_fixture::attempts_dir(
            job.job().id().to_string(),
        ))
        .join("0002");
    let expected = snapshot(&held_path);
    drop(fixture.store);
    let before = readers(&path);
    let result = collect(&path, false).unwrap();
    assert_eq!(result["freed_inodes"], 2 + BULK);
    assert_eq!(result["held"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot(&held_path), expected);
    assert_eq!(before, readers(&path));
    assert_eq!(collect(&path, false).unwrap()["freed_inodes"], 0);
}

#[test]
fn hardware_record_read_faults_stop_report_and_collect_before_removal() {
    let (case, _) = populated();
    empty_probe(&case);
    let hardware = case.state.join("hardware");
    crate::store::create_dir(&hardware).unwrap();
    let store = Store::open(&hardware).unwrap();
    store.mkdir(store.root(), &name("runs")).unwrap();
    let runs = store
        .open_dir(store.root(), &name("runs"))
        .unwrap()
        .unwrap();
    store.mkdir(&runs, &name("0001")).unwrap();
    let directory = store.open_dir(&runs, &name("0001")).unwrap().unwrap();
    let text = |value: &str| crate::record::Text::new(value).unwrap();
    store
        .create_record(
            &directory,
            &name("finished"),
            &crate::record::Hardware {
                argv: vec![text("fake-controller")],
                class: Some(crate::record::HardwareClass::Gated),
                custody_directory: None,
                directory: text(hardware.to_str().unwrap()),
                exit: Some(0),
                kind: crate::record::HardwareKind::Sweep,
                number: 1,
                phase: crate::record::HardwarePhase::Finished,
                platform: text("x86_64-linux"),
                profile: text("read"),
                reason: text("gated"),
                signal: None,
                stopped: false,
            },
        )
        .unwrap();
    store
        .create_record(
            &directory,
            &name("disposition"),
            &crate::record::HardwareDisposition::new(1, text("operator evidence")).unwrap(),
        )
        .unwrap();
    drop(store);
    let before = snapshot(&case.state);
    let (opened, opening) = crate::store::fixture::scripted([], || View::snapshot(&hardware));
    drop(opened.unwrap().unwrap());
    let opening = opening.iter().filter(|point| **point == Step::Read).count();
    let view = View::open(&case.state).unwrap();
    let (result, hardware_trace) =
        crate::store::fixture::scripted([], || crate::hardware::rows(&view, &mut Vec::new()));
    let (_, rows) = result.unwrap().unwrap();
    assert_eq!(rows[0]["class"], "gated");
    assert_eq!(rows[0]["disposed"], true);
    let reads: Vec<_> = hardware_trace
        .iter()
        .enumerate()
        .filter_map(|(index, point)| (*point == Step::Read).then_some(index))
        .collect();
    assert_eq!(reads.len(), opening + 3);
    let index_in = |trace: &[Step], read| {
        trace
            .windows(hardware_trace.len())
            .position(|window| window == hardware_trace)
            .unwrap()
            + read
    };
    for read in &reads[opening..] {
        let (result, trace) =
            crate::store::fixture::scripted([], || crate::campaign::report(&case.state));
        result.unwrap().unwrap();
        let index = index_in(&trace, *read);
        let (result, trace) =
            crate::store::fixture::scripted([(index, Outcome::Errno(libc::EIO))], || {
                crate::campaign::report(&case.state)
            });
        let error = result.unwrap().unwrap_err();
        assert!(error.host_fault());
        assert_eq!(error.exit(), crate::exit::Supervisor::Held);
        assert_eq!(trace[index], Step::Read);
        let (result, trace) = crate::store::fixture::scripted([], || collect(&case.state, true));
        result.unwrap().unwrap();
        let index = index_in(&trace, *read);
        let (result, trace) =
            crate::store::fixture::scripted([(index, Outcome::Errno(libc::EIO))], || {
                collect(&case.state, false)
            });
        assert_eq!(
            result.unwrap().unwrap_err().exit(),
            crate::exit::Supervisor::Held
        );
        assert_eq!(trace[index], Step::Read);
        assert!(!trace.contains(&Step::Unlink));
        assert_eq!(snapshot(&case.state), before);
    }
    assert_eq!(
        collect(&case.state, false).unwrap()["freed_inodes"],
        2 + BULK
    );
    let (result, trace) =
        crate::store::fixture::scripted([], || crate::campaign::report(&case.state));
    result.unwrap().unwrap();
    let move_at = index_in(&trace, *reads.last().unwrap());
    let moved = case.state.join("moved-hardware");
    let mut index = 0;
    step::install(Some(Script {
        observe: Some(Box::new(move |_| {
            if index == move_at {
                fs::rename(&hardware, &moved).unwrap();
            }
            index += 1;
        })),
        ..Script::default()
    }));
    let result = crate::campaign::report(&case.state);
    step::install(None);
    let error = result.unwrap_err();
    assert!(matches!(error, Error::Store(crate::store::Error::Replaced)));
    assert_eq!(error.held_code(), "store");
}

#[test]
fn snapshot_barrier_failure_stays_visible_after_a_later_successful_barrier() {
    let (case, _) = populated();
    let view = View::open(&case.state).unwrap();
    let jobs = crate::layout::shards(&view, crate::layout::JOBS)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .dir;
    let entry = view
        .list(&jobs, crate::SCAN_BOUND)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let read = view
        .read(&jobs, &entry, crate::record::BOUND)
        .unwrap()
        .unwrap();
    assert!(view.barriers_succeeded());
    step::install(Some(Script {
        nth: Some((Step::Sync, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    }));
    assert!(view.barrier(&read).is_err());
    step::install(None);
    assert!(view.barrier(&read).is_err());
    fs::write(case.state.join("other"), b"independent inode").unwrap();
    let other = view
        .read(view.root(), &name("other"), crate::record::BOUND)
        .unwrap()
        .unwrap();
    view.barrier(&other).unwrap();
    assert!(!view.barriers_succeeded());
}

#[test]
fn released_failure_waiting_for_capture_remains_rooted_beside_a_collectible_control() {
    let fixture = Fixture::new();
    fixture.probe();
    let control = fixture.admit(0);
    let control_dir = fixture.finish(&control, Some(7));
    let failure = fixture.admit(1);
    let (failure_dir, job, completed) =
        fixture.finish_unsettled(&failure, 1, Some(7), crate::record::Class::Watchdog);
    assert!(completed.has_finding());
    assert!(!fixture.case.state.join("findings").exists());
    for directory in [&control_dir, &failure_dir] {
        launcher_logs(&fixture.store, directory, b"rooted pending failure");
    }
    let failure_path = fixture
        .case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(
            failure.job().id().to_string(),
        ));
    let expected = snapshot(&failure_path);
    let path = fixture.case.state.clone();
    drop(fixture.store);
    let pending = crate::campaign::findings(&path).unwrap();
    assert!(!pending["findings"].as_array().unwrap().is_empty());
    let result = collect(&path, false).unwrap();
    assert_eq!(result["held"], json!([]), "{result}");
    assert_eq!(result["freed_inodes"], 2 + BULK);
    assert_eq!(snapshot(&failure_path), expected);
    assert_eq!(crate::campaign::findings(&path).unwrap(), pending);
    let store = Store::open(&path).unwrap();
    crate::attempt::settle(&store, job, completed).unwrap();
    drop(store);
    assert_eq!(collect(&path, false).unwrap()["freed_inodes"], 0);
    assert!(failure_path.join("0001/launcher.stdout").exists());
}

#[test]
fn hardware_barrier_failure_survives_a_later_run_lookup_failure_and_blocks_deletion() {
    let (case, _) = populated();
    empty_probe(&case);
    let hardware = case.state.join("hardware");
    crate::store::create_dir(&hardware).unwrap();
    let store = Store::open(&hardware).unwrap();
    store.mkdir(store.root(), &name("runs")).unwrap();
    let runs = store
        .open_dir(store.root(), &name("runs"))
        .unwrap()
        .unwrap();
    for number in 1..=2 {
        store.mkdir(&runs, &name(&format!("{number:04}"))).unwrap();
        let directory = store
            .open_dir(&runs, &name(&format!("{number:04}")))
            .unwrap()
            .unwrap();
        let text = |value: &str| crate::record::Text::new(value).unwrap();
        store
            .create_record(
                &directory,
                &name("finished"),
                &crate::record::Hardware {
                    argv: vec![text("fake-controller")],
                    class: Some(crate::record::HardwareClass::Gated),
                    custody_directory: None,
                    directory: text(hardware.to_str().unwrap()),
                    exit: Some(0),
                    kind: crate::record::HardwareKind::Sweep,
                    number,
                    phase: crate::record::HardwarePhase::Finished,
                    platform: text("x86_64-linux"),
                    profile: text("read"),
                    reason: text("gated"),
                    signal: None,
                    stopped: false,
                },
            )
            .unwrap();
    }
    drop(store);
    let fault = |first_sync| {
        let moved = hardware.join("runs/0002");
        let retained = hardware.join("retained");
        let mut syncs = 0;
        let mut opens = 0;
        Script {
            nth: Some((Step::Sync, first_sync, Outcome::Errno(libc::EIO))),
            observe: Some(Box::new(move |point| {
                if point == Step::Sync {
                    syncs += 1;
                }
                if syncs == first_sync + 1 && point == Step::Open {
                    opens += 1;
                    if opens == 2 {
                        fs::rename(&moved, &retained).unwrap();
                    }
                }
            })),
            ..Script::default()
        }
    };
    let parent = View::open(&case.state).unwrap();
    step::install(Some(fault(0)));
    let mut held = Vec::new();
    let (locked, rows) = crate::hardware::rows(&parent, &mut held).unwrap();
    step::install(None);
    assert!(!locked.as_ref().unwrap().barriers_succeeded());
    assert!(rows.iter().any(|row| {
        row["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("hardware directory vanished"))
    }));
    drop(locked);
    fs::rename(hardware.join("retained"), hardware.join("runs/0002")).unwrap();
    step::install(Some(fault(2)));
    let result = collect(&case.state, false);
    let trace = step::install(None).unwrap().reached;
    assert_eq!(result.unwrap_err().exit(), crate::exit::Supervisor::Held);
    assert!(hardware.join("retained/finished").is_file());
    assert!(!trace.contains(&Step::Unlink));
}

#[test]
fn collection_depth_hold_preserves_all_entries() {
    let (case, id) = populated();
    empty_probe(&case);
    let mut deep = case
        .state
        .join(crate::campaign::state_fixture::attempts_dir(id))
        .join("0001/artifacts/deep");
    for _ in 0..64 {
        deep.push("d");
    }
    fs::create_dir_all(deep).unwrap();
    let before = snapshot(&case.state);
    let (result, trace) = crate::store::fixture::scripted([], || collect(&case.state, false));
    let error = result.unwrap().unwrap_err();
    assert_eq!(
        error.to_string(),
        "a census found a directory nested 64 levels deep"
    );
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(!trace.contains(&Step::Unlink));
    assert_eq!(snapshot(&case.state), before);
}

/// A settled passing attempt loses exactly the bulk its artifact record
/// names and its launcher logs, its `reclaimed` record written first; its
/// records stay, and `report`, `findings`, `show` and `status` read the same
/// bytes before and after. A dry run lists the attempt and writes nothing.
#[test]
fn a_settled_pass_loses_exactly_its_bulk_and_keeps_its_records() {
    let (case, id) = populated();
    let attempt = crate::layout::attempt_path(&id, 1);
    let evidence = attempt.join("artifacts").join(format!("{id}-0001"));
    let before = snapshot(&case.state);
    let read_before = readers(&case.state);
    let status_before = crate::campaign::status_tests::status(&case.state).unwrap()["jobs"].clone();
    let dry = collect(&case.state, true).unwrap();
    assert_eq!(dry["reclaimed"], json!([attempt.to_str().unwrap()]));
    assert_eq!(snapshot(&case.state), before);
    let done = collect(&case.state, false).unwrap();
    assert_eq!(done["reclaimed"], dry["reclaimed"]);
    let after = snapshot(&case.state);
    let removed: BTreeSet<_> = before
        .keys()
        .filter(|entry| !after.contains_key(*entry))
        .cloned()
        .collect();
    let bulk = ["bundle", "run.stdout", "run.stderr", "inspect.stderr"];
    let expected: BTreeSet<_> = bulk
        .iter()
        .map(|entry| evidence.join(entry))
        .chain(crate::custody::LAUNCHER_OUTPUTS.map(|output| attempt.join(output)))
        .collect();
    assert_eq!(removed, expected);
    let added: Vec<_> = after
        .keys()
        .filter(|entry| !before.contains_key(*entry))
        .cloned()
        .collect();
    assert_eq!(added, [attempt.join("reclaimed")]);
    for (entry, bytes) in &before {
        if let Some(kept) = after.get(entry) {
            assert_eq!(kept, bytes, "{}", entry.display());
        }
    }
    let store = Store::open(&case.state).unwrap();
    let directory = crate::layout::attempts(&store, &id).unwrap().unwrap();
    let directory = store.open_dir(&directory, &name("0001")).unwrap().unwrap();
    let marker = store
        .read_record::<crate::record::Reclaimed>(&directory, &name("reclaimed"))
        .unwrap()
        .unwrap();
    let finished = store
        .read_record::<crate::record::Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap();
    assert_eq!(marker.record().attempt, 1);
    assert_eq!(
        marker.record().finished,
        crate::record::Digest::of(finished.read().bytes())
    );
    let names: BTreeSet<_> = marker
        .record()
        .names
        .iter()
        .map(|entry| attempt.join(entry.as_str()))
        .collect();
    assert_eq!(names, expected);
    drop(store);
    assert_eq!(readers(&case.state), read_before);
    assert_eq!(
        crate::campaign::status_tests::status(&case.state).unwrap()["jobs"],
        status_before
    );
    let again = collect(&case.state, false).unwrap();
    assert_eq!(again["freed_inodes"], 0);
    assert_eq!(again["reclaimed"], json!([]));
    // Readers take the outcome from the records: damaged bytes under a
    // reclaimed bulk name change no output.
    fs::write(case.state.join(evidence.join("bundle")), b"damaged").unwrap();
    assert_eq!(readers(&case.state), read_before);
}

/// The reclaim keeps an attempt a finding or triage step names, one whose
/// binding is not matching, and the attempt the job's pin names, and it
/// holds an attempt whose artifact record is missing, which keeps and
/// reports it.
#[test]
fn reclaim_keeps_named_unbound_and_pinned_attempts_and_holds_a_missing_artifact() {
    for case_kind in ["findings", "triage", "unbound", "pinned", "missing"] {
        let (case, id) = populated();
        let attempt_id = format!("{id}-0001");
        let view = View::open(&case.state).unwrap();
        let projected = super::super::report::snapshot(&view).unwrap();
        let history = &projected.histories[&id];
        let store = Store::open(&case.state).unwrap();
        let attempts = crate::layout::attempts(&store, &id).unwrap().unwrap();
        let directory = store.open_dir(&attempts, &name("0001")).unwrap().unwrap();
        let root = crate::layout::attempts(&view, &id).unwrap().unwrap();
        let path = crate::layout::attempt_path(&id, 1).display().to_string();
        let planned_unit = unit(&view, &root, &id, 1, &history.attempts[0], &path)
            .unwrap()
            .unwrap();
        assert_eq!(planned_unit.logs.len(), 2);
        match case_kind {
            "findings" | "triage" => {
                store.mkdir(store.root(), &name(case_kind)).unwrap();
                let root = store
                    .open_dir(store.root(), &name(case_kind))
                    .unwrap()
                    .unwrap();
                store.mkdir(&root, &name(&attempt_id)).unwrap();
            }
            "unbound" => {
                let mut finished = store
                    .read_record::<crate::record::Finished>(&directory, &name("finished"))
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                finished.binding = crate::record::Binding::Missing;
                store
                    .replace_record(&directory, &name("finished"), &finished)
                    .unwrap();
            }
            "pinned" => {
                let jobs = store.shard_jobs(&id).unwrap().unwrap();
                let result = store
                    .read_record::<crate::record::JobResult>(
                        &jobs,
                        &name(&format!("{id}{}", crate::record::JobResult::SUFFIX)),
                    )
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                store
                    .create_record(
                        &jobs,
                        &name(&format!("{id}{}", crate::record::Pin::SUFFIX)),
                        &crate::record::Pin { result },
                    )
                    .unwrap();
            }
            _ => {
                fs::remove_file(
                    case.state
                        .join(crate::layout::attempt_path(&id, 1))
                        .join("artifacts")
                        .join(&attempt_id)
                        .join("artifact"),
                )
                .unwrap();
            }
        }
        drop(store);
        // Collect leaves the attempt untouched and reclaims nothing.
        let attempt = case.state.join(crate::layout::attempt_path(&id, 1));
        let before = snapshot(&attempt);
        let collected = collect(&case.state, false).unwrap();
        assert_eq!(
            collected["reclaimed"],
            json!([]),
            "{case_kind}: {collected}"
        );
        assert_eq!(snapshot(&attempt), before, "{case_kind}");
        let settled = settled(&view, &id).unwrap();
        if case_kind == "pinned" {
            assert_eq!(settled, Some(Some(1)), "{case_kind}");
            let mut plans = Vec::new();
            let mut held = Vec::new();
            mark(
                &view,
                &projected.projection,
                &projected.histories,
                &BTreeSet::new(),
                &mut plans,
                &mut held,
            )
            .unwrap();
            assert!(plans.is_empty());
            assert!(held.is_empty());
            assert!(!collected["held"].as_array().unwrap().is_empty());
            continue;
        }
        assert_eq!(settled, Some(None), "{case_kind}");
        if case_kind == "unbound" {
            assert!(
                unit(&view, &root, &id, 1, &history.attempts[0], &path)
                    .unwrap()
                    .is_none()
            );
            continue;
        }
        let planned = reclaim(&view, planned_unit, &id, 1, &path);
        match case_kind {
            "missing" => assert_eq!(
                planned.err().unwrap().to_string(),
                "attempt lacks its artifact record",
                "{case_kind}"
            ),
            _ => assert!(
                matches!(planned, Ok((None, ref files)) if files.is_empty()),
                "{case_kind}"
            ),
        }
    }
}

/// A reader of a reclaimed attempt holds when its `reclaimed` record names
/// another attempt or finish, or its kept artifact record is replaced or
/// gone, so a reclaimed attempt is read only through records that bind it.
#[test]
fn readers_hold_a_reclaimed_attempt_whose_records_no_longer_bind_it() {
    for (damage, reason) in [
        ("attempt", "reclaim record names another finish"),
        ("finished", "reclaim record names another finish"),
        ("replaced", "reclaimed artifact record differs"),
        ("removed", "reclaimed attempt lacks its artifact record"),
        ("marker-raw", "the record is no JSON"),
        ("artifacts-file", "reclaimed artifact record unreadable"),
        ("unbound-finish", "reclaimed attempt lacks bound evidence"),
        ("manifest-removed", "reclaimed manifest missing"),
        ("manifest-replaced", "reclaimed manifest differs"),
        ("manifest-directory", "reclaimed manifest unreadable"),
    ] {
        let (case, id) = populated();
        collect(&case.state, false).unwrap();
        let store = Store::open(&case.state).unwrap();
        let attempts = crate::layout::attempts(&store, &id).unwrap().unwrap();
        let directory = store.open_dir(&attempts, &name("0001")).unwrap().unwrap();
        let mut marker = store
            .read_record::<crate::record::Reclaimed>(&directory, &name("reclaimed"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        let artifact = case
            .state
            .join(crate::layout::attempt_path(&id, 1))
            .join("artifacts")
            .join(format!("{id}-0001"))
            .join("artifact");
        match damage {
            "marker-raw" => {
                store
                    .replace(&directory, &name("reclaimed"), b"raw")
                    .unwrap();
            }
            "artifacts-file" => {
                let artifacts = artifact.parent().unwrap().parent().unwrap();
                fs::remove_dir_all(artifacts).unwrap();
                fs::write(artifacts, b"file").unwrap();
            }
            "unbound-finish" => {
                let mut finish = store
                    .read_record::<crate::record::Finished>(&directory, &name("finished"))
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                finish.bound = None;
                store
                    .replace_record(&directory, &name("finished"), &finish)
                    .unwrap();
                marker.finished = crate::record::Digest::of(
                    store
                        .read_record::<crate::record::Finished>(&directory, &name("finished"))
                        .unwrap()
                        .unwrap()
                        .read()
                        .bytes(),
                );
            }
            "manifest-removed" => fs::remove_file(artifact.with_file_name("manifest")).unwrap(),
            "manifest-replaced" => {
                fs::write(artifact.with_file_name("manifest"), b"replaced").unwrap()
            }
            "manifest-directory" => {
                let manifest = artifact.with_file_name("manifest");
                fs::remove_file(&manifest).unwrap();
                fs::create_dir(manifest).unwrap();
            }
            "attempt" => marker.attempt = 2,
            "finished" => marker.finished = crate::record::Digest::of(b"another finish"),
            "replaced" => {
                let (evidence, artifact, _) = evidence_records(&store, &directory);
                let mut record = artifact.record().clone();
                record.reason = crate::record::Text::new("replaced").unwrap();
                store
                    .replace_record(&evidence, &name("artifact"), &record)
                    .unwrap();
            }
            _ => fs::remove_file(&artifact).unwrap(),
        }
        if matches!(damage, "attempt" | "finished" | "unbound-finish") {
            store
                .replace_record(&directory, &name("reclaimed"), &marker)
                .unwrap();
        }
        drop(store);
        let report = crate::campaign::report(&case.state).unwrap();
        assert!(
            report["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["reason"].as_str().unwrap().contains(reason)),
            "{damage}: {report}"
        );
    }
}

#[test]
fn readers_hold_a_reclaimed_artifact_that_names_another_attempt_under_matching_digests() {
    for (damage, reason) in [
        ("run-id", "reclaimed artifact binding differs"),
        ("run-id-path", "reclaimed artifact binding differs"),
        ("command", "reclaimed artifact binding differs"),
        ("manifest", "reclaimed artifact binding differs"),
        ("archive", "reclaimed artifact binding differs"),
        (
            "bound-attempt",
            "stored outcome differs from bound evidence",
        ),
        ("bound-bundle", "stored outcome differs from bound evidence"),
    ] {
        let (case, id) = populated();
        collect(&case.state, false).unwrap();
        let store = Store::open(&case.state).unwrap();
        let attempts = crate::layout::attempts(&store, &id).unwrap().unwrap();
        let directory = store.open_dir(&attempts, &name("0001")).unwrap().unwrap();
        let (evidence, artifact, finished) = evidence_records(&store, &directory);
        let mut artifact = artifact.record().clone();
        let mut finish = finished.record().clone();
        let text = |value| crate::record::Text::new(value).unwrap();
        match damage {
            "run-id" => artifact.run_id = text("other-0001"),
            "run-id-path" => artifact.run_id = text("a/b"),
            "command" => artifact.command = text("inspect"),
            "manifest" => {
                artifact.manifest = Some(crate::record::Digest::of(b"another manifest"));
                store
                    .replace(&evidence, &name("manifest"), b"another manifest")
                    .unwrap();
            }
            "archive" => artifact.archive = Some(crate::record::Digest::of(b"another build")),
            "bound-attempt" => finish.bound.as_mut().unwrap().attempt = text("other-0001"),
            _ => finish.bound.as_mut().unwrap().bundle = None,
        }
        store
            .replace_record(&evidence, &name("artifact"), &artifact)
            .unwrap();
        let (_, artifact, _) = evidence_records(&store, &directory);
        finish.bound.as_mut().unwrap().artifact =
            crate::record::Digest::of(artifact.read().bytes());
        store
            .replace_record(&directory, &name("finished"), &finish)
            .unwrap();
        store
            .replace_record(&directory, &name("bound"), finish.bound.as_ref().unwrap())
            .unwrap();
        let (_, _, finished) = evidence_records(&store, &directory);
        let digest = crate::record::Digest::of(finished.read().bytes());
        let mut marker = store
            .read_record::<crate::record::Reclaimed>(&directory, &name("reclaimed"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        marker.finished = digest;
        store
            .replace_record(&directory, &name("reclaimed"), &marker)
            .unwrap();
        let mut captured = store
            .read_record::<crate::record::Captured>(&directory, &name("captured"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        captured.finished = digest;
        store
            .replace_record(&directory, &name("captured"), &captured)
            .unwrap();
        let jobs = crate::layout::jobs(&store, &id).unwrap().unwrap();
        let result_name = name(&format!("{id}{}", crate::record::JobResult::SUFFIX));
        let mut result = store
            .read_record::<crate::record::JobResult>(&jobs, &result_name)
            .unwrap()
            .unwrap()
            .record()
            .clone();
        result.finished = finish;
        store.replace_record(&jobs, &result_name, &result).unwrap();
        drop(store);
        let report = crate::campaign::report(&case.state).unwrap();
        assert!(
            report["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["reason"].as_str().unwrap().contains(reason)),
            "{damage}: {report}"
        );
    }
}

/// A kill at every step of one pass, the `reclaimed` record's publication
/// included, then a rerun, gives the tree of one uninterrupted pass.
#[test]
fn a_kill_at_every_step_of_a_reclaim_then_a_rerun_equals_one_pass() {
    let (case, _) = populated();
    let (result, trace) = crate::store::fixture::scripted([], || collect(&case.state, false));
    result.unwrap().unwrap();
    let expected = comparable(&case.state);
    let first = trace
        .iter()
        .position(|point| matches!(point, Step::Write | Step::Rename))
        .unwrap();
    for index in first..trace.len() {
        let (case, _) = populated();
        let before = snapshot(&case.state);
        let (result, reached) = crate::store::fixture::scripted([(index, Outcome::Kill)], || {
            collect(&case.state, false)
        });
        assert!(result.is_none(), "kill at step {index}");
        assert_eq!(reached, trace[..=index], "kill at step {index}");
        collect(&case.state, false).unwrap();
        kept_bytes(&before, &case.state);
        assert_eq!(comparable(&case.state), expected, "kill at step {index}");
    }
}

/// The most entries any directory under `path` lists, `path` included,
/// and the entries of the whole tree.
fn listings(path: &Path) -> (usize, usize) {
    let entries: Vec<_> = fs::read_dir(path).unwrap().flatten().collect();
    entries
        .iter()
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .map(|entry| listings(&entry.path()))
        .fold(
            (entries.len(), entries.len()),
            |(widest, total), (child, under)| (widest.max(child), total + under),
        )
}

/// Builds about 2,000 entries of settled jobs through the store.
fn horizon() -> (Case, BTreeSet<std::path::PathBuf>) {
    let fixture = Fixture::new();
    let mut removable = BTreeSet::new();
    fixture.probe();
    for run in 0..110 {
        let job = fixture.admit(run);
        let directory = fixture.finish(&job, Some(7));
        let id = job.job().id().to_string();
        let path = crate::layout::attempt_path(&id, 1);
        for file in ["launcher.stdout", "launcher.stderr"] {
            removable.insert(path.join(file));
        }
        for file in ["bundle", "run.stdout", "run.stderr", "inspect.stderr"] {
            removable.insert(path.join("artifacts").join(format!("{id}-0001")).join(file));
        }
        for output in crate::custody::LAUNCHER_OUTPUTS {
            fixture
                .store
                .create_once(&directory, &name(output), b"horizon log")
                .unwrap();
        }
    }
    for index in 0..3 {
        crate::campaign::state_fixture::released_probe(
            &fixture.store,
            &format!("probe-horizon-{index}"),
            "/sys/fs/cgroup/campaign-released-probe",
        );
    }
    let failure = fixture.admit(110);
    fixture.finish_at(&failure, 1, Some(7), crate::record::Class::Watchdog);
    let unsettled = fixture.admit(111);
    fixture.finish_unsettled(&unsettled, 1, Some(7), crate::record::Class::Interrupted);
    drop(fixture.store);
    (fixture.case, removable)
}

/// Runs `op` under the scan bound `bound` with the outcomes `at` names,
/// returning its value, `None` after a kill, and the steps it reached.
fn under<T>(
    bound: usize,
    at: Vec<(usize, Outcome)>,
    op: impl FnOnce() -> T,
) -> (Option<T>, Vec<Step>) {
    step::install(Some(Script {
        at,
        scan_bound: Some(bound),
        ..Script::default()
    }));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(op));
    let script = step::install(None).unwrap();
    match result {
        Ok(value) => (Some(value), script.reached),
        Err(payload) => {
            assert!(payload.is::<step::Killed>(), "the operation panicked");
            (None, script.reached)
        }
    }
}

/// With the scan bound lowered to 512, a tree of about 2,000 entries,
/// past the whole-tree walk's budget, counts and collects with every
/// per-directory listing under the bound, keeps every record file byte for
/// byte, and a kill during the pass then a rerun gives the tree of one
/// pass.
#[test]
fn a_lowered_bound_horizon_counts_and_collects_under_the_bound() {
    let bound = 512;
    let (case, expected_removals) = horizon();
    let (widest, total) = listings(&case.state);
    assert!(total >= 2_000, "{total}");
    assert!(widest < bound, "{widest}");
    let before = snapshot(&case.state);
    let (counted, _) = under(bound, Vec::new(), || {
        crate::campaign::census::Census::count(&Store::open(&case.state).unwrap()).map(drop)
    });
    counted.unwrap().unwrap();
    let (collected, steps) = under(bound, Vec::new(), || collect(&case.state, false));
    let collected = collected.unwrap().unwrap();
    assert_eq!(collected["held"], json!([]), "{collected}");
    assert_eq!(collected["reclaimed"].as_array().unwrap().len(), 110);
    // The whole-tree measurement passes the lowered bound, so collect
    // reports none; its per-directory listings stay under the bound.
    assert_eq!(collected["before"], Value::Null);
    assert_eq!(collected["after"], Value::Null);
    assert!(listings(&case.state).0 < bound);
    let after = snapshot(&case.state);
    assert_eq!(
        collected["probes"]["removed"],
        json!(["probe-horizon-0", "probe-horizon-1"])
    );
    let (removed, _) = assert_removal_report(&before, &after, &collected);
    assert_eq!(removed, expected_removals);
    assert_eq!(removed.len(), 110 * (2 + BULK as usize));
    let expected = comparable(&case.state);
    let unlinks: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == Step::Unlink)
        .map(|(index, _)| index)
        .collect();
    let rename = steps
        .iter()
        .position(|point| *point == Step::Rename)
        .unwrap();
    let boundary = unlinks
        .iter()
        .copied()
        .find(|index| *index > rename)
        .unwrap();
    for index in [
        unlinks[1],
        boundary,
        unlinks[unlinks.len() / 2],
        *unlinks.last().unwrap(),
    ] {
        let (case, _) = horizon();
        let before = snapshot(&case.state);
        let (killed, reached) = under(bound, vec![(index, Outcome::Kill)], || {
            collect(&case.state, false)
        });
        assert!(killed.is_none(), "step {index}");
        assert_eq!(reached, steps[..=index]);
        assert_eq!(reached.last(), Some(&Step::Unlink));
        assert_ne!(snapshot(&case.state), before);
        under(bound, Vec::new(), || collect(&case.state, false))
            .0
            .unwrap()
            .unwrap();
        kept_bytes(&before, &case.state);
        assert_eq!(comparable(&case.state), expected, "kill at step {index}");
    }
}

/// A report-held unfinished probe keeps all launcher logs in place while
/// dry and real collection agree and preserve the complete tree.
#[test]
fn a_kept_probe_hold_keeps_collectible_launcher_logs() {
    for partial in [false, true] {
        let (case, _) = populated();
        let store = Store::open(&case.state).unwrap();
        let probe = crate::campaign::state_fixture::finished_probe(
            &store,
            "probe-unfinished",
            "/sys/fs/cgroup/campaign-released-probe",
            crate::record::Digest::of(b"archive"),
            crate::record::ProbeOutcome::Held,
        );
        if !partial {
            store.delete(&probe, &name("finished")).unwrap();
        }
        drop(store);
        if partial {
            fs::remove_file(
                case.state
                    .join("probes/probe-unfinished/artifacts/probe/artifact"),
            )
            .unwrap();
        }
        let before = snapshot(&case.state);
        for dry in [true, false] {
            let result = direct_pass(&case.state, dry);
            assert_eq!((result.deletions, result.finished), (0, false));
            assert!(result.held.is_some());
            let report = result.report;
            assert_eq!(report["entries"], json!([]));
            assert_eq!(report["projected_inodes"], 0);
            assert_eq!(report["probes"]["swept"], true);
            assert!(
                report["held"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["path"] == "probes/probe-unfinished")
            );
            assert!(
                report["probes"]["kept"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["probe"] == "probe-unfinished")
            );
            assert_eq!(snapshot(&case.state), before);
        }
    }
}

/// A root-scoped configuration hold skips both sweeps, while the report
/// explicitly distinguishes that skip from an empty probe sweep.
#[test]
fn a_root_hold_reports_a_skipped_probe_sweep() {
    let (case, _) = populated();
    empty_probe(&case);
    fs::write(case.state.join("config.json"), b"damaged").unwrap();
    let before = snapshot(&case.state);
    for dry in [true, false] {
        let store = Store::for_collection(&case.state).unwrap();
        let result = pass(&store, dry, usize::MAX, &mut || false).unwrap();
        assert_eq!((result.deletions, result.finished), (0, false));
        drop(store);
        let report = result.report;
        assert_eq!(
            report["probes"],
            json!({"swept": false, "removed": [], "kept": []})
        );
        assert_eq!(report["entries"], json!([]));
        assert!(
            report["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["path"] == "config.json")
        );
        assert_eq!(snapshot(&case.state), before);
    }
}

/// Collection's snapshot and refusal preflight accept every interrupted
/// probe deletion prefix. Both a kill and a sync failure resume to one
/// uninterrupted collect, and a third collect performs zero unlinks.
#[test]
fn interrupted_probe_collection_passes_preflight_on_rerun() {
    let build = || {
        let (case, id) = populated();
        let store = Store::open(&case.state).unwrap();
        crate::campaign::state_fixture::finished_probe(
            &store,
            "probe-a",
            "/sys/fs/cgroup/campaign-released-probe",
            crate::record::Digest::parse(&"b".repeat(64)).unwrap(),
            crate::record::ProbeOutcome::Complete,
        );
        drop(store);
        (case, id)
    };
    let (reference, id) = build();
    let (result, trace) = crate::store::fixture::scripted([], || collect(&reference.state, false));
    let result = result.unwrap().unwrap();
    assert_eq!(result["probes"]["removed"], json!(["probe-a"]));
    assert_eq!(result["held"], json!([]));
    let collected = snapshot(&reference.state);
    let logs = crate::custody::LAUNCHER_OUTPUTS.map(|output| {
        crate::campaign::state_fixture::attempts_dir(&id)
            .join("0001")
            .join(output)
    });
    assert!(
        collected
            .keys()
            .all(|path| !path.starts_with("probes/probe-a") && !logs.contains(path))
    );
    assert_eq!(
        trace.iter().filter(|step| **step == Step::Unlink).count(),
        15 + 1 + BULK as usize
    );
    for (index, step) in trace
        .iter()
        .enumerate()
        .filter(|(_, step)| matches!(step, Step::Unlink | Step::Sync))
    {
        for fault in [Outcome::Kill, Outcome::Errno(libc::EIO)] {
            let (case, id) = build();
            let before = snapshot(&case.state);
            collect(&case.state, false).unwrap();
            let once = snapshot(&case.state);
            // Restore the removed probe and logs through store publications
            // at the same path, so lifecycle bytes match the reference run.
            let store = Store::open(&case.state).unwrap();
            crate::campaign::state_fixture::finished_probe(
                &store,
                "probe-a",
                "/sys/fs/cgroup/campaign-released-probe",
                crate::record::Digest::parse(&"b".repeat(64)).unwrap(),
                crate::record::ProbeOutcome::Complete,
            );
            let job = crate::layout::attempts(&store, &id).unwrap().unwrap();
            let attempt = store.open_dir(&job, &name("0001")).unwrap().unwrap();
            launcher_logs(&store, &attempt, b"unreferenced launcher log");
            drop(store);
            // The reclaimed bulk returns byte for byte, and its record goes.
            let now = snapshot(&case.state);
            for (entry, bytes) in &before {
                if let Some(bytes) = bytes
                    && !now.contains_key(entry)
                {
                    fs::write(case.state.join(entry), bytes).unwrap();
                }
            }
            for entry in now.keys().filter(|entry| !before.contains_key(*entry)) {
                fs::remove_file(case.state.join(entry)).unwrap();
            }
            assert_eq!(snapshot(&case.state), before);
            let (result, reached) =
                crate::store::fixture::scripted([(index, fault)], || collect(&case.state, false));
            match fault {
                Outcome::Kill => {
                    assert!(result.is_none());
                    assert_eq!(reached, trace[..=index]);
                }
                Outcome::Errno(_) => {
                    assert_eq!(
                        result.unwrap().unwrap_err().exit(),
                        crate::exit::Supervisor::Held
                    );
                    assert!(!reached[index + 1..].contains(&Step::Unlink));
                }
                _ => unreachable!(),
            }
            let rerun = collect(&case.state, false).unwrap();
            assert_eq!(rerun["held"], json!([]), "{index} {step:?}");
            assert_eq!(snapshot(&case.state), once, "{index} {step:?}");
            let (third, reached) =
                crate::store::fixture::scripted([], || collect(&case.state, false));
            assert_eq!(third.unwrap().unwrap()["probes"]["removed"], json!([]));
            assert!(!reached.contains(&Step::Unlink));
            assert_eq!(snapshot(&case.state), once);
        }
    }
}

/// A queued targeted job's frozen-input hold pins that job while an empty
/// admission probe and a healthy job's launcher logs remain collectible.
#[test]
fn a_queued_target_hold_allows_the_probe_sweep_and_other_job_logs() {
    let fixture = Fixture::new();
    fixture.probe();
    let healthy = fixture.admit(0);
    let directory = fixture.finish(&healthy, Some(7));
    launcher_logs(&fixture.store, &directory, b"healthy log");
    let targeted = fixture.targeted(1);
    crate::campaign::state_fixture::probe(&fixture.store, "probe-empty", 0);
    let path = fixture.case.state.clone();
    let id = targeted.job().id().to_string();
    drop(fixture.store);
    fs::write(
        path.join(crate::layout::job_file(&id, &format!("{id}.bundle"))),
        b"damaged frozen target",
    )
    .unwrap();
    let before = snapshot(&path);
    let dry = collect(&path, true).unwrap();
    assert_eq!(snapshot(&path), before);
    assert_eq!(dry["probes"]["removed"], json!(["probe-empty"]));
    assert_eq!(dry["projected_inodes"], 2 + BULK);
    assert!(
        dry["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == format!("jobs/{id}"))
    );
    let real = collect(&path, false).unwrap();
    for field in ["held", "entries", "probes"] {
        assert_eq!(real[field], dry[field]);
    }
    assert_eq!(real["freed_inodes"], 2 + BULK);
}

/// A pass stops after `limit` deletions, a probe directory counting as
/// one, or at an interruption before a deletion, reports itself
/// unfinished, and a later collect gives the tree of one full pass.
#[test]
fn a_limited_or_interrupted_pass_stops_before_its_next_deletion_and_a_rerun_finishes() {
    let (case, _) = populated();
    collect(&case.state, false).unwrap();
    let expected = comparable(&case.state);
    let deletions = 2 + BULK as usize;
    for limit in [0, 1, 3, deletions] {
        let (case, _) = populated();
        let before = snapshot(&case.state);
        let store = Store::for_collection(&case.state).unwrap();
        let stopped = pass(&store, false, limit, &mut || false).unwrap();
        assert_partial_pass(&case, &before, &stopped);
        drop(store);
        assert_eq!(stopped.deletions, limit, "{limit}");
        assert_eq!(stopped.finished, limit == deletions, "{limit}");
        collect(&case.state, false).unwrap();
        kept_bytes(&before, &case.state);
        assert_eq!(comparable(&case.state), expected, "limit {limit}");
    }
    // The sweep checks once for the report's source probe, then the
    // removals check before each deletion.
    for checks in [0usize, 1, 3] {
        let (case, _) = populated();
        let before = snapshot(&case.state);
        let store = Store::for_collection(&case.state).unwrap();
        let mut calls = 0;
        let stopped = pass(&store, false, usize::MAX, &mut || {
            calls += 1;
            calls > checks
        })
        .unwrap();
        drop(store);
        assert_eq!(stopped.deletions, checks.saturating_sub(1), "{checks}");
        assert!(!stopped.finished, "{checks}");
        assert_partial_pass(&case, &before, &stopped);
        collect(&case.state, false).unwrap();
        kept_bytes(&before, &case.state);
        assert_eq!(comparable(&case.state), expected, "checks {checks}");
    }
}

#[test]
fn reclaim_marker_precedes_bulk_unlinks_and_partial_bulk_keeps_its_charge() {
    let (case, id) = populated();
    let attempt = case.state.join(crate::layout::attempt_path(&id, 1));
    let path = attempt.clone();
    let mut unlinks = 0;
    step::install(Some(Script {
        observe: Some(Box::new(move |point| {
            if point == Step::Unlink {
                unlinks += 1;
                if unlinks > 1 {
                    assert!(path.join("reclaimed").is_file());
                }
            }
        })),
        ..Script::default()
    }));
    collect(&case.state, false).unwrap();
    let trace = step::install(None).unwrap().reached;
    assert_eq!(
        trace.iter().filter(|point| **point == Step::Unlink).count(),
        1 + (2 + BULK) as usize
    );
    for cut in 0..2 + BULK {
        let (case, id) = populated();
        let store = Store::open(&case.state).unwrap();
        let config = crate::campaign::state_fixture::config(8 << 20, 100);
        let charged = crate::campaign::census::census(&store, &config).unwrap();
        drop(store);
        step::install(Some(Script {
            nth: Some((Step::Unlink, 1 + cut as usize, Outcome::Kill)),
            ..Script::default()
        }));
        let killed =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect(&case.state, false)));
        step::install(None);
        assert!(killed.unwrap_err().is::<step::Killed>());
        let marker = case
            .state
            .join(crate::layout::attempt_path(&id, 1))
            .join("reclaimed");
        assert!(marker.is_file());
        let shown = crate::campaign::report(&case.state).unwrap();
        assert_eq!(shown["held"], json!([]));
        let store = Store::open(&case.state).unwrap();
        let partial = crate::campaign::census::census(&store, &config).unwrap();
        assert_eq!(
            (partial.bytes, partial.inodes),
            (charged.bytes, charged.inodes),
            "cut {cut}"
        );
        drop(store);
        collect(&case.state, false).unwrap();
        let store = Store::open(&case.state).unwrap();
        let complete = crate::campaign::census::census(&store, &config).unwrap();
        assert!(complete.bytes < charged.bytes);
        assert!(complete.inodes < charged.inodes);
    }
}

#[test]
fn unknown_or_staged_evidence_keeps_its_attempt_beside_a_reclaimable_control() {
    for extra in [
        "artifacts",
        "evidence",
        "staging",
        "foreign-marker",
        "dotfile",
        "attempt-dotfile",
    ] {
        let fixture = Fixture::new();
        fixture.probe();
        let held = fixture.admit(0);
        let directory = fixture.finish(&held, Some(7));
        let control = fixture.admit(1);
        fixture.finish(&control, Some(7));
        launcher_logs(&fixture.store, &directory, b"keep");
        let path = fixture.case.state.clone();
        let id = held.job().id().to_string();
        let attempt = path.join(crate::layout::attempt_path(&id, 1));
        let evidence = attempt.join("artifacts").join(format!("{id}-0001"));
        drop(fixture.store);
        match extra {
            "attempt-dotfile" => fs::write(attempt.join(".worker"), b"keep").unwrap(),
            "artifacts" => fs::write(attempt.join("artifacts/scratch"), b"keep").unwrap(),
            "staging" => {
                fs::write(evidence.join(".state"), crate::store::MARKER_BYTES).unwrap();
                fs::create_dir_all(evidence.join(".staging")).unwrap();
                fs::write(evidence.join(".staging/orphan"), b"keep").unwrap();
            }
            "foreign-marker" => fs::write(evidence.join(".state"), b"foreign").unwrap(),
            "dotfile" => fs::write(evidence.join(".worker"), b"keep").unwrap(),
            _ => fs::write(evidence.join("scratch"), b"keep").unwrap(),
        }
        let before = snapshot(&attempt);
        let store = Store::open(&path).unwrap();
        let config = crate::campaign::state_fixture::config(8 << 20, 100);
        let charged = crate::campaign::census::census(&store, &config).unwrap();
        drop(store);
        let collected = collect(&path, false).unwrap();
        assert_eq!(
            collected["reclaimed"],
            json!([
                crate::layout::attempt_path(&control.job().id().to_string(), 1)
                    .display()
                    .to_string()
            ])
        );
        assert_eq!(
            collected["held"].as_array().unwrap().len(),
            1,
            "{extra}: {collected}"
        );
        let reason = collected["held"][0]["reason"].as_str().unwrap();
        assert!(
            reason.contains(match extra {
                "staging" | "foreign-marker" => "staged evidence or a foreign marker",
                "artifacts" => "unknown artifacts entry",
                "attempt-dotfile" | "dotfile" => "foreign entry",
                _ => "unknown evidence entry",
            }),
            "{extra}: {collected}"
        );
        assert_eq!(snapshot(&attempt), before, "{extra}");
        let store = Store::open(&path).unwrap();
        let after = crate::campaign::census::census(&store, &config).unwrap();
        assert_eq!(
            u128::from(charged.bytes - after.bytes),
            config.retained_charge().bytes - config.reclaimed_charge().bytes
        );
    }
}

#[test]
fn a_settled_artifact_hold_pins_only_its_job() {
    for damage in ["missing", "malformed"] {
        let fixture = Fixture::new();
        fixture.probe();
        let damaged = fixture.admit(0);
        let directory = fixture.finish(&damaged, Some(7));
        launcher_logs(&fixture.store, &directory, b"keep");
        let control = fixture.admit(1);
        fixture.finish(&control, Some(7));
        let path = fixture.case.state.clone();
        let id = damaged.job().id().to_string();
        let attempt = path.join(crate::layout::attempt_path(&id, 1));
        let artifact = attempt
            .join("artifacts")
            .join(format!("{id}-0001/artifact"));
        drop(fixture.store);
        if damage == "missing" {
            fs::remove_file(artifact).unwrap();
        } else {
            fs::write(artifact, b"damaged").unwrap();
        }
        let before = snapshot(&attempt);
        let dry = collect(&path, true).unwrap();
        assert!(!dry["held"].as_array().unwrap().is_empty());
        assert_eq!(snapshot(&attempt), before);
        let real = collect(&path, false).unwrap();
        assert_eq!(real["entries"], dry["entries"]);
        assert_eq!(
            real["reclaimed"],
            json!([
                crate::layout::attempt_path(&control.job().id().to_string(), 1)
                    .display()
                    .to_string()
            ])
        );
        assert_eq!(snapshot(&attempt), before);
    }
}

#[test]
fn a_differing_reclaim_name_list_holds_only_its_attempt() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let directory = fixture.finish(&job, Some(7));
    let control = fixture.admit(1);
    fixture.finish(&control, Some(7));
    let (_, artifact, finished) = evidence_records(&fixture.store, &directory);
    let mut marker =
        crate::record::Reclaimed::new(1, &finished, &artifact.record().bulk().unwrap());
    marker.names.pop();
    fixture
        .store
        .create_record(&directory, &name("reclaimed"), &marker)
        .unwrap();
    let path = fixture.case.state.clone();
    let attempt = path.join(crate::layout::attempt_path(&job.job().id().to_string(), 1));
    drop(fixture.store);
    let before = snapshot(&attempt);
    for dry in [true, false] {
        let result = collect(&path, dry).unwrap();
        assert!(result["held"].as_array().unwrap().iter().any(|row| {
            row["path"]
                == crate::layout::attempt_path(&job.job().id().to_string(), 1)
                    .display()
                    .to_string()
                && row["reason"] == "reclaim record differs from the attempt's records"
        }));
        assert_eq!(
            result["reclaimed"],
            json!([
                crate::layout::attempt_path(&control.job().id().to_string(), 1)
                    .display()
                    .to_string()
            ])
        );
        assert_eq!(snapshot(&attempt), before);
    }
}

#[test]
fn a_capabilities_attempt_keeps_report_stdout_and_reclaims_its_other_streams() {
    let fixture = Fixture::new();
    let job = fixture.admit(0);
    fixture.finish_at_with_listing(
        &job,
        1,
        Some(7),
        crate::record::Class::Pass,
        Some(include_bytes!("../../testdata/admission-listing.txt")),
    );
    let path = fixture.case.state.clone();
    let evidence = path
        .join(crate::layout::attempt_path(&job.job().id().to_string(), 1))
        .join("artifacts")
        .join(format!("{}-0001", job.job().id()));
    drop(fixture.store);
    let before = readers(&path);
    let result = collect(&path, false).unwrap();
    assert_eq!(result["held"], json!([]));
    assert_eq!(result["freed_inodes"], BULK + 1);
    assert!(evidence.join("capabilities.stdout").is_file());
    assert!(evidence.join("inspect.stdout").is_file());
    assert!(!evidence.join("capabilities.stderr").exists());
    assert_eq!(before, readers(&path));
}

#[test]
fn unsettled_and_targeted_jobs_keep_their_bulk() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let (directory, _, _) =
        fixture.finish_unsettled(&job, 1, Some(7), crate::record::Class::Interrupted);
    launcher_logs(&fixture.store, &directory, b"log");
    let target = fixture.targeted(1);
    let jobs = fixture
        .store
        .shard_jobs(target.job().id().to_string())
        .unwrap()
        .unwrap();
    fixture
        .store
        .create_once(
            &jobs,
            &name(&format!(
                "{}{}",
                target.job().id(),
                crate::record::JobResult::SUFFIX
            )),
            b"present",
        )
        .unwrap();
    let path = fixture.case.state.clone();
    drop(fixture.store);
    let view = View::open(&path).unwrap();
    assert_eq!(
        settled(&view, &target.job().id().to_string()).unwrap(),
        None
    );
    // The direct targeted gate above uses file presence; the corrupt result
    // is removed before the command checks its verified snapshot.
    fs::remove_file(path.join(crate::layout::job_file(
        &target.job().id().to_string(),
        &format!("{}{}", target.job().id(), crate::record::JobResult::SUFFIX),
    )))
    .unwrap();
    let attempt = path.join(crate::layout::attempt_path(&job.job().id().to_string(), 1));
    let before = snapshot(&attempt);
    let result = collect(&path, false).unwrap();
    assert_eq!(result["held"], json!([]));
    assert_eq!(result["reclaimed"], json!([]));
    let after = snapshot(&attempt);
    let removed: BTreeSet<_> = before
        .keys()
        .filter(|entry| !after.contains_key(*entry))
        .cloned()
        .collect();
    assert_eq!(
        removed,
        crate::custody::LAUNCHER_OUTPUTS
            .map(std::path::PathBuf::from)
            .into_iter()
            .collect()
    );
    assert!(!attempt.join("reclaimed").exists());
}

#[test]
fn a_nonmatching_retry_keeps_logs_before_and_after_job_settlement() {
    let mut fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    let (first, verified, _) =
        fixture.finish_unsettled(&job, 1, Some(7), crate::record::Class::Interrupted);
    let id = job.job().id().to_string();
    let record = fixture
        .store
        .read_record::<crate::record::Attempt>(&first, &name("attempt"))
        .unwrap()
        .unwrap();
    let mut finish = fixture
        .store
        .read_record::<crate::record::Finished>(&first, &name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finish.binding = crate::record::Binding::Missing;
    finish.bound = None;
    fs::remove_dir_all(
        fixture
            .case
            .state
            .join(crate::layout::attempt_path(&id, 1))
            .join("artifacts"),
    )
    .unwrap();
    fixture
        .store
        .replace_record(&first, &name("finished"), &finish)
        .unwrap();
    let completed =
        crate::attempt::read_completed(&fixture.store, &first, record.record(), job.command())
            .unwrap();
    crate::attempt::settle(&fixture.store, verified, completed).unwrap();
    launcher_logs(&fixture.store, &first, b"keep retry");
    let path = fixture.case.state.clone();
    let first_path = path.join(crate::layout::attempt_path(&id, 1));
    drop(fixture.store);
    let before = snapshot(&first_path);
    let result = collect(&path, false).unwrap();
    assert_eq!(result["held"], json!([]));
    assert_eq!(result["entries"], json!([]));
    assert_eq!(snapshot(&first_path), before);
    let store = Store::open(&path).unwrap();
    fixture.store = store;
    fixture.finish_at(&job, 2, Some(7), crate::record::Class::Pass);
    drop(fixture.store);
    let result = collect(&path, false).unwrap();
    assert_eq!(result["held"], json!([]));
    assert_eq!(
        result["reclaimed"],
        json!([crate::layout::attempt_path(&id, 2).display().to_string()])
    );
    assert_eq!(snapshot(&first_path), before);
}

#[test]
fn marker_free_removals_finish_before_a_new_marker_write_fails() {
    let fixture = Fixture::new();
    fixture.probe();
    let mut jobs: Vec<_> = (0..2)
        .map(|run| {
            let job = fixture.admit(run);
            let directory = fixture.finish(&job, Some(7));
            launcher_logs(&fixture.store, &directory, b"log");
            (job, directory)
        })
        .collect();
    jobs.sort_by_key(|(job, _)| job.job().id().to_string());
    let (new_job, _) = &jobs[0];
    let (resumed_job, resumed) = &jobs[1];
    let (_, artifact, finished) = evidence_records(&fixture.store, resumed);
    fixture
        .store
        .create_record(
            resumed,
            &name("reclaimed"),
            &crate::record::Reclaimed::new(1, &finished, &artifact.record().bulk().unwrap()),
        )
        .unwrap();
    let waiting_job = fixture.admit(2);
    let (waiting, _, _) =
        fixture.finish_unsettled(&waiting_job, 1, Some(7), crate::record::Class::Interrupted);
    launcher_logs(&fixture.store, &waiting, b"log");
    let path = fixture.case.state.clone();
    let resumed_path = path.join(crate::layout::attempt_path(
        &resumed_job.job().id().to_string(),
        1,
    ));
    let new_path = path.join(crate::layout::attempt_path(
        &new_job.job().id().to_string(),
        1,
    ));
    let waiting_path = path.join(crate::layout::attempt_path(
        &waiting_job.job().id().to_string(),
        1,
    ));
    drop(fixture.store);
    let before = snapshot(&resumed_path);
    step::install(Some(Script {
        nth: Some((Step::Write, 0, Outcome::Errno(libc::ENOSPC))),
        ..Script::default()
    }));
    let result = collect(&path, false);
    let trace = step::install(None).unwrap().reached;
    assert_eq!(result.unwrap_err().exit(), crate::exit::Supervisor::Held);
    let write = trace
        .iter()
        .position(|point| *point == Step::Write)
        .unwrap();
    assert!(!trace[write + 1..].contains(&Step::Unlink));
    assert_eq!(
        before.len() - snapshot(&resumed_path).len(),
        (2 + BULK) as usize
    );
    for output in crate::custody::LAUNCHER_OUTPUTS {
        assert!(!waiting_path.join(output).exists());
        assert!(new_path.join(output).is_file());
    }
    assert!(!new_path.join("reclaimed").exists());
}

#[test]
fn an_oversized_reclaim_marker_is_held_during_planning() {
    let (case, id) = populated();
    let store = Store::open(&case.state).unwrap();
    let root = crate::layout::attempts(&store, &id).unwrap().unwrap();
    let directory = store.open_dir(&root, &name("0001")).unwrap().unwrap();
    let (evidence, artifact, finished) = evidence_records(&store, &directory);
    let mut artifact = artifact.record().clone();
    let worker = artifact.workers.values().next().unwrap().clone();
    for index in 0..2200 {
        artifact.workers.insert(
            crate::record::Text::new(&format!("phase-{index:04}-{}", "a".repeat(160))).unwrap(),
            worker.clone(),
        );
    }
    assert!(crate::record::Record::encoded_len(&artifact) as u64 <= crate::record::BOUND);
    let marker = crate::record::Reclaimed::new(1, &finished, &artifact.bulk().unwrap());
    assert!(crate::record::Record::encoded_len(&marker) as u64 > crate::record::BOUND);
    store
        .replace_record(&evidence, &name("artifact"), &artifact)
        .unwrap();
    let rebound_artifact = store
        .read_record::<crate::record::Artifact>(&evidence, &name("artifact"))
        .unwrap()
        .unwrap();
    let mut finish = finished.record().clone();
    finish.bound.as_mut().unwrap().artifact =
        crate::record::Digest::of(rebound_artifact.read().bytes());
    store
        .replace_record(&directory, &name("finished"), &finish)
        .unwrap();
    let finished = store
        .read_record::<crate::record::Finished>(&directory, &name("finished"))
        .unwrap()
        .unwrap();
    let before = snapshot(&case.state);
    let view = View::open(&case.state).unwrap();
    let path = crate::layout::attempt_path(&id, 1).display().to_string();
    let error = reclaim(
        &view,
        Unit {
            directory,
            finished,
            logs: Vec::new(),
        },
        &id,
        1,
        &path,
    )
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "reclaim record exceeds its byte bound");
    assert_eq!(snapshot(&case.state), before);
}

/// A sweep-only unlisted-entry hold preserves its probe and leaves report
/// holds empty, so verified launcher logs and settled bulk can still be
/// collected.
#[test]
fn a_sweep_only_hold_preserves_its_probe_and_allows_launcher_log_collection() {
    let (case, _) = populated();
    let store = Store::open(&case.state).unwrap();
    crate::campaign::state_fixture::finished_probe(
        &store,
        "probe-extra",
        "/sys/fs/cgroup/campaign-released-probe",
        crate::record::Digest::parse(&"b".repeat(64)).unwrap(),
        crate::record::ProbeOutcome::Complete,
    );
    drop(store);
    let probe = case.state.join("probes/probe-extra");
    fs::write(probe.join("extra"), b"keep").unwrap();
    let before = snapshot(&probe);
    for dry in [true, false] {
        let result = direct_pass(&case.state, dry);
        assert!(result.finished);
        assert_eq!(
            result.held.as_deref(),
            Some("probes/probe-extra: probe holds unlisted entry extra")
        );
        let report = result.report;
        assert_eq!(report["held"], json!([]));
        // The launcher logs and the settled attempt's bulk.
        assert_eq!(report["projected_inodes"], 2 + BULK);
        assert!(report["probes"]["kept"].as_array().unwrap().contains(&json!({"probe": "probe-extra", "code": "binding", "reason": "probe holds unlisted entry extra"})));
        assert_eq!(snapshot(&probe), before);
    }
}

/// A `probes/` listing past the scan bound holds collect before it sweeps
/// a removable probe, in either a dry run or a real run.
#[test]
fn a_full_probe_root_keeps_removable_probes_when_its_listing_holds() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for index in 0..5 {
        crate::campaign::state_fixture::probe(&store, &format!("probe-{index}"), 0);
    }
    drop(store);
    let before = snapshot(&case.state);
    for dry in [true, false] {
        let (result, reached) = crate::store::fixture::bounded(4, || collect(&case.state, dry));
        let error = result.unwrap_err();
        assert_eq!(error.exit(), crate::exit::Supervisor::Held);
        assert_eq!(
            error.to_string(),
            "probes holds more than 4 entries at bound 4; collect or shard"
        );
        assert!(!reached.contains(&Step::Unlink));
        assert_eq!(snapshot(&case.state), before);
    }
}

fn assert_removal_report(
    before: &crate::store::fixture::Snapshot,
    after: &crate::store::fixture::Snapshot,
    report: &Value,
) -> (BTreeSet<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    let entries: BTreeSet<std::path::PathBuf> = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["path"].as_str().unwrap().into())
        .collect();
    assert_eq!(entries.len(), report["entries"].as_array().unwrap().len());
    let probes: Vec<std::path::PathBuf> = report["probes"]["removed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| std::path::PathBuf::from("probes").join(row.as_str().unwrap()))
        .collect();
    for entry in &entries {
        assert!(
            [
                "launcher.stdout",
                "launcher.stderr",
                "bundle",
                "run.stdout",
                "run.stderr",
                "inspect.stderr"
            ]
            .contains(&entry.file_name().unwrap().to_str().unwrap()),
            "{entry:?}"
        );
        assert!(before.contains_key(entry), "{entry:?}");
        assert!(!after.contains_key(entry), "{entry:?}");
    }
    for (entry, bytes) in before {
        if !entries.contains(entry) && !probes.iter().any(|probe| entry.starts_with(probe)) {
            assert_eq!(after.get(entry), Some(bytes), "{entry:?}");
        }
    }
    let markers: BTreeSet<_> = report["reclaimed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| std::path::PathBuf::from(path.as_str().unwrap()).join("reclaimed"))
        .collect();
    for entry in after.keys().filter(|entry| !before.contains_key(*entry)) {
        assert!(markers.contains(entry), "unexpected addition {entry:?}");
    }
    (entries, probes)
}

fn assert_partial_pass(case: &Case, before: &crate::store::fixture::Snapshot, result: &Pass) {
    let after = snapshot(&case.state);
    let (entries, probes) = assert_removal_report(before, &after, &result.report);
    assert_eq!(result.deletions, entries.len() + probes.len());
    if !result.changed {
        assert_eq!(&after, before);
    }
    for path in result.report["reclaimed"].as_array().unwrap() {
        let path = path.as_str().unwrap();
        assert!(case.state.join(path).join("reclaimed").is_file());
    }
}

fn direct_pass(path: &Path, dry: bool) -> Pass {
    pass(
        &Store::for_collection(path).unwrap(),
        dry,
        usize::MAX,
        &mut || false,
    )
    .unwrap()
}

#[test]
fn a_probe_and_bulk_share_the_pass_budget_and_a_sweep_stop_is_latched() {
    let (case, _) = populated();
    empty_probe(&case);
    let before = snapshot(&case.state);
    let store = Store::for_collection(&case.state).unwrap();
    let result = pass(&store, false, 2, &mut || false).unwrap();
    assert_eq!(result.report["probes"]["removed"], json!(["probe-empty"]));
    assert_eq!(result.report["entries"].as_array().unwrap().len(), 1);
    assert_eq!((result.deletions, result.finished), (2, false));
    assert_partial_pass(&case, &before, &result);
    drop(store);
    collect(&case.state, false).unwrap();
    kept_bytes(&before, &case.state);
    let expected = comparable(&case.state);
    let (whole, _) = populated();
    empty_probe(&whole);
    collect(&whole.state, false).unwrap();
    assert_eq!(comparable(&whole.state), expected);

    for limit in [0, 1, usize::MAX] {
        let (case, _) = populated();
        empty_probe(&case);
        let before = snapshot(&case.state);
        let store = Store::for_collection(&case.state).unwrap();
        let mut calls = 0;
        let result = pass(&store, false, limit, &mut || {
            calls += 1;
            calls == 1
        })
        .unwrap();
        assert_eq!((result.deletions, result.finished), (0, false));
        assert!(calls <= 1, "{calls}");
        assert_eq!(result.report["reclaimed"], json!([]));
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn a_reclaim_waits_for_marker_headroom_and_keeps_the_store_writable() {
    for free_space in [(0, u64::MAX), (1, u64::MAX), (u64::MAX, 0)] {
        let (case, id) = populated();
        let before = snapshot(&case.state);
        let store = Store::for_collection(&case.state).unwrap();
        step::install(Some(Script {
            free_space: Some(free_space),
            ..Script::default()
        }));
        let result = pass(&store, false, usize::MAX, &mut || false);
        let trace = step::install(None).unwrap().reached;
        let result = result.unwrap();
        assert_eq!((result.deletions, result.finished), (0, false));
        assert_eq!(result.report["reclaimed"], json!([]));
        assert!(!trace.contains(&Step::Write));
        assert_eq!(snapshot(&case.state), before);
        assert!(
            !case
                .state
                .join(crate::layout::attempt_path(&id, 1))
                .join("reclaimed")
                .exists()
        );
        assert!(
            result.report["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["path"]
                    == crate::layout::attempt_path(&id, 1).display().to_string()
                    && row["reason"].as_str().unwrap().contains("free disk space"))
        );
        store.writable(store.root()).unwrap();
    }
}

#[test]
fn measured_propagates_host_faults_at_and_below_its_scan_bound() {
    let (case, _) = populated();
    let store = Store::for_collection(&case.state).unwrap();
    for bound in [1, crate::scan_bound()] {
        let (_, trace) = crate::store::fixture::bounded(bound, || measured(&store).unwrap());
        for (index, point) in trace.iter().enumerate().filter(|(_, point)| {
            matches!(
                point,
                Step::Stat | Step::List | Step::Open | Step::Read | Step::Census
            )
        }) {
            step::install(Some(Script {
                scan_bound: Some(bound),
                at: vec![(index, Outcome::Errno(libc::EIO))],
                ..Script::default()
            }));
            let error = measured(&store).unwrap_err();
            let reached = step::install(None).unwrap().reached;
            assert_eq!(reached[index], *point);
            assert!(error.to_string().contains("Input/output error"), "{error}");
        }
    }
}
#[test]
fn a_bound_capture_reference_keeps_its_attempt_on_both_collection_paths() {
    for settled_job in [false, true] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        let directory = fixture.finish_at(&job, 1, Some(7), crate::record::Class::Interrupted);
        if settled_job {
            fixture.finish_at(&job, 2, Some(7), crate::record::Class::Pass);
        }
        launcher_logs(&fixture.store, &directory, b"keep captured");
        let view = View::open(&fixture.case.state).unwrap();
        let verified = super::super::report::snapshot(&view).unwrap();
        let id = job.job().id().to_string();
        assert!(!verified.histories[&id].attempts[0].rooted);
        let mut capture = fixture
            .store
            .read_record::<crate::record::Captured>(&directory, &name("captured"))
            .unwrap()
            .unwrap()
            .record()
            .clone();
        capture.finding = Some(capture.attempt.clone());
        fixture
            .store
            .replace_record(&directory, &name("captured"), &capture)
            .unwrap();
        let fresh = super::super::report::snapshot(&view).unwrap();
        assert!(fresh.histories[&id].attempts[0].rooted);
        let root = crate::layout::attempts(&view, &id).unwrap().unwrap();
        assert!(
            unit(
                &view,
                &root,
                &id,
                1,
                &verified.histories[&id].attempts[0],
                &crate::layout::attempt_path(&id, 1).display().to_string()
            )
            .unwrap()
            .is_none()
        );
        let path = fixture.case.state.clone();
        let id = job.job().id().to_string();
        let kept = path.join(crate::layout::attempt_path(&id, 1));
        drop(fixture.store);
        let before = snapshot(&kept);
        for dry in [true, false] {
            let result = collect(&path, dry).unwrap();
            assert_eq!(result["held"], json!([]), "{result}");
            assert_eq!(
                result["reclaimed"],
                if settled_job {
                    json!([crate::layout::attempt_path(&id, 2).display().to_string()])
                } else {
                    json!([])
                }
            );
            assert_eq!(snapshot(&kept), before);
        }
    }
}

#[test]
fn undeclared_or_oversized_retained_stdout_keeps_its_job_beside_a_control() {
    for damage in ["undeclared", "oversized", "directory"] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        let directory = fixture.finish(&job, Some(7));
        launcher_logs(&fixture.store, &directory, b"keep");
        let control = fixture.admit(1);
        fixture.finish(&control, Some(7));
        let path = fixture.case.state.clone();
        let id = job.job().id().to_string();
        let attempt = path.join(crate::layout::attempt_path(&id, 1));
        let evidence = attempt.join("artifacts").join(format!("{id}-0001"));
        drop(fixture.store);
        match damage {
            "undeclared" => fs::write(evidence.join("capabilities.stdout"), b"undeclared").unwrap(),
            "oversized" => fs::write(
                evidence.join("inspect.stdout"),
                vec![b'x'; crate::sim::OUTPUT + 1],
            )
            .unwrap(),
            _ => {
                fs::remove_file(evidence.join("inspect.stdout")).unwrap();
                fs::create_dir(evidence.join("inspect.stdout")).unwrap();
            }
        }
        let before = snapshot(&attempt);
        let result = collect(&path, false).unwrap();
        assert_eq!(
            result["reclaimed"],
            json!([
                crate::layout::attempt_path(&control.job().id().to_string(), 1)
                    .display()
                    .to_string()
            ])
        );
        assert_eq!(
            result["held"].as_array().unwrap().len(),
            1,
            "{damage}: {result}"
        );
        let row = &result["held"][0];
        if damage == "undeclared" {
            assert_eq!(
                row["path"],
                crate::layout::attempt_path(&id, 1).display().to_string()
            );
            assert_eq!(row["reason"], "unknown evidence entry pins its subtree");
        } else {
            assert_eq!(row["path"], format!("jobs/{id}"));
        }
        assert_eq!(snapshot(&attempt), before);
    }
}

#[test]
fn a_resumed_reclaim_holds_missing_damaged_or_nonregular_manifests() {
    for damage in ["missing", "truncated", "directory"] {
        let (case, id) = populated();
        step::install(Some(Script {
            nth: Some((Step::Unlink, 1, Outcome::Kill)),
            ..Script::default()
        }));
        let killed =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect(&case.state, false)));
        step::install(None);
        assert!(killed.unwrap_err().is::<step::Killed>());
        let attempt = case.state.join(crate::layout::attempt_path(&id, 1));
        assert!(attempt.join("reclaimed").is_file());
        let manifest = attempt
            .join("artifacts")
            .join(format!("{id}-0001/manifest"));
        match damage {
            "missing" => fs::remove_file(manifest).unwrap(),
            "truncated" => fs::write(manifest, b"truncated").unwrap(),
            _ => {
                fs::remove_file(&manifest).unwrap();
                fs::create_dir(manifest).unwrap();
            }
        }
        let before = snapshot(&attempt);
        for dry in [true, false] {
            let result = collect(&case.state, dry).unwrap();
            assert_eq!(result["entries"], json!([]));
            assert!(
                result["held"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["reason"].as_str().unwrap().contains("manifest")),
                "{damage}: {result}"
            );
            assert_eq!(snapshot(&attempt), before);
        }
    }
}

#[test]
fn a_valid_nested_evidence_store_keeps_its_housekeeping_entries() {
    let (case, id) = populated();
    let evidence = case
        .state
        .join(crate::layout::attempt_path(&id, 1))
        .join("artifacts")
        .join(format!("{id}-0001"));
    fs::write(evidence.join(".state"), crate::store::MARKER_BYTES).unwrap();
    fs::create_dir(evidence.join(".staging")).unwrap();
    let result = collect(&case.state, false).unwrap();
    assert_eq!(result["held"], json!([]));
    assert_eq!(result["freed_inodes"], 2 + BULK);
    assert_eq!(
        fs::read(evidence.join(".state")).unwrap(),
        crate::store::MARKER_BYTES
    );
    assert!(evidence.join(".staging").is_dir());
    assert!(
        fs::read_dir(evidence.join(".staging"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn a_marker_only_reclaim_reduces_an_empty_bulk_attempt_charge() {
    let fixture = Fixture::new();
    fixture.probe();
    let job = fixture.admit_n(0, 1);
    let (directory, verified, _) =
        fixture.finish_unsettled(&job, 1, Some(7), crate::record::Class::Interrupted);
    let (evidence, artifact, finished) = evidence_records(&fixture.store, &directory);
    let mut artifact = artifact.record().clone();
    for entry in artifact.bulk().unwrap() {
        fixture.store.delete(&evidence, &entry).unwrap();
    }
    fixture
        .store
        .delete(&evidence, &name("inspect.stdout"))
        .unwrap();
    artifact.bundle = None;
    artifact.workers.clear();
    artifact.summary = None;
    fixture
        .store
        .replace_record(&evidence, &name("artifact"), &artifact)
        .unwrap();
    let mut finish = finished.record().clone();
    let mut binding = finish.bound.clone().unwrap();
    binding.artifact = crate::record::Digest::of(
        fixture
            .store
            .read_record::<crate::record::Artifact>(&evidence, &name("artifact"))
            .unwrap()
            .unwrap()
            .read()
            .bytes(),
    );
    binding.bundle = None;
    finish.bound = Some(binding.clone());
    fixture
        .store
        .replace_record(&directory, &name("bound"), &binding)
        .unwrap();
    fixture
        .store
        .replace_record(&directory, &name("finished"), &finish)
        .unwrap();
    let attempt = fixture
        .store
        .read_record::<crate::record::Attempt>(&directory, &name("attempt"))
        .unwrap()
        .unwrap();
    let completed =
        crate::attempt::read_completed(&fixture.store, &directory, attempt.record(), job.command())
            .unwrap();
    crate::attempt::settle(&fixture.store, verified, completed).unwrap();
    let config = crate::campaign::state_fixture::config(8 << 20, 100);
    let before = crate::campaign::census::census(&fixture.store, &config).unwrap();
    let path = fixture.case.state.clone();
    drop(fixture.store);
    let result = direct_pass(&path, false);
    assert_eq!(
        (result.deletions, result.changed, result.finished),
        (0, true, true)
    );
    assert_eq!(result.report["held"], json!([]));
    assert_eq!(result.report["entries"], json!([]));
    assert_eq!(result.report["reclaimed"].as_array().unwrap().len(), 1);
    let store = Store::open(&path).unwrap();
    let after = crate::campaign::census::census(&store, &config).unwrap();
    assert_eq!(
        u128::from(before.bytes - after.bytes),
        config.retained_charge().bytes - config.reclaimed_charge().bytes
    );
}

#[test]
fn resumed_marker_barrier_failures_precede_every_bulk_unlink() {
    let build = || {
        let (case, id) = populated();
        let store = Store::open(&case.state).unwrap();
        let root = crate::layout::attempts(&store, &id).unwrap().unwrap();
        let directory = store.open_dir(&root, &name("0001")).unwrap().unwrap();
        let (_, artifact, finished) = evidence_records(&store, &directory);
        store
            .create_record(
                &directory,
                &name("reclaimed"),
                &crate::record::Reclaimed::new(1, &finished, &artifact.record().bulk().unwrap()),
            )
            .unwrap();
        drop(store);
        (case, id)
    };
    let (case, _) = build();
    let (result, trace) = crate::store::fixture::scripted([], || collect(&case.state, false));
    result.unwrap().unwrap();
    let first = trace
        .iter()
        .position(|point| *point == Step::Unlink)
        .unwrap();
    let read = trace[..first]
        .iter()
        .rposition(|point| *point == Step::Read)
        .unwrap();
    let syncs: Vec<_> = trace[read + 1..first]
        .iter()
        .enumerate()
        .filter_map(|(index, point)| (*point == Step::Sync).then_some(read + 1 + index))
        .collect();
    assert_eq!(syncs.len(), 2);
    for index in syncs {
        let (case, _) = build();
        let before = snapshot(&case.state);
        let (result, trace) =
            crate::store::fixture::scripted([(index, Outcome::Errno(libc::EIO))], || {
                collect(&case.state, false)
            });
        assert_eq!(
            result.unwrap().unwrap_err().exit(),
            crate::exit::Supervisor::Held
        );
        assert_eq!(trace[index], Step::Sync);
        assert!(!trace.contains(&Step::Unlink));
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn unsettled_or_targeted_authority_holds_keep_unrelated_attempt_bulk() {
    for targeted in [false, true] {
        let fixture = Fixture::new();
        fixture.probe();
        let control = fixture.admit(0);
        fixture.finish(&control, Some(7));
        if targeted {
            let held = fixture.targeted(1);
            let jobs = fixture.store.shard_jobs(held.job().id()).unwrap().unwrap();
            fixture
                .store
                .create_once(
                    &jobs,
                    &name(&format!(
                        "{}{}",
                        held.job().id(),
                        crate::record::JobResult::SUFFIX
                    )),
                    b"damaged",
                )
                .unwrap();
        } else {
            let held = fixture.admit(1);
            let (directory, _, _) =
                fixture.finish_unsettled(&held, 1, Some(7), crate::record::Class::Interrupted);
            crate::custody::charge(
                &fixture.store,
                &directory,
                &crate::record::Text::new(&format!("{}-0001", held.job().id())).unwrap(),
            )
            .unwrap();
        }
        let path = fixture.case.state.clone();
        drop(fixture.store);
        let before = snapshot(&path.join("attempts"));
        let result = collect(&path, false).unwrap();
        assert!(!result["held"].as_array().unwrap().is_empty());
        assert_eq!(result["entries"], json!([]));
        assert_eq!(result["reclaimed"], json!([]));
        assert_eq!(snapshot(&path.join("attempts")), before);
    }
}

#[test]
fn planning_refuses_an_artifact_that_changed_after_its_verified_finish() {
    let (case, id) = populated();
    let view = View::open(&case.state).unwrap();
    let verified = super::super::report::snapshot(&view).unwrap();
    let root = crate::layout::attempts(&view, &id).unwrap().unwrap();
    let path = crate::layout::attempt_path(&id, 1).display().to_string();
    let candidate = unit(
        &view,
        &root,
        &id,
        1,
        &verified.histories[&id].attempts[0],
        &path,
    )
    .unwrap()
    .unwrap();
    let store = Store::open(&case.state).unwrap();
    let (evidence, artifact, _) = evidence_records(&store, &candidate.directory);
    let mut artifact = artifact.record().clone();
    artifact.reason = crate::record::Text::new("changed after verification").unwrap();
    store
        .replace_record(&evidence, &name("artifact"), &artifact)
        .unwrap();
    let before = snapshot(&case.state);
    let error = reclaim(&view, candidate, &id, 1, &path).err().unwrap();
    assert_eq!(error.to_string(), "artifact differs from the bound finish");
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn unsettled_ordinary_logs_require_a_valid_evidence_layout() {
    for damage in ["artifacts", "evidence", "staging"] {
        let fixture = Fixture::new();
        fixture.probe();
        let job = fixture.admit(0);
        let (directory, _, _) =
            fixture.finish_unsettled(&job, 1, Some(7), crate::record::Class::Interrupted);
        launcher_logs(&fixture.store, &directory, b"keep logs");
        let control = fixture.admit(1);
        fixture.finish(&control, Some(7));
        let id = job.job().id().to_string();
        let path = fixture.case.state.clone();
        drop(fixture.store);
        let attempt = path.join(crate::layout::attempt_path(&id, 1));
        let evidence = attempt.join("artifacts").join(format!("{id}-0001"));
        match damage {
            "artifacts" => fs::write(attempt.join("artifacts/scratch"), b"extra").unwrap(),
            "evidence" => fs::write(evidence.join("scratch"), b"extra").unwrap(),
            _ => {
                fs::write(evidence.join(".state"), crate::store::MARKER_BYTES).unwrap();
                fs::create_dir(evidence.join(".staging")).unwrap();
                fs::write(evidence.join(".staging/orphan"), b"extra").unwrap();
            }
        }
        let before = snapshot(&attempt);
        let result = collect(&path, false).unwrap();
        assert_eq!(
            result["held"][0]["path"],
            crate::layout::attempt_path(&id, 1).display().to_string(),
            "{result}"
        );
        assert_eq!(
            result["reclaimed"],
            json!([
                crate::layout::attempt_path(&control.job().id().to_string(), 1)
                    .display()
                    .to_string()
            ])
        );
        assert_eq!(snapshot(&attempt), before);
        for output in crate::custody::LAUNCHER_OUTPUTS {
            assert_eq!(fs::read(attempt.join(output)).unwrap(), b"keep logs");
        }
    }
}

#[test]
fn retained_stdout_guards_refuse_the_planner_input_directly() {
    for damage in ["oversized", "directory"] {
        let (case, id) = populated();
        let view = View::open(&case.state).unwrap();
        let verified = super::super::report::snapshot(&view).unwrap();
        let root = crate::layout::attempts(&view, &id).unwrap().unwrap();
        let path = crate::layout::attempt_path(&id, 1).display().to_string();
        let candidate = unit(
            &view,
            &root,
            &id,
            1,
            &verified.histories[&id].attempts[0],
            &path,
        )
        .unwrap()
        .unwrap();
        let output = case
            .state
            .join(&path)
            .join("artifacts")
            .join(format!("{id}-0001/inspect.stdout"));
        if damage == "oversized" {
            fs::write(&output, vec![b'x'; crate::sim::OUTPUT + 1]).unwrap();
        } else {
            fs::remove_file(&output).unwrap();
            fs::create_dir(&output).unwrap();
        }
        let error = super::super::reclaim::prepare(
            &view,
            &candidate.directory,
            &id,
            1,
            &candidate.finished,
            &path,
        )
        .err()
        .unwrap();
        let message = error.to_string();
        assert!(
            message.starts_with(&format!("{path}/artifacts/{id}-0001/inspect.stdout:")),
            "{message}"
        );
        if damage == "oversized" {
            assert!(
                message.ends_with("retained file exceeds its byte bound"),
                "{message}"
            );
        }
    }
}

#[test]
fn two_reclaim_plans_stop_at_the_first_boundary_and_preserve_the_next_marker() {
    let build = || {
        let fixture = Fixture::new();
        fixture.probe();
        for run in 0..2 {
            let job = fixture.admit(run);
            let directory = fixture.finish(&job, Some(7));
            for file in crate::custody::LAUNCHER_OUTPUTS {
                fixture
                    .store
                    .create_once(&directory, &name(file), b"two-plan log")
                    .unwrap();
            }
        }
        drop(fixture.store);
        fixture.case
    };
    let full = build();
    collect(&full.state, false).unwrap();
    let expected = comparable(&full.state);
    let case = build();
    let before = snapshot(&case.state);
    let store = Store::for_collection(&case.state).unwrap();
    let result = pass(&store, false, (2 + BULK) as usize, &mut || false).unwrap();
    assert_eq!(
        (result.deletions, result.finished, result.changed),
        ((2 + BULK) as usize, false, true)
    );
    assert_eq!(result.report["reclaimed"].as_array().unwrap().len(), 1);
    assert_partial_pass(&case, &before, &result);
    drop(store);
    collect(&case.state, false).unwrap();
    kept_bytes(&before, &case.state);
    assert_eq!(comparable(&case.state), expected);
}

#[test]
fn a_targeted_stage_cleanup_precedes_marker_headroom_and_a_killed_write_resumes() {
    let (control, id) = populated();
    fs::write(
        control.state.join(".staging/preserve"),
        b"other publication",
    )
    .unwrap();
    let store = Store::for_collection(&control.state).unwrap();
    let (result, trace) =
        crate::store::fixture::scripted([], || pass(&store, false, usize::MAX, &mut || false));
    assert!(result.unwrap().unwrap().finished);
    drop(store);
    let expected = comparable(&control.state);
    let marker = control
        .state
        .join(crate::layout::attempt_path(&id, 1))
        .join("reclaimed");
    let bytes = fs::metadata(marker).unwrap().len();
    let write = trace
        .iter()
        .position(|point| *point == Step::Write)
        .unwrap();
    let cut = write
        + 1
        + trace[write + 1..]
            .iter()
            .position(|point| *point == Step::Close)
            .unwrap();
    let (case, id) = populated();
    fs::write(case.state.join(".staging/preserve"), b"other publication").unwrap();
    let before = snapshot(&case.state);
    let store = Store::for_collection(&case.state).unwrap();
    let (killed, _) = crate::store::fixture::scripted([(cut, Outcome::Kill)], || {
        pass(&store, false, usize::MAX, &mut || false)
    });
    assert!(killed.is_none());
    drop(store);
    let staged: Vec<_> = fs::read_dir(case.state.join(".staging"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != "preserve")
        .collect();
    assert_eq!(staged.len(), 1);
    assert!(
        staged[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(".reclaimed")
    );
    assert!(
        !case
            .state
            .join(crate::layout::attempt_path(&id, 1))
            .join("reclaimed")
            .exists()
    );
    let store = Store::for_collection(&case.state).unwrap();
    let fragment = store.root().free_space().unwrap().2.get();
    let needed = bytes.next_multiple_of(fragment);
    let target = staged[0].clone();
    step::install(Some(Script {
        free_space: Some((needed, 1)),
        observe: Some(Box::new(move |point| {
            if point == Step::Census {
                assert!(
                    !target.exists(),
                    "staged allocation must be released before the marker preflight"
                );
            }
        })),
        ..Script::default()
    }));
    let result = pass(&store, false, usize::MAX, &mut || false);
    step::install(None);
    assert!(result.unwrap().finished);
    kept_bytes(&before, &case.state);
    assert_eq!(comparable(&case.state), expected);
    assert_eq!(
        fs::read(case.state.join(".staging/preserve")).unwrap(),
        b"other publication"
    );
}

#[test]
fn marker_preflight_accepts_its_rounded_boundary_and_propagates_a_stat_fault() {
    let (control, id) = populated();
    let store = Store::for_collection(&control.state).unwrap();
    let fragment = store.root().free_space().unwrap().2.get();
    let (_, trace) = crate::store::fixture::scripted([], || {
        pass(&store, false, usize::MAX, &mut || false).unwrap()
    });
    let marker = control
        .state
        .join(crate::layout::attempt_path(&id, 1))
        .join("reclaimed");
    let bytes = fs::metadata(marker).unwrap().len();
    let needed = bytes.next_multiple_of(fragment);
    for (free, finished) in [(needed - 1, false), (needed, true)] {
        let (case, id) = populated();
        let store = Store::for_collection(&case.state).unwrap();
        step::install(Some(Script {
            free_space: Some((free, 1)),
            ..Script::default()
        }));
        let result = pass(&store, false, usize::MAX, &mut || false);
        step::install(None);
        let result = result.unwrap();
        assert_eq!(result.finished, finished);
        assert_eq!(result.changed, finished);
        assert_eq!(
            case.state
                .join(crate::layout::attempt_path(&id, 1))
                .join("reclaimed")
                .exists(),
            finished
        );
    }
    let write = trace
        .iter()
        .position(|point| *point == Step::Write)
        .unwrap();
    let census = trace[..write]
        .iter()
        .rposition(|point| *point == Step::Census)
        .unwrap();
    let stat = trace[..census]
        .iter()
        .rposition(|point| *point == Step::Stat)
        .unwrap();
    let (case, _) = populated();
    let before = snapshot(&case.state);
    let store = Store::for_collection(&case.state).unwrap();
    let (result, reached) =
        crate::store::fixture::scripted([(stat, Outcome::Errno(libc::EIO))], || {
            pass(&store, false, usize::MAX, &mut || false)
        });
    assert!(result.unwrap().err().unwrap().host_fault());
    assert_eq!(reached[stat], Step::Stat);
    assert!(!reached.contains(&Step::Write));
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn typed_pass_diagnostics_exclude_verified_sources_and_escape_foreign_names() {
    let (case, _) = populated();
    assert_eq!(direct_pass(&case.state, true).held, None);
    let store = Store::open(&case.state).unwrap();
    crate::campaign::state_fixture::finished_probe(
        &store,
        "probe-extra",
        "/sys/fs/cgroup/campaign-released-probe",
        crate::record::Digest::parse(&"b".repeat(64)).unwrap(),
        crate::record::ProbeOutcome::Complete,
    );
    drop(store);
    fs::write(case.state.join("probes/probe-extra/bad\nname"), b"keep").unwrap();
    let result = direct_pass(&case.state, true);
    assert_eq!(
        result.held.as_deref(),
        Some("probes/probe-extra: probe holds unlisted entry bad\\nname")
    );
    assert!(!result.held.unwrap().contains('\n'));
}

#[test]
fn a_kill_during_staged_marker_release_then_a_rerun_preserves_records() {
    let prepare = || {
        let (case, id) = populated();
        let store = Store::for_collection(&case.state).unwrap();
        let root = crate::layout::attempts(&store, &id).unwrap().unwrap();
        let directory = store.open_dir(&root, &name("0001")).unwrap().unwrap();
        let staged = case
            .state
            .join(".staging")
            .join(format!("{:016x}.reclaimed", directory.identity().1));
        fs::write(&staged, b"interrupted marker").unwrap();
        (case, store, staged)
    };
    let (control, store, _) = prepare();
    let (_, trace) = crate::store::fixture::scripted([], || {
        pass(&store, false, usize::MAX, &mut || false).unwrap()
    });
    let expected = comparable(&control.state);
    let unlink = trace
        .iter()
        .position(|point| *point == Step::Unlink)
        .unwrap();
    assert_eq!(trace[unlink + 1], Step::Sync);
    for cut in [unlink, unlink + 1] {
        let (case, store, staged) = prepare();
        let before = snapshot(&case.state);
        let (result, reached) = crate::store::fixture::scripted([(cut, Outcome::Kill)], || {
            pass(&store, false, usize::MAX, &mut || false)
        });
        assert!(result.is_none());
        assert_eq!(reached, trace[..=cut]);
        assert_eq!(staged.exists(), cut == unlink);
        drop(store);
        collect(&case.state, false).unwrap();
        kept_bytes(&before, &case.state);
        assert_eq!(comparable(&case.state), expected);
        assert!(!staged.exists());
    }
}
