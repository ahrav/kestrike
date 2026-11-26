use super::Census;
use crate::campaign::state_fixture::counted_at;
use crate::campaign::state_fixture::{
    self, attempt, bundle, config, entries, job, probe, targeted,
};
use crate::record::BOUND;
use crate::step::{self, Outcome, Script, Step};
use crate::store::Store;
use crate::store::fixture::{Case, scripted};

/// Builds three jobs, three attempts and `probes` probes, each attempt and
/// probe holding `files` files.
fn built(case: &Case, probes: usize, files: usize) -> Store {
    let store = Store::open(&case.state).unwrap();
    let jobs: Vec<_> = (0..3).map(|run| job(&store, run)).collect();
    attempt(&store, &jobs[0], 1, files);
    attempt(&store, &jobs[0], 2, files);
    attempt(&store, &jobs[1], 1, files);
    for index in 0..probes {
        probe(&store, &format!("probe-{index}"), files);
    }
    store
}

/// The census of a built tree is the declared charge of its job-root
/// entries, concluded attempts and probes, whatever the attempts and probes
/// hold.
#[test]
fn a_built_census_equals_the_charge_sum() {
    let config = config(1 << 20, 100);
    for files in [0, 9] {
        let case = Case::new();
        let store = built(&case, 2, files);
        let usage = Census::count(&store)
            .unwrap()
            .usage(&store, &config)
            .unwrap();
        let retained = config.retained_charge();
        let listed: Vec<_> = state_fixture::job_file_lengths(&case.state)
            .into_iter()
            .map(u128::from)
            .collect();
        let jobs = listed.len() as u128;
        assert_eq!(jobs, 6);
        assert_eq!(
            u128::from(usage.bytes),
            listed.iter().sum::<u128>() + 3 * retained.bytes + 2 * 8 * u128::from(BOUND)
        );
        assert_eq!(
            u128::from(usage.inodes),
            jobs + 3 * retained.inodes + 2 * 16
        );
        assert_eq!(
            retained.bytes,
            (1 << 20)
                + 8 * u128::from(BOUND)
                + crate::record::Kind::Captured.bound() as u128
                + crate::record::Kind::Finding.bound() as u128
                + crate::record::Kind::Reclaimed.bound() as u128
        );
        assert_eq!(retained.inodes, 100 + 17);
    }
}

/// Two unmarked trees with the same root-level entries and different file counts
/// beneath them take the same steps to count, and the per-start usage
/// takes the same steps with no listing.
#[test]
fn equal_root_entries_take_equal_census_steps_and_usage_lists_nothing() {
    let config = config(1 << 20, 100);
    let traces: Vec<_> = [1, 12]
        .into_iter()
        .map(|files| {
            let case = Case::new();
            let store = built(&case, 3, files);
            let (census, counted) = scripted([], || Census::count(&store).unwrap());
            let census = census.unwrap();
            let (_, used) = scripted([], || census.usage(&store, &config).unwrap());
            (counted, used)
        })
        .collect();
    assert_eq!(traces[0], traces[1]);
    // The count lists ten directories, `jobs/` and its three shards,
    // `attempts/` and its two shards, two attempt histories and `probes/`,
    // in two batches each, opens each of the three attempts and its
    // `reclaimed` name, and reads two admission records; an attempt or
    // probe directory it also listed would add to these totals.
    let count = |step: Step| traces[0].0.iter().filter(|at| **at == step).count();
    assert_eq!(
        (count(Step::Open), count(Step::List), count(Step::Read)),
        (40, 20, 2)
    );
    assert!(!traces[0].1.contains(&Step::List));
    assert_eq!(traces[0].1, [Step::Stat, Step::Census]);
}

/// The in-process charges of one concluded attempt and two published
/// records of their lengths add what a fresh count reads after the tree
/// grows by them.
#[test]
fn session_charge_arithmetic_matches_a_fresh_count_of_the_grown_tree() {
    let case = Case::new();
    let store = built(&case, 1, 2);
    let mut census = Census::count(&store).unwrap();
    let grown = state_fixture::job(&store, 7);
    attempt(&store, &grown, 1, 4);
    for suffix in ["json", "manifest"] {
        let id = grown.job().id().to_string();
        let path = case
            .state
            .join(crate::layout::job_file(&id, &format!("{id}.{suffix}")));
        census
            .published(
                crate::layout::shard(&grown.job().id().to_string()).as_str(),
                std::fs::metadata(path).unwrap().len(),
            )
            .unwrap();
    }
    census.concluded(1);
    assert_eq!(census, Census::count(&store).unwrap());
}

/// A failed free-space query holds with exit 4 and names the call.
#[test]
fn a_failed_free_space_query_holds_and_names_fstatvfs() {
    let case = Case::new();
    let store = built(&case, 0, 0);
    let census = Census::count(&store).unwrap();
    step::install(Some(Script {
        nth: Some((Step::Census, 0, Outcome::Errno(libc::EIO))),
        ..Script::default()
    }));
    let failed = census.usage(&store, &config(1 << 20, 100));
    step::install(None);
    let error = failed.unwrap_err();
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(crate::campaign::triage::global(&error), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("fstatvfs of the state directory failed: "),
        "{error}"
    );
}

/// A `jobs/` entry that fails to open holds the census as a state-wide
/// store error naming the entry, which triage treats as a hold for every
/// finding.
#[test]
fn an_unopenable_job_entry_is_a_state_wide_hold() {
    let case = Case::new();
    let store = built(&case, 0, 0);
    std::fs::create_dir_all(case.state.join("jobs/ab")).unwrap();
    std::os::unix::fs::symlink("elsewhere", case.state.join("jobs/ab/linked.json")).unwrap();
    let error = Census::count(&store).unwrap_err();
    assert_state_wide(&error, "census of jobs/ab/linked.json: ");
    assert!(!error.host_fault());
    assert_eq!(error.held_code(), "unreadable");
}

/// A two-hex root entry that does not open as a directory holds the census
/// as a state-wide store error whose text names the entry to repair.
#[test]
fn a_root_entry_that_is_no_shard_directory_is_named_in_the_hold() {
    for root in ["jobs", "attempts"] {
        let case = Case::new();
        let store = built(&case, 0, 0);
        std::fs::create_dir_all(case.state.join(root)).unwrap();
        std::os::unix::fs::symlink("elsewhere", case.state.join(root).join("ab")).unwrap();
        let error = Census::count(&store).unwrap_err();
        assert_state_wide(&error, &format!("census of {root}: "));
        assert!(error.to_string().contains(&format!("{root}/ab")), "{error}");
        assert!(!error.host_fault());
    }
}

/// A listing that fails holds the census as a state-wide store error
/// naming the root it was listing.
#[test]
fn a_failed_listing_names_its_root() {
    let case = Case::new();
    let store = built(&case, 0, 0);
    let (_, trace) = scripted([], || Census::count(&store).unwrap());
    let list = trace.iter().position(|at| *at == Step::List).unwrap();
    let (counted, _) = scripted([(list, Outcome::Errno(libc::EIO))], || {
        Census::count(&store)
    });
    assert_state_wide(&counted.unwrap().unwrap_err(), "census of jobs: ");
    let (counted, _) = scripted([(list, Outcome::Errno(libc::EMFILE))], || {
        Census::count(&store)
    });
    let error = counted.unwrap().unwrap_err();
    assert_state_wide(
        &error,
        "census of jobs: descriptor limit reached (RLIMIT_NOFILE)",
    );
    assert!(error.host_fault());
    assert!(matches!(error, crate::campaign::Error::Census { cause, .. }
        if matches!(*cause, crate::campaign::Error::Store(crate::store::Error::Io(ref io))
            if io.raw_os_error() == Some(libc::EMFILE))));
}

/// A nonempty attempt history holds the census, naming the history, when
/// its job's admission record is missing or admits another job, and naming
/// the record when it fails its read, because one share would undercount a
/// targeted job's attempts. An empty history needs no record.
#[test]
fn an_attempt_history_without_its_bound_admission_record_holds() {
    for state in ["missing", "misbound", "damaged", "empty"] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let other = job(&store, 1);
        let ordinary = job(&store, 0);
        let target = targeted(&store, &ordinary, 2);
        let id = target.job().id().to_string();
        let record_path = crate::campaign::state_fixture::job_file(format!("{id}.json"));
        let record = case.state.join(&record_path);
        let history = crate::campaign::state_fixture::attempts_dir(&id);
        if state == "empty" {
            std::fs::create_dir_all(case.state.join(&history)).unwrap();
        } else {
            attempt(&store, &target, 1, 0);
        }
        match state {
            "missing" | "empty" => std::fs::remove_file(&record).unwrap(),
            "misbound" => std::fs::copy(
                case.state
                    .join(crate::campaign::state_fixture::job_file(format!(
                        "{}.json",
                        other.job().id()
                    ))),
                &record,
            )
            .map(drop)
            .unwrap(),
            "damaged" => {
                let mut bytes = std::fs::read(&record).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                std::fs::write(&record, bytes).unwrap();
            }
            _ => {}
        }
        let counted = Census::count(&store);
        match state {
            "empty" => assert!(counted.is_ok(), "{counted:?}"),
            "damaged" => assert_state_wide(
                &counted.unwrap_err(),
                &format!("census of {}: ", record_path.display()),
            ),
            _ => assert_state_wide(
                &counted.unwrap_err(),
                &format!(
                    "census of {}: history has no admission record {} bound to its job",
                    history.display(),
                    record_path.display()
                ),
            ),
        }
    }
}

/// Asserts that `error` holds with exit 4 for every triage finding and
/// that its text holds `text`.
fn assert_state_wide(error: &crate::campaign::Error, text: &str) {
    assert_eq!(error.exit(), crate::exit::Supervisor::Held, "{error}");
    assert!(crate::campaign::triage::global(error), "{error:?}");
    assert!(error.to_string().contains(text), "{error}");
}

/// A counted root at the scan bound holds the census and names the root.
#[test]
fn a_counted_root_at_the_scan_bound_holds() {
    let case = Case::new();
    let store = built(&case, 4, 0);
    let single = Case::new();
    let one = Store::open(&single.state).unwrap();
    let id = job(&one, 0).job().id().to_string();
    assert_eq!(
        counted_at(&one, 2).unwrap_err().to_string(),
        format!(
            "jobs/{} holds 2 entries at bound 2; collect or shard",
            crate::layout::shard(&id).as_str()
        )
    );
    assert!(counted_at(&store, 7).is_ok());
    probe(&store, "probe-4", 0);
    probe(&store, "probe-5", 0);
    probe(&store, "probe-6", 0);
    assert_eq!(
        counted_at(&store, 7).unwrap_err().to_string(),
        "probes holds 7 entries at bound 7; collect or shard"
    );
}

/// A `jobs/` entry is charged its file length, as a frozen bundle shows at
/// both sides of the record bound.
#[test]
fn a_job_root_entry_is_charged_its_length() {
    let config = config(1 << 20, 100);
    let charged = |bytes: usize| {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        bundle(&store, "f0frozen", bytes);
        Census::count(&store)
            .unwrap()
            .usage(&store, &config)
            .unwrap()
            .bytes
    };
    assert_eq!(charged(1), 1);
    assert_eq!(charged(BOUND as usize + 1), BOUND + 1);
}

/// Entries under `findings/` and `triage/` change neither the census nor
/// the steps that count it.
#[test]
fn findings_and_triage_entries_are_uncharged_and_unlisted() {
    let config = config(1 << 20, 100);
    let counted: Vec<_> = [0, 5]
        .into_iter()
        .map(|count| {
            let case = Case::new();
            let store = built(&case, 1, 1);
            entries(&store, "findings", count);
            entries(&store, "triage", count);
            let (census, trace) = scripted([], || Census::count(&store).unwrap());
            let usage = census.unwrap().usage(&store, &config).unwrap();
            (usage.bytes, usage.inodes, trace)
        })
        .collect();
    assert_eq!(counted[0], counted[1]);
    // Ten listings of two batches each: `findings/` and `triage/` are
    // never listed.
    assert_eq!(
        counted[0].2.iter().filter(|at| **at == Step::List).count(),
        20
    );
}

/// A corpus probe stages its bundle and then runs under the attempt budget,
/// so it is charged the in-flight attempt charge; an admission probe is
/// charged its custody budget.
#[test]
fn a_corpus_probe_is_charged_as_a_running_attempt() {
    let config = config(1 << 20, 100);
    let usage = |name: &str| {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        probe(&store, name, 0);
        Census::count(&store)
            .unwrap()
            .usage(&store, &config)
            .unwrap()
    };
    let corpus = usage("corpus-probe-1-2");
    let charge = config.charge();
    assert_eq!(u128::from(corpus.bytes), charge.bytes);
    assert_eq!(u128::from(corpus.inodes), charge.inodes);
    let retained = config.retained_charge();
    assert_eq!(charge.bytes, retained.bytes + (1 << 20));
    assert_eq!(charge.inodes, retained.inodes + 100);
    let admission = usage("probe-1-2");
    assert_eq!(admission.bytes, 8 * BOUND);
    assert_eq!(admission.inodes, 16);
}

/// A concluded attempt of a targeted job is charged its retained charge
/// times the job's fork shares, the factor custody scales its output
/// limits by.
#[test]
fn a_targeted_attempt_is_charged_at_its_fork_shares() {
    let config = config(1 << 20, 100);
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let ordinary = job(&store, 0);
    let target = targeted(&store, &ordinary, 2);
    assert_eq!(target.shares(), 3);
    attempt(&store, &target, 1, 0);
    attempt(&store, &target, 2, 0);
    let listed: u128 = state_fixture::job_file_lengths(&case.state)
        .into_iter()
        .map(u128::from)
        .sum();
    let usage = Census::count(&store)
        .unwrap()
        .usage(&store, &config)
        .unwrap();
    let retained = config.retained_charge();
    assert_eq!(u128::from(usage.bytes), listed + 2 * 3 * retained.bytes);
    assert_eq!(u128::from(usage.inodes), 3 + 2 * 3 * retained.inodes);
}

/// The `attempts/` root at the scan bound holds the census and names it.
#[test]
fn the_attempts_root_at_the_scan_bound_holds() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let shard = crate::layout::make_shard(&store, crate::layout::ATTEMPTS, "aa").unwrap();
    for index in 0..3 {
        store
            .mkdir(&shard, &crate::campaign::name(&format!("aa{index}")))
            .unwrap();
    }
    assert_eq!(
        counted_at(&store, 3).unwrap_err().to_string(),
        "attempts/aa holds 3 entries at bound 3; collect or shard"
    );
    assert!(counted_at(&store, 4).is_ok());
}

/// A job's attempt listing at the scan bound holds the census and names
/// `attempts/<xx>/<id>`; one entry below the bound counts.
#[test]
fn a_job_attempt_listing_at_the_scan_bound_names_the_job() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let only = job(&store, 0);
    for number in 1..=4 {
        attempt(&store, &only, number, 0);
    }
    assert_eq!(
        counted_at(&store, 4).unwrap_err().to_string(),
        format!(
            "{} holds 4 entries at bound 4; collect or shard",
            crate::campaign::state_fixture::attempts_dir(only.job().id().to_string()).display()
        )
    );
    assert!(counted_at(&store, 5).is_ok());
}

/// A listing past the scan bound holds with the `more than` form, and a
/// session census whose published records reach the bound holds at its
/// publication and next usage.
#[test]
fn a_census_past_or_grown_to_the_bound_holds() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let id = job(&store, 0).job().id().to_string();
    let shard = format!("jobs/{}", crate::layout::shard(&id).as_str());
    assert_eq!(
        counted_at(&store, 1).unwrap_err().to_string(),
        format!("{shard} holds more than 1 entries at bound 1; collect or shard")
    );
    let config = config(1 << 20, 100);
    step::install(Some(Script {
        scan_bound: Some(3),
        ..Script::default()
    }));
    let mut census = Census::count(&store).unwrap();
    let below = census.usage(&store, &config);
    let publication = census.published(crate::layout::shard(&id).as_str(), 1);
    let held = census.usage(&store, &config).map(drop);
    step::install(None);
    let below = below.unwrap();
    let bytes: u64 = state_fixture::job_file_lengths(&case.state).iter().sum();
    assert_eq!((below.inodes, below.bytes), (2, bytes));
    assert_eq!(
        publication.unwrap_err().to_string(),
        format!("{shard} holds 3 entries at bound 3; collect or shard")
    );
    assert_eq!(
        held.unwrap_err().to_string(),
        format!("{shard} holds 3 entries at bound 3; collect or shard")
    );
}

/// A lower `attempt_output` and `attempt_inodes` installed while attempts
/// exist lowers the census charge of each concluded attempt by the
/// difference.
#[test]
fn a_lowered_attempt_budget_lowers_each_attempt_charge() {
    let case = Case::new();
    let store = built(&case, 0, 0);
    let mut settings = config(4 << 20, 100).config().clone();
    settings.insert(crate::record::Text::new("slots").unwrap(), 1);
    let high = crate::record::Configuration::new(settings.clone()).unwrap();
    crate::campaign::configure(&store, high.clone()).unwrap();
    let census = Census::count(&store).unwrap();
    let before = census.usage(&store, &high).unwrap();
    settings.insert(crate::record::Text::new("attempt_output").unwrap(), 1 << 20);
    settings.insert(crate::record::Text::new("attempt_inodes").unwrap(), 50);
    let low =
        crate::campaign::configure(&store, crate::record::Configuration::new(settings).unwrap())
            .unwrap();
    let after = census.usage(&store, &low).unwrap();
    assert_eq!(before.bytes - after.bytes, 3 * (3 << 20));
    assert_eq!(before.inodes - after.inodes, 3 * 50);
}

#[test]
fn a_real_reclaimed_attempt_is_charged_for_its_records_and_kept_streams() {
    let config = config(8 << 20, 100);
    let fixture = crate::campaign::report::tests::Fixture::new();
    let job = fixture.admit(0);
    fixture.finish_at_with_listing(
        &job,
        1,
        Some(7),
        crate::record::Class::Pass,
        Some(include_bytes!("../../testdata/admission-listing.txt")),
    );
    let before = Census::count(&fixture.store)
        .unwrap()
        .usage(&fixture.store, &config)
        .unwrap();
    let path = fixture.case.state.clone();
    drop(fixture.store);
    let collected = crate::campaign::collect::collect(&path, false).unwrap();
    assert_eq!(collected["held"], serde_json::json!([]));
    let store = Store::open(&path).unwrap();
    let after = Census::count(&store)
        .unwrap()
        .usage(&store, &config)
        .unwrap();
    let retained = config.retained_charge();
    let reclaimed = config.reclaimed_charge();
    assert_eq!(
        u128::from(before.bytes - after.bytes),
        retained.bytes - reclaimed.bytes
    );
    assert_eq!(
        u128::from(before.inodes - after.inodes),
        retained.inodes - reclaimed.inodes
    );
    assert_eq!(retained.bytes - reclaimed.bytes, 4 << 20);
    assert_eq!(retained.inodes - reclaimed.inodes, 100 - 6);
    let attempt = path.join(crate::layout::attempt_path(&job.job().id().to_string(), 1));
    let entries = crate::store::fixture::snapshot(&attempt);
    let bytes: u128 = entries
        .values()
        .filter_map(Option::as_ref)
        .map(|bytes| bytes.len() as u128)
        .sum();
    assert!(bytes <= reclaimed.bytes);
    assert!((entries.len() as u128) < reclaimed.inodes);
}

#[test]
fn reclaimed_charge_clamps_to_small_retained_budgets() {
    let config = config(1 << 20, 4);
    assert_eq!(
        config.reclaimed_charge().bytes,
        config.retained_charge().bytes
    );
    assert_eq!(
        config.reclaimed_charge().inodes,
        config.retained_charge().inodes
    );
}

#[test]
fn damaged_or_misbound_reclaim_markers_keep_the_retained_charge() {
    for damage in ["malformed", "number", "finish", "names"] {
        let fixture = crate::campaign::report::tests::Fixture::new();
        let job = fixture.admit(0);
        let directory = fixture.finish(&job, Some(7));
        let path = fixture.case.state.clone();
        let config = config(8 << 20, 100);
        let before = Census::count(&fixture.store)
            .unwrap()
            .usage(&fixture.store, &config)
            .unwrap();
        drop(fixture.store);
        crate::campaign::collect::collect(&path, false).unwrap();
        let store = Store::open(&path).unwrap();
        let mut marker = store
            .read_record::<crate::record::Reclaimed>(
                &directory,
                &crate::campaign::name("reclaimed"),
            )
            .unwrap()
            .unwrap()
            .record()
            .clone();
        match damage {
            "number" => marker.attempt += 1,
            "finish" => marker.finished = crate::record::Digest::of(b"other"),
            "names" => marker.names.clear(),
            _ => {}
        }
        if damage == "malformed" {
            store
                .replace(
                    &directory,
                    &crate::campaign::name("reclaimed"),
                    b"reclaimed",
                )
                .unwrap();
        } else {
            store
                .replace_record(&directory, &crate::campaign::name("reclaimed"), &marker)
                .unwrap();
        }
        let usage = Census::count(&store)
            .unwrap()
            .usage(&store, &config)
            .unwrap();
        assert_eq!(
            (usage.bytes, usage.inodes),
            (before.bytes, before.inodes),
            "{damage}"
        );
    }
}

#[test]
fn damaged_attempt_and_reclaim_opens_keep_the_concluded_charge() {
    for (entry, kind) in [
        ("0001", "file"),
        ("0001", "symlink"),
        ("0001/reclaimed", "directory"),
        ("0001/reclaimed", "symlink"),
    ] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let job = job(&store, 0);
        attempt(&store, &job, 1, 0);
        let root = state_fixture::attempts_dir(job.job().id().to_string());
        let path = case.state.join(&root).join(entry);
        if entry == "0001" {
            std::fs::remove_dir(&path).unwrap();
        }
        match kind {
            "file" => std::fs::write(&path, b"file").unwrap(),
            "directory" => std::fs::create_dir(&path).unwrap(),
            _ => std::os::unix::fs::symlink("elsewhere", &path).unwrap(),
        }
        let census = Census::count(&store).unwrap();
        assert_eq!(census.reclaimed_shares, 0);
        assert_eq!(census.attempt_shares, 1);
    }
}

#[test]
fn a_census_whose_total_reaches_the_bound_with_no_full_shard_counts() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for run in 0..4 {
        job(&store, run);
    }
    let shards: Vec<usize> = crate::campaign::state_fixture::job_file_lengths_by_shard(&case.state)
        .iter()
        .map(Vec::len)
        .collect();
    let total: usize = shards.iter().sum();
    assert!(shards.iter().all(|&entries| entries < total), "{shards:?}");
    step::install(Some(Script {
        scan_bound: Some(total),
        ..Script::default()
    }));
    let counted =
        Census::count(&store).and_then(|census| census.usage(&store, &config(1 << 20, 100)));
    step::install(None);
    let usage = counted.unwrap();
    let bytes: u64 = state_fixture::job_file_lengths(&case.state).iter().sum();
    assert_eq!((usage.inodes, usage.bytes), (total as u64, bytes));
}

#[test]
fn census_names_the_listed_path_of_a_misplaced_history() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    std::fs::create_dir_all(case.state.join("attempts/ab/notes/0001")).unwrap();
    let error = Census::count(&store).unwrap_err();
    assert!(error.to_string().contains("attempts/ab/notes"), "{error}");
    assert!(!error.to_string().contains("attempts/no/notes"), "{error}");
}

fn real_reclaim() -> (
    Case,
    String,
    crate::record::Configuration,
    crate::store::Usage,
) {
    let fixture = crate::campaign::report::tests::Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish(&job, Some(7));
    let config = config(8 << 20, 100);
    let before = Census::count(&fixture.store)
        .unwrap()
        .usage(&fixture.store, &config)
        .unwrap();
    let id = job.job().id().to_string();
    drop(fixture.store);
    crate::campaign::collect::collect(&fixture.case.state, false).unwrap();
    (fixture.case, id, config, before)
}

#[test]
fn every_restored_bulk_name_and_invalid_retained_layout_keeps_the_full_charge() {
    let (reference, id, _, _) = real_reclaim();
    let root = reference.state.join(crate::layout::attempt_path(&id, 1));
    let store = Store::open(&reference.state).unwrap();
    let attempts = crate::layout::attempts(&store, &id).unwrap().unwrap();
    let directory = store
        .open_dir(&attempts, &crate::campaign::name("0001"))
        .unwrap()
        .unwrap();
    let marker = store
        .read_record::<crate::record::Reclaimed>(&directory, &crate::campaign::name("reclaimed"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    assert!(root.join("reclaimed").is_file());
    drop(store);
    for entry in &marker.names {
        let (case, id, config, before) = real_reclaim();
        let path = case.state.join(crate::layout::attempt_path(&id, 1));
        std::fs::write(path.join(entry.as_str()), b"restored bulk").unwrap();
        let store = Store::open(&case.state).unwrap();
        let after = Census::count(&store)
            .unwrap()
            .usage(&store, &config)
            .unwrap();
        assert_eq!(
            (after.bytes, after.inodes),
            (before.bytes, before.inodes),
            "{}",
            entry.as_str()
        );
    }
    for damage in [
        "artifact-missing",
        "artifact-malformed",
        "artifact-replaced",
        "finish-malformed",
        "finish-unbound",
        "finish-binding",
        "finish-attempt",
        "bound-attempt",
        "bound-bundle",
        "oversized-record",
        "nonregular-record",
        "manifest-missing",
        "manifest-damaged",
        "extra-evidence",
        "undeclared-stdout",
        "oversized-stdout",
        "nonregular-stdout",
        "staging",
        "foreign-marker",
        "extra-artifacts",
        "attempt-dotfile",
    ] {
        let (case, id, config, before) = real_reclaim();
        let path = case.state.join(crate::layout::attempt_path(&id, 1));
        let evidence = path.join("artifacts").join(format!("{id}-0001"));
        let store = Store::open(&case.state).unwrap();
        let attempts = crate::layout::attempts(&store, &id).unwrap().unwrap();
        let directory = store
            .open_dir(&attempts, &crate::campaign::name("0001"))
            .unwrap()
            .unwrap();
        let artifacts = store
            .open_dir(&directory, &crate::campaign::name("artifacts"))
            .unwrap()
            .unwrap();
        let record_dir = store
            .open_dir(&artifacts, &crate::campaign::name(&format!("{id}-0001")))
            .unwrap()
            .unwrap();
        match damage {
            "artifact-missing" => std::fs::remove_file(evidence.join("artifact")).unwrap(),
            "artifact-malformed" => {
                std::fs::write(evidence.join("artifact"), b"malformed").unwrap()
            }
            "artifact-replaced" => {
                let mut artifact = store
                    .read_record::<crate::record::Artifact>(
                        &record_dir,
                        &crate::campaign::name("artifact"),
                    )
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                artifact.reason = crate::record::Text::new("replaced").unwrap();
                store
                    .replace_record(&record_dir, &crate::campaign::name("artifact"), &artifact)
                    .unwrap();
            }
            "finish-malformed" => std::fs::write(path.join("finished"), b"malformed").unwrap(),
            "finish-unbound" | "finish-binding" | "finish-attempt" | "bound-attempt"
            | "bound-bundle" => {
                let mut finish = store
                    .read_record::<crate::record::Finished>(
                        &directory,
                        &crate::campaign::name("finished"),
                    )
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                match damage {
                    "finish-unbound" => finish.bound = None,
                    "finish-binding" => finish.binding = crate::record::Binding::Missing,
                    "finish-attempt" => {
                        finish.attempt = crate::record::Text::new("other-0001").unwrap()
                    }
                    "bound-attempt" => {
                        finish.bound.as_mut().unwrap().attempt =
                            crate::record::Text::new("other-0001").unwrap()
                    }
                    _ => finish.bound.as_mut().unwrap().bundle = None,
                }
                store
                    .replace_record(&directory, &crate::campaign::name("finished"), &finish)
                    .unwrap();
                let mut marker = store
                    .read_record::<crate::record::Reclaimed>(
                        &directory,
                        &crate::campaign::name("reclaimed"),
                    )
                    .unwrap()
                    .unwrap()
                    .record()
                    .clone();
                marker.finished = crate::record::Digest::of(
                    store
                        .read_record::<crate::record::Finished>(
                            &directory,
                            &crate::campaign::name("finished"),
                        )
                        .unwrap()
                        .unwrap()
                        .read()
                        .bytes(),
                );
                store
                    .replace_record(&directory, &crate::campaign::name("reclaimed"), &marker)
                    .unwrap();
            }
            "oversized-record" => std::fs::write(
                path.join("started"),
                vec![b'x'; crate::record::BOUND as usize + 1],
            )
            .unwrap(),
            "nonregular-record" => {
                std::fs::remove_file(path.join("started")).unwrap();
                std::fs::create_dir(path.join("started")).unwrap();
            }
            "manifest-missing" => std::fs::remove_file(evidence.join("manifest")).unwrap(),
            "manifest-damaged" => std::fs::write(evidence.join("manifest"), b"damaged").unwrap(),
            "extra-evidence" => std::fs::write(evidence.join("scratch"), b"extra").unwrap(),
            "undeclared-stdout" => {
                std::fs::write(evidence.join("capabilities.stdout"), b"extra").unwrap()
            }
            "oversized-stdout" => std::fs::write(
                evidence.join("inspect.stdout"),
                vec![b'x'; crate::sim::OUTPUT + 1],
            )
            .unwrap(),
            "nonregular-stdout" => {
                std::fs::remove_file(evidence.join("inspect.stdout")).unwrap();
                std::fs::create_dir(evidence.join("inspect.stdout")).unwrap();
            }
            "staging" => {
                std::fs::write(evidence.join(".state"), crate::store::MARKER_BYTES).unwrap();
                std::fs::create_dir_all(evidence.join(".staging")).unwrap();
                std::fs::write(evidence.join(".staging/orphan"), b"extra").unwrap();
            }
            "foreign-marker" => std::fs::write(evidence.join(".state"), b"foreign").unwrap(),
            "extra-artifacts" => std::fs::write(path.join("artifacts/scratch"), b"extra").unwrap(),
            _ => std::fs::write(path.join(".worker"), b"extra").unwrap(),
        }
        let after = Census::count(&store)
            .unwrap()
            .usage(&store, &config)
            .unwrap();
        assert_eq!(
            (after.bytes, after.inodes),
            (before.bytes, before.inodes),
            "{damage}"
        );
    }
}

#[test]
fn a_long_noncanonical_attempt_name_preserves_the_charge_without_panicking() {
    let (case, id, config, before) = real_reclaim();
    let old = case.state.join(crate::layout::attempt_path(&id, 1));
    let long = format!("{}1", "0".repeat(199));
    let new = old.with_file_name(&long);
    std::fs::rename(old, &new).unwrap();
    let store = Store::open(&case.state).unwrap();
    let attempts = crate::layout::attempts(&store, &id).unwrap().unwrap();
    let directory = store
        .open_dir(&attempts, &crate::campaign::name(&long))
        .unwrap()
        .unwrap();
    let mut finish = store
        .read_record::<crate::record::Finished>(&directory, &crate::campaign::name("finished"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    finish.attempt = crate::record::Text::new(&format!("{id}-{long}")).unwrap();
    store
        .replace_record(&directory, &crate::campaign::name("finished"), &finish)
        .unwrap();
    let mut marker = store
        .read_record::<crate::record::Reclaimed>(&directory, &crate::campaign::name("reclaimed"))
        .unwrap()
        .unwrap()
        .record()
        .clone();
    marker.finished = crate::record::Digest::of(
        store
            .read_record::<crate::record::Finished>(&directory, &crate::campaign::name("finished"))
            .unwrap()
            .unwrap()
            .read()
            .bytes(),
    );
    store
        .replace_record(&directory, &crate::campaign::name("reclaimed"), &marker)
        .unwrap();
    let after = Census::count(&store)
        .unwrap()
        .usage(&store, &config)
        .unwrap();
    assert_eq!((after.bytes, after.inodes), (before.bytes, before.inodes));
}

#[test]
fn a_completed_reclaims_probe_cost_is_independent_of_retained_stdout_length() {
    let fixture = crate::campaign::report::tests::Fixture::new();
    fixture.probe();
    let job = fixture.admit(0);
    fixture.finish(&job, Some(7));
    let (_, before) = scripted([], || Census::count(&fixture.store).unwrap());
    drop(fixture.store);
    crate::campaign::collect::collect(&fixture.case.state, false).unwrap();
    let store = Store::open(&fixture.case.state).unwrap();
    let (_, after) = scripted([], || Census::count(&store).unwrap());
    let count = |trace: &[Step], step| trace.iter().filter(|point| **point == step).count();
    let delta = [Step::Open, Step::Stat, Step::List, Step::Read]
        .map(|step| count(&after, step) - count(&before, step));
    let retained_reads = ["finished", "artifact", "manifest"].len();
    let controller_files = [
        "attempt",
        "intent",
        "started",
        "bound",
        "finished",
        "captured",
        "reclaimed",
    ]
    .len();
    let bulk_probes = [
        "bundle",
        "run.stdout",
        "run.stderr",
        "inspect.stderr",
        "launcher.stdout",
        "launcher.stderr",
    ]
    .len();
    let listed_directories = ["attempt", "artifacts", "evidence"].len();
    let opens =
        1 + 2 * retained_reads + controller_files + bulk_probes + listed_directories + 2 + 1;
    let stats = 2 + 2 * retained_reads + controller_files + 2 + 1;
    assert_eq!(
        delta,
        [opens, stats, 2 * listed_directories, 1 + retained_reads]
    );
    assert_eq!(count(&before, Step::Census), count(&after, Step::Census));
    let evidence = fixture
        .case
        .state
        .join(crate::layout::attempt_path(&job.job().id().to_string(), 1))
        .join("artifacts")
        .join(format!("{}-0001", job.job().id()));
    std::fs::write(
        evidence.join("inspect.stdout"),
        vec![b'x'; crate::sim::OUTPUT],
    )
    .unwrap();
    let (_, longer) = scripted([], || Census::count(&store).unwrap());
    assert_eq!(after, longer);
}

#[test]
fn retained_record_host_read_faults_name_the_entry_and_remain_state_wide() {
    let (case, id, _, _) = real_reclaim();
    let store = Store::open(&case.state).unwrap();
    let root = crate::layout::attempt_path(&id, 1).display().to_string();
    let (_, trace) = scripted([], || Census::count(&store).unwrap());
    let reads: Vec<_> = trace
        .iter()
        .enumerate()
        .filter_map(|(index, point)| (*point == Step::Read).then_some(index))
        .collect();
    assert_eq!(reads.len(), 5);
    for (index, suffix) in reads[1..].iter().zip([
        "reclaimed".to_owned(),
        "finished".into(),
        format!("artifacts/{id}-0001/artifact"),
        format!("artifacts/{id}-0001/manifest"),
    ]) {
        let (result, _) = scripted([(*index, Outcome::Errno(libc::EIO))], || {
            Census::count(&store)
        });
        assert_state_wide(
            &result.unwrap().unwrap_err(),
            &format!("census of {root}/{suffix}: "),
        );
    }
}

#[test]
fn every_retained_layout_probe_fault_stays_state_wide() {
    for marked in [false, true] {
        let (case, id, _, _) = real_reclaim();
        let path = case.state.join(crate::layout::attempt_path(&id, 1));
        let evidence = path.join("artifacts").join(format!("{id}-0001"));
        if marked {
            std::fs::write(evidence.join(".state"), crate::store::MARKER_BYTES).unwrap();
            std::fs::create_dir(evidence.join(".staging")).unwrap();
        }
        let store = Store::open(&case.state).unwrap();
        let (_, trace) = scripted([], || Census::count(&store).unwrap());
        let start = trace.iter().position(|step| *step == Step::Read).unwrap();
        for (index, point) in trace.iter().enumerate().skip(start) {
            if !matches!(point, Step::Open | Step::Stat | Step::List | Step::Read) {
                continue;
            }
            let (result, reached) = scripted([(index, Outcome::Errno(libc::EIO))], || {
                Census::count(&store)
            });
            let error = result.unwrap().unwrap_err();
            assert_eq!(reached[index], *point, "{index} {point:?}");
            assert!(error.host_fault(), "{index} {point:?}: {error}");
            assert_state_wide(&error, "census of ");
        }
    }
}

#[test]
fn a_short_noncanonical_attempt_name_keeps_the_concluded_charge() {
    let (case, id, config, before) = real_reclaim();
    let old = case.state.join(crate::layout::attempt_path(&id, 1));
    std::fs::rename(&old, old.with_file_name("00001")).unwrap();
    let store = Store::open(&case.state).unwrap();
    let after = Census::count(&store)
        .unwrap()
        .usage(&store, &config)
        .unwrap();
    assert_eq!((after.bytes, after.inodes), (before.bytes, before.inodes));
}

#[test]
fn an_overfull_retained_evidence_listing_keeps_the_concluded_charge() {
    let (case, id, config, before) = real_reclaim();
    let evidence = case
        .state
        .join(crate::layout::attempt_path(&id, 1))
        .join("artifacts")
        .join(format!("{id}-0001"));
    for index in 0..20 {
        std::fs::write(evidence.join(format!("extra-{index}")), b"extra").unwrap();
    }
    let store = Store::open(&case.state).unwrap();
    let (after, trace) = crate::store::fixture::bounded(16, || {
        Census::count(&store)
            .unwrap()
            .usage(&store, &config)
            .unwrap()
    });
    assert!(trace.contains(&Step::List));
    assert_eq!((after.bytes, after.inodes), (before.bytes, before.inodes));
}
