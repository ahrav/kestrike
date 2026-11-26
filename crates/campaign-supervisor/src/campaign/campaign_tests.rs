use super::*;
use crate::campaign::state_fixture::Sharded;
use crate::protocol::Listing;
use crate::record::{Admission, Pins, Purpose, Text};
use crate::step::{Outcome as Fault, Step};
use crate::store::fixture::{Case, observed, scripted, snapshot};
use crate::store::{Store, View};

#[test]
fn the_current_worker_listing_freezes_a_live_job_with_every_schema_key() {
    let listing = Listing::parse(include_str!("../../testdata/worker-listing.txt")).unwrap();
    let mut request = request();
    request.counts.clear();
    let (job, manifest) = freeze::freeze(&listing, pins(), &request).unwrap();
    assert_eq!(job.experiment().profile.as_str(), "upload");
    assert_eq!(
        job.experiment().counts.len(),
        listing
            .keys
            .iter()
            .filter(
                |key| key.name != "root" && matches!(key.form, crate::protocol::Form::Count { .. })
            )
            .count()
    );
    assert_eq!(manifest.lines().count(), listing.keys.len());
    assert_eq!(
        job.experiment().counts[&text("source_bytes").unwrap()],
        65536
    );
    request.profile = text("cluster-broad").unwrap();
    let (job, _) = freeze::freeze(&listing, pins(), &request).unwrap();
    assert_eq!(job.experiment().generator.as_ref().unwrap().as_str(), "1");
    assert_eq!(
        job.experiment().minima.as_ref().unwrap().as_str(),
        "published:4,hits:1,cross:0,faults:1,healthy:3,reused:0"
    );
}

#[test]
fn a_frozen_experiment_records_the_version_its_listing_printed() {
    let current = Listing::parse(include_str!("../../testdata/worker-listing.txt")).unwrap();
    let mut defaults = request();
    defaults.counts.clear();
    for (listing, request, version) in [(current, defaults, "2"), (listing(), request(), "1")] {
        let (job, _) = freeze::freeze(&listing, pins(), &request).unwrap();
        assert_eq!(job.experiment().capabilities.as_str(), version);
    }
}

/// The request of the first run after 0 whose job shares the shard of
/// `first`.
fn same_shard(first: &Admission) -> Request {
    let shard = crate::layout::shard(&first.job().id().to_string());
    (1..)
        .map(|run| {
            let mut changed = request();
            changed.run = run;
            changed
        })
        .find(|changed| {
            let (job, _) = freeze::freeze(&listing(), pins(), changed).unwrap();
            crate::layout::shard(&job.id().to_string()) == shard
        })
        .unwrap()
}

#[test]
fn job_entry_capacity_refuses_new_pairs_and_allows_duplicates_and_one_file_orphans() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let first = admit(&store, &request()).unwrap().record;
    let jobs = case
        .state
        .join("jobs")
        .join(crate::layout::shard(&first.job().id().to_string()).as_str());
    let bound = 16;
    for index in 0..bound - 4 {
        std::fs::write(jobs.join(format!("retained-{index}")), b"").unwrap();
    }
    let changed = same_shard(&first);
    crate::step::install(Some(crate::step::Script {
        scan_bound: Some(bound),
        ..crate::step::Script::default()
    }));
    assert!(admit(&store, &request()).unwrap().existing);
    let before = snapshot(&case.state);
    // The listing holds fewer than the bound entries; the hold names the
    // projected count, which the reserved settlement entries push past it.
    assert!(matches!(
        admit(&store, &changed),
        Err(Error::Bound { root, entries: Some(projected), .. })
            if root == format!("jobs/{}", crate::layout::shard(&first.job().id().to_string()).as_str()) && projected == bound + 4
    ));
    assert_eq!(snapshot(&case.state), before);
    std::fs::remove_file(jobs.join("retained-0")).unwrap();
    assert!(
        matches!(admit(&store, &changed), Err(Error::Bound { root, entries: Some(projected), .. }) if root == format!("jobs/{}", crate::layout::shard(&first.job().id().to_string()).as_str()) && projected == bound + 3)
    );
    std::fs::write(jobs.join("retained-0"), b"").unwrap();
    let directory = store.shard_jobs(first.job().id()).unwrap().unwrap();
    store
        .delete(&directory, &name(&format!("{}.json", first.job().id())))
        .unwrap();
    assert!(!admit(&store, &request()).unwrap().existing);
    assert!(admit(&store, &request()).unwrap().existing);
    crate::step::install(None);
    assert_eq!(std::fs::read_dir(&jobs).unwrap().count(), bound - 2);
}

#[test]
fn duplicate_admission_keeps_the_original_archive_path_and_default_identity_fields() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let first = admit(&store, &request()).unwrap().record;
    let before = snapshot(&case.state);
    let duplicate = admission::admit(
        &store,
        &listing(),
        pins(),
        text("/other-archive").unwrap(),
        &request(),
        Purpose::Campaign,
    )
    .unwrap();
    assert!(duplicate.existing);
    assert_eq!(duplicate.record, first);
    assert_eq!(snapshot(&case.state), before);
    assert_eq!(first.job().experiment().run, 0);
    assert_eq!(first.job().experiment().attempts, 3);
}

#[test]
fn unavailable_profiles_and_non_count_overrides_refuse_before_job_publication() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for fault in 0..4 {
        let mut listing = listing();
        let mut request = request();
        match fault {
            0 => request.profile = text("unknown-profile").unwrap(),
            1 => listing.profiles[0].support = "unsupported".into(),
            2 => listing.profiles[0].campaign = "qualified".into(),
            3 => {
                request.counts.insert(text("build").unwrap(), 1);
            }
            _ => unreachable!(),
        }
        let before = snapshot(&case.state);
        assert!(matches!(
            admission::admit(
                &store,
                &listing,
                pins(),
                text("/archive").unwrap(),
                &request,
                Purpose::Campaign
            ),
            Err(Error::Rejected(_))
        ));
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn recorder_manifest_room_has_exact_count_and_byte_boundaries() {
    for (every, room) in [(5, 16), (1, 23)] {
        let mut request = request();
        request.counts.insert(text("every").unwrap(), every);
        request.counts.insert(text("records").unwrap(), room);
        let (_, manifest) = freeze::freeze(&listing(), pins(), &request).unwrap();
        let bytes: usize = manifest
            .lines()
            .filter(|line| !line.starts_with("cpu = "))
            .map(|line| line.len() + 1)
            .sum();
        assert_eq!(bytes.div_ceil(43), 8);
        assert!(bytes % 43 > 26);
        request.counts.insert(text("records").unwrap(), room - 1);
        assert!(matches!(
            freeze::freeze(&listing(), pins(), &request),
            Err(Error::Rejected(_))
        ));
        request.counts.insert(text("records").unwrap(), 80);
        request.counts.insert(text("bytes").unwrap(), room * 48);
        assert!(freeze::freeze(&listing(), pins(), &request).is_ok());
        request.counts.insert(text("bytes").unwrap(), room * 48 - 1);
        assert!(matches!(
            freeze::freeze(&listing(), pins(), &request),
            Err(Error::Rejected(_))
        ));
    }
}

#[test]
fn cluster_generator_and_minima_are_frozen_into_identity() {
    let mut request = request();
    request.profile = text("cluster-broad").unwrap();
    let mut listing = listing();
    let (first, manifest) = freeze::freeze(&listing, pins(), &request).unwrap();
    assert_eq!(first.experiment().generator.as_ref().unwrap().as_str(), "1");
    assert_eq!(
        first.experiment().minima.as_ref().unwrap().as_str(),
        "published:4,hits:1,cross:0,faults:1,healthy:3,reused:0"
    );
    assert!(manifest.contains("profile = cluster-broad\n"));
    listing.clusters[0]
        .fields
        .iter_mut()
        .find(|(key, _)| key == "minima")
        .unwrap()
        .1 = "published:2,hits:3".into();
    let (second, other) = freeze::freeze(&listing, pins(), &request).unwrap();
    assert_eq!(
        second.experiment().minima.as_ref().unwrap().as_str(),
        "published:2,hits:3"
    );
    assert_ne!(first.id(), second.id());
    assert_ne!(first.seed(), second.seed());
    assert_ne!(manifest, other);
    listing.clusters[0]
        .fields
        .iter_mut()
        .find(|(key, _)| key == "generator")
        .unwrap()
        .1 = "2".into();
    let (third, _) = freeze::freeze(&listing, pins(), &request).unwrap();
    assert_eq!(third.experiment().generator.as_ref().unwrap().as_str(), "2");
    assert_ne!(third.id(), second.id());
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let before = snapshot(&case.state);
    for missing in ["generator", "minima"] {
        let mut bad = listing.clone();
        bad.clusters[0].fields.retain(|(key, _)| key != missing);
        let error = admission::admit(
            &store,
            &bad,
            pins(),
            text("/archive").unwrap(),
            &request,
            Purpose::Campaign,
        )
        .err()
        .unwrap();
        assert_eq!(error.to_string(), format!("cluster requires {missing}"));
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn campaign_profiles_expect_passes_and_calibration_can_admit_controls() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    for (class, expected) in [
        (crate::protocol::Class::Control, None),
        (
            crate::protocol::Class::History,
            Some(crate::protocol::Expected::Violation),
        ),
        (
            crate::protocol::Class::History,
            Some(crate::protocol::Expected::Unsuccessful),
        ),
    ] {
        let mut listing = listing();
        listing.profiles[0].class = class;
        listing.profiles[0].expected = expected;
        let before = snapshot(&case.state);
        let refused = admission::admit(
            &store,
            &listing,
            pins(),
            text("/archive").unwrap(),
            &request(),
            Purpose::Campaign,
        );
        assert!(matches!(refused, Err(Error::Rejected(_))));
        assert_eq!(snapshot(&case.state), before);
        let mut calibration = request();
        calibration.campaign = text("calibration").unwrap();
        let admitted = admission::admit(
            &store,
            &listing,
            pins(),
            text("/archive").unwrap(),
            &calibration,
            Purpose::Calibration,
        )
        .unwrap();
        assert_eq!(admitted.record.purpose(), Purpose::Calibration);
    }
    let mut listing = listing();
    listing.profiles[0].class = crate::protocol::Class::History;
    listing.profiles[0].expected = Some(crate::protocol::Expected::Pass);
    assert!(
        admission::admit(
            &store,
            &listing,
            pins(),
            text("/archive").unwrap(),
            &request(),
            Purpose::Campaign
        )
        .is_ok()
    );
}

#[test]
fn listed_forms_refuse_bad_pins_and_enforce_count_endpoints() {
    for key in ["build", "executable", "platform"] {
        let mut bad = pins();
        match key {
            "build" => bad.build = text("invalid").unwrap(),
            "executable" => bad.executable = text("invalid").unwrap(),
            "platform" => bad.platform = text("").unwrap(),
            _ => unreachable!(),
        }
        let error = freeze::freeze(&listing(), bad, &request()).unwrap_err();
        assert_eq!(error.to_string(), format!("{key} fails its listed form"));
    }
    let mut listing = listing();
    listing
        .keys
        .iter_mut()
        .find(|key| key.name == "turns")
        .unwrap()
        .form = crate::protocol::Form::Count { min: 8, max: 9 };
    for (value, accepted) in [(7, false), (8, true), (9, true), (10, false)] {
        let mut request = request();
        request.counts.insert(text("turns").unwrap(), value);
        assert_eq!(freeze::freeze(&listing, pins(), &request).is_ok(), accepted);
    }
}

#[test]
fn reserved_campaign_refuses_before_capability_probe_effects() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let mut request = request();
    request.campaign = text("calibration").unwrap();
    let before = snapshot(&case.state);
    let result = super::admit_campaign(
        &store,
        &case.root.join("missing-archive"),
        &case.root.join("missing-cgroup"),
        std::time::Duration::from_secs(1),
        &request,
    );
    assert!(matches!(result, Err(Error::Rejected(_))));
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn duplicate_and_orphan_admission_barriers_poison_on_every_sync_fault() {
    let job = freeze::freeze(&listing(), pins(), &request()).unwrap().0;
    for orphan in [false, true] {
        let setup = |store: &Store| {
            let record = admit(store, &request()).unwrap().record;
            if orphan {
                let jobs = store.shard_jobs(record.job().id()).unwrap().unwrap();
                store
                    .delete(&jobs, &name(&format!("{}.json", record.job().id())))
                    .unwrap();
            }
        };
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        setup(&store);
        let (_, reached) = scripted(None, || admit(&store, &request()).unwrap());
        let indices: Vec<_> = reached
            .iter()
            .enumerate()
            .filter_map(|(index, at)| (*at == Step::Sync).then_some(index))
            .collect();
        assert_eq!(indices.len(), 6);
        let last_sync = *indices.last().unwrap();
        for index in indices {
            let case = Case::new();
            let store = Store::open(&case.state).unwrap();
            setup(&store);
            let before = snapshot(&case.state);
            let (result, reached) = scripted(Some((index, Fault::Errno(libc::EIO))), || {
                admit(&store, &request())
            });
            assert_eq!(reached[index], Step::Sync);
            assert!(matches!(result, Some(Err(Error::Store(_)))));
            if orphan && index < last_sync {
                assert!(
                    !case
                        .state
                        .join(crate::campaign::state_fixture::job_file(format!(
                            "{}.json",
                            job.id()
                        )))
                        .exists()
                );
            }
            assert!(matches!(
                store.create_once(store.root(), &name("later"), b"later"),
                Err(crate::store::Error::Poisoned)
            ));
            for (path, bytes) in before.iter().filter(|(path, _)| path.starts_with("jobs")) {
                assert_eq!(snapshot(&case.state).get(path), Some(bytes));
            }
        }
    }
}

#[test]
fn a_job_publish_fault_keeps_its_manifest_and_restart_completes_admission() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (job, manifest) = freeze::freeze(&listing(), pins(), &request()).unwrap();
    let id = job.id().to_string();
    let jobs = case
        .state
        .join("jobs")
        .join(crate::layout::shard(&id).as_str());
    let manifest_path = jobs.join(format!("{id}.manifest"));
    let record_path = jobs.join(format!("{id}.json"));
    let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen = std::rc::Rc::new(std::cell::Cell::new(0));
    let observed_trace = trace.clone();
    let observed_seen = seen.clone();
    let observed_manifest = manifest.clone();
    observed(
        move |at| {
            observed_trace.borrow_mut().push(at);
            if at == Step::Rename && manifest_path.exists() && !record_path.exists() {
                assert_eq!(
                    std::fs::read(&manifest_path).unwrap(),
                    observed_manifest.as_bytes()
                );
                observed_seen.set(observed_seen.get() + 1);
            }
        },
        || admit(&store, &request()),
    )
    .unwrap();
    assert_eq!(seen.get(), 1);
    let renames: Vec<_> = trace
        .borrow()
        .iter()
        .enumerate()
        .filter_map(|(index, at)| (*at == Step::Rename).then_some(index))
        .collect();
    assert_eq!(renames.len(), 2);
    let publication_sync = trace
        .borrow()
        .iter()
        .rposition(|at| *at == Step::Sync)
        .unwrap();
    drop(store);
    for &index in &renames {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let (result, _) = scripted(Some((index, Fault::Errno(libc::EIO))), || {
            admit(&store, &request())
        });
        assert!(matches!(result, Some(Err(Error::Store(_)))));
        let jobs = case
            .state
            .join("jobs")
            .join(crate::layout::shard(&id).as_str());
        assert!(!jobs.join(format!("{id}.json")).exists());
        if index == renames[1] {
            assert_eq!(
                std::fs::read(jobs.join(format!("{id}.manifest"))).unwrap(),
                manifest.as_bytes()
            );
        }
        drop(store);
        let store = Store::open(&case.state).unwrap();
        let finished = admit(&store, &request()).unwrap();
        assert_eq!(finished.record.job().id(), job.id());
        assert!(!finished.existing);
    }
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (result, reached) = scripted(Some((publication_sync, Fault::Kill)), || {
        admit(&store, &request())
    });
    assert!(result.is_none());
    assert_eq!(reached[publication_sync], Step::Sync);
    assert!(
        case.state
            .join(crate::campaign::state_fixture::job_file(format!(
                "{id}.json"
            )))
            .exists()
    );
    assert_eq!(
        std::fs::read(
            case.state
                .join(crate::campaign::state_fixture::job_file(format!(
                    "{id}.manifest"
                )))
        )
        .unwrap(),
        manifest.as_bytes()
    );
    drop(store);
    let store = Store::open(&case.state).unwrap();
    let recovered = admit(&store, &request()).unwrap();
    assert!(recovered.existing);
    assert_eq!(recovered.record.job().id(), job.id());
}

#[test]
fn non_capacity_raises_and_inclusive_memory_budget_are_persisted() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let mut values = config();
    values.insert(text("memory").unwrap(), 256);
    configure(&store, values.clone()).unwrap();
    values.insert(text("wall").unwrap(), 61);
    values.insert(text("attempt_output").unwrap(), 101);
    configure(&store, values.clone()).unwrap();
    let saved = store
        .read_record::<crate::record::Configuration>(store.root(), &name("config.json"))
        .unwrap()
        .unwrap();
    assert_eq!(saved.record().config(), &values);
}

#[test]
fn cpu_nanosecond_boundary_and_query_faults_preserve_configuration() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let mut accepted = config();
    accepted.insert(text("cpu").unwrap(), u64::MAX / 1_000_000_000 - 1);
    configure(&store, accepted).unwrap();
    let before = snapshot(&case.state);
    let mut refused = config();
    refused.insert(text("cpu").unwrap(), u64::MAX / 1_000_000_000);
    assert!(matches!(
        configure(&store, refused),
        Err(Error::Rejected(_))
    ));
    assert_eq!(snapshot(&case.state), before);
    for errno in [libc::EIO, libc::EINVAL] {
        let (result, reached) = scripted(Some((0, Fault::Errno(errno))), || {
            configure(&store, config())
        });
        assert_eq!(reached[0], Step::Limits);
        assert!(matches!(result, Some(Err(Error::Held(_)))));
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn every_reference_worker_default_is_frozen_and_manifest_keys_keep_listing_order() {
    let expected: std::collections::BTreeMap<_, _> = [
        ("turns", 20000),
        ("same_time", 400),
        ("no_progress", 5000),
        ("actors", 16),
        ("disk_depth", 8),
        ("scripted", 32),
        ("link_copy_bytes", 1048576),
        ("tx_slots", 1024),
        ("rules", 32),
        ("taps", 8),
        ("captures", 4096),
        ("audit_records", 65536),
        ("registry", 4096),
        ("upload_attempts", 2),
        ("source_bytes", 65536),
        ("slots", 1),
        ("restarts", 1),
        ("bundles", 1),
        ("suffix_depth", 2),
        ("suffix_children", 3),
        ("suffix_faults", 12),
        ("suffix_advances", 16),
        ("pending", 64),
        ("ring", 64),
        ("records", 1000000),
        ("bytes", 48000000),
        ("every", 256),
        ("watchdog", 600),
    ]
    .into_iter()
    .map(|(key, value)| (text(key).unwrap(), value))
    .collect();
    let mut declaration = listing();
    for key in expected.keys() {
        if !declaration.keys.iter().any(|k| k.name == key.as_str()) {
            declaration.keys.push(crate::protocol::Key {
                name: key.as_str().to_owned(),
                form: crate::protocol::Form::Count {
                    min: 1,
                    max: u64::MAX,
                },
            });
        }
    }
    let mut defaults = request();
    defaults.counts.clear();
    let (job, manifest) = freeze::freeze(&declaration, pins(), &defaults).unwrap();
    assert_eq!(job.experiment().counts, expected);
    let lines: Vec<_> = manifest
        .lines()
        .map(|line| line.split_once(" = ").unwrap().0)
        .collect();
    assert_eq!(
        lines,
        declaration
            .keys
            .iter()
            .map(|k| k.name.as_str())
            .collect::<Vec<_>>()
    );
    for (key, value) in expected {
        assert!(
            manifest
                .lines()
                .any(|line| line == format!("{} = {value}", key.as_str()))
        );
    }
}

fn listing() -> Listing {
    Listing::parse(include_str!("../../testdata/admission-listing.txt")).unwrap()
}
fn pins() -> Pins {
    Pins {
        build: text(&"b".repeat(64)).unwrap(),
        executable: text(&"e".repeat(64)).unwrap(),
        platform: text("x86_64-linux").unwrap(),
        toolchain: text("rustc 1.99.0").unwrap(),
    }
}
fn request() -> Request {
    Request {
        profile: text("upload").unwrap(),
        campaign: text("c1").unwrap(),
        run: 0,
        attempts: 3,
        counts: [
            ("bytes", 9600),
            ("every", 5),
            ("pending", 3),
            ("records", 80),
            ("ring", 2),
            ("turns", 7),
        ]
        .into_iter()
        .map(|(k, v)| (text(k).unwrap(), v))
        .collect(),
    }
}
fn admit(store: &Store, request: &Request) -> Result<Outcome, Error> {
    admission::admit(
        store,
        &listing(),
        pins(),
        text("/archive").unwrap(),
        request,
        Purpose::Campaign,
    )
}
fn configure(
    store: &Store,
    values: std::collections::BTreeMap<Text, u64>,
) -> Result<crate::record::Configuration, Error> {
    super::configuration::prepare(values).and_then(|config| super::configure(store, config))
}

#[test]
fn the_attempt_bound_and_default_minima_are_frozen() {
    let mut bound = request();
    bound.attempts = crate::SCAN_BOUND as u64;
    assert!(bound.validate(Purpose::Campaign).is_ok());
    assert_eq!(
        freeze::freeze(&listing(), pins(), &bound)
            .unwrap()
            .0
            .experiment()
            .attempts,
        crate::SCAN_BOUND as u64
    );
    bound.attempts += 1;
    assert!(matches!(
        bound.validate(Purpose::Campaign),
        Err(Error::Rejected(_))
    ));
    let mut defaults = request();
    defaults.counts.clear();
    let mut declared = listing();
    declared.profiles[0]
        .held
        .iter_mut()
        .find(|(key, _)| key == "ring")
        .unwrap()
        .1 = 70;
    let (job, _) = freeze::freeze(&declared, pins(), &defaults).unwrap();
    let expected = [
        ("bytes", 48000000),
        ("every", 256),
        ("pending", 64),
        ("records", 1000000),
        ("ring", 70),
        ("turns", 20000),
    ]
    .into_iter()
    .map(|(k, v)| (text(k).unwrap(), v))
    .collect();
    assert_eq!(job.experiment().counts, expected);
}

#[test]
fn calibration_authority_and_oversize_records_refuse_before_publication() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let before = snapshot(&case.state);
    assert!(matches!(
        super::admit(
            &store,
            &listing(),
            pins(),
            text("/archive").unwrap(),
            &request(),
            Purpose::Calibration
        ),
        Err(Error::Rejected(_))
    ));
    let mut large = request();
    large.campaign = text(&"c".repeat(crate::record::BOUND as usize)).unwrap();
    assert!(matches!(admit(&store, &large), Err(Error::Rejected(_))));
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn a_changed_manifest_holds_both_readmission_and_show() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let record = admit(&store, &request()).unwrap().record;
    let jobs = store.shard_jobs(record.job().id()).unwrap().unwrap();
    store
        .replace(
            &jobs,
            &name(&format!("{}.manifest", record.job().id())),
            b"tampered",
        )
        .unwrap();
    let before = snapshot(&case.state);
    assert!(matches!(admit(&store, &request()), Err(Error::Held(_))));
    let row = &show(&case.state).unwrap()["jobs"][0];
    assert_eq!(row["held_code"], "binding");
    assert!(row.get("verified").is_none());
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn configure_replaces_a_stored_configuration_that_fails_the_current_budget_rules() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let old = concat!(
        r#"{"format":1,"kind":"configuration","record":{"config":{"artifact_bytes":1000,"#,
        r#""artifact_inodes":100,"attempt_inodes":10,"attempt_output":100,"backlog":10,"cores":4,"#,
        r#""cpu":60,"memory":1024,"processes":64,"reserve_slots":1,"retained_builds":1,"slots":1,"#,
        r#""tree_memory":128,"wall":60},"enforcement":"census","format":1},"#,
        r#""sha256":"c3316b2054592165f75cf76fddd9bcb2d41fcf2296a46130d73c960fa350b59b"}"#
    );
    std::fs::write(case.state.join("config.json"), old).unwrap();
    assert!(matches!(
        store.read_record::<crate::record::Configuration>(store.root(), &name("config.json")),
        Err(crate::record::Held::Mismatch)
    ));
    let installed = configure(&store, config()).unwrap();
    assert_eq!(installed.config(), &config());
    let saved = store
        .read_record::<crate::record::Configuration>(store.root(), &name("config.json"))
        .unwrap()
        .unwrap();
    assert_eq!(saved.record(), &installed);
    std::fs::write(case.state.join("config.json"), &old[..old.len() - 2]).unwrap();
    assert!(matches!(
        configure(&store, config()),
        Err(Error::Record(crate::record::Held::Malformed))
    ));
}

#[test]
fn portable_cpu_and_output_refusals_preserve_configuration() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    configure(&store, config()).unwrap();
    let before = snapshot(&case.state);
    for value in [(1u64 << 63) - 2, u64::MAX] {
        let mut bad = config();
        bad.insert(text("cpu").unwrap(), value);
        assert!(matches!(configure(&store, bad), Err(Error::Rejected(_))));
        assert_eq!(snapshot(&case.state), before);
    }
    let mut bad = config();
    bad.insert(text("attempt_output").unwrap(), (1u64 << 63) - 1);
    bad.insert(text("artifact_bytes").unwrap(), u64::MAX);
    assert!(matches!(configure(&store, bad), Err(Error::Rejected(_))));
    assert_eq!(snapshot(&case.state), before);
}

fn config() -> std::collections::BTreeMap<Text, u64> {
    [
        ("slots", 1),
        ("reserve_slots", 1),
        ("cores", 4),
        ("memory", 1024),
        ("cpu", 60),
        ("tree_memory", 128),
        ("attempt_output", 100),
        ("attempt_inodes", 10),
        ("wall", 60),
        ("processes", 64),
        ("artifact_bytes", 50_000_000),
        ("artifact_inodes", 100),
        ("backlog", 10),
        ("retained_builds", 1),
    ]
    .into_iter()
    .map(|(k, v)| (text(k).unwrap(), v))
    .collect()
}

#[test]
fn frozen_admission_reproduces_the_pinned_vector_and_is_idempotent() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let first = admit(&store, &request()).unwrap();
    assert!(!first.existing);
    assert_eq!(
        first.record.job().id().to_string(),
        "dede8442617896e012b3588170f0d42d2f5811b975f42335d570713f2a93aeaf"
    );
    assert_eq!(first.record.job().seed(), 15296928082430272672);
    let before = snapshot(&case.state);
    let duplicate = admit(&store, &request()).unwrap();
    assert!(duplicate.existing);
    assert_eq!(duplicate.record, first.record);
    assert_eq!(snapshot(&case.state), before);
    let moved = admission::admit(
        &store,
        &listing(),
        pins(),
        text("/moved/archive").unwrap(),
        &request(),
        Purpose::Campaign,
    )
    .unwrap();
    assert_eq!(moved.record.archive(), first.record.archive());
}

#[test]
fn each_frozen_input_changes_identity() {
    let (base, _) = freeze::freeze(&listing(), pins(), &request()).unwrap();
    let mut changed = request();
    changed.counts.insert(text("turns").unwrap(), 8);
    let (other, _) = freeze::freeze(&listing(), pins(), &changed).unwrap();
    assert_ne!(base.id(), other.id());
    let mut build = pins();
    build.build = text(&"a".repeat(64)).unwrap();
    assert_ne!(
        base.id(),
        freeze::freeze(&listing(), build, &request())
            .unwrap()
            .0
            .id()
    );
    for change in 0..3 {
        let mut changed = request();
        match change {
            0 => changed.campaign = text("c2").unwrap(),
            1 => changed.run = 1,
            _ => changed.attempts = 4,
        }
        assert_ne!(
            base.id(),
            freeze::freeze(&listing(), pins(), &changed).unwrap().0.id()
        );
    }
}

#[test]
fn campaign_authority_refuses_calibration_before_store_effects() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let before = snapshot(&case.state);
    let mut calibration = request();
    calibration.campaign = text("calibration").unwrap();
    assert!(matches!(
        admit(&store, &calibration),
        Err(Error::Rejected(_))
    ));
    assert_eq!(snapshot(&case.state), before);
    let calibration = admission::admit(
        &store,
        &listing(),
        pins(),
        text("/archive").unwrap(),
        &calibration,
        Purpose::Calibration,
    )
    .unwrap();
    assert_eq!(calibration.record.purpose(), Purpose::Calibration);
    let campaign = admit(&store, &request()).unwrap();
    assert_eq!(campaign.record.purpose(), Purpose::Campaign);
    assert_ne!(calibration.record.job().id(), campaign.record.job().id());
}

#[test]
fn corrupt_job_stays_held_and_unchanged_on_readmission_and_show() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let admitted = admit(&store, &request()).unwrap();
    let jobs = store
        .shard_jobs(admitted.record.job().id())
        .unwrap()
        .unwrap();
    let filename = name(&format!("{}.json", admitted.record.job().id()));
    store.replace(&jobs, &filename, b"corrupt").unwrap();
    let before = snapshot(&case.state);
    assert!(store.read_record::<Admission>(&jobs, &filename).is_err());
    assert!(matches!(
        admit(&store, &request()),
        Err(Error::Record(crate::record::Held::Malformed))
    ));
    assert_eq!(snapshot(&case.state), before);
    let shown = show(&case.state).unwrap();
    assert!(shown["jobs"][0]["held"].is_string());
    assert!(shown["jobs"][0].get("verified").is_none());
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn orphan_manifests_complete_only_when_the_frozen_bytes_match() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (job, manifest) = freeze::freeze(&listing(), pins(), &request()).unwrap();
    store.mkdir(store.root(), &name("jobs")).unwrap();
    let jobs = store.shard_jobs(job.id()).unwrap().unwrap();
    let filename = name(&format!("{}.manifest", job.id()));
    store.create_once(&jobs, &filename, b"wrong").unwrap();
    let before = snapshot(&case.state);
    assert!(matches!(admit(&store, &request()), Err(Error::Held(_))));
    assert_eq!(snapshot(&case.state), before);
    store
        .replace(&jobs, &filename, manifest.as_bytes())
        .unwrap();
    assert!(!admit(&store, &request()).unwrap().existing);
    store.delete(&jobs, &filename).unwrap();
    let before = snapshot(&case.state);
    assert!(matches!(admit(&store, &request()), Err(Error::Held(_))));
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn count_forms_and_recorder_constraints_refuse_invalid_inputs() {
    for (key, value) in [
        ("root", 1),
        ("unknown", 1),
        ("turns", 0),
        ("pending", u64::MAX),
        ("records", 1),
        ("bytes", 1),
    ] {
        let mut request = request();
        request.counts.insert(text(key).unwrap(), value);
        assert!(
            matches!(
                request
                    .validate(Purpose::Campaign)
                    .and_then(|()| freeze::freeze(&listing(), pins(), &request).map(drop)),
                Err(Error::Rejected(_))
            ),
            "{key}={value}"
        );
    }
    for field in 0..3 {
        let mut listing = listing();
        match field {
            0 => listing.manifest = 3,
            1 => listing.constraints.clear(),
            _ => listing.profiles[0].support = "planned".into(),
        }
        assert!(matches!(
            freeze::freeze(&listing, pins(), &request()),
            Err(Error::Rejected(_))
        ));
    }
}

/// A configuration installs when its own budgets cover its slots, as the
/// first configuration and as a raise. One that leaves a share without a
/// core is rejected and the stored bytes stay.
#[test]
fn configuration_installs_the_capacity_its_budgets_cover() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let mut wide = config();
    for (key, value) in [
        ("slots", 2),
        ("artifact_bytes", 200_000_000),
        ("artifact_inodes", 400),
    ] {
        wide.insert(text(key).unwrap(), value);
    }
    assert_eq!(configure(&store, wide.clone()).unwrap().config(), &wide);
    let mut wider = wide.clone();
    wider.insert(text("slots").unwrap(), 3);
    assert_eq!(configure(&store, wider.clone()).unwrap().config(), &wider);
    let mut uncovered = wider;
    uncovered.insert(text("slots").unwrap(), 4);
    let before = snapshot(&case.state);
    assert!(matches!(
        configure(&store, uncovered),
        Err(Error::Rejected(_))
    ));
    assert_eq!(snapshot(&case.state), before);
    let mut lower = config();
    lower.insert(text("cores").unwrap(), 2);
    assert_eq!(configure(&store, lower.clone()).unwrap().config(), &lower);
    assert_eq!(
        store
            .read_record::<crate::record::Configuration>(store.root(), &name("config.json"))
            .unwrap()
            .unwrap()
            .record()
            .config(),
        &lower
    );
    let before = snapshot(&case.state);
    assert!(show(&case.state).unwrap()["config"]["verified"].is_object());
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn configuration_bounds_and_corruption_preserve_authoritative_bytes() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    configure(&store, config()).unwrap();
    for (key, value) in [
        ("memory", 1),
        ("cores", 1),
        ("artifact_bytes", 200),
        ("artifact_inodes", 20),
        ("slots", 0),
        ("unknown", 1),
        ("corpus_bytes", 1),
        ("cpu", u64::MAX),
    ] {
        let mut bad = config();
        bad.insert(text(key).unwrap(), value);
        let before = snapshot(&case.state);
        let outcome = configure(&store, bad);
        assert!(matches!(outcome, Err(Error::Rejected(_))), "{key}={value}");
        assert_eq!(snapshot(&case.state), before);
    }
    store
        .replace(store.root(), &name("config.json"), b"corrupt")
        .unwrap();
    let before = snapshot(&case.state);
    assert!(matches!(
        configure(&store, config()),
        Err(Error::Record(crate::record::Held::Malformed))
    ));
    assert!(show(&case.state).unwrap()["config"]["held"].is_string());
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn show_reports_verified_jobs_and_orphans_without_mutation() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let record = admit(&store, &request()).unwrap().record;
    let jobs = store.shard_jobs("a".repeat(64)).unwrap().unwrap();
    store
        .create_once(
            &jobs,
            &name(&format!("{}.manifest", "a".repeat(64))),
            b"orphan",
        )
        .unwrap();
    store
        .create_once(
            &jobs,
            &name(&format!("aa{}.json", "z".repeat(188))),
            b"foreign",
        )
        .unwrap();
    let before = snapshot(&case.state);
    let shown = show(&case.state).unwrap();
    let rows = shown["jobs"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .any(|row| row["held"] == "invalid job identity filename")
    );
    assert!(
        rows.iter()
            .any(|r| r["verified"]["job"]["seed"] == record.job().seed())
    );
    assert_eq!(rows.iter().filter(|r| r["held"].is_string()).count(), 2);
    assert_eq!(snapshot(&case.state), before);
    drop(store);
    let view = View::open(&case.state).unwrap();
    assert!(
        view.read_record::<crate::record::Configuration>(view.root(), &name("config.json"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn targeted_retention_checks_precede_writes_and_count_orphan_roots_once() {
    for resume in [false, true] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let ordinary = admit(&store, &request()).unwrap().record;
        let manifest = std::fs::read_to_string(case.state.join(
            crate::campaign::state_fixture::job_file(format!("{}.manifest", ordinary.job().id())),
        ))
        .unwrap();
        let bytes = [0u8; 48];
        store
            .create_once(store.root(), &name("bundle"), &bytes)
            .unwrap();
        let admission = crate::campaign::state_fixture::target_admission(&ordinary, 1);
        let target = admission.job().experiment().target.clone().unwrap();
        let id = admission.job().id();
        let jobs = store.shard_jobs(id).unwrap().unwrap();
        let publish = || {
            super::admission::publish(
                &store,
                admission.clone(),
                &manifest,
                Some((store.root(), &target)),
            )
        };
        if resume {
            store
                .create_once(&jobs, &name(&format!("{id}.bundle")), &bytes)
                .unwrap();
        }
        use crate::record::{Configuration, Record};
        let config = Configuration::new(
            [
                ("slots", 1),
                ("reserve_slots", 1),
                ("cores", 2),
                ("memory", 512 << 20),
                ("cpu", 60),
                ("tree_memory", 128 << 20),
                ("attempt_output", 16 << 20),
                ("attempt_inodes", 200),
                ("wall", 120),
                ("processes", 64),
                ("artifact_bytes", 256 << 20),
                ("artifact_inodes", 1 << 20),
                ("backlog", 2),
                ("retained_builds", 1),
            ]
            .into_iter()
            .map(|(key, value)| (text(key).unwrap(), value))
            .collect(),
        )
        .unwrap();
        super::configure(&store, config.clone()).unwrap();
        let shard = case
            .state
            .join("jobs")
            .join(crate::layout::shard(&id.to_string()).as_str());
        let elsewhere = std::fs::read_dir(case.state.join("jobs"))
            .unwrap()
            .map(|entry| std::fs::read_dir(entry.unwrap().path()).unwrap().count())
            .sum::<usize>()
            - std::fs::read_dir(&shard).unwrap().count();
        let padding = if resume {
            crate::SCAN_BOUND - 9
        } else {
            crate::SCAN_BOUND - 8
        } + 2 * elsewhere;
        for index in 0..padding {
            std::fs::write(
                case.state.join(crate::layout::job_file(
                    &id.to_string(),
                    &format!("retained-{index}"),
                )),
                b"",
            )
            .unwrap();
        }
        let before = snapshot(&case.state);
        let published = publish();
        if resume {
            assert!(!published.unwrap().existing);
            assert_eq!(
                store
                    .read_record::<Admission>(&jobs, &name(&format!("{id}.json")))
                    .unwrap()
                    .unwrap()
                    .record(),
                &admission
            );
        } else {
            assert!(matches!(
                published,
                Err(Error::Bound { ref root, entries: Some(projected), .. })
                    if root == &format!("jobs/{}", crate::layout::shard(&id.to_string()).as_str()) && projected == crate::SCAN_BOUND + 1
            ));
            assert_eq!(snapshot(&case.state), before);
            for index in 0..padding {
                std::fs::remove_file(case.state.join(crate::layout::job_file(
                    &id.to_string(),
                    &format!("retained-{index}"),
                )))
                .unwrap();
            }
            store
                .replace(store.root(), &name("bundle"), b"short")
                .unwrap();
            let before = snapshot(&case.state);
            assert!(
                matches!(publish(),Err(Error::Held(reason)) if reason=="target bundle size differs")
            );
            assert_eq!(snapshot(&case.state), before);
            store
                .replace(store.root(), &name("bundle"), &bytes)
                .unwrap();
            for free in [(0, u64::MAX), (u64::MAX, 0)] {
                crate::step::install(Some(crate::step::Script {
                    free_space: Some(free),
                    ..Default::default()
                }));
                let before = snapshot(&case.state);
                let error = publish().err().unwrap();
                crate::step::install(None);
                assert!(
                    matches!(error, Error::Rejected(ref reason) if reason == "target copies leave insufficient storage capacity"),
                    "{free:?}: {error}"
                );
                assert_eq!(snapshot(&case.state), before);
            }
            // Each census-fed dimension refuses with the tree unchanged at
            // its threshold, and the copy is admitted one unit above both.
            let usage = crate::campaign::census::census(&store, &config).unwrap();
            let bytes = u128::from(usage.bytes)
                + 48
                + manifest.len() as u128
                + admission.encoded_len() as u128
                + 2 * config.charge().bytes;
            let inodes = u128::from(usage.inodes) + 3 + 2 * config.charge().inodes;
            let limit = |limits: &[(&str, u128)]| {
                let mut values = config.config().clone();
                for (key, limit) in limits {
                    values.insert(text(key).unwrap(), *limit as u64);
                }
                super::configure(&store, Configuration::new(values).unwrap()).unwrap();
            };
            for (limits, refusal) in [
                (
                    [("artifact_bytes", bytes)],
                    "target copies leave insufficient attempt output capacity",
                ),
                (
                    [("artifact_inodes", inodes)],
                    "target copies leave insufficient storage capacity",
                ),
            ] {
                limit(&limits);
                let before = snapshot(&case.state);
                let error = publish().err().unwrap();
                assert!(
                    matches!(error, Error::Rejected(ref reason) if reason == refusal),
                    "{error}"
                );
                assert_eq!(snapshot(&case.state), before);
            }
            limit(&[
                ("artifact_bytes", bytes + 1),
                ("artifact_inodes", inodes + 1),
            ]);
            assert!(!publish().unwrap().existing);
        }
    }
}

#[test]
fn job_filename_projection_keeps_results_ahead_of_generic_json() {
    for suffix in [
        crate::record::JobResult::SUFFIX,
        crate::record::Pin::SUFFIX,
        ".manifest",
        ".bundle",
        ".json",
    ] {
        assert_eq!(
            super::admission::job_id(&format!("job{suffix}")),
            Some("job")
        );
    }
    assert_eq!(super::admission::job_id("unknown"), None);
}

fn child_finding() -> crate::record::Finding {
    use crate::record::{
        Admission, Attempt, Binding, ChildEvidence, Class, Digest, Finding, FindingKind, Finished,
        Kernel, Purpose,
    };
    let (job, _) = freeze::freeze(&listing(), pins(), &request()).unwrap();
    let admission =
        Admission::new(text("/archive").unwrap(), job.clone(), Purpose::Campaign).unwrap();
    let parent = text(&format!("{}-0001", job.id())).unwrap();
    let child = ChildEvidence {
        bundle: None,
        class: Class::Violation,
        digest: None,
        file: None,
        kind: FindingKind::Violation,
        label: text("c0-0").unwrap(),
        terminal: None,
    };
    let mut artifact = crate::attempt::tests::artifact(parent.as_str(), job.manifest_sha256());
    artifact.archive = Digest::parse(job.experiment().pins.build.as_str());
    let bound = crate::record::BoundEvidence {
        artifact: Digest::of(b"bound"),
        attempt: parent.clone(),
        bundle: artifact.bundle,
    };
    Finding {
        admission,
        artifact: Some(artifact),
        attempt: Attempt {
            attempt: parent.clone(),
            file_bytes: 4096,
            job: job.id().digest(),
            manifest: job.manifest_sha256(),
            number: 1,
        },
        calibration_root: None,
        child: Some(child),
        finished: Finished {
            attempt: parent.clone(),
            binding: Binding::Matching,
            bound: Some(bound),
            class: Class::Violation,
            exit: Some(1),
            interruption: None,
            kernel: Kernel::default(),
            residual_members: false,
            signal: None,
            watchdog: false,
        },
        kind: FindingKind::Violation,
        parent_attempt: Some(parent),
    }
}

#[test]
fn sibling_child_findings_share_one_parent_verification_per_listing() {
    use super::lineage::{Parent, Parents, verify};
    use crate::record::{Admission, ChildEvidence, Class, Purpose};
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let finding = child_finding();
    let mut sibling = finding.clone();
    sibling.child.as_mut().unwrap().label = text("c0-1").unwrap();
    let parent = Parent {
        admission: finding.admission.clone(),
        attempt: finding.attempt.clone(),
        finished: finding.finished.clone(),
        artifact: finding.artifact.clone().unwrap(),
        children: Some(
            [&finding, &sibling]
                .map(|found| ChildEvidence {
                    bundle: None,
                    ..found.child.clone().unwrap()
                })
                .to_vec(),
        ),
    };
    let calls = std::cell::Cell::new(0);
    let checked = || {
        calls.set(calls.get() + 1);
        Ok(parent.clone())
    };
    let parents = Parents::default();
    parents.get(&finding, checked).unwrap();
    for found in [&finding, &sibling, &finding] {
        verify(&store, found, &parents).unwrap();
    }
    assert_eq!(calls.get(), 1);
    let mut changed = sibling.clone();
    changed.child.as_mut().unwrap().class = Class::Incomplete;
    assert!(
        matches!(verify(&store, &changed, &parents), Err(super::Error::Held(ref reason)) if reason == "child differs from its bound parent evidence")
    );
    let mut other = sibling.clone();
    other.admission = Admission::new(
        text("/other").unwrap(),
        finding.admission.job().clone(),
        Purpose::Campaign,
    )
    .unwrap();
    parents.get(&other, checked).unwrap();
    assert_eq!(calls.get(), 2);
    let failing = Parents::default();
    let refusals = std::cell::Cell::new(0);
    let refused = || {
        refusals.set(refusals.get() + 1);
        Err(super::Error::Held("child parent evidence missing".into()))
    };
    for found in [&finding, &sibling] {
        assert!(failing.get(found, refused).is_err());
    }
    assert_eq!(refusals.get(), 2);
}

#[test]
fn child_finding_identity_guards_refuse_each_invalid_lineage() {
    use crate::record::FindingKind;
    let finding = child_finding();
    let parent = finding.parent_attempt.clone().unwrap();
    assert!(super::findings::validate(&finding, finding.id().as_str()).is_ok());
    for mutation in ["id", "kind", "orphan"] {
        let mut changed = finding.clone();
        let id = match mutation {
            "id" => "another-id".to_owned(),
            "kind" => {
                changed.child.as_mut().unwrap().kind = FindingKind::Incomplete;
                changed.id().as_str().to_owned()
            }
            "orphan" => {
                changed.child = None;
                parent.as_str().to_owned()
            }
            _ => unreachable!(),
        };
        assert!(
            matches!(super::findings::validate(&changed,&id),Err(super::Error::Held(reason)) if reason=="child finding identity differs"),
            "{mutation}"
        );
    }
}

#[test]
fn calibration_replay_finding_verifies_with_its_replay_command() {
    use crate::record::{
        Artifact, Attempt, Binding, BoundEvidence, Class, Digest, Finding, FindingKind, Finished,
        Kernel,
    };
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let mut request = request();
    request.campaign = text("calibration").unwrap();
    let admission = admission::admit(
        &store,
        &listing(),
        pins(),
        text("/archive").unwrap(),
        &request,
        Purpose::Calibration,
    )
    .unwrap()
    .record;
    let job = admission.job();
    let id = format!("{}-calibration-replay-0001", job.id());
    let input = b"replay input";
    let finished = Finished {
        attempt: text(&id).unwrap(),
        binding: Binding::Matching,
        bound: Some(BoundEvidence {
            artifact: Digest::of(b"replay artifact"),
            attempt: text(&id).unwrap(),
            bundle: Some(Digest::of(input)),
        }),
        class: Class::Violation,
        exit: Some(1),
        interruption: None,
        kernel: Kernel::default(),
        residual_members: false,
        signal: None,
        watchdog: false,
    };
    let mut finding = Finding {
        child: None,
        parent_attempt: None,
        admission: admission.clone(),
        artifact: Some(Artifact {
            archive: Digest::parse(job.experiment().pins.build.as_str()),
            archive_path: None,
            bundle: Some(Digest::of(input)),
            class: text("violation").unwrap(),
            command: text("replay").unwrap(),
            comparison: None,
            manifest: Some(job.manifest_sha256()),
            output: None,
            reason: text("replayed violation").unwrap(),
            run_id: text(&id).unwrap(),
            session: None,
            session_original: None,
            summary: None,
            workers: std::collections::BTreeMap::new(),
        }),
        attempt: Attempt {
            attempt: text(&id).unwrap(),
            file_bytes: 1024,
            job: job.id().digest(),
            manifest: job.manifest_sha256(),
            number: 1,
        },
        calibration_root: Some(job.id().digest()),
        finished,
        kind: FindingKind::Violation,
    };
    let manifest = std::fs::read(case.state.join(crate::campaign::state_fixture::job_file(
        format!("{}.manifest", job.id()),
    )))
    .unwrap();
    store.mkdir(store.root(), &name("findings")).unwrap();
    let root = store
        .open_dir(store.root(), &name("findings"))
        .unwrap()
        .unwrap();
    store.mkdir(&root, &name(&id)).unwrap();
    let directory = store.open_dir(&root, &name(&id)).unwrap().unwrap();
    store
        .create_once(&directory, &name("manifest"), &manifest)
        .unwrap();
    store
        .create_once(&directory, &name("input"), input)
        .unwrap();
    store
        .create_record(&directory, &name("finding.json"), &finding)
        .unwrap();
    let listed = findings(&case.state).unwrap();
    let row = &listed["findings"][0];
    assert_eq!(row["id"], id, "{row}");
    assert!(row.get("held").is_none(), "{row}");
    assert_eq!(row["verified"]["kind"], "violation");
    assert_eq!(listed["release_blockers"], serde_json::json!([id]));
    let shown = super::status_tests::status(&case.state).unwrap();
    assert_eq!(shown["findings"], listed["findings"]);
    assert_eq!(
        shown["failure_groups"][0]["findings"],
        serde_json::json!([id])
    );
    finding.artifact.as_mut().unwrap().command = text("run").unwrap();
    store
        .replace_record(&directory, &name("finding.json"), &finding)
        .unwrap();
    let listed = findings(&case.state).unwrap();
    assert_eq!(
        listed["findings"][0]["held"], "finding artifact binding differs",
        "{listed}"
    );
    finding.artifact.as_mut().unwrap().command = text("replay").unwrap();
    store
        .replace_record(&directory, &name("finding.json"), &finding)
        .unwrap();
    drop((directory, root, store));
    dispose(
        &case.state,
        text(&id).unwrap(),
        crate::record::Decision::Resolved,
        text("replay reproduced the planted violation").unwrap(),
    )
    .unwrap();
    let listed = findings(&case.state).unwrap();
    assert_eq!(listed["findings"][0]["resolved"], true, "{listed}");
    assert_eq!(listed["release_blockers"], serde_json::json!([]));
}

/// `findings` bounds each listing on its own, so it lists a state
/// directory whose pending entries exceed the scan bound in total while no
/// single directory reaches it.
#[test]
fn findings_lists_past_the_total_bound_when_no_directory_reaches_it() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let last = (0..12)
        .map(|run| {
            let job = crate::campaign::state_fixture::job(&store, run);
            crate::campaign::state_fixture::attempt(&store, &job, 1, 0);
            job.job().id().to_string()
        })
        .max()
        .unwrap();
    drop(store);
    // A damaged pin in the last shard listed is a release blocker, so the
    // scan reaches every shard.
    let pin = crate::layout::job_file(&last, &format!("{last}.pin"));
    std::fs::write(case.state.join(&pin), b"damaged").unwrap();
    let total: usize = ["jobs", "attempts"]
        .iter()
        .flat_map(|root| std::fs::read_dir(case.state.join(root)).unwrap())
        .map(|shard| std::fs::read_dir(shard.unwrap().path()).unwrap().count())
        .sum();
    let bound = 16;
    assert!(total > bound, "{total}");
    crate::step::install(Some(crate::step::Script {
        scan_bound: Some(bound),
        ..crate::step::Script::default()
    }));
    let listed = super::findings(&case.state);
    crate::step::install(None);
    assert_eq!(
        listed.unwrap()["release_blockers"],
        serde_json::json!([pin.to_str().unwrap()])
    );
}

#[test]
fn first_admission_retries_after_each_shard_creation_cut() {
    use crate::step::{Outcome, Step};
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let (admitted, trace) = crate::store::fixture::scripted([], || admit(&store, &request()));
    assert!(admitted.unwrap().is_ok());
    assert!(trace.contains(&Step::Mkdir));
    let mut saw_empty_shard = false;
    for (index, step) in trace
        .iter()
        .enumerate()
        .filter(|(_, step)| matches!(step, Step::Mkdir | Step::Sync))
    {
        for outcome in [Outcome::Kill, Outcome::Errno(libc::EIO)] {
            let case = Case::new();
            let store = Store::open(&case.state).unwrap();
            let (result, reached) =
                crate::store::fixture::scripted([(index, outcome)], || admit(&store, &request()));
            assert_eq!(reached.last(), Some(step));
            assert!(result.is_none_or(|result| result.is_err()));
            drop(store);
            let store = Store::open(&case.state).unwrap();
            if case.state.join("jobs").is_dir() {
                let sizes: Vec<_> =
                    crate::campaign::state_fixture::job_file_lengths_by_shard(&case.state)
                        .iter()
                        .map(Vec::len)
                        .collect();
                if sizes.iter().all(|&size| size == 0) {
                    saw_empty_shard |= !sizes.is_empty();
                    assert!(
                        crate::campaign::show(&case.state).unwrap()["jobs"]
                            .as_array()
                            .unwrap()
                            .is_empty()
                    );
                }
            }
            let admitted = admit(&store, &request()).unwrap();
            assert!(admit(&store, &request()).unwrap().existing);
            let shown = crate::campaign::show(&case.state).unwrap();
            assert!(
                shown["jobs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["id"] == admitted.record.job().id().to_string()
                        && row.get("verified").is_some())
            );
        }
    }
    assert!(saw_empty_shard);
}
