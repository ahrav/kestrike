use super::*;
use crate::record::{Artifact, BOUND, Class, CorpusRetirement, ProbeOutcome, Record};
use crate::record::{CorpusAsset, CorpusProbe, CorpusVersion, Digest};
use crate::store::Store;
use crate::store::fixture::Case;

#[test]
fn semantic_keys_share_trajectory_across_roots() {
    let mut asset = asset();
    let id = asset.id();
    let key = asset.semantic_key();
    assert_eq!(
        id.to_string(),
        "84f805a792c76197f6aeeca1167e39dd9ddf252189576060b3a70a4ec1c15821"
    );
    assert_eq!(
        key.to_string(),
        "a02c6f9097f283a20f9191972464fba2200bbe860fecb69761b605d1ee8386a3"
    );
    asset.root = 2;
    asset.probe.manifest = Digest::of(b"root = 2");
    asset.probe.bundle = Digest::of(b"bundle 2");
    assert_ne!(id, asset.id());
    assert_eq!(key, asset.semantic_key());
    asset.probe.milestone = text("other-milestone").unwrap();
    assert_ne!(asset.semantic_key(), key);
}

#[test]
fn prefixes_hash_semantic_records_and_only_trajectory_for_novelty() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let mut records = vec![[0; 48]; 8];
    for (record, tag) in records.iter_mut().zip([1, 9, 10, 3, 4, 7, 8, 2]) {
        record[0] = tag;
    }
    let bytes = records.concat();
    store
        .create_once(store.root(), &name("bundle"), &bytes)
        .unwrap();
    let (prefix, state) = verify::prefixes(&store, store.root(), bytes.len() as u64, 6).unwrap();
    assert_eq!(
        prefix,
        Digest::of(
            &[
                records[0], records[3], records[4], records[5], records[6], records[7]
            ]
            .concat()
        )
    );
    assert_eq!(state, Digest::of(&[records[4], records[5]].concat()));
    assert_eq!(
        prefix.to_string(),
        "2b4d6a180e04b0673b2c81ec97e2a7a427fb22879319cd1e0910cacedbb48ef6"
    );
    assert_eq!(
        state.to_string(),
        "511209945b046a0ba4b98789ff9b4d4da7079d11708a93a54c3b8e98565a07d1"
    );
    assert!(matches!(
        verify::prefixes(&store, store.root(), bytes.len() as u64, 7),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn prefixes_refuse_record_tags_outside_the_bundle_format() {
    for unknown in [0, 11, 255] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let mut records = [[0; 48]; 3];
        for (record, tag) in records.iter_mut().zip([1, unknown, 4]) {
            record[0] = tag;
        }
        let bytes = records.concat();
        store
            .create_once(store.root(), &name("bundle"), &bytes)
            .unwrap();
        assert!(
            matches!(
                verify::prefixes(&store, store.root(), bytes.len() as u64, 2),
                Err(Error::Rejected(reason)) if reason == format!("corpus bundle has unknown record tag {unknown}")
            ),
            "tag {unknown}"
        );
    }
}

#[test]
fn an_unknown_retirement_preserves_the_empty_catalog() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    assert!(matches!(
        remove(&store, Digest::of(b"absent")),
        Err(Error::Rejected(_))
    ));
    assert!(Catalog::load(&store).unwrap().assets.is_empty());
    assert_eq!(Catalog::load(&store).unwrap().version, 0);
    assert!(
        store
            .open_dir(store.root(), &name("corpus"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn incomplete_custody_cannot_publish_assets_or_versions() {
    for started_missing in [true, false] {
        let (_case, store, asset) = verified_fixture();
        let dir = super::probe_directory(&store, &asset.probe).unwrap();
        crate::campaign::probe::released(&store, &dir, &asset.probe.attempt).unwrap();
        assert_eq!(
            verify::stored_result(&store, &dir, &asset.probe).unwrap(),
            asset
        );
        let expected = if started_missing {
            store.delete(&dir, &name("started")).unwrap();
            "probe started witness missing"
        } else {
            store
                .replace_record(
                    &dir,
                    &name("finished"),
                    &crate::record::ProbeFinished {
                        attempt: asset.probe.attempt.clone(),
                        outcome: crate::record::ProbeOutcome::Held,
                    },
                )
                .unwrap();
            "probe lifecycle is held or incomplete"
        };
        assert!(
            matches!(execute::publish(&store, &asset, &config(32 << 20)),
            Err(Error::Held(reason)) if reason == expected)
        );
        assert!(
            store
                .open_dir(store.root(), &name("corpus"))
                .unwrap()
                .is_none()
        );
    }
}

fn asset() -> CorpusAsset {
    CorpusAsset {
        boundary: 1,
        decisions: 1,
        prefix: Digest::of(b"prefix"),
        probe: CorpusProbe {
            archive: Digest::of(b"archive"),
            archive_path: text("/archive").unwrap(),
            attempt: text("corpus-probe-1").unwrap(),
            bundle: Digest::of(b"bundle"),
            bytes: 48,
            manifest: Digest::of(b"manifest"),
            milestone: text("pending-put").unwrap(),
        },
        profile: text("cluster-broad").unwrap(),
        root: 1,
        semantic: 1,
        state: Digest::of(b"state"),
    }
}

fn config(bytes: u64) -> crate::record::Configuration {
    crate::record::Configuration::new(
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
            ("artifact_inodes", 10000),
            ("backlog", 2),
            ("retained_builds", 1),
            ("corpus_count", 4),
            ("corpus_bytes", bytes),
        ]
        .into_iter()
        .map(|(key, value)| (text(key).unwrap(), value))
        .collect(),
    )
    .unwrap()
}

fn verified_fixture() -> (Case, Store, CorpusAsset) {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let asset = verified_probe(&store, "corpus-probe-1", 1);
    (case, store, asset)
}

fn verified_probe(store: &Store, id: &str, root: u64) -> CorpusAsset {
    use crate::record::{Artifact, Intent, ProbeFinished, ProbeOutcome, Started, Worker};
    let probes = directory(store, store.root(), "probes").unwrap();
    let dir = directory(store, &probes, id).unwrap();
    let manifest = format!(
        "version = 2\nprofile = upload\nroot = {root}\nbuild = {}\nexecutable = {}\nplatform = test\ntoolchain = test\nrecords = 10000\nbytes = 480000\n",
        Digest::of(b"archive"),
        Digest::of(b"executable")
    );
    let mut bytes = vec![0; 48];
    bytes[0] = 1;
    for chunk in manifest.as_bytes().chunks(43) {
        let mut record = [0; 48];
        record[0] = 2;
        record[1] = 1;
        record[4] = chunk.len() as u8;
        record[5..5 + chunk.len()].copy_from_slice(chunk);
        bytes.extend_from_slice(&record);
    }
    let mut turn = [0; 48];
    turn[0] = 4;
    turn[5] = u8::try_from(root).unwrap();
    bytes.extend_from_slice(&turn);
    store.create_once(&dir, &name("bundle"), &bytes).unwrap();
    store
        .create_once(&dir, &name("manifest"), manifest.as_bytes())
        .unwrap();
    let probe = CorpusProbe {
        archive: Digest::of(b"archive"),
        archive_path: text("/archive").unwrap(),
        attempt: text(id).unwrap(),
        bundle: Digest::of(&bytes),
        bytes: bytes.len() as u64,
        manifest: Digest::of(manifest.as_bytes()),
        milestone: text("pending-put").unwrap(),
    };
    once(store, &dir, "corpus-probe", &probe).unwrap();
    let artifacts = directory(store, &dir, "artifacts").unwrap();
    let evidence = directory(store, &artifacts, probe.attempt.as_str()).unwrap();
    let printed = format!(
        "milestone: pending-put boundary=13 semantic={} decisions=1 prefix={}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\nchild: suffix=0 sibling=0 class=success digest={} terminal=complete pass fired=03 required=03\nbranch: 1 children, 1 credited, 0 problems\n",
        bytes.len() / 48,
        Digest::of(&bytes),
        Digest::of(b"child")
    );
    let mut workers = std::collections::BTreeMap::new();
    for (phase, stdout) in [
        (
            "capabilities",
            include_str!("../../../testdata/admission-listing.txt"),
        ),
        ("branch", printed.as_str()),
    ] {
        store
            .create_once(
                &evidence,
                &name(&format!("{phase}.stdout")),
                stdout.as_bytes(),
            )
            .unwrap();
        workers.insert(
            text(phase).unwrap(),
            Worker {
                ended: text("exited").unwrap(),
                exit: Some(0),
                signal: None,
                stderr: Digest::of(b""),
                stdout: Digest::of(stdout.as_bytes()),
            },
        );
    }
    once(
        store,
        &evidence,
        "artifact",
        &Artifact {
            archive: Some(probe.archive),
            archive_path: Some(probe.archive_path.clone()),
            bundle: Some(probe.bundle),
            class: text("counts").unwrap(),
            command: text("branch").unwrap(),
            comparison: None,
            manifest: Some(Digest::of(&crate::sim::input::worker_manifest(&manifest))),
            output: None,
            reason: text("counts").unwrap(),
            run_id: probe.attempt.clone(),
            session: None,
            session_original: None,
            summary: None,
            workers,
        },
    )
    .unwrap();
    let cgroup = text(store.path().join("absent-cgroup").to_str().unwrap()).unwrap();
    once(
        store,
        &dir,
        "intent",
        &Intent {
            attempt: probe.attempt.clone(),
            boot: text("boot").unwrap(),
            cgroup: cgroup.clone(),
        },
    )
    .unwrap();
    once(
        store,
        &dir,
        "started",
        &Started {
            attempt: probe.attempt.clone(),
            baseline: Default::default(),
            boot: text("boot").unwrap(),
            cgroup,
            cgroup_inode: 1,
            launcher_pid: 1,
        },
    )
    .unwrap();
    once(
        store,
        &dir,
        "finished",
        &ProbeFinished {
            attempt: probe.attempt.clone(),
            outcome: ProbeOutcome::Complete,
        },
    )
    .unwrap();
    verify::result(store, &dir, &probe, Some(0)).unwrap()
}

/// The rewritten stdout carries a matching artifact digest, so verification
/// reaches the changed output.
fn rewrite_branch_output(
    store: &Store,
    dir: &crate::store::Dir,
    probe: &CorpusProbe,
    from: &str,
    to: &str,
) {
    let artifacts = store.open_dir(dir, &name("artifacts")).unwrap().unwrap();
    let evidence = store
        .open_dir(&artifacts, &name(probe.attempt.as_str()))
        .unwrap()
        .unwrap();
    let stdout = store
        .read(&evidence, &name("branch.stdout"), BOUND)
        .unwrap()
        .unwrap();
    let changed = String::from_utf8(stdout.bytes().to_vec())
        .unwrap()
        .replace(from, to);
    assert_ne!(changed.as_bytes(), stdout.bytes());
    drop(stdout);
    store
        .replace(&evidence, &name("branch.stdout"), changed.as_bytes())
        .unwrap();
    let artifact = store
        .read_record::<Artifact>(&evidence, &name("artifact"))
        .unwrap()
        .unwrap();
    let mut artifact = artifact.record().clone();
    artifact
        .workers
        .get_mut(&text("branch").unwrap())
        .unwrap()
        .stdout = Digest::of(changed.as_bytes());
    store
        .replace_record(&evidence, &name("artifact"), &artifact)
        .unwrap();
}

#[test]
fn the_byte_boundary_counts_probe_asset_versions_and_reserved_retirement() {
    use crate::record::{CorpusRetirement, Record};
    let (_case, store, asset) = verified_fixture();
    let probe = super::probe_directory(&store, &asset.probe).unwrap();
    let probe_bytes = probe.usage(crate::SCAN_BOUND).unwrap().bytes;
    let need = probe_bytes
        + asset.encoded_len() as u64
        + CorpusRetirement { asset: asset.id() }.encoded_len() as u64
        + [false, true]
            .into_iter()
            .map(|retired| {
                CorpusVersion {
                    asset: asset.id(),
                    number: u64::MAX,
                    retired,
                }
                .encoded_len() as u64
            })
            .sum::<u64>();
    assert!(need > asset.probe.bytes);
    assert!(
        matches!(execute::publish(&store, &asset, &config(need-1)), Err(Error::Rejected(reason)) if reason == "corpus byte limit reached")
    );
    assert!(
        store
            .open_dir(store.root(), &name("corpus"))
            .unwrap()
            .is_none()
    );
    assert_eq!(execute::publish(&store, &asset, &config(need)).unwrap(), 1);
    let v1 = CorpusVersion {
        asset: asset.id(),
        number: 1,
        retired: false,
    };
    let reserved = CorpusVersion {
        asset: asset.id(),
        number: u64::MAX,
        retired: true,
    };
    let retirement = CorpusRetirement { asset: asset.id() };
    assert_eq!(
        retained_bytes(&store, &Catalog::load(&store).unwrap()).unwrap(),
        probe_bytes
            + asset.encoded_len() as u64
            + v1.encoded_len() as u64
            + retirement.encoded_len() as u64
            + reserved.encoded_len() as u64
    );
    assert_eq!(remove(&store, asset.id()).unwrap(), 2);
    let v2 = CorpusVersion {
        asset: asset.id(),
        number: 2,
        retired: true,
    };
    assert_eq!(
        retained_bytes(&store, &Catalog::load(&store).unwrap()).unwrap(),
        probe_bytes
            + asset.encoded_len() as u64
            + retirement.encoded_len() as u64
            + v1.encoded_len() as u64
            + v2.encoded_len() as u64
    );
    assert!(retained_bytes(&store, &Catalog::load(&store).unwrap()).unwrap() <= need);
}

#[test]
fn fsync_faults_keep_registered_and_retired_corpus_reconcilable() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    for retiring in [false, true] {
        let (_case, store, asset) = verified_fixture();
        if retiring {
            execute::publish(&store, &asset, &config(32 << 20)).unwrap();
        }
        let (result, trace) = scripted([], || {
            if retiring {
                remove(&store, asset.id())
            } else {
                execute::publish(&store, &asset, &config(32 << 20))
            }
        });
        assert!(result.unwrap().is_ok());
        let indices: Vec<_> = trace
            .iter()
            .enumerate()
            .filter(|(_, step)| **step == Step::Sync)
            .map(|(index, _)| index)
            .collect();
        assert!(!indices.is_empty());
        let rename = trace.iter().position(|step| *step == Step::Rename).unwrap();
        drop(store);
        for index in indices {
            for outcome in [Outcome::Errno(libc::EIO), Outcome::Kill] {
                let (case, store, asset) = verified_fixture();
                if retiring {
                    execute::publish(&store, &asset, &config(32 << 20)).unwrap();
                }
                let bundle_path = case.state.join("probes/corpus-probe-1/bundle");
                let frozen = std::fs::read(&bundle_path).unwrap();
                let (result, reached) = scripted([(index, outcome)], || {
                    if retiring {
                        remove(&store, asset.id())
                    } else {
                        execute::publish(&store, &asset, &config(32 << 20))
                    }
                });
                assert!(reached.len() > index);
                assert_eq!(reached[index], Step::Sync);
                assert!(result.is_none_or(|result| result.is_err()));
                if matches!(outcome, Outcome::Errno(_)) {
                    assert!(matches!(
                        store.create_once(store.root(), &name("after-fault"), b"held"),
                        Err(crate::store::Error::Poisoned)
                    ));
                }
                drop(store);
                let store = Store::open(&case.state).unwrap();
                let catalog = reconcile(&store).unwrap();
                assert_eq!(
                    catalog.assets.contains_key(&asset.id()),
                    retiring || index > rename
                );
                if retiring {
                    assert_eq!(catalog.assets[&asset.id()].retired, index > rename);
                }
                let snapshot = crate::store::fixture::snapshot(&case.state);
                let twice = reconcile(&store).unwrap();
                assert_eq!(crate::store::fixture::snapshot(&case.state), snapshot);
                assert_eq!(twice.version, catalog.version);
                assert_eq!(twice.assets.len(), catalog.assets.len());
                assert_eq!(std::fs::read(bundle_path).unwrap(), frozen);
                if let Some(row) = catalog.assets.get(&asset.id()) {
                    assert_eq!(row.asset, asset);
                    assert_eq!(catalog.version, if row.retired { 2 } else { 1 });
                    assert_eq!(row.version, Some(1));
                } else {
                    assert!(!retiring);
                    assert_eq!(catalog.version, 0);
                }
            }
        }
    }
}

#[test]
fn successful_probes_still_require_publish_time_count_headroom() {
    let (_case, store, first) = verified_fixture();
    let second = verified_probe(&store, "corpus-probe-2", 2);
    execute::publish(&store, &first, &config(32 << 20)).unwrap();
    let mut settings = config(32 << 20).config().clone();
    settings.insert(text("corpus_count").unwrap(), 1);
    let config = crate::record::Configuration::new(settings).unwrap();
    assert!(
        matches!(execute::publish(&store, &second, &config), Err(Error::Rejected(reason)) if reason == "corpus count limit reached")
    );
    let catalog = Catalog::load(&store).unwrap();
    assert_eq!(catalog.version, 1);
    assert_eq!(catalog.assets.len(), 1);
    assert!(!catalog.assets.contains_key(&second.id()));
}

#[test]
fn malformed_version_histories_hold_projection_and_reconciliation() {
    for fault in 0..7 {
        let (_case, store, asset) = verified_fixture();
        execute::publish(&store, &asset, &config(32 << 20)).unwrap();
        let corpus = store
            .open_dir(store.root(), &name("corpus"))
            .unwrap()
            .unwrap();
        let versions = store.open_dir(&corpus, &name("versions")).unwrap().unwrap();
        let mut bad = CorpusVersion {
            asset: asset.id(),
            number: 1,
            retired: false,
        };
        let expected = match fault {
            0 => {
                bad.number = 2;
                store.replace_record(&versions, &name("1"), &bad).unwrap();
                "corpus version name differs"
            }
            1 => {
                store.delete(&versions, &name("1")).unwrap();
                bad.number = 0;
                once(&store, &versions, "0", &bad).unwrap();
                "corpus version name differs"
            }
            2 => {
                bad.asset = Digest::of(b"absent");
                store.replace_record(&versions, &name("1"), &bad).unwrap();
                "corpus version asset missing"
            }
            3 => {
                remove(&store, asset.id()).unwrap();
                store.delete(&versions, &name("2")).unwrap();
                bad.number = 3;
                bad.retired = true;
                once(&store, &versions, "3", &bad).unwrap();
                "corpus version history differs"
            }
            4 => {
                remove(&store, asset.id()).unwrap();
                bad.number = 2;
                store.replace_record(&versions, &name("2"), &bad).unwrap();
                "corpus version history differs"
            }
            5 => {
                remove(&store, asset.id()).unwrap();
                store.delete(&versions, &name("2")).unwrap();
                bad.retired = true;
                store.replace_record(&versions, &name("1"), &bad).unwrap();
                "corpus version history differs"
            }
            6 => {
                bad.number = 2;
                bad.retired = true;
                once(&store, &versions, "2", &bad).unwrap();
                "corpus version history differs"
            }
            _ => unreachable!(),
        };
        assert!(matches!(Catalog::load(&store), Err(Error::Held(reason)) if reason == expected));
        assert!(matches!(reconcile(&store), Err(Error::Held(reason)) if reason == expected));
        let mut held = Vec::new();
        let projection = super::project(&store, &mut held).unwrap();
        assert!(projection["assets"].as_array().unwrap().is_empty());
        assert!(projection["version"].is_null());
        assert_eq!(held[0]["path"], "corpus");
        assert_eq!(held[0]["reason"], expected);
    }
}

#[test]
fn an_unconfigured_corpus_refuses_before_creating_a_probe() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    assert!(
        matches!(add(&store, std::path::Path::new("/archive"), std::path::Path::new("/bundle"), "pending-put", std::path::Path::new("/root")), Err(Error::Rejected(reason)) if reason == "corpus requires configured count and byte limits")
    );
    assert!(
        store
            .open_dir(store.root(), &name("probes"))
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .open_dir(store.root(), &name("corpus"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn eligibility_requires_a_registration_version_and_an_active_asset() {
    for retired in [false, true] {
        for version in [None, Some(1)] {
            let row = super::history::Registered {
                asset: asset(),
                retired,
                version,
            };
            assert_eq!(row.eligible(), version.is_some() && !retired);
        }
    }
}

#[test]
fn damaged_dependencies_hold_registration_retirement_and_the_whole_projection() {
    let (case, store, first) = verified_fixture();
    execute::publish(&store, &first, &config(32 << 20)).unwrap();
    let second = verified_probe(&store, "corpus-probe-2", 2);
    let bundle = case.state.join("probes/corpus-probe-1/bundle");
    let original = std::fs::read(&bundle).unwrap();
    std::fs::write(&bundle, b"damaged").unwrap();
    assert!(
        matches!(remove(&store, first.id()), Err(Error::Held(reason)) if reason == "corpus bundle digest differs")
    );
    assert!(
        matches!(execute::publish(&store, &second, &config(32 << 20)), Err(Error::Held(reason)) if reason == "corpus bundle digest differs")
    );
    let mut held = Vec::new();
    let projection = super::project(&store, &mut held).unwrap();
    assert!(projection["assets"].as_array().unwrap().is_empty());
    assert_eq!(held[0]["path"], "corpus");
    assert_eq!(held[0]["reason"], "corpus bundle digest differs");
    assert!(
        !case
            .state
            .join("corpus/assets")
            .join(first.id().to_string())
            .join("retired")
            .exists()
    );
    assert!(
        !case
            .state
            .join("corpus/assets")
            .join(second.id().to_string())
            .exists()
    );
    std::fs::write(bundle, original).unwrap();
    assert_eq!(Catalog::load(&store).unwrap().version, 1);
    assert_eq!(
        execute::publish(&store, &second, &config(32 << 20)).unwrap(),
        2
    );
    assert_eq!(remove(&store, first.id()).unwrap(), 3);
}

#[test]
fn status_lists_a_published_corpus_asset_without_a_sync() {
    use crate::step::Step;
    use crate::store::fixture::scripted;
    let (case, store, asset) = verified_fixture();
    execute::publish(&store, &asset, &config(32 << 20)).unwrap();
    drop(store);
    let before = crate::store::fixture::snapshot(&case.state);
    let (shown, reached) = scripted([], || crate::campaign::status_tests::status(&case.state));
    let shown = shown.unwrap().unwrap();
    assert_eq!(crate::store::fixture::snapshot(&case.state), before);
    assert!(
        !reached.contains(&Step::Sync),
        "status issued an fsync: {reached:?}"
    );
    assert_eq!(shown["release_blockers"], serde_json::json!([]));
    let listed = crate::campaign::findings(&case.state).unwrap();
    assert_eq!(shown["findings"], listed["findings"]);
}

#[test]
fn catalog_barrier_faults_withhold_assets_and_keep_reread_probes_held() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let (case, store, asset) = verified_fixture();
    execute::publish(&store, &asset, &config(32 << 20)).unwrap();
    let view = crate::store::View::open(&case.state).unwrap();
    let (catalog, trace) = scripted([], || Catalog::load(&view));
    assert_eq!(catalog.unwrap().unwrap().version, 1);
    for index in trace
        .iter()
        .enumerate()
        .filter_map(|(index, step)| (*step == Step::Sync).then_some(index))
    {
        let view = crate::store::View::open(&case.state).unwrap();
        let mut held = Vec::new();
        let (projected, reached) = scripted([(index, Outcome::Errno(libc::EIO))], || {
            super::project(&view, &mut held)
        });
        assert!(reached.len() > index);
        assert_eq!(reached[index], Step::Sync);
        let projected = projected.unwrap().unwrap();
        assert!(projected["version"].is_null());
        assert!(projected["assets"].as_array().unwrap().is_empty());
        assert_eq!(held[0]["path"], "corpus");
        let mut held = Vec::new();
        let reread = super::project(&view, &mut held).unwrap();
        assert!(reread["assets"].as_array().unwrap().is_empty());
        assert_eq!(held[0]["path"], "corpus");
    }
}

#[test]
fn probe_root_damage_is_held_and_a_listing_host_fault_propagates() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store
        .create_once(store.root(), &name("probes"), b"damaged")
        .unwrap();
    let mut held = Vec::new();
    assert!(super::project(&store, &mut held).is_ok());
    assert_eq!(held[0]["path"], "probes");
    store.delete(store.root(), &name("probes")).unwrap();
    store.mkdir(store.root(), &name("probes")).unwrap();
    let (_, trace) = scripted([], || super::project(&store, &mut Vec::new()));
    let index = trace.iter().position(|step| *step == Step::List).unwrap();
    let mut held = Vec::new();
    let (projected, reached) = scripted([(index, Outcome::Errno(libc::EIO))], || {
        super::project(&store, &mut held)
    });
    assert!(reached.len() > index);
    assert_eq!(reached[index], Step::List);
    let error = projected.unwrap().unwrap_err();
    assert!(error.host_fault());
    assert_eq!(error.exit(), crate::exit::Supervisor::Held);
    assert!(held.is_empty());
}

#[test]
fn persistent_probe_refusals_are_held_while_fresh_probe_refusals_are_rejected() {
    use crate::record::{Artifact, BOUND};
    let (_case, store, asset) = verified_fixture();
    let dir = super::probe_directory(&store, &asset.probe).unwrap();
    let artifacts = store.open_dir(&dir, &name("artifacts")).unwrap().unwrap();
    let evidence = store
        .open_dir(&artifacts, &name(asset.probe.attempt.as_str()))
        .unwrap()
        .unwrap();
    let stdout = store
        .read(&evidence, &name("branch.stdout"), BOUND)
        .unwrap()
        .unwrap();
    let changed = String::from_utf8(stdout.bytes().to_vec()).unwrap().replace(
        &asset.prefix.to_string(),
        &Digest::of(b"wrong prefix").to_string(),
    );
    drop(stdout);
    store
        .replace(&evidence, &name("branch.stdout"), changed.as_bytes())
        .unwrap();
    let artifact = store
        .read_record::<Artifact>(&evidence, &name("artifact"))
        .unwrap()
        .unwrap();
    let mut record = artifact.record().clone();
    record
        .workers
        .get_mut(&text("branch").unwrap())
        .unwrap()
        .stdout = Digest::of(changed.as_bytes());
    drop(artifact);
    store
        .replace_record(&evidence, &name("artifact"), &record)
        .unwrap();
    assert!(
        matches!(verify::result(&store, &dir, &asset.probe, Some(0)), Err(Error::Rejected(reason)) if reason == "corpus prefix differs from the frozen bundle")
    );
    assert!(
        matches!(verify::stored_result(&store, &dir, &asset.probe), Err(Error::Held(reason)) if reason == "corpus prefix differs from the frozen bundle")
    );
}

#[test]
fn failed_probe_history_uses_the_shared_artifact_budget() {
    use crate::record::{ProbeFinished, ProbeOutcome};
    let (_case, store, asset) = verified_fixture();
    let dir = super::probe_directory(&store, &asset.probe).unwrap();
    store
        .replace_record(
            &dir,
            &name("finished"),
            &ProbeFinished {
                attempt: asset.probe.attempt.clone(),
                outcome: ProbeOutcome::Held,
            },
        )
        .unwrap();
    for (outcome, state) in [
        (ProbeOutcome::Held, "held"),
        (ProbeOutcome::OutputLimit, "output-limit"),
        (ProbeOutcome::Oom, "oom"),
        (ProbeOutcome::PidLimit, "pid-limit"),
        (ProbeOutcome::CpuLimit, "cpu-limit"),
        (ProbeOutcome::MixedLimits, "mixed-limits"),
    ] {
        store
            .replace_record(
                &dir,
                &name("finished"),
                &ProbeFinished {
                    attempt: asset.probe.attempt.clone(),
                    outcome,
                },
            )
            .unwrap();
        assert_eq!(
            retained_bytes(&store, &Catalog::load(&store).unwrap()).unwrap(),
            0
        );
        let mut held = Vec::new();
        let projection = projection::project(&store, &mut held).unwrap();
        assert!(held.is_empty());
        assert_eq!(projection["probes"][0]["state"], state);
        assert_eq!(projection["probes"][0]["charged"], false);
        assert!(projection["assets"].as_array().unwrap().is_empty());
    }
    let config = config(1);
    let usage = crate::campaign::census::census(&store, &config).unwrap();
    assert_eq!(u128::from(usage.bytes), config.charge().bytes);
    store
        .replace(&dir, &name("launcher.stdout"), &vec![0; 9 << 20])
        .unwrap();
    let measured = dir.usage(crate::SCAN_BOUND).unwrap();
    assert!(measured.bytes > (8 << 20), "{measured:?}");
    assert!(
        u128::from(measured.bytes) <= config.charge().bytes,
        "{measured:?}"
    );
    assert!(
        u128::from(measured.inodes) <= config.charge().inodes,
        "{measured:?}"
    );
    store
        .create_once(&dir, &name("history-padding"), &[0; 4096])
        .unwrap();
    assert_eq!(
        crate::campaign::census::census(&store, &config)
            .unwrap()
            .bytes,
        usage.bytes
    );
    let reserve = config.value("reserve_slots");
    let threshold = usage.bytes + (1 + reserve) * u64::try_from(config.charge().bytes).unwrap();
    for (limit, paused) in [(threshold, true), (threshold + 1, false)] {
        let mut settings = config.config().clone();
        settings.insert(text("artifact_bytes").unwrap(), limit);
        let bounded = crate::record::Configuration::new(settings).unwrap();
        let usage = crate::campaign::census::census(&store, &bounded).unwrap();
        assert_eq!(
            super::super::dispatch::storage_pauses(&bounded, usage, 0, reserve)
                .contains("artifact_bytes"),
            paused
        );
    }
    assert_eq!(
        retained_bytes(&store, &Catalog::load(&store).unwrap()).unwrap(),
        0
    );
}

#[test]
fn classification_and_signal_faults_judge_the_stopped_probe_held() {
    let classification = || Ok((Class::Incomplete, vec!["tree_memory"], false));
    assert!(
        execute::stop_judgement(classification(), Ok(None), (None, None), false, Some(0)).is_ok()
    );
    for fault in [
        crate::custody::Error::Held("kernel counter vanished"),
        crate::custody::Error::Held("kernel counter regressed"),
    ] {
        assert!(matches!(
            execute::stop_judgement(Err(fault), Ok(None), (None, None), false, Some(0)),
            Err((ProbeOutcome::Held, Error::Held(_)))
        ));
    }
    let descriptor =
        crate::custody::Error::Io(std::io::Error::other("short signal descriptor read"));
    assert!(matches!(
        execute::stop_judgement(
            classification(),
            Err(descriptor),
            (None, None),
            false,
            Some(0)
        ),
        Err((
            ProbeOutcome::Held,
            Error::Store(crate::store::Error::Unreadable(_))
        ))
    ));
}

#[test]
fn kernel_limited_probes_refuse_successful_exits_and_interrupted_probes_stay_held() {
    use crate::record::{Class, ProbeOutcome};
    for code in [0, 1] {
        for (class, outcome, limit) in [
            (
                Class::OutputLimit,
                ProbeOutcome::OutputLimit,
                "attempt_output or attempt_inodes",
            ),
            (Class::Oom, ProbeOutcome::Oom, "tree_memory"),
            (Class::PidLimit, ProbeOutcome::PidLimit, "processes"),
            (Class::CpuLimit, ProbeOutcome::CpuLimit, "cpu"),
            (
                Class::MixedLimits,
                ProbeOutcome::MixedLimits,
                "tree_memory, processes",
            ),
        ] {
            let Err((actual, Error::Rejected(reason))) = execute::probe_judgement(
                class,
                &["tree_memory", "processes"],
                (None, None),
                false,
                Some(code),
                false,
            ) else {
                panic!("kernel-limited probe must refuse exit {code}");
            };
            assert_eq!(actual, outcome);
            assert_eq!(
                reason,
                format!(
                    "corpus probe {} exceeds configured {limit} limit",
                    class.name()
                )
            );
            if class != Class::OutputLimit {
                assert!(matches!(
                    execute::probe_judgement(
                        class,
                        &["tree_memory", "processes"],
                        (Some(crate::sys::OUTPUT_SIGNAL), None),
                        false,
                        Some(code),
                        false,
                    ),
                    Err((ProbeOutcome::Held, Error::Held(_)))
                ));
            }
        }
        assert!(
            execute::probe_judgement(
                Class::Incomplete,
                &[],
                (None, None),
                false,
                Some(code),
                false
            )
            .is_ok()
        );
        for (class, limits, outcome, limit) in [
            (Class::CpuLimit, vec!["cpu"], ProbeOutcome::CpuLimit, "cpu"),
            (
                Class::MixedLimits,
                vec!["tree_memory", "cpu"],
                ProbeOutcome::MixedLimits,
                "tree_memory, cpu",
            ),
            (
                Class::MixedLimits,
                vec!["processes", "cpu"],
                ProbeOutcome::MixedLimits,
                "processes, cpu",
            ),
            (
                Class::MixedLimits,
                vec!["tree_memory", "processes", "cpu"],
                ProbeOutcome::MixedLimits,
                "tree_memory, processes, cpu",
            ),
        ] {
            let Err((actual, Error::Rejected(reason))) = execute::probe_judgement(
                class,
                &limits,
                (Some(crate::sys::CPU_SIGNAL), None),
                false,
                Some(code),
                false,
            ) else {
                panic!("CPU enforcement must reject exit {code}");
            };
            assert_eq!(actual, outcome);
            assert_eq!(
                reason,
                format!(
                    "corpus probe {} exceeds configured {limit} limit",
                    class.name()
                )
            );
        }
    }
    for (class, signal, watchdog) in [
        (Class::CpuLimit, Some(libc::SIGTERM), false),
        (Class::OutputLimit, Some(libc::SIGINT), false),
        (Class::OutputLimit, Some(libc::SIGTERM), false),
        (Class::OutputLimit, Some(crate::sys::OUTPUT_SIGNAL), true),
        (Class::OutputLimit, None, true),
    ] {
        assert!(matches!(
            execute::probe_judgement(class, &[], (signal, None), watchdog, Some(0), false),
            Err((ProbeOutcome::Held, Error::Held(_)))
        ));
    }
    assert!(matches!(
        execute::probe_judgement(
            Class::OutputLimit,
            &[],
            (Some(crate::sys::OUTPUT_SIGNAL), None),
            false,
            Some(0),
            false,
        ),
        Err((ProbeOutcome::OutputLimit, Error::Rejected(_)))
    ));
    for class in [
        Class::Oom,
        Class::PidLimit,
        Class::CpuLimit,
        Class::MixedLimits,
    ] {
        for interruption in [None, Some(crate::sys::CPU_SIGNAL), Some(libc::SIGTERM)] {
            assert!(matches!(
                execute::probe_judgement(
                    class,
                    &["tree_memory", "cpu"],
                    (interruption, Some(crate::sys::OUTPUT_SIGNAL)),
                    false,
                    None,
                    false,
                ),
                Err((ProbeOutcome::Held, Error::Held(_)))
            ));
        }
    }
    assert!(matches!(
        execute::probe_judgement(
            Class::OutputLimit,
            &[],
            (None, Some(crate::sys::OUTPUT_SIGNAL)),
            false,
            None,
            false,
        ),
        Err((ProbeOutcome::OutputLimit, Error::Rejected(_)))
    ));
}

#[test]
fn prefix_storage_faults_are_held_and_short_inputs_are_rejected() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let (_case, store, asset) = verified_fixture();
    let dir = super::probe_directory(&store, &asset.probe).unwrap();
    let (result, trace) = scripted([], || {
        verify::prefixes(&store, &dir, asset.probe.bytes, asset.semantic)
    });
    assert!(result.unwrap().is_ok());
    let index = trace.iter().position(|step| *step == Step::Read).unwrap();
    let (result, reached) = scripted([(index, Outcome::Errno(libc::EIO))], || {
        verify::prefixes(&store, &dir, asset.probe.bytes, asset.semantic)
    });
    assert!(reached.len() > index);
    assert_eq!(reached[index], Step::Read);
    assert!(matches!(result.unwrap(), Err(Error::Unreadable(error)) if error.faulted()));
    assert!(matches!(
        verify::prefixes(&store, &dir, 1, asset.semantic),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn source_open_and_read_faults_hold_staging_without_a_probe_record() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let (case, store, _asset) = verified_fixture();
    let source = case.state.join("probes/corpus-probe-1/bundle");
    let (result, trace) = scripted([], || execute::stage(&store, &source, 4 << 20));
    assert!(result.unwrap().is_ok());
    let open = trace.iter().position(|step| *step == Step::Open).unwrap();
    let read = trace.iter().rposition(|step| *step == Step::Read).unwrap();
    drop(store);
    for (index, errno, reading) in [
        (open, libc::EIO, false),
        (open, libc::EMFILE, false),
        (read, libc::EIO, true),
    ] {
        let (case, store, _asset) = verified_fixture();
        let source = case.state.join("probes/corpus-probe-1/bundle");
        let (result, reached) = scripted([(index, Outcome::Errno(errno))], || {
            execute::stage(&store, &source, 4 << 20)
        });
        assert!(reached.len() > index);
        assert_eq!(
            reached[index],
            if reading { Step::Read } else { Step::Open }
        );
        match result.unwrap() {
            Err(Error::Held(reason)) if reading => {
                assert!(reason.starts_with("corpus source read failed:"))
            }
            Err(Error::Unreadable(_)) if !reading => {}
            _ => panic!("the source fault must hold staging"),
        }
        assert!(Catalog::load(&store).unwrap().assets.is_empty());
        assert_eq!(Catalog::load(&store).unwrap().version, 0);
        let probes = store
            .open_dir(store.root(), &name("probes"))
            .unwrap()
            .unwrap();
        for entry in store.list(&probes, crate::SCAN_BOUND).unwrap() {
            if entry.as_str() == "corpus-probe-1" {
                continue;
            }
            let dir = store.open_dir(&probes, &entry).unwrap().unwrap();
            assert!(
                store
                    .read_record::<CorpusProbe>(&dir, &name("corpus-probe"))
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[test]
fn changed_source_is_held_before_a_scan_refusal_becomes_rejected() {
    use crate::step::Step;
    use crate::store::fixture::observed;
    let (case, store, _asset) = verified_fixture();
    let source = case.state.join("probes/corpus-probe-1/bundle");
    let changed = source.clone();
    let mut replaced = false;
    let result = observed(
        move |step| {
            if step == Step::Read && !replaced {
                std::fs::write(&changed, b"torn").unwrap();
                replaced = true;
            }
        },
        || execute::stage(&store, &source, 4 << 20),
    );
    assert!(
        matches!(result, Err(Error::Held(reason)) if reason == "corpus source changed while staging")
    );
    assert!(matches!(
        execute::stage(&store, &source, 4 << 20),
        Err(Error::Rejected(_))
    ));
    assert!(Catalog::load(&store).unwrap().assets.is_empty());
    assert_eq!(Catalog::load(&store).unwrap().version, 0);
}

#[test]
fn probe_provenance_preserves_frozen_prefix_identity() {
    let mut asset = asset();
    let id = asset.id();
    let key = asset.semantic_key();
    asset.probe.attempt = text("another-probe").unwrap();
    asset.probe.archive_path = text("/another/archive").unwrap();
    assert_eq!(asset.id(), id);
    assert_eq!(asset.semantic_key(), key);
}

#[test]
fn signals_during_verification_and_publication_preparation_hold_the_asset() {
    for preparing in [false, true] {
        let (case, store, asset) = verified_fixture();
        let dir = super::probe_directory(&store, &asset.probe).unwrap();
        let signals = crate::sys::Signals::open().unwrap();
        let sent = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = sent.clone();
        let checked = crate::store::fixture::observed(
            move |step| {
                if step == crate::step::Step::Sync && !observed.get() {
                    crate::sys::interrupt(crate::sys::TERM_SIGNAL).unwrap();
                    observed.set(true);
                }
            },
            || {
                if preparing {
                    execute::publication_directory(&store, &asset, &config(32 << 20)).map(|_| ())
                } else {
                    verify::result(&store, &dir, &asset.probe, Some(0)).map(|_| ())
                }
            },
        );
        assert!(sent.get());
        checked.unwrap();
        let pending = signals.take().unwrap();
        assert_eq!(pending, Some(crate::sys::TERM_SIGNAL));
        assert!(
            matches!(execute::uninterrupted(pending), Err(Error::Held(reason)) if reason == "corpus publication interrupted")
        );
        let catalog = Catalog::load(&store).unwrap();
        assert!(catalog.assets.is_empty());
        assert_eq!(catalog.version, 0);
        assert!(
            !case
                .state
                .join("corpus/assets")
                .join(asset.id().to_string())
                .join("asset")
                .exists()
        );
    }
}

#[test]
fn a_signal_during_a_refused_verification_holds_the_probe() {
    // A controller signal before the publication cutoff outranks the
    // verification's refusal, so the probe exits Held.
    let (_case, store, asset) = verified_fixture();
    let dir = super::probe_directory(&store, &asset.probe).unwrap();
    rewrite_branch_output(
        &store,
        &dir,
        &asset.probe,
        "upload=attempt:1,grant:3,held:2,outcome:0",
        "upload=none",
    );
    let signals = crate::sys::Signals::open().unwrap();
    let sent = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = sent.clone();
    let verification = crate::store::fixture::observed(
        move |step| {
            if step == crate::step::Step::Sync && !observed.get() {
                crate::sys::interrupt(crate::sys::TERM_SIGNAL).unwrap();
                observed.set(true);
            }
        },
        || verify::result(&store, &dir, &asset.probe, Some(0)),
    );
    assert!(sent.get());
    assert!(
        matches!(&verification, Err(Error::Rejected(reason)) if reason == "corpus witness facts do not satisfy the milestone")
    );
    let pending = signals.take().unwrap();
    assert_eq!(pending, Some(crate::sys::TERM_SIGNAL));
    assert!(
        matches!(execute::judged(verification, pending), Err(Error::Held(reason)) if reason == "corpus publication interrupted")
    );
    assert!(Catalog::load(&store).unwrap().assets.is_empty());
}

#[test]
fn a_signal_after_the_publication_cutoff_completes_verified_publication() {
    let (case, store, asset) = verified_fixture();
    let dir = execute::publication_directory(&store, &asset, &config(32 << 20)).unwrap();
    let signals = crate::sys::Signals::open().unwrap();
    execute::uninterrupted(signals.take().unwrap()).unwrap();
    let sent = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = sent.clone();
    let version = crate::store::fixture::observed(
        move |step| {
            if step == crate::step::Step::Sync && !observed.get() {
                crate::sys::interrupt(crate::sys::TERM_SIGNAL).unwrap();
                observed.set(true);
            }
        },
        || execute::register(&store, &dir, &asset),
    )
    .unwrap();
    assert!(sent.get());
    assert_eq!(signals.take().unwrap(), Some(crate::sys::TERM_SIGNAL));
    assert_eq!(version, 1);
    let catalog = Catalog::load(&store).unwrap();
    assert_eq!(catalog.assets[&asset.id()].asset, asset);
    assert!(catalog.assets[&asset.id()].eligible());
    drop(store);
    assert!(
        crate::campaign::report(&case.state).unwrap()["held"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn witness_facts_are_evaluated_independently_of_the_holds_flag() {
    for replacement in [
        "upload=none",
        "upload=attempt:0,grant:3,held:2,outcome:0",
        "upload=attempt:1,grant:0,held:2,outcome:0",
        "upload=attempt:1,grant:3,held:0,outcome:0",
        "upload=attempt:1,grant:3,held:2,outcome:1",
    ] {
        let (_case, store, asset) = verified_fixture();
        let dir = super::probe_directory(&store, &asset.probe).unwrap();
        assert_eq!(
            verify::stored_result(&store, &dir, &asset.probe).unwrap(),
            asset
        );
        rewrite_branch_output(
            &store,
            &dir,
            &asset.probe,
            "upload=attempt:1,grant:3,held:2,outcome:0",
            replacement,
        );
        assert!(
            matches!(verify::result(&store, &dir, &asset.probe, Some(0)), Err(Error::Rejected(reason)) if reason == "corpus witness facts do not satisfy the milestone")
        );
        assert!(matches!(
            execute::publish(&store, &asset, &config(32 << 20)),
            Err(Error::Held(_))
        ));
        assert!(Catalog::load(&store).unwrap().assets.is_empty());
    }
}

#[test]
fn external_launcher_stops_hold_limits_and_residual_members_hold_clean_probes() {
    for class in [
        Class::OutputLimit,
        Class::Oom,
        Class::PidLimit,
        Class::CpuLimit,
        Class::MixedLimits,
    ] {
        for code in [5, 6] {
            assert!(matches!(
                execute::probe_judgement(class, &[], (None, None), false, Some(code), false),
                Err((ProbeOutcome::Held, Error::Held(_)))
            ));
        }
        for signal in [libc::SIGINT, libc::SIGTERM] {
            assert!(matches!(
                execute::probe_judgement(class, &[], (None, Some(signal)), false, None, false),
                Err((ProbeOutcome::Held, Error::Held(_)))
            ));
            assert!(matches!(
                execute::probe_judgement(class, &[], (Some(signal), None), false, Some(0), false),
                Err((ProbeOutcome::Held, Error::Held(_)))
            ));
        }
    }
    for code in [0, 1] {
        assert!(matches!(
            execute::probe_judgement(
                Class::Infrastructure,
                &[],
                (None, None),
                false,
                Some(code),
                true
            ),
            Err((ProbeOutcome::Held, Error::Held(_)))
        ));
    }
}

#[test]
fn sealed_asset_entries_hold_catalog_report_and_findings() {
    let (case, store, asset) = verified_fixture();
    execute::publish(&store, &asset, &config(32 << 20)).unwrap();
    std::fs::write(
        case.state
            .join("corpus/assets")
            .join(asset.id().to_string())
            .join("unknown"),
        b"retained",
    )
    .unwrap();
    assert!(
        matches!(Catalog::load(&store), Err(Error::Held(reason)) if reason == "undeclared corpus asset entry")
    );
    assert!(matches!(reconcile(&store), Err(Error::Held(_))));
    let view = crate::store::View::open(&case.state).unwrap();
    let report = crate::campaign::report::project(&view).unwrap();
    assert!(report["corpus"]["assets"].as_array().unwrap().is_empty());
    assert!(
        report["held"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == "corpus")
    );
    assert_eq!(report["release_blockers"], serde_json::json!(["corpus"]));
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == "corpus"
                && row["held"] == "undeclared corpus asset entry"
                && row["blocker"] == true)
    );
    drop(view);
    drop(store);
    let findings = crate::campaign::findings(&case.state).unwrap();
    assert_eq!(findings["release_blockers"], serde_json::json!(["corpus"]));
    assert!(
        findings["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == "corpus"
                && row["held"] == "undeclared corpus asset entry"
                && row["blocker"] == true)
    );
}

#[test]
fn findings_propagates_corpus_host_read_faults() {
    use crate::step::{Outcome, Step};
    use crate::store::fixture::scripted;
    let (case, store, asset) = verified_fixture();
    execute::publish(&store, &asset, &config(32 << 20)).unwrap();
    drop(store);
    let (result, trace) = scripted([], || crate::campaign::findings(&case.state));
    assert!(result.unwrap().is_ok());
    for (index, step) in trace
        .iter()
        .enumerate()
        .filter(|(_, step)| matches!(step, Step::Read | Step::Open))
    {
        for errno in [libc::EIO, libc::EMFILE] {
            let (result, reached) = scripted([(index, Outcome::Errno(errno))], || {
                crate::campaign::findings(&case.state)
            });
            assert_eq!(reached[index], *step);
            assert!(
                result.unwrap().is_err(),
                "host fault at {index} {step:?} must propagate"
            );
        }
    }
}

#[test]
fn repeated_retirement_preserves_every_byte_and_the_current_version() {
    let (case, store, asset) = verified_fixture();
    execute::publish(&store, &asset, &config(32 << 20)).unwrap();
    assert_eq!(remove(&store, asset.id()).unwrap(), 2);
    let before = crate::store::fixture::snapshot(&case.state);
    assert_eq!(remove(&store, asset.id()).unwrap(), 2);
    assert_eq!(crate::store::fixture::snapshot(&case.state), before);
    assert!(matches!(
        remove(&store, Digest::of(b"unknown")),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn second_asset_budget_counts_registered_and_retired_roots_at_equality() {
    for retired in [false, true] {
        let (_case, store, first) = verified_fixture();
        execute::publish(&store, &first, &config(32 << 20)).unwrap();
        if retired {
            remove(&store, first.id()).unwrap();
        }
        let second = verified_probe(&store, "corpus-probe-2", 2);
        let dir = super::probe_directory(&store, &second.probe).unwrap();
        let need = retained_bytes(&store, &Catalog::load(&store).unwrap()).unwrap()
            + dir.usage(crate::SCAN_BOUND).unwrap().bytes
            + second.encoded_len() as u64
            + CorpusRetirement { asset: second.id() }.encoded_len() as u64
            + CorpusVersion {
                asset: second.id(),
                number: u64::MAX,
                retired: false,
            }
            .encoded_len() as u64
            + CorpusVersion {
                asset: second.id(),
                number: u64::MAX,
                retired: true,
            }
            .encoded_len() as u64;
        assert!(
            matches!(execute::publish(&store, &second, &config(need - 1)), Err(Error::Rejected(reason)) if reason == "corpus byte limit reached")
        );
        let corpus = store
            .open_dir(store.root(), &name("corpus"))
            .unwrap()
            .unwrap();
        let assets = store.open_dir(&corpus, &name("assets")).unwrap().unwrap();
        assert!(
            store
                .open_dir(&assets, &name(&second.id().to_string()))
                .unwrap()
                .is_none()
        );
        execute::publish(&store, &second, &config(need)).unwrap();
        remove(&store, second.id()).unwrap();
        if !retired {
            remove(&store, first.id()).unwrap();
        }
        assert!(retained_bytes(&store, &Catalog::load(&store).unwrap()).unwrap() <= need);
    }
}

#[test]
fn projection_verifies_a_registered_probe_once() {
    use crate::step::Step;
    use crate::store::fixture::scripted;
    let reads = |trace: Vec<Step>| trace.into_iter().filter(|step| *step == Step::Read).count();
    let (case, store, asset) = verified_fixture();
    execute::publish(&store, &asset, &config(32 << 20)).unwrap();
    let dir = super::probe_directory(&store, &asset.probe).unwrap();
    let (verified, verification) = scripted([], || {
        crate::campaign::probe::released(&store, &dir, &asset.probe.attempt)
            .and_then(|()| verify::stored_result(&store, &dir, &asset.probe))
    });
    assert_eq!(verified.unwrap().unwrap(), asset);
    let view = crate::store::View::open(&case.state).unwrap();
    let (catalog, loading) = scripted([], || Catalog::load(&view).map(|catalog| catalog.version));
    assert_eq!(catalog.unwrap().unwrap(), 1);
    let mut held = Vec::new();
    let (projected, projecting) = scripted([], || super::project(&view, &mut held));
    let projected = projected.unwrap().unwrap();
    assert!(held.is_empty(), "{held:?}");
    assert_eq!(projected["version"], 1);
    assert_eq!(projected["probes"][0]["state"], "verified");
    assert!(reads(projecting) - reads(loading) < reads(verification));
}

#[test]
fn diagnostic_deduplication_is_confined_to_the_shared_probes_root() {
    let mut rows = Vec::new();
    for path in ["probes", "unknown", "probes/corpus-probe-1"] {
        let before = rows.len();
        for _ in 0..2 {
            crate::campaign::projection::held(&mut rows, path, Error::Held("damaged".into()))
                .unwrap();
        }
        assert_eq!(rows.len() - before, if path == "probes" { 1 } else { 2 });
    }
}

#[test]
fn full_report_projects_corpus_probes_and_deduplicates_shared_root_damage() {
    let (case, store, asset) = verified_fixture();
    execute::publish(&store, &asset, &config(32 << 20)).unwrap();
    let view = crate::store::View::open(&case.state).unwrap();
    let report = crate::campaign::report::project(&view).unwrap();
    assert!(report["held"].as_array().unwrap().is_empty(), "{report}");
    assert_eq!(
        report["corpus"]["assets"][0]["asset"],
        asset.id().to_string()
    );
    assert_eq!(report["corpus"]["probes"][0]["state"], "verified");
    drop(view);
    drop(store);
    drop(case);
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store
        .create_once(store.root(), &name("probes"), b"damaged")
        .unwrap();
    let view = crate::store::View::open(&case.state).unwrap();
    let report = crate::campaign::report::project(&view).unwrap();
    assert_eq!(
        report["held"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["path"] == "probes")
            .count(),
        1
    );
}

#[test]
fn target_admission_reconciles_pending_versions_after_retired_refusal() {
    let (case, store, first) = verified_fixture();
    execute::publish(&store, &first, &config(32 << 20)).unwrap();
    let second = verified_probe(&store, "corpus-probe-2", 2);
    execute::publish(&store, &second, &config(32 << 20)).unwrap();
    assert_eq!(remove(&store, second.id()).unwrap(), 3);
    std::fs::remove_file(case.state.join("corpus/versions/3")).unwrap();
    let before = crate::store::fixture::snapshot(&case.state);
    assert!(matches!(
        super::target_input(&store, second.id()),
        Err(Error::Rejected(_))
    ));
    assert_eq!(crate::store::fixture::snapshot(&case.state), before);
    let (asset, _, _, version) = super::target_input(&store, first.id()).unwrap();
    assert_eq!(asset, first);
    assert_eq!(version, 3);
    assert!(case.state.join("corpus/versions/3").exists());
}
