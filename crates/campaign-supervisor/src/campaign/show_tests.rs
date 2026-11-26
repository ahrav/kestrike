use super::{Error, name, show};
use crate::campaign::state_fixture::Sharded;
use crate::step::Step;
use crate::store::Store;
use crate::store::fixture::{Case, observed, replace, snapshot};

#[test]
fn show_refuses_missing_incompatible_and_oversized_state_markers_without_effects() {
    for marker in [
        None,
        Some(b"campaign-supervisor state 2\n".to_vec()),
        Some(vec![b'x'; 4096]),
        Some(include_bytes!("../../testdata/reservation.json").to_vec()),
    ] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        drop(store);
        let path = case.state.join(".state");
        match marker {
            Some(bytes) => std::fs::write(path, bytes).unwrap(),
            None => std::fs::remove_file(path).unwrap(),
        }
        let before = snapshot(&case.state);
        assert!(show(&case.state).is_err());
        assert_eq!(snapshot(&case.state), before);
    }
}

#[test]
fn show_reports_invalid_names_orphans_and_missing_or_misbound_manifests() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("jobs")).unwrap();
    let jobs = store.shard_jobs("a".repeat(64)).unwrap().unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../testdata/admission.json")).unwrap();
    let admission: crate::record::Admission =
        serde_json::from_value(value["record"].clone()).unwrap();
    store
        .create_once(&jobs, &name("aainvalid.json"), b"corrupt")
        .unwrap();
    store
        .create_once(
            &jobs,
            &name(&format!("{}.manifest", "a".repeat(64))),
            b"manifest",
        )
        .unwrap();
    let misbound = store.shard_jobs("b".repeat(64)).unwrap().unwrap();
    store
        .create_record(
            &misbound,
            &name(&format!("{}.json", "b".repeat(64))),
            &admission,
        )
        .unwrap();
    store
        .create_once(
            &misbound,
            &name(&format!("{}.manifest", "b".repeat(64))),
            b"manifest",
        )
        .unwrap();
    store
        .create_record(
            &store.shard_jobs(admission.job().id()).unwrap().unwrap(),
            &name(&format!("{}.json", admission.job().id())),
            &admission,
        )
        .unwrap();
    let before = snapshot(&case.state);
    let shown = show(&case.state).unwrap();
    let rows = shown["jobs"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "{shown}");
    let invalid = rows.iter().find(|row| row["id"] == "aainvalid").unwrap();
    assert_eq!(invalid["held_code"], "identity");
    let held: std::collections::BTreeMap<_, _> = rows
        .iter()
        .map(|row| (row["id"].as_str().unwrap(), row["held"].as_str().unwrap()))
        .collect();
    let id = admission.job().id().to_string();
    let expected: std::collections::BTreeMap<_, _> = [
        ("a".repeat(64), "job dependency without job record"),
        ("b".repeat(64), "job binding differs"),
        (id, "job manifest missing"),
        ("aainvalid".to_owned(), "invalid job identity filename"),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        held,
        expected
            .iter()
            .map(|(id, reason)| (id.as_str(), *reason))
            .collect()
    );
    for row in rows {
        assert!(row.get("verified").is_none());
    }
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn held_job_and_configuration_codes_leave_the_store_byte_identical() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("jobs")).unwrap();
    let jobs = store.shard_jobs("a".repeat(64)).unwrap().unwrap();
    store
        .create_once(
            &jobs,
            &name(&format!("{}.json", "a".repeat(64))),
            b"corrupt",
        )
        .unwrap();
    store
        .create_once(store.root(), &name("config.json"), b"corrupt")
        .unwrap();
    let before = snapshot(&case.state);
    let shown = show(&case.state).unwrap();
    assert_eq!(shown["config"]["held_code"], "malformed");
    assert_eq!(shown["jobs"][0]["held_code"], "malformed");
    assert!(shown["config"].get("verified").is_none());
    assert!(shown["jobs"][0].get("verified").is_none());
    assert_eq!(snapshot(&case.state), before);
}

#[test]
fn replacement_during_the_job_scan_returns_held() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    store.mkdir(store.root(), &name("jobs")).unwrap();
    let jobs = store.shard_jobs("a".repeat(64)).unwrap().unwrap();
    store
        .create_once(
            &jobs,
            &name(&format!("{}.json", "a".repeat(64))),
            b"corrupt",
        )
        .unwrap();
    let before = snapshot(&case.state);
    let state = case.state.clone();
    let old = case.root.join("old-state");
    let replaced = old.clone();
    let mut reached = false;
    let result = observed(
        move |at| {
            if at == Step::List && !reached {
                reached = true;
                replace(&state, &replaced);
            }
        },
        || show(&case.state),
    );
    assert!(matches!(result, Err(Error::Held(_))));
    assert!(old.is_dir());
    assert_eq!(snapshot(&old), before);
    assert!(snapshot(&case.state).is_empty());
}

#[test]
fn show_keeps_verified_jobs_and_storage_beside_foreign_root_entries() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let job = crate::campaign::state_fixture::job(&store, 0);
    let id = job.job().id().to_string();
    let attempts = crate::layout::make_shard(&store, crate::layout::ATTEMPTS, &id).unwrap();
    store.mkdir(&attempts, &name(&id)).unwrap();
    for root in ["jobs", "attempts"] {
        for entry in ["0", "zz"] {
            std::fs::create_dir_all(case.state.join(root).join(entry)).unwrap();
        }
    }
    let shown = show(&case.state).unwrap();
    assert!(
        shown["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == job.job().id().to_string() && row.get("verified").is_some())
    );
    for path in ["jobs/0", "jobs/zz"] {
        assert!(
            shown["jobs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == path && row["held"] == "root entry is not a shard")
        );
    }
    assert_eq!(shown["storage"]["roots"]["jobs"]["entries"], 2);
    assert_eq!(shown["storage"]["roots"]["attempts"]["entries"], 1);
}
