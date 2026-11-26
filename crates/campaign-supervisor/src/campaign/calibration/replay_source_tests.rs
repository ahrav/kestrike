use super::*;
#[test]
fn missing_replay_sources_hold_the_root_while_host_faults_stay_global() {
    let case = crate::store::fixture::Case::new();
    let missing = canonical_source(&case.state.join("missing")).unwrap_err();
    assert!(matches!(missing, Error::Held(_)));
    assert!(!crate::campaign::triage::global(&missing));
    for errno in [libc::EIO, libc::EMFILE] {
        let (result, _) =
            crate::store::fixture::scripted([(0, crate::step::Outcome::Errno(errno))], || {
                canonical_source(&case.state)
            });
        let error = result.unwrap().unwrap_err();
        assert!(crate::campaign::triage::global(&error), "{error}");
    }
}

#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn missing_attempts_keeps_a_damaged_plan_local() {
    let _processes = crate::store::fixture::processes();
    use std::time::Duration;
    let host = crate::custody::run_tests::Hosted::new(25100);
    let store = Store::open(&host.case.state).unwrap();
    let mut custody = host.custody(Duration::from_secs(1));
    let unrelated = crate::campaign::state_fixture::job(&store, 0);
    let jobs = crate::layout::jobs(&store, &unrelated.job().id().to_string())
        .unwrap()
        .unwrap();
    store
        .replace(
            &jobs,
            &name(&format!("{}.json", unrelated.job().id())),
            b"damaged unrelated admission",
        )
        .unwrap();
    store.mkdir(store.root(), &name("calibrations")).unwrap();
    let roots = store
        .open_dir(store.root(), &name("calibrations"))
        .unwrap()
        .unwrap();
    let id = Digest::of(b"damaged-plan").to_string();
    store.mkdir(&roots, &name(&id)).unwrap();
    let root = store.open_dir(&roots, &name(&id)).unwrap().unwrap();
    store.create_once(&root, &name("plan"), b"damaged").unwrap();
    assert!(
        store
            .open_dir(store.root(), &name("attempts"))
            .unwrap()
            .is_none()
    );
    let held = reconcile(&store, &mut custody).unwrap();
    assert_eq!(held.keys().collect::<Vec<_>>(), [&id]);
}
