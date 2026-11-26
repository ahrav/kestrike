use super::*;
use crate::record::Digest;

fn text(s: &str) -> Text {
    Text::new(s).unwrap()
}
fn target(form: ForkForm) -> Target {
    Target {
        asset: Digest::of(b"asset"),
        boundary: 13,
        build: Digest::of(b"build"),
        bundle: Digest::of(b"bundle"),
        bytes: 48,
        decisions: 1,
        form,
        manifest: Digest::of(b"manifest"),
        milestone: text("pending-put"),
        prefix: Digest::of(b"prefix"),
        root: 1,
        semantic: 5,
    }
}
fn header() -> String {
    format!(
        "milestone: pending-put boundary=13 semantic=5 decisions=1 prefix={}\nwitness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false\nparent: reproduced\n",
        Digest::of(b"prefix")
    )
}
fn branch() -> String {
    format!(
        "{}child: suffix=0 sibling=0 class=success digest={} terminal=complete pass fired=03 required=03\nchild: suffix=0 sibling=1 class=success digest={} terminal=complete pass fired=03 required=03\nbranch: 2 children, 2 credited, 0 problems\n",
        header(),
        Digest::of(b"child"),
        Digest::of(b"child")
    )
}
#[test]
fn branch_credit_requires_frozen_prefix_actual_witness_exact_pairs_and_agreement() {
    let mut target = target(ForkForm::Branch {
        siblings: 2,
        suffixes: 1,
    });
    let output = branch();
    let judged = judge(&target, &output).unwrap();
    assert_eq!(judged.class, Class::Pass);
    assert_eq!((judged.printed, judged.credited), (2, 2));
    for (from, to) in [
        ("semantic=5", "semantic=6"),
        ("boundary=13", "boundary=14"),
        ("decisions=1", "decisions=2"),
        ("attempt:1", "attempt:0"),
        ("grant:3", "grant:0"),
        ("held:2", "held:0"),
        ("outcome:0", "outcome:1"),
        ("pending-put", "other"),
    ] {
        assert_eq!(
            judge(&target, &output.replace(from, to)).unwrap().class,
            Class::Incomplete,
            "{from}"
        );
    }
    assert_eq!(
        judge(
            &target,
            &output.replace("parent: reproduced", "parent: changed")
        )
        .unwrap()
        .class,
        Class::EngineFailure
    );
    assert_eq!(
        judge(&target, &output.replace("suffix=0", "suffix=1"))
            .unwrap()
            .class,
        Class::Incomplete
    );
    target.prefix = Digest::of(b"wrong");
    assert_eq!(judge(&target, &output).unwrap().class, Class::Incomplete);
    target.prefix = Digest::of(b"prefix");
    let digest = Digest::of(b"child").to_string();
    let disagree = output.replacen(&digest, &Digest::of(b"different").to_string(), 1);
    assert_eq!(
        judge(&target, &disagree).unwrap().class,
        Class::EngineFailure
    );
    assert!(judge(&target, &output.replace("sibling=1", "sibling=0")).is_err());
    target.form = ForkForm::Branch {
        siblings: 1,
        suffixes: 1,
    };
    assert_eq!(judge(&target, &output).unwrap().class, Class::Incomplete);
}
#[test]
fn child_failures_have_independent_classes_and_product_failures_win() {
    let target = target(ForkForm::Branch {
        siblings: 2,
        suffixes: 1,
    });
    for (terminal, class) in [
        ("violation", Class::Violation),
        ("unsuccessful", Class::Unsuccessful),
        ("inconclusive", Class::Inconclusive),
    ] {
        let judged = judge(
            &target,
            &branch().replace("complete pass", &format!("complete {terminal}")),
        )
        .unwrap();
        assert_eq!(judged.class, class);
        assert_eq!(judged.children.len(), 2);
        assert_eq!(judged.children[0].label.as_str(), "c0-0");
        assert_eq!(judged.children[1].label.as_str(), "c0-1");
    }
    let output = format!(
        "{}child: suffix=0 sibling=0 class=failed\nchild: suffix=0 sibling=1 class=watchdog\nbranch: 2 children, 0 credited, 0 problems\n",
        header()
    );
    let judged = judge(&target, &output).unwrap();
    assert_eq!(judged.class, Class::Watchdog);
    assert_eq!(judged.children[0].kind, FindingKind::Incomplete);
    assert_eq!(judged.children[1].kind, FindingKind::Watchdog);
    assert_eq!(
        judge(&target, "parent: diverged before the milestone\n")
            .unwrap()
            .class,
        Class::EngineFailure
    );
}
#[test]
fn child_and_leaf_defect_terminals_are_engine_failures() {
    let target = target(ForkForm::Branch {
        siblings: 2,
        suffixes: 1,
    });
    let defect = "infrastructure defect";
    for output in [
        branch().replace("complete pass fired=03 required=03", defect),
        branch().replacen("complete pass fired=03 required=03", defect, 1),
    ] {
        let judged = judge(&target, &output).unwrap();
        assert_eq!(judged.class, Class::EngineFailure, "{output}");
        assert!(!judged.children.is_empty());
        assert!(judged.children.iter().all(|child| {
            child.class == Class::EngineFailure && child.kind == FindingKind::Engine
        }));
    }
    let target = super::tests::target(ForkForm::Explore {
        advances: 16,
        children: 2,
        depth: 2,
        faults: 12,
    });
    let output = explore()
        .replace(
            "counts=true verdict=complete pass fired=03 required=03",
            &format!("counts=false verdict={defect}"),
        )
        .replace("failing=0", "failing=1");
    let judged = judge(&target, &output).unwrap();
    assert_eq!(judged.class, Class::EngineFailure);
    assert_eq!(judged.leaves, Some((1, 0)));
    assert_eq!(judged.children.len(), 1);
    assert_eq!(judged.children[0].label.as_str(), "l0");
    assert_eq!(judged.children[0].kind, FindingKind::Engine);
}
#[test]
fn child_checks_distinguish_missing_evidence_from_engine_disagreement() {
    let target = target(ForkForm::Branch {
        siblings: 2,
        suffixes: 1,
    });
    for (check, class) in [
        ("its bundle cannot be read", Class::Incomplete),
        ("its digest disagrees", Class::EngineFailure),
    ] {
        let output = branch().replace(
            "branch: 2 children, 2 credited, 0 problems",
            &format!(
                "problem: suffix 0 sibling 1: {check}\nbranch: 2 children, 2 credited, 1 problems"
            ),
        );
        let judged = judge(&target, &output).unwrap();
        assert_eq!(judged.class, class);
        assert_eq!(judged.children.len(), 1);
    }
}
fn explore() -> String {
    format!(
        "label: composed-bounded\n{}limits: depth=2 children=2 faults=12 advances=16\nnode: path=0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nnode: path=0.0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0.0 digest={} unexplored=0 counts=true verdict=complete pass fired=03 required=03\nfrontier: nodes=2 credited=2 explored=1 failing=0 unexplored=0\nexplore: composed-bounded, 0 problems\n",
        header(),
        Digest::of(b"leaf")
    )
}
#[test]
fn exploration_credit_reconciles_frozen_limits_nodes_leaves_and_census() {
    let target = target(ForkForm::Explore {
        advances: 16,
        children: 2,
        depth: 2,
        faults: 12,
    });
    let output = explore();
    assert_eq!(
        judge(
            &target,
            &output.replace("parent: reproduced", "parent: changed")
        )
        .unwrap()
        .class,
        Class::EngineFailure
    );
    assert_eq!(judge(&target, &output).unwrap().class, Class::Pass);
    assert_eq!(
        judge(&target, &output.replace("faults=12", "faults=13"))
            .unwrap()
            .class,
        Class::Incomplete
    );
    for (from, to) in [
        ("leaf: path=0.0", "leaf: path=1"),
        ("nodes=2", "nodes=3"),
        ("holds=true", "holds=false"),
    ] {
        assert!(judge(&target, &output.replace(from, to)).is_err());
    }
    let output = output
        .replace(
            "counts=true verdict=complete pass",
            "counts=false verdict=complete violation",
        )
        .replace("failing=0", "failing=1");
    let judged = judge(&target, &output).unwrap();
    assert_eq!(judged.class, Class::Violation);
    assert_eq!(judged.leaves, Some((1, 0)));
    assert_eq!((judged.printed, judged.credited), (2, 2));
    assert_eq!(judged.children[0].label.as_str(), "l0");
}
#[test]
fn fork_bounds_are_checked_before_tree_size_and_scaled_limits_preserve_file_bounds() {
    assert!(
        ForkForm::Explore {
            advances: 1,
            children: u64::MAX,
            depth: 128,
            faults: 1
        }
        .children()
        .is_none()
    );
    assert!(
        ForkForm::Explore {
            advances: 1,
            children: 1,
            depth: 129,
            faults: 1
        }
        .children()
        .is_none()
    );
    assert_eq!(
        ForkForm::Explore {
            advances: 1,
            children: 2,
            depth: 7,
            faults: 1
        }
        .children(),
        Some(254)
    );
    let limits = crate::custody::Limits {
        cpu_quota_us: 1000,
        memory_bytes: 1000,
        pids: 10,
        file_bytes: 1000,
        cpu_seconds: 10,
        output_bytes: 2000,
        output_inodes: 20,
    };
    let scaled = crate::attempt::scaled(limits, 3).unwrap();
    assert_eq!(
        (
            scaled.cpu_quota_us,
            scaled.memory_bytes,
            scaled.pids,
            scaled.cpu_seconds,
            scaled.output_bytes,
            scaled.output_inodes,
            scaled.file_bytes
        ),
        (3000, 3000, 12, 30, 6000, 60, 1000)
    );
    assert!(crate::attempt::scaled(limits, u64::MAX).is_err());
    assert!(crate::attempt::scaled(limits, 0).is_err());
    let mut excess = limits;
    excess.output_inodes = crate::store::EVIDENCE_BOUND as u64 - 2;
    assert!(matches!(
        crate::attempt::scaled(excess, 2),
        Err(crate::custody::Error::Rejected("invalid custody limits"))
    ));
}

#[test]
fn bound_targeted_classifier_rejects_copied_runs_and_prioritizes_product_evidence() {
    use crate::attempt::{binding, classify, name};
    use crate::record::{Artifact, Attempt, Binding, Finished, Kernel, Pins, Purpose, Worker};
    use crate::store::{Store, fixture::Case};
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let listing =
        crate::protocol::Listing::parse(include_str!("../../testdata/admission-listing.txt"))
            .unwrap();
    let pins = Pins {
        build: text(&Digest::of(b"build").to_string()),
        executable: text(&Digest::of(b"exe").to_string()),
        platform: text("linux"),
        toolchain: text("rustc"),
    };
    let ordinary = crate::campaign::admit(
        &store,
        &listing,
        pins,
        text("/archive"),
        &crate::campaign::Request {
            profile: text("upload"),
            campaign: text("c1"),
            run: 0,
            attempts: 3,
            counts: Default::default(),
        },
        Purpose::Campaign,
    )
    .unwrap()
    .record;
    let bundle = vec![0u8; 48];
    let manifest = format!("build = {}\n", Digest::of(b"build"));
    let mut target = target(ForkForm::Branch {
        siblings: 2,
        suffixes: 1,
    });
    target.manifest = Digest::of(manifest.as_bytes());
    target.bundle = Digest::of(&bundle);
    let mut experiment = ordinary.job().experiment().clone();
    experiment.format = 2;
    experiment.target = Some(target.clone());
    let job = crate::record::Job::targeted(experiment).unwrap();
    let admission = crate::record::Admission::targeted(text("/archive"), job.clone(), 1).unwrap();
    let jobs =
        crate::layout::make_shard(&store, crate::layout::JOBS, &job.id().to_string()).unwrap();
    store
        .create_record(&jobs, &name(&format!("{}.json", job.id())), &admission)
        .unwrap();
    let attempt = Attempt {
        attempt: text(&format!("{}-0001", job.id())),
        file_bytes: 4096,
        job: job.id().digest(),
        manifest: target.manifest,
        number: 1,
    };
    store.mkdir(store.root(), &name("artifacts")).unwrap();
    let artifacts = store
        .open_dir(store.root(), &name("artifacts"))
        .unwrap()
        .unwrap();
    store
        .mkdir(&artifacts, &name(attempt.attempt.as_str()))
        .unwrap();
    let dir = store
        .open_dir(&artifacts, &name(attempt.attempt.as_str()))
        .unwrap()
        .unwrap();
    for (entry, bytes) in [
        ("input", bundle.as_slice()),
        ("manifest", manifest.as_bytes()),
        ("branch.stdout", branch().as_bytes()),
        ("branch.stderr", b"".as_slice()),
    ] {
        store.create_once(&dir, &name(entry), bytes).unwrap();
    }
    let worker = Worker {
        ended: text("exited"),
        exit: Some(0),
        signal: None,
        stderr: Digest::of(b""),
        stdout: Digest::of(branch().as_bytes()),
    };
    let artifact = Artifact {
        archive: Some(target.build),
        archive_path: None,
        bundle: Some(target.bundle),
        class: text("counts"),
        command: text("branch"),
        comparison: None,
        manifest: Some(target.manifest),
        output: None,
        reason: text("branch"),
        run_id: attempt.attempt.clone(),
        session: None,
        session_original: None,
        summary: None,
        workers: [(text("branch"), worker)].into(),
    };
    let mut finished = Finished {
        attempt: attempt.attempt.clone(),
        binding: Binding::Matching,
        bound: None,
        class: Class::Pass,
        exit: Some(0),
        interruption: None,
        kernel: Kernel::default(),
        residual_members: false,
        signal: None,
        watchdog: false,
    };
    let observed = |artifact: &Artifact, finished: &Finished| {
        store
            .replace_record(&dir, &name("artifact"), artifact)
            .unwrap();
        let evidence = binding::read_command(&store, store.root(), &attempt, "branch").unwrap();
        classify::classify(finished, &evidence)
    };
    assert_eq!(observed(&artifact, &finished), Class::Pass);
    let mut missing_fork = artifact.clone();
    missing_fork.workers.clear();
    store.delete(&dir, &name("branch.stdout")).unwrap();
    assert_eq!(observed(&missing_fork, &finished), Class::MalformedEvidence);
    store
        .replace(&dir, &name("branch.stdout"), branch().as_bytes())
        .unwrap();
    assert_eq!(observed(&artifact, &finished), Class::Pass);
    let mut changed_input = bundle.clone();
    changed_input[0] = 1;
    store.replace(&dir, &name("input"), &changed_input).unwrap();
    let mut changed_artifact = artifact.clone();
    changed_artifact.bundle = Some(Digest::of(&changed_input));
    assert_eq!(
        observed(&changed_artifact, &finished),
        Class::MisboundEvidence
    );
    store.replace(&dir, &name("input"), &bundle).unwrap();
    assert_eq!(observed(&artifact, &finished), Class::Pass);
    for (label, exit, expected) in [
        ("rejected", 2, Class::Rejected),
        ("interrupted", 5, Class::Interrupted),
        ("watchdog", 6, Class::Watchdog),
        ("build-failure", 3, Class::Infrastructure),
    ] {
        let mut changed = artifact.clone();
        changed.class = text(label);
        let mut stopped = finished.clone();
        stopped.exit = Some(exit);
        assert_eq!(observed(&changed, &stopped), expected);
    }
    let signaled = format!(
        "{}child: suffix=0 sibling=0 class=signaled\nchild: suffix=0 sibling=1 class=success digest={} terminal=complete pass fired=03 required=03\nbranch: 2 children, 1 credited, 0 problems\n",
        header(),
        Digest::of(b"child")
    );
    store
        .replace(&dir, &name("branch.stdout"), signaled.as_bytes())
        .unwrap();
    let mut signaled_artifact = artifact.clone();
    signaled_artifact.class = text("complete");
    signaled_artifact
        .workers
        .get_mut(&text("branch"))
        .unwrap()
        .stdout = Digest::of(signaled.as_bytes());
    let mut stopped = finished.clone();
    stopped.exit = Some(1);
    for stop in [
        "none",
        "residual",
        "watchdog",
        "oom",
        "launcher-watchdog",
        "launcher-interrupted",
    ] {
        stopped.watchdog = stop == "watchdog";
        stopped.residual_members = stop == "residual";
        stopped.exit = Some(match stop {
            "launcher-watchdog" => 6,
            "launcher-interrupted" => 5,
            _ => 1,
        });
        signaled_artifact.class = text(match stop {
            "launcher-watchdog" => "watchdog",
            "launcher-interrupted" => "interrupted",
            _ => "complete",
        });
        stopped.kernel = Default::default();
        if stop == "oom" {
            stopped.kernel.memory.insert(text("oom_kill"), 1);
        }
        store
            .replace_record(&dir, &name("artifact"), &signaled_artifact)
            .unwrap();
        let evidence = binding::read_command(&store, store.root(), &attempt, "branch").unwrap();
        let bound = evidence.into_bound().unwrap();
        assert_eq!(
            bound.targeted().unwrap().children[0].kind,
            FindingKind::Abort,
            "{stop}"
        );
        let expected = if stop == "oom" {
            Class::Oom
        } else {
            Class::EngineFailure
        };
        assert_eq!(observed(&signaled_artifact, &stopped), expected, "{stop}");
    }
    let two_signaled = format!(
        "{}child: suffix=0 sibling=0 class=signaled\nchild: suffix=0 sibling=1 class=signaled\nbranch: 2 children, 0 credited, 0 problems\n",
        header()
    );
    store
        .replace(&dir, &name("branch.stdout"), two_signaled.as_bytes())
        .unwrap();
    let mut two_signaled_artifact = signaled_artifact.clone();
    two_signaled_artifact.class = text("complete");
    two_signaled_artifact
        .workers
        .get_mut(&text("branch"))
        .unwrap()
        .stdout = Digest::of(two_signaled.as_bytes());
    let mut one_kill = finished.clone();
    one_kill.exit = Some(1);
    one_kill.kernel.memory.insert(text("oom_kill"), 1);
    store
        .replace_record(&dir, &name("artifact"), &two_signaled_artifact)
        .unwrap();
    let evidence = binding::read_command(&store, store.root(), &attempt, "branch").unwrap();
    let bound = evidence.into_bound().unwrap();
    assert!(
        bound
            .targeted()
            .unwrap()
            .children
            .iter()
            .all(|child| child.kind == FindingKind::Abort && child.class == Class::EngineFailure)
    );
    assert_eq!(observed(&two_signaled_artifact, &one_kill), Class::Oom);
    store
        .replace(&dir, &name("branch.stdout"), signaled.as_bytes())
        .unwrap();
    let changed_parent = signaled.replace("parent: reproduced", "parent: changed");
    store
        .replace(&dir, &name("branch.stdout"), changed_parent.as_bytes())
        .unwrap();
    signaled_artifact.class = text("complete");
    signaled_artifact
        .workers
        .get_mut(&text("branch"))
        .unwrap()
        .stdout = Digest::of(changed_parent.as_bytes());
    stopped = finished.clone();
    stopped.exit = Some(1);
    stopped.watchdog = true;
    assert_eq!(observed(&signaled_artifact, &stopped), Class::EngineFailure);
    let mut limited_engine = stopped.clone();
    limited_engine.watchdog = false;
    limited_engine.kernel.memory.insert(text("oom_kill"), 1);
    limited_engine.class = Class::Oom;
    assert_eq!(observed(&signaled_artifact, &limited_engine), Class::Oom);
    let engine_evidence = binding::read_command(&store, store.root(), &attempt, "branch").unwrap();
    let engine_bound = engine_evidence.into_bound().unwrap();
    assert_eq!(
        classify::finding_kind(&limited_engine, Some(&engine_bound)),
        Some(FindingKind::Engine)
    );
    let violating = branch().replace("complete pass", "complete violation");
    store
        .replace(&dir, &name("branch.stdout"), violating.as_bytes())
        .unwrap();
    let mut violation_artifact = artifact.clone();
    violation_artifact.class = text("complete");
    violation_artifact
        .workers
        .get_mut(&text("branch"))
        .unwrap()
        .stdout = Digest::of(violating.as_bytes());
    let mut limited = finished.clone();
    limited.exit = Some(1);
    limited.kernel.memory.insert(text("oom_kill"), 1);
    limited.class = Class::Oom;
    assert_eq!(observed(&violation_artifact, &limited), Class::Oom);
    let bound = binding::read_command(&store, store.root(), &attempt, "branch")
        .unwrap()
        .into_bound()
        .unwrap();
    assert_eq!(
        classify::finding_kind(&limited, Some(&bound)),
        Some(FindingKind::Violation)
    );
    let mut completed_finish = finished.clone();
    completed_finish.class = Class::Violation;
    completed_finish.exit = Some(1);
    completed_finish.bound = Some(bound.binding().clone());
    store
        .create_record(
            store.root(),
            &name("intent"),
            &crate::record::Intent {
                attempt: attempt.attempt.clone(),
                boot: text("boot"),
                cgroup: text(case.state.join("absent-cgroup").to_str().unwrap()),
            },
        )
        .unwrap();
    store
        .create_record(store.root(), &name("attempt"), &attempt)
        .unwrap();
    store
        .create_record(store.root(), &name("bound"), bound.binding())
        .unwrap();
    store
        .create_record(store.root(), &name("finished"), &completed_finish)
        .unwrap();
    store
        .create_once(
            &jobs,
            &name(&format!("{}.manifest", job.id())),
            manifest.as_bytes(),
        )
        .unwrap();
    store
        .create_once(&jobs, &name(&format!("{}.bundle", job.id())), &bundle)
        .unwrap();
    store.mkdir(&dir, &name("branch")).unwrap();
    let children = store.open_dir(&dir, &name("branch")).unwrap().unwrap();
    store
        .create_once(&children, &name("suffix-0-0.bundle"), b"child bytes")
        .unwrap();
    let cfg: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/configuration.json")).unwrap();
    let config: crate::record::Configuration =
        serde_json::from_value(cfg["record"].clone()).unwrap();
    store
        .create_record(store.root(), &name("config.json"), &config)
        .unwrap();
    let completed =
        crate::attempt::read_completed(&store, store.root(), &attempt, "branch").unwrap();
    let record = store
        .read_record::<Attempt>(store.root(), &name("attempt"))
        .unwrap()
        .unwrap();
    crate::step::install(Some(crate::step::Script {
        free_space: Some((0, 0)),
        ..Default::default()
    }));
    let before = crate::store::fixture::snapshot(store.path());
    assert!(matches!(
        crate::attempt::capture(&store, &admission, &completed, store.root(), &record, None),
        Err(crate::custody::Error::Held(
            "target finding retention exceeds reserved capacity"
        ))
    ));
    crate::step::install(None);
    assert_eq!(crate::store::fixture::snapshot(store.path()), before);
    assert!(
        store
            .open_dir(store.root(), &name("findings"))
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .read_record::<crate::record::Captured>(store.root(), &name("captured"))
            .unwrap()
            .is_none()
    );
    std::fs::create_dir(case.state.join("findings")).unwrap();
    for index in 0..32 {
        std::fs::create_dir(case.state.join(format!("findings/retained-{index}"))).unwrap();
    }
    let before = crate::store::fixture::snapshot(store.path());
    crate::step::install(Some(crate::step::Script {
        scan_bound: Some(32),
        ..Default::default()
    }));
    let error =
        crate::attempt::capture(&store, &admission, &completed, store.root(), &record, None)
            .unwrap_err();
    crate::step::install(None);
    assert_eq!(
        error.to_string(),
        "findings holds 35 entries at bound 32; collect or shard"
    );
    assert_eq!(crate::store::fixture::snapshot(store.path()), before);
    for index in 0..32 {
        std::fs::remove_dir(case.state.join(format!("findings/retained-{index}"))).unwrap();
    }
    let mut changed = config.config().clone();
    changed.insert(text("attempt_output"), config.file_bytes() / 2);
    store
        .replace_record(
            store.root(),
            &name("config.json"),
            &crate::record::Configuration::new(changed).unwrap(),
        )
        .unwrap();
    let deep = (0..65).fold(case.state.join("deep"), |path, _| path.join("d"));
    std::fs::create_dir_all(&deep).unwrap();
    assert!(matches!(
        store.usage(crate::SCAN_BOUND),
        Err(crate::store::Error::DepthBound)
    ));
    crate::attempt::capture(&store, &admission, &completed, store.root(), &record, None).unwrap();
    assert!(
        store
            .read_record::<crate::record::Captured>(store.root(), &name("captured"))
            .unwrap()
            .is_some()
    );
    let retained = crate::store::fixture::snapshot(store.path());
    crate::attempt::capture(&store, &admission, &completed, store.root(), &record, None).unwrap();
    assert_eq!(crate::store::fixture::snapshot(store.path()), retained);
    std::fs::remove_dir_all(case.state.join("deep")).unwrap();
    store
        .replace(&dir, &name("branch.stdout"), branch().as_bytes())
        .unwrap();
    assert_eq!(observed(&artifact, &finished), Class::Pass);
    finished.exit = None;
    assert_eq!(observed(&artifact, &finished), Class::Interrupted);
    finished.exit = Some(0);
    finished.residual_members = true;
    assert_eq!(observed(&artifact, &finished), Class::Disagreement);
    finished.residual_members = false;
    let parent_kind = |done: &Finished| {
        let evidence = binding::read_command(&store, store.root(), &attempt, "branch")
            .unwrap()
            .into_bound()
            .unwrap();
        classify::finding_kind(done, Some(&evidence))
    };
    let mut crashed = artifact.clone();
    crashed.workers.get_mut(&text("branch")).unwrap().exit = Some(77);
    let mut parent = finished.clone();
    parent.class = Class::EngineFailure;
    assert_eq!(observed(&crashed, &parent), Class::EngineFailure);
    assert_eq!(parent_kind(&parent), Some(FindingKind::Abort));
    observed(&artifact, &finished);
    let job_name = name(&format!("{}.json", job.id()));
    store
        .replace(&jobs, &job_name, b"corrupt admitted target")
        .unwrap();
    assert_eq!(observed(&artifact, &finished), Class::MalformedEvidence);
    store.replace_record(&jobs, &job_name, &admission).unwrap();
    assert_eq!(observed(&artifact, &finished), Class::Pass);
    let mut copied = artifact.clone();
    copied.run_id = text("another-parent-attempt");
    assert_eq!(observed(&copied, &finished), Class::MisboundEvidence);
    let mut disagreement = artifact.clone();
    disagreement.class = text("complete");
    assert_eq!(observed(&disagreement, &finished), Class::Disagreement);
    let mut abnormal = artifact.clone();
    abnormal.class = text("incomplete");
    abnormal.workers.get_mut(&text("branch")).unwrap().exit = Some(101);
    finished.exit = Some(4);
    assert_eq!(observed(&abnormal, &finished), Class::Incomplete);
    let mut zero = abnormal.clone();
    zero.class = text("counts");
    finished.exit = Some(0);
    assert_eq!(observed(&zero, &finished), Class::Disagreement);
    let mut complete = artifact.clone();
    complete.class = text("complete");
    finished.exit = Some(1);
    assert_eq!(observed(&complete, &finished), Class::Incomplete);
    finished.exit = Some(4);
    let panic = b"thread 'main' panicked at engine.rs:1:1\n";
    store.replace(&dir, &name("branch.stderr"), panic).unwrap();
    abnormal.workers.get_mut(&text("branch")).unwrap().stderr = Digest::of(panic);
    assert_eq!(observed(&abnormal, &finished), Class::EngineFailure);
    store.replace(&dir, &name("branch.stderr"), b"").unwrap();
    let violation = branch().replace("complete pass", "complete violation");
    store
        .replace(&dir, &name("branch.stdout"), violation.as_bytes())
        .unwrap();
    let mut refused = artifact.clone();
    refused.class = text("rejected");
    refused.workers.get_mut(&text("branch")).unwrap().stdout = Digest::of(violation.as_bytes());
    refused.workers.get_mut(&text("branch")).unwrap().exit = Some(2);
    finished.exit = Some(2);
    assert_eq!(observed(&refused, &finished), Class::Violation);
    let unwitnessed = branch().replace("grant:3", "grant:0");
    store
        .replace(&dir, &name("branch.stdout"), unwitnessed.as_bytes())
        .unwrap();
    let mut false_pass = artifact.clone();
    false_pass.workers.get_mut(&text("branch")).unwrap().stdout =
        Digest::of(unwitnessed.as_bytes());
    finished.exit = Some(0);
    assert_eq!(observed(&false_pass, &finished), Class::Incomplete);
    store
        .replace(&dir, &name("branch.stdout"), b"unparsed output\n")
        .unwrap();
    let mut malformed = artifact.clone();
    malformed.workers.get_mut(&text("branch")).unwrap().stdout = Digest::of(b"unparsed output\n");
    assert_eq!(observed(&malformed, &finished), Class::MalformedEvidence);
    let panic = b"thread 'main' panicked at engine.rs:1:1\n";
    store.replace(&dir, &name("branch.stderr"), panic).unwrap();
    let mut panic_artifact = malformed.clone();
    panic_artifact.class = text("incomplete");
    let phase = panic_artifact.workers.get_mut(&text("branch")).unwrap();
    phase.stderr = Digest::of(panic);
    phase.exit = Some(101);
    finished.exit = Some(4);
    assert_eq!(observed(&panic_artifact, &finished), Class::EngineFailure);
    let mut parent = finished.clone();
    parent.class = Class::EngineFailure;
    assert_eq!(parent_kind(&parent), Some(FindingKind::Panic));
    store.replace(&dir, &name("branch.stderr"), b"").unwrap();
    store
        .replace(
            &dir,
            &name("branch.stdout"),
            b"a copied stream with another digest",
        )
        .unwrap();
    assert_eq!(observed(&false_pass, &finished), Class::MisboundEvidence);
}

#[test]
fn mixed_child_product_failures_preserve_independent_kinds_and_name_bounds() {
    let target = target(ForkForm::Branch {
        siblings: 2,
        suffixes: 1,
    });
    let output = format!(
        "{}child: suffix=0 sibling=0 class=success digest={} terminal=complete violation fired=03 required=03\nchild: suffix=0 sibling=1 class=failed\nbranch: 2 children, 1 credited, 0 problems\n",
        header(),
        Digest::of(b"child")
    );
    let judged = judge(&target, &output).unwrap();
    assert_eq!(judged.class, Class::Violation);
    assert_eq!(
        judged
            .children
            .iter()
            .map(|child| child.kind)
            .collect::<Vec<_>>(),
        [FindingKind::Violation, FindingKind::Incomplete]
    );
    assert!(
        ForkForm::Explore {
            advances: 1,
            children: 1,
            depth: 94,
            faults: 1
        }
        .children()
        .is_some()
    );
    assert!(
        ForkForm::Explore {
            advances: 1,
            children: 1,
            depth: 95,
            faults: 1
        }
        .children()
        .is_none()
    );
}

#[test]
fn automatic_release_blocker_kinds_are_exact() {
    assert_eq!(
        FindingKind::ALL
            .iter()
            .copied()
            .filter(|kind| kind.release_blocker())
            .map(FindingKind::name)
            .collect::<Vec<_>>(),
        ["violation", "panic", "abort"]
    );
}

#[test]
fn branch_refuses_missing_pairs_and_bounds_extra_child_retention() {
    let target = target(ForkForm::Branch {
        siblings: 2,
        suffixes: 2,
    });
    let judged = judge(&target, &branch()).unwrap();
    assert_eq!(judged.class, Class::Incomplete);
    let target = super::tests::target(ForkForm::Branch {
        siblings: 1,
        suffixes: 1,
    });
    let output = format!(
        "{}child: suffix=0 sibling=0 class=success digest={} terminal=complete pass fired=03 required=03\nchild: suffix=1 sibling=0 class=failed\nbranch: 2 children, 1 credited, 0 problems\n",
        header(),
        Digest::of(b"child")
    );
    let judged = judge(&target, &output).unwrap();
    assert_eq!(judged.class, Class::Incomplete);
    assert!(judged.children.is_empty());
}
#[test]
fn child_infrastructure_and_explore_leaf_checks_keep_failure_facts() {
    let target = target(ForkForm::Branch {
        siblings: 2,
        suffixes: 1,
    });
    for class in [
        "failed",
        "lost",
        "silent",
        "malformed",
        "mismatch",
        "success",
    ] {
        let credited = if class == "success" { 2 } else { 1 };
        let output = format!(
            "{}child: suffix=0 sibling=0 class={class}\nchild: suffix=0 sibling=1 class=success digest={} terminal=complete pass fired=03 required=03\nbranch: 2 children, {credited} credited, 0 problems\n",
            header(),
            Digest::of(b"child")
        );
        let judged = judge(&target, &output).unwrap();
        assert_eq!(judged.class, Class::Incomplete, "{class}");
        assert_eq!(judged.children.len(), 1);
        assert_eq!(judged.children[0].kind, FindingKind::Incomplete);
    }
    let target = super::tests::target(ForkForm::Explore {
        advances: 16,
        children: 2,
        depth: 2,
        faults: 12,
    });
    for (check, expected) in [
        ("its bundle cannot be read", Class::Incomplete),
        ("its digest disagrees", Class::EngineFailure),
    ] {
        let output = explore().replace(
            "explore: composed-bounded, 0 problems",
            &format!("problem: leaf 0.0: {check}\nexplore: composed-bounded, 1 problems"),
        );
        let judged = judge(&target, &output).unwrap();
        assert_eq!(judged.class, expected);
        assert_eq!(judged.children.len(), 1);
        assert_eq!(judged.children[0].label.as_str(), "l0");
        assert_eq!(judged.leaves, Some((1, 0)));
    }
    let judged = judge(&target, &explore()).unwrap();
    assert_eq!(
        (judged.printed, judged.credited, judged.leaves),
        (2, 2, Some((1, 1)))
    );
    assert_eq!(
        judge(&target, &explore().replace("0.0", "0.2"))
            .unwrap()
            .class,
        Class::Incomplete
    );
    let mut shallow = target.clone();
    if let ForkForm::Explore { ref mut depth, .. } = shallow.form {
        *depth = 1;
    }
    assert_eq!(
        judge(&shallow, &explore().replace("depth=2", "depth=1"))
            .unwrap()
            .class,
        Class::Incomplete
    );
}

#[test]
fn exploration_shape_and_cardinality_keep_parent_and_child_failures() {
    let target = target(ForkForm::Explore {
        depth: 1,
        children: 2,
        faults: 12,
        advances: 16,
    });
    let missing = format!(
        "label: composed-bounded\n{}limits: depth=1 children=2 faults=12 advances=16\nnode: path=0 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nfrontier: nodes=1 credited=1 explored=0 failing=0 unexplored=0\nexplore: composed-bounded, 0 problems\n",
        header()
    );
    assert_eq!(judge(&target, &missing).unwrap().class, Class::Incomplete);
    let mut output = format!(
        "label: composed-bounded\n{}limits: depth=1 children=2 faults=12 advances=16\n",
        header()
    );
    for path in 0..3 {
        output.push_str(&format!("node: path={path} class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path={path} digest={} unexplored=0 counts=true verdict=complete pass fired=03 required=03\n",Digest::of(b"leaf")));
    }
    output.push_str("frontier: nodes=3 credited=3 explored=3 failing=0 unexplored=0\nexplore: composed-bounded, 0 problems\n");
    assert_eq!(judge(&target, &output).unwrap().class, Class::Incomplete);
    let branch_target = super::tests::target(ForkForm::Branch {
        siblings: 2,
        suffixes: 1,
    });
    let output = branch().replace(
        "branch: 2 children, 2 credited, 0 problems",
        "problem: branch prefix changed\nbranch: 2 children, 2 credited, 1 problems",
    );
    assert_eq!(
        judge(&branch_target, &output).unwrap().class,
        Class::Incomplete
    );
}

#[test]
fn an_extra_success_node_without_leaf_or_child_breaks_only_tree_shape() {
    let target = target(ForkForm::Explore {
        depth: 2,
        children: 2,
        faults: 12,
        advances: 16,
    });
    assert_eq!(judge(&target, &explore()).unwrap().class, Class::Pass);
    let output = explore()
        .replace(
            "leaf: path=0.0",
            "node: path=1 class=success wall_us=1 cpu_us=1 max_rss_kib=1\nleaf: path=0.0",
        )
        .replace("nodes=2 credited=2", "nodes=3 credited=3");
    assert_eq!(judge(&target, &output).unwrap().class, Class::Incomplete);
}
