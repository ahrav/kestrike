use super::*;

#[test]
fn limit_binding_stop_and_exit_matrix_credits_only_the_supported_pass_cell() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    stage(
        &store,
        store.root(),
        &attempt,
        &artifact(attempt.attempt.as_str(), attempt.manifest),
    );
    let evidence = [
        binding::read(&store, store.root(), &attempt).unwrap(),
        Evidence::Missing,
        Evidence::Malformed,
        Evidence::Misbound,
    ];
    let exits = [
        Some(0),
        Some(1),
        Some(2),
        Some(3),
        Some(4),
        Some(5),
        Some(6),
        Some(7),
        Some(125),
        None,
    ];
    let mut cells = 0;
    for limits in 0..8 {
        for (bound, evidence) in evidence.iter().enumerate() {
            for stops in 0..8 {
                for exit in exits {
                    let mut result = finished();
                    result.exit = exit;
                    result.binding = evidence.state();
                    result.bound = evidence.binding().cloned();
                    if limits & 1 != 0 {
                        result.kernel.memory.insert(text("oom_kill"), 1);
                    }
                    if limits & 2 != 0 {
                        result.kernel.pids.insert(text("max"), 1);
                    }
                    if limits & 4 != 0 {
                        result.kernel.cpu.insert(text("nr_throttled"), 1);
                    }
                    result.interruption = (stops & 1 != 0).then_some(15);
                    result.watchdog = stops & 2 != 0;
                    result.signal = if limits & 4 != 0 {
                        Some(crate::sys::CPU_SIGNAL as u64)
                    } else {
                        (stops & 4 != 0).then_some(15)
                    };
                    let class = classify(&result, evidence);
                    let expected = if limits != 0 {
                        match limits {
                            1 => Class::Oom,
                            2 => Class::PidLimit,
                            4 => Class::CpuLimit,
                            _ => Class::MixedLimits,
                        }
                    } else if bound == 2 {
                        Class::MalformedEvidence
                    } else if bound == 3 {
                        Class::MisboundEvidence
                    } else if stops & 1 != 0 {
                        Class::Interrupted
                    } else if stops & 2 != 0 {
                        Class::Watchdog
                    } else if stops & 4 != 0 {
                        Class::Signal
                    } else {
                        match (bound, exit) {
                            (_, None) | (1, Some(5)) => Class::Interrupted,
                            (1, Some(6)) => Class::Watchdog,
                            (0, Some(0)) => Class::Pass,
                            (0, Some(1..=6)) => Class::Disagreement,
                            (1, Some(0 | 1 | 4)) => Class::Incomplete,
                            _ => Class::Infrastructure,
                        }
                    };
                    assert_eq!(
                        class, expected,
                        "limits={limits} bound={bound} stops={stops} exit={exit:?}"
                    );
                    cells += 1;
                }
            }
        }
    }
    assert_eq!(cells, 2560);
}

#[test]
fn every_pass_guard_and_product_failure_trigger_has_a_refusing_control() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let cases = [
        ("artifact-class", Class::Disagreement),
        ("prewritten-artifact", Class::Disagreement),
        ("complete-pass", Class::Inconclusive),
        ("counts", Class::Incomplete),
        ("zero-decisions", Class::Incomplete),
        ("missing-decisions", Class::Incomplete),
        ("summary", Class::Incomplete),
        ("unfired", Class::Incomplete),
        ("zero-required", Class::Incomplete),
        ("run-exit", Class::Disagreement),
        ("inspect-exit", Class::Disagreement),
        ("extra-phase-exit", Class::Disagreement),
        ("phase-ended", Class::Disagreement),
        ("missing-run", Class::Disagreement),
        ("missing-inspect", Class::Disagreement),
        ("session-complete", Class::Incomplete),
        ("session-counts", Class::Incomplete),
        ("panic", Class::EngineFailure),
        ("worker-exit", Class::EngineFailure),
        ("worker-crash", Class::EngineFailure),
        ("worker-signal", Class::Signal),
        ("unwound", Class::Incomplete),
        ("build", Class::Infrastructure),
        ("launcher-interrupted", Class::Interrupted),
        ("unknown", Class::Infrastructure),
        ("interruption", Class::Interrupted),
        ("watchdog", Class::Watchdog),
        ("complete-cap", Class::Inconclusive),
        ("incomplete-cap", Class::Inconclusive),
        ("malformed-violation", Class::MalformedEvidence),
        ("oom", Class::Oom),
        ("oom-group", Class::Oom),
        ("throttled-usec", Class::Pass),
    ];
    for (input, expected) in cases {
        let mut artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
        let mut result = finished();
        match input {
            "artifact-class" => artifact.class = text("incomplete"),
            "prewritten-artifact" => result.exit = Some(4),
            "complete-pass" => {
                artifact.class = text("complete");
                result.exit = Some(1);
            }
            "counts" => artifact.summary.as_mut().unwrap().counts = false,
            "zero-decisions" => artifact.summary.as_mut().unwrap().decisions = Some(0),
            "missing-decisions" => artifact.summary.as_mut().unwrap().decisions = None,
            "summary" => artifact.summary = None,
            "unfired" => {
                artifact.summary.as_mut().unwrap().terminal =
                    text("complete pass fired=00 required=03")
            }
            "zero-required" => {
                artifact.summary.as_mut().unwrap().terminal =
                    text("complete pass fired=00 required=00")
            }
            "run-exit" => artifact.workers.get_mut(&text("run")).unwrap().exit = Some(1),
            "inspect-exit" => artifact.workers.get_mut(&text("inspect")).unwrap().exit = Some(1),
            "extra-phase-exit" => {
                let mut phase = artifact.workers[&text("run")].clone();
                phase.exit = Some(2);
                artifact.workers.insert(text("list"), phase);
            }
            "phase-ended" => {
                artifact.workers.get_mut(&text("run")).unwrap().ended = text("watchdog")
            }
            "missing-run" | "missing-inspect" => {
                artifact
                    .workers
                    .remove(&text(input.strip_prefix("missing-").unwrap()));
            }
            "session-complete" | "session-counts" => {
                artifact.session = Some(crate::record::SessionEvidence {
                    bytes: 6,
                    chain: Digest::of(b"prefix"),
                    complete: input != "session-complete",
                    counts: input != "session-counts",
                    digests: vec![Digest::of(b"window")],
                    end: None,
                    index: text("window 1"),
                    output: text("session"),
                    records: 1,
                    tail: None,
                    verification_error: Some(text("stopped in window 2")),
                    verified_windows: 1,
                })
            }
            "panic" => {
                artifact.workers.get_mut(&text("run")).unwrap().stderr =
                    Digest::of(b"thread 'main' panicked at failure");
            }
            "worker-exit" => artifact.workers.get_mut(&text("run")).unwrap().exit = Some(9),
            "worker-crash" => {
                artifact.workers.get_mut(&text("run")).unwrap().exit = None;
                artifact.workers.get_mut(&text("run")).unwrap().signal = Some(11);
            }
            "worker-signal" => {
                artifact.workers.get_mut(&text("run")).unwrap().exit = None;
                artifact.workers.get_mut(&text("run")).unwrap().signal = Some(15);
            }
            "unwound" => {
                artifact.workers.get_mut(&text("run")).unwrap().exit = Some(101);
                artifact.class = text("incomplete");
                result.exit = Some(4);
            }
            "build" => {
                artifact.class = text("build-failure");
                result.exit = Some(3);
            }
            "launcher-interrupted" => {
                artifact.class = text("interrupted");
                result.exit = Some(5);
            }
            "unknown" => result.exit = Some(7),
            "interruption" => result.interruption = Some(15),
            "watchdog" => result.watchdog = true,
            "complete-cap" | "incomplete-cap" => {
                artifact.summary.as_mut().unwrap().terminal = text("infrastructure cap");
                let sim = if input == "complete-cap" {
                    crate::exit::Sim::Complete
                } else {
                    crate::exit::Sim::Incomplete
                };
                artifact.class = text(sim.name());
                result.exit = Some(crate::exit::Exit::Sim(sim).code().into());
            }
            "malformed-violation" => {
                artifact.summary.as_mut().unwrap().terminal =
                    text("complete violation fired=broken required=03")
            }
            "oom" => {
                result.kernel.memory.insert(text("oom"), 1);
            }
            "oom-group" => {
                result.kernel.memory.insert(text("oom_group_kill"), 1);
            }
            "throttled-usec" => {
                result.kernel.cpu.insert(text("throttled_usec"), 1);
            }
            _ => panic!("every named control has its mutation"),
        }
        stage(&store, store.root(), &attempt, &artifact);
        let artifacts = store
            .open_dir(store.root(), &name("artifacts"))
            .unwrap()
            .unwrap();
        let dir = store
            .open_dir(&artifacts, &name(attempt.attempt.as_str()))
            .unwrap()
            .unwrap();
        if input == "panic" {
            store
                .replace(
                    &dir,
                    &name("run.stderr"),
                    b"thread 'main' panicked at failure",
                )
                .unwrap();
        }
        if input == "extra-phase-exit" {
            store
                .replace(&dir, &name("list.stdout"), b"stdout")
                .unwrap();
            store
                .replace(&dir, &name("list.stderr"), b"stderr")
                .unwrap();
        }
        let evidence = binding::read(&store, store.root(), &attempt).unwrap();
        assert!(
            matches!(evidence, Evidence::Bound(_)),
            "{input} reaches classification"
        );
        result.binding = evidence.state();
        result.bound = evidence.binding().cloned();
        assert_eq!(classify(&result, &evidence), expected, "{input}");
    }
}

#[test]
fn session_prefix_artifact_is_misbound_and_earns_no_credit() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut record = artifact(attempt.attempt.as_str(), attempt.manifest);
    record.command = text("session");
    record.class = text("interrupted");
    record.session = Some(crate::record::SessionEvidence {
        bytes: 6,
        chain: Digest::of(b"prefix"),
        complete: false,
        counts: false,
        digests: vec![Digest::of(b"window")],
        end: None,
        index: text("window 1"),
        output: text("session"),
        records: 1,
        tail: None,
        verification_error: Some(text("stopped in window 2")),
        verified_windows: 1,
    });
    stage(&store, store.root(), &attempt, &record);
    let evidence = binding::read(&store, store.root(), &attempt).unwrap();
    assert!(matches!(evidence, Evidence::Misbound));
    let mut result = finished();
    result.exit = Some(5);
    result.binding = evidence.state();
    assert_eq!(classify(&result, &evidence), Class::MisboundEvidence);
}

#[test]
fn bound_product_failures_precede_stop_flags_and_follow_kernel_limits() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut cells = 0;
    for product in [Class::Violation, Class::EngineFailure] {
        let mut record = artifact(attempt.attempt.as_str(), attempt.manifest);
        if product == Class::Violation {
            record.summary.as_mut().unwrap().terminal =
                text("complete violation fired=03 required=03");
        } else {
            record.workers.get_mut(&text("run")).unwrap().stderr =
                Digest::of(b"thread 'main' panicked at failure");
        }
        stage(&store, store.root(), &attempt, &record);
        if product == Class::EngineFailure {
            let artifacts = store
                .open_dir(store.root(), &name("artifacts"))
                .unwrap()
                .unwrap();
            let directory = store
                .open_dir(&artifacts, &name(attempt.attempt.as_str()))
                .unwrap()
                .unwrap();
            store
                .replace(
                    &directory,
                    &name("run.stderr"),
                    b"thread 'main' panicked at failure",
                )
                .unwrap();
        }
        let evidence = binding::read(&store, store.root(), &attempt).unwrap();
        assert!(matches!(evidence, Evidence::Bound(_)));
        for limits in 0..8 {
            for stops in 0..8 {
                for exit in [0, 7] {
                    let mut result = finished();
                    result.binding = evidence.state();
                    result.bound = evidence.binding().cloned();
                    result.exit = Some(exit);
                    if limits & 1 != 0 {
                        result.kernel.memory.insert(text("oom_kill"), 1);
                    }
                    if limits & 2 != 0 {
                        result.kernel.pids.insert(text("max"), 1);
                    }
                    if limits & 4 != 0 {
                        result.kernel.cpu.insert(text("nr_throttled"), 1);
                    }
                    result.interruption = (stops & 1 != 0).then_some(15);
                    result.watchdog = stops & 2 != 0;
                    result.signal = if limits & 4 != 0 {
                        Some(crate::sys::CPU_SIGNAL as u64)
                    } else {
                        (stops & 4 != 0).then_some(15)
                    };
                    let expected = match limits {
                        0 => product,
                        1 => Class::Oom,
                        2 => Class::PidLimit,
                        4 => Class::CpuLimit,
                        _ => Class::MixedLimits,
                    };
                    assert_eq!(
                        classify(&result, &evidence),
                        expected,
                        "product={product:?} limits={limits} stops={stops} exit={exit}"
                    );
                    cells += 1;
                }
            }
        }
    }
    assert_eq!(cells, 256);
}

#[test]
fn throttling_deltas_preserve_a_successful_bound_verdict() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    stage(
        &store,
        store.root(),
        &attempt,
        &artifact(attempt.attempt.as_str(), attempt.manifest),
    );
    let evidence = binding::read(&store, store.root(), &attempt).unwrap();
    let mut result = finished();
    result.binding = evidence.state();
    result.bound = evidence.binding().cloned();
    result.exit = Some(0);
    result.kernel.cpu.insert(text("nr_throttled"), 8);
    result.kernel.cpu.insert(text("throttled_usec"), 9000);
    assert_eq!(classify(&result, &evidence), Class::Pass);
    assert_eq!(result.kernel.cpu.get(&text("nr_throttled")), Some(&8));
    result.interruption = Some(crate::sys::CPU_SIGNAL as u64);
    assert_eq!(classify(&result, &evidence), Class::CpuLimit);
}

#[test]
fn fresh_replay_pass_requires_each_bound_worker_phase() {
    for missing in [
        None,
        Some("replay"),
        Some("inspect-original"),
        Some("inspect-replay"),
    ] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let attempt = attempt_record();
        let mut artifact = artifact(attempt.attempt.as_str(), attempt.manifest);
        artifact.command = text("replay");
        let worker = artifact.workers[&text("run")].clone();
        artifact.workers = ["replay", "inspect-original", "inspect-replay"]
            .into_iter()
            .filter(|phase| Some(*phase) != missing)
            .map(|phase| (text(phase), worker.clone()))
            .collect();
        let directory = stage(&store, store.root(), &attempt, &artifact);
        store
            .replace(&directory, &name("input"), b"bundle")
            .unwrap();
        for phase in artifact.workers.keys() {
            store
                .replace(
                    &directory,
                    &name(&format!("{}.stdout", phase.as_str())),
                    b"stdout",
                )
                .unwrap();
            store
                .replace(
                    &directory,
                    &name(&format!("{}.stderr", phase.as_str())),
                    b"stderr",
                )
                .unwrap();
        }
        let bound = binding::read_command(&store, store.root(), &attempt, "replay").unwrap();
        assert_eq!(bound.state(), Binding::Matching);
        assert_eq!(
            classify(&finished(), &bound),
            if missing.is_none() {
                Class::Pass
            } else {
                Class::Disagreement
            },
            "{missing:?}"
        );
    }
}

#[test]
fn output_limits_retry_and_preserve_bound_product_failures_and_kernel_priority() {
    for product in [Class::Pass, Class::Violation, Class::EngineFailure] {
        let case = Case::new();
        let store = Store::open(&case.state).unwrap();
        let attempt = attempt_record();
        let mut value = artifact(attempt.attempt.as_str(), attempt.manifest);
        if product == Class::Violation {
            value.summary.as_mut().unwrap().terminal =
                text("complete violation fired=03 required=03");
        }
        if product == Class::EngineFailure {
            value.summary.as_mut().unwrap().terminal = text("infrastructure defect");
        }
        stage(&store, store.root(), &attempt, &value);
        let evidence = binding::read(&store, store.root(), &attempt).unwrap();
        let mut result = finished();
        result.exit = Some(0);
        result.binding = evidence.state();
        result.bound = evidence.binding().cloned();
        result.interruption = Some(crate::sys::OUTPUT_SIGNAL as u64);
        assert_eq!(
            classify(&result, &evidence),
            if product == Class::Pass {
                Class::OutputLimit
            } else {
                product
            }
        );
        result.kernel.memory.insert(text("oom_kill"), 1);
        assert_eq!(classify(&result, &evidence), Class::Oom);
        result.kernel.memory.clear();
        result.interruption = Some(crate::sys::CPU_SIGNAL as u64);
        result.signal = Some(crate::sys::OUTPUT_SIGNAL as u64);
        assert_eq!(classify(&result, &evidence), Class::CpuLimit);
    }
    let mut result = finished();
    result.interruption = Some(crate::sys::OUTPUT_SIGNAL as u64);
    for evidence in [Evidence::Missing, Evidence::Malformed, Evidence::Misbound] {
        assert_eq!(classify(&result, &evidence), Class::OutputLimit);
    }
}

#[test]
fn a_bound_worker_cpu_signal_is_limit_evidence() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut value = artifact(attempt.attempt.as_str(), attempt.manifest);
    value.workers.get_mut(&text("run")).unwrap().signal = Some(crate::sys::CPU_SIGNAL as u64);
    value.workers.get_mut(&text("run")).unwrap().exit = None;
    stage(&store, store.root(), &attempt, &value);
    let evidence = binding::read(&store, store.root(), &attempt).unwrap();
    assert_eq!(classify(&finished(), &evidence), Class::CpuLimit);
}

#[test]
fn malformed_terminal_preserves_bound_worker_crash_over_output_limit() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut value = artifact(attempt.attempt.as_str(), attempt.manifest);
    value.summary.as_mut().unwrap().terminal = text("malformed terminal");
    value.workers.get_mut(&text("run")).unwrap().signal = Some(crate::sys::CRASH_SIGNALS[0]);
    stage(&store, store.root(), &attempt, &value);
    let evidence = binding::read(&store, store.root(), &attempt).unwrap();
    let mut result = finished();
    result.interruption = Some(crate::sys::OUTPUT_SIGNAL as u64);
    assert_eq!(classify(&result, &evidence), Class::EngineFailure);
}

#[test]
fn replay_observed_violation_overrides_the_original_passing_summary() {
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut value = artifact(attempt.attempt.as_str(), attempt.manifest);
    let original = value.summary.clone().unwrap();
    let mut observed = original.clone();
    observed.counts = false;
    observed.terminal = text("complete violation fired=03 required=03");
    value.command = text("replay");
    value.comparison = Some(crate::record::Comparison {
        candidate: None,
        divergence: None,
        failure_identity: None,
        failure_kind: None,
        observed: Some(observed),
        original: Some(original),
        output: None,
        status: text("diverged"),
    });
    let worker = value.workers[&text("run")].clone();
    value.workers = ["replay", "inspect-original", "inspect-replay"]
        .into_iter()
        .map(|phase| (text(phase), worker.clone()))
        .collect();
    let directory = stage(&store, store.root(), &attempt, &value);
    store
        .replace(&directory, &name("input"), b"bundle")
        .unwrap();
    for phase in value.workers.keys() {
        store
            .replace(
                &directory,
                &name(&format!("{}.stdout", phase.as_str())),
                b"stdout",
            )
            .unwrap();
        store
            .replace(
                &directory,
                &name(&format!("{}.stderr", phase.as_str())),
                b"stderr",
            )
            .unwrap();
    }
    let bound = binding::read_command(&store, store.root(), &attempt, "replay").unwrap();
    assert_eq!(bound.state(), Binding::Matching);
    assert_eq!(classify(&finished(), &bound), Class::Violation);
    let Evidence::Bound(bound) = &bound else {
        panic!("matching replay is bound")
    };
    assert_eq!(
        crate::attempt::finding_kind(&finished(), Some(bound)),
        Some(crate::record::FindingKind::Violation)
    );
}

#[test]
fn an_incomplete_replay_without_an_observed_summary_keeps_its_exit_class() {
    // The replay artifact's `summary` repeats the comparison's original, so a
    // replay with a comparison classifies from `comparison.observed` alone.
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let attempt = attempt_record();
    let mut value = artifact(attempt.attempt.as_str(), attempt.manifest);
    let mut original = value.summary.clone().unwrap();
    original.counts = false;
    original.terminal = text("complete violation fired=03 required=03");
    value.summary = Some(original.clone());
    value.command = text("replay");
    value.class = text("incomplete");
    value.comparison = Some(crate::record::Comparison {
        candidate: None,
        divergence: None,
        failure_identity: None,
        failure_kind: None,
        observed: None,
        original: Some(original),
        output: None,
        status: text("incomplete"),
    });
    let worker = value.workers[&text("run")].clone();
    value.workers = ["replay", "inspect-original"]
        .into_iter()
        .map(|phase| (text(phase), worker.clone()))
        .collect();
    let directory = stage(&store, store.root(), &attempt, &value);
    store
        .replace(&directory, &name("input"), b"bundle")
        .unwrap();
    for phase in value.workers.keys() {
        store
            .replace(
                &directory,
                &name(&format!("{}.stdout", phase.as_str())),
                b"stdout",
            )
            .unwrap();
        store
            .replace(
                &directory,
                &name(&format!("{}.stderr", phase.as_str())),
                b"stderr",
            )
            .unwrap();
    }
    let bound = binding::read_command(&store, store.root(), &attempt, "replay").unwrap();
    assert_eq!(bound.state(), Binding::Matching);
    let mut stopped = finished();
    stopped.exit = Some(4);
    assert_eq!(classify(&stopped, &bound), Class::Incomplete);
    let Evidence::Bound(bound) = &bound else {
        panic!("matching replay is bound")
    };
    assert_eq!(crate::attempt::finding_kind(&stopped, Some(bound)), None);
}
