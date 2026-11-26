#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod calibration;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod cases;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[path = "../sim_launch/worker.rs"]
mod sim_worker;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod triage;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod worker;

/// Paths of the sharded layout: a job's records in `jobs/<xx>/` and its
/// attempts in `attempts/<xx>/<id>/`, `<xx>` the id's first two characters.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod sharded {
    use campaign_supervisor::store::{Dir, Name, Store, View};
    use std::path::PathBuf;

    /// `jobs/<xx>/<file>` for the job id that starts `file`.
    pub(crate) fn job_file(file: impl AsRef<str>) -> PathBuf {
        let file = file.as_ref();
        PathBuf::from("jobs").join(&file[..2]).join(file)
    }

    /// `attempts/<xx>/<id>`.
    pub(crate) fn attempts_dir(id: impl AsRef<str>) -> PathBuf {
        let id = id.as_ref();
        PathBuf::from("attempts").join(&id[..2]).join(id)
    }

    fn name(value: &str) -> Name {
        Name::new(value).unwrap()
    }

    pub(crate) fn open_shard(view: &View, root: &str, id: &str) -> Dir {
        let parent = view.open_dir(view.root(), &name(root)).unwrap().unwrap();
        view.open_dir(&parent, &name(&id[..2])).unwrap().unwrap()
    }

    fn shard(store: &Store, root: &str, id: impl ToString) -> Dir {
        let id = id.to_string();
        store.mkdir(store.root(), &name(root)).unwrap();
        let parent = store.open_dir(store.root(), &name(root)).unwrap().unwrap();
        store.mkdir(&parent, &name(&id[..2])).unwrap();
        store.open_dir(&parent, &name(&id[..2])).unwrap().unwrap()
    }

    /// The `jobs/` shard of job `id`, created when absent.
    pub(crate) fn jobs(store: &Store, id: impl ToString) -> Dir {
        shard(store, "jobs", id)
    }

    /// The `attempts/` shard of job `id`, created when absent.
    pub(crate) fn attempts(store: &Store, id: impl ToString) -> Dir {
        shard(store, "attempts", id)
    }
}

/// Every case needs a delegated cgroup-v2 user scope, so every case is ignored.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const DELEGATION: &str = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT";

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn main() -> std::process::ExitCode {
    if let Some(plan) = std::env::var_os(sim_worker::PLAN) {
        let path = std::path::Path::new(&plan);
        if path.join("calibration").exists() {
            return calibration::worker(path);
        }
        return sim_worker::worker(path);
    }
    if let Some(plan) = std::env::var_os("CAMPAIGN_ATTEMPT_LAUNCHER") {
        return cases::attempt_launcher(std::path::Path::new(&plan));
    }
    if let Some(plan) = std::env::var_os("CAMPAIGN_ATTEMPT_STRAGGLER") {
        return cases::attempt_straggler(std::path::Path::new(&plan));
    }
    if let Some(plan) = std::env::var_os("CAMPAIGN_CUSTODY_WORKER") {
        return worker::worker(std::path::Path::new(&plan));
    }
    if let Some(plan) = std::env::var_os("CAMPAIGN_CUSTODY_TEST_CONTROLLER") {
        return cases::controller(
            std::path::Path::new(&plan),
            std::path::Path::new(&std::env::var_os("CAMPAIGN_CUSTODY_TEST_ROOT").unwrap()),
        );
    }
    macro_rules! cases {
        ($($case:ident),* $(,)?) => {
            &[$((stringify!($case), cases::$case as fn())),*]
        };
    }
    let cases: &[(&str, fn())] = cases![
        targeted_missing_facts_settle_one_replay_and_explicit_steps_can_repeat,
        targeted_explore_nodes_and_leaves_keep_separate_findings_and_waiting_nodes,
        targeted_exploration_freezes_manifest_bounds_and_rejudges_retired_inputs,
        targeted_admission_freezes_versions_retirement_and_dispatch_roots,
        targeted_child_capture_binds_actual_parent_and_retains_independent_bundle,
        corpus_duplicate_bundles_preserve_version_and_skip_workers,
        corpus_registration_retirement_and_report_keep_frozen_roots,
        corpus_duplicate_semantics_and_caps_refuse_at_reached_guards,
        corpus_failed_prefix_and_interruption_keep_history_without_admission,
        corpus_lost_probe_reservation_reconciles_before_new_registration,
        undetected_control_preserves_its_release_blocker,
        calibration_replay_panic_is_a_release_blocker_with_root_provenance,
        calibrated_controls_lost_attempt_and_two_fresh_replays_grant_scoped_capacity,
        missing_controls_and_disagreeing_fresh_replays_preserve_explicit_verdicts,
        lost_calibration_replay_reconciles_under_dispatch_and_preserves_dependencies,
        unsealed_replay_disagreement_blocks_every_later_capacity_root,
        retained_run_replays_in_fresh_processes_and_drift_starts_nothing,
        retained_rerun_and_reduction_keep_full_identity,
        retained_step_owner_loss_at_worker_seam_is_interrupted_and_exclusive,
        storage_pause_is_successful_dispatch_and_explicit_refusal_without_mutation,
        triage_runs_on_reserve_while_the_ordinary_slot_is_full,
        cli_signal_drain_smoke_preserves_minted_results,
        dispatch_cli_runs_and_reports_held_reservations,
        numbered_retries_enforce_limits_and_reconcile_finished_evidence,
        started_attempt_reconciles_membership_after_owner_drop,
        numbered_attempts_classify_kernel_limits_and_rederive_binding,
        held_history_and_evidence_overflow_preserve_a_started_campaign_witness,
        straggler_pass_is_fenced_by_stopped_membership,
        corrupt_released_probe_does_not_leave_a_healthy_charged_probe_running,
        live_probe_reservation_damage_prevents_release_and_admission,
        invalid_archive_refuses_without_probe_or_job_publication,
        released_probes_allow_a_different_delegated_root,
        reappeared_released_cgroups_stay_held_and_alive,
        probe_retention_and_foreign_groups_refuse_before_launch,
        interrupted_probe_reconciles_before_new_admission,
        probe_lifecycle_marker_damage_keeps_the_tree_held,
        admission_watchdog_and_sigterm_stop_reached_workers,
        held_probe_records_block_new_admission,
        failed_probe_releases_custody_and_allows_retry,
        show_scan_overflow_has_no_partial_stdout,
        admission_probe_and_frozen_jobs,
        admission_cli_rejections_and_configuration,
        recreated_cgroup_instance_keeps_a_live_sentinel_held,
        watchdog_stops_a_reached_stalled_worker,
        gate_setup_clears_mask_and_sets_group_before_direct_exec,
        idle_interruption_is_typed_and_refuses_a_fresh_launch,
        prior_boot_absence_reconciles_and_reused_paths_stay_held,
        existing_groups_stay_held_after_intent_without_started,
        all_pidfds_stop_a_later_attempt_that_exits_first,
        interruption_marks_every_remaining_attempt_for_drain,
        durable_records_precede_worker_effects_and_the_mask_is_empty,
        kill_drain_remove_contains_session_escapees,
        nested_empty_children_hold_removal_and_redrain_on_restart,
        restart_stops_membership_and_preserves_a_live_sentinel,
        unknown_and_foreign_root_cgroups_stay_held,
        file_size_limit_stops_a_worker_and_preserves_partial_bytes,
        ignored_sigint_still_reaches_the_signal_descriptor,
        pid_memory_and_cpu_limits_preserve_kernel_events,
        returning_controller_preserves_the_parent_test_membership,
        controller_sigkill_preserves_records_for_membership_reconciliation,
        signal_descriptor_interruptions_stop_the_attempt,
        gate_failures_own_125_and_non_gate_commands_exclude_it,
    ];
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().any(|arg| arg == name);
    if flag("--ignored") && flag("--include-ignored") {
        eprintln!("error: the options --include-ignored and --ignored are mutually exclusive");
        return std::process::ExitCode::from(101);
    }
    let selected = flag("--ignored") || flag("--include-ignored");
    let mut filters = Vec::new();
    let mut skips = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--skip" => skips.push(rest.next().expect("skip name").as_str()),
            "--test-threads" | "--format" | "--color" => {
                rest.next();
            }
            flag if flag.starts_with("--skip=") => skips.push(&flag[7..]),
            flag if !flag.starts_with('-') => filters.push(flag),
            _ => {}
        }
    }
    let matches = |name: &str, filter: &str| {
        if flag("--exact") {
            name == filter
        } else {
            name.contains(filter)
        }
    };
    let chosen: Vec<_> = cases
        .iter()
        .filter(|(name, _)| {
            !skips.iter().any(|filter| matches(name, filter))
                && (filters.is_empty() || filters.iter().any(|filter| matches(name, filter)))
        })
        .collect();
    if flag("--list") {
        for (name, _) in &chosen {
            println!("{name}: test");
        }
        println!("\n{} tests, 0 benchmarks", chosen.len());
        return std::process::ExitCode::SUCCESS;
    }
    let started = std::time::Instant::now();
    let (mut passed, mut failed, mut ignored) = (0, 0, 0);
    println!("\nrunning {} tests", chosen.len());
    for (name, case) in &chosen {
        if !selected {
            ignored += 1;
            println!("test {name} ... ignored, {DELEGATION}");
            continue;
        }
        if std::panic::catch_unwind(*case).is_ok() {
            passed += 1;
            println!("test {name} ... ok");
        } else {
            failed += 1;
            println!("test {name} ... FAILED");
        }
    }
    println!(
        "\ntest result: {}. {passed} passed; {failed} failed; {ignored} ignored; 0 measured; {} filtered out; finished in {:.2}s\n",
        if failed == 0 { "ok" } else { "FAILED" },
        cases.len() - chosen.len(),
        started.elapsed().as_secs_f64()
    );
    cases::remove_archive();
    if failed == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(101)
    }
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn main() {
    println!("0 tests, 0 benchmarks");
}
