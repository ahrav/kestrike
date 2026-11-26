//! A libtest-shaped runner: lists the cases, or runs those the arguments
//! select on a few threads and prints libtest's outcome and result lines.

use std::fs;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::Instant;

use super::cases::*;

const CASES: &[(&str, fn())] = &[
    (
        "session_end_budget_and_lossy_diagnostics_have_reached_oracles",
        session_end_budget_and_lossy_diagnostics_have_reached_oracles,
    ),
    (
        "session_metadata_bounds_keep_a_published_prefix",
        session_metadata_bounds_keep_a_published_prefix,
    ),
    (
        "session_refusals_and_panic_divergence_reach_their_guards",
        session_refusals_and_panic_divergence_reach_their_guards,
    ),
    (
        "session_argv_uses_frozen_manifest_and_canonical_source",
        session_argv_uses_frozen_manifest_and_canonical_source,
    ),
    (
        "session_host_read_faults_are_incomplete_before_workers",
        session_host_read_faults_are_incomplete_before_workers,
    ),
    (
        "a_session_output_at_the_record_name_cannot_publish_credit",
        a_session_output_at_the_record_name_cannot_publish_credit,
    ),
    (
        "panicked_session_sources_verify_before_replaying_without_credit",
        panicked_session_sources_verify_before_replaying_without_credit,
    ),
    (
        "forked_argv_keeps_the_manifest_milestone_and_requested_pairs",
        forked_argv_keeps_the_manifest_milestone_and_requested_pairs,
    ),
    (
        "forked_rules_reach_nodes_milestones_problems_and_maximum_pairs",
        forked_rules_reach_nodes_milestones_problems_and_maximum_pairs,
    ),
    (
        "session_manifest_and_stdout_facts_have_independent_oracles",
        session_manifest_and_stdout_facts_have_independent_oracles,
    ),
    (
        "explicit_fork_watchdogs_keep_the_supplied_wait",
        explicit_fork_watchdogs_keep_the_supplied_wait,
    ),
    (
        "a_diverged_infrastructure_session_retains_incomplete_window_state",
        a_diverged_infrastructure_session_retains_incomplete_window_state,
    ),
    (
        "reproduced_sessions_use_the_end_credit_class",
        reproduced_sessions_use_the_end_credit_class,
    ),
    (
        "altered_archives_refuse_every_new_command_before_workers",
        altered_archives_refuse_every_new_command_before_workers,
    ),
    (
        "new_launcher_outputs_and_fork_bounds_refuse_before_workers",
        new_launcher_outputs_and_fork_bounds_refuse_before_workers,
    ),
    (
        "session_verdicts_require_files_stdout_and_source_stability",
        session_verdicts_require_files_stdout_and_source_stability,
    ),
    (
        "forked_false_credit_and_noncredit_classes_preserve_exit_agreement",
        forked_false_credit_and_noncredit_classes_preserve_exit_agreement,
    ),
    (
        "forked_watchdogs_use_the_tripled_manifest_bound",
        forked_watchdogs_use_the_tripled_manifest_bound,
    ),
    (
        "branch_siblings_match_the_exact_requested_pairs_and_reports",
        branch_siblings_match_the_exact_requested_pairs_and_reports,
    ),
    (
        "sessions_verify_all_files_and_agree_with_the_worker",
        sessions_verify_all_files_and_agree_with_the_worker,
    ),
    (
        "altered_session_sources_start_no_worker",
        altered_session_sources_start_no_worker,
    ),
    (
        "session_replay_compares_every_fact_except_apply_time",
        session_replay_compares_every_fact_except_apply_time,
    ),
    (
        "a_stop_in_the_second_window_publishes_the_verified_prefix",
        a_stop_in_the_second_window_publishes_the_verified_prefix,
    ),
    (
        "forked_summaries_require_worker_exit_agreement",
        forked_summaries_require_worker_exit_agreement,
    ),
    (
        "default_acls_preserve_private_worker_evidence_and_refuse_external_parents",
        default_acls_preserve_private_worker_evidence_and_refuse_external_parents,
    ),
    (
        "panic_reduction_requires_equal_inspected_summaries",
        panic_reduction_requires_equal_inspected_summaries,
    ),
    (
        "panic_candidates_keep_credit_and_terminals_distinct",
        panic_candidates_keep_credit_and_terminals_distinct,
    ),
    (
        "permissive_caller_masks_keep_worker_outputs_private",
        permissive_caller_masks_keep_worker_outputs_private,
    ),
    (
        "reduction_stops_when_its_baseline_does_not_reproduce",
        reduction_stops_when_its_baseline_does_not_reproduce,
    ),
    (
        "reduction_worker_exits_require_complete_result_evidence",
        reduction_worker_exits_require_complete_result_evidence,
    ),
    (
        "manual_truncated_replay_retains_incomplete_evidence",
        manual_truncated_replay_retains_incomplete_evidence,
    ),
    (
        "a_replay_worker_killed_by_a_signal_is_incomplete",
        a_replay_worker_killed_by_a_signal_is_incomplete,
    ),
    (
        "a_changed_replay_ledger_is_divergence",
        a_changed_replay_ledger_is_divergence,
    ),
    (
        "panic_output_and_summary_bindings_refuse_changed_evidence",
        panic_output_and_summary_bindings_refuse_changed_evidence,
    ),
    (
        "fresh_panic_steps_keep_passing_and_different_failures_distinct",
        fresh_panic_steps_keep_passing_and_different_failures_distinct,
    ),
    (
        "incomplete_reductions_keep_their_class",
        incomplete_reductions_keep_their_class,
    ),
    (
        "triage_output_paths_admit_printable_ascii_before_workers",
        triage_output_paths_admit_printable_ascii_before_workers,
    ),
    (
        "panic_replay_uses_the_verified_original_identity",
        panic_replay_uses_the_verified_original_identity,
    ),
    (
        "worker_detail_bounds_keep_a_publishable_artifact",
        worker_detail_bounds_keep_a_publishable_artifact,
    ),
    (
        "failed_capability_listings_are_incomplete",
        failed_capability_listings_are_incomplete,
    ),
    (
        "two_fresh_replays_keep_the_same_summary_and_inputs",
        two_fresh_replays_keep_the_same_summary_and_inputs,
    ),
    (
        "replay_from_run_checks_every_frozen_binding",
        replay_from_run_checks_every_frozen_binding,
    ),
    (
        "replay_of_a_reduction_uses_its_original_frozen_summary",
        replay_of_a_reduction_uses_its_original_frozen_summary,
    ),
    (
        "every_replay_fact_has_a_divergence_oracle",
        every_replay_fact_has_a_divergence_oracle,
    ),
    (
        "the_candidate_must_reproduce_in_an_independent_process",
        the_candidate_must_reproduce_in_an_independent_process,
    ),
    (
        "panic_reduction_keeps_the_location_payload_and_bundle",
        panic_reduction_keeps_the_location_payload_and_bundle,
    ),
    (
        "unreducible_inputs_and_passing_reruns_have_distinct_statuses",
        unreducible_inputs_and_passing_reruns_have_distinct_statuses,
    ),
    (
        "a_disappearing_replay_input_is_incomplete",
        a_disappearing_replay_input_is_incomplete,
    ),
    (
        "relative_reduction_paths_resolve_against_the_caller",
        relative_reduction_paths_resolve_against_the_caller,
    ),
    (
        "capabilities_list_the_verified_worker_contract",
        capabilities_list_the_verified_worker_contract,
    ),
    (
        "fresh_replay_preserves_the_frozen_failure",
        fresh_replay_preserves_the_frozen_failure,
    ),
    (
        "replay_records_the_first_semantic_divergence",
        replay_records_the_first_semantic_divergence,
    ),
    (
        "replay_result_and_summary_disagreements_remain_distinct",
        replay_result_and_summary_disagreements_remain_distinct,
    ),
    (
        "reduction_accepts_only_equal_full_failure_identity",
        reduction_accepts_only_equal_full_failure_identity,
    ),
    (
        "frozen_inputs_are_checked_around_each_triage_phase",
        frozen_inputs_are_checked_around_each_triage_phase,
    ),
    (
        "replay_from_run_verifies_the_record_and_archive_before_workers",
        replay_from_run_verifies_the_record_and_archive_before_workers,
    ),
    (
        "replay_from_run_reproduces_a_summary_recorded_without_its_rule",
        replay_from_run_reproduces_a_summary_recorded_without_its_rule,
    ),
    (
        "altered_triage_archives_start_no_worker",
        altered_triage_archives_start_no_worker,
    ),
    (
        "a_counting_run_records_every_form_under_the_launch_contract",
        a_counting_run_records_every_form_under_the_launch_contract,
    ),
    (
        "counts_with_no_decision_is_incomplete",
        counts_with_no_decision_is_incomplete,
    ),
    (
        "the_worker_exit_alone_never_counts",
        the_worker_exit_alone_never_counts,
    ),
    (
        "a_recovery_run_counts_only_with_a_credited_ledger",
        a_recovery_run_counts_only_with_a_credited_ledger,
    ),
    (
        "a_worker_that_fails_its_output_is_incomplete",
        a_worker_that_fails_its_output_is_incomplete,
    ),
    (
        "a_manifest_changed_during_the_run_is_incomplete",
        a_manifest_changed_during_the_run_is_incomplete,
    ),
    (
        "the_watchdog_kills_and_drains_the_group",
        the_watchdog_kills_and_drains_the_group,
    ),
    ("refused_inputs_run_no_worker", refused_inputs_run_no_worker),
    (
        "a_summary_of_another_profile_is_incomplete",
        a_summary_of_another_profile_is_incomplete,
    ),
    (
        "evidence_changed_during_a_form_is_incomplete",
        evidence_changed_during_a_form_is_incomplete,
    ),
    (
        "run_ids_name_new_artifact_directories",
        run_ids_name_new_artifact_directories,
    ),
    (
        "an_interruption_during_inspect_exits_5",
        an_interruption_during_inspect_exits_5,
    ),
    (
        "setup_refusals_preserve_pending_signals_and_infrastructure_classes",
        setup_refusals_preserve_pending_signals_and_infrastructure_classes,
    ),
    ("the_runner_applies_each_skip", the_runner_applies_each_skip),
    (
        "a_non_utf8_artifact_directory_is_refused",
        a_non_utf8_artifact_directory_is_refused,
    ),
    (
        "the_worker_dies_with_the_launcher",
        the_worker_dies_with_the_launcher,
    ),
    (
        "inspect_classes_a_staged_bundle",
        inspect_classes_a_staged_bundle,
    ),
    (
        "inspect_refuses_foreign_oversized_and_changed_bundles",
        inspect_refuses_foreign_oversized_and_changed_bundles,
    ),
];

/// Lists or runs the cases the arguments select, as libtest prints them:
/// `--list` lists them, `--ignored` selects none, since no case is
/// ignored, and positional arguments filter by substring or whole name
/// under `--exact`. `--skip NAME` and `--skip=NAME` drop matching cases.
pub(crate) fn runner() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut filters = Vec::new();
    let mut skips = Vec::new();
    let (mut list, mut ignored, mut exact) = (false, false, false);
    let mut threads = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--list" => list = true,
            "--ignored" => ignored = true,
            "--exact" => exact = true,
            "--skip" => {
                let Some(skip) = rest.next() else {
                    eprintln!("--skip requires a case name");
                    return ExitCode::from(2);
                };
                skips.push(skip.as_str());
            }
            flag if flag.starts_with("--skip=") => {
                skips.push(flag.strip_prefix("--skip=").expect("a skip"));
            }
            "--test-threads" => {
                threads = rest.next().and_then(|value| value.parse::<usize>().ok());
                if threads.is_none_or(|count| count == 0) {
                    eprintln!("--test-threads requires a positive count");
                    return ExitCode::from(2);
                }
            }
            flag if flag.starts_with("--test-threads=") => {
                threads = flag
                    .strip_prefix("--test-threads=")
                    .and_then(|value| value.parse::<usize>().ok());
                if threads.is_none_or(|count| count == 0) {
                    eprintln!("--test-threads requires a positive count");
                    return ExitCode::from(2);
                }
            }
            "--format" | "--color" => {
                rest.next();
            }
            flag if flag.starts_with('-') => {}
            filter => filters.push(filter.to_owned()),
        }
    }
    let matches = |name: &str, filter: &str| {
        if exact {
            name == filter
        } else {
            name.contains(filter)
        }
    };
    let chosen: Vec<&(&str, fn())> = CASES
        .iter()
        .filter(|(name, _)| {
            !ignored
                && !skips.iter().any(|skip| matches(name, skip))
                && (filters.is_empty() || filters.iter().any(|filter| matches(name, filter)))
        })
        .collect();
    let filtered = CASES.len() - chosen.len();
    if list {
        for (name, _) in &chosen {
            println!("{name}: test");
        }
        if !chosen.is_empty() {
            println!();
        }
        println!("{} tests, 0 benchmarks", chosen.len());
        return ExitCode::SUCCESS;
    }
    let started = Instant::now();
    println!("\nrunning {} tests", chosen.len());
    let threads = threads
        .or_else(|| {
            std::env::var("RUST_TEST_THREADS")
                .ok()
                .and_then(|count| count.parse().ok())
        })
        .unwrap_or(4usize)
        .max(1);
    let queue = Mutex::new(chosen.iter());
    let failed = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let next = queue.lock().expect("the queue").next();
                    let Some((name, case)) = next else { return };
                    let passed = std::panic::catch_unwind(case).is_ok();
                    println!("test {name} ... {}", if passed { "ok" } else { "FAILED" });
                    if !passed {
                        failed.lock().expect("the failures").push(*name);
                    }
                }
            });
        }
    });
    let failed = failed.into_inner().expect("the failures");
    let passed = chosen.len() - failed.len();
    if !failed.is_empty() {
        println!("\nfailures:");
        for name in &failed {
            println!("    {name}");
        }
    }
    println!(
        "\ntest result: {}. {passed} passed; {} failed; 0 ignored; 0 measured; {filtered} filtered out; finished in {:.2}s\n",
        if failed.is_empty() { "ok" } else { "FAILED" },
        failed.len(),
        started.elapsed().as_secs_f64(),
    );
    if failed.is_empty() {
        let _ = fs::remove_dir_all(scratch());
        ExitCode::SUCCESS
    } else {
        ExitCode::from(101)
    }
}
