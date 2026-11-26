//! Each case runs the real `sim-host` binary in its own directory, with
//! the fake `campaign`, a loopback metadata service and a plain directory
//! tree for the unit's cgroup.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::fake;

pub const CASES: &[(&str, fn())] = &[
    (
        "stints_a_kill_and_a_restart_keep_one_root",
        stints_a_kill_and_a_restart_keep_one_root,
    ),
    (
        "a_killed_runner_stops_its_running_sweep",
        a_killed_runner_stops_its_running_sweep,
    ),
    (
        "a_second_runner_on_one_state_exits_at_once",
        a_second_runner_on_one_state_exits_at_once,
    ),
    (
        "another_instance_id_opens_a_new_root_and_leaves_the_old_one",
        another_instance_id_opens_a_new_root_and_leaves_the_old_one,
    ),
    (
        "a_foreign_root_gets_no_confirm_without_an_assignment",
        a_foreign_root_gets_no_confirm_without_an_assignment,
    ),
    (
        "a_changed_build_opens_a_new_root",
        a_changed_build_opens_a_new_root,
    ),
    (
        "changed_counts_or_name_open_a_new_root",
        changed_counts_or_name_open_a_new_root,
    ),
    (
        "a_changed_confirm_slot_count_opens_a_new_root",
        a_changed_confirm_slot_count_opens_a_new_root,
    ),
    (
        "a_replaced_assignment_changes_the_next_stint_only",
        a_replaced_assignment_changes_the_next_stint_only,
    ),
    (
        "an_unreadable_assignment_leaves_the_stored_copy_in_force",
        an_unreadable_assignment_leaves_the_stored_copy_in_force,
    ),
    (
        "a_lost_or_altered_copy_is_rewritten_from_the_source",
        a_lost_or_altered_copy_is_rewritten_from_the_source,
    ),
    (
        "an_unrecorded_copy_leaves_the_recorded_assignment_in_force",
        an_unrecorded_copy_leaves_the_recorded_assignment_in_force,
    ),
    (
        "a_missing_or_other_archive_blocks_the_stint",
        a_missing_or_other_archive_blocks_the_stint,
    ),
    (
        "each_sweep_exit_sets_the_next_step_and_failures_wait",
        each_sweep_exit_sets_the_next_step_and_failures_wait,
    ),
    (
        "a_completed_sweep_resets_the_failure_count",
        a_completed_sweep_resets_the_failure_count,
    ),
    (
        "a_sweep_that_cannot_start_waits_before_its_retry",
        a_sweep_that_cannot_start_waits_before_its_retry,
    ),
    (
        "a_sweep_that_cannot_start_publishes_no_stint_share",
        a_sweep_that_cannot_start_publishes_no_stint_share,
    ),
    (
        "a_restart_keeps_the_wait_after_a_failed_sweep",
        a_restart_keeps_the_wait_after_a_failed_sweep,
    ),
    (
        "a_restart_after_the_third_failure_keeps_the_wait",
        a_restart_after_the_third_failure_keeps_the_wait,
    ),
    (
        "an_alarmed_sweep_keeps_sweeping_and_sets_the_alarm",
        an_alarmed_sweep_keeps_sweeping_and_sets_the_alarm,
    ),
    (
        "a_replaced_root_keeps_its_alarm_and_the_record_follows_the_new_root",
        a_replaced_root_keeps_its_alarm_and_the_record_follows_the_new_root,
    ),
    (
        "a_backlog_hold_lets_the_sweep_continue_and_confirm_waits",
        a_backlog_hold_lets_the_sweep_continue_and_confirm_waits,
    ),
    (
        "a_backlog_report_without_its_error_log_holds_the_root",
        a_backlog_report_without_its_error_log_holds_the_root,
    ),
    (
        "another_confirm_hold_stops_stints_until_a_confirm_succeeds",
        another_confirm_hold_stops_stints_until_a_confirm_succeeds,
    ),
    (
        "a_confirm_hold_at_the_stint_boundary_stops_the_next_stint",
        a_confirm_hold_at_the_stint_boundary_stops_the_next_stint,
    ),
    (
        "a_busy_confirm_waits_and_the_sweep_continues",
        a_busy_confirm_waits_and_the_sweep_continues,
    ),
    (
        "a_restart_keeps_the_wait_after_a_held_confirm",
        a_restart_keeps_the_wait_after_a_held_confirm,
    ),
    (
        "a_restart_with_a_lost_copy_waits_the_source_stint_before_a_confirm",
        a_restart_with_a_lost_copy_waits_the_source_stint_before_a_confirm,
    ),
    (
        "a_restart_takes_its_confirm_wait_from_the_source",
        a_restart_takes_its_confirm_wait_from_the_source,
    ),
    (
        "no_confirm_starts_without_a_new_suspect_line",
        no_confirm_starts_without_a_new_suspect_line,
    ),
    (
        "a_torn_suspect_line_starts_no_confirm",
        a_torn_suspect_line_starts_no_confirm,
    ),
    (
        "a_line_written_during_a_confirm_gets_another_confirm",
        a_line_written_during_a_confirm_gets_another_confirm,
    ),
    (
        "queued_jobs_get_another_confirm_without_a_new_line",
        queued_jobs_get_another_confirm_without_a_new_line,
    ),
    (
        "lines_of_a_replaced_root_are_confirmed",
        lines_of_a_replaced_root_are_confirmed,
    ),
    (
        "the_disk_reserve_skips_the_stint",
        the_disk_reserve_skips_the_stint,
    ),
    (
        "a_signal_stops_the_children_before_the_runner_exits",
        a_signal_stops_the_children_before_the_runner_exits,
    ),
    (
        "an_error_after_the_sweep_starts_stops_the_sweep_first",
        an_error_after_the_sweep_starts_stops_the_sweep_first,
    ),
    (
        "an_ignored_sigchld_leaves_the_children_waitable",
        an_ignored_sigchld_leaves_the_children_waitable,
    ),
    (
        "the_health_record_carries_the_sweep_groups_cpu",
        the_health_record_carries_the_sweep_groups_cpu,
    ),
    (
        "an_unreadable_cpu_counter_is_unmeasured",
        an_unreadable_cpu_counter_is_unmeasured,
    ),
    (
        "a_host_without_an_instance_id_starts_nothing",
        a_host_without_an_instance_id_starts_nothing,
    ),
    (
        "check_refuses_each_oversubscription_limit_and_missing_id",
        check_refuses_each_oversubscription_limit_and_missing_id,
    ),
    (
        "status_exits_by_the_record_and_prints_the_hand_computed_share",
        status_exits_by_the_record_and_prints_the_hand_computed_share,
    ),
    (
        "check_reads_only_the_assignment",
        check_reads_only_the_assignment,
    ),
    (
        "a_new_head_is_published_once_and_the_next_head_moves_current",
        a_new_head_is_published_once_and_the_next_head_moves_current,
    ),
    (
        "a_relative_checkout_and_state_publish_the_same_record",
        a_relative_checkout_and_state_publish_the_same_record,
    ),
    (
        "a_publisher_that_finds_its_build_stored_uses_the_stored_one",
        a_publisher_that_finds_its_build_stored_uses_the_stored_one,
    ),
    (
        "a_record_of_another_commit_is_not_promoted",
        a_record_of_another_commit_is_not_promoted,
    ),
    (
        "a_dirty_checkout_or_a_failed_build_publishes_nothing_until_the_next_head",
        a_dirty_checkout_or_a_failed_build_publishes_nothing_until_the_next_head,
    ),
    (
        "an_unbuilt_binary_or_an_unclean_archive_publishes_nothing",
        an_unbuilt_binary_or_an_unclean_archive_publishes_nothing,
    ),
    (
        "a_failed_fetch_publishes_nothing_until_a_fetch_succeeds",
        a_failed_fetch_publishes_nothing_until_a_fetch_succeeds,
    ),
    (
        "a_directory_at_the_built_binary_is_kept_and_nothing_builds",
        a_directory_at_the_built_binary_is_kept_and_nothing_builds,
    ),
    (
        "a_skipped_head_is_tried_again_when_main_returns_to_it",
        a_skipped_head_is_tried_again_when_main_returns_to_it,
    ),
    (
        "a_published_build_is_fetched_and_swept",
        a_published_build_is_fetched_and_swept,
    ),
    (
        "two_runner_states_fetch_one_build_and_name_the_same_build",
        two_runner_states_fetch_one_build_and_name_the_same_build,
    ),
    (
        "each_refused_download_leaves_no_final_directory",
        each_refused_download_leaves_no_final_directory,
    ),
    (
        "a_failed_download_keeps_the_host_on_its_build",
        a_failed_download_keeps_the_host_on_its_build,
    ),
    (
        "every_stint_sweeps_through_a_store_outage_and_the_stored_objects_match_after",
        every_stint_sweeps_through_a_store_outage_and_the_stored_objects_match_after,
    ),
    (
        "the_last_stint_is_uploaded_at_a_stop",
        the_last_stint_is_uploaded_at_a_stop,
    ),
    (
        "a_stop_during_a_hung_store_call_exits_promptly",
        a_stop_during_a_hung_store_call_exits_promptly,
    ),
    (
        "an_old_root_is_deleted_when_all_four_conditions_hold",
        an_old_root_is_deleted_when_all_four_conditions_hold,
    ),
    (
        "an_old_root_of_the_assigned_build_stays",
        an_old_root_of_the_assigned_build_stays,
    ),
    (
        "an_old_root_with_unread_suspect_lines_stays",
        an_old_root_with_unread_suspect_lines_stays,
    ),
    (
        "an_old_root_with_an_unresolved_finding_stays",
        an_old_root_with_an_unresolved_finding_stays,
    ),
    (
        "an_old_root_is_confirmed_after_its_build_changes_and_then_deleted",
        an_old_root_is_confirmed_after_its_build_changes_and_then_deleted,
    ),
    (
        "a_root_without_a_sweep_is_deleted_when_its_build_changes",
        a_root_without_a_sweep_is_deleted_when_its_build_changes,
    ),
    (
        "a_foreign_root_is_neither_uploaded_nor_deleted",
        a_foreign_root_is_neither_uploaded_nor_deleted,
    ),
    (
        "a_failed_snapshot_command_keeps_the_stored_objects",
        a_failed_snapshot_command_keeps_the_stored_objects,
    ),
    (
        "a_stray_entry_under_builds_leaves_the_runner_sweeping",
        a_stray_entry_under_builds_leaves_the_runner_sweeping,
    ),
    (
        "an_old_root_whose_stored_objects_differ_stays_until_they_match",
        an_old_root_whose_stored_objects_differ_stays_until_they_match,
    ),
    (
        "the_next_pass_finishes_an_interrupted_deletion",
        the_next_pass_finishes_an_interrupted_deletion,
    ),
    (
        "the_stored_record_is_a_version_of_the_local_record",
        the_stored_record_is_a_version_of_the_local_record,
    ),
    (
        "a_failing_record_put_delays_no_stint_and_stays_named_until_one_succeeds",
        a_failing_record_put_delays_no_stint_and_stays_named_until_one_succeeds,
    ),
    (
        "a_hung_record_put_delays_no_stint_and_no_stop",
        a_hung_record_put_delays_no_stint_and_no_stop,
    ),
    (
        "a_paused_runner_keeps_its_stored_record_fresh",
        a_paused_runner_keeps_its_stored_record_fresh,
    ),
    (
        "the_stopped_record_is_stored_after_the_final_snapshot_upload",
        the_stopped_record_is_stored_after_the_final_snapshot_upload,
    ),
    (
        "a_host_key_is_checked_before_its_read",
        a_host_key_is_checked_before_its_read,
    ),
    (
        "the_watch_reads_only_changed_roots_and_its_document_equals_a_full_read",
        the_watch_reads_only_changed_roots_and_its_document_equals_a_full_read,
    ),
    (
        "an_old_status_only_entry_refreshes_the_root_payload",
        an_old_status_only_entry_refreshes_the_root_payload,
    ),
    (
        "a_cache_that_cannot_be_read_or_written_reads_the_bucket",
        a_cache_that_cannot_be_read_or_written_reads_the_bucket,
    ),
    (
        "a_root_replaced_after_its_listing_enters_no_cache_entry",
        a_root_replaced_after_its_listing_enters_no_cache_entry,
    ),
    (
        "each_failure_identity_gets_one_record_created_once",
        each_failure_identity_gets_one_record_created_once,
    ),
    (
        "twenty_new_identities_are_recorded_within_two_cycles",
        twenty_new_identities_are_recorded_within_two_cycles,
    ),
    (
        "a_host_alert_opens_once_per_condition_and_survives_a_failed_cycle",
        a_host_alert_opens_once_per_condition_and_survives_a_failed_cycle,
    ),
    (
        "the_watch_writes_only_its_prefixes_and_one_watch_holds_a_state_directory",
        the_watch_writes_only_its_prefixes_and_one_watch_holds_a_state_directory,
    ),
    (
        "one_summary_is_created_per_utc_day",
        one_summary_is_created_per_utc_day,
    ),
    (
        "a_root_enters_the_cache_only_when_its_listing_agrees_with_the_bucket",
        a_root_enters_the_cache_only_when_its_listing_agrees_with_the_bucket,
    ),
    (
        "a_root_is_judged_at_the_reading_after_its_status_download",
        a_root_is_judged_at_the_reading_after_its_status_download,
    ),
    (
        "a_host_event_key_held_by_another_event_keeps_its_alerts_due",
        a_host_event_key_held_by_another_event_keeps_its_alerts_due,
    ),
    (
        "a_host_event_found_stored_with_its_bytes_counts_as_stored",
        a_host_event_found_stored_with_its_bytes_counts_as_stored,
    ),
    (
        "a_failed_event_put_keeps_the_closures_it_saw",
        a_failed_event_put_keeps_the_closures_it_saw,
    ),
    (
        "a_watch_whose_alert_saves_fail_keeps_its_open_set",
        a_watch_whose_alert_saves_fail_keeps_its_open_set,
    ),
    (
        "a_cycle_sweeps_staged_cache_files_before_its_reads",
        a_cycle_sweeps_staged_cache_files_before_its_reads,
    ),
    (
        "a_failed_record_or_summary_put_leaves_it_due",
        a_failed_record_or_summary_put_leaves_it_due,
    ),
    (
        "a_stop_ends_a_hung_watch_and_an_unusable_state_refuses_it",
        a_stop_ends_a_hung_watch_and_an_unusable_state_refuses_it,
    ),
    (
        "the_watch_starts_only_after_listing_its_known_identities",
        the_watch_starts_only_after_listing_its_known_identities,
    ),
    (
        "a_host_record_listed_empty_or_cut_at_the_bound_is_read_again",
        a_host_record_listed_empty_or_cut_at_the_bound_is_read_again,
    ),
    (
        "a_download_that_leaves_no_file_exits_3",
        a_download_that_leaves_no_file_exits_3,
    ),
    (
        "the_report_reads_the_clock_again_after_each_host_download",
        the_report_reads_the_clock_again_after_each_host_download,
    ),
    (
        "a_failing_stopped_record_put_leaves_the_last_running_record",
        a_failing_stopped_record_put_leaves_the_last_running_record,
    ),
    (
        "a_longer_stint_is_stored_before_the_longer_upload_period",
        a_longer_stint_is_stored_before_the_longer_upload_period,
    ),
    (
        "each_record_put_follows_its_save_and_a_raised_stint_is_stored_once_a_record_saves",
        each_record_put_follows_its_save_and_a_raised_stint_is_stored_once_a_record_saves,
    ),
    (
        "a_stop_after_failed_record_puts_stores_a_stopped_record_without_their_error",
        a_stop_after_failed_record_puts_stores_a_stopped_record_without_their_error,
    ),
    (
        "the_report_is_byte_equal_under_any_listing_order_and_builds_never_share_a_sum",
        the_report_is_byte_equal_under_any_listing_order_and_builds_never_share_a_sum,
    ),
    (
        "one_failure_seen_by_three_roots_is_listed_once_with_all_three",
        one_failure_seen_by_three_roots_is_listed_once_with_all_three,
    ),
    (
        "each_report_flag_sets_its_exit_code_and_a_missing_field_never_prints_zero",
        each_report_flag_sets_its_exit_code_and_a_missing_field_never_prints_zero,
    ),
    (
        "an_unreadable_bucket_exits_3_and_an_unreadable_object_flags_its_root",
        an_unreadable_bucket_exits_3_and_an_unreadable_object_flags_its_root,
    ),
    (
        "a_root_with_an_unprintable_name_is_flagged_and_named_in_no_bucket_call",
        a_root_with_an_unprintable_name_is_flagged_and_named_in_no_bucket_call,
    ),
    (
        "a_malformed_listing_exits_3_and_an_empty_bucket_exits_0",
        a_malformed_listing_exits_3_and_an_empty_bucket_exits_0,
    ),
    (
        "a_listing_past_its_object_bound_exits_3",
        a_listing_past_its_object_bound_exits_3,
    ),
    (
        "the_report_reads_again_an_object_its_listing_shows_empty_or_absent",
        the_report_reads_again_an_object_its_listing_shows_empty_or_absent,
    ),
    (
        "the_report_downloads_into_a_fresh_scratch_directory_it_removes",
        the_report_downloads_into_a_fresh_scratch_directory_it_removes,
    ),
    (
        "the_report_reads_its_clock_before_the_bucket",
        the_report_reads_its_clock_before_the_bucket,
    ),
    (
        "an_ignored_sigchld_leaves_the_reports_helpers_waitable",
        an_ignored_sigchld_leaves_the_reports_helpers_waitable,
    ),
    (
        "a_stop_signal_ends_the_report_with_no_document_and_no_scratch_directory",
        a_stop_signal_ends_the_report_with_no_document_and_no_scratch_directory,
    ),
    (
        "a_cut_after_the_commit_record_is_repaired_without_a_rebuild",
        a_cut_after_the_commit_record_is_repaired_without_a_rebuild,
    ),
    (
        "an_interrupted_archive_is_retried_and_a_malformed_head_publishes_nothing",
        an_interrupted_archive_is_retried_and_a_malformed_head_publishes_nothing,
    ),
    (
        "a_second_publisher_on_one_state_exits_at_once",
        a_second_publisher_on_one_state_exits_at_once,
    ),
    (
        "an_oversized_assignment_leaves_the_stored_copy_in_force",
        an_oversized_assignment_leaves_the_stored_copy_in_force,
    ),
    (
        "an_assignment_download_that_leaves_no_file_names_its_key_once",
        an_assignment_download_that_leaves_no_file_names_its_key_once,
    ),
    (
        "a_failed_fetch_waits_a_stint_and_stale_staging_is_removed",
        a_failed_fetch_waits_a_stint_and_stale_staging_is_removed,
    ),
    (
        "a_running_status_pairs_the_stint_with_its_work",
        a_running_status_pairs_the_stint_with_its_work,
    ),
    (
        "a_failed_status_put_leaves_no_receipt_and_is_retried",
        a_failed_status_put_leaves_no_receipt_and_is_retried,
    ),
    (
        "a_damaged_commit_record_is_fetched_again",
        a_damaged_commit_record_is_fetched_again,
    ),
    (
        "a_hung_store_delays_each_stint_by_the_document_wait_only",
        a_hung_store_delays_each_stint_by_the_document_wait_only,
    ),
    (
        "a_shortened_list_or_a_count_past_it_keeps_the_old_root",
        a_shortened_list_or_a_count_past_it_keeps_the_old_root,
    ),
    (
        "an_assignment_past_the_host_memory_blocks_the_stint",
        an_assignment_past_the_host_memory_blocks_the_stint,
    ),
    (
        "a_large_confirm_report_still_clears_pending",
        a_large_confirm_report_still_clears_pending,
    ),
    (
        "an_old_root_whose_stored_checksum_differs_stays",
        an_old_root_whose_stored_checksum_differs_stays,
    ),
    (
        "a_held_earlier_root_reaches_status",
        a_held_earlier_root_reaches_status,
    ),
    (
        "an_earlier_root_with_more_slots_waits_for_them",
        an_earlier_root_with_more_slots_waits_for_them,
    ),
    (
        "a_late_line_on_an_earlier_root_is_confirmed",
        a_late_line_on_an_earlier_root_is_confirmed,
    ),
    (
        "an_earlier_root_without_its_archive_records_a_failed_confirm",
        an_earlier_root_without_its_archive_records_a_failed_confirm,
    ),
    (
        "an_exited_confirm_keeps_its_outcome_at_shutdown",
        an_exited_confirm_keeps_its_outcome_at_shutdown,
    ),
    (
        "the_heartbeat_keeps_a_short_stint_fresh",
        the_heartbeat_keeps_a_short_stint_fresh,
    ),
    (
        "an_unreadable_list_or_cursor_starts_a_confirm",
        an_unreadable_list_or_cursor_starts_a_confirm,
    ),
    (
        "a_confirm_that_cannot_start_waits_and_the_sweep_continues",
        a_confirm_that_cannot_start_waits_and_the_sweep_continues,
    ),
    (
        "an_exhausted_stint_counter_starts_no_sweep",
        an_exhausted_stint_counter_starts_no_sweep,
    ),
    (
        "a_partition_or_free_space_fault_blocks_the_stint",
        a_partition_or_free_space_fault_blocks_the_stint,
    ),
    (
        "a_state_directory_under_a_shared_parent_is_refused",
        a_state_directory_under_a_shared_parent_is_refused,
    ),
];

const SIM_HOST: &str = env!("CARGO_BIN_EXE_sim-host");
const WAIT: Duration = Duration::from_secs(60);

struct Metadata {
    address: String,
    id: Arc<Mutex<Option<String>>>,
}

impl Metadata {
    fn serve(id: Option<&str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("its address").to_string();
        let id = Arc::new(Mutex::new(id.map(str::to_owned)));
        let served = Arc::clone(&id);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => request.push(byte[0]),
                        _ => break,
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let id = served.lock().expect("the id").clone();
                let token = request.starts_with("PUT /latest/api/token")
                    && request.contains("\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\n");
                let read = request.starts_with("GET /latest/meta-data/instance-id")
                    && request.contains("\r\nX-aws-ec2-metadata-token: a-token\r\n");
                let body = match (token, read, id) {
                    (true, _, _) => Some("a-token".to_owned()),
                    (false, true, Some(id)) => Some(id),
                    _ => None,
                };
                let reply = match body {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    ),
                    None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
                };
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        Self { address, id }
    }

    fn set(&self, id: &str) {
        *self.id.lock().expect("the id") = Some(id.to_owned());
    }
}

struct Running(Option<Child>);

impl Running {
    fn id(&self) -> u32 {
        self.0.as_ref().expect("a running child").id()
    }

    fn take(mut self) -> Child {
        self.0.take().expect("a running child")
    }

    fn kill(self) {
        let mut child = self.take();
        child.kill().expect("the runner is killed");
        child.wait().expect("the killed runner is reaped");
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Case {
    dir: PathBuf,
    metadata: Metadata,
    disk_reserve: u64,
    slots: u64,
    system_cores: u64,
}

fn complete_entries(text: &str) -> Vec<Value> {
    let complete = text.rfind('\n').map_or("", |end| &text[..end]);
    complete
        .lines()
        .map(|line| serde_json::from_str(line).expect("a log entry"))
        .collect()
}

/// The cases' base directory, with no symlinked component, since the
/// runner and the publisher refuse a state path through a symlink.
fn scratch() -> PathBuf {
    fs::canonicalize(env!("CARGO_TARGET_TMPDIR"))
        .expect("the target's temporary directory")
        .join("sim-host")
}

impl Case {
    fn new(name: &str) -> Self {
        let dir = scratch().join(name);
        if dir.exists() {
            let _ = Command::new("chmod")
                .arg("-R")
                .arg("u+rwx")
                .arg(&dir)
                .status();
            fs::remove_dir_all(&dir).expect("an earlier case directory is removed");
        }
        fs::create_dir_all(dir.join("bin")).expect("the case directory");
        fs::create_dir_all(dir.join("bucket")).expect("the bucket");
        fs::create_dir_all(dir.join("tmp")).expect("the temporary directory");
        for name in ["aws", "git", "cargo"] {
            std::os::unix::fs::symlink(
                std::env::current_exe().expect("this executable"),
                dir.join("bin").join(name),
            )
            .expect("a fake's link");
        }
        let cgroup = dir.join("cgroup");
        make_cgroup(&cgroup);
        Self {
            dir,
            metadata: Metadata::serve(Some("i-0000000a")),
            disk_reserve: 0,
            slots: 1,
            system_cores: 0,
        }
    }

    fn archive(&self, build: &str) -> PathBuf {
        sim_host::build::archive(&self.state(), build)
    }

    fn state(&self) -> PathBuf {
        self.dir.join("state")
    }

    fn bucket(&self) -> PathBuf {
        self.dir.join("bucket")
    }

    fn object(&self, key: &str) -> Option<Vec<u8>> {
        fs::read(self.bucket().join(key)).ok()
    }

    fn put(&self, key: &str, bytes: &[u8]) {
        let path = self.bucket().join(key);
        let checksum = fake::checksum_path(&self.bucket(), key);
        for path in [&path, &checksum] {
            fs::create_dir_all(path.parent().expect("a prefix")).expect("the prefix");
        }
        fs::write(&path, bytes).expect("an object");
        fs::write(checksum, fake::digest64(bytes)).expect("its checksum");
    }

    fn archive_tar(&self, content: &str, worker: &str) -> Vec<u8> {
        let source = self.dir.join("sources").join(sim_host::file::sha256(
            format!("{content}/{worker}").as_bytes(),
        ));
        let _ = fs::remove_dir_all(&source);
        fs::create_dir_all(source.join("archive")).expect("the archive directory");
        fs::set_permissions(source.join("archive"), fs::Permissions::from_mode(0o700))
            .expect("its mode");
        fs::write(source.join("archive/build"), content).expect("the build record");
        fs::write(source.join("archive/worker"), worker).expect("the worker");
        let tarball = source.join("archive.tar");
        let status = Command::new("tar")
            .arg("-cf")
            .arg(&tarball)
            .arg("-C")
            .arg(&source)
            .arg("archive")
            .status()
            .expect("tar runs");
        assert!(status.success(), "the archive is packed");
        fs::read(tarball).expect("the tar")
    }

    fn build(&self, content: &str) -> String {
        let build = sim_host::file::sha256(content.as_bytes());
        let tar = self.archive_tar(content, "worker");
        self.put(&format!("builds/{build}/archive.tar"), &tar);
        self.put(&format!("builds/{build}/campaign"), executable());
        build
    }

    fn install(&self, content: &str) -> String {
        let build = sim_host::file::sha256(content.as_bytes());
        let state = self.state();
        let archive = sim_host::build::archive(&state, &build);
        sim_host::file::private_dir(&archive).expect("the archive directory");
        fs::write(archive.join("build"), content).expect("the build record");
        fs::write(archive.join("worker"), "worker").expect("the worker");
        let program = sim_host::build::campaign(&state, &build);
        fs::write(&program, executable()).expect("the binary");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("its mode");
        fs::write(
            sim_host::build::record(&state, &build),
            commit(&build).to_string(),
        )
        .expect("the commit record");
        build
    }

    fn script(&self, name: &str, values: &str) {
        fs::write(self.dir.join(name), values).expect("a script file");
    }

    fn assignment(build: &str, profiles: &[&str], stint: u64) -> Value {
        json!({
            "format": 1, "name": "sim", "build": build, "profiles": profiles,
            "counts": {"watchdog": 900}, "batch": 30, "wall": 600,
            "memory": 1 << 20, "processes": 64, "stint": stint,
        })
    }

    fn write_assignment(&self, assignment: &Value) {
        let mut document = assignment.clone();
        let build = document
            .as_object_mut()
            .expect("an object")
            .remove("build")
            .expect("a build");
        self.put("assignment.json", document.to_string().as_bytes());
        self.put(
            "current.json",
            commit(build.as_str().expect("a build"))
                .to_string()
                .as_bytes(),
        );
    }

    fn damage_assignment(&self) {
        self.put("assignment.json", b"{");
    }

    fn assign(&self, build: &str, profiles: &[&str], stint: u64) {
        self.write_assignment(&Self::assignment(build, profiles, stint));
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(SIM_HOST);
        command
            .args(args)
            .env(fake::CASE, &self.dir)
            .env("TMPDIR", self.dir.join("tmp"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.dir.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env(sim_host::instance::METADATA, &self.metadata.address)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run_command(&self) -> Command {
        self.run_command_at(&self.state(), &self.dir.join("cgroup"))
    }

    fn run_command_at(&self, state: &Path, cgroup: &Path) -> Command {
        let reserve = self.disk_reserve.to_string();
        let slots = self.slots.to_string();
        let cores = self.system_cores.to_string();
        let args = [
            "run",
            "--state",
            state.to_str().expect("a text path"),
            "--bucket",
            "sims",
            "--cgroup",
            cgroup.to_str().expect("a text path"),
            "--confirm-slots",
            &slots,
            "--system-cores",
            &cores,
            "--disk-reserve",
            &reserve,
            "--system-memory",
            "0",
        ];
        self.command(&args)
    }

    fn start(&self) -> Running {
        Running(Some(self.run_command().spawn().expect("sim-host starts")))
    }

    fn start_at(&self, state: &Path, cgroup: &Path, metadata: &Metadata) -> Running {
        let mut command = self.run_command_at(state, cgroup);
        command.env(sim_host::instance::METADATA, &metadata.address);
        Running(Some(command.spawn().expect("sim-host starts")))
    }

    /// The complete lines of the case's log. A last line without its
    /// newline is one a fake is still writing, so it is left out.
    fn log(&self) -> Vec<Value> {
        complete_entries(&fs::read_to_string(self.dir.join("log")).unwrap_or_default())
    }

    fn events(&self, command: &str, event: &str) -> Vec<Value> {
        self.log()
            .into_iter()
            .filter(|entry| entry["command"] == command && entry["event"] == event)
            .collect()
    }

    fn wait_for(&self, what: &str, done: impl Fn(&Self) -> bool) {
        let until = Instant::now() + WAIT;
        while !done(self) {
            assert!(
                Instant::now() < until,
                "timed out waiting for {what}: {:#?}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn health(&self) -> Value {
        read_json(&self.state().join("health.json"))
    }

    fn health_now(&self) -> Value {
        read_lenient(&self.state().join("health.json"))
    }

    fn runner_state(&self) -> Value {
        read_json(&self.state().join("state.json"))
    }

    fn current(&self) -> Value {
        let state = read_lenient(&self.state().join("state.json"));
        state["current"]
            .as_str()
            .map_or(Value::Null, |current| state["roots"][current].clone())
    }

    fn roots(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.state().join("roots"))
            .expect("the roots directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .into_string()
                    .expect("a name")
            })
            .collect();
        names.sort();
        names
    }

    fn status(&self) -> (Option<i32>, Value) {
        let output = self
            .command(&[
                "status",
                "--state",
                self.state().to_str().expect("a text path"),
            ])
            .output()
            .expect("status runs");
        let report = serde_json::from_slice(&output.stdout).expect("a report");
        (output.status.code(), report)
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("the record reads")).expect("the record parses")
}

fn executable() -> &'static [u8] {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES.get_or_init(|| {
        fs::read(std::env::current_exe().expect("this executable")).expect("it reads")
    })
}

fn commit(build: &str) -> Value {
    json!({"format": 1, "commit": &build[..40], "build": build,
           "campaign": sim_host::file::sha256(executable())})
}

fn make_cgroup(dir: &Path) {
    for group in ["runner", "confirm"] {
        fs::create_dir_all(dir.join(group)).expect("the cgroup tree");
    }
    fs::write(dir.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
    for file in [
        "cgroup.subtree_control",
        "cgroup.procs",
        "runner/cgroup.procs",
        "confirm/cgroup.subtree_control",
    ] {
        fs::write(dir.join(file), "").expect("a control file");
    }
}

fn read_lenient(path: &Path) -> Value {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null)
}

fn signal(child: &Running, signal: libc::c_int) {
    let pid = libc::pid_t::try_from(child.id()).expect("a pid");
    // SAFETY: the child has not been waited for, so `pid` names it.
    assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
}

fn exited(mut running: Running) -> (Output, u64) {
    let until = Instant::now() + WAIT;
    loop {
        let child = running.0.as_mut().expect("a running child");
        if child.try_wait().expect("the runner's status").is_some() {
            break;
        }
        assert!(Instant::now() < until, "the runner did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
    let seen = fake::now_ms();
    let output = running
        .take()
        .wait_with_output()
        .expect("the runner's output");
    (output, seen)
}

fn ended(running: Running, signal_number: libc::c_int) -> (Output, u64) {
    signal(&running, signal_number);
    exited(running)
}

fn stop(running: Running) -> Output {
    let (output, _) = ended(running, libc::SIGTERM);
    assert!(
        output.status.success(),
        "the runner stops cleanly: {output:?}"
    );
    output
}

fn arg(entry: &Value, flag: &str) -> String {
    let args = entry["args"].as_array().expect("the args");
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .unwrap_or_else(|| panic!("{flag} in {args:?}"));
    args[index + 1].as_str().expect("a text arg").to_owned()
}

fn args_of(entry: &Value, flag: &str) -> Vec<String> {
    let args = entry["args"].as_array().expect("the args");
    args.windows(2)
        .filter(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str().expect("a text arg").to_owned())
        .collect()
}

fn time(entry: &Value) -> u64 {
    entry["t"].as_u64().expect("a time")
}

fn codes(entries: &[Value]) -> Vec<u64> {
    entries
        .iter()
        .map(|entry| entry["code"].as_u64().expect("a code"))
        .collect()
}

fn campaigns(entries: &[Value]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| arg(entry, "--campaign"))
        .collect()
}

fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).expect("a listing") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push((path.clone(), fs::read(&path).expect("a file")));
            }
        }
    }
    files.sort();
    files
}

fn all_children_ended(case: &Case) -> bool {
    ["sweep", "confirm"]
        .iter()
        .all(|command| case.events(command, "exit").len() == case.events(command, "start").len())
}

fn stints_a_kill_and_a_restart_keep_one_root() {
    let case = Case::new("kill");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("two stints", |case| case.events("sweep", "exit").len() >= 2);
    runner.kill();
    let before = case.events("sweep", "start").len();
    case.wait_for("the orphaned sweep to end", all_children_ended);
    let runner = case.start();
    case.wait_for("a stint after the restart", |case| {
        case.events("sweep", "exit").len() > before
    });
    stop(runner);
    let campaigns = campaigns(&case.events("sweep", "start"));
    assert!(campaigns.len() >= 3, "{campaigns:?}");
    assert!(
        campaigns.iter().all(|campaign| *campaign == campaigns[0]),
        "{campaigns:?}"
    );
    assert_eq!(case.roots(), [campaigns[0].clone()]);
    let state = case.runner_state();
    assert_eq!(state["roots"].as_object().expect("roots").len(), 1);
    assert!(
        state["roots"][&campaigns[0]]["stints"]
            .as_u64()
            .expect("stints")
            >= 3
    );
}

fn a_killed_runner_stops_its_running_sweep() {
    let case = Case::new("death");
    let build = case.build("one");
    case.assign(&build, &["a"], 30);
    let runner = case.start();
    case.wait_for("a running sweep", |case| {
        !case.events("sweep", "start").is_empty()
    });
    let killed = fake::now_ms();
    runner.kill();
    case.wait_for("the sweep to end", |case| {
        !case.events("sweep", "exit").is_empty()
    });
    let exit = &case.events("sweep", "exit")[0];
    assert_eq!(exit["terminated"], true, "the sweep got the death signal");
    assert!(time(exit) - killed < 5_000, "{exit}");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint after the restart", |case| {
        case.events("sweep", "exit").len() >= 2
    });
    stop(runner);
    let campaigns = campaigns(&case.events("sweep", "start"));
    assert!(campaigns.iter().all(|campaign| *campaign == campaigns[0]));
}

fn a_second_runner_on_one_state_exits_at_once() {
    let case = Case::new("second");
    let build = case.build("one");
    case.assign(&build, &["a"], 30);
    let first = case.start();
    case.wait_for("the first stint in state.json", |case| {
        case.current()["stints"] == 1 && case.health_now()["phase"] == "sweeping"
    });
    let state = fs::read(case.state().join("state.json")).expect("the state");
    let output = case.run_command().output().expect("the second runner ends");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("another runner"));
    assert_eq!(
        fs::read(case.state().join("state.json")).expect("the state"),
        state
    );
    assert_eq!(case.events("sweep", "start").len(), 1);
    assert!(case.events("confirm", "start").is_empty());
    let first_pid = u64::from(first.id());
    stop(first);
    assert!(
        case.log()
            .iter()
            .filter(|entry| entry["event"] == "start")
            .all(|entry| entry["parent"] == first_pid)
    );
}

fn another_instance_id_opens_a_new_root_and_leaves_the_old_one() {
    let case = Case::new("instance");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "2");
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    stop(runner);
    let old = case.roots();
    assert_eq!(old.len(), 1);
    assert!(old[0].starts_with("sim.i-0000000a."), "{old:?}");
    let before = snapshot(&case.state().join("roots").join(&old[0]));
    case.metadata.set("i-0000000b");
    let starts = case.events("sweep", "start").len();
    let runner = case.start();
    case.wait_for("a stint under the new id", |case| {
        case.events("sweep", "exit").len() > starts
    });
    stop(runner);
    let roots = case.roots();
    assert_eq!(roots.len(), 2, "{roots:?}");
    let new: Vec<&String> = roots.iter().filter(|root| **root != old[0]).collect();
    assert!(new[0].starts_with("sim.i-0000000b."), "{roots:?}");
    let after = snapshot(&case.state().join("roots").join(&old[0]));
    assert_eq!(before, after, "the old root is unchanged");
    let latest = case.events("sweep", "start");
    assert_eq!(arg(latest.last().expect("a start"), "--campaign"), *new[0]);
}

fn a_foreign_root_gets_no_confirm_without_an_assignment() {
    let case = Case::new("foreign");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "2");
    case.script("confirm.codes", "3");
    case.script("confirm.ms", "60000");
    let runner = case.start();
    case.wait_for("a running confirm", |case| {
        !case.events("confirm", "start").is_empty()
    });
    stop(runner);
    let old = case.roots();
    case.damage_assignment();
    fs::remove_dir_all(case.state().join("assignments")).expect("the stored copies");
    let mut state = case.runner_state();
    state["roots"][&old[0]]["alarm"] = json!(true);
    sim_host::file::replace(
        &case.state().join("state.json"),
        state.to_string().as_bytes(),
    )
    .expect("an alarmed foreign root");
    let before = snapshot(&case.state().join("roots").join(&old[0]));
    case.metadata.set("i-0000000b");
    let confirms = case.events("confirm", "start").len();
    let runner = case.start();
    case.wait_for("the blocked phase", |case| {
        case.health_now()["phase"] == "blocked"
    });
    std::thread::sleep(Duration::from_millis(2_500));
    let health = case.health();
    let (_, report) = case.status();
    stop(runner);
    assert_eq!(case.events("confirm", "start").len(), confirms);
    assert_eq!(case.roots(), old);
    assert_eq!(snapshot(&case.state().join("roots").join(&old[0])), before);
    for field in [
        "root",
        "build",
        "stint",
        "alarm",
        "confirmation",
        "cpu_usec",
    ] {
        assert!(health[field].is_null(), "{field}: {health:#}");
    }
    assert_eq!(health["instance"], "i-0000000b");
    assert!(
        !report["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("alarm")),
        "{report:#}"
    );
}

fn a_changed_build_opens_a_new_root() {
    let case = Case::new("build");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    case.assign(&second, &["a"], 1);
    case.wait_for("a stint of the second build", |case| {
        case.events("sweep", "start")
            .iter()
            .any(|entry| arg(entry, "--archive").contains(&second))
    });
    stop(runner);
    let starts = case.events("sweep", "start");
    let old = arg(&starts[0], "--campaign");
    let new = arg(starts.last().expect("a start"), "--campaign");
    assert_ne!(old, new);
    let state = case.runner_state();
    assert_eq!(state["roots"][&new]["build"], second);
    assert_eq!(state["current"], new);
    assert!(case.roots().contains(&new));
    if case.roots().contains(&old) {
        assert_eq!(state["roots"][&old]["build"], first);
    }
}

fn changed_counts_or_name_open_a_new_root() {
    let case = Case::new("binding");
    let build = case.build("one");
    let mut assignment = Case::assignment(&build, &["a"], 1);
    case.write_assignment(&assignment);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    let first = campaigns(&case.events("sweep", "start"))[0].clone();
    assignment["counts"]["watchdog"] = json!(901);
    case.write_assignment(&assignment);
    case.wait_for("a stint of the new counts", |case| {
        case.events("sweep", "start")
            .iter()
            .any(|entry| args_of(entry, "--set") == ["watchdog=901"])
    });
    let before = snapshot(&case.state().join("roots").join(&first));
    assignment["name"] = json!("other");
    case.write_assignment(&assignment);
    case.wait_for("a stint of the new name", |case| {
        case.events("sweep", "start")
            .iter()
            .any(|entry| arg(entry, "--campaign").starts_with("other."))
    });
    stop(runner);
    let starts = case.events("sweep", "start");
    let counted = starts
        .iter()
        .find(|entry| args_of(entry, "--set") == ["watchdog=901"])
        .map(|entry| arg(entry, "--campaign"))
        .expect("a sweep of the new counts");
    let named = arg(starts.last().expect("a start"), "--campaign");
    assert_ne!(counted, first);
    assert_ne!(named, counted);
    assert!(named.starts_with("other.i-0000000a."), "{named}");
    let state = case.runner_state();
    assert_eq!(state["roots"][&counted]["counts"]["watchdog"], 901);
    assert_eq!(state["roots"][&named]["name"], "other");
    assert_eq!(case.roots().len(), 3);
    assert_eq!(snapshot(&case.state().join("roots").join(&first)), before);
}

fn a_changed_confirm_slot_count_opens_a_new_root() {
    let online = sim_host::host::online_cpus();
    assert!(online >= 4, "the case needs four CPUs");
    let mut case = Case::new("slots");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    stop(runner);
    case.slots = 2;
    let starts = case.events("sweep", "start").len();
    let runner = case.start();
    case.wait_for("a stint with two slots", |case| {
        case.events("sweep", "exit").len() > starts
    });
    stop(runner);
    let starts = case.events("sweep", "start");
    let first = arg(&starts[0], "--campaign");
    let last = starts.last().expect("a start");
    assert_ne!(arg(last, "--campaign"), first);
    assert_eq!(arg(last, "--workers"), (online - 3).to_string());
    let state = case.runner_state();
    assert_eq!(state["roots"][&first]["confirm_slots"], 1);
    assert_eq!(state["roots"][&arg(last, "--campaign")]["confirm_slots"], 2);
}

fn a_replaced_assignment_changes_the_next_stint_only() {
    let case = Case::new("replaced");
    let build = case.build("one");
    case.assign(&build, &["a", "a", "b"], 2);
    case.script("sweep.suspects", "1");
    let runner = case.start();
    let pid = runner.id();
    case.wait_for("the first stint", |case| {
        !case.events("sweep", "start").is_empty()
    });
    case.assign(&build, &["c"], 2);
    case.wait_for("the second stint and a confirm", |case| {
        case.events("sweep", "start").len() >= 2 && !case.events("confirm", "start").is_empty()
    });
    stop(runner);
    let starts = case.events("sweep", "start");
    let exits = case.events("sweep", "exit");
    assert_eq!(arg(&starts[0], "--profiles"), "a,a,b");
    assert_eq!(arg(&starts[1], "--profiles"), "c");
    let campaign = arg(&starts[0], "--campaign");
    assert_eq!(arg(&starts[1], "--campaign"), campaign);
    assert_eq!(exits[0]["terminated"], false);
    assert!(
        time(&exits[0]) - time(&starts[0]) >= 2_000,
        "the first stint ran its length"
    );
    let state = case.state();
    let cgroup = case.dir.join("cgroup");
    let archive = sim_host::build::archive(&state, &build);
    let root = state.join("roots").join(&campaign);
    let text = |path: &Path| path.to_str().expect("a text path").to_owned();
    let online = sim_host::host::online_cpus();
    for (flag, value) in [
        ("--root", text(&root)),
        ("--archive", text(&archive)),
        ("--workers", (online - 2).to_string()),
        ("--batch", "30".into()),
        ("--wall", "600".into()),
        ("--for", "2".into()),
        ("--memory", (1u64 << 20).to_string()),
        ("--processes", "64".into()),
        ("--cgroup-root", text(&cgroup.join("campaign"))),
    ] {
        assert_eq!(arg(&starts[0], flag), value, "{flag}");
    }
    assert_eq!(args_of(&starts[0], "--set"), ["watchdog=900"]);
    let confirm = &case.events("confirm", "start")[0];
    let nonce = campaign.rsplit('.').next().expect("a nonce");
    for (flag, value) in [
        ("--root", text(&root)),
        ("--archive", text(&archive)),
        ("--slots", "1".into()),
        ("--cgroup-root", text(&cgroup.join("confirm").join(nonce))),
    ] {
        assert_eq!(arg(confirm, flag), value, "{flag}");
    }
    assert_eq!(
        fs::read_to_string(cgroup.join("runner/cgroup.procs")).expect("procs"),
        pid.to_string()
    );
    for parent in [cgroup.clone(), cgroup.join("confirm")] {
        assert_eq!(
            fs::read_to_string(parent.join("cgroup.subtree_control")).expect("control"),
            "+cpu +memory +pids"
        );
    }
    let copy = fs::read(stored_copy(&case)).expect("the stored copy");
    assert_eq!(
        json!(sim_host::file::sha256(&copy)),
        case.runner_state()["assignment"]
    );
    assert!(String::from_utf8_lossy(&copy).contains("\"c\""));
}

fn an_unreadable_assignment_leaves_the_stored_copy_in_force() {
    let case = Case::new("unreadable");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    case.damage_assignment();
    let starts = case.events("sweep", "start").len();
    case.wait_for("a stint from the copy", |case| {
        case.events("sweep", "start").len() > starts + 1
    });
    let health = case.health();
    stop(runner);
    assert!(
        health["assignment_error"]
            .as_str()
            .is_some_and(|error| error.contains("assignment")),
        "{health:#}"
    );
    let starts = case.events("sweep", "start").len();
    let runner = case.start();
    case.wait_for("a stint from the copy after a restart", |case| {
        let health = case.health_now();
        case.events("sweep", "start").len() > starts
            && health["phase"] == "sweeping"
            && health["assignment_error"].is_string()
    });
    let digest = case.runner_state()["assignment"].clone();
    let mut rooted = Case::assignment(&build, &["r"], 1);
    rooted["counts"] = json!({"root": 1});
    case.write_assignment(&rooted);
    case.wait_for("the refused root count", |case| {
        case.health_now()["assignment_error"]
            .as_str()
            .is_some_and(|error| error.contains("\"root\""))
    });
    let refused = case.events("sweep", "start").len();
    case.wait_for("a stint from the copy", |case| {
        case.events("sweep", "start").len() > refused
    });
    assert_eq!(case.runner_state()["assignment"], digest);
    case.assign(&build, &["c"], 1);
    case.wait_for("a stint of the repaired assignment", |case| {
        case.events("sweep", "start")
            .iter()
            .any(|entry| arg(entry, "--profiles") == "c")
    });
    case.wait_for("the error to clear", |case| {
        case.health_now()["assignment_error"].is_null()
    });
    stop(runner);
    let sweeps = case.events("sweep", "start");
    let profiles: Vec<String> = sweeps
        .iter()
        .map(|entry| arg(entry, "--profiles"))
        .collect();
    assert!(
        profiles.iter().all(|profile| profile != "r"),
        "{profiles:?}"
    );
    assert!(profiles[..=refused].iter().all(|profile| profile == "a"));
    assert!(
        sweeps[..=refused]
            .iter()
            .all(|entry| args_of(entry, "--set") == ["watchdog=900"])
    );
}

fn stored_copy(case: &Case) -> PathBuf {
    let digest = case.runner_state()["assignment"]
        .as_str()
        .expect("a digest")
        .to_owned();
    case.state()
        .join("assignments")
        .join(format!("{digest}.json"))
}

fn a_lost_or_altered_copy_is_rewritten_from_the_source() {
    let case = Case::new("copy");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    stop(runner);
    let copy = stored_copy(&case);
    let digest = case.runner_state()["assignment"].clone();
    for damage in ["remove", "alter"] {
        if damage == "remove" {
            fs::remove_file(&copy).expect("the copy is removed");
        } else {
            fs::write(&copy, "{}").expect("the copy is altered");
        }
        let starts = case.events("sweep", "start").len();
        let runner = case.start();
        case.wait_for("a stint", |case| {
            case.events("sweep", "start").len() > starts
        });
        stop(runner);
        let bytes = fs::read(&copy).expect("the copy");
        assert_eq!(json!(sim_host::file::sha256(&bytes)), digest, "{damage}");
    }
    case.damage_assignment();
    fs::write(&copy, "{}").expect("the copy is altered");
    let starts = case.events("sweep", "start").len();
    let mut runner = case.start();
    case.wait_for("the blocked phase", |case| {
        case.health_now()["phase"] == "blocked"
    });
    std::thread::sleep(Duration::from_millis(1_500));
    let child = runner.0.as_mut().expect("a runner");
    assert!(
        child.try_wait().expect("a status").is_none(),
        "the runner keeps running"
    );
    stop(runner);
    assert_eq!(case.events("sweep", "start").len(), starts);
}

fn an_unrecorded_copy_leaves_the_recorded_assignment_in_force() {
    let case = Case::new("unrecorded");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    stop(runner);
    let recorded = Case::assignment(&build, &["a"], 1);
    let mut document = Case::assignment(&build, &["b"], 1);
    document.as_object_mut().expect("an object").remove("build");
    let next = json!({"document": document, "commit": commit(&build)}).to_string();
    let digest = sim_host::file::sha256(next.as_bytes());
    fs::write(
        case.state()
            .join("assignments")
            .join(format!("{digest}.json")),
        &next,
    )
    .expect("a copy that state.json does not name");
    case.damage_assignment();
    let starts = case.events("sweep", "start").len();
    let runner = case.start();
    case.wait_for("a stint", |case| {
        case.events("sweep", "start").len() > starts
    });
    stop(runner);
    case.write_assignment(&recorded);
    let resumed = case.events("sweep", "start").len();
    let runner = case.start();
    case.wait_for("a stint", |case| {
        case.events("sweep", "start").len() > resumed
    });
    stop(runner);
    let starts = case.events("sweep", "start");
    assert!(starts.iter().all(|entry| arg(entry, "--profiles") == "a"));
    let campaigns = campaigns(&starts);
    assert!(campaigns.iter().all(|campaign| *campaign == campaigns[0]));
}

fn a_missing_or_other_archive_blocks_the_stint() {
    let case = Case::new("archive");
    let first = case.build("one");
    case.assign(&first, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    let resumed = case.runner_state()["current"].clone();
    let build = sim_host::file::sha256(b"absent");
    case.assign(&build, &["a"], 1);
    let fetch_error = |case: &Case, text: &str| {
        case.health_now()["fetch_error"]
            .as_str()
            .is_some_and(|error| error.contains(text))
    };
    case.wait_for("the missing archive", |case| {
        fetch_error(case, "the object is missing")
    });
    case.put(
        &format!("builds/{build}/archive.tar"),
        &case.archive_tar("other", "worker"),
    );
    case.put(&format!("builds/{build}/campaign"), executable());
    case.wait_for("the other archive", |case| {
        fetch_error(case, &format!("is not build {build}"))
    });
    let state = case.runner_state();
    assert_eq!(state["current"], resumed, "a refused build keeps the root");
    assert_eq!(state["roots"].as_object().expect("roots").len(), 1);
    assert!(
        case.events("sweep", "start")
            .iter()
            .all(|entry| !arg(entry, "--archive").contains(&build))
    );
    assert!(
        !sim_host::build::dir(&case.state(), &build).exists(),
        "a refused download leaves no final directory"
    );
    let sweeps = case.events("sweep", "start").len();
    case.put(
        &format!("builds/{build}/archive.tar"),
        &case.archive_tar("absent", "worker"),
    );
    case.wait_for("a sweep of the placed archive", |case| {
        case.events("sweep", "start")
            .iter()
            .any(|entry| arg(entry, "--archive").contains(&build))
    });
    stop(runner);
    let campaigns = campaigns(&case.events("sweep", "start"));
    assert_eq!(json!(campaigns[sweeps - 1]), resumed);
    assert_eq!(
        case.runner_state()["roots"]
            .as_object()
            .expect("roots")
            .len(),
        2
    );
}

fn each_sweep_exit_sets_the_next_step_and_failures_wait() {
    let case = Case::new("exits");
    let build = case.build("one");
    case.assign(&build, &["a"], 4);
    case.script("sweep.codes", "0 1 2 3 4 0");
    let runner = case.start();
    case.wait_for("six sweeps", |case| case.events("sweep", "exit").len() >= 6);
    stop(runner);
    let starts = case.events("sweep", "start");
    let exits = case.events("sweep", "exit");
    let codes = codes(&exits);
    assert_eq!(codes[..6], [0, 1, 2, 3, 4, 0]);
    for index in 0..5 {
        let gap = time(&starts[index + 1]) - time(&exits[index]);
        if codes[index] >= 2 {
            assert!(
                gap >= 4_000,
                "sweep {index} exited {} and the next started {gap} ms later",
                codes[index]
            );
        } else {
            assert!(
                gap < 2_000,
                "sweep {index} exited {} and the next waited {gap} ms",
                codes[index]
            );
        }
    }
    let campaigns = campaigns(&starts);
    assert!(
        campaigns[..5]
            .iter()
            .all(|campaign| *campaign == campaigns[0])
    );
    assert_ne!(
        campaigns[5], campaigns[0],
        "three failed stints open a new root"
    );
    assert_eq!(arg(&starts[5], "--archive"), arg(&starts[0], "--archive"));
    let state = case.runner_state();
    assert_eq!(state["roots"][&campaigns[0]]["failures"], 3);
    assert_eq!(state["roots"][&campaigns[0]]["alarm"], true);
}

fn a_completed_sweep_resets_the_failure_count() {
    for (name, script) in [("reset-0", "2 3 0 4 0"), ("reset-1", "2 3 1 4 1")] {
        let case = Case::new(name);
        let build = case.build("one");
        case.assign(&build, &["a"], 1);
        case.script("sweep.codes", script);
        let runner = case.start();
        case.wait_for("five sweeps", |case| {
            case.events("sweep", "exit").len() >= 5
        });
        stop(runner);
        let campaigns = campaigns(&case.events("sweep", "start"));
        assert!(
            campaigns[..5]
                .iter()
                .all(|campaign| *campaign == campaigns[0]),
            "{script}: {campaigns:?}"
        );
        assert_eq!(
            case.runner_state()["roots"][&campaigns[0]]["failures"],
            0,
            "{script}"
        );
    }
}

fn a_sweep_that_cannot_start_waits_before_its_retry() {
    let case = Case::new("no-start");
    let build = case.install("one");
    case.assign(&build, &["a"], 2);
    let program = sim_host::build::campaign(&case.state(), &build);
    fs::set_permissions(&program, fs::Permissions::from_mode(0o644)).expect("no execute bit");
    let runner = case.start();
    case.wait_for("the failed start", |case| {
        let health = case.health_now();
        health["phase"] == "waiting"
            && health["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("did not start"))
    });
    let restored = fake::now_ms();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("the execute bit");
    case.wait_for("the retry", |case| {
        !case.events("sweep", "start").is_empty()
    });
    stop(runner);
    let start = time(&case.events("sweep", "start")[0]);
    assert!(
        start - restored >= 1_500,
        "the retry came {} ms after the fake returned",
        start - restored
    );
}

fn a_sweep_that_cannot_start_publishes_no_stint_share() {
    let case = Case::new("no-start-share");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.cpu", "5000000");
    let runner = case.start();
    case.wait_for("a measured stint", |case| {
        case.health_now()["share_stint"] == 1
    });
    let program = sim_host::build::campaign(&case.state(), &build);
    fs::set_permissions(&program, fs::Permissions::from_mode(0o644)).expect("no execute bit");
    case.wait_for("the failed start", |case| {
        let health = case.health_now();
        health["phase"] == "waiting"
            && health["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("did not start"))
    });
    let health = case.health();
    stop(runner);
    assert!(health["share_stint"].is_null(), "{health:#}");
    assert!(health["stint_cpu_usec"].is_null(), "{health:#}");
}

fn a_restart_keeps_the_wait_after_a_failed_sweep() {
    let case = Case::new("restart-wait");
    let build = case.build("one");
    case.assign(&build, &["a"], 4);
    case.script("sweep.codes", "4 0");
    let runner = case.start();
    case.wait_for("a recorded failure", |case| {
        case.current()["retry"]["until_ms"]
            .as_u64()
            .is_some_and(|until| until > 0)
    });
    runner.kill();
    let runner = case.start();
    case.wait_for("the retry", |case| case.events("sweep", "start").len() >= 2);
    stop(runner);
    let starts = case.events("sweep", "start");
    let exits = case.events("sweep", "exit");
    let gap = time(&starts[1]) - time(&exits[0]);
    assert!(
        gap >= 4_000,
        "the retry after a restart came {gap} ms after the failure"
    );
}

fn a_restart_after_the_third_failure_keeps_the_wait() {
    let case = Case::new("third-wait");
    let build = case.build("one");
    case.assign(&build, &["a"], 3);
    case.script("sweep.codes", "2 2 2 0");
    let runner = case.start();
    case.wait_for("the third recorded failure", |case| {
        case.current()["failures"] == 3
    });
    runner.kill();
    let runner = case.start();
    case.wait_for("the sweep of a new root", |case| {
        case.events("sweep", "start").len() >= 4
    });
    stop(runner);
    let starts = case.events("sweep", "start");
    let exits = case.events("sweep", "exit");
    let campaigns = campaigns(&starts);
    assert_ne!(campaigns[3], campaigns[0]);
    let gap = time(&starts[3]) - time(&exits[2]);
    assert!(
        gap >= 3_000,
        "the new root's sweep came {gap} ms after the failure"
    );
}

fn an_alarmed_sweep_keeps_sweeping_and_sets_the_alarm() {
    let case = Case::new("alarm");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.codes", "1 1 0");
    let runner = case.start();
    case.wait_for("two sweeps", |case| case.events("sweep", "exit").len() >= 2);
    let health = case.health();
    let (code, report) = case.status();
    assert_eq!(health["alarm"], true, "{health:#}");
    assert_eq!(code, Some(2), "{report:#}");
    assert!(
        report["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("alarm")),
        "{report:#}"
    );
    case.wait_for("a completed sweep to clear the alarm", |case| {
        case.events("sweep", "exit").len() >= 3 && case.health_now()["alarm"] == false
    });
    stop(runner);
}

fn a_replaced_root_keeps_its_alarm_and_the_record_follows_the_new_root() {
    let case = Case::new("alarm-replaced");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.codes", "1 2 2 2 0");
    let runner = case.start();
    case.wait_for("a completed sweep of the new root", |case| {
        case.events("sweep", "exit").len() >= 5 && case.health_now()["alarm"] == false
    });
    stop(runner);
    let old = campaigns(&case.events("sweep", "start"))[0].clone();
    let state = case.runner_state();
    let new = state["current"]
        .as_str()
        .expect("a current root")
        .to_owned();
    assert_ne!(new, old);
    assert_eq!(state["roots"][&old]["alarm"], true, "{state:#}");
    assert_eq!(state["roots"][&new]["alarm"], false, "{state:#}");
    assert_eq!(case.health()["root"], json!(new));
}

fn a_backlog_hold_lets_the_sweep_continue_and_confirm_waits() {
    let case = Case::new("backlog");
    let build = case.build("one");
    case.assign(&build, &["a"], 3);
    case.script("sweep.suspects", "1 1 1 1 1");
    case.script("confirm.codes", "4 0");
    case.script("confirm.backlog", "1 0");
    case.script("confirm.findings_bytes", "200000");
    let runner = case.start();
    case.wait_for("a backlog while sweeping", |case| {
        let health = case.health_now();
        health["confirmation"] == "backlog" && health["phase"] == "sweeping"
    });
    let (code, report) = case.status();
    assert!(matches!(code, Some(1 | 2)), "{report:#}");
    assert!(
        report["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("confirmation backlog")),
        "{report:#}"
    );
    case.wait_for("a confirm after the backlog", |case| {
        case.events("confirm", "exit").len() >= 2
    });
    case.wait_for("three sweeps", |case| {
        case.events("sweep", "exit").len() >= 3
    });
    stop(runner);
    let confirms = case.events("confirm", "exit");
    assert_eq!(confirms[0]["code"], 4);
    let retry = case.events("confirm", "start");
    assert!(
        time(&retry[1]) - time(&confirms[0]) >= 3_000,
        "the retry waited a stint"
    );
    let starts = case.events("sweep", "start");
    let exits = case.events("sweep", "exit");
    assert!(
        time(&starts[1]) <= time(&retry[1]),
        "the next sweep starts before the confirm retry"
    );
    for index in 0..2 {
        assert!(
            time(&starts[index + 1]) - time(&exits[index]) < 1_800,
            "sweep {index} was followed at once"
        );
    }
}

fn a_backlog_report_without_its_error_log_holds_the_root() {
    let case = Case::new("backlog-no-log");
    let build = case.build("one");
    case.assign(&build, &["a"], 3);
    case.script("sweep.suspects", "1");
    case.script("confirm.codes", "4 0");
    case.script("confirm.backlog", "1 0");
    case.script("confirm.lose_err", "1 0");
    let runner = case.start();
    let outcome = |case: &Case| case.current()["confirmation"]["state"].clone();
    case.wait_for("a recorded outcome", |case| {
        outcome(case) == "held" || outcome(case) == "backlog"
    });
    let recorded = outcome(&case);
    stop(runner);
    assert_eq!(recorded, "held");
}

fn another_confirm_hold_stops_stints_until_a_confirm_succeeds() {
    for (name, script, backlog) in [
        ("held", "4 4 0", "0 1 0"),
        ("held-busy", "4 3 0", "0 0 0"),
        ("held-interrupted", "4 0 0", "0 0 0"),
    ] {
        let case = Case::new(name);
        let build = case.build("one");
        case.assign(&build, &["a"], 1);
        case.script("sweep.suspects", "1");
        case.script("confirm.codes", script);
        case.script("confirm.backlog", backlog);
        case.script("confirm.dispatch", "x interrupted queue_empty");
        let runner = case.start();
        case.wait_for("the held phase", |case| {
            case.health_now()["phase"] == "held"
        });
        let (code, report) = case.status();
        assert_eq!(code, Some(2), "{name}: {report:#}");
        let reasons = report["reasons"].as_array().expect("reasons");
        assert!(reasons.contains(&json!("phase held")), "{report:#}");
        assert!(reasons.contains(&json!("confirmation held")), "{report:#}");
        case.wait_for("a second stint", |case| {
            case.events("sweep", "start").len() >= 2
        });
        stop(runner);
        let confirms = case.events("confirm", "start");
        let confirmed = case.events("confirm", "exit");
        assert_eq!(
            codes(&confirmed)[..3],
            script
                .split(' ')
                .map(|code| code.parse::<u64>().expect("a code"))
                .collect::<Vec<_>>()[..],
            "{name}"
        );
        for index in 0..2 {
            let gap = time(&confirms[index + 1]) - time(&confirmed[index]);
            assert!(
                gap >= 1_000,
                "{name}: confirm {index} held and the retry came {gap} ms later"
            );
        }
        let starts = case.events("sweep", "start");
        assert!(
            time(&starts[1]) >= time(&confirmed[2]),
            "{name}: no stint starts while confirm is held"
        );
    }
}

fn a_confirm_hold_at_the_stint_boundary_stops_the_next_stint() {
    let case = Case::new("boundary");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1");
    case.script("sweep.after_confirm", "1");
    case.script("confirm.codes", "4 0");
    case.script("confirm.ms", "300");
    let runner = case.start();
    case.wait_for("a second stint", |case| {
        case.events("sweep", "start").len() >= 2
    });
    stop(runner);
    let confirmed = case.events("confirm", "exit");
    assert_eq!(codes(&confirmed)[..2], [4, 0]);
    let starts = case.events("sweep", "start");
    assert!(
        time(&starts[1]) >= time(&confirmed[1]),
        "the hold that ended with the sweep stops the next stint"
    );
}

fn a_busy_confirm_waits_and_the_sweep_continues() {
    let case = Case::new("busy");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1");
    case.script("confirm.codes", "3 0");
    let runner = case.start();
    case.wait_for("a confirm after the busy one", |case| {
        case.events("confirm", "exit").len() >= 2
    });
    stop(runner);
    let starts = case.events("confirm", "start");
    let exits = case.events("confirm", "exit");
    assert_eq!(codes(&exits)[..2], [3, 0]);
    assert!(
        time(&starts[1]) - time(&exits[0]) >= 1_000,
        "the retry waited"
    );
    let sweeps = case.events("sweep", "start");
    let ended = case.events("sweep", "exit");
    assert!(
        sweeps.iter().zip(&ended).any(|(sweep, exit)| {
            time(sweep) < time(&starts[1]) && time(exit) > time(&exits[0])
        }),
        "a sweep ran while the busy confirm waited"
    );
}

fn a_restart_keeps_the_wait_after_a_held_confirm() {
    for (name, codes, backlog, state) in [
        ("held-restart", "4 0", "0 0", "held"),
        ("failed-restart", "3 0", "0 0", "failed"),
        ("backlog-restart", "4 0", "1 0", "backlog"),
    ] {
        let case = Case::new(name);
        let build = case.build("one");
        case.assign(&build, &["a"], 3);
        case.script("sweep.suspects", "1 1 1 1");
        case.script("confirm.codes", codes);
        case.script("confirm.backlog", backlog);
        let runner = case.start();
        case.wait_for("a recorded outcome", |case| {
            case.current()["confirmation"]["state"] == state
        });
        runner.kill();
        case.wait_for("the orphaned children to end", all_children_ended);
        let restarted = fake::now_ms();
        let runner = case.start();
        case.wait_for("the confirm retry", |case| {
            case.events("confirm", "start").len() >= 2
        });
        stop(runner);
        let retry = time(&case.events("confirm", "start")[1]);
        assert!(
            retry - restarted >= 3_000,
            "{name}: the retry came {} ms after the restart",
            retry - restarted
        );
    }
}

fn a_restart_with_a_lost_copy_waits_the_source_stint_before_a_confirm() {
    let case = Case::new("copy-restart");
    let build = case.build("one");
    case.assign(&build, &["a"], 3);
    case.script("sweep.suspects", "1 1 1 1");
    case.script("confirm.codes", "3 0");
    let runner = case.start();
    case.wait_for("a recorded outcome", |case| {
        case.current()["confirmation"]["state"] == "failed"
    });
    runner.kill();
    case.wait_for("the orphaned children to end", all_children_ended);
    fs::remove_file(stored_copy(&case)).expect("the copy is removed");
    let restarted = fake::now_ms();
    let runner = case.start();
    case.wait_for("the confirm retry", |case| {
        case.events("confirm", "start").len() >= 2
    });
    stop(runner);
    let waited = time(&case.events("confirm", "start")[1]) - restarted;
    assert!(
        (3_000..30_000).contains(&waited),
        "the retry came {waited} ms after the restart"
    );
}

fn a_restart_takes_its_confirm_wait_from_the_source() {
    let case = Case::new("source-restart");
    let build = case.build("one");
    case.assign(&build, &["a"], 20);
    case.script("sweep.suspects", "1 1 1 1");
    case.script("confirm.codes", "3 0");
    let runner = case.start();
    case.wait_for("a recorded outcome", |case| {
        case.current()["confirmation"]["state"] == "failed"
    });
    runner.kill();
    case.wait_for("the orphaned children to end", all_children_ended);
    case.assign(&build, &["a"], 2);
    let restarted = fake::now_ms();
    let runner = case.start();
    case.wait_for("the confirm retry", |case| {
        case.events("confirm", "start").len() >= 2
    });
    stop(runner);
    let waited = time(&case.events("confirm", "start")[1]) - restarted;
    assert!(
        (2_000..15_000).contains(&waited),
        "the retry came {waited} ms after the restart"
    );
}

fn no_confirm_starts_without_a_new_suspect_line() {
    let case = Case::new("lines");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "0 0 2 0 0");
    case.script("confirm.findings_bytes", "200000");
    let runner = case.start();
    case.wait_for("five sweeps", |case| {
        case.events("sweep", "exit").len() >= 5
    });
    stop(runner);
    let confirms = case.events("confirm", "start");
    assert_eq!(confirms.len(), 1, "{confirms:#?}");
    let starts = case.events("sweep", "start");
    assert!(time(&confirms[0]) >= time(&starts[2]));
    assert_eq!(case.current()["pending"], false);
}

fn a_torn_suspect_line_starts_no_confirm() {
    let case = Case::new("torn");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.torn", "1");
    case.script("sweep.suspects", "0 0 1 0");
    let runner = case.start();
    case.wait_for("four sweeps", |case| {
        case.events("sweep", "exit").len() >= 4
    });
    stop(runner);
    let confirms = case.events("confirm", "start");
    assert_eq!(confirms.len(), 1, "{confirms:#?}");
    let starts = case.events("sweep", "start");
    assert!(time(&confirms[0]) >= time(&starts[2]));
}

fn a_line_written_during_a_confirm_gets_another_confirm() {
    let case = Case::new("during");
    let build = case.build("one");
    case.assign(&build, &["a"], 2);
    case.script("sweep.suspects", "1");
    case.script("sweep.late", "1");
    case.script("confirm.ms", "3000 0");
    let runner = case.start();
    case.wait_for("two confirms", |case| {
        case.events("confirm", "exit").len() >= 2
    });
    stop(runner);
    let starts = case.events("confirm", "start");
    let exits = case.events("confirm", "exit");
    assert_eq!(starts.len(), 2);
    assert!(time(&starts[1]) >= time(&exits[0]));
    let root = arg(&starts[0], "--root");
    assert_eq!(
        fs::read_to_string(Path::new(&root).join("confirm/confirmed")).expect("the cursor"),
        "2"
    );
}

fn queued_jobs_get_another_confirm_without_a_new_line() {
    let case = Case::new("queued");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1");
    case.script("confirm.ms", "60000 0 0");
    case.script("confirm.dispatch", "x paused queue_empty");
    let runner = case.start();
    case.wait_for("a running confirm", |case| {
        !case.events("confirm", "start").is_empty()
    });
    stop(runner);
    assert_eq!(case.current()["pending"], true);
    let restarted = fake::now_ms();
    let runner = case.start();
    case.wait_for("a drained queue", |case| {
        case.events("confirm", "exit").len() >= 3 && case.current()["pending"] == false
    });
    let sweeps = case.events("sweep", "exit").len();
    case.wait_for("three quiet sweeps", |case| {
        case.events("sweep", "exit").len() >= sweeps + 3
    });
    stop(runner);
    let starts = case.events("confirm", "start");
    let exits = case.events("confirm", "exit");
    assert_eq!(starts.len(), 3, "{starts:#?}");
    assert_eq!(exits[0]["terminated"], true);
    assert!(
        time(&starts[1]) - restarted >= 1_000,
        "pending work waits a stint after a restart"
    );
    assert!(
        time(&starts[2]) - time(&exits[1]) >= 1_000,
        "a paused dispatch is retried after a stint"
    );
}

fn lines_of_a_replaced_root_are_confirmed() {
    let case = Case::new("replaced-root");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 2);
    case.script("sweep.late", "1");
    let runner = case.start();
    case.wait_for("the first sweep", |case| {
        !case.events("sweep", "start").is_empty()
    });
    case.assign(&second, &["a"], 2);
    let old = campaigns(&case.events("sweep", "start"))[0].clone();
    let root = case.state().join("roots").join(&old);
    case.wait_for(
        "a confirm of the old root and a sweep of the next build",
        |case| {
            fs::read_to_string(root.join("confirm/confirmed")).is_ok_and(|text| text == "1")
                && case
                    .events("sweep", "start")
                    .iter()
                    .any(|entry| arg(entry, "--archive").contains(&second))
        },
    );
    stop(runner);
    let confirm = case
        .events("confirm", "start")
        .into_iter()
        .find(|entry| arg(entry, "--root").ends_with(&old))
        .expect("a confirm of the old root");
    let nonce = old.rsplit('.').next().expect("a nonce");
    let group = case.dir.join("cgroup/confirm").join(nonce);
    assert_eq!(
        arg(&confirm, "--archive"),
        case.archive(&first).to_str().expect("a text path")
    );
    assert_eq!(
        arg(&confirm, "--cgroup-root"),
        group.to_str().expect("a text path")
    );
    assert_eq!(arg(&confirm, "--slots"), "1");
    assert!(
        case.events("sweep", "start")
            .iter()
            .any(|entry| arg(entry, "--archive").contains(&second))
    );
}

fn the_disk_reserve_skips_the_stint() {
    let mut case = Case::new("reserve");
    case.disk_reserve = u64::MAX;
    let build = case.install("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("the full phase", |case| {
        case.health_now()["phase"] == "full"
    });
    std::thread::sleep(Duration::from_millis(2_500));
    let health = case.health();
    stop(runner);
    assert!(case.events("sweep", "start").is_empty());
    assert_eq!(health["phase"], "full");
    assert!(
        health["reason"]
            .as_str()
            .expect("a reason")
            .contains("reserve")
    );
}

fn a_signal_stops_the_children_before_the_runner_exits() {
    for (name, number, sweep_linger, confirm_linger) in [
        ("signal-term", libc::SIGTERM, 1_500, 0),
        ("signal-int", libc::SIGINT, 0, 1_500),
    ] {
        let case = Case::new(name);
        let build = case.build("one");
        case.assign(&build, &["a"], 60);
        case.script("sweep.suspects", "1");
        case.script("confirm.ms", "60000");
        case.script("sweep.linger", &sweep_linger.to_string());
        case.script("confirm.linger", &confirm_linger.to_string());
        let runner = case.start();
        case.wait_for("a running confirm", |case| {
            !case.events("confirm", "start").is_empty()
        });
        let signalled = fake::now_ms();
        let (output, seen) = ended(runner, number);
        assert!(output.status.success(), "{name}: {output:?}");
        for (command, linger) in [("sweep", sweep_linger), ("confirm", confirm_linger)] {
            let exits = case.events(command, "exit");
            assert_eq!(exits.len(), 1, "{name}: {command} ended once");
            assert_eq!(
                exits[0]["terminated"], true,
                "{name}: {command} got SIGTERM"
            );
            let received = time(&case.events(command, "signal")[0]);
            assert!(received >= signalled, "{name}: {command}");
            assert!(time(&exits[0]) >= received + linger, "{name}: {command}");
            assert!(
                time(&exits[0]) <= seen,
                "{name}: the runner outlived {command}"
            );
        }
        assert_eq!(case.health()["phase"], "stopped");
    }
}

fn an_error_after_the_sweep_starts_stops_the_sweep_first() {
    let case = Case::new("post-spawn");
    let build = case.build("one");
    case.assign(&build, &["a"], 30);
    case.script("sweep.suspects", "1");
    case.script("sweep.linger", "1500");
    case.script("confirm.block_state", "1");
    let (output, seen) = exited(case.start());
    let _ = fs::remove_dir(case.state().join(".state.json.staged"));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let exits = case.events("sweep", "exit");
    assert_eq!(exits.len(), 1, "{:#?}", case.log());
    assert_eq!(exits[0]["terminated"], true);
    let received = time(&case.events("sweep", "signal")[0]);
    assert!(time(&exits[0]) >= received + 1_500);
    assert!(time(&exits[0]) <= seen, "the sweep ended before the runner");
}

fn an_ignored_sigchld_leaves_the_children_waitable() {
    let case = Case::new("sigchld");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1");
    let mut command = case.run_command();
    // SAFETY: between fork and exec the hook calls `signal`, which is
    // async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::signal(libc::SIGCHLD, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let runner = Running(Some(command.spawn().expect("sim-host starts")));
    case.wait_for("three sweeps and a confirm", |case| {
        case.events("sweep", "exit").len() >= 3 && !case.events("confirm", "exit").is_empty()
    });
    stop(runner);
}

fn the_health_record_carries_the_sweep_groups_cpu() {
    let case = Case::new("share");
    let build = case.build("one");
    let other = case.build("two");
    case.assign(&build, &["a"], 1);
    case.script("sweep.cpu", "5000000 7000000");
    let runner = case.start();
    case.wait_for("two stints in the health record", |case| {
        case.health_now()["cpu_usec"] == 12_000_000
    });
    let health = case.health();
    let online = sim_host::host::online_cpus();
    let capacity = health["stint_capacity_usec"].as_u64().expect("a capacity");
    assert!(
        (online * 1_000_000..online * 3_000_000).contains(&capacity),
        "{health:#}"
    );
    assert_eq!(health["stint_cpu_usec"], 7_000_000, "{health:#}");
    assert_eq!(health["share_stint"], 2, "{health:#}");
    let root = health["root"].as_str().expect("a root").to_owned();
    let state = case.runner_state();
    assert!(
        state["roots"][&root]["capacity_usec"]
            .as_u64()
            .expect("a sum")
            >= capacity * 2 - online * 1_000_000
    );
    case.assign(&other, &["a"], 1);
    case.wait_for("the new root's first sweep", |case| {
        let health = case.health_now();
        health["root"] != json!(root) && health["phase"] == "sweeping"
    });
    let health = case.health();
    stop(runner);
    assert!(health["stint_cpu_usec"].is_null(), "{health:#}");
    assert!(health["share_stint"].is_null(), "{health:#}");
}

fn an_unreadable_cpu_counter_is_unmeasured() {
    let case = Case::new("broken-cpu");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.cpu", "5000000 7000000 9000000 1000000");
    case.script("sweep.cpu_broken", "0 1 0 0");
    let runner = case.start();
    case.wait_for("the stint after the unreadable counter", |case| {
        case.health_now()["stint"] == 3
    });
    let health = case.health();
    let (_, report) = case.status();
    assert!(health["stint_cpu_usec"].is_null(), "{health:#}");
    assert_eq!(health["cpu_usec"], 5_000_000, "{health:#}");
    assert_eq!(report["share"], "unknown");
    let capacity = health["capacity_usec"].as_u64().expect("a capacity");
    case.wait_for("a measured stint", |case| {
        case.health_now()["share_stint"] == 4
    });
    let health = case.health();
    stop(runner);
    assert_eq!(health["cpu_usec"], 6_000_000, "{health:#}");
    assert_eq!(health["stint_cpu_usec"], 1_000_000, "{health:#}");
    assert_eq!(
        health["capacity_usec"].as_u64().expect("a capacity"),
        capacity
            + health["stint_capacity_usec"]
                .as_u64()
                .expect("a stint capacity"),
        "unmeasured stints add no capacity: {health:#}"
    );
}

fn a_host_without_an_instance_id_starts_nothing() {
    let case = Case {
        metadata: Metadata::serve(None),
        ..Case::new("no-instance")
    };
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let output = case
        .start()
        .take()
        .wait_with_output()
        .expect("the runner ends");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("instance"));
    assert!(!case.state().join("state.json").exists());
    assert!(case.log().is_empty());
    let health = case.health();
    assert_eq!(health["phase"], "blocked", "{health:#}");
    assert_eq!(case.status().0, Some(2));
}

fn allowed_cpus(count: usize) -> Vec<usize> {
    let status = fs::read_to_string("/proc/self/status").expect("the process status");
    let list = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .expect("an allowed CPU list")
        .trim();
    let chosen: Vec<usize> = list
        .split(',')
        .flat_map(|range| {
            let (first, last) = range.split_once('-').unwrap_or((range, range));
            let first: usize = first.parse().expect("a CPU number");
            let last: usize = last.parse().expect("a CPU number");
            first..=last
        })
        .take(count)
        .collect();
    assert_eq!(chosen.len(), count, "the test may use {count} CPUs");
    chosen
}

fn check(case: &Case, cgroup: &Path, extra: &[&str], cpus: Option<usize>) -> (Option<i32>, Value) {
    let mut args = vec![
        "check",
        "--bucket",
        "sims",
        "--cgroup",
        cgroup.to_str().expect("a text path"),
        "--confirm-slots",
        "1",
        "--system-memory",
        "0",
    ];
    args.extend_from_slice(extra);
    let mut command = case.command(&args);
    if let Some(cpus) = cpus {
        let chosen = allowed_cpus(cpus);
        // SAFETY: between fork and exec the hook fills a stack mask and
        // calls `sched_setaffinity`, both async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                for cpu in &chosen {
                    libc::CPU_SET(*cpu, &mut set);
                }
                if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let output = command.output().expect("check runs");
    let report = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (output.status.code(), report)
}

fn refused(report: &Value, text: &str) -> bool {
    report["refusals"].as_array().is_some_and(|refusals| {
        refusals.iter().any(|refusal| {
            refusal
                .as_str()
                .is_some_and(|refusal| refusal.contains(text))
        })
    })
}

fn check_refuses_each_oversubscription_limit_and_missing_id() {
    let case = Case::new("check");
    let build = case.build("one");
    let mut small = Case::assignment(&build, &["a"], 1);
    small["memory"] = json!(1 << 20);
    case.write_assignment(&small);
    let cgroup = case.dir.join("cgroup");
    let online = sim_host::host::online_cpus();
    let (code, report) = check(&case, &cgroup, &["--system-cores", "0"], None);
    if sim_host::host::usable_cpus().expect("the mask") == online {
        assert_eq!(code, Some(0), "{report:#}");
        assert_eq!(report["workers"], online - 2);
        assert_eq!(report["metadata"], json!(case.metadata.address));
    }
    let (code, report) = check(&case, &cgroup, &["--system-cores", "0"], Some(1));
    assert_eq!(code, Some(2));
    assert!(
        refused(&report, "online CPUs and the runner may use 1"),
        "{report:#}"
    );
    let all = online.to_string();
    let (code, report) = check(&case, &cgroup, &["--system-cores", &all], None);
    assert_eq!(code, Some(2));
    assert!(refused(&report, "leave no worker"), "{report:#}");
    let memory = sim_host::host::memory_bytes().expect("meminfo");
    let mut large = small.clone();
    large["memory"] = json!(memory);
    case.write_assignment(&large);
    let (code, report) = check(&case, &cgroup, &["--system-cores", "0"], None);
    assert_eq!(code, Some(2));
    assert!(refused(&report, "bytes of memory"), "{report:#}");
    case.write_assignment(&small);
    fs::write(cgroup.join("cgroup.controllers"), "cpu memory").expect("controllers");
    let (code, report) = check(&case, &cgroup, &["--system-cores", "0"], None);
    assert_eq!(code, Some(2));
    assert!(refused(&report, "does not delegate pids"), "{report:#}");
    fs::remove_file(cgroup.join("cgroup.controllers")).expect("the controller list is removed");
    let (code, report) = check(&case, &cgroup, &["--system-cores", "0"], None);
    assert_eq!(code, Some(2));
    assert!(refused(&report, "cgroup.controllers"), "{report:#}");
    fs::write(cgroup.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
    let superuser = fs::metadata(&case.dir).expect("the case directory").uid() == 0;
    if !superuser {
        let control = cgroup.join("cgroup.subtree_control");
        fs::set_permissions(&control, fs::Permissions::from_mode(0o444))
            .expect("a read-only control file");
        let (code, report) = check(&case, &cgroup, &["--system-cores", "0"], None);
        fs::set_permissions(&control, fs::Permissions::from_mode(0o644))
            .expect("a writable control file");
        assert_eq!(code, Some(2));
        assert!(refused(&report, "may not write"), "{report:#}");
    }
    let slice = case.dir.join("limited");
    let unit = slice.join("unit");
    fs::create_dir_all(&unit).expect("a limited tree");
    for dir in [&slice, &unit] {
        fs::write(dir.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
    }
    fs::write(unit.join("cgroup.procs"), "").expect("procs");
    fs::write(unit.join("cgroup.subtree_control"), "").expect("control");
    fs::write(slice.join("cpu.max"), "50000 100000").expect("a CPU limit");
    let (code, report) = check(&case, &unit, &["--system-cores", "0"], None);
    assert_eq!(code, Some(2));
    assert!(refused(&report, "sets cpu.max 50000 100000"), "{report:#}");
    let missing = Case {
        metadata: Metadata::serve(None),
        ..Case::new("check-no-instance")
    };
    missing.write_assignment(&small);
    let cgroup = missing.dir.join("cgroup");
    let (code, report) = check(&missing, &cgroup, &["--system-cores", "0"], None);
    assert_eq!(code, Some(2));
    assert!(refused(&report, "no instance id"), "{report:#}");
}

fn status_exits_by_the_record_and_prints_the_hand_computed_share() {
    let case = Case::new("status");
    let state = case.state();
    fs::create_dir_all(&state).expect("the state directory");
    let now = sim_host::host::now_s();
    let healthy = json!({
        "format": 1, "written": now, "stint_seconds": 3600, "phase": "sweeping",
        "alarm": false, "confirmation": "idle",
        "stint_cpu_usec": 648_000_000_000u64, "stint_capacity_usec": 691_200_000_000u64,
    });
    let run = |record: &Value| {
        fs::write(state.join("health.json"), record.to_string()).expect("a health record");
        case.status()
    };
    let (code, report) = run(&healthy);
    assert_eq!(code, Some(0), "{report:#}");
    assert_eq!(report["share"], 0.9375, "180 of 192 CPUs over one stint");
    assert_eq!(report["build"], "unknown");
    let change = |key: &str, value: Value| {
        let mut record = healthy.clone();
        record[key] = value;
        record
    };
    for (record, expected) in [
        (change("alarm", json!(true)), 2),
        (change("phase", json!("held")), 2),
        (change("written", json!(now - 7_300)), 2),
        (change("confirmation", json!("held")), 2),
        (change("sweep_overdue", json!(true)), 2),
        (change("sweep_overdue", json!(false)), 0),
        (change("confirmation", json!("backlog")), 1),
        (change("stint_cpu_usec", json!(600_000_000_000u64)), 1),
    ] {
        let (code, report) = run(&record);
        assert_eq!(code, Some(expected), "{report:#}");
    }
    let (_, report) = run(&change("written", json!(now - 7_300)));
    assert_eq!(report["stale"], true);
    fs::write(state.join("health.json"), "{").expect("a damaged record");
    assert_eq!(case.status().0, Some(2));
}

fn check_reads_only_the_assignment() {
    let case = Case::new("check-assignment");
    let document = json!({
        "format": 1, "name": "sim", "profiles": ["a"], "batch": 30,
        "wall": 600, "memory": 1 << 20, "processes": 64, "stint": 1,
    });
    case.put("assignment.json", document.to_string().as_bytes());
    let cgroup = case.dir.join("cgroup");
    let (code, report) = check(&case, &cgroup, &["--system-cores", "0"], None);
    assert!(
        report["workers"].is_u64(),
        "the partition is printed: {report:#}"
    );
    if sim_host::host::usable_cpus().expect("the mask") == sim_host::host::online_cpus() {
        assert_eq!(code, Some(0), "{report:#}");
    }
    assert!(
        calls(&case, "aws")
            .iter()
            .all(|call| call["key"] == "assignment.json"),
        "check reads nothing but the assignment"
    );
    case.put("assignment.json", b"{");
    let (code, _) = check(&case, &cgroup, &["--system-cores", "0"], None);
    assert_eq!(code, Some(2), "a damaged assignment is refused");
    let leftovers: Vec<_> = fs::read_dir(case.dir.join("tmp"))
        .expect("the case's temporary directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "check removes its scratch: {leftovers:?}"
    );
}

fn publish_in(case: &Case, cwd: &Path, checkout: &str, state: &str) -> Running {
    fs::create_dir_all(case.dir.join("checkout")).expect("the checkout");
    let args = [
        "publish",
        "--checkout",
        checkout,
        "--state",
        state,
        "--bucket",
        "sims",
        "--interval",
        "1",
    ];
    let mut command = case.command(&args);
    command.current_dir(cwd);
    Running(Some(command.spawn().expect("the publisher starts")))
}

fn publish(case: &Case) -> Running {
    let checkout = case.dir.join("checkout");
    let state = case.dir.join("publisher");
    publish_in(
        case,
        &case.dir,
        checkout.to_str().expect("a text path"),
        state.to_str().expect("a text path"),
    )
}

fn calls(case: &Case, command: &str) -> Vec<Value> {
    case.events(command, "call")
}

fn puts(case: &Case, key: &str) -> usize {
    put_times(case, key).len()
}

/// The start times of the puts of `key`, in call order.
fn put_times(case: &Case, key: &str) -> Vec<u64> {
    calls(case, "aws")
        .iter()
        .filter(|call| call["op"] == "put-object" && call["key"] == key)
        .map(time)
        .collect()
}

fn published(case: &Case, head: &str) -> bool {
    case.object("current.json")
        .is_some_and(|current| Some(current) == case.object(&format!("commits/{head}.json")))
}

fn a_new_head_is_published_once_and_the_next_head_moves_current() {
    let case = Case::new("publish-once");
    let head = "a".repeat(40);
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    let publisher = publish(&case);
    case.wait_for("current.json", |case| published(case, &head));
    std::thread::sleep(Duration::from_millis(3_500));
    let build = sim_host::file::sha256(fake::build_record(&case.dir, &head).as_bytes());
    let first = case
        .object(&format!("commits/{head}.json"))
        .expect("the commit record");
    let record: Value = serde_json::from_slice(&first).expect("a record");
    assert_eq!(record["build"], build);
    assert_eq!(record["campaign"], sim_host::file::sha256(executable()));
    assert!(
        case.object(&format!("builds/{build}/archive.tar"))
            .is_some()
    );
    assert_eq!(
        case.object(&format!("builds/{build}/campaign")).as_deref(),
        Some(executable())
    );
    assert_eq!(calls(&case, "cargo").len(), 1, "the head is built once");
    assert_eq!(puts(&case, &format!("commits/{head}.json")), 1);
    assert_eq!(puts(&case, &format!("builds/{build}/archive.tar")), 1);
    assert_eq!(puts(&case, "current.json"), 1);
    assert_eq!(
        calls(&case, "cargo")[0]["head"],
        head,
        "cargo builds the checked-out head"
    );
    let archived = case.events("campaign", "archive");
    assert_eq!(archived.len(), 1);
    assert_eq!(
        archived[0]["head"], head,
        "the archive is built at the head"
    );
    assert_eq!(
        archived[0]["opt_level"], "3",
        "optimized with debug assertions"
    );
    let checkout = case.dir.join("checkout");
    assert!(
        calls(&case, "git")
            .iter()
            .all(|call| { call["cwd"] == json!(checkout) && call["args"][0] != "-C" })
    );
    let git = calls(&case, "git");
    assert_eq!(
        git[0]["args"],
        json!(["fetch", "--quiet", "origin", "main"])
    );
    assert_eq!(git[1]["args"], json!(["rev-parse", "origin/main"]));
    assert_eq!(
        calls(&case, "cargo")[0]["args"],
        json!(["build", "--release", "-p", "campaign-supervisor"])
    );
    let next = "c".repeat(40);
    fs::write(case.dir.join("git.head"), &next).expect("the next head");
    case.wait_for("current.json of the next head", |case| {
        published(case, &next)
    });
    let output = stop(publisher);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(calls(&case, "cargo").len(), 2);
    assert_eq!(puts(&case, "current.json"), 2);
    assert_eq!(
        case.object(&format!("commits/{head}.json")),
        Some(first),
        "the earlier record is unchanged"
    );
    let record: Value = serde_json::from_slice(&case.object("current.json").expect("current.json"))
        .expect("a record");
    assert_eq!(record["commit"], next);
    assert_eq!(
        record["build"],
        sim_host::file::sha256(fake::build_record(&case.dir, &next).as_bytes())
    );
    assert!(
        fs::read_dir(case.dir.join("publisher/publish"))
            .map_or(true, |mut dir| dir.next().is_none()),
        "the publisher leaves no work directory"
    );
}

fn a_relative_checkout_and_state_publish_the_same_record() {
    let case = Case::new("publish-relative");
    let head = "d".repeat(40);
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    let publisher = publish_in(&case, &case.dir, "checkout", "publisher");
    case.wait_for("current.json", |case| published(case, &head));
    stop(publisher);
    let record: Value = serde_json::from_slice(&case.object("current.json").expect("current.json"))
        .expect("a record");
    assert_eq!(record["commit"], head);
    for nested in ["checkout/checkout", "checkout/publisher"] {
        assert!(!case.dir.join(nested).exists(), "{nested}");
    }
}

fn a_publisher_that_finds_its_build_stored_uses_the_stored_one() {
    let case = Case::new("publish-stored");
    let head = "b".repeat(40);
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    let build = sim_host::file::sha256(fake::build_record(&case.dir, &head).as_bytes());
    case.put(
        &format!("builds/{build}/archive.tar"),
        b"the stored archive",
    );
    case.put(&format!("builds/{build}/campaign"), b"the stored campaign");
    let publisher = publish(&case);
    case.wait_for("current.json", |case| case.object("current.json").is_some());
    stop(publisher);
    let record: Value = serde_json::from_slice(&case.object("current.json").expect("current.json"))
        .expect("a record");
    assert_eq!(record["build"], build);
    assert_eq!(
        record["campaign"],
        sim_host::file::sha256(b"the stored campaign")
    );
    assert_eq!(
        case.object(&format!("builds/{build}/archive.tar"))
            .as_deref(),
        Some(&b"the stored archive"[..])
    );
    assert_eq!(
        case.object(&format!("builds/{build}/campaign")).as_deref(),
        Some(&b"the stored campaign"[..])
    );
    assert!(
        calls(&case, "aws")
            .iter()
            .all(|call| !(call["op"] == "get-object"
                && call["key"] == format!("builds/{build}/campaign"))),
        "the stored binary's digest comes from its header"
    );
}

fn a_record_of_another_commit_is_not_promoted() {
    let case = Case::new("publish-misplaced");
    let head = "e".repeat(40);
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    let build = sim_host::file::sha256(b"x");
    let other = json!({"format": 1, "commit": "f".repeat(40), "build": build,
                       "campaign": build});
    case.put(
        &format!("commits/{head}.json"),
        other.to_string().as_bytes(),
    );
    case.put("current.json", b"the current record");
    let publisher = publish(&case);
    std::thread::sleep(Duration::from_millis(2_500));
    let (output, _) = ended(publisher, libc::SIGTERM);
    assert_eq!(
        case.object("current.json").as_deref(),
        Some(&b"the current record"[..])
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains(&format!("names commit {}", "f".repeat(40))),
        "{output:?}"
    );
}

fn a_dirty_checkout_or_a_failed_build_publishes_nothing_until_the_next_head() {
    let case = Case::new("publish-dirty");
    let heads = ["1".repeat(40), "2".repeat(40), "3".repeat(40)];
    fs::write(case.dir.join("git.head"), &heads[0]).expect("the head");
    fs::write(case.dir.join("git.dirty"), " M crates/a.rs\n").expect("a dirty checkout");
    case.script("cargo.codes", "1 0");
    let release = case.dir.join("checkout/target/release");
    fs::create_dir_all(&release).expect("an earlier build");
    std::os::unix::fs::symlink(
        std::env::current_exe().expect("this executable"),
        release.join("campaign"),
    )
    .expect("an earlier campaign binary");
    let publisher = publish(&case);
    std::thread::sleep(Duration::from_millis(2_500));
    assert!(case.object("current.json").is_none());
    assert!(
        calls(&case, "cargo").is_empty(),
        "a dirty checkout is not built"
    );
    fs::write(case.dir.join("git.dirty"), "").expect("a clean checkout");
    std::thread::sleep(Duration::from_millis(2_500));
    assert!(
        calls(&case, "cargo").is_empty(),
        "a skipped head is not tried again"
    );
    fs::write(case.dir.join("git.head"), &heads[1]).expect("the next head");
    case.wait_for("the failed build", |case| !calls(case, "cargo").is_empty());
    std::thread::sleep(Duration::from_millis(2_500));
    assert!(case.object("current.json").is_none());
    assert_eq!(
        calls(&case, "cargo").len(),
        1,
        "a failed build is not tried again"
    );
    assert!(
        case.events("campaign", "archive").is_empty(),
        "a failed build makes no archive"
    );
    fs::write(case.dir.join("git.head"), &heads[2]).expect("the third head");
    case.wait_for("current.json", |case| case.object("current.json").is_some());
    stop(publisher);
    let record: Value = serde_json::from_slice(&case.object("current.json").expect("current.json"))
        .expect("a record");
    assert_eq!(record["commit"], heads[2]);
    for head in &heads[..2] {
        assert!(case.object(&format!("commits/{head}.json")).is_none());
    }
    let puts: Vec<Value> = calls(&case, "aws")
        .into_iter()
        .filter(|call| call["op"] == "put-object")
        .collect();
    assert!(
        puts.iter()
            .all(|put| !put["key"].as_str().expect("a key").contains(&heads[0][..8])),
        "{puts:#?}"
    );
}

/// A build that exits 0 without writing `target/release/campaign` beside
/// an earlier binary, and an archive whose build record names another
/// revision or a dirty checkout, each publish nothing for their head; a
/// clean head after them publishes.
fn an_unbuilt_binary_or_an_unclean_archive_publishes_nothing() {
    let case = Case::new("publish-unclean");
    let heads = [
        "4".repeat(40),
        "5".repeat(40),
        "6".repeat(40),
        "7".repeat(40),
    ];
    let release = case.dir.join("checkout/target/release");
    fs::create_dir_all(&release).expect("an earlier build");
    std::os::unix::fs::symlink(
        std::env::current_exe().expect("this executable"),
        release.join("campaign"),
    )
    .expect("an earlier campaign binary");
    fs::write(case.dir.join("cargo.empty"), "").expect("a build that writes no binary");
    fs::write(case.dir.join("git.head"), &heads[0]).expect("the head");
    let publisher = publish(&case);
    case.wait_for("the build", |case| !calls(case, "cargo").is_empty());
    std::thread::sleep(Duration::from_millis(2_500));
    assert!(
        case.events("campaign", "archive").is_empty(),
        "the earlier binary is not run"
    );
    fs::remove_file(case.dir.join("cargo.empty")).expect("a build that writes its binary");
    let provenances = [
        json!({"revision": "f".repeat(40), "dirty": false, "untracked": 0}),
        json!({"revision": heads[2], "dirty": true, "untracked": 0}),
    ];
    for (head, provenance) in heads[1..3].iter().zip(&provenances) {
        fs::write(case.dir.join("archive.provenance"), provenance.to_string())
            .expect("the archive's provenance");
        let archives = case.events("campaign", "archive").len();
        fs::write(case.dir.join("git.head"), head).expect("the next head");
        case.wait_for("the archive", |case| {
            case.events("campaign", "archive").len() > archives
        });
        std::thread::sleep(Duration::from_millis(2_500));
        assert_eq!(
            case.events("campaign", "archive").len(),
            archives + 1,
            "a refused head is archived once"
        );
    }
    fs::remove_file(case.dir.join("archive.provenance")).expect("a clean archive");
    fs::write(case.dir.join("git.head"), &heads[3]).expect("the last head");
    case.wait_for("current.json", |case| published(case, &heads[3]));
    stop(publisher);
    for head in &heads[..3] {
        assert!(case.object(&format!("commits/{head}.json")).is_none());
    }
    let puts: Vec<Value> = calls(&case, "aws")
        .into_iter()
        .filter(|call| call["op"] == "put-object")
        .collect();
    assert_eq!(
        puts.iter()
            .filter(|put| put["key"]
                .as_str()
                .is_some_and(|key| key.starts_with("builds/")))
            .count(),
        2,
        "only the clean head stores its archive and binary: {puts:#?}"
    );
}

/// A fetch that fails leaves `origin/main` at the head it fetched last, and
/// the publisher builds and stores nothing until a later fetch succeeds.
fn a_failed_fetch_publishes_nothing_until_a_fetch_succeeds() {
    let case = Case::new("publish-fetch");
    let (stale, remote) = ("8".repeat(40), "9".repeat(40));
    // `origin/main` names an unpublished head, and the remote has moved on;
    // a publisher that went on after a failed fetch would build the stale
    // head.
    fs::write(case.dir.join("git.fetched"), &stale).expect("a stale origin/main");
    fs::write(case.dir.join("git.head"), &remote).expect("the remote head");
    fs::write(case.dir.join("git.fetch.fail"), "").expect("a failing fetch");
    let publisher = publish(&case);
    case.wait_for("two failed fetches", |case| {
        case.events("git", "fetch-failed").len() >= 2
    });
    assert!(
        calls(&case, "cargo").is_empty(),
        "a failed fetch builds nothing"
    );
    assert!(
        calls(&case, "git")
            .iter()
            .all(|call| call["args"][0] != "rev-parse"),
        "a failed fetch resolves nothing"
    );
    assert!(
        calls(&case, "aws")
            .iter()
            .all(|call| call["op"] != "put-object"),
        "a failed fetch stores nothing"
    );
    fs::remove_file(case.dir.join("git.fetch.fail")).expect("a working fetch");
    case.wait_for("the remote head", |case| published(case, &remote));
    let output = stop(publisher);
    assert!(case.object(&format!("commits/{stale}.json")).is_none());
    assert_eq!(calls(&case, "cargo").len(), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unable to access the remote"), "{stderr}");
}

/// The publisher removes the built binary's path as one file before it
/// builds, so a directory there stays with its contents and the head is
/// tried again at the next interval.
fn a_directory_at_the_built_binary_is_kept_and_nothing_builds() {
    let case = Case::new("publish-binary-dir");
    let head = "e".repeat(40);
    let program = case.dir.join("checkout/target/release/campaign");
    fs::create_dir_all(&program).expect("a directory at the binary's path");
    fs::write(program.join("sentinel"), "x").expect("a sentinel");
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    let publisher = publish(&case);
    case.wait_for("two fetches", |case| {
        calls(case, "git")
            .iter()
            .filter(|call| call["args"][0] == "fetch")
            .count()
            >= 2
    });
    let output = stop(publisher);
    assert!(calls(&case, "cargo").is_empty(), "nothing builds");
    assert_eq!(
        fs::read(program.join("sentinel")).expect("the sentinel"),
        b"x"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&program.display().to_string()), "{stderr}");
    assert!(case.object(&format!("commits/{head}.json")).is_none());
}

fn a_skipped_head_is_tried_again_when_main_returns_to_it() {
    let case = Case::new("publish-return");
    let heads = ["1".repeat(40), "2".repeat(40)];
    fs::write(case.dir.join("git.head"), &heads[0]).expect("the head");
    fs::write(case.dir.join("git.dirty"), " M crates/a.rs\n").expect("a dirty checkout");
    let publisher = publish(&case);
    case.wait_for("the dirty checkout to be read", |case| {
        calls(case, "git")
            .iter()
            .any(|call| call["args"][0] == "status")
    });
    fs::write(case.dir.join("git.dirty"), "").expect("a clean checkout");
    fs::write(case.dir.join("git.head"), &heads[1]).expect("the next head");
    case.wait_for("the second head", |case| published(case, &heads[1]));
    assert!(case.object(&format!("commits/{}.json", heads[0])).is_none());
    fs::write(case.dir.join("git.head"), &heads[0]).expect("the first head again");
    case.wait_for("the first head", |case| published(case, &heads[0]));
    stop(publisher);
}

fn a_published_build_is_fetched_and_swept() {
    let case = Case::new("publish-run");
    let head = "9".repeat(40);
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    let publisher = publish(&case);
    case.wait_for("current.json", |case| published(case, &head));
    stop(publisher);
    let mut document = Case::assignment(&"0".repeat(64), &["a"], 1);
    document.as_object_mut().expect("an object").remove("build");
    case.put("assignment.json", document.to_string().as_bytes());
    let build = sim_host::file::sha256(fake::build_record(&case.dir, &head).as_bytes());
    let runner = case.start();
    case.wait_for("a sweep of the published build", |case| {
        case.events("sweep", "start")
            .iter()
            .any(|entry| arg(entry, "--archive").contains(&build))
    });
    stop(runner);
    let probes = case.events("campaign", "capabilities");
    assert_eq!(probes.len(), 1, "the fetch checked the archive once");
    let record = read_json(&sim_host::build::record(&case.state(), &build));
    assert_eq!(record["commit"], head);
}

fn two_runner_states_fetch_one_build_and_name_the_same_build() {
    let case = Case::new("two-hosts");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let other = Metadata::serve(Some("i-0000000b"));
    let second = case.dir.join("state2");
    let cgroup = case.dir.join("cgroup2");
    make_cgroup(&cgroup);
    let first = case.start();
    let next = case.start_at(&second, &cgroup, &other);
    let swept = |state: &Path| {
        let health = state.join("health.json");
        health.exists() && read_json(&health)["build"] == build.as_str()
    };
    case.wait_for("both hosts on the build", |case| {
        swept(&case.state()) && swept(&second)
    });
    stop(first);
    stop(next);
    let one = fs::read(sim_host::build::archive(&case.state(), &build).join("build"))
        .expect("the first host's archive");
    let two = fs::read(sim_host::build::archive(&second, &build).join("build"))
        .expect("the second host's archive");
    assert_eq!(one, two);
    assert_eq!(sim_host::file::sha256(&one), build);
    let roots: Vec<String> = [case.state(), second.clone()]
        .iter()
        .map(|state| {
            read_json(&state.join("health.json"))["root"]
                .as_str()
                .expect("a root")
                .to_owned()
        })
        .collect();
    assert!(
        roots[0].contains("i-0000000a") && roots[1].contains("i-0000000b"),
        "{roots:?}"
    );
}

fn builds_left(case: &Case) -> Vec<String> {
    let mut left: Vec<String> = fs::read_dir(sim_host::build::builds(&case.state()))
        .expect("the builds directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    left.sort();
    left
}

fn tar_of(dir: &Path, member: &str) -> Vec<u8> {
    let tarball = dir.join("custom.tar");
    let status = Command::new("tar")
        .arg("-cf")
        .arg(&tarball)
        .arg("-C")
        .arg(dir)
        .arg(member)
        .status()
        .expect("tar runs");
    assert!(status.success(), "the archive is packed");
    fs::read(tarball).expect("the tar")
}

fn linked_archive(case: &Case) -> Vec<u8> {
    let source = case.dir.join("sources/linked");
    fs::create_dir_all(source.join("archive")).expect("the archive directory");
    fs::write(source.join("archive/build"), "one").expect("the build record");
    fs::write(source.join("archive/worker"), "worker").expect("the worker");
    std::os::unix::fs::symlink("/etc/hostname", source.join("archive/link")).expect("a link");
    tar_of(&source, "archive")
}

fn each_refused_download_leaves_no_final_directory() {
    type Damage = fn(&mut Case, &str);
    let variants: [(&str, Damage, &str); 8] = [
        (
            "link",
            |case, build| {
                let tar = linked_archive(case);
                case.put(&format!("builds/{build}/archive.tar"), &tar);
            },
            "tar type '2'",
        ),
        (
            "compressed",
            |case, build| {
                let tar = case.archive_tar("one", "worker");
                let mut gzip = Command::new("gzip")
                    .arg("-c")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .expect("gzip runs");
                gzip.stdin
                    .take()
                    .expect("stdin")
                    .write_all(&tar)
                    .expect("the tar is written");
                let output = gzip.wait_with_output().expect("gzip ends");
                case.put(&format!("builds/{build}/archive.tar"), &output.stdout);
            },
            "no uncompressed ustar archive",
        ),
        (
            "reserve",
            |case, _| case.disk_reserve = u64::MAX / 2,
            "with a reserve of",
        ),
        (
            "checksum",
            |case, build| {
                let key = format!("builds/{build}/archive.tar");
                fs::write(
                    fake::checksum_path(&case.bucket(), &key),
                    fake::digest64(b"other bytes"),
                )
                .expect("a stored checksum of other bytes");
            },
            "did not match",
        ),
        (
            "identity",
            |case, build| {
                case.put(
                    &format!("builds/{build}/archive.tar"),
                    &case.archive_tar("other", "worker"),
                );
            },
            "is not build",
        ),
        (
            "binary",
            |case, build| {
                let mut other = executable().to_vec();
                other.push(b'x');
                case.put(&format!("builds/{build}/campaign"), &other);
            },
            "differs from its recorded SHA-256",
        ),
        (
            "worker",
            |case, build| {
                case.put(
                    &format!("builds/{build}/archive.tar"),
                    &case.archive_tar("one", "damaged"),
                );
            },
            "capabilities refused the archive",
        ),
        (
            "oversized",
            |case, _| fs::write(case.dir.join("aws.huge"), "").expect("a huge object"),
            "past",
        ),
    ];
    for (name, damage, text) in variants {
        let mut case = Case::new(&format!("refused-{name}"));
        let build = case.build("one");
        damage(&mut case, &build);
        case.assign(&build, &["a"], 1);
        let runner = case.start();
        case.wait_for("the refused download", |case| {
            case.health_now()["fetch_error"]
                .as_str()
                .is_some_and(|error| error.contains(text))
        });
        stop(runner);
        assert!(
            builds_left(&case).is_empty(),
            "{name}: {:?}",
            builds_left(&case)
        );
        assert!(case.events("sweep", "start").is_empty(), "{name}");
    }
}

fn a_failed_download_keeps_the_host_on_its_build() {
    let case = Case::new("keep-build");
    let first = case.build("one");
    let second = case.build("two");
    case.put(
        &format!("builds/{second}/archive.tar"),
        &case.archive_tar("other", "worker"),
    );
    case.assign(&first, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    case.assign(&second, &["a"], 1);
    case.wait_for("the refused download", |case| {
        case.health_now()["fetch_error"]
            .as_str()
            .is_some_and(|error| error.contains("is not build"))
    });
    let starts = case.events("sweep", "start").len();
    case.wait_for("three more stints", |case| {
        case.events("sweep", "start").len() >= starts + 3
    });
    let mut moved = commit(&first);
    moved["campaign"] = json!(sim_host::file::sha256(b"another binary"));
    case.put("current.json", moved.to_string().as_bytes());
    case.wait_for("the refused record", |case| {
        case.health_now()["fetch_error"]
            .as_str()
            .is_some_and(|error| error.contains("differs from its recorded SHA-256"))
    });
    let starts = case.events("sweep", "start").len();
    case.wait_for("two more stints", |case| {
        case.events("sweep", "start").len() >= starts + 2
    });
    stop(runner);
    assert!(
        case.events("sweep", "start")
            .iter()
            .all(|entry| arg(entry, "--archive").contains(&first)),
        "every stint swept the build on disk"
    );
    assert_eq!(builds_left(&case), std::slice::from_ref(&first));
    assert_eq!(
        sim_host::file::sha256(
            &fs::read(sim_host::build::campaign(&case.state(), &first)).expect("the binary")
        ),
        sim_host::file::sha256(executable())
    );
}

fn root_of(case: &Case, build: &str) -> Option<String> {
    case.events("sweep", "start").iter().find_map(|start| {
        arg(start, "--archive")
            .contains(build)
            .then(|| arg(start, "--campaign"))
    })
}

fn every_stint_sweeps_through_a_store_outage_and_the_stored_objects_match_after() {
    let case = Case::new("outage");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1 1 1 1 1 1 1 1 1 1 1 1 1 1");
    case.script("sweep.cpu", &"5000 ".repeat(40));
    let runner = case.start();
    case.wait_for("a first upload", |case| {
        root_of(case, &build)
            .is_some_and(|root| case.object(&format!("roots/{root}/status.json")).is_some())
    });
    let root = root_of(&case, &build).expect("a root");
    fs::write(case.dir.join("aws.fail"), "").expect("an outage");
    let began = sim_host::host::now_s();
    let started = fake::now_ms();
    let before = case.events("sweep", "exit").len();
    case.wait_for("three stints in the outage", |case| {
        case.events("sweep", "exit").len() >= before + 4
            && case.health_now()["upload_error"].is_string()
    });
    fs::remove_file(case.dir.join("aws.fail")).expect("the outage ends");
    let ended = fake::now_ms();
    case.wait_for("an upload after the outage", |case| {
        case.health_now()["upload_error"].is_null()
            && case.events("sweep", "exit").len() >= before + 6
    });
    stop(runner);
    let during = case
        .events("sweep", "start")
        .iter()
        .filter(|start| (started..ended).contains(&time(start)))
        .count();
    assert!(during >= 3, "{during} stints started during the outage");
    let dir = case.state().join("roots").join(&root);
    let list = fs::read(dir.join("suspects.jsonl")).expect("the root's list");
    let complete = list
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |at| at + 1);
    assert_eq!(
        case.object(&format!("roots/{root}/suspects.jsonl"))
            .as_deref(),
        Some(&list[..complete]),
        "the stored list is the root's list up to its last complete line"
    );
    let status: Value = serde_json::from_slice(
        &case
            .object(&format!("roots/{root}/status.json"))
            .expect("the status"),
    )
    .expect("an envelope");
    let recorded = &case.runner_state()["roots"][&root];
    assert_eq!(status["build"], build.as_str());
    assert_eq!(status["host"], "i-0000000a");
    assert_eq!(status["campaign"], root.as_str());
    for (field, kept) in [
        ("stint", "stints"),
        ("cpu_usec", "cpu_usec"),
        ("capacity_usec", "capacity_usec"),
    ] {
        assert_eq!(status[field], recorded[kept], "{field}");
    }
    assert!(status["written"].is_u64());
    assert!(status["cpu_usec"].as_u64().is_some_and(|cpu| cpu > 0));
    assert_eq!(
        case.object(&format!("roots/{root}/findings.json")),
        Some(
            fs::read(
                case.state()
                    .join("uploads")
                    .join(&root)
                    .join("findings.json")
            )
            .expect("the local listing")
        )
    );
    let runs: u64 = fs::read_to_string(dir.join("runs"))
        .expect("the runs")
        .trim()
        .parse()
        .expect("a count");
    assert_eq!(status["sweep_status"]["runs"], runs);
    assert!(status["sweep_status"]["runs"].as_u64().is_some());
    assert_eq!(status["stint_seconds"], 1, "the assigned stint length");
    let (_, _, output, stderr) = report(&case, &[]);
    let row = &output["roots"][&root];
    assert_eq!(row["build"], build.as_str(), "{stderr}{output:#}");
    assert_eq!(row["stint_seconds"], 1);
    assert_eq!(row["host"], "i-0000000a");
    assert!(row["stint"].is_u64(), "{row:#}");
    let written = row["written"].as_u64().expect("a written second");
    assert!(
        (began..=sim_host::host::now_s()).contains(&written),
        "{written} is a Unix second of the run"
    );
    assert!(
        row["cpu_usec"].is_u64() && row["capacity_usec"].is_u64(),
        "{row:#}"
    );
    let puts: Vec<String> = case
        .events("aws", "call")
        .iter()
        .filter(|call| call["op"] == "put-object")
        .filter_map(|call| {
            call["key"]
                .as_str()?
                .strip_prefix(&format!("roots/{root}/"))
                .map(str::to_owned)
        })
        .collect();
    let statuses: Vec<usize> = (0..puts.len())
        .filter(|&index| puts[index] == "status.json")
        .collect();
    assert!(!statuses.is_empty(), "{puts:?}");
    for index in statuses {
        assert_eq!(
            puts[index.saturating_sub(2)..index],
            ["suspects.jsonl", "findings.json"],
            "status.json goes after the list and the findings: {puts:?}"
        );
    }
}

fn the_last_stint_is_uploaded_at_a_stop() {
    let case = Case::new("last-stint");
    let build = case.build("one");
    case.assign(&build, &["a"], 30);
    case.script("sweep.suspects", "3");
    let runner = case.start();
    case.wait_for("a running sweep", |case| {
        !case.events("sweep", "start").is_empty()
    });
    std::thread::sleep(Duration::from_millis(500));
    stop(runner);
    let root = root_of(&case, &build).expect("a root");
    let list = fs::read(
        case.state()
            .join("roots")
            .join(&root)
            .join("suspects.jsonl"),
    )
    .expect("the root's list");
    assert_eq!(
        case.object(&format!("roots/{root}/suspects.jsonl")),
        Some(list)
    );
    let status: Value = serde_json::from_slice(
        &case
            .object(&format!("roots/{root}/status.json"))
            .expect("the status"),
    )
    .expect("an envelope");
    assert_eq!(status["stint"], 1);
    assert_eq!(
        status["capacity_usec"],
        case.runner_state()["roots"][&root]["capacity_usec"]
    );
    assert_eq!(case.health()["phase"], "stopped");
}

fn a_stop_during_a_hung_store_call_exits_promptly() {
    let case = Case::new("hung-store");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    let calls_before = calls(&case, "aws").len();
    fs::write(case.dir.join("aws.hang"), "").expect("a hung store");
    case.wait_for("a hung call", |case| {
        calls(case, "aws").len() > calls_before
    });
    std::thread::sleep(Duration::from_millis(300));
    let asked = fake::now_ms();
    signal(&runner, libc::SIGTERM);
    fs::remove_file(case.dir.join("aws.hang")).expect("the store answers again");
    let mut child = runner.take();
    let until = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("the runner's status").is_none() {
        assert!(Instant::now() < until, "the runner waited on the hung call");
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().expect("the output");
    assert!(output.status.success(), "{output:?}");
    assert!(fake::now_ms() - asked < 30_000);
    assert_eq!(case.health()["phase"], "stopped");
}

fn uploaded(case: &Case, root: &str) -> bool {
    case.object(&format!("roots/{root}/suspects.jsonl"))
        .is_some_and(|list| !list.is_empty())
        && case
            .events("confirm", "exit")
            .iter()
            .any(|exit| exit["code"] == 0)
}

fn recorded(case: &Case, root: &str) -> bool {
    case.runner_state()["roots"]
        .as_object()
        .expect("roots")
        .contains_key(root)
}

fn an_old_root_is_deleted_when_all_four_conditions_hold() {
    let case = Case::new("delete");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 1);
    case.script("sweep.suspects", "1");
    let runner = case.start();
    case.wait_for("an uploaded, confirmed first root", |case| {
        root_of(case, &first).is_some_and(|root| uploaded(case, &root))
    });
    let old = root_of(&case, &first).expect("the first root");
    case.assign(&second, &["a"], 1);
    case.wait_for("the old root's deletion", |case| {
        root_of(case, &second).is_some() && !recorded(case, &old)
    });
    std::thread::sleep(Duration::from_millis(1_500));
    stop(runner);
    let new = root_of(&case, &second).expect("the second root");
    assert_eq!(case.roots(), std::slice::from_ref(&new));
    assert!(!case.state().join("uploads").join(&old).exists());
    let nonce = old.rsplit('.').next().expect("a nonce");
    assert!(
        !case.dir.join("cgroup/confirm").join(nonce).exists(),
        "the old root's confirmation cgroup is removed"
    );
    assert_eq!(
        builds_left(&case),
        std::slice::from_ref(&second),
        "the old build is deleted"
    );
    assert!(
        case.object(&format!("roots/{old}/status.json")).is_some(),
        "the stored objects stay"
    );
}

fn assert_stays(case: &Case, old: &str, build: &str) {
    assert!(case.roots().contains(&old.to_owned()), "{:?}", case.roots());
    let root = &case.runner_state()["roots"][old];
    assert!(root.is_object());
    assert_eq!(root["deleting"], false);
    assert!(
        sim_host::build::dir(&case.state(), build).exists(),
        "the build of a kept root stays"
    );
}

fn an_old_root_of_the_assigned_build_stays() {
    let case = Case::new("stays-build");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.codes", "0 2 3 4");
    let runner = case.start();
    case.wait_for("an upload of the second root", |case| {
        let starts = case.events("sweep", "start");
        starts.len() >= 6
            && case
                .object(&format!(
                    "roots/{}/status.json",
                    arg(&starts[5], "--campaign")
                ))
                .is_some()
    });
    let applied = case.events("sweep", "start").len();
    case.wait_for("two more stints", |case| {
        case.events("sweep", "start").len() >= applied + 2
    });
    stop(runner);
    let starts = case.events("sweep", "start");
    let old = arg(&starts[0], "--campaign");
    assert_ne!(arg(&starts[5], "--campaign"), old);
    assert_stays(&case, &old, &build);
}

fn an_old_root_with_unread_suspect_lines_stays() {
    let case = Case::new("stays-unread");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 1);
    case.script("sweep.suspects", "2");
    case.script("confirm.codes", &"3 ".repeat(50));
    let runner = case.start();
    case.wait_for("an uploaded first root", |case| {
        root_of(case, &first).is_some_and(|root| {
            case.object(&format!("roots/{root}/suspects.jsonl"))
                .is_some_and(|list| !list.is_empty())
        })
    });
    let old = root_of(&case, &first).expect("the first root");
    case.assign(&second, &["a"], 1);
    case.wait_for("three stints of the second build", |case| {
        case.events("sweep", "start")
            .iter()
            .filter(|start| arg(start, "--archive").contains(&second))
            .count()
            >= 3
    });
    stop(runner);
    assert_stays(&case, &old, &first);
}

fn an_old_root_with_an_unresolved_finding_stays() {
    let case = Case::new("stays-finding");
    let first = case.build("one");
    let second = case.build("two");
    fs::write(
        case.dir.join("findings.json"),
        r#"{"findings":[{"id":"f1","resolved":false}],"release_blockers":[]}"#,
    )
    .expect("an unresolved finding");
    case.assign(&first, &["a"], 1);
    case.script("sweep.suspects", "1");
    let runner = case.start();
    case.wait_for("an uploaded, confirmed first root", |case| {
        root_of(case, &first).is_some_and(|root| {
            uploaded(case, &root)
                && case
                    .object(&format!("roots/{root}/findings.json"))
                    .is_some_and(|findings| findings.starts_with(b"{\"findings\":[{"))
        })
    });
    let old = root_of(&case, &first).expect("the first root");
    case.assign(&second, &["a"], 1);
    case.wait_for("three stints of the second build", |case| {
        case.events("sweep", "start")
            .iter()
            .filter(|start| arg(start, "--archive").contains(&second))
            .count()
            >= 3
    });
    assert_stays(&case, &old, &first);
    fs::remove_file(case.dir.join("findings.json")).expect("the finding is resolved");
    case.wait_for("the deletion of the resolved root", |case| {
        !recorded(case, &old)
    });
    stop(runner);
    assert_eq!(
        case.object(&format!("roots/{old}/findings.json"))
            .as_deref(),
        Some(sim_host::snapshot::NO_FINDINGS.as_bytes()),
        "the bucket holds the root's last listing"
    );
}

fn an_old_root_is_confirmed_after_its_build_changes_and_then_deleted() {
    let case = Case::new("old-confirm");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 1);
    case.script("sweep.suspects", "2");
    case.script("confirm.codes", &"3 ".repeat(200));
    let runner = case.start();
    case.wait_for("a failed confirm", |case| {
        !case.events("confirm", "exit").is_empty()
    });
    let old = root_of(&case, &first).expect("the first root");
    case.assign(&second, &["a"], 1);
    case.wait_for("a sweep of the second build", |case| {
        root_of(case, &second).is_some()
    });
    let next = case.events("confirm", "start").len();
    case.script(
        "confirm.codes",
        &format!("{}{}", "3 ".repeat(next), "0 ".repeat(50)),
    );
    case.wait_for("the old root's deletion", |case| !recorded(case, &old));
    stop(runner);
    let drained = case
        .events("confirm", "start")
        .into_iter()
        .zip(case.events("confirm", "exit"))
        .find(|(_, exit)| exit["code"] == 0)
        .map(|(start, _)| start)
        .expect("a confirm that succeeded");
    assert!(arg(&drained, "--root").ends_with(&old));
    assert_eq!(
        arg(&drained, "--archive"),
        sim_host::build::archive(&case.state(), &first)
            .to_str()
            .expect("a text path"),
        "the old root is confirmed with its own archive"
    );
    assert!(
        drained["program"]
            .as_str()
            .is_some_and(|program| program.contains(&first)),
        "and with its own binary: {drained}"
    );
    let new = root_of(&case, &second).expect("the second root");
    assert!(
        case.events("sweep", "start")
            .iter()
            .any(|start| arg(start, "--campaign") == new && time(start) < time(&drained)),
        "the old root was confirmed after the new root opened"
    );
    assert!(!sim_host::build::dir(&case.state(), &first).exists());
}

fn a_root_without_a_sweep_is_deleted_when_its_build_changes() {
    let case = Case::new("dead-root");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 1);
    case.script("sweep.codes", "2 2 2");
    let runner = case.start();
    case.wait_for("a second root", |case| {
        let starts = case.events("sweep", "start");
        starts.len() >= 4 && arg(&starts[3], "--campaign") != arg(&starts[0], "--campaign")
    });
    let dead = arg(&case.events("sweep", "start")[0], "--campaign");
    assert!(!case.state().join("roots").join(&dead).exists());
    assert!(recorded(&case, &dead));
    case.assign(&second, &["a"], 1);
    case.wait_for("the dead root's deletion", |case| !recorded(case, &dead));
    stop(runner);
}

fn a_foreign_root_is_neither_uploaded_nor_deleted() {
    let case = Case::new("foreign-store");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 1);
    case.script("sweep.suspects", "2");
    let runner = case.start();
    case.wait_for("an uploaded, confirmed first root", |case| {
        root_of(case, &first).is_some_and(|root| uploaded(case, &root))
    });
    stop(runner);
    let old = root_of(&case, &first).expect("the first root");
    let stored = snapshot(&case.bucket().join("roots").join(&old));
    let before = calls(&case, "aws").len();
    let path = case.state().join("state.json");
    let mut state = read_json(&path);
    state["current"] = Value::Null;
    state["roots"][&old]["deleting"] = json!(true);
    fs::write(&path, serde_json::to_vec(&state).expect("a state")).expect("the state");
    case.metadata.set("i-0000000b");
    case.assign(&second, &["a"], 1);
    let runner = case.start();
    case.wait_for("an upload of the new root and two more stints", |case| {
        root_of(case, &second).is_some_and(|root| {
            case.object(&format!("roots/{root}/status.json")).is_some()
                && case
                    .events("sweep", "start")
                    .iter()
                    .filter(|start| arg(start, "--campaign") == root)
                    .count()
                    >= 3
        })
    });
    stop(runner);
    assert!(case.roots().contains(&old), "{:?}", case.roots());
    assert_eq!(case.runner_state()["roots"][&old]["deleting"], true);
    assert!(sim_host::build::dir(&case.state(), &first).exists());
    assert_eq!(snapshot(&case.bucket().join("roots").join(&old)), stored);
    let prefix = format!("roots/{old}/");
    assert!(
        calls(&case, "aws")[before..]
            .iter()
            .all(|call| !call["key"].as_str().expect("a key").starts_with(&prefix)),
        "no store call names the foreign root"
    );
}

fn a_failed_snapshot_command_keeps_the_stored_objects() {
    let case = Case::new("snapshot-fail");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1 1 1 1 1 1 1 1 1 1 1 1");
    let runner = case.start();
    case.wait_for("an uploaded, confirmed root", |case| {
        root_of(case, &build).is_some_and(|root| {
            uploaded(case, &root)
                && case
                    .object(&format!("roots/{root}/findings.json"))
                    .is_some()
        })
    });
    let root = root_of(&case, &build).expect("a root");
    for (name, text) in [
        ("sweep-status.fail", "sweep-status"),
        ("findings.fail", "findings"),
    ] {
        fs::write(case.dir.join(name), "").expect("a failing command");
        case.wait_for("the named failure", |case| {
            case.health_now()["upload_error"]
                .as_str()
                .is_some_and(|error| error.contains(&format!("campaign {text}")))
        });
        let stored = snapshot(&case.bucket().join("roots").join(&root));
        let starts = case.events("sweep", "start").len();
        case.wait_for("two more stints", |case| {
            case.events("sweep", "start").len() >= starts + 2
        });
        assert_eq!(
            snapshot(&case.bucket().join("roots").join(&root)),
            stored,
            "{name}: the stored objects stay"
        );
        fs::remove_file(case.dir.join(name)).expect("the command recovers");
        case.wait_for("an upload after the failure", |case| {
            case.health_now()["upload_error"].is_null()
                && snapshot(&case.bucket().join("roots").join(&root)) != stored
        });
    }
    stop(runner);
}

fn a_stray_entry_under_builds_leaves_the_runner_sweeping() {
    let case = Case::new("stray");
    let builds = sim_host::build::builds(&case.state());
    sim_host::file::private_dir(&builds).expect("the builds directory");
    fs::write(builds.join("stray"), "a file").expect("a stray file");
    fs::write(builds.join(".trash-left"), "a file").expect("a stray trash file");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("two stints", |case| case.events("sweep", "exit").len() >= 2);
    stop(runner);
    assert!(builds.join("stray").exists(), "an unknown entry stays");
    assert!(!builds.join(".trash-left").exists(), "trash is removed");
    assert!(case.health()["cleanup_error"].is_null());
}

fn blocked_by_a_failed_check(case: &Case) -> (Running, String, String) {
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 1);
    case.script("sweep.suspects", "1");
    let runner = case.start();
    case.wait_for("an uploaded, confirmed first root", |case| {
        root_of(case, &first).is_some_and(|root| uploaded(case, &root))
    });
    let old = root_of(case, &first).expect("the first root");
    fs::write(
        case.dir
            .join(format!("aws.fail.head-object.roots_{old}_status.json")),
        "",
    )
    .expect("the stored check fails");
    case.assign(&second, &["a"], 1);
    case.wait_for(
        "three stints of the second build and a named check failure",
        |case| {
            case.events("sweep", "start")
                .iter()
                .filter(|start| arg(start, "--archive").contains(&second))
                .count()
                >= 3
                && case.health_now()["upload_error"]
                    .as_str()
                    .is_some_and(|error| error.contains(&format!("roots/{old}/status.json")))
        },
    );
    (runner, old, first)
}

fn an_old_root_whose_stored_objects_differ_stays_until_they_match() {
    let case = Case::new("stays-stored");
    let (runner, old, first) = blocked_by_a_failed_check(&case);
    assert_stays(&case, &old, &first);
    case.put(&format!("roots/{old}/status.json"), b"{\"changed\": true}");
    fs::remove_file(
        case.dir
            .join(format!("aws.fail.head-object.roots_{old}_status.json")),
    )
    .expect("the check answers");
    case.wait_for("the deletion once the objects match", |case| {
        !recorded(case, &old)
    });
    stop(runner);
    assert!(!case.roots().contains(&old));
    let stored = case
        .object(&format!("roots/{old}/status.json"))
        .expect("the stored status");
    assert!(
        !stored.starts_with(b"{\"changed\""),
        "the differing object was stored again before the deletion"
    );
}

fn the_next_pass_finishes_an_interrupted_deletion() {
    let case = Case::new("interrupted");
    let (runner, old, first) = blocked_by_a_failed_check(&case);
    stop(runner);
    let current = case.runner_state()["current"].clone();
    let path = case.state().join("state.json");
    let mut state = read_json(&path);
    state["roots"][&old]["deleting"] = json!(true);
    fs::write(&path, serde_json::to_vec(&state).expect("a state")).expect("the state");
    let roots = case.state().join("roots");
    fs::rename(roots.join(&old), roots.join(format!(".trash-{old}"))).expect("a renamed root");
    let trash = roots.join(".trash-left");
    fs::create_dir_all(trash.join("inner")).expect("a half-removed root");
    let runner = case.start();
    case.wait_for("the finished deletion", |case| {
        !recorded(case, &old)
            && !roots.join(format!(".trash-{old}")).exists()
            && !trash.exists()
            && !sim_host::build::dir(&case.state(), &first).exists()
    });
    stop(runner);
    assert!(!case.state().join("uploads").join(&old).exists());
    assert_eq!(case.runner_state()["current"], current);
    assert!(roots.join(current.as_str().expect("a root")).exists());
}

fn a_cut_after_the_commit_record_is_repaired_without_a_rebuild() {
    let case = Case::new("publish-repair");
    let head = "5".repeat(40);
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    fs::write(case.dir.join("aws.fail.put-object.current.json"), "").expect("a failing put");
    let publisher = publish(&case);
    case.wait_for("a failed pointer put after the commit record", |case| {
        case.object(&format!("commits/{head}.json")).is_some() && puts(case, "current.json") >= 1
    });
    assert!(case.object("current.json").is_none());
    fs::remove_file(case.dir.join("aws.fail.put-object.current.json")).expect("the put works");
    case.wait_for("the repaired pointer", |case| published(case, &head));
    assert!(
        fs::read_dir(case.dir.join("publisher/publish")).is_ok_and(|mut dir| dir.next().is_none()),
        "the repair pass leaves no work directory"
    );
    stop(publisher);
    assert_eq!(calls(&case, "cargo").len(), 1, "the head is built once");
    assert_eq!(puts(&case, &format!("commits/{head}.json")), 1);
}

fn an_interrupted_archive_is_retried_and_a_malformed_head_publishes_nothing() {
    let case = Case::new("publish-retry");
    let head = "6".repeat(40);
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    case.script("archive.codes", "5 0");
    let publisher = publish(&case);
    case.wait_for("current.json", |case| published(case, &head));
    assert_eq!(case.events("campaign", "archive-failed").len(), 1);
    assert_eq!(case.events("campaign", "archive").len(), 1);
    fs::write(case.dir.join("git.head"), "main").expect("a malformed head");
    std::thread::sleep(Duration::from_millis(2_500));
    let (output, _) = ended(publisher, libc::SIGTERM);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no commit id"),
        "{output:?}"
    );
    assert!(case.object("commits/main.json").is_none());
}

fn a_second_publisher_on_one_state_exits_at_once() {
    let case = Case::new("publish-second");
    let head = "7".repeat(40);
    fs::write(case.dir.join("git.head"), &head).expect("the head");
    let first = publish(&case);
    case.wait_for("current.json", |case| published(case, &head));
    let second = publish(&case)
        .take()
        .wait_with_output()
        .expect("the second ends");
    assert_eq!(second.status.code(), Some(2), "{second:?}");
    assert!(String::from_utf8_lossy(&second.stderr).contains("another publisher"));
    stop(first);
    assert_eq!(calls(&case, "cargo").len(), 1);
}

fn an_oversized_assignment_leaves_the_stored_copy_in_force() {
    let case = Case::new("oversized-document");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    let mut document = Case::assignment(&build, &["c"], 1);
    document.as_object_mut().expect("an object").remove("build");
    let mut padded = document.to_string().into_bytes();
    padded.extend(std::iter::repeat_n(b' ', 1 << 20));
    case.put("assignment.json", &padded);
    let starts = case.events("sweep", "start").len();
    case.wait_for("a stint from the copy", |case| {
        case.events("sweep", "start").len() > starts + 1
            && case.health_now()["assignment_error"]
                .as_str()
                .is_some_and(|error| error.contains("more than"))
    });
    stop(runner);
    assert!(
        case.events("sweep", "start")
            .iter()
            .all(|entry| arg(entry, "--profiles") == "a")
    );
    assert!(
        calls(&case, "aws")
            .iter()
            .filter(|call| call["key"] == "assignment.json")
            .all(|call| call["range"] == format!("bytes=0-{}", 1 << 20)),
        "every read asks for a bounded range"
    );
    assert!(
        fs::read_dir(case.state().join("store")).is_ok_and(|mut dir| dir.next().is_none()),
        "no download is left in the scratch directory"
    );
}

fn an_assignment_download_that_leaves_no_file_names_its_key_once() {
    let case = Case::new("document-no-file");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    fs::write(case.dir.join("aws.nowrite.prefix"), "assignment.json").expect("a download control");
    case.wait_for("an assignment error", |case| {
        case.health_now()["assignment_error"].is_string()
    });
    let error = case.health_now()["assignment_error"].clone();
    stop(runner);
    assert_eq!(error, "assignment.json: the download left no file");
}

fn a_failed_fetch_waits_a_stint_and_stale_staging_is_removed() {
    let case = Case::new("fetch-wait");
    let first = case.build("one");
    let second = case.build("two");
    case.put(
        &format!("builds/{second}/archive.tar"),
        &case.archive_tar("other", "worker"),
    );
    let stale = sim_host::build::builds(&case.state()).join(format!(".fetch-{}", "0".repeat(64)));
    fs::create_dir_all(stale.join("archive")).expect("stale staging");
    fs::write(stale.join("archive/build"), "left").expect("a staged file");
    case.assign(&first, &["a"], 6);
    let runner = case.start();
    case.wait_for("a stint and the stale staging removed", |case| {
        !case.events("sweep", "start").is_empty() && !stale.exists()
    });
    case.assign(&second, &["a"], 6);
    case.wait_for("the refused download", |case| {
        case.health_now()["fetch_error"]
            .as_str()
            .is_some_and(|error| error.contains("is not build"))
    });
    let key = format!("builds/{second}/archive.tar");
    let gets = |case: &Case| {
        calls(case, "aws")
            .iter()
            .filter(|call| call["op"] == "get-object" && call["key"] == key)
            .count()
    };
    let failed = gets(&case);
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(gets(&case), failed, "the retry waits a stint");
    case.put(&key, &case.archive_tar("two", "worker"));
    case.wait_for("a sweep of the repaired build", |case| {
        root_of(case, &second).is_some()
    });
    stop(runner);
}

fn a_running_status_pairs_the_stint_with_its_work() {
    let case = Case::new("running-status");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.cpu", &"7000 ".repeat(40));
    let runner = case.start();
    let paired = |case: &Case| {
        let root = root_of(case, &build)?;
        let status: Value =
            serde_json::from_slice(&case.object(&format!("roots/{root}/status.json"))?).ok()?;
        let stint = status["stint"].as_u64()?;
        (stint >= 3).then(|| {
            (
                stint,
                status["sweep_status"]["runs"].as_u64(),
                status["cpu_usec"].as_u64(),
            )
        })
    };
    case.wait_for("a status of the third stint", |case| paired(case).is_some());
    let (stint, runs, cpu) = paired(&case).expect("a status");
    stop(runner);
    assert_eq!(runs, Some(10 * stint), "the work of the same stint");
    assert_eq!(cpu, Some(7000 * stint), "the CPU of the same stint");
}

fn a_failed_status_put_leaves_no_receipt_and_is_retried() {
    let case = Case::new("receipt");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1 1 1 1 1 1 1 1 1 1");
    let runner = case.start();
    case.wait_for("a first upload", |case| {
        root_of(case, &build)
            .is_some_and(|root| case.object(&format!("roots/{root}/status.json")).is_some())
    });
    let root = root_of(&case, &build).expect("a root");
    let fail = case
        .dir
        .join(format!("aws.fail.put-object.roots_{root}_status.json"));
    fs::write(&fail, "").expect("the status put fails");
    let receipt = case.state().join("uploads").join(&root).join("receipt");
    case.wait_for("a failed status put after the list's put", |case| {
        case.health_now()["upload_error"]
            .as_str()
            .is_some_and(|error| error.contains("status.json"))
            && !receipt.exists()
    });
    let list = case
        .object(&format!("roots/{root}/suspects.jsonl"))
        .expect("the stored list");
    let status = case
        .object(&format!("roots/{root}/status.json"))
        .expect("the stored status");
    let summarized: Value = serde_json::from_slice(&status).expect("an envelope");
    assert!(
        summarized["sweep_status"]["suspects"]
            .as_u64()
            .is_some_and(|lines| {
                lines <= list.iter().filter(|byte| **byte == b'\n').count() as u64
            }),
        "the stored status summarizes no more than the stored list"
    );
    fs::remove_file(&fail).expect("the put works");
    case.wait_for("a receipt after the retry", |_| receipt.exists());
    stop(runner);
}

fn a_damaged_commit_record_is_fetched_again() {
    let case = Case::new("record");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1");
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    let record = sim_host::build::record(&case.state(), &build);
    let gets = |case: &Case| {
        calls(case, "aws")
            .iter()
            .filter(|call| {
                call["op"] == "get-object" && call["key"] == format!("builds/{build}/archive.tar")
            })
            .count()
    };
    let before = gets(&case);
    let archive = sim_host::build::archive(&case.state(), &build);
    let inode = fs::metadata(&archive).expect("the archive").ino();
    fs::write(&record, "{").expect("a damaged record");
    case.wait_for("a repair of the record", |case| {
        sim_host::build::verify_recorded(&case.state(), &build).is_ok()
    });
    assert_eq!(
        gets(&case),
        before,
        "the record is repaired with no download"
    );
    assert_eq!(
        fs::metadata(&archive).expect("the archive").ino(),
        inode,
        "the archive a sweep uses stays in place"
    );
    let starts = case.events("sweep", "start").len();
    case.wait_for("sweeps after the repair", |case| {
        case.events("sweep", "start").len() > starts + 1
    });
    stop(runner);
}

fn a_hung_store_delays_each_stint_by_the_document_wait_only() {
    let case = Case::new("hung-docs");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("two stints", |case| case.events("sweep", "exit").len() >= 2);
    fs::write(case.dir.join("aws.hang"), "").expect("a hung store");
    let starts = case.events("sweep", "start").len();
    case.wait_for("two stints with the store hung", |case| {
        case.events("sweep", "start").len() >= starts + 2
    });
    let all = case.events("sweep", "start");
    let gap = time(&all[starts + 1]) - time(&all[starts]);
    fs::remove_file(case.dir.join("aws.hang")).expect("the store answers");
    stop(runner);
    assert!(
        (14_000..40_000).contains(&gap),
        "a stint waited {gap} ms for the documents"
    );
}

fn a_shortened_list_or_a_count_past_it_keeps_the_old_root() {
    for variant in ["shortened", "count"] {
        let case = Case::new(&format!("short-{variant}"));
        let first = case.build("one");
        let second = case.build("two");
        case.assign(&first, &["a"], 1);
        case.script("sweep.suspects", "2");
        let runner = case.start();
        case.wait_for("an uploaded, confirmed first root", |case| {
            root_of(case, &first).is_some_and(|root| uploaded(case, &root))
        });
        stop(runner);
        let old = root_of(&case, &first).expect("the first root");
        let dir = case.state().join("roots").join(&old);
        let stored = case
            .object(&format!("roots/{old}/suspects.jsonl"))
            .expect("the stored list");
        if variant == "shortened" {
            let list = fs::read(dir.join("suspects.jsonl")).expect("the list");
            let first_line = list.iter().position(|byte| *byte == b'\n').expect("a line") + 1;
            fs::write(dir.join("suspects.jsonl"), &list[..first_line]).expect("a shorter list");
            fs::write(dir.join("confirm/confirmed"), "1").expect("a matching count");
        } else {
            fs::write(dir.join("confirm/confirmed"), "9").expect("a count past the list");
        }
        case.assign(&second, &["a"], 1);
        let runner = case.start();
        case.wait_for("a named refusal", |case| {
            case.health_now()["upload_error"]
                .as_str()
                .is_some_and(|error| {
                    error.contains(&old)
                        && (error.contains("no longer starts") || error.contains("confirm counts"))
                })
        });
        stop(runner);
        assert_stays(&case, &old, &first);
        assert_eq!(
            case.object(&format!("roots/{old}/suspects.jsonl")),
            Some(stored),
            "{variant}: the stored list stays"
        );
    }
}

fn an_assignment_past_the_host_memory_blocks_the_stint() {
    let case = Case::new("memory");
    let build = case.build("one");
    let mut assignment = Case::assignment(&build, &["a"], 1);
    assignment["memory"] = json!(u64::MAX / 4);
    case.write_assignment(&assignment);
    let runner = case.start();
    case.wait_for("the blocked phase", |case| {
        let health = case.health_now();
        health["phase"] == "blocked"
            && health["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("bytes of memory"))
    });
    assert!(case.events("sweep", "start").is_empty());
    assignment["memory"] = json!(1 << 20);
    case.write_assignment(&assignment);
    case.wait_for("a sweep", |case| !case.events("sweep", "start").is_empty());
    stop(runner);
}

fn a_large_confirm_report_still_clears_pending() {
    let case = Case::new("big-report");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1");
    case.script("confirm.big", "");
    let runner = case.start();
    case.wait_for("a confirm that drained its queue", |case| {
        !case.events("confirm", "exit").is_empty() && case.current()["pending"] == false
    });
    stop(runner);
    let report = fs::metadata(case.state().join("logs/confirm.out")).expect("the report");
    assert!(
        report.len() > 64 << 10,
        "the report passes the diagnostic tail"
    );
}

fn an_old_root_whose_stored_checksum_differs_stays() {
    let case = Case::new("stays-checksum");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 1);
    case.script("sweep.suspects", "1");
    let runner = case.start();
    case.wait_for("an uploaded, confirmed first root", |case| {
        root_of(case, &first).is_some_and(|root| uploaded(case, &root))
    });
    let old = root_of(&case, &first).expect("the first root");
    let badsum = case.dir.join(format!("aws.badsum.roots_{old}_status.json"));
    fs::write(&badsum, "").expect("a stored checksum of other bytes");
    case.assign(&second, &["a"], 1);
    case.wait_for("three stints of the second build", |case| {
        case.events("sweep", "start")
            .iter()
            .filter(|start| arg(start, "--archive").contains(&second))
            .count()
            >= 3
    });
    assert_stays(&case, &old, &first);
    assert!(
        case.health_now()["upload_error"].is_null(),
        "a differing checksum is no failed check"
    );
    fs::remove_file(&badsum).expect("the checksums match");
    case.wait_for("the deletion once the checksums match", |case| {
        !recorded(case, &old)
    });
    stop(runner);
}

fn a_held_earlier_root_reaches_status() {
    let case = Case::new("held-earlier");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 2);
    case.script("sweep.suspects", "1");
    case.script("confirm.codes", "4 4 0");
    case.script("confirm.ms", "1000");
    let runner = case.start();
    case.wait_for("a running confirm", |case| {
        !case.events("confirm", "start").is_empty()
    });
    case.assign(&second, &["a"], 2);
    case.wait_for("an earlier root held", |case| {
        let health = case.health_now();
        health["held_roots"] == 1 && health["build"] == json!(second)
    });
    let (code, report) = case.status();
    assert_eq!(code, Some(2), "{report:#}");
    assert!(
        report["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("earlier root held")),
        "{report:#}"
    );
    case.wait_for("the earlier hold to clear", |case| {
        case.health_now()["held_roots"] == 0
    });
    stop(runner);
}

fn an_earlier_root_with_more_slots_waits_for_them() {
    let online = sim_host::host::online_cpus();
    assert!(online >= 4, "the case needs four CPUs");
    let mut case = Case::new("slot-gate");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.slots = 2;
    case.script("sweep.suspects", "1");
    case.script("confirm.ms", "60000");
    let runner = case.start();
    case.wait_for("a running confirm", |case| {
        !case.events("confirm", "start").is_empty()
    });
    stop(runner);
    let old = case.runner_state()["current"]
        .as_str()
        .expect("a root")
        .to_owned();
    case.slots = 1;
    let runner = case.start();
    let sweeps = case.events("sweep", "exit").len();
    case.wait_for("three stints with one slot", |case| {
        case.events("sweep", "exit").len() >= sweeps + 3
    });
    stop(runner);
    assert_eq!(
        case.events("confirm", "start").len(),
        1,
        "no confirm of the root"
    );
    case.slots = 2;
    let runner = case.start();
    case.wait_for("a confirm of the earlier root", |case| {
        case.events("confirm", "start").len() >= 2
    });
    stop(runner);
    let confirm = &case.events("confirm", "start")[1];
    assert!(arg(confirm, "--root").ends_with(&old));
    assert_eq!(arg(confirm, "--slots"), "2");
    let nonce = old.rsplit('.').next().expect("a nonce");
    assert!(arg(confirm, "--cgroup-root").ends_with(&format!("confirm/{nonce}")));
}

fn a_late_line_on_an_earlier_root_is_confirmed() {
    let case = Case::new("late-earlier");
    let first = case.build("one");
    let second = case.build("two");
    case.assign(&first, &["a"], 30);
    case.script("sweep.late", "1");
    case.script("sweep.late_delay", "3000");
    let runner = case.start();
    case.wait_for("the first sweep", |case| {
        !case.events("sweep", "start").is_empty()
    });
    let old = campaigns(&case.events("sweep", "start"))[0].clone();
    case.assign(&second, &["a"], 30);
    runner.kill();
    let runner = case.start();
    case.wait_for("a sweep of the second build", |case| {
        case.events("sweep", "start")
            .iter()
            .any(|entry| arg(entry, "--archive").contains(&second))
    });
    let root = case.state().join("roots").join(&old);
    case.wait_for("the late line confirmed", |_| {
        fs::read_to_string(root.join("confirm/confirmed")).is_ok_and(|text| text == "1")
    });
    stop(runner);
}

fn an_earlier_root_without_its_archive_records_a_failed_confirm() {
    let case = Case::new("earlier-archive");
    let first = case.build("one");
    let second = case.build("two");
    // An unresolved finding keeps the earlier root in `state.json` after
    // its confirm, so its confirmation reads back.
    fs::write(
        case.dir.join("findings.json"),
        r#"{"findings":[{"id":"f1","resolved":false}],"release_blockers":[]}"#,
    )
    .expect("an unresolved finding");
    case.assign(&first, &["a"], 3);
    case.script("sweep.late", "1");
    case.script("sweep.late_delay", "3000");
    let runner = case.start();
    case.wait_for("the first sweep", |case| {
        !case.events("sweep", "start").is_empty()
    });
    let old = campaigns(&case.events("sweep", "start"))[0].clone();
    case.assign(&second, &["a"], 3);
    runner.kill();
    fs::remove_dir_all(case.archive(&first)).expect("the first archive is removed");
    let runner = case.start();
    let confirmation = |case: &Case| {
        read_lenient(&case.state().join("state.json"))["roots"][&old]["confirmation"].clone()
    };
    case.wait_for("a failed confirmation of the earlier root", |case| {
        confirmation(case)["state"] == "failed"
    });
    let reason = confirmation(&case)["reason"].clone();
    assert!(
        reason
            .as_str()
            .is_some_and(|reason| reason.ends_with("archive/build is missing")),
        "{reason:#}"
    );
    let confirms_of_old = |case: &Case| {
        case.events("confirm", "start")
            .iter()
            .filter(|entry| arg(entry, "--root").ends_with(&old))
            .count()
    };
    assert_eq!(confirms_of_old(&case), 0);
    case.install("one");
    let root = case.state().join("roots").join(&old);
    case.wait_for("the late line confirmed", |_| {
        fs::read_to_string(root.join("confirm/confirmed")).is_ok_and(|text| text == "1")
    });
    case.wait_for("the earlier root idle again", |case| {
        confirmation(case)["state"] == "idle"
    });
    stop(runner);
    assert_eq!(confirms_of_old(&case), 1);
}

fn an_exited_confirm_keeps_its_outcome_at_shutdown() {
    let case = Case::new("exited-confirm");
    let build = case.build("one");
    case.assign(&build, &["a"], 30);
    case.script("sweep.suspects", "1");
    case.script("confirm.codes", "4");
    case.script("confirm.ms", "1500");
    let runner = case.start();
    case.wait_for("a running confirm", |case| {
        !case.events("confirm", "start").is_empty()
    });
    signal(&runner, libc::SIGSTOP);
    case.wait_for("the confirm exit", |case| {
        !case.events("confirm", "exit").is_empty()
    });
    signal(&runner, libc::SIGTERM);
    signal(&runner, libc::SIGCONT);
    let (output, _) = exited(runner);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        case.current()["confirmation"]["state"],
        "held",
        "{:#}",
        case.runner_state()
    );
}

fn the_heartbeat_keeps_a_short_stint_fresh() {
    let case = Case::new("heartbeat");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1");
    case.script("sweep.after_confirm", "1");
    case.script("confirm.ms", "5000");
    let runner = case.start();
    case.wait_for("a running confirm", |case| {
        !case.events("confirm", "start").is_empty()
    });
    std::thread::sleep(Duration::from_millis(3_800));
    let (_, report) = case.status();
    let alive = case.events("sweep", "exit").is_empty();
    stop(runner);
    assert!(alive, "the sweep still ran");
    assert_eq!(report["stale"], false, "{report:#}");
    assert_eq!(report["sweep_overdue"], false, "{report:#}");
}

fn an_unreadable_list_or_cursor_starts_a_confirm() {
    let case = Case::new("unreadable-list");
    let build = case.build("one");
    case.assign(&build, &["a"], 30);
    case.script("confirm.codes", "4");
    let runner = case.start();
    case.wait_for("the first stint in state.json", |case| {
        case.current()["stints"] == 1 && case.health_now()["phase"] == "sweeping"
    });
    let campaign = case.runner_state()["current"]
        .as_str()
        .expect("a root")
        .to_owned();
    let list = case
        .state()
        .join("roots")
        .join(&campaign)
        .join("suspects.jsonl");
    fs::create_dir_all(&list).expect("a directory at the suspect list");
    case.wait_for("a held confirm", |case| {
        case.health_now()["confirmation"] == "held"
    });
    fs::remove_dir(&list).expect("the list path is restored");
    stop(runner);
    let case = Case::new("unreadable-cursor");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", "1");
    let runner = case.start();
    case.wait_for("a drained confirm", |case| {
        !case.events("confirm", "exit").is_empty() && case.current()["pending"] == false
    });
    let campaign = case.runner_state()["current"]
        .as_str()
        .expect("a root")
        .to_owned();
    let cursor = case
        .state()
        .join("roots")
        .join(&campaign)
        .join("confirm/confirmed");
    fs::write(&cursor, "x").expect("a malformed cursor");
    case.wait_for("a confirm of the malformed cursor", |case| {
        case.events("confirm", "start").len() >= 2
    });
    stop(runner);
}

fn a_confirm_that_cannot_start_waits_and_the_sweep_continues() {
    let case = Case::new("confirm-spawn");
    let build = case.build("one");
    case.assign(&build, &["a"], 2);
    case.script("sweep.suspects", "1");
    let logs = case.state().join("logs");
    sim_host::file::private_dir(&logs.join("confirm.out")).expect("a directory at the log");
    let runner = case.start();
    case.wait_for("the failed confirm start", |case| {
        let health = case.health_now();
        health["confirmation"] == "failed"
            && health["confirmation_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("did not start"))
    });
    let observed = fake::now_ms();
    let sweeps = case.events("sweep", "start").len();
    case.wait_for("a sweep while the confirm waits", |case| {
        case.events("sweep", "start").len() > sweeps
    });
    fs::remove_dir(logs.join("confirm.out")).expect("the log path is restored");
    case.wait_for("the confirm retry", |case| {
        !case.events("confirm", "start").is_empty()
    });
    stop(runner);
    let start = time(&case.events("confirm", "start")[0]);
    assert!(start - observed >= 1_500, "the retry waited a stint");
    let case = Case::new("confirm-cgroup");
    let build = case.build("one");
    case.assign(&build, &["a"], 2);
    case.script("sweep.suspects", "0 1");
    let runner = case.start();
    case.wait_for("the first sweep", |case| {
        !case.events("sweep", "start").is_empty()
    });
    let campaign = campaigns(&case.events("sweep", "start"))[0].clone();
    let nonce = campaign.rsplit('.').next().expect("a nonce").to_owned();
    let blocker = case.dir.join("cgroup/confirm").join(&nonce);
    fs::write(&blocker, "").expect("a file at the confirmation cgroup");
    case.wait_for("the failed confirmation cgroup", |case| {
        case.health_now()["confirmation_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("confirmation cgroup"))
    });
    fs::remove_file(&blocker).expect("the cgroup path is restored");
    case.wait_for("the confirm retry", |case| {
        !case.events("confirm", "start").is_empty()
    });
    stop(runner);
}

fn an_exhausted_stint_counter_starts_no_sweep() {
    let case = Case::new("stint-max");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    stop(runner);
    let mut state = case.runner_state();
    let campaign = state["current"].as_str().expect("a root").to_owned();
    state["roots"][&campaign]["stints"] = json!(u64::MAX);
    sim_host::file::replace(
        &case.state().join("state.json"),
        state.to_string().as_bytes(),
    )
    .expect("an exhausted counter");
    let sweeps = case.events("sweep", "start").len();
    let runner = case.start();
    case.wait_for("the blocked phase", |case| {
        let health = case.health_now();
        health["phase"] == "blocked"
            && health["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("no stint number left"))
    });
    stop(runner);
    assert_eq!(case.events("sweep", "start").len(), sweeps);
}

fn a_partition_or_free_space_fault_blocks_the_stint() {
    let mut case = Case::new("no-worker");
    case.system_cores = sim_host::host::online_cpus();
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("the blocked partition", |case| {
        case.health_now()["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no worker count"))
    });
    stop(runner);
    assert!(case.events("sweep", "start").is_empty());
    let case = Case::new("no-statvfs");
    let absent = sim_host::file::sha256(b"later");
    case.assign(&absent, &["a"], 1);
    let runner = case.start();
    case.wait_for("the missing archive", |case| {
        case.health_now()["phase"] == "blocked"
    });
    fs::remove_dir(case.state().join("roots")).expect("the roots directory is removed");
    assert_eq!(case.build("later"), absent);
    case.wait_for("the unreadable free space", |case| {
        let health = case.health_now();
        health["phase"] == "blocked"
            && health["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("roots"))
    });
    assert!(case.events("sweep", "start").is_empty());
    sim_host::file::private_dir(&case.state().join("roots")).expect("the roots directory");
    case.wait_for("a sweep", |case| !case.events("sweep", "start").is_empty());
    stop(runner);
}

fn a_state_directory_under_a_shared_parent_is_refused() {
    let case = Case::new("shared-parent");
    let shared = case.dir.join("shared");
    fs::create_dir(&shared).expect("a shared directory");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("its mode");
    let state = shared.join("state");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let output = case
        .run_command_at(&state, &case.dir.join("cgroup"))
        .output()
        .expect("the runner ends");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!state.exists(), "the refusal creates nothing");
    assert!(case.log().is_empty());
}

fn envelope(campaign: &str, build: &str, host: &str, written: u64, mut swept: Value) -> Value {
    swept["campaign"] = json!(campaign);
    json!({
        "format": 1, "build": build, "host": host, "campaign": campaign, "stint": 4,
        "stint_seconds": 600, "written": written, "cpu_usec": 1, "capacity_usec": 2,
        "sweep_status": swept,
    })
}

fn swept(runs: u64, pass: u64, keys: Value) -> Value {
    json!({
        "counts": {"watchdog": 900},
        "runs": runs, "pass": pass, "uncredited": 3, "suspects": 5, "replays": 2,
        "elapsed_s": 100.0, "controls": {"missed": 0}, "histories": {"missed": 0},
        "profiles": {"p": {"suspect_keys": keys}},
    })
}

/// A health record that `sim-host status` rates ok now.
fn host_record(instance: &str) -> Value {
    json!({
        "format": 1, "written": sim_host::host::now_s(), "instance": instance,
        "stint_seconds": 600, "phase": "sweeping", "held_roots": 0,
        "stint_cpu_usec": 95, "stint_capacity_usec": 100,
    })
}

fn stored_host(case: &Case, instance: &str, record: &Value) {
    case.put(
        &sim_host::health::key(instance),
        record.to_string().as_bytes(),
    );
}

/// Stores the root's three objects and, for a host with no stored record,
/// an ok record, so the report judges the root's own objects.
fn stored_root(case: &Case, status: &Value, lines: &[Value], findings: &Value) {
    if let Some(instance) = status["host"].as_str()
        && sim_host::instance::is_instance_id(instance)
        && case.object(&sim_host::health::key(instance)).is_none()
    {
        stored_host(case, instance, &host_record(instance));
    }
    let campaign = status["campaign"].as_str().expect("a campaign");
    case.put(
        &format!("roots/{campaign}/status.json"),
        status.to_string().as_bytes(),
    );
    let list: String = lines.iter().map(|line| format!("{line}\n")).collect();
    case.put(&format!("roots/{campaign}/suspects.jsonl"), list.as_bytes());
    case.put(
        &format!("roots/{campaign}/findings.json"),
        findings.to_string().as_bytes(),
    );
}

fn suspect(campaign: &str, build: &str, run: u64, key: &str) -> Value {
    json!({"campaign": campaign, "profile": "p", "run": run, "counts": {"watchdog": 900},
           "seed": 7, "build": build, "class": "violation", "key": key})
}

/// Runs `sim-host report` with `args` after the bucket's name and returns
/// its exit code, standard output, parsed output and standard error.
fn report(case: &Case, args: &[&str]) -> (Option<i32>, Vec<u8>, Value, String) {
    let output = case
        .command(&[&["report", "--bucket", "sims"], args].concat())
        .output()
        .expect("the report runs");
    let parsed = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (
        output.status.code(),
        output.stdout,
        parsed,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn no_findings() -> Value {
    json!({"findings": [], "release_blockers": []})
}

fn the_report_is_byte_equal_under_any_listing_order_and_builds_never_share_a_sum() {
    let case = Case::new("report-order");
    let now = sim_host::host::now_s();
    let one = "1".repeat(64);
    let two = "2".repeat(64);
    let mut first = envelope(
        "sim.i-0000000a.aa",
        &one,
        "i-0000000a",
        now,
        swept(100, 90, json!({})),
    );
    first["cpu_usec"] = json!(300);
    first["capacity_usec"] = json!(1_000);
    stored_root(
        &case,
        &first,
        &[suspect("sim.i-0000000a.aa", &one, 1, "violation: k")],
        &no_findings(),
    );
    let mut second = envelope(
        "sim.i-0000000b.bb",
        &one,
        "i-0000000b",
        now,
        swept(50, 45, json!({})),
    );
    second["cpu_usec"] = json!(600);
    second["capacity_usec"] = json!(3_000);
    second["sweep_status"]["elapsed_s"] = json!(300.0);
    let finding = json!({"findings": [{"id": "f1", "resolved": false,
        "dispositions": [{"decision": "harness"}, {"decision": "product"}]}], "release_blockers": []});
    stored_root(&case, &second, &[], &finding);
    let mut other = envelope(
        "sim.i-0000000a.cc",
        &two,
        "i-0000000a",
        now,
        swept(7, 7, json!({})),
    );
    other["capacity_usec"] = json!(4);
    other["sweep_status"]["alarm"] = json!("1 control runs were missed");
    stored_root(&case, &other, &[], &no_findings());
    stored_host(&case, "i-0000000c", &host_record("i-0000000c"));
    let (code, forward, output, _) = report(&case, &[]);
    assert_eq!(
        code,
        Some(2),
        "the alarmed root of the second build: {output:#}"
    );
    let calls = case.events("aws", "call");
    let lists: Vec<(&Value, &Value)> = calls
        .iter()
        .filter(|call| call["op"] == "list-objects-v2")
        .map(|call| (&call["prefix"], &call["max_items"]))
        .collect();
    assert_eq!(
        lists,
        [
            (&json!("roots/"), &json!("1000")),
            (&json!("hosts/"), &json!("1000"))
        ],
        "one page of at most 1000 objects per prefix"
    );
    let gets: Vec<(&str, &Value)> = calls
        .iter()
        .filter(|call| call["op"] == "get-object")
        .map(|call| (call["key"].as_str().expect("a key"), &call["range"]))
        .collect();
    for (key, range) in &gets {
        let bound: u64 = if key.ends_with("suspects.jsonl") {
            1 << 30
        } else if key.starts_with("hosts/") {
            sim_host::health::BOUND
        } else {
            256 << 20
        };
        assert_eq!(**range, json!(format!("bytes=0-{bound}")), "{key}");
    }
    assert!(gets.iter().any(|(key, _)| key.ends_with("suspects.jsonl")));
    assert!(
        calls
            .iter()
            .filter(|call| call["op"] == "get-object")
            .all(|call| call["if_match"].is_null()),
        "each download of the report reads whatever object its key holds"
    );
    for root in [
        "sim.i-0000000a.aa",
        "sim.i-0000000b.bb",
        "sim.i-0000000a.cc",
    ] {
        let (first, _) = gets
            .iter()
            .find(|(key, _)| key.starts_with(&format!("roots/{root}/")))
            .expect("a download");
        assert_eq!(
            *first,
            format!("roots/{root}/status.json"),
            "status.json is read first"
        );
    }
    let host_reads = |calls: &[Value]| -> Vec<Value> {
        calls
            .iter()
            .filter(|call| {
                call["key"]
                    .as_str()
                    .is_some_and(|key| key.starts_with("hosts/"))
            })
            .map(|call| json!([call["op"], call["key"]]))
            .collect()
    };
    let before = case.events("aws", "call").len();
    fs::write(case.dir.join("aws.reverse"), "").expect("a reversed listing");
    fs::write(case.dir.join("aws.page"), "1").expect("one object per listing page");
    let (_, reversed, _, _) = report(&case, &[]);
    assert_eq!(
        forward, reversed,
        "the report is byte-equal under another listing order and paging"
    );
    let calls = case.events("aws", "call");
    assert_eq!(
        host_reads(&calls[before..]),
        host_reads(&calls[..before]),
        "host records are read in key order under any listing order"
    );
    assert_eq!(host_reads(&calls[..before]).len(), 3);
    let totals = &output["builds"][&one];
    assert_eq!(totals["roots"], 2);
    assert_eq!(totals["hosts"], 2);
    assert_eq!(totals["runs"], 150);
    assert_eq!(totals["pass"], 135);
    assert_eq!(totals["unproven"], 0);
    assert_eq!(totals["uncredited"], 6);
    assert_eq!(totals["cpu_share"], 0.225, "(300 + 600) / (1000 + 3000)");
    assert_eq!(totals["runs_per_s"], 0.375, "150 runs over 400 seconds");
    assert_eq!(totals["findings"][0]["disposition"], "product");
    assert_eq!(
        output["builds"][&two],
        json!({
            "roots": 1, "hosts": 1, "runs": 7, "uncredited": 3, "suspects": 5, "replays": 2,
            "missed_controls": 0, "missed_histories": 0, "elapsed_s": 100.0, "pass": 0,
            "unproven": 7, "runs_per_s": 0.07, "cpu_usec": 1, "capacity_usec": 4,
            "cpu_share": 0.25, "failures": [], "unkeyed": [], "findings": [],
        })
    );
    let before = case.events("aws", "call").len();
    let (code, _, filtered, _) = report(&case, &["--build", &one]);
    assert_eq!(code, Some(0), "{filtered:#}");
    assert_eq!(filtered["flags"], json!([]));
    assert_eq!(filtered["builds"].as_object().expect("builds").len(), 1);
    assert_eq!(filtered["builds"][&one], output["builds"][&one]);
    let gets: Vec<String> = case.events("aws", "call")[before..]
        .iter()
        .filter(|call| call["op"] == "get-object")
        .map(|call| call["key"].as_str().expect("a key").to_owned())
        .filter(|key| key.starts_with("roots/sim.i-0000000a.cc/"))
        .collect();
    assert_eq!(gets, ["roots/sim.i-0000000a.cc/status.json"]);
    let (code, _, unmatched, _) = report(&case, &["--build", &"3".repeat(64)]);
    assert_eq!(code, Some(1), "{unmatched:#}");
    assert_eq!(unmatched["builds"], json!({}));
}

fn one_failure_seen_by_three_roots_is_listed_once_with_all_three() {
    let case = Case::new("report-failure");
    let now = sim_host::host::now_s();
    let build = "3".repeat(64);
    let key = "violation: lost write";
    for (index, campaign) in [
        "sim.i-0000000a.aa",
        "sim.i-0000000b.bb",
        "sim.i-0000000c.cc",
    ]
    .iter()
    .enumerate()
    {
        let count = index as u64 + 2;
        stored_root(
            &case,
            &envelope(
                campaign,
                &build,
                &format!("i-0000000{}", ['a', 'b', 'c'][index]),
                now,
                swept(10, 9, json!({key: count})),
            ),
            &[
                suspect(campaign, &build, 50, key),
                suspect(campaign, &build, 40 - index as u64, key),
            ],
            &no_findings(),
        );
    }
    let (code, _, output, _) = report(&case, &[]);
    assert_eq!(code, Some(0), "{output:#}");
    let failures = output["builds"][&build]["failures"]
        .as_array()
        .expect("failures");
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert_eq!(failures[0]["key"], key);
    assert_eq!(
        failures[0]["count"], 9,
        "2 + 3 + 4 from each root's suspect_keys"
    );
    assert_eq!(
        failures[0]["roots"],
        json!([
            "sim.i-0000000a.aa",
            "sim.i-0000000b.bb",
            "sim.i-0000000c.cc"
        ])
    );
    assert_eq!(
        failures[0]["rerun"],
        json!({"campaign": "sim.i-0000000a.aa", "profile": "p", "run": 40, "counts": {"watchdog": 900}})
    );
}

fn each_report_flag_sets_its_exit_code_and_a_missing_field_never_prints_zero() {
    let now = sim_host::host::now_s();
    let build = "4".repeat(64);
    let root = "sim.i-0000000a.aa";
    let good = envelope(root, &build, "i-0000000a", now, swept(10, 9, json!({})));
    let mut alarmed = good.clone();
    alarmed["sweep_status"]["alarm"] = json!("1 control runs were missed");
    let overflow = envelope(
        root,
        &build,
        "i-0000000a",
        now,
        swept(10, 9, json!({"other": 12})),
    );
    let mut missing = good.clone();
    missing["sweep_status"]
        .as_object_mut()
        .expect("an object")
        .remove("runs");
    let lines: Vec<Value> = (0..8)
        .map(|run| suspect(root, &build, run, "other"))
        .collect();
    let mut silent = host_record("i-0000000a");
    silent["written"] = json!(now - 1_201);
    for (name, status, lines, code, flag) in [
        ("report-good", &good, &[][..], 0, None),
        ("report-silent", &good, &[][..], 2, Some("silent")),
        ("report-alarm", &alarmed, &[][..], 2, Some("alarm")),
        ("report-other", &overflow, &lines[..], 1, Some("other")),
        ("report-missing", &missing, &[][..], 1, Some("missing")),
    ] {
        let case = Case::new(name);
        if name == "report-silent" {
            stored_host(&case, "i-0000000a", &silent);
        }
        stored_root(&case, status, lines, &no_findings());
        let (exit, _, output, _) = report(&case, &[]);
        assert_eq!(exit, Some(code), "{name}: {output:#}");
        let flags = output["flags"].as_array().expect("flags");
        match flag {
            None => assert!(flags.is_empty(), "{name}: {flags:#?}"),
            Some(flag) => {
                assert_eq!(flags.len(), 1, "{name}: {flags:#?}");
                let flagged = if flag == "silent" {
                    json!(null)
                } else {
                    json!(root)
                };
                assert_eq!(
                    (&flags[0]["flag"], &flags[0]["root"]),
                    (&json!(flag), &flagged)
                );
            }
        }
        let totals = &output["builds"][&build];
        match name {
            "report-alarm" => {
                assert_eq!(
                    totals["pass"], 0,
                    "an alarmed root's passes leave the build's"
                );
                assert_eq!(totals["unproven"], 9);
            }
            "report-missing" => {
                assert_eq!(
                    totals["runs"], "unknown",
                    "a missing field never prints as 0"
                );
                assert_eq!(output["roots"][root]["runs"], "unknown");
                assert_eq!(totals["pass"], 9);
            }
            _ => assert_eq!(totals["runs"], 10),
        }
    }
}

fn an_unreadable_bucket_exits_3_and_an_unreadable_object_flags_its_root() {
    let case = Case::new("report-unreadable");
    let now = sim_host::host::now_s();
    let build = "5".repeat(64);
    let healthy = envelope(
        "sim.i-0000000a.aa",
        &build,
        "i-0000000a",
        now,
        swept(100, 90, json!({})),
    );
    stored_root(&case, &healthy, &[], &no_findings());
    let status = "roots/sim.i-0000000a.aa/status.json";
    let record = "hosts/i-0000000a/health.json";
    for (outage, content, named) in [
        ("aws.fail.list-objects-v2", "", "roots/"),
        ("aws.fail.get-object", "", status),
        ("aws.fail.prefix", "roots/", status),
        ("aws.fail.prefix", "hosts/", record),
        ("aws.listing.hosts_", "[", "list-objects-v2 of hosts/"),
    ] {
        fs::write(case.dir.join(outage), content).expect("an outage");
        let before = case.events("aws", "call").len();
        let (code, stdout, _, stderr) = report(&case, &[]);
        assert_eq!(code, Some(3), "{outage} {content}: {stderr}");
        assert!(stdout.is_empty(), "{outage} {content} prints no report");
        assert!(stderr.contains(named), "{outage} {content}: {stderr}");
        assert_eq!(
            fs::read_dir(case.dir.join("tmp"))
                .expect("the directory")
                .count(),
            0,
            "{outage} {content}: the scratch directory is removed"
        );
        let gets: Vec<Value> = case.events("aws", "call")[before..]
            .iter()
            .filter(|call| call["op"] == "get-object")
            .map(|call| call["key"].clone())
            .collect();
        if content == "hosts/" {
            assert_eq!(
                (gets.first(), gets.last()),
                (Some(&json!(status)), Some(&json!(record))),
                "the roots are read before the failed host record"
            );
        } else if content == "roots/" {
            assert_eq!(gets, [json!(status)], "the roots are read first");
        }
        fs::remove_file(case.dir.join(outage)).expect("the outage ends");
    }
    case.put("roots/sim.i-0000000b.bb/status.json", b"{");
    case.put("roots/sim.i-0000000b.bb/suspects.jsonl", b"{}\n");
    case.put("roots/sim.i-0000000b.bb/findings.json", b"{}");
    let lacking = envelope(
        "sim.i-0000000c.cc",
        &build,
        "i-0000000c",
        now,
        swept(1, 1, json!({})),
    );
    case.put(
        "roots/sim.i-0000000c.cc/status.json",
        lacking.to_string().as_bytes(),
    );
    case.put("roots/sim.i-0000000c.cc/suspects.jsonl", b"");
    case.put("roots/sim.i-0000000d.dd/suspects.jsonl", b"");
    let large = case.bucket().join("roots/sim.i-0000000d.dd/status.json");
    fs::File::create(&large)
        .and_then(|file| file.set_len(300 << 20))
        .expect("a sparse object past the bound");
    let before = case.events("aws", "call").len();
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(1), "{stderr}{output:#}");
    assert_eq!(output["builds"][&build]["runs"], 101);
    let flags: Vec<(&Value, &Value)> = output["flags"]
        .as_array()
        .expect("flags")
        .iter()
        .map(|flag| (&flag["root"], &flag["detail"]))
        .collect();
    let error = |root: &str| {
        flags
            .iter()
            .find(|(flagged, _)| **flagged == root)
            .map(|(_, detail)| detail["error"].as_str().unwrap_or_default().to_owned())
            .unwrap_or_default()
    };
    assert!(
        error("sim.i-0000000b.bb").starts_with("does not parse"),
        "{flags:?}"
    );
    assert_eq!(error("sim.i-0000000c.cc"), "absent");
    assert_eq!(
        error("sim.i-0000000d.dd"),
        format!("holds {} bytes, more than {}", 300 << 20, 256 << 20)
    );
    let gets: Vec<String> = case.events("aws", "call")[before..]
        .iter()
        .filter(|call| call["op"] == "get-object")
        .map(|call| call["key"].as_str().expect("a key").to_owned())
        .collect();
    assert!(
        !gets
            .iter()
            .any(|key| key == "roots/sim.i-0000000d.dd/status.json"),
        "an object past its bound is never downloaded"
    );
    assert_eq!(
        gets.iter()
            .filter(|key| key.starts_with("roots/sim.i-0000000b.bb/"))
            .collect::<Vec<_>>(),
        ["roots/sim.i-0000000b.bb/status.json"],
        "a root whose status does not parse has its other objects left unread"
    );
}

fn a_root_with_an_unprintable_name_is_flagged_and_named_in_no_bucket_call() {
    let case = Case::new("report-unprintable");
    let now = sim_host::host::now_s();
    let build = "a".repeat(64);
    let escape = '\u{1b}';
    let unprintable = format!("sim.i-0000000a.{escape}[2Ja");
    for (campaign, host, runs) in [
        (unprintable.as_str(), "i-0000000a", 1),
        ("sim.i-0000000b.bb", "i-0000000b", 100),
    ] {
        stored_root(
            &case,
            &envelope(campaign, &build, host, now, swept(runs, runs, json!({}))),
            &[],
            &no_findings(),
        );
    }
    fs::write(case.dir.join("aws.fail.prefix"), "roots/").expect("a root outage");
    let (code, stdout, _, stderr) = report(&case, &[]);
    assert_eq!(code, Some(3), "{stderr:?}");
    assert!(stdout.is_empty(), "an outage prints no report");
    assert!(
        stderr.contains("roots/sim.i-0000000b.bb/status.json") && !stderr.contains(escape),
        "the unprintable root sorts first and the error names the first root read: {stderr:?}"
    );
    fs::remove_file(case.dir.join("aws.fail.prefix")).expect("the outage ends");
    let (code, stdout, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(1), "{stderr:?}{output:#}");
    assert!(
        !stdout.contains(&(escape as u8)),
        "the document prints the name as a JSON escape"
    );
    assert_eq!(
        output["flags"],
        json!([{"root": unprintable, "flag": "missing",
                "detail": {"object": "status.json",
                           "error": "is not read: its root's name holds a byte outside printable ASCII"}}])
    );
    assert_eq!(
        output["builds"][&build]["runs"], 100,
        "the unread root adds to no sum"
    );
    let named: Vec<Value> = case
        .events("aws", "call")
        .into_iter()
        .filter(|call| call["key"].as_str().is_some_and(|key| key.contains(escape)))
        .collect();
    assert_eq!(named, Vec::<Value>::new(), "no call names the root");
}

fn a_malformed_listing_exits_3_and_an_empty_bucket_exits_0() {
    let case = Case::new("report-listing");
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(output["flags"], json!([]));
    for (name, pages) in [
        ("no key", &[("", r#"{"Contents": [{"Size": 1}]}"#)][..]),
        (
            "no size",
            &[("", r#"{"Contents": [{"Key": "roots/a/status.json"}]}"#)][..],
        ),
        ("contents", &[("", r#"{"Contents": {"Key": "k"}}"#)][..]),
        ("page", &[("", "[]")][..]),
        ("token", &[("", r#"{"Contents": [], "NextToken": 7}"#)][..]),
        (
            "cycle",
            &[
                ("", r#"{"Contents": [], "NextToken": "A"}"#),
                ("A", r#"{"Contents": [], "NextToken": "B"}"#),
                ("B", r#"{"Contents": [], "NextToken": "A"}"#),
            ][..],
        ),
    ] {
        for (token, page) in pages {
            fs::write(case.dir.join(format!("aws.listing.roots_{token}")), page).expect("a page");
        }
        let before = case.events("aws", "call").len();
        let (code, stdout, _, stderr) = report(&case, &[]);
        assert_eq!(code, Some(3), "{name}: {stderr}");
        assert!(stdout.is_empty(), "{name} prints no report");
        assert!(stderr.contains("list-objects-v2"), "{name}: {stderr}");
        let lists = case.events("aws", "call")[before..]
            .iter()
            .filter(|call| call["op"] == "list-objects-v2" && call["prefix"] == "roots/")
            .count();
        assert_eq!(lists, pages.len(), "{name}");
        for (token, _) in pages {
            fs::remove_file(case.dir.join(format!("aws.listing.roots_{token}"))).expect("the page");
        }
    }
}

/// Each listing the report makes, `hosts/` and `roots/`, is refused past
/// 1,048,576 objects with no document.
fn a_listing_past_its_object_bound_exits_3() {
    for prefix in ["hosts", "roots"] {
        let case = Case::new(&format!("report-listing-bound-{prefix}"));
        let page = |objects: usize, next: Option<&str>| {
            let entry = format!(r#"{{"Key":"{prefix}/c/x","Size":0}}"#);
            let contents = vec![entry; objects].join(",");
            let next = next.map_or(String::new(), |next| format!(r#","NextToken":"{next}""#));
            format!(r#"{{"Contents":[{contents}]{next}}}"#)
        };
        let half = 1 << 19;
        let canned = format!("aws.listing.{prefix}_");
        fs::write(case.dir.join(&canned), page(half, Some("1"))).expect("a page");
        fs::write(case.dir.join(format!("{canned}1")), page(half + 1, None)).expect("a page");
        let (code, stdout, _, stderr) = report(&case, &[]);
        assert_eq!(code, Some(3), "{prefix}: {stderr}");
        assert!(
            stdout.is_empty(),
            "{prefix}: a listing past the bound prints no report"
        );
        assert!(
            stderr.contains(&format!("listing {prefix}/"))
                && stderr.contains("more than 1048576 objects"),
            "{stderr}"
        );
        let calls = case.events("aws", "call");
        assert!(
            calls.iter().all(|call| call["op"] == "list-objects-v2"),
            "{prefix}: no object is read: {calls:?}"
        );
    }
}

/// The listing is read before any object, so an upload that follows it
/// leaves the listing's sizes stale. The report takes an empty list from
/// the listing only while the status it read afterwards counts no suspect.
fn the_report_reads_again_an_object_its_listing_shows_empty_or_absent() {
    let case = Case::new("report-stale-listing");
    let now = sim_host::host::now_s();
    let build = "8".repeat(64);
    let calls = |from: usize| -> Vec<(String, String)> {
        case.events("aws", "call")[from..]
            .iter()
            .filter(|call| {
                call["prefix"] != "hosts/"
                    && !call["key"]
                        .as_str()
                        .unwrap_or_default()
                        .starts_with("hosts/")
            })
            .map(|call| {
                let text = |field: &str| call[field].as_str().unwrap_or_default().to_owned();
                (text("op"), text("key"))
            })
            .collect()
    };
    let call = |op: &str, key: &str| (op.to_owned(), key.to_owned());
    let quiet = "sim.i-0000000a.aa";
    stored_root(
        &case,
        &envelope(quiet, &build, "i-0000000a", now, swept(1, 1, json!({}))),
        &[],
        &no_findings(),
    );
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(0), "{stderr}{output:#}");
    assert_eq!(
        calls(0),
        [
            call("list-objects-v2", ""),
            call("get-object", &format!("roots/{quiet}/status.json")),
            call("get-object", &format!("roots/{quiet}/findings.json")),
        ],
        "an empty list whose status counts no suspect costs no call"
    );
    let root = "sim.i-0000000b.bb";
    let key = "violation: k";
    stored_root(
        &case,
        &envelope(
            root,
            &build,
            "i-0000000b",
            now,
            swept(10, 9, json!({key: 1})),
        ),
        &[suspect(root, &build, 3, key)],
        &no_findings(),
    );
    let listed = |name: &str, size: Option<u64>| {
        let stored = fs::metadata(case.bucket().join(format!("roots/{root}/{name}")))
            .expect("an object")
            .len();
        json!({"Key": format!("roots/{root}/{name}"), "Size": size.unwrap_or(stored)})
    };
    let before_the_list = json!({"Contents": [
        listed("findings.json", None),
        listed("status.json", None),
        listed("suspects.jsonl", Some(0)),
    ]});
    fs::write(
        case.dir.join("aws.listing.roots_"),
        before_the_list.to_string(),
    )
    .expect("a listing");
    let before = case.events("aws", "call").len();
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(0), "{stderr}{output:#}");
    assert_eq!(output["flags"], json!([]));
    let failures = &output["builds"][&build]["failures"];
    assert_eq!(failures[0]["key"], key, "{output:#}");
    assert_eq!(failures[0]["count"], 1);
    assert_eq!(
        calls(before),
        [
            call("list-objects-v2", ""),
            call("get-object", &format!("roots/{root}/status.json")),
            call("head-object", &format!("roots/{root}/suspects.jsonl")),
            call("get-object", &format!("roots/{root}/suspects.jsonl")),
            call("get-object", &format!("roots/{root}/findings.json")),
        ],
        "a counted suspect has the list read again"
    );
    let before_the_status = json!({"Contents": [listed("suspects.jsonl", None)]});
    fs::write(
        case.dir.join("aws.listing.roots_"),
        before_the_status.to_string(),
    )
    .expect("a listing");
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(0), "{stderr}{output:#}");
    assert_eq!(output["flags"], json!([]));
    assert_eq!(output["builds"][&build]["runs"], 10);
    assert_eq!(output["builds"][&build]["findings"], json!([]));
}

fn the_report_downloads_into_a_fresh_scratch_directory_it_removes() {
    let case = Case::new("report-scratch");
    let now = sim_host::host::now_s();
    let healthy = envelope(
        "sim.i-0000000a.aa",
        &"6".repeat(64),
        "i-0000000a",
        now,
        swept(1, 1, json!({})),
    );
    stored_root(&case, &healthy, &[], &no_findings());
    let temporary = case.dir.join("tmp");
    fs::create_dir_all(&temporary).expect("a temporary directory");
    let output = case
        .command(&["report", "--bucket", "sims"])
        .env("TMPDIR", &temporary)
        .output()
        .expect("the report runs");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        case.events("aws", "call")
            .iter()
            .any(|call| call["op"] == "get-object"),
        "the report downloads"
    );
    assert_eq!(
        fs::read_dir(&temporary).expect("the directory").count(),
        0,
        "the scratch directory is removed"
    );
    let before = case.events("aws", "call").len();
    for (command, code) in [
        (&["report", "--bucket", "sims"][..], 3),
        (&["check", "--bucket", "sims"][..], 2),
    ] {
        let output = case
            .command(command)
            .env("TMPDIR", case.dir.join("absent"))
            .output()
            .expect("the command runs");
        assert_eq!(output.status.code(), Some(code), "{command:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{command:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("a scratch directory"),
            "{command:?}: {output:?}"
        );
    }
    assert_eq!(
        case.events("aws", "call").len(),
        before,
        "no command reached the bucket"
    );
}

/// A slow download of a fresh record with a one-second stint leaves the
/// host active, so the clock reading that judges the record precedes it.
fn the_report_reads_its_clock_before_the_bucket() {
    let case = Case::new("report-clock");
    let mut fresh = host_record("i-0000000a");
    fresh["stint_seconds"] = json!(1);
    stored_host(&case, "i-0000000a", &fresh);
    fs::write(case.dir.join("aws.delay"), "3500").expect("a slow download");
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(0), "{stderr}{output:#}");
    assert_eq!(output["flags"], json!([]));
    assert_eq!(output["hosts"]["i-0000000a"]["state"], "active");
}

fn an_ignored_sigchld_leaves_the_reports_helpers_waitable() {
    let case = Case::new("report-sigchld");
    let healthy = envelope(
        "sim.i-0000000a.aa",
        &"8".repeat(64),
        "i-0000000a",
        sim_host::host::now_s(),
        swept(1, 1, json!({})),
    );
    stored_root(&case, &healthy, &[], &no_findings());
    let mut command = case.command(&["report", "--bucket", "sims"]);
    // SAFETY: between fork and exec the hook calls `signal`, which is
    // async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::signal(libc::SIGCHLD, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().expect("the report runs");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).expect("a document");
    assert_eq!(document["flags"], json!([]), "{document:#}");
}

fn a_stop_signal_ends_the_report_with_no_document_and_no_scratch_directory() {
    let case = Case::new("report-stop");
    let healthy = envelope(
        "sim.i-0000000a.aa",
        &"9".repeat(64),
        "i-0000000a",
        sim_host::host::now_s(),
        swept(1, 1, json!({})),
    );
    stored_root(&case, &healthy, &[], &no_findings());
    fs::remove_file(case.bucket().join(sim_host::health::key("i-0000000a")))
        .expect("no host record, so the delayed download is the root's");
    fs::write(case.dir.join("aws.delay"), "30000").expect("a slow download");
    let temporary = case.dir.join("tmp");
    fs::create_dir_all(&temporary).expect("a temporary directory");
    let mut command = case.command(&["report", "--bucket", "sims"]);
    let running = Running(Some(command.spawn().expect("the report starts")));
    case.wait_for("a root download in flight", |case| {
        case.events("aws", "call").iter().any(|call| {
            call["op"] == "get-object"
                && call["key"]
                    .as_str()
                    .is_some_and(|key| key.starts_with("roots/"))
        })
    });
    let (output, _) = ended(running, libc::SIGTERM);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stopped at a stop request"),
        "{output:?}"
    );
    assert_eq!(
        fs::read_dir(&temporary).expect("the directory").count(),
        0,
        "the scratch directory is removed"
    );
}

const RECORD: &str = "hosts/i-0000000a/health.json";

fn stored_record(case: &Case, key: &str) -> Option<Value> {
    case.object(key)
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

/// The stored record is a version of the local record, byte for byte,
/// under the runner's own instance id; another instance's runner writes
/// another key.
fn the_stored_record_is_a_version_of_the_local_record() {
    let case = Case::new("record-local");
    let build = case.build("one");
    case.assign(&build, &["a"], 2);
    let runner = case.start();
    case.wait_for(
        "a stored record equal to the local one after two stints",
        |case| {
            let local = fs::read(case.state().join("health.json")).ok();
            let stored = case.object(RECORD);
            stored.is_some()
                && stored == local
                && stored_record(case, RECORD)
                    .is_some_and(|record| record["stint"].as_u64() >= Some(2))
        },
    );
    let stored = stored_record(&case, RECORD).expect("the record");
    let local = case.health();
    for field in ["instance", "root", "build", "phase"] {
        assert_eq!(stored[field], local[field], "{field}");
    }
    assert_eq!(stored["instance"], "i-0000000a");
    assert_eq!(stored["build"], build.as_str());
    stop(runner);
    let first = case.object(RECORD).expect("the record");
    assert_eq!(
        Some(&first),
        fs::read(case.state().join("health.json")).ok().as_ref(),
        "the last stored version is the local record at the exit"
    );
    let other = case.dir.join("other");
    make_cgroup(&other.join("cgroup"));
    let metadata = Metadata::serve(Some("i-0000000b"));
    let starts = case.events("sweep", "start").len();
    let runner = case.start_at(&other.join("state"), &other.join("cgroup"), &metadata);
    case.wait_for("a stint under the other id", |case| {
        case.events("sweep", "exit").len() > starts
            && case.object("hosts/i-0000000b/health.json").is_some()
    });
    stop(runner);
    assert_eq!(
        case.object(RECORD),
        Some(first),
        "the other runner leaves the first key's object"
    );
    let other = stored_record(&case, "hosts/i-0000000b/health.json").expect("its record");
    assert_eq!(other["instance"], "i-0000000b");
    assert_eq!(other["phase"], "stopped");
}

/// A failing put of the record delays no stint, its error stays named
/// while store passes succeed, and the stored `written` advances once the
/// puts succeed again.
fn a_failing_record_put_delays_no_stint_and_stays_named_until_one_succeeds() {
    let case = Case::new("record-fail");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", &"1 ".repeat(40));
    let runner = case.start();
    case.wait_for("a stored record and a root", |case| {
        case.object(RECORD).is_some() && root_of(case, &build).is_some()
    });
    fs::write(case.dir.join("aws.fail.prefix"), "hosts/").expect("failing record puts");
    let failed_at = fake::now_ms();
    let before = case.events("sweep", "exit").len();
    let root = root_of(&case, &build).expect("a root");
    let status_puts = puts(&case, &format!("roots/{root}/status.json"));
    case.wait_for("three stints with failing record puts", |case| {
        case.events("sweep", "exit").len() >= before + 4
            && puts(case, &format!("roots/{root}/status.json")) > status_puts + 1
    });
    let error = case.health_now()["upload_error"].clone();
    assert!(
        error.as_str().is_some_and(|error| error.contains(RECORD)),
        "a succeeding store pass leaves the record's error: {error}"
    );
    let stuck = stored_record(&case, RECORD).expect("the earlier record")["written"]
        .as_u64()
        .expect("a written second");
    fs::remove_file(case.dir.join("aws.fail.prefix")).expect("the puts succeed");
    let cleared_at = fake::now_ms();
    case.wait_for("a stored record after the failure", |case| {
        stored_record(case, RECORD)
            .and_then(|record| record["written"].as_u64())
            .is_some_and(|written| written > stuck)
            && case.health_now()["upload_error"].is_null()
    });
    let times = put_times(&case, RECORD);
    let attempts = times
        .iter()
        .filter(|put| (failed_at..cleared_at).contains(*put))
        .count() as u64;
    let resumed = times
        .iter()
        .copied()
        .find(|put| *put >= cleared_at)
        .expect("a put after the failure cleared");
    stop(runner);
    assert!(
        resumed - cleared_at < 5_000,
        "a record put starts {} ms after the failure clears; the period is 400 ms",
        resumed - cleared_at
    );
    let during = case
        .events("sweep", "start")
        .iter()
        .filter(|start| (failed_at..cleared_at).contains(&time(start)))
        .count();
    assert!(
        during >= 3,
        "{during} stints started while record puts failed"
    );
    let window = cleared_at - failed_at;
    assert!(
        attempts <= window / 400 + 3,
        "{attempts} record puts in {window} ms retry no faster than the 400 ms period"
    );
}

/// A put of the record that hangs leaves each next stint on time, and a
/// stop during it ends the put and stores the stopped record.
fn a_hung_record_put_delays_no_stint_and_no_stop() {
    let case = Case::new("record-hang");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    case.script("sweep.suspects", &"1 ".repeat(40));
    let runner = case.start();
    case.wait_for("a stored record", |case| case.object(RECORD).is_some());
    fs::write(case.dir.join("aws.hang.prefix"), "hosts/").expect("hung record puts");
    case.wait_for("a hung record put", |case| {
        !case.events("aws", "hang").is_empty()
    });
    let hung_at = time(&case.events("aws", "hang")[0]);
    let stored = case.object(RECORD);
    case.wait_for("four stints after the hang", |case| {
        case.events("sweep", "start")
            .iter()
            .filter(|start| time(start) >= hung_at)
            .count()
            >= 4
    });
    let log = case.log();
    let hang = log
        .iter()
        .position(|entry| entry["event"] == "hang")
        .expect("the hang");
    let later: Vec<&Value> = log[hang..]
        .iter()
        .filter(|entry| {
            entry["event"] == "call" && entry["op"] == "put-object" && entry["key"] == RECORD
        })
        .collect();
    assert_eq!(
        (case.events("aws", "hang").len(), later),
        (1, Vec::<&Value>::new()),
        "one record put is in flight while it hangs"
    );
    assert_eq!(case.object(RECORD), stored, "the hung put stores nothing");
    let starts: Vec<u64> = case
        .events("sweep", "start")
        .iter()
        .map(time)
        .filter(|start| *start >= hung_at)
        .collect();
    for pair in starts.windows(2) {
        assert!(
            pair[1] - pair[0] < 3_000,
            "a one-second stint starts within 3 s of the last: {starts:?}"
        );
    }
    let asked = fake::now_ms();
    signal(&runner, libc::SIGTERM);
    fs::remove_file(case.dir.join("aws.hang.prefix")).expect("the puts answer again");
    let (output, _) = exited(runner);
    assert!(output.status.success(), "{output:?}");
    assert!(
        fake::now_ms() - asked < 30_000,
        "the stop waited on the hung put"
    );
    assert_eq!(
        stored_record(&case, RECORD).expect("the record")["phase"],
        "stopped"
    );
}

/// A runner paused in `blocked` because its assigned build left the disk
/// and the bucket keeps storing its record, with its reason, at least
/// every half stint length.
fn a_paused_runner_keeps_its_stored_record_fresh() {
    let case = Case::new("record-paused");
    let build = case.build("one");
    case.assign(&build, &["a"], 2);
    let runner = case.start();
    case.wait_for("a stint", |case| !case.events("sweep", "exit").is_empty());
    stop(runner);
    fs::remove_dir_all(sim_host::build::dir(&case.state(), &build)).expect("the build leaves");
    for name in ["archive.tar", "campaign"] {
        fs::remove_file(case.bucket().join(format!("builds/{build}/{name}")))
            .expect("the stored build leaves");
    }
    fs::remove_file(case.bucket().join(RECORD)).expect("the stored record leaves");
    let runner = case.start();
    case.wait_for("a stored blocked record", |case| {
        stored_record(case, RECORD)
            .is_some_and(|record| record["phase"] == "blocked" && record["reason"].is_string())
    });
    let first = stored_record(&case, RECORD).expect("the record")["written"]
        .as_u64()
        .expect("a written second");
    let from = puts(&case, RECORD);
    std::thread::sleep(Duration::from_millis(4_500));
    let read_at = fake::unix_ms();
    let later = stored_record(&case, RECORD).expect("the record");
    let starts = put_times(&case, RECORD);
    stop(runner);
    let settled = calls(&case, "aws")
        .iter()
        .filter(|call| call["op"] == "put-object" && call["key"] == RECORD)
        .filter_map(|call| call["unix_ms"].as_u64())
        .filter(|start| *start + 1_000 < read_at)
        .max()
        .expect("a settled put");
    assert!(
        later["written"]
            .as_u64()
            .is_some_and(|written| written * 1_000 + 1_000 > settled),
        "the stored written is the upload's start, {settled} Unix ms: {later:#}"
    );
    assert_eq!(later["phase"], "blocked");
    assert!(
        later["written"]
            .as_u64()
            .is_some_and(|written| written > first),
        "the stored written advances in a paused phase: {later:#}"
    );
    let paused = &starts[from.saturating_sub(1)..];
    assert!(paused.len() >= 4, "{starts:?}");
    for pair in paused.windows(2) {
        assert!(
            pair[1] - pair[0] <= 1_500,
            "a put starts at least every half stint length: {starts:?}"
        );
    }
}

/// After a stop signal during a sweep, one put of the record follows the
/// sweep's exit and the final snapshot upload, and it stores `stopped`.
fn the_stopped_record_is_stored_after_the_final_snapshot_upload() {
    let case = Case::new("record-stopped");
    let build = case.build("one");
    case.assign(&build, &["a"], 30);
    case.script("sweep.suspects", "3");
    let runner = case.start();
    case.wait_for("a running sweep and a stored record", |case| {
        !case.events("sweep", "start").is_empty() && case.object(RECORD).is_some()
    });
    std::thread::sleep(Duration::from_millis(500));
    let asked = fake::now_ms();
    stop(runner);
    let root = root_of(&case, &build).expect("a root");
    let after: Vec<u64> = put_times(&case, RECORD)
        .into_iter()
        .filter(|put| *put >= asked)
        .collect();
    assert_eq!(after.len(), 1, "one put of the record after the signal");
    let sweep_exit = case
        .events("sweep", "exit")
        .iter()
        .map(time)
        .max()
        .expect("the sweep exited");
    let snapshot = calls(&case, "aws")
        .iter()
        .filter(|call| {
            call["op"] == "put-object"
                && call["key"]
                    .as_str()
                    .is_some_and(|key| key.starts_with(&format!("roots/{root}/")))
        })
        .map(time)
        .max()
        .expect("the final snapshot upload");
    assert!(
        after[0] >= sweep_exit && after[0] >= snapshot,
        "the stopped record follows the sweep's exit and the snapshot upload"
    );
    assert_eq!(
        stored_record(&case, RECORD).expect("the record")["phase"],
        "stopped"
    );
    assert_eq!(
        case.object(RECORD),
        fs::read(case.state().join("health.json")).ok()
    );
    let (_, _, output, stderr) = report(&case, &[]);
    assert_eq!(
        output["hosts"]["i-0000000a"]["state"], "stopped",
        "{stderr}{output:#}"
    );
    let named: Vec<&Value> = output["flags"]
        .as_array()
        .expect("flags")
        .iter()
        .filter(|flag| flag["detail"]["host"] == "i-0000000a")
        .collect();
    assert!(
        named.is_empty(),
        "a fresh stopped record raises no flag: {named:#?}"
    );
}

/// A key under `hosts/` whose instance part is no instance id, and a
/// record past the health bound, are flagged and never downloaded; a
/// listed record the read finds gone raises nothing by itself.
fn a_host_key_is_checked_before_its_read() {
    let case = Case::new("report-host-keys");
    case.put("hosts/not-an-id/health.json", b"{}");
    let mut large = host_record("i-0000000b");
    large["reason"] = json!("r".repeat(sim_host::health::BOUND as usize));
    stored_host(&case, "i-0000000b", &large);
    stored_host(&case, "i-0000000a", &host_record("i-0000000a"));
    let listing = json!({"Contents": [
        {"Key": "hosts/i-0000000a/health.json",
         "Size": case.object("hosts/i-0000000a/health.json").expect("a record").len()},
        {"Key": "hosts/i-0000000b/health.json",
         "Size": case.object("hosts/i-0000000b/health.json").expect("a record").len()},
        {"Key": "hosts/i-0000000c/health.json", "Size": 40},
        {"Key": "hosts/not-an-id/health.json", "Size": 2},
    ]});
    fs::write(case.dir.join("aws.listing.hosts_"), listing.to_string()).expect("a listing");
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(1), "{stderr}{output:#}");
    let gets: Vec<String> = calls(&case, "aws")
        .iter()
        .filter(|call| call["op"] == "get-object")
        .filter_map(|call| call["key"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        gets,
        [
            "hosts/i-0000000a/health.json",
            "hosts/i-0000000c/health.json"
        ],
        "only records within the bound under an instance id are read"
    );
    assert_eq!(output["hosts"]["i-0000000a"]["state"], "active");
    assert_eq!(output["hosts"]["i-0000000b"]["state"], "missing");
    assert!(
        output["hosts"].get("i-0000000c").is_none(),
        "a record gone at its read is no record: {output:#}"
    );
    let raised: Vec<&Value> = output["flags"]
        .as_array()
        .expect("flags")
        .iter()
        .map(|flag| &flag["detail"])
        .collect();
    assert_eq!(raised.len(), 2, "{raised:#?}");
    assert!(
        raised
            .iter()
            .any(|detail| detail["key"] == "hosts/not-an-id/health.json")
    );
    assert!(raised.iter().any(|detail| detail["host"] == "i-0000000b"));
}

/// A record listed empty has its length read again: one gone by then has
/// no row, one replaced by a record is judged, and one still empty is
/// missing with no ranged read. A record longer than the health bound
/// under a short listed size is cut at the bound and flagged unread.
fn a_host_record_listed_empty_or_cut_at_the_bound_is_read_again() {
    let case = Case::new("report-host-sizes");
    stored_host(&case, "i-0000000e", &host_record("i-0000000e"));
    case.put("hosts/i-0000000f/health.json", b"");
    let mut long = host_record("i-00000010");
    long["reason"] = json!("r".repeat(2 * sim_host::health::BOUND as usize));
    stored_host(&case, "i-00000010", &long);
    let mut grown = host_record("i-00000011");
    grown["reason"] = json!("r".repeat(sim_host::health::BOUND as usize));
    stored_host(&case, "i-00000011", &grown);
    let grown = case
        .object("hosts/i-00000011/health.json")
        .expect("a record")
        .len();
    let listing = json!({"Contents": [
        {"Key": "hosts/", "Size": 0},
        {"Key": "hosts/i-0000000d/health.json", "Size": 0},
        {"Key": "hosts/i-0000000e/health.json", "Size": 0},
        {"Key": "hosts/i-0000000f/health.json", "Size": 0},
        {"Key": "hosts/i-00000010/health.json", "Size": 40},
        {"Key": "hosts/i-00000011/health.json", "Size": 0},
    ]});
    fs::write(case.dir.join("aws.listing.hosts_"), listing.to_string()).expect("a listing");
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(1), "{stderr}{output:#}");
    let hosts = output["hosts"].as_object().expect("rows");
    assert_eq!(
        hosts.keys().collect::<Vec<_>>(),
        ["i-0000000e", "i-0000000f", "i-00000010", "i-00000011"],
        "a record gone at its length read is no record, and hosts/ is no key: {output:#}"
    );
    assert_eq!(
        hosts["i-00000011"]["error"],
        format!(
            "the record holds {grown} bytes, more than {}",
            sim_host::health::BOUND
        )
        .as_str(),
        "a length read past the bound is flagged with that length"
    );
    assert_eq!(hosts["i-0000000e"]["state"], "active");
    assert_eq!(hosts["i-0000000f"]["state"], "missing");
    assert_eq!(hosts["i-00000010"]["state"], "missing");
    let cut = format!(
        "the record holds more than {} bytes",
        sim_host::health::BOUND
    );
    assert_eq!(hosts["i-00000010"]["error"], cut.as_str());
    let flagged: Vec<&Value> = output["flags"]
        .as_array()
        .expect("flags")
        .iter()
        .map(|flag| &flag["detail"])
        .collect();
    let hosts_flagged: Vec<&Value> = flagged.iter().map(|detail| &detail["host"]).collect();
    assert_eq!(
        hosts_flagged,
        [
            &json!("i-0000000f"),
            &json!("i-00000010"),
            &json!("i-00000011")
        ],
        "the folder marker raises no flag: {flagged:#?}"
    );
    assert!(
        flagged
            .iter()
            .any(|detail| detail["host"] == "i-00000010" && detail["reasons"] == json!([cut])),
        "{flagged:#?}"
    );
    let calls: Vec<(String, String)> = calls(&case, "aws")
        .iter()
        .filter(|call| call["op"] != "list-objects-v2")
        .map(|call| {
            let text = |field: &str| call[field].as_str().unwrap_or_default().to_owned();
            (text("op"), text("key"))
        })
        .collect();
    let call = |op: &str, key: &str| (op.to_owned(), format!("hosts/{key}/health.json"));
    assert_eq!(
        calls,
        [
            call("head-object", "i-0000000d"),
            call("head-object", "i-0000000e"),
            call("get-object", "i-0000000e"),
            call("head-object", "i-0000000f"),
            call("get-object", "i-00000010"),
            call("head-object", "i-00000011"),
        ],
        "an empty record, one past the bound and the folder marker take no download"
    );
    let failed = "aws.fail.head-object.hosts_i-0000000d_health.json";
    fs::write(case.dir.join(failed), "").expect("a failing length read");
    let (code, stdout, _, stderr) = report(&case, &[]);
    assert_eq!(code, Some(3), "{stderr}");
    assert!(stdout.is_empty(), "a failed length read prints no report");
    assert!(stderr.contains("hosts/i-0000000d/health.json"), "{stderr}");
    fs::remove_file(case.dir.join(failed)).expect("the failure ends");
}

/// A record written 302 seconds after the test's clock reading is judged
/// once its download took 3.5 seconds: the ahead check reads the clock
/// after the download, and the age is judged at the earlier reading.
fn the_report_reads_the_clock_again_after_each_host_download() {
    let case = Case::new("report-clock-after");
    let mut ahead = host_record("i-0000000a");
    ahead["written"] = json!(sim_host::host::now_s() + 302);
    stored_host(&case, "i-0000000a", &ahead);
    fs::write(case.dir.join("aws.delay"), "3500").expect("a slow download");
    let (code, _, output, stderr) = report(&case, &[]);
    assert_eq!(code, Some(0), "{stderr}{output:#}");
    assert_eq!(output["hosts"]["i-0000000a"]["state"], "active");
}

/// A download that exits 0 and leaves no file, or leaves a directory, is
/// an error under hosts/ and under roots/, so the report prints no
/// document.
fn a_download_that_leaves_no_file_exits_3() {
    let case = Case::new("report-no-file");
    let healthy = envelope(
        "sim.i-0000000a.aa",
        &"6".repeat(64),
        "i-0000000a",
        sim_host::host::now_s(),
        swept(1, 1, json!({})),
    );
    stored_root(&case, &healthy, &[], &no_findings());
    for (control, error) in [
        ("aws.nowrite.prefix", "the download left no file"),
        ("aws.nonregular.prefix", "is not a regular file"),
    ] {
        for prefix in ["hosts/", "roots/"] {
            fs::write(case.dir.join(control), prefix).expect("a download control");
            let (code, stdout, _, stderr) = report(&case, &[]);
            assert_eq!(code, Some(3), "{control} {prefix}: {stderr}");
            assert!(stdout.is_empty(), "{control} {prefix} prints no report");
            assert!(stderr.contains(error), "{control} {prefix}: {stderr}");
            assert!(
                stderr.contains(prefix),
                "{control} {prefix} names the object's key: {stderr}"
            );
            assert_eq!(
                fs::read_dir(case.dir.join("tmp"))
                    .expect("the directory")
                    .count(),
                0,
                "{control} {prefix}: the scratch directory is removed"
            );
        }
        fs::remove_file(case.dir.join(control)).expect("the control ends");
    }
}

/// A stop whose put of the stopped record fails before it writes anything
/// exits 0, names the failure in the local stopped record and leaves the
/// last stored record.
fn a_failing_stopped_record_put_leaves_the_last_running_record() {
    let case = Case::new("record-stop-fail");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stored record", |case| case.object(RECORD).is_some());
    fs::write(case.dir.join("aws.fail.prefix"), "hosts/").expect("failing record puts");
    case.wait_for("a failed record put", |case| {
        case.health_now()["upload_error"]
            .as_str()
            .is_some_and(|error| error.contains(RECORD))
    });
    let stored = case.object(RECORD);
    let asked = fake::now_ms();
    stop(runner);
    let final_pass = calls(&case, "aws")
        .iter()
        .filter(|call| {
            call["op"] == "put-object"
                && call["key"]
                    .as_str()
                    .is_some_and(|key| key.starts_with("roots/"))
        })
        .map(time)
        .max()
        .expect("the final snapshot upload");
    assert!(final_pass >= asked, "the final pass ran after the signal");
    let finals = put_times(&case, RECORD)
        .into_iter()
        .filter(|put| *put >= final_pass)
        .count();
    assert_eq!(
        finals, 1,
        "one put of the stopped record after the final pass"
    );
    let local = case.health();
    assert_eq!(local["phase"], "stopped");
    assert!(
        local["upload_error"]
            .as_str()
            .is_some_and(|error| error.contains(RECORD)),
        "{local:#}"
    );
    assert_eq!(case.object(RECORD), stored, "the last running record stays");
    assert_ne!(
        stored_record(&case, RECORD).expect("the record")["phase"],
        "stopped"
    );
}

/// A longer stint length is stored in the record before the longer
/// upload period that it sets takes effect.
fn a_longer_stint_is_stored_before_the_longer_upload_period() {
    let case = Case::new("record-stint");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stored one-second stint", |case| {
        stored_record(case, RECORD).is_some_and(|record| record["stint_seconds"] == 1)
    });
    case.assign(&build, &["a"], 600);
    case.wait_for("a stored 600-second stint", |case| {
        stored_record(case, RECORD).is_some_and(|record| record["stint_seconds"] == 600)
    });
    stop(runner);
}

/// A directory at the staged name of the local record fails every save of
/// it. The one-second delay gives puts spawned after an earlier save time
/// to start before the returned time, which opens the measured failure
/// interval.
fn fail_record_saves(case: &Case) -> u64 {
    let staged = case.state().join(".health.json.staged");
    case.wait_for("a directory at the staged name", |_| {
        fs::create_dir(&staged).is_ok()
    });
    std::thread::sleep(Duration::from_secs(1));
    fake::now_ms()
}

/// Each put of the record follows a successful save of it, while the
/// runner runs and at its stop. A stint length raised to 600 seconds while
/// saves fail is stored within 10 seconds after saves resume.
fn each_record_put_follows_its_save_and_a_raised_stint_is_stored_once_a_record_saves() {
    let case = Case::new("record-unsaved");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stored one-second stint", |case| {
        stored_record(case, RECORD).is_some_and(|record| record["stint_seconds"] == 1)
    });
    let state = case.state().join("state.json");
    let digest = case.runner_state()["assignment"].clone();
    let unsaved = fail_record_saves(&case);
    case.assign(&build, &["a"], 600);
    case.wait_for("the 600-second assignment in force", |_| {
        let now = read_lenient(&state)["assignment"].clone();
        now.is_string() && now != digest
    });
    std::thread::sleep(Duration::from_secs(1));
    let saved = fake::now_ms();
    fs::remove_dir(case.state().join(".health.json.staged")).expect("the directory is removed");
    let unsaved_puts: Vec<u64> = put_times(&case, RECORD)
        .into_iter()
        .filter(|put| (unsaved..saved).contains(put))
        .collect();
    assert!(
        unsaved_puts.is_empty(),
        "puts of a record that was not saved, between {unsaved} and {saved}: {unsaved_puts:?}"
    );
    let until = Instant::now() + Duration::from_secs(10);
    while stored_record(&case, RECORD).is_none_or(|record| record["stint_seconds"] != 600) {
        assert!(
            Instant::now() < until,
            "the 600-second stint is not stored within 10 seconds after saves resume"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let unsaved = fail_record_saves(&case);
    let stored = case.object(RECORD);
    stop(runner);
    let stop_puts: Vec<u64> = put_times(&case, RECORD)
        .into_iter()
        .filter(|put| *put >= unsaved)
        .collect();
    assert!(
        stop_puts.is_empty(),
        "puts of a stopped record that was not saved: {stop_puts:?}"
    );
    assert_eq!(case.object(RECORD), stored, "the last saved record stays");
    assert_ne!(case.health()["phase"], "stopped");
}

/// A stop that begins while the record's puts fail, and whose final put
/// succeeds, stores and keeps a stopped record that names no record
/// error.
fn a_stop_after_failed_record_puts_stores_a_stopped_record_without_their_error() {
    let case = Case::new("record-stop-clear");
    let build = case.build("one");
    case.assign(&build, &["a"], 1);
    let runner = case.start();
    case.wait_for("a stored record", |case| case.object(RECORD).is_some());
    fs::write(case.dir.join("aws.fail.prefix"), "hosts/").expect("failing record puts");
    case.wait_for("a failed record put", |case| {
        case.health_now()["upload_error"]
            .as_str()
            .is_some_and(|error| error.contains(RECORD))
    });
    signal(&runner, libc::SIGTERM);
    fs::remove_file(case.dir.join("aws.fail.prefix")).expect("the puts succeed again");
    let (output, _) = exited(runner);
    assert!(output.status.success(), "{output:?}");
    let stored = stored_record(&case, RECORD).expect("the record");
    assert_eq!(stored["phase"], "stopped", "{stored:#}");
    assert!(
        !stored["upload_error"]
            .as_str()
            .is_some_and(|error| error.contains(RECORD)),
        "{stored:#}"
    );
    assert_eq!(
        case.object(RECORD),
        fs::read(case.state().join("health.json")).ok()
    );
}

/// A running `sim-host watch` and the JSON line each finished cycle
/// printed.
struct Watching {
    running: Running,
    lines: Arc<Mutex<Vec<Value>>>,
}

impl Watching {
    fn lines(&self) -> Vec<Value> {
        self.lines.lock().expect("the lines").clone()
    }

    /// Waits until `count` cycles have printed their lines, and returns
    /// the last one.
    fn cycles(&self, case: &Case, count: usize) -> Value {
        case.wait_for(&format!("{count} watch cycles"), |_| {
            self.lines.lock().expect("the lines").len() >= count
        });
        self.lines()[count - 1].clone()
    }

    /// The cycle lines from index `before` on, once two lines past the
    /// count printed at this call have arrived. Read `before` ahead of a
    /// change to the bucket or the state and call this after the change:
    /// the cycle that consumed the change printed at or past `before`, and
    /// the last line returned comes from a cycle that began after the first
    /// line this call waited for had printed, so after the change.
    fn since(&self, case: &Case, before: usize) -> Vec<Value> {
        let seen = self.lines().len();
        self.cycles(case, seen + 2);
        self.lines()[before..seen + 2].to_vec()
    }

    /// Waits for two more cycle lines than have printed so far.
    fn next_two(&self, case: &Case) -> Vec<Value> {
        self.since(case, self.lines().len())
    }
}

/// The sum of a numeric field over cycle lines.
fn summed(lines: &[Value], field: &str) -> u64 {
    lines
        .iter()
        .map(|line| line[field].as_u64().expect("a count"))
        .sum()
}

/// The sorted names under `events/` that start with `prefix`, staged
/// objects of the fake left out.
fn event_names(case: &Case, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(case.bucket().join("events"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(prefix) && !name.ends_with(".staged"))
        .collect();
    names.sort();
    names
}

fn watch(case: &Case, state: &Path) -> Watching {
    watch_every(case, state, 1)
}

fn watch_every(case: &Case, state: &Path, interval: u64) -> Watching {
    let interval = interval.to_string();
    let mut child = case
        .command(&[
            "watch",
            "--bucket",
            "sims",
            "--state",
            state.to_str().expect("a text path"),
            "--interval",
            &interval,
        ])
        .spawn()
        .expect("the watch starts");
    let stdout = child.stdout.take().expect("the watch's output");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if let Ok(line) = serde_json::from_str(&line) {
                sink.lock().expect("the lines").push(line);
            }
        }
    });
    Watching {
        running: Running(Some(child)),
        lines,
    }
}

fn latest(case: &Case) -> Value {
    serde_json::from_slice(&case.object("reports/latest.json").expect("a stored report"))
        .expect("the stored report parses")
}

/// The keys of the root objects the calls from index `from` on read or
/// asked the length of.
fn root_reads(case: &Case, from: usize) -> Vec<String> {
    calls(case, "aws")[from..]
        .iter()
        .filter(|call| call["op"] == "get-object" || call["op"] == "head-object")
        .filter_map(|call| call["key"].as_str())
        .filter(|key| key.starts_with("roots/"))
        .map(str::to_owned)
        .collect()
}

/// Stores a root of `build` on `host` whose list holds one line for each
/// of `keys`, and an ok record for its host.
fn keyed_root(case: &Case, host: &str, nonce: &str, build: &str, keys: &[&str]) -> String {
    let campaign = format!("sim.{host}.{nonce}");
    let counts: serde_json::Map<String, Value> = keys
        .iter()
        .map(|key| ((*key).to_owned(), json!(1)))
        .collect();
    let status = envelope(
        &campaign,
        build,
        host,
        sim_host::host::now_s(),
        swept(10, 9, Value::Object(counts)),
    );
    let lines: Vec<Value> = keys
        .iter()
        .enumerate()
        .map(|(run, key)| suspect(&campaign, build, run as u64, key))
        .collect();
    stored_root(case, &status, &lines, &no_findings());
    campaign
}

/// The path of `campaign`'s cache entry under the watch's `state`.
fn cache_entry(state: &Path, campaign: &str) -> PathBuf {
    state
        .join("cache")
        .join(sim_host::file::sha256(campaign.as_bytes()))
}

/// A listing row for the stored object at `key`, with the fake's ETag.
fn listed_row(case: &Case, key: &str) -> Value {
    let body = case.object(key).expect("an object");
    json!({"Key": key, "Size": body.len(),
           "ETag": format!("\"{}\"", sim_host::file::sha256(&body))})
}

/// Makes the fake answer every `roots/` listing with `contents`.
fn canned_roots(case: &Case, contents: Vec<Value>) {
    fs::write(
        case.dir.join("aws.listing.roots_"),
        json!({"Contents": contents}).to_string(),
    )
    .expect("a listing");
}

/// The call index of the `nth` listing of `prefix` from call index `from`
/// on, counting from 1.
fn listing_index(case: &Case, prefix: &str, from: usize, nth: usize) -> usize {
    calls(case, "aws")
        .iter()
        .enumerate()
        .skip(from)
        .filter(|(_, call)| call["op"] == "list-objects-v2" && call["prefix"] == prefix)
        .nth(nth - 1)
        .map(|(index, _)| index)
        .expect("the listing")
}

/// Over unchanged roots a cycle reads no root object, a changed root is
/// read again status first while the others come from the cache, and the
/// document equals a full report after a changed list, a removed root and
/// a deleted cache.
fn the_watch_reads_only_changed_roots_and_its_document_equals_a_full_read() {
    let case = Case::new("watch-cache");
    let build = "1".repeat(64);
    let began = sim_host::host::now_s();
    let a = keyed_root(&case, "i-0000000a", "aa", &build, &["k1"]);
    let b = keyed_root(&case, "i-0000000b", "bb", &build, &["k2"]);
    let c = keyed_root(&case, "i-0000000c", "cc", &build, &[]);
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    let first = watching.cycles(&case, 1);
    assert_eq!(
        (first["read"].clone(), first["cached"].clone()),
        (json!(3), json!(0))
    );
    let from = calls(&case, "aws").len();
    let second = watching.cycles(&case, 2);
    assert_eq!(
        (second["read"].clone(), second["cached"].clone()),
        (json!(0), json!(3))
    );
    let third = watching.cycles(&case, 3);
    assert_eq!(
        root_reads(&case, from),
        Vec::<String>::new(),
        "unchanged roots cost listing calls only"
    );
    assert!(
        third["calls"].as_u64() < first["calls"].as_u64(),
        "{first} {third}"
    );
    let (_, _, full, _) = report(&case, &[]);
    let stored = latest(&case);
    assert_eq!(stored["document"], full);
    let seconds = stored["seconds"].as_f64().expect("the stored seconds");
    assert!(
        (0.0..60.0).contains(&seconds),
        "seconds, not milliseconds: {stored:#}"
    );
    let written = stored["written"].as_u64().expect("the time written");
    assert!(
        (began..=sim_host::host::now_s()).contains(&written),
        "{written} is a Unix second of this case"
    );
    for line in [&first, &second, &third] {
        assert!(
            line["seconds"]
                .as_f64()
                .is_some_and(|seconds| seconds >= 0.0),
            "{line}"
        );
    }
    let mut changed = envelope(
        &a,
        &build,
        "i-0000000a",
        sim_host::host::now_s(),
        swept(20, 19, json!({"k1": 1})),
    );
    changed["stint"] = json!(5);
    let from = calls(&case, "aws").len();
    let before = watching.lines().len();
    case.put(
        &format!("roots/{a}/status.json"),
        changed.to_string().as_bytes(),
    );
    let after = watching.since(&case, before);
    assert_eq!(
        summed(&after, "read"),
        1,
        "the changed root is read once: {after:?}"
    );
    let reads = root_reads(&case, from);
    assert_eq!(
        reads.first().map(String::as_str),
        Some(format!("roots/{a}/status.json").as_str()),
        "{reads:?}"
    );
    assert!(
        reads
            .iter()
            .all(|key| key.starts_with(&format!("roots/{a}/"))),
        "{reads:?}"
    );
    let (_, _, full, _) = report(&case, &[]);
    assert_eq!(latest(&case)["document"], full);
    assert_eq!(full["roots"][&a]["runs"], 20);
    let rerun = |document: &Value| {
        document["builds"][&build]["failures"]
            .as_array()
            .expect("failure groups")
            .iter()
            .find(|group| group["key"] == "k2")
            .map(|group| group["rerun"]["run"].clone())
    };
    assert_eq!(rerun(&latest(&case)["document"]), Some(json!(0)));
    let from = calls(&case, "aws").len();
    let before = watching.lines().len();
    let list = format!("{}\n", suspect(&b, &build, 3, "k2"));
    case.put(&format!("roots/{b}/suspects.jsonl"), list.as_bytes());
    let after = watching.since(&case, before);
    assert_eq!(summed(&after, "read"), 1, "{after:?}");
    let reads = root_reads(&case, from);
    assert!(
        reads.contains(&format!("roots/{b}/suspects.jsonl"))
            && reads
                .iter()
                .all(|key| key.starts_with(&format!("roots/{b}/"))),
        "a changed list under an unchanged status is read again: {reads:?}"
    );
    let document = latest(&case)["document"].clone();
    assert_eq!(
        rerun(&document),
        Some(json!(3)),
        "the stored document folds the new list"
    );
    let (_, _, full, _) = report(&case, &[]);
    assert_eq!(document, full);
    for name in ["status.json", "suspects.jsonl", "findings.json"] {
        fs::remove_file(case.bucket().join(format!("roots/{c}/{name}"))).expect("the root leaves");
    }
    watching.next_two(&case);
    let document = latest(&case)["document"].clone();
    assert!(
        document["roots"].get(&c).is_none(),
        "a removed root leaves the totals"
    );
    assert_eq!(document["builds"][&build]["roots"], 2);
    let entries = fs::read_dir(state.join("cache"))
        .expect("the cache")
        .count();
    assert_eq!(entries, 2, "the removed root's entry is removed");
    let before = watching.lines().len();
    fs::remove_dir_all(state.join("cache")).expect("the cache is deleted");
    let rebuilt = watching.since(&case, before);
    assert_eq!(summed(&rebuilt, "read"), 2, "{rebuilt:?}");
    let (_, _, full, _) = report(&case, &[]);
    assert_eq!(latest(&case)["document"], full);
    stop(watching.running);
    assert!(
        latest(&case)["document"].is_object(),
        "the stored report parses after a stop"
    );
}

/// A format 2 or 3 cache entry can contain just `status.json` even when
/// the listing includes `findings.json`. The watch fetches the findings
/// from the bucket before it folds the root.
fn an_old_status_only_entry_refreshes_the_root_payload() {
    for (format, member) in [(2, json!({"p":["TOKEN"]})), (3, json!("TOKEN"))] {
        let case = Case::new(&format!("watch-upgrade-{format}"));
        let host = "i-0000000a";
        let campaign = "sim.i-0000000a.aa";
        let build = "2".repeat(64);
        let mut status = envelope(
            campaign,
            &build,
            host,
            sim_host::host::now_s(),
            swept(3, 3, json!({})),
        );
        status["sweep_status"]["unreached"] = member;
        let findings = json!({"findings":[{"id":"f1","resolved":false,"dispositions":[{"decision":"product"}]}],"release_blockers":[]});
        stored_root(&case, &status, &[], &findings);
        let raw = status.to_string().replace("\"TOKEN\"", "1e400");
        case.put(&format!("roots/{campaign}/status.json"), raw.as_bytes());
        let state = case.dir.join("watch");
        let path = cache_entry(&state, campaign);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listed: BTreeMap<_, _> = ["status.json", "findings.json", "suspects.jsonl"]
            .into_iter()
            .map(|name| {
                let row = listed_row(&case, &format!("roots/{campaign}/{name}"));
                (name, json!([row["Size"], row["ETag"]]))
            })
            .collect();
        let header = json!({"format":format,"campaign":campaign,"listed":listed,"parts":[{"read":raw.len()},null,null]});
        let body = format!("{header}\n{raw}");
        fs::write(
            path,
            format!("{}\n{body}", sim_host::file::sha256(body.as_bytes())),
        )
        .unwrap();
        let watching = watch(&case, &state);
        let first = watching.cycles(&case, 1);
        assert_eq!(first["read"], 1, "format {format}");
        assert!(root_reads(&case, 0).contains(&format!("roots/{campaign}/findings.json")));
        let second = watching.cycles(&case, 2);
        assert_eq!(second["cached"], 1, "format {format}");
        let document = latest(&case)["document"].clone();
        stop(watching.running);
        assert_eq!(document, report(&case, &[]).2);
        assert_eq!(
            document["builds"][&build]["findings"][0]["disposition"], "product",
            "format {format}"
        );
        assert!(
            document["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["flag"] == "missing" && f["detail"]["field"] == "unreached"),
            "format {format}"
        );
    }
}

/// An unreadable or unwritable cache entry leads to a read from the
/// bucket and the same document, and a reversed listing gives the same
/// document.
fn a_cache_that_cannot_be_read_or_written_reads_the_bucket() {
    let case = Case::new("watch-cache-fault");
    let build = "2".repeat(64);
    let a = keyed_root(&case, "i-0000000a", "aa", &build, &["k1"]);
    keyed_root(&case, "i-0000000b", "bb", &build, &["k2"]);
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    watching.cycles(&case, 1);
    let expected = latest(&case)["document"].clone();
    let entry = state
        .join("cache")
        .join(sim_host::file::sha256(a.as_bytes()));
    let before = watching.lines().len();
    fs::write(&entry, b"{\"format\": 1").expect("a damaged entry");
    let lines = watching.since(&case, before);
    assert_eq!(summed(&lines, "read"), 1, "{lines:?}");
    assert_eq!(latest(&case)["document"], expected);
    stop(watching.running);
    fs::remove_dir_all(state.join("cache")).expect("the cache is deleted");
    fs::write(state.join("cache"), b"").expect("a file where the cache belongs");
    let watching = watch(&case, &state);
    let lines = [watching.cycles(&case, 1), watching.cycles(&case, 2)];
    assert_eq!(
        (lines[0]["read"].clone(), lines[1]["read"].clone()),
        (json!(2), json!(2)),
        "an entry that cannot be written is read again: {lines:?}"
    );
    assert_eq!(latest(&case)["document"], expected);
    stop(watching.running);
    fs::remove_file(state.join("cache")).expect("the file leaves");
    let watching = watch(&case, &state);
    watching.cycles(&case, 1);
    fs::write(case.dir.join("aws.reverse"), "").expect("a reversed listing");
    watching.next_two(&case);
    assert_eq!(latest(&case)["document"], expected);
    stop(watching.running);
}

/// A download whose object was replaced after the listing reads it again
/// with no condition and leaves no cache entry, and a watch killed during
/// a cycle folds no part of an entry after its restart.
fn a_root_replaced_after_its_listing_enters_no_cache_entry() {
    let case = Case::new("watch-replaced");
    let build = "3".repeat(64);
    let a = keyed_root(&case, "i-0000000a", "aa", &build, &["k1"]);
    let object = |name: &str| listed_row(&case, &format!("roots/{a}/{name}"));
    let mut stale = object("status.json");
    stale["ETag"] = json!("\"an-earlier-version\"");
    canned_roots(
        &case,
        vec![object("findings.json"), stale, object("suspects.jsonl")],
    );
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    watching.cycles(&case, 2);
    let gets: Vec<Value> = calls(&case, "aws")
        .into_iter()
        .filter(|call| {
            call["op"] == "get-object" && call["key"] == format!("roots/{a}/status.json")
        })
        .map(|call| call["if_match"].clone())
        .collect();
    assert_eq!(
        gets[..2],
        [json!("\"an-earlier-version\""), Value::Null],
        "a conditioned download and its unconditioned read: {gets:?}"
    );
    assert!(
        !cache_entry(&state, &a).exists(),
        "a replaced object leaves no entry"
    );
    let (_, _, full, _) = report(&case, &[]);
    assert_eq!(
        latest(&case)["document"],
        full,
        "the unconditioned read folds as a full read under the same listing"
    );
    fs::remove_file(case.dir.join("aws.listing.roots_")).expect("the listing answers again");
    let (_, _, current, _) = report(&case, &[]);
    assert_eq!(full, current);
    watching.next_two(&case);
    assert!(
        cache_entry(&state, &a).exists(),
        "an agreeing read enters the cache"
    );
    watching.running.kill();
    fs::write(cache_entry(&state, &a), b"{\"format\": 1, \"campaign\"")
        .expect("an entry cut by a kill");
    let watching = watch(&case, &state);
    let line = watching.cycles(&case, 1);
    assert_eq!(
        line["read"], 1,
        "a cut entry is read from the bucket: {line}"
    );
    assert_eq!(latest(&case)["document"], current);
    stop(watching.running);
}

/// A root enters the cache only when its listing agrees with the bucket.
/// An object listed absent and absent when asked, and one listed empty and
/// empty when asked, agree: the next cycle folds the root from its entry
/// with no root-object call. An object listed absent that the bucket holds
/// empty, one listed empty that the bucket lacks, and one listed with bytes
/// that is gone at its download disagree: the root gets no entry and is
/// read again at the next cycle. Each document equals a full report under
/// the same listing.
fn a_root_enters_the_cache_only_when_its_listing_agrees_with_the_bucket() {
    let case = Case::new("watch-disagreed");
    let build = "b".repeat(64);
    let a = keyed_root(&case, "i-0000000a", "aa", &build, &["k1"]);
    let object = |name: &str| listed_row(&case, &format!("roots/{a}/{name}"));
    let suspects = format!("roots/{a}/suspects.jsonl");
    let findings = format!("roots/{a}/findings.json");
    let state = case.dir.join("watch");
    let run = |what: &str, asked: &str, admitted: bool| {
        let _ = fs::remove_file(cache_entry(&state, &a));
        let from = calls(&case, "aws").len();
        let watching = watch(&case, &state);
        let lines = [watching.cycles(&case, 1), watching.cycles(&case, 2)];
        let output = stop(watching.running);
        let second = if admitted { (0, 1) } else { (1, 0) };
        assert_eq!(
            (
                lines[0]["read"].clone(),
                lines[1]["read"].clone(),
                lines[1]["cached"].clone()
            ),
            (json!(1), json!(second.0), json!(second.1)),
            "{what}: {lines:?} {output:?}"
        );
        assert!(
            calls(&case, "aws")[from..]
                .iter()
                .any(|call| call["key"] == asked
                    && ["head-object", "get-object"].contains(&call["op"].as_str().unwrap_or(""))),
            "{what}: the bucket is asked of {asked}"
        );
        assert_eq!(cache_entry(&state, &a).exists(), admitted, "{what}");
        if admitted {
            assert_eq!(
                root_reads(&case, listing_index(&case, "roots/", from, 2)),
                Vec::<String>::new(),
                "{what}: a folded entry costs no root-object call"
            );
        }
        let (_, _, full, _) = report(&case, &[]);
        assert_eq!(latest(&case)["document"], full, "{what}");
    };
    fs::remove_file(case.bucket().join(&findings)).expect("the findings leave");
    canned_roots(&case, vec![object("status.json"), object("suspects.jsonl")]);
    run(
        "an object absent in the listing and the bucket",
        &findings,
        true,
    );
    case.put(&findings, no_findings().to_string().as_bytes());
    case.put(&suspects, b"");
    canned_roots(
        &case,
        vec![
            object("findings.json"),
            object("status.json"),
            json!({"Key": suspects, "Size": 0, "ETag": "\"an-empty-list\""}),
        ],
    );
    run(
        "an object empty in the listing and the bucket",
        &suspects,
        true,
    );
    canned_roots(&case, vec![object("findings.json"), object("status.json")]);
    run("an object listed absent and stored empty", &suspects, false);
    fs::remove_file(case.bucket().join(&suspects)).expect("the list leaves");
    canned_roots(
        &case,
        vec![
            object("findings.json"),
            object("status.json"),
            json!({"Key": suspects, "Size": 0, "ETag": "\"an-empty-list\""}),
        ],
    );
    run(
        "an object listed empty and absent when asked",
        &suspects,
        false,
    );
    case.put(
        &suspects,
        format!("{}\n", suspect(&a, &build, 0, "k1")).as_bytes(),
    );
    let gone = object("findings.json");
    fs::remove_file(case.bucket().join(&findings)).expect("the findings leave");
    canned_roots(
        &case,
        vec![gone, object("status.json"), object("suspects.jsonl")],
    );
    let from = calls(&case, "aws").len();
    run("an object gone at its download", &findings, false);
    assert!(calls(&case, "aws")[from..].iter().any(|call| {
        call["op"] == "get-object"
            && call["key"] == findings.as_str()
            && call["if_match"].is_string()
    }));
}

fn written_ahead(document: &Value, campaign: &str) -> bool {
    document["flags"]
        .as_array()
        .expect("flags")
        .iter()
        .any(|flag| flag["root"] == campaign && flag["detail"]["field"] == "written")
}

/// `report` judges a root at the clock reading taken right after its
/// `status.json` download, before its payload downloads, and the watch
/// judges a root it reads from the bucket at that reading too, not at
/// the reading of the cycle's start. The stored `seconds` runs to just
/// before the report put, the printed `seconds` covers the whole cycle,
/// and the next report stores that whole figure as `previous_seconds`.
fn a_root_is_judged_at_the_reading_after_its_status_download() {
    let case = Case::new("watch-reading");
    let build = "f".repeat(64);
    let campaign = "sim.i-0000000a.aa";
    let ahead = |seconds: u64| {
        let written = sim_host::host::now_s() + 300 + seconds;
        let status = envelope(
            campaign,
            &build,
            "i-0000000a",
            written,
            swept(10, 9, json!({})),
        );
        (written, status)
    };
    let slow_findings = case
        .dir
        .join(format!("aws.delay.roots_{campaign}_findings.json"));
    fs::write(&slow_findings, "10000").expect("a slow findings download");
    let status_key = format!("roots/{campaign}/status.json");
    let mut judged = None;
    for _ in 0..3 {
        let (written, status) = ahead(5);
        stored_root(&case, &status, &[], &no_findings());
        let from = calls(&case, "aws").len();
        let (_, _, output, stderr) = report(&case, &[]);
        let asked = calls(&case, "aws")[from..]
            .iter()
            .find(|call| call["op"] == "get-object" && call["key"] == status_key.as_str())
            .and_then(|call| call["t"].as_u64())
            .expect("the status download");
        if asked / 1_000 + 1 + 300 < written {
            judged = Some((output, stderr));
            break;
        }
    }
    let (output, stderr) = judged.expect("a report that read the status within 4 seconds");
    assert!(
        written_ahead(&output, campaign),
        "a delayed payload leaves the reading at the status download: {stderr}{output:#}"
    );
    fs::remove_file(&slow_findings).expect("the findings answer at once");
    let (_, status) = ahead(5);
    case.put(&status_key, status.to_string().as_bytes());
    fs::write(
        case.dir
            .join(format!("aws.delay.roots_{campaign}_status.json")),
        "10000",
    )
    .expect("a slow status download");
    fs::write(case.dir.join("aws.delay.reports_latest.json"), "2000").expect("a slow report put");
    let watching = watch_every(&case, &case.dir.join("watch"), 4);
    let first = watching.cycles(&case, 1);
    let stored = latest(&case);
    assert!(
        !written_ahead(&stored["document"], campaign),
        "the watch judges the root after its status download: {stored:#}"
    );
    let printed = first["seconds"].as_f64().expect("the printed seconds");
    let before_put = stored["seconds"].as_f64().expect("the stored seconds");
    assert!(
        (10.0..printed - 1.5).contains(&before_put) && printed < 60.0,
        "seconds, from the cycle's start to the report put and to its end: {before_put} {printed}"
    );
    assert_eq!(stored["previous_seconds"], Value::Null, "{stored:#}");
    watching.cycles(&case, 2);
    let next = latest(&case);
    assert_eq!(
        next["previous_seconds"].as_f64(),
        Some(printed),
        "the next report stores the whole first cycle: {next:#}"
    );
    stop(watching.running);
}

fn failure_record(case: &Case, profile: &str, key: &str) -> Option<Vec<u8>> {
    let id = sim_host::file::sha256(format!("{profile}\0{key}").as_bytes());
    case.object(&format!("events/failure-{id}.json"))
}

fn failure_records(case: &Case) -> Vec<String> {
    event_names(case, "failure-")
}

/// Each failure identity gets one record, created once with the group of
/// the lowest build that lists it: a second build of the identity, a
/// restarted watch and a second watch on another state directory leave
/// each record byte-equal, and the second watch reports no error.
fn each_failure_identity_gets_one_record_created_once() {
    let case = Case::new("watch-records");
    let (low, high) = ("4".repeat(64), "5".repeat(64));
    let key = "violation: one";
    let a = keyed_root(&case, "i-0000000a", "aa", &high, &[key]);
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    watching.cycles(&case, 1);
    let first = failure_record(&case, "p", key).expect("a record of the identity");
    let record: Value = serde_json::from_slice(&first).expect("the record parses");
    let group = &latest(&case)["document"]["builds"][&high]["failures"][0];
    assert_eq!(record["format"], 1);
    assert_eq!(
        record["id"],
        sim_host::file::sha256(format!("p\0{key}").as_bytes()).as_str(),
        "the record names the id its key holds"
    );
    assert_eq!(record["build"], high.as_str());
    for field in ["profile", "key", "count", "roots", "rerun"] {
        assert_eq!(record[field], group[field], "{field}");
    }
    assert_eq!(record["rerun"]["campaign"], a.as_str());
    let before = watching.lines().len();
    keyed_root(&case, "i-0000000b", "bb", &low, &[key]);
    let lines = watching.since(&case, before);
    assert!(
        latest(&case)["document"]["builds"].get(&low).is_some(),
        "the second build is folded"
    );
    assert_eq!(
        summed(&lines, "failures"),
        0,
        "the same identity in a second build creates nothing"
    );
    assert_eq!(failure_record(&case, "p", key), Some(first.clone()));
    let before = watching.lines().len();
    keyed_root(&case, "i-0000000b", "b2", &low, &["violation: two"]);
    let lines = watching.since(&case, before);
    assert_eq!(summed(&lines, "failures"), 1, "{lines:?}");
    let second: Value = serde_json::from_slice(
        &failure_record(&case, "p", "violation: two").expect("a second record"),
    )
    .expect("it parses");
    assert_eq!(second["build"], low.as_str());
    stop(watching.running);
    assert_eq!(failure_records(&case).len(), 2);
    let records = failure_records(&case)
        .iter()
        .map(|name| case.object(&format!("events/{name}")))
        .collect::<Vec<_>>();
    let restarted = watch(&case, &state);
    let line = restarted.cycles(&case, 1);
    assert_eq!(
        line["failures"], 0,
        "a restarted watch knows both identities"
    );
    stop(restarted.running);
    let calls_before = calls(&case, "aws").len();
    let other = watch(&case, &case.dir.join("other-watch"));
    let line = other.cycles(&case, 1);
    let output = stop(other.running);
    assert_eq!(line["failures"], 0, "{line}");
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "a second watch reports no error: {output:?}"
    );
    let creates: Vec<Value> = calls(&case, "aws")[calls_before..]
        .iter()
        .filter(|call| {
            call["op"] == "put-object"
                && call["key"]
                    .as_str()
                    .is_some_and(|key| key.starts_with("events/failure-"))
        })
        .cloned()
        .collect();
    assert!(
        creates.is_empty(),
        "a watch that lists the records creates none: {creates:?}"
    );
    let after = failure_records(&case)
        .iter()
        .map(|name| case.object(&format!("events/{name}")))
        .collect::<Vec<_>>();
    assert_eq!(after, records, "no record is replaced");
}

/// Twenty new identities give sixteen records in one cycle, lowest id
/// first, and twenty after two; a create that finds its record present,
/// as a record stored by another watch, counts it as known.
fn twenty_new_identities_are_recorded_within_two_cycles() {
    let case = Case::new("watch-bound");
    let build = "6".repeat(64);
    let keys: Vec<String> = (0..20).map(|index| format!("violation: {index}")).collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    keyed_root(&case, "i-0000000a", "aa", &build, &refs);
    let mut ids: Vec<String> = keys
        .iter()
        .map(|key| sim_host::file::sha256(format!("p\0{key}").as_bytes()))
        .collect();
    ids.sort();
    fs::write(case.dir.join("aws.fail.put-object"), "").expect("failing puts");
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    case.wait_for(
        "the hosts/ listing after events/failure- returned",
        |case| {
            calls(case, "aws")
                .iter()
                .any(|call| call["prefix"] == "hosts/")
        },
    );
    let planted = format!("events/failure-{}.json", ids[0]);
    case.put(&planted, b"{}");
    fs::remove_file(case.dir.join("aws.fail.put-object")).expect("puts succeed");
    let first = watching.cycles(&case, 1);
    assert_eq!(
        (first["failures"].clone(), first["waiting"].clone()),
        (json!(16), json!(4)),
        "{first}"
    );
    assert_eq!(failure_records(&case).len(), 16);
    let created: Vec<String> = failure_records(&case)
        .iter()
        .map(|name| name["failure-".len()..name.len() - ".json".len()].to_owned())
        .collect();
    assert_eq!(created, ids[..16], "lowest id first");
    assert_eq!(case.object(&planted).as_deref(), Some(&b"{}"[..]));
    assert!(
        calls(&case, "aws")
            .iter()
            .any(|call| call["op"] == "put-object"
                && call["key"] == planted.as_str()
                && call["once"] == true),
        "the planted record was asked for once and found present"
    );
    let second = watching.cycles(&case, 2);
    assert_eq!(
        (second["failures"].clone(), second["waiting"].clone()),
        (json!(4), json!(0))
    );
    assert_eq!(failure_records(&case).len(), 20);
    stop(watching.running);
}

fn host_events(case: &Case) -> Vec<Value> {
    event_names(case, "hosts-")
        .iter()
        .map(|name| {
            serde_json::from_slice(&case.object(&format!("events/{name}")).expect("an event"))
                .expect("the event parses")
        })
        .collect()
}

/// The puts of keys under `prefix` logged from call index `from` on.
fn puts_under(case: &Case, prefix: &str, from: usize) -> usize {
    calls(case, "aws")[from..]
        .iter()
        .filter(|call| {
            call["op"] == "put-object"
                && call["key"]
                    .as_str()
                    .is_some_and(|key| key.starts_with(prefix))
        })
        .count()
}

/// The open set the watch saved in `state`, `Null` when none parses.
fn saved_open(state: &Path) -> Value {
    read_lenient(&state.join("alerts.json"))["open"].clone()
}

/// The stored failure records' names and bytes.
fn stored_records(case: &Case) -> Vec<(String, Option<Vec<u8>>)> {
    failure_records(case)
        .into_iter()
        .map(|name| {
            let bytes = case.object(&format!("events/{name}"));
            (name, bytes)
        })
        .collect()
}

/// An alert opens once per condition: an unchanged condition gives one
/// event, a recovery and a new condition give a new one, a cycle whose
/// event put failed stores the event once puts succeed, a restart after a
/// lost alert state stores the alerts once more, and a watch killed after
/// its event was stored and before the alerts were saved stores them once
/// more after its restart and replaces no failure record.
fn a_host_alert_opens_once_per_condition_and_survives_a_failed_cycle() {
    let case = Case::new("watch-alerts");
    let build = "7".repeat(64);
    keyed_root(&case, "i-0000000a", "aa", &build, &["k"]);
    let mut blocked = host_record("i-0000000a");
    blocked["phase"] = json!("blocked");
    blocked["reason"] = json!("builds/x is missing");
    stored_host(&case, "i-0000000a", &blocked);
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    watching.cycles(&case, 3);
    let events = host_events(&case);
    assert_eq!(
        events.len(),
        1,
        "one event across three cycles: {events:#?}"
    );
    let opened =
        json!([{"flag": "unhealthy", "instance": "i-0000000a", "reasons": ["phase blocked"]}]);
    assert_eq!(events[0]["alerts"], opened);
    let key = &event_names(&case, "hosts-")[0];
    assert_eq!(events[0]["format"], 1);
    assert_eq!(
        format!(
            "hosts-{}.json",
            events[0]["written"].as_u64().expect("a second")
        ),
        *key,
        "an event is written at the second its key names"
    );
    let records = stored_records(&case);
    assert_eq!(records.len(), 1);
    stored_host(&case, "i-0000000a", &host_record("i-0000000a"));
    watching.next_two(&case);
    assert_eq!(host_events(&case).len(), 1, "a recovery stores no event");
    fs::write(case.dir.join("aws.fail.prefix"), "events/hosts-").expect("failing event puts");
    let from = calls(&case, "aws").len();
    stored_host(&case, "i-0000000a", &blocked);
    case.wait_for("two failed event puts", |case| {
        puts_under(case, "events/hosts-", from) >= 2
    });
    assert_eq!(
        host_events(&case).len(),
        1,
        "the failed cycles stored no event and kept the alert due"
    );
    fs::remove_file(case.dir.join("aws.fail.prefix")).expect("puts succeed");
    case.wait_for("the event after the failure", |case| {
        host_events(case).len() == 2
    });
    watching.next_two(&case);
    assert_eq!(
        host_events(&case).len(),
        2,
        "the turned-unhealthy host gives one new event"
    );
    stop(watching.running);
    fs::remove_file(state.join("alerts.json")).expect("the alert state is lost");
    let watching = watch(&case, &state);
    case.wait_for("the alerts once more", |case| host_events(case).len() == 3);
    watching.next_two(&case);
    assert_eq!(host_events(&case).len(), 3);
    stored_host(&case, "i-0000000a", &host_record("i-0000000a"));
    case.wait_for("the closed alert saved", |_| {
        saved_open(&state) == json!([])
    });
    fs::write(case.dir.join("aws.stall.prefix"), "events/hosts-").expect("stalled event puts");
    stored_host(&case, "i-0000000a", &blocked);
    case.wait_for("the stored event of a stalled put", |case| {
        host_events(case).len() == 4
    });
    watching.running.kill();
    assert_eq!(
        saved_open(&state),
        json!([]),
        "the kill came before the alerts were saved"
    );
    fs::remove_file(case.dir.join("aws.stall.prefix")).expect("puts answer");
    let watching = watch(&case, &state);
    case.wait_for("the alerts saved after the restart", |_| {
        saved_open(&state) == json!([{"flag": "unhealthy", "instance": "i-0000000a"}])
    });
    let events = host_events(&case);
    assert!(
        (4..=5).contains(&events.len()),
        "the restart stores the alerts once more, or finds this second's event \
         stored with its bytes: {events:#?}"
    );
    assert_eq!(events[events.len() - 1]["alerts"], opened);
    let count = events.len();
    watching.next_two(&case);
    assert_eq!(host_events(&case).len(), count);
    assert_eq!(
        stored_records(&case),
        records,
        "no failure record is replaced"
    );
    stop(watching.running);
}

/// A host event whose key holds another event fails its cycle and keeps
/// its alerts due, so a later second stores an event that lists them; the
/// object at the held key retains its bytes.
fn a_host_event_key_held_by_another_event_keeps_its_alerts_due() {
    let case = Case::new("watch-held-event");
    let build = "c".repeat(64);
    keyed_root(&case, "i-0000000a", "aa", &build, &[]);
    let mut blocked = host_record("i-0000000a");
    blocked["phase"] = json!("blocked");
    stored_host(&case, "i-0000000a", &blocked);
    let mut stale = host_record("i-0000000b");
    stale["written"] = json!(sim_host::host::now_s() - 3 * 600);
    stored_host(&case, "i-0000000b", &stale);
    stored_host(&case, "i-0000000c", &host_record("i-0000000d"));
    fs::write(case.dir.join("aws.collide.prefix"), "events/hosts-").expect("a held event key");
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    case.wait_for("an event at a free second", |case| {
        host_events(case)
            .iter()
            .any(|event| event.get("alerts").is_some())
    });
    let held: Vec<String> = event_names(&case, "hosts-")
        .into_iter()
        .filter(|name| {
            case.object(&format!("events/{name}")).as_deref() == Some(&b"{\"another\": true}"[..])
        })
        .collect();
    assert_eq!(held.len(), 1, "the first event put found its key held");
    assert!(
        calls(&case, "aws")
            .iter()
            .any(|call| call["op"] == "get-object"
                && call["key"] == format!("events/{}", held[0]).as_str()),
        "the held object is read back"
    );
    let event = host_events(&case)
        .into_iter()
        .find(|event| event.get("alerts").is_some())
        .expect("the event");
    let flags: Vec<(String, String)> = event["alerts"]
        .as_array()
        .expect("alerts")
        .iter()
        .map(|alert| {
            (
                alert["flag"].as_str().expect("a flag").to_owned(),
                alert["instance"].as_str().expect("an instance").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        flags,
        [
            ("missing".to_owned(), "i-0000000c".to_owned()),
            ("silent".to_owned(), "i-0000000b".to_owned()),
            ("unhealthy".to_owned(), "i-0000000a".to_owned()),
        ]
    );
    let output = stop(watching.running);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("holds another event"),
        "{output:?}"
    );
}

/// A host event put that finds its own bytes stored, as a retry past a
/// lost reply does, counts the event as stored.
fn a_host_event_found_stored_with_its_bytes_counts_as_stored() {
    let case = Case::new("watch-echoed-event");
    keyed_root(&case, "i-0000000a", "aa", &"c".repeat(64), &[]);
    let mut blocked = host_record("i-0000000a");
    blocked["phase"] = json!("blocked");
    stored_host(&case, "i-0000000a", &blocked);
    fs::write(case.dir.join("aws.echo.prefix"), "events/hosts-").expect("echoed event puts");
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    let first = watching.cycles(&case, 1);
    let key = first["hosts_event"]
        .as_str()
        .expect("an event key")
        .to_owned();
    let logged = calls(&case, "aws");
    let put = logged
        .iter()
        .position(|call| call["op"] == "put-object" && call["key"] == key.as_str())
        .expect("the event put");
    assert!(
        logged[put..]
            .iter()
            .any(|call| call["op"] == "get-object" && call["key"] == key.as_str()),
        "the present event is read back"
    );
    assert_eq!(
        saved_open(&state),
        json!([{"flag": "unhealthy", "instance": "i-0000000a"}])
    );
    watching.next_two(&case);
    assert_eq!(event_names(&case, "hosts-").len(), 1, "one event");
    let output = stop(watching.running);
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("holds another event"),
        "{output:?}"
    );
}

fn a_failed_event_put_keeps_the_closures_it_saw() {
    let case = Case::new("watch-closures");
    keyed_root(&case, "i-0000000a", "aa", &"c".repeat(64), &[]);
    let mut blocked_a = host_record("i-0000000a");
    blocked_a["phase"] = json!("blocked");
    let mut blocked_b = host_record("i-0000000b");
    blocked_b["phase"] = json!("blocked");
    stored_host(&case, "i-0000000a", &blocked_a);
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    case.wait_for("the first event", |case| host_events(case).len() == 1);
    fs::write(case.dir.join("aws.fail.prefix"), "events/hosts-").expect("failing event puts");
    let from = calls(&case, "aws").len();
    stored_host(&case, "i-0000000a", &host_record("i-0000000a"));
    stored_host(&case, "i-0000000b", &blocked_b);
    case.wait_for("two failed event puts", |case| {
        puts_under(case, "events/hosts-", from) >= 2
    });
    assert_eq!(
        saved_open(&state),
        json!([]),
        "the closed alert is saved closed and the failed one is not open"
    );
    let from = calls(&case, "aws").len();
    stored_host(&case, "i-0000000a", &blocked_a);
    case.wait_for("two more failed event puts", |case| {
        puts_under(case, "events/hosts-", from) >= 2
    });
    fs::remove_file(case.dir.join("aws.fail.prefix")).expect("puts succeed");
    case.wait_for("the event after the failure", |case| {
        host_events(case).len() == 2
    });
    let instances: Vec<Value> = host_events(&case)[1]["alerts"]
        .as_array()
        .expect("alerts")
        .iter()
        .map(|alert| alert["instance"].clone())
        .collect();
    assert_eq!(
        instances,
        [json!("i-0000000a"), json!("i-0000000b")],
        "the reopened alert is listed with the one whose event failed"
    );
    stop(watching.running);
}

fn a_watch_whose_alert_saves_fail_keeps_its_open_set() {
    let case = Case::new("watch-alert-saves");
    keyed_root(&case, "i-0000000a", "aa", &"c".repeat(64), &[]);
    let mut blocked = host_record("i-0000000a");
    blocked["phase"] = json!("blocked");
    stored_host(&case, "i-0000000a", &blocked);
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    watching.cycles(&case, 2);
    stop(watching.running);
    assert_eq!(event_names(&case, "hosts-").len(), 1);
    let open = json!([{"flag": "unhealthy", "instance": "i-0000000a"}]);
    assert_eq!(saved_open(&state), open);
    let watching = watch(&case, &state);
    watching.cycles(&case, 2);
    assert_eq!(
        event_names(&case, "hosts-").len(),
        1,
        "a restart reads the saved open set"
    );
    let staged = state.join(".alerts.json.staged");
    fs::create_dir(&staged).expect("an entry no staged write can replace");
    fs::write(staged.join("held"), b"x").expect("a file under it");
    let before = watching.lines().len();
    watching.cycles(&case, before + 3);
    assert!(
        !state.join("alerts.json").exists(),
        "a failed save removes the older state"
    );
    assert_eq!(
        event_names(&case, "hosts-").len(),
        1,
        "the running watch repeats no alert while its saves fail"
    );
    let before = watching.lines().len();
    stored_host(&case, "i-0000000a", &host_record("i-0000000a"));
    let lines = watching.since(&case, before);
    assert!(lines.iter().all(|line| line["hosts_event"].is_null()));
    stored_host(&case, "i-0000000a", &blocked);
    case.wait_for("the reopened alert", |case| {
        event_names(case, "hosts-").len() == 2
    });
    watching.next_two(&case);
    assert_eq!(
        event_names(&case, "hosts-").len(),
        2,
        "one event per opening"
    );
    fs::remove_dir_all(&staged).expect("the obstruction leaves");
    case.wait_for("the open set saved again", |_| saved_open(&state) == open);
    stop(watching.running);
    let watching = watch(&case, &state);
    watching.cycles(&case, 2);
    assert_eq!(event_names(&case, "hosts-").len(), 2);
    stop(watching.running);
}

fn a_cycle_sweeps_staged_cache_files_before_its_reads() {
    let case = Case::new("watch-sweep");
    let a = keyed_root(&case, "i-0000000a", "aa", &"c".repeat(64), &[]);
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    watching.cycles(&case, 1);
    stop(watching.running);
    let leftover = state
        .join("cache")
        .join(format!(".{}.staged", sim_host::file::sha256(a.as_bytes())));
    fs::write(&leftover, b"part of an entry").expect("a staged leftover");
    fs::write(case.dir.join("aws.fail.list-prefix"), "hosts/").expect("a failing hosts/ listing");
    let from = calls(&case, "aws").len();
    let watching = watch(&case, &state);
    case.wait_for("two failed hosts/ listings", |case| {
        calls(case, "aws")[from..]
            .iter()
            .filter(|call| call["prefix"] == "hosts/")
            .count()
            >= 2
    });
    assert!(
        !leftover.exists(),
        "the sweep runs before a cycle's first read"
    );
    assert!(cache_entry(&state, &a).exists(), "the entry stays");
    stop(watching.running);
}

/// The watch writes under `reports/` and `events/` only and keeps every
/// object outside those prefixes byte for byte; a second watch on its
/// state directory exits 2, and a stop signal ends it with exit 0 within
/// one second.
fn the_watch_writes_only_its_prefixes_and_one_watch_holds_a_state_directory() {
    let case = Case::new("watch-prefixes");
    let build = "8".repeat(64);
    keyed_root(&case, "i-0000000a", "aa", &build, &["k"]);
    case.put("assignment.json", b"{}");
    let before: Vec<(PathBuf, Vec<u8>)> = snapshot(&case.bucket());
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    watching.cycles(&case, 3);
    let second = Running(Some(
        case.command(&[
            "watch",
            "--bucket",
            "sims",
            "--state",
            state.to_str().expect("a path"),
        ])
        .spawn()
        .expect("a second watch runs"),
    ));
    let (second, _) = exited(second);
    assert_eq!(second.status.code(), Some(2), "{second:?}");
    assert!(String::from_utf8_lossy(&second.stderr).contains("another watch holds"));
    let asked = fake::now_ms();
    let (output, seen) = ended(watching.running, libc::SIGTERM);
    assert!(output.status.success(), "{output:?}");
    assert!(
        seen - asked < 1_000,
        "the stop ends the watch within one poll"
    );
    let after = snapshot(&case.bucket());
    let untouched = |files: &[(PathBuf, Vec<u8>)]| -> Vec<(PathBuf, Vec<u8>)> {
        files
            .iter()
            .filter(|(path, _)| {
                let key = path.strip_prefix(case.bucket()).expect("under the bucket");
                !key.starts_with("reports")
                    && !key.starts_with("events")
                    && !key.starts_with(".checksums/reports")
                    && !key.starts_with(".checksums/events")
            })
            .cloned()
            .collect()
    };
    assert_eq!(
        untouched(&after),
        untouched(&before),
        "objects outside the two prefixes stay"
    );
    let ops: BTreeSet<String> = calls(&case, "aws")
        .iter()
        .filter_map(|call| call["op"].as_str().map(str::to_owned))
        .collect();
    assert!(
        ops.iter().all(
            |op| ["list-objects-v2", "get-object", "head-object", "put-object"]
                .contains(&op.as_str())
        ),
        "{ops:?}"
    );
    for call in calls(&case, "aws")
        .iter()
        .filter(|call| call["op"] == "put-object")
    {
        let key = call["key"].as_str().expect("a key");
        assert!(
            key.starts_with("reports/") || key.starts_with("events/"),
            "{key}"
        );
    }
}

/// Waits past the next UTC midnight when it is less than `seconds` away,
/// so a case whose checks assume one UTC day runs within one.
fn clear_of_midnight(seconds: u64) {
    let into = sim_host::host::now_s() % 86_400;
    if into + seconds >= 86_400 {
        std::thread::sleep(Duration::from_secs(86_400 - into + 1));
    }
}

/// The first cycle of a day creates its summary, and a restart on that day
/// creates no second one.
fn one_summary_is_created_per_utc_day() {
    clear_of_midnight(120);
    let case = Case::new("watch-digest");
    let build = "9".repeat(64);
    keyed_root(&case, "i-0000000a", "aa", &build, &["k"]);
    let mut stale = host_record("i-0000000b");
    stale["written"] = json!(sim_host::host::now_s() - 3 * 600);
    stored_host(&case, "i-0000000b", &stale);
    let began = sim_host::host::now_s();
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    let first = watching.cycles(&case, 1);
    let line = watching.cycles(&case, 2);
    stop(watching.running);
    assert_eq!(first["roots"], 1);
    assert_eq!(
        line["digest"],
        Value::Null,
        "the day's summary is known stored"
    );
    let digests = event_names(&case, "digest-");
    assert_eq!(digests.len(), 1, "{digests:?}");
    let key = format!("events/{}", digests[0]);
    let stored = case.object(&key).expect("the summary");
    let summary: Value = serde_json::from_slice(&stored).expect("it parses");
    assert_eq!(
        key,
        format!(
            "events/digest-{}.json",
            summary["day"].as_str().expect("a day")
        )
    );
    assert_eq!(
        first["digest"],
        key.as_str(),
        "the first cycle names its summary"
    );
    assert_eq!(summary["format"], 1);
    assert!(
        (began..=sim_host::host::now_s()).contains(&summary["written"].as_u64().expect("a second")),
        "{summary:#}"
    );
    assert_eq!(summary["host_counts"]["active"], 1);
    assert_eq!(summary["failure_identities"], 1);
    assert_eq!(summary["builds"][&build]["runs"], 10);
    let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
    for flag in latest(&case)["document"]["flags"]
        .as_array()
        .expect("flags")
    {
        *kinds
            .entry(flag["flag"].as_str().expect("a kind").to_owned())
            .or_default() += 1;
    }
    assert!(
        kinds.contains_key("silent"),
        "the stale host is flagged: {kinds:?}"
    );
    assert_eq!(
        summary["flags"],
        json!(kinds),
        "the summary counts the report's flags by kind"
    );
    let restarted = watch(&case, &state);
    let line = restarted.cycles(&case, 1);
    stop(restarted.running);
    assert_eq!(
        puts(&case, &key),
        2,
        "the restart asks once and finds the summary present: {line}"
    );
    assert_eq!(case.object(&key), Some(stored), "no second summary");
}

/// A failed put of a failure record or of the day's summary leaves it due:
/// the same watch creates it once the put succeeds, records whose puts
/// succeeded stay as they are, and a later cycle asks for neither again.
fn a_failed_record_or_summary_put_leaves_it_due() {
    clear_of_midnight(120);
    let case = Case::new("watch-failed-records");
    let build = "d".repeat(64);
    keyed_root(&case, "i-0000000a", "aa", &build, &["k"]);
    let record = format!("events/failure-{}.json", sim_host::file::sha256(b"p\0k"));
    let fault = case
        .dir
        .join(format!("aws.fail.put-object.{}", record.replace('/', "_")));
    fs::write(&fault, "").expect("a failing record put");
    fs::write(case.dir.join("aws.fail.prefix"), "events/digest-").expect("failing summary puts");
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    case.wait_for("two failed record puts", |case| puts(case, &record) >= 2);
    assert!(
        case.object(&record).is_none(),
        "a failed put stores nothing"
    );
    assert!(
        case.object("reports/latest.json").is_some(),
        "the report put succeeded"
    );
    assert_eq!(
        puts_under(&case, "events/digest-", 0),
        0,
        "a cycle stops at its failed put"
    );
    fs::remove_file(&fault).expect("record puts succeed");
    case.wait_for("the record once its put succeeds", |case| {
        case.object(&record).is_some()
    });
    let stored = case.object(&record);
    case.wait_for("two failed summary puts", |case| {
        puts_under(case, "events/digest-", 0) >= 2
    });
    assert!(event_names(&case, "digest-").is_empty());
    let asked = puts(&case, &record);
    fs::remove_file(case.dir.join("aws.fail.prefix")).expect("summary puts succeed");
    case.wait_for("the summary once its put succeeds", |case| {
        event_names(case, "digest-").len() == 1
    });
    let summaries = puts_under(&case, "events/digest-", 0);
    watching.next_two(&case);
    assert_eq!(puts(&case, &record), asked, "a stored record is known");
    assert_eq!(case.object(&record), stored);
    assert_eq!(
        puts_under(&case, "events/digest-", 0),
        summaries,
        "a stored summary is known for its day"
    );
    stop(watching.running);
}

/// A stop signal ends a watch whose bucket call hangs with exit 0 within
/// one second, and a state path that is no directory refuses the start
/// with exit 2 before any bucket call.
fn a_stop_ends_a_hung_watch_and_an_unusable_state_refuses_it() {
    let case = Case::new("watch-hung");
    keyed_root(&case, "i-0000000a", "aa", &"e".repeat(64), &[]);
    fs::write(case.dir.join("aws.hang.list-prefix"), "roots/").expect("a hanging listing");
    let watching = watch(&case, &case.dir.join("watch"));
    case.wait_for("the hanging roots/ listing", |case| {
        calls(case, "aws")
            .iter()
            .any(|call| call["prefix"] == "roots/")
    });
    let asked = fake::now_ms();
    let (output, seen) = ended(watching.running, libc::SIGTERM);
    assert!(output.status.success(), "{output:?}");
    assert!(
        seen - asked < 1_000,
        "the stop ends the hung call within one second"
    );
    let file = case.dir.join("state-file");
    fs::write(&file, b"").expect("a file where the state belongs");
    let before = calls(&case, "aws").len();
    let refused = Running(Some(
        case.command(&[
            "watch",
            "--bucket",
            "sims",
            "--state",
            file.to_str().expect("a path"),
        ])
        .spawn()
        .expect("the watch runs"),
    ));
    let (refused, _) = exited(refused);
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
    assert_eq!(calls(&case, "aws").len(), before, "no bucket call");
}

/// A listing of `events/failure-` past its bound refuses the start with
/// exit 2, and a failed first listing is retried with no record created
/// before it succeeds.
fn the_watch_starts_only_after_listing_its_known_identities() {
    let case = Case::new("watch-identities");
    let build = "a".repeat(64);
    keyed_root(&case, "i-0000000a", "aa", &build, &["k"]);
    fs::write(case.dir.join("aws.fail.list-prefix"), "events/failure-").expect("a failing listing");
    let state = case.dir.join("watch");
    let watching = watch(&case, &state);
    case.wait_for("two failed listings", |case| {
        calls(case, "aws")
            .iter()
            .filter(|call| call["prefix"] == "events/failure-")
            .count()
            >= 2
    });
    assert!(failure_records(&case).is_empty());
    assert!(
        case.object("reports/latest.json").is_none(),
        "a failed listing stores nothing"
    );
    fs::remove_file(case.dir.join("aws.fail.list-prefix")).expect("the listing answers");
    watching.cycles(&case, 1);
    assert_eq!(failure_records(&case).len(), 1);
    stop(watching.running);
    let page = |objects: usize, next: Option<&str>| {
        let entry = r#"{"Key":"x","Size":0}"#;
        let contents = vec![entry; objects].join(",");
        let next = next.map_or(String::new(), |next| format!(r#","NextToken":"{next}""#));
        format!(r#"{{"Contents":[{contents}]{next}}}"#)
    };
    let half = 1 << 19;
    fs::write(
        case.dir.join("aws.listing.events_failure-"),
        page(half, Some("1")),
    )
    .expect("a page");
    fs::write(
        case.dir.join("aws.listing.events_failure-1"),
        page(half + 1, None),
    )
    .expect("a page");
    let refused = Running(Some(
        case.command(&[
            "watch",
            "--bucket",
            "sims",
            "--state",
            state.to_str().expect("a path"),
        ])
        .spawn()
        .expect("the watch runs"),
    ));
    let (refused, _) = exited(refused);
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
    assert!(String::from_utf8_lossy(&refused.stderr).contains("more than 1048576 objects"));
}
