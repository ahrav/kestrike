//! The single-threaded simulation worker: the crate's module tree compiled
//! under `cfg(test)` without the test harness, so every case runs on the
//! process's one thread. The worker speaks libtest's listing and summary
//! lines to the selection validator and runs the cases of one manifest;
//! case selection decides nothing from the environment, a path or a clock.
//! Given a run manifest file and a bundle path, it runs the manifest into a
//! new bundle; given a bundle and its manifest, it loads the bundle and
//! reports it; given a bundle and a milestone, it forks children at that
//! milestone and judges them; given a cluster manifest and a new directory,
//! it runs a session of committed windows into it, and given a session, it
//! replays it into a new directory and compares the two; given a bundle
//! and a new file, it writes the bundle's narrative into it. Those forms
//! read the named manifest and bundle paths and the executable's own bytes;
//! every form that runs the turn loop also reads the monotonic clock for
//! its wall-time diagnostic, which stays outside the digest, and the branch
//! form reads it for each child's watchdog deadline, which no decision
//! reads. The reduce forms read its library search path, `LD_LIBRARY_PATH`,
//! for its fresh processes to keep, and no decision reads it. Fork runs
//! only here, where every case runs on the process's one thread.
//! Under `INLINE_RECOVERY`, which the worker sets, recovery helpers and a
//! store lane a case starts run their jobs on the worker thread, so the
//! process stays on one thread between stopped boundaries.
//!
//! The module tree's tests and their fixtures compile here without the
//! harness that runs them, so the worker allows the dead code and unused
//! imports and macros they leave; its own cases keep those lints.

#![allow(
    dead_code,
    unused_imports,
    unused_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the worker compiles unit-test fixtures outside its simulation harness"
)]

::core::include!("mod.rs");

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn main() {
    crate::storage::INLINE_RECOVERY.with(|inline| inline.set(true));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    std::process::exit(cases::run(
        &args,
        &cases::CASES,
        &cases::IGNORED,
        &mut out,
        &mut err,
    ));
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn main() {}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[warn(dead_code, unused_imports, unused_macros, clippy::disallowed_methods)]
mod cases {
    use std::cell::Cell;
    use std::io::Write;

    use crate::native::wire_fuzz_tests::WIRE;
    use crate::net::world_tests::branch::{
        Branched, ChildPlant, MAX_SIBLINGS, MAX_SUFFIXES, Unbranched, branch, milestone_lines,
        terminal_text,
        tests::{diverging_before, forked_suffixes_keep_the_pending_put_prefix},
    };
    use crate::net::world_tests::bundle::tests::{
        an_old_bundle_decodes_its_action_codes, least_maximum,
    };
    use crate::net::world_tests::bundle::{
        Admitted, Breach, OBSERVED, Observed, admit, breach, observed, traced, unsuccessful_rule,
    };
    use crate::net::world_tests::campaign_fuzz::{
        CAMPAIGN, PLANTED,
        tests::{
            PANICKING, a_merge_enters_the_driver_in_its_inner_process,
            a_panicking_input_tears_down_before_the_driver_aborts,
            a_parser_failure_replays_and_minimizes,
            a_wrong_byte_input_audits_tears_down_then_aborts,
            the_appended_seeds_replay_alike_in_fresh_processes,
            the_campaign_driver_loads_seeds_and_executes_positively,
            the_parser_targets_load_seeds_and_execute_positively,
        },
    };
    use crate::net::world_tests::catalog::SUMMARY;
    use crate::net::world_tests::cluster::{self, Reached};
    use crate::net::world_tests::histories::Expect;
    use crate::net::world_tests::histories::cohorts::COHORTS;
    use crate::net::world_tests::replay::{
        Identity, Reduced, Refused as ReplayRefused, Replayed, Stop, Verify, recorded, reduce,
        replay_recording, violated,
    };
    use crate::net::world_tests::schedule::{Budget, Reduced as ScheduleReduced};
    use crate::net::world_tests::suffix::{
        TreePlant, explore, tests::composed_bounded_tree_accounts_every_leaf_and_frontier,
    };
    use crate::sim::choice_tests::{
        ROOT, launched, replaying, sequence, sequence_holds, vectors_hold,
    };
    use crate::sim::cut_tests::{PINNED as PINNED_CUTS, pinned_cuts};
    use crate::sim::entropy_tests::{PINNED, pinned_identity};
    use crate::sim::fork::Refusal as ForkRefusal;
    use crate::sim::fork_tests::{
        credited_only_on_framed_success, inherited_descriptors_close, refused_off_its_boundary,
        watchdog_classifies_a_hung_child,
    };
    use crate::sim::fuzz::{Target as FuzzTarget, drive, minimized};
    use crate::sim::ledger::{Campaign, LIMITS, campaign, counts};
    use crate::sim::long_run_tests::{Gate, MANIFEST as LONG_RUN_MANIFEST, Plants};
    use crate::sim::manifest::Manifest;
    use crate::sim::trace::{Field, Infrastructure, Loaded, Outcome, RECORD, Terminal, load, read};
    use crate::sim::window::{Status, recorded as recovery_census};
    use crate::storage::churn_tests::scaled::{RUN as SCALED_RUN, geometries, seeds};
    use crate::storage::record::fuzz_tests::{RECORD as RECORD_TARGET, RECORD_CONTROL};

    pub(super) type Case = (&'static str, fn() -> Result<(), String>);

    /// Every case the worker runs, in listing order; a build under
    /// `cfg(protocol_contract)` ends it with the protocol contract case.
    pub(super) const CASES: [Case; 54 + cfg!(protocol_contract) as usize] = [
        (
            "choice::derivation_vectors_match_in_a_fresh_process",
            vectors_hold,
        ),
        (
            "choice::the_pinned_sequence_draws_in_a_fresh_process",
            sequence_holds,
        ),
        (
            "choice::a_recorded_sequence_replays_in_this_process",
            replays,
        ),
        ("worker::the_counting_allocator_is_live", allocator_live),
        (
            "worker::a_sweep_prints_each_roots_manifest_run",
            a_sweep_prints_each_roots_manifest_run,
        ),
        (
            "worker::the_allocator_probe_fails_without_counts",
            probe_control,
        ),
        ("worker::cases_run_on_one_thread", one_thread),
        (
            "worker::a_fresh_process_lists_the_catalog_admission_reads",
            capabilities,
        ),
        (
            "worker::a_fresh_process_lists_the_rule_catalog",
            rule_catalog,
        ),
        (
            "session::fresh_processes_commit_and_replay_one_session",
            sessions,
        ),
        (
            "worker::the_protocol_reports_failures_and_refusals",
            protocol,
        ),
        (
            "worker::a_cluster_summary_without_a_stop_event_prints_its_coverage_unavailable",
            coverage_needs_a_stop,
        ),
        ("worker::outcome_lines_flush_as_cases_return", streamed),
        (
            "worker::ignored_names_the_cases_with_an_ignore_attribute",
            ignored_cases,
        ),
        (
            "worker::a_failed_fresh_process_shows_no_refusal_of_a_changed_line",
            a_failed_run_is_no_refusal,
        ),
        (REPORT, report),
        ("entropy::two_fresh_processes_report_one_identity", across),
        (CUT_REPORT, cut_report),
        (
            "cut::two_fresh_processes_enumerate_one_cut_table",
            cut_tables_across,
        ),
        ("bundle::two_fresh_processes_record_one_bundle", two_bundles),
        (
            "bundle::an_old_bundle_decodes_its_action_codes",
            an_old_bundle_decodes_its_action_codes,
        ),
        (
            "replay::fresh_processes_replay_and_reduce_a_bundle",
            replayed_and_reduced,
        ),
        (
            "schedule::fresh_processes_reduce_a_schedule",
            crate::net::world_tests::schedule::tests::fresh_processes_reduce_a_schedule,
        ),
        ("narrate::a_fresh_process_narrates_into_its_file", narrated),
        (
            "fork::children_are_credited_only_on_framed_success_at_exit_zero",
            credited_only_on_framed_success,
        ),
        (
            "fork::inherited_descriptors_close_in_the_child",
            inherited_descriptors_close,
        ),
        (
            "fork::the_watchdog_classifies_a_hung_child",
            watchdog_classifies_a_hung_child,
        ),
        (
            "fork::a_fork_is_refused_off_its_boundary",
            refused_off_its_boundary,
        ),
        (
            "branch::forked_suffixes_keep_the_pending_put_prefix",
            forked_suffixes_keep_the_pending_put_prefix,
        ),
        (
            "branch::fresh_processes_branch_a_bundle_alike",
            fresh_processes_branch_alike,
        ),
        (
            "branch::fresh_processes_fork_at_turn_and_script_milestones",
            fresh_processes_fork_at_turns_and_steps,
        ),
        (
            "suffix::composed_bounded_tree_accounts_every_leaf_and_frontier",
            composed_bounded_tree_accounts_every_leaf_and_frontier,
        ),
        (
            "suffix::fresh_processes_explore_a_composed_bounded_tree_alike",
            fresh_processes_explore_alike,
        ),
        (
            "fuzz::the_campaign_driver_loads_seeds_and_executes_positively",
            the_campaign_driver_loads_seeds_and_executes_positively,
        ),
        (
            "fuzz::a_merge_enters_the_driver_in_its_inner_process",
            a_merge_enters_the_driver_in_its_inner_process,
        ),
        (
            "fuzz::a_wrong_byte_input_audits_tears_down_then_aborts",
            a_wrong_byte_input_audits_tears_down_then_aborts,
        ),
        (
            "fuzz::a_panicking_input_tears_down_before_the_driver_aborts",
            a_panicking_input_tears_down_before_the_driver_aborts,
        ),
        (
            "fuzz::the_appended_seeds_replay_alike_in_fresh_processes",
            the_appended_seeds_replay_alike_in_fresh_processes,
        ),
        (
            "fuzz::the_parser_targets_load_seeds_and_execute_positively",
            the_parser_targets_load_seeds_and_execute_positively,
        ),
        (
            "fuzz::a_parser_failure_replays_and_minimizes",
            a_parser_failure_replays_and_minimizes,
        ),
        (
            "histories::each_history_replays_in_a_fresh_process",
            histories_replayed,
        ),
        (
            "cluster::two_fresh_processes_record_and_replay_one_bundle",
            cluster_bundles_agree,
        ),
        (LONG_RUN, the_long_run_gate_passes),
        (SEEDS, every_seed_passes_on_one_engine_each),
        (GEOMETRIES, every_larger_geometry_passes_on_one_engine_each),
        (
            DEEPER,
            deeper_composed_bounded_trees_account_every_leaf_and_frontier,
        ),
        (CYCLES, seeded_warm_cycles_pass_on_seeds_1_to_16),
        (FLEET_REPORT, fleet_report),
        (
            "fleet::two_fresh_processes_report_one_digest_for_every_pinned_run",
            fleet_digests_across,
        ),
        (FLEET_ROOTS, fleet_runs_pass_on_roots_1_to_16),
        (
            PUBLISHING,
            seeded_restart_cycles_load_the_published_cut_plus_the_suffix,
        ),
        (
            ROLLING,
            seeded_roll_cycles_restart_at_e_plus_one_with_every_acknowledged_mutation,
        ),
        (
            SLOT_REUSE,
            slot_reuse_cycles_replace_a_host_every_cycle_on_seeds_1_to_16,
        ),
        (
            HANDOFF,
            seeded_handoff_cycles_hold_every_acknowledged_mutation_across_both_hosts,
        ),
        #[cfg(protocol_contract)]
        (contract::NAME, contract::every_form_parses),
    ];

    /// The case that runs the long-run gate manifest; ignored, so only an
    /// `--ignored` or `--include-ignored` selection runs it.
    const LONG_RUN: &str = "long_run::the_long_run_gate_passes";

    /// The cases that run the scaled churn run's seeds on the original
    /// geometry and on the larger geometries, and the one that explores the
    /// deeper composed bounded suffix trees; ignored, as [`LONG_RUN`] is.
    const SEEDS: &str = "scaled::every_seed_passes_on_one_engine_each";
    const GEOMETRIES: &str = "scaled::every_larger_geometry_passes_on_one_engine_each";
    const DEEPER: &str = "suffix::deeper_composed_bounded_trees_account_every_leaf_and_frontier";

    /// The case that runs the seeded warm takeover and restart cycles; ignored, as [`LONG_RUN`] is.
    const CYCLES: &str = "cycles::seeded_warm_cycles_pass_on_seeds_1_to_16";

    const FLEET_REPORT: &str = "fleet::pinned_runs_report_their_digests";

    /// The long-run lane selects `FLEET_ROOTS` with `--ignored` to exercise both fleet shapes on roots 1 through 16.
    const FLEET_ROOTS: &str = "fleet::fleet_runs_pass_on_roots_1_to_16";

    /// The case that runs the seeded restart cycles of a publishing owner through the host driver; ignored, as
    /// [`LONG_RUN`] is.
    const PUBLISHING: &str =
        "publishing::seeded_restart_cycles_load_the_published_cut_plus_the_suffix";

    /// The case that runs the seeded roll cycles through the host driver; ignored, as [`LONG_RUN`] is.
    const ROLLING: &str =
        "rolling::seeded_roll_cycles_restart_at_e_plus_one_with_every_acknowledged_mutation";

    /// The case that runs the slot-reuse cycles, a replacement in every cycle; ignored, as [`LONG_RUN`] is.
    const SLOT_REUSE: &str =
        "cycles::slot_reuse_cycles_replace_a_host_every_cycle_on_seeds_1_to_16";

    /// The case that runs the seeded planned-exit cycles of transfers and requested restarts between two hosts
    /// through the host driver; ignored, as [`LONG_RUN`] is.
    const HANDOFF: &str =
        "handoff::seeded_handoff_cycles_hold_every_acknowledged_mutation_across_both_hosts";

    /// The cases of [`CASES`] a run reports ignored unless `--ignored` or
    /// `--include-ignored` selects them, as libtest treats an ignore
    /// attribute. Each names, after its last `::`, a function of this
    /// file whose ignore attribute carries the registry's cause text; the
    /// run reads this list, and the attribute only states the cause.
    pub(super) const IGNORED: [&str; 10] = [
        LONG_RUN,
        SEEDS,
        GEOMETRIES,
        DEEPER,
        CYCLES,
        FLEET_ROOTS,
        PUBLISHING,
        ROLLING,
        SLOT_REUSE,
        HANDOFF,
    ];

    /// The case a fresh worker process runs to report its identity.
    const REPORT: &str = "entropy::fixed_inputs_report_the_pinned_identity";

    /// The case a fresh worker process runs to report its cut tables.
    const CUT_REPORT: &str = "cut::fixed_descriptors_report_the_pinned_cut_tables";

    /// The manifests the worker accepts by name, each running every case;
    /// with none named, the first.
    const MANIFESTS: [&str; 1] = ["u1"];

    const USAGE: &str = "Usage: sim_worker [OPTIONS] [FILTER]...

Runs the cases of one manifest on the process's one thread. A FILTER naming
a manifest (u1) selects it; any other FILTER keeps the cases it names.

   or: sim_worker --manifest MANIFEST --bundle BUNDLE
   or: sim_worker --inspect BUNDLE --manifest MANIFEST
   or: sim_worker --replay BUNDLE --output DIR
   or: sim_worker --reduce BUNDLE --output DIR
   or: sim_worker --reduce-schedule BUNDLE --output DIR [--max-records N] [--max-candidates N] [--max-passes N] [--max-runs N]
   or: sim_worker --capabilities
   or: sim_worker --rules
   or: sim_worker --session MANIFEST --output DIR
   or: sim_worker --replay-session SESSION --output DIR
   or: sim_worker --branch BUNDLE --milestone NAME --suffixes N [--siblings M] --output DIR
   or: sim_worker --explore BUNDLE --milestone NAME --output DIR
   or: sim_worker --fuzz TARGET --artifacts DIR [-- LIBFUZZER-ARGS...]
   or: sim_worker --seeds TARGET DIR
   or: sim_worker --sweep MANIFEST
   or: sim_worker --minimize TARGET INPUT --output FILE
   or: sim_worker --narrate BUNDLE --output FILE [--events] [--from N] [--to N] [--max-records N]
   or: sim_worker --narrate BUNDLE --output FILE --failure [--max-records N]

The second form runs the run manifest MANIFEST into the new bundle BUNDLE,
refusing a BUNDLE that exists, and prints its summary: exit 0 when the run
counts as a pass, 1 for any other complete result, 2 for a refused command
line, a missing or unparsable MANIFEST or a BUNDLE that exists, and 3 for
incomplete evidence, the host unable to read MANIFEST or create BUNDLE
and a run that panicked included, which keeps every record before the
panic in BUNDLE and prints `run: the run panicked at LOCATION: PAYLOAD`,
or complains of a BUNDLE write that failed, before or during its unwind,
and prints no such line. The third
refuses a MANIFEST that pins another executable or platform, loads BUNDLE
under MANIFEST's record maximum and prints its summary: exit 0 when it
loads and recorded MANIFEST, 2 when it is rejected, a missing BUNDLE or
MANIFEST included, 3 when the host cannot read either. Both forms report
a worker that cannot read its own executable as incomplete evidence.

A summary names the bundle's digest, decisions, terminal and whether it
counts, the observed turns, progress, virtual and skipped time, its format
(`summary: 1`), the profile and the turn limits its manifest declared
(`declared_turns`, `declared_same_time`, `declared_no_progress`), how the
run stopped (`stop: goal`, `limit turns`, `limit same_time`, `limit
no_progress`, `quiescent`, `defect KIND`, `halted` for a run whose hook
stopped recording, `unknown` for a code this worker does not name,
or `unavailable` for a bundle that records no stop event), the stopped
boundaries it checked (`boundaries_checked`), its executed operations,
witnesses and the faults its links delivered (`faults_delivered`; a device
fault its audit records reaches only the verdict, and a cluster device's
I/O error, torn write and partial read are counted in no summary field), and its owner and client counts. A field the bundle records no
value for prints `unavailable`, never zero: the decisions, turns,
progress, virtual and skipped time of a bundle that ends before its
terminal's checkpoint, the profile when the recorded one is no listed
name, every observed count when the bundle holds no stop event naming a
mixed or cluster world, a recovery run's, a cluster run's whose setup
draw was refused and one the record cap or a panic cut short included,
operations and witnesses for a scripted history, whose steps record no
action, and always `incarnations` and `retained_depth`. A cluster
profile's bundle adds its drawn `topology` (`owners`, `keys`, and `hot`,
the hot key's index below `keys`), its `coverage` (what its generated
operations reached: publications, exact reads, misses, GETs that ended
with neither an exact read nor a miss, invalidations, cancels and exact
reads by a client that has read from two owners; then reused slots,
probes' publications included, healed phases and delivered faults) and
the dimensions it leaves `unavailable`;
`topology` and `coverage` print `unavailable` unless the bundle holds both
its stop and coverage events. For counts: false, the summary prints
`cause`. It also prints `unsuccessful` when the first recorded unsuccessful
check contains a valid printable ASCII rule prefix, up to 41 bytes. For a complete violation with a
violation record and a recorded identity, `identity` prints the last
identity event's payload in lowercase hex. Reduction keeps that identity.
When the recovery ledger rebuilds, `windows:` follows `stages:`
and `limits:`. Each planned row counts passing cuts with a matching
measurement for that boundary and failure class. Zero marks a coverage
gap; optional boundaries and sites outside the profile's declared points
print `unplanned`. For an unrecorded or mismatched recovery record, the
rows describe this executable's cut table; coverage of the recorded table
is unknown.

--session runs the cluster manifest MANIFEST, which must pin this
executable and platform, into the new directory DIR as a session: the
frozen manifest, each committed window's chunk under DIR/windows, synced
before DIR/index names its digest and chained digest, the records after
the last window in DIR/windows/tail.chunk and DIR/end. The chain starts
from the SHA-256 digest of DIR/manifest. Verification recomputes the chain
from that digest and compares it with the recorded chain. The writer holds
only the open window's records in memory and charges every session file
to the manifest's `bytes`; its `records` counts one record per begin,
clock, turn and end callback of the run. It prints the window count and
chain and the end line, and exits 0 when the run counts, 1 for another
complete run, 2 for a missing, non-UTF-8 or refused manifest or a DIR
that exists and 3 when the host cannot read MANIFEST or create DIR, the
run is incomplete or a write failed, a record or byte budget of the
manifest was spent, the run panicked or the worker cannot read its own
executable; a session that stops before its end prints the reason and
the end line it did not commit on stderr. The end line names how the run
stopped (`stop`, the summary's stop name), its `terminal` (`complete
OUTCOME fired=HEX required=HEX` or `infrastructure CLASS`, the words a
summary prints) and whether it `counts`, its `turns`, its time in
microseconds (`virtual_us` the clock at the end, which includes the
world's start offset, `skipped_us` the clock's whole advance and
`rested_us` the idle part of that advance between phases, so phase time
is skipped_us less rested_us), `apply_ms`, the time spent applying turns
as twelve digits so the line's length is the same on every run, the
first failure (`failure`: `None` when no check failed, else `Some` and
the failure's debug text, which may hold spaces and quotes), the most
uploads the checker carried (`carried`), the most registry entries one
partition held (`registry`), the most outstanding GETs at a window cut
(`outstanding`), the most records one link audit held (`kept`) and the
largest window buffer (`window_bytes`). DIR/end then adds the window
count, the last chained digest and the tail chunk's SHA-256 (`windows`,
`chain`, `tail`); the copies printed on stdout and stderr end at
`window_bytes`. A run that panicked ends with `end: panicked` and the
panic's text before those last three fields.
--replay-session checks SESSION's windows, end and tail, reruns it from
its origin into DIR and compares every committed window: exit 0 when
every window and the end line, all but its apply_ms, the tail chunk's
digest included, reproduce; 1 naming the first window and record that
diverged, with a turn's virtual time and candidate in hex, or that the
window count or the end differs; 2 when SESSION or its manifest is
missing, has a truncated, changed or out-of-chain window, a missing or
torn end or tail, an index line or an end line other than a panicked
run's naming a field twice, an index line its chunk does not yield, or
a manifest that is not UTF-8 or pins another build, or DIR exists; 3,
before any window is compared, when the host cannot read SESSION's
manifest, DIR cannot be written, a record or byte budget is spent, the
rerun panics or the worker cannot read its own executable, and 3 when
the replay's windows cannot be read back.

--capabilities prints the capability listing: its format, the summary
format, the manifest version, each key's form and range, the two recorder
constraints, the order of the held bounds, each profile admission accepts
with its class, its least admitted bounds and
`support=implemented campaign=unqualified`, each history's expected
ending and, for a history of two owners, its `owners=N clients=M`, one
`fails: NAME violation CODE RULE` or `fails: NAME unsuccessful WITNESS`
line for each history that expects no pass, where CODE is the obligation's
code in a failure identity, the
`settled-` words and their rules, the branch milestones and milestone
families, the suffix and sibling bounds, the topology of every other mixed
profile and each cluster profile's ranges, dimensions and minima, and
exits 0; beside any other argument, --help included, it is refused with
exit 2.

--rules prints the rule catalog: its format, then one `rule: SCOPE TEXT`
line for each violation rule a check can raise, where SCOPE names the
check: boundary for the stopped-boundary observer, world for the
single-owner world, cluster for the cluster checker, history for a
scripted history and oracle for the oracle over recorded rows. It exits
0; followed by any other argument it is refused with exit 2.

The replay forms read BUNDLE once, refuse a bundle whose recorded manifest
pins another executable or platform, and write into the new directory DIR.
--replay reruns BUNDLE from its tape into DIR/replay.bundle and prints
what the replay claims, its terminal and the obligation a violation names
or the class of a failing audit record: exit 0 when it reproduced, 1 when
it diverged or its run panicked, which writes the bundle recorded so far
to DIR/replay.bundle and prints `replay: the run panicked at
LOCATION: PAYLOAD`, 2 when the tape ends before or inside a decision the run
draws or the input is refused, 3 when the host cannot read BUNDLE or write
DIR/replay.bundle. --reduce minimizes the failing mixed-world BUNDLE,
replaying it and every kept step in a fresh process whose environment
holds only this one's LD_LIBRARY_PATH, into DIR/original.bundle,
regression.manifest, regression.bundle, scenario.txt, steps.txt and
conditions.txt, beside DIR/step-N.bundle for the Nth bundle it verifies,
the original first, and the directory DIR/step-N.replay that check's
replay writes its replay.bundle into, or for a panic DIR/step-N.manifest
and DIR/step-N.rerun.bundle. It keeps a step only when it fails as
BUNDLE does: with BUNDLE's failure identity and, for a planted
violation, its plant's premise, for an unplanted violation, every
enabling condition its rule names, or, for a BUNDLE a panic cut short,
rerunning in a fresh process to the same panic location and payload,
which the summary line names. conditions.txt lists those enabling
conditions, one per line, and is empty for a planted violation or a
panic. A reduction tries at most 512 steps; one that stops there still
writes the best regression kept so far, steps.txt ends with `stopped at
the step bound`, and its summary line names `, bounded` after the
scenario, before a panic's location and payload. Exit 0 when it reduced,
1 when BUNDLE names another world than the mixed one, is no planted
violation, cataloged unplanted violation or panicked run a fresh process
reproduces, records a violation with no failure identity, or when its
plant's premise or its rule's enabling conditions do not hold on BUNDLE,
2 when it is refused, an existing DIR included, 3 when the host cannot
create DIR or a file in it, or a fresh-process check fails. A check that
fails after the original replayed keeps the best regression so far and
goes on to write each file, steps.txt ending with the unverified step
and the reason, before exit 3; a file the host cannot write stops the
writing there and exits 3.

--reduce-schedule reads the regular file BUNDLE, at most --max-records records
(1000000) and its recorded manifest's maximum, and shrinks the decisions of
its mixed-world violation, the scenario fixed, as a fed run of its tape's
values zero-padded to at least 65536 bytes: passes zero a suffix, delete one
decision and lower one index or bounded-value decision to zero, then the
turn limit is cut. A candidate is kept when it keeps BUNDLE's failure
identity and enabling requirement, is smaller and replays in a fresh
process, as --reduce's steps do, within --max-candidates (512), --max-passes
(8) and --max-runs (1026) runs and checks, each a positive decimal. The
requirement is the plant's premise, the cataloged rule's enabling
conditions, or a history predicate bound to BUNDLE's profile and failure;
conditions.txt names it. It writes --reduce's files; steps.txt names the
original's counts, the budget and the requirement, each candidate's
verdict, what was spent, the regression's counts and `stopped: exhausted`,
`bounded` or `interrupted` with the reason. It prints `reduce-schedule:
reduced to R records, D decisions, T of L turns, I input bytes, K kept,
STOP`, STOP `exhausted` or `bounded`; with none kept the regression is
BUNDLE. Exit codes are --reduce's; 1 also for a panicked run, a failure
with no checkable requirement or a tape whose values do not record its run
again.

--branch replays BUNDLE strictly to the first stopped boundary where
milestone NAME holds. NAME is a fixed milestone --capabilities lists or
an instance of a family it lists: turn-N holds once at least N turns
have completed, so turn-0 holds at the initial boundary; script-N holds
once the scripted history's step N, counted from zero, returned an
outcome other than STAY, which a step returns when it waits and runs
again. Only a mixed run counts scripted steps, so script-N never holds
for a cluster or recovery bundle. A milestone's N is an unsigned decimal
with no sign, space or leading zero, at most 18446744073709551615 for
turn-N and 4294967295 for script-N. Stopped boundaries follow the start
and each clock advance, so a turn or step completing between them
reaches the milestone at the next one, and a run that ends first never
reaches it. The branch then forks M identical siblings, from 1 to 4 and
1 when not given, for each of the --suffixes N suffixes, from 1 to 16;
each writes DIR/suffix-K-S.bundle, and siblings of one suffix whose
decisions, digest or terminal disagree are a failed check. It prints the
milestone, the `witness:` line naming the facts at the boundary where it
forked with `holds=true` when the milestone's predicate holds over them,
whether the parent's replay still reproduced BUNDLE, each child's class
and result and every failed check: exit 0 when every child is credited
from a success frame at exit 0, passes its checks, ran to a terminal
that counts as a pass, and the parent reproduced; 1 otherwise, a prefix
replay that diverges before the milestone included, which prints only
`parent: diverged before the milestone`; 2 when BUNDLE, NAME, N, M or
DIR is refused or the run never reaches the milestone, removing the DIR
it created when that DIR is still empty; 3 when the host cannot fork,
read BUNDLE or create DIR, or a child's suffix left no evidence: its
pipe or reap was lost, it could not set up its report, list its
descriptors or write its bundle, something outside the branch killed it
with SIGKILL, the parent could not read or load that bundle, or its run
ended in an infrastructure class. The recorded manifest's watchdog
seconds bound every child from its fork.

--explore replays BUNDLE strictly to milestone NAME, as --branch reaches
it, and explores the composed bounded suffix tree the recorded
manifest's suffix_depth, suffix_children, suffix_faults and
suffix_advances fix: each node forks one child per runnable candidate,
up to suffix_children, at its first choice of more than one; each leaf
writes DIR/leaf-PATH.bundle. It prints the composed-bounded label, the
milestone and its `witness:` line, the limits, whether the root still
reproduced BUNDLE, every node's class and cost, every leaf's verdict,
the frontier census and every failed check: exit 0 when every node is
credited, every check passes and every leaf passes, 1 otherwise, 2 and 3
as for --branch. The recorded watchdog bounds the tree from the root's
first fork.

--fuzz enters libFuzzer once for fuzz target TARGET (see Targets) with the
arguments after --. The worker counts inputs after the target returns or
unwinds. On a classified failure it attempts to create the input, optional
bundle and claim files in DIR. It reports teardown and retention, prints
counts and aborts. The registered exit handler also prints counts, in
every process but a merge's outer one, which runs no input. A timeout
or RSS-limit stop bypasses that handler and can interrupt an input before
classification. In fuzzing mode, failure artifact names include
-artifact_prefix, the failure kind (timeout-, oom-, crash- or leak-) and the
input hash. A nonempty -exact_artifact_path overrides the generated name.
Individual-file mode disables libFuzzer's artifact writer. The worker exits
2 for invalid worker arguments and for libFuzzer's restart options supplied
as -flag=value (-fork, -jobs, -workers, -set_cover_merge,
-minimize_crash, -cleanse_crash). When libFuzzer merges, which takes a
nonzero -merge and two or more directories, it starts each inner merge
process through a shell as this worker's own --fuzz form for TARGET and DIR.
The worker therefore checks every run with a -merge= argument, -merge=0
included. Such a run exits 2 for a -merge= value other than 0 or 1. It
exits 2 unless the last -merge_control_file=FILE
argument names a nonempty FILE that does not exist when the worker starts,
and exits 2 when FILE cannot be looked up, for an -ignore_remaining_args=
argument, for an executable path that is unknown or not UTF-8, when that
path, TARGET, DIR or a libFuzzer argument is empty or holds a byte outside
A-Za-z0-9/._=,-, and when a directory argument holds, as the worker
starts, an entry whose name contains a line break. A merge can exit 0 when
every inner process failed or none started: the line MERGE-OUTER:
successful in N attempt(s) reports one inner process that exited 0, and an
inner process that classifies a failure attempts to retain it in DIR and
aborts, so read DIR and the output directory for a merge's result. --seeds
writes
TARGET's seed inputs into the existing directory DIR, stopping at the
first that exists: exit 0, or 2 when refused. --minimize removes byte runs
from the failing INPUT while it fails with the same claim, judging a
bounded number of removals, and writes the result to the new FILE: exit 0
when it minimized, 1 when INPUT does not fail, 2 when refused.

--sweep runs the run manifest MANIFEST once for each root it reads from
standard input, one root per line as a manifest writes it, with MANIFEST's
root replaced by it and the run's bundle kept in memory. It prints
`sweep: ready` once it has accepted MANIFEST, before it reads a root. For
each root it prints `root: ROOT`, `code: CODE`, the lines the second form
prints for that manifest, and `end: ROOT`, where CODE is the second form's
exit code: a run that panicked prints its `run:` line, a manifest the run
refuses prints `refused: REASON` under code 2, and a bundle that does not
load prints `load: REASON` under code 3. It exits 0 at the end of its
input, 2 for a refused command line, a MANIFEST it cannot parse or that
pins another executable or platform, or a root a manifest cannot hold, 3
when the host cannot read MANIFEST, its input or its own executable, and
101 when it cannot write a line.

--narrate reads the regular file BUNDLE, at most --max-records records
(1000000 when not given) and its recorded manifest's maximum, validates it
whole as a load does, and writes its narrative to the new FILE: a header
naming its digest, record counts, completeness, the pins it recorded beside
this worker's own and where the names come from, then its records in
stream order, turns numbered from 0. The narrative holds the turns from
--from up to but not including --to, by default every turn, and every
violation and the terminal; --events adds the clocks and events among those
turns, the last clock before --from unless one at --from opens them, and
every failure, observed failure, entropy, identity, stop and coverage event,
marking each record outside the turns as context. --failure instead writes
the whole bundle's failure: its violation, the turn, clock boundary, setup
or settlement its identity's site shows raised it, else unknown, its identity and its full rule when this worker's
catalog holds the text the identity hashes, an audit failure's code, or an
unsuccessful run's recorded or derived cause, each derived value labelled and
each unrecorded one unknown; it takes no --events, --from or --to. A mixed
or cluster turn that collected a GET or PUT result names it; a recovery
turn, and every turn of a build that records no request results, names none. It prints one line naming FILE:
exit 0 when a complete bundle rendered, a recorded violation or
unsuccessful run included, 2 for a refused command line, a missing or
irregular BUNDLE, one past a record bound, that does not load or records
no manifest that parses, a window outside 0 <= from <= to <= turns, or a
FILE that exists, and 3 when the bundle is incomplete evidence, the worker
cannot read its own executable, or the host cannot read BUNDLE, write
FILE or print the line, naming the partial FILE it leaves.

Targets: campaign, record and wire fuzz the real paths; planted fails its
wrong-byte scenario, panicking fails every input, and record-control fails
each key change made without a reseal.

Options:
        --list              List the selected cases
        --ignored           Select and run the ignored cases only
        --include-ignored   Run the ignored cases beside the others
        --exact             Match filters and skips as whole names
        --skip NAME         Drop the cases NAME matches
        --test-threads 1    The only count the worker runs; 01 and +1 spell it too
        --nocapture, --no-capture, --show-output
                            Accepted; the worker captures no output
        --format pretty     The only format the worker prints
        --color WHEN        Accepted; the worker prints no color
        --test              Runs the cases; every case is a test
        --bench             Reports every selected case ignored, as libtest does,
                            unless --test is also given
    -h, --help              Print this message

Libtest's -q, --quiet and --logfile are refused: the worker prints the
pretty format to stdout only. Its nightly-only flags are refused as unknown.
";

    /// The flags that take a value and select a bundle form.
    const BUNDLE_FLAGS: [&str; 13] = [
        "--manifest",
        "--bundle",
        "--inspect",
        "--replay",
        "--reduce",
        "--output",
        "--branch",
        "--milestone",
        "--suffixes",
        "--siblings",
        "--explore",
        "--session",
        "--replay-session",
    ];

    /// The command line as the worker reads it.
    #[derive(Default)]
    struct Command {
        help: bool,
        list: bool,
        ignored: bool,
        include_ignored: bool,
        bench: bool,
        test: bool,
        exact: bool,
        /// A positional named the manifest.
        manifest: bool,
        filters: Vec<String>,
        skips: Vec<String>,
        /// A run manifest file.
        run: Option<String>,
        bundle: Option<String>,
        inspect: Option<String>,
        replay: Option<String>,
        reduce: Option<String>,
        output: Option<String>,
        branch: Option<String>,
        milestone: Option<String>,
        suffixes: Option<String>,
        siblings: Option<String>,
        capabilities: bool,
        explore: Option<String>,
        /// A session's run manifest.
        session: Option<String>,
        replay_session: Option<String>,
    }

    /// `spelling` is the flag as given, for the refusal.
    fn thread_count(spelling: &str, count: &str) -> Result<(), String> {
        match count.parse::<usize>() {
            Ok(1) => Ok(()),
            _ => Err(format!("{spelling}: the worker runs on one thread")),
        }
    }

    /// The first positional naming a manifest selects it; any other
    /// positional, a repeated manifest name included, filters cases by name,
    /// and each `--skip` drops cases by name, both exactly under `--exact`.
    fn parse(args: &[String]) -> Result<Command, String> {
        let mut command = Command::default();
        let mut args = args.iter().map(String::as_str);
        while let Some(arg) = args.next() {
            match arg {
                "--help" | "-h" => command.help = true,
                "--capabilities" => command.capabilities = true,
                "--list" => command.list = true,
                "--ignored" => command.ignored = true,
                "--exact" => command.exact = true,
                "--skip" => match args.next() {
                    Some(name) => command.skips.push(name.to_owned()),
                    None => return Err("--skip needs a value".into()),
                },
                flag if flag.starts_with("--skip=") => {
                    command.skips.push(flag["--skip=".len()..].to_owned());
                }
                "--include-ignored" => command.include_ignored = true,
                "--nocapture" | "--no-capture" | "--show-output" | "--format=pretty" => {}
                "--test" => command.test = true,
                flag if BUNDLE_FLAGS.contains(&flag) => {
                    let Some(value) = args.next() else {
                        return Err(format!("{flag} needs a value"));
                    };
                    let slot = match flag {
                        "--manifest" => &mut command.run,
                        "--bundle" => &mut command.bundle,
                        "--inspect" => &mut command.inspect,
                        "--replay" => &mut command.replay,
                        "--reduce" => &mut command.reduce,
                        "--branch" => &mut command.branch,
                        "--milestone" => &mut command.milestone,
                        "--suffixes" => &mut command.suffixes,
                        "--siblings" => &mut command.siblings,
                        "--explore" => &mut command.explore,
                        "--session" => &mut command.session,
                        "--replay-session" => &mut command.replay_session,
                        _ => &mut command.output,
                    };
                    if slot.replace(value.to_owned()).is_some() {
                        return Err(format!("{flag} given twice"));
                    }
                }
                "--bench" => command.bench = true,
                "-q" | "--quiet" => {
                    return Err(format!("{arg}: the worker prints the pretty format"));
                }
                "--logfile" => match args.next() {
                    Some(path) => {
                        return Err(format!("--logfile {path}: the worker writes no logfile"));
                    }
                    None => return Err("--logfile needs a value".into()),
                },
                "--format" => match args.next() {
                    Some("pretty") => {}
                    Some(format) => {
                        return Err(format!(
                            "--format {format}: the worker prints the pretty format"
                        ));
                    }
                    None => return Err("--format needs a value".into()),
                },
                "--color" => match args.next() {
                    Some(_) => {}
                    None => return Err("--color needs a value".into()),
                },
                flag if flag.starts_with("--color=") => {}
                "--test-threads" => match args.next() {
                    Some(count) => thread_count(&format!("--test-threads {count}"), count)?,
                    None => return Err("--test-threads needs a value".into()),
                },
                flag if flag.starts_with("--test-threads=") => {
                    thread_count(flag, &flag["--test-threads=".len()..])?;
                }
                flag if flag.starts_with('-') => return Err(format!("unknown flag {flag}")),
                name if !command.manifest && MANIFESTS.contains(&name) => command.manifest = true,
                name => command.filters.push(name.to_owned()),
            }
        }
        if command.ignored && command.include_ignored {
            return Err(
                "the options --include-ignored and --ignored are mutually exclusive".into(),
            );
        }
        Ok(command)
    }

    /// Runs the command in `args` over `cases`, of which those `ignored`
    /// names run only under `--ignored` or `--include-ignored`, writing
    /// libtest's lines to `out` and a refused command line to `err`, and
    /// returns the exit code:
    /// 0, or 101 when a case failed, the command line was refused or writing
    /// the output failed. A refused command line naming a bundle form's flag
    /// or `--capabilities`, or one `--rules` begins, exits [`REFUSED`]. Cargo
    /// passes one command line
    /// to every test target of the package, so a run that selects no case
    /// exits 0, as libtest's does.
    pub(super) fn run(
        args: &[String],
        cases: &[Case],
        ignored: &[&str],
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> i32 {
        crate::sim::unwind::install();
        match args.first().map(String::as_str) {
            Some("--fuzz") => return fuzz_into(&args[1..], err),
            Some("--seeds") => return seeds_into(&args[1..], err),
            Some("--sweep") => {
                return sweep_into(&args[1..], &mut std::io::stdin().lock(), out, err);
            }
            Some("--minimize") => return minimize_into(&args[1..], out, err),
            Some("--reduce-schedule") => return reduce_schedule_into(&args[1..], out, err),
            Some("--rules") => {
                if args.len() != 1 {
                    return refused(err, "--rules takes no other argument");
                }
                let catalog = crate::net::world_tests::narrate::rules::listing();
                return finish(out, &catalog, COUNTS);
            }
            Some("--narrate") => {
                let decoder = || (own_digest(), platform());
                return crate::net::world_tests::narrate::run(&args[1..], decoder, out, err);
            }
            _ => {}
        }
        let command = match parse(args) {
            Ok(command) => command,
            Err(error) => {
                let code = if args
                    .iter()
                    .any(|arg| BUNDLE_FLAGS.contains(&arg.as_str()) || arg == "--capabilities")
                {
                    REFUSED
                } else {
                    101
                };
                return finish(err, &format!("error: {error}\n"), code);
            }
        };
        if command.capabilities {
            if args.len() != 1 {
                return refused(err, "--capabilities takes no other argument");
            }
            return finish(out, &crate::net::world_tests::catalog::listing(), COUNTS);
        }
        if command.help {
            return finish(out, USAGE, 0);
        }
        if command.session.is_some() || command.replay_session.is_some() {
            return session_into(&command, out, err);
        }
        if command.explore.is_some() {
            return explore_into(&command, out, err);
        }
        if command.branch.is_some()
            || command.milestone.is_some()
            || command.suffixes.is_some()
            || command.siblings.is_some()
        {
            return branch_into(&command, out, err);
        }
        if command.replay.is_some() || command.reduce.is_some() || command.output.is_some() {
            return rerun(&command, out, err);
        }
        if command.run.is_some() || command.bundle.is_some() || command.inspect.is_some() {
            return bundles(&command, out, err);
        }
        let matches = |name: &str, pattern: &String| {
            if command.exact {
                name == pattern
            } else {
                name.contains(pattern.as_str())
            }
        };
        let selected = |name: &str| {
            (command.filters.is_empty()
                || command.filters.iter().any(|filter| matches(name, filter)))
                && !command.skips.iter().any(|skip| matches(name, skip))
        };
        // `--ignored` keeps only the ignored cases; a plain run lists and
        // reports them without running them.
        let is_ignored = |name: &str| ignored.contains(&name);
        let chosen: Vec<&Case> = cases
            .iter()
            .filter(|(name, _)| (!command.ignored || is_ignored(name)) && selected(name))
            .collect();
        let runs = |name: &str| command.ignored || command.include_ignored || !is_ignored(name);
        let filtered = cases.len() - chosen.len();
        let mut lines = String::new();
        if command.list {
            for (name, _) in &chosen {
                lines.push_str(&format!("{name}: test\n"));
            }
            if !chosen.is_empty() {
                lines.push('\n');
            }
            lines.push_str(&format!("{}, 0 benchmarks\n", tests(chosen.len())));
            return finish(out, &lines, 0);
        }
        lines.push_str(&format!("\nrunning {}\n", tests(chosen.len())));
        if command.bench && !command.test {
            for (name, _) in &chosen {
                lines.push_str(&format!("test {name} ... ignored\n"));
            }
            lines.push_str(&format!(
                "\ntest result: ok. 0 passed; 0 failed; {} ignored; 0 measured; {filtered} filtered out; finished in 0.00s\n\n",
                chosen.len()
            ));
            return finish(out, &lines, 0);
        }
        if finish(out, &lines, 0) != 0 {
            return 101;
        }
        lines.clear();
        let mut failures = Vec::new();
        let mut skipped = 0;
        for (name, case) in &chosen {
            if !runs(name) {
                skipped += 1;
                if finish(out, &format!("test {name} ... ignored\n"), 0) != 0 {
                    return 101;
                }
                continue;
            }
            let outcome = std::panic::catch_unwind(case).unwrap_or_else(|_| Err("panicked".into()));
            let verdict = if outcome.is_ok() { "ok" } else { "FAILED" };
            if finish(out, &format!("test {name} ... {verdict}\n"), 0) != 0 {
                return 101;
            }
            if let Err(reason) = outcome {
                failures.push((name, reason));
            }
        }
        if !failures.is_empty() {
            lines.push_str("\nfailures:\n\n");
            for (name, reason) in &failures {
                lines.push_str(&format!("---- {name} stdout ----\n{reason}\n\n"));
            }
            lines.push_str("failures:\n");
            for (name, _) in &failures {
                lines.push_str(&format!("    {name}\n"));
            }
        }
        let passed = chosen.len() - failures.len() - skipped;
        let result = if failures.is_empty() { "ok" } else { "FAILED" };
        lines.push_str(&format!(
            "\ntest result: {result}. {passed} passed; {} failed; {skipped} ignored; 0 measured; {filtered} filtered out; finished in 0.00s\n\n",
            failures.len()
        ));
        finish(out, &lines, if failures.is_empty() { 0 } else { 101 })
    }

    /// Exit codes of the bundle forms.
    const COUNTS: i32 = 0;
    const COMPLETE: i32 = 1;
    const REFUSED: i32 = 2;
    const INCOMPLETE: i32 = 3;

    /// Writes `reason` as the refusal of a bundle form and returns its
    /// exit code.
    fn refused(err: &mut impl Write, reason: &str) -> i32 {
        complain(err, reason);
        REFUSED
    }

    /// Writes `reason` as a bundle form's error.
    fn complain(err: &mut impl Write, reason: &str) {
        let _ = writeln!(err, "error: {reason}");
        let _ = err.flush();
    }

    /// Runs or inspects a bundle as `command` names. A missing or non-UTF-8
    /// manifest is refused; any other failure to read it is the host's.
    fn bundles(command: &Command, out: &mut impl Write, err: &mut impl Write) -> i32 {
        let Some(path) = &command.run else {
            return refused(err, "--manifest is required");
        };
        let text = match read_manifest(path.as_ref(), &format!("manifest {path}"), err) {
            Ok(text) => text,
            Err(code) => return code,
        };
        let manifest = match Manifest::parse(&text) {
            Ok(manifest) => manifest,
            Err(error) => return refused(err, &format!("manifest {path}: {error:?}")),
        };
        match (&command.bundle, &command.inspect) {
            (Some(bundle), None) => record(&manifest, bundle, out, err),
            (None, Some(bundle)) => inspect(&manifest, bundle, out, err),
            _ => refused(err, "give exactly one of --bundle and --inspect"),
        }
    }

    fn read_manifest(
        path: &std::path::Path,
        what: &str,
        err: &mut impl Write,
    ) -> Result<String, i32> {
        std::fs::read_to_string(path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidData => {
                refused(err, &format!("{what}: {error}"))
            }
            _ => host(err, &error, what.to_owned()),
        })
    }

    /// Runs or replays a session as `command` names, into the new output
    /// directory it names. A session's manifest must pin this executable
    /// and platform and name a cluster profile; a replayed session must
    /// hold every committed window, its end and its tail intact.
    fn session_into(command: &Command, out: &mut impl Write, err: &mut impl Write) -> i32 {
        use crate::net::world_tests::session;
        let Some(dir) = &command.output else {
            return refused(err, "--output is required");
        };
        if command.run.is_some()
            || command.bundle.is_some()
            || command.inspect.is_some()
            || command.replay.is_some()
            || command.reduce.is_some()
            || command.branch.is_some()
            || command.milestone.is_some()
            || command.suffixes.is_some()
            || command.siblings.is_some()
            || command.explore.is_some()
        {
            return refused(err, "the session forms take no other bundle form");
        }
        let (manifest_text, original) = match (&command.session, &command.replay_session) {
            (Some(path), None) => {
                match read_manifest(path.as_ref(), &format!("manifest {path}"), err) {
                    Ok(text) => (text, None),
                    Err(code) => return code,
                }
            }
            (None, Some(source)) => {
                let source = std::path::PathBuf::from(source);
                let what = format!("session {}", source.display());
                let text = match read_manifest(&source.join("manifest"), &what, err) {
                    Ok(text) => text,
                    Err(code) => return code,
                };
                // The original's windows, end and tail check before any
                // output exists or the run starts.
                let checked = session::committed(&source).and_then(|(lines, chain)| {
                    let end = session::ended(&source, lines.len(), &chain)?;
                    Ok((lines, end))
                });
                match checked {
                    Ok((lines, end)) => (text, Some((source, lines, end))),
                    Err(reason) => return refused(err, &reason),
                }
            }
            _ => return refused(err, "give exactly one of --session and --replay-session"),
        };
        let manifest = match Manifest::parse(&manifest_text) {
            Ok(manifest) => manifest,
            Err(error) => return refused(err, &format!("manifest: {error:?}")),
        };
        if let Err(code) = pinned_here(&manifest, "manifest", err) {
            return code;
        }
        let admitted = match admit(&manifest) {
            Ok(admitted) => admitted,
            Err(refusal) => return refused(err, &format!("{refusal:?}")),
        };
        if admitted.cluster().is_none() {
            return refused(err, &format!("{} is no cluster profile", manifest.profile));
        }
        let dir = std::path::Path::new(dir);
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return refused(err, &format!("output {}: {error}", dir.display()));
            }
            Err(error) => return host(err, &error, format!("output {}", dir.display())),
        }
        let budget = session::Budget {
            records: manifest.count("records"),
            bytes: manifest.count("bytes"),
        };
        let mut writer = match session::Writer::new(dir, &manifest.text(), budget) {
            Ok(writer) => writer,
            Err(error) => return host(err, &error, format!("session {}", dir.display())),
        };
        let ran = match crate::sim::unwind::caught(|| {
            crate::net::world_tests::cluster::session(&admitted, &mut writer)
        }) {
            Ok(ran) => ran.expect("an admitted cluster profile"),
            Err(panic) => {
                let end = session_panic_end(&panic);
                writer.finish(&end);
                let lost = writer
                    .failed()
                    .map(|reason| format!("; {reason}; the uncommitted end: {end}"))
                    .unwrap_or_default();
                complain(
                    err,
                    &format!("session {} panicked: {panic}{lost}", dir.display()),
                );
                return INCOMPLETE;
            }
        };
        let terminal = ran.judged();
        let counts = terminal.counts();
        let end = format!(
            "end: stop={} terminal={} counts={counts} turns={} virtual_us={} skipped_us={} rested_us={} apply_ms={:012} failure={:?} carried={} registry={} outstanding={} kept={} window_bytes={}",
            ran.stop(),
            terminal_text(terminal),
            ran.report.turn_count,
            ran.report.virtual_us,
            ran.report.skipped_us,
            ran.rested_us,
            ran.report.wall.as_millis(),
            ran.failure,
            ran.marks.carried,
            ran.marks.registry,
            ran.marks.outstanding,
            ran.marks.kept,
            writer.high_water,
        );
        writer.finish(&end);
        if let Some(reason) = writer.failed() {
            complain(err, &format!("{reason}; the uncommitted end: {end}"));
            return INCOMPLETE;
        }
        let Some((source, windows, original_end)) = original else {
            let lines = format!(
                "session: {} windows, chain {}\n{end}\n",
                writer.committed(),
                hex(&writer.chain())
            );
            let code = if counts {
                COUNTS
            } else if matches!(terminal, Terminal::Complete { .. }) {
                COMPLETE
            } else {
                INCOMPLETE
            };
            return finish(out, &lines, code);
        };
        let replayed = session::committed(dir).and_then(|(lines, chain)| {
            let end = session::ended(dir, lines.len(), &chain)?;
            Ok((lines, end))
        });
        let (replayed, replayed_end) = match replayed {
            Ok(replayed) => replayed,
            Err(reason) => {
                complain(err, &reason);
                return INCOMPLETE;
            }
        };
        match replay_verdict(
            (&source, &windows, &original_end),
            (dir, &replayed, &replayed_end),
        ) {
            SessionReplay::Diverged(line) => finish(out, &format!("{line}\n"), DIVERGED),
            SessionReplay::Reproduced => finish(
                out,
                &format!(
                    "replay: reproduced, {} windows, chain {}\n",
                    replayed.len(),
                    hex(&writer.chain())
                ),
                REPRODUCED,
            ),
            SessionReplay::Refused(reason) => refused(err, &reason),
            SessionReplay::Unread(reason) => {
                complain(err, &reason);
                INCOMPLETE
            }
        }
    }

    fn session_panic_end(panic: &str) -> String {
        format!("end: panicked {panic}")
    }

    /// How a replayed session compares with its original.
    enum SessionReplay {
        /// The line naming the first divergence.
        Diverged(String),
        /// Every window and the end, all but its `apply_ms`, reproduced.
        Reproduced,
        /// The original's chunk is unreadable or changed, or its index
        /// names a line its own chunk does not produce.
        Refused(String),
        /// The replay's own chunk could not be read back.
        Unread(String),
    }

    /// Compares an original session's committed windows and end with a
    /// replay's.
    fn replay_verdict(
        (source, windows, original_end): (&std::path::Path, &[String], &str),
        (dir, replayed, replayed_end): (&std::path::Path, &[String], &str),
    ) -> SessionReplay {
        use crate::net::world_tests::session;
        let Some(at) = windows
            .iter()
            .zip(replayed)
            .position(|(ours, theirs)| ours != theirs)
        else {
            if windows.len() != replayed.len() {
                return SessionReplay::Diverged(format!(
                    "replay: diverged at window {}: {} windows were committed, {} replayed",
                    windows.len().min(replayed.len()),
                    windows.len(),
                    replayed.len()
                ));
            }
            // Everything but the apply time must agree, the tail chunk's
            // digest included.
            let fields = |line: &str| {
                line.split(' ')
                    .filter(|field| !field.starts_with("apply_ms="))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            };
            if fields(original_end) != fields(replayed_end) {
                return SessionReplay::Diverged(
                    "replay: diverged after the last window: the end differs".to_owned(),
                );
            }
            return SessionReplay::Reproduced;
        };
        let ours = match session::chunk(source, at, &windows[at]) {
            Ok(ours) => ours,
            Err(reason) => return SessionReplay::Refused(reason),
        };
        let theirs = match session::chunk(dir, at, &replayed[at]) {
            Ok(theirs) => theirs,
            Err(reason) => return SessionReplay::Unread(reason),
        };
        SessionReplay::Diverged(match session::divergence(&ours, &theirs) {
            Some(found) => match found.turn {
                Some((now, candidate)) => format!(
                    "replay: diverged at window {at} record {}: a turn at virtual_us={now} candidate={}",
                    found.record,
                    hex(&candidate)
                ),
                None => format!(
                    "replay: diverged at window {at} record {} of tag {}",
                    found.record, found.tag
                ),
            },
            // One chunk yields one index line, so the original's line
            // changed after its chunk was written.
            None => {
                return SessionReplay::Refused(format!(
                    "window {at}'s index line differs from the one its chunk yields"
                ));
            }
        })
    }

    /// Exit codes of the replay forms beside the bundle forms': a replay
    /// that reproduced or a finished reduction, and a replay that diverged
    /// or a bundle no reduction applies to.
    const REPRODUCED: i32 = COUNTS;
    const DIVERGED: i32 = 1;

    /// Replays or reduces a bundle as `command` names, writing into the new
    /// output directory it names. The bundle is read once and never
    /// written; its recorded manifest must pin this executable and platform.
    /// A missing bundle and an existing output directory are refused; any
    /// other failure to read or create them, or to read the executable, is
    /// incomplete evidence.
    fn rerun(command: &Command, out: &mut impl Write, err: &mut impl Write) -> i32 {
        let (path, reducing) = match (&command.replay, &command.reduce) {
            (Some(path), None) => (path, false),
            (None, Some(path)) => (path, true),
            _ => return refused(err, "give exactly one of --replay and --reduce"),
        };
        let Some(dir) = &command.output else {
            return refused(err, "--output is required");
        };
        if command.run.is_some() || command.bundle.is_some() || command.inspect.is_some() {
            return refused(err, "the replay forms take no manifest or bundle path");
        }
        let (bytes, _, dir) = match staged(path, dir, err) {
            Ok(staged) => staged,
            Err(code) => return code,
        };
        let dir = dir.as_path();
        if reducing {
            let reduced = |verify: &mut Verify<'_>| reduce(&bytes, verify).map(scenario_regression);
            reduce_into(&bytes, dir, reduced, out, err)
        } else {
            replay_into(&bytes, dir, out, err)
        }
    }

    /// The fuzz targets the worker drives, by name.
    fn fuzz_target(name: &str) -> Option<&'static FuzzTarget> {
        [
            &CAMPAIGN,
            &PLANTED,
            &RECORD_TARGET,
            &WIRE,
            &PANICKING,
            &RECORD_CONTROL,
        ]
        .into_iter()
        .find(|target| target.name == name)
    }

    /// Enters the fuzz driver as `args` name it: a target, its artifact
    /// directory, then libFuzzer's arguments after `--`. The program name
    /// libFuzzer gets is this executable's `--fuzz` form for that target
    /// and directory.
    fn fuzz_into(args: &[String], err: &mut impl Write) -> i32 {
        let (ours, theirs) = match args.iter().position(|arg| arg == "--") {
            Some(at) => (&args[..at], &args[at + 1..]),
            None => (args, &[][..]),
        };
        let [name, flag, artifacts] = ours else {
            return refused(err, "--fuzz takes TARGET --artifacts DIR");
        };
        let (Some(target), "--artifacts") = (fuzz_target(name), flag.as_str()) else {
            return refused(err, "--fuzz needs a known TARGET and --artifacts DIR");
        };
        if !std::path::Path::new(artifacts).is_dir() {
            return refused(err, &format!("--artifacts {artifacts}: no such directory"));
        }
        match drive(target, artifacts, theirs) {
            Ok(code) => code,
            Err(reason) => refused(err, &reason),
        }
    }

    /// Minimizes the failing input `args` names under its target and writes
    /// the shortest input found failing with the same claim to the new file
    /// it names.
    fn minimize_into(args: &[String], out: &mut impl Write, err: &mut impl Write) -> i32 {
        let [name, input, flag, output] = args else {
            return refused(err, "--minimize takes TARGET INPUT --output FILE");
        };
        let (Some(target), "--output") = (fuzz_target(name), flag.as_str()) else {
            return refused(err, "--minimize needs a known TARGET and --output FILE");
        };
        let path = std::path::Path::new(output);
        let (dir, Some(file), false) = (
            path.parent().unwrap_or(std::path::Path::new(".")),
            path.file_name().and_then(|name| name.to_str()),
            output.ends_with('/'),
        ) else {
            return refused(err, "--output names no file");
        };
        if path.symlink_metadata().is_ok() || !(dir.as_os_str().is_empty() || dir.is_dir()) {
            return refused(
                err,
                &format!("--output {output}: exists or its directory does not"),
            );
        }
        let bytes = match std::fs::read(input) {
            Ok(bytes) => bytes,
            Err(error) => return refused(err, &format!("{input}: {error}")),
        };
        let Some((smallest, claim)) = minimized(target, &bytes) else {
            return finish(out, "minimize: the input does not fail\n", DIVERGED);
        };
        if let Err(reason) = create(dir, file, &smallest) {
            return refused(err, &reason);
        }
        let line = format!(
            "minimize: {} of {} bytes fail with {claim}\n",
            smallest.len(),
            bytes.len()
        );
        finish(out, &line, COUNTS)
    }

    /// Writes the seeds of the target `args` names into the directory it
    /// names.
    fn seeds_into(args: &[String], err: &mut impl Write) -> i32 {
        let [name, dir] = args else {
            return refused(err, "--seeds takes TARGET DIR");
        };
        let Some(target) = fuzz_target(name) else {
            return refused(err, &format!("no fuzz target is named {name}"));
        };
        let dir = std::path::Path::new(dir);
        for (file, bytes) in (target.seeds)() {
            if let Err(reason) = create(dir, &file, &bytes) {
                return refused(err, &reason);
            }
        }
        COUNTS
    }

    /// Branches a bundle as `command` names, into the new output directory
    /// it names, and prints the milestone, the parent's replay, each child
    /// and every failed check.
    fn branch_into(command: &Command, out: &mut impl Write, err: &mut impl Write) -> i32 {
        let (Some(path), Some(name), Some(count), Some(dir)) = (
            &command.branch,
            &command.milestone,
            &command.suffixes,
            &command.output,
        ) else {
            return refused(
                err,
                "--branch, --milestone, --suffixes and --output are all required",
            );
        };
        if command.run.is_some()
            || command.bundle.is_some()
            || command.inspect.is_some()
            || command.replay.is_some()
            || command.reduce.is_some()
        {
            return refused(err, "the branch form takes no other bundle form");
        }
        let bounded = |flag: &str, count: &str, max: u32| match count.parse::<u32>() {
            Ok(value) if (1..=max).contains(&value) && count == value.to_string() => Ok(value),
            _ => Err(format!("{flag} {count}: from 1 to {max}")),
        };
        let suffixes = match bounded("--suffixes", count, MAX_SUFFIXES) {
            Ok(suffixes) => suffixes,
            Err(reason) => return refused(err, &reason),
        };
        let siblings = match command
            .siblings
            .as_deref()
            .map_or(Ok(1), |count| bounded("--siblings", count, MAX_SIBLINGS))
        {
            Ok(siblings) => siblings,
            Err(reason) => return refused(err, &reason),
        };
        let (bytes, manifest, dir) = match staged(path, dir, err) {
            Ok(staged) => staged,
            Err(code) => return code,
        };
        let wait = std::time::Duration::from_secs(manifest.count("watchdog"));
        let branched = match branch(
            &bytes,
            name,
            (suffixes, siblings),
            &dir,
            ChildPlant::None,
            wait,
        ) {
            Ok(branched) => branched,
            Err(refusal) => {
                // A refusal before any child wrote leaves the directory empty,
                // so a corrected retry at the same path is admitted; a
                // directory holding bundles stays.
                let _ = std::fs::remove_dir(&dir);
                return match refusal {
                    Unbranched::Milestone(ForkRefusal::Host(reason)) => {
                        complain(err, &format!("the fork failed: {reason}"));
                        INCOMPLETE
                    }
                    Unbranched::Diverged => {
                        finish(out, "parent: diverged before the milestone\n", COMPLETE)
                    }
                    refusal => refused(err, &format!("{refusal:?}")),
                };
            }
        };
        let (lines, problems) = rendered(name, &branched);
        let code = match (branched.incomplete(), problems) {
            (true, _) => INCOMPLETE,
            (false, 0) => COUNTS,
            (false, _) => COMPLETE,
        };
        finish(out, &lines, code)
    }

    /// Explores a bundle's suffix tree as `command` names, into the new
    /// output directory it names, and prints the census.
    fn explore_into(command: &Command, out: &mut impl Write, err: &mut impl Write) -> i32 {
        let (Some(path), Some(name), Some(dir)) =
            (&command.explore, &command.milestone, &command.output)
        else {
            return refused(err, "--explore, --milestone and --output are all required");
        };
        if command.run.is_some()
            || command.bundle.is_some()
            || command.inspect.is_some()
            || command.replay.is_some()
            || command.reduce.is_some()
            || command.branch.is_some()
            || command.suffixes.is_some()
            || command.siblings.is_some()
        {
            return refused(err, "the explore form takes no other bundle form");
        }
        let (bytes, _, dir) = match staged(path, dir, err) {
            Ok(staged) => staged,
            Err(code) => return code,
        };
        let explored = match explore(&bytes, name, &dir, TreePlant::None) {
            Ok(explored) => explored,
            Err(refusal) => {
                // A refusal before any leaf wrote leaves the directory empty,
                // so a corrected retry at the same path is admitted; a
                // directory holding bundles stays.
                let _ = std::fs::remove_dir(&dir);
                return match refusal {
                    Unbranched::Milestone(ForkRefusal::Host(reason)) => {
                        complain(err, &format!("the fork failed: {reason}"));
                        INCOMPLETE
                    }
                    Unbranched::Diverged => {
                        finish(out, "parent: diverged before the milestone\n", COMPLETE)
                    }
                    refusal => refused(err, &format!("{refusal:?}")),
                };
            }
        };
        let (lines, problems) = explored.render(name, &dir);
        let code = match (
            explored.incomplete(&problems),
            problems.is_empty() && explored.passes(),
        ) {
            (true, _) => INCOMPLETE,
            (false, true) => COUNTS,
            (false, false) => COMPLETE,
        };
        finish(out, &lines, code)
    }

    /// The lines the branch form prints for `branched` at milestone `name`,
    /// and how many checks failed.
    fn rendered(name: &str, branched: &Branched) -> (String, usize) {
        let reached = &branched.reached;
        let mut lines = format!(
            "{}parent: {}\n",
            milestone_lines(name, reached),
            if branched.parent {
                "reproduced"
            } else {
                "changed"
            },
        );
        for child in &branched.children {
            lines.push_str(&format!(
                "child: suffix={} sibling={} class={}",
                child.suffix,
                child.sibling,
                child.class.name()
            ));
            if let Some(report) = &child.report {
                lines.push_str(&format!(
                    " digest={} terminal={}",
                    hex(&report.digest),
                    report.terminal
                ));
            }
            lines.push('\n');
        }
        let problems = branched.problems();
        for problem in &problems {
            lines.push_str(&format!("problem: {problem}\n"));
        }
        let credited = branched
            .children
            .iter()
            .filter(|child| child.class.credited())
            .count();
        lines.push_str(&format!(
            "branch: {} children, {credited} credited, {} problems\n",
            branched.children.len(),
            problems.len()
        ));
        (lines, problems.len())
    }

    /// Reads the bundle at `path` once and creates the new output directory
    /// `dir`. The bundle's recorded manifest must pin this executable and
    /// platform. A missing bundle and an existing output directory are
    /// refused; any other failure to read or create them, or to read the
    /// executable, is incomplete evidence. Returns the bundle, its manifest
    /// and the directory, or the exit code of the refusal.
    fn staged(
        path: &str,
        dir: &str,
        err: &mut impl Write,
    ) -> Result<(Vec<u8>, Manifest, std::path::PathBuf), i32> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(refused(err, &format!("bundle {path}: {error}")));
            }
            Err(error) => return Err(host(err, &error, format!("bundle {path}"))),
        };
        stage(bytes, path, dir, err)
    }

    /// [`staged`] over `bytes`, read from `path`.
    fn stage(
        bytes: Vec<u8>,
        path: &str,
        dir: &str,
        err: &mut impl Write,
    ) -> Result<(Vec<u8>, Manifest, std::path::PathBuf), i32> {
        let manifest = match recorded(&bytes) {
            Ok((_, manifest)) => manifest,
            Err(refusal) => return Err(refused(err, &format!("bundle {path}: {refusal:?}"))),
        };
        pinned_here(&manifest, "bundle", err)?;
        let dir = std::path::Path::new(dir).to_path_buf();
        match std::fs::create_dir(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(refused(err, &format!("output {}: {error}", dir.display())));
            }
            Err(error) => return Err(host(err, &error, format!("output {}", dir.display()))),
        }
        Ok((bytes, manifest, dir))
    }

    /// Returns the bundle's terminal and either the obligation named in its
    /// violation record or the class of its failed audit record.
    fn claim(bytes: &[u8]) -> String {
        load(bytes, u64::MAX).map_or_else(|_| "no terminal".into(), |loaded| claimed(&loaded))
    }

    /// `loaded`'s terminal and either the obligation named in its violation
    /// record or the class of its failed audit record.
    fn claimed(loaded: &Loaded) -> String {
        with_breach(terminal_text(loaded.terminal), loaded)
    }

    /// `prefix`, followed by [`breach_text`] of `loaded` when it names one.
    fn with_breach(prefix: String, loaded: &Loaded) -> String {
        match breach_text(loaded) {
            Some(breached) => format!("{prefix}, {breached}"),
            None => prefix,
        }
    }

    /// The obligation `loaded`'s violation record names or the class of
    /// its failed audit record, as the claim and the summary's cause print
    /// it; `None` without a violation record that names either.
    fn breach_text(loaded: &Loaded) -> Option<String> {
        match loaded.violation.as_ref().and_then(breach)? {
            Breach::Obligation(obligation) => Some(format!("violating {obligation:?}")),
            Breach::Audit(class) => Some(format!("a failing {class:?} audit record")),
        }
    }

    /// Where a replay diverged: a semantic record, counting `Begin` as 0, or
    /// the result once every record matched.
    fn position(at: Option<usize>) -> String {
        match at {
            Some(at) => format!("semantic record {at}"),
            None => "the result".into(),
        }
    }

    /// Reports a failure of the host to read or write `what` as
    /// incomplete evidence.
    fn host(err: &mut impl Write, error: &std::io::Error, what: String) -> i32 {
        complain(err, &format!("{what}: {error}"));
        INCOMPLETE
    }

    /// Writes `bytes` as the new file `name` in `dir`.
    fn create(dir: &std::path::Path, name: &str, bytes: &[u8]) -> Result<(), String> {
        let path = dir.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Replays `bytes` and writes the replay's bundle into `dir`: exit 0
    /// when it reproduced, 1 when it diverged or its run panicked, which
    /// writes the bundle recorded so far and prints the panic's location
    /// and payload, 2 when the tape ends before or inside a decision the
    /// run draws or the run is refused, 3 when the replay's bundle cannot
    /// be written.
    fn replay_into(
        bytes: &[u8],
        dir: &std::path::Path,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> i32 {
        let mut again = Vec::new();
        let replayed = match crate::sim::unwind::caught(|| replay_recording(bytes, &mut again)) {
            Ok(replayed) => replayed,
            Err(panic) => {
                if let Err(reason) = create(dir, "replay.bundle", &again) {
                    complain(err, &reason);
                    return INCOMPLETE;
                }
                return finish(out, &panic_replay_line(panic), DIVERGED);
            }
        };
        let replayed = match replayed {
            Ok(replayed) => replayed,
            Err(
                refusal @ (ReplayRefused::Input(_)
                | ReplayRefused::Exhausted
                | ReplayRefused::Recovery(_)),
            ) => {
                return refused(err, &format!("{refusal:?}"));
            }
            Err(other) => {
                complain(err, &format!("{other:?}"));
                return INCOMPLETE;
            }
        };
        if let Err(reason) = create(dir, "replay.bundle", &again) {
            complain(err, &reason);
            return INCOMPLETE;
        }
        let (line, code) = replay_line(replayed, &again);
        finish(out, &line, code)
    }

    fn replay_line(replayed: Replayed, bytes: &[u8]) -> (String, i32) {
        match replayed {
            Replayed::Reproduced => (
                format!("replay: reproduced, {}\n", claim(bytes)),
                REPRODUCED,
            ),
            Replayed::Diverged { at, reason } => (
                format!("replay: diverged at {}: {reason}\n", position(at)),
                DIVERGED,
            ),
        }
    }
    fn panic_replay_line(panic: String) -> String {
        format!("replay: {}\n", Identity::Panic(panic))
    }

    /// A command running `worker` in a fresh process whose environment
    /// holds only `library_path` as `LD_LIBRARY_PATH`, when there is one, so
    /// the fresh process searches the same library directories as its
    /// parent.
    fn fresh_worker(
        worker: &std::path::Path,
        library_path: Option<&std::ffi::OsStr>,
    ) -> std::process::Command {
        let mut command = std::process::Command::new(worker);
        command.env_clear();
        if let Some(path) = library_path {
            command.env("LD_LIBRARY_PATH", path);
        }
        command
    }

    /// Reduces `bytes` into `dir` through `reduce`, the --reduce or
    /// --reduce-schedule reducer, under the contract USAGE states, its files
    /// and exit codes included, replaying the original and every step that
    /// would be kept in a fresh worker process. A step whose fresh replay
    /// diverges or refuses its bundle does not reproduce. The
    /// executable's path and the library search path locate the worker and
    /// its libraries for the fresh processes alone; no decision reads them.
    ///
    /// A refused panic-step rerun or an unreadable rerun bundle counts as a
    /// failed fresh-process check.
    fn reduce_into(
        bytes: &[u8],
        dir: &std::path::Path,
        reduce: impl FnOnce(&mut Verify<'_>) -> Result<Regression, ReplayRefused>,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> i32 {
        let worker = match std::env::current_exe() {
            Ok(worker) => worker,
            Err(error) => return host(err, &error, "the worker's own path".into()),
        };
        let library_path = std::env::var_os("LD_LIBRARY_PATH");
        let mut step = 0;
        let mut verify = |candidate: &[u8], identity: &Identity| -> Result<bool, String> {
            step += 1;
            let name = format!("step-{step}.bundle");
            create(dir, &name, candidate)?;
            // A panicked run's tape ends before the turn the panic cut, so
            // the fresh process reruns its recorded manifest to the same
            // panic and the same bundle.
            let rerun = dir.join(format!("step-{step}.rerun.bundle"));
            let mut command = fresh_worker(&worker, library_path.as_deref());
            match identity {
                Identity::Violation(_) => {
                    command
                        .arg("--replay")
                        .arg(dir.join(&name))
                        .arg("--output")
                        .arg(dir.join(format!("step-{step}.replay")));
                }
                Identity::Panic(_) => {
                    let manifest = format!("step-{step}.manifest");
                    let (_, recorded) =
                        recorded(candidate).map_err(|refusal| format!("{refusal:?}"))?;
                    create(dir, &manifest, recorded.text().as_bytes())?;
                    command
                        .arg("--manifest")
                        .arg(dir.join(&manifest))
                        .arg("--bundle")
                        .arg(&rerun);
                }
            }
            let replayed = command
                .output()
                .map_err(|error| format!("step {step} fresh process: {error}"))?;
            reproduced_by(step, identity, &replayed, &rerun, candidate)
        };
        let reduced = match reduce(&mut verify) {
            Ok(reduced) => reduced,
            Err(ReplayRefused::Unreducible(reason)) => {
                complain(err, &reason);
                return DIVERGED;
            }
            Err(ReplayRefused::Infrastructure(reason)) => {
                complain(err, &reason);
                return INCOMPLETE;
            }
            Err(refusal) => return refused(err, &format!("{refusal:?}")),
        };
        let written: [(&str, &[u8]); 6] = [
            ("original.bundle", bytes),
            ("regression.manifest", reduced.manifest.as_bytes()),
            ("regression.bundle", &reduced.bundle),
            ("scenario.txt", reduced.scenario.as_bytes()),
            ("steps.txt", reduced.steps.as_bytes()),
            ("conditions.txt", reduced.conditions.as_bytes()),
        ];
        let written = written
            .into_iter()
            .try_for_each(|(name, contents)| create(dir, name, contents));
        if let Err(reason) = written {
            complain(err, &reason);
            return INCOMPLETE;
        }
        match reduced.line {
            Ok(line) => finish(out, &line, REPRODUCED),
            Err(reason) => {
                complain(err, &reason);
                INCOMPLETE
            }
        }
    }

    /// A reduction's regression as its files hold it: the recorded
    /// manifest's text, the bundle, scenario.txt, steps.txt and
    /// conditions.txt, and the summary line, or the reason a fresh-process
    /// check failed.
    struct Regression {
        manifest: String,
        bundle: Vec<u8>,
        scenario: String,
        steps: String,
        conditions: String,
        line: Result<String, String>,
    }

    /// The files of a scenario reduction.
    fn scenario_regression(reduced: Reduced) -> Regression {
        let mut steps: String = reduced
            .steps
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        steps.push('\n');
        let (stopped, line) = stop_lines(&reduced);
        let line = line.map_err(str::to_owned);
        steps.push_str(&stopped);
        let conditions: String = reduced
            .conditions
            .iter()
            .map(|name| format!("{name}\n"))
            .collect();
        Regression {
            manifest: reduced.manifest.text(),
            scenario: reduced.scenario,
            steps,
            conditions,
            line,
            bundle: reduced.bundle,
        }
    }

    /// Reduces the schedule of the bundle `args` names under the
    /// --reduce-schedule contract USAGE states: `BUNDLE --output DIR` and
    /// each bound at most once.
    fn reduce_schedule_into(args: &[String], out: &mut impl Write, err: &mut impl Write) -> i32 {
        use crate::net::world_tests::{narrate, schedule};
        let (bytes, path, output, budget) = match scheduled(args) {
            Ok((path, output, records, budget)) => match narrate::bounded(path, records) {
                Ok(bytes) => (bytes, path, output, budget),
                Err((code, reason)) => {
                    complain(err, &format!("bundle {path}: {reason}"));
                    return code;
                }
            },
            Err(reason) => return refused(err, &reason),
        };
        let (bytes, _, dir) = match stage(bytes, path, output, err) {
            Ok(staged) => staged,
            Err(code) => return code,
        };
        let reduced = |verify: &mut Verify<'_>| {
            schedule::reduce(&bytes, verify, budget).map(schedule_regression)
        };
        reduce_into(&bytes, &dir, reduced, out, err)
    }

    /// The bundle, output directory, record bound and budget of a
    /// --reduce-schedule command line.
    fn scheduled(args: &[String]) -> Result<(&str, &str, u64, Budget), String> {
        let (path, flags) = args
            .split_first()
            .ok_or("--reduce-schedule takes BUNDLE --output DIR")?;
        let (mut output, mut records) = (None, None);
        let (mut candidates, mut passes, mut runs) = (None, None, None);
        let mut flags = flags.iter().map(String::as_str);
        while let Some(flag) = flags.next() {
            let value = flags.next().ok_or(format!("{flag} needs a value"))?;
            let slot = match flag {
                "--output" if output.is_none() => {
                    output = Some(value);
                    continue;
                }
                "--max-records" if records.is_none() => &mut records,
                "--max-candidates" if candidates.is_none() => &mut candidates,
                "--max-passes" if passes.is_none() => &mut passes,
                "--max-runs" if runs.is_none() => &mut runs,
                _ => {
                    return Err(format!(
                        "{flag}: unknown or repeated after --reduce-schedule"
                    ));
                }
            };
            let count = value.parse::<u64>().ok();
            let count = count.filter(|&count| count > 0 && count.to_string() == value);
            *slot = Some(count.ok_or(format!("{flag} {value}: not a positive count"))?);
        }
        let default = Budget::DEFAULT;
        let budget = Budget {
            candidates: candidates.unwrap_or(default.candidates),
            passes: passes.unwrap_or(default.passes),
            runs: runs.unwrap_or(default.runs),
        };
        let records = records.unwrap_or(crate::net::world_tests::narrate::MAX_RECORDS);
        Ok((path, output.ok_or("--output is required")?, records, budget))
    }

    /// The files of a schedule reduction, steps.txt and the summary line as
    /// [`ScheduleReduced::report`] writes them.
    fn schedule_regression(reduced: ScheduleReduced) -> Regression {
        let (steps, line) = reduced.report();
        Regression {
            manifest: reduced.manifest.text(),
            scenario: reduced.scenario,
            steps,
            conditions: reduced
                .requirement
                .iter()
                .map(|name| format!("{name}\n"))
                .collect(),
            line,
            bundle: reduced.bundle,
        }
    }

    /// How `reduced` stopped: the steps.txt line that follows its steps,
    /// empty for an exhausted reduction, and its summary line, which names
    /// `, bounded` for a reduction at its step bound before a panic's
    /// location and payload. An interrupted reduction has no summary line
    /// and gives the reason the fresh-process check failed, so it exits
    /// incomplete.
    fn stop_lines(reduced: &Reduced) -> (String, Result<String, &str>) {
        let (stopped, bounded) = match &reduced.stop {
            Stop::Exhausted => ("", ""),
            Stop::Bounded => ("stopped at the step bound\n", ", bounded"),
            // The reason can carry a fresh process's stderr, so it prints
            // escaped to keep each steps.txt entry on one line.
            Stop::Interrupted(reason) => {
                let stopped = format!("interrupted, the fresh-process check failed: {reason:?}\n");
                return (stopped, Err(reason));
            }
        };
        let records = reduced.bundle.len() / RECORD;
        let mut line = format!(
            "reduce: reduced to {records} records, scenario {}{bounded}",
            reduced.manifest.scenario
        );
        // The panic's text comes last, so the bounded marker precedes it.
        if let Identity::Panic(_) = &reduced.identity {
            line.push_str(&format!(", {}", reduced.identity));
        }
        line.push('\n');
        (stopped.to_owned(), Ok(line))
    }

    /// `Err` means the fresh process's result is inconclusive for the
    /// candidate. A refused replay, including tape exhaustion, counts as a
    /// failure to reproduce. A rerun is inconclusive when the run form
    /// refuses it or the host cannot read the rerun bundle, since the
    /// reducer admits the rerun's manifest before requesting the rerun.
    fn reproduced_by(
        step: usize,
        identity: &Identity,
        ran: &std::process::Output,
        rerun: &std::path::Path,
        candidate: &[u8],
    ) -> Result<bool, String> {
        let printed = String::from_utf8_lossy(&ran.stdout);
        match (identity, ran.status.code()) {
            (Identity::Violation(_), Some(REPRODUCED)) => Ok(true),
            (Identity::Violation(_), Some(DIVERGED | REFUSED)) => Ok(false),
            (Identity::Panic(_), Some(INCOMPLETE)) => {
                let named: Vec<&str> = printed
                    .lines()
                    .filter(|line| line.starts_with("run: the run panicked at "))
                    .collect();
                if named.is_empty() {
                    return Err(format!(
                        "step {step} rerun ended incomplete with no panic: {}",
                        String::from_utf8_lossy(&ran.stderr)
                    ));
                }
                if named != [format!("run: {identity}")] {
                    return Ok(false);
                }
                let rerun = std::fs::read(rerun)
                    .map_err(|error| format!("step {step} {}: {error}", rerun.display()))?;
                Ok(rerun == candidate)
            }
            (Identity::Panic(_), Some(REPRODUCED | DIVERGED)) => Ok(false),
            _ => Err(format!(
                "step {step} fresh process exited {}: {}",
                ran.status,
                String::from_utf8_lossy(&ran.stderr)
            )),
        }
    }

    /// A fresh-process case's fixture: the worker's own executable and an
    /// empty scratch directory beside it, named for the case and this
    /// process and removed when the fixture drops. The executable's path
    /// locates the worker and its directory for the check alone; no
    /// decision reads it.
    struct Scratch {
        worker: std::path::PathBuf,
        dir: std::path::PathBuf,
    }

    impl Scratch {
        fn new(name: &str) -> Result<Self, String> {
            let worker = std::env::current_exe().map_err(|error| error.to_string())?;
            let dir = crate::net::world_tests::scratch(name)?;
            Ok(Self { worker, dir })
        }

        /// The worker as a fresh process with a cleared environment.
        fn command(&self) -> std::process::Command {
            let mut command = std::process::Command::new(&self.worker);
            command.env_clear();
            command
        }

        /// Runs the worker in a fresh process with a cleared environment.
        fn run(&self, args: &[&std::ffi::OsStr]) -> Result<std::process::Output, String> {
            self.command()
                .args(args)
                .output()
                .map_err(|error| error.to_string())
        }

        /// Writes manifest `text` to `PROFILE.manifest` and runs it into
        /// `PROFILE.bundle`.
        fn record(&self, profile: &str, text: &str) -> Result<std::process::Output, String> {
            let manifest = self.dir.join(format!("{profile}.manifest"));
            std::fs::write(&manifest, text).map_err(|error| error.to_string())?;
            let bundle = self.dir.join(format!("{profile}.bundle"));
            self.run(&[
                "--manifest".as_ref(),
                manifest.as_os_str(),
                "--bundle".as_ref(),
                bundle.as_os_str(),
            ])
        }

        /// Runs `form` over `PROFILE.bundle` at milestone `name` with the
        /// further arguments `extra`, writing into `output`.
        fn at_milestone(
            &self,
            (form, profile, name): (&str, &str, &str),
            extra: &[&str],
            output: &str,
        ) -> Result<std::process::Output, String> {
            let (bundle, output) = (
                self.dir.join(format!("{profile}.bundle")),
                self.dir.join(output),
            );
            let mut args = vec![
                form.as_ref(),
                bundle.as_os_str(),
                "--milestone".as_ref(),
                name.as_ref(),
            ];
            args.extend(extra.iter().map(std::ffi::OsStr::new));
            args.extend(["--output".as_ref(), output.as_os_str()]);
            self.run(&args)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A fresh worker process narrates a bundle of 12,000 turns into its new
    /// output file, past a megabyte there, and prints one line; with that
    /// file present it is refused and the file stays as it was.
    fn narrated() -> Result<(), String> {
        let scratch = Scratch::new("sim-narrate")?;
        let (bundle, output) = (scratch.dir.join("bundle"), scratch.dir.join("narrative"));
        let large = crate::net::world_tests::narrate::tests::large_bundle();
        std::fs::write(&bundle, large).map_err(|error| error.to_string())?;
        let args = [
            "--narrate".as_ref(),
            bundle.as_os_str(),
            "--output".as_ref(),
            output.as_os_str(),
            "--events".as_ref(),
        ];
        let first = scratch.run(&args)?;
        let written = std::fs::read(&output).map_err(|error| error.to_string())?;
        let again = scratch.run(&args)?;
        let codes = (first.status.code(), again.status.code());
        let one_line = first.stdout.split(|&byte| byte == b'\n').count() == 2;
        if codes != (Some(COUNTS), Some(REFUSED)) || !first.stderr.is_empty() || !one_line {
            return Err(format!(
                "the narrative exited {codes:?}: {first:?}, then {again:?}"
            ));
        }
        if written.len() <= 1 << 20 || std::fs::read(&output).ok() != Some(written) {
            return Err("the narrative did not stay whole in its file".into());
        }
        Ok(())
    }

    /// Fresh processes commit a broad cluster session of 3 windows and
    /// replay it to the same chain; a changed end line diverges; an index
    /// line naming a field twice is refused before any replay output
    /// exists, and one whose verdict its chunk does not yield is refused
    /// after the replay compares; a replay whose own chunk cannot be read
    /// back is unread; the session is refused after its manifest's root or
    /// registry bound changes, which breaks its chain, or after a chunk is
    /// removed, and no replay output is written then. An end that differs
    /// only in `apply_ms` reproduces, and the end counts its turns. A byte
    /// budget of the manifest and two windows stops a session in window 2
    /// with exit 3, nothing on stdout, those two windows committed and no
    /// end, and its replay is refused as incomplete; that session's DIR is
    /// a bare name under the worker's current directory. A non-cluster
    /// manifest, an existing DIR, a missing MANIFEST or SESSION, `--bundle`
    /// given with `--session`, and `--session` given with
    /// `--replay-session` exit 2 before any output exists, preserving the
    /// existing DIR. A MANIFEST or SESSION manifest the host cannot read as
    /// text exits 3 before any output exists. A complete version-end
    /// session exits 1.
    fn sessions() -> Result<(), String> {
        let scratch = Scratch::new("worker-sessions")?;
        let dir = &scratch.dir;
        let manifest = dir.join("broad.manifest");
        let text = crate::sim::manifest_tests::sample("cluster-broad", &own_digest()?, &platform())
            .replace("actors = 32", "actors = 64")
            .replace("same_time = 400", "same_time = 4000")
            .replace("no_progress = 5000", "no_progress = 50000");
        std::fs::write(&manifest, &text).map_err(|error| error.to_string())?;
        let replay = |source: &std::path::Path, name: &str| {
            let target = dir.join(name);
            let ran = scratch.run(&[
                "--replay-session".as_ref(),
                source.as_os_str(),
                "--output".as_ref(),
                target.as_os_str(),
            ])?;
            Ok::<_, String>((ran, target))
        };
        let original = dir.join("original");
        let ran = scratch.run(&[
            "--session".as_ref(),
            manifest.as_os_str(),
            "--output".as_ref(),
            original.as_os_str(),
        ])?;
        let printed = String::from_utf8_lossy(&ran.stdout).into_owned();
        if ran.status.code() != Some(COUNTS) || !printed.starts_with("session: 3 windows, chain ") {
            return Err(format!("the session exited {}: {printed}", ran.status));
        }
        let size = |path: std::path::PathBuf| {
            std::fs::metadata(&path)
                .map(|meta| meta.len())
                .map_err(|error| format!("{}: {error}", path.display()))
        };
        let (lines, _) = crate::net::world_tests::session::committed(&original)?;
        let mut windows_bytes = 0;
        for (at, line) in lines.iter().take(2).enumerate() {
            windows_bytes += size(original.join("windows").join(format!("{at:06}.chunk")))?
                + line.len() as u64
                + 1;
        }
        let frozen = size(original.join("manifest"))?;
        let chain = printed
            .lines()
            .next()
            .and_then(|line| line.rsplit(' ').next())
            .unwrap_or("");
        let (replayed, _) = replay(&original, "again")?;
        let line = String::from_utf8_lossy(&replayed.stdout).into_owned();
        if replayed.status.code() != Some(REPRODUCED)
            || !line.ends_with(&format!("chain {chain}\n"))
        {
            return Err(format!("the replay exited {}: {line}", replayed.status));
        }
        let end_path = original.join("end");
        let saved_end = std::fs::read_to_string(&end_path).map_err(|error| error.to_string())?;
        let apply = saved_end
            .split(' ')
            .find_map(|field| field.strip_prefix("apply_ms="))
            .unwrap_or("");
        if apply.len() != 12 || !apply.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!(
                "the end's apply_ms is not twelve digits: {saved_end}"
            ));
        }
        let turns = saved_end
            .split(' ')
            .find_map(|field| field.strip_prefix("turns="))
            .and_then(|turns| turns.parse::<u64>().ok());
        if !matches!(turns, Some(1..)) {
            return Err(format!("the end counts no turns: {saved_end}"));
        }
        let other_apply = saved_end.replacen(
            &format!("apply_ms={apply}"),
            if apply == "999999999999" {
                "apply_ms=000000000000"
            } else {
                "apply_ms=999999999999"
            },
            1,
        );
        if other_apply == saved_end
            || !matches!(
                replay_verdict(
                    (&original, &lines, &saved_end),
                    (&original, &lines, &other_apply)
                ),
                SessionReplay::Reproduced
            )
        {
            return Err(format!(
                "an end differing only in apply_ms did not reproduce: {other_apply}"
            ));
        }
        std::fs::write(&end_path, saved_end.replacen(" turns=", " turns=1", 1))
            .map_err(|error| error.to_string())?;
        let (differs, _) = replay(&original, "different-end")?;
        let line = String::from_utf8_lossy(&differs.stdout).into_owned();
        if differs.status.code() != Some(DIVERGED) || !line.contains("the end differs") {
            return Err(format!(
                "a changed end replayed with {}: {line}",
                differs.status
            ));
        }
        std::fs::write(&end_path, &saved_end).map_err(|error| error.to_string())?;
        let index_path = original.join("index");
        let index = std::fs::read_to_string(&index_path).map_err(|error| error.to_string())?;
        for (name, changed, expected) in [
            (
                "repeated",
                index.replacen('\n', &format!(" digest={}\n", "00".repeat(32)), 1),
                "window 0 names digest twice",
            ),
            (
                "altered",
                index.replacen(" verdict=pass ", " verdict=failed ", 1),
                "window 0's index line differs from the one its chunk yields",
            ),
        ] {
            if changed == index {
                return Err(format!("the {name} index equals the saved one"));
            }
            std::fs::write(&index_path, changed).map_err(|error| error.to_string())?;
            let (ran, target) = replay(&original, name)?;
            let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
            if ran.status.code() != Some(REFUSED)
                || !stderr.contains(expected)
                || (name == "repeated" && target.exists())
            {
                return Err(format!(
                    "a {name} index line replayed with {}: {stderr}",
                    ran.status
                ));
            }
        }
        std::fs::write(&index_path, &index).map_err(|error| error.to_string())?;
        let mut other = lines.clone();
        other[0].push_str(" other");
        let unread = replay_verdict(
            (&original, &lines, &saved_end),
            (&dir.join("absent"), &other, &saved_end),
        );
        if !matches!(unread, SessionReplay::Unread(_)) {
            return Err("a replay without its own chunk read as another verdict".to_owned());
        }
        let manifest_path = original.join("manifest");
        let saved = std::fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
        for (from, to) in [
            ("root = 3", "root = 4"),
            ("registry = 4096", "registry = 8192"),
        ] {
            if !saved.contains(from) {
                return Err(format!("the session's manifest names no {from}"));
            }
            std::fs::write(&manifest_path, saved.replace(from, to))
                .map_err(|error| error.to_string())?;
            let (changed, target) = replay(&original, &format!("changed-{}", &to[..4]))?;
            let stderr = String::from_utf8_lossy(&changed.stderr).into_owned();
            if changed.status.code() != Some(REFUSED)
                || !stderr.contains("out of its chain")
                || target.exists()
            {
                return Err(format!(
                    "a manifest changed to {to} replayed with {}: {stderr}",
                    changed.status
                ));
            }
        }
        std::fs::write(&manifest_path, saved).map_err(|error| error.to_string())?;
        std::fs::remove_file(original.join("windows").join("000001.chunk"))
            .map_err(|error| error.to_string())?;
        let (refused, missing) = replay(&original, "missing")?;
        if refused.status.code() != Some(REFUSED) || missing.exists() {
            return Err(format!(
                "a session missing a window replayed with {}",
                refused.status
            ));
        }
        let budgeted = |bytes: u64| text.replace("bytes = 48000000", &format!("bytes = {bytes}"));
        // The frozen manifest's length moves with the digits of its own
        // byte budget, so the budget settles in a few steps.
        let mut bytes = frozen + windows_bytes;
        loop {
            let next = frozen + windows_bytes + budgeted(bytes).len() as u64 - text.len() as u64;
            if next == bytes {
                break;
            }
            bytes = next;
        }
        let small = dir.join("small.manifest");
        std::fs::write(&small, budgeted(bytes)).map_err(|error| error.to_string())?;
        // A bare relative DIR syncs the current directory as its parent.
        let halted = dir.join("halted");
        let stopped = scratch
            .command()
            .current_dir(dir)
            .args(["--session".as_ref(), small.as_os_str(), "--output".as_ref()])
            .arg("halted")
            .output()
            .map_err(|error| error.to_string())?;
        let stderr = String::from_utf8_lossy(&stopped.stderr).into_owned();
        let kept = crate::net::world_tests::session::committed(&halted).map(|(kept, _)| kept.len());
        if stopped.status.code() != Some(INCOMPLETE)
            || !stopped.stdout.is_empty()
            || !stderr.contains(&format!("the session's byte budget of {bytes} is spent"))
            || !stderr.contains("the uncommitted end: end: stop=halted ")
            || kept != Ok(2)
            || halted.join("end").exists()
        {
            return Err(format!(
                "a session within {bytes} bytes exited {} with {kept:?} windows: {stderr}",
                stopped.status
            ));
        }
        let (refused, target) = replay(&halted, "halted-replay")?;
        let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
        if refused.status.code() != Some(REFUSED)
            || !stderr.contains("the session is incomplete")
            || target.exists()
        {
            return Err(format!(
                "an incomplete session replayed with {}: {stderr}",
                refused.status
            ));
        }
        let upload = dir.join("upload.manifest");
        std::fs::write(
            &upload,
            crate::sim::manifest_tests::sample("upload", &own_digest()?, &platform()),
        )
        .map_err(|error| error.to_string())?;
        let fresh = dir.join("never");
        // Every entry's name and, for a file, its bytes, under `path`.
        fn entries(
            path: &std::path::Path,
            out: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
        ) -> Result<(), String> {
            let mut found: Vec<_> = std::fs::read_dir(path)
                .map_err(|error| error.to_string())?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<Result<_, _>>()
                .map_err(|error| error.to_string())?;
            found.sort();
            for entry in found {
                if entry.is_dir() {
                    out.push((entry.clone(), Vec::new()));
                    entries(&entry, out)?;
                } else {
                    let bytes = std::fs::read(&entry).map_err(|error| error.to_string())?;
                    out.push((entry, bytes));
                }
            }
            Ok(())
        }
        let snapshot = |path: &std::path::Path| {
            let mut out = Vec::new();
            entries(path, &mut out)?;
            Ok::<_, String>(out)
        };
        let before = snapshot(&original)?;
        // A directory at the manifest path opens, but reading it fails with
        // `IsADirectory`, a host failure distinct from a missing file.
        let unreadable = dir.join("unreadable");
        std::fs::create_dir_all(unreadable.join("manifest")).map_err(|error| error.to_string())?;
        let absent = dir.join("absent");
        for (name, flag, source, target, code, expected) in [
            (
                "a non-cluster manifest",
                "--session",
                &upload,
                &fresh,
                REFUSED,
                "is no cluster profile",
            ),
            (
                "an existing DIR",
                "--session",
                &manifest,
                &original,
                REFUSED,
                "output ",
            ),
            (
                "a missing manifest",
                "--session",
                &absent,
                &fresh,
                REFUSED,
                "manifest ",
            ),
            (
                "a directory as the manifest",
                "--session",
                &unreadable,
                &fresh,
                INCOMPLETE,
                "manifest ",
            ),
            (
                "a missing session",
                "--replay-session",
                &absent,
                &fresh,
                REFUSED,
                "session ",
            ),
            (
                "a session whose manifest is a directory",
                "--replay-session",
                &unreadable,
                &fresh,
                INCOMPLETE,
                "session ",
            ),
        ] {
            let ran = scratch.run(&[
                flag.as_ref(),
                source.as_os_str(),
                "--output".as_ref(),
                target.as_os_str(),
            ])?;
            let stderr = String::from_utf8_lossy(&ran.stderr).into_owned();
            if ran.status.code() != Some(code)
                || !ran.stdout.is_empty()
                || !stderr.contains(expected)
                || fresh.exists()
                || snapshot(&original)? != before
            {
                return Err(format!("{name} ran with {}: {stderr}", ran.status));
            }
        }
        let bundled = scratch.run(&[
            "--session".as_ref(),
            manifest.as_os_str(),
            "--bundle".as_ref(),
            dir.join("other.bundle").as_os_str(),
            "--output".as_ref(),
            fresh.as_os_str(),
        ])?;
        let stderr = String::from_utf8_lossy(&bundled.stderr).into_owned();
        if bundled.status.code() != Some(REFUSED)
            || !bundled.stdout.is_empty()
            || !stderr.contains("the session forms take no other bundle form")
            || fresh.exists()
        {
            return Err(format!(
                "a session beside --bundle ran with {}: {stderr}",
                bundled.status
            ));
        }
        let both = scratch.run(&[
            "--session".as_ref(),
            manifest.as_os_str(),
            "--replay-session".as_ref(),
            original.as_os_str(),
            "--output".as_ref(),
            fresh.as_os_str(),
        ])?;
        if both.status.code() != Some(REFUSED) || !both.stdout.is_empty() || fresh.exists() {
            return Err(format!("both session flags ran with {}", both.status));
        }
        let stale = dir.join("version-end.manifest");
        std::fs::write(
            &stale,
            crate::sim::manifest_tests::sample("cluster-version-end", &own_digest()?, &platform())
                .replace("root = 3", "root = 7")
                .replace("actors = 32", "actors = 64")
                .replace("same_time = 400", "same_time = 4000")
                .replace("no_progress = 5000", "no_progress = 50000"),
        )
        .map_err(|error| error.to_string())?;
        let complete = dir.join("version-end");
        let ran = scratch.run(&[
            "--session".as_ref(),
            stale.as_os_str(),
            "--output".as_ref(),
            complete.as_os_str(),
        ])?;
        let printed = String::from_utf8_lossy(&ran.stdout).into_owned();
        if ran.status.code() != Some(COMPLETE)
            || !printed.starts_with("session: ")
            || !printed.contains(" counts=false ")
            || !complete.join("end").exists()
        {
            return Err(format!(
                "a complete session that does not count exited {}: {printed}",
                ran.status
            ));
        }
        println!(
            "session: 3 windows committed and replayed alike by fresh processes, chain {chain}"
        );
        Ok(())
    }

    /// A fresh worker process prints the capability listing for
    /// `--capabilities` alone and exits 0; `--capabilities` beside another
    /// argument, `--help` included, is refused.
    fn capabilities() -> Result<(), String> {
        let worker = std::env::current_exe().map_err(|error| error.to_string())?;
        let listed = std::process::Command::new(&worker)
            .arg("--capabilities")
            .env_clear()
            .output()
            .map_err(|error| error.to_string())?;
        let text = String::from_utf8_lossy(&listed.stdout).into_owned();
        if listed.status.code() != Some(COUNTS)
            || text != crate::net::world_tests::catalog::listing()
        {
            return Err(format!("--capabilities exited {}: {text}", listed.status));
        }
        for other in ["--list", "--help", "-h"] {
            let extra = std::process::Command::new(&worker)
                .args(["--capabilities", other])
                .env_clear()
                .output()
                .map_err(|error| error.to_string())?;
            if extra.status.code() != Some(REFUSED) || !extra.stdout.is_empty() {
                return Err(format!("--capabilities {other} exited {}", extra.status));
            }
        }
        Ok(())
    }

    /// A fresh worker process prints the rule catalog for `--rules` alone
    /// and exits 0; `--rules` beside another argument is refused with no
    /// output.
    fn rule_catalog() -> Result<(), String> {
        let worker = std::env::current_exe().map_err(|error| error.to_string())?;
        let listed = std::process::Command::new(&worker)
            .arg("--rules")
            .env_clear()
            .output()
            .map_err(|error| error.to_string())?;
        let text = String::from_utf8_lossy(&listed.stdout).into_owned();
        if listed.status.code() != Some(COUNTS)
            || text != crate::net::world_tests::narrate::rules::listing()
        {
            return Err(format!("--rules exited {}: {text}", listed.status));
        }
        for other in ["--list", "--help", "--capabilities"] {
            let extra = std::process::Command::new(&worker)
                .args(["--rules", other])
                .env_clear()
                .output()
                .map_err(|error| error.to_string())?;
            if extra.status.code() != Some(REFUSED) || !extra.stdout.is_empty() {
                return Err(format!("--rules {other} exited {}", extra.status));
            }
        }
        Ok(())
    }

    /// The SHA-256 of the running executable, lowercase hex. It reads the
    /// image `/proc/self/exe` opens, the file this process executes even
    /// when another file has since replaced it at its path, through one
    /// fixed buffer; no decision reads it.
    fn own_digest() -> Result<String, String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut file = std::fs::File::open("/proc/self/exe").map_err(|error| error.to_string())?;
        let (mut digest, mut buffer) = (Sha256::new(), vec![0_u8; 64 * 1024]);
        loop {
            match file.read(&mut buffer) {
                Ok(0) => return Ok(hex(&digest.finalize())),
                Ok(read) => digest.update(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The platform the worker was built for, as a manifest names it.
    fn platform() -> String {
        format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    }

    fn summary(loaded: &Loaded) -> String {
        let (terminal, work) = (loaded.terminal, loaded.work);
        let campaign = campaign(loaded);
        let counts = counts(loaded);
        let class = terminal_text(terminal);
        // A bundle that ends before its terminal's checkpoint records no
        // work, so its work fields print `unavailable`.
        let recorded = terminal != Terminal::Infrastructure(Infrastructure::Truncated);
        let work_text = |value: u64| {
            if recorded {
                value.to_string()
            } else {
                "unavailable".to_owned()
            }
        };
        let mut out = format!(
            "digest: {}\ndecisions: {}\nterminal: {class}\ncounts: {counts}\nturns: {}\nprogress: {}\nvirtual_us: {}\nskipped_us: {}\n",
            hex(&loaded.digest),
            work_text(work.decisions),
            work_text(work.turns),
            work_text(work.progress),
            work_text(work.virtual_us),
            work_text(work.skipped_us),
        );
        out.push_str(&observed_lines(loaded, counts, campaign));
        if let Some(identity) = violated(loaded) {
            out.push_str(&format!("identity: {}\n", hex(identity.bytes())));
        }
        match campaign {
            Some(Campaign::Credited) => out.push_str("ledger: credited\n"),
            Some(Campaign::Inconclusive(gap)) => {
                out.push_str(&format!("ledger: inconclusive {gap:?}\n"));
            }
            Some(Campaign::Refused(error)) => out.push_str(&format!("ledger: refused {error:?}\n")),
            Some(Campaign::Unrecorded) => out.push_str("ledger: unrecorded\n"),
            Some(Campaign::Mismatched(mismatch)) => {
                out.push_str(&format!("ledger: mismatched {mismatch:?}\n"));
            }
            None => {}
        }
        if let Some(([planned, reached, activated, recovered, checked, skipped], rows)) =
            recovery_census(loaded)
        {
            out.push_str(&format!(
                "stages: planned={planned} reached={reached} activated={activated} recovered={recovered} checked={checked} skipped={skipped}\nlimits: {LIMITS}\nwindows:"
            ));
            for row in rows {
                use std::fmt::Write as _;
                write!(out, " {}=", row.name).expect("writing to a string");
                match row.status {
                    Status::Covered | Status::Gap => {
                        write!(out, "{}", row.count).expect("writing to a string")
                    }
                    Status::NotRequired | Status::Undecided | Status::Unreached => {
                        out.push_str("unplanned")
                    }
                }
            }
            out.push('\n');
        }
        out
    }

    /// The summary's version line, the inputs the recorded manifest
    /// declared, and what the run observed, each field `unavailable` where
    /// the bundle records no value for it, then the cause of a run that
    /// does not count and the rule of its first unsuccessful check when
    /// that rule is printable ASCII within the payload, where `counts` and
    /// `campaign` are the bundle's.
    ///
    /// Observed counts print only beside a stop event naming a mixed or
    /// cluster world: a bundle without one may hold only a prefix of its
    /// events. A scripted history's steps record no action, so its
    /// operations and witnesses print `unavailable`. The profile prints only
    /// as a listed name, so recorded text never forges a summary line. A
    /// listed cluster profile's summary prints `topology` and `coverage`
    /// from its coverage event beside its stop event, and `unavailable` for
    /// both when either event is absent.
    fn observed_lines(loaded: &Loaded, counts: bool, campaign: Option<Campaign>) -> String {
        use crate::net::world_tests::catalog;
        let declared = crate::net::world_tests::replay::manifest_of(loaded).ok();
        let seen = observed(&loaded.events);
        let unavailable = || "unavailable".to_owned();
        let profile = declared
            .as_ref()
            .map(|manifest| manifest.profile.as_str())
            .filter(|profile| catalog::listed(profile));
        let mut out = format!(
            "summary: {SUMMARY}\nprofile: {}\n",
            profile.map_or_else(unavailable, str::to_owned)
        );
        for key in ["turns", "same_time", "no_progress"] {
            let value = declared
                .as_ref()
                .map_or_else(unavailable, |manifest| manifest.count(key).to_string());
            out.push_str(&format!("declared_{key}: {value}\n"));
        }
        let composed = seen.composed;
        let counted = |value: u64| composed.map_or_else(unavailable, |_| value.to_string());
        let scripted = profile.and_then(catalog::class) == Some(catalog::Class::History);
        let acted = |value: u64| {
            if scripted {
                unavailable()
            } else {
                counted(value)
            }
        };
        out.push_str(&format!(
            "stop: {}\nboundaries_checked: {}\noperations: {}\nwitnesses: {}\nfaults_delivered: {}\nowners: {}\nclients: {}\nincarnations: unavailable\nretained_depth: unavailable\n",
            seen.stop_text(),
            composed.map_or_else(unavailable, |composed| composed.checked.to_string()),
            acted(seen.operations),
            acted(seen.witnesses),
            counted(seen.faults),
            composed.map_or_else(unavailable, |composed| composed.owners.to_string()),
            composed.map_or_else(unavailable, |composed| composed.clients.to_string()),
        ));
        if profile.is_some_and(|profile| cluster::shape(profile).is_some()) {
            let coverage = composed.and(seen.coverage);
            let topology = coverage.map_or_else(unavailable, |(topology, _)| {
                let cluster::Topology { owners, keys, hot } = topology;
                format!("owners={owners} keys={keys} hot={hot}")
            });
            let counts = coverage.map_or_else(unavailable, |(_, reached)| {
                Reached::NAMES
                    .iter()
                    .zip(reached)
                    .map(|(name, count)| format!("{name}={count}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            });
            out.push_str(&format!(
                "topology: {topology}\ncoverage: {counts}\nunavailable: {}\n",
                cluster::UNAVAILABLE
            ));
        }
        if !counts {
            out.push_str(&format!("cause: {}\n", cause(loaded, campaign, &seen)));
            if let Some(rule) = unsuccessful_rule(loaded) {
                out.push_str(&format!("unsuccessful: {rule}\n"));
            }
        }
        out
    }

    /// Why `loaded`, a bundle that does not count, earns no credit, given
    /// its `campaign` verdict and what its events record.
    fn cause(loaded: &Loaded, campaign: Option<Campaign>, seen: &Observed) -> String {
        let stop = seen.stop_text();
        let (fired, required, outcome) = match loaded.terminal {
            Terminal::Infrastructure(_) => return format!("{}, stop {stop}", claimed(loaded)),
            Terminal::Complete {
                outcome,
                fired,
                required,
            } => (fired, required, outcome),
        };
        match outcome {
            Outcome::Pass if required == 0 => "no required obligation".to_owned(),
            Outcome::Pass if fired & required != required => {
                format!("required obligations {required:02x} fired {fired:02x}")
            }
            // A pass firing every required obligation counts unless its
            // campaign verdict withholds credit, so the verdict is present.
            Outcome::Pass => format!(
                "the campaign ledger is {:?}",
                campaign.expect("a pass that does not count carries a campaign verdict")
            ),
            Outcome::Violation => with_breach("violation".to_owned(), loaded),
            Outcome::Inconclusive => match campaign {
                Some(Campaign::Inconclusive(gap)) => {
                    format!("inconclusive, ledger {gap:?}, stop {stop}")
                }
                _ if seen.observations > 0 => {
                    format!("inconclusive, an oracle observation recorded, stop {stop}")
                }
                _ => format!("inconclusive, stop {stop}"),
            },
            Outcome::Unsuccessful => "unsuccessful".to_owned(),
        }
    }

    fn code(loaded: &Loaded) -> i32 {
        match loaded.terminal {
            _ if counts(loaded) => COUNTS,
            Terminal::Complete { .. } => COMPLETE,
            Terminal::Infrastructure(_) => INCOMPLETE,
        }
    }

    /// Checks that `manifest`, the one `subject` (`manifest` or `bundle`)
    /// names, pins this executable and platform. Returns the exit code
    /// otherwise: incomplete evidence when the worker cannot read its own
    /// executable, a refusal for a pin naming another executable or
    /// platform.
    fn pinned_here(manifest: &Manifest, subject: &str, err: &mut impl Write) -> Result<(), i32> {
        pin_check(own_digest(), manifest, subject, err)
    }

    /// [`pinned_here`] over `digest`, the worker's reading of its own
    /// executable.
    fn pin_check(
        digest: Result<String, String>,
        manifest: &Manifest,
        subject: &str,
        err: &mut impl Write,
    ) -> Result<(), i32> {
        let digest = digest.map_err(|reason| {
            complain(err, &format!("the worker cannot read itself: {reason}"));
            INCOMPLETE
        })?;
        if digest != manifest.executable {
            let pinned = &manifest.executable;
            let reason = format!("the {subject} pins executable {pinned}; this worker is {digest}");
            return Err(refused(err, &reason));
        }
        if manifest.platform != platform() {
            let named = &manifest.platform;
            let reason = format!(
                "the {subject} names platform {named}; this worker is {}",
                platform()
            );
            return Err(refused(err, &reason));
        }
        Ok(())
    }

    /// Runs `manifest` into the new bundle at `path`. The manifest must pin
    /// this executable and platform and fit its run, and the bundle path
    /// must not exist; a worker that cannot read its own executable, or a
    /// bundle the host cannot create, reports incomplete evidence. The exit
    /// code is the terminal's once the written bundle loads to the
    /// terminal, digest and work the run recorded; otherwise the evidence
    /// is incomplete.
    fn record(manifest: &Manifest, path: &str, out: &mut impl Write, err: &mut impl Write) -> i32 {
        if let Err(code) = pinned_here(manifest, "manifest", err) {
            return code;
        }
        let admitted = match admit(manifest) {
            Ok(admitted) => admitted,
            Err(refusal) => return refused(err, &format!("{refusal:?}")),
        };
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return refused(err, &format!("bundle {path}: {error}"));
            }
            Err(error) => return host(err, &error, format!("bundle {path}")),
        };
        recorded_into(manifest, admitted, file, path, out, err)
    }

    /// Runs the manifest at `args[0]` once for each root read from
    /// `roots`, one root per line in the form a manifest holds, with the
    /// manifest's `root` replaced by it. The manifest must pin this
    /// executable and platform; the pin is checked once, and the worker
    /// then prints `sweep: ready`, so a reader can tell a worker that
    /// refused its command line or manifest from one that ended during a
    /// run. Each run records its bundle in memory and
    /// prints one block: `root`, the exit `code` a `--manifest` run of the
    /// same manifest returns, the summary that run prints, and `end`
    /// naming the root again. In place of a summary, a run that panics
    /// prints its `run` line, a manifest admission refuses prints a
    /// `refused` line, and a bundle that does not load prints a `load`
    /// line. The worker flushes each block before it reads the next root.
    /// It returns 0 at the end of `roots`, the refusal code for a command
    /// line, manifest or root it refuses, the incomplete-evidence code for
    /// a host read that fails, and 101 for a line it cannot write.
    fn sweep_into(
        args: &[String],
        roots: &mut impl std::io::BufRead,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> i32 {
        let [path] = args else {
            return refused(err, "--sweep takes one manifest");
        };
        let text = match read_manifest(path.as_ref(), &format!("manifest {path}"), err) {
            Ok(text) => text,
            Err(code) => return code,
        };
        let mut manifest = match Manifest::parse(&text) {
            Ok(manifest) => manifest,
            Err(error) => return refused(err, &format!("manifest {path}: {error:?}")),
        };
        if let Err(code) = pinned_here(&manifest, "manifest", err) {
            return code;
        }
        if finish(out, "sweep: ready\n", COUNTS) != COUNTS {
            return 101;
        }
        let mut line = String::new();
        loop {
            line.clear();
            match roots.read_line(&mut line) {
                Ok(0) => return COUNTS,
                Ok(_) => {}
                Err(error) => return host(err, &error, "the root list".to_owned()),
            }
            let listed = line.strip_suffix('\n').unwrap_or(&line);
            let Some(root) = crate::sim::manifest::counted("root", listed) else {
                return refused(err, &format!("root {listed:?} is no root a manifest holds"));
            };
            manifest.root = root;
            let (code, lines) = swept(&manifest);
            let block = format!("root: {root}\ncode: {code}\n{lines}end: {root}\n");
            if finish(out, &block, COUNTS) != COUNTS {
                return 101;
            }
        }
    }

    /// One run of `manifest` into memory: the exit code and summary lines
    /// of a `--manifest` run whose bundle holds the same bytes.
    fn swept(manifest: &Manifest) -> (i32, String) {
        let admitted = match admit(manifest) {
            Ok(admitted) => admitted,
            Err(refusal) => return (REFUSED, format!("refused: {refusal:?}\n")),
        };
        let closed = match crate::sim::unwind::caught(|| traced(admitted, Vec::new())) {
            Ok(closed) => closed,
            Err(panic) => return (INCOMPLETE, format!("run: {}\n", Identity::Panic(panic))),
        };
        let max = manifest.capacity().records();
        match read(closed.sink.as_slice(), max).map(|bytes| load(&bytes, max)) {
            Ok(Ok(loaded)) => {
                let agrees = (loaded.terminal, loaded.digest, loaded.work)
                    == (closed.terminal, closed.digest, closed.work);
                let code = if agrees { code(&loaded) } else { INCOMPLETE };
                (code, summary(&loaded))
            }
            Ok(Err(error)) => (INCOMPLETE, format!("load: {error:?}\n")),
            Err(error) => (INCOMPLETE, format!("load: {error}\n")),
        }
    }

    /// A fresh worker in `--sweep` mode prints its ready line and then, for
    /// each root it reads, the exit code and the summary a fresh
    /// `--manifest` run of the manifest at that root prints, a repeated
    /// root included, and exits 0 at the end of its roots. A root a
    /// manifest cannot hold, such as a word, zero or a padded count, is
    /// refused after the blocks of the roots before it.
    fn a_sweep_prints_each_roots_manifest_run() -> Result<(), String> {
        use std::process::Stdio;
        let scratch = Scratch::new("sim-sweep")?;
        let text = upload_manifest(&own_digest()?);
        let manifest = scratch.dir.join("sweep.manifest");
        std::fs::write(&manifest, &text).map_err(|error| error.to_string())?;
        let sweep = |roots: &str| -> Result<std::process::Output, String> {
            let mut child = scratch
                .command()
                .arg("--sweep")
                .arg(&manifest)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|error| error.to_string())?;
            let mut input = child.stdin.take().ok_or("the sweep has no stdin")?;
            input
                .write_all(roots.as_bytes())
                .map_err(|error| error.to_string())?;
            drop(input);
            child.wait_with_output().map_err(|error| error.to_string())
        };
        let mut expected = String::from("sweep: ready\n");
        for (index, root) in [3, 4, 3].into_iter().enumerate() {
            let rooted = text.replace("root = 3", &format!("root = {root}"));
            let run = scratch.record(&format!("sweep-{index}"), &rooted)?;
            let code = run.status.code().ok_or("a manifest run was signalled")?;
            expected.push_str(&format!(
                "root: {root}\ncode: {code}\n{}end: {root}\n",
                String::from_utf8_lossy(&run.stdout)
            ));
        }
        let swept = sweep("3\n4\n3\n")?;
        let printed = String::from_utf8_lossy(&swept.stdout);
        if swept.status.code() != Some(COUNTS) || printed != expected {
            return Err(format!(
                "the sweep exited {:?} and printed {printed}, not {expected}",
                swept.status.code()
            ));
        }
        for unlisted in ["four", "0", "04"] {
            let refused = sweep(&format!("4\n{unlisted}\n"))?;
            let printed = String::from_utf8_lossy(&refused.stdout);
            if refused.status.code() != Some(REFUSED)
                || !printed.starts_with("sweep: ready\nroot: 4\n")
                || !printed.ends_with("end: 4\n")
            {
                return Err(format!(
                    "the root {unlisted} exited {:?} after {printed}",
                    refused.status.code()
                ));
            }
        }
        // A manifest that pins another executable is refused before the
        // ready line.
        std::fs::write(&manifest, upload_manifest(&"0".repeat(64)))
            .map_err(|error| error.to_string())?;
        let unpinned = sweep("3\n")?;
        if unpinned.status.code() == Some(COUNTS) || !unpinned.stdout.is_empty() {
            return Err(format!(
                "a manifest pinning another executable exited {:?} and printed {}",
                unpinned.status.code(),
                String::from_utf8_lossy(&unpinned.stdout)
            ));
        }
        Ok(())
    }

    /// A bundle sink whose failure survives the run's unwind.
    struct Noted<'f, W> {
        sink: W,
        failed: &'f Cell<bool>,
    }

    impl<W: Write> Write for Noted<'_, W> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.sink
                .write(bytes)
                .inspect_err(|_| self.failed.set(true))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.sink.flush().inspect_err(|_| self.failed.set(true))
        }
    }

    fn recorded_into(
        manifest: &Manifest,
        admitted: Admitted<'_>,
        sink: impl Write,
        path: &str,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> i32 {
        let failed = Cell::new(false);
        let noted = Noted {
            sink,
            failed: &failed,
        };
        let closed = match crate::sim::unwind::caught(|| traced(admitted, noted)) {
            Ok(closed) => closed,
            Err(panic) if failed.get() => {
                let panic = Identity::Panic(panic);
                complain(err, &format!("bundle {path}: a write failed, and {panic}"));
                return INCOMPLETE;
            }
            // The bundle keeps every record before the panic.
            Err(panic) => {
                return finish(
                    out,
                    &format!("run: {}\n", Identity::Panic(panic)),
                    INCOMPLETE,
                );
            }
        };
        match reload(manifest, path) {
            Ok(loaded)
                if (loaded.terminal, loaded.digest, loaded.work)
                    == (closed.terminal, closed.digest, closed.work) =>
            {
                let summary = summary(&loaded);
                finish(out, &summary, code(&loaded))
            }
            Ok(loaded) => {
                complain(
                    err,
                    &format!("bundle {path} loads as {:?}", loaded.terminal),
                );
                let summary = summary(&loaded);
                finish(out, &summary, INCOMPLETE)
            }
            Err(unloaded) => {
                complain(err, &unloaded.reason(path));
                INCOMPLETE
            }
        }
    }

    /// Why [`reload`] produced no bundle: the host's read failed, or the
    /// bytes read do not load.
    enum Unloaded {
        Read(std::io::Error),
        Load(crate::sim::trace::LoadError),
    }

    impl Unloaded {
        /// The failure as a complaint about the bundle at `path`.
        fn reason(&self, path: &str) -> String {
            match self {
                Self::Read(error) => format!("bundle {path}: {error}"),
                Self::Load(error) => format!("bundle {path}: {error:?}"),
            }
        }
    }

    /// The bundle at `path`, loaded under `manifest`'s record maximum.
    fn reload(manifest: &Manifest, path: &str) -> Result<Loaded, Unloaded> {
        let max = manifest.capacity().records();
        let bytes = std::fs::File::open(path)
            .and_then(|file| read(file, max))
            .map_err(Unloaded::Read)?;
        load(&bytes, max).map_err(Unloaded::Load)
    }

    /// Refuses a `manifest` that pins another executable or platform, then
    /// loads the bundle at `path` under `manifest`'s record maximum and
    /// reports it when `manifest` is the one it recorded. A worker that
    /// cannot read its own executable or a bundle the host cannot read
    /// reports incomplete evidence; a missing bundle is refused.
    fn inspect(manifest: &Manifest, path: &str, out: &mut impl Write, err: &mut impl Write) -> i32 {
        if let Err(code) = pinned_here(manifest, "manifest", err) {
            return code;
        }
        let loaded = match reload(manifest, path) {
            Ok(loaded) => loaded,
            Err(Unloaded::Read(error)) if error.kind() != std::io::ErrorKind::NotFound => {
                return host(err, &error, format!("bundle {path}"));
            }
            Err(unloaded) => return refused(err, &unloaded.reason(path)),
        };
        let recorded = loaded
            .fields
            .iter()
            .find(|(field, _)| *field == Field::Manifest)
            .map(|(_, bytes)| bytes.as_slice());
        if recorded != Some(manifest.canonical().as_bytes()) {
            return refused(
                err,
                &format!("bundle {path} was recorded under another manifest"),
            );
        }
        let summary = summary(&loaded);
        finish(out, &summary, 0)
    }

    /// A cluster bundle's summary prints the topology and coverage its
    /// coverage event recorded beside its stop event; a bundle missing its
    /// stop event, or both events as a record cap leaves it, prints both
    /// `unavailable`, as it does every other observed count. Another
    /// profile's bundle prints no cluster lines, a coverage event included.
    fn coverage_needs_a_stop() -> Result<(), String> {
        let traced_at = |profile: &str| {
            let text = crate::sim::manifest_tests::sample(profile, &"a".repeat(64), &platform())
                .replace("root = 3", "root = 7");
            let manifest = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
            let admitted = admit(&manifest).map_err(|refusal| format!("{refusal:?}"))?;
            let closed = traced(admitted, Vec::new());
            load(&closed.sink, manifest.capacity().records()).map_err(|e| format!("{e:?}"))
        };
        let mut loaded = traced_at("cluster-broad")?;
        let complete = summary(&loaded);
        let (expected, topology) = cluster_lines(&loaded)?;
        if !complete.contains(&expected) {
            return Err(format!("the complete bundle printed {complete}"));
        }
        let unavailable = format!(
            "\ntopology: unavailable\ncoverage: unavailable\nunavailable: {}\n",
            cluster::UNAVAILABLE
        );
        loaded
            .events
            .retain(|event| event.kind != crate::net::world_tests::bundle::STOP);
        let stopless = summary(&loaded);
        if !stopless.contains(&unavailable) || !stopless.contains("\nowners: unavailable\n") {
            return Err(format!("the stopless bundle printed {stopless}"));
        }
        loaded
            .events
            .retain(|event| event.kind != cluster::COVERAGE);
        let cut = summary(&loaded);
        if !cut.contains(&unavailable) {
            return Err(format!("the bundle without its last events printed {cut}"));
        }
        let mut mixed = traced_at("upload")?;
        mixed
            .events
            .push(cluster::coverage_event(topology, &Reached::default()));
        let printed = summary(&mixed);
        if printed.contains("\ntopology: ") || printed.contains("\ncoverage: ") {
            return Err(format!("the upload bundle printed {printed}"));
        }
        Ok(())
    }

    /// The topology, coverage and unavailable lines a cluster bundle's
    /// summary prints, built from the bundle's own coverage event, and the
    /// topology that event recorded.
    fn cluster_lines(loaded: &Loaded) -> Result<(String, cluster::Topology), String> {
        let (topology, reached) = observed(&loaded.events)
            .coverage
            .ok_or_else(|| "the cluster bundle holds no coverage event".to_owned())?;
        let cluster::Topology { owners, keys, hot } = topology;
        let counts: Vec<String> = Reached::NAMES
            .iter()
            .zip(reached)
            .map(|(name, count)| format!("{name}={count}"))
            .collect();
        let lines = format!(
            "\ntopology: owners={owners} keys={keys} hot={hot}\ncoverage: {}\nunavailable: {}\n",
            counts.join(" "),
            cluster::UNAVAILABLE
        );
        Ok((lines, topology))
    }

    /// A run manifest of the upload profile pinning `executable` on this
    /// worker's platform.
    pub(super) fn upload_manifest(executable: &str) -> String {
        crate::sim::manifest_tests::sample("upload", executable, &platform())
    }

    /// The worker prints these keys first, in this order, in every summary.
    const SUMMARY_KEYS: [&str; 22] = [
        "digest",
        "decisions",
        "terminal",
        "counts",
        "turns",
        "progress",
        "virtual_us",
        "skipped_us",
        "summary",
        "profile",
        "declared_turns",
        "declared_same_time",
        "declared_no_progress",
        "stop",
        "boundaries_checked",
        "operations",
        "witnesses",
        "faults_delivered",
        "owners",
        "clients",
        "incarnations",
        "retained_depth",
    ];

    /// The summary keys a bundle without a stop event naming a mixed world
    /// prints as `unavailable`.
    const OBSERVED_KEYS: [&str; 6] = [
        "boundaries_checked",
        "operations",
        "witnesses",
        "faults_delivered",
        "owners",
        "clients",
    ];

    /// The value `fields`, a summary's [`summary_fields`], holds for `key`.
    fn summary_value<'s>(fields: &[(&'s str, &'s str)], key: &str) -> Option<&'s str> {
        fields
            .iter()
            .find(|(known, _)| *known == key)
            .map(|(_, value)| *value)
    }

    /// `summary_fields` requires unique keys so prefix-based lookups
    /// select an unambiguous value.
    fn summary_fields(printed: &str) -> Result<Vec<(&str, &str)>, String> {
        let mut fields: Vec<(&str, &str)> = Vec::new();
        for line in printed.lines() {
            let Some((key, value)) = line.split_once(": ") else {
                return Err(format!("the summary line {line:?} is no key and value"));
            };
            if fields.iter().any(|(known, _)| *known == key) {
                return Err(format!("the summary prints {key} twice: {printed}"));
            }
            fields.push((key, value));
        }
        Ok(fields)
    }

    /// Two fresh worker processes run one upload manifest into two bundles,
    /// one with an empty environment, the other from the root directory;
    /// both load with one digest, one decision count and one counting
    /// result, and inspecting one reports that digest and result. A third
    /// run onto an existing bundle and a run under a manifest pinning
    /// another executable are refused, the stored bundle stays
    /// byte-for-byte, and a copy with one byte changed, or the bundle under
    /// another manifest, one differing only in its build pin included, is
    /// refused on inspection. The summary prints its keys in order, its
    /// format, profile and stop, the work and the observed counts the
    /// bundle decodes to, and its topology, and no cause and no identity. A
    /// run whose record maximum it outgrows exits with incomplete evidence,
    /// and its bundle inspects as capped, naming its cause and printing
    /// every observed count as unavailable and its work as recorded. A
    /// manifest naming another platform is refused by both the run and the
    /// inspection, a worker unable to read its own executable reports
    /// incomplete evidence, and a bundle path the host cannot create or
    /// read is incomplete evidence while a missing one is refused. The
    /// executable's path locates the worker and its scratch directory for
    /// this check alone; no decision reads it. The case ends by recording
    /// one `contended` bundle in two fresh processes and replaying it in a
    /// third.
    fn two_bundles() -> Result<(), String> {
        let scratch = Scratch::new("sim-bundles")?;
        let (worker, dir) = (&scratch.worker, &scratch.dir);
        let executable = own_digest()?;
        let whole = std::fs::read(worker).map_err(|error| error.to_string())?;
        let oneshot = hex(&<sha2::Sha256 as sha2::Digest>::digest(&whole));
        drop(whole);
        if executable != oneshot {
            return Err(format!(
                "the worker reads its digest as {executable}, its file hashes to {oneshot}"
            ));
        }
        let manifest = dir.join("run.manifest");
        std::fs::write(&manifest, upload_manifest(&executable)).map_err(|e| e.to_string())?;
        let run = |bundle: &std::path::Path, clear: bool, manifest: &std::path::Path| {
            let mut command = std::process::Command::new(worker);
            if clear {
                command.env_clear();
            } else {
                command.current_dir("/");
            }
            command
                .arg("--manifest")
                .arg(manifest)
                .arg("--bundle")
                .arg(bundle)
                .output()
                .map_err(|error| error.to_string())
        };
        let mut loaded = Vec::new();
        for (at, clear) in [true, false].into_iter().enumerate() {
            let bundle = dir.join(format!("run-{at}.bundle"));
            let ran = run(&bundle, clear, &manifest)?;
            if ran.status.code() != Some(COUNTS) {
                return Err(format!(
                    "run {at} exited {}: {}{}",
                    ran.status,
                    String::from_utf8_lossy(&ran.stdout),
                    String::from_utf8_lossy(&ran.stderr)
                ));
            }
            let bytes = std::fs::read(&bundle).map_err(|error| error.to_string())?;
            let decoded = load(&bytes, 1_000_000).map_err(|error| format!("{error:?}"))?;
            loaded.push((bytes, decoded));
        }
        let ((first_bytes, first), (_, second)) = (&loaded[0], &loaded[1]);
        let identity = |bundle: &Loaded| (bundle.digest, bundle.decisions, bundle.terminal);
        if identity(first) != identity(second) || !first.terminal.counts() {
            return Err(format!(
                "{:?} against {:?}",
                identity(first),
                identity(second)
            ));
        }
        let stored = dir.join("run-0.bundle");
        let again = run(&stored, true, &manifest)?;
        let unchanged = std::fs::read(&stored).map_err(|error| error.to_string())?;
        if again.status.code() != Some(REFUSED) || unchanged != *first_bytes {
            return Err(format!(
                "a run onto a stored bundle exited {}",
                again.status
            ));
        }
        let inspect = |bundle: &std::path::Path, manifest: &std::path::Path| {
            std::process::Command::new(worker)
                .env_clear()
                .arg("--inspect")
                .arg(bundle)
                .arg("--manifest")
                .arg(manifest)
                .output()
                .map_err(|error| error.to_string())
        };
        let inspected = inspect(&stored, &manifest)?;
        let printed = String::from_utf8_lossy(&inspected.stdout).into_owned();
        let digest = format!("digest: {}\n", hex(&first.digest));
        if inspected.status.code() != Some(0) || !printed.starts_with(&digest) {
            return Err(format!("inspect exited {}: {printed}", inspected.status));
        }
        let work = first.work;
        let seen = observed(&first.events);
        let composed = seen.composed.ok_or("the upload recorded no composition")?;
        let fields = summary_fields(&printed)?;
        let keys: Vec<&str> = fields.iter().map(|(key, _)| *key).collect();
        let value = |key: &str| summary_value(&fields, key);
        if keys != SUMMARY_KEYS
            || value("counts") != Some("true")
            || !value("terminal").is_some_and(|terminal| terminal.starts_with("complete pass "))
        {
            return Err(format!("the summary prints {printed}"));
        }
        for (key, expected) in [
            ("decisions", work.decisions),
            ("turns", work.turns),
            ("progress", work.progress),
            ("virtual_us", work.virtual_us),
            ("skipped_us", work.skipped_us),
            ("declared_turns", 20_000),
            ("declared_same_time", 400),
            ("declared_no_progress", 5_000),
            ("boundaries_checked", composed.checked),
            ("operations", seen.operations),
            ("witnesses", seen.witnesses),
        ] {
            if value(key) != Some(expected.to_string().as_str()) {
                return Err(format!(
                    "the summary prints {key} {:?}, not {expected}",
                    value(key)
                ));
            }
        }
        let summary_text = SUMMARY.to_string();
        for (key, expected) in [
            ("summary", summary_text.as_str()),
            ("profile", "upload"),
            ("stop", "goal"),
            ("faults_delivered", "0"),
            ("owners", "1"),
            ("clients", "2"),
            ("incarnations", "unavailable"),
            ("retained_depth", "unavailable"),
        ] {
            if value(key) != Some(expected) {
                return Err(format!(
                    "the summary prints {key} {:?}: {printed}",
                    value(key)
                ));
            }
        }
        if composed.checked == 0 || seen.witnesses == 0 || seen.operations <= seen.witnesses {
            return Err(format!("the summary counts no observed work: {printed}"));
        }
        let ended = |outcome: Outcome, fired: u8, required: u8, observations: u64| {
            let mut loaded = first.clone();
            loaded.terminal = Terminal::Complete {
                outcome,
                fired,
                required,
            };
            loaded
                .events
                .extend((0..observations).map(|_| crate::sim::trace::Event {
                    kind: OBSERVED,
                    payload: [0; crate::sim::trace::PAYLOAD],
                }));
            loaded
        };
        for (loaded, expected) in [
            (ended(Outcome::Pass, 0, 0, 0), "no required obligation"),
            (
                ended(Outcome::Pass, 0x01, 0x03, 0),
                "required obligations 03 fired 01",
            ),
            (
                ended(Outcome::Inconclusive, 0x03, 0x03, 1),
                "inconclusive, an oracle observation recorded, stop goal",
            ),
            (
                ended(Outcome::Inconclusive, 0x03, 0x03, 0),
                "inconclusive, stop goal",
            ),
            (ended(Outcome::Unsuccessful, 0x03, 0x03, 0), "unsuccessful"),
        ] {
            let printed = summary(&loaded);
            if summary_value(&summary_fields(&printed)?, "cause") != Some(expected) {
                return Err(format!("a summary lacks the cause {expected:?}: {printed}"));
            }
        }
        let withheld = cause(
            &ended(Outcome::Pass, 0x03, 0x03, 0),
            Some(Campaign::Unrecorded),
            &seen,
        );
        if withheld != "the campaign ledger is Unrecorded" {
            return Err(format!("a withheld pass names its cause as {withheld:?}"));
        }
        let mut changed = first_bytes.clone();
        changed[60] ^= 1;
        let flipped = dir.join("flipped.bundle");
        std::fs::write(&flipped, &changed).map_err(|error| error.to_string())?;
        let rejected = inspect(&flipped, &manifest)?;
        if rejected.status.code() != Some(REFUSED) {
            return Err(format!(
                "a changed bundle inspected with {}",
                rejected.status
            ));
        }
        let beneath = stored.join("out");
        let under_file = run(&beneath, true, &manifest)?;
        let kept = std::fs::read(&stored).map_err(|error| error.to_string())?;
        let as_directory = inspect(dir, &manifest)?;
        let missing = inspect(&dir.join("absent.bundle"), &manifest)?;
        for (case, ran, code) in [
            ("a run beneath a file", &under_file, INCOMPLETE),
            ("a directory inspected", &as_directory, INCOMPLETE),
            ("a missing bundle inspected", &missing, REFUSED),
        ] {
            if ran.status.code() != Some(code) || !ran.stdout.is_empty() || kept != *first_bytes {
                return Err(format!("{case} exited {}", ran.status));
            }
        }
        let small = dir.join("small.manifest");
        let capped_text =
            upload_manifest(&executable).replace("records = 1000000", "records = 200");
        std::fs::write(&small, capped_text).map_err(|e| e.to_string())?;
        let short = dir.join("short.bundle");
        let ran = run(&short, true, &small)?;
        let printed = String::from_utf8_lossy(&ran.stdout).into_owned();
        if ran.status.code() != Some(INCOMPLETE)
            || !printed.contains("terminal: infrastructure cap")
        {
            return Err(format!("a capped run exited {}: {printed}", ran.status));
        }
        let reread = inspect(&short, &small)?;
        let summary = String::from_utf8_lossy(&reread.stdout).into_owned();
        let capped = summary_fields(&summary)?;
        // A capped bundle still records its terminal's work.
        let short_bytes = std::fs::read(&short).map_err(|error| error.to_string())?;
        let short_work = load(&short_bytes, 200)
            .map_err(|error| format!("{error:?}"))?
            .work;
        let (decisions, turns) = (
            short_work.decisions.to_string(),
            short_work.turns.to_string(),
        );
        let unexpected = [
            ("terminal", "infrastructure cap"),
            ("counts", "false"),
            ("cause", "infrastructure cap, stop unavailable"),
            ("decisions", decisions.as_str()),
            ("turns", turns.as_str()),
        ]
        .into_iter()
        .chain(OBSERVED_KEYS.map(|key| (key, "unavailable")))
        .any(|(key, value)| summary_value(&capped, key) != Some(value));
        if reread.status.code() != Some(0)
            || !capped
                .iter()
                .map(|(key, _)| *key)
                .eq(SUMMARY_KEYS.into_iter().chain(["cause"]))
            || unexpected
            || short_work.turns == 0
        {
            return Err(format!(
                "the capped bundle inspected with {}: {summary}",
                reread.status
            ));
        }
        let other = dir.join("other.manifest");
        std::fs::write(&other, upload_manifest(&"0".repeat(64))).map_err(|e| e.to_string())?;
        let rebuilt_pin = dir.join("rebuilt.manifest");
        let lines = crate::sim::manifest_tests::sample_lines("upload", &executable, &platform());
        let text = crate::sim::manifest_tests::edited(lines, &[("build", &"0".repeat(64))]);
        std::fs::write(&rebuilt_pin, text).map_err(|e| e.to_string())?;
        for (foreign, reason) in [
            (&other, "the manifest pins executable"),
            (&small, "TooMany"),
            (&rebuilt_pin, "was recorded under another manifest"),
        ] {
            let crossed = inspect(&stored, foreign)?;
            let error = String::from_utf8_lossy(&crossed.stderr);
            if crossed.status.code() != Some(REFUSED)
                || !crossed.stdout.is_empty()
                || !error.contains(reason)
            {
                return Err(format!(
                    "the bundle inspected under {} exited {}: {error}",
                    foreign.display(),
                    crossed.status
                ));
            }
        }
        let rebuilt = dir.join("rebuilt.bundle");
        let refused = run(&rebuilt, true, &other)?;
        if refused.status.code() != Some(REFUSED) || rebuilt.exists() {
            return Err(format!(
                "another executable's manifest exited {}",
                refused.status
            ));
        }
        let elsewhere = dir.join("elsewhere.manifest");
        let text = upload_manifest(&executable).replace(
            &format!("platform = {}\n", platform()),
            "platform = riscv64-none\n",
        );
        std::fs::write(&elsewhere, text).map_err(|e| e.to_string())?;
        let target = dir.join("elsewhere.bundle");
        for rejected in [
            run(&target, true, &elsewhere)?,
            inspect(&stored, &elsewhere)?,
        ] {
            if rejected.status.code() != Some(REFUSED)
                || !rejected.stdout.is_empty()
                || !String::from_utf8_lossy(&rejected.stderr)
                    .contains("the manifest names platform riscv64-none")
                || target.exists()
            {
                return Err(format!(
                    "a foreign-platform manifest exited {}",
                    rejected.status
                ));
            }
        }
        pin_checks_classify_their_failures(&executable)?;
        println!(
            "bundle: {} recorded alike by two fresh processes, complete pass with every obligation fired",
            hex(&first.digest)
        );
        armed_bundles_agree(&scratch, &executable)
    }

    /// Two fresh worker processes record one bundle of `contended` at a
    /// pinned root, a complete pass whose tape reaches every chaos point and
    /// fires `gate-busy` and `capture-busy` alone, and a third replays it to the
    /// same digest, decisions and terminal. A fired `exchange-lost` refuses
    /// the run's one upload, so a passing tape holds its unfired reach.
    fn armed_bundles_agree(scratch: &Scratch, executable: &str) -> Result<(), String> {
        let lines = crate::sim::manifest_tests::sample_lines("contended", executable, &platform());
        let root = crate::net::world_tests::bundle::chaos_tests::PUBLISHED.to_string();
        let text = crate::sim::manifest_tests::edited(lines, &[("root", &root)]);
        let requested = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        let mut loaded = Vec::new();
        for at in 0..2 {
            let name = format!("contended-{at}");
            let ran = scratch.record(&name, &text)?;
            if ran.status.code() != Some(COUNTS) {
                return Err(format!("{name} exited {}", ran.status));
            }
            let bundle = scratch.dir.join(format!("{name}.bundle"));
            let bytes = std::fs::read(&bundle).map_err(|error| error.to_string())?;
            let bundle = load(&bytes, 1_000_000).map_err(|error| format!("{error:?}"))?;
            let recorded = bundle
                .fields
                .iter()
                .find(|(field, _)| *field == Field::Manifest)
                .map(|(_, bytes)| bytes.as_slice());
            if recorded != Some(requested.canonical().as_bytes()) {
                return Err(format!("{name} was recorded under another manifest"));
            }
            if !bundle.terminal.counts() {
                return Err(format!("{name} ended {:?}", bundle.terminal));
            }
            loaded.push(bundle);
        }
        let identity = |bundle: &Loaded| (bundle.digest, bundle.decisions, bundle.terminal);
        if identity(&loaded[0]) != identity(&loaded[1]) {
            return Err(format!(
                "{:?} against {:?}",
                identity(&loaded[0]),
                identity(&loaded[1])
            ));
        }
        let census = crate::sim::chaos::census(&loaded[0].tape).ok_or("an unreadable tape")?;
        let fired = crate::net::world_tests::bundle::chaos_tests::FIRED_IN_A_PASS;
        for point in crate::sim::chaos::Point::ALL {
            let counts = census[point.at()];
            let expected = fired.contains(&point);
            if counts.reached == 0 || (counts.fired > 0) != expected {
                return Err(format!(
                    "the contended bundle reaches {} {} times and fires it {} times, where a pass {} it",
                    point.row().name,
                    counts.reached,
                    counts.fired,
                    if expected { "fires" } else { "never fires" }
                ));
            }
        }
        let (bundle, output) = (
            scratch.dir.join("contended-0.bundle"),
            scratch.dir.join("contended.replay"),
        );
        let replayed = scratch.run(&[
            "--replay".as_ref(),
            bundle.as_os_str(),
            "--output".as_ref(),
            output.as_os_str(),
        ])?;
        let printed = String::from_utf8_lossy(&replayed.stdout).into_owned();
        if replayed.status.code() != Some(REPRODUCED) || !printed.starts_with("replay: reproduced")
        {
            return Err(format!(
                "the contended bundle replayed {}: {printed}",
                replayed.status
            ));
        }
        let again =
            std::fs::read(output.join("replay.bundle")).map_err(|error| error.to_string())?;
        let again = load(&again, 1_000_000).map_err(|error| format!("{error:?}"))?;
        if identity(&again) != identity(&loaded[0]) {
            return Err(format!(
                "the replay bundle recorded {:?} against {:?}",
                identity(&again),
                identity(&loaded[0])
            ));
        }
        let digest = hex(&loaded[0].digest);
        let line = format!(
            "bundle: contended digest {digest} recorded alike by two fresh processes and replayed in a third, reaching every chaos point"
        );
        inventory_witnesses(&line, &digest)?;
        println!("{line}");
        Ok(())
    }

    /// Fails unless `scripts/test-inventory.json` lists, as one witness, the
    /// pattern that matches `line` whole with `digest` as 64 hexadecimal
    /// digits, so the lane's inventory credits the line this case prints.
    fn inventory_witnesses(line: &str, digest: &str) -> Result<(), String> {
        let witness = format!("\"^{}$\"", line.replace(digest, "[0-9a-f]{64}"));
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/test-inventory.json");
        let inventory = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if inventory.contains(&witness) {
            Ok(())
        } else {
            Err(format!("{} lists no witness {witness}", path.display()))
        }
    }

    /// A worker that cannot read its own executable reports incomplete
    /// evidence, a pin naming another executable is refused, and a pin
    /// naming this one passes without complaint.
    fn pin_checks_classify_their_failures(executable: &str) -> Result<(), String> {
        let pinned =
            Manifest::parse(&upload_manifest(executable)).map_err(|error| format!("{error:?}"))?;
        for (digest, expected, said) in [
            (
                Err("unreadable".to_owned()),
                Err(INCOMPLETE),
                "error: the worker cannot read itself: unreadable\n",
            ),
            (
                Ok("0".repeat(64)),
                Err(REFUSED),
                "error: the manifest pins executable ",
            ),
            (Ok(executable.to_owned()), Ok(()), ""),
        ] {
            let mut complaint = Vec::new();
            let checked = pin_check(digest, &pinned, "manifest", &mut complaint);
            let complaint = String::from_utf8_lossy(&complaint);
            let complained = if said.is_empty() {
                complaint.is_empty()
            } else {
                complaint.starts_with(said)
            };
            if checked != expected || !complained {
                return Err(format!("a pin check gave {checked:?}: {complaint}"));
            }
        }
        Ok(())
    }

    /// A recorded faulted upload's summary prints the nonzero faults its
    /// bundle records, and a clean upload's prints zero. Two fresh worker
    /// processes branch the faulted upload at its pending-PUT milestone:
    /// both exit 0, print one milestone, a `witness:` line on which the
    /// pending-PUT predicate holds, one parent reproduction and the same
    /// credited children, so a prefix replay in a fresh process
    /// reaches the same milestone, and each child's bundle stands in its
    /// output directory. The most identical siblings of one suffix the form
    /// accepts are all credited and each writes its bundle. A sibling count
    /// of zero, past the bound or not canonical, and siblings beside the
    /// explore form, are refused. An unknown milestone, a suffix count
    /// of zero or past the bound, an existing output directory and a bundle
    /// whose run never reaches the milestone are refused, and a refusal
    /// leaves no output directory behind. A bundle whose prefix replay
    /// diverges before the milestone is a complete branch that prints only
    /// the divergence and leaves no directory either. The executable's
    /// path locates the worker and its scratch directory for this check
    /// alone; no decision reads it.
    fn fresh_processes_branch_alike() -> Result<(), String> {
        let scratch = Scratch::new("sim-branches")?;
        let dir = &scratch.dir;
        let executable = own_digest()?;
        let run = |args: &[&std::ffi::OsStr]| scratch.run(args);
        let path = |name: &str| dir.join(name).into_os_string();
        for (profile, delivers) in [("faulted", true), ("upload", false)] {
            let text = crate::sim::manifest_tests::sample(profile, &executable, &platform());
            let manifest = format!("{profile}.manifest");
            std::fs::write(dir.join(&manifest), text).map_err(|e| e.to_string())?;
            let recorded = run(&[
                "--manifest".as_ref(),
                &path(&manifest),
                "--bundle".as_ref(),
                &path(&format!("{profile}.bundle")),
            ])?;
            if recorded.status.code() != Some(COUNTS) {
                return Err(format!("the {profile} run exited {}", recorded.status));
            }
            // The summary prints the faults the bundle's links delivered;
            // the faulted links deliver some, the clean ones none.
            let bytes = std::fs::read(dir.join(format!("{profile}.bundle")))
                .map_err(|error| error.to_string())?;
            let faults = observed(
                &load(&bytes, 1_000_000)
                    .map_err(|e| format!("{e:?}"))?
                    .events,
            )
            .faults;
            let printed = String::from_utf8_lossy(&recorded.stdout).into_owned();
            let faults_text = faults.to_string();
            if summary_value(&summary_fields(&printed)?, "faults_delivered") != Some(&faults_text)
                || (faults > 0) != delivers
            {
                return Err(format!("the {profile} run printed {printed}"));
            }
        }
        let branch = |bundle: &str, name: &str, suffixes: &str, output: &str| {
            run(&[
                "--branch".as_ref(),
                &path(bundle),
                "--milestone".as_ref(),
                name.as_ref(),
                "--suffixes".as_ref(),
                suffixes.as_ref(),
                "--output".as_ref(),
                &path(output),
            ])
        };
        let mut printed = Vec::new();
        for output in ["first", "second"] {
            let branched = branch("faulted.bundle", "pending-put", "2", output)?;
            let text = String::from_utf8_lossy(&branched.stdout).into_owned();
            let shaped = |line: &str| {
                let fields: Vec<&str> = line.splitn(6, ' ').collect();
                fields.len() == 6
                    && fields[0] == "child:"
                    && fields[1].starts_with("suffix=")
                    && fields[2].starts_with("sibling=")
                    && fields[3] == "class=success"
                    && fields[4]
                        .strip_prefix("digest=")
                        .is_some_and(|hex| hex.len() == 64)
                    && fields[5] == "terminal=complete pass fired=03 required=03"
            };
            let credited = text.lines().filter(|line| shaped(line)).count();
            if branched.status.code() != Some(COUNTS)
                || !text.contains("parent: reproduced\n")
                || !text.contains("\nwitness: pending-put holds=true boundary=")
                || credited != 2
                || !text.ends_with("branch: 2 children, 2 credited, 0 problems\n")
            {
                return Err(format!(
                    "branch {output} exited {}: {text}",
                    branched.status
                ));
            }
            for suffix in 0..2 {
                let name = format!("suffix-{suffix}-0.bundle");
                if !dir.join(output).join(&name).is_file() {
                    return Err(format!("{output} holds no {name}"));
                }
            }
            printed.push(text);
        }
        if printed[0] != printed[1] {
            return Err(format!("{} against {}", printed[0], printed[1]));
        }
        let siblings = |count: &str, output: &str| {
            run(&[
                "--branch".as_ref(),
                &path("faulted.bundle"),
                "--milestone".as_ref(),
                "pending-put".as_ref(),
                "--suffixes".as_ref(),
                "1".as_ref(),
                "--siblings".as_ref(),
                count.as_ref(),
                "--output".as_ref(),
                &path(output),
            ])
        };
        let branched = siblings(&MAX_SIBLINGS.to_string(), "siblings")?;
        let text = String::from_utf8_lossy(&branched.stdout).into_owned();
        if branched.status.code() != Some(COUNTS)
            || !text.contains("parent: reproduced\n")
            || !text.ends_with(&format!(
                "branch: {MAX_SIBLINGS} children, {MAX_SIBLINGS} credited, 0 problems\n"
            ))
        {
            return Err(format!("siblings exited {}: {text}", branched.status));
        }
        for sibling in 0..MAX_SIBLINGS {
            let child = format!("child: suffix=0 sibling={sibling} class=success ");
            let bundle = format!("suffix-0-{sibling}.bundle");
            if !text.contains(&child) || !dir.join("siblings").join(&bundle).is_file() {
                return Err(format!("sibling {sibling} is missing: {text}"));
            }
        }
        for count in ["0", "5", "01"] {
            let refusal = siblings(count, "no-siblings")?;
            let error = String::from_utf8_lossy(&refusal.stderr).into_owned();
            if refusal.status.code() != Some(REFUSED)
                || !error.contains(&format!("--siblings {count}"))
                || dir.join("no-siblings").exists()
            {
                return Err(format!(
                    "--siblings {count} exited {}: {error}",
                    refusal.status
                ));
            }
        }
        let explored = run(&[
            "--explore".as_ref(),
            &path("faulted.bundle"),
            "--milestone".as_ref(),
            "pending-put".as_ref(),
            "--siblings".as_ref(),
            "2".as_ref(),
            "--output".as_ref(),
            &path("explored"),
        ])?;
        if explored.status.code() != Some(REFUSED) || dir.join("explored").exists() {
            return Err(format!("--explore --siblings exited {}", explored.status));
        }
        for (bundle, name, suffixes, output, said) in [
            (
                "faulted.bundle",
                "elsewhere",
                "1",
                "unknown",
                "no milestone",
            ),
            ("faulted.bundle", "pending-put", "0", "none", "--suffixes 0"),
            (
                "faulted.bundle",
                "pending-put",
                "17",
                "many",
                "--suffixes 17",
            ),
            ("faulted.bundle", "pending-put", "1", "first", "output"),
            ("upload.bundle", "pending-put", "1", "never", "Predicate"),
        ] {
            let refused = branch(bundle, name, suffixes, output)?;
            let error = String::from_utf8_lossy(&refused.stderr).into_owned();
            if refused.status.code() != Some(REFUSED) || !error.contains(said) {
                return Err(format!(
                    "{name} {suffixes} into {output} exited {}: {error}",
                    refused.status
                ));
            }
            if output != "first" && dir.join(output).exists() {
                return Err(format!("the refused branch left {output} behind"));
            }
        }
        let recorded = std::fs::read(dir.join("faulted.bundle")).map_err(|e| e.to_string())?;
        std::fs::write(
            dir.join("diverging.bundle"),
            diverging_before(&recorded, "pending-put"),
        )
        .map_err(|e| e.to_string())?;
        let diverged = branch("diverging.bundle", "pending-put", "1", "diverged")?;
        let text = String::from_utf8_lossy(&diverged.stdout).into_owned();
        if diverged.status.code() != Some(COMPLETE)
            || text != "parent: diverged before the milestone\n"
            || dir.join("diverged").exists()
        {
            return Err(format!(
                "the diverging branch exited {}: {text}",
                diverged.status
            ));
        }
        Ok(())
    }

    /// Two fresh worker processes explore one recorded faulted upload's
    /// suffix tree from its pending-PUT milestone: both exit 0 and print
    /// one census, labelled composed-bounded, with the limits the manifest
    /// fixed, a `witness:` line on which the pending-PUT predicate holds,
    /// every node credited and a leaf bundle for each leaf line. Neither
    /// explore prints a nested fork refusal on stderr. A fresh worker running
    /// the composed-bounded case passes and prints its planted interior
    /// node's refusal on stderr. A bundle whose run never reaches the
    /// milestone, an unknown milestone and an existing output directory
    /// are refused. The executable's path locates the worker and its scratch
    /// directory for this check alone; no decision reads it.
    fn fresh_processes_explore_alike() -> Result<(), String> {
        let scratch = Scratch::new("sim-explores")?;
        let dir = &scratch.dir;
        let executable = own_digest()?;
        let run = |args: &[&std::ffi::OsStr]| scratch.run(args);
        let path = |name: &str| dir.join(name).into_os_string();
        for profile in ["faulted", "upload"] {
            let text = crate::sim::manifest_tests::sample(profile, &executable, &platform());
            let manifest = format!("{profile}.manifest");
            std::fs::write(dir.join(&manifest), text).map_err(|e| e.to_string())?;
            let recorded = run(&[
                "--manifest".as_ref(),
                &path(&manifest),
                "--bundle".as_ref(),
                &path(&format!("{profile}.bundle")),
            ])?;
            if recorded.status.code() != Some(COUNTS) {
                return Err(format!("the {profile} run exited {}", recorded.status));
            }
        }
        let explore = |bundle: &str, name: &str, output: &str| {
            run(&[
                "--explore".as_ref(),
                &path(bundle),
                "--milestone".as_ref(),
                name.as_ref(),
                "--output".as_ref(),
                &path(output),
            ])
        };
        let mut censuses = Vec::new();
        for output in ["first", "second"] {
            let explored = explore("faulted.bundle", "pending-put", output)?;
            let text = String::from_utf8_lossy(&explored.stdout).into_owned();
            let leaves: Vec<&str> = text
                .lines()
                .filter(|line| line.starts_with("leaf: "))
                .collect();
            let nodes: Vec<&str> = text
                .lines()
                .filter(|line| line.starts_with("node: "))
                .collect();
            let limits = "limits: depth=2 children=3 faults=12 advances=16\n";
            if explored.status.code() != Some(COUNTS)
                || !text.starts_with("label: composed-bounded\n")
                || !text.contains(limits)
                || !text.contains("\nwitness: pending-put holds=true boundary=")
                || !text.contains("parent: reproduced\n")
                || leaves.is_empty()
                || !nodes.iter().all(|line| line.contains(" class=success "))
                || nodes.is_empty()
                || !text.ends_with("explore: composed-bounded, 0 problems\n")
                || String::from_utf8_lossy(&explored.stderr).contains("suffix fork ")
            {
                return Err(format!(
                    "explore {output} exited {}: {text}\nstderr: {}",
                    explored.status,
                    String::from_utf8_lossy(&explored.stderr)
                ));
            }
            for leaf in &leaves {
                let at = leaf
                    .split(' ')
                    .nth(1)
                    .and_then(|field| field.strip_prefix("path="));
                let name = format!("leaf-{}.bundle", at.ok_or("a leaf path")?);
                if !dir.join(output).join(&name).is_file() {
                    return Err(format!("{output} holds no {name}"));
                }
            }
            // Costs differ between runs; the rest of the census is fixed.
            let fixed: String = text
                .lines()
                .map(|line| line.split(" wall_us=").next().unwrap_or(line))
                .collect::<Vec<_>>()
                .join("\n");
            censuses.push(fixed);
        }
        if censuses[0] != censuses[1] {
            return Err(format!("{} against {}", censuses[0], censuses[1]));
        }
        let leaves = censuses[0]
            .lines()
            .filter(|line| line.starts_with("leaf: "))
            .count();
        for (bundle, name, output, said) in [
            ("upload.bundle", "pending-put", "never", "Predicate"),
            ("faulted.bundle", "elsewhere", "unknown", "no milestone"),
            ("faulted.bundle", "pending-put", "first", "output"),
        ] {
            let refused = explore(bundle, name, output)?;
            let error = String::from_utf8_lossy(&refused.stderr).into_owned();
            if refused.status.code() != Some(REFUSED) || !error.contains(said) {
                return Err(format!(
                    "{name} into {output} exited {}: {error}",
                    refused.status
                ));
            }
        }
        let controls = run(&[
            "--exact".as_ref(),
            "suffix::composed_bounded_tree_accounts_every_leaf_and_frontier".as_ref(),
        ])?;
        let error = String::from_utf8_lossy(&controls.stderr);
        if !controls.status.success()
            || !error.contains("suffix fork 1 refused: Host(\"a planted refusal\")\n")
        {
            return Err(format!(
                "the nested-fork controls exited {}: {error}",
                controls.status
            ));
        }
        println!(
            "explore: the composed-bounded tree of {leaves} leaves explored alike in two fresh processes"
        );
        Ok(())
    }

    /// Fresh worker processes branch and explore recorded histories at turn
    /// and script milestones. c4 records no upload and advances its clock
    /// once after several turns; h5-put's step 3 returns `STAY` before it
    /// completes. Each branch forks two suffixes, and every child is
    /// credited: c4 at `turn-0`, at `turn-1` (twice, alike) and at
    /// `script-5`, h5-put at `script-3`, the faulted upload at `turn-0`,
    /// before any upload state, and at `turn-3`, whose upload is not
    /// pending, and a cluster-broad run at `turn-1`. The two suffixes
    /// record different bundles where a later draw has several candidates.
    /// Each branch prints the milestone with its `witness:` line at the
    /// boundary actually used, `upload=none` where the prefix holds no
    /// upload state. Exploring c4 at `turn-1` and `script-5` and the
    /// cluster run at `turn-1` credits every node. A listed pattern used as
    /// a name and a turn count past c4's last boundary are refused with
    /// exit 2 and leave no directory; a prefix edited before the milestone
    /// is a divergence, exit 1. A panicking child and a hanging child at
    /// `turn-0`, whose plants act at the advance after it, keep their exit
    /// and watchdog classes and earn no credit.
    ///
    /// The case pins each explored root so that every leaf of its tree
    /// reaches its goal. A tree that misses that premise, as
    /// [`unmet_leaves`] reads it, fails the case under the premise's name; a
    /// node without credit and a leaf that ended in a violation fail it
    /// under the tree's own report.
    fn fresh_processes_fork_at_turns_and_steps() -> Result<(), String> {
        let scratch = Scratch::new("sim-milestones")?;
        let dir = &scratch.dir;
        let executable = own_digest()?;
        // Root 228 gives the cluster-broad run a second stopped boundary,
        // where `turn-1` forks (`boundary=2`), and a tree at
        // `turn-1` in which every leaf reaches its goal.
        let roots = [
            ("c4", 3),
            ("h5-put", 3),
            ("faulted", 3),
            ("cluster-broad", 228),
        ];
        for (profile, root) in roots {
            let text = crate::sim::manifest_tests::sample(profile, &executable, &platform())
                .replace("root = 3\n", &format!("root = {root}\n"));
            let recorded = scratch.record(profile, &text)?;
            if recorded.status.code() != Some(COUNTS) {
                return Err(format!("the {profile} run exited {}", recorded.status));
            }
        }
        let run = |form: (&str, &str, &str), extra: &[&str], output: &str| {
            let ran = scratch.at_milestone(form, extra, output)?;
            let text = String::from_utf8_lossy(&ran.stdout).into_owned();
            let error = String::from_utf8_lossy(&ran.stderr).into_owned();
            Ok::<_, String>((ran.status.code(), text, error))
        };
        let mut printed = Vec::new();
        // `bundles` is how many distinct bundles the two suffixes record:
        // one after h5-put's `script-3`, whose later draws have one
        // candidate each.
        let in_flight = "attempt:1,grant:0,held:0,outcome:0";
        for (profile, name, boundary, upload, output, bundles) in [
            ("c4", "turn-0", 1, "none", "c4-turn-0", 2),
            ("c4", "turn-1", 2, "none", "c4-turn-1", 2),
            ("c4", "turn-1", 2, "none", "c4-turn-1-again", 2),
            ("c4", "script-5", 2, "none", "c4-script-5", 2),
            ("h5-put", "script-3", 2, "none", "h5-script-3", 1),
            ("cluster-broad", "turn-1", 2, "none", "cluster-turn-1", 2),
            ("faulted", "turn-0", 1, "none", "faulted-turn-0", 2),
            ("faulted", "turn-3", 2, in_flight, "faulted-turn-3", 2),
        ] {
            let form = ("--branch", profile, name);
            let (code, text, _) = run(form, &["--suffixes", "2"], output)?;
            let witness = format!(
                "\nwitness: {name} holds=true boundary={boundary} upload={upload} armed=false\n"
            );
            let digests: std::collections::BTreeSet<_> = text
                .lines()
                .filter_map(|line| line.split(" digest=").nth(1))
                .collect();
            if code != Some(COUNTS)
                || !text.starts_with(&format!("milestone: {name} boundary={boundary} "))
                || !text.contains(&witness)
                || !text.contains("parent: reproduced\n")
                || !text.ends_with("branch: 2 children, 2 credited, 0 problems\n")
                || digests.len() != bundles
            {
                return Err(format!("{profile} {name} exited {code:?}: {text}"));
            }
            printed.push(text);
        }
        if printed[1] != printed[2] {
            return Err(format!("{} against {}", printed[1], printed[2]));
        }
        for (profile, name) in [
            ("c4", "turn-1"),
            ("c4", "script-5"),
            ("cluster-broad", "turn-1"),
        ] {
            let output = format!("explore-{profile}-{name}");
            let (code, text, _) = run(("--explore", profile, name), &[], &output)?;
            let credited = text.ends_with("explore: composed-bounded, 0 problems\n");
            if let Some(unmet) = unmet_leaves(&dir.join(&output), &text)? {
                let root = roots.iter().find(|(pinned, _)| *pinned == profile);
                return Err(format!(
                    "premise unmet: every leaf of {profile} root {} explored at {name} runs to its goal; {}: {text}",
                    root.map_or(0, |(_, root)| *root),
                    unmet.join("; ")
                ));
            }
            if code != Some(COUNTS)
                || !text.contains(&format!(
                    "\nwitness: {name} holds=true boundary=2 upload=none "
                ))
                || !text.lines().any(|line| line.starts_with("leaf: "))
                || !credited
            {
                return Err(format!(
                    "explore {profile} at {name} exited {code:?}: {text}"
                ));
            }
            // A zero-problem report with an uncounted leaf requires that
            // leaf's bundle. A reported problem lets `unmet_leaves` return
            // `Ok(None)` with the bundle missing.
            let uncounted = text.replacen(
                " counts=true verdict=complete pass ",
                " counts=false verdict=complete inconclusive ",
                1,
            );
            let problem = uncounted.replace(", 0 problems\n", ", 1 problems\n");
            let absent = dir.join("absent");
            let read = [&uncounted, &problem].map(|report| unmet_leaves(&absent, report));
            if read[0].is_ok() || read[1] != Ok(None) {
                return Err(format!(
                    "the premise of {profile} at {name} without leaf bundles read {read:?}"
                ));
            }
        }
        for (at, (form, extra, said)) in [
            (
                ("--branch", "c4", "turn-N"),
                &["--suffixes", "1"][..],
                "no milestone",
            ),
            (("--explore", "c4", "turn-1000"), &[], "Predicate"),
        ]
        .into_iter()
        .enumerate()
        {
            let output = format!("refused-{at}");
            let (code, _, error) = run(form, extra, &output)?;
            if code != Some(REFUSED) || !error.contains(said) || dir.join(&output).exists() {
                return Err(format!("{form:?} exited {code:?}: {error}"));
            }
        }
        let recorded = std::fs::read(dir.join("c4.bundle")).map_err(|e| e.to_string())?;
        let edited = diverging_before(&recorded, "turn-1");
        std::fs::write(dir.join("edited.bundle"), edited).map_err(|e| e.to_string())?;
        for (form, extra) in [
            (("--branch", "edited", "turn-1"), &["--suffixes", "1"][..]),
            (("--explore", "edited", "turn-1"), &[]),
        ] {
            let (code, text, _) = run(form, extra, "diverged")?;
            if code != Some(COMPLETE)
                || text != "parent: diverged before the milestone\n"
                || dir.join("diverged").exists()
            {
                return Err(format!("{form:?} exited {code:?}: {text}"));
            }
        }
        let planted = dir.join("planted");
        std::fs::create_dir(&planted).map_err(|error| error.to_string())?;
        crate::net::world_tests::branch::tests::planted(&recorded, "turn-0", &planted)?;
        println!("milestones: every listed fork credited, refused or diverged as expected");
        Ok(())
    }

    /// `unmet_leaves` reads bundles only if the exploration report `text`
    /// ends with `explore: composed-bounded, 0 problems\n`. With that
    /// ending it returns `Some` when at least one leaf is uncounted and
    /// every uncounted leaf has verdict `complete inconclusive` or
    /// `complete unsuccessful`, and `None` for every other report. The
    /// value holds one entry for each uncounted leaf: its path, then the
    /// cause and any applicable unsuccessful rule derived from
    /// `leaf-PATH.bundle` in `output`. If an uncounted leaf's bundle fails
    /// to load, `unmet_leaves` returns an error.
    fn unmet_leaves(output: &std::path::Path, text: &str) -> Result<Option<Vec<String>>, String> {
        if !text.ends_with("explore: composed-bounded, 0 problems\n") {
            return Ok(None);
        }
        let uncounted: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("leaf: ") && !line.contains(" counts=true "))
            .collect();
        let harness = |leaf: &&str| {
            ["inconclusive", "unsuccessful"]
                .iter()
                .any(|ending| leaf.contains(&format!(" verdict=complete {ending} ")))
        };
        if uncounted.is_empty() || !uncounted.iter().all(harness) {
            return Ok(None);
        }
        let mut unmet = Vec::new();
        for leaf in uncounted {
            let at = leaf
                .split(' ')
                .nth(1)
                .and_then(|field| field.strip_prefix("path="))
                .ok_or("a leaf path")?;
            let bytes = std::fs::read(output.join(format!("leaf-{at}.bundle")))
                .map_err(|error| format!("leaf {at}: {error}"))?;
            let loaded =
                load(&bytes, 1_000_000).map_err(|error| format!("leaf {at}: {error:?}"))?;
            let mut reason = cause(&loaded, campaign(&loaded), &observed(&loaded.events));
            if let Some(rule) = unsuccessful_rule(&loaded) {
                reason.push_str(&format!(" under {rule}"));
            }
            unmet.push(format!("leaf {at} ended {reason}"));
        }
        Ok(Some(unmet))
    }

    /// A cluster-broad manifest records in two fresh worker processes into
    /// bundles with one digest, decision count and passing terminal, one of
    /// them replays in a third into a bundle with the same three, and
    /// inspecting it prints the drawn topology and each coverage count its
    /// coverage event recorded, under its name in order, and the unavailable
    /// dimensions, with no unsuccessful line. A cluster-version-end run
    /// inspects with cause unsuccessful and names the version counter's end
    /// as its unsuccessful rule.
    fn cluster_bundles_agree() -> Result<(), String> {
        let scratch = Scratch::new("sim-cluster")?;
        let dir = &scratch.dir;
        let profile = "cluster-broad";
        let text = crate::sim::manifest_tests::sample(profile, &own_digest()?, &platform());
        create(dir, "cluster.manifest", text.as_bytes())?;
        let manifest = dir.join("cluster.manifest");
        let parsed = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        let reloaded = |path: &std::path::Path| -> Result<Loaded, String> {
            let path = path.to_str().ok_or("a scratch path is not UTF-8")?;
            reload(&parsed, path).map_err(|unloaded| unloaded.reason(path))
        };
        let mut loaded = Vec::new();
        let mut lines = String::new();
        for at in 0..2 {
            let bundle = dir.join(format!("cluster-{at}.bundle"));
            let recorded = scratch.run(&[
                "--manifest".as_ref(),
                manifest.as_os_str(),
                "--bundle".as_ref(),
                bundle.as_os_str(),
            ])?;
            if recorded.status.code() != Some(COUNTS) {
                return Err(format!(
                    "run {at} exited {}: {}",
                    recorded.status,
                    String::from_utf8_lossy(&recorded.stdout)
                ));
            }
            let bundle = reloaded(&bundle)?;
            if at == 0 {
                lines = cluster_lines(&bundle)?.0;
            }
            loaded.push((bundle.digest, bundle.decisions, bundle.terminal));
        }
        if loaded[0] != loaded[1] || !loaded[0].2.counts() {
            return Err(format!("{:?} against {:?}", loaded[0], loaded[1]));
        }
        let bundle = dir.join("cluster-0.bundle");
        let output = dir.join("cluster.replay");
        let replayed = scratch.run(&[
            "--replay".as_ref(),
            bundle.as_os_str(),
            "--output".as_ref(),
            output.as_os_str(),
        ])?;
        let printed = String::from_utf8_lossy(&replayed.stdout).into_owned();
        if replayed.status.code() != Some(REPRODUCED) || !printed.starts_with("replay: reproduced")
        {
            return Err(format!(
                "the cluster bundle replayed {}: {printed}",
                replayed.status
            ));
        }
        let again = reloaded(&output.join("replay.bundle"))?;
        if (again.digest, again.decisions, again.terminal) != loaded[0] {
            return Err(format!(
                "the replay bundle recorded {:?} against {:?}",
                (again.digest, again.decisions, again.terminal),
                loaded[0]
            ));
        }
        let inspected = scratch.run(&[
            "--inspect".as_ref(),
            bundle.as_os_str(),
            "--manifest".as_ref(),
            manifest.as_os_str(),
        ])?;
        let printed = String::from_utf8_lossy(&inspected.stdout).into_owned();
        if inspected.status.code() != Some(0)
            || !printed.contains(&lines)
            || printed.contains("\nunsuccessful: ")
        {
            return Err(format!("inspect exited {}: {printed}", inspected.status));
        }
        let ended = dir.join("ended.manifest");
        let text =
            crate::sim::manifest_tests::sample("cluster-version-end", &own_digest()?, &platform())
                .replace("actors = 32\n", "actors = 64\n")
                .replace("root = 3\n", "root = 7\n");
        std::fs::write(&ended, text).map_err(|e| e.to_string())?;
        let refused = dir.join("ended.bundle");
        scratch.run(&[
            "--manifest".as_ref(),
            ended.as_os_str(),
            "--bundle".as_ref(),
            refused.as_os_str(),
        ])?;
        let inspected = scratch.run(&[
            "--inspect".as_ref(),
            refused.as_os_str(),
            "--manifest".as_ref(),
            ended.as_os_str(),
        ])?;
        let printed = String::from_utf8_lossy(&inspected.stdout).into_owned();
        if !printed.contains("\ncause: unsuccessful\n")
            || !printed.contains("\nunsuccessful: a key's version counter reached its end\n")
        {
            return Err(format!(
                "the refused upload names no unsuccessful rule: {printed}"
            ));
        }
        println!(
            "cluster: {profile} digest {} recorded alike in two fresh processes and replayed in a third",
            hex(&loaded[0].0)
        );
        Ok(())
    }

    /// Each composed history, custody, incident, cohort, relaunch and
    /// isolation, records in one fresh worker process, ends as it declares,
    /// prints a summary naming it, with its operations and witnesses
    /// unavailable and the cause of a violating or unsuccessful ending, and
    /// replays to its digest, decision count and terminal in another.
    fn histories_replayed() -> Result<(), String> {
        let scratch = Scratch::new("sim-histories")?;
        let dir = &scratch.dir;
        let executable = own_digest()?;
        let run = |args: &[&std::ffi::OsStr]| scratch.run(args);
        for history in crate::net::world_tests::histories::every() {
            let text = crate::sim::manifest_tests::sample(history.name, &executable, &platform());
            let manifest = dir.join(format!("{}.manifest", history.name));
            let bundle = dir.join(format!("{}.bundle", history.name));
            let output = dir.join(format!("{}.replay", history.name));
            std::fs::write(&manifest, &text).map_err(|e| e.to_string())?;
            let recorded = run(&[
                "--manifest".as_ref(),
                manifest.as_os_str(),
                "--bundle".as_ref(),
                bundle.as_os_str(),
            ])?;
            if !matches!(recorded.status.code(), Some(COUNTS | COMPLETE)) {
                return Err(format!("{} recorded {}", history.name, recorded.status));
            }
            let bytes = std::fs::read(&bundle).map_err(|e| e.to_string())?;
            let capacity = Manifest::parse(&text)
                .map_err(|error| format!("{error:?}"))?
                .capacity()
                .records();
            let loaded =
                load(&bytes, capacity).map_err(|error| format!("{}: {error:?}", history.name))?;
            history.ends_as_declared(&loaded)?;
            // The run's summary names the history, prints its operations and
            // witnesses unavailable, since its steps record no action, and
            // names the declared ending of a violating or unsuccessful one
            // as its cause.
            let summary = String::from_utf8_lossy(&recorded.stdout).into_owned();
            let fields = summary_fields(&summary)?;
            let value = |key: &str| summary_value(&fields, key);
            let caused = match history.expect {
                Expect::Violation(obligation, _) => {
                    value("cause") == Some(&format!("violation, violating {obligation:?}"))
                }
                Expect::Unsuccessful(_) => value("cause") == Some("unsuccessful"),
                Expect::Pass => value("cause").is_none(),
            };
            if value("profile") != Some(history.name)
                || value("operations") != Some("unavailable")
                || value("witnesses") != Some("unavailable")
                || !caused
            {
                return Err(format!("{} printed {summary}", history.name));
            }
            let replayed = run(&[
                "--replay".as_ref(),
                bundle.as_os_str(),
                "--output".as_ref(),
                output.as_os_str(),
            ])?;
            let printed = String::from_utf8_lossy(&replayed.stdout).into_owned();
            if replayed.status.code() != Some(REPRODUCED)
                || !printed.starts_with("replay: reproduced")
            {
                return Err(format!(
                    "{} replayed {}: {printed}",
                    history.name, replayed.status
                ));
            }
            let kind = if COHORTS.iter().any(|cohort| cohort.name == history.name) {
                "cohort"
            } else {
                "history"
            };
            println!(
                "{kind}: {} digest {} ended as declared and replayed in a fresh process",
                history.name,
                hex(&loaded.digest)
            );
        }
        Ok(())
    }

    /// Fresh worker processes replay a recorded planted failure, whose
    /// summary names its violated obligation as the cause: two replays
    /// of the unchanged bundle reproduce it and leave it byte-for-byte; a
    /// changed selection diverges; an exhausted tape, an existing output
    /// directory, a missing bundle and a bundle whose recorded manifest pins
    /// another executable or platform are refused by name, and a bundle or
    /// output directory the host cannot read or create is incomplete
    /// evidence. A bundle recording an unlisted profile inspects with its
    /// profile unavailable, and a replay a panic cut short inspects with
    /// its work unavailable. A planted run capped one record short of its
    /// stop names its violation in its cause, and a turn-bounded faulted
    /// run names its limit. A recovery campaign over every cut counts with
    /// its ledger credited, under the two-key and the torn profiles, and
    /// one past its restart bound does not and names the ledger gap as its
    /// cause; each prints its observed counts unavailable; the counting
    /// bundle reproduces alike in two fresh processes, branches and
    /// explores from its recovery milestone, is refused by the pin when it
    /// pins another executable and by its record under the other recovery
    /// profile. A fresh reduction of the
    /// failure, of the planted claim on acknowledgment and of the unplanted
    /// corrupted record keeps at least one step, keeps only the upload's
    /// actions for the two planted ones, replays the original and each kept
    /// step in a fresh process, leaves its input byte-for-byte and writes it
    /// as original.bundle, names boundary-checked in conditions.txt for the
    /// unplanted one and nothing for the planted ones, and its regression
    /// replays in another fresh process with the original's failure
    /// identity. The acked and corrupted summaries name the identity their
    /// reductions keep. A reducer's fresh process runs with only the
    /// library search path it is given in its environment, and with an
    /// empty one without it. The executable's path locates the worker and
    /// its scratch directory for this check alone; no decision reads it.
    ///
    /// For a panicking run, the reducer keeps a step only when a fresh rerun
    /// reproduces the panic, and a refused rerun or an unreadable rerun
    /// bundle stops the reduction as infrastructure.
    fn replayed_and_reduced() -> Result<(), String> {
        use crate::sim::trace::reseal;
        let scratch = Scratch::new("sim-replays")?;
        let dir = &scratch.dir;
        let env = std::path::Path::new("/usr/bin/env");
        for (given, expected) in [
            (Some("/archive/lib"), "LD_LIBRARY_PATH=/archive/lib\n"),
            (None, ""),
        ] {
            let listed = fresh_worker(env, given.map(std::ffi::OsStr::new))
                .output()
                .map_err(|error| error.to_string())?;
            if !listed.status.success() || listed.stdout != expected.as_bytes() {
                return Err(format!(
                    "a fresh reducer process given {given:?} runs with {:?}",
                    String::from_utf8_lossy(&listed.stdout)
                ));
            }
        }
        let executable = own_digest()?;
        let text = crate::sim::manifest_tests::sample("planted", &executable, &platform());
        let manifest = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        std::fs::write(dir.join("run.manifest"), &text).map_err(|e| e.to_string())?;
        let bundle = dir.join("run.bundle");
        let run = |args: &[&std::ffi::OsStr]| scratch.run(args);
        let path = |name: &str| dir.join(name).into_os_string();
        let (manifest_path, bundle_path) = (path("run.manifest"), path("run.bundle"));
        let recorded = run(&[
            "--manifest".as_ref(),
            &manifest_path,
            "--bundle".as_ref(),
            &bundle_path,
        ])?;
        let printed = String::from_utf8_lossy(&recorded.stdout).into_owned();
        if recorded.status.code() != Some(COMPLETE)
            || !summary_fields(&printed)?.contains(&("cause", "violation, violating Bytes"))
        {
            return Err(format!(
                "the planted run exited {}: {printed}",
                recorded.status
            ));
        }
        let original = std::fs::read(&bundle).map_err(|error| error.to_string())?;
        let replay = |input: &str, output: &str| {
            let (input, output) = (path(input), path(output));
            run(&["--replay".as_ref(), &input, "--output".as_ref(), &output])
        };
        for output in ["first", "second"] {
            let replayed = replay("run.bundle", output)?;
            let printed = String::from_utf8_lossy(&replayed.stdout).into_owned();
            let claim =
                "replay: reproduced, complete violation fired=03 required=03, violating Bytes\n";
            if replayed.status.code() != Some(REPRODUCED) || printed != claim {
                return Err(format!(
                    "replay {output} exited {}: {printed}",
                    replayed.status
                ));
            }
        }
        if std::fs::read(&bundle).map_err(|e| e.to_string())? != original {
            return Err("a replay changed its input".into());
        }
        // A file where a directory must stand, and a directory where a
        // file must, fail for any user.
        for (input, output, code) in [
            ("run.bundle", "run.bundle/out", INCOMPLETE),
            ("absent.bundle", "absent.replay", REFUSED),
            ("first", "directory.replay", INCOMPLETE),
        ] {
            let replayed = replay(input, output)?;
            if replayed.status.code() != Some(code) {
                return Err(format!("{input} into {output} exited {}", replayed.status));
            }
        }
        let refusal = replay("run.bundle", "first")?;
        if refusal.status.code() != Some(REFUSED) {
            return Err(format!("an existing output exited {}", refusal.status));
        }
        let capacity = manifest.capacity();
        let mut selections = Vec::new();
        reseal(&original, capacity, |records| {
            selections = (1..records.len())
                .filter(|&at| records[at][0] == 3 && records[at][4] == 3 && records[at - 1][4] == 2)
                .collect();
        });
        let at = *selections.get(3).ok_or("a turn's selection")?;
        let changed = reseal(&original, capacity, |records| {
            let word = |from: usize| {
                u64::from_le_bytes(records[at][from..from + 8].try_into().expect("eight bytes"))
            };
            let (value, bound) = (word(5), word(13));
            records[at][5..13].copy_from_slice(&((value + 1) % bound).to_le_bytes());
        });
        let exhausted = reseal(&original, capacity, |records| {
            let last = records.iter().rposition(|record| record[0] == 3);
            records.remove(last.expect("a choice"));
        });
        // `bundle` with its recorded manifest rewritten by `edit`.
        let rewritten = |bundle: &[u8], edit: &dyn Fn(String) -> String| {
            reseal(bundle, capacity, |records| {
                let manifest_field = |record: &[u8; RECORD]| record[0] == 2 && record[1] == 1;
                let text: Vec<u8> = records
                    .iter()
                    .filter(|record| manifest_field(record))
                    .flat_map(|record| record[5..5 + usize::from(record[4])].to_vec())
                    .collect();
                let text = edit(String::from_utf8_lossy(&text).into_owned());
                let at = records
                    .iter()
                    .position(manifest_field)
                    .expect("a manifest field");
                records.retain(|record| !manifest_field(record));
                let fields =
                    text.as_bytes()
                        .chunks(RECORD - 5)
                        .enumerate()
                        .map(|(chunk, bytes)| {
                            let mut record = [0; RECORD];
                            record[..2].copy_from_slice(&[2, 1]);
                            record[2..4].copy_from_slice(&(chunk as u16).to_le_bytes());
                            record[4] = bytes.len() as u8;
                            record[5..5 + bytes.len()].copy_from_slice(bytes);
                            record
                        });
                records.splice(at..at, fields);
            })
        };
        let foreign = rewritten(&original, &|text| {
            text.replace(&executable, &"0".repeat(64))
        });
        let elsewhere = rewritten(&original, &|text| text.replace(&platform(), "riscv64-none"));
        for (name, bytes, code, said) in [
            ("changed", &changed, DIVERGED, ""),
            ("exhausted", &exhausted, REFUSED, "Exhausted"),
            ("foreign", &foreign, REFUSED, "the bundle pins executable"),
            (
                "elsewhere",
                &elsewhere,
                REFUSED,
                "the bundle names platform riscv64-none",
            ),
        ] {
            std::fs::write(dir.join(name), bytes).map_err(|e| e.to_string())?;
            let replayed = replay(name, &format!("{name}.replay"))?;
            let error = String::from_utf8_lossy(&replayed.stderr).into_owned();
            if replayed.status.code() != Some(code) || !error.contains(said) {
                return Err(format!(
                    "the {name} bundle exited {}: {error}",
                    replayed.status
                ));
            }
        }
        let panics = rewritten(&original, &|text| {
            text.replace("profile = planted", "profile = panicking")
        });
        std::fs::write(dir.join("panics"), &panics).map_err(|e| e.to_string())?;
        let replayed = replay("panics", "panics.replay")?;
        let printed = String::from_utf8_lossy(&replayed.stdout).into_owned();
        let kept = std::fs::read(dir.join("panics.replay/replay.bundle")).unwrap_or_default();
        if replayed.status.code() != Some(DIVERGED)
            || !printed.starts_with("replay: the run panicked at ")
            || !printed.ends_with(": a planted panic once the upload published\n")
            || kept.is_empty()
            || kept.len() >= panics.len()
        {
            return Err(format!(
                "the panics bundle exited {} keeping {} of {} bytes: {printed}",
                replayed.status,
                kept.len(),
                panics.len()
            ));
        }
        // A bundle whose recorded profile is no listed name inspects with
        // its profile unavailable, and the bundle a panic cut short before
        // its terminal inspects with its work unavailable.
        let unlisted = rewritten(&original, &|text| {
            text.replace("profile = planted", "profile = unlisted")
        });
        std::fs::write(dir.join("unlisted"), &unlisted).map_err(|e| e.to_string())?;
        for (profile, manifest) in [
            ("unlisted", "unlisted.manifest"),
            ("panicking", "panics.manifest"),
        ] {
            let edited = text.replace("profile = planted", &format!("profile = {profile}"));
            std::fs::write(dir.join(manifest), edited).map_err(|e| e.to_string())?;
        }
        let cut: &[(&str, &str)] = &[
            ("terminal", "infrastructure truncated"),
            ("counts", "false"),
            ("profile", "panicking"),
            ("decisions", "unavailable"),
            ("turns", "unavailable"),
            ("progress", "unavailable"),
            ("virtual_us", "unavailable"),
            ("skipped_us", "unavailable"),
            ("stop", "unavailable"),
        ];
        for (bundle, manifest, expected) in [
            (
                "unlisted",
                "unlisted.manifest",
                &[("profile", "unavailable")][..],
            ),
            ("panics.replay/replay.bundle", "panics.manifest", cut),
        ] {
            let inspected = run(&[
                "--inspect".as_ref(),
                &path(bundle),
                "--manifest".as_ref(),
                &path(manifest),
            ])?;
            let printed = String::from_utf8_lossy(&inspected.stdout).into_owned();
            let fields = summary_fields(&printed)?;
            if inspected.status.code() != Some(0)
                || expected.iter().any(|pair| !fields.contains(pair))
            {
                return Err(format!(
                    "the {bundle} bundle inspected with {}: {printed}",
                    inspected.status
                ));
            }
        }
        // A planted run one record short of the least maximum that holds
        // its stop event keeps its violation record and ends capped, and
        // its cause names both; a faulted run stopped by its turn bound
        // names the bound.
        let traced_at = |run: &Manifest| -> Result<Loaded, String> {
            let admitted = admit(run).map_err(|refusal| format!("{refusal:?}"))?;
            let closed = traced(admitted, Vec::new());
            load(&closed.sink, run.capacity().records()).map_err(|e| format!("{e:?}"))
        };
        let sized = |records: u64| manifest.clone().with("ring", 1).with("records", records);
        let (_, _, tight) = least_maximum(sized)?;
        let faulted_text = crate::sim::manifest_tests::sample("faulted", &executable, &platform());
        let bounded = Manifest::parse(&faulted_text)
            .map_err(|error| format!("{error:?}"))?
            .with("turns", 3);
        for (loaded, expected) in [
            (
                tight,
                "infrastructure cap, violating Bytes, stop unavailable",
            ),
            (traced_at(&bounded)?, "inconclusive, stop limit turns"),
        ] {
            let printed = summary(&loaded);
            if summary_value(&summary_fields(&printed)?, "cause") != Some(expected) {
                return Err(format!("a summary lacks the cause {expected:?}: {printed}"));
            }
        }
        // A recovery campaign over every cut counts with its ledger
        // credited, as does the torn profile's, whose cuts land none, whole
        // and a sector prefix; one whose restart bound skips a cut is
        // complete without counting, the counting bundle reproduces alike in two fresh
        // processes and branches and explores from its recovery milestone,
        // and the bundle pinning another executable is refused by the pin.
        let text = crate::sim::manifest_tests::sample("recovery-16k", &executable, &platform());
        let two_keys = [
            "0.accepted-submission.0.before.ProcessDeath",
            "0.accepted-submission.0.after.ProcessDeath",
            "1.accepted-submission.0.before.ProcessDeath",
            "1.accepted-submission.0.after.ProcessDeath",
        ];
        let torn = [
            "0.accepted-submission.0.before.ProcessDeath",
            "0.accepted-submission.0.before.ControllerReset",
            "0.accepted-submission.0.after.ProcessDeath",
            "0.accepted-submission.0.after.ControllerReset",
        ];
        for (name, profile, restarts, code, ledger, names, counts) in [
            (
                "recovery",
                "recovery-16k",
                4,
                COUNTS,
                "ledger: credited\n",
                two_keys,
                [1, 1, 1, 1],
            ),
            (
                "bounded",
                "recovery-16k",
                1,
                COMPLETE,
                "ledger: inconclusive Bound { cut: 1 }\n",
                two_keys,
                [1, 0, 0, 0],
            ),
            (
                "torn",
                "recovery-torn",
                20,
                COUNTS,
                "ledger: credited\n",
                torn,
                [1, 1, 1, 17],
            ),
        ] {
            let manifest = format!("{name}.manifest");
            let text = text
                .replace("restarts = 1\n", &format!("restarts = {restarts}\n"))
                .replace("profile = recovery-16k", &format!("profile = {profile}"));
            std::fs::write(dir.join(&manifest), &text).map_err(|e| e.to_string())?;
            let recovered = run(&[
                "--manifest".as_ref(),
                &path(&manifest),
                "--bundle".as_ref(),
                &path(&format!("{name}.bundle")),
            ])?;
            let printed = String::from_utf8_lossy(&recovered.stdout).into_owned();
            let expected =
                (code == COMPLETE).then_some("inconclusive, ledger Bound { cut: 1 }, stop goal");
            let fields = summary_fields(&printed)?;
            let value = |key: &str| summary_value(&fields, key);
            let tail: &[&str] = if code == COMPLETE {
                &["cause", "ledger", "stages", "limits", "windows"]
            } else {
                &["ledger", "stages", "limits", "windows"]
            };
            if recovered.status.code() != Some(code)
                || !fields
                    .iter()
                    .map(|(key, _)| *key)
                    .eq(SUMMARY_KEYS.into_iter().chain(tail.iter().copied()))
                || !printed.contains(ledger)
                || OBSERVED_KEYS
                    .iter()
                    .any(|key| value(key) != Some("unavailable"))
                || value("cause") != expected
            {
                return Err(format!(
                    "the {name} run exited {}: {printed}",
                    recovered.status
                ));
            }
            let windows = value("windows").ok_or("recovery summary omitted windows")?;
            let mut entries = Vec::new();
            let planned = |at: usize| format!("{}={}", names[at], counts[at]);
            let first = if profile == "recovery-torn" { 4 } else { 2 };
            entries.extend((0..first).map(planned));
            for site in [
                "qualified-persistence",
                "root-or-admission-publication",
                "recovery-mutation",
            ] {
                for side in ["before", "after"] {
                    entries.push(format!("0.{site}.0.{side}.ProcessDeath=unplanned"));
                    if first == 4 {
                        entries.push(format!("0.{site}.0.{side}.ControllerReset=unplanned"));
                    }
                }
            }
            entries.extend((first..4).map(planned));
            for site in [
                "permitted-media-effect",
                "completion-posting-and-delivery",
                "protected-exclusion",
                "first-successor-visibility",
                "external-response-observation",
                "reuse",
            ] {
                entries.push(format!("{site}=unplanned"));
            }
            if windows != entries.join(" ") {
                return Err(format!("unexpected {name} window counts: {windows}"));
            }
            if name == "recovery" {
                for _ in 0..2 {
                    let inspect = run(&[
                        "--inspect".as_ref(),
                        &path("recovery.bundle"),
                        "--manifest".as_ref(),
                        &path(&manifest),
                    ])?;
                    if inspect.status.code() != Some(COUNTS) || inspect.stdout != recovered.stdout {
                        return Err(format!(
                            "inspection {} differed from run: {}\n{}",
                            inspect.status,
                            String::from_utf8_lossy(&inspect.stderr),
                            String::from_utf8_lossy(&inspect.stdout)
                        ));
                    }
                }
            }
        }
        let mut replays = Vec::new();
        for output in ["recovered-first", "recovered-second"] {
            let replayed = replay("recovery.bundle", output)?;
            if replayed.status.code() != Some(REPRODUCED) {
                return Err(format!(
                    "the recovery replay {output} exited {}",
                    replayed.status
                ));
            }
            replays.push(replayed.stdout);
        }
        if replays[0] != replays[1] {
            return Err("two fresh recovery replays printed differently".into());
        }
        let bundle_of_recovery = path("recovery.bundle");
        for form in ["--branch", "--explore"] {
            let output = path(&format!("recovery{form}"));
            let mut args: Vec<&std::ffi::OsStr> = vec![
                form.as_ref(),
                &bundle_of_recovery,
                "--milestone".as_ref(),
                "recovery-reached".as_ref(),
            ];
            if form == "--branch" {
                args.extend(["--suffixes", "2"].map(std::ffi::OsStr::new));
            }
            args.extend([std::ffi::OsStr::new("--output"), output.as_os_str()]);
            let forked = run(&args)?;
            let printed = String::from_utf8_lossy(&forked.stdout).into_owned();
            if forked.status.code() != Some(COUNTS) || !printed.contains("parent: reproduced\n") {
                return Err(format!(
                    "the recovery {form} exited {}: {printed}\nstderr: {}",
                    forked.status,
                    String::from_utf8_lossy(&forked.stderr)
                ));
            }
        }
        let recovery = std::fs::read(dir.join("recovery.bundle")).map_err(|e| e.to_string())?;
        let older = rewritten(&recovery, &|text| {
            text.replace(&executable, &"0".repeat(64))
        });
        let relabelled = rewritten(&recovery, &|text| {
            text.replace("profile = recovery-16k", "profile = recovery-512")
        });
        for (name, bytes, code, said) in [
            ("recovered", &recovery, REPRODUCED, ""),
            ("older", &older, REFUSED, "the bundle pins executable"),
            (
                "relabelled",
                &relabelled,
                REFUSED,
                "Recovery(Mismatch(Profile))",
            ),
        ] {
            std::fs::write(dir.join(name), bytes).map_err(|e| e.to_string())?;
            let replayed = replay(name, &format!("{name}.replay"))?;
            let error = String::from_utf8_lossy(&replayed.stderr).into_owned();
            if replayed.status.code() != Some(code) || !error.contains(said) {
                return Err(format!(
                    "the {name} bundle exited {}: {error}",
                    replayed.status
                ));
            }
        }
        // Planted violations reduce under their plant's premise and an
        // unplanted one under its rule's enabling condition: every kept step
        // reproduces the full identity in a fresh process, the original is
        // kept unchanged beside the regression, conditions.txt names the
        // conditions each kept step held, and the regression replays to the
        // same obligation.
        let upload = Some("kinds = PutInvoke, PutPrepare, Supply, PutOutcome\n");
        for (name, obligation, input, kinds, conditions) in [
            ("planted", "Bytes", "run.bundle", upload, ""),
            ("acked", "History", "acked.bundle", upload, ""),
            (
                "corrupted",
                "Bytes",
                "corrupted.bundle",
                None,
                "boundary-checked\n",
            ),
        ] {
            let summary = if name == "planted" {
                None
            } else {
                let text = crate::sim::manifest_tests::sample(name, &executable, &platform());
                let manifest_name = format!("{name}.manifest");
                std::fs::write(dir.join(&manifest_name), &text).map_err(|e| e.to_string())?;
                let (manifest, bundle) = (path(&manifest_name), path(input));
                let recorded = run(&[
                    "--manifest".as_ref(),
                    &manifest,
                    "--bundle".as_ref(),
                    &bundle,
                ])?;
                let printed = String::from_utf8_lossy(&recorded.stdout).into_owned();
                let cause = format!("violation, violating {obligation}");
                if recorded.status.code() != Some(COMPLETE)
                    || !summary_fields(&printed)?.contains(&("cause", cause.as_str()))
                {
                    return Err(format!(
                        "the {name} run exited {}: {printed}",
                        recorded.status
                    ));
                }
                Some(printed)
            };
            let before = std::fs::read(dir.join(input)).map_err(|e| e.to_string())?;
            let identity = |bytes: &[u8]| load(bytes, u64::MAX).ok().as_ref().and_then(violated);
            let original = identity(&before)
                .ok_or_else(|| format!("the {name} bundle records no violation identity"))?;
            // The violation's summary names the failure identity its
            // reduction keeps, as 88 lowercase hex characters.
            if let Some(printed) = summary {
                let named = summary_value(&summary_fields(&printed)?, "identity");
                let well_formed = named.is_some_and(|text| {
                    text.len() == 2 * crate::sim::trace::PAYLOAD
                        && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                });
                if !well_formed || named != Some(hex(original.bytes()).as_str()) {
                    return Err(format!(
                        "the {name} summary names another identity: {printed}"
                    ));
                }
            }
            let out = format!("{name}.reduced");
            let (input_path, out_path) = (path(input), path(&out));
            let reduced = run(&[
                "--reduce".as_ref(),
                &input_path,
                "--output".as_ref(),
                &out_path,
            ])?;
            let summary = String::from_utf8_lossy(&reduced.stdout).into_owned();
            if reduced.status.code() != Some(REPRODUCED) || summary.contains(", bounded") {
                return Err(format!(
                    "the {name} reduction exited {}: {summary}{}",
                    reduced.status,
                    String::from_utf8_lossy(&reduced.stderr)
                ));
            }
            let saved =
                std::fs::read(dir.join(&out).join("original.bundle")).map_err(|e| e.to_string())?;
            if std::fs::read(dir.join(input)).map_err(|e| e.to_string())? != before
                || saved != before
            {
                return Err(format!("the {name} reduction changed or dropped its input"));
            }
            let read = |file: &str| {
                std::fs::read_to_string(dir.join(&out).join(file)).map_err(|e| e.to_string())
            };
            if read("conditions.txt")? != conditions {
                return Err(format!(
                    "the {name} reduction names other enabling conditions"
                ));
            }
            let scenario = read("scenario.txt")?;
            if kinds.is_some_and(|kinds| !scenario.starts_with(kinds)) {
                return Err(format!("the {name} regression keeps {scenario}"));
            }
            let kept = read("steps.txt")?
                .lines()
                .filter(|line| line.starts_with("kept"))
                .count();
            let verified = (1..)
                .take_while(|step| {
                    dir.join(&out)
                        .join(format!("step-{step}.replay/replay.bundle"))
                        .exists()
                })
                .count();
            if kept == 0 || verified < kept + 1 {
                return Err(format!(
                    "{name}: {verified} fresh replays for {kept} kept steps"
                ));
            }
            let regression = replay(
                &format!("{out}/regression.bundle"),
                &format!("{name}.regression"),
            )?;
            let printed = String::from_utf8_lossy(&regression.stdout).into_owned();
            if regression.status.code() != Some(REPRODUCED)
                || !printed.ends_with(&format!(", violating {obligation}\n"))
            {
                return Err(format!(
                    "the {name} regression replay exited {}: {printed}",
                    regression.status
                ));
            }
            let regressed = std::fs::read(dir.join(&out).join("regression.bundle"))
                .map_err(|e| e.to_string())?;
            if identity(&regressed) != Some(original) {
                return Err(format!("the {name} regression names another identity"));
            }
            regression_manifest(&dir.join(&out), &regressed)?;
            println!(
                "replay: the {name} bundle reproduced in fresh processes; its regression of {kept} kept steps reproduced {obligation} in another"
            );
        }
        // A run that panics keeps every record before its panic and names
        // the panic; its reduction keeps only steps that rerun, each in a
        // fresh process, to the same location and payload.
        let text = crate::sim::manifest_tests::sample("panicking", &executable, &platform());
        std::fs::write(dir.join("panicking.manifest"), &text).map_err(|e| e.to_string())?;
        let recorded = run(&[
            "--manifest".as_ref(),
            &path("panicking.manifest"),
            "--bundle".as_ref(),
            &path("panicked.bundle"),
        ])?;
        let printed = String::from_utf8_lossy(&recorded.stdout).into_owned();
        let named = |line: &str| line.ends_with(": a planted panic once the upload published");
        let identity = printed
            .strip_suffix('\n')
            .and_then(|line| line.strip_prefix("run: "))
            .filter(|line| !line.contains('\n'))
            .filter(|line| named(line) && line.starts_with("the run panicked at "))
            .map(str::to_owned);
        let (Some(INCOMPLETE), Some(identity)) = (recorded.status.code(), identity) else {
            return Err(format!(
                "the panicking run exited {}: {printed}",
                recorded.status
            ));
        };
        let reduced = run(&[
            "--reduce".as_ref(),
            &path("panicked.bundle"),
            "--output".as_ref(),
            &path("panicked.reduced"),
        ])?;
        let printed = String::from_utf8_lossy(&reduced.stdout).into_owned();
        if reduced.status.code() != Some(REPRODUCED)
            || printed.contains(", bounded")
            || !printed.ends_with(&format!(", {identity}\n"))
        {
            return Err(format!(
                "the panicking reduction exited {}: {printed}{}",
                reduced.status,
                String::from_utf8_lossy(&reduced.stderr)
            ));
        }
        let out = dir.join("panicked.reduced");
        let saved = std::fs::read(out.join("original.bundle")).map_err(|e| e.to_string())?;
        let conditions = std::fs::read(out.join("conditions.txt")).map_err(|e| e.to_string())?;
        if saved != std::fs::read(dir.join("panicked.bundle")).map_err(|e| e.to_string())?
            || !conditions.is_empty()
        {
            return Err("panicking: an invalid original or conditions artifact".into());
        }
        let kept = std::fs::read_to_string(out.join("steps.txt"))
            .map_err(|e| e.to_string())?
            .lines()
            .filter(|line| line.starts_with("kept"))
            .count();
        let rerun = (1..)
            .take_while(|step| out.join(format!("step-{step}.rerun.bundle")).exists())
            .count();
        let (original, regression) = (
            std::fs::read(dir.join("panicked.bundle")).map_err(|e| e.to_string())?,
            std::fs::read(out.join("regression.bundle")).map_err(|e| e.to_string())?,
        );
        regression_manifest(&out, &regression)?;
        if kept == 0 || rerun < kept + 1 || regression.len() >= original.len() {
            return Err(format!(
                "panicking: {rerun} fresh reruns for {kept} kept steps, {} of {} bytes",
                regression.len(),
                original.len()
            ));
        }
        println!(
            "replay: the panicking bundle reduced under its panic in fresh processes; its regression of {kept} kept steps reruns to {identity}"
        );
        unwritable()?;
        reduce_exits(dir, &run)?;
        verdicts(dir)
    }

    /// The regression.manifest a reduction into `out` wrote parses and
    /// equals the manifest its regression bundle `regression` recorded.
    fn regression_manifest(out: &std::path::Path, regression: &[u8]) -> Result<(), String> {
        let text =
            std::fs::read_to_string(out.join("regression.manifest")).map_err(|e| e.to_string())?;
        let saved = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        let (_, bundled) = recorded(regression).map_err(|error| format!("{error:?}"))?;
        if saved != bundled {
            return Err(format!(
                "{}: the regression manifest differs from its bundle's",
                out.display()
            ));
        }
        Ok(())
    }

    /// --reduce exits by how the reduction ends. A recovery bundle is
    /// unreducible: exit 1 with its reason, no summary and no regression.
    /// A step bundle that already stands in the output directory fails the
    /// fresh-process check that would write it. At the original's step the
    /// reduction exits 3 and writes no regression. At a later candidate's
    /// step it exits 3 with no summary, names that step bundle, and still
    /// writes every file: the original as the regression, original.bundle,
    /// its manifest and enabling conditions, and a steps.txt whose last two
    /// lines name the unverified candidate and the interruption.
    fn reduce_exits(
        dir: &std::path::Path,
        run: &dyn Fn(&[&std::ffi::OsStr]) -> Result<std::process::Output, String>,
    ) -> Result<(), String> {
        let unreducible = dir.join("recovery.reduced");
        let refused = run(&[
            "--reduce".as_ref(),
            dir.join("recovery.bundle").as_os_str(),
            "--output".as_ref(),
            unreducible.as_os_str(),
        ])?;
        let error = String::from_utf8_lossy(&refused.stderr);
        if refused.status.code() != Some(DIVERGED)
            || !refused.stdout.is_empty()
            || !error.contains("only a mixed-world bundle reduces")
            || unreducible.join("regression.bundle").exists()
        {
            return Err(format!(
                "the recovery reduction exited {}: {error}",
                refused.status
            ));
        }
        let original = std::fs::read(dir.join("corrupted.bundle")).map_err(|e| e.to_string())?;
        let files = [
            "original.bundle",
            "regression.manifest",
            "regression.bundle",
            "scenario.txt",
            "steps.txt",
            "conditions.txt",
        ];
        for (step, written) in [(1, false), (2, true)] {
            let out = dir.join(format!("corrupted.stopped-{step}"));
            std::fs::create_dir(&out).map_err(|e| e.to_string())?;
            let blocked = format!("step-{step}.bundle");
            std::fs::write(out.join(&blocked), b"").map_err(|e| e.to_string())?;
            let (mut printed, mut complaint) = (Vec::new(), Vec::new());
            let reduced =
                |verify: &mut Verify<'_>| reduce(&original, verify).map(scenario_regression);
            let code = reduce_into(&original, &out, reduced, &mut printed, &mut complaint);
            let complaint = String::from_utf8_lossy(&complaint).into_owned();
            let present = files.iter().filter(|file| out.join(file).exists()).count();
            if code != INCOMPLETE
                || !printed.is_empty()
                || !complaint.contains(&blocked)
                || present != if written { files.len() } else { 0 }
            {
                return Err(format!(
                    "a reduction stopped at step {step} exited {code} with {present} files: {complaint}"
                ));
            }
            if !written {
                continue;
            }
            let steps =
                std::fs::read_to_string(out.join("steps.txt")).map_err(|e| e.to_string())?;
            let lines: Vec<&str> = steps.lines().collect();
            let regression =
                std::fs::read(out.join("regression.bundle")).map_err(|e| e.to_string())?;
            let saved = std::fs::read(out.join("original.bundle")).map_err(|e| e.to_string())?;
            let conditions =
                std::fs::read_to_string(out.join("conditions.txt")).map_err(|e| e.to_string())?;
            regression_manifest(&out, &regression)?;
            let logged = matches!(
                lines.as_slice(),
                [.., unverified, interrupted]
                    if unverified.starts_with("unverified, ")
                        && interrupted.starts_with("interrupted, ")
                        && interrupted.contains(&blocked)
            );
            if regression != original
                || saved != original
                || conditions != "boundary-checked\n"
                || !logged
            {
                return Err(format!("the interrupted reduction logs {steps}"));
            }
        }
        Ok(())
    }

    struct Unwritable;

    impl Write for Unwritable {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if std::thread::panicking() {
                return Err(std::io::Error::other("no space left"));
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn unwritable() -> Result<(), String> {
        let text = crate::sim::manifest_tests::sample("panicking", &own_digest()?, &platform());
        let manifest = Manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        let admitted = admit(&manifest).map_err(|refusal| format!("{refusal:?}"))?;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = recorded_into(
            &manifest,
            admitted,
            Unwritable,
            "unwritable.bundle",
            &mut out,
            &mut err,
        );
        let (out, err) = (String::from_utf8_lossy(&out), String::from_utf8_lossy(&err));
        if code != INCOMPLETE
            || out.contains("run: the run panicked")
            || !err.contains("unwritable.bundle")
        {
            return Err(format!(
                "the unwritable panicking run exited {code}: {out}{err}"
            ));
        }
        Ok(())
    }

    /// Each reduction stop renders its steps.txt line and its summary
    /// line, or its reason: an exhausted reduction adds no steps line, a
    /// bounded one names `, bounded` after the scenario and before a
    /// panic's text, and an interrupted one prints its reason escaped on
    /// one line and gives no summary line, so it exits incomplete.
    fn stopped(violation: &Identity, panic: &Identity) -> Result<(), String> {
        let manifest = Manifest::parse(&crate::sim::manifest_tests::sample(
            "corrupted",
            &"a".repeat(64),
            "x86_64-linux",
        ))
        .map_err(|error| format!("{error:?}"))?;
        let reduced = |identity: &Identity, stop: Stop| Reduced {
            manifest: manifest.clone(),
            bundle: vec![0; 3 * RECORD],
            steps: Vec::new(),
            scenario: String::new(),
            identity: identity.clone(),
            conditions: Vec::new(),
            stop,
        };
        let scenario = &manifest.scenario;
        let interrupted = Stop::Interrupted("a\nb".into());
        for (identity, stop, expected) in [
            (
                violation,
                Stop::Exhausted,
                (
                    String::new(),
                    Ok(format!(
                        "reduce: reduced to 3 records, scenario {scenario}\n"
                    )),
                ),
            ),
            (
                violation,
                Stop::Bounded,
                (
                    "stopped at the step bound\n".to_owned(),
                    Ok(format!(
                        "reduce: reduced to 3 records, scenario {scenario}, bounded\n"
                    )),
                ),
            ),
            (
                panic,
                Stop::Bounded,
                (
                    "stopped at the step bound\n".to_owned(),
                    Ok(format!(
                        "reduce: reduced to 3 records, scenario {scenario}, bounded, {panic}\n"
                    )),
                ),
            ),
            (
                panic,
                interrupted.clone(),
                (
                    "interrupted, the fresh-process check failed: \"a\\nb\"\n".to_owned(),
                    Err("a\nb"),
                ),
            ),
            (
                violation,
                interrupted.clone(),
                (
                    "interrupted, the fresh-process check failed: \"a\\nb\"\n".to_owned(),
                    Err("a\nb"),
                ),
            ),
        ] {
            let reduced = reduced(identity, stop);
            let found = stop_lines(&reduced);
            if found != expected {
                return Err(format!(
                    "{:?} of {identity}: {found:?}, expected {expected:?}",
                    reduced.stop
                ));
            }
        }
        Ok(())
    }

    fn verdicts(dir: &std::path::Path) -> Result<(), String> {
        use std::os::unix::process::ExitStatusExt;
        let ran = |code: i32, stdout: &str| std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        let event = crate::sim::trace::Event {
            kind: crate::net::world_tests::bundle::IDENTITY,
            payload: [0; crate::sim::trace::PAYLOAD],
        };
        let violation = Identity::Violation(
            crate::net::world_tests::replay::FailureIdentity::of(&event)
                .ok_or("an identity event carries an identity")?,
        );
        let panic = Identity::Panic("src/a.rs:1:2: a panic".into());
        stopped(&violation, &panic)?;
        let rerun = dir.join("verdict.rerun.bundle");
        std::fs::write(&rerun, b"candidate").map_err(|e| e.to_string())?;
        let mut verdicts = Vec::new();
        for (code, expected) in [
            (REPRODUCED, Some(true)),
            (DIVERGED, Some(false)),
            (REFUSED, Some(false)),
            (INCOMPLETE, None),
        ] {
            let verdict = reproduced_by(1, &violation, &ran(code, ""), &rerun, b"candidate");
            verdicts.push((format!("a violation's exit {code}"), verdict, expected));
        }
        for (code, expected) in [
            (REPRODUCED, Some(false)),
            (DIVERGED, Some(false)),
            (REFUSED, None),
        ] {
            let verdict = reproduced_by(1, &panic, &ran(code, ""), &rerun, b"candidate");
            verdicts.push((format!("a panic's exit {code}"), verdict, expected));
        }
        let named = format!("run: {panic}\n");
        let other = "run: the run panicked at src/b.rs:1:2: a panic\n";
        let absent = dir.join("absent.rerun.bundle");
        for (case, printed, at, candidate, expected) in [
            (
                "the named panic",
                named.as_str(),
                &rerun,
                "candidate",
                Some(true),
            ),
            ("another panic", other, &rerun, "candidate", Some(false)),
            (
                "other bytes",
                named.as_str(),
                &rerun,
                "other bytes",
                Some(false),
            ),
            (
                "an unreadable rerun",
                named.as_str(),
                &absent,
                "candidate",
                None,
            ),
            ("no panic named", "", &rerun, "candidate", None),
        ] {
            let ran = ran(INCOMPLETE, printed);
            let verdict = reproduced_by(1, &panic, &ran, at, candidate.as_bytes());
            verdicts.push((case.to_owned(), verdict, expected));
        }
        match verdicts
            .into_iter()
            .find(|(_, verdict, expected)| verdict.as_ref().ok().copied() != *expected)
        {
            Some((case, verdict, expected)) => {
                Err(format!("{case}: {verdict:?}, expected {expected:?}"))
            }
            None => Ok(()),
        }
    }

    /// The checked-in long-run manifest's run completes with every check,
    /// witness and bound passing; it prints its report lines.
    #[ignore = "the manifest's long-run gate; the long-run lane runs it with --ignored"]
    fn the_long_run_gate_passes() -> Result<(), String> {
        let gate = Gate::parse(LONG_RUN_MANIFEST)?;
        for line in crate::sim::long_run_tests::run(&gate, Plants::default())? {
            println!("long-run: {line}");
        }
        Ok(())
    }

    /// The scaled churn run's seeds each pass on the original
    /// geometry, one engine each, with the lifecycle and poisoned-gate
    /// phases and the whole witness set; it prints its report lines.
    #[ignore = "scaled churn of 12 seeds at 409,600 actions each; the long-run lane runs it with --ignored"]
    fn every_seed_passes_on_one_engine_each() -> Result<(), String> {
        for line in seeds(SCALED_RUN)? {
            println!("{line}");
        }
        Ok(())
    }

    /// The scaled churn run's seeds each pass on every larger
    /// geometry, one engine each, with each geometry's occupancy, reserve
    /// and fragmentation witnesses; it prints its report lines.
    #[ignore = "scaled churn of 12 seeds on each larger geometry at 409,600 actions each; the long-run lane runs it with --ignored"]
    fn every_larger_geometry_passes_on_one_engine_each() -> Result<(), String> {
        for line in geometries(SCALED_RUN)? {
            println!("{line}");
        }
        Ok(())
    }

    /// The deeper composed bounded suffix trees from the faulted upload's
    /// pending-PUT milestone each account every leaf and frontier as the
    /// sample tree does; it prints its report lines.
    #[ignore = "composed bounded suffix trees to depth 4 by 3 children and depth 7 by 2; the long-run lane runs it with --ignored"]
    fn deeper_composed_bounded_trees_account_every_leaf_and_frontier() -> Result<(), String> {
        crate::net::world_tests::suffix::tests::deeper_composed_bounded_trees_account_every_leaf_and_frontier()
    }

    /// Seeds 1 to 16 each run 32 cycles of warm takeovers and same-host restarts under the open-loop tape and pass
    /// the four verdicts and the quiescent conservation judgment; it prints each run's lines and their digest, the
    /// census, the compositions the runs reached and the cases they leave unscored. The runs are unpowered discovery.
    #[ignore = "seeded warm takeover and restart cycles, 16 seeds of 32 cycles each; the long-run lane runs it with --ignored"]
    fn seeded_warm_cycles_pass_on_seeds_1_to_16() -> Result<(), String> {
        for line in crate::net::takeover_history_tests::cycles::discovery(1..=16, 32)? {
            println!("{line}");
        }
        Ok(())
    }

    /// Every pinned fleet run's digest line, then the crash table's line over all its cells.
    fn fleet_pinned() -> Result<Vec<String>, String> {
        use crate::net::takeover_history_tests::fleet;
        let mut lines = fleet::pinned_runs(None)?;
        let cells = fleet::reconcile::CrashCell::all();
        lines.push(fleet::crash_table(fleet::CRASH_TABLE_ROOT, &cells)?);
        Ok(lines)
    }

    fn fleet_report() -> Result<(), String> {
        for line in fleet_pinned()? {
            println!("{line}");
        }
        Ok(())
    }

    /// Two fresh worker processes, launched as [`across`] launches them, each print the pinned digest lines this
    /// process computes.
    fn fleet_digests_across() -> Result<(), String> {
        const PREFIX: &str = "fleet: pinned ";
        let pinned = fleet_pinned()?;
        let expected: Vec<&str> = (pinned.iter())
            .filter_map(|line| line.strip_prefix(PREFIX))
            .collect();
        if expected.len() != pinned.len() {
            return Err(format!("a pinned line lacks its prefix: {pinned:?}"));
        }
        reported_and_refuses_a_change(&fresh_runs(FLEET_REPORT)?, PREFIX, &expected)?;
        println!(
            "fleet: {} pinned digests reported alike by two fresh processes",
            expected.len()
        );
        Ok(())
    }

    /// Reusing both successful outputs isolates the changed expectation as
    /// the cause of rejection.
    fn reported_and_refuses_a_change(
        runs: &[std::process::Output; 2],
        prefix: &str,
        expected: &[&str],
    ) -> Result<(), String> {
        reported(runs, prefix, expected)?;
        let mut changed = expected.first().map(|line| (*line).to_owned());
        let last = changed.as_mut().and_then(String::pop);
        let (Some(mut changed), Some(last)) = (changed, last) else {
            return Err(format!("no character to change in {expected:?}"));
        };
        changed.push(if last == '0' { '1' } else { '0' });
        let mut other = expected.to_vec();
        other[0] = &changed;
        if reported(runs, prefix, &other).is_ok() {
            return Err(format!(
                "a fresh process was accepted against a line it did not report: {changed}"
            ));
        }
        Ok(())
    }

    /// A rejection tests the digest comparison only when both processes
    /// exit successfully.
    fn a_failed_run_is_no_refusal() -> Result<(), String> {
        use std::os::unix::process::ExitStatusExt;
        const PRINTED: &str = "probe: first 10\nunrelated\nprobe: second 20\n";
        let expected = ["first 10", "second 20"];
        let exited = |code: i32, printed: &str| std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: printed.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        let passed = |printed: &str| [exited(0, printed), exited(0, printed)];
        reported_and_refuses_a_change(&passed(PRINTED), "probe: ", &expected)?;
        let failed: [([std::process::Output; 2], &[&str]); 5] = [
            ([exited(0, PRINTED), exited(101, PRINTED)], &expected),
            ([exited(101, PRINTED), exited(0, PRINTED)], &expected),
            (passed(PRINTED), &["first 11", "second 20"]),
            (passed("probe: \n"), &[""]),
            (passed(""), &[]),
        ];
        for (runs, expected) in failed {
            if reported_and_refuses_a_change(&runs, "probe: ", expected).is_ok() {
                return Err(format!("{runs:?} passed the control against {expected:?}"));
            }
        }
        Ok(())
    }

    #[ignore = "fleet owner crashes and warm restarts, 2 shapes on 16 roots each; the long-run lane runs it with --ignored"]
    fn fleet_runs_pass_on_roots_1_to_16() -> Result<(), String> {
        use crate::net::takeover_history_tests::fleet;
        for line in fleet::roots(fleet::ROOTS)? {
            println!("{line}");
        }
        Ok(())
    }

    /// Seeds 1 to 16 each run 8 same-host restarts through `recover`, `bring_up`, `serve` and `Duties` with a
    /// publishing owner, and every warm load serves exactly the objects the earlier tenures held; it prints
    /// one line per seed and a summary.
    #[ignore = "seeded restart cycles of a publishing owner through the host driver, 16 seeds of 8 restarts each; the long-run lane runs it with --ignored"]
    fn seeded_restart_cycles_load_the_published_cut_plus_the_suffix() -> Result<(), String> {
        for line in crate::host::duties::step_tests::publishing_cycles(1..=16, 8)? {
            println!("{line}");
        }
        Ok(())
    }

    /// Seeds 1 to 16 each run 8 tenures that roll on a bound the seed draws, then a restart, through `recover`,
    /// `bring_up`, `serve` and `Duties`; every tenure after a roll serves exactly the objects the earlier tenures
    /// acknowledged, and every roll keeps the generation, the volume and the owner. It prints one line per seed and a
    /// summary.
    #[ignore = "seeded roll cycles through the host driver, 16 seeds of 8 rolls each; the long-run lane runs it with --ignored"]
    fn seeded_roll_cycles_restart_at_e_plus_one_with_every_acknowledged_mutation()
    -> Result<(), String> {
        for line in crate::host::duties::roll_tests::rolling_cycles(1..=16, 8)? {
            println!("{line}");
        }
        Ok(())
    }

    /// Seeds 1 to 16 each run 24 slot-reuse cycles, a standby or owner replacement in every cycle through the
    /// reconciler's record, enrollment, designation and end, the owner's reclaim step, and the reconciler's detach
    /// and release. Each run passes all four verdicts with at most three live attaches and a fresh host for each
    /// replacement; the case prints each run's lines and their digest, then the replacement totals.
    #[ignore = "seeded slot-reuse cycles, 16 seeds of 24 cycles each; the long-run lane runs it with --ignored"]
    fn slot_reuse_cycles_replace_a_host_every_cycle_on_seeds_1_to_16() -> Result<(), String> {
        for line in crate::net::takeover_history_tests::cycles::slot_reuse_discovery(1..=16, 24)? {
            println!("{line}");
        }
        Ok(())
    }

    /// Seeds 1 to 16 each run 8 tenures between the warm volume's two recorded hosts, each ending in an accepted
    /// planned request the seed draws, a transfer to the named standby or a same-host restart, then one plain tenure,
    /// through `recover`, `bring_up`, `serve` and `Duties`. Every tenure first serves exactly the objects the earlier
    /// tenures acknowledged; a transfer's target activates through its restart's lineage arm. It prints one line per
    /// seed and a summary.
    #[ignore = "seeded planned-exit cycles between two hosts through the host driver, 16 seeds of 8 exits each; the long-run lane runs it with --ignored"]
    fn seeded_handoff_cycles_hold_every_acknowledged_mutation_across_both_hosts()
    -> Result<(), String> {
        for line in crate::host::duties::transfer_tests::handoff_cycles(1..=16, 8)? {
            println!("{line}");
        }
        Ok(())
    }

    /// libtest's count of tests: `1 test`, otherwise `N tests`.
    fn tests(count: usize) -> String {
        if count == 1 {
            "1 test".into()
        } else {
            format!("{count} tests")
        }
    }

    fn finish(out: &mut impl Write, lines: &str, code: i32) -> i32 {
        match out.write_all(lines.as_bytes()).and_then(|()| out.flush()) {
            Ok(()) => code,
            Err(_) => 101,
        }
    }

    /// A recorded run of the choice sequence replays to the same decisions
    /// and consumes its whole tape.
    fn replays() -> Result<(), String> {
        let mut recorder = launched(ROOT);
        let recorded = sequence(&mut recorder, 8);
        let tape = recorder.finish().map_err(|error| format!("{error:?}"))?;
        let mut replayer = replaying(tape);
        let replayed = sequence(&mut replayer, 8);
        let finished = replayer.finish();
        if replayed != recorded || finished.is_err() {
            return Err(format!("{replayed:?} against {recorded:?}: {finished:?}"));
        }
        Ok(())
    }

    /// Whether `count` moves across one heap allocation.
    fn live(count: impl Fn() -> usize) -> bool {
        let before = count();
        let boxed = std::hint::black_box(Box::new([0u8; 64]));
        let after = count();
        drop(boxed);
        after > before
    }

    /// The worker's allocations reach the counting allocator, so a window
    /// that counts none is not vacuous.
    fn allocator_live() -> Result<(), String> {
        if live(crate::instrument::allocations) {
            Ok(())
        } else {
            Err("the allocation counter did not move".into())
        }
    }

    /// Control: a counter that never moves, as an absent counting allocator
    /// reads, fails the probe.
    fn probe_control() -> Result<(), String> {
        if live(|| 0) {
            Err("the probe passed without counts".into())
        } else {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Flushed {
        pending: Vec<u8>,
        chunks: Vec<String>,
    }

    impl Write for Flushed {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.pending.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let chunk = String::from_utf8_lossy(&self.pending).into_owned();
            self.pending.clear();
            self.chunks.push(chunk);
            Ok(())
        }
    }

    fn streamed() -> Result<(), String> {
        let stub: [Case; 2] = [
            ("stub::passes", || Ok(())),
            ("stub::fails", || Err("no".into())),
        ];
        let (mut out, mut err) = (Flushed::default(), Vec::new());
        let code = run(&[], &stub, &[], &mut out, &mut err);
        let expected = [
            "\nrunning 2 tests\n",
            "test stub::passes ... ok\n",
            "test stub::fails ... FAILED\n",
        ];
        let head: Vec<&str> = out.chunks.iter().take(3).map(String::as_str).collect();
        if code != 101 || head != expected || out.chunks.len() != 4 {
            return Err(format!("exit {code}, chunks {:?}", out.chunks));
        }
        if !out.chunks[3].contains("test result: FAILED. 1 passed; 1 failed;") {
            return Err(format!("summary chunk {:?}", out.chunks[3]));
        }
        Ok(())
    }

    /// [`IGNORED`] names exactly the cases of [`CASES`] whose function in
    /// this file carries an ignore attribute, by the function name after
    /// the case name's last `::`.
    fn ignored_cases() -> Result<(), String> {
        let attribute = concat!("#[", "ignore");
        let mut lines = include_str!("worker.rs").lines().map(str::trim);
        let mut attributed = Vec::new();
        while let Some(line) = lines.next() {
            if !line.starts_with(attribute) {
                continue;
            }
            let signature = lines.find(|line| line.starts_with("fn "));
            let name = signature.and_then(|line| line["fn ".len()..].split('(').next());
            attributed.push(name.ok_or("an ignore attribute without a function")?);
        }
        attributed.sort_unstable();
        let mut named: Vec<&str> = IGNORED
            .iter()
            .map(|case| case.rsplit("::").next().unwrap_or(case))
            .collect();
        named.sort_unstable();
        let listed = IGNORED
            .iter()
            .all(|ignored| CASES.iter().any(|(name, _)| name == ignored));
        if attributed != named || !listed {
            return Err(format!(
                "ignored functions {attributed:?}, IGNORED {IGNORED:?}"
            ));
        }
        Ok(())
    }

    fn protocol() -> Result<(), String> {
        let stub: [Case; 2] = [
            ("stub::passes", || Ok(())),
            ("stub::fails", || Err("no".into())),
        ];
        let ignoring = |ignored: &[&str], args: &[&str]| {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = run(&args, &stub, ignored, &mut out, &mut err);
            out.extend_from_slice(&err);
            (code, String::from_utf8_lossy(&out).into_owned())
        };
        let ran = |args: &[&str]| ignoring(&[], args);
        let failing = |args: &[&str]| ignoring(&["stub::fails"], args);
        let checks = [
            (
                failing(&[]),
                0,
                "test stub::fails ... ignored\n\ntest result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out",
            ),
            (
                failing(&["--ignored"]),
                101,
                "running 1 test\ntest stub::fails ... FAILED",
            ),
            (
                failing(&["--ignored"]),
                101,
                "0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out",
            ),
            (
                failing(&["--include-ignored"]),
                101,
                "1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out",
            ),
            (
                failing(&["--include-ignored", "--skip", "fails"]),
                0,
                "1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out",
            ),
            (
                failing(&["--exact", "stub::fails"]),
                0,
                "0 passed; 0 failed; 1 ignored; 0 measured; 1 filtered out",
            ),
            (
                failing(&["--list"]),
                0,
                "stub::passes: test\nstub::fails: test\n\n2 tests, 0 benchmarks",
            ),
            (
                failing(&["--list", "--ignored"]),
                0,
                "stub::fails: test\n\n1 test, 0 benchmarks",
            ),
            (
                failing(&["--ignored", "passes"]),
                0,
                "0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out",
            ),
            (
                failing(&["--bench"]),
                0,
                "0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out",
            ),
            (
                failing(&["--ignored", "--include-ignored"]),
                101,
                "error: the options --include-ignored and --ignored are mutually exclusive",
            ),
            (ran(&[]), 101, "test stub::fails ... FAILED\n\nfailures:"),
            (
                ran(&[]),
                101,
                "test result: FAILED. 1 passed; 1 failed; 0 ignored",
            ),
            (
                ran(&["--exact", "stub::passes"]),
                0,
                "1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out",
            ),
            (
                ran(&["--exact", "stub"]),
                0,
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out",
            ),
            (
                ran(&["u2"]),
                0,
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out",
            ),
            (
                ran(&["--ignored"]),
                0,
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out",
            ),
            (
                ran(&["--skip", "fails"]),
                0,
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out",
            ),
            (
                ran(&["--exact", "--skip", "stub"]),
                101,
                "1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out",
            ),
            (
                ran(&["--skip", "stub", "--list"]),
                0,
                "0 tests, 0 benchmarks",
            ),
            (ran(&["--skip"]), 101, "error: --skip needs a value"),
            (
                ran(&["--include-ignored"]),
                101,
                "test result: FAILED. 1 passed; 1 failed; 0 ignored",
            ),
            (ran(&["u1", "--list"]), 0, "2 tests, 0 benchmarks"),
            (ran(&["--list", "--ignored"]), 0, "0 tests, 0 benchmarks"),
            (
                ran(&["--test-threads=1", "passes"]),
                0,
                "test stub::passes ... ok",
            ),
            (
                ran(&["--nocapture", "--no-capture", "--show-output", "passes"]),
                0,
                "test stub::passes ... ok",
            ),
            (
                ran(&["--test-threads", "1", "--exact", "stub::passes"]),
                0,
                "1 passed; 0 failed",
            ),
            (
                ran(&["--test-threads=2"]),
                101,
                "error: --test-threads=2: the worker runs on one thread",
            ),
            (
                ran(&["--test-threads", "01", "--test-threads=+1", "passes"]),
                0,
                "test stub::passes ... ok",
            ),
            (
                ran(&["--test-threads", "0"]),
                101,
                "error: --test-threads 0: the worker runs on one thread",
            ),
            (
                ran(&["--test-threads=two"]),
                101,
                "error: --test-threads=two: the worker runs on one thread",
            ),
            (ran(&["--bench"]), 0, "test stub::fails ... ignored"),
            (
                ran(&["--bench"]),
                0,
                "test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out",
            ),
            (ran(&["--bench", "--list"]), 0, "stub::fails: test"),
            (
                ran(&["--bench", "--test", "passes"]),
                0,
                "test stub::passes ... ok",
            ),
            (
                ran(&["--test", "--bench", "passes"]),
                0,
                "test stub::passes ... ok",
            ),
            (
                ran(&["--skip=fails"]),
                0,
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out",
            ),
            (
                ran(&["--test-threads", "2"]),
                101,
                "error: --test-threads 2: the worker runs on one thread",
            ),
            (
                ran(&["--test-threads"]),
                101,
                "error: --test-threads needs a value",
            ),
            (ran(&["--bogus"]), 101, "error: unknown flag --bogus"),
            (
                ran(&["--help"]),
                0,
                "Usage: sim_worker [OPTIONS] [FILTER]...",
            ),
            (ran(&["-h", "fails"]), 0, "--test-threads 1"),
            (
                ran(&["--format", "pretty", "--color", "always", "passes"]),
                0,
                "test stub::passes ... ok",
            ),
            (
                ran(&["--format=pretty", "--color=never", "passes"]),
                0,
                "test stub::passes ... ok",
            ),
            (
                ran(&["--format", "json"]),
                101,
                "error: --format json: the worker prints the pretty format",
            ),
            (ran(&["--format"]), 101, "error: --format needs a value"),
            (ran(&["--color"]), 101, "error: --color needs a value"),
            (ran(&["--test", "passes"]), 0, "test stub::passes ... ok"),
            (
                ran(&["-q"]),
                101,
                "error: -q: the worker prints the pretty format",
            ),
            (
                ran(&["--quiet"]),
                101,
                "error: --quiet: the worker prints the pretty format",
            ),
            (
                ran(&["--logfile", "out.log"]),
                101,
                "error: --logfile out.log: the worker writes no logfile",
            ),
            (ran(&["--manifest"]), 2, "error: --manifest needs a value"),
            (
                ran(&["--manifest", "m", "--bundle", "b", "--manifest", "x"]),
                2,
                "error: --manifest given twice",
            ),
            (
                ran(&["--inspect", "b", "--manifest", "m", "--bogus"]),
                2,
                "error: unknown flag --bogus",
            ),
            (
                ran(&["--reduce", "b", "--output"]),
                2,
                "error: --output needs a value",
            ),
            (
                ran(&["--replay", "b", "--output", "d", "--events"]),
                2,
                "error: unknown flag --events",
            ),
            (
                ran(&["--output", "d"]),
                2,
                "error: give exactly one of --replay and --reduce",
            ),
            (
                ran(&["--manifest", "m", "--bundle", "b", "--output", "d"]),
                2,
                "error: give exactly one of --replay and --reduce",
            ),
        ];
        for ((code, output), expected, line) in checks {
            if code != expected || !output.contains(line) {
                return Err(format!(
                    "exit {code}, expected {expected}, without {line:?}: {output}"
                ));
            }
        }
        Ok(())
    }

    /// Derives the pinned identity and prints it on one `identity: ` line.
    /// It is the entry each fresh process of `across` runs, and an ordinary
    /// run of the worker also runs it in place.
    fn report() -> Result<(), String> {
        let drawn = pinned_identity()?;
        println!("identity: {drawn}");
        Ok(())
    }

    /// Two fresh worker processes, each running only the report case, pass
    /// it and report the pinned identity: one with an empty environment, the
    /// other with an unrelated variable and the root directory as its working
    /// directory, so neither the environment nor the working directory
    /// reaches identity.
    fn across() -> Result<(), String> {
        fresh_reports(REPORT, "identity: ", &[PINNED])
    }

    /// Enumerates the fixture descriptors' cuts and prints, on one `cuts: `
    /// line, the digest of the registry hash, each fixture's descriptor
    /// hash and its cut table's canonical bytes. It is the entry each
    /// fresh process of `cut_tables_across` runs, and an ordinary run of
    /// the worker also runs it in place.
    fn cut_report() -> Result<(), String> {
        let digest = pinned_cuts()?;
        println!("cuts: {digest}");
        Ok(())
    }

    /// Two fresh worker processes, each running only the cut report case,
    /// pass it and report the pinned digest of the fixtures' cut tables, as
    /// [`across`] runs them, so the reported digest is independent of addresses,
    /// the environment and the working directory.
    fn cut_tables_across() -> Result<(), String> {
        fresh_reports(CUT_REPORT, "cuts: ", &[PINNED_CUTS])
    }

    /// Runs `case` alone in two fresh worker processes, one with an empty
    /// environment and one with an unrelated variable and the root
    /// directory as its working directory, and requires each to pass it
    /// and print exactly the lines of `expected`, in order, after `prefix`. The
    /// executable's path locates the worker for this check alone; no
    /// decision reads it.
    fn fresh_reports(case: &str, prefix: &str, expected: &[&str]) -> Result<(), String> {
        reported(&fresh_runs(case)?, prefix, expected)
    }

    fn fresh_runs(case: &str) -> Result<[std::process::Output; 2], String> {
        let worker = std::env::current_exe().map_err(|error| error.to_string())?;
        let mut cleared = std::process::Command::new(&worker);
        cleared.env_clear();
        let mut moved = std::process::Command::new(&worker);
        moved.env("KESTRIKE_IDENTITY_PROBE", "1").current_dir("/");
        let run = |mut command: std::process::Command| {
            let ran = command.args(["--exact", case]).output();
            ran.map_err(|error| error.to_string())
        };
        Ok([run(cleared)?, run(moved)?])
    }

    fn reported(
        runs: &[std::process::Output; 2],
        prefix: &str,
        expected: &[&str],
    ) -> Result<(), String> {
        for (process, run) in runs.iter().enumerate() {
            let stdout = String::from_utf8_lossy(&run.stdout);
            let reported: Vec<&str> = stdout
                .lines()
                .filter_map(|line| line.strip_prefix(prefix))
                .collect();
            if !run.status.success() || reported != expected {
                return Err(format!(
                    "process {process} exited {}, reported {reported:?}, expected {expected:?}: {stdout}{}",
                    run.status,
                    String::from_utf8_lossy(&run.stderr)
                ));
            }
        }
        Ok(())
    }

    /// The protocol contract case. Its text lives in `worker_contract.rs`
    /// beside this file, whose own text [`ignored_cases`] embeds, so a
    /// worker built without `cfg(protocol_contract)` holds neither the
    /// case's text nor the supervisor's parser.
    #[cfg(protocol_contract)]
    mod contract {
        include!("worker_contract.rs");
    }

    /// The process runs this case and its recovery jobs on its only thread.
    /// The task directory is read for this check alone; no decision reads it.
    fn one_thread() -> Result<(), String> {
        #[cfg(not(loom))]
        crate::storage::helpers_run_on_one_thread()?;
        let threads = std::fs::read_dir("/proc/self/task")
            .map_err(|error| error.to_string())?
            .count();
        if threads == 1 {
            Ok(())
        } else {
            Err(format!("{threads} threads"))
        }
    }
}
