//! The fuzz root's start, recovery, bounds and records, and runs of
//! shell-script workers. A test that runs workers needs a delegated
//! cgroup-v2 scope named by `CAMPAIGN_CGROUP_ROOT`, where each worker's pen
//! is created.

use std::os::unix::fs::PermissionsExt;

use super::super::pen_tests::Delegation;
use super::super::tests::{GATE, failing_gate};
use super::*;
use crate::step::{Outcome, Step};
use crate::store::fixture::{Case, bounded, processes, scripted, snapshot};

/// A worker that prints one counts line and exits 0.
pub(super) const PASSING: &str = "echo 'fuzz: campaign executed=3 pass=3' >&2\nexit 0";

/// A merge that copies every corpus file into the new corpus.
pub(super) const COPYING: &str = "cp \"$corpus\"/* \"$new\"/\nexit 0";

/// Each pen's limits in these tests, as [`plan`] names them.
pub(super) const PEN: Limits = Limits {
    memory: 64 << 20,
    processes: 16,
};

pub(super) fn build() -> Text {
    crate::record::Text::new(&"b".repeat(64)).unwrap()
}

/// A run of one second with `workers` workers of 64 MiB and 16 processes
/// each, on the root `fuzz` of the case.
pub(super) fn plan(case: &Case, workers: u64) -> Plan {
    Plan {
        root: case.root.join("fuzz"),
        archive: case.root.join("archive"),
        seconds: 1,
        workers,
        cgroup: case.root.join("cgroup"),
        memory: 64 << 20,
        processes: 16,
    }
}

/// An executable shell script `name` under the case's directory.
fn executable(case: &Case, name: &str, script: &str) -> PathBuf {
    let path = case.root.join(name);
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A worker script `name` whose run of one input file exits 0, as
/// [`worker_with`] makes it.
pub(super) fn worker(case: &Case, name: &str, fuzz: &str, merge: &str) -> Worker {
    worker_with(case, name, fuzz, merge, "exit 0")
}

/// A worker script `name`, whose approved environment sets `KEPT`. Each
/// form writes its arguments, its working directory, then whether it
/// inherited `CARGO_MANIFEST_DIR` from the test and the value of `KEPT`:
/// the `--seeds` form to `argv` in the seeds directory, then it writes
/// `upload.input` and fails, as the worker does, when that file exists;
/// every other form to the file `argv` beside its artifact directory,
/// named for it. A run of one input file, as a rerun and the control
/// are, then runs `single` with `target`, `artifacts` and `input` set, a
/// merge runs `merge` with `new`, `corpus` and `seeds` set, and a fuzz
/// worker runs `fuzz` with `artifacts`, `corpus` and `seeds` set.
pub(super) fn worker_with(
    case: &Case,
    name: &str,
    fuzz: &str,
    merge: &str,
    single: &str,
) -> Worker {
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = --seeds ]; then\n\
         printf '%s\\n' \"$@\" \"$PWD\" \"${{CARGO_MANIFEST_DIR+inherited}}:$KEPT\" > \"$3/argv\"\n\
         set -C; printf seed > \"$3/upload.input\"; exit; fi\n\
         printf '%s\\n' \"$@\" \"$PWD\" \"${{CARGO_MANIFEST_DIR+inherited}}:$KEPT\" > \"$4.argv\"\n\
         target=$2 artifacts=$4\nshift 5\n\
         if [ $# = 1 ]; then input=$1\n{single}\nfi\n\
         if [ \"$5\" = -merge=1 ]; then new=$7 corpus=$8 seeds=$9\n{merge}\nfi\n\
         corpus=$6 seeds=$7\n{fuzz}\n"
    );
    Worker {
        program: executable(case, name, &script).into(),
        environment: vec![("KEPT".into(), Some("kept".into()))],
        gate: executable(case, "gate.sh", GATE),
        build: build(),
        provenance: crate::archive::publish_tests::built().provenance,
    }
}

/// A run of `plan` that has taken its number and written its seeds.
pub(super) fn started<'a>(
    plan: &'a Plan,
    worker: &'a Worker,
    limits: Limits,
) -> Result<Session<'a>, Error> {
    let session = opened(plan, worker, limits)?;
    session.advance(None)?;
    Ok(session)
}

/// The JSON file at `path`.
pub(super) fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// The sorted names under the directory `dir`.
pub(super) fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// One run of `worker` on the claimed root of `plan`, in pens under
/// `host`, closed with a kept archive: the `run.json` the run stored,
/// which equals the record the run returned.
pub(super) fn run(plan: &Plan, worker: &Worker, host: &Delegation, bounds: Bounds) -> Value {
    crate::sys::block_interruptions().unwrap();
    let _claimed = claim(&plan.root).unwrap();
    let mut session = started(plan, worker, PEN).unwrap();
    session.bounds = bounds;
    let stored = session.directory.join("run.json");
    let ran = session.fuzzed(&host.root()).unwrap();
    let returned = session.closed(&ran, Ok(())).unwrap();
    let record = json(&stored);
    assert_eq!(record, returned);
    record
}

/// Waits up to 20 seconds for each file of `paths`. When one is still
/// missing then, it sets `stop`, so the run under test ends, and panics
/// naming that file.
pub(super) fn awaited(paths: &[PathBuf], stop: &OnceLock<&'static str>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while let Some(missing) = paths.iter().find(|path| !path.exists()) {
        if Instant::now() > deadline {
            let _ = stop.set("signal");
            panic!("{} never appeared", missing.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The merge's line holds the paths unquoted, so a root or an archive
/// path with a byte outside its set is refused before the root is
/// claimed: a space in the root, then a `$` in the archive.
#[test]
fn a_path_outside_the_merge_byte_set_is_rejected_before_the_root_is_claimed() {
    let case = Case::new();
    let mut spaced = plan(&case, 1);
    spaced.root = case.root.join("fuzz root");
    let mut expanded = plan(&case, 1);
    expanded.archive = case.root.join("archive$HOME");
    for plan in [spaced, expanded] {
        let ran = fuzz(&plan);
        assert!(
            matches!(&ran, Err(Error::Rejected(reason)) if reason.contains("A-Za-z0-9/._=,-")),
            "{ran:?}"
        );
        assert!(!plan.root.exists());
    }
}

/// Each byte a shell splits, quotes, expands or redirects on is refused
/// in either path, and paths of the set's bytes alone are accepted.
#[test]
fn only_the_merge_byte_set_is_accepted() {
    let plain = Path::new("/data/Fuzz-1/root_2.a=b,c");
    assert!(accepted(plain, plain).is_ok());
    assert!(accepted(Path::new(""), plain).is_err());
    for byte in " \t\n'\"\\$`;&|<>*?[]{}()~#!%:^@+\u{e9}".chars() {
        let path = format!("/data/fuzz{byte}root");
        let path = Path::new(&path);
        assert!(accepted(path, plain).is_err(), "{path:?}");
        assert!(accepted(plain, path).is_err(), "{path:?}");
    }
}

/// A kill between the swap's two renames leaves no `corpus/`: the old
/// corpus comes back by rename and the merged one is removed. A kill
/// after both leaves `corpus.old`, which is removed so the next swap's
/// rename meets no directory. The corpus each start keeps is checked by
/// its file names, and a new root gets an empty `corpus/`.
#[test]
fn a_cut_swap_is_undone_at_each_kill_point() {
    let case = Case::new();
    let root = case.root.join("fuzz");
    let fill = |name: &str, file: &str| {
        std::fs::create_dir_all(root.join(name)).unwrap();
        std::fs::write(root.join(name).join(file), file).unwrap();
    };
    fill("corpus.old", "old");
    fill("corpus.new", "merged");
    recovered(&root).unwrap();
    assert_eq!(names(&root), ["corpus"]);
    assert_eq!(names(&root.join("corpus")), ["old"]);
    std::fs::remove_dir_all(&root).unwrap();
    fill("corpus", "merged");
    fill("corpus.old", "old");
    recovered(&root).unwrap();
    assert_eq!(names(&root), ["corpus"]);
    assert_eq!(names(&root.join("corpus")), ["merged"]);
    std::fs::remove_dir_all(&root).unwrap();
    fill("corpus", "kept");
    fill("corpus.new", "merged");
    recovered(&root).unwrap();
    assert_eq!(names(&root), ["corpus"]);
    assert_eq!(names(&root.join("corpus")), ["kept"]);
    std::fs::remove_dir_all(&root).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    recovered(&root).unwrap();
    assert_eq!(names(&root), ["corpus"]);
    assert!(names(&root.join("corpus")).is_empty());
}

/// A `corpus` entry that is a file fails the recovery before either copy
/// of the corpus is removed, and a symlink to a directory does too.
#[test]
fn a_corpus_that_is_no_directory_keeps_both_copies() {
    let case = Case::new();
    let root = case.root.join("fuzz");
    for directory in ["corpus.old", "corpus.new", "target"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
        std::fs::write(root.join(directory).join("input"), directory).unwrap();
    }
    std::fs::write(root.join("corpus"), "file").unwrap();
    let before = snapshot(&root);
    assert!(recovered(&root).is_err());
    assert_eq!(snapshot(&root), before);
    std::fs::remove_file(root.join("corpus")).unwrap();
    std::os::unix::fs::symlink(root.join("target"), root.join("corpus")).unwrap();
    let before = snapshot(&root);
    assert!(recovered(&root).is_err());
    assert_eq!(snapshot(&root), before);
}

/// A swap leaves the merged corpus alone.
#[test]
fn a_swap_replaces_the_corpus() {
    let case = Case::new();
    let root = case.root.join("fuzz");
    for (name, file) in [("corpus", "old"), ("corpus.new", "merged")] {
        std::fs::create_dir_all(root.join(name)).unwrap();
        std::fs::write(root.join(name).join(file), file).unwrap();
    }
    swapped(&root).unwrap();
    assert_eq!(names(&root), ["corpus"]);
    assert_eq!(snapshot(&root.join("corpus")), corpus("merged"));
}

/// The single file `name` holding its name, as a snapshot of a corpus.
fn corpus(name: &str) -> crate::store::fixture::Snapshot {
    [(PathBuf::from(name), Some(name.as_bytes().to_vec()))].into()
}

/// The swap syncs the merged corpus's filesystem before its first rename
/// and the root's directory after both renames, before it removes
/// `corpus.old`. So the merged files are durable before a rename can
/// publish them, and the old corpus stays until both renames are durable.
/// After a kill at any step, recovery restores one whole corpus: the old
/// one until the second rename and the merged one after it. After a kill
/// at any recovery step, rerunning recovery yields the same corpus, and
/// further runs leave the tree unchanged. Each tree removal is one step,
/// so each cut falls at a removal's boundary.
#[test]
fn a_swap_killed_at_each_step_is_recovered_to_one_whole_corpus() {
    let case = Case::new();
    let root = case.root.join("fuzz");
    let cut = |at: Option<usize>| {
        std::fs::remove_dir_all(&root).ok();
        for (name, file) in [("corpus", "old"), ("corpus.new", "merged")] {
            std::fs::create_dir_all(root.join(name)).unwrap();
            std::fs::write(root.join(name).join(file), file).unwrap();
        }
        scripted(at.map(|at| (at, Outcome::Kill)), || swapped(&root))
    };
    let (swap, reached) = cut(None);
    swap.unwrap().unwrap();
    let steps = [
        Step::Open,
        Step::Sync,
        Step::Rename,
        Step::Rename,
        Step::Open,
        Step::Sync,
        Step::Unlink,
    ];
    assert_eq!(reached, steps);
    let kept = ["old", "old", "old", "old", "merged", "merged", "merged"];
    for (at, kept) in kept.into_iter().enumerate() {
        for kill in 0.. {
            assert!(cut(Some(at)).0.is_none(), "the swap is cut at step {at}");
            let (recovery, _) = scripted([(kill, Outcome::Kill)], || recovered(&root));
            recovered(&root).unwrap();
            let label = format!("swap cut {at}, recovery cut {kill}");
            assert_eq!(names(&root), ["corpus"], "{label}");
            assert_eq!(snapshot(&root.join("corpus")), corpus(kept), "{label}");
            let after = snapshot(&root);
            recovered(&root).unwrap();
            assert_eq!(snapshot(&root), after, "{label}");
            if recovery.is_some() {
                break;
            }
        }
    }
}

/// A failed lookup of `corpus` or of `corpus.old`, or a failed rename
/// back, on a root a kill left between the swap's renames fails the
/// recovery with every entry as it was, and a recovery after it restores
/// the old corpus.
#[test]
fn a_failed_lookup_in_recovery_keeps_every_copy() {
    let case = Case::new();
    let root = case.root.join("fuzz");
    for (name, file) in [("corpus.old", "old"), ("corpus.new", "merged")] {
        std::fs::create_dir_all(root.join(name)).unwrap();
        std::fs::write(root.join(name).join(file), file).unwrap();
    }
    let before = snapshot(&root);
    for (at, step) in [(0, Step::Stat), (1, Step::Stat), (2, Step::Rename)] {
        let failed = [(at, Outcome::Errno(libc::EIO))];
        let (recovery, reached) = scripted(failed, || recovered(&root));
        assert!(recovery.unwrap().is_err(), "step {at}");
        assert_eq!(reached.get(at), Some(&step));
        assert_eq!(snapshot(&root), before, "step {at}");
    }
    recovered(&root).unwrap();
    assert_eq!(names(&root), ["corpus"]);
    assert_eq!(snapshot(&root.join("corpus")), corpus("old"));
}

/// A start on a root a kill left between the swap's renames, then on one
/// a kill left after both, recovers the corpus that cut keeps before it
/// counts the corpus: the old one, then the merged one, with neither
/// `corpus.old` nor `corpus.new` left.
#[test]
fn a_start_recovers_a_cut_swap_before_it_counts_the_corpus() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    let layouts = [
        ([("corpus.old", "old"), ("corpus.new", "merged")], "old"),
        ([("corpus", "merged"), ("corpus.old", "old")], "merged"),
    ];
    for (layout, kept) in layouts {
        std::fs::remove_dir_all(plan.root.join("corpus")).ok();
        for (name, file) in layout {
            std::fs::create_dir_all(plan.root.join(name)).unwrap();
            std::fs::write(plan.root.join(name).join(file), file).unwrap();
        }
        let session = started(&plan, &worker, PEN).unwrap();
        assert_eq!(session.before.into_inner(), 1, "{kept}");
        assert_eq!(snapshot(&plan.root.join("corpus")), corpus(kept));
        assert!(!plan.root.join("corpus.old").exists(), "{kept}");
        assert!(!plan.root.join("corpus.new").exists(), "{kept}");
    }
}

/// A corpus past the scan bound, 65,536 files, is held before the run
/// number advances, before a run directory exists and before the seed
/// writer runs, which here would note its start, and so is a corpus that
/// holds a subdirectory, whose files the workers would load; a corpus at
/// the bound starts. The case lowers the bound to two.
#[test]
fn a_corpus_past_its_bound_is_held_before_any_worker() {
    assert_eq!(crate::SCAN_BOUND, 65_536);
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut worker = worker(&case, "worker.sh", PASSING, COPYING);
    let noted = case.root.join("seeded");
    let script = format!(
        "#!/bin/sh\nprintf x > {}\nexec {} \"$@\"\n",
        noted.display(),
        Path::new(&worker.program).display()
    );
    worker.program = executable(&case, "noting.sh", &script).into();
    let _claimed = claim(&plan.root).unwrap();
    let corpus = plan.root.join("corpus");
    std::fs::create_dir(&corpus).unwrap();
    for file in 0..3 {
        std::fs::File::create(corpus.join(file.to_string())).unwrap();
    }
    let (started_past, _) = bounded(2, || {
        started(&plan, &worker, PEN).map(|session| session.number)
    });
    assert!(
        matches!(&started_past, Err(Error::Held(reason)) if reason.contains("3 files, past the 2")),
        "{started_past:?}"
    );
    assert_eq!(names(&plan.root), ["corpus"]);
    assert!(!noted.exists());
    std::fs::remove_file(corpus.join("0")).unwrap();
    std::fs::create_dir_all(corpus.join("nested/inner")).unwrap();
    let (nested, _) = bounded(2, || {
        started(&plan, &worker, PEN).map(|session| session.number)
    });
    assert!(
        matches!(&nested, Err(Error::Held(reason)) if reason.contains("invalid data")),
        "{nested:?}"
    );
    assert_eq!(names(&plan.root), ["corpus"]);
    assert!(!noted.exists());
    std::fs::remove_dir_all(corpus.join("nested")).unwrap();
    let (number, _) = bounded(2, || {
        started(&plan, &worker, PEN).map(|session| session.number)
    });
    assert_eq!(number.unwrap(), 0);
    assert!(noted.exists());
}

/// The last 16 run directories stay, their names compared as numbers.
/// A directory whose name is no canonical run number stays as it is, and
/// so do a file and a symlink with a run number's name, which take no
/// place among the 16.
#[test]
fn the_last_sixteen_run_directories_stay() {
    let case = Case::new();
    let runs = case.root.join("runs");
    for number in 1..=20 {
        std::fs::create_dir_all(runs.join(number.to_string()).join("w0")).unwrap();
    }
    std::fs::create_dir(runs.join("notes")).unwrap();
    std::fs::create_dir(runs.join("07")).unwrap();
    std::fs::write(runs.join("30"), "file").unwrap();
    std::os::unix::fs::symlink(runs.join("notes"), runs.join("31")).unwrap();
    pruned(&runs).unwrap();
    let mut kept: Vec<String> = (5..=20).map(|number: u64| number.to_string()).collect();
    kept.extend(["07", "30", "31", "notes"].map(str::to_owned));
    kept.sort();
    assert_eq!(names(&runs), kept);
}

/// The new run's directory is among the 16 a start keeps: with runs 0 to
/// 15 on the root, run 16 starts and run 0 goes.
#[test]
fn the_new_run_is_among_the_sixteen_kept() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    for number in 0..16 {
        std::fs::create_dir_all(plan.root.join("runs").join(number.to_string())).unwrap();
    }
    let record = Record {
        next: 16,
        failed_merges: 0,
        ..Record::default()
    };
    store(&plan.root, &record).unwrap();
    assert_eq!(started(&plan, &worker, PEN).unwrap().number, 16);
    let mut kept: Vec<String> = (1..=16).map(|number: u64| number.to_string()).collect();
    kept.sort();
    assert_eq!(names(&plan.root.join("runs")), kept);
}

/// A start whose seed writer fails still keeps 16 run directories, the
/// failed run's among them: two failed starts on runs 0 to 15 leave runs
/// 2 to 17.
#[test]
fn a_start_whose_seeds_fail_keeps_sixteen_run_directories() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut worker = worker(&case, "worker.sh", PASSING, COPYING);
    worker.program = executable(&case, "failing.sh", "#!/bin/sh\nexit 1\n").into();
    let _claimed = claim(&plan.root).unwrap();
    for number in 0..16 {
        std::fs::create_dir_all(plan.root.join("runs").join(number.to_string())).unwrap();
    }
    let record = Record {
        next: 16,
        failed_merges: 0,
        ..Record::default()
    };
    store(&plan.root, &record).unwrap();
    for _ in 0..2 {
        let failed = started(&plan, &worker, PEN).map(|session| session.number);
        assert!(
            matches!(&failed, Err(Error::Held(reason)) if reason.contains("seeds")),
            "{failed:?}"
        );
    }
    let mut kept: Vec<String> = (2..=17).map(|number: u64| number.to_string()).collect();
    kept.sort();
    assert_eq!(names(&plan.root.join("runs")), kept);
}

/// Each form's `-rss_limit_mb` is three quarters of its pen's memory limit
/// in MiB. The default 8 GiB pen sets `-rss_limit_mb=6144`, leaving 2 GiB
/// below the pen's memory limit. If rounding yields 0 MiB, the threshold
/// is 1 MiB because libFuzzer treats 0 as unlimited.
#[test]
fn each_fuzz_form_carries_the_limits_and_its_own_artifact_prefix() {
    for (artifacts, memory, rss, tail) in [
        ("/r/runs/3/w1", MEMORY, "6144", "/r/corpus"),
        ("/r/runs/3/merge", MEMORY, "6144", "-merge=1"),
        ("/r/runs/3/w0", PEN.memory, "48", "/r/corpus"),
        ("/r/runs/3/w0", (1 << 20) + 1, "1", "/r/corpus"),
    ] {
        let form = super::bounded(Path::new(artifacts), memory, [OsString::from(tail)]);
        let expected = [
            "--fuzz",
            "campaign",
            "--artifacts",
            artifacts,
            "--",
            "-max_len=65536",
            "-timeout=60",
            &format!("-rss_limit_mb={rss}"),
            &format!("-artifact_prefix={artifacts}/"),
            tail,
        ];
        assert_eq!(form, expected.map(OsString::from));
    }
}

/// Help mode probes whether the worker accepts `-merge=1` before running a
/// corpus merge.
#[test]
fn the_merge_probe_rejects_a_worker_that_refuses_a_merge() {
    let _processes = processes();
    let case = Case::new();
    let root = case.root.join("fuzz");
    std::fs::create_dir(&root).unwrap();
    let noted = case.root.join("probe");
    let mut worker = worker(&case, "worker.sh", PASSING, COPYING);
    let accepting = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" \"$PWD\" \"${{CARGO_MANIFEST_DIR+inherited}}:$KEPT\" \
         > {}\nexit 0\n",
        noted.display()
    );
    worker.program = executable(&case, "accepting.sh", &accepting).into();
    merging(&worker, &root, PEN.memory).unwrap();
    let root_text = root.display().to_string();
    let argv = std::fs::read_to_string(&noted).unwrap();
    assert_eq!(
        argv.lines().collect::<Vec<_>>(),
        [
            "--fuzz",
            "campaign",
            "--artifacts",
            &root_text,
            "--",
            "-max_len=65536",
            "-timeout=60",
            "-rss_limit_mb=48",
            &format!("-artifact_prefix={root_text}/"),
            "-merge=1",
            &format!("-merge_control_file={root_text}/merge.txt"),
            "-help=1",
            &root_text,
            ":kept",
        ]
    );
    assert!(names(&root).is_empty());
    let refusing = "#!/bin/sh\nfor arg; do case $arg in -merge=*) exit 2;; esac; done\nexit 0\n";
    worker.program = executable(&case, "refusing.sh", refusing).into();
    let refused = merging(&worker, &root, PEN.memory);
    assert!(
        matches!(&refused, Err(Error::Rejected(reason)) if reason.contains("corpus merge")),
        "{refused:?}"
    );
    assert!(names(&root).is_empty());
}

/// A spawn failure identifies a host-side startup error.
#[test]
fn the_merge_probe_holds_a_worker_that_cannot_start() {
    let _processes = processes();
    let case = Case::new();
    let root = case.root.join("fuzz");
    std::fs::create_dir(&root).unwrap();
    let mut worker = worker(&case, "worker.sh", PASSING, COPYING);
    worker.program = case.root.join("absent").into();
    let held = merging(&worker, &root, PEN.memory);
    assert!(
        matches!(&held, Err(Error::Held(reason)) if reason.contains("it cannot run")),
        "{held:?}"
    );
    assert!(names(&root).is_empty());
}

/// The monitor's bounds are 180 seconds past the deadline,
/// 1,800 seconds for a merge and 64 MiB of output. Past its kill time a
/// process has passed the time bound, whatever its output; before it, the
/// output bound alone applies.
#[test]
fn the_bounds_are_three_minutes_half_an_hour_and_64_mib_with_time_first() {
    assert_eq!(BOUNDS.grace, Duration::from_secs(180));
    assert_eq!(BOUNDS.merge, Duration::from_secs(1_800));
    assert_eq!(BOUNDS.output, 64 << 20);
    let now = Instant::now();
    let (past, ahead) = (now - Duration::from_secs(1), now + Duration::from_secs(1));
    assert_eq!(BOUNDS.passed(now, past, 0), Some("time"));
    assert_eq!(BOUNDS.passed(now, past, u64::MAX), Some("time"));
    assert_eq!(BOUNDS.passed(now, ahead, (64 << 20) + 1), Some("output"));
    assert_eq!(BOUNDS.passed(now, ahead, 64 << 20), None);
}

/// A run's number is stored before its directory exists, so after a run
/// killed once its directory exists the next run takes the next number
/// and its seed writer, which fails at a seed file that exists, writes
/// into a new directory.
#[test]
fn a_killed_runs_number_is_not_taken_again() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    let killed = started(&plan, &worker, PEN).unwrap();
    assert_eq!(killed.number, 0);
    assert_eq!(killed.bounds.grace, BOUNDS.grace);
    assert_eq!(killed.bounds.merge, BOUNDS.merge);
    assert_eq!(killed.bounds.output, BOUNDS.output);
    let seeds = killed.directory.join("seeds");
    let argv = std::fs::read_to_string(seeds.join("argv")).unwrap();
    let expected = [
        "--seeds".to_owned(),
        "campaign".to_owned(),
        seeds.display().to_string(),
        killed.directory.display().to_string(),
        ":kept".to_owned(),
    ];
    assert_eq!(argv.lines().collect::<Vec<_>>(), expected);
    drop(killed);
    let next = started(&plan, &worker, PEN);
    assert_eq!(
        next.as_ref().map(|next| next.number).ok(),
        Some(1),
        "{:?}",
        next.as_ref().err()
    );
    let next = next.unwrap();
    assert_eq!(
        names(&next.directory.join("seeds")),
        ["argv", "upload.input"]
    );
    let stored = read(&plan.root).unwrap().unwrap();
    let last = Last {
        run: 1,
        build: build(),
    };
    assert_eq!((stored.next, stored.last), (2, Some(last)));
}

/// The run number is stored before its directory is made: a start that
/// fails at the creation of `runs/0`, which a directory already holds,
/// has stored the next number 1, and the next start takes run 1 and
/// writes its seeds there.
#[test]
fn the_run_number_is_stored_before_its_directory_is_made() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    std::fs::create_dir_all(plan.root.join("runs/0")).unwrap();
    let cut = started(&plan, &worker, PEN).map(|session| session.number);
    assert!(matches!(cut, Err(Error::Held(_))), "{cut:?}");
    assert_eq!(read(&plan.root).unwrap().unwrap().next, 1);
    assert!(names(&plan.root.join("runs/0")).is_empty());
    let next = started(&plan, &worker, PEN).unwrap();
    assert_eq!(next.number, 1);
    assert_eq!(
        names(&next.directory.join("seeds")),
        ["argv", "upload.input"]
    );
}

/// A `fuzz.json` that does not parse as a record is held, and a valid
/// record padded past the size bound is unreadable, at the start and in
/// the status. The refused start has recovered the corpus by then, as
/// every start does first, and it stores no run number, makes no run
/// directory and runs no seed writer; the record's bytes stay.
#[test]
fn an_unreadable_record_holds_the_start_and_stays() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    let path = plan.root.join("fuzz.json");
    let mut padded = br#"{"next": 1, "failed_merges": 0}"#.to_vec();
    padded.resize(usize::try_from(RECORD_BOUND).unwrap(), b' ');
    std::fs::write(&path, &padded).unwrap();
    assert!(status(&plan.root).unwrap().is_some());
    padded.push(b' ');
    let expected = |found: &Result<u64, Error>, oversized: bool| match found {
        Err(Error::Unreadable(crate::store::Unreadable::Oversize)) => oversized,
        Err(Error::Held(_)) => !oversized,
        _ => false,
    };
    for (bytes, oversized) in [(b"{\"next\": -1}".to_vec(), false), (padded, true)] {
        std::fs::write(&path, &bytes).unwrap();
        let refused = started(&plan, &worker, PEN).map(|session| session.number);
        assert!(expected(&refused, oversized), "{refused:?}");
        let status = status(&plan.root).map(|_| 0);
        assert!(expected(&status, oversized), "{status:?}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(names(&plan.root), ["corpus", "fuzz.json"]);
    }
}

/// `fuzz-status` reads `fuzz.json` while a run holds the root's lock and
/// leaves every file of the root as it was: a cut corpus swap stays, and
/// `fuzz.json` keeps its inode, which a rewrite of the same bytes would
/// change. A root no run has written has no status.
#[test]
fn the_status_reads_fuzz_json_and_writes_nothing_while_a_run_holds_the_root() {
    let case = Case::new();
    let root = case.root.join("fuzz");
    let _claimed = claim(&root).unwrap();
    assert_eq!(status(&root).unwrap(), None);
    assert!(names(&root).is_empty());
    let record = Record {
        next: 7,
        failed_merges: 2,
        ..Record::default()
    };
    store(&root, &record).unwrap();
    for directory in ["corpus.old", "corpus.new/x"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    let inode = |path: &Path| std::os::unix::fs::MetadataExt::ino(&path.metadata().unwrap());
    let (before, record_inode) = (snapshot(&root), inode(&root.join("fuzz.json")));
    assert_eq!(
        status(&root).unwrap(),
        Some(json!({
            "next": 7, "failed_merges": 2, "last": null, "alarm": false, "keys": {},
            "control": {"caught": 0, "missed": 0},
        }))
    );
    assert_eq!(snapshot(&root), before);
    assert_eq!(inode(&root.join("fuzz.json")), record_inode);
}

/// A merge that exited with `code` and left the cause `cause`.
fn merge(code: i32, cause: Option<&str>) -> Option<Merged> {
    use std::os::unix::process::ExitStatusExt;
    Some(Merged {
        ended: Ended {
            status: Some(ExitStatus::from_raw(code << 8)),
            killed: None,
            out_of_memory: false,
            counts: None,
            output: "merge.stderr".into(),
            stopped: false,
            filed: None,
        },
        cause: cause.map(str::to_owned),
        files: 1,
        attempts: Some(1),
    })
}

/// `run.json` reports the corpus the workers start from and the time the
/// start completed. A start that files a killed run's failure removes the
/// failing input's corpus copy before `corpus.before` is counted. The
/// seed writer of the second start takes over a second and then notes
/// the time, and `started` is no earlier than that note, which a stamp
/// taken before the seed writer ended precedes by a second.
#[test]
fn a_runs_record_takes_its_corpus_count_and_start_after_the_leftover_intake() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let mut slow = worker_with(&case, "slow.sh", PASSING, COPYING, "exit 0");
    let done = case.root.join("done");
    let seeds = format!("#!/bin/sh\nsleep 1.1\ndate +%s > '{}'\n", done.display());
    slow.program = executable(&case, "seeds.sh", &seeds).into();
    let _claimed = claim(&plan.root).unwrap();
    let killed = started(&plan, &worker, PEN).unwrap();
    let artifacts = killed.directory.join("w0");
    std::fs::create_dir(&artifacts).unwrap();
    std::fs::write(artifacts.join("first-failure.input"), "i").unwrap();
    std::fs::write(artifacts.join("first-failure.claim"), "a claim\n").unwrap();
    std::fs::write(plan.root.join("corpus/same"), "i").unwrap();
    std::fs::write(plan.root.join("corpus/other"), "o").unwrap();
    drop(killed);
    let session = opened(&plan, &slow, PEN).unwrap();
    session.advance(None).unwrap();
    let directory = session.directory.clone();
    let ran = Ran {
        ending: "deadline",
        workers: Vec::new(),
        after: 1,
        merge: None,
    };
    session.closed(&ran, Ok(())).unwrap();
    let record = json(&directory.join("run.json"));
    assert_eq!(record["corpus"]["before"], 1);
    let done: u64 = std::fs::read_to_string(done)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(record["started"].as_u64().unwrap() >= done, "{record}");
}

/// A failed closing verification is recorded in `run.json` and fails the
/// run as held, once `fuzz.json` is replaced with the run's count of
/// failed merges, and the root stays usable: the next run starts with the
/// next number.
#[test]
fn a_failed_closing_check_is_recorded_and_the_root_stays_usable() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    let _claimed = claim(&plan.root).unwrap();
    let session = started(&plan, &worker, PEN).unwrap();
    let directory = session.directory.clone();
    let ran = Ran {
        ending: "deadline",
        workers: Vec::new(),
        after: 0,
        merge: merge(1, Some("the merge ended with exit status: 1")),
    };
    let closed = session.closed(&ran, Err("the archive after the run: changed".into()));
    assert!(
        matches!(&closed, Err(Error::Held(reason)) if reason.ends_with("changed")),
        "{closed:?}"
    );
    let record = json(&directory.join("run.json"));
    assert_eq!(record["archive"], "the archive after the run: changed");
    assert_eq!(record["build"], build().as_str());
    assert_eq!(read(&plan.root).unwrap().unwrap().failed_merges, 1);
    assert_eq!(started(&plan, &worker, PEN).unwrap().number, 1);
}

/// The count of failed merges in a row, from two: an adopted merge sets
/// it to 0; an unadopted merge of a run that reached its deadline adds 1,
/// whether it exited nonzero or wrote nothing; a merge a stop ended, and
/// a run a stop kept from its merge, leave it at 2. Each record names the
/// merge's adoption and cause.
#[test]
fn the_failed_merge_count_follows_each_merge_end() {
    let _processes = processes();
    let cases = [
        ("deadline", merge(0, None), 0, Some(true)),
        ("deadline", merge(1, Some("exited 1")), 3, Some(false)),
        ("deadline", merge(0, Some("empty")), 3, Some(false)),
        ("signal", merge(0, Some("a stop came")), 2, Some(false)),
        ("signal", None, 2, None),
    ];
    for (ending, merged, failed, adopted) in cases {
        let case = Case::new();
        let plan = plan(&case, 1);
        let worker = worker(&case, "worker.sh", PASSING, COPYING);
        let _claimed = claim(&plan.root).unwrap();
        let two = Record {
            next: 0,
            failed_merges: 2,
            ..Record::default()
        };
        store(&plan.root, &two).unwrap();
        let session = started(&plan, &worker, PEN).unwrap();
        let cause = merged.as_ref().map(|merged| merged.cause.clone());
        let ran = Ran {
            ending,
            workers: Vec::new(),
            after: 0,
            merge: merged,
        };
        let record = session.closed(&ran, Ok(())).unwrap();
        assert_eq!(read(&plan.root).unwrap().unwrap().failed_merges, failed);
        assert_eq!(record["merge"]["adopted"].as_bool(), adopted);
        assert_eq!(
            record["merge"]["cause"].as_str().map(str::to_owned),
            cause.flatten()
        );
    }
}

/// The counts line kept is the last line the `campaign` target printed,
/// whatever the lines after it, and a file without one keeps none.
#[test]
fn the_last_counts_line_is_kept() {
    let case = Case::new();
    let log = case.root.join("w0.stderr");
    std::fs::write(
        &log,
        "fuzz: campaign executed=1\n#2 NEW cov: 3\nfuzz: campaign executed=9 pass=8\n\
         fuzz: audited and tore down planted\nDone 9 runs\n",
    )
    .unwrap();
    assert_eq!(
        counts(&log).as_deref(),
        Some("fuzz: campaign executed=9 pass=8")
    );
    std::fs::write(&log, "#2 NEW cov: 3\n").unwrap();
    assert_eq!(counts(&log), None);
}

/// The counts line is read from the last 64 KiB of the output: a later
/// line past the first 64 KiB is the one kept, and a line before the last
/// 64 KiB is read as none.
#[test]
fn the_counts_line_is_read_from_the_last_64_kib() {
    let case = Case::new();
    let log = case.root.join("w0.stderr");
    let filler = "#2 NEW cov: 3\n".repeat(6_000);
    std::fs::write(
        &log,
        format!("fuzz: campaign executed=1\n{filler}fuzz: campaign executed=2\n"),
    )
    .unwrap();
    assert_eq!(counts(&log).as_deref(), Some("fuzz: campaign executed=2"));
    std::fs::write(&log, format!("fuzz: campaign executed=1\n{filler}")).unwrap();
    assert_eq!(counts(&log), None);
    let line = "fuzz: campaign executed=3\n";
    let edge = format!("{line}{}", "x".repeat(65_536 - line.len()));
    std::fs::write(&log, &edge).unwrap();
    assert_eq!(counts(&log).as_deref(), Some("fuzz: campaign executed=3"));
    std::fs::write(&log, format!("{edge}x")).unwrap();
    assert_eq!(counts(&log), None);
}

/// A FIFO with no writer at a log's name reads as no counts line, and
/// the read returns at once.
#[test]
fn a_fifo_at_a_logs_name_reads_as_no_counts_line() {
    let _processes = processes();
    let case = Case::new();
    let log = case.root.join("w0.stderr");
    let made = std::process::Command::new("mkfifo")
        .arg(&log)
        .status()
        .unwrap();
    assert!(made.success());
    let (sent, received) = std::sync::mpsc::channel();
    let path = log.clone();
    std::thread::spawn(move || sent.send(counts(&path)).unwrap());
    let read = received.recv_timeout(Duration::from_secs(10));
    assert_eq!(read, Ok(None));
}

/// A second command on a root another command holds ends busy before it
/// writes a file there.
#[test]
fn a_second_command_on_the_root_ends_busy_before_it_writes() {
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.cgroup = PathBuf::from("/sys/fs/cgroup/absent");
    let _claimed = claim(&plan.root).unwrap();
    let ran = fuzz(&plan);
    assert!(
        matches!(ran, Err(Error::Store(crate::store::Error::Busy))),
        "{ran:?}"
    );
    assert!(names(&plan.root).is_empty());
}

/// A command whose cgroup root another command holds ends busy before it
/// writes a file under its root.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_second_command_on_the_cgroup_root_ends_busy_before_it_writes() {
    let _processes = processes();
    let host = Delegation::new("fuzz-busy");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.cgroup = host.root.clone();
    let _held = pen::claim(&host.root).unwrap().unwrap();
    let ran = fuzz(&plan);
    assert!(
        matches!(ran, Err(Error::Store(crate::store::Error::Busy))),
        "{ran:?}"
    );
    assert!(names(&plan.root).is_empty());
}

/// The archive is verified before the run takes a number: an archive
/// whose worker differs from its build record, and a directory that
/// holds no archive, each end the command with no `fuzz.json`, no corpus
/// and no run directory.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_archive_that_fails_verification_starts_no_run() {
    let _processes = processes();
    let host = Delegation::new("fuzz-archive");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.cgroup = host.root.clone();
    crate::archive::publish(&plan.archive, &crate::archive::publish_tests::built()).unwrap();
    let program = plan.archive.join("worker");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut bytes = std::fs::read(&program).unwrap();
    bytes.push(0);
    std::fs::write(&program, bytes).unwrap();
    let ran = fuzz(&plan);
    assert!(
        matches!(&ran, Err(error) if error.to_string().contains("worker differs from its build record")),
        "{ran:?}"
    );
    assert!(names(&plan.root).is_empty());
    std::fs::remove_dir_all(&plan.archive).unwrap();
    crate::store::create_dir(&plan.archive).unwrap();
    let ran = fuzz(&plan);
    assert!(
        matches!(&ran, Err(error) if error.to_string().contains("build")),
        "{ran:?}"
    );
    assert!(names(&plan.root).is_empty());
}

/// `/usr/bin/false` fails every invocation. The `corpus merge` reason
/// distinguishes a `-merge=1` probe failure from other rejections.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_archive_whose_worker_refuses_a_merge_starts_no_run() {
    let _processes = processes();
    let host = Delegation::new("fuzz-refused-merge");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.cgroup = host.root.clone();
    let built = crate::archive::publish_tests::built_from(Path::new("/usr/bin/false"));
    crate::archive::publish(&plan.archive, &built).unwrap();
    let ran = fuzz(&plan);
    assert!(
        matches!(&ran, Err(Error::Rejected(reason)) if reason.contains("corpus merge")),
        "{ran:?}"
    );
    assert!(names(&plan.root).is_empty());
}

/// A file a worker adds to the corpus is in the corpus the next run's
/// worker reads, when no merge replaced it: the first run's merge fails
/// here. Each run's record names each worker's exit and last counts line.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_file_a_worker_adds_is_in_the_next_runs_corpus() {
    let _processes = processes();
    let host = Delegation::new("fuzz-kept");
    let case = Case::new();
    let plan = plan(&case, 2);
    let adding = worker(
        &case,
        "adding.sh",
        &format!("printf x > \"$corpus/added-$$\"\n{PASSING}"),
        "exit 1",
    );
    let first = run(&plan, &adding, &host, BOUNDS);
    assert_eq!(first["corpus"]["before"], 0);
    assert_eq!(first["corpus"]["after"], 2);
    let worker_record = |output: &str| {
        json!({
            "code": 0, "signal": null, "killed": null, "out_of_memory": false,
            "key": null, "rerun": null,
            "counts": "fuzz: campaign executed=3 pass=3", "output": output,
        })
    };
    assert_eq!(
        first["workers"],
        json!([worker_record("w0.stderr"), worker_record("w1.stderr")])
    );
    let listing = worker(
        &case,
        "listing.sh",
        &format!("ls \"$corpus\" > \"$artifacts/listing\"\n{PASSING}"),
        "exit 1",
    );
    let second = run(&plan, &listing, &host, BOUNDS);
    assert_eq!(second["run"], 1);
    assert_eq!(second["corpus"]["before"], 2);
    let listed = std::fs::read_to_string(plan.root.join("runs/1/w0/listing")).unwrap();
    assert_eq!(
        listed
            .lines()
            .filter(|name| name.starts_with("added-"))
            .count(),
        2
    );
}

/// A merge that writes a file and exits 1, and a merge that exits 0 with
/// only a directory in `corpus.new`, each leave the corpus as it was,
/// name their cause in `run.json` and add to the failed merges in a row;
/// a merge that writes a file replaces the corpus with what it wrote and
/// sets that count to 0. The first run pins the seed writer's, the
/// workers' and the merge's command lines and working directories, and
/// the environment each receives: the approved `KEPT` alone. The workers'
/// and the merge's `-rss_limit_mb` is 48, three quarters of the pen's
/// 64 MiB.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_merge_replaces_the_corpus_only_when_it_exits_0_with_a_file() {
    let _processes = processes();
    let host = Delegation::new("fuzz-merge");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.seconds = 2;
    let adding = format!("printf x > \"$corpus/added-$$\"\n{PASSING}");
    let cases = [
        (
            "failing.sh",
            "printf p > \"$new/partial\"\nexit 1",
            "the merge ended with exit status: 1",
            1,
        ),
        (
            "empty.sh",
            "mkdir \"$new/nested\"\nexit 0",
            "the merge left no regular file alone in corpus.new",
            2,
        ),
    ];
    for (run_number, (name, merge, cause, failed)) in (1..).zip(cases) {
        let corpus = plan.root.join("corpus");
        let before = if corpus.exists() {
            names(&corpus)
        } else {
            Vec::new()
        };
        let record = run(&plan, &worker(&case, name, &adding, merge), &host, BOUNDS);
        assert_eq!(record["merge"]["adopted"], false, "{name}");
        assert_eq!(record["merge"]["cause"], cause, "{name}");
        assert_eq!(record["corpus"]["merged"], run_number, "{name}");
        let kept = names(&plan.root.join("corpus"));
        assert_eq!(kept.len(), run_number, "{name}");
        assert!(before.iter().all(|file| kept.contains(file)), "{name}");
        assert!(kept.iter().all(|file| file.starts_with("added-")), "{name}");
        let byte = |file: &String| std::fs::read(corpus.join(file)).unwrap() == b"x";
        assert!(kept.iter().all(byte), "{name}");
        assert_eq!(read(&plan.root).unwrap().unwrap().failed_merges, failed);
        assert!(!plan.root.join("corpus.new").exists(), "{name}");
    }
    let run0 = plan.root.join("runs/0");
    let lines = |path: &str| -> Vec<String> {
        let text = std::fs::read_to_string(run0.join(path)).unwrap();
        text.lines().map(str::to_owned).collect()
    };
    let (root, run0_text) = (plan.root.display(), run0.display());
    let seeds = format!("{run0_text}/seeds");
    assert_eq!(
        lines("seeds/argv"),
        [
            "--seeds",
            "campaign",
            &seeds,
            &run0_text.to_string(),
            ":kept"
        ]
    );
    let w0 = format!("{run0_text}/w0");
    assert_eq!(
        lines("w0.argv"),
        [
            "--fuzz",
            "campaign",
            "--artifacts",
            &w0,
            "--",
            "-max_len=65536",
            "-timeout=60",
            "-rss_limit_mb=48",
            &format!("-artifact_prefix={w0}/"),
            "-max_total_time=2",
            &format!("{root}/corpus"),
            &seeds,
            &run0_text.to_string(),
            ":kept",
        ]
    );
    let artifacts = format!("{run0_text}/merge");
    assert_eq!(
        lines("merge.argv"),
        [
            "--fuzz",
            "campaign",
            "--artifacts",
            &artifacts,
            "--",
            "-max_len=65536",
            "-timeout=60",
            "-rss_limit_mb=48",
            &format!("-artifact_prefix={artifacts}/"),
            "-merge=1",
            &format!("-merge_control_file={run0_text}/merge.txt"),
            &format!("{root}/corpus.new"),
            &format!("{root}/corpus"),
            &seeds,
            &run0_text.to_string(),
            ":kept",
        ]
    );
    let merging = worker(
        &case,
        "merging.sh",
        &adding,
        "printf m > \"$new/merged\"\nexit 0",
    );
    let record = run(&plan, &merging, &host, BOUNDS);
    assert_eq!(record["merge"]["adopted"], true);
    assert_eq!(record["merge"]["cause"], Value::Null);
    assert_eq!(record["corpus"]["after"], 3);
    assert_eq!(record["corpus"]["merged"], 1);
    assert_eq!(names(&plan.root.join("corpus")), ["merged"]);
    assert_eq!(
        std::fs::read(plan.root.join("corpus/merged")).unwrap(),
        b"m"
    );
    assert_eq!(names(&plan.root), ["corpus", "fuzz.json", "runs"]);
    assert_eq!(read(&plan.root).unwrap().unwrap().failed_merges, 0);
}

/// A SIGINT pending when the workers would start, as one that arrived
/// while the seeds were written, starts no worker and no merge, and the
/// run's record says a signal ended it.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_signal_pending_at_the_start_starts_no_worker_and_no_merge() {
    let _processes = processes();
    let host = Delegation::new("fuzz-pending");
    let case = Case::new();
    let plan = plan(&case, 2);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    crate::sys::block_interruptions().unwrap();
    crate::sys::interrupt(libc::SIGINT).unwrap();
    let record = run(&plan, &worker, &host, BOUNDS);
    assert_eq!(record["ending"], "signal");
    assert_eq!(record["workers"], json!([]));
    assert_eq!(record["merge"], Value::Null);
    assert_eq!(names(&plan.root.join("runs/0")), ["run.json", "seeds"]);
}

/// A stop that comes while the workers run reaches each of them as
/// SIGTERM, and no merge follows. A job that a later run's thread
/// reaches once that run's stop is set starts nothing: `waited` returns
/// `None` and creates no output file. A stop that comes after that
/// check, while the thread creates the job's output file, withholds the
/// go byte: the worker, which would write `argv` and exit 0, never runs,
/// and `waited` returns `None` once the gate has left the slot. Each
/// worker here notes its start and the SIGTERM it traps; the test marks
/// the run stopped, as the monitor does when it takes SIGINT or SIGTERM,
/// once both have started. The test's gate keeps the signal mask of the
/// thread that starts it, so this test leaves SIGTERM unblocked, as the
/// command's gate does for each worker.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_stop_during_the_run_reaches_each_worker_and_no_merge_follows() {
    let _processes = processes();
    let host = Delegation::new("fuzz-stop");
    let case = Case::new();
    let mut plan = plan(&case, 2);
    plan.seconds = 30;
    let quick = worker(&case, "quick.sh", PASSING, COPYING);
    let worker = worker(
        &case,
        "worker.sh",
        "trap 'printf x > \"$artifacts/stopped\"; exit 72' TERM\n\
         printf x > \"$artifacts/up\"\nwhile :; do sleep 0.05; done",
        COPYING,
    );
    let _claimed = claim(&plan.root).unwrap();
    let mut session = started(&plan, &worker, PEN).unwrap();
    session.bounds.grace = Duration::from_secs(1);
    let ran = std::thread::scope(|scope| {
        scope.spawn(|| {
            let up = [0, 1].map(|index| session.directory.join(format!("w{index}/up")));
            awaited(&up, &session.stop);
            session.stop.set("signal").unwrap();
        });
        session.fuzzed(&host.root()).unwrap()
    });
    assert_eq!(ran.ending, "signal");
    assert!(ran.merge.is_none());
    for (index, ended) in ran.workers.iter().enumerate() {
        assert_eq!(ended.status.and_then(|status| status.code()), Some(72));
        assert!(session.directory.join(format!("w{index}/stopped")).exists());
    }
    assert!(!session.directory.join("merge.stderr").exists());
    assert!(!session.directory.join("merge").exists());
    let late = started(&plan, &quick, PEN).unwrap();
    late.stop.set("signal").unwrap();
    let pen = Arc::new(Pen::create(&host.root(), 7, PEN).unwrap());
    let artifacts = late.directory.join("w0");
    crate::store::create_dir(&artifacts).unwrap();
    let job = Job {
        arguments: super::bounded(&artifacts, PEN.memory, []),
        log: late.directory.join("w0.stderr"),
        limit: Instant::now() + Duration::from_secs(30),
    };
    let withheld = late.waited(&pen, &job, &Mutex::new(None)).unwrap();
    assert!(withheld.is_none());
    assert!(!late.directory.join("w0.argv").exists());
    assert!(!late.directory.join("w0.stderr").exists());
    let raced = started(&plan, &quick, PEN).unwrap();
    let artifacts = raced.directory.join("w0");
    crate::store::create_dir(&artifacts).unwrap();
    let job = Job {
        arguments: super::bounded(&artifacts, PEN.memory, []),
        log: raced.directory.join("w0.stderr"),
        limit: Instant::now() + Duration::from_secs(30),
    };
    let (reached, wake) = std::sync::mpsc::channel();
    let (set, done) = std::sync::mpsc::channel();
    let mut first = Some((reached, done));
    let prior = crate::step::install(Some(crate::step::Script {
        observe: Some(Box::new(move |step| {
            if step == Step::Open
                && let Some((reached, done)) = first.take()
            {
                reached.send(()).unwrap();
                done.recv().unwrap();
            }
        })),
        ..Default::default()
    }));
    let (stop, slot) = (&raced.stop, Mutex::new(None));
    let ended = std::thread::scope(|scope| {
        scope.spawn(move || {
            wake.recv().unwrap();
            stop.set("signal").unwrap();
            set.send(()).unwrap();
        });
        raced.waited(&pen, &job, &slot)
    });
    crate::step::install(prior);
    assert!(!raced.directory.join("w0.argv").exists(), "{ended:?}");
    assert!(matches!(ended, Ok(None)), "{ended:?}");
    // The output file shows the call passed its first check and reached
    // the gate, and the empty slot that the gate was reaped.
    assert!(raced.directory.join("w0.stderr").exists());
    assert!(slot.lock().unwrap().is_none());
    Arc::into_inner(pen).unwrap().remove().unwrap();
}

/// A SIGINT the command takes while its workers run stops the run: each
/// worker gets SIGTERM, a worker still running a grace period later is
/// killed, and no merge follows. The test blocks the signals as `fuzz`
/// does and sends SIGINT to its own thread, which runs the monitor, once
/// both workers have started. The test's gate keeps the blocked mask, so the
/// workers stay until the kill one second after the stop, well inside the
/// run's 30 seconds.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_signal_during_the_run_stops_the_workers_and_no_merge_follows() {
    let _processes = processes();
    let host = Delegation::new("fuzz-signal");
    let case = Case::new();
    let mut plan = plan(&case, 2);
    plan.seconds = 30;
    let worker = worker(
        &case,
        "worker.sh",
        "printf x > \"$artifacts/up\"\nsleep 60",
        COPYING,
    );
    crate::sys::block_interruptions().unwrap();
    let _claimed = claim(&plan.root).unwrap();
    let mut session = started(&plan, &worker, PEN).unwrap();
    session.bounds.grace = Duration::from_secs(1);
    let monitor = crate::sys::this_thread();
    let up = [0, 1].map(|index| session.directory.join(format!("w{index}/up")));
    let started = Instant::now();
    let ran = std::thread::scope(|scope| {
        scope.spawn(|| {
            awaited(&up, &session.stop);
            crate::sys::interrupt_thread(monitor, libc::SIGINT).unwrap();
        });
        session.fuzzed(&host.root()).unwrap()
    });
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(ran.ending, "signal");
    assert!(ran.merge.is_none());
    let killed: Vec<_> = ran.workers.iter().map(|ended| ended.killed).collect();
    assert_eq!(killed, [Some("time"), Some("time")]);
    assert!(!session.directory.join("merge").exists());
}

/// The byte check covers the archive's canonical path, which the worker
/// starts from and the merge's shell line receives: an archive reached
/// through a symlink to a directory whose name holds a space is refused
/// before the run takes a number. An archive reached through a symlink to
/// a run directory of the root, which pruning would remove, is refused
/// with every file of the root as it was, and it still verifies.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn an_archive_whose_canonical_path_holds_a_refused_byte_is_rejected() {
    let _processes = processes();
    let host = Delegation::new("fuzz-canonical");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.cgroup = host.root.clone();
    let spaced = case.root.join("archive dir");
    crate::archive::publish(&spaced, &crate::archive::publish_tests::built()).unwrap();
    std::os::unix::fs::symlink(&spaced, &plan.archive).unwrap();
    let ran = fuzz(&plan);
    assert!(
        matches!(&ran, Err(Error::Rejected(reason)) if reason.contains("archive dir/worker")),
        "{ran:?}"
    );
    assert!(names(&plan.root).is_empty());
    let inside = plan.root.join("runs/0/archive");
    crate::store::create_dirs(inside.parent().unwrap()).unwrap();
    crate::archive::publish(&inside, &crate::archive::publish_tests::built()).unwrap();
    std::fs::remove_file(&plan.archive).unwrap();
    std::os::unix::fs::symlink(&inside, &plan.archive).unwrap();
    let before = snapshot(&plan.root);
    let ran = fuzz(&plan);
    assert!(
        matches!(&ran, Err(Error::Rejected(reason)) if reason.contains("inside the fuzz root")),
        "{ran:?}"
    );
    assert_eq!(snapshot(&plan.root), before);
    let mut kept = crate::archive::Archive::load(&inside).unwrap();
    kept.verify().unwrap().finish().unwrap();
}

/// `fuzz` rejects a root at or below the archive, named directly or
/// through a symlink to the archive, and a root whose creation would add
/// an archive entry before its `..` components lead outside. `fuzz`
/// rejects each root before creating any directory, preserving the
/// archive's recorded entries.
#[test]
fn a_root_inside_the_archive_is_refused_before_it_is_created() {
    let _processes = processes();
    let case = Case::new();
    let mut plan = plan(&case, 1);
    crate::archive::publish(&plan.archive, &crate::archive::publish_tests::built()).unwrap();
    let linked = case.root.join("linked");
    std::os::unix::fs::symlink(&plan.archive, &linked).unwrap();
    let before = snapshot(&plan.archive);
    for root in [
        plan.archive.join("lib/fuzz"),
        plan.archive.clone(),
        linked.join("lib/fuzz/deeper"),
        plan.archive.join("lib/new/../../../fuzz"),
    ] {
        plan.root = root.clone();
        let ran = fuzz(&plan);
        assert!(
            matches!(&ran, Err(Error::Rejected(reason)) if reason.contains("inside the archive")),
            "{root:?}: {ran:?}"
        );
        assert_eq!(snapshot(&plan.archive), before, "{root:?}");
    }
    let mut kept = crate::archive::Archive::load(&plan.archive).unwrap();
    kept.verify().unwrap().finish().unwrap();
}

/// A stop that comes during the merge keeps the corpus, whatever the
/// merge wrote and however it exited, and leaves the count of
/// consecutive merges that kept the corpus as it was. The merge here
/// writes a file, notes its start and exits 0 on SIGTERM; the test marks
/// the run stopped once the merge has started. The test's gate keeps the
/// signal mask of the thread that starts it, so this test leaves SIGTERM
/// unblocked.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_stop_during_the_merge_keeps_the_corpus_and_the_failed_merge_count() {
    let _processes = processes();
    let host = Delegation::new("fuzz-merge-stop");
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(
        &case,
        "worker.sh",
        &format!("printf x > \"$corpus/added\"\n{PASSING}"),
        "printf m > \"$new/merged\"\ntrap 'exit 0' TERM\n\
         printf x > \"$artifacts.up\"\nwhile :; do sleep 0.05; done",
    );
    let _claimed = claim(&plan.root).unwrap();
    let failed = Record {
        next: 0,
        failed_merges: 2,
        ..Record::default()
    };
    store(&plan.root, &failed).unwrap();
    let session = started(&plan, &worker, PEN).unwrap();
    let up = session.directory.join("merge.up");
    let ran = std::thread::scope(|scope| {
        scope.spawn(|| {
            awaited(std::slice::from_ref(&up), &session.stop);
            session.stop.set("signal").unwrap();
        });
        session.fuzzed(&host.root()).unwrap()
    });
    assert_eq!(ran.ending, "signal");
    let merged = ran.merge.as_ref().unwrap();
    assert_eq!(
        merged.ended.status.and_then(|status| status.code()),
        Some(0)
    );
    assert_eq!(
        merged.cause.as_deref(),
        Some("a stop came during the merge")
    );
    assert_eq!(names(&plan.root.join("corpus")), ["added"]);
    assert!(!plan.root.join("corpus.new").exists());
    session.closed(&ran, Ok(())).unwrap();
    assert_eq!(read(&plan.root).unwrap().unwrap().failed_merges, 2);
}

/// A worker whose thread fails stops the other workers, and a worker that
/// stays after the stop's SIGTERM is killed one grace period after the
/// stop, before the deadline. Worker 1 waits for worker 0 to start, makes
/// a child cgroup in its pen and exits, so its pen's removal fails its
/// thread; worker 0 ignores SIGTERM and would sleep past the run's 30
/// seconds. The grace here is one second.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_failed_worker_stops_the_others_within_the_grace() {
    let _processes = processes();
    let host = Delegation::new("fuzz-failed");
    let case = Case::new();
    let mut plan = plan(&case, 2);
    plan.seconds = 30;
    let worker = worker(
        &case,
        "worker.sh",
        "case $artifacts in\n\
         */w0) trap '' TERM; printf x > \"$artifacts/up\"; sleep 60;;\n\
         *) while [ ! -e w0/up ]; do sleep 0.05; done\n\
         mkdir \"/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/kept\";;\n\
         esac",
        COPYING,
    );
    let _claimed = claim(&plan.root).unwrap();
    let mut session = started(&plan, &worker, PEN).unwrap();
    session.bounds.grace = Duration::from_secs(1);
    let started = Instant::now();
    let ran = session.fuzzed(&host.root());
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.contains("busy")),
        "{:?}",
        ran.as_ref().err()
    );
    assert!(session.directory.join("w0/up").exists());
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}

/// A fuzz worker whose gate fails before worker startup holds the run.
/// The worker never ran, so the failed-worker count stays zero and the
/// root holds no finding.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_fuzz_worker_whose_gate_failed_holds_the_run() {
    let _processes = processes();
    let host = Delegation::new("fuzz-gate");
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(&case, "worker.sh", PASSING, COPYING);
    std::fs::write(&worker.gate, failing_gate("*-max_total_time=*")).unwrap();
    crate::sys::block_interruptions().unwrap();
    let _claimed = claim(&plan.root).unwrap();
    let session = started(&plan, &worker, PEN).unwrap();
    let ran = session.fuzzed(&host.root());
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.contains("os error 2")),
        "{:?}",
        ran.as_ref().err()
    );
    assert_eq!(session.failed.load(Ordering::Relaxed), 0);
    assert!(read(&plan.root).unwrap().unwrap().keys.is_empty());
    assert!(!plan.root.join("findings.jsonl").exists());
}

/// A worker whose standard error passes its bound has its pen killed, and
/// its record names the bound. The bound here is 1 MiB and the worker
/// writes 2 MB, then sleeps past the run's 30 seconds and its grace of
/// one. A worker whose output size the monitor cannot read, here one that
/// removes its own output file, counts as past the bound.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_past_its_output_bound_has_its_pen_killed() {
    let _processes = processes();
    let host = Delegation::new("fuzz-output");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.seconds = 30;
    let unlinking = worker(
        &case,
        "unlinking.sh",
        "rm \"$artifacts.stderr\"\nsleep 600",
        COPYING,
    );
    let worker = worker(
        &case,
        "worker.sh",
        "head -c 2000000 /dev/zero >&2\nsleep 600",
        COPYING,
    );
    let started = Instant::now();
    let record = run(
        &plan,
        &worker,
        &host,
        Bounds {
            output: 1 << 20,
            grace: Duration::from_secs(1),
            ..BOUNDS
        },
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(record["workers"][0]["killed"], "output");
    assert_eq!(record["workers"][0]["signal"], libc::SIGKILL);
    let started = Instant::now();
    let grace = Bounds {
        grace: Duration::from_secs(1),
        ..BOUNDS
    };
    let unread = run(&plan, &unlinking, &host, grace);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(unread["workers"][0]["killed"], "output");
}

/// Worker 0 uses a 100 MiB `dd` buffer to trigger a cgroup OOM kill.
/// Worker 1 serves as the control for per-worker attribution; the record
/// lists it after worker 0's replacement when one starts before the
/// deadline, so its output file selects it.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_the_kernel_kills_for_memory_has_the_kill_recorded() {
    let _processes = processes();
    let host = Delegation::new("fuzz-memory");
    let case = Case::new();
    let plan = plan(&case, 2);
    let worker = worker(
        &case,
        "worker.sh",
        &format!(
            "case $artifacts in */w0) dd if=/dev/zero of=/dev/null bs=100M count=1;; esac\n\
             {PASSING}"
        ),
        COPYING,
    );
    let record = run(&plan, &worker, &host, BOUNDS);
    assert_eq!(record["workers"][0]["out_of_memory"], true);
    assert_eq!(record["workers"][0]["signal"], libc::SIGKILL);
    assert_eq!(record["workers"][0]["killed"], Value::Null);
    let workers = record["workers"].as_array().unwrap();
    let control = workers
        .iter()
        .find(|worker| worker["output"] == "w1.stderr");
    let control = control.expect("worker 1 ran");
    assert_eq!(control["out_of_memory"], false);
    assert_eq!(control["code"], 0);
}

/// A worker that runs past the deadline by its grace has its pen killed,
/// and one that ends inside the grace is left to end, with its exit
/// recorded; the merge still runs. The run here lasts three seconds with
/// a grace of three; worker 0 sleeps 30 seconds and worker 1 4.5, past
/// either term alone, then exits 1.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_past_the_deadline_has_its_pen_killed() {
    let _processes = processes();
    let host = Delegation::new("fuzz-deadline");
    let case = Case::new();
    let mut plan = plan(&case, 2);
    plan.seconds = 3;
    let worker = worker(
        &case,
        "worker.sh",
        "case $artifacts in */w0) sleep 30;; *) sleep 4.5; exit 1;; esac\nexit 0",
        COPYING,
    );
    let started = Instant::now();
    let record = run(
        &plan,
        &worker,
        &host,
        Bounds {
            grace: Duration::from_secs(3),
            ..BOUNDS
        },
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(record["workers"][0]["killed"], "time");
    assert_eq!(record["workers"][0]["signal"], libc::SIGKILL);
    assert_eq!(record["workers"][1]["killed"], Value::Null);
    assert_eq!(record["workers"][1]["code"], 1);
    assert_eq!(record["ending"], "deadline");
    assert_eq!(
        record["merge"]["cause"],
        "the merge left no regular file alone in corpus.new"
    );
}

/// A merge that runs past its bound is killed and not adopted, whatever
/// it wrote, and the corpus stays as it was. The bound here is one
/// second and the merge writes a file, then sleeps 30 seconds and exits
/// 0.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_merge_past_its_bound_is_killed_and_not_adopted() {
    let _processes = processes();
    let host = Delegation::new("fuzz-merge-bound");
    let case = Case::new();
    let plan = plan(&case, 1);
    let worker = worker(
        &case,
        "worker.sh",
        &format!("printf x > \"$corpus/added\"\n{PASSING}"),
        "printf m > \"$new/merged\"\nsleep 30\nexit 0",
    );
    let started = Instant::now();
    let record = run(
        &plan,
        &worker,
        &host,
        Bounds {
            merge: Duration::from_secs(1),
            ..BOUNDS
        },
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(record["merge"]["killed"], "time");
    assert_eq!(record["merge"]["adopted"], false);
    assert_eq!(names(&plan.root.join("corpus")), ["added"]);
    assert!(!plan.root.join("corpus.new").exists());
    assert_eq!(read(&plan.root).unwrap().unwrap().failed_merges, 1);
}

/// `fuzzed` reaches `corpus.new` on its second `Step::List`. When that
/// listing fails with `EIO`, the run ends held with the corpus as the
/// worker left it.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_failed_listing_of_the_merge_output_holds_the_run() {
    let _processes = processes();
    let host = Delegation::new("fuzz-merge-listing");
    let case = Case::new();
    let plan = plan(&case, 1);
    let adding = format!("printf x > \"$corpus/added\"\n{PASSING}");
    let worker = worker(&case, "worker.sh", &adding, COPYING);
    crate::sys::block_interruptions().unwrap();
    let _claimed = claim(&plan.root).unwrap();
    let session = started(&plan, &worker, PEN).unwrap();
    let prior = crate::step::install(Some(crate::step::Script {
        nth: Some((Step::List, 1, Outcome::Errno(libc::EIO))),
        ..Default::default()
    }));
    let ran = session.fuzzed(&host.root());
    crate::step::install(prior);
    let cause = ran
        .as_ref()
        .map(|ran| ran.merge.as_ref().map(|merged| &merged.cause));
    assert!(matches!(&ran, Err(Error::Held(_))), "{cause:?}");
    assert_eq!(names(&plan.root.join("corpus")), ["added"]);
}
