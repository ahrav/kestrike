//! The sweep's block reading, run classification, suspect list and totals.
//! A test that runs sweep threads needs a delegated cgroup-v2 scope named
//! by `CAMPAIGN_CGROUP_ROOT`, where each thread's pen is created.

use std::os::unix::fs::PermissionsExt;

use super::pen_tests::Delegation;
use super::*;
use crate::store::fixture::{Case, processes};

const LISTING: &str = include_str!("../../testdata/admission-listing.txt");
const CLUSTERS: &str = include_str!("../../testdata/cluster-listing.txt");

/// The summary of a counting `upload` run.
const COUNTING: &str = include_str!("../../testdata/counting.summary");

fn word(value: &str) -> Text {
    super::super::text(value).unwrap()
}

/// The pins of an archive whose build digest repeats `build`.
fn pins(build: char) -> Pins {
    Pins {
        build: word(&build.to_string().repeat(64)),
        executable: word(&"e".repeat(64)),
        platform: word("x86_64-linux"),
        toolchain: word("rustc 1.99.0"),
    }
}

/// A sweep of `upload` under the case's `sweep` directory with `workers`
/// workers of 64 MiB and 16 processes each and no deadline.
fn plan(case: &Case, workers: u64) -> Plan {
    Plan {
        root: case.root.join("sweep"),
        archive: case.root.join("archive"),
        campaign: word("host"),
        profiles: vec![word("upload")],
        counts: BTreeMap::new(),
        workers,
        batch: Duration::from_secs(30),
        wall: Duration::from_secs(600),
        seconds: None,
        cgroup: case.root.join("cgroup"),
        memory: 64 << 20,
        processes: 16,
    }
}

/// A gate that runs the command line after its `gate --` arguments once it
/// reads the go byte `G`. On any other byte or at the end of its input it
/// prints a line that opens with [`crate::exit::GATE_LINE`] and exits 125.
pub(super) const GATE: &str = "#!/bin/sh\n[ \"$(head -c 1)\" = G ] || \
     { echo 'campaign gate: failed to fill whole buffer' >&2; exit 125; }\nshift 2\nexec \"$@\"\n";

/// A gate script that reads the go byte, then prints a line that opens
/// with [`crate::exit::GATE_LINE`] and exits 125 for a command line that
/// matches the shell pattern `jobs`, and runs every other command line.
pub(super) fn failing_gate(jobs: &str) -> String {
    format!(
        "#!/bin/sh\n[ \"$(head -c 1)\" = G ] || exit 125\n\
         case \"$*\" in {jobs}) echo '{}No such file or directory (os error 2)' >&2; exit 125;; esac\n\
         shift 2\nexec \"$@\"\n",
        crate::exit::GATE_LINE
    )
}

/// The frozen inputs of `plan` over the testdata listing, with the shell
/// script `script` as the worker of every profile, [`GATE`] as the gate
/// and no control.
fn frozen<'a>(plan: &'a Plan, script: &str) -> Frozen<'a> {
    std::fs::create_dir_all(plan.root.join("manifests")).unwrap();
    std::fs::create_dir_all(plan.root.join("replays")).unwrap();
    let executable = |name: &str, script: &str| {
        let path = plan.root.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    };
    let program = executable("worker.sh", script);
    Frozen {
        plan,
        listing: Listing::parse(LISTING).unwrap(),
        pins: pins('b'),
        manifests: plan
            .profiles
            .iter()
            .map(|profile| {
                let manifest = format!("manifests/{}.manifest", profile.as_str());
                (profile.as_str().to_owned(), plan.root.join(manifest))
            })
            .collect(),
        controls: Vec::new(),
        histories: Vec::new(),
        rules: BTreeMap::new(),
        gate: executable("gate.sh", GATE),
        program: program.into(),
        environment: Vec::new(),
        progress: Mutex::new(Progress {
            build: pins('b').build,
            campaign: plan.campaign.clone(),
            counts: plan.counts.clone(),
            archive: Closing::Kept,
            profiles: BTreeMap::new(),
            elapsed_ms: 0,
            rules: Vec::new(),
            batches: 0,
        }),
        running: (0..plan.workers).map(|_| Mutex::new(None)).collect(),
        last: Mutex::default(),
        batches: AtomicU64::new(0),
        stop: AtomicBool::new(false),
        began: Instant::now(),
        before_ms: 0,
        ready: READY_WAIT,
    }
}

/// A worker script that runs the shell command `pause` before each run
/// and ends each as a counting `upload` run. As a recorded run it prints
/// the summary and exits 0. As a sweep worker it announces its sweep and
/// prints that summary's block for each root it reads.
fn passing(pause: &str) -> String {
    format!(
        "#!/bin/sh\nsummary='{COUNTING}'\n\
         if [ \"$1\" = --manifest ]; then\n{pause}\nprintf '%s' \"$summary\"\nexit 0\nfi\n\
         echo 'sweep: ready'\nwhile read root; do\n{pause}\n\
         printf 'root: %s\\ncode: 0\\n%send: %s\\n' \"$root\" \"$summary\" \"$root\"\ndone\n"
    )
}

/// The `upload` totals of `frozen`.
fn totals(frozen: &Frozen<'_>) -> Totals {
    let progress = frozen.progress.lock().unwrap();
    progress.profiles.get("upload").cloned().unwrap_or_default()
}

/// One sweep holds a root at a time: a second claim of the root is busy
/// until the first is dropped.
#[test]
fn a_root_is_claimed_by_one_sweep_at_a_time() {
    let case = Case::new();
    let root = case.root.join("sweep");
    let first = claim(&root).unwrap();
    let second = claim(&root);
    assert!(
        matches!(second, Err(Error::Store(crate::store::Error::Busy))),
        "{second:?}"
    );
    drop(first);
    claim(&root).unwrap();
}

/// A root that another user can write, here one with group write
/// permission, is rejected.
#[test]
fn a_root_another_user_can_write_is_rejected() {
    let case = Case::new();
    let root = case.root.join("sweep");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
    let claimed = claim(&root);
    assert!(matches!(claimed, Err(Error::Rejected(_))), "{claimed:?}");
}

/// A root on a filesystem a state directory refuses, here tmpfs under
/// `/dev/shm`, is rejected, since `confirm` keeps a state directory under
/// the root.
#[test]
fn a_root_on_tmpfs_is_rejected() {
    let root = PathBuf::from(format!("/dev/shm/sweep-root-{}", std::process::id()));
    let claimed = claim(&root);
    let _ = std::fs::remove_dir(&root);
    assert!(
        matches!(&claimed, Err(Error::Rejected(reason)) if reason.contains("tmpfs")),
        "{claimed:?}"
    );
}

/// A sweep's request passes the check `admit` makes of one. A sweep with
/// a `root` count, which that check refuses, is rejected before it claims
/// its root, so `confirm` refuses none of its suspects for that count.
#[test]
fn a_sweep_admission_would_refuse_is_rejected_before_its_root_is_claimed() {
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.counts.insert(word("root"), 1);
    let swept = sweep(&plan);
    assert!(
        matches!(&swept, Err(Error::Rejected(reason)) if reason.contains("root override")),
        "{:?}",
        swept.as_ref().err()
    );
    assert!(!plan.root.exists());
}

/// A cgroup root that custody refuses by its path, here a relative one,
/// is rejected as `confirm` rejects it, before the sweep claims its
/// root.
#[test]
fn a_sweep_with_a_relative_cgroup_root_is_rejected_before_its_root_is_claimed() {
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.cgroup = "relative".into();
    let swept = sweep(&plan);
    assert!(
        matches!(&swept, Err(Error::Rejected(_))),
        "{:?}",
        swept.as_ref().err()
    );
    assert!(!plan.root.exists());
}

/// The deepest existing ancestor of a root determines where its creation
/// starts. Under `archive/lib`, `new/../../../sweep` starts inside the
/// archive when `new` is absent, while `../../sweep` resolves outside.
#[test]
fn a_root_is_inside_the_archive_when_its_creation_starts_there() {
    let case = Case::new();
    let archive = case.root.join("archive");
    std::fs::create_dir_all(archive.join("lib")).unwrap();
    let refused = |root: &Path| {
        let checked = outside_archive(root, &archive);
        matches!(&checked, Err(Error::Rejected(reason)) if reason.contains("inside the archive"))
    };
    assert!(refused(&archive.join("lib/sweep")));
    assert!(refused(&archive.join("lib/new/../../../sweep")));
    assert!(!refused(&archive.join("lib/../../sweep")));
    assert!(!refused(&case.root.join("sweep")));
    assert_eq!(crate::store::fixture::snapshot(&archive).len(), 1);
}

#[test]
fn a_sweep_root_inside_the_archive_is_rejected_before_it_is_created() {
    let _processes = processes();
    let case = Case::new();
    let mut plan = plan(&case, 1);
    crate::archive::publish(&plan.archive, &crate::archive::publish_tests::built()).unwrap();
    let before = crate::store::fixture::snapshot(&plan.archive);
    plan.root = plan.archive.join("lib/sweep");
    let swept = sweep(&plan);
    assert!(
        matches!(&swept, Err(Error::Rejected(reason)) if reason.contains("inside the archive")),
        "{:?}",
        swept.as_ref().err()
    );
    assert_eq!(crate::store::fixture::snapshot(&plan.archive), before);
    let mut kept = crate::archive::Archive::load(&plan.archive).unwrap();
    kept.verify().unwrap().finish().unwrap();
}

/// A profile's manifest is named for the profile under the root, so a
/// swept profile's name is one path component. A name that is a path, as
/// a listing may hold, is rejected before the sweep claims its root.
#[test]
fn a_profile_whose_name_is_a_path_is_rejected_before_the_root_is_claimed() {
    let case = Case::new();
    for name in ["/tmp/victim", "../victim", "a/b", "..", "a/"] {
        let mut plan = plan(&case, 1);
        plan.profiles = vec![word("upload"), word(name)];
        let swept = sweep(&plan);
        assert!(
            matches!(&swept, Err(Error::Rejected(reason)) if reason.contains("path component")),
            "{name}: {:?}",
            swept.as_ref().err()
        );
        assert!(!plan.root.exists(), "{name}");
    }
}

/// A run whose worker ends before its block counts as a run of its
/// profile, so the totals hold as many runs as endings: every worker
/// here exits on its first root, and each such run is one run and one
/// suspect.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_run_its_worker_abandons_counts_as_a_run() {
    let _processes = processes();
    let host = Delegation::new("abandon");
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "#!/bin/sh\necho 'sweep: ready'\nread root\n");
    let deadline = Instant::now() + Duration::from_millis(300);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let totals = totals(&frozen);
    assert!(totals.suspects > 0);
    assert_eq!(totals.runs, totals.suspects);
}

/// The lines of the sweep root's `suspects.jsonl`.
fn suspect_lines(plan: &Plan) -> Vec<Value> {
    std::fs::read_to_string(plan.root.join("suspects.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// A run replayed in a fresh worker process must exit with the code and
/// print the summary the sweep read. The worker here prints one summary
/// for a root both times and exits 3 as a recorded run, so each replay
/// differs and its run is a suspect whose line holds the digest and
/// ending the sweep read beside the replay's code and summary.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_run_whose_replay_ends_another_way_is_a_suspect() {
    let _processes = processes();
    let host = Delegation::new("ending");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replacen("exit 0", "exit 3", 1);
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let totals = totals(&frozen);
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!(
        totals.suspect_keys.get("replay differs: "),
        Some(&totals.replays)
    );
    let digest = COUNTING
        .lines()
        .next()
        .unwrap()
        .trim_start_matches("digest: ");
    let lines = suspect_lines(&plan);
    assert!(!lines.is_empty());
    for line in lines {
        assert_eq!(line["class"], "replay differs");
        assert_eq!(line["first"], json!({"digest": digest, "ending": "pass"}));
        assert_eq!(
            (&line["code"], &line["summary"]["digest"]),
            (&json!(3), &json!(digest))
        );
    }
}

/// A replay's gate that prints its line and exits 125 holds the sweep,
/// which records zero replays and zero suspects.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_whose_gate_failed_holds_the_sweep() {
    let _processes = processes();
    let host = Delegation::new("replay-gate");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let frozen = frozen(&plan, &passing("sleep 0.02"));
    std::fs::write(&frozen.gate, failing_gate("*--manifest*")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let ran = frozen.run(&host.root(), Some(deadline), FLUSH);
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.contains("os error 2")),
        "{ran:?}"
    );
    let totals = totals(&frozen);
    assert!(totals.runs > 0);
    assert_eq!((totals.replays, totals.suspects), (0, 0));
    assert!(!plan.root.join("suspects.jsonl").exists());
}

/// A first stderr line distinct from the gate's identifies exit 125 as a
/// worker exit, so the run is a `replay differs` suspect.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_whose_worker_exits_125_differs() {
    let _processes = processes();
    let host = Delegation::new("replay-125");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let exits = "echo 'a worker line' >&2\nexit 125";
    let script = passing("sleep 0.02").replacen("exit 0", exits, 1);
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let totals = totals(&frozen);
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!(
        totals.suspect_keys.get("replay differs: "),
        Some(&totals.replays)
    );
    for line in suspect_lines(&plan) {
        assert_eq!(line["code"], json!(125));
    }
}

/// Draining stderr lets the worker reach its summary even when its
/// output fills the pipe, so each replay agrees with its run.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_whose_worker_fills_standard_error_agrees() {
    let _processes = processes();
    let host = Delegation::new("replay-stderr");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let frozen = frozen(&plan, &passing("head -c 1048576 /dev/zero >&2 || exit 9"));
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let totals = totals(&frozen);
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!(totals.suspects, 0, "{:?}", totals.suspect_keys);
}

/// A run replayed in a fresh worker process must print the digest the
/// sweep read. The worker here prints another digest as a recorded run,
/// so the run is a suspect whose line holds both digests.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_run_whose_replay_prints_another_digest_is_a_suspect() {
    let _processes = processes();
    let host = Delegation::new("digest");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let digest = COUNTING
        .lines()
        .next()
        .unwrap()
        .trim_start_matches("digest: ");
    let other = "0".repeat(64);
    let again = COUNTING.replacen(digest, &other, 1);
    let script = passing("sleep 0.02").replacen(
        "printf '%s' \"$summary\"\nexit 0",
        &format!("printf '%s' '{again}'\nexit 0"),
        1,
    );
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let totals = totals(&frozen);
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!(
        totals.suspect_keys.get("replay differs: "),
        Some(&totals.replays)
    );
    let lines = suspect_lines(&plan);
    assert!(!lines.is_empty());
    for line in lines {
        assert_eq!(line["class"], "replay differs");
        assert_eq!(line["first"], json!({"digest": digest, "ending": "pass"}));
        assert_eq!(line["summary"]["digest"], other);
    }
}

/// Matching output and exit code with an empty pen leave the suspect count at zero. The
/// fresh roots assigned by the sweep determine the expected run, covered
/// pass, invalidation and witness totals independently of the replay count.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_run_whose_replay_agrees_is_no_suspect() {
    let _processes = processes();
    let host = Delegation::new("agrees");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.profiles = vec![word("cluster-broad")];
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replace(COUNTING, &broad_summary(COUNTING, true));
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let progress = frozen.progress.lock().unwrap();
    let totals = &progress.profiles["cluster-broad"];
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!((totals.suspects, totals.pass), (0, totals.runs));
    assert_eq!(totals.runs, totals.next);
    assert_eq!(totals.covered, totals.runs);
    assert_eq!(totals.reached["invalidated"].total, 4 * totals.runs);
    assert_eq!(totals.witnesses, 10 * totals.runs);
}

/// A replay whose pen the sweep kills at the wall limit makes its run a
/// suspect of class `wall limit`, whatever its worker exited with. The
/// worker here prints the run's summary and exits 0 as a recorded run,
/// and leaves a process that holds its output open, so the replay's
/// output ends only when the pen is killed.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_its_pen_is_killed_under_is_a_suspect_of_the_wall_limit() {
    let _processes = processes();
    let host = Delegation::new("held");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    plan.wall = Duration::from_secs(1);
    let script = passing("sleep 0.02").replacen(
        "printf '%s' \"$summary\"\nexit 0",
        "printf '%s' \"$summary\"\nsleep 600 &\nexit 0",
        1,
    );
    let frozen = frozen(&plan, &script);
    let began = Instant::now();
    let deadline = began + Duration::from_millis(1500);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let took = began.elapsed();
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(classes(&frozen), ["wall limit: "]);
    let totals = totals(&frozen);
    assert_eq!(totals.pass, totals.runs);
}

/// A replay the sweep kills after its output ended is a suspect of class
/// `wall limit` too: the class is read once the worker is retired. The
/// worker here prints the run's summary, closes its output and sleeps, so
/// the sweep kills its pen at the end of the exit wait.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_killed_at_its_exit_wait_is_a_suspect_of_the_wall_limit() {
    let _processes = processes();
    let host = Delegation::new("hung");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replacen(
        "printf '%s' \"$summary\"\nexit 0",
        "printf '%s' \"$summary\"\nexec sleep 600 > /dev/null",
        1,
    );
    let mut frozen = frozen(&plan, &script);
    frozen.ready = Duration::from_millis(200);
    let began = Instant::now();
    let deadline = began + Duration::from_millis(1500);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let took = began.elapsed();
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(classes(&frozen), ["wall limit: "]);
    let totals = totals(&frozen);
    assert_eq!(totals.pass, totals.runs);
}

/// A replay that SIGTERM ends was interrupted with its sweep, as when
/// systemd stops the sweep's unit: a replay's worker runs with the
/// signal unblocked, and the sweep itself ends a worker with SIGKILL
/// alone. Its run is no suspect and it is no replay of the totals. The
/// worker here sends itself SIGTERM as a recorded run.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_an_interruption_ends_lists_no_suspect() {
    let _processes = processes();
    let host = Delegation::new("stopped");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replacen(
        "printf '%s' \"$summary\"\nexit 0",
        "kill -TERM $$\nsleep 600",
        1,
    );
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let totals = totals(&frozen);
    assert!(totals.runs > 1, "{} runs", totals.runs);
    assert_eq!((totals.suspects, totals.replays), (0, 0));
    assert_eq!(totals.pass, totals.runs);
}

/// A replay's output is read up to a block's bound, so a worker that
/// prints more costs the sweep that much memory and is ended at once. Its
/// run is a suspect of class `worker ended during the run`, as a run
/// whose block passes the bound is. The worker here prints 3 MiB as a
/// recorded run and then sleeps under a wall limit of 30 seconds, and the
/// sweep ends inside ten.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_that_prints_past_a_blocks_bound_is_ended() {
    let _processes = processes();
    let host = Delegation::new("flood");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    plan.wall = Duration::from_secs(30);
    let script = passing("sleep 0.02").replacen(
        "printf '%s' \"$summary\"\nexit 0",
        "head -c 3145728 /dev/zero | tr '\\0' x\nsleep 600",
        1,
    );
    let frozen = frozen(&plan, &script);
    let began = Instant::now();
    let deadline = began + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let took = began.elapsed();
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(classes(&frozen), ["worker ended during the run: "]);
    let totals = totals(&frozen);
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!(totals.pass, totals.runs);
}

/// A replay that prints past a block's bound is no comparison whatever
/// its worker exits with. The worker here prints 1000 bytes past the
/// bound and exits 0 as a recorded run, so it has exited when the sweep
/// ends it, and its run is a suspect of class `worker ended during the
/// run`.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_past_a_blocks_bound_that_exits_is_ended_as_one_that_stays() {
    let _processes = processes();
    let host = Delegation::new("spill");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replacen(
        "printf '%s' \"$summary\"\nexit 0",
        "head -c 1049576 /dev/zero | tr '\\0' x\nexit 0",
        1,
    );
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    assert_eq!(classes(&frozen), ["worker ended during the run: "]);
    let totals = totals(&frozen);
    assert!(totals.replays > 0, "{} replays", totals.replays);
}

/// The totals of `planted` after a sweep in a pen under a delegation
/// named `label`. The worker ends each run of `planted` in a Bytes
/// violation in a sweep, and as a recorded run prints `replayed` and exits
/// with `code`.
fn caught_then_replayed(label: &str, replayed: &str, code: i32) -> Totals {
    let host = Delegation::new(label);
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.profiles = vec![word("planted")];
    plan.batch = Duration::from_millis(50);
    let violated = format!(
        "{}identity: 020101{}\n",
        violation().replacen("profile: upload", "profile: planted", 1),
        "0".repeat(82)
    );
    let script = passing("sleep 0.02")
        .replacen(COUNTING, &violated, 1)
        .replacen(
            "printf '%s' \"$summary\"\nexit 0",
            &format!(
                "printf '%s' '{}'\nexit {code}",
                replayed.replace('\'', "'\\''")
            ),
            1,
        )
        .replacen("code: 0", "code: 1", 1);
    let mut frozen = frozen(&plan, &script);
    let upload = "profile: upload class=live support=implemented campaign=unqualified \
                  held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n";
    let planted = upload.replace("upload class=live", "planted class=control");
    frozen.listing =
        Listing::parse(&LISTING.replacen(upload, &format!("{upload}{planted}"), 1)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let progress = frozen.progress.lock().unwrap();
    progress.profiles["planted"].clone()
}

/// A control's run that was caught and whose replay passes is a passed
/// control run: the checks let the planted defect through as a recorded
/// run. It is counted under `missed`, so the root's totals carry `alarm`,
/// beside its suspect of class `replay differs`. The worker here ends each
/// run of `planted` in a Bytes violation in a sweep and passes it as a
/// recorded run.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_caught_runs_replay_that_passes_is_a_missed_control_run() {
    let _processes = processes();
    let passed = COUNTING.replacen("profile: upload", "profile: planted", 1);
    let totals = caught_then_replayed("missed", &passed, 0);
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!(totals.caught, totals.runs);
    assert_eq!(totals.missed, totals.replays);
    assert_eq!(
        totals.suspect_keys.get("replay differs: "),
        Some(&totals.replays)
    );
}

/// A control's run that was caught and whose replay ends under the rule
/// of a plant that met no check is counted under `missed` the same way:
/// the plant took effect in the recorded run and no check failed there.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_caught_runs_replay_that_meets_no_check_is_a_missed_control_run() {
    let _processes = processes();
    let unseen = unsuccessful()
        .replacen("profile: upload", "profile: planted", 1)
        .replacen("fewer exact reads", controls::UNSEEN, 1);
    let totals = caught_then_replayed("unseen", &unseen, 1);
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!(totals.caught, totals.runs);
    assert_eq!(totals.missed, totals.replays);
    assert_eq!(
        totals.suspect_keys.get("replay differs: "),
        Some(&totals.replays)
    );
}

/// A control's run whose replay differs is listed with the ending the
/// sweep counted it under: `caught` for a run that ended in the control's
/// failure. The worker here ends each run of `planted` in a Bytes
/// violation and exits 3 as a recorded run.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_caught_runs_replay_that_differs_lists_it_as_caught() {
    let _processes = processes();
    let host = Delegation::new("caught");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.profiles = vec![word("planted")];
    plan.batch = Duration::from_millis(50);
    let violated = format!(
        "{}identity: 020101{}\n",
        violation().replacen("profile: upload", "profile: planted", 1),
        "0".repeat(82)
    );
    let script = passing("sleep 0.02")
        .replacen(COUNTING, &violated, 1)
        .replacen("exit 0", "exit 3", 1)
        .replacen("code: 0", "code: 1", 1);
    let mut frozen = frozen(&plan, &script);
    let upload = "profile: upload class=live support=implemented campaign=unqualified \
                  held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n";
    let planted = upload.replace("upload class=live", "planted class=control");
    assert!(LISTING.contains(upload));
    frozen.listing =
        Listing::parse(&LISTING.replacen(upload, &format!("{upload}{planted}"), 1)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let progress = frozen.progress.lock().unwrap();
    let totals = &progress.profiles["planted"];
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!((totals.caught, totals.pass), (totals.runs, 0));
    let lines = suspect_lines(&plan);
    assert!(!lines.is_empty());
    for line in lines {
        assert_eq!(line["class"], "replay differs");
        assert_eq!(line["first"]["ending"], "caught");
        assert_eq!(line["code"], 3);
    }
}

/// A root's sweeps share one count of batches, which `sweep.json` holds,
/// so a sweep that ends inside its first batch leaves the control batch
/// to the next sweep of the root.
#[test]
fn a_roots_batch_count_is_stored_with_its_totals() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    frozen.batches.store(5, Ordering::Relaxed);
    frozen.flush().unwrap();
    let stored = std::fs::read(plan.root.join("sweep.json")).unwrap();
    let stored: Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(stored["batches"], 5);
    // Totals stored without the count read as no batch begun.
    let unbatched: Progress = serde_json::from_slice(&swept(&pins('b'))).unwrap();
    assert_eq!(unbatched.batches, 0);
}

/// A sweep starts with no file under `replays`: a manifest or a bundle a
/// killed sweep's replay left there, at any worker's index, is removed.
#[test]
fn a_sweep_starts_without_an_earlier_sweeps_replay_files() {
    let case = Case::new();
    let replays = case.root.join("replays");
    emptied(&case.root).unwrap();
    assert!(replays.is_dir());
    let left = [replays.join("0000.manifest"), replays.join("1023.bundle")];
    for file in &left {
        std::fs::write(file, "left").unwrap();
    }
    emptied(&case.root).unwrap();
    for file in &left {
        assert!(!file.exists(), "{}", file.display());
    }
}

/// A replay that agrees and whose worker left a process in the pen makes
/// its run a suspect of class `left a process`: the worker here starts a
/// sleep as a recorded run, and each of its runs passes.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_replay_that_leaves_a_process_makes_its_run_a_suspect() {
    let _processes = processes();
    let host = Delegation::new("replayed");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replacen(
        "printf '%s' \"$summary\"\nexit 0",
        "printf '%s' \"$summary\"\nsleep 600 > /dev/null 2>&1 &\nexit 0",
        1,
    );
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    assert_eq!(classes(&frozen), ["left a process: "]);
    let totals = totals(&frozen);
    assert!(totals.replays > 0, "{} replays", totals.replays);
    assert_eq!(totals.suspects, totals.replays);
    assert_eq!(totals.pass, totals.runs);
}

/// A sweep holds one thread for each worker and one for its monitor beside
/// the pens, and the process limit of an ancestor counts each thread. Two
/// workers of 16 processes need 35 tasks, so a root limited to 35, which
/// the check requires the sum to stay below, is rejected with that root
/// named, and one limited to 36 fits. The counts are small so that the
/// root's limit decides both cases wherever the delegation's ancestors
/// allow more than 36 tasks.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_sweeps_own_threads_count_against_an_ancestors_process_limit() {
    let _processes = processes();
    let host = Delegation::new("threads");
    let case = Case::new();
    let plan = plan(&case, 2);
    let root = host.root();
    std::fs::write(host.root.join("pids.max"), "35").unwrap();
    let limits = Limits {
        memory: plan.memory,
        processes: plan.processes,
    };
    let fitted = fit(&root, plan.workers, limits);
    let named = host.root.display().to_string();
    assert!(
        matches!(
            &fitted,
            Err(Error::Rejected(reason))
                if reason.contains("aggregate pids") && reason.ends_with(&named)
        ),
        "{fitted:?}"
    );
    std::fs::write(host.root.join("pids.max"), "36").unwrap();
    fit(&root, plan.workers, limits).unwrap();
}

/// A sweep that finds another sweep holding its cgroup root ends busy, as
/// one that finds its own root held does, so a caller that waits on a
/// busy exit waits for either lock. The second sweep here has its own
/// root and is refused before it reads its archive.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_sweep_on_a_held_cgroup_root_ends_busy() {
    let _processes = processes();
    let host = Delegation::new("busy");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.cgroup = host.root.clone();
    let held = pen::claim(&host.root).unwrap().unwrap();
    let swept = sweep(&plan);
    assert!(
        matches!(swept, Err(Error::Store(crate::store::Error::Busy))),
        "{swept:?}"
    );
    drop(held);
}

/// The monitor tries a pen's kill again on each pass while the worker is
/// past its limit, so a kill that failed once ends the run once it can
/// succeed. The run here starts a sleep in a session of its own, which
/// the kill of the worker's process group does not reach and which holds
/// the worker's output open. The pen's kill file is read-only when the
/// wall limit passes and writable a second later, and the sweep ends
/// inside ten seconds, well before the sleep's twenty.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_pen_kill_that_failed_is_tried_again() {
    let _processes = processes();
    let host = Delegation::new("retry");
    let pens = host.root();
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.wall = Duration::from_millis(300);
    let script = "#!/bin/sh\necho 'sweep: ready'\nread root\nsetsid sleep 20 &\nsleep 20\n";
    let frozen = frozen(&plan, script);
    let kill = host.root.join("sweep-0000/cgroup.kill");
    let began = Instant::now();
    let deadline = began + Duration::from_secs(3);
    std::thread::scope(|scope| {
        let sweep = scope.spawn(|| frozen.run(&pens, Some(deadline), FLUSH));
        while !kill.exists() {
            assert!(began.elapsed() < Duration::from_secs(10), "no pen appeared");
            std::thread::sleep(Duration::from_millis(1));
        }
        std::fs::set_permissions(&kill, std::fs::Permissions::from_mode(0o444)).unwrap();
        let opened = std::fs::OpenOptions::new().write(true).open(&kill);
        assert!(
            opened.is_err(),
            "the pen's kill file still opens for writing"
        );
        std::thread::sleep(Duration::from_millis(1500));
        std::fs::set_permissions(&kill, std::fs::Permissions::from_mode(0o644)).unwrap();
        sweep.join().unwrap().unwrap();
    });
    let took = began.elapsed();
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(classes(&frozen), ["wall limit: "]);
}

/// A batch that fails with its worker alive ends that worker when the
/// pen's kill fails too, and the sweep returns the batch's error. Every
/// append to the suspect list fails here, the worker sleeps 20 seconds
/// once its input ends, and the pen's kill file is read-only, so the
/// sweep ends inside ten seconds only by killing the worker itself.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_failed_batch_ends_a_worker_its_pen_cannot_kill() {
    let _processes = processes();
    let host = Delegation::new("unkillable");
    let pens = host.root();
    let case = Case::new();
    let plan = plan(&case, 1);
    let script = "#!/bin/sh\necho 'sweep: ready'\nwhile read root; do\nsleep 0.5\n\
                  printf 'root: %s\\ncode: 3\\nrun: the run panicked at a.rs:1:2: b\\nend: %s\\n' \
                  \"$root\" \"$root\"\ndone\nexec sleep 20\n";
    let frozen = frozen(&plan, script);
    std::fs::create_dir(plan.root.join("suspects.jsonl")).unwrap();
    let kill = host.root.join("sweep-0000/cgroup.kill");
    let began = Instant::now();
    let ran = std::thread::scope(|scope| {
        let sweep = scope.spawn(|| frozen.run(&pens, None, FLUSH));
        while !kill.exists() {
            assert!(began.elapsed() < Duration::from_secs(10), "no pen appeared");
            std::thread::sleep(Duration::from_millis(1));
        }
        std::fs::set_permissions(&kill, std::fs::Permissions::from_mode(0o444)).unwrap();
        let opened = std::fs::OpenOptions::new().write(true).open(&kill);
        assert!(
            opened.is_err(),
            "the pen's kill file still opens for writing"
        );
        sweep.join().unwrap()
    });
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.contains("suspects.jsonl")),
        "{ran:?}"
    );
    let took = began.elapsed();
    assert!(took < Duration::from_secs(10), "{took:?}");
}

/// The suspect keys of `frozen`'s `upload` totals.
fn classes(frozen: &Frozen<'_>) -> Vec<String> {
    totals(frozen).suspect_keys.into_keys().collect()
}

/// A run that outlives the wall limit has its pen killed and is a suspect
/// of class `wall limit`: every run here sleeps five seconds under a limit
/// of one. The sweep ends inside four seconds, before the sleep would,
/// so the kill reached the sleep, which holds the worker's output open,
/// and not the worker alone.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_run_past_the_wall_limit_is_a_suspect_of_that_class() {
    let _processes = processes();
    let host = Delegation::new("wall");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.wall = Duration::from_secs(1);
    let frozen = frozen(&plan, &passing("sleep 5"));
    let began = Instant::now();
    let deadline = began + Duration::from_millis(1500);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let took = began.elapsed();
    assert!(took < Duration::from_secs(4), "{took:?}");
    assert_eq!(classes(&frozen), ["wall limit: "]);
    assert_eq!(totals(&frozen).pass, 0);
}

/// A run whose worker the kernel kills at the pen's memory limit is a
/// suspect of class `out of memory`: every run here reads zeros into
/// memory until it passes the pen's 64 MiB.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_run_killed_at_the_memory_limit_is_a_suspect_of_that_class() {
    let _processes = processes();
    let host = Delegation::new("oom");
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, &passing("tail /dev/zero"));
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    assert_eq!(classes(&frozen), ["out of memory: "]);
    assert_eq!(totals(&frozen).pass, 0);
}

/// A worker that exits at the end of its roots and leaves a process makes
/// the batch's last finished run a suspect of class `left a process`, and
/// its other runs pass: the worker here starts a sleep after its last
/// root.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_that_leaves_a_process_makes_its_last_run_a_suspect() {
    let _processes = processes();
    let host = Delegation::new("left");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(100);
    let script = passing("").replacen("done\n", "done\nsleep 600 &\n", 1);
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    assert_eq!(classes(&frozen), ["left a process: "]);
    let totals = totals(&frozen);
    assert!(totals.runs > 0);
    assert_eq!(totals.pass, totals.runs);
}

/// A worker that exits before it prints its ready line, as one that
/// refuses its command line does, fails the sweep. No seed is charged with
/// its end: no run number is taken and no suspect is counted or listed.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_that_does_not_start_fails_the_sweep() {
    let _processes = processes();
    let host = Delegation::new("start");
    let case = Case::new();
    let plan = plan(&case, 2);
    let frozen = frozen(&plan, "#!/bin/sh\nexit 101\n");
    let deadline = Instant::now() + Duration::from_secs(2);
    let ran = frozen.run(&host.root(), Some(deadline), FLUSH);
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.contains("101")),
        "{ran:?}"
    );
    let totals = totals(&frozen);
    assert_eq!((totals.next, totals.suspects), (0, 0));
    assert!(!plan.root.join("suspects.jsonl").exists());
}

/// A worker that stays silent while it waits for a root is killed at the
/// end of the ready wait and fails the sweep, well inside the wall limit
/// of a run.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_that_prints_no_ready_line_in_time_fails_the_sweep() {
    let _processes = processes();
    let host = Delegation::new("ready");
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut frozen = frozen(&plan, "#!/bin/sh\nexec sleep 20\n");
    frozen.ready = Duration::from_millis(200);
    let began = Instant::now();
    let ran = frozen.run(&host.root(), None, FLUSH);
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.contains("no ready line within")),
        "{ran:?}"
    );
    assert!(began.elapsed() < Duration::from_secs(10));
    assert_eq!(totals(&frozen).next, 0);
}

/// The read of a worker's ready line takes no more than the line's length
/// from the worker, so a worker that prints without a newline fails the
/// sweep at once and the error quotes that much of its output. The worker
/// here prints 1 MiB and then sleeps.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_that_prints_no_newline_fails_the_sweep_within_the_ready_lines_length() {
    let _processes = processes();
    let host = Delegation::new("newline");
    let case = Case::new();
    let plan = plan(&case, 1);
    let script = "#!/bin/sh\nhead -c 1048576 /dev/zero | tr '\\0' x\nexec sleep 20\n";
    let frozen = frozen(&plan, script);
    let began = Instant::now();
    let ran = frozen.run(&host.root(), None, FLUSH);
    assert!(began.elapsed() < Duration::from_secs(10));
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.len() < 200 && reason.contains("in place of its ready line")),
        "{:?}",
        ran.as_ref().err().map(|error| error.to_string().len())
    );
}

/// A sweep counter holds at its maximum: a worker that prints a summary
/// whose turns are `u64::MAX` twice leaves the total there, and the sweep
/// goes on.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_counter_past_its_maximum_stays_there() {
    let _processes = processes();
    let host = Delegation::new("maximum");
    let case = Case::new();
    let plan = plan(&case, 1);
    let script = passing("").replacen("turns: 57", "turns: 18446744073709551615", 1);
    let frozen = frozen(&plan, &script);
    let deadline = Instant::now() + Duration::from_millis(300);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let totals = totals(&frozen);
    assert!(totals.runs >= 2, "{} runs", totals.runs);
    assert_eq!(totals.turns, u64::MAX);
}

/// The sweep kills a worker's pen, and its process group when that kill
/// fails, so a process the worker started that holds its output ends with
/// it. The worker here starts `sleep 20` twice on its first root, once
/// behind it and once in front, and stalls past the wall limit: the run
/// is a suspect of that limit and the sweep ends at its deadline, well
/// inside those 20 seconds.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_killed_workers_descendants_end_with_it() {
    let _processes = processes();
    let host = Delegation::new("group");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.wall = Duration::from_millis(300);
    let script = "#!/bin/sh\necho 'sweep: ready'\nread root\nsleep 20 &\nsleep 20\n";
    let frozen = frozen(&plan, script);
    let began = Instant::now();
    frozen
        .run(&host.root(), Some(began + Duration::from_secs(1)), FLUSH)
        .unwrap();
    assert!(began.elapsed() < Duration::from_secs(10));
    let totals = totals(&frozen);
    assert!(totals.suspects > 0);
    assert_eq!(
        totals.suspect_keys.get("wall limit: "),
        Some(&totals.suspects)
    );
}

/// A worker that prints no ready line is killed with the processes it
/// started: the shell here waits for a `sleep 20` that holds its output,
/// and the sweep fails at the end of the ready wait.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_without_a_ready_line_ends_with_its_descendants() {
    let _processes = processes();
    let host = Delegation::new("silent");
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut frozen = frozen(&plan, "#!/bin/sh\nsleep 20\n");
    frozen.ready = Duration::from_millis(200);
    let began = Instant::now();
    let ran = frozen.run(&host.root(), None, FLUSH);
    assert!(began.elapsed() < Duration::from_secs(10));
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.contains("no ready line within")),
        "{:?}",
        ran.as_ref().err()
    );
}

/// A listing's worker is killed with the processes it started. The worker
/// here starts a `sleep 20`, writes its process ID, and outlives the
/// listing's wait: once the listing has failed, that process is gone.
#[test]
fn a_listing_killed_at_its_wait_ends_with_its_descendants() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let noted = plan.root.join("descendant");
    let script = format!(
        "#!/bin/sh\nsleep 20 >/dev/null 2>&1 &\necho $! > {}\nexec sleep 20\n",
        noted.display()
    );
    let frozen = frozen(&plan, &script);
    let listing = super::listed(Command::new(&frozen.program), Duration::from_millis(300));
    assert!(listing.is_err());
    let descendant = std::fs::read_to_string(&noted).unwrap();
    let process = PathBuf::from("/proc").join(descendant.trim());
    let gone = Instant::now() + Duration::from_secs(5);
    while process.exists() && Instant::now() < gone {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!process.exists(), "{process:?} still runs");
}

/// A listing whose worker has exited while a process that left its group
/// still holds its output fails at the end of the wait. The worker stays
/// unreaped until then, so the kill of its group names no other process.
#[test]
fn a_listing_whose_output_outlives_its_worker_fails_at_the_wait() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "#!/bin/sh\nsetsid sleep 5 &\nexit 0\n");
    let began = Instant::now();
    let listing = super::listed(Command::new(&frozen.program), Duration::from_millis(300));
    assert!(began.elapsed() < Duration::from_secs(3));
    assert!(
        matches!(listing.as_ref().err(), Some(Error::Held(reason)) if reason.contains("deadline")),
        "{:?}",
        listing.as_ref().err()
    );
}

/// A worker that hangs in its capability listing is killed at the end of
/// the listing's wait and fails the sweep, well inside the 20 seconds the
/// worker here would take.
#[test]
fn a_listing_that_outlives_its_wait_fails_the_sweep() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "#!/bin/sh\nexec sleep 20\n");
    let began = Instant::now();
    let listing = super::listed(Command::new(&frozen.program), Duration::from_millis(200));
    assert!(began.elapsed() < Duration::from_secs(10));
    assert!(
        matches!(listing.as_ref().err(), Some(Error::Held(reason)) if reason.contains("deadline")),
        "{:?}",
        listing.as_ref().err()
    );
}

/// A worker that prints its listing and exits inside the wait yields the
/// listing its output parses to.
#[test]
fn a_listing_printed_inside_its_wait_is_parsed() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let text = plan.root.join("listing.txt");
    let script = format!("#!/bin/sh\nexec cat {}\n", text.display());
    let frozen = frozen(&plan, &script);
    std::fs::write(&text, LISTING).unwrap();
    let listing = super::listed(Command::new(&frozen.program), READY_WAIT);
    let parsed = Listing::parse(LISTING).unwrap();
    assert!(
        matches!(&listing, Ok(listing) if listing.keys.len() == parsed.keys.len()),
        "{:?}",
        listing.as_ref().err()
    );
}

/// A worker that prints a listing and then exits with another status
/// than success has failed its capability command, so the sweep is
/// refused with that status and the listing is left unparsed.
#[test]
fn a_listing_whose_worker_fails_is_refused() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let text = plan.root.join("listing.txt");
    let script = format!("#!/bin/sh\ncat {}\nexit 3\n", text.display());
    let frozen = frozen(&plan, &script);
    std::fs::write(&text, LISTING).unwrap();
    let listing = super::listed(Command::new(&frozen.program), READY_WAIT);
    assert!(
        matches!(listing.as_ref().err(), Some(Error::Held(reason)) if reason.contains("exit status: 3")),
        "{:?}",
        listing.as_ref().err()
    );
}

/// A worker's `--rules` output: the version line and two rules.
const CATALOG: &str = "rules: 1\n\
    rule: boundary an unexpected binding\n\
    rule: world a refused read exposed bytes\n";

/// A worker that prints its rule catalog and exits inside the wait yields
/// the rules its output parses to.
#[test]
fn a_rule_catalog_printed_inside_its_wait_is_parsed() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let text = plan.root.join("catalog.txt");
    let script = format!("#!/bin/sh\nexec cat {}\n", text.display());
    let frozen = frozen(&plan, &script);
    std::fs::write(&text, CATALOG).unwrap();
    let catalog = super::cataloged(Command::new(&frozen.program), READY_WAIT);
    let texts: Vec<&str> = catalog
        .iter()
        .flatten()
        .map(|rule| rule.text.as_str())
        .collect();
    assert_eq!(
        texts,
        ["an unexpected binding", "a refused read exposed bytes"],
        "{:?}",
        catalog.as_ref().err()
    );
}

/// A worker that prints part of its catalog and then exits with another
/// status than success has failed its rules command. The part here parses
/// as a catalog of one rule, so the exit status is what refuses it.
#[test]
fn a_rule_catalog_whose_worker_fails_is_refused() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let cut = &CATALOG[..CATALOG.rfind("rule: ").unwrap()];
    assert!(crate::protocol::Rules::parse(cut).is_ok());
    let text = plan.root.join("catalog.txt");
    let script = format!("#!/bin/sh\ncat {}\nexit 3\n", text.display());
    let frozen = frozen(&plan, &script);
    std::fs::write(&text, cut).unwrap();
    let catalog = super::cataloged(Command::new(&frozen.program), READY_WAIT);
    assert!(
        matches!(catalog.as_ref().err(), Some(Error::Held(reason)) if reason.contains("exit status: 3")),
        "{catalog:?}"
    );
}

/// A worker that hangs in its rule catalog is killed at the end of the
/// catalog's wait and fails the sweep, well inside the 20 seconds the
/// worker here would take.
#[test]
fn a_rule_catalog_that_outlives_its_wait_fails_the_sweep() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "#!/bin/sh\nexec sleep 20\n");
    let began = Instant::now();
    let catalog = super::cataloged(Command::new(&frozen.program), Duration::from_millis(200));
    assert!(began.elapsed() < Duration::from_secs(10));
    assert!(
        matches!(catalog.as_ref().err(), Some(Error::Held(reason)) if reason.contains("deadline")),
        "{catalog:?}"
    );
}

/// A sweep whose deadline has passed when it starts runs nothing: no
/// worker is started and no run is counted. The worker here would note
/// its start in a file.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_deadline_already_passed_starts_no_worker() {
    let _processes = processes();
    let host = Delegation::new("passed");
    let case = Case::new();
    let plan = plan(&case, 4);
    let script = passing("").replacen(
        "echo 'sweep: ready'",
        ": > \"$0.$$\"\necho 'sweep: ready'",
        1,
    );
    let frozen = frozen(&plan, &script);
    frozen
        .run(&host.root(), Some(Instant::now()), FLUSH)
        .unwrap();
    assert_eq!(totals(&frozen).next, 0);
    let started = std::fs::read_dir(&plan.root)
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            name.to_string_lossy().starts_with("worker.sh.")
        })
        .count();
    assert_eq!(started, 0);
}

/// A signal that arrived before the workers start, as during the
/// capability listing, stops the sweep before any worker starts. The test
/// blocks the signals as `sweep` does and sends itself SIGINT; the workers
/// would each note their start in a file.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_signal_pending_at_the_start_starts_no_worker() {
    let _processes = processes();
    let host = Delegation::new("pending");
    let case = Case::new();
    let plan = plan(&case, 4);
    let script = passing("").replacen(
        "echo 'sweep: ready'",
        ": > \"$0.$$\"\necho 'sweep: ready'",
        1,
    );
    let frozen = frozen(&plan, &script);
    crate::sys::block_interruptions().unwrap();
    crate::sys::interrupt(libc::SIGINT).unwrap();
    frozen.run(&host.root(), None, FLUSH).unwrap();
    assert_eq!(totals(&frozen).next, 0);
    let started = std::fs::read_dir(&plan.root)
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            name.to_string_lossy().starts_with("worker.sh.")
        })
        .count();
    assert_eq!(started, 0);
}

/// A sweep thread the host cannot start fails the sweep with that cause,
/// and the monitor still runs for the threads that started. The child
/// process here lowers its process limit to one, which refuses every
/// thread to a user that is not root, so no thread starts.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_thread_that_cannot_start_fails_the_sweep() {
    const CHILD: &str = "CAMPAIGN_SWEEP_THREAD_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let case = Case::new();
        let plan = plan(&case, 4);
        let frozen = frozen(&plan, &passing(""));
        let host = Delegation::new("thread");
        let pens = host.root();
        crate::sys::restrict_process_limit(1, 1).unwrap();
        assert!(
            std::thread::Builder::new().spawn(|| ()).is_err(),
            "the process limit refuses a thread"
        );
        let ran = frozen.run(&pens, Some(Instant::now() + Duration::from_secs(1)), FLUSH);
        assert!(
            matches!(&ran, Err(Error::Held(reason)) if reason.contains("sweep thread")),
            "{:?}",
            ran.as_ref().err()
        );
        assert_eq!(totals(&frozen).next, 0);
        return;
    }
    if crate::sys::euid() == 0 {
        return;
    }
    let _processes = processes();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "campaign::seeds::tests::a_thread_that_cannot_start_fails_the_sweep",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "the child must complete exactly one test\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// A worker that does not exit at the end of its input is killed at the
/// end of its exit wait, and the monitor keeps the sweep's deadline
/// meanwhile: the worker here sleeps 20 seconds after its last root, and
/// the sweep ends at its deadline, well inside that time.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_that_outlives_the_end_of_its_input_is_killed() {
    let _processes = processes();
    let host = Delegation::new("exit");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("").replacen("done\n", "done\nexec sleep 20\n", 1);
    let mut frozen = frozen(&plan, &script);
    frozen.ready = Duration::from_millis(200);
    let began = Instant::now();
    frozen
        .run(&host.root(), Some(began + Duration::from_secs(1)), FLUSH)
        .unwrap();
    assert!(began.elapsed() < Duration::from_secs(10));
    let totals = totals(&frozen);
    assert!(totals.runs > 0);
    assert_eq!(totals.pass, totals.runs);
}

/// A worker killed at the end of its exit wait did not exit at the end
/// of its roots, so a process of its pen that is still exiting when the
/// worker is reaped makes no `left a process` suspect. Each worker here
/// stalls after its last root beside a child that reads 400 MB into
/// memory, which takes longer to exit than the worker does.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_worker_killed_at_its_exit_wait_leaves_no_suspect() {
    let _processes = processes();
    let host = Delegation::new("stall");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.memory = 2 << 30;
    plan.batch = Duration::from_millis(50);
    let held = "(x=$(head -c 400000000 /dev/zero | tr '\\0' x); sleep 20) &\nsleep 20\n";
    let script = passing("").replacen("done\n", &format!("done\n{held}"), 1);
    let mut frozen = frozen(&plan, &script);
    frozen.ready = Duration::from_millis(1500);
    let began = Instant::now();
    frozen
        .run(&host.root(), Some(began + Duration::from_secs(8)), FLUSH)
        .unwrap();
    assert_eq!(classes(&frozen), Vec::<String>::new());
    let totals = totals(&frozen);
    assert!(totals.runs > 0);
    assert_eq!(totals.pass, totals.runs);
}

/// A worker owes nothing between two runs, so the wall limit of a run it
/// finished kills no worker. The test holds the totals from the first
/// run's start until two monitor passes after that run's wall limit, so
/// the thread has read the run's block and waits to count it, and the
/// worker is still running then.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_finished_runs_wall_limit_kills_no_worker() {
    let _processes = processes();
    let host = Delegation::new("idle");
    let pens = host.root();
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.wall = Duration::from_secs(1);
    let frozen = frozen(&plan, &passing("sleep 0.1"));
    std::thread::scope(|scope| {
        let sweep = scope.spawn(|| frozen.run(&pens, None, FLUSH));
        let progress = loop {
            let progress = frozen.progress.lock().unwrap();
            if progress
                .profiles
                .get("upload")
                .is_some_and(|upload| upload.next == 1)
            {
                break progress;
            }
            drop(progress);
            std::thread::sleep(Duration::from_millis(1));
        };
        std::thread::sleep(Duration::from_millis(2200));
        let exited = frozen.running[0]
            .lock()
            .unwrap()
            .as_mut()
            .map(|running| running.child.try_wait().unwrap());
        frozen.stop.store(true, Ordering::Relaxed);
        drop(progress);
        sweep.join().unwrap().unwrap();
        assert_eq!(exited, Some(None));
    });
    let totals = totals(&frozen);
    assert_eq!((totals.runs, totals.pass, totals.suspects), (1, 1, 0));
}

/// A failed replacement of `sweep.json` stops the workers and fails the
/// sweep: `run` has no deadline here, and it returns the failure inside
/// the test's 10-second wait.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_failed_checkpoint_stops_the_workers_and_fails_the_sweep() {
    let _processes = processes();
    let host = Delegation::new("checkpoint");
    let pens = host.root();
    let case = Case::new();
    let plan = plan(&case, 2);
    let frozen = frozen(&plan, &passing(""));
    // A directory at the staging path fails every replacement.
    std::fs::create_dir(plan.root.join("sweep.json.tmp")).unwrap();
    let (sent, ended) = std::sync::mpsc::channel();
    let ran = std::thread::scope(|scope| {
        scope.spawn(|| sent.send(frozen.run(&pens, None, Duration::from_millis(100))));
        let ran = ended.recv_timeout(Duration::from_secs(10));
        // Ends the threads of a run that is still going, so the scope ends.
        frozen.stop.store(true, Ordering::Relaxed);
        ran
    });
    assert!(matches!(ran, Ok(Err(Error::Held(_)))), "{ran:?}");
    assert!(totals(&frozen).runs > 0);
}

/// A batch whose replay outlasts the batch window still takes a fresh seed
/// after it, so a profile of slow runs keeps exploring: every run here
/// takes four windows, and the sweep finishes several.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_batch_takes_a_fresh_seed_after_a_replay_longer_than_its_window() {
    let _processes = processes();
    let host = Delegation::new("replay");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let frozen = frozen(&plan, &passing("sleep 0.2"));
    let deadline = Instant::now() + Duration::from_secs(3);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let totals = totals(&frozen);
    assert!(totals.replays >= 2, "{} replays", totals.replays);
    assert!(totals.runs >= 3, "{} runs", totals.runs);
    assert_eq!(totals.pass, totals.runs);
}

#[test]
fn stored_totals_without_window_fields_report_unknown_coverage() {
    let case = Case::new();
    crate::store::replace_host(&case.root.join("sweep.json"), &swept(&pins('b'))).unwrap();
    let old = status(&case.root).unwrap().unwrap();
    assert_eq!(old["profiles"]["upload"]["windows"], json!({}));
    assert_eq!(old["profiles"]["upload"]["windows_unplanned"], json!([]));
    assert!(old.get("windows_missing").is_none());
}

#[test]
fn window_totals_sum_rebuilt_matching_ledgers_and_report_zero_rows() {
    let case = Case::new();
    let file = case.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&pins('b'))).unwrap();
    let mut progress = super::read(&case.root).unwrap().unwrap();
    let profile = "recovery-512";
    let other = "recovery-16k";
    let listing = include_str!("../../testdata/listing.txt")
        .replace("capabilities: 2", "capabilities: 5")
        + "fails: h1-get-unheld unsuccessful old read held\nprofile: recovery-16k class=recovery support=implemented campaign=unqualified held=actors=2,slots=1\n";
    let listing = Listing::parse(&listing).unwrap();
    let run = |profile: &str, code, ledger: &str, rows: &str| {
        let mut body = summary(&[("profile: upload", &format!("profile: {profile}"))]);
        if ledger != "credited" {
            body = body.replace("counts: true", "counts: false") + "cause: ledger gap\n";
        }
        let stages = if ledger.starts_with("inconclusive") {
            body = body.replace("complete pass", "complete inconclusive");
            "planned=4 reached=1 activated=1 recovered=1 checked=1 skipped=3"
        } else {
            "planned=4 reached=4 activated=4 recovered=4 checked=4 skipped=0"
        };
        let mut text = format!("root: 7\ncode: {code}\n{body}ledger: {ledger}\n");
        if !rows.is_empty() {
            text += &format!("stages: {stages}\nlimits: cold relaunch\nwindows: {rows}\n");
        }
        text += "end: 7\n";
        let parsed = block(&mut text.as_bytes(), 7, &listing).unwrap();
        assert!(parsed.summary().is_some(), "{text}");
        parsed
    };
    let count = |totals: &mut Totals, profile, block: &Block| {
        totals.count_block(
            profile,
            totals.runs,
            block,
            &block.ending(&word(profile)),
            0,
        );
    };
    let snapshot = |progress: &Progress| {
        crate::store::replace_host(&file, &serde_json::to_vec(progress).unwrap()).unwrap();
        status(&case.root).unwrap().unwrap()
    };
    let first_rows = "a=1 b=0 c=0 reuse=unplanned";
    let healthy_rows = "a=1 b=2 c=1 reuse=unplanned";
    let panic = read("code: 3\nrun: the run panicked at location\n", 7).unwrap();
    assert!(matches!(panic.run, Some(Run::Panicked(_))));
    for (label, swept, block) in [
        ("panic", profile, panic),
        (
            "unrecorded",
            profile,
            run(profile, 1, "unrecorded", first_rows),
        ),
        (
            "mismatched",
            profile,
            run(profile, 1, "mismatched Profile", first_rows),
        ),
        ("refused", profile, run(profile, 1, "refused Order", "")),
        (
            "wrong code",
            profile,
            run(profile, 3, "credited", first_rows),
        ),
        (
            "wrong profile",
            other,
            run(profile, 0, "credited", healthy_rows),
        ),
    ] {
        let mut totals = Totals::default();
        count(&mut totals, swept, &block);
        assert_eq!(totals.runs, 1, "{label}");
        assert!(
            totals.windows.is_empty() && totals.windows_unplanned.is_empty(),
            "{label}"
        );
    }
    let gap = run(profile, 1, "inconclusive bound", first_rows);
    assert!(matches!(
        gap.summary().unwrap().terminal,
        Terminal::Complete {
            outcome: Outcome::Inconclusive,
            ..
        }
    ));
    count(
        progress.profiles.entry(profile.into()).or_default(),
        profile,
        &gap,
    );
    count(
        progress.profiles.entry(other.into()).or_default(),
        other,
        &run(other, 1, "inconclusive bound", "x=0"),
    );
    let first = snapshot(&progress);
    assert_eq!(
        first["profiles"][profile]["windows"],
        json!({"a":1,"b":0,"c":0})
    );
    assert_eq!(
        first["windows_missing"],
        json!({"recovery-512":["b","c"],"recovery-16k":["x"]})
    );
    assert!(!carries_verdict(&first));
    count(
        progress.profiles.get_mut(profile).unwrap(),
        profile,
        &run(profile, 0, "credited", healthy_rows),
    );
    count(
        progress.profiles.get_mut(other).unwrap(),
        other,
        &run(other, 0, "credited", "x=1"),
    );
    let final_status = snapshot(&progress);
    assert_eq!(
        final_status["profiles"][profile]["windows"],
        json!({"a":2,"b":2,"c":1})
    );
    assert_eq!(
        final_status["profiles"][profile]["windows_unplanned"],
        json!(["reuse"])
    );
    assert!(final_status.get("windows_missing").is_none());
}

/// A root whose counts set `restarts` to 20 or more lists under
/// `no_window` each profile with 64 runs or more and a planned window at
/// zero, and its totals carry the sweep's verdict through that key alone.
/// The floor is each profile's own: `recovery-16k`, at 63 runs with a
/// window at zero, stays off the key beside a listed `recovery-512`. The
/// floor reads counted runs: a profile at 63 runs whose next run number is
/// 64 stays off it, and one at 65 runs is listed. Each profile also holds
/// one replay, which the checkpoint counts apart from its runs, and the
/// floor reads the runs alone.
/// Other counts on either side of `restarts` in the root's counts leave
/// the verdict in place. At 63 runs, at
/// `restarts=19`, at default counts, with another count of 20 or more in
/// place of `restarts`, with every planned window positive and with an
/// empty `windows` map the key is absent and the totals carry no verdict,
/// while `windows_missing` lists every window at zero. Each profile has one
/// pass, so `no_pass` stays off it.
#[test]
fn a_planned_window_at_zero_is_a_verdict_from_twenty_restarts_and_64_runs() {
    let case = Case::new();
    let file = case.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&pins('b'))).unwrap();
    let (profile, below) = ("recovery-512", "recovery-16k");
    let status_of = |counts: &[(&str, u64)], runs: u64, windows: &[(&str, u64)]| {
        let mut progress = super::read(&case.root).unwrap().unwrap();
        progress.counts = counts
            .iter()
            .map(|&(key, count)| (word(key), count))
            .collect();
        for (name, runs, windows) in [(profile, runs, windows), (below, 63, &[("x", 0), ("y", 1)])]
        {
            let totals = progress.profiles.entry(name.into()).or_default();
            (totals.next, totals.runs, totals.pass) = (runs.max(64), runs, 1);
            totals.replays = 1;
            totals.windows = windows
                .iter()
                .map(|&(name, count)| (name.into(), count))
                .collect();
        }
        crate::store::replace_host(&file, &serde_json::to_vec(&progress).unwrap()).unwrap();
        status(&case.root).unwrap().unwrap()
    };
    let gap = [("a", 3), ("b", 0), ("c", 2)];
    let missing = json!({profile: ["b"], below: ["x"]});
    for (counts, runs) in [
        (&[("restarts", 20)][..], 64),
        (&[("restarts", 20)][..], 65),
        (&[("restarts", 21)][..], 64),
        (&[("restarts", u64::MAX)][..], 64),
        (&[("actors", 2), ("restarts", 20), ("slots", 1)][..], 64),
    ] {
        let swept = status_of(counts, runs, &gap);
        assert_eq!(swept["no_window"], json!({profile: ["b"]}), "{counts:?}");
        assert_eq!(swept["windows_missing"], missing, "{counts:?}");
        for key in ["alarm", "no_pass", "unreached"] {
            assert!(swept.get(key).is_none(), "{key} at {counts:?}");
        }
        assert!(carries_verdict(&swept), "{counts:?}");
    }
    for (label, counts, runs) in [
        ("63 runs", &[("restarts", 20)][..], 63),
        ("restarts=19", &[("restarts", 19)][..], 64),
        ("default counts", &[][..], 64),
        ("slots=32", &[("slots", 32)][..], 64),
        (
            "restarts=1 slots=32",
            &[("restarts", 1), ("slots", 32)][..],
            64,
        ),
    ] {
        let swept = status_of(counts, runs, &gap);
        assert!(swept.get("no_window").is_none(), "{label}");
        assert_eq!(swept["windows_missing"], missing, "{label}");
        assert!(!carries_verdict(&swept), "{label}");
    }
    for (label, windows) in [
        ("every window positive", &[("a", 3), ("b", 1), ("c", 2)][..]),
        ("no window totals", &[][..]),
    ] {
        let swept = status_of(&[("restarts", 20)], 64, windows);
        assert!(swept.get("no_window").is_none(), "{label}");
        assert_eq!(swept["windows_missing"], json!({below: ["x"]}), "{label}");
        assert!(!carries_verdict(&swept), "{label}");
    }
}

/// The status of a root at `restarts` whose `recovery-512` profile holds
/// `totals` with 64 runs, or `runs` when given, a next run number of at
/// least 64 and one pass, after `edit` changes that profile's stored JSON.
fn window_status(
    case: &Case,
    totals: &Totals,
    restarts: u64,
    runs: u64,
    edit: impl Fn(&mut Value),
) -> (Value, Value) {
    let file = case.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&pins('b'))).unwrap();
    let mut progress = super::read(&case.root).unwrap().unwrap();
    progress.counts = [(word("restarts"), restarts)].into_iter().collect();
    let mut stored = totals.clone();
    (stored.next, stored.runs, stored.pass) = (runs.max(64), runs, 1);
    progress.profiles.insert("recovery-512".into(), stored);
    let mut json = serde_json::to_value(&progress).unwrap();
    let profile = json["profiles"]["recovery-512"].clone();
    edit(&mut json["profiles"]["recovery-512"]);
    crate::store::replace_host(&file, &serde_json::to_vec(&json).unwrap()).unwrap();
    (status(&case.root).unwrap().unwrap(), profile)
}

/// A planned total that sums two distinct counted rows, one at zero and
/// one positive, is listed under `no_window` at `restarts=20` and 64 runs,
/// while `windows_missing` holds no zero total. The rows meet under one
/// shortened name, under `other` once unplanned rows fill the name budget,
/// or under a name one row holds as its own and a longer row shortens to,
/// in either order and with either row at zero. A prefix of backslashes,
/// which take two escaped bytes each, is shortened at half as many
/// characters. The checkpoint records the
/// name as `null` in `windows_folded`, and at `restarts=1` the totals carry
/// no verdict.
#[test]
fn a_total_of_distinct_planned_rows_is_listed_under_no_window() {
    let case = Case::new();
    let prefix = "w".repeat(KEY_BOUND);
    let longer = format!("{prefix}1");
    let escaped = "\\".repeat(KEY_BOUND / 2);
    let mut overflow: Vec<_> = (0..KEYS).map(|at| (format!("u{at}"), None)).collect();
    overflow.extend([("p".to_owned(), Some(1)), ("q".to_owned(), Some(0))]);
    let cases = [
        (
            vec![(longer.clone(), Some(1)), (format!("{prefix}2"), Some(0))],
            prefix.as_str(),
        ),
        (overflow, OTHER),
        (
            vec![(prefix.clone(), Some(0)), (longer.clone(), Some(1))],
            prefix.as_str(),
        ),
        (
            vec![(prefix.clone(), Some(1)), (longer.clone(), Some(0))],
            prefix.as_str(),
        ),
        (
            vec![(longer.clone(), Some(0)), (prefix.clone(), Some(1))],
            prefix.as_str(),
        ),
        (
            vec![
                (format!("{escaped}1"), Some(1)),
                (format!("{escaped}2"), Some(0)),
            ],
            escaped.as_str(),
        ),
    ];
    for (at, (rows, folded)) in cases.into_iter().enumerate() {
        let mut totals = Totals::default();
        totals.count_windows(&rows);
        for (restarts, verdict) in [(20, true), (1, false)] {
            let (printed, stored) = window_status(&case, &totals, restarts, 64, |_| {});
            assert_eq!(stored["windows_folded"], json!({folded: null}), "case {at}");
            assert!(printed.get("windows_missing").is_none(), "case {at}");
            if verdict {
                assert_eq!(
                    printed["no_window"],
                    json!({"recovery-512": [folded]}),
                    "case {at}"
                );
            } else {
                assert!(printed.get("no_window").is_none(), "case {at}");
            }
            assert_eq!(carries_verdict(&printed), verdict, "case {at}");
        }
    }
}

/// A total that one counted row reaches under a shortened name or under
/// `other` keeps that row's count, so a positive one stays off `no_window`
/// at `restarts=20` and 64 runs, beside a zero row that is listed. Below the
/// floor, at 63 runs with a next run number of 64, neither is listed. An
/// unplanned row that shortens onto a planned name, or spills into a
/// planned row named `other`, adds nothing to the planned total and leaves
/// it off the key.
#[test]
fn a_total_of_one_planned_row_keeps_its_count() {
    let case = Case::new();
    let prefix = "w".repeat(KEY_BOUND);
    let lone = format!("{prefix}1");
    let mut totals = Totals::default();
    for _ in 0..2 {
        totals.count_windows(&[("b".to_owned(), Some(0)), (lone.clone(), Some(1))]);
    }
    let (printed, stored) = window_status(&case, &totals, 20, 64, |_| {});
    let digest = Digest::of(lone.as_bytes()).to_string();
    assert_eq!(stored["windows_folded"], json!({&prefix: digest}));
    assert_eq!(printed["no_window"], json!({"recovery-512": ["b"]}));
    assert_eq!(printed["windows_missing"], json!({"recovery-512": ["b"]}));
    let (printed, _) = window_status(&case, &totals, 20, 63, |_| {});
    assert!(printed.get("no_window").is_none());
    assert_eq!(printed["windows_missing"], json!({"recovery-512": ["b"]}));
    let mut spill: Vec<_> = (0..KEYS).map(|at| (format!("u{at}"), None)).collect();
    spill.push(("p".to_owned(), Some(1)));
    let mut onto = vec![(OTHER.to_owned(), Some(1))];
    onto.extend((1..=KEYS).map(|at| (format!("u{at}"), None)));
    for (label, rows) in [
        ("one row under other", spill),
        (
            "unplanned onto a prefix",
            vec![(prefix.clone(), Some(1)), (lone.clone(), None)],
        ),
        ("unplanned into other", onto),
    ] {
        let mut totals = Totals::default();
        totals.count_windows(&rows);
        totals.count_windows(&rows);
        let (printed, _) = window_status(&case, &totals, 20, 64, |_| {});
        assert!(printed.get("no_window").is_none(), "{label}");
        assert!(printed.get("windows_missing").is_none(), "{label}");
        assert!(!carries_verdict(&printed), "{label}");
    }
}

/// A checkpoint whose profile lacks the fold record, or holds it as
/// `null`, as one written before the record or rewritten by a supervisor
/// without it, treats `other` and each name [`key`] could have cut as a
/// total of distinct rows: at `restarts=20` and 64 runs `no_window` lists
/// them and the totals carry the verdict. A short name stays off it, and a
/// profile of short names alone carries no verdict. The length is the
/// name's escaped one: of two names of quotes, which take two bytes each,
/// the one of 251 escaped bytes is listed and the one of 250 is not. Rows
/// counted into such a profile keep it so. A profile with no fold stores an
/// empty record.
#[test]
fn a_profile_without_a_fold_record_lists_its_cut_names_and_other() {
    let case = Case::new();
    let cut = "w".repeat(KEY_BOUND - WIDEST + 1);
    let short = "w".repeat(KEY_BOUND - WIDEST);
    let quoted_short = "\"".repeat((KEY_BOUND - WIDEST) / 2);
    let quoted_cut = format!("{quoted_short}w");
    let totals = Totals {
        windows: [
            ("a", 1),
            (OTHER, 1),
            (cut.as_str(), 1),
            (short.as_str(), 1),
            (quoted_cut.as_str(), 1),
            (quoted_short.as_str(), 1),
        ]
        .into_iter()
        .map(|(name, count)| (name.to_owned(), count))
        .collect(),
        ..Totals::default()
    };
    let (printed, stored) = window_status(&case, &totals, 20, 64, |_| {});
    assert_eq!(stored["windows_folded"], json!({}));
    assert!(printed.get("no_window").is_none());
    let strip = |profile: &mut Value| {
        profile.as_object_mut().unwrap().remove("windows_folded");
    };
    let null = |profile: &mut Value| profile["windows_folded"] = Value::Null;
    for (label, edit) in [("absent", &strip as &dyn Fn(&mut Value)), ("null", &null)] {
        let (printed, _) = window_status(&case, &totals, 20, 64, edit);
        assert_eq!(
            printed["no_window"],
            json!({"recovery-512": [&quoted_cut, OTHER, &cut]}),
            "{label}"
        );
        assert!(printed.get("windows_missing").is_none(), "{label}");
        assert!(carries_verdict(&printed), "{label}");
    }
    let mut legacy = super::read(&case.root).unwrap().unwrap().profiles["recovery-512"].clone();
    legacy.count_windows(&[("w".repeat(KEY_BOUND + 1), Some(1))]);
    let (printed, stored) = window_status(&case, &legacy, 20, 64, |_| {});
    assert_eq!(stored["windows_folded"], Value::Null);
    let shortened = "w".repeat(KEY_BOUND);
    assert_eq!(
        printed["no_window"],
        json!({"recovery-512": [&quoted_cut, OTHER, &cut, &shortened]})
    );
    let plain = Totals {
        windows: [
            ("a".to_owned(), 1),
            (short.clone(), 1),
            (quoted_short.clone(), 1),
        ]
        .into_iter()
        .collect(),
        ..Totals::default()
    };
    let (printed, _) = window_status(&case, &plain, 20, 64, strip);
    assert!(printed.get("no_window").is_none());
    assert!(!carries_verdict(&printed));
}

/// With `no_pass` present, `no_window` still lists every planned window at
/// zero of each profile at the floor: two recovery profiles with 64 runs
/// and no pass stand under both keys, one of them with two rows at zero.
#[test]
fn no_window_lists_every_zero_row_beside_no_pass() {
    let case = Case::new();
    let file = case.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&pins('b'))).unwrap();
    let mut progress = super::read(&case.root).unwrap().unwrap();
    progress.counts = [(word("restarts"), 20)].into_iter().collect();
    for (name, windows) in [
        ("recovery-512", &[("a", 0), ("b", 0), ("c", 2)][..]),
        ("recovery-16k", &[("x", 0), ("y", 1)][..]),
    ] {
        let totals = progress.profiles.entry(name.into()).or_default();
        (totals.next, totals.runs, totals.pass, totals.caught) = (64, 64, 0, 0);
        totals.windows = windows
            .iter()
            .map(|&(name, count)| (name.into(), count))
            .collect();
    }
    crate::store::replace_host(&file, &serde_json::to_vec(&progress).unwrap()).unwrap();
    let printed = status(&case.root).unwrap().unwrap();
    assert_eq!(
        printed["no_window"],
        json!({"recovery-16k": ["x"], "recovery-512": ["a", "b"]})
    );
    assert_eq!(printed["no_pass"], json!(["recovery-16k", "recovery-512"]));
    assert!(carries_verdict(&printed));
}

/// `no_window` judges a profile by its window totals, whatever its name
/// and class: at `restarts=20` and 64 runs it lists `upload`, a profile
/// outside the recovery names, a control and a history, each with a
/// planned window at zero. The control's runs were all caught and the
/// others' all passed, so `no_pass` and `alarm` are absent and the
/// verdict rests on `no_window`.
#[test]
fn no_window_lists_a_control_a_history_and_a_profile_of_any_name() {
    let case = Case::new();
    let file = case.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&pins('b'))).unwrap();
    let mut progress = super::read(&case.root).unwrap().unwrap();
    progress.counts = [(word("restarts"), 20)].into_iter().collect();
    for (name, control, history, windows) in [
        ("upload", false, false, &[("a", 1), ("b", 0)][..]),
        ("planted", true, false, &[("x", 0)][..]),
        ("scripted", false, true, &[("y", 0), ("z", 2)][..]),
    ] {
        let totals = progress.profiles.entry(name.into()).or_default();
        (totals.next, totals.runs) = (64, 64);
        (totals.control, totals.history) = (control, Some(history));
        (totals.pass, totals.caught) = if control { (0, 64) } else { (64, 0) };
        totals.windows = windows
            .iter()
            .map(|&(name, count)| (name.into(), count))
            .collect();
    }
    crate::store::replace_host(&file, &serde_json::to_vec(&progress).unwrap()).unwrap();
    let printed = status(&case.root).unwrap().unwrap();
    assert_eq!(
        printed["no_window"],
        json!({"planted": ["x"], "scripted": ["y"], "upload": ["b"]})
    );
    for key in ["alarm", "no_pass", "unreached"] {
        assert!(printed.get(key).is_none(), "{key}");
    }
    assert!(carries_verdict(&printed));
}

/// A planned window at zero is listed under `windows_missing` and, at
/// `restarts=20` and 64 runs, under `no_window` when an unplanned row
/// holds the same stored name: the planned row is named `other`, and the
/// unplanned row past the name budget is stored under `other` too.
#[test]
fn a_planned_window_at_zero_is_listed_beside_an_unplanned_row_of_its_name() {
    let case = Case::new();
    let mut rows = vec![(OTHER.to_owned(), Some(0))];
    rows.extend((1..=KEYS).map(|at| (format!("u{at}"), None)));
    let mut totals = Totals::default();
    totals.count_windows(&rows);
    assert!(totals.windows_unplanned.contains(OTHER));
    let (printed, stored) = window_status(&case, &totals, 20, 64, |_| {});
    assert_eq!(stored["windows_folded"], json!({}));
    assert_eq!(printed["windows_missing"], json!({"recovery-512": [OTHER]}));
    assert_eq!(printed["no_window"], json!({"recovery-512": [OTHER]}));
    assert!(carries_verdict(&printed));
}

#[test]
fn window_names_share_the_profile_key_budget_and_counts_saturate() {
    let mut totals = Totals::default();
    let long = "x".repeat(KEY_BOUND + 1);
    let mut rows = vec![(long.clone(), Some(u64::MAX)), (long, Some(1))];
    rows.extend((1..KEYS).map(|at| (at.to_string(), None)));
    rows.extend([("beyond".into(), Some(2)), ("optional".into(), None)]);
    let (first, second) = rows.split_at(KEYS);
    totals.count_windows(first);
    totals.count_windows(second);
    assert_eq!(totals.windows[&"x".repeat(KEY_BOUND)], u64::MAX);
    assert_eq!(totals.windows.len(), 2);
    assert_eq!(totals.windows_unplanned.len(), KEYS);
    assert!(totals.windows_unplanned.contains(&(KEYS - 1).to_string()));
    assert_eq!(totals.windows[OTHER], 2);
    assert!(totals.windows_unplanned.contains(OTHER));
    assert!(
        !totals.windows.contains_key("beyond") && !totals.windows_unplanned.contains("optional")
    );
}

/// The totals after `runs` passing runs that each print the counting
/// summary with `edits` applied.
fn counted(runs: u64, edits: &[(&str, &str)]) -> Totals {
    let block = read(&format!("code: 0\n{}", summary(edits)), 7).unwrap();
    let mut totals = Totals::default();
    for run in 0..runs {
        totals.count(run, block.summary(), &block.ending(&word("upload")), 1);
    }
    totals
}

/// The topology and coverage lines identify a cluster summary even when the
/// draw is unavailable.
fn broad_summary(base: &str, drawn: bool) -> String {
    let base = base
        .replace("profile: upload", "profile: cluster-broad")
        .replace("owners: 1", "owners: 3");
    let lines = if drawn {
        "topology: owners=3 keys=6 hot=2\ncoverage: published=8 hits=1 misses=2 refused=3 invalidated=4 cancelled=0 cross=6 reused=7 healthy=9 faults=25"
    } else {
        "topology: unavailable\ncoverage: unavailable"
    };
    format!("{base}{lines}\nunavailable: node-lifecycle,membership\n")
}

/// Cluster passes count toward coverage even when the draw is unavailable.
/// Only drawn passes contribute event counts, while all summaries contribute operations and witnesses.
#[test]
fn only_covered_passes_add_event_counts() {
    let profile = word("cluster-broad");
    let mut totals = Totals::default();
    for (run, (body, code)) in [
        (unsuccessful(), 1),
        (COUNTING.to_owned(), 2),
        (COUNTING.to_owned(), 0),
    ]
    .into_iter()
    .enumerate()
    {
        let block = read(&format!("code: {code}\n{}", broad_summary(&body, true)), 7).unwrap();
        let ending = block.ending(&profile);
        totals.count(run as u64, block.summary(), &ending, 0);
        if code != 0 {
            assert_eq!(totals.covered, 0);
            assert!(totals.reached.is_empty());
        } else {
            let mut control = Totals {
                control: true,
                ..Totals::default()
            };
            let missed = judged(
                controls::named("cluster-wrong-owner").unwrap(),
                &block,
                ending,
            );
            assert!(missed.missed());
            control.count(0, block.summary(), &missed, 0);
            assert_eq!(control.covered, 0);
            assert!(control.reached.is_empty());
        }
    }
    assert_eq!((totals.operations, totals.witnesses), (54, 30));
    let missing = read(&format!("code: 0\n{}", broad_summary(COUNTING, false)), 7).unwrap();
    let mut fresh = Totals::default();
    fresh.count(0, missing.summary(), &missing.ending(&profile), 0);
    assert_eq!((fresh.pass, fresh.covered), (1, 1));
    assert!(fresh.reached.is_empty());
    totals.count(3, missing.summary(), &missing.ending(&profile), 0);
    assert_eq!((totals.pass, totals.covered), (2, 2));
    for (name, count) in COVERAGE.into_iter().zip([8, 1, 2, 3, 4, 0, 6, 7, 9, 25]) {
        let event = &totals.reached[name];
        assert_eq!(
            (event.runs, event.total),
            (u64::from(count > 0), count),
            "{name}"
        );
    }
    let event = totals.reached.get_mut("invalidated").unwrap();
    event.total = u64::MAX - 1;
    totals.witnesses = u64::MAX - 1;
    let block = read(&format!("code: 0\n{}", broad_summary(COUNTING, true)), 7).unwrap();
    totals.count(4, block.summary(), &block.ending(&profile), 0);
    let cross = &totals.reached["cross"];
    assert_eq!((cross.runs, cross.total), (2, 12));
    assert_eq!(
        (totals.reached["invalidated"].total, totals.witnesses),
        (u64::MAX, u64::MAX)
    );
    let upload = counted(3, &[]);
    assert_eq!(
        (upload.operations, upload.witnesses, upload.covered),
        (54, 30, 0)
    );
    assert!(upload.reached.is_empty());
}

/// A continued checkpoint retains historical work and adds reach from fresh
/// passes. Status reports shares with positive denominators and lists unreached
/// counters independently of the sweep verdict.
#[test]
fn the_status_lists_zero_reach_and_shares_with_a_denominator() {
    let case = Case::new();
    let checkpoint = case.root.join("sweep.json");
    let mut legacy: Value = serde_json::from_slice(&swept(&pins('b'))).unwrap();
    legacy["profiles"]["upload"]["operations"] = 18.into();
    crate::store::replace_host(&checkpoint, &serde_json::to_vec(&legacy).unwrap()).unwrap();
    let mut progress = super::read(&case.root).unwrap().unwrap();
    let upload = progress.profiles.get_mut("upload").unwrap();
    assert_eq!(
        (upload.witnesses, upload.covered, upload.reached.len()),
        (0, 0, 0)
    );
    let block = read(&format!("code: 0\n{COUNTING}"), 7).unwrap();
    upload.count(5, block.summary(), &block.ending(&word("upload")), 0);
    assert_eq!((upload.operations, upload.witnesses), (36, 10));
    progress.profiles.insert(
        "planted".into(),
        Totals {
            control: true,
            operations: 42,
            ..Default::default()
        },
    );
    progress.profiles.insert("idle".into(), Totals::default());
    let listed = |progress: &Progress| {
        crate::store::replace_host(&checkpoint, &serde_json::to_vec(progress).unwrap()).unwrap();
        status(&case.root).unwrap().unwrap()
    };
    for (cancelled, hits, unread) in [(0, 1, 5.0 / 6.0), (1, 7, 10.0 / 18.0)] {
        let summary = broad_summary(COUNTING, true)
            .replace("cancelled=0", &format!("cancelled={cancelled}"))
            .replace("hits=1", &format!("hits={hits}"));
        let block = read(&format!("code: 0\n{summary}"), 7).unwrap();
        progress
            .profiles
            .entry("cluster-broad".into())
            .or_default()
            .count(
                cancelled,
                block.summary(),
                &block.ending(&word("cluster-broad")),
                0,
            );
        let swept = listed(&progress);
        let profile = &swept["profiles"]["cluster-broad"];
        let covered = cancelled + 1;
        assert_eq!(profile["witnesses"], 10 * covered);
        assert_eq!(profile["covered"], covered);
        assert_eq!(
            profile["reached"]["invalidated"],
            json!({"runs": covered, "total": 4 * covered})
        );
        assert_eq!(
            profile["reached"]["cancelled"],
            json!({"runs": cancelled, "total": cancelled})
        );
        let zero = if cancelled == 0 {
            vec!["cancelled"]
        } else {
            vec![]
        };
        assert_eq!(swept["reach"]["cluster-broad"]["zero"], json!(zero));
        assert_eq!(
            swept["reach"],
            json!({
                "cluster-broad": {"covered": cancelled + 1, "zero": zero, "refused_actions": 1.0 - 10.0 / 18.0, "unread": unread},
                "upload": {"refused_actions": 26.0 / 36.0}
            })
        );
        assert!(!carries_verdict(&swept));
        progress = super::read(&case.root).unwrap().unwrap();
    }
}

/// A status share distinguishes a zero numerator from an empty population and
/// preserves small or negative differences between operation and witness counts.
#[test]
fn status_retains_defined_zero_and_signed_work_shares() {
    let case = Case::new();
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::from([
            (
                "cluster-broad".into(),
                Totals {
                    covered: 2,
                    pass: 2,
                    runs: 2,
                    next: 2,
                    ..Default::default()
                },
            ),
            ("upload".into(), Totals::default()),
        ]),
        elapsed_ms: 0,
        rules: vec![],
        batches: 0,
    };
    let listed = |progress: &Progress| {
        crate::store::replace_host(
            &case.root.join("sweep.json"),
            &serde_json::to_vec(progress).unwrap(),
        )
        .unwrap();
        status(&case.root).unwrap().unwrap()
    };
    assert_eq!(
        listed(&progress)["reach"]["cluster-broad"],
        json!({"covered": 2, "zero": COVERAGE})
    );
    progress
        .profiles
        .get_mut("cluster-broad")
        .unwrap()
        .reached
        .insert("hits".into(), EventReach { runs: 1, total: 1 });
    assert_eq!(listed(&progress)["reach"]["cluster-broad"]["unread"], 0.0);
    let upload = progress.profiles.get_mut("upload").unwrap();
    upload.operations = (1 << 53) + 1;
    upload.witnesses = 1 << 53;
    assert_eq!(
        listed(&progress)["reach"]["upload"]["refused_actions"],
        1.0 / ((1u64 << 53) + 1) as f64
    );
    let upload = progress.profiles.get_mut("upload").unwrap();
    upload.operations = 2;
    upload.witnesses = 3;
    assert_eq!(
        listed(&progress)["reach"]["upload"]["refused_actions"],
        -0.5
    );
    progress.profiles.get_mut("upload").unwrap().witnesses = 2;
    assert_eq!(listed(&progress)["reach"]["upload"]["refused_actions"], 0.0);
    let cluster = progress.profiles.get_mut("cluster-broad").unwrap();
    cluster.operations = 2;
    let before = listed(&progress);
    progress
        .profiles
        .get_mut("cluster-broad")
        .unwrap()
        .failing_history = true;
    assert_eq!(
        listed(&progress)["reach"]["cluster-broad"],
        before["reach"]["cluster-broad"]
    );
}

/// Skips shorter than a second carry into the whole seconds: 3,000 runs
/// that each skip 500 microseconds total one second and 500,000
/// microseconds, and each run counts as a pass with its busy time.
#[test]
fn counted_runs_carry_their_skipped_microseconds_into_seconds() {
    let totals = counted(3_000, &[("skipped_us: 0", "skipped_us: 500")]);
    assert_eq!((totals.skipped_s, totals.skipped_us), (1, 500_000));
    assert_eq!(
        (totals.runs, totals.pass, totals.busy_us),
        (3_000, 3_000, 3_000)
    );
    assert_eq!(totals.active_us, 3_000 * 100);
}

/// Two runs that each skip half of `u64::MAX` microseconds total more
/// than one microsecond counter holds: the seconds and the microseconds
/// past them hold the whole sum, and the time outside the skips adds up
/// beside it.
#[test]
fn counted_runs_total_skips_past_a_microsecond_counter() {
    let totals = counted(
        2,
        &[
            ("virtual_us: 600", "virtual_us: 9223372036854776408"),
            ("skipped_us: 0", "skipped_us: 9223372036854775808"),
        ],
    );
    assert_eq!(
        (totals.skipped_s, totals.skipped_us),
        (18_446_744_073_709, 551_616)
    );
    assert_eq!((totals.active_us, totals.pass), (1_200, 2));
}

/// A count a summary prints near `u64::MAX` holds its total at the
/// maximum: two runs that each print that many turns leave the turns
/// there, and both runs count.
#[test]
fn counted_runs_hold_a_total_at_its_maximum() {
    let totals = counted(2, &[("turns: 57", "turns: 18446744073709551615")]);
    assert_eq!((totals.turns, totals.runs, totals.pass), (u64::MAX, 2, 2));
}

/// An uncredited run adds to its rule's count and is one of the rule's
/// first [`EXAMPLES`] run numbers, and it is no pass.
#[test]
fn counted_uncredited_runs_keep_their_first_examples() {
    let block = read(&format!("code: 1\n{}", unsuccessful()), 7).unwrap();
    let mut totals = Totals::default();
    for run in 0..(EXAMPLES as u64 + 3) {
        totals.count(run, block.summary(), &block.ending(&word("upload")), 0);
    }
    let rule = "unsuccessful: fewer exact reads";
    assert_eq!(totals.uncredited[rule], EXAMPLES as u64 + 3);
    assert_eq!(
        totals.uncredited_runs[rule],
        (0..EXAMPLES as u64).collect::<Vec<_>>()
    );
    assert_eq!((totals.runs, totals.pass), (EXAMPLES as u64 + 3, 0));
}

/// The totals add each run's skipped virtual time in microseconds, so
/// runs that each skip less than a second add up: every run here skips
/// 500 microseconds, and the profile's total is 500 for each run.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn skips_shorter_than_a_second_add_up_in_the_totals() {
    let _processes = processes();
    let host = Delegation::new("skips");
    let case = Case::new();
    let plan = plan(&case, 1);
    let skipping = passing("").replacen("skipped_us: 0", "skipped_us: 500", 1);
    let frozen = frozen(&plan, &skipping);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    frozen.flush().unwrap();
    let status = status(&plan.root).unwrap().unwrap();
    let runs = status["runs"].as_u64().unwrap();
    assert!(runs > 0);
    assert!(status["skipped_virtual_years"].as_f64().unwrap() > 0.0);
    let upload = &status["profiles"]["upload"];
    let skipped =
        upload["skipped_s"].as_u64().unwrap() * 1_000_000 + upload["skipped_us"].as_u64().unwrap();
    assert_eq!(skipped, 500 * runs);
}

/// The skipped virtual time is totalled in whole seconds and the
/// microseconds past them, so runs with long rests add up past what one
/// microsecond counter holds: every run here skips half of `u64::MAX`
/// microseconds, more than 292,000 virtual years, and the status reports
/// that much for each run.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn skips_past_a_microsecond_counter_add_up_in_the_totals() {
    let _processes = processes();
    let host = Delegation::new("carry");
    let case = Case::new();
    let plan = plan(&case, 1);
    let skipping = passing("")
        .replacen("virtual_us: 600", "virtual_us: 9223372036854776408", 1)
        .replacen("skipped_us: 0", "skipped_us: 9223372036854775808", 1);
    let frozen = frozen(&plan, &skipping);
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    frozen.flush().unwrap();
    let status = status(&plan.root).unwrap().unwrap();
    let runs = status["runs"].as_u64().unwrap();
    assert!(runs >= 2, "{runs} runs");
    assert_eq!(status["pass"], runs);
    let years = status["skipped_virtual_years"].as_f64().unwrap();
    assert!(
        years >= 292_000.0 * runs as f64,
        "{years} years in {runs} runs"
    );
}

/// The monitor stops the workers at the sweep's deadline, so a deadline
/// inside the monitor's signal wait is kept: each run here takes 300 ms
/// and the deadline is 50 ms away, so at most the run in progress then
/// is finished.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_deadline_inside_the_monitors_wait_stops_the_workers_at_the_deadline() {
    let _processes = processes();
    let host = Delegation::new("deadline");
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, &passing("sleep 0.3"));
    let deadline = Instant::now() + Duration::from_millis(50);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let runs = totals(&frozen).runs;
    assert!(runs <= 1, "{runs} runs");
}

/// A worker starts from a cleared environment: it holds the variables the
/// approved command sets and the allocator settings `worker` adds.
/// `CARGO_MANIFEST_DIR`, which this process holds and the command leaves
/// unset, reads as unset in the worker.
#[test]
fn a_worker_holds_only_the_approved_commands_environment() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    let script = "#!/bin/sh\necho \"${CARGO_MANIFEST_DIR+inherited}:$KEPT\"\n";
    let mut frozen = frozen(&plan, script);
    frozen.environment = vec![("KEPT".into(), Some("kept".into()))];
    let output = frozen.worker("upload").unwrap().wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout), ":kept\n");
}

/// A worker inherits the blocked SIGINT and SIGTERM of the sweep thread
/// that starts it, so an interrupt sent to it stays pending and it
/// finishes its run. The worker here is sent SIGINT while it waits for a
/// root, then reads the end of its input and exits 0.
#[test]
fn a_worker_keeps_the_sweeps_blocked_interruptions() {
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "#!/bin/sh\nread root\nexit 0\n");
    let status = std::thread::scope(|scope| {
        let swept = scope.spawn(|| {
            crate::sys::block_interruptions().unwrap();
            let mut child = frozen.worker("upload").unwrap();
            let interrupt = format!("kill -INT {}", child.id());
            let sent = Command::new("/bin/sh").args(["-c", &interrupt]).status();
            assert!(sent.unwrap().success());
            drop(child.stdin.take());
            child.wait().unwrap()
        });
        swept.join().unwrap()
    });
    assert_eq!(status.code(), Some(0), "{status}");
}

/// A worker ends when the thread that started it ends, so a sweep that
/// dies, as from a terminal's hangup, leaves no worker in a run with
/// nothing to bound it. The thread here starts a worker that sleeps 20
/// seconds and returns: the worker is killed well inside that time.
#[test]
fn a_worker_ends_with_the_thread_that_started_it() {
    use std::os::unix::process::ExitStatusExt;
    let _processes = processes();
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "#!/bin/sh\necho 'sweep: ready'\nexec sleep 20\n");
    let began = Instant::now();
    let mut child = std::thread::scope(|scope| {
        scope
            .spawn(|| frozen.worker("upload").unwrap())
            .join()
            .unwrap()
    });
    let status = child.wait().unwrap();
    assert!(began.elapsed() < Duration::from_secs(10));
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status}");
}

/// The block of `root` in `text`, parsed against the testdata listing.
fn parsed(text: &str, root: u64) -> Option<Block> {
    block(
        &mut text.as_bytes(),
        root,
        &Listing::parse(LISTING).unwrap(),
    )
}

fn read(body: &str, root: u64) -> Option<Block> {
    parsed(&format!("root: 7\n{body}end: 7\n"), root)
}

/// The counting summary with each `(from, to)` of `edits` replaced once.
fn summary(edits: &[(&str, &str)]) -> String {
    let mut text = COUNTING.to_owned();
    for (from, to) in edits {
        assert!(text.contains(from), "{from}");
        text = text.replacen(from, to, 1);
    }
    text
}

/// How the block of exit code `code` and lines `body` ends.
fn ended(code: i32, body: &str) -> Ending {
    read(&format!("code: {code}\n{body}"), 7)
        .unwrap()
        .ending(&word("upload"))
}

const UNCOUNTED: (&str, &str) = ("counts: true", "counts: false");

fn unsuccessful() -> String {
    summary(&[
        ("complete pass", "complete unsuccessful"),
        UNCOUNTED,
        (
            "stop: goal\n",
            "stop: goal\ncause: unsuccessful\nunsuccessful: fewer exact reads\n",
        ),
    ])
}

fn violation() -> String {
    summary(&[
        ("complete pass", "complete violation"),
        UNCOUNTED,
        ("stop: goal\n", "stop: goal\ncause: violation\n"),
    ])
}

/// A summary that ends at the infrastructure terminal `terminal`.
fn infrastructure(terminal: &str) -> String {
    summary(&[
        ("complete pass fired=03 required=03", terminal),
        UNCOUNTED,
        ("stop: goal\n", "stop: goal\ncause: infrastructure\n"),
    ])
}

/// A run counts as a pass only with exit code 0 and a counting summary.
/// An unsuccessful, inconclusive or capped run is counted under its rule.
/// Every other ending is a suspect of its class.
#[test]
fn a_block_ends_as_its_code_and_summary_say() {
    let uncredited = |rule: &str| Ending::Uncredited(rule.to_owned());
    let suspect = |class: &str| Ending::Suspect(class.to_owned());
    for (code, body, ending) in [
        (0, summary(&[]), Ending::Pass),
        (
            1,
            unsuccessful(),
            uncredited("unsuccessful: fewer exact reads"),
        ),
        (
            1,
            summary(&[
                ("complete pass", "complete inconclusive"),
                UNCOUNTED,
                ("stop: goal\n", "stop: limit no_progress\ncause: limit\n"),
            ]),
            uncredited("inconclusive: limit no_progress"),
        ),
        (
            3,
            infrastructure("infrastructure cap"),
            uncredited("inconclusive: recorder cap"),
        ),
        (1, violation(), suspect("violation")),
        (
            3,
            "run: the run panicked at a.rs:1:2: b\n".to_owned(),
            suspect("panic"),
        ),
        (2, "refused: Profile\n".to_owned(), suspect("no terminal")),
        (3, "load: Truncated\n".to_owned(), suspect("no terminal")),
        (
            3,
            infrastructure("infrastructure defect"),
            suspect("infrastructure defect"),
        ),
    ] {
        assert_eq!(ended(code, &body), ending, "{code} {body}");
    }
}

/// A recovery run that passes while its ledger refuses the bundle does
/// not count, and the sweep counts it under its cause.
#[test]
fn a_pass_its_ledger_refuses_is_counted_under_its_cause() {
    let listing = Listing::parse(include_str!("../../testdata/listing.txt")).unwrap();
    let body = summary(&[
        ("profile: upload", "profile: recovery-512"),
        UNCOUNTED,
        (
            "stop: goal\n",
            "stop: goal\ncause: the campaign ledger is Refused\nledger: refused Truncated { at: 3 }\n",
        ),
    ]);
    let text = format!("root: 7\ncode: 1\n{body}end: 7\n");
    let block = block(&mut text.as_bytes(), 7, &listing).unwrap();
    assert_eq!(
        block.ending(&word("recovery-512")),
        Ending::Uncredited("inconclusive: uncredited pass, the campaign ledger is Refused".into())
    );
}

/// The run form exits 0 for a counting summary, 1 for another complete one
/// and 3 for an incomplete one. A block whose exit code is another, such
/// as the 3 of a run whose bundle reloads to another result, is a suspect,
/// and so is a summary that counts without a decision.
#[test]
fn an_exit_code_that_disagrees_with_its_summary_is_a_suspect() {
    for (code, body) in [
        (3, summary(&[])),
        (1, summary(&[])),
        (0, summary(&[("decisions: 61", "decisions: 0")])),
        (0, violation()),
        (3, unsuccessful()),
        (1, infrastructure("infrastructure cap")),
    ] {
        assert_eq!(
            ended(code, &body),
            Ending::Suspect("exit code disagrees with the summary".into()),
            "{code} {body}"
        );
    }
}

/// A summary the protocol's parser refuses, here one without its `turns`
/// line, is a suspect under each exit code of the run form.
#[test]
fn a_summary_that_does_not_parse_is_a_suspect() {
    for code in [0, 1, 3] {
        assert_eq!(
            ended(code, &summary(&[("turns: 57\n", "")])),
            Ending::Suspect("malformed summary".into()),
            "{code}"
        );
    }
}

/// The lines of the root's `suspects.jsonl`.
fn listed(plan: &Plan) -> usize {
    std::fs::read_to_string(plan.root.join("suspects.jsonl"))
        .unwrap()
        .lines()
        .count()
}

/// Panics at one location are one failure identity whatever values their
/// messages hold, so the list keeps the first [`EXAMPLES`] of them and
/// the totals hold one key.
#[test]
fn panics_at_one_location_share_their_examples() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    for run in 0..20 {
        let body =
            format!("code: 3\nrun: the run panicked at src/a.rs:1:2: index {run} out of range\n");
        let block = read(&body, 7).unwrap();
        frozen
            .suspect(&word("upload"), run, 7, "panic", Some(&block))
            .unwrap();
    }
    let totals = totals(&frozen);
    assert_eq!(totals.suspects, 20);
    assert_eq!(
        totals.suspect_keys.keys().collect::<Vec<_>>(),
        ["panic: src/a.rs:1:2"]
    );
    assert_eq!(listed(&plan), EXAMPLES);
}

/// A profile keys at most [`KEYS`] failure identities. A suspect of a
/// later identity is counted under one shared key, which lists its first
/// [`EXAMPLES`], so the totals and the list stay bounded.
#[test]
fn a_profile_keys_a_bounded_number_of_failure_identities() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    let extra = 20;
    for run in 0..(KEYS + extra) as u64 {
        let body = format!("code: 1\n{}identity: {run:088x}\n", violation());
        let block = read(&body, 7).unwrap();
        frozen
            .suspect(&word("upload"), run, 7, "violation", Some(&block))
            .unwrap();
    }
    let totals = totals(&frozen);
    assert_eq!(totals.suspects, (KEYS + extra) as u64);
    assert_eq!(totals.suspect_keys.len(), KEYS + 1);
    assert_eq!(totals.suspect_keys[OTHER], extra as u64);
    assert_eq!(listed(&plan), KEYS + EXAMPLES);
}

#[test]
fn a_listed_suspect_names_the_key_that_counts_it() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    let extra = 3;
    for run in 0..(KEYS + extra) as u64 {
        let body = format!("code: 1\n{}identity: {run:088x}\n", violation());
        let block = read(&body, 7).unwrap();
        frozen
            .suspect(&word("upload"), run, 7, "violation", Some(&block))
            .unwrap();
    }
    let long = "\u{1}".repeat(4 << 10);
    let panic = format!("code: 3\nrun: the run panicked at 9 {long}\n");
    frozen
        .suspect(
            &word("pull"),
            9,
            7,
            "panic",
            Some(&read(&panic, 7).unwrap()),
        )
        .unwrap();
    let totals = totals(&frozen);
    let text = std::fs::read_to_string(plan.root.join("suspects.jsonl")).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let (cut, lines) = lines.split_last().unwrap();
    // "panic: 9 " takes 9 bytes of the key's JSON form and each U+0001 six,
    // so 41 of them fill it to 255 of its 256 bytes.
    let expected = format!("panic: 9 {}", "\u{1}".repeat(41));
    assert_eq!(cut["key"], expected.as_str());
    let pull = frozen.progress.lock().unwrap().profiles["pull"].clone();
    assert_eq!(pull.suspect_keys[&expected], 1);
    let keys: Vec<String> = lines
        .iter()
        .map(|line| {
            let run = line["run"].as_u64().unwrap();
            let expected = if run < KEYS as u64 {
                format!("violation: {run:088x}")
            } else {
                OTHER.to_owned()
            };
            assert_eq!(line["key"], expected.as_str(), "run {run}");
            assert!(totals.suspect_keys.contains_key(&expected), "{expected}");
            expected
        })
        .collect();
    assert_eq!(keys.len(), KEYS + extra);
    assert_eq!(keys.iter().filter(|key| *key == OTHER).count(), extra);
    assert_eq!(
        keys.iter().collect::<std::collections::BTreeSet<_>>().len(),
        KEYS + 1
    );
    let (suspects, lines) = super::suspects(&plan.root, 0).unwrap();
    assert_eq!(
        (suspects.len(), lines),
        (KEYS + extra + 1, KEYS + extra + 1)
    );
    assert_eq!(suspects[0].request.run, 0);
    assert_eq!(suspects[0].seed, 7);
}

/// The text `other` and the eight lines listed under a key are values of
/// the stored root's format, so the test states them as literals.
#[test]
fn a_full_profile_counts_later_identities_under_other_and_lists_eight() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    let later = 9;
    for run in 0..(KEYS + later) as u64 {
        let body = format!("code: 1\n{}identity: {run:088x}\n", violation());
        let block = read(&body, 7).unwrap();
        frozen
            .suspect(&word("upload"), run, 7, "violation", Some(&block))
            .unwrap();
    }
    assert_eq!(totals(&frozen).suspect_keys["other"], later as u64);
    let text = std::fs::read_to_string(plan.root.join("suspects.jsonl")).unwrap();
    let listed = text
        .lines()
        .filter(|line| serde_json::from_str::<Value>(line).unwrap()["key"] == "other")
        .count();
    assert_eq!(listed, 8);
}

/// The totals count a suspect after its line is appended. A failed append
/// leaves the suspect count and the key counts as they were, and its
/// error names the list and the run it could not list, which a later
/// sweep does not run again, so the run can be admitted as a job.
#[test]
fn a_failed_append_leaves_the_suspect_totals_unchanged() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    // A directory at the list's path fails every append.
    std::fs::create_dir(plan.root.join("suspects.jsonl")).unwrap();
    let block = read("code: 3\nrun: the run panicked at src/a.rs:1:2: b\n", 7).unwrap();
    let listed = frozen.suspect(&word("upload"), 4, 7, "panic", Some(&block));
    assert!(
        matches!(
            &listed,
            Err(Error::Held(reason))
                if reason.contains("suspects.jsonl") && reason.contains("run 4 of upload")
        ),
        "{listed:?}"
    );
    let totals = totals(&frozen);
    assert_eq!(totals.suspects, 0);
    assert_eq!(totals.suspect_keys, BTreeMap::new());
}

/// A block holds its exit code and each printed key's first value.
#[test]
fn a_block_keeps_each_fields_first_value() {
    let block = read("code: 1\nturns: 12\nturns: 99\nstop: goal\n", 7).unwrap();
    assert_eq!(block.code, Some(1));
    assert_eq!(
        block.fields(),
        BTreeMap::from([("turns", "12"), ("stop", "goal")])
    );
}

/// Output that ends before the block's `end` line, opens or closes
/// another root, holds a field before its `root` line or holds a line
/// without a separator is no block, so the sweep records the run as a
/// suspect.
#[test]
fn output_that_is_not_the_roots_whole_block_is_no_block() {
    assert!(read("code: 0\n", 8).is_none());
    for text in [
        "root: 7\ncode: 0\n",
        "root: 7\ncode: 0\nend: 8\n",
        "code: 0\nend: 7\n",
        "root: 7\nno separator\nend: 7\n",
        "",
    ] {
        assert!(parsed(text, 7).is_none(), "{text:?}");
    }
}

/// A summary counts for the profile it names. A worker that prints the
/// passing summary of another listed profile than the one it sweeps earns
/// no pass, and each such run is a suspect.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_summary_of_another_profile_is_a_suspect() {
    let _processes = processes();
    let host = Delegation::new("profile");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.profiles = vec![word("cluster-broad")];
    let frozen = frozen(&plan, &passing(""));
    let deadline = Instant::now() + Duration::from_millis(300);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    let progress = frozen.progress.lock().unwrap();
    let totals = &progress.profiles["cluster-broad"];
    assert!(totals.runs > 0);
    assert_eq!(totals.pass, 0);
    assert_eq!(
        totals.suspect_keys.get("summary of another profile: "),
        Some(&totals.runs)
    );
}

/// A block holds at most [`BLOCK_BOUND`] bytes, so a worker that prints
/// without end costs the sweep that much memory: a block one line past the
/// bound is no block, and the sweep records the run as a suspect.
#[test]
fn a_block_past_its_bound_is_no_block() {
    let line = format!("note: {}\n", "x".repeat(1 << 16));
    let lines = (BLOCK_BOUND as usize / line.len()) + 1;
    let text = format!("root: 7\ncode: 0\n{}end: 7\n", line.repeat(lines));
    assert!(parsed(&text, 7).is_none());
    let listing = Listing::parse(LISTING).unwrap();
    let mut endless = BufReader::new(std::io::repeat(b'x'));
    assert!(block(&mut endless, 7, &listing).is_none());
    let mut endless = "root: 7\n"
        .as_bytes()
        .chain(BufReader::new(std::io::repeat(b'x')));
    assert!(block(&mut endless, 7, &listing).is_none());
}

/// A block's lines reach the parser as the worker printed them, without
/// their newline alone, so a field with trailing whitespace, which the
/// parser refuses, does not count as a pass.
#[test]
fn a_field_with_trailing_whitespace_is_a_malformed_summary() {
    assert_eq!(ended(0, &summary(&[])), Ending::Pass);
    for (from, to) in [
        ("counts: true", "counts: true "),
        ("turns: 57", "turns: 57\t"),
    ] {
        assert_eq!(
            ended(0, &summary(&[(from, to)])),
            Ending::Suspect("malformed summary".into()),
            "{to:?}"
        );
    }
}

/// A block holds one exit code. A block with a second `code` line, as two
/// runs' output run together would hold, is no block, whichever code
/// comes last.
#[test]
fn a_block_with_two_codes_is_no_block() {
    assert!(read(&format!("code: 0\n{COUNTING}"), 7).is_some());
    assert!(read(&format!("code: 3\n{COUNTING}code: 0\n"), 7).is_none());
    assert!(read(&format!("code: 0\ncode: 0\n{COUNTING}"), 7).is_none());
}

/// `suspects` returns the job and swept root of each line after `from`
/// and the number of lines read, and holds on a line that is no suspect,
/// such as one without its root. The line of a run whose replay differs
/// names the same job as any other: its class and first observation are
/// not part of the job.
#[test]
fn suspects_name_the_supervised_jobs_of_the_lines_after_from() {
    let case = Case::new();
    assert!(matches!(suspects(&case.root, 0), Ok((suspects, 0)) if suspects.is_empty()));
    let file = case.root.join("suspects.jsonl");
    for run in [4, 9] {
        let line = json!({"campaign": "host", "profile": "upload", "run": run, "counts": {"turns": 64}, "seed": run + 100, "build": "b0"});
        crate::store::append_host(&file, format!("{line}\n").as_bytes()).unwrap();
    }
    let (listed, lines) = suspects(&case.root, 0).unwrap();
    assert_eq!(lines, 2);
    assert_eq!(
        listed
            .iter()
            .map(|suspect| (suspect.request.run, suspect.seed))
            .collect::<Vec<_>>(),
        [(4, 104), (9, 109)]
    );
    assert_eq!(listed[0].build.as_str(), "b0");
    let request = &listed[0].request;
    assert_eq!(request.profile.as_str(), "upload");
    assert_eq!(request.campaign.as_str(), "host");
    assert_eq!(request.counts, [(word("turns"), 64)].into());
    let (later, lines) = suspects(&case.root, 1).unwrap();
    assert_eq!((later.len(), later[0].request.run, lines), (1, 9, 2));
    let differing = json!({"campaign": "host", "profile": "upload", "run": 10, "counts": {"turns": 64}, "seed": 110, "build": "b0", "class": "replay differs", "first": {"digest": "d", "ending": "pass"}});
    crate::store::append_host(&file, format!("{differing}\n").as_bytes()).unwrap();
    let (replayed, _) = suspects(&case.root, 2).unwrap();
    assert_eq!(
        (replayed.len(), replayed[0].request.run, replayed[0].seed),
        (1, 10, 110)
    );
    assert_eq!(replayed[0].request.counts, request.counts);
    let rootless =
        json!({"campaign": "host", "profile": "upload", "run": 11, "counts": {}, "build": "b0"});
    crate::store::append_host(&file, format!("{rootless}\n").as_bytes()).unwrap();
    assert!(matches!(suspects(&case.root, 0), Err(Error::Held(_))));
    assert!(suspects(&case.root, 4).is_ok());
}

/// The reader's line bound holds the longest line the sweep writes. A
/// block of the block bound whose bytes each take a six-byte escape in
/// JSON, as NUL does, is listed in one line, and `suspects` reads it.
/// The line of a run whose replay differs holds text of two blocks, the
/// run's ending beside the replay's fields, and `suspects` reads that as
/// well.
#[test]
fn the_longest_suspect_line_is_read() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    let filler = "\0".repeat(BLOCK_BOUND as usize - 64);
    let block = read(&format!("code: 3\nnote: {filler}\n"), 7).unwrap();
    frozen
        .suspect(&word("upload"), 4, 7, "no terminal", Some(&block))
        .unwrap();
    let written = std::fs::metadata(plan.root.join("suspects.jsonl"))
        .unwrap()
        .len();
    assert!(written > 6 * (BLOCK_BOUND - 64), "{written} bytes");
    let (listed, lines) = suspects(&plan.root, 0).unwrap();
    assert_eq!((listed.len(), listed[0].request.run, lines), (1, 4, 1));
    let first = (
        None,
        Ending::Uncredited(format!("inconclusive: uncredited pass, {filler}")),
    );
    frozen
        .list(
            &word("upload"),
            5,
            7,
            "replay differs",
            Some(&block),
            Some(&first),
        )
        .unwrap();
    let written = std::fs::metadata(plan.root.join("suspects.jsonl"))
        .unwrap()
        .len()
        - written;
    assert!(written > 12 * (BLOCK_BOUND - 64), "{written} bytes");
    let (listed, lines) = suspects(&plan.root, 1).unwrap();
    assert_eq!((listed.len(), listed[0].request.run, lines), (1, 5, 2));
}

/// No line the sweep writes passes the reader's bound, whatever its
/// fields hold. A suspect whose line would pass it is listed with its job
/// and without the run's output, so `confirm` still admits it.
#[test]
fn a_suspect_line_past_the_readers_bound_is_listed_without_its_output() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    let block = read(&format!("code: 3\nnote: {}\n", "\0".repeat(1 << 19)), 7).unwrap();
    let first = (
        None,
        Ending::Uncredited("\0".repeat(LINE_BOUND as usize / 6)),
    );
    frozen
        .list(
            &word("upload"),
            6,
            7,
            "replay differs",
            Some(&block),
            Some(&first),
        )
        .unwrap();
    let written = std::fs::read_to_string(plan.root.join("suspects.jsonl")).unwrap();
    assert!(written.len() < 1 << 10, "{} bytes", written.len());
    let line: Value = serde_json::from_str(written.trim_end()).unwrap();
    assert_eq!(
        (
            &line["class"],
            &line["code"],
            &line["summary"],
            &line["first"]
        ),
        (
            &json!("replay differs"),
            &json!(3),
            &Value::Null,
            &Value::Null
        )
    );
    // The block names no identity, so the line's key is the class and an
    // empty identity, and the totals count the line under it.
    assert_eq!(line["key"], "replay differs: ");
    assert_eq!(totals(&frozen).suspect_keys["replay differs: "], 1);
    let (listed, lines) = suspects(&plan.root, 0).unwrap();
    assert_eq!(
        (listed.len(), listed[0].request.run, listed[0].seed, lines),
        (1, 6, 7, 1)
    );
}

/// `sweep.json` holds worker text in its keys, a rule's cause and a
/// failure's identity, and every reader of it has a byte bound. A key is
/// cut to [`KEY_BOUND`] bytes of its JSON form and a profile keys [`KEYS`] rules, the rest
/// under `other`, as it keys its identities, so a worker that prints
/// long or ever-new text leaves a file `status` reads. Here 300 runs
/// each end under their own cause of 4 KiB, and three panic with their
/// own payload of that length.
#[test]
fn keys_a_worker_names_stay_inside_the_checkpoints_bound() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let frozen = frozen(&plan, "");
    let long = "\u{1}".repeat(4 << 10);
    for run in 0..300 {
        let rule = format!("inconclusive: uncredited pass, {run} {long}");
        frozen
            .progress
            .lock()
            .unwrap()
            .profiles
            .entry("upload".to_owned())
            .or_default()
            .uncredit(&rule, run);
    }
    for run in 0..3 {
        let body = format!("code: 3\nrun: the run panicked at {run} {long}\n");
        let block = read(&body, 7).unwrap();
        frozen
            .suspect(&word("upload"), run, 7, "panic", Some(&block))
            .unwrap();
    }
    frozen.flush().unwrap();
    let totals = totals(&frozen);
    assert_eq!(totals.uncredited.values().sum::<u64>(), 300);
    assert_eq!(totals.uncredited.len(), KEYS + 1);
    assert_eq!(totals.uncredited[OTHER], 300 - KEYS as u64);
    assert_eq!(
        totals.uncredited_runs.keys().collect::<Vec<_>>(),
        totals.uncredited.keys().collect::<Vec<_>>()
    );
    assert_eq!(totals.suspect_keys.len(), 3);
    let mut keys = totals.uncredited.keys().chain(totals.suspect_keys.keys());
    assert!(keys.all(|key| serde_json::to_string(key).unwrap().len() <= KEY_BOUND + 2));
    assert!(status(&plan.root).unwrap().is_some());
}

/// A record of the list ends in a newline. A record without one, which a
/// sweep killed during its append leaves at the end of the list, is not
/// read and not counted, so the count `confirm` saves stays before it.
#[test]
fn an_unterminated_record_at_the_end_of_the_list_is_not_read() {
    let case = Case::new();
    let line = |run: u64| {
        json!({"campaign": "host", "profile": "upload", "run": run, "counts": {}, "seed": run, "build": "b0"}).to_string()
    };
    let path = case.root.join("suspects.jsonl");
    std::fs::write(&path, format!("{}\n{}", line(1), line(2))).unwrap();
    let (listed, lines) = suspects(&case.root, 0).unwrap();
    assert_eq!((listed.len(), listed[0].request.run, lines), (1, 1, 1));
    std::fs::write(&path, format!("{}\n{{\"campaign\": \"ho", line(1))).unwrap();
    let (listed, lines) = suspects(&case.root, 0).unwrap();
    assert_eq!((listed.len(), lines), (1, 1));
}

/// `suspects` reads the list a line at a time, so a list of any length is
/// read, and a line holds at most [`LINE_BOUND`] bytes. The list here is
/// 260 lines of 1 MiB each, written as holes, then one suspect: the
/// lines before `from` are passed over and the suspect is returned. A
/// line past the bound holds the read.
#[test]
fn suspects_are_read_from_a_list_of_any_length() {
    use std::io::{Seek, SeekFrom};
    let case = Case::new();
    let path = case.root.join("suspects.jsonl");
    let mut file = std::fs::File::create(&path).unwrap();
    for line in 1..=260 {
        file.seek(SeekFrom::Start((line << 20) - 1)).unwrap();
        file.write_all(b"\n").unwrap();
    }
    let suspect = json!({"campaign": "host", "profile": "upload", "run": 4, "counts": {}, "seed": 104, "build": "b0"});
    file.write_all(format!("{suspect}\n").as_bytes()).unwrap();
    let (listed, lines) = suspects(&case.root, 260).unwrap();
    assert_eq!((listed.len(), listed[0].request.run, lines), (1, 4, 261));
    file.seek(SeekFrom::Current(LINE_BOUND as i64)).unwrap();
    file.write_all(b"\n").unwrap();
    assert!(matches!(
        suspects(&case.root, 261),
        Err(Error::Held(reason)) if reason.contains("line 262")
    ));
}

/// The bytes of a `sweep.json` that names the build of `pins` and holds
/// five passing `upload` runs.
fn swept(pins: &Pins) -> Vec<u8> {
    let upload = json!({
        "next": 5, "runs": 5, "pass": 5, "uncredited": {}, "suspects": 0,
        "replays": 0, "turns": 0, "operations": 0, "decisions": 0,
        "faults_delivered": 0, "active_us": 0, "skipped_s": 0, "skipped_us": 0,
        "busy_us": 0,
    });
    let progress = json!({
        "build": pins.build.as_str(),
        "campaign": "host",
        "counts": {},
        "archive": "kept",
        "profiles": {"upload": upload},
        "elapsed_ms": 7,
    });
    serde_json::to_vec(&progress).unwrap()
}

/// A root takes the archive build of its first sweep. A sweep of the
/// root with an archive of another build is rejected with both builds
/// named and leaves `sweep.json` as it was, and a sweep with the same
/// build continues at the stored run numbers.
#[test]
fn a_swept_root_rejects_an_archive_of_another_build() {
    let case = Case::new();
    let plan = Plan {
        root: case.root.clone(),
        ..plan(&case, 1)
    };
    let (first, rebuilt) = (pins('b'), pins('c'));
    let file = case.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&first)).unwrap();
    let other = stored(&plan, &rebuilt.build);
    assert!(
        matches!(
            other.as_ref().err(),
            Some(Error::Rejected(reason))
                if reason.contains(first.build.as_str()) && reason.contains(rebuilt.build.as_str())
        ),
        "{:?}",
        other.as_ref().err()
    );
    assert_eq!(std::fs::read(&file).unwrap(), swept(&first));
    let same = stored(&plan, &first.build).unwrap().unwrap();
    assert_eq!(same.profiles["upload"].next, 5);
    assert_eq!(same.elapsed_ms, 7);
}

/// A root takes the campaign and the `--set` counts of its first sweep,
/// since a run number names another root under another campaign or other
/// counts. A sweep of the root with another campaign, with a count the
/// first did not set, without one it set or with another value is
/// rejected with both named and leaves `sweep.json` as it was. A sweep
/// with the same campaign and counts continues, whatever its profiles.
#[test]
fn a_swept_root_rejects_another_campaign_or_other_counts() {
    let case = Case::new();
    let (pins, listing) = (pins('b'), Listing::parse(LISTING).unwrap());
    let file = case.root.join("sweep.json");
    std::fs::create_dir(case.root.join("manifests")).unwrap();
    let swept = |campaign: &str, counts: &[(&str, u64)]| Plan {
        root: case.root.clone(),
        campaign: word(campaign),
        counts: counts
            .iter()
            .map(|&(key, count)| (word(key), count))
            .collect(),
        ..plan(&case, 1)
    };
    bound(
        &swept("host", &[("turns", 64)]),
        &pins,
        &listing,
        (&[], &[]),
        None,
    )
    .unwrap();
    let written = std::fs::read(&file).unwrap();
    for (other, named) in [
        (swept("other", &[("turns", 64)]), ["host", "other"]),
        (swept("host", &[]), ["64", "{}"]),
        (swept("host", &[("turns", 65)]), ["64", "65"]),
        (
            swept("host", &[("turns", 64), ("bytes", 1)]),
            ["64", "bytes"],
        ),
    ] {
        let refused = stored(&other, &pins.build);
        assert!(
            matches!(
                refused.as_ref().err(),
                Some(Error::Rejected(reason)) if named.iter().all(|name| reason.contains(name))
            ),
            "{:?}",
            refused.as_ref().err()
        );
        assert_eq!(std::fs::read(&file).unwrap(), written);
    }
    let mut same = swept("host", &[("turns", 64)]);
    same.profiles = vec![word("cluster-swarm")];
    assert!(matches!(stored(&same, &pins.build), Ok(Some(_))));
}

/// A new root is bound once the listing has accepted its profiles and
/// counts: a sweep with a count the listing does not hold is rejected
/// and leaves no `sweep.json`, so the corrected sweep takes the root.
#[test]
fn a_count_the_listing_refuses_binds_no_root() {
    let case = Case::new();
    let (pins, listing) = (pins('b'), Listing::parse(LISTING).unwrap());
    std::fs::create_dir(case.root.join("manifests")).unwrap();
    let mut plan = Plan {
        root: case.root.clone(),
        ..plan(&case, 1)
    };
    plan.counts.insert(word("turn"), 64);
    let refused = bound(&plan, &pins, &listing, (&[], &[]), None);
    assert!(
        matches!(refused.as_ref().err(), Some(Error::Rejected(_))),
        "{:?}",
        refused.as_ref().err()
    );
    assert!(!case.root.join("sweep.json").exists());
    plan.counts = [(word("turns"), 64)].into();
    assert!(matches!(stored(&plan, &pins.build), Ok(None)));
    bound(&plan, &pins, &listing, (&[], &[]), None).unwrap();
    assert!(matches!(stored(&plan, &pins.build), Ok(Some(_))));
}

/// A sweep judges a profile as a control when [`controls::named`]
/// declares its failure, and counts its runs as a control's when the
/// worker lists it with the control class. A declared control the worker
/// lists with another class is rejected before the root is bound, since
/// its passed run would be judged and raise no alarm. One the worker
/// lists as a control is bound and marked as one.
#[test]
fn a_control_the_worker_lists_with_another_class_binds_no_root() {
    let case = Case::new();
    std::fs::create_dir(case.root.join("manifests")).unwrap();
    let plan = Plan {
        root: case.root.clone(),
        ..plan(&case, 1)
    };
    let pins = pins('b');
    let upload = "profile: upload class=live support=implemented campaign=unqualified \
                  held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n";
    let listing = |class: &str| {
        let planted = upload.replace("upload class=live", &format!("planted class={class}"));
        assert!(LISTING.contains(upload));
        Listing::parse(&LISTING.replacen(upload, &format!("{upload}{planted}"), 1)).unwrap()
    };
    let planted = [word("planted")];
    let refused = bound(&plan, &pins, &listing("live"), (&planted, &[]), None);
    assert!(
        matches!(
            refused.as_ref().err(),
            Some(Error::Rejected(reason)) if reason.contains("control planted")
        ),
        "{:?}",
        refused.as_ref().err()
    );
    assert!(!case.root.join("sweep.json").exists());
    let (progress, _) = bound(&plan, &pins, &listing("control"), (&planted, &[]), None).unwrap();
    assert!(progress.profiles["planted"].control && !progress.profiles["upload"].control);
}

/// A root without `sweep.json` holds one that names the archive's build
/// and the sweep's campaign and counts once `bound` returns, which is
/// before the sweep starts a worker, so a sweep that ends before its
/// first checkpoint still leaves the root bound to them. Each profile's
/// manifest is written under the root.
#[test]
fn a_new_root_names_its_build_before_the_first_worker_starts() {
    let case = Case::new();
    let plan = Plan {
        root: case.root.clone(),
        ..plan(&case, 1)
    };
    let (first, rebuilt) = (pins('b'), pins('c'));
    std::fs::create_dir(case.root.join("manifests")).unwrap();
    let listing = Listing::parse(LISTING).unwrap();
    let (fresh, manifests) = bound(&plan, &first, &listing, (&[], &[]), None).unwrap();
    assert_eq!(fresh.profiles["upload"].next, 0);
    assert!(manifests["upload"].exists());
    let stored_bytes: Value =
        serde_json::from_slice(&std::fs::read(case.root.join("sweep.json")).unwrap()).unwrap();
    assert_eq!(stored_bytes["build"], first.build.as_str());
    assert_eq!(stored_bytes["campaign"], "host");
    assert_eq!(stored_bytes["counts"], json!({}));
    let other = stored(&plan, &rebuilt.build);
    assert!(
        matches!(other.as_ref().err(), Some(Error::Rejected(_))),
        "{:?}",
        other.as_ref().err()
    );
}

/// A sweep whose archive fails its closing verification marks the root,
/// since its runs may be of other bytes than the build's. A later sweep,
/// `sweep-status` and `confirm` each refuse the root with that failure,
/// and the file is left as the mark wrote it.
#[test]
fn a_root_whose_sweep_ended_with_a_changed_archive_is_refused() {
    let case = Case::new();
    let plan = Plan {
        root: case.root.clone(),
        ..plan(&case, 1)
    };
    let pins = pins('b');
    let frozen = frozen(&plan, "");
    {
        let mut progress = frozen.progress.lock().unwrap();
        let totals = progress.profiles.entry("upload".into()).or_default();
        (totals.runs, totals.pass) = (5, 5);
    }
    frozen.close(None).unwrap();
    assert!(matches!(stored(&plan, &pins.build), Ok(Some(_))));
    assert!(matches!(status(&plan.root), Ok(Some(_))));
    assert!(matches!(build(&plan.root), Ok(Some(_))));
    frozen
        .close(Some("the archive after the sweep: a file changed"))
        .unwrap();
    let written = std::fs::read(plan.root.join("sweep.json")).unwrap();
    let refusals = [
        stored(&plan, &pins.build).err(),
        status(&plan.root).err(),
        build(&plan.root).err(),
    ];
    for refused in refusals {
        assert!(
            matches!(
                &refused,
                Some(Error::Rejected(reason))
                    if reason.contains("a file changed") && reason.contains("new root")
            ),
            "{refused:?}"
        );
    }
    assert_eq!(
        std::fs::read(plan.root.join("sweep.json")).unwrap(),
        written
    );
}

/// A checkpoint its readers would refuse is not written. The totals here
/// hold 400 profiles with every suspect key full, past the readers'
/// bound: the write fails, and the root keeps the checkpoint before it,
/// which `status` still reads.
#[test]
fn a_checkpoint_past_its_readers_bound_is_not_written() {
    let case = Case::new();
    let plan = Plan {
        root: case.root.clone(),
        ..plan(&case, 1)
    };
    let frozen = frozen(&plan, "");
    frozen.flush().unwrap();
    let kept = std::fs::read(plan.root.join("sweep.json")).unwrap();
    {
        let mut progress = frozen.progress.lock().unwrap();
        for profile in 0..400 {
            let totals = progress
                .profiles
                .entry(format!("profile-{profile}"))
                .or_default();
            totals.history = Some(true);
            for key in 0..=KEYS {
                totals.suspect_keys.insert(format!("{key:0250}"), 1);
            }
        }
    }
    let refused = frozen.flush();
    assert!(
        matches!(&refused, Err(Error::Held(reason)) if reason.contains("sweep.json") && reason.contains("automatic histories")),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(std::fs::read(plan.root.join("sweep.json")).unwrap(), kept);
    assert!(matches!(status(&plan.root), Ok(Some(_))));
}

/// A failed closing verification marks the root also when the totals
/// would pass the checkpoint's bound: the mark is then written without
/// the totals, which no reader takes from a marked root, and every
/// reader refuses the root.
#[test]
fn a_changed_archive_marks_a_root_whose_totals_pass_the_bound() {
    let case = Case::new();
    let plan = Plan {
        root: case.root.clone(),
        ..plan(&case, 1)
    };
    let pins = pins('b');
    let frozen = frozen(&plan, "");
    frozen.flush().unwrap();
    {
        let mut progress = frozen.progress.lock().unwrap();
        for profile in 0..400 {
            let totals = progress
                .profiles
                .entry(format!("profile-{profile}"))
                .or_default();
            for key in 0..=KEYS {
                totals.suspect_keys.insert(format!("{key:0250}"), 1);
            }
        }
    }
    assert!(frozen.flush().is_err());
    frozen
        .close(Some("the archive after the sweep: a file changed"))
        .unwrap();
    for refused in [
        stored(&plan, &pins.build).err(),
        status(&plan.root).err(),
        build(&plan.root).err(),
    ] {
        assert!(
            matches!(&refused, Some(Error::Rejected(reason)) if reason.contains("a file changed")),
            "{refused:?}"
        );
    }
}

/// `status` is absent for a root no sweep wrote, and sums the totals
/// of every profile of one that a sweep did. It sums the control
/// profiles' runs apart, and carries `alarm` once a control run was
/// missed.
#[test]
fn status_sums_the_profiles_of_a_swept_root() {
    let case = Case::new();
    assert!(status(&case.root).unwrap().is_none());
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: [(word("turns"), 64)].into(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 2_000,
        rules: Vec::new(),
        batches: 0,
    };
    for (profile, runs) in [("upload", 6), ("cluster-swarm", 4)] {
        let totals = progress.profiles.entry(profile.to_owned()).or_default();
        totals.runs = runs;
        totals.pass = runs - 1;
        totals.suspects = 1;
        totals.operations = 10 * runs;
    }
    let write = |progress: &Progress| {
        crate::store::replace_host(
            &case.root.join("sweep.json"),
            &serde_json::to_vec(progress).unwrap(),
        )
        .unwrap();
    };
    write(&progress);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(swept["runs"], 10);
    assert_eq!(swept["pass"], 8);
    assert_eq!(swept["suspects"], 2);
    assert_eq!(swept["operations"], 100);
    assert_eq!(
        swept["reach"]["cluster-swarm"],
        json!({"covered": 0, "refused_actions": 1.0})
    );
    assert_eq!(swept["runs_per_s"], 5.0);
    assert_eq!(swept["campaign"], "host");
    assert_eq!(swept["counts"], json!({"turns": 64}));
    assert_eq!(
        swept["controls"],
        json!({"profiles": 0, "runs": 0, "caught": 0, "no_effect": 0, "missed": 0, "other": 0})
    );
    assert_eq!(
        swept["histories"],
        json!({
            "profiles": 0, "ran": 0, "runs": 0, "pass": 0, "caught": 0, "missed": 0,
            "uncredited": 0, "suspects": 0,
        })
    );
    assert!(swept.get("alarm").is_none());
    let control = progress.profiles.entry("planted".to_owned()).or_default();
    control.control = true;
    control.runs = 6;
    control.caught = 3;
    control
        .uncredited
        .insert("inconclusive: limit turns".to_owned(), 1);
    control
        .uncredited
        .insert(unsuccessful_key(controls::NO_EFFECT), 2);
    write(&progress);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(swept["runs"], 16);
    assert_eq!(
        swept["controls"],
        json!({"profiles": 1, "runs": 6, "caught": 3, "no_effect": 2, "missed": 0, "other": 1})
    );
    assert!(swept.get("alarm").is_none());
    progress.profiles.get_mut("planted").unwrap().missed = 1;
    write(&progress);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(swept["controls"]["missed"], 1);
    assert_eq!(swept["alarm"], "1 control runs were missed");
}

/// The status counts the root's histories apart from its controls: how
/// many the root holds and how many of them ran, their runs, the passes
/// of those that expect one, the runs of the others that ended in their
/// declared failure, the uncredited runs and the suspects. A history's
/// missed runs raise the alarm with no control missed, and the alarm
/// counts the missed runs of both.
#[test]
fn the_status_counts_histories_and_alarms_on_one_that_was_missed() {
    let case = Case::new();
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 2_000,
        rules: Vec::new(),
        batches: 0,
    };
    for (history, runs, pass, caught) in [
        ("h1-get", 5, 4, 0),
        ("h1-get-stale", 7, 0, 6),
        ("h1-get-unheld", 0, 0, 0),
    ] {
        let totals = progress.profiles.entry(history.to_owned()).or_default();
        totals.history = Some(true);
        (totals.runs, totals.pass, totals.caught) = (runs, pass, caught);
    }
    let passing = progress.profiles.get_mut("h1-get").unwrap();
    passing.suspects = 1;
    let failing = progress.profiles.get_mut("h1-get-stale").unwrap();
    failing
        .uncredited
        .insert("unsuccessful: old read held".to_owned(), 1);
    failing.caught_rules.insert("a stale hit".into(), 6);
    progress.rules = vec![("history".into(), "a stale hit".into())];
    let planted = progress.profiles.entry("planted".to_owned()).or_default();
    planted.control = true;
    planted.runs = 2;
    let write = |progress: &Progress| {
        crate::store::replace_host(
            &case.root.join("sweep.json"),
            &serde_json::to_vec(progress).unwrap(),
        )
        .unwrap();
    };
    write(&progress);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(
        swept["histories"],
        json!({
            "profiles": 3, "ran": 2, "runs": 12, "pass": 4, "caught": 6, "missed": 0,
            "uncredited": 1, "suspects": 1,
        })
    );
    assert_eq!(swept["controls"]["profiles"], 1);
    assert_eq!(
        swept["rules"]["caught"]["a stale hit"],
        json!({
            "runs": 6, "controls": ["h1-get-stale"]
        })
    );
    assert_eq!(
        swept["rules"]["scopes"]["history"],
        json!({
            "rules": 1, "caught": 1, "uncaught": []
        })
    );
    assert!(swept.get("alarm").is_none());
    let failing = progress.profiles.get_mut("h1-get-stale").unwrap();
    (failing.missed, failing.suspects) = (3, 3);
    failing.runs += 3;
    write(&progress);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(swept["histories"]["missed"], 3);
    assert_eq!(swept["histories"]["uncredited"], 1);
    assert_eq!(swept["histories"]["suspects"], 4);
    assert_eq!(swept["controls"]["missed"], 0);
    assert_eq!(swept["alarm"], "3 control runs were missed");
    progress.profiles.get_mut("planted").unwrap().missed = 2;
    write(&progress);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(swept["controls"]["missed"], 2);
    assert_eq!(swept["alarm"], "5 control runs were missed");
}

/// The status holds each sum at `u64::MAX` where its counters pass it:
/// each of the controls' sums, the uncredited runs of one control among
/// them, the histories' runs and uncredited runs, the root's uncredited
/// runs, the missed runs the alarm counts and a rule's caught runs. A sum that
/// wrapped to zero would drop the alarm.
#[test]
fn overflowing_history_totals_keep_the_alarm_and_saturate_status() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut runner = frozen(&plan, &passing(":"));
    let progress = runner.progress.get_mut().unwrap();
    for name in ["h-a", "h-b"] {
        let totals = progress.profiles.entry(name.into()).or_default();
        totals.history = Some(true);
        totals.runs = u64::MAX;
        totals.missed = 1;
        totals.uncredited = [("a".into(), u64::MAX), ("b".into(), 1)].into();
        totals.caught_rules.insert("a shared rule".into(), u64::MAX);
    }
    for name in ["planted", "corrupted"] {
        let control = progress.profiles.entry(name.into()).or_default();
        control.control = true;
        (control.runs, control.caught, control.missed) = (u64::MAX, u64::MAX, u64::MAX);
        control.uncredited = [
            (unsuccessful_key(controls::NO_EFFECT), u64::MAX),
            ("inconclusive: limit turns".into(), u64::MAX),
            ("inconclusive: recorder cap".into(), 1),
        ]
        .into();
    }
    runner.flush().unwrap();
    let status = status(&plan.root).unwrap().unwrap();
    assert_eq!(
        status["controls"],
        json!({
            "profiles": 2, "runs": u64::MAX, "caught": u64::MAX, "no_effect": u64::MAX,
            "missed": u64::MAX, "other": u64::MAX,
        })
    );
    assert_eq!(status["histories"]["runs"], u64::MAX);
    assert_eq!(status["histories"]["uncredited"], u64::MAX);
    assert_eq!(status["uncredited"], u64::MAX);
    assert_eq!(status["histories"]["missed"], 2);
    assert_eq!(status["controls"]["missed"], u64::MAX);
    assert_eq!(
        status["alarm"],
        format!("{} control runs were missed", u64::MAX)
    );
    assert_eq!(status["rules"]["caught"]["a shared rule"]["runs"], u64::MAX);
}

/// A text the catalog lists under `history` and then `oracle` counts as
/// caught under `history` and stays uncaught under `oracle`. A text only
/// the oracle lists counts under `oracle`.
#[test]
fn shared_history_rules_leave_only_oracle_verdicts_attributed_to_the_oracle() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut runner = frozen(&plan, &passing(":"));
    let progress = runner.progress.get_mut().unwrap();
    let shared = "a publication before its writes completed";
    let oracle = "a recovered candidate was found without admission";
    progress.rules = vec![
        ("history".into(), shared.into()),
        ("oracle".into(), shared.into()),
        ("oracle".into(), oracle.into()),
    ];
    for (name, text) in [
        ("key-operation-control", shared),
        ("restart-control", oracle),
    ] {
        let totals = progress.profiles.entry(name.into()).or_default();
        totals.history = Some(true);
        totals.runs = 1;
        totals.caught = 1;
        totals.caught_rules.insert(text.into(), 1);
    }
    runner.flush().unwrap();
    let status = status(&plan.root).unwrap().unwrap();
    assert_eq!(
        status["rules"]["scopes"]["history"],
        json!({
            "rules": 1, "caught": 1, "uncaught": []
        })
    );
    assert_eq!(
        status["rules"]["scopes"]["oracle"],
        json!({
            "rules": 2, "caught": 1, "uncaught": [shared]
        })
    );
    assert_eq!(
        status["rules"]["caught"][oracle]["controls"],
        json!(["restart-control"])
    );
}

/// The status lists under `no_pass` each profile whose class is not
/// control, with 64 runs or more and none counted as a pass or as caught:
/// a live profile whose runs are all uncredited, at 64 runs and past it,
/// and a history whose runs are all suspects. A profile with 63 runs,
/// counted and a 64th begun, with one pass or with one caught run, and a
/// control, are not listed,
/// and the key is absent when none is. A later run that passes takes its
/// profile off the list. Totals that carry `no_pass` or `alarm` give the
/// sweep its exit 1 verdict.
#[test]
fn the_status_lists_each_profile_none_of_whose_runs_passed() {
    const RULE: &str = "inconclusive: limit no_progress";
    let case = Case::new();
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 2_000,
        rules: Vec::new(),
        batches: 0,
    };
    let listed = |progress: &Progress| {
        crate::store::replace_host(
            &case.root.join("sweep.json"),
            &serde_json::to_vec(progress).unwrap(),
        )
        .unwrap();
        status(&case.root).unwrap().unwrap()
    };
    for (profile, runs, pass, caught, control, history) in [
        ("short", 63, 0, 0, false, false),
        ("passing", 400, 1, 0, false, false),
        ("planted", 400, 0, 0, true, false),
        ("h1-get-stale", 400, 0, 1, false, true),
    ] {
        let totals = progress.profiles.entry(profile.to_owned()).or_default();
        (totals.runs, totals.next) = (runs, runs);
        (totals.pass, totals.caught) = (pass, caught);
        (totals.control, totals.history) = (control, Some(history));
        totals
            .uncredited
            .insert(RULE.to_owned(), runs - pass - caught);
    }
    // A run that has begun and is not yet counted leaves its profile
    // below the threshold.
    progress.profiles.get_mut("short").unwrap().next = 64;
    let swept = listed(&progress);
    assert!(swept.get("no_pass").is_none());
    assert!(!carries_verdict(&swept));

    let history = progress.profiles.entry("h1-get".to_owned()).or_default();
    (history.runs, history.next, history.suspects) = (64, 64, 64);
    history.history = Some(true);
    for runs in [64, 65, 400] {
        let upload = progress.profiles.entry("upload".to_owned()).or_default();
        (upload.runs, upload.next) = (runs, runs);
        upload.uncredited.insert(RULE.to_owned(), runs);
        let swept = listed(&progress);
        assert_eq!(swept["profiles"]["upload"]["uncredited"][RULE], runs);
        assert_eq!(swept["no_pass"], json!(["h1-get", "upload"]), "{runs}");
        assert!(swept.get("alarm").is_none());
        assert!(carries_verdict(&swept));
    }

    for (profile, left) in [("upload", Some(json!(["h1-get"]))), ("h1-get", None)] {
        let totals = progress.profiles.get_mut(profile).unwrap();
        (totals.runs, totals.next, totals.pass) = (totals.runs + 1, totals.next + 1, 1);
        assert_eq!(listed(&progress).get("no_pass"), left.as_ref());
    }
    progress.profiles.get_mut("planted").unwrap().missed = 1;
    let swept = listed(&progress);
    assert!(swept.get("no_pass").is_none());
    assert!(swept.get("alarm").is_some() && carries_verdict(&swept));
}

const KNOWN_RULE: &str = "a stale hit";

const KNOWN_ROW: known::Row = known::Row {
    issue: 225,
    class: known::Bug::Correctness,
    pin: "h1-get-stale",
    profiles: &["upload"],
    obligation: 2,
    rule: KNOWN_RULE,
};

/// The `violation` suspect key of a violation of obligation 2 under
/// `rule`, of identity variant `variant` at `site`.
fn violation_key(variant: u8, site: u8, rule: &str) -> String {
    let digest = Digest::of(rule.as_bytes());
    format!("violation: 02{variant:02x}0200{site:02x}0000{digest}0000000000")
}

/// The fixture varies the rule and profile independently to distinguish
/// rule mismatches from profile mismatches. When a profile's key counts
/// sum to more than `cap`, `suspects` records `cap` while `suspect_keys`
/// retains the full counts. A missed control run and 64 runs with no pass
/// give the root a verdict.
fn known_checkpoint(case: &Case, cap: u64) {
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 2_000,
        rules: Vec::new(),
        batches: 0,
    };
    let keys = [
        ("upload", violation_key(1, 1, KNOWN_RULE), 5),
        ("upload", violation_key(2, 2, KNOWN_RULE), 1),
        ("upload", violation_key(1, 1, "a stale read"), 3),
        ("upload", OTHER.to_owned(), 1),
        ("upload", "panic: src/net/owner.rs:1:1".to_owned(), 2),
        ("cluster-broad", violation_key(1, 1, KNOWN_RULE), 4),
    ];
    for (profile, key, count) in keys {
        let totals = progress.profiles.entry(profile.to_owned()).or_default();
        totals.suspect_keys.insert(key, count);
        totals.suspects = (totals.suspects + count).min(cap);
    }
    let upload = progress.profiles.get_mut("upload").unwrap();
    (upload.runs, upload.next, upload.missed) = (64, 64, 1);
    crate::store::replace_host(
        &case.root.join("sweep.json"),
        &serde_json::to_vec(&progress).unwrap(),
    )
    .unwrap();
    let line = json!({"profile": "upload", "key": violation_key(1, 1, KNOWN_RULE)});
    std::fs::write(case.root.join("suspects.jsonl"), format!("{line}\n")).unwrap();
}

fn known_status(case: &Case, table: &[known::Row]) -> Value {
    let before = crate::store::fixture::snapshot(&case.root);
    let swept = status_with(&case.root, table).unwrap().unwrap();
    assert_eq!(crate::store::fixture::snapshot(&case.root), before);
    swept
}

/// Each `known` entry groups the keys its row explains by profile and
/// sums their counts under `suspects`, and `new_suspects` is the root's
/// other suspects. A row whose rule no key carries lists 0 suspects and
/// each of its profiles with an empty array, as does a later row that
/// shares the earlier row's key. A row that names its profile twice
/// lists it once. A row with an empty profile list shows 0 suspects and
/// an empty `keys` object. Status includes `known` for a nonempty table and counts
/// every suspect as new for an empty table. A row's sum and the sum over
/// rows saturate at `u64::MAX`, so `new_suspects` is then 0.
#[test]
fn the_status_lists_the_suspects_each_known_row_explains() {
    let case = Case::new();
    known_checkpoint(&case, u64::MAX);
    let explained = |row: &known::Row, suspects: u64, keys: Value| {
        json!({
            "issue": row.issue,
            "class": "correctness bug",
            "pin": row.pin,
            "rule": row.rule,
            "suspects": suspects,
            "keys": keys,
        })
    };
    let (key, oracle) = (
        violation_key(1, 1, KNOWN_RULE),
        violation_key(2, 2, KNOWN_RULE),
    );
    let single = known_status(&case, &[KNOWN_ROW]);
    assert_eq!(single["suspects"], 16);
    assert_eq!(
        single["known"],
        json!([explained(&KNOWN_ROW, 6, json!({"upload": [key, oracle]}))])
    );
    assert_eq!(single["new_suspects"], 10);
    let twice = known::Row {
        profiles: &["upload", "upload"],
        ..KNOWN_ROW
    };
    assert_eq!(known_status(&case, &[twice]), single);

    let both = known::Row {
        profiles: &["upload", "cluster-broad"],
        ..KNOWN_ROW
    };
    let swept = known_status(&case, &[both]);
    assert_eq!(
        swept["known"],
        json!([explained(
            &both,
            10,
            json!({"cluster-broad": [key], "upload": [key, oracle]})
        )])
    );
    assert_eq!(swept["new_suspects"], 6);

    let reworded = known::Row {
        rule: "a stale hit of a removed key",
        ..both
    };
    let swept = known_status(&case, &[reworded]);
    assert_eq!(
        swept["known"],
        json!([explained(
            &reworded,
            0,
            json!({"cluster-broad": [], "upload": []})
        )])
    );
    assert_eq!(swept["new_suspects"], 16);

    let pinned = known::Row {
        profiles: &[],
        ..KNOWN_ROW
    };
    let swept = known_status(&case, &[pinned]);
    assert_eq!(swept["known"], json!([explained(&pinned, 0, json!({}))]));
    assert_eq!(swept["new_suspects"], 16);

    let second = known::Row {
        issue: 226,
        ..KNOWN_ROW
    };
    let swept = known_status(&case, &[KNOWN_ROW, second]);
    assert_eq!(
        swept["known"],
        json!([
            explained(&KNOWN_ROW, 6, json!({"upload": [key, oracle]})),
            explained(&second, 0, json!({"upload": []})),
        ])
    );
    assert_eq!(swept["new_suspects"], 10);

    let stale_read = known::Row {
        issue: 227,
        rule: "a stale read",
        ..KNOWN_ROW
    };
    let swept = known_status(&case, &[KNOWN_ROW, stale_read]);
    assert_eq!(
        swept["known"],
        json!([
            explained(&KNOWN_ROW, 6, json!({"upload": [key, oracle]})),
            explained(
                &stale_read,
                3,
                json!({"upload": [violation_key(1, 1, "a stale read")]})
            ),
        ])
    );
    assert_eq!(swept["new_suspects"], 7);

    let swept = known_status(&case, &[]);
    assert!(swept.get("known").is_none());
    assert_eq!(swept["new_suspects"], swept["suspects"]);
    assert_eq!(swept["new_suspects"], 16);

    let file = case.root.join("sweep.json");
    let mut checkpoint: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    checkpoint["profiles"]["upload"]["suspect_keys"][&key] = u64::MAX.into();
    crate::store::replace_host(&file, &serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    let cluster = known::Row {
        issue: 226,
        profiles: &["cluster-broad"],
        ..KNOWN_ROW
    };
    let swept = known_status(&case, &[KNOWN_ROW, cluster]);
    assert_eq!(swept["suspects"], 16);
    assert_eq!(
        swept["known"],
        json!([
            explained(&KNOWN_ROW, u64::MAX, json!({"upload": [key, oracle]})),
            explained(&cluster, 4, json!({"cluster-broad": [key]})),
        ])
    );
    assert_eq!(swept["new_suspects"], 0);
}

/// Known-row attribution affects only `known` and `new_suspects` in the
/// status output. Status reports `new_suspects` as 0 when the counts
/// attributed to `known` rows exceed the root's `suspects`. A checkpoint
/// whose profiles hold no `suspect_keys`, as a supervisor that predates
/// the keys wrote, counts every suspect as new.
#[test]
fn a_known_row_changes_no_count_and_no_verdict() {
    let both = known::Row {
        profiles: &["upload", "cluster-broad"],
        ..KNOWN_ROW
    };
    for (cap, keyed, verdict, suspects, new) in [
        (u64::MAX, true, true, 16, 6),
        (4, true, true, 8, 0),
        (u64::MAX, false, true, 16, 16),
        (u64::MAX, true, false, 16, 6),
    ] {
        let case = Case::new();
        known_checkpoint(&case, cap);
        let file = case.root.join("sweep.json");
        let mut checkpoint: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        if !keyed {
            for totals in checkpoint["profiles"].as_object_mut().unwrap().values_mut() {
                totals.as_object_mut().unwrap().remove("suspect_keys");
            }
        }
        if !verdict {
            let upload = &mut checkpoint["profiles"]["upload"];
            (upload["runs"], upload["next"], upload["missed"]) = (1.into(), 1.into(), 0.into());
        }
        crate::store::replace_host(&file, &serde_json::to_vec(&checkpoint).unwrap()).unwrap();
        let mut labelled = known_status(&case, &[both]);
        if !keyed {
            assert_eq!(
                labelled["known"][0]["keys"],
                json!({"cluster-broad": [], "upload": []})
            );
            assert_eq!(labelled["known"][0]["suspects"], 0);
        }
        let mut plain = known_status(&case, &[]);
        assert_eq!(carries_verdict(&labelled), verdict);
        assert_eq!(carries_verdict(&plain), verdict);
        assert_eq!(labelled["suspects"], suspects);
        assert_eq!(labelled["new_suspects"], new);
        assert_eq!(plain["new_suspects"], suspects);
        for status in [&mut labelled, &mut plain] {
            let fields = status.as_object_mut().unwrap();
            fields.remove("known");
            fields.remove("new_suspects");
        }
        assert_eq!(labelled, plain);
    }
}

#[test]
fn each_table_row_requires_or_excuses_every_coverage_counter() {
    let listing = Listing::parse(CLUSTERS).unwrap();
    let mut profiles = std::collections::BTreeSet::new();
    let mut excuses = Vec::new();
    for &(profile, covered, events, excused) in required::REQUIRED {
        assert!(profiles.insert(profile));
        assert!(matches!(
            profile,
            "cluster-swarm" | "cluster-broad" | "cluster-pressure"
        ));
        assert!(controls::HEALTHY.contains(&profile));
        assert!(controls::named(profile).is_none());
        assert_eq!(listing.profile(profile).unwrap().class, Class::Live);
        assert!(listing.cluster(profile).is_some(), "{profile}");
        assert!(covered >= 2000 && !events.is_empty(), "{profile}");
        for &(name, runs) in events {
            assert!(
                (covered.div_ceil(8)..=covered).contains(&runs),
                "{profile} {name}"
            );
        }
        for &(name, reason) in excused {
            assert!(!reason.trim().is_empty(), "{profile} {name}");
        }
        let mut named: Vec<_> = events
            .iter()
            .map(|&(name, _)| name)
            .chain(excused.iter().map(|&(name, _)| name))
            .collect();
        named.sort_unstable();
        let mut counters = COVERAGE.to_vec();
        counters.sort_unstable();
        assert_eq!(named, counters, "{profile}");
        excuses.extend(excused.iter().map(|&(name, _)| (profile, name)));
    }
    assert_eq!(profiles.len(), 3);
    excuses.sort_unstable();
    assert_eq!(
        excuses,
        [
            ("cluster-pressure", "cancelled"),
            ("cluster-pressure", "invalidated")
        ]
    );
}

/// Status and resume hold the same unmarked checkpoint if
/// `event.runs <= covered <= pass <= profile_runs` or
/// `event.runs <= event.total <= event.runs * u32::MAX` fails.
#[test]
fn impossible_reach_counts_hold_status_and_resume() {
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.root = case.root.clone();
    let pins = pins('b');
    let file = plan.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&pins)).unwrap();
    let mut progress = super::read(&plan.root).unwrap().unwrap();
    plan.campaign = progress.campaign.clone();
    plan.counts = progress.counts.clone();
    let large = u64::from(u32::MAX);
    let long = "z".repeat(243);
    for (profile, profile_runs, pass, covered, runs, total) in [
        ("cluster-pressure", 63, 64, 0, 0, 0),
        ("cluster-pressure", 65, 64, 65, 0, 0),
        ("cluster-pressure", 65, 64, 64, 65, 65),
        ("cluster-pressure", 65, 64, 64, 2, 1),
        ("cluster-pressure", 65, 64, 64, 0, 1),
        ("cluster-pressure", 65, 64, 64, 1, large + 1),
        ("a\nb\x1bc", 63, 64, 0, 0, 0),
        (long.as_str(), 63, 64, 0, 0, 0),
    ] {
        progress.profiles.insert(
            profile.into(),
            Totals {
                pass,
                runs: profile_runs,
                covered,
                reached: [(Cow::Borrowed("misses"), EventReach { runs, total })].into(),
                ..Totals::default()
            },
        );
        crate::store::replace_host(&file, &serde_json::to_vec(&progress).unwrap()).unwrap();
        let name = if profile == long {
            "a profile name of 243 bytes".into()
        } else {
            format!("{profile:?}")
        };
        let expected = format!("sweep.json: inconsistent reach counts for {name}");
        for refusal in [status(&plan.root).err(), stored(&plan, &pins.build).err()] {
            assert!(
                matches!(refusal, Some(Error::Held(reason)) if reason == expected),
                "{profile_runs} {pass} {covered} {runs} {total}"
            );
        }
        progress.profiles.remove(profile);
    }
    for (runs, total) in [(1, large), (large + 2, u64::MAX), (large + 3, u64::MAX)] {
        progress.profiles.insert(
            "cluster-pressure".into(),
            Totals {
                runs,
                pass: runs,
                covered: runs,
                reached: [(Cow::Borrowed("misses"), EventReach { runs, total })].into(),
                ..Default::default()
            },
        );
        crate::store::replace_host(&file, &serde_json::to_vec(&progress).unwrap()).unwrap();
        assert!(matches!(status(&plan.root), Ok(Some(_))), "{runs} {total}");
        assert!(
            matches!(stored(&plan, &pins.build), Ok(Some(_))),
            "{runs} {total}"
        );
    }
    progress
        .profiles
        .get_mut("cluster-pressure")
        .unwrap()
        .control = true;
    crate::store::replace_host(&file, &serde_json::to_vec(&progress).unwrap()).unwrap();
    for refusal in [status(&plan.root).err(), stored(&plan, &pins.build).err()] {
        assert!(
            matches!(refusal, Some(Error::Held(reason)) if reason.contains("marked as a control"))
        );
    }
}

/// A required counter with zero reaching passes lists under `unreached`
/// from [`required::REQUIRED_PASSES`] covered passes on: at the floor and
/// one past it, at the row's measured count and past 32 bits, and beside
/// `alarm` and `no_pass`. One covered pass under the floor, one reaching
/// pass, a control, and a profile whose name only overlaps a row's name
/// each list nothing.
#[test]
fn the_status_lists_each_required_event_no_covered_pass_reached() {
    let case = Case::new();
    let file = case.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&pins('b'))).unwrap();
    let mut progress = super::read(&case.root).unwrap().unwrap();
    let listed = |progress: &Progress| {
        crate::store::replace_host(&file, &serde_json::to_vec(progress).unwrap()).unwrap();
        status(&case.root).unwrap().unwrap()
    };
    for &(profile, measured, events, excused) in required::REQUIRED {
        let name = profile.to_owned();
        let mut totals = Totals {
            pass: 400,
            runs: 400,
            ..Default::default()
        };
        progress.profiles.insert(name.clone(), totals.clone());
        let stored = listed(&progress);
        assert_eq!(stored["reach"][profile], json!({"covered": 0}));
        assert!(stored.get("unreached").is_none());
        totals.covered = 64;
        let names: Vec<_> = events.iter().map(|&(event, _)| event).collect();
        progress.profiles.insert(name.clone(), totals.clone());
        assert_eq!(listed(&progress)["unreached"], json!({profile: names}));
        totals.control = true;
        assert!(required::unreached(&totals, events).is_empty());
        progress.profiles.insert("planted".into(), totals.clone());
        assert!(listed(&progress)["unreached"].get("planted").is_none());
        totals.control = false;
        for outside in [
            "cluster".to_owned(),
            "cluster-long".to_owned(),
            format!("{profile}-long"),
        ] {
            progress.profiles.insert(outside.clone(), totals.clone());
            assert_eq!(
                listed(&progress)["reach"][&outside],
                json!({"covered":64,"zero":COVERAGE})
            );
        }
        for &(event, _) in events {
            totals.reached = reached_once(events);
            let singleton = json!({profile: [event]});
            for (covered, runs, expected) in [
                (63, 0, None),
                (64, 0, Some(&singleton)),
                (65, 0, Some(&singleton)),
                (65, 1, None),
                (measured, 0, Some(&singleton)),
                (1 << 32, 0, Some(&singleton)),
            ] {
                totals.covered = covered;
                totals.pass = covered.max(400);
                totals.runs = totals.pass;
                totals
                    .reached
                    .insert(Cow::Borrowed(event), EventReach { runs, total: runs });
                progress.profiles.insert(name.clone(), totals.clone());
                let status = listed(&progress);
                assert_eq!(
                    carries_verdict(&status),
                    expected.is_some(),
                    "{profile} {event} {covered}"
                );
                assert_eq!(
                    status.get("unreached"),
                    expected,
                    "{profile} {event} {covered}"
                );
                let zero: Vec<_> = COVERAGE
                    .into_iter()
                    .filter(|&counter| {
                        (counter == event && runs == 0)
                            || excused.iter().any(|&(name, _)| name == counter)
                    })
                    .collect();
                assert_eq!(
                    status["reach"][profile]["zero"],
                    json!(zero),
                    "{profile} {event} {covered}"
                );
            }
        }
        progress.profiles.remove(profile);
    }
    let mut all_missing = BTreeMap::new();
    for &(profile, _, events, _) in required::REQUIRED {
        progress.profiles.insert(
            profile.into(),
            Totals {
                covered: 64,
                runs: 64,
                pass: 64,
                ..Default::default()
            },
        );
        all_missing.insert(
            profile,
            events.iter().map(|&(event, _)| event).collect::<Vec<_>>(),
        );
    }
    assert_eq!(listed(&progress)["unreached"], json!(all_missing));
    progress.profiles.insert(
        "idle".into(),
        Totals {
            runs: NO_PASS_RUNS,
            ..Default::default()
        },
    );
    progress.profiles.insert(
        "planted".into(),
        Totals {
            control: true,
            runs: 1,
            missed: 1,
            ..Default::default()
        },
    );
    let status = listed(&progress);
    assert_eq!(status["no_pass"], json!(["idle"]));
    assert!(status.get("alarm").is_some());
    assert_eq!(status["unreached"], json!(all_missing));
}

/// Exactly one covered pass reaches each required event in `events`.
fn reached_once(events: &[(&'static str, u64)]) -> BTreeMap<Cow<'static, str>, EventReach> {
    events
        .iter()
        .map(|&(event, _)| (Cow::Borrowed(event), EventReach { runs: 1, total: 1 }))
        .collect()
}

/// An excused counter stays out of `unreached` and gives no verdict at the
/// floor, at the row's measured covered count and past 32 bits, whether no
/// pass drew it, a pass drew it at zero, or a pass reached it. `zero` names
/// it while it has zero reaching passes. The status has the keys of the
/// same totals under a profile outside the table.
#[test]
fn an_excused_counter_never_lists_under_unreached() {
    let case = Case::new();
    let file = case.root.join("sweep.json");
    crate::store::replace_host(&file, &swept(&pins('b'))).unwrap();
    let mut progress = super::read(&case.root).unwrap().unwrap();
    let mut listed = |profile: &str, totals: &Totals| {
        progress.profiles.insert(profile.into(), totals.clone());
        crate::store::replace_host(&file, &serde_json::to_vec(&progress).unwrap()).unwrap();
        progress.profiles.remove(profile);
        status(&case.root).unwrap().unwrap()
    };
    let keys = |status: &Value| {
        status
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    for &(profile, measured, events, excused) in required::REQUIRED {
        let with = |runs: Option<u64>| {
            let mut reached = reached_once(events);
            if let Some(runs) = runs {
                let reach = |&(event, _)| (Cow::Borrowed(event), EventReach { runs, total: runs });
                reached.extend(excused.iter().map(reach));
            }
            reached
        };
        for (form, runs) in [("absent", None), ("drawn", Some(0)), ("reached", Some(1))] {
            let at_zero = runs != Some(1);
            let zero: Vec<_> = COVERAGE
                .into_iter()
                .filter(|counter| at_zero && excused.iter().any(|&(event, _)| event == *counter))
                .collect();
            for covered in [64, measured, 1 << 32] {
                let totals = Totals {
                    pass: covered,
                    runs: covered,
                    covered,
                    reached: with(runs),
                    ..Default::default()
                };
                let status = listed(profile, &totals);
                assert!(!carries_verdict(&status), "{profile} {form} {covered}");
                assert!(
                    status.get("unreached").is_none(),
                    "{profile} {form} {covered}"
                );
                assert_eq!(
                    status["reach"][profile]["zero"],
                    json!(zero),
                    "{profile} {form} {covered}"
                );
                assert_eq!(
                    keys(&status),
                    keys(&listed("cluster-long", &totals)),
                    "{profile} {form} {covered}"
                );
            }
        }
    }
}

/// A sweep that ends on a root with no `sweep.json` is held: it has no
/// totals to print or to give a verdict on. A root with one ends with its
/// status.
#[test]
fn a_sweep_that_ends_with_no_checkpoint_is_held() {
    let case = Case::new();
    assert!(matches!(final_totals(&case.root), Err(Error::Held(_))));
    crate::store::replace_host(&case.root.join("sweep.json"), &swept(&pins('b'))).unwrap();
    let status = status(&case.root).unwrap().unwrap();
    assert_eq!(status["reach"], json!({}));
    assert_eq!(final_totals(&case.root).unwrap(), status);
}

#[test]
fn a_checkpoint_without_classes_counts_its_declared_controls_as_controls() {
    let case = Case::new();
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 2_000,
        rules: Vec::new(),
        batches: 0,
    };
    let planted = progress.profiles.entry("planted".to_owned()).or_default();
    (planted.runs, planted.next, planted.suspects) = (64, 64, 64);
    planted.history = Some(false);
    let upload = progress.profiles.entry("upload".to_owned()).or_default();
    (upload.runs, upload.next, upload.pass) = (64, 64, 64);
    upload.history = Some(false);
    let mut stored = serde_json::to_value(&progress).unwrap();
    for totals in stored["profiles"].as_object_mut().unwrap().values_mut() {
        for field in ["control", "history", "caught"] {
            assert!(totals.as_object_mut().unwrap().remove(field).is_some());
        }
    }
    crate::store::replace_host(
        &case.root.join("sweep.json"),
        &serde_json::to_vec(&stored).unwrap(),
    )
    .unwrap();

    let restored = super::read(&case.root).unwrap().unwrap();
    assert!(restored.profiles["planted"].control);
    assert!(!restored.profiles["upload"].control);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(swept["controls"]["profiles"], 1);
    assert_eq!(swept["controls"]["runs"], 64);
    assert!(swept.get("no_pass").is_none());
    assert!(!carries_verdict(&swept));
}

/// A caught run is named by the rule it ended in: a violation by the
/// cataloged text of the digest its failure identity holds, or by
/// `unlisted rule` and that digest when the catalog holds none; an
/// unsuccessful run by its rule; and a panic by `panic:` and its
/// payload.
#[test]
fn a_caught_run_names_the_rule_it_ended_in() {
    let rule = "a bound slot's record fails its header or chunk checks";
    let digest = Digest::of(rule.as_bytes()).to_string();
    let identity = format!("02010100000000{digest}0000000000");
    assert_eq!(identity.len(), 88);
    let catalog = BTreeMap::from([(digest.clone(), rule.to_owned())]);
    assert_eq!(rule_name(&Ended::Violation(&identity), &catalog), rule);
    assert_eq!(
        rule_name(&Ended::Violation(&identity), &BTreeMap::new()),
        format!("unlisted rule {digest}")
    );
    assert_eq!(
        rule_name(&Ended::Unsuccessful("a healed owner kept"), &catalog),
        "a healed owner kept"
    );
    assert_eq!(
        rule_name(
            &Ended::Panic("the run panicked at a.rs:1:2: a planted panic"),
            &catalog
        ),
        "panic: a planted panic"
    );
}

/// A text the catalog lists under `cluster` and then `history` counts
/// under `history` for a catch by a scripted history and under `cluster`
/// for a catch by any other profile, so neither scope is credited with the
/// other's catch.
#[test]
fn a_cluster_and_history_text_counts_in_the_scope_of_the_profile_that_caught_it() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut runner = frozen(&plan, &passing(":"));
    let progress = runner.progress.get_mut().unwrap();
    let shared = "an owner binds a version an acknowledged invalidation covered";
    progress.rules = vec![
        ("cluster".into(), shared.into()),
        ("history".into(), shared.into()),
    ];
    let scopes = |runner: &mut Frozen<'_>| {
        runner.flush().unwrap();
        let status = status(&plan.root).unwrap().unwrap();
        let uncaught = |scope: &str| status["rules"]["scopes"][scope]["uncaught"].clone();
        (uncaught("cluster"), uncaught("history"))
    };
    let totals = progress
        .profiles
        .entry("covered-successors".into())
        .or_default();
    totals.history = Some(true);
    totals.caught_rules.insert(shared.into(), 1);
    assert_eq!(scopes(&mut runner), (json!([shared]), json!([])));
    let progress = runner.progress.get_mut().unwrap();
    let totals = progress
        .profiles
        .entry("cluster-covered-control".into())
        .or_default();
    totals.control = true;
    totals.caught_rules.insert(shared.into(), 1);
    assert_eq!(scopes(&mut runner), (json!([]), json!([])));
    let progress = runner.progress.get_mut().unwrap();
    progress.profiles.remove("covered-successors");
    assert_eq!(scopes(&mut runner), (json!([]), json!([shared])));
}

/// `status` lists each rule the root's controls were caught by with its
/// runs and controls, and each scope of the worker's catalog with its
/// rules, how many count as caught, and the texts that do not. A caught
/// text under two scopes counts in the one the catalog lists first and
/// stays uncaught in the other, a rule outside the catalog is listed as
/// caught and counts in no scope, and a root with no catalog has no
/// scope.
#[test]
fn status_lists_the_rules_controls_caught_and_those_none_caught() {
    let case = Case::new();
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 0,
        rules: Vec::new(),
        batches: 0,
    };
    let write = |progress: &Progress| {
        crate::store::replace_host(
            &case.root.join("sweep.json"),
            &serde_json::to_vec(progress).unwrap(),
        )
        .unwrap();
    };
    for (control, rule, runs) in [
        ("planted", "a record check", 5),
        ("corrupted", "a record check", 2),
        ("misread", "a read check", 3),
        ("cluster-late-leak", "a kept resource", 4),
    ] {
        let totals = progress.profiles.entry(control.to_owned()).or_default();
        (totals.control, totals.history) = (true, Some(false));
        totals.caught_rules.insert(rule.to_owned(), runs);
    }
    write(&progress);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(
        swept["rules"]["caught"],
        json!({
            "a kept resource": {"runs": 4, "controls": ["cluster-late-leak"]},
            "a read check": {"runs": 3, "controls": ["misread"]},
            "a record check": {"runs": 7, "controls": ["corrupted", "planted"]},
        })
    );
    assert_eq!(swept["rules"]["scopes"], json!({}));
    progress.rules = [
        ("boundary", "a record check"),
        ("boundary", "an unexpected binding"),
        ("world", "a read check"),
        ("oracle", "a read check"),
        ("oracle", "a custody check"),
    ]
    .map(|(scope, text)| (scope.to_owned(), text.to_owned()))
    .to_vec();
    write(&progress);
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(
        swept["rules"]["scopes"],
        json!({
            "boundary": {"rules": 2, "caught": 1, "uncaught": ["an unexpected binding"]},
            "oracle": {
                "rules": 2,
                "caught": 0,
                "uncaught": ["a read check", "a custody check"],
            },
            "world": {"rules": 1, "caught": 1, "uncaught": []},
        })
    );
    assert_eq!(swept["histories"]["profiles"], 0);
    assert_eq!(
        swept["unlisted_uncaught"],
        json!({"boundary": ["an unexpected binding"]})
    );
}

/// Once every history has a credited run, `status` emits
/// `unlisted_uncaught` when a text whose first scope is not `oracle` has no
/// catch and no row of `uncaught::ALLOWED`, grouped under that first scope.
/// A history with no run, or with runs and no credit, withholds the key. A
/// catch of a text in its first scope covers its later copies, an uncaught
/// text stands in the key under its first scope alone while
/// `rules.scopes` lists it under each, and the key carries no verdict.
#[test]
fn status_names_uncaught_texts_outside_the_list_once_every_history_is_credited() {
    let case = Case::new();
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 0,
        rules: [
            ("boundary", "a slot word is malformed"),
            ("boundary", "an unexpected binding"),
            ("world", "a read check"),
            ("cluster", "a kept resource"),
            ("history", "a step check"),
            ("history", "a read check"),
            ("history", "a kept resource"),
            ("oracle", "a custody check"),
        ]
        .map(|(scope, text)| (scope.to_owned(), text.to_owned()))
        .to_vec(),
        batches: 0,
    };
    let control = progress.profiles.entry("misread".to_owned()).or_default();
    (control.control, control.history) = (true, Some(false));
    control.runs = 3;
    control.caught = 3;
    control.caught_rules.insert("a read check".to_owned(), 3);
    for (history, runs, pass) in [
        ("i1-passing", 2, 2),
        ("i2-failing", 2, 0),
        ("i3-unrun", 0, 0),
    ] {
        let totals = progress.profiles.entry(history.to_owned()).or_default();
        totals.history = Some(true);
        totals.runs = runs;
        totals.pass = pass;
    }
    let write = |progress: &Progress| {
        crate::store::replace_host(
            &case.root.join("sweep.json"),
            &serde_json::to_vec(progress).unwrap(),
        )
        .unwrap();
        status(&case.root).unwrap().unwrap()
    };
    let swept = write(&progress);
    assert_eq!(swept["histories"]["ran"], 2);
    assert_eq!(swept["histories"]["profiles"], 3);
    assert_eq!(swept.get("unlisted_uncaught"), None);
    let failing = progress.profiles.get_mut("i2-failing").unwrap();
    failing.failing_history = true;
    failing.caught = 1;
    failing.caught_rules.insert("a step check".to_owned(), 1);
    assert_eq!(write(&progress).get("unlisted_uncaught"), None);
    let unrun = progress.profiles.get_mut("i3-unrun").unwrap();
    unrun.runs = 1;
    unrun.pass = 1;
    let swept = write(&progress);
    assert_eq!(swept["histories"]["ran"], 3);
    assert_eq!(
        swept["unlisted_uncaught"],
        json!({"boundary": ["an unexpected binding"], "cluster": ["a kept resource"]})
    );
    assert_eq!(
        swept["rules"]["scopes"]["boundary"]["uncaught"],
        json!(["a slot word is malformed", "an unexpected binding"])
    );
    assert_eq!(
        swept["rules"]["scopes"]["history"]["uncaught"],
        json!(["a read check", "a kept resource"])
    );
    for key in ["alarm", "no_pass", "unreached"] {
        assert_eq!(swept.get(key), None, "{key}");
    }
    assert!(!carries_verdict(&swept));
    for (history, runs, missed, ran) in [
        ("i1-passing", 0, 0, 2),
        ("i1-passing", 2, 0, 3),
        ("i2-failing", 2, 2, 3),
        ("i3-unrun", 0, 0, 2),
        ("i3-unrun", 2, 0, 3),
    ] {
        let credited = progress.profiles[history].clone();
        let uncredited = Totals {
            history: Some(true),
            failing_history: credited.failing_history,
            runs,
            missed,
            ..Totals::default()
        };
        progress.profiles.insert(history.to_owned(), uncredited);
        let swept = write(&progress);
        assert_eq!(swept["histories"]["profiles"], 3);
        assert_eq!(swept["histories"]["ran"], ran, "{history} {runs}");
        assert_eq!(
            swept.get("unlisted_uncaught"),
            None,
            "{history} with {runs} runs, {missed} missed"
        );
        progress.profiles.insert(history.to_owned(), credited);
    }
    let control = progress.profiles.get_mut("misread").unwrap();
    control.runs = 5;
    control.caught = 5;
    control
        .caught_rules
        .insert("an unexpected binding".to_owned(), 1);
    control.caught_rules.insert("a kept resource".to_owned(), 1);
    assert_eq!(write(&progress).get("unlisted_uncaught"), None);
}

/// A scripted history's catch of a text the catalog lists under `cluster`
/// and then `history` keeps the text out of `unlisted_uncaught`, while
/// `rules.scopes` credits the catch to `history` and lists the text as
/// uncaught under `cluster`.
#[test]
fn a_history_catch_keeps_a_cluster_and_history_text_out_of_unlisted_uncaught() {
    let case = Case::new();
    let shared = "an owner binds a version an acknowledged invalidation covered";
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 0,
        rules: [
            ("cluster", shared),
            ("cluster", "a kept resource"),
            ("history", shared),
        ]
        .map(|(scope, text)| (scope.to_owned(), text.to_owned()))
        .to_vec(),
        batches: 0,
    };
    let history = progress
        .profiles
        .entry("covered-successors".to_owned())
        .or_default();
    (history.history, history.failing_history) = (Some(true), true);
    (history.runs, history.caught) = (1, 1);
    history.caught_rules.insert(shared.to_owned(), 1);
    crate::store::replace_host(
        &case.root.join("sweep.json"),
        &serde_json::to_vec(&progress).unwrap(),
    )
    .unwrap();
    let swept = status(&case.root).unwrap().unwrap();
    assert_eq!(
        swept["rules"]["scopes"]["cluster"]["uncaught"],
        json!([shared, "a kept resource"])
    );
    assert_eq!(swept["rules"]["scopes"]["history"]["uncaught"], json!([]));
    assert_eq!(
        swept["unlisted_uncaught"],
        json!({"cluster": ["a kept resource"]})
    );
}

/// A profile with a missing `history` field may be an uncredited history,
/// so `status` withholds `unlisted_uncaught` even when
/// `histories.profiles` is zero. The profile row preserves the missing
/// `history` field as distinct from `false`.
#[test]
fn status_withholds_unlisted_uncaught_while_a_profile_states_no_history_class() {
    let case = Case::new();
    let mut progress = Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        archive: Closing::Kept,
        profiles: BTreeMap::new(),
        elapsed_ms: 0,
        rules: vec![("boundary".to_owned(), "an unexpected binding".to_owned())],
        batches: 0,
    };
    let upload = progress.profiles.entry("upload".to_owned()).or_default();
    (upload.runs, upload.next, upload.pass) = (64, 64, 64);
    let unheld = progress
        .profiles
        .entry("h1-get-unheld".to_owned())
        .or_default();
    (unheld.runs, unheld.next) = (2, 2);
    let stored = serde_json::to_value(&progress).unwrap();
    let swept = |classes: [(&str, Option<bool>); 2]| {
        let mut stored = stored.clone();
        for (profile, history) in classes {
            let totals = stored["profiles"][profile].as_object_mut().unwrap();
            totals.remove("history");
            if let Some(history) = history {
                totals.insert("history".to_owned(), history.into());
            }
        }
        crate::store::replace_host(
            &case.root.join("sweep.json"),
            &serde_json::to_vec(&stored).unwrap(),
        )
        .unwrap();
        status(&case.root).unwrap().unwrap()
    };
    let stated = swept([("upload", Some(false)), ("h1-get-unheld", Some(false))]);
    assert_eq!(stated["histories"]["profiles"], 0);
    assert_eq!(
        stated["unlisted_uncaught"],
        json!({"boundary": ["an unexpected binding"]})
    );
    assert_eq!(stated["profiles"]["h1-get-unheld"]["history"], false);
    for classes in [
        [("upload", Some(false)), ("h1-get-unheld", None)],
        [("upload", None), ("h1-get-unheld", Some(false))],
        [("upload", None), ("h1-get-unheld", None)],
    ] {
        let unstated = swept(classes);
        assert_eq!(unstated["histories"]["profiles"], 0, "{classes:?}");
        assert_eq!(unstated.get("unlisted_uncaught"), None, "{classes:?}");
        for (profile, history) in classes {
            assert_eq!(
                unstated["profiles"][profile].get("history"),
                history.map(Value::from).as_ref(),
                "{profile} of {classes:?}"
            );
        }
    }
    let history = swept([("upload", Some(false)), ("h1-get-unheld", Some(true))]);
    assert_eq!(history["histories"]["profiles"], 1);
    assert_eq!(history.get("unlisted_uncaught"), None);
}

/// A control's run that ends in its declared failure is caught: a
/// violation of its obligation, or of one of its obligations, a panic
/// with its payload, or its unsuccessful rule. One that passes, with
/// or without its witnesses, is a suspect of class `control passed`,
/// and one whose plant met no check is a suspect of class `control met
/// no check`. Every other ending stays what a live run's is, a plant
/// that took no effect and a failure beside an exit code that disagrees
/// with it included, except that an unsuccessful or inconclusive ending
/// of a control whose plant precedes its run is a suspect of class
/// `control met no check`. Such a control is caught only by a violation
/// of its obligation under its rule.
#[test]
fn a_control_run_is_caught_by_its_failure_and_a_suspect_when_it_passes() {
    let judge = |profile: &str, code: i32, body: &str| {
        let block = read(&format!("code: {code}\n{body}"), 7).unwrap();
        let ending = block.ending(&word("upload"));
        judged(controls::named(profile).unwrap(), &block, ending)
    };
    let violated = |obligation: &str| {
        format!(
            "{}identity: 0201{obligation}{}\n",
            violation(),
            "0".repeat(82)
        )
    };
    let suspect = |class: &str| Ending::Suspect(class.to_owned());
    assert_eq!(judge("planted", 1, &violated("01")), Ending::Caught);
    assert_eq!(judge("planted", 1, &violated("02")), suspect("violation"));
    assert_eq!(
        judge("planted", 0, &violated("01")),
        suspect("exit code disagrees with the summary")
    );
    for (obligation, ending) in [
        ("01", Ending::Caught),
        ("02", Ending::Caught),
        ("03", suspect("violation")),
    ] {
        assert_eq!(
            judge("cluster-swarm-wrong-owner", 1, &violated(obligation)),
            ending
        );
    }
    assert_eq!(
        judge(
            "panicking",
            3,
            "run: the run panicked at a.rs:1:2: a planted panic once the upload published\n"
        ),
        Ending::Caught
    );
    assert_eq!(
        judge(
            "panicking",
            3,
            "run: the run panicked at a.rs:1:2: another panic\n"
        ),
        suspect("panic")
    );
    // The planted panic beside another exit code than a panicked run's,
    // or beside none, is no caught run.
    let planted = "run: the run panicked at a.rs:1:2: a planted panic once the upload published\n";
    assert_eq!(judge("panicking", 0, planted), suspect("panic"));
    let uncoded = read(planted, 7).unwrap();
    let ending = uncoded.ending(&word("upload"));
    assert_eq!(
        judged(controls::named("panicking").unwrap(), &uncoded, ending),
        suspect("panic")
    );
    let unsuccessful = |rule: &str| unsuccessful().replacen("fewer exact reads", rule, 1);
    assert_eq!(
        judge(
            "cluster-late-leak",
            1,
            &unsuccessful("a healed owner kept the resources of fini")
        ),
        Ending::Caught
    );
    assert_eq!(
        judge("cluster-late-leak", 1, &unsuccessful(controls::UNSEEN)),
        suspect("control met no check")
    );
    let unreported = "the control met no check";
    assert_eq!(
        judge("cluster-late-leak", 1, &unsuccessful(unreported)),
        Ending::Uncredited(unsuccessful_key(unreported))
    );
    assert_eq!(
        judge("cluster-late-leak", 1, &unsuccessful(controls::NO_EFFECT)),
        Ending::Uncredited(unsuccessful_key(controls::NO_EFFECT))
    );
    let uncounted = summary(&[
        ("fired=03 required=03", "fired=01 required=03"),
        UNCOUNTED,
        ("stop: goal\n", "stop: goal\ncause: one check\n"),
    ]);
    for (code, passed) in [(0, summary(&[])), (1, uncounted)] {
        assert_eq!(judge("planted", code, &passed), suspect("control passed"));
    }
    let inconclusive = summary(&[
        ("complete pass", "complete inconclusive"),
        UNCOUNTED,
        ("stop: goal\n", "stop: limit turns\ncause: limit\n"),
    ]);
    assert_eq!(
        judge("planted", 1, &inconclusive),
        Ending::Uncredited("inconclusive: limit turns".into())
    );
    // A control over a record changed before its run is caught by a Bytes
    // violation under the record-check rule, and by no other rule of that
    // obligation. Its plant precedes its run, so an unsuccessful or
    // inconclusive run was missed, and a run that ends in a violation of
    // another obligation stays a violation. `corrupted` is `upload`'s
    // such control.
    let ruled = |rule: &str| {
        format!(
            "{}identity: 02010100000000{}{}\n",
            violation(),
            Digest::of(rule.as_bytes()),
            "00".repeat(5)
        )
    };
    let unchecked = "a bound slot's record fails its header or chunk checks";
    for control in ["corrupted", "replacing-corrupted"] {
        assert_eq!(judge(control, 1, &ruled(unchecked)), Ending::Caught);
        assert_eq!(
            judge(control, 1, &ruled("another check")),
            suspect("violation")
        );
        assert_eq!(
            judge(control, 1, &inconclusive),
            suspect("control met no check")
        );
        assert_eq!(
            judge(control, 1, &unsuccessful(controls::NO_EFFECT)),
            suspect("control met no check")
        );
        assert_eq!(judge(control, 1, &violated("02")), suspect("violation"));
        assert_eq!(
            judge(control, 3, &infrastructure("infrastructure cap")),
            Ending::Uncredited("inconclusive: recorder cap".into())
        );
    }
}

/// A control's run of either [`MISSED`] class adds to `missed`, and a
/// suspect of another class adds to no ending's count.
#[test]
fn counted_control_runs_of_a_missed_class_add_to_missed() {
    let mut totals = Totals::default();
    for (run, class) in ["control passed", "control met no check", "violation"]
        .into_iter()
        .enumerate()
    {
        totals.count(run as u64, None, &Ending::Suspect(class.to_owned()), 0);
    }
    assert_eq!(
        (totals.runs, totals.missed, totals.pass, totals.caught),
        (3, 2, 0, 0)
    );
}

/// A sweep runs every control [`controls::swept`] names for its
/// profiles, in the profiles' order, and one that two profiles share
/// once. A profile with no control adds none. A listing that lacks a
/// control of one of the profiles is rejected with the control and the
/// profile named. The listing admits required profiles with their cluster declarations.
/// When a cluster declaration is missing, the rejection names the selected profile.
#[test]
fn a_sweep_schedules_every_control_of_its_profiles_or_is_rejected() {
    let listing = |controls: &[&str]| {
        let upload = "profile: upload class=live support=implemented campaign=unqualified \
                      held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n";
        let listed: String = controls
            .iter()
            .map(|control| upload.replace("upload class=live", &format!("{control} class=control")))
            .collect();
        assert!(LISTING.contains(upload));
        Listing::parse(&LISTING.replacen(upload, &format!("{upload}{listed}"), 1)).unwrap()
    };
    let scheduled = |profiles: &[&str], listing: &Listing| {
        let profiles: Vec<Text> = profiles.iter().map(|profile| word(profile)).collect();
        controls_of(&profiles, listing).map(|controls| {
            controls
                .iter()
                .map(|control| control.as_str().to_owned())
                .collect::<Vec<_>>()
        })
    };
    let every = [
        "planted",
        "corrupted",
        "acked",
        "panicking",
        "asserting",
        "misread",
        "staged-hit",
        "leaked",
        "uncounted",
        "cluster-wrong-owner",
        "cluster-stale-read",
        "cluster-order-1",
        "cluster-order-2",
        "cluster-order-3",
        "cluster-version-end",
    ];
    assert_eq!(
        scheduled(&["upload", "cluster-broad"], &listing(&every)).unwrap(),
        every[..14]
    );
    let declared = Listing::parse(CLUSTERS).unwrap();
    assert_eq!(
        scheduled(&["cluster-pressure", "h6-get", "cluster-broad"], &declared).unwrap(),
        [
            "cluster-wrong-owner",
            "cluster-stale-read",
            "cluster-version-end",
            "cluster-order-1",
            "cluster-order-2",
            "cluster-order-3",
        ]
    );
    for &(profile, ..) in required::REQUIRED {
        assert!(scheduled(&[profile], &declared).is_ok(), "{profile}");
        let mut missing = declared.clone();
        missing.clusters.retain(|cluster| cluster.name != profile);
        let rejected = scheduled(&[profile], &missing);
        assert!(
            matches!(rejected, Err(Error::Rejected(reason)) if reason.contains(profile) && reason.contains("cluster declaration")),
            "{profile}"
        );
    }
    for (listed, lacking) in [
        (&every[..0], "planted"),
        (&every[..4], "asserting"),
        (&every[..5], "misread"),
        (&every[..6], "staged-hit"),
        (&every[..7], "leaked"),
        (&every[..8], "uncounted"),
    ] {
        let rejected = scheduled(&["upload"], &listing(listed));
        assert!(
            matches!(
                &rejected,
                Err(Error::Rejected(reason))
                    if reason.contains(&format!("control {lacking} "))
                        && reason.contains("profile upload")
            ),
            "{rejected:?}"
        );
    }
}

/// With no control and no history, the batches take the profiles in
/// turn. With controls, batch 1 and every sixteenth batch after it are
/// control batches. With histories, batch 9 and every sixteenth batch
/// after it are history batches. The other batches take the profiles in
/// turn, whichever of the two a sweep has.
#[test]
fn one_batch_in_sixteen_runs_a_control_and_one_a_history() {
    assert_eq!(
        (0..5)
            .map(|batch| scheduled(batch, 3, false, false))
            .collect::<Vec<_>>(),
        [0, 1, 2, 0, 1].map(Turn::Profile)
    );
    for (controls, histories) in [(true, false), (false, true), (true, true)] {
        let batches: Vec<_> = (0..64)
            .map(|batch| scheduled(batch, 3, controls, histories))
            .collect();
        let at =
            |turn: Turn| -> Vec<_> { (0..64).filter(|&batch| batches[batch] == turn).collect() };
        let taken = |enabled: bool, positions: [usize; 4]| {
            if enabled {
                positions.to_vec()
            } else {
                Vec::new()
            }
        };
        assert_eq!(at(Turn::Control), taken(controls, [1, 17, 33, 49]));
        assert_eq!(at(Turn::History), taken(histories, [9, 25, 41, 57]));
        let profiles: Vec<_> = batches
            .iter()
            .filter_map(|turn| match turn {
                Turn::Profile(profile) => Some(*profile),
                _ => None,
            })
            .collect();
        let checks = 4 * (usize::from(controls) + usize::from(histories));
        assert_eq!(profiles.len(), 64 - checks);
        assert!(
            profiles
                .iter()
                .enumerate()
                .all(|(nth, profile)| *profile == nth as u64 % 3)
        );
    }
}

/// The testdata listing at `capabilities` with three histories beside
/// `upload`: `h1-get` expects a pass, `h1-get-stale` a violation and
/// `h1-get-unheld` an unsuccessful ending. At version 4 the listing
/// declares the failure of the last two.
fn with_histories(capabilities: u32) -> Listing {
    let upload = "profile: upload class=live support=implemented campaign=unqualified \
                  held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n";
    let history = |name: &str, expected: &str| {
        let class = format!("{name} class=history expected={expected}");
        upload.replace("upload class=live", &class)
    };
    let histories = [
        history("h1-get", "pass"),
        history("h1-get-stale", "violation"),
        history("h1-get-unheld", "unsuccessful"),
    ]
    .concat();
    assert!(LISTING.contains(upload));
    let mut text = LISTING
        .replacen(
            "capabilities: 1",
            &format!("capabilities: {capabilities}"),
            1,
        )
        .replacen(upload, &format!("{upload}{histories}"), 1);
    if capabilities >= crate::protocol::DECLARED_FAILURES {
        text.push_str("fails: h1-get-stale violation 2 a stale hit\n");
        text.push_str("fails: h1-get-unheld unsuccessful old read held\n");
    }
    Listing::parse(&text).unwrap()
}

/// A sweep runs every listed history it can judge, in the listing's
/// order: one that expects a pass, and one that expects no pass whose
/// failure the listing declares. A listing below version 4 declares
/// none, so its sweep runs the passing history alone.
#[test]
fn a_sweep_schedules_each_listed_history_that_passes_or_declares_its_failure() {
    let names = |listing: &Listing| {
        histories_of(listing)
            .unwrap()
            .iter()
            .map(|history| history.as_str().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(&with_histories(4)),
        ["h1-get", "h1-get-stale", "h1-get-unheld"]
    );
    assert_eq!(names(&with_histories(3)), ["h1-get"]);
    assert!(names(&Listing::parse(LISTING).unwrap()).is_empty());
    // A name that is no record text rejects the sweep with the name.
    let mut listing = with_histories(4);
    listing.profiles[1].name = "h1\u{7}get".to_owned();
    let rejected = histories_of(&listing);
    assert!(
        matches!(&rejected, Err(Error::Rejected(reason)) if reason.contains(r#""h1\u{7}get""#)),
        "{rejected:?}"
    );
    // A history's manifest is a file named for it, and the name is the
    // worker's output, so one that is no single path component rejects
    // the sweep.
    for name in ["../h1-get", "a/b", ".."] {
        let mut listing = with_histories(4);
        listing.profiles[1].name = name.to_owned();
        assert_eq!(listing.profiles[1].class, Class::History);
        let rejected = histories_of(&listing);
        assert!(
            matches!(&rejected, Err(Error::Rejected(reason)) if reason.contains("path component")),
            "{name}: {rejected:?}"
        );
    }
}

/// A history that expects no pass is judged as a control by the failure
/// its listing line declares. Its run is caught when it ends in a
/// violation of the declared obligation under the declared rule, or
/// unsuccessful under the declared witness. A violation of another
/// obligation or under another rule is a suspect of class `violation`, a
/// pass is a suspect of class `control passed`, and another unsuccessful
/// ending is counted under its rule. A declared witness of 41 bytes or
/// more earns no catch, whatever the run prints, and one of 40 bytes is
/// caught only by a run that prints all of it. A history that expects a
/// pass is judged as a live profile, and so is a failing history of a
/// listing that declares no failure.
#[test]
fn a_history_that_expects_no_pass_is_caught_by_its_declared_failure() {
    let declared = with_histories(4);
    let judge = |listing: &Listing, profile: &str, code: i32, body: &str| {
        // A scripted history's summary names it and prints no operations
        // and no witnesses.
        let body = body
            .replacen("profile: upload", &format!("profile: {profile}"), 1)
            .replacen("operations: 18", "operations: unavailable", 1)
            .replacen("witnesses: 10", "witnesses: unavailable", 1);
        let text = format!("root: 7\ncode: {code}\n{body}end: 7\n");
        let block = block(&mut text.as_bytes(), 7, listing).expect("a block");
        super::ended(listing, &word(profile), &block)
    };
    let violated = |obligation: &str, rule: &str| {
        let digest = Digest::of(rule.as_bytes());
        format!(
            "{}identity: 0201{obligation}00000000{digest}0000000000\n",
            violation()
        )
    };
    let suspect = |class: &str| Ending::Suspect(class.to_owned());
    let unsuccessful = |rule: &str| unsuccessful().replacen("fewer exact reads", rule, 1);
    let stale = "h1-get-stale";
    for (body, code, ending) in [
        (violated("02", "a stale hit"), 1, Ending::Caught),
        (violated("02", "another rule"), 1, suspect("violation")),
        (violated("03", "a stale hit"), 1, suspect("violation")),
        (summary(&[]), 0, suspect("control passed")),
        (
            unsuccessful("old read held"),
            1,
            Ending::Uncredited("unsuccessful: old read held".to_owned()),
        ),
    ] {
        assert_eq!(judge(&declared, stale, code, &body), ending, "{body}");
    }
    let unheld = "h1-get-unheld";
    for (body, code, ending) in [
        (unsuccessful("old read held"), 1, Ending::Caught),
        (
            unsuccessful("fresh GET missed"),
            1,
            Ending::Uncredited("unsuccessful: fresh GET missed".to_owned()),
        ),
        (violated("02", "a stale hit"), 1, suspect("violation")),
        (summary(&[]), 0, suspect("control passed")),
    ] {
        assert_eq!(judge(&declared, unheld, code, &body), ending, "{body}");
    }
    assert_eq!(judge(&declared, "h1-get", 0, &summary(&[])), Ending::Pass);
    assert_eq!(
        judge(&declared, "h1-get", 1, &violated("02", "a stale hit")),
        suspect("violation")
    );
    // A witness whose first 41 bytes end inside a character is judged
    // without a cut there and earns no catch.
    let mut split = with_histories(4);
    let history = split
        .profiles
        .iter_mut()
        .find(|profile| profile.name == unheld)
        .expect("a listed history");
    history.fails = Some(crate::protocol::Fails::Unsuccessful(format!(
        "{}\u{e9} held",
        "a".repeat(40)
    )));
    assert_eq!(
        judge(&split, unheld, 1, &unsuccessful(&"a".repeat(40))),
        Ending::Uncredited(format!("unsuccessful: {}", "a".repeat(40)))
    );
    let prefix = "a".repeat(41);
    for witness in [
        format!("{prefix} first"),
        format!("{prefix} second"),
        prefix.clone(),
    ] {
        let mut ambiguous = declared.clone();
        ambiguous
            .profiles
            .iter_mut()
            .find(|profile| profile.name == unheld)
            .unwrap()
            .fails = Some(crate::protocol::Fails::Unsuccessful(witness));
        assert_eq!(
            judge(&ambiguous, unheld, 1, &unsuccessful(&prefix)),
            Ending::Uncredited(format!("unsuccessful: {prefix}"))
        );
    }
    // A witness of 40 bytes is caught by a run that prints all of it, and
    // by neither a run that prints one byte more nor one that prints its
    // first 39 bytes.
    let mut short = declared.clone();
    short
        .profiles
        .iter_mut()
        .find(|profile| profile.name == unheld)
        .unwrap()
        .fails = Some(crate::protocol::Fails::Unsuccessful("a".repeat(40)));
    assert_eq!(
        judge(&short, unheld, 1, &unsuccessful(&"a".repeat(40))),
        Ending::Caught
    );
    for printed in [prefix.clone(), "a".repeat(39)] {
        assert_eq!(
            judge(&short, unheld, 1, &unsuccessful(&printed)),
            Ending::Uncredited(format!("unsuccessful: {printed}"))
        );
    }
    let undeclared = with_histories(3);
    assert_eq!(
        judge(&undeclared, stale, 1, &violated("02", "a stale hit")),
        suspect("violation")
    );
    assert_eq!(judge(&undeclared, stale, 0, &summary(&[])), Ending::Pass);
}

/// A control batch takes its profile from the sweep's controls and a
/// history batch from its histories, each raising that profile's begun
/// count. A history whose turn was given back is the next one taken, and
/// a batch of one of the sweep's profiles begins no such turn.
#[test]
fn automatic_batches_select_their_own_list_and_return_an_unsent_turn() {
    let case = Case::new();
    let plan = plan(&case, 1);
    let mut runner = frozen(&plan, &passing(":"));
    runner.controls = vec![word("planted")];
    runner.histories = vec![word("h1-get"), word("h1-get-stale")];
    let (profile, turn) = runner.next_profile(1);
    assert_eq!((profile.as_str(), turn), ("planted", Turn::Control));
    let (profile, turn) = runner.next_profile(HISTORY_FIRST);
    assert_eq!((profile.as_str(), turn), ("h1-get", Turn::History));
    {
        let mut progress = runner.progress.lock().unwrap();
        assert_eq!(progress.profiles["planted"].begun, 1);
        assert_eq!(progress.profiles["h1-get"].begun, 1);
        progress.unsent(profile);
    }
    assert_eq!(
        runner
            .next_profile(HISTORY_FIRST + CONTROL_EVERY)
            .0
            .as_str(),
        "h1-get"
    );
    assert_eq!(
        runner
            .next_profile(HISTORY_FIRST + 2 * CONTROL_EVERY)
            .0
            .as_str(),
        "h1-get-stale"
    );
    assert_eq!(runner.next_profile(0).0.as_str(), "upload");
    assert!(
        !runner
            .progress
            .lock()
            .unwrap()
            .profiles
            .contains_key("upload")
    );
}

/// `body`, a summary of `upload`, as the scripted history `profile`
/// prints it: its name, and no operations and no witnesses.
fn history_summary(body: &str, profile: &str) -> String {
    body.replace("profile: upload", &format!("profile: {profile}"))
        .replace("operations: 18", "operations: unavailable")
        .replace("witnesses: 10", "witnesses: unavailable")
}

/// A runner of `plan` whose worker is `script` and whose histories are
/// those `listing` yields, each bound with its manifest, with a history
/// batch next.
fn history_runner<'a>(plan: &'a Plan, script: &str, listing: Listing) -> Frozen<'a> {
    let mut runner = frozen(plan, script);
    runner.listing = listing;
    runner.histories = histories_of(&runner.listing).unwrap();
    let (progress, manifests) = bound(
        plan,
        &runner.pins,
        &runner.listing,
        (&[], &runner.histories),
        None,
    )
    .unwrap();
    runner.progress = Mutex::new(progress);
    runner.manifests = manifests;
    runner.batches = AtomicU64::new(HISTORY_FIRST);
    runner
}

/// Runs `runner` until a worker ends before its ready line, which fails
/// the sweep: the worker of a profile the script does not serve, or a
/// start the script ends.
fn until_a_worker_fails(runner: &Frozen<'_>, host: &Delegation) {
    let result = runner.run(
        &host.root(),
        Some(Instant::now() + Duration::from_secs(10)),
        FLUSH,
    );
    assert!(
        matches!(result, Err(Error::Held(ref text)) if text.contains("before its ready line")),
        "{result:?}"
    );
}

/// A history batch replays its last finished run once its worker has
/// exited, in the batch that ran it. The worker here prints another
/// summary for each later root of one process, so the fresh replay of the
/// batch's last run differs and that run is a suspect of class `replay
/// differs`, before the next history's batch begins.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_history_batch_replays_its_last_seed_before_its_next_rotation() {
    let _processes = processes();
    let host = Delegation::new("history-replay");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_secs(1);
    let body = history_summary(COUNTING, "h1-get");
    let changed = body.replace("decisions: 61", "decisions: 62");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" != --manifest ]; then case \"$2\" in *h1-get.manifest) ;; *) exit 3 ;; esac; fi\n\
         summary='{body}'\n\
         if [ \"$1\" = --manifest ]; then printf '%s' \"$summary\"; exit 0; fi\n\
         echo 'sweep: ready'\n\
         while read root; do\n\
         printf 'root: %s\\ncode: 0\\n%send: %s\\n' \"$root\" \"$summary\" \"$root\"\n\
         summary='{changed}'\n\
         done\n"
    );
    let runner = history_runner(&plan, &script, with_histories(4));
    until_a_worker_fails(&runner, &host);
    let progress = runner.progress.lock().unwrap();
    let history = &progress.profiles["h1-get"];
    assert!(history.runs >= 2);
    assert_eq!(
        (history.begun, history.replays, history.suspects),
        (1, 1, 1)
    );
    assert_eq!(history.suspect_keys.get("replay differs: "), Some(&1));
    assert_eq!(progress.profiles["h1-get-stale"].runs, 0);
    let lines = suspect_lines(&plan);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["profile"], "h1-get");
    assert_eq!(lines[0]["run"], history.runs - 1);
    assert_eq!(lines[0]["class"], "replay differs");
    assert_eq!(lines[0]["code"], 0);
    assert_eq!(lines[0]["summary"]["decisions"], "61");
}

/// A history batch replays a run it finished also when a later run of
/// the batch lost its worker. The worker here answers its first root and
/// exits on its second: the first run is replayed once, and the second
/// is a suspect of class `worker ended during the run`.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_history_batch_whose_worker_dies_replays_the_run_it_finished() {
    let _processes = processes();
    let host = Delegation::new("history-death");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_secs(1);
    let body = history_summary(COUNTING, "h1-get");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" != --manifest ]; then case \"$2\" in *h1-get.manifest) ;; *) exit 3 ;; esac; fi\n\
         summary='{body}'\n\
         if [ \"$1\" = --manifest ]; then printf '%s' \"$summary\"; exit 0; fi\n\
         echo 'sweep: ready'\n\
         read root\n\
         printf 'root: %s\\ncode: 0\\n%send: %s\\n' \"$root\" \"$summary\" \"$root\"\n\
         read root\n\
         exit 0\n"
    );
    let runner = history_runner(&plan, &script, with_histories(4));
    until_a_worker_fails(&runner, &host);
    let progress = runner.progress.lock().unwrap();
    let history = &progress.profiles["h1-get"];
    assert_eq!(
        (
            history.runs,
            history.pass,
            history.replays,
            history.suspects
        ),
        (2, 1, 1, 1)
    );
    let lines = suspect_lines(&plan);
    assert_eq!(lines.len(), 1);
    assert_eq!(
        (&lines[0]["run"], &lines[0]["class"]),
        (&json!(1), &json!("worker ended during the run"))
    );
}

/// A history that is also one of the sweep's profiles has each sampled
/// run replayed once. Its history batch replays that batch's last run
/// and leaves none for its profile batches: the first profile batch
/// after it starts with no replay, and the second replays the first's
/// last run. The worker's third start ends before its ready line, which
/// fails the sweep, after a history batch and one profile batch.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_history_among_the_profiles_has_each_sampled_run_replayed_once() {
    let _processes = processes();
    let host = Delegation::new("history-listed");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    plan.profiles = vec![word("h1-get")];
    let body = history_summary(COUNTING, "h1-get");
    let starts = plan.root.join("starts");
    let script = format!(
        "#!/bin/sh\nsummary='{body}'\n\
         if [ \"$1\" = --manifest ]; then printf '%s' \"$summary\"; exit 0; fi\n\
         echo start >> '{}'\n\
         [ \"$(wc -l < '{}')\" -ge 3 ] && exit 3\n\
         echo 'sweep: ready'\n\
         while read root; do sleep 0.02\n\
         printf 'root: %s\\ncode: 0\\n%send: %s\\n' \"$root\" \"$summary\" \"$root\"; done\n",
        starts.display(),
        starts.display()
    );
    let mut listing = with_histories(4);
    listing
        .profiles
        .retain(|profile| profile.name == "upload" || profile.name == "h1-get");
    let runner = history_runner(&plan, &script, listing);
    until_a_worker_fails(&runner, &host);
    // Batches 9, 10 and 11: the history batch, a profile batch, and the
    // profile batch whose worker failed after its replay.
    assert_eq!(runner.batches.load(Ordering::Relaxed), HISTORY_FIRST + 3);
    let progress = runner.progress.lock().unwrap();
    let history = &progress.profiles["h1-get"];
    assert_eq!(
        (history.begun, history.replays, history.suspects),
        (1, 2, 0)
    );
    assert_eq!(history.pass, history.runs);
}

/// A history batch the sweep schedules by itself counts each run of a
/// history that expects a violation: as caught, under the rule the run
/// ended in, when the run ends in the declared failure, and as missed,
/// with a `control passed` suspect, the root's alarm and no caught rule,
/// when it passes.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_history_batch_judges_declared_failures_and_marks_misses() {
    let _processes = processes();
    let host = Delegation::new("history-judge");
    for caught in [true, false] {
        let case = Case::new();
        let mut plan = plan(&case, 1);
        plan.batch = Duration::from_millis(50);
        let digest = Digest::of(b"a stale hit");
        let body = if caught {
            format!(
                "{}identity: 02010200000000{digest}0000000000\n",
                violation()
            )
        } else {
            COUNTING.into()
        };
        let body = history_summary(&body, "h1-get-stale");
        let code = u8::from(caught);
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" != --manifest ]; then case \"$2\" in *h1-get-stale.manifest) ;; *) exit 3 ;; esac; fi\n\
             summary='{body}'\n\
             if [ \"$1\" = --manifest ]; then printf '%s' \"$summary\"; exit {code}; fi\n\
             echo 'sweep: ready'\n\
             while read root; do printf 'root: %s\\ncode: {code}\\n%send: %s\\n' \"$root\" \"$summary\" \"$root\"; done\n"
        );
        let mut listing = with_histories(4);
        listing.profiles.retain(|profile| profile.name != "h1-get");
        let runner = history_runner(&plan, &script, listing);
        until_a_worker_fails(&runner, &host);
        runner.flush().unwrap();
        let status = status(&plan.root).unwrap().unwrap();
        let history = &status["profiles"]["h1-get-stale"];
        let runs = history["runs"].as_u64().unwrap();
        assert!(runs > 0);
        assert_eq!(history["begun"], 1);
        assert_eq!(history["replays"], 1);
        assert_eq!(history["caught"], if caught { runs } else { 0 });
        assert_eq!(history["missed"], if caught { 0 } else { runs });
        assert_eq!(history["suspects"], if caught { 0 } else { runs });
        // The runner holds no catalog, so the batch names the rule by its
        // digest.
        let rules = if caught {
            json!({format!("unlisted rule {digest}"): runs})
        } else {
            json!({})
        };
        assert_eq!(history["caught_rules"], rules);
        assert_eq!(status.get("alarm").is_some(), !caught);
        assert_eq!(status["histories"]["ran"], 1);
        if !caught {
            assert!(
                suspect_lines(&plan)
                    .iter()
                    .all(|line| line["class"] == "control passed")
            );
        }
    }
}

/// A history batch whose worker ends before its ready line sent no root,
/// so its history keeps the turn: the sweep fails naming that history's
/// worker after its one batch, and no batch is counted as begun for it.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_history_batch_without_a_first_root_returns_its_turn() {
    let _processes = processes();
    let host = Delegation::new("history-unsent");
    let case = Case::new();
    let plan = plan(&case, 1);
    let runner = history_runner(&plan, "#!/bin/sh\nexit 3\n", with_histories(4));
    let result = runner.run(
        &host.root(),
        Some(Instant::now() + Duration::from_secs(10)),
        FLUSH,
    );
    assert!(
        matches!(
            &result,
            Err(Error::Held(text))
                if text.contains("worker of h1-get ended") && text.contains("before its ready line")
        ),
        "{result:?}"
    );
    assert_eq!(runner.batches.load(Ordering::Relaxed), HISTORY_FIRST + 1);
    let progress = runner.progress.lock().unwrap();
    let history = &progress.profiles["h1-get"];
    assert_eq!((history.begun, history.next, history.replays), (0, 0, 0));
}

/// A profile's manifest is staged as its name with `.manifest.tmp` after
/// it. A sweep whose profiles hold a name of 243 bytes is rejected before
/// it claims its root, and a listed history of that length is rejected
/// for its length. A listed history of 242 bytes is bound and its
/// manifest written.
#[test]
fn staged_history_manifest_names_fit_a_directory_entry() {
    let case = Case::new();
    let long = word(&"h".repeat(243));
    let mut swept = plan(&case, 1);
    swept.profiles = vec![word("upload"), long.clone()];
    let rejected = sweep(&swept);
    assert!(
        matches!(&rejected, Err(Error::Rejected(reason)) if reason.contains("242 bytes")),
        "{:?}",
        rejected.as_ref().err()
    );
    assert!(!swept.root.exists());
    let named = |name: &str| {
        let mut listing = with_histories(4);
        listing.profiles[1].name = name.to_owned();
        assert_eq!(listing.profiles[1].class, Class::History);
        listing
    };
    let rejected = histories_of(&named(long.as_str()));
    assert!(
        matches!(&rejected, Err(Error::Rejected(reason)) if reason.contains("242 bytes")),
        "{rejected:?}"
    );
    let fits = "h".repeat(242);
    let listing = named(&fits);
    let histories = histories_of(&listing).unwrap();
    let plan = Plan {
        root: case.root.clone(),
        ..plan(&case, 1)
    };
    std::fs::create_dir(plan.root.join("manifests")).unwrap();
    let (_, manifests) = bound(&plan, &pins('b'), &listing, (&[], &histories), None).unwrap();
    assert_eq!(
        manifests[&fits],
        plan.root.join("manifests").join(format!("{fits}.manifest"))
    );
    assert!(manifests[&fits].exists());
}

/// A `--set` count the sweep's profile accepts and a listed history's
/// held bound refuses rejects the sweep with the history and the count
/// named. A new root is left without `sweep.json` and manifests, and a
/// bound root keeps its checkpoint and manifests as they were.
#[test]
fn an_implicit_historys_bound_refusal_names_it_and_preserves_the_root() {
    let case = Case::new();
    let plan = Plan {
        root: case.root.clone(),
        profiles: vec![word("healthy")],
        counts: [(word("turns"), 64)].into(),
        ..plan(&case, 1)
    };
    std::fs::create_dir(plan.root.join("manifests")).unwrap();
    let mut listing = with_histories(4);
    listing.profiles[0].name = "healthy".into();
    let histories = histories_of(&listing).unwrap();
    let controls = controls_of(&plan.profiles, &listing).unwrap();
    assert!(controls.is_empty());
    let mut larger = listing.clone();
    let history = larger
        .profiles
        .iter_mut()
        .find(|p| p.name == "h1-get")
        .unwrap();
    history
        .held
        .iter_mut()
        .find(|(key, _)| key == "turns")
        .unwrap()
        .1 = 128;
    let check = |stored| {
        let result = bound(&plan, &pins('b'), &larger, (&controls, &histories), stored);
        assert!(
            matches!(result, Err(Error::Rejected(ref text))
            if text.contains("history h1-get:") && text.contains("turns")),
            "{:?}",
            result.err()
        );
    };
    check(None);
    assert!(!plan.root.join("sweep.json").exists());
    assert_eq!(
        std::fs::read_dir(plan.root.join("manifests"))
            .unwrap()
            .count(),
        0
    );
    let (progress, manifests) =
        bound(&plan, &pins('b'), &listing, (&controls, &histories), None).unwrap();
    let checkpoint = std::fs::read(plan.root.join("sweep.json")).unwrap();
    let before: Vec<_> = manifests
        .values()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    check(Some(progress));
    assert_eq!(
        std::fs::read(plan.root.join("sweep.json")).unwrap(),
        checkpoint
    );
    assert_eq!(
        manifests
            .values()
            .map(|path| std::fs::read(path).unwrap())
            .collect::<Vec<_>>(),
        before
    );
}

/// A control's unsuccessful rule earns a catch only beside a complete
/// unsuccessful terminal. A run that prints the same rule and ended at
/// the recorder's cap or inconclusive is counted under that ending, and
/// one that completed a pass that does not count is a suspect of class
/// `control passed`. This holds for a history's witness and for the
/// unsuccessful controls the supervisor names.
#[test]
fn an_incomplete_run_keeps_its_witness_without_earning_control_credit() {
    let listing = with_histories(4);
    let history = Control::history(listing.profile("h1-get-unheld").unwrap()).unwrap();
    for (control, witness) in [
        (history, "old read held"),
        (
            *controls::named("cluster-version-end").unwrap(),
            "a key's version counter reached its end",
        ),
        (
            *controls::named("cluster-late-leak").unwrap(),
            "a healed owner kept the resources of fini",
        ),
        (
            *controls::named("cluster-swarm-leak").unwrap(),
            "a healed owner kept the resources of fini",
        ),
    ] {
        let complete = unsuccessful().replace("fewer exact reads", witness);
        let incomplete = complete
            .replace(
                "complete unsuccessful fired=03 required=03",
                "infrastructure cap",
            )
            .replace("cause: unsuccessful", "cause: infrastructure");
        let inconclusive = complete
            .replace("complete unsuccessful", "complete inconclusive")
            .replace("cause: unsuccessful", "cause: inconclusive")
            .replace("stop: goal", "stop: limit turns");
        let uncounted = complete
            .replace("complete unsuccessful fired=03", "complete pass fired=00")
            .replace("cause: unsuccessful", "cause: uncredited");
        for (code, body, expected) in [
            (1, complete, Ending::Caught),
            (
                3,
                incomplete,
                Ending::Uncredited("inconclusive: recorder cap".into()),
            ),
            (
                1,
                inconclusive,
                Ending::Uncredited("inconclusive: limit turns".into()),
            ),
            (1, uncounted, Ending::Suspect("control passed".into())),
        ] {
            let block = read(&format!("code: {code}\n{body}"), 7).unwrap();
            let original = block.ending(&word("upload"));
            let ending = judged(&control, &block, original.clone());
            assert_eq!(ending, expected, "{}: {body}", control.profile);
            // `shown` yields an unsuccessful rule only beside a complete
            // unsuccessful terminal, so each incomplete run here that
            // prints the witness shows none.
            assert_eq!(
                shown(&original, &block).is_some(),
                expected == Ending::Caught,
                "{}: {body}",
                control.profile
            );
            let mut totals = Totals::default();
            totals.count(0, block.summary(), &ending, 0);
            assert_eq!(totals.caught, u64::from(expected == Ending::Caught));
            assert_eq!(totals.missed, u64::from(expected.missed()));
        }
    }
}

/// A history named among a sweep's profiles that expects no pass binds no
/// root while its listing declares no failure for it: its failing runs
/// would be listed as suspects and its passing runs would raise no alarm.
/// With the failure declared, `bound` writes each history's manifest and
/// sets its `Totals::history` flag.
#[test]
fn a_failing_history_that_declares_no_failure_binds_no_root() {
    let case = Case::new();
    std::fs::create_dir(case.root.join("manifests")).unwrap();
    let plan = Plan {
        root: case.root.clone(),
        profiles: vec![word("upload"), word("h1-get-stale")],
        ..plan(&case, 1)
    };
    let pins = pins('b');
    let refused = bound(&plan, &pins, &with_histories(3), (&[], &[]), None);
    assert!(
        matches!(
            refused.as_ref().err(),
            Some(Error::Rejected(reason)) if reason.contains("history h1-get-stale ")
        ),
        "{:?}",
        refused.as_ref().err()
    );
    assert!(!case.root.join("sweep.json").exists());
    let listing = with_histories(4);
    let histories = histories_of(&listing).unwrap();
    let (progress, manifests) = bound(&plan, &pins, &listing, (&[], &histories), None).unwrap();
    for history in ["h1-get", "h1-get-stale", "h1-get-unheld"] {
        assert_eq!(progress.profiles[history].history, Some(true), "{history}");
        assert!(!progress.profiles[history].control, "{history}");
        assert!(manifests[history].exists(), "{history}");
    }
    assert_eq!(progress.profiles["upload"].history, Some(false));
}

/// Binding restores the listing's failure declarations and preserves the
/// checkpoint's work counts. Status sees the declarations after the save.
#[test]
fn rebinding_a_history_restores_its_declared_failure_for_reach() {
    let case = Case::new();
    let plan = plan(&case, 1);
    std::fs::create_dir_all(plan.root.join("manifests")).unwrap();
    let pins = pins('b');
    let listing = with_histories(4);
    let histories = histories_of(&listing).unwrap();
    let bind = |stored| {
        bound(&plan, &pins, &listing, (&[], &histories), stored)
            .unwrap()
            .0
    };
    let mut progress = bind(None);
    let text = format!("root: 7\ncode: 0\n{COUNTING}end: 7\n");
    let block = block(&mut text.as_bytes(), 7, &listing).unwrap();
    let ending = super::ended(&listing, &word("upload"), &block);
    assert_eq!(ending, Ending::Pass);
    progress
        .profiles
        .get_mut("upload")
        .unwrap()
        .count(0, block.summary(), &ending, 0);
    for history in ["h1-get", "h1-get-stale", "h1-get-unheld"] {
        let ending = super::ended(&listing, &word(history), &block);
        assert_eq!(ending, Ending::Suspect("summary of another profile".into()));
        let totals = progress.profiles.get_mut(history).unwrap();
        totals.count(0, block.summary(), &ending, 0);
        assert_eq!((totals.operations, totals.witnesses), (18, 10));
    }
    let checkpoint = plan.root.join("sweep.json");
    let save = |bytes: Vec<u8>| crate::store::replace_host(&checkpoint, &bytes).unwrap();
    let reported = || status(&plan.root).unwrap().unwrap();
    let share = json!({"refused_actions": 8.0 / 18.0});
    let eligible = json!({"upload": share, "h1-get": share});
    save(serde_json::to_vec(&progress).unwrap());
    assert_eq!(reported()["reach"], eligible);
    let mut legacy = serde_json::to_value(&progress).unwrap();
    for name in ["upload", "h1-get"] {
        assert!(
            !legacy["profiles"][name]
                .as_object()
                .unwrap()
                .contains_key("failing_history")
        );
    }
    let mut before = eligible.clone();
    for name in ["h1-get-stale", "h1-get-unheld"] {
        assert_eq!(
            legacy["profiles"][name]
                .as_object_mut()
                .unwrap()
                .remove("failing_history"),
            Some(json!(true))
        );
        before[name] = share.clone();
    }
    save(serde_json::to_vec(&legacy).unwrap());
    assert_eq!(reported()["reach"], before);
    let rebound = bind(stored(&plan, &pins.build).unwrap());
    assert_eq!(reported()["reach"], before);
    save(serde_json::to_vec(&rebound).unwrap());
    let after = reported();
    assert_eq!(after["reach"], eligible);
    for name in ["upload", "h1-get", "h1-get-stale", "h1-get-unheld"] {
        let totals = &after["profiles"][name];
        assert_eq!(totals["operations"], 18);
        assert_eq!(totals["witnesses"], 10);
    }
}

/// A control batch takes the listed control with the fewest control
/// batches begun in the root's sweeps, the earliest listed among
/// equals, whatever lists those sweeps had. Each sweep here reaches one
/// control batch, and `sweep.json` is stored and read between two.
/// Sweeps of one list take its controls in turn. A sweep whose list
/// gained a control begins that one, sweeps that alternate one list
/// with its reverse alternate its two controls, and sweeps that
/// alternate two lists with no control in common each take their own
/// list in turn.
#[test]
fn a_control_batch_takes_the_control_begun_least_in_the_roots_sweeps() {
    // The control the next sweep of the root begins, for the control
    // list of its profiles.
    fn begun(progress: &mut Progress, controls: &[&'static str]) -> &'static str {
        let listed: Vec<Text> = controls.iter().map(|control| word(control)).collect();
        let taken = progress.next_listed(&listed);
        *progress = serde_json::from_slice(&serde_json::to_vec(progress).unwrap()).unwrap();
        controls[taken]
    }
    let fresh = || Progress {
        build: pins('b').build,
        campaign: word("host"),
        counts: BTreeMap::new(),
        profiles: BTreeMap::new(),
        elapsed_ms: 0,
        rules: Vec::new(),
        batches: 0,
        archive: Closing::Kept,
    };
    let upload = ["planted", "corrupted", "acked", "panicking", "asserting"];
    let mut root = fresh();
    let taken: Vec<_> = (0..6).map(|_| begun(&mut root, &upload)).collect();
    assert_eq!(taken[..5], upload);
    assert_eq!(taken[5], "planted");

    let mut root = fresh();
    assert_eq!(begun(&mut root, &upload), "planted");
    let gained = [
        "long-planted",
        "planted",
        "corrupted",
        "acked",
        "panicking",
        "asserting",
    ];
    assert_eq!(begun(&mut root, &gained), "long-planted");
    assert_eq!(begun(&mut root, &gained), "corrupted");

    let mut root = fresh();
    let (listed, reversed) = (
        ["long-planted", "rekey-stalled"],
        ["rekey-stalled", "long-planted"],
    );
    let taken: Vec<_> = (0..4)
        .map(|sweep| begun(&mut root, if sweep % 2 == 0 { &listed } else { &reversed }))
        .collect();
    assert_eq!(
        taken,
        [
            "long-planted",
            "rekey-stalled",
            "long-planted",
            "rekey-stalled"
        ]
    );

    let mut root = fresh();
    let mut taken = Vec::new();
    for _ in 0..5 {
        taken.push(begun(&mut root, &upload));
        assert_eq!(begun(&mut root, &["long-planted"]), "long-planted");
    }
    assert_eq!(taken, upload);

    // Totals stored without a count read as none begun.
    let mut root: Progress = serde_json::from_slice(&swept(&pins('b'))).unwrap();
    assert_eq!(begun(&mut root, &["upload", "planted"]), "upload");
    assert_eq!(root.profiles["upload"].begun, 1);
}

/// A control batch that sends its worker no root leaves its control the
/// turn: the sweep's time ends here while the control's worker starts,
/// so the batch is begun and runs nothing, and the control has no batch
/// begun in the root's totals.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_control_batch_that_sends_no_root_keeps_its_controls_turn() {
    let _processes = processes();
    let host = Delegation::new("unbegun");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replacen(
        "echo 'sweep: ready'",
        "case \"$2\" in *planted*) sleep 2 ;; esac\necho 'sweep: ready'",
        1,
    );
    let mut frozen = frozen(&plan, &script);
    frozen.controls = vec![word("planted")];
    frozen.manifests.insert(
        "planted".to_owned(),
        plan.root.join("manifests/planted.manifest"),
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    // Batch 0 ran `upload`, and batch 1, a control batch, was begun.
    assert_eq!(frozen.batches.load(Ordering::Relaxed), 2);
    let progress = frozen.progress.lock().unwrap();
    let control = progress
        .profiles
        .get("planted")
        .cloned()
        .unwrap_or_default();
    assert_eq!((control.begun, control.next), (0, 0));
}

/// The sweep's time can also end during a control batch's replay, and
/// then too the batch sends no root and its control keeps the turn. The
/// root's next batch here is a control batch that replays the control's
/// last run, and the replay outlasts the sweep.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_control_batch_stopped_in_its_replay_keeps_its_controls_turn() {
    let _processes = processes();
    let host = Delegation::new("unreplayed");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replacen(
        "printf '%s' \"$summary\"\nexit 0",
        "sleep 2\nprintf '%s' \"$summary\"\nexit 0",
        1,
    );
    let mut frozen = frozen(&plan, &script);
    let upload = "profile: upload class=live support=implemented campaign=unqualified \
                  held=bytes=1,every=1,pending=1,records=1,ring=1,turns=1\n";
    let planted = upload.replace("upload class=live", "planted class=control");
    frozen.listing =
        Listing::parse(&LISTING.replacen(upload, &format!("{upload}{planted}"), 1)).unwrap();
    frozen.controls = vec![word("planted")];
    frozen.manifests.insert(
        "planted".to_owned(),
        plan.root.join("manifests/planted.manifest"),
    );
    frozen.batches = AtomicU64::new(1);
    let ran = Block {
        code: Some(0),
        text: COUNTING.to_owned(),
        run: None,
    };
    frozen
        .last
        .lock()
        .unwrap()
        .insert("planted".to_owned(), (0, 7, ran));
    let deadline = Instant::now() + Duration::from_secs(1);
    frozen.run(&host.root(), Some(deadline), FLUSH).unwrap();
    assert_eq!(frozen.batches.load(Ordering::Relaxed), 2);
    let progress = frozen.progress.lock().unwrap();
    let control = &progress.profiles["planted"];
    assert_eq!((control.begun, control.replays, control.next), (0, 1, 0));
}

/// A control batch whose worker fails the sweep before its first root
/// keeps its control's turn as well: the worker here ends before its
/// ready line.
#[test]
#[ignore = "needs a delegated cgroup-v2 user scope named by CAMPAIGN_CGROUP_ROOT"]
fn a_control_batch_whose_worker_fails_keeps_its_controls_turn() {
    let _processes = processes();
    let host = Delegation::new("unstarted");
    let case = Case::new();
    let mut plan = plan(&case, 1);
    plan.batch = Duration::from_millis(50);
    let script = passing("sleep 0.02").replacen(
        "echo 'sweep: ready'",
        "case \"$2\" in *planted*) exit 3 ;; esac\necho 'sweep: ready'",
        1,
    );
    let mut frozen = frozen(&plan, &script);
    frozen.controls = vec![word("planted")];
    frozen.manifests.insert(
        "planted".to_owned(),
        plan.root.join("manifests/planted.manifest"),
    );
    frozen.batches = AtomicU64::new(1);
    let ran = frozen.run(&host.root(), None, FLUSH);
    assert!(
        matches!(&ran, Err(Error::Held(reason)) if reason.contains("before its ready line")),
        "{ran:?}"
    );
    let progress = frozen.progress.lock().unwrap();
    assert_eq!(progress.profiles["planted"].begun, 0);
}

/// A replay that exits with the code and prints the summary the sweep
/// read agrees. One that exits with another code, prints another
/// summary, or prints output that is no summary differs, and keeps its
/// exit code. One with no exit code is a suspect of the class its
/// worker's end has. A replay that agrees and left a process in its pen
/// is a suspect of class `left a process`; one that differs or has no
/// exit code keeps its class.
#[test]
fn a_replay_differs_by_its_code_or_its_output() {
    let listing = Listing::parse(LISTING).unwrap();
    let counting = summary(&[]);
    let swept = read(&format!("code: 0\n{counting}"), 7).unwrap();
    let compare = |code, printed: &str, left| {
        compared(&swept, 7, code, printed, "wall limit", left, &listing)
    };
    assert!(compare(Some(0), &counting, false).is_none());
    let (class, replayed) = compare(Some(1), &counting, false).unwrap();
    assert_eq!((class, replayed.unwrap().code), ("replay differs", Some(1)));
    let other = summary(&[("turns: 57", "turns: 58")]);
    let (class, replayed) = compare(Some(0), &other, false).unwrap();
    assert_eq!(class, "replay differs");
    assert_eq!(replayed.unwrap().fields()["turns"], "58");
    for unread in ["", "no summary\n", "end: 7\nturns: 57\n"] {
        let (class, replayed) = compare(Some(3), unread, false).unwrap();
        let replayed = replayed.unwrap();
        assert_eq!(
            (class, replayed.code, replayed.text.as_str()),
            ("replay differs", Some(3), ""),
            "{unread:?}"
        );
    }
    let (class, replayed) = compare(None, &counting, false).unwrap();
    assert!(class == "wall limit" && replayed.is_none());
    // A run the worker refused, or whose bundle did not load, prints that
    // line in a sweep and nothing on standard output as a recorded run,
    // so its replay agrees by its code.
    for (code, line) in [(2, "refused: Profile\n"), (3, "load: Truncated\n")] {
        let swept = read(&format!("code: {code}\n{line}"), 7).unwrap();
        let compare = |replayed, printed: &str| {
            compared(
                &swept,
                7,
                Some(replayed),
                printed,
                "wall limit",
                false,
                &listing,
            )
        };
        assert!(compare(code, "").is_none(), "{line}");
        assert!(
            matches!(compare(1, ""), Some(("replay differs", Some(_)))),
            "{line}"
        );
        assert!(
            matches!(compare(code, &counting), Some(("replay differs", Some(_)))),
            "{line}"
        );
    }
    // Output past the summary differs: a repeated field, and lines after
    // a line that closes the block.
    for trailing in ["counts: false\n", "end: 7\nturns: 58\n"] {
        let printed = format!("{counting}{trailing}");
        assert!(
            matches!(
                compare(Some(0), &printed, false),
                Some(("replay differs", Some(_)))
            ),
            "{trailing:?}"
        );
    }
    assert!(matches!(
        compare(Some(0), &counting, true),
        Some(("left a process", None))
    ));
    assert!(matches!(
        compare(Some(1), &counting, true),
        Some(("replay differs", Some(_)))
    ));
    assert!(matches!(
        compare(None, &counting, true),
        Some(("wall limit", None))
    ));
}
