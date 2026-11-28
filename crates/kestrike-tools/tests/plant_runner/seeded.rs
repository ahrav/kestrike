//! Tests of the seed checks on the unpatched head: which confirmed suspect is the catch, which seeds
//! count as failures of the head, and what a catch records.

use std::fs;

use kestrike_tools::json::{self, Value};

use super::fixture::{Fixture, shown, text_of, write_plant};
use super::swept::{digest, exited, same, suspect};

fn archive_of(run: &[String]) -> String {
    super::standins::option(run, "--archive").to_owned()
}

/// `failures` are the run, seed and head result of each of the entry's head failures.
fn failures(entry: &json::Object) -> Vec<(String, String, String)> {
    let Some(Value::Array(failed)) = entry.get("head_failures") else {
        panic!("the entry lists its head failures");
    };
    failed
        .iter()
        .map(|item| {
            let Value::Object(item) = item else {
                panic!("a head failure is an object");
            };
            (
                shown(item.get("run")),
                shown(item.get("seed")),
                text_of(item.get("head").expect("head")),
            )
        })
        .collect()
}

#[test]
fn a_catch_rests_on_a_confirmed_suspect_whose_seed_passes_on_the_head() {
    let mut fx = Fixture::new();
    let shared = fx.scratch.join("shared-target");
    let shared_text = shared.display().to_string();
    let env = [
        ("CARGO_TARGET_DIR", shared_text.as_str()),
        ("CARGO_BUILD_BUILD_DIR", shared_text.as_str()),
    ];
    let done = fx.run(&["p-catch"], &env);
    exited(&done, 0);
    let caught = fx.verdict("p-catch", "caught", "violation: a rule in run 7 of b");
    same(
        caught.get("suspect"),
        r#"{"profile": "b", "run": 7, "seed": 42, "key": "violation: a rule",
            "finding": "finding-0", "head": "counts: complete pass"}"#,
        "suspect",
    );
    same(caught.get("head_failures"), "[]", "head_failures");
    assert_eq!(
        text_of(caught.get("archive").expect("an archive")),
        digest("catch")
    );
    assert_eq!(
        text_of(caught.get("campaign").expect("a campaign")),
        "plant-p-catch"
    );
    same(caught.get("profiles"), r#"["a", "b"]"#, "profiles");
    same(caught.get("counts"), "{}", "counts");
    same(
        caught.get("controls"),
        r#"{"caught": 3, "missed": 0}"#,
        "controls",
    );
    same(
        caught.get("histories"),
        r#"{"caught": 2, "missed": 0}"#,
        "histories",
    );
    let (written, _) = fx.results();
    assert_eq!(text_of(written.get("commit").expect("a commit")), fx.head);
    let Some(Value::Object(runs)) = caught.get("runs") else {
        panic!("the catch holds its runs");
    };
    same(
        runs.get("a"),
        r#"{"runs": 300, "next": 400, "range": [0, 399], "pass": 300, "suspects": 0,
            "replays": 1, "uncredited": {}}"#,
        "runs of a",
    );
    assert!(caught.get("miss_cause").is_none());
    let commit = text_of(caught.get("commit").expect("a planted commit"));
    assert_eq!(
        fx.git(&["rev-parse", &format!("{commit}^")]).trim(),
        fx.head
    );
    assert_eq!(fx.git(&["show", &format!("{commit}:mode")]), "catch\n");
    assert_eq!(
        fx.git(&["rev-parse", &format!("{commit}^{{tree}}")]).trim(),
        text_of(caught.get("tree").expect("a tree"))
    );
    let runs = fx.calls(&["sim", "run"]);
    assert_eq!(runs.len(), 1);
    assert_eq!(
        archive_of(&runs[0]),
        fx.work.join("base").join("archive").display().to_string()
    );
    let places = [
        ("base", fx.work.join("base")),
        ("p-catch", fx.work.join("plants").join("p-catch")),
    ];
    for (name, place) in places {
        let text = fs::read_to_string(place.join("archive").join("env"))
            .expect("the stand-in's archive environment reads");
        let target = json::text(&Value::String(
            place.join("target").display().to_string().into(),
        ));
        same(
            Some(&json::parse(&text).expect("the environment is JSON")),
            &format!(
                r##"{{"CARGO_PROFILE_DEV_OPT_LEVEL": "3", "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS": "true",
                    "CARGO_TARGET_DIR": {target}, "CARGO_BUILD_BUILD_DIR": {target},
                    "lockfile": "# the checkout's resolution\n",
                    "proof": {{"target": false, "tree": false}}}}"##
            ),
            name,
        );
        assert!(!place.join("target").exists(), "{name}");
    }
    assert!(!shared.exists());
    let check = fx.work.join("plants/p-catch/seeds/b/7-42/manifest");
    let manifest = fs::read_to_string(check).expect("the seed check's manifest reads");
    let build = format!("build = {}", digest("base"));
    let lines: Vec<&str> = manifest.split('\n').collect();
    assert_eq!(
        lines,
        [
            "version = 2",
            "profile = b",
            "root = 42",
            "executable = x-base",
            "toolchain = t-base",
            build.as_str(),
            "platform = p-base",
            "turns = 9",
            ""
        ]
    );
    assert!(!fx.hooked.exists());
}

#[test]
fn a_plant_named_base_is_caught_with_its_seed_on_the_unpatched_head() {
    let mut fx = Fixture::new();
    fx.run(&["base"], &[]);
    fx.verdict("base", "caught", "violation: a rule in run 7 of a");
    let runs = fx.calls(&["sim", "run"]);
    assert_eq!(
        archive_of(&runs[0]),
        fx.work.join("base").join("archive").display().to_string()
    );
}

/// A profile name of 242 bytes, the longest `campaign` takes, and a seed of 20 digits leave the seed
/// check a directory to make.
#[test]
fn a_suspect_of_a_profile_with_the_longest_name_is_checked_and_caught() {
    let mut fx = Fixture::new();
    let longest: &'static str = Box::leak("p".repeat(242).into_boxed_str());
    let expected: &'static [&'static str] = Box::leak(vec![longest].into_boxed_slice());
    write_plant(
        &fx.store,
        "p-longest",
        ("longest", expected, "null", "base"),
        &[],
        None,
    );
    fx.commit("the longest profile name");
    let done = fx.run(&["p-longest"], &[]);
    exited(&done, 0);
    let record = fx.verdict(
        "p-longest",
        "caught",
        &format!("violation: a rule in run 7 of {longest}"),
    );
    assert_eq!(suspect(&record, "seed"), u64::MAX.to_string());
}

#[test]
fn a_catch_stands_when_a_later_seed_check_fails() {
    let mut fx = Fixture::new();
    fx.run(&["p-catchbroken"], &[]);
    let caught = fx.verdict("p-catchbroken", "caught", "violation: a rule in run 7 of a");
    assert_eq!(suspect(&caught, "seed"), "42");
}

#[test]
fn a_seed_check_that_prints_no_result_ran_nothing_on_the_head() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-noresult"], &[]);
    exited(&done, 3);
    let failed = fx.verdict(
        "p-noresult",
        "no verdict",
        "the seed check of violation: a rule in run 7 of a did not run: exit 4 with no result",
    );
    assert!(failures(&failed).is_empty());
}

#[test]
fn a_seed_check_that_exits_0_with_another_class_than_counts_is_no_pass_on_the_head() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-oddpass"], &[]);
    exited(&done, 3);
    let failed = fx.verdict(
        "p-oddpass",
        "no verdict",
        "the seed check of violation: a rule in run 7 of a did not run: exit 0 with the class complete",
    );
    assert!(failures(&failed).is_empty());
}

#[test]
fn the_first_suspect_whose_seed_passes_on_the_head_is_the_catch() {
    let mut fx = Fixture::new();
    fx.run(&["p-twopass"], &[]);
    let caught = fx.verdict("p-twopass", "caught", "violation: a rule in run 7 of a");
    assert_eq!(
        (suspect(&caught, "seed"), suspect(&caught, "finding")),
        ("42".to_owned(), "\"finding-0\"".to_owned())
    );
    assert_eq!(fx.calls(&["sim", "run"]).len(), 2);
}

#[test]
fn a_catch_lists_each_confirmed_seed_that_fails_on_the_head_in_either_order() {
    let mut fx = Fixture::new();
    fx.run(&["p-second", "p-passthenfail"], &[]);
    for (name, failing) in [("p-second", "7"), ("p-passthenfail", "8")] {
        let caught = fx.verdict(name, "caught", "violation: a rule in run");
        assert_eq!(suspect(&caught, "seed"), "42", "{name}");
        assert_eq!(
            failures(&caught),
            [(
                failing.to_owned(),
                "666".to_owned(),
                "incomplete: the run panicked".to_owned()
            )],
            "{name}"
        );
    }
    assert_eq!(fx.calls(&["sim", "run"]).len(), 4);
}

#[test]
fn a_suspect_listed_twice_is_checked_once() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-dup"], &[]);
    exited(&done, 3);
    let plant = fx.verdict(
        "p-dup",
        "no verdict",
        "does not pass on the unpatched head: incomplete",
    );
    assert_eq!(failures(&plant).len(), 1);
    assert_eq!(fx.calls(&["sim", "run"]).len(), 1);
}

#[test]
fn a_seed_that_completes_with_a_failure_on_the_head_leaves_no_verdict() {
    let mut fx = Fixture::new();
    fx.run(&["p-lonehead"], &[]);
    fx.verdict(
        "p-lonehead",
        "no verdict",
        "does not pass on the unpatched head: complete: a rule failed",
    );
}

#[test]
fn a_seed_that_ends_in_a_violation_on_the_head_leaves_the_next_suspect_to_catch() {
    let mut fx = Fixture::new();
    fx.run(&["p-violatehead"], &[]);
    let caught = fx.verdict("p-violatehead", "caught", "run 8 of a");
    assert_eq!(
        failures(&caught),
        [(
            "7".to_owned(),
            "665".to_owned(),
            "complete: a rule failed".to_owned()
        )]
    );
    assert_eq!(fx.calls(&["sim", "run"]).len(), 2);
}

#[test]
fn a_refused_seed_check_leaves_the_next_suspect_to_catch() {
    let mut fx = Fixture::new();
    fx.run(&["p-oddthen"], &[]);
    fx.verdict("p-oddthen", "caught", "run 8 of a");
}

#[test]
fn a_refused_seed_check_is_no_failure_of_the_head() {
    let mut fx = Fixture::new();
    fx.run(&["p-rejectseed"], &[]);
    let plant = fx.verdict(
        "p-rejectseed",
        "no verdict",
        "seed check of violation: a rule in run 7 of a on the unpatched head exited 2 (rejected: the \
         manifest names another build)",
    );
    assert!(failures(&plant).is_empty());
}

#[test]
fn a_seed_check_runs_only_the_job_confirm_ran() {
    let mut fx = Fixture::new();
    fx.run(&["p-othermanifest"], &[]);
    fx.verdict(
        "p-othermanifest",
        "no verdict",
        "did not run: its manifest differs from the job `confirm` ran",
    );
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

#[test]
fn a_seed_check_that_fails_leaves_another_suspect_s_catch_in_either_order() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-gapfirst", "p-gaplast"], &[]);
    exited(&done, 0);
    for name in ["p-gapfirst", "p-gaplast"] {
        let caught = fx.verdict(name, "caught", "violation: a rule in run");
        assert_eq!(suspect(&caught, "profile"), "\"a\"", "{name}");
    }
}

/// When `git worktree add` exits 128 for the unpatched head, `p-catch` reports `no verdict` with the
/// reason `` `git worktree` exited 128 ``, and Git's error stays in `base/git.err`.
#[test]
fn a_failed_worktree_of_the_unpatched_head_fails_its_seed_checks_and_keeps_its_error() {
    let mut fx = Fixture::new();
    let (name, path) = fx.git_shim(
        "add",
        "case \"$*\" in */base/tree*) echo 'fatal: no base' >&2; exit 128;; esac",
    );
    let done = fx.run(&["p-catch"], &[(name, path.as_str())]);
    exited(&done, 3);
    fx.verdict(
        "p-catch",
        "no verdict",
        "the seed check of violation: a rule in run 7 of b did not run: the unpatched head's worktree: \
         `git worktree` exited 128; its error is in base/git.err",
    );
    let kept = fs::read_to_string(fx.work.join("base/git.err")).expect("the error is kept");
    assert_eq!(kept, "git worktree exited 128:\nfatal: no base\n");
    assert!(fx.calls(&["sim", "run"]).is_empty());
}

/// The first base worktree add writes byte 0xFF to stderr and exits 0 before creating the worktree;
/// the next seed check retries the add and runs `sim run` once.
#[test]
fn a_base_worktree_add_that_prints_no_text_is_tried_again_at_the_next_seed_check() {
    let mut fx = Fixture::new();
    let (once, adds) = (fx.scratch.join("once"), fx.scratch.join("adds"));
    let action = format!(
        "case \"$*\" in */base/tree*) echo add >> '{}'; if [ ! -e '{}' ]; then touch '{}'; \
         printf '\\377' >&2; exit 0; fi;; esac",
        adds.display(),
        once.display(),
        once.display()
    );
    let (name, path) = fx.git_shim("add", &action);
    let done = fx.run(&["p-twopass"], &[(name, path.as_str())]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_eq!(
        fs::read_to_string(&adds).expect("the adds are logged"),
        "add\nadd\n"
    );
    fx.verdict("p-twopass", "caught", "violation: a rule in run");
    assert_eq!(fx.calls(&["sim", "run"]).len(), 1);
}

/// A base archive whose kept `Cargo.lock` cannot be read gives the first seed check `did not run:` with
/// the path and the system's text, and the next seed check prepares the base again. That attempt adds
/// the worktree at the path the first attempt filled, so Git refuses it, the refusal is kept in
/// `base/git.err`, and no second base archive builds.
#[test]
fn an_unreadable_base_lockfile_is_tried_again_and_the_retry_meets_the_first_worktree() {
    if super::repository::is_root() {
        return;
    }
    let mut fx = Fixture::new();
    let done = fx.run(&["p-twopass"], &[("STANDIN_BASE_LOCK_UNREADABLE", "1")]);
    exited(&done, 3);
    fx.verdict(
        "p-twopass",
        "no verdict",
        "the seed check of violation: a rule in run 7 of a did not run: \
         <work>/base/archive/Cargo.lock: Permission denied (os error 13)",
    );
    let kept = fs::read_to_string(fx.work.join("base/git.err")).expect("the retry's error is kept");
    assert!(kept.starts_with("git worktree exited 128:\n"), "{kept}");
    assert!(kept.contains("already exists"), "{kept}");
    assert_eq!(fx.calls(&["sim", "archive"]).len(), 2);
    assert!(fx.calls(&["sim", "run"]).is_empty());
}
