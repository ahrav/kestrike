//! The cases of steps 1 and 2: the check that a patch applies, the proof's reruns on the head and on
//! the plant, the proof's worktree, its lockfile and its helper, and how each ending of a rerun settles
//! its plant and the later ones.

use super::fixture::{CAUSE, Fixture, patch_of, shown, text_of, write_plant};

const OTHER_PROOF: [(&str, &str); 1] = [("proof", "\"b::test\"")];

/// `other_proof` writes `p-otherproof`, whose proof is `b::test`, and commits it.
fn other_proof(fx: &mut Fixture) {
    write_plant(
        &fx.store,
        "p-otherproof",
        ("otherproof", &["a"], CAUSE, "base"),
        &OTHER_PROOF,
        None,
    );
    fx.commit("another proof");
}

fn sentence(fx: &Fixture) -> String {
    let (written, _) = fx.results();
    text_of(written.get("sentence").expect("a sentence"))
}

/// A plant whose proof passes on the plant is not live, gets no archive, and stays out of `n`; each
/// rerun runs in the proof's worktree with its target, the run's lockfile and a session of its own.
#[test]
fn a_plant_whose_proof_passes_on_the_plant_is_not_live_and_leaves_n() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss", "p-notlive"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    let (written, plants) = fx.results();
    assert_eq!(
        sentence(&fx),
        format!("0 of 1 plants at commit {}", fx.head)
    );
    assert_eq!(
        shown(written.get("results")),
        r#"{"missed":1,"not live":1}"#
    );
    assert_eq!(shown(written.get("not_live")), r#"["p-notlive"]"#);
    let record = fx.verdict(
        "p-notlive",
        "not live",
        "its proof exits 0 on the head and 0 on the plant",
    );
    assert_eq!(shown(record.get("proof_exits")), r#"{"head":0,"plant":0}"#);
    assert_eq!(shown(record.get("archive")), "null");
    assert_eq!(
        shown(plants["p-miss"].get("proof_exits")),
        r#"{"head":0,"plant":1}"#
    );
    assert_eq!(fx.calls(&["sim", "archive"]).len(), 1);
    assert_eq!(fx.proof_modes(), ["base", "pass", "notlive"]);
    let place = fx.work.join("proof");
    let (tree, target) = (place.join("tree"), place.join("target"));
    for proof in fx.proof_log() {
        let texts: Vec<String> = proof.iter().map(text_of).collect();
        assert_eq!(
            texts[1..4],
            [
                tree.display().to_string(),
                target.display().to_string(),
                target.display().to_string()
            ]
        );
        assert_eq!(
            texts[4..6],
            [
                "# the checkout's resolution\n".to_owned(),
                "true".to_owned()
            ]
        );
        assert_eq!(
            texts[6..14],
            [
                "--package",
                "kestrike",
                "--target",
                "lib",
                "--attempts",
                "1",
                "--test",
                "a::test"
            ]
        );
    }
    assert!(!target.exists());
}

fn pairs(fx: &Fixture) -> Vec<(String, String)> {
    let mut planted: Vec<(String, String)> = fx
        .proof_log()
        .iter()
        .map(|record| record.iter().map(text_of).collect::<Vec<String>>())
        .filter(|texts| texts[0] != "base")
        .map(|texts| {
            let at = texts
                .iter()
                .position(|text| text == "--test")
                .expect("--test");
            (texts[0].clone(), texts[at + 1].clone())
        })
        .collect();
    planted.sort();
    planted
}

/// Each plant's proof reruns on the head under its own test id, once a proof.
#[test]
fn each_plant_is_judged_by_its_own_proof_on_the_head() {
    let mut fx = Fixture::new();
    other_proof(&mut fx);
    let done = fx.run(
        &["p-miss", "p-otherproof", "p-catch"],
        &[("STANDIN_HEAD_PROOFS", r#"{"b::test": 1}"#)],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-otherproof",
        "not live",
        "its proof exits 1 on the head and 1 on the plant",
    );
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    let mut heads = fx.proof_tests(|mode| mode == "base");
    heads.sort();
    assert_eq!(heads, ["a::test", "b::test"]);
    let want = [
        ("catch", "a::test"),
        ("otherproof", "b::test"),
        ("pass", "a::test"),
    ]
    .map(|(mode, test)| (mode.to_owned(), test.to_owned()));
    assert_eq!(pairs(&fx), want);
}

/// A proof that fails on the head makes its plant not live, with no archive.
#[test]
fn a_plant_whose_proof_fails_on_the_head_is_not_live() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss"], &[("STANDIN_HEAD_PROOFS", r#"{"a::test": 1}"#)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "not live",
        "its proof exits 1 on the head and 1 on the plant",
    );
    assert!(fx.calls(&["sim", "archive"]).is_empty());
}

/// A head whose library tests do not build fails every proof not yet rerun from that one rerun.
#[test]
fn a_head_whose_library_tests_do_not_build_fails_every_proof_from_one_rerun() {
    let mut fx = Fixture::new();
    other_proof(&mut fx);
    let done = fx.run(
        &["p-miss", "p-otherproof", "p-catch"],
        &[("STANDIN_HEAD_PROOFS", r#"{"a::test": 3}"#)],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    for name in ["p-miss", "p-otherproof", "p-catch"] {
        fx.verdict(
            name,
            "no verdict",
            "the head's library tests do not build, so no proof reruns on the head: the rerun of the proof \
             a::test exited 3; its verdict is in proof/head-0.out and its build output under \
             proof/artifacts/head-0",
        );
    }
    assert_eq!(fx.proof_modes(), ["base"]);
    assert!(!fx.work.join("proof/head-1.out").exists());
    assert!(fx.calls(&["sim", "archive"]).is_empty());
}

/// A head build failure at a later proof leaves the earlier proof's plant judged.
#[test]
fn a_head_build_failure_at_a_later_proof_leaves_the_earlier_proof_s_plant_judged() {
    let mut fx = Fixture::new();
    other_proof(&mut fx);
    let done = fx.run(
        &["p-miss", "p-otherproof"],
        &[("STANDIN_HEAD_PROOFS", r#"{"b::test": 3}"#)],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    let record = fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    assert_eq!(shown(record.get("proof_exits")), r#"{"head":0,"plant":1}"#);
    fx.verdict(
        "p-otherproof",
        "no verdict",
        "the rerun of the proof b::test exited 3; its verdict is in proof/head-1.out",
    );
}

/// A plant rerun that fails to run leaves that plant no verdict and resets the tree for the next.
#[test]
fn a_proof_rerun_that_fails_to_run_on_a_plant_leaves_that_plant_no_verdict_and_resets_the_tree() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-brokenproof", "p-miss"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    let broken = fx.verdict(
        "p-brokenproof",
        "no verdict",
        "the rerun of the proof a::test exited 3; its verdict is in proof/plant-p-brokenproof.out and its \
         build output under proof/artifacts/plant-p-brokenproof",
    );
    assert_eq!(shown(broken.get("archive")), "null");
    let record = fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    assert_eq!(shown(record.get("proof_exits")), r#"{"head":0,"plant":1}"#);
    assert_eq!(fx.calls(&["sim", "archive"]).len(), 1);
    assert_eq!(fx.proof_modes(), ["base", "brokenproof", "pass"]);
}

/// A proof that fails on the head and passes on the plant is not live.
#[test]
fn a_plant_whose_proof_fails_on_the_head_and_passes_on_the_plant_is_not_live() {
    let mut fx = Fixture::new();
    let done = fx.run(
        &["p-notlive"],
        &[("STANDIN_HEAD_PROOFS", r#"{"a::test": 1}"#)],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    let record = fx.verdict(
        "p-notlive",
        "not live",
        "its proof exits 1 on the head and 0 on the plant",
    );
    assert_eq!(shown(record.get("proof_exits")), r#"{"head":1,"plant":0}"#);
    assert_eq!(
        sentence(&fx),
        format!("0 of 0 plants at commit {}", fx.head)
    );
    assert!(fx.calls(&["sim", "archive"]).is_empty());
}

fn not_live_list(fx: &Fixture) -> String {
    let (written, _) = fx.results();
    shown(written.get("not_live"))
}

/// A plant rerun that exits 0 or 1 without that exit's verdict line leaves its plant no verdict.
#[test]
fn a_plant_rerun_that_exits_0_or_1_without_that_exit_s_verdict_line_leaves_no_verdict() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss", "p-silentfail", "p-silentpass"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-silentfail",
        "no verdict",
        "the rerun of the proof a::test exited 1 without the verdict `reproduced`; its output is in \
         proof/plant-p-silentfail.out",
    );
    fx.verdict(
        "p-silentpass",
        "no verdict",
        "the rerun of the proof a::test exited 0 without the verdict `not reproduced`; its output is in \
         proof/plant-p-silentpass.out",
    );
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    assert_eq!(not_live_list(&fx), "[]");
    assert_eq!(fx.calls(&["sim", "archive"]).len(), 1);
}

/// A head rerun that exits 0 or 1 without that exit's verdict line leaves its plants no verdict.
#[test]
fn a_head_rerun_that_exits_0_or_1_without_that_exit_s_verdict_line_leaves_no_verdict() {
    let mut fx = Fixture::new();
    other_proof(&mut fx);
    let env = [
        ("STANDIN_HEAD_PROOFS", r#"{"a::test": 1}"#),
        ("STANDIN_SILENT_PROOFS", r#"["a::test", "b::test"]"#),
    ];
    let done = fx.run(&["p-miss", "p-otherproof"], &env);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "the rerun of the proof a::test exited 1 without the verdict `reproduced`; its output is in \
         proof/head-0.out",
    );
    fx.verdict(
        "p-otherproof",
        "no verdict",
        "the rerun of the proof b::test exited 0 without the verdict `not reproduced`; its output is in \
         proof/head-1.out",
    );
    assert_eq!(not_live_list(&fx), "[]");
    assert!(fx.calls(&["sim", "archive"]).is_empty());
}

/// A plant that patches the helper is judged by the head's staged copy, which its patch leaves alone.
#[test]
fn a_plant_that_patches_the_proof_helper_is_judged_by_the_head_s_helper() {
    let mut fx = Fixture::new();
    let forced = "--- a/scripts/reproduce-test.py\n+++ b/scripts/reproduce-test.py\n@@ -1,2 +1,5 @@\n \
                  #!/usr/bin/env python3\n+import sys\n+print(\"reproduced: reproduced on attempt 1\")\n\
                  +sys.exit(1)\n import json, os, signal, sys, time\n";
    write_plant(
        &fx.store,
        "p-judge",
        ("base", &["a"], CAUSE, "base"),
        &[("files", "[\"scripts/reproduce-test.py\"]")],
        Some(forced),
    );
    fx.commit("a plant that patches the helper");
    let done = fx.run(&["p-judge"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-judge",
        "not live",
        "its proof exits 0 on the head and 0 on the plant",
    );
    assert_eq!(fx.proof_modes(), ["base", "base"]);
    assert!(fx.calls(&["sim", "archive"]).is_empty());
    let staged = fx
        .work
        .join("proof/scripts/reproduce-test.py")
        .display()
        .to_string();
    let helpers =
        std::fs::read_to_string(fx.scratch.join("helpers")).expect("the helpers are logged");
    let wanted: Vec<String> = ["question", "rerun", "question", "rerun", "question"]
        .iter()
        .map(|role| format!("{role} {staged}"))
        .collect();
    assert_eq!(helpers.lines().collect::<Vec<_>>(), wanted);
}

/// A head without the selector leaves every plant no verdict before any rerun.
#[test]
fn a_head_without_the_proof_helper_leaves_no_verdict() {
    let mut fx = Fixture::new();
    fx.git(&["rm", "--quiet", "scripts/select-tests.py"]);
    fx.commit("a head without the selector");
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "the head's scripts/select-tests.py cannot be copied: No such file",
    );
    assert!(fx.proof_log().is_empty());
}

/// A head whose selector is a link to a named pipe gives every plant no verdict: the copy opens the
/// pipe without waiting for a writer and refuses it on the opened file.
#[test]
fn a_head_whose_helper_links_to_a_named_pipe_leaves_no_verdict() {
    let mut fx = Fixture::new();
    let pipe = fx.scratch.join("pipe");
    let made = std::process::Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo starts");
    assert!(made.success());
    let selector = fx.repo.join("scripts/select-tests.py");
    std::fs::remove_file(&selector).expect("removed");
    std::os::unix::fs::symlink(&pipe, &selector).expect("linked");
    fx.commit("a selector that links to a pipe");
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "the head's scripts/select-tests.py cannot be copied:",
    );
    let (_, plants) = fx.results();
    let reason = super::fixture::text_of(plants["p-miss"].get("reason").expect("a reason"));
    assert!(reason.ends_with("is a named pipe"), "{reason}");
    assert!(fx.proof_log().is_empty());
}

/// `side_plant` writes `p-side`, whose patch adds the file `side`, and commits it.
fn side_plant(fx: &mut Fixture) {
    let side = "--- /dev/null\n+++ b/side\n@@ -0,0 +1 @@\n+planted\n";
    write_plant(
        &fx.store,
        "p-side",
        ("base", &["a"], CAUSE, "base"),
        &[("files", "[\"side\"]")],
        Some(side),
    );
    fx.commit("a plant on another file");
}

/// A reset that fails keeps the plant in the proof's worktree, so no later plant is judged there.
#[test]
fn a_proof_worktree_that_keeps_a_plant_after_a_failed_reset_judges_no_later_plant() {
    let mut fx = Fixture::new();
    side_plant(&mut fx);
    let marker = fx.scratch.join("fail-reset");
    std::fs::write(&marker, "").expect("the marker is written");
    let once = format!(
        "if [ -e {0} ]; then rm {0}; echo \"the index is locked\" >&2; exit 128; fi",
        marker.display()
    );
    let (name, path) = fx.git_shim("reset", &once);
    let done = fx.run(&["p-miss", "p-side"], &[(name, &path)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    assert!(!marker.exists());
    fx.verdict(
        "p-miss",
        "no verdict",
        "`git reset` exited 128; its error is in plants/p-miss/git.err",
    );
    fx.verdict(
        "p-side",
        "no verdict",
        "the proof's worktree is no longer the head's tree: `git reset` exited 128 at the plant p-miss",
    );
    assert_eq!(fx.proof_modes(), ["base", "pass"]);
    assert!(fx.calls(&["sim", "archive"]).is_empty());
}

/// A proof or a profile that no process takes as an argument refuses the run before any worktree and
/// leaves the checkout as it was.
#[test]
fn a_proof_or_profile_that_no_process_takes_as_an_argument_is_rejected_before_any_worktree() {
    let mut fx = Fixture::new();
    let cases = [
        (
            ("proof", r#""a::\u0000test""#),
            "proof holds no NUL and is UTF-8 text",
        ),
        (
            ("proof", r#""a::\udcfftest""#),
            "proof holds no NUL and is UTF-8 text",
        ),
        (
            ("expected", r#"["a\u0000b"]"#),
            "expected is a list of profile names campaign can take",
        ),
        (
            ("expected", r#"["a\udcff"]"#),
            "expected is a list of profile names campaign can take",
        ),
    ];
    let head = fx.head.clone();
    for (field, rule) in cases {
        write_plant(
            &fx.store,
            "p-bad",
            ("pass", &["a"], CAUSE, "base"),
            &[field],
            None,
        );
        fx.commit("a record no process takes");
        let before = fx.state();
        let done = fx.run(&["p-miss"], &[]);
        assert_eq!(done.code, 2, "{}", done.stderr);
        assert!(
            done.stderr.contains(&format!("p-bad: {rule}")),
            "{}",
            done.stderr
        );
        assert!(!fx.work.exists());
        assert!(fx.proof_log().is_empty());
        assert_eq!(fx.state(), before, "{field:?}");
        fx.git(&["reset", "--hard", "--quiet", &head]);
    }
}

/// A head rerun that prints no UTF-8 text leaves only its own proof with no verdict.
#[test]
fn a_head_rerun_that_prints_no_text_leaves_only_its_own_proof_with_no_verdict() {
    let mut fx = Fixture::new();
    write_plant(
        &fx.store,
        "p-bproof",
        ("otherproof", &["a"], CAUSE, "base"),
        &OTHER_PROOF,
        None,
    );
    write_plant(
        &fx.store,
        "p-third",
        ("pass", &["a"], CAUSE, "base"),
        &[("proof", "\"c::test\"")],
        None,
    );
    fx.commit("three proofs");
    let done = fx.run(
        &["p-miss", "p-bproof", "p-third"],
        &[("STANDIN_BINARY_PROOFS", r#"["b::test"]"#)],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-bproof",
        "no verdict",
        "`reproduce-test.py` exited 0 and printed no UTF-8 text",
    );
    fx.verdict(
        "p-bproof",
        "no verdict",
        "its output is in proof/head-0.out",
    );
    for name in ["p-miss", "p-third"] {
        let record = fx.verdict(name, "missed", "each expected profile reached 300 runs");
        assert_eq!(shown(record.get("proof_exits")), r#"{"head":0,"plant":1}"#);
    }
    assert_eq!(
        fx.proof_tests(|mode| mode == "base"),
        ["b::test", "a::test", "c::test"]
    );
}

/// A rerun that rewrites the run's lockfile leaves that plant and each later one no verdict.
#[test]
fn a_rerun_that_rewrites_the_run_s_lockfile_leaves_that_plant_and_each_later_one_no_verdict() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss", "p-relock", "p-slow"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    for name in ["p-relock", "p-slow"] {
        fx.verdict(
            name,
            "no verdict",
            "the rerun of the proof a::test left the proof's worktree without the run's Cargo.lock; its \
             output is in proof/plant-p-relock.out",
        );
    }
    assert_eq!(fx.proof_modes(), ["base", "pass", "relock"]);
    assert_eq!(not_live_list(&fx), "[]");
    assert_eq!(fx.calls(&["sim", "archive"]).len(), 1);
}

/// A head rerun that rewrites the run's lockfile ends the head's reruns.
#[test]
fn a_head_rerun_that_rewrites_the_run_s_lockfile_ends_the_head_s_reruns() {
    let mut fx = Fixture::new();
    other_proof(&mut fx);
    let done = fx.run(&["p-miss", "p-otherproof"], &[("STANDIN_RELOCK_HEAD", "1")]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    for name in ["p-miss", "p-otherproof"] {
        fx.verdict(
            name,
            "no verdict",
            "the rerun of the proof a::test left the proof's worktree without the run's Cargo.lock; its \
             output is in proof/head-0.out",
        );
    }
    assert_eq!(fx.proof_modes(), ["base"]);
}

/// A rerun that removes the run's lockfile leaves its plant no verdict.
#[test]
fn a_rerun_that_removes_the_run_s_lockfile_leaves_no_verdict() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-unlock"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-unlock",
        "no verdict",
        "left the proof's worktree without the run's Cargo.lock; its output is in proof/plant-p-unlock.out",
    );
    assert!(fx.calls(&["sim", "archive"]).is_empty());
}

/// The proof reruns resolve from the tree's lockfile whatever lockfile path the caller sets.
#[test]
fn the_proof_reruns_pin_the_tree_s_lockfile_over_the_caller_s_path() {
    let mut fx = Fixture::new();
    let elsewhere = fx.scratch.join("elsewhere.lock").display().to_string();
    let done = fx.run(&["p-miss"], &[("CARGO_RESOLVER_LOCKFILE_PATH", &elsewhere)]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    assert_eq!(fx.proof_log().len(), 2);
    let seen = std::fs::read_to_string(fx.scratch.join("lockfile-path"))
        .expect("the rerun saw a lockfile path");
    assert_eq!(
        seen,
        fx.work.join("proof/tree/Cargo.lock").display().to_string()
    );
}

fn rewrite(fx: &Fixture, text: &str) -> String {
    let checkout = fx.store.join("p-miss/plant.patch");
    format!(
        "[{}, {}]",
        super::fixture::json_text(&checkout.display().to_string()),
        super::fixture::json_text(text)
    )
}

/// The proof and the archive apply the patch bytes the head holds, read at the start, when the
/// checkout's copy changes during the run.
#[test]
fn the_proof_and_the_archive_apply_the_head_s_copy_of_the_patch() {
    let mut fx = Fixture::new();
    let checkout = fx.store.join("p-miss/plant.patch");
    let pair = rewrite(&fx, &patch_of("catch", "base"));
    let done = fx.run(&["p-miss"], &[("STANDIN_REWRITE", &pair)]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_eq!(
        std::fs::read_to_string(&checkout).expect("reads"),
        patch_of("catch", "base")
    );
    let record = fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    let commit = text_of(record.get("commit").expect("a commit"));
    assert_eq!(fx.git(&["show", &format!("{commit}:mode")]), "pass\n");
    let archived =
        std::fs::read_to_string(fx.work.join("plants/p-miss/archive/mode")).expect("reads");
    assert_eq!(archived, "pass");
    assert_eq!(fx.proof_modes(), ["base", "pass"]);
}

/// The head reruns only the proofs of plants whose patch applies.
#[test]
fn the_head_reruns_only_the_proofs_of_plants_whose_patch_applies() {
    let mut fx = Fixture::new();
    write_plant(
        &fx.store,
        "p-stale-own",
        ("pass", &["a"], CAUSE, "other"),
        &[("proof", "\"z::test\"")],
        None,
    );
    fx.commit("a stale plant with a proof of its own");
    let done = fx.run(&["p-stale-own", "p-miss"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict("p-stale-own", "does not apply", "patch failed");
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    assert_eq!(fx.proof_tests(|_| true), ["a::test", "a::test"]);
    assert!(!fx.work.join("proof/head-1.out").exists());
}

/// A run where no patch applies reruns no proof and makes no proof's place.
#[test]
fn a_run_where_no_patch_applies_reruns_no_proof() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-stale"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict("p-stale", "does not apply", "patch failed");
    assert!(fx.proof_log().is_empty());
    assert!(!fx.work.join("proof").exists());
}

/// A proof setup that fails is kept, and every plant reports its first cause; the proof's worktree is
/// added once and removed.
#[test]
fn a_failed_proof_setup_is_kept_and_every_plant_reports_its_first_cause() {
    let mut fx = Fixture::new();
    std::fs::write(fx.repo.join(".gitignore"), "").expect("written");
    fx.git(&["add", "--force", "Cargo.lock"]);
    fx.commit("a head that tracks its Cargo.lock");
    let added = fx.scratch.join("added");
    let (name, path) = fx.git_shim("add", &format!("echo \"$*\" >> {}", added.display()));
    let done = fx.run(&["p-miss", "p-catch"], &[(name, &path)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    for name in ["p-miss", "p-catch"] {
        fx.verdict(
            name,
            "no verdict",
            "the proof's worktree already holds a Cargo.lock",
        );
    }
    let proof_tree = fx.work.join("proof/tree").display().to_string();
    let lines = std::fs::read_to_string(&added).expect("the adds are logged");
    let adds = lines
        .lines()
        .filter(|line| line.split_whitespace().any(|word| word == proof_tree))
        .count();
    assert_eq!(adds, 1);
    assert!(fx.proof_log().is_empty());
    assert!(!fx.work.join("proof/tree").exists());
}

/// A reset that fails with output that is no UTF-8 judges no later plant; its reason is the tool's
/// words for that output.
#[test]
fn a_reset_that_fails_with_undecodable_output_judges_no_later_plant() {
    let mut fx = Fixture::new();
    side_plant(&mut fx);
    let marker = fx.scratch.join("fail-reset");
    std::fs::write(&marker, "").expect("the marker is written");
    let once = format!(
        "if [ -e {0} ]; then rm {0}; printf '\\377\\376\\n' >&2; exit 1; fi",
        marker.display()
    );
    let (name, path) = fx.git_shim("reset", &once);
    let done = fx.run(&["p-miss", "p-side"], &[(name, &path)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "the run failed: `git reset` wrote output that is no UTF-8",
    );
    fx.verdict(
        "p-side",
        "no verdict",
        "the proof's worktree is no longer the head's tree",
    );
    assert_eq!(fx.proof_modes(), ["base", "pass"]);
    assert!(fx.calls(&["sim", "archive"]).is_empty());
}

/// An apply check that fails itself leaves no verdict, and a patch Git refuses does not apply.
#[test]
fn an_apply_check_that_fails_itself_leaves_no_verdict_and_a_refused_patch_does_not_apply() {
    let mut fx = Fixture::new();
    let (name, path) = fx.git_shim("--check", "echo 'fatal: a broken check' >&2; exit 128");
    let done = fx.run(&["p-miss", "p-stale"], &[(name, &path)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    for name in ["p-miss", "p-stale"] {
        fx.verdict(name, "no verdict", "`git apply` exited 128");
    }
    assert!(fx.proof_log().is_empty());
    let again = fx.scratch.join("work-2");
    let done = fx.run_in(&["p-stale"], &[], &[], Some(&again));
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict("p-stale", "does not apply", "patch failed");
}

/// An apply check that exits 1 reads as a patch that does not apply, whatever made Git exit 1: the
/// tool takes the first line of Git's error output as the reason and judges the plant no further.
#[test]
fn an_apply_check_that_exits_1_for_any_cause_reads_as_a_patch_that_does_not_apply() {
    let mut fx = Fixture::new();
    let (name, path) = fx.git_shim("--check", "echo 'error: the index is locked' >&2; exit 1");
    let done = fx.run(&["p-miss"], &[(name, &path)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict("p-miss", "does not apply", "error: the index is locked");
    assert!(fx.proof_log().is_empty());
}

/// An ignored file in the store refuses the run.
#[test]
fn an_ignored_file_in_the_store_is_rejected() {
    let mut fx = Fixture::new();
    std::fs::create_dir_all(fx.repo.join(".git/info")).expect("made");
    std::fs::write(fx.repo.join(".git/info/exclude"), "extra.txt\n").expect("written");
    std::fs::write(fx.store.join("p-miss/extra.txt"), "ignored\n").expect("written");
    let done = fx.run(&["p-miss"], &[]);
    fx.rejected(
        &done,
        "differs from HEAD at verification/plants/p-miss/extra.txt",
    );
}

/// The verdict check is the head's staged helper's own: a head that words its verdicts its own way is
/// judged by those words, and a head whose helper defines no `reported` gives every plant no verdict.
#[test]
fn the_verdict_check_comes_from_the_head_s_staged_helper() {
    let mut fx = Fixture::new();
    let helper = fx.repo.join("scripts/reproduce-test.py");
    let text = std::fs::read_to_string(&helper).expect("reads");
    let worded = text.replace(
        r#"0: "not reproduced", 1: "reproduced""#,
        r#"0: "held", 1: "failed""#,
    );
    assert_ne!(worded, text, "the helper's words are replaced");
    std::fs::write(&helper, &worded).expect("written");
    fx.commit("a head whose helper words its verdicts its own way");
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let record = fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    assert_eq!(shown(record.get("proof_exits")), r#"{"head":0,"plant":1}"#);
    std::fs::write(&helper, worded.replace("def reported(", "def unreported(")).expect("written");
    fx.commit("a head whose helper has no verdict check");
    std::fs::write(&fx.proofs, "").expect("emptied");
    let again = fx.scratch.join("work-2");
    let done = fx.run_in(&["p-miss", "p-catch"], &[], &[], Some(&again));
    assert_eq!(done.code, 3, "{}", done.stderr);
    for name in ["p-miss", "p-catch"] {
        fx.verdict(
            name,
            "no verdict",
            "the head's scripts/reproduce-test.py gives no verdict check: AttributeError",
        );
    }
    assert!(fx.proof_log().is_empty());
}

/// A proof target that cannot be removed holds every archive, and the cleanup names it.
#[test]
fn a_proof_target_that_cannot_be_removed_holds_every_archive() {
    if super::repository::is_root() {
        return;
    }
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss", "p-pintarget"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    for name in ["p-miss", "p-pintarget"] {
        fx.verdict(
            name,
            "no verdict",
            "the proof's proof/target remained after the last proof rerun",
        );
    }
    assert!(fx.calls(&["sim", "archive"]).is_empty());
    assert!(
        done.stderr
            .contains("plant-runner left the proof's target directory"),
        "{}",
        done.stderr
    );
}

/// An archive without the run's lockfile leaves its plant no verdict.
#[test]
fn an_archive_without_the_run_s_lockfile_leaves_no_verdict() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-nolockarchive"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-nolockarchive",
        "no verdict",
        "keeps no regular Cargo.lock equal to the run's",
    );
}

/// A rerun that exits 2, 4 or 6 leaves its plant alone with no verdict.
#[test]
fn a_rerun_that_exits_2_4_or_6_leaves_its_plant_alone_with_no_verdict() {
    let mut fx = Fixture::new();
    let done = fx.run(
        &["p-crashproof", "p-rejectproof", "p-slow", "p-watchproof"],
        &[],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    for (name, code) in [
        ("p-crashproof", 4),
        ("p-rejectproof", 2),
        ("p-watchproof", 6),
    ] {
        let reason = format!(
            "the rerun of the proof a::test exited {code}; its verdict is in proof/plant-{name}.out"
        );
        let record = fx.verdict(name, "no verdict", &reason);
        assert_eq!(shown(record.get("archive")), "null");
    }
    let record = fx.verdict("p-slow", "missed", "each expected profile reached 300 runs");
    assert_eq!(shown(record.get("proof_exits")), r#"{"head":0,"plant":1}"#);
    assert_eq!(not_live_list(&fx), "[]");
    assert_eq!(fx.calls(&["sim", "archive"]).len(), 1);
}

/// A head rerun that exits 6 stays its own proof's: the next proof reruns on the head.
#[test]
fn a_head_rerun_that_exits_6_stays_its_own_proof_s() {
    let mut fx = Fixture::new();
    other_proof(&mut fx);
    let done = fx.run(
        &["p-miss", "p-otherproof"],
        &[("STANDIN_HEAD_PROOFS", r#"{"a::test": 6}"#)],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "the rerun of the proof a::test exited 6; its verdict is in proof/head-0.out",
    );
    let (_, plants) = fx.results();
    assert_eq!(
        shown(plants["p-otherproof"].get("proof_exits")),
        r#"{"head":0,"plant":1}"#
    );
    assert_eq!(
        fx.proof_tests(|mode| mode == "base"),
        ["a::test", "b::test"]
    );
}

/// A rerun whose last line is not its exit's verdict leaves its plant no verdict, on a plant and on the
/// head.
#[test]
fn a_rerun_whose_last_line_is_not_its_exit_s_verdict_leaves_no_verdict() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-swapfail", "p-swappass", "p-trailfail"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    for (name, code, wanted) in [
        ("p-swapfail", 1, "reproduced"),
        ("p-swappass", 0, "not reproduced"),
        ("p-trailfail", 1, "reproduced"),
    ] {
        let reason = format!(
            "the rerun of the proof a::test exited {code} without the verdict `{wanted}`; its output is in \
             proof/plant-{name}.out"
        );
        fx.verdict(name, "no verdict", &reason);
    }
    assert!(fx.calls(&["sim", "archive"]).is_empty());
    let again = fx.scratch.join("work-2");
    let lines = r#"{"a::test": "reproduced: reproduced on attempt 1"}"#;
    let done = fx.run_in(
        &["p-miss"],
        &[],
        &[("STANDIN_HEAD_LINES", lines)],
        Some(&again),
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "exited 0 without the verdict `not reproduced`; its output is in proof/head-0.out",
    );
}

/// The proof applies the head's patch when the checkout's copy changes before it.
#[test]
fn the_proof_applies_the_head_s_patch_when_the_checkout_s_copy_changes_before_it() {
    let mut fx = Fixture::new();
    let pair = rewrite(&fx, &patch_of("catch", "base"));
    let done = fx.run(
        &["p-miss"],
        &[("STANDIN_REWRITE", &pair), ("STANDIN_REWRITE_IN", "base")],
    );
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_eq!(fx.proof_modes(), ["base", "pass"]);
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
}

/// The work directory's ancestors the run makes are private under a umask that would leave them group
/// writable, and a second run under them is accepted.
#[test]
fn work_directory_ancestors_the_run_makes_are_private_under_any_umask() {
    let mut fx = Fixture::new();
    let private = fx.scratch.join("private");
    super::repository::private_dir(&private);
    let under_umask = |fx: &mut Fixture, work: &std::path::Path| {
        let args = fx.args(&["p-miss"], &[], Some(work));
        let env = fx.environment(&[]);
        let output = std::process::Command::new("sh")
            .args(["-c", "umask 002; exec \"$@\"", "sh", super::fixture::BINARY])
            .arg(&fx.repo)
            .arg("plant-runner")
            .args(&args)
            .current_dir(&fx.repo)
            .env_clear()
            .envs(env)
            .output()
            .expect("the tool starts");
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let work = private.join("a/b/work");
    let (code, err) = under_umask(&mut fx, &work);
    assert_eq!(code, Some(0), "{err}");
    for made in [private.join("a"), private.join("a/b"), work] {
        assert_eq!(
            super::fixture::mode_bits(&made) & 0o022,
            0,
            "{}",
            made.display()
        );
    }
    let (code, err) = under_umask(&mut fx, &private.join("a/b/work-2"));
    assert_eq!(code, Some(0), "{err}");
}

/// The proof's output is read as UTF-8 under an English single-byte locale, whose Git messages are
/// ASCII; on a host without that locale the case runs under `C`, since the tool's reading takes no
/// locale.
#[test]
fn proof_output_is_read_as_utf_8_under_a_single_byte_locale() {
    let names = std::process::Command::new("locale")
        .arg("-a")
        .output()
        .map(|listed| String::from_utf8_lossy(&listed.stdout).into_owned())
        .unwrap_or_default();
    let latin = names
        .split_whitespace()
        .find(|name| name.to_lowercase() == "en_us.iso88591")
        .unwrap_or("C");
    let mut fx = Fixture::new();
    write_plant(
        &fx.store,
        "p-bproof",
        ("otherproof", &["a"], CAUSE, "base"),
        &OTHER_PROOF,
        None,
    );
    fx.commit("a second proof");
    let env = [
        ("LC_ALL", latin),
        ("PYTHONUTF8", "0"),
        ("STANDIN_BINARY_PROOFS", r#"["b::test"]"#),
    ];
    let done = fx.run(&["p-bproof", "p-miss"], &env);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-bproof",
        "no verdict",
        "`reproduce-test.py` exited 0 and printed no UTF-8 text",
    );
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
}

/// The archive build sees no lockfile path of the caller's.
#[test]
fn the_archive_build_sees_no_lockfile_path_of_the_caller_s() {
    let mut fx = Fixture::new();
    let elsewhere = fx.scratch.join("elsewhere.lock").display().to_string();
    let done = fx.run(&["p-miss"], &[("CARGO_RESOLVER_LOCKFILE_PATH", &elsewhere)]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_eq!(fx.calls(&["sim", "archive"]).len(), 1);
    assert!(!fx.scratch.join("archive-lockfile-path").exists());
}

/// An apply in the proof's worktree that fails judges no later plant there.
#[test]
fn a_failed_apply_in_the_proof_s_worktree_judges_no_later_plant() {
    let mut fx = Fixture::new();
    side_plant(&mut fx);
    let counter = fx.scratch.join("applies");
    let third = format!(
        "echo x >> {0}; if [ \"$(wc -l < {0})\" -eq 3 ]; then echo 'error: disk full' >&2; exit 1; fi",
        counter.display()
    );
    let (name, path) = fx.git_shim("--index", &third);
    let done = fx.run(&["p-miss", "p-side"], &[(name, &path)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "`git apply` exited 1; its error is in plants/p-miss/git.err",
    );
    fx.verdict(
        "p-side",
        "no verdict",
        "the proof's worktree is no longer the head's tree: `git apply` exited 1 at the plant p-miss",
    );
    assert_eq!(fx.proof_modes(), ["base"]);
}

/// A proof worktree that cannot be added gives every plant its first cause and keeps Git's error.
#[test]
fn a_proof_worktree_that_cannot_be_added_gives_every_plant_its_first_cause() {
    let mut fx = Fixture::new();
    let refuse = "case \"$*\" in *proof/tree*) echo 'fatal: no room' >&2; exit 128;; esac";
    let (name, path) = fx.git_shim("add", refuse);
    let done = fx.run(&["p-miss", "p-catch"], &[(name, &path)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    for name in ["p-miss", "p-catch"] {
        fx.verdict(
            name,
            "no verdict",
            "the proof's worktree: `git worktree` exited 128; its error is in proof/git.err",
        );
    }
    assert!(fx.proof_log().is_empty());
    let kept = std::fs::read_to_string(fx.work.join("proof/git.err")).expect("the error is kept");
    assert!(kept.contains("fatal: no room"), "{kept}");
}

/// An untracked file that a planted rerun leaves in the proof's worktree stays through the reset, so a
/// later plant whose patch adds that path fails its apply and gives its proof no verdict.
#[test]
fn an_untracked_file_a_rerun_leaves_stays_for_the_next_plant() {
    let mut fx = Fixture::new();
    let adding = "diff --git a/leftover b/leftover\nnew file mode 100644\n--- /dev/null\n+++ b/leftover\n\
                  @@ -0,0 +1 @@\n+x\ndiff --git a/mode b/mode\n--- a/mode\n+++ b/mode\n@@ -1 +1 @@\n-base\n\
                  +pass\n";
    write_plant(
        &fx.store,
        "p-zadd",
        ("pass", &["a"], CAUSE, "base"),
        &[("files", "[\"leftover\", \"mode\"]")],
        Some(adding),
    );
    fx.commit("a plant that adds a file");
    let left = r#"["leftover", "left by a rerun\n"]"#;
    let done = fx.run(
        &["p-catch", "p-zadd"],
        &[("STANDIN_REWRITE", left), ("STANDIN_REWRITE_IN", "catch")],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-zadd",
        "no verdict",
        "`git apply` exited 1; its error is in plants/p-zadd/git.err",
    );
    let kept = std::fs::read_to_string(fx.work.join("plants/p-zadd/git.err")).expect("kept");
    assert!(kept.contains("leftover"), "{kept}");
    assert_eq!(fx.proof_modes(), ["base", "catch"]);
}

/// A planted rerun that commits in the proof's worktree moves its HEAD, and the reset after it keeps
/// that commit, so `git apply` runs against the planted tree and exits 1 for `p-miss`.
#[test]
fn a_commit_a_rerun_makes_moves_the_tree_the_next_plant_applies_to() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-catch", "p-miss"], &[("STANDIN_COMMIT_IN", "catch")]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "`git apply` exited 1; its error is in plants/p-miss/git.err",
    );
    assert_eq!(fx.proof_modes(), ["base", "catch"]);
}

/// When the first head rerun rewrites `Cargo.lock` and emits invalid UTF-8, the second head rerun still
/// starts, and its check of the lockfile ends the head's reruns for both plants.
#[test]
fn a_relocking_rerun_with_undecodable_output_lets_the_next_head_rerun_start() {
    let mut fx = Fixture::new();
    other_proof(&mut fx);
    let done = fx.run(
        &["p-miss", "p-otherproof"],
        &[
            ("STANDIN_RELOCK_HEAD", "1"),
            ("STANDIN_BINARY_PROOFS", r#"["a::test"]"#),
        ],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    assert_eq!(
        fx.proof_tests(|mode| mode == "base"),
        ["a::test", "b::test"]
    );
    for name in ["p-miss", "p-otherproof"] {
        fx.verdict(
            name,
            "no verdict",
            "the rerun of the proof b::test left the proof's worktree without the run's Cargo.lock; its \
             output is in proof/head-1.out",
        );
    }
}

fn steered(fx: &mut Fixture, line: &str) {
    let helper = format!("{}{line}", super::fixture::HELPER);
    std::fs::write(fx.repo.join("scripts/reproduce-test.py"), helper).expect("written");
    fx.commit("a steered helper");
}

/// The staged helper's count determines whether the rerun contributes to `proof_exits`.
#[test]
fn the_staged_helper_s_answer_decides_a_rerun_that_its_prefix_would_refuse() {
    let mut fx = Fixture::new();
    steered(&mut fx, super::standins::COUNTS_EVERY);
    let done = fx.run(&["p-swapfail"], &[]);
    let (_, plants) = fx.results();
    let entry = &plants["p-swapfail"];
    assert_eq!(
        shown(entry.get("proof_exits")),
        r#"{"head":0,"plant":1}"#,
        "{}",
        done.stderr
    );
    assert_ne!(
        text_of(entry.get("result").expect("a result")),
        "no verdict"
    );
}

/// The setup's question passes and the head rerun's question fails.
#[test]
fn a_rerun_s_question_that_fails_leaves_no_verdict_with_its_last_error_line() {
    let mut fx = Fixture::new();
    steered(&mut fx, super::standins::RAISES);
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "the head's verdict check failed on the rerun of the proof a::test: ValueError: no count",
    );
}

/// The setup's question waits for its release; the signal reaches the run alone.
#[test]
fn a_signal_during_the_helper_s_question_acts_after_the_question() {
    let mut fx = Fixture::new();
    steered(&mut fx, super::standins::HOLDS);
    let mut runner = fx.spawn(&["p-miss"], &[], false);
    super::fixture::wait_for(&fx.scratch.join("question-ready"), &mut runner.child);
    runner.signal(libc::SIGTERM, false);
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!fx.scratch.join("question-answered").exists());
    std::fs::write(fx.scratch.join("question-release"), "").expect("written");
    let (code, err) = runner.finish();
    assert_eq!(code, 128 + libc::SIGTERM, "{err}");
    assert!(fx.scratch.join("question-answered").exists());
    assert!(fx.proof_log().is_empty());
    assert!(!fx.score.exists());
}

/// The planted rerun rewrites the staged `plants/p-miss/plant.patch` in the work directory, and the
/// planted commit holds the rewritten patch's change.
#[test]
fn the_staged_patch_is_applied_by_name_after_the_proof_reruns() {
    let mut fx = Fixture::new();
    let staged = fx.work.join("plants/p-miss/plant.patch");
    let pair = format!(
        "[{}, {}]",
        super::fixture::json_text(&staged.display().to_string()),
        super::fixture::json_text(&patch_of("catch", "base"))
    );
    let done = fx.run(&["p-miss"], &[("STANDIN_REWRITE", &pair)]);
    let (_, plants) = fx.results();
    let commit = text_of(plants["p-miss"].get("commit").expect("a commit"));
    assert_eq!(
        fx.git(&["show", &format!("{commit}:mode")]),
        "catch\n",
        "{}",
        done.stderr
    );
    assert_eq!(fx.proof_modes(), ["base", "pass"]);
}

/// A head rerun that rewrites the staged helper changes the program each later rerun starts, since every
/// rerun starts the staged copy by its name; the question still runs the source read at the setup, so
/// the plant's rerun, which prints the rewritten helper's verdict words, is judged by the setup's words
/// and gives no verdict.
#[test]
fn a_rerun_that_rewrites_the_staged_helper_changes_later_reruns_and_not_their_judge() {
    let mut fx = Fixture::new();
    let staged = fx.work.join("proof/scripts/reproduce-test.py");
    let rewritten = super::fixture::HELPER.replace("1: \"reproduced\"", "1: \"broken\"");
    let pair = format!(
        "[{}, {}]",
        super::fixture::json_text(&staged.display().to_string()),
        super::fixture::json_text(&rewritten)
    );
    let done = fx.run(
        &["p-miss"],
        &[("STANDIN_REWRITE", &pair), ("STANDIN_REWRITE_IN", "base")],
    );
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "exited 1 without the verdict `reproduced`",
    );
    let out =
        std::fs::read_to_string(fx.work.join("proof/plant-p-miss.out")).expect("the log reads");
    assert!(out.starts_with("broken"), "{out}");
}
