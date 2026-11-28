//! The cases of the run's exit codes and of its refusals before any worktree: a miss without its
//! cause exits 1, a plant left out of the count exits 3, and each refused input exits 2 with no
//! stand-in call, no work directory and no score.

use super::fixture::{CAUSE, Fixture, patch_of, shown, text_of, write_plant};

fn discard(path: &std::path::Path) {
    let _ = std::fs::remove_dir_all(path);
}

/// A miss without its cause exits 1.
#[test]
fn a_miss_without_its_cause_exits_1() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-nocause", "p-catch", "p-nobuild"], &[]);
    assert_eq!(done.code, 1, "{}", done.stderr);
    let (_, plants) = fx.results();
    assert_eq!(
        text_of(plants["p-nocause"].get("result").expect("a result")),
        "missed"
    );
    assert_eq!(shown(plants["p-nocause"].get("miss_cause")), "null");
}

/// A miss without a sweep and without its cause exits 1.
#[test]
fn a_miss_without_a_sweep_and_without_its_cause_exits_1() {
    let mut fx = Fixture::new();
    write_plant(
        &fx.store,
        "p-unswept",
        ("pass", &[], "null", "base"),
        &[],
        None,
    );
    fx.commit("a plant with no expected profile and no cause");
    let done = fx.run(&["p-unswept"], &[]);
    assert_eq!(done.code, 1, "{}", done.stderr);
    let (_, plants) = fx.results();
    assert_eq!(
        text_of(plants["p-unswept"].get("result").expect("a result")),
        "missed"
    );
    assert_eq!(shown(plants["p-unswept"].get("miss_cause")), "null");
}

/// Each of the four cause words stands in the score of its miss.
#[test]
fn each_of_the_four_cause_words_stands_in_the_score_of_its_miss() {
    let mut fx = Fixture::new();
    let words = ["environment", "workload", "ordering", "property"];
    let causes: Vec<String> = words
        .iter()
        .map(|word| format!("{{\"cause\": \"{word}\", \"evidence\": \"A sentence on {word}.\"}}"))
        .collect();
    for (word, cause) in words.iter().zip(&causes) {
        let cause: &'static str = Box::leak(cause.clone().into_boxed_str());
        write_plant(
            &fx.store,
            &format!("p-{word}"),
            ("pass", &[], cause, "base"),
            &[],
            None,
        );
    }
    fx.commit("a plant for each cause word");
    let names: Vec<String> = words.iter().map(|word| format!("p-{word}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let done = fx.run(&names, &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let (written, plants) = fx.results();
    let commit = text_of(written.get("commit").expect("a commit"));
    assert_eq!(commit, fx.git(&["rev-parse", "HEAD"]).trim());
    assert_eq!(fx.sentence(), format!("0 of 4 plants at commit {commit}"));
    for word in words {
        let plant = &plants[&format!("p-{word}")];
        assert_eq!(text_of(plant.get("result").expect("a result")), "missed");
        let cause = format!("{{\"cause\":\"{word}\",\"evidence\":\"A sentence on {word}.\"}}");
        assert_eq!(shown(plant.get("miss_cause")), cause);
    }
}

/// Every plant with a verdict and every miss with its cause exits 0.
#[test]
fn every_plant_with_a_verdict_and_every_miss_with_a_cause_exits_0() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-catch", "p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_eq!(
        fx.sentence(),
        format!("1 of 2 plants at commit {}", fx.head)
    );
}

/// A patch that does not apply exits 3 and stays out of the count.
#[test]
fn a_patch_that_does_not_apply_exits_3_and_stays_out_of_the_count() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-catch", "p-miss", "p-stale"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    let (_, plants) = fx.results();
    assert_eq!(
        fx.sentence(),
        format!("1 of 2 plants at commit {}", fx.head)
    );
    assert_eq!(
        text_of(plants["p-stale"].get("result").expect("a result")),
        "does not apply"
    );
    discard(&fx.work);
    let done = fx.run(&["p-stale"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    assert_eq!(
        fx.sentence(),
        format!("0 of 0 plants at commit {}", fx.head)
    );
}

/// Each malformed record refuses the run before any work.
#[test]
fn a_malformed_record_is_rejected_before_any_work() {
    let mut fx = Fixture::new();
    let cases = [
        (
            "p-broken",
            ("miss_cause", r#"{"cause": "luck", "evidence": "none"}"#),
            "miss_cause",
        ),
        (
            "p-noevidence",
            ("miss_cause", r#"{"cause": "workload", "evidence": " "}"#),
            "miss_cause",
        ),
        ("p-bareword", ("miss_cause", r#""workload""#), "miss_cause"),
        ("p-boolrow", ("row", "true"), "row is a positive integer"),
        ("p-nofiles", ("files", "[]"), "files is a nonempty list"),
        (
            "p-twoprofiles",
            ("expected", r#"["a,b"]"#),
            "expected is a list of profile names",
        ),
        (
            "p-badfix",
            ("fix", r#"{"pull_request": 0, "commit": "c"}"#),
            "fix holds a positive pull_request",
        ),
    ];
    for (name, field, rule) in cases {
        let place = write_plant(
            &fx.store,
            name,
            ("pass", &["a"], CAUSE, "base"),
            &[field],
            None,
        );
        let done = fx.run(&[], &[]);
        fx.rejected(&done, &format!("{name}: {rule}"));
        discard(&place);
    }
}

/// A record with a repeated member or nesting past the reader's depth refuses the run.
#[test]
fn a_record_with_a_repeated_member_or_deep_nesting_is_rejected() {
    let mut fx = Fixture::new();
    let place = write_plant(
        &fx.store,
        "p-twice",
        ("pass", &["a"], CAUSE, "base"),
        &[],
        None,
    );
    let record = std::fs::read_to_string(place.join("plant.json")).expect("reads");
    let repeated = format!("{}, \"expected\": []}}", &record[..record.len() - 1]);
    for (broken, text) in [
        (
            repeated,
            "plant.json is unreadable: repeated member expected",
        ),
        ("[".repeat(100_000), "plant.json is unreadable"),
    ] {
        std::fs::write(place.join("plant.json"), broken).expect("written");
        let done = fx.run(&[], &[]);
        fx.rejected(&done, &format!("p-twice: {text}"));
    }
}

/// A missing, empty or corrupt patch refuses the run.
#[test]
fn a_missing_empty_or_corrupt_patch_is_rejected() {
    let mut fx = Fixture::new();
    let place = write_plant(
        &fx.store,
        "p-patch",
        ("pass", &["a"], CAUSE, "base"),
        &[],
        None,
    );
    for patch in ["", "--- a/mode\n+++ b/mode\n@@ -1 +1 @@\n-base\n"] {
        std::fs::write(place.join("plant.patch"), patch).expect("written");
        let done = fx.run(&[], &[]);
        fx.rejected(&done, "p-patch: plant.patch is no patch");
    }
    std::fs::remove_file(place.join("plant.patch")).expect("removed");
    let done = fx.run(&[], &[]);
    fx.rejected(
        &done,
        "p-patch: plant.json and plant.patch are both required",
    );
}

/// A patch that renames a path or changes a mode refuses the run.
#[test]
fn a_patch_that_renames_or_changes_a_mode_is_rejected() {
    let mut fx = Fixture::new();
    let place = write_plant(
        &fx.store,
        "p-rename",
        ("pass", &["mode"], CAUSE, "base"),
        &[],
        None,
    );
    for (patch, text) in [
        (
            "diff --git a/mode b/mode\nold mode 100644\nnew mode 100755\n",
            "mode change",
        ),
        (
            "diff --git a/mode b/mode\nsimilarity index 100%\nrename from mode\nrename to mode\n",
            "rename",
        ),
    ] {
        std::fs::write(place.join("plant.patch"), patch).expect("written");
        let done = fx.run(&[], &[]);
        assert_eq!(done.code, 2, "{}", done.stderr);
        let refused = format!("p-rename: plant.patch does more than change file contents: {text}");
        assert!(done.stderr.contains(&refused), "{}", done.stderr);
        assert!(fx.calls(&[]).is_empty());
    }
}

/// A patch past 1 MiB refuses the run.
#[test]
fn a_patch_past_the_bound_is_rejected() {
    let mut fx = Fixture::new();
    let place = write_plant(
        &fx.store,
        "p-big",
        ("pass", &["mode"], CAUSE, "base"),
        &[],
        None,
    );
    std::fs::write(
        place.join("plant.patch"),
        patch_of("pass", "base") + &"#".repeat(1 << 20),
    )
    .expect("written");
    let done = fx.run(&[], &[]);
    fx.rejected(
        &done,
        "p-big: plant.json or plant.patch holds more than 1048576 bytes",
    );
}

/// A plant file edited under an assume-unchanged flag refuses the run.
#[test]
fn a_plant_file_edited_under_an_assume_unchanged_flag_is_rejected() {
    let mut fx = Fixture::new();
    let record = fx.store.join("p-miss/plant.json");
    let patch = fx.store.join("p-miss/plant.patch");
    let edited = std::fs::read_to_string(&record)
        .expect("reads")
        .replace("A defect.", "Another defect.");
    for (path, edit) in [(record, edited), (patch, patch_of("catch", "base"))] {
        let name = path
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        let before = std::fs::read_to_string(&path).expect("reads");
        fx.git(&[
            "update-index",
            "--assume-unchanged",
            &format!("verification/plants/p-miss/{name}"),
        ]);
        std::fs::write(&path, edit).expect("written");
        assert_eq!(
            fx.git(&["status", "--porcelain", "--", "verification/plants/p-miss"]),
            ""
        );
        let done = fx.run(&["p-miss"], &[]);
        fx.rejected(
            &done,
            &format!("differs from HEAD at verification/plants/p-miss/{name}"),
        );
        std::fs::write(&path, before).expect("written");
    }
}

/// A plant directory removed under an assume-unchanged flag refuses the run.
#[test]
fn a_plant_directory_removed_under_an_assume_unchanged_flag_is_rejected() {
    let mut fx = Fixture::new();
    for name in ["plant.json", "plant.patch"] {
        fx.git(&[
            "update-index",
            "--assume-unchanged",
            &format!("verification/plants/p-miss/{name}"),
        ]);
    }
    discard(&fx.store.join("p-miss"));
    assert_eq!(
        fx.git(&["status", "--porcelain", "--", "verification/plants"]),
        ""
    );
    let done = fx.run(&[], &[]);
    fx.rejected(&done, "differs from HEAD at verification/plants/p-miss");
}

/// A listing of the head's plant directories that fails refuses the run.
#[test]
fn a_listing_of_the_head_s_plant_directories_that_fails_is_rejected() {
    let mut fx = Fixture::new();
    let (name, path) = fx.git_shim("-d", "echo 'a refused listing' >&2; exit 1");
    let done = fx.run(&["p-miss"], &[(name, &path)]);
    fx.rejected(
        &done,
        "the plant store of HEAD cannot be listed: `git ls-tree` exited 1",
    );
}

/// `behind_link` moves `path` to `moved` and leaves a link to it in its place.
fn behind_link(path: &std::path::Path, moved: &std::path::Path) {
    std::fs::rename(path, moved).expect("moved");
    std::os::unix::fs::symlink(moved, path).expect("linked");
}

/// A plant store that is a link refuses the run and writes no score through it.
#[test]
fn a_linked_plant_store_is_rejected() {
    let mut fx = Fixture::new();
    let moved = fx.scratch.join("elsewhere");
    behind_link(&fx.store, &moved);
    let done = fx.run(&["p-miss"], &[]);
    fx.rejected(
        &done,
        "is a link; the plant store must be a directory of the checkout",
    );
    assert!(!moved.join("score.json").exists());
}

/// A verification directory that is a link refuses the run.
#[test]
fn a_linked_verification_directory_is_rejected() {
    let mut fx = Fixture::new();
    let moved = fx.scratch.join("elsewhere");
    behind_link(&fx.repo.join("verification"), &moved);
    let done = fx.run(&["p-miss"], &[]);
    fx.rejected(
        &done,
        "is a link; the plant store must be a directory of the checkout",
    );
    assert!(!moved.join("plants/score.json").exists());
}

/// A store with no plant refuses the run.
#[test]
fn a_store_with_no_plant_is_rejected() {
    let mut fx = Fixture::new();
    for entry in std::fs::read_dir(&fx.store).expect("lists") {
        discard(&entry.expect("an entry").path());
    }
    std::fs::write(fx.store.join("keep"), "").expect("written");
    fx.commit("a store with no plant");
    let done = fx.run(&[], &[]);
    fx.rejected(&done, "holds no plant");
}

/// A floor of exactly 300 is accepted.
#[test]
fn a_floor_of_exactly_300_is_accepted() {
    let mut fx = Fixture::new();
    let done = fx.run_in(&["p-noprofile"], &["--runs", "300"], &[], None);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let (written, _) = fx.results();
    let Some(json_value) = written.get("settings") else {
        panic!("settings")
    };
    let kestrike_tools::json::Value::Object(settings) = json_value else {
        panic!("an object")
    };
    assert_eq!(shown(settings.get("runs")), "300");
}

/// A plant's name, the fields its record replaces or adds, and the rule its refusal names.
type Case = (
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static str,
);

/// A record that names a profile `campaign` cannot take, or other fields, refuses the run.
#[test]
fn a_record_naming_a_profile_campaign_cannot_take_or_other_fields_is_rejected() {
    let mut fx = Fixture::new();
    let cases: [Case; 6] = [
        (
            "p-slash",
            &[("expected", r#"["a/b"]"#)],
            "expected is a list of profile names campaign can take",
        ),
        (
            "p-dot",
            &[("expected", r#"[".."]"#)],
            "expected is a list of profile names campaign can take",
        ),
        (
            "p-noproof",
            &[("proof", r#"" ""#)],
            "restores and proof are nonempty text",
        ),
        (
            "p-otherid",
            &[("id", r#""p-elsewhere""#)],
            "id names the plant's directory",
        ),
        (
            "p-edge ",
            &[],
            "id names the plant's directory in printable ASCII without edge spaces",
        ),
        (
            "p-extra",
            &[("note", r#""x""#)],
            "plant.json holds exactly the fields",
        ),
    ];
    for (name, fields, rule) in cases {
        let place = write_plant(
            &fx.store,
            name,
            ("pass", &["a"], CAUSE, "base"),
            fields,
            None,
        );
        let done = fx.run(&[], &[]);
        fx.rejected(&done, &format!("{name}: {rule}"));
        discard(&place);
    }
}

/// A checkout without a lockfile refuses the run.
#[test]
fn a_checkout_without_a_lockfile_is_rejected() {
    let mut fx = Fixture::new();
    std::fs::remove_file(fx.repo.join("Cargo.lock")).expect("removed");
    let done = fx.run(&["p-miss"], &[]);
    fx.rejected(&done, "the checkout holds no readable Cargo.lock");
}

/// A checkout whose lockfile is a link refuses the run.
#[test]
fn a_checkout_whose_lockfile_is_a_link_is_rejected() {
    let mut fx = Fixture::new();
    behind_link(
        &fx.repo.join("Cargo.lock"),
        &fx.scratch.join("outside.lock"),
    );
    let done = fx.run(&["p-miss"], &[]);
    fx.rejected(
        &done,
        "the checkout holds no readable Cargo.lock (no regular file)",
    );
}

/// A `--campaign` path relative to the invoking directory runs from there.
#[test]
fn a_campaign_path_relative_to_the_invoking_directory_runs_from_there() {
    let mut fx = Fixture::new();
    let mut args = fx.args(&["p-noprofile"], &[], None);
    args[1] = std::ffi::OsString::from("../campaign");
    let env = fx.environment(&[]);
    let repo = fx.repo.clone();
    let done = fx.run_with(&args, &env, &repo);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let calls: Vec<Vec<String>> = fx
        .calls(&[])
        .into_iter()
        .map(|call| call[..2].to_vec())
        .collect();
    assert_eq!(calls, [["sim", "archive"]]);
}

/// A patch that changes other paths than its `files` refuses the run.
#[test]
fn a_patch_that_changes_paths_beyond_its_files_is_rejected() {
    let mut fx = Fixture::new();
    let wider = patch_of("pass", "base") + "--- /dev/null\n+++ b/extra\n@@ -0,0 +1 @@\n+x\n";
    let place = write_plant(
        &fx.store,
        "p-wider",
        ("pass", &["a"], CAUSE, "base"),
        &[],
        Some(&wider),
    );
    let done = fx.run(&[], &[]);
    fx.rejected(
        &done,
        "p-wider: plant.patch changes extra, mode, and files names mode",
    );
    discard(&place);
    write_plant(
        &fx.store,
        "p-fewer",
        ("pass", &["a"], CAUSE, "base"),
        &[("files", r#"["mode", "other"]"#)],
        None,
    );
    let done = fx.run(&[], &[]);
    fx.rejected(
        &done,
        "p-fewer: plant.patch changes mode, and files names mode, other",
    );
}

/// A plant store that differs from the head refuses the run: an edited file, a new plant, a file the
/// commit does not hold and a plant the working tree lost.
#[test]
fn a_plant_store_that_differs_from_head_is_rejected() {
    let mut fx = Fixture::new();
    let record = fx.store.join("p-miss/plant.json");
    let patch = fx.store.join("p-miss/plant.patch");
    let edited = std::fs::read_to_string(&record)
        .expect("reads")
        .replace("A defect.", "Another defect.");
    for (path, edit) in [(record, edited), (patch, patch_of("catch", "base"))] {
        let name = path
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        let before = std::fs::read_to_string(&path).expect("reads");
        std::fs::write(&path, edit).expect("written");
        let done = fx.run(&["p-miss"], &[]);
        fx.rejected(
            &done,
            &format!("differs from HEAD at verification/plants/p-miss/{name}"),
        );
        std::fs::write(&path, before).expect("written");
    }
    let place = write_plant(
        &fx.store,
        "p-new",
        ("pass", &["a"], CAUSE, "base"),
        &[],
        None,
    );
    let done = fx.run(&["p-miss"], &[]);
    fx.rejected(
        &done,
        "differs from HEAD at verification/plants/p-new/plant.json",
    );
    discard(&place);
    let note = fx.store.join("p-miss/note");
    std::fs::write(&note, "a file the commit does not hold\n").expect("written");
    let done = fx.run(&["p-miss"], &[]);
    fx.rejected(
        &done,
        "differs from HEAD at verification/plants/p-miss/note",
    );
    std::fs::remove_file(&note).expect("removed");
    discard(&fx.store.join("p-short"));
    let done = fx.run(&["p-miss"], &[]);
    fx.rejected(
        &done,
        "differs from HEAD at verification/plants/p-short/plant.json",
    );
}

/// Git variables that point at another repository or index refuse the run and leave the checkout as
/// it was.
#[test]
fn git_variables_that_point_at_another_repository_or_index_are_rejected() {
    let mut fx = Fixture::new();
    std::fs::write(fx.repo.join("mode"), "staged\n").expect("written");
    fx.git(&["add", "mode"]);
    std::fs::write(fx.repo.join("mode"), "base\n").expect("written");
    let before = fx.state();
    for (name, value) in [
        ("GIT_DIR", fx.repo.join(".git")),
        ("GIT_INDEX_FILE", fx.repo.join(".git/index")),
    ] {
        let value = value.display().to_string();
        let done = fx.run(&["p-miss"], &[(name, &value)]);
        fx.rejected(&done, &format!("{name} would point"));
        assert_eq!(fx.state(), before, "{name}");
    }
}

/// A floor below 300 refuses the run.
#[test]
fn a_floor_below_300_is_rejected() {
    let mut fx = Fixture::new();
    let done = fx.run_in(&["p-miss"], &["--runs", "299"], &[], None);
    fx.rejected(&done, "below the floor of 300");
}

/// A work directory inside the checkout, or under a directory another user can write, refuses the run
/// and makes nothing.
#[test]
fn a_work_directory_inside_the_checkout_or_under_a_shared_directory_is_rejected() {
    let mut fx = Fixture::new();
    let before = fx.state();
    let inside = fx.repo.join("work");
    let done = fx.run_in(&["p-miss"], &[], &[], Some(&inside));
    assert_eq!(done.code, 2, "{}", done.stderr);
    assert!(
        done.stderr.contains("lies inside the checkout"),
        "{}",
        done.stderr
    );
    assert!(!inside.exists());
    assert_eq!(fx.state(), before);
    let shared = fx.scratch.join("shared");
    std::fs::create_dir(&shared).expect("made");
    super::repository::chmod(&shared, 0o777);
    let done = fx.run_in(&["p-miss"], &[], &[], Some(&shared.join("inner/work")));
    fx.rejected(&done, "another user owns or can write");
    assert!(!shared.join("inner").exists());
}

/// A default work directory under a shared temporary directory refuses the run and names both ways
/// out.
#[test]
fn a_default_work_directory_under_a_shared_temporary_directory_is_rejected_with_both_ways_out() {
    let mut fx = Fixture::new();
    let before = fx.state();
    let shared = fx.scratch.join("shared-temporary");
    std::fs::create_dir(&shared).expect("made");
    super::repository::chmod(&shared, 0o777);
    let mut args = fx.args(&["p-miss"], &[], None);
    let at = args.iter().position(|arg| arg == "--work").expect("--work");
    args.drain(at..at + 2);
    let mut env = fx.environment(&[]);
    env.retain(|(name, _)| name != "TEMP" && name != "TMP" && name != "TMPDIR");
    env.push(("TMPDIR".into(), shared.clone().into_os_string()));
    let repo = fx.repo.clone();
    let done = fx.run_with(&args, &env, &repo);
    fx.rejected(
        &done,
        &format!("another user owns or can write {}", shared.display()),
    );
    for way in ["--work", "TMPDIR"] {
        assert!(done.stderr.contains(way), "{}", done.stderr);
    }
    assert_eq!(std::fs::read_dir(&shared).expect("lists").count(), 0);
    assert_eq!(fx.state(), before);
}

/// An existing work directory, and an invoking directory outside a checkout, refuse the run.
#[test]
fn an_existing_work_directory_and_a_directory_outside_a_checkout_are_rejected() {
    let mut fx = Fixture::new();
    std::fs::create_dir(&fx.work).expect("made");
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 2);
    assert!(
        done.stderr.contains("the work directory"),
        "{}",
        done.stderr
    );
    std::fs::remove_dir(&fx.work).expect("removed");
    let below = fx.scratch.join("outside");
    std::fs::create_dir(&below).expect("made");
    let args = fx.args(&["p-miss"], &[], None);
    let env = fx.environment(&[]);
    let done = fx.run_with(&args, &env, &below);
    fx.rejected(&done, "outside a Git checkout");
}

/// A `campaign` binary that is absent refuses the run.
#[test]
fn a_campaign_binary_that_is_absent_is_rejected() {
    let mut fx = Fixture::new();
    let absent = fx.scratch.join("absent").display().to_string();
    let done = fx.run_in(&["p-miss"], &["--campaign", &absent], &[], None);
    fx.rejected(&done, "no campaign binary at");
}

/// An unknown plant refuses the run.
#[test]
fn an_unknown_plant_is_rejected() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-none"], &[]);
    fx.rejected(&done, "no plant named p-none");
}

/// A plant at the score's path refuses the run before any work, and the directory stays.
#[test]
fn a_plant_at_the_score_s_path_is_rejected_before_any_work() {
    let mut fx = Fixture::new();
    write_plant(
        &fx.store,
        "score.json",
        ("pass", &["a"], CAUSE, "base"),
        &[],
        None,
    );
    fx.commit("a plant at the score's path");
    let done = fx.run(&[], &[]);
    assert_eq!(done.code, 2, "{}", done.stderr);
    assert!(
        done.stderr
            .contains("score.json: id is another name than score.json"),
        "{}",
        done.stderr
    );
    assert!(fx.calls(&[]).is_empty());
    assert!(!fx.work.exists());
    assert!(fx.score.is_dir());
}

/// A plant id of 245 bytes keeps its proof logs, whose names take 255 bytes; one of 246 refuses the run.
#[test]
fn a_plant_whose_id_passes_245_bytes_is_rejected_and_one_of_245_keeps_its_proof_logs() {
    let mut fx = Fixture::new();
    let (longest, longer) = (
        format!("p-{}", "x".repeat(243)),
        format!("p-{}", "x".repeat(244)),
    );
    write_plant(
        &fx.store,
        &longest,
        ("pass", &["a"], CAUSE, "base"),
        &[],
        None,
    );
    fx.commit("a plant whose proof logs' names take 255 bytes");
    let done = fx.run(&[&longest], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    fx.verdict(&longest, "missed", "each expected profile reached 300 runs");
    for end in [".out", ".err"] {
        assert!(
            fx.work
                .join(format!("proof/plant-{longest}{end}"))
                .is_file(),
            "{end}"
        );
    }
    write_plant(
        &fx.store,
        &longer,
        ("pass", &["a"], CAUSE, "base"),
        &[],
        None,
    );
    fx.commit("a plant whose proof logs' names would pass 255 bytes");
    let before = fx.calls(&[]);
    let again = fx.scratch.join("work-2");
    let done = fx.run_in(&[&longer], &[], &[], Some(&again));
    assert_eq!(done.code, 2, "{}", done.stderr);
    assert!(
        done.stderr.contains("id holds at most 245 bytes"),
        "{}",
        done.stderr
    );
    assert_eq!(fx.calls(&[]), before);
    assert!(!again.exists());
}

/// A score that cannot be written exits 4 with the results on standard error and leaves no staging
/// file.
#[test]
fn a_score_that_cannot_be_written_exits_4_with_the_results() {
    let mut fx = Fixture::new();
    let score = fx.score.display().to_string();
    let done = fx.run(&["p-miss"], &[("STANDIN_BLOCK_SCORE", &score)]);
    assert_eq!(done.code, 4, "{}", done.stderr);
    assert!(
        done.stderr.contains("plant-runner wrote no score"),
        "{}",
        done.stderr
    );
    assert!(
        done.stderr
            .contains("p-miss: missed (each expected profile reached 300 runs"),
        "{}",
        done.stderr
    );
    assert!(!done.stdout.contains("plants at commit"), "{}", done.stdout);
    assert!(fx.score.is_dir());
    let staged = std::fs::read_dir(&fx.store)
        .expect("lists")
        .filter(|entry| {
            entry
                .as_ref()
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".score.json.")
        })
        .count();
    assert_eq!(staged, 0);
}

#[test]
fn a_run_writes_its_progress_lines_to_standard_error() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_eq!(
        done.stderr,
        format!(
            "work: {}\np-miss: proof {{'head': 0, 'plant': 1}}\np-miss: missed\n",
            fx.work.display()
        )
    );
}

/// A plant its apply check settles prints its result in the first phase and again in the second; a
/// plant its proof settles prints `proof RESULT`, and one its proof leaves live prints its exits.
#[test]
fn each_line_form_of_the_two_phases_comes_in_store_order() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss", "p-notlive", "p-stale"], &[]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    assert_eq!(
        done.stderr,
        format!(
            "work: {}\np-stale: does not apply\np-miss: proof {{'head': 0, 'plant': 1}}\n\
             p-notlive: proof not live\np-miss: missed\np-notlive: not live\np-stale: does not apply\n",
            fx.work.display()
        )
    );
}

fn full() -> std::fs::File {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full opens")
}

/// A standard error that refuses the work line ends the run before any worktree: exit 4, no stand-in
/// call, no plant directory and no score.
#[test]
fn a_work_line_that_cannot_be_written_ends_the_run_with_exit_4() {
    let mut fx = Fixture::new();
    let mut runner = fx.spawn_with(&["p-miss"], &[], false, |command| {
        command.stderr(full());
    });
    let (code, _) = runner.finish();
    assert_eq!(code, 4);
    assert!(fx.calls(&[]).is_empty());
    assert!(!fx.work.join("plants").exists());
    assert!(!fx.score.exists());
}

/// A standard error that refuses the first progress line ends the run after its cleanup: exit 4, the
/// plant's worktree removed and unlisted, and no score.
#[test]
fn a_progress_line_that_cannot_be_written_ends_the_run_after_its_cleanup() {
    let mut fx = Fixture::new();
    let gate = fx.scratch.join("gate");
    let (name, path) = fx.git_shim(
        "--check",
        &format!("while [ ! -e '{}' ]; do sleep 0.02; done", gate.display()),
    );
    let env = fx.environment(&[(name, path.as_str())]);
    let args = fx.args(&["p-stale"], &[], None);
    let repo = fx.repo.clone();
    let mut child = fx
        .command(&args, &env, &repo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the tool starts");
    let mut err = std::io::BufReader::new(child.stderr.take().expect("a pipe"));
    let mut line = String::new();
    std::io::BufRead::read_line(&mut err, &mut line).expect("the work line reads");
    assert!(line.starts_with("work: "), "{line}");
    drop(err);
    std::fs::write(&gate, "").expect("the gate opens");
    let status = child.wait().expect("the tool ends");
    assert_eq!(status.code(), Some(4));
    assert!(!fx.work.join("plants/p-stale/tree").exists());
    let listed = fx.git(&["worktree", "list", "--porcelain"]);
    assert!(!listed.contains("p-stale"), "{listed}");
    assert!(!fx.score.exists());
}

/// The help goes to standard output with exit 0 and nothing on standard error, for both flags; a
/// standard output that refuses it exits 120.
#[test]
fn the_help_is_printed_on_standard_output_or_exits_120() {
    let fx = Fixture::new();
    let env = fx.environment(&[]);
    for flag in ["--help", "-h"] {
        let done = fx.run_with(&[flag.into()], &env, &fx.repo);
        assert_eq!(done.code, 0, "{flag}: {}", done.stderr);
        assert_eq!(done.stderr, "", "{flag}");
        assert!(done.stdout.contains("Exit 120: standard"), "{flag}");
    }
    let status = fx
        .command(&["--help".into()], &env, &fx.repo)
        .stdout(full())
        .status()
        .expect("the tool starts");
    assert_eq!(status.code(), Some(120));
}

/// The shim fails the head's date read, which runs before any worktree.
#[test]
fn a_failure_outside_a_plant_exits_4_with_its_line() {
    let mut fx = Fixture::new();
    let (name, path) = fx.git_shim("--format=%cI", "echo 'fatal: no date' >&2; exit 128");
    let done = fx.run(&["p-miss"], &[(name, &path)]);
    assert_eq!(done.code, 4, "{}", done.stderr);
    let last = done.stderr.lines().last().expect("a line");
    assert!(last.starts_with("plant-runner: "), "{}", done.stderr);
    assert!(last.contains("`git show` exited 128"), "{}", done.stderr);
    assert!(fx.calls(&[]).is_empty());
    assert!(!fx.score.exists());
    assert!(!fx.work.join("plants").exists());
}

/// A standard output opened read-only refuses the score's lines: the score stands, and the tool exits
/// 120, the exit of a score whose lines were not printed.
#[test]
fn a_read_only_standard_output_refuses_the_score_s_lines_and_exits_120() {
    let mut fx = Fixture::new();
    let args = fx.args(&["p-miss"], &[], None);
    let env = fx.environment(&[]);
    let sink = fx.scratch.join("read-only.out");
    std::fs::write(&sink, "").expect("written");
    let repo = fx.repo.clone();
    let status = fx
        .command(&args, &env, &repo)
        .stdout(std::fs::File::open(&sink).expect("opens read-only"))
        .stderr(std::process::Stdio::null())
        .status()
        .expect("the tool starts");
    assert_eq!(status.code(), Some(120));
    let (written, _) = fx.results();
    assert_eq!(text_of(written.get("commit").expect("a commit")), fx.head);
    assert_eq!(std::fs::read_to_string(&sink).expect("reads"), "");
}

/// A standard output past the soft file size limit refuses the score's lines with `EFBIG`, which ends
/// no process: the score stands and the tool exits 120.
#[test]
fn a_standard_output_past_the_file_size_limit_refuses_the_score_s_lines_and_exits_120() {
    let mut fx = Fixture::new();
    let args = fx.args(&["p-miss"], &[], None);
    let env = fx.environment(&[]);
    let sink = fx.scratch.join("full.out");
    std::fs::write(&sink, vec![b'x'; 600 * 1024]).expect("written");
    let out = std::fs::OpenOptions::new()
        .append(true)
        .open(&sink)
        .expect("opens");
    let output = std::process::Command::new("sh")
        .args([
            "-c",
            "ulimit -f 1000; exec \"$@\"",
            "sh",
            super::fixture::BINARY,
        ])
        .arg(&fx.repo)
        .arg("plant-runner")
        .args(&args)
        .current_dir(&fx.repo)
        .env_clear()
        .envs(env.iter().cloned())
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("the tool starts");
    assert_eq!(
        output.status.code(),
        Some(120),
        "{:?} {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let (written, _) = fx.results();
    assert_eq!(text_of(written.get("commit").expect("a commit")), fx.head);
}
