//! The cases of the planted commit and of the run's Git steps: the commit depends on the head and the
//! patch alone, takes the patch's bytes as they stand and signs nothing; a replacement object is not
//! read; and a Git step that fails names its command and keeps its error output in the work directory.

use std::time::Duration;

use super::fixture::{CAUSE, Fixture, patch_of, text_of, write_plant};

fn field(fx: &Fixture, name: &str, member: &str) -> String {
    let (_, plants) = fx.results();
    text_of(
        plants[name]
            .get(member)
            .unwrap_or_else(|| panic!("{name} holds {member}")),
    )
}

/// Another date, identity and commit encoding in the caller's configuration leave the planted commit
/// as it was.
#[test]
fn the_planted_commit_depends_on_the_head_and_the_patch_alone() {
    let mut fx = Fixture::new();
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let first = (field(&fx, "p-miss", "commit"), field(&fx, "p-miss", "tree"));
    std::fs::remove_file(&fx.score).expect("the first score is removed");
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(
        fx.scratch.join("gitconfig"),
        "[author]\n\tname = someone\n[committer]\n\tname = someone\n",
    )
    .expect("written");
    fx.git(&["config", "i18n.commitEncoding", "ISO-8859-1"]);
    let again = fx.scratch.join("again");
    let identity = [
        ("GIT_AUTHOR_NAME", "another"),
        ("GIT_COMMITTER_EMAIL", "another@invalid"),
    ];
    let done = fx.run_in(&["p-miss"], &[], &identity, Some(&again));
    assert_eq!(done.code, 0, "{}", done.stderr);
    let second = (field(&fx, "p-miss", "commit"), field(&fx, "p-miss", "tree"));
    assert_ne!(first.0, "null");
    assert_eq!(first, second);
}

/// A head with a signature and `log.showSignature` set give the planted commit the head's date: the
/// commit is the one a run without that setting makes.
#[test]
fn the_planted_commit_takes_the_head_s_date_beside_a_shown_signature() {
    let mut fx = Fixture::new();
    let text = fx.git(&["cat-file", "commit", "HEAD"]);
    let (header, message) = text.split_once("\n\n").expect("a commit holds a message");
    let signed = format!(
        "{header}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n fixture\n -----END PGP SIGNATURE-----\n\n{message}"
    );
    let path = fx.scratch.join("signed");
    std::fs::write(&path, signed).expect("written");
    let written = fx.git(&[
        "hash-object",
        "-t",
        "commit",
        "-w",
        &path.display().to_string(),
    ]);
    fx.git(&["reset", "--quiet", "--hard", written.trim()]);
    let verifier = fx.scratch.join("verifier");
    super::repository::executable(
        &verifier,
        "#!/bin/sh\necho 'gpg: Signature made a day' >&2\nexit 1\n",
    );
    fx.git(&["config", "gpg.program", &verifier.display().to_string()]);
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let first = field(&fx, "p-miss", "commit");
    fx.git(&["config", "log.showSignature", "true"]);
    let shown = std::process::Command::new("git")
        .arg("-C")
        .arg(&fx.repo)
        .args(["show", "--no-patch", "--format=%cI", "HEAD"])
        .env_clear()
        .envs(fx.env.iter().cloned())
        .output()
        .expect("git starts");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&shown.stdout),
        String::from_utf8_lossy(&shown.stderr)
    );
    assert!(all.contains("gpg: Signature made a day"), "{all}");
    let again = fx.scratch.join("again");
    let done = fx.run_in(&["p-miss"], &[], &[], Some(&again));
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_ne!(first, "null");
    assert_eq!(first, field(&fx, "p-miss", "commit"));
}

/// A patch line that ends in a space stands in the planted tree under `apply.whitespace = fix`.
#[test]
fn the_planted_tree_holds_the_patch_s_bytes_under_a_configured_whitespace_fix() {
    let mut fx = Fixture::new();
    write_plant(
        &fx.store,
        "p-space",
        ("pass", &["a"], CAUSE, "base"),
        &[],
        Some(&patch_of("pass ", "base")),
    );
    fx.commit("a patch with a trailing space");
    let done = fx.run(&["p-space"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let first = (
        field(&fx, "p-space", "tree"),
        field(&fx, "p-space", "commit"),
    );
    fx.git(&["config", "apply.whitespace", "fix"]);
    let again = fx.scratch.join("again");
    let done = fx.run_in(&["p-space"], &[], &[], Some(&again));
    assert_eq!(done.code, 0, "{}", done.stderr);
    assert_ne!(first.0, "null");
    assert_eq!(fx.git(&["show", &format!("{}:mode", first.1)]), "pass \n");
    assert_eq!(
        first,
        (
            field(&fx, "p-space", "tree"),
            field(&fx, "p-space", "commit")
        )
    );
}

/// The run builds the tree of the commit its score names, whatever `refs/replace` holds for it.
#[test]
fn a_replacement_of_the_head_commit_is_not_read() {
    let mut fx = Fixture::new();
    std::fs::write(fx.repo.join("mode"), "other\n").expect("written");
    fx.git(&["add", "mode"]);
    let tree = fx.git(&["write-tree"]).trim().to_owned();
    fx.git(&["reset", "--quiet", "--hard", "HEAD"]);
    let replacement = fx
        .git(&["commit-tree", &tree, "-m", "a replacement"])
        .trim()
        .to_owned();
    let head = fx.head.clone();
    fx.git(&["replace", &head, &replacement]);
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    let (written, _) = fx.results();
    assert_eq!(text_of(written.get("commit").expect("a commit")), fx.head);
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
}

/// A Git step that fails names its command in the reason, which holds no scratch path, and keeps its
/// error output in the plant's directory.
#[test]
fn a_failed_git_step_names_its_command_and_keeps_its_message_in_the_work_directory() {
    let mut fx = Fixture::new();
    let action = format!(
        "echo \"a signer refused at {}\" >&2; exit 7",
        fx.scratch.display()
    );
    let (name, path) = fx.git_shim("commit", &action);
    fx.run(&["p-miss"], &[(name, &path)]);
    let plant = fx.verdict(
        "p-miss",
        "no verdict",
        "`git commit` exited 7; its error is in plants/p-miss/git.err",
    );
    let reason = text_of(plant.get("reason").expect("a reason"));
    assert!(
        !reason.contains(&fx.scratch.display().to_string()),
        "{reason}"
    );
    let kept =
        std::fs::read_to_string(fx.work.join("plants/p-miss/git.err")).expect("the error is kept");
    assert!(kept.contains("a signer refused"), "{kept}");
}

/// The shim's check exits with status 128 to simulate a damaged index.
#[test]
fn a_patch_check_that_fails_for_another_cause_than_the_patch_is_no_plant_that_does_not_apply() {
    let mut fx = Fixture::new();
    let (name, path) = fx.git_shim("--check", "echo 'fatal: a damaged index' >&2; exit 128");
    let done = fx.run(&["p-miss"], &[(name, &path)]);
    assert_eq!(done.code, 3, "{}", done.stderr);
    fx.verdict(
        "p-miss",
        "no verdict",
        "`git apply` exited 128; its error is in plants/p-miss/git.err",
    );
    let kept =
        std::fs::read_to_string(fx.work.join("plants/p-miss/git.err")).expect("the error is kept");
    assert!(kept.contains("a damaged index"), "{kept}");
}

/// A patch that adds a lockfile fails its check against the run's lockfile and starts no `campaign`.
#[test]
fn a_patch_that_adds_a_lockfile_leaves_no_verdict() {
    let mut fx = Fixture::new();
    let patch = "--- /dev/null\n+++ b/Cargo.lock\n@@ -0,0 +1 @@\n+another resolution\n";
    write_plant(
        &fx.store,
        "p-ownlock",
        ("pass", &["a"], CAUSE, "base"),
        &[("files", "[\"Cargo.lock\"]")],
        Some(patch),
    );
    fx.commit("a plant that adds a lockfile");
    fx.run(&["p-ownlock"], &[]);
    fx.verdict(
        "p-ownlock",
        "no verdict",
        "`git apply` exited 1; its error is in plants/p-ownlock/git.err",
    );
    let kept = std::fs::read_to_string(fx.work.join("plants/p-ownlock/git.err"))
        .expect("the error is kept");
    assert!(kept.contains("Cargo.lock: already exists"), "{kept}");
    assert!(fx.calls(&[]).is_empty());
}

/// Commit signing in the caller's configuration signs no scratch commit.
#[test]
fn commit_signing_in_the_caller_s_configuration_signs_no_scratch_commit() {
    let mut fx = Fixture::new();
    let signer = fx.scratch.join("signer");
    super::repository::executable(
        &signer,
        &format!(
            "#!/bin/sh\ntouch {}\nexit 1\n",
            fx.scratch.join("signed").display()
        ),
    );
    std::fs::write(
        fx.scratch.join("gitconfig"),
        format!(
            "[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = {}\n",
            signer.display()
        ),
    )
    .expect("written");
    let done = fx.run(&["p-miss"], &[]);
    assert_eq!(done.code, 0, "{}", done.stderr);
    fx.verdict("p-miss", "missed", "each expected profile reached 300 runs");
    assert!(!fx.scratch.join("signed").exists());
}
