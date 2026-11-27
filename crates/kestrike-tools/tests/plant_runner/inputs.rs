//! The checks outside the store, in their order: the Git variables, the invoking directory and its
//! checkout, the head commit, `Cargo.lock`, the `campaign` binary and the work directory; the failures
//! outside a plant; and a run's checked inputs. Each refusal leaves no path made and `git status` as it
//! was.

use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use kestrike_tools::json::Integer;
use kestrike_tools::ownership::foreign_toolchain_paths;
use kestrike_tools::plants::{Outcome, prepare};
use kestrike_tools::python::hexdigest;
use kestrike_tools::text::Text;

use super::repository::{
    CAMPAIGN, Call, Change, LOCK, Repository, chmod, is_root, patch, private_dir, shown, write,
};

const VARIABLES: [&str; 5] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
];
const NO_LOCK: &str = "rejected: the checkout holds no readable Cargo.lock (no regular file); build it \
                       once to resolve the dependencies every archive of the run shares";

fn redirect(names: &str) -> String {
    format!(
        "rejected: {names} would point the run's Git commands at another repository or index; unset them"
    )
}

/// Each Git variable that redirects Git is refused while set, an empty value included, and the set ones
/// are named in a fixed order; the refusal comes before the invoking directory is judged.
#[test]
fn each_git_variable_is_refused_before_the_checkout() {
    let repository = Repository::new();
    for name in VARIABLES {
        let call = repository.call(&[]).set(name, "");
        assert_eq!(repository.refused(&call), redirect(name));
    }
    let mut call = repository.call(&[]).here(&repository.tmp);
    for name in VARIABLES.iter().rev() {
        call = call.set(name, repository.scratch.as_os_str());
    }
    assert_eq!(repository.refused(&call), redirect(&VARIABLES.join(", ")));
}

/// A directory outside every checkout and a checkout without a commit are refused.
#[test]
fn the_invoking_directory_lies_in_a_checkout_with_a_head_commit() {
    let repository = Repository::new();
    let call = repository.call(&[]).here(&repository.tmp);
    assert_eq!(
        repository.refused(&call),
        "rejected: the invoking directory is outside a Git checkout"
    );
    let empty = repository.scratch.join("empty");
    private_dir(&empty);
    let init = std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&empty)
        .env_clear()
        .envs(repository.env())
        .status()
        .expect("git starts");
    assert!(init.success());
    let call = repository.call(&[]).here(&empty);
    assert_eq!(
        repository.refused(&call),
        "rejected: the checkout names no HEAD commit"
    );
}

/// An invoking directory that cannot be read is a failure outside a plant, after the Git variables.
#[test]
fn an_unreadable_invoking_directory_is_a_failure() {
    let repository = Repository::new();
    let gone = || Err(io::Error::from_raw_os_error(libc::ENOENT));
    let Outcome::Failed(reason) = prepare(&[], repository.env(), gone()) else {
        panic!("an unreadable directory fails");
    };
    assert_eq!(
        reason.to_string(),
        "the invoking directory cannot be read: No such file or directory (os error 2)"
    );
    let mut env = repository.env();
    env.push((OsString::from("GIT_DIR"), OsString::from("x")));
    let Outcome::Rejected(reason) = prepare(&[], env, gone()) else {
        panic!("the variable is refused first");
    };
    assert_eq!(format!("rejected: {reason}"), redirect("GIT_DIR"));
}

/// `Cargo.lock` missing, a link, a directory or a FIFO has no regular file; one the user cannot read
/// names the operating system's text.
#[test]
fn cargo_lock_is_a_readable_regular_file() {
    let lock = |repository: &Repository| repository.path("Cargo.lock");
    let rows: [(&str, Change); 4] = [
        ("missing", &|r| fs::remove_file(lock(r)).expect("removed")),
        ("a link", &|r| {
            let kept = r.scratch.join("Cargo.lock");
            fs::rename(lock(r), &kept).expect("moved");
            symlink(&kept, lock(r)).expect("linked");
        }),
        ("a directory", &|r| {
            fs::remove_file(lock(r)).expect("removed");
            fs::create_dir(lock(r)).expect("made");
        }),
        ("a FIFO", &|r| {
            fs::remove_file(lock(r)).expect("removed");
            let name = CString::new(lock(r).as_os_str().as_bytes()).expect("no NUL");
            // SAFETY: `mkfifo` reads the NUL-terminated name, which `name` owns for the call.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        }),
    ];
    for (state, change) in rows {
        let repository = Repository::new();
        change(&repository);
        assert_eq!(
            repository.refused(&repository.call(&[])),
            NO_LOCK,
            "{state}"
        );
    }
    if !is_root() {
        let repository = Repository::new();
        chmod(&lock(&repository), 0o000);
        assert_eq!(
            repository.refused(&repository.call(&[])),
            NO_LOCK.replace("(no regular file)", "(Permission denied)")
        );
    }
}

/// `--campaign` with a `/` is that path from the invoking directory; any other value is looked up in
/// `PATH`, where an empty entry is the invoking directory; with `PATH` unset, and for a value
/// that names no file the user may execute, no binary is found.
#[test]
fn campaign_names_a_file_the_user_may_execute() {
    let repository = Repository::new();
    write(&repository.scratch.join("notes"), "notes\n");
    chmod(&repository.scratch.join("notes"), 0o644);
    let none = |value: &str| format!("rejected: no campaign binary at {value}");
    let rows = [
        (repository.call(&["--campaign", "nothing"]), none("nothing")),
        (
            repository.call(&["--campaign", "../notes"]),
            none("../notes"),
        ),
        (repository.call(&["--campaign", "../bin"]), none("../bin")),
        (repository.call(&["--campaign", ""]), none("")),
        (repository.call(&[]).unset("PATH"), none("campaign")),
    ];
    for (call, expected) in rows {
        assert_eq!(repository.refused(&call), expected, "{:?}", call.args);
    }
    let sealed = repository.bin.join("sealed");
    write(&sealed, CAMPAIGN);
    chmod(&sealed, 0o111);
    if !is_root() {
        assert_eq!(
            repository.refused(&repository.call(&["--campaign", "sealed"])),
            format!(
                "rejected: the campaign binary cannot be read: {}: Permission denied (os error 13)",
                shown(&sealed)
            )
        );
    }
}

/// A found `campaign` is resolved through its links and hashed; `PATH`'s empty entry names the invoking
/// directory.
#[test]
fn campaign_is_resolved_and_hashed() {
    let repository = Repository::new();
    let campaign = repository.bin.join("campaign");
    symlink("campaign", repository.bin.join("linked")).expect("linked");
    let runs = |call: &Call| match repository.prepare(call) {
        Outcome::Run(inputs) => (
            inputs.campaign().to_path_buf(),
            inputs.campaign_sha256().to_owned(),
        ),
        other => panic!("{:?} runs, not {other:?}", call.args),
    };
    let digest = hexdigest(CAMPAIGN.as_bytes());
    assert_eq!(
        runs(&repository.call(&["--campaign", "linked"])),
        (campaign.clone(), digest.clone())
    );
    assert_eq!(
        runs(&repository.call(&["--campaign", "../bin/linked"])),
        (campaign, digest.clone())
    );
    let local = repository.path("campaign");
    write(&local, "#!/bin/sh\nexit 1\n");
    chmod(&local, 0o700);
    let mut path = OsString::from(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let found = runs(&repository.call(&[]).set("PATH", &path));
    assert_eq!(found, (local, hexdigest(b"#!/bin/sh\nexit 1\n")));
}

fn foreign(parent: &Path) -> String {
    let found = foreign_toolchain_paths(parent).expect("the ancestors stat");
    let shown: Vec<String> = found.iter().map(|path| shown(path)).collect();
    shown.join(", ")
}

const CHOSEN_WAY: &str = "choose a work directory under a directory only you control";
const DEFAULT_WAY: &str =
    "pass --work DIR or set TMPDIR, naming a directory only you control on xfs or journaled ext4";

fn shared(names: &str, way: &str) -> String {
    format!(
        "rejected: another user owns or can write {names}, and so can configure Cargo in the run's \
         worktrees; {way}"
    )
}

/// The work directory must be new, outside the checkout, and under ancestors only this user or root owns
/// and can write; `TMPDIR`, read from the invoking directory, or `/tmp` when it is unset or empty, holds
/// the default one.
#[test]
fn the_work_directory_is_new_private_and_outside_the_checkout() {
    let repository = Repository::new();
    let shared_dir = repository.scratch.join("shared");
    private_dir(&shared_dir);
    chmod(&shared_dir, 0o777);
    let top = shown(&repository.top);
    let inside =
        |place: &str| format!("rejected: the work directory {place} lies inside the checkout");
    let tmp = shown(&repository.tmp);
    let rows = [
        (
            repository.call(&["--work", &tmp]),
            format!("rejected: the work directory: {tmp}: File exists (os error 17)"),
        ),
        (repository.call(&["--work", "."]), inside(&top)),
        (repository.call(&["--work", ""]), inside(&top)),
        (
            repository.call(&["--work", "w"]),
            inside(&format!("{top}/w")),
        ),
        (
            repository.call(&["--work", "a/../../checkout/b"]),
            inside(&format!("{top}/b")),
        ),
        (
            repository.call(&[]).set("TMPDIR", "rel"),
            inside(&format!("{top}/rel")),
        ),
        (
            repository.call(&["--work", &format!("{}/w", shown(&shared_dir))]),
            shared(&shown(&shared_dir), CHOSEN_WAY),
        ),
        (
            repository.call(&[]).set("TMPDIR", &shared_dir),
            shared(&shown(&shared_dir), DEFAULT_WAY),
        ),
        (
            repository.call(&[]).unset("TMPDIR"),
            shared(&foreign(Path::new("/tmp")), DEFAULT_WAY),
        ),
        (
            repository.call(&[]).set("TMPDIR", ""),
            shared(&foreign(Path::new("/tmp")), DEFAULT_WAY),
        ),
    ];
    for (call, expected) in rows {
        assert_eq!(repository.refused(&call), expected, "{:?}", call.env.last());
    }
}

/// Missing ancestors of `--work` are made with no bit for the group or others, and stay when the work
/// directory itself cannot be made; the parent's links are resolved.
#[test]
fn missing_ancestors_are_made_private_and_links_resolved() {
    let repository = Repository::new();
    let made = repository.scratch.join("made");
    let long = made.join("n".repeat(300));
    let Outcome::Rejected(reason) =
        repository.prepare(&repository.call(&["--work", &shown(&long)]))
    else {
        panic!("a name past the limit is refused");
    };
    assert_eq!(
        reason.to_string(),
        format!(
            "the work directory: {}: File name too long (os error 36)",
            shown(&long)
        )
    );
    let mode = fs::metadata(&made)
        .expect("the ancestor stays")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "{mode:o}");
    let real = repository.scratch.join("real");
    private_dir(&real);
    symlink(&real, repository.scratch.join("linked")).expect("linked");
    let rows: [(PathBuf, PathBuf); 3] = [
        (
            repository.scratch.join("new/a/b"),
            repository.scratch.join("new/a/b"),
        ),
        (repository.scratch.join("linked/w"), real.join("w")),
        (repository.top.join("../w2"), repository.scratch.join("w2")),
    ];
    for (given, expected) in rows {
        let Outcome::Run(inputs) =
            repository.prepare(&repository.call(&["--work", &shown(&given)]))
        else {
            panic!("{} runs", given.display());
        };
        assert_eq!(inputs.work(), expected);
        for made in expected
            .ancestors()
            .take_while(|made| made.starts_with(&repository.scratch))
        {
            let mode = fs::metadata(made).expect("made").permissions().mode();
            assert_eq!(mode & 0o077, 0, "{}: {mode:o}", made.display());
        }
    }
}

/// An ancestor of the work directory whose `stat` fails for want of permission is a failure outside a
/// plant.
#[test]
fn an_unreadable_ancestor_is_a_failure() {
    if is_root() {
        return;
    }
    let repository = Repository::new();
    let locked = repository.scratch.join("locked");
    private_dir(&locked);
    chmod(&locked, 0o000);
    let work = locked.join("inner/w");
    assert_eq!(
        repository.refused(&repository.call(&["--work", &shown(&work)])),
        format!(
            "failed: an ancestor of the work directory cannot be read: {}: Permission denied (os error 13)",
            shown(&locked.join("inner"))
        )
    );
}

/// `standin` puts a `git` first on `PATH` that exits `code`, after printing `out`, when its arguments hold
/// the word `when`, and runs the host's Git otherwise.
fn standin(repository: &Repository, when: &str, out: &str, code: u8) -> Call {
    let real = std::process::Command::new("sh")
        .args(["-c", "command -v git"])
        .output()
        .expect("sh starts");
    let real = String::from_utf8(real.stdout)
        .expect("UTF-8")
        .trim()
        .to_owned();
    let dir = repository
        .scratch
        .join(format!("standin{}", when.trim_start_matches('-')));
    private_dir(&dir);
    let script = dir.join("git");
    write(
        &script,
        format!(
            "#!/bin/sh\nfor arg; do [ \"$arg\" = '{when}' ] && {{ printf '{out}'; exit {code}; }}; done\n\
             exec '{real}' \"$@\"\n"
        ),
    );
    chmod(&script, 0o755);
    let mut path = dir.into_os_string();
    path.push(":");
    path.push(
        repository
            .env()
            .iter()
            .find(|(name, _)| name == "PATH")
            .expect("PATH")
            .1
            .clone(),
    );
    repository.call(&[]).set("PATH", path)
}

/// A checked `git status` that exits nonzero, Git output that is no UTF-8 and a Git that cannot start are
/// failures outside a plant; a store `HEAD` cannot list is refused.
#[test]
fn git_failures_outside_a_plant() {
    let repository = Repository::new();
    let rows = [
        (
            standin(&repository, "status", "", 5),
            "failed: `git status` exited 5".to_owned(),
        ),
        (
            standin(&repository, "--name-only", "", 5),
            "rejected: the plant store of HEAD cannot be listed: `git ls-tree` exited 5".to_owned(),
        ),
        (
            standin(&repository, "--show-toplevel", "\\377\\n", 0),
            "failed: `git rev-parse` wrote output that is no UTF-8".to_owned(),
        ),
        (
            repository.call(&[]).set("PATH", &repository.bin),
            "failed: git cannot be started: No such file or directory (os error 2)".to_owned(),
        ),
    ];
    for (call, expected) in rows {
        assert_eq!(repository.refused(&call), expected);
    }
}

/// A run's inputs: the resolved top from a directory below it through a link, the head commit, the
/// plants with their records and patches, `Cargo.lock`'s bytes, the resolved and hashed `campaign`, the
/// options, the score's path, the environment with `GIT_NO_REPLACE_OBJECTS=1`, and a new private work
/// directory under `TMPDIR`.
#[test]
fn a_run_holds_every_checked_input() {
    let repository = Repository::new();
    let link = repository.scratch.join("link");
    symlink(&repository.top, &link).expect("linked");
    let call = repository
        .call(&["--plant", "alpha"])
        .here(link.join("src"));
    let Outcome::Run(inputs) = repository.prepare(&call) else {
        panic!("the run's inputs check");
    };
    assert_eq!(inputs.top(), repository.top);
    assert_eq!(inputs.head(), repository.head());
    let [alpha] = inputs.plants() else {
        panic!("one plant is selected");
    };
    assert_eq!(alpha.id(), &Text::from("alpha"));
    assert_eq!(alpha.row(), &Integer::from(7u64));
    assert_eq!(alpha.files(), [&Text::from("src/lib.rs")]);
    assert_eq!(
        alpha.expected(),
        [&Text::from("smoke"), &Text::from("crash-loop")]
    );
    assert_eq!(alpha.restores(), &Text::from("the defect the fix removed"));
    assert_eq!(alpha.proof(), &Text::from("tests::the_proof"));
    assert_eq!(alpha.miss_cause(), None);
    let fix: Vec<String> = alpha
        .fix()
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    assert_eq!(fix, ["pull_request", "commit"]);
    assert_eq!(alpha.patch(), patch("src/lib.rs").as_bytes());
    assert_eq!(inputs.lock(), LOCK.as_bytes());
    assert_eq!(inputs.campaign(), repository.bin.join("campaign"));
    assert_eq!(inputs.campaign_sha256(), hexdigest(CAMPAIGN.as_bytes()));
    assert_eq!(
        inputs.score(),
        repository.path("verification/plants/score.json")
    );
    let replace = inputs
        .env()
        .iter()
        .find(|(name, _)| name == "GIT_NO_REPLACE_OBJECTS");
    assert_eq!(
        replace.map(|(_, value)| value.as_os_str()),
        Some("1".as_ref())
    );
    let work = inputs.work();
    assert_eq!(work.parent(), Some(repository.tmp.as_path()));
    let name = work
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a UTF-8 name");
    let letters = name.strip_prefix("plant-runner-").expect("the prefix");
    assert_eq!(letters.len(), 8, "{name}");
    let mode = fs::metadata(work).expect("made").permissions().mode();
    assert_eq!(mode & 0o077, 0, "{mode:o}");
}

/// A parent of `--work` whose links loop cannot be resolved and is refused.
#[test]
fn a_parent_whose_links_loop_is_refused() {
    let repository = Repository::new();
    let looped = repository.scratch.join("loop");
    symlink("loop", &looped).expect("linked");
    let call = repository.call(&["--work", &shown(&looped.join("w"))]);
    assert_eq!(
        repository.refused(&call),
        format!(
            "rejected: the work directory's parent cannot be resolved: symlink loop from {}",
            shown(&looped)
        )
    );
}
