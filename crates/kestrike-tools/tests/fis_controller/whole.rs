//! The whole-file write: each state of the name, a failure at each of steps 3 to 6 and at step 8, and
//! the directories a write makes and syncs. Each row's error text, the file's text and the
//! directory's entries after the write are the write's steps' on each arrangement.

use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kestrike_tools::fis_controller::{create_partial, write_file, write_file_by};
use kestrike_tools::host_stop::Disk;

use crate::fis_support::steps::Steps;
use crate::fis_support::{Scratch, listing};

/// The outcome of one write: its error, the file's text where a regular file stands at the name, and
/// the directory's entries.
#[derive(Debug, PartialEq)]
struct Outcome {
    error: Option<String>,
    content: Option<String>,
    listing: Vec<String>,
}

fn outcome(
    scratch: &Scratch,
    directory: &Path,
    target: &Path,
    result: Result<(), String>,
) -> Outcome {
    let regular = fs::symlink_metadata(target).is_ok_and(|metadata| metadata.is_file());
    Outcome {
        error: result.err().map(|error| scratch.norm(&error)),
        content: regular.then(|| fs::read_to_string(target).expect("the file reads")),
        listing: listing(directory),
    }
}

fn expected(error: Option<&str>, content: Option<&str>, listing: &[&str]) -> Outcome {
    Outcome {
        error: error.map(str::to_owned),
        content: content.map(str::to_owned),
        listing: listing.iter().map(|name| (*name).to_owned()).collect(),
    }
}

/// A directory `write-<name>` under the scratch directory and the path `f.json` in it.
fn place(scratch: &Scratch, name: &str) -> (PathBuf, PathBuf) {
    let directory = scratch.path().join(format!("write-{name}"));
    fs::create_dir(&directory).expect("the directory is made");
    let target = directory.join("f.json");
    (directory, target)
}

fn written(files: &Steps, target: &Path) -> Result<(), String> {
    write_file(files, target, "new\n").map_err(|error| error.to_string())
}

/// An absent name, a present file and a partial file a killed write left each end with the new text
/// alone at the name.
#[test]
fn a_write_puts_the_new_text_whole_at_the_name() {
    let scratch = Scratch::new("write-states");
    for (name, prepare) in [
        ("absent", None),
        ("present", Some(("f.json", "old"))),
        ("partial", Some(("f.json.partial", "junk"))),
    ] {
        let (directory, target) = place(&scratch, name);
        if let Some((file, text)) = prepare {
            fs::write(directory.join(file), text).expect("the file is written");
        }
        let got = outcome(
            &scratch,
            &directory,
            &target,
            written(&Steps::default(), &target),
        );
        assert_eq!(got, expected(None, Some("new\n"), &["f.json"]), "{name}");
    }
}

/// A link at the name, to a file or to nothing, is the error `ELOOP`: the link and its target stay
/// and no partial file is made.
#[test]
fn a_link_at_the_name_is_refused_and_left_as_it_stands() {
    let scratch = Scratch::new("write-link");
    let (directory, target) = place(&scratch, "link");
    fs::write(directory.join("target"), "kept").expect("the target is written");
    symlink(directory.join("target"), &target).expect("the link is made");
    let got = outcome(
        &scratch,
        &directory,
        &target,
        written(&Steps::default(), &target),
    );
    let refusal = "[Errno 40] Too many levels of symbolic links: '<d>/write-link/f.json'";
    assert_eq!(got, expected(Some(refusal), None, &["f.json@", "target"]));
    assert_eq!(
        fs::read_to_string(directory.join("target")).expect("reads"),
        "kept"
    );
    let (directory, target) = place(&scratch, "dangling");
    symlink(directory.join("nowhere"), &target).expect("the link is made");
    let got = outcome(
        &scratch,
        &directory,
        &target,
        written(&Steps::default(), &target),
    );
    let refusal = "[Errno 40] Too many levels of symbolic links: '<d>/write-dangling/f.json'";
    assert_eq!(got, expected(Some(refusal), None, &["f.json@"]));
}

/// A failure at step 3 (a directory at the partial name), step 4 (the create), step 5 (the file's
/// sync) or step 6 (a directory at the name) returns the system's error and leaves the previous
/// version at the name; the partial file the write made is removed, and an entry it could not remove
/// stays.
#[test]
fn a_write_that_fails_leaves_the_previous_version_and_no_partial_file() {
    let scratch = Scratch::new("write-failures");
    let (directory, target) = place(&scratch, "step3");
    fs::write(&target, "old").expect("the file is written");
    fs::create_dir(directory.join("f.json.partial")).expect("the directory is made");
    let got = outcome(
        &scratch,
        &directory,
        &target,
        written(&Steps::default(), &target),
    );
    let error = "[Errno 21] Is a directory: '<d>/write-step3/f.json.partial'";
    assert_eq!(
        got,
        expected(Some(error), Some("old"), &["f.json", "f.json.partial/"])
    );

    let (directory, target) = place(&scratch, "step4");
    fs::write(&target, "old").expect("the file is written");
    let refused = |_: &Path| Err(io::Error::from_raw_os_error(libc::EACCES));
    let result = write_file_by(&Disk, refused, &target, "new\n").map_err(|error| error.to_string());
    let got = outcome(&scratch, &directory, &target, result);
    let error = "[Errno 13] Permission denied: '<d>/write-step4/f.json.partial'";
    assert_eq!(got, expected(Some(error), Some("old"), &["f.json"]));

    let (directory, target) = place(&scratch, "step5");
    fs::write(&target, "old").expect("the file is written");
    let files = Steps {
        file_sync: true,
        probe: Some(directory.join("f.json.partial")),
        ..Steps::default()
    };
    let got = outcome(&scratch, &directory, &target, written(&files, &target));
    assert_eq!(
        got,
        expected(
            Some("[Errno 5] Input/output error"),
            Some("old"),
            &["f.json"]
        )
    );
    assert_eq!(
        *files.probed.borrow(),
        Some(true),
        "the partial file stood when its sync failed, and the failure removed it"
    );

    let (directory, target) = place(&scratch, "step6");
    fs::create_dir(&target).expect("the directory is made");
    fs::write(target.join("inner"), "x").expect("the file is written");
    let got = outcome(
        &scratch,
        &directory,
        &target,
        written(&Steps::default(), &target),
    );
    let error =
        "[Errno 21] Is a directory: '<d>/write-step6/f.json.partial' -> '<d>/write-step6/f.json'";
    assert_eq!(got, expected(Some(error), None, &["f.json/"]));
    assert_eq!(
        listing(&target),
        ["inner"],
        "the directory at the name keeps its entry"
    );
}

/// Step 4 creates `<name>.partial` exclusively, refusing an entry or a link at its name.
#[test]
fn the_partial_file_is_made_exclusively() {
    let scratch = Scratch::new("write-create");
    let (directory, _) = place(&scratch, "create");
    let partial = directory.join("f.json.partial");
    fs::write(&partial, "junk").expect("the file is written");
    let error = create_partial(&partial).expect_err("an existing file is refused");
    assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
    fs::remove_file(&partial).expect("removed");
    symlink(directory.join("nowhere"), &partial).expect("linked");
    let error = create_partial(&partial).expect_err("a link is refused");
    assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
    assert!(
        !directory.join("nowhere").exists(),
        "the link's target is not made"
    );
    fs::remove_file(&partial).expect("removed");
    drop(create_partial(&partial).expect("the control is made"));
    assert!(
        partial.is_file(),
        "with nothing at the name the create succeeds"
    );
}

/// The variable that marks the child of [`the_partial_file_has_mode_0644_and_keeps_it_at_the_name`].
const UNMASKED: &str = "KESTRIKE_TOOLS_FIS_UNMASKED";

/// The partial file is made with mode 0644 and the rename keeps it at the name. A umask of 0 is
/// process-wide, so the case runs again in a child started by `/bin/sh` after `umask 0`, where any
/// other requested mode would show, and asserts the exact mode there.
#[test]
fn the_partial_file_has_mode_0644_and_keeps_it_at_the_name() {
    let mode = |path: &Path| fs::metadata(path).expect("stat").permissions().mode() & 0o7777;
    if std::env::var_os(UNMASKED).is_some() {
        let scratch = Scratch::new("write-mode");
        let (directory, target) = place(&scratch, "mode");
        let partial = directory.join("f.json.partial");
        drop(create_partial(&partial).expect("the partial file is made"));
        assert_eq!(mode(&partial), 0o644, "the partial file's mode");
        fs::remove_file(&partial).expect("removed");
        write_file(&Disk, &target, "new\n").expect("the file is written");
        assert_eq!(mode(&target), 0o644, "the mode at the name");
        return;
    }
    let exe = std::env::current_exe().expect("the test executable resolves");
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg("umask 0 && exec \"$0\" --exact --test-threads=1 \"$1\"")
        .arg(&exe)
        .arg("fis_controller::whole::the_partial_file_has_mode_0644_and_keeps_it_at_the_name")
        .env(UNMASKED, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .expect("the child runs");
    assert!(status.success(), "the child's case passes: {status}");
}

/// A `mkdir` that fails because another maker's directory stands at the path goes on: the parent is
/// synced and the file written. Control: the same `EEXIST` with no directory there fails the write
/// with the `mkdir`'s error.
#[test]
fn a_directory_another_maker_made_first_is_taken() {
    let scratch = Scratch::new("write-raced");
    for made in [true, false] {
        let base = scratch.path().join(format!("raced-{made}"));
        fs::create_dir(&base).expect("the directory is made");
        let target = base.join("sub/f.json");
        let files = Steps {
            mkdir: Some((base.join("sub"), made)),
            ..Steps::default()
        };
        let result = written(&files, &target);
        if made {
            assert_eq!(result, Ok(()));
            assert_eq!(
                files.opened.borrow().first(),
                Some(&base),
                "the parent is synced"
            );
            assert_eq!(fs::read_to_string(&target).expect("reads"), "new\n");
        } else {
            let error = result.expect_err("the write fails");
            assert_eq!(
                scratch.norm(&error),
                "[Errno 17] File exists: '<d>/raced-false/sub'"
            );
        }
    }
}

/// A failed sync of the parent after the rename returns its error with the new file at the name: a
/// failed open names the directory, a failed sync names none.
#[test]
fn a_failed_sync_of_the_directory_returns_with_the_new_file_in_place() {
    let scratch = Scratch::new("write-step8");
    let (directory, target) = place(&scratch, "step8");
    fs::write(&target, "old").expect("the file is written");
    let files = Steps {
        directory_sync: Some(directory.clone()),
        ..Steps::default()
    };
    let got = outcome(&scratch, &directory, &target, written(&files, &target));
    assert_eq!(
        got,
        expected(
            Some("[Errno 5] Input/output error"),
            Some("new\n"),
            &["f.json"]
        )
    );
    let (directory, target) = place(&scratch, "step8-open");
    fs::write(&target, "old").expect("the file is written");
    let files = Steps {
        open: Some(directory.clone()),
        ..Steps::default()
    };
    let got = outcome(&scratch, &directory, &target, written(&files, &target));
    let error = "[Errno 13] Permission denied: '<d>/write-step8-open'";
    assert_eq!(got, expected(Some(error), Some("new\n"), &["f.json"]));
}

/// A write under missing directories makes each, from the highest, and syncs the parent of each
/// before the file's own directory; an ancestor that is a file stops the write at the `mkdir` under
/// it with nothing made.
#[test]
fn a_write_makes_each_missing_directory_and_syncs_its_parent() {
    let scratch = Scratch::new("write-deep");
    let base = scratch.path();
    let target = base.join("write-deep/a/b/f.json");
    let files = Steps::default();
    assert_eq!(written(&files, &target), Ok(()));
    let synced: Vec<String> = files
        .opened
        .borrow()
        .iter()
        .map(|path| scratch.norm(&path.display().to_string()))
        .collect();
    assert_eq!(
        synced,
        [
            "<d>",
            "<d>/write-deep",
            "<d>/write-deep/a",
            "<d>/write-deep/a/b"
        ]
    );
    assert_eq!(fs::read_to_string(&target).expect("reads"), "new\n");

    let above = base.join("write-file-above");
    fs::create_dir(&above).expect("the directory is made");
    fs::write(above.join("plain"), "x").expect("the file is written");
    let blocked = above.join("plain/sub/f.json");
    let got = outcome(
        &scratch,
        &above,
        &blocked,
        written(&Steps::default(), &blocked),
    );
    let error = "[Errno 20] Not a directory: '<d>/write-file-above/plain/sub'";
    assert_eq!(got, expected(Some(error), None, &["plain"]));
}
