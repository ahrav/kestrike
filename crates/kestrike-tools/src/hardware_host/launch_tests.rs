//! The expected revisions, sentences and facts were recorded from the hardware lane's functions with
//! the same stand-in programs on `PATH` and the same bytes.

use std::ffi::{CString, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::{RevisionError, git_revision, mappings_facts};
use crate::environ::Environ;
use crate::json::{self, Value};
use crate::paths::tests::Scratch;

/// Writes a program `git` of `body` in its own directory and returns the environment whose `PATH` is
/// that directory alone. The program runs under `/bin/sh` and calls its builtins alone.
fn stand_in(scratch: &Scratch, name: &str, body: &str) -> Environ {
    let directory = scratch.0.join(name);
    fs::create_dir(&directory).expect("made");
    let git = directory.join("git");
    fs::write(&git, format!("#!/bin/sh\n{body}\n")).expect("written");
    fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).expect("executable");
    vec![(OsString::from("PATH"), directory.into_os_string())]
}

/// [`git_revision`], started again while the stand-in is busy: another case's fork can hold a copy of
/// the descriptor that wrote it until that fork's exec.
fn revision(top: &Path, environ: &Environ) -> Result<String, RevisionError> {
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        match git_revision(top, environ) {
            Err(RevisionError::Start(error))
                if error.raw_os_error() == Some(libc::ETXTBSY) && Instant::now() < end =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            done => return done,
        }
    }
}

/// The revision is git's output stripped; git starts in `<top>/scripts` with `rev-parse HEAD` and the
/// environment given, which here lacks `GIT_NO_REPLACE_OBJECTS`, while an environment that holds it
/// passes it on.
#[test]
fn the_revision_is_the_stripped_output_of_rev_parse() {
    let scratch = Scratch::new("launch-revision");
    let calls = scratch.0.join("calls");
    let body = format!(
        "printf '%s|%s\\n' \"$*\" \"${{GIT_NO_REPLACE_OBJECTS-unset}}\" >> '{}'; printf '  abc123\\r\\n\\n'",
        calls.display()
    );
    let mut environ = stand_in(&scratch, "ok", &body);
    let top = Path::new("/checkout/top");
    assert_eq!(revision(top, &environ).expect("a revision"), "abc123");
    environ.push((
        OsString::from("GIT_NO_REPLACE_OBJECTS"),
        OsString::from("1"),
    ));
    revision(top, &environ).expect("a revision");
    assert_eq!(
        fs::read_to_string(&calls).expect("the calls were written"),
        "-C /checkout/top/scripts rev-parse HEAD|unset\n-C /checkout/top/scripts rev-parse HEAD|1\n"
    );
}

/// An exit other than 0 gives the lane's sentence with the code, a signal's number negated, and the
/// standard error with `\r\n` read as `\n` and stripped.
#[test]
fn a_failed_rev_parse_gives_the_lane_sentence() {
    let scratch = Scratch::new("launch-failed");
    let fails = stand_in(
        &scratch,
        "fails",
        "printf ' bad\\r\\nthing \\n' >&2; printf 'out'; exit 3",
    );
    let error = revision(Path::new("/top"), &fails).expect_err("the exit is refused");
    assert_eq!(error.to_string(), "git rev-parse HEAD exited 3: bad\nthing");
    let killed = stand_in(&scratch, "killed", "kill -9 $$");
    let error = revision(Path::new("/top"), &killed).expect_err("the signal is refused");
    assert_eq!(error.to_string(), "git rev-parse HEAD exited -9: ");
}

/// A `PATH` without `git` gives the start's error.
#[test]
fn a_git_that_cannot_start_is_its_own_error() {
    let scratch = Scratch::new("launch-start");
    let environ = vec![(OsString::from("PATH"), scratch.0.clone().into_os_string())];
    match git_revision(Path::new("/top"), &environ) {
        Err(RevisionError::Start(error)) => assert_eq!(error.raw_os_error(), Some(libc::ENOENT)),
        other => panic!("git cannot start: {other:?}"),
    }
}

/// The facts come from one read of the bytes: the first `format=` line's value, the sorted functions,
/// the first volume, an absent address as null, a `\x1c` as a line boundary, and undecodable bytes
/// replaced; an empty file holds no facts but its digest.
#[test]
fn the_mappings_facts_follow_the_lane() {
    let scratch = Scratch::new("launch-mappings");
    let path = scratch.0.join("m");
    fs::write(
        &path,
        b"format=3\r\nnvme.bdf=b\neni.bdf=a\x1cnvme.volume=v=1\nnvme.volume=v2\nformat=9\n\xff\xfe=x\n",
    )
    .expect("written");
    let facts = |path: &Path| {
        mappings_facts(path.as_os_str()).map(|facts| json::text(&Value::Object(facts)))
    };
    assert_eq!(
        facts(&path).expect("facts"),
        format!(
            r#"{{"path":"{}","sha256":"5e45c66f100c814a9dbf3a0ff2f1c030ad413bcb3fbcd025545c1e94e20cd23c","format":"3","functions":["a","b"],"volume":"v=1","address":null}}"#,
            path.display()
        )
    );
    let empty = scratch.0.join("e");
    fs::write(&empty, b"").expect("written");
    assert_eq!(
        facts(&empty).expect("facts"),
        format!(
            r#"{{"path":"{}","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","format":null,"functions":[],"volume":null,"address":null}}"#,
            empty.display()
        )
    );
    let link = scratch.0.join("link");
    symlink("m", &link).expect("linked");
    assert!(facts(&link).is_some());
}

/// An empty path, an absent path, a directory and a FIFO give none, and the FIFO's open does not wait
/// for a writer.
#[test]
fn a_path_that_is_no_regular_file_gives_none() {
    let scratch = Scratch::new("launch-none");
    assert_eq!(mappings_facts(OsString::new().as_os_str()), None);
    assert_eq!(mappings_facts(scratch.0.join("absent").as_os_str()), None);
    assert_eq!(mappings_facts(scratch.0.as_os_str()), None);
    let fifo = scratch.0.join("fifo");
    let name = CString::new(fifo.as_os_str().as_bytes()).expect("no NUL");
    // SAFETY: `name` is a NUL-terminated path that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert_eq!(mappings_facts(fifo.as_os_str()), None);
}
