//! Each stand-in `git` stands alone on a `PATH` of its own directory, and each case writes its bytes in
//! a scratch directory of its own.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, symlink};
use std::path::Path;

use super::{RevisionError, git_revision, mappings_facts};
use crate::environ::Environ;
use crate::fixtures::tests::script;
use crate::hardware_host::within::within;
use crate::json::{self, Value};
use crate::paths::tests::Scratch;

/// Writes a program `git` of `body` in its own directory with [`script`] and returns the environment
/// whose `PATH` is that directory alone. The program runs under `/bin/sh` and calls its builtins alone.
fn stand_in(scratch: &Scratch, name: &str, body: &str) -> Environ {
    let directory = scratch.0.join(name);
    fs::create_dir(&directory).expect("made");
    script(&directory.join("git"), &format!("#!/bin/sh\n{body}\n"));
    vec![(OsString::from("PATH"), directory.into_os_string())]
}

/// git starts with exactly four arguments, `-C`, `<top>/scripts`, `rev-parse` and `HEAD`, a top with a
/// space arriving whole, and with the given environment alone: `GIT_NO_REPLACE_OBJECTS` reaches git
/// only when that environment holds it, and `CARGO_MANIFEST_DIR`, which the test process holds, never
/// does. The whitespace around git's output is dropped.
#[test]
fn the_revision_is_the_stripped_output_of_rev_parse() {
    let scratch = Scratch::new("launch-revision");
    let calls = scratch.0.join("calls");
    let body = format!(
        "printf '%s:' \"$#\" >> '{calls}'; printf '[%s]' \"$@\" >> '{calls}'; \
         printf '|%s|%s\\n' \"${{GIT_NO_REPLACE_OBJECTS-unset}}\" \"${{CARGO_MANIFEST_DIR-unset}}\" \
         >> '{calls}'; printf '  abc123\\r\\n\\n'",
        calls = calls.display()
    );
    let mut environ = stand_in(&scratch, "ok", &body);
    let top = Path::new("/checkout/my top");
    assert_eq!(git_revision(top, &environ).expect("a revision"), "abc123");
    environ.push((
        OsString::from("GIT_NO_REPLACE_OBJECTS"),
        OsString::from("1"),
    ));
    git_revision(top, &environ).expect("a revision");
    assert_eq!(
        fs::read_to_string(&calls).expect("the calls were written"),
        "4:[-C][/checkout/my top/scripts][rev-parse][HEAD]|unset|unset\n\
         4:[-C][/checkout/my top/scripts][rev-parse][HEAD]|1|unset\n"
    );
}

/// An exit other than 0 gives a sentence with the code, a signal's number negated, and the standard
/// error with `\r\n` read as `\n` and stripped.
#[test]
fn a_failed_rev_parse_names_its_code_and_its_error() {
    let scratch = Scratch::new("launch-failed");
    let fails = stand_in(
        &scratch,
        "fails",
        "printf ' bad\\r\\nthing \\n' >&2; printf 'out'; exit 3",
    );
    let error = git_revision(Path::new("/top"), &fails).expect_err("the exit is refused");
    assert_eq!(error.to_string(), "git rev-parse HEAD exited 3: bad\nthing");
    let killed = stand_in(&scratch, "killed", "kill -9 $$");
    let error = git_revision(Path::new("/top"), &killed).expect_err("the signal is refused");
    assert_eq!(error.to_string(), "git rev-parse HEAD exited -9: ");
}

/// A byte outside UTF-8 on either stream refuses the revision even when git exits 0, and the same
/// streams in UTF-8 give it.
#[test]
fn a_stream_outside_utf8_refuses_the_revision() {
    let scratch = Scratch::new("launch-undecodable");
    for (name, body) in [
        ("out", "printf 'abc\\377\\n'"),
        ("err", "printf 'abc\\n'; printf '\\377' >&2"),
    ] {
        let environ = stand_in(&scratch, name, body);
        assert!(
            matches!(
                git_revision(Path::new("/top"), &environ),
                Err(RevisionError::Undecodable)
            ),
            "{name}"
        );
    }
    let control = stand_in(&scratch, "control", "printf 'abc\\n'; printf 'x' >&2");
    assert_eq!(
        git_revision(Path::new("/top"), &control).expect("a revision"),
        "abc"
    );
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

fn facts(path: &OsStr) -> Option<String> {
    mappings_facts(path).map(|facts| json::text(&Value::Object(facts)))
}

/// The facts of a file's bytes: the first `format=` line's value, the sorted functions, the first
/// volume and address, a `\x1c` as a line boundary, and each undecodable byte replaced by U+FFFD; an
/// empty file holds no facts but its digest, and nulls. A link to the file gives its facts.
#[test]
fn the_mappings_facts_follow_the_bytes() {
    let scratch = Scratch::new("launch-mappings");
    let path = scratch.0.join("m");
    fs::write(
        &path,
        b"format=3\r\nnvme.bdf=b\neni.bdf=a\x1cnvme.volume=v=1\nnvme.volume=v2\nformat=9\n\xff\xfe=x\n\
          eni.ipv4=\xff1\neni.ipv4=z\n",
    )
    .expect("written");
    assert_eq!(
        facts(path.as_os_str()).expect("facts"),
        format!(
            r#"{{"path":"{}","sha256":"6199ee948e32ca69a0d8feaeca6c555e0141ec9b159048dc9dc50dc370cc83eb","format":"3","functions":["a","b"],"volume":"v=1","address":"\ufffd1"}}"#,
            path.display()
        )
    );
    let empty = scratch.0.join("e");
    fs::write(&empty, b"").expect("written");
    assert_eq!(
        facts(empty.as_os_str()).expect("facts"),
        format!(
            r#"{{"path":"{}","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","format":null,"functions":[],"volume":null,"address":null}}"#,
            empty.display()
        )
    );
    let link = scratch.0.join("link");
    symlink("m", &link).expect("linked");
    assert!(facts(link.as_os_str()).is_some());
}

/// A regular file named with a trailing `/` or `/.` opens by its pure spelling and gives the digest of
/// its bytes, while the recorded path keeps the caller's spelling.
#[test]
fn a_redundant_spelling_opens_the_file_and_keeps_its_text() {
    let scratch = Scratch::new("launch-spelling");
    let path = scratch.0.join("m");
    fs::write(&path, b"format=1\n").expect("written");
    for suffix in ["/", "/."] {
        let mut spelled = path.as_os_str().to_owned();
        spelled.push(suffix);
        assert_eq!(
            facts(&spelled).expect("facts"),
            format!(
                r#"{{"path":"{}{suffix}","sha256":"f83c8ebc16969e69f7098688dbfffdb3d4c763d9e58ac89e5252638f30638f5f","format":"1","functions":[],"volume":null,"address":null}}"#,
                path.display()
            )
        );
    }
}

/// The recorded path decodes the caller's bytes as UTF-8, each other byte held as the surrogate U+DC00
/// plus the byte.
#[test]
fn the_recorded_path_holds_each_byte_of_the_name() {
    let scratch = Scratch::new("launch-bytes");
    let mut name = scratch.0.as_os_str().as_bytes().to_vec();
    name.extend_from_slice(b"/m\xc3\xa9\xff");
    let path = OsStr::from_bytes(&name);
    fs::write(path, b"").expect("written");
    let recorded = mappings_facts(path).expect("facts");
    assert_eq!(
        json::text(recorded.get("path").expect("a path")),
        format!(r#""{}/m\u00e9\udcff""#, scratch.0.display())
    );
}

/// An empty path, an absent path, a name too long to look up, a directory and a FIFO give none, and
/// the FIFO's open does not wait for a writer.
#[test]
fn a_path_that_is_no_regular_file_gives_none() {
    let scratch = Scratch::new("launch-none");
    assert_eq!(mappings_facts(OsString::new().as_os_str()), None);
    assert_eq!(mappings_facts(scratch.0.join("absent").as_os_str()), None);
    assert_eq!(
        mappings_facts(scratch.0.join("n".repeat(300)).as_os_str()),
        None
    );
    assert_eq!(mappings_facts(scratch.0.as_os_str()), None);
    let fifo = scratch.0.join("fifo");
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo starts");
    assert!(made.success());
    assert!(
        fs::symlink_metadata(&fifo)
            .expect("the FIFO stands")
            .file_type()
            .is_fifo()
    );
    let probe = fifo.clone();
    let none = within("the FIFO's facts", move || {
        mappings_facts(probe.as_os_str()).is_none()
    });
    assert!(none);
}
