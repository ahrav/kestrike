//! Each row's expected result is the judge's at the base under Python 3.9.25 for the same call: the read
//! of the row's name with its size limit, in the open directory or not, with or without the sync.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::{ReadError, closed, read_file, read_sized};
use crate::gameday::constants::FILE_LIMIT;
use crate::gameday::test_support::within_deadline;
use crate::paths::tests::Scratch;
use crate::text::Text;

/// Python's `repr` of bytes that are printable ASCII.
fn repr(bytes: &[u8]) -> String {
    format!("b'{}'", String::from_utf8(bytes.to_vec()).expect("ASCII"))
}

/// A name, the size limit, whether the name is read in the open directory, whether to sync, and the
/// judge's result.
type Row = (
    &'static str,
    u64,
    bool,
    bool,
    Result<&'static str, &'static str>,
);

/// `/proc/self/mem` is a regular file of size 0 whose read at offset 0 fails, so it reaches the read's
/// refusal with and without the sync. A named pipe with no writer is read under a deadline, so an open that
/// waits for a writer fails the row.
#[test]
fn read_file_reads_a_regular_file_and_refuses_every_other_input() {
    let scratch = Scratch::new("gameday-read");
    let top = &scratch.0;
    fs::write(top.join("a"), "abcd").expect("written");
    symlink("a", top.join("link")).expect("linked");
    fs::create_dir(top.join("dir")).expect("made");
    let made = std::process::Command::new("mkfifo")
        .arg(top.join("fifo"))
        .status();
    assert!(made.expect("mkfifo starts").success(), "the fifo is made");
    let dir = File::open(top).expect("the directory opens");
    #[rustfmt::skip]
    let rows: &[Row] = &[
    (r#"a"#, 4, false, false, Ok(r#"b'abcd'"#)),
    (r#"a"#, 3, false, false, Err(r#"x holds more than 3 bytes"#)),
    (r#"absent"#, 4, false, false, Err(r#"x cannot be read: No such file or directory"#)),
    (r#"link"#, 4, false, false, Err(r#"x cannot be read: Too many levels of symbolic links"#)),
    (r#"dir"#, 4, false, false, Err(r#"x is no regular file"#)),
    (r#"/proc/self/status"#, 67108864, false, false, Err(r#"x grew while it was read"#)),
    (r#"a"#, 4, true, false, Ok(r#"b'abcd'"#)),
    (r#"a"#, 4, false, true, Ok(r#"b'abcd'"#)),
    (r#"absent"#, 4, true, false, Err(r#"x cannot be read: No such file or directory"#)),
        (r#"/proc/self/mem"#, 4, false, false, Err(r#"x cannot be read: Input/output error"#)),
        (r#"/proc/self/mem"#, 4, false, true, Err(r#"x cannot be read and synced: Input/output error"#)),
    ];
    for &(name, limit, at, sync, expected) in rows {
        let path = if name.starts_with('/') || at {
            Path::new(name).to_path_buf()
        } else {
            top.join(name)
        };
        let found = read_file(
            &path,
            at.then(|| dir.as_fd()),
            &Text::from("x"),
            limit,
            sync,
        )
        .map(|bytes| repr(&bytes))
        .map_err(|error| match error {
            ReadError::Refused(refusal) => refusal.to_string(),
            ReadError::Nul => "a NUL byte".to_owned(),
            ReadError::Closed(reason) => format!("a failed close: {reason}"),
        });
        let expected = expected.map(str::to_owned).map_err(str::to_owned);
        assert_eq!(
            found, expected,
            "read_file({name:?}, limit {limit}, in the directory {at}, sync {sync})"
        );
    }
    let fifo = top.join("fifo");
    let found = within_deadline("read_file of a named pipe with no writer", move || {
        read_file(&fifo, None, &Text::from("x"), 4, false)
    });
    assert_eq!(
        found,
        Err(ReadError::Refused(super::Refusal::new(Text::from(
            "x is no regular file"
        )))),
        "read_file('fifo', 'x')"
    );
    let absolute = read_file(
        &top.join("a"),
        Some(dir.as_fd()),
        &Text::from("x"),
        4,
        false,
    );
    assert_eq!(
        absolute,
        Ok(b"abcd".to_vec()),
        "an absolute path stands for itself"
    );
    let empty = read_file(Path::new(""), Some(dir.as_fd()), &Text::from("x"), 4, false);
    assert_eq!(
        empty.map_err(|error| format!("{error:?}")),
        Err(format!(
            "{:?}",
            ReadError::Refused(super::Refusal::new(Text::from(
                "x cannot be read: No such file or directory"
            )))
        )),
        "read_file('', 'x', dir_fd=fd)"
    );
    let nul = read_file(
        Path::new(OsStr::from_bytes(b"a\0b")),
        None,
        &Text::from("x"),
        4,
        false,
    );
    assert_eq!(nul, Err(ReadError::Nul));
}

/// The judge's self-test case of the same name: a file whose size passes the limit is refused with the
/// size's sentence, a file that reads longer than its size (a file of `/proc`, whose size reads 0) is
/// refused with the growth's sentence, which comes before the sync's, and a regular file within the limit
/// is read and synced. These rows observe the refusals and their order; the rows of
/// `a_sync_follows_a_whole_read_and_its_failure_names_the_sync` observe the sync itself.
#[test]
fn a_file_past_the_limit_is_refused_before_it_is_read_and_one_that_grows_before_it_is_synced() {
    let scratch = Scratch::new("gameday-big");
    let path = scratch.0.join("big.json");
    fs::write(&path, "12345").expect("written");
    let big = Text::from("big");
    let refused = |result: Result<Vec<u8>, ReadError>| match result {
        Err(ReadError::Refused(refusal)) => refusal.to_string(),
        other => panic!("{other:?} is a refusal"),
    };
    assert_eq!(
        refused(read_file(&path, None, &big, 4, true)),
        "big holds more than 4 bytes"
    );
    let status = read_file(Path::new("/proc/self/status"), None, &big, FILE_LIMIT, true);
    assert_eq!(refused(status), "big grew while it was read");
    assert_eq!(
        read_file(&path, None, &big, FILE_LIMIT, true),
        Ok(b"12345".to_vec())
    );
}

/// The read of `/proc/self/status` with a size above its content passes the growth check: without the
/// sync it returns the bytes, and with it the sync fails (`fsync` of a file of `/proc` reads `EINVAL`),
/// so the refusal holds the sync's words.
#[test]
fn a_sync_follows_a_whole_read_and_its_failure_names_the_sync() {
    let file = File::open("/proc/self/status").expect("the status opens");
    let what = Text::from("x");
    let read = read_sized(&file, 1 << 20, &what, None).expect("the status reads");
    assert!(read.starts_with(b"Name:"), "the bytes of the status");
    let file = File::open("/proc/self/status").expect("the status opens");
    assert_eq!(
        read_sized(&file, 1 << 20, &what, Some(&|file: &File| file.sync_all()))
            .map_err(|refusal| refusal.to_string()),
        Err("x cannot be read and synced: Invalid argument".to_owned())
    );
}

/// A failed close stands in place of the read's outcome, a refusal included; a close that succeeds keeps
/// it.
#[test]
fn a_failed_close_stands_in_place_of_every_outcome() {
    let failed = || Err(std::io::Error::from_raw_os_error(libc::EIO));
    let refusal = super::Refusal::new(Text::from("x is no regular file"));
    assert_eq!(
        closed(Ok(b"abcd".to_vec()), failed()),
        Err(ReadError::Closed("Input/output error".to_owned()))
    );
    assert_eq!(
        closed(Err(refusal.clone()), failed()),
        Err(ReadError::Closed("Input/output error".to_owned()))
    );
    assert_eq!(closed(Ok(b"abcd".to_vec()), Ok(())), Ok(b"abcd".to_vec()));
    assert_eq!(
        closed(Err(refusal.clone()), Ok(())),
        Err(ReadError::Refused(refusal))
    );
}
