//! Each row's expected result is the judge's own function's at the base under Python 3.9.25, as the
//! expression beside it gives it.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::{ReadError, read_file};
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
    (r#"fifo"#, 4, false, false, Err(r#"x is no regular file"#)),
    (r#"/proc/self/status"#, 67108864, false, false, Err(r#"x grew while it was read"#)),
    (r#"a"#, 4, true, false, Ok(r#"b'abcd'"#)),
    (r#"a"#, 4, false, true, Ok(r#"b'abcd'"#)),
    (r#"absent"#, 4, true, false, Err(r#"x cannot be read: No such file or directory"#)),
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
        });
        let expected = expected.map(str::to_owned).map_err(str::to_owned);
        assert_eq!(
            found, expected,
            "read_file({name:?}, limit {limit}, in the directory {at}, sync {sync})"
        );
    }
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
