use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use super::{expect_streams, unframed};
use crate::red_green::options::Options;
use crate::red_green::reasons::tests::options;
use crate::text::Text;

const TEST: &str = "storage::device::table_tests::a_poll_reports_each_completion_once";
const EXPECT: &str = "a poll counts that completion as delivered";
const TWO_LINES: &str = "first payload line\nsecond payload line";

fn framed(line: &str) -> (String, String) {
    (format!("{line}\n"), "\0\n".to_owned())
}

fn kept(line: &str) -> (String, String) {
    (format!("{line}\n"), format!("{line}\n"))
}

/// `unframed` preserves the shuffle-seed line so its text remains searchable.
#[test]
fn unframed_replaces_each_framing_and_backtrace_line_with_a_nul() {
    let mut rows: Vec<(String, String)> = [
        "running 1 test".to_owned(),
        "running 12 tests".to_owned(),
        format!("test {TEST} ... FAILED"),
        format!("test {TEST} - should panic ... ok"),
        "FAILED".to_owned(),
        "test result: FAILED. 0 passed; 1 failed".to_owned(),
        "failures:".to_owned(),
        "successes:".to_owned(),
        format!("---- {TEST} stdout ----"),
        format!("---- {TEST} stderr ----"),
        format!("    {TEST}"),
        format!("thread '{TEST}' panicked at src/a.rs:9:5:"),
        format!("thread '{TEST}' (4242) panicked at src/a.rs:9:5:"),
        "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace".to_owned(),
        "note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace."
            .to_owned(),
        "note: panic did not contain expected string".to_owned(),
        "note: expected panic with string value,".to_owned(),
        "      panic message: `\"lost\"`,".to_owned(),
        " expected substring: `\"kept\"`".to_owned(),
        "  found non-string value: 7".to_owned(),
        format!("\u{1c}{TEST}"),
        format!("\u{85}{TEST}"),
        "running \u{661} test".to_owned(),
        format!("\u{3000}{TEST}"),
    ]
    .iter()
    .map(|line| framed(line))
    .collect();
    rows.extend(
        [
            "running 1 tests (shuffle seed: 7)".to_owned(),
            format!("\u{1c}{TEST}x"),
            format!("test {TEST}x ... ok"),
            "FAILED here".to_owned(),
            "left: OK, right: FAILED".to_owned(),
            "error: failures:".to_owned(),
            "x running 1 test".to_owned(),
            "note: test did not panic as expected".to_owned(),
            "thread 'other' panicked at src/a.rs:9:".to_owned(),
            format!("\u{3000}\u{3000}{TEST}x"),
        ]
        .iter()
        .map(|line| kept(line)),
    );
    rows.extend([
        (
            format!("running 1 test\r\n{EXPECT}\r\n"),
            format!("\0\n{EXPECT}\r\n"),
        ),
        (
            format!("running 1 test\r\r\n{EXPECT}\r"),
            format!("running 1 test\r\r\n{EXPECT}\r"),
        ),
        (
            "stack backtrace:\n   0: f\n             at a.rs:1\nafter\n   1: g\n".to_owned(),
            "\0\n\0\n\0\nafter\n   1: g\n".to_owned(),
        ),
        (
            "stack backtrace:\r\n   0: f\r\nafter\r\n".to_owned(),
            "\0\n\0\nafter\r\n".to_owned(),
        ),
        (format!("failures:\n{EXPECT}"), format!("\0\n{EXPECT}")),
        (
            format!("x\n{TWO_LINES}\ny\n"),
            format!("x\n{TWO_LINES}\ny\n"),
        ),
        (
            "first payload line\nfailures:\nsecond payload line\n".to_owned(),
            "first payload line\n\0\nsecond payload line\n".to_owned(),
        ),
    ]);
    for (output, expected) in rows {
        let found = unframed(output.as_bytes(), &Text::from(TEST));
        assert_eq!(found, Text::from(expected), "{output:?}");
    }
    let bytes = |data: &[u8]| Text::from_os(OsStr::from_bytes(data));
    let invalid = unframed(b"a\xff\n\xc3\nfailures:\n", &Text::from(TEST));
    assert_eq!(
        invalid,
        bytes(b"a\xff\n\xc3\n\0\n"),
        "bytes outside UTF-8 stand as they are"
    );
    let test = bytes(b"t\xff");
    let framed = unframed(b"---- t\xff stdout ----\n---- t\xfe stdout ----\n", &test);
    assert_eq!(
        framed,
        bytes(b"\0\n---- t\xfe stdout ----\n"),
        "a test ID outside UTF-8 frames its own lines"
    );
    let any = unframed(b"test t\xff ... \xff lost\n", &test);
    assert_eq!(
        any,
        Text::from("\0\n"),
        "a byte outside UTF-8 stands under `.*`"
    );
    let dotted = unframed(
        b"---- a.b stdout ----\n---- axb stdout ----\n",
        &Text::from("a.b"),
    );
    assert_eq!(
        dotted,
        Text::from("\0\n---- axb stdout ----\n"),
        "a dot of the test ID stands for itself"
    );
}

/// A test ID as long as the longest argument Linux passes frames its own lines.
#[test]
fn a_test_id_of_120_000_bytes_frames_its_lines() {
    let long = "m".repeat(120_000);
    let output = format!("---- {long} stdout ----\n{EXPECT}\ntest {long} ... FAILED\n");
    let found = unframed(output.as_bytes(), &Text::from(long.as_str()));
    assert_eq!(found, Text::from(format!("\0\n{EXPECT}\n\0\n")));
    let outputs = vec![("stdout", output.into_bytes()), ("stderr", Vec::new())];
    assert_eq!(
        expect_streams(&outputs, &options(&long, EXPECT)),
        ["stdout"]
    );
}

/// The search compares code points: an expected text that ends inside a UTF-8 sequence of the output
/// misses it, and a byte outside UTF-8 matches the same byte.
#[test]
fn expect_streams_lists_the_streams_whose_kept_lines_hold_the_text() {
    let stdout = |data: &str| vec![("stdout", data.as_bytes().to_vec()), ("stderr", Vec::new())];
    type Row<'a> = (&'a str, Vec<(&'a str, Vec<u8>)>, &'a [u8], &'a [&'a str]);
    let rows: Vec<Row> = vec![
        (
            "standard output alone",
            stdout(EXPECT),
            EXPECT.as_bytes(),
            &["stdout"],
        ),
        (
            "standard error alone",
            vec![
                ("stdout", Vec::new()),
                ("stderr", format!("x\n{EXPECT}\n").into_bytes()),
            ],
            EXPECT.as_bytes(),
            &["stderr"],
        ),
        (
            "both streams",
            vec![("stdout", EXPECT.into()), ("stderr", EXPECT.into())],
            EXPECT.as_bytes(),
            &["stdout", "stderr"],
        ),
        ("neither stream", stdout("failures:\n"), b"failures:", &[]),
        (
            "inside a framing line alone",
            stdout(&format!("---- {TEST} stdout ----\n")),
            b"stdout",
            &[],
        ),
        (
            "two lines across kept lines",
            stdout(TWO_LINES),
            TWO_LINES.as_bytes(),
            &["stdout"],
        ),
        (
            "two lines across a framing line",
            stdout("first payload line\nFAILED\nsecond payload line\n"),
            TWO_LINES.as_bytes(),
            &[],
        ),
        (
            "the code points before a non-ASCII one",
            stdout("caf\u{e9}"),
            b"caf",
            &["stdout"],
        ),
        (
            "part of a UTF-8 sequence",
            stdout("caf\u{e9}"),
            b"caf\xc3",
            &[],
        ),
        (
            "a byte outside UTF-8",
            vec![("stdout", b"x\xffy\n".to_vec()), ("stderr", Vec::new())],
            b"\xff",
            &["stdout"],
        ),
        ("an empty text", stdout("x"), b"", &["stdout", "stderr"]),
    ];
    for (name, outputs, expect, expected) in rows {
        assert_eq!(
            expect_streams(
                &outputs,
                &Options {
                    expect: Text::from_os(OsStr::from_bytes(expect)),
                    ..options(TEST, "")
                }
            ),
            expected,
            "{name}"
        );
    }
}
