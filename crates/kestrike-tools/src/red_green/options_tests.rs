use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::{
    DEFAULT_WATCHDOG, Options, TIMEOUT_MAX, check_expect, check_given, check_receipt_directory,
    check_watchdog, repeat,
};
use crate::args::Parsed;
use crate::shell;
use crate::text::Text;

const TEST: &str = "storage::device::table_tests::a_poll_reports_each_completion_once";
const USAGE: &str = "usage: red-green [options]";

fn read(words: &[OsString], help: &str) -> Parsed<Options> {
    super::read(words, "red-green", USAGE, help)
}

fn bytes(text: &[u8]) -> Text {
    Text::from_os(OsStr::from_bytes(text))
}

fn args(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

fn options() -> Options {
    Options {
        package: Text::from("p"),
        target: Text::from("lib"),
        test: Text::from("t"),
        expect: Text::from("e"),
        carry: vec![Text::from("a")],
        base: None,
        head: Text::from("HEAD"),
        watchdog: DEFAULT_WATCHDOG,
        artifacts: None,
        cargo: Text::from("cargo"),
        release: false,
    }
}

fn refused(message: &str) -> Parsed<Options> {
    Parsed::Refused {
        code: 2,
        text: format!("{USAGE}\nred-green: error: {message}\n"),
    }
}

const REQUIRED: [&str; 8] = [
    "--package",
    "p",
    "--target",
    "lib",
    "--test",
    "t",
    "--expect",
    "e",
];

fn with(extra: &[&str]) -> Vec<OsString> {
    let mut words: Vec<&str> = REQUIRED.to_vec();
    words.extend(extra);
    args(&words)
}

/// `read` treats `=--` as the literal value `--`. `--watchdog` uses `f64` syntax, so `1_0` and a digit
/// outside ASCII are invalid floats. A word of `-` and decimal digits outside ASCII reads as an option, so
/// it is a value only where `=` joins it to its option. `-h=` is refused.
#[test]
fn read_takes_the_eleven_options_by_unique_prefix() {
    let carry = |paths: &[&str]| {
        paths
            .iter()
            .map(|path| Text::from(*path))
            .collect::<Vec<_>>()
    };
    #[rustfmt::skip]
    let rows: Vec<(&str, Vec<OsString>, Result<Options, &str>)> = vec![
        ("the required options", with(&["--carry", "a.rs"]), Ok(Options { carry: carry(&["a.rs"]), ..options() })),
        ("every option", with(&["--carry", "a.rs", "b.rs", "--base", "B", "--head", "H", "--watchdog", "2.5",
                                "--artifacts", "r", "--cargo", "/c", "--release"]),
         Ok(Options { carry: carry(&["a.rs", "b.rs"]), base: Some(Text::from("B")), head: Text::from("H"),
                      watchdog: 2.5, artifacts: Some(Text::from("r")), cargo: Text::from("/c"), release: true,
                      ..options() })),
        ("prefixes", args(&["--pack=p", "--targ", "lib", "--te", "t", "--exp", "e", "--carr", "a.rs", "--rel",
                            "--w", "9"]),
         Ok(Options { carry: carry(&["a.rs"]), watchdog: 9.0, release: true, ..options() })),
        ("an ambiguous prefix", with(&["--ca", "x"]), Err("ambiguous option: --ca could match --carry, --cargo")),
        ("a prefix of --head and --help", with(&["--carry", "a", "--he", "H"]),
         Err("ambiguous option: --he could match --help, --head")),
        ("two occurrences of --carry", with(&["--carry", "a", "b", "--carry=c", "--carry", "d"]),
         Ok(Options { carry: carry(&["a", "b", "c", "d"]), ..options() })),
        ("--carry up to the next option", with(&["--carry", "a", "-", "-1", "x y", "--head", "H"]),
         Ok(Options { carry: carry(&["a", "-", "-1", "x y"]), head: Text::from("H"), ..options() })),
        ("--carry with no value", with(&["--carry"]), Err("argument --carry: expected at least one argument")),
        ("--carry before another option", with(&["--carry", "--head", "H"]),
         Err("argument --carry: expected at least one argument")),
        ("--carry before --", with(&["--carry", "--", "a"]), Err("argument --carry: expected at least one argument")),
        ("--carry=", with(&["--carry="]), Ok(Options { carry: carry(&[""]), ..options() })),
        ("--carry=a with a leftover", with(&["--carry=a", "b"]), Err("unrecognized arguments: b")),
        ("--carry missing", with(&[]), Err("the following arguments are required: --carry")),
        ("all required missing", args(&[]),
         Err("the following arguments are required: --package, --target, --test, --expect, --carry")),
        ("--release=x", with(&["--carry", "a", "--release=x"]),
         Err("argument --release: ignored explicit argument 'x'")),
        ("--release=", with(&["--carry", "a", "--release="]), Err("argument --release: ignored explicit argument ''")),
        ("--rel=x", with(&["--carry", "a", "--rel=x"]), Err("argument --release: ignored explicit argument 'x'")),
        ("--release twice", with(&["--carry", "a", "--release", "--release"]), Ok(Options { release: true, ..options() })),
        ("--watchdog with white space", with(&["--carry", "a", "--watchdog", " 1e3\t"]),
         Ok(Options { watchdog: 1000.0, ..options() })),
        ("--watchdog -Infinity", with(&["--carry", "a", "--watchdog", "-Infinity"]),
         Err("argument --watchdog: expected one argument")),
        ("--watchdog x", with(&["--carry", "a", "--watchdog", "x"]), Err("argument --watchdog: invalid float value: 'x'")),
        ("--watchdog 1_0", with(&["--carry", "a", "--watchdog", "1_0"]),
         Err("argument --watchdog: invalid float value: '1_0'")),
        ("--watchdog in other digits", with(&["--carry", "a", "--watchdog", "\u{661}"]),
         Err("argument --watchdog: invalid float value: '\u{661}'")),
        ("--watchdog inf", with(&["--carry", "a", "--watchdog", "inf"]),
         Ok(Options { watchdog: f64::INFINITY, ..options() })),
        ("--watchdog Infinity", with(&["--carry", "a", "--watchdog", "Infinity"]),
         Ok(Options { watchdog: f64::INFINITY, ..options() })),
        ("--watchdog 1e400", with(&["--carry", "a", "--watchdog", "1e400"]),
         Ok(Options { watchdog: f64::INFINITY, ..options() })),
        ("--watchdog +.5", with(&["--carry", "a", "--watchdog", "+.5"]), Ok(Options { watchdog: 0.5, ..options() })),
        ("--watchdog 5.", with(&["--carry", "a", "--watchdog", "5."]), Ok(Options { watchdog: 5.0, ..options() })),
        ("--watchdog 1e", with(&["--carry", "a", "--watchdog", "1e"]),
         Err("argument --watchdog: invalid float value: '1e'")),
        ("--watchdog 0x1p0", with(&["--carry", "a", "--watchdog", "0x1p0"]),
         Err("argument --watchdog: invalid float value: '0x1p0'")),
        ("--watchdog ' 5 '", with(&["--carry", "a", "--watchdog", " 5 "]), Ok(Options { watchdog: 5.0, ..options() })),
        ("--watchdog \\x1c5", with(&["--carry", "a", "--watchdog", "\u{1c}5"]),
         Err("argument --watchdog: invalid float value: '\\x1c5'")),
        ("--watchdog U+3000 5", with(&["--carry", "a", "--watchdog", "\u{3000}5"]),
         Ok(Options { watchdog: 5.0, ..options() })),
        ("--watchdog=--", with(&["--carry", "a", "--watchdog=--"]),
         Err("argument --watchdog: invalid float value: '--'")),
        ("--package=--", { let mut words = vec!["--package=--"]; words.extend(&REQUIRED[2..]);
                           words.extend(["--carry", "a"]); args(&words) },
         Ok(Options { package: Text::from("--"), ..options() })),
        ("--carry=--", with(&["--carry=--"]), Ok(Options { carry: carry(&["--"]), ..options() })),
        ("an unknown option", with(&["--carry", "a", "--bogus"]), Err("unrecognized arguments: --bogus")),
        ("-h=", with(&["--carry", "a", "-h="]), Err("argument -h/--help: ignored explicit argument ''")),
        ("--carry before a negative number in other digits", with(&["--carry", "-\u{661}"]),
         Err("argument --carry: expected at least one argument")),
        ("--carry a before a negative number in other digits", with(&["--carry", "a", "-\u{661}"]),
         Err("unrecognized arguments: -\u{661}")),
        ("--head before a negative number in other digits", with(&["--carry", "a", "--head", "-\u{661}"]),
         Err("argument --head: expected one argument")),
        ("--watchdog before a negative number in other digits", with(&["--carry", "a", "--watchdog", "-\u{661}"]),
         Err("argument --watchdog: expected one argument")),
        ("--carry= with a negative number in other digits", with(&["--carry=-\u{661}"]),
         Ok(Options { carry: carry(&["-\u{661}"]), ..options() })),
    ];
    for (name, words, expected) in rows {
        let expected = expected.map_or_else(refused, Parsed::Run);
        assert_eq!(read(&words, "help\n"), expected, "{name}");
    }
    assert_eq!(
        read(&args(&["--help"]), "help\n"),
        Parsed::Help("help\n".to_owned())
    );
    for nan in ["nan", "-nan"] {
        let Parsed::Run(read) = read(&with(&["--carry", "a", &format!("--watchdog={nan}")]), "")
        else {
            panic!("{nan} reads as a float");
        };
        assert!(read.watchdog.is_nan(), "{nan}");
    }
}

#[test]
fn check_given_refuses_an_empty_or_double_dash_value() {
    let given = "an option has no value, or --carry names no path";
    #[rustfmt::skip]
    let rows: Vec<(&str, Options, Result<(), &str>)> = vec![
        ("every value", options(), Ok(())),
        ("an empty package", Options { package: Text::new(), ..options() }, Err(given)),
        ("a package of --", Options { package: Text::from("--"), ..options() }, Err(given)),
        ("an empty target", Options { target: Text::new(), ..options() }, Err(given)),
        ("an empty test", Options { test: Text::new(), ..options() }, Err(given)),
        ("an empty head", Options { head: Text::new(), ..options() }, Err(given)),
        ("an empty cargo", Options { cargo: Text::new(), ..options() }, Err(given)),
        ("an empty carried path", Options { carry: vec![Text::from("a"), Text::new()], ..options() }, Err(given)),
        ("a carried path of --", Options { carry: vec![Text::from("--")], ..options() }, Err(given)),
        ("no carried path", Options { carry: vec![], ..options() }, Err(given)),
        ("an empty base", Options { base: Some(Text::new()), ..options() }, Err(given)),
        ("a base of --", Options { base: Some(Text::from("--")), ..options() }, Err(given)),
        ("an empty artifacts", Options { artifacts: Some(Text::new()), ..options() }, Err(given)),
        ("an empty expect", Options { expect: Text::new(), ..options() }, Ok(())),
        ("an expect of --", Options { expect: Text::from("--"), ..options() }, Err(given)),
        ("a blank expect", Options { expect: Text::from(" "), ..options() }, Ok(())),
    ];
    for (name, options, expected) in rows {
        assert_eq!(
            check_given(&options),
            expected.map_err(Text::from),
            "{name}"
        );
    }
}

/// A text that holds a NUL is refused as an empty one.
#[test]
fn check_expect_refuses_a_blank_text_and_part_of_the_test_id() {
    let rows: [(&str, Text, Text, Option<&str>); 11] = [
        (
            "a text",
            Text::from("lost a completion"),
            Text::from(TEST),
            None,
        ),
        (
            "empty",
            Text::new(),
            Text::from(TEST),
            Some("--expect is empty"),
        ),
        (
            "white space",
            Text::from(" \t\u{3000}\u{1c}"),
            Text::from(TEST),
            Some("--expect is empty"),
        ),
        (
            "a NUL",
            Text::from("\0"),
            Text::from(TEST),
            Some("--expect is empty"),
        ),
        (
            "a NUL inside a text",
            Text::from("lost\0a completion"),
            Text::from(TEST),
            Some("--expect is empty"),
        ),
        (
            "part of the test ID",
            Text::from("table_tests"),
            Text::from(TEST),
            Some("--expect 'table_tests' is part of the test ID"),
        ),
        (
            "the whole test ID",
            Text::from(TEST),
            Text::from(TEST),
            Some(
                "--expect 'storage::device::table_tests::a_poll_reports_each_completion_once' is part of the test ID",
            ),
        ),
        (
            "a quote",
            Text::from("it's"),
            Text::from("it's a test"),
            Some("--expect \"it's\" is part of the test ID"),
        ),
        (
            "a byte outside UTF-8",
            bytes(b"\xff"),
            bytes(b"t\xff"),
            Some("--expect '\\udcff' is part of the test ID"),
        ),
        (
            "a byte inside a UTF-8 sequence of the test ID",
            bytes(b"\xc3"),
            Text::from("caf\u{e9}"),
            None,
        ),
        (
            "an ID that holds no part",
            Text::from("poll\n"),
            Text::from(TEST),
            None,
        ),
    ];
    for (name, expect, test, expected) in rows {
        assert_eq!(
            check_expect(&Options {
                expect,
                test,
                ..options()
            }),
            expected.map_or(Ok(()), |reason| Err(Text::from(reason))),
            "{name}"
        );
    }
}

#[test]
fn check_watchdog_takes_a_positive_wait_up_to_the_platform_bound() {
    let refused = "--watchdog must be a positive number of seconds up to 9223372036.0";
    let rows = [
        (1500.0, true),
        (0.0, false),
        (-0.0, false),
        (-1.0, false),
        (5e-324, true),
        (TIMEOUT_MAX, true),
        (9_223_372_036.000_002, false),
        (f64::INFINITY, false),
        (f64::NAN, false),
        (0.5, true),
    ];
    for (watchdog, accepted) in rows {
        let expected = if accepted {
            Ok(())
        } else {
            Err(Text::from(refused))
        };
        assert_eq!(check_watchdog(watchdog), expected, "{watchdog}");
    }
}

#[test]
fn check_receipt_directory_refuses_a_line_break_and_a_byte_outside_utf8() {
    let tail = "cannot appear on the runner's one-line UTF-8 artifact announcement";
    let rows: [(&[u8], Option<&str>); 15] = [
        (b"/r/target/red-green", None),
        (b"/r/a\nb", Some("'/r/a\\nb'")),
        (b"/r/a\rb", Some("'/r/a\\rb'")),
        (b"/r/a\x0bb", Some("'/r/a\\x0bb'")),
        (b"/r/a\x0cb", Some("'/r/a\\x0cb'")),
        (b"/r/a\x1cb", Some("'/r/a\\x1cb'")),
        (b"/r/a\x1db", Some("'/r/a\\x1db'")),
        (b"/r/a\x1eb", Some("'/r/a\\x1eb'")),
        (b"/r/a\x1fb", None),
        ("/r/a\u{85}b".as_bytes(), Some("'/r/a\\x85b'")),
        ("/r/a\u{2028}b".as_bytes(), Some("'/r/a\\u2028b'")),
        ("/r/a\u{2029}b".as_bytes(), Some("'/r/a\\u2029b'")),
        (b"/r/a\xffb", Some("'/r/a\\udcffb'")),
        (b"/r/a\tb", None),
        ("/r/\u{e9}".as_bytes(), None),
    ];
    for (path, shown) in rows {
        let expected = shown.map_or(Ok(()), |shown| {
            Err(Text::from(format!("the receipt directory {shown} {tail}")))
        });
        assert_eq!(
            check_receipt_directory(Path::new(OsStr::from_bytes(path))),
            expected,
            "{path:?}"
        );
    }
}

const BASE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HEAD: &str = "cccccccccccccccccccccccccccccccccccccccc";

fn run() -> Options {
    Options {
        test: Text::from(TEST),
        expect: Text::from("a poll counts that completion as delivered"),
        carry: vec![Text::from("t.rs")],
        watchdog: 30.0,
        ..options()
    }
}

#[test]
fn repeat_joins_each_value_to_its_flag_and_quotes_each_word() {
    let prefix = "bash scripts/tool.sh red-green --package=p --target=lib \
                  --test=storage::device::table_tests::a_poll_reports_each_completion_once";
    let commits = format!("--base={BASE} --head={HEAD}");
    #[rustfmt::skip]
    let rows: Vec<(&str, Options, String)> = vec![
        ("the defaults", run(),
         format!("{prefix} '--expect=a poll counts that completion as delivered' --carry=t.rs {commits} --watchdog=30.0")),
        ("every option", Options { artifacts: Some(Text::from("r")), cargo: Text::from("/c/cargo"), release: true,
                                   carry: vec![Text::from("-a.rs"), Text::from("b c.rs")],
                                   expect: Text::from("-x"), ..run() },
         format!("{prefix} --expect=-x --carry=-a.rs '--carry=b c.rs' {commits} --watchdog=30.0 --release \
                  --artifacts=/r --cargo=/c/cargo")),
        ("quotes and non-ASCII", Options { expect: Text::from("it's \"done\""),
                                           carry: vec![Text::from("caf\u{e9}.rs"), bytes(b"n\xff")],
                                           watchdog: 1e-05, ..run() },
         format!("{prefix} '--expect=it'\"'\"'s \"done\"' '--carry=caf\u{e9}.rs' '--carry=n\u{fffd}' {commits} \
                  --watchdog=1e-05")),
        ("an empty expect", Options { expect: Text::new(), ..run() },
         format!("{prefix} --expect= --carry=t.rs {commits} --watchdog=30.0")),
    ];
    for (name, options, expected) in rows {
        let command = repeat(
            &options,
            &Text::from(BASE),
            &Text::from(HEAD),
            Path::new("/r/local-1-1"),
        );
        let surrogate = bytes(b"n\xff");
        let expected = Text::from(expected).replace(&Text::from("n\u{fffd}"), &surrogate);
        assert_eq!(command, expected, "{name}");
    }
}

#[test]
fn repeat_names_the_parent_of_the_receipt_where_the_run_named_artifacts() {
    let named = Options {
        artifacts: Some(Text::from("r")),
        ..run()
    };
    let empty = Options {
        artifacts: Some(Text::new()),
        ..run()
    };
    let rows: [(&str, &Options, &str, Option<&str>); 5] = [
        ("a nested receipt", &named, "/r/local-1-1", Some("/r")),
        (
            "a receipt of one relative component",
            &named,
            "local-1-1",
            Some("."),
        ),
        ("the root for the receipt", &named, "/", Some("/")),
        ("an empty artifacts", &empty, "/r/local-1-1", None),
        ("no artifacts", &run(), "/r/local-1-1", None),
    ];
    for (name, options, receipt, parent) in rows {
        let command = repeat(
            options,
            &Text::from(BASE),
            &Text::from(HEAD),
            Path::new(receipt),
        );
        let words = shell::split(&command).expect("the command splits");
        let artifacts: Vec<Text> = words
            .into_iter()
            .filter(|word| word.starts_with(&Text::from("--artifacts")))
            .collect();
        let expected: Vec<Text> = parent
            .iter()
            .map(|parent| Text::from(format!("--artifacts={parent}")))
            .collect();
        assert_eq!(artifacts, expected, "{name}");
    }
}

/// The repeat command, split as a shell splits it, reads back through the option reader to the run's
/// values with both revisions as full commit IDs.
#[test]
fn the_repeat_command_parses_back_to_the_run_arguments() {
    let options = Options {
        package: Text::from("kestrike"),
        expect: Text::from("-x"),
        release: true,
        carry: vec![Text::from("-a.rs"), Text::from("b c.rs"), bytes(b"n\xff")],
        cargo: Text::from("/c/cargo"),
        artifacts: Some(Text::from("r")),
        ..run()
    };
    let command = repeat(
        &options,
        &Text::from(BASE),
        &Text::from(HEAD),
        Path::new("/root/r/local-1-1"),
    );
    let words = shell::split(&command).expect("the command splits");
    assert_eq!(
        words[..3],
        [
            Text::from("bash"),
            Text::from("scripts/tool.sh"),
            Text::from("red-green")
        ]
    );
    let words: Vec<OsString> = words[3..]
        .iter()
        .map(|word| word.to_os().expect("a word encodes"))
        .collect();
    let Parsed::Run(parsed) = read(&words, "") else {
        panic!("{command} reads back");
    };
    let expected = Options {
        base: Some(Text::from(BASE)),
        head: Text::from(HEAD),
        artifacts: Some(Text::from("/root/r")),
        ..options
    };
    assert_eq!(parsed, expected);
}
