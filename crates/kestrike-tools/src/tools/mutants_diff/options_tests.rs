use std::ffi::OsString;

use super::options::{Options, parse};
use crate::args::Parsed;
use crate::text::Text;

fn read(args: &[&str]) -> Parsed<Options> {
    parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
}

fn refusal(parsed: Parsed<Options>) -> String {
    match parsed {
        Parsed::Refused { code: 2, text } => text.lines().last().unwrap_or_default().to_owned(),
        other => panic!("a refusal, not {other:?}"),
    }
}

fn options(parsed: Parsed<Options>) -> Options {
    match parsed {
        Parsed::Run(options) => options,
        other => panic!("options, not {other:?}"),
    }
}

#[test]
fn the_token_after_an_option_is_a_value_unless_it_reads_as_an_option() {
    let refusals = [
        (
            &["--max-mutants", "-5"][..],
            "mutants-diff: error: argument --max-mutants: a positive integer",
        ),
        (
            &["--base", "--", "x"][..],
            "mutants-diff: error: argument --base: expected one argument",
        ),
        (
            &["--base", "-x"][..],
            "mutants-diff: error: argument --base: expected one argument",
        ),
        (
            &["--tests", "a \\"][..],
            "mutants-diff: error: argument --tests: a backslash with no character after it",
        ),
        (
            &["--shard", "1/2\n"][..],
            "mutants-diff: error: argument --shard: K/N with 0 <= K < N",
        ),
    ];
    for (args, expected) in refusals {
        assert_eq!(
            refusal(read(args)),
            expected,
            "p.parse_args({args:?}) exits 2"
        );
    }
    let tests = options(read(&["--tests", "-x y"])).tests;
    assert_eq!(
        tests,
        Some(vec![Text::from("-x"), Text::from("y")]),
        "tests: ['-x', 'y']"
    );
}

#[test]
fn dash_dash_after_an_equals_sign_is_the_value_and_each_check_decides_about_it() {
    let given = |flag: &str| options(read(&[&format!("{flag}=--")]));
    assert_eq!(
        given("--base").base,
        Some(OsString::from("--")),
        "a maintained Python binds base='--'"
    );
    assert_eq!(given("--head").head, OsString::from("--"));
    assert_eq!(
        given("--tests").tests,
        Some(vec![Text::from("--")]),
        "shlex.split('--') gives ['--']"
    );
    assert_eq!(given("--artifacts").artifacts, Some(OsString::from("--")));
    assert_eq!(given("--cargo").cargo, OsString::from("--"));
    let limit = refusal(read(&["--max-mutants=--"]));
    assert_eq!(
        limit,
        "mutants-diff: error: argument --max-mutants: a positive integer"
    );
    let shard = refusal(read(&["--shard=--"]));
    assert_eq!(
        shard,
        "mutants-diff: error: argument --shard: K/N with 0 <= K < N"
    );
}

#[test]
fn numbers_keep_their_value_and_past_4300_digits_are_invalid() {
    assert_eq!(
        options(read(&["--max-mutants", "0007"]))
            .max_mutants
            .to_string(),
        "7",
        "max_mutants: 7"
    );
    let shard = options(read(&["--shard", "01/02"])).shard.expect("a shard");
    assert_eq!(
        (shard.value, shard.k.to_string(), shard.n.to_string()),
        (OsString::from("01/02"), "1".into(), "2".into())
    );
    let long = "1".repeat(4301);
    let limit = refusal(read(&["--max-mutants", &long]));
    assert_eq!(
        limit,
        format!("mutants-diff: error: argument --max-mutants: invalid positive value: '{long}'")
    );
    let shard = format!("{long}/2");
    let refused = refusal(read(&["--shard", &shard]));
    assert_eq!(
        refused,
        format!("mutants-diff: error: argument --shard: invalid shard_value value: '{shard}'")
    );
}

/// A limit is a run of Unicode digits: a decimal digit of any script counts by its value, a digit outside
/// category `Nd` is an invalid value, and zero in any script is no positive integer.
#[test]
fn a_limit_reads_unicode_decimal_digits_by_their_value() {
    for (value, limit) in [
        ("\u{661}", "1"),
        ("1\u{661}\u{967}", "111"),
        ("\u{ff10}7", "7"),
    ] {
        assert_eq!(
            options(read(&["--max-mutants", value]))
                .max_mutants
                .to_string(),
            limit,
            "int({value:?}) gives {limit}"
        );
    }
    let refusals = [
        ("\u{b2}", "invalid positive value: '\u{b2}'"),
        ("1\u{b2}", "invalid positive value: '1\u{b2}'"),
        ("\u{660}", "a positive integer"),
        ("\u{660}\u{966}", "a positive integer"),
        ("\u{bd}", "a positive integer"),
        ("1 ", "a positive integer"),
    ];
    for (value, refusal) in refusals {
        assert_eq!(
            self::refusal(read(&["--max-mutants", value])),
            format!("mutants-diff: error: argument --max-mutants: {refusal}"),
            "--max-mutants {value:?}"
        );
    }
}

#[test]
fn help_prints_the_usage_and_the_header() {
    let Parsed::Help(text) = read(&["--help"]) else {
        panic!("--help prints the help");
    };
    assert!(text.starts_with("usage: mutants-diff [-h] "), "{text}");
    assert!(text.contains(include_str!("help.md")));
}
