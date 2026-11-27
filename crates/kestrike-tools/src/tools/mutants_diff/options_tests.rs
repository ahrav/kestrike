use std::ffi::OsString;

use super::options::{Options, Revision, parse};
use crate::args::Parsed;

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
        (
            &["--max-mutants", "\u{661}"][..],
            "mutants-diff: error: argument --max-mutants: a positive integer",
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
        Some(vec![OsString::from("-x"), OsString::from("y")]),
        "tests: ['-x', 'y']"
    );
}

#[test]
fn the_value_list_of_dash_dash_leaves_defaults_or_empty_values() {
    let empty = |flag: &str| options(read(&[&format!("{flag}=--")]));
    assert_eq!(empty("--base").base, None, "base: [] takes the merge base");
    assert_eq!(empty("--head").head, Revision::EmptyList, "head: []");
    assert_eq!(empty("--head").head.repr(), "[]", "repr([])");
    assert_eq!(empty("--tests").tests, Some(Vec::new()), "tests: []");
    assert_eq!(empty("--max-mutants").max_mutants, None, "max_mutants: []");
    assert_eq!(empty("--shard").shard, None, "shard: [] passes no shard");
    assert_eq!(
        empty("--artifacts").artifacts,
        None,
        "artifacts: [] takes the default"
    );
    assert_eq!(empty("--cargo").cargo, None, "cargo: []");
}

#[test]
fn numbers_keep_their_value_and_past_4300_digits_are_invalid() {
    assert_eq!(
        options(read(&["--max-mutants", "0007"]))
            .max_mutants
            .as_deref(),
        Some("7"),
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
