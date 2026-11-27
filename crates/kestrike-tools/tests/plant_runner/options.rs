//! The command line: the defaults, `--plant` repeated in both forms, the words of the count and floor
//! checks, and counts of 4,300 and 4,301 digits.

use kestrike_tools::json::Integer;
use kestrike_tools::plants::Outcome;
use kestrike_tools::text::Text;

use super::repository::{Repository, executable};

fn integer(digits: &str) -> Integer {
    Integer::from_digits(false, digits).expect("digits")
}

/// With no option the run takes 28 workers, a floor of 300 runs, 60 seconds and 10 rounds a sweep,
/// `campaign` from `PATH`, the default work directory and the whole store.
#[test]
fn the_defaults_fill_every_option() {
    let repository = Repository::new();
    let Outcome::Run(inputs) = repository.prepare(&repository.call(&[])) else {
        panic!("the default call runs");
    };
    let options = inputs.options();
    assert_eq!(
        [
            options.workers(),
            options.runs(),
            options.seconds(),
            options.rounds()
        ],
        [
            &integer("28"),
            &integer("300"),
            &integer("60"),
            &integer("10")
        ]
    );
    assert_eq!(options.campaign(), "campaign");
    assert_eq!(options.work(), None);
    assert!(options.plants().is_empty());
}

/// Each `--plant` occurrence is kept in order, a repeat included, whether its value follows as the next
/// argument or after `=`; the run still takes the selected plants in store order.
#[test]
fn plant_keeps_every_occurrence_in_both_forms() {
    let repository = Repository::new();
    let call = repository.call(&["--plant", "beta", "--plant=alpha", "--plant", "beta"]);
    let Outcome::Run(inputs) = repository.prepare(&call) else {
        panic!("the selection runs");
    };
    let chosen: Vec<&Text> = inputs.options().plants().iter().collect();
    assert_eq!(
        chosen,
        [
            &Text::from("beta"),
            &Text::from("alpha"),
            &Text::from("beta")
        ]
    );
    let ids: Vec<&Text> = inputs.plants().iter().map(|plant| plant.id()).collect();
    assert_eq!(ids, [&Text::from("alpha"), &Text::from("beta")]);
}

/// A count is read as Python's `int` reads a string: surrounding whitespace, a sign and underscores
/// between digits included, up to 4,300 digits.
#[test]
fn counts_read_as_python_reads_an_integer() {
    let repository = Repository::new();
    executable(&repository.bin.join("-\u{663}"), "#!/bin/sh\nexit 0\n");
    let digits = "1".repeat(4300);
    let call = repository.call(&[
        "--workers",
        " 3\n",
        "--campaign=-\u{663}",
        "--for",
        "1_0",
        "--rounds",
        &digits,
        "--runs",
        "+0300",
    ]);
    let Outcome::Run(inputs) = repository.prepare(&call) else {
        panic!("the counts run");
    };
    let Outcome::Run(least) = repository.prepare(&repository.call(&["--workers", "1"])) else {
        panic!("a count of 1 runs");
    };
    assert_eq!(least.options().workers(), &integer("1"));
    let options = inputs.options();
    assert_eq!(inputs.campaign(), repository.bin.join("-\u{663}"));
    assert_eq!(options.workers(), &integer("3"));
    assert_eq!(options.seconds(), &integer("10"));
    assert_eq!(options.rounds(), &integer(&digits));
    assert_eq!(options.runs(), &integer("300"));
}

/// Each refusal of the argument reader reads `plant-runner: error: ` and the option's message: a count
/// below its bound, a value no integer reads, a missing value, and an unknown or shortened option.
#[test]
fn the_reader_refuses_each_bad_value() {
    let repository = Repository::new();
    let long = "1".repeat(4301);
    let rows: &[(&[&str], String)] = &[
        (
            &["--workers", "0"],
            "argument --workers: 0 is not a positive integer".to_owned(),
        ),
        (
            &["--for", "-2"],
            "argument --for: -2 is not a positive integer".to_owned(),
        ),
        (
            &["--for=-2"],
            "argument --for: -2 is not a positive integer".to_owned(),
        ),
        (
            &["--rounds", "x"],
            "argument --rounds: invalid positive value: 'x'".to_owned(),
        ),
        (
            &["--rounds", "1.5"],
            "argument --rounds: invalid positive value: '1.5'".to_owned(),
        ),
        (
            &["--workers", &long],
            format!("argument --workers: invalid positive value: '{long}'"),
        ),
        (
            &["--runs", "299"],
            "argument --runs: 299 is below the floor of 300 runs a profile".to_owned(),
        ),
        (
            &["--runs", " 299"],
            "argument --runs:  299 is below the floor of 300 runs a profile".to_owned(),
        ),
        (
            &["--runs", "lots"],
            "argument --runs: invalid floor value: 'lots'".to_owned(),
        ),
        (
            &["--runs", &long],
            format!("argument --runs: invalid floor value: '{long}'"),
        ),
        (
            &["--plant"],
            "argument --plant: expected one argument".to_owned(),
        ),
        (
            &["--workers", "\u{663}"],
            "argument --workers: invalid positive value: '\u{663}'".to_owned(),
        ),
        (
            &["--campaign", "-\u{663}"],
            "argument --campaign: expected one argument".to_owned(),
        ),
        (
            &["--wor", "w"],
            "unrecognized arguments: --wor w".to_owned(),
        ),
        (&["extra"], "unrecognized arguments: extra".to_owned()),
    ];
    for (args, expected) in rows {
        assert_eq!(
            repository.refused(&repository.call(args)),
            format!("usage: plant-runner: error: {expected}"),
            "{args:?}"
        );
    }
}

/// `-h` and `--help` return the help, whose first line is the usage.
#[test]
fn help_returns_the_usage_and_the_options() {
    let repository = Repository::new();
    for flag in ["-h", "--help"] {
        let Outcome::Help(text) = repository.prepare(&repository.call(&["--workers", "3", flag]))
        else {
            panic!("{flag} asks for help");
        };
        assert!(
            text.starts_with("usage: plant-runner [-h] [--work DIR]"),
            "{text}"
        );
        assert!(text.contains("--plant ID"), "{text}");
    }
}
