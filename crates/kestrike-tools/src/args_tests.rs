use std::ffi::{OsStr, OsString};

use crate::args::{Kind, Opt, Parsed, Prefixes, Reader, Reads, any, unrecognized};
use crate::text::Text;

fn given(value: &Text) -> Result<(), String> {
    if value.is_empty() {
        return Err("a value".to_owned());
    }
    Ok(())
}

fn positive(value: &Text) -> Result<(), String> {
    let digits = value
        .to_str()
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()));
    match digits {
        Some(digits) if digits.trim_start_matches('0').is_empty() => {
            Err("a positive integer".to_owned())
        }
        Some(_) => Ok(()),
        None => Err("a positive integer".to_owned()),
    }
}

const fn value(name: &'static [&'static str], check: fn(&Text) -> Result<(), String>) -> Opt {
    Opt {
        names: name,
        kind: Kind::Value {
            required: false,
            check,
        },
    }
}

const OPTIONS: [Opt; 8] = [
    Opt {
        names: &["-h", "--help"],
        kind: Kind::Help,
    },
    value(&["--base"], given),
    value(&["--head"], given),
    value(&["--max-mutants"], positive),
    value(&["--shard"], any),
    value(&["--tests"], any),
    value(&["--artifacts"], given),
    value(&["--cargo"], given),
];

fn read(args: &[&str]) -> Parsed {
    let reader = Reader::new(
        "tool",
        "usage: tool [options]",
        "help\n",
        Prefixes::Refuse,
        &OPTIONS,
    );
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    reader.parse(&args)
}

fn run(values: &[(usize, &'static str)]) -> Vec<Option<&'static OsStr>> {
    let mut given = vec![None; OPTIONS.len()];
    for &(index, value) in values {
        given[index] = Some(OsStr::new(value));
    }
    given
}

enum Outcome {
    Run(Vec<Option<&'static OsStr>>),
    Refused(Parsed),
    Help,
}

fn refused(message: &str) -> Parsed {
    Parsed::Refused {
        code: 2,
        text: format!("usage: tool [options]\ntool: error: {message}\n"),
    }
}

const PARSER: &str = "def given(v):\n    if not v: raise argparse.ArgumentTypeError('a value')\n    return v\n\
    def positive(v):\n    if not (v.isascii() and v.isdigit()) or int(v) == 0: \
    raise argparse.ArgumentTypeError('a positive integer')\n    return int(v)\n\
    p = argparse.ArgumentParser(prog='tool', allow_abbrev=False); \
    p.add_argument('--base', type=given); p.add_argument('--head', type=given); \
    p.add_argument('--max-mutants', type=positive); p.add_argument('--shard'); p.add_argument('--tests'); \
    p.add_argument('--artifacts', type=given); p.add_argument('--cargo', type=given)";

/// Each row's first field is the result of `PARSER` on Python 3.12.3. Python 3.9.25 gives another result
/// on the rows with a value `--` after `=`, which it reads as the empty list `[]` without a call of the
/// option's type, and on the rows with `-h=`, where it raises `IndexError`.
#[test]
fn long_options_without_prefixes_keep_the_last_value_and_check_each_occurrence() {
    #[rustfmt::skip]
    let rows: &[(&str, &[&str], Outcome)] = &[
        ("{'base': 'b', 'head': 'h', 'max_mutants': 3, 'shard': '0/2', 'tests': '-x y', 'artifacts': 'a', 'cargo': 'c'}",
         &["--base", "b", "--head=h", "--max-mutants", "3", "--shard", "0/2", "--tests", "-x y", "--artifacts", "a", "--cargo", "c"],
         Outcome::Run(run(&[(1, "b"), (2, "h"), (3, "3"), (4, "0/2"), (5, "-x y"), (6, "a"), (7, "c")]))),
        ("{'base': 'b'}", &["--base", "a", "--base", "b"], Outcome::Run(run(&[(1, "b")]))),
        ("{'max_mutants': 7}", &["--max-mutants", "5", "--max-mutants", "7"], Outcome::Run(run(&[(3, "7")]))),
        ("{'base': '--'}", &["--base=--"], Outcome::Run(run(&[(1, "--")]))),
        ("{'base': 'b'}", &["--base=--", "--base", "b"], Outcome::Run(run(&[(1, "b")]))),
        ("{'shard': '--'}", &["--shard=--"], Outcome::Run(run(&[(4, "--")]))),
        ("{'shard': '-5'}", &["--shard=1/2", "--shard", "-5"], Outcome::Run(run(&[(4, "-5")]))),
        ("argument --base: a value", &["--base=", "--base", "b"], Outcome::Refused(refused("argument --base: a value"))),
        ("argument --base: a value", &["--base", "b", "--base="], Outcome::Refused(refused("argument --base: a value"))),
        ("argument --max-mutants: a positive integer", &["--max-mutants", "0", "--max-mutants", "3"], Outcome::Refused(refused("argument --max-mutants: a positive integer"))),
        ("argument --max-mutants: a positive integer", &["--max-mutants", "3", "--max-mutants", "x"], Outcome::Refused(refused("argument --max-mutants: a positive integer"))),
        ("argument --max-mutants: a positive integer", &["--max-mutants", "-1"], Outcome::Refused(refused("argument --max-mutants: a positive integer"))),
        ("unrecognized arguments: --bas b", &["--bas", "b"], Outcome::Refused(refused("unrecognized arguments: --bas b"))),
        ("unrecognized arguments: --he h", &["--he", "h"], Outcome::Refused(refused("unrecognized arguments: --he h"))),
        ("unrecognized arguments: --b=x", &["--b=x"], Outcome::Refused(refused("unrecognized arguments: --b=x"))),
        ("unrecognized arguments: x", &["--base", "b", "x"], Outcome::Refused(refused("unrecognized arguments: x"))),
        ("argument --base: expected one argument", &["--base"], Outcome::Refused(refused("argument --base: expected one argument"))),
        ("argument --base: expected one argument", &["--base", "--head", "h"], Outcome::Refused(refused("argument --base: expected one argument"))),
        ("argument --tests: expected one argument", &["--tests", "--"], Outcome::Refused(refused("argument --tests: expected one argument"))),
        ("argument --cargo: expected one argument", &["--cargo", "a b", "--cargo", "-c"], Outcome::Refused(refused("argument --cargo: expected one argument"))),
        ("argument --max-mutants: a positive integer", &["--max-mutants=--"], Outcome::Refused(refused("argument --max-mutants: a positive integer"))),
        ("{'shard': '-.5'}", &["--shard", "-.5"], Outcome::Run(run(&[(4, "-.5")]))),
        ("argument --max-mutants: a positive integer", &["--max-mutants", "0", "-h"], Outcome::Refused(refused("argument --max-mutants: a positive integer"))),
        ("argument --max-mutants: a positive integer", &["--max-mutants", "0", "--base"], Outcome::Refused(refused("argument --max-mutants: a positive integer"))),
        ("argument -h/--help: ignored explicit argument ''", &["-h="], Outcome::Refused(refused("argument -h/--help: ignored explicit argument ''"))),
        ("argument -h/--help: ignored explicit argument ''", &["--help="], Outcome::Refused(refused("argument -h/--help: ignored explicit argument ''"))),
        ("argument -h/--help: ignored explicit argument ''", &["--base", "b", "-h="], Outcome::Refused(refused("argument -h/--help: ignored explicit argument ''"))),
        ("help", &["-hh"], Outcome::Help),
        ("help", &["-h"], Outcome::Help),
        ("help", &["--help"], Outcome::Help),
    ];
    for (python, args, expected) in rows {
        let found = read(args);
        match (expected, &found) {
            (Outcome::Run(given), Parsed::Run(values)) => {
                for (option, given) in OPTIONS.iter().zip(given) {
                    assert_eq!(
                        values.get(option.names[0]),
                        *given,
                        "{PARSER}; p.parse_args({args:?}) gives {python}"
                    );
                }
            }
            (Outcome::Refused(refusal), _) => {
                assert_eq!(
                    &found, refusal,
                    "{PARSER}; p.parse_args({args:?}) exits 2: {python}"
                )
            }
            (Outcome::Help, Parsed::Help(text)) => assert_eq!(text, "help\n"),
            _ => panic!("{PARSER}; p.parse_args({args:?}) gives {python}, not {found:?}"),
        }
    }
}

#[test]
fn a_negative_number_in_other_decimal_digits_reads_as_an_option() {
    let expression = "p.parse_args(['--base', '-\\u0661'])";
    let python = "Namespace(base='-\u{661}')";
    let found = read(&["--base", "-\u{661}"]);
    assert_eq!(
        found,
        refused("argument --base: expected one argument"),
        "{PARSER}; {expression} gives {python}; the reader takes ASCII digits"
    );
}

#[test]
fn every_name_of_a_row_selects_its_value() {
    const NAMED: [Opt; 2] = [
        Opt {
            names: &["-h", "--help"],
            kind: Kind::Help,
        },
        value(&["--out", "--output"], given),
    ];
    let parser = "p = argparse.ArgumentParser(prog='tool', allow_abbrev=False); \
        p.add_argument('--out', '--output', type=given)";
    let reader = Reader::new(
        "tool",
        "usage: tool [options]",
        "help\n",
        Prefixes::Refuse,
        &NAMED,
    );
    for args in [
        ["--output", "a", "--out", "b"],
        ["--out", "a", "--output", "b"],
    ] {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let Parsed::Run(values) = reader.parse(&args) else {
            panic!("{parser}; p.parse_args({args:?}) gives Namespace(out='b')");
        };
        for name in ["--out", "--output"] {
            assert_eq!(
                values.get(name),
                Some(OsStr::new("b")),
                "{parser}; p.parse_args({args:?}) gives Namespace(out='b')"
            );
        }
        assert_eq!(values.get("--help"), None);
    }
    let Parsed::Run(values) = reader.parse(&[]) else {
        panic!("{parser}; p.parse_args([]) gives Namespace(out=None)");
    };
    assert_eq!(values.get("--output"), None);
}

#[test]
#[should_panic(expected = "the option table names --missing")]
fn a_name_no_row_lists_panics() {
    let Parsed::Run(values) = read(&[]) else {
        panic!("{PARSER}; p.parse_args([]) runs");
    };
    values.get("--missing");
}

const HELP: Opt = Opt {
    names: &["-h", "--help"],
    kind: Kind::Help,
};

fn table(options: &[Opt]) {
    Reader::new("tool", "usage", "help\n", Prefixes::Select, options);
}

#[test]
#[should_panic(expected = "each option has a name")]
fn a_row_without_a_name_is_refused() {
    table(&[HELP, value(&[], any)]);
}

#[test]
#[should_panic(expected = "the option name base starts with a dash")]
fn a_name_without_a_dash_is_refused() {
    table(&[HELP, value(&["base"], any)]);
}

#[test]
#[should_panic(expected = "the option name - starts with a dash")]
fn a_one_byte_name_is_refused() {
    table(&[HELP, value(&["-"], any)]);
}

#[test]
#[should_panic(expected = "the option name -- starts with a dash and differs from --")]
fn the_name_double_dash_is_refused() {
    table(&[HELP, value(&["--"], any)]);
}

#[test]
#[should_panic(expected = "the option name --base appears once")]
fn a_repeated_name_is_refused() {
    table(&[HELP, value(&["--base"], any), value(&["--base"], any)]);
}

#[test]
#[should_panic(expected = "the table holds one help row")]
fn a_table_without_a_help_row_is_refused() {
    table(&[value(&["--base"], any)]);
}

#[test]
#[should_panic(expected = "the table holds one help row")]
fn a_table_with_two_help_rows_is_refused() {
    table(&[
        HELP,
        Opt {
            names: &["--usage"],
            kind: Kind::Help,
        },
    ]);
}

#[test]
#[should_panic(expected = "the help row holds the one short name, -h; -b breaks it")]
fn a_short_name_other_than_h_is_refused() {
    table(&[HELP, value(&["-b", "--base"], any)]);
}

#[test]
#[should_panic(expected = "the help row holds the one short name, -h; -x breaks it")]
fn a_short_name_other_than_h_on_the_help_row_is_refused() {
    table(&[Opt {
        names: &["-x", "--help"],
        kind: Kind::Help,
    }]);
}

const REPEATED: [Opt; 3] = [
    HELP,
    value(&["--base"], given),
    Opt {
        names: &["--plant"],
        kind: Kind::Repeated { check: given },
    },
];

fn repeated(args: &[&str]) -> Parsed {
    let reader = Reader::new(
        "tool",
        "usage: tool [options]",
        "help\n",
        Prefixes::Refuse,
        &REPEATED,
    );
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    reader.parse(&args)
}

/// `p.add_argument('--plant', action='append', default=[], type=given)` keeps each value in order, a repeat
/// included, in both forms; each value meets the check; `get` reads the last. An option of one value
/// given twice keeps the last alone.
#[test]
fn a_repeated_option_keeps_every_occurrence_in_order() {
    let Parsed::Run(values) = repeated(&[
        "--plant",
        "b",
        "--base",
        "w",
        "--plant=a",
        "--plant",
        "b",
        "--base",
        "x",
        "--plant",
        "c",
    ]) else {
        panic!("the arguments read");
    };
    let all: Vec<&OsStr> = values
        .all("--plant")
        .iter()
        .map(OsString::as_os_str)
        .collect();
    assert_eq!(all, ["b", "a", "b", "c"].map(OsStr::new));
    assert_eq!(values.get("--plant"), Some(OsStr::new("c")));
    let all: Vec<&OsStr> = values
        .all("--base")
        .iter()
        .map(OsString::as_os_str)
        .collect();
    assert_eq!(all, [OsStr::new("x")]);
    let Parsed::Run(none) = repeated(&[]) else {
        panic!("no argument reads");
    };
    assert!(none.all("--plant").is_empty());
    assert_eq!(
        repeated(&["--plant", "a", "--plant="]),
        refused("argument --plant: a value")
    );
    assert_eq!(
        repeated(&["--plant=", "--plant", "a"]),
        refused("argument --plant: a value")
    );
    assert_eq!(
        repeated(&["--plant"]),
        refused("argument --plant: expected one argument")
    );
}

const KINDS: [Opt; 4] = [
    HELP,
    value(&["--base"], any),
    Opt {
        names: &["--plant"],
        kind: Kind::Many {
            required: true,
            check: any,
        },
    },
    Opt {
        names: &["--quiet"],
        kind: Kind::Flag,
    },
];

fn kinds(args: &[&str]) -> Parsed {
    let reader = Reader::new(
        "tool",
        "usage: tool [options]",
        "help\n",
        Prefixes::Select,
        &KINDS,
    );
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    reader.parse(args.as_slice())
}

/// `--plant` is `nargs="+"` with `action="append"` and `required=True`, `--quiet` is
/// `action="store_true"`. A value after `=` is that value, `--` included, where Python 3.9.25 reads
/// `--plant=--` as no value and Python 3.12.3 as `--`.
#[test]
fn a_flag_takes_no_value_and_a_many_option_takes_each_value_up_to_the_next_option() {
    #[rustfmt::skip]
    type Row<'a> = (&'a [&'a str], Result<(&'a [&'a str], bool), &'a str>);
    let rows: &[Row] = &[
        (&["--plant", "a"], Ok((&["a"], false))),
        (
            &["--plant", "a", "b", "--base", "x"],
            Ok((&["a", "b"], false)),
        ),
        (&["--plant=a", "b"], Err("unrecognized arguments: b")),
        (
            &["--plant", "a", "--plant", "b", "c"],
            Ok((&["a", "b", "c"], false)),
        ),
        (
            &["--plant"],
            Err("argument --plant: expected at least one argument"),
        ),
        (
            &["--plant", "--base", "x"],
            Err("argument --plant: expected at least one argument"),
        ),
        (
            &["--plant", "--", "a"],
            Err("argument --plant: expected at least one argument"),
        ),
        (
            &["--plant", "a", "--", "b"],
            Err("unrecognized arguments: -- b"),
        ),
        (
            &["--plant", "-", "-1", "-.5", "a b"],
            Ok((&["-", "-1", "-.5", "a b"], false)),
        ),
        (
            &["--plant", "-x"],
            Err("argument --plant: expected at least one argument"),
        ),
        (&[], Err("the following arguments are required: --plant")),
        (
            &["--base", "x"],
            Err("the following arguments are required: --plant"),
        ),
        (&["--plant", "a", "--quiet"], Ok((&["a"], true))),
        (&["--plant", "a", "--quiet", "--quiet"], Ok((&["a"], true))),
        (
            &["--plant", "a", "--quiet=x"],
            Err("argument --quiet: ignored explicit argument 'x'"),
        ),
        (
            &["--plant", "a", "--quiet="],
            Err("argument --quiet: ignored explicit argument ''"),
        ),
        (&["--plant=", "a"], Err("unrecognized arguments: a")),
        (&["--plant=--"], Ok((&["--"], false))),
    ];
    for (args, expected) in rows {
        let found = kinds(args);
        match expected {
            Ok((plants, quiet)) => {
                let Parsed::Run(values) = found else {
                    panic!("{args:?} reads, not {found:?}");
                };
                let all: Vec<&OsStr> = values
                    .all("--plant")
                    .iter()
                    .map(OsString::as_os_str)
                    .collect();
                assert_eq!(
                    all,
                    plants.iter().map(OsStr::new).collect::<Vec<_>>(),
                    "{args:?}"
                );
                assert_eq!(values.flag("--quiet"), *quiet, "{args:?}");
            }
            Err(message) => assert_eq!(found, refused(message), "{args:?}"),
        }
    }
}

/// `p.add_argument('--plant', nargs='+', action='append', required=True, type=given)` refuses the first
/// value its type refuses, in either form, with the type's message.
#[test]
fn a_many_option_checks_each_value() {
    const CHECKED: [Opt; 2] = [
        HELP,
        Opt {
            names: &["--plant"],
            kind: Kind::Many {
                required: true,
                check: given,
            },
        },
    ];
    let reader = Reader::new(
        "tool",
        "usage: tool [options]",
        "help\n",
        Prefixes::Select,
        &CHECKED,
    );
    for args in [
        &["--plant", "a", ""][..],
        &["--plant", "", "a"],
        &["--plant="],
    ] {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        assert_eq!(
            reader.parse(&args),
            refused("argument --plant: a value"),
            "{args:?}"
        );
    }
}

/// `p.add_argument('--plant', nargs='+', action='append', type=given)` reads a command line without the
/// option, where `plant` is `None`, and asks for at least one value where the option stands.
#[test]
fn a_many_option_that_is_not_required_may_be_left_out() {
    const OPTIONAL: [Opt; 2] = [
        HELP,
        Opt {
            names: &["--plant"],
            kind: Kind::Many {
                required: false,
                check: given,
            },
        },
    ];
    let reader = Reader::new(
        "tool",
        "usage: tool [options]",
        "help\n",
        Prefixes::Select,
        &OPTIONAL,
    );
    let read = |args: &[&str]| {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        reader.parse(&args)
    };
    let Parsed::Run(values) = read(&[]) else {
        panic!("a command line without --plant reads");
    };
    assert!(values.all("--plant").is_empty());
    assert_eq!(values.get("--plant"), None);
    let Parsed::Run(values) = read(&["--plant", "a", "b"]) else {
        panic!("--plant a b reads");
    };
    assert_eq!(values.all("--plant"), ["a", "b"].map(OsString::from));
    assert_eq!(
        read(&["--plant"]),
        refused("argument --plant: expected at least one argument")
    );
    assert_eq!(
        read(&["--plant", "a", ""]),
        refused("argument --plant: a value")
    );
}

/// `parse_known` returns the leftover arguments in command-line order beside the values, and
/// `parse` refuses the same leftovers with the text of [`unrecognized`] after the missing-option
/// check.
#[test]
fn parse_known_keeps_the_leftovers_in_order_and_parse_refuses_them() {
    let reader = Reader::new(
        "tool",
        "usage: tool [options]",
        "help\n",
        Prefixes::Refuse,
        &OPTIONS,
    );
    let args: Vec<OsString> = ["x", "--base", "b", "--nope", "y", "--head=h", "-z"]
        .iter()
        .map(OsString::from)
        .collect();
    let Parsed::Run((values, extras)) = reader.parse_known(&args) else {
        panic!("the reader takes the values")
    };
    assert_eq!(values.get("--base"), Some(OsStr::new("b")));
    assert_eq!(values.get("--head"), Some(OsStr::new("h")));
    let expected: Vec<OsString> = ["x", "--nope", "y", "-z"]
        .iter()
        .map(OsString::from)
        .collect();
    assert_eq!(extras, expected);
    assert_eq!(reader.parse(&args), refused(&unrecognized(&expected)));
}

/// `reads` sorts one argument as `parse` does: a value, an option of a row, an unknown option, or
/// the refusal of an ambiguous prefix.
#[test]
fn reads_sorts_an_argument_as_parse_does() {
    let reader = Reader::new(
        "tool",
        "usage: tool [options]",
        "help\n",
        Prefixes::Select,
        &OPTIONS,
    );
    for (arg, expected) in [
        ("--", Ok(Reads::End)),
        ("x", Ok(Reads::Value)),
        ("-", Ok(Reads::Value)),
        ("-1", Ok(Reads::Value)),
        ("-a b", Ok(Reads::Value)),
        ("--base", Ok(Reads::Option)),
        ("--ba=x", Ok(Reads::Option)),
        ("-hx=y", Ok(Reads::Option)),
        ("--nope", Ok(Reads::Unknown)),
        (
            "--=x",
            Err(
                "ambiguous option: --=x could match --help, --base, --head, --max-mutants, \
                 --shard, --tests, --artifacts, --cargo"
                    .to_owned(),
            ),
        ),
    ] {
        assert_eq!(reader.reads(OsStr::new(arg)), expected, "{arg}");
    }
}

/// The rows' texts after `error: ` were recorded from Python 3.9's `argparse` with a required subparser
/// action `command` holding `check` and `run --work WORK [--row ROW]...`; the usage lines and program
/// names are this reader's own.
#[test]
fn a_command_word_selects_its_reader_as_argparse_reads_subparsers() {
    use crate::args::{Commands, Word};
    const CHECK: [Opt; 1] = [Opt {
        names: &["-h", "--help"],
        kind: Kind::Help,
    }];
    const RUN: [Opt; 3] = [
        Opt {
            names: &["-h", "--help"],
            kind: Kind::Help,
        },
        Opt {
            names: &["--work"],
            kind: Kind::Value {
                required: true,
                check: any,
            },
        },
        Opt {
            names: &["--row"],
            kind: Kind::Repeated { check: any },
        },
    ];
    let words = [
        Word {
            word: "check",
            reader: Reader::new(
                "t check",
                "usage: t check",
                "check help",
                Prefixes::Select,
                &CHECK,
            ),
        },
        Word {
            word: "run",
            reader: Reader::new("t run", "usage: t run", "run help", Prefixes::Select, &RUN),
        },
    ];
    let commands = Commands::new("t", "usage: t", "top help", &words);
    let parse = |line: &str| {
        let args: Vec<OsString> = line.split_whitespace().map(OsString::from).collect();
        commands.parse(&args)
    };
    let refused = |prefix: &str, message: &str| Parsed::<()>::Refused {
        code: 2,
        text: format!("usage: {prefix}\n{prefix}: error: {message}\n"),
    };
    let rows = [
        (
            "",
            refused("t", "the following arguments are required: command"),
        ),
        (
            "bogus",
            refused(
                "t",
                "argument command: invalid choice: 'bogus' (choose from 'check', 'run')",
            ),
        ),
        (
            "bogus -h",
            refused(
                "t",
                "argument command: invalid choice: 'bogus' (choose from 'check', 'run')",
            ),
        ),
        (
            "--",
            refused("t", "the following arguments are required: command"),
        ),
        (
            "-x --",
            refused("t", "the following arguments are required: command"),
        ),
        (
            "-- check",
            refused(
                "t",
                "argument command: invalid choice: '--' (choose from 'check', 'run')",
            ),
        ),
        (
            "-1 check",
            refused(
                "t",
                "argument command: invalid choice: '-1' (choose from 'check', 'run')",
            ),
        ),
        (
            "--work x check",
            refused(
                "t",
                "argument command: invalid choice: 'x' (choose from 'check', 'run')",
            ),
        ),
        ("check extra", refused("t", "unrecognized arguments: extra")),
        (
            "--work=x check",
            refused("t", "unrecognized arguments: --work=x"),
        ),
        ("-x check", refused("t", "unrecognized arguments: -x")),
        ("check -- x", refused("t", "unrecognized arguments: -- x")),
        (
            "run --work d x y",
            refused("t", "unrecognized arguments: x y"),
        ),
        (
            "run --work d -x",
            refused("t", "unrecognized arguments: -x"),
        ),
        (
            "run",
            refused("t run", "the following arguments are required: --work"),
        ),
        (
            "run -x",
            refused("t run", "the following arguments are required: --work"),
        ),
        (
            "-x run",
            refused("t run", "the following arguments are required: --work"),
        ),
        (
            "run --work",
            refused("t run", "argument --work: expected one argument"),
        ),
        (
            "run --work d --row",
            refused("t run", "argument --row: expected one argument"),
        ),
        ("--he", Parsed::Help("top help".to_owned())),
        ("-x -h check", Parsed::Help("top help".to_owned())),
        ("check -h x", Parsed::Help("check help".to_owned())),
        ("run -h", Parsed::Help("run help".to_owned())),
    ];
    for (line, expected) in rows {
        let parsed = parse(line).map(|_| ());
        assert_eq!(parsed, expected, "{line:?}");
    }
    let Parsed::Run((index, values)) = parse("run --wo d --ro a --row b") else {
        panic!("a run parses");
    };
    assert_eq!(index, 1);
    assert_eq!(values.get("--work"), Some(OsStr::new("d")));
    assert_eq!(
        values.all("--row"),
        [OsString::from("a"), OsString::from("b")]
    );
    let Parsed::Run((index, _)) = parse("check") else {
        panic!("a check parses");
    };
    assert_eq!(index, 0);
}
