use std::ffi::{OsStr, OsString};

use crate::args::{Kind, Opt, Parsed, Prefixes, Reader, any};
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
