use std::ffi::OsString;

use crate::args::{Given, Opt, Parsed, Reader, any};
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
        takes_value: true,
        required: false,
        prefix: false,
        check,
    }
}

const OPTIONS: [Opt; 8] = [
    Opt {
        names: &["-h", "--help"],
        takes_value: false,
        required: false,
        prefix: false,
        check: any,
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
    let reader = Reader::new("tool", "usage: tool [options]", "help\n", &OPTIONS);
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    reader.parse(&args)
}

fn run(values: &[(usize, Option<&str>)]) -> Vec<Given> {
    let mut given = vec![Given::Absent; OPTIONS.len()];
    for &(index, value) in values {
        given[index] = value.map_or(Given::Empty, |value| Given::Value(OsString::from(value)));
    }
    given
}

enum Outcome {
    Run(Vec<Given>),
    Refused(Parsed),
    Help,
}

fn refused(message: &str) -> Parsed {
    Parsed::Refused {
        code: 2,
        text: format!("usage: tool [options]\ntool: error: {message}\n"),
    }
}

const PARSER: &str = "p = argparse.ArgumentParser(prog='tool', allow_abbrev=False); \
    p.add_argument('--base', type=given); p.add_argument('--head', type=given); \
    p.add_argument('--max-mutants', type=positive); p.add_argument('--shard'); p.add_argument('--tests'); \
    p.add_argument('--artifacts', type=given); p.add_argument('--cargo', type=given)";

#[test]
fn long_options_without_prefixes_keep_the_last_value_and_check_each_occurrence() {
    #[rustfmt::skip]
    let rows: &[(&str, &[&str], Outcome)] = &[
        ("{'base': 'b', 'head': 'h', 'max_mutants': 3, 'shard': '0/2', 'tests': '-x y', 'artifacts': 'a', 'cargo': 'c'}",
         &["--base", "b", "--head=h", "--max-mutants", "3", "--shard", "0/2", "--tests", "-x y", "--artifacts", "a", "--cargo", "c"],
         Outcome::Run(run(&[(1, Some("b")), (2, Some("h")), (3, Some("3")), (4, Some("0/2")), (5, Some("-x y")), (6, Some("a")), (7, Some("c"))]))),
        ("{'base': 'b'}", &["--base", "a", "--base", "b"], Outcome::Run(run(&[(1, Some("b"))]))),
        ("{'max_mutants': 7}", &["--max-mutants", "5", "--max-mutants", "7"], Outcome::Run(run(&[(3, Some("7"))]))),
        ("{'base': []}", &["--base=--"], Outcome::Run(run(&[(1, None)]))),
        ("{'shard': '-5'}", &["--shard=1/2", "--shard", "-5"], Outcome::Run(run(&[(4, Some("-5"))]))),
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
                        given,
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
