use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use crate::fixtures::args::{Options, Parsed, parse};

fn read(args: &[&str]) -> Parsed {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    parse("tool", "About.", &args)
}

fn run(quint: &str, output: &str) -> Parsed {
    Parsed::Run(Options {
        quint: OsString::from(quint),
        output: OsString::from(output),
    })
}

fn refused(message: &str) -> Parsed {
    let text = format!("usage: tool [-h] --quint QUINT --output OUTPUT\ntool: error: {message}\n");
    Parsed::Refused { code: 2, text }
}

#[test]
fn values_follow_an_equals_sign_a_prefix_or_the_next_argument_and_the_last_wins() {
    assert_eq!(read(&["--quint", "q", "--output", "o"]), run("q", "o"));
    assert_eq!(read(&["--qu", "a", "--o=b", "--quint=c"]), run("c", "b"));
    assert_eq!(read(&["--quint", "-5", "--output", "o"]), run("-5", "o"));
    assert_eq!(
        read(&["--quint", "-5\n", "--output", "-"]),
        run("-5\n", "-")
    );
    assert_eq!(read(&["--quint", "-a b", "--output", ""]), run("-a b", ""));
    assert_eq!(read(&["--quint=--", "--output", "o"]), run("--", "o"));
    assert_eq!(read(&["--quint", "q", "--output=--"]), run("q", "--"));
    assert_eq!(read(&["--qu=--", "--out=--"]), run("--", "--"));
    assert_eq!(read(&["--quint=", "--output", "o"]), run("", "o"));
}

#[test]
fn each_refusal_carries_the_message_argparse_prints() {
    let required = "the following arguments are required: --quint, --output";
    let cases: [(&[&str], &str); 18] = [
        (&[], required),
        (&["x", "--", "y"], required),
        (
            &["--quint", "a", "--output", "b", "--", "z"],
            "unrecognized arguments: -- z",
        ),
        (
            &["--quint", "-x", "--output", "o"],
            "argument --quint: expected one argument",
        ),
        (
            &["--quint", "--", "a", "--output", "b"],
            "argument --quint: expected one argument",
        ),
        (
            &["-q", "--quint", "a", "--output", "b"],
            "unrecognized arguments: -q",
        ),
        (&["--quint"], "argument --quint: expected one argument"),
        (
            &["-hhx"],
            "argument -h/--help: ignored explicit argument 'x'",
        ),
        (
            &["--help=x"],
            "argument -h/--help: ignored explicit argument 'x'",
        ),
        (&["-h="], "argument -h/--help: ignored explicit argument ''"),
        (
            &["--help="],
            "argument -h/--help: ignored explicit argument ''",
        ),
        (
            &["--quint", "a", "--output", "o", "-h="],
            "argument -h/--help: ignored explicit argument ''",
        ),
        (
            &["--=x", "-h"],
            "ambiguous option: --=x could match --help, --quint, --output",
        ),
        (
            &["-h", "--=x"],
            "ambiguous option: --=x could match --help, --quint, --output",
        ),
        (
            &["--help", "--=x"],
            "ambiguous option: --=x could match --help, --quint, --output",
        ),
        (
            &["--quint", "q", "-h", "--="],
            "ambiguous option: --= could match --help, --quint, --output",
        ),
        (
            &["-h'\"x"],
            "argument -h/--help: ignored explicit argument '\\'\"x'",
        ),
        (
            &["-h\u{1}\u{e9}"],
            "argument -h/--help: ignored explicit argument '\\x01\u{e9}'",
        ),
    ];
    for (args, message) in cases {
        assert_eq!(read(args), refused(message), "{args:?}");
    }
    let bytes = [
        b"--quint".to_vec(),
        b"a".to_vec(),
        b"--output".to_vec(),
        b"o".to_vec(),
        b"x\xff".to_vec(),
    ];
    let args: Vec<OsString> = bytes.into_iter().map(OsString::from_vec).collect();
    assert_eq!(
        parse("tool", "About.", &args),
        refused("unrecognized arguments: x\\udcff")
    );
}

/// Help precedes each error the reader would find behind it while it reads values: a missing value
/// (`-h --quint`) and text attached to a later help name (`-h --help=x`, `-h -hx`). An ambiguous prefix
/// behind help is refused instead, since every argument is classified before the first is read; the rows
/// `-h --=x` of the refusal test assert that.
#[test]
fn help_wins_once_the_reader_reaches_it() {
    for args in [
        &["-hh"][..],
        &["x", "-h"],
        &["--quint", "a", "-h", "--quint"],
        &["-h", "--quint"],
        &["-h", "--help=x"],
        &["-h", "-hx"],
        &["--he"],
    ] {
        let Parsed::Help(text) = read(args) else {
            panic!("{args:?} prints the help");
        };
        assert!(
            text.starts_with("usage: tool [-h] --quint QUINT --output OUTPUT\n\nAbout.\n"),
            "{text}"
        );
    }
}
