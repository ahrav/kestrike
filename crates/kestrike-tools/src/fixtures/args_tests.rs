use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use crate::fixtures::args::{Options, Parsed, parse};

fn read(args: &[&str]) -> Parsed {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    parse("tool", "About.", &args)
}

fn run(quint: Option<&str>, output: Option<&str>) -> Parsed {
    Parsed::Run(Options {
        quint: quint.map(OsString::from),
        output: output.map(OsString::from),
    })
}

fn refused(code: u8, message: &str) -> Parsed {
    let text = format!("usage: tool [-h] --quint QUINT --output OUTPUT\ntool: error: {message}\n");
    Parsed::Refused { code, text }
}

#[test]
fn values_follow_an_equals_sign_a_prefix_or_the_next_argument_and_the_last_wins() {
    assert_eq!(
        read(&["--quint", "q", "--output", "o"]),
        run(Some("q"), Some("o"))
    );
    assert_eq!(
        read(&["--qu", "a", "--o=b", "--quint=c"]),
        run(Some("c"), Some("b"))
    );
    assert_eq!(
        read(&["--quint", "-5", "--output", "o"]),
        run(Some("-5"), Some("o"))
    );
    assert_eq!(
        read(&["--quint", "-5\n", "--output", "-"]),
        run(Some("-5\n"), Some("-"))
    );
    assert_eq!(
        read(&["--quint", "-a b", "--output", ""]),
        run(Some("-a b"), Some(""))
    );
    assert_eq!(read(&["--quint=--", "--output", "o"]), run(None, Some("o")));
    assert_eq!(
        read(&["--quint=", "--output", "o"]),
        run(Some(""), Some("o"))
    );
}

/// For `-h=`, the reader returns `string index out of range` with status 1, the behavior kept from the script;
/// issue #363 holds its fix.
#[test]
fn each_refusal_carries_the_message_argparse_prints() {
    let required = "the following arguments are required: --quint, --output";
    let cases: [(&[&str], &str); 12] = [
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
        (
            &["--=x", "-h"],
            "ambiguous option: --=x could match --help, --quint, --output",
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
        assert_eq!(read(args), refused(2, message), "{args:?}");
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
        refused(2, "unrecognized arguments: x\\udcff")
    );
    let index = Parsed::Refused {
        code: 1,
        text: "tool: argument -h/--help: string index out of range\n".to_owned(),
    };
    assert_eq!(read(&["-h="]), index);
}

#[test]
fn help_wins_once_the_reader_reaches_it() {
    for args in [
        &["-hh"][..],
        &["x", "-h"],
        &["--quint", "a", "-h", "--quint"],
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
