use std::ffi::OsString;

use crate::fixtures::args::{Options, parse};

fn read(args: &[&str]) -> Result<Options, u8> {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    parse("tool", "About.", &args)
}

fn options(quint: Option<&str>, output: Option<&str>) -> Options {
    Options {
        quint: quint.map(OsString::from),
        output: output.map(OsString::from),
    }
}

#[test]
fn values_follow_an_equals_sign_a_prefix_or_the_next_argument_and_the_last_wins() {
    assert_eq!(
        read(&["--quint", "q", "--output", "o"]),
        Ok(options(Some("q"), Some("o")))
    );
    assert_eq!(
        read(&["--qu", "a", "--o=b", "--quint=c"]),
        Ok(options(Some("c"), Some("b")))
    );
    assert_eq!(
        read(&["--quint", "-5", "--output", "o"]),
        Ok(options(Some("-5"), Some("o")))
    );
    assert_eq!(
        read(&["--quint", "-5\n", "--output", "-"]),
        Ok(options(Some("-5\n"), Some("-")))
    );
    assert_eq!(
        read(&["--quint", "-a b", "--output", ""]),
        Ok(options(Some("-a b"), Some("")))
    );
    assert_eq!(
        read(&["--quint=--", "--output", "o"]),
        Ok(options(None, Some("o")))
    );
    assert_eq!(
        read(&["--quint=", "--output", "o"]),
        Ok(options(Some(""), Some("o")))
    );
}

#[test]
fn argument_errors_exit_2_and_help_exits_0_in_the_order_the_reader_meets_them() {
    let cases: [(&[&str], u8); 13] = [
        (&[], 2),
        (&["x", "--", "y"], 2),
        (&["--quint", "a", "--output", "b", "--", "z"], 2),
        (&["--quint", "-x", "--output", "o"], 2),
        (&["--quint", "--", "a", "--output", "b"], 2),
        (&["-q", "--quint", "a", "--output", "b"], 2),
        (&["--quint"], 2),
        (&["-hhx"], 2),
        (&["--help=x"], 2),
        (&["--=x", "-h"], 2),
        (&["-hh"], 0),
        (&["x", "-h"], 0),
        (&["--quint", "a", "-h", "--quint"], 0),
    ];
    for (args, code) in cases {
        assert_eq!(read(args).err(), Some(code), "{args:?}");
    }
    assert_eq!(read(&["-h="]).err(), Some(1));
}
