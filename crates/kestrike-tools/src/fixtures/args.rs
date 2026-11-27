//! The fixture writer's command line follows `argparse`'s conventions. It takes the required options
//! `--quint` and `--output` and the help option `-h`/`--help`.
//!
//! `--quint` and `--output` accept a value in the next argument or after `=`, where any text is the value,
//! the empty string and `--` included. A unique long-option prefix selects the matching option, and a
//! repeated option keeps its last value. The text of [`Parsed::Refused`] is the usage line and
//! `<tool>: error: <message>`, and its code is 2.

use std::ffi::OsString;

use crate::args::{Kind, Opt, Prefixes, Reader, Values, any};

#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub quint: OsString,
    pub output: OsString,
}

pub type Parsed = crate::args::Parsed<Options>;

const OPTIONS: [Opt; 3] = [
    Opt {
        names: &["-h", "--help"],
        kind: Kind::Help,
    },
    Opt {
        names: &["--quint"],
        kind: Kind::Value {
            required: true,
            check: any,
        },
    },
    Opt {
        names: &["--output"],
        kind: Kind::Value {
            required: true,
            check: any,
        },
    },
];

pub fn parse(tool: &str, about: &str, args: &[OsString]) -> Parsed {
    let usage = format!("usage: {tool} [-h] --quint QUINT --output OUTPUT");
    let help = format!(
        "{usage}\n\n{about}\n\noptional arguments:\n  -h, --help       show this help message and exit\n  \
         --quint QUINT\n  --output OUTPUT\n"
    );
    let reader = Reader::new(tool, &usage, &help, Prefixes::Select, &OPTIONS);
    reader.parse(args).map(|values| Options {
        quint: required(&values, "--quint"),
        output: required(&values, "--output"),
    })
}

/// `OPTIONS` marks `name` required, so the reader returns [`Values`] only with a value for it.
fn required(values: &Values, name: &str) -> OsString {
    values
        .get(name)
        .expect("the reader returns the values of a command line that gives each required option")
        .to_owned()
}
