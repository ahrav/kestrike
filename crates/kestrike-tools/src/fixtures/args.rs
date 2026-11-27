//! The fixture writer's command line follows Python 3.9's `argparse` conventions. It takes the required
//! options `--quint` and `--output` and the help option `-h`/`--help`.
//!
//! `--quint` and `--output` accept a value in the next argument or after `=`. A unique long-option prefix
//! selects the matching option, and a repeated option keeps its last value. For [`Parsed::Refused`] with code
//! 2, the text is the usage line and `<tool>: error: <message>`.

use std::ffi::OsString;

use crate::args::{Given, Opt, Reader, any};

#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub quint: Option<OsString>,
    pub output: Option<OsString>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Run(Options),
    Help(String),
    Refused { code: u8, text: String },
}

const OPTIONS: [Opt; 3] = [
    Opt {
        names: &["-h", "--help"],
        takes_value: false,
        required: false,
        prefix: true,
        check: any,
    },
    Opt {
        names: &["--quint"],
        takes_value: true,
        required: true,
        prefix: true,
        check: any,
    },
    Opt {
        names: &["--output"],
        takes_value: true,
        required: true,
        prefix: true,
        check: any,
    },
];

pub fn parse(tool: &str, about: &str, args: &[OsString]) -> Parsed {
    let usage = format!("usage: {tool} [-h] --quint QUINT --output OUTPUT");
    let help = format!(
        "{usage}\n\n{about}\n\noptional arguments:\n  -h, --help       show this help message and exit\n  \
         --quint QUINT\n  --output OUTPUT\n"
    );
    let reader = Reader {
        tool,
        usage: &usage,
        help: &help,
        options: &OPTIONS,
    };
    let value = |given: &Given| match given {
        Given::Value(value) => Some(value.clone()),
        Given::Absent | Given::Empty => None,
    };
    match reader.parse(args) {
        crate::args::Parsed::Run(values) => Parsed::Run(Options {
            quint: value(values.get(1)),
            output: value(values.get(2)),
        }),
        crate::args::Parsed::Help(text) => Parsed::Help(text),
        crate::args::Parsed::Refused { code, text } => Parsed::Refused { code, text },
    }
}
