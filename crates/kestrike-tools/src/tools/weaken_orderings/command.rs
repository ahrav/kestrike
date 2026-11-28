//! The tool's entry: the command word, `check` and `run`.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;

use crate::args::{Commands, Kind, Opt, Parsed, Prefixes, Reader, Word, any};
use crate::genmc::{package_sources, read_source};
use crate::json::{self, Value};
use crate::orderings::check::check;
use crate::orderings::sites::EXTERNAL;
use crate::plants::UNANNOUNCED;
use crate::process::ignore_file_size_signal;

const USAGE: &str = "usage: weaken-orderings [-h] {check,run} ...";
const CHECK_USAGE: &str = "usage: weaken-orderings check [-h]";
const RUN_USAGE: &str = "usage: weaken-orderings run [-h] --work WORK [--row ROW]";

const HELP: Opt = Opt {
    names: &["-h", "--help"],
    kind: Kind::Help,
};
const CHECK: [Opt; 1] = [HELP];
const RUN: [Opt; 3] = [
    HELP,
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

/// `checked` prints the report `check` gives as JSON indented by two spaces in document order, with a
/// newline, on `out`, and returns the check's exit code.
pub(super) fn checked(check: impl FnOnce() -> (Value, u8), out: &mut impl Write) -> u8 {
    let (report, code) = check();
    match writeln!(out, "{}", json::indented_in_order(&report)).and_then(|()| out.flush()) {
        Ok(()) => code,
        Err(_) => UNANNOUNCED,
    }
}

/// `run` reads the command word and its options from `args` and runs that command on the checkout
/// `top`.
pub fn run(top: &Path, args: &[OsString]) -> u8 {
    if let Err(error) = ignore_file_size_signal() {
        let _ = writeln!(
            io::stderr(),
            "weaken-orderings: SIGXFSZ cannot be ignored: {error}"
        );
        return 1;
    }
    let help = format!("{USAGE}\n\n{}", include_str!("help.md"));
    let check_help = format!(
        "{CHECK_USAGE}\n\noptional arguments:\n  -h, --help  show this help message and exit\n"
    );
    let run_help = format!(
        "{RUN_USAGE}\n\noptional arguments:\n  -h, --help   show this help message and exit\n  --work WORK\n  --row ROW\n"
    );
    let words = [
        Word {
            word: "check",
            reader: Reader::new(
                "weaken-orderings check",
                CHECK_USAGE,
                &check_help,
                Prefixes::Select,
                &CHECK,
            ),
        },
        Word {
            word: "run",
            reader: Reader::new(
                "weaken-orderings run",
                RUN_USAGE,
                &run_help,
                Prefixes::Select,
                &RUN,
            ),
        },
    ];
    let commands = Commands::new(super::NAME, USAGE, &help, &words);
    let (mut out, mut err) = (io::stdout().lock(), io::stderr().lock());
    match commands.parse(args) {
        Parsed::Help(text) => match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
            Ok(()) => 0,
            Err(_) => UNANNOUNCED,
        },
        Parsed::Refused { code, text } => {
            let _ = err.write_all(text.as_bytes());
            code
        }
        Parsed::Run((0, _)) => {
            let read = |path: &str| read_source(top, path);
            checked(
                || check(&read, top, top, EXTERNAL, &package_sources),
                &mut out,
            )
        }
        Parsed::Run((_, values)) => {
            let work = values.get("--work").unwrap_or_default().to_owned();
            super::run::run_command(top, &work, values.all("--row"), &mut out, &mut err)
        }
    }
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;
