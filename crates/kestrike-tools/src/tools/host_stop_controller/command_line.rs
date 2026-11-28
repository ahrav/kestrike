//! The command line: a command, `run`, `restore` or `seal`, named by its whole word, then its
//! options, each read by [`Reader`] with a unique prefix selecting its row. Ahead of the command
//! each argument reads by a [`Reader`] of the help row alone: an option of that row asks for the help
//! or is refused as that reader refuses it, an unknown option is left over, and the first argument
//! that reads as a value, or `--` with an argument after it, is the command's word. The leftover
//! arguments of both levels are refused together, once the command's own options are read.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::args::{Kind, Opt, Parsed, Prefixes, Reader, Reads, Values, any, unrecognized};
use crate::host_stop_controller::Command;
use crate::text::Text;

/// The text `-h` prints.
pub const HELP: &str = include_str!("help.txt");

const TOOL: &str = super::NAME;
const USAGE: &str = "usage: host-stop-controller [-h] {run,restore,seal} ...";

/// One command: its word, its option table, its usage line and the [`Command`] its values build.
struct Spec {
    word: &'static str,
    table: &'static [Opt],
    usage: &'static str,
    command: fn(&Values) -> Command,
}

const HELP_ROW: Opt = Opt {
    names: &["-h", "--help"],
    kind: Kind::Help,
};

const fn required(names: &'static [&'static str]) -> Opt {
    Opt {
        names,
        kind: Kind::Value {
            required: true,
            check: any,
        },
    }
}

const RUN: [Opt; 4] = [
    HELP_ROW,
    required(&["--operator"]),
    required(&["--package"]),
    required(&["--evidence"]),
];

const RESTORE: [Opt; 4] = [
    HELP_ROW,
    required(&["--operator"]),
    required(&["--evidence"]),
    Opt {
        names: &["--reviewed"],
        kind: Kind::Value {
            required: false,
            check: any,
        },
    },
];

const SEAL: [Opt; 3] = [
    HELP_ROW,
    required(&["--operator"]),
    required(&["--evidence"]),
];

const SPECS: [Spec; 3] = [
    Spec {
        word: "run",
        table: &RUN,
        usage: "usage: host-stop-controller run [-h] --operator F --package F --evidence DIR",
        command: |values| Command::Run {
            operator: path(values, "--operator"),
            package: path(values, "--package"),
            evidence: value(values, "--evidence"),
        },
    },
    Spec {
        word: "restore",
        table: &RESTORE,
        usage: "usage: host-stop-controller restore [-h] --operator F --evidence DIR [--reviewed F]",
        command: |values| Command::Restore {
            operator: path(values, "--operator"),
            evidence: value(values, "--evidence"),
            reviewed: values.get("--reviewed").map(PathBuf::from),
        },
    },
    Spec {
        word: "seal",
        table: &SEAL,
        usage: "usage: host-stop-controller seal [-h] --operator F --evidence DIR",
        command: |values| Command::Seal {
            operator: path(values, "--operator"),
            evidence: value(values, "--evidence"),
        },
    },
];

/// `read` returns the command `args` name, the help, or the refusal with exit 2 and the words after
/// `error:` of each of the six errors: no command, an invalid command, missing options, a missing
/// value, leftover arguments and a value given to the help.
pub fn read(args: &[OsString]) -> Parsed<Command> {
    let top = Reader::new(TOOL, USAGE, HELP, Prefixes::Select, &[HELP_ROW]);
    let mut leftover = Vec::new();
    let mut word = None;
    for (at, arg) in args.iter().enumerate() {
        match top.reads(arg) {
            Ok(Reads::End) => {
                if at + 1 < args.len() {
                    word = Some(at);
                }
                break;
            }
            Ok(Reads::Value) => {
                word = Some(at);
                break;
            }
            Ok(Reads::Option) => {
                return top
                    .parse(std::slice::from_ref(arg))
                    .map(|_| unreachable!("an argument that reads as the help row is help"));
            }
            Ok(Reads::Unknown) => leftover.push(arg.clone()),
            Err(message) => return top.refuse(message),
        }
    }
    let Some(at) = word else {
        return top.refuse("the following arguments are required: command".to_owned());
    };
    let name = args[at].as_bytes();
    let Some(spec) = SPECS.iter().find(|spec| spec.word.as_bytes() == name) else {
        let choices: Vec<String> = SPECS
            .iter()
            .map(|spec| format!("'{}'", spec.word))
            .collect();
        let shown = Text::from_os(&args[at]).repr();
        let message = format!(
            "argument command: invalid choice: {shown} (choose from {})",
            choices.join(", ")
        );
        return top.refuse(message);
    };
    let tool = format!("{TOOL} {}", spec.word);
    let reader = Reader::new(&tool, spec.usage, HELP, Prefixes::Select, spec.table);
    let (values, extras) = match reader.parse_known(&args[at + 1..]) {
        Parsed::Run(read) => read,
        Parsed::Help(help) => return Parsed::Help(help),
        Parsed::Refused { code, text } => return Parsed::Refused { code, text },
    };
    leftover.extend(extras);
    if !leftover.is_empty() {
        return top.refuse(unrecognized(&leftover));
    }
    Parsed::Run((spec.command)(&values))
}

fn path(values: &Values, name: &str) -> PathBuf {
    PathBuf::from(value(values, name))
}

fn value(values: &Values, name: &str) -> OsString {
    values
        .get(name)
        .map(OsStr::to_owned)
        .expect("the reader refuses a missing required option")
}
