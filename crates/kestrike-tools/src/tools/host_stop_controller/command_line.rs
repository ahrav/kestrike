//! The command line: a command, `run`, `restore` or `seal`, named by its whole word, then its
//! options, each read by [`Reader`] with a unique prefix selecting its row. Ahead of the command,
//! `-h`, `--help` and a prefix of `--help` ask for the help, and every other argument that reads as
//! an option is left over; the first argument that reads as a value, or `--` with an argument after
//! it, is the command's word. The leftover arguments of both levels are refused together, once the
//! command's own options are read.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::args::{Kind, Opt, Parsed, Prefixes, Reader, any, unrecognized};
use crate::host_stop_controller::Command;
use crate::text::Text;

/// The text `-h` prints.
pub const HELP: &str = include_str!("help.txt");

const TOOL: &str = super::NAME;
const USAGE: &str = "usage: host-stop-controller [-h] {run,restore,seal} ...";
const COMMANDS: [&str; 3] = ["run", "restore", "seal"];

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

/// How an argument ahead of the command reads.
enum Ahead<'a> {
    Value,
    /// `-h`, `--help` or a prefix of `--help`, with the text after its name and `=`, or after `-h`.
    Help(Option<&'a [u8]>),
    Unknown,
}

/// `read` returns the command `args` name, the help, or the refusal with exit 2 and the words after
/// `error:` of each of the six errors: no command, an invalid command, missing options, a missing
/// value, leftover arguments and a value given to the help.
pub fn read(args: &[OsString]) -> Parsed<Command> {
    let mut leftover = Vec::new();
    let mut word = None;
    for (at, arg) in args.iter().enumerate() {
        let bytes = arg.as_bytes();
        if bytes == b"--" {
            if at + 1 < args.len() {
                word = Some(at);
            }
            break;
        }
        match ahead(bytes) {
            Ahead::Value => {
                word = Some(at);
                break;
            }
            Ahead::Help(None) => return Parsed::Help(HELP.to_owned()),
            Ahead::Help(Some(_)) => return help_with(arg),
            Ahead::Unknown => leftover.push(arg.clone()),
        }
    }
    let Some(at) = word else {
        return refused(USAGE, TOOL, "the following arguments are required: command");
    };
    let name = args[at].as_bytes();
    let Some(&command) = COMMANDS.iter().find(|command| command.as_bytes() == name) else {
        let choices: Vec<String> = COMMANDS.iter().map(|c| format!("'{c}'")).collect();
        let shown = Text::from_os(&args[at]).repr();
        let message = format!(
            "argument command: invalid choice: {shown} (choose from {})",
            choices.join(", ")
        );
        return refused(USAGE, TOOL, &message);
    };
    let (table, usage): (&[Opt], &str) = match command {
        "run" => (
            &RUN,
            "usage: host-stop-controller run [-h] --operator F --package F --evidence DIR",
        ),
        "restore" => (
            &RESTORE,
            "usage: host-stop-controller restore [-h] --operator F --evidence DIR [--reviewed F]",
        ),
        _ => (
            &SEAL,
            "usage: host-stop-controller seal [-h] --operator F --evidence DIR",
        ),
    };
    let tool = format!("{TOOL} {command}");
    let reader = Reader::new(&tool, usage, HELP, Prefixes::Select, table);
    let (values, extras) = match reader.parse_known(&args[at + 1..]) {
        Parsed::Run(read) => read,
        Parsed::Help(help) => return Parsed::Help(help),
        Parsed::Refused { code, text } => return Parsed::Refused { code, text },
    };
    leftover.extend(extras);
    if !leftover.is_empty() {
        return refused(USAGE, TOOL, &unrecognized(&leftover));
    }
    let path = |name| PathBuf::from(value(&values, name));
    Parsed::Run(match command {
        "run" => Command::Run {
            operator: path("--operator"),
            package: path("--package"),
            evidence: value(&values, "--evidence"),
        },
        "restore" => Command::Restore {
            operator: path("--operator"),
            evidence: value(&values, "--evidence"),
            reviewed: values.get("--reviewed").map(PathBuf::from),
        },
        _ => Command::Seal {
            operator: path("--operator"),
            evidence: value(&values, "--evidence"),
        },
    })
}

fn value(values: &crate::args::Values, name: &str) -> OsString {
    values
        .get(name)
        .map(OsStr::to_owned)
        .expect("the reader refuses a missing required option")
}

/// How `arg`, which is not `--`, reads ahead of the command, by the classification [`Reader`]
/// applies to a table that holds the help row alone.
fn ahead(arg: &[u8]) -> Ahead<'_> {
    if arg.first() != Some(&b'-') || arg.len() == 1 {
        return Ahead::Value;
    }
    if arg == b"-h" || arg == b"--help" {
        return Ahead::Help(None);
    }
    if let Some(equals) = arg.iter().position(|&byte| byte == b'=') {
        let name = &arg[..equals];
        let explicit = &arg[equals + 1..];
        if name == b"-h" || name == b"--help" || (arg[1] == b'-' && b"--help".starts_with(name)) {
            return Ahead::Help(Some(explicit));
        }
    } else if arg[1] == b'-' {
        if b"--help".starts_with(arg) {
            return Ahead::Help(None);
        }
    } else if arg[1] == b'h' {
        return Ahead::Help(Some(&arg[2..]));
    }
    if negative(arg) || arg.contains(&b' ') {
        return Ahead::Value;
    }
    Ahead::Unknown
}

/// The help that `arg`, an argument [`ahead`] reads as help with attached text, asks for, or the
/// refusal of the attached text, as [`Reader`] reads it in a table of the help row alone.
fn help_with(arg: &OsString) -> Parsed<Command> {
    let help = Reader::new(TOOL, USAGE, HELP, Prefixes::Select, &[HELP_ROW]);
    match help.parse(std::slice::from_ref(arg)) {
        Parsed::Help(text) => Parsed::Help(text),
        Parsed::Refused { code, text } => Parsed::Refused { code, text },
        Parsed::Run(_) => unreachable!("a help argument reads as help"),
    }
}

/// Whether `arg` reads as a negative number: `-` and digits, with at most one `.` before a digit.
fn negative(arg: &[u8]) -> bool {
    let arg = arg.strip_suffix(b"\n").unwrap_or(arg);
    let Some(number) = arg.strip_prefix(b"-") else {
        return false;
    };
    let digits = |part: &[u8]| part.iter().all(u8::is_ascii_digit);
    match number.iter().position(|&byte| byte == b'.') {
        None => !number.is_empty() && digits(number),
        Some(point) => {
            digits(&number[..point]) && number.len() > point + 1 && digits(&number[point + 1..])
        }
    }
}

fn refused(usage: &str, tool: &str, message: &str) -> Parsed<Command> {
    Parsed::Refused {
        code: 2,
        text: format!("{usage}\n{tool}: error: {message}\n"),
    }
}
