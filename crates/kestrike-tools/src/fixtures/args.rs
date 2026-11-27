//! The fixture writer's command line follows Python 3.9's `argparse` conventions. It takes the required
//! options `--quint` and `--output` and the help option `-h`/`--help`.
//!
//! `--quint` and `--output` accept a value in the next argument or after `=`. A unique long-option prefix
//! selects the matching option, and a repeated option keeps its last value. For [`Parsed::Refused`] with code
//! 2, the text is the usage line and `<tool>: error: <message>`.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

/// `None` stands for the empty value list that `--quint=--` or `--output=--` gives.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub quint: Option<OsString>,
    pub output: Option<OsString>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Run(Options),
    /// The caller writes the help to standard output and exits 0.
    Help(String),
    /// The caller writes `text` to standard error and exits with `code`.
    Refused {
        code: u8,
        text: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Help,
    Quint,
    Output,
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Help => "-h/--help",
            Self::Quint => "--quint",
            Self::Output => "--output",
        }
    }
}

const OPTIONS: [(&[u8], Action); 4] = [
    (b"-h", Action::Help),
    (b"--help", Action::Help),
    (b"--quint", Action::Quint),
    (b"--output", Action::Output),
];

/// `explicit` holds the text after `=` or after a short option's letter.
#[derive(Clone, Copy)]
struct Match<'a> {
    action: Action,
    string: &'a [u8],
    explicit: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
enum Kind<'a> {
    Value,
    Marker,
    Unknown,
    Option(Match<'a>),
}

pub fn parse(tool: &str, about: &str, args: &[OsString]) -> Parsed {
    let usage = format!("usage: {tool} [-h] --quint QUINT --output OUTPUT");
    let refuse = |message: String| Parsed::Refused {
        code: 2,
        text: format!("{usage}\n{tool}: error: {message}\n"),
    };
    let args: Vec<&[u8]> = args.iter().map(|arg| arg.as_bytes()).collect();
    let mut kinds = Vec::with_capacity(args.len());
    let mut ended = false;
    for arg in &args {
        kinds.push(if ended {
            Kind::Value
        } else if *arg == b"--" {
            ended = true;
            Kind::Marker
        } else {
            match classify(arg) {
                Ok(kind) => kind,
                Err(message) => return refuse(message),
            }
        });
    }
    let mut options = Options {
        quint: None,
        output: None,
    };
    let mut seen = Vec::new();
    let mut extras = Vec::new();
    let mut at = 0;
    while at < args.len() {
        let Kind::Option(found) = kinds[at] else {
            extras.push(args[at]);
            at += 1;
            continue;
        };
        let value = match (found.action, found.explicit) {
            (Action::Help, Some(explicit)) => match help_explicit(found.string, explicit) {
                Ok(()) => None,
                Err(HelpRefusal::Ignored(rest)) => {
                    return refuse(format!(
                        "argument -h/--help: ignored explicit argument {}",
                        repr(rest)
                    ));
                }
                Err(HelpRefusal::IndexError) => {
                    let text = format!("{tool}: argument -h/--help: string index out of range\n");
                    return Parsed::Refused { code: 1, text };
                }
            },
            (Action::Help, None) => None,
            (_, Some(explicit)) => Some(explicit),
            (action, None) => match kinds.get(at + 1) {
                Some(Kind::Value) => {
                    at += 1;
                    Some(args[at])
                }
                _ => return refuse(format!("argument {}: expected one argument", action.name())),
            },
        };
        at += 1;
        let value = value
            .filter(|value| *value != b"--")
            .map(|value| OsStr::from_bytes(value).to_owned());
        match found.action {
            Action::Help => {
                return Parsed::Help(format!(
                    "{usage}\n\n{about}\n\noptional arguments:\n  -h, --help       show this help message and exit\n  \
                     --quint QUINT\n  --output OUTPUT\n"
                ));
            }
            Action::Quint => options.quint = value,
            Action::Output => options.output = value,
        }
        seen.push(found.action);
    }
    let missing: Vec<&str> = [Action::Quint, Action::Output]
        .into_iter()
        .filter(|action| !seen.contains(action))
        .map(Action::name)
        .collect();
    if !missing.is_empty() {
        return refuse(format!(
            "the following arguments are required: {}",
            missing.join(", ")
        ));
    }
    if !extras.is_empty() {
        let shown: Vec<String> = extras.iter().map(|arg| shown(arg)).collect();
        return refuse(format!("unrecognized arguments: {}", shown.join(" ")));
    }
    Parsed::Run(options)
}

enum HelpRefusal<'a> {
    Ignored(&'a [u8]),
    IndexError,
}

/// Each letter after `-h` reads as one more `-h`, and the rest from the first letter other than `h` is an
/// ignored explicit argument. For `-h=`, `parse` returns `Parsed::Refused` with code 1 and the message
/// `string index out of range`. The long form `--help=` refuses any explicit value.
fn help_explicit<'a>(string: &[u8], explicit: &'a [u8]) -> Result<(), HelpRefusal<'a>> {
    let short = string[1] != b'-';
    if !short {
        return Err(HelpRefusal::Ignored(explicit));
    }
    if explicit.is_empty() {
        return Err(HelpRefusal::IndexError);
    }
    match explicit.iter().position(|&letter| letter != b'h') {
        Some(rest) => Err(HelpRefusal::Ignored(&explicit[rest..])),
        None => Ok(()),
    }
}

fn action_of(string: &[u8]) -> Option<Action> {
    OPTIONS
        .iter()
        .find(|(name, _)| *name == string)
        .map(|&(_, action)| action)
}

fn classify(arg: &[u8]) -> Result<Kind<'_>, String> {
    if arg.first() != Some(&b'-') {
        return Ok(Kind::Value);
    }
    if let Some(action) = action_of(arg) {
        return Ok(Kind::Option(Match {
            action,
            string: arg,
            explicit: None,
        }));
    }
    if arg.len() == 1 {
        return Ok(Kind::Value);
    }
    if let Some(equals) = arg.iter().position(|&byte| byte == b'=') {
        let (string, explicit) = (&arg[..equals], &arg[equals + 1..]);
        if let Some(action) = action_of(string) {
            return Ok(Kind::Option(Match {
                action,
                string,
                explicit: Some(explicit),
            }));
        }
    }
    match prefix_matches(arg).as_slice() {
        [] => {}
        [found] => return Ok(Kind::Option(*found)),
        matches => {
            let names: Vec<String> = matches.iter().map(|found| shown(found.string)).collect();
            return Err(format!(
                "ambiguous option: {} could match {}",
                shown(arg),
                names.join(", ")
            ));
        }
    }
    if looks_negative(arg) || arg.contains(&b' ') {
        return Ok(Kind::Value);
    }
    Ok(Kind::Unknown)
}

/// For `--` arguments, `prefix_matches` uses the bytes before the first `=` (or the entire argument) as the
/// option prefix and any suffix after `=` as the explicit value. For an argument with exactly one leading `-`
/// and at least two bytes, an option equal to the first two bytes takes the rest as its explicit value.
fn prefix_matches(arg: &[u8]) -> Vec<Match<'_>> {
    let mut matches = Vec::new();
    if arg[1] == b'-' {
        let (prefix, explicit) = match arg.iter().position(|&byte| byte == b'=') {
            Some(equals) => (&arg[..equals], Some(&arg[equals + 1..])),
            None => (arg, None),
        };
        for &(string, action) in &OPTIONS {
            if string.starts_with(prefix) {
                matches.push(Match {
                    action,
                    string,
                    explicit,
                });
            }
        }
    } else {
        for &(string, action) in &OPTIONS {
            if string == &arg[..2] {
                matches.push(Match {
                    action,
                    string,
                    explicit: Some(&arg[2..]),
                });
            }
        }
    }
    matches
}

/// `looks_negative` matches the `argparse` pattern `^-\d+$|^-\d*\.\d+$` with ASCII digits; `$` also matches
/// before a final newline.
fn looks_negative(arg: &[u8]) -> bool {
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

enum Piece {
    Character(char),
    Byte(u8),
}

fn pieces(arg: &[u8]) -> Vec<Piece> {
    let mut pieces = Vec::new();
    for chunk in arg.utf8_chunks() {
        pieces.extend(chunk.valid().chars().map(Piece::Character));
        pieces.extend(chunk.invalid().iter().copied().map(Piece::Byte));
    }
    pieces
}

/// `shown` writes a byte outside a UTF-8 sequence as `\udc` and two hexadecimal digits.
fn shown(arg: &[u8]) -> String {
    let mut out = String::new();
    for piece in pieces(arg) {
        match piece {
            Piece::Character(character) => out.push(character),
            Piece::Byte(byte) => out.push_str(&format!("\\udc{byte:02x}")),
        }
    }
    out
}

fn repr(arg: &[u8]) -> String {
    let pieces = pieces(arg);
    let holds = |wanted: char| {
        pieces
            .iter()
            .any(|piece| matches!(piece, Piece::Character(found) if *found == wanted))
    };
    let quote = if holds('\'') && !holds('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for piece in pieces {
        match piece {
            Piece::Byte(byte) => out.push_str(&format!("\\udc{byte:02x}")),
            Piece::Character('\\') => out.push_str("\\\\"),
            Piece::Character('\t') => out.push_str("\\t"),
            Piece::Character('\n') => out.push_str("\\n"),
            Piece::Character('\r') => out.push_str("\\r"),
            Piece::Character(character) if character == quote => {
                out.push('\\');
                out.push(quote);
            }
            Piece::Character(character @ ('\u{0}'..='\u{1f}' | '\u{7f}'..='\u{a0}' | '\u{ad}')) => {
                out.push_str(&format!("\\x{:02x}", u32::from(character)));
            }
            Piece::Character(character) => out.push(character),
        }
    }
    out.push(quote);
    out
}
