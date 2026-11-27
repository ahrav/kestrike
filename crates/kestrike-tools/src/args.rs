//! [`Reader::parse`] parses command-line arguments against an [`Opt`] table. Missing required options take
//! precedence over leftover arguments.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::text::Text;

/// A check judges one value an option takes; its `Err` text follows `argument <names>: ` in the refusal.
pub type Check = fn(&Text) -> Result<(), String>;

pub fn any(_: &Text) -> Result<(), String> {
    Ok(())
}

/// One row of an option table: the names that select it, long names of the form `--name` and, on the help
/// row alone, `-h`, and what it takes. [`Values::get`] looks a row up by any of its names.
#[derive(Clone, Copy, Debug)]
pub struct Opt {
    pub names: &'static [&'static str],
    pub kind: Kind,
}

/// `parse` returns [`Parsed::Help`] when it accepts a `Kind::Help` option.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Help,
    /// An option that takes one value. `required` asks only that the option appear: an explicit `--`
    /// satisfies it without a call of `check`, and every other value, the empty string included, is checked
    /// at each occurrence `parse` reaches.
    Value {
        required: bool,
        check: Check,
    },
}

impl Opt {
    fn name(&self) -> String {
        self.names.join("/")
    }
}

/// `parse` records the value `--` as `Given::Empty`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Given {
    Absent,
    Empty,
    Value(OsString),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Values(Vec<(&'static [&'static str], Given)>);

impl Values {
    /// Returns what the command line gave for the row that lists `name`; any of a row's names selects it.
    ///
    /// # Panics
    ///
    /// `get` panics when no row of the option table lists `name`.
    #[track_caller]
    pub fn get(&self, name: &str) -> &Given {
        match self.0.iter().find(|(names, _)| names.contains(&name)) {
            Some((_, given)) => given,
            None => panic!("the option table names {name}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed<T = Values> {
    Run(T),
    /// The caller writes the help to standard output and exits 0.
    Help(String),
    /// The caller writes `text` to standard error and exits with `code`.
    Refused {
        code: u8,
        text: String,
    },
}

impl<T> Parsed<T> {
    pub fn map<U>(self, run: impl FnOnce(T) -> U) -> Parsed<U> {
        match self {
            Self::Run(values) => Parsed::Run(run(values)),
            Self::Help(text) => Parsed::Help(text),
            Self::Refused { code, text } => Parsed::Refused { code, text },
        }
    }
}

/// Whether a unique prefix of a long name selects its row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefixes {
    /// A unique prefix of a long name, as `--out` for `--output`, selects its row.
    Select,
    /// Only a whole name selects a row.
    Refuse,
}

pub struct Reader<'a> {
    tool: &'a str,
    usage: &'a str,
    help: &'a str,
    prefixes: Prefixes,
    options: &'a [Opt],
}

#[derive(Clone, Copy)]
struct Match<'a> {
    option: usize,
    string: &'a [u8],
    explicit: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
enum Arg<'a> {
    Value,
    Unknown,
    Option(Match<'a>),
}

enum HelpRefusal<'a> {
    Ignored(&'a [u8]),
    IndexError,
}

impl<'t> Reader<'t> {
    /// `tool` and `usage` open each refusal of code 2, which writes `usage`, a newline, then
    /// `<tool>: error: <message>`; `help` is returned unchanged in [`Parsed::Help`]. With
    /// [`Prefixes::Select`], a unique prefix of a long name selects its row; an exact long name and the `-h`
    /// cluster rules apply whatever `prefixes` says.
    ///
    /// # Panics
    ///
    /// `new` panics on any violation of these requirements: each row lists at least one name; each option
    /// name starts with `-`, spans at least two bytes, differs from `--`, and occurs exactly once in the
    /// table; the table holds exactly one `Kind::Help` row; `-h`, permitted on the help row alone, is the
    /// only short name.
    pub fn new(
        tool: &'t str,
        usage: &'t str,
        help: &'t str,
        prefixes: Prefixes,
        options: &'t [Opt],
    ) -> Self {
        let names: Vec<&str> = options
            .iter()
            .flat_map(|option| option.names.iter().copied())
            .collect();
        assert!(
            options.iter().all(|option| !option.names.is_empty()),
            "each option has a name"
        );
        for (at, name) in names.iter().enumerate() {
            assert!(
                name.starts_with('-') && name.len() >= 2 && *name != "--",
                "the option name {name} starts with a dash and differs from --"
            );
            assert!(
                !names[..at].contains(name),
                "the option name {name} appears once"
            );
        }
        let helps: Vec<&Opt> = options
            .iter()
            .filter(|option| matches!(option.kind, Kind::Help))
            .collect();
        assert!(helps.len() == 1, "the table holds one help row");
        for option in options {
            for name in option.names {
                let short = !name.starts_with("--");
                assert!(
                    !short || (*name == "-h" && matches!(option.kind, Kind::Help)),
                    "the help row holds the one short name, -h; {name} breaks it"
                );
            }
        }
        Self {
            tool,
            usage,
            help,
            prefixes,
            options,
        }
    }

    fn refuse(&self, message: String) -> Parsed {
        Parsed::Refused {
            code: 2,
            text: format!("{}\n{}: error: {message}\n", self.usage, self.tool),
        }
    }

    /// `parse` classifies every argument before it reads any value, so a classification error takes
    /// precedence over help and value errors. A value-taking option consumes the next argument only when it
    /// lacks an explicit value and the next argument has kind `Arg::Value`. `parse` records `b"--"` as
    /// `Given::Empty` and calls the option's `check` for every other supplied value; a later occurrence replaces
    /// an earlier one. `parse` returns `Parsed::Help` immediately upon accepting help. Missing required
    /// options take precedence over leftover arguments.
    pub fn parse(&self, args: &[OsString]) -> Parsed {
        let args: Vec<&[u8]> = args.iter().map(|arg| arg.as_bytes()).collect();
        let mut kinds = Vec::with_capacity(args.len());
        let mut ended = false;
        for arg in &args {
            kinds.push(if ended {
                Arg::Value
            } else if *arg == b"--" {
                ended = true;
                Arg::Unknown
            } else {
                match self.classify(arg) {
                    Ok(kind) => kind,
                    Err(message) => return self.refuse(message),
                }
            });
        }
        let mut values: Vec<Given> = vec![Given::Absent; self.options.len()];
        let mut extras = Vec::new();
        let mut at = 0;
        while at < args.len() {
            let Arg::Option(found) = kinds[at] else {
                extras.push(args[at]);
                at += 1;
                continue;
            };
            let option = &self.options[found.option];
            let check = match option.kind {
                Kind::Help => {
                    let Some(explicit) = found.explicit else {
                        return Parsed::Help(self.help.to_owned());
                    };
                    return match help_explicit(found.string, explicit) {
                        Ok(()) => Parsed::Help(self.help.to_owned()),
                        Err(HelpRefusal::Ignored(rest)) => self.refuse(format!(
                            "argument {}: ignored explicit argument {}",
                            option.name(),
                            Text::from_os(OsStr::from_bytes(rest)).repr()
                        )),
                        Err(HelpRefusal::IndexError) => Parsed::Refused {
                            code: 1,
                            text: format!(
                                "{}: argument {}: string index out of range\n",
                                self.tool,
                                option.name()
                            ),
                        },
                    };
                }
                Kind::Value { check, .. } => check,
            };
            let value = match (found.explicit, kinds.get(at + 1)) {
                (Some(explicit), _) => explicit,
                (None, Some(Arg::Value)) => {
                    at += 1;
                    args[at]
                }
                (None, _) => {
                    return self
                        .refuse(format!("argument {}: expected one argument", option.name()));
                }
            };
            at += 1;
            values[found.option] = if value == b"--" {
                Given::Empty
            } else {
                let value = OsStr::from_bytes(value);
                if let Err(message) = check(&Text::from_os(value)) {
                    return self.refuse(format!("argument {}: {message}", option.name()));
                }
                Given::Value(value.to_owned())
            };
        }
        let missing: Vec<String> = self
            .options
            .iter()
            .zip(&values)
            .filter(|(option, given)| {
                matches!(option.kind, Kind::Value { required: true, .. })
                    && **given == Given::Absent
            })
            .map(|(option, _)| option.name())
            .collect();
        if !missing.is_empty() {
            return self.refuse(format!(
                "the following arguments are required: {}",
                missing.join(", ")
            ));
        }
        if !extras.is_empty() {
            let shown: Vec<String> = extras.iter().map(|arg| shown(arg)).collect();
            return self.refuse(format!("unrecognized arguments: {}", shown.join(" ")));
        }
        let names = self.options.iter().map(|option| option.names);
        Parsed::Run(Values(names.zip(values).collect()))
    }

    fn strings(&self) -> impl Iterator<Item = (usize, &'static [u8])> + '_ {
        self.options
            .iter()
            .enumerate()
            .flat_map(|(option, row)| row.names.iter().map(move |name| (option, name.as_bytes())))
    }

    fn exact(&self, string: &[u8]) -> Option<usize> {
        self.strings()
            .find(|&(_, name)| name == string)
            .map(|(option, _)| option)
    }

    fn classify<'a>(&self, arg: &'a [u8]) -> Result<Arg<'a>, String> {
        if arg.first() != Some(&b'-') {
            return Ok(Arg::Value);
        }
        if let Some(option) = self.exact(arg) {
            return Ok(Arg::Option(Match {
                option,
                string: arg,
                explicit: None,
            }));
        }
        if arg.len() == 1 {
            return Ok(Arg::Value);
        }
        if let Some(equals) = arg.iter().position(|&byte| byte == b'=') {
            let (string, explicit) = (&arg[..equals], &arg[equals + 1..]);
            if let Some(option) = self.exact(string) {
                return Ok(Arg::Option(Match {
                    option,
                    string,
                    explicit: Some(explicit),
                }));
            }
        }
        match self.prefix_matches(arg).as_slice() {
            [] => {}
            [found] => return Ok(Arg::Option(*found)),
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
            return Ok(Arg::Value);
        }
        Ok(Arg::Unknown)
    }

    fn prefix_matches<'a>(&self, arg: &'a [u8]) -> Vec<Match<'a>> {
        let mut matches = Vec::new();
        if arg[1] == b'-' {
            let (prefix, explicit) = match arg.iter().position(|&byte| byte == b'=') {
                Some(equals) => (&arg[..equals], Some(&arg[equals + 1..])),
                None => (arg, None),
            };
            for (option, string) in self.strings() {
                if self.prefixes == Prefixes::Select && string.starts_with(prefix) {
                    matches.push(Match {
                        option,
                        string,
                        explicit,
                    });
                }
            }
        } else {
            for (option, string) in self.strings() {
                if string == &arg[..2] {
                    matches.push(Match {
                        option,
                        string,
                        explicit: Some(&arg[2..]),
                    });
                }
            }
        }
        matches
    }
}

/// `help_explicit` judges the text attached to a help name: any text after `--help=` is ignored and
/// refused, an empty attachment to `-h` (as in `-h=`) is the code-1 refusal, and an attachment of `h`s alone
/// (as in `-hh`) is help.
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

/// `looks_negative` matches the `argparse` pattern `^-\d+$|^-\d*\.\d+$` with ASCII digits; `$` also
/// matches before a final newline.
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

fn shown(arg: &[u8]) -> String {
    Text::from_os(OsStr::from_bytes(arg)).to_string()
}
