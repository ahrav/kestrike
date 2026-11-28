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
    /// An option that takes one value. `check` judges the value of each occurrence `parse` reaches, the
    /// empty string and an explicit `--` (as in `--name=--`) included. `required` asks that the option
    /// appear.
    Value {
        required: bool,
        check: Check,
    },
    /// An option that takes one value at each occurrence and keeps every value in command-line order.
    /// `check` judges each value as it does for [`Kind::Value`].
    Repeated {
        check: Check,
    },
}

impl Opt {
    fn name(&self) -> String {
        self.names.join("/")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Values(Vec<(&'static [&'static str], Vec<OsString>)>);

impl Values {
    /// Returns the value the command line gave for the row that lists `name`, `None` when the command
    /// line left the option out; any of a row's names selects it. A required option's value is `Some`.
    /// For a [`Kind::Repeated`] row it is the last value.
    ///
    /// # Panics
    ///
    /// `get` panics when no row of the option table lists `name`.
    #[track_caller]
    pub fn get(&self, name: &str) -> Option<&OsStr> {
        self.all(name).last().map(OsString::as_os_str)
    }

    /// Returns every value the command line gave for the row that lists `name`, in command-line order:
    /// each occurrence for a [`Kind::Repeated`] row, and at most the last for any other row.
    ///
    /// # Panics
    ///
    /// `all` panics when no row of the option table lists `name`.
    #[track_caller]
    pub fn all(&self, name: &str) -> &[OsString] {
        match self.0.iter().find(|(names, _)| names.contains(&name)) {
            Some((_, values)) => values,
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

/// How [`Reader::reads`] reads one argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reads {
    Value,
    Option,
    Unknown,
}

#[derive(Clone, Copy)]
enum Arg<'a> {
    Value,
    Unknown,
    Option(Match<'a>),
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

    /// The refusal of code 2 with `message`, in the form of each refusal of [`Reader::parse`].
    pub fn refuse<T>(&self, message: String) -> Parsed<T> {
        Parsed::Refused {
            code: 2,
            text: format!("{}\n{}: error: {message}\n", self.usage, self.tool),
        }
    }

    /// `parse` classifies every argument before it reads any value, so a classification error takes
    /// precedence over help and value errors. A value-taking option consumes the next argument only when it
    /// lacks an explicit value and the next argument has kind `Arg::Value`. `parse` calls the option's
    /// `check` for every supplied value; a later occurrence replaces an earlier one, except under
    /// [`Kind::Repeated`], which keeps each. `parse` returns
    /// `Parsed::Help` immediately upon accepting help. Missing required options take precedence over
    /// leftover arguments.
    pub fn parse(&self, args: &[OsString]) -> Parsed {
        match self.parse_known(args) {
            Parsed::Run((values, extras)) if extras.is_empty() => Parsed::Run(values),
            Parsed::Run((_, extras)) => self.refuse(unrecognized(&extras)),
            Parsed::Help(text) => Parsed::Help(text),
            Parsed::Refused { code, text } => Parsed::Refused { code, text },
        }
    }

    /// `parse_known` reads `args` as [`Reader::parse`] does and returns the leftover arguments, in
    /// command-line order, beside the values in place of refusing them.
    pub fn parse_known(&self, args: &[OsString]) -> Parsed<(Values, Vec<OsString>)> {
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
        let mut values: Vec<Vec<OsString>> = vec![Vec::new(); self.options.len()];
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
                    return match ignored(found.string, explicit) {
                        None => Parsed::Help(self.help.to_owned()),
                        Some(rest) => self.refuse(format!(
                            "argument {}: ignored explicit argument {}",
                            option.name(),
                            Text::from_os(OsStr::from_bytes(rest)).repr()
                        )),
                    };
                }
                Kind::Value { check, .. } | Kind::Repeated { check } => check,
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
            let value = OsStr::from_bytes(value);
            if let Err(message) = check(&Text::from_os(value)) {
                return self.refuse(format!("argument {}: {message}", option.name()));
            }
            let kept = &mut values[found.option];
            if !matches!(option.kind, Kind::Repeated { .. }) {
                kept.clear();
            }
            kept.push(value.to_owned());
        }
        let missing: Vec<String> = self
            .options
            .iter()
            .zip(&values)
            .filter(|(option, value)| {
                matches!(option.kind, Kind::Value { required: true, .. }) && value.is_empty()
            })
            .map(|(option, _)| option.name())
            .collect();
        if !missing.is_empty() {
            return self.refuse(format!(
                "the following arguments are required: {}",
                missing.join(", ")
            ));
        }
        let names = self.options.iter().map(|option| option.names);
        let extras = extras
            .iter()
            .map(|arg| OsStr::from_bytes(arg).to_owned())
            .collect();
        Parsed::Run((Values(names.zip(values).collect()), extras))
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

    /// How [`Reader::parse`] reads `arg`, which is not `--`, by the table: a value, a row's option or an
    /// unknown option; `Err` holds the refusal's message of an ambiguous prefix.
    pub fn reads(&self, arg: &OsStr) -> Result<Reads, String> {
        Ok(match self.classify(arg.as_bytes())? {
            Arg::Value => Reads::Value,
            Arg::Unknown => Reads::Unknown,
            Arg::Option(_) => Reads::Option,
        })
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

/// `ignored` returns the part of the text attached to the help name `string` that `parse` refuses, `None`
/// when the argument is help. After a long name (as in `--help=x`, `--help=`) and after `-h=` with nothing
/// behind it, that part is the whole text. After `-h`, an attachment of `h`s alone (as in `-hh`) is help,
/// and any other attachment is refused from its first byte that differs from `h`.
fn ignored<'a>(string: &[u8], explicit: &'a [u8]) -> Option<&'a [u8]> {
    let short = string[1] != b'-';
    if !short || explicit.is_empty() {
        return Some(explicit);
    }
    let rest = explicit.iter().position(|&letter| letter != b'h')?;
    Some(&explicit[rest..])
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

/// The message of a refusal of the leftover arguments `extras`: `unrecognized arguments: ` and each
/// argument, joined by a space.
pub fn unrecognized(extras: &[OsString]) -> String {
    let shown: Vec<String> = extras.iter().map(|arg| shown(arg.as_bytes())).collect();
    format!("unrecognized arguments: {}", shown.join(" "))
}

fn shown(arg: &[u8]) -> String {
    Text::from_os(OsStr::from_bytes(arg)).to_string()
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
