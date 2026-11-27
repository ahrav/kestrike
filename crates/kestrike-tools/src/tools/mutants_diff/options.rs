//! The command line: seven long options read by [`Reader`] with whole names alone, and the help. Each
//! option's check decides about every value it is given, `--` included.

use std::ffi::{OsStr, OsString};

use crate::args::{Kind, Opt, Parsed, Prefixes, Reader};
use crate::json::{Integer, MAX_INTEGER_DIGITS};
use crate::shell;
use crate::text::Text;

pub(super) const TOOL: &str = "mutants-diff";
const USAGE: &str = "usage: mutants-diff [-h] [--base REV] [--head REV] [--max-mutants N] [--shard K/N] \
                     [--tests=ARGS] [--artifacts DIR] [--cargo PATH]";
const OPTIONS_HELP: &str = "options:
  -h, --help        show this help and exit
  --base REV        default: the merge base of the head with origin/main
  --head REV        default: HEAD
  --max-mutants N   default: 40
  --shard K/N       passed to the tool unchanged
  --tests=ARGS      test arguments after the tool's first --, split as a shell splits them
  --artifacts DIR   default: target/mutants under the checkout's top level
  --cargo PATH      default: cargo
";
const DEFAULT_LIMIT: &str = "40";

/// A `--shard K/N` value: the text passed to the tool and its two numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Shard {
    pub(super) value: OsString,
    pub(super) k: Integer,
    pub(super) n: Integer,
}

/// The options [`parse`] accepted, `tests` as the shell-split words of `--tests`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub(super) base: Option<OsString>,
    pub(super) head: OsString,
    pub(super) max_mutants: Integer,
    pub(super) shard: Option<Shard>,
    pub(super) tests: Option<Vec<OsString>>,
    pub(super) artifacts: Option<OsString>,
    pub(super) cargo: OsString,
}

const fn value(names: &'static [&'static str], check: fn(&Text) -> Result<(), String>) -> Opt {
    Opt {
        names,
        kind: Kind::Value {
            required: false,
            check,
        },
    }
}

const TABLE: [Opt; 8] = [
    Opt {
        names: &["-h", "--help"],
        kind: Kind::Help,
    },
    value(&["--base"], given),
    value(&["--head"], given),
    value(&["--max-mutants"], positive),
    value(&["--shard"], shard),
    value(&["--tests"], tests),
    value(&["--artifacts"], given),
    value(&["--cargo"], given),
];

fn given(value: &Text) -> Result<(), String> {
    if value.is_empty() {
        return Err("a value".to_owned());
    }
    Ok(())
}

/// `is_ascii_digits` holds for one or more ASCII digits.
fn is_ascii_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// `ascii_digits` returns the text when it is one or more ASCII digits.
fn ascii_digits(value: &Text) -> Option<&str> {
    value.to_str().filter(|digits| is_ascii_digits(digits))
}

/// A limit is ASCII digits worth one or more. Past [`MAX_INTEGER_DIGITS`] digits the value is refused as
/// one the integer conversion takes no further.
fn positive(value: &Text) -> Result<(), String> {
    let Some(digits) = ascii_digits(value) else {
        return Err("a positive integer".to_owned());
    };
    if digits.len() > MAX_INTEGER_DIGITS {
        return Err(format!("invalid positive value: {}", value.repr()));
    }
    if digits.bytes().all(|byte| byte == b'0') {
        return Err("a positive integer".to_owned());
    }
    Ok(())
}

/// `shard_numbers` splits `K/N`, each one or more ASCII digits, into its two numbers.
fn shard_numbers(value: &Text) -> Option<(&str, &str)> {
    let (k, n) = value.to_str()?.split_once('/')?;
    (is_ascii_digits(k) && is_ascii_digits(n)).then_some((k, n))
}

fn integer(digits: &str) -> Integer {
    Integer::from_digits(false, digits).expect("a checked number is ASCII digits")
}

fn shard(value: &Text) -> Result<(), String> {
    let refused = || "K/N with 0 <= K < N".to_owned();
    let (k, n) = shard_numbers(value).ok_or_else(refused)?;
    if k.len() > MAX_INTEGER_DIGITS || n.len() > MAX_INTEGER_DIGITS {
        return Err(format!("invalid shard_value value: {}", value.repr()));
    }
    if integer(k) < integer(n) {
        Ok(())
    } else {
        Err(refused())
    }
}

fn words(value: &Text) -> Result<Vec<Text>, String> {
    let words = shell::split(value).map_err(|error| {
        match error {
            shell::Error::UnclosedQuotation => "a quotation without its closing quote",
            shell::Error::TrailingBackslash => "a backslash with no character after it",
        }
        .to_owned()
    })?;
    if words.is_empty() {
        return Err("one or more test arguments".to_owned());
    }
    Ok(words)
}

fn tests(value: &Text) -> Result<(), String> {
    words(value).map(drop)
}

/// `parse` reads `args` as [`Reader`] does with the option table above and whole names alone.
pub fn parse(args: &[OsString]) -> Parsed<Options> {
    let help = format!("{USAGE}\n\n{}\n{OPTIONS_HELP}", include_str!("help.md"));
    let reader = Reader::new(TOOL, USAGE, &help, Prefixes::Refuse, &TABLE);
    reader.parse(args).map(|values| {
        let given = |name| values.get(name).map(OsStr::to_os_string);
        let or_default =
            |name, default: &str| given(name).unwrap_or_else(|| OsString::from(default));
        let limit = or_default("--max-mutants", DEFAULT_LIMIT);
        let limit = limit.to_str().expect("a checked limit is ASCII digits");
        let shard = given("--shard").map(|text| {
            let shown = Text::from_os(&text);
            let (k, n) = shard_numbers(&shown).expect("a checked shard is K/N");
            let (k, n) = (integer(k), integer(n));
            Shard { value: text, k, n }
        });
        let tests = given("--tests").map(|value| {
            let words = words(&Text::from_os(&value)).expect("checked test arguments split");
            let encoded = words
                .iter()
                .map(|word| word.to_os().expect("a word of an argument encodes back"));
            encoded.collect()
        });
        Options {
            base: given("--base"),
            head: or_default("--head", "HEAD"),
            max_mutants: integer(limit),
            shard,
            tests,
            artifacts: given("--artifacts"),
            cargo: or_default("--cargo", "cargo"),
        }
    })
}
