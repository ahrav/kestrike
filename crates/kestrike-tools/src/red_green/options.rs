//! `red-green` accepts unique prefixes for all eleven long options.
//!
//! `--watchdog` trims the white space Python's `float` trims, the ASCII space, tab, line feed, vertical
//! tab, form feed and carriage return and each non-ASCII `White_Space` code point, before parsing its value
//! as `f64`.

use std::ffi::OsString;
use std::path::Path;

use crate::args::{Kind, Opt, Parsed, Prefixes, Reader, any};
use crate::python;
use crate::shell;
use crate::text::{self, Text, text};

/// The tool's word in the repeat command.
const TOOL: &str = "red-green";

pub const WATCHDOG: f64 = 1500.0;

/// The longest wait in seconds the platform's timed lock takes, `threading.TIMEOUT_MAX` on 64-bit Linux.
pub const TIMEOUT_MAX: f64 = 9_223_372_036.0;

/// The code points that end a line in Python's `str.splitlines()`.
const LINE_BREAKS: [char; 10] = [
    '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}', '\u{2029}',
];

const fn value(names: &'static [&'static str], required: bool) -> Opt {
    Opt {
        names,
        kind: Kind::Value {
            required,
            check: any,
        },
    }
}

const TABLE: [Opt; 12] = [
    Opt {
        names: &["-h", "--help"],
        kind: Kind::Help,
    },
    value(&["--package"], true),
    value(&["--target"], true),
    value(&["--test"], true),
    value(&["--expect"], true),
    Opt {
        names: &["--carry"],
        kind: Kind::Many {
            required: true,
            check: any,
        },
    },
    value(&["--base"], false),
    value(&["--head"], false),
    Opt {
        names: &["--watchdog"],
        kind: Kind::Value {
            required: false,
            check: float,
        },
    },
    value(&["--artifacts"], false),
    value(&["--cargo"], false),
    Opt {
        names: &["--release"],
        kind: Kind::Flag,
    },
];

#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    pub package: Text,
    pub target: Text,
    pub test: Text,
    pub expect: Text,
    pub carry: Vec<Text>,
    pub base: Option<Text>,
    pub head: Text,
    pub watchdog: f64,
    pub artifacts: Option<Text>,
    pub cargo: Text,
    pub release: bool,
}

fn parsed_float(value: &Text) -> Option<f64> {
    let trimmed = |c: char| {
        matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
            || (!c.is_ascii() && text::is_space(u32::from(c)))
    };
    value.to_str()?.trim_matches(trimmed).parse().ok()
}

fn float(value: &Text) -> Result<(), String> {
    match parsed_float(value) {
        Some(_) => Ok(()),
        None => Err(format!("invalid float value: {}", value.repr())),
    }
}

/// `read` returns `help` unchanged for `-h` and `--help`.
pub fn read(args: &[OsString], tool: &str, usage: &str, help: &str) -> Parsed<Options> {
    let reader = Reader::new(tool, usage, help, Prefixes::Select, &TABLE);
    reader.parse(args).map(|values| {
        let given = |name| values.get(name).map(Text::from_os);
        let or = |name, default: &str| given(name).unwrap_or_else(|| Text::from(default));
        let watchdog = given("--watchdog").map_or(WATCHDOG, |value| {
            parsed_float(&value).expect("a checked float parses")
        });
        Options {
            package: or("--package", ""),
            target: or("--target", ""),
            test: or("--test", ""),
            expect: or("--expect", ""),
            carry: values
                .all("--carry")
                .iter()
                .map(|value| Text::from_os(value))
                .collect(),
            base: given("--base"),
            head: or("--head", "HEAD"),
            watchdog,
            artifacts: given("--artifacts"),
            cargo: or("--cargo", "cargo"),
            release: values.flag("--release"),
        }
    })
}

/// `check_given` requires at least one `--carry` path. It rejects `--` for every option value it checks
/// and accepts an empty value only for `--expect`.
pub fn check_given(options: &Options) -> Result<(), &'static str> {
    let values = [
        &options.package,
        &options.target,
        &options.test,
        &options.head,
        &options.cargo,
    ]
    .into_iter()
    .chain(&options.carry)
    .chain(options.base.iter())
    .chain(options.artifacts.iter());
    let mut given = true;
    for value in values {
        given &= !value.is_empty() && *value != "--";
    }
    if options.carry.is_empty() || !given || options.expect == "--" {
        return Err("an option has no value, or --carry names no path");
    }
    Ok(())
}

pub fn check_expect(expect: &Text, test: &Text) -> Result<(), Text> {
    if expect.strip().is_empty() {
        return Err(Text::from("--expect is empty"));
    }
    if super::holds(test.as_bytes(), expect.as_bytes()) {
        return Err(text!("--expect ", expect.repr(), " is part of the test ID"));
    }
    Ok(())
}

/// A NaN fails the bound.
pub fn check_watchdog(watchdog: f64) -> Result<(), String> {
    if 0.0 < watchdog && watchdog <= TIMEOUT_MAX {
        return Ok(());
    }
    Err(format!(
        "--watchdog must be a positive number of seconds up to {}",
        python::repr_float(TIMEOUT_MAX)
    ))
}

/// The runner prints the receipt directory path in a single-line UTF-8 announcement, so the entire path
/// must be single-line UTF-8 text.
pub fn check_receipt_directory(parent: &Path) -> Result<(), Text> {
    let shown = Text::from_os(parent.as_os_str());
    let broken = shown
        .to_str()
        .is_none_or(|valid| valid.contains(LINE_BREAKS));
    if broken {
        return Err(text!(
            "the receipt directory ",
            shown.repr(),
            " cannot appear on the runner's one-line UTF-8 artifact announcement"
        ));
    }
    Ok(())
}

/// `repeat` builds a shell command to rerun the tool from the repository root. It joins each flag and
/// value with `=`, so a value that starts with `-` reads back as that value. The parent of `receipt`
/// stands as `--artifacts` where the run named one.
pub fn repeat(options: &Options, base: &Text, head: &Text, receipt: &Path) -> Text {
    let flag = |name: &str, value: &Text| text!("--", name, "=", value);
    let mut words: Vec<Text> = ["bash", "scripts/tool.sh", TOOL].map(Text::from).to_vec();
    words.push(flag("package", &options.package));
    words.push(flag("target", &options.target));
    words.push(flag("test", &options.test));
    words.push(flag("expect", &options.expect));
    words.extend(options.carry.iter().map(|path| flag("carry", path)));
    words.push(flag("base", base));
    words.push(flag("head", head));
    words.push(flag(
        "watchdog",
        &Text::from(python::repr_float(options.watchdog)),
    ));
    if options.release {
        words.push(Text::from("--release"));
    }
    if options.artifacts.is_some() {
        let parent = receipt.parent().unwrap_or(Path::new("."));
        words.push(flag("artifacts", &Text::from_os(parent.as_os_str())));
    }
    if options.cargo != "cargo" {
        words.push(flag("cargo", &options.cargo));
    }
    shell::join(&words)
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
