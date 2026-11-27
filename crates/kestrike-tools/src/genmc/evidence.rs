//! The GenMC lane checks the recorded Cargo configuration that shapes the kernels' build, and each
//! case's command line and environment. The caller vouches for the evidence directory and the checkout
//! root it names, and these functions read the files under both as the caller's own.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use super::refusal::{Code, Error, Refusal, member, parse_json, read_error, string};
use crate::genmc::{is_file, read_text};
use crate::json::{Object, Value};
use crate::paths::resolve;
use crate::python::{equal, members, repr, str_of};

const SHAPING_TABLES: [&str; 5] = ["profile", "target", "unstable", "patch", "source"];

const SHAPING_BUILD_KEYS: [&str; 8] = [
    "rustc",
    "rustc-wrapper",
    "rustc-workspace-wrapper",
    "target",
    "target-dir",
    "build-dir",
    "rustflags",
    "rustdocflags",
];

const SHAPING_ENV_PREFIXES: [&str; 3] = ["CASE", "RUST", "CARGO"];

static ADMITTED_TARGET: LazyLock<Value> = LazyLock::new(|| {
    crate::json::parse(
        r#"{"cfg(target_arch = \"aarch64\")": {"rustflags": ["-C", "target-feature=+lse"], "rustdocflags": ["-C", "target-feature=+lse"]}}"#,
    )
    .expect("the admitted target table is JSON")
});

fn tool_failure(reason: String) -> Error {
    Error::Refusal(Refusal::new(Code::ToolFailure, reason))
}

/// `check_config` rejects build-shaping entries in `evidence/cargo-config.json` except for the
/// permitted `target` table.
///
/// # Errors
///
/// `check_config` returns a tool failure if `cargo-config.json` is missing, unreadable, or contains a
/// prohibited build-shaping entry.
pub fn check_config(evidence: &Path) -> Result<(), Error> {
    let path = evidence.join("cargo-config.json");
    if !is_file(&path).map_err(Error::Os)? {
        return Err(tool_failure(
            "the lane left no recorded cargo configuration".to_owned(),
        ));
    }
    let text = read_text(&path).map_err(|error| match read_error(error) {
        Error::Value(error) => tool_failure(format!(
            "the recorded cargo configuration is unreadable: {error}"
        )),
        error => error,
    })?;
    let config = match parse_json(&text) {
        Ok(config) => config,
        Err(Error::Runtime(error)) => {
            return Err(tool_failure(format!("malformed evidence: {error}")));
        }
        Err(error) => {
            return Err(tool_failure(format!(
                "the recorded cargo configuration is unreadable: {error}"
            )));
        }
    };
    let Value::Object(config) = &config else {
        return Err(tool_failure(
            "the recorded cargo configuration is not a table".to_owned(),
        ));
    };
    for key in ["build", "env"] {
        if config
            .get(key)
            .is_some_and(|value| !matches!(value, Value::Object(_)))
        {
            return Err(tool_failure(format!(
                "malformed evidence: the recorded cargo configuration's {key} is not a table"
            )));
        }
    }
    let mut entries: Vec<String> = SHAPING_TABLES
        .iter()
        .filter(|&&table| {
            config
                .get(table)
                .is_some_and(|value| !(table == "target" && equal(value, &ADMITTED_TARGET)))
        })
        .map(|&table| table.to_owned())
        .collect();
    let table = |key: &str| match config.get(key) {
        Some(Value::Object(table)) => table.clone(),
        _ => Object::new(),
    };
    let build = table("build");
    entries.extend(
        SHAPING_BUILD_KEYS
            .iter()
            .filter(|key| build.get(key).is_some())
            .map(|key| format!("build.{key}")),
    );
    let env = table("env");
    let mut names: Vec<_> = env.iter().map(|(name, _)| name.clone()).collect();
    names.sort();
    entries.extend(
        names
            .iter()
            .filter(|name| {
                let name = name.to_string();
                SHAPING_ENV_PREFIXES
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
            })
            .map(|name| format!("env.{name}")),
    );
    if entries.is_empty() {
        Ok(())
    } else {
        Err(tool_failure(format!(
            "the cargo configuration sets {}",
            entries.join(", ")
        )))
    }
}

fn resolved(path: &Path) -> Result<PathBuf, Error> {
    resolve(path).map_err(Error::Os)
}

fn listed(value: &Value, what: &str) -> Result<Vec<Value>, Error> {
    members(value).ok_or_else(|| Error::Type(format!("{what} is not iterable")))
}

/// `check_command` checks the recorded command and environment of case `name`. The command is the
/// record's binary path, the declared options, `--dump-error-graph=` with the case's graph file in
/// `evidence`, and the manifest `<root>/<package's parent>/run-<name>/Cargo.toml`; the environment
/// holds exactly the case's five pinned entries.
///
/// # Errors
///
/// `check_command` returns a tool failure for a command or environment mismatch.
pub fn check_command(
    root: &Path,
    name: &str,
    expected: &Value,
    record: &Value,
    argv: &[String],
    env: &Object,
    evidence: &Path,
) -> Result<(), Error> {
    let graph = resolved(&evidence.join(format!("genmc-{name}.dot")))?;
    let package = string(member(expected, "package")?, "the declared package")?;
    let parent = Path::new(package).parent().unwrap_or(Path::new(""));
    let manifest = root
        .join(parent)
        .join(format!("run-{name}"))
        .join("Cargo.toml");
    let option = "--dump-error-graph=";
    let options = member(expected, "options")?;
    let matches = argv.len() >= 2 && {
        let mut wanted = vec![member(member(record, "binary")?, "path")?.clone()];
        wanted.extend(listed(options, "the declared options")?);
        let head: Vec<Value> = argv[..argv.len() - 2]
            .iter()
            .map(|argument| Value::String(argument.as_str().into()))
            .collect();
        equal(&Value::Array(head), &Value::Array(wanted))
            && match argv[argv.len() - 2].strip_prefix(option) {
                Some(path) => {
                    resolved(Path::new(path))? == graph
                        && resolved(Path::new(&argv[argv.len() - 1]))? == manifest
                }
                None => false,
            }
    };
    if !matches {
        let mut joined = Vec::new();
        for item in listed(options, "the declared options")? {
            joined.push(string(&item, "a declared option")?.to_owned());
        }
        let argv = Value::Array(
            argv.iter()
                .map(|argument| Value::String(argument.as_str().into()))
                .collect(),
        );
        return Err(tool_failure(format!(
            "{name} ran {}, not genmc {} {option}{} {}",
            repr(&argv),
            joined.join(" "),
            graph.display(),
            manifest.display()
        )));
    }
    let rustc = member(record, "rustc")?;
    let mut pinned = Object::new();
    pinned.insert("CASE", Value::String(name.into()));
    pinned.insert("RUSTUP_TOOLCHAIN", member(rustc, "name")?.clone());
    pinned.insert(
        "RUSTC",
        Value::String(format!("{}/bin/rustc", str_of(member(rustc, "toolchain")?)).into()),
    );
    pinned.insert("RUSTC_WRAPPER", Value::String("".into()));
    pinned.insert("RUSTC_WORKSPACE_WRAPPER", Value::String("".into()));
    let env = Value::Object(env.clone());
    let pinned = Value::Object(pinned);
    if !equal(&env, &pinned) {
        return Err(tool_failure(format!(
            "{name} ran with {}, not {}",
            repr(&env),
            repr(&pinned)
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
