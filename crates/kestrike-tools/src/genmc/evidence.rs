//! The GenMC lane checks the recorded Cargo configuration that shapes the kernels' build, and each
//! case's command line and environment. The caller vouches for the evidence directory and the checkout
//! root it names, and these functions read the files under both as the caller's own.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use super::refusal::{
    Error, listed, member, parse_json, read_error, string, strings, tool_failure,
};
use crate::genmc::{is_file, read_text};
use crate::json::{Object, Text, Value};
use crate::paths::resolve;
use crate::python::{equal, repr, str_of};

const OPTION: &str = "--dump-error-graph=";

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
    let empty = Object::new();
    let table = |key: &str| match config.get(key) {
        Some(Value::Object(table)) => table,
        _ => &empty,
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
    resolve(path).map_err(|error| {
        if error.kind() == io::ErrorKind::Other {
            Error::Runtime(error.to_string())
        } else {
            Error::Os(error)
        }
    })
}

fn ran_declared(
    argv: &[String],
    record: &Value,
    options: &Value,
    graph: &Path,
    manifest: &Path,
) -> Result<bool, Error> {
    let [head @ .., graph_option, manifest_argument] = argv else {
        return Ok(false);
    };
    let mut wanted = vec![member(member(record, "binary")?, "path")?.clone()];
    wanted.extend(listed(options, "the declared options")?);
    if !equal(&strings(head), &Value::Array(wanted)) {
        return Ok(false);
    }
    let Some(path) = graph_option.strip_prefix(OPTION) else {
        return Ok(false);
    };
    Ok(resolved(Path::new(path))? == graph && resolved(Path::new(manifest_argument))? == manifest)
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
    let package = Path::new(string(
        member(expected, "package")?,
        "the declared package",
    )?);
    let manifest: PathBuf = root
        .join(package.parent().unwrap_or(package))
        .join(format!("run-{name}"))
        .join("Cargo.toml")
        .components()
        .collect();
    let options = member(expected, "options")?;
    if !ran_declared(argv, record, options, &graph, &manifest)? {
        let mut joined = Vec::new();
        for item in listed(options, "the declared options")? {
            let Value::String(item) = item else {
                return Err(Error::Type("a declared option is no string".to_owned()));
            };
            joined.push(item);
        }
        return Err(tool_failure(format!(
            "{name} ran {}, not genmc {} {OPTION}{} {}",
            repr(&strings(argv)),
            Text::join(" ", &joined),
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
