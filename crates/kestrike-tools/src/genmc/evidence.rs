//! The GenMC lane checks the recorded Cargo configuration that shapes the kernels' build, and each
//! case's command line and environment. The caller vouches for the evidence directory and the checkout
//! root it names, and these functions read the files under both as the caller's own.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use super::refusal::{
    Error, listed, member, openable, parse_json, read_strict, string, strings, tool_failure,
};
use crate::genmc::is_file;
use crate::json::{Object, Text, Value};
use crate::paths::{joined, parent, resolve};
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

/// The one `target` table a recorded configuration may hold: the aarch64 table of the repository's
/// `.cargo/config.toml`, which enables LSE atomics. It changes with that file.
static ADMITTED_TARGET: LazyLock<Value> = LazyLock::new(|| {
    crate::json::parse(
        r#"{"cfg(target_arch = \"aarch64\")": {"rustflags": ["-C", "target-feature=+lse"], "rustdocflags": ["-C", "target-feature=+lse"]}}"#,
    )
    .expect("the admitted target table is JSON")
});

/// `check_config` rejects build-shaping entries in `evidence/cargo-config.json`: a shaping table, a
/// shaping `build` key and an `[env]` name with a shaping prefix. A `target` table equal to
/// the repository's aarch64 LSE table is the one admitted table.
///
/// # Errors
///
/// `check_config` returns a tool failure for a configuration that is no regular file, bytes that are
/// no UTF-8, text the JSON reader refuses (nesting past [`crate::json::MAX_DEPTH`] included), a value
/// that is no object, a `build` or `env` that is no object, and a shaping entry. A failed lookup or
/// read of the file is [`Error::Os`].
pub fn check_config(evidence: &Path) -> Result<(), Error> {
    let path = evidence.join("cargo-config.json");
    if !is_file(&path).map_err(Error::Os)? {
        return Err(tool_failure(
            "the lane left no recorded cargo configuration".to_owned(),
        ));
    }
    let config = match read_strict(&path).and_then(|text| parse_json(&text)) {
        Ok(config) => config,
        Err(Error::Runtime(error)) => {
            return Err(tool_failure(format!("malformed evidence: {error}")));
        }
        Err(Error::Value(error)) => {
            return Err(tool_failure(format!(
                "the recorded cargo configuration is unreadable: {error}"
            )));
        }
        Err(error) => return Err(error),
    };
    let Value::Object(config) = &config else {
        return Err(tool_failure(
            "the recorded cargo configuration is not a table".to_owned(),
        ));
    };
    let empty = Object::new();
    let table = |key: &str| match config.get(key) {
        None => Ok(&empty),
        Some(Value::Object(table)) => Ok(table),
        Some(_) => Err(tool_failure(format!(
            "malformed evidence: the recorded cargo configuration's {key} is not a table"
        ))),
    };
    let build = table("build")?;
    let env = table("env")?;
    let mut entries: Vec<String> = SHAPING_TABLES
        .iter()
        .filter(|&&table| {
            config
                .get(table)
                .is_some_and(|value| !(table == "target" && equal(value, &ADMITTED_TARGET)))
        })
        .map(|&table| table.to_owned())
        .collect();
    entries.extend(
        SHAPING_BUILD_KEYS
            .iter()
            .filter(|key| build.get(key).is_some())
            .map(|key| format!("build.{key}")),
    );
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
    resolve(openable(path)?).map_err(|error| {
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
    wanted.extend(listed(options, "the declared options")?.iter().cloned());
    if !equal(&strings(head), &Value::Array(wanted)) {
        return Ok(false);
    }
    let Some(path) = graph_option.strip_prefix(OPTION) else {
        return Ok(false);
    };
    Ok(resolved(Path::new(path))? == graph
        && resolved(Path::new(manifest_argument))?.as_os_str() == manifest.as_os_str())
}

/// `check_command` checks the recorded command and environment of case `name`. The command is the
/// record's binary path, the declared options, `--dump-error-graph=` with the case's graph file in
/// `evidence`, and the manifest `<root>/<package's parent>/run-<name>/Cargo.toml`; the environment
/// holds exactly the case's five pinned entries.
///
/// The checkout root is resolved before the manifest's path is built from it, and the graph and manifest
/// arguments are resolved before they are compared.
///
/// # Errors
///
/// `check_command` returns a tool failure for a command or environment mismatch, [`Error::Key`] for a
/// member the declaration or the identity record lacks, [`Error::Type`] for a member of another JSON
/// type, [`Error::Value`] for a recorded path that holds a NUL byte, [`Error::Runtime`] for a path
/// whose lookup meets a link loop or links nested past [`crate::paths::DEPTH`], and [`Error::Os`] for
/// another failed lookup.
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
    let tail = joined(
        &joined(&parent(package), &format!("run-{name}")),
        "Cargo.toml",
    );
    let manifest = if tail.starts_with('/') {
        PathBuf::from(tail)
    } else {
        let mut manifest = resolved(root)?.into_os_string();
        if !manifest.as_bytes().ends_with(b"/") {
            manifest.push("/");
        }
        manifest.push(tail);
        PathBuf::from(manifest)
    };
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
            Text::join(" ", joined),
            graph.display(),
            manifest.display()
        )));
    }
    let rustc = member(record, "rustc")?;
    let mut pinned = Object::new();
    pinned.insert("CASE", Value::String(name.into()));
    pinned.insert("RUSTUP_TOOLCHAIN", member(rustc, "name")?.clone());
    let mut compiler = str_of(member(rustc, "toolchain")?);
    compiler.push_str("/bin/rustc");
    pinned.insert("RUSTC", Value::String(compiler));
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
