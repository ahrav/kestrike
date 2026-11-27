//! The three fixture writers share the command line, the case text, the `quint run` call and the rewrite of
//! each trace's `#meta`.
//!
//! A writer runs its traces in order. For each trace it creates `<output>/<name>/`, which must be new, writes
//! the model and `case.qnt` there, runs Quint in that directory to write the trace to
//! `<output>/<name>.itf.json`, checks that the trace contains `trace.steps + 1` states, and writes the trace
//! again with `#meta` replaced by Quint's `format` and the writer's own record. The first failure ends the
//! run with exit 1 and a diagnostic on standard error; earlier traces remain on disk.

pub mod args;
pub mod case;
pub mod quint;

#[cfg(test)]
mod args_tests;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::json::{self, Integer, Object, Value};
use crate::paths;

pub struct Model {
    pub tool: &'static str,
    pub about: &'static str,
    /// The stem of the model's file under `quint/` and the key of the writer's record under `#meta`.
    pub name: &'static str,
}

pub struct Trace {
    pub name: String,
    pub seed: u64,
    pub steps: usize,
    pub recipe: Option<&'static [&'static str]>,
    pub case: String,
    /// Fields of the writer's record that follow `steps`.
    pub meta: Vec<(&'static str, Value)>,
}

/// The hook a writer runs on the parsed trace after the state count check.
pub type Rewrite = fn(&mut Object, &Trace) -> Result<(), String>;

pub fn keep(_: &mut Object, _: &Trace) -> Result<(), String> {
    Ok(())
}

pub fn write(
    model: &Model,
    top: &Path,
    args: &[OsString],
    traces: &[Trace],
    rewrite: Rewrite,
) -> u8 {
    let options = match args::parse(model.tool, model.about, args) {
        Ok(options) => options,
        Err(code) => return code,
    };
    let outcome = options
        .output
        .ok_or_else(|| "argument --output: the value `--` leaves no path".to_owned())
        .and_then(|output| {
            paths::resolve(Path::new(&output)).map_err(|error| format!("--output: {error}"))
        })
        .and_then(|output| {
            generate(
                model,
                top,
                options.quint.as_deref(),
                &output,
                traces,
                rewrite,
            )
        });
    match outcome {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("{}: {message}", model.tool);
            1
        }
    }
}

fn generate(
    model: &Model,
    top: &Path,
    quint: Option<&OsStr>,
    output: &Path,
    traces: &[Trace],
    rewrite: Rewrite,
) -> Result<(), String> {
    let source = top.join("quint").join(format!("{}.qnt", model.name));
    let bytes = fs::read(&source).map_err(|error| format!("{}: {error}", source.display()))?;
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for trace in traces {
        let file = output.join(format!("{}.itf.json", trace.name));
        let directory = output.join(&trace.name);
        create(&directory).map_err(|error| format!("{}: {error}", directory.display()))?;
        let text = read_text(&source).map_err(|error| format!("{}: {error}", source.display()))?;
        for (name, text) in [
            (format!("{}.qnt", model.name), text.as_str()),
            ("case.qnt".to_owned(), &trace.case),
        ] {
            let path = directory.join(name);
            fs::write(&path, text).map_err(|error| format!("{}: {error}", path.display()))?;
        }
        let quint =
            quint.ok_or_else(|| "argument --quint: the value `--` leaves no program".to_owned())?;
        quint::run(
            quint,
            &arguments(model, trace, &file),
            &directory,
            quint::LIMIT,
        )
        .map_err(|failure| format!("{}: {failure}", trace.name))?;
        let mut data = read_trace(&file)?;
        let states = data
            .get("states")
            .ok_or_else(|| format!("{}: the trace has no key 'states'", file.display()))?;
        let count = python_len(states)
            .ok_or_else(|| format!("{}: 'states' has no length", file.display()))?;
        if count != trace.steps + 1 {
            return Err(format!(
                "{}: the trace stopped before its final action",
                trace.name
            ));
        }
        rewrite(&mut data, trace).map_err(|message| format!("{}: {message}", file.display()))?;
        let mut record = Object::new();
        record.insert("model_sha256", Value::String(digest.as_str().into()));
        record.insert("seed", Value::String(format!("{:#x}", trace.seed).into()));
        record.insert("steps", Value::Integer(Integer::from(trace.steps as u64)));
        for (key, value) in &trace.meta {
            record.insert(*key, value.clone());
        }
        if let Some(recipe) = trace.recipe {
            record.insert(
                "recipe",
                Value::Array(
                    recipe
                        .iter()
                        .map(|&step| Value::String(step.into()))
                        .collect(),
                ),
            );
        }
        let format = match data.get("#meta") {
            Some(Value::Object(meta)) => meta.get("format").cloned(),
            _ => None,
        }
        .ok_or_else(|| {
            format!(
                "{}: the trace has no '#meta' record with a 'format'",
                file.display()
            )
        })?;
        let mut meta = Object::new();
        meta.insert("format", format);
        meta.insert(model.name, Value::Object(record));
        data.insert("#meta", Value::Object(meta));
        fs::write(&file, json::dump(&Value::Object(data)))
            .map_err(|error| format!("{}: {error}", file.display()))?;
    }
    Ok(())
}

fn arguments(model: &Model, trace: &Trace, file: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "run".into(),
        "case.qnt".into(),
        "--main".into(),
        format!("{}Case", model.name).into(),
    ];
    if trace.recipe.is_some_and(|recipe| !recipe.is_empty()) {
        args.extend(["--step".into(), "recipe".into()]);
    }
    for arg in [
        "--backend",
        "typescript",
        "--mbt",
        "--invariant",
        "safety",
        "--seed",
    ] {
        args.push(arg.into());
    }
    args.push(format!("{:#x}", trace.seed).into());
    args.extend([
        "--max-samples".into(),
        "1".into(),
        "--max-steps".into(),
        trace.steps.to_string().into(),
    ]);
    args.extend([
        "--n-traces".into(),
        "1".into(),
        "--out-itf".into(),
        file.as_os_str().to_owned(),
    ]);
    args
}

/// `create` creates missing ancestors and returns an error if `directory` already exists.
fn create(directory: &Path) -> io::Result<()> {
    match fs::create_dir(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = directory.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::create_dir(directory)
        }
        other => other,
    }
}

fn read_text(path: &Path) -> io::Result<String> {
    Ok(fs::read_to_string(path)?
        .replace("\r\n", "\n")
        .replace('\r', "\n"))
}

fn read_trace(file: &Path) -> Result<Object, String> {
    let bytes = fs::read(file).map_err(|error| format!("{}: {error}", file.display()))?;
    let text = String::from_utf8(bytes).map_err(|error| format!("{}: {error}", file.display()))?;
    match json::parse(&text).map_err(|error| format!("{}: {error}", file.display()))? {
        Value::Object(data) => Ok(data),
        _ => Err(format!(
            "{}: the trace is a JSON value other than an object",
            file.display()
        )),
    }
}

pub fn python_len(value: &Value) -> Option<usize> {
    match value {
        Value::String(text) => Some(text.as_str().chars().count()),
        Value::Array(items) => Some(items.len()),
        Value::Object(object) => Some(object.len()),
        Value::Integer(_) | Value::Bool(_) => None,
    }
}

/// `python_int` preserves integer values and maps `false` to 0 and `true` to 1. A string takes ASCII digits
/// with an optional leading sign and optional single underscores between digits. `python_int` trims
/// `python_space` characters from both ends before parsing the sign.
pub fn python_int(value: &Value) -> Result<Integer, String> {
    let text = match value {
        Value::Integer(integer) => return Ok(integer.clone()),
        Value::Bool(flag) => return Ok(Integer::from(u64::from(*flag))),
        Value::String(text) => text.as_str(),
        Value::Array(_) | Value::Object(_) => {
            return Err("int() takes a string or a number".to_owned());
        }
    };
    let refused = || format!("invalid literal for int() with base 10: {text:?}");
    let trimmed = text.trim_matches(python_space);
    let (negative, body) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    if body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return Err(refused());
    }
    Integer::from_digits(negative, &body.replace('_', "")).ok_or_else(refused)
}

/// `python_space` matches Python's `str.isspace()` for a single character.
fn python_space(character: char) -> bool {
    matches!(
        character,
        '\t'..='\r'
            | '\u{1c}'..=' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}
