//! [`write`] reads a writer's command line and writes its traces as the module comment of `fixtures` states.
//!
//! The output is all or nothing for each trace up to the first failure: the traces before it are complete,
//! and the failing one keeps Quint's own bytes when Quint wrote them.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::args::{self, Parsed};
use super::quint;
use crate::json::{self, Integer, Object, Value};
use crate::paths;
use crate::python;

pub struct Model {
    pub tool: &'static str,
    pub about: &'static str,
    /// The stem of the model's file under `quint/` and the key of the writer's record under `#meta`.
    pub name: &'static str,
}

/// The keys of the writer's record that [`Trace::new`] refuses in `meta`.
const RECORD: [&str; 4] = ["model_sha256", "seed", "steps", "recipe"];

pub struct Trace {
    name: String,
    seed: u64,
    steps: usize,
    recipe: Option<&'static [&'static str]>,
    case: String,
    meta: Vec<(&'static str, Value)>,
}

impl Trace {
    /// A recipe with at least one action makes a directed trace of one step per action; `None` or an empty
    /// recipe makes a seeded trace of `steps` steps. `case` receives the step count and the recipe and returns
    /// the text of `case.qnt`. `meta` holds the fields of the writer's record that follow `steps`.
    ///
    /// # Panics
    ///
    /// `Trace::new` panics if `meta` contains one of the keys `model_sha256`, `seed`, `steps` and
    /// `recipe`.
    pub fn new(
        name: String,
        seed: u64,
        recipe: Option<&'static [&'static str]>,
        steps: usize,
        case: impl FnOnce(usize, Option<&[&str]>) -> String,
        meta: Vec<(&'static str, Value)>,
    ) -> Self {
        let recipe = recipe.filter(|recipe| !recipe.is_empty());
        let steps = recipe.map_or(steps, <[_]>::len);
        for (key, _) in &meta {
            assert!(
                !RECORD.contains(key),
                "the writer's record sets {key} itself"
            );
        }
        Self {
            case: case(steps, recipe),
            name,
            seed,
            steps,
            recipe,
            meta,
        }
    }

    pub fn recipe(&self) -> Option<&'static [&'static str]> {
        self.recipe
    }
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
        Parsed::Run(options) => options,
        Parsed::Help(text) => {
            return match emit(io::stdout().as_fd(), &text) {
                Ok(()) => 0,
                Err(error) => fail(model, &format!("standard output: {error}"), 120),
            };
        }
        Parsed::Refused { code, text } => return report(&text, code),
    };
    let outcome = paths::resolve(Path::new(&options.output))
        .map_err(|error| format!("--output: {error}"))
        .and_then(|output| {
            generate(
                model,
                top,
                &options.quint,
                &output,
                traces,
                rewrite,
                quint::LIMIT,
            )
        });
    match outcome {
        Ok(()) => 0,
        Err(message) => fail(model, &message, 1),
    }
}

fn fail(model: &Model, message: &str, code: u8) -> u8 {
    report(&format!("{}: {message}\n", model.tool), code)
}

/// `report` returns `code` once `text` is written to standard error, and 120 when the write fails.
fn report(text: &str, code: u8) -> u8 {
    match emit(io::stderr().as_fd(), text) {
        Ok(()) => code,
        Err(_) => 120,
    }
}

/// `emit` writes `text` to a duplicate of `stream`, so a write error such as `EBADF` on a descriptor opened
/// read-only reaches the caller. A closed `stream` takes the text without an error.
fn emit(stream: BorrowedFd<'_>, text: &str) -> io::Result<()> {
    match stream.try_clone_to_owned() {
        Ok(owned) => File::from(owned).write_all(text.as_bytes()),
        Err(error) if error.raw_os_error() == Some(libc::EBADF) => Ok(()),
        Err(error) => Err(error),
    }
}

fn at<E: fmt::Display>(path: &Path) -> impl FnOnce(E) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

pub(crate) fn generate(
    model: &Model,
    top: &Path,
    quint: &OsStr,
    output: &Path,
    traces: &[Trace],
    rewrite: Rewrite,
    limit: Duration,
) -> Result<(), String> {
    let source = top.join("quint").join(format!("{}.qnt", model.name));
    let bytes = fs::read(&source).map_err(at(&source))?;
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for trace in traces {
        let file = output.join(format!("{}.itf.json", trace.name));
        let directory = output.join(&trace.name);
        create(&directory).map_err(at(&directory))?;
        let text = read_text(&source).map_err(at(&source))?;
        for (name, text) in [
            (format!("{}.qnt", model.name), text.as_str()),
            ("case.qnt".to_owned(), &trace.case),
        ] {
            let path = directory.join(name);
            fs::write(&path, text).map_err(at(&path))?;
        }
        quint::run(quint, &arguments(model, trace, &file), &directory, limit)
            .map_err(|failure| format!("{}: {failure}", trace.name))?;
        let mut data = read_trace(&file)?;
        let states = data
            .get("states")
            .ok_or_else(|| format!("{}: the trace has no key 'states'", file.display()))?;
        let count = python::len(states)
            .ok_or_else(|| format!("{}: 'states' has no length", file.display()))?;
        if trace.steps.checked_add(1) != Some(count) {
            return Err(format!(
                "{}: the trace stopped before its final action",
                trace.name
            ));
        }
        rewrite(&mut data, trace).map_err(at(&file))?;
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
        // Quint's other `#meta` fields record the time of the run, so the written trace replaces them with
        // the writer's record, which depends on the model and the trace alone.
        let mut meta = Object::new();
        meta.insert("format", format);
        meta.insert(model.name, Value::Object(record(&digest, trace)));
        data.insert("#meta", Value::Object(meta));
        fs::write(&file, json::dump(&Value::Object(data))).map_err(at(&file))?;
    }
    Ok(())
}

fn record(digest: &str, trace: &Trace) -> Object {
    let mut record = Object::new();
    record.insert("model_sha256", Value::String(digest.into()));
    record.insert("seed", Value::String(format!("{:#x}", trace.seed).into()));
    record.insert("steps", Value::Integer(Integer::from(trace.steps)));
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
    record
}

fn arguments(model: &Model, trace: &Trace, file: &Path) -> Vec<OsString> {
    let main = format!("{}Case", model.name);
    let seed = format!("{:#x}", trace.seed);
    let steps = trace.steps.to_string();
    let step: &[&str] = if trace.recipe.is_some() {
        &["--step", "recipe"]
    } else {
        &[]
    };
    let head = ["run", "case.qnt", "--main", &main];
    let tail = [
        "--backend",
        "typescript",
        "--mbt",
        "--invariant",
        "safety",
        "--seed",
        &seed,
        "--max-samples",
        "1",
    ];
    let last = ["--max-steps", &steps, "--n-traces", "1", "--out-itf"];
    let mut args: Vec<OsString> = head
        .iter()
        .chain(step)
        .chain(&tail)
        .chain(&last)
        .map(OsString::from)
        .collect();
    args.push(file.as_os_str().to_owned());
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

/// `read_text` reads `path` as UTF-8 and writes each `\r\n` and each lone `\r` as `\n`, the text a model
/// copy holds.
fn read_text(path: &Path) -> io::Result<String> {
    Ok(fs::read_to_string(path)?
        .replace("\r\n", "\n")
        .replace('\r', "\n"))
}

fn read_trace(file: &Path) -> Result<Object, String> {
    let bytes = fs::read(file).map_err(at(file))?;
    let text = String::from_utf8(bytes).map_err(at(file))?;
    match json::parse(&text).map_err(at(file))? {
        Value::Object(data) => Ok(data),
        _ => Err(format!(
            "{}: the trace is a JSON value other than an object",
            file.display()
        )),
    }
}
