use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::args::{self, Parsed};
use super::{case, quint};
use crate::json::{self, Integer, Object, Value};
use crate::paths;
use crate::python;

pub struct Model {
    pub tool: &'static str,
    pub about: &'static str,
    /// The stem of the model's file under `quint/` and the key of the writer's record under `#meta`.
    pub name: &'static str,
    pub style: Style,
}

/// How a writer runs Quint and records each trace under `#meta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// Quint's standard output is discarded, one run is limited to 120 seconds, and a seeded trace passes no
    /// `--step`. `#meta` becomes Quint's `format` followed by the record `model_sha256`, `seed`, `steps`, the
    /// trace's own fields and, for a directed trace, `recipe`. A trace whose `#meta` holds no `format` is
    /// refused.
    Format,
    /// Quint's standard output reaches the writer's, one run is limited to 60 seconds, and a seeded trace
    /// passes `--step step`. `#meta` is replaced by the record alone: `recipe` (empty for a seeded trace),
    /// `seed`, `steps`, the trace's own fields and `model_sha256`. Quint's own `#meta` is never read; a trace
    /// without one gains the record as its last key.
    Record,
}

impl Style {
    pub fn limit(self) -> Duration {
        match self {
            Self::Format => Duration::from_secs(120),
            Self::Record => Duration::from_secs(60),
        }
    }

    fn stdout(self) -> Stdio {
        match self {
            Self::Format => Stdio::null(),
            Self::Record => Stdio::inherit(),
        }
    }
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
    /// `Trace::new` panics if `meta` contains a key listed in `RECORD`.
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

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn recipe(&self) -> Option<&'static [&'static str]> {
        self.recipe
    }
}

/// The traces of a model whose `case.qnt` sets `BOUND` alone: each recipe under `recipe_seed`, then a seeded
/// trace of `steps` steps for each named seed, in the given orders.
pub fn traces(
    model: &Model,
    recipes: &[(&str, &'static [&'static str])],
    recipe_seed: u64,
    seeds: &[(&str, u64)],
    steps: usize,
) -> Vec<Trace> {
    let case = |steps, recipe: Option<&[&str]>| case::bounded(model.name, steps, recipe);
    let directed = recipes
        .iter()
        .map(|&(name, recipe)| (name, recipe_seed, Some(recipe)));
    let seeded = seeds.iter().map(|&(name, seed)| (name, seed, None));
    directed
        .chain(seeded)
        .map(|(name, seed, recipe)| {
            Trace::new(name.to_owned(), seed, recipe, steps, case, Vec::new())
        })
        .collect()
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
            let mut stdout = io::stdout().lock();
            return match stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
            {
                Ok(()) => 0,
                Err(error) => fail(model, &format!("standard output: {error}"), 120),
            };
        }
        Parsed::Refused { code, text } => return report(&text, code),
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
                model.style.limit(),
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

fn report(text: &str, code: u8) -> u8 {
    match io::stderr().write_all(text.as_bytes()) {
        Ok(()) => code,
        Err(_) => 120,
    }
}

fn at<E: fmt::Display>(path: &Path) -> impl FnOnce(E) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

pub(crate) fn generate(
    model: &Model,
    top: &Path,
    quint: Option<&OsStr>,
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
        // If `quint` is `None`, `generate` reports the `--quint` error after writing the model and `case.qnt`
        // to the trace directory.
        let quint =
            quint.ok_or_else(|| "argument --quint: the value `--` leaves no program".to_owned())?;
        let args = arguments(model, trace, &file);
        quint::run(quint, &args, &directory, model.style.stdout(), limit)
            .map_err(|failure| format!("{}: {failure}", trace.name))?;
        let mut data = read_trace(&file)?;
        let states = data
            .get("states")
            .ok_or_else(|| format!("{}: the trace has no key 'states'", file.display()))?;
        let count = python::len(states)
            .ok_or_else(|| format!("{}: 'states' has no length", file.display()))?;
        if count != trace.steps + 1 {
            return Err(format!(
                "{}: the trace stopped before its final action",
                trace.name
            ));
        }
        rewrite(&mut data, trace).map_err(at(&file))?;
        let mut meta = Object::new();
        if model.style == Style::Format {
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
            meta.insert("format", format);
        }
        meta.insert(
            model.name,
            Value::Object(record(model.style, &digest, trace)),
        );
        data.insert("#meta", Value::Object(meta));
        fs::write(&file, json::dump(&Value::Object(data))).map_err(at(&file))?;
    }
    Ok(())
}

fn record(style: Style, digest: &str, trace: &Trace) -> Object {
    let digest = ("model_sha256", Value::String(digest.into()));
    let recipe = |recipe: &[&str]| {
        let steps = recipe.iter().map(|&step| Value::String(step.into()));
        ("recipe", Value::Array(steps.collect()))
    };
    let fields = [
        ("seed", Value::String(format!("{:#x}", trace.seed).into())),
        ("steps", Value::Integer(Integer::from(trace.steps))),
    ]
    .into_iter()
    .chain(trace.meta.iter().cloned());
    let fields: Vec<(&str, Value)> = match style {
        Style::Format => [digest]
            .into_iter()
            .chain(fields)
            .chain(trace.recipe.map(recipe))
            .collect(),
        Style::Record => [recipe(trace.recipe.unwrap_or_default())]
            .into_iter()
            .chain(fields)
            .chain([digest])
            .collect(),
    };
    let mut record = Object::new();
    for (key, value) in fields {
        record.insert(key, value);
    }
    record
}

fn arguments(model: &Model, trace: &Trace, file: &Path) -> Vec<OsString> {
    let main = format!("{}Case", model.name);
    let seed = format!("{:#x}", trace.seed);
    let steps = trace.steps.to_string();
    let step: &[&str] = match (trace.recipe, model.style) {
        (Some(_), _) => &["--step", "recipe"],
        (None, Style::Record) => &["--step", "step"],
        (None, Style::Format) => &[],
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
