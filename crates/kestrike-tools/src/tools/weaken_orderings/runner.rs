//! One `run`'s copy of the checkout, its pins and the runs of its tests: each loom test and each GenMC
//! lane call once per plant, judged for each entry that names it.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use super::execute::{GENMC_DEADLINE, GENMC_SETUP, LOOM_DEADLINE, Launch, with_defaults};
use super::files::sha256;
use super::halt::Halt;
use super::pins::{Pins, lane_env, overlay, pin, workflow_pins};
use crate::environ::set;
use crate::genmc::correspondence::check_correspondence;
use crate::genmc::evidence::check_config;
use crate::genmc::input::listed;
use crate::genmc::refusal::Error;
use crate::genmc::transcription::check_transcription;
use crate::genmc::{is_file, read_source};
use crate::json::{self, Integer, Object, Text, Value};
use crate::orderings::check::{GENMC, family_kernel};
use crate::orderings::sources::{kernel_texts, loom_site};
use crate::orderings::verdicts::{LOOM_REBUILT, case_exit, genmc_result, loom_result};
use crate::ownership::PathError;
use crate::process::{Interrupt, captured};
use crate::python::{hexdigest, returncode, str_of, truthy};
use crate::shell::join;
use crate::text::{newlines, text};

/// The run of a test's command, `(exit code, seconds)`, as [`super::execute::execute`] gives it.
pub(super) type Execute = fn(
    &Launch<'_>,
    &[OsString],
    &Path,
    Option<&[(OsString, OsString)]>,
    Duration,
    &Path,
) -> Result<(Option<i32>, f64), Halt>;

/// A test's run under one plant: its report members, and the loom output's text or the GenMC lane's
/// evidence directory.
pub(super) struct Ran {
    members: Object,
    code: Option<i32>,
    exit: Option<Integer>,
    text: String,
    evidence: PathBuf,
}

/// A read of [`Runner::read`] as kept: the text, or the error's kind and text.
pub(super) type Read = Result<String, (io::ErrorKind, String)>;

/// The runs of one plant, by lane and test.
pub(super) type Runs = BTreeMap<(&'static str, Text), Ran>;

pub(super) struct Runner<'l> {
    pub(super) work: PathBuf,
    pub(super) copy: PathBuf,
    pub(super) evidence: PathBuf,
    pub(super) revision: String,
    pub(super) pins: Pins,
    pub(super) environ: Vec<(OsString, OsString)>,
    pub(super) launch: &'l Launch<'l>,
    pub(super) execute: Execute,
    /// Each output's serial number keeps its path apart from every other output of the run.
    serial: u64,
    /// The row whose plant the loom build holds: a row's first loom test rebuilds the crate, and its
    /// later tests reuse that build.
    rebuilt: Option<Text>,
    declared: Value,
    kernels: BTreeMap<String, String>,
    /// Each file [`Runner::read`] has read, with its text or its error, so the copy's check, the selection
    /// and every loom site's judgment read one text of a file: the one the check read before any plant.
    pub(super) reads: RefCell<BTreeMap<String, Read>>,
}

/// `text_of` is `path` as Python's `str` of a path writes it.
pub(super) fn text_of(path: &Path) -> Text {
    Text::from_os(path.as_os_str())
}

/// `os_of` is `text` as an argument, or a failure for a lone surrogate no byte stands behind.
pub(super) fn os_of(text: &Text) -> Result<OsString, Halt> {
    text.to_os()
        .ok_or_else(|| Halt::failed(text!("surrogates not allowed: ", text.repr())))
}

fn status_failed(command: &str, code: i32) -> Halt {
    Halt::failed(format!(
        "Command '{command}' returned non-zero exit status {code}."
    ))
}

/// `waited` waits for each of `children`, polling them and `interrupt` at pauses from 0.5 ms that double
/// up to 20 ms. A recorded signal, or a wait that fails, kills each other child that still runs with
/// SIGKILL and reaps it; the child whose wait failed, whose state is then unknown, gets no signal.
fn waited(children: &mut [Child], interrupt: &Interrupt) -> Result<Vec<ExitStatus>, Halt> {
    let mut statuses: Vec<Option<ExitStatus>> = vec![None; children.len()];
    let mut pause = Duration::from_micros(500);
    loop {
        let mut failed = None;
        for (at, (child, status)) in children.iter_mut().zip(&mut statuses).enumerate() {
            if status.is_none() && failed.is_none() {
                match child.try_wait() {
                    Ok(found) => *status = found,
                    Err(error) => failed = Some((at, Halt::from(error))),
                }
            }
        }
        if failed.is_none() && statuses.iter().all(Option::is_some) {
            return Ok(statuses.into_iter().flatten().collect());
        }
        let ended = match failed {
            Some((at, halt)) => Some((Some(at), halt)),
            None => interrupt
                .check()
                .err()
                .map(|interrupted| (None, interrupted.into())),
        };
        if let Some((unknown, halt)) = ended {
            for (at, (child, status)) in children.iter_mut().zip(&statuses).enumerate() {
                if status.is_none() && Some(at) != unknown {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            return Err(halt);
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(20));
    }
}

impl<'l> Runner<'l> {
    /// `new` copies the checkout `top`'s `HEAD` into `work/copy`, with `git archive` piped into
    /// `tar -x`, and reads the copy's workflow pins; `environ` is the run's environment.
    ///
    /// # Errors
    ///
    /// A recorded signal, a Git or tar call that fails or exits nonzero, or a refusal of the pins.
    pub(super) fn new(
        top: &Path,
        work: &Path,
        environ: Vec<(OsString, OsString)>,
        launch: &'l Launch<'l>,
    ) -> Result<Self, Halt> {
        let interrupt = launch.interrupt;
        let mut git = Command::new("git");
        git.arg("-C").arg(top).args(["rev-parse", "HEAD"]);
        with_defaults(&mut git);
        let shown = format!(
            "['git', '-C', {}, 'rev-parse', 'HEAD']",
            text_of(top).repr()
        );
        let parsed = crate::process::capture(&mut git, interrupt)??;
        let code = returncode(parsed.status);
        if code != 0 {
            return Err(status_failed(&shown, code));
        }
        let revision = Text::from(
            String::from_utf8(parsed.stdout)
                .map_err(Halt::failed)?
                .as_str(),
        )
        .strip()
        .to_string();
        let copy = work.join("copy");
        let mut archive = Command::new("git");
        archive
            .arg("-C")
            .arg(top)
            .args(["archive", &revision])
            .stdout(Stdio::piped());
        with_defaults(&mut archive);
        let mut archiving = archive.spawn()?;
        let mut tar = Command::new("tar");
        tar.arg("-x").arg("-C").arg(&copy);
        if let Some(stream) = archiving.stdout.take() {
            tar.stdin(stream);
        }
        with_defaults(&mut tar);
        let extracting = match tar.spawn() {
            Ok(extracting) => extracting,
            Err(error) => {
                let _ = archiving.kill();
                let _ = archiving.wait();
                return Err(error.into());
            }
        };
        // The command holds this process's copy of the pipe's read end; dropping it leaves `tar` the only
        // reader, so `git archive` gets a broken pipe when `tar` ends early.
        drop(tar);
        let mut children = [archiving, extracting];
        let statuses = waited(&mut children, interrupt)?;
        let codes: Vec<i32> = statuses.into_iter().map(returncode).collect();
        if let Some(&code) = codes.iter().find(|&&code| code != 0) {
            return Err(status_failed("git archive | tar -x", code));
        }
        let pins = workflow_pins(&copy)?;
        Ok(Self {
            work: work.to_owned(),
            evidence: work.join("evidence"),
            copy,
            revision,
            pins,
            environ,
            launch,
            execute: super::execute::execute,
            serial: 0,
            rebuilt: None,
            declared: Value::Null,
            kernels: BTreeMap::new(),
            reads: RefCell::new(BTreeMap::new()),
        })
    }

    /// `read` is the text of `path` in the copy, with `\r\n` and a lone `\r` read as `\n`, as the first
    /// read of `path` in this run found it.
    ///
    /// # Errors
    ///
    /// The first read of `path` failed, as when the file cannot be read as UTF-8.
    pub(super) fn read(&self, path: &str) -> io::Result<String> {
        if let Some(read) = self.reads.borrow().get(path) {
            return read
                .clone()
                .map_err(|(kind, text)| io::Error::new(kind, text));
        }
        let read = read_source(&self.copy, path);
        let kept = match &read {
            Ok(text) => Ok(text.clone()),
            Err(error) => Err((error.kind(), error.to_string())),
        };
        self.reads.borrow_mut().insert(path.to_owned(), kept);
        read
    }

    /// The kernel package's directory in the copy.
    fn package(&self) -> Result<PathBuf, Halt> {
        let package = match &self.declared {
            Value::Object(declared) => declared.get("package"),
            _ => None,
        };
        match package {
            Some(Value::String(package)) => Ok(self.copy.join(os_of(package)?)),
            _ => Err(Halt::failed("KeyError: 'package'")),
        }
    }

    /// `prepare` reads the copy's GenMC declaration and kernel texts, once the check has accepted the
    /// copy.
    ///
    /// # Errors
    ///
    /// The declaration or a kernel file cannot be read.
    pub(super) fn prepare(&mut self) -> Result<(), Halt> {
        let path = self.copy.join(GENMC);
        let source = fs::read_to_string(&path)
            .map_err(|error| Halt::failed(PathError::new(&path, error)))?;
        self.declared = json::parse(&source)
            .map_err(|error| Halt::failed(format!("{}: {error}", path.display())))?;
        self.kernels = kernel_texts(&self.package()?)?;
        Ok(())
    }

    /// `output` names the next output under the evidence directory: its serial number, `label` and
    /// `name`.
    pub(super) fn output(&mut self, label: &str, name: &str) -> PathBuf {
        self.serial += 1;
        self.evidence
            .join(format!("{:03}-{label}-{name}", self.serial))
    }
}

impl Runner<'_> {
    /// `check_configs` stops the run where the merged Cargo configuration that a selected lane builds
    /// under holds an entry that shapes a build, as the GenMC judge reads one: the copy's for both lanes,
    /// the kernel package's for GenMC. A loom selection also stops on a `LOOM_*` environment entry.
    ///
    /// # Errors
    ///
    /// A refusal of exit 2 for a read that fails or an entry that shapes the build; a recorded signal; a
    /// failure for an output or a start that fails.
    pub(super) fn check_configs(&mut self, lanes: &BTreeSet<&str>) -> Result<(), Halt> {
        let mut probes = vec![("copy", self.copy.clone())];
        if lanes.contains("genmc") {
            probes.push(("kernels", self.package()?));
        }
        for (name, directory) in probes {
            let recorded = self.output("config", name);
            fs::create_dir(&recorded)
                .map_err(|error| Halt::failed(PathError::new(&recorded, error)))?;
            let nightly = format!("+{}", pin(&self.pins, "NIGHTLY"));
            let words = [
                "cargo",
                &nightly,
                "-Zunstable-options",
                "config",
                "get",
                "--format",
                "json",
            ];
            let config = recorded.join("cargo-config.json");
            let sink = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&config)
                .map_err(|error| Halt::failed(PathError::new(&config, error)))?;
            let mut command = Command::new(words[0]);
            command
                .args(&words[1..])
                .current_dir(&directory)
                .env_clear()
                .envs(lane_env(&self.environ, &self.work, &self.pins))
                .stdin(Stdio::inherit())
                .stdout(sink)
                .stderr(Stdio::piped());
            with_defaults(&mut command);
            let child = command.spawn()?;
            let done = captured(child, self.launch.interrupt)??;
            let code = returncode(done.status);
            if code != 0 {
                let stderr = Text::from(String::from_utf8_lossy(&done.stderr).as_ref()).strip();
                let lines = stderr.splitlines();
                let tail = Text::join(" | ", &lines[lines.len().saturating_sub(3)..]);
                let shown: Vec<Text> = words.iter().map(|word| Text::from(*word)).collect();
                return Err(Halt::stop(
                    2,
                    text!(
                        join(&shown),
                        " in ",
                        text_of(&directory),
                        " exited ",
                        code,
                        ": ",
                        tail
                    ),
                ));
            }
            let shapes = |refusal: &dyn std::fmt::Display| {
                Halt::stop(
                    2,
                    text!(
                        "the Cargo configuration of ",
                        text_of(&directory),
                        " shapes the build: ",
                        refusal.to_string()
                    ),
                )
            };
            match check_config(&recorded) {
                Ok(()) => {}
                Err(error @ (Error::Refusal(_) | Error::Value(_) | Error::Type(_))) => {
                    return Err(shapes(&error));
                }
                Err(error) => return Err(Halt::failed(error)),
            }
            if !lanes.contains("loom") {
                continue;
            }
            let read = fs::read_to_string(&config)
                .map_err(|error| Halt::failed(PathError::new(&config, error)))?;
            let parsed = json::parse(&read).map_err(|error| shapes(&error))?;
            let loom = loom_entries(&parsed);
            if !loom.is_empty() {
                let named: Vec<Text> = loom.iter().map(|entry| text!("env.", entry)).collect();
                return Err(Halt::stop(
                    2,
                    text!(
                        "the Cargo configuration of ",
                        text_of(&directory),
                        " sets ",
                        Text::join(", ", &named)
                    ),
                ));
            }
        }
        Ok(())
    }

    /// `check_declaration` stops the run where the GenMC judge refuses the copy's declaration against the
    /// unweakened copy: a binding whose kernel or production operation drifted, or a case that disagrees
    /// with the litmus tests it names. A plant then differs from the judged sources in its one site.
    ///
    /// # Errors
    ///
    /// A refusal of exit 2 for the judge's refusal, a failed read or a misshapen declaration; a failure
    /// for nesting past the reader's depth or a binding with no occurrence to read.
    pub(super) fn check_declaration(&self) -> Result<(), Halt> {
        let judged = check_transcription(&self.copy, &self.declared)
            .and_then(|()| check_correspondence(&self.copy, &self.declared));
        match judged {
            Ok(()) => Ok(()),
            Err(
                error @ (Error::Refusal(_)
                | Error::Os(_)
                | Error::Type(_)
                | Error::Key(_)
                | Error::Value(_)),
            ) => Err(Halt::stop(
                2,
                text!(
                    "the copy's GenMC judge refuses its declaration: ",
                    error.to_string()
                ),
            )),
            Err(error) => Err(Halt::failed(error)),
        }
    }
}

/// `loom_entries` is the sorted names of the `env` table of the merged Cargo configuration `parsed` that
/// start `LOOM_`.
pub(super) fn loom_entries(parsed: &Value) -> Vec<Text> {
    let mut loom: Vec<Text> = match json_path(parsed, &["env"]) {
        Some(Value::Object(env)) => env
            .iter()
            .map(|(entry, _)| entry.clone())
            .filter(|entry| entry.starts_with(&Text::from("LOOM_")))
            .collect(),
        _ => Vec::new(),
    };
    loom.sort();
    loom
}

/// `label_of` is the label of a run's outputs: the row's label under a plant, `baseline` on the
/// unweakened copy.
fn label_of(row: Option<&Text>) -> String {
    row.map_or_else(|| "baseline".to_owned(), ToString::to_string)
}

fn code_value(code: Option<i32>) -> Value {
    code.map_or(Value::Null, |code| {
        let digits = code.unsigned_abs().to_string();
        let integer = Integer::from_digits(code < 0, &digits);
        Value::Integer(integer.expect("an i32's digits spell an integer"))
    })
}

impl Runner<'_> {
    /// `loom` is the result of loom test `test` judged for `failure`, running the test once per plant
    /// into `runs`: on the unweakened copy where `row` is `None`, else under the plant of the row it
    /// labels.
    ///
    /// # Errors
    ///
    /// The run of the test halts, its output cannot be read, or the judgment fails.
    pub(super) fn loom(
        &mut self,
        test: &Text,
        failure: &str,
        row: Option<&Text>,
        runs: &mut Runs,
    ) -> Result<Value, Halt> {
        let key = ("loom", test.clone());
        if !runs.contains_key(&key) {
            let name = test.replace(&Text::from("::"), &Text::from("."));
            let output = self.output(&label_of(row), &format!("loom-{name}.txt"));
            let env = lane_env(&self.environ, &self.work, &self.pins);
            let stable = Text::from(format!("+{}", pin(&self.pins, "STABLE")).as_str());
            let words: Vec<Text> = [
                Text::from("cargo"),
                stable,
                Text::from("test"),
                Text::from("-p"),
                Text::from("kestrike"),
                Text::from("--lib"),
                Text::from("--release"),
                test.clone(),
                Text::from("--"),
                Text::from("--exact"),
            ]
            .into();
            let argv = words.iter().map(os_of).collect::<Result<Vec<_>, _>>()?;
            let (code, seconds) = (self.execute)(
                self.launch,
                &argv,
                &self.copy,
                Some(&env),
                LOOM_DEADLINE,
                &output,
            )?;
            let bytes =
                fs::read(&output).map_err(|error| Halt::failed(PathError::new(&output, error)))?;
            let text = newlines(String::from_utf8_lossy(&bytes).into_owned());
            if let Some(row) = row
                && LOOM_REBUILT.is_match(&text)
            {
                self.rebuilt = Some(row.clone());
            }
            let mut members = Object::new();
            members.insert(
                "command",
                Value::String(text!("RUSTFLAGS=\"--cfg loom\" ", join(&words))),
            );
            members.insert("exit", code_value(code));
            members.insert("seconds", Value::Float(seconds));
            members.insert("output", Value::String(text_of(&output)));
            let digest = hexdigest(&bytes);
            members.insert("digest", Value::String(Text::from(digest.as_str())));
            runs.insert(
                key.clone(),
                Ran {
                    members,
                    code,
                    exit: None,
                    text,
                    evidence: PathBuf::new(),
                },
            );
        }
        let ran = &runs[&key];
        let site = if failure.is_empty() {
            None
        } else {
            let read = |path: &str| self.read(path);
            test.to_str()
                .and_then(|test| loom_site(test, failure, &read))
        };
        let code = ran.code;
        let rebuilt = row.is_none() || self.rebuilt.as_ref() == row;
        let (verdict, reason) = loom_result(
            &ran.text,
            code,
            failure,
            rebuilt,
            site.as_ref().map(|(path, line)| (path.as_str(), *line)),
        )
        .map_err(Halt::failed)?;
        let result = result_record("loom", test, &ran.members, verdict.name(), &reason);
        Ok(Value::Object(result))
    }
}

impl Runner<'_> {
    /// `genmc` is the results of GenMC `cases` judged for `failure`, running each case once per plant
    /// into `runs`: the cases not yet run go to one lane call, with the `pr` profile where it holds each
    /// of them and `scheduled` otherwise.
    ///
    /// # Errors
    ///
    /// The lane call halts, its evidence directory cannot be made, an output cannot be read, or a
    /// judgment fails.
    pub(super) fn genmc(
        &mut self,
        cases: &[Text],
        failure: &str,
        row: Option<&Text>,
        runs: &mut Runs,
    ) -> Result<Vec<Value>, Halt> {
        let mut fresh: Vec<&Text> = Vec::new();
        for case in cases {
            if !fresh.contains(&case) && !runs.contains_key(&("genmc", case.clone())) {
                fresh.push(case);
            }
        }
        if !fresh.is_empty() {
            let evidence = self.output(&label_of(row), "genmc");
            let pr = match json_path(&self.declared, &["profiles", "pr"]) {
                Some(pr) => listed(pr, "the pr profile").map_err(Halt::failed)?,
                None => return Err(Halt::failed("KeyError: 'profiles'")),
            };
            if let Some(unhashable) = pr
                .iter()
                .find(|named| matches!(named, Value::Array(_) | Value::Object(_)))
            {
                return Err(Halt::failed(format!(
                    "TypeError: unhashable type: '{}'",
                    type_name(unhashable)
                )));
            }
            let held = fresh.iter().all(|case| {
                pr.iter()
                    .any(|named| *named == Value::String((*case).clone()))
            });
            let profile = if held { "pr" } else { "scheduled" };
            let mut words: Vec<Text> = ["bash", "scripts/rust-lane.sh", "genmc", profile]
                .map(Text::from)
                .into();
            words.extend(fresh.iter().map(|case| (*case).clone()));
            let argv = words.iter().map(os_of).collect::<Result<Vec<_>, _>>()?;
            let mut env = self.environ.clone();
            overlay(&mut env, &self.pins);
            set(&mut env, "EVIDENCE", evidence.clone().into_os_string());
            set(
                &mut env,
                "GITHUB_STEP_SUMMARY",
                evidence.join("summary.md").into_os_string(),
            );
            fs::create_dir(&evidence)
                .map_err(|error| Halt::failed(PathError::new(&evidence, error)))?;
            let count = u32::try_from(fresh.len()).unwrap_or(u32::MAX);
            let deadline = GENMC_DEADLINE
                .saturating_mul(count)
                .saturating_add(GENMC_SETUP);
            let (code, seconds) = (self.execute)(
                self.launch,
                &argv,
                &self.copy,
                Some(&env),
                deadline,
                &evidence.join("lane.txt"),
            )?;
            for case in fresh {
                let named = case.to_str().unwrap_or_default();
                let output = evidence.join(format!("genmc-{named}.txt"));
                let exit = case_exit(&evidence, named);
                let mut members = Object::new();
                members.insert("command", Value::String(join(&words)));
                members.insert("exit", exit.clone().map_or(Value::Null, Value::Integer));
                members.insert("lane_exit", code_value(code));
                members.insert("seconds", Value::Float(seconds));
                members.insert("output", Value::String(text_of(&output)));
                let digest = if is_file(&output)? {
                    let digest = sha256(&output)
                        .map_err(|error| Halt::failed(PathError::new(&output, error)))?;
                    Value::String(Text::from(digest.as_str()))
                } else {
                    Value::Null
                };
                members.insert("digest", digest);
                let ran = Ran {
                    members,
                    code,
                    exit,
                    text: String::new(),
                    evidence: evidence.clone(),
                };
                runs.insert(("genmc", case.clone()), ran);
            }
        }
        let mut results = Vec::new();
        for case in cases {
            let ran = &runs[&("genmc", case.clone())];
            let (verdict, reason, executions) = if ran.code.is_none() {
                (
                    "no verdict",
                    "the lane passed its deadline".to_owned(),
                    Value::Null,
                )
            } else {
                let kernel = family_kernel(case, &self.kernels).map(|(path, _)| path);
                let kill = kernel.map(|kernel| (failure, kernel));
                let named = case.to_str().unwrap_or_default();
                let outcome = genmc_result(
                    &self.copy,
                    &self.declared,
                    named,
                    kill,
                    &ran.evidence,
                    row.is_some(),
                    ran.exit.as_ref(),
                )
                .map_err(Halt::failed)?;
                let executions = outcome
                    .executions()
                    .cloned()
                    .map_or(Value::Null, Value::Integer);
                (
                    outcome.verdict().name(),
                    outcome.reason().to_owned(),
                    executions,
                )
            };
            let mut result = result_record("genmc", case, &ran.members, verdict, &reason);
            result.insert("executions", executions);
            results.push(Value::Object(result));
        }
        Ok(results)
    }

    /// `each` gives `yielded` the results of one lane entry as each is judged: a list per loom test, and
    /// one list for a GenMC batch. `runs` holds each test's run under the same plant, so a test that two
    /// entries name runs once.
    ///
    /// # Errors
    ///
    /// A run or a judgment halts, or `yielded` does.
    pub(super) fn each(
        &mut self,
        entry: &Object,
        row: Option<&Text>,
        runs: &mut Runs,
        yielded: &mut dyn FnMut(Vec<Value>) -> Result<(), Halt>,
    ) -> Result<(), Halt> {
        let raw = entry.get("failure").unwrap_or(&Value::Null);
        let loom = entry.get("lane") == Some(&Value::String(Text::from("loom")));
        let failure = match raw {
            Value::String(failure) => failure.to_string(),
            other if !truthy(other) => String::new(),
            other if loom => {
                return Err(Halt::failed(format!(
                    "TypeError: 'in <string>' requires string as left operand, not {}",
                    type_name(other)
                )));
            }
            other => str_of(other).to_string(),
        };
        let tests: Vec<Text> = match entry.get("tests") {
            Some(Value::Array(tests)) => tests
                .iter()
                .filter_map(|test| match test {
                    Value::String(test) => Some(test.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        if loom {
            for test in &tests {
                let result = self.loom(test, &failure, row, runs)?;
                yielded(vec![result])?;
            }
            Ok(())
        } else {
            let results = self.genmc(&tests, &failure, row, runs)?;
            yielded(results)
        }
    }
}

/// `result_record` is a result's report members: its lane, its test, the members of its run, its verdict
/// and its reason, in that order.
fn result_record(lane: &str, test: &Text, members: &Object, verdict: &str, reason: &str) -> Object {
    let mut result = Object::new();
    result.insert("lane", Value::String(Text::from(lane)));
    result.insert("test", Value::String(test.clone()));
    for (name, value) in members.iter() {
        result.insert(name.clone(), value.clone());
    }
    result.insert("result", Value::String(Text::from(verdict)));
    result.insert("reason", Value::String(Text::from(reason)));
    result
}

/// `type_name` is the name Python gives the type of the JSON value `value` reads as.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "dict",
        Value::Array(_) => "list",
        Value::String(_) => "str",
        Value::Integer(_) => "int",
        Value::Float(_) => "float",
        Value::Bool(_) => "bool",
        Value::Null => "NoneType",
    }
}

/// `json_path` is the member that `keys` reach from `value` through objects.
pub(super) fn json_path<'v>(value: &'v Value, keys: &[&str]) -> Option<&'v Value> {
    keys.iter().try_fold(value, |value, key| match value {
        Value::Object(object) => object.get(key),
        _ => None,
    })
}

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;
