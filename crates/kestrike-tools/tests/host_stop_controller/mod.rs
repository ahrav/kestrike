//! The cases of the host stop controller's `run`, each over the plane of [`plane`], the clock it
//! holds and the file steps of [`steps`], in a scratch directory that holds the operator file, the
//! snapshot, the package, a catalog in which each GD-2 prerequisite reads as met, and an evidence
//! directory that holds the operator's copy of the package.

#![cfg(target_os = "linux")]

mod abort_path;
mod after_stop;
mod before_stop;
mod marks;
mod plane;
mod refusals;
mod signals;
mod step_one;
mod steps;
mod stop_run;
mod window;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use kestrike_tools::gameday::FILE_LIMIT;
use kestrike_tools::host_stop::{Delivered, Record, Signal, gd2_of, read_operator, steps_tail};
use kestrike_tools::host_stop_controller::{Command, Context, Controller, entry};
use kestrike_tools::json::{Text, Value};
use kestrike_tools::python::hexdigest;

use crate::host_stop_support::{
    START, Scratch, gd2_mut, json, met, object, operator, package, rewrite, tree, value,
};
use plane::{ALARMS, Action, CHANGES, Logged, Plane, STATUS, STOP, Shared, State};
use steps::{Plant, Plants, Step, Steps};

/// The name under which the evidence directory holds the operator's copy of the package.
const COPY: &str = "package.json";

/// A stream whose bytes the case reads after the run, shared by the run's two streams.
#[derive(Clone, Default)]
pub(crate) struct Output(Rc<RefCell<Vec<u8>>>);

impl Output {
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.borrow().clone()).expect("the lines are UTF-8")
    }
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What a case's stream does at one write: `None` takes the bytes into the case's [`Output`].
pub(crate) type Writes = Rc<dyn Fn(&[u8]) -> Option<io::Result<usize>>>;

/// One of the run's two streams: it takes its bytes into the case's [`Output`] of both streams and
/// into its own, through the case's [`Writes`] when it has one.
struct Hooked(Output, Output, Option<Writes>);

impl Write for Hooked {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(ended) = self.2.as_ref().and_then(|writes| writes(bytes)) {
            return ended;
        }
        self.1.write_all(bytes)?;
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// GD-2's guardrail texts in the catalog's order.
pub(crate) fn guardrails() -> Vec<String> {
    let mut catalog = met();
    let Some(Value::Array(texts)) = gd2_mut(&mut catalog).get("guardrail").cloned() else {
        panic!("GD-2 lists its guardrails")
    };
    texts
        .iter()
        .map(|text| match text {
            Value::String(text) => text.to_string(),
            other => panic!("{other:?} is a guardrail text"),
        })
        .collect()
}

/// GD-2's restoration steps.
pub(crate) fn steps() -> String {
    let mut catalog = met();
    let gd2 = gd2_mut(&mut catalog);
    match gd2.get("restoration") {
        Some(Value::Object(restoration)) => match restoration.get("steps") {
            Some(Value::String(steps)) => steps.to_string(),
            other => panic!("{other:?} are the steps"),
        },
        other => panic!("{other:?} is the restoration"),
    }
}

/// The end of every abort mark's detail.
pub(crate) fn tail() -> String {
    steps_tail(&steps())
}

/// The sorted names of the entries under `root`, each relative to it, directories walked.
pub(crate) fn listing(root: &Path) -> Vec<String> {
    fn walk(root: &Path, at: &Path, names: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(at) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("the directory lists");
            let path = entry.path();
            let shown = path.strip_prefix(root).expect("under the root");
            names.push(shown.to_string_lossy().into_owned());
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                walk(root, &path, names);
            }
        }
    }
    let mut names = Vec::new();
    walk(root, root, &mut names);
    names.sort();
    names
}

/// One case's scratch directory, plane, plants and signal record.
pub(crate) struct Case {
    pub(crate) scratch: Scratch,
    pub(crate) operator: Value,
    pub(crate) operator_text: Option<String>,
    pub(crate) package: PathBuf,
    pub(crate) evidence: PathBuf,
    pub(crate) catalog: PathBuf,
    pub(crate) plane: Shared,
    pub(crate) plants: Plants,
    pub(crate) cap: Rc<Cell<Option<usize>>>,
    pub(crate) stall: Rc<Cell<bool>>,
    pub(crate) delivered: &'static Delivered,
    pub(crate) output: Output,
    pub(crate) stdout: Output,
    pub(crate) stderr: Output,
    pub(crate) writes: Option<Writes>,
    pub(crate) env: Vec<(OsString, OsString)>,
    pub(crate) file_limit: u64,
    pub(crate) mark_limit: u64,
}

impl Case {
    pub(crate) fn new(label: &str) -> Self {
        let scratch = Scratch::new(label);
        scratch.snapshot();
        let evidence = scratch.0.join("evidence");
        fs::create_dir(&evidence).expect("the evidence directory is made");
        let catalog = scratch.write("gamedays.json", json(&met()).as_bytes());
        let o = operator();
        let texts = |key: &str| -> Vec<String> {
            match (key, object(o.clone()).get(key)) {
                ("alarms", Some(Value::Object(alarms))) => {
                    alarms.iter().map(|(_, name)| plain(name)).collect()
                }
                (_, Some(Value::Array(items))) => items.iter().map(plain).collect(),
                (_, other) => panic!("{other:?} is the fixture's {key}"),
            }
        };
        let o_object = object(o.clone());
        let state = State::new(
            START,
            evidence.clone(),
            &plain(o_object.get("region").expect("a region")),
            &plain(o_object.get("identity").expect("an identity")),
            &texts("instances"),
            &texts("alarms"),
        );
        let case = Self {
            package: scratch.0.join("package.json"),
            scratch,
            operator: o,
            operator_text: None,
            evidence,
            catalog,
            plane: Rc::new(RefCell::new(state)),
            plants: Rc::new(RefCell::new(Vec::new())),
            cap: Rc::new(Cell::new(None)),
            stall: Rc::new(Cell::new(false)),
            delivered: Box::leak(Box::new(Delivered::new())),
            output: Output::default(),
            stdout: Output::default(),
            stderr: Output::default(),
            writes: None,
            env: vec![(OsString::from("PATH"), OsString::from("/nonexistent"))],
            file_limit: FILE_LIMIT,
            mark_limit: FILE_LIMIT,
        };
        case.fill(&package());
        case
    }

    /// Writes `data` as the package and as the operator's copy of it in the evidence directory.
    pub(crate) fn fill(&self, data: &[u8]) {
        fs::write(&self.package, data).expect("the package is written");
        fs::write(self.evidence.join(COPY), data).expect("the copy is written");
    }

    pub(crate) fn write_operator(&self) -> PathBuf {
        let text = self
            .operator_text
            .clone()
            .unwrap_or_else(|| format!("{}\n", json(&self.operator)));
        self.scratch.write("operator.json", text.as_bytes())
    }

    pub(crate) fn plant(&self, plant: Plant) {
        self.plants.borrow_mut().push(plant);
    }

    /// Runs `run` over the plane and the clock with `evidence` as the evidence argument, and
    /// returns the exit code.
    pub(crate) fn run_with(&mut self, evidence: OsString) -> u8 {
        let deadline = object(self.operator.clone())
            .get("deadline_seconds")
            .and_then(kestrike_tools::host_stop::Number::of)
            .map(|deadline| deadline.to_string().parse::<f64>().expect("a number"));
        {
            let mut plane = self.plane.borrow_mut();
            plane.deadline = deadline.map(|deadline| plane.t + deadline);
        }
        let command = Command::Run {
            operator: self.write_operator(),
            package: self.package.clone(),
            evidence,
        };
        self.in_context(|cx| entry(&command, cx))
    }

    /// Runs `body` on a context over this case's plane, file steps, record, environment and streams.
    pub(crate) fn in_context<T>(
        &self,
        body: impl FnOnce(&mut Context<'_, Plane, Steps>) -> T,
    ) -> T {
        let mut seam = Plane(Rc::clone(&self.plane));
        let files = self.steps();
        let mut record = Record::new(self.delivered);
        let mut out = Hooked(
            self.output.clone(),
            self.stdout.clone(),
            self.writes.clone(),
        );
        let mut err = Hooked(
            self.output.clone(),
            self.stderr.clone(),
            self.writes.clone(),
        );
        let top = tree();
        let mut cx = Context {
            seam: &mut seam,
            files: &files,
            record: &mut record,
            env: &self.env,
            out: &mut out,
            err: &mut err,
            catalog: &self.catalog,
            top: &top,
            file_limit: self.file_limit,
            mark_limit: self.mark_limit,
        };
        body(&mut cx)
    }

    pub(crate) fn steps(&self) -> Steps {
        Steps {
            state: Rc::clone(&self.plane),
            plants: Rc::clone(&self.plants),
            cap: Rc::clone(&self.cap),
            stall: Rc::clone(&self.stall),
        }
    }

    pub(crate) fn run(&mut self) -> u8 {
        let evidence = self.evidence.clone().into_os_string();
        self.run_with(evidence)
    }

    /// The lines of both streams in the order the run wrote them.
    pub(crate) fn output(&self) -> String {
        self.output.text()
    }

    pub(crate) fn stdout(&self) -> String {
        self.stdout.text()
    }

    pub(crate) fn stderr(&self) -> String {
        self.stderr.text()
    }

    pub(crate) fn ops(&self) -> Vec<String> {
        self.plane.borrow().ops()
    }

    pub(crate) fn stops(&self) -> Vec<Logged> {
        self.plane.borrow().stops()
    }

    pub(crate) fn log(&self) -> Vec<Logged> {
        self.plane.borrow().log.clone()
    }

    /// `{mark: value}` of `injection/`; the evidence directory holds nothing else but the package's
    /// copy once it holds `injection`.
    pub(crate) fn marks(&self) -> BTreeMap<String, Value> {
        let root = self.evidence.join("injection");
        if !root.exists() {
            return BTreeMap::new();
        }
        assert_eq!(
            listing_top(&self.evidence),
            ["injection", COPY],
            "{}",
            self.output()
        );
        fs::read_dir(&root)
            .expect("injection/ lists")
            .map(|entry| {
                let path = entry.expect("injection/ lists").path();
                let stem = path
                    .file_stem()
                    .expect("a mark's name")
                    .to_string_lossy()
                    .into_owned();
                let text = fs::read_to_string(&path).expect("a mark reads");
                (stem, value(&text))
            })
            .collect()
    }

    /// Rewrites one snapshot file with `change` applied to its rows.
    pub(crate) fn snapshot(&self, name: &str, change: impl FnOnce(&mut Vec<Value>)) {
        rewrite(&self.scratch.0.join("snapshot").join(name), change);
    }

    /// Rewrites the package with `change` applied and approves its new digest.
    pub(crate) fn repackage(&mut self, change: impl FnOnce(&mut Value)) {
        let mut p = value(&fs::read_to_string(&self.package).expect("the package reads"));
        change(&mut p);
        let data = json(&p).into_bytes();
        self.fill(&data);
        set(
            &mut self.operator,
            &["approval", "package_sha256"],
            Value::String(Text::from(hexdigest(&data))),
        );
    }

    /// The run ends in a refusal naming `reason`, after exactly `calls`, with the evidence directory
    /// holding the package's copy alone.
    pub(crate) fn assert_refused(&mut self, calls: &[&str], reason: &str) {
        let code = self.run();
        let output = self.output();
        assert_eq!(code, 2, "{output}");
        assert!(output.contains("refused: "), "{output}");
        assert!(output.contains(reason), "{reason:?} in {output}");
        assert_eq!(self.ops(), calls, "{output}");
        assert_eq!(listing(&self.evidence), [COPY], "{output}");
        assert_eq!(
            self.stdout(),
            "",
            "a refusal prints on standard error alone"
        );
        let stderr = self.stderr();
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        assert!(
            stderr.starts_with("host-stop-controller: refused: "),
            "{stderr}"
        );
        self.assert_retries();
    }

    /// Every call but the stop request runs with the CLI's retries on, and the stop request with
    /// them off.
    pub(crate) fn assert_retries(&self) {
        for logged in self.log() {
            assert_eq!(logged.retry, logged.op != STOP, "{logged:?}");
        }
    }

    /// The run ends in the abort path with `cause` and `guardrail`, the marks `marks` standing, the
    /// detail holding `detail` and ending with the steps' digest, the steps printed, no call that
    /// changes an instance but one stop request at most, and the abort's status read last when a
    /// stop request may have left.
    pub(crate) fn assert_aborted(
        &mut self,
        cause: &str,
        marks: &[&str],
        guardrail: Option<&str>,
        detail: Option<&str>,
    ) -> BTreeMap<String, Value> {
        let code = self.run();
        let output = self.output();
        assert_eq!(code, 1, "{output}");
        let found = self.marks();
        let mut expected: Vec<&str> = marks.to_vec();
        expected.sort_unstable();
        assert_eq!(
            found.keys().map(String::as_str).collect::<Vec<_>>(),
            expected,
            "{output}"
        );
        let abort = object(found["abort"].clone());
        let shown = |key: &str| match abort.get(key) {
            Some(Value::String(text)) => Some(text.to_string()),
            Some(Value::Null) => None,
            other => panic!("{other:?} is the abort's {key}"),
        };
        assert_eq!(shown("cause").as_deref(), Some(cause), "{abort:?}");
        assert_eq!(shown("guardrail").as_deref(), guardrail, "{abort:?}");
        let text = shown("detail").expect("a detail");
        if let Some(detail) = detail {
            assert!(text.contains(detail), "{detail:?} in {text}");
        }
        assert!(text.ends_with(&tail()), "{text}");
        assert!(output.contains(&steps()), "{output}");
        self.assert_abort_lines(cause, guardrail, &text);
        let ops = self.ops();
        assert!(
            !ops.iter()
                .any(|op| CHANGES.contains(&op.as_str()) && op != STOP),
            "{ops:?}"
        );
        let stops = self.stops();
        assert!(stops.len() <= 1, "{ops:?}");
        self.assert_retries();
        if !stops.is_empty() {
            let log = self.log();
            let last = log.last().expect("a call");
            assert_eq!(last.op, STATUS, "{ops:?}");
            assert!(last.marks.iter().any(|mark| mark == "abort"), "{last:?}");
        }
        found
    }
}

impl Case {
    /// Standard output ends with the abort's line, the target's status line when a stop request may
    /// have left, and GD-2's restoration steps; standard error holds only the lines of an abort
    /// path's mark that failed.
    pub(crate) fn assert_abort_lines(&self, cause: &str, guardrail: Option<&str>, detail: &str) {
        let stdout = self.stdout();
        let lines: Vec<&str> = stdout.lines().collect();
        let sent = !self.stops().is_empty();
        let count = if sent { 3 } else { 2 };
        assert!(lines.len() >= count, "{stdout}");
        let last = &lines[lines.len() - count..];
        let shown = guardrail.map_or_else(String::new, |guardrail| format!(" ({guardrail})"));
        assert_eq!(
            last[0],
            format!("host-stop-controller: aborted on {cause}{shown}: {detail}"),
            "{stdout}"
        );
        if sent {
            assert!(
                last[1].starts_with("host-stop-controller: the target reads {")
                    || last[1].starts_with("host-stop-controller: the target's state is unknown: "),
                "{stdout}"
            );
        }
        assert_eq!(
            last[count - 1],
            format!("GD-2's restoration steps: {}", steps()),
            "{stdout}"
        );
        let marks = self.marks();
        for line in self.stderr().lines() {
            let named = ["abort", "stopped"].iter().any(|name| {
                let unwritten = format!("host-stop-controller: {name}.json is unwritten: ");
                let stands = format!(
                    "host-stop-controller: {name}.json stands with its durability unknown: "
                );
                (line.starts_with(&unwritten) && !marks.contains_key(*name))
                    || (line.starts_with(&stands) && marks.contains_key(*name))
            });
            assert!(named, "{line}");
        }
    }
}

/// The sorted names of the entries of `root` itself.
pub(crate) fn listing_top(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root)
        .expect("the directory lists")
        .map(|entry| {
            entry
                .expect("the directory lists")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The text of a string value.
pub(crate) fn plain(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_string(),
        other => panic!("{other:?} is a string"),
    }
}

pub(crate) use crate::host_stop_support::set;

/// The member `key` of the object `value`.
pub(crate) fn member<'v>(value: &'v Value, key: &str) -> &'v Value {
    match value {
        Value::Object(object) => object
            .get(key)
            .unwrap_or_else(|| panic!("{key} in {object:?}")),
        other => panic!("{other:?} is an object"),
    }
}

/// The fixture's decoded operator file's member `key` of the object `value`, as a text.
pub(crate) fn text_of(value: &Value, key: &str) -> String {
    plain(member(value, key))
}

impl Case {
    /// Runs `step` on a controller over this case's plane, file steps and record, made from the
    /// case's catalog and operator file with no step taken.
    pub(crate) fn controlled<T>(
        &mut self,
        step: impl FnOnce(&mut Controller<'_, '_, Plane, Steps>) -> T,
    ) -> T {
        self.owned(|mut controller| step(&mut controller))
    }

    /// Runs `step` on a controller as [`Case::controlled`] makes it, handing the controller over.
    pub(crate) fn owned<T>(
        &mut self,
        step: impl FnOnce(Controller<'_, '_, Plane, Steps>) -> T,
    ) -> T {
        let catalog = value(&fs::read_to_string(&self.catalog).expect("the catalog reads"));
        let gd2 = gd2_of(&catalog).expect("GD-2 is the one written for");
        let operator =
            read_operator(&self.write_operator(), &gd2, FILE_LIMIT).expect("the operator file");
        self.in_context(|cx| {
            let mut written = Vec::new();
            step(Controller::new(cx, &mut written, &operator, gd2))
        })
    }

    /// Delivers `signal` into the case's record at each step `when` names, once.
    pub(crate) fn signal_at(
        &self,
        signal: Signal,
        mut when: impl FnMut(&Step<'_>) -> bool + 'static,
    ) {
        let delivered = self.delivered;
        let mut sent = false;
        self.plant(Box::new(move |_, step| {
            if !sent && when(step) {
                sent = true;
                delivered.deliver(signal);
            }
            None
        }));
    }

    /// Fails the first step `when` names with the system error `code`.
    pub(crate) fn fail_once(&self, code: i32, mut when: impl FnMut(&Step<'_>) -> bool + 'static) {
        let mut failed = false;
        self.plant(Box::new(move |_, step| {
            (!failed && when(step)).then(|| {
                failed = true;
                steps::errno(code)
            })
        }));
    }

    /// Plants `action` on the first alarm read after the stop is shown, or, with `while_stopping`,
    /// after the stop request and before the record read.
    pub(crate) fn faulted(&self, action: Action, while_stopping: bool) {
        let mut action = Some(action);
        self.plane.borrow_mut().fault = Some(Box::new(move |state, op| {
            if op != ALARMS || state.stops().is_empty() || state.shown() == while_stopping {
                return None;
            }
            action.take()
        }));
    }

    pub(crate) fn fault_index(&self) -> usize {
        self.plane.borrow().fault_index()
    }

    /// Each call after the one the fault marked.
    pub(crate) fn after_fault(&self) -> Vec<String> {
        self.plane.borrow().after_fault()
    }
}

/// The variable that tells a test executable started again by [`child`] to run its case's body.
pub(crate) const CHILD: &str = "HOST_STOP_CONTROLLER_CHILD";

/// Runs the case `name` of this module again in a process of its own, with an environment that
/// holds [`CHILD`] set to `place`, `TMPDIR` and `extra` alone, and returns its exit status and its
/// output.
pub(crate) fn child(
    name: &str,
    place: &Path,
    extra: &[(&str, &str)],
) -> (std::process::ExitStatus, String) {
    let case = format!("host_stop_controller::{name}");
    let output = std::process::Command::new(std::env::current_exe().expect("the test executable"))
        .args(["--exact", &case, "--nocapture", "--test-threads", "1"])
        .env_clear()
        .env(CHILD, place)
        .env("TMPDIR", place)
        .envs(extra.iter().copied())
        .output()
        .expect("the test executable starts again");
    let shown = format!(
        "{}\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status, shown)
}
