//! Each restore uses the case's plane for command responses and its clock for timestamps.

use std::cell::{Cell, RefCell};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use kestrike_tools::gameday::FILE_LIMIT;
use kestrike_tools::host_stop::{Delivered, Disk, Record};
use kestrike_tools::host_stop_controller::{Command, Context, entry};
use kestrike_tools::json::{Object, Value};
use kestrike_tools::python::hexdigest;

use super::plane::{Action, Plane, STATUS, State, string};
use super::stop_run::time;
use super::{Case, Output, listing, steps};
use crate::host_stop_support::{TARGET, json, tree};

impl Case {
    pub(crate) fn restore(&mut self, reviewed: Option<&Path>) -> u8 {
        let evidence = self.evidence.clone();
        let calls = self.log().len();
        let code = self.restore_at(&evidence, reviewed);
        if code == 0 {
            let restored = time(&self.marks()["restoration"]);
            let ready = self.plane.borrow().log[calls..]
                .iter()
                .rev()
                .find(|logged| logged.op == STATUS)
                .and_then(|logged| logged.wall)
                .expect("a status read answered");
            assert!(self.floor() <= restored, "{restored} {:?}", self.marks());
            assert!(restored <= ready, "{restored} after the ready read {ready}");
        }
        code
    }

    /// Plants `action` on the first call `op` in place of that call's scripted action, whose later
    /// entries stay, and marks that call as the fault.
    pub(crate) fn fault_first(&self, op: &'static str, action: Action) {
        let mut planted = Some(action);
        self.plane.borrow_mut().fault =
            Some(Box::new(
                move |_, called| {
                    if called == op { planted.take() } else { None }
                },
            ));
    }

    pub(crate) fn floor(&self) -> f64 {
        let marks = self.marks();
        ["stop", "stopped", "abort"]
            .iter()
            .filter_map(|name| marks.get(*name).map(time))
            .fold(f64::NEG_INFINITY, f64::max)
    }

    pub(crate) fn start_target(&self, initializing: usize) {
        let mut plane = self.plane.borrow_mut();
        let t = plane.t;
        let target = plane.instances.get_mut(TARGET).expect("the target");
        target.state = "running".to_owned();
        target.transition = String::new();
        target.reason = None;
        target.checks = "initializing".to_owned();
        target.launched = t;
        plane.stopping = None;
        let reads = Rc::new(Cell::new(0));
        let ready: Vec<Action> = (0..initializing + 2)
            .map(|_| {
                let reads = Rc::clone(&reads);
                Action::Hook(Box::new(move |state: &mut State| {
                    if reads.get() >= initializing {
                        let target = state.instances.get_mut(TARGET).expect("the target");
                        target.checks = "ok".to_owned();
                    }
                    reads.set(reads.get() + 1);
                    Action::Answer
                }))
            })
            .collect();
        plane.script(STATUS, ready);
    }

    pub(crate) fn review(&self) -> Value {
        let abort = fs::read(self.evidence.join("injection/abort.json")).expect("abort.json reads");
        let mut review = Object::new();
        review.insert("abort_sha256", string(&hexdigest(&abort)));
        review.insert("steps", string(&steps()));
        review.insert("reviewer", string("the operator"));
        review.insert("time", Value::Float(self.plane.borrow().wall()));
        Value::Object(review)
    }

    pub(crate) fn aborted_run(&mut self) -> (PathBuf, Value) {
        self.plane.borrow_mut().stop_after = None;
        assert_eq!(self.run(), 1, "{}", self.output());
        self.start_target(0);
        (self.scratch.0.join("reviewed.json"), self.review())
    }

    /// A refused `restore` exits with code 2, includes `reason` in the output from that invocation,
    /// and preserves both the call count and the evidence directory listing.
    pub(crate) fn assert_restore_refused(&mut self, reviewed: Option<&Path>, reason: &str) {
        let (start, before, seen) = (
            self.log().len(),
            listing(&self.evidence),
            self.output().len(),
        );
        let code = self.restore(reviewed);
        let output = self.output();
        assert_eq!(code, 2, "{output}");
        assert!(
            output[seen..].contains(reason),
            "{reason:?} in {}",
            &output[seen..]
        );
        assert_eq!(self.ops()[start..], [] as [String; 0], "{output}");
        assert_eq!(listing(&self.evidence), before, "{output}");
    }
}

pub(crate) fn write_json(path: &Path, value: &Value) {
    fs::write(path, dumps(value)).expect("the file is written");
}

/// `dumps` writes Python's `json.dumps(value)`: members in document order, `, ` between items
/// and `: ` after a key.
pub(crate) fn dumps(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let members: Vec<String> = object
                .iter()
                .map(|(key, member)| {
                    format!("{}: {}", json(&Value::String(key.clone())), dumps(member))
                })
                .collect();
            format!("{{{}}}", members.join(", "))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(dumps).collect();
            format!("[{}]", items.join(", "))
        }
        scalar => json(scalar),
    }
}

pub(crate) fn replace_mark(injection: &Path, name: &str, value: &Value) {
    let path = injection.join(name);
    fs::remove_file(&path).expect("the mark is removed");
    write_json(&path, value);
}

pub(crate) fn digest(path: &Path) -> String {
    hexdigest(&fs::read(path).expect("the file reads"))
}

/// `restore_alone` takes paths alone, so a case can run it on another thread or inside a call of
/// the case's plane. Each invocation creates a fresh `State` and uses `Disk` for file steps.
pub(crate) fn restore_alone(
    operator: &Path,
    catalog: &Path,
    evidence: &Path,
    reviewed: Option<&Path>,
) -> (u8, String, Vec<String>) {
    let state = State::new(
        0.0,
        evidence.to_path_buf(),
        "us-west-2",
        "arn",
        &[TARGET.to_owned()],
        &[],
    );
    let shared = Rc::new(RefCell::new(state));
    let mut seam = Plane(Rc::clone(&shared));
    let delivered: &'static Delivered = Box::leak(Box::new(Delivered::new()));
    let mut record = Record::new(delivered);
    let output = Output::default();
    let (mut out, mut err) = (output.clone(), output.clone());
    let env = vec![(OsString::from("PATH"), OsString::from("/nonexistent"))];
    let top = tree();
    let mut cx = Context {
        seam: &mut seam,
        files: &Disk,
        record: &mut record,
        env: &env,
        out: &mut out,
        err: &mut err,
        catalog,
        top: &top,
        file_limit: FILE_LIMIT,
        mark_limit: FILE_LIMIT,
    };
    let command = Command::Restore {
        operator: operator.to_path_buf(),
        evidence: evidence.as_os_str().to_owned(),
        reviewed: reviewed.map(Path::to_path_buf),
    };
    let code = entry(&command, &mut cx);
    let ops = shared.borrow().ops();
    (code, output.text(), ops)
}
