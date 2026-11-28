//! After the operator starts the target again, `restore` checks the marks a run left, polls the
//! target until a read shows it running again, and writes `restoration.json` once.
//!
//! `restore` names the evidence by the pathname `DIR/injection` and trusts the operator to keep that
//! directory under that name until `restore` returns.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::context::{Stream, beside, pure, seconds};
use super::controller::Controller;
use super::fault::{Fault, Halt};
use super::run::{TOOL, lock_sentence, probe_refusal, shown_path};
use crate::host_stop::{
    Files, Number, Request, SKEW_SECONDS, Seam, check_reviewed, check_stopped, instance_id,
    launch_time, lock, probe, read_json, stands,
};
use crate::json::{Object, Value};
use crate::plants::files::strerror;
use crate::python::{repr, repr_float};
use crate::text::Text;

impl<S: Seam, F: Files> Controller<'_, '_, S, F> {
    /// `restore` returns 0 when it writes `restoration.json`, and 1 with no mark after a signal from
    /// the caller check on, a poll that reaches its bound, or a failed write.
    ///
    /// # Errors
    ///
    /// `restore` returns the first refusal in check order.
    pub fn restore(&mut self, evidence: &OsStr, reviewed: Option<&Path>) -> Result<u8, Halt> {
        if evidence.is_empty() {
            return Err(refused("no evidence directory is named"));
        }
        let start = self.wall();
        let root = pure(evidence.as_bytes());
        let injection = beside(&root, "injection");
        if !directory(&root) {
            let mut sentence = Text::from_os(evidence);
            sentence.push_str(" is no directory");
            return Err(Halt::refused(sentence));
        }
        if !directory(&injection) {
            let mut sentence = shown_path(&injection);
            sentence.push_str(" is no directory: no stop to restore from");
            return Err(Halt::refused(sentence));
        }
        probe(self.cx.files, &injection).map_err(|error| probe_refusal(&injection, &error))?;
        let limit = self.cx.file_limit;
        let what = Text::from("injection/stop.json");
        let stop = read_json(&beside(&injection, "stop.json"), &what, limit)?;
        let stop = Request::checked(&stop, &what)?;
        if self.stands_in(&injection, "restoration.json")? {
            return Err(refused(
                "injection/restoration.json exists: the restoration is written once",
            ));
        }
        let what = Text::from("injection/stop.json instance");
        let instance = instance_id(&Value::String(stop.instance().clone()), &what)?;
        if !self.operator.instances().contains(&instance) {
            let mut sentence = Text::from("the stop's instance ");
            sentence.push_text(&instance);
            sentence.push_str(" is outside the declared set");
            return Err(Halt::refused(sentence));
        }
        let approval = self.operator.approval();
        if instance != *approval.instance() || stop.identity() != self.operator.identity() {
            return Err(refused(
                "injection/stop.json names another instance or identity than the approval's \
                 target and the operator's",
            ));
        }
        self.instance = Some(instance.clone());
        let _held = lock(self.cx.files, &injection)
            .map_err(|error| Halt::refused(lock_sentence(&injection, &error)))?;
        let shown = self.stands_in(&injection, "stopped.json")?;
        let aborted = self.stands_in(&injection, "abort.json")?;
        if !(aborted || shown) {
            return Err(refused(
                "the run ended with neither stopped.json nor abort.json, so its outcome is \
                 unknown and restore records nothing; follow GD-2's restoration steps",
            ));
        }
        let what = Text::from("injection/roles.json");
        let roles = read_json(&beside(&injection, "roles.json"), &what, limit)?;
        if !names_package(&roles, approval.package_sha256()) {
            return Err(refused(
                "injection/roles.json names another package than the approval's",
            ));
        }
        if self.stands_in(&injection, "collected.json")? {
            return Err(refused(
                "injection/collected.json stands, and this restore reads no sealed evidence",
            ));
        }
        let now = Number::from(start);
        let stopped_at = if shown {
            let path = beside(&injection, "stopped.json");
            Some(check_stopped(&path, &stop, now, limit)?)
        } else {
            None
        };
        let (reviewed_sha256, aborted_at) = if aborted {
            let path = beside(&injection, "abort.json");
            let (digest, at) =
                check_reviewed(reviewed, &path, Path::new(evidence), now, &stop, limit)?;
            let line = Text::from(format!("{TOOL}reviewed record sha256 {digest}"));
            self.cx.say(Stream::Out, &line);
            (Value::String(Text::from(digest)), Some(at))
        } else {
            if reviewed.is_some() {
                return Err(refused(
                    "--reviewed names a review of an abort, and no abort stands",
                ));
            }
            (Value::Null, None)
        };
        // For ties at the latest time, `floor` keeps the first value in this order: the stop's
        // time, the stopped report's, the abort's.
        let mut floor = stop.time();
        for at in [stopped_at, aborted_at].into_iter().flatten() {
            if at > floor {
                floor = at;
            }
        }
        self.injection = Some(injection);
        let mut seen = Text::from("no status read was made");
        self.cx.record.arm();
        let polled = self.poll(&instance, start, floor, stopped_at, &mut seen);
        self.cx.record.disarm();
        self.deadline = None;
        let ready = match polled {
            Ok(ready) => ready,
            Err(Halt::Aborted(bound)) => {
                seen.push_str("; ");
                seen.push_text(bound.detail());
                None
            }
            Err(Halt::Interrupted(raised)) => {
                let mut line = Text::from(format!(
                    "{TOOL}signal {raised}: the restoration is unwritten: "
                ));
                line.push_text(&seen);
                self.cx.say(Stream::Out, &line);
                return Ok(1);
            }
            Err(other) => return Err(other),
        };
        let Some(ready) = ready else {
            let mut line = Text::from(format!(
                "{TOOL}the restoration was not shown within {} s, so it is unrecorded and the \
                 evidence is not to be judged as it stands: ",
                self.operator.deadline_seconds()
            ));
            line.push_text(&seen);
            self.cx.say(Stream::Out, &line);
            return Ok(1);
        };
        self.restoration(&instance, ready, reviewed_sha256)
    }

    fn poll(
        &mut self,
        instance: &Text,
        start: f64,
        floor: Number,
        stopped_at: Option<Number>,
        seen: &mut Text,
    ) -> Result<Option<Number>, Halt> {
        self.cx.record.read()?;
        self.require_caller()?;
        let deadline = self.monotonic() + seconds(self.operator.deadline_seconds());
        self.deadline = Some(deadline);
        while self.monotonic() < deadline {
            match self.ready_read(instance, start, floor, stopped_at, seen) {
                Ok(Some(ready)) => return Ok(Some(ready)),
                Ok(None) => {}
                Err(Halt::Failed(failed)) => {
                    *seen = Text::from("a read failed: ");
                    seen.push_text(&failed.sentence());
                }
                Err(other) => return Err(other),
            }
            self.pause(deadline)?;
        }
        Ok(None)
    }

    fn ready_read(
        &mut self,
        instance: &Text,
        start: f64,
        floor: Number,
        stopped_at: Option<Number>,
        seen: &mut Text,
    ) -> Result<Option<Number>, Halt> {
        let states = self.statuses(std::slice::from_ref(instance), None)?;
        let status = states.get(instance).expect("the statuses name the target");
        let at = self.wall();
        *seen = Text::from(format!("the target reads {}", repr(&status.to_value())));
        let ok = |check: Option<&Text>| check.is_some_and(|check| *check == "ok");
        if !(*status.state() == "running" && ok(status.instance()) && ok(status.system())) {
            return Ok(None);
        }
        if at < start {
            seen.push_str(&format!(
                " at {}, before restore's start {}",
                repr_float(at),
                repr_float(start)
            ));
            return Ok(None);
        }
        let (ready, shown) = self.dated(instance, at, floor, stopped_at)?;
        if let Some(shown) = shown {
            *seen = shown;
        }
        Ok(ready)
    }

    /// `dated` returns `(Some(time), None)` when the record supports a restoration time for the
    /// ready read at wall reading `at`, and `(None, Some(reason))` when it does not. The time is
    /// the record's `LaunchTime` less [`SKEW_SECONDS`], at least `floor`.
    fn dated(
        &mut self,
        instance: &Text,
        at: f64,
        floor: Number,
        stopped_at: Option<Number>,
    ) -> Result<(Option<Number>, Option<Text>), Halt> {
        let record = self.record(instance, None)?;
        let launch = launch_time(record.launch()).map_err(Halt::Failed)?;
        if *record.state() != "running" {
            let mut shown = Text::from("the target's record reads ");
            shown.push_text(record.state());
            return Ok((None, Some(shown)));
        }
        let skew = Number::from(SKEW_SECONDS);
        if let Some(stopped_at) = stopped_at
            && launch.plus(skew) < stopped_at
        {
            let shown = format!(
                "the target's record dates its last launch at {launch}, more than {SKEW_SECONDS} s \
                 before the stopped report at {stopped_at}, so it shows no start after the stop"
            );
            return Ok((None, Some(Text::from(shown))));
        }
        if launch.minus(skew) > Number::from(at) {
            let shown = format!(
                "the target's record dates its last launch at {launch}, more than {SKEW_SECONDS} s \
                 after the read at {} that shows it running",
                repr_float(at)
            );
            return Ok((None, Some(Text::from(shown))));
        }
        let earliest = launch.minus(skew);
        Ok((Some(if earliest > floor { earliest } else { floor }), None))
    }

    fn restoration(&mut self, instance: &Text, ready: Number, reviewed: Value) -> Result<u8, Halt> {
        let mut mark = Object::new();
        mark.insert("instance", Value::String(instance.clone()));
        mark.insert("state", Value::String(Text::from("running")));
        mark.insert("time", ready.value());
        mark.insert("reviewed_sha256", reviewed);
        let mut line = Text::from(TOOL);
        match self.mark("restoration", &Value::Object(mark)) {
            Ok(()) => {}
            Err(Halt::Fault(Fault::Unwritten(sentence))) => {
                line.push_text(&sentence);
                self.cx.say(Stream::Err, &line);
                return Ok(1);
            }
            Err(Halt::Fault(Fault::Os { code, text })) => {
                line.push_str("restoration.json is unwritten: ");
                line.push_str(&errno_text(code, &text));
                self.cx.say(Stream::Err, &line);
                return Ok(1);
            }
            Err(Halt::Fault(Fault::Refusal(sentence))) => return Err(Halt::refused(sentence)),
            Err(other) => return Err(other),
        }
        line.push_text(instance);
        line.push_str(" runs again with both status checks ok");
        self.cx.say(Stream::Out, &line);
        Ok(0)
    }

    fn stands_in(&self, injection: &Path, name: &str) -> Result<bool, Halt> {
        stands(self.cx.files, &beside(injection, name)).map_err(|error| {
            Halt::refused(Text::from(format!(
                "injection/{name} cannot be looked up: {}",
                strerror(&error)
            )))
        })
    }
}

fn refused(sentence: &str) -> Halt {
    Halt::refused(Text::from(sentence))
}

fn directory(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|found| found.is_dir())
        && !fs::symlink_metadata(path).is_ok_and(|found| found.file_type().is_symlink())
}

fn names_package(roles: &Value, digest: &Text) -> bool {
    matches!(roles, Value::Object(roles)
        if matches!(roles.get("package_sha256"), Some(Value::String(named)) if named == digest))
}

fn errno_text(code: Option<i32>, text: &str) -> String {
    match code {
        Some(code) => format!("[Errno {code}] {text}"),
        None => text.to_owned(),
    }
}
