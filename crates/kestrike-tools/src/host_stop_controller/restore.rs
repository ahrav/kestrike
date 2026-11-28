//! After the operator starts the target again, `restore` checks the marks a run left, polls the
//! target until a read shows it running again, and writes `restoration.json` once.
//!
//! `restore` names the evidence by the pathname `DIR/injection` and trusts the operator to keep that
//! directory under that name until `restore` returns.

use std::cmp::Ordering;
use std::ffi::OsStr;
use std::path::Path;

use super::checks::{check_roles, other_package, read_halt, refused};
use super::context::{Stream, beside, seconds};
use super::controller::{Controller, window};
use super::fault::Halt;
use super::run::{TOOL, lock_sentence};
use crate::gameday::{ends_observation, read_evidence};
use crate::host_stop::{
    Files, Number, Request, SKEW_SECONDS, Seam, check_reviewed, check_stopped, instance_id,
    launch_time, lock, read_json,
};
use crate::json::{Object, Value};
use crate::python::{repr, repr_float};
use crate::text::Text;

/// The times a ready read is dated against: restore's start, a wall reading; the latest time among
/// the stop, the stopped report and the abort; and the stopped report's time where one stands.
#[derive(Clone, Copy)]
struct Times {
    start: f64,
    floor: Number,
    stopped_at: Option<Number>,
}

impl<S: Seam, F: Files> Controller<'_, '_, S, F> {
    /// A return of 0 means `restore` wrote `restoration.json`. It returns 1 and writes no mark after
    /// a signal in the caller check or the poll, or a poll that reaches its bound. It returns 1
    /// after a write that fails: a failure through the link leaves the name as it found it, so an
    /// entry found at the link keeps its bytes and a later `restore` refuses it; a sync that fails
    /// after the link leaves the mark removed with the removal synced, removed with the removal
    /// unsynced, so the mark may stand again after a crash, or standing whole with its durability
    /// unknown, as the line on stderr says. Where `injection/collected.json` stands, `restore`
    /// first reads the evidence as the judge does, and returns 1 after writing a restoration that
    /// ends observation; that mark stands.
    ///
    /// A panic in the armed span or the mark's write unwinds out of `restore` and can leave the
    /// record armed or held and the poll's deadline set; [`entry`](super::entry) disarms the record
    /// and ends its hold.
    ///
    /// # Errors
    ///
    /// `restore` returns the first refusal in check order, and [`Halt::Fault`] for a failed close
    /// of a file its sealed branch reads or a failed write the mark does not word.
    pub fn restore(&mut self, evidence: &OsStr, reviewed: Option<&Path>) -> Result<u8, Halt> {
        if evidence.is_empty() {
            return Err(refused("no evidence directory is named"));
        }
        let start = self.wall();
        let (root, injection) = self.evidence_dirs(evidence, "no stop to restore from")?;
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
        check_roles(&roles, approval.package_sha256())?;
        let sealed = if self.stands_in(&injection, "collected.json")? {
            Some(self.sealed(&root)?)
        } else {
            None
        };
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
        let times = Times {
            start,
            floor,
            stopped_at,
        };
        self.injection = Some(injection);
        let mut seen = Text::from("no status read was made");
        let polled = self.armed(|c| c.poll(&instance, times, &mut seen));
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
        let code = self.write_restoration(&instance, ready, reviewed_sha256)?;
        if code != 0 {
            return Ok(code);
        }
        if let Some(p) = sealed
            && ends_observation(&p, Some(&ready.value()))
        {
            let end = window(&p, "run").1;
            let line = format!(
                "{TOOL}the restoration dates {ready}, less than the clock error after the run \
                 window's end {end}, and the seal does not name it, so the judge refuses this \
                 evidence while the mark stands"
            );
            self.cx.say(Stream::Out, &Text::from(line));
            return Ok(1);
        }
        let mut line = Text::from(TOOL);
        line.push_text(&instance);
        line.push_str(" runs again with both status checks ok");
        self.cx.say(Stream::Out, &line);
        Ok(0)
    }

    /// The approved package of a sealed run: the evidence directory at `root` as the judge's
    /// [`read_evidence`] admits it, with `package.json` of the approval's digest. Only the package
    /// is kept: the checks that follow read `stopped.json` and `abort.json` again by name, so the
    /// floor and the review rest on those reads and not on the bytes the load verified. The load
    /// drops a failed close of a directory it opened.
    fn sealed(&mut self, root: &Path) -> Result<Object, Halt> {
        let bounds = self.bounds()?;
        let evidence = read_evidence(root, self.cx.file_limit, &bounds).map_err(read_halt)?;
        if *self.operator.approval().package_sha256() != evidence.package_sha256() {
            return Err(other_package());
        }
        Ok(evidence.into_package())
    }

    fn poll(
        &mut self,
        instance: &Text,
        times: Times,
        seen: &mut Text,
    ) -> Result<Option<Number>, Halt> {
        self.cx.record.release()?;
        self.deadline = None;
        self.require_caller()?;
        let deadline = self.monotonic() + seconds(self.operator.deadline_seconds());
        self.deadline = Some(deadline);
        while self.monotonic() < deadline {
            match self.ready_read(instance, times, seen) {
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
        times: Times,
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
        // A reading that does not compare at or after the start, NaN included, leads to another
        // poll.
        if !matches!(
            at.partial_cmp(&times.start),
            Some(Ordering::Greater | Ordering::Equal)
        ) {
            seen.push_str(&format!(
                " at {}, before restore's start {}",
                repr_float(at),
                repr_float(times.start)
            ));
            return Ok(None);
        }
        match self.dated(instance, at, times)? {
            Ok(ready) => Ok(Some(ready)),
            Err(shown) => {
                *seen = shown;
                Ok(None)
            }
        }
    }

    /// For the ready read at wall reading `at`, `dated` returns `Ok(Err(reason))` when the record
    /// provides insufficient evidence to establish a restoration time. When the record establishes
    /// a time, `dated` returns `Ok(Ok(time))`, where `time` is the greater of `times.floor` and
    /// the record's `LaunchTime` minus [`SKEW_SECONDS`].
    fn dated(
        &mut self,
        instance: &Text,
        at: f64,
        times: Times,
    ) -> Result<Result<Number, Text>, Halt> {
        let record = self.instance_record(instance, None)?;
        let launch = launch_time(record.launch()).map_err(Halt::Failed)?;
        if *record.state() != "running" {
            let mut shown = Text::from("the target's record reads ");
            shown.push_text(record.state());
            return Ok(Err(shown));
        }
        let skew = Number::from(SKEW_SECONDS);
        if let Some(stopped_at) = times.stopped_at
            && launch.plus(skew) < stopped_at
        {
            let shown = format!(
                "the target's record dates its last launch at {launch}, more than {SKEW_SECONDS} s \
                 before the stopped report at {stopped_at}, so it shows no start after the stop"
            );
            return Ok(Err(Text::from(shown)));
        }
        if launch.minus(skew) > Number::from(at) {
            let shown = format!(
                "the target's record dates its last launch at {launch}, more than {SKEW_SECONDS} s \
                 after the read at {} that shows it running",
                repr_float(at)
            );
            return Ok(Err(Text::from(shown)));
        }
        let earliest = launch.minus(skew);
        Ok(Ok(if earliest > times.floor {
            earliest
        } else {
            times.floor
        }))
    }

    fn write_restoration(
        &mut self,
        instance: &Text,
        ready: Number,
        reviewed: Value,
    ) -> Result<u8, Halt> {
        let mut mark = Object::new();
        mark.insert("instance", Value::String(instance.clone()));
        mark.insert("state", Value::String(Text::from("running")));
        mark.insert("time", ready.value());
        mark.insert("reviewed_sha256", reviewed);
        match self.mark("restoration", &Value::Object(mark)) {
            Ok(()) => Ok(0),
            Err(failed) => {
                self.failed_write("restoration.json", failed)?;
                Ok(1)
            }
        }
    }
}
