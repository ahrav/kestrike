//! One run's state and the steps every phase of a run takes: a call through its one path, the
//! deadline's check, the alarms' quiet read, the check before the stop request, the pause between
//! polls and a mark's write.
//!
//! The deadline and each `until` a step takes are monotonic readings; the package's windows, the
//! snapshot's times, the request's time and each mark's time are wall readings in POSIX seconds. A
//! call reads the record before it starts, ahead of every bound it checks, and once it returns, so a
//! signal that stands then ends the step before the call or before its reply or failure is used. It
//! checks the deadline before it starts and once it returns. A mark's write reads the record, then
//! holds it from before its first file step to its end, and reads it again at its end when the
//! write succeeds; a write that fails keeps its failure and leaves a signal stored.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::context::{Context, beside, seconds};
use super::fault::{Fault, Halt};
use crate::gameday::{Names, conform, layout};
use crate::host_stop::{
    Alarm, CALL_SECONDS, Call, CallError, FailedCall, Files, Gd2, InstanceRecord, MISSING_DATA,
    Number, Operator, POLL_SECONDS, SKEW_SECONDS, Seam, Status, caller_arn, encoded, iso_time,
    publish, read_alarms, read_record, read_statuses, reply,
};
use crate::json::{Object, Value};
use crate::python::{repr, repr_float};
use crate::text::Text;

/// What the first three steps read for the check before the stop request: the admitted package,
/// the snapshot's cut and its oldest time, the wall and monotonic readings at the run's start, and
/// the monotonic reading at which the snapshot passes its age bound.
#[derive(Clone, Debug)]
pub struct Preflight {
    package: Object,
    cut: Number,
    oldest: Number,
    origin: (f64, f64),
    fresh_until: f64,
}

impl Preflight {
    pub fn new(
        package: Object,
        cut: Number,
        oldest: Number,
        origin: (f64, f64),
        fresh_until: f64,
    ) -> Self {
        Self {
            package,
            cut,
            oldest,
            origin,
            fresh_until,
        }
    }

    pub(crate) fn package(&self) -> &Object {
        &self.package
    }
}

/// Which call [`Controller::aws`] makes: a read, with the CLI's retries on, or the stop request, with
/// them off, which counts as sent and keeps its times, its answer and its failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Read,
    Stop,
}

/// One run under one operator file and GD-2's admitted entry. `written` lists each mark that
/// stands, a mark that stands with its durability unknown included; the caller owns it, so it
/// outlives a panic that ends the run.
pub struct Controller<'c, 'a, S: Seam, F: Files> {
    pub(crate) cx: &'c mut Context<'a, S, F>,
    pub(crate) written: &'c mut Vec<&'static str>,
    pub(crate) operator: &'c Operator,
    pub(crate) gd2: Gd2<'c>,
    pub(crate) deadline: Option<f64>,
    pub(crate) preflight: Option<Preflight>,
    pub(crate) injection: Option<PathBuf>,
    pub(crate) instance: Option<Text>,
    pub(crate) transitions: Option<BTreeMap<Text, Text>>,
    pub(crate) shown: Option<Value>,
    pub(crate) stop_failure: Option<Text>,
    pub(crate) request_at: Option<f64>,
    pub(crate) launched: Option<f64>,
    pub(crate) returned: Option<f64>,
    pub(crate) sent: bool,
    pub(crate) answered: bool,
}

impl<'c, 'a, S: Seam, F: Files> Controller<'c, 'a, S, F> {
    pub fn new(
        cx: &'c mut Context<'a, S, F>,
        written: &'c mut Vec<&'static str>,
        operator: &'c Operator,
        gd2: Gd2<'c>,
    ) -> Self {
        Self {
            cx,
            written,
            operator,
            gd2,
            deadline: None,
            preflight: None,
            injection: None,
            instance: None,
            transitions: None,
            shown: None,
            stop_failure: None,
            request_at: None,
            launched: None,
            returned: None,
            sent: false,
            answered: false,
        }
    }

    /// Sets what the first three steps read, for a caller that runs a later step alone.
    pub fn set_preflight(&mut self, preflight: Preflight) {
        self.preflight = Some(preflight);
    }

    /// Sets the run's deadline, a monotonic reading.
    pub fn set_deadline(&mut self, deadline: f64) {
        self.deadline = Some(deadline);
    }

    /// Sets the directory the marks are written in.
    pub fn set_injection(&mut self, injection: &Path) {
        self.injection = Some(injection.to_path_buf());
    }

    pub fn written(&self) -> &[&'static str] {
        self.written
    }

    pub(crate) fn wall(&self) -> f64 {
        self.cx.seam.wall()
    }

    pub(crate) fn monotonic(&self) -> f64 {
        self.cx.seam.monotonic()
    }

    pub(crate) fn within_deadline(&self) -> Result<(), Halt> {
        match self.deadline {
            Some(deadline) if self.monotonic() >= deadline => Err(Halt::aborted(
                "deadline",
                None,
                Text::from(format!(
                    "the deadline of {} s passed",
                    self.operator.deadline_seconds()
                )),
            )),
            _ => Ok(()),
        }
    }

    /// One call of `argv` with `--region`, whose timeout is the least of [`CALL_SECONDS`], the time
    /// left before the deadline when one is set and the time left before `until`, a monotonic
    /// reading, when one is given. The deadline is checked before the call and after it returns or
    /// fails. The record is read first, before the deadline's check, so a signal that stands then
    /// ends the step with no call made, and again when the call returns, so a signal raised then
    /// comes before its reply or failure. The stop request ([`Kind::Stop`]) reads its launch time and
    /// the record once more and then counts as sent: from there a launch that starts no child counts
    /// as sent too. It reads its return time and the record again before its answer or its failure
    /// is kept; a second stop request is a failure the controller names.
    pub(crate) fn aws(
        &mut self,
        argv: &[&str],
        until: Option<f64>,
        kind: Kind,
    ) -> Result<Object, Halt> {
        let mutating = kind == Kind::Stop;
        if mutating && self.sent {
            return Err(Halt::order("a second stop request was asked for"));
        }
        self.cx.record.read()?;
        self.within_deadline()?;
        let mut timeout = CALL_SECONDS as f64;
        for end in [self.deadline, until].into_iter().flatten() {
            timeout = timeout.min(end - self.monotonic());
        }
        if timeout <= 0.0 {
            let what = argv[..argv.len().min(2)].join(" ");
            return Err(Halt::Failed(FailedCall::Reply(Text::from(format!(
                "{what} has no time left before its window ends"
            )))));
        }
        if mutating {
            let launched = self.monotonic();
            self.cx.record.read()?;
            self.sent = true;
            self.launched = Some(launched);
        }
        let region = self
            .operator
            .region()
            .to_str()
            .expect("a region name is ASCII");
        let mut full = argv.to_vec();
        full.extend(["--region", region]);
        let call = Call {
            argv: &full,
            retry: !mutating,
            cut: at_least(timeout),
            env: self.cx.env,
        };
        let answer = reply(&mut *self.cx.seam, self.cx.record, &call);
        let mut raised = self.cx.record.read();
        if mutating {
            self.returned = Some(self.monotonic());
            raised = raised.and_then(|()| self.cx.record.read());
        }
        match (answer, raised) {
            (_, Err(raised)) | (Err(CallError::Interrupted(raised)), Ok(())) => {
                Err(Halt::Interrupted(raised))
            }
            (Err(CallError::Failed(failed)), Ok(())) => {
                if mutating {
                    self.stop_failure = Some(failed.sentence());
                }
                self.within_deadline()?;
                Err(Halt::Failed(failed))
            }
            (Ok(object), Ok(())) => {
                if mutating {
                    self.answered = true;
                }
                self.within_deadline()?;
                Ok(object)
            }
        }
    }

    pub(crate) fn statuses(
        &mut self,
        instances: &[Text],
        until: Option<f64>,
    ) -> Result<BTreeMap<Text, Status>, Halt> {
        let mut argv = vec![
            "ec2",
            "describe-instance-status",
            "--include-all-instances",
            "--instance-ids",
        ];
        argv.extend(instances.iter().map(ascii));
        let reply = self.aws(&argv, until, Kind::Read)?;
        read_statuses(&reply, instances).map_err(Halt::Failed)
    }

    pub(crate) fn instance_record(
        &mut self,
        instance: &Text,
        until: Option<f64>,
    ) -> Result<InstanceRecord, Halt> {
        let argv = [
            "ec2",
            "describe-instances",
            "--instance-ids",
            ascii(instance),
        ];
        let reply = self.aws(&argv, until, Kind::Read)?;
        read_record(&reply, instance).map_err(Halt::Failed)
    }

    /// The guardrail alarms' read, the names asked in GD-2's order, cut at `until`, a monotonic
    /// reading.
    ///
    /// # Errors
    ///
    /// The call's end, or its reply off the shape the reader takes as a failed call.
    pub fn alarms(&mut self, until: Option<f64>) -> Result<BTreeMap<Text, Alarm>, Halt> {
        let names: Vec<Text> = self
            .gd2
            .guardrails()
            .into_iter()
            .map(|text| self.alarm_of(text).clone())
            .collect();
        let mut argv = vec![
            "cloudwatch",
            "describe-alarms",
            "--alarm-types",
            "MetricAlarm",
            "--alarm-names",
        ];
        argv.extend(names.iter().map(ascii));
        let reply = self.aws(&argv, until, Kind::Read)?;
        read_alarms(&reply, &names).map_err(Halt::Failed)
    }

    fn alarm_of(&self, text: &Text) -> &'c Text {
        self.operator
            .alarm(text)
            .expect("the operator file keys its alarms by GD-2's guardrail texts")
    }

    pub(crate) fn require_caller(&mut self) -> Result<(), Halt> {
        let unknown = |reason: Text| {
            let mut sentence = Text::from("the caller is unknown: ");
            sentence.push_text(&reason);
            Halt::refused(sentence)
        };
        let reply = match self.aws(&["sts", "get-caller-identity"], None, Kind::Read) {
            Err(Halt::Failed(failed)) => return Err(unknown(failed.sentence())),
            other => other?,
        };
        let arn = caller_arn(&reply).map_err(|failed| unknown(failed.sentence()))?;
        if arn == self.operator.identity() {
            return Ok(());
        }
        let mut sentence = Text::from("the caller is ");
        sentence.push_text(arn);
        sentence.push_str(", not ");
        sentence.push_text(self.operator.identity());
        Err(Halt::refused(sentence))
    }

    /// Returns once every guardrail's alarm reads quiet, in GD-2's order, and keeps the first read's
    /// transition timestamps; else the abort with cause `guardrail` naming the first guardrail shown
    /// otherwise. A read that fails at or after `until` returns its failed call.
    pub(crate) fn quiet(&mut self, until: Option<f64>) -> Result<(), Halt> {
        let first = (*self.gd2.guardrails()[0]).clone();
        let alarms = match self.alarms(until) {
            Ok(alarms) => alarms,
            Err(Halt::Failed(failed)) => {
                if until.is_some_and(|until| self.monotonic() >= until) {
                    return Err(Halt::Failed(failed));
                }
                let mut detail =
                    Text::from("the alarms are unread, so no guardrail is shown quiet: ");
                detail.push_text(&failed.sentence());
                return Err(Halt::aborted("guardrail", Some(first), detail));
            }
            Err(other) => return Err(other),
        };
        for text in self.gd2.guardrails() {
            let name = self.alarm_of(text);
            let shown = |rest: &dyn Fn(&mut Text)| {
                let mut detail = Text::from("alarm ");
                detail.push_text(name);
                rest(&mut detail);
                Halt::aborted("guardrail", Some(text.clone()), detail)
            };
            let Some(alarm) = alarms.get(name).filter(|alarm| *alarm.state() == "OK") else {
                let state = alarms.get(name).map(Alarm::state);
                return Err(shown(&|d| {
                    d.push_str(" reads ");
                    match state {
                        Some(state) => d.push_text(state),
                        None => d.push_str("no answer"),
                    }
                }));
            };
            if !alarm
                .missing()
                .is_some_and(|missing| MISSING_DATA.iter().any(|way| *missing == *way))
            {
                return Err(shown(&|d| {
                    d.push_str(" treats missing data as ");
                    match alarm.missing() {
                        Some(missing) => d.push_text(missing),
                        None => d.push_str("None"),
                    }
                    d.push_str(", so it can read OK without data");
                }));
            }
            if let Some(evaluation) = alarm.evaluation() {
                return Err(shown(&|d| {
                    d.push_str(" reads OK with evaluation state ");
                    d.push_text(evaluation);
                }));
            }
            if let Some(kind) = alarm.kind() {
                return Err(shown(&|d| {
                    d.push_str(&format!(" is {kind}, which reads OK without data"));
                }));
            }
            if let Some(before) = self.transitions.as_ref().and_then(|seen| seen.get(name))
                && before != alarm.transitioned()
            {
                return Err(shown(&|d| {
                    d.push_str(" changed state at ");
                    d.push_text(alarm.transitioned());
                    d.push_str(" since the read before the stop (");
                    d.push_text(before);
                    d.push_str(")");
                }));
            }
        }
        if self.transitions.is_none() {
            let seen = alarms
                .iter()
                .map(|(name, alarm)| (name.clone(), alarm.transitioned().clone()))
                .collect();
            self.transitions = Some(seen);
        }
        Ok(())
    }

    /// The wall reading at which the stop request may leave, read now; else the abort with cause
    /// `reach` for a snapshot past its age bound on either clock, or `deadline` for clocks apart by
    /// more than [`SKEW_SECONDS`], too little time for the observation and one poll, or a reading at
    /// or before the snapshot's cut, outside the run window or less than [`SKEW_SECONDS`] before the
    /// approval's lapse.
    ///
    /// # Errors
    ///
    /// [`Halt::Aborted`] with cause `reach` or `deadline` as above; [`Halt::Fault`] when no preflight
    /// or deadline is set; [`Halt::Refused`] when the approval's lapse reads no ISO time.
    ///
    /// # Panics
    ///
    /// A preflight whose package holds no baseline or run window with numeric ends.
    pub fn ready(&mut self) -> Result<f64, Halt> {
        let (Some(preflight), Some(deadline)) = (self.preflight.as_ref(), self.deadline) else {
            return Err(Halt::order(
                "a stop request is checked before the run's preflight",
            ));
        };
        let at = self.monotonic();
        let now = self.wall();
        let left = deadline - at;
        let bound = self.operator.snapshot_max_age_seconds();
        if at > preflight.fresh_until || now - seconds(preflight.oldest) > seconds(bound) {
            return Err(Halt::aborted(
                "reach",
                None,
                Text::from(format!(
                    "the snapshot passed its age bound of {bound} s before the stop request"
                )),
            ));
        }
        let drift = (now - preflight.origin.0) - (at - preflight.origin.1);
        if drift.abs() > SKEW_SECONDS as f64 {
            return Err(deadline_abort(format!(
                "the wall clock moved {drift:.1} s apart from the monotonic clock since the run's start"
            )));
        }
        let observe = self.operator.observe_seconds();
        if left <= seconds(observe) + POLL_SECONDS as f64 {
            return Err(deadline_abort(format!(
                "{left:.1} s before the deadline cannot hold the observation of {observe} s and one poll"
            )));
        }
        let not_after = self.operator.approval().not_after();
        let lapse = iso_time(
            &Value::String(not_after.clone()),
            &Text::from("approval not_after"),
        )?;
        let baseline_end = window(&preflight.package, "baseline").1;
        let window = window(&preflight.package, "run");
        let reading = Number::from(now);
        let admitted = now + SKEW_SECONDS as f64 <= lapse as f64
            && baseline_end <= reading
            && preflight.cut < reading
            && window.0 <= reading
            && reading < window.1;
        if !admitted {
            let shown = preflight
                .package
                .get("run")
                .map_or_else(|| "None".to_owned(), repr);
            return Err(deadline_abort(format!(
                "the wall clock reads {}, at or before the snapshot's cut, outside the run window \
                 {shown} or past {SKEW_SECONDS} s before the approval's lapse {not_after}",
                repr_float(now)
            )));
        }
        Ok(now)
    }

    /// Sleeps one poll period, or less to reach `until`, a monotonic reading, or the deadline.
    ///
    /// # Errors
    ///
    /// [`Halt::Interrupted`] for a signal the sleep raises; [`Halt::Fault`] when no deadline is set.
    pub fn pause(&mut self, until: f64) -> Result<(), Halt> {
        let Some(deadline) = self.deadline else {
            return Err(Halt::order("a poll pauses with no deadline set"));
        };
        let length = (POLL_SECONDS as f64)
            .min(until.min(deadline) - self.monotonic())
            .max(0.0);
        self.cx.seam.sleep(self.cx.record, at_least(length))?;
        Ok(())
    }

    /// Writes the mark `name` once, its value checked first against the judge's layout (`roles`
    /// excepted, which its builder checked) and its bytes against the mark size limit, with a signal
    /// held to the write's end. A mark that stands with its durability unknown counts as written.
    ///
    /// # Errors
    ///
    /// [`Halt::Interrupted`] for a signal the read before the hold or the release raises;
    /// [`Halt::Fault`] for a value or bytes a check refuses, no injection directory set, or a write
    /// that fails, and an order fault for a `name` other than the six marks of the judge's layout,
    /// `roles`, `stop`, `stopped`, `abort`, `restoration` and `collected`.
    pub fn mark(&mut self, name: &'static str, value: &Value) -> Result<(), Halt> {
        self.mark_under(name, value, &Names::new())
    }

    /// Writes the mark `name` as [`Controller::mark`] does, its value checked against the judge's
    /// layout under `names`.
    ///
    /// # Errors
    ///
    /// Each failure [`Controller::mark`] names.
    pub(crate) fn mark_under(
        &mut self,
        name: &'static str,
        value: &Value,
        names: &Names,
    ) -> Result<(), Halt> {
        if !matches!(
            name,
            "roles" | "stop" | "stopped" | "abort" | "restoration" | "collected"
        ) {
            return Err(Halt::order(&format!("{name} is no mark of a run")));
        }
        let what = Text::from(format!("injection/{name}.json"));
        if name != "roles" {
            let (schema, _) = layout(&format!("injection/{name}.json"))
                .expect("the judge's layout holds each mark of a run");
            conform(value, schema, &what, names)
                .map_err(|refusal| Fault::Refusal(refusal.message().clone()))?;
        }
        let data = encoded(value, &what, self.cx.mark_limit)
            .map_err(|refusal| Fault::Refusal(refusal.message().clone()))?;
        let Some(injection) = self.injection.clone() else {
            return Err(Halt::order(&format!(
                "the mark {name} has no injection directory to stand in"
            )));
        };
        let file = format!("{name}.json");
        let path = beside(&injection, &file);
        let files = self.cx.files;
        let written = &mut *self.written;
        let outcome = self.cx.record.holding(|| {
            match publish(files, &injection, OsStr::new(&file), &data) {
                Ok(()) => {
                    written.push(name);
                    Ok(())
                }
                Err(unwritten) => {
                    if unwritten.stands() {
                        written.push(name);
                    }
                    Err(unwritten)
                }
            }
        })?;
        outcome.map_err(|unwritten| Halt::Fault(Fault::unwritten(&unwritten, &path)))
    }
}

/// `seconds` as a `Duration` whose reading back as seconds is no less than `seconds`, and at most a
/// nanosecond longer than the nearest `Duration`. A cut or a pause of the length a caller chose
/// then reads, once it has run whole, at or past the reading it ran toward.
fn at_least(seconds: f64) -> Duration {
    let mut length = Duration::from_secs_f64(seconds);
    if length.as_secs_f64() < seconds {
        length += Duration::from_nanos(1);
    }
    length
}

fn deadline_abort(detail: String) -> Halt {
    Halt::aborted("deadline", None, Text::from(detail))
}

pub(crate) fn ascii(text: &Text) -> &str {
    text.to_str()
        .expect("an instance ID and an alarm name the operator file admitted are ASCII or UTF-8")
}

fn number_at(object: &Object, window: &str, end: &str) -> Number {
    let Some(Value::Object(window)) = object.get(window) else {
        panic!("the package check admitted the window {window}")
    };
    window
        .get(end)
        .and_then(Number::of)
        .unwrap_or_else(|| panic!("the package check admitted the window's {end}"))
}

pub(crate) fn window(package: &Object, name: &str) -> (Number, Number) {
    (
        number_at(package, name, "start"),
        number_at(package, name, "end"),
    )
}
