//! One run's state and the steps every phase of a run takes: a call through its one path, the
//! deadline's check, the alarms' quiet read, the check before the stop request, the pause between
//! polls and a mark's write.
//!
//! The deadline and every window's end are monotonic readings. A call checks the deadline before it
//! starts and once it returns, and reads the record once it returns, so a signal that stands then
//! ends the step before its reply or failure is used. A mark's write holds the record from before
//! its first file step to its end.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::context::{Context, beside, seconds};
use super::fault::{Fault, Halt};
use crate::gameday::{Names, conform, layout};
use crate::host_stop::{
    Alarm, CALL_SECONDS, Call, CallError, FailedCall, Files, Gd2, InstanceRecord, MISSING_DATA,
    Number, Operator, POLL_SECONDS, SKEW_SECONDS, Seam, Status, encoded, iso_time, publish,
    read_alarms, read_record, read_statuses, reply,
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

    /// One call of `argv` with `--region`, cut at [`CALL_SECONDS`], at the deadline and at `until`.
    /// The deadline is checked before the call and after it returns or fails; a signal the record
    /// raises when the call returns comes before its reply or failure. With `mutating`, the call
    /// counts as sent from its launch, and its monotonic times, its answer and its failure are kept.
    pub(crate) fn aws(
        &mut self,
        argv: &[&str],
        retry: bool,
        until: Option<f64>,
        mutating: bool,
    ) -> Result<Object, Halt> {
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
            self.sent = true;
            self.launched = Some(self.monotonic());
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
            retry,
            cut: Duration::from_secs_f64(timeout),
            env: self.cx.env,
        };
        let answer = reply(&mut *self.cx.seam, self.cx.record, &call);
        let raised = self.cx.record.read();
        let answer = match (answer, raised) {
            (_, Err(raised)) | (Err(CallError::Interrupted(raised)), Ok(())) => {
                if mutating {
                    self.returned = Some(self.monotonic());
                }
                return Err(Halt::Interrupted(raised));
            }
            (answer, Ok(())) => answer,
        };
        match answer {
            Err(CallError::Failed(failed)) => {
                if mutating {
                    self.returned = Some(self.monotonic());
                    self.stop_failure = Some(failed.sentence());
                }
                self.within_deadline()?;
                Err(Halt::Failed(failed))
            }
            Ok(object) => {
                if mutating {
                    self.returned = Some(self.monotonic());
                    self.answered = true;
                }
                self.within_deadline()?;
                Ok(object)
            }
            Err(CallError::Interrupted(_)) => unreachable!("a raised signal returned above"),
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
        let reply = self.aws(&argv, true, until, false)?;
        read_statuses(&reply, instances).map_err(Halt::Failed)
    }

    pub(crate) fn record(
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
        let reply = self.aws(&argv, true, until, false)?;
        read_record(&reply, instance).map_err(Halt::Failed)
    }

    /// The guardrail alarms' read, the names asked in GD-2's order, cut at `until`.
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
        let reply = self.aws(&argv, true, until, false)?;
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
        let reply = match self.aws(&["sts", "get-caller-identity"], true, None, false) {
            Err(Halt::Failed(failed)) => return Err(unknown(failed.sentence())),
            other => other?,
        };
        let arn = match reply.get("Arn") {
            Some(Value::String(arn)) => arn,
            other => {
                let shown = other.map_or_else(|| "None".to_owned(), repr);
                let cut: String = format!("Arn is no str: {shown}")
                    .chars()
                    .take(400)
                    .collect();
                return Err(unknown(Text::from(cut)));
            }
        };
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
            let shown = |words: &[&dyn Fn(&mut Text)]| {
                let mut detail = Text::from("alarm ");
                detail.push_text(name);
                for word in words {
                    word(&mut detail);
                }
                Halt::aborted("guardrail", Some(text.clone()), detail)
            };
            let Some(alarm) = alarms.get(name).filter(|alarm| *alarm.state() == "OK") else {
                let state = alarms.get(name).map(Alarm::state);
                return Err(shown(&[&|d| {
                    d.push_str(" reads ");
                    match state {
                        Some(state) => d.push_text(state),
                        None => d.push_str("no answer"),
                    }
                }]));
            };
            if !alarm
                .missing()
                .is_some_and(|missing| MISSING_DATA.iter().any(|way| *missing == *way))
            {
                return Err(shown(&[&|d| {
                    d.push_str(" treats missing data as ");
                    match alarm.missing() {
                        Some(missing) => d.push_text(missing),
                        None => d.push_str("None"),
                    }
                    d.push_str(", so it can read OK without data");
                }]));
            }
            if let Some(evaluation) = alarm.evaluation() {
                return Err(shown(&[&|d| {
                    d.push_str(" reads OK with evaluation state ");
                    d.push_text(evaluation);
                }]));
            }
            if let Some(kind) = alarm.kind() {
                return Err(shown(&[&|d| {
                    d.push_str(&format!(" is {kind}, which reads OK without data"));
                }]));
            }
            if let Some(before) = self.transitions.as_ref().and_then(|seen| seen.get(name))
                && before != alarm.transitioned()
            {
                return Err(shown(&[&|d| {
                    d.push_str(" changed state at ");
                    d.push_text(alarm.transitioned());
                    d.push_str(" since the read before the stop (");
                    d.push_text(before);
                    d.push_str(")");
                }]));
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
    pub fn ready(&mut self) -> Result<f64, Halt> {
        let (Some(preflight), Some(deadline)) = (self.preflight.as_ref(), self.deadline) else {
            return Err(order(
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
        )
        .map_err(Halt::from)?;
        let window = window(&preflight.package, "run");
        let baseline_end = window_end(&preflight.package, "baseline");
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

    /// Sleeps one poll period, or less to reach `until` or the deadline.
    pub fn pause(&mut self, until: f64) -> Result<(), Halt> {
        let Some(deadline) = self.deadline else {
            return Err(order("a poll pauses with no deadline set"));
        };
        let length = (POLL_SECONDS as f64)
            .min(until.min(deadline) - self.monotonic())
            .max(0.0);
        let mut slept = Duration::from_secs_f64(length);
        if slept.as_secs_f64() < length {
            slept += Duration::from_nanos(1);
        }
        self.cx.seam.sleep(self.cx.record, slept)?;
        Ok(())
    }

    /// Writes the mark `name` once, its value checked first against the judge's layout (`roles`
    /// excepted, which its builder checked) and its bytes against the mark size limit, with a signal
    /// held to the write's end. A mark that stands with its durability unknown counts as written.
    pub fn mark(&mut self, name: &'static str, value: &Value) -> Result<(), Halt> {
        let what = Text::from(format!("injection/{name}.json"));
        if name != "roles" {
            let (schema, _) = layout(&format!("injection/{name}.json"))
                .unwrap_or_else(|| panic!("the judge's layout holds injection/{name}.json"));
            conform(value, schema, &what, &Names::new())
                .map_err(|refusal| Fault::Refusal(refusal.message().clone()))?;
        }
        let data = encoded(value, &what, self.cx.mark_limit)
            .map_err(|refusal| Fault::Refusal(refusal.message().clone()))?;
        let Some(injection) = self.injection.clone() else {
            return Err(order(&format!(
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

fn order(sentence: &str) -> Halt {
    Halt::Fault(Fault::Order(sentence.to_owned()))
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

fn window_end(package: &Object, name: &str) -> Number {
    number_at(package, name, "end")
}
