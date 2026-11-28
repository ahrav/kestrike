//! The run's seven steps, the abort path, and the entry that reads the catalog and the operator
//! file and prints the line of a run that ends before `roles.json` stands.
//!
//! Once `injection/` is made the run holds its lock to the run's end. A failure before `roles.json`
//! stands removes `injection/` again and is a refusal; once it stands, every end but the
//! observation's is the abort path, which writes `abort.json`, then `stopped.json` when the stop
//! was shown, reads the target's status once when a stop request may have left, and prints GD-2's
//! restoration steps.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;

use super::context::{Command, Context, Stream, beside, list_repr, pure, seconds};
use super::controller::{Controller, Kind, Preflight, ascii, window};
use super::fault::{Aborted, Fault, Halt};
use crate::gameday::{FleetBounds, TBD, exact, roles_reach, shown};
use crate::host_stop::{
    DETAIL_MAX, Files, LockError, Number, ProbeError, Run, SKEW_SECONDS, Seam, USER_SHUTDOWN,
    USER_STOP, build_roles, check_run, encoded, gd2_of, lock, posix_seconds, probe, read_bytes,
    read_json, read_operator, read_snapshot, steps_tail, sync_directory,
};
use crate::json::{Object, Value};
use crate::plants::files::strerror;
use crate::python::{repr, repr_float};
use crate::text::{Text, text};

pub(super) const TOOL: &str = "host-stop-controller: ";

/// Runs `command` on `cx` and returns the exit code: 0 for a run that ends with the restoration
/// pending, 1 for an abort, 2 for a refusal, a signal before any mark, or an unforeseen failure that
/// reaches the entry, whose line names the marks that stand. A panic counts as an unforeseen failure,
/// a panic inside the abort path itself included. The entry leaves the record unarmed and unheld,
/// with a stored signal still stored.
///
/// The library installs no signal handler. A process calls
/// [`install`](crate::host_stop::install) before it reads its arguments and passes in `cx` an unarmed,
/// unheld record over the same [`Delivered`](crate::host_stop::Delivered) the handlers store into. A
/// panic the entry catches has already passed the process's panic hook, which the process owns.
pub fn entry<S: Seam, F: Files>(command: &Command, cx: &mut Context<'_, S, F>) -> u8 {
    let (Command::Run { operator, .. } | Command::Restore { operator, .. }) = command;
    let mut written = Vec::new();
    let ended = caught(|| {
        let limit = cx.file_limit;
        let catalog = read_json(cx.catalog, &Text::from("the game-day catalog"), limit)?;
        let gd2 = gd2_of(&catalog)?;
        let operator = read_operator(operator, &gd2, limit)?;
        let mut controller = Controller::new(&mut *cx, &mut written, &operator, gd2);
        match command {
            Command::Run {
                package, evidence, ..
            } => controller.run(package, evidence),
            Command::Restore {
                evidence, reviewed, ..
            } => controller.restore(evidence, reviewed.as_deref()),
        }
    });
    cx.record.disarm();
    cx.record.end_hold();
    let halt = match ended {
        Ok(code) => return code,
        Err(halt) => halt,
    };
    let mut line = Text::from(TOOL);
    let unforeseen = |line: &mut Text, text: Text| {
        line.push_text(&text);
        if written.is_empty() {
            line.push_str("; nothing written");
        } else {
            let names: Vec<Text> = written.iter().map(|name| Text::from(*name)).collect();
            line.push_str(&format!("; marks written: {}", list_repr(&names)));
        }
    };
    match halt {
        Halt::Refused {
            sentence,
            may_stand,
        } => {
            line.push_str("refused: ");
            line.push_text(&sentence);
            if !may_stand {
                line.push_str("; nothing written");
            }
        }
        Halt::Interrupted(raised) => {
            line.push_str(&format!("signal {raised} before any mark; nothing written"));
        }
        halt => unforeseen(&mut line, halt_text(halt)),
    }
    cx.say(Stream::Err, &line);
    2
}

/// `step`'s result, a panic folded into [`Halt::Fault`].
fn caught<T>(step: impl FnOnce() -> Result<T, Halt>) -> Result<T, Halt> {
    catch_unwind(AssertUnwindSafe(step))
        .unwrap_or_else(|payload| Err(Halt::Fault(Fault::panic(&*payload))))
}

fn aborted_text(aborted: &Aborted) -> Text {
    let mut text = Text::from("Aborted: ");
    text.push_text(aborted.detail());
    text
}

pub(super) fn shown_path(path: &Path) -> Text {
    Text::from_os(path.as_os_str())
}

impl<S: Seam, F: Files> Controller<'_, '_, S, F> {
    /// The run's seven steps on a controller that has made no step; returns the exit code of a run
    /// that writes `roles.json`, and the refusal, the signal or the failure of one that ends before
    /// it stands. A panic inside the abort path unwinds out of `run`.
    ///
    /// # Errors
    ///
    /// [`Halt::Fault`] for a controller whose list of written marks is not empty.
    pub fn run(mut self, package: &Path, evidence: &OsStr) -> Result<u8, Halt> {
        if !self.written.is_empty() {
            return Err(order_fault("a run starts with marks written"));
        }
        self.cx.record.arm();
        let read = self.before_injection(package, evidence);
        let read = self.raised(read);
        self.cx.record.disarm();
        let (root, run, roles) = read?;
        let injection = beside(&root, "injection");
        self.cx.record.hold();
        if let Err(error) = self.cx.files.mkdir(&injection) {
            self.cx.record.end_hold();
            return Err(Halt::refused(text!(
                shown_path(&injection),
                " cannot be made: ",
                &strerror(&error),
            )));
        }
        self.injection = Some(injection.clone());
        let mut held = None;
        let ended = caught(|| {
            held = Some(
                lock(self.cx.files, &injection)
                    .map_err(|error| Fault::Refusal(lock_sentence(&injection, &error)))?,
            );
            self.inject(&root, &run, &roles)
        });
        self.cx.record.disarm();
        self.cx.record.end_hold();
        let (cause, guardrail, detail) = match ended {
            Ok(code) => return Ok(code),
            Err(Halt::Aborted(aborted)) => (
                aborted.cause(),
                aborted.guardrail().cloned(),
                aborted.detail().clone(),
            ),
            Err(Halt::Interrupted(raised)) => {
                ("signal", None, Text::from(format!("signal {raised}")))
            }
            Err(halt) => ("exception", None, halt_text(halt)),
        };
        if self.written.contains(&"roles") {
            let code = self.abort(cause, guardrail, &detail);
            drop(held);
            return Ok(code);
        }
        drop(held);
        let mut what = detail;
        what.push_str(" before roles.json stood; ");
        what.push_text(&shown_path(&injection));
        let removed = self
            .cx
            .files
            .rmdir(&injection)
            .and_then(|()| sync_directory(self.cx.files, &root));
        match removed {
            Err(error) => Err(Halt::Refused {
                sentence: {
                    let mut sentence = what;
                    sentence.push_str(&format!(
                        " may stand, since its removal failed or is unsynced ({}): remove it \
                         before another run",
                        strerror(&error)
                    ));
                    sentence
                },
                may_stand: true,
            }),
            Ok(()) => Err(Halt::refused(text!(what, " is removed"))),
        }
    }

    /// `ended`, or the signal a read of the record raises at the end of an armed span whose last
    /// read came before it: a refusal, a cause of the abort or the span's end then gives way to the
    /// signal, and a failure or a panic keeps its own end.
    fn raised<T>(&mut self, ended: Result<T, Halt>) -> Result<T, Halt> {
        match ended {
            Ok(_) | Err(Halt::Refused { .. } | Halt::Aborted(_)) => {
                self.cx.record.read()?;
                ended
            }
            other => other,
        }
    }

    /// Steps 1 to 3 up to the making of `injection/`: the evidence root, the admitted package and
    /// the roles mark. A deadline passed here is a refusal.
    fn before_injection(
        &mut self,
        package: &Path,
        evidence: &OsStr,
    ) -> Result<(std::path::PathBuf, Run, Value), Halt> {
        self.cx.record.read()?;
        let at = self.monotonic();
        let start = self.wall();
        self.deadline = Some(at + seconds(self.operator.deadline_seconds()));
        let owed = self.gd2.entry().get("prerequisites");
        let met = matches!(owed, Some(Value::Array(owed)) if owed.iter().all(|text| {
            matches!(text, Value::String(text) if !text.to_string().contains(TBD))
        }));
        if !met {
            let shown = owed.map_or_else(|| "None".to_owned(), repr);
            return Err(Halt::refused(text!(format!(
                "GD-2's prerequisites are not all met, so the catalog blocks its execution: {shown}"
            ))));
        }
        let limit = self.cx.file_limit;
        let raw = read_bytes(package, &Text::from("the package"), limit)?;
        let Some(bounds) = FleetBounds::new(self.cx.top, limit) else {
            return Err(Halt::refused(text!(
                "the tree's top has a path no file can have"
            )));
        };
        let run = check_run(&raw, self.operator, Number::from(start), &bounds)?;
        self.instance = Some(run.instance().clone());
        let root = pure(evidence.as_bytes());
        let directory = !evidence.is_empty()
            && self
                .cx
                .files
                .lstat(&root)
                .is_ok_and(|found| found.file_type().is_dir());
        if !directory {
            return Err(Halt::refused(text!(
                Text::from_os(evidence).repr(),
                " is no directory",
            )));
        }
        let injection = beside(&root, "injection");
        if self.cx.files.lstat(&injection).is_ok() {
            return Err(Halt::refused(text!(
                shown_path(&injection),
                " exists: a run's marks are written once",
            )));
        }
        probe(self.cx.files, &root).map_err(|error| probe_refusal(&root, &error))?;
        let copy = beside(&root, "package.json");
        if read_bytes(&copy, &shown_path(&copy), limit)? != raw {
            return Err(Halt::refused(text!(
                shown_path(&copy),
                " holds other bytes than --package, so the judge would refuse the run's evidence",
            )));
        }
        match self.before_roles(&run, (start, at)) {
            Err(Halt::Aborted(aborted)) => Err(Halt::refused(text!(
                aborted.detail(),
                " before injection/ was made",
            ))),
            Ok(roles) => Ok((root, run, roles)),
            Err(other) => Err(other),
        }
    }

    /// The caller, the snapshot and the declared set's status, then the roles mark and its bytes.
    fn before_roles(&mut self, run: &Run, origin: (f64, f64)) -> Result<Value, Halt> {
        self.require_caller()?;
        let at = self.monotonic();
        let now = self.wall();
        let limit = self.cx.file_limit;
        let snapshot = read_snapshot(
            self.operator,
            run.package(),
            run.names(),
            Number::from(now),
            limit,
        )?;
        let bound = seconds(self.operator.snapshot_max_age_seconds());
        let fresh_until = at + seconds(snapshot.oldest()) + bound - now;
        self.preflight = Some(Preflight::new(
            run.package().clone(),
            snapshot.cut(),
            snapshot.oldest(),
            origin,
            fresh_until,
        ));
        let states = match self.statuses(self.operator.instances(), None) {
            Err(Halt::Failed(failed)) => {
                return Err(Halt::refused(text!(
                    "the declared instances' status is unknown: ",
                    failed.sentence(),
                )));
            }
            other => other?,
        };
        let open: Vec<&Text> = states
            .iter()
            .filter(|(_, status)| *status.state() != "running")
            .map(|(instance, _)| instance)
            .collect();
        if !open.is_empty() {
            return Err(Halt::refused(text!(format!(
                "declared instances {} are not running: a run is left open",
                list_repr(open)
            ))));
        }
        let roles = build_roles(
            run.package(),
            run.names(),
            run.package_sha256(),
            snapshot.records(),
            snapshot.reports(),
            &states,
            snapshot.cut(),
        )?;
        encoded(
            &roles,
            &Text::from("injection/roles.json"),
            self.cx.mark_limit,
        )?;
        self.within_deadline()?;
        Ok(roles)
    }

    /// Steps 3 to 7 once `injection/` stands under `root`, armed until the observation ends; the hold
    /// `run` starts before making `injection/` ends with the roles' write, and `stopped.json` is
    /// written unarmed.
    fn inject(&mut self, root: &Path, run: &Run, roles: &Value) -> Result<u8, Halt> {
        self.cx.record.arm();
        let observed = self.observed(root, run, roles);
        let observed = self.raised(observed);
        self.cx.record.disarm();
        let stopped = observed?;
        self.mark("stopped", &stopped)?;
        let end = exact(member(member_object(run.package(), "run"), "end"))
            .expect("the package check admitted the run window's end");
        let error = exact(member(run.package(), "clock_error_seconds"))
            .expect("the package check admitted the clock error");
        let margin = exact(&Number::from(2 * SKEW_SECONDS + 1).value()).expect("an integer");
        let late = shown(&(&(&end + &margin) + &error));
        let mut line = Text::from(TOOL);
        line.push_text(run.instance());
        line.push_str(&format!(
            " stopped and observed for {} s; the restoration is pending and the alarms are no \
             longer watched: start the instance, then run restore. A start before {late} may end \
             the judge's observation before the run window's end",
            self.operator.observe_seconds()
        ));
        self.cx.say(Stream::Out, &line);
        Ok(0)
    }

    fn observed(&mut self, root: &Path, run: &Run, roles: &Value) -> Result<Value, Halt> {
        sync_directory(self.cx.files, root).map_err(|error| Fault::os(&error))?;
        self.mark("roles", roles)?;
        let Value::Object(marked) = roles else {
            unreachable!("the roles mark is an object")
        };
        let unmet = roles_reach(marked, run.package());
        if !unmet.is_empty() {
            return Err(Halt::aborted("reach", None, Text::join("; ", &unmet)));
        }
        self.quiet(None)?;
        let request_at = self.monotonic();
        self.request_at = Some(request_at);
        let effect = seconds(self.operator.effect_timeout_seconds());
        let mut request = Object::new();
        request.insert("instance", Value::String(run.instance().clone()));
        request.insert("time", Value::Float(self.ready()?));
        request.insert("identity", Value::String(self.operator.identity().clone()));
        let request = Value::Object(request);
        self.mark("stop", &request)?;
        self.stop(request_at + effect / 2.0)?;
        let stopped = self.await_stop(&request, request_at + effect)?;
        self.shown = Some(stopped.clone());
        let end = self.monotonic() + seconds(self.operator.observe_seconds());
        loop {
            self.pause(end)?;
            let started = self.monotonic();
            self.quiet(None)?;
            if started >= end {
                return Ok(stopped);
            }
        }
    }

    /// Reads the alarms and checks the stop may leave again once `stop.json` stands, then sends the
    /// stop request once, cut at `until`. A request that never left, one refused before its launch
    /// for no time left, aborts with cause `stop-not-shown`; one that counts as sent keeps its
    /// failure for the polls to decide.
    fn stop(&mut self, until: f64) -> Result<(), Halt> {
        self.quiet(None)?;
        self.ready()?;
        let instance = self
            .instance
            .clone()
            .expect("the preflight read the target");
        let argv = ["ec2", "stop-instances", "--instance-ids", ascii(&instance)];
        match self.aws(&argv, Some(until), Kind::Stop) {
            Ok(_) => Ok(()),
            Err(Halt::Failed(failed)) if !self.sent => {
                let mut detail = Text::from("the stop request never left: ");
                detail.push_text(&failed.sentence());
                Err(Halt::aborted("stop-not-shown", None, detail))
            }
            Err(Halt::Failed(failed)) => {
                let mut line = Text::from(TOOL);
                line.push_str("the stop request's outcome is unknown: ");
                line.push_text(&failed.sentence());
                line.push_str("; the polls decide");
                self.cx.say(Stream::Out, &line);
                Ok(())
            }
            Err(other) => Err(other),
        }
    }

    /// `stopped.json`'s value once a status read dated from the request to the run window's end
    /// reads `stopped` and the target's record then shows this request, both by `until`; else the
    /// abort with cause `stop-not-shown`, naming the last read. The first poll runs at once. The
    /// request's time and the run window's end are wall readings; `until` is a monotonic reading.
    ///
    /// # Errors
    ///
    /// [`Halt::Aborted`] as above or from an alarm read; [`Halt::Interrupted`] for a signal;
    /// [`Halt::Fault`] when no preflight or target is set.
    ///
    /// # Panics
    ///
    /// A `request` that is no object with a numeric `time`.
    pub fn await_stop(&mut self, request: &Value, until: f64) -> Result<Value, Halt> {
        let Some(preflight) = self.preflight.as_ref() else {
            return Err(Halt::Fault(Fault::Order(
                "the stop is awaited before the run's preflight".to_owned(),
            )));
        };
        let run_end = window(preflight.package(), "run").1;
        let Some(instance) = self.instance.clone() else {
            return Err(order_fault(
                "the stop is awaited before the run's target is read",
            ));
        };
        let requested = member(member_object_of(request), "time");
        let requested = Number::of(requested).expect("the request's time is a number");
        let mut seen = Text::from("no status read was made");
        let mut first = true;
        loop {
            if !first {
                self.pause(until)?;
            }
            first = false;
            if self.monotonic() >= until {
                break;
            }
            let read = self.quiet(Some(until)).and_then(|()| {
                let instances = [instance.clone()];
                self.statuses(&instances, Some(until))
            });
            let state = match read {
                Err(Halt::Failed(failed)) => {
                    seen = Text::from("a read failed: ");
                    seen.push_text(&failed.sentence());
                    continue;
                }
                Err(other) => return Err(other),
                Ok(states) => states
                    .get(&instance)
                    .expect("the statuses name the target")
                    .state()
                    .clone(),
            };
            let at = self.wall();
            seen = Text::from("the target reads ");
            seen.push_text(&state);
            if state != "stopped" {
                continue;
            }
            let reading = Number::from(at);
            if !(requested <= reading && reading < run_end) {
                seen = Text::from(format!(
                    "the target reads stopped at {}, outside [the stop request, the run window's end)",
                    repr_float(at)
                ));
                continue;
            }
            let record = match self.instance_record(&instance, Some(until)) {
                Err(Halt::Failed(failed)) => {
                    seen = Text::from("the target reads stopped and its record is unread: ");
                    seen.push_text(&failed.sentence());
                    continue;
                }
                other => other?,
            };
            if self.monotonic() > until {
                seen = Text::from(
                    "the target reads stopped and its record answered past the effect timeout",
                );
                break;
            }
            if self.confirms(&record, seconds(requested)) {
                let mut stopped = Object::new();
                stopped.insert("instance", Value::String(instance.clone()));
                stopped.insert("state", Value::String(Text::from("stopped")));
                stopped.insert("time", Value::Float(at));
                stopped.insert("request", request.clone());
                return Ok(Value::Object(stopped));
            }
            seen = Text::from("the target reads stopped and its record ");
            seen.push_str(&repr(&record.to_value()));
            seen.push_str(" does not show the request");
        }
        let mut detail = Text::from(format!(
            "the stop was not shown within {} s: ",
            self.operator.effect_timeout_seconds()
        ));
        detail.push_text(&seen);
        Err(Halt::aborted("stop-not-shown", None, detail))
    }

    /// Whether the record shows the stop: a user's shutdown whose transition second lies whole in
    /// the stop call's window, from [`SKEW_SECONDS`] before its launch to [`SKEW_SECONDS`] after its
    /// return, each end the request's wall reading plus the monotonic time since the request.
    fn confirms(&self, record: &crate::host_stop::InstanceRecord, requested: f64) -> bool {
        let transition = record.transition().to_str().unwrap_or_default();
        let Some(found) = USER_STOP.captures(transition) else {
            return false;
        };
        if *record.state() != "stopped" || record.code().is_none_or(|code| *code != USER_SHUTDOWN) {
            return false;
        }
        let second = found
            .get(1)
            .expect("the pattern captures the second")
            .as_str();
        let Some(at) = posix_seconds(second) else {
            return false;
        };
        let (Some(launched), Some(returned), Some(request_at)) =
            (self.launched, self.returned, self.request_at)
        else {
            return false;
        };
        let skew = SKEW_SECONDS as f64;
        let lower = requested + (launched - request_at) - skew;
        let upper = requested + (returned - request_at) + skew;
        lower <= at as f64 && (at + 1) as f64 <= upper
    }

    /// The abort path, unarmed and with no deadline: `abort.json` with the detail cut at
    /// [`DETAIL_MAX`] characters ahead of the steps' digest, then `stopped.json` when the stop was
    /// shown and the abort mark counts as written, one status read of the target when a request may
    /// have left, and GD-2's restoration steps. It makes no call that changes an instance; returns 1.
    fn abort(&mut self, cause: &'static str, guardrail: Option<Text>, detail: &Text) -> u8 {
        self.deadline = None;
        let mut text = if !self.sent {
            Text::from("no stop request was sent")
        } else if self.answered {
            Text::from("the stop request was sent and answered")
        } else {
            let mut text = Text::from("a stop request may have left and its outcome is unknown");
            if let Some(failure) = &self.stop_failure {
                text.push_str(": ");
                text.push_text(failure);
            }
            text
        };
        if !detail.is_empty() {
            text.push_str("; ");
            text.push_text(detail);
        }
        let steps = self.gd2.steps();
        let tail = steps_tail(steps);
        let time = self.wall();
        let kept = DETAIL_MAX.saturating_sub(tail.chars().count());
        let mut cut = Text::from_code_points(text.code_points().take(kept))
            .expect("the code points of a text form a text");
        cut.push_str(&tail);
        let mut mark = Object::new();
        mark.insert("cause", Value::String(Text::from(cause)));
        mark.insert(
            "guardrail",
            guardrail.clone().map_or(Value::Null, Value::String),
        );
        mark.insert("time", Value::Float(time));
        mark.insert("detail", Value::String(cut.clone()));
        let mark = Value::Object(mark);
        self.abort_mark("abort", &mark);
        if let Some(shown) = self.shown.clone()
            && self.written.contains(&"abort")
            && !self.written.contains(&"stopped")
        {
            self.abort_mark("stopped", &shown);
        }
        let mut line = Text::from(format!("{TOOL}aborted on {cause}"));
        if let Some(guardrail) = &guardrail {
            line.push_str(" (");
            line.push_text(guardrail);
            line.push_str(")");
        }
        line.push_str(": ");
        line.push_text(&cut);
        self.cx.say(Stream::Out, &line);
        if self.sent {
            let instance = self.instance.clone().expect("a request names the target");
            let read = caught(|| {
                let states = self.statuses(std::slice::from_ref(&instance), None)?;
                let status = states.get(&instance).expect("the statuses name the target");
                let line = Text::from(format!(
                    "{TOOL}the target reads {}",
                    repr(&status.to_value())
                ));
                self.cx.say(Stream::Out, &line);
                Ok(())
            });
            if let Err(halt) = read {
                self.cx.say(Stream::Out, &state_unknown(halt_text(halt)));
            }
        }
        self.cx.say(
            Stream::Out,
            &Text::from(format!("GD-2's restoration steps: {steps}")),
        );
        1
    }
}

impl<S: Seam, F: Files> Controller<'_, '_, S, F> {
    /// Writes the mark `name` in the abort path, and prints on standard error a line that says it
    /// stands with its durability unknown or is unwritten when the write fails or panics. A write
    /// that panics inside its hold leaves the record unheld.
    fn abort_mark(&mut self, name: &'static str, value: &Value) {
        let wrote = caught(|| self.mark(name, value));
        self.cx.record.end_hold();
        let Err(halt) = wrote else {
            return;
        };
        let failed = halt_text(halt);
        let standing = if self.written.contains(&name) {
            "stands with its durability unknown"
        } else {
            "is unwritten"
        };
        let mut line = Text::from(format!("{TOOL}{name}.json {standing}: "));
        line.push_text(&failed);
        self.cx.say(Stream::Err, &line);
    }
}

fn state_unknown(text: Text) -> Text {
    let mut line = Text::from(format!("{TOOL}the target's state is unknown: "));
    line.push_text(&text);
    line
}

/// The `<class>: <message>` text of a step's end that the abort path reports.
fn halt_text(halt: Halt) -> Text {
    match halt {
        Halt::Refused { sentence, .. } => Fault::Refusal(sentence).text(),
        Halt::Aborted(aborted) => aborted_text(&aborted),
        Halt::Interrupted(raised) => Text::from(format!("Interrupted: {raised}")),
        Halt::Failed(failed) => {
            let mut text = Text::from("CallFailed: ");
            text.push_text(&failed.sentence());
            text
        }
        Halt::Fault(fault) => fault.text(),
    }
}

fn order_fault(sentence: &str) -> Halt {
    Halt::Fault(Fault::Order(sentence.to_owned()))
}

pub(super) fn lock_sentence(directory: &Path, error: &LockError) -> Text {
    let mut sentence = shown_path(directory);
    match error {
        LockError::Open(error) => {
            sentence.push_str(&format!(" cannot be opened: {}", strerror(error)));
        }
        LockError::Taken(error) => sentence.push_str(&format!(
            " is held by a run, restore or seal that has not ended: {}",
            strerror(error)
        )),
    }
    sentence
}

pub(super) fn probe_refusal(root: &Path, error: &ProbeError) -> Halt {
    match error {
        ProbeError::Unnamed(error) => Halt::refused(text!(
            shown_path(root),
            " takes no unnamed file, so no mark can be written there: ",
            &strerror(error),
        )),
        ProbeError::Unresolved(resolved) => Halt::refused(text!(
            shown_path(resolved),
            " does not resolve, so no unnamed file in ",
            shown_path(root),
            " can be linked to a mark's name",
        )),
    }
}

fn member<'v>(object: &'v Object, key: &str) -> &'v Value {
    object
        .get(key)
        .unwrap_or_else(|| panic!("the checked value holds {key}"))
}

fn member_object<'v>(object: &'v Object, key: &str) -> &'v Object {
    member_object_of(member(object, key))
}

fn member_object_of(value: &Value) -> &Object {
    match value {
        Value::Object(object) => object,
        other => panic!("{other:?} is the object the checks admitted"),
    }
}
