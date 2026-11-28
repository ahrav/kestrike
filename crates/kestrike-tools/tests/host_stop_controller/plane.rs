//! A control plane stand-in behind the [`Seam`]: the declared instances' states and checks, the
//! guardrail alarms' rows and the caller, answering the five calls in the reply shapes the
//! controller reads, with scripted actions per call, reply shapes, a fault asked at each call, and a
//! log that holds the marks standing in `injection/` at each call's start. Its clock holds the true
//! time `t`, which the monotonic clock reads from another origin and the wall clock reads with a
//! step added.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use kestrike_tools::host_stop::{CALL_SECONDS, Call, CallFailed, Ended, Interrupted, Record, Seam};
use kestrike_tools::json::{Object, Text, Value, text};

use crate::host_stop_support::value;

pub(crate) const CALLER: &str = "sts get-caller-identity";
pub(crate) const STATUS: &str = "ec2 describe-instance-status";
pub(crate) const RECORD: &str = "ec2 describe-instances";
pub(crate) const ALARMS: &str = "cloudwatch describe-alarms";
pub(crate) const STOP: &str = "ec2 stop-instances";
/// The calls that change an instance.
pub(crate) const CHANGES: [&str; 4] = [
    "ec2 stop-instances",
    "ec2 start-instances",
    "ec2 reboot-instances",
    "ec2 terminate-instances",
];
/// The monotonic clock's origin against the true time.
pub(crate) const MONOTONIC: f64 = 1e6;

/// What the plane does at one call. A hook runs first, and its result is the call's action.
pub(crate) enum Action {
    Answer,
    /// Fails with no effect.
    Refuse,
    /// Applies the call and fails.
    Lose,
    /// Answers after this many seconds more.
    Delay(f64),
    /// Applies the call and runs to the call's cut.
    Stall,
    /// Applies the call and answers half a second past its cut.
    Late,
    Hook(Box<dyn FnOnce(&mut State) -> Action>),
}

pub(crate) type Shape = Box<dyn FnOnce(Value) -> Value>;
pub(crate) type FaultPlan = Box<dyn FnMut(&State, &str) -> Option<Action>>;
/// Runs once a call has answered, before its reply returns.
pub(crate) type After = Box<dyn FnMut(&mut State, &str)>;
/// Runs once a sleep has moved the clock.
pub(crate) type Slept = Box<dyn FnMut(&mut State)>;
/// Runs at each wall reading.
pub(crate) type Reading = Rc<dyn Fn(&State)>;
/// Runs at each monotonic reading, before the reading is taken.
pub(crate) type Ticking = Rc<dyn Fn(&mut State)>;

#[derive(Clone, Debug)]
pub(crate) struct Instance {
    pub(crate) state: String,
    pub(crate) checks: String,
    pub(crate) system: String,
    pub(crate) transition: String,
    pub(crate) reason: Option<String>,
    pub(crate) launched: f64,
}

/// One call as the plane saw it.
#[derive(Clone, Debug)]
pub(crate) struct Logged {
    pub(crate) op: String,
    pub(crate) args: Vec<String>,
    pub(crate) retry: bool,
    pub(crate) start: f64,
    pub(crate) timeout: f64,
    /// The seconds the deadline left at the call's start.
    pub(crate) left: Option<f64>,
    pub(crate) marks: Vec<String>,
    pub(crate) time: Option<f64>,
    pub(crate) wall: Option<f64>,
    pub(crate) cut: bool,
    pub(crate) fault: bool,
    /// `stop.json` as it stood at a stop request.
    pub(crate) stop_json: Option<Value>,
}

/// The plane's state and clock, shared by the seam and the file steps of one case.
pub(crate) struct State {
    pub(crate) t: f64,
    pub(crate) step: f64,
    pub(crate) sleeps: usize,
    pub(crate) call_seconds: f64,
    pub(crate) evidence: PathBuf,
    pub(crate) region: String,
    pub(crate) arn: String,
    pub(crate) instances: BTreeMap<String, Instance>,
    pub(crate) alarms: BTreeMap<String, Object>,
    pub(crate) flips: u32,
    pub(crate) script: HashMap<&'static str, VecDeque<Action>>,
    pub(crate) shapes: HashMap<&'static str, VecDeque<Shape>>,
    pub(crate) fault: Option<FaultPlan>,
    pub(crate) after: Option<After>,
    pub(crate) reading: Option<Reading>,
    /// Runs at each monotonic reading.
    pub(crate) ticking: Option<Ticking>,
    pub(crate) log: Vec<Logged>,
    pub(crate) envs: Vec<Vec<(OsString, OsString)>>,
    pub(crate) deadline: Option<f64>,
    pub(crate) transition_offset: i64,
    pub(crate) stop_after: Option<u32>,
    pub(crate) stop_reads: u32,
    pub(crate) stop_reply: String,
    pub(crate) stop_code: String,
    pub(crate) stopping: Option<String>,
    /// Makes the call that runs now read the record once it is answered and end with the signal
    /// the read raises, as a launch whose wait reads the record does.
    pub(crate) interrupt: bool,
    pub(crate) slept: Option<Slept>,
}

pub(crate) type Shared = Rc<RefCell<State>>;

impl State {
    pub(crate) fn new(
        start: f64,
        evidence: PathBuf,
        region: &str,
        arn: &str,
        instances: &[String],
        alarms: &[String],
    ) -> Self {
        let instances = instances
            .iter()
            .map(|id| {
                let fresh = Instance {
                    state: "running".to_owned(),
                    checks: "ok".to_owned(),
                    system: "ok".to_owned(),
                    transition: String::new(),
                    reason: None,
                    launched: 0.0,
                };
                (id.clone(), fresh)
            })
            .collect();
        let alarms = alarms
            .iter()
            .map(|name| {
                let mut row = Object::new();
                row.insert("StateValue", string("OK"));
                row.insert("TreatMissingData", string("missing"));
                row.insert(
                    "StateTransitionedTimestamp",
                    string("2026-11-24T00:00:00.000Z"),
                );
                (name.clone(), row)
            })
            .collect();
        Self {
            t: start,
            step: 0.0,
            sleeps: 0,
            call_seconds: 0.2,
            evidence,
            region: region.to_owned(),
            arn: arn.to_owned(),
            instances,
            alarms,
            flips: 0,
            script: HashMap::new(),
            shapes: HashMap::new(),
            fault: None,
            after: None,
            reading: None,
            ticking: None,
            log: Vec::new(),
            envs: Vec::new(),
            deadline: None,
            transition_offset: 0,
            stop_after: Some(2),
            stop_reads: 0,
            stop_reply: "stopping".to_owned(),
            stop_code: "Client.UserInitiatedShutdown".to_owned(),
            stopping: None,
            interrupt: false,
            slept: None,
        }
    }

    pub(crate) fn wall(&self) -> f64 {
        self.t + self.step
    }

    /// Sets the alarm's state and moves its transition timestamp.
    pub(crate) fn flip(&mut self, name: &str, state: &str) {
        self.flips += 1;
        let row = self.alarms.get_mut(name).expect("the alarm exists");
        row.insert("StateValue", string(state));
        row.insert(
            "StateTransitionedTimestamp",
            string(&format!("2026-11-24T00:00:{:02}.000Z", self.flips)),
        );
    }

    /// Sets or, for `None`, removes a field of an alarm's row.
    pub(crate) fn row(&mut self, name: &str, field: &str, new: Option<Value>) {
        let row = self.alarms.get_mut(name).expect("the alarm exists");
        match new {
            Some(new) => row.insert(field, new),
            None => {
                row.remove(field);
            }
        }
    }

    pub(crate) fn script(&mut self, op: &'static str, actions: Vec<Action>) {
        self.script.insert(op, actions.into());
    }

    pub(crate) fn shape(&mut self, op: &'static str, shapes: Vec<Shape>) {
        self.shapes.insert(op, shapes.into());
    }

    pub(crate) fn ops(&self) -> Vec<String> {
        self.log.iter().map(|logged| logged.op.clone()).collect()
    }

    pub(crate) fn stops(&self) -> Vec<Logged> {
        self.log
            .iter()
            .filter(|logged| logged.op == STOP)
            .cloned()
            .collect()
    }

    /// Whether the record read that shows the stop has been made.
    pub(crate) fn shown(&self) -> bool {
        self.log.iter().any(|logged| logged.op == RECORD)
    }

    /// The index in the log of the call a fault marked.
    pub(crate) fn fault_index(&self) -> usize {
        self.log
            .iter()
            .position(|logged| logged.fault)
            .expect("the fault was planted")
    }

    /// Each call after the one the fault marked.
    pub(crate) fn after_fault(&self) -> Vec<String> {
        self.ops()[self.fault_index() + 1..].to_vec()
    }

    fn standing(&self) -> Vec<String> {
        let root = self.evidence.join("injection");
        let Ok(entries) = fs::read_dir(&root) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|entry| {
                let name = entry.expect("injection/ lists").file_name();
                let name = name.into_string().expect("a mark's name is UTF-8");
                name.strip_suffix(".json")
                    .map_or(name.clone(), str::to_owned)
            })
            .collect();
        names.sort();
        names
    }
}

pub(crate) fn string(text: &str) -> Value {
    Value::String(Text::from(text))
}

/// The seam over a shared [`State`].
pub(crate) struct Plane(pub(crate) Shared);

impl Seam for Plane {
    fn call(&mut self, record: &mut Record<'_>, call: &Call<'_>) -> Result<String, Ended> {
        let answer = self.0.borrow_mut().answer(call);
        if std::mem::take(&mut self.0.borrow_mut().interrupt) {
            record.read().map_err(Ended::Interrupted)?;
        }
        answer
    }

    fn wall(&self) -> f64 {
        let state = self.0.borrow();
        if let Some(reading) = state.reading.clone() {
            reading(&state);
        }
        state.wall()
    }

    fn monotonic(&self) -> f64 {
        let mut state = self.0.borrow_mut();
        if let Some(ticking) = state.ticking.clone() {
            ticking(&mut state);
        }
        state.t + MONOTONIC
    }

    fn sleep(&mut self, record: &mut Record<'_>, length: Duration) -> Result<(), Interrupted> {
        record.read()?;
        let mut state = self.0.borrow_mut();
        state.sleeps += 1;
        assert!(state.sleeps < 10_000, "the controller sleeps without end");
        state.t += length.as_secs_f64();
        if let Some(mut slept) = state.slept.take() {
            slept(&mut state);
            state.slept = Some(slept);
        }
        Ok(())
    }
}

impl State {
    fn answer(&mut self, call: &Call<'_>) -> Result<String, Ended> {
        let argv = call.argv;
        let n = argv.len();
        assert!(n >= 4, "{argv:?}");
        assert_eq!(
            &argv[n - 2..],
            ["--region", self.region.as_str()],
            "{argv:?}"
        );
        let timeout = call.cut.as_secs_f64();
        assert!(timeout > 0.0 && timeout <= CALL_SECONDS as f64, "{timeout}");
        let op = format!("{} {}", argv[0], argv[1]);
        let args: Vec<String> = argv[2..n - 2].iter().map(|arg| (*arg).to_owned()).collect();
        let begin = self.t;
        self.envs.push(call.env.to_vec());
        let marks = self.standing();
        let stop_json = (op == STOP)
            .then(|| fs::read_to_string(self.evidence.join("injection/stop.json")).ok())
            .flatten()
            .map(|json| value(&json));
        self.log.push(Logged {
            op: op.clone(),
            args: args.clone(),
            retry: call.retry,
            start: begin,
            timeout,
            left: self.deadline.map(|deadline| deadline - begin),
            marks,
            time: None,
            wall: None,
            cut: false,
            fault: false,
            stop_json,
        });
        let key = [CALLER, STATUS, RECORD, ALARMS, STOP]
            .into_iter()
            .find(|known| *known == op)
            .unwrap_or_else(|| panic!("{op} is one of the five calls"));
        let mut action = self
            .script
            .get_mut(key)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Action::Answer);
        if let Some(mut plan) = self.fault.take() {
            match plan(self, key) {
                Some(planted) => {
                    action = planted;
                    self.log.last_mut().expect("logged").fault = true;
                }
                None => self.fault = Some(plan),
            }
        }
        if let Action::Hook(hook) = action {
            action = hook(self);
        }
        let failed = |reason: &str| Err(Ended::Failed(CallFailed::no_answer(argv, reason)));
        let mut delay = 0.0;
        match action {
            Action::Delay(seconds) => delay = seconds,
            Action::Stall => {
                let _ = self.apply(key, &args);
                delay = CALL_SECONDS as f64;
            }
            Action::Late => {
                self.t = begin + timeout + 0.5;
                self.log.last_mut().expect("logged").time = Some(self.t);
                return self.apply(key, &args).map(|reply| text(&reply));
            }
            _ => {}
        }
        let spent = self.t - begin + self.call_seconds + delay;
        if spent >= timeout {
            self.t = begin + timeout;
            let logged = self.log.last_mut().expect("logged");
            logged.time = Some(self.t);
            logged.cut = true;
            return failed(&format!("timed out after {timeout} seconds"));
        }
        self.t = begin + spent;
        self.log.last_mut().expect("logged").time = Some(self.t);
        if matches!(action, Action::Refuse) {
            return failed("refused");
        }
        let mut reply = self.apply(key, &args)?;
        if let Some(shape) = self.shapes.get_mut(key).and_then(VecDeque::pop_front) {
            reply = shape(reply);
        }
        if matches!(action, Action::Lose) {
            return failed("the reply was lost");
        }
        if let Some(mut after) = self.after.take() {
            after(self, key);
            self.after = Some(after);
        }
        let wall = self.wall();
        self.log.last_mut().expect("logged").wall = Some(wall);
        Ok(text(&reply))
    }

    fn apply(&mut self, op: &str, args: &[String]) -> Result<Value, Ended> {
        match op {
            CALLER => Ok(value(&format!(
                r#"{{"UserId": "AROAEXAMPLE:gd2-run", "Account": "account", "Arn": {}}}"#,
                text(&string(&self.arn))
            ))),
            STATUS => self.describe_instance_status(args),
            RECORD => self.describe_instances(args),
            STOP => self.stop_instances(args),
            _ => Ok(self.describe_alarms(args)),
        }
    }

    fn ids(&self, args: &[String]) -> Result<Vec<String>, Ended> {
        let at = args
            .iter()
            .position(|arg| arg == "--instance-ids")
            .expect("the call names its instances");
        let ids = args[at + 1..].to_vec();
        for id in &ids {
            if !self.instances.contains_key(id) {
                let reason = format!("InvalidInstanceID.NotFound {id}");
                return Err(Ended::Failed(CallFailed::no_answer(
                    &["ec2", "call"],
                    reason,
                )));
            }
        }
        Ok(ids)
    }

    fn describe_instance_status(&mut self, args: &[String]) -> Result<Value, Ended> {
        assert_eq!(args[0], "--include-all-instances", "{args:?}");
        let mut rows = Vec::new();
        for id in self.ids(args)? {
            let stopping = self.stopping.as_deref() == Some(id.as_str());
            let instance = self.instances.get_mut(&id).expect("checked");
            if stopping && instance.state == "stopping" {
                self.stop_reads += 1;
                if self
                    .stop_after
                    .is_some_and(|after| self.stop_reads >= after)
                {
                    instance.state = "stopped".to_owned();
                }
            }
            let running = instance.state == "running";
            let check = |status: &str| {
                if running {
                    status.to_owned()
                } else {
                    "not-applicable".to_owned()
                }
            };
            rows.push(value(&format!(
                r#"{{"InstanceId": {}, "AvailabilityZone": "us-west-2a",
                    "InstanceState": {{"Code": 16, "Name": {}}},
                    "InstanceStatus": {{"Status": {}, "Details": []}},
                    "SystemStatus": {{"Status": {}, "Details": []}}}}"#,
                text(&string(&id)),
                text(&string(&instance.state)),
                text(&string(&check(&instance.checks))),
                text(&string(&check(&instance.system))),
            )));
        }
        let mut reply = Object::new();
        reply.insert("InstanceStatuses", Value::Array(rows));
        Ok(Value::Object(reply))
    }

    fn describe_instances(&mut self, args: &[String]) -> Result<Value, Ended> {
        let ids = self.ids(args)?;
        let [id] = ids.as_slice() else {
            panic!("a record read names one instance: {ids:?}")
        };
        let instance = &self.instances[id];
        let mut row = value(&format!(
            r#"{{"InstanceId": {}, "State": {{"Code": 80, "Name": {}}},
                "StateTransitionReason": {}, "LaunchTime": {}}}"#,
            text(&string(id)),
            text(&string(&instance.state)),
            text(&string(&instance.transition)),
            text(&string(&launch_text(instance.launched))),
        ));
        if let (Value::Object(row), Some(reason)) = (&mut row, &instance.reason) {
            let mut state_reason = Object::new();
            state_reason.insert("Code", string(reason));
            state_reason.insert("Message", string(reason));
            row.insert("StateReason", Value::Object(state_reason));
        }
        let mut reservation = Object::new();
        reservation.insert("ReservationId", string("r-1"));
        reservation.insert("Instances", Value::Array(vec![row]));
        let mut reply = Object::new();
        reply.insert(
            "Reservations",
            Value::Array(vec![Value::Object(reservation)]),
        );
        Ok(Value::Object(reply))
    }

    /// A stop request of a running instance: it reads `stopping`, with a user's shutdown dated at
    /// the request's second plus `transition_offset`, until `stop_after` status reads.
    pub(crate) fn stop_instances(&mut self, args: &[String]) -> Result<Value, Ended> {
        let ids = self.ids(args)?;
        let [id] = ids.as_slice() else {
            panic!("a stop request names one instance: {ids:?}")
        };
        let second = self.t.floor() as i64 + self.transition_offset;
        let code = self.stop_code.clone();
        let instance = self.instances.get_mut(id).expect("checked");
        if instance.state == "running" {
            instance.state = "stopping".to_owned();
            instance.reason = Some(code);
            instance.transition = format!("User initiated ({} GMT)", calendar(second, ' '));
            self.stopping = Some(id.clone());
            self.stop_reads = 0;
        }
        Ok(value(&format!(
            r#"{{"StoppingInstances": [{{"InstanceId": {}, "CurrentState": {{"Code": 64, "Name": {}}},
                "PreviousState": {{"Code": 16, "Name": "running"}}}}]}}"#,
            text(&string(id)),
            text(&string(&self.stop_reply)),
        )))
    }

    fn describe_alarms(&self, args: &[String]) -> Value {
        assert_eq!(
            &args[..3],
            ["--alarm-types", "MetricAlarm", "--alarm-names"],
            "{args:?}"
        );
        let mut rows = Vec::new();
        for name in &args[3..] {
            if let Some(fields) = self.alarms.get(name) {
                let mut row = Object::new();
                row.insert("AlarmName", string(name));
                row.insert("MetricName", string("Errors"));
                row.insert("Namespace", string("Kestrike/GameDay"));
                for (key, field) in fields.iter() {
                    row.insert(key.clone(), field.clone());
                }
                rows.push(Value::Object(row));
            }
        }
        let mut reply = Object::new();
        reply.insert("MetricAlarms", Value::Array(rows));
        Value::Object(reply)
    }
}

/// `seconds` as `YYYY-MM-DD?HH:MM:SS` in UTC, `separator` at `?`.
pub(crate) fn calendar(seconds: i64, separator: char) -> String {
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}{separator}{:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// A `describe-instances` `LaunchTime`: whole seconds, a fraction of three digits when `seconds`
/// holds one, and `+00:00`.
pub(crate) fn launch_text(seconds: f64) -> String {
    let whole = calendar(seconds.floor() as i64, 'T');
    let fraction = seconds - seconds.floor();
    if fraction == 0.0 {
        format!("{whole}+00:00")
    } else {
        format!(
            "{whole}.{:03}+00:00",
            (fraction * 1000.0).round_ties_even() as i64
        )
    }
}
