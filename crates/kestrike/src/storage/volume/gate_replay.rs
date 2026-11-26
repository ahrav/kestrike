//! Replays committed traces of the attach-gate model `quint/gate.qnt` against
//! a [`Volume`](super::super::super::Volume) attached over the reservation registry
//! double of `gate_fixture`, single-threaded.
//!
//! Each model step runs its production calls, and the replay then requires
//! the volume's projected state to equal the model's state: the count of
//! reservation commands the driver logged, the gate's step and whether its
//! command is outstanding, the attach outcome with the step a `command`
//! refusal names, the device's loss, the serving machine's state and flip
//! request, the driver's medium admissions, whether a medium command reached
//! the driver or the simulated device, and the readiness word.
//!
//! # Pacing
//!
//! The driver refuses every reservation submit with a full queue outside a
//! model tick, and it holds every completion until the model delivers it, so
//! the polls of one model step move the gate by that step alone. A tick
//! stages the submit result its outcome names: `submitted` accepts the
//! command, `busy` and `idle` keep the full queue, `lost` refuses with
//! `DeviceGone` and `command` with `InvalidRange`.
//!
//! # Completions and events
//!
//! A model completion stages its view in the registry before the driver
//! executes the command. A registrant entry or a reservation type lets the
//! driver's own rules produce the status and the Report bytes; a Report check
//! error or a set status replaces them. The own host ID under another key makes the Register
//! conflict, and a foreign holder makes the Acquire conflict. A Report's
//! `unreadable` outcome fails the driver's Report check, so the command table
//! withholds the bytes; `command` completes the Report with generic status
//! 0x6, a failure that leaves the serving machine in place; `authority`
//! completes it with Reservation Conflict, which deposes the machine.
//!
//! `expire`, `withdraw` and `close` deliver the serving-machine event and then
//! poll. `timeout` sets the serving clock, which starts at zero, to the
//! authority's Report deadline plus one microsecond and polls.
//!
//! `storage::volume::attach::tests::a_withdrawal_close_or_window_expiry_during_any_gate_step_ends_the_attach`
//! exercises a `Cause::Planned` withdrawal during the gate.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::super::ServingAuthority;
use super::super::super::authority_tests::Clock;
use super::super::super::gate_fixture::{
    arena, attach_reserving, foreign, medium, own, storage, ticks,
};
use super::super::super::metadata::Phase;
use super::super::{GateRefusal, GateStep};
use crate::failover::evidence::{Pair, RESERVATION_CONFLICT, Registrant};
use crate::failover::serving::{Cause, Event, State as Serving};
use crate::storage::device::{DeviceStatus, RefusalReason, ReportError, ReservationCommand};
use crate::storage::readiness::State as Readiness;
use crate::storage::recovery::MetadataOutcome;

const MODEL: &[u8] = include_bytes!("../../../../../quint/gate.qnt");
/// The key of the model's state record in each trace state.
const STATE: &str = "gateCase::gate::st";
/// The traces `quint/gate_fixtures.py` writes: eighteen directed recipes, then eight seeded runs of twelve steps
/// of the model's `step`, each named `step_` and its seed in hexadecimal.
const FIXTURES: [(&str, &str); 26] = [
    (
        "passes",
        include_str!("gate_replay_fixtures/passes.itf.json"),
    ),
    (
        "busy_then_foreign_registrant",
        include_str!("gate_replay_fixtures/busy_then_foreign_registrant.itf.json"),
    ),
    (
        "acquire_conflict",
        include_str!("gate_replay_fixtures/acquire_conflict.itf.json"),
    ),
    (
        "report_times_out",
        include_str!("gate_replay_fixtures/report_times_out.itf.json"),
    ),
    (
        "register_conflict",
        include_str!("gate_replay_fixtures/register_conflict.itf.json"),
    ),
    (
        "submit_refused",
        include_str!("gate_replay_fixtures/submit_refused.itf.json"),
    ),
    (
        "device_gone",
        include_str!("gate_replay_fixtures/device_gone.itf.json"),
    ),
    (
        "foreign_holder",
        include_str!("gate_replay_fixtures/foreign_holder.itf.json"),
    ),
    (
        "other_type",
        include_str!("gate_replay_fixtures/other_type.itf.json"),
    ),
    (
        "duplicate_own_record",
        include_str!("gate_replay_fixtures/duplicate_own_record.itf.json"),
    ),
    (
        "own_pair_not_holding",
        include_str!("gate_replay_fixtures/own_pair_not_holding.itf.json"),
    ),
    (
        "withheld_bytes",
        include_str!("gate_replay_fixtures/withheld_bytes.itf.json"),
    ),
    (
        "failed_report",
        include_str!("gate_replay_fixtures/failed_report.itf.json"),
    ),
    (
        "deposing_report",
        include_str!("gate_replay_fixtures/deposing_report.itf.json"),
    ),
    (
        "expiry_under_the_register",
        include_str!("gate_replay_fixtures/expiry_under_the_register.itf.json"),
    ),
    (
        "withdrawal_under_the_acquire",
        include_str!("gate_replay_fixtures/withdrawal_under_the_acquire.itf.json"),
    ),
    (
        "close_under_the_report",
        include_str!("gate_replay_fixtures/close_under_the_report.itf.json"),
    ),
    (
        "close_before_the_register",
        include_str!("gate_replay_fixtures/close_before_the_register.itf.json"),
    ),
    (
        "step_1221",
        include_str!("gate_replay_fixtures/step_1221.itf.json"),
    ),
    (
        "step_1222",
        include_str!("gate_replay_fixtures/step_1222.itf.json"),
    ),
    (
        "step_1223",
        include_str!("gate_replay_fixtures/step_1223.itf.json"),
    ),
    (
        "step_1224",
        include_str!("gate_replay_fixtures/step_1224.itf.json"),
    ),
    (
        "step_1225",
        include_str!("gate_replay_fixtures/step_1225.itf.json"),
    ),
    (
        "step_1226",
        include_str!("gate_replay_fixtures/step_1226.itf.json"),
    ),
    (
        "step_1227",
        include_str!("gate_replay_fixtures/step_1227.itf.json"),
    ),
    (
        "step_1228",
        include_str!("gate_replay_fixtures/step_1228.itf.json"),
    ),
];

/// How the replay maps a model step to production calls. Each variant after `Faithful` hides one fact from
/// production and serves as a negative control.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model action runs its production calls.
    Faithful,
    /// A foreign registrant's Report shows the own pair alone.
    RegistrantHidden,
    /// The model's serving-machine events run nothing.
    EventDropped,
    /// The model's Acquire conflict completes as a success.
    ConflictHidden,
}

/// Replaces every ITF big integer with a JSON number.
fn plain(v: &mut Value) {
    match v {
        Value::Object(map) if map.contains_key("#bigint") => {
            *v = map["#bigint"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap()
                .into();
        }
        Value::Object(map) => map.values_mut().for_each(plain),
        Value::Array(list) => list.iter_mut().for_each(plain),
        _ => {}
    }
}

/// The attach state the model and production are compared in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    /// The count of reservation commands the driver logged.
    sent: u64,
    /// The gate's next or outstanding step, numbered as the model numbers it, and whether its command is
    /// outstanding; `Some` while the attach has no outcome and the device is present.
    gate: Option<(u64, bool)>,
    /// `""` while bootstrapping, `"fenced"` once the gate passed, otherwise the refusal.
    outcome: String,
    /// The step a `command` refusal names.
    failed: Option<u64>,
    lost: bool,
    /// The serving machine's state: `"pre"`, `"recovering"`, `"withdrawn"` or `"closed"`.
    machine: String,
    /// Whether the serving machine requests a flip.
    flip: bool,
    /// The count of medium admissions the volume granted the driver.
    admissions: u64,
    /// Whether a medium command reached the driver or the simulated device.
    medium: bool,
    /// The readiness word: `"detached"`, `"loading"` or `"withheld"`.
    ready: String,
}

/// The projection of the model's state record; the model's `failed` of -1 stands for no failed step.
///
/// # Errors
///
/// A field it reads that is missing or has another JSON type, a count below zero, or a `failed` below -1, named
/// `model` and its key. It reads `step` and `pending` only while the gate runs.
fn modeled(model: &Value) -> Result<Seen, String> {
    let flag = |key: &str| model[key].as_bool().ok_or(format!("model {key}"));
    let number = |key: &str| model[key].as_u64().ok_or(format!("model {key}"));
    let text = |key: &str| {
        model[key]
            .as_str()
            .map(str::to_owned)
            .ok_or(format!("model {key}"))
    };
    let (outcome, lost) = (text("outcome")?, flag("lost")?);
    Ok(Seen {
        sent: number("sent")?,
        gate: (outcome.is_empty() && !lost)
            .then(|| Ok::<_, String>((number("step")?, flag("pending")?)))
            .transpose()?,
        failed: match model["failed"].as_i64() {
            Some(-1) => None,
            Some(step) if step >= 0 => Some(step as u64),
            _ => return Err("model failed".into()),
        },
        outcome,
        lost,
        machine: text("machine")?,
        flip: flag("flip")?,
        admissions: number("admissions")?,
        medium: flag("medium")?,
        ready: text("ready")?,
    })
}

/// The model's number for `step`: its `REGISTER`, `ACQUIRE` and `REPORT` constants.
fn step_of(step: GateStep) -> u64 {
    match step {
        GateStep::Register => 0,
        GateStep::Acquire => 1,
        GateStep::Report => 2,
    }
}

/// Replays one trace and returns the `(action, outcome)` of every state, `init` first.
///
/// # Errors
///
/// A trace that fails to parse as JSON, whose model digest differs from the
/// SHA-256 of `quint/gate.qnt`, whose `states` is other than an array, or
/// whose length differs from its recorded step count plus one. Otherwise the
/// first state:
///
/// - whose event or model field is malformed, an error that names the field;
/// - whose event action differs from the action the trace took, an error
///   that names the state's index;
/// - whose action is unknown, which includes `init` after state 0, or whose
///   outcome is unknown to a tick or a completion;
/// - at which the volume's state differs from the model's;
/// - at which the volume's state lies outside the projection: a reservation
///   log other than a prefix of Register, Acquire, Report, a flip request for
///   another target, or a serving state, attach outcome or readiness the
///   model lacks.
///
/// The errors of the last three kinds name the state's action and index.
///
/// # Panics
///
/// If an ITF big integer of the trace is malformed.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["gate"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if Some(states.len() as u64)
        != trace["#meta"]["gate"]["steps"]
            .as_u64()
            .map(|steps| steps + 1)
    {
        return Err("fixture length".into());
    }

    let authority = ServingAuthority::fixture();
    let target = authority.session().target();
    let arena = arena();
    let storage = storage();
    let (mut dev, control, registry) = attach_reserving(&storage, &arena, authority);
    let clock = Rc::new(Cell::new(0));
    dev.set_serving_clock(Box::new(Clock(Rc::clone(&clock))));
    {
        let mut registry = registry.borrow_mut();
        registry.budget = Some(0);
        registry.refuse = Some(RefusalReason::QueueFull);
    }
    // The Report is the third ordered reservation command, so it carries ordinal 3.
    let gate_log = [
        ReservationCommand::Register { new: own().key },
        ReservationCommand::Acquire { current: own().key },
        ReservationCommand::Report { not_before: 3 },
    ];
    let entry = |cntlid, holder, pair| Registrant {
        cntlid,
        holder,
        pair,
    };
    // The own host ID under the foreign pair's key.
    let rekeyed = Pair {
        key: foreign().key,
        ..own()
    };

    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let ev = &model["ev"];
        let (act, res) = (
            ev["act"].as_str().ok_or("event action")?,
            ev["res"].as_str().ok_or("event outcome")?,
        );
        if state["mbt::actionTaken"] != act {
            return Err(format!("action {i}: the event names another action"));
        }
        let unknown = || format!("{act} at {i}: unknown outcome {res}");
        // Delivers the one held completion.
        let deliver = |dev: &mut _| {
            registry.borrow_mut().budget = Some(1);
            ticks(dev, &control, 2);
            registry.borrow_mut().budget = Some(0);
        };
        match act {
            "init" if i == 0 => {}
            "tick" => {
                registry.borrow_mut().refuse = match res {
                    "submitted" => None,
                    "busy" | "idle" => Some(RefusalReason::QueueFull),
                    "lost" => Some(RefusalReason::DeviceGone),
                    "command" => Some(RefusalReason::InvalidRange),
                    _ => return Err(unknown()),
                };
                ticks(&mut dev, &control, 2);
                registry.borrow_mut().refuse = Some(RefusalReason::QueueFull);
            }
            "register" => {
                match res {
                    "ok" => {}
                    "command" => registry
                        .borrow_mut()
                        .entries
                        .push(entry(11, false, rekeyed)),
                    _ => return Err(unknown()),
                }
                deliver(&mut dev);
            }
            "acquire" => {
                match res {
                    "ok" => {}
                    "command" if driver == Driver::ConflictHidden => {}
                    "command" => registry
                        .borrow_mut()
                        .entries
                        .push(entry(20, true, foreign())),
                    _ => return Err(unknown()),
                }
                deliver(&mut dev);
            }
            "report" => {
                {
                    let mut registry = registry.borrow_mut();
                    match res {
                        "fenced" => {}
                        "registrant" if driver == Driver::RegistrantHidden => {}
                        "registrant" => registry.entries.push(entry(20, false, foreign())),
                        "holder" => registry.entries.push(entry(20, true, foreign())),
                        "type" => registry.rtype = 0,
                        "duplicate" => registry.entries.push(entry(11, false, own())),
                        "notholder" => {
                            for entry in &mut registry.entries {
                                entry.holder = false;
                            }
                        }
                        "unreadable" => registry.report_check = Some(ReportError::Truncated),
                        "command" => registry.report_status = Some(DeviceStatus::Nvme(0x6 << 1)),
                        "authority" => {
                            registry.report_status =
                                Some(DeviceStatus::Nvme(RESERVATION_CONFLICT << 1));
                        }
                        _ => return Err(unknown()),
                    }
                }
                deliver(&mut dev);
            }
            "expire" | "withdraw" | "close" if driver == Driver::EventDropped => {}
            "expire" | "withdraw" | "close" => {
                let _ = dev.authority_event(match act {
                    "expire" => Event::Expire { now: 0 },
                    "withdraw" => Event::Withdraw(Cause::Attachment),
                    _ => Event::Close,
                });
                ticks(&mut dev, &control, 2);
            }
            "timeout" => {
                clock.set(dev.authority.bounds.report_deadline() + 1);
                ticks(&mut dev, &control, 2);
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        }

        let log = registry.borrow().log.clone();
        if log.as_slice() != &gate_log[..log.len().min(3)] || log.len() > 3 {
            return Err(format!("{act} at {i}: reservation commands {log:?}"));
        }
        let report = dev.authority_report();
        if report.flip.is_some_and(|flip| flip != target) {
            return Err(format!("{act} at {i}: the flip names another target"));
        }
        let fenced = dev.metadata.fenced.is_some();
        let (outcome, failed) = match dev.metadata_outcome() {
            MetadataOutcome::Unfenced(refusal) => match refusal {
                GateRefusal::CommandFailed(step) => ("command", Some(step_of(step))),
                GateRefusal::AuthorityLost => ("authority", None),
                GateRefusal::ReportUnreadable => ("unreadable", None),
                GateRefusal::ReservationType => ("type", None),
                GateRefusal::ForeignHolder => ("holder", None),
                GateRefusal::ForeignRegistrant => ("registrant", None),
                GateRefusal::DuplicateOwnRecord => ("duplicate", None),
                GateRefusal::NotHolder => ("notholder", None),
                GateRefusal::Unsupported => {
                    return Err(format!("{act} at {i}: outcome {refusal:?}"));
                }
            },
            _ if fenced => ("fenced", None),
            MetadataOutcome::Bootstrapping => ("", None),
            outcome => return Err(format!("{act} at {i}: outcome {outcome:?}")),
        };
        let lost = dev.is_lost();
        let seen = Seen {
            sent: log.len() as u64,
            gate: match dev.metadata.phase {
                Phase::Gate { step, pending } if outcome.is_empty() && !lost => {
                    Some((step_of(step), pending.is_some()))
                }
                _ => None,
            },
            outcome: outcome.into(),
            failed,
            lost,
            machine: match report.state {
                Serving::PreBoundary => "pre",
                Serving::Recovering => "recovering",
                Serving::Withdrawn => "withdrawn",
                Serving::Closed => "closed",
                state => return Err(format!("{act} at {i}: serving state {state:?}")),
            }
            .into(),
            flip: report.flip.is_some(),
            admissions: registry.borrow().admissions.len() as u64,
            medium: medium(&control) > 0 || registry.borrow().medium > 0,
            ready: match dev.readiness() {
                Readiness::Detached => "detached",
                Readiness::Loading => "loading",
                Readiness::Withheld => "withheld",
                state => return Err(format!("{act} at {i}: readiness {state:?}")),
            }
            .into(),
        };
        let model = modeled(model)?;
        if seen != model {
            return Err(format!("{act} at {i}: {seen:?}, modeled {model:?}"));
        }
        reached.push((act.to_owned(), res.to_owned()));
    }
    Ok(reached)
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap()
        .1
}

/// Every committed trace replays with the volume's projected state equal to
/// the model's at every state, and together the traces reach `init`, each of
/// the eight actions the model's `step` chooses among and every outcome an
/// action records.
#[test]
fn committed_gate_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        reached.extend(
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}")),
        );
    }
    assert!(
        std::str::from_utf8(MODEL).unwrap().contains(
            "    any {tick(refusal), register(ok), acquire(ok), report(view), expire, withdraw, close, timeout}\n"
        ),
        "the model's step chooses among other actions than the replay drives"
    );
    let outcomes: BTreeSet<(&str, &str)> = reached
        .iter()
        .map(|(act, res)| (act.as_str(), res.as_str()))
        .collect();
    assert_eq!(
        outcomes,
        BTreeSet::from([
            ("acquire", "command"),
            ("acquire", "ok"),
            ("close", "authority"),
            ("expire", "authority"),
            ("init", ""),
            ("register", "command"),
            ("register", "ok"),
            ("report", "authority"),
            ("report", "command"),
            ("report", "duplicate"),
            ("report", "fenced"),
            ("report", "holder"),
            ("report", "notholder"),
            ("report", "registrant"),
            ("report", "type"),
            ("report", "unreadable"),
            ("tick", "busy"),
            ("tick", "command"),
            ("tick", "idle"),
            ("tick", "lost"),
            ("tick", "submitted"),
            ("timeout", "authority"),
            ("withdraw", "authority"),
        ])
    );
}

/// The state of a gate that still runs with `sent` commands submitted: the
/// machine before the boundary, the readiness word detached and no medium
/// admission or command. Each driver control derives its expected production
/// and model states from it.
fn running(sent: u64, gate: (u64, bool)) -> Seen {
    Seen {
        sent,
        gate: Some(gate),
        outcome: String::new(),
        failed: None,
        lost: false,
        machine: "pre".into(),
        flip: false,
        admissions: 0,
        medium: false,
        ready: "detached".into(),
    }
}

/// Each wrong driver hides one fact the model's step stands for, and the
/// replay refuses it at the first state the missing fact shows in, through
/// the comparison of the projected state: a Report that hides the foreign
/// registrant passes the gate where the model refuses, a dropped withdrawal
/// leaves the gate running under its outstanding Acquire, and an Acquire
/// conflict delivered as a success moves the gate on to its Report.
#[test]
fn negative_control_a_driver_that_hides_a_fact_fails_the_replay_at_that_step() {
    // busy_then_foreign_registrant: a busy tick, the three commands, then report("registrant") at state 7.
    let refused = Seen {
        sent: 3,
        gate: None,
        outcome: "registrant".into(),
        machine: "withdrawn".into(),
        flip: true,
        ready: "withheld".into(),
        ..running(3, (2, true))
    };
    let passed = Seen {
        outcome: "fenced".into(),
        machine: "recovering".into(),
        flip: false,
        admissions: 1,
        medium: true,
        ready: "loading".into(),
        ..refused.clone()
    };
    assert_eq!(
        replay(
            fixture("busy_then_foreign_registrant"),
            Driver::RegistrantHidden
        )
        .unwrap_err(),
        format!("report at 7: {passed:?}, modeled {refused:?}")
    );
    // withdrawal_under_the_acquire: tick, register(true), tick, withdraw at state 4.
    let seen = running(2, (1, true));
    let model = Seen {
        gate: None,
        outcome: "authority".into(),
        machine: "withdrawn".into(),
        flip: true,
        ready: "withheld".into(),
        ..seen.clone()
    };
    assert_eq!(
        replay(
            fixture("withdrawal_under_the_acquire"),
            Driver::EventDropped
        )
        .unwrap_err(),
        format!("withdraw at 4: {seen:?}, modeled {model:?}")
    );
    // acquire_conflict: tick, register(true), tick, acquire(false) at state 4.
    let seen = running(2, (2, false));
    let model = Seen {
        gate: None,
        outcome: "command".into(),
        failed: Some(1),
        machine: "withdrawn".into(),
        ready: "withheld".into(),
        ..seen.clone()
    };
    assert_eq!(
        replay(fixture("acquire_conflict"), Driver::ConflictHidden).unwrap_err(),
        format!("acquire at 4: {seen:?}, modeled {model:?}")
    );
}

/// A trace altered in one projected field of one state fails at that state, through
/// the comparison that reads the field, and a state whose recorded action
/// differs from its event's fails at that state before its calls run; a stale
/// model digest or a missing state fails the trace before any state replays.
#[test]
fn negative_control_an_altered_trace_fails_at_the_altered_state() {
    // passes: tick, register(true), tick, acquire(true), tick, report("sole") at state 6, tick.
    let json = fixture("passes");
    let altered = |state: usize, field: &str, value: Value| {
        let mut trace: Value = serde_json::from_str(json).unwrap();
        trace["states"][state][STATE][field] = value;
        replay(&trace.to_string(), Driver::Faithful).unwrap_err()
    };
    assert!(
        altered(6, "admissions", serde_json::json!({"#bigint": "0"}))
            .starts_with("report at 6: Seen { sent: 3, gate: None, outcome: \"fenced\",")
    );
    assert!(altered(6, "medium", false.into()).starts_with("report at 6: "));
    assert!(altered(4, "ready", "loading".into()).starts_with("acquire at 4: "));
    assert!(altered(3, "sent", serde_json::json!({"#bigint": "3"})).starts_with("tick at 3: "));
    assert!(altered(2, "pending", true.into()).starts_with("register at 2: "));
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][4]["mbt::actionTaken"] = "tick".into();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "action 4: the event names another action"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"].as_array_mut().unwrap().pop();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "fixture length"
    );
}
