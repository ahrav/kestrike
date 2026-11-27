//! Replays committed traces of the register model `quint/register.qnt` against a live [`Storage`] on the heap-backed platform with two registration records.
//!
//! Each model step runs the storage code for one model action: `Storage::register`; `Registration::enter` followed by the guard's test-only `exit` or by `mem::forget` of the guard; the registration's drop or `mem::forget`; and `Storage::close`. For the two actions that land the close inside a call, the replay arms the hook `register.rs` offers its tests at that point, `INTERPOSE_BEFORE_CUTOFF` between a registration's claim and its cutoff read or `INTERPOSE_AFTER_PIN` between an entry's pin and its cutoff read, with a function that stores the cutoff, and requires that the hook ran.
//! The replay then requires the call's return to equal the step's recorded event, and both records' reports (claimed, pinned era, intervals), the cutoff and the count of outstanding registrations to equal the model's state.
//! The model's `held` flag says whether the replay still holds a record's handle; `late` and `kept` are history the model's invariants read, and they stay inside the model, where `quint run --invariant safety` checks them as each trace is generated.
//!
//! `bash scripts/tool.sh register_fixtures --quint QUINT --output DIR` writes the traces with `quint run --mbt`: five directed recipes and six traces of fourteen steps of the model's own `step` under pinned seeds. Each trace names the model's sha256, and a trace of another model text fails before any state replays.
//! The replay is evidence for exactly the schedules these traces record, one call at a time; the close inside a call lands only at the two hooks.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::RegistrationIndex;
use super::grace::ERA_FIRST;
use super::grace_tests::unclaimed_storage;
use super::register::{
    INTERPOSE_AFTER_PIN, INTERPOSE_BEFORE_CUTOFF, PinError, RegisterError, Registration,
    RegistrationReport,
};
use super::test_platform::TestPlatform;

const MODEL: &[u8] = include_bytes!("../../../../quint/register.qnt");
const STATE: &str = "registerCase::register::st";
/// The model's registration records.
const RECORDS: usize = 2;

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("register_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 11] = fixtures![
    "closeRacesAnEntry",
    "leakedGuardBlocks",
    "limitAndReturn",
    "forgottenHandles",
    "leakedAcrossTheClose",
    "step_a",
    "step_b",
    "step_c",
    "step_d",
    "step_e",
    "step_f",
];

/// How the replay maps a model step to storage calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model action runs its storage code.
    Faithful,
    /// The model's drop keeps the registration.
    DropSkipped,
    /// The model's entry that the close lands inside runs with no hook armed.
    CloseNotArmed,
    /// The model's leaked guard exits.
    LeakExits,
}

/// Stores the cutoff, as `Storage::close` does; the hooks pass the cutoff word.
fn close(cutoff: &AtomicBool) {
    cutoff.store(true, Ordering::SeqCst);
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

fn n(v: &Value, key: &str) -> i64 {
    v[key].as_i64().unwrap()
}

/// What the storage holds, in the order the model's state is read: the cutoff, each record's report and the outstanding registrations.
type Held = (bool, [RegistrationReport; RECORDS], usize);

/// What the model's state holds, as the replay reads the storage.
fn modelled(model: &Value) -> Result<Held, String> {
    let mut reports = [RegistrationReport {
        claimed: false,
        pinned_era: None,
        intervals: 0,
    }; RECORDS];
    for row in model["recs"]["#map"].as_array().ok_or("model records")? {
        let (at, record) = (row[0].as_i64().ok_or("record number")?, &row[1]);
        // Record -1 stands for no record.
        let Some(report) = usize::try_from(at).ok().and_then(|at| reports.get_mut(at)) else {
            continue;
        };
        let pin = n(record, "pin") as u64;
        *report = RegistrationReport {
            claimed: record["claimed"].as_bool().ok_or("claimed flag")?,
            pinned_era: (pin != 0).then_some(pin),
            intervals: n(record, "intervals") as u64,
        };
    }
    let claimed = reports.iter().filter(|report| report.claimed).count();
    Ok((model["closed"].as_bool().ok_or("cutoff")?, reports, claimed))
}

/// Replays one trace and returns the `(action, outcome)` of every state, `init` first.
///
/// # Errors
///
/// A trace that fails to parse or whose model digest or length is wrong; a step whose field the replay cannot read or that names an unknown action; a step whose hook did not run; an entry the storage refuses `Contended`; otherwise the first step whose action name, storage return or storage state differ from the model's event and state, named with its index.
///
/// # Panics
///
/// If a number the trace records is missing or is not an integer, a recorded record lies outside the model's, or a step names a record whose handle the replay does not hold.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["register"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as i64 != n(&trace["#meta"]["register"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let storage = unclaimed_storage(1, RECORDS);
    let mut handles: [Option<Registration<'_, TestPlatform>>; RECORDS] = [None, None];
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let ev = &model["ev"];
        let (act, res) = (
            ev["act"].as_str().ok_or("event action")?,
            ev["res"].as_str().ok_or("event outcome")?,
        );
        // A trace of the model's `step` names the action or the wrapper that draws its record.
        let taken = state["mbt::actionTaken"].as_str().ok_or("action taken")?;
        if !taken
            .strip_prefix("some")
            .unwrap_or(taken)
            .eq_ignore_ascii_case(act)
        {
            return Err(format!("action {i}: the event names another action"));
        }
        let at = n(ev, "record") as usize;
        // The storage's return in the model's terms: the outcome and the value.
        let (outcome, value): (&str, i64) = match act {
            "init" if i == 0 => ("", 0),
            "register" | "registerRacingClose" => {
                let racing = act == "registerRacingClose";
                if racing {
                    INTERPOSE_BEFORE_CUTOFF.with(|hook| hook.set(Some(close)));
                }
                let registered = storage.register();
                if racing && INTERPOSE_BEFORE_CUTOFF.with(|hook| hook.take()).is_some() {
                    return Err(format!("{act} at {i}: the hook did not run"));
                }
                match registered {
                    Ok(registration) => {
                        let record = registration.index().0;
                        handles[record] = Some(registration);
                        ("Ok", record as i64)
                    }
                    Err(RegisterError::Closed) => ("Closed", -1),
                    Err(RegisterError::ReaderLimit) => ("ReaderLimit", -1),
                }
            }
            "interval" | "leak" | "intervalRacingClose" => {
                let racing = act == "intervalRacingClose" && driver != Driver::CloseNotArmed;
                if racing {
                    INTERPOSE_AFTER_PIN.with(|hook| hook.set(Some(close)));
                }
                let registration = handles[at].as_mut().expect("a held registration");
                let index = registration.index();
                let entered = match registration.enter() {
                    Ok(guard) => {
                        let pinned = storage.registration_report(index).unwrap().pinned_era;
                        if act == "leak" && driver != Driver::LeakExits {
                            std::mem::forget(guard);
                        } else {
                            guard.exit();
                        }
                        ("Ok", pinned.map_or(0, |era| era as i64))
                    }
                    Err(PinError::Closed) => ("Closed", 0),
                    Err(PinError::Leaked) => ("Leaked", 0),
                    Err(PinError::Contended) => return Err(format!("{act} at {i}: Contended")),
                };
                if racing && INTERPOSE_AFTER_PIN.with(|hook| hook.take()).is_some() {
                    return Err(format!("{act} at {i}: the hook did not run"));
                }
                entered
            }
            "drop" => {
                let leaked = storage
                    .registration_report(RegistrationIndex(at))
                    .unwrap()
                    .pinned_era
                    .is_some();
                let registration = handles[at].take().expect("a held registration");
                if driver == Driver::DropSkipped {
                    handles[at] = Some(registration);
                } else {
                    drop(registration);
                }
                ("Ok", i64::from(leaked))
            }
            "forget" => {
                std::mem::forget(handles[at].take().expect("a held registration"));
                ("Ok", 0)
            }
            "close" => {
                storage.close();
                ("Ok", 0)
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        let recorded = (res, n(ev, "value"));
        if (outcome, value) != recorded {
            return Err(format!(
                "{act} at {i}: {outcome} {value}, recorded {recorded:?}"
            ));
        }
        let report = |record| {
            storage
                .registration_report(RegistrationIndex(record))
                .unwrap()
        };
        let held: Held = (
            storage.is_closed(),
            [report(0), report(1)],
            storage.outstanding().registrations,
        );
        if held != modelled(model)? {
            return Err(format!("state at {i}: {held:?}"));
        }
        reached.push((act.to_owned(), res.to_owned()));
    }
    Ok(reached)
}

/// The era every pin of these traces holds: the model's one era is the storage's first.
const _: () = assert!(ERA_FIRST == 1);

/// Every committed trace replays, and together the traces reach `init` and every choice of the model's `step` with each of its outcomes.
#[test]
fn committed_register_traces_replay_against_a_live_storage() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        let steps =
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}"));
        reached.extend(steps);
    }
    let expected: BTreeSet<(String, String)> = [
        ("init", ""),
        ("register", "Ok"),
        ("register", "ReaderLimit"),
        ("register", "Closed"),
        ("registerRacingClose", "Closed"),
        ("interval", "Ok"),
        ("interval", "Closed"),
        ("interval", "Leaked"),
        ("leak", "Ok"),
        ("intervalRacingClose", "Closed"),
        ("drop", "Ok"),
        ("forget", "Ok"),
        ("close", "Ok"),
    ]
    .into_iter()
    .map(|(act, outcome)| (act.to_owned(), outcome.to_owned()))
    .collect();
    assert_eq!(reached, expected);
}

/// A driver that enters without arming the close, one that exits a guard the model leaks and one that keeps a dropped registration each fail the replay at the step they change, through the replay's own comparison.
#[test]
fn negative_control_a_wrong_register_driver_fails_the_replay_at_its_step() {
    let trace = |name: &str| FIXTURES.iter().find(|(n, _)| *n == name).unwrap().1;
    for (name, driver, at) in [
        (
            "closeRacesAnEntry",
            Driver::CloseNotArmed,
            r#"intervalRacingClose at 3: Ok 1, recorded ("Closed", 0)"#,
        ),
        ("leakedGuardBlocks", Driver::LeakExits, "state at 2: "),
        ("leakedGuardBlocks", Driver::DropSkipped, "state at 4: "),
    ] {
        let error = replay(trace(name), driver).unwrap_err();
        assert!(error.starts_with(at), "{error}");
    }
}

/// A trace whose recorded interval count is raised by one fails the replay at that state.
#[test]
fn a_perturbed_register_trace_fails_the_replay_at_the_changed_state() {
    let mut trace: Value = serde_json::from_str(FIXTURES[0].1).unwrap();
    let records = trace["states"][2][STATE]["recs"]["#map"]
        .as_array_mut()
        .unwrap();
    let first = records
        .iter_mut()
        .find(|row| row[0]["#bigint"] == "0")
        .unwrap();
    let intervals = &mut first[1]["intervals"]["#bigint"];
    assert_eq!(intervals.as_str(), Some("1"));
    *intervals = "2".into();
    let error = replay(&trace.to_string(), Driver::Faithful).unwrap_err();
    assert!(error.starts_with("state at 2: "), "{error}");
}

/// A trace that names another model text is refused before any state replays.
#[test]
fn a_register_trace_of_another_model_text_is_refused() {
    let mut trace: Value = serde_json::from_str(FIXTURES[0].1).unwrap();
    trace["#meta"]["register"]["model_sha256"] = "0".repeat(64).into();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
}
