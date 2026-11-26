//! Replays committed traces of the rearmable-watchdog model
//! `quint/watchdog.qnt` against the production [`Rearmable`] and its worker
//! thread over the scripted timer.
//!
//! One model tick is one second on the scripted clock and the deadline is
//! the model's two ticks, so no step waits on real time. Each model step
//! runs its owner call or advances the clock by the step's recorded `dt`,
//! with or without a wake. After a step that wakes the worker the replay
//! waits until the worker entered its next wait or its containment, and then
//! requires the step's outcome, the clock, the expiry flag, the containment
//! count, the count of waits the worker entered and the timeout of its last
//! wait to equal the model's state.
//!
//! The model's `armed` stamp and its history fields have no production
//! reading; the replay checks the stamp through the timeouts and the expiry
//! it leads to. A worker that ended is known by its one containment, and a
//! wake of it is checked by the wait count staying the model's.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{BOUND, Observer, Script};
use crate::native::watchdog::Rearmable;

const MODEL: &[u8] = include_bytes!("../../../../../quint/watchdog.qnt");
const STATE: &str = "watchdogCase::watchdog::st";
/// One model tick on the scripted clock.
const TICK: Duration = Duration::from_secs(1);
/// The model's deadline in ticks.
const MODEL_DEADLINE: u32 = 2;
const FIXTURES: [(&str, &str); 10] = [
    (
        "idle_then_full_deadline",
        include_str!("replay_fixtures/idle_then_full_deadline.itf.json"),
    ),
    (
        "disarm_then_rearm",
        include_str!("replay_fixtures/disarm_then_rearm.itf.json"),
    ),
    (
        "partial_then_expiry",
        include_str!("replay_fixtures/partial_then_expiry.itf.json"),
    ),
    (
        "three_episodes",
        include_str!("replay_fixtures/three_episodes.itf.json"),
    ),
    ("step_a", include_str!("replay_fixtures/step_a.itf.json")),
    ("step_b", include_str!("replay_fixtures/step_b.itf.json")),
    ("step_c", include_str!("replay_fixtures/step_c.itf.json")),
    ("step_d", include_str!("replay_fixtures/step_d.itf.json")),
    ("step_e", include_str!("replay_fixtures/step_e.itf.json")),
    ("step_f", include_str!("replay_fixtures/step_f.itf.json")),
];

/// How the replay maps a model step to production calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model action runs its production call.
    Faithful,
    /// The model's disarm runs nothing, so the deadline keeps running.
    DisarmDropped,
    /// The model's silent advance leaves the clock where it was, so the next
    /// arm stamps a reading older than its own.
    PassDropped,
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

/// What a woken worker did next.
#[derive(Debug, PartialEq, Eq)]
enum Reaction {
    /// It entered a wait with this timeout.
    Waited(Duration),
    /// It asked the supervisor to contain.
    Contained,
}

/// Waits, bounded, until the worker entered a wait past the first `waits`
/// or a containment past the first `entries`.
fn settled(script: &Script, observer: &Observer, waits: usize, entries: usize) -> Option<Reaction> {
    let start = Instant::now();
    let mut seen = script.waits.lock().unwrap();
    loop {
        if observer.entries() > entries {
            return Some(Reaction::Contained);
        }
        if seen.len() > waits {
            return Some(Reaction::Waited(seen[waits]));
        }
        if start.elapsed() >= BOUND {
            return None;
        }
        seen = script
            .waited
            .wait_timeout(seen, Duration::from_millis(2))
            .unwrap()
            .0;
    }
}

/// The timeout the model's `wait` field names: unbounded below zero, else
/// that many ticks.
fn timeout(wait: i64) -> Duration {
    u32::try_from(wait).map_or(Duration::MAX, |ticks| TICK * ticks)
}

/// Returns the text the replay compares with a recipe entry.
fn recorded_action(act: &str, ev: &Value) -> String {
    match act {
        "pass" | "wake" => format!("{act}({})", ev["dt"]),
        act => act.into(),
    }
}

/// Replays one trace and returns the `(action, outcome)` of every state,
/// `init` first.
///
/// # Errors
///
/// A trace whose model digest or length is wrong; otherwise the first step,
/// with its index, whose production outcome, clock, expiry flag, containment
/// count, wait count or last wait timeout differs from the model's state,
/// whose woken worker neither waited nor contained within the bound, or
/// whose event is malformed.
///
/// A nonempty recipe must contain one entry for each state after `init`;
/// the replay reports a length mismatch as `fixture recipe length` and an
/// entry that differs from the state's recorded action as
/// `action {i}: recipe`.
///
/// # Panics
///
/// If a number the trace records is missing or is not an integer.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["watchdog"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as i64 != n(&trace["#meta"]["watchdog"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let recipe = trace["#meta"]["watchdog"]["recipe"]
        .as_array()
        .ok_or("fixture recipe")?;
    if !recipe.is_empty() && recipe.len() + 1 != states.len() {
        return Err("fixture recipe length".into());
    }
    let script = Arc::new(Script::default());
    let observer = Observer::new(None);
    let mut watchdog =
        Rearmable::idle_with(TICK * MODEL_DEADLINE, observer.clone(), script.clone())
            .map_err(|e| e.to_string())?;
    observer.watched.set(watchdog.shared());
    let mut clock = 0;
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
        if i > 0 && !recipe.is_empty() && recipe[i - 1] != recorded_action(act, ev).as_str() {
            return Err(format!("action {i}: recipe"));
        }
        if matches!(act, "pass" | "wake") {
            clock += n(ev, "dt");
        }
        let now = TICK * u32::try_from(clock).map_err(|_| format!("clock at {i}: {clock}"))?;
        let (waits, entries) = (script.waits.lock().unwrap().len(), observer.entries());
        let react = || {
            settled(&script, &observer, waits, entries).ok_or(format!(
                "{act} at {i}: the worker neither waited nor contained"
            ))
        };
        let outcome = match act {
            "init" if i == 0 => {
                settled(&script, &observer, 0, 0).ok_or("init: the worker did not wait")?;
                ""
            }
            "rearm" => {
                if watchdog.rearm() {
                    react()?;
                    "Armed"
                } else {
                    "Refused"
                }
            }
            "disarm" if driver == Driver::DisarmDropped => res,
            "disarm" => {
                if watchdog.disarm() {
                    "Expired"
                } else {
                    "Running"
                }
            }
            "pass" => {
                if driver != Driver::PassDropped {
                    script.advance(now);
                }
                "Passed"
            }
            "wake" => {
                script.advance_and_wake(&watchdog.shared(), now);
                if entries > 0 {
                    "Ended"
                } else {
                    match react()? {
                        Reaction::Contained => "Contained",
                        Reaction::Waited(Duration::MAX) => "Idle",
                        Reaction::Waited(_) => "Waiting",
                    }
                }
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        if outcome != res {
            return Err(format!("{act} at {i}: {outcome}, recorded {res}"));
        }
        if clock != n(model, "now") {
            return Err(format!("clock at {i}: {clock}"));
        }
        if watchdog.expired() != model["expired"].as_bool().ok_or("expiry flag")? {
            return Err(format!("expired at {i}: {}", watchdog.expired()));
        }
        if observer.entries() as i64 != n(model, "contained") {
            return Err(format!("contained at {i}: {}", observer.entries()));
        }
        let seen = script.waits.lock().unwrap().clone();
        if seen.len() as i64 != n(model, "waits") {
            return Err(format!("waits at {i}: {}", seen.len()));
        }
        let last = *seen.last().ok_or("the worker never waited")?;
        if last != timeout(n(model, "wait")) {
            return Err(format!("wait at {i}: {last:?}"));
        }
        reached.push((act.to_owned(), res.to_owned()));
    }
    Ok(reached)
}

#[test]
fn committed_watchdog_traces_replay_and_reach_every_step_choice() {
    let model = std::str::from_utf8(MODEL).unwrap();
    assert!(
        model.contains(&format!("  pure val DEADLINE = {MODEL_DEADLINE}\n")),
        "the model's deadline is another than the replay's"
    );
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        let steps =
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}"));
        reached.extend(steps);
    }
    // `init` and every choice of the model's `step`.
    assert!(
        model.contains("    any {rearm, disarm, pass(dt), wake(dt)}\n"),
        "the model's step chooses among other actions than the replay drives"
    );
    let actions: BTreeSet<&str> = reached.iter().map(|(act, _)| act.as_str()).collect();
    assert_eq!(
        actions,
        BTreeSet::from(["disarm", "init", "pass", "rearm", "wake"])
    );
    let outcomes: BTreeSet<&str> = reached.iter().map(|(_, res)| res.as_str()).collect();
    assert_eq!(
        outcomes,
        BTreeSet::from([
            "",
            "Armed",
            "Contained",
            "Ended",
            "Expired",
            "Idle",
            "Passed",
            "Refused",
            "Running",
            "Waiting",
        ])
    );
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap()
        .1
}

/// Each wrong driver drops one production call a model step stands for, and
/// the replay refuses it at the first wake the missing effect shows in: a
/// dropped disarm leaves the deadline running, so the worker contains where
/// the model idles, and a dropped silent advance makes the next arm stamp an
/// old reading, so the worker contains a tick into a deadline the model has
/// just started.
#[test]
fn negative_control_a_driver_that_drops_a_call_fails_the_replay_at_the_next_wake() {
    // disarm_then_rearm: rearm, disarm, wake(3), ...
    assert_eq!(
        replay(fixture("disarm_then_rearm"), Driver::DisarmDropped).unwrap_err(),
        "wake at 3: Contained, recorded Idle"
    );
    // three_episodes: rearm, wake(1), disarm, pass(3), rearm, wake(1), ...
    assert_eq!(
        replay(fixture("three_episodes"), Driver::PassDropped).unwrap_err(),
        "wake at 6: Contained, recorded Waiting"
    );
}

/// A trace that records another outcome or another wait than the model's
/// fails the faithful replay at the perturbed state, and a trace of another
/// model text is refused before any step.
#[test]
fn negative_control_a_perturbed_trace_fails_the_replay_at_the_perturbed_state() {
    // idle_then_full_deadline: wake(3), rearm, wake(1), wake(1), disarm, rearm.
    let json = fixture("idle_then_full_deadline");
    let (refused, armed) = (r#""res":"Refused""#, r#""res":"Armed""#);
    assert_eq!(json.matches(refused).count(), 1);
    assert_eq!(
        replay(&json.replace(refused, armed), Driver::Faithful).unwrap_err(),
        "rearm at 6: Refused, recorded Armed"
    );
    let (one, two) = (r##""wait":{"#bigint":"1"}"##, r##""wait":{"#bigint":"2"}"##);
    // The first state that records a one-tick wait is the first `wake(1)`.
    assert!(json.contains(one));
    assert_eq!(
        replay(&json.replacen(one, two, 1), Driver::Faithful).unwrap_err(),
        "wait at 3: 1s"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][4][STATE]["ev"]["dt"] = serde_json::json!({"#bigint": "0"});
    trace["#meta"]["watchdog"]["recipe"][3] = "wake(0)".into();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "wake at 4: Waiting, recorded Contained"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][1][STATE]["now"] = serde_json::json!({"#bigint": "2"});
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "clock at 1: 3"
    );
    let digest = r#""model_sha256":""#;
    assert_eq!(json.matches(digest).count(), 1);
    assert_eq!(
        replay(
            &json.replace(digest, r#""model_sha256":"0"#),
            Driver::Faithful
        )
        .unwrap_err(),
        "fixture model digest"
    );
}

/// A directed trace whose state records another action or elapsed time than
/// its recipe entry fails at that state, and a recipe of another length fails
/// the trace before any state replays.
#[test]
fn a_trace_off_its_declared_recipe_fails_at_that_action() {
    // partial_then_expiry: rearm, wake(0), wake(1), pass(1), wake(0), wake(2),
    // disarm, rearm, disarm.
    let off = |edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(fixture("partial_then_expiry")).unwrap();
        edit(&mut trace);
        replay(&trace.to_string(), Driver::Faithful).unwrap_err()
    };
    for (index, entry, error) in [
        (1, "wake(1)", "action 2: recipe"),
        (3, "pass(2)", "action 4: recipe"),
        (6, "rearm", "action 7: recipe"),
    ] {
        assert_eq!(
            off(&|trace| trace["#meta"]["watchdog"]["recipe"][index] = entry.into()),
            error
        );
    }
    assert_eq!(
        off(&|trace| {
            trace["#meta"]["watchdog"]["recipe"]
                .as_array_mut()
                .unwrap()
                .pop();
        }),
        "fixture recipe length"
    );
}
