//! Replays committed traces of the burst custody model `quint/burst.qnt`
//! against the production [`Burst`](crate::native::burst::Burst) over the mock
//! port and the mock arena, single-threaded.
//!
//! Each model step sets the mock device's answers from the step's recorded
//! arguments and runs one production call: a send of one-segment datagrams,
//! the device's return of every chain it holds, a reclaim, or `into_port`.
//! The replay then requires the call's outcome to equal the step's recorded
//! outcome, and the header pool's held count, the chains the mock device
//! holds, the link, the poison and the burst report's counters to equal the
//! model's state. While the burst is live, its retained quarantine header's
//! token and device-held membership distinguish returned, kept and untaken.
//! Header allocation requires an unpoisoned burst, and this replay alone
//! uses the header pool, so a returned quarantine header stays disarmed
//! until settlement. After the model's `close`, the replay compares the
//! header pool and the device.
//!
//! The model's `restart` argument selects the registration's recheck
//! (`stale`) or the device's start (`fail`) as the failing restart step. The
//! recovery watchdog runs with the mock's one-minute deadline and never
//! expires; the model does not describe it.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{Fixture, LOCAL, PEERS, fixture_over, held};
use crate::native::burst::Link;
use crate::native::mock::{self, MockPort, iova};
use crate::native::wire::Wire;
use crate::net::{DatagramError, Datagrams, Outgoing, Payload, PeerId};
use crate::storage::{EngineBudget, PoolKind};

const MODEL: &[u8] = include_bytes!("../../../../../quint/burst.qnt");
const STATE: &str = "burstCase::burst::st";
const FIXTURES: [(&str, &str); 14] = [
    (
        "uncertain_settles",
        include_str!("replay_fixtures/uncertain_settles.itf.json"),
    ),
    (
        "unproven_holds",
        include_str!("replay_fixtures/unproven_holds.itf.json"),
    ),
    ("down", include_str!("replay_fixtures/down.itf.json")),
    (
        "lost_after_restart",
        include_str!("replay_fixtures/lost_after_restart.itf.json"),
    ),
    ("freed", include_str!("replay_fixtures/freed.itf.json")),
    (
        "kept_unsettled",
        include_str!("replay_fixtures/kept_unsettled.itf.json"),
    ),
    (
        "lost_then_settled",
        include_str!("replay_fixtures/lost_then_settled.itf.json"),
    ),
    (
        "unsettled_kept",
        include_str!("replay_fixtures/unsettled_kept.itf.json"),
    ),
    (
        "unsettled_untaken",
        include_str!("replay_fixtures/unsettled_untaken.itf.json"),
    ),
    ("cleanup", include_str!("replay_fixtures/cleanup.itf.json")),
    ("step_a", include_str!("replay_fixtures/step_a.itf.json")),
    ("step_b", include_str!("replay_fixtures/step_b.itf.json")),
    ("step_c", include_str!("replay_fixtures/step_c.itf.json")),
    ("step_d", include_str!("replay_fixtures/step_d.itf.json")),
];

/// How the replay maps a model step to the mock device and production calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model step sets the device's answers as recorded and runs its production call.
    Faithful,
    /// The device proves every stop, the ones the model leaves unproven included.
    StopsProven,
    /// The device never reports a post uncertain.
    UncertainUnreported,
    /// The model's device return runs nothing.
    ReturnDropped,
}

/// Replaces every ITF big integer with a JSON number.
fn plain(v: &mut Value) {
    match v {
        Value::Object(map) if map.contains_key("#bigint") => {
            *v = map["#bigint"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                .into();
        }
        Value::Object(map) => map.values_mut().for_each(plain),
        Value::Array(list) => list.iter_mut().for_each(plain),
        _ => {}
    }
}

fn n(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap()
}

fn flag(v: &Value, key: &str) -> bool {
    v[key].as_bool().unwrap()
}

/// `Ok` when production's `real` equals the model's `model`, else the mismatch named `what` at state `i`.
fn same<T: PartialEq + std::fmt::Debug>(
    what: &str,
    i: usize,
    real: T,
    model: T,
) -> Result<(), String> {
    if real == model {
        Ok(())
    } else {
        Err(format!("{what} at {i}: {real:?}, model {model:?}"))
    }
}

/// Returns the text the replay compares with a recipe entry.
fn recorded_action(act: &str, arg: &Value) -> String {
    match act {
        "send" => format!("send({}, {}, {})", arg["n"], arg["k"], arg["unc"]),
        "reclaim" => format!(
            "reclaim({}, {}, {}, {})",
            arg["reset"], arg["proven"], arg["restart"], arg["again"]
        ),
        "close" => format!("close({})", arg["proven"]),
        act => act.into(),
    }
}

/// Replays one trace and returns the `(action, outcome)` of every state, `init` first.
///
/// # Errors
///
/// A trace whose model digest or length is wrong; otherwise the first step
/// whose production outcome differs from the recorded one, or whose custody,
/// link, poison or counters differ from the model's state, named with its
/// index.
///
/// A nonempty recipe must contain one entry for each state after `init`;
/// the replay reports a length mismatch as `fixture recipe length` and an
/// entry that differs from the state's recorded action as
/// `action {i}: recipe`.
///
/// # Panics
///
/// If a field the trace records is missing or has another type.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["burst"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as u64 != n(&trace["#meta"]["burst"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let recipe = trace["#meta"]["burst"]["recipe"]
        .as_array()
        .ok_or("fixture recipe")?;
    if !recipe.is_empty() && recipe.len() + 1 != states.len() {
        return Err("fixture recipe length".into());
    }
    let stale = Rc::new(Cell::new(false));
    let recheck = Rc::clone(&stale);
    let Fixture {
        arena,
        burst,
        receive_ops,
        header,
        payload,
        ..
    } = fixture_over(
        mock::arena(),
        Wire::new(LOCAL, &PEERS, &mut EngineBudget::unlimited()).unwrap(),
        Box::new(iova),
        Box::new(move || !recheck.get()),
    );
    // The pools outlive the burst logic and the port handed back.
    let header_state = header.state;
    let _pools = (receive_ops, header, payload);
    let mut handed: Option<MockPort> = None;
    let mut burst = Some(burst);
    let bytes = [0x5a; 192];
    let datagram = Outgoing {
        peer: PeerId(0),
        header: &bytes,
        payload: [Payload::Inline(b"b"), Payload::EMPTY],
    };
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let (ev, arg) = (&model["ev"], &model["arg"]);
        let (act, res) = (
            ev["act"].as_str().ok_or("event action")?,
            ev["res"].as_str().ok_or("event outcome")?,
        );
        if state["mbt::actionTaken"] != act {
            return Err(format!("action {i}: the event names another action"));
        }
        if i > 0 && !recipe.is_empty() && recipe[i - 1] != recorded_action(act, arg).as_str() {
            return Err(format!("action {i}: recipe"));
        }
        let proven = flag(arg, "proven") || driver == Driver::StopsProven;
        let outcome: String = match (act, burst.as_mut()) {
            ("init", Some(_)) if i == 0 => String::new(),
            ("send" | "complete" | "reclaim" | "close", None) => "Gone".into(),
            ("send", Some(burst)) => {
                let unc = arg["unc"].as_str().ok_or("uncertain argument")?;
                let port = burst.port_mut();
                port.accept = n(arg, "k") as usize;
                port.uncertain = unc != "no" && driver != Driver::UncertainUnreported;
                port.retain_uncertain = unc == "kept";
                port.free_uncertain = unc == "freed";
                let quarantined = burst.report().quarantined;
                let result = burst.send(&[datagram; 2][..n(arg, "n") as usize]);
                let port = burst.port_mut();
                port.take_accepted();
                port.uncertain = false;
                match result {
                    Ok(accepted) => {
                        same("accepted", i, accepted as u64, n(ev, "n"))?;
                        if burst.report().quarantined > quarantined {
                            "Uncertain".into()
                        } else {
                            "Sent".into()
                        }
                    }
                    Err(DatagramError::Closed) => "Closed".into(),
                    Err(DatagramError::Failed {
                        code: Some(libc::EIO),
                    }) => "Poisoned".into(),
                    Err(error) => return Err(format!("send at {i}: {error:?}")),
                }
            }
            ("complete", Some(_)) if driver == Driver::ReturnDropped => res.into(),
            ("complete", Some(burst)) => {
                let port = burst.port_mut();
                let chains = port.held.len() as u64;
                port.complete();
                if chains == 0 {
                    "Idle".into()
                } else {
                    same("returned", i, chains, n(ev, "n"))?;
                    "Returned".into()
                }
            }
            ("reclaim", Some(burst)) => {
                let (link, resets) = (burst.link(), burst.report().resets);
                let port = burst.port_mut();
                let stops = port.stops;
                let again = flag(arg, "again") || driver == Driver::StopsProven;
                port.reset = flag(arg, "reset");
                port.proven_stops = stops + u32::from(proven) + u32::from(proven && again);
                port.restart_error = (arg["restart"] == "fail").then_some(libc::EIO);
                stale.set(arg["restart"] == "stale");
                burst.reclaim();
                let port = burst.port_mut();
                port.reset = false;
                let stopped = port.stops - stops;
                if link != Link::Up {
                    "Closed".into()
                } else if burst.report().resets == resets {
                    "Cleanup".into()
                } else {
                    match (burst.link(), stopped) {
                        (Link::Up, 1) => "Recovered".into(),
                        (Link::Down, 2) => "Down".into(),
                        (Link::Lost, 1) => "Lost".into(),
                        (Link::Lost, 2) => "LostAfterRestart".into(),
                        (link, stopped) => {
                            return Err(format!("reclaim at {i}: {link:?} after {stopped} stops"));
                        }
                    }
                }
            }
            ("close", Some(_)) => {
                let mut burst = burst.take().expect("matched a live burst");
                let poisoned = burst.poisoned();
                let stops = burst.port_mut().stops;
                burst.port_mut().proven_stops = stops + u32::from(proven);
                let port = handed.insert(burst.into_port());
                match (poisoned, port.stops - stops) {
                    (false, 0) => "Handed".into(),
                    (true, 1) if port.stops <= port.proven_stops => "Settled".into(),
                    (true, 1) => "Unsettled".into(),
                    (poisoned, stopped) => {
                        return Err(format!(
                            "close at {i}: poisoned {poisoned}, {stopped} stops"
                        ));
                    }
                }
            }
            (action, _) => return Err(format!("action {i}: unknown action {action}")),
        };
        if outcome != res {
            return Err(format!("{act} at {i}: {outcome}, recorded {res}"));
        }
        same(
            "held",
            i,
            u64::from(held(arena, PoolKind::PacketHeader)),
            n(model, "held"),
        )?;
        same("gone", i, burst.is_none(), flag(model, "gone"))?;
        let Some(burst) = burst.as_mut() else {
            let port = handed
                .as_ref()
                .expect("a closed burst handed its port back");
            same("device", i, port.held.len() as u64, n(model, "dev"))?;
            reached.push((act.to_owned(), res.to_owned()));
            continue;
        };
        same(
            "device",
            i,
            burst.port_mut().held.len() as u64,
            n(model, "dev"),
        )?;
        let link = match burst.link() {
            Link::Up => "Up",
            Link::Down => "Down",
            Link::Lost => "Lost",
        };
        same("link", i, link, model["link"].as_str().ok_or("model link")?)?;
        same("poisoned", i, burst.poisoned(), model["quar"] != "none")?;
        let quarantine = match burst.quarantine_header() {
            None => "none",
            Some(head) => {
                // SAFETY: the mock pools remain allocated and this single-threaded
                // replay reads between port calls, which own all token writes.
                let armed = unsafe { header_state.armed_token(head.cast()) };
                if armed.is_none() {
                    "returned"
                } else if burst.port().held.contains(&head) {
                    "kept"
                } else {
                    "untaken"
                }
            }
        };
        same(
            "quarantine",
            i,
            quarantine,
            model["quar"].as_str().ok_or("model quarantine")?,
        )?;
        let report = burst.report();
        same(
            "counters",
            i,
            [
                report.sent,
                report.quarantined,
                report.quarantine_returned,
                report.quarantine_released,
                report.resets,
                report.recoveries,
            ],
            [
                n(model, "sent"),
                n(model, "quarantined"),
                n(model, "returned"),
                n(model, "released"),
                n(model, "resets"),
                n(model, "recoveries"),
            ],
        )?;
        reached.push((act.to_owned(), res.to_owned()));
    }
    Ok(reached)
}

#[test]
fn committed_burst_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        reached.extend(
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}")),
        );
    }
    // `init` and every choice of the model's `step`, each with every outcome it records.
    assert!(
        std::str::from_utf8(MODEL).unwrap().contains(
            "    any {send(n, k, unc), complete, reclaim(reset, proven, restart, again), close(proven)}\n"
        ),
        "the model's step chooses among other actions than the replay drives"
    );
    let reached: Vec<(&str, &str)> = reached
        .iter()
        .map(|(act, res)| (act.as_str(), res.as_str()))
        .collect();
    assert_eq!(
        reached,
        [
            ("close", "Gone"),
            ("close", "Handed"),
            ("close", "Settled"),
            ("close", "Unsettled"),
            ("complete", "Gone"),
            ("complete", "Idle"),
            ("complete", "Returned"),
            ("init", ""),
            ("reclaim", "Cleanup"),
            ("reclaim", "Closed"),
            ("reclaim", "Down"),
            ("reclaim", "Gone"),
            ("reclaim", "Lost"),
            ("reclaim", "LostAfterRestart"),
            ("reclaim", "Recovered"),
            ("send", "Closed"),
            ("send", "Gone"),
            ("send", "Poisoned"),
            ("send", "Sent"),
            ("send", "Uncertain"),
        ]
    );
}

#[test]
fn a_trace_with_another_quarantine_kind_fails_at_that_state() {
    for (name, at, kind) in [
        ("unproven_holds", 2, "kept"),
        ("lost_then_settled", 2, "untaken"),
        ("freed", 1, "returned"),
        ("kept_unsettled", 2, "returned"),
    ] {
        for other in ["kept", "untaken", "returned", "invalid"] {
            if other == kind {
                continue;
            }
            let mut trace: Value = serde_json::from_str(fixture(name)).unwrap();
            assert_eq!(trace["states"][at][STATE]["quar"], kind);
            trace["states"][at][STATE]["quar"] = other.into();
            assert_eq!(
                replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
                format!("quarantine at {at}: {kind:?}, model {other:?}")
            );
        }
    }
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap()
        .1
}

/// Each wrong driver changes one answer of the device or drops one call the
/// model's step stands for, and the replay refuses it at the first state the
/// difference shows in: the outcome comparison for a stop the device proves
/// where the model leaves it unproven and for an uncertain post the device
/// does not report, and the header pool comparison for a dropped return.
#[test]
fn negative_control_a_wrong_driver_fails_the_replay_at_that_step() {
    // unproven_holds: send, send (uncertain, kept), reclaim with an unproven stop, ...
    assert_eq!(
        replay(fixture("unproven_holds"), Driver::StopsProven).unwrap_err(),
        "reclaim at 3: Recovered, recorded Lost"
    );
    // lost_then_settled: send, send (uncertain, untaken), reclaim with an unproven stop, ...
    assert_eq!(
        replay(fixture("lost_then_settled"), Driver::StopsProven).unwrap_err(),
        "reclaim at 3: Recovered, recorded Lost"
    );
    // uncertain_settles: send (uncertain, untaken), ...
    assert_eq!(
        replay(fixture("uncertain_settles"), Driver::UncertainUnreported).unwrap_err(),
        "send at 1: Sent, recorded Uncertain"
    );
    // cleanup: send of two, reclaim, the device's return, ...
    assert_eq!(
        replay(fixture("cleanup"), Driver::ReturnDropped).unwrap_err(),
        "held at 3: 2, model 0"
    );
}

/// A trace altered in one state's recorded field fails at that state, through
/// the comparison that reads the field; a stale model digest or a missing
/// state fails the trace before any state replays.
#[test]
fn negative_control_an_altered_trace_fails_at_the_altered_state() {
    let json = fixture("unproven_holds");
    let altered = |state: usize, field: &str, value: Value| {
        let mut trace: Value = serde_json::from_str(json).unwrap();
        trace["states"][state][STATE][field] = value;
        replay(&trace.to_string(), Driver::Faithful).unwrap_err()
    };
    let big = |value: u64| serde_json::json!({"#bigint": value.to_string()});
    // State 3 is the unproven stop: the link is lost, four header buffers stay held, the device holds four chains.
    assert_eq!(
        altered(3, "link", "Up".into()),
        "link at 3: \"Lost\", model \"Up\""
    );
    assert_eq!(altered(3, "held", big(0)), "held at 3: 4, model 0");
    assert_eq!(altered(3, "dev", big(0)), "device at 3: 4, model 0");
    assert_eq!(
        altered(3, "quar", "none".into()),
        "poisoned at 3: true, model false"
    );
    assert_eq!(
        altered(3, "resets", big(0)),
        "counters at 3: [3, 1, 0, 0, 1, 0], model [3, 1, 0, 0, 0, 0]"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][3][STATE]["ev"]["res"] = "Recovered".into();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "reclaim at 3: Lost, recorded Recovered"
    );
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"][4]["mbt::actionTaken"] = "send".into();
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

/// A directed trace whose state records another action or argument than its
/// recipe entry fails at that state, as does a trace that holds the states of
/// another recipe of the same length; a recipe of another length fails the
/// trace before any state replays.
#[test]
fn a_trace_off_its_declared_recipe_fails_at_that_action() {
    // down: send(2, 2, "no"), reclaim(true, true, "fail", true),
    // send(1, 1, "no"), reclaim(true, true, "ok", true), complete,
    // close(true), complete.
    let off = |name: &str, edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(fixture(name)).unwrap();
        edit(&mut trace);
        replay(&trace.to_string(), Driver::Faithful).unwrap_err()
    };
    for (index, entry, error) in [
        (0, r#"send(2, 1, "no")"#, "action 1: recipe"),
        (1, r#"reclaim(true, true, "ok", true)"#, "action 2: recipe"),
        (4, "close(true)", "action 5: recipe"),
        (5, "close(false)", "action 6: recipe"),
    ] {
        assert_eq!(
            off("down", &|trace| {
                trace["#meta"]["burst"]["recipe"][index] = entry.into();
            }),
            error
        );
    }
    // `cleanup` holds six steps, as `lost_then_settled` does; both begin with
    // the same send and part at the second step.
    let other: Value = serde_json::from_str(fixture("cleanup")).unwrap();
    assert_eq!(
        off("lost_then_settled", &|trace| {
            trace["states"] = other["states"].clone();
        }),
        "action 2: recipe"
    );
    assert_eq!(
        off("down", &|trace| {
            trace["#meta"]["burst"]["recipe"]
                .as_array_mut()
                .unwrap()
                .pop();
        }),
        "fixture recipe length"
    );
}
