//! Replays committed traces of the grace model `quint/grace.qnt` against the `grace` module's `pin`, `unpin`, `bump`, [`PassCursor`] and `releasable` at the production strength [`Sequential`], over `std` atomics on one thread.
//!
//! Each model step that names a call of the module runs that call. The replay then requires the call's return, and the outcome the replay derives from it, to equal the step's recorded event, and the era word, both pin words, the certified word and the pass cursor to equal the model's state.
//! The model's observation, removal and reuse are acts of the module's callers; the replay checks that the words stay unchanged across them. The model's `copies`, `visible`, `stamp`, `anchored`, `released` and `reused` stay inside the model. `safety`, which `quint run --invariant safety` checks as each trace is generated, reads `copies`, `released` and `reused`. Of the six, the replay reads only the stamp, which it passes to `releasable`.
//!
//! Model era `e` is production era `BASE + e`, with zero kept as zero, so the model's terminal era 3 is the production [`ERA_TERMINAL`] and `Sequential` runs with its own band. The model's absent pin, `NOPIN`, is the cursor's `u64::MAX`.
//!
//! `bash scripts/tool.sh grace_fixtures --quint QUINT --output DIR` writes the traces with `quint run --mbt`: seven directed recipes and six traces of sixteen steps of the model's own `step` under pinned seeds. Each trace names the model's sha256, and a trace of another model text fails before any state replays.
//! The replay is evidence for exactly the schedules these traces record.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::grace::{
    ERA_TERMINAL, INACTIVE, PassCursor, PinRefused, Sequential, bump, pin, releasable, unpin,
};

const MODEL: &[u8] = include_bytes!("../../../../quint/grace.qnt");
const STATE: &str = "graceCase::grace::st";
/// The model's terminal era.
const TERMINAL: u64 = 3;
/// The production era of model era zero.
const BASE: u64 = ERA_TERMINAL - TERMINAL;
/// The model's value for a pass that has seen no pin.
const NOPIN: i64 = 1000;
/// The model's registration records.
const RECORDS: usize = 2;

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("grace_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 13] = fixtures![
    "readerBeforePass",
    "passBeforeReader",
    "releaseAfterUnpin",
    "terminalRefusesPins",
    "refusals",
    "keptCertificate",
    "closingRetirement",
    "step_a",
    "step_b",
    "step_c",
    "step_d",
    "step_e",
    "step_f",
];

/// How the replay maps a model step to production calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model action that names a call runs it.
    Faithful,
    /// The model's release asks whether the stamp is at or below the certified era.
    ReleaseAtEqual,
    /// The model's visit of the second record runs nothing.
    SecondVisitDropped,
    /// The model's unpin runs nothing.
    UnpinDropped,
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

/// The production era of a model era; zero, the inactive record and the unset certificate, stays zero.
fn era(model: i64) -> u64 {
    if model == 0 { 0 } else { BASE + model as u64 }
}

/// The words the module runs over and the pass in progress.
struct Words {
    era: AtomicU64,
    certified: AtomicU64,
    pins: [AtomicU64; RECORDS],
    pass: Option<PassCursor>,
}

/// What the words hold, in the order the model's state is read: the era, the certified era, both pins, and the pass as its start era, smallest pin and next record, or `None` between passes.
type Held = (u64, u64, [u64; RECORDS], Option<(u64, u64, usize)>);

impl Words {
    fn held(&self) -> Held {
        (
            self.era.load(Ordering::SeqCst),
            self.certified.load(Ordering::SeqCst),
            [
                self.pins[0].load(Ordering::SeqCst),
                self.pins[1].load(Ordering::SeqCst),
            ],
            self.pass
                .map(|cursor| (cursor.start_era, cursor.min_pin(), cursor.next)),
        )
    }
}

/// What the model's state holds, as [`Words::held`] reads the words.
fn modelled(model: &Value) -> Result<Held, String> {
    let mut pins = [0; RECORDS];
    for row in model["pins"]["#map"].as_array().ok_or("model pins")? {
        let at = row[0].as_u64().ok_or("pin record")? as usize;
        pins[at] = era(row[1].as_i64().ok_or("pin era")?);
    }
    let pass = &model["pass"];
    let low = n(pass, "low");
    Ok((
        era(n(model, "era")),
        era(n(model, "certified")),
        pins,
        pass["on"].as_bool().ok_or("pass flag")?.then(|| {
            (
                era(n(pass, "start")),
                if low == NOPIN { u64::MAX } else { era(low) },
                n(pass, "next") as usize,
            )
        }),
    ))
}

/// Replays one trace and returns the `(action, outcome)` of every state, `init` first; a bump's outcome names its closing flag and a visit's whether it read a pin.
///
/// # Errors
///
/// A trace that fails to parse or whose model digest or length is wrong; a step whose field the replay cannot read, that names an unknown action, or that visits or completes outside a pass; otherwise the first step whose action name, production return or words differ from the model's event and state, or whose caller's act changed the words, named with its index.
///
/// # Panics
///
/// If a number the trace records is missing or is not an integer, or a recorded reader or record lies outside `0..=1`.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["grace"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as i64 != n(&trace["#meta"]["grace"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let mut words = Words {
        era: AtomicU64::new(era(1)),
        certified: AtomicU64::new(0),
        pins: [AtomicU64::new(INACTIVE), AtomicU64::new(INACTIVE)],
        pass: None,
    };
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let ev = &model["ev"];
        let (act, res) = (
            ev["act"].as_str().ok_or("event action")?,
            ev["res"].as_str().ok_or("event outcome")?,
        );
        // A trace of the model's `step` names the action or the wrapper that draws its reader.
        let taken = state["mbt::actionTaken"].as_str().ok_or("action taken")?;
        if taken.strip_prefix("some").unwrap_or(taken).to_lowercase() != act {
            return Err(format!("action {i}: the event names another action"));
        }
        let reader = n(ev, "reader") as usize;
        let value = n(ev, "value");
        let closes = ev["closes"].as_bool().ok_or("closing flag")?;
        let before = words.held();
        // The call's return as the model records it: the outcome, the value and the closing flag.
        let (outcome, returned, closing): (&str, u64, bool) = match act {
            "init" if i == 0 => ("", 0, false),
            "pin" => match pin::<_, Sequential>(&words.era, &words.pins[reader]) {
                Ok(pinned) => ("Ok", pinned, false),
                Err(PinRefused::Terminal) => ("Terminal", 0, false),
                Err(PinRefused::Active) => ("Active", 0, false),
            },
            "unpin" if driver == Driver::UnpinDropped => ("Ok", 0, false),
            "unpin" => {
                unpin(&words.pins[reader]);
                ("Ok", 0, false)
            }
            "retire" | "elsewhere" => {
                let bumped = bump::<_, Sequential>(&words.era);
                ("Ok", bumped.retire_era, bumped.closes_admission)
            }
            "begin" => {
                let cursor = PassCursor::begin::<_, Sequential>(&words.era);
                words.pass = Some(cursor);
                ("Ok", cursor.start_era, false)
            }
            "visit" => {
                let cursor = words.pass.as_mut().ok_or("visit outside a pass")?;
                if driver == Driver::SecondVisitDropped && cursor.next == 1 {
                    ("Ok", era(value), false)
                } else {
                    let record = &words.pins[cursor.next];
                    ("Ok", cursor.visit::<_, Sequential>(record), false)
                }
            }
            "complete" => {
                let cursor = words.pass.take().ok_or("complete outside a pass")?;
                let (start, low) = (cursor.start_era, cursor.min_pin());
                let certified = cursor.complete::<_, Sequential>(RECORDS, &words.certified);
                let outcome = if certified == before.1 {
                    "Kept"
                } else if low < start {
                    "Pin"
                } else {
                    "Start"
                };
                (outcome, certified, false)
            }
            "release" => {
                let (stamp, certified) = (era(n(model, "stamp")), before.1);
                let released = if driver == Driver::ReleaseAtEqual {
                    stamp <= certified
                } else {
                    releasable(stamp, certified)
                };
                (if released { "Released" } else { "Held" }, 0, false)
            }
            "observe" | "remove" | "reuse" => (res, era(value), closes),
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        if (outcome, returned, closing) != (res, era(value), closes) {
            return Err(format!(
                "{act} at {i}: {outcome} {returned} {closing}, recorded {res} {value} {closes}"
            ));
        }
        let held = words.held();
        if held != modelled(model)? {
            return Err(format!("words at {i}: {held:?}"));
        }
        if matches!(act, "observe" | "remove" | "reuse" | "release") && held != before {
            return Err(format!("{act} at {i}: the words changed"));
        }
        let detail = match act {
            "retire" | "elsewhere" if closes => "closes",
            "retire" | "elsewhere" => "open",
            "visit" if value != 0 => "pin",
            "visit" => "inactive",
            _ => res,
        };
        reached.push((act.to_owned(), detail.to_owned()));
    }
    Ok(reached)
}

/// Every committed trace replays, and together the traces reach `init` and every choice of the model's `step` with each of its outcomes.
#[test]
fn committed_grace_traces_replay_against_the_grace_words() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        let steps =
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}"));
        reached.extend(steps);
    }
    let expected: BTreeSet<(String, String)> = [
        ("init", ""),
        ("pin", "Ok"),
        ("pin", "Active"),
        ("pin", "Terminal"),
        ("observe", "Visible"),
        ("observe", "Gone"),
        ("unpin", "Ok"),
        ("remove", "Ok"),
        ("retire", "open"),
        ("retire", "closes"),
        ("elsewhere", "open"),
        ("elsewhere", "closes"),
        ("begin", "Ok"),
        ("visit", "pin"),
        ("visit", "inactive"),
        ("complete", "Start"),
        ("complete", "Pin"),
        ("complete", "Kept"),
        ("release", "Released"),
        ("release", "Held"),
        ("reuse", "Ok"),
    ]
    .into_iter()
    .map(|(act, outcome)| (act.to_owned(), outcome.to_owned()))
    .collect();
    assert_eq!(reached, expected);
}

/// A driver that releases at a stamp equal to the certified era, one that skips the second visit and one that skips the unpin each fail the replay at the step they change, through the replay's own comparison.
#[test]
fn negative_control_a_wrong_grace_driver_fails_the_replay_at_its_step() {
    let trace = |name: &str| FIXTURES.iter().find(|(n, _)| *n == name).unwrap().1;
    assert_eq!(
        replay(trace("readerBeforePass"), Driver::ReleaseAtEqual).unwrap_err(),
        "release at 9: Released 0 false, recorded Held 0 false"
    );
    let dropped = replay(trace("readerBeforePass"), Driver::SecondVisitDropped).unwrap_err();
    assert!(dropped.starts_with("words at 7: "), "{dropped}");
    let kept = replay(trace("releaseAfterUnpin"), Driver::UnpinDropped).unwrap_err();
    assert!(kept.starts_with("words at 10: "), "{kept}");
}

/// A trace whose recorded certified era is raised by one fails the replay at that state.
#[test]
fn a_perturbed_grace_trace_fails_the_replay_at_the_changed_state() {
    let json = FIXTURES[0].1;
    let mut trace: Value = serde_json::from_str(json).unwrap();
    let certified = &mut trace["states"][8][STATE]["certified"]["#bigint"];
    assert_eq!(certified.as_str(), Some("1"));
    *certified = "2".into();
    let error = replay(&trace.to_string(), Driver::Faithful).unwrap_err();
    assert!(error.starts_with("words at 8: "), "{error}");
}

/// A trace that names another model text is refused before any state replays.
#[test]
fn a_grace_trace_of_another_model_text_is_refused() {
    let mut trace: Value = serde_json::from_str(FIXTURES[0].1).unwrap();
    trace["#meta"]["grace"]["model_sha256"] = "0".repeat(64).into();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
}
