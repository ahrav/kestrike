//! Replays committed traces of the extent-allocator model `quint/extent.qnt` against [`ExtentAllocator`] over tables of eight units and an index of two entries, on one thread.
//!
//! Each model step executes a production reservation or return. Replay checks the outcome and allocated start against the recorded event, reservation length against requested units, and maximal free runs, indexed runs, and drop count against model state. The allocator's `check` runs after every step.
//! A reservation's outcome is `Indexed` when a run the index held before the call holds the reservation and `Fallback` otherwise, and a return's is `Joined` when a free unit bordered the extent before the call and `Alone` otherwise; both read the allocator's tables before the call.
//!
//! The model's `held` set is the replay's premise: it returns only extents the trace reserved, or extents the model refuses. Its `misplaced` history stays inside the model, where `safety` checks it as each trace is generated.
//! Visits, budgets, the ledger's terms and the placeable count are outside the model; the replay funds each reservation with the allocator's own bound, leaves visits to the allocator's debug bounds and the ledger and placeable count to `check`.
//!
//! `python3 quint/extent_check.py --quint QUINT --output DIR` writes the traces with `quint run --mbt`: four directed recipes and six traces of twenty-four steps of the model's own `step` under pinned seeds. Each trace names the model's sha256, and a trace of another model text fails before any state replays.
//! The replay is evidence for exactly the schedules these traces record.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::budget::WorkBudget;
use super::allocator::ExtentStateError;
use super::index::index_nodes;
use super::{
    ExtentAllocator, ExtentLocator, ExtentRefusal, ExtentRoot, HeldPhase, RunNode, space_words,
};

const MODEL: &[u8] = include_bytes!("../../../../../quint/extent.qnt");
const STATE: &str = "extentCase::extent::st";
/// The model's volume, in units.
const UNITS: u64 = 8;
/// The model's index capacity.
const CAPACITY: usize = 2;
const METADATA_UNITS: u64 = 3;
/// The full-extent charge, which only the placeable count reads.
const CHARGE: u64 = 1;

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 10] = fixtures![
    "bestFit",
    "fullIndexDrop",
    "fallback",
    "notHeld",
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
    /// Every model action runs its production call.
    Faithful,
    /// A return the model accepts runs nothing.
    ReturnDropped,
    /// A reservation asks for one unit more than the model's.
    ReservationGrown,
    /// A reservation's locator reads one unit shorter than the allocator returned.
    LengthShortened,
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

/// The model's runs under `key` as `(start, len)` in address order.
fn modeled(model: &Value, key: &str) -> Result<Vec<(u64, u64)>, String> {
    let mut runs: Vec<(u64, u64)> = model[key]["#set"]
        .as_array()
        .ok_or("model runs")?
        .iter()
        .map(|run| (n(run, "start"), n(run, "len")))
        .collect();
    runs.sort_unstable();
    Ok(runs)
}

/// The maximal runs of the model's free units as `(start, len)` in address order.
fn free_runs(model: &Value) -> Result<Vec<(u64, u64)>, String> {
    let mut free: Vec<u64> = model["free"]["#set"]
        .as_array()
        .ok_or("model free units")?
        .iter()
        .map(|unit| unit.as_u64().unwrap())
        .collect();
    free.sort_unstable();
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for unit in free {
        match runs.last_mut() {
            Some((start, len)) if *start + *len == unit => *len += 1,
            _ => runs.push((unit, 1)),
        }
    }
    Ok(runs)
}

/// Replays one trace and returns the `(action, outcome)` of every state, `init` first.
///
/// # Errors
///
/// A trace that fails to parse or whose model digest or length is wrong; otherwise the first step whose action name, outcome, placed start, returned length, free runs, indexed runs or drop count differ from the model's state, named with its index.
///
/// # Panics
///
/// If a number the trace records is missing or is not an unsigned integer, if a step names an extent no locator can hold, or if the allocator's `check` finds one of the module's invariants broken.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["extent"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as u64 != n(&trace["#meta"]["extent"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let mut root = ExtentRoot::default();
    let mut space = vec![u64::MAX; space_words(UNITS)];
    let mut nodes = vec![RunNode::default(); index_nodes(CAPACITY)];
    let mut allocator = ExtentAllocator::init(
        UNITS,
        METADATA_UNITS,
        CAPACITY,
        CHARGE,
        &mut root,
        &mut space,
        &mut nodes,
    )
    .map_err(|error| format!("{error:?}"))?;
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let ev = &model["ev"];
        let (act, res) = (
            ev["act"].as_str().ok_or("event action")?,
            ev["res"].as_str().ok_or("event outcome")?,
        );
        // A trace of the model's `step` names the wrapper that draws the action's arguments.
        let taken = state["mbt::actionTaken"].as_str().ok_or("action taken")?;
        if taken.strip_prefix("some").unwrap_or(taken).to_lowercase() != act {
            return Err(format!("action {i}: the event names another action"));
        }
        let (start, len) = (n(ev, "start"), n(ev, "len"));
        let outcome: String = match act {
            "init" if i == 0 => String::new(),
            "reserve" => {
                let units = len as u32 + u32::from(driver == Driver::ReservationGrown);
                let indexed = allocator
                    .indexed_runs()
                    .iter()
                    .any(|run| run.1 >= u64::from(units));
                let limit = allocator.bound_for(u64::from(units));
                let mut budget = WorkBudget::new(limit);
                let short = u32::from(driver == Driver::LengthShortened);
                match allocator
                    .reserve(units, 0, limit, &mut budget)
                    .map(|locator| (locator.start_unit(), locator.len_units() - short))
                {
                    Ok((placed, _)) if placed != start => {
                        return Err(format!("reserve at {i}: start {placed}"));
                    }
                    Ok((_, held)) if held != units => {
                        return Err(format!("reserve at {i}: len {held}"));
                    }
                    Ok(_) if indexed => "Indexed".into(),
                    Ok(_) => "Fallback".into(),
                    Err(ExtentRefusal::NoFit { .. }) => "NoFit".into(),
                    Err(error) => return Err(format!("reserve at {i}: {error:?}")),
                }
            }
            "release" if driver == Driver::ReturnDropped && res != "NotHeld" => res.into(),
            "release" => {
                let free = allocator.free_set();
                let bordered = free
                    .iter()
                    .any(|run| run.0 + run.1 == start || run.0 == start + len);
                let locator = ExtentLocator::new(start, len as u32).expect("inside the limits");
                match allocator.release(locator, HeldPhase::Reserved, 0) {
                    Ok(()) if bordered => "Joined".into(),
                    Ok(()) => "Alone".into(),
                    Err(ExtentStateError::NotHeld) => "NotHeld".into(),
                    Err(error) => return Err(format!("release at {i}: {error:?}")),
                }
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        if outcome != res {
            return Err(format!("{act} at {i}: {outcome}, recorded {res}"));
        }
        let free = allocator.free_set();
        if free != free_runs(model)? {
            return Err(format!("free runs at {i}: {free:?}"));
        }
        let indexed = allocator.indexed_runs();
        if indexed != modeled(model, "index")? {
            return Err(format!("indexed runs at {i}: {indexed:?}"));
        }
        if allocator.drops() != n(model, "drops") {
            return Err(format!("drops at {i}: {}", allocator.drops()));
        }
        allocator.check(METADATA_UNITS);
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

#[test]
fn committed_extent_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        reached.extend(
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}")),
        );
    }
    // `init` and both choices of the model's `step`, each a wrapper that draws its action's arguments.
    assert!(
        std::str::from_utf8(MODEL)
            .unwrap()
            .contains("  action step = any {someReserve, someRelease}\n"),
        "the model's step chooses among other actions than the replay drives"
    );
    assert_eq!(
        reached,
        BTreeSet::from(
            [
                ("init", ""),
                ("release", "Alone"),
                ("release", "Joined"),
                ("release", "NotHeld"),
                ("reserve", "Fallback"),
                ("reserve", "Indexed"),
                ("reserve", "NoFit"),
            ]
            .map(|(act, res)| (act.to_owned(), res.to_owned()))
        )
    );
}

#[test]
fn negative_control_a_wrong_extent_driver_fails_at_the_step_it_changes() {
    // bestFit: reserve(3), reserve(2), reserve(1), release(0, 3) at 4, which the model frees.
    assert_eq!(
        replay(fixture("bestFit"), Driver::ReturnDropped).unwrap_err(),
        "free runs at 4: [(6, 2)]"
    );
    // notHeld: reserve(2) at 1 takes units 0 and 1; one unit more also takes unit 2.
    assert_eq!(
        replay(fixture("notHeld"), Driver::ReservationGrown).unwrap_err(),
        "free runs at 1: [(3, 5)]"
    );
    assert_eq!(
        replay(fixture("notHeld"), Driver::LengthShortened).unwrap_err(),
        "reserve at 1: len 1"
    );
}

/// A trace altered in one state's recorded field fails at that state, through the comparison that reads the field; a stale model digest or a missing state fails the trace before any state replays.
#[test]
fn negative_control_an_altered_extent_trace_fails_at_the_altered_state() {
    // fullIndexDrop: six reservations of one unit, then release(0, 1) at 7, release(1, 1) at 8, release(3, 1) at 9, which the full index drops, and release(4, 1) at 10.
    let json = fixture("fullIndexDrop");
    let altered = |at: usize, edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(json).unwrap();
        edit(&mut trace["states"][at]);
        replay(&trace.to_string(), Driver::Faithful).unwrap_err()
    };
    let number = |value: u64| serde_json::json!({ "#bigint": value.to_string() });
    assert_eq!(
        altered(8, &|state| state[STATE]["ev"]["res"] = "Alone".into()),
        "release at 8: Joined, recorded Alone"
    );
    assert_eq!(
        altered(2, &|state| state[STATE]["ev"]["start"] = number(5)),
        "reserve at 2: start 1"
    );
    // The model drops the one-unit run at 3 and keeps both two-unit runs; a trace that indexes the dropped run names a run the allocator left out.
    assert_eq!(
        altered(9, &|state| {
            state[STATE]["index"]["#set"][0] =
                serde_json::json!({"len": number(1), "start": number(3)});
        }),
        "indexed runs at 9: [(0, 2), (6, 2)]"
    );
    assert_eq!(
        altered(9, &|state| state[STATE]["drops"] = number(0)),
        "drops at 9: 1"
    );
    assert_eq!(
        altered(7, &|state| state[STATE]["free"]["#set"] =
            serde_json::json!([number(6), number(7)])),
        "free runs at 7: [(0, 1), (6, 2)]"
    );
    assert_eq!(
        altered(3, &|state| state["mbt::actionTaken"] = "release".into()),
        "action 3: the event names another action"
    );
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"].as_array_mut().unwrap().pop();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "fixture length"
    );
}
