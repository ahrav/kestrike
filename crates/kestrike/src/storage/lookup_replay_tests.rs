//! Replays committed traces of the lookup model `quint/lookup.qnt` against a live indexed [`Storage`] on the heap-backed platform: two keys, one registered reader, and the publications, replacements, removals, lookups, expiry, close, certification and service that change what a lookup returns.
//!
//! Each model step except `expire` runs storage code for one model action. A publication or a replacement goes through the `lookup_tests` helpers: `Storage::reserve`, then the test-only `complete` and `Completed::publish` or `Completed::replace`, which share their preparation and commit with the fill's publication. A removal goes through the test-only `Storage::remove`, which routes the key and calls the removal that eviction and expiry use. The other steps are `Registration::lookup` under a clock sample the replay queues, a lease's drop, `Storage::close`, one funded `Storage::certify` and one funded `Storage::service`. `expire` calls no storage code: it moves the sample the replay queues before each later lookup from one nanosecond before the deadline to the deadline.
//! The replay then requires the call's return, and the outcome the replay derives from it, to equal the step's recorded event: a hit must name the object the model names. It also requires the era report, the reserved lease credits, `Storage::outstanding`, and every published object's slot state and count to equal the model's state, and each slot's incarnation to equal the one recorded at publication.
//! The model numbers objects in publication order; the replay records each object's `AllocationId` when it is published and reads the model's numbers through that record. The model's `bad` flag is history its invariant reads; it stays inside the model, where `quint run --invariant safety` checks it as each trace is generated.
//!
//! `bash scripts/tool.sh lookup_fixtures --quint QUINT --output DIR` writes the traces with `quint run --mbt`: four directed recipes and six traces of sixteen steps of the model's own `step` under pinned seeds. Each trace names the model's sha256, and a trace of another model text fails before any state replays.
//! The replay is evidence for exactly the schedules these traces record, one operation at a time.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::budget::WorkBudget;
use super::lookup::LookupError;
use super::lookup_tests::{body, key, lookup, publish, ready, replace, reserved, ticks};
use super::publish_tests::{RETRIES, TRIES, budget, refs};
use super::release::Outstanding;
use super::tables::SlotState;
use super::test_platform::TestPlatform;
use super::{AllocationId, ExtentLease, RetireOutcome, SlotIndex};

const MODEL: &[u8] = include_bytes!("../../../../quint/lookup.qnt");
const STATE: &str = "lookupCase::lookup::st";
/// Every object's deadline on the engine's nanosecond timeline.
const DEADLINE: u64 = 100 * 1_000_000_000;
/// The model's objects, numbered from 1.
const OBJECTS: usize = 4;
/// Steps that fund any one certification or service call of this storage.
const FUNDED: usize = 400;

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("lookup_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 10] = fixtures![
    "replaceUnderLease",
    "removeThenReclaim",
    "expiryAndClose",
    "twoKeys",
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
    /// The model's removal runs nothing.
    RemovalSkipped,
    /// The model's lookup asks for the other key.
    OtherKey,
    /// The model's dropped lease stays held.
    DropKept,
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

/// One published object as the storage holds it: its slot's state and incarnation, and its count.
type Slot = (SlotState, u32, usize);

/// What the storage holds, in the order the model's state is read: the era, the certified era, the reserved lease credits, what is outstanding, and each published object's slot, `None` once the object returned.
type Held = (u64, u64, usize, Outstanding, Vec<Option<Slot>>);

/// What the model's state holds, as the replay reads the storage.
fn modelled(model: &Value) -> Result<Held, String> {
    let mut objects = vec![None; n(model, "born") as usize];
    let (mut visible, mut retired, mut rights, mut counted) = (0, 0, 0, 0);
    for row in model["objs"]["#map"].as_array().ok_or("model objects")? {
        let (id, object) = (row[0].as_u64().ok_or("object number")? as usize, &row[1]);
        let leases = n(object, "rights") as usize;
        let count = leases + usize::from(object["anchored"].as_bool().ok_or("anchor flag")?);
        let state = match object["phase"].as_str().ok_or("phase")? {
            "Unborn" => continue,
            "Visible" => {
                visible += 1;
                Some(SlotState::Resident)
            }
            "Retired" => {
                retired += 1;
                Some(SlotState::Retired)
            }
            "Returned" => None,
            other => return Err(format!("phase {other}")),
        };
        rights += leases;
        counted += usize::from(count > 0);
        // Every object here is the first incarnation of its slot or follows a returned one; the replay reads the incarnation from the identity it recorded.
        objects[id - 1] = state.map(|state| (state, 0, count));
    }
    Ok((
        n(model, "era") as u64,
        n(model, "certified") as u64,
        rights,
        Outstanding {
            live: visible,
            pending: retired,
            leases: rights,
            anchored: counted,
            unverifiable: false,
            registrations: 1,
        },
        objects,
    ))
}

/// Replays one trace and returns the `(action, outcome)` of every state, `init` first; a service's outcome is `nothing`, `held` or `returned`.
///
/// # Errors
///
/// A trace that fails to parse or whose model digest or length is wrong; a step whose field the replay cannot read or that names an unknown action; otherwise the first step whose action name, storage return or storage state differ from the model's event and state, named with its index.
///
/// # Panics
///
/// If a number the trace records is missing or is not an integer, a recorded key or object lies outside the model's, a helper's own publication fails, or the storage gives no era report or slot state.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["lookup"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as i64 != n(&trace["#meta"]["lookup"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let storage = ready(2 * OBJECTS);
    let mut reader = storage.register().map_err(|e| format!("{e:?}"))?;
    // What the replay itself did: each object's identity, the object each key names, the leases held on each object, and whether the clock passed the deadline.
    let mut ids: Vec<AllocationId> = Vec::new();
    let mut names = [0usize; 2];
    let mut leases: Vec<Vec<ExtentLease<'_, TestPlatform>>> = Vec::new();
    let mut late = false;
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let ev = &model["ev"];
        let (act, res) = (
            ev["act"].as_str().ok_or("event action")?,
            ev["res"].as_str().ok_or("event outcome")?,
        );
        // A trace of the model's `step` names the action or the wrapper that draws its key or object.
        let taken = state["mbt::actionTaken"].as_str().ok_or("action taken")?;
        if taken.strip_prefix("some").unwrap_or(taken).to_lowercase() != act {
            return Err(format!("action {i}: the event names another action"));
        }
        let k = n(ev, "key") as usize;
        let name = key(k as u8 + 1);
        // The storage's return in the model's terms: the outcome, the value, and service's visited, held, released and returned objects.
        let (outcome, value, visits): (&str, usize, [usize; 4]) = match act {
            "init" if i == 0 => ("", 0, [0; 4]),
            "publish" => {
                ids.push(publish(&storage, name, DEADLINE, &body(k as u8 + 1)));
                leases.push(Vec::new());
                names[k] = ids.len();
                ("Ok", ids.len(), [0; 4])
            }
            "replace" => {
                let published = replace(&storage, name, DEADLINE, &body(k as u8 + 1));
                let old = ids[names[k] - 1];
                if published.replaced != Some((old, RetireOutcome::Recorded)) {
                    return Err(format!("replace at {i}: {published:?}"));
                }
                ids.push(published.id);
                leases.push(Vec::new());
                names[k] = ids.len();
                ("Ok", ids.len(), [0; 4])
            }
            "remove" => {
                let old = names[k];
                names[k] = 0;
                if driver != Driver::RemovalSkipped {
                    let removed = storage.remove(&name, ids[old - 1], TRIES, &mut budget());
                    if removed != Ok(RetireOutcome::Recorded) {
                        return Err(format!("remove at {i}: {removed:?}"));
                    }
                }
                ("Ok", old, [0; 4])
            }
            "lookup" => {
                let asked = if driver == Driver::OtherKey {
                    key(2 - k as u8)
                } else {
                    name
                };
                ticks(
                    &storage,
                    &[Some(if late { DEADLINE } else { DEADLINE - 1 })],
                );
                match lookup(&mut reader, &asked, RETRIES) {
                    Ok(lease) => {
                        let at = ids
                            .iter()
                            .position(|id| *id == lease.id())
                            .ok_or(format!("lookup at {i}: a lease on {:?}", lease.id()))?;
                        leases[at].push(lease);
                        ("Hit", at + 1, [0; 4])
                    }
                    Err(LookupError::Missing) => ("Missing", 0, [0; 4]),
                    Err(LookupError::Expired) => ("Expired", 0, [0; 4]),
                    Err(LookupError::Closed) => ("Closed", 0, [0; 4]),
                    Err(other) => return Err(format!("lookup at {i}: {other:?}")),
                }
            }
            "drop" => {
                let id = n(ev, "value") as usize;
                if driver != Driver::DropKept {
                    drop(
                        leases[id - 1]
                            .pop()
                            .ok_or(format!("drop at {i}: no lease"))?,
                    );
                }
                ("Ok", id, [0; 4])
            }
            "expire" => {
                late = true;
                ("Ok", 0, [0; 4])
            }
            "close" => {
                storage.close();
                ("Ok", 0, [0; 4])
            }
            "certify" => {
                let report = storage
                    .certify(&mut WorkBudget::new(FUNDED))
                    .map_err(|error| format!("certify at {i}: {error:?}"))?;
                match (report.visited, report.certified, report.budget_exhausted) {
                    (0, Some(certified), false) => ("Idle", certified as usize, [0; 4]),
                    (1, Some(certified), false) => ("Certified", certified as usize, [0; 4]),
                    _ => return Err(format!("certify at {i}: {report:?}")),
                }
            }
            "service" => {
                let report = storage
                    .service(&mut WorkBudget::new(FUNDED))
                    .map_err(|error| format!("service at {i}: {error:?}"))?;
                if report.partial != 0 || report.budget_exhausted {
                    return Err(format!("service at {i}: {report:?}"));
                }
                (
                    "Ok",
                    0,
                    [
                        report.visited,
                        report.held,
                        report.released,
                        report.serviced,
                    ],
                )
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        let recorded = (
            res,
            n(ev, "value") as usize,
            [
                n(ev, "visited") as usize,
                n(ev, "held") as usize,
                n(ev, "released") as usize,
                n(ev, "serviced") as usize,
            ],
        );
        if (outcome, value, visits) != recorded {
            return Err(format!(
                "{act} at {i}: {outcome} {value} {visits:?}, recorded {recorded:?}"
            ));
        }
        let mut expected = modelled(model)?;
        let eras = storage.era_report().unwrap();
        let mut objects = Vec::new();
        for (at, id) in ids.iter().enumerate() {
            let slot = storage.slot_state(SlotIndex(id.slot_index())).unwrap();
            // A returned object's slot is free under its incarnation until a later object takes it.
            let returned = slot == (SlotState::Free, id.incarnation())
                || ids[at + 1..]
                    .iter()
                    .any(|later| later.slot_index() == id.slot_index());
            objects.push((!returned).then(|| (slot.0, slot.1, refs(&storage, *id))));
            if let Some(Some(object)) = expected.4.get_mut(at) {
                object.1 = id.incarnation();
            }
        }
        let held: Held = (
            eras.era,
            eras.certified,
            reserved(&storage),
            storage.outstanding(),
            objects,
        );
        if held != expected {
            return Err(format!("state at {i}: {held:?}"));
        }
        let detail = match (act, visits) {
            ("service", [0, ..]) => "nothing",
            ("service", [_, _, _, 0]) => "held",
            ("service", _) => "returned",
            _ => res,
        };
        reached.push((act.to_owned(), detail.to_owned()));
    }
    Ok(reached)
}

/// Every committed trace replays, and together the traces reach `init` and every choice of the model's `step` with each of its outcomes.
#[test]
fn committed_lookup_traces_replay_against_a_live_storage() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        let steps =
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}"));
        reached.extend(steps);
    }
    let expected: BTreeSet<(String, String)> = [
        ("init", ""),
        ("publish", "Ok"),
        ("replace", "Ok"),
        ("remove", "Ok"),
        ("lookup", "Hit"),
        ("lookup", "Missing"),
        ("lookup", "Expired"),
        ("lookup", "Closed"),
        ("drop", "Ok"),
        ("expire", "Ok"),
        ("close", "Ok"),
        ("certify", "Certified"),
        ("certify", "Idle"),
        ("service", "nothing"),
        ("service", "held"),
        ("service", "returned"),
    ]
    .into_iter()
    .map(|(act, outcome)| (act.to_owned(), outcome.to_owned()))
    .collect();
    assert_eq!(reached, expected);
}

/// A driver that looks up the other key, one that keeps a dropped lease and one that skips a removal each fail the replay at the step they change, through the replay's own comparison.
#[test]
fn negative_control_a_wrong_lookup_driver_fails_the_replay_at_its_step() {
    let trace = |name: &str| FIXTURES.iter().find(|(n, _)| *n == name).unwrap().1;
    for (name, driver, at) in [
        ("replaceUnderLease", Driver::OtherKey, "lookup at 2: "),
        ("replaceUnderLease", Driver::DropKept, "state at 7: "),
        ("removeThenReclaim", Driver::RemovalSkipped, "state at 2: "),
    ] {
        let error = replay(trace(name), driver).unwrap_err();
        assert!(error.starts_with(at), "{error}");
    }
}

/// A trace whose recorded certified era is raised by one fails the replay at that state.
#[test]
fn a_perturbed_lookup_trace_fails_the_replay_at_the_changed_state() {
    let mut trace: Value = serde_json::from_str(FIXTURES[1].1).unwrap();
    let certified = &mut trace["states"][4][STATE]["certified"]["#bigint"];
    assert_eq!(certified.as_str(), Some("2"));
    *certified = "3".into();
    let error = replay(&trace.to_string(), Driver::Faithful).unwrap_err();
    assert!(error.starts_with("state at 4: "), "{error}");
}

/// A trace that names another model text is refused before any state replays.
#[test]
fn a_lookup_trace_of_another_model_text_is_refused() {
    let mut trace: Value = serde_json::from_str(FIXTURES[0].1).unwrap();
    trace["#meta"]["lookup"]["model_sha256"] = "0".repeat(64).into();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
}
