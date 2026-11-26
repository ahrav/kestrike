//! Replay of committed traces of the settle-rule model, `quint/settle.qnt`, against [`Namespace`].
//!
//! The traces are the model's instance of one peer with one wire slot, a table of two handles and generation 4 as
//! the limit: the directed recipes and seeded runs that `quint/settle_fixtures.py` writes. The namespace has one
//! peer, a width of one, a table of two and a share of two. A model generation below the limit is the wire
//! generation of the same number and the model's limit is [`GENERATION_LIMIT`]; the model's zero watermark and zero
//! refused generation are a slot with none.
//!
//! Each model action is the namespace call it names:
//!
//! - `admit` is [`Namespace::admit`], which must admit; `refuse` is [`Namespace::admissible`] and then
//!   [`Namespace::admit`], which must both return the model's refusal with the record builder uncalled.
//! - `settle` is [`Namespace::settle`] with a row when the model's answer keeps one. The call returns nothing, so
//!   its outcome, `Settled`, `Refused` or `Ignored`, is judged by the state comparison after it.
//! - `end` moves the bound record to draining. The replay reads the slot before the call: a request whose slot
//!   holds a watermark ended under its own session, so the replay retains a row and requires `Ended`; a slot with
//!   none was replaced, so the replay retains none, as an operation that ends a replaced session's request does,
//!   and requires `EndedReplaced`.
//! - `unbind` is `Namespace::unbind`, `release` is [`Namespace::release`], which must free, `replace` is
//!   [`Namespace::retire`] and `route` is [`Namespace::route`], which must return the model's route.
//!
//! After every action the slot's watermark, bound request, row and refused generation equal the model's, each live
//! model record is live and draining exactly when the model's has ended, each released one is gone from the table,
//! and the census equals the model's live and ended records. The replay also counts admissions itself and refuses
//! a second admission of one generation under one session epoch.
//!
//! The traces take `init`, every choice of the model's `step` (`admit`, `refuse`, `settle`, `end`, `unbind`,
//! `release`, `replace`, `route`) and every outcome those actions record, among them a lower generation settled
//! after a higher one while a request holds the binding, and an unbind and a release that each raise the watermark
//! to a refused generation.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::storage::EngineBudget;

use super::datagram::PeerId;
use super::namespace::{Cached, Namespace, Operated, Operation, Refusal, Route};
use super::requests::{GENERATION_LIMIT, RequestId, RequestPressure, RequestTable};

const MODEL: &[u8] = include_bytes!("../../../../quint/settle.qnt");

/// The model's `HANDLES` size and its `LIMIT`.
const TABLE: u32 = 2;
const LIMIT: u64 = 4;
const PEER: PeerId = PeerId(0);

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("settle_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const TRACES: [(&str, &str); 8] = fixtures![
    "refused_order",
    "free_slot",
    "pressure",
    "replaced",
    "step_5e771e",
    "step_a11ce",
    "step_ddba11",
    "step_7e57",
];

/// `init` and the choices of the model's `step`.
const ACTIONS: [&str; 9] = [
    "init", "admit", "refuse", "settle", "end", "unbind", "release", "replace", "route",
];

/// Every outcome a model action records.
const OUTCOMES: [&str; 18] = [
    "Admitted",
    "Busy",
    "Stale",
    "Exhausted",
    "Pressure",
    "Settled",
    "Refused",
    "Ignored",
    "Ended",
    "EndedReplaced",
    "Unbound",
    "UnboundRaised",
    "Released",
    "ReleasedRaised",
    "Replaced",
    "Older",
    "Fresh",
    "Same",
];

/// A GET record or row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tagged;

impl Operated for Tagged {
    fn operation(&self) -> Operation {
        Operation::Get
    }
}

/// When a driver passes the model's settle to the namespace.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Settling {
    /// Always.
    Every,
    /// Planted defect: only on a free binding, so a generation answered while a request holds the binding is
    /// never recorded as refused and would admit once the binding frees.
    WhenFree,
}

/// Rewrites the ITF encodings of integers, sets, tuples and maps as plain JSON numbers and arrays.
fn plain(v: &mut Value) {
    match v {
        Value::Object(map) if map.contains_key("#bigint") => {
            *v = map["#bigint"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap()
                .into()
        }
        Value::Object(map) if map.len() == 1 && map.keys().all(|key| key.starts_with('#')) => {
            let mut inner = map.values().next().unwrap().clone();
            plain(&mut inner);
            *v = inner;
        }
        Value::Object(map) => map.values_mut().for_each(plain),
        Value::Array(list) => list.iter_mut().for_each(plain),
        _ => {}
    }
}

fn number(v: &Value) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| "fixture number".to_owned())
}

fn text(v: &Value) -> Result<&str, String> {
    v.as_str().ok_or_else(|| "fixture text".to_owned())
}

/// The wire identity of model generation `generation` on the one wire slot.
fn wire(generation: u64) -> RequestId {
    RequestId::from_wire(if generation == LIMIT {
        GENERATION_LIMIT
    } else {
        generation
    })
}

fn refusal(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Outside => "Outside",
        Refusal::Busy => "Busy",
        Refusal::Stale => "Stale",
        Refusal::Exhausted => "Exhausted",
        Refusal::Pressure(RequestPressure::Peer) => "Pressure",
        Refusal::Pressure(RequestPressure::Table) => "TablePressure",
    }
}

/// The recipe entry of the action and arguments the event `ev` records.
fn recorded(ev: &Value) -> Result<String, String> {
    let (g, handle) = (number(&ev["gen"])?, number(&ev["handle"])?);
    Ok(match text(&ev["act"])? {
        "admit" => format!("admit({g}, {handle})"),
        "settle" => format!("settle({g}, {})", ev["keep"] == true),
        act @ ("refuse" | "route") => format!("{act}({g})"),
        "release" => format!("release({handle})"),
        act => act.to_owned(),
    })
}

/// The trace's states after its digest, its length and, for a directed trace, its recipe's actions and their
/// arguments are checked.
fn states(trace: &str) -> Result<Vec<Value>, String> {
    let mut trace: Value = serde_json::from_str(trace).map_err(|_| "fixture json")?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let meta = trace["#meta"]["settle"].clone();
    if meta["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?.clone();
    if states.len() as u64 != number(&meta["steps"])? + 1 {
        return Err("fixture length".into());
    }
    let recipe = meta["recipe"].as_array().ok_or("fixture recipe")?;
    if !recipe.is_empty() {
        if states.len() != recipe.len() + 1 {
            return Err("fixture recipe length".into());
        }
        for (i, entry) in recipe.iter().enumerate() {
            if *entry != recorded(&states[i + 1]["settleCase::settle::st"]["ev"])?.as_str() {
                return Err(format!("action {}: recipe", i + 1));
            }
        }
    }
    Ok(states)
}

/// Replays `trace` and returns each action it took with its outcome, or the first action or state at which the
/// namespace disagrees with the model.
fn replay(trace: &str, settling: Settling) -> Result<Vec<(String, String)>, String> {
    let states = states(trace)?;
    let mut names: Namespace<Tagged, Tagged> = Namespace::new(
        RequestTable::new(TABLE, 1, TABLE),
        1,
        &mut EngineBudget::new(1 << 16),
    )
    .map_err(|_| "namespace budget")?;
    // Each live admission's table handle by the model's handle.
    let mut handles: HashMap<u64, RequestId> = HashMap::new();
    // The session epoch, and the generations admitted under each epoch.
    let mut epoch = 1_u64;
    let mut admitted: HashSet<(u64, u64)> = HashSet::new();
    let mut taken = Vec::with_capacity(states.len());
    for (i, state) in states.iter().enumerate() {
        let st = &state["settleCase::settle::st"];
        let ev = &st["ev"];
        let (act, res) = (text(&ev["act"])?, text(&ev["res"])?);
        if state["mbt::actionTaken"] != act {
            return Err(format!("action at {i}"));
        }
        let (g, handle) = (number(&ev["gen"])?, number(&ev["handle"])?);
        let live = |handles: &HashMap<u64, RequestId>| {
            handles
                .get(&handle)
                .copied()
                .ok_or(format!("admission named at {i}"))
        };
        let row = Cached {
            epoch,
            expires_us: u64::MAX,
            outcome: Tagged,
        };
        let built = Cell::new(false);
        let build = || {
            built.set(true);
            Tagged
        };
        match act {
            "init" if i == 0 => {}
            "admit" => {
                let id = names
                    .admit(PEER, wire(g), build)
                    .map_err(|refused| format!("admission at {i}: {}", refusal(refused)))?;
                if !built.get() || handles.insert(handle, id).is_some() {
                    return Err(format!("admission at {i}"));
                }
                if !admitted.insert((epoch, g)) {
                    return Err(format!("second admission at {i}"));
                }
            }
            "refuse" => {
                let expected = names.admissible(PEER, wire(g)).err().map(refusal);
                let refused = names.admit(PEER, wire(g), build).err().map(refusal);
                if refused != Some(res) || expected != refused || built.get() {
                    return Err(format!("refusal at {i}"));
                }
            }
            "settle" => {
                let bound = names
                    .slot(PEER, 0)
                    .is_some_and(|slot| slot.active.is_some());
                if settling == Settling::Every || !bound {
                    let kept = (ev["keep"] == true).then_some(row);
                    names.settle(PEER, wire(g), kept);
                }
            }
            "end" => {
                let id = live(&handles)?;
                // A replacement clears the slot's watermark and a bound slot takes no other, so a watermark
                // at an end means the request was admitted under the current session.
                let in_session = names
                    .slot(PEER, 0)
                    .is_some_and(|slot| slot.watermark.is_some());
                if !names.begin_drain(id) {
                    return Err(format!("end at {i}"));
                }
                if in_session {
                    names.retain(PEER, 0, id, row);
                }
                if res != if in_session { "Ended" } else { "EndedReplaced" } {
                    return Err(format!("end result at {i}"));
                }
            }
            "unbind" => names.unbind(PEER, 0, live(&handles)?),
            "release" => {
                if !names.release(live(&handles)?, PEER, 0) {
                    return Err(format!("release at {i}"));
                }
                handles.remove(&handle);
            }
            "replace" => {
                names.retire(PEER);
                epoch += 1;
            }
            "route" => {
                let route = match names.route(PEER, wire(g), Operation::Get) {
                    Route::Outside => "Outside",
                    Route::Older => "Older",
                    Route::Same { .. } => "Same",
                    Route::Fresh => "Fresh",
                    Route::WrongOperation => "WrongOperation",
                };
                if route != res {
                    return Err(format!("route at {i}"));
                }
            }
            _ => return Err(format!("action at {i}")),
        }
        compare(&names, st, &handles, i)?;
        taken.push((act.to_owned(), res.to_owned()));
    }
    Ok(taken)
}

/// Compares the namespace with the model state `st` after action `i`.
fn compare(
    names: &Namespace<Tagged, Tagged>,
    st: &Value,
    handles: &HashMap<u64, RequestId>,
    i: usize,
) -> Result<(), String> {
    let slot = names.slot(PEER, 0).ok_or(format!("slot at {i}"))?;
    let some = |n: u64| (n != 0).then_some(n);
    if slot.watermark != some(number(&st["mark"])?) {
        return Err(format!("watermark at {i}"));
    }
    if slot.refused != some(number(&st["refused"])?) {
        return Err(format!("refused at {i}"));
    }
    let active = number(&st["active"])?;
    if slot.active != handles.get(&active).copied() || (active != 0) != slot.active.is_some() {
        return Err(format!("binding at {i}"));
    }
    if slot.cached.is_some() != (st["row"] == true) {
        return Err(format!("row at {i}"));
    }
    let (mut live, mut ended) = (0, 0);
    for handle in 1..=u64::from(TABLE) {
        let model = st["table"]
            .as_array()
            .and_then(|pairs| pairs.iter().find(|pair| pair[0] == handle))
            .map(|pair| &pair[1])
            .ok_or("fixture table")?;
        let id = handles.get(&handle);
        if number(&model["gen"])? == 0 {
            if id.is_some() {
                return Err(format!("released record at {i}"));
            }
            continue;
        }
        let id = id.ok_or(format!("record at {i}"))?;
        let draining = model["ended"] == true;
        if names.table().peer(*id) != Some(PEER) || names.table().draining(*id) != draining {
            return Err(format!("record at {i}"));
        }
        live += 1;
        ended += u32::from(draining);
    }
    let census = names.census();
    if census.live() != live || census.draining != ended || names.wrong_operation() != 0 {
        return Err(format!("census at {i}"));
    }
    Ok(())
}

fn trace(name: &str) -> &'static str {
    TRACES.iter().find(|(n, _)| *n == name).unwrap().1
}

/// Every committed trace replays with the namespace equal to the model after every action, and together the traces
/// take `init`, every choice of the model's `step` and every outcome an action records.
#[test]
fn committed_settle_traces_replay() {
    let mut taken: Vec<(String, String)> = Vec::new();
    for (name, trace) in TRACES {
        let actions =
            replay(trace, Settling::Every).unwrap_or_else(|error| panic!("{name}: {error}"));
        taken.extend(actions);
    }
    for action in ACTIONS {
        assert!(
            taken.iter().any(|(seen, _)| seen == action),
            "{action} is replayed"
        );
    }
    for outcome in OUTCOMES {
        assert!(
            taken.iter().any(|(_, seen)| seen == outcome),
            "{outcome} is replayed"
        );
    }
}

/// Planted `Settling::WhenFree`: a driver that drops a settle while a request holds the binding records no refused
/// generation, so the replay's comparison of the slot's refused generation with the model's fails at that settle.
#[test]
fn a_driver_that_drops_a_settle_under_a_held_binding_fails_at_that_settle() {
    for (name, error) in [
        ("refused_order", "refused at 2"),
        ("replaced", "refused at 2"),
    ] {
        assert_eq!(replay(trace(name), Settling::Every).map(|_| ()), Ok(()));
        assert_eq!(replay(trace(name), Settling::WhenFree).unwrap_err(), error);
    }
}

/// A trace whose recorded watermark, refused generation, binding, row, refusal, route, recipe or model digest is
/// changed fails at the changed state or action, and a trace that lost states fails as `fixture length`.
#[test]
fn a_perturbed_settle_trace_fails_at_the_changed_state() {
    const ST: &str = "settleCase::settle::st";
    let fixture = |name: &str| -> Value { serde_json::from_str(trace(name)).unwrap() };
    let big = |n: u64| serde_json::json!({ "#bigint": n.to_string() });
    let failure = |trace: &Value| replay(&trace.to_string(), Settling::Every).unwrap_err();

    // The recorded unbind leaves the watermark below the refused generation.
    let mut trace = fixture("refused_order");
    trace["states"][6][ST]["mark"] = big(1);
    assert_eq!(failure(&trace), "watermark at 6");

    // The recorded lower settle replaces the higher refusal.
    let mut trace = fixture("refused_order");
    trace["states"][3][ST]["refused"] = big(2);
    assert_eq!(failure(&trace), "refused at 3");

    let mut trace = fixture("refused_order");
    trace["states"][6][ST]["active"] = big(1);
    assert_eq!(failure(&trace), "binding at 6");

    let mut trace = fixture("free_slot");
    trace["states"][1][ST]["row"] = false.into();
    assert_eq!(failure(&trace), "row at 1");

    // The recorded refusal is the one a bound slot gives, where the slot is free and the generation settled.
    let mut trace = fixture("free_slot");
    trace["states"][2][ST]["ev"]["res"] = "Busy".into();
    assert_eq!(failure(&trace), "refusal at 2");

    let mut trace = fixture("free_slot");
    trace["states"][4][ST]["ev"]["res"] = "Fresh".into();
    assert_eq!(failure(&trace), "route at 4");

    let mut trace = fixture("pressure");
    trace["#meta"]["settle"]["recipe"][1] = "unbind".into();
    assert_eq!(failure(&trace), "action 2: recipe");

    // The recorded route names generation 3, which routes `Fresh`, where the recipe routes generation 2.
    let mut trace = fixture("free_slot");
    trace["states"][4][ST]["ev"]["gen"] = big(3);
    trace["states"][4][ST]["ev"]["res"] = "Fresh".into();
    assert_eq!(failure(&trace), "action 4: recipe");

    // The recorded settle keeps a row where the recipe's settle keeps none.
    let mut trace = fixture("refused_order");
    trace["states"][2][ST]["ev"]["keep"] = true.into();
    assert_eq!(failure(&trace), "action 2: recipe");

    // The same-session end is recorded as a replaced session's, with no row from then on.
    let mut trace = fixture("free_slot");
    trace["states"][7][ST]["ev"]["res"] = "EndedReplaced".into();
    trace["states"][7][ST]["row"] = false.into();
    trace["states"][8][ST]["row"] = false.into();
    assert_eq!(failure(&trace), "end result at 7");

    // The replaced session's end is recorded as a same-session one that kept its row.
    let mut trace = fixture("replaced");
    trace["states"][5][ST]["ev"]["res"] = "Ended".into();
    trace["states"][5][ST]["row"] = true.into();
    assert_eq!(failure(&trace), "end result at 5");

    // The recorded row alone is changed at each of the two ends.
    let mut trace = fixture("free_slot");
    trace["states"][7][ST]["row"] = false.into();
    assert_eq!(failure(&trace), "row at 7");
    let mut trace = fixture("replaced");
    trace["states"][5][ST]["row"] = true.into();
    assert_eq!(failure(&trace), "row at 5");

    let mut trace = fixture("pressure");
    trace["#meta"]["settle"]["recipe"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert_eq!(failure(&trace), "fixture recipe length");

    // A seeded and a directed trace that each lost their last state hold fewer states than the steps they record.
    for name in ["step_5e771e", "pressure"] {
        let mut trace = fixture(name);
        trace["states"].as_array_mut().unwrap().pop();
        assert_eq!(failure(&trace), "fixture length", "{name}");
    }

    // The seeded trace cut to the prefix that still reaches `Fresh`, the one outcome no directed trace records.
    let mut trace = fixture("step_5e771e");
    trace["states"].as_array_mut().unwrap().truncate(3);
    assert_eq!(failure(&trace), "fixture length");

    let mut trace = fixture("step_7e57");
    trace["#meta"]["settle"]["model_sha256"] = "0".into();
    assert_eq!(failure(&trace), "fixture model digest");
}
