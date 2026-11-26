//! Replays committed traces of the buffer-pool model `quint/pool.qnt` against one pool of a heap-backed [`BufferArena`], on one thread.
//!
//! Each model step runs its production call: an acquire or a posting, the end of a handle, a device reference taken as a [`NicHold`], taken raw or taken with the handle's end, a reference returned by a hold's drop or by a raw return, a request for a mutable view, the command table's custody moves, and a posting's completion or unposting.
//! The replay then requires the call's outcome and the buffer it names to equal the step's recorded event, and each buffer's obligation class, incarnation and device reference count, the free stack, the mismatched-return count, the retired count and the ended-hold count to equal the model's state.
//! Model buffer `b` is the pool's buffer `b`, and model incarnation `i` is production incarnation `base + i`: a trace replays with both buffers planted so that the model's last incarnation is `u64::MAX`, and a trace that retires no buffer also replays from incarnation 0.
//! A step on a kept handle, record, posting or hold names its buffer at the incarnation the buffer holds before the call.
//! Each model state must contain exactly two buffer records, ordered by index: 0, then 1.
//!
//! The model's `lent` and `raw` counts are the replay's own holds and outstanding raw references, and its `issued` history stays inside the model, where `safety` checks it as each trace is generated.
//!
//! `python3 quint/pool_check.py --quint QUINT --output DIR` writes the traces with `quint run --mbt`: six directed recipes and six traces of sixteen steps of the model's own `step` under pinned seeds. Each trace names the model's sha256, and a trace of another model text fails before any state replays.
//! The replay is evidence for exactly the schedules these traces record.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::ledger::EngineBudget;
use super::super::os::HugepageSize;
use super::super::placement::NodeMask;
use super::super::test_platform::TestPlatform;
use super::pool::Held;
use super::{Buffer, BufferArena, BufferConfig, NicHold, PoolKind, PoolSpec, RxPosted};

const MODEL: &[u8] = include_bytes!("../../../../../quint/pool.qnt");
const STATE: &str = "poolCase::pool::st";
const KIND: PoolKind = PoolKind::ReadResponse;
const LEN: u32 = 4096;
/// The model's last incarnation.
const MODEL_MAX: u64 = 3;
/// The base that puts the model's last incarnation on `u64::MAX`.
const PLANTED: u64 = u64::MAX - MODEL_MAX;
/// The model's obligation classes in the order of the pool's census.
const CLASSES: [&str; 7] = [
    "Free",
    "App",
    "Storage",
    "Quarantined",
    "Posted",
    "Nic",
    "Retired",
];

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("pool_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 12] = fixtures![
    "heldThroughDrop",
    "olderIncarnation",
    "retire",
    "quarantine",
    "posting",
    "exhausted",
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
    /// A matched raw return runs nothing, so the device keeps its reference.
    ReturnDropped,
    /// A mismatched return to buffer 0 or 1 names the buffer's current incarnation.
    StaleNamesCurrent,
    /// The model's `drop` forgets the handle and releases nothing.
    DropForgotten,
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

/// The handles, custody records, postings and holds the replay keeps for the pool's two buffers.
#[derive(Default)]
struct Kept<'a> {
    handles: [Option<Buffer<'a>>; 2],
    stored: [Option<Held<'a>>; 2],
    posted: [Option<RxPosted<'a>>; 2],
    lent: [Vec<NicHold<'a>>; 2],
}

/// Replays one trace with model incarnation `i` as production incarnation `base + i` and returns the `(action, outcome)` of every state, `init` first.
///
/// # Errors
///
/// The replay reports an error when a step on a kept handle, record, posting or hold names an incarnation that differs from the buffer's pre-call incarnation. Each model state must contain exactly two buffer records, ordered by index: 0, then 1.
///
/// A matched `ret` requires an outstanding raw reference beyond those owned by `kept.lent`.
///
/// A trace that fails to parse or whose model digest or length is wrong; a step that names a handle, record, posting or hold the replay does not keep; otherwise the first step whose action name, outcome, named buffer and incarnation, buffer classes and incarnations, reference counts, free stack or counters differ from the model's state, named with its index.
///
/// # Panics
///
/// If a number the trace records is missing or is not an integer; if a step that ends, lends, gives, hands off, views, stores, restores, detaches, discards, completes or unposts names a buffer outside `0..=1`; or if a production call other than a view panics.
fn replay(json: &str, base: u64, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["pool"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as i64 != n(&trace["#meta"]["pool"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let pools = [PoolSpec {
        kind: KIND,
        count: 2,
        buffer_len: LEN,
    }];
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).unwrap(),
        pools: &pools,
    }
    .validate()
    .unwrap();
    let arena = BufferArena::initialize(
        &validated,
        TestPlatform::heap(4096),
        &mut EngineBudget::new(usize::MAX),
    )
    .unwrap();
    let pools = arena.pools();
    for index in 0..2 {
        pools.set_incarnation(KIND, index, base);
    }
    let mut kept = Kept::default();
    let mut counts = Vec::new();
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let ev = &model["ev"];
        let (act, res) = (
            ev["act"].as_str().ok_or("event action")?,
            ev["res"].as_str().ok_or("event outcome")?,
        );
        // A trace of the model's `step` names the action, or `someRet`, which draws a raw return's arguments.
        let taken = state["mbt::actionTaken"].as_str().ok_or("action taken")?;
        if taken != act && (taken, act) != ("someRet", "ret") {
            return Err(format!("action {i}: the event names another action"));
        }
        let (b, incarnation) = (n(ev, "buf"), base.wrapping_add(n(ev, "inc") as u64));
        let at = b as usize;
        let missing = |what: &str| format!("premise at {i}: no {what} for buffer {b}");
        // A step on a kept handle, record, posting or hold names its buffer at the incarnation the buffer holds before the call.
        let before = pools.snapshot(KIND).get(at).map(|record| record.1);
        if !matches!(act, "acquire" | "post" | "ret")
            && let Some(before) = before.filter(|before| *before != incarnation)
        {
            return Err(format!(
                "{act} at {i}: buffer {b} at {}",
                before.wrapping_sub(base)
            ));
        }
        // The buffer and incarnation a step's production call named, where the call names one.
        let mut named = None;
        let outcome: String = match act {
            "init" if i == 0 => String::new(),
            "acquire" => match arena.acquire(KIND) {
                Ok(buffer) => {
                    let (index, current) = buffer.identity();
                    named = Some((i64::from(index), current));
                    if kept.handles[index as usize].replace(buffer).is_some() {
                        return Err(format!("acquire at {i}: buffer {index} has a handle"));
                    }
                    String::new()
                }
                Err(_) => "Exhausted".into(),
            },
            "post" => match arena.post(KIND) {
                Ok(posting) => {
                    // The posting names no index; it is the one posted buffer the replay keeps no posting for.
                    let index = pools
                        .snapshot(KIND)
                        .iter()
                        .enumerate()
                        .position(|(index, (class, _))| {
                            CLASSES[*class] == "Posted" && kept.posted[index].is_none()
                        })
                        .ok_or(format!("post at {i}: no new posting"))?;
                    named = Some((index as i64, pools.snapshot(KIND)[index].1));
                    if kept.posted[index].replace(posting).is_some() {
                        return Err(format!("post at {i}: buffer {index} has a posting"));
                    }
                    String::new()
                }
                Err(_) => "Exhausted".into(),
            },
            "drop" => {
                let handle = kept.handles[at].take().ok_or_else(|| missing("handle"))?;
                if driver == Driver::DropForgotten {
                    std::mem::forget(handle);
                } else {
                    drop(handle);
                }
                String::new()
            }
            "lend" | "give" => {
                let handle = kept.handles[at].as_ref().ok_or_else(|| missing("handle"))?;
                let hold = handle
                    .source(0..LEN as usize)
                    .ok_or("source range")?
                    .hold()
                    .map_err(|error| format!("{act} at {i}: {error:?}"))?;
                let (_, index, current) = if act == "lend" {
                    let identity = hold.identity();
                    kept.lent[at].push(hold);
                    identity
                } else {
                    hold.into_raw()
                };
                named = Some((i64::from(index), current));
                String::new()
            }
            "unlend" => {
                drop(kept.lent[at].pop().ok_or_else(|| missing("hold"))?);
                String::new()
            }
            "handoff" => {
                let handle = kept.handles[at].take().ok_or_else(|| missing("handle"))?;
                let (_, index, current) = handle
                    .into_device()
                    .map_err(|(_, error)| format!("handoff at {i}: {error:?}"))?;
                named = Some((i64::from(index), current));
                String::new()
            }
            "ret" if driver == Driver::ReturnDropped && res == "Matched" => res.into(),
            "ret" => {
                let sent = if driver == Driver::StaleNamesCurrent && res == "Mismatched" && at < 2 {
                    pools.snapshot(KIND)[at].1
                } else {
                    incarnation
                };
                if before == Some(sent) {
                    pools.device_counts_into(KIND, &mut counts);
                    let (references, holds) = (usize::from(counts[at]), kept.lent[at].len());
                    if (1..=holds).contains(&references) {
                        return Err(format!(
                            "ret at {i}: buffer {b} has {references} references and {holds} kept holds"
                        ));
                    }
                }
                // SAFETY: a return names a live reference when it names the buffer's current incarnation while the buffer's count is positive, and the check above passes such a return only when the count exceeds the holds in `kept.lent`. The replay takes every device reference of this pool with `hold` and keeps the hold, hands it over with `into_raw`, or hands it over with `into_device`, so a count above the kept holds is a handed-over reference the device has yet to return, and this call is that reference's only return.
                if unsafe { arena.nic_return(KIND, b as u32, sent) } {
                    "Matched".into()
                } else {
                    "Mismatched".into()
                }
            }
            "view" => {
                let handle = kept.handles[at].as_mut().ok_or_else(|| missing("handle"))?;
                let viewed = catch_unwind(AssertUnwindSafe(|| {
                    handle.bytes_mut();
                }));
                if viewed.is_ok() { "Viewed" } else { "Refused" }.into()
            }
            "store" => {
                let handle = kept.handles[at].take().ok_or_else(|| missing("handle"))?;
                kept.stored[at] = Some(handle.into_storage());
                String::new()
            }
            "restore" => {
                let held = kept.stored[at].take().ok_or_else(|| missing("record"))?;
                kept.handles[at] = Some(held.into_buffer(pools));
                String::new()
            }
            "detach" => {
                kept.stored[at]
                    .as_ref()
                    .ok_or_else(|| missing("record"))?
                    .detach(pools);
                String::new()
            }
            "discard" => {
                kept.stored[at]
                    .take()
                    .ok_or_else(|| missing("record"))?
                    .free(pools);
                String::new()
            }
            "complete" => {
                let posting = kept.posted[at].take().ok_or_else(|| missing("posting"))?;
                // SAFETY: no device ever received the posting's address, so nothing else reaches the buffer's bytes.
                kept.handles[at] = Some(unsafe { posting.complete() });
                String::new()
            }
            "unpost" => {
                let posting = kept.posted[at].take().ok_or_else(|| missing("posting"))?;
                // SAFETY: no device ever received the posting's address.
                unsafe { posting.unpost() };
                String::new()
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        if outcome != res {
            return Err(format!("{act} at {i}: {outcome}, recorded {res}"));
        }
        if named.is_some_and(|named| named != (b, incarnation)) {
            return Err(format!("{act} at {i}: named {named:?}"));
        }
        let snapshot = pools.snapshot(KIND);
        pools.device_counts_into(KIND, &mut counts);
        let rows = model["bufs"]["#map"].as_array().ok_or("model buffers")?;
        let indices: Vec<Option<u64>> = rows.iter().map(|row| row[0].as_u64()).collect();
        if indices != [Some(0), Some(1)] {
            return Err(format!("buffers at {i}: the model names {indices:?}"));
        }
        for (index, row) in rows.iter().enumerate() {
            let buffer = &row[1];
            let class = CLASSES
                .iter()
                .position(|class| buffer["set"] == *class)
                .ok_or("buffer class")?;
            let expected = (
                class,
                base.wrapping_add(n(buffer, "inc") as u64),
                n(buffer, "nic"),
            );
            let seen = (
                snapshot[index].0,
                snapshot[index].1,
                i64::from(counts[index]),
            );
            if seen != expected {
                return Err(format!(
                    "buffer {index} at {i}: {} at {} with {} references",
                    CLASSES[seen.0],
                    seen.1.wrapping_sub(base),
                    seen.2
                ));
            }
        }
        let stack: Vec<i64> = pools.free_stack(KIND).into_iter().map(i64::from).collect();
        let expected: Vec<i64> = model["stack"]
            .as_array()
            .ok_or("free stack")?
            .iter()
            .map(|index| index.as_i64().unwrap())
            .collect();
        if stack != expected {
            return Err(format!("free stack at {i}: {stack:?}"));
        }
        let report = arena.report(KIND);
        let counters = (
            report.mismatched as i64,
            i64::from(report.retired),
            pools.holds_ended(KIND) as i64,
        );
        if counters
            != (
                n(model, "mismatched"),
                n(model, "retired"),
                n(model, "ended"),
            )
        {
            return Err(format!("counters at {i}: {counters:?}"));
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

/// Whether a trace retires a buffer, which only planted incarnations reach.
fn retires(json: &str) -> bool {
    json.contains("Retired")
}

#[test]
fn committed_pool_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        let planted = replay(json, PLANTED, Driver::Faithful)
            .unwrap_or_else(|error| panic!("{name}, planted: {error}"));
        if !retires(json) {
            assert_eq!(
                replay(json, 0, Driver::Faithful),
                Ok(planted.clone()),
                "{name}, unplanted"
            );
        }
        reached.extend(planted);
    }
    assert!(retires(fixture("retire")), "no trace retires a buffer");
    // `init` and every choice of the model's `step`: `acquire`, `post`, each action `some` chooses among and the raw return `someRet` draws.
    let model = std::str::from_utf8(MODEL).unwrap();
    assert!(
        model.contains("  action step = any {acquire, post, some, someRet}\n")
            && model.contains(
                "    any {drop(b), lend(b), unlend(b), give(b), handoff(b), view(b), store(b), restore(b), detach(b), discard(b), complete(b),\n      unpost(b)}\n"
            ),
        "the model's step chooses among other actions than the replay drives"
    );
    let actions: BTreeSet<&str> = reached.iter().map(|(act, _)| act.as_str()).collect();
    assert_eq!(
        actions,
        BTreeSet::from([
            "acquire", "complete", "detach", "discard", "drop", "give", "handoff", "init", "lend",
            "post", "restore", "ret", "store", "unlend", "unpost", "view",
        ])
    );
    let outcomes: BTreeSet<(&str, &str)> = reached
        .iter()
        .filter(|(_, res)| !res.is_empty())
        .map(|(act, res)| (act.as_str(), res.as_str()))
        .collect();
    assert_eq!(
        outcomes,
        BTreeSet::from([
            ("acquire", "Exhausted"),
            ("post", "Exhausted"),
            ("ret", "Matched"),
            ("ret", "Mismatched"),
            ("view", "Refused"),
            ("view", "Viewed"),
        ])
    );
}

/// Each wrong driver changes the production side of one model step, and the replay refuses it at the first state the difference shows in: a dropped return through the buffer's reference count at the return's own state, a stale return that names the current incarnation through the return's own outcome, and a forgotten handle through the buffer's class at the drop's own state.
#[test]
fn negative_control_a_wrong_pool_driver_fails_at_the_step_it_changes() {
    // heldThroughDrop: acquire, give(0), give(0), drop(0), acquire, ret(0, 0) at 6.
    assert_eq!(
        replay(fixture("heldThroughDrop"), 0, Driver::ReturnDropped).unwrap_err(),
        "buffer 0 at 6: Nic at 0 with 2 references"
    );
    // olderIncarnation: ..., acquire at 5 takes buffer 0 at incarnation 1, give(0), ret(0, 0) at 7 is mismatched.
    for base in [0, PLANTED] {
        assert_eq!(
            replay(fixture("olderIncarnation"), base, Driver::StaleNamesCurrent).unwrap_err(),
            "ret at 7: Matched, recorded Mismatched"
        );
    }
    // posting: post, complete(0), lend(0), drop(0) at 4, which the model leaves `Nic` and a forgotten handle leaves `App`.
    assert_eq!(
        replay(fixture("posting"), PLANTED, Driver::DropForgotten).unwrap_err(),
        "buffer 0 at 4: App at 0 with 1 references"
    );
}

#[test]
fn negative_control_a_raw_return_of_a_held_reference_fails_before_the_call() {
    // A matched `ret` requires an outstanding raw reference beyond those owned by `kept.lent`.
    let mut trace: Value = serde_json::from_str(fixture("posting")).unwrap();
    let state = &mut trace["states"][5];
    state["mbt::actionTaken"] = "ret".into();
    state[STATE]["ev"]["act"] = "ret".into();
    state[STATE]["ev"]["res"] = "Matched".into();
    for base in [0, PLANTED] {
        assert_eq!(
            replay(&trace.to_string(), base, Driver::Faithful).unwrap_err(),
            "ret at 5: buffer 0 has 1 references and 1 kept holds"
        );
    }
}

/// A trace altered in one state's recorded field fails at that state, through the comparison that reads the field; a stale model digest or a missing state fails the trace before any state replays.
#[test]
fn negative_control_an_altered_pool_trace_fails_at_the_altered_state() {
    let json = fixture("heldThroughDrop");
    let altered = |at: usize, edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(json).unwrap();
        edit(&mut trace["states"][at]);
        replay(&trace.to_string(), 0, Driver::Faithful).unwrap_err()
    };
    let number = |value: i64| serde_json::json!({ "#bigint": value.to_string() });
    // State 4 is the drop of a handle whose buffer the device holds twice: the buffer stays off the free stack as `Nic`.
    assert_eq!(
        altered(4, &|state| state[STATE]["bufs"]["#map"][0][1]["set"] =
            "Free".into()),
        "buffer 0 at 4: Nic at 0 with 2 references"
    );
    assert_eq!(
        altered(4, &|state| state[STATE]["stack"] =
            serde_json::json!([number(1), number(0)])),
        "free stack at 4: [1]"
    );
    assert_eq!(
        altered(6, &|state| state[STATE]["ev"]["res"] = "Mismatched".into()),
        "ret at 6: Matched, recorded Mismatched"
    );
    assert_eq!(
        altered(7, &|state| state[STATE]["ended"] = number(0)),
        "counters at 7: (0, 0, 1)"
    );
    assert_eq!(
        altered(8, &|state| state[STATE]["ev"]["inc"] = number(0)),
        "acquire at 8: named Some((0, 1))"
    );
    // State 4's `drop` ends the handle of buffer 0 at incarnation 0.
    assert_eq!(
        altered(4, &|state| state[STATE]["ev"]["inc"] = number(1)),
        "drop at 4: buffer 0 at 0"
    );
    assert_eq!(
        altered(4, &|state| state[STATE]["bufs"]["#map"] =
            serde_json::json!([])),
        "buffers at 4: the model names []"
    );
    assert_eq!(
        altered(3, &|state| state["mbt::actionTaken"] = "lend".into()),
        "action 3: the event names another action"
    );
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, 0, Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
    let mut trace: Value = serde_json::from_str(json).unwrap();
    trace["states"].as_array_mut().unwrap().pop();
    assert_eq!(
        replay(&trace.to_string(), 0, Driver::Faithful).unwrap_err(),
        "fixture length"
    );
}
