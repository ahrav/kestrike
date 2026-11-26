//! Replays committed traces of the volume read model `quint/read.qnt` against
//! [`Volume`](super::Volume): `read_raw`, `grant_read`, `cancel_read` and the
//! tick, over the simulated disk, on one thread.
//!
//! The volume reads one command ahead with two-chunk response buffers, and the
//! placed record has a five-chunk body, so the read takes three commands:
//! command 1 carries the header and chunk 0, command 2 chunks 1 and 2, and
//! command 3 chunks 3 and 4. Each model step runs its production input: the
//! admission, a grant, a cancel, or the release of one held read command as
//! read or as a device error. The replay holds every read command the device
//! accepts and then runs three device steps and ticks, holding again after
//! each, so the volume finishes what the input enabled. After every step it
//! requires the events the volume delivered (each handed-off command's chunk
//! range, in order, and the one `Done` with its status), the grant's or
//! cancel's result, the number of commands the device newly accepted and
//! `read_drained` to equal what the model's state gives, and it requires the
//! handed-off bytes to be the placed payload's prefix, the whole payload at
//! `Complete`.

use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::lifecycle_tests::step;
use super::volume_tests::{
    CHUNK, SESSION, TICK, arena_with_reads, attach, place, record, storage_reading_ahead_by,
};
use super::{ReadEvent, ReadOp};
use crate::storage::device::sim::{Event, Fault};
use crate::storage::device::{CommandToken, DeviceStatus};

const MODEL: &[u8] = include_bytes!("../../../../../quint/read.qnt");
const STATE: &str = "readCase::read::st";
/// The chunk range, in chunks, each of the read's three commands hands off.
const RANGES: [std::ops::Range<u64>; 3] = [0..1, 1..3, 3..5];

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("read_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 16] = fixtures![
    "complete",
    "ahead_first",
    "kept_merged",
    "cancel_two_out",
    "cancel_after_chunk",
    "failed_ahead",
    "failed_ahead_kept",
    "failed_current",
    "failed_last",
    "failed_ahead_last",
    "newest_first_tail",
    "one_at_a_time",
    "failed_first",
    "step_a",
    "step_b",
    "step_c",
];

/// How the replay maps a model step to production inputs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model step runs its production input.
    Faithful,
    /// A terminal the model records as failed completes as read.
    FaultDropped,
    /// The model's cancel runs nothing.
    CancelDropped,
    /// A terminal releases the other outstanding command when there is one.
    OtherReleased,
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

/// The events the model's step delivers: each handed-off command's chunk
/// range, then its `Done`.
fn delivered(ev: &Value) -> Vec<String> {
    let mut events: Vec<String> = ev["handed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|command| format!("{:?}", RANGES[command.as_u64().unwrap() as usize - 1]))
        .collect();
    match ev["done"].as_str().unwrap() {
        "" => {}
        status => events.push(format!("Done {status}")),
    }
    events
}

/// Replays one trace and returns the `(action, result, done)` of every state,
/// `init` first.
///
/// # Errors
///
/// A trace that does not parse, has no states, or whose model digest or
/// length is wrong; otherwise the first state whose recorded action differs
/// from its event's or is unknown, whose event lacks its action, result, flag
/// or outstanding commands, whose admission is refused, whose terminal names
/// no accepted command, or whose production result, delivered events, newly
/// accepted command count, drained flag or handed-off bytes differ from the
/// model's state.
///
/// # Panics
///
/// If a number, the handed-off list, the done string or an outstanding
/// command the trace records is missing or has another type.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["read"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as u64 != n(&trace["#meta"]["read"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let storage = storage_reading_ahead_by(2, 1);
    let arena = arena_with_reads(5, 2 * CHUNK);
    let (mut volume, control) = attach(&storage, &arena, TICK);
    let placed = record(0, 0, 5 * CHUNK, SESSION, 1);
    place(&storage, &control, &placed);
    // The read's commands in submission order, each held at its acceptance.
    let mut tokens: Vec<CommandToken> = Vec::new();
    let accepted = |tokens: &mut Vec<CommandToken>| {
        let all: Vec<CommandToken> = control
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Submitted(token, _) => Some(*token),
                _ => None,
            })
            .collect();
        let new = all.len() - tokens.len();
        for token in &all[tokens.len()..] {
            control.hold(*token);
        }
        *tokens = all;
        new
    };
    let mut op: Option<ReadOp> = None;
    let mut out = Vec::with_capacity(16);
    let mut bytes = Vec::new();
    let mut reached = vec![("init".to_owned(), String::new(), String::new())];
    for (i, state) in states.iter().enumerate().skip(1) {
        let model = &state[STATE];
        let ev = &model["ev"];
        let act = ev["act"].as_str().ok_or("event action")?;
        if state["mbt::actionTaken"] != act {
            return Err(format!("action {i}: the event names another action"));
        }
        let result = match act {
            "admit" => {
                op = Some(
                    volume
                        .read_raw(&placed.read, u64::MAX)
                        .map_err(|refusal| format!("admit at {i}: {refusal:?}"))?,
                );
                String::new()
            }
            "grant" => match volume.grant_read(op.ok_or("no read")?) {
                Ok(grant) => format!("{grant:?}"),
                Err(refusal) => format!("{refusal:?}"),
            },
            "cancel" if driver == Driver::CancelDropped => {
                ev["res"].as_str().ok_or("event result")?.to_owned()
            }
            "cancel" => match volume.cancel_read(op.ok_or("no read")?) {
                Ok(()) => String::new(),
                Err(refusal) => format!("{refusal:?}"),
            },
            "terminal" => {
                let command = n(ev, "arg") as usize - 1;
                let ok = ev["ok"].as_bool().ok_or("event flag")?;
                let before: Vec<u64> = states[i - 1][STATE]["cmds"]["#set"]
                    .as_array()
                    .ok_or("outstanding commands")?
                    .iter()
                    .map(|command| command.as_u64().unwrap())
                    .collect();
                let other = before.iter().find(|other| **other as usize != command + 1);
                let token = match other {
                    Some(other) if driver == Driver::OtherReleased => tokens[*other as usize - 1],
                    _ => *tokens.get(command).ok_or("no such command")?,
                };
                control.release(token);
                if !ok && driver != Driver::FaultDropped {
                    control.fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
                }
                String::new()
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        if result != ev["res"].as_str().ok_or("event result")? {
            return Err(format!("{act} at {i}: result {result}"));
        }
        let mut new = accepted(&mut tokens);
        for _ in 0..3 {
            step(&mut volume, &control, 0, &mut out);
            new += accepted(&mut tokens);
        }
        let mut events = Vec::new();
        for event in out.drain(..) {
            match event {
                ReadEvent::Chunk { range, chunk, .. } => {
                    if range.start != bytes.len() as u64 {
                        return Err(format!("bytes at {i}: a chunk out of payload order"));
                    }
                    events.push(format!(
                        "{:?}",
                        range.start / u64::from(CHUNK)..range.end / u64::from(CHUNK)
                    ));
                    bytes.extend_from_slice(chunk.bytes());
                }
                ReadEvent::Done { status, .. } => events.push(format!("Done {status:?}")),
            }
        }
        if events != delivered(ev) {
            return Err(format!("{act} at {i}: events {events:?}"));
        }
        if new as u64 != n(ev, "issued") {
            return Err(format!("{act} at {i}: {new} commands accepted"));
        }
        let drained = model["phase"] == "done"
            && model["cmds"]["#set"]
                .as_array()
                .ok_or("outstanding commands")?
                .is_empty();
        if op.is_some_and(|op| volume.read_drained(op)) != drained {
            return Err(format!("drained at {i}: {}", !drained));
        }
        if !placed.payload.starts_with(&bytes)
            || (ev["done"] == "Complete" && bytes != placed.payload)
        {
            return Err(format!("bytes at {i}: {} handed off", bytes.len()));
        }
        reached.push((
            act.to_owned(),
            result,
            ev["done"].as_str().ok_or("event done")?.to_owned(),
        ));
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
fn committed_read_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        reached.extend(
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}")),
        );
    }
    // `init` and every choice of the model's `step`.
    assert!(
        std::str::from_utf8(MODEL)
            .unwrap()
            .contains("    any {admit, grant, terminal(k, ok), cancel}\n"),
        "the model's step chooses among other actions than the replay drives"
    );
    let actions: BTreeSet<&str> = reached.iter().map(|(act, _, _)| act.as_str()).collect();
    assert_eq!(
        actions,
        BTreeSet::from(["admit", "cancel", "grant", "init", "terminal"])
    );
    for (act, result, done) in [
        ("grant", "Added", ""),
        ("grant", "Merged", ""),
        ("grant", "Exhausted", ""),
        ("grant", "Stale", ""),
        ("cancel", "", "Cancelled"),
        ("cancel", "Stale", ""),
        ("terminal", "", ""),
        ("terminal", "", "Complete"),
        ("terminal", "", "DeviceError"),
    ] {
        assert!(
            reached.contains(&(act.to_owned(), result.to_owned(), done.to_owned())),
            "{act} {result} {done}"
        );
    }
}

/// Each wrong driver changes one thing the model's step stands for, and the
/// replay refuses it through its event comparison at the step where the
/// volume then delivers otherwise than the model.
#[test]
fn negative_control_a_driver_that_drops_a_fault_or_a_cancel_or_ends_another_command_fails_the_replay()
 {
    // failed_current: admit, grant, grant, terminal(1, false) at 4. A first
    // command that completes instead hands off chunk 0 and lets the kept
    // grant submit command 3.
    assert_eq!(
        replay(fixture("failed_current"), Driver::FaultDropped).unwrap_err(),
        r#"terminal at 4: events ["0..1"]"#
    );
    // cancel_two_out: admit, grant, cancel at 3. Without the cancel the
    // volume delivers no Done.
    assert_eq!(
        replay(fixture("cancel_two_out"), Driver::CancelDropped).unwrap_err(),
        "cancel at 3: events []"
    );
    // complete: admit, grant, terminal(1, true) at 3 with commands 1 and 2
    // outstanding. Ending command 2 instead hands off nothing, because its
    // chunks wait for command 1.
    assert_eq!(
        replay(fixture("complete"), Driver::OtherReleased).unwrap_err(),
        "terminal at 3: events []"
    );
}

/// A trace altered in one recorded field fails at the altered state, through
/// the comparison that reads the field; a stale model digest or a missing
/// state fails the trace before any state replays.
#[test]
fn negative_control_an_altered_trace_fails_at_the_altered_state() {
    let json = fixture("ahead_first");
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(json).unwrap();
        edit(&mut trace);
        replay(&trace.to_string(), Driver::Faithful).unwrap_err()
    };
    let number = |value: u64| serde_json::json!({"#bigint": value.to_string()});
    // ahead_first: admit, grant, grant (kept) at 3, terminal(2, true) at 4,
    // terminal(1, true) at 5, which hands off commands 1 and 2 and submits
    // command 3, grant (Exhausted) at 6, terminal(3, true) at 7.
    assert_eq!(
        edited(&|trace| trace["states"][5][STATE]["ev"]["handed"] = serde_json::json!([number(1)])),
        r#"terminal at 5: events ["0..1", "1..3"]"#
    );
    assert_eq!(
        edited(&|trace| trace["states"][4][STATE]["ev"]["handed"] = serde_json::json!([number(2)])),
        "terminal at 4: events []"
    );
    assert_eq!(
        edited(&|trace| trace["states"][7][STATE]["ev"]["done"] = "DeviceError".into()),
        r#"terminal at 7: events ["3..5", "Done Complete"]"#
    );
    assert_eq!(
        edited(&|trace| trace["states"][6][STATE]["ev"]["res"] = "Added".into()),
        "grant at 6: result Exhausted"
    );
    assert_eq!(
        edited(&|trace| trace["states"][5][STATE]["ev"]["issued"] = number(0)),
        "terminal at 5: 1 commands accepted"
    );
    assert_eq!(
        edited(&|trace| trace["states"][7][STATE]["phase"] = "reading".into()),
        "drained at 7: true"
    );
    assert_eq!(
        edited(&|trace| trace["states"][2]["mbt::actionTaken"] = "cancel".into()),
        "action 2: the event names another action"
    );
    assert_eq!(
        edited(&|trace| trace["#meta"]["read"]["model_sha256"] = "0".into()),
        "fixture model digest"
    );
    assert_eq!(
        edited(&|trace| {
            trace["states"].as_array_mut().unwrap().pop();
        }),
        "fixture length"
    );
}
