//! Replays committed traces of the reclaim model `quint/reclaim.qnt` against a live [`Storage`] on the heap-backed platform: one slot, two registered readers, and the retirement, certification, service and reuse of the slot's object.
//!
//! Each model step runs the storage code for one model action: a reader's `enter` or the exit of its guard, a lease's test-only `duplicate` or its drop, the resident's test-only `retire` over the production retirement, one `Storage::certify` funded for one record, one `Storage::service`, or the next object's publication through [`handoff`], which reserves, completes and hands off. The replay then requires the call's return, and the outcome the replay derives from it, to equal the step's recorded event, and the era report, both registration records' pins, the slot's state, incarnation, count and stamp, the pass cursor and `Storage::outstanding` to equal the model's state.
//! The model's `watch`, `returns` and `published` are history its invariants read; they stay inside the model, where `quint run --invariant safety` checks them as each trace is generated.
//!
//! Each reader runs on its own thread, which owns the reader's [`Registration`] and holds its guard between an entry and the exit, since a guard borrows its registration and stays on the thread that pinned. The replay sends one command at a time and waits for its reply, so one call runs at a time in the model's order.
//!
//! `python3 quint/reclaim_fixtures.py --quint QUINT --output DIR` writes the traces with `quint run --mbt`: five directed recipes and six traces of eighteen steps of the model's own `step` under pinned seeds. Each trace names the model's sha256, and a trace of another model text fails before any state replays.
//! The replay is evidence for exactly the schedules these traces record.

use std::collections::BTreeSet;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::budget::WorkBudget;
use super::grace_tests::{handoff, refs, retire_era, unclaimed_storage};
use super::owner::Storage;
use super::register::{PinError, Registration};
use super::release::{Outstanding, certify_minimum};
use super::tables::SlotState;
use super::test_platform::TestPlatform;
use super::{ExtentLease, RegistrationIndex, Resident, RetireOutcome, SlotIndex};

const MODEL: &[u8] = include_bytes!("../../../../quint/reclaim.qnt");
const STATE: &str = "reclaimCase::reclaim::st";
/// The model's value for a pass that has seen no pin.
const NOPIN: i64 = 1000;
/// The model's readers, one registration record each.
const READERS: usize = 2;
/// Steps that fund any one service call on the one-slot storage.
const SERVICE: usize = 400;

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("reclaim_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 11] = fixtures![
    "anchorLast",
    "rightLast",
    "pinnedReaderHolds",
    "reuse",
    "leases",
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
    /// Every model action runs its storage code.
    Faithful,
    /// The model's exit leaves the guard in place.
    ExitDropped,
    /// The model's dropped lease stays held.
    UnleaseDropped,
    /// The model's certification call that completes a pass runs nothing.
    CompletionSkipped,
}

/// What the replay asks of a reader's thread.
enum Command {
    Enter,
    Exit,
}

/// The replay's end of one reader's thread: where it sends commands and where each reply arrives.
type Link = (Sender<Command>, Receiver<Result<(), PinError>>);

/// One reader: its registration lives on the thread, and a guard lives there from an `Enter` to the next `Exit`. The thread ends when its command channel closes, dropping the guard, if any, and then the registration.
fn reader(
    mut registration: Registration<'static, TestPlatform>,
    commands: Receiver<Command>,
    replies: Sender<Result<(), PinError>>,
) {
    while let Ok(Command::Enter) = commands.recv() {
        match registration.enter() {
            Ok(guard) => {
                replies.send(Ok(())).unwrap();
                let Ok(Command::Exit) = commands.recv() else {
                    return;
                };
                guard.exit();
                replies.send(Ok(())).unwrap();
            }
            Err(refused) => replies.send(Err(refused)).unwrap(),
        }
    }
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

/// What the storage holds, in the order the model's state is read: the era, the certified era, both pins with zero for an inactive record, the slot's state, incarnation and count, its stamp while retired, the pass as its start era, smallest pin and next record, and what is outstanding.
type Held = (
    u64,
    u64,
    [u64; READERS],
    (SlotState, u32),
    usize,
    Option<u64>,
    Option<(u64, u64, usize)>,
    Outstanding,
);

fn held(storage: &Storage<TestPlatform>, slot: usize) -> Held {
    let eras = storage.era_report().unwrap();
    let pin = |record| {
        storage
            .registration_report(RegistrationIndex(record))
            .unwrap()
            .pinned_era
            .unwrap_or(0)
    };
    let state = storage.slot_state(SlotIndex(slot)).unwrap();
    let cursor = storage.grace_cursor().load();
    (
        eras.era,
        eras.certified,
        [pin(0), pin(1)],
        state,
        refs(storage, slot),
        (state.0 == SlotState::Retired).then(|| retire_era(storage, slot)),
        cursor
            .in_progress()
            .then(|| (cursor.start_era, cursor.min_pin(), cursor.next)),
        storage.outstanding(),
    )
}

/// What the model's state holds, as [`held`] reads the storage.
fn modelled(model: &Value) -> Result<Held, String> {
    let mut pins = [0; READERS];
    for row in model["pins"]["#map"].as_array().ok_or("model pins")? {
        let at = row[0].as_u64().ok_or("pin record")? as usize;
        pins[at] = row[1].as_u64().ok_or("pin era")?;
    }
    let state = match model["phase"].as_str().ok_or("phase")? {
        "Resident" => SlotState::Resident,
        "Retired" => SlotState::Retired,
        "Free" => SlotState::Free,
        other => return Err(format!("phase {other}")),
    };
    let rights = n(model, "rights") as usize;
    let count = rights + usize::from(model["anchored"].as_bool().ok_or("anchor flag")?);
    let pass = &model["pass"];
    let low = n(pass, "low");
    Ok((
        n(model, "era") as u64,
        n(model, "certified") as u64,
        pins,
        (state, n(model, "inc") as u32),
        count,
        (state == SlotState::Retired).then(|| n(model, "stamp") as u64),
        pass["on"].as_bool().ok_or("pass flag")?.then(|| {
            (
                n(pass, "start") as u64,
                if low == NOPIN { u64::MAX } else { low as u64 },
                n(pass, "next") as usize,
            )
        }),
        Outstanding {
            live: usize::from(state == SlotState::Resident),
            pending: usize::from(state == SlotState::Retired),
            leases: rights,
            anchored: usize::from(count > 0),
            unverifiable: false,
            registrations: READERS,
        },
    ))
}

/// Replays one trace and returns the `(action, outcome)` of every state, `init` first; a service's outcome also names an anchor it released.
///
/// # Errors
///
/// A trace that fails to parse or whose model digest or length is wrong; a step whose field the replay cannot read or that names an unknown action; otherwise the first step whose action name, production return or storage state differ from the model's event and state, named with its index.
///
/// # Panics
///
/// If a number the trace records is missing or is not an integer, a recorded reader lies outside `0..=1`, or a step asks for a call the storage's own handles rule out: a lease with none held, a retirement with no resident.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["reclaim"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as i64 != n(&trace["#meta"]["reclaim"], "steps") + 1 {
        return Err("fixture length".into());
    }
    // The readers' threads borrow the storage for as long as they run, so each replay leaks its one-slot storage.
    let storage: &'static Storage<TestPlatform> =
        Box::leak(Box::new(unclaimed_storage(1, READERS)));
    let mut readers: Vec<Link> = Vec::new();
    let mut threads: Vec<JoinHandle<()>> = Vec::new();
    for record in 0..READERS {
        let registration = storage.register().map_err(|e| format!("{e:?}"))?;
        if registration.index() != RegistrationIndex(record) {
            return Err(format!("reader {record} took another record"));
        }
        let (commands, inbox) = channel();
        let (outbox, replies) = channel();
        threads.push(std::thread::spawn(move || {
            reader(registration, inbox, outbox)
        }));
        readers.push((commands, replies));
    }
    let body = [7; 20];
    let (first, lease) = handoff(storage, &body);
    let slot = first.id().slot_index();
    let mut resident: Option<Resident<'static, TestPlatform>> = Some(first);
    let mut leases: Vec<ExtentLease<'static, TestPlatform>> = vec![lease];
    let mut reached = Vec::new();
    let mut step = |i: usize, state: &Value| -> Result<(String, String), String> {
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
        let at = n(ev, "reader") as usize;
        let ask = |command| -> Result<(), String> {
            readers[at].0.send(command).map_err(|e| e.to_string())?;
            readers[at]
                .1
                .recv()
                .map_err(|e| e.to_string())?
                .map_err(|refused| format!("{act} at {i}: {refused:?}"))
        };
        // The call's return as the model records it: the outcome, the value, and whether service released the anchor and returned the slot.
        let (outcome, value, released, returned): (&str, u64, bool, bool) = match act {
            "init" if i == 0 => ("", 0, false, false),
            "enter" => {
                ask(Command::Enter)?;
                ("Ok", held(storage, slot).2[at], false, false)
            }
            "exit" if driver == Driver::ExitDropped => ("Ok", 0, false, false),
            "exit" => {
                ask(Command::Exit)?;
                ("Ok", 0, false, false)
            }
            "lease" => {
                let right = leases.last().expect("a held lease").duplicate();
                leases.push(right);
                ("Ok", leases.len() as u64, false, false)
            }
            "unlease" if driver == Driver::UnleaseDropped => {
                ("Ok", leases.len() as u64 - 1, false, false)
            }
            "unlease" => {
                drop(leases.pop().expect("a held lease"));
                ("Ok", leases.len() as u64, false, false)
            }
            "retire" => {
                let stamp = held(storage, slot).0;
                match resident.take().expect("a resident object").retire() {
                    RetireOutcome::Recorded => ("Ok", stamp, false, false),
                    RetireOutcome::Parked => ("Parked", stamp, false, false),
                }
            }
            "certify" if driver == Driver::CompletionSkipped && res == "Certified" => {
                (res, n(ev, "value") as u64, false, false)
            }
            "certify" => {
                let report = storage
                    .certify(&mut WorkBudget::new(certify_minimum(READERS)))
                    .map_err(|error| format!("certify at {i}: {error:?}"))?;
                match (report.visited, report.certified, report.budget_exhausted) {
                    (0, Some(certified), false) => ("Idle", certified, false, false),
                    (1, None, true) => ("Advanced", 0, false, false),
                    (1, Some(certified), false) => ("Certified", certified, false, false),
                    _ => return Err(format!("certify at {i}: {report:?}")),
                }
            }
            "service" => {
                let report = storage
                    .service(&mut WorkBudget::new(SERVICE))
                    .map_err(|error| format!("service at {i}: {error:?}"))?;
                match (
                    report.visited,
                    report.held,
                    report.released,
                    report.serviced,
                    report.partial,
                ) {
                    (0, 0, 0, 0, 0) => ("Nothing", 0, false, false),
                    (1, 1, released, 0, 0) if released <= 1 => ("Held", 0, released == 1, false),
                    (1, 0, released, 1, 0) if released <= 1 => ("Returned", 0, released == 1, true),
                    _ => return Err(format!("service at {i}: {report:?}")),
                }
            }
            "republish" => {
                let (next, lease) = handoff(storage, &body);
                if next.id().slot_index() != slot {
                    return Err(format!("republish at {i}: slot {}", next.id().slot_index()));
                }
                let incarnation = u64::from(next.id().incarnation());
                resident = Some(next);
                leases.push(lease);
                ("Ok", incarnation, false, false)
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        };
        let recorded = (
            res,
            n(ev, "value") as u64,
            ev["released"].as_bool().ok_or("released flag")?,
            ev["returned"].as_bool().ok_or("returned flag")?,
        );
        if (outcome, value, released, returned) != recorded {
            return Err(format!(
                "{act} at {i}: {outcome} {value} {released} {returned}, recorded {recorded:?}"
            ));
        }
        let now = held(storage, slot);
        if now != modelled(model)? {
            return Err(format!("state at {i}: {now:?}"));
        }
        let detail = match (act, released) {
            ("service", true) => format!("{res} released"),
            _ => res.to_owned(),
        };
        Ok((act.to_owned(), detail))
    };
    let mut failed = None;
    for (i, state) in states.iter().enumerate() {
        match step(i, state) {
            Ok(pair) => reached.push(pair),
            Err(error) => {
                failed = Some(error);
                break;
            }
        }
    }
    // Closing the command channels ends each reader, whose guard and registration drop on its own thread.
    drop(readers);
    for thread in threads {
        thread.join().map_err(|_| "a reader panicked")?;
    }
    failed.map_or(Ok(reached), Err)
}

/// Every committed trace replays, and together the traces reach `init` and every choice of the model's `step` with each of its outcomes.
#[test]
fn committed_reclaim_traces_replay_against_a_live_storage() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        let steps =
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}"));
        reached.extend(steps);
    }
    let expected: BTreeSet<(String, String)> = [
        ("init", ""),
        ("enter", "Ok"),
        ("exit", "Ok"),
        ("lease", "Ok"),
        ("unlease", "Ok"),
        ("retire", "Ok"),
        ("certify", "Idle"),
        ("certify", "Advanced"),
        ("certify", "Certified"),
        ("service", "Nothing"),
        ("service", "Held"),
        ("service", "Held released"),
        ("service", "Returned"),
        ("service", "Returned released"),
        ("republish", "Ok"),
    ]
    .into_iter()
    .map(|(act, outcome)| (act.to_owned(), outcome.to_owned()))
    .collect();
    assert_eq!(reached, expected);
}

/// A driver that keeps a guard past its exit, one that keeps a dropped lease and one that skips the certification call that completes a pass each fail the replay at the step they change, through the replay's own comparison.
#[test]
fn negative_control_a_wrong_reclaim_driver_fails_the_replay_at_its_step() {
    let trace = FIXTURES
        .iter()
        .find(|(name, _)| *name == "pinnedReaderHolds")
        .unwrap()
        .1;
    for (driver, at) in [
        (Driver::UnleaseDropped, "state at 2: "),
        (Driver::CompletionSkipped, "state at 5: "),
        (Driver::ExitDropped, "state at 7: "),
    ] {
        let error = replay(trace, driver).unwrap_err();
        assert!(error.starts_with(at), "{error}");
    }
}

/// A trace whose recorded certified era is raised by one fails the replay at that state.
#[test]
fn a_perturbed_reclaim_trace_fails_the_replay_at_the_changed_state() {
    let mut trace: Value = serde_json::from_str(FIXTURES[2].1).unwrap();
    let certified = &mut trace["states"][6][STATE]["certified"]["#bigint"];
    assert_eq!(certified.as_str(), Some("1"));
    *certified = "2".into();
    let error = replay(&trace.to_string(), Driver::Faithful).unwrap_err();
    assert!(error.starts_with("state at 6: "), "{error}");
}

/// A trace that names another model text is refused before any state replays.
#[test]
fn a_reclaim_trace_of_another_model_text_is_refused() {
    let mut trace: Value = serde_json::from_str(FIXTURES[0].1).unwrap();
    trace["#meta"]["reclaim"]["model_sha256"] = "0".repeat(64).into();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "fixture model digest"
    );
}
