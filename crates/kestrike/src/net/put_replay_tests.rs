//! Replays committed traces of the PUT owner model `quint/put.qnt` against the
//! owner, its storage and the simulated disk and links of the `put_tests`
//! scene, on one thread.
//!
//! Each model step runs its production input: a BEGIN, PREPARE, DATA or CANCEL
//! frame of peer 1, a DATA frame whose body differs from the credited one, an
//! invalidation of the key, the terminal of one of the upload's two write
//! commands, or a successor upload of the same key from peer 0 and its one
//! write's terminal. The replay holds every write command at its submission
//! and ends it only at the model's terminal step, as written or as a device
//! error. After every step it requires the PUT frames the owner sent each
//! peer, the owner's live upload count, the device's outstanding commands and
//! the key's visibility to equal what the model's state gives, and each
//! range's write command to be outstanding on the device exactly while the
//! model's range is `submitted`. At a
//! trace's end it reads the key back and requires the bytes of the upload the
//! model published. Range 0 of the model is the write that carries the
//! record's header, the command at the lower device offset, and range 1 the
//! other; the replay requires the submission order the model records.
//!
//! The model's revoked upload ends `Contended` at a new fragment only when
//! the fragment extends the cumulative base, which is when the owner hands
//! payload to the fill; a fragment behind a missing one is credited and
//! acknowledged like any other. The traces `revoked_behind_base` and
//! `revoked_behind_base_failed` hold that schedule.

use std::cell::RefCell;
use std::collections::BTreeSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::frame::{Header, Kind, Status};
use super::geometry::{FRAGMENT_LEN, FragmentGeometry};
use super::owner_tests::{PRINCIPALS, key, payload};
use super::put_tests::{Scene, cancel, error, prepare, request, scene};
use crate::storage::device::sim::{Captured, Fault};
use crate::storage::owner_fixture::write_tokens;
use crate::storage::{CommandToken, DeviceStatus, WorkBudget};

const MODEL: &[u8] = include_bytes!("../../../../quint/put.qnt");
const STATE: &str = "putCase::put::st";
/// The key every trace uploads.
const NAME: u8 = 5;

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("put_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 17] = fixtures![
    "published",
    "out_of_order",
    "successor",
    "failed_header",
    "failed_payload",
    "cancel_draining",
    "cancel_authority",
    "conflict_ended",
    "conflict_draining",
    "revoked_at_data",
    "revoked_failed",
    "revoked_at_completion",
    "revoked_behind_base",
    "revoked_behind_base_failed",
    "step_a",
    "step_b",
    "step_c",
];

/// How the replay maps a model step to production inputs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Every model step runs its production input.
    Faithful,
    /// A terminal the model records as failed completes as written.
    FaultDropped,
    /// The model's invalidation runs nothing.
    InvalidateDropped,
    /// Write commands stay unheld, so the disk ends them at its next tick.
    HoldDropped,
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

/// The model's `ws`: the state of ranges 0 and 1.
fn ranges(model: &Value) -> [&str; 2] {
    let rows = model["ws"]["#map"].as_array().unwrap();
    let mut states = [""; 2];
    for row in rows {
        states[row[0].as_u64().unwrap() as usize] = row[1].as_str().unwrap();
    }
    states
}

/// The DATA frame of fragment `index` of `object` from `peer`.
fn fragment(
    scene: &mut Scene<'_, '_>,
    peer: usize,
    at: u64,
    serial: u64,
    object: &[u8],
    index: u32,
) -> (Header, Vec<u8>) {
    let start = index as usize * FRAGMENT_LEN as usize;
    let body = object[start..(start + FRAGMENT_LEN as usize).min(object.len())].to_vec();
    let total = object.len() as u64;
    let header = scene.frame(peer, Kind::PutData, at, NAME, |header| {
        header.allocation = serial;
        header.metadata_len = 0;
        header.body_len = total as u32;
        header.total = total;
        header.count = FragmentGeometry::fragments(total) as u32;
        header.index = index;
        header.offset = start as u64;
        header.datagram_len = body.len() as u32;
    });
    (header, body)
}

/// The PUT frames the owner sent `peer` since the last call, each as the
/// model names a reply, with a READY's grant and an ACK's base.
fn sent(scene: &mut Scene<'_, '_>, peer: usize) -> Vec<String> {
    scene
        .replies(peer)
        .iter()
        .map(|header| match header.kind {
            Kind::PutAuthority => "AUTHORITY".into(),
            Kind::PutReady => format!("READY {}", header.grant),
            Kind::PutAck => format!("ACK {}", header.index),
            Kind::PutResult => "RESULT".into(),
            Kind::PutError => match error(header) {
                Some(Status::Cancelled) => "Cancelled".into(),
                Some(Status::ConflictingData) => "ConflictingData".into(),
                Some(Status::DeviceError) => "DeviceError".into(),
                Some(Status::Contended) => "Contended".into(),
                status => format!("ERROR {status:?}"),
            },
            kind => format!("{kind:?}"),
        })
        .collect()
}

/// The device start of write command `token`.
fn device_start(scene: &Scene<'_, '_>, token: CommandToken) -> u64 {
    scene
        .control
        .capture()
        .events
        .iter()
        .find_map(|event| match *event {
            Captured::Submitted {
                token: found,
                device,
                ..
            } if found == token => Some(device.start()),
            _ => None,
        })
        .unwrap()
}

/// The recipe entry of action `act` with the arguments the event `ev`
/// records.
fn recorded(act: &str, ev: &Value) -> String {
    let (arg, ok) = (n(ev, "arg"), ev["ok"] == true);
    match act {
        "data" | "differ" => format!("{act}({arg})"),
        "terminal" => format!("terminal({arg}, {ok})"),
        "sterminal" => format!("sterminal({ok})"),
        _ => act.to_owned(),
    }
}

/// The commands whose completions the device handed to the owner.
fn delivered(scene: &Scene<'_, '_>) -> Vec<CommandToken> {
    scene
        .control
        .capture()
        .events
        .iter()
        .filter_map(|event| match *event {
            Captured::Delivered { token, .. } => Some(token),
            _ => None,
        })
        .collect()
}

/// What one replayed upload holds between steps.
struct Replay {
    driver: Driver,
    object: Vec<u8>,
    next: Vec<u8>,
    at: u64,
    serial: u64,
    /// How many of the device's write commands, in submission order, the
    /// replay has attributed.
    seen: usize,
    /// The upload's write commands by model range.
    writes: [Option<CommandToken>; 2],
    successor: Option<CommandToken>,
    /// Whether peer 0 sent raw frames, which spends its client's session.
    raw_peer_0: bool,
}

impl Replay {
    /// Injects `header` from `peer` and polls the owner, leaving the disk
    /// untouched.
    fn deliver(scene: &mut Scene<'_, '_>, peer: usize, header: &Header, body: &[u8]) {
        scene.inject_edited(peer, header, body, |_| {});
        scene.polls(2);
    }

    /// The write commands the device accepted since the last call, held
    /// unless the driver drops the hold.
    fn accepted(&mut self, scene: &Scene<'_, '_>) -> Vec<CommandToken> {
        let new = write_tokens(&scene.control).split_off(self.seen);
        self.seen += new.len();
        if self.driver != Driver::HoldDropped {
            for token in &new {
                scene.control.hold(*token);
            }
        }
        new
    }

    /// Ends `token` as the model's terminal says and runs the turns that
    /// deliver it.
    fn end(&self, scene: &mut Scene<'_, '_>, token: CommandToken, ok: bool) {
        if self.driver != Driver::HoldDropped {
            scene.control.release(token);
            if !ok && self.driver != Driver::FaultDropped {
                scene
                    .control
                    .fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
            }
        }
        scene.turns(3);
    }

    /// Runs the production input of the model step that led to `model` and
    /// returns the PUT frames the owner sent peers 1 and 0.
    fn step(
        &mut self,
        scene: &mut Scene<'_, '_>,
        model: &Value,
        before: &Value,
    ) -> Result<[Vec<String>; 2], String> {
        let ev = &model["ev"];
        let (arg, ok) = (n(ev, "arg"), ev["ok"].as_bool().ok_or("event flag")?);
        match ev["act"].as_str().ok_or("event action")? {
            "begin" => {
                let header = scene.frame(1, Kind::PutBegin, self.at, NAME, |_| {});
                scene.inject(1, &header);
                scene.polls(2);
                let authority = scene.replies(1);
                let [reply] = authority[..] else {
                    return Err(format!("{authority:?}"));
                };
                if reply.kind != Kind::PutAuthority || reply.allocation == 0 {
                    return Err(format!("{reply:?}"));
                }
                self.serial = reply.allocation;
                return Ok([vec!["AUTHORITY".into()], sent(scene, 0)]);
            }
            "prepare" => {
                let header = scene.frame(
                    1,
                    Kind::PutPrepare,
                    self.at,
                    NAME,
                    prepare(self.serial, self.object.len() as u32, 60_000),
                );
                Self::deliver(scene, 1, &header, &[]);
            }
            act @ ("data" | "differ") => {
                let object = self.object.clone();
                let (header, mut body) =
                    fragment(scene, 1, self.at, self.serial, &object, arg as u32);
                if act == "differ" {
                    body[0] ^= 1;
                }
                Self::deliver(scene, 1, &header, &body);
                let new = self.accepted(scene);
                let submits = ranges(before) == ["none"; 2] && ranges(model) == ["submitted"; 2];
                match new[..] {
                    [] if !submits => {}
                    // The model's order is range 1, then range 0: the header's
                    // command, at the lower device offset, is accepted last.
                    [other, header]
                        if submits
                            && model["order"] == serde_json::json!([1, 0])
                            && device_start(scene, header) < device_start(scene, other) =>
                    {
                        self.writes = [Some(header), Some(other)];
                    }
                    _ => return Err(format!("{} write commands accepted", new.len())),
                }
            }
            "cancel" => {
                let header = scene.frame(1, Kind::PutCancel, self.at, NAME, cancel(self.serial));
                Self::deliver(scene, 1, &header, &[]);
            }
            "invalidate" if self.driver == Driver::InvalidateDropped => {}
            "invalidate" => {
                let ended = scene
                    .owner
                    .invalidate(&key(NAME), 4, &mut WorkBudget::new(1 << 12))
                    .map_err(|error| format!("{error:?}"))?;
                if ended.revoked != Some(self.serial) || ended.removed.is_some() {
                    return Err(format!("{ended:?}"));
                }
            }
            "terminal" => {
                let token = self.writes[arg as usize].ok_or("no write command of that range")?;
                self.end(scene, token, ok);
            }
            "sbegin" => {
                self.raw_peer_0 = true;
                let at = request(1, 1);
                let header = scene.frame(0, Kind::PutBegin, at, NAME, |_| {});
                scene.inject(0, &header);
                scene.polls(2);
                let authority = scene.replies(0);
                let [reply] = authority[..] else {
                    return Err(format!("{authority:?}"));
                };
                let serial = reply.allocation;
                if reply.kind != Kind::PutAuthority || serial == 0 || serial == self.serial {
                    return Err(format!("{reply:?}"));
                }
                let header = scene.frame(
                    0,
                    Kind::PutPrepare,
                    at,
                    NAME,
                    prepare(serial, self.next.len() as u32, 60_000),
                );
                Self::deliver(scene, 0, &header, &[]);
                let next = self.next.clone();
                let (header, body) = fragment(scene, 0, at, serial, &next, 0);
                Self::deliver(scene, 0, &header, &body);
                let [token] = self.accepted(scene)[..] else {
                    return Err("the successor's one write command".into());
                };
                self.successor = Some(token);
                let replies = sent(scene, 0);
                if replies != ["READY 1", "ACK 1"] {
                    return Err(format!("{replies:?}"));
                }
                return Ok([sent(scene, 1), vec!["ACK 1".into()]]);
            }
            "sterminal" => {
                let token = self.successor.ok_or("no successor write command")?;
                self.end(scene, token, ok);
            }
            action => return Err(format!("unknown action {action}")),
        }
        Ok([sent(scene, 1), sent(scene, 0)])
    }
}

/// The PUT frames the model's step sends peers 1 and 0.
fn replies(ev: &Value) -> [Vec<String>; 2] {
    let reply = match (ev["act"].as_str().unwrap(), ev["reply"].as_str().unwrap()) {
        (_, "") => return [vec![], vec![]],
        ("prepare", "READY") => "READY 2".into(),
        (_, "ACK") => format!("ACK {}", n(ev, "base")),
        (_, reply) => reply.to_owned(),
    };
    if matches!(ev["act"].as_str(), Some("sbegin" | "sterminal")) {
        [vec![], vec![reply]]
    } else {
        [vec![reply], vec![]]
    }
}

/// Replays one trace and returns the `(action, reply)` of every state,
/// `init` first.
///
/// # Errors
///
/// A trace that does not parse or whose model digest or length is wrong,
/// or a directed trace whose recipe holds another number of entries than
/// the trace holds steps; otherwise the first state whose recorded action
/// differs from its event's, whose action and arguments differ from its
/// recipe entry, whose production input fails (an unexpected reply, another
/// number or order of accepted write commands, an invalidation that revokes
/// another serial), or whose production frames, live upload count,
/// outstanding device commands, delivered range commands or visibility
/// differ from the model's state, each named with its index; or `read back` when the bytes the key holds at the trace's end are
/// another upload's than the one the model published.
///
/// # Panics
///
/// If a number, flag or reply the trace records is missing or has another
/// type.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String)>, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["put"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    plain(&mut trace);
    let states = trace["states"].as_array().ok_or("fixture states")?;
    if states.len() as u64 != n(&trace["#meta"]["put"], "steps") + 1 {
        return Err("fixture length".into());
    }
    let recipe = trace["#meta"]["put"]["recipe"]
        .as_array()
        .ok_or("fixture recipe")?;
    if !recipe.is_empty() && recipe.len() + 1 != states.len() {
        return Err("fixture recipe length".into());
    }
    let result = RefCell::new(None);
    scene(&PRINCIPALS, |mut scene| {
        let mut replay = Replay {
            driver,
            object: payload(2 * FRAGMENT_LEN as usize, 41),
            next: payload(FRAGMENT_LEN as usize, 43),
            at: request(1, 1),
            serial: 0,
            seen: write_tokens(&scene.control).len(),
            writes: [None; 2],
            successor: None,
            raw_peer_0: false,
        };
        let idle = scene.control.outstanding();
        let mut reached = vec![("init".to_owned(), String::new())];
        let run = (|| {
            for (i, state) in states.iter().enumerate().skip(1) {
                let model = &state[STATE];
                let ev = &model["ev"];
                let act = ev["act"].as_str().ok_or("event action")?;
                if state["mbt::actionTaken"] != act {
                    return Err(format!("action {i}: the event names another action"));
                }
                if !recipe.is_empty() && recipe[i - 1] != recorded(act, ev).as_str() {
                    return Err(format!("action {i}: recipe"));
                }
                let frames = replay
                    .step(&mut scene, model, &states[i - 1][STATE])
                    .map_err(|error| format!("{act} at {i}: {error}"))?;
                if frames != replies(ev) {
                    return Err(format!("{act} at {i}: frames {frames:?}"));
                }
                let stage = model["stage"].as_str().ok_or("stage")?;
                let writing = model["succ"] == "writing";
                let live = u32::from(matches!(stage, "authority" | "ready" | "draining"))
                    + u32::from(writing);
                if scene.live() != live {
                    return Err(format!("live at {i}: {}", scene.live()));
                }
                let outstanding = ranges(model)
                    .iter()
                    .filter(|state| **state == "submitted")
                    .count()
                    + usize::from(writing);
                if scene.control.outstanding() != idle + outstanding {
                    return Err(format!(
                        "outstanding at {i}: {}",
                        scene.control.outstanding() - idle
                    ));
                }
                let delivered = delivered(&scene);
                for (range, state) in ranges(model).iter().enumerate() {
                    let Some(token) = replay.writes[range] else {
                        continue;
                    };
                    let ended = delivered.contains(&token);
                    if (*state == "submitted") == ended {
                        let found = if ended { "delivered" } else { "outstanding" };
                        return Err(format!("range {range} at {i}: {found}"));
                    }
                }
                if scene.visible(NAME) != (n(model, "published") != 0) {
                    return Err(format!("visible at {i}: {}", scene.visible(NAME)));
                }
                reached.push((act.to_owned(), ev["reply"].as_str().unwrap().to_owned()));
            }
            let published = n(&states[states.len() - 1][STATE], "published");
            if published != 0 {
                if replay.raw_peer_0 {
                    scene.reopen(0);
                }
                let expected = if published == 1 {
                    &replay.object
                } else {
                    &replay.next
                };
                if scene.fetch(NAME) != *expected {
                    return Err("read back".into());
                }
            }
            Ok(())
        })();
        *result.borrow_mut() = Some(run.map(|()| reached));
    });
    result.into_inner().unwrap()
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap()
        .1
}

#[test]
fn committed_put_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        reached.extend(
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}")),
        );
    }
    // `init` and every choice of the model's `step`.
    assert!(
        std::str::from_utf8(MODEL).unwrap().contains(
            "    any {begin, prepare, data(i), differ(i), cancel, invalidate, terminal(w, ok), sbegin, sterminal(ok)}\n"
        ),
        "the model's step chooses among other actions than the replay drives"
    );
    let actions: BTreeSet<&str> = reached.iter().map(|(act, _)| act.as_str()).collect();
    assert_eq!(
        actions,
        BTreeSet::from([
            "begin",
            "cancel",
            "data",
            "differ",
            "init",
            "invalidate",
            "prepare",
            "sbegin",
            "sterminal",
            "terminal",
        ])
    );
    for outcome in [
        ("terminal", "RESULT"),
        ("terminal", "Contended"),
        ("terminal", "DeviceError"),
        ("terminal", ""),
        ("data", "Contended"),
        ("differ", "ConflictingData"),
        ("cancel", "Cancelled"),
        ("sterminal", "RESULT"),
        ("sterminal", "DeviceError"),
    ] {
        assert!(
            reached.contains(&(outcome.0.to_owned(), outcome.1.to_owned())),
            "{outcome:?}"
        );
    }
}

/// Each wrong driver drops one thing the model's step stands for, and the
/// replay refuses it through its frame comparison at the step where
/// production then answers otherwise than the model.
#[test]
fn negative_control_a_driver_that_drops_a_fault_an_invalidation_or_a_hold_fails_the_replay() {
    // failed_header: ..., terminal(1, true) at 5, terminal(0, false) at 6. A
    // header write that completes instead publishes.
    assert_eq!(
        replay(fixture("failed_header"), Driver::FaultDropped).unwrap_err(),
        r#"terminal at 6: frames [["RESULT"], []]"#
    );
    // revoked_at_completion: ..., invalidate at 6, terminal(0, true) at 7. An
    // upload that was never revoked publishes at its last terminal.
    assert_eq!(
        replay(fixture("revoked_at_completion"), Driver::InvalidateDropped).unwrap_err(),
        r#"terminal at 7: frames [["RESULT"], []]"#
    );
    // published: ..., data(1) at 4 submits both writes, the duplicate data(1)
    // is at 5, terminal(1, true) at 6. Unheld, both writes end at the first
    // terminal step's tick and the upload publishes one step early.
    assert_eq!(
        replay(fixture("published"), Driver::HoldDropped).unwrap_err(),
        r#"terminal at 6: frames [["RESULT"], []]"#
    );
}

/// A trace whose two ranges exchange their recorded states keeps the count
/// of outstanding commands and fails at the range whose command the device
/// already delivered.
#[test]
fn negative_control_exchanged_range_states_fail_at_the_delivered_range() {
    // out_of_order: ..., terminal(0, true) at 5 leaves range 0 written and
    // range 1 submitted.
    let mut trace: Value = serde_json::from_str(fixture("out_of_order")).unwrap();
    let ws = trace["states"][5][STATE]["ws"]["#map"].clone();
    assert_eq!(
        (&ws[0][1], &ws[1][1]),
        (&"written".into(), &"submitted".into())
    );
    trace["states"][5][STATE]["ws"]["#map"][0][1] = ws[1][1].clone();
    trace["states"][5][STATE]["ws"]["#map"][1][1] = ws[0][1].clone();
    assert_eq!(
        replay(&trace.to_string(), Driver::Faithful).unwrap_err(),
        "range 0 at 5: delivered"
    );
}

/// A trace altered in one recorded field fails through the comparison that
/// reads the field: at the altered state for a reply, a base, a stage, a
/// range, a visibility or the action label, and at the read back for the
/// last state's published upload; a stale model digest, a missing state or
/// a recipe of another length fails the trace before any state replays, and
/// a recipe entry with another argument fails at its state.
#[test]
fn negative_control_an_altered_trace_fails_at_the_altered_state() {
    let json = fixture("successor");
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(json).unwrap();
        edit(&mut trace);
        replay(&trace.to_string(), Driver::Faithful).unwrap_err()
    };
    // successor: begin, prepare, data(0), data(1), invalidate at 5, sbegin at
    // 6, sterminal(true) at 7, terminal(1, true) at 8, terminal(0, true) at 9.
    assert_eq!(
        edited(&|trace| trace["states"][9][STATE]["ev"]["reply"] = "RESULT".into()),
        r#"terminal at 9: frames [["Contended"], []]"#
    );
    assert_eq!(
        edited(
            &|trace| trace["states"][3][STATE]["ev"]["base"] = serde_json::json!({"#bigint": "2"})
        ),
        r#"data at 3: frames [["ACK 1"], []]"#
    );
    assert_eq!(
        edited(&|trace| trace["states"][8][STATE]["stage"] = "ended".into()),
        "live at 8: 1"
    );
    assert_eq!(
        edited(
            &|trace| trace["states"][7][STATE]["published"] = serde_json::json!({"#bigint": "0"})
        ),
        "visible at 7: true"
    );
    assert_eq!(
        edited(&|trace| trace["states"][8][STATE]["ws"]["#map"][1][1] = "submitted".into()),
        "outstanding at 8: 1"
    );
    assert_eq!(
        edited(
            &|trace| trace["states"][9][STATE]["published"] = serde_json::json!({"#bigint": "1"})
        ),
        "read back"
    );
    assert_eq!(
        edited(&|trace| trace["states"][5]["mbt::actionTaken"] = "cancel".into()),
        "action 5: the event names another action"
    );
    assert_eq!(
        edited(&|trace| trace["#meta"]["put"]["model_sha256"] = "0".into()),
        "fixture model digest"
    );
    assert_eq!(
        edited(&|trace| {
            trace["states"].as_array_mut().unwrap().pop();
        }),
        "fixture length"
    );
    // The last state and the recorded step count are cut together; the
    // recipe still holds nine entries.
    assert_eq!(
        edited(&|trace| {
            trace["states"].as_array_mut().unwrap().pop();
            trace["#meta"]["put"]["steps"] = 8.into();
        }),
        "fixture recipe length"
    );
    // The recipe's third entry names fragment 1 where the state records
    // fragment 0, and its ninth a failed terminal where the state records a
    // successful one.
    assert_eq!(
        edited(&|trace| trace["#meta"]["put"]["recipe"][2] = "data(1)".into()),
        "action 3: recipe"
    );
    assert_eq!(
        edited(&|trace| trace["#meta"]["put"]["recipe"][8] = "terminal(0, false)".into()),
        "action 9: recipe"
    );
}
