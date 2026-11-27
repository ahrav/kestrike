//! Replay of committed traces of the watermark-log model, `quint/marklog.qnt`, against the store client over the
//! file log.
//!
//! The traces are written by `bash scripts/tool.sh marklog_fixtures --quint QUINT --output DIR`: directed
//! recipes and seeded runs of the model's `step`, each naming the model's sha256 and its `steps`, and each state after the first names the action taken and its
//! arguments. A trace with a mismatched model sha256 or a state count unequal to `steps + 1` fails before any
//! state replays. The simulated store holds a shard with three coverage pages, the model's pages 1 to 3 at
//! version 1.
//! The host records the empty watermark in a log file of its own directory, and each client process opens a
//! [`FileLog`] on that file.
//!
//! - `read` is the client's `read_all` of the batch's pages in page order. The replay tells from the file how the
//!   log recorded the raised marks: a new inode is a whole replacement, changed bytes under the same inode an
//!   in-place raise, and unchanged bytes no write.
//! - `crash` makes the same call and then builds the file a crash in its log write leaves: for an in-place raise
//!   the previous file with the rewritten slots of the landed pages, and for a whole replacement the previous
//!   file or the new one. It drops the client, writes that file and opens the next client on it.
//! - `write` is another host's client replacing a page, which advances its version. `restart` drops the client
//!   and opens the next one on the file.
//!
//! After every action the replay compares the file's slots, each a free slot or a page with its version, with the
//! model's, requires every slot past the model's to be free, and requires the client's watermark to equal the one
//! the file loads. The committed traces take `init` and every choice of `step` with each way the log records.
//! A `write` preserves the file's bytes, so each replay state compares the store's page versions with the model's `store`.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use core::num::NonZeroU16;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::failover::records::{CoveragePage, ShardRecord};
use crate::storage::store::sim::Shared;
use crate::storage::store::{Client, FileLog, Key, Watermark, WatermarkLog};
use crate::storage::store_tests::{client, record, shard};

const MODEL: &[u8] = include_bytes!("../../../../quint/marklog.qnt");

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("marklog_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const TRACES: [(&str, &str); 12] = fixtures![
    "partly_landed",
    "whole_replacement",
    "out_of_key_order",
    "raise_after_whole",
    "crashes",
    "whole_then_in_place",
    "step_6b01",
    "step_6b02",
    "step_6b03",
    "step_6b05",
    "step_6b08",
    "step_6b0d",
];

/// `init` and every choice of the model's `step` with each way the log records a batch's marks.
const REACHED: [&str; 8] = [
    "crash inPlace",
    "crash whole",
    "init ",
    "read inPlace",
    "read none",
    "read whole",
    "restart ",
    "write ",
];

/// The bytes of the file's header and of each slot.
const SLOT: usize = 64;

/// A defect planted in the driver.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Plant {
    None,
    /// A restart finds the file as it was before the last batch that returned.
    LostRaise,
}

/// Replaces every `#bigint` of an ITF value with its number.
fn plain(v: &mut Value) {
    match v {
        Value::Object(map) if map.len() == 1 && map.contains_key("#bigint") => {
            let number: u64 = map["#bigint"].as_str().unwrap().parse().unwrap();
            *v = number.into();
        }
        Value::Object(map) => map.values_mut().for_each(plain),
        Value::Array(items) => items.iter_mut().for_each(plain),
        _ => {}
    }
}

fn var<'a>(state: &'a Value, name: &str) -> &'a Value {
    &state[format!("marklogCase::marklog::{name}")]
}

fn parse(name: &str, text: &str) -> Value {
    let mut trace: Value = serde_json::from_str(text).unwrap();
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        trace["#meta"]["marklog"]["model_sha256"].as_str(),
        Some(digest.as_str()),
        "{name}: the trace was generated from another quint/marklog.qnt"
    );
    plain(&mut trace);
    let states = trace["states"].as_array().map_or(0, Vec::len);
    assert_eq!(
        Some(states as u64),
        trace["#meta"]["marklog"]["steps"]
            .as_u64()
            .map(|steps| steps + 1),
        "{name}: the trace's states and the steps it names"
    );
    trace
}

/// The file's slots as the model states them: `(0, 0)` for a free slot, and a page's model key with its version.
fn slots(bytes: &[u8]) -> Vec<(u64, u64)> {
    bytes[SLOT..]
        .chunks(SLOT)
        .map(|slot| match slot[0] {
            0xFF => (0, 0),
            1 => (
                u64::from(u16::from_be_bytes([slot[5], slot[6]])) + 1,
                u64::from_be_bytes(slot[7..15].try_into().unwrap()),
            ),
            kind => panic!("a slot of kind {kind}"),
        })
        .collect()
}

/// The model's slots of a state.
fn modelled(state: &Value) -> Vec<(u64, u64)> {
    let file = var(state, "file").as_array().unwrap().iter();
    file.map(|slot| (slot["key"].as_u64().unwrap(), slot["ver"].as_u64().unwrap()))
        .collect()
}

/// The pages of a call's argument as keys, in page order.
fn pages(argument: &Value) -> Vec<Key> {
    let listed = argument.as_array().expect("a list of pages").iter();
    listed
        .map(|page| Key::Page(shard(), page.as_u64().unwrap() as u16 - 1))
        .collect()
}

/// The directory of the calling thread's replay. Each test thread replays one trace at a time, so the process id
/// and the thread id isolate each running replay's directory.
fn directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "marklog-replay-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// `Scratch::new` removes any directory left at the replay's [`directory`] and creates it. Dropping the value
/// attempts to remove the directory, including during panic unwinding, and ignores removal errors.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let directory = directory();
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open(store: &Shared, path: &Path) -> Client<Shared, FileLog> {
    Client::open(store.clone(), FileLog::new(path.to_owned()).unwrap()).unwrap()
}

/// Replays `trace` through a driver that carries `plant` and returns each event taken with the way the log
/// recorded it.
fn replay(name: &str, trace: &Value, plant: Plant) -> Vec<String> {
    let states = trace["states"].as_array().expect("states");
    let scratch = Scratch::new();
    let path = scratch.0.join("mark");
    FileLog::new(path.clone())
        .unwrap()
        .record(&Watermark::default())
        .unwrap();
    let store = Shared::new();
    client(&store)
        .create_shard(ShardRecord {
            pages: NonZeroU16::new(3).unwrap(),
            ..record()
        })
        .unwrap();
    let mut owner = open(&store, &path);
    let mut returned = std::fs::read(&path).unwrap();
    let mut events = Vec::new();
    for (at, state) in states.iter().enumerate() {
        let (act, how) = (
            var(state, "ev")["act"].as_str().unwrap(),
            var(state, "ev")["how"].as_str().unwrap(),
        );
        events.push(format!("{act} {how}"));
        let call = &state["call"];
        match act {
            "init" => {}
            "read" | "crash" => {
                let (previous, inode) = (
                    std::fs::read(&path).unwrap(),
                    std::fs::metadata(&path).unwrap().ino(),
                );
                for result in owner.read_all::<CoveragePage>(&pages(&call[1])) {
                    result.unwrap();
                }
                let next = std::fs::read(&path).unwrap();
                let recorded = if std::fs::metadata(&path).unwrap().ino() != inode {
                    "whole"
                } else if next != previous {
                    "inPlace"
                } else {
                    "none"
                };
                assert_eq!(recorded, how, "{name}: record at {at}");
                if act == "read" {
                    returned = previous;
                } else {
                    let landed = pages(&call[2]);
                    let torn = if how == "whole" {
                        if landed.is_empty() { previous } else { next }
                    } else {
                        let mut torn = previous.clone();
                        for (index, key) in slots(&next).iter().enumerate() {
                            let page = Key::Page(shard(), key.0.saturating_sub(1) as u16);
                            if key.0 > 0 && landed.contains(&page) {
                                let at = SLOT * (1 + index);
                                torn[at..at + SLOT].copy_from_slice(&next[at..at + SLOT]);
                            }
                        }
                        torn
                    };
                    drop(owner);
                    std::fs::write(&path, &torn).unwrap();
                    owner = open(&store, &path);
                }
            }
            "write" => {
                let key = Key::Page(shard(), call[1].as_u64().unwrap() as u16 - 1);
                let mut other = client(&store);
                let read = other.read::<CoveragePage>(key).unwrap();
                other.replace(&read, read.value().clone()).unwrap();
            }
            "restart" => {
                drop(owner);
                if plant == Plant::LostRaise {
                    std::fs::write(&path, &returned).unwrap();
                }
                owner = open(&store, &path);
            }
            other => panic!("{name}: an action outside the model: {other} at {at}"),
        }
        let bytes = std::fs::read(&path).unwrap();
        let held = slots(&bytes);
        let expected = modelled(state);
        assert_eq!(held[..expected.len()], expected[..], "{name}: file at {at}");
        assert!(
            held[expected.len()..].iter().all(|slot| *slot == (0, 0)),
            "{name}: a mark past the model's slots at {at}"
        );
        assert_eq!(
            owner.watermark(),
            &FileLog::new(path.clone()).unwrap().load().unwrap(),
            "{name}: the client's watermark and the file's at {at}"
        );
        let mut reader = client(&store);
        let stored: Vec<(u64, u64)> = (0..3)
            .map(|page| {
                let read = reader
                    .read::<CoveragePage>(Key::Page(shard(), page))
                    .unwrap();
                (u64::from(page) + 1, read.version().get())
            })
            .collect();
        let expected: Vec<(u64, u64)> = var(state, "store")["#map"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row[0].as_u64().unwrap(), row[1].as_u64().unwrap()))
            .collect();
        assert_eq!(stored, expected, "{name}: store at {at}");
    }
    events
}

/// Every committed trace replays, and together the traces take `init` and every choice of the model's `step` with
/// each way the log records a batch's marks.
#[test]
fn committed_marklog_traces_replay() {
    let mut reached = BTreeSet::new();
    for (name, text) in TRACES {
        reached.extend(replay(name, &parse(name, text), Plant::None));
    }
    assert_eq!(
        reached.iter().map(String::as_str).collect::<Vec<_>>(),
        REACHED
    );
}

/// The message of the panic `run` ends in.
fn failure(run: impl FnOnce() + std::panic::UnwindSafe) -> String {
    let panic = std::panic::catch_unwind(run).expect_err("the replay accepted the run");
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .expect("a panic message")
}

fn trace(name: &str) -> (&'static str, Value) {
    let (name, text) = TRACES.iter().find(|(trace, _)| *trace == name).unwrap();
    (name, parse(name, text))
}

/// A log that loses the raise of a batch that returned, the file a restart finds being the one before that batch,
/// fails the replay at the restart's file.
#[test]
fn a_marklog_that_loses_a_returned_raise_fails_at_the_restart() {
    let (name, trace) = trace("out_of_key_order");
    let message = failure(move || drop(replay(name, &trace, Plant::LostRaise)));
    assert!(message.contains("out_of_key_order: file at 3"), "{message}");
    assert!(
        !directory().exists(),
        "the failed replay kept its directory"
    );
}

/// A trace with one recorded value changed fails at the changed state.
#[test]
fn a_perturbed_marklog_trace_fails_at_the_changed_state() {
    let (name, trace) = trace("partly_landed");
    let perturbed = |at: usize, variable: &str, change: fn(&mut Value)| {
        let mut trace = trace.clone();
        change(&mut trace["states"][at][format!("marklogCase::marklog::{variable}")]);
        failure(move || drop(replay(name, &trace, Plant::None)))
    };
    let cases: [Perturbation; 4] = [
        (1, "ev", |ev| ev["how"] = "whole".into(), "record at 1"),
        (5, "file", |file| file[0]["ver"] = 2.into(), "file at 5"),
        (2, "file", |file| file[1]["key"] = 3.into(), "file at 2"),
        // State 4 records `write(2)`, which leaves page 2 at version 2.
        (
            4,
            "store",
            |store| store["#map"][1][1] = 1.into(),
            "store at 4",
        ),
    ];
    for (at, variable, change, expected) in cases {
        let message = perturbed(at, variable, change);
        assert!(
            message.contains(&format!("{name}: {expected}")),
            "{message}"
        );
        assert!(
            !directory().exists(),
            "the failed replay kept its directory"
        );
    }
}

/// A trace that lost its last state, or every state, is refused before any state replays.
#[test]
fn a_marklog_trace_short_of_its_steps_is_refused() {
    let (name, text) = TRACES[0];
    let whole: Value = serde_json::from_str(text).unwrap();
    let states = whole["states"].as_array().unwrap().len();
    for kept in [states - 1, 0] {
        let mut trace = whole.clone();
        trace["states"].as_array_mut().unwrap().truncate(kept);
        let message = failure(move || drop(parse(name, &trace.to_string())));
        assert!(
            message.contains("partly_landed: the trace's states and the steps it names"),
            "{message}"
        );
    }
}

/// A state, one of its variables, a change to the recorded value and the comparison that fails on it.
type Perturbation = (usize, &'static str, fn(&mut Value), &'static str);
