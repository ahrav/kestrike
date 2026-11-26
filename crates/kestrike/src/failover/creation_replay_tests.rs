//! Replays committed traces of the reconciler-creation model
//! `quint/creation.qnt` against [`Reconciler::create_shard`],
//! [`Reconciler::provision`] and [`Reconciler::record_attach`] over the
//! simulated store.
//!
//! # Threads
//!
//! The replay thread owns the simulated store. A `begin` step starts the
//! operation of one of the model's two processes on its own thread
//! ([`Op::start`]), over a [`Proxy`](super::replay_driver::Proxy) store that sends each request to the replay
//! thread and blocks for the reply. The replay thread blocks, up to [`WAIT`](super::replay_driver::WAIT), for the
//! operation's next message, and the operation blocks for each reply, so one
//! thread runs at a time and each production request falls on one model step. `begin` requires the operation's
//! first message to be a request and leaves it pending. A `read` step requires the pending request to be a
//! read of the record the step names, and a `write`, `commit`, `lost` or
//! `hold` step requires a write of it; the step performs it, replies, and
//! receives the next message: a request while the step records no result, or
//! the operation's result, which must equal the step's.
//!
//! # Store arms
//!
//! A shard creation's requests reach the store as the shard-provisioning
//! principal ([`AsProvisioner`]) and a provision's or an attach's as the
//! reconciler's ([`AsReconciler`]). A shard creation requests the shard
//! record and the pages, which the provisioning principal is granted; a
//! provision and an attach request the volume record, which the reconciler's
//! is granted. Each request runs under the arm its step names.
//!
//! | Model action | Event `act` | Store request |
//! | --- | --- | --- |
//! | `request` | `read` | a read under [`Arm::Pass`] |
//! | `request` | `write` | a write under [`Arm::Pass`] |
//! | `unknown` | `commit` | a write under `Arm::Timeout { commit: true }` |
//! | `unknown` | `lost` | a write under `Arm::Timeout { commit: false }` |
//! | `unknown` | `hold` | a write under [`Arm::Hold`] |
//! | `release` | `release` | `Shared::release`, whose outcome must equal the step's result |
//! | `fence` | `fence` | a read of the page and an exact-version write of a nonzero fence to it, on the store itself |
//!
//! # Comparison
//!
//! Before each step runs, the action the trace records for it must be the
//! one its event names. After every step, `init` included, the stored shard
//! record, both pages and the volume record, read as [`Seen`], must equal the
//! model's.
//!
//! Model creation 1 is the shard record that names `vol-0a` active and
//! creation 2 the one that names `vol-0e`; the two differ in that field
//! alone, which makes each a conflicting creation of the other. Model hosts 1
//! and 2 are the owner and the spare host, and both attaches record [`ERA`],
//! so two attach events are equal exactly when their hosts are. The volume is
//! `vol-0c`. A model version is the record's commit count.
//!
//! The model ends a shard creation with `created` after its shard-record
//! write and `found` after a read that returns its own creation, and a
//! provision with `provisioned` and `found` likewise;
//! [`Reconciler::create_shard`] and [`Reconciler::provision`] return `Ok` for
//! both, which the replay renders `ok`. A success takes its model result only
//! when the value inside `Ok` is the one the operation's arguments name: the
//! shard record of its creation, the provisioning record of `vol-0c` at the
//! simulated layout, or the attach witness of `vol-0c` and its host. The
//! witness's fields are private to `reconcile`, so the replay reads them in
//! its `Debug` text.

use std::collections::BTreeSet;

use serde_json::Value;

use super::replay_driver::{Message, Op, Reply, states};
use super::{commits, empty, fence_page, vol};
use crate::failover::detect_route_replay_tests::ReplayScratch;
use crate::failover::reconcile::{ReconcileError, Reconciler};
use crate::failover::records::{
    CoveragePage, CreationSource, ERA, EventKind, Layout, Lineage, Record, ShardRecord, VolumeId,
    VolumeRecord, VolumeState,
};
use crate::failover::sim::{host, layout};
use crate::storage::store::sim::{Arm, AsProvisioner, AsReconciler, MemLog, Shared};
use crate::storage::store::{
    Client, Item, Key, Outcome, Refusal, Store, StoreError, Version, Write,
};
use crate::storage::store_tests::{OWNER, SPARE, record, shard as sid};

const MODEL: &[u8] = include_bytes!("../../../../quint/creation.qnt");
const STATE: &str = "creationCase::creation::st";
/// The traces `quint/creation_fixtures.py` writes: ten directed recipes, then sixteen seeded runs of twenty-four
/// steps of the model's `step`, each named `step_` and its seed in hexadecimal.
const FIXTURES: [(&str, &str); 26] = [
    (
        "create_then_replay",
        include_str!("creation_replay_fixtures/create_then_replay.itf.json"),
    ),
    (
        "racing_creations",
        include_str!("creation_replay_fixtures/racing_creations.itf.json"),
    ),
    (
        "attach_once",
        include_str!("creation_replay_fixtures/attach_once.itf.json"),
    ),
    (
        "racing_creations_of_one_record",
        include_str!("creation_replay_fixtures/racing_creations_of_one_record.itf.json"),
    ),
    (
        "fenced_page_under_a_retry",
        include_str!("creation_replay_fixtures/fenced_page_under_a_retry.itf.json"),
    ),
    (
        "unknown_outcomes_and_retries",
        include_str!("creation_replay_fixtures/unknown_outcomes_and_retries.itf.json"),
    ),
    (
        "held_create_after_the_winner",
        include_str!("creation_replay_fixtures/held_create_after_the_winner.itf.json"),
    ),
    (
        "volume_unknown_outcomes",
        include_str!("creation_replay_fixtures/volume_unknown_outcomes.itf.json"),
    ),
    (
        "racing_attaches",
        include_str!("creation_replay_fixtures/racing_attaches.itf.json"),
    ),
    (
        "held_attach_lands",
        include_str!("creation_replay_fixtures/held_attach_lands.itf.json"),
    ),
    (
        "step_2185",
        include_str!("creation_replay_fixtures/step_2185.itf.json"),
    ),
    (
        "step_2186",
        include_str!("creation_replay_fixtures/step_2186.itf.json"),
    ),
    (
        "step_2187",
        include_str!("creation_replay_fixtures/step_2187.itf.json"),
    ),
    (
        "step_2188",
        include_str!("creation_replay_fixtures/step_2188.itf.json"),
    ),
    (
        "step_2189",
        include_str!("creation_replay_fixtures/step_2189.itf.json"),
    ),
    (
        "step_218a",
        include_str!("creation_replay_fixtures/step_218a.itf.json"),
    ),
    (
        "step_218b",
        include_str!("creation_replay_fixtures/step_218b.itf.json"),
    ),
    (
        "step_218c",
        include_str!("creation_replay_fixtures/step_218c.itf.json"),
    ),
    (
        "step_218d",
        include_str!("creation_replay_fixtures/step_218d.itf.json"),
    ),
    (
        "step_218e",
        include_str!("creation_replay_fixtures/step_218e.itf.json"),
    ),
    (
        "step_218f",
        include_str!("creation_replay_fixtures/step_218f.itf.json"),
    ),
    (
        "step_2190",
        include_str!("creation_replay_fixtures/step_2190.itf.json"),
    ),
    (
        "step_2191",
        include_str!("creation_replay_fixtures/step_2191.itf.json"),
    ),
    (
        "step_2192",
        include_str!("creation_replay_fixtures/step_2192.itf.json"),
    ),
    (
        "step_2193",
        include_str!("creation_replay_fixtures/step_2193.itf.json"),
    ),
    (
        "step_2194",
        include_str!("creation_replay_fixtures/step_2194.itf.json"),
    ),
];
/// The shard record of model creation 1, or of creation 2 for any other `id`.
fn creation(id: u64) -> ShardRecord {
    match id {
        1 => empty(),
        _ => ShardRecord {
            active: vol("vol-0e"),
            ..empty()
        },
    }
}

/// The record [`Reconciler::provision`] creates for `volume` at `layout`.
fn provisioning(volume: VolumeId, layout: Layout) -> VolumeRecord {
    VolumeRecord {
        volume,
        state: VolumeState::Provisioning,
        source: CreationSource::Provisioned,
        lineage: Lineage::None,
        modification: None,
        layout,
        next: 0,
        forced: false,
        fence: 0,
        pairs: Vec::new(),
        events: Vec::new(),
    }
}

/// The result string of an operation, in the model's words: `ok` names a success whose value `named` accepts;
/// `ReconcileError::Conflict` is `conflict`; a condition refusal is `condition`; an unknown write outcome is
/// `unknown`; and a read of an absent record is `absent`. A success whose value `named` refuses, and any other
/// error, renders as its `Debug` text, which equals no model result.
fn outcome<T: std::fmt::Debug>(
    result: Result<T, ReconcileError>,
    ok: &'static str,
    named: impl FnOnce(&T) -> bool,
) -> String {
    match result {
        Ok(value) if named(&value) => ok.into(),
        Ok(value) => format!("{value:?}"),
        Err(ReconcileError::Conflict) => "conflict".into(),
        Err(ReconcileError::Store(StoreError::Refused(Refusal::Condition))) => "condition".into(),
        Err(ReconcileError::Store(StoreError::Unknown)) => "unknown".into(),
        Err(ReconcileError::Store(StoreError::Absent)) => "absent".into(),
        Err(error) => format!("{error:?}"),
    }
}

/// How the replay maps a model step to store requests. `Faithful` is the mapping of the module doc; each other
/// variant changes one row of it and serves as a negative control.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    Faithful,
    /// A write the store refuses on its condition is answered `Committed`, with the store unchanged: a create at
    /// `Version::FIRST`, an exact-version write at the version after the expected one.
    AcknowledgesRefused,
    /// A `fence` step issues no store request.
    FenceDropped,
    /// A `hold` step writes under `Arm::Timeout { commit: false }`, so the store parks nothing and a later
    /// `release` applies nothing.
    HeldDropped,
    /// A `read` step of the shard record is answered with the stored record at `E = 1`, with the store unchanged,
    /// so a shard creation that finds its own creation returns a record other than the one it was given.
    ShardReadBumped,
    /// A `provision` asks for 128 units, a layout the floor admits, where the model's provision asks for the
    /// simulated layout.
    OtherLayout,
    /// An `attach` records the other host than the one its `begin` step names.
    OtherHost,
    /// An `attach` returns `recorded` before it issues a request.
    EndsAtBegin,
}

/// The stored records the model and production are compared in, in model units: the shard record's
/// `(present, creation, version)`, where the creation is 1 or 2 by the active volume the record names; `(present,
/// version, fenced)` of page 0 and of page 1, where a page is fenced when its fence is nonzero; and the volume
/// record's `(state, attach host, version)`, where state 0 is absent, 1 provisioning and 2 fresh, and the host is 0
/// for a record with no event, 1 for one attach event of the owner and 2 for one of the spare host. A version is
/// the record's commit count. An absent shard record or page is `false` and zero in every field; an absent volume
/// record is zero in every field.
type Seen = ((bool, u64, u64), [(bool, u64, bool); 2], (u64, u64, u64));

/// The [`Seen`] of a model state.
fn modeled(model: &Value) -> Result<Seen, String> {
    let number = |v: &Value, key: &str| v[key].as_u64().ok_or(format!("model {key}"));
    let flag = |v: &Value, key: &str| v[key].as_bool().ok_or(format!("model {key}"));
    let shard = &model["shard"];
    let mut pages = [(false, 0, false); 2];
    for row in model["pages"]["#map"].as_array().ok_or("model pages")? {
        let at = row[0].as_u64().ok_or("model page")? as usize;
        *pages.get_mut(at).ok_or("model page range")? = (
            flag(&row[1], "exists")?,
            number(&row[1], "ver")?,
            flag(&row[1], "fenced")?,
        );
    }
    let vol = &model["vol"];
    Ok((
        (
            flag(shard, "exists")?,
            number(shard, "id")?,
            number(shard, "ver")?,
        ),
        pages,
        (
            number(vol, "state")?,
            number(vol, "host")?,
            number(vol, "ver")?,
        ),
    ))
}

/// Replays one trace and returns the event's `(act, op, key, res)` of every state, `init` first.
///
/// # Errors
///
/// Before any state replays, the errors of [`states`] for a trace that fails to parse, records a stale model
/// digest, holds a malformed big integer, holds no state array or holds another state count than its steps.
///
/// Then the error of the first state that fails, in one of three forms:
///
/// - `event <field>` for an event field that is missing or of another type; `event proc range` when a `begin` or
///   request step names a process other than 0 and 1; `event key` when a `read`, `write`, `commit`, `lost` or
///   `hold` step names a record other than `shard`, `page0`, `page1` and `volume`, or a `fence` step a page other
///   than `page0` and `page1`; `model <field>`, `model pages`,
///   `model page` or `model page range` for such a field of the model's records; and `version` when
///   [`Driver::AcknowledgesRefused`] acknowledges a write that expects the last version.
/// - `action <index>: the event names another action` when the trace's recorded action differs, and
///   `action <index>: unknown action <act>` for an action the replay drives no request for, `init` after state 0
///   included.
/// - `<act> at <index>: <what>` for a divergence between production and the model, where `<what>` is one of:
///   - `the process already runs an operation` or `the process runs no operation`;
///   - `no operation <op>(<arg>)` when a `begin` step names an operation other than `createShard` and `attach` of
///     creation or host 1 or 2 and `provision` of argument 0;
///   - `the operation issued no request` when no message arrives within [`WAIT`](super::replay_driver::WAIT) or
///     the operation's thread ends without one;
///   - `the operation reads <key>`, `the operation writes <key>` or `the operation ended <result>` when the
///     pending message is another request than the step names, or a result;
///   - `the operation is gone` when the operation's thread dropped its channel;
///   - `the operation ended <result>` when the operation ends at a step that records no result, its `begin` step
///     included;
///   - `result <result>, modeled <result>` when the results differ, where a success that returns another value
///     than its arguments name gives that value's `Debug` text as its result;
///   - `the operation continues, modeled <result>` when the operation issues a request at a step that records a
///     result;
///   - `the operation panicked` when the operation's thread panics after it sends its result; a panic before the
///     result reports `the operation issued no request`;
///   - `released <outcome>, modeled <result>` when a `release` step applies another outcome than the step
///     records, and `released <outcomes>` for any outcome list other than empty, one commit or one condition
///     refusal;
///   - `shard record`, `page` or `volume record` when a stored value fails to decode;
///   - `another creation`, `events <events>` or `volume state <state>` when a stored record holds a value with no
///     model counterpart: an active volume of neither creation, an event list other than empty or one attach of
///     the owner or the spare host, or a state other than provisioning and fresh;
///   - `stored <seen>, modeled <seen>` when the [`Seen`] tuples differ.
///
/// # Panics
///
/// If a `fence` step's client fails to open, its read of the page fails, the page is absent, or its write is
/// refused or unknown.
fn replay(json: &str, driver: Driver) -> Result<Vec<(String, String, String, String)>, String> {
    let (states, _) = states(json, MODEL, "creation")?;

    let store = Shared::new();
    let volume = vol("vol-0c");
    let key_of = |key: &str| match key {
        "shard" => Ok(Key::Shard(sid())),
        "page0" => Ok(Key::Page(sid(), 0)),
        "page1" => Ok(Key::Page(sid(), 1)),
        "volume" => Ok(Key::Volume(volume)),
        _ => Err("event key"),
    };
    let hosts = [host(OWNER), host(SPARE)];

    let mut runs: [Option<(Op, bool)>; 2] = [None, None];
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let model = &state[STATE];
        let ev = &model["ev"];
        let text = |key: &str| ev[key].as_str().ok_or(format!("event {key}"));
        let (act, op, key, res) = (text("act")?, text("op")?, text("key")?, text("res")?);
        let proc = ev["proc"].as_u64().ok_or("event proc")? as usize;
        let fail = |what: String| format!("{act} at {i}: {what}");
        let taken = match act {
            "read" | "write" => "request",
            "commit" | "lost" | "hold" => "unknown",
            act => act,
        };
        if state["mbt::actionTaken"] != taken {
            return Err(format!("action {i}: the event names another action"));
        }
        match act {
            "init" if i == 0 => {}
            "begin" => {
                if runs.get(proc).ok_or("event proc range")?.is_some() {
                    return Err(fail("the process already runs an operation".into()));
                }
                let arg = ev["arg"].as_u64().ok_or("event arg")?;
                if !matches!(
                    (op, arg),
                    ("createShard" | "attach", 1 | 2) | ("provision", 0)
                ) {
                    return Err(fail(format!("no operation {op}({arg})")));
                }
                let op = op.to_owned();
                let provisions = op == "createShard";
                let attaching = hosts[usize::from(arg == 2)];
                let attached = match driver {
                    Driver::OtherHost => hosts[usize::from(arg != 2)],
                    _ => attaching,
                };
                let asked = match driver {
                    Driver::OtherLayout => Layout {
                        units: 128,
                        ..layout()
                    },
                    _ => layout(),
                };
                let run = Op::start(move |proxy| {
                    let mut reconciler =
                        Reconciler::new(Client::open(proxy, MemLog::default()).unwrap());
                    match op.as_str() {
                        "attach" if driver == Driver::EndsAtBegin => "recorded".into(),
                        "createShard" => {
                            outcome(reconciler.create_shard(creation(arg)), "ok", |read| {
                                *read.value() == creation(arg)
                            })
                        }
                        "provision" => outcome(reconciler.provision(volume, asked), "ok", |read| {
                            *read.value() == provisioning(volume, layout())
                        }),
                        "attach" => outcome(
                            reconciler.record_attach(volume, attached, ERA),
                            "recorded",
                            |witness| {
                                format!("{witness:?}")
                                    == format!(
                                        "AttachRecorded {{ volume: {volume:?}, host: {attaching:?} }}"
                                    )
                            },
                        ),
                        _ => unreachable!("the begin step admits only the three operations"),
                    }
                })
                .map_err(fail)?;
                if let Message::Done(result) = run.pending() {
                    return Err(fail(format!("the operation ended {result}")));
                }
                runs[proc] = Some((run, provisions));
            }
            "read" | "write" | "commit" | "lost" | "hold" => {
                let (run, provisions) = runs
                    .get_mut(proc)
                    .ok_or("event proc range")?
                    .as_mut()
                    .ok_or_else(|| fail("the process runs no operation".into()))?;
                let key = key_of(key)?;
                let mut provisioner = AsProvisioner(store.clone());
                let mut reconciler = AsReconciler(store.clone());
                let inner: &mut dyn Store = if *provisions {
                    &mut provisioner
                } else {
                    &mut reconciler
                };
                let reply = if act == "read" {
                    run.read_of(&key).map_err(fail)?;
                    Reply::Read(match inner.read(&key) {
                        Ok(Some(item))
                            if driver == Driver::ShardReadBumped
                                && matches!(key, Key::Shard(_)) =>
                        {
                            let held = ShardRecord::decode(&item.value)
                                .map_err(|_| fail("shard record".into()))?;
                            let value = ShardRecord {
                                attempts: 1,
                                ..held
                            }
                            .encode();
                            Ok(Some(Item { value, ..item }))
                        }
                        read => read,
                    })
                } else {
                    let write = run.write_of(&key).map_err(fail)?;
                    match act {
                        "commit" => store.schedule(Arm::Timeout { commit: true }),
                        "lost" => store.schedule(Arm::Timeout { commit: false }),
                        "hold" if driver == Driver::HeldDropped => {
                            store.schedule(Arm::Timeout { commit: false });
                        }
                        "hold" => store.schedule(Arm::Hold),
                        _ => {}
                    }
                    let outcome = inner.write(&key, write);
                    Reply::Write(match (outcome, write) {
                        (Outcome::NotCommitted(Refusal::Condition), write)
                            if driver == Driver::AcknowledgesRefused =>
                        {
                            Outcome::Committed(match write {
                                Write::Create(_) => Version::FIRST,
                                Write::Exact { expect, .. } => expect.next().ok_or("version")?,
                            })
                        }
                        (outcome, _) => outcome,
                    })
                };
                run.answer(reply).map_err(fail)?;
                // The model ends a shard creation with `created` or `found` and a provision with `provisioned` or
                // `found`; production returns `Ok` for each pair.
                let expected = match (op, res) {
                    ("createShard", "created" | "found")
                    | ("provision", "provisioned" | "found") => "ok",
                    (_, res) => res,
                };
                match run.pending() {
                    Message::Done(result) if expected.is_empty() => {
                        return Err(fail(format!("the operation ended {result}")));
                    }
                    Message::Done(result) if result != expected => {
                        return Err(fail(format!("result {result}, modeled {expected}")));
                    }
                    Message::Done(_) => {
                        let (run, _) = runs[proc].take().expect("the run");
                        run.finish().map_err(fail)?;
                    }
                    _ if !expected.is_empty() => {
                        return Err(fail(format!("the operation continues, modeled {expected}")));
                    }
                    _ => {}
                }
            }
            "release" => {
                let outcomes = store.release();
                let landed = match outcomes.as_slice() {
                    [] => "nothing",
                    [Outcome::Committed(_)] => "committed",
                    [Outcome::NotCommitted(Refusal::Condition)] => "refused",
                    outcomes => return Err(fail(format!("released {outcomes:?}"))),
                };
                if landed != res {
                    return Err(fail(format!("released {landed}, modeled {res}")));
                }
            }
            "fence" => {
                let page = match key {
                    "page0" => 0,
                    "page1" => 1,
                    _ => return Err("event key".into()),
                };
                if driver != Driver::FenceDropped {
                    fence_page(&store, page, (record().generation.get() << 32) | 2);
                }
            }
            action => return Err(format!("action {i}: unknown action {action}")),
        }

        let current = |key: Key| store.0.borrow().current(&key).cloned();
        let shard = match current(Key::Shard(sid())) {
            None => (false, 0, 0),
            Some(item) => {
                let held =
                    ShardRecord::decode(&item.value).map_err(|_| fail("shard record".into()))?;
                let id = match held.active {
                    active if active == creation(1).active => 1,
                    active if active == creation(2).active => 2,
                    _ => return Err(fail("another creation".into())),
                };
                (true, id, commits(&store, Key::Shard(sid())) as u64)
            }
        };
        let page = |at: u16| -> Result<(bool, u64, bool), String> {
            let key = Key::Page(sid(), at);
            Ok(match current(key) {
                None => (false, 0, false),
                Some(item) => (
                    true,
                    commits(&store, key) as u64,
                    CoveragePage::decode(&item.value)
                        .map_err(|_| fail("page".into()))?
                        .fence
                        != 0,
                ),
            })
        };
        let held = match current(Key::Volume(volume)) {
            None => (0, 0, 0),
            Some(item) => {
                let held =
                    VolumeRecord::decode(&item.value).map_err(|_| fail("volume record".into()))?;
                let attached = match held.events.as_slice() {
                    [] => 0,
                    [event] if event.kind == EventKind::Attach && event.host == hosts[0] => 1,
                    [event] if event.kind == EventKind::Attach && event.host == hosts[1] => 2,
                    events => return Err(fail(format!("events {events:?}"))),
                };
                let state = match held.state {
                    VolumeState::Provisioning => 1,
                    VolumeState::Fresh => 2,
                    state => return Err(fail(format!("volume state {state:?}"))),
                };
                (state, attached, commits(&store, Key::Volume(volume)) as u64)
            }
        };
        let seen: Seen = (shard, [page(0)?, page(1)?], held);
        let model = modeled(model)?;
        if seen != model {
            return Err(fail(format!("stored {seen:?}, modeled {model:?}")));
        }
        reached.push((
            act.to_owned(),
            op.to_owned(),
            key.to_owned(),
            res.to_owned(),
        ));
    }
    // An operation the trace leaves running is blocked in its pending request. Dropping its `Op` ends that request
    // with no reply and joins the operation.
    drop(runs);
    Ok(reached)
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap()
        .1
}

/// Every committed trace replays with each request, each result and the stored records equal to the model's at
/// every state. Together the traces reach `init` and every event `act` the five actions of the model's `step`
/// record, `request` as `read` and `write` and `unknown` as `commit`, `lost` and `hold`, and their `read` and
/// `write` steps
/// end each of the three operations with every result the model's `request` gives it. The model's `step` line is
/// pinned, so a model whose `step` chooses among other actions fails here.
#[test]
fn committed_creation_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    for (name, json) in FIXTURES {
        reached.extend(
            replay(json, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}")),
        );
    }
    assert!(
        std::str::from_utf8(MODEL).unwrap().contains(
            "    any {begin(p, op, arg), request(p), unknown(p, fault), release, fence(page)}\n"
        ),
        "the model's step chooses among other actions than the replay drives"
    );
    let actions: BTreeSet<&str> = reached.iter().map(|(act, ..)| act.as_str()).collect();
    assert_eq!(
        actions,
        BTreeSet::from([
            "begin", "commit", "fence", "hold", "init", "lost", "read", "release", "write"
        ])
    );
    let outcomes: BTreeSet<(&str, &str, &str, &str)> = reached
        .iter()
        .filter(|(act, _, _, res)| !res.is_empty() && matches!(act.as_str(), "read" | "write"))
        .map(|(act, op, key, res)| (act.as_str(), op.as_str(), key.as_str(), res.as_str()))
        .collect();
    assert_eq!(
        outcomes,
        BTreeSet::from([
            ("read", "attach", "volume", "absent"),
            ("read", "attach", "volume", "conflict"),
            ("read", "attach", "volume", "recorded"),
            ("read", "createShard", "shard", "conflict"),
            ("read", "createShard", "shard", "found"),
            ("read", "provision", "volume", "conflict"),
            ("read", "provision", "volume", "found"),
            ("write", "attach", "volume", "condition"),
            ("write", "attach", "volume", "recorded"),
            ("write", "createShard", "shard", "created"),
            ("write", "provision", "volume", "provisioned"),
        ])
    );
}

/// Quint regenerates each trace `quint/creation_fixtures.py` declares; the committed fixture must equal the model's
/// states, so the workspace replay of the committed fixtures replays the model's traces.
#[test]
#[ignore = "generated creation traces; the quint lane runs it with Quint on PATH"]
fn generated_creation_traces_replay() {
    let traces = ReplayScratch::run("creation", "creation_fixtures.py", &[]);
    let states = |text: &str| serde_json::from_str::<Value>(text).unwrap()["states"].take();
    let mut actions = 0;
    for (name, committed) in FIXTURES {
        let generated = traces.trace(name);
        assert_eq!(
            states(&generated),
            states(committed),
            "{name}: the committed trace differs from the model's"
        );
        let reached =
            replay(&generated, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}"));
        actions += reached.len() - 1;
    }
    println!(
        "core replay: traces={} actions={actions} agreement=all",
        FIXTURES.len()
    );
}

/// Each wrong driver breaks one fact of the store the model stands for, and the replay refuses it at the first
/// state the fact shows in. A store that acknowledges a create of a page that exists sends the losing creation on
/// to create the next page where the model has it read the page it lost. A dropped fence leaves the stored page
/// behind the model's. A held write that is lost releases nothing where the model commits it.
#[test]
fn negative_control_a_store_that_breaks_a_create_rule_fails_the_creation_replay() {
    // racing_creations: the model refuses creation 2's create of page 0 at state 6 and has it read the page at
    // state 7, where the acknowledged creation issues its create of page 1.
    assert_eq!(
        replay(fixture("racing_creations"), Driver::AcknowledgesRefused).unwrap_err(),
        "read at 7: the operation writes Page(Shard(7), 1)"
    );
    // held_create_after_the_winner: the owner fences page 1 at state 16.
    let stored: Seen = (
        (true, 1, 1),
        [(true, 1, false), (true, 1, false)],
        (0, 0, 0),
    );
    let model: Seen = ((true, 1, 1), [(true, 1, false), (true, 2, true)], (0, 0, 0));
    assert_eq!(
        replay(
            fixture("held_create_after_the_winner"),
            Driver::FenceDropped
        )
        .unwrap_err(),
        format!("fence at 16: stored {stored:?}, modeled {model:?}")
    );
    // held_attach_lands: the attach write is held at state 5 and released at state 6.
    assert_eq!(
        replay(fixture("held_attach_lands"), Driver::HeldDropped).unwrap_err(),
        "release at 6: released nothing, modeled committed"
    );
}

/// A success that returns another value than its arguments name fails the result comparison at the step that
/// ends the operation. A shard creation that reads its own creation at `E = 1` returns that record; a provision of
/// another layout returns the record of that layout; an attach of the other host returns that host's witness. An
/// attach that returns before its first request fails at its `begin` step.
#[test]
fn negative_control_a_success_that_returns_another_value_fails_the_creation_replay() {
    let volume = vol("vol-0c");
    // create_then_replay: the second creation of record 1 reads the shard record at state 7 and ends `found`.
    let bumped = ShardRecord {
        attempts: 1,
        ..creation(1)
    };
    assert_eq!(
        replay(fixture("create_then_replay"), Driver::ShardReadBumped).unwrap_err(),
        format!(
            "read at 7: result Read {{ key: {:?}, version: {:?}, value: {bumped:?} }}, modeled ok",
            Key::Shard(sid()),
            Version::FIRST
        )
    );
    // attach_once: the provision writes at state 2 and host 1's attach writes at state 5.
    let other = provisioning(
        volume,
        Layout {
            units: 128,
            ..layout()
        },
    );
    assert_eq!(
        replay(fixture("attach_once"), Driver::OtherLayout).unwrap_err(),
        format!(
            "write at 2: result Read {{ key: {:?}, version: {:?}, value: {other:?} }}, modeled ok",
            Key::Volume(volume),
            Version::FIRST
        )
    );
    // attach_once: host 1's attach begins at state 3.
    assert_eq!(
        replay(fixture("attach_once"), Driver::EndsAtBegin).unwrap_err(),
        "begin at 3: the operation ended recorded"
    );
    assert_eq!(
        replay(fixture("attach_once"), Driver::OtherHost).unwrap_err(),
        format!(
            "write at 5: result AttachRecorded {{ volume: {volume:?}, host: {:?} }}, modeled recorded",
            host(SPARE)
        )
    );
}

/// A trace altered in one compared field of one state fails at that state, through the comparison that reads the
/// field; a stale model digest or a missing state fails the trace before any state replays.
#[test]
fn negative_control_an_altered_creation_trace_fails_at_the_altered_state() {
    // attach_once: the provision writes at state 2, host 1's attach reads at state 4 and writes at state 5, and
    // host 2's attach conflicts at state 7.
    let json = fixture("attach_once");
    let altered = |state: usize, edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(json).unwrap();
        edit(&mut trace["states"][state][STATE]);
        replay(&trace.to_string(), Driver::Faithful).unwrap_err()
    };
    let number = |value: u64| serde_json::json!({ "#bigint": value.to_string() });
    let absent = [(false, 0u64, false); 2];
    assert_eq!(
        altered(5, &|model| model["vol"]["host"] = number(2)),
        format!(
            "write at 5: stored {:?}, modeled {:?}",
            ((false, 0u64, 0u64), absent, (2u64, 1u64, 2u64)),
            ((false, 0u64, 0u64), absent, (2u64, 2u64, 2u64))
        )
    );
    assert_eq!(
        altered(7, &|model| model["ev"]["res"] = "recorded".into()),
        "read at 7: result conflict, modeled recorded"
    );
    assert!(
        altered(4, &|model| model["ev"]["key"] = "shard".into())
            .starts_with("read at 4: the operation reads Volume(")
    );
    assert_eq!(
        altered(3, &|model| model["ev"]["arg"] = number(3)),
        "begin at 3: no operation attach(3)"
    );
    let mut fenced: Value = serde_json::from_str(fixture("held_create_after_the_winner")).unwrap();
    fenced["states"][16][STATE]["ev"]["key"] = "page2".into();
    assert_eq!(
        replay(&fenced.to_string(), Driver::Faithful).unwrap_err(),
        "event key"
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
