//! Replays the key-operation model's committed traces against a live [`Storage`] and feeds them to the history
//! oracle.
//!
//! Each trace under `keyops_fixtures` is one directed run of `quint/keyops.qnt` at two units. The replay drives a
//! storage of two one-unit slots and two fill records through every recorded action and, after each one, compares the action's
//! typed result and this projection of the storage with the trace's state: each slot's state and count, with a
//! held slot at the incarnation its reservation claimed, the slot ledger and the raw ledger, the occupied records of
//! the fill table, the shard's visible key count and the admission cutoff. A model slot is bound to the storage slot its reservation claimed, so the comparison holds
//! whichever free slot a claim takes. The device delivers a fill's write terminal only at the trace's `writeDone`,
//! and its metadata commands settle after every action.
//!
//! The same traces become history rows, and the oracle must pass them with the History obligation activated. A
//! reserved fill that ends by abort is recorded as its publication refused, the row that ends a fill in the
//! oracle's key model.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::attempt_tests::records;
use super::device::sim::Fault;
use super::device::{CommandToken, DeviceStatus, IO_UNIT};
use super::evict::Commit;
use super::evict_tests::generous;
use super::extent::RawPartition;
use super::fill::Record;
use super::owner_fixture::write_tokens;
use super::publish_tests::{PAGE, TRIES, budget, index_config, key, storage_config, storage_from};
use super::register::Registration;
use super::tables::{SlotIndex, SlotState};
use super::test_platform::TestPlatform;
use super::volume_fixture::{Device, ample_io, arena_with, step};
use super::{
    Admitted, AllocationId, BeginError, CacheVersion, Decision, ExtentLease, FillAttempt,
    FillPublishError, FillReserveError, InvalidateError, LookupError, ReceiveError, Storage,
    WritableFill,
};
use crate::index::{IndexConfig, Key, ShardIndex};
use crate::oracle::{
    ActionKind, ClockSample, KeyId, Label, NoInformation, Obligation, OpId, Outcome, Recorder, Row,
    Verdict, check,
};

const FIXTURES: [(&str, &str); 8] = [
    ("expiry", include_str!("keyops_fixtures/expiry.itf.json")),
    ("replace", include_str!("keyops_fixtures/replace.itf.json")),
    ("revoke", include_str!("keyops_fixtures/revoke.itf.json")),
    ("refuse", include_str!("keyops_fixtures/refuse.itf.json")),
    ("abandon", include_str!("keyops_fixtures/abandon.itf.json")),
    ("evict", include_str!("keyops_fixtures/evict.itf.json")),
    ("close", include_str!("keyops_fixtures/close.itf.json")),
    ("shut", include_str!("keyops_fixtures/shut.itf.json")),
];
const MODEL: &[u8] = include_bytes!("../../../../quint/keyops.qnt");
/// The traces' `UNITS` and the model's `FILLS` and `RIGHTS`.
const SLOTS: usize = 2;
const FILLS: usize = 2;
const RIGHTS: usize = 2;
const SECOND: u64 = 1_000_000_000;
const META: usize = 4;
const BODY: usize = 20;
const PAYLOAD: usize = META + BODY;
const K: KeyId = KeyId(0);

fn object() -> Key {
    key(1)
}

/// The trace with every ITF integer as a number, every set as an array and every map as an object keyed by its
/// keys' decimal text.
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
        Value::Object(map) if map.contains_key("#set") => {
            let mut members = map.remove("#set").unwrap();
            plain(&mut members);
            *v = members;
        }
        Value::Object(map) if map.contains_key("#map") => {
            let mut pairs = map.remove("#map").unwrap();
            plain(&mut pairs);
            *v = pairs
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| (pair[0].to_string(), pair[1].clone()))
                .collect::<serde_json::Map<_, _>>()
                .into();
        }
        Value::Object(map) => map.values_mut().for_each(plain),
        Value::Array(list) => list.iter_mut().for_each(plain),
        _ => {}
    }
}

fn n(v: &Value, field: &str) -> i64 {
    v[field].as_i64().unwrap()
}

fn text<'v>(v: &'v Value, field: &str) -> &'v str {
    v[field].as_str().unwrap()
}

fn var<'v>(state: &'v Value, name: &str) -> &'v Value {
    &state[format!("keyopsCase::keyops::{name}")]
}

fn parsed(json: &str) -> Result<Value, String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|_| "fixture json")?;
    let digest: String = Sha256::digest(MODEL)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if trace["#meta"]["keyops"]["model_sha256"] != digest {
        return Err("fixture model digest".into());
    }
    let states = trace["states"].as_array().ok_or("fixture states")?.len();
    let recipe = trace["#meta"]["keyops"]["recipe"]
        .as_array()
        .ok_or("fixture recipe")?
        .len();
    if states != recipe + 1 {
        return Err("fixture recipe length".into());
    }
    plain(&mut trace);
    Ok(trace)
}

/// Checks that the event and the action Quint recorded for state `i` are recipe entry `i - 1`.
fn declared_action(trace: &Value, i: usize) -> Result<(), String> {
    let state = &trace["states"][i];
    let ev = var(state, "ev");
    let act = text(ev, "act");
    let entry = match act {
        "reserve" | "receive" | "abort" => format!("{act}({})", ev["n"]),
        "writeDone" => format!("writeDone({}, {})", ev["s"], ev["ok"]),
        "publish" => format!("publish({}, {})", ev["n"], ev["d"]),
        "release" => format!("release({})", ev["s"]),
        act => act.into(),
    };
    if state["mbt::actionTaken"] != act || trace["#meta"]["keyops"]["recipe"][i - 1] != entry {
        return Err(format!("action {i}: recipe"));
    }
    Ok(())
}

/// The model's count of slot `s`: the rights naming its incarnation, plus its anchor.
fn model_refs(st: &Value, s: &str) -> usize {
    let slot = &st["slots"][s];
    let index: i64 = s.parse().unwrap();
    let rights = st["rights"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|right| n(right, "slot") == index && right["inc"] == slot["inc"])
        .count();
    rights + usize::from(slot["anchor"].as_bool().unwrap())
}

/// Whether `raw` books the model's free, reserved, resident and retired units: a held unit's payload terms count
/// the metadata and body lengths its reservation named, and the rest of the unit is waste.
fn raw_agrees(raw: RawPartition, [free, reserved, resident, retired]: [usize; 4]) -> bool {
    let held = SLOTS - free;
    (raw.free, raw.reserved, raw.resident, raw.retired, raw.waste)
        == (
            (SLOTS + 1 - held) * IO_UNIT,
            reserved * PAYLOAD,
            resident * PAYLOAD,
            retired * PAYLOAD,
            held * (IO_UNIT - PAYLOAD),
        )
}

enum Fill<'s, 'a> {
    Granted(FillAttempt<'s, TestPlatform>),
    Reserved(Box<WritableFill<'s, 'a, TestPlatform>>),
}

/// One storage under replay and what the driver holds of it.
struct Replay<'s, 'a> {
    storage: &'s Storage<TestPlatform>,
    device: Device<'s, 'a>,
    reader: Registration<'s, TestPlatform>,
    fills: BTreeMap<i64, Fill<'s, 'a>>,
    leases: BTreeMap<i64, Vec<ExtentLease<'s, TestPlatform>>>,
    /// The allocation each model slot's current incarnation is bound to.
    bound: BTreeMap<i64, AllocationId>,
    /// The held write command of each model slot.
    writes: BTreeMap<i64, CommandToken>,
    /// The advisory admission of the one object shape, decided while admission was open and kept for every
    /// reservation, as a caller keeps it for the life of its attempt.
    admitted: Admitted,
}

fn storage() -> Storage<TestPlatform> {
    let fills = [FILLS];
    let index = IndexConfig {
        fills: &fills,
        ..index_config(&[SLOTS], (1, 1), 1)
    };
    let config = super::config::StorageConfig {
        object_rights: RIGHTS,
        ..storage_config(SLOTS)
    };
    storage_from(&config, &index, TestPlatform::heap(PAGE))
}

impl<'s, 'a> Replay<'s, 'a> {
    fn states(&self) -> Vec<SlotState> {
        (0..SLOTS)
            .map(|slot| self.storage.slot_state(SlotIndex(slot)).unwrap().0)
            .collect()
    }

    fn model_slot(&self, id: AllocationId) -> Option<i64> {
        self.bound
            .iter()
            .find_map(|(&slot, &bound)| (bound == id).then_some(slot))
    }

    fn clock(&self, seconds: i64) {
        self.storage
            .platform
            .ticks(&[Some(seconds as u64 * SECOND + 1)]);
    }

    /// Ticks the device until the journal cell is empty and the held writes are its only outstanding commands.
    fn settle(&mut self) {
        let mut out = Vec::with_capacity(16);
        for _ in 0..64 {
            step(&mut self.device.volume, &self.device.control, &mut out);
            out.clear();
            if self.device.volume.journal_settled()
                && self.device.control.outstanding() == self.writes.len()
            {
                return;
            }
        }
        panic!(
            "the device kept a metadata command\n{}",
            self.device.control.describe()
        );
    }

    /// What a visit returned, read from the slot states before and after it.
    fn visited(&self, before: &[SlotState]) -> &'static str {
        let after = self.states();
        let returned = before
            .iter()
            .zip(&after)
            .any(|pair| pair == (&SlotState::Retired, &SlotState::Free));
        if returned {
            "Returned"
        } else if after.contains(&SlotState::Retired) {
            "Held"
        } else {
            "None"
        }
    }

    /// Runs the action `ev` records and returns its typed result under the model's name.
    fn act(&mut self, ev: &Value, clock: i64) -> Result<String, String> {
        let storage = self.storage;
        let serial = n(ev, "n");
        let result = match text(ev, "act") {
            "begin" => match storage.begin_fill(&object(), CacheVersion(0), TRIES, &mut budget()) {
                Ok(attempt) => {
                    if attempt.serial() as i64 != serial {
                        return Err("serial".into());
                    }
                    self.fills.insert(serial, Fill::Granted(attempt));
                    "Granted"
                }
                Err(BeginError::Closed) => "Closed",
                Err(BeginError::InProgress) => "InProgress",
                Err(BeginError::FillSlotsFull) => "FillSlotsFull",
                Err(other) => return Err(format!("begin {other:?}")),
            },
            "reserve" => {
                let Some(Fill::Granted(attempt)) = self.fills.remove(&serial) else {
                    return Err("reserve without a granted attempt".into());
                };
                match attempt.reserve_storage(
                    self.admitted,
                    Some(META),
                    Some(BODY),
                    TRIES,
                    &mut budget(),
                ) {
                    Ok(fill) => {
                        let id = fill.id();
                        self.bound
                            .retain(|_, bound| bound.slot_index() != id.slot_index());
                        self.bound.insert(n(ev, "s"), id);
                        self.fills.insert(serial, Fill::Reserved(Box::new(fill)));
                        "Reserved"
                    }
                    Err(FillReserveError::Closed) => "Closed",
                    Err(FillReserveError::CleanReserve) => "CleanReserve",
                    Err(FillReserveError::Superseded) => "Superseded",
                    Err(other) => return Err(format!("reserve {other:?}")),
                }
            }
            "receive" => {
                let Some(Fill::Reserved(fill)) = self.fills.get_mut(&serial) else {
                    return Err("receive without a reserved fill".into());
                };
                let payload = Recorder::content(K, Label(serial as u64), META as u32, BODY as u64);
                let before = write_tokens(&self.device.control);
                match fill.receive(&mut self.device.volume, &payload, &mut ample_io()) {
                    Ok(taken) => {
                        let progress = fill.progress(&self.device.volume);
                        let submitted = write_tokens(&self.device.control);
                        if taken != payload.len()
                            || progress.submitted_units != progress.len_units
                            || submitted.len() != before.len() + 1
                        {
                            return Err("receive submitted other than one whole write".into());
                        }
                        let token = submitted[before.len()];
                        self.device.control.hold(token);
                        self.writes.insert(n(ev, "s"), token);
                        "Submitted"
                    }
                    Err(ReceiveError::Closed) => "Closed",
                    Err(ReceiveError::Revoked) => "Revoked",
                    Err(other) => return Err(format!("receive {other:?}")),
                }
            }
            "writeDone" => {
                let token = self
                    .writes
                    .remove(&n(ev, "s"))
                    .ok_or("writeDone without a held write")?;
                let ok = ev["ok"].as_bool().unwrap();
                if !ok {
                    self.device
                        .control
                        .fault(token, Fault::Status(DeviceStatus::Kernel(-5)));
                }
                self.device.control.release(token);
                self.device.control.post(token);
                if ok { "Written" } else { "Failed" }
            }
            "publish" => {
                let Some(Fill::Reserved(fill)) = self.fills.remove(&serial) else {
                    return Err("publish without a reserved fill".into());
                };
                let replacing = self.states().contains(&SlotState::Resident);
                let slot = n(ev, "s");
                match fill.publish(
                    &mut self.device.volume,
                    n(ev, "d") as u64 * SECOND,
                    TRIES,
                    &mut budget(),
                ) {
                    Ok(lease) => {
                        if self.model_slot(lease.id()) != Some(slot) {
                            return Err("publication's lease".into());
                        }
                        self.leases.entry(slot).or_default().push(lease);
                        if replacing { "Replaced" } else { "Published" }
                    }
                    Err(FillPublishError::Incomplete) => "Incomplete",
                    Err(FillPublishError::Closed) => "Closed",
                    Err(FillPublishError::Superseded) => "Superseded",
                    Err(FillPublishError::Expired) => "Expired",
                    Err(other) => return Err(format!("publish {other:?}")),
                }
            }
            "abort" => {
                match self.fills.remove(&serial) {
                    Some(Fill::Granted(attempt)) => attempt.abort(),
                    Some(Fill::Reserved(fill)) => fill.abort(),
                    None => return Err("abort without an attempt".into()),
                }
                "Aborted"
            }
            "lookup" => match self.reader.lookup(&object(), TRIES, &mut budget()) {
                Ok(lease) => {
                    let slot = self.model_slot(lease.id()).ok_or("hit an unbound slot")?;
                    if slot != n(ev, "s") {
                        return Err("hit another slot".into());
                    }
                    self.leases.entry(slot).or_default().push(lease);
                    "Hit"
                }
                Err(LookupError::Missing) => "Missing",
                Err(LookupError::Expired) => "Expired",
                Err(LookupError::RetainLimit) => "RetainLimit",
                Err(LookupError::Closed) => "Closed",
                Err(other) => return Err(format!("lookup {other:?}")),
            },
            "release" => {
                let lease = self
                    .leases
                    .get_mut(&n(ev, "s"))
                    .and_then(Vec::pop)
                    .ok_or("release without a lease")?;
                drop(lease);
                "Released"
            }
            "invalidate" => match storage.invalidate(&object(), TRIES, &mut budget()) {
                Ok(done) => {
                    let removed = done.removed.and_then(|(id, _)| self.model_slot(id));
                    let revoked = done.revoked.map_or(0, |serial| serial as i64);
                    if removed.unwrap_or(-1) != n(ev, "s") || revoked != serial {
                        return Err("invalidation's removal or revocation".into());
                    }
                    "Invalidated"
                }
                Err(InvalidateError::Closed) => "Closed",
                Err(other) => return Err(format!("invalidate {other:?}")),
            },
            "expire" => match storage
                .expire_step(&mut generous())
                .map_err(|error| format!("expire {error:?}"))?
                .commit
            {
                Some(Commit::Evicted { victim, .. }) => {
                    if self.model_slot(victim) != Some(n(ev, "s")) {
                        return Err("expired another slot".into());
                    }
                    "Removed"
                }
                None => "None",
                Some(other) => return Err(format!("expire {other:?}")),
            },
            "evict" => match storage
                .evict_step(&mut generous(), |_, _| true)
                .map_err(|error| format!("evict {error:?}"))?
                .commit
            {
                Some(Commit::Evicted { victim, .. }) => {
                    if self.model_slot(victim) != Some(n(ev, "s")) {
                        return Err("evicted another slot".into());
                    }
                    "Removed"
                }
                Some(Commit::Replacing) => "Replacing",
                None => "None",
                Some(other) => return Err(format!("evict {other:?}")),
            },
            "certify" => {
                let report = storage
                    .certify(&mut generous())
                    .map_err(|error| format!("certify {error:?}"))?;
                if report.certified.is_none() {
                    return Err("certification left its pass unfinished".into());
                }
                "Certified"
            }
            "service" => {
                let before = self.states();
                storage
                    .service(&mut generous())
                    .map_err(|error| format!("service {error:?}"))?;
                self.visited(&before)
            }
            "serviceFills" => {
                let report = storage
                    .service_fills(ShardIndex(0), TRIES, &mut budget())
                    .map_err(|error| format!("serviceFills {error:?}"))?;
                if report.released > 0 { "Freed" } else { "None" }
            }
            "close" => {
                storage.close();
                "Done"
            }
            "closeService" => {
                let before: Vec<SlotState> = self
                    .states()
                    .into_iter()
                    .map(|state| match state {
                        SlotState::Resident => SlotState::Retired,
                        state => state,
                    })
                    .collect();
                storage
                    .close_service(&mut generous())
                    .map_err(|error| format!("closeService {error:?}"))?;
                self.visited(&before)
            }
            "tick" => {
                self.clock(clock);
                "Tick"
            }
            other => return Err(format!("unknown action {other}")),
        };
        self.settle();
        Ok(result.into())
    }

    /// Compares the storage with the model state `st` after action `i`.
    fn agree(&mut self, st: &Value, i: usize) -> Result<(), String> {
        let pool = self.storage.live_pool().ok_or("drained")?;
        for (s, slot) in st["slots"].as_object().unwrap() {
            let model = text(slot, "state");
            let Some(id) = self.bound.get(&s.parse::<i64>().unwrap()) else {
                if model != "Free" {
                    return Err(format!("slot {s} at {i}: unbound"));
                }
                continue;
            };
            let real = self.storage.slot_state(SlotIndex(id.slot_index())).unwrap();
            let held = model != "Free";
            if format!("{:?}", real.0) != model
                || (held && real.1 != id.incarnation())
                || pool.refs(id.slot_index()) != model_refs(st, s)
            {
                return Err(format!("slot {s} at {i}"));
            }
        }
        let ledger = self
            .storage
            .pool_report()
            .and_then(|report| report.ledger)
            .ok_or("ledger")?;
        let want = &st["ledger"];
        let term = |name: &str| n(want, name) as usize;
        let units = [
            term("free"),
            term("reserved"),
            term("resident"),
            term("retired"),
        ];
        let slots = ledger.slots;
        let unbound_free = (0..SLOTS)
            .filter(|slot| !self.bound.values().any(|id| id.slot_index() == *slot))
            .all(|slot| self.storage.slot_state(SlotIndex(slot)).unwrap().0 == SlotState::Free);
        if [slots.free, slots.filling, slots.resident, slots.retired] != units
            || slots.quarantined != 0
            || !unbound_free
        {
            return Err(format!("ledger at {i}"));
        }
        if !raw_agrees(ledger.raw, units) {
            return Err(format!("raw ledger at {i}"));
        }
        let mut occupied: Vec<(i64, bool, bool)> = records(self.storage)
            .into_iter()
            .filter_map(|record| match record {
                Record::Free => None,
                Record::Occupied {
                    serial,
                    departed,
                    revoked,
                } => Some((serial.get() as i64, departed, revoked)),
            })
            .collect();
        occupied.sort_unstable();
        let mut fills: Vec<(i64, bool, bool)> = st["fills"]
            .as_array()
            .unwrap()
            .iter()
            .map(|fill| {
                (
                    n(fill, "serial"),
                    fill["departed"].as_bool().unwrap(),
                    fill["revoked"].as_bool().unwrap(),
                )
            })
            .collect();
        fills.sort_unstable();
        if occupied != fills {
            return Err(format!("fills at {i}"));
        }
        let resident = usize::from(term("resident") > 0);
        if self.storage.shard_report(ShardIndex(0)).unwrap().visible != resident {
            return Err(format!("mapping at {i}"));
        }
        if self.storage.is_closed() != st["closed"].as_bool().unwrap() {
            return Err(format!("cutoff at {i}"));
        }
        Ok(())
    }
}

/// Replays `json` and returns its action count, or the first disagreement.
fn replay(json: &str) -> Result<usize, String> {
    let trace = parsed(json)?;
    let storage = storage();
    let arena = arena_with(4, 5);
    let Decision::Admit(admitted) = storage.decide_admission(Some(META), Some(BODY)) else {
        return Err("admission".into());
    };
    let mut run = Replay {
        storage: &storage,
        device: Device::new(&storage, &arena),
        reader: storage.register().map_err(|_| "registration")?,
        fills: BTreeMap::new(),
        leases: BTreeMap::new(),
        bound: BTreeMap::new(),
        writes: BTreeMap::new(),
        admitted,
    };
    run.clock(0);
    let states = trace["states"].as_array().unwrap();
    for (i, state) in states.iter().enumerate() {
        let st = var(state, "st");
        if i > 0 {
            declared_action(&trace, i)?;
            let ev = var(state, "ev");
            let result = run
                .act(ev, n(st, "clock"))
                .map_err(|error| format!("action {i}: {error}"))?;
            if result != text(ev, "res") {
                return Err(format!("result at {i}: {result} != {}", text(ev, "res")));
            }
        }
        run.agree(st, i)?;
    }
    Ok(states.len() - 1)
}

/// The rows the oracle's recorder writes for one published fill of `serial`: its reservation, receive, write
/// completion and publication, under operation `op`.
fn fill_rows(serial: i64, op: OpId) -> [Row; 4] {
    let mut recorder = Recorder::new(1);
    recorder.published(K, Label(serial as u64), META as u32, BODY as u64, (1, 1));
    let mut rows: [Row; 4] = recorder.rows().to_vec().try_into().unwrap();
    rows.iter_mut().for_each(|row| row.op = op);
    rows
}

/// The one row `record` writes, under operation `op`.
fn recorded(op: OpId, record: impl FnOnce(&mut Recorder)) -> Row {
    let mut recorder = Recorder::new(1);
    record(&mut recorder);
    let mut row = recorder.rows()[0].clone();
    row.op = op;
    row
}

/// A row of `kind` about the key with no outcome, answered at once under operation `op`.
fn instant(op: OpId, kind: ActionKind) -> Row {
    let keyed = recorded(op, |recorder| {
        recorder.lookup_at(K, Outcome::Missing, None, None);
    });
    let mut row = Row::new(op, kind);
    row.subject = keyed.subject;
    row.episode = keyed.episode;
    row.responded = keyed.responded;
    row
}

/// The history rows a trace records, in the model's order: each reserved fill's reservation, receive, write
/// completion and publication under one operation, each lookup and the release of its lease, each invalidation,
/// expiry and eviction, and the close. A refused reservation names no content and records no row.
fn rows(json: &str) -> Vec<Row> {
    let trace = parsed(json).unwrap();
    let mut rows: Vec<Row> = Vec::new();
    let mut fills: BTreeMap<i64, [Row; 4]> = BTreeMap::new();
    // Each slot's leases, newest last: the lookup that took it, or `None` for a publisher's.
    let mut leases: BTreeMap<i64, Vec<Option<OpId>>> = BTreeMap::new();
    let mut next = 0;
    let mut fresh = || {
        next += 1;
        OpId(next)
    };
    let refusal = |res: &str| {
        Outcome::NoInformation(match res {
            "Closed" => NoInformation::Closed,
            "RetainLimit" => NoInformation::RetainLimit,
            _ => NoInformation::Refused,
        })
    };
    for state in &trace["states"].as_array().unwrap()[1..] {
        let (ev, st) = (var(state, "ev"), var(state, "st"));
        let (res, serial, slot) = (text(ev, "res"), n(ev, "n"), n(ev, "s"));
        let clock = ClockSample::Seconds(n(st, "clock") as u64);
        match text(ev, "act") {
            "reserve" if res == "Reserved" => {
                let [fill, ..] = fills
                    .entry(serial)
                    .or_insert(fill_rows(serial, fresh()))
                    .clone();
                rows.push(fill);
            }
            "receive" => {
                let [_, mut receive, ..] = fills[&serial].clone();
                if res != "Submitted" {
                    receive.payload = Some(Vec::new());
                    receive.outcome = Some(refusal(res));
                }
                rows.push(receive);
            }
            "writeDone" if res == "Written" => {
                let of = n(&st["slots"][slot.to_string()], "label");
                rows.push(fills[&of][2].clone());
            }
            "publish" | "abort" if fills.contains_key(&serial) => {
                let [.., mut publish] = fills[&serial].clone();
                match res {
                    "Published" | "Replaced" => {
                        publish.deadline = Some(n(ev, "d") as u64);
                        publish.clock = Some(clock);
                        leases.entry(slot).or_default().push(None);
                    }
                    res => publish.outcome = Some(refusal(res)),
                }
                if res == "Replaced" {
                    publish.kind = ActionKind::Replace;
                }
                rows.push(publish);
            }
            "lookup" => {
                let op = fresh();
                let (outcome, label) = match res {
                    "Hit" => (Outcome::Hit, Some(Label(n(ev, "label") as u64))),
                    "Expired" => (Outcome::Expired, Some(Label(n(ev, "label") as u64))),
                    "Missing" => (Outcome::Missing, None),
                    res => (refusal(res), None),
                };
                if res == "Hit" {
                    leases.entry(slot).or_default().push(Some(op));
                }
                let sample = label.map(|_| clock);
                rows.push(recorded(op, |recorder| {
                    recorder.lookup_at(K, outcome, label, sample);
                }));
            }
            "release" => {
                if let Some(Some(op)) = leases.get_mut(&slot).and_then(Vec::pop) {
                    rows.push(instant(op, ActionKind::Release));
                }
            }
            "invalidate" => {
                let outcome = if res == "Invalidated" {
                    Outcome::Acknowledged
                } else {
                    refusal(res)
                };
                rows.push(recorded(fresh(), |recorder| {
                    recorder.invalidate(K, outcome);
                }));
            }
            "expire" | "evict" if res == "Removed" => {
                let expiry = text(ev, "act") == "expire";
                let kind = if expiry {
                    ActionKind::Expire
                } else {
                    ActionKind::Evict
                };
                let mut row = instant(fresh(), kind);
                row.label = Some(Label(n(ev, "label") as u64));
                row.clock = expiry.then_some(clock);
                rows.push(row);
            }
            "close" => rows.push(recorded(fresh(), |recorder| {
                recorder.close(Outcome::Acknowledged);
            })),
            _ => {}
        }
    }
    Recorder::renumber(&mut rows);
    rows
}

fn judged(json: &str) -> Verdict {
    check(&Recorder::rebuilt(rows(json)))
}

/// `fixture` with `edit` applied to its parsed trace.
fn altered(fixture: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut trace: Value = serde_json::from_str(fixture).unwrap();
    edit(&mut trace);
    trace.to_string()
}

fn state<'v>(trace: &'v mut Value, i: usize, name: &str) -> &'v mut Value {
    &mut trace["states"][i][format!("keyopsCase::keyops::{name}")]
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find_map(|(fixture, json)| (*fixture == name).then_some(*json))
        .unwrap()
}

#[test]
fn committed_keyops_traces_replay() {
    let actions: usize = FIXTURES
        .iter()
        .map(|(name, json)| replay(json).unwrap_or_else(|error| panic!("{name}: {error}")))
        .sum();
    println!(
        "core replay: traces={} actions={actions} agreement=all",
        FIXTURES.len()
    );
}

#[test]
fn committed_keyops_traces_pass_the_history_oracle() {
    for (name, json) in FIXTURES {
        let verdict = judged(json);
        assert!(
            verdict.satisfies(&[Obligation::History]),
            "{name}: {verdict:?}"
        );
    }
}

/// A trace whose recorded result, slot, ledger, fill table or cutoff differs from the storage's fails at that
/// action.
#[test]
fn an_altered_keyops_trace_fails_at_the_action_it_changes() {
    let int = |value: i64| serde_json::json!({ "#bigint": value.to_string() });
    for (name, at, error, edit) in [
        (
            "revoke",
            13,
            "result at 13: Missing != Hit",
            Box::new(|trace: &mut Value| state(trace, 13, "ev")["res"] = "Hit".into())
                as Box<dyn FnOnce(&mut Value)>,
        ),
        (
            "expiry",
            7,
            "result at 7: RetainLimit != Hit",
            Box::new(|trace: &mut Value| state(trace, 7, "ev")["res"] = "Hit".into()),
        ),
        (
            "evict",
            9,
            "result at 9: Replacing != Removed",
            Box::new(|trace: &mut Value| state(trace, 9, "ev")["res"] = "Removed".into()),
        ),
        (
            "replace",
            14,
            "slot 0 at 14",
            Box::new(|trace: &mut Value| {
                state(trace, 14, "st")["slots"]["#map"][0][1]["state"] = "Free".into();
            }),
        ),
        (
            "abandon",
            5,
            "slot 0 at 5",
            Box::new(|trace: &mut Value| {
                state(trace, 5, "st")["rights"] = serde_json::json!({ "#set": [] });
            }),
        ),
        (
            "replace",
            17,
            "ledger at 17",
            Box::new(move |trace: &mut Value| {
                state(trace, 17, "st")["ledger"]["retired"] = int(0);
            }),
        ),
        (
            "revoke",
            12,
            "fills at 12",
            Box::new(|trace: &mut Value| {
                let fills = &mut state(trace, 12, "st")["fills"]["#set"];
                for fill in fills.as_array_mut().unwrap() {
                    fill["revoked"] = false.into();
                }
            }),
        ),
        (
            "close",
            9,
            "cutoff at 9",
            Box::new(|trace: &mut Value| state(trace, 9, "st")["closed"] = false.into()),
        ),
    ] {
        let failed = replay(&altered(fixture(name), edit)).unwrap_err();
        assert_eq!(failed, error, "{name} altered at {at}");
    }
}

/// A stale model digest, a truncated trace and a trace off its declared recipe are refused before or at the action.
#[test]
fn a_stale_truncated_or_undeclared_keyops_trace_is_refused() {
    let stale = altered(fixture("evict"), |trace| {
        trace["#meta"]["keyops"]["model_sha256"] = "stale".into();
    });
    assert_eq!(replay(&stale).unwrap_err(), "fixture model digest");
    let short = altered(fixture("evict"), |trace| {
        trace["states"].as_array_mut().unwrap().pop();
    });
    assert_eq!(replay(&short).unwrap_err(), "fixture recipe length");
    for (index, entry) in [(0, "lookup"), (4, "publish(1, 1)"), (5, "expire")] {
        let undeclared = altered(fixture("evict"), |trace| {
            trace["#meta"]["keyops"]["recipe"][index] = entry.into();
        });
        assert_eq!(
            replay(&undeclared).unwrap_err(),
            format!("action {}: recipe", index + 1)
        );
    }
    let renamed = altered(fixture("evict"), |trace| {
        state(trace, 6, "ev")["act"] = "expire".into();
    });
    assert_eq!(replay(&renamed).unwrap_err(), "action 6: recipe");
}

#[test]
fn a_raw_ledger_that_misbooks_the_payload_disagrees() {
    let units = [1, 1, 0, 0];
    let booked = |reserved: usize| RawPartition {
        free: SLOTS * IO_UNIT,
        reserved,
        waste: IO_UNIT - reserved,
        ..RawPartition::default()
    };
    assert!(raw_agrees(booked(PAYLOAD), units));
    assert!(!raw_agrees(booked(0), units), "payload booked as waste");
    assert!(
        !raw_agrees(booked(IO_UNIT), units),
        "whole extent booked as payload"
    );
}

/// The oracle refuses a trace altered to hit after the acknowledged invalidation, to hit at the deadline, to
/// publish a revoked fill and to evict beside a current fill, each by its key-model rule.
#[test]
fn an_altered_keyops_trace_fails_the_history_oracle_by_its_rule() {
    let int = |value: i64| serde_json::json!({ "#bigint": value.to_string() });
    for (name, rule, edit) in [
        (
            "revoke",
            "a hit of a version an acknowledged invalidation covered",
            Box::new(move |trace: &mut Value| {
                let ev = state(trace, 13, "ev");
                ev["res"] = "Hit".into();
                ev["label"] = int(1);
            }) as Box<dyn FnOnce(&mut Value)>,
        ),
        (
            "expiry",
            "a hit at or past the deadline",
            Box::new(|trace: &mut Value| state(trace, 11, "ev")["res"] = "Hit".into()),
        ),
        (
            "revoke",
            "a fill revoked by an invalidation or a tenure change published",
            Box::new(|trace: &mut Value| state(trace, 17, "ev")["res"] = "Published".into()),
        ),
        (
            "replace",
            "an eviction while a fill is current",
            Box::new(move |trace: &mut Value| {
                let ev = state(trace, 9, "ev");
                ev["res"] = "Removed".into();
                ev["label"] = int(1);
            }),
        ),
    ] {
        let verdict = judged(&altered(fixture(name), edit));
        assert_eq!(
            verdict.violated(),
            Some((Obligation::History, rule)),
            "{name}: {verdict:?}"
        );
    }
}

/// Quint regenerates each run's trace; the committed fixture must equal the model's states, so the workspace replay
/// of the committed fixtures replays the model's traces.
#[test]
#[ignore = "generated keyops traces; the quint lane runs it with Quint on PATH"]
fn generated_keyops_traces_replay() {
    let out = std::env::temp_dir().join(format!("keyops-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = std::process::Command::new("python3")
        .arg(root.join("quint/keyops_check.py"))
        .args(["--quint", "quint"])
        .arg("--output")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "trace generation completed");
    let states = |text: &str| serde_json::from_str::<Value>(text).unwrap()["states"].take();
    let mut actions = 0;
    for (name, committed) in FIXTURES {
        let generated = std::fs::read_to_string(out.join(format!("{name}.itf.json"))).unwrap();
        assert_eq!(
            states(&generated),
            states(committed),
            "{name}: the committed trace differs from the model's"
        );
        actions += replay(&generated).unwrap();
    }
    let _ = std::fs::remove_dir_all(&out);
    println!(
        "core replay: traces={} actions={actions} agreement=all",
        FIXTURES.len()
    );
}
