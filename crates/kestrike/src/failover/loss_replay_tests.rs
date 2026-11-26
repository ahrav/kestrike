//! The replay tests run the committed traces of the volume-loss model `quint/loss.qnt` against
//! `Reconciler::replacement`, `create_replacement`, `release_hold`, `retire` and `abandon`, and the caller's
//! `record_attach`, `add_spare` and `flip`, over the shared driver of `replay_driver`, with the `Provisioner` double
//! answering each provider create at the model's `call` step.
//!
//! # Steps
//!
//! Each model step answers the store request its process's `pc` names. The subsection "Replay against the
//! reconciler" of the section "Volume loss model" of `quint/README.md` lists the requests that fall on another
//! step: the caller's `record_attach`, `create_replacement`'s second shard read after it records the volume,
//! `retire`'s settling write and `flip`'s read of the displaced volume. A flip whose attach the record refuses ends
//! at its `begin`, and the model's shard read and then its volume read of that flip pass with no request.
//!
//! Request and call steps record the process's `pc` at the start of the step. A step that leaves its operation
//! running carries the result `""` or `ok` at a request, and the kind of the provider's kept outcome at a call.
//!
//! # Comparison
//!
//! After every step the shard records, receipts, volume records, the provider's kept outcomes and the tokens it was
//! called under equal the model's, in model units: a shard record's version is its commit count less `retire`'s
//! settling writes, a volume record's version its commit count less the attach write, and a receipt's version its
//! commit count. `RESULTS` and `REQUESTS` list the results and requests the committed traces must cover.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::Provisioner;
use super::commits;
use super::replay_driver::{Message, Op, Reply, states};
use crate::failover::detect_route_replay_tests::ReplayScratch;
use crate::failover::loss::{CreateError, Health, Phase, Provider, Receipt, Request};
use crate::failover::reconcile::{Flip, OperatorRelease, ReconcileError, Reconciler, StandbyGate};
use crate::failover::records::{
    CreationSource, ERA, Layout, Lineage, Record, ShardRecord, VolumeId, VolumeRecord, VolumeState,
};
use crate::failover::retire::Target;
use crate::failover::sim::{host, layout};
use crate::net::ownership::{Shard, ShardGeneration};
use crate::storage::store::sim::{Arm, AsReconciler, MemLog, NAMESPACE, Shared};
use crate::storage::store::{Client, Key, Outcome, Refusal, Store, StoreError, Write};
use crate::storage::store_tests::record;

const MODEL: &[u8] = include_bytes!("../../../../quint/loss.qnt");
const ST: &str = "lossCase::loss::st";
macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("loss_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

const FIXTURES: [(&str, &str); 110] = fixtures![
    "replay_abandonHeld",
    "replay_abandonNamedSpare",
    "replay_abandonOpensHeld",
    "replay_abandonReplayed",
    "replay_abandonStale",
    "replay_abandonStaleAfterTwoRaises",
    "replay_absentBeforeLoss",
    "replay_crashedAbandons",
    "replay_crashedCreates",
    "replay_crashedFlips",
    "replay_crashedStarts",
    "replay_createLatches",
    "replay_createdThenPast",
    "replay_duelingFlips",
    "replay_fenceRefusesRetire",
    "replay_flipHeldAtRecheck",
    "replay_flipOfRetired",
    "replay_flipPastAtReread",
    "replay_flipRefusesHeld",
    "replay_heldStaysWhenIsolated",
    "replay_holdRefused",
    "replay_hostsLost",
    "replay_impairedRetained",
    "replay_issueRefused",
    "replay_keptRefusal",
    "replay_latchAndRelease",
    "replay_latchRefused",
    "replay_latchUnknown",
    "replay_raiseOverReleased",
    "replay_raiseRefused",
    "replay_refusalUnknown",
    "replay_releasedNotLatched",
    "replay_rereadFindsRecorded",
    "replay_retiredFlipPast",
    "replay_settleKeepsSpare",
    "replay_shardTwoCreates",
    "replay_spareAndFenceRefused",
    "replay_spareOfRetired",
    "replay_startRacesStart",
    "replay_unknownCreates",
    "replay_unknownFlips",
    "replay_unknownReceiptWrites",
    "replay_unknownStart",
    "run_correlated_release",
    "run_crash_at_call",
    "run_host_loss",
    "run_isolated_replacement",
    "run_latch_after_issue",
    "run_retirement",
    "run_stale_token",
    "step_covered_7900",
    "step_covered_7901",
    "step_covered_7902",
    "step_covered_7903",
    "step_created_7900",
    "step_created_7901",
    "step_created_7902",
    "step_created_7903",
    "step_dueling_7900",
    "step_dueling_7901",
    "step_dueling_7902",
    "step_dueling_7903",
    "step_failed_7900",
    "step_failed_7901",
    "step_failed_7902",
    "step_failed_7903",
    "step_fenced_7900",
    "step_fenced_7901",
    "step_fenced_7902",
    "step_fenced_7903",
    "step_flipped_7900",
    "step_flipped_7901",
    "step_flipped_7902",
    "step_flipped_7903",
    "step_held_7900",
    "step_held_7901",
    "step_held_7902",
    "step_held_7903",
    "step_init_7900",
    "step_init_7901",
    "step_init_7902",
    "step_init_7903",
    "step_issued_7900",
    "step_issued_7901",
    "step_issued_7902",
    "step_issued_7903",
    "step_latched_7900",
    "step_latched_7901",
    "step_latched_7902",
    "step_latched_7903",
    "step_opened_7900",
    "step_opened_7901",
    "step_opened_7902",
    "step_opened_7903",
    "step_racing_7900",
    "step_racing_7901",
    "step_racing_7902",
    "step_racing_7903",
    "step_released_7900",
    "step_released_7901",
    "step_released_7902",
    "step_released_7903",
    "step_spared_7900",
    "step_spared_7901",
    "step_spared_7902",
    "step_spared_7903",
    "step_stale_7900",
    "step_stale_7901",
    "step_stale_7902",
    "step_stale_7903",
];

/// `Driver` selects faithful behavior or a negative control.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    Faithful,
    /// `OtherShard` passes the other shard to `create_replacement`.
    OtherShard,
    /// `ForgetfulProvider` renames the provider's kept volume of a repeated token before the create.
    ForgetfulProvider,
    /// `ForeignAttach` runs a flip's caller `record_attach` for the other shard's owner.
    ForeignAttach,
    /// `PastAsStale` reports `flip`'s `Ok(Flip::Past)` as `stale`.
    PastAsStale,
    /// `AttachReadsOnly` replaces a create's caller `record_attach` with a read of the volume record.
    AttachReadsOnly,
    /// `OtherLayout` passes `replacement` a layout of twice the units.
    OtherLayout,
}

fn num(v: &Value, what: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("model {what}"))
}

fn flag(v: &Value, what: &str) -> Result<bool, String> {
    v.as_bool().ok_or_else(|| format!("model {what}"))
}

fn text<'a>(v: &'a Value, what: &str) -> Result<&'a str, String> {
    v.as_str().ok_or_else(|| format!("model {what}"))
}

fn rows<'a>(map: &'a Value, what: &str) -> Result<&'a Vec<Value>, String> {
    map["#map"]
        .as_array()
        .ok_or_else(|| format!("model {what}"))
}

fn at<'a>(map: &'a Value, key: u64, what: &str) -> Result<&'a Value, String> {
    rows(map, what)?
        .iter()
        .find(|row| row[0].as_u64() == Some(key))
        .map(|row| &row[1])
        .ok_or_else(|| format!("model {what} {key}"))
}

fn keys(map: &Value, what: &str) -> Result<Vec<u64>, String> {
    let mut keys = rows(map, what)?
        .iter()
        .map(|row| num(&row[0], what))
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort_unstable();
    Ok(keys)
}

fn members(set: &Value, what: &str) -> Result<BTreeSet<u64>, String> {
    set["#set"]
        .as_array()
        .ok_or_else(|| format!("model {what}"))?
        .iter()
        .map(|member| num(member, what))
        .collect()
}

fn token_key(v: &Value, what: &str) -> Result<(u64, u64), String> {
    match v["#tup"].as_array().map(Vec::as_slice) {
        Some([shard, attempt]) => Ok((num(shard, what)?, num(attempt, what)?)),
        _ => Err(format!("model {what}")),
    }
}

const RESULTS: [(&str, &str, &str); 72] = [
    ("abandon", "current", "crash"),
    ("abandon", "current", "held"),
    ("abandon", "current", "replayed"),
    ("abandon", "current", "stale"),
    ("abandon", "named", "named"),
    ("abandon", "observe", "crash"),
    ("abandon", "observe", "nothing"),
    ("abandon", "raise", "condition"),
    ("abandon", "raise", "crash"),
    ("abandon", "raise", "raise"),
    ("abandon", "raise", "unknown"),
    ("abandon", "retire", "condition"),
    ("abandon", "retire", "crash"),
    ("abandon", "retire", "unknown"),
    ("create", "call", "crash"),
    ("create", "hold", "condition"),
    ("create", "hold", "crash"),
    ("create", "hold", "held"),
    ("create", "hold", "unknown"),
    ("create", "issue", "condition"),
    ("create", "issue", "unknown"),
    ("create", "provision", "unknown"),
    ("create", "raise", "condition"),
    ("create", "raise", "raise"),
    ("create", "raise", "unknown"),
    ("create", "receipt", "absent"),
    ("create", "receipt", "crash"),
    ("create", "receipt", "held"),
    ("create", "record", "condition"),
    ("create", "record", "record"),
    ("create", "record", "unknown"),
    ("create", "reread", "created"),
    ("create", "reread", "stale"),
    ("create", "shard", "crash"),
    ("create", "shard", "created"),
    ("create", "shard", "stale"),
    ("flip", "fence", "condition"),
    ("flip", "fence", "unknown"),
    ("flip", "flip", "condition"),
    ("flip", "flip", "crash"),
    ("flip", "flip", "flip"),
    ("flip", "flip", "unknown"),
    ("flip", "receipt", "held"),
    ("flip", "recheck", "crash"),
    ("flip", "recheck", "held"),
    ("flip", "reread", "crash"),
    ("flip", "reread", "past"),
    ("flip", "shard", "crash"),
    ("flip", "shard", "past"),
    ("flip", "spare", "condition"),
    ("flip", "spare", "crash"),
    ("flip", "spare", "unknown"),
    ("flip", "unused", "crash"),
    ("flip", "volume", "conflict"),
    ("release", "receipt", "absent"),
    ("release", "receipt", "crash"),
    ("release", "receipt", "unheld"),
    ("release", "release", "crash"),
    ("release", "release", "release"),
    ("release", "release", "unknown"),
    ("replacement", "latch", "condition"),
    ("replacement", "latch", "held"),
    ("replacement", "latch", "unknown"),
    ("replacement", "receipt", "crash"),
    ("replacement", "receipt", "returned"),
    ("replacement", "shard", "crash"),
    ("replacement", "shard", "outside"),
    ("replacement", "shard", "retain"),
    ("replacement", "start", "condition"),
    ("replacement", "start", "crash"),
    ("replacement", "start", "start"),
    ("replacement", "start", "unknown"),
];
const REQUESTS: [(&str, &str, &str); 44] = [
    ("abandon", "current", "read"),
    ("abandon", "due", "read"),
    ("abandon", "named", "read"),
    ("abandon", "observe", "read"),
    ("abandon", "raise", "unknown"),
    ("abandon", "raise", "write"),
    ("abandon", "retire", "unknown"),
    ("abandon", "retire", "write"),
    ("abandon", "volume", "read"),
    ("create", "hold", "unknown"),
    ("create", "hold", "write"),
    ("create", "issue", "unknown"),
    ("create", "issue", "write"),
    ("create", "provRead", "read"),
    ("create", "provision", "unknown"),
    ("create", "provision", "write"),
    ("create", "raise", "unknown"),
    ("create", "raise", "write"),
    ("create", "receipt", "read"),
    ("create", "record", "unknown"),
    ("create", "record", "write"),
    ("create", "reread", "read"),
    ("create", "shard", "read"),
    ("flip", "fence", "unknown"),
    ("flip", "fence", "write"),
    ("flip", "flip", "unknown"),
    ("flip", "flip", "write"),
    ("flip", "receipt", "read"),
    ("flip", "recheck", "read"),
    ("flip", "reread", "read"),
    ("flip", "shard", "read"),
    ("flip", "spare", "unknown"),
    ("flip", "spare", "write"),
    ("flip", "unused", "read"),
    ("flip", "volume", "read"),
    ("release", "receipt", "read"),
    ("release", "release", "unknown"),
    ("release", "release", "write"),
    ("replacement", "latch", "unknown"),
    ("replacement", "latch", "write"),
    ("replacement", "receipt", "read"),
    ("replacement", "shard", "read"),
    ("replacement", "start", "unknown"),
    ("replacement", "start", "write"),
];
const SHARDS: [u64; 2] = [1, 2];

fn shard_of(s: u64) -> Result<Shard, String> {
    u32::try_from(s)
        .ok()
        .and_then(Shard::new)
        .ok_or_else(|| format!("shard {s} lies outside the instance"))
}

fn volume_of(v: u64) -> Result<VolumeId, String> {
    let name = match v {
        1 | 2 => format!("vol-0a{v}"),
        v => format!("vol-0c{}", v.checked_sub(3).ok_or("model volume 0")?),
    };
    VolumeId::new(&name).ok_or_else(|| format!("model volume {v}"))
}

fn number_of(volume: VolumeId) -> Result<u64, String> {
    let name = volume.as_str();
    let parsed = match (name.strip_prefix("vol-0a"), name.strip_prefix("vol-0c")) {
        (Some(n), _) => n.parse::<u64>().ok().filter(|n| matches!(n, 1 | 2)),
        (_, Some(n)) => n.parse::<u64>().ok().and_then(|n| n.checked_add(3)),
        _ => None,
    };
    parsed
        .filter(|&v| volume_of(v) == Ok(volume))
        .ok_or_else(|| format!("volume {name} lies outside the instance"))
}

fn request_of(s: u64) -> Result<Request, String> {
    Ok(Request {
        namespace: NAMESPACE,
        shard: shard_of(s)?,
        generation: ShardGeneration::new(2).ok_or("generation 2")?,
    })
}

fn first(s: u64) -> Result<ShardRecord, String> {
    Ok(ShardRecord {
        shard: shard_of(s)?,
        generation: ShardGeneration::new(1).ok_or("generation 1")?,
        active: volume_of(s)?,
        owner: host(s),
        attempts: 0,
        spare: None,
        standby: None,
        ..record()
    })
}

fn token_of(s: u64, attempt: u64) -> Result<String, String> {
    let receipt = Receipt {
        request: request_of(s)?,
        layout: layout(),
        attempt: u32::try_from(attempt).map_err(|_| format!("model attempt {attempt}"))?,
        phase: Phase::Issued,
        held: false,
        released: false,
    };
    Ok(receipt.token())
}

type Held = (bool, u64, String, u64, bool, bool, u64);

#[derive(Debug, PartialEq, Eq)]
struct Seen {
    shards: Vec<(u64, u64, u64, u64)>,
    receipts: Vec<Held>,
    volumes: Vec<(u64, u64, u64)>,
    provider: Vec<((u64, u64), String, u64)>,
    calls: BTreeSet<(u64, u64)>,
}

fn modeled(st: &Value) -> Result<Seen, String> {
    let mut shards = Vec::new();
    let mut receipts = Vec::new();
    for s in SHARDS {
        let r = at(&st["shards"], s, "shard")?;
        shards.push((
            num(&r["g"], "g")?,
            num(&r["active"], "active")?,
            num(&r["spare"], "spare")?,
            num(&r["ver"], "shard version")?,
        ));
        let c = at(&st["rcpts"], s, "receipt")?;
        receipts.push((
            flag(&c["exists"], "receipt")?,
            num(&c["attempt"], "attempt")?,
            text(&c["phase"], "phase")?.to_owned(),
            num(&c["vol"], "receipt volume")?,
            flag(&c["held"], "held")?,
            flag(&c["released"], "released")?,
            num(&c["ver"], "receipt version")?,
        ));
    }
    let mut volumes = Vec::new();
    for v in keys(&st["vrecs"], "volumes")? {
        let r = at(&st["vrecs"], v, "volume")?;
        volumes.push((
            v,
            num(&r["state"], "volume state")?,
            num(&r["ver"], "volume version")?,
        ));
    }
    let mut provider = Vec::new();
    for row in rows(&st["prov"], "provider")? {
        let kind = text(&row[1]["kind"], "outcome")?.to_owned();
        provider.push((
            token_key(&row[0], "token")?,
            kind,
            num(&row[1]["vol"], "outcome volume")?,
        ));
    }
    provider.sort();
    let calls = st["calls"]["#set"]
        .as_array()
        .ok_or("model calls")?
        .iter()
        .map(|call| Ok((num(&call["shard"], "call")?, num(&call["attempt"], "call")?)))
        .collect::<Result<_, String>>()?;
    Ok(Seen {
        shards,
        receipts,
        volumes,
        provider,
        calls,
    })
}

const NO_RECEIPT: Held = (false, 0, String::new(), 0, false, false, 0);

fn outcome<T>(result: Result<T, ReconcileError>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(ReconcileError::Conflict) => "conflict".into(),
        Err(ReconcileError::Stale) => "stale".into(),
        Err(ReconcileError::Held) => "held".into(),
        Err(ReconcileError::Named) => "named".into(),
        Err(ReconcileError::Create(CreateError::Unknown)) => "unknown".into(),
        Err(ReconcileError::Create(CreateError::Failed)) => "failed".into(),
        Err(ReconcileError::Store(error)) => store_outcome(error),
        Err(error) => format!("{error:?}"),
    }
}

fn store_outcome(error: StoreError) -> String {
    match error {
        StoreError::Refused(Refusal::Condition) => "condition".into(),
        StoreError::Unknown => "unknown".into(),
        StoreError::Absent => "absent".into(),
        StoreError::Flip(_) => "noSpare".into(),
        error => format!("{error:?}"),
    }
}

/// `agrees` checks whether `result` of operation `name` matches `modeled` at `pc`, given whether the receipt write
/// committed (`wrote`).
fn agrees(name: &str, result: &str, wrote: bool, pc: &str, modeled: &str) -> bool {
    let named: &[&str] = match (name, result, wrote) {
        (_, "condition", _) => &["condition"],
        (_, "unknown", _) => &["unknown"],
        ("replacement", "none", false) => &["outside", "retain"],
        ("replacement", "ok", true) => &["start", "held"],
        ("replacement", "ok", false) => &["returned"],
        ("create", "ok", _) => &["created", "record"],
        ("create", "ok attach conflict", _) => &["created"],
        ("create", "held", _) => &["held"],
        ("create", "absent", false) => &["absent"],
        ("create", "stale", _) => &["stale"],
        ("create", "failed", _) => &["raise"],
        ("create", "conflict", _) => &["conflict"],
        ("release", "absent", false) => &["absent"],
        ("release", "ok", true) => &["release"],
        ("release", "ok", false) => &["unheld"],
        ("abandon", "nothing", false) => &["nothing"],
        ("abandon", "named", false) => &["named"],
        ("abandon", "held", false) => &["held"],
        ("abandon", "stale", false) => &["stale"],
        ("abandon", "ok", true) => &["raise"],
        ("abandon", "ok", false) => &["replayed"],
        ("flip", "stale", _) if pc == "shard" => &["past"],
        ("flip", "past", _) if pc == "reread" => &["past"],
        ("flip", "attach conflict", _) if pc == "volume" => &["conflict"],
        ("flip", "attach conflict", _) if pc == "shard" => &["past"],
        ("flip", "conflict" | "noSpare", _) => &["conflict"],
        ("flip", "held", _) => &["held"],
        ("flip", "flip", _) => &["flip"],
        _ => &[],
    };
    named.contains(&modeled)
}

fn open<S: Store>(store: S) -> Client<S, MemLog> {
    Client::open(store, MemLog::default()).unwrap()
}

struct Running {
    op: Op,
    name: String,
    shard: u64,
    /// `wrote` says whether a receipt write of this operation committed.
    wrote: bool,
    /// `early` is true when a flip ended at the caller's `record_attach`.
    early: bool,
    /// `skipped` counts the model's shard read and volume read of an early flip that have passed, in that order.
    skipped: usize,
}

impl Running {
    fn names(&self, op: &str, s: u64) -> Result<(), String> {
        if (op, s) == (self.name.as_str(), self.shard) {
            return Ok(());
        }
        Err(format!(
            "the event names {op}({s}), the process runs {}({})",
            self.name, self.shard
        ))
    }

    fn ended(&self) -> Option<String> {
        match self.op.pending() {
            Message::Done(result) => Some(result.clone()),
            _ => None,
        }
    }
}

struct Replay {
    store: Shared,
    driver: Driver,
    provider: Provisioner,
    /// `tokens` maps each token the provider was called under to the model's `(shard, attempt)`.
    tokens: BTreeMap<String, (u64, u64)>,
    procs: [Option<Running>; 3],
    /// `settled` counts `retire`'s settling writes committed on each shard record.
    settled: BTreeMap<u64, u64>,
    /// `requests` logs each request the replay answered, or found parked at a crash or the end of the trace, with
    /// its state.
    requests: Vec<(usize, &'static str, Key)>,
    /// `evidence` logs the state, shard and health of each `replacement` evidence the replay passed.
    evidence: Vec<(usize, u64, Health)>,
    at: usize,
}

impl Replay {
    fn current<R: Record>(&self, key: Key) -> Result<Option<R>, String> {
        let Some(item) = self.store.0.borrow().current(&key).cloned() else {
            return Ok(None);
        };
        R::decode(&item.value)
            .map(Some)
            .map_err(|error| format!("{key:?} fails to decode: {error:?}"))
    }

    fn commits(&self, key: Key) -> u64 {
        commits(&self.store, key) as u64
    }

    fn put(&self, key: Key, value: Vec<u8>) -> Result<(), String> {
        match self.store.clone().write(&key, &Write::Create(value)) {
            Outcome::Committed(_) => Ok(()),
            outcome => Err(format!("the driver's write of {key:?}: {outcome:?}")),
        }
    }

    fn seed(&self) -> Result<(), String> {
        for s in SHARDS {
            self.put(Key::Shard(shard_of(s)?), first(s)?.encode())?;
            let held = VolumeRecord {
                volume: volume_of(s)?,
                state: VolumeState::Active,
                source: CreationSource::Provisioned,
                lineage: Lineage::None,
                modification: None,
                layout: layout(),
                next: 0,
                forced: false,
                fence: 0,
                pairs: Vec::new(),
                events: Vec::new(),
            };
            self.put(Key::Volume(held.volume), held.encode())?;
        }
        Ok(())
    }

    fn seen(&self) -> Result<Seen, String> {
        let mut shards = Vec::new();
        let mut receipts = Vec::new();
        for s in SHARDS {
            let key = Key::Shard(shard_of(s)?);
            let r: ShardRecord = self
                .current(key)?
                .ok_or_else(|| format!("shard record {s}"))?;
            let spare = match r.spare {
                None => 0,
                Some((volume, holder)) if holder == host(s) => number_of(volume)?,
                Some((volume, holder)) => {
                    return Err(format!("shard {s} names {volume:?} spare on {holder:?}"));
                }
            };
            let version = self
                .commits(key)
                .checked_sub(self.settled.get(&s).copied().unwrap_or(0))
                .ok_or("shard version")?;
            shards.push((r.generation.get(), number_of(r.active)?, spare, version));
            let key = Key::Replacement(shard_of(s)?);
            let held = match self.current::<Receipt>(key)? {
                None => NO_RECEIPT,
                Some(c) if c.request != request_of(s)? || c.layout != layout() => {
                    return Err(format!("receipt {s} names {:?}", c.request));
                }
                Some(c) => {
                    let (phase, vol) = match c.phase {
                        Phase::Open => ("open", 0),
                        Phase::Issued => ("issued", 0),
                        Phase::Created(volume) => ("created", number_of(volume)?),
                    };
                    (
                        true,
                        c.attempt.into(),
                        phase.into(),
                        vol,
                        c.held,
                        c.released,
                        self.commits(key),
                    )
                }
            };
            receipts.push(held);
        }
        let mut known: BTreeSet<u64> = BTreeSet::from(SHARDS);
        for (_, volume) in &self.provider.created {
            known.insert(number_of(*volume)?);
        }
        let mut volumes = Vec::new();
        for v in known {
            let key = Key::Volume(volume_of(v)?);
            let held = match self.current::<VolumeRecord>(key)? {
                None => (v, 0, 0),
                Some(r) => {
                    let state = match r.state {
                        VolumeState::Provisioning | VolumeState::Fresh => 1,
                        VolumeState::Active => 2,
                        VolumeState::Retired => 3,
                        state => return Err(format!("volume {v} state {state:?}")),
                    };
                    let version = self
                        .commits(key)
                        .checked_sub(u64::from(!r.events.is_empty()))
                        .ok_or("volume version")?;
                    (v, state, version)
                }
            };
            volumes.push(held);
        }
        let token = |t: &str| {
            self.tokens
                .get(t)
                .copied()
                .ok_or_else(|| format!("the provider holds the unknown token {t}"))
        };
        let mut provider = Vec::new();
        for (t, volume) in &self.provider.created {
            provider.push((token(t)?, "volume".into(), number_of(*volume)?));
        }
        for t in &self.provider.failed {
            provider.push((token(t)?, "failed".into(), 0));
        }
        provider.sort();
        let calls = self
            .provider
            .layouts
            .iter()
            .map(|(t, _)| token(t))
            .collect::<Result<_, _>>()?;
        Ok(Seen {
            shards,
            receipts,
            volumes,
            provider,
            calls,
        })
    }

    fn begin(&mut self, name: &str, s: u64, proc: &Value, st: &Value) -> Result<Running, String> {
        let shard = shard_of(s)?;
        let lost = members(&proc["lost"], "lost")?;
        let others = usize::try_from(num(&proc["others"], "others")?).map_err(|_| "others")?;
        let vol = num(&proc["vol"], "vol")?;
        let gate = StandbyGate::qualified;
        let op = match name {
            "replacement" => {
                let health = match text(&at(&st["vols"], s, "vols")?["health"], "health")? {
                    "available" => Health::Available,
                    "impaired" => Health::Impaired,
                    "lost" => Health::Lost,
                    health => return Err(format!("model health {health}")),
                };
                if (health == Health::Lost) != lost.contains(&s) {
                    return Err(format!(
                        "volume {s} is {health:?} and the lost volumes are {lost:?}"
                    ));
                }
                self.evidence.push((self.at, s, health));
                let evidence = (volume_of(s)?, health);
                let asked = match self.driver {
                    Driver::OtherLayout => Layout {
                        units: layout().units * 2,
                        ..layout()
                    },
                    _ => layout(),
                };
                Op::start(move |proxy| {
                    match Reconciler::new(open(proxy)).replacement(
                        &gate(),
                        shard,
                        evidence,
                        others,
                        asked,
                    ) {
                        Ok(None) => "none".into(),
                        replaced => outcome(replaced),
                    }
                })
            }
            "create" => {
                let shard = if self.driver == Driver::OtherShard {
                    shard_of(3u64.checked_sub(s).ok_or("shard")?)?
                } else {
                    shard
                };
                let owner = host(s);
                let reads = self.driver == Driver::AttachReadsOnly;
                Op::start(move |proxy| {
                    let mut provider = proxy.clone();
                    let mut reconciler = Reconciler::new(open(proxy));
                    match reconciler.create_replacement(&gate(), shard, others, &mut provider) {
                        Ok(created) if reads => {
                            let volume = Key::Volume(created.value().volume);
                            match reconciler.read::<VolumeRecord>(volume) {
                                Ok(_) => "ok".into(),
                                Err(error) => store_outcome(error),
                            }
                        }
                        Ok(created) => {
                            match reconciler.record_attach(created.value().volume, owner, ERA) {
                                Ok(_) => "ok".into(),
                                refused => format!("ok attach {}", outcome(refused)),
                            }
                        }
                        refused => outcome(refused),
                    }
                })
            }
            "release" => {
                let request = request_of(s)?;
                Op::start(move |proxy| {
                    outcome(
                        Reconciler::new(open(proxy))
                            .release_hold(&OperatorRelease::diagnosed(), request),
                    )
                })
            }
            "abandon" => {
                let lost = lost
                    .iter()
                    .map(|&v| volume_of(v))
                    .collect::<Result<Vec<_>, _>>()?;
                Op::start(move |proxy| {
                    let mut reconciler = Reconciler::new(open(proxy));
                    let observed = match reconciler.read::<Receipt>(Key::Replacement(shard)) {
                        Ok(read) => read.value().clone(),
                        Err(StoreError::Absent) => return "nothing".into(),
                        Err(error) => return store_outcome(error),
                    };
                    let volume = match observed.phase {
                        Phase::Created(volume) if !observed.held && lost.contains(&volume) => {
                            volume
                        }
                        _ => return "nothing".into(),
                    };
                    let retired = match reconciler.retire(shard, volume) {
                        Ok(retired) => retired,
                        refused => return outcome(refused),
                    };
                    outcome(reconciler.abandon(&gate(), shard, &observed, &retired, others))
                })
            }
            "flip" => {
                let volume = volume_of(vol)?;
                let target = Target::of(&first(s)?);
                let owner = host(if self.driver == Driver::ForeignAttach {
                    3u64.checked_sub(s).ok_or("shard")?
                } else {
                    s
                });
                let past = if self.driver == Driver::PastAsStale {
                    "stale"
                } else {
                    "past"
                };
                Op::start(move |proxy| {
                    let mut reconciler = Reconciler::new(open(proxy));
                    let attached = match reconciler.record_attach(volume, owner, ERA) {
                        Ok(attached) => attached,
                        refused => return format!("attach {}", outcome(refused)),
                    };
                    if let Err(refused) = reconciler.add_spare(shard, target, &attached) {
                        return outcome::<()>(Err(refused));
                    }
                    match reconciler.flip(&gate(), shard, target) {
                        Ok(Flip::Flipped(_)) => "flip".into(),
                        Ok(Flip::Past) => past.into(),
                        flipped => outcome(flipped),
                    }
                })
            }
            name => return Err(format!("unknown operation {name}")),
        }?;
        let mut run = Running {
            op,
            name: name.into(),
            shard: s,
            wrote: false,
            early: false,
            skipped: 0,
        };
        if name == "flip" {
            self.attach(&mut run, vol)?;
            run.early = run.ended().is_some();
        }
        Ok(run)
    }

    fn serve(&mut self, run: &mut Running, key: Key, arm: Option<Arm>) -> Result<(), String> {
        let mut inner = AsReconciler(self.store.clone());
        let reply = match arm {
            None => {
                run.op.read_of(&key)?;
                self.requests.push((self.at, "read", key));
                Reply::Read(inner.read(&key))
            }
            Some(arm) => {
                let write = run.op.write_of(&key)?.clone();
                self.requests.push((self.at, "write", key));
                let before = self.commits(key);
                self.store.schedule(arm);
                let outcome = inner.write(&key, &write);
                if matches!(key, Key::Replacement(_)) && self.commits(key) > before {
                    run.wrote = true;
                }
                Reply::Write(outcome)
            }
        };
        run.op.answer(reply)
    }

    /// `attach` serves the caller's `record_attach` read of volume `v`, and its attach write when the stored record
    /// is `Provisioning` with no events. A create may end there with `ok`, or with `ok attach conflict` over a
    /// `Retired` record; a flip may end there with `attach conflict` over a `Retired` record.
    fn attach(&mut self, run: &mut Running, v: u64) -> Result<(), String> {
        let key = Key::Volume(volume_of(v)?);
        let due = self.current::<VolumeRecord>(key)?.is_some_and(|record| {
            record.state == VolumeState::Provisioning && record.events.is_empty()
        });
        self.serve(run, key, None)?;
        if due {
            self.serve(run, key, Some(Arm::Pass))?;
        }
        let Some(result) = run.ended() else {
            return Ok(());
        };
        let refusal = match run.name.as_str() {
            "flip" => "attach conflict",
            _ if result == "ok" => return Ok(()),
            _ => "ok attach conflict",
        };
        match self.current::<VolumeRecord>(key)? {
            Some(record) if result == refusal && record.state == VolumeState::Retired => Ok(()),
            held => Err(format!("the {} ended {result} over {held:?}", run.name)),
        }
    }

    /// Requires the pending message of a process the model stops at `pc` to be the request the model names there.
    fn pending(&mut self, run: &Running, proc: &Value, pc: &str) -> Result<(), String> {
        if run.early {
            if ["shard", "volume"].get(run.skipped) == Some(&pc) {
                return Ok(());
            }
            return Err(format!(
                "the operation ended {}",
                run.ended().unwrap_or_default()
            ));
        }
        if pc == "call" {
            parked_call(run, proc)?;
            self.requests.push((
                self.at,
                "dropped call",
                Key::Replacement(shard_of(run.shard)?),
            ));
            return Ok(());
        }
        let (write, key) = expected(run, proc, pc)?;
        if write {
            run.op.write_of(&key)?;
        } else {
            run.op.read_of(&key)?;
        }
        let dropped = if write {
            "dropped write"
        } else {
            "dropped read"
        };
        self.requests.push((self.at, dropped, key));
        Ok(())
    }

    fn settle_write(&mut self, run: &mut Running) -> Result<(), String> {
        let s = run.shard;
        let key = Key::Shard(shard_of(s)?);
        let before = self.commits(key);
        self.serve(run, key, Some(Arm::Pass))?;
        if self.commits(key) > before {
            *self.settled.entry(s).or_default() += 1;
        }
        Ok(())
    }

    fn step(
        &mut self,
        run: &mut Running,
        proc: &Value,
        st: &Value,
        act: &str,
        pc: &str,
        res: &str,
    ) -> Result<(), String> {
        let arm = match act {
            "read" => None,
            "write" => Some(Arm::Pass),
            _ => Some(Arm::Timeout { commit: true }),
        };
        if run.early {
            if arm.is_none() && ["shard", "volume"].get(run.skipped) == Some(&pc) {
                run.skipped += 1;
                return Ok(());
            }
            return Err(format!(
                "the operation ended {}",
                run.ended().unwrap_or_default()
            ));
        }
        let s = run.shard;
        let vol = num(&proc["vol"], "vol")?;
        let shard = Key::Shard(shard_of(s)?);
        let (write, key) = expected(run, proc, pc)?;
        if write == arm.is_none() {
            return Err(format!("the model's {act} at {pc}"));
        }
        self.serve(run, key, arm)?;
        match (run.name.as_str(), pc, res) {
            ("flip", "recheck", _) => self.serve(run, Key::Replacement(shard_of(s)?), None)?,
            ("create", "shard", "created") => {
                let created = num(&proc["rc"]["vol"], "receipt volume")?;
                self.serve(run, Key::Volume(volume_of(created)?), None)?;
                self.attach(run, created)?;
            }
            ("create", "record", "record") => {
                self.serve(run, shard, None)?;
                self.attach(run, vol)?;
            }
            ("create", "reread", "created") => {
                self.serve(run, Key::Volume(volume_of(vol)?), None)?;
                self.serve(run, shard, None)?;
                self.attach(run, vol)?;
            }
            ("abandon", "volume", _)
                if num(&at(&st["vrecs"], vol, "volume")?["state"], "state")? == 3 =>
            {
                self.serve(run, shard, None)?;
                self.settle_write(run)?;
            }
            ("abandon", "retire", "ok") if act == "write" => self.settle_write(run)?,
            _ => {}
        }
        Ok(())
    }

    /// `settle` compares the operation of process `p` with the model's step. A step that `ends` the operation needs
    /// an ended operation whose result names `res`. A step that leaves it running needs `res` in `open` and a
    /// running operation, or one that ended as an early flip.
    fn settle(
        &mut self,
        p: usize,
        res: &str,
        pc: &str,
        ends: bool,
        open: &[&str],
    ) -> Result<(), String> {
        let run = self.procs[p]
            .as_ref()
            .ok_or("the process runs no operation")?;
        let continues = || {
            if open.contains(&res) {
                Ok(())
            } else {
                Err(format!("the step continues with result {res}"))
            }
        };
        match (run.ended(), ends) {
            (None, false) => continues(),
            (Some(_), false) if run.early => continues(),
            (Some(result), false) => Err(format!("the operation ended {result}")),
            (None, true) => Err(format!("the operation continues, modeled {res}")),
            (Some(result), true) if !agrees(&run.name, &result, run.wrote, pc, res) => {
                Err(format!("result {result}, modeled {res}"))
            }
            (Some(_), true) => {
                let run = self.procs[p].take().expect("the run");
                run.op.finish()
            }
        }
    }

    fn call(
        &mut self,
        run: &mut Running,
        proc: &Value,
        pre: &Value,
        post: &Value,
        reply: bool,
    ) -> Result<String, String> {
        let s = run.shard;
        let (token, attempt) = parked_call(run, proc)?;
        match self.tokens.insert(token.clone(), (s, attempt)) {
            Some(bound) if bound != (s, attempt) => {
                return Err(format!(
                    "the token {token} stands for {bound:?} and for ({s}, {attempt})"
                ));
            }
            _ => {}
        }
        let kept = |st: &Value| -> Result<Option<String>, String> {
            for row in rows(&st["prov"], "provider")? {
                if token_key(&row[0], "token")? == (s, attempt) {
                    return Ok(Some(text(&row[1]["kind"], "outcome")?.to_owned()));
                }
            }
            Ok(None)
        };
        let known = kept(pre)?.is_some();
        let decided = kept(post)?;
        if known && self.driver == Driver::ForgetfulProvider {
            for (kept, _) in &mut self.provider.created {
                if *kept == token {
                    kept.push_str("-forgotten");
                    self.tokens.insert(kept.clone(), (s, attempt));
                }
            }
        }
        match decided.as_deref() {
            _ if known => {}
            Some("failed") => self.provider.failed.push(token.clone()),
            Some(_) => {}
            None => self.provider.unsent = 1,
        }
        if !reply && decided.is_some() {
            self.provider.lose = 1;
        }
        let created = self.provider.create(&token, layout());
        if (self.provider.unsent, self.provider.lose) != (0, 0) {
            return Err("the provider left a scripted answer unused".into());
        }
        self.requests
            .push((self.at, "call", Key::Replacement(shard_of(s)?)));
        run.op.answer(Reply::Call(created))?;
        Ok(format!(
            "{} {}{}",
            if known { "kept" } else { "new" },
            decided.as_deref().unwrap_or("dropped"),
            if reply || decided.is_none() {
                ""
            } else {
                " unknown"
            }
        ))
    }
}

fn parked_call(run: &Running, proc: &Value) -> Result<(String, u64), String> {
    let attempt = num(&proc["rc"]["attempt"], "attempt")?;
    let (token, asked) = run.op.call()?;
    if token != token_of(run.shard, attempt)? {
        return Err(format!(
            "the operation calls under {token}, modeled attempt {attempt}"
        ));
    }
    if asked != layout() {
        return Err(format!("the operation calls with {asked:?}"));
    }
    Ok((token.to_owned(), attempt))
}

fn expected(run: &Running, proc: &Value, pc: &str) -> Result<(bool, Key), String> {
    let s = run.shard;
    let vol = num(&proc["vol"], "vol")?;
    let shard = Key::Shard(shard_of(s)?);
    let receipt = Key::Replacement(shard_of(s)?);
    Ok(match (run.name.as_str(), pc) {
        ("replacement" | "flip", "shard") | ("flip", "reread") => (false, shard),
        ("abandon", "named" | "due") | ("create", "shard") => (false, shard),
        ("flip", "spare" | "flip") => (true, shard),
        ("replacement" | "create" | "release", "receipt") => (false, receipt),
        ("create", "reread") | ("abandon", "observe" | "current") => (false, receipt),
        ("flip", "receipt") => (false, receipt),
        ("flip", "recheck") => (false, Key::Volume(volume_of(s)?)),
        ("replacement", "start" | "latch") | ("create", "hold" | "issue" | "record" | "raise") => {
            (true, receipt)
        }
        ("release", "release") | ("abandon", "raise") => (true, receipt),
        ("create", "provRead") | ("abandon", "volume") | ("flip", "volume" | "unused") => {
            (false, Key::Volume(volume_of(vol)?))
        }
        ("create", "provision") | ("abandon", "retire") | ("flip", "fence") => {
            (true, Key::Volume(volume_of(vol)?))
        }
        (name, pc) => return Err(format!("no request of {name} at {pc}")),
    })
}

fn leaf(act: &str, taken: &str) -> Option<&'static str> {
    Some(match (act, taken) {
        ("init", "init") => "init",
        ("begin", "begin" | "starts") => "begin",
        ("read" | "write", "request" | "requests") => "request",
        ("unknown", "unknown" | "requests") => "unknown",
        ("crash", "crash" | "requests") => "crash",
        ("call", "call" | "calls") => "call",
        ("lose", "lose" | "health") => "lose",
        ("impair", "impair" | "health") => "impair",
        ("recover", "recover" | "health") => "recover",
        ("hostLoss", "hostLoss" | "hosts") => "hostLoss",
        _ => return None,
    })
}

struct Replayed {
    reached: Vec<(&'static str, String, String, String, String)>,
    requests: Vec<(usize, &'static str, Key)>,
    evidence: Vec<(usize, u64, Health)>,
    created: Vec<(String, VolumeId)>,
}

fn process(st: &Value, p: usize) -> Result<&Value, String> {
    at(&st["procs"], p as u64, "procs")
}

fn replay(json: &str, driver: Driver) -> Result<Replayed, String> {
    let (states, _) = states(json, MODEL, "loss")?;
    let mut replay = Replay {
        store: Shared::new(),
        driver,
        provider: Provisioner::default(),
        tokens: BTreeMap::new(),
        procs: Default::default(),
        settled: BTreeMap::new(),
        requests: Vec::new(),
        evidence: Vec::new(),
        at: 0,
    };
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        replay.at = i;
        let st = &state[ST];
        let ev = &st["ev"];
        let field = |key: &str| ev[key].as_str().ok_or_else(|| format!("event {key}"));
        let (act, op, pc, res) = (field("act")?, field("op")?, field("pc")?, field("res")?);
        let fail = |what: String| format!("{act} at {i}: {what}");
        let taken = state["mbt::actionTaken"].as_str().unwrap_or_default();
        let leaf = leaf(act, taken)
            .ok_or_else(|| format!("action {i}: unknown action {act} ({taken})"))?;
        let p = usize::try_from(num(&ev["proc"], "proc").map_err(fail)?)
            .map_err(|_| fail("proc".into()))?;
        let s = num(&ev["shard"], "shard").map_err(fail)?;
        let pre = &states[i.saturating_sub(1)][ST];
        let ends = || -> Result<bool, String> { Ok(text(&process(st, p)?["op"], "op")? == "idle") };
        let stands = || -> Result<(), String> {
            let stood = text(&process(pre, p)?["pc"], "pc")?;
            if stood == pc {
                Ok(())
            } else {
                Err(format!("the step at {pc}, the process stands at {stood}"))
            }
        };
        let mut answer = res.to_owned();
        match leaf {
            "init" if i == 0 => replay.seed().map_err(fail)?,
            "begin" => {
                if p > 2 || replay.procs[p].is_some() {
                    return Err(fail("the process already runs an operation".into()));
                }
                let run = replay
                    .begin(op, s, process(st, p).map_err(fail)?, st)
                    .map_err(fail)?;
                replay.procs[p] = Some(run);
                replay.settle(p, res, pc, false, &[""]).map_err(fail)?;
            }
            "request" | "unknown" => {
                let mut run = replay
                    .procs
                    .get_mut(p)
                    .and_then(Option::take)
                    .ok_or_else(|| fail("the process runs no operation".into()))?;
                let stepped = run
                    .names(op, s)
                    .and_then(|()| replay.step(&mut run, process(pre, p)?, pre, act, pc, res));
                replay.procs[p] = Some(run);
                stepped.map_err(fail)?;
                stands().map_err(fail)?;
                replay
                    .settle(p, res, pc, ends().map_err(fail)?, &["", "ok"])
                    .map_err(fail)?;
            }
            "crash" => {
                let run = replay
                    .procs
                    .get_mut(p)
                    .and_then(Option::take)
                    .ok_or_else(|| fail("the process runs no operation".into()))?;
                let before = process(pre, p).map_err(fail)?;
                run.names(op, s).map_err(fail)?;
                let stood = text(&before["pc"], "pc").map_err(fail)?;
                if (res, stood, ends().map_err(fail)?) != ("crash", pc, true) {
                    return Err(fail(format!(
                        "the crash at {pc} ends {res}, the process stands at {stood}"
                    )));
                }
                replay.pending(&run, before, pc).map_err(fail)?;
            }
            "call" => {
                let mut run = replay
                    .procs
                    .get_mut(p)
                    .and_then(Option::take)
                    .ok_or_else(|| fail("the process runs no operation".into()))?;
                let called = run.names(op, s).and_then(|()| {
                    replay.call(&mut run, process(pre, p)?, pre, st, res != "unknown")
                });
                replay.procs[p] = Some(run);
                answer = called.map_err(fail)?;
                stands().map_err(fail)?;
                if flag(&ev["kept"], "kept").map_err(fail)? != answer.starts_with("kept") {
                    return Err(fail(format!("the provider's answer is {answer}")));
                }
                let kind = answer.rsplit(' ').next().unwrap_or_default();
                replay
                    .settle(p, res, pc, ends().map_err(fail)?, &[kind])
                    .map_err(fail)?;
            }
            "lose" | "impair" | "recover" | "hostLoss" => {}
            leaf => return Err(fail(format!("{leaf} has no step here"))),
        }
        let seen = replay.seen().map_err(fail)?;
        let model = modeled(st).map_err(fail)?;
        if seen != model {
            return Err(fail(format!("stored {seen:?}, modeled {model:?}")));
        }
        reached.push((leaf, act.to_owned(), op.to_owned(), pc.to_owned(), answer));
    }
    let last = &states.last().ok_or("fixture states")?[ST];
    for p in 0..3 {
        if let Some(run) = replay.procs[p].take() {
            let proc = process(last, p)?;
            run.names(text(&proc["op"], "op")?, num(&proc["shard"], "shard")?)
                .and_then(|()| replay.pending(&run, proc, text(&proc["pc"], "pc")?))
                .map_err(|error| format!("end of trace: {error}"))?;
        }
    }
    Ok(Replayed {
        reached,
        requests: replay.requests,
        evidence: replay.evidence,
        created: replay.provider.created,
    })
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap()
        .1
}

/// Every committed trace replays. Together the traces reach `init`, every choice of the model's `step`, every
/// event `act`, the results `RESULTS` names, the requests `REQUESTS` names and nine provider answers, and the
/// directed traces alone, those whose name does not start with `step_`, reach the same, so the coverage holds
/// whatever the seeded traces draw.
#[test]
fn committed_loss_traces_replay_and_reach_every_step_choice() {
    let mut reached = BTreeSet::new();
    let mut directed = BTreeSet::new();
    let mut failures = Vec::new();
    for (name, json) in FIXTURES {
        match replay(json, Driver::Faithful) {
            Ok(replayed) => {
                if !name.starts_with("step_") {
                    directed.extend(replayed.reached.iter().cloned());
                }
                reached.extend(replayed.reached);
            }
            Err(error) => failures.push(format!("{name}: {error}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(
        directed, reached,
        "the seeded traces reach a step the directed traces do not"
    );
    let model = std::str::from_utf8(MODEL).unwrap();
    for choice in [
        "    begin(p, op, shard)\n",
        "    any {request(p), unknown(p), crash(p)}\n",
        "    call(p, result, reply)\n",
        "    any {lose(v), impair(v), recover(v)}\n",
        "    hostLoss(h)\n",
        "  action step = any {starts, requests, calls, health, hosts}\n",
    ] {
        assert!(
            model.contains(choice),
            "the model's step chooses among other actions than the replay drives: {choice}"
        );
    }
    let acts: BTreeSet<(&str, &str)> = reached
        .iter()
        .map(|(leaf, act, ..)| (act.as_str(), *leaf))
        .collect();
    assert_eq!(
        acts,
        BTreeSet::from([
            ("begin", "begin"),
            ("call", "call"),
            ("crash", "crash"),
            ("hostLoss", "hostLoss"),
            ("impair", "impair"),
            ("init", "init"),
            ("lose", "lose"),
            ("read", "request"),
            ("recover", "recover"),
            ("unknown", "unknown"),
            ("write", "request"),
        ])
    );
    let results: BTreeSet<(&str, &str, &str)> = reached
        .iter()
        .filter(|(leaf, _, op, _, res)| {
            *leaf != "call" && !op.is_empty() && !["", "ok"].contains(&res.as_str())
        })
        .map(|(_, _, op, pc, res)| (op.as_str(), pc.as_str(), res.as_str()))
        .collect();
    assert_eq!(results, BTreeSet::from(RESULTS));
    let requests: BTreeSet<(&str, &str, &str)> = reached
        .iter()
        .filter(|(leaf, ..)| matches!(*leaf, "request" | "unknown"))
        .map(|(_, act, op, pc, _)| (op.as_str(), pc.as_str(), act.as_str()))
        .collect();
    assert_eq!(requests, BTreeSet::from(REQUESTS));
    let answers: BTreeSet<&str> = reached
        .iter()
        .filter(|(leaf, ..)| *leaf == "call")
        .map(|(.., res)| res.as_str())
        .collect();
    assert_eq!(
        answers,
        BTreeSet::from([
            "kept failed",
            "kept failed unknown",
            "kept volume",
            "kept volume unknown",
            "new dropped",
            "new failed",
            "new failed unknown",
            "new volume",
            "new volume unknown",
        ])
    );
}

#[test]
fn each_loss_request_falls_on_its_model_step_and_the_unmodeled_requests_on_theirs() {
    let (shard, receipt) = (
        Key::Shard(shard_of(1).unwrap()),
        Key::Replacement(shard_of(1).unwrap()),
    );
    let volume = |v| Key::Volume(volume_of(v).unwrap());
    let requests: Vec<_> = replay(fixture("run_retirement"), Driver::Faithful)
        .unwrap()
        .requests
        .into_iter()
        .filter(|&(at, ..)| [12, 18, 35, 36, 42, 43, 44].contains(&at))
        .collect();
    assert_eq!(
        requests,
        [
            (12, "write", receipt),
            (12, "read", shard),
            (12, "read", volume(3)),
            (12, "write", volume(3)),
            (18, "write", volume(3)),
            (18, "write", shard),
            (35, "read", volume(4)),
            (36, "read", shard),
            (42, "write", volume(4)),
            (43, "read", volume(1)),
            (43, "read", receipt),
            (44, "write", shard),
        ]
    );
    // replay_flipOfRetired: the flip of the retired volume 3 begins at state 19 with its attach read, which the
    // record refuses, and the model's shard and volume reads of it at states 20 and 21 make no request.
    let flip: Vec<_> = replay(fixture("replay_flipOfRetired"), Driver::Faithful)
        .unwrap()
        .requests
        .into_iter()
        .filter(|&(at, ..)| (19..=21).contains(&at))
        .collect();
    assert_eq!(flip, [(19, "read", volume(3))]);
    // replay_retiredFlipPast: the same refused flip of volume 3 begins at state 19, and its model shard read at
    // state 40, after the other reconciler flipped the shard to generation 2, ends it past with no request.
    let past: Vec<_> = replay(fixture("replay_retiredFlipPast"), Driver::Faithful)
        .unwrap()
        .requests
        .into_iter()
        .filter(|&(at, ..)| at == 19 || at == 40)
        .collect();
    assert_eq!(past, [(19, "read", volume(3))]);
    // replay_spareOfRetired: the flip read the shard at state 14, and add_spare's volume read at state 21 finds
    // volume 3 retired.
    let spare: Vec<_> = replay(fixture("replay_spareOfRetired"), Driver::Faithful)
        .unwrap()
        .requests
        .into_iter()
        .filter(|&(at, act, _)| at == 21 && act == "read")
        .collect();
    assert_eq!(spare, [(21, "read", volume(3))]);
}

/// replay_impairedRetained: the replacement that begins at state 2 over the impaired volume 1 receives `Impaired`
/// evidence, reads the shard record at state 3 and retains: it reads no receipt and writes nothing.
#[test]
fn an_impaired_volume_reaches_replacement_as_impaired_evidence_and_is_retained() {
    let replayed = replay(fixture("replay_impairedRetained"), Driver::Faithful).unwrap();
    assert_eq!(replayed.evidence, [(2, 1, Health::Impaired)]);
    assert_eq!(
        replayed.requests,
        [(3, "read", Key::Shard(shard_of(1).unwrap()))]
    );
}

#[test]
fn the_two_shards_call_the_provider_under_distinct_tokens_for_distinct_volumes() {
    let replayed = replay(fixture("replay_shardTwoCreates"), Driver::Faithful).unwrap();
    assert_ne!(token_of(1, 1).unwrap(), token_of(2, 1).unwrap());
    assert_eq!(
        replayed.created,
        [
            (token_of(1, 1).unwrap(), volume_of(3).unwrap()),
            (token_of(2, 1).unwrap(), volume_of(4).unwrap()),
        ]
    );
}

#[test]
fn a_volume_number_round_trips_and_a_padded_alias_is_refused() {
    for v in [1, 2, 3, 4, 13, 103] {
        assert_eq!(number_of(volume_of(v).unwrap()), Ok(v));
    }
    for alias in ["vol-0c00", "vol-0c01", "vol-0a01", "vol-0a3"] {
        assert!(number_of(VolumeId::new(alias).unwrap()).is_err(), "{alias}");
    }
}

#[test]
fn a_host_loss_writes_no_receipt_and_calls_no_provider() {
    for name in ["run_host_loss", "replay_hostsLost"] {
        let replayed = replay(fixture(name), Driver::Faithful).unwrap();
        let writes: Vec<_> = replayed
            .requests
            .iter()
            .filter(|(_, act, _)| !matches!(*act, "read" | "dropped read"))
            .collect();
        assert!(writes.is_empty(), "{name}: {writes:?}");
        assert!(replayed.created.is_empty(), "{name}");
    }
}

#[test]
fn a_create_after_a_crash_at_the_call_repeats_the_issued_token_and_makes_one_volume() {
    let replayed = replay(fixture("run_crash_at_call"), Driver::Faithful).unwrap();
    assert_eq!(
        replayed.created,
        [(token_of(1, 1).unwrap(), volume_of(3).unwrap())]
    );
    let receipt = Key::Replacement(shard_of(1).unwrap());
    let calls: Vec<_> = replayed
        .requests
        .iter()
        .copied()
        .filter(|(_, act, _)| matches!(*act, "call" | "dropped call"))
        .collect();
    assert_eq!(calls[0], (10, "dropped call", receipt));
    assert_eq!(calls.iter().filter(|(_, act, _)| *act == "call").count(), 1);
}

#[test]
#[ignore = "generated loss traces; the quint lane runs it with Quint on PATH"]
fn generated_loss_traces_replay() {
    let traces = ReplayScratch::run("loss", "loss_fixtures.py", &["--timeout", "0"]);
    let mut actions = 0;
    for (name, committed) in FIXTURES {
        let generated = traces.trace(name);
        assert_eq!(
            serde_json::from_str::<Value>(&generated).unwrap(),
            serde_json::from_str::<Value>(committed).unwrap(),
            "{name}: the committed trace differs from the model's"
        );
        let replayed =
            replay(&generated, Driver::Faithful).unwrap_or_else(|error| panic!("{name}: {error}"));
        actions += replayed.reached.len() - 1;
    }
    println!(
        "core replay: traces={} actions={actions} agreement=all",
        FIXTURES.len()
    );
}

#[test]
fn negative_control_a_create_given_the_other_shard_fails_the_loss_replay() {
    assert_eq!(
        replay(fixture("run_isolated_replacement"), Driver::OtherShard).err(),
        Some("read at 7: the operation reads Replacement(Shard(2))".into())
    );
}

#[test]
fn negative_control_a_provider_that_forgets_a_token_fails_the_loss_replay() {
    let error = replay(
        fixture("run_isolated_replacement"),
        Driver::ForgetfulProvider,
    )
    .err()
    .unwrap_or_default();
    assert!(error.starts_with("call at 14: stored "), "{error}");
    assert!(
        error.contains(r#"provider: [((1, 1), "volume", 3), ((1, 1), "volume", 4)]"#),
        "{error}"
    );
}

/// run_retirement: the create's record write at state 12 ends it with its volume, whose record is provisioned with
/// no attach event, so the caller's attach write must follow its read. A caller that only reads ends there.
#[test]
fn negative_control_a_caller_that_skips_the_attach_write_fails_the_loss_replay() {
    assert_eq!(
        replay(fixture("run_retirement"), Driver::AttachReadsOnly).err(),
        Some("write at 12: the operation ended ok".into())
    );
}

/// run_retirement: the start write at state 5 commits the receipt, which must carry the replay's layout.
#[test]
fn negative_control_a_replacement_asked_with_another_layout_fails_the_loss_replay() {
    let error = replay(fixture("run_retirement"), Driver::OtherLayout)
        .err()
        .unwrap_or_default();
    assert!(error.starts_with("write at 5: receipt 1 names "), "{error}");
}

#[test]
fn negative_control_a_flip_past_read_as_stale_fails_the_loss_replay() {
    assert_eq!(
        replay(fixture("replay_flipPastAtReread"), Driver::PastAsStale).err(),
        Some("read at 26: result stale, modeled past".into())
    );
}

#[test]
fn negative_control_a_flip_attached_for_another_host_fails_at_its_begin() {
    let error = replay(fixture("step_created_7900"), Driver::ForeignAttach)
        .err()
        .unwrap_or_default();
    assert!(
        error.starts_with("begin at 23: the flip ended attach conflict over Some("),
        "{error}"
    );
}

#[test]
fn negative_control_a_crash_or_trace_end_off_the_pending_request_fails() {
    let altered = |name: &str, at: Option<usize>, edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(fixture(name)).unwrap();
        let states = trace["states"].as_array_mut().unwrap();
        let at = at.unwrap_or(states.len() - 1);
        edit(&mut states[at]);
        replay(&trace.to_string(), Driver::Faithful)
            .err()
            .unwrap_or_default()
    };
    let number = |value: u64| serde_json::json!({ "#bigint": value.to_string() });
    assert_eq!(
        altered("run_crash_at_call", Some(10), &|state| {
            state[ST]["ev"]["shard"] = number(2)
        }),
        "crash at 10: the event names create(2), the process runs create(1)"
    );
    assert_eq!(
        altered("run_crash_at_call", Some(10), &|state| {
            state[ST]["ev"]["pc"] = "issue".into()
        }),
        "crash at 10: the crash at issue ends crash, the process stands at call"
    );
    assert_eq!(
        altered("step_created_7900", None, &|state| {
            state[ST]["procs"]["#map"][1][1]["pc"] = "spare".into()
        }),
        "end of trace: the operation reads Replacement(Shard(1))"
    );
}

#[test]
fn negative_control_an_altered_loss_trace_fails_at_the_altered_state() {
    let trace: Value = serde_json::from_str(fixture("run_retirement")).unwrap();
    let altered = |at: usize, edit: &dyn Fn(&mut Value)| {
        let mut trace = trace.clone();
        edit(&mut trace["states"][at]);
        replay(&trace.to_string(), Driver::Faithful)
            .err()
            .unwrap_or_default()
    };
    let seen = |at: usize, edit: &dyn Fn(&mut Value)| {
        let mut state = trace["states"][at].clone();
        edit(&mut state);
        super::replay_driver::plain(&mut state).unwrap();
        modeled(&state[ST]).unwrap()
    };
    let stored = |act: &str, at: usize, edit: &dyn Fn(&mut Value)| {
        format!(
            "{act} at {at}: stored {:?}, modeled {:?}",
            seen(at, &|_| {}),
            seen(at, edit)
        )
    };
    let number = |value: u64| serde_json::json!({ "#bigint": value.to_string() });
    type Check<'a> = (&'a str, usize, &'a dyn Fn(&mut Value));
    let checks: [Check; 6] = [
        ("write", 5, &|state| {
            state[ST]["rcpts"]["#map"][0][1]["held"] = true.into()
        }),
        ("write", 21, &|state| {
            state[ST]["rcpts"]["#map"][0][1]["attempt"] = number(3)
        }),
        ("write", 12, &|state| {
            state[ST]["rcpts"]["#map"][0][1]["phase"] = "issued".into()
        }),
        ("write", 39, &|state| {
            state[ST]["shards"]["#map"][0][1]["spare"] = number(0)
        }),
        ("write", 18, &|state| {
            state[ST]["vrecs"]["#map"][2][1]["state"] = number(1)
        }),
        ("call", 10, &|state| {
            state[ST]["calls"]["#set"] = serde_json::json!([])
        }),
    ];
    for (act, at, edit) in checks {
        assert_eq!(altered(at, edit), stored(act, at, edit));
    }
    assert_eq!(
        altered(27, &|state| state[ST]["ev"]["res"] = "record".into()),
        "write at 27: result failed, modeled record"
    );
    assert_eq!(
        altered(8, &|state| state[ST]["ev"]["pc"] = "receipt".into()),
        "read at 8: the operation reads Shard(Shard(1))"
    );
    let error = altered(25, &|state| {
        state[ST]["procs"]["#map"][1][1]["rc"]["attempt"] = number(3);
    });
    assert!(
        error.starts_with("call at 26: the operation calls under ")
            && error.ends_with("-00000002, modeled attempt 3"),
        "{error}"
    );
    // The create's shard read at state 8 leaves it running, and its record write at state 12 ends it.
    assert_eq!(
        altered(8, &|state| state[ST]["procs"]["#map"][1][1]["op"] =
            "idle".into()),
        "read at 8: the operation continues, modeled "
    );
    assert_eq!(
        altered(12, &|state| state[ST]["procs"]["#map"][1][1]["op"] =
            "create".into()),
        "write at 12: the operation ended ok"
    );
    // A held receipt or a failed provider call conflicts with the create's recorded continuation.
    assert_eq!(
        altered(7, &|state| state[ST]["ev"]["res"] = "held".into()),
        "read at 7: the step continues with result held"
    );
    assert_eq!(
        altered(10, &|state| state[ST]["ev"]["res"] = "failed".into()),
        "call at 10: the step continues with result failed"
    );
    // The recorded step's `pc` must match the acting process's position.
    assert_eq!(
        altered(36, &|state| state[ST]["ev"]["pc"] = "reread".into()),
        "read at 36: the step at reread, the process stands at shard"
    );
    assert_eq!(
        altered(10, &|state| state[ST]["ev"]["pc"] = "issue".into()),
        "call at 10: the step at issue, the process stands at call"
    );
    // The provider answers the call at state 10 with a new volume.
    assert_eq!(
        altered(10, &|state| state[ST]["ev"]["kept"] = true.into()),
        "call at 10: the provider's answer is new volume"
    );
    assert_eq!(
        altered(8, &|state| state[ST]["ev"]["act"] = "write".into()),
        "write at 8: the model's write at shard"
    );
    // The create writes the volume record at state 11.
    let written = altered(11, &|state| state[ST]["ev"]["pc"] = "record".into());
    assert!(
        written.starts_with("write at 11: the operation writes Volume("),
        "{written}"
    );
    // The replacement begins at state 2 over volume 1, which the model holds lost.
    assert_eq!(
        altered(2, &|state| {
            state[ST]["vols"]["#map"][0][1]["health"] = "available".into()
        }),
        "begin at 2: volume 1 is Available and the lost volumes are {1}"
    );
    assert_eq!(
        altered(5, &|state| state["mbt::actionTaken"] = "crash".into()),
        "action 5: unknown action write (crash)"
    );
    let other = |name: &str, at: usize, edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(fixture(name)).unwrap();
        edit(&mut trace["states"][at]);
        replay(&trace.to_string(), Driver::Faithful)
            .err()
            .unwrap_or_default()
    };
    // replay_flipOfRetired: the flip of process 2 ends at its begin at state 19, while process 1 runs an abandon,
    // and the model reads the shard record at state 20 and the volume record at state 21, in that order.
    assert_eq!(
        other("replay_flipOfRetired", 20, &|state| {
            state[ST]["ev"]["pc"] = "volume".into()
        }),
        "read at 20: the operation ended attach conflict"
    );
    assert_eq!(
        other("replay_flipOfRetired", 19, &|state| {
            state[ST]["ev"]["proc"] = number(1)
        }),
        "begin at 19: the process already runs an operation"
    );
    // replay_latchAndRelease: the replacement's receipt read at state 8 returns the receipt with no write.
    assert_eq!(
        other("replay_latchAndRelease", 8, &|state| {
            state[ST]["ev"]["res"] = "start".into()
        }),
        "read at 8: result ok, modeled start"
    );
    let json = fixture("run_retirement");
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, Driver::Faithful).err(),
        Some("fixture model digest".into())
    );
    let mut short = trace.clone();
    short["states"].as_array_mut().unwrap().pop();
    assert_eq!(
        replay(&short.to_string(), Driver::Faithful).err(),
        Some("fixture length".into())
    );
}

/// The row of the ITF map `map` under the integer key `key`.
fn row(map: &mut Value, key: u64) -> &mut Value {
    map["#map"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row[0]["#bigint"].as_str() == Some(key.to_string().as_str()))
        .map(|row| &mut row[1])
        .unwrap()
}

/// Every field the replay compares in the stored records and the provider is compared: the last state of
/// `run_retirement`, altered in one field of either shard record, of either receipt, of a volume record, of the
/// set of volume records, of a kept provider outcome or of the set of called tokens, fails at that state through
/// the record comparison.
#[test]
fn negative_control_each_compared_field_altered_fails_the_loss_replay() {
    let trace: Value = serde_json::from_str(fixture("run_retirement")).unwrap();
    let at = trace["states"].as_array().unwrap().len() - 1;
    let number = |value: u64| serde_json::json!({ "#bigint": value.to_string() });
    let modeled_after = |edit: &dyn Fn(&mut Value)| {
        let mut state = trace["states"][at].clone();
        edit(&mut state[ST]);
        super::replay_driver::plain(&mut state).unwrap();
        modeled(&state[ST]).unwrap()
    };
    let replayed = |edit: &dyn Fn(&mut Value)| {
        let mut trace = trace.clone();
        edit(&mut trace["states"][at][ST]);
        replay(&trace.to_string(), Driver::Faithful)
            .err()
            .unwrap_or_default()
    };
    type Edit<'a> = (&'a str, &'a dyn Fn(&mut Value));
    let edits: [Edit; 22] = [
        ("shard g", &|st| row(&mut st["shards"], 1)["g"] = number(3)),
        ("shard active", &|st| {
            row(&mut st["shards"], 1)["active"] = number(3)
        }),
        ("shard spare", &|st| {
            row(&mut st["shards"], 1)["spare"] = number(3)
        }),
        ("shard version", &|st| {
            row(&mut st["shards"], 1)["ver"] = number(4)
        }),
        ("shard 2 version", &|st| {
            row(&mut st["shards"], 2)["ver"] = number(2)
        }),
        ("receipt exists", &|st| {
            row(&mut st["rcpts"], 1)["exists"] = false.into()
        }),
        ("receipt attempt", &|st| {
            row(&mut st["rcpts"], 1)["attempt"] = number(4)
        }),
        ("receipt phase", &|st| {
            row(&mut st["rcpts"], 1)["phase"] = "issued".into()
        }),
        ("receipt volume", &|st| {
            row(&mut st["rcpts"], 1)["vol"] = number(3)
        }),
        ("receipt held", &|st| {
            row(&mut st["rcpts"], 1)["held"] = true.into()
        }),
        ("receipt released", &|st| {
            row(&mut st["rcpts"], 1)["released"] = true.into()
        }),
        ("receipt version", &|st| {
            row(&mut st["rcpts"], 1)["ver"] = number(9)
        }),
        ("receipt 2 exists", &|st| {
            row(&mut st["rcpts"], 2)["exists"] = true.into()
        }),
        ("volume state", &|st| {
            row(&mut st["vrecs"], 4)["state"] = number(2)
        }),
        ("volume version", &|st| {
            row(&mut st["vrecs"], 3)["ver"] = number(3)
        }),
        ("volume 2 version", &|st| {
            row(&mut st["vrecs"], 2)["ver"] = number(2)
        }),
        ("volume set", &|st| {
            st["vrecs"]["#map"].as_array_mut().unwrap().pop();
        }),
        ("provider kind", &|st| {
            st["prov"]["#map"][0][1]["kind"] = "failed".into()
        }),
        ("provider volume", &|st| {
            st["prov"]["#map"][0][1]["vol"] = number(4)
        }),
        ("provider token", &|st| {
            st["prov"]["#map"][0][0]["#tup"][1] = number(4)
        }),
        ("provider set", &|st| {
            st["prov"]["#map"].as_array_mut().unwrap().pop();
        }),
        ("calls", &|st| {
            st["calls"]["#set"].as_array_mut().unwrap().pop();
        }),
    ];
    let stored = modeled_after(&|_| {});
    for (field, edit) in edits {
        let altered = modeled_after(edit);
        assert_ne!(altered, stored, "{field}");
        assert_eq!(
            replayed(edit),
            format!("write at {at}: stored {stored:?}, modeled {altered:?}"),
            "{field}"
        );
    }
}

#[test]
fn the_fixture_list_names_every_committed_trace() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/failover/loss_replay_fixtures");
    let committed: BTreeSet<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let listed: BTreeSet<String> = FIXTURES
        .iter()
        .map(|(name, _)| format!("{name}.itf.json"))
        .collect();
    assert_eq!(committed, listed);
}
