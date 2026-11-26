//! Replays committed traces of the standby-census model `quint/standbys.qnt` against [`Reconciler::reserve`],
//! [`Reconciler::release`], [`Reconciler::designate`], [`Reconciler::record_standby`], [`enroll_standby`] and the
//! attach end ([`Reconciler::end_attach`], [`Reconciler::detachable`], [`Reconciler::release_attach`]) over the
//! simulated store, through the shared driver of `replay_driver`. `quint/README.md`, section "Replay against the
//! reconciler", states the abstraction map and the action map.
//!
//! # Steps
//!
//! Each step of a trace answers one production store request of the operation its event names, which must be the
//! read or write of the record the event's key names, and the event must name the operation, shard and host its
//! `begin` step named. Four exceptions: the read of the operation's coverage page 0
//! right after a shard read in `record_standby` and `enroll_standby`, and after the census read in `designate`, is
//! answered with no model step, and any other page read fails the replay; `endRead` answers the end's shard and
//! volume reads; `endWrite` answers the end's write and its shard reread, writes the owner's pair drop and runs
//! `detachable` and `release_attach`, which the model makes one step; and a release whose census read finds a census
//! that lists no entry for its shard returns at that read while the model goes on to read the shard and then the
//! volume record, which the driver accepts in that order with no request. `detachable` and `release_attach` run on
//! the replay thread over a store that logs their requests, which must be a read of the volume record, another read
//! of it and its write.
//!
//! The driver writes the environment's steps itself: `bump`, `fresh` and `takeover` through the store client,
//! `flip` as its own write of the new volume's record and the flipped shard record, `transfer` as its own write of
//! the shard record with the standby as owner at the next attempt and no standby, and `learn`, `suspect` and a
//! failed `attachEnds` into the [`Evidence`] the `lost` closure of a reservation or a release reads. The planned
//! transfer's production writer reads the volume record and writes the shard record in two requests; the replay
//! runs neither, so a transfer step shows only that the operations around it agree with the model over the record
//! the model's one step leaves. `end_attach` takes the shard's active volume and the number of the host's latest
//! entry from the stored records at its `endRead` step, standing for the caller's survey. A reservation's
//! candidate report comes from the model's state at that reservation's volume read ([`Replay::report`]). A `flip` of
//! a shard whose end is decided drops that end's operation before its volume write, whose request then returns
//! `Outcome::Unknown` with no store write, as the model's end of that shard lands nowhere.
//!
//! # Comparison
//!
//! Before each step runs, the action the trace records must be one the event's `act` names ([`leaf`]), and the
//! event's shard and host must be 0 or in the instance. After every step, `init` included, the stored census of each
//! zone, each shard record, the record of each shard's active volume and whether a write is parked must equal the
//! model's state ([`Seen`]), a census must hold no entry for a shard outside the instance, each process's slot
//! must equal the model's `(ss, slot)`, each process must be idle or run the model's operation with the request
//! the model's `pc` names pending ([`Replay::stands`]), and the decided end must be the one the model's
//! `en.ending` holds ([`Replay::decided`]). A step that ends an operation must find it ended with a result [`agrees`]
//! maps to the model's, and a step that does not end it must find it running; an end that lands must report the
//! host named by the shard record it rereads exactly when the model's shard record names it owner or standby. A
//! `deliver` step requires the held write to be one of the record its event names.
//!
//! A write request is matched by its key alone: its condition and its value are compared through the stored records
//! after the write commits or is delivered, and the value of a write the store loses is compared nowhere. The other
//! successful replies, the designation's read, `StandbyRecorded` and the enrolled pair, are compared by their status
//! alone.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use serde_json::Value;

use super::replay_driver::{Message, Op, Reply, states};
use super::{capped, commits};
use crate::failover::detect_route_replay_tests::ReplayScratch;
use crate::failover::evidence::Pair;
use crate::failover::evidence_tests::exhid;
use crate::failover::poll::Holder;
use crate::failover::reconcile::{
    Binding, Listing, ReconcileError, Reconciler, Settle, StandbyGate, StandbyRefusal,
    enroll_standby,
};
use crate::failover::record::{Binding as LocalBinding, LocalRecord};
use crate::failover::records::Namespace;
use crate::failover::records::{
    CoveragePage, CreationSource, ERA, Enrollment, EventKind, Host, Lineage, Record, RecordedPair,
    ShardRecord, VolumeId, VolumeRecord, VolumeState, attachment_key,
};
use crate::failover::report::tests::bare;
use crate::failover::report::{Gauge, HostReport, RecordedRole, VolumeEntry};
use crate::failover::retire::Target;
use crate::failover::sim::{host, instance_of_host, layout};
use crate::failover::standbys::tests::report_of;
use crate::failover::standbys::{
    Attach, Census, Entry, Population, Refusal as PopulationRefusal, Slot, Zone,
};
use crate::net::ownership::{Shard, ShardGeneration};
use crate::storage::store::sim::{Arm, AsReconciler, MemLog, Shared};
use crate::storage::store::{
    Client, Item, Key, Outcome, Refusal, Store, StoreError, Unavailable, Write,
};
use crate::storage::store_tests::{client, record};

const MODEL: &[u8] = include_bytes!("../../../../quint/standbys.qnt");
const ST: &str = "standbysCase::standbys::st";
const EV: &str = "standbysCase::standbys::ev";
const PROCS: &str = "standbysCase::standbys::procs";
const EN: &str = "standbysCase::standbys::en";
macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("standbys_replay_fixtures/", $name, ".itf.json")))),*]
    };
}

/// The traces `quint/standbys_fixtures.py` writes: the directed recipes, then 32 seeded runs of 24 steps of the
/// model's `step`, each named `step_` and its seed in hexadecimal.
const FIXTURES: [(&str, &str); 93] = fixtures![
    "recipe_conflictBeforeDesignation",
    "recipe_designationBeforeEndLands",
    "recipe_designationOvertaken",
    "recipe_designationRacesEnd",
    "recipe_endLandsOnOwner",
    "recipe_endRefusedOnMovedVolume",
    "recipe_enrollRefusedAfterFlip",
    "recipe_enrollRefusedAtFlip",
    "recipe_enrollRefusedUnattached",
    "recipe_heldDeliveryRefused",
    "recipe_recordRefusedAfterFlip",
    "recipe_recordRefusedAtFlip",
    "recipe_releaseDropsOnLoss",
    "recipe_releasedAfterEnd",
    "recipe_reopenedAfterEnd",
    "recipe_suspicionHeldAcrossLoss",
    "recipe_unenrolledKeepsLive",
    "recipe_unlistedKeepsCensus",
    "recipe_volumeConditionLost",
    "replay_designationAsIs",
    "replay_designationStale",
    "replay_designationStaleByAttempt",
    "replay_designationStaleByGeneration",
    "replay_designationUnenrolled",
    "replay_endEnrolledAttach",
    "replay_endFailedAttach",
    "replay_endRecordedAttach",
    "replay_enrollConditionLost",
    "replay_enrollUnknownLost",
    "replay_occupiedRefusesHeadroom",
    "replay_recordHeldDelivered",
    "replay_recordUnknownCommitted",
    "replay_releaseAbsent",
    "replay_releaseHeldDelivered",
    "replay_releaseKeptStandby",
    "replay_reservationExcluded",
    "replay_reserveIneligibleUnacquired",
    "run_attachFailedMovesSlot",
    "run_capRefusesSecond",
    "run_designateReadsCensusAfterShard",
    "run_designationBehindRivalRacesEnd",
    "run_earlierTenureLosesCondition",
    "run_enrollOne",
    "run_flipReleasesEntry",
    "run_freshHostAfterDoubleLoss",
    "run_freshTakesStaleEntry",
    "run_headroomAfterTakeoverBetweenReads",
    "run_hostInTwoRolesLost",
    "run_listedAfterUnknownAtLimit",
    "run_ownerAtRoleLimit",
    "run_racingReservations",
    "run_reEnrollAfterTakeover",
    "run_releaseReadsShardAfterCensus",
    "run_renewedAtLimitAfterBump",
    "run_reservedAfterEnrollBetweenReads",
    "run_restartConverges",
    "run_slotKeptUnderLoopOrder",
    "run_slotTakenAfterTakeover",
    "run_staleReconcilerRefused",
    "run_stormOwnerOfTwo",
    "run_transferThenRedesignate",
    "step_5b00",
    "step_5b01",
    "step_5b02",
    "step_5b04",
    "step_5b05",
    "step_5b06",
    "step_5b07",
    "step_5b08",
    "step_5b09",
    "step_5b0a",
    "step_5b0b",
    "step_5b0c",
    "step_5b0d",
    "step_5b0e",
    "step_5b0f",
    "step_5b10",
    "step_5b20",
    "step_5b21",
    "step_5b22",
    "step_5b23",
    "step_5b24",
    "step_5b25",
    "step_5b26",
    "step_5b27",
    "step_5b30",
    "step_5b31",
    "step_5b32",
    "step_5b35",
    "step_5b36",
    "step_5b37",
    "step_5b38",
    "step_5b39",
];

/// Every `(operation, result)` the committed traces end an operation with: each result of the model's operations but
/// `record`'s `attachClosed`, which no instance of `quint/standbys_check.py` reaches, and `release`'s `keptRecording`,
/// which the replay leaves out.
const RESULTS: [(&str, &str); 34] = [
    ("designate", "asis"),
    ("designate", "condition"),
    ("designate", "conflict"),
    ("designate", "designated"),
    ("designate", "stale"),
    ("designate", "unenrolled"),
    ("designate", "unknown"),
    ("enroll", "condition"),
    ("enroll", "enrolled"),
    ("enroll", "tenure"),
    ("enroll", "unattached"),
    ("enroll", "unknown"),
    ("record", "condition"),
    ("record", "notServing"),
    ("record", "recorded"),
    ("record", "unknown"),
    ("release", "absent"),
    ("release", "condition"),
    ("release", "keptCurrent"),
    ("release", "keptLive"),
    ("release", "keptStandby"),
    ("release", "released"),
    ("release", "unknown"),
    ("release", "unlisted"),
    ("reserve", "closed"),
    ("reserve", "condition"),
    ("reserve", "excluded"),
    ("reserve", "full"),
    ("reserve", "headroom"),
    ("reserve", "ineligible"),
    ("reserve", "listed"),
    ("reserve", "reserved"),
    ("reserve", "taken"),
    ("reserve", "unknown"),
];
/// The zones of the model's census map; every shard is in zone 1, the model's `ZONE`.
const ZONES: [u16; 2] = [1, 2];

/// How the replay maps a model step to production calls. `Faithful` is the mapping of the module doc; `OtherSlot`
/// changes one row of it and serves as a negative control.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    Faithful,
    /// A designation is passed the slot the other reconciler holds, when it holds one.
    OtherSlot,
    /// A release returns `unlisted` once its census read is answered, whatever the census holds.
    UnlistedRelease,
    /// An end that lands reports the host named by no role of the shard record it rereads.
    Unnamed,
    /// A census write commits with one more entry, for shard 9, outside the instance.
    ExtraCensusEntry,
    /// A volume write commits with one more live attach, of host 9, outside the instance.
    ExtraLiveHost,
    /// A release reads the census and the shard record and then returns `unlisted`.
    LateUnlistedRelease,
    /// `end_attach` is asked to end the entry after the host's latest one.
    OtherEntry,
    /// The end's cleanup stops after `detachable` and makes no `release_attach` call.
    SkipsGoneMark,
    /// The gone mark's write commits the volume record it read, so the entry stays ended.
    EndStaysEnded,
    /// An attach record reads coverage page 0 of its shard once more, right after its volume read.
    PageAfterVolume,
    /// An attach record reads coverage page 1 of its shard right after its shard read.
    OtherPage,
}

fn num(v: &Value, what: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("model {what}"))
}

fn flag(v: &Value, what: &str) -> Result<bool, String> {
    v.as_bool().ok_or_else(|| format!("model {what}"))
}

fn at<'a>(map: &'a Value, key: u64, what: &str) -> Result<&'a Value, String> {
    map["#map"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row[0].as_u64() == Some(key)))
        .map(|row| &row[1])
        .ok_or_else(|| format!("model {what} {key}"))
}

fn keys(map: &Value, what: &str) -> Result<Vec<u64>, String> {
    let rows = map["#map"]
        .as_array()
        .ok_or_else(|| format!("model {what}"))?;
    let mut keys = rows
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

fn pairs(set: &Value, what: &str) -> Result<BTreeSet<(u64, u64)>, String> {
    set["#set"]
        .as_array()
        .ok_or_else(|| format!("model {what}"))?
        .iter()
        .map(
            |member| match member["#tup"].as_array().map(Vec::as_slice) {
                Some([first, second]) => Ok((num(first, what)?, num(second, what)?)),
                _ => Err(format!("model {what}")),
            },
        )
        .collect()
}

/// Callers must supply an `s` that fits in `u32` and that `Shard::new` accepts.
fn shard_of(s: u64) -> Shard {
    Shard::new(u32::try_from(s).unwrap()).unwrap()
}

/// The volume the replay names shard `s`'s active volume at generation `g`.
fn volume_of(s: u64, g: u64) -> VolumeId {
    VolumeId::new(&format!("vol-{s:02x}{g:02x}")).unwrap()
}

/// Page 0's fence after the owner's activation at generation `g`: `g` in the high word and activated epoch 2 in the
/// low word.
fn activation(g: u64) -> u64 {
    (g << 32) | 2
}

/// A census entry as the model holds it: `(on, g, owner, e, host)`, all zero for no entry.
type Slotted = (bool, u64, u64, u64, u64);

const NO_SLOT: Slotted = (false, 0, 0, 0, 0);

/// The [`Slotted`] of a model entry.
fn slotted(entry: &Value) -> Result<Slotted, String> {
    Ok((
        flag(&entry["on"], "slot")?,
        num(&entry["g"], "slot")?,
        num(&entry["owner"], "slot")?,
        num(&entry["e"], "slot")?,
        num(&entry["host"], "slot")?,
    ))
}

/// The [`Slotted`] of a production entry that holds `target` for `host`.
fn held_slot(target: &Target, host: Host) -> Slotted {
    (
        true,
        target.generation.get(),
        target.owner.get(),
        target.attempts.into(),
        host.get(),
    )
}

/// The records the model and production are compared in, in model units: each zone's census version and entries,
/// each shard's `(g, owner, e, standby, version)`, each shard's active volume's live hosts, enrolled hosts and
/// version, and whether a write is held. A version is the record's commit count; a shard's volume version counts
/// the commits of every volume record of the shard less the writes an end step merges.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    census: Vec<(u64, Vec<Slotted>)>,
    shards: Vec<(u64, u64, u64, u64, u64)>,
    volumes: Vec<(BTreeSet<u64>, BTreeSet<u64>, u64)>,
    held: bool,
}

fn modeled(st: &Value) -> Result<Seen, String> {
    let shards = keys(&st["shards"], "shards")?;
    let mut census = Vec::new();
    for z in ZONES {
        let held = at(&st["census"], z.into(), "census")?;
        let slots = shards
            .iter()
            .map(|&s| slotted(at(&held["slots"], s, "slots")?))
            .collect::<Result<_, String>>()?;
        census.push((num(&held["ver"], "census version")?, slots));
    }
    let mut records = Vec::new();
    let mut volumes = Vec::new();
    for &s in &shards {
        let r = at(&st["shards"], s, "shard")?;
        records.push((
            num(&r["g"], "g")?,
            num(&r["owner"], "owner")?,
            num(&r["e"], "e")?,
            num(&r["standby"], "standby")?,
            num(&r["ver"], "shard version")?,
        ));
        let v = at(&st["volumes"], s, "volume")?;
        volumes.push((
            members(&v["live"], "live")?,
            members(&v["enrolled"], "enrolled")?,
            num(&v["ver"], "volume version")?,
        ));
    }
    Ok(Seen {
        census,
        shards: records,
        volumes,
        held: flag(&st["held"]["on"], "held")?,
    })
}

/// Each reconciler's loss evidence and the attaches that failed for good, as `(shard, host)`.
#[derive(Default)]
struct Evidence {
    seen: [BTreeSet<u64>; 2],
    failed: BTreeSet<(u64, u64)>,
}

impl Evidence {
    /// The model's `lostTo`: a host reconciler `r` holds lost, or one whose attach of shard `s`'s volume failed.
    fn lost(&self, r: usize, s: u64, h: Host) -> bool {
        self.seen[r].contains(&h.get()) || self.failed.contains(&(s, h.get()))
    }
}

/// An operation in flight, started for the event's `(name, shard, host)`: `wrote` holds once one of its writes
/// committed or a timeout committed it, `early` once a release returned at its census read before the model's last
/// read of it, `served` the keys the driver answered and `skipped` the model reads after `early` that made no
/// request.
struct Running {
    op: Op,
    name: String,
    shard: u64,
    host: u64,
    wrote: bool,
    early: bool,
    served: Vec<Key>,
    skipped: usize,
}

impl Running {
    fn new(op: Op, name: &str, shard: u64, host: u64) -> Self {
        Self {
            op,
            name: name.into(),
            shard,
            host,
            wrote: false,
            early: false,
            served: Vec::new(),
            skipped: 0,
        }
    }

    /// Requires an event of this operation to name its operation, shard and host.
    fn names(&self, op: &str, s: u64, h: u64) -> Result<(), String> {
        if (op, s, h) == (self.name.as_str(), self.shard, self.host) {
            return Ok(());
        }
        Err(format!(
            "the event names {op}({s}, {h}), the process runs {}({}, {})",
            self.name, self.shard, self.host
        ))
    }
}

/// The store of the attach end's cleanup calls, which run on the replay thread: it passes each request on and logs
/// its kind and key. With `keep`, an exact-version write commits the value the store holds in place of its own.
struct Recording<S> {
    store: S,
    log: Rc<RefCell<Vec<(&'static str, Key)>>>,
    keep: bool,
}

impl<S: Store> Store for Recording<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.log.borrow_mut().push(("read", *key));
        self.store.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.log.borrow_mut().push(("write", *key));
        match (write, self.store.read(key)) {
            (Write::Exact { expect, .. }, Ok(Some(held))) if self.keep => self.store.write(
                key,
                &Write::Exact {
                    expect: *expect,
                    value: held.value,
                },
            ),
            _ => self.store.write(key, write),
        }
    }

    fn namespace(&self) -> Namespace {
        self.store.namespace()
    }
}

/// A read a driver adds to an attach record: the keys it follows, and the key it reads.
type Extra = (fn(&Key) -> bool, Key);

/// The store of an attach record under a driver that adds a page read: after a read whose key `extra` accepts
/// returns, it reads `extra`'s key and drops the reply.
struct Probing<S> {
    store: S,
    extra: Option<Extra>,
}

impl<S: Store> Store for Probing<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        let read = self.store.read(key);
        if let Some((after, extra)) = self.extra
            && after(key)
        {
            let _ = self.store.read(&extra);
        }
        read
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.store.write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.store.namespace()
    }
}

#[derive(Default)]
struct Proc {
    running: Option<Running>,
    slot: Option<Slot>,
    reserved: Option<Arc<Mutex<Option<Slot>>>>,
}

/// Whether the model result `modeled` of operation `name` is one the code's `result` stands for, given whether the
/// operation wrote.
fn agrees(name: &str, result: &str, wrote: bool, modeled: &str) -> bool {
    let named: &[&str] = match (name, result, wrote) {
        (_, "condition", _) => &["condition"],
        (_, "unknown", _) => &["unknown"],
        ("reserve", "ok", true) => &["reserved"],
        ("reserve", "ok", false) => &["listed"],
        ("reserve", "ineligible", false) => &["ineligible"],
        ("reserve", "closed", false) => &["closed"],
        ("reserve", "headroom", false) => &["headroom"],
        ("reserve", "taken", false) => &["taken"],
        ("reserve", "full", false) => &["full"],
        ("release", "unlisted", true) => &["released"],
        ("release", "unlisted", false) => &["unlisted", "absent"],
        ("release", "listed", false) => &["keptStandby", "keptCurrent", "keptLive"],
        ("designate", "ok", true) => &["designated"],
        ("designate", "ok", false) => &["asis"],
        ("designate", "stale", false) => &["stale"],
        ("designate", "conflict", false) => &["conflict", "unenrolled"],
        ("record", "ok", true) => &["recorded"],
        ("record", "conflict", _) => &["notServing", "attachClosed"],
        ("enroll", "ok", true) => &["enrolled"],
        ("enroll", "tenure", _) => &["tenure"],
        ("enroll", "unattached", false) => &["unattached"],
        _ => &[],
    };
    named.contains(&modeled)
}

/// A reconciler step's result string: `ok`, the model's name of a population refusal, `conflict`, `stale`,
/// `condition`, `unknown`, or the error's `Debug` text.
fn outcome<T>(result: Result<T, ReconcileError>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(ReconcileError::Population(refusal)) => match refusal {
            PopulationRefusal::Ineligible => "ineligible",
            PopulationRefusal::Closed => "closed",
            PopulationRefusal::Headroom => "headroom",
            PopulationRefusal::Taken => "taken",
            PopulationRefusal::Full => "full",
        }
        .into(),
        Err(ReconcileError::Conflict) => "conflict".into(),
        Err(ReconcileError::Stale) => "stale".into(),
        Err(ReconcileError::Store(error)) => store_outcome(error),
        Err(error) => format!("{error:?}"),
    }
}

fn store_outcome(error: StoreError) -> String {
    match error {
        StoreError::Refused(Refusal::Condition) => "condition".into(),
        StoreError::Unknown => "unknown".into(),
        error => format!("{error:?}"),
    }
}

fn open<S: Store>(store: S) -> Client<S, MemLog> {
    Client::open(store, MemLog::default()).unwrap()
}

struct Replay<'a> {
    store: Shared,
    states: &'a [Value],
    driver: Driver,
    cap: usize,
    attach_limit: u64,
    shards: Vec<u64>,
    hosts: Vec<u64>,
    evidence: Arc<Mutex<Evidence>>,
    procs: [Proc; 2],
    ending: Option<Running>,
    merged: std::collections::BTreeMap<u64, u64>,
    requests: Vec<(usize, &'static str, Key)>,
    at: usize,
}

impl Replay<'_> {
    /// The record the store holds under `key`, or `None` when it holds none.
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

    /// The host `h` names, which must be a host of the instance.
    fn known(&self, h: u64) -> Result<Host, String> {
        if self.hosts.contains(&h) {
            return Ok(host(h));
        }
        Err(format!("host {h} lies outside the instance"))
    }

    fn shard_record(&self, s: u64) -> Result<ShardRecord, String> {
        self.current(Key::Shard(shard_of(s)))?
            .ok_or_else(|| format!("shard record {s}"))
    }

    fn active(&self, s: u64) -> Result<VolumeId, String> {
        Ok(self.shard_record(s)?.active)
    }

    fn put(&self, key: Key, value: Vec<u8>) -> Result<(), String> {
        let current = self.store.0.borrow().current(&key).cloned();
        let write = match current {
            None => Write::Create(value),
            Some(Item { version, .. }) => Write::Exact {
                expect: version,
                value,
            },
        };
        match self.store.clone().write(&key, &write) {
            Outcome::Committed(_) => Ok(()),
            outcome => Err(format!("the driver's write of {key:?}: {outcome:?}")),
        }
    }

    fn volume(
        s: u64,
        g: u64,
        live: &BTreeSet<u64>,
        enrolled: &BTreeSet<u64>,
    ) -> Result<VolumeRecord, String> {
        let mut held = VolumeRecord {
            volume: volume_of(s, g),
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
        for &h in live {
            let seq = held.push(EventKind::Attach, host(h), ERA).ok_or("attach")?;
            held.events.last_mut().ok_or("attach")?.instance = Some(instance_of_host(host(h)));
            if enrolled.contains(&h) {
                held.pairs.push(RecordedPair {
                    host: host(h),
                    pair: Pair {
                        exhid: exhid(u8::try_from(h).unwrap()),
                        key: attachment_key(seq).ok_or("key")?,
                    },
                    attach: seq,
                });
            }
        }
        Ok(held)
    }

    fn seed(&mut self, st: &Value) -> Result<(), String> {
        for &s in &self.shards {
            let r = at(&st["shards"], s, "shard")?;
            let g = num(&r["g"], "g")?;
            let standby = num(&r["standby"], "standby")?;
            let shard = ShardRecord {
                shard: shard_of(s),
                generation: ShardGeneration::new(g).ok_or("g")?,
                active: volume_of(s, g),
                owner: self.known(num(&r["owner"], "owner")?)?,
                attempts: u32::try_from(num(&r["e"], "e")?).map_err(|_| "e")?,
                spare: None,
                standby: (standby != 0).then(|| self.known(standby)).transpose()?,
                ..record()
            };
            for page in 0..shard.pages.get() {
                let held = CoveragePage {
                    fence: if page == 0 { activation(g) } else { 0 },
                    ..CoveragePage::default()
                };
                self.put(Key::Page(shard_of(s), page), held.encode())?;
            }
            self.put(Key::Shard(shard_of(s)), shard.encode())?;
            let v = at(&st["volumes"], s, "volume")?;
            let live = members(&v["live"], "live")?;
            let enrolled = members(&v["enrolled"], "enrolled")?;
            for &h in live.union(&enrolled) {
                self.known(h)?;
            }
            let held = Self::volume(s, g, &live, &enrolled)?;
            self.put(Key::Volume(held.volume), held.encode())?;
        }
        for z in ZONES {
            let held = at(&st["census"], z.into(), "census")?;
            if num(&held["ver"], "census version")? == 0 {
                continue;
            }
            let mut census = Census::empty(Zone(z));
            for &s in &self.shards {
                let entry = at(&held["slots"], s, "slots")?;
                if !flag(&entry["on"], "slot")? {
                    continue;
                }
                let tenure = ShardRecord {
                    generation: ShardGeneration::new(num(&entry["g"], "slot")?).ok_or("g")?,
                    owner: self.known(num(&entry["owner"], "slot")?)?,
                    attempts: u32::try_from(num(&entry["e"], "slot")?).map_err(|_| "slot")?,
                    ..self.shard_record(s)?
                };
                let candidate = report_of(
                    self.known(num(&entry["host"], "slot")?)?,
                    Gauge::known(0, 64),
                    Gauge::known(0, 1),
                );
                census = Population { cap: 64 }
                    .admit(&census, &tenure, &candidate, Attach::Live, |_| true)
                    .map_err(|refusal| format!("init census {refusal:?}"))?
                    .ok_or("init census")?;
            }
            self.put(Key::Standbys(Zone(z)), census.encode())?;
        }
        Ok(())
    }

    fn seen(&self) -> Result<Seen, String> {
        let mut census = Vec::new();
        for z in ZONES {
            let key = Key::Standbys(Zone(z));
            let held: Option<Census> = self.current(key)?;
            if let Some((shard, _)) = held
                .iter()
                .flat_map(Census::entries)
                .find(|(shard, _)| !self.shards.contains(&u64::from(shard.get())))
            {
                return Err(format!(
                    "the census of zone {z} holds shard {}",
                    shard.get()
                ));
            }
            let slots = self
                .shards
                .iter()
                .map(|&s| {
                    held.as_ref()
                        .and_then(|census| census.slot(shard_of(s)))
                        .map_or(NO_SLOT, |entry| held_slot(&entry.target, entry.host))
                })
                .collect();
            census.push((self.commits(key), slots));
        }
        let mut shards = Vec::new();
        let mut volumes = Vec::new();
        for &s in &self.shards {
            let r = self.shard_record(s)?;
            if r.generation.get() > self.at as u64 + 1 {
                return Err(format!("shard {s} generation {}", r.generation.get()));
            }
            shards.push((
                r.generation.get(),
                r.owner.get(),
                r.attempts.into(),
                r.standby.map_or(0, Host::get),
                self.commits(Key::Shard(shard_of(s))),
            ));
            let held: VolumeRecord = self
                .current(Key::Volume(r.active))?
                .ok_or_else(|| format!("volume record {s}"))?;
            let live = held.live_hosts().map(Host::get).collect();
            let enrolled = held.pairs.iter().map(|pair| pair.host.get()).collect();
            let version = (1..=r.generation.get())
                .map(|g| self.commits(Key::Volume(volume_of(s, g))))
                .sum::<u64>()
                - self.merged.get(&s).copied().unwrap_or(0);
            volumes.push((live, enrolled, version));
        }
        let held = !self.store.0.borrow().parked().is_empty();
        Ok(Seen {
            census,
            shards,
            volumes,
            held,
        })
    }

    /// The candidate report of process `r`'s reservation for host `h`, from the model's state at that reservation's
    /// volume read, or at this step when the trace ends before it.
    fn report(&self, r: u64, h: u64) -> Result<HostReport, String> {
        let decided = self.states[self.at..]
            .iter()
            .find(|state| {
                let ev = &state[EV];
                ev["proc"].as_u64() == Some(r) && ev["op"] == "reserve" && ev["key"] == "volume"
            })
            .unwrap_or(&self.states[self.at]);
        let st = &decided[ST];
        let attached = pairs(&st["attached"], "attached")?;
        let used = num(at(&st["outside"], h, "outside")?, "outside")?
            .checked_add(attached.iter().filter(|&&(_, x)| x == h).count() as u64)
            .ok_or("model outside count")?;
        let mut report = report_of(
            host(h),
            Gauge::known(used, self.attach_limit),
            Gauge::known(0, 1),
        );
        for &s in &self.shards {
            let enrolled = members(&at(&st["volumes"], s, "volume")?["enrolled"], "enrolled")?;
            let owner = num(&at(&st["shards"], s, "shard")?["owner"], "owner")?;
            if enrolled.contains(&h) && owner != h {
                report.entries.push(VolumeEntry {
                    shard: shard_of(s),
                    ..bare("vol-0a", RecordedRole::Standby)
                });
            }
        }
        Ok(report)
    }

    fn begin(&mut self, r: usize, name: &str, s: u64, h: u64) -> Result<Running, String> {
        if !self.shards.contains(&s) {
            return Err(format!("shard {s} lies outside the instance"));
        }
        if name != "release" {
            self.known(h)?;
        }
        let gate = StandbyGate::qualified;
        let shard = shard_of(s);
        let evidence = self.evidence.clone();
        let lost = move |x: Host| evidence.lock().unwrap().lost(r, s, x);
        let slot = match self.driver {
            Driver::OtherSlot => self.procs[1 - r].slot.or(self.procs[r].slot),
            _ => self.procs[r].slot,
        };
        let active = self.active(s)?;
        let op = match name {
            "reserve" => {
                let (cap, report) = (self.cap, self.report(r as u64, h)?);
                let out = Arc::new(Mutex::new(None));
                self.procs[r].reserved = Some(out.clone());
                Op::start(move |proxy| {
                    let reserved = Reconciler::new(open(proxy)).reserve(
                        &gate(),
                        &Population { cap },
                        &capped(8),
                        Zone(ZONES[0]),
                        shard,
                        &report,
                        lost,
                    );
                    if let Ok(slot) = &reserved {
                        *out.lock().unwrap() = Some(*slot);
                    }
                    outcome(reserved)
                })
            }
            "release" if self.driver == Driver::UnlistedRelease => {
                let census = Key::Standbys(Zone(ZONES[0]));
                Op::start(move |mut proxy| {
                    let _ = proxy.read(&census);
                    "unlisted".into()
                })
            }
            "release" if self.driver == Driver::LateUnlistedRelease => {
                let census = Key::Standbys(Zone(ZONES[0]));
                Op::start(move |mut proxy| {
                    let _ = proxy.read(&census);
                    let _ = proxy.read(&Key::Shard(shard));
                    "unlisted".into()
                })
            }
            "release" => {
                let zone = Zone(ZONES[0]);
                let judged: Option<Census> = self.current(Key::Standbys(zone))?;
                let held = match judged.and_then(|census| census.slot(shard)) {
                    Some(entry) => entry,
                    None => {
                        let tenure = self.shard_record(s)?;
                        Entry {
                            target: Target::of(&tenure),
                            host: tenure.owner,
                        }
                    }
                };
                Op::start(move |proxy| {
                    match Reconciler::new(open(proxy)).release(&gate(), zone, shard, held, lost) {
                        Ok(true) => "listed".into(),
                        Ok(false) => "unlisted".into(),
                        released => outcome(released),
                    }
                })
            }
            "designate" => {
                let slot = slot.ok_or("designate holds no slot")?;
                Op::start(move |proxy| {
                    outcome(Reconciler::new(open(proxy)).designate(&gate(), &slot, active))
                })
            }
            "record" => {
                let extra: Option<Extra> = match self.driver {
                    Driver::PageAfterVolume => {
                        Some((|key| matches!(key, Key::Volume(_)), Key::Page(shard, 0)))
                    }
                    Driver::OtherPage => {
                        Some((|key| matches!(key, Key::Shard(_)), Key::Page(shard, 1)))
                    }
                    _ => None,
                };
                Op::start(move |proxy| {
                    let binding = Binding {
                        instance: instance_of_host(host(h)),
                        unbound: &[],
                        listing: None,
                    };
                    let store = Probing {
                        store: proxy,
                        extra,
                    };
                    outcome(Reconciler::new(open(store)).record_standby(
                        &gate(),
                        shard,
                        active,
                        host(h),
                        ERA,
                        &capped(8),
                        &binding,
                    ))
                })
            }
            "enroll" => Op::start(move |proxy| {
                let holder = Holder {
                    volume: active,
                    host: host(h),
                    instance: instance_of_host(host(h)),
                };
                let persist = |key| {
                    let binding = LocalBinding {
                        instance: holder.instance.as_str().to_owned(),
                        volume: active.as_str().to_owned(),
                        attachment: format!("{}-attach", active.as_str()),
                    };
                    Ok(LocalRecord::fresh(binding, key, || {
                        Some(exhid(u8::try_from(h).unwrap()).bytes())
                    })
                    .unwrap())
                };
                let enrolled = enroll_standby(
                    &gate(),
                    shard,
                    &holder,
                    &capped(8),
                    &mut open(proxy),
                    persist,
                );
                match enrolled {
                    Ok(_) => "ok".into(),
                    Err(StandbyRefusal::Tenure) => "tenure".into(),
                    Err(StandbyRefusal::Enrollment(Enrollment::Unattached)) => "unattached".into(),
                    Err(StandbyRefusal::Write(error)) => store_outcome(error),
                    Err(error) => format!("{error:?}"),
                }
            }),
            name => return Err(format!("unknown operation {name}")),
        }?;
        Ok(Running::new(op, name, s, h))
    }

    /// Plants the change [`Driver::ExtraCensusEntry`] or [`Driver::ExtraLiveHost`] makes to a census or volume
    /// write, and returns any other write as it is.
    fn planted(&self, key: Key, write: &Write) -> Result<Write, String> {
        let value = match write {
            Write::Create(value) | Write::Exact { value, .. } => value,
        };
        let value = match (self.driver, key) {
            (Driver::ExtraCensusEntry, Key::Standbys(_)) => {
                let census = Census::decode(value).map_err(|error| format!("{error:?}"))?;
                let shard = Shard::new(9).ok_or("shard 9")?;
                let tenure = ShardRecord {
                    shard,
                    attempts: 1,
                    ..record()
                };
                let candidate = report_of(host(7), Gauge::known(0, 64), Gauge::known(0, 1));
                Population { cap: 64 }
                    .admit(&census, &tenure, &candidate, Attach::Live, |_| true)
                    .map_err(|refusal| format!("planted entry {refusal:?}"))?
                    .ok_or("planted entry")?
                    .encode()
            }
            (Driver::ExtraLiveHost, Key::Volume(_)) => {
                let mut held = VolumeRecord::decode(value).map_err(|error| format!("{error:?}"))?;
                held.push(EventKind::Attach, host(9), ERA)
                    .ok_or("planted attach")?;
                held.encode()
            }
            _ => return Ok(write.clone()),
        };
        Ok(match write {
            Write::Create(_) => Write::Create(value),
            Write::Exact { expect, .. } => Write::Exact {
                expect: *expect,
                value,
            },
        })
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
                let written = self.planted(key, run.op.write_of(&key)?)?;
                self.requests.push((self.at, "write", key));
                self.store.schedule(arm);
                let outcome = inner.write(&key, &written);
                run.wrote |= matches!(outcome, Outcome::Committed(_))
                    || arm == (Arm::Timeout { commit: true });
                Reply::Write(outcome)
            }
        };
        run.served.push(key);
        run.op.answer(reply)?;
        let page = Key::Page(shard_of(run.shard), 0);
        let follows = match run.name.as_str() {
            "record" | "enroll" => matches!(key, Key::Shard(_)),
            "designate" => matches!(key, Key::Standbys(_)),
            _ => false,
        };
        if follows && matches!(run.op.pending(), Message::Read(asked) if *asked == page) {
            self.requests.push((self.at, "page", page));
            run.op.answer(Reply::Read(inner.read(&page)))?;
        }
        Ok(())
    }

    fn key_of(&self, key: &str, s: u64) -> Result<Key, String> {
        Ok(match key {
            "census" => Key::Standbys(Zone(ZONES[0])),
            "shard" => Key::Shard(shard_of(s)),
            "volume" => Key::Volume(self.active(s)?),
            _ => return Err("event key".into()),
        })
    }

    fn ended(run: &Running) -> Option<String> {
        match run.op.pending() {
            Message::Done(result) => Some(result.clone()),
            _ => None,
        }
    }

    /// Whether the stored census of the replay's zone exists and lists no entry for shard `s`.
    fn unlisted(&self, s: u64) -> Result<bool, String> {
        let census: Option<Census> = self.current(Key::Standbys(Zone(ZONES[0])))?;
        Ok(census.is_some_and(|census| census.slot(shard_of(s)).is_none()))
    }

    fn settle(&mut self, r: usize, res: &str) -> Result<(), String> {
        let shard = self.procs[r]
            .running
            .as_ref()
            .ok_or("the process runs no operation")?
            .shard;
        let unlisted = self.unlisted(shard)?;
        let run = self.procs[r]
            .running
            .as_mut()
            .ok_or("the process runs no operation")?;
        match (Self::ended(run), res) {
            (None, "") => Ok(()),
            (None, res) => Err(format!("the operation continues, modeled {res}")),
            (Some(_), "") if run.early => Ok(()),
            (Some(result), "")
                if run.name == "release"
                    && result == "unlisted"
                    && unlisted
                    && matches!(run.served.as_slice(), [Key::Standbys(_)]) =>
            {
                run.early = true;
                Ok(())
            }
            (Some(result), "") => Err(format!("the operation ended {result}")),
            (Some(result), res) if !agrees(&run.name, &result, run.wrote, res) => {
                Err(format!("result {result}, modeled {res}"))
            }
            (Some(_), _) => {
                let run = self.procs[r].running.take().expect("the run");
                run.op.finish()?;
                if let Some(out) = self.procs[r].reserved.take() {
                    self.procs[r].slot = *out.lock().unwrap();
                }
                Ok(())
            }
        }
    }

    /// Answers process `r`'s pending request for the record `key` names under `arm`, for an event that names the
    /// operation `named`, and settles its result against the model's `res`.
    fn request(
        &mut self,
        r: usize,
        named: (&str, u64, u64),
        key: &str,
        arm: Option<Arm>,
        res: &str,
    ) -> Result<(), String> {
        let mut run = self.procs[r]
            .running
            .take()
            .ok_or("the process runs no operation")?;
        let served = match run.names(named.0, named.1, named.2) {
            Err(error) => Err(error),
            Ok(())
                if run.early
                    && arm.is_none()
                    && ["shard", "volume"].get(run.skipped) == Some(&key) =>
            {
                run.skipped += 1;
                Ok(())
            }
            Ok(()) => self
                .key_of(key, run.shard)
                .and_then(|key| self.serve(&mut run, key, arm)),
        };
        self.procs[r].running = Some(run);
        served?;
        self.settle(r, res)
    }

    /// Requires process `r` to stand where the model's process stands at `state`: idle, or running the model's
    /// operation for its shard and host with the request the model's `pc` names pending. A release that returned
    /// at its census read stands at the model read it skips next.
    fn stands(&self, r: usize, state: &Value) -> Result<(), String> {
        let p = at(&state[PROCS], r as u64, "procs")?;
        let op = p["op"].as_str().ok_or("model op")?;
        let run = match (op, &self.procs[r].running) {
            ("idle", None) => return Ok(()),
            ("idle", Some(run)) => {
                return Err(format!(
                    "process {r} runs {}, the model's is idle",
                    run.name
                ));
            }
            (op, None) => return Err(format!("process {r} is idle, the model's runs {op}")),
            (_, Some(run)) => run,
        };
        run.names(op, num(&p["s"], "s")?, num(&p["h"], "h")?)?;
        let next = usize::try_from(num(&p["pc"], "pc")?)
            .ok()
            .and_then(|pc| order(op).get(pc).copied())
            .ok_or_else(|| format!("process {r} of the model stands at no request"))?;
        if run.early {
            if ["shard", "volume"].get(run.skipped) == Some(&next) {
                return Ok(());
            }
            return Err(format!(
                "process {r} returned early, the model's reads {next}"
            ));
        }
        if next != "write" {
            return run.op.read_of(&self.key_of(next, run.shard)?);
        }
        let written = match op {
            "reserve" | "release" => "census",
            "designate" => "shard",
            _ => "volume",
        };
        run.op.write_of(&self.key_of(written, run.shard)?).map(drop)
    }

    /// Requires the decided end to be the one the model's `en.ending` holds at `state`, with its volume write
    /// pending.
    fn decided(&self, state: &Value) -> Result<(), String> {
        let modeled = state[EN]["ending"]["#set"]
            .as_array()
            .ok_or("model ending")?
            .iter()
            .map(|end| match end["#tup"].as_array().map(Vec::as_slice) {
                Some([s, h, ..]) => Ok((num(s, "ending")?, num(h, "ending")?)),
                _ => Err(String::from("model ending")),
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let held: BTreeSet<_> = self
            .ending
            .iter()
            .map(|run| (run.shard, run.host))
            .collect();
        if held != modeled {
            return Err(format!("the decided end is {held:?}, modeled {modeled:?}"));
        }
        match &self.ending {
            Some(run) => run
                .op
                .write_of(&Key::Volume(self.active(run.shard)?))
                .map(drop),
            None => Ok(()),
        }
    }

    fn crash(&mut self, r: usize) {
        self.procs[r] = Proc::default();
    }

    /// Starts `end_attach` of host `h`'s attach of shard `s`'s volume and answers its shard and volume reads. The
    /// end's result is `named` or `unnamed` by [`AttachEnded::named`](crate::failover::reconcile::AttachEnded::named).
    fn end_read(&mut self, s: u64, h: u64) -> Result<(), String> {
        if self.ending.is_some() {
            return Err("an end is already decided".into());
        }
        if !self.shards.contains(&s) {
            return Err(format!("shard {s} lies outside the instance"));
        }
        let (shard, target) = (shard_of(s), self.known(h)?);
        let volume = self.active(s)?;
        let held: VolumeRecord = self.current(Key::Volume(volume))?.ok_or("volume record")?;
        let (seq, _) = held
            .latest(target)
            .ok_or("the host holds no attach entry")?;
        let seq = seq + u32::from(self.driver == Driver::OtherEntry);
        let unnamed = self.driver == Driver::Unnamed;
        let op = Op::start(move |proxy| {
            match Reconciler::new(open(proxy)).end_attach(
                &StandbyGate::qualified(),
                shard,
                volume,
                target,
                seq,
            ) {
                Ok(ended) if ended.named() && !unnamed => "named".into(),
                Ok(_) => "unnamed".into(),
                ended => outcome(ended),
            }
        })?;
        let mut run = Running::new(op, "end", s, h);
        self.serve(&mut run, Key::Shard(shard_of(s)), None)?;
        self.serve(&mut run, Key::Volume(self.active(s)?), None)?;
        self.ending = Some(run);
        Ok(())
    }

    /// Answers the decided end's volume write and, when it lands, its shard reread, requiring the reread's role bit
    /// to equal `named`, the model's shard record naming the host owner or standby; then runs the cleanup the model's
    /// one step holds.
    fn end_write(&mut self, s: u64, h: u64, lands: bool, named: bool) -> Result<(), String> {
        let mut run = self.ending.take().ok_or("no end is decided")?;
        run.names("end", s, h)?;
        let volume = self.active(s)?;
        self.serve(&mut run, Key::Volume(volume), Some(Arm::Pass))?;
        if lands {
            self.serve(&mut run, Key::Shard(shard_of(s)), None)?;
        }
        let result = Self::ended(&run).ok_or("the end continues")?;
        run.op.finish()?;
        match (lands, result.as_str()) {
            (true, "named" | "unnamed") if (result == "named") != named => {
                return Err(format!("the end reports {result}, modeled named {named}"));
            }
            (true, "named" | "unnamed") => {}
            (false, "condition") => return Ok(()),
            (_, result) => return Err(format!("the end ended {result}")),
        }
        let mut owner = client(&self.store);
        let read = owner
            .read::<VolumeRecord>(Key::Volume(volume))
            .map_err(|error| format!("pair drop read {error:?}"))?;
        let mut dropped = read.value().clone();
        dropped.pairs.retain(|pair| pair.host != host(h));
        owner
            .replace(&read, dropped)
            .map_err(|error| format!("pair drop {error:?}"))?;
        self.merge(s);
        if self.shard_record(s)?.owner == host(h) {
            let kept: VolumeRecord = self.current(Key::Volume(volume))?.ok_or("volume record")?;
            return match kept.latest(host(h)) {
                Some((_, entry)) if entry.kind == EventKind::Ended => Ok(()),
                latest => Err(format!("the owner's end left {latest:?}")),
            };
        }
        let log = Rc::default();
        let mut reconciler = Reconciler::new(open(Recording {
            store: AsReconciler(self.store.clone()),
            log: Rc::clone(&log),
            keep: self.driver == Driver::EndStaysEnded,
        }));
        let witness = reconciler
            .detachable(volume, host(h))
            .map_err(|error| format!("detachable {error:?}"))?;
        let listings = [
            Listing {
                at: 1,
                instances: &[],
            },
            Listing {
                at: 2,
                instances: &[],
            },
        ];
        if self.driver != Driver::SkipsGoneMark {
            reconciler
                .release_attach(
                    &StandbyGate::qualified(),
                    &witness,
                    &listings,
                    Settle {
                        requested: 0,
                        settle: 1,
                    },
                )
                .map_err(|error| format!("release_attach {error:?}"))?;
        }
        let cleanup = log.take();
        let key = Key::Volume(volume);
        if cleanup != [("read", key), ("read", key), ("write", key)] {
            return Err(format!("the end's cleanup requests {cleanup:?}"));
        }
        self.requests
            .extend(cleanup.into_iter().map(|(act, key)| (self.at, act, key)));
        let gone: VolumeRecord = self.current(Key::Volume(volume))?.ok_or("volume record")?;
        match gone.latest(host(h)) {
            Some((seq, entry)) if seq == witness.seq() && entry.kind == EventKind::Gone => {}
            latest => return Err(format!("release_attach left {latest:?}")),
        }
        self.merge(s);
        Ok(())
    }

    /// Counts one commit of shard `s`'s volume record that the model's end step holds within its one version: the
    /// owner's pair drop, or `release_attach`'s gone mark, each one exact-version write.
    fn merge(&mut self, s: u64) {
        *self.merged.entry(s).or_default() += 1;
    }

    fn tenure(&mut self, act: &str, s: u64, h: u64) -> Result<(), String> {
        let key = Key::Shard(shard_of(s));
        let mut owner = client(&self.store);
        let read = owner
            .read::<ShardRecord>(key)
            .map_err(|error| format!("{act} read {error:?}"))?;
        let held = *read.value();
        match act {
            "bump" => owner.bump(&read).map(drop),
            "fresh" => {
                owner
                    .bump(&read)
                    .map(drop)
                    .map_err(|error| format!("fresh {error:?}"))?;
                let page = CoveragePage {
                    fence: activation(held.generation.get()),
                    ..CoveragePage::default()
                };
                return self.put(Key::Page(shard_of(s), 0), page.encode());
            }
            "takeover" => owner
                .take_over(&read, Target::of(&held), held.standby.ok_or("takeover")?)
                .map(drop),
            "transfer" => {
                let moved = ShardRecord {
                    owner: held.standby.ok_or("transfer")?,
                    attempts: held.attempts.checked_add(1).ok_or("transfer")?,
                    standby: None,
                    ..held
                };
                return self.put(key, moved.encode());
            }
            "flip" => {
                let g = held.generation.get() + 1;
                let alone = BTreeSet::from([h]);
                let fresh = Self::volume(s, g, &alone, &alone)?;
                self.put(Key::Volume(fresh.volume), fresh.encode())?;
                let flipped = ShardRecord {
                    generation: ShardGeneration::new(g).ok_or("g")?,
                    active: fresh.volume,
                    owner: host(h),
                    attempts: 0,
                    standby: None,
                    ..held
                };
                return self.put(key, flipped.encode());
            }
            act => return Err(format!("no tenure step {act}")),
        }
        .map_err(|error| format!("{act} {error:?}"))
    }
}

/// The slot model process `r` holds at `state`: its shard, 0 for none, and the entry.
fn slot_of(state: &Value, r: u64) -> Result<(u64, Slotted), String> {
    let p = at(&state[PROCS], r, "procs")?;
    Ok((num(&p["ss"], "ss")?, slotted(&p["slot"])?))
}

/// The requests of each model operation in the model's order, as `order` of `quint/standbys.qnt` lists them; a
/// process at `pc` makes the request at that index next, and `write` is the operation's one write.
fn order(op: &str) -> &'static [&'static str] {
    match op {
        "reserve" | "release" => &["census", "shard", "volume", "write"],
        "designate" => &["volume", "shard", "census", "write"],
        "record" | "enroll" => &["volume", "shard", "write", "shard"],
        _ => &[],
    }
}

/// The choice of the model's `step` that a state's event `act` and `mbt::actionTaken` name.
fn leaf(act: &str, taken: &str) -> Option<&'static str> {
    Some(match (act, taken) {
        ("init", "init") => "init",
        ("read" | "plan", "begin" | "beginStep") => "begin",
        ("read" | "write", "request") => "request",
        ("crash", "crash") => "crash",
        ("commit" | "lost" | "hold", "unknown" | "faultStep") => "unknown",
        ("deliver", "deliver") => "deliver",
        ("lose", "lose") => "lose",
        ("occupy", "occupy") => "occupy",
        ("learn", "learn") => "learn",
        ("suspect", "suspect") => "suspect",
        ("attachEnds", "attachEnds" | "attachStep") => "attachEnds",
        ("endRead", "endRead") => "endRead",
        ("endWrite" | "endRefused", "endWrite") => "endWrite",
        ("bump", "bump") => "bump",
        ("fresh", "fresh") => "fresh",
        ("takeover", "takeover") => "takeover",
        ("transfer", "transfer") => "transfer",
        ("flip", "flip" | "flipStep") => "flip",
        _ => return None,
    })
}

/// The `(step choice, act, op, res, key)` of every state a replay reached, `init` first, and each production request
/// it answered with the state it answered it at.
struct Replayed {
    reached: Vec<(&'static str, String, String, String, String)>,
    requests: Vec<(usize, &'static str, Key)>,
}

fn replay(json: &str, driver: Driver) -> Result<Replayed, String> {
    let (states, meta) = states(json, MODEL, "standbys")?;
    let limits = &meta["limits"];
    let limit = |name: &str| {
        limits[name]
            .as_u64()
            .ok_or_else(|| format!("fixture limits {name}"))
    };
    let st0 = &states.first().ok_or("fixture states")?[ST];
    let mut replay = Replay {
        store: Shared::new(),
        states: &states,
        driver,
        cap: limit("cap")? as usize,
        attach_limit: limit("attach")?,
        shards: keys(&st0["shards"], "shards")?,
        hosts: keys(&st0["outside"], "hosts")?,
        evidence: Arc::default(),
        procs: Default::default(),
        ending: None,
        merged: Default::default(),
        requests: Vec::new(),
        at: 0,
    };
    let shards = replay
        .shards
        .iter()
        .all(|&s| u32::try_from(s).ok().and_then(Shard::new).is_some());
    let hosts = replay
        .hosts
        .iter()
        .all(|&h| u8::try_from(h).is_ok_and(|h| h > 0));
    if !shards || !hosts {
        return Err("fixture instance".into());
    }
    let mut reached = Vec::new();
    for (i, state) in states.iter().enumerate() {
        replay.at = i;
        let ev = &state[EV];
        let field = |key: &str| ev[key].as_str().ok_or_else(|| format!("event {key}"));
        let (act, op, key, res) = (field("act")?, field("op")?, field("key")?, field("res")?);
        let number = |key: &str| ev[key].as_u64().ok_or_else(|| format!("event {key}"));
        let (r, s, h) = (number("proc")? as usize, number("s")?, number("h")?);
        if (s != 0 && !replay.shards.contains(&s)) || (h != 0 && !replay.hosts.contains(&h)) {
            return Err(format!(
                "{act} at {i}: event ({s}, {h}) lies outside the instance"
            ));
        }
        let taken = state["mbt::actionTaken"].as_str().unwrap_or_default();
        let fail = |what: String| format!("{act} at {i}: {what}");
        let leaf = leaf(act, taken)
            .ok_or_else(|| format!("action {i}: unknown action {act} ({taken})"))?;
        let proc =
            || -> Result<usize, String> { (r < 2).then_some(r).ok_or("event proc range".into()) };
        match leaf {
            "init" if i == 0 => replay.seed(&state[ST]).map_err(fail)?,
            "begin" if act == "plan" => {
                let r = proc()?;
                if replay.procs[r].running.is_some() {
                    return Err(fail("the process already runs an operation".into()));
                }
                replay.procs[r].slot = None;
            }
            "begin" => {
                let r = proc()?;
                if replay.procs[r].running.is_some() {
                    return Err(fail("the process already runs an operation".into()));
                }
                if op == "reserve" {
                    replay.procs[r].slot = None;
                }
                let run = replay.begin(r, op, s, h).map_err(fail)?;
                replay.procs[r].running = Some(run);
                replay
                    .request(r, (op, s, h), key, None, res)
                    .map_err(fail)?;
            }
            "request" => {
                let arm = (act == "write").then_some(Arm::Pass);
                replay
                    .request(proc()?, (op, s, h), key, arm, res)
                    .map_err(fail)?;
            }
            "unknown" => {
                let arm = match act {
                    "commit" => Arm::Timeout { commit: true },
                    "lost" => Arm::Timeout { commit: false },
                    _ => Arm::Hold,
                };
                replay
                    .request(proc()?, (op, s, h), key, Some(arm), res)
                    .map_err(fail)?;
            }
            "crash" => replay.crash(proc()?),
            "deliver" => {
                let parked = replay
                    .store
                    .0
                    .borrow()
                    .parked()
                    .front()
                    .map(|(key, _)| *key);
                let named = match (key, parked) {
                    ("census", Some(Key::Standbys(zone))) => zone == Zone(ZONES[0]),
                    ("shard", Some(Key::Shard(shard))) => shard == shard_of(s),
                    ("volume", Some(Key::Volume(volume))) => replay
                        .shard_record(s)
                        .map_err(fail)?
                        .generation
                        .get()
                        .checked_add(1)
                        .is_some_and(|last| (1..last).any(|g| volume_of(s, g) == volume)),
                    _ => false,
                };
                if !named {
                    return Err(fail(format!("the held write is {parked:?}")));
                }
                let landed = match replay.store.release().as_slice() {
                    [Outcome::Committed(_)] => "committed",
                    [Outcome::NotCommitted(Refusal::Condition)] => "refused",
                    outcomes => return Err(fail(format!("released {outcomes:?}"))),
                };
                if landed != res {
                    return Err(fail(format!("released {landed}, modeled {res}")));
                }
            }
            "lose" | "occupy" => {}
            "learn" | "suspect" => {
                replay.evidence.lock().unwrap().seen[proc()?].insert(h);
            }
            "attachEnds" => match res {
                _ if s == 0 || h == 0 => return Err(fail(format!("attach ({s}, {h})"))),
                "attached" => {}
                "failed" => {
                    replay.evidence.lock().unwrap().failed.insert((s, h));
                }
                res => return Err(fail(format!("attach result {res}"))),
            },
            "endRead" => replay.end_read(s, h).map_err(fail)?,
            "endWrite" => {
                let modeled = at(&state[ST]["shards"], s, "shard").map_err(fail)?;
                let named = num(&modeled["owner"], "owner").map_err(fail)? == h
                    || num(&modeled["standby"], "standby").map_err(fail)? == h;
                replay
                    .end_write(s, h, act == "endWrite", named)
                    .map_err(fail)?;
            }
            "flip" => {
                if replay.ending.as_ref().is_some_and(|run| run.shard == s) {
                    replay.ending = None;
                }
                replay
                    .evidence
                    .lock()
                    .unwrap()
                    .failed
                    .retain(|&(x, _)| x != s);
                replay.tenure(act, s, h).map_err(fail)?;
            }
            "bump" | "fresh" | "takeover" | "transfer" => {
                replay.tenure(leaf, s, h).map_err(fail)?
            }
            leaf => return Err(fail(format!("{leaf} has no step here"))),
        }
        let seen = replay.seen().map_err(fail)?;
        let model = modeled(&state[ST]).map_err(fail)?;
        if seen != model {
            return Err(fail(format!("stored {seen:?}, modeled {model:?}")));
        }
        for (r, proc) in replay.procs.iter().enumerate() {
            let held = proc.slot.map_or((0, NO_SLOT), |slot| {
                (
                    slot.shard().get().into(),
                    held_slot(&slot.target(), slot.host()),
                )
            });
            let modeled = slot_of(state, r as u64).map_err(fail)?;
            if held != modeled {
                return Err(fail(format!(
                    "slot of process {r}: held {held:?}, modeled {modeled:?}"
                )));
            }
            replay.stands(r, state).map_err(fail)?;
        }
        replay.decided(state).map_err(fail)?;
        reached.push((
            leaf,
            act.to_owned(),
            op.to_owned(),
            res.to_owned(),
            key.to_owned(),
        ));
    }
    Ok(Replayed {
        reached,
        requests: replay.requests,
    })
}

fn fixture(name: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(fixture, _)| *fixture == name)
        .unwrap()
        .1
}

/// Every committed trace replays with each request, each result and the stored records equal to the model's at every
/// state. Together the traces reach `init` and every event `act` the model records at each choice of the model's
/// `step` that records it, and the operations end with each result [`RESULTS`] names; the directed traces alone,
/// those whose name does not start with `step_`, reach the same acts, results and answers, so the coverage holds
/// whatever the seeded runs draw. The model's `step` lines are pinned, so a model whose `step` chooses among other
/// actions fails here.
#[test]
fn committed_standbys_traces_replay_and_reach_every_step_choice() {
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
    let model = std::str::from_utf8(MODEL).unwrap();
    for choice in [
        "    any {request(r), crash(r)}\n",
        "    any {lose(h), occupy(h)}\n",
        "    any {learn(r, h), suspect(r, h)}\n",
        "    attachEnds(s, h, completes)\n",
        "    any {endRead(s, h), endWrite(s, h)}\n",
        "    any {bump(s), fresh(s), takeover(s), transfer(s)}\n",
        "    flip(s, h)\n",
        "    unknown(r, fault)\n",
        "    begin(r, op, s, h)\n",
        "  action step = any {beginStep, procStep, faultStep, deliver, hostStep, evidenceStep, attachStep, endStep,\n    tenureStep, flipStep}\n",
    ] {
        assert!(
            model.contains(choice),
            "the model's step chooses among other actions than the replay drives: {choice}"
        );
    }
    type Reached = BTreeSet<(&'static str, String, String, String, String)>;
    let acts = |reached: &Reached| -> BTreeSet<(String, &'static str)> {
        reached
            .iter()
            .map(|(leaf, act, ..)| (act.clone(), *leaf))
            .collect()
    };
    assert_eq!(acts(&directed), acts(&reached));
    assert_eq!(
        acts(&reached)
            .iter()
            .map(|(act, leaf)| (act.as_str(), *leaf))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ("attachEnds", "attachEnds"),
            ("bump", "bump"),
            ("commit", "unknown"),
            ("crash", "crash"),
            ("deliver", "deliver"),
            ("endRead", "endRead"),
            ("endRefused", "endWrite"),
            ("endWrite", "endWrite"),
            ("flip", "flip"),
            ("fresh", "fresh"),
            ("hold", "unknown"),
            ("init", "init"),
            ("learn", "learn"),
            ("lose", "lose"),
            ("lost", "unknown"),
            ("occupy", "occupy"),
            ("plan", "begin"),
            ("read", "begin"),
            ("read", "request"),
            ("suspect", "suspect"),
            ("takeover", "takeover"),
            ("transfer", "transfer"),
            ("write", "request"),
        ])
    );
    let results = |reached: &Reached| -> BTreeSet<(String, String)> {
        reached
            .iter()
            .filter(|(_, _, op, res, _)| !op.is_empty() && !res.is_empty())
            .map(|(_, _, op, res, _)| (op.clone(), res.clone()))
            .collect()
    };
    assert_eq!(results(&directed), results(&reached));
    assert_eq!(
        results(&reached)
            .iter()
            .map(|(op, res)| (op.as_str(), res.as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(RESULTS)
    );
    let answers = |reached: &Reached| -> BTreeSet<(String, String, String)> {
        reached
            .iter()
            .filter(|(_, _, op, res, _)| op.is_empty() && !res.is_empty())
            .map(|(_, act, _, res, key)| (act.clone(), key.clone(), res.clone()))
            .collect()
    };
    assert_eq!(answers(&directed), answers(&reached));
    assert_eq!(
        answers(&reached)
            .iter()
            .map(|(act, key, res)| (act.as_str(), key.as_str(), res.as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ("attachEnds", "", "attached"),
            ("attachEnds", "", "failed"),
            ("deliver", "census", "committed"),
            ("deliver", "shard", "refused"),
            ("deliver", "volume", "committed"),
        ])
    );
}

#[test]
fn each_standby_request_falls_on_its_model_step_and_page_zero_reads_pass_through() {
    let volume = Key::Volume(volume_of(1, 1));
    let (census, shard, page) = (
        Key::Standbys(Zone(1)),
        Key::Shard(shard_of(1)),
        Key::Page(shard_of(1), 0),
    );
    let replayed = replay(fixture("run_enrollOne"), Driver::Faithful).unwrap();
    let standby: Vec<_> = replayed
        .requests
        .iter()
        .copied()
        .filter(|&(at, ..)| (5..=17).contains(&at))
        .collect();
    assert_eq!(
        standby,
        [
            (5, "read", volume),
            (6, "read", shard),
            (6, "page", page),
            (7, "write", volume),
            (8, "read", shard),
            (8, "page", page),
            (10, "read", volume),
            (11, "read", shard),
            (11, "page", page),
            (12, "write", volume),
            (13, "read", shard),
            (13, "page", page),
            (14, "read", volume),
            (15, "read", shard),
            (16, "read", census),
            (16, "page", page),
            (17, "write", shard),
        ]
    );
    // run_designateReadsCensusAfterShard: process 0's designation reads the volume record at state 5, the shard
    // record at state 6 and, after process 1's designation, the census at state 16.
    let designation: Vec<_> = replay(
        fixture("run_designateReadsCensusAfterShard"),
        Driver::Faithful,
    )
    .unwrap()
    .requests
    .into_iter()
    .filter(|&(at, act, _)| [5, 6, 16].contains(&at) && act != "page")
    .collect();
    assert_eq!(
        designation,
        [
            (5, "read", volume),
            (6, "read", shard),
            (16, "read", census)
        ]
    );
    let release: Vec<_> = replay(
        fixture("run_releaseReadsShardAfterCensus"),
        Driver::Faithful,
    )
    .unwrap()
    .requests
    .into_iter()
    .filter(|&(at, ..)| [5, 12, 13, 14].contains(&at))
    .collect();
    assert_eq!(
        release,
        [
            (5, "read", census),
            (12, "read", shard),
            (13, "read", volume),
            (14, "write", census),
        ]
    );
    // The driver runs `detachable` and `release_attach` in the `endWrite` step at state 10.
    let end: Vec<_> = replay(fixture("replay_endRecordedAttach"), Driver::Faithful)
        .unwrap()
        .requests
        .into_iter()
        .filter(|&(at, ..)| at == 10)
        .collect();
    assert_eq!(
        end,
        [
            (10, "write", volume),
            (10, "read", shard),
            (10, "read", volume),
            (10, "read", volume),
            (10, "write", volume),
        ]
    );
}

#[test]
#[ignore = "generated standbys traces; the quint lane runs it with Quint on PATH"]
fn generated_standbys_traces_replay() {
    let traces = ReplayScratch::run("standbys", "standbys_fixtures.py", &["--timeout", "0"]);
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
fn negative_control_a_designation_given_the_other_slot_fails_the_standbys_replay() {
    assert_eq!(
        replay(
            fixture("run_designateReadsCensusAfterShard"),
            Driver::OtherSlot
        )
        .err(),
        Some("read at 14: the operation ended conflict".into())
    );
}

/// Each wrong driver breaks one fact the replay compares, and the replay refuses it at the step that shows it: a
/// release that returns `unlisted` at its census read while the census lists its shard; an end that reports the host
/// unnamed while the shard record names it standby; a census write that holds an entry outside the instance; a
/// volume write that holds a live attach outside the instance.
#[test]
fn negative_control_a_driver_that_breaks_a_compared_fact_fails_the_standbys_replay() {
    // replay_releaseKeptStandby: process 1's release reads a census that lists shard 1 at state 11.
    assert_eq!(
        replay(
            fixture("replay_releaseKeptStandby"),
            Driver::UnlistedRelease
        )
        .err(),
        Some("read at 11: the operation ended unlisted".into())
    );
    // recipe_designationBeforeEndLands: the end lands at state 10 on a shard record that names host 2 standby.
    assert_eq!(
        replay(fixture("recipe_designationBeforeEndLands"), Driver::Unnamed).err(),
        Some("endWrite at 10: the end reports unnamed, modeled named true".into())
    );
    assert_eq!(
        replay(fixture("run_enrollOne"), Driver::ExtraCensusEntry).err(),
        Some("write at 4: the census of zone 1 holds shard 9".into())
    );
    // run_enrollOne: the attach record reads the volume record at state 5 and the shard record at state 6, and
    // writes the volume record at state 7. A page read after the volume read, and a read of another page after
    // the shard read, stay pending where the model's process stands at its next request.
    assert_eq!(
        replay(fixture("run_enrollOne"), Driver::PageAfterVolume).err(),
        Some("read at 5: the operation reads Page(Shard(1), 0)".into())
    );
    assert_eq!(
        replay(fixture("run_enrollOne"), Driver::OtherPage).err(),
        Some("read at 6: the operation reads Page(Shard(1), 1)".into())
    );
    // recipe_unlistedKeepsCensus: process 1's release reads a census that lists no entry for shard 2 at state 5,
    // and the model reads the shard record at state 6. A release that returns only after its shard read ends there.
    assert_eq!(
        replay(
            fixture("recipe_unlistedKeepsCensus"),
            Driver::LateUnlistedRelease
        )
        .err(),
        Some("read at 6: the operation ended unlisted".into())
    );
    // replay_endRecordedAttach: the end is decided at state 9, with its volume write pending. An end asked for
    // another entry returns there with no write.
    assert_eq!(
        replay(fixture("replay_endRecordedAttach"), Driver::OtherEntry).err(),
        Some("endRead at 9: the operation ended conflict".into())
    );
    // replay_endRecordedAttach: the end lands at state 10. A cleanup with no `release_attach` call makes one read,
    // and a gone mark that commits the record it read leaves the entry ended.
    let volume = Key::Volume(volume_of(1, 1));
    assert_eq!(
        replay(fixture("replay_endRecordedAttach"), Driver::SkipsGoneMark).err(),
        Some(format!(
            "endWrite at 10: the end's cleanup requests {:?}",
            [("read", volume)]
        ))
    );
    let ended = replay(fixture("replay_endRecordedAttach"), Driver::EndStaysEnded)
        .err()
        .unwrap_or_default();
    assert!(
        ended.starts_with("endWrite at 10: release_attach left Some(") && ended.contains("Ended"),
        "{ended}"
    );
    let error = replay(fixture("run_enrollOne"), Driver::ExtraLiveHost)
        .err()
        .unwrap_or_default();
    assert!(
        error.starts_with("write at 7: stored ") && error.contains("volumes: [({1, 3, 9}, {1}, 2)"),
        "{error}"
    );
}

/// A trace altered in one compared field of one state fails at that state, through the comparison that reads the
/// field: a census entry, a shard record's standby, a volume record's enrolled set and the held write through the
/// stored records, a process's slot through the slot comparison, an event's result through the result comparison
/// and an event's key through the request match. A stale model digest or a missing state fails the trace before
/// any state replays.
#[test]
fn negative_control_an_altered_standbys_trace_fails_at_the_altered_state() {
    let altered = |name: &str, at: usize, edit: &dyn Fn(&mut Value)| {
        let mut trace: Value = serde_json::from_str(fixture(name)).unwrap();
        edit(&mut trace["states"][at]);
        replay(&trace.to_string(), Driver::Faithful)
            .err()
            .unwrap_or_default()
    };
    let seen = |name: &str, at: usize, edit: &dyn Fn(&mut Value)| {
        let mut state: Value =
            serde_json::from_str::<Value>(fixture(name)).unwrap()["states"][at].take();
        edit(&mut state);
        super::replay_driver::plain(&mut state).unwrap();
        modeled(&state[ST]).unwrap()
    };
    let number = |value: u64| serde_json::json!({ "#bigint": value.to_string() });
    let stored = |act: &str, name: &str, at: usize, edit: &dyn Fn(&mut Value)| {
        format!(
            "{act} at {at}: stored {:?}, modeled {:?}",
            seen(name, at, &|_| {}),
            seen(name, at, edit)
        )
    };
    // run_enrollOne: the reservation writes the census at state 4, the enrollment writes the volume record at
    // state 12 and the designation writes the shard record at state 17.
    let census = |state: &mut Value| {
        state[ST]["census"]["#map"][0][1]["slots"]["#map"][0][1]["host"] = number(2);
    };
    assert_eq!(
        altered("run_enrollOne", 4, &census),
        stored("write", "run_enrollOne", 4, &census)
    );
    let standby = |state: &mut Value| state[ST]["shards"]["#map"][0][1]["standby"] = number(2);
    assert_eq!(
        altered("run_enrollOne", 17, &standby),
        stored("write", "run_enrollOne", 17, &standby)
    );
    let enrolled = |state: &mut Value| {
        state[ST]["volumes"]["#map"][0][1]["enrolled"] = serde_json::json!({ "#set": [number(1)] });
    };
    assert_eq!(
        altered("run_enrollOne", 12, &enrolled),
        stored("write", "run_enrollOne", 12, &enrolled)
    );
    // replay_releaseHeldDelivered: the release's census write is held at state 11.
    let held = |state: &mut Value| state[ST]["held"]["on"] = false.into();
    assert_eq!(
        altered("replay_releaseHeldDelivered", 11, &held),
        stored("hold", "replay_releaseHeldDelivered", 11, &held)
    );
    assert_eq!(
        altered("run_enrollOne", 4, &|state| {
            state["standbysCase::standbys::procs"]["#map"][0][1]["slot"]["host"] = number(2);
        }),
        "write at 4: slot of process 0: held (1, (true, 1, 1, 1, 3)), modeled (1, (true, 1, 1, 1, 2))"
    );
    assert_eq!(
        altered("run_enrollOne", 4, &|state| state[EV]["res"] =
            "listed".into()),
        "write at 4: result ok, modeled listed"
    );
    assert_eq!(
        altered("run_enrollOne", 2, &|state| state[EV]["key"] =
            "volume".into()),
        "read at 2: the operation reads Shard(Shard(1))"
    );
    // replay_enrollConditionLost: process 1 begins its enrollment at state 11 while process 0 runs its own.
    assert_eq!(
        altered(
            "replay_enrollConditionLost",
            11,
            &|state| state[EV]["proc"] = number(0)
        ),
        "read at 11: the process already runs an operation"
    );
    // run_enrollOne: the reservation writes the census at state 4.
    assert_eq!(
        altered("run_enrollOne", 4, &|state| state[EV]["key"] =
            "volume".into()),
        "write at 4: the operation writes Standbys(Zone(1))"
    );
    // run_enrollOne: the reservation's shard read at state 2 leaves it running.
    assert_eq!(
        altered("run_enrollOne", 2, &|state| state[EV]["res"] =
            "ineligible".into()),
        "read at 2: the operation continues, modeled ineligible"
    );
    assert_eq!(
        altered("run_enrollOne", 2, &|state| state[EV]["s"] = number(2)),
        "read at 2: the event names reserve(2, 3), the process runs reserve(1, 3)"
    );
    assert_eq!(
        altered("run_enrollOne", 0, &|state| {
            state[ST]["shards"]["#map"][0][1]["g"] = number(5);
        }),
        "init at 0: shard 1 generation 5"
    );
    assert_eq!(
        altered("run_reservedAfterEnrollBetweenReads", 16, &|state| {
            state[ST]["outside"]["#map"][2][1] = u64::MAX.into();
        }),
        "read at 10: model outside count"
    );
    let ends_at = |name: &str, act: &str| {
        let trace: Value = serde_json::from_str(fixture(name)).unwrap();
        trace["states"]
            .as_array()
            .unwrap()
            .iter()
            .position(|state| state[EV]["act"] == act)
            .unwrap()
    };
    let attach = ends_at("replay_enrollUnknownLost", "attachEnds");
    assert_eq!(
        altered("replay_enrollUnknownLost", attach, &|state| {
            state[EV]["res"] = "other".into();
        }),
        "attachEnds at 9: attach result other"
    );
    assert_eq!(
        altered(
            "replay_enrollUnknownLost",
            attach,
            &|state| state[EV]["h"] = number(9)
        ),
        "attachEnds at 9: event (1, 9) lies outside the instance"
    );
    // recipe_unlistedKeepsCensus: the release returns at its census read at state 5, and the model reads the shard
    // record at state 6 and the volume record at state 7, in that order.
    assert_eq!(
        altered("recipe_unlistedKeepsCensus", 6, &|state| state[EV]["key"] =
            "volume".into()),
        "read at 6: the operation ended unlisted"
    );
    // replay_endRecordedAttach: the end's write lands at state 10 and the end goes on to its shard reread, so a
    // trace that records the write refused finds the end still running.
    assert_eq!(
        altered("replay_endRecordedAttach", 10, &|state| state[EV]["act"] =
            "endRefused".into()),
        "endRefused at 10: the end continues"
    );
    // run_enrollOne: the action recorded at state 4 is a `request`, which the event's `write` names.
    assert_eq!(
        altered("run_enrollOne", 4, &|state| state["mbt::actionTaken"] =
            "crash".into()),
        "action 4: unknown action write (crash)"
    );
    // replay_releaseHeldDelivered: the held census write is delivered and commits at state 12.
    assert_eq!(
        altered(
            "replay_releaseHeldDelivered",
            12,
            &|state| state[EV]["key"] = "shard".into()
        ),
        "deliver at 12: the held write is Some(Standbys(Zone(1)))"
    );
    assert_eq!(
        altered(
            "replay_releaseHeldDelivered",
            12,
            &|state| state[EV]["res"] = "refused".into()
        ),
        "deliver at 12: released committed, modeled refused"
    );
    // A delivery event must name the same shard as the held write's volume record.
    let delivered = altered("replay_recordHeldDelivered", 8, &|state| {
        state[EV]["s"] = number(2);
    });
    assert!(
        delivered.starts_with("deliver at 8: the held write is Some(Volume("),
        "{delivered}"
    );
    // run_enrollOne: after state 2 the model's reservation stands at its volume read, `pc` 2.
    let stands = altered("run_enrollOne", 2, &|state| {
        state[PROCS]["#map"][0][1]["pc"] = number(3);
    });
    assert!(
        stands.starts_with("read at 2: the operation reads Volume("),
        "{stands}"
    );
    assert_eq!(
        altered("run_enrollOne", 2, &|state| {
            state[PROCS]["#map"][0][1]["op"] = "idle".into();
        }),
        "read at 2: process 0 runs reserve, the model's is idle"
    );
    // replay_endEnrolledAttach: the end of host 3's attach of shard 1's volume is decided at its `endRead` state.
    let decided = ends_at("replay_endEnrolledAttach", "endRead");
    assert_eq!(
        altered("replay_endEnrolledAttach", decided, &|state| {
            state[EN]["ending"] = serde_json::json!({ "#set": [] });
        }),
        format!("endRead at {decided}: the decided end is {{(1, 3)}}, modeled {{}}")
    );
    let mut wrapped: Value = serde_json::from_str(fixture("replay_enrollUnknownLost")).unwrap();
    wrapped["states"][attach]["mbt::actionTaken"] = "attachStep".into();
    assert!(replay(&wrapped.to_string(), Driver::Faithful).is_ok());
    let json = fixture("run_enrollOne");
    let stale = json.replacen(r#""model_sha256":""#, r#""model_sha256":"0"#, 1);
    assert_eq!(
        replay(&stale, Driver::Faithful).err(),
        Some("fixture model digest".into())
    );
    let mut short: Value = serde_json::from_str(json).unwrap();
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

/// Every field the replay compares in the stored records and in a process's slot is compared: the last state of
/// `run_enrollOne`, altered in one field of the model's census of either zone, of a census entry, of either shard
/// record, of either shard's volume record or of the held write, fails at that state through the record
/// comparison, and altered in one field of process 0's slot through the slot comparison.
#[test]
fn negative_control_each_compared_field_altered_fails_the_standbys_replay() {
    let name = "run_enrollOne";
    let trace: Value = serde_json::from_str(fixture(name)).unwrap();
    let at = trace["states"].as_array().unwrap().len() - 1;
    let number = |value: u64| serde_json::json!({ "#bigint": value.to_string() });
    let some = |hosts: &[u64]| serde_json::json!({ "#set": hosts.iter().map(|&h| number(h)).collect::<Vec<_>>() });
    let modeled_after = |edit: &dyn Fn(&mut Value)| {
        let mut state = trace["states"][at].clone();
        edit(&mut state);
        super::replay_driver::plain(&mut state).unwrap();
        modeled(&state[ST]).unwrap()
    };
    let replayed = |edit: &dyn Fn(&mut Value)| {
        let mut trace = trace.clone();
        edit(&mut trace["states"][at]);
        replay(&trace.to_string(), Driver::Faithful)
            .err()
            .unwrap_or_default()
    };
    type Edit<'a> = (&'a str, &'a dyn Fn(&mut Value));
    let records: [Edit; 20] = [
        ("census version", &|state| {
            row(&mut state[ST]["census"], 1)["ver"] = number(2)
        }),
        ("entry on", &|state| {
            row(&mut row(&mut state[ST]["census"], 1)["slots"], 1)["on"] = false.into()
        }),
        ("entry g", &|state| {
            row(&mut row(&mut state[ST]["census"], 1)["slots"], 1)["g"] = number(2)
        }),
        ("entry owner", &|state| {
            row(&mut row(&mut state[ST]["census"], 1)["slots"], 1)["owner"] = number(2)
        }),
        ("entry e", &|state| {
            row(&mut row(&mut state[ST]["census"], 1)["slots"], 1)["e"] = number(2)
        }),
        ("entry host", &|state| {
            row(&mut row(&mut state[ST]["census"], 1)["slots"], 1)["host"] = number(2)
        }),
        ("entry of shard 2", &|state| {
            row(&mut row(&mut state[ST]["census"], 1)["slots"], 2)["on"] = true.into()
        }),
        ("zone 2 version", &|state| {
            row(&mut state[ST]["census"], 2)["ver"] = number(1)
        }),
        ("zone 2 entry", &|state| {
            row(&mut row(&mut state[ST]["census"], 2)["slots"], 1)["on"] = true.into()
        }),
        ("shard g", &|state| {
            row(&mut state[ST]["shards"], 1)["g"] = number(2)
        }),
        ("shard owner", &|state| {
            row(&mut state[ST]["shards"], 1)["owner"] = number(2)
        }),
        ("shard e", &|state| {
            row(&mut state[ST]["shards"], 1)["e"] = number(2)
        }),
        ("shard standby", &|state| {
            row(&mut state[ST]["shards"], 1)["standby"] = number(2)
        }),
        ("shard version", &|state| {
            row(&mut state[ST]["shards"], 1)["ver"] = number(3)
        }),
        ("shard 2 owner", &|state| {
            row(&mut state[ST]["shards"], 2)["owner"] = number(3)
        }),
        ("volume live", &|state| {
            row(&mut state[ST]["volumes"], 1)["live"] = some(&[1])
        }),
        ("volume enrolled", &|state| {
            row(&mut state[ST]["volumes"], 1)["enrolled"] = some(&[1])
        }),
        ("volume version", &|state| {
            row(&mut state[ST]["volumes"], 1)["ver"] = number(4)
        }),
        ("volume 2 version", &|state| {
            row(&mut state[ST]["volumes"], 2)["ver"] = number(2)
        }),
        ("held", &|state| state[ST]["held"]["on"] = true.into()),
    ];
    let stored = modeled_after(&|_| {});
    for (field, edit) in records {
        let altered = modeled_after(edit);
        assert_ne!(altered, stored, "{field}");
        assert_eq!(
            replayed(edit),
            format!("write at {at}: stored {stored:?}, modeled {altered:?}"),
            "{field}"
        );
    }
    type Slot<'a> = (&'a str, &'a dyn Fn(&mut Value), &'a str);
    let slots: [Slot; 6] = [
        (
            "slot shard",
            &|p| p["ss"] = number(2),
            "(2, (true, 1, 1, 1, 3))",
        ),
        (
            "slot on",
            &|p| p["slot"]["on"] = false.into(),
            "(1, (false, 1, 1, 1, 3))",
        ),
        (
            "slot g",
            &|p| p["slot"]["g"] = number(2),
            "(1, (true, 2, 1, 1, 3))",
        ),
        (
            "slot owner",
            &|p| p["slot"]["owner"] = number(2),
            "(1, (true, 1, 2, 1, 3))",
        ),
        (
            "slot e",
            &|p| p["slot"]["e"] = number(2),
            "(1, (true, 1, 1, 2, 3))",
        ),
        (
            "slot host",
            &|p| p["slot"]["host"] = number(2),
            "(1, (true, 1, 1, 1, 2))",
        ),
    ];
    for (field, edit, modeled) in slots {
        assert_eq!(
            replayed(&|state| edit(row(&mut state[PROCS], 0))),
            format!(
                "write at {at}: slot of process 0: held (1, (true, 1, 1, 1, 3)), modeled {modeled}"
            ),
            "{field}"
        );
    }
}

/// The committed fixture directory holds exactly the traces `FIXTURES` names, so a generated trace the list omits
/// fails here.
#[test]
fn the_fixture_list_names_every_committed_trace() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/failover/standbys_replay_fixtures");
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
