//! Warm-load histories: a first tenure publishes a capture pass as a
//! checkpoint and closes, and its successor attaches the same media warm
//! from the record that names that checkpoint.
//!
//! - `wl1-closed-pass-lost`: key 2 is filled and published, a capture pass
//!   is published, the tenure's suffix opens, key 3 is filled and published,
//!   the storage closes and drains, and a second pass is attempted after the
//!   drain and published when its start succeeds. `wl1-closed-without-pass`
//!   runs the same steps with no pass after the drain.
//! - `wl2-fill-in-pass-lost`: the first pass starts, then key 2 is filled
//!   and published while that pass is in flight. `wl2-fill-before-pass`
//!   publishes key 2 before the pass starts.
//! - Each `wl1` and `wl2` control is its passing sibling with one key's
//!   restore row withheld from the judgment: key 3 for
//!   `wl1-without-pass-judged-unrestored` and key 1 for
//!   `wl2-before-pass-judged-unrestored`. The key's data and its GET stay as
//!   in the sibling, and the control still needs an `Open` load and every
//!   published key served.
//! - Each loss history's violation counts only when the run records the
//!   required loss marks: every published key for `wl1-closed-pass-lost`,
//!   and key 2 for `wl2-fill-in-pass-lost`. A violating run ends
//!   `Unsuccessful` under its first missing mark.
//!
//! The `wl1` and `wl2` histories then close the first owner, relaunch it
//! warm, GET each published key from the successor and judge the restore
//! rows.
//!
//! Property: "a retained entry outside every damage set was lost on host
//! loss", array `ORACLE` of
//! `crates/kestrike/src/net/world_tests/narrate/rules.rs`, under
//! `Obligation::Restart`.
//!
//! The `wl3` histories judge the same rule text under `CAPPED`, whose entry
//! cap of 3 lies below the eight slots of the `Geometry::Warm` pool. The
//! tenure publishes keys 1 to 3, publishes a capture pass, opens its suffix
//! and attempts the fill of key 4. The entry-cap guard of a fill
//! publication (`install` in `storage/publication.rs`) refuses key 4
//! `History`, the history's witness, and the successor serves keys 1 to 3.
//! The control's tenure records under `WIDE`, acknowledges key 4, and its
//! successor loads under `CAPPED`, which refuses `Entries`. The world's next
//! scene starts only after an `Open` load, so `Mixed::probe_warm` reads the
//! load of a tenure that acknowledged key 4 over a copy of its media. That
//! control starts no successor and issues no GET: the judgment records a
//! restore row for each published key resident in the probe's storage.
//!
//! The `wl4` histories judge the obligation record
//! `warm-activation-commits-allocation-before-fills` of
//! `verification/obligations.json`, "Restored entries grant nothing below
//! Live and serve their exact bytes at Live", through the rule text "a
//! retained entry outside every damage set was never served after host
//! loss" of the same array. Two warm loads of one record sample scripted
//! clocks placed by key 2's portable deadline. The first load is of a
//! tenure with no owner, which `Mixed::relaunch_warm_after` runs between
//! the incarnations: it reads key 2 expired and keeps its units, and the
//! tenure writes a fill whose publication is refused. The second load, the
//! next incarnation's, reads key 2 alive, and the passing history's
//! witnesses are the first load's `Expired` lookup of key 2, the tenure's
//! allocator holding key 2's unit across the fill, the unit the fill left
//! and the GET that serves key 2's exact bytes. The control steps the clock
//! back between the loads: its first load reads two seconds past the
//! deadline and frees key 2's units, the fill rewrites them, and the second
//! load restores key 2 over the rewritten unit, whose GET reads a header
//! that names another key and serves no exact bytes.
//!
//! The `wl5` histories judge the lost-entry rule over the hold order of a
//! coverage page write (`Owner::cover_begin`). They follow "The history" of
//! `net/takeover_history_tests/hold_order.rs` on one tenure and its warm
//! successor. The tenure fences both coverage pages over a store the family
//! keeps and installs the fencing. It takes four INVALIDATEs of key 2 at
//! versions 1, 5, 9 and 13, each acknowledged by its page write, which
//! brings the key to the fencing's four intervals. It then holds a burst
//! without writing it: key 2 at 17, key 2 at 30, then 20 other keys of key
//! 2's page, the first 16 each after a key of the other page, all at
//! version 1 and of no object: 38 entries, 22 of them on key 2's page. A
//! held entry is named by its key, its interval, its page and its position
//! in the hold order: key 2 at [17, 17] on its page holds position 1 of the
//! burst and key 2 at [30, 30] position 2. With the burst held, the
//! coverage admits key 2 at version 20, and the tenure publishes key 2 at
//! that version. `Owner::cover_pending` then writes the pages. Held in
//! order, key 2's intervals stay clear of version 20. The tenure publishes
//! a capture pass and closes, and its successor fences the stored pages and
//! loads warm under their coverage. The successor must serve key 2.
//! Witnesses: more than 20 entries of key 2's page were held, and after the
//! writes the coverage admits key 2 at version 20. The control runs one
//! step before the writes. `Owner::reverse_held_on_page`, a test method of
//! `net/owner_tenure_tests.rs`, reverses the held entries of key 2's page.
//! The stable sort keeps that order, so the write merges version 30 before
//! 17, and the hull [1, 30] covers version 20. The successor's load omits
//! key 2, and the judgment records no restore row for it. The control's
//! premise holds the mark that the written coverage covers key 2 at version
//! 20. No INVALIDATE names version 20 of key 2, and the other keys name no
//! object, so the judgment's rows hold no INVALIDATE and key 2 lies outside
//! every damage set.

use std::rc::Rc;

use crate::failover::records::{Layout, ShardRecord, UNIT_ENTRIES, VolumeRecord};
use crate::failover::restart::tests as restart_tests;
use crate::failover::retire::Target as Own;
use crate::failover::takeover::tests::with_c;
use crate::oracle::{
    CutId, Hypothesis, KeyId, MAX_KEYS, NEVER_SERVED, Outcome as Answer, Recorder, Script, Tenure,
    check, preserved,
};
use crate::storage::checkpoint::{
    Checkpoint, PossiblyNamed, StagedCheckpoint, SuffixBounds, SuffixLimits, open_suffix, publish,
};
use crate::storage::owner_fixture::units_free;
use crate::storage::page_coverage::{Entry, Fencing, Interval, page_of};
use crate::storage::store::sim::{MemLog, Shared};
use crate::storage::store::{Client, Key as StoreKey, Read};
use crate::storage::store_tests::{client, record_under, shard};
use crate::storage::warm_sim::{
    FillRefused, LoadClock, fill_beside, refused_unrecorded, suffix_idle,
};
use crate::storage::{
    CacheVersion, CaptureEntry, CaptureError, Crc32c, EngineBudget, FillPublishError, IO_UNIT,
    LoadRefusal, LookupError, MetadataOutcome, Session, Storage, UnitDone, finish_test_capture,
};

use super::super::relaunch::loaded_over;
use super::covered_successors::{fence_over, fenced_pages};
use super::keyops::{close_storage, drain_closed};
use super::*;

/// The records layout `arm_warm` requires the volume to admit. `units` is the
/// warm fixture storage's metadata prefix, which `admits_layout` compares
/// exactly; `slots` is `MIN_SLOTS`; each slot spans `slot_units(UNIT_ENTRIES)`
/// units and holds `UNIT_ENTRIES` entries, one checkpoint data unit's worth.
const LAYOUT: Layout = Layout {
    units: 16,
    slots: 3,
    slot_units: 2,
    entries: UNIT_ENTRIES as u32,
};

const CAPPED: Layout = Layout {
    entries: 3,
    ..LAYOUT
};

const WIDE: Layout = Layout {
    entries: 4,
    ..LAYOUT
};

/// The suffix bounds of the first tenure: a block seals at the next delta
/// stage, and the tenure reserves eight blocks.
const BOUNDS: SuffixBounds = SuffixBounds {
    limits: SuffixLimits {
        flush_ns: 0,
        queue_blocks: 8,
        oldest_ns: 1 << 40,
        uncertified: 16,
    },
    step: 8,
    margin: 1,
};

/// The hypothesis the judgment's captured and activate rows cite: the warm
/// relaunch from the published checkpoint.
const EVIDENCE: Hypothesis = Hypothesis("warm-relaunch");
const CUT: CutId = CutId(9);
/// The length of each published key's body, in bytes.
const BODY: u64 = 1000;

pub(super) const ADMITTED: &str = "the volume admits the warm layout";
const KEY_1: &str = "key 1 has a resident slot";
const KEY_2: &str = "key 2 published";
const KEY_3: &str = "key 3 published";
pub(super) const PASS_STARTED: &str = "a capture pass started";
pub(super) const PASS_PUBLISHED: &str = "the capture pass published";
pub(super) const SUFFIX_OPENED: &str = "the tenure's suffix opened";
const SUFFIX_LANDED: &str = "every suffix block landed";
const AFTER_DRAIN: &str = "a pass after the drain was attempted";
const ATTEMPT_ENDED: &str = "the attempted pass ended";
pub(super) const OWNER_CLOSED: &str = "the first tenure's owner closed";
const RELAUNCHED: &str = "owner relaunched warm";
const LOADED_OPEN: &str = "the warm load ended Open";
const LOOKED_UP: &str = "each published key was looked up";
const ALL_SERVED: &str = "every published key served";
const KEPT: &str = "the warm load kept every captured entry";
const RESTORED: &str = "every published key restored";
const UNJUDGED: &str = "the warm load reached no restart verdict";
const PAST_CAP_REFUSED: &str = "the fill past the cap was refused";
const PAST_CAP_ACKED: &str = "the fill past the cap was acknowledged";
const PROBED: &str = "the successor's load was probed";
const DEADLINE_READ: &str = "key 2's portable deadline was read";
const FIRST_OPEN: &str = "the first warm load ended Open";
const FILL_REFUSED: &str = "the unrecorded fill was refused";
const UNSERVED: &str = "the first load left key 2 unserved";
const READ_EXPIRED: &str = "the first load read key 2 expired";
const FILL_WRITTEN: &str = "the unrecorded fill's bytes were written";
const UNIT_REWRITTEN: &str = "the unrecorded fill wrote key 2's unit";
const UNIT_KEPT: &str = "the unrecorded fill left key 2's unit";
const RESTORED_OVER: &str = "the second load restored key 2";
const UNIT_HELD: &str = "the first load held key 2's unit";
const READ_REWRITTEN: &str = "key 2's GET read the rewritten unit";
const PAGES_FENCED: &str = "the tenure fenced its coverage pages";
const FOUR_ACKED: &str = "four INVALIDATEs of key 2 acknowledged";
const BURST_HELD: &str = "over 20 entries of key 2's page held";
const HELD_ADMITS: &str = "the held coverage admits key 2 at 20";
const ALL_ACKED: &str = "every held INVALIDATE acknowledged";
const WRITTEN_ADMITS: &str = "the written coverage admits key 2 at 20";
const WRITTEN_COVERS: &str = "the written coverage covers key 2 at 20";
const REVERSED: &str = "the held entries of key 2's page reversed";
const SUCCESSOR_FENCED: &str = "the successor fenced the stored pages";
const KEY_2_ALONE: &str = "key 1 served its exact bytes and the pass staged key 2";

/// The keys of the other coverage page the `wl5` burst interleaves, so the
/// page sort moves entries. With rustc 1.99.0's `sort_unstable_by_key` in
/// `Owner::cover_begin`, the sort of this burst moves key 2 at 30 ahead of
/// key 2 at 17, and the passing history ends in the lost-entry rule.
const ACROSS: usize = 16;
/// The other keys of key 2's page the `wl5` burst holds.
const ALONGSIDE: usize = 20;
/// The version the `wl5` tenure publishes key 2 at.
const BETWEEN: CacheVersion = CacheVersion(20);

const SECOND_NS: u64 = 1_000_000_000;
const SECOND_I64: i64 = 1_000_000_000;
const ENTRIES_REFUSED: &str = "the warm load refused Entries";

const LOST: &str = "a retained entry outside every damage set was lost on host loss";

/// For published key `k` in `1..=4`, `UNRESTORED[k - 1]` is its loss mark.
/// Key 4 is published only by the `wl3` control's `WIDE` tenure.
const UNRESTORED: [&str; 4] = [
    "key 1 was not restored",
    "key 2 was not restored",
    "key 3 was not restored",
    "key 4 was not restored",
];

/// The obligation each warm-load check's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(KEPT, Obligation::Restart)];

/// The state a warm-load history carries from `arm_warm` to its judgment.
pub(super) struct Warm {
    /// The client of the seeded record store that holds the shard record.
    host: Client<Shared, MemLog>,
    /// The seeded record store, which holds the shard record and its
    /// coverage pages.
    records: Shared,
    /// The shard record as last read, which the relaunch step takes to bump.
    read: Option<Read<ShardRecord>>,
    /// The ownership target the shard record names.
    own: Own,
    /// The records layout the tenure publishes and records under.
    layout: Layout,
    /// The checkpoint the first tenure may have named, which a publication
    /// advances.
    possible: PossiblyNamed,
    /// The first tenure's encoded session.
    session: u64,
    /// The capture pass in flight, if any.
    pass: Option<Pass>,
    /// Each key the first tenure published: its number, its label and the
    /// first device unit its slot occupies.
    published: Vec<(u8, Label, u64)>,
    /// The successor's encoded session, 0 until the relaunch step sets it.
    successor: u64,
    /// The published keys whose GET on the successor served their exact
    /// bytes.
    served: Vec<u8>,
    /// The GET of the key at this index of `published` that the look-up
    /// step waits for.
    looking: (usize, Option<RequestId>),
    /// The owner's count of lookup false positives when the pending GET
    /// was issued.
    issued_false: u64,
    /// The published keys whose GET ended `Missing` after a read whose
    /// first header named another key, which the owner counts as a lookup
    /// false positive.
    read_foreign: Vec<u8>,
    /// The world time the look-up step began waiting to issue its next GET.
    waiting: Option<u64>,
    /// The published keys resident in the probe's storage after the probe
    /// read the successor's load.
    probed: Option<Vec<u8>>,
    /// Key 2's portable deadline in nanoseconds since the Unix epoch, read
    /// from the entry the capture pass staged.
    deadline_ns: Option<u64>,
    /// The `wl5` burst the tenure holds, in hold order.
    burst: Vec<Entry>,
}

/// One capture pass's progress through staging, its unit writes and their
/// read-back.
#[derive(Default)]
struct Pass {
    counter: u32,
    staged: Option<StagedCheckpoint>,
    unit: u32,
    reading: bool,
    submitted: bool,
    replacement: bool,
    polled: u64,
    deadline: u64,
}

fn warm_state<'w>(world: &'w mut Mixed<'_, '_, '_>) -> &'w mut Warm {
    world.history.warm.as_mut().expect("the warm-load state")
}

fn resident_unit(storage: &Storage<TestPlatform>, n: u8) -> Option<u64> {
    let fingerprint = storage.fingerprint_of(&key(n))?.2;
    let mut facts = Vec::new();
    storage.slot_facts_into(&mut facts).ok()?;
    facts
        .iter()
        .find(|fact| fact.resident && fact.fingerprint == fingerprint)
        .map(|fact| fact.device_unit)
}

/// The saved row of published key `n`.
fn published_key(warm: &Warm, n: u8) -> Option<(u8, Label, u64)> {
    warm.published.iter().copied().find(|row| row.0 == n)
}

pub(super) fn arm_warm(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    armed(world, LAYOUT)
}

fn arm_capped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    armed(world, CAPPED)
}

fn arm_wide(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    armed(world, WIDE)
}

/// Seeds the tenure's shard record and volume record under `layout` and
/// starts the warm-load state with key 1, the scene's resident object.
fn armed(world: &mut Mixed<'_, '_, '_>, layout: Layout) -> u64 {
    if !world.scene.owner.admits_layout(&layout) {
        return premised(world, false, ADMITTED);
    }
    let Some(unit) = resident_unit(world.storage(), 1) else {
        return premised(world, false, KEY_1);
    };
    let tenure = world.scene.owner.tenure();
    let session = tenure.get();
    let target = tenure.target();
    let records = restart_tests::store(
        ShardRecord {
            generation: target.generation,
            ..restart_tests::shard_record(target.attempts)
        },
        VolumeRecord { layout, ..with_c() },
    );
    let mut host = client(&records);
    let read = host
        .read::<ShardRecord>(StoreKey::Shard(shard()))
        .expect("the seeded shard record");
    let own = Own::of(read.value());
    world.history.warm = Some(Box::new(Warm {
        host,
        records,
        read: Some(read),
        own,
        layout,
        possible: PossiblyNamed::new((shard(), session), layout, None),
        session,
        pass: None,
        published: vec![(1, Label(1), unit)],
        successor: 0,
        served: Vec::new(),
        looking: (0, None),
        issued_false: 0,
        read_foreign: Vec::new(),
        waiting: None,
        probed: None,
        deadline_ns: None,
        burst: Vec::new(),
    }));
    mark(world, ADMITTED)
}

fn fill_key(world: &mut Mixed<'_, '_, '_>, n: u8, version: CacheVersion) -> u64 {
    let object = payload(BODY as usize, u64::from(n));
    if !fill_key_with(world, n, version, &object, Label(u64::from(n))) {
        return STAY;
    }
    1
}

fn fill_2(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fill_key(world, 2, CacheVersion(0))
}

fn fill_3(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fill_key(world, 3, CacheVersion(0))
}

fn fill_4(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fill_key(world, 4, CacheVersion(0))
}

/// Publishes the written fill of key `n`; an acknowledged key joins the
/// published keys with the first device unit of its resident slot. The error
/// is the publication's refusal, or `None` for an acknowledged key with no
/// resident slot.
fn publish_written(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    n: u8,
) -> Result<(), Option<FillPublishError>> {
    let fill = world.history.fill.take().expect("a written fill");
    let deadline = ticks(now + 60 * super::super::SECOND_US);
    let published = world
        .scene
        .owner
        .publish_fill(fill, deadline, 2, &mut budget());
    world.owner_due = now;
    let _lease = published.map_err(Some)?;
    let unit = resident_unit(world.storage(), n).ok_or(None)?;
    let label = Label(u64::from(n));
    warm_state(world).published.push((n, label, unit));
    Ok(())
}

/// Publishes the written fill of key `n`, or ends the run Unsuccessful under
/// `witness`.
fn publish_key(world: &mut Mixed<'_, '_, '_>, now: u64, n: u8, witness: &'static str) -> u64 {
    let formed = publish_written(world, now, n).is_ok();
    premised(world, formed, witness)
}

/// Attempts to publish key 4 while keys 1 through 3 are members and the
/// suffix is open. Key 4 would exceed `CAPPED`'s three-entry cap. Under
/// `CAPPED`, the entry-cap guard rejects key 4 with `History`; under
/// `WIDE`, the tenure acknowledges it. The history continues after either.
fn attempt_past_cap(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match publish_written(world, now, 4) {
        Ok(()) => mark(world, PAST_CAP_ACKED),
        Err(Some(FillPublishError::History)) => mark(world, PAST_CAP_REFUSED),
        Err(_) => premised(world, false, PAST_CAP_REFUSED),
    }
}

fn publish_2(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    publish_key(world, now, 2, KEY_2)
}

fn publish_3(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    publish_key(world, now, 3, KEY_3)
}

fn started(world: &mut Mixed<'_, '_, '_>) -> bool {
    let entries = warm_state(world).layout.entries as usize;
    let Ok(counter) = world.storage().start_capture(entries, true, 1024) else {
        return false;
    };
    warm_state(world).pass = Some(Pass {
        counter,
        ..Pass::default()
    });
    true
}

pub(super) fn start_pass(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let formed = started(world);
    premised(world, formed, PASS_STARTED)
}

/// Attempts a pass after the drain; a refused start leaves no pass for the
/// next step to publish.
fn attempt_pass(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    started(world);
    mark(world, AFTER_DRAIN)
}

/// The pass's walk: every member the cursor visits, then its side list.
fn walked(storage: &Storage<TestPlatform>, counter: u32) -> Option<Vec<CaptureEntry>> {
    let mut entries = Vec::new();
    loop {
        let visited = storage.capture_visit(counter, 64, |entry| entries.push(entry.clone()));
        match visited {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    entries.extend(storage.capture_saved(counter).ok()?);
    Some(entries)
}

/// Walks the pass, takes its proof and stages its checkpoint. The state
/// keeps the portable deadline of key 2's walked entry, `None` when the walk
/// holds no entry of key 2.
fn staged(world: &mut Mixed<'_, '_, '_>, counter: u32) -> Option<StagedCheckpoint> {
    let storage = world.storage();
    let entries = walked(storage, counter)?;
    let warm = warm_state(world);
    let second = entries.iter().find(|entry| entry.key == key(2));
    warm.deadline_ns = second.map(|entry| entry.deadline_ns);
    let checkpoint = Checkpoint {
        shard: shard(),
        session: warm.session,
        capture: counter,
    };
    StagedCheckpoint::new(
        Crc32c::detect(),
        &mut warm.possible,
        (checkpoint, &entries),
        &EngineBudget::unlimited(),
    )
    .ok()
}

enum Advanced {
    /// A unit command is outstanding or was just submitted.
    Waiting,
    Published,
    /// The start was refused, or `cut_intact` refused the pass's proof.
    Refused,
    /// A released pass frees its stage's reservation so a replacement pass
    /// can stage.
    Released,
    /// A step after the start failed: the walk or staging, a unit command,
    /// the record-store Publish or the capture's end.
    Failed,
}

/// Moves the history's pass one command on: stages its checkpoint, writes
/// and reads back each unit through the owner, then publishes it to the
/// record store and ends it. On `Published`, `Refused`, `Released` or
/// `Failed`, `advance` abandons any remaining stage, which releases an
/// unpublished stage's reservation.
fn advance(world: &mut Mixed<'_, '_, '_>, now: u64) -> Advanced {
    let Some(mut pass) = warm_state(world).pass.take() else {
        return Advanced::Refused;
    };
    let advanced = advance_pass(world, now, &mut pass);
    if matches!(advanced, Advanced::Waiting) {
        warm_state(world).pass = Some(pass);
        return advanced;
    }
    world.history.wake = None;
    if let Some(stage) = pass.staged.take() {
        stage.abandon(&mut warm_state(world).possible);
    }
    advanced
}

fn advance_pass(world: &mut Mixed<'_, '_, '_>, now: u64, pass: &mut Pass) -> Advanced {
    if pass.staged.is_none() {
        let Some(stage) = staged(world, pass.counter) else {
            return Advanced::Failed;
        };
        pass.staged = Some(stage);
    }
    let storage = world.storage();
    let warm = world.history.warm.as_mut().expect("the warm-load state");
    let stage = pass.staged.as_mut().expect("a staged checkpoint");
    if pass.unit == stage.units().len() as u32 {
        let proof = match storage.cut_intact((shard(), warm.session), pass.counter) {
            Ok(proof) => proof,
            Err(CaptureError::Released) => return Advanced::Released,
            Err(_) => return Advanced::Refused,
        };
        let read = warm.read.take().expect("the shard record");
        let known = read.value().checkpoint;
        let epoch = storage.capture_epoch();
        let committed = publish(
            &mut warm.host,
            &mut warm.possible,
            &read,
            (warm.own, known),
            (&proof, epoch),
            stage,
        );
        let Ok(committed) = committed else {
            warm.read = Some(read);
            return Advanced::Failed;
        };
        warm.read = Some(committed);
        if finish_test_capture(storage, pass.counter).is_err() {
            return Advanced::Failed;
        }
        return Advanced::Published;
    }
    let owner = &mut world.scene.owner;
    let slot = stage.slot();
    if !pass.submitted {
        let submitted = if pass.reading {
            owner.stage_unit_read(&warm.possible, (slot, pass.unit))
        } else {
            owner.stage_unit_write(&warm.possible, stage, pass.unit)
        };
        if submitted.is_err() {
            return Advanced::Failed;
        }
        (pass.submitted, pass.polled) = (true, world.owner_polls);
        pass.deadline = now + BOUND_US;
        world.history.wake = Some(pass.deadline + 1);
        world.owner_due = now;
        return Advanced::Waiting;
    }
    let unit = pass.unit;
    match owner.take_unit_for(stage) {
        None if now > pass.deadline => Advanced::Failed,
        None => {
            pass.polled = world.owner_polls;
            Advanced::Waiting
        }
        Some(UnitDone::Written { slot: at, unit: of })
            if !pass.reading && (at, of) == (slot, unit) =>
        {
            (pass.reading, pass.submitted) = (true, false);
            Advanced::Waiting
        }
        Some(UnitDone::Read { slot: at, unit: of }) if pass.reading && (at, of) == (slot, unit) => {
            (pass.reading, pass.submitted) = (false, false);
            pass.unit += 1;
            Advanced::Waiting
        }
        Some(UnitDone::Failed { slot: at, unit: of }) if (at, of) == (slot, unit) => {
            Advanced::Failed
        }
        Some(_) => Advanced::Failed,
    }
}

fn pass_ready(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    let warm = world.history.warm.as_ref().expect("the warm-load state");
    warm.pass.as_ref().is_none_or(|pass| {
        !pass.submitted || pass.polled != world.owner_polls || now > pass.deadline
    })
}

pub(super) fn publish_pass(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match advance(world, now) {
        Advanced::Waiting => STAY,
        Advanced::Published => mark(world, PASS_PUBLISHED),
        Advanced::Refused | Advanced::Released | Advanced::Failed => {
            premised(world, false, PASS_PUBLISHED)
        }
    }
}

/// When `advance` returns `Advanced::Released` for the original pass,
/// `publish_raced` requires `finish_test_capture` to succeed before
/// attempting one replacement pass, which must publish to mark
/// `PASS_PUBLISHED`.
fn publish_raced(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let pass = warm_state(world).pass.as_ref();
    let (counter, replacement) = pass.map_or((0, true), |pass| (pass.counter, pass.replacement));
    match advance(world, now) {
        Advanced::Waiting => STAY,
        Advanced::Published => mark(world, PASS_PUBLISHED),
        Advanced::Released if !replacement => {
            let ended = finish_test_capture(world.storage(), counter).is_ok();
            if !(ended && started(world)) {
                return premised(world, false, PASS_PUBLISHED);
            }
            let pass = warm_state(world)
                .pass
                .as_mut()
                .expect("the replacement pass");
            pass.replacement = true;
            STAY
        }
        Advanced::Refused | Advanced::Released | Advanced::Failed => {
            premised(world, false, PASS_PUBLISHED)
        }
    }
}

/// `publish_attempted` accepts `Published`, a refused start, and a proof
/// `cut_intact` refused or released as completed attempts. A failure after
/// the start ends the run Unsuccessful under `ATTEMPT_ENDED`.
fn publish_attempted(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match advance(world, now) {
        Advanced::Waiting => STAY,
        Advanced::Published | Advanced::Refused | Advanced::Released => 1,
        Advanced::Failed => premised(world, false, ATTEMPT_ENDED),
    }
}

pub(super) fn open_tenure_suffix(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let storage = world.storage();
    let warm = warm_state(world);
    let read = warm.read.take().expect("the shard record");
    let ends: &[(u64, u64)] = &[];
    let opened = open_suffix(
        &mut warm.host,
        &mut warm.possible,
        (read, warm.own),
        (storage, ends),
        BOUNDS,
    );
    let Ok((read, opened)) = opened else {
        return premised(world, false, SUFFIX_OPENED);
    };
    warm.read = Some(read);
    premised(world, opened, SUFFIX_OPENED)
}

fn suffix_landed(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    suffix_idle(world.storage())
}

fn mark_landed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, SUFFIX_LANDED)
}

pub(super) fn close_first(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    stop(world, now);
    mark(world, OWNER_CLOSED)
}

fn relaunchable(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.relaunchable()
}

/// Bumps the record's attempts and relaunches the closed owner warm under
/// the session of the bumped record. The successor's device must share the
/// run's one media handle for `RELAUNCHED` to hold.
fn relaunch_warm(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let layout = warm_state(world).layout;
    relaunched_under(world, now, layout)
}

/// Bumps the shard record's attempts for the next tenure and returns the
/// record the bump wrote with the session it activates, which becomes the
/// successor the judgment names. The state keeps the record the bump
/// committed, at the version it wrote, which a later bump compares against.
/// `None` when the state holds no record, the bump fails or its activation
/// is refused.
fn bumped(world: &mut Mixed<'_, '_, '_>) -> Option<(ShardRecord, Session)> {
    let warm = warm_state(world);
    let read = warm.read.take()?;
    let bumped = warm.host.bump(&read).ok()?;
    let committed = bumped.committed().clone();
    let record = *committed.value();
    let session = Session::activate(bumped).ok()?;
    warm.read = Some(committed);
    warm.successor = session.get();
    Some((record, session))
}

/// On relaunch, `PAGES_FENCED` identifies `Warm::records` as the store of
/// the successor's fenced pages.
fn relaunched_under(world: &mut Mixed<'_, '_, '_>, now: u64, layout: Layout) -> u64 {
    let Some((record, session)) = bumped(world) else {
        return premised(world, false, RELAUNCHED);
    };
    let fenced = world.history.marks.contains(&PAGES_FENCED);
    let pages = fenced.then(|| warm_state(world).records.clone());
    let fencing = match pages.map(|store| fenced_pages(&store, &session)) {
        Some(None) => return premised(world, false, SUCCESSOR_FENCED),
        fenced => fenced.flatten(),
    };
    let coverage = fencing.as_ref().and_then(Fencing::coverage);
    let media = world.scene.control.shared_media();
    let loaded = world.relaunch_warm(now, (&record, layout, session), coverage);
    let shared = Rc::ptr_eq(&media, &world.scene.control.shared_media());
    if premised(world, shared, RELAUNCHED) == 0 {
        return 0;
    }
    let open = premised(world, loaded == MetadataOutcome::Open, LOADED_OPEN);
    let Some(fencing) = fencing.filter(|_| open != 0) else {
        return open;
    };
    let installed = world.scene.owner.install_coverage(fencing).is_ok();
    premised(world, installed, SUCCESSOR_FENCED)
}

/// Loads the successor under `CAPPED`. A tenure that refused the fill past
/// the cap relaunches the owner warm. A tenure that acknowledged it, which
/// `PAST_CAP_ACKED` marks, has its successor's load read by a probe with no
/// relaunch: an `Open` probe marks `LOADED_OPEN` and keeps the published
/// keys resident in the probe's storage, an `Entries` refusal marks
/// `ENTRIES_REFUSED` and keeps none, and a probe with no device or any other
/// outcome ends the run Unsuccessful under `LOADED_OPEN`.
fn relaunch_capped(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if !world.history.marks.contains(&PAST_CAP_ACKED) {
        return relaunched_under(world, now, CAPPED);
    }
    let Some((record, session)) = bumped(world) else {
        return premised(world, false, RELAUNCHED);
    };
    let keys: Vec<u8> = warm_state(world).published.iter().map(|p| p.0).collect();
    let resident = |storage: &Storage<TestPlatform>| {
        let held = |&&n: &&u8| resident_unit(storage, n).is_some();
        keys.iter().filter(held).copied().collect::<Vec<_>>()
    };
    let probed = world.probe_warm((&record, CAPPED, session), resident);
    mark(world, PROBED);
    let (resident, witness) = match probed {
        Some(Ok(resident)) => (resident, LOADED_OPEN),
        Some(Err(MetadataOutcome::Unloadable(LoadRefusal::Entries))) => {
            (Vec::new(), ENTRIES_REFUSED)
        }
        None | Some(Err(_)) => return premised(world, false, LOADED_OPEN),
    };
    warm_state(world).probed = Some(resident);
    mark(world, witness)
}

/// The clocks of a load whose physical reading lies `offset_ns` after key
/// 2's portable deadline, before it when negative, at the monotonic sample
/// `monotonic_ns`; `None` when no pass staged key 2's entry.
fn load_clock(
    world: &mut Mixed<'_, '_, '_>,
    offset_ns: i64,
    monotonic_ns: u64,
) -> Option<LoadClock> {
    let deadline = warm_state(world).deadline_ns?;
    Some(LoadClock {
        physical_ns: deadline.checked_add_signed(offset_ns)?,
        monotonic_ns,
    })
}

/// The monotonic sample of the `wl4` histories' second load, 0.8 s into a
/// second, which every later owner turn samples.
const SUCCESSOR_TICK: u64 = 200 * SECOND_NS + 8 * SECOND_NS / 10;

/// The body of the fill the tenure between the incarnations writes.
const UNRECORDED: [u8; 40] = [0xa5; 40];

/// What the tenure between the incarnations left.
struct Between {
    /// After a load that ended `Open`: the error key 2's lookup returned in
    /// the tenure, `None` for a hit or a refused reader registration, and
    /// the fill's outcome.
    tenure: Option<(Option<LookupError>, Result<(), FillRefused>)>,
    /// The tenure's allocator held key 2's unit both before the fill and
    /// after its refusal settled.
    held: bool,
    /// The tenure changed the media.
    written: bool,
    /// The tenure changed key 2's first device unit.
    rewritten: bool,
}

/// Relaunches the owner warm through two loads of one record. The first is
/// of a tenure with no owner, between the incarnations: it reads
/// `first_ns` from key 2's deadline, 0.1 s into a monotonic second, and
/// writes a fill of key 3 whose publication is refused, since the tenure
/// opens no suffix and no record names the write. The second is the next
/// incarnation's: it reads 0.5 s before the deadline, 0.8 s into a second,
/// which reads key 2 alive, and every later owner turn samples its
/// monotonic tick. Each premise is read from state the loads leave whether
/// or not key 2's units stayed held: the first load ended `Open`, key 2's
/// lookup ended `Missing` or `Expired` in its tenure, the fill wrote bytes
/// and its publication was refused `History`, and the second load ended
/// `Open`. The step marks a lookup that ended `Expired`, which a held entry
/// gives and an omitted one does not, the tenure's allocator holding key
/// 2's unit before the fill and after its refusal settled, and whether the
/// fill changed key 2's first device unit.
fn relaunched_through(world: &mut Mixed<'_, '_, '_>, now: u64, first_ns: i64) -> u64 {
    let first = load_clock(world, first_ns, 100 * SECOND_NS + SECOND_NS / 10);
    let second = load_clock(world, -(5 * SECOND_I64 / 10), SUCCESSOR_TICK);
    let (Some(first), Some(second)) = (first, second) else {
        return premised(world, false, DEADLINE_READ);
    };
    let Some(tenure) = bumped(world) else {
        return premised(world, false, RELAUNCHED);
    };
    let Some(successor) = bumped(world) else {
        return premised(world, false, RELAUNCHED);
    };
    let warm = warm_state(world);
    let Some((_, _, unit)) = published_key(warm, 2) else {
        return premised(world, false, KEY_2);
    };
    let (layout, unit) = (warm.layout, unit as usize);
    let named = (&successor.0, layout, successor.1);
    let media = world.scene.control.shared_media();
    let (loaded, between) = world.relaunch_warm_after(now, (named, second), |media| {
        let before = media.borrow().clone();
        let named = (&tenure.0, layout, tenure.1);
        let payload = (unit as u64 - layout.units, 1);
        let ran = loaded_over(media, named, Some(first), |storage, device| {
            let (volume, control) = (&mut device.volume, &device.control);
            let held = !units_free(storage, payload);
            let tenure = fill_beside(storage, volume, control, &key(2), (&key(3), &UNRECORDED));
            (tenure, held && !units_free(storage, payload))
        });
        let after = media.borrow();
        let span = unit * IO_UNIT..(unit + 1) * IO_UNIT;
        let (tenure, held) = match ran {
            Some(Ok((tenure, held))) => (Some(tenure), held),
            _ => (None, false),
        };
        Between {
            tenure,
            held,
            written: *after != before,
            rewritten: after[span.clone()] != before[span],
        }
    });
    let Some((looked, filled)) = between.tenure else {
        return premised(world, false, FIRST_OPEN);
    };
    mark(world, FIRST_OPEN);
    let refused = refused_unrecorded(&filled);
    if between.held {
        mark(world, UNIT_HELD);
    }
    let unserved = matches!(looked, Some(LookupError::Missing | LookupError::Expired));
    if looked == Some(LookupError::Expired) {
        mark(world, READ_EXPIRED);
    }
    if premised(world, unserved, UNSERVED) == 0
        || premised(world, between.written, FILL_WRITTEN) == 0
        || premised(world, refused, FILL_REFUSED) == 0
    {
        return 0;
    }
    let unit = if between.rewritten {
        UNIT_REWRITTEN
    } else {
        UNIT_KEPT
    };
    mark(world, unit);
    let shared = Rc::ptr_eq(&media, &world.scene.control.shared_media());
    if premised(world, shared, RELAUNCHED) == 0 {
        return 0;
    }
    premised(world, loaded == MetadataOutcome::Open, LOADED_OPEN)
}

/// The first load reads 0.6 s before the deadline: the rounded local
/// deadline falls in the sample's own second, so the load reads key 2
/// expired and keeps its units held.
fn relaunch_through_expired(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    relaunched_through(world, now, -(6 * SECOND_I64 / 10))
}

/// A control: the first load reads two seconds past the deadline, where
/// every later trusted reading judges key 2 expired, so the load omits the
/// entry and frees its units, and the second load's reading steps back. The
/// run is Unsuccessful unless the tenure's fill wrote key 2's unit and the
/// second load restored key 2 at that unit. The script's later steps run at the
/// relaunch's world instant, so the judgment records the first failure; a
/// stopped boundary after the second load would fail the restored slot
/// first, under the observer's record check.
fn relaunch_through_past(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if relaunched_through(world, now, 2 * SECOND_I64) == 0 {
        return 0;
    }
    if !world.history.marks.contains(&UNIT_REWRITTEN) {
        return premised(world, false, UNIT_REWRITTEN);
    }
    let Some((_, _, rewritten)) = published_key(warm_state(world), 2) else {
        return premised(world, false, KEY_2);
    };
    let restored = resident_unit(world.storage(), 2) == Some(rewritten);
    premised(world, restored, RESTORED_OVER)
}

/// Issues no GET after a probe read the successor's load, since no
/// successor lives. Otherwise GETs each key the first tenure published from
/// the successor through client 0, one at a time, and keeps the keys whose GET completed with their
/// exact bytes. `misread` judges each decided GET first, and a failure it
/// reports ends the history through `misread_failed`. Each GET is issued once client 0's earlier requests have left
/// the owner's table, since its share of two would refuse a third while two
/// still drain. `look_ready` resumes a pending GET step when client 0 has an
/// outcome. Waiting longer than `BOUND_US` to issue the next GET, a refused
/// GET, or a GET that ends other than `Complete` or `Missing` ends the run
/// Unsuccessful under `LOOKED_UP`.
fn look_up(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if warm_state(world).probed.is_some() {
        return 1;
    }
    let (at, pending) = warm_state(world).looking;
    if let Some(id) = pending {
        if world.scene.clients[0].outcome(id).is_none() {
            return STAY;
        }
        let bytes = drain(&mut world.scene.clients[0], id);
        let outcome = world.collect_get(0, id);
        let _ = world.scene.clients[0].retire(id);
        let n = warm_state(world).published[at].0;
        if let Some(decided) = outcome {
            let failure =
                super::super::misread(&world.registry.borrow(), &key(n), true, decided, &bytes);
            if let Some(failure) = failure {
                return super::misread_failed(world, failure);
            }
        }
        let foreign = world.scene.owner.report().false_positives > warm_state(world).issued_false;
        let warm = warm_state(world);
        match outcome {
            Some(Outcome::Complete) if bytes == payload(BODY as usize, u64::from(n)) => {
                warm.served.push(n);
            }
            Some(Outcome::Missing) if foreign => warm.read_foreign.push(n),
            Some(Outcome::Complete | Outcome::Missing) => {}
            _ => return premised(world, false, LOOKED_UP),
        }
        warm.looking = (at + 1, None);
        return STAY;
    }
    let warm = warm_state(world);
    let Some(&(n, _, _)) = warm.published.get(at) else {
        let all = warm.served.len() == warm.published.len();
        world.history.wake = None;
        let looked = mark(world, LOOKED_UP);
        if !all {
            return looked;
        }
        return mark(world, ALL_SERVED);
    };
    let census = world.scene.owner.peer_census(PeerId(0));
    let waited = *warm_state(world).waiting.get_or_insert(now);
    if now > waited + BOUND_US {
        return premised(world, false, LOOKED_UP);
    }
    world.history.wake = Some(waited + BOUND_US + 1);
    if !world.active(0) || census.active + census.draining > 0 {
        return STAY;
    }
    let issued = world.scene.clients[0].get(key(n), 0, 1 << 20, now, super::super::WAIT_US);
    let Ok(id) = issued else {
        return premised(world, false, LOOKED_UP);
    };
    world.history.wake = None;
    let issued_false = world.scene.owner.report().false_positives;
    let warm = warm_state(world);
    warm.looking = (at, Some(id));
    warm.issued_false = issued_false;
    warm.waiting = None;
    STAY
}

fn look_ready(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    let warm = world.history.warm.as_ref().expect("the warm-load state");
    match warm.looking {
        (_, Some(id)) => world.scene.clients[0].outcome(id).is_some(),
        (at, None) => {
            let census = world.scene.owner.peer_census(PeerId(0));
            let drained = world.active(0) && census.active + census.draining == 0;
            let expired = warm.waiting.is_none_or(|waited| now > waited + BOUND_US);
            at >= warm.published.len() || drained || expired
        }
    }
}

/// `CUT` stands for the published checkpoint together with the suffix the
/// first tenure opened after it. The judgment asserts a captured row for each
/// key the first tenure acknowledged. A key counts as restored from one of
/// two sources: after a probe read the successor's load, the key is
/// resident in the probe's storage, which an `Entries` refusal leaves with
/// none; otherwise its slot is resident on the successor and its GET served
/// its exact bytes. The judgment asserts a restore row for each restored
/// key except key `withheld`. With a `withheld` key, an unrestored
/// published key fails the `RESTORED` premise before `check` runs.
///
/// When the oracle reports a violation, `restored_judged` marks each
/// unrestored published key before `judged` records it, so a history
/// premise can identify those keys.
fn restored_judged(world: &mut Mixed<'_, '_, '_>, withheld: Option<u8>) -> u64 {
    let storage = world.storage();
    let warm = world.history.warm.as_ref().expect("the warm-load state");
    let restored = |n: u8| match &warm.probed {
        Some(resident) => resident.contains(&n),
        None => warm.served.contains(&n) && resident_unit(storage, n).is_some(),
    };
    if withheld.is_some() && !warm.published.iter().all(|&(n, _, _)| restored(n)) {
        return premised(world, false, RESTORED);
    }
    let tenure = Tenure {
        g: warm.successor >> 32,
        a: warm.successor & 0xFFFF_FFFF,
    };
    let mut failed = None;
    for group in warm.published.chunks(MAX_KEYS) {
        let mut rows = Script::new();
        for &(n, label, _) in group {
            rows.publish(KeyId(n), label, BODY);
        }
        for &(n, label, unit) in group {
            rows.captured(EVIDENCE, (KeyId(n), label), CUT, (0, unit as u32));
        }
        rows.activate(EVIDENCE, Some(tenure), Some(CUT));
        rows.in_tenure(Some(tenure));
        for &(n, label, _) in group {
            if withheld != Some(n) && restored(n) {
                rows.restore(KeyId(n), label, CUT);
            }
        }
        let verdict = check(&rows.finish());
        if !verdict.satisfies(&[Obligation::Restart]) {
            failed = Some(verdict.violated());
            break;
        }
    }
    if let Some(Some(_)) = failed {
        let unrestored = warm.published.iter().filter(|&&(n, _, _)| !restored(n));
        let lost: Vec<_> = unrestored
            .map(|&(n, _, _)| UNRESTORED[usize::from(n) - 1])
            .collect();
        for key in lost {
            mark(world, key);
        }
    }
    judged(world, failed)
}

/// Records a judgment's verdict: `None` marks the kept check, a violation
/// fails the run under the rule the oracle returned, and any other verdict
/// ends it Unsuccessful.
fn judged(
    world: &mut Mixed<'_, '_, '_>,
    verdict: Option<Option<(Obligation, &'static str)>>,
) -> u64 {
    match verdict {
        None => mark(world, KEPT),
        Some(Some((obligation, rule))) => fail(world, obligation, rule),
        Some(None) => premised(world, false, UNJUDGED),
    }
}

/// Judges key 2 after the second load through the oracle's preservation
/// judgment. The captured row is asserted, since the first tenure
/// acknowledged the key before its pass; the restore row is read from the
/// second successor's resident slot, and the hit with its complete delivery
/// from the GET that served the key's exact bytes. A restored key with no
/// such GET fails as never served.
fn judge_served(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let storage = world.storage();
    let warm = world.history.warm.as_ref().expect("the warm-load state");
    let tenure = Tenure {
        g: warm.successor >> 32,
        a: warm.successor & 0xFFFF_FFFF,
    };
    let Some((n, label, unit)) = published_key(warm, 2) else {
        return premised(world, false, KEY_2);
    };
    let mut rows = Script::new();
    rows.publish_sized(KeyId(n), label, 0, BODY);
    rows.captured(EVIDENCE, (KeyId(n), label), CUT, (0, unit as u32));
    rows.activate(EVIDENCE, Some(tenure), Some(CUT));
    rows.in_tenure(Some(tenure));
    if resident_unit(storage, n).is_some() {
        rows.restore(KeyId(n), label, CUT);
    }
    if warm.served.contains(&n) {
        let op = rows.lookup(KeyId(n), Answer::Hit, Some(label));
        let bytes = Recorder::content(KeyId(n), label, 0, BODY);
        rows.deliver_sized(op, KeyId(n), label, (0, BODY), Answer::Complete, bytes);
    }
    let failed = preserved(&rows.finish()).err();
    judged(world, failed.map(|verdict| verdict.violated()))
}

/// A control: `judge_served` once key 2's GET ended `Missing` after a read
/// whose first header named another key, the unit the tenure's fill
/// rewrote; otherwise the run ends Unsuccessful under `READ_REWRITTEN`.
fn judge_rewritten(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let read = warm_state(world).read_foreign.contains(&2);
    if premised(world, read, READ_REWRITTEN) == 0 {
        return 0;
    }
    judge_served(world, now)
}

fn judge_warm(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    restored_judged(world, None)
}

/// Serving key 1's exact bytes and staging key 2 let `judge_reversed`
/// attribute a detected loss to key 2.
fn judge_reversed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let warm = warm_state(world);
    let alone = warm.served.contains(&1) && warm.deadline_ns.is_some();
    if premised(world, alone, KEY_2_ALONE) == 0 {
        return 0;
    }
    judge_warm(world, now)
}

/// A control: the judgment withholds key 1's restore row.
fn judge_withheld(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    restored_judged(world, Some(1))
}

/// A control: the judgment withholds key 3's restore row.
fn judge_withheld_3(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    restored_judged(world, Some(3))
}

fn fence_pages(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let store = warm_state(world).records.clone();
    let installed = fence_over(world, &store);
    premised(world, installed, PAGES_FENCED)
}

fn one(version: u64) -> Interval {
    Interval::new(CacheVersion(version), CacheVersion(version)).expect("an ordered interval")
}

/// A successful `hold` leaves the invalidation pending for the next page
/// write.
fn hold(world: &mut Mixed<'_, '_, '_>, (key, interval): Entry) -> bool {
    let owner = &mut world.scene.owner;
    (owner.invalidate_interval(&key, interval, 4, &mut budget())).is_ok()
}

/// Writes the held pages over the family's store: the entries the writes
/// acknowledged, `None` when the fencing withdrew.
fn write(world: &mut Mixed<'_, '_, '_>, now: u64) -> Option<Vec<Entry>> {
    let mut client = client(&warm_state(world).records.clone());
    let mut acknowledged = Vec::new();
    let owner = &mut world.scene.owner;
    (owner.cover_pending(&mut client, &mut acknowledged, now)).ok()?;
    world.owner_due = now;
    Some(acknowledged)
}

/// Whether the tenure's coverage admits key 2 at `BETWEEN`.
fn admits_between(world: &mut Mixed<'_, '_, '_>) -> bool {
    let fencing = world.scene.owner.coverage_mut();
    fencing.is_some_and(|fencing| fencing.admits(&key(2), BETWEEN))
}

/// Four INVALIDATEs of key 2, at versions 1, 5, 9 and 13, each acknowledged
/// by its page write before the next.
fn invalidate_acked(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let acked = [1, 5, 9, 13].into_iter().all(|version| {
        hold(world, (key(2), one(version)))
            && write(world, now).is_some_and(|acked| acked == [(key(2), one(version))])
    });
    premised(world, acked, FOUR_ACKED)
}

/// The `wl5` entries in the order the owner holds them. With `s` candidate
/// keys on key 2's page and `d` on the other pages, the burst holds
/// `2 + n + min(n, ACROSS, d)` entries, where `n = min(s, ALONGSIDE)`.
fn burst_of(pages: std::num::NonZeroU16) -> Vec<Entry> {
    let on = page_of(&key(2), pages);
    let of = |own| {
        (100..=u8::MAX)
            .map(key)
            .filter(move |k| (page_of(k, pages) == on) == own)
    };
    let mut across = of(false).take(ACROSS);
    let mut burst = vec![(key(2), one(17)), (key(2), one(30))];
    for other in of(true).take(ALONGSIDE) {
        burst.extend(across.next().map(|k| (k, one(1))));
        burst.push((other, one(1)));
    }
    burst
}

fn hold_burst(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let pages = record_under(world.scene.owner.tenure()).pages;
    burst_held(world, burst_of(pages))
}

/// `BURST_HELD` requires a burst that spans pages, which exercises the page
/// sort in `Owner::cover_begin`.
fn burst_held(world: &mut Mixed<'_, '_, '_>, burst: Vec<Entry>) -> u64 {
    let pages = record_under(world.scene.owner.tenure()).pages;
    let on = page_of(&key(2), pages);
    let own = burst
        .iter()
        .filter(|(k, _)| page_of(k, pages) == on)
        .count();
    let spread = own == ALONGSIDE + 2 && burst.len() == own + ACROSS;
    let held = spread && burst.iter().all(|&entry| hold(world, entry));
    let formed = held && world.scene.owner.held_invalidations() == burst.len();
    warm_state(world).burst = burst;
    if premised(world, formed, BURST_HELD) == 0 {
        return 0;
    }
    let admits = admits_between(world);
    premised(world, admits, HELD_ADMITS)
}

fn fill_between(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fill_key(world, 2, BETWEEN)
}

/// A control: reverses the held entries of key 2's page, more than 20.
fn reverse_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let reversed = world.scene.owner.reverse_held_on_page(&key(2));
    premised(world, reversed > 20, REVERSED)
}

/// The write premise requires the acknowledgments to match `Warm::burst`
/// by multiplicity, in any order, and the owner's held count after the
/// write to be zero.
fn write_pages(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let mut burst = warm_state(world).burst.clone();
    burst.sort_unstable();
    let acked = write(world, now).is_some_and(|mut acked| {
        acked.sort_unstable();
        acked == burst
    });
    let formed = acked && world.scene.owner.held_invalidations() == 0;
    if premised(world, formed, ALL_ACKED) == 0 {
        return 0;
    }
    let admits = admits_between(world);
    mark(
        world,
        if admits {
            WRITTEN_ADMITS
        } else {
            WRITTEN_COVERS
        },
    )
}

const RELAUNCHED_STEPS: [Step; 5] = [
    step("close-owner", always, close_first),
    step("relaunch", relaunchable, relaunch_warm),
    step("look-up", look_ready, look_up),
    step("judge-warm", always, judge_warm),
    JUDGE,
];

const WL1_LOST: [Step; 18] = joined(
    [
        step("arm", always, arm_warm),
        step("fill-2", always, fill_2),
        step("publish-2", fill_written, publish_2),
        step("start-pass", always, start_pass),
        step("publish-pass", pass_ready, publish_pass),
        step("open-suffix", always, open_tenure_suffix),
        step("fill-3", always, fill_3),
        step("publish-3", fill_written, publish_3),
        step("suffix-landed", suffix_landed, mark_landed),
        step("close-storage", always, close_storage),
        step("drain-closed", always, drain_closed),
        step("attempt-pass", always, attempt_pass),
        step("publish-attempt", pass_ready, publish_attempted),
    ],
    RELAUNCHED_STEPS,
);

const WL1_KEPT: [Step; 18] = replaced(
    replaced(
        WL1_LOST,
        "attempt-pass",
        step("no-pass", always, removed_step),
    ),
    "publish-attempt",
    step("no-publish", always, removed_step),
);

const WL1_KEPT_UNRESTORED: [Step; 18] = replaced(
    WL1_KEPT,
    "judge-warm",
    step("judge-withheld", always, judge_withheld_3),
);

const WL2_LOST: [Step; 12] = joined(
    [
        step("arm", always, arm_warm),
        step("start-pass", always, start_pass),
        step("fill-2", always, fill_2),
        step("publish-2", fill_written, publish_2),
        step("publish-pass", pass_ready, publish_raced),
        step("open-suffix", always, open_tenure_suffix),
        step("suffix-landed", suffix_landed, mark_landed),
    ],
    RELAUNCHED_STEPS,
);

const WL2_KEPT: [Step; 12] = joined(
    [
        step("arm", always, arm_warm),
        step("fill-2", always, fill_2),
        step("publish-2", fill_written, publish_2),
        step("start-pass", always, start_pass),
        step("publish-pass", pass_ready, publish_pass),
        step("open-suffix", always, open_tenure_suffix),
        step("suffix-landed", suffix_landed, mark_landed),
    ],
    RELAUNCHED_STEPS,
);

const WL2_KEPT_UNRESTORED: [Step; 12] = replaced(
    WL2_KEPT,
    "judge-warm",
    step("judge-withheld", always, judge_withheld),
);

const WL3_CAPPED: [Step; 16] = replaced(
    joined(
        [
            step("arm", always, arm_capped),
            step("fill-2", always, fill_2),
            step("publish-2", fill_written, publish_2),
            step("fill-3", always, fill_3),
            step("publish-3", fill_written, publish_3),
            step("start-pass", always, start_pass),
            step("publish-pass", pass_ready, publish_pass),
            step("open-suffix", always, open_tenure_suffix),
            step("fill-4", always, fill_4),
            step("attempt-4", fill_written, attempt_past_cap),
            step("suffix-landed", suffix_landed, mark_landed),
        ],
        RELAUNCHED_STEPS,
    ),
    "relaunch",
    step("relaunch-capped", relaunchable, relaunch_capped),
);

const WL3_WIDE: [Step; 16] = replaced(WL3_CAPPED, "arm", step("arm-wide", always, arm_wide));

const WL4_KEPT: [Step; 10] = [
    step("arm", always, arm_warm),
    step("fill-2", always, fill_2),
    step("publish-2", fill_written, publish_2),
    step("start-pass", always, start_pass),
    step("publish-pass", pass_ready, publish_pass),
    step("close-owner", always, close_first),
    step("relaunch-expired", relaunchable, relaunch_through_expired),
    step("look-up", look_ready, look_up),
    step("judge-served", always, judge_served),
    JUDGE,
];

const WL4_PAST: [Step; 10] = replaced(
    replaced(
        WL4_KEPT,
        "relaunch-expired",
        step("relaunch-past", relaunchable, relaunch_through_past),
    ),
    "judge-served",
    step("judge-rewritten", always, judge_rewritten),
);

const WL5_IN_ORDER: [Step; 15] = joined(
    [
        step("arm", always, arm_warm),
        step("fence-pages", always, fence_pages),
        step("invalidate-acked", always, invalidate_acked),
        step("hold-burst", always, hold_burst),
        step("fill-2", always, fill_between),
        step("publish-2", fill_written, publish_2),
        step("keep-order", always, removed_step),
        step("write-pages", always, write_pages),
        step("start-pass", always, start_pass),
        step("publish-pass", pass_ready, publish_pass),
    ],
    RELAUNCHED_STEPS,
);

const WL5_REVERSED: [Step; 15] = replaced(
    replaced(
        WL5_IN_ORDER,
        "keep-order",
        step("reverse-held", always, reverse_held),
    ),
    "judge-warm",
    step("judge-reversed", always, judge_reversed),
);

const WL1_LOST_WITNESSES: &[&str] = &[
    ADMITTED,
    KEY_2,
    PASS_STARTED,
    PASS_PUBLISHED,
    SUFFIX_OPENED,
    KEY_3,
    SUFFIX_LANDED,
    AFTER_DRAIN,
    OWNER_CLOSED,
    RELAUNCHED,
    LOADED_OPEN,
    LOOKED_UP,
];

const WL1_KEPT_WITNESSES: &[&str] = &[
    ADMITTED,
    KEY_2,
    PASS_STARTED,
    PASS_PUBLISHED,
    SUFFIX_OPENED,
    KEY_3,
    SUFFIX_LANDED,
    OWNER_CLOSED,
    RELAUNCHED,
    LOADED_OPEN,
    LOOKED_UP,
    ALL_SERVED,
    KEPT,
];

const WL2_LOST_WITNESSES: &[&str] = &[
    ADMITTED,
    PASS_STARTED,
    KEY_2,
    PASS_PUBLISHED,
    SUFFIX_OPENED,
    SUFFIX_LANDED,
    OWNER_CLOSED,
    RELAUNCHED,
    LOADED_OPEN,
    LOOKED_UP,
];

const WL2_KEPT_WITNESSES: &[&str] = &[
    ADMITTED,
    KEY_2,
    PASS_STARTED,
    PASS_PUBLISHED,
    SUFFIX_OPENED,
    SUFFIX_LANDED,
    OWNER_CLOSED,
    RELAUNCHED,
    LOADED_OPEN,
    LOOKED_UP,
    ALL_SERVED,
    KEPT,
];

const WL3_CAPPED_WITNESSES: &[&str] = &[
    ADMITTED,
    KEY_2,
    KEY_3,
    PASS_STARTED,
    PASS_PUBLISHED,
    SUFFIX_OPENED,
    PAST_CAP_REFUSED,
    SUFFIX_LANDED,
    OWNER_CLOSED,
    RELAUNCHED,
    LOADED_OPEN,
    LOOKED_UP,
    ALL_SERVED,
    KEPT,
];

const WL3_WIDE_WITNESSES: &[&str] = &[
    ADMITTED,
    KEY_2,
    KEY_3,
    PASS_STARTED,
    PASS_PUBLISHED,
    SUFFIX_OPENED,
    PAST_CAP_ACKED,
    SUFFIX_LANDED,
    OWNER_CLOSED,
    PROBED,
    KEPT,
];

const WL4_WITNESSES: &[&str] = &[
    ADMITTED,
    KEY_2,
    PASS_STARTED,
    PASS_PUBLISHED,
    OWNER_CLOSED,
    FIRST_OPEN,
    UNSERVED,
    READ_EXPIRED,
    FILL_WRITTEN,
    FILL_REFUSED,
    UNIT_HELD,
    UNIT_KEPT,
    RELAUNCHED,
    LOADED_OPEN,
    LOOKED_UP,
    ALL_SERVED,
    KEPT,
];

/// The marks the stepped-clock control's run holds when its plant formed
/// and its judgment found no violation.
const WL4_PAST_WITNESSES: &[&str] = &[
    ADMITTED,
    KEY_2,
    PASS_STARTED,
    PASS_PUBLISHED,
    OWNER_CLOSED,
    FIRST_OPEN,
    UNSERVED,
    FILL_WRITTEN,
    FILL_REFUSED,
    UNIT_REWRITTEN,
    RELAUNCHED,
    LOADED_OPEN,
    RESTORED_OVER,
    LOOKED_UP,
    READ_REWRITTEN,
    KEPT,
];

const WL5_WITNESSES: &[&str] = &[
    ADMITTED,
    PAGES_FENCED,
    FOUR_ACKED,
    BURST_HELD,
    HELD_ADMITS,
    KEY_2,
    ALL_ACKED,
    WRITTEN_ADMITS,
    PASS_STARTED,
    PASS_PUBLISHED,
    OWNER_CLOSED,
    SUCCESSOR_FENCED,
    RELAUNCHED,
    LOADED_OPEN,
    LOOKED_UP,
    ALL_SERVED,
    KEPT,
];

/// The marks the reversed control's run holds when its judgment found no
/// violation.
const WL5_REVERSED_WITNESSES: &[&str] = &[
    ADMITTED,
    PAGES_FENCED,
    FOUR_ACKED,
    BURST_HELD,
    HELD_ADMITS,
    KEY_2,
    REVERSED,
    ALL_ACKED,
    WRITTEN_COVERS,
    PASS_STARTED,
    PASS_PUBLISHED,
    OWNER_CLOSED,
    SUCCESSOR_FENCED,
    RELAUNCHED,
    LOADED_OPEN,
    LOOKED_UP,
    KEY_2_ALONE,
    KEPT,
];

/// The marks the reversed control's run holds before its judgment.
const REVERSED_PREMISE: &[&str] = &[REVERSED, WRITTEN_COVERS, LOADED_OPEN, KEY_2_ALONE];

/// The marks the stepped-clock control's run holds once its relaunch step
/// ended, before its judgment.
const REWRITTEN_PREMISE: &[&str] = &[
    FIRST_OPEN,
    FILL_REFUSED,
    UNIT_REWRITTEN,
    LOADED_OPEN,
    RESTORED_OVER,
    READ_REWRITTEN,
];

/// The marks the planted tenure's run holds before its judgment: the tenure
/// acknowledged the fill past the cap and the probe's load refused
/// `Entries`.
const PAST_CAP_PREMISE: &[&str] = &[PAST_CAP_ACKED, ENTRIES_REFUSED];

/// The marks each control's run holds before its withheld judgment.
const UNRESTORED_PREMISE: &[&str] = &[LOADED_OPEN, ALL_SERVED];

/// The premise of `wl1-closed-pass-lost`: the loss mark of each published key.
const WL1_LOSES: &[&str] = &[UNRESTORED[0], UNRESTORED[1], UNRESTORED[2]];

/// The premise of `wl2-fill-in-pass-lost`: the loss mark of key 2, which its script fills while the pass is in
/// flight.
const WL2_LOSES: &[&str] = &[UNRESTORED[1]];

const JUDGED: &[Obligation] = &[Obligation::Restart];

const LOST_ON_HOST_LOSS: Expect = Expect::Violation(Obligation::Restart, LOST);

const fn warm_load(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
) -> History {
    warm(relaunching(
        history(name, script, witnesses, JUDGED, expect),
        1,
    ))
}

pub(super) const WARM_LOADS: [History; 12] = [
    control(
        warm_load(
            "wl1-closed-pass-lost",
            &WL1_LOST,
            WL1_LOST_WITNESSES,
            LOST_ON_HOST_LOSS,
        ),
        WL1_LOSES,
    ),
    warm_load(
        "wl1-closed-without-pass",
        &WL1_KEPT,
        WL1_KEPT_WITNESSES,
        Expect::Pass,
    ),
    control(
        warm_load(
            "wl1-without-pass-judged-unrestored",
            &WL1_KEPT_UNRESTORED,
            WL1_KEPT_WITNESSES,
            LOST_ON_HOST_LOSS,
        ),
        UNRESTORED_PREMISE,
    ),
    control(
        warm_load(
            "wl2-fill-in-pass-lost",
            &WL2_LOST,
            WL2_LOST_WITNESSES,
            LOST_ON_HOST_LOSS,
        ),
        WL2_LOSES,
    ),
    warm_load(
        "wl2-fill-before-pass",
        &WL2_KEPT,
        WL2_KEPT_WITNESSES,
        Expect::Pass,
    ),
    control(
        warm_load(
            "wl2-before-pass-judged-unrestored",
            &WL2_KEPT_UNRESTORED,
            WL2_KEPT_WITNESSES,
            LOST_ON_HOST_LOSS,
        ),
        UNRESTORED_PREMISE,
    ),
    warm_load(
        "wl3-fill-past-cap-refused",
        &WL3_CAPPED,
        WL3_CAPPED_WITNESSES,
        Expect::Pass,
    ),
    control(
        warm_load(
            "wl3-wide-tenure-loaded-capped",
            &WL3_WIDE,
            WL3_WIDE_WITNESSES,
            LOST_ON_HOST_LOSS,
        ),
        PAST_CAP_PREMISE,
    ),
    warm_load(
        "wl4-expired-then-alive-served",
        &WL4_KEPT,
        WL4_WITNESSES,
        Expect::Pass,
    ),
    control(
        warm_load(
            "wl4-clock-stepped-back-unserved",
            &WL4_PAST,
            WL4_PAST_WITNESSES,
            Expect::Violation(Obligation::Restart, NEVER_SERVED),
        ),
        REWRITTEN_PREMISE,
    ),
    warm_load(
        "wl5-burst-held-in-order-served",
        &WL5_IN_ORDER,
        WL5_WITNESSES,
        Expect::Pass,
    ),
    control(
        warm_load(
            "wl5-burst-reversed-lost",
            &WL5_REVERSED,
            WL5_REVERSED_WITNESSES,
            LOST_ON_HOST_LOSS,
        ),
        REVERSED_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use crate::oracle::Obligation;

    use super::super::super::{LIMITS, mixed_run, sites_for, ticks};
    use super::super::named;
    use super::super::tests::{ends_as_declared_at, first_failure};
    use super::{Expect, LOST, NEVER_SERVED, SUCCESSOR_TICK, WARM_LOADS};

    /// The roots the seeded tests pin.
    const ROOTS: [u64; 3] = [1, 2, 4_302_617_955_180_736_441];

    /// Each control declares its rule and a premise its run marks before the
    /// failure, and the family's other histories that expect a failure are
    /// the two losses, which declare the lost-entry rule. The family lists
    /// each named control and loss once. Each control and loss records
    /// exactly its declared failure under each pinned root.
    #[test]
    fn every_warm_load_control_fails_through_its_named_check() {
        let lost = Expect::Violation(Obligation::Restart, LOST);
        let controls = [
            ("wl1-without-pass-judged-unrestored", lost),
            ("wl2-before-pass-judged-unrestored", lost),
            ("wl3-wide-tenure-loaded-capped", lost),
            ("wl5-burst-reversed-lost", lost),
            (
                "wl4-clock-stepped-back-unserved",
                Expect::Violation(Obligation::Restart, NEVER_SERVED),
            ),
        ];
        let losses: [(&str, &[&str]); 2] = [
            (
                "wl1-closed-pass-lost",
                &[
                    "key 1 was not restored",
                    "key 2 was not restored",
                    "key 3 was not restored",
                ],
            ),
            ("wl2-fill-in-pass-lost", &["key 2 was not restored"]),
        ];
        let names = controls.iter().map(|control| control.0);
        for name in names.chain(losses.iter().map(|loss| loss.0)) {
            let listed = WARM_LOADS.iter().filter(|history| history.name == name);
            assert_eq!(listed.count(), 1, "{name} is listed once");
        }
        for history in &WARM_LOADS {
            let name = history.name;
            let loss = losses.iter().find(|(pin, _)| *pin == name);
            if let Some((_, declared)) = controls.iter().find(|control| control.0 == name) {
                assert_eq!(history.expect, *declared, "{name}");
                assert!(!history.premise.is_empty(), "{name} declares its premise");
            } else if let Some((_, loses)) = loss {
                assert_eq!(history.expect, lost, "{name}");
                assert_eq!(history.premise, *loses, "{name}");
            } else {
                assert_eq!(history.expect, Expect::Pass, "{name}");
                continue;
            }
            for root in ROOTS {
                assert_eq!(
                    first_failure(name, root),
                    history.expect.failure(),
                    "{name} at {root}"
                );
            }
        }
    }

    /// A clocked relaunch holds the successor storage at its load's
    /// monotonic sample: the relaunch's turn and every later owner turn arm
    /// that tick and leave the platform's last sample at it, and each
    /// earlier turn arms its own time's tick.
    #[test]
    fn a_clocked_relaunch_holds_every_later_turn_at_the_loads_monotonic_sample() {
        for name in [
            "wl4-expired-then-alive-served",
            "wl4-clock-stepped-back-unserved",
        ] {
            let (profile, plan, goal) = named(name, ROOTS[0]).expect(name);
            let chooser = profile.recorder(&sites_for(&plan));
            let (ran, _, _) = mixed_run(chooser, &profile, plan, goal, LIMITS, &mut ());
            let held = Some(SUCCESSOR_TICK);
            let relaunch = ran.clocks.iter().position(|clock| clock.last == held);
            let relaunch = relaunch.expect("a turn sampled the second load's tick");
            assert!(relaunch > 0, "{name}: the first tenure sampled its clock");
            for clock in &ran.clocks[..relaunch] {
                assert_eq!(clock.projection, ticks(clock.now), "{name}: {clock:?}");
            }
            let later = &ran.clocks[relaunch..];
            assert!(
                later.len() > 1,
                "{name}: an owner turn follows the relaunch"
            );
            for clock in later {
                assert_eq!(
                    (clock.projection, clock.last),
                    (SUCCESSOR_TICK, held),
                    "{name}: {clock:?}"
                );
            }
        }
    }

    #[test]
    fn every_warm_load_history_ends_as_declared_under_pinned_roots() {
        for history in &WARM_LOADS {
            for root in ROOTS {
                ends_as_declared_at(history, root);
            }
        }
    }

    mod planted;
}
