//! Successor coverage histories: a tenure acknowledges an INVALIDATE
//! through its coverage page, its owner stops and relaunches, and the
//! successor tenure fences the same pages before a client uploads key 1,
//! which the first tenure's INVALIDATE names in the covered history and
//! leaves alone in the sibling.
//!
//! The property is the coverage model's `FencedCoverageComplete` and
//! `NoCoveredResidency`, which `quint/README.md` states as "A tenure that
//! fenced every page covers every INVALIDATE an earlier tenure
//! acknowledged." and "No resident FILL is an entry that its tenure or an
//! earlier one acknowledged." The histories
//! judge the residency side, the successor's upload and read of the
//! covered key; the control whose successor fenced other pages shows the
//! coverage side.
//!
//! The covered history follows the directed run
//! `coverage-run-successorRefusesAckedFill` of `quint/coverage.qnt` with a
//! proven stop and a relaunch between the acknowledgment and the
//! successor's fences, which the model's tenures do not take, and it
//! judges the refusal by the upload's outcome where the run reads the
//! successor's coverage. The sibling follows the admitting half of
//! `coverage-run-successorAdmitsUncoveredKey`: its successor admits a key
//! the acknowledged INVALIDATE leaves uncovered; its first tenure fills
//! nothing, and the refusal of the covered key is the covered history's.
//! The model's entries are at version 1; the histories' entry is
//! `[0, 0]`, the version an upload that names none records.
//!
//! Each history's first tenure fences both coverage pages over a
//! simulated store and installs the fencing before its first published
//! fill, acknowledges one INVALIDATE of `[0, 0]`, and stops with a proven
//! stop. The owner relaunches cold over the shared media, and the
//! successor tenure fences the pages of the same store and installs its
//! fencing. Each history's own steps install the coverages, so the family
//! judges what a successor does with pages its predecessor wrote; the
//! storage tests cover how a coverage reaches an owner. The store
//! outlives the relaunch in a thread-local, because the relaunch resets
//! the history state apart from its marks and times.
//!
//! - `cs1-successor-put-of-a-key-its-predecessor-invalidated`: the
//!   INVALIDATE names key 1. The successor's upload of key 1, which names
//!   no version, must end other than published with the successor's
//!   published count unmoved, and a GET of the key must deliver nothing.
//! - `cs1-successor-put-of-a-key-its-predecessor-left` is the sibling: the
//!   INVALIDATE names another key, and the successor's upload of key 1
//!   publishes and reads back exactly.
//! - `cs1-successor-fenced-other-pages` is a control that plants a
//!   world-side effect: the successor fences the pages of a fresh store,
//!   as a successor that lost its predecessor's pages would, so its
//!   coverage lacks the acknowledged entry and the upload publishes.
//! - `cs1-successor-key-read-as-served` is a control that hands the GET's
//!   judge a planted observation: the read complete with the upload's
//!   bytes.
//!
//! CS0 judges the acknowledging tenure itself, with no stop and no
//! successor. The property is the rule the cluster world's checker judges,
//! "an owner binds a version an acknowledged invalidation covered". The
//! scene publishes key 1 before the run; the tenure fences both coverage
//! pages, installs the fencing, and acknowledges one INVALIDATE of
//! `[0, 0]`.
//!
//! - `cs0-tenure-binding-of-a-key-its-invalidate-covered`: the INVALIDATE
//!   names key 1. The owner's storage must then map no object under key 1,
//!   read through a fresh registration, and a GET of the key must end
//!   `Missing` with no byte delivered. Only a lookup that ends `Missing`
//!   and a GET that ends `Missing` show the mapping gone. A registration
//!   or a lookup the storage refused, and a GET that ended another way
//!   with no byte, are premises that did not form.
//! - `cs0-tenure-binding-of-a-key-its-invalidate-left` is the sibling: the
//!   INVALIDATE names another key, key 1 stays bound, and a GET reads the
//!   resident object back exactly.
//! - `cs0-tenure-key-read-as-served` is a control that hands the GET's
//!   judge a planted observation: the read complete with the resident
//!   object's bytes.
//! - `cs0-tenure-key-left-judged-covered` is a control of the binding
//!   check: the INVALIDATE names another key, so key 1 stays bound, and
//!   the covered history's lookup of key 1 finds the object and fails it
//!   through the rule. Its script issues no GET.
//! - `cs0-tenure-binding-unread` closes the storage's admission after the
//!   acknowledgment, so no registration can look the key up. It ends
//!   unsuccessful under the premise that the binding was read.
//!
//! CS2 judges the acknowledging tenure itself, with no stop and no
//! successor, over an INVALIDATE of more than one version. The property is
//! the oracle's rule "a hit of a version an acknowledged invalidation
//! covered". The tenure fences both coverage pages, installs the fencing
//! before its first fill, and acknowledges INVALIDATE(key 1, `[1, 2]`).
//!
//! - `cs2-tenure-put-of-the-highest-version-its-invalidate-covers`: the
//!   client uploads key 1 at version 2, the interval's upper end, and once
//!   that upload ended a GET of the key must end `Missing`.
//! - `cs2-tenure-put-of-the-first-version-above-its-invalidate` is the
//!   sibling: the client uploads version 3, the first the interval leaves,
//!   which publishes and reads back exactly.
//! - The `cs2-tenure-key-read-as-served` control gives the GET's judge a
//!   planted observation: a completed read containing the upload's bytes.
//! - `cs2-tenure-get-of-the-covered-key-cancelled` cancels the GET on
//!   issue. The GET ends `Failed(Cancelled)`, leaving presence
//!   undetermined, and the run ends unsuccessful.
//!
//! The first tenure's installed fencing, its acknowledgment, the relaunch
//! over the shared media, the successor's installed fencing and the
//! successor's fences committing on the pages the first tenure wrote are
//! premises read from the owner, the acknowledged list of
//! `Owner::cover_pending`, the media handle and the store's commit counts,
//! which exist with and without a defect; one that does not form ends the
//! run unsuccessful under its name. The proven stop is judged by `reset_ended` under its
//! Custody rules.

use std::cell::RefCell;
use std::rc::Rc;

use crate::storage::page_coverage::{Fencing, Interval, Progress};
use crate::storage::store::Key;
use crate::storage::store::sim::Shared;
use crate::storage::store_tests::{client, record_under, seeded_under};
use crate::storage::{CacheVersion, LookupError};

use super::super::STRANGER;
use super::incidents::uploader_idle;
use super::keyops::close_storage;
use super::*;

/// The rule for a successor tenure that published, or served, a FILL of a
/// key whose INVALIDATE an earlier tenure acknowledged: a tenure that
/// fenced every page covers every INVALIDATE an earlier tenure
/// acknowledged, and no resident FILL is such an entry.
pub(crate) const SUCCESSOR_PUBLISHED: &str =
    "a successor published a FILL its predecessor's acknowledged INVALIDATE covers";

const FENCED: &str = "the first tenure fenced its coverage before its first fill";
const ACKNOWLEDGED: &str = "the first tenure acknowledged its INVALIDATE";
const RELAUNCHED: &str = "the successor relaunched over the shared media";
const ADOPTED: &str = "the successor installed its fencing";
const SAME_PAGES: &str = "the successor's fences committed on the pages the first tenure wrote";
const REFUSED: &str = "the successor's upload of the covered key ended unpublished";

/// The rule for a tenure whose storage maps, or whose GET serves, a
/// version of a key that its own acknowledged INVALIDATE covers.
const TENURE_BOUND: &str = "an owner binds a version an acknowledged invalidation covered";

const RESIDENT: &str = "the tenure fenced its coverage over the resident key";
const UNBOUND: &str = "the storage maps no object under the covered key";
const KEPT: &str = "the storage maps the key the INVALIDATE left";
const PROBED: &str = "the key's binding was read";

/// The rule for a tenure that served a version of a key its own
/// acknowledged INVALIDATE covers.
pub(crate) const COVERED_HIT: &str = "a hit of a version an acknowledged invalidation covered";

const ENDED: &str = "the upload of the covered version ended";

/// The upper end of the interval CS2's INVALIDATE names, `[1, 2]`: not a
/// point, and above version 0.
const HIGH: u64 = 2;

thread_local! {
    /// The store the first tenure's pages live in, kept for the successor
    /// of the same run, and the commits its coverage pages held once the
    /// first tenure's INVALIDATE was acknowledged. Each run's first step
    /// replaces the store.
    static STORE: RefCell<Option<(Shared, usize)>> = const { RefCell::new(None) };
}

/// The run's store.
fn store() -> Shared {
    STORE
        .with(|cell| cell.borrow().as_ref().map(|(store, _)| store.clone()))
        .expect("the run's store")
}

/// The commits `store` holds on the coverage pages of the owner's shard.
fn page_commits(world: &Mixed<'_, '_, '_>, store: &Shared) -> usize {
    let record = record_under(world.scene.owner.tenure());
    (0..record.pages.get())
        .map(|at| store.0.borrow().commit_count(&Key::Page(record.shard, at)))
        .sum()
}

/// The entry each history's INVALIDATE names: version 0 alone, the
/// version an upload that names none records.
fn entry() -> Interval {
    Interval::new(CacheVersion(0), CacheVersion(0)).expect("a point interval")
}

/// The fencing of every coverage page of `session`'s tenure over `store`,
/// at most four intervals of one key on a page; `None` when `Fencing::new`
/// refuses the session or a page stays unfenced.
pub(super) fn fenced_pages(store: &Shared, session: &crate::storage::Session) -> Option<Fencing> {
    let mut client = client(store);
    let record = record_under(session);
    let mut fencing = Fencing::new(&record, session, 4).ok()?;
    (0..record.pages.get())
        .all(|at| (0..8).any(|_| fencing.fence(&mut client, at) == Ok(Progress::Done)))
        .then_some(fencing)
}

/// Fences every coverage page of the owner's tenure over `store` and
/// installs the fencing; whether every page fenced and the owner took the
/// fencing.
pub(super) fn fence_over(world: &mut Mixed<'_, '_, '_>, store: &Shared) -> bool {
    let fenced = fenced_pages(store, world.scene.owner.tenure());
    fenced.is_some_and(|fencing| world.scene.owner.install_coverage(fencing).is_ok())
}

/// The first tenure fences a fresh store, which the run keeps for its
/// successor.
fn fence_first(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let store = seeded_under(world.scene.owner.tenure());
    STORE.with(|cell| *cell.borrow_mut() = Some((store.clone(), 0)));
    let installed = fence_over(world, &store);
    premised(world, installed, FENCED)
}

/// The first tenure takes INVALIDATE(`name`, `[0, 0]`) and writes its
/// coverage page; the premise forms when that write acknowledged the
/// entry.
fn invalidate_named(world: &mut Mixed<'_, '_, '_>, name: u8, now: u64) -> u64 {
    invalidate_over(world, name, entry(), now)
}

/// The tenure takes INVALIDATE(`name`, `entry`) and writes its coverage
/// page; the premise forms when that write acknowledged exactly the entry.
fn invalidate_over(world: &mut Mixed<'_, '_, '_>, name: u8, entry: Interval, now: u64) -> u64 {
    let store = store();
    let mut client = client(&store);
    let held = world
        .scene
        .owner
        .invalidate_interval(&key(name), entry, 4, &mut budget())
        .is_ok();
    let mut acknowledged = Vec::new();
    let covered = world
        .scene
        .owner
        .cover_pending(&mut client, &mut acknowledged, now)
        .is_ok();
    world.owner_due = now;
    let commits = page_commits(world, &store);
    STORE.with(|cell| *cell.borrow_mut() = Some((store, commits)));
    let formed = held && covered && acknowledged == [(key(name), entry)];
    premised(world, formed, ACKNOWLEDGED)
}

fn invalidate_key(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    invalidate_named(world, 1, now)
}

/// The sibling's INVALIDATE names a key no object is published under.
fn invalidate_other(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    invalidate_named(world, STRANGER, now)
}

fn relaunchable(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.relaunchable()
}

/// Relaunches the stopped owner; the premise forms when the next
/// incarnation's device shares the dead one's media handle.
fn relaunch(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let media = world.scene.control.shared_media();
    world.relaunch(now);
    let shared = Rc::ptr_eq(&media, &world.scene.control.shared_media());
    premised(world, shared, RELAUNCHED)
}

/// The successor fences the pages of the first tenure's store. The
/// second premise forms when those pages held exactly the commits the
/// first tenure left and the successor's fences added to them.
fn fence_successor(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let store = store();
    let left = STORE.with(|cell| cell.borrow().as_ref().map_or(0, |(_, commits)| *commits));
    let before = page_commits(world, &store);
    let installed = fence_over(world, &store);
    if premised(world, installed, ADOPTED) == 0 {
        return 0;
    }
    let same = left > 0 && before == left && page_commits(world, &store) > before;
    premised(world, same, SAME_PAGES)
}

/// A control: the successor fences the pages of a fresh store, which hold
/// nothing its predecessor wrote.
fn fence_other_pages(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let store = seeded_under(world.scene.owner.tenure());
    let installed = fence_over(world, &store);
    premised(world, installed, ADOPTED)
}

/// Starts the successor's upload of key 1 and keeps the owner's published
/// count to compare.
fn begin(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.published = world.scene.owner.put_report().published;
    put_begin(world, now)
}

/// The upload ended before this step, as one refused at its BEGIN does.
fn ended(world: &Mixed<'_, '_, '_>) -> bool {
    world
        .history
        .put
        .is_some_and(|id| world.scene.clients[0].put_outcome(id).is_some())
}

/// Prepares the upload unless its BEGIN already ended it.
fn prepare_live(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if ended(world) {
        return 1;
    }
    put_prepare(world, now)
}

/// Supplies the upload's DATA unless the upload already ended.
fn supply_live(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if ended(world) {
        return 1;
    }
    put_supply(world, now)
}

/// The successor's upload of the covered key ended other than published
/// and the successor published nothing.
fn unpublished(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    let published = world.scene.owner.put_report().published != world.history.published;
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    if published || outcome == Some(UploadOutcome::Published) {
        return fail(world, Obligation::History, SUCCESSOR_PUBLISHED);
    }
    mark(world, REFUSED)
}

/// The GET of the covered key delivered nothing.
fn key_missed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    judge_read(world, outcome, &bytes)
}

/// A control: the GET is read as complete with the upload's bytes, as a
/// successor that served the covered FILL would leave it.
fn key_served(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let _ = fresh_result(world);
    judge_read(world, Some(Outcome::Complete), &version_b())
}

/// Judges a GET of the covered key under the successor: it completes
/// nothing and delivers no byte.
fn judge_read(world: &mut Mixed<'_, '_, '_>, outcome: Option<Outcome>, bytes: &[u8]) -> u64 {
    if outcome == Some(Outcome::Complete) || !bytes.is_empty() {
        return fail(world, Obligation::History, SUCCESSOR_PUBLISHED);
    }
    mark(world, "fresh GET missed")
}

/// Whether the owner's storage maps key `name` now, read through a fresh
/// registration. `Some(false)` only for a lookup that ended `Missing`, the
/// complete search that found no object. A lookup that found the object
/// and refused its lease as `Expired` or `RetainLimit` is `Some(true)`.
/// A refused registration and every other lookup refusal are `None`.
fn binding(world: &Mixed<'_, '_, '_>, name: u8) -> Option<bool> {
    let mut reader = world.storage().register().ok()?;
    match reader.lookup(&key(name), 4, &mut crate::storage::WorkBudget::new(1 << 16)) {
        Ok(_) | Err(LookupError::Expired | LookupError::RetainLimit) => Some(true),
        Err(LookupError::Missing) => Some(false),
        Err(_) => None,
    }
}

/// The tenure fences a fresh store over the key the scene published. The
/// premise forms when every page fenced, the owner took the fencing, and
/// key 1 is resident under it.
fn fence_resident(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let store = seeded_under(world.scene.owner.tenure());
    STORE.with(|cell| *cell.borrow_mut() = Some((store.clone(), 0)));
    let installed = fence_over(world, &store);
    let resident = binding(world, 1) == Some(true);
    premised(world, installed && resident, RESIDENT)
}

/// After the acknowledgment the owner's storage maps nothing under the
/// covered key. A binding that cannot be read leaves the premise unformed.
fn key_unbound(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some(bound) = binding(world, 1) else {
        return premised(world, false, PROBED);
    };
    mark(world, PROBED);
    if bound {
        return fail(world, Obligation::History, TENURE_BOUND);
    }
    mark(world, UNBOUND)
}

/// The sibling: the key the INVALIDATE left stays bound.
fn key_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let kept = binding(world, 1) == Some(true);
    premised(world, kept, KEPT)
}

/// A GET of the key the tenure's own INVALIDATE covers ends `Missing` with
/// no byte delivered.
fn key_unserved(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    judge_unserved(world, outcome, &bytes)
}

/// A control: the GET is read as complete with the resident object's
/// bytes, as a tenure that served the key its INVALIDATE covers would
/// leave it.
fn key_served_bound(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let _ = fresh_result(world);
    judge_unserved(world, Some(Outcome::Complete), &version_a())
}

/// Judges a GET of the key the tenure's own INVALIDATE covers. A GET that
/// completes or delivers a byte breaks the rule. Any ending other than
/// `Missing` proves no absence and leaves the miss unformed.
fn judge_unserved(world: &mut Mixed<'_, '_, '_>, outcome: Option<Outcome>, bytes: &[u8]) -> u64 {
    if outcome == Some(Outcome::Complete) || !bytes.is_empty() {
        return fail(world, Obligation::History, TENURE_BOUND);
    }
    premised(world, outcome == Some(Outcome::Missing), "fresh GET missed")
}

/// The sibling: a GET of the key the INVALIDATE left reads the resident
/// object exactly.
fn key_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fresh_exact_of(world, &version_a())
}

const CS0_COVERED: [Step; 6] = [
    step("fence", active_put, fence_resident),
    step("invalidate", always, invalidate_key),
    step("key-binding", always, key_unbound),
    step("key-get", active_put, fresh_get),
    step("key-read", fresh_decided, key_unserved),
    JUDGE,
];

const CS0_LEFT: [Step; 6] = replaced(
    replaced(
        replaced(
            CS0_COVERED,
            "invalidate",
            step("invalidate-other", always, invalidate_other),
        ),
        "key-binding",
        step("key-binding", always, key_kept),
    ),
    "key-read",
    step("key-read", fresh_decided, key_exact),
);

const CS0_UNREAD: [Step; 7] = [
    step("fence", active_put, fence_resident),
    step("invalidate", always, invalidate_key),
    step("close-storage", always, close_storage),
    step("key-binding", always, key_unbound),
    step("key-get", active_put, fresh_get),
    step("key-read", fresh_decided, key_unserved),
    JUDGE,
];

const CS0_SERVED: [Step; 6] = replaced(
    CS0_COVERED,
    "key-read",
    step("key-read-served", fresh_decided, key_served_bound),
);

/// The control's script ends at the binding check, so the GET's judge,
/// which raises the same rule, takes no part in its ending.
const CS0_LEFT_JUDGED_COVERED: [Step; 4] = [
    step("fence", active_put, fence_resident),
    step("invalidate-other", always, invalidate_other),
    step("key-binding", always, key_unbound),
    JUDGE,
];

const CS0_COVERED_WITNESSES: &[&str] =
    &[RESIDENT, ACKNOWLEDGED, PROBED, UNBOUND, "fresh GET missed"];

const CS0_LEFT_WITNESSES: &[&str] = &[RESIDENT, ACKNOWLEDGED, KEPT, "qualified exact read"];

const CS0: &[Obligation] = &[Obligation::History];

const CS0_PREMISE: &[&str] = &[RESIDENT, ACKNOWLEDGED, PROBED, UNBOUND];

const CS0_PROBED_PREMISE: &[&str] = &[RESIDENT, ACKNOWLEDGED, PROBED];

/// CS2's INVALIDATE names versions 1 to `HIGH` of key 1.
fn invalidate_versions(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let versions =
        Interval::new(CacheVersion(1), CacheVersion(HIGH)).expect("an interval of two versions");
    invalidate_over(world, 1, versions, now)
}

/// The upload names the highest version the INVALIDATE covers.
fn begin_covered(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    put_begin_with(world, CacheVersion(HIGH), version_b(), LABEL_B, now)
}

/// The sibling's upload names the first version above the interval.
fn begin_above(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    put_begin_with(world, CacheVersion(HIGH + 1), version_b(), LABEL_B, now)
}

/// The upload of the covered version ended, whatever its outcome: the read
/// judges whether it is served.
fn upload_ended(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    premised(world, outcome.is_some(), ENDED)
}

/// After the upload ended, a GET of the covered version's key must end
/// `Missing`.
fn version_missed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    judge_version(world, outcome, &bytes)
}

/// This control models a tenure serving the version its INVALIDATE covers.
fn version_served(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let _ = fresh_result(world);
    judge_version(world, Some(Outcome::Complete), &version_b())
}

/// Only a `Missing` GET outcome establishes that the covered version is
/// absent.
fn judge_version(world: &mut Mixed<'_, '_, '_>, outcome: Option<Outcome>, bytes: &[u8]) -> u64 {
    if outcome == Some(Outcome::Complete) || !bytes.is_empty() {
        return fail(world, Obligation::History, COVERED_HIT);
    }
    premised(world, outcome == Some(Outcome::Missing), "fresh GET missed")
}

const CS2_COVERED: [Step; 9] = [
    step("fence", active_put, fence_first),
    step("invalidate", always, invalidate_versions),
    step("put-begin", active_put, begin_covered),
    step("put-prepare", always, prepare_live),
    step("put-supply", always, supply_live),
    step("put-result", put_decided, upload_ended),
    step("key-get", uploader_idle, fresh_get),
    step("key-read", fresh_decided, version_missed),
    JUDGE,
];

const CS2_ABOVE: [Step; 9] = replaced(
    replaced(
        replaced(
            CS2_COVERED,
            "put-begin",
            step("put-begin", active_put, begin_above),
        ),
        "put-result",
        step("put-result", put_decided, put_published),
    ),
    "key-read",
    step("key-read", fresh_decided, fresh_exact_b),
);

const CS2_CANCELLED: [Step; 9] = replaced(
    CS2_COVERED,
    "key-get",
    step("key-get-cancelled", uploader_idle, fresh_get_cancelled),
);

const CS2_SERVED: [Step; 9] = replaced(
    CS2_COVERED,
    "key-read",
    step("key-read-as-served", fresh_decided, version_served),
);

const CS2_COVERED_WITNESSES: &[&str] = &[FENCED, ACKNOWLEDGED, ENDED, "fresh GET missed"];

const CS2_ABOVE_WITNESSES: &[&str] = &[
    FENCED,
    ACKNOWLEDGED,
    "upload prepared",
    "upload DATA supplied",
    "upload published",
    "qualified exact read",
];

const CS2: &[Obligation] = &[Obligation::History];

const CS2_PREMISE: &[&str] = &[FENCED, ACKNOWLEDGED, ENDED];

const CS1_COVERED: [Step; 13] = [
    step("fence", active_put, fence_first),
    step("invalidate", always, invalidate_key),
    step("stop", always, reset_stop),
    step("stop-ended", owner_polled, reset_ended),
    step("relaunch", relaunchable, relaunch),
    step("fence-successor", active_put, fence_successor),
    step("put-begin", active_put, begin),
    step("put-prepare", always, prepare_live),
    step("put-supply", always, supply_live),
    step("put-result", put_decided, unpublished),
    step("key-get", active_put, fresh_get),
    step("key-read", fresh_decided, key_missed),
    JUDGE,
];

const CS1_UNCOVERED: [Step; 13] = replaced(
    replaced(
        replaced(
            CS1_COVERED,
            "invalidate",
            step("invalidate-other", always, invalidate_other),
        ),
        "put-result",
        step("put-result", put_decided, put_published),
    ),
    "key-read",
    step("key-read", fresh_decided, fresh_exact_b),
);

const CS1_OTHER_PAGES: [Step; 13] = replaced(
    CS1_COVERED,
    "fence-successor",
    step("fence-other-pages", active_put, fence_other_pages),
);

const CS1_SERVED: [Step; 13] = replaced(
    CS1_COVERED,
    "key-read",
    step("key-read-as-served", fresh_decided, key_served),
);

const CS1_COVERED_WITNESSES: &[&str] = &[
    FENCED,
    ACKNOWLEDGED,
    "the proven stop ended its device custody",
    RELAUNCHED,
    ADOPTED,
    SAME_PAGES,
    REFUSED,
    "fresh GET missed",
];

const CS1_UNCOVERED_WITNESSES: &[&str] = &[
    FENCED,
    ACKNOWLEDGED,
    "the proven stop ended its device custody",
    RELAUNCHED,
    ADOPTED,
    SAME_PAGES,
    "upload prepared",
    "upload DATA supplied",
    "upload published",
    "qualified exact read",
];

const CS1: &[Obligation] = &[Obligation::Custody, Obligation::History];

/// The marks a control's kill needs: the first tenure's installed fencing
/// and its acknowledgment, the relaunch and the successor's installed
/// fencing.
const CS1_PREMISE: &[&str] = &[FENCED, ACKNOWLEDGED, RELAUNCHED, ADOPTED];

pub(super) const COVERED_SUCCESSORS: [History; 13] = [
    relaunching(
        uploading(
            history(
                "cs1-successor-put-of-a-key-its-predecessor-invalidated",
                &CS1_COVERED,
                CS1_COVERED_WITNESSES,
                CS1,
                Expect::Pass,
            ),
            1,
        ),
        1,
    ),
    relaunching(
        uploading(
            history(
                "cs1-successor-put-of-a-key-its-predecessor-left",
                &CS1_UNCOVERED,
                CS1_UNCOVERED_WITNESSES,
                CS1,
                Expect::Pass,
            ),
            1,
        ),
        1,
    ),
    control(
        relaunching(
            uploading(
                history(
                    "cs1-successor-fenced-other-pages",
                    &CS1_OTHER_PAGES,
                    CS1_COVERED_WITNESSES,
                    CS1,
                    Expect::Violation(Obligation::History, SUCCESSOR_PUBLISHED),
                ),
                1,
            ),
            1,
        ),
        CS1_PREMISE,
    ),
    control(
        relaunching(
            uploading(
                history(
                    "cs1-successor-key-read-as-served",
                    &CS1_SERVED,
                    CS1_COVERED_WITNESSES,
                    CS1,
                    Expect::Violation(Obligation::History, SUCCESSOR_PUBLISHED),
                ),
                1,
            ),
            1,
        ),
        CS1_PREMISE,
    ),
    history(
        "cs0-tenure-binding-of-a-key-its-invalidate-covered",
        &CS0_COVERED,
        CS0_COVERED_WITNESSES,
        CS0,
        Expect::Pass,
    ),
    history(
        "cs0-tenure-binding-of-a-key-its-invalidate-left",
        &CS0_LEFT,
        CS0_LEFT_WITNESSES,
        CS0,
        Expect::Pass,
    ),
    control(
        history(
            "cs0-tenure-key-read-as-served",
            &CS0_SERVED,
            CS0_COVERED_WITNESSES,
            CS0,
            Expect::Violation(Obligation::History, TENURE_BOUND),
        ),
        CS0_PREMISE,
    ),
    control(
        history(
            "cs0-tenure-key-left-judged-covered",
            &CS0_LEFT_JUDGED_COVERED,
            CS0_COVERED_WITNESSES,
            CS0,
            Expect::Violation(Obligation::History, TENURE_BOUND),
        ),
        CS0_PROBED_PREMISE,
    ),
    history(
        "cs0-tenure-binding-unread",
        &CS0_UNREAD,
        CS0_COVERED_WITNESSES,
        CS0,
        Expect::Unsuccessful(PROBED),
    ),
    uploading(
        history(
            "cs2-tenure-put-of-the-highest-version-its-invalidate-covers",
            &CS2_COVERED,
            CS2_COVERED_WITNESSES,
            CS2,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "cs2-tenure-put-of-the-first-version-above-its-invalidate",
            &CS2_ABOVE,
            CS2_ABOVE_WITNESSES,
            CS2,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "cs2-tenure-get-of-the-covered-key-cancelled",
            &CS2_CANCELLED,
            CS2_COVERED_WITNESSES,
            CS2,
            Expect::Unsuccessful("fresh GET missed"),
        ),
        1,
    ),
    control(
        uploading(
            history(
                "cs2-tenure-key-read-as-served",
                &CS2_SERVED,
                CS2_COVERED_WITNESSES,
                CS2,
                Expect::Violation(Obligation::History, COVERED_HIT),
            ),
            1,
        ),
        CS2_PREMISE,
    ),
];

#[cfg(test)]
mod tests;
