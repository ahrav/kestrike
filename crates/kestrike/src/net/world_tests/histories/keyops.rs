//! Key-operation histories: each family reaches one refusal of the storage's
//! per-key operations through the owner's local fill path and the storage
//! the owner serves from, and judges that the key is left as the refusal's
//! property states. Its steps call the owner and the storage as a local
//! integrator does beside the owner's requests. Each family holds the
//! refused history, a sibling that runs its steps without the fault, and a
//! control.
//!
//! K1 refuses a local fill's publication four ways. `k1-publish-revoked`
//! starts from REVOKE (`storage` module documentation; obligation record
//! `fill-end-disposes-then-departs-under-revocation-and-loss`): an
//! acknowledged invalidation revokes the written fill beside the resident it
//! removes, the fill's publication is refused `Superseded`, and a GET misses.
//! `k1-publish-expired` starts from the deadline rule (`storage::slot`
//! documentation of `expires_at_s`: no object is served at or after its
//! deadline): a publication whose deadline has passed is refused `Expired`
//! and the incumbent stays exact. `k1-publish-incomplete` starts from
//! PUBLISH-COMPLETE (`storage` module documentation; obligation record
//! `write-counts-tile-extent-gate-publish`): a publication while the fill's
//! write is outstanding is refused `Incomplete` and the incumbent stays
//! exact. `k1-publish-admitted` runs the fill and its publication with no
//! fault and reads the replacement exactly. Each of these faulted histories
//! then fills, publishes and reads a second replacement exactly.
//! `k1-publish-failed-write` starts from the oracle's rule for a publication
//! before every write of its attempt delivered success: it holds the owner's
//! write commands, fails the fill's first held write at the device with an
//! I/O error that moves no byte, releases the writes and, once the device
//! delivered the terminal of every one of the fill's writes, publishes the
//! fill. The publication is refused and the incumbent stays exact; a lease
//! fails the run with the oracle's rule. `k1-publish-after-held-writes` runs
//! the same hold and release with no fault: the fill publishes and is read
//! exactly. Each history's judgment has a control that runs the other
//! history's steps under it: `k1-publish-held-writes-judged-failed` judges
//! the unfaulted fill's publication as one after a failed write, and
//! `k1-publish-failed-write-judged-published` judges the faulted fill's
//! refused publication as one that must publish.
//!
//! K2 starts from the eviction commit's rule (`storage::evict`
//! documentation: a victim whose fingerprint has a current, undeparted
//! attempt is refused `Replacing`, attempt intact, incumbent visible):
//! `k2-evict-beside-fill` runs one eviction step while a fill of the
//! resident's key is current, and the incumbent stays exact and is then
//! replaced by that fill. `k2-evict-alone` runs the step with no fill, which
//! removes the unleased resident.
//!
//! K3 starts from the fill grant's rule (`storage::attempt` documentation: at
//! most one live attempt per full key per index shard):
//! `k3-second-fill-in-progress` begins a second fill of the key while the
//! first is current, which is refused `InProgress`, and the first publishes.
//! `k3-second-fill-after-publication` begins it after the first published,
//! which is granted.
//!
//! K4 starts from REUSE (`storage` module documentation; obligation record
//! `mc-event-derived-return-oracle`): an extent returns to the allocator only
//! after service observes its slot's count at zero. Its histories run over
//! the two-slot storage, where any held unit leaves the placeable units below
//! the low watermark: the owner's maintenance evicts the resident, or the
//! first replacement's publication replaces it.
//! `k4-reserve-beside-held-slots` publishes a
//! replacement under its publisher's lease, fills a second replacement, and
//! reserves a fill of a second key while the lease holds one slot and the
//! current fill the other: the reservation is refused for space, the leased
//! replacement reads exactly, and the second replacement then publishes and
//! reads exactly. `k4-reserve-with-room` reserves for the second key before
//! the second fill, while one slot is free, which is granted.
//!
//! K5 starts from the admission cutoff (`storage` module documentation:
//! after close, admission refuses and every existing owner stays valid; the
//! oracle's rules for a publication, a fill and a lookup after the cache
//! closed): `k5-closed-admits-nothing` closes the storage's admission while
//! a written fill is kept, and the fill's publication, a fill of a second
//! key and a lookup on a reader registered before the close are each refused
//! `Closed`; close service then returns every slot and frees every fill
//! record. `k5-open-admits` runs the same three operations with admission
//! open, and each is admitted. `k5-closed-receives-nothing` starts from the
//! refusals of `WritableFill::receive` (`ReceiveError` documentation: each
//! copies no byte of the input; the oracle's rule for a receive after the
//! cache closed): it closes admission once a current fill holds the first
//! half of its payload, and the receive of the second half takes no byte
//! and answers `Closed`; the fill is aborted and close service drains.
//! `k5-open-receives` offers the second half with admission open, and the
//! fill publishes and reads exactly.
//!
//! K6 starts from the right limit (`storage::lookup` documentation of
//! `RetainLimit`: the object already holds `C` external rights; the
//! `storage::acquire` module documentation): `k6-lookup-at-right-limit`
//! leases every right of the resident, and one more lookup is refused
//! `RetainLimit`; the rights are then released and a GET reads the resident
//! exactly. `k6-lookup-below-right-limit` leaves one right free, and the
//! lookup is leased.
//!
//! K7 starts from the owner's invalidation after its close (`Owner::invalidate`
//! documentation: `Closed` after `Owner::close`, with the mapping unchanged;
//! the oracle's rule for an invalidation after the cache closed):
//! `k7-invalidate-after-close` closes the owner and then asks it to
//! invalidate key 1, which is refused `Closed` with the storage's count of
//! visible keys unchanged. `k7-invalidate-before-close` asks before the
//! close: the invalidation is acknowledged with the key's mapping removed and
//! one key fewer visible, and the owner closes afterwards. The mapping is
//! judged by the shards' visible-key counts, which `Storage::shard_report`
//! reads without a registration, a lease or the volume, so a closed owner's
//! storage is read as an open one's is.
//!
//! K8 starts from the join's rule (`storage::join` module documentation: a
//! departed publication is joinable only while its object is still the
//! key's mapping; the oracle's rule for a hit after a recorded removal of
//! its label in the same tenure): `k8-search-after-eviction` publishes a
//! fill, drops its publisher's lease, evicts the published version and
//! searches the key with `Registration::lookup_or_join`, all in one step
//! with no owner poll inside it, so the fill's departed record is still
//! unfreed when the search runs. Until the owner's service runs, the
//! evicted version's slot also still counts a right on its incarnation, so
//! a follower joined to the departed record would lease the version: the
//! join's walk of the key's mapping alone refuses it. The search leases
//! nothing, through neither a hit nor a joined follower, and a GET then
//! misses.
//! `k8-search-after-publication` runs the step without the eviction: the
//! search leases the version the fill published and a GET reads it exactly.
//! `k8-get-after-eviction-cancelled` cancels the GET at its issue. The GET
//! ends `Failed(Cancelled)`, leaving presence undetermined, and the run ends
//! unsuccessful.
//! K8 uses `k8-search-judged-after-eviction` and
//! `k8-get-judged-after-eviction` as controls.
//!
//! K9 starts from the cutoff of a closed cache (`storage::writable` module
//! documentation: close refuses new receives, reservations and
//! publications; the oracle's rule for a fill after the cache closed). Its
//! histories run over the sequence storage, where a fill of
//! [`SEQUENCED_METADATA`] metadata bytes and one body byte spans two extents
//! and claims them through a promised placement.
//! `k9-placement-across-close` promises such a fill of key 2 with no extent
//! placed, closes the owner, then places both extents and takes the shard
//! hold, and the closed owner must refuse the placement or the hold
//! `Closed`. The owner's close closes its volume's readiness and leaves the
//! storage's cutoff open, and the hold reads only the cutoff, so the hold
//! grants the fill and the history ends in the violation it declares. The
//! oracle's rule judges a fill row invoked after an acknowledged close;
//! K9's check judges the grant, which comes after the close.
//! `k9-placement-across-storage-close` runs the pin's steps with the
//! storage's own close: the shard hold reads that cutoff, the closed
//! storage refuses the kept placement `Closed`, and the history passes.
//! The hold reads the cutoff before it claims the key's index place
//! (`storage::writable` module documentation: the claims follow the record
//! check), so the check also requires the storage's additional-key claims
//! after a `Closed` to equal those before the step, and fails a `Closed`
//! that kept a claim through the same rule.
//! `k9-promise-after-close` closes the owner before the promise, which a
//! closed cache refuses `Closed` at the begin, the decision or the promise.
//! A refusal other than `Closed` leaves either check's premise unformed.
//! `k9-revoked-placement-judged-closed` revokes the kept placement with an
//! invalidation of its key, so its hold is refused `Superseded`, and
//! `k9-stale-promise-judged-closed` promises under a decision made for
//! another body, which is refused `Superseded`; both runs end unsuccessful
//! under the check's witness.
//! `k9-promise-judged-open` is a control of `k9-promise-after-close`'s
//! check: it skips the close, the open owner keeps the promise, and the
//! check fails it through the rule.
//! The `storage::readiness` invariant ALLOCATION-READY reads the other way
//! for the first history: "Fills and builders admitted earlier keep their
//! reservations or escrowed extents in every state."
//!
//! Each control runs its history's check where the fault never formed, so
//! the outcome the check forbids happens and the check fails it through its
//! rule: an invalidation skipped, a live deadline, a publication after the
//! write's terminal, an eviction after the fill ended, a second fill begun
//! after the first published, a reservation made while a slot is free, a
//! publication with admission open, a receive with admission open, a
//! lookup with one right free, an invalidation the open owner
//! acknowledges, a search and a GET of a published version that stays
//! the key's mapping, a kept placement the open owner grants, a
//! placement the open owner promised, judged as the answer to a promise
//! after the close, and a granted placement that keeps its claim, judged
//! as a `Closed` answer.

use crate::index::ShardIndex;
use crate::storage::device::sim::Fault;
use crate::storage::owner_fixture::Commit;
use crate::storage::{
    AllocationId, BeginError, CacheVersion, Decision, DeviceStatus, FillPublishError,
    FillReserveError, InvalidateError, JoinedReadError, LookupError, PlacingFill, ReceiveError,
    ShardReport, Sought, SoughtError, WriteProgress,
};

use super::super::SEQUENCED_METADATA;

use super::incidents::incumbent_kept;
use super::*;

const REVOKED_REFUSED: &str = "the revoked fill's publication was refused";
const LATE_REFUSED: &str = "the publication past its deadline was refused";
const EARLY_REFUSED: &str = "the publication before its write's terminal was refused";
const WRITES_ARMED: &str = "owner write commands held";
const WRITES_HELD: &str = "the fill's write commands held at the device";
const WRITE_FAULTED: &str = "the device accepted an I/O error for the fill's write";
const WRITES_RELEASED: &str = "the held writes released";
const TERMINALS_DELIVERED: &str = "the device delivered the terminal of every fill write";
const FAILED_REFUSED: &str = "the failed fill's publication refused";
const EVICTION_REFUSED: &str = "the eviction refused the current fill's incumbent";
const EVICTION_REMOVED: &str = "the eviction removed the unleased resident";
const SECOND_REFUSED: &str = "the second fill was refused in progress";
const LATER_GRANTED: &str = "a fill after the publication was granted";
const SPACE_REFUSED: &str = "the reservation beside the held slots was refused";
const ROOM_GRANTED: &str = "a reservation beside one held slot was granted";
const READER_REGISTERED: &str = "a reader registered";
const STORAGE_CLOSED: &str = "the storage's admission closed";
const CLOSED_DRAINED: &str = "the closed storage returned every slot and fill record";
const RIGHTS_LEASED: &str = "the resident's rights were leased";
const LIMIT_REFUSED: &str = "the lookup at the right limit was refused";
const BELOW_LEASED: &str = "a lookup below the right limit was leased";
const CLOSED_REFUSED: &str = "the closed storage refused a publication, a fill and a lookup";
const OPEN_ADMITTED: &str = "the open storage admitted a publication, a fill and a lookup";
const HALF_RECEIVED: &str = "the fill took the first half of its payload";
const RECEIVE_REFUSED: &str = "the closed storage's receive took no byte and answered Closed";
const REST_RECEIVED: &str = "the open storage's receive took the rest of the payload";
const KEY_RESIDENT: &str = "the storage maps the resident key";
const OWNER_CLOSED: &str = "the owner closed";
const INVALIDATE_REFUSED: &str = "the closed owner refused Closed";
const MAPPING_STAYS: &str = "the mapping stays after the refusal";
const INVALIDATE_ACKNOWLEDGED: &str = "the open owner acknowledged";
const MAPPING_REMOVED: &str = "the acknowledgment removed the mapping";
const VERSION_REMOVED: &str = "the eviction removed the version the fill published";
const NOTHING_LEASED: &str = "the search after the eviction leased nothing";
const REPLACEMENT_LEASED: &str = "the search leased the version the fill published";
const SEARCHED: &str = "the search of key 1 ran to an answer";
const REMOVED_HIT: &str = "a hit after a recorded removal of its label in the same tenure";
const PLACEMENT_PROMISED: &str = "a two-extent placement was promised";
const PLACEMENT_REVOKED: &str = "an invalidation revoked the placement";
const PLACEMENT_REFUSED: &str = "the closed owner refused the placement";
const PROMISE_REFUSED: &str = "the closed owner refused the promise";

/// The obligation each key-operation check's mark judges.
pub(super) const CHECKS: [(&str, Obligation); 20] = [
    (INVALIDATE_REFUSED, Obligation::History),
    (INVALIDATE_ACKNOWLEDGED, Obligation::History),
    (LIMIT_REFUSED, Obligation::History),
    (BELOW_LEASED, Obligation::History),
    (CLOSED_REFUSED, Obligation::History),
    (OPEN_ADMITTED, Obligation::History),
    (RECEIVE_REFUSED, Obligation::History),
    (SPACE_REFUSED, Obligation::Custody),
    (ROOM_GRANTED, Obligation::Custody),
    (REVOKED_REFUSED, Obligation::History),
    (LATE_REFUSED, Obligation::History),
    (EARLY_REFUSED, Obligation::History),
    (FAILED_REFUSED, Obligation::History),
    (EVICTION_REFUSED, Obligation::History),
    (EVICTION_REMOVED, Obligation::History),
    (SECOND_REFUSED, Obligation::History),
    (LATER_GRANTED, Obligation::History),
    (NOTHING_LEASED, Obligation::History),
    (PLACEMENT_REFUSED, Obligation::History),
    (PROMISE_REFUSED, Obligation::History),
];

/// What the kept fill's publication answered.
enum Answer {
    /// The refusal the history's fault requires.
    Refused,
    Published,
    /// Another refusal: the fault's premise did not form.
    Other,
}

/// Publishes the kept fill under `deadline` and classifies the answer
/// against `refused`, the refusal the fault requires. The refused fill's
/// record and unit return through the owner's maintenance, so the history
/// waits out the owner's maintenance rest before its second replacement.
fn publication(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    deadline: u64,
    refused: FillPublishError,
) -> Answer {
    let fill = world.history.fill.take().expect("a kept fill");
    let answer = world
        .scene
        .owner
        .publish_fill(fill, deadline, 2, &mut budget());
    rest(world, now);
    match answer {
        Ok(_) => Answer::Published,
        Err(error) if error == refused => Answer::Refused,
        Err(_) => Answer::Other,
    }
}

/// World time past the owner's maintenance rest.
const REST_US: u64 = 10 * super::super::super::owner::MAINTAIN_REST_US;

/// Makes the owner due at `now` and wakes the run once its maintenance rest
/// has passed.
pub(super) fn rest(world: &mut Mixed<'_, '_, '_>, now: u64) {
    world.owner_due = now;
    world.history.released_at = now;
    world.history.wake = Some(now + REST_US);
}

pub(super) fn rested(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    now >= world.history.released_at + REST_US
}

/// Ends the run unsuccessful: the premise behind `witness` did not form.
fn unformed(world: &mut Mixed<'_, '_, '_>, witness: &'static str) -> u64 {
    world.first.record(Failure::Unsuccessful(witness));
    0
}

/// A deadline one minute past `now`, as the replacement's publication takes.
fn live_deadline(now: u64) -> u64 {
    ticks(now + 60 * super::super::SECOND_US)
}

fn publish_revoked(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match publication(world, now, live_deadline(now), FillPublishError::Superseded) {
        Answer::Refused => mark(world, REVOKED_REFUSED),
        Answer::Published => fail(
            world,
            Obligation::History,
            "a fill revoked by an invalidation or a tenure change published",
        ),
        Answer::Other => unformed(world, REVOKED_REFUSED),
    }
}

/// Judges the kept fill's publication under `deadline` as one at or past its
/// deadline: `Expired` marks `refused`, a lease is the violation, and
/// another refusal leaves the premise behind `refused` unformed.
pub(super) fn judge_reached(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    deadline: u64,
    refused: &'static str,
) -> u64 {
    match publication(world, now, deadline, FillPublishError::Expired) {
        Answer::Refused => mark(world, refused),
        Answer::Published => fail(
            world,
            Obligation::History,
            "a publication at or past its deadline",
        ),
        Answer::Other => unformed(world, refused),
    }
}

fn judge_expired(world: &mut Mixed<'_, '_, '_>, now: u64, deadline: u64) -> u64 {
    judge_reached(world, now, deadline, LATE_REFUSED)
}

/// The deadline is the timeline's first tick, which every sample has reached.
fn publish_expired(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_expired(world, now, 1)
}

/// A control: the publication carries a live deadline and is judged as one
/// past its deadline.
fn publish_live_as_expired(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_expired(world, now, live_deadline(now))
}

/// Fills the replacement and publishes it in the same step, while its one
/// write command is outstanding. A refused fill repeats the step, and a
/// write that is no longer outstanding leaves the premise unformed.
fn publish_incomplete(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if fill_b(world, now) == STAY {
        return STAY;
    }
    let outstanding = world
        .history
        .fill
        .as_ref()
        .is_some_and(|fill| world.scene.owner.fill_progress(fill).outstanding_commands == 1);
    if !outstanding {
        return unformed(world, EARLY_REFUSED);
    }
    publish_written_as_incomplete(world, now)
}

/// Judges the kept fill's publication as one before its write's terminal; a
/// control runs it once the write completed.
fn publish_written_as_incomplete(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match publication(world, now, live_deadline(now), FillPublishError::Incomplete) {
        Answer::Refused => mark(world, EARLY_REFUSED),
        Answer::Published => fail(
            world,
            Obligation::History,
            "a publication before its writes completed",
        ),
        Answer::Other => unformed(world, EARLY_REFUSED),
    }
}

/// Fills the second replacement. A refused fill that departed unrevoked
/// stays the key's attempt until the owner's fill service frees its record,
/// so a refused grant, admission or reservation repeats the step after
/// another maintenance rest.
pub(super) fn fill_second(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    fill_later(world, now, &version_c(), LABEL_C)
}

/// Fills a later replacement of key 1; a refused fill rests the owner
/// again and repeats the step.
pub(super) fn fill_later(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    object: &[u8],
    label: Label,
) -> u64 {
    let filled = fill_with(world, object, label);
    if filled == STAY {
        rest(world, now);
    }
    filled
}

fn fresh_exact_c(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fresh_exact_of(world, &version_c())
}

/// The second replacement a faulted history fills, publishes and reads
/// exactly once its refusal was judged.
const HEALED: [Step; 5] = [
    step("fill-second", rested, fill_second),
    step("publish-second", fill_written, publish_fill),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_c),
    JUDGE,
];

const K1_ADMITTED: [Step; 5] = [
    step("fill-replacement", always, fill_b),
    step("publish-replacement", fill_written, publish_fill),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const K1_REVOKED: [Step; 10] = joined(
    [
        step("fill-replacement", always, fill_b),
        step("invalidate", fill_written, invalidate),
        step("publish-revoked", fill_written, publish_revoked),
        step("fresh-get", active_put, fresh_get),
        step("fresh-miss", fresh_decided, fresh_missed),
    ],
    HEALED,
);

const K1_REVOKED_UNINVALIDATED: [Step; 10] = replaced(
    K1_REVOKED,
    "invalidate",
    step("invalidate-skipped", fill_written, removed_step),
);

const K1_EXPIRED: [Step; 9] = joined(
    [
        step("fill-replacement", always, fill_b),
        step("publish-expired", fill_written, publish_expired),
        step("incumbent-get", active_put, fresh_get),
        step("incumbent-read", fresh_decided, incumbent_kept),
    ],
    HEALED,
);

const K1_EXPIRED_LIVE: [Step; 9] = replaced(
    K1_EXPIRED,
    "publish-expired",
    step(
        "publish-live-as-expired",
        fill_written,
        publish_live_as_expired,
    ),
);

const K1_INCOMPLETE: [Step; 8] = joined(
    [
        step("publish-incomplete", always, publish_incomplete),
        step("incumbent-get", active_put, fresh_get),
        step("incumbent-read", fresh_decided, incumbent_kept),
    ],
    HEALED,
);

const K1_INCOMPLETE_WRITTEN: [Step; 9] = joined(
    [
        step("fill-replacement", always, fill_b),
        step(
            "publish-written-as-incomplete",
            fill_written,
            publish_written_as_incomplete,
        ),
        step("incumbent-get", active_put, fresh_get),
        step("incumbent-read", fresh_decided, incumbent_kept),
    ],
    HEALED,
);

/// Holds every write command the owner's device accepts from here on.
fn hold_writes(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_writes = true;
    mark(world, WRITES_ARMED)
}

/// Starts the fill of the replacement after noting how many writes the
/// history held before it, so the writes held from here on are the fill's.
fn fill_under_hold(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.supplied_at = world.history.writes.len();
    fill_b(world, now)
}

/// The write commands the history held since the fill began.
fn fill_writes<'w>(world: &'w Mixed<'_, '_, '_>) -> &'w [CommandToken] {
    &world.history.writes[world.history.supplied_at..]
}

/// The kept fill's write progress on the owner's volume.
fn progress(world: &Mixed<'_, '_, '_>) -> Option<WriteProgress> {
    let fill = world.history.fill.as_ref()?;
    Some(world.scene.owner.fill_progress(fill))
}

/// The fill submitted every unit, and the history holds at least as many
/// writes as the fill has outstanding.
fn writes_held(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    progress(world).is_some_and(|progress| {
        progress.submitted_units == progress.len_units
            && progress.outstanding_commands > 0
            && fill_writes(world).len() >= progress.outstanding_commands as usize
    })
}

/// The device holds exactly the fill's outstanding write commands, each
/// still pending.
fn held_exactly(world: &Mixed<'_, '_, '_>) -> bool {
    let outstanding = progress(world).map_or(0, |progress| progress.outstanding_commands);
    let tokens = fill_writes(world);
    let control = &world.scene.control;
    tokens.len() == outstanding as usize
        && tokens.iter().all(|&token| control.try_hold(token).is_ok())
}

/// Fails the fill's first held write at the device: it moves no byte and
/// reports an I/O error.
fn fault_write(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = held_exactly(world);
    if premised(world, held, WRITES_HELD) == 0 {
        return 0;
    }
    let token = fill_writes(world)[0];
    let status = Fault::Status(DeviceStatus::Kernel(-libc::EIO));
    let faulted = world.scene.control.try_fault(token, status).is_ok();
    premised(world, faulted, WRITE_FAULTED)
}

/// The step in the fault's place: the same premise, no fault.
fn keep_write(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = held_exactly(world);
    premised(world, held, WRITES_HELD)
}

/// Ends the hold. The history keeps the tokens to read their terminals from
/// the device.
fn release_writes(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_writes = false;
    for &token in &world.history.writes {
        world.scene.control.release(token);
    }
    mark(world, WRITES_RELEASED)
}

/// The fill has no write command outstanding.
fn writes_ended(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    progress(world).is_some_and(|progress| progress.outstanding_commands == 0)
}

/// The device's event log holds the delivery of every fill write's terminal
/// to the driver. The premise is read from the device and not from the
/// fill's progress, which is what the terminal's accounting reports.
fn terminals_delivered(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let events = world.scene.control.events();
    let delivered = fill_writes(world).iter().all(|&token| {
        events
            .iter()
            .any(|event| matches!(*event, DiskEvent::Delivered(done) if done == token))
    });
    premised(world, delivered, TERMINALS_DELIVERED)
}

/// Publishes the kept fill through the owner and returns whether the
/// publication returned a lease. The lease ends here: the judgment needs
/// only whether one was returned.
fn published_after_hold(world: &mut Mixed<'_, '_, '_>, now: u64) -> bool {
    let fill = world.history.fill.take().expect("a kept fill");
    let published = world
        .scene
        .owner
        .publish_fill(fill, live_deadline(now), 2, &mut budget())
        .is_ok();
    world.owner_due = now;
    published
}

/// A fill whose write the device failed returns no lease.
fn publish_failed_write(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if published_after_hold(world, now) {
        return fail(
            world,
            Obligation::History,
            "a publication before every write of its attempt delivered success",
        );
    }
    mark(world, FAILED_REFUSED)
}

/// A fill whose every write delivered success publishes.
fn publish_after_held_writes(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if !published_after_hold(world, now) {
        return fail(
            world,
            Obligation::Progress,
            "the replacement never published",
        );
    }
    mark(world, "replacement published")
}

/// The GET after the refused publication reads the incumbent exactly.
fn incumbent_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fresh_exact_of(world, &version_a())
}

/// One write of the fill fails at the device; the publication is refused and
/// the incumbent stays.
const K1_FAILED_WRITE: [Step; 9] = [
    step("hold-writes", always, hold_writes),
    step("fill-replacement", always, fill_under_hold),
    step("fault-write", writes_held, fault_write),
    step("release-writes", always, release_writes),
    step("write-terminals", writes_ended, terminals_delivered),
    step("publish-failed-write", always, publish_failed_write),
    step("qualified-get", active_put, fresh_get),
    step("incumbent-read", fresh_decided, incumbent_exact),
    JUDGE,
];

/// The same hold, release and publication with no fault; the replacement
/// publishes and is read.
const K1_AFTER_HELD_WRITES: [Step; 9] = [
    step("hold-writes", always, hold_writes),
    step("fill-replacement", always, fill_under_hold),
    step("keep-write", writes_held, keep_write),
    step("release-writes", always, release_writes),
    step("write-terminals", writes_ended, terminals_delivered),
    step(
        "publish-after-held-writes",
        always,
        publish_after_held_writes,
    ),
    step("qualified-get", active_put, fresh_get),
    step("replacement-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

/// A control: every write of the fill delivered success, and its
/// publication is judged as one after a failed write.
const K1_HELD_WRITES_JUDGED_FAILED: [Step; 9] = replaced(
    K1_AFTER_HELD_WRITES,
    "publish-after-held-writes",
    step("publish-judged-failed", always, publish_failed_write),
);

/// A control: the device failed one write of the fill, and its refused
/// publication is judged as one that must publish.
const K1_FAILED_WRITE_JUDGED_PUBLISHED: [Step; 9] = replaced(
    K1_FAILED_WRITE,
    "publish-failed-write",
    step(
        "publish-judged-published",
        always,
        publish_after_held_writes,
    ),
);

/// One eviction step on the owner's storage, judged for a resident whose
/// key has a current fill: `Replacing` marks the refusal, a removal is the
/// violation, and any other answer leaves the premise unformed.
fn evict_beside_fill(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    match world.evict_commit() {
        Some(Commit::Replacing) => mark(world, EVICTION_REFUSED),
        Some(Commit::Evicted { .. }) => fail(
            world,
            Obligation::History,
            "an eviction while a fill is current",
        ),
        _ => unformed(world, EVICTION_REFUSED),
    }
}

/// A control: the fill ends before the eviction step, which is judged as
/// one beside a current fill.
fn evict_after_abort(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.fill.take().expect("a kept fill").abort();
    evict_beside_fill(world, now)
}

/// One eviction step with no fill of the resident's key: it removes the
/// unleased resident.
fn evict_alone(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if !matches!(world.evict_commit(), Some(Commit::Evicted { .. })) {
        return unformed(world, EVICTION_REMOVED);
    }
    world.owner_due = now;
    mark(world, EVICTION_REMOVED)
}

const K2_BESIDE: [Step; 7] = [
    step("fill-replacement", always, fill_b),
    step("evict-beside-fill", always, evict_beside_fill),
    step("incumbent-get", active_put, fresh_get),
    step("incumbent-read", fresh_decided, incumbent_kept),
    step("publish-replacement", fill_written, publish_fill),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
];

const K2_BESIDE_JUDGED: [Step; 8] = joined(K2_BESIDE, [JUDGE]);

const K2_AFTER_ABORT: [Step; 8] = replaced(
    K2_BESIDE_JUDGED,
    "evict-beside-fill",
    step("evict-after-abort", always, evict_after_abort),
);

const K2_ALONE: [Step; 6] = joined([step("evict-alone", always, evict_alone)], K1_ADMITTED);

/// Begins a second fill of key 1 on the owner's storage and judges it
/// beside the kept fill: `InProgress` marks the refusal, a grant is the
/// violation, and any other refusal leaves the premise unformed.
fn second_fill_refused(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    match world
        .storage()
        .begin_fill(&key(1), CacheVersion(0), 2, &mut budget())
    {
        Err(BeginError::InProgress) => mark(world, SECOND_REFUSED),
        Ok(attempt) => {
            attempt.abort();
            fail(
                world,
                Obligation::History,
                "a key was granted a second fill beside its current attempt",
            )
        }
        Err(_) => unformed(world, SECOND_REFUSED),
    }
}

/// Begins a fill of key 1 once the first published: the publication ended
/// the key's attempt, so the grant succeeds.
fn later_fill_granted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    match world
        .storage()
        .begin_fill(&key(1), CacheVersion(0), 2, &mut budget())
    {
        Ok(attempt) => {
            attempt.abort();
            mark(world, LATER_GRANTED)
        }
        Err(_) => unformed(world, LATER_GRANTED),
    }
}

const K3_IN_PROGRESS: [Step; 6] = [
    step("fill-replacement", always, fill_b),
    step("second-fill", always, second_fill_refused),
    step("publish-replacement", fill_written, publish_fill),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const K3_AFTER_PUBLICATION: [Step; 6] = [
    step("fill-replacement", always, fill_b),
    step("publish-replacement", fill_written, publish_fill),
    step("later-fill", always, later_fill_granted),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const K3_JUDGED_LATE: [Step; 6] = replaced(
    K3_AFTER_PUBLICATION,
    "later-fill",
    step("second-fill-judged-late", always, second_fill_refused),
);

/// What a reservation for a second key answered.
enum Claim {
    /// The storage refused it for space: no slot, no unit beyond the clean
    /// reserve, no free run, or the retired-unit limit.
    NoSpace,
    Granted,
    /// The grant found no record: the table is full, or an earlier try's
    /// departed record is still the key's. Either waits for the owner's fill
    /// service.
    NoRecord,
    /// The grant or the reservation refused for another cause.
    Other,
}

/// Begins and reserves a fill of key 2 on the owner's storage and ends it at
/// once. The owner is made due, since its maintenance frees the ended
/// attempt's record.
fn reserve_other(world: &mut Mixed<'_, '_, '_>, now: u64) -> Claim {
    let storage = world.storage();
    let len = version_c().len();
    let mut work = budget();
    world.owner_due = now;
    let attempt = match storage.begin_fill(&key(2), CacheVersion(0), 2, &mut work) {
        Ok(attempt) => attempt,
        Err(BeginError::FillSlotsFull | BeginError::InProgress) => return Claim::NoRecord,
        Err(_) => return Claim::Other,
    };
    let Decision::Admit(admitted) = storage.decide_admission(Some(0), Some(len)) else {
        return Claim::Other;
    };
    match attempt.reserve_storage(admitted, Some(0), Some(len), 2, &mut work) {
        Ok(fill) => {
            fill.abort();
            Claim::Granted
        }
        Err(
            FillReserveError::ObjectSlotsFull
            | FillReserveError::CleanReserve
            | FillReserveError::PayloadFull
            | FillReserveError::RetiredPressure,
        ) => Claim::NoSpace,
        Err(_) => Claim::Other,
    }
}

/// Judges `claim` as the answer to a reservation made while a publisher's
/// lease holds one of the storage's two slots and a current fill the other:
/// a space refusal marks the check, and a grant took a slot a right still
/// names. A grant that found no record repeats the step, and any other
/// answer leaves the premise unformed.
fn judge_beside_held(world: &mut Mixed<'_, '_, '_>, claim: Claim) -> u64 {
    match claim {
        Claim::NoSpace => mark(world, SPACE_REFUSED),
        Claim::Granted => fail(
            world,
            Obligation::Custody,
            "a resource was reused while a custodian held an earlier incarnation",
        ),
        Claim::NoRecord => STAY,
        Claim::Other => unformed(world, SPACE_REFUSED),
    }
}

/// Reserves for the second key while the lease and a current fill hold both
/// slots, and judges the answer.
fn reserve_beside_held(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let claim = reserve_other(world, now);
    judge_beside_held(world, claim)
}

/// Reserves while the lease holds one slot and no fill is current. A
/// refusal for space or for a record repeats the step, and the reservation
/// is granted once the owner's maintenance returned the other slot and freed
/// the earlier tries' records.
fn reserve_with_room(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match reserve_other(world, now) {
        Claim::Granted => mark(world, ROOM_GRANTED),
        Claim::NoSpace | Claim::NoRecord => STAY,
        Claim::Other => unformed(world, ROOM_GRANTED),
    }
}

/// Publishes the second replacement over the first, whose lease the
/// history's kept lease replaces.
const SECOND_PUBLISHED: [Step; 4] = [
    step("publish-second", fill_written, publish_fill),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_c),
    JUDGE,
];

/// The first replacement published under its publisher's lease, which holds
/// one of the storage's two slots.
const K4_LEASED: [Step; 2] = [
    step("fill-replacement", always, fill_b),
    step("publish-replacement", fill_written, publish_fill),
];

const K4_BESIDE: [Step; 10] = joined(
    joined::<2, 4, 6>(
        K4_LEASED,
        [
            step("fill-second", always, fill_second),
            step("reserve-beside-held", always, reserve_beside_held),
            step("incumbent-get", active_put, fresh_get),
            step("incumbent-read", fresh_decided, fresh_exact_b),
        ],
    ),
    SECOND_PUBLISHED,
);

const K4_ROOM: [Step; 10] = joined(
    joined::<2, 4, 6>(
        K4_LEASED,
        [
            step("reserve-with-room", always, reserve_with_room),
            step("fill-second", always, fill_second),
            step("incumbent-get", active_put, fresh_get),
            step("incumbent-read", fresh_decided, fresh_exact_b),
        ],
    ),
    SECOND_PUBLISHED,
);

/// A control: the reservation made with a slot free is judged as one beside
/// two held slots. A refusal for space, while the other slot's return is
/// pending, repeats the step; every other answer goes to that judgment.
fn reserve_judged_with_room(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match reserve_other(world, now) {
        Claim::NoSpace => STAY,
        claim => judge_beside_held(world, claim),
    }
}

const K4_ROOM_JUDGED: [Step; 10] = replaced(
    K4_ROOM,
    "reserve-with-room",
    step("reserve-judged-with-room", always, reserve_judged_with_room),
);

/// Registers the history's reader, which a closed storage refuses.
fn register_reader(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let storage = world.storage();
    match storage.register() {
        Ok(reader) => {
            world.reader = Some(reader);
            mark(world, READER_REGISTERED)
        }
        Err(_) => unformed(world, READER_REGISTERED),
    }
}

pub(super) fn close_storage(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.storage().close();
    world.owner_due = now;
    mark(world, STORAGE_CLOSED)
}

/// Publishes the kept fill, begins a fill of key 2 and looks key 1 up, and
/// judges each answer as one a closed storage gives: `Closed` three times
/// marks the check, an admitted operation is the violation its rule names,
/// and any other refusal leaves the premise unformed.
fn closed_admits_nothing(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match publication(world, now, live_deadline(now), FillPublishError::Closed) {
        Answer::Refused => {}
        Answer::Published => {
            return fail(
                world,
                Obligation::History,
                "a publication after the cache closed",
            );
        }
        Answer::Other => return unformed(world, CLOSED_REFUSED),
    }
    match world
        .storage()
        .begin_fill(&key(2), CacheVersion(0), 2, &mut budget())
    {
        Err(BeginError::Closed) => {}
        Ok(attempt) => {
            attempt.abort();
            return fail(world, Obligation::History, ADMITTED_CLOSED);
        }
        Err(_) => return unformed(world, CLOSED_REFUSED),
    }
    match looked_up(world) {
        Some(Err(LookupError::Closed)) => mark(world, CLOSED_REFUSED),
        Some(Ok(())) => fail(
            world,
            Obligation::History,
            "a lookup answered after the cache closed",
        ),
        _ => unformed(world, CLOSED_REFUSED),
    }
}

/// A lookup of key 1 on the history's reader, its lease released at once.
fn looked_up(world: &mut Mixed<'_, '_, '_>) -> Option<Result<(), LookupError>> {
    let reader = world.reader.as_mut()?;
    Some(reader.lookup(&key(1), 2, &mut budget()).map(drop))
}

/// The open storage's answers to the same three operations: the kept fill
/// publishes, a fill of key 2 is granted and a lookup of key 1 is leased.
fn open_admits(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if !matches!(
        publication(world, now, live_deadline(now), FillPublishError::Closed),
        Answer::Published
    ) {
        return unformed(world, OPEN_ADMITTED);
    }
    match world
        .storage()
        .begin_fill(&key(2), CacheVersion(0), 2, &mut budget())
    {
        Ok(attempt) => attempt.abort(),
        Err(_) => return unformed(world, OPEN_ADMITTED),
    }
    match looked_up(world) {
        Some(Ok(())) => mark(world, OPEN_ADMITTED),
        _ => unformed(world, OPEN_ADMITTED),
    }
}

/// Releases the history's reader and runs one close-service call. The step
/// repeats until a complete call finds no slot held and no fill record
/// live: every slot returned and every fill record freed.
pub(super) fn drain_closed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.reader = None;
    world.owner_due = now;
    let drained = world
        .storage()
        .close_service(&mut budget())
        .is_ok_and(|report| {
            report.complete && report.blockers.held_slots == 0 && report.blockers.live_fills == 0
        });
    if !drained {
        return STAY;
    }
    mark(world, CLOSED_DRAINED)
}

const K5_CLOSED: [Step; 6] = [
    step("register-reader", always, register_reader),
    step("fill-replacement", always, fill_b),
    step("close-storage", fill_written, close_storage),
    step("closed-admits-nothing", always, closed_admits_nothing),
    step("drain-closed", always, drain_closed),
    JUDGE,
];

const K5_OPEN_JUDGED: [Step; 6] = replaced(
    K5_CLOSED,
    "close-storage",
    step("close-skipped", fill_written, removed_step),
);

const K5_OPEN: [Step; 6] = replaced(
    replaced(
        K5_OPEN_JUDGED,
        "closed-admits-nothing",
        step("open-admits", always, open_admits),
    ),
    "drain-closed",
    step("drain-skipped", always, removed_step),
);

/// The bytes of the replacement's first half.
fn half() -> usize {
    VERSION_B_LEN / 2
}

/// Offers `input` to the history's fill through the owner and returns the
/// receive's answer with the bytes the fill's received count moved by.
fn offer(
    world: &mut Mixed<'_, '_, '_>,
    input: &[u8],
) -> Option<(Result<usize, ReceiveError>, u64)> {
    let mut kept = world.history.fill.take()?;
    let before = kept.received();
    let io = &mut crate::storage::WorkBudget::with_io(0, usize::MAX, usize::MAX);
    let answer = world.scene.owner.receive_fill(&mut kept, input, io);
    let moved = kept.received() - before;
    world.history.fill = Some(kept);
    Some((answer, moved))
}

/// Begins the fill of key 1 with the replacement's length and receives the
/// first half of its payload. The step repeats while the reservation or a
/// receive is refused, and marks once exactly half is received.
fn receive_first_half(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let object = version_b();
    if world.history.fill.is_none() {
        let Some(begun) = fill(world.storage(), &key(1), object.len()) else {
            return STAY;
        };
        world
            .registry
            .borrow_mut()
            .register(key(1), LABEL_B, 0, object.clone());
        world.history.fill = Some(begun);
    }
    loop {
        let received = world
            .history
            .fill
            .as_ref()
            .map_or(0, |kept| kept.received()) as usize;
        if received == half() {
            return mark(world, HALF_RECEIVED);
        }
        match offer(world, &object[received..half()]) {
            Some((Ok(count), _)) if count > 0 => {}
            _ => return STAY,
        }
    }
}

/// Offers the second half to the fill of the closed storage and judges the
/// answer: an `Ok` of any count, or a byte taken under a refusal, is the
/// violation; `Closed` with no byte taken is the refusal the history
/// requires; when `moved == 0`, any other error leaves the cause of the
/// refusal unconfirmed.
fn receive_after_close(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let object = version_b();
    match offer(world, &object[half()..]) {
        Some((answer, moved)) if admitted(&answer, moved) => fail(
            world,
            Obligation::History,
            "a receive after the cache closed",
        ),
        Some((Err(ReceiveError::Closed), _)) => mark(world, RECEIVE_REFUSED),
        _ => unformed(world, RECEIVE_REFUSED),
    }
}

/// A receive the storage refuses returns an error and copies no byte, so
/// an `Ok` of any count shows an admitted receive. `moved` is the change of
/// the fill's received count across the receive, so a byte taken under a
/// refusal shows one too.
fn admitted(answer: &Result<usize, ReceiveError>, moved: u64) -> bool {
    answer.is_ok() || moved > 0
}

/// Aborts the refused fill and drains the closed storage as
/// [`drain_closed`] does.
fn abort_and_drain(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if let Some(kept) = world.history.fill.take() {
        kept.abort();
    }
    drain_closed(world, now)
}

/// Offers the rest of the payload to the fill of the open storage. The
/// step repeats while a receive is refused for a buffer or a busy table,
/// and marks once the whole payload is received.
fn receive_rest(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let object = version_b();
    loop {
        let Some(received) = world
            .history
            .fill
            .as_ref()
            .map(|kept| kept.received() as usize)
        else {
            return unformed(world, REST_RECEIVED);
        };
        if received == object.len() {
            return mark(world, REST_RECEIVED);
        }
        match offer(world, &object[received..]) {
            Some((Ok(count), _)) if count > 0 => {}
            Some((Err(ReceiveError::PoolExhausted | ReceiveError::TableFull), _)) => return STAY,
            _ => return unformed(world, REST_RECEIVED),
        }
    }
}

const K5_CLOSED_RECEIVE: [Step; 5] = [
    step("fill-first-half", always, receive_first_half),
    step("close-storage", always, close_storage),
    step("receive-after-close", always, receive_after_close),
    step("abort-and-drain", always, abort_and_drain),
    JUDGE,
];

const K5_OPEN_RECEIVE_JUDGED: [Step; 5] = replaced(
    K5_CLOSED_RECEIVE,
    "close-storage",
    step("close-skipped", always, removed_step),
);

const K5_OPEN_RECEIVE: [Step; 6] = [
    step("fill-first-half", always, receive_first_half),
    step("receive-rest", always, receive_rest),
    step("publish-replacement", fill_written, publish_fill),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const CLOSED_RECEIVE_WITNESSES: &[&str] = &[
    HALF_RECEIVED,
    STORAGE_CLOSED,
    RECEIVE_REFUSED,
    CLOSED_DRAINED,
];

const OPEN_RECEIVE_WITNESSES: &[&str] = &[
    HALF_RECEIVED,
    REST_RECEIVED,
    "replacement published",
    "qualified exact read",
];

const CLOSED_WITNESSES: &[&str] = &[
    READER_REGISTERED,
    "replacement filled",
    STORAGE_CLOSED,
    CLOSED_REFUSED,
    CLOSED_DRAINED,
];

/// The rule for an owner that, once closed, acknowledged an invalidation
/// or removed a mapping while refusing one.
const INVALIDATED_CLOSED: &str = "an invalidation after the cache closed";

/// The most shards the count of visible keys visits; the fixture's index
/// holds far fewer.
const SHARDS: usize = 1 << 10;

/// Keys the owner's storage maps now, over every enabled shard, or `None`
/// when no shard reports.
fn visible(world: &Mixed<'_, '_, '_>) -> Option<usize> {
    counted(world, |report| report.visible)
}

/// Additional-key claims the owner's storage holds now, one for each
/// reserved fill, over every enabled shard, or `None` when no shard
/// reports.
fn claims(world: &Mixed<'_, '_, '_>) -> Option<usize> {
    counted(world, |report| report.reserved)
}

/// The sum of `count` over the report of every enabled shard.
fn counted(world: &Mixed<'_, '_, '_>, count: fn(ShardReport) -> usize) -> Option<usize> {
    let storage = world.storage();
    let mut reports = (0..SHARDS).filter_map(|shard| storage.shard_report(ShardIndex(shard)));
    let first = count(reports.next()?);
    Some(reports.fold(first, |sum, report| sum + count(report)))
}

/// The premise both K7 histories start from: the storage maps at least the
/// resident key.
fn key_resident(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !visible(world).is_some_and(|keys| keys > 0) {
        return unformed(world, KEY_RESIDENT);
    }
    mark(world, KEY_RESIDENT)
}

/// The owner closes. `Owner::close` sets its admission closed whatever its
/// volume's quiesce reports.
fn close_admission(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let _ = world.scene.owner.close(now);
    world.closed = true;
    if world.scene.owner.quiesce().is_none() {
        return unformed(world, OWNER_CLOSED);
    }
    mark(world, OWNER_CLOSED)
}

/// The closed owner is asked to invalidate key 1: it must refuse `Closed`
/// and leave every mapping. Any other refusal, or a count that cannot be
/// read, leaves the premise unformed.
fn invalidate_closed(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let before = visible(world);
    let asked = world.scene.owner.invalidate(&key(1), 3, &mut budget());
    let after = visible(world);
    world.owner_due = now;
    match asked {
        Ok(_) => fail(world, Obligation::History, INVALIDATED_CLOSED),
        Err(InvalidateError::Closed) => {
            if before.is_none() || after.is_none() {
                return unformed(world, MAPPING_STAYS);
            }
            if before != after {
                return fail(world, Obligation::History, INVALIDATED_CLOSED);
            }
            mark(world, INVALIDATE_REFUSED);
            mark(world, MAPPING_STAYS)
        }
        Err(_) => unformed(world, INVALIDATE_REFUSED),
    }
}

/// The sibling: the open owner is asked to invalidate key 1 and must
/// acknowledge it with the mapping gone.
fn invalidate_open(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let before = visible(world);
    let asked = world.scene.owner.invalidate(&key(1), 3, &mut budget());
    let after = visible(world);
    world.owner_due = now;
    if !asked.is_ok_and(|done| done.removed.is_some()) {
        return unformed(world, INVALIDATE_ACKNOWLEDGED);
    }
    mark(world, INVALIDATE_ACKNOWLEDGED);
    let removed = before
        .zip(after)
        .is_some_and(|(before, after)| after + 1 == before);
    if !removed {
        return unformed(world, MAPPING_REMOVED);
    }
    mark(world, MAPPING_REMOVED)
}

const K7_AFTER_CLOSE: [Step; 4] = [
    step("resident", always, key_resident),
    step("close", always, close_admission),
    step("invalidate", always, invalidate_closed),
    JUDGE,
];

const K7_BEFORE_CLOSE: [Step; 4] = [
    step("resident", always, key_resident),
    step("invalidate", always, invalidate_open),
    step("close", always, close_admission),
    JUDGE,
];

/// A control: the close is skipped, so the open owner acknowledges the
/// invalidation and the closed owner's check fails that acknowledgment
/// through its rule.
const K7_JUDGED_OPEN: [Step; 4] = replaced(
    K7_AFTER_CLOSE,
    "close",
    step("close-skipped", always, removed_step),
);

const AFTER_CLOSE_WITNESSES: &[&str] = &[
    KEY_RESIDENT,
    OWNER_CLOSED,
    INVALIDATE_REFUSED,
    MAPPING_STAYS,
];

const BEFORE_CLOSE_WITNESSES: &[&str] = &[
    KEY_RESIDENT,
    INVALIDATE_ACKNOWLEDGED,
    MAPPING_REMOVED,
    OWNER_CLOSED,
];

/// The rights per object the scripted owner's storage is built with.
const RIGHTS: usize = 8;

/// Leases key 1 on the history's reader until the history holds `count`
/// leases; a refused lookup leaves the premise unformed.
fn lease_rights(world: &mut Mixed<'_, '_, '_>, count: usize) -> bool {
    while world.held.len() < count {
        let Some(reader) = world.reader.as_mut() else {
            return false;
        };
        match reader.lookup(&key(1), 2, &mut budget()) {
            Ok(lease) => world.held.push((0, super::super::Held::Extent(lease))),
            Err(_) => return false,
        }
    }
    true
}

fn lease_every_right(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !lease_rights(world, RIGHTS) {
        return unformed(world, RIGHTS_LEASED);
    }
    mark(world, RIGHTS_LEASED)
}

fn lease_all_but_one(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !lease_rights(world, RIGHTS - 1) {
        return unformed(world, RIGHTS_LEASED);
    }
    mark(world, RIGHTS_LEASED)
}

/// Judges a lookup of the resident whose every right is leased:
/// `RetainLimit` marks the refusal, a lease is the violation, and any other
/// answer leaves the premise unformed.
fn lookup_at_limit(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    match looked_up(world) {
        Some(Err(LookupError::RetainLimit)) => mark(world, LIMIT_REFUSED),
        Some(Ok(())) => fail(
            world,
            Obligation::History,
            "a lookup leased an object past its right limit",
        ),
        _ => unformed(world, LIMIT_REFUSED),
    }
}

/// A lookup with one right free, which is leased.
fn lookup_below_limit(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    match looked_up(world) {
        Some(Ok(())) => mark(world, BELOW_LEASED),
        _ => unformed(world, BELOW_LEASED),
    }
}

fn release_rights(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.held.clear();
    world.owner_due = now;
    1
}

const K6_AT_LIMIT: [Step; 7] = [
    step("register-reader", always, register_reader),
    step("lease-every-right", always, lease_every_right),
    step("lookup-at-limit", always, lookup_at_limit),
    step("release-rights", always, release_rights),
    step("resident-get", active_put, fresh_get),
    step("resident-read", fresh_decided, incumbent_kept),
    JUDGE,
];

const K6_JUDGED_BELOW: [Step; 7] = replaced(
    K6_AT_LIMIT,
    "lease-every-right",
    step("lease-all-but-one", always, lease_all_but_one),
);

const K6_BELOW: [Step; 7] = replaced(
    K6_JUDGED_BELOW,
    "lookup-at-limit",
    step("lookup-below-limit", always, lookup_below_limit),
);

/// Eviction steps a search history runs before the removal counts as
/// unformed. The published version is the storage's one unleased object, so
/// the policy reaches it within a few steps.
const EVICTION_STEPS: usize = 64;

/// The followers a fill record takes, and the lookup's retries and the
/// join's gate tries.
const FOLLOWERS: u64 = 4;
const RETRIES: usize = 4;
const TRIES: usize = 4;

/// What the search of key 1 ended in.
enum Found {
    /// A lease on this version, from the lookup's hit or a joined
    /// follower's acquisition.
    Leased(AllocationId),
    /// A proved miss with no joinable fill, or a joined follower whose
    /// acquisition reported the version missing.
    Nothing,
    /// The lookup, the join, the follower's acquisition or the reader's
    /// registration refused: no answer.
    Refused,
}

/// What a joined follower's refused acquisition answers. `Missing` reports
/// the version gone; every other refusal leaves the version's presence
/// undetermined, so the search has no answer.
fn unleased(refusal: JoinedReadError) -> Found {
    match refusal {
        JoinedReadError::Missing => Found::Nothing,
        JoinedReadError::Expired
        | JoinedReadError::ClockUnavailable
        | JoinedReadError::LeaseLimit
        | JoinedReadError::RetainLimit
        | JoinedReadError::Contended
        | JoinedReadError::BudgetExhausted
        | JoinedReadError::Failed(_)
        | JoinedReadError::Pending
        | JoinedReadError::Corrupt
        | JoinedReadError::Closed => Found::Refused,
    }
}

/// Searches key 1 on the world's reader of the owner's storage, registered
/// on first use. Every lease and follower the search took is returned
/// before the answer.
fn search(world: &mut Mixed<'_, '_, '_>) -> Found {
    let mut reader = match world.reader.take() {
        Some(reader) => reader,
        None => match world.storage().register() {
            Ok(reader) => reader,
            Err(_) => return Found::Refused,
        },
    };
    let sought = reader.lookup_or_join(&key(1), FOLLOWERS, RETRIES, TRIES, &mut budget());
    let found = match sought {
        Ok(Sought::Hit(lease)) => Found::Leased(lease.id()),
        Ok(Sought::Joined(follower)) => match follower.acquire(TRIES, &mut budget()) {
            Ok(lease) => Found::Leased(lease.id()),
            Err((follower, refusal)) => {
                follower.detach();
                unleased(refusal)
            }
        },
        Err(SoughtError::Missing) => Found::Nothing,
        Err(_) => Found::Refused,
    };
    world.reader = Some(reader);
    found
}

/// Publishes the kept fill and drops its publisher's lease: the published
/// version, or `None` when the publication was refused, which
/// `publish_fill` records.
fn publish_unleased(world: &mut Mixed<'_, '_, '_>, now: u64) -> Option<AllocationId> {
    publish_fill(world, now);
    world.history.lease.take().map(|lease| lease.id())
}

/// Runs eviction steps until a commit reports `version` evicted, within
/// `EVICTION_STEPS`.
fn evict(world: &Mixed<'_, '_, '_>, version: AllocationId) -> bool {
    (0..EVICTION_STEPS).any(|_| {
        matches!(
            world.evict_commit(),
            Some(Commit::Evicted { victim, .. }) if victim == version
        )
    })
}

/// Publication, the lease's drop, the eviction of the published version
/// and the judged search, with no owner poll between them. A lease is the
/// violation.
fn search_after_eviction(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let Some(version) = publish_unleased(world, now) else {
        return 0;
    };
    if !evict(world, version) {
        return unformed(world, VERSION_REMOVED);
    }
    mark(world, VERSION_REMOVED);
    judge_search(world)
}

/// The judge treats the search for key 1 as occurring after eviction of the
/// published version: a lease is the violation.
fn judge_search(world: &mut Mixed<'_, '_, '_>) -> u64 {
    match search(world) {
        Found::Leased(_) => fail(world, Obligation::History, REMOVED_HIT),
        Found::Nothing => mark(world, NOTHING_LEASED),
        Found::Refused => unformed(world, SEARCHED),
    }
}

/// The control skips eviction so the search leases the published version.
/// The eviction check rejects that lease.
fn search_judged_evicted(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if publish_unleased(world, now).is_none() {
        return 0;
    }
    judge_search(world)
}

/// Publication, the lease's drop and the search, with no eviction. The
/// search leases the published version; any other answer leaves the witness
/// unmarked.
fn search_after_publication(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let Some(version) = publish_unleased(world, now) else {
        return 0;
    };
    match search(world) {
        Found::Leased(leased) if leased == version => mark(world, REPLACEMENT_LEASED),
        _ => unformed(world, REPLACEMENT_LEASED),
    }
}

/// After eviction, a GET of key 1 must end `Missing`.
fn key_missed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    if outcome == Some(Outcome::Complete) || !bytes.is_empty() {
        return fail(world, Obligation::History, REMOVED_HIT);
    }
    if outcome != Some(Outcome::Missing) {
        return unformed(world, "fresh GET missed");
    }
    mark(world, "fresh GET missed")
}

const K8_EVICTED: [Step; 5] = [
    step("fill-replacement", always, fill_b),
    step("publish-evict-search", fill_written, search_after_eviction),
    step("key-get", active_put, fresh_get),
    step("key-read", fresh_decided, key_missed),
    JUDGE,
];

const K8_CANCELLED: [Step; 5] = replaced(
    K8_EVICTED,
    "key-get",
    step("key-get-cancelled", active_put, fresh_get_cancelled),
);

const K8_JUDGED_EVICTED: [Step; 5] = replaced(
    K8_EVICTED,
    "publish-evict-search",
    step("publish-search-judged", fill_written, search_judged_evicted),
);

const K8_KEPT: [Step; 5] = [
    step("fill-replacement", always, fill_b),
    step("publish-search", fill_written, search_after_publication),
    step("key-get", active_put, fresh_get),
    step("key-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const K8_KEPT_JUDGED_MISSED: [Step; 5] = replaced(
    K8_KEPT,
    "key-read",
    step("key-read-judged-missed", fresh_decided, key_missed),
);

/// The rule for a fill a closed cache admitted.
const ADMITTED_CLOSED: &str = "a fill admitted after the cache closed";

/// How the owner's storage answered a fill of key 2 of two extents.
enum Promised<'s> {
    Placing(PlacingFill<'s, TestPlatform>),
    /// The begin, the decision or the promise refused the fill `Closed`.
    Closed,
    /// Another refusal, or a decision that admits another extent count.
    Unformed,
}

/// Begins a fill of key 2 and promises its object of [`SEQUENCED_METADATA`]
/// metadata bytes and one body byte, which the sequence storage admits as
/// two extents. A `Closed` answer from the begin, the decision or the
/// promise is the closed cache's refusal, whichever cutoff gave it. The
/// decision is made for a body of `decided` bytes: the promise refuses a
/// decision made for another body than its own `Superseded` before it
/// reads a cutoff.
fn promise<'s>(world: &Mixed<'_, 's, '_>, decided: usize) -> Promised<'s> {
    let storage = world.storage();
    let (metadata, body) = (Some(SEQUENCED_METADATA), Some(1));
    let attempt = match storage.begin_fill(&key(2), CacheVersion(0), 2, &mut budget()) {
        Ok(attempt) => attempt,
        Err(BeginError::Closed) => return Promised::Closed,
        Err(_) => return Promised::Unformed,
    };
    let admitted = match storage.decide_admission(metadata, Some(decided)) {
        Decision::Admit(admitted) if admitted.extents() == 2 => admitted,
        Decision::Closed => return Promised::Closed,
        _ => return Promised::Unformed,
    };
    match attempt.promise_storage(admitted, metadata, body, &mut budget()) {
        Ok(placing) => Promised::Placing(placing),
        Err(FillReserveError::Closed) => Promised::Closed,
        Err(_) => Promised::Unformed,
    }
}

/// Promises the two-extent fill and keeps its placement, with no extent
/// placed.
fn promise_placement(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    match promise(world, 1) {
        Promised::Placing(placing) if placing.placed() == 0 => {
            world.history.placing = Some(placing);
            mark(world, PLACEMENT_PROMISED)
        }
        Promised::Placing(placing) => {
            placing.abort();
            unformed(world, PLACEMENT_PROMISED)
        }
        _ => unformed(world, PLACEMENT_PROMISED),
    }
}

/// Places every extent of the kept placement and takes its shard hold:
/// the granted fill, or the refusal of the placement or of the hold. The
/// answer is `None` while a placement places part of the object or finds
/// the pool gate busy, and the placement is then kept for the step's next
/// turn.
fn placed<'s, 'm>(
    world: &mut Mixed<'_, 's, 'm>,
) -> Option<Result<WritableFill<'s, 'm, TestPlatform>, FillReserveError>> {
    let mut placing = world.history.placing.take()?;
    match placing.place(&mut budget()) {
        Ok(true) => Some(placing.reserve_storage(2, &mut budget())),
        Ok(false) | Err(FillReserveError::Contended) => {
            world.history.placing = Some(placing);
            None
        }
        Err(refusal) => {
            placing.abort();
            Some(Err(refusal))
        }
    }
}

/// Judges `answer`, a closed owner's to the kept placement and its shard
/// hold, against the additional-key claims `before` them: `Closed` with
/// the claims as they stood marks the check, a granted fill or a `Closed`
/// that kept a claim is the violation its rule names, and any other
/// refusal, or a count no shard reports, leaves the premise unformed.
fn closed_placement_judged(
    world: &mut Mixed<'_, '_, '_>,
    before: Option<usize>,
    answer: Result<(), FillReserveError>,
) -> u64 {
    match answer {
        Ok(()) => fail(world, Obligation::History, ADMITTED_CLOSED),
        Err(FillReserveError::Closed) => match (before, claims(world)) {
            (Some(before), Some(after)) if before == after => mark(world, PLACEMENT_REFUSED),
            (Some(_), Some(_)) => fail(world, Obligation::History, ADMITTED_CLOSED),
            _ => unformed(world, PLACEMENT_REFUSED),
        },
        Err(_) => unformed(world, PLACEMENT_REFUSED),
    }
}

/// Places the kept placement, takes its shard hold and judges the answer
/// as a closed owner's. The step repeats while [`placed`] answers `None`.
fn place_after_close(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if world.history.placing.is_none() {
        return unformed(world, PLACEMENT_PROMISED);
    }
    world.owner_due = now;
    let before = claims(world);
    match placed(world) {
        Some(answer) => closed_placement_judged(world, before, answer.map(WritableFill::abort)),
        None => STAY,
    }
}

/// A control's step: the open owner grants the kept placement, the history
/// keeps the fill with its claim, and the step judges the grant as a
/// closed owner's `Closed`.
fn grant_judged_refused(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if world.history.placing.is_none() {
        return unformed(world, PLACEMENT_PROMISED);
    }
    world.owner_due = now;
    let before = claims(world);
    match placed(world) {
        Some(Ok(fill)) => {
            world.history.fill = Some(fill);
            closed_placement_judged(world, before, Err(FillReserveError::Closed))
        }
        Some(Err(_)) => unformed(world, PLACEMENT_REFUSED),
        None => STAY,
    }
}

/// A falsifier's step: the open owner invalidates key 2, which revokes the
/// kept placement's attempt, so its shard hold is refused `Superseded`.
fn revoke_placement(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let revoked = world
        .scene
        .owner
        .invalidate(&key(2), 3, &mut budget())
        .is_ok_and(|done| done.revoked.is_some());
    world.owner_due = now;
    if !revoked {
        return unformed(world, PLACEMENT_REVOKED);
    }
    mark(world, PLACEMENT_REVOKED)
}

/// Promises the two-extent fill once the owner has closed, and judges the
/// answer as a closed owner's: `Closed` marks the check, a granted promise
/// is the violation its rule names, and any other answer leaves the
/// premise unformed.
fn promise_after_close(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.owner_due = now;
    let answer = promise(world, 1);
    closed_promise_judged(world, answer)
}

/// A falsifier's step: the open owner refuses a promise under a decision
/// made for another body `Superseded`, and the step judges that refusal as
/// a closed owner's answer, which leaves the check's premise unformed.
fn stale_promise_judged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.owner_due = now;
    let answer = promise(world, 2);
    closed_promise_judged(world, answer)
}

/// The judgment of [`promise_after_close`], which the control
/// `k9-promise-judged-kept` also reaches.
fn closed_promise_judged(world: &mut Mixed<'_, '_, '_>, answer: Promised<'_>) -> u64 {
    match answer {
        Promised::Closed => mark(world, PROMISE_REFUSED),
        Promised::Placing(placing) => {
            placing.abort();
            fail(world, Obligation::History, ADMITTED_CLOSED)
        }
        Promised::Unformed => unformed(world, PROMISE_REFUSED),
    }
}

/// Judges the placement the open owner promised before the close as the
/// closed owner's answer to a promise.
fn kept_promise_judged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.owner_due = now;
    let Some(placing) = world.history.placing.take() else {
        return unformed(world, PLACEMENT_PROMISED);
    };
    closed_promise_judged(world, Promised::Placing(placing))
}

const K9_ACROSS: [Step; 4] = [
    step("promise-placement", always, promise_placement),
    step("close", always, close_admission),
    step("place-after-close", always, place_after_close),
    JUDGE,
];

/// The sibling: the storage's own close, whose cutoff the shard hold reads,
/// takes the owner's close's step.
const K9_ACROSS_STORAGE: [Step; 4] = replaced(
    K9_ACROSS,
    "close",
    step("close-storage", always, close_storage),
);

/// A control: the close is skipped, so the open owner grants the placed
/// fill and the closed owner's check fails that grant through its rule.
const K9_JUDGED_OPEN: [Step; 4] = replaced(
    K9_ACROSS,
    "close",
    step("close-skipped", always, removed_step),
);

/// A control: the open owner grants the placed fill, which keeps its
/// claim, and the check judges a `Closed` beside that claim through its
/// rule.
const K9_GRANT_JUDGED_REFUSED: [Step; 4] = replaced(
    K9_JUDGED_OPEN,
    "place-after-close",
    step("grant-judged-refused", always, grant_judged_refused),
);

/// A falsifier: an invalidation takes the close's step, so the hold is
/// refused `Superseded` and the check's premise stays unformed.
const K9_REVOKED: [Step; 4] = replaced(
    K9_ACROSS,
    "close",
    step("revoke-placement", always, revoke_placement),
);

const K9_BEFORE: [Step; 3] = [
    step("close", always, close_admission),
    step("promise-after-close", always, promise_after_close),
    JUDGE,
];

/// A falsifier: the promise is refused `Superseded`, so the check's
/// premise stays unformed.
const K9_STALE_PROMISE: [Step; 2] = [
    step("stale-promise-judged", always, stale_promise_judged),
    JUDGE,
];

/// A control: the placement the open owner promised before the close is
/// judged as the answer to a promise after it, and the check fails it
/// through its rule.
const K9_PROMISE_JUDGED_KEPT: [Step; 4] = [
    step("promise-placement", always, promise_placement),
    step("close", always, close_admission),
    step("kept-promise-judged", always, kept_promise_judged),
    JUDGE,
];

/// The owner never closed: it reports no quiesce progress.
const OWNER_OPEN: &str = "the owner stayed open";

/// The control's step in the place of the close: the owner is still open.
fn close_skipped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if world.scene.owner.quiesce().is_some() {
        return unformed(world, OWNER_OPEN);
    }
    mark(world, OWNER_OPEN)
}

/// A control: the sibling's close is skipped, so the open owner keeps the
/// promise and the closed owner's check fails it through its rule.
const K9_PROMISE_JUDGED_OPEN: [Step; 3] = replaced(
    K9_BEFORE,
    "close",
    step("close-skipped", always, close_skipped),
);

const ACROSS_WITNESSES: &[&str] = &[PLACEMENT_PROMISED, OWNER_CLOSED, PLACEMENT_REFUSED];
const ACROSS_STORAGE_WITNESSES: &[&str] = &[PLACEMENT_PROMISED, STORAGE_CLOSED, PLACEMENT_REFUSED];
const BEFORE_PROMISE_WITNESSES: &[&str] = &[OWNER_CLOSED, PROMISE_REFUSED];
const KEPT_PROMISE_WITNESSES: &[&str] = &[PLACEMENT_PROMISED, OWNER_CLOSED, PROMISE_REFUSED];
const REVOKED_PLACEMENT_WITNESSES: &[&str] =
    &[PLACEMENT_PROMISED, PLACEMENT_REVOKED, PLACEMENT_REFUSED];

const AT_LIMIT_WITNESSES: &[&str] = &[
    READER_REGISTERED,
    RIGHTS_LEASED,
    LIMIT_REFUSED,
    "the incumbent stayed exact",
];
const BELOW_WITNESSES: &[&str] = &[
    READER_REGISTERED,
    RIGHTS_LEASED,
    BELOW_LEASED,
    "the incumbent stayed exact",
];
const OPEN_WITNESSES: &[&str] = &[READER_REGISTERED, "replacement filled", OPEN_ADMITTED];
const EVICTED_WITNESSES: &[&str] = &[
    "replacement filled",
    "replacement published",
    VERSION_REMOVED,
    NOTHING_LEASED,
    "fresh GET missed",
];
const KEPT_WITNESSES: &[&str] = &[
    "replacement filled",
    "replacement published",
    REPLACEMENT_LEASED,
    "qualified exact read",
];

const BESIDE_HELD_WITNESSES: &[&str] = &[
    "replacement filled",
    "replacement published",
    SPACE_REFUSED,
    "qualified exact read",
];
const ROOM_WITNESSES: &[&str] = &[
    "replacement filled",
    "replacement published",
    ROOM_GRANTED,
    "qualified exact read",
];
const HELD: &[Obligation] = &[Obligation::History, Obligation::Custody];

const ADMITTED_WITNESSES: &[&str] = &[
    "replacement filled",
    "replacement published",
    "qualified exact read",
];
const REVOKED_WITNESSES: &[&str] = &[
    "replacement filled",
    "invalidation acknowledged",
    REVOKED_REFUSED,
    "fresh GET missed",
    "replacement published",
    "qualified exact read",
];
const EXPIRED_WITNESSES: &[&str] = &[
    "replacement filled",
    LATE_REFUSED,
    "the incumbent stayed exact",
    "replacement published",
    "qualified exact read",
];
const INCOMPLETE_WITNESSES: &[&str] = &[
    "replacement filled",
    EARLY_REFUSED,
    "the incumbent stayed exact",
    "replacement published",
    "qualified exact read",
];
const FAILED_WRITE_WITNESSES: &[&str] = &[
    WRITES_ARMED,
    WRITES_HELD,
    WRITE_FAULTED,
    WRITES_RELEASED,
    TERMINALS_DELIVERED,
    FAILED_REFUSED,
    "qualified exact read",
];
const FAILED_WRITE_PREMISE: &[&str] = &[
    WRITES_ARMED,
    WRITES_HELD,
    WRITE_FAULTED,
    TERMINALS_DELIVERED,
];
const AFTER_HELD_WRITES_WITNESSES: &[&str] = &[
    WRITES_ARMED,
    WRITES_HELD,
    WRITES_RELEASED,
    TERMINALS_DELIVERED,
    "replacement published",
    "qualified exact read",
];
const AFTER_HELD_WRITES_PREMISE: &[&str] = &[WRITES_ARMED, WRITES_HELD, TERMINALS_DELIVERED];
const BESIDE_WITNESSES: &[&str] = &[
    "replacement filled",
    EVICTION_REFUSED,
    "the incumbent stayed exact",
    "replacement published",
    "qualified exact read",
];
const ALONE_WITNESSES: &[&str] = &[
    EVICTION_REMOVED,
    "replacement filled",
    "replacement published",
    "qualified exact read",
];
const IN_PROGRESS_WITNESSES: &[&str] = &[
    "replacement filled",
    SECOND_REFUSED,
    "replacement published",
    "qualified exact read",
];
const AFTER_PUBLICATION_WITNESSES: &[&str] = &[
    "replacement filled",
    "replacement published",
    LATER_GRANTED,
    "qualified exact read",
];

const KEYED: &[Obligation] = &[Obligation::History];

const KEYED_PUBLISHED: &[Obligation] = &[Obligation::History, Obligation::Progress];
const FILLED: &[&str] = &["replacement filled"];
const PUBLISHED: &[&str] = &["replacement published"];

/// A key-operation history: its GETs are the uploading client's own, so the
/// plan budgets none.
const fn keyed(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
) -> History {
    getting(history(name, script, witnesses, KEYED, expect), [0, 0])
}

/// `history` over the two-slot storage, whose checks also judge custody.
const fn cramped(history: History) -> History {
    History {
        obligations: HELD,
        ..super::cramped(history)
    }
}

const HALF: &[&str] = &[HALF_RECEIVED];

pub(super) const KEYOPS: [History; 46] = [
    keyed(
        "k1-publish-admitted",
        &K1_ADMITTED,
        ADMITTED_WITNESSES,
        Expect::Pass,
    ),
    keyed(
        "k1-publish-revoked",
        &K1_REVOKED,
        REVOKED_WITNESSES,
        Expect::Pass,
    ),
    control(
        keyed(
            "k1-publish-revoked-uninvalidated",
            &K1_REVOKED_UNINVALIDATED,
            REVOKED_WITNESSES,
            Expect::Violation(
                Obligation::History,
                "a fill revoked by an invalidation or a tenure change published",
            ),
        ),
        FILLED,
    ),
    keyed(
        "k1-publish-expired",
        &K1_EXPIRED,
        EXPIRED_WITNESSES,
        Expect::Pass,
    ),
    control(
        keyed(
            "k1-publish-expired-live",
            &K1_EXPIRED_LIVE,
            EXPIRED_WITNESSES,
            Expect::Violation(Obligation::History, "a publication at or past its deadline"),
        ),
        FILLED,
    ),
    keyed(
        "k1-publish-incomplete",
        &K1_INCOMPLETE,
        INCOMPLETE_WITNESSES,
        Expect::Pass,
    ),
    control(
        keyed(
            "k1-publish-incomplete-written",
            &K1_INCOMPLETE_WRITTEN,
            INCOMPLETE_WITNESSES,
            Expect::Violation(
                Obligation::History,
                "a publication before its writes completed",
            ),
        ),
        FILLED,
    ),
    control(
        history(
            "k1-publish-failed-write",
            &K1_FAILED_WRITE,
            FAILED_WRITE_WITNESSES,
            KEYED,
            Expect::Pass,
        ),
        FAILED_WRITE_PREMISE,
    ),
    control(
        history(
            "k1-publish-after-held-writes",
            &K1_AFTER_HELD_WRITES,
            AFTER_HELD_WRITES_WITNESSES,
            KEYED,
            Expect::Pass,
        ),
        AFTER_HELD_WRITES_PREMISE,
    ),
    control(
        history(
            "k1-publish-held-writes-judged-failed",
            &K1_HELD_WRITES_JUDGED_FAILED,
            AFTER_HELD_WRITES_WITNESSES,
            KEYED,
            Expect::Violation(
                Obligation::History,
                "a publication before every write of its attempt delivered success",
            ),
        ),
        AFTER_HELD_WRITES_PREMISE,
    ),
    control(
        history(
            "k1-publish-failed-write-judged-published",
            &K1_FAILED_WRITE_JUDGED_PUBLISHED,
            FAILED_WRITE_WITNESSES,
            KEYED_PUBLISHED,
            Expect::Violation(Obligation::Progress, "the replacement never published"),
        ),
        FAILED_WRITE_PREMISE,
    ),
    keyed(
        "k2-evict-beside-fill",
        &K2_BESIDE_JUDGED,
        BESIDE_WITNESSES,
        Expect::Pass,
    ),
    keyed("k2-evict-alone", &K2_ALONE, ALONE_WITNESSES, Expect::Pass),
    control(
        keyed(
            "k2-evict-after-abort",
            &K2_AFTER_ABORT,
            BESIDE_WITNESSES,
            Expect::Violation(Obligation::History, "an eviction while a fill is current"),
        ),
        FILLED,
    ),
    keyed(
        "k3-second-fill-in-progress",
        &K3_IN_PROGRESS,
        IN_PROGRESS_WITNESSES,
        Expect::Pass,
    ),
    keyed(
        "k3-second-fill-after-publication",
        &K3_AFTER_PUBLICATION,
        AFTER_PUBLICATION_WITNESSES,
        Expect::Pass,
    ),
    control(
        keyed(
            "k3-second-fill-judged-late",
            &K3_JUDGED_LATE,
            IN_PROGRESS_WITNESSES,
            Expect::Violation(
                Obligation::History,
                "a key was granted a second fill beside its current attempt",
            ),
        ),
        PUBLISHED,
    ),
    cramped(keyed(
        "k4-reserve-beside-held-slots",
        &K4_BESIDE,
        BESIDE_HELD_WITNESSES,
        Expect::Pass,
    )),
    cramped(keyed(
        "k4-reserve-with-room",
        &K4_ROOM,
        ROOM_WITNESSES,
        Expect::Pass,
    )),
    control(
        cramped(keyed(
            "k4-reserve-judged-with-room",
            &K4_ROOM_JUDGED,
            BESIDE_HELD_WITNESSES,
            Expect::Violation(
                Obligation::Custody,
                "a resource was reused while a custodian held an earlier incarnation",
            ),
        )),
        PUBLISHED,
    ),
    keyed(
        "k5-closed-admits-nothing",
        &K5_CLOSED,
        CLOSED_WITNESSES,
        Expect::Pass,
    ),
    keyed("k5-open-admits", &K5_OPEN, OPEN_WITNESSES, Expect::Pass),
    control(
        keyed(
            "k5-open-judged-closed",
            &K5_OPEN_JUDGED,
            CLOSED_WITNESSES,
            Expect::Violation(Obligation::History, "a publication after the cache closed"),
        ),
        FILLED,
    ),
    keyed(
        "k5-closed-receives-nothing",
        &K5_CLOSED_RECEIVE,
        CLOSED_RECEIVE_WITNESSES,
        Expect::Pass,
    ),
    keyed(
        "k5-open-receives",
        &K5_OPEN_RECEIVE,
        OPEN_RECEIVE_WITNESSES,
        Expect::Pass,
    ),
    control(
        keyed(
            "k5-open-receive-judged-closed",
            &K5_OPEN_RECEIVE_JUDGED,
            CLOSED_RECEIVE_WITNESSES,
            Expect::Violation(Obligation::History, "a receive after the cache closed"),
        ),
        HALF,
    ),
    keyed(
        "k6-lookup-at-right-limit",
        &K6_AT_LIMIT,
        AT_LIMIT_WITNESSES,
        Expect::Pass,
    ),
    keyed(
        "k6-lookup-below-right-limit",
        &K6_BELOW,
        BELOW_WITNESSES,
        Expect::Pass,
    ),
    control(
        keyed(
            "k6-lookup-judged-below-limit",
            &K6_JUDGED_BELOW,
            AT_LIMIT_WITNESSES,
            Expect::Violation(
                Obligation::History,
                "a lookup leased an object past its right limit",
            ),
        ),
        &[RIGHTS_LEASED],
    ),
    history(
        "k7-invalidate-after-close",
        &K7_AFTER_CLOSE,
        AFTER_CLOSE_WITNESSES,
        KEYED,
        Expect::Pass,
    ),
    history(
        "k7-invalidate-before-close",
        &K7_BEFORE_CLOSE,
        BEFORE_CLOSE_WITNESSES,
        KEYED,
        Expect::Pass,
    ),
    control(
        history(
            "k7-invalidate-judged-open",
            &K7_JUDGED_OPEN,
            AFTER_CLOSE_WITNESSES,
            KEYED,
            Expect::Violation(Obligation::History, INVALIDATED_CLOSED),
        ),
        &[KEY_RESIDENT],
    ),
    keyed(
        "k8-search-after-eviction",
        &K8_EVICTED,
        EVICTED_WITNESSES,
        Expect::Pass,
    ),
    keyed(
        "k8-search-after-publication",
        &K8_KEPT,
        KEPT_WITNESSES,
        Expect::Pass,
    ),
    control(
        keyed(
            "k8-search-judged-after-eviction",
            &K8_JUDGED_EVICTED,
            EVICTED_WITNESSES,
            Expect::Violation(Obligation::History, REMOVED_HIT),
        ),
        PUBLISHED,
    ),
    control(
        keyed(
            "k8-get-judged-after-eviction",
            &K8_KEPT_JUDGED_MISSED,
            EVICTED_WITNESSES,
            Expect::Violation(Obligation::History, REMOVED_HIT),
        ),
        &[REPLACEMENT_LEASED],
    ),
    keyed(
        "k8-get-after-eviction-cancelled",
        &K8_CANCELLED,
        EVICTED_WITNESSES,
        Expect::Unsuccessful("fresh GET missed"),
    ),
    sequenced(control(
        keyed(
            "k9-placement-across-close",
            &K9_ACROSS,
            ACROSS_WITNESSES,
            Expect::Violation(Obligation::History, ADMITTED_CLOSED),
        ),
        &[PLACEMENT_PROMISED, OWNER_CLOSED],
    )),
    sequenced(keyed(
        "k9-placement-across-storage-close",
        &K9_ACROSS_STORAGE,
        ACROSS_STORAGE_WITNESSES,
        Expect::Pass,
    )),
    sequenced(keyed(
        "k9-promise-after-close",
        &K9_BEFORE,
        BEFORE_PROMISE_WITNESSES,
        Expect::Pass,
    )),
    sequenced(control(
        keyed(
            "k9-placement-judged-open",
            &K9_JUDGED_OPEN,
            ACROSS_WITNESSES,
            Expect::Violation(Obligation::History, ADMITTED_CLOSED),
        ),
        &[PLACEMENT_PROMISED],
    )),
    sequenced(control(
        keyed(
            "k9-promise-judged-kept",
            &K9_PROMISE_JUDGED_KEPT,
            KEPT_PROMISE_WITNESSES,
            Expect::Violation(Obligation::History, ADMITTED_CLOSED),
        ),
        &[PLACEMENT_PROMISED, OWNER_CLOSED],
    )),
    sequenced(control(
        keyed(
            "k9-grant-judged-refused",
            &K9_GRANT_JUDGED_REFUSED,
            ACROSS_WITNESSES,
            Expect::Violation(Obligation::History, ADMITTED_CLOSED),
        ),
        &[PLACEMENT_PROMISED],
    )),
    sequenced(keyed(
        "k9-revoked-placement-judged-closed",
        &K9_REVOKED,
        REVOKED_PLACEMENT_WITNESSES,
        Expect::Unsuccessful(PLACEMENT_REFUSED),
    )),
    sequenced(keyed(
        "k9-stale-promise-judged-closed",
        &K9_STALE_PROMISE,
        &[PROMISE_REFUSED],
        Expect::Unsuccessful(PROMISE_REFUSED),
    )),
    sequenced(control(
        keyed(
            "k9-promise-judged-open",
            &K9_PROMISE_JUDGED_OPEN,
            BEFORE_PROMISE_WITNESSES,
            Expect::Violation(Obligation::History, ADMITTED_CLOSED),
        ),
        &[OWNER_OPEN],
    )),
];

#[cfg(test)]
mod tests {
    use crate::oracle::Obligation;
    use crate::sim::trace::{Outcome, Terminal, load};

    use super::super::super::bundle::{admit, traced};
    use super::super::super::replay::{Replayed, replay};
    use super::super::tests::manifest;
    use super::{Expect, KEYOPS};

    /// History `name` recorded under `root`: its terminal and its bundle.
    fn ran_at(name: &str, root: u64) -> (Terminal, Vec<u8>) {
        let mut manifest = manifest(name);
        manifest.root = root;
        let closed = traced(admit(&manifest).expect("admitted"), Vec::new());
        let loaded = load(&closed.sink, manifest.capacity().records()).expect("a loadable bundle");
        (loaded.terminal, closed.sink)
    }

    /// Every key-operation history is recorded under its manifest, ends as
    /// it declares and replays equal.
    #[test]
    fn every_key_operation_history_ends_as_declared_and_replays_equal() {
        for history in &KEYOPS {
            let bytes = traced(
                admit(&manifest(history.name)).expect("admitted"),
                Vec::new(),
            )
            .sink;
            let loaded = load(&bytes, 1_000_000).expect("a loadable bundle");
            assert_eq!(history.ends_as_declared(&loaded), Ok(()));
            assert_eq!(
                replay(&bytes).expect("a replay").0,
                Replayed::Reproduced,
                "{}",
                history.name
            );
        }
    }

    #[test]
    fn every_passing_key_operation_history_activates_the_obligation_it_declares() {
        for history in KEYOPS.iter().filter(|h| h.expect == Expect::Pass) {
            let activated = super::super::activated(history.witnesses);
            for obligation in history.obligations {
                assert!(
                    activated.contains(obligation),
                    "{}: {obligation:?} has no witnessed check",
                    history.name
                );
            }
        }
    }

    /// Each control declares the rule its history's check raises and a
    /// premise its run marks before the check.
    #[test]
    fn every_key_operation_control_fails_through_its_named_check() {
        use Obligation::{History, Progress};
        let killed = [
            (
                "k1-publish-held-writes-judged-failed",
                History,
                "a publication before every write of its attempt delivered success",
            ),
            (
                "k1-publish-failed-write-judged-published",
                Progress,
                "the replacement never published",
            ),
            (
                "k1-publish-revoked-uninvalidated",
                History,
                "a fill revoked by an invalidation or a tenure change published",
            ),
            (
                "k1-publish-expired-live",
                History,
                "a publication at or past its deadline",
            ),
            (
                "k1-publish-incomplete-written",
                History,
                "a publication before its writes completed",
            ),
            (
                "k2-evict-after-abort",
                History,
                "an eviction while a fill is current",
            ),
            (
                "k3-second-fill-judged-late",
                History,
                "a key was granted a second fill beside its current attempt",
            ),
            (
                "k5-open-judged-closed",
                History,
                "a publication after the cache closed",
            ),
            (
                "k5-open-receive-judged-closed",
                History,
                "a receive after the cache closed",
            ),
            (
                "k6-lookup-judged-below-limit",
                History,
                "a lookup leased an object past its right limit",
            ),
            (
                "k7-invalidate-judged-open",
                History,
                "an invalidation after the cache closed",
            ),
            (
                "k4-reserve-judged-with-room",
                Obligation::Custody,
                "a resource was reused while a custodian held an earlier incarnation",
            ),
            (
                "k8-search-judged-after-eviction",
                History,
                "a hit after a recorded removal of its label in the same tenure",
            ),
            (
                "k8-get-judged-after-eviction",
                History,
                "a hit after a recorded removal of its label in the same tenure",
            ),
            (
                "k9-placement-across-close",
                History,
                "a fill admitted after the cache closed",
            ),
            (
                "k9-placement-judged-open",
                History,
                "a fill admitted after the cache closed",
            ),
            (
                "k9-promise-judged-kept",
                History,
                "a fill admitted after the cache closed",
            ),
            (
                "k9-grant-judged-refused",
                History,
                "a fill admitted after the cache closed",
            ),
            (
                "k9-promise-judged-open",
                History,
                "a fill admitted after the cache closed",
            ),
        ];
        let controls: Vec<_> = KEYOPS
            .iter()
            .filter(|h| matches!(h.expect, Expect::Violation(..)))
            .collect();
        assert_eq!(controls.len(), killed.len());
        for (name, obligation, rule) in killed {
            let control = controls.iter().find(|h| h.name == name).expect(name);
            assert_eq!(
                control.expect,
                Expect::Violation(obligation, rule),
                "{name}"
            );
            assert!(!control.premise.is_empty(), "{name} declares its premise");
            let (profile, plan, goal) = super::super::named(name, 3).expect(name);
            let chooser = profile.recorder(&super::super::super::sites_for(&plan));
            let (_, first, _) = super::super::super::mixed_run(
                chooser,
                &profile,
                plan,
                goal,
                super::super::super::LIMITS,
                &mut (),
            );
            assert_eq!(first, control.expect.failure(), "{name}");
        }
    }

    /// Each passing key-operation history passes and replays equal under
    /// three pinned roots.
    #[test]
    fn every_passing_key_operation_history_passes_under_pinned_roots() {
        for history in KEYOPS.iter().filter(|h| h.expect == Expect::Pass) {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                let (terminal, bytes) = ran_at(history.name, root);
                assert_eq!(
                    replay(&bytes).expect("a replay").0,
                    Replayed::Reproduced,
                    "{} at {root}",
                    history.name
                );
                assert!(
                    matches!(
                        terminal,
                        Terminal::Complete {
                            outcome: Outcome::Pass,
                            ..
                        }
                    ),
                    "{} at {root}: {terminal:?}",
                    history.name
                );
            }
        }
    }

    /// A follower's refusal answers the search only when it reports the
    /// version missing.
    #[test]
    fn a_follower_refusal_other_than_missing_leaves_the_search_unanswered() {
        use super::{Found, JoinedReadError, unleased};
        use crate::storage::FillFailure;
        assert!(matches!(unleased(JoinedReadError::Missing), Found::Nothing));
        for refusal in [
            JoinedReadError::Expired,
            JoinedReadError::ClockUnavailable,
            JoinedReadError::LeaseLimit,
            JoinedReadError::RetainLimit,
            JoinedReadError::Contended,
            JoinedReadError::BudgetExhausted,
            JoinedReadError::Failed(FillFailure::DeviceError),
            JoinedReadError::Pending,
            JoinedReadError::Corrupt,
            JoinedReadError::Closed,
        ] {
            assert!(matches!(unleased(refusal), Found::Refused), "{refusal:?}");
        }
    }

    #[test]
    fn a_search_history_whose_get_is_cancelled_ends_unsuccessful() {
        let name = "k8-get-after-eviction-cancelled";
        let declared = KEYOPS.iter().find(|h| h.name == name).expect(name);
        assert_eq!(declared.expect, Expect::Unsuccessful("fresh GET missed"));
        for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
            assert_eq!(
                super::super::tests::first_failure(name, root),
                declared.expect.failure(),
                "{name} at {root}"
            );
        }
    }

    /// Under three pinned roots, each history of the placement family
    /// records the first failure it declares: the pin and the controls
    /// their rule, the falsifiers their unformed premise, the siblings
    /// none. Each recorded bundle ends as declared and replays equal.
    #[test]
    fn the_placement_family_ends_as_declared_under_pinned_roots() {
        let family: Vec<_> = KEYOPS
            .iter()
            .filter(|history| history.name.starts_with("k9-"))
            .collect();
        assert_eq!(family.len(), 9);
        for declared in family {
            for root in [3, 7_677_221_855_602_090_617, 10_289_227_118_843_548_305] {
                assert_eq!(
                    super::super::tests::first_failure(declared.name, root),
                    declared.expect.failure(),
                    "{} at {root}",
                    declared.name
                );
                super::super::tests::ends_as_declared_at(declared, root);
            }
        }
    }

    #[test]
    fn a_receive_is_admitted_by_any_ok_answer_or_any_byte_taken() {
        use super::admitted;
        use crate::storage::ReceiveError;
        assert!(
            admitted(&Ok(0), 0),
            "an Ok answer that took no byte read as a refusal"
        );
        assert!(admitted(&Ok(1), 0));
        assert!(admitted(&Ok(0), 1));
        assert!(admitted(&Err(ReceiveError::Closed), 1));
        assert!(!admitted(&Err(ReceiveError::Closed), 0));
        assert!(!admitted(&Err(ReceiveError::Lost), 0));
    }
}
