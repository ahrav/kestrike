//! A PUT CANCEL that names a live GET's wire identity moves only the owner's wrong-operation
//! counter.
//!
//! Both histories run the single-owner world, whose scene publishes version A under key 1 before the run.
//! Client 1 issues the named GET of key 1 and client 0 a concurrent GET of the same key; the history holds
//! every device read, so both GETs stay live at the owner with their reads on the device. The named GET's
//! header is read from the link toward the owner.
//!
//! - `ng1-put-cancel-names-a-live-get`: the script injects a PUT CANCEL that client 1's
//!   key authenticates and that carries the named GET's wire request ID, key and session, at the session's
//!   next sequence. Once the owner's `wrong_operation` counter moved, the check reads the named wire slot
//!   again (`Owner::request_slot`: watermark, bound request, retained row, refused generation). A counter
//!   delta other than one or a slot that differs from its pre-injection state fails with
//!   `cohorts::MOVED_MORE`.
//! - `ng1-no-frame-names-a-live-get`: the same steps with no frame injected.
//!   The check runs ten link turns after the snapshot and fails with `cohorts::MOVED_MORE` unless the
//!   counter and the slot match their snapshot values.
//! - `ng1-put-cancel-moved-the-slot` repeats `ng1-put-cancel-names-a-live-get` as a control: its check
//!   compares the snapshot with a slot whose refused generation differs.
//! - `ng1-no-frame-counted` repeats `ng1-no-frame-names-a-live-get` as a control: its check compares
//!   the snapshot with a counter one above the owner's.
//!
//! Premises, each ending the run unsuccessful under its name when it does not form: the named GET is live
//! on its wire slot when the snapshot is taken, and the concurrent GET is live at the owner when the check
//! runs. After the check both reads are released and each GET must end `Complete` with version A's exact
//! bytes, which shows the named GET was still the owner's to finish.

use super::cohorts::{
    Counters, MOVED_MORE, concurrent_decided, counted_only, counters, forge, get_sent, learn_get,
    live_at_owner, read_exact, s19_concurrent_get, s19_counted,
};
use super::*;

use super::super::super::frame::Kind;

const LEARNED: &str = "the named GET's header learned from the link";
const READS_HELD: &str = "old read held";
const NAMED_LIVE: &str = "the named GET was live on its wire slot at the snapshot";
const INJECTED: &str = "PUT CANCEL naming the live GET injected";
const OBSERVED: &str = "the named slot observed with no frame injected";
const COUNTED: &str = "the owner counted the wrong operation";
const RESTED: &str = "ten link turns passed after the snapshot";
const BESIDE: &str = "the concurrent GET was live at the check";
const COUNTER_ONLY: &str = "only the wrong-operation counter moved";
const UNCHANGED: &str = "the counter and the named slot stayed as they were";
const READS_RELEASED: &str = "old read released";
const NAMED_READ: &str = "the named GET read its exact version";
const CONCURRENT_READ: &str = "the concurrent GET read its exact version";

pub(super) const CHECKS: [(&str, Obligation); 4] = [
    (COUNTER_ONLY, Obligation::Contain),
    (UNCHANGED, Obligation::Contain),
    (NAMED_READ, Obligation::Bytes),
    (CONCURRENT_READ, Obligation::Bytes),
];

fn learn(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !learn_get(world) {
        return STAY;
    }
    mark(world, LEARNED)
}

/// The premise that the named GET is live on its wire slot, then the snapshot the check compares with.
fn snapshot(world: &mut Mixed<'_, '_, '_>) -> bool {
    world.history.forged = None;
    let named = world
        .history
        .learned
        .expect("the named GET's header")
        .request;
    if !live_at_owner(world, 1, named) {
        world.first.record(Failure::Unsuccessful(NAMED_LIVE));
        return false;
    }
    mark(world, NAMED_LIVE);
    world.history.forged = Some(counters(world));
    true
}

fn inject(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !snapshot(world) {
        return 0;
    }
    let get = world.history.learned.expect("the named GET's header");
    forge(world, Kind::PutCancel, get.sequence + 1);
    mark(world, INJECTED)
}

/// The sibling's snapshot: no frame follows it, and the run wakes ten link turns later.
fn observe(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if !snapshot(world) {
        return 0;
    }
    world.history.wake = Some(now + 10 * super::super::LINK_TURN_US);
    mark(world, OBSERVED)
}

fn mark_counted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, COUNTED)
}

fn rested(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    world.history.wake.is_some_and(|wake| now >= wake)
}

fn mark_rested(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    mark(world, RESTED)
}

fn judge_named(
    world: &mut Mixed<'_, '_, '_>,
    after: Counters,
    counted: u64,
    witness: &'static str,
) -> u64 {
    let id = world.gets[0].as_ref().expect("the concurrent GET").id;
    let wire = attempt(world, 0, id);
    if !live_at_owner(world, 0, wire) {
        world.first.record(Failure::Unsuccessful(BESIDE));
        return 0;
    }
    mark(world, BESIDE);
    let only = world
        .history
        .forged
        .is_some_and(|before| counted_only(before, after, counted));
    if !only {
        return fail(world, Obligation::Contain, MOVED_MORE);
    }
    mark(world, witness)
}

fn check_counter_only(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let after = counters(world);
    judge_named(world, after, 1, COUNTER_ONLY)
}

fn check_unchanged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let after = counters(world);
    judge_named(world, after, 0, UNCHANGED)
}

fn check_slot_moved(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let after = Counters {
        refused: Some(u64::MAX),
        ..counters(world)
    };
    judge_named(world, after, 1, COUNTER_ONLY)
}

fn check_counted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let read = counters(world);
    let after = Counters {
        wrong_operation: read.wrong_operation + 1,
        ..read
    };
    judge_named(world, after, 0, UNCHANGED)
}

fn exact(world: &mut Mixed<'_, '_, '_>, client: usize) -> bool {
    world.read(client);
    let get = world.gets[client].as_ref().expect("the client's GET");
    read_exact(get.outcome, &get.bytes, &version_a())
}

fn named_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !exact(world, 1) {
        return fail(
            world,
            Obligation::Bytes,
            "a GET a PUT frame named ended other than with its exact version",
        );
    }
    mark(world, NAMED_READ)
}

fn concurrent_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !exact(world, 0) {
        return fail(
            world,
            Obligation::Bytes,
            "the concurrent GET ended other than with its exact version",
        );
    }
    mark(world, CONCURRENT_READ)
}

const NAMING: [Step; 13] = [
    step("arm", always, arm),
    step("named-get", active_get, old_get),
    step("learn", get_sent, learn),
    step("concurrent-get", active_put, s19_concurrent_get),
    step("reads-held", reads_held, mark_read_held),
    step("inject", always, inject),
    step("counted", s19_counted, mark_counted),
    step("check", always, check_counter_only),
    step("release-reads", always, release_reads),
    step("named-read", old_decided, named_read),
    step("concurrent-read", concurrent_decided, concurrent_read),
    step("release-nic", always, release_nic),
    JUDGE,
];

const QUIET_SLOT: [Step; 13] = replaced(
    replaced(
        replaced(NAMING, "inject", step("observe", always, observe)),
        "counted",
        step("rested", rested, mark_rested),
    ),
    "check",
    step("check", always, check_unchanged),
);

const NAMING_MOVED: [Step; 13] = replaced(
    NAMING,
    "check",
    step("check-slot-moved", always, check_slot_moved),
);

const QUIET_COUNTED: [Step; 13] = replaced(
    QUIET_SLOT,
    "check",
    step("check-counted", always, check_counted),
);

const NAMING_WITNESSES: &[&str] = &[
    LEARNED,
    READS_HELD,
    NAMED_LIVE,
    INJECTED,
    COUNTED,
    BESIDE,
    COUNTER_ONLY,
    READS_RELEASED,
    NAMED_READ,
    CONCURRENT_READ,
];

const QUIET_WITNESSES: &[&str] = &[
    LEARNED,
    READS_HELD,
    NAMED_LIVE,
    OBSERVED,
    RESTED,
    BESIDE,
    UNCHANGED,
    READS_RELEASED,
    NAMED_READ,
    CONCURRENT_READ,
];

const NAMING_PREMISE: &[&str] = &[NAMED_LIVE, INJECTED, COUNTED];

const QUIET_PREMISE: &[&str] = &[NAMED_LIVE, OBSERVED, RESTED];

const JUDGED: &[Obligation] = &[Obligation::Contain, Obligation::Bytes];

/// GET budgets: client 0's concurrent GET and client 1's named GET.
const GETS: [u32; 2] = [1, 1];

const fn named_get(
    name: &'static str,
    script: &'static [Step],
    witnesses: &'static [&'static str],
    expect: Expect,
) -> History {
    getting(history(name, script, witnesses, JUDGED, expect), GETS)
}

pub(super) const NAMED_GETS: [History; 4] = [
    named_get(
        "ng1-put-cancel-names-a-live-get",
        &NAMING,
        NAMING_WITNESSES,
        Expect::Pass,
    ),
    named_get(
        "ng1-no-frame-names-a-live-get",
        &QUIET_SLOT,
        QUIET_WITNESSES,
        Expect::Pass,
    ),
    control(
        named_get(
            "ng1-put-cancel-moved-the-slot",
            &NAMING_MOVED,
            NAMING_WITNESSES,
            Expect::Violation(Obligation::Contain, MOVED_MORE),
        ),
        NAMING_PREMISE,
    ),
    control(
        named_get(
            "ng1-no-frame-counted",
            &QUIET_COUNTED,
            QUIET_WITNESSES,
            Expect::Violation(Obligation::Contain, MOVED_MORE),
        ),
        QUIET_PREMISE,
    ),
];
