//! A GET reads the visible version once the read-response pool that refused an earlier GET is free
//! again.
//!
//! Property: unrelated work neither stalls nor reads bytes outside the visible versions. The rule
//! this file judges is RULE below, the text the incident histories I1 to I4 raise for it.
//!
//! Both histories run against the scene's resident object, version A under key 1, with no upload.
//!
//! - `hp1-get-after-the-pool-heals`: the history takes every buffer of the owner's
//!   read-response pool, issues a GET of key 1 from client 1 and waits for the owner's typed pressure,
//!   returns the buffers, and issues a second GET of key 1 from the same client. Once that GET is decided,
//!   any ending but a complete read of version A's exact bytes is the rule: a refusal that outlives its
//!   cause stalls work that has nothing to do with it.
//! - `hp1-get-with-the-pool-untouched`: the same two GETs with the pool left alone. The
//!   first reads version A, and the second is judged the same way.
//! - `hp1-get-with-the-pool-still-held`: a control. The first history's steps, with the buffers kept
//!   where the heal returns them: the owner refuses the second GET too, and the judgment fails with the
//!   rule.
//!
//! The premises are apart from the judgment: a pool that gives no buffer, a first GET that ends another
//! way than its history states, and buffers still held at the heal each end the run unsuccessful under
//! the premise's name. The pool and GET steps follow `histories/incidents.rs`, whose own are private.

use super::*;

/// The rule, which `histories/incidents.rs` raises and `narrate/rules.rs` lists.
const RULE: &str = "unrelated work stalled or read bytes outside the visible versions";

const TAKEN: &str = "every buffer of the read-response pool taken";
const LEFT: &str = "the read-response pool left free";
const ISSUED: &str = "the first GET issued";
const PRESSED: &str = "the first GET ended with the owner's typed pressure";
const SERVED: &str = "the first GET read the resident version";
const RETURNED: &str = "the read-response pool's buffers returned";
const NONE_HELD: &str = "the history held no buffer of the read-response pool";
const STILL_HELD: &str = "the history kept the read-response pool's buffers";
const READ: &str = "the GET after the heal read the visible version";

/// The client both GETs come from.
const READER: usize = 1;

/// The fault: the history takes every buffer of the owner's read-response pool and keeps them.
fn take_pool(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let arena = world.scene.buffers.expect("the owner's arena");
    while let Ok(buffer) = arena.acquire(crate::storage::PoolKind::ReadResponse) {
        world.history.pool.push(buffer);
    }
    let formed = !world.history.pool.is_empty();
    premised(world, formed, TAKEN)
}

/// The sibling takes nothing.
fn leave_pool(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let formed = world.history.pool.is_empty();
    premised(world, formed, LEFT)
}

/// The first GET of key 1, issued beside the world's own so that the judged GET keeps the plan's budget.
fn first_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[READER].get(key(1), 0, 1 << 20, now, super::super::WAIT_US) {
        Ok(id) => {
            world.history.peer = Some(id);
            mark(world, ISSUED)
        }
        Err(_) => STAY,
    }
}

fn first_decided(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world
        .history
        .peer
        .is_some_and(|id| world.scene.clients[READER].outcome(id).is_some())
}

/// Ends the first GET: its bytes, its collected outcome, and its request retired.
fn first_result(world: &mut Mixed<'_, '_, '_>) -> (Option<Outcome>, Vec<u8>) {
    let id = world.history.peer.take().expect("the first GET");
    let bytes = drain(&mut world.scene.clients[READER], id);
    let outcome = world.collect_get(READER, id);
    let _ = world.scene.clients[READER].retire(id);
    (outcome, bytes)
}

/// The premise of the first history: the owner refused the first GET with its typed pressure.
fn first_pressed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, _) = first_result(world);
    let formed = outcome == Some(Outcome::Pressure(Status::RetransmissionPressure));
    premised(world, formed, PRESSED)
}

/// The premise of the sibling: with the pool free the first GET read version A.
fn first_served(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = first_result(world);
    let formed = outcome == Some(Outcome::Complete) && bytes == version_a();
    premised(world, formed, SERVED)
}

/// The heal: every buffer the history took goes back to the pool.
fn return_pool(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let formed = !world.history.pool.is_empty();
    world.history.pool.clear();
    premised(world, formed, RETURNED)
}

/// The control retains every buffer the history took, so the pool remains empty for the second GET.
fn keep_pool(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let formed = !world.history.pool.is_empty();
    premised(world, formed, STILL_HELD)
}

/// The sibling has nothing to return.
fn nothing_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let formed = world.history.pool.is_empty();
    premised(world, formed, NONE_HELD)
}

/// The judged GET: the world's own GET of key 1 from the same client, with no read held.
fn healed_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.hold_reads = false;
    old_get(world, now)
}

/// Judges the decided GET: any ending but a complete read of version A's exact bytes is the rule.
fn healed_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(READER);
    let get = world.gets[READER].as_ref().expect("the GET after the heal");
    let exact = get.outcome == Some(Outcome::Complete) && get.bytes == version_a();
    if !exact {
        return fail(world, Obligation::Progress, RULE);
    }
    mark(world, READ)
}

const HEALED: [Step; 7] = [
    step("take-pool", always, take_pool),
    step("first-get", active_get, first_get),
    step("first-pressed", first_decided, first_pressed),
    step("heal", always, return_pool),
    step("healed-get", active_get, healed_get),
    step("healed-read", old_decided, healed_read),
    JUDGE,
];

const FREE: [Step; 7] = [
    step("leave-pool", always, leave_pool),
    step("first-get", active_get, first_get),
    step("first-served", first_decided, first_served),
    step("heal", always, nothing_held),
    step("healed-get", active_get, healed_get),
    step("healed-read", old_decided, healed_read),
    JUDGE,
];

const STILL_TAKEN: [Step; 7] = replaced(HEALED, "heal", step("keep-pool", always, keep_pool));

const HEALED_WITNESSES: &[&str] = &[TAKEN, ISSUED, PRESSED, RETURNED, READ];

const FREE_WITNESSES: &[&str] = &[LEFT, ISSUED, SERVED, NONE_HELD, READ];

const JUDGED: &[Obligation] = &[Obligation::Progress];

/// The obligation the mark of the judged GET's read judges.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(READ, Obligation::Progress)];

pub(super) const HEALED_POOLS: [History; 3] = [
    history(
        "hp1-get-after-the-pool-heals",
        &HEALED,
        HEALED_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    history(
        "hp1-get-with-the-pool-untouched",
        &FREE,
        FREE_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "hp1-get-with-the-pool-still-held",
            &STILL_TAKEN,
            HEALED_WITNESSES,
            JUDGED,
            Expect::Violation(Obligation::Progress, RULE),
        ),
        &[PRESSED, STILL_HELD],
    ),
];
