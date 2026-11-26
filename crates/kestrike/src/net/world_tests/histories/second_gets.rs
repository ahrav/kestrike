//! Second-GET histories: a client's second GET of a key reads the version visible when it was issued.
//!
//! A client's GET issued after a replacement was published reads exactly the visible version. The rule is
//! the one `fresh_exact_of` in `histories.rs` fails through, "a qualified GET missed the visible version's
//! exact bytes"; `narrate/rules.rs` holds its text.
//!
//! Both histories run the single-owner world, whose scene publishes the first version under key 1 before the
//! run. One client issues two GETs of the key, one after the other on the same connection, and the history
//! reads the first to its end before the second starts. The second is the qualified GET: the owner has
//! already decided an earlier request of this client, so an owner that answered the second from what it
//! kept of the first would return the earlier answer.
//!
//! - `sg1-get-replaced`: the owner acknowledges an INVALIDATE of the key, the
//!   first GET ends `Missing`, the owner fills and publishes a replacement, and the qualified GET must end
//!   `Complete` with exactly the replacement's bytes. The acknowledged invalidation, the first GET's
//!   `Missing` and the publication are premises: one that does not form ends the run unsuccessful under its
//!   name, and the rule counts only with the last two marked.
//! - `sg1-get-unchanged`: no invalidation and no replacement. The first
//!   GET reads the first version, which is the premise, and the qualified GET must read it exactly too.
//!
//! Neither history judges another request of the client between its two GETs.

use super::*;

const INVALIDATED: &str = "the invalidation was acknowledged";
const FIRST_MISSED: &str = "the first GET was decided Missing";
const PUBLISHED: &str = "the replacement was published";
const FIRST_READ: &str = "the first GET read the first version";
/// The mark `fresh_exact_of` leaves, which `histories.rs` lists as a check of `Obligation::History`.
const QUALIFIED: &str = "qualified exact read";

/// The owner invalidates key 1; the premise forms when the invalidation removed the key's mapping.
fn invalidate_key(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let removed = world
        .scene
        .owner
        .invalidate(&key(1), 3, &mut budget())
        .is_ok_and(|done| done.removed.is_some());
    world.owner_due = now;
    premised(world, removed, INVALIDATED)
}

/// The first GET, issued after the invalidation, ended `Missing` with no byte delivered. Reading it retires
/// the request, so the client's next GET is a new request on the same connection.
fn first_missed(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    premised(
        world,
        outcome == Some(Outcome::Missing) && bytes.is_empty(),
        FIRST_MISSED,
    )
}

/// The sibling's first GET ended `Complete` with the first version's bytes.
fn first_read(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (outcome, bytes) = fresh_result(world);
    premised(
        world,
        outcome == Some(Outcome::Complete) && bytes == version_a(),
        FIRST_READ,
    )
}

/// The owner publishes the written replacement with an expiry a minute ahead; the premise forms when the
/// publication succeeds.
fn publish_replacement(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let fill = world.history.fill.take().expect("a written fill");
    let published = world.scene.owner.publish_fill(
        fill,
        ticks(now + 60 * super::super::SECOND_US),
        2,
        &mut budget(),
    );
    world.owner_due = now;
    let formed = published.is_ok();
    world.history.lease = published.ok();
    premised(world, formed, PUBLISHED)
}

/// The sibling's judgment: the qualified GET reads the first version, the one still visible.
fn qualified_exact_a(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fresh_exact_of(world, &version_a())
}

const REPLACED: [Step; 9] = [
    step("invalidate", always, invalidate_key),
    step("first-get", active_put, fresh_get),
    step("first-decided", fresh_decided, first_missed),
    step("fill-replacement", always, fill_b),
    step("publish-replacement", fill_written, publish_replacement),
    step("release-lease", always, release_reads),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const KEPT: [Step; 5] = [
    step("first-get", active_put, fresh_get),
    step("first-decided", fresh_decided, first_read),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, qualified_exact_a),
    JUDGE,
];

const REPLACED_WITNESSES: &[&str] = &[INVALIDATED, FIRST_MISSED, PUBLISHED, QUALIFIED];

const KEPT_WITNESSES: &[&str] = &[FIRST_READ, QUALIFIED];

const JUDGED: &[Obligation] = &[Obligation::History];

pub(super) const SECOND_GETS: [History; 2] = [
    control(
        history(
            "sg1-get-replaced",
            &REPLACED,
            REPLACED_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        &[FIRST_MISSED, PUBLISHED],
    ),
    control(
        history(
            "sg1-get-unchanged",
            &KEPT,
            KEPT_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        &[FIRST_READ],
    ),
];
