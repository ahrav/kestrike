//! After an upload the owner admitted ended at its deadline, the same peer's next upload publishes.
//!
//! Property: after an upload the owner admitted ended at its deadline, the same peer's next upload
//! publishes. The rule this file judges is "a healed funded upload never published", under
//! `Obligation::Progress`; `healed_published` of `histories/incidents.rs` raises it.
//!
//! - `hu1-put-after-a-deadline`: the uploading client begins and prepares an upload of key 1 and
//!   supplies no DATA. The owner holds a record for it, which is a premise, and the upload ends at its
//!   deadline other than published, which is a second premise. Once the owner holds no request of the peer,
//!   the same client begins, prepares and supplies a new upload. The step that sees the new upload decided
//!   fails with the rule unless its outcome is `Published`. The scene's owner gives each peer one upload at
//!   a time, so a charge the ended upload left behind refuses the new one.
//! - `hu1-put-with-none-before`: the same second upload with no upload before it.

use super::incidents::{healed_prepare, healed_published, uploader_idle};
use super::*;

const CHARGED: &str = "the owner held a record of the first upload";
const ENDED: &str = "the first upload ended at its deadline unpublished";

/// The first upload, begun and prepared with its DATA withheld, holds a record at the owner: an upload
/// refused at its BEGIN would charge nothing.
fn charged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let census = world.scene.owner.peer_census(PeerId(0));
    premised(world, census.active + census.draining > 0, CHARGED)
}

/// The first upload ended with no DATA supplied: failed by the owner's answer or unknown at the client's
/// deadline, at or after the wait its BEGIN named.
fn first_ended(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let id = world.history.put.expect("a PUT");
    let outcome = world.collect_put(id);
    let _ = world.scene.clients[0].abandon(id);
    let _ = world.scene.clients[0].retire(id);
    let ended = matches!(
        outcome,
        Some(UploadOutcome::Failed(Status::TimedOut) | UploadOutcome::Unknown)
    );
    let at_deadline = now >= world.history.since + super::super::WAIT_US;
    premised(world, ended && at_deadline, ENDED)
}

/// Supplies the new upload's DATA unless the upload already ended, which the result step judges.
fn healed_supply(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if put_decided(world, now) {
        return 1;
    }
    put_supply(world, now)
}

const AFTER_AN_ENDED_UPLOAD: [Step; 9] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("first-charged", always, charged),
    step("first-ended", put_decided, first_ended),
    step("healed-begin", uploader_idle, put_begin),
    step("healed-prepare", always, healed_prepare),
    step("healed-supply", always, healed_supply),
    step("healed-result", put_decided, healed_published),
    JUDGE,
];

const ALONE: [Step; 5] = [
    step("healed-begin", uploader_idle, put_begin),
    step("healed-prepare", always, healed_prepare),
    step("healed-supply", always, healed_supply),
    step("healed-result", put_decided, healed_published),
    JUDGE,
];

const AFTER_WITNESSES: &[&str] = &[
    "upload prepared",
    CHARGED,
    ENDED,
    "upload DATA supplied",
    "upload published",
];

const ALONE_WITNESSES: &[&str] = &[
    "upload prepared",
    "upload DATA supplied",
    "upload published",
];

const JUDGED: &[Obligation] = &[Obligation::Progress];

pub(super) const HEALED_UPLOADS: [History; 2] = [
    uploading(
        history(
            "hu1-put-after-a-deadline",
            &AFTER_AN_ENDED_UPLOAD,
            AFTER_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        2,
    ),
    uploading(
        history(
            "hu1-put-with-none-before",
            &ALONE,
            ALONE_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
];
