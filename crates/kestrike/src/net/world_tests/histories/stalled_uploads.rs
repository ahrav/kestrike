//! A GET of a published object completes exactly and in time while another peer's upload of the
//! same key is stalled before its DATA.
//!
//! Property: a GET of a key that holds a published object completes with that object's exact bytes,
//! in time, while another peer's upload of the same key is stalled before its DATA. The rule this file
//! judges is the one `judge_beside_stall` of `histories.rs` fails with: "an eligible peer's GET starved
//! beside a stalled upload".
//!
//! Both histories run the single-owner world, whose scene publishes version A under key 1 before the run.
//! The GET is client 1's, of key 1, and its step fails with the rule unless it ends `Complete` with version
//! A's exact bytes within `BOUND_US`, 200 ms, of its issue.
//!
//! - `su1-get-beside-a-stalled-upload`: client 0 begins and prepares an upload of version B
//!   under key 1 and supplies no DATA. The upload having no outcome while the owner's wire slot binds its
//!   request is a premise, read before the GET is issued and again once the GET passed its judgment; one that
//!   does not form ends the run unsuccessful under its name. After the GET the upload's DATA is supplied
//!   and the upload must publish, which shows the request the GET ran beside was one the owner could
//!   still complete.
//! - `su1-get-with-no-upload`: the same GET and the same judgment with no
//!   upload begun.

use super::*;

const STALLED: &str = "upload stalled before its DATA";
const PROGRESSED: &str = "eligible peer progressed";
const STILL_STALLED: &str = "upload stayed stalled past the peer's GET";
const PUBLISHED: &str = "upload published";

/// Whether the upload is stalled now: begun, with no outcome at its client, and its own request bound at
/// the owner's slot for the upload's wire identity.
fn upload_stalled_now(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    !put_decided(world, now)
        && world
            .history
            .put
            .and_then(|id| world.scene.clients[0].put_wire(id))
            .is_some_and(|wire| super::cohorts::live_at_owner(world, 0, wire))
}

/// The premise before the GET: the prepared upload is stalled.
fn upload_stalled(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let formed = upload_stalled_now(world, now);
    premised(world, formed, STALLED)
}

/// The judgment of the peer's GET beside the stalled upload, then the premise that the upload was still
/// stalled when the GET was judged, so the read completed beside the upload and not after its end.
/// The rule comes first: a GET that starved is the violation whatever became of the upload meanwhile.
fn peer_read_beside_stall(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if peer_beside_stall(world, now) == 0 {
        return 0;
    }
    let formed = upload_stalled_now(world, now);
    premised(world, formed, STILL_STALLED)
}

const BESIDE_STALL: [Step; 8] = [
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("stalled", always, upload_stalled),
    step("peer-get", active_get, peer_old_get),
    step("peer-read", old_decided_or_late, peer_read_beside_stall),
    step("put-supply", always, put_supply),
    step("put-result", put_decided, put_published),
    JUDGE,
];

const ALONE: [Step; 3] = [
    step("peer-get", active_get, peer_old_get),
    step("peer-read", old_decided_or_late, peer_beside_stall),
    JUDGE,
];

const BESIDE_STALL_WITNESSES: &[&str] = &[STALLED, PROGRESSED, STILL_STALLED, PUBLISHED];

const ALONE_WITNESSES: &[&str] = &[PROGRESSED];

/// Both histories judge the peer's GET, a check of `Obligation::Progress`. The upload's live charge is a
/// premise here; `h4-put` of `histories.rs` judges it under `Obligation::Resources`.
const JUDGED: &[Obligation] = &[Obligation::Progress];

pub(super) const STALLED_UPLOADS: [History; 2] = [
    uploading(
        history(
            "su1-get-beside-a-stalled-upload",
            &BESIDE_STALL,
            BESIDE_STALL_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    history(
        "su1-get-with-no-upload",
        &ALONE,
        ALONE_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
];
