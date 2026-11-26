//! A GET past its peer's share, held by one GET and one pending upload, ends typed
//! Pressure(RequestPressure) while the other peer's GET completes exactly.
//!
//! Property: a GET that peer A issues while A's request share is full
//! ends at A's client with the typed outcome `Pressure(RequestPressure)`. The rule this file judges is
//! UNTYPED below.
//!
//! Both histories run the single-owner world, in which a peer's share is two requests. Client 0 is peer A
//! and uploads; client 1 is peer B. Key 1 holds the resident object.
//!
//! - `fs1-get-past-a-full-share`: A issues a GET of key 1 whose read the device holds, then
//!   begins and prepares an upload that it does not supply. Once the owner began the upload, the premise
//!   FULL forms when `Owner::peer_census` reads A's charge equal to the share and the upload is undecided.
//!   A then issues one more GET of key 1 with the wait `WAIT_US`. The step `a-capped` runs once A's client
//!   decided that GET. `a-capped` fails with OUTLIVED when the decision came later than the issue plus
//!   `WAIT_US`. With the same wait, A's first GET expires first, so `a-capped` judges the deadline
//!   before the premise STAYED_FULL: both of A's earlier requests are still undecided at A's client
//!   and A's charge still equals the share. When STAYED_FULL holds, `a-capped` requires
//!   `Pressure(RequestPressure)` and fails with UNTYPED on mismatch.
//! - `fs1-get-inside-the-share`: the same steps, but A issues no first GET and the
//!   device holds no read. The premise ROOM forms when A's charge is the pending upload alone. A's GET is
//!   then inside its share, and the premise ADMITTED forms when it completes with the resident object's
//!   exact bytes.
//! - `fs1-get-capped-late` is the deadline's control: A's link drops every ERROR toward A, and A issues
//!   the GET past its share with a `2 * WAIT_US` wait. A's client decides the GET after the judged
//!   wait, and `a-capped` fails through OUTLIVED.
//! - In the `fs1-b-uncharged` control, `b-read` treats B's charge as zero and fails through RETAINED.
//! - In the `fs1-get-capped-read-complete` control, `a-capped` judges the refused GET as `Complete`
//!   and fails through UNTYPED.
//! - In the `fs1-b-late` control, `b-read` judges B's GET two waits after its decision and fails
//!   through STARVED.
//! - In the `fs1-wrong-peer` control, `b-read` reads each peer's charge from the other peer and fails
//!   through MISCHARGED.
//!
//! In both histories B's GET of key 1 then completes with the resident object's exact bytes within one
//! `WAIT_US` of its issue. `Owner::peer_census` reads exactly one upload attempt and, for A, the full
//! share in the first history and from one request through the full share in the sibling. B's share
//! carries exactly one GET charge while the history holds the GET response's transmit references.
//! A missed GET deadline triggers STARVED. An incorrect upload-attempt count or A charge triggers
//! MISCHARGED. A B charge other than one GET while the transmit references are held triggers RETAINED.
//! Both histories then
//! release every hold, supply the upload, require it published and read its bytes back exactly.
//!
//! A premise that does not form ends the run unsuccessful under its name.
//!
//! A's first GET and the readiness of its judged GET are the steps of the history `i5`, which
//! `histories/incidents.rs` shares with its link-rule helpers. `a_over` is this file's own: its witness
//! ISSUED also holds in the sibling, whose GET is inside the share.

use super::super::super::frame::Kind;
use super::super::super::rules::{Effect, Rule};
use super::super::{OWNER, WAIT_US};
use super::incidents::{a_get, a_over_decided, i7_rules_on, toward_client};
use super::*;

/// The rule both histories judge.
const UNTYPED: &str = "a GET past a peer's share ended without a typed pressure outcome";

/// The rule of a late decision.
const OUTLIVED: &str = "a GET past a peer's share outlived its one deadline";

/// The rule of the other peer's GET.
const STARVED: &str = "an eligible peer's GET starved behind a saturated share";

/// The rule of the census.
const MISCHARGED: &str = "a peer's share was charged with another peer's work";

/// B's completed GET stays charged to B's share until the history releases the transmit references
/// of its response.
const RETAINED: &str = "a retained GET left its peer's share before its release";

const NO_GET: &str = "A holds no GET";
const UNHELD: &str = "the device holds no read";
const FULL: &str = "A's GET and pending upload fill its share";
const ROOM: &str = "A's pending upload leaves its share room";
const ISSUED: &str = "A issued one more GET";
const STAYED_FULL: &str = "A's share stayed full to the decision";
const REFUSED_TYPED: &str = "A's GET past its share ended typed";
const ADMITTED: &str = "A's GET inside its share read exactly";
const B_LIVE: &str = "A's requests were live at B's read";
const B_EXACT: &str = "B's GET completed exactly beside A";
const RECONCILED: &str = "charges reconciled by peer";

/// Peer A's client, which uploads.
const A: usize = 0;

/// Peer B's client.
const B: usize = 1;

/// The live requests the owner charges to `client`'s share.
fn charged(world: &Mixed<'_, '_, '_>, client: usize) -> u32 {
    let peer = PeerId(u16::try_from(client).expect("a client index"));
    let census = world.scene.owner.peer_census(peer);
    census.active + census.draining
}

/// A's upload is undecided at A's client.
fn upload_pending(world: &Mixed<'_, '_, '_>) -> bool {
    world
        .history
        .put
        .is_some_and(|id| world.scene.clients[A].put_outcome(id).is_none())
}

/// The sibling: A issues no first GET.
fn a_no_get(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.begun = world.scene.owner.put_report().begun;
    mark(world, NO_GET)
}

/// The sibling's premise: the device holds no read.
fn nothing_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let unheld = world.history.held.is_empty();
    premised(world, unheld, UNHELD)
}

/// The owner began A's upload, or A's client decided it.
fn upload_begun(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    world.scene.owner.put_report().begun > world.history.begun || !upload_pending(world)
}

/// The premise of the first history: A's held GET and pending upload are its whole share.
fn share_full(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let full = upload_pending(world) && charged(world, A) == OWNER.peer_requests;
    premised(world, full, FULL)
}

/// The premise of the sibling: A's charge is its pending upload alone.
fn share_room(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let room = upload_pending(world) && charged(world, A) == 1;
    premised(world, room, ROOM)
}

/// A's next GET of key 1, with the wait `WAIT_US`.
fn a_over(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    match world.scene.clients[A].get(key(1), 0, 1 << 20, now, WAIT_US) {
        Ok(id) => {
            world.history.peer = Some(id);
            world.history.issued = now;
            mark(world, ISSUED)
        }
        Err(_) => STAY,
    }
}

/// A's link drops refusals so the history can judge the first `WAIT_US` while the GET deadline is
/// still `WAIT_US` away.
fn a_over_kept(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let refusals = vec![Rule::new(toward_client(Kind::Error), Effect::Drop)];
    i7_rules_on(world, A, refusals);
    match world.scene.clients[A].get(key(1), 0, 1 << 20, now, 2 * WAIT_US) {
        Ok(id) => {
            world.history.peer = Some(id);
            world.history.issued = now;
            mark(world, ISSUED)
        }
        Err(_) => STAY,
    }
}

/// The judgment: A's GET past its full share ended in time and typed `Pressure(RequestPressure)`.
fn a_capped(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let Some(outcome) = a_over_outcome(world) else {
        return premised(world, false, ISSUED);
    };
    judge_capped(world, now, outcome)
}

fn a_capped_read_complete(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if a_over_outcome(world).is_none() {
        return premised(world, false, ISSUED);
    }
    judge_capped(world, now, Some(Outcome::Complete))
}

fn a_over_outcome(world: &mut Mixed<'_, '_, '_>) -> Option<Option<Outcome>> {
    let id = world.history.peer.take()?;
    let outcome = world.collect_get(A, id);
    let _ = world.scene.clients[A].retire(id);
    Some(outcome)
}

fn judge_capped(world: &mut Mixed<'_, '_, '_>, now: u64, outcome: Option<Outcome>) -> u64 {
    if now > world.history.issued + WAIT_US {
        return fail(world, Obligation::Resources, OUTLIVED);
    }
    let first_live = world
        .history
        .ids
        .first()
        .is_some_and(|&held| world.scene.clients[A].outcome(held).is_none());
    let full = first_live && upload_pending(world) && charged(world, A) == OWNER.peer_requests;
    if premised(world, full, STAYED_FULL) == 0 {
        return 0;
    }
    if outcome != Some(Outcome::Pressure(Status::RequestPressure)) {
        return fail(world, Obligation::Resources, UNTYPED);
    }
    mark(world, REFUSED_TYPED)
}

/// The sibling's premise: A's GET inside its share completed with the resident object's exact bytes.
fn a_admitted(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let Some(id) = world.history.peer.take() else {
        return premised(world, false, ISSUED);
    };
    let bytes = drain(&mut world.scene.clients[A], id);
    let outcome = world.collect_get(A, id);
    let _ = world.scene.clients[A].retire(id);
    let exact = outcome == Some(Outcome::Complete) && bytes == version_a();
    premised(world, exact, ADMITTED)
}

/// B's GET of the resident object. The device holds no read from here on; the read of A's first GET
/// stays held.
fn b_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.hold_reads = false;
    world.history.b_issued = now;
    old_get(world, now)
}

/// B's GET completes with the resident object's bytes within `WAIT_US` of its issue.
/// The owner begins one upload. While the history holds transmit references for B's GET, that GET
/// accounts for B's entire charge. A's charge equals the whole share when `full`. Otherwise, A's
/// charge ranges from one request through the whole share, inclusive.
fn judge_b(
    world: &mut Mixed<'_, '_, '_>,
    now: u64,
    full: bool,
    charge: impl Fn(&Mixed<'_, '_, '_>, usize) -> u32,
) -> u64 {
    world.read(B);
    let read = world.gets[B]
        .as_ref()
        .map(|get| (get.outcome, get.bytes.clone()));
    let Some((outcome, bytes)) = read else {
        return premised(world, false, B_EXACT);
    };
    if now > world.history.b_issued + WAIT_US {
        return fail(world, Obligation::Progress, STARVED);
    }
    if judge_peer_read(world, outcome, &bytes) == 0 {
        return 0;
    }
    let first_live = world
        .history
        .ids
        .first()
        .is_some_and(|&held| world.scene.clients[A].outcome(held).is_none());
    let live = upload_pending(world) && (first_live || !full);
    if premised(world, live, B_LIVE) == 0 {
        return 0;
    }
    let share = OWNER.peer_requests;
    let (a, b) = (charge(world, A), charge(world, B));
    let attempts = world.scene.owner.put_report().begun - world.history.begun;
    let a_within = if full {
        a == share
    } else {
        (1..=share).contains(&a)
    };
    if !a_within || b > 1 || attempts != 1 {
        return fail(world, Obligation::Resources, MISCHARGED);
    }
    if world.history.hold_nic && b != 1 {
        return fail(world, Obligation::Resources, RETAINED);
    }
    mark(world, B_EXACT);
    mark(world, RECONCILED)
}

fn b_beside_full(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_b(world, now, true, charged)
}

fn b_beside_room(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_b(world, now, false, charged)
}

/// Serves as the control for `b_beside_full`.
fn b_uncharged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_b(world, now, true, |world, client| match client {
        B => 0,
        client => charged(world, client),
    })
}

fn b_late(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_b(world, now + 2 * WAIT_US, true, charged)
}

fn b_wrong_peer(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_b(world, now, true, |world, client| {
        charged(world, A + B - client)
    })
}

/// A's session is active and the owner charges A nothing.
fn a_idle(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    active_put(world, now) && charged(world, A) == 0
}

const CAPPED: [Step; 16] = [
    step("arm", always, arm),
    step("a-get", active_put, a_get),
    step("a-read-held", read_held, mark_read_held),
    step("a-put-begin", active_put, put_begin),
    step("a-put-prepare", always, put_prepare),
    step("a-share", upload_begun, share_full),
    step("a-over", active_put, a_over),
    step("a-capped", a_over_decided, a_capped),
    step("b-get", active_get, b_get),
    step("b-read", old_decided, b_beside_full),
    step("release", always, release_everything),
    step("a-supply", always, put_supply),
    step("a-result", put_decided, put_published),
    step("qualified-get", a_idle, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const ROOMY: [Step; 16] = replaced(
    replaced(
        replaced(
            replaced(
                replaced(
                    replaced(CAPPED, "arm", step("arm", always, arm_nic)),
                    "a-get",
                    step("a-get", active_put, a_no_get),
                ),
                "a-read-held",
                step("a-read-held", always, nothing_held),
            ),
            "a-share",
            step("a-share", upload_begun, share_room),
        ),
        "a-capped",
        step("a-capped", a_over_decided, a_admitted),
    ),
    "b-read",
    step("b-read", old_decided, b_beside_room),
);

const CAPPED_LATE: [Step; 16] = replaced(
    CAPPED,
    "a-over",
    step("a-over-kept", active_put, a_over_kept),
);

const CAPPED_B_UNCHARGED: [Step; 16] = replaced(
    CAPPED,
    "b-read",
    step("b-read-uncharged", old_decided, b_uncharged),
);

const CAPPED_READ_COMPLETE: [Step; 16] = replaced(
    CAPPED,
    "a-capped",
    step(
        "a-capped-read-complete",
        a_over_decided,
        a_capped_read_complete,
    ),
);

const CAPPED_B_LATE: [Step; 16] =
    replaced(CAPPED, "b-read", step("b-read-late", old_decided, b_late));

const CAPPED_WRONG_PEER: [Step; 16] = replaced(
    CAPPED,
    "b-read",
    step("b-read-wrong-peer", old_decided, b_wrong_peer),
);

const CAPPED_WITNESSES: &[&str] = &[
    "holds armed",
    "old read held",
    FULL,
    ISSUED,
    STAYED_FULL,
    REFUSED_TYPED,
    B_LIVE,
    B_EXACT,
    RECONCILED,
    "holds released",
    "upload published",
    "qualified exact read",
];

const ROOMY_WITNESSES: &[&str] = &[
    "holds armed",
    NO_GET,
    UNHELD,
    ROOM,
    ISSUED,
    ADMITTED,
    B_LIVE,
    B_EXACT,
    RECONCILED,
    "holds released",
    "upload published",
    "qualified exact read",
];

const JUDGED: &[Obligation] = &[Obligation::Resources, Obligation::Progress];

/// The obligation the mark of B's judged GET judges.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(B_EXACT, Obligation::Progress)];

/// The late control's kill counts once A's share was full and A issued one more GET.
const LATE_PREMISE: &[&str] = &[FULL, ISSUED];

/// The uncharged control's kill counts once A's share was full and A's requests were live at B's read.
const UNCHARGED_PREMISE: &[&str] = &[FULL, B_LIVE];

const TYPED_PREMISE: &[&str] = &[FULL, ISSUED, STAYED_FULL];

const B_LATE_PREMISE: &[&str] = &[FULL, REFUSED_TYPED];

pub(super) const FULL_SHARES: [History; 7] = [
    uploading(
        history(
            "fs1-get-past-a-full-share",
            &CAPPED,
            CAPPED_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "fs1-get-inside-the-share",
            &ROOMY,
            ROOMY_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    control(
        uploading(
            history(
                "fs1-get-capped-late",
                &CAPPED_LATE,
                CAPPED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Resources, OUTLIVED),
            ),
            1,
        ),
        LATE_PREMISE,
    ),
    control(
        uploading(
            history(
                "fs1-b-uncharged",
                &CAPPED_B_UNCHARGED,
                CAPPED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Resources, RETAINED),
            ),
            1,
        ),
        UNCHARGED_PREMISE,
    ),
    control(
        uploading(
            history(
                "fs1-get-capped-read-complete",
                &CAPPED_READ_COMPLETE,
                CAPPED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Resources, UNTYPED),
            ),
            1,
        ),
        TYPED_PREMISE,
    ),
    control(
        uploading(
            history(
                "fs1-b-late",
                &CAPPED_B_LATE,
                CAPPED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Progress, STARVED),
            ),
            1,
        ),
        B_LATE_PREMISE,
    ),
    control(
        uploading(
            history(
                "fs1-wrong-peer",
                &CAPPED_WRONG_PEER,
                CAPPED_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Resources, MISCHARGED),
            ),
            1,
        ),
        UNCHARGED_PREMISE,
    ),
];
