//! The owner charges each request to the share of the peer that sent it, and to no other peer's.
//!
//! Property: the owner charges each request to the share of the peer that sent it, and to no other
//! peer's. The rule this file judges is MISCHARGED below, a rule text of `narrate/rules.rs`.
//!
//! Both histories run the single-owner world, in which a peer's share is two requests. Client 0 is peer A,
//! which holds requests open; client 1 is peer B. Key 1 holds the resident object. Every judgment reads
//! `Owner::peer_census` of both peers and compares each peer's `active + draining` with the requests that
//! peer's own client holds undecided, which the history reads from the clients and the device, never from
//! the census.
//!
//! - `pc1-get-beside-a-get-and-an-upload`: A issues a GET of key 1 whose read the device holds, then
//!   begins and prepares an upload that it does not supply. Once the owner began the upload, the premise
//!   A_HOLDS_TWO forms when A's GET and A's upload are both undecided at A's client and the device still
//!   holds the read. The step `a-share` then judges the census: A is charged exactly its two requests and
//!   B, which has sent nothing, is charged none. B then issues its GET of key 1, whose read the device
//!   does not hold. The step `b-read` runs once B's client decided that GET. It requires the premise
//!   A_LIVE (A's two requests are still undecided at A's client), then judges the census again: A is
//!   charged exactly its own two requests and B at most its one GET, which may still drain while its
//!   transmit references are held. A census that differs fails through MISCHARGED. The step then requires
//!   B's GET to have completed within one wait with the resident object's exact bytes, which is the rule
//!   STARVED.
//! - `pc1-get-beside-one-get`: the same steps without A's upload. The premise
//!   A_HOLDS_ONE forms when the owner began no upload and A's one GET is undecided with its read held, and
//!   both census judgments expect A charged exactly that one request.
//!
//! A request charged to another peer's share shows at `b-read` in either direction: B's GET in A's count
//! makes A's charge exceed its own requests, and A's requests in B's count make B's charge exceed its one
//! GET and leave A's short.
//!
//! Both histories then release every hold. The first history supplies the upload, requires it published and
//! reads its bytes back exactly; the sibling requires A's held GET to complete with the resident object's
//! exact bytes.
//!
//! A premise that does not form ends the run unsuccessful under its name.
//!
//! Two controls hand a judgment what a defect would leave. `pc1-get-and-upload-judged-on-the-other-peer`
//! reads each peer's charge from the other peer's share at the step `a-share`, as an owner that charged
//! A's two requests to B would leave them, and fails through MISCHARGED.
//! `pc1-get-beside-one-judged-late` judges B's GET one wait and a microsecond after the step saw it
//! decided, and fails through STARVED.
//!
//! The steps of the history `i5` are private items of `histories/incidents.rs`, so this file writes its own
//! from the items of `histories.rs`.

use super::super::WAIT_US;
use super::*;

/// The rule both histories judge.
const MISCHARGED: &str = "a peer's share was charged with another peer's work";

/// The rule of B's GET.
const STARVED: &str = "an eligible peer's GET starved behind a saturated share";

const A_HOLDS_TWO: &str = "A holds a GET and a pending upload";
const A_HOLDS_ONE: &str = "A holds one GET and no upload";
const CHARGED_BEFORE: &str = "each peer charged its own before B";
const A_LIVE: &str = "A's requests were live at B's read";
const CHARGED_BESIDE: &str = "each peer charged its own at B's read";
const B_EXACT: &str = "B's GET completed exactly beside A";

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

/// A's first GET is undecided at A's client and the device still holds its read.
fn get_held(world: &Mixed<'_, '_, '_>) -> bool {
    let undecided = world
        .history
        .ids
        .first()
        .is_some_and(|&held| world.scene.clients[A].outcome(held).is_none());
    undecided && !world.history.held.is_empty() && commands_pending(world)
}

/// The uploads the owner began since A's first GET.
fn uploads_begun(world: &Mixed<'_, '_, '_>) -> u64 {
    world.scene.owner.put_report().begun - world.history.begun
}

/// A's GET, whose read the device holds once the owner submits it.
fn a_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.begun = world.scene.owner.put_report().begun;
    fresh_get(world, now)
}

/// The owner began A's upload, or A's client decided it.
fn upload_begun(world: &Mixed<'_, '_, '_>, _: u64) -> bool {
    uploads_begun(world) > 0 || !upload_pending(world)
}

/// The charges of A's share and of B's, in that order.
fn charges(world: &Mixed<'_, '_, '_>) -> (u32, u32) {
    (charged(world, A), charged(world, B))
}

/// Fails through MISCHARGED unless `charges` holds exactly `own` requests on A's share and at most
/// `other` on B's.
fn judge_census(
    world: &mut Mixed<'_, '_, '_>,
    charges: (u32, u32),
    own: u32,
    other: u32,
    witness: &'static str,
) -> u64 {
    if charges.0 != own || charges.1 > other {
        return fail(world, Obligation::Resources, MISCHARGED);
    }
    mark(world, witness)
}

/// The premise A_HOLDS_TWO: A's held GET and its pending upload, the one upload the owner began.
fn a_holds_two(world: &mut Mixed<'_, '_, '_>) -> u64 {
    let holds = get_held(world) && upload_pending(world) && uploads_begun(world) == 1;
    premised(world, holds, A_HOLDS_TWO)
}

/// The first history before B's GET: A holds its held GET and its pending upload, and is charged those two.
fn a_two_charged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if a_holds_two(world) == 0 {
        return 0;
    }
    let charges = charges(world);
    judge_census(world, charges, 2, 0, CHARGED_BEFORE)
}

/// A control: each peer's charge is read from the other peer's share, as an owner that charged A's two
/// requests to B would leave them.
fn a_two_charged_to_b(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if a_holds_two(world) == 0 {
        return 0;
    }
    let (a, b) = charges(world);
    judge_census(world, (b, a), 2, 0, CHARGED_BEFORE)
}

/// The sibling before B's GET: A holds its held GET alone, and is charged that one.
fn a_one_charged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let holds = get_held(world) && world.history.put.is_none() && uploads_begun(world) == 0;
    if premised(world, holds, A_HOLDS_ONE) == 0 {
        return 0;
    }
    let charges = charges(world);
    judge_census(world, charges, 1, 0, CHARGED_BEFORE)
}

/// B's GET of the resident object. The device holds no read from here on; the read of A's GET stays held.
fn b_get(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.hold_reads = false;
    world.history.b_issued = now;
    old_get(world, now)
}

/// The judgment at B's GET, seen decided at `decided_at`: while A's `own` requests are live, A is charged
/// exactly those and B at most its one GET; B's GET then completed exactly within one wait.
fn judge_b(world: &mut Mixed<'_, '_, '_>, decided_at: u64, own: u32) -> u64 {
    world.read(B);
    let read = world.gets[B]
        .as_ref()
        .map(|get| (get.outcome, get.bytes.clone()));
    let Some((outcome, bytes)) = read else {
        return premised(world, false, B_EXACT);
    };
    let live = get_held(world) && (own == 1 || upload_pending(world));
    if premised(world, live, A_LIVE) == 0 {
        return 0;
    }
    let charges = charges(world);
    if judge_census(world, charges, own, 1, CHARGED_BESIDE) == 0 {
        return 0;
    }
    if decided_at > world.history.b_issued + WAIT_US {
        return fail(world, Obligation::Progress, STARVED);
    }
    if judge_peer_read(world, outcome, &bytes) == 0 {
        return 0;
    }
    mark(world, B_EXACT)
}

fn b_beside_two(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_b(world, now, 2)
}

fn b_beside_one(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_b(world, now, 1)
}

/// A control: B's GET is judged one wait and a microsecond after the step saw it decided, as a GET that
/// waited behind A's requests past its deadline would be seen.
fn b_beside_one_late(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    judge_b(world, now + WAIT_US + 1, 1)
}

/// A's session is active and the owner charges A nothing.
fn a_idle(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    active_put(world, now) && charged(world, A) == 0
}

/// The sibling's end: A's held GET completes with the resident object's exact bytes.
fn a_exact(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    fresh_exact_of(world, &version_a())
}

const TWO_HELD: [Step; 14] = [
    step("arm", always, arm),
    step("a-get", active_put, a_get),
    step("a-read-held", read_held, mark_read_held),
    step("a-put-begin", active_put, put_begin),
    step("a-put-prepare", always, put_prepare),
    step("a-share", upload_begun, a_two_charged),
    step("b-get", active_get, b_get),
    step("b-read", old_decided, b_beside_two),
    step("release", always, release_everything),
    step("a-supply", always, put_supply),
    step("a-result", put_decided, put_published),
    step("qualified-get", a_idle, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const ONE_HELD: [Step; 9] = [
    step("arm", always, arm),
    step("a-get", active_put, a_get),
    step("a-read-held", read_held, mark_read_held),
    step("a-share", always, a_one_charged),
    step("b-get", active_get, b_get),
    step("b-read", old_decided, b_beside_one),
    step("release", always, release_everything),
    step("a-read", fresh_decided, a_exact),
    JUDGE,
];

const TWO_JUDGED_ON_B: [Step; 14] = replaced(
    TWO_HELD,
    "a-share",
    step("a-share-swapped", upload_begun, a_two_charged_to_b),
);

const ONE_JUDGED_LATE: [Step; 9] = replaced(
    ONE_HELD,
    "b-read",
    step("b-read-late", old_decided, b_beside_one_late),
);

const TWO_HELD_WITNESSES: &[&str] = &[
    "holds armed",
    "old read held",
    A_HOLDS_TWO,
    CHARGED_BEFORE,
    A_LIVE,
    CHARGED_BESIDE,
    B_EXACT,
    "holds released",
    "upload published",
    "qualified exact read",
];

const ONE_HELD_WITNESSES: &[&str] = &[
    "holds armed",
    "old read held",
    A_HOLDS_ONE,
    CHARGED_BEFORE,
    A_LIVE,
    CHARGED_BESIDE,
    B_EXACT,
    "holds released",
    "qualified exact read",
];

const JUDGED: &[Obligation] = &[Obligation::Resources, Obligation::Progress];

pub(super) const CHECKS: [(&str, Obligation); 3] = [
    (CHARGED_BEFORE, Obligation::Resources),
    (CHARGED_BESIDE, Obligation::Resources),
    (B_EXACT, Obligation::Progress),
];

pub(super) const PEER_CHARGES: [History; 4] = [
    uploading(
        history(
            "pc1-get-beside-a-get-and-an-upload",
            &TWO_HELD,
            TWO_HELD_WITNESSES,
            JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    history(
        "pc1-get-beside-one-get",
        &ONE_HELD,
        ONE_HELD_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    control(
        uploading(
            history(
                "pc1-get-and-upload-judged-on-the-other-peer",
                &TWO_JUDGED_ON_B,
                TWO_HELD_WITNESSES,
                JUDGED,
                Expect::Violation(Obligation::Resources, MISCHARGED),
            ),
            1,
        ),
        &[A_HOLDS_TWO],
    ),
    control(
        history(
            "pc1-get-beside-one-judged-late",
            &ONE_JUDGED_LATE,
            ONE_HELD_WITNESSES,
            JUDGED,
            Expect::Violation(Obligation::Progress, STARVED),
        ),
        &[A_HOLDS_ONE, A_LIVE, CHARGED_BESIDE],
    ),
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{B_EXACT, CHARGED_BEFORE, CHARGED_BESIDE, Expect, PEER_CHARGES};

    /// Both passing histories judge the census at the steps `a-share` and `b-read`, and the step
    /// `b-read` then judges B's GET, so each declares the obligations those three marks activate.
    #[test]
    fn every_passing_peer_charge_history_declares_the_obligations_its_judging_marks_activate() {
        let marks = [CHARGED_BEFORE, CHARGED_BESIDE, B_EXACT];
        let judged: BTreeSet<_> = super::super::activated(&marks).into_iter().collect();
        let passing: Vec<_> = PEER_CHARGES
            .iter()
            .filter(|history| history.expect == Expect::Pass)
            .collect();
        assert_eq!(passing.len(), 2);
        for history in passing {
            for mark in marks {
                assert!(history.witnesses.contains(&mark), "{}", history.name);
            }
            let declared: BTreeSet<_> = history.obligations.iter().copied().collect();
            assert_eq!(declared, judged, "{}", history.name);
        }
    }
}
