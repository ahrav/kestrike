//! The owner charges a peer at most its share of request slots, and exactly its live requests.
//!
//! The rule this file judges is LEFT_SHARE below, under `Obligation::Resources`.
//!
//! - `sc1-get-past-a-held-share`: the GET client issues two GETs of key 1 while the owner's device
//!   reads are held, which fills its share at the owner (`OwnerConfig::peer_requests`, 2 in the scene), and
//!   then a third GET past the share. Once the third GET was decided, or the device holds a third read, or
//!   the bound since its issue passed, the `effect` step reads `Owner::peer_census` of that peer and fails
//!   with LEFT_SHARE when active + draining exceeds the share or falls below the count of reads the
//!   history holds at the device, which `judge_share` takes as `live`.
//!   It judges no other peer's progress. Three premises must form, and a run in which one does not ends
//!   unsuccessful under that premise's name: the share was full at the owner before the third GET, the
//!   client issued the third GET, and the device still holds the peer's reads at the judgment. The history
//!   then releases the reads and waits until every GET of the peer was decided.
//! - `sc1-get-share-held-full`: the same steps without the fault. It issues no GET past
//!   the share, so the same judgment finds the peer charged its two held GETs.
//!
//! The judgment takes the charge it compares as an argument, and a control hands it the charge a defect
//! would leave: `sc1-get-past-share-judged-admitted` one request above the share, as an owner that
//! admitted the third GET would charge, and `sc1-get-share-judged-uncharged` one below the held GETs.
//! `sc1-get-past-share-judged-admitted-uncharged` hands the judgment one more held read with the
//! charge unchanged, the state of an owner that admitted the third GET and charged the peer nothing
//! for it.
//!
//! `peer_exact_charged` of `histories.rs` raises the same rule only after it judged the other peer's GET;
//! `judge_share` judges the charge alone.

use super::*;

/// The rule, which `histories.rs` raises from its saturated share.
const LEFT_SHARE: &str = "a peer's charge left its live requests or its share";

/// The premises of the first history's judgment, and the names an unsuccessful run carries.
const SHARE_FULL: &str = "the peer's share was full at the owner";
const PAST: &str = "the peer issued a GET past its share";
const DEVICE_HELD: &str = "the device held the peer's reads at the check";

const WITHIN: &str = "the peer's charge stayed within its share";

/// The peer whose share the history fills: the GET client.
const SATURATING: PeerId = PeerId(1);

/// The peer's share of request slots at the owner.
fn share(world: &Mixed<'_, '_, '_>) -> u64 {
    u64::from(
        world
            .plan
            .share
            .unwrap_or(super::super::OWNER.peer_requests),
    )
}

/// The requests the owner charges to the saturating peer's share: its live ones and its draining ones.
fn charged(world: &Mixed<'_, '_, '_>) -> u64 {
    let census = world.scene.owner.peer_census(SATURATING);
    u64::from(census.active) + u64::from(census.draining)
}

/// Holds the device's reads from here on; the links stay as they are.
fn arm_reads(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.history.hold_reads = true;
    mark(world, "reads held from here")
}

/// The device holds both saturating reads: the owner charges the peer exactly its share.
fn share_full(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let full = charged(world) == share(world);
    premised(world, full, SHARE_FULL)
}

/// The fault: a third GET of the saturating peer, past its full share.
fn past_share(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    let issued = world.scene.clients[1].get(key(1), 0, 1 << 20, now, super::super::WAIT_US);
    if let Ok(id) = issued {
        world.history.ids.push(id);
        world.history.since = now;
        world.history.wake = Some(now + BOUND_US + 1);
    }
    premised(world, issued.is_ok(), PAST)
}

/// The owner had its chance to admit the GET past the share: the client holds its outcome, the device
/// holds a third read, or the bound since its issue passed.
fn past_share_seen(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    let decided = world
        .history
        .ids
        .last()
        .is_some_and(|&id| world.scene.clients[1].outcome(id).is_some());
    decided || world.history.held.len() > 2 || now > world.history.since + BOUND_US
}

/// Judges `charged`, the saturating peer's charge read while the device holds its reads: at most its
/// share, and at least `live`, the reads the device holds for the peer's admitted GETs.
fn judge_share(world: &mut Mixed<'_, '_, '_>, charged: u64, live: u64) -> u64 {
    let held = world.scene.control.outstanding() >= 2;
    if premised(world, held, DEVICE_HELD) == 0 {
        return 0;
    }
    if charged > share(world) || charged < live {
        return fail(world, Obligation::Resources, LEFT_SHARE);
    }
    mark(world, WITHIN)
}

/// The reads the history holds at the device, one for each GET the owner admitted.
fn held_reads(world: &Mixed<'_, '_, '_>) -> u64 {
    world.history.held.len() as u64
}

fn share_kept(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (charged, live) = (charged(world), held_reads(world));
    judge_share(world, charged, live)
}

/// A control: the peer's charge is read one higher, as an owner that admitted the GET past the share
/// would leave it.
fn share_exceeded(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (charged, live) = (charged(world) + 1, held_reads(world));
    judge_share(world, charged, live)
}

/// A control: the peer's charge is read one lower, as an owner that dropped a held GET's charge would
/// leave it.
fn share_dropped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (charged, live) = (charged(world).saturating_sub(1), held_reads(world));
    judge_share(world, charged, live)
}

/// A control that models admission of one GET past the share: `live` is one higher and `charged`
/// is unchanged.
fn share_unraised(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let (charged, live) = (charged(world), held_reads(world) + 1);
    judge_share(world, charged, live)
}

const A_GET_PAST_THE_FULL_SHARE: [Step; 9] = [
    step("arm", always, arm_reads),
    step("saturate", active_get, saturate),
    step("reads-held", reads_held, |world, _| {
        mark(world, "saturating reads held")
    }),
    step("setup", always, share_full),
    step("past-share", always, past_share),
    step("effect", past_share_seen, share_kept),
    step("release", always, release_everything),
    step("healed", saturated_drained, saturated_exact),
    JUDGE,
];

const THE_FULL_SHARE_ALONE: [Step; 8] = [
    step("arm", always, arm_reads),
    step("saturate", active_get, saturate),
    step("reads-held", reads_held, |world, _| {
        mark(world, "saturating reads held")
    }),
    step("setup", always, share_full),
    step("effect", always, share_kept),
    step("release", always, release_everything),
    step("healed", saturated_drained, saturated_exact),
    JUDGE,
];

const PAST_JUDGED_ADMITTED: [Step; 9] = replaced(
    A_GET_PAST_THE_FULL_SHARE,
    "effect",
    step("effect-admitted", past_share_seen, share_exceeded),
);

const PAST_JUDGED_ADMITTED_UNCHARGED: [Step; 9] = replaced(
    A_GET_PAST_THE_FULL_SHARE,
    "effect",
    step("effect-admitted-uncharged", past_share_seen, share_unraised),
);

const ALONE_JUDGED_UNCHARGED: [Step; 8] = replaced(
    THE_FULL_SHARE_ALONE,
    "effect",
    step("effect-uncharged", always, share_dropped),
);

const WITNESSES: &[&str] = &[
    "reads held from here",
    "share saturated",
    "saturating reads held",
    SHARE_FULL,
    PAST,
    DEVICE_HELD,
    WITHIN,
    "holds released",
    "qualified exact read",
];

const SIBLING_WITNESSES: &[&str] = &[
    "reads held from here",
    "share saturated",
    "saturating reads held",
    SHARE_FULL,
    DEVICE_HELD,
    WITHIN,
    "holds released",
    "qualified exact read",
];

const JUDGED: &[Obligation] = &[Obligation::Resources];

/// The obligation the mark of the share judgment judges.
pub(super) const CHECKS: [(&str, Obligation); 1] = [(WITHIN, Obligation::Resources)];

pub(super) const SHARE_CHARGES: [History; 5] = [
    history(
        "sc1-get-past-a-held-share",
        &A_GET_PAST_THE_FULL_SHARE,
        WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    history(
        "sc1-get-share-held-full",
        &THE_FULL_SHARE_ALONE,
        SIBLING_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "sc1-get-past-share-judged-admitted",
            &PAST_JUDGED_ADMITTED,
            WITNESSES,
            JUDGED,
            Expect::Violation(Obligation::Resources, LEFT_SHARE),
        ),
        &[SHARE_FULL, PAST, DEVICE_HELD],
    ),
    control(
        history(
            "sc1-get-past-share-judged-admitted-uncharged",
            &PAST_JUDGED_ADMITTED_UNCHARGED,
            WITNESSES,
            JUDGED,
            Expect::Violation(Obligation::Resources, LEFT_SHARE),
        ),
        &[SHARE_FULL, PAST, DEVICE_HELD],
    ),
    control(
        history(
            "sc1-get-share-judged-uncharged",
            &ALONE_JUDGED_UNCHARGED,
            SIBLING_WITNESSES,
            JUDGED,
            Expect::Violation(Obligation::Resources, LEFT_SHARE),
        ),
        &[SHARE_FULL, DEVICE_HELD],
    ),
];

#[cfg(test)]
mod tests {
    use crate::sim::turn::End;

    use super::super::tests::run_end;
    use super::{Expect, SHARE_CHARGES};

    /// Each run of both passing histories at roots 1, 2 and 3 must reach `Done` with an empty first
    /// failure. A run stopped by a limit also leaves that field empty, so `Done` confirms the judgment
    /// ran.
    #[test]
    fn the_pinned_roots_of_both_histories_end_done_with_no_failure() {
        let passing = SHARE_CHARGES
            .iter()
            .filter(|history| history.expect == Expect::Pass);
        for history in passing {
            for root in [1, 2, 3] {
                assert_eq!(
                    run_end(history, root),
                    (End::Done, None),
                    "{} under root {root}",
                    history.name
                );
            }
        }
    }
}
