//! A displacement leaves the old session's live requests charged to the peer's share until they
//! drain.
//!
//! The first history judges the rule DROPPED below, under `Obligation::Custody`. Its sibling judges the
//! rule LEFT_SHARE, under `Obligation::Resources`.
//!
//! - `dc1-get-held-across-displacement`: the uploading client issues a GET of key 1 while
//!   the owner's device reads are held, so the device holds the GET's read. The `setup` step records the
//!   requests the owner charges to the peer's share (`Owner::peer_census`, active + draining), and a
//!   replacement boot of the same peer then opens a session, which displaces the first boot's. Once the
//!   owner counted the displacement, the `effect` step reads the census again and fails with DROPPED when
//!   it reads lower than the recorded value. Two premises must form, and a run in which either does not
//!   ends unsuccessful under that premise's name: the peer held a charge when the replacement opened its
//!   session, and the device still holds a command at the judgment. The history then releases the read
//!   and waits until the peer's share is empty.
//! - `dc1-get-drained-before-displacement`: the same steps without the fault. It ends
//!   the holds and waits until the GET left the peer's share before the replacement boot opens its
//!   session. Every request of the peer has drained by the displacement, so the `effect` step expects a
//!   zero charge and fails with LEFT_SHARE when the share still holds a request.
//!
//! Each judgment takes the count it compares as an argument, and a control hands it the count a defect
//! would leave: `dc1-get-held-judged-dropped` one charge fewer than the displacement found, and
//! `dc1-get-drained-judged-charged` one charge on the drained share.
//!
//! `d19_setup`, `d19_preserved` and `judge_d19` are private to `histories/cohorts.rs`; `setup_charged`,
//! `setup_drained`, `effect_held` and `effect_drained` do their work here, without the cohort's identity
//! records.

use super::incidents::{
    displace, displaced, mark_displaced, mark_old_drained, note_epoch, old_drained, old_held,
};
use super::*;

/// The rule, which `histories/cohorts.rs` raises from its displaced session.
const DROPPED: &str = "a displacement dropped the old session's live charges";

/// The premises of the first history's judgment, and the names an unsuccessful run carries.
const CHARGED: &str = "the old session held a live charge";
const DEVICE_HELD: &str = "the device held the read at the check";

/// The rule of the drained history, which `histories.rs` raises from its saturated share.
const LEFT_SHARE: &str = "a peer's charge left its live requests or its share";

const NOTHING_LIVE: &str = "the old session held no live charge";
const KEPT: &str = "the old session's charges stayed";
const UNCHARGED: &str = "the displaced peer's share stayed empty";

/// The requests the owner charges to the displaced peer's share: its live ones and its draining ones.
fn charged(world: &Mixed<'_, '_, '_>) -> u64 {
    let census = world.scene.owner.peer_census(PeerId(0));
    u64::from(census.active) + u64::from(census.draining)
}

/// Records the peer's charges while the device holds its read, then opens the replacement's session.
fn setup_charged(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.kept = charged(world);
    if premised(world, world.history.kept != 0, CHARGED) == 0 {
        return 0;
    }
    displace(world, now)
}

/// Records the peer's charges once its GET drained, then opens the replacement's session.
fn setup_drained(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    world.history.kept = charged(world);
    if premised(world, world.history.kept == 0, NOTHING_LIVE) == 0 {
        return 0;
    }
    displace(world, now)
}

/// Fails with DROPPED when `charged`, the requests read from the peer's share, is fewer than the
/// displacement found.
fn judge_charges(world: &mut Mixed<'_, '_, '_>, charged: u64) -> u64 {
    if charged < world.history.kept {
        return fail(world, Obligation::Custody, DROPPED);
    }
    mark(world, KEPT)
}

/// The owner counted the displacement and the device still holds the displaced GET's read: judges the
/// peer's charges against those recorded before the displacement.
fn effect_held(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = world.scene.control.outstanding() != 0;
    if premised(world, held, DEVICE_HELD) == 0 {
        return 0;
    }
    let charged = charged(world);
    judge_charges(world, charged)
}

/// A control: the peer's charges are read one lower, as a displacement that dropped the held GET's
/// charge would leave them.
fn effect_dropped(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let held = world.scene.control.outstanding() != 0;
    if premised(world, held, DEVICE_HELD) == 0 {
        return 0;
    }
    let charged = charged(world).saturating_sub(1);
    judge_charges(world, charged)
}

/// Any request read from the drained peer's share (`charged` > 0) fails with LEFT_SHARE: every request
/// the peer issued drained before the displacement.
fn judge_uncharged(world: &mut Mixed<'_, '_, '_>, charged: u64) -> u64 {
    if charged != 0 {
        return fail(world, Obligation::Resources, LEFT_SHARE);
    }
    mark(world, UNCHARGED)
}

fn effect_drained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let charged = charged(world);
    judge_uncharged(world, charged)
}

/// A control: the peer's charges are read one higher, as a displacement that charged the drained
/// request again would leave them.
fn effect_charged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let charged = charged(world) + 1;
    judge_uncharged(world, charged)
}

const DISPLACED_WITH_A_READ_HELD: [Step; 9] = [
    step("arm", always, arm),
    step("old-get", active_put, fresh_get),
    step("old-read-held", old_held, note_epoch),
    step("setup", always, setup_charged),
    step("displaced", displaced, mark_displaced),
    step("effect", always, effect_held),
    step("release-old-read", always, release_reads),
    step("old-drained", old_drained, mark_old_drained),
    JUDGE,
];

const DISPLACED_AFTER_THE_DRAIN: [Step; 9] = [
    step("arm", always, arm),
    step("old-get", active_put, fresh_get),
    step("old-read-held", old_held, note_epoch),
    step("release-old-read", always, release_everything),
    step("old-drained", old_drained, mark_old_drained),
    step("setup", always, setup_drained),
    step("displaced", displaced, mark_displaced),
    step("effect", always, effect_drained),
    JUDGE,
];

const HELD_JUDGED_DROPPED: [Step; 9] = replaced(
    DISPLACED_WITH_A_READ_HELD,
    "effect",
    step("effect-dropped", always, effect_dropped),
);

const DRAINED_JUDGED_CHARGED: [Step; 9] = replaced(
    DISPLACED_AFTER_THE_DRAIN,
    "effect",
    step("effect-charged", always, effect_charged),
);

const WITNESSES: &[&str] = &[
    "old read held",
    CHARGED,
    "a replacement client opened a session",
    "a replacement boot displaced the old session",
    DEVICE_HELD,
    KEPT,
    "old read released",
    "old work drained",
];

const SIBLING_WITNESSES: &[&str] = &[
    "old read held",
    "holds released",
    "old work drained",
    NOTHING_LIVE,
    "a replacement client opened a session",
    "a replacement boot displaced the old session",
    UNCHARGED,
];

const JUDGED: &[Obligation] = &[Obligation::Custody];

/// The exact-charge rule LEFT_SHARE judges the displacement after all requests from the displaced peer
/// have drained.
const SIBLING_JUDGED: &[Obligation] = &[Obligation::Resources];

/// The marks a kill of DROPPED needs: the peer was charged at the displacement, and the device held its
/// read at the judgment.
const PREMISE: &[&str] = &[CHARGED, DEVICE_HELD];

/// The mark a kill of LEFT_SHARE needs: the peer's GET had drained before the displacement.
const SIBLING_PREMISE: &[&str] = &[NOTHING_LIVE];

/// The obligation the mark of each charge judgment judges.
pub(super) const CHECKS: [(&str, Obligation); 2] = [
    (KEPT, Obligation::Custody),
    (UNCHARGED, Obligation::Resources),
];

pub(super) const DISPLACED_CHARGES: [History; 4] = [
    history(
        "dc1-get-held-across-displacement",
        &DISPLACED_WITH_A_READ_HELD,
        WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    history(
        "dc1-get-drained-before-displacement",
        &DISPLACED_AFTER_THE_DRAIN,
        SIBLING_WITNESSES,
        SIBLING_JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "dc1-get-held-judged-dropped",
            &HELD_JUDGED_DROPPED,
            WITNESSES,
            JUDGED,
            Expect::Violation(Obligation::Custody, DROPPED),
        ),
        PREMISE,
    ),
    control(
        history(
            "dc1-get-drained-judged-charged",
            &DRAINED_JUDGED_CHARGED,
            SIBLING_WITNESSES,
            SIBLING_JUDGED,
            Expect::Violation(Obligation::Resources, LEFT_SHARE),
        ),
        SIBLING_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use crate::sim::turn::End;

    use super::super::tests::run_end;
    use super::{DISPLACED_CHARGES, Expect};

    /// Each run of both passing histories at roots 1, 2 and 3 must reach `Done` with an empty first
    /// failure. A run stopped by a limit also leaves that field empty, so `Done` confirms the judgment
    /// ran.
    #[test]
    fn the_pinned_roots_of_both_histories_end_done_with_no_failure() {
        let passing = DISPLACED_CHARGES
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
