//! Retained-GET histories: a completed GET stays in its peer's share while
//! a device still holds the transmit references of its DATA.
//!
//! Property: the rule "a retained GET left its peer's share before its
//! release" of `narrate/rules.rs`, which the step `b_charged` of
//! `histories/incidents.rs` judges history `i5` with. The judgment is made
//! here for one peer and one GET, and the census is read again after the
//! references returned.
//!
//! Both histories run the single-owner world, whose scene publishes version
//! A under key 1 before the run, and both withhold the links' transmit
//! references (`hold_nic`) before client 1, peer B, issues its GET of key 1.
//! The owner sends B the object's DATA from its retained chunk, the link's
//! device delivers it and keeps the reference, and B's GET ends once the
//! owner's COMPLETE reaches it.
//!
//! - `rt1-get-retained`: the step that collects B's read runs while the
//!   references are still withheld. That the read ended `Complete` with
//!   version A's exact bytes, and that B's link withholds a reference, are
//!   premises: one that does not form ends the run unsuccessful under its
//!   name, and both are read from the client and the link, which hold the
//!   same with and without a defect. The judgment is `Owner::peer_census`
//!   of B: the GET is still counted, `active + draining == 1`, and any other
//!   count fails through the rule. The holds then end, every reference must
//!   be reclaimed, and the GET must then leave B's share.
//! - `rt1-get-released`: the same GET, the same hold and the same premises,
//!   with the holds ended and every reference reclaimed before the read is
//!   collected. B's census is then 0: the GET left its share after its
//!   release.
//! - `rt1-get-judged-uncharged` repeats `rt1-get-retained` as a negative
//!   control. Its `b-read-uncharged` step reads B's charge as 0 while B's
//!   link withholds the transmit references, so the charge check fails.

use super::*;

const COMPLETED: &str = "B's GET completed with exact bytes";
const WITHHELD: &str = "B's DATA references withheld";
const KEPT: &str = "the retained GET stayed in B's share";
const RECLAIMED: &str = "each custody domain released after its proof";
const LEFT: &str = "the released GET left B's share";
const LEFT_EARLY: &str = "a retained GET left its peer's share before its release";

/// The peer whose GET the histories judge: client 1 of the world.
const B: PeerId = PeerId(1);

/// B's live requests at the owner, active and draining.
fn b_charge(world: &Mixed<'_, '_, '_>) -> u32 {
    let census = world.scene.owner.peer_census(B);
    census.active + census.draining
}

/// Collects B's read. The premise: it ended `Complete` with version A's exact bytes.
fn b_completed(world: &mut Mixed<'_, '_, '_>) -> bool {
    world.read(1);
    let get = world.gets[1].as_ref().expect("B's GET");
    if get.outcome != Some(Outcome::Complete) || get.bytes != version_a() {
        world.first.record(Failure::Unsuccessful(COMPLETED));
        return false;
    }
    mark(world, COMPLETED);
    true
}

/// References B's link withholds. B sends no retained piece, so each is one of the owner's DATA to B.
fn b_withheld(world: &Mixed<'_, '_, '_>) -> usize {
    world.scene.nets[1].borrow().withheld()
}

/// The judgment, at the step that collects B's read while the history withholds the transmit references:
/// B's completed GET is still counted in B's share.
fn b_retained(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    let charge = b_charge(world);
    judge_retained(world, charge)
}

fn b_retained_uncharged(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    judge_retained(world, 0)
}

fn judge_retained(world: &mut Mixed<'_, '_, '_>, charge: u32) -> u64 {
    if !b_completed(world) {
        return 0;
    }
    if !world.history.hold_nic || b_withheld(world) == 0 {
        world.first.record(Failure::Unsuccessful(WITHHELD));
        return 0;
    }
    mark(world, WITHHELD);
    if charge != 1 {
        return fail(world, Obligation::Resources, LEFT_EARLY);
    }
    mark(world, KEPT)
}

/// The second history's premise before its release: B's GET is decided and its DATA references are withheld.
fn b_decided_withheld(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if !world.history.hold_nic || b_withheld(world) == 0 {
        world.first.record(Failure::Unsuccessful(WITHHELD));
        return 0;
    }
    mark(world, WITHHELD)
}

/// B's share is empty, or the bound since the holds' release passed twice: once for the references to
/// return, once for the owner to drop the GET.
fn b_left_or_late(world: &Mixed<'_, '_, '_>, now: u64) -> bool {
    b_charge(world) == 0 || now > world.history.released_at + 2 * BOUND_US
}

/// After the release: the GET left B's share. A GET still counted is no retained GET that left early, so
/// it ends the run unsuccessful under this witness and never through the rule.
fn b_left(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    if b_charge(world) != 0 {
        world.first.record(Failure::Unsuccessful(LEFT));
        return 0;
    }
    mark(world, LEFT)
}

/// The second history's collection after the release: the same read, and B's share is empty.
fn b_released(world: &mut Mixed<'_, '_, '_>, now: u64) -> u64 {
    if !b_completed(world) {
        return 0;
    }
    b_left(world, now)
}

const RETAINED: [Step; 7] = [
    step("arm", always, arm_nic),
    step("b-get", active_get, old_get),
    step("b-read", old_decided, b_retained),
    step("release", always, release_everything),
    step("returned", released_or_late, released_in_domain),
    step("b-left", b_left_or_late, b_left),
    JUDGE,
];

const RELEASED: [Step; 7] = [
    step("arm", always, arm_nic),
    step("b-get", active_get, old_get),
    step("b-decided", old_decided, b_decided_withheld),
    step("release", always, release_everything),
    step("returned", released_or_late, released_in_domain),
    step("b-read", b_left_or_late, b_released),
    JUDGE,
];

const UNCHARGED: [Step; 7] = replaced(
    RETAINED,
    "b-read",
    step("b-read-uncharged", old_decided, b_retained_uncharged),
);

const RETAINED_WITNESSES: &[&str] = &[
    "holds armed",
    COMPLETED,
    WITHHELD,
    KEPT,
    "holds released",
    RECLAIMED,
    LEFT,
];

const RELEASED_WITNESSES: &[&str] = &[
    "holds armed",
    WITHHELD,
    "holds released",
    RECLAIMED,
    COMPLETED,
    LEFT,
];

const UNCHARGED_PREMISE: &[&str] = &["holds armed", COMPLETED, WITHHELD];

const JUDGED: &[Obligation] = &[Obligation::Resources];

pub(super) const RETAINED_GETS: [History; 3] = [
    history(
        "rt1-get-retained",
        &RETAINED,
        RETAINED_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    history(
        "rt1-get-released",
        &RELEASED,
        RELEASED_WITNESSES,
        JUDGED,
        Expect::Pass,
    ),
    control(
        history(
            "rt1-get-judged-uncharged",
            &UNCHARGED,
            RETAINED_WITNESSES,
            JUDGED,
            Expect::Violation(Obligation::Resources, LEFT_EARLY),
        ),
        UNCHARGED_PREMISE,
    ),
];

#[cfg(test)]
mod tests {
    use super::super::Expect;
    use super::super::tests::ends_as_declared_at;
    use super::RETAINED_GETS;

    #[test]
    fn a_retained_get_keeps_its_share_until_its_release_at_pinned_roots() {
        for history in RETAINED_GETS.iter().filter(|h| h.expect == Expect::Pass) {
            for root in [3, 211, 6_004_799_503_160_661] {
                ends_as_declared_at(history, root);
            }
        }
    }
}
