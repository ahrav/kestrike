use super::{identity::Exhid, route::*, route_merge::merge_identity};
use crate::net::ownership::{ActivatedEpoch, ShardGeneration, Tenure};

/// A tenure at generation `g` and activated epoch `2a`, held by host identifier `[x; 16]`.
pub(super) fn tenure(g: u64, a: u32, x: u8) -> Tenure {
    Tenure {
        generation: ShardGeneration::new(g).unwrap(),
        epoch: ActivatedEpoch::new(2 * a).unwrap(),
        host: Exhid::new([x; 16]).unwrap(),
    }
}

fn conflicted(g: u64, a: u32) -> HighWater {
    HighWater::Conflict {
        generation: ShardGeneration::new(g).unwrap(),
        epoch: ActivatedEpoch::new(2 * a).unwrap(),
    }
}

fn darkened(g: u64, a: u32) -> HighWater {
    HighWater::Dark {
        generation: ShardGeneration::new(g).unwrap(),
        epoch: ActivatedEpoch::new(2 * a).unwrap(),
    }
}

/// The frame kind of the model's `(bound, dark)` pair; `dark` takes precedence.
pub(super) fn kind(bound: bool, retired: bool) -> FrameKind {
    match (bound, retired) {
        (_, true) => FrameKind::Retired,
        (true, false) => FrameKind::Ready,
        (false, false) => FrameKind::Candidate,
    }
}

fn frame(g: u64, a: u32, x: u8, bound: bool, retired: bool) -> HolderFrame {
    HolderFrame {
        tenure: tenure(g, a, x),
        kind: kind(bound, retired),
    }
}

/// The high-water witness over `merge`: a conflict does not depend on arrival order, a duplicate changes nothing,
/// a conflict refuses requests and both tenures' responses until a higher epoch binds, a lower or equal tenure leaves
/// the binding, and a retirement of the bound tenure darkens it.
fn preserves_the_high_water(merge: impl Fn(Option<HighWater>, HolderFrame) -> HighWater) {
    let a_first = merge(
        Some(merge(None, frame(1, 7, 1, true, false))),
        frame(1, 7, 2, true, false),
    );
    let b_first = merge(
        Some(merge(None, frame(1, 7, 2, true, false))),
        frame(1, 7, 1, true, false),
    );
    assert_eq!(
        a_first, b_first,
        "a conflict does not depend on arrival order"
    );
    for (a, b) in [(1, 2), (2, 1)] {
        let f = frame(1, 7, a, true, false);
        let g = frame(1, 7, b, true, false);
        let hw = merge(None, f);
        assert!(hw.requests());
        assert!(hw.response(f.tenure));
        assert_eq!(merge(Some(hw), f), hw);
        let conflict = merge(Some(hw), g);
        assert_eq!(conflict, conflicted(1, 7));
        assert!(!conflict.requests());
        for x in [a, b] {
            assert!(!conflict.response(tenure(1, 7, x)));
        }
        assert_eq!(merge(Some(conflict), f), conflict);
        assert_eq!(merge(Some(conflict), frame(1, 6, a, true, false)), conflict);
        let bound = merge(Some(conflict), frame(1, 8, a, true, false));
        assert!(matches!(bound, HighWater::Bound(_)));
        assert!(!bound.response(f.tenure));
        assert_eq!(merge(Some(bound), frame(1, 7, a, true, false)), bound);
        let dark = merge(Some(bound), frame(1, 8, a, true, true));
        assert_eq!(dark, darkened(1, 8));
        assert!(!dark.requests());
        assert!(!dark.response(tenure(1, 8, a)));
    }
}

#[test]
fn reordering_duplication_conflict_and_dark_preserve_the_high_water() {
    preserves_the_high_water(HighWater::merge);
}

/// The negative control "latest arrival wins": a merge that replaces the high-water with each frame it receives binds
/// whichever of two equal-tenure holders arrived last, so the witness rejects it at its arrival-order check.
#[test]
#[should_panic(expected = "a conflict does not depend on arrival order")]
fn negative_control_a_latest_arrival_merge_depends_on_arrival_order() {
    preserves_the_high_water(|_, frame| HighWater::merge(None, frame));
}

#[test]
fn candidate_frames_preserve_a_bound_session_and_responses_name_the_exact_tenure() {
    let c = HighWater::merge(None, frame(1, 8, 1, false, false));
    assert!(matches!(c, HighWater::Candidate(_)));
    assert!(c.requests());
    assert!(!c.response(tenure(1, 8, 1)));
    let b = HighWater::merge(Some(c), frame(1, 8, 1, true, false));
    assert_eq!(b, HighWater::Bound(tenure(1, 8, 1)));
    assert!(b.response(tenure(1, 8, 1)));
    assert_eq!(HighWater::merge(Some(b), frame(1, 8, 1, false, false)), b);
    assert!(!b.response(tenure(1, 8, 2)));
    for old in 0..5 {
        for new in 0..5 {
            for conflict in [false, true] {
                for x in [1, 2] {
                    let m = merge_identity(old, 1, conflict, new, x);
                    assert!(m.0 >= old && m.0 >= new);
                    assert_eq!(m.3, new > old || (new == old && x == 1 && !conflict));
                    if conflict && new <= old {
                        assert!(!m.3);
                    }
                    if new == old && x == 2 {
                        assert!(m.2);
                        assert!(!m.3);
                    }
                }
            }
        }
    }
}

#[test]
fn high_water_orders_by_generation_then_epoch() {
    let old = HighWater::merge(None, frame(1, 4, 1, true, false));
    let flipped = HighWater::merge(Some(old), frame(2, 1, 2, true, false));
    assert_eq!(
        flipped,
        HighWater::Bound(tenure(2, 1, 2)),
        "a later generation outranks a larger epoch of an earlier one"
    );
    assert!(flipped.response(tenure(2, 1, 2)));
    for stale in [frame(1, 4, 1, true, false), frame(1, 9, 1, true, false)] {
        assert_eq!(HighWater::merge(Some(flipped), stale), flipped);
        assert!(
            !flipped.response(stale.tenure),
            "a response below the high-water is discarded"
        );
    }
    let conflict = HighWater::merge(Some(flipped), frame(2, 1, 3, true, false));
    assert_eq!(conflict, conflicted(2, 1));
    assert!(!conflict.requests());
    assert!(!conflict.response(tenure(2, 1, 2)) && !conflict.response(tenure(2, 1, 3)));
    assert_eq!(
        HighWater::merge(Some(conflict), frame(2, 1, 2, true, false)),
        conflict
    );
    assert_eq!(
        HighWater::merge(Some(conflict), frame(1, 9, 2, true, false)),
        conflict,
        "a larger epoch of an earlier generation leaves the conflict"
    );
    assert_eq!(
        HighWater::merge(Some(conflicted(1, 7)), frame(2, 1, 3, true, false)),
        HighWater::Bound(tenure(2, 1, 3)),
        "a later generation with a smaller epoch clears the conflict"
    );
    let exit = HighWater::merge(Some(conflict), frame(2, 2, 3, true, false));
    assert_eq!(exit, HighWater::Bound(tenure(2, 2, 3)));
}

#[test]
fn retired_volume_not_routed() {
    let bound = HighWater::merge(None, frame(3, 2, 1, true, false));
    let retired = HighWater::merge(Some(bound), frame(3, 2, 1, true, true));
    assert_eq!(retired, darkened(3, 2));
    assert!(!retired.requests());
    assert!(!retired.response(tenure(3, 2, 1)));
    for delayed in [
        frame(3, 2, 1, true, false),
        frame(3, 3, 1, true, false),
        frame(3, 9, 2, false, false),
        frame(3, 1, 1, true, false),
    ] {
        assert_eq!(
            HighWater::merge(Some(retired), delayed),
            retired,
            "a frame of the retired volume's generation leaves the route dark"
        );
    }
    let successor = HighWater::merge(Some(retired), frame(4, 1, 2, true, false));
    assert_eq!(successor, HighWater::Bound(tenure(4, 1, 2)));
    assert!(successor.requests());
    assert_eq!(
        HighWater::merge(Some(successor), frame(3, 2, 1, true, true)),
        successor,
        "a late retirement of the predecessor leaves the successor routed"
    );
    assert_eq!(
        HighWater::merge(Some(retired), frame(3, 9, 2, true, true)),
        retired,
        "a higher-epoch retirement of the dark generation from another host leaves it unchanged"
    );
    assert_eq!(
        HighWater::merge(Some(retired), frame(4, 1, 2, false, false)),
        HighWater::Candidate(tenure(4, 1, 2)),
        "a candidate of a later generation exits Dark"
    );
    let next = HighWater::merge(Some(retired), frame(4, 1, 2, true, true));
    assert_eq!(
        next,
        darkened(4, 1),
        "a retirement of a later generation darkens that generation"
    );
    for delayed in [frame(4, 3, 2, true, false), frame(3, 9, 1, true, false)] {
        assert_eq!(HighWater::merge(Some(next), delayed), next);
    }
    assert_eq!(
        HighWater::merge(Some(next), frame(5, 1, 3, true, false)),
        HighWater::Bound(tenure(5, 1, 3))
    );
    assert_eq!(
        HighWater::merge(Some(bound), frame(4, 1, 2, false, true)),
        darkened(4, 1)
    );
}

#[test]
fn packed_order_holds_at_the_field_limits() {
    let last_epoch = ActivatedEpoch::MAX / 2;
    let top = u64::from(u32::MAX);
    let bound = |tenure| HolderFrame {
        tenure,
        kind: FrameKind::Ready,
    };
    for (low, high) in [
        (tenure(1, last_epoch, 1), tenure(2, 1, 2)),
        (tenure(top - 1, last_epoch, 1), tenure(top, 1, 2)),
        (tenure(top, 1, 1), tenure(top, last_epoch, 2)),
    ] {
        let raised = HighWater::merge(Some(HighWater::merge(None, bound(low))), bound(high));
        assert_eq!(raised, HighWater::Bound(high));
        assert_eq!(HighWater::merge(Some(raised), bound(low)), raised);
    }
    let dark = HighWater::merge(
        None,
        HolderFrame {
            tenure: tenure(top, 1, 1),
            kind: FrameKind::Retired,
        },
    );
    for x in [1, 2] {
        assert_eq!(
            HighWater::merge(Some(dark), bound(tenure(top, last_epoch, x))),
            dark,
            "a Dark route is unchanged by the largest epoch of its generation from either host"
        );
    }
}

#[test]
fn dark_and_conflict_routes_keep_identity_and_tenure_rules() {
    let dark = HighWater::merge(None, frame(1, 7, 1, true, true));
    let conflict = conflicted(1, 7);
    assert_eq!(
        HighWater::merge(Some(dark), frame(1, 7, 2, true, false)),
        dark,
        "the retired generation absorbs another host's frame"
    );
    assert_eq!(
        HighWater::merge(Some(dark), frame(1, 6, 1, true, true)),
        dark
    );
    assert_eq!(
        HighWater::merge(Some(conflict), frame(1, 8, 1, true, true)),
        darkened(1, 8)
    );
}

#[test]
fn a_retirement_of_the_held_generation_darkens_it_at_any_epoch_or_state() {
    for (held, x) in [
        HighWater::merge(None, frame(3, 6, 1, true, false)),
        HighWater::merge(None, frame(3, 6, 1, false, false)),
    ]
    .into_iter()
    .flat_map(|held| [(held, 1), (held, 2)])
    {
        let dark = HighWater::merge(Some(held), frame(3, 4, x, true, true));
        assert_eq!(
            dark,
            darkened(3, 6),
            "a delayed retirement below the held epoch darkens the generation and keeps the high-water"
        );
        assert!(!dark.requests() && !dark.response(tenure(3, 6, 1)));
        assert_eq!(
            HighWater::merge(Some(dark), frame(3, 7, 1, true, false)),
            dark
        );
    }
    let conflict = conflicted(1, 7);
    assert_eq!(
        HighWater::merge(Some(conflict), frame(1, 7, 2, true, true)),
        darkened(1, 7)
    );
    let dark = HighWater::merge(Some(conflict), frame(1, 7, 1, true, true));
    assert_eq!(
        dark,
        darkened(1, 7),
        "a retirement at the conflicting tenure darkens the generation"
    );
    let later = HighWater::merge(Some(dark), frame(1, 8, 1, true, false));
    assert_eq!(
        later, dark,
        "a later epoch of the retired generation stays dark"
    );
    assert!(!later.requests());
}

#[test]
fn higher_candidates_replace_a_bound_route() {
    let old = tenure(1, 1, 1);
    let bound = HighWater::merge(None, frame(1, 1, 1, true, false));
    for higher in [frame(2, 1, 2, false, false), frame(1, 2, 1, false, false)] {
        let raised = HighWater::merge(Some(bound), higher);
        assert_eq!(raised, HighWater::Candidate(higher.tenure));
        assert!(raised.requests());
        assert!(!raised.response(old));
        assert!(!raised.response(higher.tenure));
    }
}

#[test]
fn an_unactivated_candidate_sorts_below_its_generation_and_yields_to_ready() {
    let old = HighWater::merge(None, frame(1, 5, 1, true, false));
    let announced = HighWater::merge(Some(old), frame(2, 0, 2, false, false));
    assert_eq!(announced, HighWater::Candidate(tenure(2, 0, 2)));
    assert!(!announced.response(tenure(2, 0, 2)));
    let ready = HighWater::merge(Some(announced), frame(2, 1, 2, true, false));
    assert_eq!(ready, HighWater::Bound(tenure(2, 1, 2)));
    assert_eq!(
        HighWater::merge(Some(ready), frame(2, 0, 2, false, false)),
        ready
    );
}

#[test]
fn candidates_enter_conflict_and_retirements_darken_a_conflict() {
    for held in [
        HighWater::merge(None, frame(1, 7, 1, false, false)),
        HighWater::merge(None, frame(1, 7, 1, true, false)),
    ] {
        assert_eq!(
            HighWater::merge(Some(held), frame(1, 7, 2, false, false)),
            conflicted(1, 7),
            "another host's candidate at the held tenure conflicts"
        );
    }
    assert_eq!(
        HighWater::merge(Some(conflicted(1, 7)), frame(1, 3, 2, true, true)),
        darkened(1, 7),
        "a lower-epoch retirement darkens a conflicted generation at the held epoch"
    );
    assert_eq!(
        HighWater::merge(Some(conflicted(1, 7)), frame(2, 1, 2, true, true)),
        darkened(2, 1),
        "a later-generation retirement darkens that generation"
    );
}
