//! The route's high-water orders tenures by generation, then epoch.
//!
//! The per-shard high-water never decreases in `(g, a)`, ordered by
//! generation, then activated epoch. `HighWater::merge` is driven from a
//! Candidate and from a Bound route with Candidate and Ready frames whose
//! tenures are chosen so that the generation order and the epoch order
//! disagree: a later generation with a lower epoch replaces the route, an
//! earlier generation with a higher epoch leaves it, and within one
//! generation the higher epoch replaces it and the lower one leaves it.
//!
//! The expected route of every merge comes from this file's own order, the
//! tuple `(g, a)` compared generation first, and never from `route::key`.
//! The frames here are Candidate and Ready frames of tenures that differ
//! in `(g, a)` from the held one, so the conflict and retirement clauses
//! take no part. `HighWater::merge` is a pure function of its arguments:
//! the tests hold no fixture, and each decides its verdict into a value
//! before it asserts.

use std::cmp::Ordering;

use crate::failover::identity::Exhid;
use crate::failover::route::{FrameKind, HighWater, HolderFrame};
use crate::net::ownership::{ActivatedEpoch, ShardGeneration, Tenure};

/// The tenure `(generation, epoch)` of the host whose identifier repeats `host`.
fn tenure(generation: u64, epoch: u32, host: u8) -> Tenure {
    Tenure {
        generation: ShardGeneration::new(generation).expect("premise: a generation in 1..2^32"),
        epoch: ActivatedEpoch::new(epoch).expect("premise: an even activated epoch"),
        host: Exhid::new([host; 16]).expect("premise: a nonzero host identifier"),
    }
}

fn frame(tenure: Tenure, kind: FrameKind) -> HolderFrame {
    HolderFrame { tenure, kind }
}

/// The agreed order of two tenures: generation first, activated epoch second.
fn order(left: Tenure, right: Tenure) -> Ordering {
    (left.generation.get(), left.epoch.get()).cmp(&(right.generation.get(), right.epoch.get()))
}

/// The route the property requires after a Candidate or Ready frame of `incoming` reaches a Candidate or
/// Bound route `old` of another `(g, a)`: a higher tenure replaces the route, bound by a Ready frame and a
/// Candidate otherwise, and a lower tenure leaves it.
fn required(old: HighWater, held: Tenure, incoming: Tenure, kind: FrameKind) -> HighWater {
    match (order(incoming, held), kind) {
        (Ordering::Greater, FrameKind::Ready) => HighWater::Bound(incoming),
        (Ordering::Greater, _) => HighWater::Candidate(incoming),
        _ => old,
    }
}

/// The held tenure of every single-merge test: generation 5, epoch 10.
fn held() -> Tenure {
    tenure(5, 10, 0xA1)
}

/// The two routes a merge starts from, at `held`.
fn starts(held: Tenure) -> [HighWater; 2] {
    [HighWater::Candidate(held), HighWater::Bound(held)]
}

/// What one merge left: the route, whether it admits requests, and whether it answers for the frame's
/// tenure and for the held one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Merged {
    route: HighWater,
    requests: bool,
    answers_frame: bool,
    answers_held: bool,
}

fn merged(old: HighWater, held: Tenure, incoming: Tenure, kind: FrameKind) -> Merged {
    let route = HighWater::merge(Some(old), frame(incoming, kind));
    Merged {
        route,
        requests: route.requests(),
        answers_frame: route.response(incoming),
        answers_held: route.response(held),
    }
}

/// A frame of generation g + 1 whose epoch is below the held one replaces a Candidate and a Bound route: a
/// Candidate frame leaves a Candidate of the new tenure, a Ready frame binds it, and the route then answers
/// for the new tenure and no longer for the old.
#[test]
fn a_later_generation_with_a_lower_epoch_replaces_the_route() {
    let held = held();
    let later = tenure(6, 4, 0xB2);
    let premise = order(later, held) == Ordering::Greater && later.epoch < held.epoch;
    let seen: Vec<Merged> = starts(held)
        .into_iter()
        .flat_map(|old| {
            [FrameKind::Candidate, FrameKind::Ready].map(|kind| merged(old, held, later, kind))
        })
        .collect();
    let candidate = Merged {
        route: HighWater::Candidate(later),
        requests: true,
        answers_frame: false,
        answers_held: false,
    };
    let bound = Merged {
        route: HighWater::Bound(later),
        requests: true,
        answers_frame: true,
        answers_held: false,
    };
    assert!(
        premise,
        "premise: the generation order and the epoch order disagree"
    );
    assert_eq!(
        seen,
        [candidate, bound, candidate, bound],
        "a later generation is the higher tenure whatever its epoch"
    );
}

/// A frame of generation g - 1 whose epoch is above the held one leaves a Candidate and a Bound route as it
/// is: a Bound route still answers for the held tenure and never for the frame's.
#[test]
fn an_earlier_generation_with_a_higher_epoch_leaves_the_route() {
    let held = held();
    let earlier = tenure(4, 20, 0xB2);
    let premise = order(earlier, held) == Ordering::Less && earlier.epoch > held.epoch;
    let seen: Vec<Merged> = starts(held)
        .into_iter()
        .flat_map(|old| {
            [FrameKind::Candidate, FrameKind::Ready].map(|kind| merged(old, held, earlier, kind))
        })
        .collect();
    let candidate = Merged {
        route: HighWater::Candidate(held),
        requests: true,
        answers_frame: false,
        answers_held: false,
    };
    let bound = Merged {
        route: HighWater::Bound(held),
        requests: true,
        answers_frame: false,
        answers_held: true,
    };
    assert!(
        premise,
        "premise: the generation order and the epoch order disagree"
    );
    assert_eq!(
        seen,
        [candidate, candidate, bound, bound],
        "an earlier generation is the lower tenure whatever its epoch"
    );
}

/// Within one generation the epoch decides: the higher epoch replaces the route and the lower one leaves
/// it. The epoch order alone agrees with this, so this is the test that an order on epochs also passes.
#[test]
fn within_one_generation_the_higher_epoch_replaces_and_the_lower_leaves() {
    let held = held();
    let (higher, lower) = (tenure(5, 12, 0xB2), tenure(5, 8, 0xB2));
    let seen: Vec<(HighWater, HighWater)> = starts(held)
        .into_iter()
        .flat_map(|old| {
            [FrameKind::Candidate, FrameKind::Ready].map(|kind| {
                (
                    HighWater::merge(Some(old), frame(higher, kind)),
                    HighWater::merge(Some(old), frame(lower, kind)),
                )
            })
        })
        .collect();
    assert_eq!(
        seen,
        [
            (HighWater::Candidate(higher), HighWater::Candidate(held)),
            (HighWater::Bound(higher), HighWater::Candidate(held)),
            (HighWater::Candidate(higher), HighWater::Bound(held)),
            (HighWater::Bound(higher), HighWater::Bound(held)),
        ],
        "within a generation the activated epoch orders tenures"
    );
}

/// Every pair of tenures over three generations and four epochs that differ in `(g, a)`, from both routes,
/// with both frame kinds and with the frame's host equal to the held one and distinct from it: the merge is
/// the one the `(g, a)` order requires. The grid holds the pairs where the two orders disagree, the pairs
/// where they agree, and the pairs of two generations at one epoch.
#[test]
fn every_pair_of_unequal_tenures_merges_by_generation_then_epoch() {
    const GENERATIONS: [u64; 3] = [1, 2, 0xFFFF_FFFF];
    const EPOCHS: [u32; 4] = [0, 2, 10, ActivatedEpoch::MAX];
    let mut pairs = 0;
    let mut disagreeing = 0;
    let mut wrong = Vec::new();
    for held_generation in GENERATIONS {
        for held_epoch in EPOCHS {
            let held = tenure(held_generation, held_epoch, 0xA1);
            for generation in GENERATIONS {
                for epoch in EPOCHS {
                    if (generation, epoch) == (held_generation, held_epoch) {
                        continue;
                    }
                    for host in [0xA1, 0xB2] {
                        let incoming = tenure(generation, epoch, host);
                        for old in starts(held) {
                            for kind in [FrameKind::Candidate, FrameKind::Ready] {
                                pairs += 1;
                                disagreeing += usize::from(
                                    generation.cmp(&held_generation)
                                        == epoch.cmp(&held_epoch).reverse(),
                                );
                                let route = HighWater::merge(Some(old), frame(incoming, kind));
                                let expected = required(old, held, incoming, kind);
                                if route != expected && wrong.len() < 4 {
                                    wrong.push((old, incoming, kind, route, expected));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(
        (pairs, disagreeing > 0),
        (12 * 11 * 2 * 2 * 2, true),
        "premise: the grid's merges ran and some set the two orders against each other"
    );
    assert!(
        wrong.is_empty(),
        "(old route, frame tenure, kind, merged, required) of the first merges out of order: {wrong:?}"
    );
}

/// A run of Ready and Candidate frames whose generations rise while their epochs fall, with stale frames of
/// earlier generations and higher epochs between them: after every frame the route's `(g, a)` is the highest
/// tenure seen so far in the agreed order, so it never decreases, and the route answers only for that
/// tenure once a Ready frame bound it.
#[test]
fn a_run_of_frames_holds_the_highest_tenure_by_generation_then_epoch() {
    let run = [
        (tenure(2, 40, 0xA1), FrameKind::Ready),
        (tenure(3, 30, 0xB2), FrameKind::Candidate),
        (tenure(2, 50, 0xA1), FrameKind::Ready),
        (tenure(3, 30, 0xB2), FrameKind::Ready),
        (tenure(1, 60, 0xC3), FrameKind::Ready),
        (tenure(4, 2, 0xC3), FrameKind::Ready),
        (tenure(3, 58, 0xB2), FrameKind::Candidate),
        (tenure(4, 6, 0xA1), FrameKind::Candidate),
        (tenure(4, 4, 0xC3), FrameKind::Ready),
        (tenure(5, 0, 0xB2), FrameKind::Ready),
    ];
    // The route this file's own order requires after each frame of the run.
    let required = [
        HighWater::Bound(tenure(2, 40, 0xA1)),
        HighWater::Candidate(tenure(3, 30, 0xB2)),
        HighWater::Candidate(tenure(3, 30, 0xB2)),
        HighWater::Bound(tenure(3, 30, 0xB2)),
        HighWater::Bound(tenure(3, 30, 0xB2)),
        HighWater::Bound(tenure(4, 2, 0xC3)),
        HighWater::Bound(tenure(4, 2, 0xC3)),
        HighWater::Candidate(tenure(4, 6, 0xA1)),
        HighWater::Candidate(tenure(4, 6, 0xA1)),
        HighWater::Bound(tenure(5, 0, 0xB2)),
    ];
    let mut route = None;
    let mut highest: Option<Tenure> = None;
    let mut seen = Vec::new();
    let mut falls = Vec::new();
    for (at, (incoming, kind)) in run.into_iter().enumerate() {
        let before = route.map(|route: HighWater| (route.generation().get(), route.epoch().get()));
        let next = HighWater::merge(route, frame(incoming, kind));
        let after = (next.generation().get(), next.epoch().get());
        if highest.is_none_or(|highest| order(incoming, highest) == Ordering::Greater) {
            highest = Some(incoming);
        }
        let top = highest.map(|top| (top.generation.get(), top.epoch.get()));
        if before.is_some_and(|before| after < before) || top != Some(after) {
            falls.push((at, before, after, top));
        }
        seen.push(next);
        route = Some(next);
    }
    assert!(
        falls.is_empty(),
        "(frame, (g, a) before, after, highest seen) where the high-water fell or missed the highest tenure: {falls:?}"
    );
    assert_eq!(seen, required, "the route after each frame of the run");
}
