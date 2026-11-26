//! RouteMonotonic: `HighWater::merge` never moves a route's `(generation, activated epoch)` down, and a
//! Dark route keeps the epoch it recorded when its generation darkened.
//!
//! `merge` is a pure function of the held route and one frame, so the first test checks every merge of every
//! route that any sequence of frames reaches, over three generations, four epochs, two hosts and the four frame
//! kinds. The other tests name two sequences: a retirement of the held generation whose epoch is below the held
//! epoch, and a frame of an earlier generation with a higher epoch.
//!
//! The route core holds no fixture, so each test reads its verdict into a value and then asserts it.

use crate::failover::identity::Exhid;
use crate::failover::route::{FrameKind, HighWater, HolderFrame};
use crate::net::ownership::{ActivatedEpoch, ShardGeneration, Tenure};

const KINDS: [FrameKind; 4] = [
    FrameKind::Candidate,
    FrameKind::Ready,
    FrameKind::Retired,
    FrameKind::Invalid,
];
const GENERATIONS: [u64; 3] = [1, 2, 3];
/// Zero is the epoch of a tenure whose attempt has not activated; it sorts below every activated epoch.
const EPOCHS: [u32; 4] = [0, 2, 4, 6];
const HOSTS: [u8; 2] = [0xA1, 0xB2];

fn tenure(generation: u64, epoch: u32, host: u8) -> Tenure {
    Tenure {
        generation: ShardGeneration::new(generation).unwrap(),
        epoch: ActivatedEpoch::new(epoch).unwrap(),
        host: Exhid::new([host; 16]).unwrap(),
    }
}

fn frame(generation: u64, epoch: u32, host: u8, kind: FrameKind) -> HolderFrame {
    HolderFrame {
        tenure: tenure(generation, epoch, host),
        kind,
    }
}

fn dark(generation: u64, epoch: u32) -> HighWater {
    HighWater::Dark {
        generation: ShardGeneration::new(generation).unwrap(),
        epoch: ActivatedEpoch::new(epoch).unwrap(),
    }
}

/// Every frame of the scenario: each kind at each tenure.
fn frames() -> Vec<HolderFrame> {
    let mut frames = Vec::new();
    for generation in GENERATIONS {
        for epoch in EPOCHS {
            for host in HOSTS {
                for kind in KINDS {
                    frames.push(frame(generation, epoch, host, kind));
                }
            }
        }
    }
    frames
}

/// The pair RouteMonotonic orders: the generation, then the activated epoch.
fn pair(route: HighWater) -> (u64, u32) {
    (route.generation().get(), route.epoch().get())
}

/// Folds `frames` through `merge` from `start` and returns the route after each frame.
fn fold(start: Option<HighWater>, frames: &[HolderFrame]) -> Vec<HighWater> {
    let mut route = start;
    frames
        .iter()
        .map(|&frame| {
            let next = HighWater::merge(route, frame);
            route = Some(next);
            next
        })
        .collect()
}

/// Every route some sequence of the scenario's frames reaches from no route: the closure of `merge` over them.
fn reachable(frames: &[HolderFrame]) -> Vec<HighWater> {
    let mut routes: Vec<HighWater> = Vec::new();
    let mut next = 0;
    let mut current = None;
    loop {
        for &frame in frames {
            let merged = HighWater::merge(current, frame);
            if !routes.contains(&merged) {
                routes.push(merged);
            }
        }
        let Some(&route) = routes.get(next) else {
            return routes;
        };
        current = Some(route);
        next += 1;
    }
}

/// From no route and from every route a sequence of frames reaches, Candidate, Bound, Conflict and Dark among
/// them, a frame of any kind at any tenure leaves `(generation, epoch)` at or above the pair before it, and a
/// Dark route that stays in its generation keeps its epoch.
#[test]
fn no_merge_of_any_reachable_route_lowers_its_generation_and_epoch() {
    let frames = frames();
    let routes = reachable(&frames);
    let held = [
        routes.iter().any(|r| matches!(r, HighWater::Candidate(_))),
        routes.iter().any(|r| matches!(r, HighWater::Bound(_))),
        routes
            .iter()
            .any(|r| matches!(r, HighWater::Conflict { .. })),
        routes.iter().any(|r| matches!(r, HighWater::Dark { .. })),
    ];
    let mut lowered = Vec::new();
    let mut dark_moved = Vec::new();
    for &old in &routes {
        for &frame in &frames {
            let new = HighWater::merge(Some(old), frame);
            if pair(new) < pair(old) {
                lowered.push((old, frame, new));
            }
            if matches!(old, HighWater::Dark { .. })
                && new.generation() == old.generation()
                && new != old
            {
                dark_moved.push((old, frame, new));
            }
        }
    }
    assert_eq!(held, [true; 4], "the closure holds every kind of route");
    // Two hosts at each of the 12 `(g, a)` pairs as Candidate and as Bound, and one Conflict and one Dark a pair.
    assert_eq!(
        routes.len(),
        72,
        "every route over the scenario's tenures is reached"
    );
    assert!(
        lowered.is_empty(),
        "a merge lowered (generation, epoch): {lowered:?}"
    );
    assert!(
        dark_moved.is_empty(),
        "a frame of a Dark route's generation changed it: {dark_moved:?}"
    );
}

/// A retirement frame of the held generation whose epoch is below the held epoch darkens the route at the held
/// epoch, from a Candidate, a Bound and a Conflict route; the Dark route then keeps that epoch against every
/// later frame of its generation, a retirement at a lower or a higher epoch included.
#[test]
fn a_lower_epoch_retirement_of_the_held_generation_darkens_at_the_held_epoch() {
    let candidate = fold(None, &[frame(2, 6, 0xA1, FrameKind::Candidate)]);
    let bound = fold(None, &[frame(2, 6, 0xA1, FrameKind::Ready)]);
    let conflict = fold(
        None,
        &[
            frame(2, 6, 0xA1, FrameKind::Ready),
            frame(2, 6, 0xB2, FrameKind::Candidate),
        ],
    );
    let held = [candidate[0], bound[0], conflict[1]];
    let kinds = (
        matches!(held[0], HighWater::Candidate(_)),
        matches!(held[1], HighWater::Bound(_)),
        matches!(held[2], HighWater::Conflict { .. }),
    );
    let retirement = frame(2, 2, 0xB2, FrameKind::Retired);
    let darkened = held.map(|route| HighWater::merge(Some(route), retirement));
    let later = [
        frame(2, 0, 0xA1, FrameKind::Retired),
        frame(2, 2, 0xA1, FrameKind::Retired),
        frame(2, 8, 0xA1, FrameKind::Retired),
        frame(2, 8, 0xA1, FrameKind::Ready),
        frame(2, 8, 0xB2, FrameKind::Candidate),
        frame(2, 8, 0xB2, FrameKind::Invalid),
        frame(1, 8, 0xA1, FrameKind::Ready),
    ];
    let kept = fold(Some(dark(2, 6)), &later);

    assert_eq!(kinds, (true, true, true), "the three held routes: {held:?}");
    assert_eq!(
        darkened,
        [dark(2, 6); 3],
        "the held generation darkens at the larger epoch, the held one"
    );
    assert_eq!(
        kept,
        [dark(2, 6); 7],
        "a Dark route keeps the epoch it recorded"
    );
}

/// The other two retirements: a retirement of the held generation at a higher epoch darkens at
/// the frame's epoch, and a retirement of a later generation darkens that generation at the frame's epoch, so
/// neither lowers the pair.
#[test]
fn a_higher_retirement_darkens_at_its_own_epoch() {
    let held = fold(None, &[frame(2, 2, 0xA1, FrameKind::Ready)])[0];
    let same = HighWater::merge(Some(held), frame(2, 6, 0xB2, FrameKind::Retired));
    let later = HighWater::merge(Some(held), frame(3, 0, 0xB2, FrameKind::Retired));
    assert_eq!((same, later), (dark(2, 6), dark(3, 0)));
}

/// A frame of an earlier generation with a higher epoch leaves the route as it is, whatever the frame's kind and
/// whatever the route holds: generation orders ahead of the epoch.
#[test]
fn a_frame_of_an_earlier_generation_with_a_higher_epoch_keeps_the_route() {
    let held = [
        fold(None, &[frame(2, 2, 0xA1, FrameKind::Candidate)])[0],
        fold(None, &[frame(2, 2, 0xA1, FrameKind::Ready)])[0],
        fold(
            None,
            &[
                frame(2, 2, 0xA1, FrameKind::Candidate),
                frame(2, 2, 0xB2, FrameKind::Candidate),
            ],
        )[1],
        fold(None, &[frame(2, 2, 0xA1, FrameKind::Retired)])[0],
    ];
    let mut moved = Vec::new();
    for route in held {
        for kind in KINDS {
            for host in HOSTS {
                let earlier = frame(1, 6, host, kind);
                let new = HighWater::merge(Some(route), earlier);
                if new != route {
                    moved.push((route, earlier, new));
                }
            }
        }
    }
    assert!(
        moved.is_empty(),
        "an earlier generation moved the route: {moved:?}"
    );
}
