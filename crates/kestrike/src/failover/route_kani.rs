//! Kani proof of one step of the client route's merge in `route`: for
//! every route and every authenticated frame,
//! [`HighWater::merge`](super::route::HighWater::merge) never lowers the
//! `(g, a)` high-water, turns an equal `(g, a)` from another host into a
//! conflict, leaves a conflict only for a higher tenure or a retirement of
//! the held or a later generation, and leaves a Dark route unchanged for
//! every frame of its generation or an earlier one. Monotonicity over a
//! sequence of frames follows by induction on this one step; Kani checks
//! the step alone.
//!
//! Bounds: the proof is loop-free and runs at Kani's default unwinding. A
//! route is absent or one of its four variants. Each tenure has a symbolic
//! nonzero `u32` generation, a symbolic even epoch up to
//! [`ActivatedEpoch::MAX`](crate::net::ownership::ActivatedEpoch::MAX) and
//! a symbolic nonzero 16-byte host. The frame is one of its four kinds.

#[cfg(kani)]
mod verification {
    use super::super::identity::Exhid;
    use super::super::route::{FrameKind, HighWater, HolderFrame};
    use crate::net::ownership::{ActivatedEpoch, ShardGeneration, Tenure};

    fn generation() -> ShardGeneration {
        let value: u32 = kani::any();
        kani::assume(value != 0);
        ShardGeneration::new(u64::from(value)).unwrap()
    }

    fn epoch() -> ActivatedEpoch {
        let value: u32 = kani::any();
        kani::assume(value.is_multiple_of(2) && value <= ActivatedEpoch::MAX);
        ActivatedEpoch::new(value).unwrap()
    }

    fn tenure() -> Tenure {
        let host: [u8; 16] = kani::any();
        kani::assume(host != [0; 16]);
        Tenure {
            generation: generation(),
            epoch: epoch(),
            host: Exhid::new(host).unwrap(),
        }
    }

    fn route() -> HighWater {
        match kani::any::<u8>() % 4 {
            0 => HighWater::Candidate(tenure()),
            1 => HighWater::Bound(tenure()),
            2 => HighWater::Conflict {
                generation: generation(),
                epoch: epoch(),
            },
            _ => HighWater::Dark {
                generation: generation(),
                epoch: epoch(),
            },
        }
    }

    fn kind() -> FrameKind {
        match kani::any::<u8>() % 4 {
            0 => FrameKind::Candidate,
            1 => FrameKind::Ready,
            2 => FrameKind::Retired,
            _ => FrameKind::Invalid,
        }
    }

    fn pair(generation: ShardGeneration, epoch: ActivatedEpoch) -> (u64, u32) {
        (generation.get(), epoch.get())
    }

    fn order(route: HighWater) -> (u64, u32) {
        pair(route.generation(), route.epoch())
    }

    /// Over one symbolic route, absent or present, and one symbolic frame of any kind: the merged route's `(g, a)`
    /// is at least the held one; a Candidate or Bound route meeting a Candidate or READY frame at its `(g, a)` from
    /// another host becomes a Conflict at that `(g, a)`; a Conflict ends only at a higher frame `(g, a)` or a
    /// retirement of its generation or a later one; and a Dark route keeps itself for every frame of its generation
    /// or an earlier one.
    #[kani::proof]
    fn the_high_water_never_decreases_and_conflict_clears_only_above_it() {
        let current = kani::any::<bool>().then(route);
        let frame = HolderFrame {
            tenure: tenure(),
            kind: kind(),
        };
        let merged = HighWater::merge(current, frame);
        let frame_key = pair(frame.tenure.generation, frame.tenure.epoch);
        kani::cover!(current.is_none() && matches!(merged, HighWater::Dark { .. }));
        kani::cover!(
            matches!(current, Some(HighWater::Candidate(_)))
                && matches!(merged, HighWater::Conflict { .. })
        );
        kani::cover!(
            matches!(current, Some(HighWater::Bound(_)))
                && frame.kind == FrameKind::Invalid
                && matches!(merged, HighWater::Candidate(_))
                && current.map(order) == Some(frame_key)
        );
        kani::cover!(
            matches!(current, Some(HighWater::Conflict { .. }))
                && matches!(merged, HighWater::Bound(_))
        );
        kani::cover!(
            matches!(current, Some(HighWater::Conflict { .. }))
                && matches!(merged, HighWater::Dark { .. })
        );
        kani::cover!(
            matches!(current, Some(HighWater::Dark { .. }))
                && matches!(merged, HighWater::Bound(_))
        );
        kani::cover!(
            matches!(current, Some(HighWater::Bound(_)))
                && current.is_some_and(|old| frame_key < order(old))
                && merged == current.unwrap()
        );
        let Some(old) = current else {
            return;
        };
        assert!(order(merged) >= order(old));
        if let HighWater::Candidate(held) | HighWater::Bound(held) = old
            && matches!(frame.kind, FrameKind::Candidate | FrameKind::Ready)
            && frame_key == order(old)
            && frame.tenure.host != held.host
        {
            assert_eq!(
                merged,
                HighWater::Conflict {
                    generation: held.generation,
                    epoch: held.epoch,
                }
            );
        }
        if let HighWater::Conflict { generation, .. } = old
            && !matches!(merged, HighWater::Conflict { .. })
        {
            assert!(
                frame_key > order(old)
                    || (frame.kind == FrameKind::Retired && frame.tenure.generation >= generation)
            );
        }
        if let HighWater::Dark { generation, .. } = old
            && frame.tenure.generation <= generation
        {
            assert_eq!(merged, old);
        }
    }
}
