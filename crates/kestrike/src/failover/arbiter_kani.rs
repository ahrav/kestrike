//! Kani proof of [`nominate`](super::arbiter::nominate) over one call with zero to two votes:
//!
//! - A nomination names the `(g, owner, E)` its observation was opened for.
//! - `nominate` declines when the suspicion's observation generation differs from the observation's generation.
//! - A nomination has valid bounds, a healthy observer, a suspicion stamped at or before `now`, a holder past its
//!   grace, votes that are each `Dead` and in round, and a trusted clock sampled at most `clock_age` before `now`.
//! - A vote counts when its reading is `Dead`, its generation matches the observation's generation, and its stamp
//!   is at or before `now`. A nomination has counted votes in at least `k` distinct partitions.
//! - A nomination under a gray suspicion or a counted gray reading has counted votes of two observer classes, and a
//!   nomination whose counted votes come from one observer class has a suspicion and counted readings that are each
//!   silent or declared. The suspicion and each vote range over all three failure kinds independently.
//!
//! Bounds: the vote list holds zero to two votes, and the proof runs at an unwinding of 4, which unwinds every
//! loop over that list in full. Every count, stamp, round, partition, class and generation is a symbolic integer of
//! its field's full width; the target's generation and owner are symbolic nonzero values the constructors admit.

#[cfg(kani)]
mod verification {
    use super::super::arbiter::{
        ArbiterBounds, Clock, Decline, Nomination, Observation, ObserverClass, Partition, Vote,
        nominate,
    };
    use super::super::detect::{Failure, Liveness, ObservationGeneration, Suspicion};
    use super::super::records::Host;
    use super::super::retire::Target;
    use crate::net::ownership::ShardGeneration;

    /// The longest vote list the proof covers.
    const VOTES: usize = 2;

    fn suspicion() -> Suspicion {
        Suspicion {
            generation: ObservationGeneration(kani::any()),
            failure: match kani::any::<u8>() % 3 {
                0 => Failure::Silent,
                1 => Failure::Gray,
                _ => Failure::Declared,
            },
            since: kani::any(),
        }
    }

    fn vote() -> Vote {
        let reading = match kani::any::<u8>() % 3 {
            0 => Liveness::Alive,
            1 => Liveness::Unknown,
            _ => Liveness::Dead(suspicion()),
        };
        Vote {
            partition: Partition(kani::any()),
            class: ObserverClass(kani::any()),
            round: kani::any(),
            reading,
        }
    }

    /// Over one symbolic call: an `Ok` carries the observation's target, bounds that validate, a healthy observer,
    /// a suspicion of the observation's generation stamped at or before `now`, a holder past its grace, one to
    /// `hosts` votes that are each `Dead` and in round, and a trusted clock sampled at most `clock_age` before
    /// `now`. A suspicion of another generation never nominates, and under valid bounds and a healthy observer its
    /// decline is `StaleSuspicion`. A nomination on one observer class reads no gray evidence; the covers reach a
    /// one-class nomination under a declared suspicion and the gray refusal of mixed declared and gray evidence with
    /// the gray kind local and with it counted. Bounds: zero to two votes, an unwinding of 4, one call.
    #[kani::proof]
    #[kani::unwind(4)]
    fn a_nomination_names_its_observation_target_and_follows_every_decline() {
        let bounds = ArbiterBounds {
            h: kani::any(),
            holder_grace: kani::any(),
            k: kani::any(),
            rounds: kani::any(),
            clock_age: kani::any(),
            dwell: kani::any(),
            hosts: kani::any(),
        };
        let generation = ShardGeneration::new(kani::any());
        let owner = Host::new(kani::any());
        kani::assume(generation.is_some() && owner.is_some());
        let target = Target {
            generation: generation.unwrap(),
            owner: owner.unwrap(),
            attempts: kani::any(),
        };
        let observation = Observation {
            generation: ObservationGeneration(kani::any()),
            target,
        };
        let votes = [vote(), vote()];
        let len: usize = kani::any();
        kani::assume(len <= VOTES);
        let clock = if kani::any() {
            Clock::Trusted {
                sampled_at: kani::any(),
            }
        } else {
            Clock::Untrusted
        };
        let nomination = Nomination {
            now: kani::any(),
            observer_healthy: kani::any(),
            observation,
            suspicion: suspicion(),
            holder_since: kani::any(),
            votes: &votes[..len],
            clock,
        };
        let result = nominate(&bounds, &nomination);
        let stale = nomination.suspicion.generation != observation.generation;
        let counts = |vote: &Vote| {
            matches!(vote.reading, Liveness::Dead(s)
                if s.generation == observation.generation && s.since <= nomination.now)
        };
        let reads_gray = |vote: &Vote| {
            counts(vote) && matches!(vote.reading, Liveness::Dead(s) if s.failure == Failure::Gray)
        };
        let reads_declared = |vote: &Vote| {
            counts(vote)
                && matches!(vote.reading, Liveness::Dead(s) if s.failure == Failure::Declared)
        };
        let local = nomination.suspicion.failure;
        let gray_vote =
            (len >= 1 && reads_gray(&votes[0])) || (len == VOTES && reads_gray(&votes[1]));
        let declared_vote =
            (len >= 1 && reads_declared(&votes[0])) || (len == VOTES && reads_declared(&votes[1]));
        let gray = local == Failure::Gray || gray_vote;
        let one_class = !(len == VOTES
            && counts(&votes[0])
            && counts(&votes[1])
            && votes[0].class != votes[1].class);
        kani::cover!(result.is_ok() && len == VOTES);
        kani::cover!(result.is_ok() && gray);
        kani::cover!(result == Err(Decline::StaleSuspicion) && stale);
        kani::cover!(result == Err(Decline::StaleSuspicion) && !stale);
        kani::cover!(result == Err(Decline::Quorum));
        kani::cover!(result == Err(Decline::GrayNeedsSecondClass));
        kani::cover!(result.is_ok() && local == Failure::Declared && one_class);
        kani::cover!(result.is_ok() && declared_vote && len == VOTES && one_class);
        kani::cover!(
            result == Err(Decline::GrayNeedsSecondClass) && local == Failure::Gray && declared_vote
        );
        kani::cover!(
            result == Err(Decline::GrayNeedsSecondClass) && local == Failure::Declared && gray_vote
        );
        // "a retracked generation declines stale evidence"
        if stale {
            assert!(result.is_err());
            if bounds.validate().is_ok() && nomination.observer_healthy {
                assert_eq!(result, Err(Decline::StaleSuspicion));
            }
        }
        if let Ok(nominated) = result {
            // "a nomination names the (g, owner, E) its observation was opened for"
            assert_eq!(nominated.target, target);
            // "every decline precedes the nomination": each assertion below excludes one decline.
            assert!(bounds.validate().is_ok());
            assert!(nomination.observer_healthy);
            assert!(nomination.suspicion.since <= nomination.now);
            assert!(nomination.holder_since <= nomination.now);
            assert!(nomination.now - nomination.holder_since > bounds.holder_grace);
            assert!((1..=bounds.hosts).contains(&len));
            for vote in &votes[..len] {
                assert!(matches!(vote.reading, Liveness::Dead(_)));
                assert!(vote.round >= 1 && vote.round <= bounds.rounds);
            }
            match clock {
                Clock::Trusted { sampled_at } => {
                    assert!(sampled_at <= nomination.now);
                    assert!(nomination.now - sampled_at <= bounds.clock_age);
                }
                Clock::Untrusted => panic!("an untrusted clock nominated"),
            }
            let first = len >= 1 && counts(&votes[0]);
            let second = len == VOTES && counts(&votes[1]);
            let distinct = usize::from(first)
                + usize::from(second && !(first && votes[0].partition == votes[1].partition));
            assert!(distinct >= bounds.k);
            if gray {
                assert!(first && second && votes[0].class != votes[1].class);
            }
            // "a nomination whose counted votes come from one observer class has a suspicion and counted readings
            // that are each silent or declared"
            if one_class {
                assert!(local != Failure::Gray && !gray_vote);
            }
        }
    }
}
