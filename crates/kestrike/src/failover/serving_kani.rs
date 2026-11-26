//! Kani proof of the serving gate in `serving`: for every
//! [`Standing`](super::serving::Standing),
//! operation, submitted token, status, metadata kind and time,
//! [`admit`](super::serving::admit), [`retry`](super::serving::retry) and
//! [`admit_metadata`](super::serving::admit_metadata) return what a reference
//! predicate returns, refusal variant and payload included, and every
//! admission of `admit` and `admit_metadata` holds the conditions it
//! implies, asserted without the reference; a `retry` admission equals an
//! `admit` admission through the reference. A control harness shows that
//! each of five wrong gates, the production gate given its input with one
//! field changed, admits an input the reference refuses.
//!
//! Bounds: the proof is loop-free and runs at Kani's default unwinding. Each
//! token field takes every value its constructor admits and the lineage is
//! any `u32`. Each window bound is absent or any `u64`; the state, the held
//! token's presence, the fill latch, the withhold, the operation with any
//! reply lineage, the `u16` status, the metadata kind and the `u64` time are
//! unconstrained. The domain includes standings no machine reaches, such as
//! `Serving` with no token or a window with one bound.

#[cfg(kani)]
mod verification {
    use super::super::identity::{Epoch, Exhid, Incarnation, Key};
    use super::super::serving::{
        Denial, MetadataKind, Operation, Outcome, Rejection, Standing, State, Token, admit,
        admit_metadata, retry,
    };
    use crate::net::ownership::{ActivatedEpoch, Shard, ShardGeneration};

    fn token() -> Token {
        let shard: u32 = kani::any();
        kani::assume(shard != 0);
        let generation: u64 = kani::any();
        kani::assume(generation != 0 && generation <= u64::from(u32::MAX));
        let epoch: u32 = kani::any();
        kani::assume(epoch.is_multiple_of(2) && epoch <= ActivatedEpoch::MAX);
        let exhid: [u8; 16] = kani::any();
        kani::assume(exhid != [0; 16]);
        let key_epoch: u32 = kani::any();
        kani::assume(key_epoch != 0 && key_epoch != u32::MAX);
        let incarnation: u32 = kani::any();
        kani::assume(incarnation != 0 && incarnation != u32::MAX);
        Token {
            shard: Shard::new(shard).unwrap(),
            generation: ShardGeneration::new(generation).unwrap(),
            epoch: ActivatedEpoch::new(epoch).unwrap(),
            exhid: Exhid::new(exhid).unwrap(),
            key: Key::new(
                Epoch::new(key_epoch).unwrap(),
                Incarnation::new(incarnation).unwrap(),
            ),
            lineage: kani::any(),
        }
    }

    fn state() -> State {
        let state = match kani::any::<u8>() % 5 {
            0 => State::PreBoundary,
            1 => State::Recovering,
            2 => State::Serving,
            3 => State::Withdrawn,
            _ => State::Closed,
        };
        // A new variant fails to compile here; the selector above then needs an arm for it.
        match state {
            State::PreBoundary
            | State::Recovering
            | State::Serving
            | State::Withdrawn
            | State::Closed => state,
        }
    }

    fn standing() -> Standing {
        Standing {
            state: state(),
            token: kani::any::<bool>().then(token),
            window_start: kani::any(),
            window_end: kani::any(),
            fills: kani::any(),
            withheld: kani::any(),
        }
    }

    fn operation() -> Operation {
        let operation = match kani::any::<u8>() % 4 {
            0 => Operation::Get,
            1 => Operation::Read,
            2 => Operation::Fill,
            _ => Operation::Reply {
                lineage: kani::any(),
            },
        };
        // A new variant fails to compile here; the selector above then needs an arm for it.
        match operation {
            Operation::Get | Operation::Read | Operation::Fill | Operation::Reply { .. } => {
                operation
            }
        }
    }

    fn kind() -> MetadataKind {
        let kind = match kani::any::<u8>() % 3 {
            0 => MetadataKind::CheckpointUnit,
            1 => MetadataKind::CheckpointRoot,
            _ => MetadataKind::ResetRoot,
        };
        // A new variant fails to compile here; the selector above then needs an arm for it.
        match kind {
            MetadataKind::CheckpointUnit
            | MetadataKind::CheckpointRoot
            | MetadataKind::ResetRoot => kind,
        }
    }

    /// Whether the two tokens agree in all six fields, compared through the values the field accessors return and the
    /// lineage value.
    fn same_fields(held: Token, submitted: Token) -> bool {
        held.shard.get() == submitted.shard.get()
            && held.generation.get() == submitted.generation.get()
            && held.epoch.get() == submitted.epoch.get()
            && held.exhid.bytes() == submitted.exhid.bytes()
            && held.key.encode() == submitted.key.encode()
            && held.lineage == submitted.lineage
    }

    /// The first failing condition of the token and window rule: the submitted token equals the held one, the
    /// window has no start or has started at or before `now`, and both bounds are present with `now` before the end.
    fn authority_refusal(standing: Standing, submitted: Token, now: u64) -> Option<Denial> {
        let matches = match standing.token {
            Some(held) => same_fields(held, submitted),
            None => false,
        };
        let started = match standing.window_start {
            Some(start) => start <= now,
            None => true,
        };
        let open = match (standing.window_start, standing.window_end) {
            (Some(_), Some(end)) => now < end,
            _ => false,
        };
        if !matches {
            Some(Denial::TokenMismatch)
        } else if !started {
            Some(Denial::WindowNotStarted)
        } else if !open {
            Some(Denial::WindowExpired)
        } else {
            None
        }
    }

    /// The operation gate's rule: `Serving` with a held token, then the token and window rule, then the
    /// operation's own condition; an admission returns the submitted token.
    fn reference(
        standing: Standing,
        operation: Operation,
        submitted: Token,
        now: u64,
    ) -> Result<Token, Denial> {
        let serving = standing.state == State::Serving && standing.token.is_some();
        let own = match operation {
            Operation::Get => standing.withheld.then_some(Denial::Withheld),
            Operation::Read => None,
            Operation::Fill => (!standing.fills).then_some(Denial::FillsNotAdmitted),
            Operation::Reply { lineage } => {
                (lineage != submitted.lineage).then_some(Denial::StaleLineage {
                    lineage,
                    current: submitted.lineage,
                })
            }
        };
        if !serving {
            return Err(Denial::NotServing(standing.state));
        }
        match authority_refusal(standing, submitted, now).or(own) {
            Some(denial) => Err(denial),
            None => Ok(submitted),
        }
    }

    /// The retry gate's rule: statuses `0x83` and `0x1b` refuse before every other condition.
    fn reference_retry(
        standing: Standing,
        operation: Operation,
        status: u16,
        submitted: Token,
        now: u64,
    ) -> Result<Token, Denial> {
        if status == 0x83 || status == 0x1b {
            return Err(Denial::DeposingStatusNeverRetried(status));
        }
        reference(standing, operation, submitted, now)
    }

    /// The metadata gate's rule: `Serving` takes every kind and `Recovering` the two root kinds, then the token and
    /// window rule; an admission returns the submitted token.
    fn reference_metadata(
        standing: Standing,
        submitted: Token,
        now: u64,
        kind: MetadataKind,
    ) -> Outcome {
        let root = kind == MetadataKind::CheckpointRoot || kind == MetadataKind::ResetRoot;
        let takes =
            standing.state == State::Serving || (standing.state == State::Recovering && root);
        if !takes {
            return Outcome::Rejected(Rejection::MetadataRefused {
                state: standing.state,
                kind,
            });
        }
        match authority_refusal(standing, submitted, now) {
            Some(denial) => Outcome::Rejected(Rejection::AuthorityDenied(denial)),
            None => Outcome::Admitted(submitted),
        }
    }

    /// An admission of `submitted` at `now` implies a held token equal to it in every field and both window bounds
    /// present with `start <= now < end`.
    fn assert_held_token_and_open_window(standing: Standing, submitted: Token, now: u64) {
        assert_eq!(standing.token, Some(submitted));
        assert!(standing.window_start.is_some_and(|start| start <= now));
        assert!(standing.window_end.is_some_and(|end| now < end));
    }

    /// Over one symbolic standing, operation, submitted token, status and time: the operation gate and the retry
    /// gate each return the reference's answer, and an admission holds `Serving`, the held token, the open window
    /// and its operation's own condition.
    #[kani::proof]
    fn the_operation_gate_answers_as_the_reference_predicate() {
        let standing = standing();
        let operation = operation();
        let submitted = token();
        let status: u16 = kani::any();
        let now: u64 = kani::any();
        let admitted = admit(standing, operation, submitted, now);
        let retried = retry(standing, operation, status, submitted, now);
        kani::cover!(admitted.is_ok() && retried.is_ok());
        kani::cover!(matches!(admitted, Err(Denial::NotServing(_))));
        kani::cover!(admitted == Err(Denial::TokenMismatch));
        kani::cover!(admitted == Err(Denial::WindowNotStarted));
        kani::cover!(admitted == Err(Denial::WindowExpired));
        kani::cover!(admitted == Err(Denial::Withheld));
        kani::cover!(admitted == Err(Denial::FillsNotAdmitted));
        kani::cover!(matches!(admitted, Err(Denial::StaleLineage { .. })));
        kani::cover!(
            admitted.is_err() && matches!(retried, Err(Denial::DeposingStatusNeverRetried(_)))
        );
        assert_eq!(admitted, reference(standing, operation, submitted, now));
        assert_eq!(
            retried,
            reference_retry(standing, operation, status, submitted, now)
        );
        if admitted.is_ok() {
            assert!(standing.state == State::Serving);
            assert_held_token_and_open_window(standing, submitted, now);
            match operation {
                Operation::Get => {
                    assert!(!standing.withheld);
                }
                Operation::Read => {
                    assert_eq!(admitted, Ok(submitted));
                }
                Operation::Fill => {
                    assert!(standing.fills);
                }
                Operation::Reply { lineage } => {
                    assert_eq!(lineage, submitted.lineage);
                }
            }
        }
    }

    /// Over one symbolic standing, submitted token, time and metadata kind: the metadata gate returns the
    /// reference's answer, and an admission holds the held token, the open window and `Serving`, or `Recovering`
    /// with a root kind.
    #[kani::proof]
    fn the_metadata_gate_answers_as_the_reference_predicate() {
        let standing = standing();
        let submitted = token();
        let now: u64 = kani::any();
        let kind = kind();
        let outcome = admit_metadata(standing, submitted, now, kind);
        kani::cover!(
            standing.state == State::Serving
                && kind == MetadataKind::CheckpointUnit
                && matches!(outcome, Outcome::Admitted(_))
        );
        kani::cover!(
            standing.state == State::Recovering
                && kind == MetadataKind::ResetRoot
                && matches!(outcome, Outcome::Admitted(_))
        );
        kani::cover!(
            standing.state == State::Recovering
                && kind == MetadataKind::CheckpointUnit
                && matches!(
                    outcome,
                    Outcome::Rejected(Rejection::MetadataRefused { .. })
                )
        );
        kani::cover!(
            standing.token.is_none()
                && outcome == Outcome::Rejected(Rejection::AuthorityDenied(Denial::TokenMismatch))
        );
        assert_eq!(outcome, reference_metadata(standing, submitted, now, kind));
        if matches!(outcome, Outcome::Admitted(_)) {
            assert_held_token_and_open_window(standing, submitted, now);
            assert!(standing.state == State::Serving || standing.state == State::Recovering);
            if standing.state == State::Recovering {
                assert!(kind == MetadataKind::CheckpointRoot || kind == MetadataKind::ResetRoot);
            }
        }
    }

    /// Each planted gate admits an input that the reference rejects for the reason the plant targets. That input
    /// disproves equivalence. The plants make the window end inclusive, read an absent start as open, treat tokens
    /// that differ only in key as matching, admit operations in `Recovering`, and admit a fill before its latch is set.
    #[kani::proof]
    fn each_planted_gate_differs_from_the_reference() {
        let standing = standing();
        let operation = operation();
        let submitted = token();
        let now: u64 = kani::any();
        let expected = reference(standing, operation, submitted, now);
        let planted = |input: Standing| admit(input, operation, submitted, now);
        let inclusive_end = planted(Standing {
            window_end: standing.window_end.map(|end| end.saturating_add(1)),
            ..standing
        });
        let open_start = planted(Standing {
            window_start: standing.window_start.or(Some(0)),
            ..standing
        });
        let keyless = planted(Standing {
            token: standing.token.map(|held| Token {
                key: submitted.key,
                ..held
            }),
            ..standing
        });
        let recovering_serves = planted(Standing {
            state: match standing.state {
                State::Recovering => State::Serving,
                state => state,
            },
            ..standing
        });
        let unlatched = planted(Standing {
            fills: true,
            ..standing
        });
        kani::cover!(
            inclusive_end.is_ok()
                && expected == Err(Denial::WindowExpired)
                && standing.window_end == Some(now)
        );
        kani::cover!(open_start.is_ok() && expected == Err(Denial::WindowExpired));
        kani::cover!(keyless.is_ok() && expected == Err(Denial::TokenMismatch));
        kani::cover!(
            recovering_serves.is_ok() && expected == Err(Denial::NotServing(State::Recovering))
        );
        kani::cover!(unlatched.is_ok() && expected == Err(Denial::FillsNotAdmitted));
    }
}
