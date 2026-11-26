//! Kani proofs of four clauses of the peer detector in `detect`, each over a peer with every field symbolic; the
//! last clause has a harness of its own:
//!
//! - a heartbeat whose sequence is at or below the held sequence leaves the peer unchanged;
//! - a gap, a window closed with `observed = false`, keeps the empty and stalled counts, keeps the declared count
//!   and the suspicion unless it admitted a healthy heartbeat, which ends the count and turns a declared suspicion
//!   gray, and reports `Dead` only for a suspicion the peer already held;
//! - an observed window keeps a gray suspicion while the window saw no progress, which turns declared only in a
//!   declaring window at a declared count of at least `D`;
//! - an observed window that admitted a healthy heartbeat neither sets nor keeps a declared suspicion and reads no
//!   declared failure; an observed window adds one to the declared count exactly when it admitted a heartbeat and
//!   no healthy one, ends the count when it admitted a healthy one and keeps it when it admitted none; a suspicion
//!   turns declared only in such a declaring window at a declared count of at least `D`; a declared reading comes
//!   only from a declaring window; the peer's fresh-declaration flag is set exactly when the close leaves a
//!   declared suspicion in a declaring window with an empty count below `D`, whether or not the probe cycle is
//!   exhausted, and equals the reading of a close that is not; a set flag is a standing declaration; a
//!   declaring window keeps a silent suspicion and its exit count or relabels the suspicion declared; and a healthy
//!   heartbeat that turns a declared suspicion gray marks the suspicion while it lasts, after which the peer
//!   recovers ([`Peer::recovers`](super::Peer::recovers)) only on a gray suspicion and, outside new-peer grace,
//!   only after a window that progressed. A gap leaves no peer recovering.
//!
//! Bounds: one peer and one call per clause; `u64` times and `u32` counters, restricted only to the time order
//! `tracked_since <= window_at` and `suspicion.since <= window_at` and to a demotion mark on a gray suspicion alone,
//! which the harness also shows `Peer::new` and every window close establish; bounds that [`DetectBounds::validate`](super::DetectBounds::validate) admits; no
//! loop, so no unwinding bound applies.

#[cfg(kani)]
mod verification {
    use super::super::{DetectBounds, Failure, Liveness, ObservationGeneration, Peer, Suspicion};

    fn any_suspicion() -> Suspicion {
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

    /// What every constructor and window close leaves: tracking and a held suspicion start at or before the last
    /// close, and only a gray suspicion carries the demotion mark.
    fn anchored(peer: &Peer) -> bool {
        peer.tracked_since <= peer.window_at
            && peer
                .suspicion
                .is_none_or(|suspicion| suspicion.since <= peer.window_at)
            && (!peer.demoted
                || peer
                    .suspicion
                    .is_some_and(|suspicion| suspicion.failure == Failure::Gray))
    }

    /// A peer with every field symbolic under [`anchored`].
    fn any_peer() -> Peer {
        let peer = Peer {
            generation: ObservationGeneration(kani::any()),
            tracked_since: kani::any(),
            window_at: kani::any(),
            sequence: kani::any(),
            progress: kani::any(),
            seen: kani::any(),
            progressed: kani::any(),
            affirmed: kani::any(),
            empty: kani::any(),
            stalled: kani::any(),
            declared: kani::any(),
            declares: kani::any(),
            demoted: kani::any(),
            exit: kani::any(),
            suspicion: if kani::any() {
                Some(any_suspicion())
            } else {
                None
            },
        };
        kani::assume(anchored(&peer));
        peer
    }

    fn any_bounds() -> DetectBounds {
        let bounds = DetectBounds {
            h: kani::any(),
            d: kani::any(),
            tau: kani::any(),
            jitter: kani::any(),
            peer_grace: kani::any(),
            exit_windows: kani::any(),
            dwell: kani::any(),
            hosts: kani::any(),
        };
        kani::assume(bounds.validate().is_ok());
        bounds
    }

    /// A duplicate sequence changes nothing, an unobserved gap adds no failure evidence, and a gray suspicion does not
    /// exit on a window without progress; it stays gray or, at a declared count of at least `D`, turns declared. Each clause takes its own symbolic peer; the `anchored` assertions show
    /// the assumed time order holds again after each close and at construction.
    #[kani::proof]
    fn a_gap_adds_no_failure_evidence_a_duplicate_changes_nothing_and_gray_exit_requires_progress()
    {
        let bounds = any_bounds();

        let held = any_peer();
        let mut peer = held;
        let sequence: u64 = kani::any();
        kani::assume(held.sequence.is_some_and(|old| sequence <= old));
        peer.heartbeat(sequence, kani::any(), kani::any());
        kani::cover!(held.seen && held.sequence == Some(sequence));
        kani::cover!(!held.seen && held.empty > 0);
        assert_eq!(peer, held);

        let held = any_peer();
        let mut peer = held;
        let now: u64 = kani::any();
        let exhausted: bool = kani::any();
        let closed = peer.close(&bounds, now, false, exhausted);
        kani::cover!(closed.is_ok() && now - held.window_at > bounds.h);
        kani::cover!(matches!(closed, Ok(Liveness::Dead(_))));
        kani::cover!(closed.is_ok() && held.suspicion.is_none() && held.empty >= bounds.d);
        kani::cover!(closed.is_err());
        if let Ok(liveness) = closed {
            // A healthy heartbeat the gap admitted ends the declared count and turns a declared suspicion gray.
            let kept = held.suspicion.map(|s| match s.failure {
                Failure::Declared if held.affirmed => Suspicion {
                    failure: Failure::Gray,
                    ..s
                },
                _ => s,
            });
            let count = if held.affirmed { 0 } else { held.declared };
            assert_eq!(
                (peer.empty, peer.stalled, peer.declared, peer.suspicion),
                (held.empty, held.stalled, count, kept)
            );
            assert!(!matches!(liveness, Liveness::Dead(_)) || held.suspicion.is_some());
            // A gap resets the exit count, so no peer recovers across it.
            assert!(!peer.recovers());
        }
        assert!(anchored(&peer));

        let held = any_peer();
        let mut peer = held;
        let now: u64 = kani::any();
        kani::assume(
            held.suspicion
                .is_some_and(|suspicion| suspicion.failure == Failure::Gray),
        );
        let progressed = held.progressed;
        let closed = peer.close(&bounds, now, true, false);
        kani::cover!(closed.is_ok() && progressed && peer.suspicion.is_none());
        kani::cover!(
            closed.is_ok()
                && !progressed
                && held.exit >= bounds.exit_windows
                && held
                    .suspicion
                    .is_some_and(|s| now - s.since >= bounds.dwell)
                && now - held.tracked_since >= bounds.peer_grace
        );
        if closed.is_ok() && !progressed {
            let promoted = held.suspicion.map(|s| Suspicion {
                failure: Failure::Declared,
                ..s
            });
            assert!(
                peer.suspicion == held.suspicion
                    || (peer.suspicion == promoted
                        && peer.declared >= bounds.d
                        && held.seen
                        && !held.affirmed)
            );
        }
        assert!(anchored(&peer));

        let mut peer = any_peer();
        let _ = peer.close(&bounds, kani::any(), kani::any(), kani::any());
        assert!(anchored(&peer));
        assert!(anchored(&Peer::new(
            ObservationGeneration(kani::any()),
            kani::any()
        )));
    }

    /// An observed window that admitted a healthy heartbeat neither sets nor keeps a declared suspicion and reads no
    /// declared failure; the declared count rises by one on a window with a heartbeat and no healthy one, ends on a
    /// window with a healthy one and stays on a window with none; a suspicion turns declared only in a declaring
    /// window at a declared count of at least `D`; a declared reading comes only from a declaring window; the
    /// fresh-declaration flag follows the suspicion, the window and the empty count alone, so an exhausted close
    /// sets it as an unexhausted one does, and equals the reading where no mask applies; a set flag is a standing
    /// declaration; and a declaring window keeps a silent suspicion and its exit count unless it relabels the
    /// suspicion declared. These are clauses of one transition from a symbolic peer.
    /// One symbolic peer, one observed close, exhausted or not.
    #[kani::proof]
    fn an_observed_window_with_a_healthy_heartbeat_neither_sets_nor_keeps_a_declared_suspicion() {
        let bounds = any_bounds();
        let held = any_peer();
        let mut peer = held;
        let now: u64 = kani::any();
        let exhausted: bool = kani::any();
        let closed = peer.close(&bounds, now, true, exhausted);
        let declared = |s: Option<Suspicion>| s.is_some_and(|s| s.failure == Failure::Declared);
        let silent = |s: Option<Suspicion>| s.is_some_and(|s| s.failure == Failure::Silent);
        let reads_declared =
            matches!(closed, Ok(Liveness::Dead(s)) if s.failure == Failure::Declared);
        kani::cover!(closed.is_ok() && held.affirmed && declared(held.suspicion));
        kani::cover!(closed.is_ok() && !declared(held.suspicion) && declared(peer.suspicion));
        kani::cover!(reads_declared);
        kani::cover!(closed.is_ok() && declared(peer.suspicion) && !reads_declared);
        kani::cover!(closed.is_ok() && exhausted && peer.declares);
        kani::cover!(
            closed.is_ok()
                && silent(held.suspicion)
                && held.seen
                && !held.affirmed
                && held.exit > 0
                && silent(peer.suspicion)
        );
        kani::cover!(closed.is_ok() && declared(held.suspicion) && peer.recovers());
        if closed.is_ok() {
            // "an observed window that admitted a healthy heartbeat never sets or keeps a declared suspicion"
            if held.affirmed {
                assert!(!declared(peer.suspicion));
                assert!(!reads_declared);
            }
            let declaring = held.seen && !held.affirmed;
            assert_eq!(
                peer.declared,
                if declaring {
                    held.declared.saturating_add(1)
                } else if held.affirmed {
                    0
                } else {
                    held.declared
                }
            );
            // "a suspicion turns declared only in a declaring window at the onset count"
            if declared(peer.suspicion) && !declared(held.suspicion) {
                assert!(declaring && peer.declared >= bounds.d);
            }
            if reads_declared {
                assert!(declaring);
            }
            // The exhaustion mask changes the returned reading and leaves the flag.
            assert_eq!(
                peer.declares,
                declared(peer.suspicion) && declaring && peer.empty < bounds.d
            );
            if !exhausted {
                assert_eq!(peer.declares, reads_declared);
            }
            if peer.declares {
                assert!(peer.stands_declared(&bounds));
            }
            if silent(held.suspicion) && declaring {
                assert!(
                    declared(peer.suspicion)
                        || (peer.suspicion == held.suspicion && peer.exit == held.exit)
                );
            }
            // "a healthy heartbeat that turns a declared suspicion gray marks the suspicion while it lasts"
            if held.affirmed && declared(held.suspicion) {
                assert_eq!(peer.demoted, peer.suspicion.is_some());
            }
            // "the peer recovers only on a gray suspicion and, outside new-peer grace, only after progress"
            if peer.recovers() {
                assert!(peer.demoted && !declared(peer.suspicion));
                if now - held.tracked_since >= bounds.peer_grace {
                    assert!(held.progressed);
                }
            }
        }
        assert!(anchored(&peer));
    }
}
