use super::detect::*;

pub(super) fn bounds() -> DetectBounds {
    DetectBounds {
        h: 1,
        d: 3,
        tau: 0,
        jitter: 1,
        peer_grace: 2,
        exit_windows: 2,
        dwell: 2,
        hosts: 2,
    }
}

#[test]
fn observer_pause_duplicates_grace_and_exhaustion_contribute_no_dead_evidence() {
    let b = bounds();
    let mut p = Peer::new(ObservationGeneration(1), 0);
    assert_eq!(p.window(&b, 1, true, false), Ok(Liveness::Alive));
    assert_eq!(p.window(&b, 50, false, false), Ok(Liveness::Alive));
    p.heartbeat(1, 1, true);
    assert_eq!(p.window(&b, 51, true, false), Ok(Liveness::Alive));
    let unchanged = p;
    p.heartbeat(1, 2, true);
    assert_eq!(p, unchanged);
    assert_eq!(p.window(&b, 52, true, false), Ok(Liveness::Alive));
    assert_eq!(p.window(&b, 53, true, false), Ok(Liveness::Alive));
    assert_eq!(p.window(&b, 54, true, true), Ok(Liveness::Unknown));
    assert!(matches!(
        p.window(&b, 55, true, false),
        Ok(Liveness::Dead(Suspicion {
            generation: ObservationGeneration(1),
            failure: Failure::Silent,
            since: 54,
        }))
    ));
    let mut grace = b;
    grace.peer_grace = 10;
    let mut p = Peer::new(ObservationGeneration(2), 0);
    for t in 1..10 {
        assert_eq!(p.window(&grace, t, true, false), Ok(Liveness::Alive));
    }
    assert!(matches!(
        p.window(&grace, 10, true, false),
        Ok(Liveness::Dead(_))
    ));
}

#[test]
fn failing_reads_d_empty_or_stalled_windows_with_or_without_a_suspicion() {
    let mut grace = bounds();
    grace.peer_grace = 10;
    for stalled in [false, true] {
        let mut p = Peer::new(ObservationGeneration(1), 0);
        // Each window of the stalled peer holds a heartbeat with flat progress; the first sample counts as progress.
        p.heartbeat(1, 1, true);
        assert_eq!(p.window(&grace, 1, true, false), Ok(Liveness::Alive));
        for t in 2..=3 {
            if stalled {
                p.heartbeat(t, 1, true);
            }
            assert_eq!(p.window(&grace, t, true, false), Ok(Liveness::Alive));
            assert!(!p.failing(&grace), "{stalled} at {t}: below D");
        }
        if stalled {
            p.heartbeat(4, 1, true);
        }
        assert_eq!(p.window(&grace, 4, true, false), Ok(Liveness::Alive));
        assert!(p.failing(&grace), "{stalled}: D windows inside grace");
        assert_eq!(p.window(&grace, 50, false, false), Ok(Liveness::Alive));
        assert!(
            p.failing(&grace),
            "{stalled}: an unobserved close past the grace keeps the counters and sets no suspicion"
        );
        if stalled {
            p.heartbeat(5, 1, true);
        }
        assert!(matches!(
            p.window(&grace, 51, true, false),
            Ok(Liveness::Dead(_))
        ));
        assert!(p.failing(&grace), "{stalled}: the suspicion is set");
        p.heartbeat(9, 9, true);
        assert!(!p.failing(&grace), "{stalled}: a heartbeat with progress");
    }
}

#[test]
fn stalled_progress_preserves_gray_suspicion_and_exit_requires_windows_and_dwell() {
    let mut b = bounds();
    b.dwell = 4;
    let mut p = Peer::new(ObservationGeneration(1), 0);
    for t in 1..=4 {
        p.heartbeat(t, 1, true);
        p.window(&b, t, true, false).unwrap();
    }
    for t in 5..=6 {
        p.heartbeat(t, 1, true);
        assert!(matches!(
            p.window(&b, t, true, false),
            Ok(Liveness::Dead(Suspicion {
                failure: Failure::Gray,
                since: 4,
                ..
            }))
        ));
    }
    p.heartbeat(7, 2, true);
    assert!(matches!(
        p.window(&b, 7, true, false),
        Ok(Liveness::Dead(_))
    ));
    p.heartbeat(8, 3, true);
    assert_eq!(p.window(&b, 8, true, false), Ok(Liveness::Alive));
}

#[test]
fn detector_bounds_peer_limit_and_time_refuse_by_name() {
    let b = bounds();
    for (bad, refusal) in [
        (DetectBounds { h: 0, ..b }, DetectRefusal::Window),
        (DetectBounds { d: 1, ..b }, DetectRefusal::Threshold),
        (DetectBounds { jitter: 2, ..b }, DetectRefusal::Timing),
        (DetectBounds { h: u64::MAX, ..b }, DetectRefusal::Timing),
        (DetectBounds { peer_grace: 0, ..b }, DetectRefusal::Grace),
        (
            DetectBounds {
                exit_windows: 0,
                ..b
            },
            DetectRefusal::Exit,
        ),
        (DetectBounds { dwell: 0, ..b }, DetectRefusal::Dwell),
        (DetectBounds { hosts: 0, ..b }, DetectRefusal::Hosts),
    ] {
        assert_eq!(bad.validate().unwrap_err(), refusal);
    }
    assert!(matches!(
        Detector::new(DetectBounds {
            hosts: usize::MAX,
            ..b
        }),
        Err(DetectRefusal::Allocation)
    ));
    let mut table = Detector::new(b).unwrap();
    let first = table.track(ObservationGeneration(1), 0).unwrap();
    let second = table.track(ObservationGeneration(2), 0).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        table.track(ObservationGeneration(3), 0),
        Err(DetectRefusal::PeerLimit)
    );
    assert_eq!(table.heartbeat(first, 1, 1, true), Some(()));
    let old = *table.peer(first).unwrap();
    assert_eq!(
        table.window(first, 0, true, false),
        Some(Err(DetectRefusal::Time))
    );
    assert_eq!(*table.peer(first).unwrap(), old);
    assert_eq!(
        table.window(first, 3, true, false),
        Some(Err(DetectRefusal::Time))
    );
    assert_eq!(*table.peer(first).unwrap(), old);
    assert_eq!(
        table.retrack(first, ObservationGeneration(1), 1),
        Some(Err(DetectRefusal::Time))
    );
    assert_eq!(*table.peer(first).unwrap(), old);
    assert_eq!(
        table.retrack(first, ObservationGeneration(2), 1),
        Some(Ok(()))
    );
    assert_eq!(
        table.window(first, 2, true, false),
        Some(Ok(Liveness::Alive))
    );
    assert_eq!(
        table.peer(second).copied(),
        Some(Peer::new(ObservationGeneration(2), 0))
    );
}

#[test]
fn observer_gaps_preserve_failure_counts_and_break_exit_progress() {
    let b = bounds();
    let mut p = Peer::new(ObservationGeneration(1), 0);
    assert_eq!(p.window(&b, 1, true, false), Ok(Liveness::Alive));
    assert_eq!(p.window(&b, 50, false, false), Ok(Liveness::Alive));
    let before = p;
    assert_eq!(p.window(&b, 50, false, false), Err(DetectRefusal::Time));
    assert_eq!(p, before);
    assert_eq!(p.window(&b, 51, true, false), Ok(Liveness::Alive));
    assert_eq!(
        p.window(&b, 52, true, false),
        Ok(Liveness::Dead(Suspicion {
            generation: ObservationGeneration(1),
            failure: Failure::Silent,
            since: 52
        }))
    );
    p.heartbeat(1, 1, true);
    assert!(matches!(
        p.window(&b, 53, true, false),
        Ok(Liveness::Dead(_))
    ));
    p.window(&b, 60, false, false).unwrap();
    p.heartbeat(2, 2, true);
    assert!(matches!(
        p.window(&b, 61, true, false),
        Ok(Liveness::Dead(_))
    ));
    p.heartbeat(3, 3, true);
    assert_eq!(p.window(&b, 62, true, false), Ok(Liveness::Alive));
}

fn gray(b: &DetectBounds) -> Peer {
    let mut p = Peer::new(ObservationGeneration(1), 0);
    for t in 1..=4 {
        p.heartbeat(t, 1, true);
        p.window(b, t, true, false).unwrap();
    }
    p
}

#[test]
fn suspicion_exit_needs_progress_exit_count_and_dwell_independently() {
    let b = bounds();
    let mut p = gray(&b);
    for t in 5..=7 {
        p.heartbeat(t, 1, true);
        assert!(matches!(
            p.window(&b, t, true, false),
            Ok(Liveness::Dead(_))
        ));
    }
    p.heartbeat(8, 2, true);
    assert!(matches!(
        p.window(&b, 8, true, false),
        Ok(Liveness::Dead(_))
    ));
    p.heartbeat(9, 3, true);
    assert_eq!(p.window(&b, 9, true, false), Ok(Liveness::Alive));
    let long = DetectBounds { dwell: 4, ..b };
    let mut p = gray(&long);
    for t in 5..=7 {
        p.heartbeat(t, t, true);
        assert!(matches!(
            p.window(&long, t, true, false),
            Ok(Liveness::Dead(_))
        ));
    }
    p.heartbeat(8, 8, true);
    assert_eq!(p.window(&long, 8, true, false), Ok(Liveness::Alive));
}

#[test]
fn gray_reports_silence_and_silent_recovery_keeps_stalled_progress_suspected() {
    let b = bounds();
    let mut p = gray(&b);
    for t in 5..=6 {
        assert!(matches!(
            p.window(&b, t, true, false),
            Ok(Liveness::Dead(Suspicion {
                failure: Failure::Gray,
                ..
            }))
        ));
    }
    assert_eq!(
        p.window(&b, 7, true, false),
        Ok(Liveness::Dead(Suspicion {
            generation: ObservationGeneration(1),
            failure: Failure::Silent,
            since: 4
        }))
    );
    let mut silent = Peer::new(ObservationGeneration(1), 0);
    for t in 1..=3 {
        silent.window(&b, t, true, false).unwrap();
    }
    silent.heartbeat(1, 1, true);
    assert!(matches!(
        silent.window(&b, 4, true, false),
        Ok(Liveness::Dead(_))
    ));
    silent.heartbeat(2, 1, true);
    assert_eq!(silent.window(&b, 5, true, false), Ok(Liveness::Alive));
    let mut stalled = Peer::new(ObservationGeneration(1), 0);
    for t in 1..=4 {
        stalled.window(&b, t, true, false).unwrap();
    }
    stalled.heartbeat(1, 1, true);
    stalled.window(&b, 5, true, false).unwrap();
    for t in 6..=8 {
        stalled.window(&b, t, true, false).unwrap();
    }
    for t in 9..=10 {
        stalled.heartbeat(t, 1, true);
        assert_eq!(
            stalled.window(&b, t, true, false),
            Ok(Liveness::Dead(Suspicion {
                generation: ObservationGeneration(1),
                failure: if t == 9 {
                    Failure::Silent
                } else {
                    Failure::Gray
                },
                since: 3,
            }))
        );
    }
}

#[test]
fn first_zero_heartbeat_and_same_boot_retrack_preserve_high_water() {
    let b = bounds();
    let mut p = Peer::new(ObservationGeneration(1), 0);
    let fresh = p;
    p.heartbeat(0, 0, true);
    assert_ne!(p, fresh);
    let once = p;
    p.heartbeat(0, 1, true);
    assert_eq!(p, once);
    p.heartbeat(7, 4, true);
    p.window(&b, 1, true, false).unwrap();
    p.retrack(ObservationGeneration(2), 1).unwrap();
    let before = p;
    p.heartbeat(7, 99, true);
    assert_eq!(p, before);
    assert_eq!(
        p.retrack(ObservationGeneration(1), 2),
        Err(DetectRefusal::Time)
    );
    assert_eq!(
        p.retrack(ObservationGeneration(3), 0),
        Err(DetectRefusal::Time)
    );
    for t in 2..=4 {
        p.window(&b, t, true, false).unwrap();
    }
    assert!(matches!(
        p.window(&b, 5, true, false),
        Ok(Liveness::Dead(Suspicion {
            generation: ObservationGeneration(2),
            ..
        }))
    ));
    let mut table = Detector::new(b).unwrap();
    let slot = table.track(ObservationGeneration(1), 0).unwrap();
    assert_eq!(
        table.window(slot, 1, true, false),
        Some(Ok(Liveness::Alive))
    );
    assert_eq!(table.untrack(slot), Some(()));
    assert_eq!(table.window(slot, 2, true, false), None);
}

#[test]
fn table_windows_match_peer_windows_under_the_construction_bounds() {
    let b = bounds();
    let mut table = Detector::new(b).unwrap();
    let index = table.track(ObservationGeneration(1), 0).unwrap();
    let mut peer = Peer::new(ObservationGeneration(1), 0);
    let mut last = Ok(Liveness::Alive);
    for (t, observed) in [(1, true), (3, false), (4, true), (5, true), (6, true)] {
        last = peer.window(&b, t, observed, false);
        assert_eq!(table.window(index, t, observed, false), Some(last));
    }
    assert!(matches!(last, Ok(Liveness::Dead(_))));
    assert_eq!(table.peer(index).copied(), Some(peer));
    assert_eq!(
        table.window(index, 6, true, false),
        Some(Err(DetectRefusal::Time))
    );
}

#[test]
fn a_full_table_observes_a_rebooted_host_in_its_slot() {
    let b = bounds();
    let mut table = Detector::new(b).unwrap();
    let a = table.track(ObservationGeneration(1), 0).unwrap();
    table.track(ObservationGeneration(1), 0).unwrap();
    table.heartbeat(a, 5, 3, true);
    assert_eq!(table.window(a, 1, true, false), Some(Ok(Liveness::Alive)));
    assert_eq!(
        table.track(ObservationGeneration(2), 1),
        Err(DetectRefusal::PeerLimit)
    );
    let old = *table.peer(a).unwrap();
    for (generation, now) in [(1, 1), (2, 0)] {
        assert_eq!(
            table.reboot(a, ObservationGeneration(generation), now),
            Some(Err(DetectRefusal::Time))
        );
        assert_eq!(*table.peer(a).unwrap(), old);
    }
    assert_eq!(table.reboot(a, ObservationGeneration(2), 1), Some(Ok(())));
    assert_eq!(
        table.peer(a).copied(),
        Some(Peer::new(ObservationGeneration(2), 1))
    );
    table.heartbeat(a, 1, 1, true);
    assert_ne!(
        table.peer(a).copied(),
        Some(Peer::new(ObservationGeneration(2), 1))
    );
    assert_eq!(table.window(a, 2, true, false), Some(Ok(Liveness::Alive)));
    for t in 3..=5 {
        table.window(a, t, true, false).unwrap().unwrap();
    }
    assert_eq!(
        table.window(a, 6, true, false),
        Some(Ok(Liveness::Dead(Suspicion {
            generation: ObservationGeneration(2),
            failure: Failure::Silent,
            since: 5
        })))
    );
}

#[test]
fn a_full_table_tracks_a_replacement_host_in_a_vacated_slot() {
    let mut table = Detector::new(bounds()).unwrap();
    let a = table.track(ObservationGeneration(3), 0).unwrap();
    let b = table.track(ObservationGeneration(3), 0).unwrap();
    table.heartbeat(b, 9, 9, true);
    assert_eq!(
        table.track(ObservationGeneration(1), 1),
        Err(DetectRefusal::PeerLimit)
    );
    assert_eq!(table.untrack(b), Some(()));
    assert_eq!(table.untrack(b), None);
    assert_eq!(table.peer(b), None);
    assert_eq!(table.heartbeat(b, 1, 1, true), None);
    assert_eq!(table.window(b, 1, true, false), None);
    assert_eq!(table.reboot(b, ObservationGeneration(9), 1), None);
    assert_eq!(table.retrack(b, ObservationGeneration(9), 1), None);
    assert_eq!(
        table.peer(a).copied(),
        Some(Peer::new(ObservationGeneration(3), 0))
    );
    let c = table.track(ObservationGeneration(1), 1).unwrap();
    assert_ne!(c, b);
    let fresh = Peer::new(ObservationGeneration(1), 1);
    assert_eq!(table.peer(c).copied(), Some(fresh));
    assert_eq!(table.heartbeat(b, 9, 9, true), None);
    assert_eq!(table.reboot(b, ObservationGeneration(4), 1), None);
    assert_eq!(table.untrack(b), None);
    assert_eq!(table.peer(c).copied(), Some(fresh));
    assert_eq!(
        table.track(ObservationGeneration(1), 1),
        Err(DetectRefusal::PeerLimit)
    );
    table.heartbeat(c, 1, 1, true);
    assert_eq!(table.window(c, 2, true, false), Some(Ok(Liveness::Alive)));
    for t in 3..=4 {
        assert_eq!(table.window(c, t, true, false), Some(Ok(Liveness::Alive)));
    }
    assert_eq!(
        table.window(c, 5, true, false),
        Some(Ok(Liveness::Dead(Suspicion {
            generation: ObservationGeneration(1),
            failure: Failure::Silent,
            since: 5
        })))
    );
}

/// Three observed windows whose every heartbeat reports the peer unhealthy read a declared failure, and a healthy
/// heartbeat in a window resets that count. A window with no heartbeat reads a declared suspicion gray and keeps it.
/// One healthy heartbeat turns the suspicion gray, so unhealthy windows with flat counters after it read gray, and
/// the suspicion turns declared again only after three more such windows. The first phase's counters rise, so no
/// window reads as a stall.
#[test]
fn declared_windows_need_every_heartbeat_unhealthy_and_a_healthy_one_turns_the_suspicion_gray() {
    let b = bounds();
    let kind = |p: &mut Peer, t: u64| match p.window(&b, t, true, false).unwrap() {
        Liveness::Dead(s) => Some((s.failure, p.suspicion().unwrap().failure)),
        _ => None,
    };
    let mut p = Peer::new(ObservationGeneration(1), 0);
    for t in 1..=2 {
        p.heartbeat(t, t, false);
        assert_eq!(kind(&mut p, t), None);
    }
    p.heartbeat(3, 3, true);
    p.heartbeat(4, 4, false);
    assert_eq!(
        kind(&mut p, 3),
        None,
        "a healthy heartbeat in the window resets the count"
    );
    for (seq, t) in [(5, 4), (6, 5)] {
        p.heartbeat(seq, seq, false);
        assert_eq!(kind(&mut p, t), None);
    }
    p.heartbeat(7, 7, false);
    assert_eq!(
        kind(&mut p, 6),
        Some((Failure::Declared, Failure::Declared)),
        "three declared windows"
    );
    assert_eq!(
        kind(&mut p, 7),
        Some((Failure::Gray, Failure::Declared)),
        "a window with no heartbeat reads gray"
    );
    p.heartbeat(8, 8, true);
    assert_eq!(
        kind(&mut p, 8),
        Some((Failure::Gray, Failure::Gray)),
        "a healthy heartbeat turns the suspicion gray"
    );
    for (seq, t) in [(9, 9), (10, 10)] {
        p.heartbeat(seq, 8, false);
        assert_eq!(kind(&mut p, t), Some((Failure::Gray, Failure::Gray)));
    }
    p.heartbeat(11, 8, false);
    assert_eq!(
        kind(&mut p, 11),
        Some((Failure::Declared, Failure::Declared)),
        "declared again after three more windows"
    );
}

/// The declared count follows heartbeats, not window edges: a window with no heartbeat keeps the count, so
/// declarations that straddle window edges still reach the onset count; a healthy heartbeat in a gap ends the count
/// and turns a declared suspicion gray, as it does in an observed window.
#[test]
fn empty_windows_keep_the_declared_count_and_a_healthy_heartbeat_in_a_gap_ends_it() {
    let b = bounds();
    let reads =
        |p: &mut Peer, t: u64, observed: bool| match p.window(&b, t, observed, false).unwrap() {
            Liveness::Dead(s) => Some(s.failure),
            _ => None,
        };
    let mut p = Peer::new(ObservationGeneration(1), 0);
    p.heartbeat(1, 1, false);
    assert_eq!(reads(&mut p, 1, true), None);
    assert_eq!(reads(&mut p, 2, true), None, "an empty window");
    p.heartbeat(2, 2, false);
    assert_eq!(reads(&mut p, 3, true), None);
    p.heartbeat(3, 3, false);
    assert_eq!(
        reads(&mut p, 4, true),
        Some(Failure::Declared),
        "three declaring windows around an empty one"
    );
    p.heartbeat(4, 4, true);
    assert_eq!(
        reads(&mut p, 10, false),
        Some(Failure::Gray),
        "a gap with a healthy heartbeat"
    );
    assert_eq!(p.suspicion().unwrap().failure, Failure::Gray);
    p.heartbeat(5, 4, false);
    assert_eq!(
        reads(&mut p, 11, true),
        Some(Failure::Gray),
        "the gap ended the count, so one declaring window reads gray"
    );
}

/// A peer recovers from a declared hold from the healthy heartbeat with progress that ends its declaration until
/// its gray exit, while every observed window progresses. A healthy heartbeat with flat counters, a window without
/// progress and an unobserved close end the recovery until the next observed window that progresses, a suspicion
/// that turns declared again ends it, and a gray suspicion that began as an observed stall never recovers this way.
#[test]
fn a_peer_recovers_from_a_declared_hold_while_every_observed_window_progresses() {
    let b = bounds();
    let close = |p: &mut Peer, t: u64, observed: bool| {
        p.window(&b, t, observed, false).unwrap();
    };
    let kind = |p: &Peer| p.suspicion().map(|s| s.failure);
    // Three declaring windows with flat counters, then the peer's first healthy heartbeat with `progress`.
    let leaving = |progress: u64| {
        let mut p = Peer::new(ObservationGeneration(1), 0);
        for t in 1..=3 {
            p.heartbeat(t, 1, false);
            close(&mut p, t, true);
            assert!(!p.recovers(), "declaring at {t}");
        }
        assert_eq!(kind(&p), Some(Failure::Declared));
        p.heartbeat(4, progress, true);
        p
    };

    let mut p = leaving(2);
    assert!(p.recovers(), "the open window admitted health and progress");
    close(&mut p, 4, true);
    assert_eq!(kind(&p), Some(Failure::Gray));
    assert!(p.recovers(), "the close turned the suspicion gray");
    p.heartbeat(5, 3, true);
    close(&mut p, 5, true);
    assert_eq!((kind(&p), p.recovers()), (None, false), "the gray exit");
    for t in 6..=8 {
        p.heartbeat(t, 3, true);
        close(&mut p, t, true);
    }
    assert_eq!(kind(&p), Some(Failure::Gray), "a stall after the exit");
    p.heartbeat(9, 4, true);
    close(&mut p, 9, true);
    assert!(!p.recovers(), "the exit ended the mark");

    let mut p = leaving(1);
    assert!(!p.recovers(), "healthy with flat counters");
    close(&mut p, 4, true);
    assert_eq!((kind(&p), p.recovers()), (Some(Failure::Gray), false));
    p.heartbeat(5, 2, true);
    close(&mut p, 5, true);
    assert!(p.recovers(), "the next window that progresses");

    let mut p = leaving(2);
    close(&mut p, 4, true);
    p.heartbeat(5, 2, false);
    close(&mut p, 5, true);
    assert_eq!(
        (kind(&p), p.recovers()),
        (Some(Failure::Gray), false),
        "a window without progress"
    );
    for t in 6..=7 {
        p.heartbeat(t, 2, false);
        close(&mut p, t, true);
    }
    assert_eq!(
        (kind(&p), p.recovers()),
        (Some(Failure::Declared), false),
        "declared again"
    );
    p.heartbeat(8, 3, true);
    close(&mut p, 8, true);
    assert!(p.recovers(), "a second recovery");

    let mut p = leaving(2);
    close(&mut p, 4, true);
    close(&mut p, 50, false);
    assert_eq!(
        (kind(&p), p.recovers()),
        (Some(Failure::Gray), false),
        "an unobserved close"
    );

    let mut p = Peer::new(ObservationGeneration(1), 0);
    for t in 1..=4 {
        p.heartbeat(t, 1, true);
        close(&mut p, t, true);
    }
    assert_eq!(kind(&p), Some(Failure::Gray), "an observed stall");
    p.heartbeat(5, 2, true);
    close(&mut p, 5, true);
    assert_eq!(
        (kind(&p), p.recovers()),
        (Some(Failure::Gray), false),
        "a stall that progresses toward its exit still counts"
    );
}

/// A silent suspicion whose first heartbeats all report the peer unhealthy turns declared at the onset count, ahead
/// of its exit; a declared suspicion does not exit on progress; and when the stalled and declared counts reach `D`
/// in one close, the peer reads declared.
#[test]
fn a_declaration_relabels_silence_ahead_of_exit_and_outlasts_progress() {
    let b = bounds();
    let reads = |p: &mut Peer, t: u64| match p.window(&b, t, true, false).unwrap() {
        Liveness::Dead(s) => Some((s.failure, s.since)),
        _ => None,
    };
    let mut p = Peer::new(ObservationGeneration(1), 0);
    for t in 1..=3 {
        reads(&mut p, t);
    }
    assert_eq!(reads(&mut p, 4), Some((Failure::Silent, 3)));
    for (seq, t) in [(1, 5), (2, 6)] {
        p.heartbeat(seq, seq, false);
        reads(&mut p, t);
    }
    p.heartbeat(3, 3, false);
    assert_eq!(
        reads(&mut p, 7),
        Some((Failure::Declared, 3)),
        "relabelled before the silent exit, with its stamp"
    );
    for (seq, t) in [(4, 8), (5, 9), (6, 10), (7, 11)] {
        p.heartbeat(seq, seq, false);
        assert_eq!(
            reads(&mut p, t),
            Some((Failure::Declared, 3)),
            "progress past the exit count and the dwell"
        );
    }

    let mut p = Peer::new(ObservationGeneration(1), 0);
    p.heartbeat(1, 1, true);
    reads(&mut p, 1);
    for (seq, t) in [(2, 2), (3, 3), (4, 4)] {
        p.heartbeat(seq, 1, false);
        reads(&mut p, t);
    }
    assert_eq!(
        p.suspicion().map(|s| s.failure),
        Some(Failure::Declared),
        "the stalled and declared counts reached D together"
    );
}

/// A silent suspicion ends after the exit count of windows with a healthy heartbeat plus the dwell, whether or not
/// windows whose every heartbeat reports the peer unhealthy fall between them: such a window neither counts toward
/// the exit nor restarts it, so a peer whose health bit alternates from window to window does not read silent while
/// its heartbeats arrive. The suspicion does not end in the unhealthy window itself, and a window with no heartbeat
/// restarts the count.
#[test]
fn a_silent_suspicion_exits_on_healthy_windows_that_unhealthy_windows_separate() {
    let b = bounds();
    let reads = |p: &mut Peer, t: u64| match p.window(&b, t, true, false).unwrap() {
        Liveness::Dead(s) => Some((s.failure, s.since)),
        _ => None,
    };
    let silent = || {
        let mut p = Peer::new(ObservationGeneration(1), 0);
        for t in 1..=2 {
            reads(&mut p, t);
        }
        assert_eq!(reads(&mut p, 3), Some((Failure::Silent, 3)));
        p
    };

    let mut p = silent();
    p.heartbeat(1, 1, true);
    assert_eq!(reads(&mut p, 4), Some((Failure::Silent, 3)));
    p.heartbeat(2, 2, false);
    assert_eq!(
        reads(&mut p, 5),
        Some((Failure::Silent, 3)),
        "an unhealthy window does not end the silence"
    );
    p.heartbeat(3, 3, true);
    assert_eq!(
        reads(&mut p, 6),
        None,
        "the second healthy window ends it across the unhealthy one"
    );

    // Two healthy windows reach the exit count at 5, and the dwell of the suspicion stamped 3 passes at 7.
    let late = DetectBounds { dwell: 4, ..b };
    let reads_late = |p: &mut Peer, t: u64| match p.window(&late, t, true, false).unwrap() {
        Liveness::Dead(s) => Some((s.failure, s.since)),
        _ => None,
    };
    let mut p = silent();
    for (seq, t, healthy) in [(1, 4, true), (2, 5, true), (3, 6, false)] {
        p.heartbeat(seq, seq, healthy);
        assert_eq!(reads_late(&mut p, t), Some((Failure::Silent, 3)));
    }
    p.heartbeat(4, 4, false);
    assert_eq!(
        reads_late(&mut p, 7),
        Some((Failure::Silent, 3)),
        "the dwell passed in an unhealthy window, which ends nothing"
    );
    p.heartbeat(5, 5, true);
    assert_eq!(reads_late(&mut p, 8), None);

    let mut p = silent();
    p.heartbeat(1, 1, true);
    assert_eq!(reads(&mut p, 4), Some((Failure::Silent, 3)));
    assert_eq!(
        reads(&mut p, 5),
        Some((Failure::Silent, 3)),
        "a window with no heartbeat"
    );
    p.heartbeat(2, 2, true);
    assert_eq!(
        reads(&mut p, 6),
        Some((Failure::Silent, 3)),
        "the empty window restarted the count"
    );
    p.heartbeat(3, 3, true);
    assert_eq!(reads(&mut p, 7), None);
}
