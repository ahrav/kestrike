//! `nominate` declines a suspicion of another observation generation.
//!
//! `nominate` compares observation generations only, so a suspicion
//! gathered under an earlier target set or boot declines `StaleSuspicion`
//! once the caller opens the newer generation through `Peer::retrack` or
//! `Peer::reboot`. A suspicion stamped after `now` declines the same way.
//!
//! A `detect::Peer` tracks the owner under the earlier generation, hears
//! one heartbeat and then closes silent windows until it holds a
//! suspicion. That suspicion nominates the owner's `(g, owner, E)` while
//! the observation names the generation it was gathered under. The caller
//! then opens the newer generation on the same peer, and the suspicion
//! held from before the opening is offered against the newer observation,
//! with a quorum of votes that name the newer generation, so the
//! suspicion's generation is the only stale input: `nominate` must decline
//! `StaleSuspicion`. The same steps with the suspicion the peer gathers
//! after the opening nominate the newer `(g, owner, E)`.
//!
//! The tests hold plain values only.

use super::arbiter::{
    ArbiterBounds, Clock, Decline, FlipNomination, Nomination, Observation, ObserverClass,
    Partition, Vote, nominate,
};
use super::detect::{DetectBounds, Failure, Liveness, ObservationGeneration, Peer, Suspicion};
use super::records::Host;
use super::retire::Target;
use crate::net::ownership::ShardGeneration;

const EARLIER: ObservationGeneration = ObservationGeneration(7);
const NEWER: ObservationGeneration = ObservationGeneration(8);

/// The local time of every nomination. Both suspicions the peers gather are stamped before it.
const NOW: u64 = 10;

/// The sequence of the one heartbeat the owner sends before it goes silent.
const HEARD: u64 = 4;

/// Valid arbiter bounds: a quorum of two partitions among three hosts.
fn bounds() -> ArbiterBounds {
    ArbiterBounds {
        h: 1,
        holder_grace: 2,
        k: 2,
        rounds: 2,
        clock_age: 3,
        dwell: 2,
        hosts: 3,
    }
}

/// Valid detector bounds: two silent windows of one tick raise a suspicion.
fn detect_bounds() -> DetectBounds {
    DetectBounds {
        h: 1,
        d: 2,
        tau: 0,
        jitter: 0,
        peer_grace: 1,
        exit_windows: 1,
        dwell: 1,
        hosts: 3,
    }
}

/// The shard record's `(g, owner, E)` with `E = attempts`.
fn target(attempts: u32) -> Target {
    Target {
        generation: ShardGeneration::new(4).unwrap(),
        owner: Host::new(11).unwrap(),
        attempts,
    }
}

/// The target the earlier generation was opened for, and the one the newer generation is opened for.
fn earlier_target() -> Target {
    target(3)
}
fn newer_target() -> Target {
    target(4)
}

/// Closes observed windows with no heartbeat in them until the peer holds a suspicion, and returns it as
/// the peer holds it. `None` when a close is refused or `d` silent windows raise no suspicion.
fn silence(peer: &mut Peer) -> Option<Suspicion> {
    let b = detect_bounds();
    for _ in 0..b.d {
        let at = peer.window_at() + b.h;
        peer.window(&b, at, true, false).ok()?;
    }
    peer.suspicion()
}

/// A peer tracked under the earlier generation from time 0 that heard one heartbeat in its first window and
/// nothing after, with the suspicion it holds.
fn suspected_peer() -> (Peer, Suspicion) {
    let b = detect_bounds();
    let mut peer = Peer::new(EARLIER, 0);
    peer.heartbeat(HEARD, 1, true);
    assert_eq!(
        peer.window(&b, b.h, true, false),
        Ok(Liveness::Alive),
        "premise: the window that holds the heartbeat reads Alive"
    );
    let held = silence(&mut peer).expect("premise: silent windows raise a suspicion");
    assert_eq!(
        (held.generation, held.failure),
        (EARLIER, Failure::Silent),
        "premise: the suspicion carries the generation the peer was tracked under"
    );
    assert!(
        held.since <= NOW,
        "premise: the suspicion is stamped before the nomination"
    );
    (peer, held)
}

/// Two Dead votes of distinct partitions and observer classes whose suspicion names `generation`.
fn quorum(generation: ObservationGeneration) -> [Vote; 2] {
    let reading = Liveness::Dead(Suspicion {
        generation,
        failure: Failure::Silent,
        since: 6,
    });
    [
        Vote {
            partition: Partition(1),
            class: ObserverClass(1),
            round: 1,
            reading,
        },
        Vote {
            partition: Partition(2),
            class: ObserverClass(2),
            round: 1,
            reading,
        },
    ]
}

/// Evidence that nominates when `suspicion` names `observation`'s generation and `votes` hold a quorum for
/// it: a healthy observer, a holder past its grace and a trusted, fresh clock.
fn evidence<'a>(
    observation: Observation,
    suspicion: Suspicion,
    votes: &'a [Vote],
) -> Nomination<'a> {
    Nomination {
        now: NOW,
        observer_healthy: true,
        observation,
        suspicion,
        holder_since: 0,
        votes,
        clock: Clock::Trusted { sampled_at: 8 },
    }
}

/// How the caller opens the newer observation generation on the owner's peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opening {
    /// The owner's targeted `(g, owner, E)` set changed within one boot.
    Retrack,
    /// The first authenticated heartbeat of the owner's next boot arrived.
    Reboot,
}

/// What `nominate` returned at the three points of one run.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    /// The earlier suspicion against the earlier observation, before the opening.
    before: Result<FlipNomination, Decline>,
    /// The earlier suspicion against the newer observation, after the opening.
    stale: Result<FlipNomination, Decline>,
    /// The suspicion the peer gathers after the opening, against the newer observation.
    regathered: Result<FlipNomination, Decline>,
}

/// Gathers a suspicion under the earlier generation, opens the newer generation by `opening`, and offers
/// the held suspicion and then a regathered one against the newer observation. The votes after the opening
/// name the newer generation in both offers.
fn run(opening: Opening) -> Run {
    let b = bounds();
    let (mut peer, held) = suspected_peer();

    let earlier_votes = quorum(EARLIER);
    let before = nominate(
        &b,
        &evidence(
            Observation {
                generation: peer.generation(),
                target: earlier_target(),
            },
            held,
            &earlier_votes,
        ),
    );

    let opened_at = peer.window_at();
    let (opened, sequence_kept) = match opening {
        Opening::Retrack => (peer.retrack(NEWER, opened_at), Some(HEARD)),
        Opening::Reboot => (peer.reboot(NEWER, opened_at), None),
    };
    assert_eq!(
        opened,
        Ok(()),
        "premise: the peer admits the newer generation"
    );
    assert_eq!(
        (peer.generation(), peer.suspicion(), peer.sequence()),
        (NEWER, None, sequence_kept),
        "premise: the opening starts fresh observations under the newer generation"
    );

    let newer = Observation {
        generation: peer.generation(),
        target: newer_target(),
    };
    let newer_votes = quorum(NEWER);
    let stale = nominate(&b, &evidence(newer, held, &newer_votes));

    let fresh = silence(&mut peer).expect("premise: silence after the opening raises a suspicion");
    assert_eq!(
        (fresh.generation, fresh.failure),
        (NEWER, held.failure),
        "premise: the regathered suspicion differs from the held one in generation and stamp alone"
    );
    assert!(
        fresh.since <= NOW,
        "premise: the regathered suspicion is stamped before the nomination"
    );
    let regathered = nominate(&b, &evidence(newer, fresh, &newer_votes));

    Run {
        before,
        stale,
        regathered,
    }
}

/// The suspicion with another stamp.
fn stamped(suspicion: Suspicion, since: u64) -> Suspicion {
    Suspicion { since, ..suspicion }
}

/// The run the property requires: the suspicion nominates under its own generation, declines
/// `StaleSuspicion` against the newer one, and the regathered suspicion nominates the newer target.
fn required() -> Run {
    Run {
        before: Ok(FlipNomination {
            target: earlier_target(),
        }),
        stale: Err(Decline::StaleSuspicion),
        regathered: Ok(FlipNomination {
            target: newer_target(),
        }),
    }
}

/// A target change within one boot opens the newer generation through `Peer::retrack`; the suspicion the
/// peer held before it must not nominate the changed `(g, owner, E)`.
#[test]
fn a_suspicion_held_from_before_retrack_declines_stale_suspicion() {
    assert_eq!(run(Opening::Retrack), required());
}

/// A new boot opens the newer generation through `Peer::reboot`; the suspicion gathered against the
/// previous boot must not nominate the rebooted owner.
#[test]
fn a_suspicion_held_from_before_reboot_declines_stale_suspicion() {
    assert_eq!(run(Opening::Reboot), required());
}

/// The comparison is for equality, not order: a suspicion that names a generation the caller's observation
/// has not opened declines as well, although the votes hold a quorum for the observation's generation.
#[test]
fn a_suspicion_of_a_generation_after_the_observations_declines_stale_suspicion() {
    let b = bounds();
    let (_, held) = suspected_peer();
    let ahead = Suspicion {
        generation: NEWER,
        ..held
    };
    let votes = quorum(EARLIER);
    let observation = Observation {
        generation: EARLIER,
        target: earlier_target(),
    };
    assert_eq!(
        nominate(&b, &evidence(observation, held, &votes)),
        Ok(FlipNomination {
            target: earlier_target()
        }),
        "the suspicion of the observation's generation nominates"
    );
    assert_eq!(
        nominate(&b, &evidence(observation, ahead, &votes)),
        Err(Decline::StaleSuspicion)
    );
}

/// `nominate` returns its first refusal, and the stale-suspicion check runs before holder grace, the probe
/// bound, the vote readings, self-suspicion, quorum, gray corroboration and clock trust. Each row of evidence
/// declines with its own reason while the suspicion names the observation's generation, and declines
/// `StaleSuspicion` once the suspicion is the one held from before the opening.
#[test]
fn a_stale_generation_declines_before_every_later_refusal() {
    let b = bounds();
    let (_, held) = suspected_peer();
    let current = Suspicion {
        generation: NEWER,
        ..held
    };
    let observation = Observation {
        generation: NEWER,
        target: newer_target(),
    };
    let full = quorum(NEWER);
    let dead = full[0];
    let alive = [
        dead,
        Vote {
            reading: Liveness::Alive,
            ..full[1]
        },
    ];
    let unknown = [
        dead,
        Vote {
            reading: Liveness::Unknown,
            ..full[1]
        },
    ];
    let over_hosts = [dead; 4];
    let one_class = [
        dead,
        Vote {
            class: dead.class,
            ..full[1]
        },
    ];

    type Shape = for<'a> fn(Nomination<'a>) -> Nomination<'a>;
    let keep: Shape = |n| n;
    let rows: [(&str, &[Vote], Shape, Decline); 9] = [
        (
            "holder within grace",
            &full,
            |n| Nomination {
                holder_since: NOW - 1,
                ..n
            },
            Decline::HolderGrace,
        ),
        (
            "holder tenure after now",
            &full,
            |n| Nomination {
                holder_since: NOW + 1,
                ..n
            },
            Decline::Time,
        ),
        (
            "more votes than hosts",
            &over_hosts,
            keep,
            Decline::ProbeBound,
        ),
        ("an Alive vote", &alive, keep, Decline::Alive),
        ("an Unknown vote", &unknown, keep, Decline::Unknown),
        (
            "no vote",
            &[],
            keep,
            Decline::SelfSuspect {
                until: NOW + bounds().dwell,
            },
        ),
        ("one partition", &full[..1], keep, Decline::Quorum),
        (
            "gray with one observer class",
            &one_class,
            |n| Nomination {
                suspicion: Suspicion {
                    failure: Failure::Gray,
                    ..n.suspicion
                },
                ..n
            },
            Decline::GrayNeedsSecondClass,
        ),
        (
            "untrusted clock",
            &full,
            |n| Nomination {
                clock: Clock::Untrusted,
                ..n
            },
            Decline::ClockUntrusted,
        ),
    ];

    let mut wrong = Vec::new();
    for (name, votes, shape, own) in rows {
        let with_current = nominate(&b, &shape(evidence(observation, current, votes)));
        if with_current != Err(own) {
            wrong.push(format!(
                "{name}, current suspicion: {with_current:?}, expected {own:?}"
            ));
        }
        let with_stale = nominate(&b, &shape(evidence(observation, held, votes)));
        if with_stale != Err(Decline::StaleSuspicion) {
            wrong.push(format!(
                "{name}, stale suspicion: {with_stale:?}, expected StaleSuspicion"
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A suspicion of the observation's generation whose stamp is after `now` declines `StaleSuspicion`; the
/// same suspicion stamped at `now` nominates. The votes are stamped before `now` in both, so the
/// suspicion's stamp is the only future input.
#[test]
fn a_suspicion_stamped_after_now_declines_stale_suspicion() {
    let b = bounds();
    let (peer, held) = suspected_peer();
    let observation = Observation {
        generation: peer.generation(),
        target: earlier_target(),
    };
    let votes = quorum(EARLIER);
    assert_eq!(
        nominate(&b, &evidence(observation, stamped(held, NOW), &votes)),
        Ok(FlipNomination {
            target: earlier_target()
        }),
        "a suspicion stamped at now nominates"
    );
    for since in [NOW + 1, u64::MAX] {
        assert_eq!(
            nominate(&b, &evidence(observation, stamped(held, since), &votes)),
            Err(Decline::StaleSuspicion),
            "a suspicion stamped at {since}, after now = {NOW}"
        );
    }
}
