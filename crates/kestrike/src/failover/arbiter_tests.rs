use super::retire::Target;
use super::{
    arbiter::*,
    detect::{Failure, Liveness, ObservationGeneration, Suspicion},
};
use crate::failover::records::Host;
use crate::net::ownership::ShardGeneration;

pub(super) fn bounds() -> ArbiterBounds {
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
pub(super) fn suspicion() -> Suspicion {
    Suspicion {
        generation: ObservationGeneration(1),
        failure: Failure::Silent,
        since: 3,
    }
}
pub(super) fn votes() -> [Vote; 2] {
    [
        Vote {
            partition: Partition(1),
            class: ObserverClass(1),
            round: 1,
            reading: Liveness::Dead(suspicion()),
        },
        Vote {
            partition: Partition(2),
            class: ObserverClass(2),
            round: 1,
            reading: Liveness::Dead(suspicion()),
        },
    ]
}
pub(super) fn target() -> Target {
    Target {
        generation: ShardGeneration::new(4).unwrap(),
        owner: Host::new(11).unwrap(),
        attempts: 3,
    }
}
pub(super) fn nomination(votes: &[Vote]) -> Nomination<'_> {
    Nomination {
        now: 10,
        observer_healthy: true,
        suspicion: suspicion(),
        observation: Observation {
            generation: ObservationGeneration(1),
            target: target(),
        },
        holder_since: 0,
        votes,
        clock: Clock::Trusted { sampled_at: 7 },
    }
}

/// The vote with its suspicion moved to an earlier observation generation, so it does not count.
fn stale(vote: Vote) -> Vote {
    Vote {
        reading: Liveness::Dead(Suspicion {
            generation: ObservationGeneration(0),
            ..suspicion()
        }),
        ..vote
    }
}

#[test]
fn nomination_spends_nothing() {
    let b = bounds();
    let v = votes();
    let n = nomination(&v);
    let first = nominate(&b, &n).unwrap();
    assert_eq!(first, FlipNomination { target: target() });
    for t in [20, 100, 1000] {
        let later = Nomination {
            now: t,
            clock: Clock::Trusted { sampled_at: t },
            ..nomination(&v)
        };
        assert_eq!(
            nominate(&b, &later),
            Ok(first),
            "a repeated nomination is the same nomination"
        );
    }
    let retracked_same_target = Nomination {
        observation: Observation {
            generation: ObservationGeneration(2),
            target: target(),
        },
        ..nomination(&v)
    };
    assert_eq!(
        nominate(&b, &retracked_same_target),
        Err(Decline::StaleSuspicion),
        "the generation alone binds evidence to its observation"
    );
    for other in [
        Target {
            attempts: 4,
            ..target()
        },
        Target {
            generation: ShardGeneration::new(5).unwrap(),
            owner: Host::new(12).unwrap(),
            attempts: 0,
        },
    ] {
        let stale = Nomination {
            observation: Observation {
                generation: ObservationGeneration(2),
                target: other,
            },
            ..nomination(&v)
        };
        assert_eq!(
            nominate(&b, &stale),
            Err(Decline::StaleSuspicion),
            "a suspicion gathered before the target changed names the earlier observation"
        );
        let retracked = Suspicion {
            generation: ObservationGeneration(2),
            ..suspicion()
        };
        let votes = v.map(|vote| Vote {
            reading: Liveness::Dead(retracked),
            ..vote
        });
        let fresh = Nomination {
            suspicion: retracked,
            votes: &votes,
            ..stale
        };
        assert_eq!(
            nominate(&b, &fresh),
            Ok(FlipNomination { target: other }),
            "a nomination names the target of the observation its suspicion belongs to"
        );
    }
}

#[test]
fn nomination_returns_exact_declines() {
    let b = bounds();
    let v = votes();
    let n = nomination(&v);
    assert!(nominate(&b, &n).is_ok());
    macro_rules! declines {
        ($field:ident, $value:expr, $why:expr) => {{
            let changed = Nomination {
                $field: $value,
                ..nomination(&v)
            };
            assert_eq!(nominate(&b, &changed), Err($why));
        }};
    }
    declines!(observer_healthy, false, Decline::ObserverUnhealthy);
    declines!(
        suspicion,
        Suspicion {
            generation: ObservationGeneration(2),
            ..suspicion()
        },
        Decline::StaleSuspicion
    );
    declines!(holder_since, 8, Decline::HolderGrace);
    declines!(votes, &[], Decline::SelfSuspect { until: 12 });
    let alive = [
        Vote {
            reading: Liveness::Alive,
            ..v[0]
        },
        v[1],
    ];
    declines!(votes, &alive, Decline::Alive);
    let unknown = [
        v[0],
        Vote {
            reading: Liveness::Unknown,
            ..v[1]
        },
    ];
    declines!(votes, &unknown, Decline::Unknown);
    let unknown_extra = [
        v[0],
        v[1],
        Vote {
            reading: Liveness::Unknown,
            ..v[1]
        },
    ];
    declines!(votes, &unknown_extra, Decline::Unknown);
    let same = [
        v[0],
        Vote {
            partition: Partition(1),
            ..v[1]
        },
    ];
    declines!(votes, &same, Decline::Quorum);
    let stale = [
        v[0],
        Vote {
            reading: Liveness::Dead(Suspicion {
                generation: ObservationGeneration(0),
                ..suspicion()
            }),
            ..v[1]
        },
    ];
    declines!(votes, &stale, Decline::Quorum);
    let round = [Vote { round: 3, ..v[0] }, v[1]];
    declines!(votes, &round, Decline::ProbeBound);
    let gray = Suspicion {
        failure: Failure::Gray,
        ..suspicion()
    };
    let same_class = [
        v[0],
        Vote {
            class: ObserverClass(1),
            ..v[1]
        },
    ];
    let g = Nomination {
        suspicion: gray,
        votes: &same_class,
        ..nomination(&v)
    };
    assert_eq!(nominate(&b, &g), Err(Decline::GrayNeedsSecondClass));
    declines!(clock, Clock::Untrusted, Decline::ClockUntrusted);
    declines!(
        clock,
        Clock::Trusted { sampled_at: 6 },
        Decline::ClockUntrusted
    );
    declines!(
        clock,
        Clock::Trusted { sampled_at: 11 },
        Decline::ClockUntrusted
    );
    assert_eq!(
        nominate(
            &b,
            &Nomination {
                now: 0,
                ..nomination(&v)
            }
        ),
        Err(Decline::StaleSuspicion)
    );
    assert_eq!(
        nominate(
            &b,
            &Nomination {
                holder_since: 11,
                ..nomination(&v)
            }
        ),
        Err(Decline::Time)
    );
}
#[test]
fn arbiter_bounds_require_every_timing_and_quorum_input() {
    let b = bounds();
    for bad in [
        ArbiterBounds { h: 0, ..b },
        ArbiterBounds { h: 3, ..b },
        ArbiterBounds { dwell: 0, ..b },
    ] {
        assert_eq!(bad.validate().unwrap_err(), Decline::Dwell);
    }
    for bad in [
        ArbiterBounds { k: 1, ..b },
        ArbiterBounds { k: 4, ..b },
        ArbiterBounds { rounds: 0, ..b },
        ArbiterBounds {
            holder_grace: 0,
            ..b
        },
        ArbiterBounds { clock_age: 0, ..b },
    ] {
        assert_eq!(bad.validate().unwrap_err(), Decline::Bounds);
    }
}

#[test]
fn gray_evidence_requires_and_admits_distinct_observer_classes() {
    let gray = Suspicion {
        failure: Failure::Gray,
        ..suspicion()
    };
    let v = votes().map(|v| Vote {
        reading: Liveness::Dead(gray),
        ..v
    });
    assert!(nominate(&bounds(), &nomination(&v)).is_ok());
    let one_class = [
        v[0],
        Vote {
            class: v[0].class,
            ..v[1]
        },
    ];
    assert_eq!(
        nominate(&bounds(), &nomination(&one_class)),
        Err(Decline::GrayNeedsSecondClass)
    );
}

#[test]
fn probe_bounds_future_evidence_and_refusal_precedence_are_pinned() {
    let b = bounds();
    let v = votes();
    for bad in [
        [Vote { round: 0, ..v[0] }, v[1]],
        [
            v[0],
            Vote {
                reading: Liveness::Dead(Suspicion {
                    since: 11,
                    ..suspicion()
                }),
                ..v[1]
            },
        ],
    ] {
        let why = if bad[0].round == 0 {
            Decline::ProbeBound
        } else {
            Decline::Quorum
        };
        assert_eq!(nominate(&b, &nomination(&bad)), Err(why));
    }
    assert_eq!(
        nominate(&b, &nomination(&[v[0]; 4])),
        Err(Decline::ProbeBound)
    );
    assert!(
        nominate(
            &b,
            &nomination(&[
                Vote {
                    round: b.rounds,
                    ..v[0]
                },
                v[1]
            ])
        )
        .is_ok()
    );
    assert_eq!(
        nominate(
            &b,
            &Nomination {
                votes: &[],
                clock: Clock::Untrusted,
                ..nomination(&v)
            }
        ),
        Err(Decline::SelfSuspect { until: 12 })
    );
    assert_eq!(
        nominate(
            &b,
            &Nomination {
                observer_healthy: false,
                clock: Clock::Untrusted,
                ..nomination(&v)
            }
        ),
        Err(Decline::ObserverUnhealthy)
    );
    let mixed = [
        Vote {
            reading: Liveness::Alive,
            ..v[0]
        },
        Vote {
            reading: Liveness::Unknown,
            ..v[1]
        },
    ];
    assert_eq!(nominate(&b, &nomination(&mixed)), Err(Decline::Alive));
}

#[test]
fn quorum_counts_each_partition_once_across_stale_and_repeated_votes() {
    let b = ArbiterBounds {
        hosts: 8,
        ..bounds()
    };
    let v = votes();
    let repeated = [v[0], stale(v[1]), v[0], stale(v[1]), v[0]];
    assert_eq!(nominate(&b, &nomination(&repeated)), Err(Decline::Quorum));
    let late = [stale(v[1]), v[0], stale(v[0]), v[0], v[0], v[1]];
    assert!(nominate(&b, &nomination(&late)).is_ok());
    let third = Vote {
        partition: Partition(3),
        ..v[0]
    };
    let k3 = ArbiterBounds { k: 3, ..b };
    let two = [v[0], v[1], v[0], stale(third), v[1]];
    assert_eq!(nominate(&k3, &nomination(&two)), Err(Decline::Quorum));
    let three = [v[0], v[1], v[0], stale(third), v[1], third];
    assert!(nominate(&k3, &nomination(&three)).is_ok());
}

#[test]
fn quorum_counts_partitions_that_share_their_low_bits_exactly() {
    let b = ArbiterBounds {
        hosts: 8,
        k: 3,
        ..bounds()
    };
    let at = |p: u32| Vote {
        partition: Partition(p),
        ..votes()[0]
    };
    let (p, q, r) = (1, 1 << 16 | 1, 1 << 17 | 1);
    let two = [at(p), at(q), at(p), at(q), stale(at(r))];
    assert_eq!(nominate(&b, &nomination(&two)), Err(Decline::Quorum));
    let three = [at(p), at(q), at(p), at(r)];
    assert!(nominate(&b, &nomination(&three)).is_ok());
    let k2 = ArbiterBounds { k: 2, ..b };
    let shadowed = [at(p), stale(at(q)), at(p)];
    assert_eq!(nominate(&k2, &nomination(&shadowed)), Err(Decline::Quorum));
    let late = [at(p), stale(at(q)), at(p), at(q)];
    assert!(nominate(&k2, &nomination(&late)).is_ok());
    assert_eq!(
        nominate(&k2, &nomination(&[at(0), at(0)])),
        Err(Decline::Quorum)
    );
    assert!(nominate(&k2, &nomination(&[at(0), at(16)])).is_ok());
}

#[test]
fn repeats_in_a_shared_slot_cost_the_same_order_as_repeats_in_their_own_slot() {
    const M: usize = 1 << 15;
    let at = |p: u32| Vote {
        partition: Partition(p),
        ..votes()[0]
    };
    let grouped = |q: u32| -> Vec<Vote> {
        std::iter::repeat_n(at(1), M)
            .chain(std::iter::repeat_n(at(q), M))
            .collect()
    };
    let (shared, own) = (grouped(17), grouped(2));
    let b = ArbiterBounds {
        hosts: 2 * M,
        k: 3,
        ..bounds()
    };
    let fastest = |list: &[Vote]| {
        (0..3)
            .map(|_| {
                let start = std::time::Instant::now();
                assert_eq!(nominate(&b, &nomination(list)), Err(Decline::Quorum));
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let (own_time, shared_time) = (fastest(&own), fastest(&shared));
    assert!(
        shared_time <= own_time * 16 + std::time::Duration::from_millis(1),
        "shared slot {shared_time:?}, own slots {own_time:?}"
    );
}

#[test]
fn probe_bound_refuses_an_out_of_round_vote_after_the_quorum() {
    let b = bounds();
    let v = votes();
    for round in [0, b.rounds + 1] {
        let late = [v[0], v[1], Vote { round, ..v[0] }];
        assert_eq!(nominate(&b, &nomination(&late)), Err(Decline::ProbeBound));
    }
}

#[test]
fn refusal_precedence_does_not_depend_on_the_vote_order() {
    let b = bounds();
    let v = votes();
    let alive = Vote {
        reading: Liveness::Alive,
        ..v[0]
    };
    let unknown = Vote {
        reading: Liveness::Unknown,
        ..v[0]
    };
    assert_eq!(
        nominate(&b, &nomination(&[alive, Vote { round: 0, ..v[1] }])),
        Err(Decline::ProbeBound)
    );
    assert_eq!(
        nominate(&b, &nomination(&[unknown, alive])),
        Err(Decline::Alive)
    );
}

#[test]
fn gray_corroboration_reads_every_counted_vote_and_no_stale_one() {
    let b = bounds();
    let v = votes();
    let gray = Suspicion {
        failure: Failure::Gray,
        ..suspicion()
    };
    let same_class = Vote {
        class: v[0].class,
        ..v[1]
    };
    let third = Vote {
        partition: Partition(3),
        ..v[1]
    };
    let gray_suspicion = Nomination {
        suspicion: gray,
        ..nomination(&[])
    };
    let stale_second_class = [v[0], stale(third), same_class];
    assert_eq!(
        nominate(
            &b,
            &Nomination {
                votes: &stale_second_class,
                ..gray_suspicion
            }
        ),
        Err(Decline::GrayNeedsSecondClass)
    );
    let stale_gray = Vote {
        class: v[0].class,
        reading: Liveness::Dead(Suspicion {
            generation: ObservationGeneration(0),
            ..gray
        }),
        ..third
    };
    assert!(nominate(&b, &nomination(&[v[0], stale_gray, same_class])).is_ok());
    let later_gray = Vote {
        reading: Liveness::Dead(gray),
        ..same_class
    };
    assert_eq!(
        nominate(&b, &nomination(&[v[0], later_gray])),
        Err(Decline::GrayNeedsSecondClass)
    );
}

/// A DEAD vote of `failure` from `partition` in observer class 1.
fn one_class(partition: u32, failure: Failure) -> Vote {
    Vote {
        partition: Partition(partition),
        class: ObserverClass(1),
        round: 1,
        reading: Liveness::Dead(Suspicion {
            failure,
            ..suspicion()
        }),
    }
}

/// A declared suspicion and declared or silent votes of one observer class nominate on the ordinary quorum, and one
/// counted gray vote refuses the same evidence wherever it stands in the list, the votes after the quorum's second
/// partition included. The control drops the gray vote and nominates.
#[test]
fn a_counted_gray_vote_after_the_quorum_still_refuses_one_class() {
    let b = bounds();
    let declared = Nomination {
        suspicion: Suspicion {
            failure: Failure::Declared,
            ..suspicion()
        },
        ..nomination(&[])
    };
    let quorum = [
        one_class(1, Failure::Declared),
        one_class(2, Failure::Silent),
    ];
    assert_eq!(
        nominate(
            &b,
            &Nomination {
                votes: &quorum,
                ..declared
            }
        ),
        Ok(FlipNomination { target: target() }),
        "the control: declared and silent evidence of one class meets the ordinary quorum"
    );
    let after = [
        one_class(1, Failure::Declared),
        one_class(2, Failure::Declared),
        one_class(3, Failure::Gray),
    ];
    let before = [after[2], after[0], after[1]];
    for votes in [&after, &before] {
        assert_eq!(
            nominate(&b, &Nomination { votes, ..declared }),
            Err(Decline::GrayNeedsSecondClass),
            "a counted gray vote at any place in {votes:?}"
        );
    }
    let gray_local = Nomination {
        suspicion: suspicion_of(Failure::Gray),
        votes: &quorum,
        ..nomination(&[])
    };
    assert_eq!(
        nominate(&b, &gray_local),
        Err(Decline::GrayNeedsSecondClass),
        "a gray local suspicion refuses declared votes of one class"
    );
}

/// A gray vote of observer class 1 whose suspicion names an earlier observation generation, so it does not count.
fn stale_gray(partition: u32) -> Vote {
    Vote {
        reading: Liveness::Dead(Suspicion {
            generation: ObservationGeneration(0),
            ..suspicion_of(Failure::Gray)
        }),
        ..one_class(partition, Failure::Gray)
    }
}

fn suspicion_of(failure: Failure) -> Suspicion {
    Suspicion {
        failure,
        ..suspicion()
    }
}

/// A gray vote counts only when it names the observation's generation and is stamped at or before `now`: a gray
/// vote of an earlier generation or a later stamp leaves a declared quorum of one class nominating, and the control,
/// the same gray vote counted, refuses.
#[test]
fn a_stale_gray_vote_does_not_count() {
    let b = bounds();
    let declared = Nomination {
        suspicion: suspicion_of(Failure::Declared),
        ..nomination(&[])
    };
    let gray = one_class(3, Failure::Gray);
    let earlier = stale_gray(3);
    let later = Vote {
        reading: Liveness::Dead(Suspicion {
            since: declared.now + 1,
            ..suspicion_of(Failure::Gray)
        }),
        ..gray
    };
    for stale_gray in [earlier, later] {
        let votes = [
            one_class(1, Failure::Declared),
            one_class(2, Failure::Declared),
            stale_gray,
        ];
        assert_eq!(
            nominate(
                &b,
                &Nomination {
                    votes: &votes,
                    ..declared
                }
            ),
            Ok(FlipNomination { target: target() }),
            "{stale_gray:?} does not count"
        );
    }
    let votes = [
        one_class(1, Failure::Declared),
        one_class(2, Failure::Declared),
        gray,
    ];
    assert_eq!(
        nominate(
            &b,
            &Nomination {
                votes: &votes,
                ..declared
            }
        ),
        Err(Decline::GrayNeedsSecondClass),
        "the control: the gray vote counted"
    );
}

/// The control that reads no vote past the quorum's second counted partition for gray evidence fails the late-gray
/// case: a gray vote after a declared quorum of one class nominates.
#[test]
fn the_control_that_reads_no_vote_past_the_quorum_nominates_on_a_late_gray_vote() {
    let votes = [
        one_class(1, Failure::Declared),
        one_class(2, Failure::Declared),
        one_class(3, Failure::Gray),
    ];
    let declared = Nomination {
        suspicion: suspicion_of(Failure::Declared),
        votes: &votes,
        ..nomination(&[])
    };
    let planted = super::detect::tests::planted("gray-unread-after-quorum", || {
        nominate(&bounds(), &declared)
    });
    assert_eq!(
        planted,
        Ok(FlipNomination { target: target() }),
        "the control misses the late gray vote"
    );
}

/// The control that reads gray evidence from votes that do not count fails the stale-gray case: a gray vote of an
/// earlier generation refuses a declared quorum of one class.
#[test]
fn the_control_that_reads_stale_votes_refuses_on_a_stale_gray_vote() {
    let votes = [
        one_class(1, Failure::Declared),
        one_class(2, Failure::Declared),
        stale_gray(3),
    ];
    let declared = Nomination {
        suspicion: suspicion_of(Failure::Declared),
        votes: &votes,
        ..nomination(&[])
    };
    let planted =
        super::detect::tests::planted("stale-gray-counts", || nominate(&bounds(), &declared));
    assert_eq!(
        planted,
        Err(Decline::GrayNeedsSecondClass),
        "the control counts the stale gray vote"
    );
}
