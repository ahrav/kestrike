//! Two hosts announcing the same `(g, a)` leave the route in one `Conflict`.
//!
//! The tests merge holder frames of one shard into an empty route with `HighWater::merge`. Two hosts announce
//! the same `(g, a)`, as a Candidate or a Ready frame each, in both arrival orders. Every order and every
//! pair of kinds must give the one `HighWater::Conflict` of that `(g, a)`, which names no host, admits no
//! request and admits neither host's response. The Conflict must stay under a repeat of either frame, under a
//! third host at the same `(g, a)` and under every lower tenure, and must end at a higher tenure: a Ready
//! frame there binds its tenure and admits requests and its response again.
//!
//! The same merges with one host in place of two conflict nowhere, so the route keeps the host and admits its
//! requests, and its response once a Ready frame bound it.
//!
//! Every test is a pure computation over `Copy` values: it holds no fixture, so each assertion that fails
//! unwinds to libtest and ends in a result line.

use super::route::{FrameKind, HighWater, HolderFrame};
use super::route_tests::tenure;
use crate::net::ownership::Tenure;

/// The generation of the contested tenure.
const G: u64 = 3;
/// The activation count of the contested tenure.
const A: u32 = 5;
/// The two hosts that announce the contested tenure, by the byte that fills each identifier.
const HOSTS: [u8; 2] = [0x11, 0x22];
/// A host that announces neither frame of the conflict.
const THIRD: u8 = 0x33;
/// The frame kinds by which a holder announces its tenure.
const ANNOUNCES: [FrameKind; 2] = [FrameKind::Candidate, FrameKind::Ready];

fn frame(tenure: Tenure, kind: FrameKind) -> HolderFrame {
    HolderFrame { tenure, kind }
}

/// The route an empty route becomes when `first` and then `second` reach it.
fn after(first: HolderFrame, second: HolderFrame) -> HighWater {
    HighWater::merge(Some(HighWater::merge(None, first)), second)
}

/// The two hosts' tenures at the contested `(g, a)`.
fn contested() -> [Tenure; 2] {
    HOSTS.map(|host| tenure(G, A, host))
}

/// The Conflict of the contested `(g, a)`.
fn conflict() -> HighWater {
    let [held, _] = contested();
    HighWater::Conflict {
        generation: held.generation,
        epoch: held.epoch,
    }
}

/// Tenures below the contested one: an earlier epoch of its generation, and an earlier generation at a
/// later epoch, each for both hosts and for a third.
fn lower() -> Vec<Tenure> {
    let mut lower = Vec::new();
    for host in HOSTS.into_iter().chain([THIRD]) {
        lower.push(tenure(G, A - 1, host));
        lower.push(tenure(G - 1, A + 4, host));
    }
    lower
}

/// Tenures above the contested one: the next epoch of its generation, and the next generation at an
/// earlier epoch, each for both hosts and for a third.
fn higher() -> Vec<Tenure> {
    let mut higher = Vec::new();
    for host in HOSTS.into_iter().chain([THIRD]) {
        higher.push(tenure(G, A + 1, host));
        higher.push(tenure(G + 1, 1, host));
    }
    higher
}

#[test]
fn two_hosts_at_one_tenure_give_one_conflict_in_either_arrival_order() {
    let [x, y] = contested();
    for kind_x in ANNOUNCES {
        for kind_y in ANNOUNCES {
            let arrivals = [
                after(frame(x, kind_x), frame(y, kind_y)),
                after(frame(y, kind_y), frame(x, kind_x)),
            ];
            for (order, route) in arrivals.into_iter().enumerate() {
                assert_eq!(
                    route,
                    conflict(),
                    "equal (g, a) with distinct hosts produce one Conflict value \
                     (arrival order {order}, kinds {kind_x:?} and {kind_y:?})"
                );
                assert_eq!(route.host(), None, "a Conflict names no host");
                assert!(!route.requests(), "a Conflict withholds requests");
                for claimant in [x, y] {
                    assert!(
                        !route.response(claimant),
                        "a Conflict withholds the response of {claimant:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_conflict_stays_under_repeats_and_lower_tenures() {
    let held = conflict();
    let [x, y] = contested();
    let repeats = [x, y, tenure(G, A, THIRD)];
    for arrival in repeats.into_iter().chain(lower()) {
        for kind in ANNOUNCES {
            let route = HighWater::merge(Some(held), frame(arrival, kind));
            assert_eq!(
                route, held,
                "a Conflict withholds until a higher tenure; a {kind:?} frame of {arrival:?} is none"
            );
        }
    }
}

#[test]
fn a_higher_tenure_ends_the_conflict() {
    let held = conflict();
    let [x, y] = contested();
    for above in higher() {
        let bound = HighWater::merge(Some(held), frame(above, FrameKind::Ready));
        assert_eq!(
            bound,
            HighWater::Bound(above),
            "a Ready frame of a higher tenure binds it over a Conflict"
        );
        assert!(bound.requests(), "a bound route admits requests");
        assert!(
            bound.response(above),
            "a bound route admits its tenure's response"
        );
        for claimant in [x, y] {
            assert!(
                !bound.response(claimant),
                "the route bound at {above:?} admits no response of the contested tenure"
            );
        }
        let announced = HighWater::merge(Some(held), frame(above, FrameKind::Candidate));
        assert_eq!(
            announced,
            HighWater::Candidate(above),
            "a Candidate frame of a higher tenure replaces a Conflict"
        );
        assert!(announced.requests(), "a candidate route admits requests");
        assert!(
            !announced.response(above),
            "a candidate route admits no response"
        );
    }
}

#[test]
fn one_host_at_one_tenure_keeps_its_route() {
    for host in contested() {
        for first in ANNOUNCES {
            for second in ANNOUNCES {
                let route = after(frame(host, first), frame(host, second));
                // A Ready frame binds the tenure, and a Candidate frame at a bound tenure keeps the binding.
                let bound = first == FrameKind::Ready || second == FrameKind::Ready;
                let expected = if bound {
                    HighWater::Bound(host)
                } else {
                    HighWater::Candidate(host)
                };
                assert_eq!(
                    route, expected,
                    "one host at one (g, a) conflicts with nothing ({first:?} then {second:?})"
                );
                assert_eq!(route.host(), Some(host.host), "the route names its host");
                assert!(route.requests(), "the route admits requests");
                assert_eq!(
                    route.response(host),
                    bound,
                    "the route admits its host's response once a Ready frame bound it"
                );
            }
        }
    }
}
