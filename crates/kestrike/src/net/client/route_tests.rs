use std::num::NonZeroU32;

use super::{Binder, Receiver, ShardRoutes};
use crate::failover::identity::Exhid;
use crate::failover::route::{FrameKind, HighWater, HolderFrame, key};
use crate::net::ownership::{
    ActivatedEpoch, OwnershipBody, Shard, ShardGeneration, Tenure, Validity, Volume, VolumeState,
};
use crate::storage::EngineBudget;
use crate::storage::seeded::SplitMix64;

fn table(capacity: u32) -> ShardRoutes {
    ShardRoutes::new(
        NonZeroU32::new(capacity).unwrap(),
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap()
}

fn moved(merged: Option<bool>) -> bool {
    merged.unwrap()
}

/// Merges a serving WrongOwner from the host `tenure` names, returning whether the route changed.
fn redirect(routes: &ShardRoutes, tenure: Tenure) -> bool {
    let body = OwnershipBody {
        responder: Some(tenure.host),
        ..reply(1, Some(tenure), VolumeState::Active, SERVING)
    };
    moved(routes.reply(&body, Receiver::Unbound))
}

fn shard() -> Shard {
    Shard::new(3).unwrap()
}

fn tenure(g: u64, a: u32, x: u8) -> Tenure {
    Tenure {
        generation: ShardGeneration::new(g).unwrap(),
        epoch: ActivatedEpoch::new(2 * a).unwrap(),
        host: Exhid::new([x; 16]).unwrap(),
    }
}

fn frame(kind: FrameKind, g: u64, a: u32, x: u8) -> HolderFrame {
    HolderFrame {
        tenure: tenure(g, a, x),
        kind,
    }
}

fn conflict(g: u64, a: u32) -> HighWater {
    HighWater::Conflict {
        generation: ShardGeneration::new(g).unwrap(),
        epoch: ActivatedEpoch::new(2 * a).unwrap(),
    }
}

fn dark(g: u64, a: u32) -> HighWater {
    HighWater::Dark {
        generation: ShardGeneration::new(g).unwrap(),
        epoch: ActivatedEpoch::new(2 * a).unwrap(),
    }
}

fn reply(x: u8, named: Option<Tenure>, state: VolumeState, validity: u8) -> OwnershipBody<'static> {
    OwnershipBody {
        shard: shard(),
        volume: Some(Volume {
            name: "vol-0123456789abcdef0",
            state,
        }),
        tenure: named,
        report_age_us: 0,
        responder: Some(Exhid::new([x; 16]).unwrap()),
        validity: Validity::new(validity).unwrap(),
    }
}

/// The session whose READY binds a route in these tests and whose newest frame may withdraw it.
const SESSION: Binder = Binder::new([7; 16], 1).unwrap();

const SERVING: u8 = Validity::REPORT | Validity::SERVING | Validity::LIVE;

#[test]
fn per_shard_high_water_transitions() {
    use FrameKind::{Candidate, Invalid, Ready, Retired};
    let bound = HighWater::Bound;
    let candidate = HighWater::Candidate;
    // Each row holds two frames and the route after `a` then `b`, then after `b` then `a`.
    let rows: [(HolderFrame, HolderFrame, HighWater, HighWater); 16] = [
        (
            frame(Candidate, 1, 2, 1),
            frame(Ready, 1, 2, 1),
            bound(tenure(1, 2, 1)),
            bound(tenure(1, 2, 1)),
        ),
        (
            frame(Ready, 1, 2, 1),
            frame(Ready, 1, 3, 1),
            bound(tenure(1, 3, 1)),
            bound(tenure(1, 3, 1)),
        ),
        (
            frame(Ready, 1, 2, 1),
            frame(Ready, 2, 1, 2),
            bound(tenure(2, 1, 2)),
            bound(tenure(2, 1, 2)),
        ),
        (
            frame(Ready, 1, 2, 1),
            frame(Candidate, 1, 3, 2),
            candidate(tenure(1, 3, 2)),
            candidate(tenure(1, 3, 2)),
        ),
        (
            frame(Ready, 1, 2, 1),
            frame(Ready, 1, 2, 2),
            conflict(1, 2),
            conflict(1, 2),
        ),
        (
            frame(Candidate, 1, 2, 1),
            frame(Candidate, 1, 2, 2),
            conflict(1, 2),
            conflict(1, 2),
        ),
        (
            frame(Ready, 1, 2, 1),
            frame(Retired, 1, 1, 1),
            dark(1, 2),
            dark(1, 1),
        ),
        (
            frame(Ready, 1, 2, 1),
            frame(Retired, 2, 1, 2),
            dark(2, 1),
            dark(2, 1),
        ),
        (
            frame(Ready, 2, 1, 2),
            frame(Retired, 1, 2, 1),
            bound(tenure(2, 1, 2)),
            bound(tenure(2, 1, 2)),
        ),
        (
            frame(Retired, 1, 2, 1),
            frame(Ready, 1, 3, 1),
            dark(1, 2),
            dark(1, 3),
        ),
        (
            frame(Ready, 1, 2, 1),
            frame(Invalid, 1, 2, 1),
            candidate(tenure(1, 2, 1)),
            bound(tenure(1, 2, 1)),
        ),
        (
            frame(Invalid, 1, 2, 1),
            frame(Ready, 1, 3, 1),
            bound(tenure(1, 3, 1)),
            bound(tenure(1, 3, 1)),
        ),
        (
            frame(Invalid, 1, 2, 1),
            frame(Candidate, 1, 2, 2),
            conflict(1, 2),
            conflict(1, 2),
        ),
        (
            frame(Invalid, 1, 3, 1),
            frame(Ready, 1, 2, 1),
            candidate(tenure(1, 3, 1)),
            candidate(tenure(1, 3, 1)),
        ),
        (
            frame(Retired, 1, 2, 1),
            frame(Invalid, 1, 3, 1),
            dark(1, 2),
            dark(1, 3),
        ),
        (
            frame(Invalid, 1, 2, 1),
            frame(Retired, 1, 1, 1),
            dark(1, 2),
            dark(1, 1),
        ),
    ];
    for (row, (a, b, ab, ba)) in rows.into_iter().enumerate() {
        for (first, second, expected) in [(a, b, ab), (b, a, ba)] {
            let routes = table(2);
            assert_eq!(
                routes.route(shard()),
                None,
                "row {row}: a shard starts with no route"
            );
            routes.observe(shard(), first);
            assert_eq!(routes.observe(shard(), second), Some(expected), "row {row}");
            assert_eq!(
                routes.route(shard()),
                Some(expected),
                "row {row}: the table keeps it"
            );
            assert_eq!(
                routes.route(Shard::new(4).unwrap()),
                None,
                "row {row}: another shard keeps no route"
            );
        }
    }
    let routes = table(1);
    routes.observe(shard(), frame(Ready, 1, 2, 1));
    assert_eq!(
        routes.observe(Shard::new(4).unwrap(), frame(Ready, 1, 2, 1)),
        None,
        "a full table routes no further shard"
    );
    assert!(!routes.admit(Shard::new(4).unwrap(), tenure(1, 2, 1), || None));
    assert!(routes.admit(shard(), tenure(1, 2, 1), || None));

    // Each chain reaches a Conflict, a Dark or a Candidate, then merges one more frame.
    let conflicted = [frame(Ready, 1, 2, 1), frame(Ready, 1, 2, 2)];
    let withdrawn = [frame(Ready, 1, 2, 1), frame(Invalid, 1, 2, 1)];
    let later_withdrawn = [frame(Ready, 2, 2, 1), frame(Invalid, 2, 2, 1)];
    let retired = [frame(Retired, 1, 2, 1)];
    let held = [frame(Candidate, 1, 3, 1)];
    let chains: [(&[HolderFrame], HolderFrame, HighWater); 20] = [
        (&conflicted, frame(Invalid, 1, 1, 1), conflict(1, 2)),
        (&conflicted, frame(Invalid, 1, 2, 1), conflict(1, 2)),
        (
            &conflicted,
            frame(Invalid, 1, 3, 1),
            candidate(tenure(1, 3, 1)),
        ),
        (
            &conflicted,
            frame(Invalid, 2, 1, 1),
            candidate(tenure(2, 1, 1)),
        ),
        (&conflicted, frame(Retired, 1, 1, 1), dark(1, 2)),
        (
            &conflicted,
            frame(Candidate, 1, 3, 3),
            candidate(tenure(1, 3, 3)),
        ),
        (&conflicted, frame(Ready, 1, 2, 1), conflict(1, 2)),
        (
            &withdrawn,
            frame(Invalid, 1, 1, 1),
            candidate(tenure(1, 2, 1)),
        ),
        (
            &withdrawn,
            frame(Invalid, 1, 3, 1),
            candidate(tenure(1, 3, 1)),
        ),
        (&withdrawn, frame(Retired, 1, 1, 1), dark(1, 2)),
        (&withdrawn, frame(Ready, 1, 2, 1), bound(tenure(1, 2, 1))),
        (&withdrawn, frame(Ready, 1, 2, 2), conflict(1, 2)),
        (&withdrawn, frame(Ready, 1, 3, 1), bound(tenure(1, 3, 1))),
        (
            &later_withdrawn,
            frame(Retired, 1, 5, 1),
            candidate(tenure(2, 2, 1)),
        ),
        (&later_withdrawn, frame(Retired, 3, 1, 1), dark(3, 1)),
        (&retired, frame(Invalid, 1, 5, 1), dark(1, 2)),
        (
            &retired,
            frame(Invalid, 2, 1, 1),
            candidate(tenure(2, 1, 1)),
        ),
        (&retired, frame(Ready, 2, 1, 2), bound(tenure(2, 1, 2))),
        (&held, frame(Invalid, 1, 2, 1), candidate(tenure(1, 3, 1))),
        (&held, frame(Invalid, 1, 3, 2), conflict(1, 3)),
    ];
    for (row, (start, next, expected)) in chains.into_iter().enumerate() {
        let routes = table(2);
        for &frame in start {
            routes.observe(shard(), frame);
        }
        assert_eq!(routes.observe(shard(), next), Some(expected), "chain {row}");
    }
}

#[test]
fn older_rejected_equal_conflicts() {
    let routes = table(2);
    assert!(routes.admit(shard(), tenure(2, 2, 1), || None));
    assert!(
        !routes.admit(shard(), tenure(2, 1, 1), || None),
        "a delayed response of a lower epoch at the same generation"
    );
    assert!(
        !routes.admit(shard(), tenure(1, 9, 1), || None),
        "a delayed response of a lower generation with a higher epoch"
    );
    assert!(!redirect(&routes, tenure(2, 1, 3)), "a WrongOwner below");
    assert!(
        !redirect(&routes, tenure(2, 2, 1)),
        "a WrongOwner at the high-water naming the bound host"
    );
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Bound(tenure(2, 2, 1)))
    );
    assert!(
        !routes.admit(shard(), tenure(2, 2, 3), || None),
        "equal (g, a) from another host"
    );
    let route = routes.route(shard()).unwrap();
    assert_eq!(route, conflict(2, 2));
    assert!(!route.requests(), "Conflict sends no request");
    for x in [1, 3] {
        assert!(
            !routes.admit(shard(), tenure(2, 2, x), || None),
            "Conflict accepts no response at its tenure, host {x}"
        );
    }
    assert_eq!(routes.route(shard()), Some(conflict(2, 2)));
    assert!(redirect(&routes, tenure(2, 3, 3)), "a WrongOwner above");
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Candidate(tenure(2, 3, 3)))
    );
    assert!(routes.admit(shard(), tenure(2, 3, 3), || None));
    assert!(
        !routes.admit(shard(), tenure(2, 2, 1), || None),
        "the conflicted tenure stays below"
    );

    // A WrongOwner naming another host at the bound (g, a) conflicts in both arrival orders.
    let routes = table(2);
    assert!(routes.admit(shard(), tenure(2, 2, 1), || None));
    assert!(redirect(&routes, tenure(2, 2, 3)));
    assert_eq!(routes.route(shard()), Some(conflict(2, 2)));
    let routes = table(2);
    assert!(redirect(&routes, tenure(2, 2, 3)));
    assert!(!routes.admit(shard(), tenure(2, 2, 1), || None));
    assert_eq!(routes.route(shard()), Some(conflict(2, 2)));
}

#[test]
fn retired_reply_goes_dark() {
    let routes = table(2);
    assert!(moved(routes.reply(
        &reply(1, Some(tenure(1, 2, 1)), VolumeState::Active, SERVING),
        Receiver::Unbound
    )));
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Candidate(tenure(1, 2, 1)))
    );
    assert!(routes.admit(shard(), tenure(1, 2, 1), || None));
    assert!(
        moved(routes.reply(&reply(1, None, VolumeState::Retired, 0), Receiver::Unbound)),
        "the retired responder names no tenure while the route holds the responder"
    );
    let route = routes.route(shard()).unwrap();
    assert_eq!(route, dark(1, 2), "the responder's generation darkens");
    assert!(!route.requests());
    assert!(!routes.admit(shard(), tenure(1, 2, 1), || None));
    assert!(!moved(routes.reply(
        &reply(1, Some(tenure(1, 3, 1)), VolumeState::Active, SERVING),
        Receiver::Unbound
    )));
    assert_eq!(
        routes.route(shard()),
        Some(dark(1, 2)),
        "a later epoch of the retired generation stays dark"
    );
    let successor = tenure(2, 1, 2);
    assert!(moved(routes.reply(
        &reply(2, Some(successor), VolumeState::Active, SERVING),
        Receiver::Unbound
    )));
    assert_eq!(routes.route(shard()), Some(HighWater::Candidate(successor)));

    // A retired responder that names its successor darkens its own generation and raises the route to the successor.
    let routes = table(2);
    assert!(routes.admit(shard(), tenure(1, 2, 1), || None));
    assert!(moved(routes.reply(
        &reply(1, Some(successor), VolumeState::Retired, 0),
        Receiver::Unbound
    )));
    assert_eq!(routes.route(shard()), Some(HighWater::Candidate(successor)));
    for delayed in [tenure(1, 2, 1), tenure(1, 3, 1)] {
        assert!(
            !routes.ready(shard(), delayed, Some(SESSION)),
            "a delayed READY below the named successor, {delayed:?}"
        );
    }

    // A successor named by a third host raises a route bound to another host.
    let routes = table(2);
    assert!(routes.admit(shard(), tenure(2, 2, 2), || None));
    assert!(moved(routes.reply(
        &reply(1, Some(tenure(3, 2, 3)), VolumeState::Retired, 0),
        Receiver::Unbound
    )));
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Candidate(tenure(3, 2, 3)))
    );
    assert!(!routes.admit(shard(), tenure(2, 2, 2), || None));

    let routes = table(2);
    assert!(moved(routes.reply(
        &reply(1, Some(tenure(1, 2, 1)), VolumeState::Retired, 0),
        Receiver::Unbound
    )));
    assert_eq!(routes.route(shard()), Some(dark(1, 2)));
    assert!(
        !moved(routes.reply(
            &reply(3, Some(tenure(1, 2, 1)), VolumeState::Retired, 0),
            Receiver::Unbound
        )),
        "another host's tenure in the retired generation stays dark"
    );

    for valid in [Validity::SERVING | Validity::LIVE, SERVING] {
        let routes = table(2);
        assert!(moved(routes.reply(
            &reply(1, Some(tenure(1, 2, 1)), VolumeState::Active, valid),
            Receiver::Unbound
        )));
        assert_eq!(
            routes.route(shard()),
            Some(HighWater::Candidate(tenure(1, 2, 1))),
            "bits {valid} assert serving and liveness"
        );
    }

    let routes = table(2);
    assert!(routes.admit(shard(), successor, || None));
    assert!(
        !moved(routes.reply(
            &reply(1, Some(successor), VolumeState::Retired, 0),
            Receiver::Unbound
        )),
        "a lagging responder's retirement leaves another host's route"
    );
    assert_eq!(routes.route(shard()), Some(HighWater::Bound(successor)));
    assert!(
        !moved(routes.reply(
            &reply(1, Some(successor), VolumeState::Active, SERVING),
            Receiver::Unbound
        )),
        "a valid reply naming another host's held tenure leaves the route"
    );
}

#[test]
fn a_not_serving_reply_withdraws_a_binding_that_a_ready_at_its_tenure_restores() {
    let own = tenure(1, 2, 1);
    for failed in [
        0,
        Validity::REPORT,
        Validity::SERVING,
        Validity::LIVE,
        Validity::REPORT | Validity::SERVING,
        Validity::REPORT | Validity::LIVE,
    ] {
        let routes = table(2);
        assert!(routes.admit(shard(), own, || Some(SESSION)));
        assert!(moved(routes.reply(
            &reply(1, Some(own), VolumeState::Active, failed),
            Receiver::Newest(own, SESSION)
        )));
        assert_eq!(
            routes.route(shard()),
            Some(HighWater::Candidate(own)),
            "bits {failed} withdraw the binding and keep the high-water"
        );
        assert!(
            !routes.admit(shard(), tenure(1, 1, 1), || None),
            "bits {failed}: a lower tenure stays refused"
        );
        assert!(
            !moved(routes.reply(
                &reply(1, Some(own), VolumeState::Active, SERVING),
                Receiver::Unbound
            )),
            "bits {failed}: a serving reply at the withdrawn tenure binds nothing"
        );
        assert!(
            routes.ready(shard(), own, Some(SESSION)),
            "bits {failed}: a READY at the withdrawn tenure binds it again"
        );
        assert_eq!(routes.route(shard()), Some(HighWater::Bound(own)));
    }
    let routes = table(2);
    assert!(routes.admit(shard(), own, || Some(SESSION)));
    routes.reply(
        &reply(1, Some(own), VolumeState::Active, 0),
        Receiver::Newest(own, SESSION),
    );
    assert!(
        !routes.admit(shard(), tenure(1, 2, 2), || None),
        "another host at the withdrawn (g, a)"
    );
    assert_eq!(routes.route(shard()), Some(conflict(1, 2)));
    let routes = table(2);
    assert!(routes.admit(shard(), own, || Some(SESSION)));
    routes.reply(
        &reply(1, Some(own), VolumeState::Active, 0),
        Receiver::Newest(own, SESSION),
    );
    assert!(moved(routes.reply(
        &reply(1, Some(tenure(1, 3, 1)), VolumeState::Active, SERVING),
        Receiver::Unbound
    )));
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Candidate(tenure(1, 3, 1))),
        "a serving reply above the withdrawn tenure raises the route"
    );
    assert!(
        !routes.admit(shard(), own, || Some(SESSION)),
        "the withdrawn tenure is below it"
    );
}

/// WITHDRAWAL-NEEDS-SESSION at the table: an invalid-flag frame withdraws a binding only when its receiver is the
/// session of the route's latest binding admission, admitted the frame as its newest, and is bound to the tenure the
/// frame names. A READY is a binding admission whether or not it moves the route; a response is one only when it
/// moves the route to Bound. The session table decides `Receiver::Newest`; `net::owner::tests` drive that decision
/// over the wire.
#[test]
fn a_withdrawal_needs_the_session_of_the_latest_binding_admission() {
    let own = tenure(1, 2, 1);
    let other = Binder::new([9; 16], 1).unwrap();
    let never = Binder::new([11; 16], 1).unwrap();
    let reopened = Binder::new([7; 16], 2).unwrap();
    let invalid = reply(1, Some(own), VolumeState::Active, Validity::REPORT);
    let withdraws = |routes: &ShardRoutes, session| {
        let moved = moved(routes.reply(&invalid, Receiver::Newest(own, session)));
        assert_eq!(
            moved,
            routes.route(shard()) == Some(HighWater::Candidate(own))
        );
        moved
    };
    let routes = table(2);
    assert!(routes.ready(shard(), own, Some(SESSION)));
    for receiver in [Receiver::Unbound, Receiver::Bound(own)] {
        assert!(
            !moved(routes.reply(&invalid, receiver)),
            "a frame the session did not admit as its newest keeps the binding: {receiver:?}"
        );
    }
    assert!(
        !withdraws(&routes, other),
        "the newest frame of a session with no binding admission keeps the binding"
    );
    let reversed = table(2);
    assert!(
        moved(reversed.reply(&invalid, Receiver::Unbound)),
        "the frame first raises an empty route to its tenure"
    );
    assert_eq!(reversed.route(shard()), Some(HighWater::Candidate(own)));
    assert!(
        reversed.ready(shard(), own, Some(SESSION)),
        "the READY then binds it"
    );
    assert!(
        routes.ready(shard(), own, Some(other)),
        "a sharing session's READY on the route already Bound"
    );
    assert_eq!(routes.route(shard()), Some(HighWater::Bound(own)));
    for receiver in [Receiver::Unbound, Receiver::Bound(own)] {
        assert!(
            !moved(routes.reply(&invalid, receiver)),
            "a frame no session admitted as its newest keeps the binding of two sessions: {receiver:?}"
        );
    }
    assert!(
        !withdraws(&routes, SESSION),
        "the first session's frame cannot undo the binding the later READY admitted"
    );
    assert!(
        !withdraws(&routes, never),
        "the newest frame of a session that never bound keeps the binding of two sessions"
    );
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Bound(own)),
        "every refused frame left the route Bound"
    );
    assert!(
        withdraws(&routes, other),
        "a sharing session that did not move the route withdraws after its own READY"
    );
    assert!(routes.ready(shard(), own, Some(SESSION)));
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Bound(own)),
        "a READY at the withdrawn tenure binds it again"
    );
    assert!(
        routes.ready(shard(), own, Some(reopened)),
        "the client reopens its session at the same tenure"
    );
    assert!(
        !withdraws(&routes, SESSION),
        "a frame of the replaced session keeps the binding"
    );
    assert!(
        withdraws(&routes, reopened),
        "the reopened session's newest frame withdraws"
    );
    assert!(
        routes.admit(shard(), own, || Some(other)),
        "a response that moves the route to Bound is a binding admission"
    );
    assert!(!withdraws(&routes, reopened));
    assert!(
        routes.admit(shard(), own, || Some(reopened)),
        "a response on the route already Bound records nothing"
    );
    assert!(!withdraws(&routes, reopened));
    assert!(withdraws(&routes, other));
    assert!(routes.ready(shard(), own, Some(SESSION)));
    let next = tenure(1, 3, 1);
    assert!(routes.ready(shard(), next, Some(SESSION)));
    assert!(
        !routes.ready(shard(), own, Some(other)),
        "a READY below the route binds nothing"
    );
    assert!(
        !moved(routes.reply(&invalid, Receiver::Newest(next, SESSION))),
        "a session bound to a later tenure admits a frame naming the earlier one"
    );
    let newer = reply(1, Some(next), VolumeState::Active, Validity::REPORT);
    assert!(
        !moved(routes.reply(&newer, Receiver::Newest(own, SESSION))),
        "a session of the earlier tenure cannot withdraw the later one"
    );
    assert!(
        !moved(routes.reply(&newer, Receiver::Newest(next, other))),
        "the refused READY recorded no binding admission"
    );
    assert_eq!(routes.route(shard()), Some(HighWater::Bound(next)));
    let foreign = reply(2, Some(tenure(1, 3, 2)), VolumeState::Active, 0);
    assert!(
        moved(routes.reply(&foreign, Receiver::Bound(next))),
        "an equal (g, a) under another host conflicts without a session"
    );
    assert_eq!(routes.route(shard()), Some(conflict(1, 3)));
    assert!(!routes.ready(shard(), next, Some(SESSION)));
}

/// A successor that retained the volume keeps its generation and raises the epoch. The deposed host's frame names
/// the volume active and the successor's tenure, so the route becomes the successor's candidate whether the frame
/// arrives outside a session or as the newest frame of the session that bound the deposed tenure. The successor's
/// READY binds it, the deposed tenure's responses are refused, a late not-serving frame of the deposed tenure keeps
/// the successor's binding, and a neighboring shard keeps its own route. For contrast, a retirement frame at the
/// deposed tenure darkens the generation and refuses the successor.
#[test]
fn a_same_generation_successor_binds_and_the_generation_stays_lit() {
    let neighbor = Shard::new(4).unwrap();
    let (old, successor) = (tenure(1, 2, 1), tenure(1, 3, 2));
    let next = Binder::new([7; 16], 2).unwrap();
    for receiver in [Receiver::Unbound, Receiver::Newest(old, SESSION)] {
        let routes = table(2);
        assert!(routes.ready(shard(), old, Some(SESSION)));
        assert!(routes.admit(neighbor, old, || Some(SESSION)));
        let deposed = reply(1, Some(successor), VolumeState::Active, 0);
        assert!(moved(routes.reply(&deposed, receiver)), "{receiver:?}");
        assert_eq!(
            routes.route(shard()),
            Some(HighWater::Candidate(successor)),
            "the deposed host's frame names the successor: {receiver:?}"
        );
        assert!(
            !routes.admit(shard(), old, || Some(SESSION)),
            "a response of the deposed tenure is refused: {receiver:?}"
        );
        assert_eq!(routes.route(shard()), Some(HighWater::Candidate(successor)));
        assert!(
            routes.ready(shard(), successor, Some(next)),
            "the successor's READY binds: {receiver:?}"
        );
        assert!(
            !moved(routes.reply(
                &reply(1, Some(old), VolumeState::Active, 0),
                Receiver::Newest(old, SESSION)
            )),
            "a late not-serving frame of the deposed tenure leaves the successor's binding: {receiver:?}"
        );
        assert_eq!(routes.route(shard()), Some(HighWater::Bound(successor)));
        assert_eq!(
            routes.route(neighbor),
            Some(HighWater::Bound(old)),
            "the neighboring shard keeps its route: {receiver:?}"
        );
    }

    let retired = table(2);
    assert!(retired.admit(shard(), old, || None));
    retired.observe(
        shard(),
        HolderFrame {
            tenure: old,
            kind: FrameKind::Retired,
        },
    );
    assert!(
        !retired.admit(shard(), successor, || None),
        "a retirement frame at the deposed tenure darkens the generation"
    );
    assert_eq!(retired.route(shard()), Some(dark(1, 2)));
}

#[test]
fn reply_resolves_the_responders_own_tenure() {
    let unbound = tenure(1, 4, 1);
    // A tenure-less invalid-flag reply darkens nothing, in both orders with the READY.
    for ready_first in [true, false] {
        let routes = table(2);
        if ready_first {
            assert!(routes.ready(shard(), unbound, Some(SESSION)));
        }
        assert!(!moved(routes.reply(
            &reply(1, None, VolumeState::Active, 0),
            Receiver::Unbound
        )));
        if !ready_first {
            assert!(routes.ready(shard(), unbound, Some(SESSION)));
        }
        assert_eq!(routes.route(shard()), Some(HighWater::Bound(unbound)));
    }

    // A retirement darkens a Conflict route when the receiving session's bound tenure identifies the responder.
    let routes = table(2);
    routes.observe(shard(), frame(FrameKind::Ready, 1, 2, 1));
    routes.observe(shard(), frame(FrameKind::Ready, 1, 2, 2));
    let retired = reply(1, None, VolumeState::Retired, 0);
    assert!(
        !moved(routes.reply(&retired, Receiver::Unbound)),
        "no tenure of the responder"
    );
    assert!(
        !moved(routes.reply(&retired, Receiver::Bound(tenure(1, 2, 2)))),
        "a bound tenure of another host"
    );
    assert!(moved(
        routes.reply(&retired, Receiver::Bound(tenure(1, 2, 1)))
    ));
    assert_eq!(routes.route(shard()), Some(dark(1, 2)));
    assert!(
        !routes.admit(shard(), tenure(1, 4, 1), || None),
        "a later epoch of the retired generation"
    );

    // A tenure-less retirement darkens a withdrawn binding through the Candidate's own tenure.
    let routes = table(2);
    routes.observe(shard(), frame(FrameKind::Ready, 1, 2, 1));
    routes.observe(shard(), frame(FrameKind::Invalid, 1, 2, 1));
    assert!(moved(routes.reply(&retired, Receiver::Unbound)));
    assert_eq!(routes.route(shard()), Some(dark(1, 2)));

    let routes = table(2);
    let mut body = reply(1, Some(tenure(1, 2, 1)), VolumeState::Active, SERVING);
    body.volume = None;
    assert!(
        moved(routes.reply(&body, Receiver::Unbound)),
        "a reply naming no volume is invalid"
    );
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Candidate(tenure(1, 2, 1)))
    );
    body.responder = None;
    assert!(
        !moved(routes.reply(&body, Receiver::Unbound)),
        "a reply without a responder"
    );

    let routes = table(1);
    assert!(routes.admit(Shard::new(4).unwrap(), tenure(1, 2, 1), || None));
    assert_eq!(routes.refused(), 0);
    for responder in [1, 2] {
        assert_eq!(
            routes.reply(
                &reply(
                    responder,
                    Some(tenure(1, 2, 1)),
                    VolumeState::Active,
                    SERVING
                ),
                Receiver::Unbound
            ),
            None,
            "a full table refuses the reply"
        );
    }
    assert_eq!((routes.held(), routes.capacity()), (1, 1));
    assert_eq!(
        routes.route(shard()),
        None,
        "the full table routes no further shard"
    );
    assert_eq!(routes.refused(), 2);

    let routes = table(2);
    assert!(
        redirect(&routes, tenure(1, 2, 1)),
        "a WrongOwner on an empty route"
    );
    routes.observe(shard(), frame(FrameKind::Retired, 1, 2, 1));
    assert!(
        !redirect(&routes, tenure(1, 4, 2)),
        "a Dark keeps a WrongOwner of its generation out"
    );
    assert_eq!(routes.route(shard()), Some(dark(1, 2)));
}

#[test]
fn shared_high_water_raised_before_surface() {
    let routes = table(2);
    let deposed = tenure(4, 1, 1);
    let successor = tenure(4, 2, 2);
    assert!(
        routes.admit(shard(), deposed, || None),
        "the first frame of the deposed response"
    );
    assert!(
        routes.admit(shard(), successor, || None),
        "the successor's response"
    );
    assert_eq!(
        routes.route(shard()),
        Some(HighWater::Bound(successor)),
        "admitting the successor's response raised the high-water"
    );
    assert!(
        !routes.admit(shard(), deposed, || None),
        "the deposed response's last byte is discarded"
    );

    for (at, schedule) in schedules().iter().enumerate() {
        assert_eq!(
            shared(schedule),
            reference(schedule),
            "schedule {at}: {schedule:?}"
        );
    }
}

/// Seeded schedules of response frames from four sessions, each a session index and that session's tenure.
fn schedules() -> Vec<Vec<(usize, Tenure)>> {
    let mut rng = SplitMix64::new(0x1178);
    (0..512)
        .map(|_| {
            let sessions: Vec<Tenure> = (0..4)
                .map(|_| {
                    let draw = rng.next_u64();
                    tenure(
                        1 + draw % 2,
                        1 + (draw >> 8) as u32 % 2,
                        1 + (draw >> 16) as u8 % 3,
                    )
                })
                .collect();
            (0..12)
                .map(|_| {
                    let at = rng.next_u64() as usize % sessions.len();
                    (at, sessions[at])
                })
                .collect()
        })
        .collect()
}

/// Admission by one maximum `(g, a)` and the hosts seen at it: a response is admitted when its tenure is that maximum
/// and one host holds it.
fn reference(schedule: &[(usize, Tenure)]) -> Vec<bool> {
    let mut top: Option<((ShardGeneration, ActivatedEpoch), Vec<Exhid>)> = None;
    schedule
        .iter()
        .map(|&(_, tenure)| {
            let at = (tenure.generation, tenure.epoch);
            match &mut top {
                Some((key, _)) if at < *key => {}
                Some((key, hosts)) if at == *key => {
                    if !hosts.contains(&tenure.host) {
                        hosts.push(tenure.host);
                    }
                }
                _ => top = Some((at, vec![tenure.host])),
            }
            let (key, hosts) = top.as_ref().unwrap();
            at == *key && hosts.len() == 1
        })
        .collect()
}

fn shared(schedule: &[(usize, Tenure)]) -> Vec<bool> {
    let routes = table(2);
    schedule
        .iter()
        .map(|&(_, tenure)| routes.admit(shard(), tenure, || None))
        .collect()
}

/// Whether `control` admits, on some schedule, a response the reference refuses whose `(g, a)` is below the highest
/// `(g, a)` the schedule has reached by then.
fn diverges(control: fn(&[(usize, Tenure)]) -> Vec<bool>) -> bool {
    schedules().iter().any(|schedule| {
        let mut top = None;
        control(schedule)
            .iter()
            .zip(reference(schedule))
            .zip(schedule)
            .any(|((&admitted, expected), &(_, tenure))| {
                let at = (tenure.generation, tenure.epoch);
                let below = top.is_some_and(|top| at < top);
                top = top.max(Some(at));
                admitted && !expected && below
            })
    })
}

/// Admits each frame of a chunk of `chunk` frames by merging it alone into the route the chunk started from, then
/// raises the route with all of them.
fn raised_after_surface(schedule: &[(usize, Tenure)], chunk: usize) -> Vec<bool> {
    let routes = table(2);
    let mut admitted = Vec::new();
    for frames in schedule.chunks(chunk) {
        let checked: Vec<bool> = frames
            .iter()
            .map(|&(_, tenure)| {
                let alone = HolderFrame {
                    tenure,
                    kind: FrameKind::Ready,
                };
                HighWater::merge(routes.route(shard()), alone).response(tenure)
            })
            .collect();
        for &(_, tenure) in frames {
            routes.admit(shard(), tenure, || None);
        }
        admitted.extend(checked);
    }
    admitted
}

#[test]
fn high_water_controls_diverge_from_the_reference() {
    let generation_only = |schedule: &[(usize, Tenure)]| {
        let routes = table(2);
        schedule
            .iter()
            .map(|&(_, tenure)| {
                let coarse = Tenure {
                    epoch: ActivatedEpoch::new(2).unwrap(),
                    ..tenure
                };
                routes.admit(shard(), coarse, || None)
            })
            .collect()
    };
    assert!(
        diverges(generation_only),
        "compare on g only admits a lower epoch of the high-water's generation"
    );
    let per_session = |schedule: &[(usize, Tenure)]| {
        let routes: Vec<ShardRoutes> = (0..4).map(|_| table(2)).collect();
        schedule
            .iter()
            .map(|&(session, tenure)| routes[session].admit(shard(), tenure, || None))
            .collect()
    };
    assert!(
        diverges(per_session),
        "a per-session high-water admits a tenure another session raised above"
    );
    for schedule in schedules() {
        assert_eq!(
            raised_after_surface(&schedule, 1),
            reference(&schedule),
            "one frame per chunk is the shared route: {schedule:?}"
        );
    }
    assert!(
        diverges(|schedule: &[(usize, Tenure)]| raised_after_surface(schedule, 2)),
        "raising after surfacing admits a response checked before a concurrent raise"
    );
}

/// Over seeded mixes of every frame kind, READY and response admission under two sessions, WrongOwner redirects and
/// ownership replies outside a session, from a bound session and as a session's newest frame, the route's `(g, a)`
/// never decreases and a response is admitted only at or above every `(g, a)` merged before it. The mixes reach the
/// session-ordered withdrawal.
#[test]
fn mixed_frames_never_admit_below_the_high_water() {
    let mut rng = SplitMix64::new(0x1178_0002);
    let mut kinds = [0u32; 7];
    let mut withdrawals = 0u32;
    for _ in 0..512 {
        let routes = table(2);
        let mut top = None;
        let mut held = None;
        for _ in 0..16 {
            let (op, t, admitted, withdrew) = mixed_frame(&routes, rng.next_u64());
            kinds[op] += 1;
            withdrawals += u32::from(withdrew);
            let at = (t.generation, t.epoch);
            assert!(
                !admitted || top.is_none_or(|top| at >= top),
                "{t:?} admitted below {top:?}"
            );
            top = top.max(Some(at));
            let now = routes
                .route(shard())
                .map(|route| (route.generation(), route.epoch()));
            assert!(now >= held, "the route fell from {held:?} to {now:?}");
            held = now;
        }
    }
    assert!(
        kinds.iter().all(|&count| count > 0),
        "every operation ran: {kinds:?}"
    );
    assert!(withdrawals > 0, "a session-ordered withdrawal ran");
}

/// One seeded operation on the shard's route. Returns the operation, its tenure, whether a response was admitted, and
/// whether an ownership reply withdrew a binding, leaving a Candidate of the tenure that was Bound.
fn mixed_frame(routes: &ShardRoutes, draw: u64) -> (usize, Tenure, bool, bool) {
    let mut t = tenure(
        1 + draw % 3,
        1 + (draw >> 8) as u32 % 3,
        1 + (draw >> 16) as u8 % 3,
    );
    let session = Binder::new([7; 16], 1 + (draw >> 44) % 2).unwrap();
    let op = ((draw >> 24) % 7) as usize;
    let before = routes.route(shard());
    let admitted = match op {
        0 => routes.admit(shard(), t, || Some(session)),
        6 => {
            routes.ready(shard(), t, Some(session));
            false
        }
        1 => {
            redirect(routes, t);
            false
        }
        2..=4 => {
            let kind = [FrameKind::Retired, FrameKind::Invalid, FrameKind::Candidate][op - 2];
            routes.observe(shard(), HolderFrame { tenure: t, kind });
            false
        }
        _ => {
            let state = if draw >> 32 & 1 == 0 {
                VolumeState::Active
            } else {
                VolumeState::Retired
            };
            let bits = (draw >> 33) as u8 & Validity::ALL;
            let responder = 1 + (draw >> 36) as u8 % 3;
            let mut body = reply(responder, Some(t), state, bits);
            let receiver = match ((draw >> 46) % 4, before) {
                (0, _) => Receiver::Unbound,
                (1, _) => Receiver::Bound(t),
                // Half the newest frames answer for the route's own binding, so the session rule decides them.
                (2, Some(HighWater::Bound(bound))) => {
                    t = bound;
                    body.tenure = Some(bound);
                    body.responder = Some(bound.host);
                    Receiver::Newest(bound, session)
                }
                _ => Receiver::Newest(t, session),
            };
            routes.reply(&body, receiver);
            false
        }
    };
    let withdrew = op == 5
        && matches!(
            (before, routes.route(shard())),
            (Some(HighWater::Bound(bound)), Some(HighWater::Candidate(now))) if bound == now
        );
    (op, t, admitted, withdrew)
}

fn record_slot(routes: &ShardRoutes, recorded: &mut Vec<Option<(u64, [u64; 2])>>) {
    let held = routes
        .find(shard())
        .ok()
        .and_then(|at| routes.lock().entries[at].route);
    let expected = match held {
        Some(HighWater::Bound(t)) => Some((key(t.generation, t.epoch), super::words(t.host))),
        Some(HighWater::Candidate(t)) => Some((
            key(t.generation, t.epoch) | super::CANDIDATE,
            super::words(t.host),
        )),
        _ => None,
    };
    assert_eq!(
        routes.published(shard()),
        expected,
        "the slot records {held:?}"
    );
    assert_eq!(
        expected.and_then(|(session, host)| super::recorded(session, host)),
        held.filter(|_| expected.is_some()),
        "the recorded words decode to the route"
    );
    if recorded.last() != Some(&expected) {
        recorded.push(expected);
    }
}

#[test]
fn the_slot_records_the_bound_tenure_and_its_sessions_never_fall() {
    let mut rng = SplitMix64::new(0x1178_0003);
    let (mut bindings, mut rebinds, mut republished) = (0u32, 0u32, 0u32);
    for _ in 0..512 {
        let routes = table(2);
        let mut recorded = Vec::new();
        for _ in 0..16 {
            let draw = rng.next_u64();
            mixed_frame(&routes, draw);
            record_slot(&routes, &mut recorded);
            if draw >> 40 & 3 == 0
                && let Some(HighWater::Bound(t)) = routes.route(shard())
            {
                routes.observe(
                    shard(),
                    HolderFrame {
                        tenure: t,
                        kind: FrameKind::Invalid,
                    },
                );
                record_slot(&routes, &mut recorded);
                assert!(routes.admit(shard(), t, || None), "{t:?} binds again");
                record_slot(&routes, &mut recorded);
            }
        }
        let published: Vec<(u64, [u64; 2])> = recorded.into_iter().flatten().collect();
        bindings += published.len() as u32;
        rebinds += published.len().saturating_sub(1) as u32;
        let held = |word: u64| word & !super::CANDIDATE;
        republished += published
            .windows(2)
            .filter(|pair| held(pair[0].0) == held(pair[1].0))
            .count() as u32;
        assert!(
            published
                .windows(2)
                .all(|pair| held(pair[0].0) < held(pair[1].0)
                    || (held(pair[0].0) == held(pair[1].0) && pair[0].1 == pair[1].1)),
            "each publish has a higher (g, a) or the same tenure whole: {published:x?}"
        );
    }
    assert!(
        bindings > 0 && rebinds > 0 && republished > 0,
        "the mixes bind, rebind and republish: {bindings} bindings, {rebinds} rebinds, {republished} republished"
    );
}

/// Readers that take the route without the lock while a writer rebinds it must see each binding whole and never fall
/// behind a raise they saw complete. The writer rotates three hosts, so a torn read shows as a host that never held its
/// session, and every fourth step makes a Conflict, which clears the session without host stores.
/// A serving reply that names the tenure of a completed raise must report the route unchanged, because the route is
/// at or above that tenure from then on.
#[test]
fn lock_free_reads_take_whole_bindings_at_or_above_a_completed_raise() {
    use std::sync::atomic::{AtomicU32, Ordering};

    const RAISES: u32 = 50_000;
    let bound = |step: u32| tenure(1, step, 1 + (step % 3) as u8);
    /// Ends the readers when the writer unwinds, so a failed writer assertion fails the test.
    struct Finish<'a>(&'a AtomicU32);
    impl Drop for Finish<'_> {
        fn drop(&mut self) {
            self.0.store(RAISES, Ordering::Release);
        }
    }

    let routes = table(2);
    let raised = AtomicU32::new(0);
    std::thread::scope(|scope| {
        for _ in 0..3 {
            scope.spawn(|| {
                let mut reads = 0u64;
                loop {
                    let seen = raised.load(Ordering::Acquire);
                    if let Some(HighWater::Bound(t)) = routes.route(shard()) {
                        let step = t.epoch.get() / 2;
                        assert_eq!(t, bound(step), "a bound tenure the writer published whole");
                        assert!(
                            step >= seen,
                            "step {step} is below the completed raise {seen}"
                        );
                    }
                    if seen > 1 {
                        assert!(
                            !routes.admit(shard(), bound(seen - 1), || None),
                            "a tenure below the completed raise {seen} admits"
                        );
                    }
                    if seen > 0 {
                        let named = bound(seen);
                        let serving = OwnershipBody {
                            responder: Some(named.host),
                            ..reply(1, Some(named), VolumeState::Active, SERVING)
                        };
                        assert_eq!(
                            routes.reply(&serving, Receiver::Bound(named)),
                            Some(false),
                            "a serving reply at the completed raise {seen} changes the route"
                        );
                    }
                    reads += 1;
                    if seen == RAISES {
                        return reads;
                    }
                }
            });
        }
        let _finish = Finish(&raised);
        for step in 1..=RAISES {
            assert!(
                routes.admit(shard(), bound(step), || None),
                "step {step} binds"
            );
            if step % 4 == 2 {
                routes.observe(
                    shard(),
                    HolderFrame {
                        tenure: bound(step),
                        kind: FrameKind::Invalid,
                    },
                );
                assert_eq!(
                    routes.route(shard()),
                    Some(HighWater::Candidate(bound(step)))
                );
                assert!(
                    routes.admit(shard(), bound(step), || None),
                    "step {step} binds again"
                );
            }
            if step % 4 == 0 {
                let other = tenure(1, step, 1 + ((step + 1) % 3) as u8);
                routes.observe(
                    shard(),
                    HolderFrame {
                        tenure: other,
                        kind: FrameKind::Candidate,
                    },
                );
                assert_eq!(routes.route(shard()), Some(conflict(1, step)));
            }
            raised.store(step, Ordering::Release);
        }
    });
}

#[test]
fn the_slot_keeps_exactly_the_frames_whose_merge_returns_the_held_route() {
    let tenures: Vec<Tenure> = (1..=3)
        .flat_map(|g| (0..3).flat_map(move |a| (1..=3).map(move |x| tenure(g, a, x))))
        .collect();
    let (mut kept, mut changed, mut refused) = (0u32, 0u32, 0u32);
    for &held in &tenures {
        let bound = held.epoch.is_activated().then_some(HighWater::Bound(held));
        for route in bound.into_iter().chain([HighWater::Candidate(held)]) {
            let slot = super::Binding::<std::sync::atomic::AtomicU64>::default();
            slot.publish(route);
            let published = slot.read().unwrap();
            assert_eq!(super::recorded(published.0, published.1), Some(route));
            for &named in &tenures {
                let merge = |kind| {
                    HighWater::merge(
                        Some(route),
                        HolderFrame {
                            tenure: named,
                            kind,
                        },
                    )
                };
                let keeps = super::kept(published, named);
                assert_eq!(
                    keeps,
                    merge(FrameKind::Candidate) == route,
                    "a candidate at {named:?} on {route:?}"
                );
                kept += u32::from(keeps);
                changed += u32::from(!keeps);
                if !named.epoch.is_activated() {
                    continue;
                }
                let below = key(named.generation, named.epoch) < published.0 & !super::CANDIDATE;
                let ready = merge(FrameKind::Ready);
                assert_eq!(
                    below,
                    ready == route && !ready.response(named),
                    "a READY at {named:?} on {route:?}"
                );
                refused += u32::from(below);
            }
        }
    }
    assert!(
        kept > 0 && changed > 0 && refused > 0,
        "{kept} kept, {changed} changed, {refused} refused"
    );
}

/// The slot decides a frame the route's tenure keeps, so each one answers before the lock is released. Raising the
/// route takes the lock, so a reply that names a higher tenure answers only after the release.
#[test]
fn kept_frames_return_while_another_thread_holds_the_table_lock() {
    use std::sync::mpsc;
    use std::time::Duration;

    let routes = table(2);
    let (deposed, bound, successor) = (tenure(4, 1, 1), tenure(4, 2, 2), tenure(4, 3, 3));
    let (found, lower) = (tenure(6, 2, 2), tenure(6, 1, 2));
    let other = Shard::new(4).unwrap();
    assert!(routes.ready(shard(), bound, Some(SESSION)));
    let serving = reply(2, Some(bound), VolumeState::Active, SERVING);
    let idle = reply(2, Some(bound), VolumeState::Active, Validity::REPORT);
    let redirect = reply(1, Some(bound), VolumeState::Active, 0);
    let raising = reply(3, Some(successor), VolumeState::Active, SERVING);
    let discovery = OwnershipBody {
        shard: other,
        ..reply(2, Some(found), VolumeState::Active, SERVING)
    };
    assert_eq!(routes.reply(&discovery, Receiver::Unbound), Some(true));
    assert_eq!(routes.route(other), Some(HighWater::Candidate(found)));
    let (sent, received) = mpsc::channel();
    std::thread::scope(|scope| {
        let held = routes.lock();
        scope.spawn(|| {
            let kept = vec![
                routes.reply(&serving, Receiver::Bound(bound)),
                routes.reply(&idle, Receiver::Bound(bound)),
                routes.reply(&redirect, Receiver::Bound(deposed)),
                Some(routes.admit(shard(), deposed, || None)),
                Some(routes.admit(shard(), bound, || None)),
                routes.reply(&discovery, Receiver::Unbound),
                Some(routes.admit(other, lower, || None)),
                Some(routes.route(other) == Some(HighWater::Candidate(found))),
            ];
            sent.send(kept).unwrap();
            sent.send(vec![routes.reply(&raising, Receiver::Unbound)])
                .unwrap();
        });
        let kept = received.recv_timeout(Duration::from_secs(30));
        let waiting = received.recv_timeout(Duration::from_millis(200));
        drop(held);
        assert_eq!(
            kept,
            Ok(vec![
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(true),
                Some(false),
                Some(false),
                Some(true),
            ]),
            "the slot decides each kept frame while the lock is held"
        );
        assert!(
            waiting.is_err(),
            "a reply that raises the route waits for the lock"
        );
    });
    assert_eq!(received.recv(), Ok(vec![Some(true)]));
    assert_eq!(routes.route(shard()), Some(HighWater::Candidate(successor)));
}

/// KEPT-WITHOUT-LOCK requires every ownership frame decided by the slot to leave the route unchanged under
/// `merge_reply`.
#[test]
fn a_reply_returns_what_the_locked_merge_returns() {
    let held = tenure(2, 2, 1);
    let elsewhere = tenure(3, 1, 2);
    let other = Binder::new([9; 16], 1).unwrap();
    let tenures =
        (1..=3).flat_map(|g| (1..=3).flat_map(move |a| (1..=2).map(move |x| tenure(g, a, x))));
    let named: Vec<Option<Tenure>> = std::iter::once(None).chain(tenures.map(Some)).collect();
    let receivers = [
        Receiver::Unbound,
        Receiver::Bound(held),
        Receiver::Bound(elsewhere),
        Receiver::Newest(held, SESSION),
        Receiver::Newest(held, other),
        Receiver::Newest(elsewhere, SESSION),
    ];
    let validities = [
        0,
        Validity::REPORT,
        Validity::REPORT | Validity::SERVING,
        Validity::SERVING | Validity::LIVE,
        SERVING,
    ];
    let volumes = [None, Some(VolumeState::Active), Some(VolumeState::Retired)];
    let primed = |bound: bool, latest: Option<Binder>| {
        let routes = table(2);
        assert!(routes.ready(shard(), held, latest));
        if !bound {
            routes.observe(shard(), frame(FrameKind::Invalid, 2, 2, 1));
        }
        routes
    };
    let (mut kept, mut withdrawn, mut darkened, mut raised) = (0u32, 0u32, 0u32, 0u32);
    for (bound, latest) in [
        (true, None),
        (true, Some(SESSION)),
        (true, Some(other)),
        (false, None),
        (false, Some(SESSION)),
    ] {
        let before = match bound {
            true => HighWater::Bound(held),
            false => HighWater::Candidate(held),
        };
        for &tenure in &named {
            for responder in [1, 2] {
                for state in volumes {
                    for validity in validities {
                        let mut body = reply(responder, tenure, VolumeState::Active, validity);
                        body.volume = state.map(|state| Volume {
                            name: "vol-0123456789abcdef0",
                            state,
                        });
                        let host = body.responder.unwrap();
                        for receiver in receivers {
                            let (slot, locked) = (primed(bound, latest), primed(bound, latest));
                            assert_eq!(slot.route(shard()), Some(before));
                            let case = format!(
                                "{body:?} to {receiver:?} on {before:?} bound by {latest:?}"
                            );
                            assert_eq!(
                                slot.reply(&body, receiver),
                                locked.merge_reply(&body, host, &receiver),
                                "reply and the locked merge return the same value: {case}"
                            );
                            let after = locked.route(shard()).unwrap();
                            assert_eq!(slot.route(shard()), Some(after), "{case}");
                            kept += u32::from(after == before);
                            withdrawn += u32::from(bound && after == HighWater::Candidate(held));
                            darkened += u32::from(matches!(after, HighWater::Dark { .. }));
                            raised += u32::from(after.host() == Some(elsewhere.host));
                        }
                    }
                }
            }
        }
    }
    assert!(
        kept > 0 && withdrawn > 0 && darkened > 0 && raised > 0,
        "{kept} kept, {withdrawn} withdrawn, {darkened} darkened, {raised} raised"
    );
}

#[test]
fn the_table_charges_its_budget() {
    let capacity = NonZeroU32::new(4).unwrap();
    let charge = ShardRoutes::charge(capacity);
    assert_eq!(
        charge,
        8 * (size_of::<super::Slot>() + size_of::<super::Entry>()),
        "four routes take a power-of-two table at least twice their count"
    );
    let mut budget = EngineBudget::new(charge - 1);
    assert!(ShardRoutes::new(capacity, &mut budget).is_err());
    assert_eq!(budget.used(), 0, "a refusal leaves the budget");
    let mut budget = EngineBudget::new(charge);
    let routes = ShardRoutes::new(capacity, &mut budget).unwrap();
    assert_eq!(budget.used(), charge);
    assert_eq!((routes.held(), routes.capacity()), (0, 4));
}
