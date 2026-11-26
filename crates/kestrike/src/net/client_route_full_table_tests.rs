//! A full table refuses the frames of every shard outside it;
//! `ShardRoutes::refused` counts those frames.
//!
//! The scenario fills a `ShardRoutes` table of capacity 2 with the READYs of two shards, then sends it three
//! frames for a third shard: a READY (`ready`), a response (`admit`) and an ownership reply that names its
//! responder (`reply`). It checks each frame's result right after the frame: the frame is refused, the third
//! shard has no route and no slot, the table still holds 2 routes and `refused()` rose by one. A later READY of
//! a higher tenure for a held shard still raises that shard's route. The control sends the same frames to a
//! table of capacity 3, which is not full: it gives the third shard a route and refuses nothing.

use std::num::NonZeroU32;

use super::client::route::{Binder, Receiver, ShardRoutes};
use super::ownership::{
    ActivatedEpoch, OwnershipBody, Shard, ShardGeneration, Tenure, Validity, Volume, VolumeState,
};
use crate::failover::identity::Exhid;
use crate::failover::route::HighWater;
use crate::storage::EngineBudget;

/// The session whose READYs and responses the table merges.
const SESSION: Binder = Binder::new([7; 16], 1).unwrap();

fn table(capacity: u32) -> ShardRoutes {
    ShardRoutes::new(
        NonZeroU32::new(capacity).expect("a capacity above zero"),
        &mut EngineBudget::new(1 << 20),
    )
    .expect("a table within the budget")
}

fn shard(n: u32) -> Shard {
    Shard::new(n).expect("a shard")
}

/// The tenure of generation `g` and activation `a` at the host whose identity bytes are all `x`.
fn tenure(g: u64, a: u32, x: u8) -> Tenure {
    Tenure {
        generation: ShardGeneration::new(g).expect("a generation"),
        epoch: ActivatedEpoch::new(2 * a).expect("an activated epoch"),
        host: Exhid::new([x; 16]).expect("a host identity"),
    }
}

/// A serving ownership reply for `shard` in which the host of `tenure` names itself as the responder.
fn serving_reply(shard: Shard, tenure: Tenure) -> OwnershipBody<'static> {
    OwnershipBody {
        shard,
        volume: Some(Volume {
            name: "vol-0123456789abcdef0",
            state: VolumeState::Active,
        }),
        tenure: Some(tenure),
        report_age_us: 0,
        responder: Some(tenure.host),
        validity: Validity::new(Validity::REPORT | Validity::SERVING | Validity::LIVE)
            .expect("a validity"),
    }
}

/// A table of `capacity` routes that holds the routes of shards 3 and 4, each bound by a READY.
fn table_holding_two(capacity: u32) -> ShardRoutes {
    let routes = table(capacity);
    assert!(
        routes.ready(shard(3), tenure(1, 1, 1), Some(SESSION)),
        "the first shard's READY binds"
    );
    assert!(
        routes.ready(shard(4), tenure(1, 1, 2), Some(SESSION)),
        "the second shard's READY binds"
    );
    assert_eq!(
        (routes.held(), routes.capacity(), routes.refused()),
        (2, capacity as usize, 0),
        "the table holds two routes and has refused nothing"
    );
    routes
}

/// What the table says of the third shard and of itself: the shard's route, its slot, the routes held and the
/// frames refused.
fn standing(routes: &ShardRoutes, third: Shard) -> (Option<HighWater>, Option<usize>, usize, u64) {
    (
        routes.route(third),
        routes.slot(third),
        routes.held(),
        routes.refused(),
    )
}

/// A table of capacity 2 that holds two shards refuses a READY, a response and an ownership reply for a third
/// shard, gives that shard no route and no slot, and counts each refused frame. A table that admitted an
/// n + 1st shard would bind the READY: `ready` would return true and the shard would have a route.
#[test]
fn a_full_table_refuses_every_frame_of_a_shard_outside_it() {
    let routes = table_holding_two(2);
    let (third, at) = (shard(5), tenure(1, 1, 3));

    let bound = routes.ready(third, at, Some(SESSION));
    assert!(
        !bound,
        "the full table refuses the READY of a shard outside it"
    );
    assert_eq!(
        standing(&routes, third),
        (None, None, 2, 1),
        "after the refused READY the shard has no route and no slot, the table holds 2 routes and \
         refused() counts the frame"
    );

    let admitted = routes.admit(third, at, || Some(SESSION));
    assert!(
        !admitted,
        "the full table refuses the response of a shard outside it"
    );
    assert_eq!(
        standing(&routes, third),
        (None, None, 2, 2),
        "after the refused response the shard has no route and no slot, the table holds 2 routes and \
         refused() counts the frame"
    );

    let merged = routes.reply(&serving_reply(third, at), Receiver::Unbound);
    assert_eq!(
        merged, None,
        "the full table refuses the ownership reply of a shard outside it"
    );
    assert_eq!(
        standing(&routes, third),
        (None, None, 2, 3),
        "after the refused reply the shard has no route and no slot, the table holds 2 routes and \
         refused() counts the frame"
    );

    let higher = tenure(1, 2, 1);
    assert!(
        routes.ready(shard(3), higher, Some(SESSION)),
        "a held shard's later READY still merges"
    );
    assert_eq!(
        routes.route(shard(3)),
        Some(HighWater::Bound(higher)),
        "the higher tenure raised the held shard's route"
    );
    assert_eq!(
        (routes.held(), routes.refused()),
        (2, 3),
        "a frame of a held shard is not refused"
    );
}

/// The control: the same three frames reach a table of capacity 3 that holds two shards. The table is not
/// full, so the READY binds the third shard's route, the response is admitted, the reply merges, and
/// `refused()` stays 0.
#[test]
fn a_table_with_room_gives_the_third_shard_a_route() {
    let routes = table_holding_two(3);
    let (third, at) = (shard(5), tenure(1, 1, 3));

    assert!(
        routes.ready(third, at, Some(SESSION)),
        "the READY binds the third shard"
    );
    let (route, slot, held, refused) = standing(&routes, third);
    assert_eq!(
        route,
        Some(HighWater::Bound(at)),
        "the third shard has its route"
    );
    assert!(slot.is_some(), "the third shard has a slot");
    assert_eq!(
        (held, refused),
        (3, 0),
        "the table holds 3 routes and refused nothing"
    );

    assert!(
        routes.admit(third, at, || Some(SESSION)),
        "the response is admitted"
    );
    let merged = routes.reply(&serving_reply(third, at), Receiver::Unbound);
    assert!(
        merged.is_some(),
        "the reply is merged, not refused: {merged:?}"
    );
    assert_eq!(
        standing(&routes, third),
        (Some(HighWater::Bound(at)), slot, 3, 0),
        "the route stands and nothing was refused"
    );
}
