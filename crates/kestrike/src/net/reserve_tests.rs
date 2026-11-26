//! Owner start refuses PUT caps that leave less than the GET reserves, and PUTs that saturate their caps leave each reserve to GETs.

use std::cell::Cell;
use std::rc::Rc;

use crate::storage::EngineBudget;
use crate::storage::owner_fixture::{arena, storage};

use super::datagram::PeerId;
use super::fetch::Outcome;
use super::frame::{Header, Kind, Status};
use super::geometry::FRAGMENT_LEN;
use super::link::{Faults, network};
use super::owner::{OwnerConfig, OwnerError};
use super::owner_tests::{OWNER, PRINCIPALS, TestOwner, payload, pool};
use super::put::PutConfig;
use super::put_tests::{Scene, error, request, scene_with, send_all, start_owner, upload_at};
use super::requests::GENERATION_LIMIT;

/// Saturation states an audited history reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Reached {
    /// Live PUTs, active and draining, equal the global PUT cap.
    pub(super) put_cap: bool,
    /// A peer's live PUTs equal the per-peer PUT cap.
    pub(super) peer_put_cap: bool,
    /// A peer's live records fill its share.
    pub(super) full_share: bool,
    /// Every request slot is live or retired.
    pub(super) full_table: bool,
}

pub(super) fn audit(owner: &TestOwner<'_, '_, '_>, config: &OwnerConfig, reached: &Cell<Reached>) {
    let core = owner.put_occupancy();
    let records = &core.records;
    assert_eq!(
        &core.peers, records,
        "each peer's PUT count is its PUT records"
    );
    assert_eq!(
        core.live,
        records.iter().sum::<u32>(),
        "live PUTs are the PUT records"
    );
    assert_eq!(
        core.live as usize + core.free_lanes,
        config.put.puts as usize
    );
    assert!(core.live <= config.put.puts, "{core:?}");
    assert!(
        core.peers.iter().all(|&puts| puts <= config.put.peer_puts),
        "a peer's live PUTs stay within the peer PUT cap: {core:?}"
    );
    let put = owner.put_report();
    assert_eq!(put.refused_lane_guard, 0, "every live PUT holds a lane");
    assert_eq!(
        put.refused_live,
        put.refused_global_cap
            + put.refused_peer_share
            + put.refused_get_backlog
            + put.refused_lane_guard
    );
    let serve = owner.serve_report();
    let pressure = serve.refused_pressure;
    assert_eq!(
        pressure.busy + pressure.peer + pressure.table,
        serve.refused_of(super::frame::Status::RequestPressure),
        "{serve:?}"
    );
    let mut seen = reached.get();
    seen.put_cap |= core.live == config.put.puts;
    seen.peer_put_cap |= core.peers.contains(&config.put.peer_puts);
    for (peer, &puts) in records.iter().enumerate() {
        let census = owner.peer_census(PeerId(peer as u16));
        let live = census.active + census.draining;
        if live == config.peer_requests {
            seen.full_share = true;
            assert!(
                live - puts >= config.peer_get_reserve,
                "peer {peer}: {census:?}"
            );
        }
    }
    let census = owner.census();
    if census.live() + census.retired == config.request_slots {
        seen.full_table = true;
        assert!(
            census.live() - core.live + census.retired >= config.get_reserve,
            "{census:?} beside {core:?}"
        );
    }
    reached.set(seen);
}

pub(super) fn audited(scene: &mut Scene<'_, '_>, config: OwnerConfig) -> Rc<Cell<Reached>> {
    let reached = Rc::new(Cell::new(Reached::default()));
    let seen = Rc::clone(&reached);
    scene.audit = Some(Box::new(move |owner| audit(owner, &config, &seen)));
    reached
}

fn started(config: OwnerConfig) -> Result<(), (OwnerError, bool)> {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let (_a, first, _net_a) = network(64, 8384, 94, [Faults::default(); 2]);
    let (_b, second, _net_b) = network(64, 8384, 95, [Faults::default(); 2]);
    match start_owner(
        &storage,
        &buffers,
        &receive,
        vec![first, second],
        config,
        &PRINCIPALS,
        super::auth::os_entropy,
    ) {
        Ok(_) => Ok(()),
        Err((error, budget)) => Err((error, budget == EngineBudget::new(1 << 26))),
    }
}

fn reserving(get_reserve: u32, peer_get_reserve: u32, puts: u32, peer_puts: u32) -> OwnerConfig {
    OwnerConfig {
        get_reserve,
        peer_get_reserve,
        put: PutConfig {
            puts,
            peer_puts,
            run_waiters: puts,
            ..OWNER.put
        },
        ..OWNER
    }
}

#[test]
fn start_refuses_every_reserve_that_leaves_puts_too_few_slots_and_admits_each_exact_fit() {
    assert_eq!(
        (OWNER.request_slots, OWNER.peer_requests, PRINCIPALS.len()),
        (4, 2, 2)
    );
    let admitted = [
        reserving(1, 1, 2, 1),
        reserving(2, 1, 2, 1),
        reserving(4, 1, 0, 0),
        reserving(4, 2, 0, 0),
        reserving(3, 2, 1, 0),
    ];
    for config in admitted {
        assert_eq!(started(config), Ok(()), "{config:?}");
    }
    let refused = [
        reserving(0, 1, 2, 1),
        reserving(1, 0, 2, 1),
        reserving(3, 1, 2, 1),
        reserving(1, 2, 2, 1),
        reserving(4, 1, 1, 0),
        reserving(5, 1, 0, 0),
        reserving(1, 3, 0, 0),
        reserving(u32::MAX, 1, 0, 0),
    ];
    for config in refused {
        assert_eq!(
            started(config),
            Err((OwnerError::GetReserve, true)),
            "{config:?}"
        );
    }
    let one_record_share = OwnerConfig {
        peer_requests: 1,
        ..reserving(1, 1, 2, 1)
    };
    assert_eq!(
        started(one_record_share),
        Err((OwnerError::GetReserve, true)),
        "a one-record share leaves an upload no room beside the peer's reserve"
    );
    assert_eq!(
        started(reserving(1, 1, 5, 1)),
        Err((OwnerError::Puts, true)),
        "the PUT shape refuses before the reserves"
    );
}

const ZERO_PEER_CAP: OwnerConfig = OwnerConfig {
    request_slots: 2,
    peer_requests: 1,
    get_reserve: 1,
    peer_get_reserve: 1,
    put: PutConfig {
        puts: 1,
        peer_puts: 0,
        run_waiters: 1,
        ..OWNER.put
    },
    ..OWNER
};

#[test]
fn a_zero_peer_put_cap_starts_refuses_every_begin_under_request_pressure_and_serves_gets() {
    zero_peer_cap(ZERO_PEER_CAP);
}

/// The zero-cap audit detects the live PUT that [`OWNER`] admits under its per-peer PUT cap of one.
#[test]
#[should_panic(expected = "a peer's live PUTs stay within the peer PUT cap")]
fn negative_control_a_peer_put_cap_of_one_starts_a_begin_the_zero_cap_refuses() {
    zero_peer_cap(OWNER);
}

/// Runs the owner under `run`, audits every turn against `run` with a zero per-peer PUT cap, and sends each peer a
/// fresh BEGIN, which must be refused under request pressure, and then a GET it serves.
fn zero_peer_cap(run: OwnerConfig) {
    let judged = OwnerConfig {
        put: PutConfig {
            peer_puts: 0,
            ..run.put
        },
        ..run
    };
    scene_with(run, &PRINCIPALS, |mut scene| {
        let reached = audited(&mut scene, judged);
        for peer in [0, 1] {
            // The refused BEGIN settles its wire identity, so it takes a slot
            // the client's GET below leaves alone.
            let begin = scene.frame(peer, Kind::PutBegin, request(3, 1), 5, |_| {});
            assert_eq!(
                error(&scene.one(peer, &begin)),
                Some(Status::RequestPressure),
                "peer {peer}"
            );
            assert_eq!(
                scene.read(peer, 1, 0),
                (Some(Outcome::Complete), payload(1000, 1))
            );
        }
        assert_eq!(scene.owner.put_report().refused_live, 2);
        assert_eq!(scene.owner.put_report().refused_peer_share, 2);
        assert_eq!(scene.owner.put_report().begun, 0);
        assert!(reached.get().full_share, "a peer's GET filled its share");
    });
}

#[test]
fn saturated_put_caps_with_a_timed_out_draining_put_leave_each_peer_a_get_inside_its_reserve() {
    scene_with(OWNER, &PRINCIPALS, |mut scene| {
        let reached = audited(&mut scene, OWNER);
        let object = payload(2 * FRAGMENT_LEN as usize, 61);
        let (at, serial) = upload_at(&mut scene, request(3, 1), &object, 30);
        let writes = send_all(&mut scene, at, serial, &object, 0..2);
        for &token in &writes {
            scene.control.hold(token);
        }
        while scene.owner.put_report().failed_timed_out == 0 {
            scene.turns(1);
            assert!(scene.turn < 5_000, "the upload's deadline passed");
        }
        assert_eq!(
            scene.live(),
            1,
            "the timed-out upload drains its held writes"
        );
        scene.replies(1);
        scene.begin(0, request(3, 1), 6);
        assert_eq!(scene.owner.put_report().live_peak, 2);
        for peer in [0, 1] {
            let begin = scene.frame(peer, Kind::PutBegin, request(2, 1), 7, |_| {});
            assert_eq!(
                error(&scene.one(peer, &begin)),
                Some(Status::RequestPressure),
                "peer {peer}"
            );
        }
        for peer in [1, 0] {
            assert_eq!(
                scene.read(peer, 1, 0),
                (Some(Outcome::Complete), payload(1000, 1)),
                "peer {peer}'s GET is admitted inside its reserve"
            );
        }
        assert_eq!(scene.live(), 2, "both PUTs stay charged");
        for &token in &writes {
            scene.control.release(token);
        }
        scene.turns(20);
        assert_eq!(
            scene.live(),
            1,
            "the timed-out upload released at its writes' end"
        );
        scene.refresh(1);
        scene.begin(1, request(3, 2), 8);
        let seen = reached.get();
        assert!(
            seen.put_cap && seen.peer_put_cap && seen.full_share,
            "{seen:?}"
        );
    });
}

fn gets_beside_saturated_puts(retired: bool) -> (u32, Vec<Status>, u32, Reached) {
    let config = reserving(2, 1, 2, 1);
    let mut result = None;
    scene_with(config, &PRINCIPALS, |mut scene| {
        let reached = audited(&mut scene, config);
        if retired {
            scene.owner.start_request_slot_at(0, GENERATION_LIMIT);
            assert_eq!(
                scene.read(0, 1, 0),
                (Some(Outcome::Complete), payload(1000, 1))
            );
            assert_eq!(scene.owner.census().retired, 1);
            scene.refresh(0);
        }
        scene.begin(0, request(3, 1), 5);
        scene.begin(1, request(3, 1), 6);
        let gets: [(usize, Header); 2] =
            [1, 0].map(|peer| (peer, scene.get(peer, request(2, 1), 1)));
        for (peer, get) in &gets {
            scene.inject(*peer, get);
            scene.polls(2);
        }
        let census = scene.owner.census();
        let refused = scene
            .sent(0)
            .iter()
            .filter(|header| header.kind == Kind::Error && header.request == request(2, 1))
            .filter_map(|header| Status::from_wire(header.status))
            .collect();
        let puts = scene.owner.put_occupancy().live;
        result = Some((census.live() - puts, refused, census.retired, reached.get()));
    });
    result.expect("the scene ran")
}

/// Asserts that a run of [`gets_beside_saturated_puts`] that holds `gets` GETs and refused `refused` admitted both
/// GETs of the reserve.
fn every_reserved_get_admitted(gets: u32, refused: &[Status]) {
    assert_eq!(
        (gets, refused),
        (2, [].as_slice()),
        "saturated PUT caps leave both GETs of the reserve admitted"
    );
}

#[test]
fn one_retired_slot_shrinks_the_get_headroom_beside_saturated_puts_by_exactly_one() {
    let (gets, refused, retired, reached) = gets_beside_saturated_puts(false);
    every_reserved_get_admitted(gets, &refused);
    assert_eq!(retired, 0, "no slot is retired");
    let config = reserving(2, 1, 2, 1);
    assert_eq!(gets, config.get_reserve);
    assert_eq!(gets, config.request_slots - config.put.puts);
    assert!(reached.full_table && reached.put_cap, "{reached:?}");
    let (gets, refused, retired, reached) = gets_beside_saturated_puts(true);
    assert_eq!(
        (gets, refused, retired),
        (1, vec![Status::RequestPressure], 1),
        "the retired slot takes one GET slot"
    );
    assert!(reached.full_table && reached.put_cap, "{reached:?}");
}

/// The control for the GET reserve: a retired slot beside the saturated PUTs takes one GET slot, so one of the two
/// GETs is refused under request pressure, as a table that answers pressure with one slot still free refuses it.
#[test]
#[should_panic(expected = "saturated PUT caps leave both GETs of the reserve admitted")]
fn negative_control_a_retired_slot_refuses_one_reserved_get() {
    let (gets, refused, retired, _) = gets_beside_saturated_puts(true);
    assert_eq!(retired, 1, "the plant retired one slot");
    every_reserved_get_admitted(gets, &refused);
}

#[test]
fn a_release_the_namespace_refuses_keeps_the_put_charge() {
    scene_with(OWNER, &PRINCIPALS, |mut scene| {
        let reached = audited(&mut scene, OWNER);
        let object = payload(2 * FRAGMENT_LEN as usize, 81);
        let (at, serial) = upload_at(&mut scene, request(3, 1), &object, 60_000);
        let writes = send_all(&mut scene, at, serial, &object, 0..2);
        for &token in &writes {
            scene.control.hold(token);
        }
        scene.replies(1);
        let stop = scene.frame(1, Kind::PutCancel, at, 5, |header| {
            header.allocation = serial
        });
        assert_eq!(error(&scene.one(1, &stop)), Some(Status::Cancelled));
        scene.owner.forget_unbound_requests();
        for &token in &writes {
            scene.control.release(token);
        }
        scene.turns(20);
        let volume = scene.owner.volume_report();
        assert_eq!(
            volume.writes_submitted, volume.writes_done,
            "the fill drained"
        );
        let occupancy = scene.owner.put_occupancy();
        assert_eq!(
            (occupancy.live, occupancy.records),
            (1, vec![0, 1]),
            "the refused release keeps the record and its charge"
        );
        assert!(reached.get().peer_put_cap);
    });
}
