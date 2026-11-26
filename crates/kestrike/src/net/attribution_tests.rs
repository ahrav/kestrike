//! The serve report attributes GET refusals by status and pressure cause, the PUT report attributes fresh BEGINs by cause, the owner report records clock outages during expiry and poisoned grace gates, and it counts each received datagram as handled or under one drop reason.

use crate::storage::owner_fixture::{
    Device, arena, expiry_cursor, poison_maintenance, poison_pool, publish, publish_until,
    residents, set_clock, storage, with_maintenance_held,
};
use crate::storage::{CertifyStall, EngineBudget, WorkBudget};

use super::fetch::Outcome;
use super::frame::{Header, Kind, Status};
use super::link::{Faults, network};
use super::owner::{Bundle, Keys, MAINTAIN_REST_US, Owner, OwnerConfig};
use super::owner_tests::{Mux, OWNER, PRINCIPALS, entries, key, payload, pool};
use super::put::{PutConfig, PutReport};
use super::put_tests::{Scene, error, refusal_parts, request, scene_over, scene_with};
use super::requests::GENERATION_LIMIT;
use super::serve::{ServeConfig, ServeReport};

const SECOND: u64 = 1_000_000_000;

const TURN_US: u64 = 100;

fn saturate(scene: &mut Scene<'_, '_>) {
    for slot in [0, 1] {
        scene.owner.start_request_slot_at(slot, GENERATION_LIMIT);
    }
    for _ in 0..2 {
        assert_eq!(
            scene.read(0, 1, 0),
            (Some(Outcome::Complete), payload(1000, 1))
        );
    }
    assert_eq!(scene.owner.census().retired, 2);
    scene.refresh(0);
    for slot in [2, 3] {
        let get = scene.get(0, request(slot, 1), 1);
        scene.inject(0, &get);
    }
    scene.polls(2);
    assert_eq!(
        scene.owner.census().live(),
        2,
        "peer 0 fills its share and the table"
    );
}

fn pressure(report: &ServeReport) -> (u64, u64, u64) {
    let causes = report.refused_pressure;
    (causes.busy, causes.peer, causes.table)
}

fn attributed(report: &ServeReport) {
    let (busy, peer, table) = pressure(report);
    assert_eq!(
        busy + peer + table,
        report.refused_of(Status::RequestPressure),
        "{report:?}"
    );
}

#[test]
fn each_get_refusal_counts_once_under_its_status_and_pressure_cause() {
    let config = OwnerConfig {
        serve: ServeConfig {
            replies: 1,
            ..OWNER.serve
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        saturate(&mut scene);
        let quiet = scene.owner.serve_report();
        assert_eq!(pressure(&quiet), (0, 0, 0));

        let census = scene.owner.census();
        let peer = scene.get(0, request(1, 1 << 20), 1);
        let table = scene.get(1, request(1, 1), 1);
        scene.inject(0, &peer);
        scene.inject(1, &table);
        scene.polls(1);
        let one_turn = scene.owner.serve_report();
        assert_eq!(
            scene.owner.census(),
            census,
            "the refusals leave the census"
        );
        assert_eq!(pressure(&one_turn), (0, 1, 1));
        assert_eq!(one_turn.refused_of(Status::RequestPressure), 2);
        assert_eq!(one_turn.requests, quiet.requests);

        let busy = scene.get(0, request(2, 2), 1);
        scene.inject(0, &busy);
        let stale = scene.get(0, request(3, 0), 1);
        scene.inject(0, &stale);
        let invalid = scene.get(0, request(9, 1), 1);
        scene.inject(0, &invalid);
        scene.polls(1);
        let mixed = scene.owner.serve_report();
        assert_eq!(
            pressure(&mixed),
            (1, 1, 1),
            "the busy wire slot counts under busy"
        );
        assert_eq!(mixed.refused_of(Status::InvalidRequest), 1);
        assert_eq!(
            mixed.refused_by_status.iter().sum::<u64>(),
            one_turn.refused_by_status.iter().sum::<u64>() + 2,
            "the stale generation's dropped frame is no refusal"
        );

        let dropped = mixed.dropped_replies;
        for slot in [2, 3] {
            let get = scene.get(1, request(slot, 1), 1);
            scene.inject(1, &get);
        }
        scene.polls(1);
        let ring = scene.owner.serve_report();
        assert_eq!(pressure(&ring), (1, 1, 3));
        assert!(
            ring.dropped_replies > dropped,
            "the one-reply ring dropped a refusal's ERROR"
        );
        assert_eq!(scene.owner.census(), census);
        attributed(&ring);
    });
}

fn begins(report: &PutReport) -> u64 {
    report.begun
        + report.refused_global_cap
        + report.refused_peer_share
        + report.refused_get_backlog
        + report.refused_lane_guard
        + report.refused_namespace
        + report.refused_fill_slots
        + report.refused_in_progress
        + report.refused_other
}

fn live_split(report: &PutReport) {
    assert_eq!(
        report.refused_live,
        report.refused_global_cap
            + report.refused_peer_share
            + report.refused_get_backlog
            + report.refused_lane_guard,
        "{report:?}"
    );
    assert_eq!(report.refused_lane_guard, 0, "every live PUT holds a lane");
}

fn begin(scene: &mut Scene<'_, '_>, peer: usize, at: u64, name: u8) -> Option<Status> {
    let before = scene.owner.put_report();
    let frame = scene.frame(peer, Kind::PutBegin, at, name, |_| {});
    let reply = scene.one(peer, &frame);
    let after = scene.owner.put_report();
    assert_eq!(
        begins(&after),
        begins(&before) + 1,
        "{before:?} then {after:?}"
    );
    live_split(&after);
    let status = error(&reply);
    assert_eq!(
        status.is_none(),
        after.begun == before.begun + 1,
        "a BEGIN without an error is begun"
    );
    status
}

#[test]
fn each_fresh_begin_counts_once_under_its_cause() {
    scene_with(OWNER, &PRINCIPALS, |mut scene| {
        assert_eq!(begin(&mut scene, 1, request(1, 1), 5), None);
        assert_eq!(
            begin(&mut scene, 1, request(2, 1), 6),
            Some(Status::RequestPressure)
        );
        assert_eq!(scene.owner.put_report().refused_peer_share, 1);
        assert_eq!(
            begin(&mut scene, 0, request(1, 1), 5),
            Some(Status::InProgress)
        );
        assert_eq!(scene.owner.put_report().refused_in_progress, 1);
        assert_eq!(begin(&mut scene, 0, request(2, 1), 6), None);
        assert_eq!(
            begin(&mut scene, 0, request(3, 1), 7),
            Some(Status::RequestPressure)
        );
        let report = scene.owner.put_report();
        assert_eq!(
            (report.refused_global_cap, report.refused_peer_share),
            (1, 1),
            "both caps spent count under the global cap"
        );
        let stop = scene.frame(0, Kind::PutCancel, request(2, 1), 6, |header| {
            header.allocation = 0
        });
        assert_eq!(error(&scene.one(0, &stop)), Some(Status::Cancelled));
        assert_eq!(
            begin(&mut scene, 0, request(3, GENERATION_LIMIT), 7),
            Some(Status::CounterExhausted)
        );
        assert_eq!(scene.owner.put_report().refused_namespace, 1);
        let mut held = Vec::new();
        let fill = loop {
            match scene.storage.begin_fill(
                &key(100 + held.len() as u8),
                crate::storage::CacheVersion(0),
                4,
                &mut WorkBudget::new(1 << 12),
            ) {
                Ok(attempt) => held.push(attempt),
                Err(error) => break error,
            }
        };
        assert_eq!(fill, crate::storage::BeginError::FillSlotsFull);
        assert_eq!(
            begin(&mut scene, 0, request(0, 1), 8),
            Some(Status::StoragePressure)
        );
        assert_eq!(scene.owner.put_report().refused_fill_slots, 1);
        let report = scene.owner.put_report();
        assert_eq!(
            (report.reserve_refused, refusal_parts(&report)),
            (0, [0; 4]),
            "a BEGIN short of fill records counts no reservation refusal"
        );
        for attempt in held {
            attempt.abort();
        }
    });
    scene_with(OWNER, &PRINCIPALS[1..], |mut scene| {
        assert_eq!(
            begin(&mut scene, 0, request(1, 1), 5),
            Some(Status::PermissionDenied)
        );
        assert_eq!(scene.owner.put_report().refused_other, 1);
    });
}

#[test]
fn a_begin_is_admitted_below_the_get_backlog_and_refused_at_it_without_taking_a_slot_or_a_fill() {
    let config = OwnerConfig {
        put: PutConfig {
            get_backlog: 2,
            ..OWNER.put
        },
        ..OWNER
    };
    scene_with(config, &PRINCIPALS, |mut scene| {
        let live_get = |scene: &mut Scene<'_, '_>, peer: usize, slot: u16| {
            let get = scene.get(peer, request(slot, 1), 1);
            scene.inject(peer, &get);
            scene.polls(2);
        };
        assert_eq!(begin(&mut scene, 0, request(1, 1), 4), None);
        live_get(&mut scene, 1, 0);
        assert_eq!(scene.live(), 2, "peer 0's PUT and peer 1's GET");
        assert_eq!(
            begin(&mut scene, 1, request(1, 1), 5),
            None,
            "one live GET is below the backlog of two, and peer 0's live PUT is no GET"
        );
        for (peer, name) in [(1, 5), (0, 4)] {
            let stop = scene.frame(peer, Kind::PutCancel, request(1, 1), name, |header| {
                header.allocation = 0
            });
            assert_eq!(error(&scene.one(peer, &stop)), Some(Status::Cancelled));
        }
        assert_eq!(scene.live(), 1, "the cancelled PUTs left the table");

        live_get(&mut scene, 0, 2);
        assert_eq!(scene.live(), 2);
        assert_eq!(
            begin(&mut scene, 1, request(2, 1), 6),
            Some(Status::RequestPressure),
            "two live GETs reach the backlog and peer 1's one GET passes half its share"
        );
        let report = scene.owner.put_report();
        assert_eq!(
            (report.refused_get_backlog, report.refused_live),
            (1, 1),
            "{report:?}"
        );
        assert_eq!(scene.live(), 2, "the refused BEGIN took no request slot");
        scene
            .storage
            .begin_fill(
                &key(6),
                crate::storage::CacheVersion(0),
                4,
                &mut WorkBudget::new(1 << 12),
            )
            .expect("the refused BEGIN took no fill authority over its key")
            .abort();

        let get = scene.get(0, request(2, 1), 1);
        let cancel = Header {
            kind: Kind::Cancel,
            status: Status::Cancelled as u16,
            metadata_len: 0,
            body_len: 0,
            grant: 0,
            remaining_ms: 0,
            ..get
        };
        scene.inject(0, &cancel);
        scene.polls(2);
        let census = scene.owner.census();
        assert_eq!(
            (census.active, census.draining),
            (1, 1),
            "the cancelled GET drains while the link holds its bytes"
        );
        assert_eq!(
            begin(&mut scene, 1, request(3, 1), 7),
            Some(Status::RequestPressure),
            "a draining GET counts toward the backlog"
        );
        assert_eq!(scene.owner.put_report().refused_get_backlog, 2);
    });
}

/// Peer 0's unacknowledged GETs keep the backlog of three full across every BEGIN attempt. Over two peers, half an even share is three quarters of a GET, so the check refuses the BEGIN of a peer that holds one live GET. A peer's count is its live GETs alone: peer 1 with one live PUT counts zero, and the check admits its second BEGIN.
#[test]
fn one_peers_gets_at_the_backlog_refuse_its_own_begin_and_leave_another_peers_begin_admitted() {
    let config = OwnerConfig {
        request_slots: 6,
        peer_requests: 3,
        put: PutConfig {
            puts: 4,
            peer_puts: 2,
            get_backlog: 3,
            ..OWNER.put
        },
        ..OWNER
    };
    let storage = crate::storage::owner_fixture::storage_for_puts(6, 4);
    scene_over(storage, config, &PRINCIPALS, |mut scene| {
        for slot in [1, 2, 3] {
            let get = scene.get(0, request(slot, 1), 1);
            scene.inject(0, &get);
        }
        scene.polls(2);
        assert_eq!(scene.live(), 3, "peer 0's three GETs reach the backlog");
        assert_eq!(
            begin(&mut scene, 1, request(1, 1), 5),
            None,
            "peer 1 holds no GET, below half its share of the backlog"
        );
        assert_eq!(
            begin(&mut scene, 1, request(3, 1), 8),
            None,
            "peer 1's live PUT is no GET, so peer 1 still holds none of the backlog"
        );
        for (slot, name) in [(1, 5), (3, 8)] {
            let stop = scene.frame(1, Kind::PutCancel, request(slot, 1), name, |header| {
                header.allocation = 0
            });
            assert_eq!(error(&scene.one(1, &stop)), Some(Status::Cancelled));
        }

        let get = scene.get(1, request(0, 1), 1);
        scene.inject(1, &get);
        scene.polls(2);
        assert_eq!(scene.live(), 4);
        assert_eq!(
            begin(&mut scene, 1, request(2, 1), 6),
            Some(Status::RequestPressure),
            "peer 1's one GET reaches half its share of the backlog"
        );
        assert_eq!(
            begin(&mut scene, 0, request(0, 1), 7),
            Some(Status::RequestPressure),
            "peer 0 holds the backlog's GETs"
        );
        let report = scene.owner.put_report();
        assert_eq!(
            (report.begun, report.refused_get_backlog),
            (2, 2),
            "{report:?}"
        );
    });
}

type Maintaining<'s, 'a, 'm> = super::owner_tests::TestOwner<'s, 'a, 'm>;

fn maintaining<'s, 'a, 'm>(
    storage: &'s crate::storage::Storage<crate::storage::owner_fixture::TestPlatform>,
    device: Device<'s, 'a>,
    receive: &'m super::packet::PacketPool<'a>,
) -> Maintaining<'s, 'a, 'm> {
    let Device { volume, .. } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &[],
    };
    let (_, end, _) = network(4, 8384, 1, [Faults::default(); 2]);
    let config = OwnerConfig {
        maintain_work: 1 << 16,
        ..OWNER
    };
    Owner::start(
        config,
        Bundle {
            cache,
            registration,
            volume,
        },
        keys,
        Mux::new(vec![end]),
        receive,
        &mut EngineBudget::new(1 << 26),
    )
    .map_err(|refused| refused.error)
    .unwrap()
}

/// Polls `owner` once at `turn`, checking that the turn made at most one maintenance call, and returns whether the call it made found no clock sample.
fn turn(owner: &mut Maintaining<'_, '_, '_>, at: u64) -> bool {
    let before = owner.report();
    owner.poll(at * TURN_US);
    let after = owner.report();
    let calls = after.maintained + after.maintenance_refused;
    assert!(calls <= before.maintained + before.maintenance_refused + 1);
    after.maintenance_clock_unavailable > before.maintenance_clock_unavailable
}

#[test]
fn a_clock_outage_during_expiry_shows_in_the_owner_report_and_expiry_resumes_when_the_clock_returns()
 {
    clock_outage(None);
}

/// The control for the outage: the clock gives a sample past the resident's deadline where the test gives none,
/// so expiry sweeps during the outage's turns, as a sweep that goes on with a maximal sample when the clock gives
/// none would sweep.
#[test]
#[should_panic(expected = "a missing sample leaves the expiry cursor")]
fn negative_control_a_late_sample_in_the_outage_runs_the_sweep() {
    clock_outage(Some(20 * SECOND));
}

/// Publishes one resident that expires at 10 s and one without a deadline and maintains them over a valid sample.
/// It then maintains them during the outage with `sample` as the clock's only sample, which must leave the expired
/// resident and the expiry cursor, and then over a returned clock, whose first funded call removes the resident.
fn clock_outage(sample: Option<u64>) {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let mut device = Device::new(&storage, &buffers);
    publish_until(
        &storage,
        &mut device,
        &key(1),
        0,
        &payload(900, 31),
        10 * SECOND,
    );
    publish(&storage, &mut device, &key(2), 0, &payload(900, 32));
    let mut owner = maintaining(&storage, device, &receive);
    set_clock(&storage, &[Some(5 * SECOND)]);
    for at in 0..20 {
        assert!(!turn(&mut owner, at));
    }
    assert!(
        owner.report().maintained > 0,
        "a call took the valid sample"
    );
    assert_eq!(
        residents(&storage),
        2,
        "the resident outlives a sample before its deadline"
    );
    set_clock(&storage, &[sample]);
    let cursor = expiry_cursor(&storage);
    let (mut outage, mut rested) = (false, false);
    for at in 20..60 {
        if turn(&mut owner, at) {
            outage |= residents(&storage) == 2;
            rested |= owner.maintain_rest_until_us().is_some();
        }
        assert_eq!(
            expiry_cursor(&storage),
            cursor,
            "a missing sample leaves the expiry cursor"
        );
    }
    let report = owner.report();
    assert!(outage, "a call met the outage beside the expired resident");
    assert!(
        rested,
        "a call that met the outage reported no more work and the stage rested"
    );
    assert!(report.maintenance_clock_unavailable > 1);
    assert_eq!(
        report.maintenance_contended, 0,
        "the outage is the only observation"
    );
    assert_eq!(residents(&storage), 2);
    set_clock(&storage, &[Some(20 * SECOND)]);
    let calls = owner.report().maintained;
    let mut at = 60;
    while residents(&storage) == 2 {
        assert!(
            !turn(&mut owner, at),
            "the returned clock gives every call a sample"
        );
        at += 1;
        assert!(
            at <= 60 + MAINTAIN_REST_US / TURN_US + 1,
            "the expired resident outlived one rest and one funded call"
        );
    }
    assert_eq!(
        owner.report().maintained,
        calls + 1,
        "the first funded call removed it"
    );
    assert_eq!(residents(&storage), 1);
    let mut reader = storage.register().unwrap();
    assert!(
        reader
            .lookup(&key(1), 4, &mut WorkBudget::new(1 << 16))
            .is_err()
    );
    assert!(
        reader
            .lookup(&key(2), 4, &mut WorkBudget::new(1 << 16))
            .is_ok()
    );
}

#[test]
fn a_poisoned_grace_gate_shows_in_the_owner_report() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &payload(900, 33));
    let mut owner = maintaining(&storage, device, &receive);
    poison_maintenance(&storage);
    for at in 0..40 {
        turn(&mut owner, at);
    }
    let report = owner.report();
    assert_eq!(report.last_certify_stall, Some(CertifyStall::Poisoned));
    assert!(report.maintenance_contended > 0, "{report:?}");
}

#[test]
fn a_poisoned_pool_gate_accumulates_in_the_owner_reports_contended_count() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &payload(900, 34));
    let mut owner = maintaining(&storage, device, &receive);
    poison_pool(&storage);
    let mut per_call = Vec::new();
    for at in 0..40 {
        let before = owner.report();
        turn(&mut owner, at);
        let after = owner.report();
        if after.maintained > before.maintained {
            per_call.push(after.maintenance_contended - before.maintenance_contended);
        }
    }
    assert!(per_call.len() >= 2, "{per_call:?}");
    assert!(
        per_call.iter().all(|&contended| contended > 0),
        "{per_call:?}"
    );
    assert_eq!(
        owner.report().maintenance_contended,
        per_call.iter().sum::<u64>(),
        "the owner sums every call's count"
    );
}

#[test]
fn a_refused_maintenance_call_counts_its_cause_and_leaves_the_stage_unrested() {
    let storage = storage(8);
    let buffers = arena(8);
    let receive = pool();
    let mut device = Device::new(&storage, &buffers);
    publish(&storage, &mut device, &key(1), 0, &payload(900, 35));
    let mut owner = maintaining(&storage, device, &receive);
    with_maintenance_held(&storage, || turn(&mut owner, 0));
    let report = owner.report();
    assert_eq!((report.maintained, report.maintenance_refused), (0, 1));
    assert_eq!(
        report.last_maintenance_refusal,
        Some(crate::storage::MaintainError::Contended)
    );
    assert_eq!(owner.maintain_rest_until_us(), None);
    turn(&mut owner, 1);
    assert_eq!(owner.report().maintained, 1, "the next turn calls again");
}

#[derive(Debug, PartialEq, Eq)]
struct History {
    census: super::requests::RequestCensus,
    rest: Option<u64>,
    maintained: u64,
    maintenance_refused: u64,
    put: PutReport,
}

/// When `refuse` is true, the last turn refuses one GET against its peer's share and one against the table.
fn refusal_history(refuse: bool) -> (History, (u64, u64, u64)) {
    let mut seen = None;
    scene_with(OWNER, &PRINCIPALS, |mut scene| {
        saturate(&mut scene);
        if refuse {
            let peer = scene.get(0, request(1, 1 << 20), 1);
            let table = scene.get(1, request(1, 1), 1);
            scene.inject(0, &peer);
            scene.inject(1, &table);
        }
        scene.polls(1);
        let report = scene.owner.report();
        let history = History {
            census: scene.owner.census(),
            rest: scene.owner.maintain_rest_until_us(),
            maintained: report.maintained,
            maintenance_refused: report.maintenance_refused,
            put: scene.owner.put_report(),
        };
        seen = Some((history, pressure(&scene.owner.serve_report())));
    });
    seen.expect("the scene ran")
}

#[test]
fn counting_refusals_leaves_the_census_and_the_maintenance_schedule_unchanged() {
    let (refused, causes) = refusal_history(true);
    let (quiet, none) = refusal_history(false);
    assert_eq!((causes, none), ((0, 1, 1), (0, 0, 0)));
    assert!(quiet.maintained > 0, "the twins fund maintenance");
    assert_eq!(refused, quiet);
}

/// Every drop reason in discriminant order, each once.
const REASONS: [super::DropReason; super::DropReason::COUNT] = {
    use super::DropReason::*;
    [
        NoPeer,
        Vacant,
        Truncated,
        Malformed,
        Unauthenticated,
        Session,
        Kind,
        Body,
        Declined,
    ]
};

/// For one examined datagram, `moved` reports each nonzero counter delta,
/// with `None` for `handled` or `Some(reason)` for
/// `dropped_by[reason as usize]`.
pub(super) fn moved(
    before: &super::OwnerReport,
    after: &super::OwnerReport,
) -> Vec<(Option<super::DropReason>, u64)> {
    let mut moved = Vec::new();
    if after.handled != before.handled {
        moved.push((None, after.handled - before.handled));
    }
    for reason in REASONS {
        let at = reason as usize;
        let delta = after.dropped_by[at] - before.dropped_by[at];
        if delta != 0 {
            moved.push((Some(reason), delta));
        }
    }
    moved
}

/// `received == handled + dropped`, and `dropped` is the total of
/// `dropped_by`; the reason a report breaks either, or `None`.
pub(super) fn accounted(report: &super::OwnerReport) -> Option<&'static str> {
    if report.dropped_by.iter().sum::<u64>() != report.dropped {
        return Some("dropped differs from the total of dropped_by");
    }
    if report.received != report.handled + report.dropped {
        return Some("received differs from handled plus dropped");
    }
    None
}

/// Injects into `scene` toward the owner what `case` builds, polls, and
/// returns the report before and after.
fn examined(
    scene: &mut Scene<'_, '_>,
    case: impl FnOnce(&mut Scene<'_, '_>),
) -> (super::OwnerReport, super::OwnerReport) {
    let before = scene.owner.report();
    case(scene);
    scene.polls(1);
    (before, scene.owner.report())
}

/// Each drop reason has a datagram that the owner drops under it and no
/// other: a GET relabelled as from no peer, as a vacant slot or as
/// truncated; a GET whose magic changed; a GET tagged under the other
/// peer's key; a GET naming another session epoch; a frame of a kind the
/// owner rejects; a correctly tagged PUT DATA fragment whose stored body
/// crc differs from its body's crc, the header edited and resealed before
/// the tag is computed, so authentication passes and the body crc check
/// refuses it; and a well-formed PUT DATA fragment for an unknown upload,
/// which the PUT core refuses. After each exactly one counter moved, by one,
/// `dropped` equals the total of the nine, and `received == handled +
/// dropped`; a GET of a published object moves `handled` alone. A report
/// with one entry moved twice fails the accounting.
#[test]
fn each_dropped_datagram_counts_once_under_its_reason() {
    use super::DropReason;
    use super::owner_tests::{RELABEL, Relabel};
    type Case = (Option<DropReason>, fn(&mut Scene<'_, '_>));
    let cases: [Case; 10] = [
        (None, |scene| {
            let get = scene.get(0, request(0, 1), 1);
            scene.inject(0, &get);
        }),
        (Some(DropReason::NoPeer), |scene| {
            let get = scene.get(0, request(0, 1), 1);
            scene.inject(0, &get);
            RELABEL.with(|relabels| relabels.borrow_mut().push((0, Relabel::Stranger)));
        }),
        (Some(DropReason::Vacant), |scene| {
            let get = scene.get(0, request(0, 1), 1);
            scene.inject(0, &get);
            RELABEL.with(|relabels| relabels.borrow_mut().push((0, Relabel::Vacant)));
        }),
        (Some(DropReason::Truncated), |scene| {
            let get = scene.get(0, request(0, 1), 1);
            scene.inject(0, &get);
            RELABEL.with(|relabels| relabels.borrow_mut().push((0, Relabel::Truncated)));
        }),
        (Some(DropReason::Malformed), |scene| {
            let get = scene.get(0, request(0, 1), 1);
            scene.inject_edited(0, &get, &[], |encoded| encoded[0] ^= 1);
        }),
        (Some(DropReason::Unauthenticated), |scene| {
            let get = scene.get(0, request(0, 1), 1);
            let datagram = scene.sealed(1, &get, &[], |_| {});
            scene.nets[0].borrow_mut().inject(1, &datagram);
        }),
        (Some(DropReason::Session), |scene| {
            let mut get = scene.get(0, request(0, 1), 1);
            get.epoch += 2;
            scene.inject(0, &get);
        }),
        (Some(DropReason::Kind), |scene| {
            let ack = scene.frame(0, Kind::PutAck, request(0, 1), 1, |_| {});
            scene.inject(0, &ack);
        }),
        (Some(DropReason::Body), |scene| {
            let object = payload(3000, 7);
            let (header, body) = scene.fragment(request(0, 1), 9, &object, 0);
            scene.inject_edited(1, &header, &body, |encoded| {
                encoded[164] ^= 1;
                super::frame_tests::reseal(encoded);
            });
        }),
        (Some(DropReason::Declined), |scene| {
            let object = payload(3000, 7);
            let (header, body) = scene.fragment(request(0, 1), 9, &object, 0);
            scene.inject_edited(1, &header, &body, |_| {});
        }),
    ];
    assert!(
        REASONS
            .iter()
            .enumerate()
            .all(|(at, reason)| *reason as usize == at),
        "the reason list holds each reason once, in discriminant order"
    );
    for (reason, case) in cases {
        scene_with(OWNER, &[], |mut scene| {
            let (before, after) = examined(&mut scene, case);
            assert_eq!(moved(&before, &after), [(reason, 1)], "{reason:?}");
            assert_eq!(after.received - before.received, 1, "{reason:?}");
            assert_eq!(after.dropped - before.dropped, u64::from(reason.is_some()));
            assert_eq!(accounted(&after), None, "{reason:?}");
            let mut twice = after;
            if let Some(reason) = reason {
                twice.dropped_by[reason as usize] += 1;
            } else {
                twice.handled += 1;
            }
            assert!(accounted(&twice).is_some(), "{reason:?}: the self-test");
        });
    }
}

/// The session table refuses this CONFIRM: its epoch exceeds peer 0's
/// session epoch by two.
fn inject_confirm(scene: &mut Scene<'_, '_>) {
    let caps = super::owner_tests::CAPS.body();
    let base = scene.get(0, 0, 0);
    let confirm = Header {
        principal: base.principal,
        key_epoch: base.key_epoch,
        owner_nonce: base.owner_nonce,
        client_nonce: base.client_nonce,
        epoch: base.epoch + 2,
        sequence: base.sequence,
        datagram_len: caps.len() as u32,
        ..super::serve::header(Kind::Confirm, 0, [0; 32])
    };
    scene.inject_edited(0, &confirm, &caps, |_| {});
}

/// The reason is the first check a datagram failed on its kind's path: a
/// truncated GET from no peer counts `NoPeer`, and a truncated GET tagged
/// under another peer's key counts `Truncated`. On the PUT DATA path a
/// fragment from no peer, truncated, with its magic changed, tagged under
/// another peer's key or naming another session epoch counts its own
/// reason. A CONFIRM to an owner that admits no reply counts `Declined`
/// even when the session table would refuse it. A transport that reports a datagram past the slots it was given
/// counts it, and every slot it left empty, as `Vacant`. A PUT DATA group of four, one with a body crc
/// that fails, counts each fragment once under its own reason, and so does
/// a partial group of two.
#[test]
fn the_first_failed_check_names_the_reason_and_each_group_fragment_counts_once() {
    use super::DropReason;
    use super::owner_tests::{RELABEL, Relabel};
    scene_with(OWNER, &[], |mut scene| {
        let (before, after) = examined(&mut scene, |scene| {
            let get = scene.get(0, request(0, 1), 1);
            scene.inject(0, &get);
            RELABEL.with(|relabels| {
                relabels
                    .borrow_mut()
                    .extend([(0, Relabel::Stranger), (0, Relabel::Truncated)])
            });
        });
        assert_eq!(moved(&before, &after), [(Some(DropReason::NoPeer), 1)]);
        let (before, after) = examined(&mut scene, |scene| {
            let get = scene.get(0, request(0, 1), 1);
            let datagram = scene.sealed(1, &get, &[], |_| {});
            scene.nets[0].borrow_mut().inject(1, &datagram);
            RELABEL.with(|relabels| relabels.borrow_mut().push((0, Relabel::Truncated)));
        });
        assert_eq!(moved(&before, &after), [(Some(DropReason::Truncated), 1)]);
        assert_eq!(accounted(&after), None);
    });
    type Case = (DropReason, fn(&mut Scene<'_, '_>));
    let cases: [Case; 9] = [
        (DropReason::NoPeer, |scene| {
            let (header, body) = scene.fragment(request(0, 1), 9, &payload(3000, 7), 0);
            scene.inject_edited(1, &header, &body, |_| {});
            RELABEL.with(|relabels| relabels.borrow_mut().push((0, Relabel::Stranger)));
        }),
        (DropReason::Truncated, |scene| {
            let (header, body) = scene.fragment(request(0, 1), 9, &payload(3000, 7), 0);
            scene.inject_edited(1, &header, &body, |_| {});
            RELABEL.with(|relabels| relabels.borrow_mut().push((0, Relabel::Truncated)));
        }),
        (DropReason::NoPeer, |scene| {
            let (header, body) = scene.fragment(request(0, 1), 9, &payload(3000, 7), 0);
            scene.inject_edited(1, &header, &body, |_| {});
            RELABEL.with(|relabels| {
                relabels
                    .borrow_mut()
                    .extend([(0, Relabel::Stranger), (0, Relabel::Truncated)])
            });
        }),
        (DropReason::Malformed, |scene| {
            let (header, body) = scene.fragment(request(0, 1), 9, &payload(3000, 7), 0);
            scene.inject_edited(1, &header, &body, |encoded| encoded[0] ^= 1);
        }),
        (DropReason::Unauthenticated, |scene| {
            let (header, body) = scene.fragment(request(0, 1), 9, &payload(3000, 7), 0);
            let datagram = scene.sealed(0, &header, &body, |_| {});
            scene.nets[1].borrow_mut().inject(1, &datagram);
        }),
        (DropReason::Session, |scene| {
            let (mut header, body) = scene.fragment(request(0, 1), 9, &payload(3000, 7), 0);
            header.epoch += 2;
            scene.inject_edited(1, &header, &body, |_| {});
        }),
        // Another session epoch and a stored body crc that fails: session
        // admission runs first and names the reason.
        (DropReason::Session, |scene| {
            let (mut header, body) = scene.fragment(request(0, 1), 9, &payload(3000, 7), 0);
            header.epoch += 2;
            scene.inject_edited(1, &header, &body, |encoded| {
                encoded[164] ^= 1;
                super::frame_tests::reseal(encoded);
            });
        }),
        // The owner's serving clock has failed, so it admits no reply under
        // its token, and the session table would refuse the CONFIRM's epoch
        // too.
        (DropReason::Declined, |scene| {
            struct Failed;
            impl crate::storage::ServingClock for Failed {
                fn now_us(&self) -> Option<u64> {
                    None
                }
            }
            scene.owner.set_serving_clock(Box::new(Failed));
            inject_confirm(scene);
        }),
        (DropReason::Session, inject_confirm),
    ];
    for (reason, case) in cases {
        scene_with(OWNER, &[], |mut scene| {
            let (before, after) = examined(&mut scene, case);
            assert_eq!(moved(&before, &after), [(Some(reason), 1)], "{reason:?}");
            assert_eq!(accounted(&after), None, "{reason:?}");
        });
    }
    scene_with(OWNER, &[], |mut scene| {
        let (before, after) = examined(&mut scene, |scene| {
            let get = scene.get(0, request(0, 1), 1);
            scene.inject(0, &get);
            RELABEL.with(|relabels| relabels.borrow_mut().push((0, Relabel::Surplus)));
        });
        let slots = u64::from(OWNER.batch);
        assert_eq!(
            after.received - before.received,
            slots + 1,
            "premise: the transport reported one past its slots"
        );
        assert_eq!(
            moved(&before, &after),
            [(None, 1), (Some(DropReason::Vacant), slots)]
        );
        assert_eq!(accounted(&after), None);
    });
    let object = payload(4 * super::geometry::FRAGMENT_LEN as usize, 7);
    let group = |scene: &mut Scene<'_, '_>, at: u64, serial: u64| {
        for index in 0..4 {
            let (header, body) = scene.fragment(at, serial, &object, index);
            scene.inject_edited(1, &header, &body, |encoded| {
                if index == 2 {
                    encoded[164] ^= 1;
                    super::frame_tests::reseal(encoded);
                }
            });
        }
    };
    scene_with(OWNER, &PRINCIPALS, |mut scene| {
        let (at, serial) = super::put_tests::ready_upload(&mut scene, &object);
        let (before, after) = examined(&mut scene, |scene| group(scene, at, serial));
        assert_eq!(after.received - before.received, 4);
        assert_eq!(
            moved(&before, &after),
            [(None, 3), (Some(DropReason::Body), 1)]
        );
        assert_eq!(accounted(&after), None);
    });
    scene_with(OWNER, &[], |mut scene| {
        let (before, after) = examined(&mut scene, |scene| group(scene, request(0, 1), 9));
        assert_eq!(
            moved(&before, &after),
            [(Some(DropReason::Body), 1), (Some(DropReason::Declined), 3)]
        );
        assert_eq!(after.received - before.received, 4);
        let (before, after) = examined(&mut scene, |scene| {
            for index in 0..2 {
                let (header, body) = scene.fragment(request(0, 1), 9, &object, index);
                scene.inject_edited(1, &header, &body, |_| {});
            }
        });
        assert_eq!(after.received - before.received, 2);
        assert_eq!(after.dropped - before.dropped, 2);
        assert_eq!(moved(&before, &after), [(Some(DropReason::Declined), 2)]);
        assert_eq!(accounted(&after), None);
    });
}
