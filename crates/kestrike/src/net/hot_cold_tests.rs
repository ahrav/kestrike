//! An owner serving a hot GET stream beside cold objects that invalidation retired: every GET completes within `B_g` polls whatever the cold backlog, and every cold slot returns within `B_m` polls, with both bounds computed from the fixture.
//!
//! The owner sends at most `batch = 2` frames per poll, and one client keeps `R = peer_requests` GETs of the hot object live, each reissued when it completes, so the hot stream fills the batch in every poll its frames are ready.
//! The pacer (`burst` 64 datagrams, `rate_per_sec` 10^7, so 1000 per 100 µs poll) admits more than the batch in every poll, and the shaper stays unshaped because the transport reports no allowance exceedance; the batch is the binding limit.
//!
//! `B_g`. A GET issued in client poll `p` reaches the owner in poll `p + 1`, whose lookup and grant submit the read; the device completes it before poll `p + 2`, whose delivery stages its frames.
//! Each GET answers with a Start frame, one Data frame per fragment and a Complete frame, `F + 2` frames for `F` fragments; the at most `R` live GETs share the batch, so a GET's frames leave within `ceil(R * (F + 2) / batch)` polls of its first, and the client takes the Complete in the poll after it leaves.
//! A window of four frames per request never binds, because each request has at most two frames unacknowledged between its ACKs; so `B_g = 2 + ceil(R * (F + 2) / batch)`, which names no cold-backlog term.
//!
//! `B_m`. With the per-poll allowance at the maintenance minimum, every call runs at least the stage at its cursor and the cursor advances after each stage it runs, so Reclaim runs at least once in every `STAGES` calls.
//! The certification pass in progress at the invalidations may have begun before them, so the retired slots are eligible after the next complete pass, two passes of at most `records + 1` certification calls; each Reclaim call then returns at least one eligible slot.
//! The owner's invalidations end the maintenance rest, and maintenance reports more work while a retired slot is pending, so no rest begins before the last return, which the funded history checks every poll; GET releases leave the rest alone.
//! So `B_m = STAGES * (2 * (records + 1) + cold)` polls after the invalidations.
//!
//! The same-window witness: some window of `B_g` consecutive polls ending by poll `B_m` both completes a GET and returns a cold slot.

use crate::index::ShardIndex;
use crate::storage::maintain_tests::{MAINTAIN_STAGES as STAGES, with_restarting_stage_cursor};
use crate::storage::owner_fixture::{
    Device, Shape, SimControl, TestPlatform, arena, publish, registration_records,
    storage_shaped_as,
};
use crate::storage::{BufferArena, EngineBudget, Storage, WorkBudget};

use super::client::SessionState;
use super::fetch::{Outcome, Releases};
use super::geometry::FragmentGeometry;
use super::link::{Faults, LinkEnd, network};
use super::owner::{Bundle, Keys, Owner, OwnerConfig};
use super::owner_tests::{
    Mux, OWNER, PRINCIPALS, TestOwner, client, collect, drive, entries, key, open, payload, pool,
};
use super::packet::PacketPool;
use super::requests::RequestId;
use super::serve::ServeReport;

/// The send batch, below the hot stream's frames per poll.
const BATCH: usize = 2;
/// The hot object's bytes, several fragments.
const HOT: usize = 40_000;
/// Each cold object's bytes, one unit.
const COLD: usize = 900;
/// The two cold backlog sizes.
const BACKLOGS: [usize; 2] = [4, 16];

/// The storage every history runs on: 256 units and 32 slots, room for the hot object and the larger backlog.
fn fixture() -> Storage<TestPlatform> {
    storage_shaped_as(
        Shape {
            units: 256,
            slots: 32,
        },
        8192,
    )
}

/// How the owner funds maintenance.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Maintenance {
    /// One call per poll at the maintenance minimum.
    Funded,
    /// A zero allowance: no call.
    Unfunded,
    /// Funded, with the planted stage cursor that returns to Expiry in front of Reclaim.
    Restarting,
}

/// A started owner over `storage` serving one link under `config`, `objects` published first with fill service after each, so the fill table always has a free record.
fn start<'a, 'm>(
    storage: &'static Storage<TestPlatform>,
    buffers: &'a BufferArena<TestPlatform>,
    receive: &'m PacketPool<'a>,
    objects: &[([u8; 32], &[u8])],
    end: LinkEnd<'a>,
    config: OwnerConfig,
) -> (TestOwner<'static, 'a, 'm>, SimControl) {
    let mut device = Device::new(storage, buffers);
    for (key, payload) in objects {
        publish(storage, &mut device, key, 0, payload);
        storage
            .service_fills(ShardIndex(0), 2, &mut WorkBudget::new(1 << 12))
            .unwrap();
    }
    let Device { volume, control } = device;
    let cache = storage.issue_cache().unwrap();
    let registration = cache.register().unwrap();
    let keys = Keys {
        principals: &PRINCIPALS[..1],
        entries: &entries()[..1],
        epoch: 1,
        put: &[],
    };
    let owner = Owner::start(
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
    .unwrap();
    (owner, control)
}

/// What one history observed.
struct Observed {
    /// The poll, counted from the invalidations, after which every cold slot was free again.
    returned: Option<u64>,
    /// Cold slots still retired after poll `B_m`.
    retired_at_b_m: usize,
    /// The first poll of the first window of `B_g` polls, counted from the invalidations, that both completed a GET and returned a cold slot.
    both: Option<u64>,
    /// GETs completed.
    completed: usize,
    /// Polls whose send batch the owner filled.
    saturated: u64,
    /// Datagrams the owner sent during the history.
    sent: u64,
    /// The serve core's counters at the start and the end of the history.
    served: [ServeReport; 2],
    /// Maintenance calls the owner made during the history.
    maintained: u64,
    /// Maintenance calls the storage refused during the history.
    refused: u64,
    /// Registration records, each of which a certification pass visits.
    records: usize,
}

/// The bounds of a history: `B_g` from the batch, the live GETs and the hot object's fragments, `B_m` from the stage count, the registration records and the backlog.
fn bounds(records: usize, cold: usize) -> (u64, u64) {
    let fragments = FragmentGeometry::fragments(HOT as u64) as usize;
    let r = OWNER.peer_requests as usize;
    let b_g = 2 + (r * (fragments + 2)).div_ceil(BATCH);
    let b_m = STAGES * (2 * (records + 1) + cold);
    (b_g as u64, b_m as u64)
}

fn history_polls(b_g: u64, b_m: u64) -> u64 {
    b_m + 3 * b_g
}

/// One owner history: the hot object and `cold` cold objects published, the cold ones invalidated through the owner once the session is open, then polls of the hot GET stream under `maintenance`, issuing until twice `B_g` past `B_m` and running `B_g` polls more.
/// Each history leaks its storage, since the planted stage cursor reaches it from a `fn` hook through a thread-local reference.
fn history(cold: usize, maintenance: Maintenance) -> Observed {
    let storage: &'static Storage<TestPlatform> = Box::leak(Box::new(fixture()));
    let records = registration_records(storage);
    let (b_g, b_m) = bounds(records, cold);
    let buffers = arena(8);
    let receive = pool();
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).unwrap();
    let (client_end, owner_end, net) = network(64, 8384, 1, [Faults::default(); 2]);
    let hot = payload(HOT, 1);
    let colds: Vec<Vec<u8>> = (0..cold).map(|n| payload(COLD, 10 + n as u64)).collect();
    let cold_key = |n: usize| key(0x40 + n as u8);
    let mut objects = vec![(key(1), &hot[..])];
    objects.extend(
        colds
            .iter()
            .enumerate()
            .map(|(n, bytes)| (cold_key(n), &bytes[..])),
    );
    let config = OwnerConfig {
        batch: BATCH as u32,
        maintain_work: match maintenance {
            Maintenance::Unfunded => 0,
            Maintenance::Funded | Maintenance::Restarting => storage.maintain_minimum(),
        },
        ..OWNER
    };
    let (mut owner, control) = start(storage, &buffers, &receive, &objects, owner_end, config);
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let opened = open(&mut client, &mut owner, &control, &nets, 0);
    assert_eq!(client.state(), SessionState::Active);
    for n in 0..cold {
        owner
            .invalidate(&cold_key(n), 2, &mut WorkBudget::new(1024))
            .unwrap();
    }
    let ledger = || storage.pool_report().unwrap().ledger.unwrap();
    let slots = || ledger().slots;
    assert_eq!(slots().retired, cold);
    let free = slots().free + cold;
    let raw = ledger().raw;
    // A returned extent's bytes leave the retired term for the free and waste terms, with the resident term unchanged.
    let raw_free = raw.free + raw.waste + raw.retired;
    let (maintained_before, refused_before) = (
        owner.report().maintained,
        owner.report().maintenance_refused,
    );
    let (sent_before, served_before) = (owner.report().sent, owner.serve_report());
    let mut run = || {
        let mut observed = Observed {
            returned: None,
            retired_at_b_m: cold,
            both: None,
            completed: 0,
            saturated: 0,
            sent: 0,
            served: [served_before; 2],
            maintained: 0,
            refused: 0,
            records,
        };
        let mut live: Vec<(RequestId, u64, Vec<u8>)> = Vec::new();
        // Each entry records whether one window of `B_g` polls returned a cold slot (first flag) and completed a GET (second flag).
        let mut windows = vec![(false, false); history_polls(b_g, b_m).div_ceil(b_g) as usize];
        // GETs issue through poll `B_m + 2 * B_g`, and `B_g` more polls let the last ones finish.
        for poll in 0..history_polls(b_g, b_m) {
            let turn = opened + poll;
            while poll < b_m + 2 * b_g && live.len() < OWNER.peer_requests as usize {
                let id = client
                    .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
                    .unwrap();
                live.push((id, poll, Vec::with_capacity(HOT)));
            }
            let retired_before = slots().retired;
            let completed_before = observed.completed;
            let sent_at_poll = owner.report().sent;
            drive(
                &mut [&mut client],
                &mut owner,
                &control,
                &nets,
                turn,
                1,
                |_| false,
            );
            live.retain_mut(|(id, issued, bytes)| {
                collect(&mut client, *id, bytes);
                let Some(outcome) = client.outcome(*id) else {
                    return true;
                };
                assert_eq!(
                    outcome,
                    Outcome::Complete,
                    "the GET issued at poll {issued}"
                );
                assert!(
                    *bytes == hot,
                    "the GET issued at poll {issued} delivered {} bytes, differing from the hot object's {HOT}",
                    bytes.len()
                );
                observed.completed += 1;
                assert!(client.retire(*id));
                false
            });
            for (_, issued, _) in &live {
                assert!(
                    poll + 1 - issued <= b_g,
                    "the GET issued at poll {issued} is live past B_g = {b_g} with {cold} cold objects"
                );
            }
            observed.saturated += u64::from(owner.report().sent - sent_at_poll == BATCH as u64);
            let now = slots();
            if observed.returned.is_none() && maintenance == Maintenance::Funded {
                assert_eq!(
                    owner.maintain_rest_until_us(),
                    None,
                    "maintenance rested at poll {poll} with {} cold slots retired",
                    now.retired
                );
            }
            let window = &mut windows[(poll / b_g) as usize];
            window.0 |= now.retired < retired_before;
            window.1 |= observed.completed > completed_before;
            let extents = ledger().raw;
            if observed.returned.is_none()
                && (now.retired, now.quarantined, now.free) == (0, 0, free)
                && (
                    extents.retired,
                    extents.resident,
                    extents.free + extents.waste,
                ) == (0, raw.resident, raw_free)
            {
                observed.returned = Some(poll + 1);
            }
            if poll + 1 == b_m {
                observed.retired_at_b_m = now.retired;
            }
        }
        assert!(
            live.is_empty(),
            "every GET completed within B_g = {b_g} of its issue"
        );
        observed.both = windows
            .iter()
            .position(|&(returned, completed)| returned && completed)
            .map(|window| window as u64 * b_g);
        observed.maintained = owner.report().maintained - maintained_before;
        observed.refused = owner.report().maintenance_refused - refused_before;
        observed.sent = owner.report().sent - sent_before;
        observed.served[1] = owner.serve_report();
        observed
    };
    if maintenance == Maintenance::Restarting {
        with_restarting_stage_cursor(storage, run)
    } else {
        run()
    }
}

fn check(cold: usize, observed: &Observed) {
    let (b_g, b_m) = bounds(observed.records, cold);
    assert!(observed.completed as u64 >= b_m / b_g, "the stream ran");
    assert_eq!(
        observed.refused, 0,
        "the storage refused no maintenance call"
    );
    // With every admitted GET completed and every sent datagram a first-transmission GET frame, the datagram count equals the completed GETs' frames: a Start, one Data frame per fragment and a Complete each.
    let [before, after] = observed.served;
    let served = |count: fn(&ServeReport) -> u64| count(&after) - count(&before);
    assert_eq!(
        (served(|s| s.requests), served(|s| s.completed)),
        (observed.completed as u64, observed.completed as u64),
        "every GET admitted during the history completed"
    );
    assert_eq!(
        (
            served(|s| s.retries),
            served(|s| s.hole_resends),
            served(|s| s.errors),
            served(|s| s.duplicates),
            served(|s| s.replays),
        ),
        (0, 0, 0, 0, 0),
        "every datagram was a first transmission of a GET frame"
    );
    let frames = (FragmentGeometry::fragments(HOT as u64) + 2) * observed.completed as u64;
    assert_eq!(
        observed.sent, frames,
        "the owner sent the {frames} frames of the completed GETs"
    );
    assert_eq!(
        observed.saturated * BATCH as u64,
        frames,
        "{} full batches carried the {frames} frames",
        observed.saturated
    );
    match observed.returned {
        Some(poll) if poll <= b_m => {}
        _ => panic!(
            "cold slots not returned by poll B_m = {b_m} with {cold} cold objects: {} still retired at poll {b_m}",
            observed.retired_at_b_m
        ),
    }
    let both = observed
        .both
        .expect("a window of B_g polls completed a GET and returned a cold slot");
    assert!(
        both + b_g <= b_m,
        "the first window with both, from poll {both}, ends past B_m = {b_m}"
    );
}

#[test]
fn hot_gets_and_cold_reclaim_both_progress_within_their_bounds_at_both_backlogs() {
    for cold in BACKLOGS {
        let observed = history(cold, Maintenance::Funded);
        assert!(observed.maintained > 0);
        check(cold, &observed);
    }
}

/// A zero maintenance allowance: the owner makes no maintenance call, every GET still completes within `B_g`, and the cold slots stay retired past `B_m`.
#[test]
#[should_panic(expected = "cold slots not returned by poll B_m")]
fn negative_control_unfunded_maintenance_fails_only_the_reclaim_bound() {
    let observed = history(BACKLOGS[1], Maintenance::Unfunded);
    assert_eq!(observed.maintained, 0);
    check(BACKLOGS[1], &observed);
}

/// The stage cursor returned to Expiry in front of Reclaim in every cycle: the owner keeps making maintenance calls and every GET still completes within `B_g`, and no cold slot returns by `B_m`: a call starting at Expiry stops in front of Reclaim when the maintenance minimum cannot fund it after Expiry, Headroom, Fills and Certify, and the plant leaves it there.
#[test]
#[should_panic(expected = "cold slots not returned by poll B_m")]
fn negative_control_a_restarting_stage_cursor_fails_only_the_reclaim_bound() {
    let observed = history(BACKLOGS[1], Maintenance::Restarting);
    assert!(observed.maintained > 0);
    assert_eq!(
        observed.retired_at_b_m, BACKLOGS[1],
        "no cold slot returned"
    );
    check(BACKLOGS[1], &observed);
}
