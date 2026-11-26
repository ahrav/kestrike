//! A cached terminal answers duplicates with a matching session and fingerprint while
//! `now_us < max(deadline_us, end_us) + linger_us`.
//!
//! Two GETs run on the owner's transfer core, each with a deadline of 100 ms and a linger of 5 ms. The
//! first completes at 2 ms, long before its deadline, so its horizon is the deadline's: 105 ms. The second
//! is ended `TimedOut` by a tick at 130 ms, after its deadline, so its horizon is the end's: 135 ms. A
//! duplicate GET of the same session and fingerprint is sent at probed times on both sides of each horizon.
//! Before the horizon the core answers `Replayed` and the next poll carries the cached COMPLETE or ERROR;
//! from the horizon on it answers `Dropped` and the next poll carries nothing. The probe at 7 ms, which is
//! the first GET's end plus the linger, separates a horizon that counts the deadline from one that counts
//! the end alone. The second GET's probes lie past the deadline plus the linger, so they separate a horizon
//! that counts the end from one that counts the deadline alone.

use crate::storage::EngineBudget;

use super::frame::{Header, Kind, Status};
use super::requests::RequestTable;
use super::serve::{GetOutcome, Manifest, ReadEnd};
use super::serve_tests::{CONFIG, Core, ack, get, payload, session};

type Chunk = Box<[u8]>;

/// The deadline of a GET received at time 0 with `remaining_ms` of 100, in microseconds.
const DEADLINE_US: u64 = 100_000;

/// What one duplicate GET met: the time it arrived, the core's answer, and the kind and status of each frame of the next poll.
type Probe = (u64, GetOutcome, Vec<(Kind, u16)>);

fn core() -> Core<Chunk> {
    Core::new(
        CONFIG,
        RequestTable::new(4, 2, 2),
        2,
        128,
        0,
        4,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap()
}

/// The kind and status of each frame `core` sends when polled at `now_us`.
fn poll(core: &mut Core<Chunk>, now_us: u64) -> Vec<(Kind, u16)> {
    let mut sent = Vec::new();
    core.poll(now_us, 64, |frames| {
        frames
            .map(|out| sent.push((out.header.kind, out.header.status)))
            .count()
    });
    sent
}

/// Sends the duplicate `request` at each of `times` in order.
fn probe(core: &mut Core<Chunk>, request: &Header, times: &[u64]) -> Vec<Probe> {
    times
        .iter()
        .map(|&now_us| {
            let outcome = core.get(session(2), request, now_us);
            (now_us, outcome, poll(core, now_us))
        })
        .collect()
}

/// The probes a cached `terminal` with horizon `horizon_us` answers: a replay before the horizon, silence from it on.
fn expected(times: &[u64], horizon_us: u64, terminal: (Kind, u16)) -> Vec<Probe> {
    times
        .iter()
        .map(|&now_us| {
            if now_us < horizon_us {
                (now_us, GetOutcome::Replayed, vec![terminal])
            } else {
                (now_us, GetOutcome::Dropped, Vec::new())
            }
        })
        .collect()
}

/// A GET that completes at 2 ms answers duplicates until its deadline plus the linger, 105 ms: at 7 ms, its end plus the linger, and up to 104.999 ms it replays COMPLETE, and from 105 ms on it is silent.
#[test]
fn a_get_completed_early_replays_until_its_deadline_plus_the_linger() {
    let end_us = 2_000;
    let horizon_us = DEADLINE_US + CONFIG.linger_us;
    let times = [
        end_us,
        end_us + CONFIG.linger_us - 1,
        end_us + CONFIG.linger_us,
        60_000,
        DEADLINE_US,
        horizon_us - 1,
        horizon_us,
        horizon_us + 1,
        1_000_000,
    ];

    let mut core = core();
    let request = get(1, 3, 2);
    let manifest = Manifest {
        allocation: 7,
        metadata_len: 0,
        body_len: 100,
    };
    let mut premises = Vec::new();
    let id = match core.get(session(2), &request, 0) {
        GetOutcome::Read { id, .. } => id,
        other => panic!("premise: the GET starts a read, got {other:?}"),
    };
    core.read_started(id);
    core.chunk(id, manifest, 0..100, payload(100).into(), &[], 0);
    core.read_done(id, ReadEnd::Complete(manifest), 0);
    let first = poll(&mut core, 0);
    if first != [(Kind::Start, 0), (Kind::Data, 0)] {
        premises.push(format!("the transfer sent {first:?}"));
    }
    core.ack(session(2), &ack(&request, &manifest, 1, 3), end_us);
    let last = poll(&mut core, end_us);
    if last != [(Kind::Complete, 0)] || !core.is_ended(id) {
        premises.push(format!("the final ACK at {end_us} sent {last:?}"));
    }
    core.release_drained(|_| true);
    let probes = probe(&mut core, &request, &times);
    drop(core);

    assert_eq!(
        premises,
        Vec::<String>::new(),
        "premise: the GET completes at 2 ms"
    );
    assert_eq!(
        probes,
        expected(&times, horizon_us, (Kind::Complete, 0)),
        "the cached COMPLETE answers while now_us < max(deadline_us, end_us) + linger_us"
    );
}

/// A GET that a tick ends `TimedOut` at 130 ms, after its deadline of 100 ms, answers duplicates until its end plus the linger, 135 ms: every probe lies past the deadline plus the linger, and those before 135 ms replay the ERROR.
#[test]
fn a_get_ended_after_its_deadline_replays_until_its_end_plus_the_linger() {
    let end_us = 130_000;
    let horizon_us = end_us + CONFIG.linger_us;
    let times = [
        end_us,
        end_us + 1,
        horizon_us - 1,
        horizon_us,
        horizon_us + 1,
        1_000_000,
    ];

    let mut core = core();
    let request = get(1, 3, 2);
    let mut premises = Vec::new();
    let id = match core.get(session(2), &request, 0) {
        GetOutcome::Read { id, .. } => id,
        other => panic!("premise: the GET starts a read, got {other:?}"),
    };
    core.read_started(id);
    core.tick(end_us);
    let ended = poll(&mut core, end_us);
    if ended != [(Kind::Error, Status::TimedOut as u16)] || !core.is_ended(id) {
        premises.push(format!("the tick at {end_us} sent {ended:?}"));
    }
    if times[0] < DEADLINE_US + CONFIG.linger_us {
        premises.push("a probe lies before the deadline plus the linger".to_owned());
    }
    let probes = probe(&mut core, &request, &times);
    drop(core);

    assert_eq!(
        premises,
        Vec::<String>::new(),
        "premise: the GET times out at 130 ms"
    );
    assert_eq!(
        probes,
        expected(&times, horizon_us, (Kind::Error, Status::TimedOut as u16)),
        "the cached ERROR answers while now_us < max(deadline_us, end_us) + linger_us"
    );
}
