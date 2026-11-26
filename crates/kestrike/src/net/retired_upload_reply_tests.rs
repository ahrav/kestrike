//! A stale DATA, ACK, RESULT, release or terminal mutates no successor's bytes, grants, receipt or
//! outcome. This file checks the client's side of it at the upload core: a PUT reply that names a retired upload's
//! wire identity, the wire slot with the retired generation, reaches no successor upload that now holds the slot.
//!
//! Each run builds one client request table and upload core, publishes and retires a first upload, admits a
//! successor of the same key on the same wire slot and drives it to READY, then delivers frames under the same
//! session. The run returns what it observed and drops the table and the core before any test asserts, so a failed
//! check unwinds through no fixture.

use crate::storage::{CacheVersion, EngineBudget};

use super::client_namespace::ClientRequests;
use super::datagram::PeerId;
use super::fetch::Releases;
use super::frame::{Header, Kind, Status};
use super::geometry::FRAGMENT_LEN;
use super::owner_tests::key;
use super::requests::{RequestId, RequestTable};
use super::serve::{Manifest, header, manifest_header};
use super::session::{Admitted, Caps};
use super::upload::{UploadConfig, UploadCore, UploadOutcome};

const SESSION: Admitted = Admitted {
    peer: PeerId(0),
    epoch: 1,
    caps: Caps {
        slots: 4,
        window: 4,
    },
};
const DEADLINE_US: u64 = 1_000_000;
const TTL_MS: u32 = 60_000;
/// The fill serial the owner gave the retired upload.
const RETIRED_SERIAL: u64 = 5;
/// The fill serial the owner gives the successor.
const SUCCESSOR_SERIAL: u64 = 9;
/// The retired upload's body: one fragment.
const RETIRED_BODY: u32 = FRAGMENT_LEN;
/// The successor's body: two fragments, so an ACK of fragment 0 leaves it short of `Received`.
const SUCCESSOR_BODY: u32 = 2 * FRAGMENT_LEN;
/// The grant the successor's READY carries.
const READY_GRANT: u32 = 1;
/// The grant the late ACK carries, above the READY's.
const ACK_GRANT: u32 = 2;

/// The successor's receipt once READY arrived: its serial, no fragment received, the READY's grant.
const AT_READY: (u64, u32, u32) = (SUCCESSOR_SERIAL, 0, READY_GRANT);
/// The successor's receipt once an ACK of fragment 0 with [`ACK_GRANT`] acted on it.
const AT_ACK: (u64, u32, u32) = (SUCCESSOR_SERIAL, 1, ACK_GRANT);

/// A reply the owner may still send after the first upload retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Late {
    /// The retired upload's PUT RESULT as the owner sent it: the retired serial and lengths.
    OwnResult,
    /// A PUT RESULT carrying the successor's serial and lengths.
    SuccessorResult,
    /// A PUT ERROR `UnknownOutcome` with no serial, the owner's answer to a late frame of a retired request.
    UnknownOutcome,
    /// A PUT ACK of fragment 0 carrying the successor's serial and lengths and a larger grant.
    Ack,
}

/// Which wire identity the delivered frames name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Named {
    /// The retired upload's: the shared wire slot under the retired generation.
    Retired,
    /// The successor's own, the control that shows each frame acts when its identity is live.
    Successor,
}

/// The successor as the run saw it after one delivered frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct After {
    frame: Late,
    /// What `receive` answered for the frame.
    taken: bool,
    outcome: Option<UploadOutcome>,
    /// The successor's serial, receipt base and grant.
    receipt: Option<(u64, u32, u32)>,
}

/// What one run observed.
#[derive(Debug)]
struct Observed {
    /// The successor after each delivered frame, in delivery order.
    after: Vec<After>,
    /// Whether `receive` took the successor's own PUT RESULT, delivered last.
    own_result_taken: bool,
    /// The successor's outcome after its own PUT RESULT.
    last: Option<UploadOutcome>,
}

fn sent(core: &mut UploadCore<'_>, requests: &mut ClientRequests<'_>, now_us: u64) -> Vec<Kind> {
    let mut kinds = Vec::new();
    core.poll(requests, now_us, 8, |_, header| {
        kinds.push(header.kind);
        true
    });
    kinds
}

fn manifest(serial: u64, body_len: u32) -> Manifest {
    Manifest {
        allocation: serial,
        metadata_len: 0,
        body_len,
    }
}

/// `late` as the owner would send it for wire identity `wire`.
fn late_frame(late: Late, wire: u64) -> Header {
    let successor = manifest(SUCCESSOR_SERIAL, SUCCESSOR_BODY);
    match late {
        Late::OwnResult => manifest_header(
            Kind::PutResult,
            wire,
            key(6),
            &manifest(RETIRED_SERIAL, RETIRED_BODY),
        ),
        Late::SuccessorResult => manifest_header(Kind::PutResult, wire, key(6), &successor),
        Late::UnknownOutcome => Header {
            status: Status::UnknownOutcome as u16,
            ..header(Kind::PutError, wire, key(6))
        },
        Late::Ack => Header {
            index: 1,
            grant: ACK_GRANT,
            ..manifest_header(Kind::PutAck, wire, key(6), &successor)
        },
    }
}

/// Drives upload `id` from its admission through BEGIN, the owner's authority under `serial` and PREPARE of a body
/// of `body_len` bytes, and returns its wire identity.
///
/// # Errors
///
/// The name of the step that did not go as the script requires.
fn prepared(
    core: &mut UploadCore<'_>,
    requests: &mut ClientRequests<'_>,
    id: RequestId,
    (serial, body_len): (u64, u32),
    now_us: u64,
) -> Result<u64, &'static str> {
    let wire = requests
        .upload(id)
        .ok_or("premise: the admitted upload is live")?
        .wire();
    if sent(core, requests, now_us) != [Kind::PutBegin] {
        return Err("premise: the upload sends its BEGIN");
    }
    let authority = Header {
        allocation: serial,
        ..header(Kind::PutAuthority, wire, key(6))
    };
    if !core.receive(requests, SESSION, &authority, now_us + 10) {
        return Err("premise: the upload takes the owner's authority");
    }
    if core.prepare(requests, id, 0, body_len, TTL_MS).is_err() {
        return Err("premise: the upload accepts its shape");
    }
    if sent(core, requests, now_us + 20) != [Kind::PutPrepare] {
        return Err("premise: the upload sends its PREPARE");
    }
    Ok(wire)
}

/// Publishes and retires a first upload, drives a successor of the same key on the same wire slot to READY,
/// delivers each frame of `frames` under the wire identity `named` selects, then the successor's own PUT RESULT.
///
/// # Errors
///
/// The name of the premise that did not form; the run then checked nothing.
fn run(named: Named, frames: &[Late]) -> Result<Observed, &'static str> {
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20))
        .map_err(|_| "premise: the release table fits its budget")?;
    let mut budget = EngineBudget::new(1 << 20);
    let mut requests = ClientRequests::new(RequestTable::new(4, 1, 4), &releases, &mut budget)
        .map_err(|_| "premise: the request table fits its budget")?;
    let config = UploadConfig {
        retry_us: 1_000,
        attempts: 3,
    };
    let mut core = UploadCore::new(config, Box::default(), &mut requests, &mut budget)
        .map_err(|_| "premise: the upload core fits its budget")?;

    let first = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            0,
            DEADLINE_US,
        )
        .map_err(|_| "premise: the first upload is admitted")?;
    let retired = prepared(
        &mut core,
        &mut requests,
        first,
        (RETIRED_SERIAL, RETIRED_BODY),
        0,
    )?;
    let own_result = late_frame(Late::OwnResult, retired);
    if !core.receive(&mut requests, SESSION, &own_result, 30)
        || core.outcome(&requests, first) != Some(UploadOutcome::Published)
    {
        return Err("premise: the first upload's own RESULT publishes it");
    }
    if !core.close(&mut requests, first) || requests.upload(first).is_some() {
        return Err("premise: the published upload retires");
    }

    let next = core
        .put(
            &mut requests,
            SESSION,
            key(6),
            CacheVersion(0),
            100,
            DEADLINE_US,
        )
        .map_err(|_| "premise: the successor is admitted")?;
    let live = prepared(
        &mut core,
        &mut requests,
        next,
        (SUCCESSOR_SERIAL, SUCCESSOR_BODY),
        100,
    )?;
    let (was, now) = (RequestId::from_wire(retired), RequestId::from_wire(live));
    if was.slot() != now.slot() || was.generation() >= now.generation() {
        return Err("premise: the successor holds the retired wire slot under a later generation");
    }
    let successor = manifest(SUCCESSOR_SERIAL, SUCCESSOR_BODY);
    let ready = Header {
        grant: READY_GRANT,
        ..manifest_header(Kind::PutReady, live, key(6), &successor)
    };
    if !core.receive(&mut requests, SESSION, &ready, 130)
        || core.outcome(&requests, next).is_some()
        || core.receipt(&requests, next) != Some(AT_READY)
    {
        return Err("premise: the successor is undecided at READY with its own receipt");
    }

    let wire = match named {
        Named::Retired => retired,
        Named::Successor => live,
    };
    let mut after = Vec::new();
    for (at, &frame) in frames.iter().enumerate() {
        let taken = core.receive(
            &mut requests,
            SESSION,
            &late_frame(frame, wire),
            200 + at as u64,
        );
        after.push(After {
            frame,
            taken,
            outcome: core.outcome(&requests, next),
            receipt: core.receipt(&requests, next),
        });
    }
    let result = manifest_header(Kind::PutResult, live, key(6), &successor);
    let own_result_taken = core.receive(&mut requests, SESSION, &result, 300);
    let last = core.outcome(&requests, next);
    Ok(Observed {
        after,
        own_result_taken,
        last,
    })
}

/// The successor as a frame that reached no upload leaves it: undecided, with the receipt READY gave it.
fn untouched(frame: Late) -> After {
    After {
        frame,
        taken: false,
        outcome: None,
        receipt: Some(AT_READY),
    }
}

/// The retired upload's own PUT RESULT, a PUT RESULT with the successor's serial and lengths
/// and a PUT ERROR `UnknownOutcome` with no serial, each naming the retired wire identity, arrive in that order
/// under the session. After each the successor is undecided with the receipt its READY gave it, and its own PUT
/// RESULT then decides it `Published`.
#[test]
fn replies_naming_the_retired_wire_identity_leave_the_successor_undecided_until_its_own_result() {
    let frames = [Late::OwnResult, Late::SuccessorResult, Late::UnknownOutcome];
    let observed = run(Named::Retired, &frames);
    let observed = observed.expect("the scenario forms");
    assert_eq!(
        observed.after,
        frames.map(untouched),
        "a reply naming the retired wire identity reached the successor"
    );
    assert!(
        observed.own_result_taken,
        "the successor takes its own RESULT after the stale replies"
    );
    assert_eq!(
        observed.last,
        Some(UploadOutcome::Published),
        "the successor's own RESULT decides it"
    );
}

/// Each reply alone, on a successor no earlier stale frame touched: a RESULT that matches the successor's serial
/// and shape publishes nothing, an `UnknownOutcome` ends nothing, and an ACK moves neither the receipt base nor
/// the grant, when the frame names the retired wire identity.
#[test]
fn each_reply_naming_the_retired_wire_identity_alone_changes_no_outcome_receipt_or_grant() {
    let observed = [
        Late::OwnResult,
        Late::SuccessorResult,
        Late::UnknownOutcome,
        Late::Ack,
    ]
    .map(|frame| (frame, run(Named::Retired, &[frame])));
    for (frame, observed) in observed {
        let observed = observed.expect("the scenario forms");
        assert_eq!(
            observed.after,
            [untouched(frame)],
            "a {frame:?} naming the retired wire identity reached the successor"
        );
        assert_eq!(
            (observed.own_result_taken, observed.last),
            (true, Some(UploadOutcome::Published)),
            "the successor's own RESULT decides it after a stale {frame:?}"
        );
    }
}

/// The control: the same steps with each frame naming the successor's own wire identity. The RESULT publishes the
/// successor, the `UnknownOutcome` ends it `Unknown`, and the ACK raises its receipt base and grant, so in the
/// tests above the retired generation alone keeps each of these frames from the successor. The retired upload's
/// own RESULT stays refused under the successor's identity, since it carries the retired serial.
#[test]
fn the_same_replies_naming_the_successor_s_own_wire_identity_act_on_it() {
    let expected = [
        (
            Late::SuccessorResult,
            Some(UploadOutcome::Published),
            AT_READY,
        ),
        (Late::UnknownOutcome, Some(UploadOutcome::Unknown), AT_READY),
        (Late::Ack, None, AT_ACK),
    ];
    let observed = expected.map(|(frame, ..)| run(Named::Successor, &[frame]));
    for ((frame, outcome, receipt), observed) in expected.into_iter().zip(observed) {
        let observed = observed.expect("the scenario forms");
        assert_eq!(
            observed.after,
            [After {
                frame,
                taken: true,
                outcome,
                receipt: Some(receipt),
            }],
            "a {frame:?} naming the successor's own wire identity acts on it"
        );
    }
    let stale = run(Named::Successor, &[Late::OwnResult]);
    let stale = stale.expect("the scenario forms");
    assert_eq!(
        stale.after,
        [untouched(Late::OwnResult)],
        "a RESULT of the retired serial is refused under the successor's identity as well"
    );
}
