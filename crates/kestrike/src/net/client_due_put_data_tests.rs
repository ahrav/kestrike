//! `Client::next_deadline_us` is 0 while a frame is
//! due and the transport takes sends. The frame here is PUT DATA: a supplied fragment below the grant
//! that waits for its send.
//!
//! A client of the two-client scene starts a PUT of a one-fragment object, prepares it once the owner's
//! authority arrived, and is driven until the owner's READY granted the upload (`adapters::upload`). The
//! scenario then reads `next_deadline_us()` three times with no poll in between: before any supply, after
//! a supply the client refuses for its length, and after the supply of fragment 0. The first two readings
//! are the premise that nothing else is due: no HELLO, CONFIRM, GET, CANCEL or PREPARE frame, and no send
//! the transport refused. One poll then sends the fragment, and a fourth reading follows it.
//!
//! Each test decides what it saw into a value inside the scene, lets the scene go, and asserts last.

use super::adapters::upload;
use super::owner_tests::{PRINCIPALS, payload};
use super::put_tests::scene;
use super::upload::SupplyRefused;

/// The one fragment of the object: a whole fragment of payload.
const FRAGMENT_BYTES: usize = 8192;
/// How long the PUT may wait, in microseconds.
const WAIT_US: u64 = 30_000_000;

/// What the client reported around one supply.
#[derive(Debug)]
struct Seen {
    /// The time of the readings: the scene's clock when the upload became ready.
    now_us: u64,
    /// `next_deadline_us()` once the upload is ready, before any supply.
    ready: Option<u64>,
    /// The refusal of a supply of fragment 0 with one byte too few.
    short: Result<usize, SupplyRefused>,
    /// `next_deadline_us()` after the refused supply.
    refused: Option<u64>,
    /// The result of the supply of fragment 0, whole.
    supplied: Result<usize, SupplyRefused>,
    /// `next_deadline_us()` right after that supply, before any poll.
    due: Option<u64>,
    /// Datagrams the next poll sent, and whether the transport refused one.
    sent: (u32, bool),
    /// `next_deadline_us()` after that poll.
    polled: Option<u64>,
}

/// The readings around the supply of fragment 0 of a ready one-fragment upload.
fn supplied() -> Seen {
    let mut seen = None;
    scene(&PRINCIPALS, |mut scene| {
        let object = payload(FRAGMENT_BYTES, 92);
        let id = upload(&mut scene, 6, &object, WAIT_US);
        let now_us = scene.turn * 100;
        let client = &mut scene.clients[0];
        let ready = client.next_deadline_us();
        let short = client.supply(id, 0, &object[..FRAGMENT_BYTES - 1]);
        let refused = client.next_deadline_us();
        let supplied = client.supply(id, 0, &object);
        let due = client.next_deadline_us();
        let report = client.poll(now_us);
        let polled = client.next_deadline_us();
        seen = Some(Seen {
            now_us,
            ready,
            short,
            refused,
            supplied,
            due,
            sent: (report.sent, report.blocked),
            polled,
        });
    });
    seen.expect("the scene ran its body")
}

/// A ready upload with nothing supplied has no frame due, and the supply of a fragment below the grant
/// makes the client report 0 at once, before its next poll.
#[test]
fn a_supplied_fragment_below_the_grant_makes_the_deadline_zero_before_the_next_poll() {
    let seen = supplied();
    assert_eq!(
        seen.supplied,
        Ok(FRAGMENT_BYTES),
        "premise: the upload is ready and takes fragment 0: {seen:?}"
    );
    assert!(
        seen.ready != Some(0) && seen.refused != Some(0),
        "premise: no other frame is due before the supply: {seen:?}"
    );
    assert_eq!(
        seen.due,
        Some(0),
        "a supplied PUT fragment below the grant waits for its send and the client does not report 0: {seen:?}"
    );
}

/// The controls of the due fragment: a supply the client refuses makes nothing due, so the deadline stays
/// what it was; and once a poll sent the fragment on a transport that takes sends, the deadline is a later
/// time again, not 0.
#[test]
fn a_refused_supply_and_a_sent_fragment_leave_no_frame_due() {
    let seen = supplied();
    assert_eq!(
        (seen.short, seen.refused),
        (Err(SupplyRefused::Length), seen.ready),
        "a refused supply changed the deadline: {seen:?}"
    );
    assert_eq!(
        (seen.sent.0 >= 1, seen.sent.1),
        (true, false),
        "premise: the poll after the supply sent a datagram and none was refused: {seen:?}"
    );
    assert!(
        seen.polled.is_some_and(|at| at > seen.now_us),
        "a sent fragment whose reply the upload awaits left the client reporting no deadline, or one \
         at or before now: {seen:?}"
    );
}
