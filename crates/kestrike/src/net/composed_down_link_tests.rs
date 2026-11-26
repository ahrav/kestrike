//! A GET cut short by a link that went down keeps the fragments the device
//! accepted and nothing after them.
//!
//! The composed endpoint is the owner over the burst logic on a mock port, a
//! client across the simulated link, and the simulated disk. The mock port's
//! restart fails, so the recovery that follows an uncertain post proves the
//! stop and leaves the owner's transport at `Link::Down`. From then on the
//! transport refuses every send. The client holds exactly the DATA fragments
//! the device accepted before the stop. The client's GET ends `Incomplete`,
//! the outcome of a request that fails after it handed out bytes. The upload
//! the client had begun ends `Unknown` once its resends run out.
//!
//! The test records what it saw in plain values, ends the fixture, and
//! asserts last, so a failed check ends in the test's own result line.

use crate::native::Link;
use crate::storage::CacheVersion;
use crate::storage::owner_fixture::storage;

use super::composed_tests::composed;
use super::fetch::Outcome;
use super::geometry::FRAGMENT_LEN;
use super::owner_tests::{key, payload};
use super::upload::{PrepareRefused, UploadOutcome};

/// Turns the client's resends and the GET's timers get to run out against
/// the down link.
const TURNS: u64 = 400_000;

/// What the schedule showed.
struct Seen {
    published: Vec<u8>,
    /// Whether the test armed the partial acceptance after the GET's first
    /// reply burst was sent.
    armed: bool,
    /// Chains the transport kept as uncertain.
    quarantined: u64,
    link: Link,
    /// Chains the pools count with the device after the recovery.
    chains_held: u32,
    /// DATA bytes the client had taken when the recovery was over.
    taken_at_stop: usize,
    /// Whether the client accepted both of the upload's fragments.
    supplied: [bool; 2],
    /// Every DATA byte the client took through the GET's end, in order.
    taken: Vec<u8>,
    get: Option<Outcome>,
    upload: Option<UploadOutcome>,
}

fn partial_get_then_down_link() -> Seen {
    let storage = storage(8);
    let object = payload(2 * 8192, 21);
    // Five fragments.
    let published = payload(40_000, 22);
    let mut c = composed(&storage, &[(key(1), 0, &published)], |port| {
        port.restart_error = Some(libc::EIO);
    });

    // An upload the owner admitted and readied; its fragments come later.
    let upload = c
        .client
        .put(key(5), CacheVersion(0), c.turn * 100, 2_000_000)
        .expect("premise: the client begins an upload");
    let mut prepared = Err(PrepareRefused::Phase);
    for _ in 0..400 {
        c.turn();
        prepared = c.client.prepare(upload, 0, object.len() as u32, 60_000);
        if prepared != Err(PrepareRefused::Phase) {
            break;
        }
    }
    assert_eq!(prepared, Ok(()), "premise: the upload reaches PREPARE");
    // The owner's replies to the upload leave before the GET's are counted.
    c.turns(20);

    // The device keeps what it accepts, takes the GET's first reply burst
    // whole, then one chain of the next burst, reporting the one after it
    // uncertain.
    c.port().cleanup = (0, 0);
    let sent_before = c.owner.transport().report().sent;
    let get = c
        .client
        .get(key(1), 0, 1 << 20, c.turn * 100, 2_000_000)
        .expect("premise: the client begins a GET");
    let mut taken = Vec::new();
    let mut armed = false;
    for _ in 0..60 {
        c.turn();
        if !armed && c.owner.transport().report().sent > sent_before {
            let port = c.port();
            port.accept = 1;
            port.uncertain = true;
            armed = true;
        }
        while let Some(fragment) = c.client.take(get) {
            taken.extend_from_slice(fragment.bytes());
        }
    }
    let quarantined = c.owner.transport().report().quarantined;
    let link = c.owner.transport().link();
    let chains_held = c.chains_held();
    let taken_at_stop = taken.len();

    // The upload has not ended; its fragments now wait on the down link.
    let supplied = [
        c.client.supply(upload, 0, &object[..8192]).is_ok(),
        c.client.supply(upload, 1, &object[8192..]).is_ok(),
    ];
    let mut turns = 0;
    while turns < TURNS
        && (c.client.put_outcome(upload).is_none() || c.client.outcome(get).is_none())
    {
        c.turn();
        turns += 1;
        while let Some(fragment) = c.client.take(get) {
            taken.extend_from_slice(fragment.bytes());
        }
    }
    while let Some(fragment) = c.client.take(get) {
        taken.extend_from_slice(fragment.bytes());
    }
    let seen = Seen {
        published,
        armed,
        quarantined,
        link,
        chains_held,
        taken_at_stop,
        supplied,
        taken,
        get: c.client.outcome(get),
        upload: c.client.put_outcome(upload),
    };
    drop(c);
    drop(storage);
    seen
}

/// A failed restart leaves the link down. When the GET ends, the client has
/// taken exactly the two DATA fragments the device accepted, and their bytes
/// equal the first bytes of the published object. The GET ends `Incomplete`
/// and the upload ends `Unknown`.
#[test]
fn a_get_cut_by_a_down_link_keeps_exactly_the_accepted_fragments() {
    let seen = partial_get_then_down_link();
    let accepted = 2 * FRAGMENT_LEN as usize;

    assert!(seen.armed, "premise: the GET's first reply burst was sent");
    assert_eq!(
        seen.quarantined, 1,
        "premise: one chain of the next burst was reported uncertain"
    );
    assert_eq!(
        seen.link,
        Link::Down,
        "the recovery proved the stop and its restart failed"
    );
    assert_eq!(
        seen.chains_held, 0,
        "premise: the proven stop returned every chain"
    );
    assert_eq!(
        seen.taken_at_stop, accepted,
        "premise: the device accepted DATA 0 with the first burst and DATA 1 of the next"
    );
    assert_eq!(
        seen.supplied,
        [true, true],
        "premise: the upload was ready for its fragments and had not ended"
    );
    assert_eq!(
        seen.taken.len(),
        accepted,
        "through the GET's end the client took the accepted fragments and no later one"
    );
    assert!(
        seen.taken == seen.published[..accepted],
        "the fragments the client took are the published object's first bytes"
    );
    assert!(
        matches!(seen.get, Some(Outcome::Incomplete(_))),
        "a GET that handed out fragments and then failed ends Incomplete: {:?}",
        seen.get
    );
    assert_eq!(
        seen.upload,
        Some(UploadOutcome::Unknown),
        "the upload's resends run out against the down link"
    );
}
