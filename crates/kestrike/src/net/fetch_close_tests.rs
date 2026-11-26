//! `FetchCore::close` retires a completed GET whose application left fragments untaken: the table slot's window is empty afterwards and their receive boxes are back in the pool, and the next request on the same wire slot is handed only its own fragments, in order, stopping at a DATA hole.

use crate::net::datagram::{HEADER_LEN, PeerId};
use crate::net::fetch_tests::{Fetcher, client, lease_of};
use crate::net::frame::{Header, Kind, encode};
use crate::net::packet::{PacketPool, test_pool};
use crate::net::requests::RequestId;
use crate::net::serve::Manifest;
use crate::net::session::{Admitted, Caps};
use crate::storage::{Crc32c, EngineBudget};

use super::{Outcome, Releases};

/// Fragments in each request's body, equal to the window.
const WINDOW: u32 = 4;
const FRAGMENT: usize = 8192;
const BOXES: u32 = 8;

const SESSION: Admitted = Admitted {
    peer: PeerId(0),
    epoch: 3,
    caps: Caps {
        slots: 1,
        window: WINDOW,
    },
};

/// Admits a GET for `key`, sends it, and binds a START naming a four-fragment body under `allocation`.
fn started(client: &mut Fetcher<'_>, key: [u8; 32], allocation: u64) -> (RequestId, Header) {
    let id = client
        .fetch(SESSION, key, 0, 1 << 20, 0, 1_000_000)
        .unwrap();
    let mut get = None;
    client.poll(0, 4, |ask| {
        get = Some(ask.header);
        true
    });
    let total = u64::from(WINDOW) * FRAGMENT as u64;
    let start = Header {
        kind: Kind::Start,
        allocation,
        total,
        body_len: total as u32,
        metadata_len: 0,
        count: WINDOW,
        grant: 0,
        remaining_ms: 0,
        ..get.expect("the GET")
    };
    client.start(SESSION, &start, 0);
    (id, start)
}

/// The payload of fragment `index` of the request tagged `tag`: every byte is `tag | index`. The tags here have a clear low nibble and the indices are below 16, so the high nibble names the request and the low one the fragment.
fn payload(tag: u8, index: u32) -> Vec<u8> {
    vec![tag | index as u8; FRAGMENT]
}

/// Delivers DATA fragment `index` of `start`'s manifest, carrying [`payload`]`(tag, index)`, in a box of `pool`.
fn deliver<'p>(
    client: &mut Fetcher<'p>,
    pool: &'p PacketPool,
    crc: Crc32c,
    start: &Header,
    tag: u8,
    index: u32,
) {
    let body = payload(tag, index);
    let mut header = Header {
        kind: Kind::Data,
        index,
        offset: u64::from(index) * FRAGMENT as u64,
        ..*start
    };
    header.principal = 1;
    header.key_epoch = 1;
    header.owner_nonce = [0x0A; 16];
    header.client_nonce = [0x0C; 16];
    header.epoch = SESSION.epoch;
    header.sequence = 1;
    header.datagram_len = body.len() as u32;
    let mut out = [0u8; HEADER_LEN];
    encode(crc, &header, [&body, &[]], &mut out).expect("a canonical frame");
    let mut bytes = out.to_vec();
    bytes.extend_from_slice(&body);
    client.data(SESSION, &header, lease_of(pool, &bytes), 0);
}

fn manifest(allocation: u64) -> Manifest {
    Manifest {
        allocation,
        metadata_len: 0,
        body_len: WINDOW * FRAGMENT as u32,
    }
}

/// A GET that completes with three of its four fragments untaken is closed: retirement empties the slot's window and returns the three boxes while the lease the application took keeps its own, and a second request for another key and allocation on the same wire slot, sent DATA 0 and 2 and DATA 1 only later, is handed its own fragment 0 and waits for fragment 1 before it hands out more.
#[test]
fn close_drops_untaken_fragments_before_the_slot_serves_another_request() {
    const OLD: u8 = 0xA0;
    const NEW: u8 = 0xB0;
    let crc = Crc32c::detect();
    let pool = test_pool(BOXES, 2).unwrap();
    let releases = Releases::new(1, &mut EngineBudget::new(1 << 20)).unwrap();
    let mut client = client(&releases, 1, WINDOW, BOXES);

    let (old, start) = started(&mut client, [7; 32], 9);
    for index in 0..WINDOW {
        deliver(&mut client, &pool, crc, &start, OLD, index);
    }
    let issued = client.take(old).expect("fragment 0 of the first request");
    client.complete(
        SESSION,
        &Header {
            kind: Kind::Complete,
            ..start
        },
    );
    assert_eq!(client.outcome(old), Some(Outcome::Complete));
    assert_eq!(
        pool.report().free,
        BOXES - WINDOW,
        "a completed request keeps its untaken fragments until it is closed"
    );
    assert_eq!(client.core.held.iter().flatten().count(), 3);

    assert!(client.close(old), "a decided request retires");
    // Retirement drops unclaimed fragments.
    assert_eq!(
        client.core.held.iter().flatten().count(),
        0,
        "close left unclaimed fragments in the slot's window"
    );
    assert_eq!(
        pool.report().free,
        BOXES - 1,
        "close returned every unclaimed fragment's box; the issued lease keeps its own"
    );
    // The lease the application took before the close is fragment 0 of the first request.
    assert_eq!(issued.index(), 0);
    assert_eq!(issued.manifest(), manifest(9));
    assert_eq!(issued.bytes(), payload(OLD, 0));

    // Retirement frees the wire slot for the peer's next request.
    let (new, start) = started(&mut client, [8; 32], 10);
    assert_eq!(
        new.slot(),
        old.slot(),
        "the one slot serves the next request"
    );
    assert_ne!(new, old);
    deliver(&mut client, &pool, crc, &start, NEW, 0);
    deliver(&mut client, &pool, crc, &start, NEW, 2);
    assert_eq!(
        client.core.held.iter().flatten().count(),
        2,
        "the window holds the two fragments the second request received"
    );
    let first = client.take(new).expect("fragment 0 of the second request");
    assert_eq!(first.index(), 0);
    assert_eq!(first.manifest(), manifest(10));
    assert_eq!(first.bytes(), payload(NEW, 0));
    assert!(
        client.take(new).is_none(),
        "fragment 1 never arrived: nothing of the first request stands in for it"
    );
    deliver(&mut client, &pool, crc, &start, NEW, 1);
    for index in 1..3 {
        let lease = client.take(new).expect("the second request's own fragment");
        assert_eq!(lease.index(), index);
        assert_eq!(lease.manifest(), manifest(10));
        assert_eq!(lease.bytes(), payload(NEW, index));
    }
    assert!(client.take(new).is_none(), "fragment 3 was never sent");
}
