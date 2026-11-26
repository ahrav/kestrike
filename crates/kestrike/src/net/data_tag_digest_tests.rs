//! The MAC input is a 16-byte domain block (the owner endpoint identifier, the direction,
//! eleven zero bytes), the canonical header bytes `[0, 176)`, then the covered body: the whole declared body
//! of every kind except DATA, and for DATA the 16-byte digest of its body. A DATA frame whose tag does not
//! cover its body's digest, so that a changed body byte still authenticates under the kept header and tag,
//! breaks the property.
//!
//! Each test seals one frame as its sender does, with the tag `KeyRing::tag` gives the input of
//! `KeyRing::mac_input`, and records two things. The first is the input itself: its domain block, its header
//! bytes and its covered body. The second is what the receiver's ring answers for the datagram as sent and
//! for the same datagram with one body bit changed, at every bit of the body, the header and tag kept.
//! `frame::parse` does not compare a body with the header's body crc, so each changed datagram reaches the
//! tag check; that it parses is a premise.
//!
//! - DATA, owner to client: the covered body is the 16-byte `KeyRing::data_digest` of the body under the
//!   session the header's nonces name, and it is not the body.
//! - PUT DATA, client to owner, the control with a body covered whole: the covered body is the body.

use crate::storage::{Crc32c, EngineBudget};

use super::auth::{AuthError, KeyEntry, KeyRing};
use super::datagram::{HEADER_LEN, PeerId};
use super::frame::{AUTHENTICATED_LEN, Direction, Header, Kind, encode, parse, seal};
use super::frame_tests::put_frame;

const ENDPOINT: u32 = 0x00E1_0001;
const CLIENT: u32 = 0x0000_0C11;
const KEY: [u8; 32] = [0x11; 32];
const OWNER_NONCE: [u8; 16] = [0x0A; 16];
const CLIENT_NONCE: [u8; 16] = [0x0C; 16];

/// The owner's ring and the client's ring, each holding the one key of principal [`CLIENT`] as peer 0.
fn rings() -> (KeyRing, KeyRing) {
    let mut budget = EngineBudget::new(1 << 20);
    let mut ring = || {
        let entry = KeyEntry {
            principal: CLIENT,
            key: &KEY,
        };
        KeyRing::load(&[CLIENT], &[entry], 1, &mut budget).expect("one key loads")
    };
    (ring(), ring())
}

/// A header of [`CLIENT`]'s session under key epoch 1; `kind` and the transfer fields are the caller's.
fn session_header(kind: Kind) -> Header {
    Header {
        kind,
        principal: CLIENT,
        key_epoch: 1,
        owner_nonce: OWNER_NONCE,
        client_nonce: CLIENT_NONCE,
        request: 7,
        sequence: 1,
        allocation: 0,
        total: 0,
        metadata_len: 0,
        body_len: 0,
        index: 0,
        count: 0,
        offset: 0,
        datagram_len: 0,
        grant: 0,
        status: 0,
        remaining_ms: 0,
        key: [0x5A; 32],
        epoch: 3,
        tag: [0; 16],
    }
}

/// What sealing one frame and receiving it, as sent and with each body bit changed, showed.
#[derive(Debug)]
struct Seen {
    /// The input's domain block.
    domain: [u8; 16],
    /// Whether the input's header is the encoded header's bytes `[0, 176)`.
    header_covered: bool,
    /// The input's covered body, its two slices joined.
    covered: Vec<u8>,
    /// The receiver's answer for the datagram as sent.
    sent: Result<(), AuthError>,
    /// Changed datagrams that did not parse.
    unparsed: usize,
    /// The body bits whose change the receiver did not refuse with `Tag`, as (byte, bit, answer).
    admitted: Vec<(usize, u8, Result<(), AuthError>)>,
}

/// Seals `header` with `body` under `sender`'s key as `direction` sends it and receives it at `receiver`.
fn sealed_and_received(
    sender: &KeyRing,
    receiver: &KeyRing,
    header: &Header,
    body: &[u8],
    direction: Direction,
) -> Seen {
    let crc = Crc32c::detect();
    let mut encoded = [0u8; HEADER_LEN];
    encode(crc, header, [body, &[]], &mut encoded).expect("premise: the header encodes");
    let mut digest = [0; 16];
    let unsealed = encoded;
    let input = sender
        .mac_input(
            PeerId(0),
            &unsealed,
            [body, &[]],
            (ENDPOINT, direction),
            &mut digest,
        )
        .expect("premise: the frame has a MAC input");
    let domain = input.domain();
    let header_covered = input.header[..] == unsealed[..AUTHENTICATED_LEN];
    let covered = [input.body[0], input.body[1]].concat();
    let tag = sender
        .tag(PeerId(0), &input)
        .expect("premise: peer 0 holds a key");
    seal(&mut encoded, tag);
    let mut datagram = encoded.to_vec();
    datagram.extend_from_slice(body);
    let answer = |bytes: &[u8]| {
        parse(crc, bytes, false).ok().map(|frame| {
            receiver
                .authenticate(&frame, PeerId(0), ENDPOINT, direction)
                .map(|_| ())
        })
    };
    let sent = answer(&datagram).expect("premise: the sealed datagram parses");
    let (mut unparsed, mut admitted) = (0, Vec::new());
    for at in 0..body.len() {
        for bit in 0..8 {
            let mut changed = datagram.clone();
            changed[HEADER_LEN + at] ^= 1 << bit;
            match answer(&changed) {
                None => unparsed += 1,
                Some(Err(AuthError::Tag)) => {}
                Some(other) => admitted.push((at, bit, other)),
            }
        }
    }
    Seen {
        domain,
        header_covered,
        covered,
        sent,
        unparsed,
        admitted,
    }
}

/// The domain block of a frame travelling `direction`: the endpoint big-endian, the direction byte and
/// eleven zero bytes.
fn domain(direction: u8) -> [u8; 16] {
    let mut block = [0; 16];
    block[..5].copy_from_slice(&[0x00, 0xE1, 0x00, 0x01, direction]);
    block
}

/// An owner-to-client DATA frame: the MAC input covers the domain block, the header bytes `[0, 176)` and the
/// 16-byte digest of the body under the frame's session, the client authenticates the frame, and the same
/// datagram with any one body bit changed is refused `Tag`.
#[test]
fn a_data_tag_covers_the_session_keyed_digest_of_its_body() {
    let (owner, client) = rings();
    let body: Vec<u8> = (0..20u8)
        .map(|at| at.wrapping_mul(37).wrapping_add(5))
        .collect();
    let header = Header {
        allocation: 9,
        total: 20,
        metadata_len: 4,
        body_len: 16,
        count: 1,
        datagram_len: 20,
        ..session_header(Kind::Data)
    };
    let nonces = (OWNER_NONCE, CLIENT_NONCE);
    let digest = owner
        .data_digest(PeerId(0), ENDPOINT, nonces, [&body, &[]])
        .expect("premise: peer 0 holds a key");
    let elsewhere = owner
        .data_digest(
            PeerId(0),
            ENDPOINT,
            ([0x0B; 16], CLIENT_NONCE),
            [&body, &[]],
        )
        .expect("premise: peer 0 holds a key");
    let seen = sealed_and_received(&owner, &client, &header, &body, Direction::OwnerToClient);
    assert_eq!(
        seen.sent,
        Ok(()),
        "premise: the client authenticates the frame as sent, {seen:?}"
    );
    assert_eq!(
        seen.unparsed, 0,
        "premise: a changed body still parses, {seen:?}"
    );
    assert_ne!(
        digest, elsewhere,
        "premise: the digest is keyed by the session, {seen:?}"
    );
    assert_eq!(seen.domain, domain(2), "the domain block, {seen:?}");
    assert!(
        seen.header_covered,
        "the canonical header bytes [0, 176), {seen:?}"
    );
    assert_eq!(
        seen.covered, digest,
        "a DATA frame's covered body is the 16-byte digest of its body, {seen:?}"
    );
    assert_eq!(
        seen.admitted,
        [],
        "a DATA body changed under the kept header and tag is refused, {seen:?}"
    );
}

/// The control whose body is covered whole: a client-to-owner PUT DATA frame's MAC input covers the domain
/// block, the header bytes `[0, 176)` and the whole declared body, the owner authenticates the frame, and
/// the same datagram with any one body bit changed is refused `Tag`.
#[test]
fn a_put_data_tag_covers_its_whole_declared_body() {
    let (owner, client) = rings();
    let (header, body) = put_frame(Kind::PutData, &session_header(Kind::Get));
    let seen = sealed_and_received(&client, &owner, &header, &body, Direction::ClientToOwner);
    assert_eq!(
        seen.sent,
        Ok(()),
        "premise: the owner authenticates the frame as sent, {seen:?}"
    );
    assert_eq!(
        seen.unparsed, 0,
        "premise: a changed body still parses, {seen:?}"
    );
    assert_eq!(
        header.datagram_len as usize,
        body.len(),
        "premise: the header declares the body"
    );
    assert_eq!(seen.domain, domain(1), "the domain block, {seen:?}");
    assert!(
        seen.header_covered,
        "the canonical header bytes [0, 176), {seen:?}"
    );
    assert_eq!(
        seen.covered, body,
        "the covered body is the whole declared body, {seen:?}"
    );
    assert_eq!(
        seen.admitted,
        [],
        "a body changed under the kept header and tag is refused, {seen:?}"
    );
}
