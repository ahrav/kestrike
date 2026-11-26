//! Authentication and session checks: published HMAC-SHA256 vectors, exact truncated tags against an HMAC built by hand from SHA-256, tamper and cross-principal refusals, the bootstrap state machine, replay windows, counter exhaustion and quiescent re-key.

use sha2::{Digest, Sha256};

use crate::storage::{Crc32c, EngineBudget};

use super::auth::{
    AuthError, Authenticated, EntropyError, KEY_LEN, KeyEntry, KeyError, KeyRing, nonce_from,
};
use super::datagram::{HEADER_LEN, PeerId};
use super::frame::{
    Direction, Frame, FrameError, Header, Kind, MacInput, Status, encode, mac_input_for, parse,
    seal,
};
use super::frame_tests::put_frame;
use super::requests::RequestCensus;
use super::session::{
    Bootstrap, CONFIRM_REPEATS, Caps, Newest, RekeyError, Role, SessionReject, SessionReport,
    Sessions, accept,
};

pub(super) const ENDPOINT: u32 = 0x00E1_0001;
const CLIENT: u32 = 0x0000_0C11;
const OTHER: u32 = 0x0000_0C22;
const KEY: [u8; 32] = [0x11; 32];
const OTHER_KEY: [u8; 32] = [0x22; 32];
pub(super) const OWNER_NONCE: [u8; 16] = [0x0A; 16];
pub(super) const CLIENT_NONCE: [u8; 16] = [0x0C; 16];

pub(super) fn crc() -> Crc32c {
    Crc32c::detect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// HMAC-SHA256 built from SHA-256 by RFC 2104's definition, independent of the crate's keyed state.
fn hand_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|k| k ^ byte);
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(data)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5C))
        .chain_update(inner)
        .finalize()
        .into()
}

/// The owner's ring over two client principals and a client's ring over one owner.
pub(super) fn rings() -> (KeyRing, KeyRing) {
    let mut budget = EngineBudget::new(1 << 20);
    let owner = KeyRing::load(
        &[CLIENT, OTHER],
        &[
            KeyEntry {
                principal: OTHER,
                key: &OTHER_KEY,
            },
            KeyEntry {
                principal: CLIENT,
                key: &KEY,
            },
        ],
        1,
        &mut budget,
    )
    .unwrap();
    let client = KeyRing::load(
        &[CLIENT],
        &[KeyEntry {
            principal: CLIENT,
            key: &KEY,
        }],
        1,
        &mut budget,
    )
    .unwrap();
    (owner, client)
}

pub(super) const CAPS: Caps = Caps {
    slots: 64,
    window: 32,
};

pub(super) fn sessions(role: Role, nonce: [u8; 16], peers: u16) -> Sessions {
    Sessions::new(role, nonce, CAPS, peers, &mut EngineBudget::new(1 << 20)).unwrap()
}

/// The header of a bootstrap frame `step` from `principal` under key epoch 1.
fn bootstrap_header(step: &Bootstrap, principal: u32) -> Header {
    Header {
        kind: step.kind,
        principal,
        key_epoch: 1,
        owner_nonce: step.owner_nonce,
        client_nonce: step.client_nonce,
        request: 0,
        sequence: step.sequence,
        allocation: 0,
        total: 0,
        metadata_len: 0,
        body_len: 0,
        index: 0,
        count: 0,
        offset: 0,
        datagram_len: 8,
        grant: 0,
        status: 0,
        remaining_ms: 0,
        key: [0; 32],
        epoch: step.epoch,
        tag: [0; 16],
    }
}

/// Encodes and tags `header` with `body` under `ring`'s key for `peer`, as `direction` sends it, returning the datagram.
pub(super) fn sealed(
    ring: &KeyRing,
    peer: PeerId,
    header: &Header,
    body: &[u8],
    direction: Direction,
) -> Vec<u8> {
    let mut out = [0u8; HEADER_LEN];
    encode(crc(), header, [body, &[]], &mut out).unwrap();
    let mut digest = [0; 16];
    let input = ring
        .mac_input(peer, &out, [body, &[]], (ENDPOINT, direction), &mut digest)
        .unwrap();
    let tag = ring.tag(peer, &input).unwrap();
    seal(&mut out, tag);
    let mut datagram = out.to_vec();
    datagram.extend_from_slice(body);
    datagram
}

/// Bootstrap step `step` from [`CLIENT`] carrying its [`bootstrap_body`](super::frame_tests::bootstrap_body), tagged
/// as `direction` sends it under `ring`'s key for `peer`.
fn bootstrap_datagram(
    ring: &KeyRing,
    peer: PeerId,
    step: &Bootstrap,
    direction: Direction,
) -> Vec<u8> {
    let body = super::frame_tests::bootstrap_body(step);
    let header = Header {
        datagram_len: body.len() as u32,
        ..bootstrap_header(step, CLIENT)
    };
    sealed(ring, peer, &header, &body, direction)
}

pub(super) fn parsed(bytes: &[u8]) -> Frame<'_> {
    parse(crc(), bytes, false).expect("canonical")
}

/// Authenticates `frame` for `direction` as the ring's `peer` sent it; the view borrows `frame`, so callers hold the frame for as long as the view lives.
pub(super) fn authenticate<'f, 'b>(
    ring: &KeyRing,
    frame: &'f Frame<'b>,
    peer: PeerId,
    direction: Direction,
) -> Result<Authenticated<'f, 'b>, AuthError> {
    ring.authenticate(frame, peer, ENDPOINT, direction)
}

/// A GET header in session `epoch` at `sequence`.
pub(super) fn get(epoch: u64, sequence: u64, client_nonce: [u8; 16]) -> Header {
    Header {
        kind: Kind::Get,
        principal: CLIENT,
        key_epoch: 1,
        owner_nonce: OWNER_NONCE,
        client_nonce,
        request: 7,
        sequence,
        allocation: 0,
        total: 0,
        metadata_len: 64,
        body_len: 1 << 16,
        index: 0,
        count: 0,
        offset: 0,
        datagram_len: 0,
        grant: 4,
        status: 0,
        remaining_ms: 100,
        key: [0x5A; 32],
        epoch,
        tag: [0; 16],
    }
}

/// Runs a whole bootstrap between `client` and `owner` for the client's peer 0 and the owner's peer 0, returning the owner's activation epoch.
fn handshake(owner: &mut Sessions, client: &mut Sessions, rings: &(KeyRing, KeyRing)) -> u64 {
    let (owner_ring, client_ring) = rings;
    let hello = client.hello(PeerId(0)).unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let frame = parsed(&bytes);
    let frame = authenticate(owner_ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
    let challenge = owner.on_hello(&frame).unwrap();
    let bytes = bootstrap_datagram(owner_ring, PeerId(0), &challenge, Direction::OwnerToClient);
    let frame = parsed(&bytes);
    let frame = authenticate(client_ring, &frame, PeerId(0), Direction::OwnerToClient).unwrap();
    let confirm = client.on_challenge(&frame).unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &confirm, Direction::ClientToOwner);
    let frame = parsed(&bytes);
    let frame = authenticate(owner_ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
    let activation = owner.on_confirm(&frame).unwrap();
    let bytes = bootstrap_datagram(
        owner_ring,
        PeerId(0),
        &activation.ready,
        Direction::OwnerToClient,
    );
    let frame = parsed(&bytes);
    let frame = authenticate(client_ring, &frame, PeerId(0), Direction::OwnerToClient).unwrap();
    let (admitted, _, _) = client.on_ready(&frame).unwrap();
    assert_eq!(admitted.epoch, activation.ready.epoch);
    admitted.epoch
}

/// RFC 4231 test cases 1 to 7 for HMAC-SHA256: the key, the data and the published MAC, of which case 5 publishes the leftmost 16 bytes.
pub(super) fn rfc_4231_cases() -> [(Vec<u8>, Vec<u8>, Vec<u8>); 7] {
    [
        (
            vec![0x0B; 20],
            b"Hi There".to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        ),
        (
            vec![0xAA; 20],
            vec![0xDD; 50],
            hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        ),
        (
            (1..=25).collect(),
            vec![0xCD; 50],
            hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        ),
        (
            vec![0x0C; 20],
            b"Test With Truncation".to_vec(),
            hex("a3b6167473100ee06e0c796c2955552b"),
        ),
        (
            vec![0xAA; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        ),
        (
            vec![0xAA; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
            hex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
        ),
    ]
}

/// RFC 4231 test cases 1 to 7 match the hand-built HMAC the frame-tag tests compare against: all 32 bytes, and for case 5 the leftmost 16 the RFC publishes.
#[test]
fn hmac_sha256_meets_rfc_4231() {
    for (case, (key, data, mac)) in rfc_4231_cases().iter().enumerate() {
        assert_eq!(
            mac.len(),
            if case == 4 { 16 } else { 32 },
            "case {}",
            case + 1
        );
        assert_eq!(
            hand_hmac(key, data)[..mac.len()],
            mac[..],
            "case {}",
            case + 1
        );
    }
}

/// A frame's tag is the leftmost 16 bytes of HMAC-SHA256 over the domain block, header `[0, 176)` and whole body, here a HELLO's 8-byte control body, keyed by the principal's key, in both directions.
#[test]
fn frame_tags_are_exact_truncated_hmacs_of_the_mac_input() {
    let (owner_ring, client_ring) = rings();
    let hello = Bootstrap {
        tenure: None,
        peer: PeerId(0),
        kind: Kind::Hello,
        owner_nonce: [0; 16],
        client_nonce: CLIENT_NONCE,
        epoch: 0,
        caps: CAPS,
        sequence: 1,
    };
    for direction in [Direction::ClientToOwner, Direction::OwnerToClient] {
        let bytes = bootstrap_datagram(&client_ring, PeerId(0), &hello, direction);
        let mut input = vec![0x00, 0xE1, 0x00, 0x01, direction as u8];
        input.extend_from_slice(&[0; 11]);
        input.extend_from_slice(&bytes[..176]);
        input.extend_from_slice(&bytes[192..200]);
        assert_eq!(
            bytes[176..192],
            hand_hmac(&KEY, &input)[..16],
            "{direction:?}"
        );
        assert!(authenticate(&owner_ring, &parsed(&bytes), PeerId(0), direction).is_ok());
    }
    let datagram = sealed(
        &client_ring,
        PeerId(0),
        &get(3, 1, CLIENT_NONCE),
        &[],
        Direction::ClientToOwner,
    );
    let mut input = vec![0x00, 0xE1, 0x00, 0x01, 1];
    input.extend_from_slice(&[0; 11]);
    input.extend_from_slice(&datagram[..176]);
    assert_eq!(datagram[176..192], hand_hmac(&KEY, &input)[..16]);
}

/// A header-only GET tagged alone and then authenticated alone compresses every block of its chain through the one-chain `sha2` kernel, and its tag is the hand-built HMAC of its MAC input. Each ring's memo starts empty, so the client's tag runs the kernel for the first block, for the two middle header blocks in one run, for the padding block and for the outer block, four runs, and the owner's authentication runs it for the same four: eight runs, so a block compressed another way lowers the count. On a host without `sha2` and `sha3` the line reports the kernel unreached and the tag still matches.
#[test]
fn a_frame_tagged_and_authenticated_alone_runs_the_one_chain_kernel() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    let (owner_ring, client_ring) = rings();
    let one = detected!(aarch64: "sha2", "sha3");
    let present = one.present;
    let before = runs(Kernel::Sha2One);
    let mut datagram = Vec::new();
    witness(
        "hmac-lone",
        one,
        || runs(Kernel::Sha2One),
        || {
            datagram = sealed(
                &client_ring,
                PeerId(0),
                &get(3, 1, CLIENT_NONCE),
                &[],
                Direction::ClientToOwner,
            );
            let frame = parsed(&datagram);
            assert!(authenticate(&owner_ring, &frame, PeerId(0), Direction::ClientToOwner).is_ok());
        },
    );
    assert_eq!(
        runs(Kernel::Sha2One) - before,
        if present { 8 } else { 0 },
        "a lone header-only chain runs the kernel four times to tag and four to authenticate"
    );
    let mut input = vec![0x00, 0xE1, 0x00, 0x01, 1];
    input.extend_from_slice(&[0; 11]);
    input.extend_from_slice(&datagram[..176]);
    assert_eq!(datagram[176..192], hand_hmac(&KEY, &input)[..16]);
}

/// The ring caches first-block SHA-256 states per peer, direction, and kind parity. Tags must match full-input HMACs across cache reuse, same-parity eviction by CANCEL, and switches between directions, peers and endpoints.
#[test]
fn memoized_first_blocks_serve_only_the_frames_they_came_from() {
    let (owner_ring, _) = rings();
    let cancel = |sequence: u64| Header {
        kind: Kind::Cancel,
        metadata_len: 0,
        body_len: 0,
        grant: 0,
        remaining_ms: 0,
        status: 18,
        ..get(3, sequence, CLIENT_NONCE)
    };
    let other_get = |sequence: u64| Header {
        principal: OTHER,
        ..get(3, sequence, [0x0D; 16])
    };
    let runs: [(PeerId, &[u8; 32], Header, Direction); 9] = [
        (
            PeerId(0),
            &KEY,
            get(3, 1, CLIENT_NONCE),
            Direction::ClientToOwner,
        ),
        (
            PeerId(0),
            &KEY,
            get(3, 2, CLIENT_NONCE),
            Direction::ClientToOwner,
        ),
        (PeerId(0), &KEY, cancel(3), Direction::ClientToOwner),
        (
            PeerId(0),
            &KEY,
            get(3, 4, CLIENT_NONCE),
            Direction::ClientToOwner,
        ),
        (
            PeerId(0),
            &KEY,
            get(3, 5, CLIENT_NONCE),
            Direction::OwnerToClient,
        ),
        (
            PeerId(1),
            &OTHER_KEY,
            other_get(1),
            Direction::ClientToOwner,
        ),
        (
            PeerId(1),
            &OTHER_KEY,
            other_get(2),
            Direction::ClientToOwner,
        ),
        (
            PeerId(0),
            &KEY,
            get(3, 6, CLIENT_NONCE),
            Direction::ClientToOwner,
        ),
        (
            PeerId(0),
            &KEY,
            get(4, 1, CLIENT_NONCE),
            Direction::ClientToOwner,
        ),
    ];
    for (at, (peer, key, header, direction)) in runs.iter().enumerate() {
        let datagram = sealed(&owner_ring, *peer, header, &[], *direction);
        let mut input = vec![0x00, 0xE1, 0x00, 0x01, *direction as u8];
        input.extend_from_slice(&[0; 11]);
        input.extend_from_slice(&datagram[..176]);
        assert_eq!(
            datagram[176..192],
            hand_hmac(*key, &input)[..16],
            "run {at}: {:?} {direction:?}",
            header.kind
        );
    }
    let mut encoded = [0u8; HEADER_LEN];
    encode(crc(), &get(3, 7, CLIENT_NONCE), [&[], &[]], &mut encoded).unwrap();
    let mut input = vec![0x00, 0xE1, 0x00, 0x02, 1];
    input.extend_from_slice(&[0; 11]);
    input.extend_from_slice(&encoded[..176]);
    let other_endpoint =
        mac_input_for(&encoded, [&[], &[]], ENDPOINT + 1, Direction::ClientToOwner).unwrap();
    assert_eq!(
        owner_ring.tag(PeerId(0), &other_endpoint).unwrap(),
        hand_hmac(&KEY, &input)[..16],
        "a different endpoint in the same memo slot"
    );
}

/// A tag computed ahead with `tag` or `tag_pair`, under the frame's own peer, authenticates the frame exactly as `authenticate` does, pairs across two peers included. A tag of another frame or of the same frame under another peer's key fails `Tag`; presented for another peer, or for a peer outside the ring, the frame fails as `authenticate` fails it, principal first. `admits` accepts a peer, principal and key epoch exactly when those principal and key-epoch checks pass.
#[test]
fn a_tag_computed_ahead_authenticates_exactly_as_the_frame_s_own_computation() {
    let (owner_ring, client_ring) = rings();
    let other_ring = KeyRing::load(
        &[OTHER],
        &[KeyEntry {
            principal: OTHER,
            key: &OTHER_KEY,
        }],
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let inbound = Direction::ClientToOwner;
    let client = sealed(
        &client_ring,
        PeerId(0),
        &get(3, 1, CLIENT_NONCE),
        &[],
        inbound,
    );
    let other_header = Header {
        principal: OTHER,
        ..get(3, 2, CLIENT_NONCE)
    };
    let other = sealed(&other_ring, PeerId(0), &other_header, &[], inbound);
    let frames = [parsed(&client), parsed(&other)];
    let inputs = frames
        .each_ref()
        .map(|frame| frame.mac_input(ENDPOINT, inbound).unwrap());
    let peers = [PeerId(0), PeerId(1)];
    let paired = owner_ring
        .tag_pair(peers, [&inputs[0], &inputs[1]])
        .unwrap();
    for (at, frame) in frames.iter().enumerate() {
        let alone = owner_ring.tag(peers[at], &inputs[at]).unwrap();
        assert_eq!(alone, paired[at]);
        assert!(
            owner_ring
                .authenticate_tagged(frame, peers[at], paired[at])
                .is_ok()
        );
        assert_eq!(
            owner_ring
                .authenticate_tagged(frame, peers[at], paired[1 - at])
                .err(),
            Some(AuthError::Tag),
            "another frame's tag"
        );
        let foreign = owner_ring.tag(peers[1 - at], &inputs[at]).unwrap();
        assert_eq!(
            owner_ring
                .authenticate_tagged(frame, peers[at], foreign)
                .err(),
            Some(AuthError::Tag),
            "the frame's tag under the other peer's key"
        );
        assert_eq!(
            owner_ring
                .authenticate_tagged(frame, peers[1 - at], paired[at])
                .err(),
            authenticate(&owner_ring, frame, peers[1 - at], inbound).err(),
            "presented for the other peer, the principal check answers first"
        );
        assert!(matches!(
            owner_ring.authenticate_tagged(frame, PeerId(7), paired[at]),
            Err(AuthError::Principal { .. })
        ));
        let header = frame.header();
        for peer in [peers[at], peers[1 - at], PeerId(7)] {
            let refused = matches!(
                owner_ring.authenticate_tagged(frame, peer, paired[at]),
                Err(AuthError::Principal { .. } | AuthError::KeyEpoch { .. })
            );
            assert_eq!(
                owner_ring.admits(peer, header.principal, header.key_epoch),
                !refused,
                "{peer:?}"
            );
        }
        assert!(!owner_ring.admits(peers[at], header.principal, header.key_epoch + 1));
    }
}

/// Flipping the low bit of any header byte in [16, 160) or [164, 176), or of any control-body byte, fails authentication whenever the frame still parses after the header crc is recomputed; so does the other direction's domain, another principal's key, a principal the transport peer does not speak for, and a stale key epoch. Flipping bit 0 or bit 7 of any tag byte in [176, 192) of a GET leaves the frame parseable, because the header crc excludes the tag, and fails with `Tag`.
#[test]
fn every_tamper_and_foreign_key_fails_authentication() {
    let (owner_ring, client_ring) = rings();
    let hello = client_ring_hello();
    let bytes = bootstrap_datagram(&client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let reseal = |bytes: &mut Vec<u8>| {
        bytes[160..164].fill(0);
        let value = crc().checksum(&bytes[..176]);
        bytes[160..164].copy_from_slice(&value.to_be_bytes());
    };
    let mut refused = 0;
    for at in (16..160).chain(164..176).chain(192..200) {
        let mut tampered = bytes.clone();
        tampered[at] ^= 0x01;
        reseal(&mut tampered);
        let Ok(frame) = parse(crc(), &tampered, false) else {
            continue;
        };
        let result = owner_ring.authenticate(&frame, PeerId(0), ENDPOINT, Direction::ClientToOwner);
        assert!(result.is_err(), "byte {at}");
        refused += 1;
    }
    assert!(
        refused == 40,
        "{refused} tampered frames parsed and were refused"
    );
    let get = sealed(
        &client_ring,
        PeerId(0),
        &super::auth_tests::get(3, 1, CLIENT_NONCE),
        &[],
        Direction::ClientToOwner,
    );
    let mut refused = 0;
    for at in (16..160).chain(164..176) {
        let mut tampered = get.clone();
        tampered[at] ^= 0x01;
        reseal(&mut tampered);
        let Ok(frame) = parse(crc(), &tampered, false) else {
            continue;
        };
        let result = owner_ring.authenticate(&frame, PeerId(0), ENDPOINT, Direction::ClientToOwner);
        assert!(result.is_err(), "GET byte {at}");
        refused += 1;
    }
    assert!(
        refused == 114,
        "{refused} tampered GET frames parsed and were refused"
    );
    for at in 176..192 {
        for bit in [0x01, 0x80] {
            let mut tampered = get.clone();
            tampered[at] ^= bit;
            let frame = parse(crc(), &tampered, false).expect("the header crc excludes the tag");
            assert_eq!(
                owner_ring
                    .authenticate(&frame, PeerId(0), ENDPOINT, Direction::ClientToOwner)
                    .err(),
                Some(AuthError::Tag),
                "tag byte {at}, bit {bit:#04x}"
            );
        }
    }
    assert_eq!(
        authenticate(
            &owner_ring,
            &parsed(&bytes),
            PeerId(0),
            Direction::OwnerToClient
        )
        .err(),
        Some(AuthError::Tag),
        "the direction is in the MAC"
    );
    let mut budget = EngineBudget::new(1 << 20);
    let impostor = KeyRing::load(
        &[CLIENT],
        &[KeyEntry {
            principal: CLIENT,
            key: &OTHER_KEY,
        }],
        1,
        &mut budget,
    )
    .unwrap();
    let forged = bootstrap_datagram(&impostor, PeerId(0), &hello, Direction::ClientToOwner);
    assert_eq!(
        authenticate(
            &owner_ring,
            &parsed(&forged),
            PeerId(0),
            Direction::ClientToOwner
        )
        .err(),
        Some(AuthError::Tag),
        "another principal's key"
    );
    assert_eq!(
        authenticate(
            &owner_ring,
            &parsed(&bytes),
            PeerId(1),
            Direction::ClientToOwner
        )
        .err(),
        Some(AuthError::Principal { principal: CLIENT }),
        "a peer speaks for its own principal only"
    );
    let stale = KeyRing::load(
        &[CLIENT],
        &[KeyEntry {
            principal: CLIENT,
            key: &KEY,
        }],
        2,
        &mut budget,
    )
    .unwrap();
    assert_eq!(
        stale
            .authenticate(
                &parse(crc(), &bytes, false).unwrap(),
                PeerId(0),
                ENDPOINT,
                Direction::ClientToOwner
            )
            .err(),
        Some(AuthError::KeyEpoch { found: 1 })
    );
}

fn client_ring_hello() -> Bootstrap {
    Bootstrap {
        tenure: None,
        peer: PeerId(0),
        kind: Kind::Hello,
        owner_nonce: [0; 16],
        client_nonce: CLIENT_NONCE,
        epoch: 0,
        caps: CAPS,
        sequence: 1,
    }
}

/// The loader accepts one distinct well-formed key per configured principal in any order and refuses each other shape with the budget unchanged; diagnostics carry no key bytes.
#[test]
fn the_loader_refuses_every_malformed_key_set() {
    let mut budget = EngineBudget::new(1 << 20);
    let before = budget;
    let peers = [CLIENT, OTHER];
    let entry = |principal, key: &'static [u8]| KeyEntry { principal, key };
    let cases: Vec<(Vec<KeyEntry<'static>>, KeyError)> = vec![
        (
            vec![entry(CLIENT, &KEY)],
            KeyError::Missing { principal: OTHER },
        ),
        (
            vec![entry(CLIENT, &KEY), entry(OTHER, &KEY[..31])],
            KeyError::Malformed {
                principal: OTHER,
                len: 31,
            },
        ),
        (
            vec![entry(CLIENT, &KEY), entry(9, &OTHER_KEY)],
            KeyError::Unknown { principal: 9 },
        ),
        (
            vec![entry(CLIENT, &KEY), entry(CLIENT, &OTHER_KEY)],
            KeyError::Duplicate { principal: CLIENT },
        ),
        (
            vec![entry(CLIENT, &KEY), entry(OTHER, &KEY)],
            KeyError::Shared {
                first: CLIENT,
                second: OTHER,
            },
        ),
    ];
    for (entries, expected) in cases {
        assert_eq!(
            KeyRing::load(&peers, &entries, 1, &mut budget).err(),
            Some(expected)
        );
        assert_eq!(budget, before);
    }
    assert_eq!(
        KeyRing::load(
            &[CLIENT, OTHER, 3],
            &[
                entry(CLIENT, &KEY),
                entry(OTHER, &OTHER_KEY),
                entry(CLIENT, &[7; 32])
            ],
            1,
            &mut budget
        )
        .err(),
        Some(KeyError::Duplicate { principal: CLIENT })
    );
    let mut small = EngineBudget::new(8);
    let allocations = crate::instrument::allocations();
    assert!(matches!(
        KeyRing::load(
            &peers,
            &[entry(CLIENT, &KEY), entry(OTHER, &OTHER_KEY)],
            1,
            &mut small
        ),
        Err(KeyError::Budget(_))
    ));
    // `KeyRing::load` checks the budget before allocating its tables.
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(small.used(), 0);
    let (owner, _) = rings();
    let shown = format!("{owner:?} {:?}", entry(CLIENT, &KEY));
    assert!(!shown.contains("17") && !shown.contains("0x11"), "{shown}");
    assert_eq!(owner.peer_of(OTHER), Some(PeerId(1)));
    assert_eq!(owner.peer_of(5), None);
}

/// A full bootstrap activates one session per CONFIRM; a CONFIRM for the active epoch at a fresh bootstrap sequence repeats READY without a new activation; a HELLO during the session preserves it; a CONFIRM for a replaced challenge is refused.
#[test]
fn a_valid_bootstrap_activates_once_and_hello_preserves_the_session() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    assert_eq!(epoch, 1, "the first issued epoch is 1");
    assert_eq!(owner.report().activations, 1);
    assert_eq!(owner.active(PeerId(0)).unwrap().caps, CAPS);
    // Two later HELLOs; the second replaces the first's challenge, whose CONFIRM is then refused.
    let hello = client.hello(PeerId(0)).unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let first = owner
        .on_hello(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        owner.active(PeerId(0)).map(|active| active.epoch),
        Some(1),
        "HELLO preserves the session"
    );
    let hello = client.hello(PeerId(0)).unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let second = owner
        .on_hello(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!((first.epoch, second.epoch), (2, 3));
    let stale_confirm = Bootstrap {
        kind: Kind::Confirm,
        sequence: hello.sequence + 1,
        ..first
    };
    let bytes = bootstrap_datagram(
        client_ring,
        PeerId(0),
        &stale_confirm,
        Direction::ClientToOwner,
    );
    assert_eq!(
        owner
            .on_confirm(
                &authenticate(
                    owner_ring,
                    &parsed(&bytes),
                    PeerId(0),
                    Direction::ClientToOwner
                )
                .unwrap()
            )
            .err(),
        Some(SessionReject::Mismatch),
        "a replaced challenge cannot activate"
    );
    assert_eq!(owner.report().activations, 1);
    // A repeated CONFIRM for the active epoch repeats READY.
    let active = Bootstrap {
        kind: Kind::Confirm,
        owner_nonce: OWNER_NONCE,
        epoch: 1,
        sequence: stale_confirm.sequence + 1,
        ..first
    };
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &active, Direction::ClientToOwner);
    let repeated = owner
        .on_confirm(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        (repeated.ready.kind, repeated.ready.epoch, repeated.replaced),
        (Kind::Ready, 1, None)
    );
    assert_eq!(owner.report().activations, 1);
}

/// A replayed HELLO is stale; a CHALLENGE echoing any HELLO but the last is stale; a CHALLENGE for another client nonce is refused.
#[test]
fn stale_and_foreign_bootstrap_frames_are_ignored() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let to_owner = |step: &Bootstrap| {
        bootstrap_datagram(client_ring, PeerId(0), step, Direction::ClientToOwner)
    };
    let to_client = |step: &Bootstrap| {
        bootstrap_datagram(owner_ring, PeerId(0), step, Direction::OwnerToClient)
    };
    let first = client.hello(PeerId(0)).unwrap();
    let bytes = to_owner(&first);
    let early = owner
        .on_hello(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        early.sequence, first.sequence,
        "a CHALLENGE echoes its HELLO"
    );
    assert_eq!(
        owner
            .on_hello(
                &authenticate(
                    owner_ring,
                    &parsed(&bytes),
                    PeerId(0),
                    Direction::ClientToOwner
                )
                .unwrap()
            )
            .err(),
        Some(SessionReject::Stale),
        "a replayed HELLO issues no second challenge"
    );
    let second = client.hello(PeerId(0)).unwrap();
    let bytes = to_owner(&second);
    let late = owner
        .on_hello(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    let bytes = to_client(&early);
    assert_eq!(
        client
            .on_challenge(
                &authenticate(
                    client_ring,
                    &parsed(&bytes),
                    PeerId(0),
                    Direction::OwnerToClient
                )
                .unwrap()
            )
            .err(),
        Some(SessionReject::Stale),
        "a challenge to an earlier HELLO"
    );
    let foreign = Bootstrap {
        client_nonce: [0x0D; 16],
        ..late
    };
    let bytes = to_client(&foreign);
    assert_eq!(
        client
            .on_challenge(
                &authenticate(
                    client_ring,
                    &parsed(&bytes),
                    PeerId(0),
                    Direction::OwnerToClient
                )
                .unwrap()
            )
            .err(),
        Some(SessionReject::Mismatch)
    );
    let bytes = to_client(&late);
    assert!(
        client
            .on_challenge(
                &authenticate(
                    client_ring,
                    &parsed(&bytes),
                    PeerId(0),
                    Direction::OwnerToClient
                )
                .unwrap()
            )
            .is_ok()
    );
}

/// After the owner restarts, the old owner boot's CHALLENGE and READY replayed at the client change neither its pending handshake nor its live session.
#[test]
fn an_earlier_owner_boots_replayed_bootstrap_changes_nothing() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut first_owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    // A handshake with the first owner boot, keeping its CHALLENGE and READY.
    let hello = client.hello(PeerId(0)).unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let challenge = first_owner
        .on_hello(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    let old_challenge =
        bootstrap_datagram(owner_ring, PeerId(0), &challenge, Direction::OwnerToClient);
    let confirm = client
        .on_challenge(
            &authenticate(
                client_ring,
                &parsed(&old_challenge),
                PeerId(0),
                Direction::OwnerToClient,
            )
            .unwrap(),
        )
        .unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &confirm, Direction::ClientToOwner);
    let activation = first_owner
        .on_confirm(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    let old_ready = bootstrap_datagram(
        owner_ring,
        PeerId(0),
        &activation.ready,
        Direction::OwnerToClient,
    );
    client
        .on_ready(
            &authenticate(
                client_ring,
                &parsed(&old_ready),
                PeerId(0),
                Direction::OwnerToClient,
            )
            .unwrap(),
        )
        .unwrap();
    // The owner restarts with a new boot nonce and the client handshakes again.
    let mut second_owner = sessions(Role::Owner, [0x0B; 16], 2);
    let epoch = handshake(&mut second_owner, &mut client, &pair);
    for replay in [&old_challenge, &old_ready] {
        let frame = parsed(replay);
        let frame = authenticate(client_ring, &frame, PeerId(0), Direction::OwnerToClient).unwrap();
        let result = match frame.header().kind {
            Kind::Challenge => client.on_challenge(&frame).map(|_| ()),
            _ => client.on_ready(&frame).map(|_| ()),
        };
        assert!(
            matches!(result, Err(SessionReject::Stale | SessionReject::Mismatch)),
            "{result:?}"
        );
    }
    assert_eq!(
        client.active(PeerId(0)).map(|active| active.epoch),
        Some(epoch)
    );
    // The old boot's session frame differs from the successor's only in its owner nonce.
    let old_boot = sealed(
        client_ring,
        PeerId(0),
        &get(epoch, 1, CLIENT_NONCE),
        &[],
        Direction::ClientToOwner,
    );
    assert_eq!(
        second_owner
            .admit(
                &authenticate(
                    owner_ring,
                    &parsed(&old_boot),
                    PeerId(0),
                    Direction::ClientToOwner
                )
                .unwrap()
            )
            .err(),
        Some(SessionReject::Mismatch)
    );
    let genuine = sealed(
        client_ring,
        PeerId(0),
        &Header {
            owner_nonce: [0x0B; 16],
            ..get(epoch, 1, CLIENT_NONCE)
        },
        &[],
        Direction::ClientToOwner,
    );
    assert!(
        second_owner
            .admit(
                &authenticate(
                    owner_ring,
                    &parsed(&genuine),
                    PeerId(0),
                    Direction::ClientToOwner
                )
                .unwrap()
            )
            .is_ok()
    );
}

/// An owner keeps the active client nonce's floor apart from other nonces: a HELLO from the displaced boot is stale, and a HELLO under another nonce does not reopen the active nonce's earlier sequences.
#[test]
fn alternating_client_nonces_cannot_reset_the_active_floor() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut old_boot = sessions(Role::Client, [0x0D; 16], 1);
    handshake(&mut owner, &mut old_boot, &pair);
    let old_hello = old_boot.hello(PeerId(0)).unwrap();
    let old_bytes =
        bootstrap_datagram(client_ring, PeerId(0), &old_hello, Direction::ClientToOwner);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let early = client.hello(PeerId(0)).unwrap();
    let early_bytes = bootstrap_datagram(client_ring, PeerId(0), &early, Direction::ClientToOwner);
    let epoch = handshake(&mut owner, &mut client, &pair);
    assert_eq!(owner.report().displacements, 1);
    let replay = |owner: &mut Sessions, bytes: &[u8]| {
        owner
            .on_hello(
                &authenticate(
                    owner_ring,
                    &parsed(bytes),
                    PeerId(0),
                    Direction::ClientToOwner,
                )
                .unwrap(),
            )
            .err()
    };
    assert_eq!(
        replay(&mut owner, &old_bytes),
        Some(SessionReject::Stale),
        "the displaced boot"
    );
    let stranger = Bootstrap {
        client_nonce: [0x0F; 16],
        sequence: 1,
        ..old_hello
    };
    let stranger = bootstrap_datagram(client_ring, PeerId(0), &stranger, Direction::ClientToOwner);
    assert_eq!(
        replay(&mut owner, &stranger),
        None,
        "a new nonce starts its own floor"
    );
    assert_eq!(
        replay(&mut owner, &early_bytes),
        Some(SessionReject::Stale),
        "the active nonce's floor stays"
    );
    assert_eq!(
        owner.active(PeerId(0)).map(|active| active.epoch),
        Some(epoch)
    );
}

/// A client with a new boot nonce displaces the old session: the activation names the replaced epoch as displaced and the count rises; the old session's frames are refused.
#[test]
fn a_changed_client_boot_displaces_the_old_session() {
    let pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let old = handshake(&mut owner, &mut client, &pair);
    let mut rebooted = sessions(Role::Client, [0x0E; 16], 1);
    let (owner_ring, client_ring) = &pair;
    let hello = rebooted.hello(PeerId(0)).unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let challenge = owner
        .on_hello(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    let bytes = bootstrap_datagram(owner_ring, PeerId(0), &challenge, Direction::OwnerToClient);
    let confirm = rebooted
        .on_challenge(
            &authenticate(
                client_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::OwnerToClient,
            )
            .unwrap(),
        )
        .unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &confirm, Direction::ClientToOwner);
    let activation = owner
        .on_confirm(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    let replaced = activation.replaced.expect("a session was active");
    assert_eq!((replaced.epoch, replaced.displaced), (old, true));
    assert_eq!(owner.report().displacements, 1);
    let stale = sealed(
        client_ring,
        PeerId(0),
        &get(old, 2, CLIENT_NONCE),
        &[],
        Direction::ClientToOwner,
    );
    assert_eq!(
        owner
            .admit(
                &authenticate(
                    owner_ring,
                    &parsed(&stale),
                    PeerId(0),
                    Direction::ClientToOwner
                )
                .unwrap()
            )
            .err(),
        Some(SessionReject::Mismatch)
    );
}

/// Seals bootstrap `step` under its sender's ring for peer 0 and hands the authenticated frame to the far end's `handle`.
pub(super) fn delivered<T>(
    pair: &(KeyRing, KeyRing),
    step: &Bootstrap,
    handle: impl FnOnce(&Authenticated<'_, '_>) -> T,
) -> T {
    let (owner_ring, client_ring) = pair;
    let direction = step.kind.direction();
    let (sender, receiver) = match direction {
        Direction::ClientToOwner => (client_ring, owner_ring),
        Direction::OwnerToClient => (owner_ring, client_ring),
    };
    let bytes = bootstrap_datagram(sender, PeerId(0), step, direction);
    let frame = parsed(&bytes);
    handle(&authenticate(receiver, &frame, PeerId(0), direction).unwrap())
}

/// A client bootstrap that ended in an activation.
struct Bootstrapped {
    /// Each bootstrap frame the client sent, as (kind, bootstrap sequence, epoch), in send order.
    frames: Vec<(Kind, u64, u64)>,
    /// Each refusal `Sessions::confirm` returned for a repeat, in order.
    refusals: Vec<SessionReject>,
}

/// Runs `client`'s bootstrap toward `owner` under the client endpoint's resend rule, which repeats the CONFIRM while `confirm` allows it and otherwise sends a fresh HELLO, and delivers every frame. Each of the `stale` older-boot HELLOs reaches the owner after one of its CHALLENGEs and before the CONFIRM answering it.
/// Returns the client's frames through the activating CONFIRM and the refusals from `client.confirm`. Returns `None` if none of the first `budget` client frames activates the session.
fn bootstrap_past(
    owner: &mut Sessions,
    client: &mut Sessions,
    pair: &(KeyRing, KeyRing),
    stale: &[Bootstrap],
    budget: u32,
) -> Option<Bootstrapped> {
    let mut stale = stale.iter();
    let mut run = Bootstrapped {
        frames: Vec::new(),
        refusals: Vec::new(),
    };
    let mut step = client.hello(PeerId(0)).unwrap();
    for _ in 0..budget {
        run.frames.push((step.kind, step.sequence, step.epoch));
        if step.kind == Kind::Hello {
            let challenge = delivered(pair, &step, |frame| owner.on_hello(frame)).unwrap();
            step = delivered(pair, &challenge, |frame| client.on_challenge(frame)).unwrap();
            if let Some(hello) = stale.next() {
                let displaced = delivered(pair, hello, |frame| owner.on_hello(frame));
                assert!(displaced.is_ok(), "the owner takes the older boot's HELLO");
            }
            continue;
        }
        assert_eq!(step.kind, Kind::Confirm);
        if let Ok(activation) = delivered(pair, &step, |frame| owner.on_confirm(frame)) {
            let (admitted, _, _) =
                delivered(pair, &activation.ready, |frame| client.on_ready(frame)).unwrap();
            assert_eq!(admitted.epoch, activation.ready.epoch);
            return Some(run);
        }
        step = match client.confirm(PeerId(0)) {
            Ok(repeat) => repeat,
            Err(refusal) => {
                run.refusals.push(refusal);
                client.hello(PeerId(0)).unwrap()
            }
        };
    }
    None
}

/// A delayed HELLO from the client's older boot, arriving between the owner's CHALLENGE and the client's CONFIRM, replaces the owner's pending handshake, so that CONFIRM and its repeats mismatch. After `CONFIRM_REPEATS` repeats the client restarts with a fresh HELLO and activates, so the stale HELLO delays activation by the bounded repeats plus one HELLO round trip.
#[test]
fn a_stale_older_boot_hello_delays_activation_by_the_bounded_confirm_repeats() {
    let pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let quiet = bootstrap_past(&mut owner, &mut client, &pair, &[], 16)
        .expect("a HELLO and its CONFIRM activate without interference");
    assert_eq!(quiet.frames, [(Kind::Hello, 1, 0), (Kind::Confirm, 2, 1)]);
    assert_eq!(quiet.refusals, []);
    assert_eq!(owner.report().mismatched, 0);

    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut old_boot = sessions(Role::Client, [0x0D; 16], 1);
    let stale = old_boot.hello(PeerId(0)).unwrap();
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let stalled = bootstrap_past(&mut owner, &mut client, &pair, &[stale], 16)
        .expect("the CONFIRM and its repeats mismatch, then a fresh HELLO round trip activates");
    // The owner challenges the client's first HELLO at epoch 1, the older boot's at 2 and the fresh HELLO at 3.
    let repeats = u64::from(CONFIRM_REPEATS);
    let mut frames = vec![(Kind::Hello, 1, 0)];
    frames.extend((0..=repeats).map(|repeat| (Kind::Confirm, 2 + repeat, 1)));
    frames.extend([
        (Kind::Hello, 3 + repeats, 0),
        (Kind::Confirm, 4 + repeats, 3),
    ]);
    assert_eq!(
        stalled.frames, frames,
        "the CONFIRM and its repeats name the first challenge, then a fresh HELLO restarts the handshake"
    );
    assert_eq!(
        stalled.refusals,
        [SessionReject::Mismatch],
        "the repeat past the bound is refused, and the client restarts on it"
    );
    assert_eq!(
        client.view(PeerId(0)).bootstrap_sent,
        frames.len() as u64,
        "the refused repeat spent no bootstrap sequence"
    );
    let report = owner.report();
    assert_eq!(report.mismatched, u64::from(1 + CONFIRM_REPEATS));
    assert_eq!((report.activations, report.displacements), (1, 0));
    let active = owner.active(PeerId(0)).unwrap();
    assert_eq!(active.epoch, 3, "the third HELLO the owner took");
    assert_eq!(
        client.active(PeerId(0)).map(|a| a.epoch),
        Some(active.epoch)
    );
    assert_eq!(
        owner.nonces(PeerId(0)),
        Some((OWNER_NONCE, CLIENT_NONCE)),
        "the activation binds the current boot's nonces"
    );
}

/// A client repeats a pending handshake's CONFIRM exactly `CONFIRM_REPEATS` times: with every earlier READY lost, the last repeat's READY activates the challenged handshake at its original epoch, and a further repeat is refused before it spends a bootstrap sequence.
#[test]
fn the_last_confirm_repeat_still_activates_its_handshake() {
    let pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let hello = client.hello(PeerId(0)).unwrap();
    let challenge = delivered(&pair, &hello, |frame| owner.on_hello(frame)).unwrap();
    let mut confirm = delivered(&pair, &challenge, |frame| client.on_challenge(frame)).unwrap();
    let mut ready = delivered(&pair, &confirm, |frame| owner.on_confirm(frame))
        .unwrap()
        .ready;
    for _ in 0..CONFIRM_REPEATS {
        confirm = client.confirm(PeerId(0)).unwrap();
        ready = delivered(&pair, &confirm, |frame| owner.on_confirm(frame))
            .unwrap()
            .ready;
    }
    assert_eq!(
        client.confirm(PeerId(0)).err(),
        Some(SessionReject::Mismatch),
        "the repeats are spent"
    );
    let (admitted, replaced, _) = delivered(&pair, &ready, |frame| client.on_ready(frame)).unwrap();
    assert_eq!((admitted.epoch, replaced), (challenge.epoch, None));
    assert_eq!(ready.sequence, confirm.sequence);
    assert_eq!(owner.report().activations, 1);
}

/// Rejecting a sequence-0 HELLO as stale preserves epoch 1 for the next accepted HELLO. Rejecting a sequence-0 CHALLENGE as stale leaves a fresh client in its initial handshake state, so `confirm` returns `SessionReject::Mismatch`.
#[test]
fn a_bootstrap_frame_at_sequence_zero_is_stale() {
    let pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let hello = client_ring_hello();
    let zero = Bootstrap {
        sequence: 0,
        ..hello
    };
    assert_eq!(
        delivered(&pair, &zero, |frame| owner.on_hello(frame)).err(),
        Some(SessionReject::Stale)
    );
    assert_eq!(owner.report().stale, 1);
    let challenge = delivered(&pair, &hello, |frame| owner.on_hello(frame)).unwrap();
    assert_eq!(challenge.epoch, 1);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let early = Bootstrap {
        sequence: 0,
        ..challenge
    };
    assert_eq!(
        delivered(&pair, &early, |frame| client.on_challenge(frame)).err(),
        Some(SessionReject::Stale)
    );
    assert_eq!(client.report().stale, 1);
    assert_eq!(
        client.confirm(PeerId(0)).err(),
        Some(SessionReject::Mismatch)
    );
}

#[test]
fn a_rekey_ends_the_confirm_repeats_with_the_pending_handshake() {
    let mut pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let hello = client.hello(PeerId(0)).unwrap();
    let challenge = delivered(&pair, &hello, |frame| owner.on_hello(frame)).unwrap();
    delivered(&pair, &challenge, |frame| client.on_challenge(frame)).unwrap();
    client.confirm(PeerId(0)).unwrap();
    assert_eq!(client.view(PeerId(0)).confirm_repeats, 1);
    client
        .rekey(
            &mut pair.1,
            &[KeyEntry {
                principal: CLIENT,
                key: &[0x44; 32],
            }],
            2,
            [0x0D; 16],
            RequestCensus::default(),
        )
        .unwrap();
    let view = client.view(PeerId(0));
    assert_eq!((view.pending, view.confirm_repeats), (None, 0));
}

/// Stale HELLOs from two older boots, alternating with the client's restarts, each cost one bounded round of CONFIRM repeats. Every HELLO under a different nonce replaces the owner's other-nonce floor, so a second copy of the first stale HELLO passes again; the client still activates once the copies end, under its own nonces.
#[test]
fn alternating_stale_boot_hellos_each_cost_one_bounded_round() {
    let pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let older = sessions(Role::Client, [0x0D; 16], 1)
        .hello(PeerId(0))
        .unwrap();
    let oldest = sessions(Role::Client, [0x0E; 16], 1)
        .hello(PeerId(0))
        .unwrap();
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let stale = [older, oldest, older];
    let round = 2 + CONFIRM_REPEATS;
    assert_eq!(
        bootstrap_past(&mut owner, &mut client, &pair, &stale, 64)
            .map(|run| run.frames.len() as u32),
        Some(3 * round + 2)
    );
    let report = owner.report();
    assert_eq!(report.mismatched, 3 * u64::from(1 + CONFIRM_REPEATS));
    assert_eq!((report.activations, report.displacements), (1, 0));
    assert_eq!(owner.nonces(PeerId(0)), Some((OWNER_NONCE, CLIENT_NONCE)));
    assert_eq!(
        client.active(PeerId(0)).map(|a| a.epoch),
        owner.active(PeerId(0)).map(|a| a.epoch)
    );
}

/// Session frames pass the replay window in any order within it; duplicates and frames at or below `highest - bits` are dropped without changing the session.
#[test]
fn the_replay_window_accepts_reordering_and_drops_stale_and_duplicates() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    let send = |sequence| {
        sealed(
            client_ring,
            PeerId(0),
            &get(epoch, sequence, CLIENT_NONCE),
            &[],
            Direction::ClientToOwner,
        )
    };
    let admit = |owner: &mut Sessions, sequence| {
        let bytes = send(sequence);
        owner.admit(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
    };
    let bits = Sessions::words(CAPS.window) as u64 * 64;
    assert_eq!(bits, 128, "a 32-fragment window rounds up to two words");
    for sequence in [3, 1, 2, 10, 5] {
        assert!(admit(&mut owner, sequence).is_ok(), "{sequence}");
    }
    assert_eq!(admit(&mut owner, 2).err(), Some(SessionReject::Duplicate));
    assert!(admit(&mut owner, 10 + bits - 1).is_ok());
    assert_eq!(
        admit(&mut owner, 9).err(),
        Some(SessionReject::Stale),
        "at highest - bits"
    );
    assert_eq!(admit(&mut owner, 10).err(), Some(SessionReject::Duplicate));
    assert!(admit(&mut owner, 11).is_ok(), "just inside the window");
    assert_eq!(owner.report().duplicate, 2);
    assert_eq!(owner.report().stale, 1);
    let error = Header {
        kind: Kind::Error,
        status: 1,
        metadata_len: 0,
        body_len: 0,
        grant: 0,
        remaining_ms: 0,
        ..get(epoch, 200, CLIENT_NONCE)
    };
    let bytes = sealed(
        client_ring,
        PeerId(0),
        &error,
        &[],
        Direction::ClientToOwner,
    );
    assert_eq!(
        owner
            .admit(
                &authenticate(
                    owner_ring,
                    &parsed(&bytes),
                    PeerId(0),
                    Direction::ClientToOwner
                )
                .unwrap()
            )
            .err(),
        Some(SessionReject::Kind),
        "an owner never admits an ERROR"
    );
    let mut words = [0u64; 2];
    let mut highest = Newest::default();
    assert_eq!(
        accept(&mut words, &mut highest, 0),
        Err(SessionReject::Stale)
    );
    assert_eq!(accept(&mut words, &mut highest, 500), Ok(()));
    assert_eq!(
        accept(&mut words, &mut highest, 500),
        Err(SessionReject::Duplicate)
    );
    assert_eq!(
        accept(&mut words, &mut highest, 373),
        Ok(()),
        "a slot cleared by the jump"
    );
    assert_eq!(
        accept(&mut words, &mut highest, 372),
        Err(SessionReject::Stale)
    );
}

/// No frame that fails authentication changes a session or a counter: the owner's report stays as it was, and the genuine frame at the same sequence is still admitted.
#[test]
fn frames_that_fail_authentication_change_nothing() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    let report = owner.report();
    let mut forged = sealed(
        client_ring,
        PeerId(0),
        &get(epoch, 1, CLIENT_NONCE),
        &[],
        Direction::ClientToOwner,
    );
    forged[180] ^= 1;
    assert_eq!(
        authenticate(
            owner_ring,
            &parsed(&forged),
            PeerId(0),
            Direction::ClientToOwner
        )
        .err(),
        Some(AuthError::Tag)
    );
    assert_eq!(owner.report(), report);
    let genuine = sealed(
        client_ring,
        PeerId(0),
        &get(epoch, 1, CLIENT_NONCE),
        &[],
        Direction::ClientToOwner,
    );
    assert!(
        owner
            .admit(
                &authenticate(
                    owner_ring,
                    &parsed(&genuine),
                    PeerId(0),
                    Direction::ClientToOwner
                )
                .unwrap()
            )
            .is_ok(),
        "the forged copy took no sequence"
    );
}

/// An exhausted pending epoch or bootstrap sequence retires the peer without panic and is counted; an exhausted send sequence ends the session.
#[test]
fn counter_exhaustion_retires_without_panic() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    handshake(&mut owner, &mut client, &pair);
    owner.set_counters(PeerId(0), u64::MAX, 0);
    let hello = client.hello(PeerId(0)).unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let frame = parsed(&bytes);
    let frame = authenticate(owner_ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
    assert_eq!(owner.on_hello(&frame).err(), Some(SessionReject::Exhausted));
    assert_eq!(owner.on_hello(&frame).err(), Some(SessionReject::Retired));
    assert_eq!(owner.report().retired_peers, 1);
    assert_eq!(
        owner.active(PeerId(0)),
        None,
        "a retired peer keeps no session"
    );
    client.set_counters(PeerId(0), 0, u64::MAX);
    assert_eq!(
        client.hello(PeerId(0)).err(),
        Some(SessionReject::Exhausted)
    );
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    handshake(&mut owner, &mut client, &pair);
    assert_eq!(client.next_sequence(PeerId(0)), Ok(1));
    client.set_send(PeerId(0), u64::MAX);
    assert_eq!(
        client.next_sequence(PeerId(0)),
        Err(SessionReject::Exhausted)
    );
    assert_eq!(client.active(PeerId(0)), None);
    assert_eq!(client.report().exhausted_sessions, 1);
}

#[test]
fn session_counters_issue_their_last_value_once_at_the_actual_width() {
    let pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    owner.set_counters(PeerId(0), u64::MAX - 1, 0);
    let last = handshake(&mut owner, &mut client, &pair);
    assert_eq!(last, u64::MAX, "the last epoch issues once");
    client.set_send(PeerId(0), u64::MAX - 1);
    assert_eq!(client.next_sequence(PeerId(0)), Ok(u64::MAX - 1));
    assert_eq!(
        client.next_sequence(PeerId(0)),
        Err(SessionReject::Exhausted)
    );
    assert_eq!(client.active(PeerId(0)), None);
    client.set_counters(PeerId(0), 0, u64::MAX - 1);
    let hello = client.hello(PeerId(0)).unwrap();
    assert_eq!(
        hello.sequence,
        u64::MAX,
        "the last bootstrap sequence issues once"
    );
    let (owner_ring, client_ring) = &pair;
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let frame = parsed(&bytes);
    let frame = authenticate(owner_ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
    assert_eq!(owner.on_hello(&frame).err(), Some(SessionReject::Exhausted));
    assert_eq!(owner.on_hello(&frame).err(), Some(SessionReject::Retired));
    assert_eq!(
        client.hello(PeerId(0)).err(),
        Some(SessionReject::Exhausted)
    );
    assert_eq!(client.hello(PeerId(0)).err(), Some(SessionReject::Retired));
    assert_eq!(client.report().retired_peers, 1);
}

/// Re-key is one quiescent operation: while requests are live, or when the new keys are refused, the ring and the sessions stay as they were; once quiescent it replaces keys and the nonce in place with no allocation, retires every session, new-key frames authenticate and old-key frames fail on the key epoch.
#[test]
fn quiescent_rekey_replaces_keys_and_nonces_in_place() {
    let pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    handshake(&mut owner, &mut client, &pair);
    let (mut owner_ring, client_ring) = pair;
    let fresh = [0x33u8; 32];
    let entries = [
        KeyEntry {
            principal: CLIENT,
            key: &fresh,
        },
        KeyEntry {
            principal: OTHER,
            key: &OTHER_KEY,
        },
    ];
    for busy in [
        RequestCensus {
            active: 0,
            draining: 1,
            retired: 0,
        },
        RequestCensus {
            active: 1,
            draining: 0,
            retired: 0,
        },
    ] {
        assert_eq!(
            owner.rekey(&mut owner_ring, &entries, 2, [0x0B; 16], busy),
            Err(RekeyError::Busy { census: busy })
        );
        assert_eq!((owner_ring.epoch(), owner.nonce()), (1, OWNER_NONCE));
        assert!(owner.active(PeerId(0)).is_some());
    }
    let shared = [
        KeyEntry {
            principal: CLIENT,
            key: &OTHER_KEY,
        },
        KeyEntry {
            principal: OTHER,
            key: &OTHER_KEY,
        },
    ];
    assert_eq!(
        owner.rekey(
            &mut owner_ring,
            &shared,
            2,
            [0x0B; 16],
            RequestCensus::default()
        ),
        Err(RekeyError::Keys(KeyError::Shared {
            first: CLIENT,
            second: OTHER
        }))
    );
    assert_eq!(
        owner.rekey(
            &mut owner_ring,
            &entries,
            1,
            [0x0B; 16],
            RequestCensus::default()
        ),
        Err(RekeyError::Keys(KeyError::SameEpoch { epoch: 1 })),
        "a re-key moves the key epoch"
    );
    assert_eq!((owner_ring.epoch(), owner.nonce()), (1, OWNER_NONCE));
    assert!(
        owner.active(PeerId(0)).is_some(),
        "a refused re-key keeps the sessions"
    );
    let allocations = crate::instrument::allocations();
    owner
        .rekey(
            &mut owner_ring,
            &entries,
            2,
            [0x0B; 16],
            RequestCensus::default(),
        )
        .unwrap();
    assert_eq!(
        crate::instrument::allocations(),
        allocations,
        "re-key allocates nothing"
    );
    assert_eq!(
        (owner.active(PeerId(0)), owner.nonce(), owner_ring.epoch()),
        (None, [0x0B; 16], 2)
    );
    let old = bootstrap_datagram(
        &client_ring,
        PeerId(0),
        &client_ring_hello(),
        Direction::ClientToOwner,
    );
    assert!(matches!(
        authenticate(
            &owner_ring,
            &parsed(&old),
            PeerId(0),
            Direction::ClientToOwner
        ),
        Err(AuthError::KeyEpoch { found: 1 })
    ));
    let mut budget = EngineBudget::new(1 << 20);
    let new_client = KeyRing::load(
        &[CLIENT],
        &[KeyEntry {
            principal: CLIENT,
            key: &fresh,
        }],
        2,
        &mut budget,
    )
    .unwrap();
    // Floors survive the re-key, so the client's bootstrap sequence keeps rising.
    let hello = Header {
        key_epoch: 2,
        sequence: 100,
        ..bootstrap_header(&client_ring_hello(), CLIENT)
    };
    let renewed = sealed(
        &new_client,
        PeerId(0),
        &hello,
        &CAPS.body(),
        Direction::ClientToOwner,
    );
    let frame = parsed(&renewed);
    let frame = authenticate(&owner_ring, &frame, PeerId(0), Direction::ClientToOwner)
        .expect("the new key authenticates");
    assert!(owner.on_hello(&frame).is_ok());
}

/// Tagging, authentication and admission allocate nothing.
#[test]
fn tagging_authentication_and_admission_allocate_nothing() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    let datagrams: Vec<Vec<u8>> = (1..=8)
        .map(|sequence| {
            let get = get(epoch, sequence, CLIENT_NONCE);
            let (header, body) = if sequence % 2 == 0 {
                put_frame(Kind::PutData, &get)
            } else {
                (get, Vec::new())
            };
            sealed(
                client_ring,
                PeerId(0),
                &header,
                &body,
                Direction::ClientToOwner,
            )
        })
        .collect();
    let allocations = crate::instrument::allocations();
    for bytes in &datagrams {
        let frame = parse(crc(), bytes, false).unwrap();
        let tag = client_ring
            .tag(
                PeerId(0),
                &frame.mac_input(ENDPOINT, Direction::ClientToOwner).unwrap(),
            )
            .unwrap();
        assert_eq!(tag, frame.header().tag);
        let frame = owner_ring
            .authenticate(&frame, PeerId(0), ENDPOINT, Direction::ClientToOwner)
            .unwrap();
        owner.admit(&frame).unwrap();
    }
    assert_eq!(crate::instrument::allocations(), allocations);
}

/// A pair of tags equals the two tags computed alone, across kinds, peers and memo states, and is `None` for a peer outside the ring; a pair of authentications gives each frame the result it gets alone: both verified, or one failing its principal, key epoch or tag, or from a peer outside the ring; pairing allocates nothing.
#[test]
fn pairs_tag_and_authenticate_as_two_singles() {
    let (owner_ring, client_ring) = rings();
    let other_ring = KeyRing::load(
        &[OTHER],
        &[KeyEntry {
            principal: OTHER,
            key: &OTHER_KEY,
        }],
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let mut cancel = get(3, 2, CLIENT_NONCE);
    cancel.kind = Kind::Cancel;
    cancel.status = Status::Cancelled as u16;
    cancel.metadata_len = 0;
    cancel.body_len = 0;
    cancel.grant = 0;
    cancel.remaining_ms = 0;
    let hello = client_ring_hello();
    let hello_header = bootstrap_header(&hello, CLIENT);
    let mut foreign = get(3, 3, CLIENT_NONCE);
    foreign.principal = OTHER;
    let frames: Vec<(PeerId, Header, Vec<u8>)> = vec![
        (PeerId(0), get(3, 1, CLIENT_NONCE), Vec::new()),
        (PeerId(0), cancel, Vec::new()),
        (PeerId(0), hello_header, hello.caps.body().to_vec()),
        (PeerId(1), foreign, Vec::new()),
        (PeerId(0), get(3, 4, CLIENT_NONCE), Vec::new()),
    ];
    let encoded: Vec<[u8; HEADER_LEN]> = frames
        .iter()
        .map(|(_, header, body)| {
            let mut out = [0u8; HEADER_LEN];
            encode(crc(), header, [body, &[]], &mut out).unwrap();
            out
        })
        .collect();
    let ring_of = |peer: PeerId| {
        if peer == PeerId(1) {
            &other_ring
        } else {
            &client_ring
        }
    };
    // Every ordered pair, including a frame with itself and the reverse order, from a cold and a warm memo.
    for (a, b) in (0..frames.len()).flat_map(|a| (0..frames.len()).map(move |b| (a, b))) {
        let (peer_a, _, body_a) = &frames[a];
        let (peer_b, _, body_b) = &frames[b];
        let input_a = mac_input_for(
            &encoded[a],
            [body_a, &[]],
            ENDPOINT,
            Direction::ClientToOwner,
        )
        .unwrap();
        let input_b = mac_input_for(
            &encoded[b],
            [body_b, &[]],
            ENDPOINT,
            Direction::ClientToOwner,
        )
        .unwrap();
        for _ in 0..2 {
            let pair = owner_ring
                .tag_pair([*peer_a, *peer_b], [&input_a, &input_b])
                .unwrap();
            assert_eq!(
                pair[0],
                owner_ring.tag(*peer_a, &input_a).unwrap(),
                "{a} with {b}"
            );
            assert_eq!(
                pair[1],
                owner_ring.tag(*peer_b, &input_b).unwrap(),
                "{a} with {b}"
            );
            assert_eq!(pair[0], ring_of(*peer_a).tag(PeerId(0), &input_a).unwrap());
        }
    }
    assert_eq!(
        owner_ring.tag_pair(
            [PeerId(0), PeerId(2)],
            [&mac_input_for(&encoded[0], [&[], &[]], ENDPOINT, Direction::ClientToOwner).unwrap();
                2]
        ),
        None,
        "a peer outside the ring"
    );

    // Sealed datagrams: GET, CANCEL and HELLO verify; a GET under a wrong key epoch, one tampered after sealing, one for peer 1 whose principal is peer 0's, and one from peer 2, outside the ring, fail.
    let mut datagrams: Vec<(PeerId, Vec<u8>)> = frames
        .iter()
        .map(|(peer, header, body)| {
            (
                *peer,
                sealed(
                    ring_of(*peer),
                    PeerId(0),
                    header,
                    body,
                    Direction::ClientToOwner,
                ),
            )
        })
        .collect();
    let mut stale = get(3, 5, CLIENT_NONCE);
    stale.key_epoch = 7;
    datagrams.push((
        PeerId(0),
        sealed(
            &client_ring,
            PeerId(0),
            &stale,
            &[],
            Direction::ClientToOwner,
        ),
    ));
    let mut tampered = datagrams[0].1.clone();
    tampered[HEADER_LEN - 1] ^= 0x80;
    datagrams.push((PeerId(0), tampered));
    datagrams.push((PeerId(1), datagrams[0].1.clone()));
    datagrams.push((PeerId(2), datagrams[0].1.clone()));
    let verdict = |result: &Result<Authenticated<'_, '_>, AuthError>| {
        result
            .as_ref()
            .map(|frame| (frame.peer(), frame.header()))
            .map_err(|error| *error)
    };
    let allocations = crate::instrument::allocations();
    let mut outcomes = [0usize; 2];
    for (a, (peer_a, bytes_a)) in datagrams.iter().enumerate() {
        for (peer_b, bytes_b) in &datagrams {
            let frame_a = parsed(bytes_a);
            let frame_b = parsed(bytes_b);
            let (first, second) = owner_ring.authenticate_pair(
                (&frame_a, *peer_a),
                (&frame_b, *peer_b),
                ENDPOINT,
                Direction::ClientToOwner,
            );
            let alone_a =
                owner_ring.authenticate(&frame_a, *peer_a, ENDPOINT, Direction::ClientToOwner);
            let alone_b =
                owner_ring.authenticate(&frame_b, *peer_b, ENDPOINT, Direction::ClientToOwner);
            assert_eq!(verdict(&first), verdict(&alone_a), "{a}");
            assert_eq!(verdict(&second), verdict(&alone_b), "{a}");
            outcomes[usize::from(first.is_ok())] += 1;
        }
    }
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(
        outcomes,
        [4 * datagrams.len(), 5 * datagrams.len()],
        "four of the nine datagrams fail"
    );
}

/// An all-zero nonce is refused, a failing source is reported, and the operating system's entropy yields distinct nonzero nonces.
#[test]
fn boot_nonces_need_nonzero_entropy() {
    assert_eq!(nonce_from(|_| Ok(())), Err(EntropyError::Zero));
    assert_eq!(
        nonce_from(|_| Err(EntropyError::Unavailable { code: 38 })),
        Err(EntropyError::Unavailable { code: 38 })
    );
    let (first, second) = (
        super::auth::boot_nonce().unwrap(),
        super::auth::boot_nonce().unwrap(),
    );
    assert_ne!(first, [0; 16]);
    assert_ne!(first, second);
}

/// A client meets a CHALLENGE's caps against its own, so an owner naming larger caps never raises what the client sized for.
#[test]
fn a_client_meets_challenge_caps_against_its_own() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let small = Caps {
        slots: 8,
        window: 4,
    };
    let mut client = Sessions::new(
        Role::Client,
        CLIENT_NONCE,
        small,
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let hello = client.hello(PeerId(0)).unwrap();
    let challenge = Bootstrap {
        kind: Kind::Challenge,
        owner_nonce: OWNER_NONCE,
        epoch: 1,
        caps: CAPS,
        ..hello
    };
    let bytes = bootstrap_datagram(owner_ring, PeerId(0), &challenge, Direction::OwnerToClient);
    let confirm = client
        .on_challenge(
            &authenticate(
                client_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::OwnerToClient,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(confirm.caps, small);
}

/// Against an active session, a frame differing only in its epoch, owner nonce or client nonce is refused.
#[test]
fn a_session_frame_must_match_epoch_and_both_nonces() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    let cases = [
        Header {
            epoch: epoch + 1,
            ..get(epoch, 1, CLIENT_NONCE)
        },
        Header {
            owner_nonce: [0x0B; 16],
            ..get(epoch, 2, CLIENT_NONCE)
        },
        get(epoch, 3, [0x0D; 16]),
    ];
    for header in cases {
        let bytes = sealed(
            client_ring,
            PeerId(0),
            &header,
            &[],
            Direction::ClientToOwner,
        );
        let frame = parsed(&bytes);
        let frame = authenticate(owner_ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
        assert_eq!(
            owner.admit(&frame).err(),
            Some(SessionReject::Mismatch),
            "{header:?}"
        );
    }
    assert_eq!(owner.report().mismatched, 3);
}

/// A client admits owner-to-client kinds under its replay window and refuses a GET; a HELLO during the session keeps it active.
#[test]
fn a_client_admits_owner_kinds_and_keeps_its_session_across_hello() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    let error = |sequence| Header {
        kind: Kind::Error,
        status: 1,
        metadata_len: 0,
        body_len: 0,
        grant: 0,
        remaining_ms: 0,
        ..get(epoch, sequence, CLIENT_NONCE)
    };
    let admit = |client: &mut Sessions, header: &Header| {
        let bytes = sealed(owner_ring, PeerId(0), header, &[], Direction::OwnerToClient);
        client.admit(
            &authenticate(
                client_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::OwnerToClient,
            )
            .unwrap(),
        )
    };
    assert!(admit(&mut client, &error(1)).is_ok());
    assert_eq!(
        admit(&mut client, &error(1)).err(),
        Some(SessionReject::Duplicate)
    );
    assert!(admit(&mut client, &error(2)).is_ok());
    assert_eq!(
        admit(&mut client, &get(epoch, 3, CLIENT_NONCE)).err(),
        Some(SessionReject::Kind)
    );
    client.hello(PeerId(0)).unwrap();
    assert_eq!(
        client.active(PeerId(0)).map(|active| active.epoch),
        Some(epoch),
        "HELLO keeps the session"
    );
}

/// Each PUT kind is admitted in one direction only: an owner admits BEGIN, PREPARE, DATA and CANCEL and a client admits AUTHORITY, READY, ACK, RESULT and ERROR. A PUT kind sent the wrong way is refused as a kind the role does not receive before the replay window or any counter moves: a kind the role receives, sent at the refused frame's sequence, is admitted afterwards, and the session report is unchanged. An admitted PUT frame records its sequence, so its replay is a duplicate.
#[test]
fn each_put_kind_is_admitted_in_one_direction_only() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    let get = get(epoch, 1, CLIENT_NONCE);
    let error = Header {
        kind: Kind::Error,
        status: 1,
        metadata_len: 0,
        body_len: 0,
        grant: 0,
        remaining_ms: 0,
        ..get
    };
    let admit = |sessions: &mut Sessions, header: &Header, body: &[u8], direction| {
        let (sender, receiver) = match direction {
            Direction::ClientToOwner => (client_ring, owner_ring),
            Direction::OwnerToClient => (owner_ring, client_ring),
        };
        let bytes = sealed(sender, PeerId(0), header, body, direction);
        sessions.admit(&authenticate(receiver, &parsed(&bytes), PeerId(0), direction).unwrap())
    };
    let toward_owner = [
        Kind::PutBegin,
        Kind::PutPrepare,
        Kind::PutData,
        Kind::PutCancel,
    ];
    for (sessions, direction, received) in [
        (&mut owner, Direction::ClientToOwner, get),
        (&mut client, Direction::OwnerToClient, error),
    ] {
        let mut sequence = 0;
        for kind in Kind::ALL.into_iter().filter(|kind| kind.is_put()) {
            sequence += 1;
            let (put, body) = put_frame(kind, &Header { sequence, ..get });
            let ours = toward_owner.contains(&kind) == (direction == Direction::ClientToOwner);
            let report = sessions.report();
            if ours {
                assert!(
                    admit(sessions, &put, &body, direction).is_ok(),
                    "{kind:?} toward {direction:?}"
                );
                assert_eq!(
                    admit(sessions, &put, &body, direction).err(),
                    Some(SessionReject::Duplicate),
                    "{kind:?} replayed"
                );
                continue;
            }
            assert_eq!(
                admit(sessions, &put, &body, direction).err(),
                Some(SessionReject::Kind),
                "{kind:?} toward {direction:?}"
            );
            assert_eq!(sessions.report(), report, "{kind:?}");
            let same = Header {
                sequence,
                ..received
            };
            assert!(
                admit(sessions, &same, &[], direction).is_ok(),
                "{kind:?} left sequence {sequence} unseen"
            );
        }
    }
}

/// A tag over a PUT kind's header and whole body is the truncated HMAC an independent RFC 2104 construction over SHA-256 gives for the domain block, the header and the body, at body lengths around every block and padding boundary, at the 16 bytes whose single slice ends the inner hash on one block copied from a constant padding template, and at a full fragment; every split of the body across two slices and every pairing of unequal bodies gives the single-call tag.
#[test]
fn put_tags_match_an_independent_hmac_over_every_body_length() {
    let (_, client_ring) = rings();
    let mut header = [0u8; 176];
    for (at, byte) in header.iter_mut().enumerate() {
        *byte = (at as u8).wrapping_mul(13) ^ 0x5C;
    }
    header[10] = Kind::PutData as u8;
    let lengths = [
        0usize, 1, 15, 16, 17, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 8191, 8192,
    ];
    let body: Vec<u8> = (0..8192).map(|at| (at * 7 + 3) as u8).collect();
    let input = |piece: [&'static [u8]; 2]| MacInput {
        endpoint: ENDPOINT,
        direction: Direction::ClientToOwner,
        header: Box::leak(Box::new(header)),
        body: piece,
    };
    let body: &'static [u8] = Box::leak(body.into_boxed_slice());
    let mut tags = Vec::new();
    for len in lengths {
        let covered = &body[..len];
        let whole = input([covered, &[]]);
        let mut message = whole.domain().to_vec();
        message.extend_from_slice(&header);
        message.extend_from_slice(covered);
        let expected = hand_hmac(&KEY, &message);
        let tag = client_ring.tag(PeerId(0), &whole).unwrap();
        assert_eq!(tag[..], expected[..16], "length {len}");
        let splits = [0, 1, len / 2, len.saturating_sub(1), len, 56, 64];
        for split in splits.into_iter().filter(|split| *split <= len) {
            let (first, second) = covered.split_at(split);
            assert_eq!(
                client_ring.tag(PeerId(0), &input([first, second])),
                Some(tag),
                "length {len} split at {split}"
            );
        }
        tags.push((covered, tag));
    }
    for &(a, tag_a) in &tags {
        for &(b, tag_b) in &tags {
            let pair =
                client_ring.tag_pair([PeerId(0), PeerId(0)], [&input([a, &[]]), &input([b, &[]])]);
            assert_eq!(
                pair,
                Some([tag_a, tag_b]),
                "lengths {} and {}",
                a.len(),
                b.len()
            );
        }
    }
}

#[test]
fn put_tag_pairs_over_split_bodies_match_single_tags() {
    let (_, client_ring) = rings();
    let mut header = [0u8; 176];
    for (at, byte) in header.iter_mut().enumerate() {
        *byte = (at as u8).wrapping_mul(29) ^ 0xA5;
    }
    header[10] = Kind::PutData as u8;
    let header: &'static [u8; 176] = Box::leak(Box::new(header));
    let body: &'static [u8] = Box::leak(
        (0..8192)
            .map(|at| (at * 11 + 5) as u8)
            .collect::<Vec<u8>>()
            .into_boxed_slice(),
    );
    let input = |piece: [&'static [u8]; 2]| MacInput {
        endpoint: ENDPOINT,
        direction: Direction::ClientToOwner,
        header,
        body: piece,
    };
    let lengths = [1usize, 63, 64, 65, 129, 8191, 8192];
    for len_a in lengths {
        for len_b in lengths {
            let (a, b) = (&body[..len_a], &body[..len_b]);
            let single = [
                client_ring.tag(PeerId(0), &input([a, &[]])).unwrap(),
                client_ring.tag(PeerId(0), &input([b, &[]])).unwrap(),
            ];
            for split_a in [1, 64, len_a / 2, len_a - 1] {
                for split_b in [1, 64, len_b / 2, len_b - 1] {
                    let (a0, a1) = a.split_at(split_a.min(len_a));
                    let (b0, b1) = b.split_at(split_b.min(len_b));
                    assert_eq!(
                        client_ring
                            .tag_pair([PeerId(0), PeerId(0)], [&input([a0, a1]), &input([b0, b1])]),
                        Some(single),
                        "lengths {len_a} and {len_b} split at {split_a} and {split_b}"
                    );
                }
            }
        }
    }
}

#[test]
fn put_tag_groups_match_single_tags() {
    let (owner_ring, _) = rings();
    let headers: [&'static [u8; 176]; 4] = std::array::from_fn(|position| {
        let mut header = [0u8; 176];
        for (at, byte) in header.iter_mut().enumerate() {
            *byte = (at as u8).wrapping_mul(31) ^ 0x5A ^ (position as u8).wrapping_mul(0x3B);
        }
        header[10] = Kind::PutData as u8;
        &*Box::leak(Box::new(header))
    });
    let body: &'static [u8] = Box::leak(
        (0..8192)
            .map(|at| (at * 13 + 7) as u8)
            .collect::<Vec<u8>>()
            .into_boxed_slice(),
    );
    let peers = [PeerId(0), PeerId(1), PeerId(1), PeerId(0)];
    let shapes = [(8192, 4096), (8191, 1), (64, 63), (1, 0)];
    let inputs: [MacInput<'static>; 4] = std::array::from_fn(|position| {
        let (len, split) = shapes[position];
        let (head, tail) = body[..len].split_at(split);
        MacInput {
            endpoint: ENDPOINT,
            direction: Direction::ClientToOwner,
            header: headers[position],
            body: [head, tail],
        }
    });
    let single: Vec<_> = (0..4)
        .map(|at| owner_ring.tag(peers[at], &inputs[at]).unwrap())
        .collect();
    let group = |at: usize| (peers[at], &inputs[at]);
    assert_eq!(
        owner_ring.tag_group([group(0), group(1)]).unwrap(),
        single[..2]
    );
    assert_eq!(
        owner_ring
            .tag_group([group(1), group(2), group(3)])
            .unwrap(),
        single[1..]
    );
    assert_eq!(
        owner_ring
            .tag_group([group(0), group(1), group(2), group(3)])
            .unwrap(),
        single[..]
    );
    assert_eq!(
        owner_ring.tag_group([group(0), (PeerId(2), &inputs[1])]),
        None,
        "a peer outside the ring refuses the group"
    );
}

/// XORs a multiple of the crc32c generator polynomial into `bytes` at `at`, which changes the bytes and keeps their crc32c.
pub(super) fn crc_preserving_flip(bytes: &mut [u8], at: usize) {
    // The generator x^32 + 0x1EDC6F41 in the crc's reflected bit order, least significant byte first.
    for (byte, delta) in bytes[at..].iter_mut().zip([0xF1, 0x76, 0xEC, 0x05, 0x01]) {
        *byte ^= delta;
    }
}

/// A body changed after sealing so that its crc32c stays the same passes the body crc on every kind. On PUT DATA, whose tag covers the whole body, it fails the tag and the session it names changes nothing: the original frame at the same sequence is admitted afterwards. On GET DATA, whose tag covers the body's digest, the same change fails the tag and the honest frame authenticates.
#[test]
fn a_crc_preserving_put_body_alteration_fails_the_mac() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    let (put, body) = put_frame(Kind::PutData, &get(epoch, 1, CLIENT_NONCE));
    let honest = sealed(
        client_ring,
        PeerId(0),
        &put,
        &body,
        Direction::ClientToOwner,
    );
    let mut altered = honest.clone();
    crc_preserving_flip(&mut altered, HEADER_LEN + 40);
    assert_ne!(altered, honest);
    let frame = parsed(&altered);
    assert!(frame.check_body(crc()).is_ok(), "the crc holds");
    let report = owner.report();
    assert_eq!(
        authenticate(owner_ring, &frame, PeerId(0), Direction::ClientToOwner).err(),
        Some(AuthError::Tag)
    );
    assert_eq!(owner.report(), report);
    let frame = parsed(&honest);
    let frame = authenticate(owner_ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
    assert!(owner.admit(&frame).is_ok(), "the sequence stayed unseen");
    let data = Header {
        kind: Kind::Data,
        ..put
    };
    let honest = sealed(
        owner_ring,
        PeerId(0),
        &data,
        &body,
        Direction::OwnerToClient,
    );
    let mut altered = honest.clone();
    crc_preserving_flip(&mut altered, HEADER_LEN + 40);
    let frame = parsed(&altered);
    assert!(frame.check_body(crc()).is_ok(), "the crc holds");
    assert_eq!(
        authenticate(client_ring, &frame, PeerId(0), Direction::OwnerToClient).err(),
        Some(AuthError::Tag),
        "GET DATA's tag covers its body through the body digest"
    );
    let frame = parsed(&honest);
    assert!(
        authenticate(client_ring, &frame, PeerId(0), Direction::OwnerToClient).is_ok(),
        "the honest frame authenticates"
    );
}

/// Two PUT DATA frames of unequal bodies, a full fragment and one byte, authenticate together as each does alone, and a changed body fails only its own frame.
#[test]
fn put_frames_of_unequal_bodies_authenticate_as_a_pair() {
    let (owner_ring, client_ring) = rings();
    let base = get(1, 1, CLIENT_NONCE);
    let datagram = |len: u32, sequence: u64| {
        let header = Header {
            kind: Kind::PutData,
            allocation: 5,
            total: u64::from(len),
            metadata_len: 0,
            body_len: len,
            index: 0,
            count: 1,
            offset: 0,
            datagram_len: len,
            grant: 0,
            remaining_ms: 0,
            sequence,
            ..base
        };
        let body: Vec<u8> = (0..len).map(|at| at as u8).collect();
        sealed(
            &client_ring,
            PeerId(0),
            &header,
            &body,
            Direction::ClientToOwner,
        )
    };
    let (long, short) = (datagram(8192, 1), datagram(1, 2));
    let mut forged = long.clone();
    forged[HEADER_LEN + 8000] ^= 1;
    for (first, second, expect) in [
        (&long, &short, [true, true]),
        (&short, &long, [true, true]),
        (&forged, &short, [false, true]),
        (&short, &forged, [true, false]),
    ] {
        let (a, b) = (parsed(first), parsed(second));
        let (ra, rb) = owner_ring.authenticate_pair(
            (&a, PeerId(0)),
            (&b, PeerId(0)),
            ENDPOINT,
            Direction::ClientToOwner,
        );
        assert_eq!([ra.is_ok(), rb.is_ok()], expect);
        let alone = [
            authenticate(&owner_ring, &a, PeerId(0), Direction::ClientToOwner).is_ok(),
            authenticate(&owner_ring, &b, PeerId(0), Direction::ClientToOwner).is_ok(),
        ];
        assert_eq!(alone, expect);
    }
}

/// Group authentication accepts the frames [`KeyRing::authenticate`] does and refuses another peer's ring entry and an altered body with `authenticate`'s errors, at every body length around the block boundaries and at 16 bytes, where `authenticate` ends the inner hash on one templated padding block.
#[test]
fn group_authentication_matches_authenticate_at_every_body_length() {
    let (owner_ring, client_ring) = rings();
    let base = get(1, 1, CLIENT_NONCE);
    let datagram = |len: u32, sequence: u64| {
        let header = Header {
            kind: Kind::PutData,
            allocation: 5,
            total: u64::from(len),
            metadata_len: 0,
            body_len: len,
            index: 0,
            count: 1,
            offset: 0,
            datagram_len: len,
            grant: 0,
            remaining_ms: 0,
            sequence,
            ..base
        };
        let body: Vec<u8> = (0..len).map(|at| (at * 7 + 3) as u8).collect();
        sealed(
            &client_ring,
            PeerId(0),
            &header,
            &body,
            Direction::ClientToOwner,
        )
    };
    let lengths = [
        1u32, 15, 16, 17, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 8127, 8128, 8129, 8191,
        8192,
    ];
    for (n, len) in lengths.into_iter().enumerate() {
        let bytes = datagram(len, n as u64 + 1);
        let frame = parsed(&bytes);
        let [authenticated] = owner_ring.authenticate_group(
            [(&frame, PeerId(0))],
            ENDPOINT,
            Direction::ClientToOwner,
        );
        let authenticated = authenticated.unwrap_or_else(|error| panic!("length {len}: {error:?}"));
        let alone = authenticate(&owner_ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
        assert_eq!(authenticated.header(), alone.header(), "length {len}");
        let [other] = owner_ring.authenticate_group(
            [(&frame, PeerId(1))],
            ENDPOINT,
            Direction::ClientToOwner,
        );
        assert_eq!(
            other.err(),
            Some(AuthError::Principal { principal: CLIENT }),
            "length {len}: another peer's ring entry"
        );
        let mut altered = bytes.clone();
        altered[HEADER_LEN + len as usize - 1] ^= 1;
        let altered = parsed(&altered);
        let [refused] = owner_ring.authenticate_group(
            [(&altered, PeerId(0))],
            ENDPOINT,
            Direction::ClientToOwner,
        );
        assert_eq!(
            refused.err(),
            Some(AuthError::Tag),
            "length {len}: the last body byte changed"
        );
    }
}

/// Verification in a pair or in a group hints, per frame, the body lines verification alone hints.
#[test]
fn single_paired_and_grouped_verification_hint_the_same_body_lines() {
    let (owner_ring, client_ring) = rings();
    let base = get(1, 1, CLIENT_NONCE);
    let datagram = |kind: Kind, len: u32, sequence: u64| {
        let header = Header {
            kind,
            allocation: 5,
            total: u64::from(len),
            metadata_len: 0,
            body_len: len,
            index: 0,
            count: 1,
            offset: 0,
            datagram_len: len,
            grant: 0,
            remaining_ms: 0,
            sequence,
            ..base
        };
        let body = vec![0x5A; len as usize];
        match kind {
            Kind::Data => sealed(
                &owner_ring,
                PeerId(0),
                &header,
                &body,
                Direction::OwnerToClient,
            ),
            _ => sealed(
                &client_ring,
                PeerId(0),
                &header,
                &body,
                Direction::ClientToOwner,
            ),
        }
    };
    let hints = || crate::storage::prefetch::READ_HINTS.with(std::cell::Cell::get);
    // A DATA frame's body digest reads its body before the tag, so its verification hints no line.
    for (kind, len, alone_lines) in [
        (Kind::Data, 8192, Some(0)),
        (Kind::Data, 20, Some(0)),
        (Kind::PutData, 8192, None),
        (Kind::PutData, 1, None),
    ] {
        let (ring, direction) = match kind {
            Kind::Data => (&client_ring, Direction::OwnerToClient),
            _ => (&owner_ring, Direction::ClientToOwner),
        };
        let (first, second) = (datagram(kind, len, 1), datagram(kind, len, 2));
        let (a, b) = (parsed(&first), parsed(&second));
        let before = hints();
        assert!(
            ring.authenticate(&a, PeerId(0), ENDPOINT, direction)
                .is_ok()
        );
        let alone = hints() - before;
        let before = hints();
        let (ra, rb) =
            ring.authenticate_pair((&a, PeerId(0)), (&b, PeerId(0)), ENDPOINT, direction);
        assert!(ra.is_ok() && rb.is_ok());
        let paired = hints() - before;
        assert_eq!(2 * alone, paired, "{kind:?} of {len} bytes");
        let before = hints();
        let [ra, rb] =
            ring.authenticate_group([(&a, PeerId(0)), (&b, PeerId(0))], ENDPOINT, direction);
        assert!(ra.is_ok() && rb.is_ok());
        assert_eq!(
            2 * alone,
            hints() - before,
            "{kind:?} of {len} bytes in a group"
        );
        if let Some(lines) = alone_lines {
            assert_eq!(alone, lines, "{kind:?} of {len} bytes");
        }
    }
}

/// A group of PUT DATA frames authenticates as its frames do alone, across body lengths, a forged body, a frame under the wrong principal, and both peers' keys mixed in one group, as arrival order mixes them in production.
#[test]
fn put_data_groups_authenticate_as_singles() {
    let (owner_ring, client_ring) = rings();
    let other_ring = KeyRing::load(
        &[OTHER],
        &[KeyEntry {
            principal: OTHER,
            key: &OTHER_KEY,
        }],
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let base = get(1, 1, CLIENT_NONCE);
    let datagram = |ring: &KeyRing, len: u32, sequence: u64, principal: u32| {
        let header = Header {
            kind: Kind::PutData,
            principal,
            allocation: 5,
            total: u64::from(len),
            metadata_len: 0,
            body_len: len,
            index: 0,
            count: 1,
            offset: 0,
            datagram_len: len,
            grant: 0,
            remaining_ms: 0,
            sequence,
            ..base
        };
        let body: Vec<u8> = (0..len).map(|at| (at * 13 + len) as u8).collect();
        sealed(ring, PeerId(0), &header, &body, Direction::ClientToOwner)
    };
    // Each case with the peer the owner checks it as: CLIENT is `PeerId(0)` and OTHER `PeerId(1)` in the owner's ring.
    let mut cases: Vec<(Vec<u8>, PeerId)> = Vec::new();
    for (sequence, len) in (1..).zip([1u32, 63, 64, 65, 120, 4096, 8191, 8192]) {
        cases.push((datagram(&client_ring, len, sequence, CLIENT), PeerId(0)));
    }
    for (sequence, len) in (20..).zip([1u32, 64, 120, 8192]) {
        cases.push((datagram(&other_ring, len, sequence, OTHER), PeerId(1)));
    }
    let mut forged = datagram(&client_ring, 8192, 50, CLIENT);
    forged[HEADER_LEN + 7000] ^= 1;
    cases.push((forged, PeerId(0)));
    cases.push((datagram(&client_ring, 64, 51, OTHER), PeerId(0)));
    let single = |(bytes, peer): &(Vec<u8>, PeerId)| {
        let frame = parsed(bytes);
        owner_ring
            .authenticate(&frame, *peer, ENDPOINT, Direction::ClientToOwner)
            .map(|verified| verified.header())
    };
    for first in &cases {
        for second in &cases {
            let (a, b) = (parsed(&first.0), parsed(&second.0));
            let [ra, rb] = owner_ring.authenticate_group(
                [(&a, first.1), (&b, second.1)],
                ENDPOINT,
                Direction::ClientToOwner,
            );
            assert_eq!(
                [ra.map(|v| v.header()), rb.map(|v| v.header())],
                [single(first), single(second)]
            );
        }
    }
    let mut rng = crate::storage::seeded::SplitMix64::new(0x4C4A);
    for _ in 0..200 {
        let picks: [usize; 3] = std::array::from_fn(|_| rng.next_u64() as usize % cases.len());
        let frames: [_; 3] = std::array::from_fn(|at| parsed(&cases[picks[at]].0));
        let results = owner_ring.authenticate_group(
            std::array::from_fn(|at| (&frames[at], cases[picks[at]].1)),
            ENDPOINT,
            Direction::ClientToOwner,
        );
        assert_eq!(
            results.map(|r| r.map(|v| v.header())),
            picks.map(|at| single(&cases[at])),
            "{picks:?}"
        );
        let picks: [usize; 4] = std::array::from_fn(|_| rng.next_u64() as usize % cases.len());
        let frames: [_; 4] = std::array::from_fn(|at| parsed(&cases[picks[at]].0));
        let results = owner_ring.authenticate_group(
            std::array::from_fn(|at| (&frames[at], cases[picks[at]].1)),
            ENDPOINT,
            Direction::ClientToOwner,
        );
        assert_eq!(
            results.map(|r| r.map(|v| v.header())),
            picks.map(|at| single(&cases[at])),
            "{picks:?}"
        );
        let picks: [usize; 6] = std::array::from_fn(|_| rng.next_u64() as usize % cases.len());
        let frames: [_; 6] = std::array::from_fn(|at| parsed(&cases[picks[at]].0));
        let results = owner_ring.authenticate_group(
            std::array::from_fn(|at| (&frames[at], cases[picks[at]].1)),
            ENDPOINT,
            Direction::ClientToOwner,
        );
        assert_eq!(
            results.map(|r| r.map(|v| v.header())),
            picks.map(|at| single(&cases[at])),
            "{picks:?}"
        );
        let picks: [usize; 9] = std::array::from_fn(|_| rng.next_u64() as usize % cases.len());
        let frames: [_; 9] = std::array::from_fn(|at| parsed(&cases[picks[at]].0));
        let results = owner_ring.authenticate_group(
            std::array::from_fn(|at| (&frames[at], cases[picks[at]].1)),
            ENDPOINT,
            Direction::ClientToOwner,
        );
        assert_eq!(
            results.map(|r| r.map(|v| v.header())),
            picks.map(|at| single(&cases[at])),
            "{picks:?}"
        );
    }
}

/// The POLYVAL of `body` under `key`, zero-padded to whole blocks, by the reference crate alone.
fn reference_polyval(key: [u8; 16], body: &[u8]) -> [u8; 16] {
    use polyval::universal_hash::UniversalHash;
    let mut hash = polyval::Polyval::new(&key.into());
    hash.update_padded(body);
    hash.finalize().into()
}

/// A session's data key by its definition: the leftmost 16 bytes of HMAC-SHA256 under `key` over the owner-to-client domain block and a 176-byte block of the label, the owner nonce, the client nonce and zeros.
fn reference_data_key(key: &[u8], owner: [u8; 16], client: [u8; 16]) -> [u8; 16] {
    reference_data_key_for(ENDPOINT, key, owner, client)
}

/// [`reference_data_key`] for owner `endpoint`, whose identifier opens the domain block.
fn reference_data_key_for(
    endpoint: u32,
    key: &[u8],
    owner: [u8; 16],
    client: [u8; 16],
) -> [u8; 16] {
    let mut input = endpoint.to_be_bytes().to_vec();
    input.push(2);
    input.extend_from_slice(&[0; 11]);
    let mut block = [0u8; 176];
    block[..16].copy_from_slice(b"IMGNET01DATA KEY");
    block[16..32].copy_from_slice(&owner);
    block[32..48].copy_from_slice(&client);
    input.extend_from_slice(&block);
    hand_hmac(key, &input)[..16].try_into().unwrap()
}

/// A DATA frame's tag covers its body through the body digest: the tag equals the hand-built HMAC over the domain block, the header's first 176 bytes and the reference POLYVAL of the body under the reference data key, and a changed body fails the tag.
#[test]
fn a_data_frame_tag_covers_its_body_through_the_digest() {
    let (owner_ring, client_ring) = rings();
    let start = Header {
        kind: Kind::Data,
        allocation: 9,
        total: 20,
        metadata_len: 4,
        body_len: 16,
        count: 1,
        datagram_len: 20,
        grant: 0,
        remaining_ms: 0,
        ..get(3, 1, CLIENT_NONCE)
    };
    let body = [7u8; 20];
    let bytes = sealed(
        &owner_ring,
        PeerId(0),
        &start,
        &body,
        Direction::OwnerToClient,
    );
    let data_key = reference_data_key(&KEY, OWNER_NONCE, CLIENT_NONCE);
    let mut input = vec![0x00, 0xE1, 0x00, 0x01, 2];
    input.extend_from_slice(&[0; 11]);
    input.extend_from_slice(&bytes[..176]);
    input.extend_from_slice(&reference_polyval(data_key, &body));
    assert_eq!(bytes[176..192], hand_hmac(&KEY, &input)[..16]);
    let mut changed = bytes.clone();
    changed[HEADER_LEN + 3] ^= 1;
    let frame = parsed(&changed);
    assert_eq!(
        authenticate(&client_ring, &frame, PeerId(0), Direction::OwnerToClient).err(),
        Some(AuthError::Tag),
        "the tag covers the body"
    );
    let frame = parsed(&bytes);
    let frame = authenticate(&client_ring, &frame, PeerId(0), Direction::OwnerToClient).unwrap();
    let shown = format!("{frame:?}");
    assert!(!shown.contains("tag") && !shown.contains("key"), "{shown}");
}

/// The owner and the client derive one data key per session, the reference derivation's: both rings' digests of a body equal its reference POLYVAL under that key, under each session's nonces; a digest under another session's nonces or another peer key differs.
#[test]
fn owner_and_client_derive_the_same_data_key_per_session() {
    let (owner_ring, client_ring) = rings();
    let body = (0..8192u32)
        .map(|at| (at * 7 + 3) as u8)
        .collect::<Vec<_>>();
    let sessions = [
        (OWNER_NONCE, CLIENT_NONCE),
        ([0x0B; 16], CLIENT_NONCE),
        (OWNER_NONCE, [0x0D; 16]),
    ];
    let mut digests = Vec::new();
    for nonces in sessions {
        let expected = reference_polyval(reference_data_key(&KEY, nonces.0, nonces.1), &body);
        let owner = owner_ring.data_digest(PeerId(0), ENDPOINT, nonces, [&body, &[]]);
        let client = client_ring.data_digest(PeerId(0), ENDPOINT, nonces, [&body, &[]]);
        assert_eq!(
            (owner, client),
            (Some(expected), Some(expected)),
            "{nonces:?}"
        );
        digests.push(expected);
    }
    assert!(digests[0] != digests[1] && digests[0] != digests[2] && digests[1] != digests[2]);
    let other = owner_ring.data_digest(PeerId(1), ENDPOINT, sessions[0], [&body, &[]]);
    assert_ne!(
        other,
        Some(digests[0]),
        "another peer's key gives another data key"
    );
    // The ring keeps one session's key: returning to the first session derives it again, equal.
    assert_eq!(
        owner_ring.data_digest(PeerId(0), ENDPOINT, sessions[0], [&body, &[]]),
        Some(digests[0])
    );
    let elsewhere = owner_ring.data_digest(PeerId(0), ENDPOINT + 1, sessions[0], [&body, &[]]);
    assert_eq!(
        elsewhere,
        Some(reference_polyval(
            reference_data_key_for(ENDPOINT + 1, &KEY, sessions[0].0, sessions[0].1),
            &body
        )),
        "another endpoint's session of the same nonces derives its own key"
    );
    assert_ne!(elsewhere, Some(digests[0]));
}

/// A DATA header of the session whose owner boot nonce is `owner`, its 20-byte body declared.
fn data_of(owner: [u8; 16]) -> Header {
    Header {
        kind: Kind::Data,
        owner_nonce: owner,
        allocation: 9,
        total: 20,
        metadata_len: 4,
        body_len: 16,
        count: 1,
        datagram_len: 20,
        grant: 0,
        remaining_ms: 0,
        ..get(3, 1, CLIENT_NONCE)
    }
}

/// A received DATA frame installs its session's data key only once its tag verifies: a forged frame naming another session fails alone, in a pair and in a group, and leaves the kept key in place; the authentic frame of that session then authenticates and installs its key; and a DATA frame travelling client to owner fails without touching the key. `data_digest` keeps the key of the session it digests for, and a re-key empties the kept key.
#[test]
fn only_an_authenticated_data_frame_replaces_the_kept_data_key() {
    let (owner_ring, mut client_ring) = rings();
    let body = [7u8; 20];
    let first = (OWNER_NONCE, CLIENT_NONCE);
    let next = ([0x0B; 16], CLIENT_NONCE);
    let honest = sealed(
        &owner_ring,
        PeerId(0),
        &data_of(first.0),
        &body,
        Direction::OwnerToClient,
    );
    let replacing = sealed(
        &owner_ring,
        PeerId(0),
        &data_of(next.0),
        &body,
        Direction::OwnerToClient,
    );
    let mut forged = replacing.clone();
    forged[176] ^= 1;
    let client = Direction::OwnerToClient;
    assert_eq!(client_ring.kept_session(PeerId(0)), None);
    let (forged_frame, honest_frame) = (parsed(&forged), parsed(&honest));
    let replacing_frame = parsed(&replacing);
    let peer = PeerId(0);
    for (offered, verdict, kept) in [
        (&forged_frame, Some(AuthError::Tag), first),
        (&replacing_frame, None, next),
    ] {
        for call in 0..5 {
            assert!(authenticate(&client_ring, &honest_frame, peer, client).is_ok());
            assert_eq!(client_ring.kept_session(peer), Some(first));
            let honest = (&honest_frame, peer);
            let (offered_error, honest_passed) = match call {
                0 => (
                    authenticate(&client_ring, offered, peer, client).err(),
                    true,
                ),
                1 => {
                    let (a, b) =
                        client_ring.authenticate_pair((offered, peer), honest, ENDPOINT, client);
                    (a.err(), b.is_ok())
                }
                2 => {
                    let (a, b) =
                        client_ring.authenticate_pair(honest, (offered, peer), ENDPOINT, client);
                    (b.err(), a.is_ok())
                }
                3 => {
                    let [a, b] =
                        client_ring.authenticate_group([(offered, peer), honest], ENDPOINT, client);
                    (a.err(), b.is_ok())
                }
                _ => {
                    let [a, b] =
                        client_ring.authenticate_group([honest, (offered, peer)], ENDPOINT, client);
                    (b.err(), a.is_ok())
                }
            };
            assert_eq!(
                (offered_error, honest_passed),
                (verdict, true),
                "call {call}"
            );
            assert_eq!(
                client_ring.kept_session(peer),
                Some(kept),
                "call {call}: only a frame whose tag verified displaced the session's key"
            );
        }
    }
    let third = ([0x0D; 16], CLIENT_NONCE);
    assert!(
        client_ring
            .data_digest(peer, ENDPOINT, third, [&body, &[]])
            .is_some()
    );
    assert_eq!(client_ring.kept_session(peer), Some(third));
    let fresh = [KeyEntry {
        principal: CLIENT,
        key: &FRESH_KEY,
    }];
    assert_eq!(client_ring.replace(&fresh, 2), Ok(()));
    assert_eq!(client_ring.kept_session(peer), None);
    let (fresh_owner, _) = rings();
    assert_eq!(
        authenticate(
            &fresh_owner,
            &parsed(&honest),
            PeerId(0),
            Direction::ClientToOwner
        )
        .err(),
        Some(AuthError::Tag)
    );
    assert_eq!(fresh_owner.kept_session(PeerId(0)), None);
}

/// A re-key replaces the data key even when a session keeps its boot nonces: the digest after the re-key is the reference POLYVAL under the key the new peer key derives, and differs from the digest before it.
#[test]
fn a_rekey_installs_a_new_data_key_for_the_same_session_nonces() {
    let (mut owner_ring, _) = rings();
    let body = [0x5Au8; 300];
    let nonces = (OWNER_NONCE, CLIENT_NONCE);
    let before = owner_ring.data_digest(PeerId(0), ENDPOINT, nonces, [&body, &[]]);
    let fresh = [[0x44u8; 32], [0x55; 32]];
    owner_ring
        .replace(
            &[
                KeyEntry {
                    principal: CLIENT,
                    key: &fresh[0],
                },
                KeyEntry {
                    principal: OTHER,
                    key: &fresh[1],
                },
            ],
            2,
        )
        .unwrap();
    let after = owner_ring.data_digest(PeerId(0), ENDPOINT, nonces, [&body, &[]]);
    assert_eq!(
        after,
        Some(reference_polyval(
            reference_data_key(&fresh[0], nonces.0, nonces.1),
            &body
        ))
    );
    assert_ne!(after, before);
}

/// A DATA payload whose length differs from the header's datagram body length has no MAC input, as a covered PUT payload of the wrong length has none.
#[test]
fn a_data_payload_of_another_length_than_declared_has_no_mac_input() {
    let (owner_ring, _) = rings();
    let body = [7u8; 20];
    let mut encoded = [0u8; HEADER_LEN];
    encode(crc(), &data_of(OWNER_NONCE), [&body, &[]], &mut encoded).unwrap();
    let mut digest = [0; 16];
    let outbound = (ENDPOINT, Direction::OwnerToClient);
    for payload in [
        [&body[..19], &[][..]],
        [&body[..], &body[..1]],
        [&body[..10], &body[10..]],
    ] {
        let input = owner_ring.mac_input(PeerId(0), &encoded, payload, outbound, &mut digest);
        assert_eq!(
            input.is_some(),
            payload[0].len() + payload[1].len() == 20,
            "{payload:?}"
        );
    }
}

/// Accept and reject follow the reference definition: for random bodies of lengths 1 through 48 and at the block and fragment boundaries 255 to 257, 4095 to 4097 and 8191 to 8192, split in two slices at every 17th offset, at the end and at random, each ring's digest equals the reference POLYVAL of the joined body, a frame sealed by the owner authenticates at the client, and a frame tagged under the reference input with one body byte changed fails.
#[test]
fn data_tags_match_the_reference_composition_for_every_length_and_split() {
    let (owner_ring, client_ring) = rings();
    let data_key = reference_data_key(&KEY, OWNER_NONCE, CLIENT_NONCE);
    let mut rng = crate::storage::seeded::SplitMix64::new(896);
    let lengths = (1..=48).chain([255, 256, 257, 4095, 4096, 4097, 8191, 8192]);
    for len in lengths {
        let body: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
        let expected = reference_polyval(data_key, &body);
        let splits = (0..=len)
            .step_by(17)
            .chain([len, (rng.next_u64() as usize) % (len + 1)]);
        for split in splits {
            let (first, second) = body.split_at(split);
            for ring in [&owner_ring, &client_ring] {
                assert_eq!(
                    ring.data_digest(
                        PeerId(0),
                        ENDPOINT,
                        (OWNER_NONCE, CLIENT_NONCE),
                        [first, second]
                    ),
                    Some(expected),
                    "length {len} split {split}"
                );
            }
        }
        let header = Header {
            kind: Kind::Data,
            allocation: 9,
            total: len as u64,
            metadata_len: 0,
            body_len: len as u32,
            count: 1,
            datagram_len: len as u32,
            grant: 0,
            remaining_ms: 0,
            ..get(3, 1 + len as u64, CLIENT_NONCE)
        };
        let bytes = sealed(
            &owner_ring,
            PeerId(0),
            &header,
            &body,
            Direction::OwnerToClient,
        );
        let mut input = vec![0x00, 0xE1, 0x00, 0x01, 2];
        input.extend_from_slice(&[0; 11]);
        input.extend_from_slice(&bytes[..176]);
        input.extend_from_slice(&expected);
        assert_eq!(
            bytes[176..192],
            hand_hmac(&KEY, &input)[..16],
            "length {len}"
        );
        let frame = parsed(&bytes);
        assert!(
            authenticate(&client_ring, &frame, PeerId(0), Direction::OwnerToClient).is_ok(),
            "length {len}"
        );
        let mut changed = bytes.clone();
        let at = HEADER_LEN + (rng.next_u64() as usize) % len;
        changed[at] ^= 1 << (rng.next_u64() % 8);
        let frame = parsed(&changed);
        assert_eq!(
            authenticate(&client_ring, &frame, PeerId(0), Direction::OwnerToClient).err(),
            Some(AuthError::Tag),
            "length {len} byte {at}"
        );
    }
}

/// The replay window agrees with a set model over seeded sequences: sequence 0 and any sequence at or below `highest - size` are stale, a seen sequence is a duplicate, and anything else is accepted.
#[test]
fn the_replay_window_matches_a_set_model() {
    for (words, climb) in [1usize, 2, 3, 65]
        .into_iter()
        .flat_map(|words| [(words, 1), (words, words as u64 * 256)])
    {
        let size = words as u64 * 64;
        let mut rng = crate::storage::seeded::SplitMix64::new(words as u64 * 1000 + climb);
        let (mut bits, mut highest) = (vec![0u64; words], Newest::default());
        let (mut seen, mut newest) = (std::collections::BTreeSet::new(), 0u64);
        for step in 0..10_000u64 {
            // Jitter of twice the window reorders sequences; the faster climb raises the base by half the window per step, so advances clear runs that cross word boundaries and the bitmap's wrap point.
            let sequence = step * climb / 8 + rng.below(2 * size);
            let expected = set_verdict(&seen, newest, size, sequence);
            assert_eq!(
                accept(&mut bits, &mut highest, sequence),
                expected,
                "{sequence} after {}",
                highest.sequence
            );
            if expected.is_ok() {
                seen.insert(sequence);
                newest = newest.max(sequence);
            }
        }
        assert!(
            seen.len() > 1000,
            "{words} words, climb {climb}: {} accepted",
            seen.len()
        );
    }
}

/// [`Sessions::admit`] agrees with the set model for two sessions of one owner table, admitted in interleaved order. Each history is mostly the next sequence, which `admit` records in the newest entry's word, and crosses 64-entry blocks and laps of the 128-entry bitmap; the rest are gaps, older and repeated sequences, jumps past the window and sequence 0. A sequence recorded in the other peer's words would break that peer's model, and the report counts exactly the model's refusals.
#[test]
fn admission_matches_the_set_model_for_two_sessions_of_one_table() {
    let (owner_ring, client_ring) = rings();
    let other_ring = KeyRing::load(
        &[OTHER],
        &[KeyEntry {
            principal: OTHER,
            key: &OTHER_KEY,
        }],
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    let clients = [
        (&client_ring, CLIENT, CLIENT_NONCE),
        (&other_ring, OTHER, [0x0D; 16]),
    ];
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut epochs = [0; 2];
    for (at, &(ring, principal, nonce)) in clients.iter().enumerate() {
        let peer = PeerId(at as u16);
        let mut client = sessions(Role::Client, nonce, 1);
        let datagram = |step: &Bootstrap, ring: &KeyRing, peer, direction| {
            let body = super::frame_tests::bootstrap_body(step);
            sealed(
                ring,
                peer,
                &bootstrap_header(step, principal),
                &body,
                direction,
            )
        };
        let inbound = Direction::ClientToOwner;
        let hello = datagram(&client.hello(PeerId(0)).unwrap(), ring, PeerId(0), inbound);
        let challenge = owner
            .on_hello(&authenticate(&owner_ring, &parsed(&hello), peer, inbound).unwrap())
            .unwrap();
        let challenge = datagram(&challenge, &owner_ring, peer, Direction::OwnerToClient);
        let confirm = client
            .on_challenge(
                &authenticate(
                    ring,
                    &parsed(&challenge),
                    PeerId(0),
                    Direction::OwnerToClient,
                )
                .unwrap(),
            )
            .unwrap();
        let confirm = datagram(&confirm, ring, PeerId(0), inbound);
        let activation = owner
            .on_confirm(&authenticate(&owner_ring, &parsed(&confirm), peer, inbound).unwrap())
            .unwrap();
        epochs[at] = activation.ready.epoch;
    }
    let size = Sessions::words(CAPS.window) as u64 * 64;
    let mut rng = crate::storage::seeded::SplitMix64::new(0x1179);
    let mut models = [(); 2].map(|()| (std::collections::BTreeSet::new(), 0u64));
    let (mut next, mut stale, mut duplicate) = (0, 0, 0);
    for _ in 0..20_000 {
        let at = rng.below(2) as usize;
        let (seen, newest) = &mut models[at];
        let sequence = match rng.below(64) {
            0 => *newest + size + rng.below(8),
            1 => 0,
            2..6 => *newest + 2 + rng.below(3 * 64),
            6..12 => newest.saturating_sub(rng.below(size + 8)),
            _ => *newest + 1,
        };
        let expected = set_verdict(seen, *newest, size, sequence);
        let (ring, principal, nonce) = clients[at];
        let header = Header {
            principal,
            ..get(epochs[at], sequence, nonce)
        };
        let bytes = sealed(ring, PeerId(0), &header, &[], Direction::ClientToOwner);
        let peer = PeerId(at as u16);
        let admitted = owner.admit(
            &authenticate(&owner_ring, &parsed(&bytes), peer, Direction::ClientToOwner).unwrap(),
        );
        assert_eq!(
            admitted.map(|session| (session.peer, session.epoch)),
            expected.map(|()| (peer, epochs[at])),
            "peer {at}: {sequence} after {newest}"
        );
        match expected {
            Ok(()) => {
                next += u64::from(sequence == *newest + 1);
                seen.insert(sequence);
                *newest = (*newest).max(sequence);
            }
            Err(SessionReject::Duplicate) => duplicate += 1,
            Err(_) => stale += 1,
        }
    }
    assert_eq!(
        (owner.report().stale, owner.report().duplicate),
        (stale, duplicate)
    );
    assert!(
        next > 10_000 && stale > 200 && duplicate > 200,
        "{next} next sequences, {stale} stale, {duplicate} duplicate"
    );
    let laps = models.map(|(_, newest)| newest / size);
    assert!(laps.iter().all(|&laps| laps > 50), "{laps:?} bitmap laps");
}

/// Calling the other role's handler is a caller defect reported as `Role`; a ring refuses a principal configured as two peers; a client replays CONFIRM for a lost READY and learns which session a new READY replaced.
#[test]
fn role_misuse_duplicate_peers_lost_ready_and_replacement_are_reported() {
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    assert_eq!(owner.hello(PeerId(0)).err(), Some(SessionReject::Role));
    assert_eq!(owner.confirm(PeerId(0)).err(), Some(SessionReject::Role));
    let mut budget = EngineBudget::new(1 << 20);
    assert_eq!(
        KeyRing::load(
            &[CLIENT, CLIENT],
            &[KeyEntry {
                principal: CLIENT,
                key: &KEY
            }],
            1,
            &mut budget
        )
        .err(),
        Some(KeyError::Duplicate { principal: CLIENT })
    );
    let first = handshake(&mut owner, &mut client, &pair);
    // A second handshake whose READY goes missing; the repeated CONFIRM gets it again.
    let hello = client.hello(PeerId(0)).unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &hello, Direction::ClientToOwner);
    let challenge = owner
        .on_hello(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    let bytes = bootstrap_datagram(owner_ring, PeerId(0), &challenge, Direction::OwnerToClient);
    let confirm = client
        .on_challenge(
            &authenticate(
                client_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::OwnerToClient,
            )
            .unwrap(),
        )
        .unwrap();
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &confirm, Direction::ClientToOwner);
    owner
        .on_confirm(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    let again = client.confirm(PeerId(0)).unwrap();
    assert!(again.sequence > confirm.sequence);
    let bytes = bootstrap_datagram(client_ring, PeerId(0), &again, Direction::ClientToOwner);
    let repeated = owner
        .on_confirm(
            &authenticate(
                owner_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::ClientToOwner,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        repeated.replaced, None,
        "a repeated READY activates nothing"
    );
    let bytes = bootstrap_datagram(
        owner_ring,
        PeerId(0),
        &repeated.ready,
        Direction::OwnerToClient,
    );
    let (admitted, replaced, _) = client
        .on_ready(
            &authenticate(
                client_ring,
                &parsed(&bytes),
                PeerId(0),
                Direction::OwnerToClient,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(admitted.epoch, challenge.epoch);
    assert_eq!(
        replaced.map(|old| (old.epoch, old.displaced)),
        Some((first, false))
    );
}

/// A seeded xorshift stream for generated key sets.
struct Draws(u64);

impl Draws {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// The refusal that pairwise scans over `peers` and `entries` give, in the loader's documented order, or `None` for a set it accepts.
fn pairwise_refusal(peers: &[u32], entries: &[KeyEntry<'_>]) -> Option<KeyError> {
    if let Some(at) = (0..peers.len()).find(|&at| peers[..at].contains(&peers[at])) {
        return Some(KeyError::Duplicate {
            principal: peers[at],
        });
    }
    for (at, entry) in entries.iter().enumerate() {
        if entry.key.len() != KEY_LEN {
            return Some(KeyError::Malformed {
                principal: entry.principal,
                len: entry.key.len(),
            });
        }
        if !peers.contains(&entry.principal) {
            return Some(KeyError::Unknown {
                principal: entry.principal,
            });
        }
        if entries[..at]
            .iter()
            .any(|seen| seen.principal == entry.principal)
        {
            return Some(KeyError::Duplicate {
                principal: entry.principal,
            });
        }
    }
    if let Some(&principal) = peers
        .iter()
        .find(|principal| !entries.iter().any(|entry| entry.principal == **principal))
    {
        return Some(KeyError::Missing { principal });
    }
    for (at, entry) in entries.iter().enumerate() {
        if let Some(earlier) = entries[..at].iter().find(|seen| seen.key == entry.key) {
            return Some(KeyError::Shared {
                first: earlier.principal,
                second: entry.principal,
            });
        }
    }
    None
}

/// A key set for `peers` drawn from `draws`: usually one entry per peer in shuffled order, sometimes with a peer left out, a principal repeated, an unknown principal, a short or long key, or one key given to two principals.
fn drawn_entries(draws: &mut Draws, peers: &[u32], keys: &mut Vec<Vec<u8>>) -> Vec<(u32, usize)> {
    let mut entries: Vec<(u32, usize)> = Vec::new();
    let fresh = |draws: &mut Draws, keys: &mut Vec<Vec<u8>>, len: usize| {
        keys.push((0..len).map(|_| draws.next() as u8).collect());
        keys.len() - 1
    };
    for &principal in peers {
        if draws.below(40) != 0 {
            let len = match draws.below(60) {
                0 => 31,
                1 => 33,
                _ => KEY_LEN,
            };
            let key = fresh(draws, keys, len);
            entries.push((principal, key));
        }
        if draws.below(40) == 0 {
            let key = fresh(draws, keys, KEY_LEN);
            entries.push((principal, key));
        }
    }
    if draws.below(30) == 0 {
        let key = fresh(draws, keys, KEY_LEN);
        entries.push((0xFFFF_0000 | draws.below(4) as u32, key));
    }
    if entries.len() > 1 && draws.below(8) == 0 {
        let (from, to) = (
            draws.below(entries.len() as u64) as usize,
            draws.below(entries.len() as u64) as usize,
        );
        entries[to].1 = entries[from].1;
    }
    for at in (1..entries.len()).rev() {
        entries.swap(at, draws.below(at as u64 + 1) as usize);
    }
    entries
}

/// Every peer's tag under `ring` equals the hand-built HMAC under the key its entry names.
fn tags_follow_entries(ring: &KeyRing, peers: &[u32], entries: &[KeyEntry<'_>]) {
    let mut encoded = [0u8; HEADER_LEN];
    encode(crc(), &get(3, 1, CLIENT_NONCE), [&[], &[]], &mut encoded).unwrap();
    let input = mac_input_for(&encoded, [&[], &[]], ENDPOINT, Direction::ClientToOwner).unwrap();
    let mut data = input.domain().to_vec();
    data.extend_from_slice(input.header);
    for (at, principal) in peers.iter().enumerate() {
        let key = entries
            .iter()
            .find(|entry| entry.principal == *principal)
            .unwrap()
            .key;
        assert_eq!(
            ring.tag(PeerId(at as u16), &input).unwrap(),
            hand_hmac(key, &data)[..16]
        );
    }
}

/// Loading and replacing keys refuse exactly what pairwise scans refuse, with the same principals named, place each peer's key in its peer slot, and leave a refused replacement's ring as it was.
#[test]
fn loading_matches_pairwise_checks_on_generated_key_sets() {
    let mut draws = Draws(0x9E37_79B9_7F4A_7C15);
    let mut outcomes = [0usize; 2];
    for _ in 0..1500 {
        let count = draws.below(25) as usize;
        let spread = if draws.below(4) == 0 { 40 } else { 1 << 31 };
        let peers: Vec<u32> = (0..count).map(|_| draws.below(spread) as u32).collect();
        let mut keys = Vec::new();
        let drawn = drawn_entries(&mut draws, &peers, &mut keys);
        let entries: Vec<KeyEntry<'_>> = drawn
            .iter()
            .map(|&(principal, key)| KeyEntry {
                principal,
                key: &keys[key],
            })
            .collect();
        let expected = pairwise_refusal(&peers, &entries);
        let mut budget = EngineBudget::new(1 << 24);
        let before = budget;
        let loaded = KeyRing::load(&peers, &entries, 1, &mut budget);
        assert_eq!(loaded.as_ref().err(), expected.as_ref(), "{peers:?}");
        outcomes[usize::from(expected.is_none())] += 1;
        let Ok(mut ring) = loaded else {
            assert_eq!(budget, before);
            continue;
        };
        for (at, principal) in peers.iter().enumerate() {
            assert_eq!(ring.peer_of(*principal), Some(PeerId(at as u16)));
        }
        tags_follow_entries(&ring, &peers, &entries);
        let mut next_keys = Vec::new();
        let next = drawn_entries(&mut draws, &peers, &mut next_keys);
        let next: Vec<KeyEntry<'_>> = next
            .iter()
            .map(|&(principal, key)| KeyEntry {
                principal,
                key: &next_keys[key],
            })
            .collect();
        match pairwise_refusal(&peers, &next) {
            None => {
                assert_eq!(ring.replace(&next, 2), Ok(()));
                assert_eq!(ring.epoch(), 2);
                tags_follow_entries(&ring, &peers, &next);
            }
            Some(refusal) => {
                assert_eq!(ring.replace(&next, 2), Err(refusal));
                assert_eq!(ring.epoch(), 1);
                tags_follow_entries(&ring, &peers, &entries);
            }
        }
    }
    assert!(
        outcomes.iter().all(|&seen| seen > 300),
        "both refused and accepted sets: {outcomes:?}"
    );
}

/// The peer table finds every configured principal at its peer and no other principal, for counts that fill tables of each size and principals that differ only in high, low or strided bits.
#[test]
fn the_peer_table_finds_exactly_the_configured_principals() {
    for count in [1usize, 2, 3, 31, 32, 33, 1000] {
        for stride in [1u32, 1 << 16, 1 << 20, 0x9E37_79B9] {
            let peers: Vec<u32> = (0..count as u32)
                .map(|at| at.wrapping_mul(stride))
                .collect();
            let keys: Vec<[u8; 32]> = (0..count)
                .map(|at| {
                    let mut key = [0u8; 32];
                    key[31] = at as u8;
                    key[30] = (at >> 8) as u8;
                    key
                })
                .collect();
            let entries: Vec<KeyEntry<'_>> = peers
                .iter()
                .zip(&keys)
                .rev()
                .map(|(&principal, key)| KeyEntry { principal, key })
                .collect();
            let ring = KeyRing::load(&peers, &entries, 1, &mut EngineBudget::new(1 << 24))
                .unwrap_or_else(|refusal| panic!("{count} x {stride}: {refusal:?}"));
            for (at, principal) in peers.iter().enumerate() {
                assert_eq!(ring.peer_of(*principal), Some(PeerId(at as u16)));
            }
            for absent in (0..64).map(|at: u32| (count as u32 + at).wrapping_mul(stride) ^ 1) {
                if !peers.contains(&absent) {
                    assert_eq!(ring.peer_of(absent), None, "{absent:#x}");
                }
            }
        }
    }
    let crowd = vec![0u32; usize::from(u16::MAX) + 1];
    assert_eq!(
        KeyRing::load(&crowd, &[], 1, &mut EngineBudget::new(8)).err(),
        Some(KeyError::Count {
            entries: 0,
            peers: crowd.len(),
        })
    );
}

/// A session-kind header in session `epoch` at `sequence` under the given boot nonces.
pub(super) fn session_header(
    kind: Kind,
    owner_nonce: [u8; 16],
    epoch: u64,
    sequence: u64,
) -> Header {
    let mut header = Header {
        kind,
        owner_nonce,
        ..get(epoch, sequence, CLIENT_NONCE)
    };
    match kind {
        Kind::Get => {}
        Kind::Error | Kind::Cancel => {
            header.status = if kind == Kind::Error { 1 } else { 18 };
            (
                header.metadata_len,
                header.body_len,
                header.grant,
                header.remaining_ms,
            ) = (0, 0, 0, 0);
        }
        _ => {
            (header.metadata_len, header.body_len, header.total) = (0, 8192, 8192);
            (
                header.count,
                header.allocation,
                header.grant,
                header.remaining_ms,
            ) = (1, 3, 0, 0);
            header.index = u32::from(kind == Kind::Complete);
            header.datagram_len = if kind == Kind::Data { 8192 } else { 0 };
            if kind == Kind::Ack {
                header.grant = 4;
            }
        }
    }
    header
}

/// The bytes a MAC input covers, as one buffer.
fn mac_bytes(input: &MacInput<'_>) -> Vec<u8> {
    let mut bytes = input.domain().to_vec();
    bytes.extend_from_slice(input.header);
    for piece in input.body {
        bytes.extend_from_slice(piece);
    }
    bytes
}

/// Tags stay the exact truncated HMAC through the memo: frames of every session kind, both directions, two owner and two client boot nonces and three peers, in an order that alternates memoized and fresh first blocks, tag and verify as the hand-built HMAC predicts, and an input that differs from a memoized first block in one byte of any of its four words takes a fresh block.
#[test]
fn memo_slots_keep_tags_exact_across_kinds_peers_and_sessions() {
    let keys = [[0x11u8; 32], [0x22; 32], [0x33; 32]];
    let peers = [CLIENT, OTHER, 0x0C33];
    let entries: Vec<KeyEntry<'_>> = peers
        .iter()
        .zip(&keys)
        .map(|(&principal, key)| KeyEntry { principal, key })
        .collect();
    let ring = KeyRing::load(&peers, &entries, 1, &mut EngineBudget::new(1 << 20)).unwrap();
    let body = [0xA5u8; 8192];
    let kinds = [
        Kind::Get,
        Kind::Start,
        Kind::Data,
        Kind::Ack,
        Kind::Complete,
        Kind::Error,
        Kind::Cancel,
    ];
    let mut draws = Draws(0x2545_F491_4F6C_DD1D);
    for round in 0..400u64 {
        let peer = draws.below(3) as usize;
        let kind = kinds[draws.below(kinds.len() as u64) as usize];
        let owner_nonce = if draws.below(4) == 0 {
            [0x0B; 16]
        } else {
            OWNER_NONCE
        };
        let client_nonce = if draws.below(4) == 0 {
            [0x0D; 16]
        } else {
            CLIENT_NONCE
        };
        let direction = if draws.below(2) == 0 {
            Direction::ClientToOwner
        } else {
            Direction::OwnerToClient
        };
        let header = Header {
            principal: peers[peer],
            client_nonce,
            ..session_header(kind, owner_nonce, 3, round + 1)
        };
        let payload: &[u8] = if kind == Kind::Data { &body } else { &[] };
        let mut encoded = [0u8; HEADER_LEN];
        encode(crc(), &header, [payload, &[]], &mut encoded).unwrap();
        let mut digest = [0; 16];
        let input = ring.mac_input(
            PeerId(peer as u16),
            &encoded,
            [payload, &[]],
            (ENDPOINT, direction),
            &mut digest,
        );
        // DATA travels owner to client only, so it has no client-to-owner input.
        if kind == Kind::Data && direction == Direction::ClientToOwner {
            assert!(input.is_none(), "round {round}");
            continue;
        }
        let input = input.unwrap();
        let expected = hand_hmac(&keys[peer], &mac_bytes(&input));
        let tag = ring.tag(PeerId(peer as u16), &input).unwrap();
        assert_eq!(tag[..], expected[..16], "round {round}: {kind:?}");
        seal(&mut encoded, tag);
        let mut datagram = encoded.to_vec();
        datagram.extend_from_slice(payload);
        assert!(
            authenticate(&ring, &parsed(&datagram), PeerId(peer as u16), direction).is_ok(),
            "round {round}: {kind:?} {direction:?}"
        );
    }
    let mut encoded = [0u8; HEADER_LEN];
    encode(crc(), &get(3, 1, CLIENT_NONCE), [&[], &[]], &mut encoded).unwrap();
    let base = mac_input_for(&encoded, [&[], &[]], ENDPOINT, Direction::ClientToOwner).unwrap();
    for at in [0usize, 3, 4, 16, 31, 36, 47, 52, 63] {
        let mut header = *base.header;
        if at >= 16 {
            header[at - 16] ^= 0x40;
        }
        let mut variant = MacInput {
            header: &header,
            ..base
        };
        match at {
            0 | 3 => variant.endpoint ^= 0x40 << (8 * (3 - at)),
            4 => variant.direction = Direction::OwnerToClient,
            _ => {}
        }
        for input in [&base, &variant, &base] {
            assert_eq!(
                ring.tag(PeerId(0), input).unwrap(),
                hand_hmac(&keys[0], &mac_bytes(input))[..16],
                "byte {at}"
            );
        }
    }
}

/// Concurrent uploads of one peer alternate their control frames in kind within one session. Each PUT kind from BEGIN through RESULT keeps its own memoized first block: once one frame of each kind was tagged in its direction, frames of those kinds for other requests, in another order, compress no first block, and every tag is the hand-built HMAC. PUT ERROR and ERROR share the slot of the unlisted kinds, so each takes a fresh first block after the other.
#[test]
fn each_put_kind_from_begin_through_result_keeps_its_own_first_block() {
    let (ring, _) = rings();
    let toward_owner = [Kind::PutBegin, Kind::PutPrepare, Kind::PutData];
    let tagged = |kind: Kind, request: u64, sequence: u64| {
        let base = Header {
            request,
            sequence,
            ..get(3, sequence, CLIENT_NONCE)
        };
        let (header, body) = match kind {
            Kind::Error => (session_header(kind, OWNER_NONCE, 3, sequence), Vec::new()),
            _ => put_frame(kind, &base),
        };
        let direction = if toward_owner.contains(&kind) {
            Direction::ClientToOwner
        } else {
            Direction::OwnerToClient
        };
        let mut encoded = [0u8; HEADER_LEN];
        encode(crc(), &header, [&body, &[]], &mut encoded).unwrap();
        let mut digest = [0; 16];
        let input = ring
            .mac_input(
                PeerId(0),
                &encoded,
                [&body, &[]],
                (ENDPOINT, direction),
                &mut digest,
            )
            .unwrap();
        assert_eq!(
            ring.tag(PeerId(0), &input).unwrap(),
            hand_hmac(&KEY, &mac_bytes(&input))[..16],
            "{kind:?} of request {request}"
        );
    };
    let fresh = || super::auth::FRESH_FIRST_BLOCKS.with(std::cell::Cell::get);
    let kinds = [
        Kind::PutBegin,
        Kind::PutAuthority,
        Kind::PutPrepare,
        Kind::PutReady,
        Kind::PutData,
        Kind::PutAck,
        Kind::PutResult,
    ];
    let before = fresh();
    for (at, kind) in kinds.into_iter().enumerate() {
        tagged(kind, 7, 1 + at as u64);
    }
    assert_eq!(fresh() - before, kinds.len(), "one first block a kind");
    // Two more uploads, their frames interleaved and in reverse kind order.
    for (at, kind) in kinds.into_iter().rev().enumerate() {
        tagged(kind, 8, 20 + at as u64);
        tagged(kind, 9, 40 + at as u64);
    }
    assert_eq!(
        fresh() - before,
        kinds.len(),
        "every later frame found its kind's block memoized"
    );
    let before = fresh();
    for (at, kind) in [Kind::PutError, Kind::Error, Kind::PutError]
        .into_iter()
        .enumerate()
    {
        tagged(kind, 7, 60 + at as u64);
    }
    assert_eq!(fresh() - before, 3, "the unlisted kinds share one slot");
}

/// A re-key empties the memo: after re-keying away from key epoch 1 and back to it under new keys, a frame tagged under the old key at epoch 1, whose first block the ring memoized, is refused, and frames under the new key verify.
#[test]
fn a_rekey_empties_the_memo_even_when_the_key_epoch_returns() {
    let (mut owner_ring, client_ring) = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let old = sealed(
        &client_ring,
        PeerId(0),
        &get(5, 9, CLIENT_NONCE),
        &[],
        Direction::ClientToOwner,
    );
    assert!(
        authenticate(
            &owner_ring,
            &parsed(&old),
            PeerId(0),
            Direction::ClientToOwner
        )
        .is_ok()
    );
    let fresh = [[0x44u8; 32], [0x55; 32]];
    let other = [[0x66u8; 32], [0x77; 32]];
    for (epoch, keys) in [(2, &other), (1, &fresh)] {
        let entries = [
            KeyEntry {
                principal: CLIENT,
                key: &keys[0],
            },
            KeyEntry {
                principal: OTHER,
                key: &keys[1],
            },
        ];
        owner
            .rekey(
                &mut owner_ring,
                &entries,
                epoch,
                [0x0B; 16],
                RequestCensus::default(),
            )
            .unwrap();
    }
    assert_eq!(owner_ring.epoch(), 1);
    assert_eq!(
        authenticate(
            &owner_ring,
            &parsed(&old),
            PeerId(0),
            Direction::ClientToOwner
        )
        .err(),
        Some(AuthError::Tag),
        "the old key's frame at the returned epoch"
    );
    let renewed = KeyRing::load(
        &[CLIENT],
        &[KeyEntry {
            principal: CLIENT,
            key: &fresh[0],
        }],
        1,
        &mut EngineBudget::new(1 << 20),
    )
    .unwrap();
    for sequence in [10, 11] {
        let bytes = sealed(
            &renewed,
            PeerId(0),
            &get(5, sequence, CLIENT_NONCE),
            &[],
            Direction::ClientToOwner,
        );
        let frame = parsed(&bytes);
        let input = frame.mac_input(ENDPOINT, Direction::ClientToOwner).unwrap();
        assert_eq!(
            frame.header().tag[..],
            hand_hmac(&fresh[0], &mac_bytes(&input))[..16]
        );
        assert!(authenticate(&owner_ring, &frame, PeerId(0), Direction::ClientToOwner).is_ok());
    }
}

/// A session after a re-key starts with an empty replay window: the sequences the peer's previous session admitted are admitted again under the new session.
#[test]
fn a_session_after_a_rekey_starts_with_an_empty_replay_window() {
    let mut pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let admit_all = |owner: &mut Sessions, pair: &(KeyRing, KeyRing), epoch: u64| {
        (1..=5u64)
            .map(|sequence| {
                let bytes = sealed(
                    &pair.1,
                    PeerId(0),
                    &get(epoch, sequence, CLIENT_NONCE),
                    &[],
                    Direction::ClientToOwner,
                );
                let frame = parsed(&bytes);
                owner.admit(
                    &authenticate(&pair.0, &frame, PeerId(0), Direction::ClientToOwner).unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };
    let first = handshake(&mut owner, &mut client, &pair);
    assert!(
        admit_all(&mut owner, &pair, first)
            .iter()
            .all(Result::is_ok)
    );
    let fresh = [[0x44u8; 32], [0x55; 32]];
    for (epoch, keys, nonce) in [
        (2, [&fresh[0], &fresh[1]], [0x0B; 16]),
        (1, [&KEY, &OTHER_KEY], OWNER_NONCE),
    ] {
        let entries = [
            KeyEntry {
                principal: CLIENT,
                key: keys[0],
            },
            KeyEntry {
                principal: OTHER,
                key: keys[1],
            },
        ];
        owner
            .rekey(
                &mut pair.0,
                &entries,
                epoch,
                nonce,
                RequestCensus::default(),
            )
            .unwrap();
    }
    assert_eq!(owner.active(PeerId(0)), None);
    let second = handshake(&mut owner, &mut client, &pair);
    assert_ne!(second, first);
    assert_eq!(
        admit_all(&mut owner, &pair, second),
        vec![Ok(owner.active(PeerId(0)).unwrap()); 5]
    );
}

/// `count` canonical full-fragment PUT DATA headers, each with its own sequence, index and offset, alternating between two sessions' owner nonces so consecutive inputs differ in their first block; a MAC input pairs one with a body of another length, which the tag covers as given.
fn put_data_headers(count: usize) -> Vec<[u8; HEADER_LEN]> {
    let fragment = [0; 8192];
    (0..count)
        .map(|at| {
            let total = 1u64 << 20;
            let header = Header {
                principal: CLIENT,
                key_epoch: 1,
                owner_nonce: [at as u8 % 2 + 1; 16],
                client_nonce: CLIENT_NONCE,
                sequence: at as u64 + 1,
                epoch: 1,
                allocation: 5,
                total,
                body_len: total as u32,
                count: 128,
                index: at as u32,
                offset: at as u64 * 8192,
                datagram_len: 8192,
                ..put_frame(Kind::PutData, &get(1, 1, CLIENT_NONCE)).0
            };
            let mut out = [0; HEADER_LEN];
            encode(crc(), &header, [&fragment, &[]], &mut out).unwrap();
            out
        })
        .collect()
}

/// Each input's truncated tag as RFC 2104 HMAC-SHA256 under [`KEY`] over its domain block, header and `bodies` entry, built by hand from SHA-256.
fn hmac_tags(inputs: &[MacInput<'_>], bodies: &[Vec<u8>]) -> Vec<[u8; 16]> {
    inputs
        .iter()
        .zip(bodies)
        .map(|(input, body)| {
            let mut bytes = input.domain().to_vec();
            bytes.extend_from_slice(input.header);
            bytes.extend_from_slice(body);
            hand_hmac(&KEY, &bytes)[..16].try_into().unwrap()
        })
        .collect()
}

/// PUT DATA inputs of mixed body lengths, two sessions' first blocks, and whole or split body slices: every count from one to forty from either end tags as RFC 2104 HMAC-SHA256 over the input does, so the sixteen-lane pass, its padded lanes, and the remainder's groups of four, three and two chains and its one input alone all agree with the definition. Mixed lengths within a group of four make its chains finish their whole blocks and tails at different passes, so the group regroups to fewer chains before its four outer blocks compress together. A refused call, for a peer outside the ring or for slices of unequal lengths in either direction, leaves a sentinel-filled `tags` unchanged.
#[test]
fn many_tags_equal_the_hmac_of_each_input() {
    let (_, client_ring) = rings();
    let lengths = [
        0, 1, 16, 55, 56, 63, 64, 65, 100, 119, 120, 4096, 8191, 8192,
    ];
    let bodies: Vec<Vec<u8>> = (0..40)
        .map(|at| {
            let len = lengths[at % lengths.len()] + at % 3 * 64;
            (0..len).map(|byte| (byte * 7 + at) as u8).collect()
        })
        .collect();
    let encoded = put_data_headers(bodies.len());
    for split in [false, true] {
        let inputs: Vec<MacInput<'_>> = bodies
            .iter()
            .zip(&encoded)
            .map(|(body, out)| {
                let half = if split { body.len() / 2 } else { body.len() };
                MacInput {
                    endpoint: ENDPOINT,
                    direction: Direction::ClientToOwner,
                    header: out.first_chunk().unwrap(),
                    body: [&body[..half], &body[half..]],
                }
            })
            .collect();
        let expected = hmac_tags(&inputs, &bodies);
        for count in 1..=inputs.len() {
            for start in [0, inputs.len() - count] {
                let mut tags = vec![[0; 16]; count];
                client_ring
                    .tags(PeerId(0), &inputs[start..start + count], &mut tags)
                    .unwrap();
                assert_eq!(
                    tags,
                    expected[start..start + count],
                    "{count} from {start}, split {split}"
                );
            }
        }
    }
    // Sixteen equal lengths make every lane's tail the shortest, so the lockstep pass also hashes each tail.
    for len in [55, 56, 119, 8191, 8192] {
        let bodies: Vec<Vec<u8>> = (0..16)
            .map(|lane| (0..len).map(|byte| (byte * 3 + lane) as u8).collect())
            .collect();
        let inputs: Vec<MacInput<'_>> = bodies
            .iter()
            .zip(&encoded)
            .map(|(body, out)| MacInput {
                endpoint: ENDPOINT,
                direction: Direction::ClientToOwner,
                header: out.first_chunk().unwrap(),
                body: [body, &[]],
            })
            .collect();
        let expected = hmac_tags(&inputs, &bodies);
        let mut tags = vec![[0; 16]; 16];
        client_ring.tags(PeerId(0), &inputs, &mut tags).unwrap();
        assert_eq!(tags, expected, "{len}-byte bodies");
        let mut vector = vec![[0; 16]; 16];
        #[cfg(target_arch = "x86_64")]
        let wide = std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512bw")
            && std::arch::is_x86_feature_detected!("vpclmulqdq");
        #[cfg(not(target_arch = "x86_64"))]
        let wide = false;
        assert_eq!(
            client_ring.vector_tags(PeerId(0), &inputs, &mut vector),
            if wide { 16 } else { 0 },
            "the vector pass runs where the CPU has it"
        );
        if wide {
            assert_eq!(vector, expected, "{len}-byte bodies in one vector pass");
        }
        assert_eq!(
            client_ring.vector_tags(PeerId(0), &inputs[..15], &mut vector[..15]),
            if wide { 15 } else { 0 },
            "fifteen inputs take one vector pass where the CPU has it"
        );
        if wide {
            assert_eq!(
                vector[..15],
                expected[..15],
                "{len}-byte bodies, fifteen lanes"
            );
        }
        assert_eq!(
            client_ring.vector_tags(PeerId(0), &inputs[..14], &mut vector[..14]),
            0,
            "fourteen inputs hash in three groups of four chains and one pair"
        );
    }
    let mut tags = [[0; 16]; 1];
    assert_eq!(
        client_ring.tags(PeerId(1), &[], &mut []),
        None,
        "a peer outside the ring"
    );
    assert_eq!(
        client_ring.tags(PeerId(0), &[], &mut tags),
        None,
        "unequal lengths"
    );
    assert_eq!(tags, [[0; 16]], "a refused call writes no tag");
    let inputs: Vec<MacInput<'_>> = bodies
        .iter()
        .zip(&encoded)
        .map(|(body, out)| MacInput {
            endpoint: ENDPOINT,
            direction: Direction::ClientToOwner,
            header: out.first_chunk().unwrap(),
            body: [body, &[]],
        })
        .collect();
    for (count, len) in [(5, 5), (2, 3), (3, 2), (17, 16)] {
        let mut tags = vec![[0xA5; 16]; len];
        let peer = if count == len { PeerId(1) } else { PeerId(0) };
        assert_eq!(
            client_ring.tags(peer, &inputs[..count], &mut tags),
            None,
            "{count} inputs, {len} tags, {peer:?}"
        );
        assert!(
            tags.iter().all(|tag| *tag == [0xA5; 16]),
            "a refused call of {count} inputs writes no tag"
        );
    }
}

/// Tags `count` PUT DATA inputs through `tag`, each with its own header and a body whose length cycles through empty, short, block and padding boundaries, a whole fragment and one byte short of it, 64 bytes longer on each later cycle, as whole and as split slices; every tag must equal the hand-built HMAC of the input at its position.
fn tags_in_place_match_the_hmac(count: usize, tag: impl Fn(&[MacInput<'_>], &mut [[u8; 16]])) {
    let lengths = [
        0, 1, 16, 55, 56, 63, 64, 65, 119, 120, 100, 4096, 8191, 8192,
    ];
    let bodies: Vec<Vec<u8>> = (0..count)
        .map(|at| {
            let len = lengths[at % lengths.len()] + at / lengths.len() * 64;
            (0..len).map(|byte| (byte * 5 + at * 11) as u8).collect()
        })
        .collect();
    let encoded = put_data_headers(count);
    for split in [false, true] {
        let inputs: Vec<MacInput<'_>> = bodies
            .iter()
            .zip(&encoded)
            .map(|(body, out)| {
                let half = if split { body.len() / 2 } else { body.len() };
                MacInput {
                    endpoint: ENDPOINT,
                    direction: Direction::ClientToOwner,
                    header: out.first_chunk().unwrap(),
                    body: [&body[..half], &body[half..]],
                }
            })
            .collect();
        let mut tags = vec![[0xA5; 16]; count];
        tag(&inputs, &mut tags);
        assert_eq!(
            tags,
            hmac_tags(&inputs, &bodies),
            "{count} inputs, split {split}"
        );
    }
}

/// A batch of `count` inputs tagged by `tag` runs the x86_64 sixteen-lane pass inside its own witness and every tag equals the hand-built HMAC at its position; on a host without `avx512f`, `avx512bw` and `vpclmulqdq` the pass reports itself unreached.
fn the_wide_pass_tags_a_batch(
    count: usize,
    tag: impl Fn(&KeyRing, &[MacInput<'_>], &mut [[u8; 16]]),
) {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    let (_, client_ring) = rings();
    witness(
        &format!("hmac-wide-{count}"),
        detected!(x86_64: "avx512f", "avx512bw", "vpclmulqdq"),
        || runs(Kernel::HmacWide),
        || tags_in_place_match_the_hmac(count, |inputs, tags| tag(&client_ring, inputs, tags)),
    );
}

/// Tags through [`KeyRing::tags`], the production dispatch.
fn dispatched(ring: &KeyRing, inputs: &[MacInput<'_>], tags: &mut [[u8; 16]]) {
    ring.tags(PeerId(0), inputs, tags).unwrap();
}

/// Nine inputs, seven fewer than the lanes: [`KeyRing::tags`] hashes them as one group of four chains, one of three and one pair and stays off the vector pass, which it enters from fifteen inputs, and the pass itself, entered directly with nine live lanes and seven repeating the last input, runs inside its own witness and gives each of the nine its hand-built HMAC.
#[test]
fn nine_inputs_tag_through_the_group_path_and_in_one_wide_pass_with_seven_repeated_lanes() {
    use crate::isa_witness::{Kernel, runs};
    let (_, client_ring) = rings();
    let before = runs(Kernel::HmacWide);
    tags_in_place_match_the_hmac(9, |inputs, tags| dispatched(&client_ring, inputs, tags));
    assert_eq!(
        runs(Kernel::HmacWide),
        before,
        "nine inputs hash in groups of four, three and two chains"
    );
    the_wide_pass_tags_a_batch(9, |ring, inputs, tags| {
        if !ring.vector_pass(PeerId(0), inputs, tags) {
            dispatched(ring, inputs, tags);
        }
    });
}

/// Fifteen inputs, the fewest [`KeyRing::tags`] sends to the vector pass, fill fifteen lanes and repeat the last in the sixteenth.
#[test]
fn fifteen_inputs_tag_in_one_wide_pass() {
    the_wide_pass_tags_a_batch(15, dispatched);
}

/// Sixteen inputs fill every lane of one vector pass.
#[test]
fn sixteen_inputs_tag_in_one_wide_pass() {
    the_wide_pass_tags_a_batch(16, dispatched);
}

/// Seventeen inputs take one vector pass of sixteen and leave one input to hash alone.
#[test]
fn seventeen_inputs_tag_in_one_wide_pass_and_one_alone() {
    the_wide_pass_tags_a_batch(17, dispatched);
}

/// Sixteen full 8192-byte PUT DATA fragments with whole body slices, in one [`KeyRing::tags`] call off the x86_64 vector pass, hash as four groups of four chains through the aarch64 `sha2` four-chain kernel, and every tag equals the hand-built HMAC at its position. After its memoized or freshly compressed first block, each chain compresses its two middle header blocks, 128 whole body blocks, one padding block and one outer block, 132 four-chain steps, so the four groups count exactly 4 × 132 = 528 steps and the two- and three-chain kernels none. The first block goes through the one-chain compression, so the count holds whatever the memo holds. `Kernel::Sha2Four` counts the aarch64 kernel alone, so on x86_64 the line reports it unreached; there, with `avx512f`, `avx512bw` and `vpclmulqdq`, the vector pass hashes all sixteen. A repeat call allocates nothing.
#[test]
fn sixteen_full_fragments_tag_in_four_groups_of_four_chains() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    let (_, client_ring) = rings();
    let bodies: Vec<Vec<u8>> = (0..16)
        .map(|at| (0..8192).map(|byte| (byte * 13 + at) as u8).collect())
        .collect();
    let encoded = put_data_headers(bodies.len());
    let inputs: Vec<MacInput<'_>> = bodies
        .iter()
        .zip(&encoded)
        .map(|(body, out)| MacInput {
            endpoint: ENDPOINT,
            direction: Direction::ClientToOwner,
            header: out.first_chunk().unwrap(),
            body: [body, &[]],
        })
        .collect();
    let mut tags = [[0xA5; 16]; 16];
    let sha2 = detected!(aarch64: "sha2");
    let present = sha2.present;
    let fewer = [Kernel::Sha2Two, Kernel::Sha2Three];
    let before = (runs(Kernel::Sha2Four), fewer.map(runs));
    witness(
        "hmac-quad-16",
        sha2,
        || runs(Kernel::Sha2Four),
        || dispatched(&client_ring, &inputs, &mut tags),
    );
    assert_eq!(
        runs(Kernel::Sha2Four) - before.0,
        if present { 528 } else { 0 },
        "every block after each chain's first runs four chains wide"
    );
    assert_eq!(
        fewer.map(runs),
        before.1,
        "sixteen equal fragments never hash two or three chains together"
    );
    assert_eq!(tags.to_vec(), hmac_tags(&inputs, &bodies));
    let allocations = crate::instrument::allocations();
    dispatched(&client_ring, &inputs, &mut tags);
    assert_eq!(
        crate::instrument::allocations(),
        allocations,
        "tagging allocates nothing"
    );
}

/// Header-only batches, the shape a poll's control frames take, tag as the hand-built HMAC of each input and allocate nothing. [`KeyRing::tags`] dispatches two GET headers as one pair, three as one group of three chains, five as a group of three chains and a pair, nine as a group of four, a group of three and a pair, and sixteen as four groups of four chains, or as one vector pass on x86_64 with `avx512f`, `avx512bw` and `vpclmulqdq`. Each group runs four steps of its kernel, over two middle blocks, the padding block and the outer block, so on aarch64 with `sha2` the two-, three- and four-chain step counts name the grouping, and a count that hashed one header alone would leave a kernel's steps short. Headers of four kinds in their own memo slots, five in all, tag as a group of three and a pair, and a group mixing GET headers with PUT DATA bodies of 8192 and 1 bytes ends each GET chain on the padding block its empty body assembles.
#[test]
fn header_only_batches_tag_as_the_hmac_of_each_input() {
    let (_, client_ring) = rings();
    let encoded: Vec<[u8; HEADER_LEN]> = (0..16)
        .map(|at| {
            let mut out = [0; HEADER_LEN];
            encode(crc(), &get(1, at + 1, CLIENT_NONCE), [&[], &[]], &mut out).unwrap();
            out
        })
        .collect();
    let inputs: Vec<MacInput<'_>> = encoded
        .iter()
        .map(|out| mac_input_for(out, [&[], &[]], ENDPOINT, Direction::ClientToOwner).unwrap())
        .collect();
    let expected = hmac_tags(&inputs, &vec![Vec::new(); inputs.len()]);
    for (count, steps) in [
        (2, [4, 0, 0]),
        (3, [0, 4, 0]),
        (5, [4, 4, 0]),
        (9, [4, 4, 4]),
        (16, [0, 0, 16]),
    ] {
        let mut tags = vec![[0xA5; 16]; count];
        let allocations = crate::instrument::allocations();
        let ran = lane_steps(|| dispatched(&client_ring, &inputs[..count], &mut tags));
        assert_eq!(crate::instrument::allocations(), allocations);
        assert_eq!(
            ran,
            on_sha2(steps),
            "{count} GET headers: two-, three- and four-chain steps"
        );
        assert_eq!(tags, expected[..count], "{count} GET headers");
    }
    let kinds = [
        Kind::Get,
        Kind::Ack,
        Kind::Complete,
        Kind::Cancel,
        Kind::Get,
    ];
    let mixed: Vec<[u8; HEADER_LEN]> = kinds
        .iter()
        .zip(1..)
        .map(|(&kind, sequence)| {
            let mut out = [0; HEADER_LEN];
            let header = session_header(kind, OWNER_NONCE, 1, sequence);
            encode(crc(), &header, [&[], &[]], &mut out).unwrap();
            out
        })
        .collect();
    let inputs: Vec<MacInput<'_>> = mixed
        .iter()
        .map(|out| mac_input_for(out, [&[], &[]], ENDPOINT, Direction::ClientToOwner).unwrap())
        .collect();
    let mut tags = vec![[0xA5; 16]; inputs.len()];
    let allocations = crate::instrument::allocations();
    dispatched(&client_ring, &inputs, &mut tags);
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(
        tags,
        hmac_tags(&inputs, &vec![Vec::new(); inputs.len()]),
        "headers of four kinds"
    );
    let put = put_data_headers(2);
    let bodies = [Vec::new(), vec![0x3C; 8192], Vec::new(), vec![0x3C]];
    let inputs: Vec<MacInput<'_>> = [&encoded[0], &put[0], &encoded[1], &put[1]]
        .iter()
        .zip(&bodies)
        .map(|(out, body)| MacInput {
            endpoint: ENDPOINT,
            direction: Direction::ClientToOwner,
            header: out.first_chunk().unwrap(),
            body: [body, &[]],
        })
        .collect();
    let mut tags = [[0xA5; 16]; 4];
    let allocations = crate::instrument::allocations();
    dispatched(&client_ring, &inputs, &mut tags);
    assert_eq!(crate::instrument::allocations(), allocations);
    assert_eq!(
        tags.to_vec(),
        hmac_tags(&inputs, &bodies),
        "GET headers grouped with PUT DATA bodies"
    );
}

/// The replay verdict a set model gives `sequence`. `seen` holds the
/// accepted sequences, `newest` is the largest of them, and the window
/// spans `size` sequences. Sequence 0 and any sequence at or below
/// `newest - size` are stale, a sequence in `seen` is a duplicate, and
/// every other sequence is accepted.
fn set_verdict(
    seen: &std::collections::BTreeSet<u64>,
    newest: u64,
    size: u64,
    sequence: u64,
) -> Result<(), SessionReject> {
    if sequence == 0 || (sequence <= newest && newest - sequence >= size) {
        Err(SessionReject::Stale)
    } else if seen.contains(&sequence) {
        Err(SessionReject::Duplicate)
    } else {
        Ok(())
    }
}

/// For windows of 2, 3 and 65 words, one history climbs from small
/// sequences to `u64::MAX` through `u64::MAX - size`, `u64::MAX - 64` and
/// `u64::MAX - 1`, with jumps past the window, reordered fresh sequences,
/// duplicates and sequence 0. Every verdict matches the set model, and a
/// refused call leaves the bitmap and the newest sequence unchanged. After
/// every call the window holds exactly the model's accepted sequences:
/// each in-window sequence probes as a duplicate when the model accepted
/// it and as fresh otherwise, and the three sequences just below the
/// window probe as stale.
#[test]
fn ib_replay_window_maximum_terminal_history_matches_the_set_model() {
    // `Sessions::words` gives every validated window 2 to 65 words.
    for words in [2usize, 3, 65] {
        let size = words as u64 * 64;
        let top = u64::MAX;
        let history = [
            1,
            5,
            3,
            top - 3 * size,
            top - size - 1,
            top - size,
            top - size + 1,
            top - size,
            top - 70,
            top - 64,
            top - 65,
            top - 64,
            top - size + 1,
            top - 2,
            top - 1,
            top - 3,
            top,
            top - 1,
            top,
            top - size,
            top - size + 1,
            top - size + 2,
            0,
            top - 63,
        ];
        let (mut bits, mut highest) = (vec![0u64; words], Newest::default());
        let (mut seen, mut newest) = (std::collections::BTreeSet::new(), 0u64);
        let (mut accepted, mut stale, mut duplicate) = (0, 0, 0);
        for sequence in history {
            let expected = set_verdict(&seen, newest, size, sequence);
            let before = (bits.clone(), highest);
            assert_eq!(
                accept(&mut bits, &mut highest, sequence),
                expected,
                "{words} words: {sequence} after {}",
                highest.sequence
            );
            match expected {
                Ok(()) => {
                    seen.insert(sequence);
                    newest = newest.max(sequence);
                    accepted += 1;
                }
                Err(reject) => {
                    assert_eq!((bits.clone(), highest), before, "{reject:?} kept the state");
                    match reject {
                        SessionReject::Duplicate => duplicate += 1,
                        _ => stale += 1,
                    }
                }
            }
            assert_eq!(highest.sequence, newest);
            // The window holds exactly the model's accepted sequences after
            // every call: each probe on a copy gets the model's verdict.
            for probe in newest.saturating_sub(size + 2)..=newest {
                let mut copy = (bits.clone(), highest);
                assert_eq!(
                    accept(&mut copy.0, &mut copy.1, probe),
                    set_verdict(&seen, newest, size, probe),
                    "{words} words: probe {probe} after {sequence}"
                );
            }
        }
        assert_eq!(highest.sequence, top);
        assert!(
            accepted > 0 && stale > 0 && duplicate > 0,
            "{words} words: {accepted} accepted, {stale} stale, {duplicate} duplicate"
        );
    }
}

/// The two-, three- and four-chain `sha2` steps `body` runs on this thread, in that order.
fn lane_steps(body: impl FnOnce()) -> [usize; 3] {
    use crate::isa_witness::{Kernel, runs};
    let kernels = [Kernel::Sha2Two, Kernel::Sha2Three, Kernel::Sha2Four];
    let before = kernels.map(runs);
    body();
    let after = kernels.map(runs);
    std::array::from_fn(|at| after[at] - before[at])
}

/// `steps` on an aarch64 host with `sha2`, whose kernels count each block step, and no steps on every other host.
fn on_sha2(steps: [usize; 3]) -> [usize; 3] {
    use crate::isa_witness::detected;
    if detected!(aarch64: "sha2").present {
        steps
    } else {
        [0; 3]
    }
}

/// The key of the owner ring's `peer` from [`rings`].
fn owner_key(peer: PeerId) -> &'static [u8] {
    if peer == PeerId(1) { &OTHER_KEY } else { &KEY }
}

/// The truncated RFC 2104 HMAC-SHA256 of `input` under `key`, built by hand from SHA-256.
pub(super) fn hand_tag(key: &[u8], input: &MacInput<'_>) -> [u8; 16] {
    hand_hmac(key, &mac_bytes(input))[..16].try_into().unwrap()
}

/// Four PUT DATA headers with bytes distinct by position, so equal bodies at two positions still give distinct MAC inputs.
fn positioned_headers() -> [[u8; 176]; 4] {
    std::array::from_fn(|position| {
        let mut header = [0u8; 176];
        for (at, byte) in header.iter_mut().enumerate() {
            *byte = (at as u8).wrapping_mul(37) ^ 0xC3 ^ (position as u8).wrapping_mul(0x4D);
        }
        header[10] = Kind::PutData as u8;
        header
    })
}

/// Four 8192-byte bodies whose bytes differ by position, so a chain that read another position's body at an equal length fails its oracle.
fn positioned_bodies() -> [Vec<u8>; 4] {
    std::array::from_fn(|position| {
        (0..8192)
            .map(|at| (at * 7 + 3 + position * 0x35) as u8 ^ (at >> 7) as u8)
            .collect()
    })
}

/// One group input: its peer and its covered body, the first `len` bytes of its position's body, split into two slices at `split`.
#[derive(Clone, Copy, Debug)]
struct Shape {
    peer: PeerId,
    len: usize,
    split: usize,
}

impl Shape {
    fn whole(peer: PeerId, len: usize) -> Self {
        Self {
            peer,
            len,
            split: len,
        }
    }
}

/// `tag_group` over `shapes`, each at its position with that position's header and body, equals [`KeyRing::tag`] and the hand-built HMAC of every input.
fn group_matches_both_oracles<const N: usize>(
    ring: &KeyRing,
    headers: &[[u8; 176]; 4],
    bodies: &[Vec<u8>; 4],
    shapes: [Shape; N],
) {
    let inputs: [MacInput<'_>; N] = std::array::from_fn(|at| {
        let Shape { len, split, .. } = shapes[at];
        let (head, tail) = bodies[at][..len].split_at(split);
        MacInput {
            endpoint: ENDPOINT,
            direction: Direction::ClientToOwner,
            header: &headers[at],
            body: [head, tail],
        }
    });
    let expected: [[u8; 16]; N] =
        std::array::from_fn(|at| hand_tag(owner_key(shapes[at].peer), &inputs[at]));
    let alone: [[u8; 16]; N] =
        std::array::from_fn(|at| ring.tag(shapes[at].peer, &inputs[at]).unwrap());
    assert_eq!(alone, expected, "{shapes:?} alone");
    let grouped = ring
        .tag_group(std::array::from_fn(|at| (shapes[at].peer, &inputs[at])))
        .unwrap();
    assert_eq!(grouped, expected, "{shapes:?} grouped");
}

/// [`group_matches_both_oracles`] for one to four shapes.
fn group_of(ring: &KeyRing, headers: &[[u8; 176]; 4], bodies: &[Vec<u8>; 4], shapes: &[Shape]) {
    match shapes.len() {
        1 => group_matches_both_oracles::<1>(ring, headers, bodies, shapes.try_into().unwrap()),
        2 => group_matches_both_oracles::<2>(ring, headers, bodies, shapes.try_into().unwrap()),
        3 => group_matches_both_oracles::<3>(ring, headers, bodies, shapes.try_into().unwrap()),
        4 => group_matches_both_oracles::<4>(ring, headers, bodies, shapes.try_into().unwrap()),
        count => unreachable!("{count} shapes"),
    }
}

/// Group tags of one to four inputs equal [`KeyRing::tag`] and the hand-built HMAC of each input. The inputs cover every ordered tuple of the tail classes 0, 1, 16, 55, 56, 64 and 65 bytes, so chains end on the empty body's padding block, a one-byte body, a 16-byte single slice, the last length whose padding fits its block, the first that needs a length block, a whole block and a block plus one, and finish their bodies at different passes; every tuple one input shorter also runs with an 8192-byte body inserted at each position, so the group again holds one to four inputs. Every tuple runs under one peer and under alternating peers, and each position reads its own header and body bytes, so equal lengths at two positions still differ. A split table places a body split across its two slices at every position beside fixed companions, every body under 56 bytes at every split runs alone, beside a 16-byte body and last in a group of four short bodies, and a seeded sweep draws lengths, splits, peers and group sizes; a failure prints its shapes.
#[test]
fn group_tags_match_both_oracles_over_tail_classes_splits_and_peers() {
    let (owner_ring, _) = rings();
    let (headers, bodies) = (positioned_headers(), positioned_bodies());
    const TAILS: [usize; 7] = [0, 1, 16, 55, 56, 64, 65];
    let peers = |pattern: usize, at: usize| PeerId((pattern * (at % 2)) as u16);
    for count in 1..=4usize {
        for index in 0..TAILS.len().pow(count as u32) {
            let tails: Vec<usize> = (0..count)
                .map(|at| TAILS[index / TAILS.len().pow(at as u32) % TAILS.len()])
                .collect();
            for pattern in 0..2 {
                let shapes: Vec<Shape> = (0..count)
                    .map(|at| Shape::whole(peers(pattern, at), tails[at]))
                    .collect();
                group_of(&owner_ring, &headers, &bodies, &shapes);
                if tails[0] == 0 {
                    for long in 0..count {
                        let mut lens = tails[1..].to_vec();
                        lens.insert(long, 8192);
                        let shapes: Vec<Shape> = (0..count)
                            .map(|at| Shape::whole(peers(pattern, at), lens[at]))
                            .collect();
                        group_of(&owner_ring, &headers, &bodies, &shapes);
                    }
                }
            }
        }
    }
    let splits = [
        (8192, 4096),
        (8192, 100),
        (8192, 1),
        (8192, 8191),
        (8191, 1),
        (120, 56),
        (65, 64),
        (64, 63),
        (57, 56),
        (16, 8),
        (1, 0),
    ];
    let companions = [
        Shape::whole(PeerId(1), 64),
        Shape::whole(PeerId(0), 0),
        Shape::whole(PeerId(1), 16),
    ];
    for (len, split) in splits {
        for count in 1..=4 {
            for position in 0..count {
                let mut shapes = companions[..count - 1].to_vec();
                shapes.insert(
                    position,
                    Shape {
                        peer: PeerId(0),
                        len,
                        split,
                    },
                );
                group_of(&owner_ring, &headers, &bodies, &shapes);
            }
        }
    }
    for len in 0..56 {
        for split in 0..=len {
            let short = Shape {
                peer: PeerId(0),
                len,
                split,
            };
            group_of(&owner_ring, &headers, &bodies, &[short]);
            group_of(
                &owner_ring,
                &headers,
                &bodies,
                &[short, Shape::whole(PeerId(1), 16)],
            );
            group_of(
                &owner_ring,
                &headers,
                &bodies,
                &[
                    Shape::whole(PeerId(1), 16),
                    Shape::whole(PeerId(0), 0),
                    Shape::whole(PeerId(1), 1),
                    short,
                ],
            );
        }
    }
    let mut rng = crate::storage::seeded::SplitMix64::new(0x1119);
    for _ in 0..400 {
        let count = 1 + rng.next_u64() as usize % 4;
        let shapes: Vec<Shape> = (0..count)
            .map(|_| {
                let len = if rng.next_u64().is_multiple_of(2) {
                    TAILS[rng.next_u64() as usize % TAILS.len()]
                        + 64 * (rng.next_u64() as usize % 3)
                } else {
                    rng.next_u64() as usize % 8193
                };
                Shape {
                    peer: PeerId((rng.next_u64() % 2) as u16),
                    len,
                    split: rng.next_u64() as usize % (len + 1),
                }
            })
            .collect();
        group_of(&owner_ring, &headers, &bodies, &shapes);
    }
}

/// Two-, three- and four-chain group steps on the aarch64 `sha2` host, counted beside a check against [`KeyRing::tag`] and the hand-built HMAC. After each chain's first block, every chain compresses its two middle header blocks, its body's blocks and padding, then one outer block. Four 8192-byte bodies share 2 + 128 + 1 + 1 = 132 four-chain steps. Four header-only GET inputs share 2 + 1 + 1 = 4, their last inner block the fixed padding block. Four 64-byte bodies share 2 + 1 + 1 + 1 = 5, one whole block and one padding block each. Bodies of 1, 16, 55 and 0 bytes each take one last inner block, 2 + 1 + 1 = 4. Bodies of 8192, 64, 0 and 0 bytes share the two middle blocks, then the long body's first whole block runs beside the 64-byte block for 1 two-chain step and its other 127 run alone through `sha_lanes::lone`; the four padding blocks and the outer blocks then share 2 four-chain steps, 4 in all. Bodies of 8192, 8192, 64 and 0 bytes share the two middle blocks, run their first whole blocks three chains wide for 1 step and the two long bodies' other 127 two chains wide, then share the four padding blocks and the outer blocks: 4 four-chain steps.
#[test]
fn four_chain_groups_count_the_steps_their_chains_share() {
    let (owner_ring, _) = rings();
    let (headers, bodies) = (positioned_headers(), positioned_bodies());
    let gets: Vec<[u8; HEADER_LEN]> = (0..4)
        .map(|at| {
            let mut out = [0; HEADER_LEN];
            encode(crc(), &get(1, at + 1, CLIENT_NONCE), [&[], &[]], &mut out).unwrap();
            out
        })
        .collect();
    let get_inputs: [MacInput<'_>; 4] = std::array::from_fn(|at| {
        mac_input_for(&gets[at], [&[], &[]], ENDPOINT, Direction::ClientToOwner).unwrap()
    });
    let expected: [[u8; 16]; 4] = std::array::from_fn(|at| hand_tag(&KEY, &get_inputs[at]));
    let mut tags = None;
    let steps = lane_steps(|| {
        tags = owner_ring.tag_group(std::array::from_fn(|at| (PeerId(0), &get_inputs[at])));
    });
    assert_eq!(tags, Some(expected), "four GET headers");
    assert_eq!(steps, on_sha2([0, 0, 4]), "four GET headers");
    for (lens, want) in [
        ([8192, 8192, 8192, 8192], [0, 0, 132]),
        ([64, 64, 64, 64], [0, 0, 5]),
        ([8192, 64, 0, 0], [1, 0, 4]),
        ([8192, 8192, 64, 0], [127, 1, 4]),
        ([1, 16, 55, 0], [0, 0, 4]),
    ] {
        let inputs: [MacInput<'_>; 4] = std::array::from_fn(|at| MacInput {
            endpoint: ENDPOINT,
            direction: Direction::ClientToOwner,
            header: &headers[at],
            body: [&bodies[at][..lens[at]], &[]],
        });
        let expected: [[u8; 16]; 4] = std::array::from_fn(|at| hand_tag(&KEY, &inputs[at]));
        let alone: [[u8; 16]; 4] =
            std::array::from_fn(|at| owner_ring.tag(PeerId(0), &inputs[at]).unwrap());
        assert_eq!(alone, expected, "{lens:?} alone");
        let mut tags = None;
        let steps = lane_steps(|| {
            tags = owner_ring.tag_group(std::array::from_fn(|at| (PeerId(0), &inputs[at])));
        });
        assert_eq!(tags, Some(expected), "{lens:?}");
        assert_eq!(
            steps,
            on_sha2(want),
            "{lens:?}: two-, three- and four-chain steps"
        );
    }
}

/// A one-frame group models a lone resend. [`KeyRing::tag`] memoizes the first block before counting begins.
#[test]
fn a_group_of_one_frame_runs_the_one_chain_kernel() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    let (owner_ring, _) = rings();
    let (headers, bodies) = (positioned_headers(), positioned_bodies());
    let input = MacInput {
        endpoint: ENDPOINT,
        direction: Direction::ClientToOwner,
        header: &headers[0],
        body: [&bodies[0][..], &[]],
    };
    let expected = hand_tag(&KEY, &input);
    assert_eq!(owner_ring.tag(PeerId(0), &input), Some(expected));
    let one = detected!(aarch64: "sha2", "sha3");
    let present = one.present;
    let before = runs(Kernel::Sha2One);
    let mut tags = None;
    witness(
        "group-lone",
        one,
        || runs(Kernel::Sha2One),
        || tags = owner_ring.tag_group([(PeerId(0), &input)]),
    );
    assert_eq!(tags, Some([expected]));
    assert_eq!(
        runs(Kernel::Sha2One) - before,
        if present { 4 } else { 0 },
        "a group of one runs the kernel for its middle blocks, its body, its padding block and its outer block"
    );
}

/// A DATA frame's 16-byte digest body, the shape every GET DATA reply tags, pairs with a header-only START or COMPLETE in either order, and each pair tag equals [`KeyRing::tag`] and the hand-built HMAC. On the aarch64 `sha2` host each pair runs 4 two-chain steps: the two middle header blocks, one last inner block per chain (the digest block beside the empty body's padding block) and the outer block.
#[test]
fn a_digest_frame_pairs_with_a_header_only_frame_through_two_chains() {
    let (owner_ring, _) = rings();
    let encoded = |header: &Header, body: &[u8]| {
        let mut out = [0u8; HEADER_LEN];
        encode(crc(), header, [body, &[]], &mut out).unwrap();
        out
    };
    let data = encoded(&data_of(OWNER_NONCE), &[0x6B; 20]);
    let start = encoded(&session_header(Kind::Start, OWNER_NONCE, 3, 2), &[]);
    let complete = encoded(&session_header(Kind::Complete, OWNER_NONCE, 3, 3), &[]);
    let digest = [0xD1u8; 16];
    let data_input = MacInput {
        endpoint: ENDPOINT,
        direction: Direction::OwnerToClient,
        header: data.first_chunk().unwrap(),
        body: [&digest, &[]],
    };
    let header_only = |out: &'static [u8; HEADER_LEN]| {
        mac_input_for(out, [&[], &[]], ENDPOINT, Direction::OwnerToClient).unwrap()
    };
    let start = header_only(Box::leak(Box::new(start)));
    let complete = header_only(Box::leak(Box::new(complete)));
    for (first, second, case) in [
        (&data_input, &start, "DATA then START"),
        (&start, &data_input, "START then DATA"),
        (&data_input, &complete, "DATA then COMPLETE"),
        (&complete, &data_input, "COMPLETE then DATA"),
    ] {
        let expected = [hand_tag(&KEY, first), hand_tag(&KEY, second)];
        assert_eq!(
            [
                owner_ring.tag(PeerId(0), first).unwrap(),
                owner_ring.tag(PeerId(0), second).unwrap()
            ],
            expected,
            "{case} alone"
        );
        let mut pair = None;
        let steps = lane_steps(|| pair = owner_ring.tag_pair([PeerId(0); 2], [first, second]));
        assert_eq!(pair, Some(expected), "{case}");
        assert_eq!(steps, on_sha2([4, 0, 0]), "{case}: two-chain steps");
    }
}

/// Pairs tag as [`KeyRing::tag`] and the hand-built HMAC do, and on the aarch64 `sha2` host count their two-chain steps: two digest bodies and two header-only GET inputs take the two middle header blocks, one last inner block and the outer block, 4 steps; two 8192-byte bodies take 2 + 128 + 1 + 1 = 132. A body of 8192 bytes beside a header-only GET shares the middle blocks, then runs its whole blocks alone, then pairs its padding block with the GET's padding block and the outer blocks: 4 steps.
#[test]
fn pairs_of_shared_shapes_count_their_two_chain_steps() {
    let (owner_ring, _) = rings();
    let (headers, bodies) = (positioned_headers(), positioned_bodies());
    let data: Vec<[u8; HEADER_LEN]> = (0..2)
        .map(|at| {
            let mut out = [0u8; HEADER_LEN];
            let header = Header {
                sequence: at + 1,
                ..data_of(OWNER_NONCE)
            };
            encode(crc(), &header, [&[0x6B; 20], &[]], &mut out).unwrap();
            out
        })
        .collect();
    let digests = [[0xD1u8; 16], [0xD2; 16]];
    let gets: Vec<[u8; HEADER_LEN]> = (0..2)
        .map(|at| {
            let mut out = [0; HEADER_LEN];
            encode(crc(), &get(1, at + 1, CLIENT_NONCE), [&[], &[]], &mut out).unwrap();
            out
        })
        .collect();
    let digest_inputs: [MacInput<'_>; 2] = std::array::from_fn(|at| MacInput {
        endpoint: ENDPOINT,
        direction: Direction::OwnerToClient,
        header: data[at].first_chunk().unwrap(),
        body: [&digests[at], &[]],
    });
    let get_inputs: [MacInput<'_>; 2] = std::array::from_fn(|at| {
        mac_input_for(&gets[at], [&[], &[]], ENDPOINT, Direction::ClientToOwner).unwrap()
    });
    let long: [MacInput<'_>; 2] = std::array::from_fn(|at| MacInput {
        endpoint: ENDPOINT,
        direction: Direction::ClientToOwner,
        header: &headers[at],
        body: [&bodies[at], &[]],
    });
    for (pair, steps, case) in [
        (
            [&digest_inputs[0], &digest_inputs[1]],
            4,
            "two digest bodies",
        ),
        ([&get_inputs[0], &get_inputs[1]], 4, "two GET headers"),
        ([&long[0], &long[1]], 132, "two 8192-byte bodies"),
        (
            [&long[0], &get_inputs[1]],
            4,
            "8192 bytes beside a GET header",
        ),
        (
            [&get_inputs[0], &long[1]],
            4,
            "a GET header beside 8192 bytes",
        ),
    ] {
        let expected = pair.map(|input| hand_tag(&KEY, input));
        assert_eq!(
            pair.map(|input| owner_ring.tag(PeerId(0), input).unwrap()),
            expected,
            "{case} alone"
        );
        let mut tags = None;
        let counted = lane_steps(|| tags = owner_ring.tag_pair([PeerId(0); 2], pair));
        assert_eq!(tags, Some(expected), "{case}");
        assert_eq!(counted, on_sha2([steps, 0, 0]), "{case}: two-chain steps");
    }
}

/// A sealed PUT DATA datagram of `len` body bytes at `sequence` from the client ring's peer, its last body byte flipped after sealing when `forged`.
fn put_datagram(ring: &KeyRing, len: u32, sequence: u64, forged: bool) -> Vec<u8> {
    let header = Header {
        kind: Kind::PutData,
        allocation: 5,
        total: u64::from(len),
        metadata_len: 0,
        body_len: len,
        index: 0,
        count: 1,
        offset: 0,
        datagram_len: len,
        grant: 0,
        remaining_ms: 0,
        sequence,
        ..get(1, 1, CLIENT_NONCE)
    };
    let body: Vec<u8> = (0..len).map(|at| (at * 5 + len) as u8).collect();
    let mut bytes = sealed(ring, PeerId(0), &header, &body, Direction::ClientToOwner);
    if forged {
        *bytes.last_mut().unwrap() ^= 1;
    }
    bytes
}

/// When either frame of a pair, or any frame of a group, fails its principal or key-epoch check, each frame gets the result [`KeyRing::authenticate`] gives it alone and no frame reaches a two-, three- or four-chain kernel; a pair of admitted GET headers runs 4 two-chain steps on the aarch64 `sha2` host.
#[test]
fn a_refused_frame_sends_its_pair_or_group_through_single_verification() {
    let (owner_ring, client_ring) = rings();
    let honest: Vec<Vec<u8>> = (1..=3)
        .map(|sequence| {
            sealed(
                &client_ring,
                PeerId(0),
                &get(3, sequence, CLIENT_NONCE),
                &[],
                Direction::ClientToOwner,
            )
        })
        .collect();
    let mut stale = get(3, 9, CLIENT_NONCE);
    stale.key_epoch = 7;
    let stale = sealed(
        &client_ring,
        PeerId(0),
        &stale,
        &[],
        Direction::ClientToOwner,
    );
    let verdict = |result: &Result<Authenticated<'_, '_>, AuthError>| {
        result
            .as_ref()
            .map(|frame| (frame.peer(), frame.header()))
            .map_err(|error| *error)
    };
    let (a, b, c) = (parsed(&honest[0]), parsed(&honest[1]), parsed(&honest[2]));
    let stale = parsed(&stale);
    let alone = |frame: &Frame<'_>, peer: PeerId| {
        verdict(&owner_ring.authenticate(frame, peer, ENDPOINT, Direction::ClientToOwner))
    };
    // Refusals by key epoch, then by a principal that differs from the transport peer's.
    for (refused, peer) in [(&stale, PeerId(0)), (&b, PeerId(1))] {
        for (first, second) in [
            ((&a, PeerId(0)), (refused, peer)),
            ((refused, peer), (&a, PeerId(0))),
        ] {
            let mut results = None;
            let steps = lane_steps(|| {
                results = Some(owner_ring.authenticate_pair(
                    first,
                    second,
                    ENDPOINT,
                    Direction::ClientToOwner,
                ));
            });
            let (ra, rb) = results.unwrap();
            assert_eq!(
                [verdict(&ra), verdict(&rb)],
                [alone(first.0, first.1), alone(second.0, second.1)]
            );
            assert!(ra.is_err() || rb.is_err());
            assert_eq!(steps, [0; 3], "a refused pair runs no lane kernel");
        }
        let group = [
            (&a, PeerId(0)),
            (refused, peer),
            (&c, PeerId(0)),
            (&a, PeerId(0)),
        ];
        let mut results = None;
        let steps = lane_steps(|| {
            results =
                Some(owner_ring.authenticate_group(group, ENDPOINT, Direction::ClientToOwner));
        });
        assert_eq!(
            results.unwrap().each_ref().map(verdict),
            group.map(|(frame, peer)| alone(frame, peer))
        );
        assert_eq!(steps, [0; 3], "a refused group runs no lane kernel");
    }
    let mut results = None;
    let steps = lane_steps(|| {
        results = Some(owner_ring.authenticate_pair(
            (&a, PeerId(0)),
            (&c, PeerId(0)),
            ENDPOINT,
            Direction::ClientToOwner,
        ));
    });
    let (ra, rb) = results.unwrap();
    assert!(ra.is_ok() && rb.is_ok());
    assert_eq!(
        steps,
        on_sha2([4, 0, 0]),
        "the admitted pair runs two chains"
    );
}

/// Verification hints every line of each PUT DATA frame's body once, alone, in a pair and in a group: 128 lines for 8192 bytes and 1 for a single byte alone, 128 + 1 = 129 for that pair, and 128 + 1 + 1 + 64 = 194 for a group of 8192, 1, 64 and 4096 bytes. Groups of two over every ordered pair of honest and forged frames, and groups of four drawn from them, give each frame the result [`KeyRing::authenticate`] gives it, and each forged frame, its last body byte flipped after sealing, fails alone with `AuthError::Tag`.
#[test]
fn verification_hints_each_body_line_once_and_groups_match_single_results() {
    let (owner_ring, client_ring) = rings();
    let hints = || crate::storage::prefetch::READ_HINTS.with(std::cell::Cell::get);
    let lens = [8192u32, 1, 64, 4096];
    let honest: Vec<Vec<u8>> = (1..)
        .zip(lens)
        .map(|(sequence, len)| put_datagram(&client_ring, len, sequence, false))
        .collect();
    let forged: Vec<Vec<u8>> = (10..)
        .zip(lens)
        .map(|(sequence, len)| put_datagram(&client_ring, len, sequence, true))
        .collect();
    let frames: Vec<Frame<'_>> = honest.iter().map(|bytes| parsed(bytes)).collect();
    for (frame, lines) in frames.iter().zip([128, 1]) {
        let before = hints();
        assert!(
            owner_ring
                .authenticate(frame, PeerId(0), ENDPOINT, Direction::ClientToOwner)
                .is_ok()
        );
        assert_eq!(
            hints() - before,
            lines,
            "{} bytes alone",
            frame.header().body_len
        );
    }
    let before = hints();
    let (ra, rb) = owner_ring.authenticate_pair(
        (&frames[0], PeerId(0)),
        (&frames[1], PeerId(0)),
        ENDPOINT,
        Direction::ClientToOwner,
    );
    assert!(ra.is_ok() && rb.is_ok());
    assert_eq!(hints() - before, 129, "8192 and 1 bytes in a pair");
    let before = hints();
    let results = owner_ring.authenticate_group(
        std::array::from_fn::<_, 4, _>(|at| (&frames[at], PeerId(0))),
        ENDPOINT,
        Direction::ClientToOwner,
    );
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(
        hints() - before,
        194,
        "8192, 1, 64 and 4096 bytes in a group"
    );
    let cases: Vec<Frame<'_>> = honest
        .iter()
        .chain(&forged)
        .map(|bytes| parsed(bytes))
        .collect();
    let single = |frame: &Frame<'_>| {
        owner_ring
            .authenticate(frame, PeerId(0), ENDPOINT, Direction::ClientToOwner)
            .map(|verified| verified.header())
    };
    for f in &forged {
        assert_eq!(single(&parsed(f)).err(), Some(AuthError::Tag));
    }
    for first in &cases {
        for second in &cases {
            let results = owner_ring.authenticate_group(
                [(first, PeerId(0)), (second, PeerId(0))],
                ENDPOINT,
                Direction::ClientToOwner,
            );
            assert_eq!(
                results.map(|r| r.map(|v| v.header())),
                [single(first), single(second)]
            );
        }
    }
    for start in 0..cases.len() {
        let picks: [usize; 4] = std::array::from_fn(|at| (start + 3 * at) % cases.len());
        let results = owner_ring.authenticate_group(
            picks.map(|at| (&cases[at], PeerId(0))),
            ENDPOINT,
            Direction::ClientToOwner,
        );
        assert_eq!(
            results.map(|r| r.map(|v| v.header())),
            picks.map(|at| single(&cases[at])),
            "{picks:?}"
        );
    }
}

/// Group and pair tagging and verification allocate nothing once their inputs exist: `tag_group` of four, `authenticate_group` of four, `tag_pair` and `authenticate_pair`.
#[test]
fn group_and_pair_tagging_and_verification_allocate_nothing() {
    let (owner_ring, client_ring) = rings();
    let (headers, bodies) = (positioned_headers(), positioned_bodies());
    let inputs: [MacInput<'_>; 4] = std::array::from_fn(|at| MacInput {
        endpoint: ENDPOINT,
        direction: Direction::ClientToOwner,
        header: &headers[at],
        body: [&bodies[at][..[8192, 1, 64, 0][at]], &[]],
    });
    let datagrams: Vec<Vec<u8>> = (1..)
        .zip([8192u32, 1, 64, 4096])
        .map(|(sequence, len)| put_datagram(&client_ring, len, sequence, false))
        .collect();
    let frames: Vec<Frame<'_>> = datagrams.iter().map(|bytes| parsed(bytes)).collect();
    let allocations = crate::instrument::allocations();
    let group = owner_ring.tag_group::<4>(std::array::from_fn(|at| (PeerId(0), &inputs[at])));
    let pair = owner_ring.tag_pair([PeerId(0), PeerId(1)], [&inputs[0], &inputs[1]]);
    let verified = owner_ring.authenticate_group(
        std::array::from_fn::<_, 4, _>(|at| (&frames[at], PeerId(0))),
        ENDPOINT,
        Direction::ClientToOwner,
    );
    let (ra, rb) = owner_ring.authenticate_pair(
        (&frames[0], PeerId(0)),
        (&frames[1], PeerId(0)),
        ENDPOINT,
        Direction::ClientToOwner,
    );
    assert_eq!(crate::instrument::allocations(), allocations);
    assert!(group.is_some() && pair.is_some());
    assert!(verified.iter().all(Result::is_ok) && ra.is_ok() && rb.is_ok());
}

/// Every version 3 vector's tag is the truncated HMAC-SHA256 of the domain block, the header and the whole body (DATA: its digest), which single authentication and the sender's MAC input reproduce. Changing one body byte of READY or an ownership kind, to a value that still parses, fails the tag through both single and grouped authentication.
#[test]
fn v3_fixed_tags_cover_ready_tenure_and_every_ownership_body_in_single_and_group_paths() {
    for (name, bytes) in super::frame::tests::vectors() {
        let frame = parsed(&bytes);
        let direction = frame.header().kind.direction();
        let mut budget = EngineBudget::new(1 << 20);
        let ring = KeyRing::load(
            &[frame.header().principal],
            &[KeyEntry {
                principal: frame.header().principal,
                key: &KEY,
            }],
            frame.header().key_epoch,
            &mut budget,
        )
        .unwrap();
        if frame.header().kind == Kind::Data {
            let mut h = frame.header();
            h.tag = [0; 16];
            let data = sealed(&ring, PeerId(0), &h, frame.raw_body(), direction);
            let data = parsed(&data);
            let digest = reference_polyval(
                reference_data_key_for(ENDPOINT, &KEY, h.owner_nonce, h.client_nonce),
                data.raw_body(),
            );
            let mut input = vec![0x00, 0xe1, 0x00, 0x01, direction as u8];
            input.extend_from_slice(&[0; 11]);
            input.extend_from_slice(data.authenticated());
            input.extend_from_slice(&digest);
            assert_eq!(data.header().tag, &hand_hmac(&KEY, &input)[..16], "{name}");
            assert!(
                ring.authenticate(&data, PeerId(0), ENDPOINT, direction)
                    .is_ok(),
                "{name}"
            );
            let mut changed = sealed(&ring, PeerId(0), &h, frame.raw_body(), direction);
            changed[HEADER_LEN] ^= 1;
            let altered = parsed(&changed);
            assert_eq!(
                ring.authenticate(&altered, PeerId(0), ENDPOINT, direction)
                    .err(),
                Some(AuthError::Tag),
                "{name}"
            );
            let group = ring.authenticate_group(
                [(&data, PeerId(0)), (&altered, PeerId(0))],
                ENDPOINT,
                direction,
            );
            assert!(group[0].is_ok(), "{name}");
            assert_eq!(group[1].as_ref().err(), Some(&AuthError::Tag), "{name}");
            continue;
        }
        let mut input = vec![0x00, 0xe1, 0x00, 0x01, direction as u8];
        input.extend_from_slice(&[0; 11]);
        input.extend_from_slice(frame.authenticated());
        input.extend_from_slice(frame.raw_body());
        assert_eq!(frame.header().tag, &hand_hmac(&KEY, &input)[..16], "{name}");
        assert!(
            ring.authenticate(&frame, PeerId(0), ENDPOINT, direction)
                .is_ok(),
            "{name}"
        );
        let mut digest = [0; 16];
        let sent = ring
            .mac_input(
                PeerId(0),
                bytes[..192].try_into().unwrap(),
                [frame.raw_body(), &[]],
                (ENDPOINT, direction),
                &mut digest,
            )
            .unwrap();
        assert_eq!(
            ring.tag(PeerId(0), &sent),
            Some(frame.header().tag),
            "{name}"
        );
        // The shard's low byte: 7 becomes 6, which still parses.
        let offset = match frame.header().kind {
            Kind::Ready => 11,
            kind if kind.is_ownership() => 7,
            _ => continue,
        };
        let mut changed = bytes.clone();
        changed[HEADER_LEN + offset] ^= 1;
        let altered = parsed(&changed);
        assert_eq!(
            ring.authenticate(&altered, PeerId(0), ENDPOINT, direction)
                .err(),
            Some(AuthError::Tag),
            "{name}"
        );
        let group = ring.authenticate_group(
            [(&frame, PeerId(0)), (&altered, PeerId(0))],
            ENDPOINT,
            direction,
        );
        assert!(group[0].is_ok());
        assert_eq!(group[1].as_ref().err(), Some(&AuthError::Tag));
    }
}

/// HELLO, CHALLENGE, CONFIRM, READY, a GET and an ERROR each refuse at parse as an unknown version in their
/// authentic version 2 copy, so no frame exists to hand to either session table; the version 3 copy of each then runs
/// the handshake and admits the GET and the ERROR, and both reports count one activation and nothing else.
#[test]
fn version_2_frames_refuse_at_parse_before_either_session_table() {
    let (owner_ring, client_ring) = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let to_owner = Direction::ClientToOwner;
    let to_client = Direction::OwnerToClient;
    let refused = |ring: &KeyRing, bytes: &[u8], direction: Direction| {
        let recast =
            super::frame_tests::recast_to_version_2(ring, PeerId(0), ENDPOINT, bytes, direction);
        assert_eq!(
            parse(crc(), &recast, false).err(),
            Some(FrameError::Version { found: 2 })
        );
    };

    let hello = client.hello(PeerId(0)).unwrap();
    let bytes = bootstrap_datagram(&client_ring, PeerId(0), &hello, to_owner);
    refused(&client_ring, &bytes, to_owner);
    let frame = parsed(&bytes);
    let auth = authenticate(&owner_ring, &frame, PeerId(0), to_owner).unwrap();
    let challenge = owner.on_hello(&auth).unwrap();
    assert_eq!(challenge.epoch, 1);

    let bytes = bootstrap_datagram(&owner_ring, PeerId(0), &challenge, to_client);
    refused(&owner_ring, &bytes, to_client);
    let frame = parsed(&bytes);
    let auth = authenticate(&client_ring, &frame, PeerId(0), to_client).unwrap();
    let confirm = client.on_challenge(&auth).unwrap();

    let bytes = bootstrap_datagram(&client_ring, PeerId(0), &confirm, to_owner);
    refused(&client_ring, &bytes, to_owner);
    let frame = parsed(&bytes);
    let auth = authenticate(&owner_ring, &frame, PeerId(0), to_owner).unwrap();
    let activation = owner.on_confirm(&auth).unwrap();

    let bytes = bootstrap_datagram(&owner_ring, PeerId(0), &activation.ready, to_client);
    refused(&owner_ring, &bytes, to_client);
    let frame = parsed(&bytes);
    let auth = authenticate(&client_ring, &frame, PeerId(0), to_client).unwrap();
    let (admitted, _, _) = client.on_ready(&auth).unwrap();
    let epoch = admitted.epoch;

    let bytes = sealed(
        &client_ring,
        PeerId(0),
        &get(epoch, 1, CLIENT_NONCE),
        &[],
        to_owner,
    );
    refused(&client_ring, &bytes, to_owner);
    let frame = parsed(&bytes);
    let auth = authenticate(&owner_ring, &frame, PeerId(0), to_owner).unwrap();
    assert!(owner.admit(&auth).is_ok());

    let error = Header {
        kind: Kind::Error,
        metadata_len: 0,
        body_len: 0,
        grant: 0,
        remaining_ms: 0,
        status: Status::Missing as u16,
        ..get(epoch, 1, CLIENT_NONCE)
    };
    let bytes = sealed(&owner_ring, PeerId(0), &error, &[], to_client);
    refused(&owner_ring, &bytes, to_client);
    let frame = parsed(&bytes);
    let auth = authenticate(&client_ring, &frame, PeerId(0), to_client).unwrap();
    assert!(client.admit(&auth).is_ok());
    let report = SessionReport {
        activations: 1,
        ..SessionReport::default()
    };
    assert_eq!((owner.report(), client.report()), (report, report));
}

/// A READY naming in-range caps other than the pending handshake's is refused with `Mismatch` and counted, and the
/// handshake stays pending, so the matching READY then activates it. On the active session, a repeated READY that
/// changes only its tenure, or only its caps, is refused and counted the same way and leaves the session's epoch,
/// caps and tenure as they were, and the original READY is still accepted.
#[test]
fn a_ready_naming_other_caps_or_another_tenure_is_refused_and_counted() {
    use crate::net::ownership::{ActivatedEpoch, ReadyBody, Shard, ShardGeneration, Tenure};
    let pair = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let hello = client.hello(PeerId(0)).unwrap();
    let challenge = delivered(&pair, &hello, |frame| owner.on_hello(frame)).unwrap();
    let confirm = delivered(&pair, &challenge, |frame| client.on_challenge(frame)).unwrap();
    let ready = delivered(&pair, &confirm, |frame| owner.on_confirm(frame))
        .unwrap()
        .ready;
    let deliver = |client: &mut Sessions, step: &Bootstrap| {
        delivered(&pair, step, |frame| client.on_ready(frame))
    };
    let refused = |client: &mut Sessions, step: &Bootstrap| {
        let before = (
            client.report(),
            client.active(PeerId(0)),
            client.tenure(PeerId(0)),
        );
        assert_eq!(deliver(client, step).err(), Some(SessionReject::Mismatch));
        let counted = SessionReport {
            mismatched: before.0.mismatched + 1,
            ..before.0
        };
        assert_eq!(
            (
                client.report(),
                client.active(PeerId(0)),
                client.tenure(PeerId(0))
            ),
            (counted, before.1, before.2)
        );
    };
    let other_caps = Caps {
        slots: CAPS.slots - 1,
        ..CAPS
    };
    refused(
        &mut client,
        &Bootstrap {
            caps: other_caps,
            ..ready
        },
    );
    assert!(
        client.active(PeerId(0)).is_none(),
        "the handshake stays pending"
    );
    let (admitted, replaced, body) = deliver(&mut client, &ready).unwrap();
    assert_eq!(
        (admitted.epoch, admitted.caps, replaced),
        (ready.epoch, CAPS, None)
    );
    let carried = ReadyBody {
        caps: CAPS,
        shard: Shard::new(7).unwrap(),
        tenure: Tenure {
            generation: ShardGeneration::new(11).unwrap(),
            epoch: ActivatedEpoch::new(10).unwrap(),
            host: crate::failover::identity::Exhid::new([0xa1; 16]).unwrap(),
        },
    };
    assert_eq!(body, carried);
    let tenure = client.tenure(PeerId(0)).expect("READY binds its tenure");
    assert_eq!(tenure, carried.tenure);
    let other_tenure = Tenure {
        generation: ShardGeneration::new(tenure.generation.get() + 1).unwrap(),
        ..tenure
    };
    refused(
        &mut client,
        &Bootstrap {
            tenure: Some(other_tenure),
            ..ready
        },
    );
    refused(
        &mut client,
        &Bootstrap {
            caps: other_caps,
            ..ready
        },
    );
    assert_eq!(client.report().mismatched, 3);
    assert_eq!(deliver(&mut client, &ready), Ok((admitted, None, carried)));
    assert_eq!(client.tenure(PeerId(0)), Some(tenure));
}

/// `Sessions::admit_newest` admits a frame of the active session only under a sequence above every sequence that
/// session admitted. A copy, an overtaken frame and a frame of another epoch return false and leave the counters and
/// the replay window as they were, so the overtaken frame still passes `admit`. A client's `admit` takes the
/// WrongOwner that answers a PROBE and refuses every other ownership kind with `Kind` before any counter moves.
#[test]
fn admit_newest_takes_only_the_newest_frame_and_a_client_admits_wrong_owner_alone_of_the_ownership_kinds()
 {
    use crate::net::ownership::{OwnershipBody, Shard, Validity};
    let pair = rings();
    let (owner_ring, client_ring) = &pair;
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 2);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let epoch = handshake(&mut owner, &mut client, &pair);
    let frame = |kind: Kind, epoch: u64, sequence: u64| {
        let reply = OwnershipBody {
            shard: Shard::new(7).unwrap(),
            volume: None,
            tenure: None,
            report_age_us: 0,
            responder: Some(crate::failover::identity::Exhid::new([0xa1; 16]).unwrap()),
            validity: Validity::new(0).unwrap(),
        };
        let mut body = vec![0; reply.encoded_len()];
        reply.encode(kind, &mut body).unwrap();
        let header = Header {
            datagram_len: body.len() as u32,
            principal: CLIENT,
            key_epoch: 1,
            owner_nonce: OWNER_NONCE,
            client_nonce: CLIENT_NONCE,
            sequence,
            epoch,
            ..super::serve::header(kind, 0, [0; 32])
        };
        sealed(
            owner_ring,
            PeerId(0),
            &header,
            &body,
            Direction::OwnerToClient,
        )
    };
    let newest = |client: &mut Sessions, bytes: &[u8]| {
        let frame = parsed(bytes);
        let auth = authenticate(client_ring, &frame, PeerId(0), Direction::OwnerToClient);
        client.admit_newest(&auth.unwrap())
    };
    let admit = |client: &mut Sessions, bytes: &[u8]| {
        let frame = parsed(bytes);
        let auth = authenticate(client_ring, &frame, PeerId(0), Direction::OwnerToClient);
        client.admit(&auth.unwrap()).map(|_| ())
    };
    let report = client.report();
    assert!(newest(&mut client, &frame(Kind::WrongOwner, epoch, 3)));
    assert_eq!(
        client.report(),
        report,
        "an admitted newest frame moves no counter"
    );
    for (bytes, case) in [
        (frame(Kind::WrongOwner, epoch, 3), "a copy"),
        (frame(Kind::WrongOwner, epoch, 2), "an overtaken frame"),
        (frame(Kind::WrongOwner, epoch + 1, 4), "another epoch"),
    ] {
        assert!(!newest(&mut client, &bytes), "{case}");
        assert_eq!(client.report(), report, "{case} moves no counter");
    }
    assert_eq!(
        admit(&mut client, &frame(Kind::WrongOwner, epoch, 2)),
        Ok(()),
        "the overtaken frame stays inside the replay window"
    );
    assert_eq!(
        admit(&mut client, &frame(Kind::WrongOwner, epoch, 3)),
        Err(SessionReject::Duplicate),
        "the newest frame was recorded"
    );
    let report = client.report();
    for kind in [Kind::Holder, Kind::Heartbeat, Kind::ProbeReply] {
        assert_eq!(
            admit(&mut client, &frame(kind, epoch, 9)),
            Err(SessionReject::Kind),
            "{kind:?}"
        );
        assert_eq!(client.report(), report, "{kind:?} moves no counter");
    }
    assert!(newest(&mut client, &frame(Kind::WrongOwner, epoch, 9)));
}

/// The signed INVALIDATE, INVALIDATED and versioned PUT BEGIN vectors authenticate, and a flipped interval or
/// version byte, resealed so the header crc holds, fails the tag.
#[test]
fn v3_tags_cover_the_version_and_interval_fields() {
    let mut budget = EngineBudget::new(1 << 20);
    for (name, flips) in [
        ("v3-invalidate", &[79, 111][..]),
        ("v3-invalidated", &[79, 111][..]),
        ("v3-put-begin-versioned", &[111][..]),
    ] {
        let bytes = super::frame::tests::vector(name);
        let frame = parsed(&bytes);
        let header = frame.header();
        let ring = KeyRing::load(
            &[header.principal],
            &[KeyEntry {
                principal: header.principal,
                key: &KEY,
            }],
            header.key_epoch,
            &mut budget,
        )
        .unwrap();
        let direction = header.kind.direction();
        assert!(
            ring.authenticate(&frame, PeerId(0), ENDPOINT, direction)
                .is_ok(),
            "{name}"
        );
        for &at in flips {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            super::frame_tests::reseal(&mut changed);
            let altered = parsed(&changed);
            assert_eq!(
                ring.authenticate(&altered, PeerId(0), ENDPOINT, direction)
                    .err(),
                Some(AuthError::Tag),
                "{name}: byte {at}"
            );
        }
    }
}

/// The refusal of `handler` for the frame of `datagram`, authenticated under `ring` as peer 0 sent it in the
/// direction its kind travels.
fn refusal(
    ring: &KeyRing,
    table: &mut Sessions,
    handler: Kind,
    datagram: &[u8],
) -> Option<SessionReject> {
    let frame = parsed(datagram);
    let direction = frame.header().kind.direction();
    let frame = authenticate(ring, &frame, PeerId(0), direction)
        .expect("the frame carries its sender's tag");
    match handler {
        Kind::Hello => table.on_hello(&frame).err(),
        Kind::Challenge => table.on_challenge(&frame).err(),
        Kind::Confirm => table.on_confirm(&frame).err(),
        Kind::Ready => table.on_ready(&frame).err(),
        _ => unreachable!("only the bootstrap kinds have handlers"),
    }
}

/// An owner and a client after the first `steps` steps of one bootstrap, with the datagrams those steps sent:
/// HELLO sent, HELLO answered, CHALLENGE answered, CONFIRM answered, READY taken. `ring` holds the one key the two
/// ends share, with the other end as peer 0, and tags and authenticates every frame.
fn bootstrapped(ring: &KeyRing, steps: usize) -> (Sessions, Sessions, Vec<Vec<u8>>) {
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 1);
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    let mut sent: Vec<Vec<u8>> = Vec::new();
    for step in 0..steps {
        bootstrap_step(ring, &mut owner, &mut client, &mut sent, step);
    }
    (owner, client, sent)
}

/// Takes step `step` of the bootstrap [`bootstrapped`] runs, on tables that took every earlier step.
fn bootstrap_step(
    ring: &KeyRing,
    owner: &mut Sessions,
    client: &mut Sessions,
    sent: &mut Vec<Vec<u8>>,
    step: usize,
) {
    let datagram =
        |step: &Bootstrap| bootstrap_datagram(ring, PeerId(0), step, step.kind.direction());
    match step {
        0 => sent.push(datagram(&client.hello(PeerId(0)).unwrap())),
        1 => {
            let frame = parsed(&sent[0]);
            let frame = authenticate(ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
            let challenge = owner.on_hello(&frame).unwrap();
            sent.push(datagram(&challenge));
        }
        2 => {
            let frame = parsed(&sent[1]);
            let frame = authenticate(ring, &frame, PeerId(0), Direction::OwnerToClient).unwrap();
            let confirm = client.on_challenge(&frame).unwrap();
            sent.push(datagram(&confirm));
        }
        3 => {
            let frame = parsed(&sent[2]);
            let frame = authenticate(ring, &frame, PeerId(0), Direction::ClientToOwner).unwrap();
            let activation = owner.on_confirm(&frame).unwrap();
            sent.push(datagram(&activation.ready));
        }
        _ => {
            let frame = parsed(&sent[3]);
            let frame = authenticate(ring, &frame, PeerId(0), Direction::OwnerToClient).unwrap();
            client.on_ready(&frame).unwrap();
        }
    }
}

/// Each bootstrap handler, named by the kind it takes, with the role it belongs to.
const HANDLERS: [(Kind, Role); 4] = [
    (Kind::Hello, Role::Owner),
    (Kind::Challenge, Role::Client),
    (Kind::Confirm, Role::Owner),
    (Kind::Ready, Role::Client),
];

/// Every handler, on an owner and on a client at every step of a bootstrap, from fresh tables through pending
/// handshakes to active sessions, with the four bootstrap frames of a completed run of that bootstrap and a GET of
/// its session: the other role's table answers `Role` whatever the frame's kind, the handler's own role answers
/// `Kind` for every kind but its own, and each refusal leaves the peer's bootstrap state, its active session and the
/// report as they were.
#[test]
fn each_bootstrap_handler_refuses_the_other_role_then_another_kind_and_changes_nothing() {
    // The client's ring holds the one key the two ends share, with the other end as peer 0, so it serves both ends.
    let (_, ring) = rings();
    let (_, _, mut frames) = bootstrapped(&ring, 5);
    assert_eq!(frames.len(), 4);
    frames.push(sealed(
        &ring,
        PeerId(0),
        &get(1, 1, CLIENT_NONCE),
        &[],
        Direction::ClientToOwner,
    ));
    let kinds = [
        Kind::Hello,
        Kind::Challenge,
        Kind::Confirm,
        Kind::Ready,
        Kind::Get,
    ];
    let mut role_refusals = 0;
    let mut kind_refusals = 0;
    for steps in 0..=5 {
        let (mut owner, mut client, mut sent) = bootstrapped(&ring, steps);
        assert_eq!(sent[..], frames[..sent.len()]);
        for (role, table) in [(Role::Owner, &mut owner), (Role::Client, &mut client)] {
            for (handler, belongs_to) in HANDLERS {
                for (kind, datagram) in kinds.iter().zip(&frames) {
                    let expected = if role != belongs_to {
                        role_refusals += 1;
                        SessionReject::Role
                    } else if *kind != handler {
                        kind_refusals += 1;
                        SessionReject::Kind
                    } else {
                        continue;
                    };
                    let before = (
                        table.view(PeerId(0)),
                        table.active(PeerId(0)),
                        table.report(),
                    );
                    assert_eq!(
                        refusal(&ring, table, handler, datagram),
                        Some(expected),
                        "the {handler:?} handler on a {role:?} table after {steps} steps, given a {kind:?} frame"
                    );
                    assert_eq!(
                        (
                            table.view(PeerId(0)),
                            table.active(PeerId(0)),
                            table.report()
                        ),
                        before,
                        "the {handler:?} handler on a {role:?} table after {steps} steps changed state as it refused a {kind:?} frame"
                    );
                }
            }
        }
        for step in steps..5 {
            bootstrap_step(&ring, &mut owner, &mut client, &mut sent, step);
        }
        let session = client.active(PeerId(0));
        assert!(
            session.is_some() && owner.active(PeerId(0)) == session,
            "after the refusals at step {steps} the bootstrap completes on both ends: {session:?}"
        );
        assert_eq!(
            (owner.report().activations, client.report().activations),
            (1, 1),
            "after the refusals at step {steps} each end activated once"
        );
    }
    assert_eq!(
        (role_refusals, kind_refusals),
        (6 * 4 * 5, 6 * 4 * 4),
        "every handler met both roles and every frame at every step"
    );
}

#[test]
fn each_bootstrap_handler_accepts_its_own_kind_on_its_own_role() {
    let (_, ring) = rings();
    let (_, _, frames) = bootstrapped(&ring, 5);
    for (at, (handler, belongs_to)) in HANDLERS.into_iter().enumerate() {
        let (mut owner, mut client, _) = bootstrapped(&ring, at + 1);
        let table = match belongs_to {
            Role::Owner => &mut owner,
            Role::Client => &mut client,
        };
        let before = table.view(PeerId(0));
        assert_eq!(
            refusal(&ring, table, handler, &frames[at]),
            None,
            "the {handler:?} handler on a {belongs_to:?} table after {} steps",
            at + 1
        );
        assert_ne!(
            table.view(PeerId(0)),
            before,
            "the {handler:?} handler moved the peer's bootstrap state"
        );
    }
}

/// The key a re-key installs in place of [`KEY`].
const FRESH_KEY: [u8; 32] = [0x33; 32];
/// The boot nonce a re-key moves a table to.
const NEXT_NONCE: [u8; 16] = [0x0B; 16];

/// Re-keys the quiescent `table` and its `ring` to [`FRESH_KEY`] under key epoch 2 and boot [`NEXT_NONCE`].
fn rekey(table: &mut Sessions, ring: &mut KeyRing) {
    let entries = [KeyEntry {
        principal: CLIENT,
        key: &FRESH_KEY,
    }];
    assert_eq!(
        table.rekey(ring, &entries, 2, NEXT_NONCE, RequestCensus::default()),
        Ok(()),
        "a quiescent re-key succeeds"
    );
    assert_eq!((ring.epoch(), table.nonce()), (2, NEXT_NONCE));
}

/// The HELLO datagram of `hello`, tagged by the client under `ring`'s current keys and key epoch.
fn hello_datagram(ring: &KeyRing, hello: &Bootstrap) -> Vec<u8> {
    assert_eq!(hello.kind, Kind::Hello);
    let body = super::frame_tests::bootstrap_body(hello);
    let header = Header {
        key_epoch: ring.epoch(),
        datagram_len: body.len() as u32,
        ..bootstrap_header(hello, CLIENT)
    };
    sealed(ring, PeerId(0), &header, &body, Direction::ClientToOwner)
}

/// A client whose bootstrap sequences for its peer reached `u64::MAX` retires the peer at the next HELLO. A
/// quiescent re-key then succeeds, and the HELLO after it is refused `Retired`: the peer stays retired, and the
/// count of retired peers stays 1.
#[test]
fn a_peer_retired_by_bootstrap_sequence_exhaustion_stays_retired_through_a_rekey() {
    let (_, mut ring) = rings();
    let mut client = sessions(Role::Client, CLIENT_NONCE, 1);
    client.set_counters(PeerId(0), 0, u64::MAX);
    assert_eq!(
        client.hello(PeerId(0)).err(),
        Some(SessionReject::Exhausted)
    );
    assert_eq!(client.hello(PeerId(0)).err(), Some(SessionReject::Retired));
    assert_eq!(client.report().retired_peers, 1);
    let before = client.view(PeerId(0));

    rekey(&mut client, &mut ring);

    assert_eq!(
        client.hello(PeerId(0)).err(),
        Some(SessionReject::Retired),
        "the re-key did not revive the peer"
    );
    assert_eq!(client.report().retired_peers, 1, "retired once");
    assert_eq!(
        client.view(PeerId(0)),
        before,
        "the retired peer's state stands"
    );
    assert_eq!(client.active(PeerId(0)), None);
}

/// An owner whose epochs for its peer reached `u64::MAX` retires the peer at the next HELLO. A quiescent re-key
/// then succeeds, and a HELLO that authenticates under the new keys, from the client's next boot, is refused
/// `Retired`, with the peer's session absent and the count of retired peers still 1.
#[test]
fn a_peer_retired_by_epoch_exhaustion_stays_retired_through_a_rekey() {
    // The client's ring serves as the owner's too: it holds the key the two ends share, with the other end as peer 0.
    let (_, mut ring) = rings();
    let mut owner = sessions(Role::Owner, OWNER_NONCE, 1);
    owner.set_counters(PeerId(0), u64::MAX, 0);
    let hello = sessions(Role::Client, CLIENT_NONCE, 1)
        .hello(PeerId(0))
        .unwrap();
    let datagram = hello_datagram(&ring, &hello);
    assert_eq!(
        refusal(&ring, &mut owner, Kind::Hello, &datagram),
        Some(SessionReject::Exhausted)
    );
    assert_eq!(
        refusal(&ring, &mut owner, Kind::Hello, &datagram),
        Some(SessionReject::Retired)
    );
    assert_eq!(owner.report().retired_peers, 1);
    let before = owner.view(PeerId(0));

    rekey(&mut owner, &mut ring);

    let hello = sessions(Role::Client, [0x0D; 16], 1)
        .hello(PeerId(0))
        .unwrap();
    let datagram = hello_datagram(&ring, &hello);
    assert_eq!(
        refusal(&ring, &mut owner, Kind::Hello, &datagram),
        Some(SessionReject::Retired),
        "the re-key did not revive the peer"
    );
    assert_eq!(owner.report().retired_peers, 1, "retired once");
    assert_eq!(
        owner.view(PeerId(0)),
        before,
        "the retired peer's state stands"
    );
    assert_eq!(owner.active(PeerId(0)), None);
}
