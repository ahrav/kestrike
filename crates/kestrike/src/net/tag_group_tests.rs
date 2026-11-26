//! Each group tag equals the leftmost 16 bytes of HMAC-SHA256 over the corresponding MAC input using that peer's key.

use crate::storage::EngineBudget;
use crate::storage::seeded::SplitMix64;

use super::auth::{AuthError, Authenticated, KeyEntry, KeyRing};
use super::auth_tests::{ENDPOINT, OWNER_NONCE, crc, hand_tag, session_header};
use super::datagram::{HEADER_LEN, PeerId};
use super::frame::{
    AUTHENTICATED_LEN, Direction, Frame, Header, KIND_AT, Kind, MacInput, encode, mac_input_for,
    parse, seal,
};
use super::frame_tests::put_frame;

const PRINCIPAL: u32 = 0x0000_0D00;

const CONTROL: [Kind; 3] = [Kind::Get, Kind::Ack, Kind::Cancel];

const DIRECTIONS: [Direction; 2] = [Direction::ClientToOwner, Direction::OwnerToClient];

fn fixed_key(peer: usize) -> [u8; 32] {
    std::array::from_fn(|at| (0x31 + 0x47 * peer + 3 * at) as u8)
}

fn ring_over(keys: &[[u8; 32]]) -> KeyRing {
    let principals: Vec<u32> = (0..keys.len() as u32).map(|p| PRINCIPAL + p).collect();
    let entries: Vec<KeyEntry<'_>> = principals
        .iter()
        .zip(keys)
        .map(|(&principal, key)| KeyEntry { principal, key })
        .collect();
    KeyRing::load(&principals, &entries, 1, &mut EngineBudget::new(1 << 20)).unwrap()
}

fn fixed_keys(peers: usize) -> Vec<[u8; 32]> {
    (0..peers).map(fixed_key).collect()
}

fn control(peer: usize, at: usize) -> [u8; HEADER_LEN] {
    let header = Header {
        principal: PRINCIPAL + peer as u32,
        ..session_header(CONTROL[at % CONTROL.len()], OWNER_NONCE, 1, 1 + at as u64)
    };
    let mut out = [0; HEADER_LEN];
    encode(crc(), &header, [&[], &[]], &mut out).unwrap();
    out
}

fn header_only(frame: &[u8; HEADER_LEN], direction: Direction) -> MacInput<'_> {
    mac_input_for(frame, [&[], &[]], ENDPOINT, direction).unwrap()
}

fn admits(
    verdict: &Result<Authenticated<'_, '_>, AuthError>,
    frame: &Frame<'_>,
    peer: usize,
) -> bool {
    verdict.as_ref().is_ok_and(|admitted| {
        std::ptr::eq(admitted.frame(), frame) && admitted.peer() == PeerId(peer as u16)
    })
}

fn group_tags(ring: &KeyRing, inputs: &[(PeerId, &MacInput<'_>)]) -> Vec<[u8; 16]> {
    match *inputs {
        [a] => ring.tag_group([a]).unwrap().to_vec(),
        [a, b] => ring.tag_group([a, b]).unwrap().to_vec(),
        [a, b, c] => ring.tag_group([a, b, c]).unwrap().to_vec(),
        [a, b, c, d] => ring.tag_group([a, b, c, d]).unwrap().to_vec(),
        _ => unreachable!("a group holds one to four inputs"),
    }
}

fn group_verdicts<'f, 'b>(
    ring: &KeyRing,
    frames: &[(&'f Frame<'b>, PeerId)],
    endpoint: u32,
    direction: Direction,
) -> Vec<Result<Authenticated<'f, 'b>, AuthError>> {
    match *frames {
        [a] => ring.authenticate_group([a], endpoint, direction).into(),
        [a, b] => ring.authenticate_group([a, b], endpoint, direction).into(),
        [a, b, c] => ring
            .authenticate_group([a, b, c], endpoint, direction)
            .into(),
        [a, b, c, d] => ring
            .authenticate_group([a, b, c, d], endpoint, direction)
            .into(),
        _ => unreachable!("a group holds one to four frames"),
    }
}

#[test]
fn header_only_frames_tag_as_the_hand_built_hmac_through_every_group_entry() {
    for peers in [1, 2, 4] {
        let keys = fixed_keys(peers);
        let ring = ring_over(&keys);
        let frames: Vec<Vec<[u8; HEADER_LEN]>> = (0..peers)
            .map(|peer| (0..17).map(|at| control(peer, at)).collect())
            .collect();
        for direction in DIRECTIONS {
            let input = |peer: usize, at: usize| header_only(&frames[peer][at], direction);
            let want = |peer: usize, at: usize| hand_tag(&keys[peer], &input(peer, at));
            for peer in 0..peers {
                let inputs: Vec<MacInput<'_>> = (0..17).map(|at| input(peer, at)).collect();
                for count in 1..=17 {
                    let mut tags = vec![[0xA5; 16]; count];
                    ring.tags(PeerId(peer as u16), &inputs[..count], &mut tags)
                        .unwrap();
                    let wants: Vec<[u8; 16]> = (0..count).map(|at| want(peer, at)).collect();
                    assert_eq!(tags, wants, "{count} inputs of peer {peer} of {peers}");
                }
            }
            for first in 0..peers {
                for second in 0..peers {
                    let pair = [input(first, 0), input(second, 1)];
                    assert_eq!(
                        ring.tag_pair(
                            [PeerId(first as u16), PeerId(second as u16)],
                            [&pair[0], &pair[1]]
                        ),
                        Some([want(first, 0), want(second, 1)]),
                        "a pair of peers {first} and {second}"
                    );
                }
                let peer = |at: usize| (first + at) % peers;
                let inputs: [MacInput<'_>; 4] = std::array::from_fn(|at| input(peer(at), at));
                let each: [(PeerId, &MacInput<'_>); 4] =
                    std::array::from_fn(|at| (PeerId(peer(at) as u16), &inputs[at]));
                for count in 1..=4 {
                    let wants: Vec<[u8; 16]> = (0..count).map(|at| want(peer(at), at)).collect();
                    assert_eq!(
                        group_tags(&ring, &each[..count]),
                        wants,
                        "a group of {count} from peer {first} of {peers}"
                    );
                }
            }
            let sealed: Vec<Vec<[u8; HEADER_LEN]>> = (0..peers)
                .map(|peer| {
                    (0..4)
                        .map(|at| {
                            let mut frame = frames[peer][at];
                            seal(&mut frame, want(peer, at));
                            frame
                        })
                        .collect()
                })
                .collect();
            let parsed: Vec<Vec<Frame<'_>>> = sealed
                .iter()
                .map(|frames| {
                    frames
                        .iter()
                        .map(|frame| parse(crc(), frame, false).unwrap())
                        .collect()
                })
                .collect();
            for first in 0..peers {
                for second in 0..peers {
                    let (left, right) = ring.authenticate_pair(
                        (&parsed[first][0], PeerId(first as u16)),
                        (&parsed[second][1], PeerId(second as u16)),
                        ENDPOINT,
                        direction,
                    );
                    assert!(admits(&left, &parsed[first][0], first), "{left:?}");
                    assert!(admits(&right, &parsed[second][1], second), "{right:?}");
                }
                let peer = |at: usize| (first + at) % peers;
                let each: [(&Frame<'_>, PeerId); 4] =
                    std::array::from_fn(|at| (&parsed[peer(at)][at], PeerId(peer(at) as u16)));
                for count in 1..=4 {
                    let verdicts = group_verdicts(&ring, &each[..count], ENDPOINT, direction);
                    assert_eq!(verdicts.len(), count);
                    for (at, verdict) in verdicts.iter().enumerate() {
                        assert!(admits(verdict, each[at].0, peer(at)), "{verdict:?}");
                    }
                }
            }
        }
    }
}

#[test]
fn a_flipped_tag_bit_refuses_its_own_frame_and_no_other() {
    for peers in [1, 2, 4] {
        let keys = fixed_keys(peers);
        let direction = Direction::ClientToOwner;
        for ring in [ring_over(&keys), ring_over(&keys).with_portable_lanes()] {
            let sealed: [[u8; HEADER_LEN]; 4] = std::array::from_fn(|at| {
                let mut frame = control(at % peers, at);
                let tag = hand_tag(&keys[at % peers], &header_only(&frame, direction));
                seal(&mut frame, tag);
                frame
            });
            for position in 0..4 {
                for bit in 0..128 {
                    let mut bytes = sealed;
                    bytes[position][AUTHENTICATED_LEN + bit / 8] ^= 1 << (bit % 8);
                    let parsed = bytes
                        .each_ref()
                        .map(|frame| parse(crc(), frame, false).unwrap());
                    let each: [(&Frame<'_>, PeerId); 4] =
                        std::array::from_fn(|at| (&parsed[at], PeerId((at % peers) as u16)));
                    for count in position + 1..=4 {
                        let verdicts = group_verdicts(&ring, &each[..count], ENDPOINT, direction);
                        assert_eq!(verdicts.len(), count);
                        for (at, verdict) in verdicts.iter().enumerate() {
                            if at == position {
                                assert_eq!(verdict.as_ref().err(), Some(&AuthError::Tag));
                            } else {
                                assert!(
                                    admits(verdict, each[at].0, at % peers),
                                    "bit {bit} of frame {position} of {count}: frame {at} {verdict:?}"
                                );
                            }
                        }
                    }
                    if position < 2 {
                        let pair = ring.authenticate_pair(each[0], each[1], ENDPOINT, direction);
                        for (at, verdict) in [pair.0, pair.1].iter().enumerate() {
                            if at == position {
                                assert_eq!(verdict.as_ref().err(), Some(&AuthError::Tag));
                            } else {
                                assert!(admits(verdict, each[at].0, at % peers), "{verdict:?}");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn header_only_groups_run_one_tail_pass_each() {
    use crate::isa_witness::{Kernel, detected, runs, witness};
    let keys = fixed_keys(2);
    let ring = ring_over(&keys);
    let direction = Direction::ClientToOwner;
    let frames: Vec<[u8; HEADER_LEN]> = (0..16).map(|at| control(0, at)).collect();
    let inputs: Vec<MacInput<'_>> = frames
        .iter()
        .map(|frame| header_only(frame, direction))
        .collect();
    let wants: Vec<[u8; 16]> = inputs
        .iter()
        .map(|input| hand_tag(&keys[0], input))
        .collect();
    let sealed: Vec<[u8; HEADER_LEN]> = frames
        .iter()
        .zip(&wants)
        .map(|(frame, tag)| {
            let mut frame = *frame;
            seal(&mut frame, *tag);
            frame
        })
        .collect();
    let parsed: Vec<Frame<'_>> = sealed
        .iter()
        .map(|frame| parse(crc(), frame, false).unwrap())
        .collect();
    let (put, body) = put_frame(Kind::PutData, &session_header(Kind::Get, OWNER_NONCE, 1, 9));
    let mut with_body = [0; HEADER_LEN];
    encode(
        crc(),
        &Header {
            principal: PRINCIPAL,
            ..put
        },
        [&body, &[]],
        &mut with_body,
    )
    .unwrap();
    let covered = mac_input_for(&with_body, [&body, &[]], ENDPOINT, direction).unwrap();
    let peer = PeerId(0);
    let other = control(1, 1);
    let other_input = header_only(&other, direction);
    let sha2 = detected!(aarch64: "sha2");
    let present = sha2.present;
    let before = runs(Kernel::Sha2Tail);
    witness(
        "hmac-tail",
        sha2,
        || runs(Kernel::Sha2Tail),
        || {
            let mut tags = [[0xA5; 16]; 16];
            ring.tags(peer, &inputs, &mut tags).unwrap();
            assert_eq!(tags.to_vec(), wants);
            let mut seven = [[0xA5; 16]; 7];
            ring.tags(peer, &inputs[..7], &mut seven).unwrap();
            assert_eq!(seven[..], wants[..7]);
            let pass = runs(Kernel::Sha2Tail);
            assert_eq!(
                ring.tag_pair([peer, PeerId(1)], [&inputs[0], &other_input]),
                Some([wants[0], hand_tag(&keys[1], &other_input)])
            );
            assert_eq!(
                runs(Kernel::Sha2Tail) - pass,
                usize::from(present),
                "a pair under two peers' keys"
            );
            let each: [(PeerId, &MacInput<'_>); 4] = std::array::from_fn(|at| (peer, &inputs[at]));
            for count in 1..=4 {
                assert_eq!(group_tags(&ring, &each[..count]), wants[..count]);
            }
            let (left, right) =
                ring.authenticate_pair((&parsed[0], peer), (&parsed[1], peer), ENDPOINT, direction);
            assert!(admits(&left, &parsed[0], 0) && admits(&right, &parsed[1], 0));
            let frames: [(&Frame<'_>, PeerId); 4] = std::array::from_fn(|at| (&parsed[at], peer));
            let verdicts = group_verdicts(&ring, &frames, ENDPOINT, direction);
            assert!((0..4).all(|at| admits(&verdicts[at], &parsed[at], 0)));
            let mixed = group_tags(&ring, &[(peer, &inputs[0]), (peer, &covered)]);
            assert_eq!(mixed, [wants[0], hand_tag(&keys[0], &covered)]);
        },
    );
    assert_eq!(
        runs(Kernel::Sha2Tail) - before,
        if present { 12 } else { 0 },
        "four groups of sixteen, a group of four and a group of three of seven, a pair under two peers, groups of two, three and four, a pair of frames and a group of four frames"
    );
}

const BODIES: [usize; 8] = [1, 16, 55, 56, 63, 64, 65, 200];

const KINDS: [Kind; 6] = [
    Kind::Get,
    Kind::Ack,
    Kind::Cancel,
    Kind::Complete,
    Kind::PutData,
    Kind::Heartbeat,
];

struct Drawn {
    peer: usize,
    endpoint: u32,
    direction: Direction,
    header: [u8; AUTHENTICATED_LEN],
    body: Vec<u8>,
    split: usize,
}

impl Drawn {
    fn input(&self) -> MacInput<'_> {
        let (head, tail) = self.body.split_at(self.split);
        MacInput {
            endpoint: self.endpoint,
            direction: self.direction,
            header: &self.header,
            body: [head, tail],
        }
    }
}

fn below(rng: &mut SplitMix64, bound: usize) -> usize {
    rng.below(bound as u64) as usize
}

fn bytes(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    out.truncate(len);
    out
}

fn body_len(rng: &mut SplitMix64) -> usize {
    match below(rng, 40) {
        0 => 8192,
        roll @ 1..=16 => BODIES[roll % BODIES.len()],
        _ => 0,
    }
}

fn drawn_inputs(rng: &mut SplitMix64, peers: usize) -> Vec<Drawn> {
    let count = 1 + below(rng, 24);
    let bodies = below(rng, 2) == 1;
    let mut base = [0u8; AUTHENTICATED_LEN];
    base.copy_from_slice(&bytes(rng, AUTHENTICATED_LEN));
    base[KIND_AT] = KINDS[below(rng, KINDS.len())] as u8;
    let endpoint = rng.next_u64() as u32;
    let direction = DIRECTIONS[below(rng, 2)];
    let lead = below(rng, peers);
    (0..count)
        .map(|at| {
            let mut header = base;
            header[64 + below(rng, 112)] ^= 1 + below(rng, 255) as u8;
            let mut drawn = Drawn {
                peer: lead,
                endpoint,
                direction,
                header,
                body: Vec::new(),
                split: 0,
            };
            if at > 0 {
                match below(rng, 24) {
                    0 => drawn.header[47] ^= 1 << below(rng, 8),
                    1 => drawn.header[48] ^= 1 << below(rng, 8),
                    2 => drawn.header[below(rng, 48)] ^= 1 << below(rng, 8),
                    3 => drawn.header[KIND_AT] = KINDS[below(rng, KINDS.len())] as u8,
                    4 => drawn.endpoint ^= 1 << below(rng, 32),
                    5 => drawn.direction = DIRECTIONS[below(rng, 2)],
                    6..=8 => drawn.peer = below(rng, peers),
                    _ => {}
                }
            }
            if bodies {
                let len = body_len(rng);
                drawn.body = bytes(rng, len);
                drawn.split = below(rng, len + 1);
            }
            drawn
        })
        .collect()
}

fn drawn_frames(
    rng: &mut SplitMix64,
    oracle: &KeyRing,
    peers: usize,
    endpoint: u32,
    direction: Direction,
) -> Vec<(usize, Vec<u8>)> {
    (0..1 + below(rng, 4))
        .map(|at| {
            let peer = below(rng, peers);
            let base = Header {
                principal: PRINCIPAL + peer as u32,
                ..session_header(CONTROL[below(rng, 3)], OWNER_NONCE, 1, 1 + at as u64)
            };
            let len = body_len(rng);
            let (header, body) = if len == 0 {
                (base, Vec::new())
            } else {
                let header = Header {
                    total: len as u64,
                    body_len: len as u32,
                    datagram_len: len as u32,
                    ..put_frame(Kind::PutData, &base).0
                };
                (header, bytes(rng, len))
            };
            let mut out = [0; HEADER_LEN];
            encode(crc(), &header, [&body, &[]], &mut out).unwrap();
            let input = mac_input_for(&out, [&body, &[]], endpoint, direction).unwrap();
            let tag = oracle.tag(PeerId(peer as u16), &input).unwrap();
            seal(&mut out, tag);
            let mut datagram = out.to_vec();
            datagram.extend_from_slice(&body);
            (peer, datagram)
        })
        .collect()
}

const CASES: usize = 100_000;

const SHARDS: usize = 8;

macro_rules! drawn_group_shards {
    ($($shard:literal => $name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                drawn_groups_match($shard);
            }
        )*
        const _: () = assert!([$($shard),*].len() == SHARDS);
    };
}

drawn_group_shards! {
    0 => every_group_entry_matches_single_tags_on_a_fresh_ring_over_drawn_groups_shard_0,
    1 => every_group_entry_matches_single_tags_on_a_fresh_ring_over_drawn_groups_shard_1,
    2 => every_group_entry_matches_single_tags_on_a_fresh_ring_over_drawn_groups_shard_2,
    3 => every_group_entry_matches_single_tags_on_a_fresh_ring_over_drawn_groups_shard_3,
    4 => every_group_entry_matches_single_tags_on_a_fresh_ring_over_drawn_groups_shard_4,
    5 => every_group_entry_matches_single_tags_on_a_fresh_ring_over_drawn_groups_shard_5,
    6 => every_group_entry_matches_single_tags_on_a_fresh_ring_over_drawn_groups_shard_6,
    7 => every_group_entry_matches_single_tags_on_a_fresh_ring_over_drawn_groups_shard_7,
}

fn drawn_groups_match(shard: usize) {
    let mut rng = SplitMix64::new(0x7A6_D1FF + shard as u64);
    for case in (shard..CASES).step_by(SHARDS) {
        let peers = [1, 2, 4][below(&mut rng, 3)];
        let keys: Vec<[u8; 32]> = (0..peers)
            .map(|peer| {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes(&mut rng, 32));
                key[0] = peer as u8;
                key
            })
            .collect();
        let (ring, portable, oracle) = (
            ring_over(&keys),
            ring_over(&keys).with_portable_lanes(),
            ring_over(&keys),
        );
        let drawn = drawn_inputs(&mut rng, peers);
        let inputs: Vec<MacInput<'_>> = drawn.iter().map(Drawn::input).collect();
        let want: Vec<[u8; 16]> = drawn
            .iter()
            .zip(&inputs)
            .map(|(drawn, input)| oracle.tag(PeerId(drawn.peer as u16), input).unwrap())
            .collect();
        assert_eq!(
            want[0],
            hand_tag(&keys[drawn[0].peer], &inputs[0]),
            "case {case}"
        );
        for peer in 0..peers {
            let (own, wants): (Vec<MacInput<'_>>, Vec<[u8; 16]>) = (0..drawn.len())
                .filter(|&at| drawn[at].peer == peer)
                .map(|at| (inputs[at], want[at]))
                .unzip();
            let mut tags = vec![[0xA5; 16]; own.len()];
            ring.tags(PeerId(peer as u16), &own, &mut tags).unwrap();
            assert_eq!(tags, wants, "case {case}: tags of peer {peer}");
        }
        let each: Vec<(PeerId, &MacInput<'_>)> = drawn
            .iter()
            .zip(&inputs)
            .map(|(drawn, input)| (PeerId(drawn.peer as u16), input))
            .collect();
        let mut swapped_once = false;
        let mut at = 0;
        while at < each.len() {
            let size = (1 + below(&mut rng, 4)).min(each.len() - at);
            let group = &each[at..at + size];
            let wants = &want[at..at + size];
            let tags = group_tags(&ring, group);
            assert_eq!(tags, wants, "case {case}: a group of {size} at {at}");
            assert_eq!(
                group_tags(&portable, group),
                wants,
                "case {case}: a portable group of {size} at {at}"
            );
            if let [first, second] = *group {
                assert_eq!(
                    ring.tag_pair([first.0, second.0], [first.1, second.1]),
                    Some([wants[0], wants[1]]),
                    "case {case}: a pair at {at}"
                );
            }
            if size > 1 && !swapped_once {
                swapped_once = true;
                let left = below(&mut rng, size);
                let right = (left + 1 + below(&mut rng, size - 1)) % size;
                let mut swapped = group.to_vec();
                swapped.swap(left, right);
                let mut expected = tags.clone();
                expected.swap(left, right);
                assert_eq!(
                    group_tags(&ring, &swapped),
                    expected,
                    "case {case}: chains {left} and {right} of {size} swapped at {at}"
                );
            }
            at += size;
        }
        let (endpoint, direction) = (drawn[0].endpoint, drawn[0].direction);
        let mut datagrams = drawn_frames(&mut rng, &oracle, peers, endpoint, direction);
        let forged = below(&mut rng, datagrams.len() + 1);
        if let Some((_, datagram)) = datagrams.get_mut(forged) {
            datagram[AUTHENTICATED_LEN + below(&mut rng, 16)] ^= 1 << below(&mut rng, 8);
        }
        let parsed: Vec<Frame<'_>> = datagrams
            .iter()
            .map(|(_, datagram)| parse(crc(), datagram, false).unwrap())
            .collect();
        let frames: Vec<(&Frame<'_>, PeerId)> = parsed
            .iter()
            .zip(&datagrams)
            .map(|(frame, (peer, _))| (frame, PeerId(*peer as u16)))
            .collect();
        for lanes in [&ring, &portable] {
            let mut verdicts = group_verdicts(lanes, &frames, endpoint, direction);
            if let [first, second] = frames[..] {
                let pair = lanes.authenticate_pair(first, second, endpoint, direction);
                verdicts.extend([pair.0, pair.1]);
            }
            for (slot, verdict) in verdicts.iter().enumerate() {
                let at = slot % frames.len();
                if at == forged {
                    assert_eq!(verdict.as_ref().err(), Some(&AuthError::Tag), "case {case}");
                } else {
                    assert!(
                        admits(verdict, frames[at].0, datagrams[at].0),
                        "case {case}: frame {at} of {} with {forged} forged: {verdict:?}",
                        frames.len()
                    );
                }
            }
        }
    }
}

#[test]
fn a_get_an_ack_and_a_cancel_tag_as_three_literal_tags() {
    const TAGS: [[u8; 16]; 3] = [
        [
            0xd1, 0x81, 0x41, 0xdb, 0xdd, 0xc1, 0xee, 0x94, 0xc7, 0x9d, 0x07, 0x15, 0x09, 0xf2,
            0xe5, 0x60,
        ],
        [
            0xef, 0x8f, 0x50, 0x45, 0x68, 0x96, 0x65, 0x14, 0x9c, 0x4c, 0x1d, 0x32, 0xee, 0x91,
            0x11, 0x01,
        ],
        [
            0x4e, 0x0d, 0x09, 0xa2, 0x1b, 0xfc, 0x9f, 0x4e, 0xc4, 0x7b, 0xa0, 0x3e, 0x36, 0x74,
            0xeb, 0x83,
        ],
    ];
    let ring = ring_over(&fixed_keys(1));
    let frames: [[u8; HEADER_LEN]; 3] = std::array::from_fn(|at| control(0, at));
    let inputs = frames
        .each_ref()
        .map(|frame| header_only(frame, Direction::ClientToOwner));
    let peer = PeerId(0);
    let mut tags = [[0xA5; 16]; 3];
    ring.tags(peer, &inputs, &mut tags).unwrap();
    assert_eq!(tags, TAGS);
    assert_eq!(
        ring.tag_group([(peer, &inputs[0]), (peer, &inputs[1]), (peer, &inputs[2])]),
        Some(TAGS)
    );
    assert_eq!(
        ring.tag_pair([peer; 2], [&inputs[2], &inputs[0]]),
        Some([TAGS[2], TAGS[0]])
    );
    assert_eq!(inputs.map(|input| ring.tag(peer, &input).unwrap()), TAGS);
}
